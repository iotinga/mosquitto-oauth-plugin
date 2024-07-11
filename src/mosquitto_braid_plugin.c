/*
 * Copyright (C) 2024 IOTINGA S.r.l. - All Rights Reserved
 * You may use, distribute and modify this code under the
 * terms of the Apache License 2.0. See LICENSE for details.
 *
 * @author Cristiano Di Bari
 */

#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "mosquitto_broker.h"
#include "mosquitto_plugin.h"
#include "mosquitto.h"
#include "mqtt_protocol.h"

#include "jansson.h"
#include "jwt.h"
#include "curl/curl.h"

#include "hashmap.h"
#include "utils.h"
#include "base64.h"

#define REQ_BODY_MAX_SIZE 200

#define BASIC_AUTH_STR_MAX_SIZE 50
#define REQ_HEADER_AUTH_MAX_SIZE 100

#define MQTT_ACL_GRANT "mqtt_acl"
#define MQTT_ACL_PUBLISH_KEY "publish"
#define MQTT_ACL_SUBSCRIBE_KEY "subscribe"
#define MQTT_ACL_SUPERUSER_KEY "superuser"

struct plugin_state
{
    struct hashmap *session_map;
    bool jwt_validate_exp;
    char *jwt_key;
    char *oauth_client_id;
    char *oauth_client_secret;
    char *oauth_token_url;
};

struct http_response_body
{
    char *data;
    size_t size;
};

static mosquitto_plugin_id_t *mosq_pid = NULL;

static int init_session_from_jwt(const char *client_id, char *token, jwt_t *jwt, struct plugin_state *state)
{
    char *jwt_payload = NULL;

    int jwt_error = jwt_decode(&jwt, token, state->jwt_key, strlen(state->jwt_key));
    if (jwt_error)
    {
        mosquitto_log_printf(MOSQ_LOG_INFO, "Password is not a valid JWT Token");
        return MOSQ_ERR_AUTH;
    }

    jwt_payload = jwt_get_grants_json(jwt, NULL);

    json_error_t json_error;
    json_t *jwt_payload_json = json_loads(jwt_payload, (size_t)NULL, &json_error);
    if (jwt_payload_json == NULL)
    {
        mosquitto_log_printf(MOSQ_LOG_ERR, "Error parsing JWT payload: %s", json_error.text);
        free(jwt_payload);
        return MOSQ_ERR_AUTH;
    }

    json_t *mqtt_acl_json = json_object_get(jwt_payload_json, MQTT_ACL_GRANT);
    if (!json_is_object(mqtt_acl_json))
    {
        mosquitto_log_printf(MOSQ_LOG_ERR, "JWT " MQTT_ACL_GRANT " claim not found or is not an object");
        free(jwt_payload);
        return MOSQ_ERR_AUTH;
    }

    json_t *mqtt_acl_publish_json = json_object_get(mqtt_acl_json, MQTT_ACL_PUBLISH_KEY);
    json_t *mqtt_acl_subscribe_json = json_object_get(mqtt_acl_json, MQTT_ACL_SUBSCRIBE_KEY);
    json_t *mqtt_acl_superuser_json = json_object_get(mqtt_acl_json, MQTT_ACL_SUPERUSER_KEY);

    string_array publish_topics;
    parse_json_string_array(mqtt_acl_publish_json, &publish_topics);

    string_array subscribe_topics;
    parse_json_string_array(mqtt_acl_subscribe_json, &subscribe_topics);

    bool superuser = json_boolean_value(mqtt_acl_superuser_json);

    user_session session = {
        .client_id = client_id,
        .superuser = superuser,
        .publish_topics = publish_topics,
        .subscribe_topics = subscribe_topics,
    };

    hashmap_set(state->session_map, &session);

    free(jwt_payload);

    return MOSQ_ERR_SUCCESS;
}

static size_t http_write_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    struct http_response_body *mem = (struct http_response_body *)userp;

    char *ptr = mosquitto_realloc(mem->data, mem->size + realsize + 1);
    if (!ptr)
    {
        return MOSQ_ERR_NOMEM;
    }

    mem->data = ptr;
    memcpy(&(mem->data[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->data[mem->size] = 0;

    return realsize;
}

static void get_user_token_from_oauth(char *username, char *password, char **token, struct plugin_state *state)
{
    mosquitto_log_printf(MOSQ_LOG_INFO, "Retrieve user token from oauth server");

    CURL *curl_handle;
    CURLcode res;

    struct http_response_body chunk;
    chunk.data = mosquitto_malloc(1); /* grown as needed by the realloc above */
    chunk.size = 0;                   /* no data at this point */

    curl_global_init(CURL_GLOBAL_ALL);
    curl_handle = curl_easy_init();

    if (curl_handle)
    {
        char basic_auth_str[BASIC_AUTH_STR_MAX_SIZE] = {0};
        snprintf(basic_auth_str, BASIC_AUTH_STR_MAX_SIZE, ":%s", state->oauth_client_secret);
        char *basic_auth_encoded = base64_encode(basic_auth_str);

        char req_auth[REQ_HEADER_AUTH_MAX_SIZE] = {0};
        snprintf(req_auth, REQ_HEADER_AUTH_MAX_SIZE, "Authorization: Basic %s", basic_auth_encoded);
        mosquitto_free(basic_auth_encoded);

        char req_body[REQ_BODY_MAX_SIZE] = {0};
        snprintf(req_body, REQ_BODY_MAX_SIZE, "grant_type=password&username=%s&password=%s&client_id=%s", username, password, state->oauth_client_id);

        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, req_auth);

        curl_easy_setopt(curl_handle, CURLOPT_URL, state->oauth_token_url);
        curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, http_write_callback);
        curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);
        curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "mosquitto-mqtt-broker");
        curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, req_body);

        res = curl_easy_perform(curl_handle);
        if (res != CURLE_OK)
        {
            mosquitto_log_printf(MOSQ_LOG_ERR, "HTTP request failed: %s", curl_easy_strerror(res));
        }
        else
        {
            json_error_t json_error;
            json_t *jwt_payload_json = json_loads(chunk.data, (size_t)NULL, &json_error);
            json_t *token_json = json_object_get(jwt_payload_json, "access_token");

            if (token_json == NULL)
            {
                mosquitto_log_printf(MOSQ_LOG_ERR, "Error in retrieve access token: %.*s", chunk.size, chunk.data);
            }
            else
            {
                const char *token_str = json_string_value(token_json);
                *token = mosquitto_strdup(token_str);
            }
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl_handle);
    }

    free(chunk.data);
    curl_global_cleanup();
}

static int basic_auth_callback(int event, void *event_data, void *userdata)
{
    UNUSED(event);

    struct plugin_state *state = userdata;
    struct mosquitto_evt_basic_auth *ed = event_data;
    jwt_t *jwt = NULL;

    int err = MOSQ_ERR_AUTH;
    char *token = NULL;
    bool is_token_dynamic = false;
    const char *client_id = mosquitto_client_id(ed->client);

    if (ed->username == NULL || ed->password == NULL)
    {
        return MOSQ_ERR_AUTH;
    }

    if (strcmp(ed->username, "jwt") == 0)
    {
        token = ed->password;
    }
    else
    {
        get_user_token_from_oauth(ed->username, ed->password, &token, state);
        is_token_dynamic = true;
    }

    if (token != NULL)
    {
        err = init_session_from_jwt(client_id, token, jwt, state);
    }

    jwt_free(jwt);
    if (is_token_dynamic)
    {
        mosquitto_free(token);
    }

    return err;
}

static int acl_check_subscribe(struct mosquitto_evt_acl_check *ed, const user_session *user)
{
    for (size_t i = 0; i < user->subscribe_topics.size; i++)
    {
        char *sub_topic_str = user->subscribe_topics.data[i];
        bool result = false;
        mosquitto_topic_matches_sub(sub_topic_str, ed->topic, &result);

        if (result)
        {
            return MOSQ_ERR_SUCCESS;
        }
    }

    return MOSQ_ERR_ACL_DENIED;
}

static int acl_check_publish(struct mosquitto_evt_acl_check *ed, const user_session *user)
{

    for (size_t i = 0; i < user->publish_topics.size; i++)
    {
        char *pub_topic_str = user->publish_topics.data[i];
        bool result = false;
        mosquitto_topic_matches_sub(pub_topic_str, ed->topic, &result);
        if (result)
        {
            return MOSQ_ERR_SUCCESS;
        }
    }

    return MOSQ_ERR_ACL_DENIED;
}

static int acl_check_callback(int event, void *event_data, void *userdata)
{
    UNUSED(event);

    struct plugin_state *state = userdata;
    struct mosquitto_evt_acl_check *ed = event_data;
    const char *client_id = mosquitto_client_id(ed->client);

    mosquitto_log_printf(MOSQ_LOG_INFO, "Checking if user %s is allowed to access topic %s with access %d.", client_id, ed->topic, ed->access);

    const user_session *user = hashmap_get(state->session_map, &(user_session){.client_id = client_id});
    if (user == NULL)
    {
        return MOSQ_ERR_PLUGIN_DEFER;
    }

    if (user->superuser)
    {
        return MOSQ_ERR_SUCCESS;
    }

    switch (ed->access)
    {
    case MOSQ_ACL_READ:
        return MOSQ_ERR_SUCCESS;
    case MOSQ_ACL_WRITE:
        return acl_check_publish(event_data, user);
    case MOSQ_ACL_SUBSCRIBE:
        return acl_check_subscribe(event_data, user);
    case MOSQ_ACL_UNSUBSCRIBE:
        return MOSQ_ERR_SUCCESS;
    default:
        return MOSQ_ERR_PLUGIN_DEFER;
    }

    return MOSQ_ERR_PLUGIN_DEFER;
}

static int disconnect_callback(int event, void *event_data, void *userdata)
{
    UNUSED(event);

    struct plugin_state *state = userdata;
    struct mosquitto_evt_disconnect *ed = event_data;
    const char *client_id = mosquitto_client_id(ed->client);

    const user_session *user = hashmap_delete(state->session_map, &(user_session){.client_id = client_id});
    if (user != NULL)
    {
        user_session_free((void *)user);
    }

    mosquitto_log_printf(MOSQ_LOG_INFO, "User %s successfully disconnected.", client_id);

    return MOSQ_ERR_SUCCESS;
}

int mosquitto_plugin_version(int supported_version_count, const int *supported_versions)
{
    int i;

    for (i = 0; i < supported_version_count; i++)
    {
        if (supported_versions[i] == 5)
        {
            return 5;
        }
    }

    return -1;
}

void load_configuration(struct plugin_state *state, struct mosquitto_opt *opts, int opt_count)
{
    for (size_t i = 0; i < opt_count; i++)
    {
        char *key = opts[i].key;
        char *value = opts[i].value;

        if (strcmp(key, "oauth_jwt_key") == 0)
        {
            size_t jwt_size = strlen(value) + 55;
            state->jwt_key = mosquitto_calloc(jwt_size, sizeof(char));
            snprintf(state->jwt_key, jwt_size, "-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----", value);
        }
        else if (strcmp(key, "oauth_jwt_validate_exp") == 0)
        {
            state->jwt_validate_exp = strcmp(value, "true") == 0;
        }
        else if (strcmp(key, "oauth_client_id") == 0)
        {
            state->oauth_client_id = value;
        }
        else if (strcmp(key, "oauth_client_secret") == 0)
        {
            state->oauth_client_secret = value;
        }
        else if (strcmp(key, "oauth_token_url") == 0)
        {
            state->oauth_token_url = value;
        }
    }
}

int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **user_data, struct mosquitto_opt *opts, int opt_count)
{
    UNUSED(opts);
    UNUSED(opt_count);

    mosq_pid = identifier;

    /* Init session data */
    *user_data = mosquitto_malloc(sizeof(struct plugin_state));
    struct hashmap *session_map = hashmap_new_with_allocator(mosquitto_malloc, mosquitto_realloc, mosquitto_free,
                                                             sizeof(user_session), 0, 0, 0,
                                                             user_session_hash, user_session_compare, user_session_free, NULL);
    ((struct plugin_state *)*user_data)->session_map = session_map;

    /* Load configuration */
    load_configuration(*user_data, opts, opt_count);

    /* Triggered on a new connection to verify username and password */
    ERROR_CHECK(mosquitto_callback_register(mosq_pid, MOSQ_EVT_BASIC_AUTH, basic_auth_callback, NULL, *user_data));

    /* Triggered for every subscribe, write and read. Return value determines if the action is allowed */
    ERROR_CHECK(mosquitto_callback_register(mosq_pid, MOSQ_EVT_ACL_CHECK, acl_check_callback, NULL, *user_data));

    /* Triggered when the client disconnects */
    ERROR_CHECK(mosquitto_callback_register(mosq_pid, MOSQ_EVT_DISCONNECT, disconnect_callback, NULL, *user_data));

    mosquitto_log_printf(MOSQ_LOG_INFO, "Mosquitto auth plugin initialized");

    return MOSQ_ERR_SUCCESS;
}

int mosquitto_plugin_cleanup(void *user_data, struct mosquitto_opt *opts, int opt_count)
{
    UNUSED(opts);
    UNUSED(opt_count);

    /* Cleanup session data */
    hashmap_free(((struct plugin_state *)user_data)->session_map);
    mosquitto_free(((struct plugin_state *)user_data)->jwt_key);
    mosquitto_free(user_data);

    ERROR_CHECK(mosquitto_callback_unregister(mosq_pid, MOSQ_EVT_BASIC_AUTH, basic_auth_callback, NULL));
    ERROR_CHECK(mosquitto_callback_unregister(mosq_pid, MOSQ_EVT_ACL_CHECK, acl_check_callback, NULL));
    ERROR_CHECK(mosquitto_callback_unregister(mosq_pid, MOSQ_EVT_DISCONNECT, acl_check_callback, NULL));

    mosquitto_log_printf(MOSQ_LOG_INFO, "Mosquitto auth plugin cleaned up");

    return MOSQ_ERR_SUCCESS;
}