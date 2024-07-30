/*
 * Copyright (C) 2024 IOTINGA S.r.l. - All Rights Reserved
 * You may use, distribute and modify this code under the
 * terms of the Apache License 2.0. See LICENSE for details.
 *
 * @author Cristiano Di Bari
 */

#include "mosquitto_oauth_plugin.h"

#include <time.h>

#define EXP_GRANT "exp"

#define MQTT_ACL_GRANT "mqtt_acl"
#define MQTT_ACL_PUBLISH_KEY "publish"
#define MQTT_ACL_SUBSCRIBE_KEY "subscribe"
#define MQTT_ACL_SUPERUSER_KEY "superuser"

int user_session_compare(const void *a, const void *b, void *udata)
{
    const struct user_session *ua = a;
    const struct user_session *ub = b;
    return strcmp(ua->client_id, ub->client_id);
}

uint64_t user_session_hash(const void *item, uint64_t seed0, uint64_t seed1)
{
    const struct user_session *user = item;
    return hashmap_sip(user->client_id, strlen(user->client_id), seed0, seed1);
}

void user_session_free(void *item)
{
    const struct user_session *user = item;
    string_array_free((void *)&user->publish_topics);
    string_array_free((void *)&user->subscribe_topics);
}

int user_session_from_jwt(const char *client_id, char *token, jwt_t *jwt, struct plugin_state *state)
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

    if (state->jwt_validate_exp)
    {
        time_t now = time(NULL);
        json_t *jwt_exp = json_object_get(jwt_payload_json, EXP_GRANT);
        time_t exp = json_integer_value(jwt_exp);
        if (now > exp)
        {
            mosquitto_log_printf(MOSQ_LOG_ERR, "JWT is expired.");
            free(jwt_payload);
            return MOSQ_ERR_AUTH;
        }
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

    struct user_session session = {
        .client_id = client_id,
        .superuser = superuser,
        .publish_topics = publish_topics,
        .subscribe_topics = subscribe_topics,
    };

    hashmap_set(state->session_map, &session);

    free(jwt_payload);

    return MOSQ_ERR_SUCCESS;
}