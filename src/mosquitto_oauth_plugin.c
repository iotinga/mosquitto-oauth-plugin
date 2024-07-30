/*
 * Copyright (C) 2024 IOTINGA S.r.l. - All Rights Reserved
 * You may use, distribute and modify this code under the
 * terms of the Apache License 2.0. See LICENSE for details.
 *
 * @author Cristiano Di Bari
 */

#include "mosquitto_oauth_plugin.h"

static mosquitto_plugin_id_t *mosq_pid = NULL;

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
        else if (strcmp(key, "oauth_admin_username") == 0)
        {
            state->oauth_admin_username = value;
        }
        else if (strcmp(key, "oauth_admin_password") == 0)
        {
            state->oauth_admin_password = value;
        }
    }
}

int disconnect_callback(int event, void *event_data, void *userdata)
{
    UNUSED(event);

    struct plugin_state *state = userdata;
    struct mosquitto_evt_disconnect *ed = event_data;
    const struct user_session *user = NULL;

    const char *client_id = mosquitto_client_id(ed->client);
    if (client_id != NULL)
    {
        hashmap_delete(state->session_map, &(struct user_session){.client_id = client_id});
    }

    if (user != NULL)
    {
        user_session_free((void *)user);
    }

    mosquitto_log_printf(MOSQ_LOG_INFO, "User %s successfully disconnected.", client_id);

    return MOSQ_ERR_SUCCESS;
}

int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **user_data, struct mosquitto_opt *opts, int opt_count)
{
    UNUSED(opts);
    UNUSED(opt_count);

    mosq_pid = identifier;

    /* Init session data */
    *user_data = mosquitto_malloc(sizeof(struct plugin_state));
    struct hashmap *session_map = hashmap_new_with_allocator(mosquitto_malloc, mosquitto_realloc, mosquitto_free,
                                                             sizeof(struct user_session), 0, 0, 0,
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