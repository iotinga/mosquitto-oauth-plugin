/*
 * Copyright (C) 2024 IOTINGA S.r.l. - All Rights Reserved
 * You may use, distribute and modify this code under the
 * terms of the Apache License 2.0. See LICENSE for details.
 *
 * @author Cristiano Di Bari
 */

#include "mosquitto_oauth_plugin.h"

#define X509_CN_MAX_SIZE 256

static int get_cn_from_certificate(X509 *certificate, char *common_name)
{
    memset(common_name, 0, X509_CN_MAX_SIZE);

    X509_NAME *subject_name = X509_get_subject_name(certificate);
    if (subject_name == NULL)
    {
        X509_free(certificate);
        return MOSQ_ERR_AUTH;
    }

    int common_name_len = X509_NAME_get_text_by_NID(subject_name, NID_commonName, common_name, X509_CN_MAX_SIZE);
    if (common_name_len == -1)
    {
        X509_free(certificate);
        return MOSQ_ERR_AUTH;
    }

    X509_free(certificate);

    return MOSQ_ERR_SUCCESS;
}

int basic_auth_callback(int event, void *event_data, void *userdata)
{
    UNUSED(event);

    struct plugin_state *state = userdata;
    struct mosquitto_evt_basic_auth *ed = event_data;

    int err = MOSQ_ERR_AUTH;
    char *admin_token = NULL;
    char *token = NULL;
    bool is_token_dynamic = false;
    static char certificate_cn[X509_CN_MAX_SIZE] = {0};

    X509 *certificate = mosquitto_client_certificate(ed->client);
    const char *client_id = mosquitto_client_id(ed->client);

    mosquitto_log_printf(MOSQ_LOG_INFO, "Trying to authenticate user %s.", ed->username);

    if (ed->username != NULL && ed->password != NULL)
    {
        if (strcmp(ed->username, "jwt") == 0)
        {
            token = ed->password;
        }
        else
        {
            is_token_dynamic = true;
            oauth_get_user_token(
                ed->username,
                ed->password,
                state->oauth_token_url,
                state->oauth_client_id,
                state->oauth_client_secret,
                &token);
        }
    }
    else if (certificate != NULL)
    {
        err = get_cn_from_certificate(certificate, certificate_cn);
        if (!err)
        {
            is_token_dynamic = true;
            oauth_get_user_token(
                state->oauth_admin_username,
                state->oauth_admin_password,
                state->oauth_token_url,
                state->oauth_client_id,
                state->oauth_client_secret,
                &admin_token);

            if (admin_token != NULL)
            {
                oauth_exchange_user_token(
                    admin_token,
                    certificate_cn,
                    state->oauth_token_url,
                    state->oauth_client_id,
                    state->oauth_client_secret,
                    &token);

                mosquitto_free(admin_token);
            }

            if (token == NULL)
            {
                err = MOSQ_ERR_AUTH;
            }
        }
    }
    else
    {
        mosquitto_log_printf(MOSQ_LOG_INFO, "Invalid credentials.");
    }

    if (token != NULL)
    {
        err = user_session_from_jwt(client_id, token, state);
    }

    if (is_token_dynamic && token != NULL)
    {
        mosquitto_free(token);
    }

    return err;
}