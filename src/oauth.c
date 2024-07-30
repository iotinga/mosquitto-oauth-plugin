/*
 * Copyright (C) 2024 IOTINGA S.r.l. - All Rights Reserved
 * You may use, distribute and modify this code under the
 * terms of the Apache License 2.0. See LICENSE for details.
 *
 * @author Cristiano Di Bari
 */

#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include "oauth.h"

#include "base64.h"
#include "curl/curl.h"
#include "jansson.h"
#include "mosquitto.h"
#include "mosquitto_broker.h"

#define HTTP_USERAGENT "mosquitto-mqtt"

#define REQ_BODY_MAX_SIZE 1024

#define BASIC_AUTH_STR_MAX_SIZE 50
#define REQ_HEADER_AUTH_MAX_SIZE 100

struct http_response_body
{
    char *data;
    size_t size;
};

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

static void get_access_token_from_http_response(struct http_response_body *body, char **token)
{
    json_error_t json_error;
    json_t *jwt_payload_json = json_loads(body->data, (size_t)NULL, &json_error);
    json_t *token_json = json_object_get(jwt_payload_json, "access_token");

    if (token_json == NULL)
    {
        mosquitto_log_printf(MOSQ_LOG_ERR, "Error in retrieve access token: %.*s", body->size, body->data);
    }
    else
    {
        const char *token_str = json_string_value(token_json);
        *token = mosquitto_strdup(token_str);
    }
}

void oauth_get_user_token(char *username, char *password, char *token_endpoint, char *client_id, char *client_secret, char **token)
{
    mosquitto_log_printf(MOSQ_LOG_INFO, "Retrieve user %s token from oauth server", username);

    CURL *curl_handle;
    CURLcode res;

    struct http_response_body chunk;
    chunk.data = mosquitto_malloc(1);
    chunk.size = 0;

    curl_global_init(CURL_GLOBAL_ALL);
    curl_handle = curl_easy_init();

    if (curl_handle)
    {
        char basic_auth_str[BASIC_AUTH_STR_MAX_SIZE] = {0};
        snprintf(basic_auth_str, BASIC_AUTH_STR_MAX_SIZE, ":%s", client_secret);
        char *basic_auth_encoded = base64_encode(basic_auth_str);

        char req_auth[REQ_HEADER_AUTH_MAX_SIZE] = {0};
        snprintf(req_auth, REQ_HEADER_AUTH_MAX_SIZE, "Authorization: Basic %s", basic_auth_encoded);
        mosquitto_free(basic_auth_encoded);

        char req_body[REQ_BODY_MAX_SIZE] = {0};
        snprintf(req_body, REQ_BODY_MAX_SIZE, "grant_type=password&username=%s&password=%s&client_id=%s", username, password, client_id);

        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, req_auth);

        curl_easy_setopt(curl_handle, CURLOPT_URL, token_endpoint);
        curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, http_write_callback);
        curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);
        curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, HTTP_USERAGENT);
        curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, req_body);

        res = curl_easy_perform(curl_handle);
        if (res != CURLE_OK)
        {
            mosquitto_log_printf(MOSQ_LOG_ERR, "HTTP request failed: %s", curl_easy_strerror(res));
        }
        else
        {
            get_access_token_from_http_response(&chunk, token);
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl_handle);
    }

    free(chunk.data);
    curl_global_cleanup();
}

void oauth_exchange_user_token(char *admin_token, char *target_username, char *token_endpoint, char *client_id, char *client_secret, char **token)
{
    mosquitto_log_printf(MOSQ_LOG_INFO, "Exchange user %s token from oauth server", target_username);

    CURL *curl_handle;
    CURLcode res;

    struct http_response_body chunk;
    chunk.data = mosquitto_malloc(1);
    chunk.size = 0;

    curl_global_init(CURL_GLOBAL_ALL);
    curl_handle = curl_easy_init();

    if (curl_handle)
    {
        char basic_auth_str[BASIC_AUTH_STR_MAX_SIZE] = {0};
        snprintf(basic_auth_str, BASIC_AUTH_STR_MAX_SIZE, ":%s", client_secret);
        char *basic_auth_encoded = base64_encode(basic_auth_str);

        char req_auth[REQ_HEADER_AUTH_MAX_SIZE] = {0};
        snprintf(req_auth, REQ_HEADER_AUTH_MAX_SIZE, "Authorization: Basic %s", basic_auth_encoded);
        mosquitto_free(basic_auth_encoded);

        char req_body[REQ_BODY_MAX_SIZE] = {0};
        snprintf(req_body, REQ_BODY_MAX_SIZE,
                 "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&requested_token_type=urn:ietf:params:oauth:token-type:access_token&client_id=%s&subject_token=%s&requested_subject=%s",
                 client_id, admin_token,
                 target_username);

        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, req_auth);

        curl_easy_setopt(curl_handle, CURLOPT_URL, token_endpoint);
        curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, http_write_callback);
        curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);
        curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, HTTP_USERAGENT);
        curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, req_body);

        res = curl_easy_perform(curl_handle);
        if (res != CURLE_OK)
        {
            mosquitto_log_printf(MOSQ_LOG_ERR, "HTTP request failed: %s", curl_easy_strerror(res));
        }
        else
        {
            get_access_token_from_http_response(&chunk, token);
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl_handle);
    }

    free(chunk.data);
    curl_global_cleanup();
}