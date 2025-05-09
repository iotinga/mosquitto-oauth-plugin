/*
 * Copyright (C) 2024 IOTINGA S.r.l. - All Rights Reserved
 * You may use, distribute and modify this code under the
 * terms of the Apache License 2.0. See LICENSE for details.
 *
 * @author Cristiano Di Bari
 */

#include "mosquitto_oauth_plugin.h"
#include <string.h>
#include <l8w8jwt/decode.h>      // for l8w8jwt_decode_raw, l8w8jwt_decoding_params, L8W8JWT_ALG_*
#include <jansson.h>             // for json_loadb, json_object_get, etc.

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

int user_session_from_jwt(const char *client_id,
    char *token,
    struct plugin_state *state)
{
    // 1) Prepare decode parameters
    struct l8w8jwt_decoding_params params;
    l8w8jwt_decoding_params_init(&params);

    params.jwt                  = token;
    params.jwt_length           = strlen(token);
    params.alg                  = L8W8JWT_ALG_HS256;               // or pick dynamically :contentReference[oaicite:0]{index=0}
    params.verification_key     = (unsigned char *)state->jwt_key;
    params.verification_key_length = strlen(state->jwt_key);
    params.validate_exp         = true;

    // 2) Decode + validate, but only extract the payload JSON
    enum l8w8jwt_validation_result validation = L8W8JWT_VALID;
    char *payload_json = NULL;
    size_t payload_json_len = 0;

    int decode_ret = l8w8jwt_decode_raw(
    &params,
    &validation,
    /* out_header */           NULL, NULL,
    /* out_payload */          &payload_json, &payload_json_len,
    /* out_signature */        NULL, NULL
    );
    if(decode_ret != L8W8JWT_SUCCESS) {
        mosquitto_log_printf(MOSQ_LOG_INFO,
        "Password is not a valid JWT Token");
        return MOSQ_ERR_AUTH;
    }

    // 3) Check exp claim if desired
    if(state->jwt_validate_exp && (validation & L8W8JWT_EXP_FAILURE))
    {
    mosquitto_log_printf(MOSQ_LOG_ERR, "JWT is expired.");
        l8w8jwt_free(payload_json);  // free buffer allocated by l8w8jwt_decode_raw :contentReference[oaicite:1]{index=1}
        return MOSQ_ERR_AUTH;
    }

    // 4) Parse that JSON
    json_error_t json_err;
    json_t *jwt_payload = json_loadb(
    payload_json,
    payload_json_len,
    0,
    &json_err
    );
    if(!jwt_payload) {
        mosquitto_log_printf(MOSQ_LOG_ERR,
        "Error parsing JWT payload: %s", json_err.text);
        l8w8jwt_free(payload_json);
        return MOSQ_ERR_AUTH;
    }

    // 5) Extract your MQTT-ACL object and claims exactly as before
    json_t *mqtt_acl_json =
    json_object_get(jwt_payload, MQTT_ACL_GRANT);
    if(!json_is_object(mqtt_acl_json)) {
        mosquitto_log_printf(MOSQ_LOG_ERR,
        "JWT " MQTT_ACL_GRANT
        " claim not found or is not an object");
        json_decref(jwt_payload);
        l8w8jwt_free(payload_json);
        return MOSQ_ERR_AUTH;
    }

    json_t *pub_arr  = json_object_get(mqtt_acl_json, MQTT_ACL_PUBLISH_KEY);
    json_t *sub_arr  = json_object_get(mqtt_acl_json, MQTT_ACL_SUBSCRIBE_KEY);
    json_t *su_flag  = json_object_get(mqtt_acl_json, MQTT_ACL_SUPERUSER_KEY);

    string_array publish_topics;
    parse_json_string_array(pub_arr, &publish_topics);

    string_array subscribe_topics;
    parse_json_string_array(sub_arr, &subscribe_topics);

    bool superuser = json_boolean_value(su_flag);

    // 6) Store in your session map
    struct user_session session = {
    .client_id       = client_id,
    .superuser       = superuser,
    .publish_topics  = publish_topics,
    .subscribe_topics= subscribe_topics,
    };
    hashmap_set(state->session_map, &session);

    // 7) Clean up
    json_decref(jwt_payload);
    l8w8jwt_free(payload_json);

    return MOSQ_ERR_SUCCESS;
}