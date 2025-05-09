/*
 * Copyright (C) 2024 IOTINGA S.r.l. - All Rights Reserved
 * You may use, distribute and modify this code under the
 * terms of the Apache License 2.0. See LICENSE for details.
 *
 * @author Cristiano Di Bari
 */

#ifndef OAUTH_PLUGIN_H
#define OAUTH_PLUGIN_H

#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "mosquitto_broker.h"
#include "mosquitto_plugin.h"
#include "mosquitto.h"
#include "mqtt_protocol.h"

#include "base64.h"
#include "curl/curl.h"
#include "hashmap.h"
#include "jansson.h"
#include "oauth.h"
#include "openssl/x509.h"
#include "utils.h"

struct plugin_state
{
    struct hashmap *session_map;
    bool jwt_validate_exp;
    char *jwt_key;
    char *oauth_client_id;
    char *oauth_client_secret;
    char *oauth_token_url;
    char *oauth_admin_username;
    char *oauth_admin_password;
};

struct user_session
{
    const char *client_id;
    bool superuser;
    string_array publish_topics;
    string_array subscribe_topics;
};

/* Auth */
int basic_auth_callback(int event, void *event_data, void *userdata);
int disconnect_callback(int event, void *event_data, void *userdata);

/* ACL */
int acl_check_callback(int event, void *event_data, void *userdata);
int acl_check_publish(struct mosquitto_evt_acl_check *ed, const struct user_session *user);
int acl_check_subscribe(struct mosquitto_evt_acl_check *ed, const struct user_session *user);
bool acl_sub_match(const char *acl, const char *sub);

/* Session */
int user_session_from_jwt(const char *client_id, char *token, struct plugin_state *state);
int user_session_compare(const void *a, const void *b, void *udata);
uint64_t user_session_hash(const void *item, uint64_t seed0, uint64_t seed1);
void user_session_free(void *item);

#endif // OAUTH_PLUGIN_H