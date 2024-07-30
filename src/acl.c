/*
 * Copyright (C) 2024 IOTINGA S.r.l. - All Rights Reserved
 * You may use, distribute and modify this code under the
 * terms of the Apache License 2.0. See LICENSE for details.
 *
 * @author Cristiano Di Bari
 */

#include "mosquitto_oauth_plugin.h"

int acl_check_subscribe(struct mosquitto_evt_acl_check *ed, const struct user_session *user)
{
    for (size_t i = 0; i < user->subscribe_topics.size; i++)
    {
        char *sub_topic_str = user->subscribe_topics.data[i];
        bool result = acl_sub_match(sub_topic_str, ed->topic);
        if (result)
        {
            mosquitto_log_printf(MOSQ_LOG_DEBUG, "User %s is allowed to SUBSCRIBE to topic %s.", mosquitto_client_username(ed->client), ed->topic);
            return MOSQ_ERR_SUCCESS;
        }
    }

    mosquitto_log_printf(MOSQ_LOG_DEBUG, "User %s NOT allowed to SUBSCRIBE to topic %s.", mosquitto_client_username(ed->client), ed->topic);
    return MOSQ_ERR_ACL_DENIED;
}

int acl_check_publish(struct mosquitto_evt_acl_check *ed, const struct user_session *user)
{
    for (size_t i = 0; i < user->publish_topics.size; i++)
    {
        char *pub_topic_str = user->publish_topics.data[i];
        bool result = false;
        mosquitto_topic_matches_sub(pub_topic_str, ed->topic, &result);
        if (result)
        {
            mosquitto_log_printf(MOSQ_LOG_DEBUG, "User %s is allowed to PUBLISH on topic %s.", mosquitto_client_username(ed->client), ed->topic);
            return MOSQ_ERR_SUCCESS;
        }
    }

    mosquitto_log_printf(MOSQ_LOG_DEBUG, "User %s NOT allowed to PUBLISH on topic %s.", mosquitto_client_username(ed->client), ed->topic);
    return MOSQ_ERR_ACL_DENIED;
}

int acl_check_callback(int event, void *event_data, void *userdata)
{
    UNUSED(event);

    struct plugin_state *state = userdata;
    struct mosquitto_evt_acl_check *ed = event_data;
    const char *client_id = mosquitto_client_id(ed->client);

    mosquitto_log_printf(MOSQ_LOG_DEBUG, "Checking if user %s is allowed to access topic %s with access %d.", mosquitto_client_username(ed->client), ed->topic, ed->access);

    const struct user_session *user = hashmap_get(state->session_map, &(struct user_session){.client_id = client_id});
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
