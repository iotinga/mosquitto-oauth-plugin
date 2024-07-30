/*
 * Copyright (C) 2024 IOTINGA S.r.l. - All Rights Reserved
 * You may use, distribute and modify this code under the
 * terms of the Apache License 2.0. See LICENSE for details.
 *
 * @author Cristiano Di Bari
 */

#include <string.h>

#include "utils.h"

#include "jansson.h"
#include "mosquitto_broker.h"

void parse_json_string_array(json_t *array_json, string_array *string_array)
{
    if (json_is_array(array_json))
    {
        string_array->size = json_array_size(array_json);
        string_array->data = mosquitto_calloc(string_array->size, sizeof(char *));
        for (size_t i = 0; i < string_array->size; i++)
        {
            json_t *topic_json = json_array_get(array_json, i);
            const char *topic_str = json_string_value(topic_json);
            string_array->data[i] = mosquitto_strdup(topic_str);
        }
    }
}

void string_array_free(string_array *string_array)
{
    for (size_t i = 0; i < string_array->size; i++)
    {
        mosquitto_free(string_array->data[i]);
    }
    mosquitto_free(string_array->data);
}
