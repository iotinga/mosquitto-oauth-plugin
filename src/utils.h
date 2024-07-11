/*
 * Copyright (C) 2024 IOTINGA S.r.l. - All Rights Reserved
 * You may use, distribute and modify this code under the
 * terms of the Apache License 2.0. See LICENSE for details.
 *
 * @author Cristiano Di Bari
 */

#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>

#include "hashmap.h"
#include "jansson.h"

#define UNUSED(A) (void)(A)

#define ERROR_CHECK(x)               \
    do                               \
    {                                \
        int err = (x);               \
        if (err != MOSQ_ERR_SUCCESS) \
            return err;              \
    } while (0)

typedef struct
{
    char **data;
    size_t size;
} string_array;

void parse_json_string_array(json_t *array_json, string_array *string_array);

void string_array_free(string_array *string_array);

typedef struct
{
    const char *client_id;
    bool superuser;
    string_array publish_topics;
    string_array subscribe_topics;
} user_session;

int user_session_compare(const void *a, const void *b, void *udata);

uint64_t user_session_hash(const void *item, uint64_t seed0, uint64_t seed1);

void user_session_free(void *item);

#endif // UTILS_H