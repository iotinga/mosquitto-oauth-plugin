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

#endif // UTILS_H