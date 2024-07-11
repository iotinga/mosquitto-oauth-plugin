/*
 * Copyright (C) 2024 IOTINGA S.r.l. - All Rights Reserved
 * You may use, distribute and modify this code under the
 * terms of the Apache License 2.0. See LICENSE for details.
 *
 * @author Cristiano Di Bari
 */

#ifndef BASE46_H
#define BASE46_H

#include <stdlib.h>
#include <memory.h>

char *base64_encode(char *plain);

char *base64_decode(char *cipher);

#endif // BASE46_H