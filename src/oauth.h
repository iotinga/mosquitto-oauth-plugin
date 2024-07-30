/*
 * Copyright (C) 2024 IOTINGA S.r.l. - All Rights Reserved
 * You may use, distribute and modify this code under the
 * terms of the Apache License 2.0. See LICENSE for details.
 *
 * @author Cristiano Di Bari
 */

#ifndef OAUTH_H
#define OAUTH_H

void oauth_get_user_token(char *username, char *password, char *token_endpoint, char *client_id, char *client_secret, char **token);

void oauth_exchange_user_token(char *admin_token, char *target_username, char *token_endpoint, char *client_id, char *client_secret, char **token);

#endif // OAUTH_H
