#pragma once

#include <stdbool.h>
#include <stdlib.h>

#include <sqlite3.h>

#define SALT_SIZE 32

void prompt(const char *msg, char *response, size_t length);
void prompt_password(const char *msg, char *password, size_t password_length);

typedef sqlite3 passwd_db_conn;

passwd_db_conn *passwd_db_connect(const char *file);
bool passwd_db_validate(passwd_db_conn *, const char *username, const char *password);
bool passwd_db_add(passwd_db_conn *, const char *username, const char *password, const char *salt);
bool passwd_db_close(passwd_db_conn *);
