#include <ncurses.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include <sqlite3.h>

#include "debug.h"
#include "password.h"

#define SHA256_SIZE (256/8)

void prompt(const char *msg, char *response, size_t length)
{
  printf("%s ", msg);
  fgets(response, length, stdin);
  size_t l = strlen(response);
  if (response[l - 1] == '\n') {
    response[l - 1] = '\0';
  }
}

void prompt_password(const char *msg, char *password, size_t length)
{
  noecho();
  prompt(msg, password, length);
  echo();
}

static void close_module()
{
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OPENSSL_config(NULL);
}

static void init_module()
{
  static bool first_call = true;
  if (!__sync_bool_compare_and_swap(&first_call, true, false)) {
    return;
  }

  sqlite3_config(SQLITE_CONFIG_SERIALIZED);

  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OPENSSL_config(NULL);
  atexit(close_module);
}

static bool sha256(const unsigned char *salted_password, size_t length, unsigned char *hash)
{
  SHA256_CTX ctx;

  if (SHA256_Init(&ctx) != 1) {
    ERR_print_errors_fp(stderr);
    return false;
  }

  if (SHA256_Update(&ctx, salted_password, length) != 1) {
    ERR_print_errors_fp(stderr);
    return false;
  }

  if (SHA256_Final(hash, &ctx) != 1) {
    ERR_print_errors_fp(stderr);
    return false;
  }

  return true;
}

passwd_db_conn *passwd_db_connect(const char *file)
{
  init_module();

  sqlite3 *sql;
  if (sqlite3_open(file, &sql) != SQLITE_OK) {
    debug("error opening database at %s: %s", file, sqlite3_errmsg(sql));
    return NULL;
  }

  static const char *schema =
    "CREATE TABLE IF NOT EXISTS users("
      "name TEXT PRIMARY KEY,"
      "salt TEXT NOT NULL,"
      "hash BLOB NOT NULL"
    ")";

  if (sqlite3_exec(sql, schema, NULL, NULL, NULL) != SQLITE_OK) {
    debug("error creating schema: %s", sqlite3_errmsg(sql));
    passwd_db_close(sql);
    return NULL;
  }

  return sql;
}

bool passwd_db_close(passwd_db_conn *sql)
{
  if (sqlite3_close(sql) != SQLITE_OK) {
    debug("error closing database: %s", sqlite3_errmsg(sql));
    return false;
  }
  return true;
}

bool passwd_db_validate(passwd_db_conn *sql , const char *username, const char *password)
{
  static const char *select_user = "SELECT salt, hash FROM users WHERE name = ?";
  sqlite3_stmt *stmt;

  bool result = false;

  if (sqlite3_prepare_v2(sql, select_user, -1, &stmt, NULL) != SQLITE_OK) {
    debug("error preparing statement %s: %s\n", select_user, sqlite3_errmsg(sql));
    return false;
  }

  if (sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC) != SQLITE_OK) {
    debug("error binding argument %s: %s\n", username, sqlite3_errmsg(sql));
    goto err_bind;
  }

  if (sqlite3_step(stmt) != SQLITE_ROW) {
    debug("error finding user %s: %s\n", username, sqlite3_errmsg(sql));
    goto err_step;
  }

  size_t password_size = strlen(password);
  size_t salted_password_size = password_size + SALT_SIZE;
  unsigned char *salted_password = (unsigned char *)malloc(salted_password_size);
  bzero(salted_password, salted_password_size);
  unsigned char *salt = salted_password + password_size;
  strcpy((char *)salted_password, password);
  strncpy((char *)salt, (char *)sqlite3_column_text(stmt, 0), SALT_SIZE);
  const unsigned char *hash = sqlite3_column_blob(stmt, 1);

  unsigned char computed_hash[SHA256_SIZE];
  if (!sha256(salted_password, salted_password_size, computed_hash)) {
    debug("error computing SHA256\n");
    goto err_sha;
  }

  result = memcmp(hash, computed_hash, SHA256_SIZE) == 0;

err_sha:
  free(salted_password);
err_step:
err_bind:
 if (sqlite3_finalize(stmt) != SQLITE_OK) {
    debug("error finalizing select users statement: %s\n", sqlite3_errmsg(sql));
  }

  return result;
}

bool passwd_db_add(passwd_db_conn *sql, const char *username, const char *password, const char *salt)
{
  static const char *add_user = "INSERT INTO users (name, hash, salt) VALUES (?, ?, ?)";

  bool result = false;

  size_t password_size = strlen(password);
  size_t salted_password_size = password_size + SALT_SIZE;
  unsigned char *salted_password = (unsigned char *)malloc(salted_password_size);
  bzero(salted_password, salted_password_size);
  strcpy((char *)salted_password, password);
  strncpy((char *)salted_password + password_size, salt, SALT_SIZE);
  unsigned char hash[SHA256_SIZE];
  if (!sha256(salted_password, salted_password_size, hash)) {
    debug("error computing SHA256\n");
    goto err_sha;
  }

  sqlite3_stmt *stmt;
  if (sqlite3_prepare_v2(sql, add_user, -1, &stmt, NULL) != SQLITE_OK) {
    debug("error preparing statement %s: %s\n", add_user, sqlite3_errmsg(sql));
    goto err_prepare;
  }

  if (sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC) != SQLITE_OK) {
    debug("error binding name %s: %s\n", username, sqlite3_errmsg(sql));
    goto err_bind;
  }

  if (sqlite3_bind_blob(stmt, 2, hash, SHA256_SIZE, SQLITE_STATIC) != SQLITE_OK) {
    debug("error binding hash: %s\n", sqlite3_errmsg(sql));
    goto err_bind;
  }

  if (sqlite3_bind_text(stmt, 3, salt, SALT_SIZE, SQLITE_STATIC) != SQLITE_OK) {
    debug("error binding salt %s: %s\n", salt, sqlite3_errmsg(sql));
    goto err_bind;
  }

  if (sqlite3_step(stmt) != SQLITE_DONE) {
    debug("error adding user %s: %s\n", username, sqlite3_errmsg(sql));
    goto err_step;
  }

  result = true;

err_step:
  sqlite3_reset(stmt);
err_bind:
  if (sqlite3_finalize(stmt) != SQLITE_OK) {
    debug("error finalizing select users statement: %s\n", sqlite3_errmsg(sql));
  }
err_prepare:
err_sha:
  free(salted_password);

  return result;
}
