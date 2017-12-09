/**
 * \file
 *
 * API for communicating with a MiniVPN password database.
 */

#pragma once

#include <stdbool.h>
#include <stdlib.h>

#include <sqlite3.h>

#define SALT_SIZE 32

/**
 * \brief Convenience function for receiving input from the user via a terminal.
 */
void prompt(const char *msg, char *response, size_t length);

/**
 * \brief Convenience function for receiving input from the user via a terminal.
 * \detail This function turns off echoing while the user enters their input, and is thus suitable
 * for accepting passwords.
 *
 * \bug Currently, echoing is not turned off.
 */
void prompt_password(const char *msg, char *password, size_t password_length);

/// State required to manipulate the password database.
typedef sqlite3 passwd_db_conn;

/**
 * \brief Open a connection to the database at the given path.
 *
 * \return An open databse connection, or NULL on failure.
 */
passwd_db_conn *passwd_db_connect(const char *file);

/**
 * \brief Validate a user in the given database.
 *
 * \return true if the user is authenticated, false otherwise.
 */
bool passwd_db_validate(passwd_db_conn *, const char *username, const char *password);

/**
 * \brief Add a user to the given database.
 *
 * \return true if the user was successfully added, false otherwise.
 */
bool passwd_db_add(passwd_db_conn *, const char *username, const char *password, const char *salt);

/**
 * \brief Close a databse connection and release resources.
 */
bool passwd_db_close(passwd_db_conn *);
