/**
 * \file
 *
 * API for controlling the MiniVPN client daemon.
 *
 * This module provides a C-level interface for starting, interacting with, and stopping a MiniVPN
 * client. The src/client/ directory also contains a set of stand-alone programs which implement a
 * command-line interface for each of the functions defined here. The CLI programs use a Unix-domain
 * TCP socket for communicating with a running client daemon.
 */

#pragma once

#include <stdbool.h>

#include "inet.h"

/**
 * Default Unix-domain socket address used by the CLI programs to communicate with the client.
 */
#define CLIENT_DEFAULT_CLI_SOCKET "minivpn-client-socket"

/**
 * \brief The main function of the client daemon.
 *
 * \detail This function starts a client, connects to a minivpn server, and begins forwarding
 * network traffic to and from the VPN. It blocks until the client disconnects.
 *
 * \return 0 if the client exited cleanly or nonzero if an error ocurred.
 *
 * \param key The initial session key. Must point to an array of at least #TUNNEL_KEY_SIZE bytes.
 * \param iv The initialization vector to use for encryption. Must point to an array of at least
 * #TUNNEL_IV_SIZE bytes.
 * \param ca_crt A file containing certificate authority certificates to trust when verifying the
 * identity of the server.
 * \param username A null-terminated string containing the username to authenticate as.
 * \param password A null-terminated string containing the password to use for authentication.
 * \param cli_socket Unix-domain abstract socket address to use for inter-process communication with
 * CLI commands.
 * \param server_ip IP address of minivpn server.
 * \param server_port TCP port of minivpn server.
 * \param udp_port UDP port to use on the client side for secure tunnel.
 * \param network Client-side network prefix.
 * \param netmask Client-side netmask.
 */
int client_start(const unsigned char *key, const unsigned char *iv, const char *ca_crt,
                 const char *username, const char *password,
                 const char *cli_socket, in_addr_t server_ip, in_port_t server_port,
                 in_port_t udp_port, in_addr_t network, in_addr_t netmask);

/**
 * \brief Check the status of the client.
 *
 * \return true if there is a client daemon running and accepting CLI commands over the given Unix-
 * domain socket, false otherwise.
 *
 * \param sock Unix-domain abstract socket address where the client is serving CLI commands.
 */
bool client_ping(const char *sock);

/**
 * \brief Disconnect and stop a client daemon.
 *
 * \return true if the client was successfully stopped, false otherwise.
 *
 * \param sock Unix-domain abstract socket address where the client is serving CLI commands.
 */
bool client_stop(const char *sock);

/**
 * \brief Change the current session key.
 *
 * \detail Instructs both the client and the server to use a different session key for encryption.
 * It is good practice to update the session key periodically for long-running sessions. The new key
 * is sent over an SSL-secured socket.
 *
 * \return true if the key was successfully updated on both the client and the server, false
 * otherwise.
 *
 * \param sock Unix-domain abstract socket address where the client is serving CLI commands.
 * \param key New session key. Must point to an array of at least #TUNNEL_KEY_SIZE bytes.
 */
bool client_update_key(const char *sock, const unsigned char *key);

/**
 * \brief Change the initialization vector on both the server and the client.
 *
 * \detail This function is identical to client_update_key() except that it updates the
 * initialization vector, not the key.
 *
 * \return true if the update was successful, false otherwise.
 *
 * \param sock Unix-domain abstract socket address where the client is serving CLI commands.
 * \param iv New initialization vector. Must point to an array of at least #TUNNEL_IV_SIZE bytes.
 */
bool client_update_iv(const char *sock, const unsigned char *iv);

/**
 * \brief Read the contents of a file into a session key object.
 *
 * \detail This function opens the given file in read-only mode and reads the first #TUNNEL_KEY_SIZE
 * bytes into the buffer pointed to by key. If there are not enough bytes in the file, the function
 * fails.
 *
 * \return true on success, false on failure.
 *
 * \param file Null-terminated file path.
 * \param key Output buffer for the session key. Must point to an array of at least #TUNNEL_KEY_SIZE
 * bytes.
 */
bool client_read_key(const char *file, unsigned char *key);

/**
 * \brief Read the contents of a file into an initialization vector object.
 *
 * \detail This function opens the given file in read-only mode and reads the first #TUNNEL_IV_SIZE
 * bytes into the buffer pointed to by key. If there are not enough bytes in the file, the function
 * fails.
 *
 * \return true on success, false on failure.
 *
 * \param file Null-terminated file path.
 * \param iv Output buffer for the initialization vector. Must point to an array of at least
 * #TUNNEL_IV_SIZE bytes.
 */
bool client_read_iv(const char *file, unsigned char *iv);
