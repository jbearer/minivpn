/**
 * \file
 *
 * API for controlling the MiniVPN server daemon.
 *
 * This module provides a C-level interface for starting, interacting with, and stopping a MiniVPN
 * server. The src/server/ directory also contains a set of stand-alone programs which implement a
 * command-line interface for each of the functions defined here. The CLI programs use a Unix-domain
 * TCP socket for communicating with a running server daemon.
 */

#pragma once

#include <stdbool.h>

#include "inet.h"

/**
 * \brief Maximum file path size for CLI programs.
 */
#define FILE_PATH_SIZE 100

/**
 * \brief Maximum password size for CLI programs.
 */
#define PASSWORD_SIZE 100

/**
 * Default Unix-domain socket address used by the CLI programs to communicate with the client.
 */
#define SERVER_DEFAULT_CLI_SOCKET "minivpn-server-socket"

/**
 * \brief The main function of the server daemon.
 *
 * \detail This function starts a server, listens for and accepts client connections, and forwards
 * network traffic to and from clients. It blocks until the server shuts down.
 *
 * \return 0 if the server exited cleanly or nonzero if an error ocurred.
 *
 * \param cert_file SSL certificate file to send to clients for verification.
 * \param pkey_file RSA private key used to encrypt the certificate.
 * \param passwd_db File path of SQLite3 database where usernames and passwords are stored.
 * \param pkey_password Null-terminated password for RSA private key.
 * \param cli_socket Unix-domain abstract socket address to use for inter-process communication with
 * CLI commands.
 * \param tcp_port TCP port on which to listen for client connections.
 * \param udp_port UDP port to use for secure tunnels.
 * \param network Network prefix of the VPN.
 * \param netmask Netmask for the VPN.
 */
int server_start(const char *cert_file, const char *pkey_file, const char *passwd_db,
                 const char *pkey_password, const char *cli_socket,
                 in_port_t tcp_port, in_port_t udp_port, in_addr_t network, in_addr_t netmask);

/**
 * \brief Check the status of the server.
 *
 * \return true if there is a server daemon running and accepting CLI commands over the given Unix-
 * domain socket, false otherwise.
 *
 * \param sock Unix-domain abstract socket address where the server is serving CLI commands.
 */
bool server_ping(const char *sock);

/**
 * \brief Shut down a server daemon.
 *
 * \detail All clients are sent a session termination message, and then the sessions are terminated
 * and the daemon exits.
 *
 * \return true if the server was successfully stopped, false otherwise.
 *
 * \param sock Unix-domain abstract socket address where the client is serving CLI commands.
 */
bool server_stop(const char *sock);
