#pragma once

#include <stdbool.h>

#include "inet.h"

#define FILE_PATH_SIZE 100
#define PASSWORD_SIZE 100
#define SERVER_DEFAULT_CLI_SOCKET "minivpn-server-socket"

int server_start(const char *cert_file, const char *pkey_file, const char *passwd_db,
                 const char *_pkey_password, const char *cli_socket,
                 in_addr_t ip, in_port_t tcp_port, in_port_t _udp_port,
                 in_addr_t network, in_addr_t netmask);

bool server_ping(const char *sock);
bool server_stop(const char *sock);
