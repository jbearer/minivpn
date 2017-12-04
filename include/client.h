#pragma once

#include <stdbool.h>

#include "inet.h"

#define CLIENT_DEFAULT_CLI_SOCKET "minivpn-client-socket"

int client_start(const unsigned char *key, const unsigned char *iv, const char *ca_crt,
                 const char *cli_socket, in_addr_t server_ip, in_port_t server_port,
                 in_addr_t client_ip, in_port_t udp_port, in_addr_t network, in_addr_t netmask);

bool client_ping(const char *sock);
bool client_stop(const char *sock);
