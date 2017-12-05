#pragma once

#include <stdbool.h>

#include "inet.h"

#define CLIENT_DEFAULT_CLI_SOCKET "minivpn-client-socket"

int client_start(const unsigned char *key, const unsigned char *iv, const char *ca_crt,
                 const char *username, const char *password,
                 const char *cli_socket, in_addr_t server_ip, in_port_t server_port,
                 in_addr_t client_ip, in_port_t udp_port, in_addr_t network, in_addr_t netmask);

bool client_ping(const char *sock);
bool client_stop(const char *sock);
bool client_update_key(const char *sock, const unsigned char *key);
bool client_update_iv(const char *sock, const unsigned char *iv);
bool client_read_key(const char *file, unsigned char *key);
bool client_read_iv(const char *file, unsigned char *iv);
