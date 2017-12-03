#pragma once

#include <stdint.h>

#include "tunnel.h"

#define MINIVPN_DATA_SIZE 500

#define MINIVPN_INIT_SESSION 0

typedef struct {
    uint16_t    type;
    uint32_t    length;
    char        data[MINIVPN_DATA_SIZE];
} minivpn_packet;

typedef struct {
    unsigned char key[TUNNEL_KEY_SIZE];
    unsigned char iv[TUNNEL_IV_SIZE];
    uint32_t      client_ip;
    uint16_t      client_port;
    uint32_t      client_network;
    uint32_t      client_netmask;
} minivpn_init_session;

void minivpn_to_network_byte_order(minivpn_packet *pkt);
void minivpn_to_host_byte_order(minivpn_packet *pkt);
