#pragma once

#include <stdint.h>

#include <openssl/ssl.h>

#include "tunnel.h"

#define MINIVPN_DATA_SIZE 500

#define MINIVPN_PKT_SERVER_HANDSHAKE 0
#define __minivpn_typesize_0 sizeof(minivpn_pkt_server_handshake)

#define MINIVPN_PKT_CLIENT_HANDSHAKE 1
#define __minivpn_typesize_1 sizeof(minivpn_pkt_client_handshake)

#define MINIVPN_PKT_ACK              2
#define __minivpn_typesize_2 0

typedef struct {
  uint16_t    type;
  uint32_t    length;
  char        data[MINIVPN_DATA_SIZE];
} minivpn_packet;

/*
 * SESSION INITIALIZATION
 * Immediately after successful SSL handshake
 *
 * Protcol:
 * client sends minivpn_pkt_client_handshake to server
 * server authenticates client and creates tunnel
 * server sends minivpn_pkt_server_handshake to client
 * client creates tunnel
 * client sends minivpn_pkt_ack to server
 */

typedef struct {
  unsigned char key[TUNNEL_KEY_SIZE];
  unsigned char iv[TUNNEL_IV_SIZE];
  uint32_t      client_ip;
  uint16_t      client_port;
  uint32_t      client_network;
  uint32_t      client_netmask;
} minivpn_pkt_client_handshake;

typedef struct {
  uint32_t    server_ip;
  uint16_t    server_port;
  uint32_t    server_network;
  uint32_t    server_netmask;
} minivpn_pkt_server_handshake;

tunnel *minivpn_client_handshake(SSL *ssl, const unsigned char *key, const unsigned char *iv,
                                 uint32_t client_ip, uint16_t client_port,
                                 uint32_t client_network, uint32_t client_netmask);

tunnel *minivpn_server_handshake(SSL *ssl, uint32_t server_ip, uint16_t server_port,
                                 uint32_t server_network, uint32_t server_netmask);

/*
 * Low-level communication
 */
void minivpn_to_network_byte_order(minivpn_packet *pkt);
void minivpn_to_host_byte_order(minivpn_packet *pkt);
bool minivpn_send_raw(SSL *ssl, uint16_t type, const void *data, size_t data_len);
bool minivpn_recv_raw(SSL *ssl, uint16_t type, void *data, size_t data_len);

#define __minivpn_typesize(type) __minivpn_typesize_ ## type
#define minivpn_send(ssl, type, data) minivpn_send_raw(ssl, type, data, __minivpn_typesize(type))
#define minivpn_recv(ssl, type, data) minivpn_recv_raw(ssl, type, data, __minivpn_typesize(type))

#define minivpn_ack(ssl) minivpn_send(ssl, MINIVPN_PKT_ACK, NULL)
#define minivpn_await_ack(ssl) minivpn_recv(ssl, MINIVPN_PKT_ACK, NULL)
