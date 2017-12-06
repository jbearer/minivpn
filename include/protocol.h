#pragma once

#include <stdint.h>

#include <openssl/ssl.h>

#include "inet.h"
#include "password.h"
#include "tunnel.h"

#define MINIVPN_DATA_SIZE 500
#define MINIVPN_USERNAME_SIZE 100
#define MINIVPN_PASSWORD_SIZE 100

#define MINIVPN_PKT_SERVER_HANDSHAKE    0
#define __minivpn_typesize_0            sizeof(minivpn_pkt_server_handshake)

#define MINIVPN_PKT_CLIENT_HANDSHAKE    1
#define __minivpn_typesize_1            sizeof(minivpn_pkt_client_handshake)

#define MINIVPN_PKT_ACK                 2
#define __minivpn_typesize_2            0

#define MINIVPN_PKT_DETACH              3
#define __minivpn_typesize_3            0

#define MINIVPN_PKT_UPDATE_KEY          4
#define __minivpn_typesize_4            sizeof(minivpn_pkt_update_key)

#define MINIVPN_PKT_UPDATE_IV           5
#define __minivpn_typesize_5            sizeof(minivpn_pkt_update_iv)

#define MINIVPN_PKT_ERROR               99
#define __minivpn_typesize_99           sizeof(minivpn_pkt_error)

#define MINIVPN_PKT_ANY                 100
#define __minivpn_typesize_100          sizeof(minivpn_packet)

typedef struct {
  uint16_t    type;
  uint32_t    length;
  char        data[MINIVPN_DATA_SIZE];
} minivpn_packet;

#define MINIVPN_OK                      0
#define MINIVPN_ERR                     1
#define MINIVPN_ERR_COMM                2
#define MINIVPN_ERR_PERM                3
#define MINIVPN_ERR_SERV                4
#define MINIVPN_ERR_EOF                 5
#define MINIVPN_ERR_TIMEOUT             6

typedef struct {
  uint16_t    code;
} minivpn_pkt_error;

const char *minivpn_errstr(uint16_t code);

/*
 * SESSION INITIALIZATION
 * Immediately after successful SSL handshake
 *
 * Protocol:
 * client sends minivpn_pkt_client_handshake
 * server authenticates client and creates tunnel
 * server sends minivpn_pkt_server_handshake
 * client creates tunnel
 * client acks
 */

typedef struct {
  unsigned char  key[TUNNEL_KEY_SIZE];
  unsigned char  iv[TUNNEL_IV_SIZE];
  in_addr_t      client_ip;
  in_port_t      client_port;
  tunnel_id_t    client_tunnel;
  in_addr_t      client_network;
  in_addr_t      client_netmask;
  char           username[MINIVPN_USERNAME_SIZE];
  char           password[MINIVPN_PASSWORD_SIZE];
} minivpn_pkt_client_handshake;

typedef struct {
  in_addr_t    server_ip;
  in_port_t    server_port;
  tunnel_id_t  server_tunnel;
  in_addr_t    server_network;
  in_addr_t    server_netmask;
} minivpn_pkt_server_handshake;

tunnel *minivpn_client_handshake(SSL *ssl, tunnel_server *tunserv,
                                 const unsigned char *key, const unsigned char *iv,
                                 uint32_t client_ip, uint16_t client_port,
                                 uint32_t client_network, uint32_t client_netmask,
                                 const char *username, const char *password);

tunnel *minivpn_server_handshake(SSL *ssl, tunnel_server *tunserv, passwd_db_conn *pwddb,
                                 uint32_t server_ip, uint16_t server_port,
                                 uint32_t server_network, uint32_t server_netmask);

/*
 * SESSION KEY UPDATE
 *
 * Protocol:
 * client sends new information
 * server acks
 */

typedef struct {
  unsigned char key[TUNNEL_KEY_SIZE];
} minivpn_pkt_update_key;

typedef struct {
  unsigned char iv[TUNNEL_IV_SIZE];
} minivpn_pkt_update_iv;

uint16_t minivpn_update_key(SSL *ssl, tunnel *tun, const unsigned char *key);
uint16_t minivpn_update_iv(SSL *ssl, tunnel *tun, const unsigned char *iv);

/*
 * SESSION TERMINATION
 *
 * Protocol:
 * closing end sends minivpn_pkt_detach, closes connections, and releases resources
 * receiving end closes connections and releases resources
 */
uint16_t minivpn_detach(SSL *ssl);

/*
 * Low-level communication
 */
void minivpn_to_network_byte_order(minivpn_packet *pkt);
void minivpn_to_host_byte_order(minivpn_packet *pkt);
int minivpn_avail(SSL *ssl);
uint16_t minivpn_send_raw(SSL *ssl, uint16_t type, const void *data, size_t data_len);
uint16_t minivpn_recv_raw(SSL *ssl, uint16_t type, void *data, size_t data_len);

#define __minivpn_typesize(type) __minivpn_typesize_ ## type
#define minivpn_send(ssl, type, data) minivpn_send_raw(ssl, type, data, __minivpn_typesize(type))
#define minivpn_recv(ssl, type, data) minivpn_recv_raw(ssl, type, data, __minivpn_typesize(type))

#define minivpn_ack(ssl) minivpn_send(ssl, MINIVPN_PKT_ACK, NULL)
#define minivpn_await_ack(ssl) minivpn_recv(ssl, MINIVPN_PKT_ACK, NULL)

uint16_t minivpn_err(SSL *ssl, uint16_t code);
