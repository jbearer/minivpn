/**
 * \file
 *
 * MiniVPN protocol definition for communication between server and clients.
 */

#pragma once

#include <stdint.h>

#include <openssl/ssl.h>

#include "inet.h"
#include "password.h"
#include "tunnel.h"

/**
 * Maximum size in bytes of the data section of a MiniVPN packet.
 */
#define MINIVPN_DATA_SIZE 500

/**
 * Maximum size in bytes of a username string.
 */
#define MINIVPN_USERNAME_SIZE 100

/**
 * Maximum size in bytes of a password string.
 */
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

/**
 * Fixed-size packet capable of containing any MiniVPN message.
 */
typedef struct {
  /// The type of message contained by the packet.
  uint16_t    type;

  /// The length of the data section of the packet.
  uint32_t    length;

  /// Data required by the specific message being sent.
  char        data[MINIVPN_DATA_SIZE];
} minivpn_packet;

#define MINIVPN_OK                      0
#define MINIVPN_ERR                     1
#define MINIVPN_ERR_COMM                2
#define MINIVPN_ERR_PERM                3
#define MINIVPN_ERR_SERV                4
#define MINIVPN_ERR_EOF                 5
#define MINIVPN_ERR_TIMEOUT             6

/// Data section of an error message.
typedef struct {
  /// The type of error that occurred.
  uint16_t    code;
} minivpn_pkt_error;

/**
 * \brief Convert a MiniVPN error code to a human-readable string.
 * \detail All error strings are statically allocated, and so the memory pointed to by the returned
 * string need not be managed by the client.
 */
const char *minivpn_errstr(uint16_t code);

/// Data section of a client handshake message.
typedef struct {
  /// Initial session key.
  unsigned char  key[TUNNEL_KEY_SIZE];

  /// Initial initialization vector.
  unsigned char  iv[TUNNEL_IV_SIZE];

  /// Client-side UDP port to use for secure tunnel.
  in_port_t      client_port;

  /// Client-side tunnel ID.
  tunnel_id_t    client_tunnel;

  /// Client-side network prefix.
  in_addr_t      client_network;

  /// Client-side netmask.
  in_addr_t      client_netmask;

  /// User to authenticate as.
  char           username[MINIVPN_USERNAME_SIZE];

  /// Password to use for authentication.
  char           password[MINIVPN_PASSWORD_SIZE];
} minivpn_pkt_client_handshake;

/// Data section of a server handshake message.
typedef struct {
  /// Server-side UDP port to use for secure tunnel.
  in_port_t    server_port;

  /// Server-side tunnel ID.
  tunnel_id_t  server_tunnel;

  /// Network prefix for the VPN.
  in_addr_t    server_network;

  /// Netmask for the VPN.
  in_addr_t    server_netmask;
} minivpn_pkt_server_handshake;

/**
 * \brief Run the client side of a MiniVPN handshake.
 *
 * \detail The protocol is as follows:
 *    * Client creates tunnel and sends minivpn_pkt_client_handshake
 *    * Server authenticates client, creates tunnel, and connects to client tunnel
 *    * Server sends minivpn_pkt_server_handshake
 *    * Client connects to server tunnel and sends minivpn_pkt_ack
 *
 * \return The newly created tunnel, or NULL if the handshake failed.
 *
 * \param ssl SSL object to use for secure out-of-band communication.
 * \param tunserv Tunnel server in which to create the client tunnel.
 * \param key Initial session key. Must point to an array of at least #TUNNEL_KEY_SIZE bytes.
 * \param iv Initial initialization vector. Must point to an array of at least #TUNNEL_IV_SIZE
 * bytes.
 * \param server_ip IP address of server with which to handshake.
 * \param client_port UDP port to use for secure tunnel.
 * \param client_network Client-side network prefix.
 * \param client_netmask Client-side netmask.
 * \param username Null-terminated username to authenticate as.
 * \param password Null-terminated password for authentication.
 */
tunnel *minivpn_client_handshake(SSL *ssl, tunnel_server *tunserv,
                                 const unsigned char *key, const unsigned char *iv,
                                 in_addr_t server_ip, uint16_t client_port, uint32_t client_network,
                                 uint32_t client_netmask, const char *username, const char *password);

/**
 * \brief Run the client side of a MiniVPN handshake.
 *
 * \detail See minivpn_client_handshake() for details of the protocol.
 *
 * \return A tunnel connected to the client, or NULL if the handshake failed.
 *
 * \param ssl SSL object to use for secure out-of-band communication.
 * \param tunserv Tunnel server in which to create the tunnel.
 * \param pwddb Connection to the database to use for authenticating the client.
 * \param server_port UDP port to use for the secure tunnel.
 * \param server_network Network prefix for the VPN.
 * \param server_netmaks Netmask for the VPN.
 */
tunnel *minivpn_server_handshake(SSL *ssl, tunnel_server *tunserv, passwd_db_conn *pwddb,
                                 uint16_t server_port, uint32_t server_network, uint32_t server_netmask);

/// Data section of a key update request.
typedef struct {
  unsigned char key[TUNNEL_KEY_SIZE];
} minivpn_pkt_update_key;

/// Data section of an initialization vector update request.
typedef struct {
  unsigned char iv[TUNNEL_IV_SIZE];
} minivpn_pkt_update_iv;

/**
 * \brief Update the session key for a tunnel and request a server to do the same.
 *
 * \detail This function should only be called by the client. The server should respond with either
 * minivpn_ack() or minivpn_err().
 *
 * \return MINIVPN_OK on success, or an error code on failure.
 */
uint16_t minivpn_update_key(SSL *ssl, tunnel *tun, const unsigned char *key);

/**
 * \brief Update the initialization vector for a tunnel and request a server to do the same.
 *
 * \detail This function should only be called by the client. The server should respond with either
 * minivpn_ack() or minivpn_err().
 *
 * \return MINIVPN_OK on success, or an error code on failure.
 */
uint16_t minivpn_update_iv(SSL *ssl, tunnel *tun, const unsigned char *iv);

/**
 * \brief Inform a peer that the MiniVPN session is ending.
 *
 * \detail This function can be called by either the client or the server. The peer will not
 * respond, but after sending this message it is safe to close the session and release resources.
 */
uint16_t minivpn_detach(SSL *ssl);

/// Convert all fields of a MiniVPN message from host to network byte order.
void minivpn_to_network_byte_order(minivpn_packet *pkt);

/// Convert all fields of a MiniVPN message from network to host byte order.
void minivpn_to_host_byte_order(minivpn_packet *pkt);

/**
 * \brief Check if any MiniVPN packets are available for immediate reading in the given SSL session.
 *
 * \detail If the return value is nonzero, then a subsequent call to minivpn_recv() will not block.
 *
 * \return 1 if a packet is available, 0 if no packets are available, -1 if the peer has
 * disconnected, or -2 if an error occurred.
 */
int minivpn_avail(SSL *ssl);

/**
 * \brief Send a MiniVPN packet over an SSL connection.
 *
 * \detail The packet will automatically be converted from host to network byte order before
 * sending.
 *
 * \return MINIVPN_OK on success, or an error code on failure.
 *
 * \param ssl SSL session over which to send the packet.
 * \param type Type of message being send.
 * \param data Data to send with the packet.
 * \param data_len Length in bytes of data.
 */
uint16_t minivpn_send_raw(SSL *ssl, uint16_t type, const void *data, size_t data_len);

/**
 * \brief Receive a MiniVPN packet from an SSL connection.
 *
 * \detail The packet will automatically converted from network to hsot byte order upon receiving.
 * This function can be used to receive packets only of a specified type, in which case data should
 * point to the corresponding specific structure. If a packet of a different type is received, an
 * error is raised. Otherwise, by setting type to MINIVPN_PKT_ANY, any packet received will be
 * returned. In this case, data should point to a generic minivpn_pkt structure.
 *
 * \return MINIVPN_OK on success, or an error code on failure.
 */
uint16_t minivpn_recv_raw(SSL *ssl, uint16_t type, void *data, size_t data_len);

#define __minivpn_typesize(type) __minivpn_typesize_ ## type

/// Send a packet of the specified type with the given data section.
#define minivpn_send(ssl, type, data) minivpn_send_raw(ssl, type, data, __minivpn_typesize(type))

/// Receive a packet of the requested type.
#define minivpn_recv(ssl, type, data) minivpn_recv_raw(ssl, type, data, __minivpn_typesize(type))

/// Send a minivpn_ack packet.
#define minivpn_ack(ssl) minivpn_send(ssl, MINIVPN_PKT_ACK, NULL)

/// Block until a minivpn_ack packet is received or an error occurs.
#define minivpn_await_ack(ssl) minivpn_recv(ssl, MINIVPN_PKT_ACK, NULL)

/// Send a minivpn_pkt_err message.
uint16_t minivpn_err(SSL *ssl, uint16_t code);
