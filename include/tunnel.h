/**
 * \file
 *
 * Low-level API for secure network tunnels.
 *
 * This module provides an interface for creating secure network tunnels using the TUN interface.
 * All traffic over the tunnels is encrypted using AES, signed with a SHA-256 HMAC, and sent to the
 * peer tunnel via a UDP socket. The peer decrypts the packet and injects it into the kernel's
 * routing system. This module is used by the higher-level client and server daemons to forward
 * network traffic between a client and a VPN.
 */

#pragma once

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>

#include "inet.h"

/**
 * The size (in bytes) of the session key used to encrypt and sign packets.
 */
#define TUNNEL_KEY_SIZE 32

/**
 * The size (in bytes) of the initialization vector used to encrypt packets.
 */
#define TUNNEL_IV_SIZE 16

/**
 * The maximum number of tunnels supported at a given time.
 */
#define MAX_TUNNELS 128

struct __tunnel_server;

/**
 * \brief Opaque object encapsulating the state required by a tunnel server.
 *
 * \detail The server is responsible for reading incoming packets from the UDP port and forwarding
 * them to the appropriate tunnel for validation and decryption.
 */
typedef struct __tunnel_server tunnel_server;


struct __tunnel;

/**
 * \brief Opaque object encapsulating the state required by a single tunnel.
 */
typedef struct __tunnel tunnel;

/**
 * \brief The type of an tunnel identifier which is unique to a given server.
 *
 * \detail A tunnel's ID is similar to a port, in that it is how a peer wishing to connect to a
 * tunnel specifies which tunnel to connect to.
 */
typedef uint32_t tunnel_id_t;

/**
 * \brief printf() format specifier for tunnel IDs.
 */
#define PRItunid PRIu32

/**
 * \brief Convert a tunnel ID from host to network byte order.
 */
tunnel_id_t hton_tunnel_id(tunnel_id_t);

/**
 * \brief Convert a tunnel ID from network to host byte order.
 */
tunnel_id_t ntoh_tunnel_id(tunnel_id_t);

/**
 * \brief Allocate, initialize, and start a tunnel server.
 *
 * \param port UDP port to use for communication with a peer server.
 */
tunnel_server *tunnel_server_new(in_port_t port);

/**
 * \brief Get a tunnel owned by a tunnel_server.
 */
tunnel *tunnel_server_get(tunnel_server *, tunnel_id_t);

/**
 * \brief Stop a tunnel server and free its resources, including any running tunnels.
 */
void tunnel_server_delete(tunnel_server *);

/**
 * \brief Allocate and initialize a new tunnel.
 *
 * \detail The tunnel is created in a disconnected, offline state. In order to connect the tunnel to
 * a peer and begin forwarding traffic, tunnel_set_key(), tunnel_set_iv(), and tunnel_connect() must
 * be called to connect the tunnel, and tunnel_loop() must be called to start the tunnel.
 *
 * \return A pointer to the tunnel, or NULL if allocation or initialization fails.
 *
 * \param server Server which the tunnel will be attached to.
 */
tunnel *tunnel_new(tunnel_server *server);

/**
 * \brief Set the session key.
 *
 * \detail This method must be called before tunnel_loop(). It may be called more than once to
 * change the key mid-session.
 *
 * \return true on success, false on failure.
 */
bool tunnel_set_key(tunnel *, const unsigned char *key);

/**
 * \brief Set the initialization vector.
 *
 * \detail This method must be called before tunnel_loop(). It may be called more than once to
 * change the initialization vector mid-session.
 *
 * \return true on success, false on failure.
 */
bool tunnel_set_iv(tunnel *, const unsigned char *iv);

/**
 * Get an identifier which can be used by a peer to uniquely specify this tunnel.
 */
tunnel_id_t tunnel_id(tunnel *);

/**
 * Get the identifier of a tunnel's peer. Only valid after tunnel_connect.
 */
tunnel_id_t tunnel_peer(tunnel *);

/**
 * \brief Connect a tunnel to a peer endpoint.
 *
 * \detail This function must be called before tunnel_loop().
 *
 * \return true on success, false on failure.
 *
 * \param tunnel Tunnel to connect.
 * \param peer_ip IP address of peer server.
 * \param peer_port UDP port of peer server.
 * \param peer_tunnel ID of peer tunnel withing the server specified by peer_ip and peer_port.
 */
bool tunnel_connect(tunnel *, in_addr_t peer_ip, in_port_t peer_port, tunnel_id_t peer_tunnel);

/**
 * \brief Create a routing table entry which directs traffic to the specified network through the
 * given tunnel.
 *
 * \return true on success, false on error.
 */
bool tunnel_route(tunnel *, in_addr_t network, in_addr_t netmask);

/**
 * \brief Begin forwarding traffic from the tunnel to the network and vice versa.
 * \detail This function blocks until tunnel_stop is called.
 */
void tunnel_loop(tunnel *);

/**
 * \brief Break out of tunnel_loop(). This function is thread-safe.
 */
void tunnel_stop(tunnel *);

/**
 * \brief Free resources associated with a tunnel.
 *
 * \detail If the given tunnel is running (i.e. tunnel_loop() has been called) the tunnel is stopped
 * before deallocating resources, as if by tunnel_stop().
 */
void tunnel_delete(tunnel *);
