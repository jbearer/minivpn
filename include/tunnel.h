#pragma once

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>

#include "inet.h"

#define TUNNEL_KEY_SIZE 32
#define TUNNEL_IV_SIZE 16
#define MAX_TUNNELS 128

struct __tunnel_server;
typedef struct __tunnel_server tunnel_server;

struct __tunnel;
typedef struct __tunnel tunnel;

typedef uint32_t tunnel_id_t;
#define PRItunid PRIu32

tunnel_id_t hton_tunnel_id(tunnel_id_t);
tunnel_id_t ntoh_tunnel_id(tunnel_id_t);

/**
 * Allocate, initialize, and start a tunnel server.
 */
tunnel_server *tunnel_server_new(in_port_t port);

/**
 * Stop a tunnel server and free its resources, including any running tunnels.
 */
void tunnel_server_delete(tunnel_server *);

/**
 * Allocate and initialize a new tunnel. Return a pointer to the tunnel, or NULL if allocation or
 * initialization fails.
 */
tunnel *tunnel_new(tunnel_server *server, const unsigned char *key, const unsigned char *iv);

/**
 * Get an identifier which can be used by a peer to uniquely specify this tunnel.
 */
tunnel_id_t tunnel_id(tunnel *);

/**
 * Connect a tunnel to a peer endpoint. This function must be called before tunnel_loop;
 */
bool tunnel_connect(tunnel *, in_addr_t peer_ip, in_port_t peer_port, tunnel_id_t peer_tunnel);

/**
 * Create a routing table entry which directs traffic to the specified network through the given
 * tunnel. Returns true on success, false on error.
 */
bool tunnel_route(tunnel *, in_addr_t network, in_addr_t netmask);

/**
 * Begin forwarding traffic from the tunnel to the network and vice versa. This function blocks
 * until tunnel_stop is called.
 */
void tunnel_loop(tunnel *);

/**
 * Break out of tunnel_loop. This function is thread-safe.
 */
void tunnel_stop(tunnel *);

/**
 * Free resources associated with a tunnel. If the given tunnel is running (i.e. tunnel_loop has
 * been called) the tunnel is stopped before deallocating resources, as if by tunnel_stop.
 */
void tunnel_delete(tunnel *);
