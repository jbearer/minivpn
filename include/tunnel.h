#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "inet.h"

#define TUNNEL_KEY_SIZE 32
#define TUNNEL_IV_SIZE 16
#define MAX_TUNNELS 128

struct __tunnel;
typedef struct __tunnel tunnel;

/**
 * Allocate and initialize a new tunnel. Return a pointer to the tunnel, or NULL if allocation or
 * initialization fails.
 */
tunnel *tunnel_new(const unsigned char *key, const unsigned char *iv,
                   in_addr_t peer_ip, in_port_t peer_port, in_port_t local_port);

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
