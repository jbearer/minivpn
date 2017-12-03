#pragma once

#include <inttypes.h>
#include <netinet/in.h>
#include <stdint.h>

#define PRIip PRIu32
#define PRIport PRIu16

#define hton_port(p) htons(p)
#define hton_ip(i) htonl(i)
#define ntoh_port(p) ntohs(p)
#define ntoh_ip(i) ntohl(i)
