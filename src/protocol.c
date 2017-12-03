#include <arpa/inet.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#include "protocol.h"

static void init_session_to_network_byte_order(minivpn_init_session *p)
{
    p->client_ip = htonl(p->client_ip);
    p->client_port = htons(p->client_port);
    p->client_network = htonl(p->client_network);
    p->client_netmask = htonl(p->client_netmask);
}

void minivpn_to_network_byte_order(minivpn_packet *pkt)
{
    switch (pkt->type) {
    case MINIVPN_INIT_SESSION:
        init_session_to_network_byte_order((minivpn_init_session *)pkt->data);
        break;
    default:
        fprintf(stderr, "unrecognized packet type %" PRIu16 "\n", pkt->type);
    }

    pkt->length = htonl(pkt->length);
    pkt->type = htons(pkt->type);
}

static void init_session_to_host_byte_order(minivpn_init_session *p)
{
    p->client_ip = ntohl(p->client_ip);
    p->client_port = ntohs(p->client_port);
    p->client_network = ntohl(p->client_network);
    p->client_netmask = ntohl(p->client_netmask);
}

void minivpn_to_host_byte_order(minivpn_packet *pkt)
{
    pkt->length = ntohl(pkt->length);
    pkt->type = ntohs(pkt->type);

    switch (pkt->type) {
    case MINIVPN_INIT_SESSION:
        init_session_to_host_byte_order((minivpn_init_session *)pkt->data);
        break;
    default:
        fprintf(stderr, "unrecognized packet type %" PRIu16 "\n", pkt->type);
    }
}
