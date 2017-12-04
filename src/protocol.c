#include <arpa/inet.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "debug.h"
#include "inet.h"
#include "protocol.h"
#include "tunnel.h"

tunnel *minivpn_client_handshake(SSL *ssl, const unsigned char *key, const unsigned char *iv,
                                 uint32_t client_ip, uint16_t client_port,
                                 uint32_t client_network, uint32_t client_netmask)
{
  minivpn_pkt_client_handshake client_init;
  memcpy(&client_init.key, key, TUNNEL_KEY_SIZE);
  memcpy(&client_init.iv, iv, TUNNEL_IV_SIZE);
  client_init.client_ip = client_ip;
  client_init.client_port = client_port;
  client_init.client_network = client_network;
  client_init.client_netmask = client_netmask;
  if (!minivpn_send(ssl, MINIVPN_PKT_CLIENT_HANDSHAKE, &client_init)) {
    debug("unable to send session initialization packet\n");
    return NULL;
  }

  minivpn_pkt_server_handshake server_init;
  if (!minivpn_recv(ssl, MINIVPN_PKT_SERVER_HANDSHAKE, &server_init)) {
    debug("did not receive handshake response from server\n");
    return NULL;
  }

  tunnel *tun = tunnel_new(key, iv, server_init.server_ip, server_init.server_port, client_port);
  if (tun == NULL) {
    debug("error creating tunnel\n");
    return NULL;
  }

  if (!tunnel_route(tun, server_init.server_network, server_init.server_netmask)) {
    debug("error routing tunnel\n");
    tunnel_delete(tun);
    return NULL;
  }

  if (!minivpn_ack(ssl)) {
    debug("unable to acknowledge session, terminating\n");
    tunnel_delete(tun);
    return NULL;
  }

  return tun;
}

tunnel *minivpn_server_handshake(SSL *ssl, uint32_t server_ip, uint16_t server_port,
                                 uint32_t server_network, uint32_t server_netmask)
{
  minivpn_pkt_client_handshake client_init;
  if (!minivpn_recv(ssl, MINIVPN_PKT_CLIENT_HANDSHAKE, &client_init)) {
    debug("unable to read session initialization packet\n");
    return NULL;
  }

  tunnel *tun = tunnel_new(
    client_init.key, client_init.iv, client_init.client_ip, client_init.client_port, server_port);
  if (tun == NULL) {
    debug("could not create tunnel\n");
    return NULL;
  }

  if (!tunnel_route(tun, client_init.client_network, client_init.client_netmask)) {
    debug("could not route tunnel\n");
    tunnel_delete(tun);
    return NULL;
  }

  minivpn_pkt_server_handshake server_init;
  server_init.server_ip = server_ip;
  server_init.server_port = server_port;
  server_init.server_network = server_network;
  server_init.server_netmask = server_netmask;
  if (!minivpn_send(ssl, MINIVPN_PKT_SERVER_HANDSHAKE, &server_init)) {
    debug("could not send session initialization packet\n");
    tunnel_delete(tun);
    return NULL;
  }

  if (!minivpn_await_ack(ssl)) {
    debug("did not receive session acknowledgement from client\n");
    tunnel_delete(tun);
    return NULL;
  }

  return tun;
}

bool minivpn_client_detach(SSL *ssl)
{
  return minivpn_send(ssl, MINIVPN_PKT_CLIENT_DETACH, NULL);
}

static void client_handshake_to_network_byte_order(minivpn_pkt_client_handshake *p)
{
    p->client_ip = hton_ip(p->client_ip);
    p->client_port = hton_port(p->client_port);
    p->client_network = hton_ip(p->client_network);
    p->client_netmask = hton_ip(p->client_netmask);
}

static void server_handshake_to_network_byte_order(minivpn_pkt_server_handshake *p)
{
    p->server_ip = hton_ip(p->server_ip);
    p->server_port = hton_port(p->server_port);
    p->server_network = hton_ip(p->server_network);
    p->server_netmask = hton_ip(p->server_netmask);
}

void minivpn_to_network_byte_order(minivpn_packet *pkt)
{
    switch (pkt->type) {
    case MINIVPN_PKT_CLIENT_HANDSHAKE:
      client_handshake_to_network_byte_order((minivpn_pkt_client_handshake *)pkt->data);
      break;
    case MINIVPN_PKT_SERVER_HANDSHAKE:
      server_handshake_to_network_byte_order((minivpn_pkt_server_handshake *)pkt->data);
      break;
    case MINIVPN_PKT_ACK:
    case MINIVPN_PKT_CLIENT_DETACH:
      break;
    default:
      debug("unrecognized packet type %" PRIu16 "\n", pkt->type);
    }

    pkt->length = htonl(pkt->length);
    pkt->type = htons(pkt->type);
}

static void client_handshake_to_host_byte_order(minivpn_pkt_client_handshake *p)
{
    p->client_ip = ntoh_ip(p->client_ip);
    p->client_port = ntoh_port(p->client_port);
    p->client_network = ntoh_ip(p->client_network);
    p->client_netmask = ntoh_ip(p->client_netmask);
}

static void server_handshake_to_host_byte_order(minivpn_pkt_server_handshake *p)
{
    p->server_ip = ntoh_ip(p->server_ip);
    p->server_port = ntoh_port(p->server_port);
    p->server_network = ntoh_ip(p->server_network);
    p->server_netmask = ntoh_ip(p->server_netmask);
}

void minivpn_to_host_byte_order(minivpn_packet *pkt)
{
    pkt->length = ntohl(pkt->length);
    pkt->type = ntohs(pkt->type);

    switch (pkt->type) {
    case MINIVPN_PKT_CLIENT_HANDSHAKE:
      client_handshake_to_host_byte_order((minivpn_pkt_client_handshake *)pkt->data);
      break;
    case MINIVPN_PKT_SERVER_HANDSHAKE:
      server_handshake_to_host_byte_order((minivpn_pkt_server_handshake *)pkt->data);
      break;
    case MINIVPN_PKT_ACK:
    case MINIVPN_PKT_CLIENT_DETACH:
      break;
    default:
      debug("unrecognized packet type %" PRIu16 "\n", pkt->type);
    }
}

bool minivpn_send_raw(SSL *ssl, uint16_t type, const void *data, size_t data_len)
{
  minivpn_packet pkt;
  pkt.type = type;
  pkt.length = data_len;

  debug("sending packet type=%" PRIu16 ", length=%" PRIu32 "\n", pkt.type, pkt.length);

  if (data) {
    memcpy(&pkt.data, data, pkt.length);
  }
  minivpn_to_network_byte_order(&pkt);

  const char *buf = (const char *)&pkt;
  size_t togo = sizeof(minivpn_packet);
  while (togo > 0) {
    int ret = SSL_write(ssl, buf, togo);
    if (ret > 0) {
      togo -= ret;
      buf += ret;
    } else {
      fprintf(stderr, "%s\n", ERR_error_string(SSL_get_error(ssl, ret), NULL));
      return false;
    }
  }

  return true;
}

bool minivpn_recv_raw(SSL *ssl, uint16_t type, void *data, size_t data_len)
{
  minivpn_packet pkt;
  char *buf = (char *)&pkt;
  size_t togo = sizeof(minivpn_packet);
  while (togo > 0) {
    int ret = SSL_read(ssl, buf, togo);
    if (ret > 0) {
      togo -= ret;
      buf += ret;
    } else {
      fprintf(stderr, "%s\n", ERR_error_string(SSL_get_error(ssl, ret), NULL));
      return false;
    }
  }
  minivpn_to_host_byte_order(&pkt);

  debug("received packet type=%" PRIu16 ", length=%" PRIu32 "\n", pkt.type, pkt.length);

  if (type == MINIVPN_PKT_ANY) {
    memcpy(data, &pkt, data_len);
    return true;
  }

  if (pkt.type != type) {
    debug("received wrong packet type %" PRIu16 " (expected %" PRIu16 ")\n", pkt.type, type);
    return false;
  }

  if (data) {
    memcpy(data, pkt.data, data_len);
  }

  return true;
}
