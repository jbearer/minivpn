#include <arpa/inet.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "debug.h"
#include "inet.h"
#include "password.h"
#include "protocol.h"
#include "tunnel.h"

tunnel *minivpn_client_handshake(SSL *ssl, tunnel_server *tunserv,
                                 const unsigned char *key, const unsigned char *iv,
                                 in_addr_t server_ip, uint16_t client_port, uint32_t client_network,
                                 uint32_t client_netmask, const char *username, const char *password)
{
  uint16_t err;

  tunnel *tun = tunnel_new(tunserv);
  if (tun == NULL) {
    debug("error creating tunnel\n");
    return NULL;
  }

  minivpn_pkt_client_handshake client_init;
  bzero(&client_init, sizeof(client_init));
  memcpy(&client_init.key, key, TUNNEL_KEY_SIZE);
  memcpy(&client_init.iv, iv, TUNNEL_IV_SIZE);
  client_init.client_port = client_port;
  client_init.client_tunnel = tunnel_id(tun);
  client_init.client_network = client_network;
  client_init.client_netmask = client_netmask;
  strncpy(client_init.username, username, MINIVPN_USERNAME_SIZE - 1);
  strncpy(client_init.password, password, MINIVPN_PASSWORD_SIZE - 1);
  if ((err = minivpn_send(ssl, MINIVPN_PKT_CLIENT_HANDSHAKE, &client_init)) != MINIVPN_OK) {
    debug("unable to send session initialization packet: %s\n", minivpn_errstr(err));
    goto err_free_tun;
  }

  minivpn_pkt_server_handshake server_init;
  if ((err = minivpn_recv(ssl, MINIVPN_PKT_SERVER_HANDSHAKE, &server_init)) != MINIVPN_OK) {
    debug("error receiving server handhsake: %s\n", minivpn_errstr(err));
    goto err_free_tun;
  }

  if (!tunnel_set_key(tun, key)) {
    debug("error setting tunnel key\n");
    goto err_free_tun;
  }
  if (!tunnel_set_iv(tun, iv)) {
    debug("error setting tunnel iv\n");
    goto err_free_tun;
  }
  if (!tunnel_connect(tun, server_ip, server_init.server_port, server_init.server_tunnel)) {
    debug("error connecting tunnel\n");
    goto err_free_tun;
  }
  if (!tunnel_route(tun, server_init.server_network, server_init.server_netmask)) {
    debug("error routing tunnel\n");
    goto err_free_tun;
  }

  if ((err = minivpn_ack(ssl)) != MINIVPN_OK) {
    debug("unable to acknowledge session: %s\n", minivpn_errstr(err));
    goto err_free_tun;
  }

  return tun;

err_free_tun:
  tunnel_delete(tun);
  return NULL;
}

tunnel *minivpn_server_handshake(SSL *ssl, tunnel_server *tunserv, passwd_db_conn *pwddb,
                                 uint16_t server_port, uint32_t server_network,
                                 uint32_t server_netmask)
{
  uint16_t err;

  struct sockaddr_in client_addr;
  socklen_t client_addr_len = sizeof(client_addr);
  int fd = SSL_get_fd(ssl);
  if (getpeername(fd, (struct sockaddr *)&client_addr, &client_addr_len) < 0) {
    perror("getpeername");
    return NULL;
  }
  in_addr_t client_ip = ntoh_ip(client_addr.sin_addr.s_addr);

  minivpn_pkt_client_handshake client_init;
  if ((err = minivpn_recv(ssl, MINIVPN_PKT_CLIENT_HANDSHAKE, &client_init)) != MINIVPN_OK) {
    debug("error receiving client handshake: %s\n", minivpn_errstr(err));
    return NULL;
  }

  if (!passwd_db_validate(pwddb, client_init.username, client_init.password)) {
    debug("client authentication failed\n");
    if ((err = minivpn_err(ssl, MINIVPN_ERR_PERM)) != MINIVPN_OK) {
      debug("error sending error message: %s\n", minivpn_errstr(err));
    }
    return NULL;
  }

  tunnel *tun = tunnel_new(tunserv);
  if (tun == NULL) {
    debug("could not create tunnel\n");
    return NULL;
  }
  if (!tunnel_set_key(tun, client_init.key)) {
    debug("could not set tunnel key\n");
    goto err_free_tun;
  }
  if (!tunnel_set_iv(tun, client_init.iv)) {
    goto err_free_tun;
  }
  if (!tunnel_connect(tun, client_ip, client_init.client_port, client_init.client_tunnel)) {
    debug("could not connect tunnel\n");
    goto err_free_tun;
  }
  if (!tunnel_route(tun, client_init.client_network, client_init.client_netmask)) {
    debug("could not route tunnel\n");
    goto err_free_tun;
  }

  minivpn_pkt_server_handshake server_init;
  server_init.server_port = server_port;
  server_init.server_tunnel = tunnel_id(tun);
  server_init.server_network = server_network;
  server_init.server_netmask = server_netmask;
  if ((err = minivpn_send(ssl, MINIVPN_PKT_SERVER_HANDSHAKE, &server_init)) != MINIVPN_OK) {
    debug("error sending server handshake: %s\n", minivpn_errstr(err));
    goto err_free_tun;
  }

  if ((err = minivpn_await_ack(ssl)) != MINIVPN_OK) {
    debug("error receiving session acknowledgement from client: %s\n", minivpn_errstr(err));
    goto err_free_tun;
  }

  return tun;

err_free_tun:
  tunnel_delete(tun);
  return NULL;
}

uint16_t minivpn_update_key(SSL *ssl, tunnel *tun, const unsigned char *key)
{
  int err;

  minivpn_pkt_update_key pkt;
  memcpy(pkt.key, key, TUNNEL_KEY_SIZE);
  if ((err = minivpn_send(ssl, MINIVPN_PKT_UPDATE_KEY, &pkt)) != MINIVPN_OK) {
    debug("error sending update key packet: %s\n", minivpn_errstr(err));
    return err;
  }
  if ((err = minivpn_await_ack(ssl)) != MINIVPN_OK) {
    debug("error receiving key change acknowledgement: %s\n", minivpn_errstr(err));
    return err;
  }

  return tunnel_set_key(tun, key) ? MINIVPN_OK : MINIVPN_ERR;
}

uint16_t minivpn_update_iv(SSL *ssl, tunnel *tun, const unsigned char *iv)
{
  int err;

  minivpn_pkt_update_iv pkt;
  memcpy(pkt.iv, iv, TUNNEL_IV_SIZE);
  if ((err = minivpn_send(ssl, MINIVPN_PKT_UPDATE_IV, &pkt)) != MINIVPN_OK) {
    debug("error sending update iv packet: %s\n", minivpn_errstr(err));
    return err;
  }
  if ((err = minivpn_await_ack(ssl)) != MINIVPN_OK) {
    debug("error receiving iv change acknowledgement: %s\n", minivpn_errstr(err));
    return err;
  }

  return tunnel_set_iv(tun, iv) ? MINIVPN_OK : MINIVPN_ERR;
}

uint16_t minivpn_detach(SSL *ssl)
{
  return minivpn_send(ssl, MINIVPN_PKT_DETACH, NULL);
}

static void client_handshake_to_network_byte_order(minivpn_pkt_client_handshake *p)
{
  p->client_port = hton_port(p->client_port);
  p->client_tunnel = hton_tunnel_id(p->client_tunnel);
  p->client_network = hton_ip(p->client_network);
  p->client_netmask = hton_ip(p->client_netmask);
}

static void server_handshake_to_network_byte_order(minivpn_pkt_server_handshake *p)
{
  p->server_port = hton_port(p->server_port);
  p->server_tunnel = hton_tunnel_id(p->server_tunnel);
  p->server_network = hton_ip(p->server_network);
  p->server_netmask = hton_ip(p->server_netmask);
}

static void error_to_network_byte_order(minivpn_pkt_error *p)
{
  p->code = htons(p->code);
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
  case MINIVPN_PKT_ERROR:
    error_to_network_byte_order((minivpn_pkt_error *)pkt->data);
    break;
  case MINIVPN_PKT_UPDATE_KEY:
  case MINIVPN_PKT_UPDATE_IV:
  case MINIVPN_PKT_ACK:
  case MINIVPN_PKT_DETACH:
    break;
  default:
    debug("unrecognized packet type %" PRIu16 "\n", pkt->type);
  }

  pkt->length = htonl(pkt->length);
  pkt->type = htons(pkt->type);
}

static void client_handshake_to_host_byte_order(minivpn_pkt_client_handshake *p)
{
  p->client_port = ntoh_port(p->client_port);
  p->client_tunnel = ntoh_tunnel_id(p->client_tunnel);
  p->client_network = ntoh_ip(p->client_network);
  p->client_netmask = ntoh_ip(p->client_netmask);
}

static void server_handshake_to_host_byte_order(minivpn_pkt_server_handshake *p)
{
  p->server_port = ntoh_port(p->server_port);
  p->server_tunnel = ntoh_tunnel_id(p->server_tunnel);
  p->server_network = ntoh_ip(p->server_network);
  p->server_netmask = ntoh_ip(p->server_netmask);
}

static void error_to_host_byte_order(minivpn_pkt_error *p)
{
  p->code = ntohs(p->code);
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
  case MINIVPN_PKT_ERROR:
    error_to_host_byte_order((minivpn_pkt_error *)pkt->data);
    break;
  case MINIVPN_PKT_UPDATE_KEY:
  case MINIVPN_PKT_UPDATE_IV:
  case MINIVPN_PKT_ACK:
  case MINIVPN_PKT_DETACH:
    break;
  default:
    debug("unrecognized packet type %" PRIu16 "\n", pkt->type);
  }
}

int minivpn_avail(SSL *ssl)
{
  // Use select so we can timeout
  int fd = SSL_get_fd(ssl);
  fd_set set;
  FD_ZERO(&set);
  FD_SET(fd, &set);

  struct timeval timeout;
  timeout.tv_sec = 1;
  timeout.tv_usec = 0;

  int ret = select(fd + 1, &set, NULL, NULL, &timeout);
  if (ret < 0) {
    perror("select");
    return -2;
  } else if (!FD_ISSET(fd, &set)) {
    return 0;
  }

  minivpn_packet pkt;
  ssize_t navail = SSL_peek(ssl, &pkt, sizeof(pkt));
  if (navail < 0) {
    ERR_print_errors_fp(stderr);
    return -2;
  } else if (navail == 0) {
    return -1;
  } else if ((size_t)navail < sizeof(pkt)) {
    return 0;
  } else {
    return 1;
  }
}

uint16_t minivpn_send_raw(SSL *ssl, uint16_t type, const void *data, size_t data_len)
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
      return MINIVPN_ERR_COMM;
    }
  }

  return MINIVPN_OK;
}

uint16_t minivpn_recv_raw(SSL *ssl, uint16_t type, void *data, size_t data_len)
{
  int ret;

  // Use select so we can timeout
  int fd = SSL_get_fd(ssl);
  fd_set set;
  FD_ZERO(&set);
  FD_SET(fd, &set);

  struct timeval timeout;
  timeout.tv_sec = 0;
  timeout.tv_usec = 100000;

  int tries;
  for (tries = 0; tries < 30; ++tries) {
    ret = select(fd + 1, &set, NULL, NULL, &timeout);
    if (ret < 0) {
      perror("select");
      return MINIVPN_ERR_COMM;
    } else if (FD_ISSET(fd, &set)) {
      break;
    }
  }
  if (tries == 30) {
    return MINIVPN_ERR_TIMEOUT;
  }

  minivpn_packet pkt;
  for (tries = 0; tries < 30; ++tries) {
    ssize_t navail = SSL_peek(ssl, &pkt, sizeof(pkt));
    if (navail < 0) {
      ERR_print_errors_fp(stderr);
      return MINIVPN_ERR_COMM;
    } else if (navail == 0) {
      return MINIVPN_ERR_EOF;
    } else if ((size_t)navail >= sizeof(pkt)) {
      break;
    }
    usleep(100000);
  }
  if (tries == 30) {
    return MINIVPN_ERR_TIMEOUT;
  }

  if ((ret = SSL_read(ssl, &pkt, sizeof(pkt))) <= 0) {
    fprintf(stderr, "%s\n", ERR_error_string(SSL_get_error(ssl, ret), NULL));
    return MINIVPN_ERR_COMM;
  }
  minivpn_to_host_byte_order(&pkt);

  debug("received packet type=%" PRIu16 ", length=%" PRIu32 "\n", pkt.type, pkt.length);

  if (pkt.type == MINIVPN_PKT_ERROR) {
    minivpn_pkt_error *err = (minivpn_pkt_error *)pkt.data;
    return err->code;
  }

  if (type == MINIVPN_PKT_ANY) {
    memcpy(data, &pkt, data_len);
    return MINIVPN_OK;
  }

  if (pkt.type != type) {
    debug("received wrong packet type %" PRIu16 " (expected %" PRIu16 ")\n", pkt.type, type);
    return MINIVPN_ERR_COMM;
  }

  if (data) {
    memcpy(data, pkt.data, data_len);
  }

  return MINIVPN_OK;
}

const char *minivpn_errstr(uint16_t code)
{
  switch (code) {
  case MINIVPN_OK:
    return "ok";
  case MINIVPN_ERR:
    return "internal error";
  case MINIVPN_ERR_COMM:
    return "protocol error";
  case MINIVPN_ERR_PERM:
    return "permission denied";
  case MINIVPN_ERR_SERV:
    return "server error";
  case MINIVPN_ERR_EOF:
    return "connection with peer unexpectedly terminated";
  case MINIVPN_ERR_TIMEOUT:
    return "timeout";
  default:
    return "unknown error";
  }
}

uint16_t minivpn_err(SSL *ssl, uint16_t code)
{
  minivpn_pkt_error pkt;
  pkt.code = code;
  return minivpn_send(ssl, MINIVPN_PKT_ERROR, &pkt);
}
