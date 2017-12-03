#include <arpa/inet.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "protocol.h"
#include "tunnel.h"

static int udp_port = 55555;

static void init_ssl()
{
  SSL_load_error_strings();
  SSL_library_init();
  OpenSSL_add_all_algorithms();
}

static void close_ssl()
{
  SSL_load_error_strings();
  SSL_library_init();
  OpenSSL_add_all_algorithms();
}

static bool send_oob(SSL *ssl, const minivpn_packet *pkt)
{
  minivpn_packet pktn;
  memcpy(&pktn, pkt, sizeof(minivpn_packet));
  minivpn_to_network_byte_order(&pktn);

  const char *buf = (const char *)&pktn;
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

typedef struct {
  SSL_CTX *ctx;
  SSL *ssl;
  tunnel *tun;
} session;

static session *session_new(const unsigned char *key, const unsigned char *iv,
                            int server_ip, int server_port, int client_ip, int network, int netmask)
{
  session *s = (session *)malloc(sizeof(session));
  if (s == NULL) {
    perror("malloc");
    goto err_malloc;
  }

  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    perror("socket");
    goto err_socket;
  }

  struct sockaddr_in sin;
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = server_ip;
  sin.sin_port = htonl(server_port);
  if (connect(sockfd, (const struct sockaddr *)&sin, sizeof(sin)) < 0) {
    perror("connect");
    goto err_connect;
  }

  s->ctx = SSL_CTX_new(SSLv23_client_method());
  if (s->ctx == NULL) {
    ERR_print_errors_fp(stderr);
    goto err_ctx_new;
  }
  SSL_CTX_set_verify(s->ctx, SSL_VERIFY_PEER, NULL);

  s->ssl = SSL_new(s->ctx);
  if (s->ssl == NULL) {
    ERR_print_errors_fp(stderr);
    goto err_ssl_new;
  }

  if (SSL_set_fd(s->ssl, sockfd) != 1) {
    ERR_print_errors_fp(stderr);
    goto err_set_fd;
  }

  int err = SSL_connect(s->ssl);
  if (err != 1) {
    fprintf(stderr, "%s\n", ERR_error_string(SSL_get_error(s->ssl, err), NULL));
    goto err_ssl_connect;
  }

  minivpn_packet pkt;
  pkt.type = MINIVPN_INIT_SESSION;
  pkt.length = sizeof(minivpn_init_session);
  minivpn_init_session *init = (minivpn_init_session *)pkt.data;
  memcpy(&init->key, key, TUNNEL_KEY_SIZE);
  memcpy(&init->iv, iv, TUNNEL_IV_SIZE);
  init->client_ip = client_ip;
  init->client_port = udp_port++;
  init->client_network = network;
  init->client_netmask = netmask;
  if (!send_oob(s->ssl, &pkt)) {
    goto err_send_init;
  }

  return s;

err_send_init:
  SSL_shutdown(s->ssl);
err_ssl_connect:
err_set_fd:
  SSL_free(s->ssl);
err_ssl_new:
  SSL_CTX_free(s->ctx);
err_ctx_new:
err_connect:
  close(sockfd);
err_socket:
  free(s);
err_malloc:
  return NULL;
}

static void session_delete(session *s)
{
  SSL_shutdown(s->ssl);
  SSL_free(s->ssl);
  SSL_CTX_free(s->ctx);
  tunnel_delete(s->tun);
  free(s);
}

static void usage(const char *progname)
{
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s [options] <server-ip> <client-ip> <network> <netmask>\n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-u, --udp-port <port>: beginning of port range to use for UDP tunnels (default 55555)\n");
  fprintf(stderr, "-p, --server-port <port>: TCP server port (default 55555)\n");
  fprintf(stderr, "-h, --help: prints this help text\n");
  exit(1);
}

int main(int argc, char **argv)
{
  unsigned char key[TUNNEL_KEY_SIZE];
  unsigned char iv[TUNNEL_IV_SIZE];
  int server_port = 55555;
  int server_ip;
  int client_ip;
  int network;
  int netmask;

  struct option long_options[] =
  {
    {"help",        no_argument,       0, 'h'},
    {"server-port", required_argument, 0, 'p'},
    {"udp-port",    required_argument, 0, 'u'},
    {0, 0, 0, 0}
  };

  char option;
  int option_index = 0;
  while((option = getopt_long(argc, argv, "hp:u:", long_options, &option_index)) > 0) {
    switch(option) {
    case 'p':
      server_port = atoi(optarg);
      break;
    case 'u':
      udp_port = atoi(optarg);
      break;
    case 'h':
    default:
      usage(argv[0]);
    }
  }

  if (argc != option_index + 4) {
    usage(argv[0]);
  }

  server_ip = inet_addr(argv[option_index++]);
  client_ip = inet_addr(argv[option_index++]);
  network = atoi(argv[option_index++]);
  netmask = atoi(argv[option_index++]);

  init_ssl();

  session *s = session_new(key, iv, server_ip, server_port, client_ip, network, netmask);
  if (s == NULL) {
    return 1;
  }

  session_delete(s);
  close_ssl();

  return 0;
}
