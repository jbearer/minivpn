#include <arpa/inet.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "debug.h"
#include "inet.h"
#include "protocol.h"
#include "tunnel.h"

static void init_ssl()
{
  SSL_load_error_strings();
  SSL_library_init();
  OpenSSL_add_all_algorithms();
}

static void close_ssl()
{
  ERR_free_strings();
}

typedef struct {
  SSL_CTX *ctx;
  SSL *ssl;
  tunnel *tun;
} session;

static session *session_new(const unsigned char *key, const unsigned char *iv,
                            in_addr_t server_ip, in_port_t server_port,
                            in_addr_t client_ip, in_port_t client_port,
                            in_addr_t network, in_addr_t netmask)
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
  sin.sin_addr.s_addr = hton_ip(server_ip);
  sin.sin_port = hton_port(server_port);
  if (connect(sockfd, (const struct sockaddr *)&sin, sizeof(sin)) < 0) {
    perror("connect");
    goto err_connect;
  }
#ifdef DEBUG
  char server_ip_str[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &sin.sin_addr, server_ip_str, INET_ADDRSTRLEN);
  debug("connected to %s:%" PRIu16 "\n", server_ip_str, server_port);
#endif

  s->ctx = SSL_CTX_new(SSLv23_client_method());
  if (s->ctx == NULL) {
    ERR_print_errors_fp(stderr);
    goto err_ctx_new;
  }
  // SSL_CTX_set_verify(s->ctx, SSL_VERIFY_PEER, NULL);

  s->ssl = SSL_new(s->ctx);
  if (s->ssl == NULL) {
    ERR_print_errors_fp(stderr);
    goto err_ssl_new;
  }

  if (SSL_set_fd(s->ssl, sockfd) != 1) {
    ERR_print_errors_fp(stderr);
    goto err_set_fd;
  }

  debug("beginning SSL handshake with %s:%" PRIu16 "\n", server_ip_str, server_port);
  int err = SSL_connect(s->ssl);
  if (err != 1) {
    ERR_print_errors_fp(stderr);
    goto err_ssl_connect;
  }

  debug("SSL handshake complete, beginning minivpn handshake with %s:%" PRIu16 "\n", server_ip_str, server_port);
  s->tun = minivpn_client_handshake(s->ssl, key, iv, client_ip, client_port, network, netmask);
  if (s->tun == NULL) {
    debug("minivpn handshake failed\n");
    goto err_minivpn_handshake;
  }

  debug("session activated with %s:%" PRIu16 "\n", server_ip_str, server_port);
  return s;

err_minivpn_handshake:
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
  debug("unable to activate session\n");
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
  fprintf(stderr, "-u, --udp-port <port>: port to use for UDP tunnel (default 55555)\n");
  fprintf(stderr, "-p, --server-port <port>: TCP server port (default 55555)\n");
  fprintf(stderr, "-h, --help: prints this help text\n");
  exit(1);
}

int main(int argc, char **argv)
{
  unsigned char key[TUNNEL_KEY_SIZE];
  unsigned char iv[TUNNEL_IV_SIZE];
  in_port_t server_port = 55555;
  in_port_t udp_port = 55555;
  in_addr_t server_ip;
  in_addr_t client_ip;
  in_addr_t network;
  in_addr_t netmask;

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

  if (argc != optind + 4) {
    usage(argv[0]);
  }

  server_ip = ntoh_ip(inet_addr(argv[optind++]));
  client_ip = ntoh_ip(inet_addr(argv[optind++]));
  network = ntoh_ip(inet_addr(argv[optind++]));
  netmask = ntoh_ip(inet_addr(argv[optind++]));

  init_ssl();

  session *s = session_new(key, iv, server_ip, server_port, client_ip, udp_port, network, netmask);
  if (s == NULL) {
    return 1;
  }

  session_delete(s);
  close_ssl();

  return 0;
}
