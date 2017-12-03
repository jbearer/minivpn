#include <arpa/inet.h>
#include <getopt.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "protocol.h"
#include "tunnel.h"

#ifdef DEBUG
#define debug(...) fprintf(stderr, __VA_ARGS__)
#else
#define debug(...)
#endif

static int udp_port = 55555;
static char cert_file[100];
static char pkey_file[100];

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

static int open_socket(int port)
{
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    perror("socket");
    return -1;
  }

  // Avoid EADDRINUSE error on bind()
  int optval = 1;
  if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0){
    perror("setsockopt");
    return -1;
  }

  struct sockaddr_in sin;
  bzero(&sin, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl(INADDR_ANY);
  sin.sin_port = htons(port);

  if (bind(sockfd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
    perror("bind");
    return -1;
  }

  if (listen(sockfd, 16) < 0) {
    perror("listen");
    return -1;
  }

  return sockfd;
}

static bool recv_oob(SSL *ssl, minivpn_packet *pkt)
{
  char *buf = (char *)pkt;
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

  minivpn_to_host_byte_order(pkt);
  return true;
}

typedef struct {
  SSL_CTX *ctx;
  SSL *ssl;
  tunnel *tun;
} in_band_arg;

static void *in_band_loop(void *void_arg)
{
  in_band_arg *arg = (in_band_arg *)void_arg;

  tunnel_loop(arg->tun);
  tunnel_delete(arg->tun);

  SSL_shutdown(arg->ssl);
  SSL_free(arg->ssl);
  SSL_CTX_free(arg->ctx);
  free(arg);

  return NULL;
}

static void accept_client(int sockfd)
{
  struct sockaddr_in sin;
  socklen_t sinlen;
  int conn = accept(sockfd, (struct sockaddr *)&sin, &sinlen);
  if (conn < 0) {
    perror("accept");
    goto err_accept;
  }

  SSL_CTX *ctx = SSL_CTX_new(SSLv23_server_method());
  if (ctx == NULL) {
    ERR_print_errors_fp(stderr);
    goto err_ctx_new;
  }

  if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) != 1) {
    ERR_print_errors_fp(stderr);
    goto err_use_cert;
  }

  if (SSL_CTX_use_PrivateKey_file(ctx, pkey_file, SSL_FILETYPE_PEM) != 1) {
    ERR_print_errors_fp(stderr);
    goto err_use_pkey;
  }

  SSL *ssl = SSL_new(ctx);
  if (ssl == NULL) {
    ERR_print_errors_fp(stderr);
    goto err_ssl_new;
  }

  if (SSL_set_fd(ssl, conn) != 1) {
    ERR_print_errors_fp(stderr);
    goto err_set_fd;
  }

  int err = SSL_accept(ssl);
  if (err != 1) {
    fprintf(stderr, "%s\n", ERR_error_string(SSL_get_error(ssl, err), NULL));
    goto err_ssl_accept;
  }

  minivpn_packet pkt;
  if (!recv_oob(ssl, &pkt) || pkt.type != MINIVPN_INIT_SESSION) {
    fprintf(stderr, "unable to read session initialization packet\n");
    goto err_init_session;
  }

  minivpn_init_session *init = (minivpn_init_session *)pkt.data;
  tunnel *tun = tunnel_new(init->key, init->iv, init->client_ip, init->client_port, udp_port++);
  if (tun == NULL) {
    goto err_tunnel_new;
  }

  if (tunnel_route(tun, init->client_network, init->client_netmask)) {
    goto err_tunnel_route;
  }

  pthread_t in_band_thread;
  int pthread_errno = 0;
  in_band_arg *ibarg = (in_band_arg *)malloc(sizeof(in_band_arg));
  ibarg->ctx = ctx;
  ibarg->ssl = ssl;
  ibarg->tun = tun;
  if ((pthread_errno = pthread_create(&in_band_thread, NULL, in_band_loop, ibarg)) != 0) {
    fprintf(stderr, "error creating in-band thread: %s\n", strerror(pthread_errno));
    goto err_in_band_thread_create;
  }
  if ((pthread_errno = pthread_detach(in_band_thread)) != 0) {
    fprintf(stderr, "error detaching in-band thread: %s\n", strerror(pthread_errno));
    goto err_in_band_thread_detach;
  }

  debug("successfully launched client");

  return;

err_in_band_thread_detach:
  tunnel_stop(tun);
  pthread_join(in_band_thread, NULL);
err_in_band_thread_create:
  free(ibarg);
err_tunnel_route:
  tunnel_delete(tun);
err_tunnel_new:
err_init_session:
  SSL_shutdown(ssl);
err_ssl_accept:
err_set_fd:
  SSL_free(ssl);
err_ssl_new:
err_use_pkey:
err_use_cert:
  SSL_CTX_free(ctx);
err_ctx_new:
  close(conn);
err_accept:
  return;
}

static void usage(const char *progname)
{
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s [options] <cert-file> <pkey-file>\n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-t, --tcp-port <port>: TCP server port (default 55555)\n");
  fprintf(stderr, "-u, --udp-port <port>: beginning of port range to use for UDP tunnels (default 55555)\n");
  fprintf(stderr, "-h, --help: prints this help text\n");
  exit(1);
}


int main(int argc, char **argv)
{
  int port = 55555;

  struct option long_options[] =
  {
    {"help",      no_argument,       0, 'h'},
    {"tcp-port",  required_argument, 0, 't'},
    {"udp-port",  required_argument, 0, 'u'},
    {0, 0, 0, 0}
  };

  char option;
  int option_index = 0;
  while((option = getopt_long(argc, argv, "ht:u:", long_options, &option_index)) > 0) {
    switch(option) {
    case 'p':
      port = atoi(optarg);
      break;
    case 'u':
      udp_port = atoi(optarg);
      break;
    case 'h':
    default:
      usage(argv[0]);
    }
  }

  if (argc != option_index + 2) {
    usage(argv[0]);
  }

  strncpy(cert_file, argv[option_index++], 99);
  strncpy(pkey_file, argv[option_index++], 99);

  init_ssl();

  int sockfd = open_socket(port);
  if (sockfd < 0) {
    return 1;
  }

  while (true) {
    accept_client(sockfd);
  }

  close(sockfd);
  close_ssl();
  return 0;
}
