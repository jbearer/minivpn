#include <arpa/inet.h>
#include <getopt.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "debug.h"
#include "inet.h"
#include "protocol.h"
#include "tunnel.h"

static in_port_t udp_port = 55555;
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
  ERR_free_strings();
}

static int open_socket(in_port_t port)
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
  sin.sin_addr.s_addr = hton_ip(INADDR_ANY);
  sin.sin_port = hton_port(port);

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

typedef struct {
  tunnel *tun;
  volatile bool *halt;
} in_band_arg;

static void *in_band_loop(void *void_arg)
{
  in_band_arg *arg = (in_band_arg *)void_arg;

  while (!*arg->halt) {
    tunnel_loop(arg->tun);
  }

  tunnel_delete(arg->tun);
  free(arg);

  return NULL;
}

typedef struct {
  tunnel *tun;
  SSL_CTX *ctx;
  SSL *ssl;
  volatile bool *halt;
} out_of_band_arg;

static void *out_of_band_loop(void *void_arg)
{
  out_of_band_arg *arg = (out_of_band_arg *)void_arg;

  while (true) {
    minivpn_packet pkt;
    if (!minivpn_recv(arg->ssl, MINIVPN_PKT_ANY, &pkt)) {
      debug("error receiving out-of-band packet\n");
      continue;
    }

    switch (pkt.type) {
    default:
      debug("received unsupported out-of-band packet type %" PRIu16 "\n", pkt.type);
      // TODO tell the client we can't do that
    }
  }

  *arg->halt = true;
  tunnel_stop(arg->tun);

  SSL_shutdown(arg->ssl);
  SSL_free(arg->ssl);
  SSL_CTX_free(arg->ctx);
  free((void *)arg->halt);
  free(arg);

  return NULL;
}

static void accept_client(
  int sockfd, in_addr_t server_ip, in_addr_t server_network, in_addr_t server_netmask)
{
  struct sockaddr_in sin;
  socklen_t sinlen = sizeof(sin);
  int conn = accept(sockfd, (struct sockaddr *)&sin, &sinlen);
  if (conn < 0) {
    perror("accept");
    goto err_accept;
  }

#ifdef DEBUG
  char client_ip_str[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &sin.sin_addr, client_ip_str, INET_ADDRSTRLEN);
  uint16_t client_tcp_port = ntoh_port(sin.sin_port);
#endif
  debug("accepted connection from %s:%" PRIu16 "\n", client_ip_str, client_tcp_port);

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

  debug("beginning SSL handshake with %s:%" PRIu16 "\n", client_ip_str, client_tcp_port);
  int err = SSL_accept(ssl);
  if (err != 1) {
    ERR_print_errors_fp(stderr);
    goto err_ssl_accept;
  }
  debug("SSL handshake complete, beginning minivpn handshake with %s:%" PRIu16 "\n",
    client_ip_str, client_tcp_port);

  tunnel *tun = minivpn_server_handshake(ssl, server_ip, udp_port++, server_network, server_netmask);
  if (tun == NULL) {
    debug("minivpn handshake failed\n");
    goto err_minivpn_handshake;
  } else {
    debug("minivpn handshake succeeded\n");
  }

  volatile bool *halt = (bool *)malloc(sizeof(bool));
  *halt = false;

  pthread_t in_band_thread;
  int pthread_errno = 0;
  in_band_arg *ibarg = (in_band_arg *)malloc(sizeof(in_band_arg));
  ibarg->tun = tun;
  ibarg->halt = halt;
  if ((pthread_errno = pthread_create(&in_band_thread, NULL, in_band_loop, ibarg)) != 0) {
    debug("error creating in-band thread: %s\n", strerror(pthread_errno));
    goto err_in_band_thread_create;
  }
  if ((pthread_errno = pthread_detach(in_band_thread)) != 0) {
    debug("error detaching in-band thread: %s\n", strerror(pthread_errno));
    goto err_in_band_thread_detach;
  }

  pthread_t out_of_band_thread;
  out_of_band_arg *obarg = (out_of_band_arg *)malloc(sizeof(out_of_band_arg));
  obarg->ctx = ctx;
  obarg->ssl = ssl;
  obarg->tun = tun;
  obarg->halt = halt;
  if ((pthread_errno = pthread_create(&out_of_band_thread, NULL, out_of_band_loop, obarg)) != 0) {
    debug("error creating out-of-band thread: %s\n", strerror(pthread_errno));
    goto err_out_of_band_thread_create;
  }
  pthread_detach(out_of_band_thread);

  debug("successfully launched client\n");

  return;

err_out_of_band_thread_create:
err_in_band_thread_detach:
  *halt = true;
  tunnel_stop(tun);
  pthread_join(in_band_thread, NULL);
  SSL_shutdown(ssl);
  SSL_free(ssl);
  SSL_CTX_free(ctx);
  close(conn);
  debug("failed to launch client\n");
  return;

err_in_band_thread_create:
  tunnel_delete(tun);
  free(ibarg);
err_minivpn_handshake:
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
  debug("failed to launch client\n");
  return;
}

static void usage(const char *progname)
{
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s [options] <server-ip> <cert-file> <pkey-file>\n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-n, --network <IP>: VPN IP prefix (defult server_ip)\n");
  fprintf(stderr, "-m, --netmask <mask>: VPN network mask (default 255.255.255.255)\n");
  fprintf(stderr, "-t, --tcp-port <port>: TCP server port (default 55555)\n");
  fprintf(stderr, "-u, --udp-port <port>: beginning of port range to use for UDP tunnels (default 55555)\n");
  fprintf(stderr, "-h, --help: prints this help text\n");
  exit(1);
}

int main(int argc, char **argv)
{
  in_port_t port = 55555;
  in_addr_t server_ip;
  bool      network_set = false;
  in_addr_t network;
  in_addr_t netmask = -1;

  struct option long_options[] =
  {
    {"help",      no_argument,       0, 'h'},
    {"network",   required_argument, 0, 'n'},
    {"netmask",   required_argument, 0, 'm'},
    {"tcp-port",  required_argument, 0, 't'},
    {"udp-port",  required_argument, 0, 'u'},
    {0, 0, 0, 0}
  };

  char option;
  int option_index = 0;
  while((option = getopt_long(argc, argv, "hn:m:t:u:", long_options, &option_index)) > 0) {
    switch(option) {
    case 'n':
      network = ntoh_ip(inet_addr(optarg));
      network_set = true;
      break;
    case 'm':
      netmask = ntoh_ip(inet_addr(optarg));
      break;
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

  if (argc != optind + 3) {
    usage(argv[0]);
  }

  server_ip = ntoh_ip(inet_addr(argv[optind++]));
  if (!network_set) {
    network = server_ip;
  }
  strncpy(cert_file, argv[optind++], 99);
  strncpy(pkey_file, argv[optind++], 99);

  init_ssl();

  int sockfd = open_socket(port);
  if (sockfd < 0) {
    return 1;
  }

  debug("listening on port %d\n", port);
  while (true) {
    accept_client(sockfd, server_ip, network, netmask);
  }

  close(sockfd);
  close_ssl();
  return 0;
}
