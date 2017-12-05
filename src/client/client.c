#include <arpa/inet.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "debug.h"
#include "inet.h"
#include "protocol.h"
#include "tcp.h"
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
  tunnel *tun;
  bool *halt;
} tunnel_arg;

static void *tun_loop(void *void_arg)
{
  tunnel_arg *arg = (tunnel_arg *)void_arg;

  while (!(*(arg->halt))) {
    tunnel_loop(arg->tun);
  }

  tunnel_delete(arg->tun);
  free(arg);

  return NULL;
}

typedef struct {
  SSL_CTX *ctx;
  SSL *ssl;
  tunnel_server *tunserv;
  tunnel *tun;
  bool *halt;
  pthread_t tunnel_thread;
} session;

static session *session_new(const unsigned char *key, const unsigned char *iv, const char *ca_crt,
                            const char *username, const char *password,
                            in_addr_t server_ip, in_port_t server_port,
                            in_addr_t client_ip, in_port_t client_port,
                            in_addr_t network, in_addr_t netmask)
{
  session *s = (session *)malloc(sizeof(session));
  if (s == NULL) {
    perror("malloc");
    goto err_malloc;
  }

  struct sockaddr_in sin;
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = hton_ip(server_ip);
  sin.sin_port = hton_port(server_port);
  int sockfd;
  if ((sockfd = tcp_client(AF_INET, (struct sockaddr *)&sin, sizeof(sin))) < 0) {
    goto err_tcp_client;
  }
#ifdef DEBUG
  char server_ip_str[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &sin.sin_addr, server_ip_str, INET_ADDRSTRLEN);
  debug("connected to %s:%" PRIu16 "\n", server_ip_str, server_port);
#endif

  s->tunserv = tunnel_server_new(client_port);
  if (s->tunserv == NULL) {
    debug("error creating tunnel server\n");
    goto err_tun_serv;
  }

  s->ctx = SSL_CTX_new(SSLv23_client_method());
  if (s->ctx == NULL) {
    ERR_print_errors_fp(stderr);
    goto err_ctx_new;
  }
  SSL_CTX_set_verify(s->ctx, SSL_VERIFY_PEER, NULL);
  if (SSL_CTX_load_verify_locations(s->ctx, ca_crt, NULL) != 1) {
    ERR_print_errors_fp(stderr);
    goto err_load_cert;
  }

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
  s->tun = minivpn_client_handshake(
    s->ssl, s->tunserv, key, iv, client_ip, client_port, network, netmask, username, password);
  if (s->tun == NULL) {
    debug("minivpn handshake failed\n");
    goto err_minivpn_handshake;
  }
  debug("minivpn handshake successful\n");

  bool *halt = (bool *)malloc(sizeof(bool));
  *halt = false;
  s->halt = halt;

  int pthread_errno = 0;
  tunnel_arg *targ = (tunnel_arg *)malloc(sizeof(tunnel_arg));
  targ->tun = s->tun;
  targ->halt = s->halt;
  if ((pthread_errno = pthread_create(&s->tunnel_thread, NULL, tun_loop, targ)) != 0) {
    debug("error creating tunnel thread: %s\n", strerror(pthread_errno));
    goto err_thread_create;
  }

  debug("session activated with %s:%" PRIu16 "\n", server_ip_str, server_port);
  return s;

err_thread_create:
  tunnel_delete(s->tun);
  free(targ);
  free(halt);
err_minivpn_handshake:
  SSL_shutdown(s->ssl);
err_ssl_connect:
err_set_fd:
  SSL_free(s->ssl);
err_ssl_new:
err_load_cert:
  SSL_CTX_free(s->ctx);
err_ctx_new:
  tunnel_server_delete(s->tunserv);
err_tun_serv:
err_tcp_client:
  free(s);
err_malloc:
  debug("unable to activate session\n");
  return NULL;
}

static void session_delete(session *s)
{
  *s->halt = true;
  tunnel_stop(s->tun);
  pthread_join(s->tunnel_thread, NULL);
  free(s->halt);

  SSL_shutdown(s->ssl);
  SSL_free(s->ssl);
  SSL_CTX_free(s->ctx);

  tunnel_server_delete(s->tunserv);

  free(s);
}

typedef struct {
  int type;
  char data[100];
} cli_command;
#define CLI_COMMAND_PING 0
#define CLI_COMMAND_STOP 1

typedef struct {
  int type;
  char data[100];
} cli_response;
#define CLI_RESPONSE_OK               0
#define CLI_RESPONSE_INVALID_COMMAND  1

static bool eval_command(session *s, int conn, const cli_command *command)
{
  cli_response res;

  switch (command->type) {
  case CLI_COMMAND_PING:
    debug("responding to ping request\n");
    res.type = CLI_RESPONSE_OK;
    break;
  case CLI_COMMAND_STOP:
    debug("beginning shutdown process\n");
    minivpn_client_detach(s->ssl);
    *s->halt = true;
    res.type = CLI_RESPONSE_OK;
    break;
  default:
    debug("invalid CLI command %d\n", command->type);
    res.type = CLI_RESPONSE_INVALID_COMMAND;
  }

  return write_n(conn, &res, sizeof(cli_response));
}

int client_start(const unsigned char *key, const unsigned char *iv, const char *ca_crt,
                 const char *username, const char *password,
                 const char *cli_socket, in_addr_t server_ip, in_port_t server_port,
                 in_addr_t client_ip, in_port_t udp_port, in_addr_t network, in_addr_t netmask)
{
  // Set up a TCP server to handle CLI commands
  struct sockaddr_un sa;
  bzero(&sa, sizeof(sa));
  sa.sun_family = AF_UNIX;
  strncpy(sa.sun_path + 1, cli_socket, 106);
  int sockfd = tcp_server(AF_UNIX, (struct sockaddr *)&sa, sizeof(sa));
  if (sockfd < 1) {
    fprintf(stderr, "unable to start cli server\n");
    return 1;
  }

  init_ssl();

  session *s = session_new(
    key, iv, ca_crt, username, password, server_ip, server_port, client_ip, udp_port, network, netmask);
  if (s == NULL) {
    return 1;
  }

  while (!*s->halt) {
    int conn = accept(sockfd, NULL, NULL);
    if (conn < 0) {
      perror("accept");
      // Back off a little so we don't spam error messages
      sleep(1);
      continue;
    }
    debug("accepted CLI connection\n");

    cli_command command;
    if (!read_n(conn, &command, sizeof(cli_command))) {
      debug("error reading cli command\n");
      goto next_client;
    }

    if (!eval_command(s, conn, &command)) {
      debug("error evaluating cli command\n");
      goto next_client;
    }

next_client:
    debug("closing CLI connection\n");
    close(conn);
  }

  session_delete(s);
  close_ssl();

  close(sockfd);

  return 0;
}

static bool send_cli_command(const char *sock, const cli_command *command, cli_response *response)
{
  bool result;

  struct sockaddr_un sa;
  sa.sun_family = AF_UNIX;
  strncpy(sa.sun_path + 1, sock, 106);
  int sockfd;
  if ((sockfd = tcp_client(AF_UNIX, (struct sockaddr *)&sa, sizeof(sa))) < 0) {
    return false;
  }

  if (!write_n(sockfd, command, sizeof(cli_command))) {
    result = false;
    goto close_socket;
  }

  if (!read_n(sockfd, response, sizeof(cli_response))) {
    result = false;
    goto close_socket;
  }

  result = true;

close_socket:
  close(sockfd);
  return result;
}

bool client_ping(const char *sock)
{
  cli_command comm;
  cli_response res;

  comm.type = CLI_COMMAND_PING;

  if (!send_cli_command(sock, &comm, &res)) {
    fprintf(stderr, "unable to reach client\n");
    return false;
  }
  return res.type == CLI_RESPONSE_OK;
}

bool client_stop(const char *sock)
{
  cli_command comm;
  cli_response res;

  comm.type = CLI_COMMAND_STOP;

  if (!send_cli_command(sock, &comm, &res)) {
    fprintf(stderr, "unable to reach client\n");
    return false;
  }
  return res.type == CLI_RESPONSE_OK;
}
