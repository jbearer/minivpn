#include <arpa/inet.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "client.h"
#include "debug.h"
#include "inet.h"
#include "password.h"
#include "tunnel.h"

#define FILE_PATH_SIZE 100

static void usage(const char *progname)
{
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s [options] <server-ip> <client-ip> <network> <netmask>\n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-s, --cli-socket <file>: unix socket to use for CLI commands (default is %s)\n",
    CLIENT_DEFAULT_CLI_SOCKET);
  fprintf(stderr, "-o, --log-file <file>: direct output to file (default is /dev/null)\n");
  fprintf(stderr, "-c, --ca-crt <file>: root CA certificate file (default ~/.minivpn/ca.crt)\n");
  fprintf(stderr, "-u, --udp-port <port>: port to use for UDP tunnel (default 55555)\n");
  fprintf(stderr, "-p, --server-port <port>: TCP server port (default 55555)\n");
  fprintf(stderr, "-D, --no-daemon: start the client in the current process, rather than as a daemon\n");
  fprintf(stderr, "-h, --help: prints this help text\n");
  exit(1);
}

int main(int argc, char **argv)
{
  int fork_daemon = 1;
  unsigned char key[TUNNEL_KEY_SIZE];
  unsigned char iv[TUNNEL_IV_SIZE];
  char ca_crt[FILE_PATH_SIZE] = {0};
  in_port_t server_port = 55555;
  in_port_t udp_port = 55555;
  in_addr_t server_ip;
  in_addr_t client_ip;
  in_addr_t network;
  in_addr_t netmask;
  char log[FILE_PATH_SIZE] = {0};
  char cli_socket[FILE_PATH_SIZE] = CLIENT_DEFAULT_CLI_SOCKET;

  snprintf(ca_crt, FILE_PATH_SIZE-1, "%s/.minivpn/ca.crt", getenv("HOME"));

  struct option long_options[] =
  {
    {"help",        no_argument,       0, 'h'},
    {"log-file",    required_argument, 0, 'o'},
    {"ca-crt",      required_argument, 0, 'c'},
    {"server-port", required_argument, 0, 'p'},
    {"udp-port",    required_argument, 0, 'u'},
    {"cli-socket",  required_argument, 0, 's'},
    {"no-daemon",   no_argument, &fork_daemon, 0},
    {0, 0, 0, 0}
  };

  char option;
  while((option = getopt_long(argc, argv, "ho:c:p:u:s:D", long_options, NULL)) > 0) {
    switch(option) {
    case 'o':
      bzero(log, FILE_PATH_SIZE);
      strncpy(log, optarg, FILE_PATH_SIZE-1);
      break;
    case 'c':
      bzero(ca_crt, FILE_PATH_SIZE);
      strncpy(ca_crt, optarg, FILE_PATH_SIZE-1);
      break;
    case 'p':
      server_port = atoi(optarg);
      break;
    case 'u':
      udp_port = atoi(optarg);
      break;
    case 's':
      bzero(cli_socket, FILE_PATH_SIZE);
      strncpy(cli_socket, optarg, FILE_PATH_SIZE-1);
      break;
    case 'D':
      fork_daemon = false;
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

  char username[100];
  char password[100];
  prompt("Username:", username, sizeof(username));
  prompt_password("Password:", password, sizeof(password));

  if (fork_daemon) {
    pid_t child = fork();
    if (child < 0) {
      perror("fork");
      return 1;
    } else if (child > 0) {
      sleep(1);
      return client_ping(cli_socket) ? 0 : 1;
    } else {
      if (log[0] != '\0') {
        int logfd = open(log, O_WRONLY|O_CREAT|O_APPEND, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
        if (logfd < 1) {
          perror("could not open log file, continuing without logging:");
          close(STDOUT_FILENO);
          close(STDERR_FILENO);
        } else {
          dup2(logfd, STDOUT_FILENO);
          dup2(logfd, STDERR_FILENO);
        }
      } else {
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
      }
      return client_start(key, iv, ca_crt, username, password, cli_socket, server_ip, server_port,
                          client_ip, udp_port, network, netmask);
    }
  } else {
    return client_start(key, iv, ca_crt, username, password, cli_socket, server_ip, server_port,
                        client_ip, udp_port, network, netmask);
  }
}
