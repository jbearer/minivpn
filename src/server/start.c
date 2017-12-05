#include <arpa/inet.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "debug.h"
#include "password.h"
#include "server.h"

static void usage(const char *progname)
{
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s [options] <server-ip>\n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-c, --cert-file <path>: SSL certificate file (default ~/.minivpn/server.crt\n");
  fprintf(stderr, "-k, --key-file <path>: RSA private key file (default ~/.minivpn/server.key\n");
  fprintf(stderr, "-p, --password-db <path>: password database (default ~/.minivpn/users)\n");
  fprintf(stderr, "-n, --network <IP>: VPN IP prefix (defult server_ip)\n");
  fprintf(stderr, "-m, --netmask <mask>: VPN network mask (default 255.255.255.255)\n");
  fprintf(stderr, "-t, --tcp-port <port>: TCP server port (default 55555)\n");
  fprintf(stderr, "-u, --udp-port <port>: beginning of port range to use for UDP tunnels (default 55555)\n");
  fprintf(stderr, "-s, --cli-socket <file>: unix socket to use for CLI commands (default is %s)\n",
    SERVER_DEFAULT_CLI_SOCKET);
  fprintf(stderr, "-o, --log-file <file>: direct output to file (default is /dev/null)\n");
  fprintf(stderr, "-D, --no-daemon: start the server in the current process, rather than as a daemon\n");
  fprintf(stderr, "-h, --help: prints this help text\n");
  exit(1);
}

int main(int argc, char **argv)
{
  int fork_daemon = 1;
  in_port_t tcp_port = 55555;
  in_port_t udp_port = 55555;
  in_addr_t server_ip;
  bool      network_set = false;
  in_addr_t network;
  in_addr_t netmask = -1;
  char cert_file[FILE_PATH_SIZE] = {0};
  char pkey_file[FILE_PATH_SIZE] = {0};
  char passwd_db[FILE_PATH_SIZE];
  char pkey_password[PASSWORD_SIZE] = {0};
  char log[FILE_PATH_SIZE] = {0};
  char cli_socket[FILE_PATH_SIZE] = SERVER_DEFAULT_CLI_SOCKET;

  snprintf(cert_file, FILE_PATH_SIZE - 1, "%s/.minivpn/server.crt", getenv("HOME"));
  snprintf(pkey_file, FILE_PATH_SIZE - 1, "%s/.minivpn/server.key", getenv("HOME"));
  snprintf(passwd_db, FILE_PATH_SIZE - 1, "%s/.minivpn/users", getenv("HOME"));

  struct option long_options[] =
  {
    {"help",          no_argument,       0, 'h'},
    {"cert-file",     required_argument, 0, 'c'},
    {"key-file",      required_argument, 0, 'k'},
    {"password-db",   required_argument, 0, 'p'},
    {"network",       required_argument, 0, 'n'},
    {"netmask",       required_argument, 0, 'm'},
    {"tcp-port",      required_argument, 0, 't'},
    {"udp-port",      required_argument, 0, 'u'},
    {"no-daemon",     no_argument, &fork_daemon, 0},
    {0, 0, 0, 0}
  };

  char option;
  int option_index = 0;
  while((option = getopt_long(argc, argv, "c:k:p:n:m:t:u:s:o:Dh", long_options, &option_index)) > 0) {
    switch(option) {
    case 'k':
      bzero(pkey_file, FILE_PATH_SIZE);
      strncpy(pkey_file, optarg, FILE_PATH_SIZE-1);
      break;
    case 'c':
      bzero(cert_file, FILE_PATH_SIZE);
      strncpy(cert_file, optarg, FILE_PATH_SIZE-1);
      break;
    case 'p':
      bzero(passwd_db, FILE_PATH_SIZE);
      strncpy(passwd_db, optarg, FILE_PATH_SIZE-1);
      break;
    case 'n':
      network = ntoh_ip(inet_addr(optarg));
      network_set = true;
      break;
    case 'm':
      netmask = ntoh_ip(inet_addr(optarg));
      break;
    case 't':
      tcp_port = atoi(optarg);
      break;
    case 'u':
      udp_port = atoi(optarg);
      break;
    case 's':
      bzero(cli_socket, FILE_PATH_SIZE);
      strncpy(cli_socket, optarg, FILE_PATH_SIZE-1);
      break;
    case 'o':
      bzero(log, FILE_PATH_SIZE);
      strncpy(log, optarg, FILE_PATH_SIZE-1);
      break;
    case 'D':
      fork_daemon = 0;
      break;
    case 'h':
    default:
      usage(argv[0]);
    }
  }

  if (argc != optind + 1) {
    usage(argv[0]);
  }

  server_ip = ntoh_ip(inet_addr(argv[optind++]));
  if (!network_set) {
    network = server_ip;
  }

  debug("key is located at %s\n", pkey_file);
  debug("crt is located at %s\n", cert_file);
  debug("network is 0x%x\n", network);
  debug("netmask is 0x%x\n", netmask);

  prompt_password("Enter password for private key:", pkey_password, PASSWORD_SIZE);

  if (fork_daemon) {
    pid_t child = fork();
    if (child < 0) {
      perror("fork");
      return 1;
    } else if (child > 0) {
      sleep(1);
      return server_ping(cli_socket) ? 0 : 1;
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
      return server_start(cert_file, pkey_file, passwd_db, pkey_password, cli_socket,
                          server_ip, tcp_port, udp_port, network, netmask);
    }
  } else {
    return server_start(cert_file, pkey_file, passwd_db, pkey_password, cli_socket,
                          server_ip, tcp_port, udp_port, network, netmask);
  }

  return 0;
}
