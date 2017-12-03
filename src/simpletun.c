#include <arpa/inet.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "tunnel.h"

static void read_key(const char *file, unsigned char *key)
{
  int fd = open(file, O_RDONLY);
  if (fd == -1) {
    perror("Error opening key file");
    exit(1);
  }

  ssize_t nbytes = read(fd, key, TUNNEL_KEY_SIZE);
  if (nbytes == -1) {
    perror("Error reading key file");
    exit(1);
  } else if (nbytes < TUNNEL_KEY_SIZE) {
    fprintf(stderr, "Invalid key length %zd (expected %d)", nbytes, TUNNEL_KEY_SIZE);
    exit(1);
  }

  // Check that the key isn't too long
  char dummy;
  if (read(fd, &dummy, 1) > 0) {
    fprintf(stderr, "Key is too long (expected %d bytes)", TUNNEL_KEY_SIZE);
    exit(1);
  }
}

static void read_iv(const char *file, unsigned char *iv)
{
  int fd = open(file, O_RDONLY);
  if (fd == -1) {
    perror("Error opening iv file");
    exit(1);
  }

  ssize_t nbytes = read(fd, iv, TUNNEL_IV_SIZE);
  if (nbytes == -1) {
    perror("Error reading iv file");
    exit(1);
  } else if (nbytes < TUNNEL_IV_SIZE) {
    fprintf(stderr, "Invalid iv length %zd (expected %d)", nbytes, TUNNEL_IV_SIZE);
    exit(1);
  }

  // Check that the iv isn't too long
  char dummy;
  if (read(fd, &dummy, 1) > 0) {
    fprintf(stderr, "Iv is too long (expected %d bytes)", TUNNEL_IV_SIZE);
    exit(1);
  }
}

/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
static void usage(const char *progname)
{
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s -i <IP> -n <IP> [options]\n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-i, --peer-ip <IP>: peer gateway IP address (mandatory)\n");
  fprintf(stderr, "-n, --network <IP>: peer network prefix (mandatory)\n");
  fprintf(stderr, "-m, --netmask <mask>: peer network mask (default 255.255.255.0)\n");
  fprintf(stderr, "-k, --encryption-key <file>: key to use for encryption, 256 bit (default 0)");
  fprintf(stderr, "-e, --encryption-iv <file>: initialization vector for encryption, 128 bit (default 0)");
  fprintf(stderr, "-o, --port <port>: outgoing UDP port (default 55555)\n");
  fprintf(stderr, "-p, --peer-port <port>: peer gateway UDP port (default 55555)\n");
  fprintf(stderr, "-h, --help: prints this help text\n");
  exit(1);
}

int main(int argc, char *argv[])
{
  int option;
  char remote_ip[16] = "";
  char network[16] = "";
  char netmask[16] = "255.255.255.0";
  unsigned short int local_port = 55555;
  unsigned short int remote_port = 55555;
  unsigned char key[TUNNEL_KEY_SIZE] = {0};
  unsigned char iv[TUNNEL_IV_SIZE] = {0};

  struct option long_options[] =
  {
    {"help",            no_argument,       0, 'h'},
    {"port",            required_argument, 0, 'o'},
    {"peer-ip",         required_argument, 0, 'i'},
    {"peer-port",       required_argument, 0, 'p'},
    {"encryption-key",  required_argument, 0, 'k'},
    {"encryption-iv",   required_argument, 0, 'e'},
    {"network",         required_argument, 0, 'n'},
    {"netmask",         required_argument, 0, 'm'},
    {0, 0, 0, 0}
  };

  /* Check command line options */
  while((option = getopt_long(argc, argv, "ho:i:p:k:e:n:m:", long_options, NULL)) > 0){
    switch(option) {
      case 'h':
        usage(argv[0]);
        break;
      case 'o':
        local_port = atoi(optarg);
        break;
      case 'i':
        strncpy(remote_ip, optarg, 15);
        break;
      case 'p':
        remote_port = atoi(optarg);
        break;
      case 'k':
        read_key(optarg, key);
        break;
      case 'e':
        read_iv(optarg, iv);
        break;
      case 'n':
        strncpy(network, optarg, 15);
        break;
      case 'm':
        strncpy(netmask, optarg, 15);
        break;
      default:
        fprintf(stderr, "unknown option %c\n", option);
        usage(argv[0]);
    }
  }

  if (*remote_ip == '\0') {
    fprintf(stderr, "must specify remote address!\n");
    usage(argv[0]);
  }
  if (*network == '\0') {
    fprintf(stderr, "musty specify remote network!\n");
    usage(argv[0]);
  }

  tunnel *tun = tunnel_new(key, iv, inet_addr(remote_ip), remote_port, local_port);
  if (!tun) {
    fprintf(stderr, "unable to open tunnel\n");
    return 1;
  }

  if (!tunnel_route(tun, inet_addr(network), inet_addr(netmask))) {
    fprintf(stderr, "unable to route tunnel\n");
    return 1;
  }

  tunnel_loop(tun);
  tunnel_delete(tun);

  return 0;
}
