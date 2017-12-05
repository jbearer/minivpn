#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "client.h"
#include "tunnel.h"

#define FILE_PATH_SIZE 100

static void usage(const char *progname)
{
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s [options]\n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-s, --socket <file>: client CLI socket (default is %s)\n",
    CLIENT_DEFAULT_CLI_SOCKET);
  fprintf(stderr, "-k, --key <file>: update the session key\n");
  fprintf(stderr, "-i, --iv <file>: update the session initialization vector\n");
  fprintf(stderr, "-h, --help: prints this help text\n");
  exit(1);
}

int main(int argc, char **argv)
{
  char sock[FILE_PATH_SIZE] = CLIENT_DEFAULT_CLI_SOCKET;
  char key_file[FILE_PATH_SIZE] = "";
  char iv_file[FILE_PATH_SIZE] = "";

  struct option long_options[] =
  {
    {"help",   no_argument,       0, 'h'},
    {"socket", required_argument, 0, 's'},
    {"key",    required_argument, 0, 'k'},
    {"iv",     required_argument, 0, 'i'},
    {0, 0, 0, 0}
  };

  char option;
  while((option = getopt_long(argc, argv, "hs:k:i:", long_options, NULL)) > 0) {
    switch(option) {
    case 's':
      bzero(sock, FILE_PATH_SIZE);
      strncpy(sock, optarg, FILE_PATH_SIZE-1);
      break;
    case 'k':
      bzero(key_file, FILE_PATH_SIZE);
      strncpy(key_file, optarg, FILE_PATH_SIZE-1);
      break;
    case 'i':
      bzero(iv_file, FILE_PATH_SIZE);
      strncpy(iv_file, optarg, FILE_PATH_SIZE-1);
      break;
    case 'h':
    default:
      usage(argv[0]);
    }
  }

  if (argc != optind) {
    usage(argv[0]);
  }

  bool ok = true;

  if (key_file[0] != '\0') {
    unsigned char key[TUNNEL_KEY_SIZE];
    ok &= (client_read_key(key_file, key) && client_update_key(sock, key));
  }
  if (iv_file[0] != '\0') {
    unsigned char iv[TUNNEL_IV_SIZE];
    ok &= (client_read_iv(iv_file, iv) && client_update_iv(sock, iv));
  }

  return ok ? 0 : 1;
}
