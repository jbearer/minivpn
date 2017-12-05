#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "server.h"

#define FILE_PATH_SIZE 100

static void usage(const char *progname)
{
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s [options]\n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-s, --socket <file>: server CLI socket (default is %s)\n",
    SERVER_DEFAULT_CLI_SOCKET);
  fprintf(stderr, "-h, --help: prints this help text\n");
  exit(1);
}

int main(int argc, char **argv)
{
  char sock[FILE_PATH_SIZE] = SERVER_DEFAULT_CLI_SOCKET;

  struct option long_options[] =
  {
    {"help",   no_argument,       0, 'h'},
    {"socket", required_argument, 0, 's'},
    {0, 0, 0, 0}
  };

  char option;
  while((option = getopt_long(argc, argv, "hs:", long_options, NULL)) > 0) {
    switch(option) {
    case 's':
      bzero(sock, FILE_PATH_SIZE);
      strncpy(sock, optarg, FILE_PATH_SIZE-1);
      break;
    case 'h':
    default:
      usage(argv[0]);
    }
  }

  if (argc != optind) {
    usage(argv[0]);
  }

  return server_ping(sock) ? 0 : 1;
}
