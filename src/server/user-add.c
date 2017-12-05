#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/rand.h>

#include "password.h"
#include "protocol.h"
#include "server.h"

static void usage(const char *progname)
{
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s [options] username\n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-s, --socket <file>: server CLI socket (default is %s)\n",
    SERVER_DEFAULT_CLI_SOCKET);
  fprintf(stderr, "-p, --password-db <path>: password database (default ~/.minivpn/users)\n");
  fprintf(stderr, "-S, --salt <salt>: %d byte salt to hash with password\n", SALT_SIZE);
  fprintf(stderr, "-o, --offline: update password database but do not attempt to alert running server\n");
  fprintf(stderr, "-h, --help: prints this help text\n");
  exit(1);
}

int main(int argc, char **argv)
{
  int offline = 0;
  char passwd_db[FILE_PATH_SIZE];
  char sock[FILE_PATH_SIZE] = SERVER_DEFAULT_CLI_SOCKET;
  char salt[SALT_SIZE];
  char username[MINIVPN_USERNAME_SIZE] = {0};
  char password[MINIVPN_PASSWORD_SIZE] = {0};

  snprintf(passwd_db, FILE_PATH_SIZE - 1, "%s/.minivpn/users", getenv("HOME"));
  if (RAND_bytes((unsigned char *)salt, SALT_SIZE) != 1) {
    ERR_print_errors_fp(stderr);
    return 1;
  }

  struct option long_options[] =
  {
    {"help",        no_argument,       0, 'h'},
    {"password-db", required_argument, 0, 'p'},
    {"salt",        required_argument, 0, 'S'},
    {"socket",      required_argument, 0, 's'},
    {"offline",     no_argument, &offline, 1},
    {0, 0, 0, 0}
  };

  char option;
  while((option = getopt_long(argc, argv, "hp:S:os:", long_options, NULL)) > 0) {
    switch(option) {
    case 'p':
      bzero(passwd_db, FILE_PATH_SIZE);
      strncpy(passwd_db, optarg, FILE_PATH_SIZE-1);
      break;
    case 'S':
      if (strlen(optarg) != SALT_SIZE) {
        fprintf(stderr, "salt must be exactly %d bytes\n", SALT_SIZE);
        return 1;
      }
      strcpy(salt, optarg);
      break;
    case 'o':
      offline = 1;
      break;
    case 's':
      bzero(sock, FILE_PATH_SIZE);
      strncpy(sock, optarg, FILE_PATH_SIZE-1);
      break;
    case 'h':
    default:
      usage(argv[0]);
    }
  }

  if (argc != optind + 1) {
    usage(argv[0]);
  }

  strncpy(username, argv[optind++], MINIVPN_USERNAME_SIZE - 1);
  prompt_password("Enter password:", password, MINIVPN_PASSWORD_SIZE);

  passwd_db_conn *pwddb = passwd_db_connect(passwd_db);
  if (pwddb == NULL) {
    fprintf(stderr, "unable to connect to password database\n");
    return 1;
  }

  if (!passwd_db_add(pwddb, username, password, salt)) {
    fprintf(stderr, "unable to add user\n");
    return 1;
  }
}
