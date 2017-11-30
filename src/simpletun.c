/**************************************************************************
 * simpletun.c                                                            *
 *                                                                        *
 * A simplistic, simple-minded, naive tunnelling program using tun/tap    *
 * interfaces and UDP. Handles (badly) IPv4 for tun, ARP and IPv4 for     *
 * tap. DO NOT USE THIS PROGRAM FOR SERIOUS PURPOSES.                     *
 *                                                                        *
 * You have been warned.                                                  *
 *                                                                        *
 * (C) 2009 Davide Brini.                                                 *
 * Modified 2017 Jeb Bearer.                                              *
 *                                                                        *
 * DISCLAIMER AND WARNING: this is all work in progress. The code is      *
 * ugly, the algorithms are naive, error checking and input validation    *
 * are very basic, and of course there can be bugs. If that's not enough, *
 * the program has not been thoroughly tested, so it might even fail at   *
 * the few simple things it should be supposed to do right.               *
 * Needless to say, I take no responsibility whatsoever for what the      *
 * program might do. The program has been written mostly for learning     *
 * purposes, and can be used in the hope that is useful, but everything   *
 * is to be taken "as is" and without any kind of warranty, implicit or   *
 * explicit. See the file LICENSE for further details.                    *
 *************************************************************************/

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000
#define PORT 55555

/* some common lengths */
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28
#define OPENSSL_KEY_SIZE (256/8)
#define OPENSSL_IV_SIZE (128/8)
#define HMAC_SIZE (256/8)

#define OPENSSL_ERR() { ERR_print_errors_fp(stderr); result = -1; goto openssl_cleanup; }

static int debug;
static char *progname;
static unsigned char openssl_key[OPENSSL_KEY_SIZE] = {0};
static EVP_PKEY *openssl_pkey;
static unsigned char openssl_iv[OPENSSL_IV_SIZE] = {0};

ssize_t encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext) {
  EVP_CIPHER_CTX *ctx;

  int len;

  ssize_t result = 0;

  /* Create and initialise the context */
  if (!(ctx = EVP_CIPHER_CTX_new())) {
    ERR_print_errors_fp(stderr);
    return -1;
  }

  /* Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, openssl_key, openssl_iv)) OPENSSL_ERR();

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) OPENSSL_ERR();
  result = len;

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) OPENSSL_ERR();
  result += len;

openssl_cleanup:
  EVP_CIPHER_CTX_free(ctx);

  return result;
}

ssize_t decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext) {
  EVP_CIPHER_CTX *ctx;

  int len;

  ssize_t result = 0;

  /* Create and initialise the context */
  if (!(ctx = EVP_CIPHER_CTX_new())) {
    ERR_print_errors_fp(stderr);
    return -1;
  }

  /* Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, openssl_key, openssl_iv)) OPENSSL_ERR();

  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) OPENSSL_ERR();
  result = len;

  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) OPENSSL_ERR();
  result += len;


openssl_cleanup:
  EVP_CIPHER_CTX_free(ctx);

  return result;
}

/*
 * Compute the SHA256 HMAC digest of msg and store it in hmac. hmac must point to an array of at
 * least HMAC_SIZE bytes.
 */
int hmac_sign(unsigned char *msg, int msg_len, unsigned char *hmac) {
  int result = 0;

  EVP_MD_CTX* ctx = EVP_MD_CTX_create();
  if (ctx == NULL) {
    ERR_print_errors_fp(stderr);
    return -1;
  }

  const EVP_MD* md = EVP_get_digestbyname("SHA256");
  if (md == NULL) OPENSSL_ERR();

  if (EVP_DigestInit_ex(ctx, md, NULL) != 1) OPENSSL_ERR();
  if (EVP_DigestSignInit(ctx, NULL, md, NULL, openssl_pkey) != 1) OPENSSL_ERR();
  if (EVP_DigestSignUpdate(ctx, msg, msg_len) != 1) OPENSSL_ERR();

  size_t hmac_size = 0;
  if (EVP_DigestSignFinal(ctx, NULL, &hmac_size) != 1 || hmac_size == 0) OPENSSL_ERR();
  if (hmac_size != HMAC_SIZE) {
    fprintf(stderr, "Unexpected hmac size %zu (expected %d)\n", hmac_size, HMAC_SIZE);
    result = -1;
    goto openssl_cleanup;
  }

  if (EVP_DigestSignFinal(ctx, hmac, &hmac_size) != 1) OPENSSL_ERR();
  if (hmac_size != HMAC_SIZE) {
    fprintf(stderr, "EVP_DigestSignFinal failed: mismatched sizes (%zu vs %d)\n",
        hmac_size, HMAC_SIZE);
    result = -1;
    goto openssl_cleanup;
  }

openssl_cleanup:
  EVP_MD_CTX_destroy(ctx);

  return result;
}

/*
 * Compute the SHA256 HMAC digest of msg and compare it to hmac. Returns 0 if digest matches,
 * 1 if digest does not match, or -1 if an error ocurred.
 */
int hmac_verify(unsigned char *msg, int msg_len, unsigned char *hmac) {
  unsigned char computed_hmac[HMAC_SIZE];
  if (hmac_sign(msg, msg_len, computed_hmac) < 0) {
    return -1;
  }

  return !!memcmp(hmac, computed_hmac, HMAC_SIZE);
}

/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            needs to reserve enough space in *dev.                      *
 **************************************************************************/
int tun_alloc(char *dev, int flags) {

  struct ifreq ifr;
  int fd, err;

  if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
    perror("Opening /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
    perror("ioctl(TUNSETIFF)");
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);

  return fd;
}

/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
void do_debug(char *msg, ...){

  va_list argp;

  if(debug){
  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
  }
}

/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(char *msg, ...) {

  va_list argp;

  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
}

void tap_to_net(int tap_fd, int net_fd, const struct sockaddr_in *remote) {
  /* data from tun/tap: just read it and write it to the network */

  static unsigned long count = 0;

  unsigned char plain[BUFSIZE];

  ssize_t nbytes = read(tap_fd, plain, BUFSIZE);
  if (nbytes == -1) {
    perror("read");
    return;
  }

  count++;
  do_debug("TAP2NET %lu: Read %d bytes from the tap interface\n", count, nbytes);

  unsigned char packet[BUFSIZE];
  unsigned char *hmac = packet;
  unsigned char *cipher = packet + HMAC_SIZE;

  ssize_t cipher_len = encrypt(plain, nbytes, cipher);
  if (cipher_len == -1) {
    do_debug("TAP2NET %lu: Failed to encrypt message, dropping packet\n", count);
    return;
  } else {
    do_debug("TAP2NET %lu: Encrypted message is %zd bytes\n", count, cipher_len);
  }

  if (hmac_sign(cipher, cipher_len, hmac) < 0) {
    do_debug("TAP2NET %lu: Failed to compute message HMAC, dropping packet\n", count);
    return;
  }

  ssize_t nwrite = sendto(net_fd, packet, HMAC_SIZE + cipher_len, 0, (const struct sockaddr *)remote, sizeof(*remote));
  if (nwrite == -1) {
    perror("sendto");
    return;
  }

  do_debug("TAP2NET %lu: Written %d bytes to the network\n", count, nwrite);
}

void net_to_tap(int net_fd, int tap_fd) {
  /* data from the network: read it, and write it to the tun/tap interface.
   * We need to read the length first, and then the packet */

  static unsigned long count = 0;

  unsigned char packet[BUFSIZE];

  ssize_t nbytes = recvfrom(net_fd, packet, BUFSIZE, 0, NULL, NULL);
  if (nbytes == -1) {
    perror("recvfrom");
    return;
  }

  if (nbytes == 0) {
    /* ctrl-c at the other end */
    exit(0);
  }
  count++;
  do_debug("NET2TAP %lu: Read %d bytes from the network\n", count, nbytes);

  unsigned char *hmac = packet;
  unsigned char *cipher = packet + HMAC_SIZE;
  size_t cipher_len = nbytes - HMAC_SIZE;

  if (hmac_verify(cipher, cipher_len, hmac) != 0) {
    do_debug("NET2TAP %lu: Failed to verify HMAC, dropping packet\n", count);
    return;
  }

  unsigned char plain[BUFSIZE];
  ssize_t plain_len = decrypt(cipher, cipher_len, plain);
  if (plain_len == -1) {
    do_debug("NET2TAP %lu: Failed to decrypt message, dropping packet\n", count);
    return;
  } else {
    do_debug("NET2TAP %lu: Decypted message is %zd bytes\n", count, plain_len);
  }

  /* now plain[] contains a full packet or frame, write it into the tun/tap interface */
  ssize_t nwrite = write(tap_fd, plain, plain_len);
  if (nwrite == -1) {
    perror("write");
    return;
  }
  do_debug("NET2TAP %lu: Written %d bytes to the tap interface\n", count, nwrite);
}

void init_openssl() {
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OPENSSL_config(NULL);

  // Set pkey to correspond with key
  openssl_pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, openssl_key, OPENSSL_KEY_SIZE);
}

void read_key(const char *file) {
  int fd = open(file, O_RDONLY);
  if (fd == -1) {
    perror("Error opening key file");
    exit(1);
  }

  ssize_t nbytes = read(fd, openssl_key, OPENSSL_KEY_SIZE);
  if (nbytes == -1) {
    perror("Error reading key file");
    exit(1);
  } else if (nbytes < OPENSSL_KEY_SIZE) {
    fprintf(stderr, "Invalid key length %zd (expected %d)", nbytes, OPENSSL_KEY_SIZE);
    exit(1);
  }

  // Check that the key isn't too long
  char dummy;
  if (read(fd, &dummy, 1) > 0) {
    fprintf(stderr, "Key is too long (expected %d bytes)", OPENSSL_KEY_SIZE);
    exit(1);
  }
}

void read_iv(const char *file) {
  int fd = open(file, O_RDONLY);
  if (fd == -1) {
    perror("Error opening iv file");
    exit(1);
  }

  ssize_t nbytes = read(fd, openssl_iv, OPENSSL_IV_SIZE);
  if (nbytes == -1) {
    perror("Error reading iv file");
    exit(1);
  } else if (nbytes < OPENSSL_IV_SIZE) {
    fprintf(stderr, "Invalid iv length %zd (expected %d)", nbytes, OPENSSL_IV_SIZE);
    exit(1);
  }

  // Check that the iv isn't too long
  char dummy;
  if (read(fd, &dummy, 1) > 0) {
    fprintf(stderr, "Iv is too long (expected %d bytes)", OPENSSL_IV_SIZE);
    exit(1);
  }
}

/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(void) {
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s -i <ifacename> -n <IP> [-p <port>] [-o <port>] [-u|-a] [-v]\n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-i, --interface <ifacename>: Name of interface to use (mandatory)\n");
  fprintf(stderr, "-n, --peer-ip <IP>: peer gateway IP address (mandatory)\n");
  fprintf(stderr, "-k, --encryption-key <file>: key to use for encryption, 256 bit (default 0)");
  fprintf(stderr, "-e, --encryption-iv <file>: initialization vector for encryption, 128 bit (default 0)");
  fprintf(stderr, "-p, --port <port>: outgoing UDP port (default 55555)\n");
  fprintf(stderr, "-o, --peer-port<port>: peer gateway UDP port (default 55555)\n");
  fprintf(stderr, "-u, --tunnel use TUN (default)\n");
  fprintf(stderr, "-a, --tap use TAP (instead of TUN)\n");
  fprintf(stderr, "-v, --verbose: outputs debug information while running\n");
  fprintf(stderr, "-h, --help: prints this help text\n");
  exit(1);
}

int main(int argc, char *argv[]) {

  int option;
  int flags = IFF_TUN;
  char if_name[IFNAMSIZ] = "";
  char remote_ip[16] = "";
  unsigned short int local_port = PORT;
  unsigned short int remote_port = PORT;

  progname = argv[0];

  struct option long_options[] =
  {
    /* These options set a flag. */
    {"verbose",         no_argument,       &debug, 1},
    {"tunnel",          no_argument,       &flags, IFF_TUN},
    {"tap",             no_argument,       &flags, IFF_TAP},
    {"help",            no_argument,       0, 'h'},
    {"interface",       required_argument, 0, 'i'},
    {"port",            required_argument, 0, 'p'},
    {"peer-ip",         required_argument, 0, 'n'},
    {"peer-port",       required_argument, 0, 'o'},
    {"encryption-key",  required_argument, 0, 'k'},
    {"encryption-iv",   required_argument, 0, 'e'},
    {0, 0, 0, 0}
  };

  /* Check command line options */
  while((option = getopt_long(argc, argv, "i:n:p:o:k:e:uahv", long_options, NULL)) > 0){
    switch(option) {
      case 'd':
        debug = 1;
        break;
      case 'h':
        usage();
        break;
      case 'i':
        strncpy(if_name, optarg, IFNAMSIZ - 1);
        break;
      case 'n':
        strncpy(remote_ip,optarg,15);
        break;
      case 'o':
        remote_port = atoi(optarg);
        break;
      case 'p':
        local_port = atoi(optarg);
        break;
      case 'u':
        flags = IFF_TUN;
        break;
      case 'a':
        flags = IFF_TAP;
        break;
      case 'k':
        read_key(optarg);
        break;
      case 'e':
        read_iv(optarg);
        break;
      case 'v':
        debug = 1;
        break;
      default:
        my_err("Unknown option %c\n", option);
        usage();
    }
  }

  if(*if_name == '\0'){
    my_err("Must specify interface name!\n");
    usage();
  } else if (*remote_ip == '\0') {
    my_err("Must specify remote address!\n");
    usage();
  }

  init_openssl();

  /* initialize tun/tap interface */
  int tap_fd;
  if ( (tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0 ) {
    my_err("Error connecting to tun/tap interface %s!\n", if_name);
    exit(1);
  }

  do_debug("Successfully connected to interface %s\n", if_name);

  int net_fd;
  if ( (net_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("socket()");
    exit(1);
  }

  /* avoid EADDRINUSE error on bind() */
  int optval = 1;
  if(setsockopt(net_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0){
    perror("setsockopt()");
    exit(1);
  }

  struct sockaddr_in local;
  memset(&local, 0, sizeof(local));
  local.sin_family = AF_INET;
  local.sin_addr.s_addr = htonl(INADDR_ANY);
  local.sin_port = htons(local_port);
  if (bind(net_fd, (struct sockaddr*) &local, sizeof(local)) < 0){
    perror("bind()");
    exit(1);
  }
  do_debug("Bound to port %d\n", local_port);

  /* assign the destination address */
  struct sockaddr_in remote;
  memset(&remote, 0, sizeof(remote));
  remote.sin_family = AF_INET;
  remote.sin_addr.s_addr = inet_addr(remote_ip);
  remote.sin_port = htons(remote_port);
  do_debug("Peer at %s:%d\n", remote_ip, remote_port);

  /* use select() to handle two descriptors at once */
  int maxfd = (tap_fd > net_fd)?tap_fd:net_fd;

  while(1) {
    int ret;
    fd_set rd_set;

    FD_ZERO(&rd_set);
    FD_SET(tap_fd, &rd_set); FD_SET(net_fd, &rd_set);

    ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);

    if (ret < 0 && errno == EINTR){
      continue;
    }

    if (ret < 0) {
      perror("select()");
      exit(1);
    }

    if(FD_ISSET(tap_fd, &rd_set)){
      tap_to_net(tap_fd, net_fd, &remote);
    }
    if(FD_ISSET(net_fd, &rd_set)){
      net_to_tap(net_fd, tap_fd);
    }

  }

  return(0);
}
