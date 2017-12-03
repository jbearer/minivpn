#include <arpa/inet.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/if.h>
#include <linux/if_tun.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "tunnel.h"

#define BUFFER_SIZE 2000
#define HMAC_SIZE (256/8)

#ifdef DEBUG
#define tunnel_debug(t, fmt, ...) fprintf(stderr, "tunnel %" PRId64 ": " fmt, t->dev, __VA_ARGS__);
#else
#define tunnel_debug(...)
#endif

#define OPENSSL_ERR() { ERR_print_errors_fp(stderr); result = -1; goto openssl_cleanup; }

// Free device name bitmap
static uint64_t _free_devices[MAX_TUNNELS / 64] = {(uint64_t)-1};

static void close_module()
{
  ERR_free_strings();
  EVP_cleanup();
}

static void init_module()
{
  static bool first_call = true;
  if (!__sync_bool_compare_and_swap(&first_call, true, false)) {
    return;
  }

  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OPENSSL_config(NULL);
  atexit(close_module);
}

static int64_t alloc_dev()
{
  for (size_t block = 0; block < MAX_TUNNELS / 64; ++block) {
    if (_free_devices[block]) {
      for (unsigned bit = 0; bit < 64; ++bit) {
        uint64_t mask = 1 << bit;
        if (_free_devices[block] & mask) {
          _free_devices[block] &= ~mask;
          return 64*block + bit;
        }
      }
    }
  }
  return -1;
}

static void dealloc_dev(int64_t dev)
{
  size_t block = dev / 64;
  size_t bit = dev % 64;
  uint64_t mask = 1 << bit;
  _free_devices[block] |= mask;
}

static int open_tunnel(char *dev)
{
  struct ifreq ifr;
  int fd, err;

  if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
    perror("opening /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

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

struct __tunnel {
  unsigned char key[TUNNEL_KEY_SIZE];
  unsigned char iv[TUNNEL_IV_SIZE];
  EVP_PKEY *pkey;
  int64_t dev;
  int tap_fd;
  int net_fd;
  struct sockaddr_in sin_local;
  struct sockaddr_in sin_remote;
  bool halt;
  bool running;
  size_t tap_to_net_count;
  size_t net_to_tap_count;
  char network[INET_ADDRSTRLEN + 1];
  char netmask[INET_ADDRSTRLEN + 1];
};

static bool isup(tunnel *t)
{
  int sockfd;
  struct ifreq ifr;

  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    tunnel_debug(t, "ifup: error opening socket: %s\n", strerror(errno));
    return false;
  }

  memset(&ifr, 0, sizeof ifr);
  snprintf(ifr.ifr_name, IFNAMSIZ, "tun%" PRId64, t->dev);

  if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
    tunnel_debug(t, "ifup: error getting interface flags: %s\n", strerror(errno));
    return false;
  }

  return !!(ifr.ifr_flags & IFF_UP);
}

static bool ifup(tunnel *t)
{
  int sockfd;
  struct ifreq ifr;

  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    tunnel_debug(t, "ifup: error opening socket: %s\n", strerror(errno));
    return false;
  }

  memset(&ifr, 0, sizeof ifr);
  snprintf(ifr.ifr_name, IFNAMSIZ, "tun%" PRId64, t->dev);

  if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
    tunnel_debug(t, "ifup: error getting interface flags: %s\n", strerror(errno));
    return false;
  }

  ifr.ifr_flags |= IFF_UP;

  if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
    tunnel_debug(t, "ifup: error setting interface falgs: %s\n", strerror(errno));
    return false;
  }

  tunnel_debug(t, "brought up interface tun%" PRId64 "\n", t->dev);
  return true;
}

static bool ifdown(tunnel *t)
{
  int sockfd;
  struct ifreq ifr;

  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    tunnel_debug(t, "ifdown: error opening socket: %s\n", strerror(errno));
    return false;
  }

  memset(&ifr, 0, sizeof ifr);
  snprintf(ifr.ifr_name, IFNAMSIZ, "tun%" PRId64, t->dev);

  if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
    tunnel_debug(t, "ifdown: error getting interface flags: %s\n", strerror(errno));
    return false;
  }

  ifr.ifr_flags &= ~IFF_UP;

  if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
    tunnel_debug(t, "ifdown: error setting interface falgs: %s\n", strerror(errno));
    return false;
  }

  tunnel_debug(t, "brought up interface tun%" PRId64 "\n", t->dev);
  return true;
}

static void tunnel_unroute(tunnel *t)
{
  if (t->network[0] != '\0') {
    // HACK should replace this with an ioctl SIOCADDRT implementation
    char comm[100] = {0};
    sprintf(comm, "route del -net %s netmask %s dev tun%" PRId64 "\n", t->network, t->netmask, t->dev);
    if (system(comm) != 0) {
      tunnel_debug(t, "could not delete route %s %s tun%" PRId64 "\n", t->network, t->netmask, t->dev);
    }
  }

  tunnel_debug(t, "deleted route %s %s tun%" PRId64 "\n", t->network, t->netmask, t->dev);
}

bool tunnel_route(tunnel *t, int network, int netmask)
{
  char network_str[INET_ADDRSTRLEN];
  char netmask_str[INET_ADDRSTRLEN];
  struct in_addr addr;

  addr.s_addr = network;
  inet_ntop(AF_INET, &addr, network_str, INET_ADDRSTRLEN);
  addr.s_addr = netmask;
  inet_ntop(AF_INET, &addr, netmask_str, INET_ADDRSTRLEN);


  bzero(t->network, sizeof(t->network));
  bzero(t->netmask, sizeof(t->netmask));
  strncpy(t->network, network_str, INET_ADDRSTRLEN);
  strncpy(t->netmask, netmask_str, INET_ADDRSTRLEN);

  tunnel_unroute(t);

  if (!isup(t)) {
    if (!ifup(t)) return false;
  }

  // HACK should replace this with an ioctl SIOCADDRT implementation
  char comm[100] = {0};
  sprintf(comm, "route add -net %s netmask %s dev tun%" PRId64 "\n", t->network, t->netmask, t->dev);
  if (system(comm) != 0) {
    tunnel_debug(t, "could not add route %s %s tun%" PRId64 "\n", t->network, t->netmask, t->dev);
    return false;
  }

  tunnel_debug(t, "added route %s %s tun%" PRId64 "\n", t->network, t->netmask, t->dev);
  return true;
}

tunnel *tunnel_new(
  const unsigned char *key, const unsigned char *iv, int peer_ip, int peer_port, int local_port)
{
  init_module();

  tunnel *t = (tunnel *)malloc(sizeof(tunnel));
  if (!t) {
    perror("malloc");
    return NULL;
  }

  bzero(t->network, sizeof(t->network));
  bzero(t->netmask, sizeof(t->netmask));
  t->halt = false;
  t->running = false;

  memcpy(t->key, key, TUNNEL_KEY_SIZE);
  memcpy(t->iv, iv, TUNNEL_IV_SIZE);
  t->pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, t->key, TUNNEL_KEY_SIZE);
  if (t->pkey == NULL) {
    ERR_print_errors_fp(stderr);
    goto err_pkey;
  }

  // Allocate device id
  t->dev = alloc_dev();
  if (t->dev < 0) {
    fprintf(stderr, "out of devices\n");
    goto err_dev;
  }

  // Open tunnel
  char dev[100];
  sprintf(dev, "tun%" PRId64, t->dev);
  t->tap_fd = open_tunnel(dev);
  if (t->tap_fd < 0) {
    goto err_tun;
  }

  // Open network socket
  t->net_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (t->net_fd < 0) {
    perror("socket");
    goto err_sock;
  }

  // Avoid EADDRINUSE error on bind()
  int optval = 1;
  if(setsockopt(t->net_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0){
    perror("setsockopt");
    goto err_sockopt;
  }

  memset(&t->sin_local, 0, sizeof(t->sin_local));
  t->sin_local.sin_family = AF_INET;
  t->sin_local.sin_addr.s_addr = htonl(INADDR_ANY);
  t->sin_local.sin_port = htons(local_port);
  if (bind(t->net_fd, (struct sockaddr*)&t->sin_local, sizeof(t->sin_local)) < 0){
    perror("bind");
    goto err_bind;
  }
  tunnel_debug(t, "bound to port %d\n", local_port);

  // Assign the destination address
  memset(&t->sin_remote, 0, sizeof(t->sin_remote));
  t->sin_remote.sin_family = AF_INET;
  t->sin_remote.sin_addr.s_addr = htonl(peer_ip);
  t->sin_remote.sin_port = htons(peer_port);
  tunnel_debug(t, "peer at %d:%d\n", peer_ip, peer_port);

  return t;

err_bind:
err_sockopt:
  close(t->net_fd);
err_sock:
  close(t->tap_fd);
err_tun:
  dealloc_dev(t->dev);
err_dev:
  EVP_PKEY_free(t->pkey);
err_pkey:
  return NULL;
}

void tunnel_delete(tunnel *t)
{
  tunnel_stop(t);
  tunnel_unroute(t);
  ifdown(t);
  EVP_PKEY_free(t->pkey);
  dealloc_dev(t->dev);
  close(t->tap_fd);
  close(t->net_fd);
}

static ssize_t encrypt(unsigned char *key, unsigned char *iv,
                       unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext)
{
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
  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) OPENSSL_ERR();

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

static ssize_t decrypt(unsigned char *key, unsigned char *iv,
                       unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext)
{
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
  if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) OPENSSL_ERR();

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
static int hmac_sign(EVP_PKEY *key, unsigned char *msg, int msg_len, unsigned char *hmac) {
  int result = 0;

  EVP_MD_CTX* ctx = EVP_MD_CTX_create();
  if (ctx == NULL) {
    ERR_print_errors_fp(stderr);
    return -1;
  }

  const EVP_MD* md = EVP_get_digestbyname("SHA256");
  if (md == NULL) OPENSSL_ERR();

  if (EVP_DigestInit_ex(ctx, md, NULL) != 1) OPENSSL_ERR();
  if (EVP_DigestSignInit(ctx, NULL, md, NULL, key) != 1) OPENSSL_ERR();
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
static int hmac_verify(EVP_PKEY *key, unsigned char *msg, int msg_len, unsigned char *hmac) {
  unsigned char computed_hmac[HMAC_SIZE];
  if (hmac_sign(key, msg, msg_len, computed_hmac) < 0) {
    return -1;
  }

  return !!memcmp(hmac, computed_hmac, HMAC_SIZE);
}

static void tap_to_net(tunnel *t) {
  unsigned char plain[BUFFER_SIZE];

  ssize_t nbytes = read(t->tap_fd, plain, BUFFER_SIZE);
  if (nbytes == -1) {
    perror("read");
    return;
  }

  t->tap_to_net_count++;
  tunnel_debug(t, "TAP2NET %zu: Read %d bytes from the tap interface\n", t->tap_to_net_count, nbytes);

  unsigned char packet[BUFFER_SIZE];
  unsigned char *hmac = packet;
  unsigned char *cipher = packet + HMAC_SIZE;

  ssize_t cipher_len = encrypt(t->key, t->iv, plain, nbytes, cipher);
  if (cipher_len == -1) {
    tunnel_debug(t, "TAP2NET %zu: Failed to encrypt message, dropping packet\n", t->tap_to_net_count);
    return;
  } else {
    tunnel_debug(t, "TAP2NET %zu: Encrypted message is %zd bytes\n", t->tap_to_net_count, cipher_len);
  }

  if (hmac_sign(t->pkey, cipher, cipher_len, hmac) < 0) {
    tunnel_debug(t, "TAP2NET %zu: Failed to compute message HMAC, dropping packet\n", t->tap_to_net_count);
    return;
  }

  ssize_t nwrite = sendto(t->net_fd, packet, HMAC_SIZE + cipher_len, 0,
                          (const struct sockaddr *)&t->sin_remote, sizeof(t->sin_remote));
  if (nwrite == -1) {
    perror("sendto");
    return;
  }

  tunnel_debug(t, "TAP2NET %zu: Written %d bytes to the network\n", t->tap_to_net_count, nwrite);
}

static void net_to_tap(tunnel *t) {
  unsigned char packet[BUFFER_SIZE];

  ssize_t nbytes = recvfrom(t->net_fd, packet, BUFFER_SIZE, 0, NULL, NULL);
  if (nbytes == -1) {
    perror("recvfrom");
    return;
  }

  if (nbytes == 0) {
    /* ctrl-c at the other end */
    exit(0);
  }
  t->net_to_tap_count++;
  tunnel_debug(t, "NET2TAP %zu: Read %d bytes from the network\n", t->net_to_tap_count, nbytes);

  unsigned char *hmac = packet;
  unsigned char *cipher = packet + HMAC_SIZE;
  size_t cipher_len = nbytes - HMAC_SIZE;

  if (hmac_verify(t->pkey, cipher, cipher_len, hmac) != 0) {
    tunnel_debug(t, "NET2TAP %zu: Failed to verify HMAC, dropping packet\n", t->net_to_tap_count);
    return;
  }

  unsigned char plain[BUFFER_SIZE];
  ssize_t plain_len = decrypt(t->key, t->iv, cipher, cipher_len, plain);
  if (plain_len == -1) {
    tunnel_debug(t, "NET2TAP %zu: Failed to decrypt message, dropping packet\n", t->net_to_tap_count);
    return;
  } else {
    tunnel_debug(t, "NET2TAP %zu: Decypted message is %zd bytes\n", t->net_to_tap_count, plain_len);
  }

  /* now plain[] contains a full packet or frame, write it into the tun/tap interface */
  ssize_t nwrite = write(t->tap_fd, plain, plain_len);
  if (nwrite == -1) {
    perror("write");
    return;
  }
  tunnel_debug(t, "NET2TAP %zu: Written %d bytes to the tap interface\n", t->net_to_tap_count, nwrite);
}

void tunnel_loop(tunnel *t)
{
  int maxfd = t->net_fd > t->tap_fd ? t->net_fd : t->tap_fd;

  while (!t->halt) {
    fd_set rd_set;
    FD_ZERO(&rd_set);
    FD_SET(t->tap_fd, &rd_set);
    FD_SET(t->net_fd, &rd_set);

    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    int ret = select(maxfd + 1, &rd_set, NULL, NULL, &timeout);

    if (ret < 0 && (errno == EINTR)) {
      continue;
    }
    if (ret < 0) {
      perror("select()");
      exit(1);
    }

    if (FD_ISSET(t->tap_fd, &rd_set)) {
      tap_to_net(t);
    }
    if (FD_ISSET(t->net_fd, &rd_set)) {
      net_to_tap(t);
    }
  }

  t->running = false;
}

void tunnel_stop(tunnel *t)
{
  t->halt = true;
  while (t->running);
}
