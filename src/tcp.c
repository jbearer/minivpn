#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#include "tcp.h"

bool read_n(int fd, void *void_buf, size_t togo)
{
  char *buf = (char *)void_buf;

  while (togo > 0) {
    ssize_t nread = read(fd, buf, togo);
    if (nread < 0) {
      perror("read");
      return false;
    }
    togo -= nread;
    buf += nread;
  }
  return true;
}

bool write_n(int fd, const void *void_buf, size_t togo)
{
  const char *buf = (const char *)void_buf;

  while (togo > 0) {
    ssize_t nwrite = write(fd, buf, togo);
    if (nwrite < 0) {
      perror("write");
      return false;
    }
    togo -= nwrite;
    buf += nwrite;
  }
  return true;
}

int tcp_server(int af, const struct sockaddr *addr, socklen_t addr_len)
{
  int sockfd = socket(af, SOCK_STREAM, 0);
  if (sockfd < 0) {
    perror("socket");
    return -1;
  }

  // Avoid EADDRINUSE error on bind()
  int optval = 1;
  if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0){
    perror("setsockopt");
    goto err_close_sock;
  }

  if (bind(sockfd, addr, addr_len) < 0) {
    perror("bind");
    goto err_close_sock;
  }

  if (listen(sockfd, 16) < 0) {
    perror("listen");
    goto err_close_sock;
  }

  return sockfd;

err_close_sock:
  close(sockfd);
  return -1;
}

int tcp_client(int af, const struct sockaddr *addr, socklen_t addr_len)
{
  int sockfd = socket(af, SOCK_STREAM, 0);
  if (sockfd < 0) {
    perror("socket");
    return -1;
  }
  if (connect(sockfd, addr, addr_len) < 0) {
    perror("connect");
    close(sockfd);
    return -1;
  }

  return sockfd;
}
