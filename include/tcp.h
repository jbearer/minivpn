#pragma once

#include <stdbool.h>
#include <sys/socket.h>

bool read_n(int fd, void *buf, size_t n);
bool write_n(int fd, const void *buf, size_t n);
int tcp_server(int af, const struct sockaddr *addr, socklen_t addr_len);
int tcp_client(int af, const struct sockaddr *addr, socklen_t addr_len);
