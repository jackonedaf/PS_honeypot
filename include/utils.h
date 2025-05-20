#ifndef UTILS_H
#define UTILS_H

#include <netinet/in.h>

void log_connection_details(const struct sockaddr_in *addr, const char *protocol, const char *payload);
void get_timestamp(char *buffer, size_t len);
void get_ip_str(const struct sockaddr_in *addr, char *ip_str, size_t maxlen);
int safe_recv(int sockfd, char *buffer, size_t len, int timeout_sec);

#endif
