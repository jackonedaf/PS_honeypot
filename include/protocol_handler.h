#ifndef PROTOCOL_HANDLER_H
#define PROTOCOL_HANDLER_H

#include <netinet/in.h>

struct sockaddr_in;

void is_suspcious_http_request(const char *request);
void is_suspcious_ssh_request(const char *request);
void is_suspcious_telnet_request(const char *request);
void handle_http_request(int client_sock, const struct sockaddr_in *client_addr);
void handle_ssh_request(int client_sock);
void handle_telnet_request(int client_sock);
#endif
