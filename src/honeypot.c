#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#include "../include/logger.h"
#include "../include/whitelist.h"
#include "../include/blacklist.h"
#include "../include/utils.h"
#include "../include/protocol_handler.h"
#include "../include/config.h"

#define PORT_TELNET 2323
#define MAX_CONNECTIONS 10

static int create_socket(int port);

int start_honeypot() {
    int sock_http = create_socket(PORT_HTTP);
    int sock_ssh = create_socket(PORT_SSH);
    int sock_telnet = create_socket(PORT_TELNET);

    if (sock_http < 0 || sock_ssh < 0 || sock_telnet < 0) {
        log_message("Socket creation failed.");
        return -1;
    }

    log_message("Honeypot listening on ports 8080 (HTTP), 2222 (SSH), 2323 (Telnet)");

    fd_set master_set, read_set;
    int max_fd = sock_http > sock_ssh ? sock_http : sock_ssh;
    if (sock_telnet > max_fd) max_fd = sock_telnet;

    FD_ZERO(&master_set);
    FD_SET(sock_http, &master_set);
    FD_SET(sock_ssh, &master_set);
    FD_SET(sock_telnet, &master_set);

    while (1) {
        read_set = master_set;
        if (select(max_fd + 1, &read_set, NULL, NULL, NULL) < 0) {
            perror("select");
            continue;
        }

        for (int fd = 0; fd <= max_fd; ++fd) {
            if (!FD_ISSET(fd, &read_set)) continue;

            struct sockaddr_in client_addr;
            socklen_t addr_len = sizeof(client_addr);
            int client_sock = accept(fd, (struct sockaddr *)&client_addr, &addr_len);
            if (client_sock < 0) {
                perror("accept");
                continue;
            }

            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &client_addr.sin_addr, ip_str, sizeof(ip_str));
            log_connection(ip_str, ntohs(client_addr.sin_port), fd == sock_http ? "HTTP" : (fd == sock_ssh ? "SSH" : "Telnet"));

            if (is_blacklisted(ip_str)) {
                log_message("Blocked blacklisted IP");
                close(client_sock);
                continue;
            }

            if (!is_whitelisted(ip_str)) {
                log_message("Suspicious IP detected (not whitelisted)");
            }

            if (fd == sock_http) {
                handle_http_request(client_sock, &client_addr);
            } else if (fd == sock_ssh) {
                handle_ssh_request(client_sock);
            } else if (fd == sock_telnet) {
                handle_telnet_request(client_sock);
            }

            close(client_sock);
        }
    }

    close(sock_http);
    close(sock_ssh);
    close(sock_telnet);
    return 0;
}

static int create_socket(int port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }

    int opt = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sockfd);
        return -1;
    }

    if (listen(sockfd, MAX_CONNECTIONS) < 0) {
        perror("listen");
        close(sockfd);
        return -1;
    }

    return sockfd;
}
