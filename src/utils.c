#include <stdio.h>
#include<sys/socket.h>
#include <arpa/inet.h>
#include<time.h>
#include <unistd.h>

#include "../include/utils.h"
#include "../include/config.h"
#include "../include/logger.h"

void log_connection_details(const struct sockaddr_in *addr, const char *protocol, const char *payload) {
    char timestamp[64];
    char ip_str[INET_ADDRSTRLEN];

    get_timestamp(timestamp, sizeof(timestamp));
    get_ip_str(addr, ip_str, sizeof(ip_str));

    char log_msg[1024];
    snprintf(log_msg, sizeof(log_msg),
             "[%s] %s connection from %s:%d | Payload: %.200s",
             timestamp,
             protocol,
             ip_str,
             ntohs(addr->sin_port),
             payload ? payload : "<no data>");

    log_message(log_msg);
}


void get_timestamp(char *buffer, size_t size) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", tm_info);
}

void get_ip_str(const struct sockaddr_in *addr, char *ip_str, size_t maxlen) {
    inet_ntop(AF_INET, &addr->sin_addr, ip_str, maxlen);
}

int safe_recv(int sockfd, char *buffer, size_t size, int timeout_sec){
    ssize_t bytes_received = recv(sockfd, buffer, size - 1, 0);
    if (bytes_received < 0) {
        perror("recv");
        return -1;
    }
    buffer[bytes_received] = '\0'; // Null-terminate the received data
    return bytes_received;
}



