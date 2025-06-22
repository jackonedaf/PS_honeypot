#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>

#include "../include/utils.h"
#include "../include/config.h"
#include "../include/logger.h"

void get_timestamp(char *buffer, size_t size)
{
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", tm_info);
}

void get_ip_str(const struct sockaddr_in *addr, char *ip_str, size_t maxlen)
{
    inet_ntop(AF_INET, &addr->sin_addr, ip_str, maxlen);
}

int safe_recv(int sockfd, char *buffer, size_t size, int timeout_sec)
{
    ssize_t bytes_received = recv(sockfd, buffer, size - 1, 0);
    if (bytes_received < 0)
    {
        perror("recv");
        return -1;
    }
    buffer[bytes_received] = '\0'; // Null-terminate the received data
    return bytes_received;
}

void clearFileByPath(const char *path)
{
    FILE *file = fopen(path, "w");
    if (file)
        fclose(file);
}
