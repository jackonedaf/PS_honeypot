#include <stdio.h>
#include <stdlib.h>
#include "include/logger.h"
#include "include/blacklist.h"
#include "include/whitelist.h"
#include "include/honeypot.h"
#include "include/suspicion_tracker.h"
#include "include/protocol_handler.h"
#include "include/config.h"
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

void* http_thread(void* arg) {
    int sockfd;
    struct sockaddr_in server_addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT_HTTP);

    bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr));
    listen(sockfd, 10);

    log_message("HTTP honeypot listening...");

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t len = sizeof(client_addr);
        int client_sock = accept(sockfd, (struct sockaddr*)&client_addr, &len);
        if (client_sock >= 0) {
            handle_http_request(client_sock, &client_addr);
        }
    }
    return NULL;
}

void* ssh_thread(void* arg) {
    int sockfd;
    struct sockaddr_in server_addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT_SSH);

    bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr));
    listen(sockfd, 10);

    log_message("SSH honeypot listening...");

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t len = sizeof(client_addr);
        int client_sock = accept(sockfd, (struct sockaddr*)&client_addr, &len);
        if (client_sock >= 0) {
            handle_ssh_request(client_sock);
        }
    }
    return NULL;
}

void* telnet_thread(void* arg) {
    int sockfd;
    struct sockaddr_in server_addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Telnet socket");
        return NULL;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT_TELNET);

    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Telnet bind");
        close(sockfd);
        return NULL;
    }

    if (listen(sockfd, 10) < 0) {
        perror("Telnet listen");
        close(sockfd);
        return NULL;
    }

    log_message("Telnet honeypot listening...");

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t len = sizeof(client_addr);
        int client_sock = accept(sockfd, (struct sockaddr*)&client_addr, &len);
        if (client_sock >= 0) {
            handle_telnet_request(client_sock);
        }
    }

    close(sockfd);
    return NULL;
}


int main() {
    log_message("Honeypot starting...");
    
    init_blacklist();
    init_whitelist();
    
    start_honeypot();

   

    pthread_t http_tid, ssh_tid, telnet_tid;

    pthread_create(&http_tid, NULL, http_thread, NULL);
    pthread_create(&ssh_tid, NULL, ssh_thread, NULL);
    pthread_create(&telnet_tid, NULL, telnet_thread, NULL);

    pthread_join(http_tid, NULL);
    pthread_join(ssh_tid, NULL);
    pthread_join(telnet_tid, NULL);
    

    return 0;
}