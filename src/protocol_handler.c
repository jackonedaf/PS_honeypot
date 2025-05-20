#include <stdio.h>
#include<unistd.h>
#include "../include/config.h"
#include "../include/protocol_handler.h"
#include "../include/logger.h"
#include<string.h>
#include <netinet/in.h>   // sockaddr_in, in_addr
#include <arpa/inet.h>    // inet_ntoa, inet_pton
#include <sys/socket.h>   // sockaddr, socket(), bind(), etc.
#include<ctype.h>

#include "../include/blacklist.h"
#include "../include/whitelist.h"
#include "../include/utils.h"
#include "../include/suspicion_tracker.h"

int is_suspicious_http_request(const char *request) {
    if (!request) return 0;

    // Przykładowe proste reguły:
    // - próba metod nie będących standardowymi (np. DELETE, PUT, TRACE)
    // - zapytania zawierające SQL Injection pattern
    // - zapytania bardzo krótkie lub zupełnie losowe
    
    // Sprawdź metodę (pierwsze słowo)
    char method[8] = {0};
    int i = 0;
    while (request[i] && !isspace(request[i]) && i < (int)(sizeof(method)-1)) {
        method[i] = request[i];
        i++;
    }
    method[i] = '\0';

    // Lista akceptowalnych metod
    const char *allowed_methods[] = {"GET", "POST", "HEAD", "OPTIONS"};
    int allowed = 0;
    for (int j = 0; j < 4; j++) {
        if (strcmp(method, allowed_methods[j]) == 0) {
            allowed = 1;
            break;
        }
    }
    if (!allowed) {
        log_message("Suspicious HTTP method detected");
        return 1;
    }

    // Proste wykrycie wzorca SQL Injection (bardzo uproszczone)
    if (strstr(request, " OR ") || strstr(request, "' OR ") || strstr(request, "--") || strstr(request, "';")) {
        log_message("Suspicious SQL injection pattern detected");
        return 1;
    }

    // Sprawdź długość zapytania
    if (strlen(request) < 10) {
        log_message("Suspiciously short HTTP request");
        return 1;
    }

    return 0; // nie jest podejrzane
}

void handle_http_request(int client_sock, const struct sockaddr_in *client_addr) {
    char buffer[BUFFER_SIZE];
    int bytes_received = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received < 0) {
        perror("recv");
        return;
    }
    log_connection_details(client_addr, "HTTP", buffer);
    buffer[bytes_received] = '\0'; // Null-terminate the received data
    log_message("Received HTTP request");

    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr->sin_addr, client_ip, sizeof(client_ip));

    if (is_blacklisted(client_ip)) {
        log_message("Blocked request from blacklisted IP");
        const char *HTTP_FORBIDDEN = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n\r\n<h1>403 Forbidden</h1>";
        send(client_sock, HTTP_FORBIDDEN, strlen(HTTP_FORBIDDEN), 0);
        close(client_sock);
        return;
    }
    if(is_suspicious_http_request(buffer)){
        log_message("Suspicious HTTP request detected");
        register_suspicious_attempt(client_ip);
    }

    
    const char *HTTP_BANNER = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>Welcome to the Honeypot</h1>";
    send(client_sock, HTTP_BANNER, strlen(HTTP_BANNER), 0);
    
    close(client_sock);
}
void handle_ssh_request(int client_sock) {
    char buffer[BUFFER_SIZE];
    int bytes_received = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received < 0) {
        perror("recv");
        return;
    }
    
    buffer[bytes_received] = '\0'; // Null-terminate the received data
    log_message("Received SSH request");
    
    // Here you would parse the SSH request and send a response
    // For example:
    // send(client_sock, SSH_RESPONSE, strlen(SSH_RESPONSE), 0);
    
    close(client_sock);
}

void handle_telnet_request(int client_sock) {
    char buffer[BUFFER_SIZE];
    int bytes_received = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received < 0) {
        perror("recv");
        return;
    }
    
    buffer[bytes_received] = '\0'; // Null-terminate the received data
    log_message("Received Telnet request");
    
    // Here you would parse the Telnet request and send a response
    // For example:
    // send(client_sock, TELNET_RESPONSE, strlen(TELNET_RESPONSE), 0);
    
    close(client_sock);
}