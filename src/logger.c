#include<stdio.h>
#include<time.h>
#include "../include/logger.h"
#include "../include/config.h"
#include "../include/utils.h"

void log_connection_details(const struct sockaddr_in *addr, const char *protocol, const char *payload) {
    char timestamp[64];
    char ip_str[INET_ADDRSTRLEN];

    get_timestamp(timestamp, sizeof(timestamp));
    get_ip_str(addr, ip_str, sizeof(ip_str));

    // Oczyść payload z \n i \r
    char clean_payload[201];  // max 200 + null terminator
    int j = 0;
    if (payload) {
        for (int i = 0; payload[i] && j < 200; ++i) {
            if (payload[i] != '\n' && payload[i] != '\r') {
                clean_payload[j++] = payload[i];
            } else {
                clean_payload[j++] = ' ';  // lub pomiń całkiem (nie dodawaj nic)
            }
        }
    }
    clean_payload[j] = '\0';

    char log_msg[1024];
    snprintf(log_msg, sizeof(log_msg),
            "%s connection from %s:%d | Payload: %.200s",
            protocol,
            ip_str,
            ntohs(addr->sin_port),
            payload ? payload : "<no data>");

    log_message(log_msg);
}

void log_connection(const char *ip, int port, const char *protocol) {
    FILE *log_file = fopen(LOG_FILE, "a");
    if (log_file == NULL) {
        perror("Failed to open log file");
        return;
    }
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_buffer[26];
    strftime(time_buffer, sizeof(time_buffer), TIME_FORMAT, tm_info);
    fprintf(log_file, "[%s] Connection from %s:%d using %s\n",time_buffer, ip, port, protocol);
    printf("[%s] Connection from %s:%d using %s\n", time_buffer, ip, port, protocol);
    fclose(log_file);
}

void log_message(const char *message) {
    FILE *log_file = fopen(LOG_FILE, "a");
    if (log_file == NULL) {
        perror("Failed to open log file");
        return;
    }
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now); 
    char time_buffer[26];
    strftime(time_buffer, sizeof(time_buffer), TIME_FORMAT, tm_info);
    fprintf(log_file, "[%s] %s\n", time_buffer, message);
    fclose(log_file);
}

void log_error(const char *message) {
    FILE *log_file = fopen(LOG_FILE, "a");
    if (log_file == NULL) {
        perror("Failed to open log file");
        return;
    }

    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_buffer[26];
    strftime(time_buffer, sizeof(time_buffer), TIME_FORMAT, tm_info);

    fprintf(log_file, "[%s] ERROR: %s\n", time_buffer, message);

    fclose(log_file);
}

void init_logger() {
    FILE *log_file = fopen(LOG_FILE, "a");
    if (log_file == NULL) {
        perror("Failed to open log file");
        return;
    }
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_buffer[26];
    strftime(time_buffer, sizeof(time_buffer), TIME_FORMAT, tm_info);

    fprintf(log_file, "[%s] Logger initialized\n", time_buffer);
    fclose(log_file);
}



