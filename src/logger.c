#include<stdio.h>
#include<time.h>
#include "../include/logger.h"
#include "../include/config.h"

#define TIME_FORMAT "%Y-%m-%d %H:%M:%S"

void log_connection(const char *ip, int port, const char *protocol) {
    FILE *log_file = fopen("/home/abrzykcy/PS/Honeypot/logs/honeypot.log", "w");
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


