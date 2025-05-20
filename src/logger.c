#include<stdio.h>
#include "../include/logger.h"
#include "../include/config.h"

void log_connection(const char *ip, int port, const char *protocol) {
    FILE *log_file = fopen("/logs/honeypot.log", "w");
    if (log_file == NULL) {
        perror("Failed to open log file");
        return;
    }

    fprintf(log_file, "Connection from %s:%d using %s\n", ip, port, protocol);
    fclose(log_file);
}

void log_message(const char *message) {
    FILE *log_file = fopen(LOG_FILE, "a");
    if (log_file == NULL) {
        perror("Failed to open log file");
        return;
    }

    fprintf(log_file, "%s\n", message);
    fclose(log_file);
}

void log_error(const char *message) {
    FILE *log_file = fopen(LOG_FILE, "a");
    if (log_file == NULL) {
        perror("Failed to open log file");
        return;
    }

    fprintf(log_file, "ERROR: %s\n", message);
    fclose(log_file);
}

void init_logger() {
    FILE *log_file = fopen(LOG_FILE, "a");
    if (log_file == NULL) {
        perror("Failed to open log file");
        return;
    }

    fprintf(log_file, "Logger initialized\n");
    fclose(log_file);
}


