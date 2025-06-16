#ifndef LOGGER_H
#define LOGGER_H

#include <netinet/in.h>

#define TIME_FORMAT "%Y-%m-%d %H:%M:%S"

void log_connection_details(const struct sockaddr_in *client_addr, const char *protocol, const char *request);
void log_connection(const char* ip, int port, const char* proto);
void log_message(const char* message); // ogólne logi, np. start/stop
void log_error(const char* message); // logi błędów
void init_logger(); // inicjalizacja loggera, np. otwarcie pliku logu


#endif
