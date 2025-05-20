#ifndef LOGGER_H
#define LOGGER_H

void log_connection(const char* ip, int port, const char* proto);
void log_message(const char* message); // ogólne logi, np. start/stop

#endif
