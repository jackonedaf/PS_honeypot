#ifndef CONFIG_H
#define CONFIG_H

#define PORT_HTTP 8080
#define PORT_SSH 2222
#define PORT_TELNET 2323

#define BUFFER_SIZE 1024

#define BANNER_HTTP "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
#define BANNER_SSH "SSH-2.0-OpenSSH_8.2p1 Ubuntu\r\n"

#define LOG_FILE "" //scieżka do pliku logów

#endif
