#include <stdio.h>
#include <unistd.h>
#include "../include/config.h"
#include "../include/protocol_handler.h"
#include "../include/logger.h"
#include <string.h>
#include <netinet/in.h> // sockaddr_in, in_addr
#include <arpa/inet.h>  // inet_ntoa, inet_pton
#include <sys/socket.h> // sockaddr, socket(), bind(), etc.
#include <ctype.h>

#include "../include/blacklist.h"
#include "../include/whitelist.h"
#include "../include/utils.h"
#include "../include/suspicion_tracker.h"
#include "../include/http_responses.h"

int is_suspicious_http_request(const char *request)
{
    if (!request)
        return 0;

    // Przykładowe proste reguły:
    // - próba metod nie będących standardowymi (np. DELETE, PUT, TRACE)
    // - zapytania zawierające SQL Injection pattern
    // - zapytania bardzo krótkie lub zupełnie losowe

    // Sprawdź metodę (pierwsze słowo)
    char method[8] = {0};
    int i = 0;
    while (request[i] && !isspace(request[i]) && i < (int)(sizeof(method) - 1))
    {
        method[i] = request[i];
        i++;
    }
    method[i] = '\0';

    // Lista akceptowalnych metod
    const char *allowed_methods[] = {"GET", "POST", "HEAD", "OPTIONS"};
    int allowed = 0;
    for (int j = 0; j < 4; j++)
    {
        if (strcmp(method, allowed_methods[j]) == 0)
        {
            allowed = 1;
            break;
        }
    }
    if (!allowed)
    {
        log_message("Suspicious HTTP method detected");
        return 1;
    }

    // Proste wykrycie wzorca SQL Injection (bardzo uproszczone)
    if (strstr(request, " OR ") || strstr(request, "' OR ") || strstr(request, "--") || strstr(request, "';"))
    {
        log_message("Suspicious SQL injection pattern detected");
        return 1;
    }

    // Sprawdź długość zapytania
    if (strlen(request) < 10)
    {
        log_message("Suspiciously short HTTP request");
        return 1;
    }

    if (strstr(request, "sqlmap") || strstr(request, "Nikto") || strstr(request, "curl") || strstr(request, "wget") || strstr(request, "nmap"))
    {
        log_message("Suspicious User-Agent detected");
        return 1;
    }

    return 0; // nie jest podejrzane
}

int is_suspicious_ssh_request(const char *request)
{
    if (!request)
        return 0;

    struct
    {
        const char *pattern;
        const char *description;
    } suspicious_patterns[] = {
        {"root", "root"},
        {"admin", "admin"},
        {"password", "password"},
        {"ssh2", "ssh2"},
        {"OpenSSH_", "OpenSSH_"},
        {"exploit", "exploit"},
        {"masscan", "masscan"},
        {"nmap", "nmap"},
        {"hydra", "hydra"},
    };

    for (int i = 0; i < sizeof(suspicious_patterns) / sizeof(suspicious_patterns[0]); ++i)
    {
        if (strstr(request, suspicious_patterns[i].pattern))
        {
            char logbuf[256];
            snprintf(logbuf, sizeof(logbuf), "Suspicious SSH string detected: %s", suspicious_patterns[i].description);
            log_message(logbuf);
            return 1;
        }
    }

    if (strlen(request) < 5)
    {
        log_message("Suspiciously short SSH data detected");
        return 1;
    }

    return 0;
}

int is_suspicious_telnet_request(const char *request)
{
    if (!request)
        return 0;

    struct
    {
        const char *pattern;
        const char *description;
    } suspicious_patterns[] = {
        {"root", "root"},
        {"admin", "admin"},
        {"1234", "1234"},
        {"telnet", "telnet"},
        {"shell", "shell"},
        {"sh", "sh"},
        {"wget", "wget"},
        {"tftp", "tftp"},
        {"busybox", "busybox"},
        {"bin/busybox", "bin/busybox"},
        {"password", "password"},
        {"login", "login"},
    };

    for (int i = 0; i < sizeof(suspicious_patterns) / sizeof(suspicious_patterns[0]); ++i)
    {
        if (strstr(request, suspicious_patterns[i].pattern))
        {
            char logbuf[256];
            snprintf(logbuf, sizeof(logbuf), "Suspicious Telnet content detected: %s", suspicious_patterns[i].description);
            log_message(logbuf);
            return 1;
        }
    }

    if (strlen(request) < 5)
    {
        log_message("Suspiciously short Telnet input detected");
        return 1;
    }

    return 0;
}

void handle_http_request(int client_sock, const struct sockaddr_in *client_addr)
{
    char buffer[BUFFER_SIZE];
    int bytes_received = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received < 0)
    {
        perror("recv");
        return;
    }
    log_connection_details(client_addr, "HTTP", buffer);
    buffer[bytes_received] = '\0'; // Null-terminate the received data

    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr->sin_addr, client_ip, sizeof(client_ip));

    if (is_blacklisted(client_ip))
    {
        log_message("Blocked request from blacklisted IP");
        const char *HTTP_FORBIDDEN = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n\r\n<h1>403 Forbidden</h1>";
        send(client_sock, HTTP_FORBIDDEN, strlen(HTTP_FORBIDDEN), 0);
        close(client_sock);
        return;
    }
    if (is_suspicious_http_request(buffer))
    {
        log_message("Received HTTP request");
        log_message("Suspicious HTTP \r\n");
        register_suspicious_attempt(client_ip);
    }
    else
    {
        log_message("Received HTTP request\r\n");
    }

    if (strstr(buffer, "GET /robots.txt"))
    {
        send(client_sock, HTTP_ROBOTS, strlen(HTTP_ROBOTS), 0);
        log_message("Served fake robots.txt");
    }
    else if (strstr(buffer, "GET /favicon.ico"))
    {
        send(client_sock, HTTP_NOT_FOUND, strlen(HTTP_NOT_FOUND), 0);
        log_message("Favicon requested");
    }
    else
    {
        const char *HTTP_BANNER = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>Welcome to the Honeypot</h1>";
        send(client_sock, HTTP_BANNER, strlen(HTTP_BANNER), 0);
    }

    close(client_sock);
}
void handle_ssh_request(int client_sock)
{
    char buffer[BUFFER_SIZE];
    int bytes_received = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received < 0)
    {
        perror("recv");
        return;
    }

    buffer[bytes_received] = '\0'; // Null-terminate

    // Pobierz IP klienta
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    getpeername(client_sock, (struct sockaddr *)&client_addr, &addr_len);
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));

    if (is_blacklisted(client_ip))
    {
        log_message("Blocked SSH request from blacklisted IP");
        close(client_sock);
        return;
    }

    log_connection_details(&client_addr, "SSH", buffer);

    if (is_suspicious_ssh_request(buffer))
    {
        log_message("Received SSH request");
        log_message("Suspicious SSH request detected\r\n");
        register_suspicious_attempt(client_ip);
    }
    else
    {
        log_message("Received SSH request\r\n");
    }

    // Możesz odpowiedzieć "fałszywym" bannerem
    const char *fake_banner = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n";
    send(client_sock, fake_banner, strlen(fake_banner), 0);

    close(client_sock);
}

void handle_telnet_request(int client_sock)
{
    char buffer[BUFFER_SIZE];
    int bytes_received = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received < 0)
    {
        perror("recv");
        return;
    }

    buffer[bytes_received] = '\0';

    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    getpeername(client_sock, (struct sockaddr *)&client_addr, &addr_len);
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));

    if (is_blacklisted(client_ip))
    {
        log_message("Blocked Telnet request from blacklisted IP");
        close(client_sock);
        return;
    }

    log_connection_details(&client_addr, "Telnet", buffer);

    if (is_suspicious_telnet_request(buffer))
    {
        log_message("Received Telnet request");
        log_message("Suspicious Telnet request detected\r\n");
        register_suspicious_attempt(client_ip);
    }
    else
    {
        log_message("Received Telnet request\r\n");
    }
    // Fałszywy login prompt
    const char *login_prompt = "login: ";
    send(client_sock, login_prompt, strlen(login_prompt), 0);

    // Opcjonalnie odczyt hasła
    int pass_bytes = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
    if (pass_bytes > 0)
    {
        buffer[pass_bytes] = '\0';
        log_message("Telnet password attempt logged");
        log_connection_details(&client_addr, "Telnet-Password", buffer);
    }

    // const char *denied = "\nLogin incorrect\n";
    // send(client_sock, denied, strlen(denied), 0);

    close(client_sock);
}
