#include "../include/http_responses.h"

const char *HTTP_OK = "HTTP/1.1 200 OK\r\n"
                      "Content-Type: text/html\r\n"
                      "Connection: close\r\n"
                      "\r\n"
                      "<html><body><h1>Welcome to the Honeypot</h1></body></html>";
const char *HTTP_FORBIDDEN = "HTTP/1.1 403 Forbidden\r\n"
                             "Content-Type: text/html\r\n"
                             "Connection: close\r\n"
                             "\r\n"
                             "<html><body><h1>403 Forbidden</h1></body></html>";
const char *HTTP_NOT_FOUND = "HTTP/1.1 404 Not Found\r\n"
                             "Content-Type: text/html\r\n"
                             "Connection: close\r\n"
                             "\r\n"
                             "<html><body><h1>404 Not Found</h1></body></html>";
const char *HTTP_SERVER_ERROR = "HTTP/1.1 500 Internal Server Error\r\n"
                                "Content-Type: text/html\r\n"
                                "Connection: close\r\n"
                                "\r\n"
                                "<html><body><h1>500 Internal Server Error</h1></body></html>";
const char *HTTP_ROBOTS = "User-agent: *\r\n"
                          "Disallow: /\r\n"
                          "Disallow: /admin/\r\n"
                          "Disallow: /login/\r\n"
                          "Disallow: /register/\r\n"
                          "Disallow: /api/\r\n"
                          "Disallow: /private/\r\n"
                          "Disallow: /tmp/\r\n"
                          "Disallow: /uploads/\r\n"
                          "Disallow: /cgi-bin/\r\n"
                          "Disallow: /scripts/\r\n";
