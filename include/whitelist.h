#ifndef WHITELIST_H
#define WHITELIST_H
#include <netinet/in.h>

#define MAX_WHITELIST 10

typedef struct{
    char ip[INET_ADDRSTRLEN];
    int access_level;
}WhiteListEntry;

extern WhiteListEntry whitelist[MAX_WHITELIST];

int add_to_whitelist(const char *ip_addr, int access_level);

int is_whitelisted(const char *ip_addr);

void init_whitelist();

#endif