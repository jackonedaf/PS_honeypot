#include <string.h>
#include <stdio.h>
#include "../include/blacklist.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

static char blacklist[MAX_BLACKLIST_SIZE][INET_ADDRSTRLEN];
int blacklist_count;

void init_blacklist()
{
    blacklist_count = 0;
}

bool is_blacklisted(const char *ip)
{
    for (int i = 0; i < blacklist_count; ++i)
    {
        if (strcmp(blacklist[i], ip) == 0)
        {
            return true;
        }
    }
    return false;
}

void add_to_blacklist(const char *ip)
{
    if (blacklist_count >= MAX_BLACKLIST_SIZE)
    {
        fprintf(stderr, "Blacklist is full, cannot add %s\n", ip);
        return;
    }
    if (!is_blacklisted(ip))
    {
        strncpy(blacklist[blacklist_count], ip, INET_ADDRSTRLEN);
        blacklist_count++;
    }
}

void print_blacklist()
{
    printf("Blacklisted IPs:\n");
    for (int i = 0; i < blacklist_count; ++i)
    {
        printf(" - %s\n", blacklist[i]);
    }
}
