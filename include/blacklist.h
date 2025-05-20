#ifndef BLACKLIST_H
#define BLACKLIST_H

#include <stdbool.h>

#define MAX_BLACKLIST_SIZE 100

void init_blacklist();
bool is_blacklisted(const char *ip);
void add_to_blacklist(const char *ip);
void print_blacklist(); // opcjonalne, do debugowania

#endif