#include <stdio.h>
#include <string.h>
#include <time.h>
#include<netinet/in.h>

#include "../include/suspicion_tracker.h"
#include "../include/blacklist.h"
#include "../include/logger.h"

#define MAX_SUSPICIOUS_ENTRIES 100
#define SUSPICIOUS_THRESHOLD 3
#define SUSPICIOUS_WINDOW_SEC 300  // 5 minut

typedef struct {
    char ip[INET_ADDRSTRLEN];
    int count;
    time_t first_attempt;
} SuspiciousEntry;

static SuspiciousEntry suspicious_entries[MAX_SUSPICIOUS_ENTRIES];
static int suspicious_count = 0;

void register_suspicious_attempt(const char *ip) {
    time_t now = time(NULL);

    // Szukamy istniejącego wpisu
    for (int i = 0; i < suspicious_count; ++i) {
        if (strcmp(suspicious_entries[i].ip, ip) == 0) {
            if (difftime(now, suspicious_entries[i].first_attempt) > SUSPICIOUS_WINDOW_SEC) {
                suspicious_entries[i].count = 1;
                suspicious_entries[i].first_attempt = now;
            } else {
                suspicious_entries[i].count++;
                if (suspicious_entries[i].count >= SUSPICIOUS_THRESHOLD) {
                    if (!is_blacklisted(ip)) {
                        add_to_blacklist(ip);
                        log_message("IP added to blacklist due to repeated suspicious activity");
                    }
                }
            }
            return;
        }
    }

    // Jeśli to nowe IP
    if (suspicious_count < MAX_SUSPICIOUS_ENTRIES) {
        strncpy(suspicious_entries[suspicious_count].ip, ip, sizeof(suspicious_entries[suspicious_count].ip));
        suspicious_entries[suspicious_count].count = 1;
        suspicious_entries[suspicious_count].first_attempt = now;
        suspicious_count++;
    } else {
        log_message("Suspicion tracker full — cannot register new IP");
    }
}
