#ifndef SUSPICION_TRACKER_H
#define SUSPICION_TRACKER_H

#define MAX_SUSPICIOUS_ENTRIES 100
#define SUSPICIOUS_THRESHOLD 1000
#define SUSPICIOUS_WINDOW_SEC 300 

void register_suspicious_attempt(const char *ip);

#endif
