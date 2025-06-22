#include <stdio.h>
#include <stdlib.h>
#include "include/logger.h"
#include "include/blacklist.h"
#include "include/whitelist.h"
#include "include/threaded_honeypot.h"
#include "include/legacy_honeypot.h"
#include "include/suspicion_tracker.h"
#include "include/protocol_handler.h"
#include "include/config.h"
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>




int main(int argc, char *argv[]) {
    clearFileByPath(LOG_FILE);
    
    log_message("Honeypot starting...");
    
    init_blacklist();
    init_whitelist();

    if (argc > 1 && strcmp(argv[1], "--mode=legacy") == 0) {
        log_message("Running in LEGACY mode");
        start_honeypot();
    } else {
        log_message("Running in MULTITHREADED mode");
        start_multithreaded_honeypot();
    }
    

    return 0;
}