#include <netinet/in.h>
#include "../include/whitelist.h"
#include<string.h>
#include<stdio.h>
#include "../include/logger.h"

WhiteListEntry whitelist[MAX_WHITELIST];
int whitelist_count = 0;

int add_to_whitelist(const char *ip_addr, int access_level) {
    // This function adds an IP address to the whitelist with the specified access level.
    // For simplicity, we will just print the action.
    if(whitelist_count >=MAX_WHITELIST){
        return -1;
    }
    strncpy(whitelist[whitelist_count].ip, ip_addr, INET_ADDRSTRLEN);
    whitelist[whitelist_count].access_level = access_level;
    whitelist_count++;
    
    return 0; // Return 0 on success
}
int is_whitelisted(const char *ip_addr) {
    // This function checks if an IP address is in the whitelist.
    // For simplicity, we will just print the action and return 1 (true).
    for(int i=0;i<whitelist_count;i++){
        log_message(ip_addr);
        if (strcmp(whitelist[i].ip, ip_addr) == 0){
            return 1; // Return 1 (true) if found
        }
    }
    return 0;
}
void init_whitelist(){
    add_to_whitelist("127.0.0.1",1);
    add_to_whitelist("192.168.196.112",1);
}