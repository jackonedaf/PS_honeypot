#include <netinet/in.h>   // sockaddr_in, in_addr
#include <arpa/inet.h>    // inet_ntoa, inet_pton
#include <sys/socket.h>   // sockaddr, socket(), bind(), etc.
#include<stdio.h>
#include<unistd.h>       // close()
#include<string.h>

int start_honeypot(){
    int sockfd;
    struct sockaddr_in server_addr; 
    
    server_addr.sin_family =AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(8080);
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    } 

    bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    listen(sockfd, 5);
    printf("Honeypot started on port 8080\n");
    
    while(1){
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_sock = accept(sockfd, (struct sockaddr *)&client_addr, &addr_len);
        if (client_sock < 0) {
            perror("accept");
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        printf("Connection from %s:%d\n", client_ip, ntohs(client_addr.sin_port));

        
        
        close(client_sock);
    }


    return 0;
}