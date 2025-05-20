#include"include/honeypot.h"
#include "include/whitelist.h"
int main(){
    init_whitelist();
    start_honeypot();
    return 0;
}
