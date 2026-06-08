#include "net.h"
#include "ip.h"
#include "icmp.h"
#include "udp.h"
#include <stdio.h>

void handle_ip(int fd, uint8_t *frame, int len) {
    struct ip_hdr *ip = (struct ip_hdr *)(frame + sizeof(struct eth_hdr));
    switch(ip->protocol){
        case 1:
        handle_icmp(fd,frame,len);
        break;
        case 17:
        handle_udp(fd,frame,len);
        break;
        default:
        printf("unsupported protocol\n");
        break;
        
    }
    if (ip->protocol == 1)  handle_icmp(fd, frame, len);
    if (ip->protocol == 17) handle_udp(fd, frame, len);
}
