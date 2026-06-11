#include "net.h"
#include "ip.h"
#include "icmp.h"
#include "udp.h"
#include <stdio.h>

int handle_ip(uint8_t *frame, int len) {
    struct ip_hdr *ip = (struct ip_hdr *)(frame + sizeof(struct eth_hdr));
    switch (ip->protocol) {
        case IP_PROTO_ICMP:
            return handle_icmp(frame, len);
        case IP_PROTO_UDP: {
            int ret = handle_udp(frame, len);
            if (ret == 0)
                return icmp_unreachable(frame);
            return ret;
        }
        default:
            printf("unsupported protocol\n");
            return 0;
    }
}
