#include "log.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "net.h"
#include "udp.h"
#include "utils.h"

int handle_udp(uint8_t *frame, int len) {
    struct eth_hdr *eth = (struct eth_hdr *)frame;
    struct ip_hdr  *ip  = (struct ip_hdr *)(frame + sizeof(struct eth_hdr));
    int ip_hlen = (ip->ver_ihl & 0x0f) * 4;
    struct udp_hdr *udp = (struct udp_hdr *)((uint8_t *)ip + ip_hlen);
    uint8_t *data    = (uint8_t *)udp + sizeof(struct udp_hdr);
    int      data_len = ntohs(udp->length) - sizeof(struct udp_hdr);
    log(LOG_INFO,"UDP 收到: 端口%d -> 端口%d, 数据: %.*s\n",
           ntohs(udp->src_port), ntohs(udp->dst_port),
           data_len, data);
    uint8_t tmp_mac[6];
    memcpy(tmp_mac,  eth->dst, 6);
    memcpy(eth->dst, eth->src, 6);
    memcpy(eth->src, tmp_mac,  6);
    uint32_t tmp_ip = ip->dst_ip;
    ip->dst_ip = ip->src_ip;
    ip->src_ip = tmp_ip;
    ip->check = 0;
    ip->check = checksum(ip, ip_hlen);
    uint16_t tmp_port = udp->dst_port;
    udp->dst_port = udp->src_port;
    udp->src_port = tmp_port;
    udp->check = 0;
    return len;
    }
