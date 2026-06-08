#include "log.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "net.h"
#include "icmp.h"
#include "utils.h"

void handle_icmp(int fd, uint8_t *frame, int len) {
    struct eth_hdr  *eth  = (struct eth_hdr *)frame;
    struct ip_hdr   *ip   = (struct ip_hdr *)(frame + sizeof(struct eth_hdr));
    int ip_hlen = (ip->ver_ihl & 0x0f) * 4;
    struct icmp_hdr *icmp = (struct icmp_hdr *)((uint8_t *)ip + ip_hlen);
    if (icmp->type != 8) return;
    log(LOG_INFO,"ICMP Echo Request -> 回复中\n");
    uint8_t tmp_mac[6];
    memcpy(tmp_mac,  eth->dst, 6);
    memcpy(eth->dst, eth->src, 6);
    memcpy(eth->src, tmp_mac,  6);
    uint32_t tmp_ip = ip->dst_ip;
    ip->dst_ip = ip->src_ip;
    ip->src_ip = tmp_ip;
    ip->check = 0;
    ip->check = checksum(ip, ip_hlen);
    icmp->type  = 0;
    icmp->check = 0;
    int icmp_len = ntohs(ip->tot_len) - ip_hlen;
    icmp->check = checksum(icmp, icmp_len);
    write(fd, frame, len);
    log(LOG_INFO,"ICMP Echo Reply 已发送\n");
}


/* 发送 ICMP Destination Unreachable */
void icmp_unreachable(int fd, uint8_t *frame) {
    struct eth_hdr *eth = (struct eth_hdr *)frame;
    struct ip_hdr  *ip  = (struct ip_hdr *)(frame + sizeof(struct eth_hdr));

    /* 构造回复帧，最大长度：以太网头+IP头+ICMP头+原IP头+8字节 */
    uint8_t reply[1514] = {0};
    struct eth_hdr  *reth  = (struct eth_hdr *)reply;
    struct ip_hdr   *rip   = (struct ip_hdr  *)(reply + sizeof(struct eth_hdr));
    struct icmp_hdr *ricmp = (struct icmp_hdr *)((uint8_t *)rip + sizeof(struct ip_hdr));

    /* 以太网头 */
    memcpy(reth->dst, eth->src, 6);
    memcpy(reth->src, eth->dst, 6);
    reth->ethertype = htons(0x0800);

    /* IP头 */
    rip->ver_ihl  = 0x45;
    rip->ttl      = 64;
    rip->protocol = 1;
    rip->src_ip   = ip->dst_ip;
    rip->dst_ip   = ip->src_ip;
    int icmp_len  = sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8;
    rip->tot_len  = htons(sizeof(struct ip_hdr) + icmp_len);
    rip->check    = 0;
    rip->check    = checksum(rip, sizeof(struct ip_hdr));

    /* ICMP头 */
    ricmp->type  = 3;   /* Destination Unreachable */
    ricmp->code  = 3;   /* Port Unreachable */
    ricmp->check = 0;
    /* 附上原始IP头+8字节 */
    memcpy((uint8_t *)ricmp + sizeof(struct icmp_hdr), ip,
           sizeof(struct ip_hdr) + 8);
    ricmp->check = checksum(ricmp, icmp_len);

    int reply_len = sizeof(struct eth_hdr) + sizeof(struct ip_hdr) + icmp_len;
    write(fd, reply, reply_len);
    log(LOG_INFO, "ICMP Destination Unreachable 已发送");
}