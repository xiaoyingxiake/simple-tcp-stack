#include "log.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "net.h"
#include "icmp.h"
#include "utils.h"

int handle_icmp(uint8_t *frame, int len) {
    struct eth_hdr  *eth  = (struct eth_hdr *)frame;
    struct ip_hdr   *ip   = (struct ip_hdr *)(frame + sizeof(struct eth_hdr));
    int ip_hlen = (ip->ver_ihl & 0x0f) * 4;
    struct icmp_hdr *icmp = (struct icmp_hdr *)((uint8_t *)ip + ip_hlen);
    if (icmp->type != 8) return 0;
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
    return len;
}


/* 构造 ICMP Destination Unreachable，直接在 frame 上原地写入 */
int icmp_unreachable(uint8_t *frame) {
    struct eth_hdr *eth = (struct eth_hdr *)frame;
    struct ip_hdr  *ip  = (struct ip_hdr *)(frame + sizeof(struct eth_hdr));

    /* 先保存原始发送方信息，覆盖之前需要用到 */
    uint8_t  src_mac[6];  memcpy(src_mac, eth->src, 6);
    uint8_t  dst_mac[6];  memcpy(dst_mac, eth->dst, 6);
    uint32_t dst_ip = ip->src_ip;
    uint32_t src_ip = ip->dst_ip;
    uint8_t  orig[sizeof(struct ip_hdr) + 8];
    memcpy(orig, ip, sizeof(orig));

    /* 直接在 frame 上构造回复 */
    struct eth_hdr  *reth  = (struct eth_hdr *)frame;
    struct ip_hdr   *rip   = (struct ip_hdr  *)(frame + sizeof(struct eth_hdr));
    struct icmp_hdr *ricmp = (struct icmp_hdr *)((uint8_t *)rip + sizeof(struct ip_hdr));

    /* 以太网头 */
    memcpy(reth->dst, src_mac, 6);
    memcpy(reth->src, dst_mac, 6);
    reth->ethertype = htons(ETH_TYPE_IP);

    /* IP头 */
    rip->ver_ihl  = 0x45;
    rip->ttl      = 64;
    rip->protocol = 1;
    rip->src_ip   = src_ip;
    rip->dst_ip   = dst_ip;
    int icmp_len  = sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8;
    rip->tot_len  = htons(sizeof(struct ip_hdr) + icmp_len);
    rip->check    = 0;
    rip->check    = checksum(rip, sizeof(struct ip_hdr));

    /* ICMP头 */
    ricmp->type  = 3;   /* Destination Unreachable */
    ricmp->code  = 3;   /* Port Unreachable */
    ricmp->check = 0;
    memcpy((uint8_t *)ricmp + sizeof(struct icmp_hdr), orig, sizeof(orig));
    ricmp->check = checksum(ricmp, icmp_len);

    int reply_len = sizeof(struct eth_hdr) + sizeof(struct ip_hdr) + icmp_len;
    return reply_len;
}
