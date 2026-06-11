#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "net.h"
#include "icmp.h"
#include "utils.h"

void build_echo_request(uint8_t *frame, int *len) {
    struct eth_hdr *eth = (struct eth_hdr *)frame;
    struct ip_hdr  *ip  = (struct ip_hdr *)(frame + sizeof(struct eth_hdr));
    int ip_hlen = sizeof(struct ip_hdr);
    struct icmp_hdr *icmp = (struct icmp_hdr *)(frame + sizeof(struct eth_hdr) + ip_hlen);

    /* 以太网头 */
    memset(eth->dst, 0xff, 6);
    memset(eth->src, 0x01, 6);
    eth->ethertype = htons(ETH_TYPE_IP);

    /* IP 头 */
    ip->ver_ihl  = 0x45;
    ip->tos      = 0;
    ip->tot_len  = htons(ip_hlen + sizeof(struct icmp_hdr) + 4);
    ip->id       = htons(0x1234);
    ip->frag_off = 0;
    ip->ttl      = IP_DEFAULT_TTL;
    ip->protocol = IP_PROTO_ICMP;
    ip->src_ip   = inet_addr("10.0.0.1");  /* 假装对端 */
    ip->dst_ip   = inet_addr("10.0.0.2");  /* 假装我们的 IP */
    ip->check    = 0;
    ip->check    = checksum(ip, ip_hlen);

    /* ICMP Echo Request */
    icmp->type  = 8;      /* Echo Request */
    icmp->code  = 0;
    icmp->id    = htons(0x5678);
    icmp->seq   = htons(1);
    icmp->check = 0;
    memcpy((uint8_t *)icmp + sizeof(struct icmp_hdr), "test", 4);
    int icmp_len = sizeof(struct icmp_hdr) + 4;
    icmp->check = checksum(icmp, icmp_len);

    *len = sizeof(struct eth_hdr) + ip_hlen + icmp_len;
}

int main() {
    uint8_t frame[ETH_FRAME_MAX] = {0};
    int len = 0;

    build_echo_request(frame, &len);

    struct icmp_hdr *icmp =
        (struct icmp_hdr *)(frame + sizeof(struct eth_hdr) + sizeof(struct ip_hdr));

    printf("=== 发送前 ===\n");
    printf("ICMP type: %d (应为 8 = Echo Request)\n", icmp->type);

    int reply_len = handle_icmp(frame, len);

    printf("\n=== 返回后 ===\n");
    printf("reply_len: %d (应 > 0)\n", reply_len);
    printf("ICMP type: %d (应为 0 = Echo Reply)\n", icmp->type);
    printf("ICMP code: %d (应为 0)\n", icmp->code);

    int errors = 0;
    if (icmp->type != 0)  { printf("❌ type 值错误\n"); errors++; }
    if (reply_len != len) { printf("❌ 返回长度错误\n"); errors++; }
    if (reply_len <= 0)   { printf("❌ 没有回复\n"); errors++; }

    if (errors == 0)
        printf("\n✅ 全部通过！\n");
    else
        printf("\n❌ %d 项失败\n", errors);

    return errors;
}
