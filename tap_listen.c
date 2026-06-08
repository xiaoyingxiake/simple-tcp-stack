#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>

static uint8_t  MY_MAC[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
static uint32_t MY_IP     = 0x0a000002;

struct eth_hdr {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t ethertype;
} __attribute__((packed));

struct arp_hdr {
    uint16_t hw_type;
    uint16_t proto;
    uint8_t  hw_len;
    uint8_t  proto_len;
    uint16_t opcode;
    uint8_t  src_mac[6];
    uint32_t src_ip;
    uint8_t  dst_mac[6];
    uint32_t dst_ip;
} __attribute__((packed));

struct ip_hdr {
    uint8_t  ver_ihl;
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t check;
    uint32_t src_ip;
    uint32_t dst_ip;
} __attribute__((packed));

struct icmp_hdr {
    uint8_t  type;
    uint8_t  code;
    uint16_t check;
    uint16_t id;
    uint16_t seq;
} __attribute__((packed));

uint16_t checksum(void *data, int len) {
    uint16_t *ptr = data;
    uint32_t sum = 0;
    while (len > 1) { sum += *ptr++; len -= 2; }
    if (len == 1) sum += *(uint8_t *)ptr;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}

int tap_alloc(char *dev) {
    struct ifreq ifr;
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) { perror("open /dev/net/tun"); return -1; }
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        perror("ioctl"); close(fd); return -1;
    }
    return fd;
}

void handle_arp(int fd, uint8_t *frame, int len) {
    struct eth_hdr *eth = (struct eth_hdr *)frame;
    struct arp_hdr *arp = (struct arp_hdr *)(frame + sizeof(struct eth_hdr));
    if (arp->opcode != htons(1))     return;
    if (arp->dst_ip != htonl(MY_IP)) return;
    printf("ARP Request -> 回复中\n");
    memcpy(eth->dst, eth->src, 6);
    memcpy(eth->src, MY_MAC, 6);
    arp->opcode = htons(2);
    memcpy(arp->dst_mac, arp->src_mac, 6);
    arp->dst_ip = arp->src_ip;
    memcpy(arp->src_mac, MY_MAC, 6);
    arp->src_ip = htonl(MY_IP);
    write(fd, frame, len);
    printf("ARP Reply 已发送\n");
}

void handle_icmp(int fd, uint8_t *frame, int len) {
    struct eth_hdr  *eth  = (struct eth_hdr *)frame;
    struct ip_hdr   *ip   = (struct ip_hdr  *)(frame + sizeof(struct eth_hdr));
    int ip_hlen = (ip->ver_ihl & 0x0f) * 4;
    struct icmp_hdr *icmp = (struct icmp_hdr *)((uint8_t *)ip + ip_hlen);
    if (icmp->type != 8) return;
    printf("ICMP Echo Request -> 回复中\n");
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
    printf("ICMP Echo Reply 已发送\n");
}

void handle_ip(int fd, uint8_t *frame, int len) {
    struct ip_hdr *ip = (struct ip_hdr *)(frame + sizeof(struct eth_hdr));
    if (ip->protocol == 1) handle_icmp(fd, frame, len);
}

int main() {
    char dev[IFNAMSIZ] = "tap0";
    int fd = tap_alloc(dev);
    if (fd < 0) return 1;
    system("ip addr add 10.0.0.1/24 dev tap0");
    system("ip link set tap0 up");
    printf("tap0 up，我是 10.0.0.2，等待数据...\n\n");
    uint8_t buf[1514];
    while (1) {
        int nread = read(fd, buf, sizeof(buf));
        if (nread < 0) { perror("read"); break; }
        struct eth_hdr *eth = (struct eth_hdr *)buf;
        uint16_t et = ntohs(eth->ethertype);
        if      (et == 0x0806) handle_arp(fd, buf, nread);
        else if (et == 0x0800) handle_ip (fd, buf, nread);
    }
    return 0;
}
