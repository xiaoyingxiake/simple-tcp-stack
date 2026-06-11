#ifndef NET_H
#define NET_H

#include <stdint.h>
/* Ethernet */
  #define ETH_FRAME_MAX   1514
  #define ETH_TYPE_IP     0x0800
  #define ETH_TYPE_ARP    0x0806

 #define IP_VERSION_4    0x40
  #define IP_DEFAULT_TTL  64
  #define IP_PROTO_ICMP   1
  #define IP_PROTO_UDP    17

#define ARP_CACHE_TIMEOUT  60
  #define ARP_CACHE_MAX      16


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

struct udp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t check;
} __attribute__((packed));

#endif
