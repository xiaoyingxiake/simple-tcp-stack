#include "log.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include "net.h"
#include "arp.h"

static uint8_t  MY_MAC[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
static uint32_t MY_IP     = 0x0a000002;

/* ARP 缓存表 */
struct arp_entry {
    uint32_t ip;
    uint8_t  mac[6];
    time_t timestamp;
};
static struct arp_entry arp_cache[ARP_CACHE_MAX];
static int arp_cache_size = 0;

//删除老化
void arp_delete(int index){
    if(index<0||index>=arp_cache_size){
        return;
    }
    if(index<arp_cache_size-1){
        arp_cache[index]=arp_cache[arp_cache_size-1];
        }
        arp_cache_size--;
}

void arp_cleanup() {
    time_t now = time(NULL);
    for (int i = 0; i < arp_cache_size; i++) {
        if (now - arp_cache[i].timestamp > ARP_CACHE_TIMEOUT) {
            log(LOG_INFO, "ARP 缓存过期，删除 IP: %d.%d.%d.%d",
                (ntohl(arp_cache[i].ip) >> 24) & 0xff,
                (ntohl(arp_cache[i].ip) >> 16) & 0xff,
                (ntohl(arp_cache[i].ip) >>  8) & 0xff,
                (ntohl(arp_cache[i].ip)       ) & 0xff);
            arp_delete(i);
            i--;  /* 删除后退一步，防止跳过下一条 */
        }
    }
}



/* 插入或更新缓存 */
void arp_insert(uint32_t ip, uint8_t *mac) {
    arp_cleanup();
    for (int i = 0; i < arp_cache_size; i++) {
        if (arp_cache[i].ip == ip) {
            memcpy(arp_cache[i].mac, mac, 6);
            arp_cache[i].timestamp = time(NULL);
            return;
        }
    }
    if (arp_cache_size >= ARP_CACHE_MAX) {
    int oldest=0;
    for(int i=1;i<arp_cache_size;i++){
    if(arp_cache[i].timestamp<arp_cache[oldest].timestamp){
    oldest=i;
    }
    }
         arp_delete(oldest); // 删第一个，因为 cleanup 后剩下的都是有效的
  }

    arp_cache[arp_cache_size].ip = ip;
    memcpy(arp_cache[arp_cache_size].mac, mac, 6);
    arp_cache[arp_cache_size].timestamp = time(NULL);
    arp_cache_size++;
}

/* 查找缓存 */
uint8_t *arp_lookup(uint32_t ip) {
    arp_cleanup();
    for (int i = 0; i < arp_cache_size; i++) {
       if (arp_cache[i].ip == ip) {
                return arp_cache[i].mac;
            }
    }
    return NULL;
}

int handle_arp(uint8_t *frame, int len) {
    struct eth_hdr *eth = (struct eth_hdr *)frame;
    struct arp_hdr *arp = (struct arp_hdr *)(frame + sizeof(struct eth_hdr));
    if (arp->opcode != htons(1))     return 0;
    if (arp->dst_ip != htonl(MY_IP)) return 0;
    log(LOG_INFO, "ARP Request -> 回复中");

    arp_insert(arp->src_ip, arp->src_mac);
    memcpy(eth->dst, eth->src, 6);
    memcpy(eth->src, MY_MAC, 6);
    arp->opcode = htons(2);
    memcpy(arp->dst_mac, arp->src_mac, 6);
    arp->dst_ip = arp->src_ip;
    memcpy(arp->src_mac, MY_MAC, 6);
    arp->src_ip = htonl(MY_IP);
    return len;
}


