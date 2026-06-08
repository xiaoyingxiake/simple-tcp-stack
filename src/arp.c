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
static struct arp_entry arp_cache[16];
static int arp_cache_size = 0;

//删除老化
void arp_delete(int index){
    if(index<0||index>arp_cache_size-1){
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
        if (now - arp_cache[i].timestamp > 60) {
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
                if (time(NULL) - arp_cache[i].timestamp > 60) {
                    arp_delete(i);
                    return NULL;  // 过期了
                }
                return arp_cache[i].mac;
            }
    }
    return NULL;
}

void handle_arp(int fd, uint8_t *frame, int len) {
    struct eth_hdr *eth = (struct eth_hdr *)frame;
    struct arp_hdr *arp = (struct arp_hdr *)(frame + sizeof(struct eth_hdr));
    if (arp->opcode != htons(1))     return;
    if (arp->dst_ip != htonl(MY_IP)) return;
    log(LOG_INFO, "ARP Request -> 回复中");

    arp_insert(arp->src_ip, arp->src_mac);
    memcpy(eth->dst, eth->src, 6);
    memcpy(eth->src, MY_MAC, 6);
    arp->opcode = htons(2);
    memcpy(arp->dst_mac, arp->src_mac, 6);
    arp->dst_ip = arp->src_ip;
    memcpy(arp->src_mac, MY_MAC, 6);
    arp->src_ip = htonl(MY_IP);
    write(fd, frame, len);
    log(LOG_INFO, "ARP Reply 已发送");
}


