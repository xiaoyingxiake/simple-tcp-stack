#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "tap.h"
#include "net.h"
#include "arp.h"
#include "ip.h"


int main() {
    char dev[16] = "tap0";
    int fd = tap_alloc(dev);
    if (fd < 0) return 1;
    system("ip addr add 10.0.0.1/24 dev tap0");
    system("ip link set tap0 up");
    printf("tap0 up，我是 10.0.0.2，等待数据...\n\n");
    uint8_t buf[ETH_FRAME_MAX];
    while (1) {
        int nread = read(fd, buf, sizeof(buf));
        if (nread < 0) { perror("read"); break; }
        int ret = 0;
        struct eth_hdr *eth = (struct eth_hdr *)buf;
        uint16_t et = ntohs(eth->ethertype);
        if      (et == ETH_TYPE_ARP) ret = handle_arp(buf, nread);
        else if (et == ETH_TYPE_IP)  ret = handle_ip(buf, nread);

        if (ret > 0) write(fd, buf, ret);
    }
    return 0;
}
