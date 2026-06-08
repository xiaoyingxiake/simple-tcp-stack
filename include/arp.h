#ifndef ARP_H
#define ARP_H

#include <stdint.h>

void handle_arp(int fd, uint8_t *frame, int len);

#endif
