#ifndef ARP_H
#define ARP_H

#include <stdint.h>
#include "net.h"


int handle_arp(uint8_t *frame, int len);

#endif
