#ifndef ICMP_H
#define ICMP_H

#include <stdint.h>

int handle_icmp( uint8_t *frame, int len);

int icmp_unreachable(uint8_t *frame);

#endif
