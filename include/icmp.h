#ifndef ICMP_H
#define ICMP_H

#include <stdint.h>

void handle_icmp(int fd, uint8_t *frame, int len);

void icmp_unreachable(int fd, uint8_t *frame);

#endif
