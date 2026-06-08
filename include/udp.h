#ifndef UDP_H
#define UDP_H

#include <stdint.h>

void handle_udp(int fd, uint8_t *frame, int len);

#endif
