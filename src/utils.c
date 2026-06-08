#include "utils.h"

uint16_t checksum(void *data, int len) {
    uint16_t *ptr = data;
    uint32_t sum = 0;
    while (len > 1) { sum += *ptr++; len -= 2; }
    if (len == 1) sum += *(uint8_t *)ptr;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}
