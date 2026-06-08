CC      = gcc
CFLAGS  = -Wall -g -Iinclude
TARGET  = netstack

SRCS    = src/main.c \
          src/tap.c  \
          src/arp.c  \
          src/icmp.c \
          src/udp.c  \
          src/ip.c   \
          src/utils.c

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS)

clean:
	rm -f $(TARGET)
