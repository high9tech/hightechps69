CC=gcc
CFLAGS=-g -Wall
LDFLAGS=

SRCS=main.c common.c device.c keys.c crypto.c
OBJS=$(SRCS:.c=.o)
TARGET=sc_access

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $^

clean:
	rm -f $(TARGET) $(OBJS)
