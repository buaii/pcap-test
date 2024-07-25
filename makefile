CC = gcc

LDLIBS += -lpcap

TARGET = pcap-test

SRCS = pcap-test.c

HEADERS = pcap-test.h

OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDLIBS)

%.o: %.c $(HEADERS)
	$(CC) -c $<

clean:
	rm -f $(OBJS) $(TARGET)
