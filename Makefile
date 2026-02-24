CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -O2
TARGET = monitor.exe
OBJS = monitor.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

monitor.o: monitor.c
	$(CC) $(CFLAGS) -c monitor.c

clean:
	rm -f $(TARGET) $(OBJS)

.PHONY: all clean