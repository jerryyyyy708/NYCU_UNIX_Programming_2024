# Makefile for Simple Debugger (sdb)

CC=gcc
CFLAGS=-g -Wall 
TARGET=sdb

# Default target
all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) main.c -o $(TARGET) -lcapstone 

clean:
	rm -f $(TARGET)

setup:
	sudo apt-get install libcapstone-dev

.PHONY: all clean
