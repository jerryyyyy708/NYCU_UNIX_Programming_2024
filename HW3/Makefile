# Makefile for Simple Debugger (sdb)

CC=gcc
CFLAGS=-g -Wall 
TARGET=sdb

$(TARGET): main.c
	$(CC) $(CFLAGS) main.c -o $(TARGET) -lcapstone 

all: $(TARGET)

clean:
	rm -f $(TARGET) test/*.out test/diff.txt

setup:
	sudo apt-get install libcapstone-dev

.PHONY: all clean
