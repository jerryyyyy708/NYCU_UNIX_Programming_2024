# Makefile for Simple Debugger (sdb)

CC=gcc
CFLAGS=-g -Wall 
TARGET=sdb
TARGET2=sdb2
TARGET3=sdb3

$(TARGET): main.c
	$(CC) $(CFLAGS) main.c -o $(TARGET) -lcapstone 

$(TARGET2): main2.c
	$(CC) $(CFLAGS) main2.c -o $(TARGET2) -lcapstone 

$(TARGET3): main3.c
	$(CC) $(CFLAGS) main3.c -o $(TARGET3) -lcapstone 

all: $(TARGET) $(TARGET2) $(TARGET3)

clean:
	rm -f $(TARGET) $(TARGET2) $(TARGET3)

setup:
	sudo apt-get install libcapstone-dev

.PHONY: all clean
