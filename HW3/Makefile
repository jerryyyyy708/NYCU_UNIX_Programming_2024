# Makefile for Simple Debugger (sdb)

CC=gcc
CFLAGS=-g -Wall 
TARGET=sdb
TARGET2=sdb2
TARGET3=sdb3
TARGET4=sdb4
TARGET5=sdb5

$(TARGET): main.c
	$(CC) $(CFLAGS) main.c -o $(TARGET) -lcapstone 

$(TARGET2): main2.c
	$(CC) $(CFLAGS) main2.c -o $(TARGET2) -lcapstone 

$(TARGET3): main3.c
	$(CC) $(CFLAGS) main3.c -o $(TARGET3) -lcapstone 

$(TARGET4): main4.c
	$(CC) $(CFLAGS) main4.c -o $(TARGET4) -lcapstone 

$(TARGET5): main5.c
	$(CC) $(CFLAGS) main5.c -o $(TARGET5) -lcapstone 

all: $(TARGET) $(TARGET2) $(TARGET3) $(TARGET4) $(TARGET5)

clean:
	rm -f $(TARGET) $(TARGET2) $(TARGET3) $(TARGET4) $(TARGET5)

setup:
	sudo apt-get install libcapstone-dev

.PHONY: all clean
