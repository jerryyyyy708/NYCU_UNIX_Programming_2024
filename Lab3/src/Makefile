CC = gcc
CFLAGS = -Wall -g -fPIC

TARGET = maze

LIB_TARGET = libmaze_dummy.so

all: $(TARGET) $(LIB_TARGET)

LIB_OBJS = libmaze_dummy.o

$(LIB_TARGET): $(LIB_OBJS)
	$(CC) -shared -o $(LIB_TARGET) $(LIB_OBJS)

libmaze_dummy.o: libmaze_dummy.c libmaze.h
	$(CC) $(CFLAGS) -c libmaze_dummy.c

OBJS = maze.o

$(TARGET): $(OBJS) $(LIB_TARGET)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) -L. -lmaze_dummy

maze.o: maze.c libmaze.h
	$(CC) $(CFLAGS) -c maze.c

clean:
	rm -f $(TARGET) $(OBJS) $(LIB_TARGET) $(LIB_OBJS) libmaze_dummy.so libmaze.so *.o

.PHONY: clean

run:
	LD_LIBRARY_PATH=. ./maze

preload:
	LD_PRELOAD=./libmaze.so LD_LIBRARY_PATH=. ./maze

basic:
	LD_PRELOAD=./basic.so LD_LIBRARY_PATH=. ./maze