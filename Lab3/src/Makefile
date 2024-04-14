# Compiler and Compiler Flags
CC = gcc
CFLAGS = -Wall -g -fPIC

# The build target executable:
TARGET = maze

# The build target shared library
LIB_TARGET = libmaze_dummy.so

all: $(TARGET) $(LIB_TARGET)

# Object file for the library
LIB_OBJS = libmaze_dummy.o

# Specify the dependencies for the library
$(LIB_TARGET): $(LIB_OBJS)
	$(CC) -shared -o $(LIB_TARGET) $(LIB_OBJS)

# Specify how each object file should be built for the library
libmaze_dummy.o: libmaze_dummy.c libmaze.h
	$(CC) $(CFLAGS) -c libmaze_dummy.c

# Object files for the executable:
OBJS = maze.o

# Specify the dependencies for the executable
$(TARGET): $(OBJS) $(LIB_TARGET)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) -L. -lmaze_dummy

# Specify how each object file should be built for the executable
maze.o: maze.c libmaze.h
	$(CC) $(CFLAGS) -c maze.c

# Clean target
clean:
	rm -f $(TARGET) $(OBJS) $(LIB_TARGET) $(LIB_OBJS) libmaze_dummy.so libmaze.so *.o

# Phony targets
.PHONY: clean

run:
	LD_LIBRARY_PATH=. ./maze

preload:
	LD_PRELOAD=./libmaze.so LD_LIBRARY_PATH=. ./maze

basic:
	LD_PRELOAD=./basic.so LD_LIBRARY_PATH=. ./maze