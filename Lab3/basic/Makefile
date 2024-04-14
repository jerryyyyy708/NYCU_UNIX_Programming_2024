# Compiler and linker variables
CC = gcc
CFLAGS = -Wall -fPIC

# Target for the shared library
LIB_TARGET = libmaze.so
LIB_OBJECTS = injection.o

# Default target
all: $(LIB_TARGET)

# Rule to create the shared library
$(LIB_TARGET): $(LIB_OBJECTS)
	$(CC) -shared -o $@ $^

# Rule to compile object files for the shared library
injection.o: injection.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean target
clean:
	rm -f $(LIB_TARGET) $(LIB_OBJECTS) *.so

.PHONY: all clean

run:
	cp libmaze.so ../src/; \
	cd ../src; \
	make preload; \