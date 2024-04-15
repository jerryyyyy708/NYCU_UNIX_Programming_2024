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
	rm -f $(LIB_TARGET) $(LIB_OBJECTS) *.so got.txt

.PHONY: all clean

submit:
	python3 submit.py libmaze.so

run:
	cp libmaze.so ./src/; \
	cd ./src; \
	make preload; \
	cd ..;

table:
	python3 generate_got_table.py