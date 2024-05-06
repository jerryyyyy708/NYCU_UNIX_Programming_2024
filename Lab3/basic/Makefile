CC = gcc
CFLAGS = -Wall -fPIC

LIB_TARGET = libmaze.so
LIB_OBJECTS = injection.o

all: $(LIB_TARGET)

$(LIB_TARGET): $(LIB_OBJECTS)
	$(CC) -shared -o $@ $^

injection.o: injection.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(LIB_TARGET) $(LIB_OBJECTS) *.so

.PHONY: all clean

run:
	cp libmaze.so ../src/; \
	cd ../src; \
	make preload; \