# Get GOT Table Address by py from Lab provided maze(not compiled by myself), then use DFS to find path, finally
#, replace the random moves to correct move

# Compiler and linker variables
CC = gcc-12
CFLAGS = -Wall -fPIC
LDFLAGS = -L. -lmaze

# Target for the shared library
LIB_TARGET = libmaze.so
LIB_OBJECTS = libmaze_dummy.o

# Target for the executable
EXE_TARGET = maze
EXE_OBJECTS = maze.o

# Default target
all: $(LIB_TARGET) $(EXE_TARGET)

# Rule to create the shared library
$(LIB_TARGET): $(LIB_OBJECTS)
	$(CC) -shared -o $@ $^

# Rule to compile object files for the shared library
libmaze_dummy.o: libmaze_dummy.c
	$(CC) $(CFLAGS) -c $< -o $@

# Rule to create the executable
$(EXE_TARGET): $(EXE_OBJECTS)
	$(CC) $^ $(LDFLAGS) -o $@

# Rule to compile object files for the executable
maze.o: maze.c moves.c libmaze.h
	$(CC) $(CFLAGS) -c maze.c -o $@

# Clean target
clean:
	rm -f $(LIB_TARGET) $(LIB_OBJECTS) $(EXE_TARGET) $(EXE_OBJECTS)

.PHONY: all clean
