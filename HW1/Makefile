# Makefile
all: logger main

logger: logger.c filemap.c filemap.h
	gcc -fPIC -shared logger.c filemap.c -o logger.so -ldl -I.

main: main.c
	gcc main.c -o main

clean:
	rm -f logger logger.so file.txt
