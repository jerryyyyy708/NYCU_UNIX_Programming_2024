all: logger main

logger: logger.c
	gcc-12 -fPIC -shared logger.c -o logger.so -ldl

main: main.c
	gcc-12 main.c -o main

clean:
	rm -f main logger.so
