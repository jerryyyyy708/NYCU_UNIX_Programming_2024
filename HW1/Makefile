# Makefile
all: unzip logger main

logger: logger.c filemap.c filemap.h
	gcc -fPIC -shared logger.c filemap.c -o logger.so -ldl -I.

main: main.c
	gcc main.c -o logger

clean:
	rm -f logger logger.so file.txt *.log
	rm -f ex1* ex2* ex3* ex4* ex5* ex6*

unzip:
	unzip -o examples.zip

run:
	@echo "./logger config.txt ./ex1-1"
	@./logger config.txt ./ex1-1 || true
	@sleep 1; echo;
	
	@echo "./logger config.txt ./ex1-2"
	@./logger config.txt ./ex1-2 || true
	@sleep 1; echo;
	
	@echo "./logger config.txt ./ex2"
	@./logger config.txt ./ex2 || true
	@sleep 1; echo;
	
	@echo "./logger config.txt ./ex3-1"
	@./logger config.txt ./ex3-1 || true
	@sleep 1; echo;
	
	@echo "./logger config.txt ./ex3-2"
	@./logger config.txt ./ex3-2 || true
	@sleep 1; echo;
	
	@echo "./logger config.txt ./ex4 www.cs.nycu.edu.tw"
	@./logger config.txt ./ex4 www.cs.nycu.edu.tw || true
	@sleep 1; echo;
	
	@echo "./logger config.txt ./ex4 www.google.com"
	@./logger config.txt ./ex4 www.google.com || true
	@sleep 1; echo;
	
	@echo "./logger config.txt ./ex5 172.217.160.100"
	@./logger config.txt ./ex5 172.217.160.100 || true
	@sleep 1; echo;
	
	@echo "./logger config.txt ./ex5 20.27.177.113"
	@./logger config.txt ./ex5 20.27.177.113 || true
	@sleep 1; echo;
	
	@echo "./logger config.txt ./ex6"
	@./logger config.txt ./ex6 || true
