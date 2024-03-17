obj-m += hellomod.o
ccflags-y += -DEXPORT_SYMTAB

# Target for compiling the kernel module
all: hello_module hello

hello_module:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

# Target for compiling the userspace application
hello: hello.c
	gcc -o hello hello.c -Wall

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f hello
