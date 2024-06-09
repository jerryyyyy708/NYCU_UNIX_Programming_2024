# NYCU_UNIX_Programming_2024
Labs and homeworks of the course.
## Labs
### Lab01: docker & pwntools 
* Build Docker.
* Use pwntools to interact with remote server.

[Lab1 Source Code](https://github.com/jerryyyyy708/NYCU_UNIX_Programming_2024/tree/main/Lab1)

### Lab02: have fun with kernel modules
* Build rootfs in QEMU.
* Implement kernel module to interact with process, and with device using ioctl.

[Lab2 Source Code](https://github.com/jerryyyyy708/NYCU_UNIX_Programming_2024/tree/main/Lab2)

### Lab03: GOT maze challenge
* Build .so library with dlsym.
* Library injection with LD_PRELOAD.
* GOT table injection.

[Lab3 Source Code](https://github.com/jerryyyyy708/NYCU_UNIX_Programming_2024/tree/main/Lab3)

### Lab04: Race & reentrant 
* Get the FLAG in remote server.
* Find race condition problem in given source code.
* Find reentrant problem in given source code.

[Lab4 Source Code](https://github.com/jerryyyyy708/NYCU_UNIX_Programming_2024/tree/main/Lab4)

### Lab05: Buffer Overflow & Shellcoding Challenges
* Write and inject shellcode to run shell in remote server.
* Use buffer overflow to modify behavior of function (ex. return address).
* Understand the concept of canary.
* Use returned-oriented programming to solve challenge.
* Tools: objdump, ROPgadget, ...etc.

[Lab5 Source Code](https://github.com/jerryyyyy708/NYCU_UNIX_Programming_2024/tree/main/Lab5)

## Homeworks
### HW1 Monitor File Activities of Dynamically Linked Programs
* Implement a logger program to monitor the running program.
* Use library injection (LD_PRELOAD) to monitor the behavior of dynamic linked functions like ``fopen``, ``fread``,  ...etc. 

[HW1 Source Code](https://github.com/jerryyyyy708/NYCU_UNIX_Programming_2024/tree/main/HW1)

### HW2 Assembly
* Simple assembly programming challenges.

[HW2 Source Code](https://github.com/jerryyyyy708/NYCU_UNIX_Programming_2024/tree/main/HW2)

### HW3 Simple Instruction Level Debugger
* Implement a simple debugger (breakpoints, single step, continue, syscall...).
* Use PTRACE to trace the stat of the program.
* Use capstone library to disassmble the program.

[HW3 Source Code](https://github.com/jerryyyyy708/NYCU_UNIX_Programming_2024/tree/main/HW3)