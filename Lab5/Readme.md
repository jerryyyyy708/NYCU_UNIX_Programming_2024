# 312551086 Lab5
## Challenge 1
Simply send a shellcode which executes /bin/sh to the server.
## Challenge 2
1. Use objdump to get relative memory of functions.
2. Get original return address by buffer overflow.
3. Compute the address of the global variable msg.
4. Set the address of return funtion to msg by buffer overflow.
5. Set shellcode into msg.
## Challenge 3
Similar to challenge 2, but an additional step to get canary by buffer overflow to recover canary after buffer overflow.

### Note
For challenge 2 and 3, use gdb to check the stack of running program, so that you can determine how long the overflow should be.

### Some Simple GDB Commands
Run binary
```
gdb [binary]
```
Print address of variable
```
print &[name]
```
Show 20 lines of the stack info
```
x/20gx $rsp
```