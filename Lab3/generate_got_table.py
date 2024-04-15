from pwn import *

elf = ELF('./maze')
print("main =", hex(elf.symbols['main']))

with open("got.txt", "w") as fd:
    for s in [ f"move_{i}" for i in range(1200)]:
        if s in elf.got:
            fd.write("{:x}\n".format(elf.got[s]))