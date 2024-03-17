#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import hashlib
import time
import sys
from pwn import *

def solve_pow(r):
    prefix = r.recvline().decode().split("'")[1];
    print(prefix)
    solved = b''
    for i in range(1000000000):
        h = hashlib.sha1((prefix + str(i)).encode()).hexdigest();
        if h[:6] == '000000':
            solved = str(i).encode();
            print("solved =", solved);
            break;
    r.sendlineafter(b'string S: ', base64.b64encode(solved));

def process_string(s, i):
    s = s.split(f"{i}: ")[1]
    s = s.split(" = ?")[0]
    return s

def parse_equation(s):
    l1 = s[0:49]
    l2 = s[50:99]
    l3 = s[100:149]
    l4 = s[150:199]
    l5 = s[200:249]
    nums = []
    for i in range(7):
        num = ""
        num = num + l1[i*7:i*7+7] + '\n'
        num = num + l2[i*7:i*7+7] + '\n'
        num = num + l3[i*7:i*7+7] + '\n'
        num = num + l4[i*7:i*7+7] + '\n'
        num = num + l5[i*7:i*7+7]
        nums.append(num)
    first = 0
    sec = 0
    op = 999
    for i in nums:
        bit = 0
        if "─┴─" in i:
            bit = 1
        elif "┌───┘" in i:
            bit = 2
        elif " ───┤" in i:
            bit = 3
        elif "└───┐" in i:
            bit = 5
        elif "├───┐" in i:
            bit = 6
        elif "├───┤" in i:
            bit = 8
        elif "╳" in i:
            bit = -1
        elif "•" in i:
            bit = -2
        elif "┼" in i:
            bit = -3
        elif "└───┤" in i and "└───┘" in i:
            bit = 9
        elif "└───┤" in i and "┌───┐" not in i:
            bit = 4
        elif "┌───┐" in i and "└───┘" not in i:
            bit = 7

        if bit < 0:
            op = bit
            continue
        if op == 999:
            first = first*10 + bit
        else:
            sec = sec*10 + bit
    print(first, sec)
    if op == -1:
        return first * sec
    elif op == -2:
        return int(first/sec)
    else:
        return first+sec


if __name__ == "__main__":
    r = None
    if len(sys.argv) == 2:
        r = remote('localhost', int(sys.argv[1]))
    elif len(sys.argv) == 3:
        r = remote(sys.argv[2], int(sys.argv[1]))
    else:
        r = process('./pow.py')
    solve_pow(r);
    _ = r.recvline()
    i = 1
    while True:
        try:
            line = r.recvuntil('= ?')
        except:
            line = r.recvline()
            print(line.decode())
            break
        line = process_string(str(line), i)
        decoded_bytes = base64.b64decode(line)
        decoded_str = decoded_bytes.decode('utf-8')
        print(decoded_str)

        ans = parse_equation(decoded_str)
        print(ans)
        r.sendline(str(ans))
        i+=1
    
    r.close();

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
