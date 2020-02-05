#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
# If srand() is not called, the rand() seed is set as if srand(1) were called at program start
from pwn import *
import ctypes
#context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
io = process('./random')
elf = ELF('./random')

dll = ctypes.CDLL('/lib/x86_64-linux-gnu/libc.so.6')
r = dll.rand()
key = r^0xdeadbeef
io.sendline(str(key))
io.interactive()
io.close()

