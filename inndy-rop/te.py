#!/usr/bin/env python
# encoding: utf-8

from pwn import *
context.log_level = 'debug'

io = process('./rop2')
io.recvuntil(':')
io.sendline('')
s = io.recv()
print s
print 'len of s -> ' + str(len(s))

