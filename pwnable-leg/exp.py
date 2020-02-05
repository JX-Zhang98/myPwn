#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
#context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
key1=0x8cdc+0x8
key2=0x8d04+0x4+0x4
key3=0x8d80

key=key1+key2+key3

print key
