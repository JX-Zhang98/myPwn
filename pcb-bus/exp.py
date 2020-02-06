#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
from sys import argv
#context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']

elf = ELF('./bus')

