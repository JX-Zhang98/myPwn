#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
import re
#context.log_level = 'debug'
class Bin():
    current_elf = None 
    def __init__(self, filename):
        # current_elf.__init__(self)
        print filename
        self.current_elf = ELF(filename)
        context.arch = self.current_elf.arch

    def read(self, loc,where, lenth):
        shellcode = shellcraft.read(0, where, lenth)
        res = shellcode + '/*end*/'
        while(True):
            mat = re.search('/(.*?)/', res)
            res = res.replace(mat.group(), '')
            if mat.group() == '/*end*/':
                break
        print res
        res = res.replace('\n', ';')
        self.current_elf.asm(loc, res)
        return loc+len(asm(res))

    def write(self, loc, where, lenth):
        res = shellcraft.write(1, where, lenth) + '/*end*/'
        while(True):
            mat = re.search('/(.*?)/', res)
            res = res.replace(mat.group(), '')
            if mat.group() == '/*end*/':
                break
        res = res.replace('\n', ';')
        self.current_elf.asm(loc, res)
        return loc+len(asm(res))


    def jmp(self, loc, target):
        ins = 'jmp {}'.format(hex(target))
        self.current_elf.asm(loc, ins)
        return target


    def edit(self, startLoc, asmfile):
        # no jmp ins in asmfile
        nowloc = startLoc
        f = open(asmfile, 'r')
        ins = f.readline()
        while(ins != '' and ins != '\n'):
            self.current_elf.asm(nowloc, ins)
            nowloc += len(asm(ins))
            ins = f.readline()
        f.close()
        return nowloc

    def save(self, filename):
        self.current_elf.save(filename)

