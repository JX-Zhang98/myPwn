#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
import string
from pwn import *
def change(c):
    result = (((ord(c) >> 6) | (4 * ord(c))) ^ cont) & 0xff
    return result
def debug(val): # 参数为变量名字符串
    success(val+' -> {:#x}'.format(eval(val)))
    raw_input('go on >>')

mid = [[0 for i in range(32)] for i in range(5)]
ans = [0x99, 0xB0, 0x87, 0x9E, 0x70, 0xE8, 0x41, 0x44, 0x05, 0x04, 0x8B, 0x9A, 0x74, 0xBC, 85, 88, 0xB5, 0x61, 0x8E, 54, 0xAC, 9, 89, 0xE5, 0x61, 0xDD, 62, 63, 0xB9, 21, 0xED, 0xD5]
# ans = [153, 176, 135, 158, 112, 232, 65, 68,5, 4, 139, 154, 116, 188, 85, 88,181, 97, 142, 54, 172, 9, 89, 229,97, 221, 62, 63, 185, 21, 237, 213]
flag = 'f'
wordlist = string.printable
cont = 0
for i in range(5):
    mid[i][0] = change('f')
    for t in range(5):
        print 'mid' + str(t)
        print mid[t]

cont = 1
while cont <32:
    for c in wordlist:
        # last = (((ord(flag[cont-1]) >> 6) | (4 * ord(flag[cont-1]))) ^ (cont-1) ) &0xff
        mid[0][cont] = change(c)
        print c + '->' + hex(mid[0][cont])
        # debug('c')
        for i in range(4):
            result = mid[i][cont]
            last = mid[i][cont -1]
            # success('result -> {:#x}'.format(result))
            # success('last -> {:#x}'.format(last))
            # raw_input('go on >>')
            v2 = result
            v3 = (last | v2)
            result = (v3 & ~(v2 & last)) & 0xff
            mid[i+1][cont] = result
        success('result -> {:#x}'.format(result))
        success('ans[{}] -> {:#x}'.format(cont, ans[cont]))
        raw_input('>>')
        if result == ans[cont]:
            flag += c
            cont +=1 
            print flag
            for t in range(5):
                print 'mid' + str(t)
                print mid[t]
            break

'''
for cont in range(32):
    for c in wordlist:
        result = (((ord(c) >> 6) | (4 * ord(c))) ^ cont) & 0xff
        if result == ans[cont]:
            print hex(ord(c))
            flag += c
            print flag
     '''       




