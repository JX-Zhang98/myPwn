#!/usr/bin/env python
# -*- coding: utf-8 -*-

from subprocess import Popen, PIPE
from sys import argv
import string
from pwn import *
pinPath = '/home/pn/pin-3.6-gcc-linux/pin'
pinInit = lambda tool, elf, password: Popen([pinPath, '-t', tool, '--', elf, '<<<', password] , stdin = PIPE, stdout = PIPE)
pinWrite = lambda cont: pin.stdin.write(cont)
pinRead = lambda : pin.communicate()[0]


dic = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
if __name__ == "__main__":
    left = 0
    right = 51 # use dichotomy to get the exact value of the password
    result = 0
    location = 0
    source = ['A', 'A', 'A', 'A', 'A']
    target = 22493966389 # the target to get by difference input
    while result != target:
        if result < target:

            source[location] = dic[dic.find(source[location]+step)]
        else:
            source[location] = dic[dic.find(source[location]-step)]


        password = ''.join(source)

        for c in dic:
            tmp = flag + c
            pin = pinInit("./myprintmem.so", "./code", password)
            pinWrite(tmp+'\n')
            info = pinRead()
            # print info    
            now = int(info.split("Count: ")[1])
            delta = now-last
            success("atmpt({}); ins({})-> delta({})".format(tmp, now,delta))
            if delta>250 and delta < 1000:
                flag += c
                success('flag ->' + flag)
            last = now

    print 'The password is:' + ''.join(source)
