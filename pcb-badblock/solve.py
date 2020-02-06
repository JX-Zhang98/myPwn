#!/usr/bin/env python
# -*- coding: utf-8 -*-

from subprocess import Popen, PIPE
from sys import argv
import string
from pwn import *
pinPath = '/home/pn/pin-3.6-gcc-linux/pin' 
pinInit = lambda tool, elf: Popen([pinPath, '-t', tool, '--', elf] , stdin = PIPE, stdout = PIPE)
pinWrite = lambda cont: pin.stdin.write(cont)
pinRead = lambda : pin.communicate()[0]
dic = string.printable


if __name__ == "__main__":
    last = 0
    flag = 'flag{'
    while 1:
        for c in dic:
            tmp = flag + c
            pin = pinInit("./obj-intel64/myinscount0.so", "./badblock")
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
