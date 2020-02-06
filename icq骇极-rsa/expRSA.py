#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
from pwn import *
context.log_level = 'debug'
from libnum import *
from hashlib import *
from gmpy2 import *
import string
from Crypto.Cipher import AES


def proof(padding, result):
    wordlist = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    dig = padding
    for a in wordlist:
        for b in wordlist:
            for c in wordlist:
                for d in wordlist:
                    att = dig + a+b+c+d
                    # print att
                    if sha512(att).hexdigest() == result:
                        print att
                        success('challenge 0 solved')
                        return a+b+c+d




if __name__ == '__main__':
    # proof
    io = remote('106.75.101.197', 7544)
    io.recvuntil('sha512(')
    padding = io.recv(16)
    io.recvuntil('== ')
    res = io.recv(128)
    io.sendlineafter('XXXX:', proof(padding, res))
    # private key
    io.recvuntil('message:')
    msg = int(io.recvuntil('\n', drop = True),16)
    io.recvuntil('text:')
    cipher = int(io.recvuntil('\n', drop = True),16)
    d=1
    N = cipher-msg
    io.sendlineafter('n:', str(N))
    io.sendlineafter('d:', '1')
    mesg1 = msg
    # decrypt one
    io.recvuntil('n=')
    n = int(io.recvuntil('\n', drop = True),16)
    io.recvuntil('e=')
    e = int(io.recvuntil('\n', drop = True),16)
    io.recvuntil('c=')
    c = int(io.recvuntil('\n', drop = True),16)
    todec = (pow(2,e,n)*c)%n
    io.sendlineafter('c):', str(todec))
    io.recvuntil('essage:')
    mes = int(io.recvuntil('\n',drop = True),16)
    message= mes/2
    io.sendlineafter('message:',str(message))
    mesg2 = message
    # get flag
    m1 = n2s(mesg1)
    m2 = n2s(mesg2)
    io.recvuntil('flag:')
    flag = int(io.recvuntil('\n',drop = True), 16) # encrypted
    flag = n2s(flag)
    aes = AES.new(m2, AES.MODE_CBC, m1)
    flag  = aes.decrypt(flag)
    success('flag is -> {}'.format(flag))


















