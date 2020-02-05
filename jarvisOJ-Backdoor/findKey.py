#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from hashlib import sha256
from libnum import n2s

key = 0x24 ^ 0x6443
key = n2s(key)[::-1]

print 'key is ' + key
flag = 'PCTF{%s}' % sha256(key).hexdigest()
print flag
