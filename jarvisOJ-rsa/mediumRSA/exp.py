#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from libnum import *
from gmpy2 import *
n = 0xC2636AE5C3D8E43FFB97AB09028F1AAC6C0BF6CD3D70EBCA281BFFE97FBE30DD
e = 65537
c = 0x6d3eb7df23eee1d38710beba78a0878e0e9c65bd3d08496dda64924199110c79
p = 2
# while p < n:
#     if n % p == 0:
#         q = n / p
#         print 'p = ' + str(p)
#         print 'q = ' + str(q)
#         break
#     p += 1
p = 275127860351348928173285174381581152299
q = 319576316814478949870590164193048041239
d=invert(e,(p-1)*(q-1))
m = pow(c,d,n)
print n2s(m)
