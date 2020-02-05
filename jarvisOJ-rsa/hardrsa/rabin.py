#!/usr/bin/env python
# -*- coding : utf-8

from libnum import *
from gmpy2 import *

e = 2
c = 0x39de036de3132757e819f769ead64bb487ee3f47e67843afb73748fd9e979be0
# rabin 
n = 0xC2636AE5C3D8E43FFB97AB09028F1AAC6C0BF6CD3D70EBCA281BFFE97FBE30DD
# from factordb :
p = 275127860351348928173285174381581152299
q = 319576316814478949870590164193048041239

mp = pow(c,(p+1)/4, p)
mq = pow(c,(q+1)/4, q)

yp, yq, _ = xgcd(p,q)
yp = invert(p,q)
yq = invert(q,p)
ans = [0,0,0,0,0]
ans[1] = (yp*p*mq+yq*q*mp)%n
ans[2] = abs(yp*p*mq - yq*q*mp)%n
ans[3] = n - int(ans[1])
ans[4] = n - int(ans[2])
for i in range(5):
    if ans[i]:
        print n2s(ans[i])
