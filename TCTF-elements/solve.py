#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
from z3 import *

x = 6.2791383142154
y = FP('y', FPSort(8, 24))
z = FP('z', FPSort(8, 24))
S = FP('S', FPSort(8, 24))
r = 1.940035480806554
R = 4.777053952827391
s = Solver()
s.add(y>x)
s.add(z>y)
s.add(x+y>z)
s.add(S == 0.5*(x+y+z)*r)
s.add(S == x*y*z/(4*R))
while s.check() == sat:
    print s.model()
    s.add(Or(s.model()[y] != y, s.model()[z]!=z, s.model()[S] != S))

