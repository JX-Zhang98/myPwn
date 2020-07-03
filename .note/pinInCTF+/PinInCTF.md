# Reverse is Multiplex, You Need Pintools plus
## intel pin
Intel pin是一款插桩分析工具，提供了丰富的API供分析程序使用。pin通过对二进制程序进行插桩，根据调用API提供程序运行时的诸多数据，几乎可以完整的描述程序整个运行状态。  

对pin的简介和安装使用在[M4x师傅的博客](http://m4x.fun/post/pin-in-ctf/)中较为易懂，不在赘述

##pin的基本功能模块
[User Guide](https://software.intel.com/sites/landingpage/pintool/docs/97619/Pin/html/)中对pin的功能模块有较为详细的说明，[BrieflyX师傅](http://brieflyx.me/2017/binary-analysis/intel-pin-intro/)给出了对一些函数的分析和使用示例.  

个人目前感觉比较容易上手和使用的功能主要有：

> 简单指令计数(指令级别插桩)
>
> 高效指令计数(BB级别插桩)
>
> 内存跟踪(指令级别插桩)

## pin in CTF

### 指令计数

指令计数是对pin最简单的应用了，通过检测不同输入下程序运行总指令数量，寻找发生指令数量突变的输入，推导正确的输入形式。

M4x师傅通过*NDH2K13-crackme-500*和*hxpCTF-2017-main_strip*进行了实践并取得较好效果。

在鹏程杯2018中也有适用于这种情况的题目：**re350-badblock**，一个虚拟机逆向题目。

根据已经做出的题目，可以猜测flag应该以‘flag{’开头，进行一些尝试：

![attempt](http://ww1.sinaimg.cn/large/006z37hrly1fxtr3ixg1xj311t0lhwqr.jpg)

可以发现：

- 在正确的基础上增加一位错误答案(fla -> flax)，指令数大概增加150
- 在正确的基础上增加一位正确答案(fla -> flag)， 指令数大概增加500
- 同一个正确答案的基础上增加不同字符产生的错误答案的指令数大概相等(flax -> flaa)

根据这个规律可以在‘flag{’的基础上逐位进行爆破，最终获得flag

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-

from subprocess import Popen, PIPE
from sys import argv
import string
from pwn import *
pinPath = '/home/pn/pin-3.6-gcc-linux/pin' 
pinInit = lambda tool, elf: Popen([pinPath, '-t', tool, '--', elf] , stdin = PIPE, stdout = PIPE)
pinWrite = lambda cont: pin.stdin.write(cont)
pinRead = lambda : pin.communicate()[0]
dic = string.printable

if __name__ == "__main__":
    last = 0
    flag = 'flag{'
    while 1:
        for c in dic:
            tmp = flag + c
            pin = pinInit("./obj-intel64/myinscount0.so", "./badblock")
            pinWrite(tmp+'\n')
            info = pinRead()
            # print info    
            now = int(info.split("Count: ")[1])
            delta = now-last
            success("atmpt({}); ins({})-> delta({})".format(tmp, now,delta))
            if delta>250 and delta < 1000:
                flag += c
                success('flag ->' + flag)
            last = now
```

**注：**这种解题方式理论上没有问题，在手动单步执行中也经过实践检验，但是在python脚本中运行时，出现所有输入指令书均大致相等的情况，目前怀疑是python的subprocess在对输入进行封装的过程导致的问题，具体原因还没有确定，如果哪位大佬遇到过这种情况或解决了这个问题，欢迎指教。

*以上代码中使用的myincount0.so是根据inscount0.cpp改写的工具，一般情况下可以使用BB级别插桩的inscount1，相比之下速度更快*

### 内存读取










