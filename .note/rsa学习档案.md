# RSA 学习档案  
## 基本原理  
随机选择两个质数p，q  
模数n=p\*q  
φ(n)=(p−1)(q−1)  
选择加密指数e: 1 < e < φ(n)  
计算机密指数d: e\*d % φ(n) = 1  
c = m ^ e % n  
m = c ^ d % n  

## 常见攻击方式  
### 模数分解  
#### 1.直接分解  
n小于256bit可以本地暴力分解。  
去[factordb](http://factordb.com/)查询是否有已经分解成功的结果。  
#### 2.给出多个n，可以尝试计算n之间的最大公约数。  

```python
from libnum import *
n1 = 9051013965404084482870087864821455535159008696042953021965631089095795348830954383127323853272528967729311045179605407693592665683311660581204886571146327720288455874927281128121117323579691204792399913106627543274457036172455814805715668293705603675386878220947722186914112990452722174363713630297685159669328951520891938403452797650685849523658191947411429068829734053745180460758604283051344339641429819373112365211739216160420494167071996438506850526168389386850499796102003625404245645796271690310748804327
n2 = 13225948396179603816062046418717214792668512413625091569997524364243995991961018894150059207824093837420451375240550310050209398964506318518991620142575926623780411532257230701985821629425722030608722035570690474171259238153947095310303522831971664666067542649034461621725656234869005501293423975184701929729170077280251436216167293058560030089006140224375425679571181787206982712477261432579537981278055755344573767076951793312062480275004564657590263719816033564139497109942073701755011873153205366238585665743
print gcd(n1, n2)
>>> 1564859779720039565508870182569324208117555667917997801104862601098933699462849007879184203051278194180664616470669559575370868384820368930104560074538872199213236203822337186927275879139590248731148622362880471439310489228147093224418374555428793546002109
```

从而找到n的因数。
#### 3.pq相差过大时或过近，使用[yafu](https://github.com/DarkenCode/yafu)  
(没分解之前我怎么知道pq差的多不多？好像就是碰运气上吧。。。)  
[>pcat<](https://www.cnblogs.com/pcat/p/7508205.html)  
[yafu](https://sourceforge.net/projects/yafu/)直接把二进制文件复制到/usr/bin中即可直接终端使用。在nextrsa中level5，使用yafu尝试一下，很快就出来，分解成功意味着本层攻击通过。  

```bash
pn@Dp:~$ yafu
08/09/18 10:58:31 v1.34.5 @ Dp, System/Build Info: 
Using GMP-ECM 6.4.4, Powered by GMP 5.1.1
detected Intel(R) Core(TM) i7-6700HQ CPU @ 2.60GHz
detected L1 = 32768 bytes, L2 = 6291456 bytes, CL = 64 bytes
measured cpu frequency ~= 2592.050760
using 20 random witnesses for Rabin-Miller PRP checks

===============================================================
======= Welcome to YAFU (Yet Another Factoring Utility) =======
=======             bbuhrow@gmail.com                   =======
=======     Type help at any time, or quit to quit      =======
===============================================================
cached 78498 primes. pmax = 999983
>> factor(0x1daf9fab45ff83e751bf7dd1b625879b3a8c89d4a086e0806b31e2a2cc1c4c1bc8694db643acc4911f3d143c1951f006df9e0a7282b65839d84b36102b8f2307c4eaa561e65435350d9cb2b978ace582535ae00d948546520252d0f59d82dcfa59bac33812da5b12c18de35bfbabfa481aa9d59a7ba00bc74cc1b55077c1ff72aff50493)
fac: factoring 89533915895730376845429388317318135465963715353319668296037460436832261571698764116420554922112987252021884948875657862384344377649170583262156985771188545996699834706518979095963558441172283692904190696321256561220096609285943746235694660754929195042921609910688164136057366713317326844870724924355344603175946880147
fac: using pretesting plan: normal
fac: no tune info: using qs/gnfs crossover of 95 digits
div: primes less than 10000
rho: x^2 + 3, starting 1000 iterations on C317 
rho: x^2 + 2, starting 1000 iterations on C317 
rho: x^2 + 1, starting 1000 iterations on C317 
pm1: starting B1 = 150K, B2 = gmp-ecm default on C317
Total factoring time = 5.0378 seconds

***factors found***

P9 = 743675299
P309 = 120393827811847730665892922601047874074897457839754965824187553709286586875999984122668238470178081377988439748992735957987417809407665405412580451688753139556272709693049760814986485709769800614157806922562929660004878835280427602632657375319022388348710785821982994403660254841027504457789884082670526620753

ans = 1
>>
```

### 低指数攻击  
#### 低加密指数  
##### 1.e=3 时小明文攻击  
e=3时，如果明文过小，导致m ^ 3  < n,(一般此时len(c) < len(n))失去加密作用，可以直接对c开三次方(或者尝试对(c+k\*n)开三次方)  

```python
i=0
while 1:
   if(gmpy2.root(c+i*N, 3)[1]==1):
       print gmpy2.root(c+i*N, 3)
       break
   i=i+1
```
安恒7月月赛中rsa：
![](https://images2018.cnblogs.com/blog/1251324/201808/1251324-20180809110655390-1080730779.png)  
c的长度远小于n，所以直接开方获得。  
![](https://images2018.cnblogs.com/blog/1251324/201808/1251324-20180809112354996-483555264.png)  

##### 2.广播攻击
加密指数较低，使用**相同的加密指数**加密**相同的消息**(m, e相同)  
![广播攻击](https://i.imgur.com/H7Zec1s.png)  
关于cx的计算和原理参见[中国剩余定理和RSA算法](https://wenku.baidu.com/view/4e8db1e081c758f5f61f6766.html),将算式迁移到此进行对比分析  

```python
# 2(c1) = x mod 3(n1)
# 3(c2) = x mod 5(n2)
# 2(c3) = x mod 7(n3)
# x 即相当于 m^e
n = [n1, n2, n3]
c = [c1, c2, c3]
N = n1 * n2 * n3 = 105
Ni = N / n[] = [35, 21, 15]
# 求逆元T[]
# Ni * T = 1 mod n1
T = []
for i in xrange(3):
	T.append(long(invert(Ni[i], n[i])))
# T = [2, 1, 1]
cx = sum(Ni[i]*T[i]*c[i]) % N
m = cx ^ (-3)
```

nextrsa中level9给出了三组{n:c},并且声明m,e相同，且e=3  
```python
# c1=pow(m,e,n1),c2=pow(m,e,n2),c3=pow(m,e,n3)
# e=0x3
```
可以根据以上原理进行运算

```python
from gmpy2 import invert
def broadcast(n1, n2 ,n3, c1, c2, c3):
	n = [n1, n2, n3]
	C = [c1, c2, c3]
	N = 1
	for i in n:
	    N *= i
	Ni = []
	for i in n:
	    Ni.append(N / i)
	T = []
	for i in xrange(3):
	    T.append(long(invert(Ni[i], n[i])))
	X = 0
	for i in xrange(3):
	    X += C[i] * Ni[i] * T[i]
	m3 = X % N
	m = iroot(m3, 3)
	return m[0]
```

##### 3.[Coppersmith定理攻击](http://inaz2.hatenablog.com/entry/2016/01/20/022936)

适用于e较小(==3 ?)且明文中有 2/3 的bit已知，可以求出明文中全部的bit.

日本大佬的博客看不懂。。。以后再对着翻译来吧，~~反正坑是这么挖下了，什么时候填，填不填的就是另一回事了。~~



#### 低解密指数  
##### 1.[Wiener attack](https://github.com/pablocelayes/rsa-wiener-attack)  
d < (1/3) N^(1/4)时,（e很大），采用wiener
python实现的高效攻击方法，e很大的时候，执行脚本，输入e， n即可。
![](https://images2018.cnblogs.com/blog/1251324/201808/1251324-20180809163017620-1831093755.png)
*//采用**相同的n**，不同的公钥e加密五次和采用五个e相乘加密一次**效果相同**，因此同模多次加密有可能采用低解密指数攻击*
### 共模攻击  
多组加密中，使用**相同的模数**和**互质的e**对**相同的明文**进行加密(m, n相同)  
可以在不分解n和求出d的情况下获得m  

> from [gwind](https://www.cnblogs.com/gwind/p/8013154.html)
>
> e1， e2互质，则存在s1， s2，使得：  
>
> e1\*s1+e2\*s2 = 1  
>
> 式中，s1、s2皆为整数，但是一正一负。  
>
> 通过扩展欧几里德算法，我们可以得到该式子的一组解（s1,s2），假设s1为正数,s2为负数.  
>
> 因为  c1 = m^e1%n ；c2 = m^e2%n
>
> 所以  (c1^s1\*c2^s2)%n = ((m^e1%n)^s1\*(m^e2%n)^s2)%n
>
> 根据模运算性质，可以化简为
>
> (c1^s1\*c2^s2)%n = ((m^e1)^s1\*(m^e2)^s2)%n
> 即
>
> (c1^s1\*c2^s2)%n = (m^(e1\*s1+e2\*s2))%n
> 又前面提到
>
> e1\*s1+e2\*s2 = 1
> 所以
>
> (c1^s1\*c2^s2)%n = (m^(1))%n 
> (c1^s1\*c2^s2)%n = m%n
> 即
>
> **c1^s1*c2^s2 = m**

*模运算中，负数次幂的运算方式：c2^s2  (s2<0)，计算c2的模反元素c2'，计算c2' ^ (-s2)*   

nextrsa 中level8：

```
c1=pow(m,e1,n),c2=pow(m,e2,n)
```

使用同样的n，不同的加密指数加密m

```python
from libnum import invmod
from libnum import xgcd
def commonN(n, e1, c1, e2, c2):
    s1, s2, _ = xgcd(e1, e2)
    if s1 < 0:
        s1 = -s1
        c1 = invmod(c1, n)
        # invmod 求模反元素
    if s2 < 0:
        s2 = -s2
        c2 = invmod(c2, n)
    m = (pow(c1, s1, n) * pow(c2, s2, n)) % n
    return m
```



**Ref**
[CTF中RSA常见攻击方法](http://sec.chinabyte.com/47/13910547.shtml)  
[Err0rzz](https://err0rzz.github.io/2017/11/14/CTF%E4%B8%ADRSA%E5%A5%97%E8%B7%AF/#%E5%BC%BA%E7%BD%91%E6%9D%AF-nextrsa-nextprime)  
[M4x的nextrsa](http://www.cnblogs.com/WangAoBo/p/8654120.html)
[Freebuf-CTF中RSA思路技巧](http://www.freebuf.com/articles/others-articles/161475.html)
[阮一峰RSA算法原理](http://www.ruanyifeng.com/blog/2013/07/rsa_algorithm_part_two.html)





