# 格式化字符串  
## format string基本介绍
此漏洞由printf类函数在使用时直接使用用户可控字符串作为格式化字符串使用所导致。如**printf(s)**,在运行时，用户可以通过给予s特殊的值造成程序崩溃或泄露内存地址，乃至任意地址写控制程序流程。
### 利用原理  
#### 获取参数
![](https://images2018.cnblogs.com/blog/1251324/201807/1251324-20180728193524258-1553707214.png)  

![](https://images2018.cnblogs.com/blog/1251324/201807/1251324-20180728194158868-517443666.png)  
在使用printf函数时，第一个参数为格式化字符串指针，之后根据格式符向下寻找需要的参数并根据格式符进行解释。但是在**printf(s)**过程中，若字符串s中存在格式符，仍会按照次序将相应位置的变量进行解析并输出。  
#### 特殊用法  
在利用格式化字符串漏洞的过程中有几个至关重要的特殊用法  
> %5\$d -> 5$表示指定使用第五个参数  
> %240c -> 表示输出240个字符  
> **%n -> 不产生输出，将再次之前已经输出的字符个数写入对应参数所指向的内存**  
> %7$hhn -> 将输出字符个数写入第七个参数所指向的区域，写入一个字节(x86)(half half)  

利用%n向指定内存中写是改变程序流程的关键，而其他格式符则用于泄露内存信息或为配合%n写数据。  

### 例题　　
####　echo　　
![](https://images2018.cnblogs.com/blog/1251324/201807/1251324-20180728164509137-501716488.png)  
一个可以循环利用的格式化字符串，可以通过%n将printf的地址改写成为system函数的地址，下一次输入"/bin/sh"后执行printf("/bin/sh")而实际上调用了system函数，获得shell。
![](https://images2018.cnblogs.com/blog/1251324/201807/1251324-20180728164559365-1549506702.png)
根据调试中的栈结构，0xffdd69b0位置存储格式化字符串指针，其下有指向\_IO\_2\_1\_stdin\_和\_GLOBAL\_OFFSET\_TABLE\_的指针。(如果有需要可以通过泄露这两个变量查询所使用的libc库，进而获得其他变量或函数的偏移。)
其下0xffdd69cc为输入的格式化串的起始地址，可以在格式化字符串中布局需要改写的内存地址，按照顺序目标地址所在位置分别为~~printf函数~~格式化字符串的第7， 8， 9 ，10个参数，即分别使用%7$hhn-%10$hhn逐字节覆写（一次输出太多字节容易导致链接断开，故使用hhn），除了起始16个字节为地址，其余使用%240c等进行占位.
**使用pwntools的fmtstr_payload()函数自动生成利用字符串。**  
> [pwnlib.fmtstr.fmtstr\_payload](http://docs.pwntools.com/en/stable/fmtstr.html)(offset, writes, numbwritten=0, write_size='byte') → str  
> Makes payload with given parameter. It can generate payload for 32 or 64 bits architectures. The size of the addr is taken from **<code>context.bits</code>**  
> Parameters:
> > - offset (int) – the first formatter’s offset you control  
> > - writes (dict) – dict with addr, value {addr: value, addr2: value2}  
> > - numbwritten (int) – number of byte already written by the printf function  
> > - write\_size (str) – must be byte, short or int. Tells if you want to write byte by byte, short by short or int by int (hhn, hn or n)  


> 函数中offset即为栈中指向被改写区域指针**相对格式化字符串指针的偏移**(作为第几个参数)，在上图中指向printf.got的指针位于格式化字符串指针下第七个的位置，offset即为7.  
> writes是一个**字典*	*，为要改写的值和目标值，即用value的值替换掉内存中key指向的区域。  
> numbwritten即为在之前已经输出的字符数，write_size为mei每次改写的size，一般使用byte(hhn),以避免程序崩溃或连接断开。  
> 所以本题payload可以直接使用函数生成  
> <code>payload = fmtstr_payload(7, {printf_got: system_plt})</code>

--------------
#### echo2  
变成了64bit且开启了PIE保护。
![stack](https://images2018.cnblogs.com/blog/1251324/201807/1251324-20180731093907436-177245858.png)  
可以看到在调用printf函数时，栈中存储着很多与全局变量和函数相关的地址，可以利用格式化字符串泄露两个函数地址，从而查询使用的libc版本(inndy网站中提供了题目使用的链接库，故不需要此步骤)，继而确定elf基址和libc的偏移量。  
在尝试中发现stdout函数地址输出为nil，setbuf和init无法从libc中获取地址，所以采用*c08*处的main和*be8*处的\_\_libc\_start\_main.  
![base](https://images2018.cnblogs.com/blog/1251324/201807/1251324-20180731085615032-1585749572.png)
//这里有一点是本地的时候be8处地址为\_\_libc\_start\_main+241，但是远程时，需要令接收到的值-240，才能满足基址后三位为000.  
*<code>  0x7fffffffcbe8 —▸ 0x7ffff7a5a2b1 (__libc_start_main+241) ◂— mov    edi, eax </code>*  
排除掉随机地址的障碍之后就可以像echo一样覆盖函数地址，但是由于64位程序中地址为0x7fffffffxxxx的形式，前两个字节为\\x00，不能向printf函数中写入，可以覆写exit函数，但是传递'/bin/sh'有障碍。  
这里可以利用**libc库中固有的一个执行execv('/bin/sh')的gadget**。可以在libc中通过查找字符串/bin/sh找到。  
![gadget](https://images2018.cnblogs.com/blog/1251324/201807/1251324-20180731091732964-2059879414.png)将此gadget的地址逐位写到exit\_got,即可获得shell。有一点是fmtstr\_payload生成的利用字符串会把地址放在前面，而地址中存在\\x00会导致printf中断，所以不能正常使用，还是手动构造。



#### echo3

这道题的主要问题在于格式化字符串不在stack中，也就无法直接利用payload构造改写的地址。这类题目的策略在于利用栈中存在的指向特定区域的变量，不断构造跳板，最终实现对指定地址的改写。    
![](https://images2018.cnblogs.com/blog/1251324/201808/1251324-20180808153101172-52007541.png)  
一般改写时选用此类**栈变量的值为栈中的地址，且该值指向另一个栈地址**的位置构造跳板，进行改写。  
一般步骤为：  

> 1.leak栈地址和libc基址  
> 2.将指向与目标地址接近的地址的栈变量连缀到跳板上  
> 3.改写上一步相近的地址为目标地址
> 4.对目标地址内容进行改写

选择上图中0x1e和0x1f形式的位置作为跳板，因为要改写栈变量为got地址(0x0804\*\*\*\*),  所以将0x13，0x15处等内容和目标相近的地址连缀到跳板处，随后改写0x13,0x15的内容，最终实现   

>  1e:78│ 0x0458 —▸ 053c —▸ 0x042c(0x13) -> 0x804a020(exit_got)
>
>  1f :7c│ 0x045c —▸ 0534 —▸ 0x0434(0x15) -> 0x804a022(exit_got+2)   

使用printf修改内存时，每次最多对一个地址修改两个字节(hn)，因而构造两个跳板，分别指向目标地址的高低两个位置(x64大概要构造4个跳板)，多重跳板进行改写时，每次都要注意*指针的层次关系*。

echo3这道题，有幸学长提前进行了点播，指出了最大的一个坑：使用不同的libc运行时，栈结构有差异。所以在本地调试的时候就通过指定libc，产生与远程相同的栈结构.  

<code>io = process('./echo3', env = {'LD\_PRELOAD':'../libc-2.23.so.i386'})</code>

另一个比较麻烦的点在于栈的位置由随机数决定，所以每次运行的栈结构不尽相同，但只有三十种情况。解决办法是挑选一个比较合适的栈结构（有丰富栈变量，指向libc全局变量等），对照固定的栈结构进行设计，运行时多次运行，进行栈结构碰撞。  
在这个程序中要求输入五次然后exit，所以先改写了exit\_got,使调用exit的时候再跳转到循环部分，从而实现无限输入（利用exit跳转回之后栈结构发生一定变化，需要适当调整），再覆写printf\_got的内容为system\_addr即可。  
弄完之后发现，其实没必要改写exit，根据上面的分析，完全可以利用改写exit\_got的机会直接改写printf\_got,并在4次输入内完成，第五次直接输入'/bin/sh',获得shell.




## Ref：
[利用小结（一）](https://www.anquanke.com/post/id/85785)  
[利用小结（二）](https://www.anquanke.com/post/id/85817)  
[CTAF Wiki](https://ctf-wiki.github.io/ctf-wiki/pwn/fmtstr/fmtstr_exploit/)  
[M4x的inndyWP](https://www.cnblogs.com/WangAoBo/p/hackme_inndy_writeup.html#_label6)  
[qazbnm456/ctf-course](https://github.com/qazbnm456/ctf-course/blob/master/slides/w4/format-string.md)  
[pwnlib.fmtstr](http://docs.pwntools.com/en/stable/fmtstr.html)  
[安全技术精粹](https://paper.seebug.org/246/)  
[m4x.fun](http://m4x.fun/post/hitcon-training-writeup/)  

