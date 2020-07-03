# 堆之\*bin理解

在程序运行中，使用bins结构对释放的堆块进行管理，以减少向系统申请内存的开销，提高效率。

## chunk数据结构

从内存申请的所有堆块，都使用相同的数据结构——**malloc\_chunk**，但在inuse和free状态，表现形式上略有差别。

```
chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             Size of previous chunk, if unallocated (P clear)  |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             Size of chunk, in bytes                     |A|M|P|
  mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             User data starts here...                          .
        .                                                               .
        .             (malloc_usable_size() bytes)                      .
next    .                                                               |
chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             (size of chunk, but used for application data)    |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             Size of next chunk, in bytes                |A|0|1|
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

以上为malloc所得到的chunk的结构，前两个size\_t为chunk_header，分别保存前一个(物理相邻)chunk的size*(如果前一个chunk为空闲，则保存其size；若为使用状态则归前一个chunk作为usrdata区域使用)* 和本chunk的size。因分配的空间会向2*size\_t进行对齐，所以后3bit没有意义，因而将其作为三个标记位

- A ： NON\_MAIN\_ARENA，记录当前 chunk 是否不属于主线程，1表示不属于，0表示属于
- M ： 记录当前 chunk 是否是由 mmap 分配的
- P ： 记录前一个 chunk 块是否被分配。

chunk被free之后，其usrdata区域被复用，作为bin中的链表指针，其结构如下  

```
chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             Size of previous chunk, if unallocated (P clear)  |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
`head:' |             Size of chunk, in bytes                     |A|0|P|
  mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             fd                                                |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             bk                                                |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             (fd_nextsize)                                     |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             (bk_nextsize)                                     |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             Unused space (may be 0 bytes long)                .
        .                                                               .
 next   .                                                               |
chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
`foot:' |             Size of chunk, in bytes                           |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             Size of next chunk, in bytes                |A|0|0|
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- fd和bk指针分别指向bin中在其之前和之后的chunk*fd指向先进入bin者；bk指向后来者*。
- fastbin中只有fd指针，使用单向链表进行维护。
- fd\_nextsize和bk\_nextsize只存在与large bin中（chunk的size不大时不需要这两个变量，也可能没有他们的空间），指向前/后一个更大size的chunk。



-----

## fastbin

对于size较小(小于max\_fast)的chunk，在释放之后进行单独处理，将其放入fastbin中。

> max_fast:
>
> 在32位系统中，fastbin里chunk的大小范围从16到64；
>
> 在64位系统中，fastbin里chunk的大小范围从32到128。

fastbin是main\_arena中的一个数组，每个元素作为特定size的空闲堆块的链表头，指向被释放并加入fastbin的chunk。

fastbin链表采用**单向链表**进行连接

![fastbin](https://images2018.cnblogs.com/blog/1251324/201804/1251324-20180417085023770-1407281540.png)

如图所示，在free之后，会将被free掉指向的地址“挂”在fastbin相应大小的条目下，以便于下次分配时**节省时间**  ~~(曾经为了节省free指针的时间而不free，原来浪费了这么多时间，心疼我的无数个TLE)~~

在分配空间时，首先检查fastbin数组对应大小的条目下是否有“空闲”的空间，有则直接取下进行分配，同时修改fd指针，维护单向链表。

1. 在fastbin条目下，无论是free掉的空间地址加进来，还是将空闲的空间地址分配出去，都是**在根部操作**
   - 加入free的空间时，新加入的连在根部，（如新加入chunk3,插入链表根部，chunk3->fd指向原来最靠近bin的chunk1），类似*蛋白质的翻译过程*
   - 分配空间时，若在对应大小的条目下有空闲的空间，则按蛋白质翻译的逆顺序进行操作（上图中取出chunk3，将chunk3->fd = chunk1链在bin上）
2. malloc(n)时，实际申请的空间sizeof(chunk) = (n + 4) align to 8   (x86)
   - 实际申请的空间从chunk开始，当堆中物理相邻的前一个chunk为free时，Size of previous chunk标记前一个chunk的大小，否则可以存储前一个chunk的数据。之后是本chunk的大小，由于分配的必定是2*4bytes（64位为2*8bytes）的整数倍，最后三位没有影响用作三个标记位。
   - malloc函数范围的指针是从mem开始的用户可用空间。

## unsorted bin

unsorted bin 可以作为chunk 被释放和分配的缓冲区。在*malloc&free剖析*中解释了malloc和free活动中对unsorted bin的使用。这里从更微观的角度解释unsorted bin如何工作。 

### main\_arena

main\_arena,主分配区，是一个静态全局变量，其中存储着进行堆块管理的各种变量和指针。  

![main_arena](https://images2018.cnblogs.com/blog/1251324/201808/1251324-20180816152021505-644401736.png)

fastbin各项指针、topchunk、和bins指针都存在于这个变量当中。

unsorted bin指针就是bins指针的前两项，ptmalloc共维护128个bin，都存放于bins数组中。

- 前两项为unsorted bin的指针
- bins[2] - bins[65]的64个元素为small bin指针
- bins[66] - bins[127]为large bin

### unsorted bin

下面通过这段代码分析在释放和分配chunk时unsorted bin中各指针的工作细节：

```c
# include <stdio.h>
# include <stdlib.h>
int main()
{   
    void *a, *b, *c, *d, *e;
    a = malloc(128);
    b = malloc(128);
    c = malloc(128);
    d = malloc(128);
    e = malloc(128);
    printf("a >> %p\nb >> %p\nc >> %p\nd >> %p\ne >> %p\n",a,b,c,d,e);
    puts("free d and b, remember the bins");
    free(d);
    free(b);
    //puts("free c,look at the unsorted bin");
    //free(c);
    puts("malloc(128) again, what will happen?");
    void * newd = malloc(128);
    printf("new d -> %p\n", newd);
    return 0;
} 
//make file(x64):
//gcc -o unsortedbin ./test_unosrted -no-pie
```

运行后得到分配的五个chunk的地址，由于直接输出了返回给用户的指针，所以指向的都是usrdata，指向实际chunk头的地址应该减去0x10。

> a >> 0x602010
> b >> 0x6020a0
> c >> 0x602130
> d >> 0x6021c0
> e >> 0x602250

1. 没有发生free之前

   ![init](https://images2018.cnblogs.com/blog/1251324/201808/1251324-20180816163031728-1397190500.png)

   bins数组的前两个可以看做unsorted bin的fd和bk指针，在unsorted bin为空的时候都指向top (main\_arena+88)

   *[CTFwiki对这个过程具体流程和背后原理](https://ctf-wiki.github.io/ctf-wiki/pwn/heap/unsorted_bin_attack/)的示意图不太准确：unsorted bin链表头并不是malloc\_chunk结构体，而是main_arena变量中bins列表的前两项分别做fd和bk指针，指向的位置也不是pre\_size，而是main_arena中的top，top指向top chunk。我的理解是这样的，如有错误，还请指出。*

2. free(d)

   ```
   pwndbg> unsortedbin 
   unsortedbin
   all: 0x6021b0 —▸ 0x7ffff7dd3b58 (main_arena+88) —▸ 0x6021b0 ◂— 0x7ffff7dd3b58
   pwndbg> p main_arena 
   $2 = {
     mutex = 0, 
     flags = 1, 
     fastbinsY = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 
     top = 0x6026e0, 
     last_remainder = 0x0, 
     bins = {0x6021b0, 0x6021b0, 0x7ffff7dd3b68 <main_arena+104>, 0x7ffff7dd3b68 <main_arena+104>...
   pwndbg> telescope 0x6021b0
   00:0000│   0x6021b0 ◂— 0x0
   01:0008│   0x6021b8 ◂— 0x91
   02:0010│   0x6021c0 —▸ 0x7ffff7dd3b58 (main_arena+88) —▸ 0x6026e0 ◂— 0x0
   ... ↓
   ```

   ![free(d)](https://images2018.cnblogs.com/blog/1251324/201808/1251324-20180816163107497-1938470487.png)

   此时unsorted bin的两个指针均指向被释放的d，d的fd、bk指针指向top

3. free(b) 

   ```
   pwndbg> p main_arena 
   $3 = {
     mutex = 0, 
     flags = 1, 
     fastbinsY = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 
     top = 0x6026e0, 
     last_remainder = 0x0, 
     bins = {0x602090, 0x6021b0, 0x7ffff7dd3b68 <main_arena+104>,...
   pwndbg> unsortedbin 
   unsortedbin
   all: 0x602090 —▸ 0x6021b0 —▸ 0x7ffff7dd3b58 (main_arena+88) —▸ 0x602090 ◂— 0x6021b0
   pwndbg> telescope 0x602090 
   00:0000│   0x602090 ◂— 0x0
   01:0008│   0x602098 ◂— 0x91
   02:0010│   0x6020a0 —▸ 0x6021b0 ◂— 0x0
   03:0018│   0x6020a8 —▸ 0x7ffff7dd3b58 (main_arena+88) —▸ 0x6026e0 ◂— 0x0
   04:0020│   0x6020b0 ◂— 0x0
   ... ↓
   pwndbg> telescope 0x6021b0
   00:0000│   0x6021b0 ◂— 0x0
   01:0008│   0x6021b8 ◂— 0x91
   02:0010│   0x6021c0 —▸ 0x7ffff7dd3b58 (main_arena+88) —▸ 0x6026e0 ◂— 0x0
   03:0018│   0x6021c8 —▸ 0x602090 ◂— 0x0
   04:0020│   0x6021d0 ◂— 0x0
   ```

   ![free(b)](https://images2018.cnblogs.com/blog/1251324/201808/1251324-20180816164123937-1124638369.png)

   新释放的b会连载unsortedbin的根部，各指针的关系如图。

4. malloc(128)

   ```
   pwndbg> p main_arena 
   $4 = {
     mutex = 0, 
     flags = 1, 
     fastbinsY = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 
     top = 0x6026e0, 
     last_remainder = 0x0, 
     bins = {0x602090, 0x602090, 0x7ffff7dd3b68 <main_arena+104>, ...
   pwndbg> unsortedbin 
   unsortedbin
   all: 0x602090 —▸ 0x7ffff7dd3b58 (main_arena+88) —▸ 0x602090 ◂— 0x7ffff7dd3b58
   pwndbg> telescope 0x602090
   00:0000│   0x602090 ◂— 0x0
   01:0008│   0x602098 ◂— 0x91
   02:0010│   0x6020a0 —▸ 0x7ffff7dd3b58 (main_arena+88) —▸ 0x6026e0 ◂— 0x0
   ... ↓
   04:0020│   0x6020b0 ◂— 0x0
   ```

   此时unsorted bin又只有一个chunk，指针关系与刚刚free(d)时相同，但在bin中的是b，先进入的d被再次分配，由此得到，unsorted bin中遵循**FIFO**原则，先进入的chunk在size合适的情况下会被优先分配。

   ### unlink

   在unsorted bin中进行分配的时候，size不合适的chunk会被放入small bin或large bin，这个unlink的过程没有对chunk进行检查，所以被篡改过的chunk也能通过unlink，破坏掉链表中的fd、bk指针，即unsorted bin attack。

## small bins & large bin

chunk进入small bin和large bin的唯一机会是在分配chunk时，在unsorted bin中进行遍历，size不合适的chunk会被unlink过来。  

small bin和large bin都是采用双向链表进行维护，遵循FIFO原则。

其中large bin中的chunk有fd_nextsize和bk_nextsize，分别指向之前/之后更大的chunk，加快寻找速度。

在分配chunk的时候，如果前面的步骤都没有找到合适的chunk，则在small bin和large bin中找到最小的**large enough**的chunk，进行分割，unlink，分配完成。

----

Ref：

[安全技术精粹](https://paper.seebug.org/255/)  

[CTF wiki](https://ctf-wiki.github.io/ctf-wiki/pwn/heap/heap_structure/)  






