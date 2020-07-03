本文重点解释malloc和free过程中涉及到的堆块管理活动，暂时省略了目前接触面比较小的关于线程和非主分配区活动的部分。

# free

用户free的chunk不会直接归还系统，而是由ptmalloc对空闲状态的chunk进行管理，以便于下一次分配的时候从空闲的chunk中快速找到合适的堆块进行分配，从而避免大量系统调用，减少申请内存的开销。

关于对空闲chunk管理的\*bins，参见[堆之*bin理解](##)

以下为free的大体流程。  

- 如果被释放堆块的size <= max_fast, 则将此chunk放入fastbin中。
  - 对于放入fastbin中的堆块，不会改变其使用状态P(物理相邻的下一个chunk的Pre_inuse位)，也不会对其进行合并操作。
  - 在之后的分配过程中，特定情况下有可能会对fastbin中的chunk进行遍历，并合并相邻的freed-chunk加入unsorted bin。

```c
#include<stdlib.h>          
int main()
{      
    void *a;
    a = malloc(0x28);
    //printf("a -> %p\n",a);//printf中会调用malloc，导致topchunk指针改变。
    free(a);
    return 0;      
}      
```

- 在以上代码中，应该会生成size=0x30的chunk，在调试中可以看到free之后，该chunk进入fastbin，且topchunk指针在free前后没有变化。  

```python
pwndbg> bins
fastbins
0x20: 0x0
0x30: 0x602000 ◂— 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x0
smallbins
empty
largebins
empty
pwndbg> p main_arena 
$2 = {
  mutex = 0, 
  flags = 0, 
  fastbinsY = {0x0, 0x602000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 
  top = 0x602030, 
  last_remainder = 0x0, 
```

- 若释放的chunk-size > max_fast :

  - 如果释放的chunk位于heap顶部(与top chunk相邻)，则将进行堆块合并操作
    - 判断物理相邻的前一个chunk是否为inuse，若空闲则与之合并。
    - 将合并的堆块与top chunk 进行合并。
    - 如果合并后topchunk 大小大于mmap的收缩阈值(128k)，要进行收缩，将多出来的部分归还给系统。
  - 否则最终将此chunk放入[unsorted bin](# unsorted bin)中。unsorted bin 可以看做是 bins 的一个缓冲区。
    - 检查其前一个chunk(物理相邻)是否空闲，是则进行合并。
    - 检查其后一个chunk是否空闲，是则进行合并。
    - 将得到的chunk加入unsorted bin的堆块要将起使用状态P赋0，并置fd和bk形成双向链表。

  ```python
  1.首先连续进行五次分配 malloc(128)
  pwndbg> r
  Starting program: /media/pn/Everything/Study/github/MyStudy/jarvisOJ/guestbook2/unsortedbin 
  a >> 0x602010
  b >> 0x6020a0
  c >> 0x602130
  d >> 0x6021c0
  e >> 0x602250               # 这些指针均指向chunk的usr data
  
  # 此时的bins中都为空
  pwndbg> bins
  fastbins
  0x20: 0x0
  ... ↓
  0x80: 0x0
  unsortedbin
  all: 0x0
  smallbins
  empty
  largebins
  empty
  pwndbg> p main_arena 
  $1 = {
    mutex = 0, 
    flags = 1, 
    fastbinsY = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 
    top = 0x6026e0, 
    last_remainder = 0x0, 
    bins = {0x7ffff7dd3b58 <main_arena+88>, 0x7ffff7dd3b58 <main_arena+88>,
    
  2.free(d)
  pwndbg> bins
  fastbins
  0x20: 0x0
  ... ↓
  0x80: 0x0
  unsortedbin
  all: 0x6021b0 —▸ 0x7ffff7dd3b58 (main_arena+88) —▸ 0x6021b0 ◂— 0x7ffff7dd3b58
  
  3.free(b)
  pwndbg> unsortedbin 
  unsortedbin
  all: 0x602090 —▸ 0x6021b0 —▸ 0x7ffff7dd3b58 (main_arena+88) —▸ 0x602090 ◂— 0x6021b0
  # 此时unsorted bin中有指向b和d两个chunk的指针
  
  4.free(c)
  pwndbg> unsortedbin 
  unsortedbin
  all: 0x602090 —▸ 0x7ffff7dd3b58 (main_arena+88) —▸ 0x602090 ◂— 0x7ffff7dd3b58
  pwndbg> telescope 0x602090
  00:0000│   0x602090 ◂— 0x0
  01:0008│   0x602098 ◂— 0x1b1
  02:0010│   0x6020a0 —▸ 0x7ffff7dd3b58 (main_arena+88) —▸ 0x6026e0 ◂— 0x0
  ... ↓
  04:0020│   0x6020b0 ◂— 0x0
  # 此时发生了chunk合并，unsorted bin中只有一个chunk，值为原来bchunk的地址
  # 查看该地址可以看到chunk的size已经变成0x1b0=3*0x90，说明正好是b、c、d三个chunk合并在一起
  
  ```

  ​

---

# malloc

- 将用户申请大小n(malloc的参数)转化为实际分配的chunk_size

  - 32位系统中size = (n + 4) align to 8
  - 64位系统中size = (n + 8) align to 16

- 若chunk_size <= max_fast ，进入fastbin进行寻找，   *search fastbins with size*

  > max_fast:
  >
  > 在32位系统中，fastbin里chunk的大小范围从16到64；
  >
  > 在64位系统中，fastbin里chunk的大小范围从32到128。

  - 如果对应size的index下有空闲的chunk，取下chunk，更新链表的fd指针，返回。
  - 如果对应index下没有空闲chunk，则进入small bin进行寻找。

- 若chunk_size 在small bin大小范围内，且not found in fastbin

  ![malloc process1](https://images2018.cnblogs.com/blog/1251324/201808/1251324-20180816011834985-1325455238.png)

  - *search smallbins with size*
  - 若对应index下有空闲的chunk，从该bin的**尾部**取下，更新fd、bk指针并返回。

- //此时仍未解决malloc申请，则申请的size较大或fastbin和small bin中都没有空闲chunk。

- 遍历fastbin中的空闲chunk，将相邻的chunk进行合并，将合并后的堆块加入unsorted bin。

- **若**此时unsorted bin中只有一个chunk，大小足够且上次分配使用过(last remainder)， 分割此堆块。

- ```python
  # 在上面free部分的演示代码中，free掉d和b后unsorted bin中有两个chunk
  pwndbg> unsortedbin 
  unsortedbin
  all: 0x602090 —▸ 0x6021b0 —▸ 0x7ffff7dd3b58 (main_arena+88) —▸ 0x602090 ◂— 0x6021b0
  # 再free(c)之后发生chunk合并,此时只有一个chunk，满足big enough 且 为上次分配使用
  pwndbg> n
  ... ↓
  pwndbg> unsortedbin 
  unsortedbin
  all: 0x602090 —▸ 0x7ffff7dd3b58 (main_arena+88) —▸ 0x602090 ◂— 0x7ffff7dd3b58
  # 此时进行malloc，从unsorted bin的唯一chunk中分割一块，剩余部分继续留在unsorted bin
  pwndbg> unsortedbin 
  unsortedbin
  all: 0x602120 —▸ 0x7ffff7dd3b58 (main_arena+88) —▸ 0x602120 ◂— 0x7ffff7dd3b58
  ```

  ​

- 对unsorted bin中的堆块进行遍历

  - 如果size不合适，则根据堆块的大小加入small bin 或 large bin(*the only place to insert small/large bin*)

  - 遇到size合适的堆块，则进行分配，停止遍历。

    ![malloc 2](https://images2018.cnblogs.com/blog/1251324/201808/1251324-20180816012014371-123620938.png)

- 在small bin和large bin中找到最小的**large enough**的chunk，进行分割，unlink，分配完成。

  - ![malloc 3](https://images2018.cnblogs.com/blog/1251324/201808/1251324-20180816012117337-1773029524.png)





---

### Ref:

[Glibc 内存管理-Ptmalloc2 源代码分析（华庭）](https://paper.seebug.org/papers/Archive/refs/heap/glibc%E5%86%85%E5%AD%98%E7%AE%A1%E7%90%86ptmalloc%E6%BA%90%E4%BB%A3%E7%A0%81%E5%88%86%E6%9E%90.pdf)

[CTF wiki](https://ctf-wiki.github.io/ctf-wiki/pwn/heap/unsorted_bin_attack/)

[How2heap](https://github.com/shellphish/how2heap)

