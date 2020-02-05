一个win下的后门程序，只有五个自定义函数，简单浏览之后很容易发现在*sub_401000*函数中存在栈溢出

```c
strcpy(Dest, Source);
```

strcpy前没有对长度进行检查，使得函数的参数Source可以直接拷贝到局部变量Dest上，从而造成栈溢出。

在主函数中，23行之后的部分，是将0x7ffa4512(*win下的万能 jmp esp*)和shellcode写到Dest的v13偏移处，再通过sub_401000处函数进行栈溢出。

```c
  v13 ^= 0x6443u;
  strcpy(Dest, "0");
  memset(&Dst, 0, 0x1FEu);
  for ( i = 0; i < v13; ++i )
    Dest[i] = 65;
  *(_DWORD *)Source = 0x7FFA4512;
  v7 = 0;
  strcpy(&Dest[v13], Source);
  qmemcpy(&v5, &unk_4021FC, 0x1Au);
  strcpy(&v11[v13], &v5);
  qmemcpy(&v3, &unk_402168, 0x91u);
  v4 = 0;
  strcpy(&v12[v13], &v3);
  sub_401000(Dest);
  return 0;
```

在win中，经常使用jmp esp + shellcode的方式，其中在win xp；2000；2003中存在一个通用的**jmp esp**的gadget，即0x0x7ffa4512，分析栈结构可以得到v13 = 0x24 ^ 0x6443 = 0x6467

在主函数最开始位置存在一个字符串到数的转换，根据小端序，对应的参数应该是'gd'