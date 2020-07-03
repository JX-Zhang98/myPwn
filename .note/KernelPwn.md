# Kernel pwn-极简题目的操作模式

>  天下事有难易乎?为之,则难者亦易矣;不为,则易者亦难矣。

*完全参照[M4x师傅](http://m4x.fun/post/linux-kernel-pwn-abc-1/)的指导，用 hacklu的baby kernel迈了第一步*

## 题目附带文件说明

一般题目会给出bzImage,*.cpio, *.sh文件

- sh文件适用于启动kernel的shell脚本文件,参数决定了内核的保护情况。

- .cpio文件为文件系统映像。将其解压可以获得服务器交互程序的客户端

- bzImage为kernel binary，可视为压缩后的文件

- vmlinux文件(if exists), 未经压缩的kernel文件，为ELF格式。

  - 如果没有vmlinux文件，可以通过*[extract-vmlinux](https://github.com/torvalds/linux/blob/master/scripts/extract-vmlinux)*提取

  - ```
    ./extract-vmlinux ./bzImage > vmlinux
    ```

## 基本操作

1. 获得服务器文件系统环境

   解压cpio文件，能够获得服务器内部文件分布，包括创建环境的init脚本和交互程序。

   **在inti文件中，通过insmod命令加载驱动模块 **

   ```
   insmod /lib/modules/4.4.72/babydriver.ko
   ```

   一般情况下，被加载的LKM即为漏洞所在。

   .ko文件也是ELF文件格式，可以通过ida进行分析。

   可以通过分析交互elf文件，确定交互逻辑和调用内核模块的？？

2. 提权

   最常用的提权手段：

   ```
   commit_creds(prepare_kernel_cred(0))
   ```

   两个函数的地址可以在 */proc/kallsyms*中查看。

   vmlinux是未压缩的kernel文件(ELF格式)，可以通过vmlinux提取到gadget，当然也可以从vmlinux文件中获取上面两个函数的地址。

3. loadling... 