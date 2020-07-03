在使用gdb调试程序的时候,需要根据函数名定位或者绝对的指令地址下断点,以便程序运行到该位置后暂停,  
但是有的题目开启PIE地址随机化保护的同时去掉了符号表,使得对程序定位较为困难.  
以下为解决方法:  
1.在/proc 目录中，每个进程都会在此目录下新建一个以进程id为名的文件夹，其中存储着进程的动态链接和地址的信息。  
在每个进程的*map_file*文件夹中，存储着各个地址段的动态链接文件  
![](https://images2018.cnblogs.com/blog/1251324/201808/1251324-20180801165727808-1217539099.png)
其中第一个文件即为elf基址，可据之与ida中获得的指令地址后三位确定其具体地址，实现下断点分析。  
2./usr/bin目录下pmap程序。*pmap + pid*命令可以将该进程的地址信息和相应地址段的权限打印出  
![](https://images2018.cnblogs.com/blog/1251324/201808/1251324-20180801170210783-515869395.png)  
第一行即为elf代码的地址信息。
在python程序中可通过  
<code>base = int(os.popen("pmap {}| awk '{{print $1}}'".format(io.pid)).readlines()[1], 16)</code>  
获取该进程的elf基址，从而调用gdb并下断点进行调试。  

    def DEBUG(bps = [], pie = False):
        cmd = "set follow-fork-mode parent\n"
        if pie:
            base = int(os.popen("pmap {}| awk '{{print $1}}'".format(io.pid)).readlines()[1], 16)
            cmd += ''.join(['b *{:#x}\n'.format(b + base) for b in bps])
        else:
            cmd += ''.join(['b *{:#x}\n'.format(b) for b in bps])
        if bps != []:
            cmd += "c"
        gdb.attach(io, cmd)
