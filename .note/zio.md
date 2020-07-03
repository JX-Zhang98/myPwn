# About zio

[zio](https://github.com/zTrix/zio)是一个较为简单的io库，能够在没有pwntools的环境下，在服务器上实现简单的读写操作。

如在hackaday2018中的TryMe问题，给出了ssh服务器的ip和地址，但是没有挂上去暴露端口，所以需要把脚本放到服务器上进行“本地”执行。但是服务器上没有pwntools环境，可以将zio.py上传上去，实现简单的交互。

## functions

| pwntools          | zio                         |
| ----------------- | --------------------------- |
| from pwn import * | from zio import *           |
| process('./file') | zio('./file arg1 arg2 ...') |
| remote(ip, port)  | zio(ip, port)               |
| recv()       (4)  | read()          (4)         |
| recvline()        | readline()                  |
| recvuntil()       | read _until()               |
| send()            | write()                     |
| sendline()        | writeline()                 |
| p32(); u64()      | l32()                       |
| p32();p64()       | l64()                       |
| interactive()     | interact()                  |

## 通过服务器上传、下载——scp

### 上传本地文件到服务器

scp /path/filename username@servername:/path/

for example :

> scp -P 2222 inputpwn.c input@pwnable.kr:/tmp

### 下载指定服务器上的文件到本地

scp -r -P port username@servername:/path/filename /path/

> scp -r -P 2222 uaf@pwnable.kr:/home/uaf/uaf ./