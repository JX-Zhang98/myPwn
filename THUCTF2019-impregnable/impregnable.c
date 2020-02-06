#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sched.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <seccomp.h>
#include <linux/seccomp.h>
#include <openssl/md5.h>
#include <sys/resource.h>


int main(int argc, char **argv)
{
    MD5_CTX ctx;
    char md5_res[17]="";
    char key[100]="";
    char sandbox_dir[100]="/home/ctf/sandbox/";
    char dir_name[100]="/home/ctf/sandbox/";

    char buf[0x11111] ,ch;
    FILE *pp;
    int i;
    int pid, fd;

    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    struct rlimit r;

    r.rlim_max = r.rlim_cur = 0;
    setrlimit(RLIMIT_CORE, &r);

    memset(key, 0, sizeof(key));
    printf("input your key:\n");
    read(0, key, 20);
    MD5_Init(&ctx);
    MD5_Update(&ctx, key, strlen(key));
    MD5_Final(md5_res, &ctx);
     for(int i = 0; i < 16; i++)
        sprintf(&(dir_name[i*2 + 18]), "%02hhx", md5_res[i]&0xff);

    printf("dir : %s\n", dir_name);
    printf("So, what's your command, sir?\n");

    for (i=0;i<0x11100;i++)
    {
        read(0, &ch, 1);
        if (ch=='\n' || ch==EOF)
        {
            break;
        }
        buf[i] = ch;
    }

    pid = syscall(__NR_clone, CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUSER | CLONE_FILES | CLONE_NEWUTS | CLONE_NEWNET,
     0, 0, 0, 0);
    if (pid) 
    {//father
        if (open(sandbox_dir, O_RDONLY) == -1)
        {
            perror("fail to open sandbox dir");
            exit(1);
        }

        if (open(dir_name, O_RDONLY) != -1)
        {
        	printf("Entering your dir\n");
            if (chdir(dir_name)==-1)
            {
                puts("chdir err, exiting\n");
                exit(1);
            }
        }
        else
        {
           	printf("Creating your dir\n");
            mkdir(dir_name, 0755);
            printf("Entering your dir\n");
            if (chdir(dir_name)==-1)
            {
                puts("chdir err, exiting\n");
                exit(1);
            }
            mkdir("bin", 0777);
            mkdir("lib", 0777);
            mkdir("lib64", 0777);
            mkdir("lib/x86_64-linux-gnu", 0777);
            system("cp /bin/bash bin/sh");
            system("cp /bin/chmod bin/");
            system("cp /usr/bin/tee bin/");
            system("cp /lib/x86_64-linux-gnu/libtinfo.so.5 lib/x86_64-linux-gnu/");
            system("cp /lib/x86_64-linux-gnu/libtinfo.so.6 lib/x86_64-linux-gnu/");
            system("cp /lib/x86_64-linux-gnu/libdl.so.2 lib/x86_64-linux-gnu/");
            system("cp /lib/x86_64-linux-gnu/libc.so.6 lib/x86_64-linux-gnu/");
            system("cp /lib64/ld-linux-x86-64.so.2 lib64/");
        }

        char uidmap[] = "0 1000 1", filename[30];
        char pid_string[7];
        sprintf(pid_string, "%d", pid);

        sprintf(filename, "/proc/%s/uid_map", pid_string);
        fd = open(filename, O_WRONLY|O_CREAT);
        if (write(fd, uidmap, sizeof(uidmap)) == -1)
        {
            printf("write to uid_map Error!\n");
            printf("errno=%d\n",errno);
        }
        exit(0);
    }
    sleep(1);

    // entering sandbox
    if (chdir(dir_name)==-1)
    {
        puts("chdir err, exiting\n");
        exit(1);
    }

    if (chroot(".") == -1)
    {
        puts("chroot err, exiting\n");
        exit(1);
    }
    scmp_filter_ctx sec_ctx;
    sec_ctx = seccomp_init(SCMP_ACT_ALLOW);
    seccomp_rule_add(sec_ctx, SCMP_ACT_KILL, SCMP_SYS(mkdir), 0);
    seccomp_rule_add(sec_ctx, SCMP_ACT_KILL, SCMP_SYS(link), 0);
    seccomp_rule_add(sec_ctx, SCMP_ACT_KILL, SCMP_SYS(symlink), 0);
    seccomp_rule_add(sec_ctx, SCMP_ACT_KILL, SCMP_SYS(unshare), 0);
    seccomp_rule_add(sec_ctx, SCMP_ACT_KILL, SCMP_SYS(prctl), 0);
    seccomp_rule_add(sec_ctx, SCMP_ACT_KILL, SCMP_SYS(chroot), 0);
    seccomp_rule_add(sec_ctx, SCMP_ACT_KILL, SCMP_SYS(seccomp), 0);
    seccomp_load(sec_ctx);

    pp = popen(buf, "w");
    if (pp == NULL)
        exit(0);
    pclose(pp);
    return 0;
}
