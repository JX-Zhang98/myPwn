#!/bin/bash

stty intr ^]
cd `dirname $0`
timeout --foreground 600 qemu-system-x86_64 \
    -m 128M \
    -nographic \
    -kernel bzImage \
    -append 'console=ttyS0 root=/dev/ram rdinit=/sbin/init loglevel=3 oops=panic panic=1 nokaslr' \
    -monitor /dev/null \
    -initrd ./initramfs.cpio \
    -smp cores=1,threads=1 \
    -cpu qemu64 2>/dev/null \
