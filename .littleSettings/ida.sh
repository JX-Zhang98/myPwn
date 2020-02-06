#!/usr/bin/env bash
# set -eux 

elf=$1
checksec $elf 2>/dev/null
if [[ $(file $elf) =~ "ELF 64-bit" ]]
then
    /media/jx/Everything/Application/IDA/ida64.exe $elf>/dev/null 2>&1 &
elif [[ $(file $elf) =~ "ELF 32-bit" ]]
then
    /media/jx/Everything/Application/IDA/ida.exe $elf>/dev/null 2>&1 &
elif [[ $(file $elf) =~ "PE32" ]]
then
    /media/jx/Everything/Application/IDA/ida.exe $elf>/dev/null 2>&1 &
else
    echo "wrong file format"
fi
