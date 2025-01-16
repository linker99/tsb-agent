#!/bin/sh

#SYSMAP=/boot/System.map-$VERSION
SYSMAP=/proc/kallsyms

POINT=`grep -w init_mm $SYSMAP | awk '{print $1}'`
init_mm_addr=0x$POINT
/sbin/insmod httc_module.ko init_mm_address=$init_mm_addr
