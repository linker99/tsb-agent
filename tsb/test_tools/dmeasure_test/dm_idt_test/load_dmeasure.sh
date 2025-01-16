#!/bin/bash

DEX=0x
SYMDIR=/proc/kallsyms
#VERSION=`uname -r`
#if [ -f /boot/System.map-$VERSION ];then
if [ -f $SYMDIR ];then
		# idt #
		#POINT=`grep -w idt_table /boot/System.map-$VERSION | awk '{print $1}'`
		#idt=$DEX$POINT
		/sbin/insmod httc_idt.ko

        exit 0
else
        echo $/boot/System.map-$VERSION is not exsit!
        exit 1
fi
