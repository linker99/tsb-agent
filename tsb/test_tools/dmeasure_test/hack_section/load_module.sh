#!/bin/sh

DEX=0x
SYMDIR=/proc/kallsyms
if [ -f $SYMDIR ];then
		# section #
		POINT=`grep -w kmsg_dump $SYMDIR | awk '{print $1}'`
		kgdb_notify=$DEX$POINT
		/sbin/insmod hack_section.ko kgdb_notify_addr=$kgdb_notify

        exit 0
else
        echo $$SYMDIR is not exsit!
        exit 1
fi
