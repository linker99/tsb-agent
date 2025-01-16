#!/bin/sh

DEX=0x
SYMDIR=/proc/kallsyms
VERSION=`uname -r`
if [ -f $SYMDIR ];then

		# filesystems #
		POINT=`grep -w file_systems $SYMDIR | awk '{print $1}'`
		file_systems=$DEX$POINT
		POINT=`grep -w file_systems_lock $SYMDIR | awk '{print $1}'`
		file_systems_lock=$DEX$POINT
		POINT=`grep -w super_blocks $SYMDIR | awk '{print $1}'`
		super_blocks=$DEX$POINT
		POINT=`grep -w sb_lock $SYMDIR | awk '{print $1}'`
		sb_lock=$DEX$POINT
		/sbin/insmod httc_filesystem.ko filesystems=$file_systems filesystemslock=$file_systems_lock superblocks=$super_blocks sblock=$sb_lock

    exit 0
else
    echo $$SYMDIR is not exsit!
    exit 1
fi
