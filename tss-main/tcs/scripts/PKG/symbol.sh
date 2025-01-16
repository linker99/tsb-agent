#!/bin/sh

version=`uname -r | awk -F . '{print $1}'`
patchlevel=`uname -r | awk -F . '{print $2}'`
sublevel=`uname -r | awk -F . '{print $3}'`

HEX=0x
VERSION=`uname -r`
SYSMAP=/proc/kallsyms

if [ -f $SYSMAP ];then
	POINT=`grep -w kallsyms_lookup_name $SYSMAP | awk '{print $1}'`
	kallsyms_lookup_name=$HEX$POINT
	POINT=`grep -w do_invalidatepage $SYSMAP | awk '{print $1}'`	
	do_invalidatepage=$HEX$POINT
else
    echo $SYSMAP is not exsit!
    exit 1
fi

export kallsyms_lookup_name do_invalidatepage

