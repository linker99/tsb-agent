#!/bin/sh

DEX=0x
SYMDIR=/proc/kallsyms
if [ -f $SYMDIR ];then
		# net #
		POINT=`grep -w net_families $SYMDIR | awk '{print $1}'`
		net_families=$DEX$POINT
		POINT=`grep -w proto_list $SYMDIR | awk '{print $1}'`
		proto_list=$DEX$POINT
		POINT=`grep -w proto_list_mutex $SYMDIR | awk '{print $1}'`
		proto_list_lock=$DEX$POINT
		POINT=`grep -w net_family_lock $SYMDIR | awk '{print $1}'`
		net_family_lock=$DEX$POINT
		POINT=`grep -w init_mm $SYMDIR | awk '{print $1}'`
		init_mm_addr=$DEX$POINT
		/sbin/insmod httc_net.ko netfamilies=$net_families protolist=$proto_list protolistmutex=$proto_list_lock netfamilieslock=$net_family_lock init_mm_address=$init_mm_addr

        exit 0
else
        echo $$SYMDIR is not exsit!
        exit 1
fi
