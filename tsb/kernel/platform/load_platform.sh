#!/bin/bash

OPT=$1
INSTALL_PATH=/usr/local/httcsec

version=`uname -r | awk -F . '{print $1}'`
patchlevel=`uname -r | awk -F . '{print $2}'`
sublevel=`uname -r | awk -F . '{print $3}'`
VERSION=`uname -r`
ARCH=`uname -m`
DEX=0x

KALLSYMSMAP=/proc/kallsyms
SYSMAP=/boot/System.map-$VERSION

sym_stext=`grep -w _stext $KALLSYMSMAP | awk '{print $1}'`
sys_stext=`grep -w _stext $SYSMAP | awk '{print $1}'`
offset=$(($DEX$sym_stext-$DEX$sys_stext))
offset=`printf "0x%x" $offset`

calculate_address()
{
   local address=$1
   if [ "$offset" != "0x0" ] && [ $address ]; then
      printf "%#x\n" $(($DEX$address+$offset))
   else
      if [ $address ]; then
         printf "%#x\n" $DEX$address
      fi
   fi
}

start_platform()
{
        POINT=`grep -w security_hook_heads $KALLSYMSMAP | awk '{print $1}'`
        if [ ! $POINT ]; then
           POINT=`grep -w security_hook_heads $SYSMAP | awk '{print $1}'`
           if [ $POINT ]; then
              hook_address=$(calculate_address $POINT)
           fi
        else
           hook_address=$DEX$POINT
        fi

        if [ ! $POINT ]; then
           POINT=`grep -w security_ops $KALLSYMSMAP | awk '{print $1}'`
           if [ ! $POINT ]; then
              POINT=`grep -w security_ops $SYSMAP | awk '{print $1}'`
              if [ $POINT ]; then
                 hook_address=$(calculate_address $POINT)
              fi
           else
              hook_address=$DEX$POINT
           fi
        fi

        #init_mm_addr
        POINT=`grep -w init_mm $KALLSYMSMAP | awk '{print $1}'`
        if [ $POINT ]; then
           init_mm_addr=$DEX$POINT
        else
           POINT=`grep -w init_mm $SYSMAP | awk '{print $1}'`
           init_mm_addr=$(calculate_address $POINT)
        fi

        #syscall
        POINT=`grep -w sys_call_table $KALLSYMSMAP | awk '{print $1}'`
        if [ $POINT ]; then
           syscall=$DEX$POINT
        else
           POINT=`grep -w sys_call_table $SYSMAP | awk '{print $1}'`
           syscall=$(calculate_address $POINT)
        fi

        #mount_lock
        POINT=`grep -w vfsmount_lock $KALLSYMSMAP | awk '{print $1}'`
        if [ ! $POINT ]; then
           POINT=`grep -w vfsmount_lock $SYSMAP | awk '{print $1}'`
           if [ $POINT ]; then
              mount_lock=$(calculate_address $POINT)
           fi
        else
            mount_lock=$DEX$POINT
        fi

        if [ ! $POINT ]; then
           POINT=`grep -w mount_lock $KALLSYMSMAP | awk '{print $1}'`
           if [ ! $POINT ]; then
              POINT=`grep -w mount_lock $SYSMAP | awk '{print $1}'`
              if [ $POINT ]; then
                 mount_lock=$(calculate_address $POINT)
              fi
           else
              mount_lock=$DEX$POINT
           fi
        fi

        /sbin/insmod ${INSTALL_PATH}/tsb/platform.ko syscall_table=$syscall mountlock=$mount_lock hook_security_address=$hook_address init_mm_address=$init_mm_addr
}

start_platform
