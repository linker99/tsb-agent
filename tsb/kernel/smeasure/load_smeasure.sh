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

start_smeasure()
{
        POINT=`grep -w kallsyms_lookup_name $KALLSYMSMAP | awk '{print $1}'`
        if [ $POINT ]; then
           lookup_name=$DEX$POINT
        else
           POINT=`grep -w kallsyms_lookup_name $SYSMAP | awk '{print $1}'`
           lookup_name=$(calculate_address $POINT)
        fi

        POINT=`grep -w __flush_dcache_area $KALLSYMSMAP | awk '{print $1}'`
        if [ ! $POINT ]; then
            POINT=`grep -w __flush_dcache_area $SYSMAP | awk '{print $1}'`
            if [ $POINT ]; then
               f_d_a=$(calculate_address $POINT)
            fi
        else
            f_d_a=$DEX$POINT
        fi

        if [ ! $POINT ]; then
           POINT=`grep -w clflush_cache_range $KALLSYMSMAP | awk '{print $1}'`
           if [ ! $POINT ]; then
              POINT=`grep -w clflush_cache_range $SYSMAP | awk '{print $1}'`
              if [ $POINT ]; then
                 f_d_a=$(calculate_address $POINT)
              fi
           else
              f_d_a=$DEX$POINT
           fi
        fi

        if [ ! $f_d_a ];then
           /sbin/insmod ${INSTALL_PATH}/tsb/httcsmeasure.ko  k_kallsyms_lookup_name=$lookup_name
        else
           /sbin/insmod ${INSTALL_PATH}/tsb/httcsmeasure.ko k_flush_area=$f_d_a k_kallsyms_lookup_name=$lookup_name
        fi
}

start_smeasure
