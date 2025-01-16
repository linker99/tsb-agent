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

start_dmeasure()
{
        #section#
        POINT=`grep -w _stext $KALLSYMSMAP | awk '{print $1}'`
        stext=$DEX$POINT
        stext=`printf "0x%x" $stext`
        POINT=`grep -w _etext $KALLSYMSMAP | awk '{print $1}'`
        etext=$DEX$POINT
        etext=`printf "0x%x" $etext`

        POINT=`grep -w lookup_symbol_name $KALLSYMSMAP | awk '{print $1}'`
        if [ $POINT ]; then
            sname=$DEX$POINT
        else
            POINT=`grep -w lookup_symbol_name $SYSMAP | awk '{print $1}'`
            sname=$(calculate_address $POINT)
        fi

        #syscall#
        POINT=`grep -w sys_call_table $KALLSYMSMAP | awk '{print $1}'`
        if [ $POINT ]; then
            syscall=$DEX$POINT
        else
            POINT=`grep -w sys_call_table $SYSMAP | awk '{print $1}'`
            syscall=$(calculate_address $POINT)
        fi

        # idt #
        POINT=`grep -w idt_table $KALLSYMSMAP | awk '{print $1}'`
        if [ $POINT ]; then
            idt=$DEX$POINT
        else
            POINT=`grep -w idt_table $SYSMAP | awk '{print $1}'`
            idt=$(calculate_address $POINT)
        fi

        #modules#
        POINT=`grep -w modules $KALLSYMSMAP | awk '{print $1}'`
        if [ $POINT ]; then
            modules=$DEX$POINT
        else
            POINT=`grep -w modules $SYSMAP | awk '{print $1}'`
            modules=$(calculate_address $POINT)
        fi

        #task#
        POINT=`grep -w tasklist_lock $KALLSYMSMAP | awk '{print $1}'`
        if [ $POINT ]; then
            tskllock=$DEX$POINT
        else
            POINT=`grep -w tasklist_lock $SYSMAP | awk '{print $1}'`
            tskllock=$(calculate_address $POINT)
        fi

        #net#
        POINT=`grep -w net_families $KALLSYMSMAP | awk '{print $1}'`
        if [ $POINT ]; then
            net_families=$DEX$POINT
        else
            POINT=`grep -w net_families $SYSMAP | awk '{print $1}'`
            net_families=$(calculate_address $POINT)
        fi

        POINT=`grep -w proto_list $KALLSYMSMAP | awk '{print $1}'`
        if [ $POINT ]; then
            proto_list=$DEX$POINT
        else
            POINT=`grep -w proto_list $SYSMAP | awk '{print $1}'`
            proto_list=$(calculate_address $POINT)
        fi

        #filesystems#
        POINT=`grep -w file_systems $KALLSYMSMAP | awk '{print $1}'`
        if [ $POINT ]; then
            file_systems=$DEX$POINT
        else
            POINT=`grep -w file_systems $SYSMAP | awk '{print $1}'`
            file_systems=$(calculate_address $POINT)
        fi

        POINT=`grep -w super_blocks $KALLSYMSMAP | awk '{print $1}'`
        if [ $POINT ]; then
            super_blocks=$DEX$POINT
        else
            POINT=`grep -w super_blocks $SYSMAP | awk '{print $1}'`
            super_blocks=$(calculate_address $POINT)
        fi

        POINT=`grep -w sb_lock $KALLSYMSMAP | awk '{print $1}'`
        if [ $POINT ]; then
            sb_lock=$DEX$POINT
        else
            POINT=`grep -w sb_lock $SYSMAP | awk '{print $1}'`
            sb_lock=$(calculate_address $POINT)
        fi
        
          POINT=`grep -w kallsyms_lookup_name $KALLSYMSMAP | awk '{print $1}'`
        if [ $POINT ]; then
            t_lookup_name=$DEX$POINT
            echo "k_lookup_name:$k_lookup_name"
        else
            POINT=`grep -w kallsyms_lookup_name  $SYSMAP | awk '{print $1}'`
            t_lookup_name=$(calculate_address $POINT)
        fi

        if [ $ARCH = 'x86_64' ]; then
                # dmeasure all #
                /sbin/insmod ${INSTALL_PATH}/tsb/httcdmeasure.ko \
                 start_text=$stext end_text=$etext t_lookup_symbol_name=$sname k_lookup_symbol_name=$sname \
                 syscall_table=$syscall \
                 idt_addr=$idt \
                 modules_addr=$modules \
                 filesystems=$file_systems superblocks=$super_blocks sblock=$sb_lock \
                 netfamilies=$net_families protolist=$proto_list \
                 tasklistlock=$tskllock
        else
                # dmeasure all #
                /sbin/insmod ${INSTALL_PATH}/tsb/httcdmeasure.ko \
                 start_text=$stext end_text=$etext t_lookup_symbol_name=$sname t_kallsyms_lookup_name=$t_lookup_name \
                 syscall_table=$syscall \
                 modules_addr=$modules \
                 filesystems=$file_systems superblocks=$super_blocks sblock=$sb_lock \
                 netfamilies=$net_families protolist=$proto_list \
                 tasklistlock=$tskllock
        fi
}

start_dmeasure
