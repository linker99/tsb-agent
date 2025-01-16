cur_dir=`pwd`
export TCF_INCLUDE=$cur_dir/../../tcf/include
export UTILS_INCLUDE=$cur_dir/../../httcutils/include

if [ -d $cur_dir/PKG/kernel/ ];then
	rm $cur_dir/PKG/kernel/ -fr
fi
if [ -d $cur_dir/PKG/user/ ];then
	rm $cur_dir/PKG/user/ -fr
fi

mkdir -p $cur_dir/PKG/kernel/
mkdir -p $cur_dir/PKG/kernel/test/
mkdir -p $cur_dir/PKG/kernel/test/tcs/
mkdir -p $cur_dir/PKG/user/
mkdir -p $cur_dir/PKG/user/utils/
mkdir -p $cur_dir/PKG/user/utils/tcs/
mkdir -p $cur_dir/PKG/user/test/
mkdir -p $cur_dir/PKG/user/test/tcm/
mkdir -p $cur_dir/PKG/user/test/tcs/
mkdir -p $cur_dir/PKG/user/tcm-lib/lib/
mkdir -p $cur_dir/PKG/user/tcm-lib/inc/crypto/sm/

CORE_NUM=`getconf _NPROCESSORS_ONLN`

run_cmd()
{
	$*
	if [ $? -ne 0 ]; then
		exit 1
	fi
}



# TDD
cd $cur_dir/../../tcs/tdd/
run_cmd make TDD_DEBUG=1 -j $CORE_NUM
cp httctdd.ko $cur_dir/PKG/kernel/
# TDDL
cd $cur_dir/../tddl
run_cmd make HTTCUTILS_DEBUG=1 -j $CORE_NUM
cp tddl.ko $cur_dir/PKG/kernel/
# TCSK
cd $cur_dir/../tcsapi/tcsk
run_cmd make HTTCUTILS_DEBUG=1 $EXTRA_FLAGS -j $CORE_NUM
cp httctcs.ko $cur_dir/PKG/kernel/
cp Module.symvers $cur_dir/PKG/kernel/tcsModule.symvers
# TCSK TEST
cd $cur_dir/../tcsapi/test/tcsk/
run_cmd make HTTCUTILS_DEBUG=1 $EXTRA_FLAGS -j $CORE_NUM
cp *.ko $cur_dir/PKG/kernel/test/tcs/
# TCSK-EX
cd $cur_dir/../tcsapi/tcsk/expend/
run_cmd make HTTCUTILS_DEBUG=1 $EXTRA_FLAGS -j $CORE_NUM
cp httctcs-ex.ko $cur_dir/PKG/kernel/
if grep -q "tdd_get_phys_addr" Module.symvers; then
    cp Module.symvers $cur_dir/PKG/kernel/tcsexModule.symvers
else
    files=("$cur_dir/../tdd/Module.symvers" "$cur_dir/../tddl/Module.symvers" "$cur_dir/../tcsapi/tcsk/Module.symvers" "$cur_dir/../tcsapi/tcsk/expend/Module.symvers")
    for file in "${files[@]}"; do
        if [ ! -f "$file" ]; then
            echo "文件 $file 不存在"
            exit 1
        fi
    done
    cat "${files[@]}" > tcsexModule.symvers
    cp tcsexModule.symvers $cur_dir/PKG/kernel/tcsexModule.symvers
fi
# TCSK-TCM TEST
cd $cur_dir/../tcsapi/test/tcsk/expend
run_cmd make HTTCUTILS_DEBUG=1 $EXTRA_FLAGS -j $CORE_NUM
cp *.ko $cur_dir/PKG/kernel/test/tcs/
#httcutils
cd $cur_dir/../../httcutils/
run_cmd make -j $CORE_NUM
cp libhttcutils.so $cur_dir/PKG/user/
# TCM
cd $cur_dir/../tcm
run_cmd ./autogen
if [ $FIX_AUTOCONFIG ]; then
rm -rf config.sub config.guess
	run_cmd wget -O config.guess 'http://git.savannah.gnu.org/gitweb/?p=config.git;a=blob_plain;f=config.guess;hb=HEAD'
	run_cmd wget -O config.sub 'http://git.savannah.gnu.org/gitweb/?p=config.git;a=blob_plain;f=config.sub;hb=HEAD'
	chmod +x config.sub config.guess
fi
ecflags=-fPIC -I$TCF_INCLUDE  -I$UTIL_INCLUDE
./configure --enable-shared CFLAGS=$ecflags --host=$HOST CC=$cc
run_cmd make -j $CORE_NUM
# tcm lib
cd $cur_dir/../tcm/lib/
cp oiaposap.h tcm_constants.h tcmfunc.h tcm.h tcmkeys.h tcm_structures.h tcm_types.h tcmutil.h $cur_dir/PKG/user/tcm-lib/inc/
cp ./crypto/sm/*.h $cur_dir/PKG/user/tcm-lib/inc/crypto/sm/
cp ./.libs/libtcm.so* $cur_dir/PKG/user/tcm-lib/lib/ -frd
# tcm utils
cd $cur_dir/../tcm/utils/
util_bins=`ls | grep -v "\.c" | grep -v "\.o"| grep -v Makefile | grep -v modules`
cp $util_bins $cur_dir/PKG/user/test/tcm/
cp -rf $cur_dir/../tcm/utils/test_* $cur_dir/PKG/user/test/tcm/
rm -rf $cur_dir/PKG/user/test/tcm/*.c $cur_dir/PKG/user/test/tcm/*.o
# TCSU
cd $cur_dir/../tcsapi/tcsu/
run_cmd make mock HTTCUTILS_DEBUG=1 -j $CORE_NUM
run_cmd make HTTCUTILS_DEBUG=1 -j $CORE_NUM
cp libhttc*.so $cur_dir/PKG/user/
cp libhttc*.so $cur_dir/../../tcf/
# TCSU TEST
cd $cur_dir/../tcsapi/test/tcsu/
run_cmd make -j $CORE_NUM
util_bins=`ls | grep -v "\.c" | grep -v "\.o" | grep -v Makefile`
cp $util_bins $cur_dir/PKG/user/test/tcs/
#TCSU SM234
cd $cur_dir/../tcsapi/test/tcsu/sm/src
run_cmd make -j $CORE_NUM
util_bins=`ls | grep -v "\.c" | grep -v "\.o" | grep -v Makefile`
cp $util_bins $cur_dir/PKG/user/test/tcs/
# TCSU UTILS
cd $cur_dir/../tcsapi/utils/tcsu/
run_cmd make -j $CORE_NUM
util_bins=`ls | grep -v "\.c" | grep -v "\.o" | grep -v Makefile`
cp $util_bins $cur_dir/PKG/user/utils/tcs/
cd $cur_dir
cp -f $cur_dir/PKG/srv.bak $cur_dir/PKG/srv
echo "insmod ./kernel/httctdd.ko httcsec_messsage_prot=29" > $cur_dir/PKG/install.sh
sed -i 's/httctdd.ko/httctdd.ko httcsec_messsage_prot=29/g' $cur_dir/PKG/srv
echo "simulator_exec=\`ps -A | grep tpcmsimulator\`" >> $cur_dir/PKG/install.sh
echo "if [ -z \"\$simulator_exec\" ]; then" >> $cur_dir/PKG/install.sh
echo "    echo \"Before insmod httctcs.ko, Please make sure [tpcmsimulator] is running!!!\"" >> $cur_dir/PKG/install.sh
echo "    exit 0" >> $cur_dir/PKG/install.sh
echo "fi" >> $cur_dir/PKG/install.sh
echo "insmod ./kernel/tddl.ko sync=0" >> $cur_dir/PKG/install.sh
echo "source ./symbol.sh" >> $cur_dir/PKG/install.sh
echo "insmod ./kernel/httctcs.ko k_kallsyms_lookup_name=\$kallsyms_lookup_name k_do_invalidatepage=\$do_invalidatepage" >> $cur_dir/PKG/install.sh
if [ -f $cur_dir/../tcsapi/tcsk/expend/httctcs-ex.ko ]; then
	echo "insmod ./kernel/httctcs-ex.ko" >> $cur_dir/PKG/install.sh
fi
echo "chmod 666 /dev/tpcm_ttd /dev/tcm_ttd /dev/httctcs" >> $cur_dir/PKG/install.sh
echo "if [ ! -d /usr/local/httcsec/lib/ ]; then" >> $cur_dir/PKG/install.sh
echo "	mkdir -p /usr/local/httcsec/lib/" >> $cur_dir/PKG/install.sh
echo "fi" >> $cur_dir/PKG/install.sh
echo "cp ./user/lib* /usr/local/httcsec/lib/ -frd" >> $cur_dir/PKG/install.sh
echo "cp ./user/tcm-lib/lib/* /usr/local/httcsec/lib/ -frd" >> $cur_dir/PKG/install.sh
echo "rm /usr/local/httcsec/lib/ -fr" > $cur_dir/PKG/uninstall.sh
echo "rm /etc/ld.so.conf.d/httc.conf -fr" >> $cur_dir/PKG/uninstall.sh
if [ -f $cur_dir/../tcsapi/tcsk/expend/httctcs-ex.ko ]; then
	echo "rmmod httctcs-ex" >> $cur_dir/PKG/uninstall.sh
fi
echo "rmmod httctcs" >> $cur_dir/PKG/uninstall.sh
echo "rmmod tddl" >> $cur_dir/PKG/uninstall.sh
echo "rmmod httctdd" >> $cur_dir/PKG/uninstall.sh
chmod +x $cur_dir/PKG/install.sh $cur_dir/PKG/uninstall.sh



