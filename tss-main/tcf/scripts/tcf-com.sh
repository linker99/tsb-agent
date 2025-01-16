usage ()
{
	echo ""
   	echo " Usage: ./tcf-com.sh [debug|release] "
    echo "   e.g. ./tcf-com.sh  debug"
    echo "   e.g. ./tcf-com.sh  release"
	echo ""
}


if [ "$#" -lt 1 ]; then
	usage
	exit 0
fi





cur_dir=`pwd`
export UTILS_INCLUDE=$cur_dir/../../httcutils/include

run_cmd()
{
	$*
	if [ $? -ne 0 ]; then
		exit 1
	fi
}

cp ../../tcs/scripts/PKG . -frd

if [ ! $2 ]; then
	mkdir -p ./PKG/user/test/tcf
fi


mkdir -p ./PKG/user/test/tcf
mkdir -p ./PKG/user/utils/tcf
mkdir -p ./PKG/user/include


if [ $1 == release ]; then
	cd $cur_dir/../../httcutils/ && run_cmd make && cp libhttcutils.so $cur_dir/PKG/user/
	# TCF
	cd $cur_dir/../ && make mock && run_cmd make && cp libhttctcf.so libhttctsb.so $cur_dir/PKG/user/
	# TCF utils
	cd $cur_dir/../utils && run_cmd make
	util_bins=`ls | grep -v "\.c" | grep -v "\.o" | grep -v Makefile`
	cp $util_bins $cur_dir/PKG/user/utils/tcf/
elif [ $1 == debug ]; then
	cd $cur_dir/../../httcutils/ && run_cmd make && cp libhttcutils.so $cur_dir/PKG/user/
	# TCF
	cd $cur_dir/../ && make mock && run_cmd make HTTCUTILS_DEBUG=1 && cp libhttctcf.so libhttctsb.so $cur_dir/PKG/user/
	# TCF test
	mkdir -p $cur_dir/PKG/user/test/tcf/
	cd $cur_dir/../test/ && run_cmd make
	util_bins=`ls | grep -v "\.c" | grep -v "\.o" | grep -v Makefile`
	cp $util_bins $cur_dir/PKG/user/test/tcf/
	cp ../test/example.cfg $cur_dir/PKG/user/test/tcf/
	# TCF utils
	cd $cur_dir/../utils && run_cmd make HTTCUTILS_DEBUG=1
	util_bins=`ls | grep -v "\.c" | grep -v "\.o" | grep -v Makefile`
	cp $util_bins $cur_dir/PKG/user/utils/tcf/
fi

cd $cur_dir/
cp tcf-test.sh tcf-utils.sh ./PKG/

cd $cur_dir/../include && cp -frd tcfapi tcsapi tsbapi $cur_dir/PKG/user/include

((1))&&{
cd $cur_dir/
if [ -z $MACHINE ];then
	MACHINE=`uname -m`
fi
if [ -z $KERNEL ];then
	KERNEL=`uname -r`
fi
DATE=`date +%Y%m%d`
MAJOR=v1.0

if [ ! -d $cur_dir/../../tpcmdriver ];then
	TDD_VER='0'
fi


BUILD_FINGERPRINT=$MAJOR.$TDD_VER.$TCS_VER.$TCF_VER
PACKAGE_BEFORE=tss
PROGRAM=$1
PACKAGE_AFTER=tss-$PROGRAM-$KERNEL-$MACHINE-$BUILD_FINGERPRINT-$2
rm $PACKAGE_BEFORE -fr && cp PKG $PACKAGE_BEFORE -frd
cp change-log.md $PACKAGE_BEFORE
tar -zcvf $PACKAGE_AFTER.tar.gz $PACKAGE_BEFORE
}

