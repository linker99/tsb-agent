
cur_dir=`pwd`

cd $cur_dir/../tdd && make clean
cd $cur_dir/../tddl && make clean
cd $cur_dir/../tcsapi/tcsk && make clean
cd $cur_dir/../tcsapi/test/tcsk && make clean
cd $cur_dir/../tcsapi/tcsk/expend && make clean
cd $cur_dir/../tcsapi/test/tcsk/expend && make clean

cd $cur_dir/../tcm && make clean && make distclean
cd $cur_dir/../tcm && rm -rf install-sh depcomp mkinstalldirs missing config.* Makefile.in aclocal.m4 autom4te.cache compile configure lib/Makefile.in ltmain.sh m4 utils/Makefile.in 
cd $cur_dir/../tcsapi/tcsu && make clean
cd $cur_dir/../tcsapi/test/tcsu && make clean
cd $cur_dir/../tcsapi/test/tcsu/sm/src && make clean
cd $cur_dir/../tcsapi/utils/tcsu && make clean
cd $cur_dir/../../httcutils && make clean
cd $cur_dir/../common/kernel/memtest/ && make clean

rm -fr $cur_dir/PKG/kernel
rm -fr $cur_dir/PKG/user
rm -fr $cur_dir/PKG/install.sh
rm -fr $cur_dir/PKG/uninstall.sh
rm -fr $cur_dir/tcs-*
rm -fr $cur_dir/tcs
rm -fr $cur_dir/PKG/srv
