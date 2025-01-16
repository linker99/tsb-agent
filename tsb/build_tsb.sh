usage ()
{
	echo " 编译tsb代码白名单功能下发到可信根执行如下参数 : "
	echo " Usage:  ./build_tsb.sh "
	echo " 编译tsb代码白名单功能不下发到可信根执行如下参数 : "
	echo "   e.g.  ./build_tsb.sh enable_white_not_tpcm" 
}

usage
# if [ "$#" -lt 1 ]; then
#     usage
#     #exit 0
# else
# echo $1
# fi

# svnversion=`svn info | grep -w "最后修改的版本" | awk -F ': ' '{print $2}'`
# if [ ! $svnversion ];then
#     svnversion=`svn info | grep -w "Last Changed Rev" | awk -F ': ' '{print $2}'`
# fi


compile_options=""
dm_compile_options=""
date=`date +%Y%m%d`
sysinfo=`uname -r`
# tar_name="tsb-$sysinfo-$date-$svnversion.tar.gz"
tar_name="tsb-$sysinfo-$date.tar.gz"
echo $tar_name
#dir_name="tsb-$date-$svnversion"
dir_name="tsb"

#mkdir -p $dir_name/kernel
#mkdir -p $dir_name/user
mkdir -p $dir_name

cd kernel/
chmod a+x srv
cp srv ../$dir_name







cd platform/
make clean;make
chmod a+x *.sh
cp *.sh platform.ko Module.symvers ../../$dir_name


cd ../smeasure
   
set_compile_options() {  
    local option  
    for option in "$@"; do  
        case $option in 
            "enable_white_not_tpcm")  
                compile_options+=" WHITE_NOT_TPCM=1"  
                ;;  
            *)  
                echo "null option: $option"   
                ;;  
        esac  
    done  
}  
    
if [ "$#" -gt 0 ]; then  
    set_compile_options "$@"  
fi  
   
make_cmd="make clean; make $compile_options"  
echo "***********************Running command: $make_cmd**********************************************"  
eval "$make_cmd"


chmod a+x *.sh
cp *.sh httcsmeasure.ko Module.symvers  ../../$dir_name

cd ../dmeasure
make_cmd="make clean;make $dm_compile_options"
echo "*************************dm_duild_command: $make_cmd*********************************************"
eval "$make_cmd"
chmod a+x *.sh
cp *.sh httcdmeasure.ko ../../$dir_name

cd ../accessctl
make clean;make
chmod a+x *.sh
cp *.sh httcfac.ko ../../$dir_name

#cd ../udisk
#make clean;make
#chmod a+x *.sh
#cp *.sh httcudisk.ko ../../$dir_name

#cd ../firewall
#make clean;make
#chmod a+x *.sh
#cp *.sh httcnet.ko ../../$dir_name

#cd ../earlywhitelist
#make clean;make
#cp httcearly.ko ../../$dir_name

cd ../../user
make clean;make
cp libhttctsb.so ../$dir_name
cp measuredisk ../$dir_name

cd ..
tar zcvf $tar_name $dir_name
