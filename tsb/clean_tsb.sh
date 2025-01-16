svnversion=`svn info | grep -w "最后修改的版本" | awk -F ': ' '{print $2}'`
if [ ! $svnversion ];then
    svnversion=`svn info | grep -w "Last Changed Rev" | awk -F ': ' '{print $2}'`
fi
date=`date +%Y%m%d`

rm -rf $dir_name

cd kernel/
rm -rf encryption/sm3/.sm3.o.cmd

cd httc_file_capture/file_capture/
make clean
cd ../../



cd platform/
make clean

cd ../smeasure
make clean

cd ../dmeasure
make clean

cd ../accessctl
make clean

cd ../udisk
make clean

cd ../firewall
make clean

cd ../earlywhitelist
make clean

cd ../../user
make clean

