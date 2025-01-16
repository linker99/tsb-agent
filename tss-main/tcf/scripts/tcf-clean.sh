
cur_dir=`pwd`

rm ./PKG -fr

cd ../../httcutils/ && make clean && cd -
cd ../ && make clean && cd -
cd ../test/ && make clean && cd - 
cd ../utils/ && make clean && cd -



rm tss* -rf
rm -rf readme
