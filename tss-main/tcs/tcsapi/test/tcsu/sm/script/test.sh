#!/bin/sh

export LD_LIBRARY_PATH=`pwd`/lib/:$LD_LIBRARY_PATH

bin_dir=`pwd`/bin

load_module ()
{
	insmod `pwd`/module/httctdd.ko
	insmod `pwd`/module/tddl.ko
	insmod `pwd`/module/tpcm_measure.ko
}

unload_module ()
{
	rmmod tpcm_measure
	rmmod tddl
	rmmod httctdd
}

tcm_configure ()
{
	$bin_dir/tcminit;
	$bin_dir/tcmbios;
	$bin_dir/physicalpresence -x 0x0020;
	$bin_dir/physicalpresence -x 0x0008;
	$bin_dir/physicalenable;
	$bin_dir/physicalsetdeactivated -c;
	$bin_dir/tcminit;
	$bin_dir/tcmbios;
	$bin_dir/physicalpresence -x 0x0020;
	$bin_dir/physicalpresence -x 0x0008;
	$bin_dir/createrevek  -pwdk $EK;
	$bin_dir/takeown -pwdo $PSW -pwds $PSW;
}

sm2_speed_test()
{
	$bin_dir/sm2_speed -t 100     # 100 times	
	$bin_dir/sm2_speed -t 200     # 200 times	
	$bin_dir/sm2_speed -t 500     # 500 times	
}

sm3_speed_test()
{
	$bin_dir/sm3_speed -s 0x100000 -t 20    # 1MB * 20 times
	$bin_dir/sm3_speed -s 0x400000 -t 20    # 4MB * 20 times
	$bin_dir/sm3_speed -s 0x800000 -t 20    # 8MB * 20 times
}

sm4_speed_test()
{
	$bin_dir/sm4_speed -s 0x100000 -t 20    # 1MB * 20 times
	$bin_dir/sm4_speed -s 0x400000 -t 20    # 4MB * 20 times
	$bin_dir/sm4_speed -s 0x800000 -t 20    # 8MB * 20 times
}

cert_wr_test()
{
	echo "Cert write: 1234567890"
	$bin_dir/cert_write -p abc -c 1234567890
	$bin_dir/cert_read -p abc
}

auth_test()
{
	echo "cert_write - Auth: abc"
	$bin_dir/cert_write -p abc -c 1234567890
	echo "cert read - Auth: 123"
	$bin_dir/cert_read -p 123
	echo "cert read - Auth: abc"
	$bin_dir/cert_read -p abc
}

main()
{
	echo ""
	echo "设备初始化中，请等待。。。"
	load_module
	./bin/configure -ek 1234567812345678123456781234567812345678123456781234567812345678 -pwdo 123 -pwds 123
	echo "设备初始化完毕，准备测试！"
	echo ""
	echo "SM2速率测试 ..."
	sm2_speed_test
	echo ""
	echo "SM3速率测试 ..."
	sm3_speed_test
	echo ""
	echo "SM4速率测试 ..."
	sm4_speed_test
	echo ""
	echo "证书读写测试 ..."
	cert_wr_test
	echo ""
	echo "口令权限测试 ..."
	auth_test
	echo ""
	echo "测试完毕！"
	echo ""
	unload_module
}

main

