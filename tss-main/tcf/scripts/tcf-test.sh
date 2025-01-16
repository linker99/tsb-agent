#!/bin/sh

OWNER_PWD="12345678"
ROOT_CERT_ID="root-cert"
GRANT_CERT_ID="grant-cert"
BMEASURE_UID="bmeasure-uid"
FILE_INTEGRITY_UID="file-integrity-uid"
DMEASURE_UID="dmeasure-uid"
GLOBAL_POLICY_UID="global-uid"
PROCESS_UID="process-uid"
PTRACE_PROTECT_UID="ptrace-protect-uid"
ADMIN_POLICY_NAME="tpcmpolicy"
FILE_PROTECT_UID="file-protect-uid"
TNC_UID="tnc-uid"
NETWORK_CONTROL_UID="network-control-uid"


ROOT_PRIVKEY=60FFA139866D596A8E107C76F3B92BB32422ED302701FA6865B86CC82DAAFC2C
ROOT_PUBKEY=09AA298AE0D2FF1A541C4CB02AF80D0C118F427A2623C5DB2D08A151D873CA99FD76A2F4BD9FA0D6FDB52BDE2124DB29B2B170E570A6E1BEE41138608F04750A
ROOT_PUBKEY_SIGN=6D9054788B55B8FA3FA22B25426597565887BCE8805C7B52E057C44B2AE712EF5E3610B360D09FE40694DFA510758AA06FF24EE9263F972E2FA7A4383E4EAA14

BMEASURE_PRIVKEY=7763B74ABFE5A83913D2825F57480A0B4302D3B6D2708D154C8BFE33035F44F8
BMEASURE_PUBKEY=EAE077B81E7BA0137DB3B36DC233DDDA015042F565C1665D94E6DABD9342A8534A2E731D9080512FB42813785A990C54A2E325279472A32B126B56E9A7532256

FILE_INTEGRITY_PRIVKEY=7638BA4A2C4E2C54D89A89D90C77E3EA71D83686B45B29265A26F99483F90AA9
FILE_INTEGRITY_PUBKEY=AEE3CAA6F0C75EEE048B6B6185BBA8C86FCA692A1750DAC49659E5FD5634407CD04979A36887BBF9B05CA0108D08329595AE0441BD5FA8E886AC07423E30B8FB

DMEASURE_PRIVKEY=42A2FCDE242A5BF2A394C380A6287ACB2159248B25D7E7E79BD7949F5C8E8961
DMEASURE_PUBKEY=5817014DEEF6364BD737A1AE84B518BEFD1838783EF4A5DDFB90D4FBF066792BED2115D7EAF9DAD7E261D6F8EEAD5EF5662A5F39513D1CE9A67DF849989EB1B9

GRANT_PRIVKEY=D002BE1DEC5920EC12CAF733C538F404C5F37DF61E1CEDD27CD0DB5355DC3AB1
GRANT_PUBKEY=91702F742E015CA47C636CCF1DEFC28DC4A32A7AF7025D6640704B727C993BAEDCFD250DB274E467F1AC472FD69412A9144BF5C6861BA28955A362E4FED5532F

GLOBAL_POLICY_PRIVKEY=3ED465DB745136370E4C96D095DB27BE051D30DA88CDD85C66BD1D674E3E3381
GLOBAL_POLICY_PUBKEY=01D5D4932C7661784136A8850C4593765031D0B9ED97C14785259D7E0D9E950E6C872364B60DEF1FAE907F0DD399D1913622F11ABEA4B22462BE286AE910F543

PROCESS_PRIVKEY=515F5ECB857D7324C328D71D5FE364C426E82C903430C226BCD5134A19A91EFA
PROCESS_PUBKEY=32A594C64DE88CF3D64EFB54B3E4BB8AA4936C70D0EFC7901760488B448A6A054A0067926F141C86A790BF135BDD3B9DAD86343FE7168FD621082A5BFDBDE26F

PTRACE_PROTECT_PRIVKEY=B6927FF84F955C16E7A1C3324A117D5A22CD41303728AEF7005E6408B00D1882
PTRACE_PROTECT_PUBKEY=5B2E0C1409BB563B7D2283DD58CBE71C2A41F3CB5A2D98876E985F12F02219D62574175550746C4796FE6DAECD4BBF0FF72341B0C7579C81BD9AE849D415138F

TNC_PRIVKEY=F8F31E47021CF11606C635C382B0E9B89A8F6D32DCB53BA081167B6B913BF74A
TNC_PUBKEY=5801AA80146AFA5875D3737813107720024157717A3E347C1BC44EC9B232637149687E56673310E69E5F70879C08B37BA3BD777069C919D551801A11C4B55E49

FILE_PROTECT_PRIVKEY=396D6C567AC5B374C93980893C532F4123195B9D19B927B0A69B5D81745C1C3E
FILE_PROTECT_PUBKEY=8D19F78081B017AF0E6E52198FDCD334F651265CEE28F300ABC3FE6D668BD1987E79916EACEE2BCF74C34ADE8F5A137C5E4F61CE30A362B8DDCD85FCF13A573A

error ()
{
	local msg; local logtype;
	logtype="ERROR"
	msg=$1
	datetime=`date +'%F %H:%M:%S'`
	logformat="[${logtype}]\t${datetime}\t${msg}"
	echo "${logformat}"
}

info ()
{
	local msg; local logtype;
	logtype="INFO"
	msg=$1
	datetime=`date +'%F %H:%M:%S'`
	logformat="[${logtype}]\t${datetime}\t${msg}"
	echo "${logformat}"
}

# 调用 get_license_info 程序获取输出信息
output=$(./user/test/tcf/get_license_info)

# 匹配版本号
version=$(echo "$output" | grep "version" | uniq | awk -F: '{print $2}' | sed 's/^ *//')
echo "$version"

err_handle ()
{
	echo "出错退出脚本之前执行重置操作，请稍后..."
	./user/test/tcs/reset_test_license
}

exec_check ()
{
	if [ ! $? -eq 0 ]; then
		error "$1 error!"
		#err_handle
		exit 1
	else
		info "$1 pass!"
	fi
}

right_check ()
{
	if [ $? -eq 0 ]; then
		error "$1 error!"
		#err_handle
		exit 1
	else
		info "$1 pass!"
	fi
}

imeasure=0;
dmeasure=0;
feature_check ()
{
	./user/test/tcs/get_tpcm_features | grep "imeasure:YES"
	imeasure=$?
	./user/test/tcs/get_tpcm_features | grep "dmeasure:YES"
	dmeasure=$?
}

im_dir=/usr/bin

intercept_measure_test ()
{
	echo ">>> intercept_measure_test <<<"

	echo "设置根证书"
	./user/test/tcs/auth -n $ROOT_CERT_ID -c 1 -d $ROOT_PUBKEY -o 0 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_set_admin_cert"
	echo "设置二级证书"
	./user/test/tcs/auth -n $FILE_INTEGRITY_UID -c 1 -d $FILE_INTEGRITY_PUBKEY -o 1 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_grant_admin_role"
	echo "设置全局策略 开启拦截控制"
	./user/test/tcs/global_control_policy -a 1 -o 0 -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY -p 5 -v 1; exec_check "tcs_set_global_control_policy"
	echo "更新文件完整性基准库"
	./user/test/tcf/update_file_integrity -o 0 -F 0x1 -n 900 -d $im_dir -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "update_file_integrity"

	all=`find $im_dir`
	for file in $all
	do
    	valid=`ls -l $file | grep "\-r..r..r.."`
    	if [ -z "$valid" ]; then
        	echo " " Skipe $file ...
        	continue
    	fi

    	if [ "$file" = "$im_dir" ];then
        	echo " " Skipe $file ...
        	continue;
    	fi

    	if [ -d "$file" ];then
        	echo " " Dir $file ...
        	continue;
    	fi

	if [ ! -x "$file" ];then
        	echo " " Skipe $file ...
        	continue;
    	fi

    	bytes=`ls $file -l | awk  '{print $5}'`
    	if [ "$bytes" = "0" ];then
        	echo " " Skipe $file ...
        	continue;
    	fi

    	echo " " Intercept measure $file ...
    	insmod ./kernel/test/tcs/intercept_measure.ko imname=$file imtype=1;
    	if [ ! $? -eq 0 ]; then
       		echo "   " NO PASS
        	error "intercept_measure.ko error"
        	exit 1
    	else
        	echo "   " PASS
    	fi
    	rmmod intercept_measure
	done
	./user/test/tcs/auth -n $FILE_INTEGRITY_UID -c 1 -d $FILE_INTEGRITY_PUBKEY -o 2 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_remove_admin_role"
}


simple_intercept_measure_test ()
{
	feature_check
	echo ">>> simple_intercept_measure_test <<<"
	echo "设置根证书"
	./user/test/tcs/auth -n $ROOT_CERT_ID -c 1 -d $ROOT_PUBKEY -o 0 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_set_admin_cert"
	echo "设置二级证书"
	./user/test/tcs/auth -n $FILE_INTEGRITY_UID -c 1 -d $FILE_INTEGRITY_PUBKEY -o 1 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_grant_admin_role"
	echo "设置默认全局策略"
	./user/test/tcf/tcf_global_control_policy -a 1 -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "tcf_global_control_policy"
	echo "扫描白名单"
	./user/test/tcf/update_file_integrity -o 0 -F 0x1 -n 900 -d $im_dir -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "update_file_integrity"

	all=`find $im_dir`
	for file in $all
	do
    	valid=`ls -l $file | grep "\-r.xr..r.."`
    	if [ -z "$valid" ]; then
        	echo " " Skipe $file ...
        	continue
    	fi

    	if [ "$file" = "$im_dir" ];then
        	echo " " Skipe $file ...
        	continue;
    	fi

    	if [ -d "$file" ];then
        	echo " " Dir $file ...
        	continue;
    	fi

    	bytes=`ls $file -l | awk  '{print $5}'`
    	if [ "$bytes" = "0" ];then
        	echo " " Skipe $file ...
        	continue;
    	fi

    	echo " " Simple intercept measure $file ...
    	insmod ./kernel/test/tcs/simple_intercept_measure.ko imname=$file imtype=1;
		if [ ! $? -eq 0 ]; then
       		echo "   " NO PASS
        	error "simple_intercept_measure.ko error"
        	exit 1
    	else
        	echo "   " PASS
    	fi
		rmmod simple_intercept_measure
	done

	./user/test/tcs/auth -n $FILE_INTEGRITY_UID -c 1 -d $FILE_INTEGRITY_PUBKEY -o 2 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_remove_admin_role"
}

global_policy_test ()
{
	echo ">>> global_policy_test <<<"
	echo "测试设置默认全局控制策略"
	./user/test/tcs/tcs_init $OWNER_PWD
	./user/test/tcs/generate_tpcm_pik $OWNER_PWD; exec_check "generate_tpcm_pik"
	./user/test/tcf/tcf_auth -n $GLOBAL_POLICY_UID -c 1 -d $GLOBAL_POLICY_PUBKEY -o 1 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_grant_admin_role"
	### 设置全局控制策略
	./user/test/tcf/tcf_global_control_policy -a 1 -k $GLOBAL_POLICY_PRIVKEY$GLOBAL_POLICY_PUBKEY -u $GLOBAL_POLICY_UID; exec_check "tcf_global_control_policy"
	### 获取全局控制策略
	./user/test/tcs/global_control_policy -o 1; exec_check "tcs_get_global_control_policy"

	echo "测试设置全局控制策略，策略防重放关闭"
	### 设置全局控制策略  policy_replay_check check
	./user/test/tcf/tcf_global_control_policy -a 1 -k $GLOBAL_POLICY_PRIVKEY$GLOBAL_POLICY_PUBKEY -u $GLOBAL_POLICY_UID -p 6 -v 1; exec_check "tcf_global_control_policy [policy_replay_check NOT]"
	./user/test/tcs/global_control_policy -o 1; exec_check "tcs_get_global_control_policy [policy_replay_check NOT]"
	./user/test/tcf/tcf_global_control_policy -a 1 -k $GLOBAL_POLICY_PRIVKEY$GLOBAL_POLICY_PUBKEY -u $GLOBAL_POLICY_UID; exec_check "tcf_global_control_policy"
	./user/test/tcs/global_control_policy -o 1; exec_check "tcs_get_global_control_policy"
	echo "测试获取策略报告"
	### 获取策略报告
	./user/test/tcs/global_control_policy -o 2; exec_check "tcs_get_policy_report"
	./user/test/tcf/tcf_auth -n $GLOBAL_POLICY_UID -c 1 -d $GLOBAL_POLICY_PUBKEY -o 2 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_remove_admin_role"
}

boot_measure_test ()
{
	echo ">>> boot_measure_test <<<"

	echo "设置根证书"
	./user/test/tcs/auth -n $ROOT_CERT_ID -c 1 -d $ROOT_PUBKEY -o 0 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_set_admin_cert"
	echo "设置二级证书"
	./user/test/tcs/auth -n $BMEASURE_UID -c 1 -d $BMEASURE_PUBKEY -o 1 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_grant_admin_role"

	echo "设置默认全局策略"
	./user/test/tcf/tcf_global_control_policy -a 1 -u $BMEASURE_UID -k $BMEASURE_PRIVKEY$BMEASURE_PUBKEY; exec_check "tcf_global_control_policy"
	echo "打开启动度量开关"
	./user/test/tcf/tcf_global_control_policy -a 1 -p 1 -v 1 -u $BMEASURE_UID -k $BMEASURE_PRIVKEY$BMEASURE_PUBKEY; exec_check "tcf_global_control_policy"
	echo "打开启动度量控制开关"
	./user/test/tcf/tcf_global_control_policy -a 1 -p 4 -v 1 -u $BMEASURE_UID -k $BMEASURE_PRIVKEY$BMEASURE_PUBKEY; exec_check "tcf_global_control_policy"

	echo "获取启动度量记录"
	./user/test/tcf/get_bmeasure_records; exec_check "get_bmeasure_records"
	echo "获取启动度量基准值"
	./user/test/tcf/get_bmeasure_references; exec_check "get_bmeasure_references"

	echo "设置管理认证策略，无需证书认证"
	./user/test/tcs/admin_auth_policy -o 0 -i 1 -a 1 -f 0x20 -u 0 -c 1 -k $ROOT_PRIVKEY$ROOT_PUBKEY -n $ADMIN_POLICY_NAME; exec_check "tcs_set_admin_auth_policies"
	echo "根证书认证，不指定证书，携带认证参数"
	./user/test/tcf/update_bmeasure_references -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "update_bmeasure_references"
	echo "根证书认证，指定证书，携带认证参数"
	./user/test/tcf/update_bmeasure_references -u $ROOT_CERT_ID -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "update_bmeasure_references"
	echo "根证书认证，指定证书，不携带认证参数"
	./user/test/tcf/update_bmeasure_references -u $ROOT_CERT_ID; exec_check "update_bmeasure_references"
	echo "根证书认证，不指定证书，不携带认证参数"
	./user/test/tcf/update_bmeasure_references; exec_check "update_bmeasure_references"
	echo "二级证书认证，不指定证书，携带认证参数"
	./user/test/tcf/update_bmeasure_references -k $BMEASURE_PRIVKEY$BMEASURE_PUBKEY; exec_check "update_bmeasure_references"
	echo "二级证书认证，指定证书，不携带认证参数"
	./user/test/tcf/update_bmeasure_references -u $BMEASURE_UID; exec_check "update_bmeasure_references"

	echo "设置管理认证策略，需证书认证"
	./user/test/tcs/admin_auth_policy -o 0 -i 1 -a 0 -f 0x20 -u 0 -c 1 -k $ROOT_PRIVKEY$ROOT_PUBKEY -n $ADMIN_POLICY_NAME; exec_check "tcs_set_admin_auth_policies"
	echo "根证书认证，不指定证书，携带认证参数"
	./user/test/tcf/update_bmeasure_references -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "update_bmeasure_references"
	echo "根证书认证，指定证书，携带认证参数"
	./user/test/tcf/update_bmeasure_references -u $ROOT_CERT_ID -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "update_bmeasure_references"
	echo "根证书认证，指定证书，不携带认证参数"
	./user/test/tcf/update_bmeasure_references -u $ROOT_CERT_ID; right_check "update_bmeasure_references"
	echo "根证书认证，不指定证书，不携带认证参数"
	./user/test/tcf/update_bmeasure_references; right_check "update_bmeasure_references"
	echo "二级证书认证，不指定证书，携带认证参数"
	./user/test/tcf/update_bmeasure_references -k $BMEASURE_PRIVKEY$BMEASURE_PUBKEY; right_check "update_bmeasure_references"
	echo "二级证书认证，指定证书，不携带认证参数"
	./user/test/tcf/update_bmeasure_references -u $BMEASURE_UID; right_check "update_bmeasure_references"

	echo "获取启动度量记录"
	./user/test/tcf/get_bmeasure_records; exec_check "get_bmeasure_records"
	echo "获取启动度量基准值"
	./user/test/tcf/get_bmeasure_references; exec_check "get_bmeasure_references"
	echo "更新启动度量基准值"
	./user/test/tcf/update_bmeasure_references -u $BMEASURE_UID -k $BMEASURE_PRIVKEY$BMEASURE_PUBKEY; exec_check "update_bmeasure_references"
	echo "获取启动度量基准值"
	./user/test/tcf/get_bmeasure_references; exec_check "get_bmeasure_references"

	#./user/test/tcf/update_bmeasure_references -m 1000 -u $BMEASURE_UID -k $BMEASURE_PRIVKEY$BMEASURE_PUBKEY; exec_check "update_bmeasure_references"
	#./user/test/tcs/get_bmeasure_references; exec_check "get_bmeasure_references"
	./user/test/tcs/auth -n $BMEASURE_UID -c 1 -d $BMEASURE_PUBKEY -o 2 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_remove_admin_role"
}

dynamic_measure_test ()
{
	echo ">>> dynamic_measure_test <<<"

	feature_check

	echo "设置根证书"
	./user/test/tcs/auth -n $ROOT_CERT_ID -c 1 -d $ROOT_PUBKEY -o 0 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_set_admin_cert"
	echo "设置二级证书"
	./user/test/tcs/auth -n $DMEASURE_UID -c 1 -d $DMEASURE_PUBKEY -o 1 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_grant_admin_role"

	echo "打开动态度量控制开关"
    ./user/test/tcs/global_control_policy -a 1 -o 0 -p 3 -v 1 -u $DMEASURE_UID -k $DMEASURE_PRIVKEY$DMEASURE_PUBKEY; exec_check "tcs_set_global_control_policy"

	echo "获取动态度量策略"
	./user/test/tcs/get_dmeasure_policy; exec_check "get_dmeasure_policy"

	echo "根证书认证，不指定证书，携带认证参数"
	./user/test/tcf/update_dmeasure_policy -n 3 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "update_dmeasure_policy"
	echo "根证书认证，指定证书，携带认证参数"
	./user/test/tcf/update_dmeasure_policy -n 3 -u $ROOT_CERT_ID -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "update_dmeasure_policy"
	echo "根证书认证，指定证书，不携带认证参数"
	./user/test/tcf/update_dmeasure_policy -n 3 -u $ROOT_CERT_ID; right_check "update_dmeasure_policy"
	echo "根证书认证，不指定证书，不携带认证参数"
	./user/test/tcf/update_dmeasure_policy -n 3 ; right_check "update_dmeasure_policy"
	echo "二级证书认证，不指定证书，携带认证参数"
	./user/test/tcf/update_dmeasure_policy -n 3 -k $DMEASURE_PRIVKEY$DMEASURE_PUBKEY; right_check "update_dmeasure_policy"
	echo "二级证书认证，指定证书，不携带认证参数"
	./user/test/tcf/update_dmeasure_policy -n 3 -u $DMEASURE_UID; right_check "update_dmeasure_policy"

	echo "获取动态度量策略"
	./user/test/tcf/get_dmeasure_policy; exec_check "get_dmeasure_policy"
	echo "清空动态度量策略"
	./user/test/tcf/update_dmeasure_policy -n 0 -u $DMEASURE_UID -k $DMEASURE_PRIVKEY$DMEASURE_PUBKEY; exec_check "update_dmeasure_policy"
	echo "获取动态度量策略"
	./user/test/tcf/get_dmeasure_policy; exec_check "get_dmeasure_policy"

	echo "下发动态度量策略"
	./user/test/tcf/update_dmeasure_policy -n 3 -u $DMEASURE_UID -k $DMEASURE_PRIVKEY$DMEASURE_PUBKEY; exec_check "update_dmeasure_policy"
	echo "获取动态度量策略"
	./user/test/tcf/get_dmeasure_policy; exec_check "get_dmeasure_policy"
	if [ $dmeasure -eq 0 ]; then
		echo "采集度量"
		insmod ./kernel/test/tcs/collect_measure.ko ; exec_check "collect_measure.ko"
		rmmod collect_measure
	fi
	### 删除syscall_table
	#./user/test/tcf/update_dmeasure_policy -o 2 -n syscall_table -d 10000 -u $DMEASURE_UID -k $DMEASURE_PRIVKEY$DMEASURE_PUBKEY; exec_check "update_dmeasure_policy"
	#./user/test/tcf/get_dmeasure_policy; exec_check "get_dmeasure_policy"

	### 清空动态度量策略
	#./user/test/tcf/update_dmeasure_policy -o 0 -n none -u $DMEASURE_UID -k $DMEASURE_PRIVKEY$DMEASURE_PUBKEY; exec_check "update_dmeasure_policy"
	#./user/test/tcf/get_dmeasure_policy; exec_check "get_dmeasure_policy"

	#./user/test/tcs/update_dmeasure_policy -o 0 -n tsb_test -d 10 -u $DMEASURE_UID -k $DMEASURE_PRIVKEY$DMEASURE_PUBKEY; exec_check "update_dmeasure_policy"
	#insmod ./kernel/test/tcs/collect_measure.ko dmname=tsb_test ; exec_check "collect_measure.ko"
	#rmmod collect_measure

	./user/test/tcs/auth -n $DMEASURE_UID -c 1 -d $DMEASURE_PUBKEY -o 2 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_remove_admin_role"
}

dynamic_measure_test_simple ()
{
	echo ">>> dynamic_measure_test_simple <<<"

	feature_check

	echo "设置根证书"
	./user/test/tcs/auth -n $ROOT_CERT_ID -c 1 -d $ROOT_PUBKEY -o 0 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_set_admin_cert"
	echo "设置二级证书"
	./user/test/tcs/auth -n $DMEASURE_UID -c 1 -d $DMEASURE_PUBKEY -o 1 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_grant_admin_role"

	echo "通过tcf获取动态度量策略"
	./user/test/tcf/get_dmeasure_policy; exec_check "get_dmeasure_policy"
	echo "通过tcf清空动态度量策略"
	./user/test/tcf/update_dmeasure_policy -n 0 -u $DMEASURE_UID -k $DMEASURE_PRIVKEY$DMEASURE_PUBKEY; exec_check "update_dmeasure_policy"
	echo "通过tcf获取动态度量策略"
	./user/test/tcf/get_dmeasure_policy; exec_check "get_dmeasure_policy"

	echo "通过tcs下发动态度量策略"
	./user/test/tcs/update_dmeasure_policy -d 2160000000 -n 3 -u $DMEASURE_UID -k $DMEASURE_PRIVKEY$DMEASURE_PUBKEY; exec_check "update_dmeasure_policy"
	echo "通过tcf获取动态度量策略"
	./user/test/tcf/get_dmeasure_policy; exec_check "get_dmeasure_policy"
	echo "通过tcs获取动态度量策略"
	./user/test/tcs/get_dmeasure_policy; exec_check "get_dmeasure_policy"

	./user/test/tcs/auth -n $DMEASURE_UID -c 1 -d $DMEASURE_PUBKEY -o 2 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_remove_admin_role"
}

process_dmeasure_test ()
{
	echo ">>> process_dmeasure_test <<<"

	echo "设置根证书"
	./user/test/tcs/auth -n $ROOT_CERT_ID -c 1 -d $ROOT_PUBKEY -o 0 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_set_admin_cert"
	echo "设置二级证书"
	./user/test/tcs/auth -n $DMEASURE_UID -c 1 -d $DMEASURE_PUBKEY -o 1 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_grant_admin_role"

	echo "根证书认证，不指定证书，携带认证参数"
	./user/test/tcf/update_dmeasure_process_policy -n 1 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "update_dmeasure_process_policy"
	echo "根证书认证，指定证书，携带认证参数"
	./user/test/tcf/update_dmeasure_process_policy -n 1 -u $ROOT_CERT_ID -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "update_dmeasure_process_policy"
	echo "根证书认证，指定证书，不携带认证参数"
	./user/test/tcf/update_dmeasure_process_policy -n 1 -u $ROOT_CERT_ID; right_check "update_dmeasure_process_policy"
	echo "根证书认证，不指定证书，不携带认证参数"
	./user/test/tcf/update_dmeasure_process_policy -n 1 ; right_check "update_dmeasure_process_policy"
	echo "二级证书认证，不指定证书，携带认证参数"
	./user/test/tcf/update_dmeasure_process_policy -n 1 -k $DMEASURE_PRIVKEY$DMEASURE_PUBKEY; right_check "update_dmeasure_process_policy"
	echo "二级证书认证，指定证书，不携带认证参数"
	./user/test/tcf/update_dmeasure_process_policy -n 1 -u $DMEASURE_UID; right_check "update_dmeasure_process_policy"

	echo "获取进程动态度量策略"
	./user/test/tcf/get_dmeasure_process_policy; exec_check "get_dmeasure_process_policy"
	echo "清空进程动态度量策略"
	./user/test/tcf/update_dmeasure_process_policy -n 0 -u $DMEASURE_UID -k $DMEASURE_PRIVKEY$DMEASURE_PUBKEY; exec_check "update_dmeasure_process_policy"
	echo "获取进程动态度量策略"
	./user/test/tcf/get_dmeasure_process_policy; exec_check "get_dmeasure_process_policy"
	echo "更新进程动态度量策略"
	./user/test/tcf/update_dmeasure_process_policy -n 3 -u $DMEASURE_UID -k $DMEASURE_PRIVKEY$DMEASURE_PUBKEY; exec_check "update_dmeasure_process_policy"
	echo "获取进程动态度量策略"
	./user/test/tcf/get_dmeasure_process_policy; exec_check "get_dmeasure_process_policy"
	echo "清空进程动态度量策略"
	./user/test/tcf/update_dmeasure_process_policy -n 0 -u $DMEASURE_UID -k $DMEASURE_PRIVKEY$DMEASURE_PUBKEY; exec_check "update_dmeasure_process_policy"
	echo "获取进程动态度量策略"
	./user/test/tcf/get_dmeasure_process_policy; exec_check "get_dmeasure_process_policy"
	./user/test/tcs/auth -n $DMEASURE_UID -c 1 -d $DMEASURE_PUBKEY -o 2 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_remove_admin_role"
}

ptrace_protect_test ()
{
	echo ">>> ptrace_protect_test <<<"

	echo "设置根证书"
	./user/test/tcs/auth -n $ROOT_CERT_ID -c 1 -d $ROOT_PUBKEY -o 0 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_set_admin_cert"
	echo "设置二级证书"
	./user/test/tcs/auth -n $PTRACE_PROTECT_UID -c 1 -d $PTRACE_PROTECT_PUBKEY -o 1 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_grant_admin_role"

	echo "获取进程跟踪防护策略"
	./user/test/tcf/get_ptrace_protect_policy; exec_check "get_ptrace_protect_policy"

	echo "根证书认证，不指定证书，携带认证参数"
	./user/test/tcf/update_ptrace_protect_policy -o 0 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "update_ptrace_protect_policy"
	echo "根证书认证，指定证书，携带认证参数"
	./user/test/tcf/update_ptrace_protect_policy -o 0 -u $ROOT_CERT_ID -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "update_ptrace_protect_policy"
	echo "根证书认证，指定证书，不携带认证参数"
	./user/test/tcf/update_ptrace_protect_policy -o 0 -u $ROOT_CERT_ID; right_check "update_ptrace_protect_policy"
	echo "根证书认证，不指定证书，不携带认证参数"
	./user/test/tcf/update_ptrace_protect_policy -o 0; right_check "update_ptrace_protect_policy"
	echo "二级证书认证，不指定证书，携带认证参数"
	./user/test/tcf/update_ptrace_protect_policy -o 0 -k $PTRACE_PROTECT_PRIVKEY$PTRACE_PROTECT_PUBKEY; right_check "update_ptrace_protect_policy"
	echo "二级证书认证，指定证书，不携带认证参数"
	./user/test/tcf/update_ptrace_protect_policy -o 0 -u $PTRACE_PROTECT_UID; right_check "update_ptrace_protect_policy"

	echo "获取进程跟踪防护策略"
	./user/test/tcf/get_ptrace_protect_policy; exec_check "get_ptrace_protect_policy"
	echo "清空进程跟踪防护策略"
	./user/test/tcf/update_ptrace_protect_policy -o 2 -u $PTRACE_PROTECT_UID -k $PTRACE_PROTECT_PRIVKEY$PTRACE_PROTECT_PUBKEY; exec_check "update_ptrace_protect_policy"
	echo "获取进程跟踪防护策略"
	./user/test/tcf/get_ptrace_protect_policy; exec_check "get_ptrace_protect_policy"
	echo "更新进程跟踪防护策略"
	./user/test/tcf/update_ptrace_protect_policy -o 0 -u $PTRACE_PROTECT_UID -k $PTRACE_PROTECT_PRIVKEY$PTRACE_PROTECT_PUBKEY; exec_check "update_ptrace_protect_policy"
	echo "获取进程跟踪防护策略"
	./user/test/tcf/get_ptrace_protect_policy; exec_check "get_ptrace_protect_policy"
	./user/test/tcs/auth -n $PTRACE_PROTECT_UID -c 1 -d $PTRACE_PROTECT_PUBKEY -o 2 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_remove_admin_role"
}

param2=$1
#weilei: 20231225, eg1:tcf-test.sh /usr/     eg2:tcf-test.sh /usr/bin/ls
file_integrity_test_limit ()
{
	# 获取第一个参数
	param1=$1

	# 获取第二个参数
	#param2=$2

	echo "param1:$param1"
	echo "param2:$param2"
	if [ $param1 -ge 0 ] && [ $param1 -le 3 ]; then
		feature_check
		echo ">>> file_integrity_test_limit <<<"
		echo "设置根证书"
		./user/test/tcs/auth -n $ROOT_CERT_ID -c 1 -d $ROOT_PUBKEY -o 0 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_set_admin_cert"
		echo "设置二级证书"
		./user/test/tcs/auth -n $FILE_INTEGRITY_UID -c 1 -d $FILE_INTEGRITY_PUBKEY -o 1 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_grant_admin_role"

		if [ -z "$param2" ]; then
			echo "要设置的白名单的目录不存在，请输入，eg:tcf-test.sh /usr/"
			exit 1
		else
			case $param1 in
				0)
					echo "更新白名单(set)："
					echo "$param2 文件夹下全部普通文件 加入白名单"
					./user/test/tcf/update_file_integrity -o $param1 -F 0x1 -n 900 -d $param2 -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "update_file_integrity"
					;;
				1)
					echo "更新白名单(add)："
					echo "$param2 文件夹下全部普通文件 加入白名单"
					./user/test/tcf/update_file_integrity -o $param1 -F 0x1 -n 900 -d $param2 -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "update_file_integrity"
					;;
				2)
					echo "更新白名单(del)：$param2"
					./user/test/tcf/update_file_integrity -o $param1 -F 0x01 -f $param2 -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "update_file_integrity"
					;;
				*)
					echo "Invalid argument"
					exit 1
					;;
			esac

		fi
	else
		echo "获取白名单(get)"
		./user/test/tcf/get_file_integrity; exec_check "get_file_integrity"

	fi

		echo "获取文件完整性库hash"
		./user/test/tcf/get_file_integrity_digest; exec_check "get_file_integrity_digest"
		echo "获取文件完整性基准库可更改条数限制"
		./user/test/tcf/get_file_integrity_modify_number_limit; exec_check "get_file_integrity_modify_number_limit"
		echo "获取文件完整性基准库总条数"
		./user/test/tcf/get_file_integrity_total_number; exec_check "get_file_integrity_total_number"
		echo "获取文件完整性基准库有效条数"
		./user/test/tcf/get_file_integrity_valid_number; exec_check "get_file_integrity_valid_number"
}

file_integrity_test ()
{
	feature_check
	echo ">>> file_integrity_test <<<"
	echo "设置根证书"
	./user/test/tcs/auth -n $ROOT_CERT_ID -c 1 -d $ROOT_PUBKEY -o 0 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_set_admin_cert"
	echo "设置二级证书"
	./user/test/tcs/auth -n $FILE_INTEGRITY_UID -c 1 -d $FILE_INTEGRITY_PUBKEY -o 1 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_grant_admin_role"

	echo "设置默认全局策略"
	./user/test/tcf/tcf_global_control_policy -a 1 -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "tcf_global_control_policy"
	#echo "打开文件完整性度量开关"
	#./user/test/tcf/tcf_global_control_policy -a 1 -p 2 -v 1 -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "tcf_global_control_policy"
	#echo "打开文件完整性度量控制开关"
	#./user/test/tcf/tcf_global_control_policy -a 1 -p 5 -v 1 -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "tcf_global_control_policy"

	echo "获取文件完整性基准库可更改条数限制"
	./user/test/tcf/get_file_integrity_modify_number_limit; exec_check "get_file_integrity_modify_number_limit"
	echo "获取文件完整性基准库总条数"
	./user/test/tcf/get_file_integrity_total_number; exec_check "get_file_integrity_total_number"
	echo "获取文件完整性基准库有效条数"
	./user/test/tcf/get_file_integrity_valid_number; exec_check "get_file_integrity_valid_number"

	echo "设置管理认证策略，无需证书认证，策略认证成功"
	./user/test/tcs/admin_auth_policy -o 0 -i 2 -a 1 -f 0x20 -u 0 -c 1 -n $ADMIN_POLICY_NAME -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_set_admin_auth_policies"
	echo "根证书认证，不指定证书，携带认证参数"
	./user/test/tcf/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "update_file_integrity"
	echo "根证书认证，指定证书，携带认证参数"
	./user/test/tcf/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls -u $ROOT_CERT_ID -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "update_file_integrity"
	echo "根证书认证，指定证书，不携带认证参数"
	./user/test/tcf/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls -u $ROOT_CERT_ID; exec_check "update_file_integrity"
	echo "根证书认证，不指定证书，不携带认证参数"
	./user/test/tcf/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls; exec_check "update_file_integrity"
	echo "二级证书认证，不指定证书，携带认证参数"
	./user/test/tcf/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "update_file_integrity"
	echo "二级证书认证，指定证书，不携带认证参数"
	./user/test/tcf/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls -u $FILE_INTEGRITY_UID; exec_check "update_file_integrity"

	echo "设置管理认证策略，需证书认证，策略认证成功"
	./user/test/tcs/admin_auth_policy -o 0 -i 2 -a 0 -f 0x20 -u 0 -c 1 -n $ADMIN_POLICY_NAME -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_set_admin_auth_policies"
	echo "根证书认证，不指定证书，携带认证参数"
	./user/test/tcf/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "update_file_integrity"
	echo "根证书认证，指定证书，携带认证参数"
	./user/test/tcf/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls -u $ROOT_CERT_ID -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "update_file_integrity"
	echo "根证书认证，指定证书，不携带认证参数"
	./user/test/tcf/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls -u $ROOT_CERT_ID; right_check "update_file_integrity"
	echo "根证书认证，不指定证书，不携带认证参数"
	./user/test/tcf/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls; right_check "update_file_integrity"
	echo "二级证书认证，不指定证书，携带认证参数"
	./user/test/tcf/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; right_check "update_file_integrity"
	echo "二级证书认证，指定证书，不携带认证参数"
	./user/test/tcf/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls -u $FILE_INTEGRITY_UID; right_check "update_file_integrity"


	./user/test/tcs/admin_auth_policy -o 0 -i 2 -a 1 -f 0x10 -u 0 -c 1 -n $ADMIN_POLICY_NAME -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_set_admin_auth_policies"
	echo "使能，不含扩展，全路径"
	./user/test/tcf/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "update_file_integrity"
	if [ $imeasure -eq 0 ]; then
	insmod ./kernel/test/tcs/intercept_measure.ko imname=/bin/ls imtype=1; exec_check "intercept_measure.ko"
	rmmod intercept_measure
	fi
	echo "使能，含扩展数据，路径HASH"
	./user/test/tcf/update_file_integrity -o 0 -e -p -F 0x1 -f /bin/ls -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "update_file_integrity"
	if [ $imeasure -eq 0 ]; then
	insmod ./kernel/test/tcs/intercept_measure.ko imname=/bin/ls imtype=1; exec_check "intercept_measure.ko"
	rmmod intercept_measure
	fi

	echo "使能，控制标记置位，全路径，匹配HASH+路径"
	./user/test/tcf/tcf_global_control_policy -a 1 -p 14 -v 1 -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "tcf_global_control_policy"
	./user/test/tcf/update_file_integrity -o 0 -p -F 0x07 -f /bin/ls -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "update_file_integrity"
	if [ $imeasure -eq 0 ]; then
	insmod ./kernel/test/tcs/intercept_measure.ko imname=/bin/ls imtype=1; exec_check "intercept_measure.ko"
	rmmod intercept_measure
	fi
	echo "切换文件路径，匹配CHECK"
	cp /bin/ls `pwd`/
	if [ $imeasure -eq 0 ]; then
	insmod ./kernel/test/tcs/intercept_measure.ko imname=`pwd`/ls imtype=1; right_check "intercept_measure.ko"
	rmmod intercept_measure
	fi
	rm `pwd`/ls -rf
	./user/test/tcf/tcf_global_control_policy -a 1 -p 14 -v 0 -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "tcf_global_control_policy"

	echo "禁用，不含扩展，全路径"
	./user/test/tcf/update_file_integrity -o 0 -p -F 0x4 -f /bin/ls -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "update_file_integrity"
	if [ $imeasure -eq 0 ]; then
	insmod ./kernel/test/tcs/intercept_measure.ko imname=/bin/ls imtype=1; exec_check "intercept_measure.ko"
	rmmod intercept_measure
	fi

	echo "测试追加"
	./user/test/tcf/update_file_integrity -o 0 -F 0x01 -f /bin/ls -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "update_file_integrity"
	./user/test/tcf/update_file_integrity -o 1 -l 20 -F 0x1 -d /usr/bin/ -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "update_file_integrity"
	./user/test/tcf/update_file_integrity -o 1 -F 0x01 -f /bin/bash -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "update_file_integrity"
	./user/test/tcf/get_file_integrity_total_number; exec_check "get_file_integrity_total_number"
	./user/test/tcf/get_file_integrity_valid_number; exec_check "get_file_integrity_valid_number"
	if [ $imeasure -eq 0 ]; then
	insmod ./kernel/test/tcs/intercept_measure.ko imname=/bin/bash imtype=1; exec_check "intercept_measure.ko"
	rmmod intercept_measure
	fi

	echo "测试修改"
	./user/test/tcf/update_file_integrity -o 3 -F 0x01 -f /bin/ls -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; right_check "update_file_integrity"
	./user/test/tcf/update_file_integrity -o 3 -F 0x01 -f /bin/bash -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; right_check "update_file_integrity"
	./user/test/tcf/get_file_integrity_total_number; exec_check "get_file_integrity_total_number"
	./user/test/tcf/get_file_integrity_valid_number; exec_check "get_file_integrity_valid_number"

	echo "测试删除"
	./user/test/tcf/update_file_integrity -o 2 -F 0x01 -f /bin/ls -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "update_file_integrity"
	./user/test/tcf/update_file_integrity -o 2 -F 0x01 -f /bin/bash -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "update_file_integrity"
	./user/test/tcf/get_file_integrity_total_number; exec_check "get_file_integrity_total_number"
	./user/test/tcf/get_file_integrity_valid_number; exec_check "get_file_integrity_valid_number"

	if [ $imeasure -eq 0 ]; then
	insmod ./kernel/test/tcs/intercept_measure.ko imname=/bin/ls imtype=1; right_check "intercept_measure.ko"
	rmmod intercept_measure
	insmod ./kernel/test/tcs/intercept_measure.ko imname=/bin/bash imtype=1; right_check "intercept_measure.ko"
	rmmod intercept_measure
	fi

	echo "获取文件完整性同步数据"
	./user/test/tcf/get_synchronized_file_integrity -M 0 -m 1024 -S 0 -s 3; exec_check "get_synchronized_file_integrity"

	echo "文件夹下全部普通文件"
	./user/test/tcf/update_file_integrity -o 0 -F 0x1 -n 900 -d $im_dir -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "update_file_integrity"

	echo "获取文件完整性库hash"
	./user/test/tcf/get_file_integrity_digest; exec_check "get_file_integrity_digest"
	./user/test/tcs/auth -n $FILE_INTEGRITY_UID -c 1 -d $FILE_INTEGRITY_PUBKEY -o 2 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_grant_admin_role"
}

critical_file_integrity_test ()
{
	echo ">>> critical_file_integrity_test <<<"
	echo "设置根证书"
	./user/test/tcs/auth -n $ROOT_CERT_ID -c 1 -d $ROOT_PUBKEY -o 0 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_set_admin_cert"
	echo "设置二级证书"
	./user/test/tcs/auth -n $FILE_INTEGRITY_UID -c 1 -d $FILE_INTEGRITY_PUBKEY -o 1 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_grant_admin_role"
	echo "设置默认全局策略"
	./user/test/tcf/tcf_global_control_policy -a 1 -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "tcf_global_control_policy"

	echo "读取关键文件完整性"
	./user/test/tcf/read_critical_file_integrity; exec_check "read_critical_file_integrity"

	echo "更新关键文件完整性"
	./user/test/tcf/update_critical_file_integrity -o 0 -p -F 0x4 -l 10 -d $im_dir -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "update_critical_file_integrity"
	echo "读取关键文件完整性"
	./user/test/tcf/read_critical_file_integrity; exec_check "read_critical_file_integrity"
	echo "用户态获取关键文件完整性基准库摘要值"
	./user/test/tcf/get_critical_file_integrity_digest; exec_check "get_critical_file_integrity_digest"

	echo "清空关键文件完整性"
	./user/test/tcf/update_critical_file_integrity -o 0 -p -F 0x4 -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "update_critical_file_integrity"
	echo "读取关键文件完整性"
	./user/test/tcf/read_critical_file_integrity; exec_check "read_critical_file_integrity"
	echo "用户态获取关键文件完整性基准库摘要值"
	./user/test/tcf/get_critical_file_integrity_digest; right_check "get_critical_file_integrity_digest"
	./user/test/tcs/auth -n $FILE_INTEGRITY_UID -c 1 -d $FILE_INTEGRITY_PUBKEY -o 2 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_remove_admin_role"
}

attest_test ()
{
	echo ">>> attest_test <<<"
	### 获得tpcm特征


	### 获得tpcm id


	### 获得可信状态


	### 生成tpcm身份密钥对


	### 获得tpcm身份密钥的公钥


	### 获得可信报告

	echo "获取策略同步信息"
	./user/test/tcf/get_policies_version; exec_check "get_policies_version"
	echo "获取指定策略同步信息"
	./user/test/tcf/get_one_policy_version -p 11; exec_check "get_one_policy_version"
	echo "HOST ID设置与获取"
	./user/test/tcf/host_id_set_and_get; exec_check "host_id_set_and_get"
}

maintain_test ()
{
	echo ">>> maintain_test <<<"
}

process_id_role_test ()
{
	echo ">>> process_id_role_test <<<"
	./user/test/tcs/tcs_init $OWNER_PWD
	./user/test/tcs/generate_tpcm_pik $OWNER_PWD; exec_check "generate_tpcm_pik"
	./user/test/tcf/tcf_auth -n $PROCESS_UID -c 1 -d $PROCESS_PUBKEY -o 1 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_grant_admin_role"

	echo "测试进程身份新增"
	./user/test/tcf/tcf_process -c 1 -k $PROCESS_PRIVKEY$PROCESS_PUBKEY -u $PROCESS_UID -n process_test -N 1 -o 0 -t 0; exec_check "tcf_prepare_update_process_identity"
	### 更新进程身份
	./user/test/tcf/tcf_process -c 1 -k $PROCESS_PRIVKEY$PROCESS_PUBKEY -u $PROCESS_UID -n process_test -N 1 -o 1 -t 0; exec_check "tcf_update_process_identity [set]"
	### 更新进程身份
	./user/test/tcf/tcf_process -c 1 -k $PROCESS_PRIVKEY$PROCESS_PUBKEY -u $PROCESS_UID -n one -N 1 -o 1 -t 1; right_check "tcf_update_process_identity [add]"
	### 读取全部进程身份
	./user/test/tcf/tcf_process -o 2; exec_check "tcf_get_process_ids"
	### 根据名字读取进程身份
	./user/test/tcf/tcf_process -o 3 -n process_test; exec_check "tcf_get_process_id"

	echo "测试进程身份删除"
	### 更新进程身份
	./user/test/tcf/tcf_process -c 1 -k $PROCESS_PRIVKEY$PROCESS_PUBKEY -u $PROCESS_UID -n one -N 1 -o 1 -t 2; right_check "tcf_update_process_identity [replace]"
	### 更新进程身份
	./user/test/tcf/tcf_process -c 1 -k $PROCESS_PRIVKEY$PROCESS_PUBKEY -u $PROCESS_UID -n one -N 1 -o 1 -t 3; right_check "tcf_update_process_identity [delete]"
	./user/test/tcf/tcf_process -o 2; exec_check "tcf_get_process_ids"

	echo "测试进程身份设置"
	./user/test/tcf/tcf_process -c 1 -k $PROCESS_PRIVKEY$PROCESS_PUBKEY -u $PROCESS_UID -N 10 -n one two tree four five six seven eight nine ten -o 1 -t 0; exec_check "tcf_update_process_identity [set]"
	./user/test/tcf/tcf_process -o 2; exec_check "tcf_get_process_ids"


	echo "测试进程角色新增"
	./user/test/tcf/tcf_process -c 1 -k $PROCESS_PRIVKEY$PROCESS_PUBKEY -u $PROCESS_UID -n role_test -N 1 -o 4 -t 0; exec_check "tcf_prepare_update_process_roles"
	### 更新进程角色库
	./user/test/tcf/tcf_process -c 1 -k $PROCESS_PRIVKEY$PROCESS_PUBKEY -u $PROCESS_UID -n role_test -N 1 -o 5 -t 0; exec_check "tcf_update_process_roles [set]"
	### 更新进程角色库
	./user/test/tcf/tcf_process -c 1 -k $PROCESS_PRIVKEY$PROCESS_PUBKEY -u $PROCESS_UID -n role-one -N 1 -o 5 -t 1; right_check "tcf_update_process_roles [add]"
	### 读取全部进程角色
	./user/test/tcf/tcf_process -o 6; exec_check "tcf_get_process_roles"
	### 根据名字读取进程角色
	./user/test/tcf/tcf_process -o 7 -n role-one; exec_check "tcf_get_process_role"

	echo "测试进程角色删除"
	### 更新进程角色库
	./user/test/tcf/tcf_process -c 1 -k $PROCESS_PRIVKEY$PROCESS_PUBKEY -u $PROCESS_UID -n role-one -N 1 -o 5 -t 2; right_check "tcf_update_process_roles [replace]"
	### 更新进程角色库
	./user/test/tcf/tcf_process -c 1 -k $PROCESS_PRIVKEY$PROCESS_PUBKEY -u $PROCESS_UID -n role-one -N 1 -o 5 -t 3; right_check "tcf_update_process_roles [delete]"
	./user/test/tcf/tcf_process -o 6; exec_check "tcf_get_process_roles"

	echo "测试进程角色设置"
	./user/test/tcf/tcf_process -c 1 -k $PROCESS_PRIVKEY$PROCESS_PUBKEY -u $PROCESS_UID -N 10 -n one two tree four five six seven eight nine ten -o 5 -t 0; exec_check "tcf_update_process_roles [set]"
	./user/test/tcf/tcf_process -o 6; exec_check "tcf_get_process_roles"
	./user/test/tcf/tcf_auth -n $PROCESS_UID -c 1 -d $PROCESS_PUBKEY -o 2 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_remove_admin_role"
}

admin_auth_test ()
{
	echo ">>> admin_auth_test <<<"
	echo "测试设置根证书和二级证书"
	### 设置根证书
	./user/test/tcf/tcf_auth -n $ROOT_CERT_ID -c 1 -d $ROOT_PUBKEY -o 0 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_set_admin_cert"
	### 设置二级证书
	./user/test/tcf/tcf_auth -n $GRANT_CERT_ID -c 1 -d $GRANT_PUBKEY -o 1 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_grant_admin_role"
	### 读取证书列表
	./user/test/tcf/tcf_auth -o 3; exec_check "tcf_get_admin_list"

	echo "测试删除根证书，期望删除失败"
	./user/test/tcf/tcf_auth -n $ROOT_CERT_ID -c 1 -d $ROOT_PUBKEY -o 2 -k $ROOT_PRIVKEY$ROOT_PUBKEY; right_check "tcs_remove_admin_role"
	./user/test/tcf/tcf_auth -o 3; exec_check "tcf_get_admin_list"

	echo "测试删除二级证书"
	./user/test/tcf/tcf_auth -n $GRANT_CERT_ID -c 1 -d $GRANT_PUBKEY -o 2 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_remove_admin_role"
	./user/test/tcf/tcf_auth -o 3; exec_check "tcf_get_admin_list"
}


tsb_test()
{
	### 设置二级证书
	./user/test/tcf/tcf_auth -n $BMEASURE_UID -c 1 -d $BMEASURE_PUBKEY -o 1 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcf_grant_admin_role"
	./user/test/tcf/tcf_auth -n $PROCESS_UID -c 1 -d $PROCESS_PUBKEY -o 1 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_grant_admin_role"

	echo "设置默认全局策略"
	./user/test/tcf/tcf_global_control_policy -a 1 -o 0 -u $BMEASURE_UID -k $BMEASURE_PRIVKEY$BMEASURE_PUBKEY; exec_check "tcf_set_global_control_policy"
	echo "打开启动度量开关"
	./user/test/tcf/tcf_global_control_policy -a 1 -o 0 -p 1 -v 1 -u $BMEASURE_UID -k $BMEASURE_PRIVKEY$BMEASURE_PUBKEY; exec_check "tcf_set_global_control_policy"
	echo "打开启动度量控制开关"
	./user/test/tcf/tcf_global_control_policy -a 1 -o 0 -p 4 -v 1 -u $BMEASURE_UID -k $BMEASURE_PRIVKEY$BMEASURE_PUBKEY; exec_check "tcf_set_global_control_policy"


	echo ">>> process <<<"
	echo "设置管理认证策略 进程身份"
	./user/test/tcs/admin_auth_policy -o 0 -t 0 -i 1 -a 1 -f 0x28 -c 1 -n member -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_set_admin_auth_policies"
	./user/test/tcs/admin_auth_policy -o 1; exec_check "tcs_get_admin_auth_policies"

	echo "进程身份更新"
	./user/test/tcf/tcf_process -c 1 -k $PROCESS_PRIVKEY$PROCESS_PUBKEY -u $PROCESS_UID -n member -o 1 -t 1; right_check "tcf_update_process_identity [add]"
	./user/test/tcf/tcf_process -o 2; exec_check "tcs_get_process_ids"

	echo "更新启动度量基准值"
	./user/test/tcs/update_bmeasure_references -u $BMEASURE_UID -k $BMEASURE_PRIVKEY$BMEASURE_PUBKEY; exec_check "update_bmeasure_references"

	echo "设置管理认证策略 进程角色"
	./user/test/tcs/admin_auth_policy -o 0 -t 0 -i 1 -a 1 -f 0x30 -c 1 -n tsb-role -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_set_admin_auth_policies"
	./user/test/tcs/admin_auth_policy -o 1; exec_check "tcs_get_admin_auth_policies"

	echo "进程角色设置"
	./user/test/tcf/tcf_process -c 1 -k $PROCESS_PRIVKEY$PROCESS_PUBKEY -u $PROCESS_UID -n tsb-role -o 5 -t 1; right_check "tcf_update_process_roles [add]"
	./user/test/tcf/tcf_process -o 6; exec_check "tcs_get_process_roles"

	echo "更新启动度量基准值"
	./user/test/tcs/update_bmeasure_references -u $BMEASURE_UID -k $BMEASURE_PRIVKEY$BMEASURE_PUBKEY; exec_check "update_bmeasure_references"
	./user/test/tcf/tcf_auth -n $PROCESS_UID -c 1 -d $PROCESS_PUBKEY -o 2 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_remove_admin_role"
}

tnc_test ()
{
	echo ">>> tnc_test <<<"
	./user/test/tcs/tcs_init $OWNER_PWD
	./user/test/tcs/generate_tpcm_pik $OWNER_PWD; exec_check "generate_tpcm_pik"

	echo "设置根证书"
	./user/test/tcs/auth -n $ROOT_CERT_ID -c 1 -d $ROOT_PUBKEY -o 0 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_set_admin_cert"
	echo "设置二级证书"
	./user/test/tcs/auth -n $TNC_UID -c 1 -d $TNC_PUBKEY -o 1 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_grant_admin_role"

	echo "设置可信链接策略"
	./user/test/tcf/update_tnc_policy -u $TNC_UID -k $TNC_PRIVKEY$TNC_PUBKEY -n 1 -a 1 -i 0 -I 0 -p 22 -P 22; exec_check "tcf_update_tnc_policy"

	echo "获取可信链接策略"
	./user/test/tcf/get_tnc_policy; exec_check "tcf_get_tnc_policy"

	echo "设置多例外可信链接策略 开启控制"
	./user/test/tcf/update_tnc_policy -m 1 -u $TNC_UID -k $TNC_PRIVKEY$TNC_PUBKEY -n 2 -a 1 -i 0 -I 0 -p 22 -P 22 -a 2 -i 192.168.1.1 -I 192.168.1.2 -p 22 -P 22; exec_check "tcf_update_tnc_policy"

	echo "获取可信链接策略"
	./user/test/tcf/get_tnc_policy; exec_check "tcf_get_tnc_policy"

	echo "设置可信链接策略 无例外 关闭控制"
	./user/test/tcf/update_tnc_policy -m 0 -u $TNC_UID -k $TNC_PRIVKEY$TNC_PUBKEY; exec_check "tcf_update_tnc_policy"

	echo "获取可信链接策略"
	./user/test/tcf/get_tnc_policy; exec_check "tcf_get_tnc_policy"

	./user/test/tcs/auth -n $TNC_UID -c 1 -d $TNC_PUBKEY -o 2 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_remove_admin_role"

}

trusted_evidence ()
{
	echo ">>> trusted_evidence test <<<"
}

log_notice ()
{
	echo ">>> log_notice test  <<<"
	./user/test/tcf/set_log_config -t 1 -v 0; exec_check "set_log_config"
	./user/test/tcf/get_log_config; exec_check "get_log_config"
	./user/test/tcf/log_test

	./user/test/tcf/set_notice_config -c 1000; exec_check "set_notice_config"
	./user/test/tcf/get_notice_config -t 1 -v 0; exec_check "get_notice_config"

}

passwd=123456

#using 'key_test 0' if don't test nv store tree
key_test()
{
	echo ">>> key_test <<<"
	./user/test/tcs/tcs_init $OWNER_PWD
	./user/test/tcs/generate_tpcm_pik $OWNER_PWD; exec_check "generate_tpcm_pik"
	./user/test/tcf/delete_keytree -k s://; exec_check "tcf_delete_keytree"
	./user/test/tcf/delete_keytree -k p://; exec_check "tcf_delete_keytree"

	echo "*** signkey test ***"
	./user/test/tcf/create_sign_key -k s://sign/a -p $passwd; exec_check "create_sign_key"
	./user/test/tcf/sign -k s://sign/a -d aaaaaaaaa -p $passwd; exec_check "sign"
	./user/test/tcf/create_sign_key -k s://sign/b -p $passwd -f 0x8020 -i 0 -o 1; exec_check "create_sign_key_on_policy"
	./user/test/tcf/sign -k s://sign/b -d aaaaaaaaa -p $passwd; exec_check "sign"

	echo "*** encryptkey test ***"
	./user/test/tcf/create_encrypt_key -k s://encrypt/a -t 0 -p $passwd -o 0; right_check "create_encrypt_key sm2"
	./user/test/tcf/create_encrypt_key -k s://encrypt/b -t 0 -p 123456 -o 1; right_check "tcf_create_inner_encrypt_key sm2"
	./user/test/tcf/create_encrypt_key -k s://encrypt/c -t 0 -p 123456 -f 0x8020 -i 0 -o 2; right_check "tcf_create_encrypt_key_on_policy sm4"
	./user/test/tcf/create_encrypt_key -k s://encrypt/d -t 0 -p 123456 -f 0x8020 -i 0 -o 3; right_check "tcf_create_inner_encrypt_key_on_policy sm4"

	./user/test/tcf/create_encrypt_key -k s://encrypt/b -t 1 -p 123456 -o 1; exec_check "tcf_create_inner_encrypt_key sm4"
	./user/test/tcf/encrypt -k s://encrypt/b -d abcdefg -p 123456 -e Encrypt; exec_check "encrypt sm4"
	./user/test/tcf/decrypt -k s://encrypt/b -p 123456 -e Encrypt; exec_check "decrypt sm4"

	./user/test/tcf/create_encrypt_key -k s://encrypt/c -t 1 -p 123456 -f 0x8020 -i 0 -o 2; exec_check "tcf_create_encrypt_key_on_policy sm4"
	./user/test/tcf/encrypt -k s://encrypt/c -d abcdefg -p 123456 -e Encrypt; exec_check "encrypt"
	./user/test/tcf/decrypt -k s://encrypt/c -p 123456 -e Encrypt; exec_check "decrypt"

	./user/test/tcf/create_encrypt_key -k s://encrypt/d -t 1 -p 123456 -f 0x8020 -i 0 -o 3; exec_check "tcf_create_inner_encrypt_key_on_policy sm4"
	./user/test/tcf/encrypt -k s://encrypt/d -d abcdefg -p 123456 -e Encrypt; exec_check "encrypt"
	./user/test/tcf/decrypt -k s://encrypt/d -p 123456 -e Encrypt; exec_check "decrypt"

	 echo "*** sealkey test ***"
	./user/test/tcf/create_seal_key -k s://seal/a -t 0 -p 123456 -o 0; exec_check "tcf_create_sign_key sm2"
	./user/test/tcf/create_seal_key -k s://seal/b -t 1 -p 123456 -f 0x8020 -i 0 -o 1; exec_check "tcf_create_sign_key_on_policy sm4"
	./user/test/tcf/seal_data -k s://seal/a -d 123456789 -p 123456 -s Seal; exec_check "tcf_seal_data sm2"
	./user/test/tcf/unseal_data -k s://seal/a -p 123456 -s Seal; exec_check "tcf_unseal_data sm2"
	./user/test/tcf/seal_data_store -k s://seal/b -d helloworld! -p 123456 -s Seal; exec_check "tcf_seal_data_store sm4"
	./user/test/tcf/unseal_stored_data -k s://seal/b -p 123456 -s Seal; exec_check "tcf_unseal_stored_data sm4"
	./user/test/tcf/get_sealed_data -k s://seal/b -s Seal; exec_check "tcf_get_sealed_data"
	./user/test/tcf/save_sealed_data -k s://seal/a -d Seal -s Seal; exec_check "save_sealed_data"

	echo "*** pathkey test ***"
	./user/test/tcf/create_path_key -k s://mig//a -t 1 -o 0; right_check "errpath sm4"
	./user/test/tcf/create_path_key -k s://migara/a -t 1 -o 0; exec_check "tcf_create_path_key"
	./user/test/tcf/create_path_key -k s:///a/b -t 0 -o 0; right_check "tcf_create_path_key sm2"
	./user/test/tcf/create_path_key -k s://migara/a/b -t 1 -o 1; exec_check "tcf_create_migratable_path_key"

	echo "*** get_public_key test ***"
	./user/test/tcf/get_pubkey -k s://sign/a; exec_check "tcf_get_public_key"

	echo "*** change_leaf_auth test ***"
	./user/test/tcf/changeauth -k s://seal/a -o 123456 -n 123123; exec_check "tcf_change_leaf_auth"
	./user/test/tcf/seal_data -k s://seal/a -d changetest -p 123456 -s Seal; right_check "seal"
	./user/test/tcf/seal_data -k s://seal/a -d changetest -p 123123 -s Seal; exec_check "seal"
	./user/test/tcf/unseal_data -k s://seal/a -p 123123 -s Seal; exec_check "unseal"

	./user/test/tcf/changeauth -k s://encrypt/c -o 123456 -n 123123; exec_check "tcf_change_leaf_auth encrypt_key"
	./user/test/tcf/encrypt -k s://encrypt/c -d abcdefg -p 123456 -e Encrypt; right_check "encrypt"
	./user/test/tcf/encrypt -k s://encrypt/c -d changetest -p 123123 -e Encrypt; exec_check "encrypt"
	./user/test/tcf/decrypt -k s://encrypt/c -p 123123 -e Encrypt; exec_check "decrypt"

	./user/test/tcf/changeauth -k s://encrypt/d -o 123456; exec_check "tcf_change_leaf_auth encrypt_key_on_policy"
	./user/test/tcf/encrypt -k s://encrypt/d -d changetest -e Encrypt; exec_check "encrypt"
	./user/test/tcf/decrypt -k s://encrypt/d -e Encrypt; exec_check "decrypt"

	echo "*** get_keyinfo test ***"
	./user/test/tcf/get_key_info -k s://sign/a -o 0; exec_check "tcf_get_keyinfo"
	./user/test/tcf/get_key_info -k s://sign/a -o 1; exec_check "tcm_get_keyinfo_path"

	echo "*** keytree test ***"
	./user/test/tcf/read_tree -k s://sign  -l 2 -r 1; exec_check "tcf_read_keytree tcf_free_keynode"

if [ ! $1 ]; then
	echo "*** load and save share tree  test ***"
	./user/test/tcf/create_keytree_storespace -w $OWNER_PWD -n 123123 -s 4000; exec_check "tcf_create_shared_keytree_storespace"
	./user/test/tcf/delete_keytree -k s://sign; exec_check "tcf_delete_keytree"
	./user/test/tcf/delete_keytree -k s://encrypt; exec_check "tcf_delete_keytree"
	./user/test/tcf/save_shared_keytree -p 123123; exec_check "tcf_save_shared_keytree"
	./user/test/tcf/load_shared_keytree -p 123123; exec_check "tcf_load_shared_keytree"
	./user/test/tcf/remove_keytree_storespace -w $OWNER_PWD; exec_check "tcf_remove_shared_keytree_storespace"
	./user/test/tcf/save_shared_keytree -p 123123; right_check "tcf_save_shared_keytree"

	echo "*** load and save private tree test ***"
	./user/test/tcf/create_sign_key -k p://sign/a -p $passwd; exec_check "create_sign_key"
	./user/test/tcf/set_private_keytree_storespace_index -i 66; exec_check "tcf_set_private_keytree_storespace_index"
	./user/test/tcf/nv_define_space -I 66 -s 4000 -w $OWNER_PWD -p 123123 -o 0; exec_check "tcf_nv_define_space"
	./user/test/tcf/save_private_keytree -p 123123; exec_check "tcf_save_private_keytree"
	./user/test/tcf/load_private_keytree -p 123123; exec_check "tcf_load_private_keytree"
	./user/test/tcf/nv_delete_space -I 66 -w $OWNER_PWD; exec_check "tcf_nv_delete_space"

fi

	echo "*** export import test ***"
	./user/test/tcf/export_keytree -k s://seal -n Export; exec_check "tcf_export_keytree"
	./user/test/tcf/import_keytree -k s://seal -n Export; right_check "tcf_import_keytree"
	./user/test/tcf/delete_keytree -k s://seal; exec_check "tcf_delete_keytree"
	./user/test/tcf/import_keytree -k s://Seal -n Export; right_check "tcf_import_keytree"
	./user/test/tcf/import_keytree -k s://seal -n Export; exec_check "tcf_import_keytree"
	./user/test/tcf/seal_data -k s://seal/a -d changetest -p 123123 -s Seal; exec_check "seal newpasswd"

	echo "*** migrate test ***"
	./user/test/tcf/create_path_key -k s://m -t 1 -o 1; exec_check "tcf_create_path_key"
	./user/test/tcf/create_path_key -k s://f -t 1 -o 1; exec_check "tcf_create_path_key"
	./user/test/tcf/get_migrate_auth -n auth; exec_check "tcf_get_migrate_auth"

	echo "*** migrate node key test ***"
	./user/test/tcf/create_path_key -k s://m/a -t 1 -o 1; exec_check "tcf_create_path_key"
	./user/test/tcf/create_sign_key -k s://m/a/b -t 0 -p 123456 -o 0; exec_check "tcf_create_sign_key"
	./user/test/tcf/emigrate_keytree -k s://m -w $OWNER_PWD -d auth -e emig; exec_check "tcf_emigrate_keytree"
	./user/test/tcf/immigrate_keytree -k s:// -e emig; exec_check "tcf_immigrate_keytree"
	./user/test/tcf/immigrate_keytree -k s://f -e emig; exec_check "tcf_immigrate_keytree"
	./user/test/tcf/immigrate_keytree -k s://abc -e emig; exec_check "tcf_immigrate_keytree"
	./user/test/tcf/sign -k s://f/m/a/b -d aaaaaaaaa -p 123456; exec_check "sign"

	echo "*** migrate leaf key test ***"
	./user/test/tcf/create_sign_key -k s://m/c -t 0 -p 123456 -o 0; exec_check "tcf_create_sign_key"
	./user/test/tcf/emigrate_keytree -k s://m/c -p 123456 -w $OWNER_PWD -d auth -e emig; exec_check "tcf_emigrate_keytree"
	./user/test/tcf/immigrate_keytree -k s://efg -e emig; exec_check "tcf_immigrate_keytree"
	./user/test/tcf/immigrate_keytree -k s://f/m/a/b -e emig; right_check "tcf_immigrate_keytree"
:<<!
	#echo "*** PCR test***"
	#./user/test/tcf/create_encrypt_key -k s://encrypt/a -t 1 -p 123456 -f 0x9028 -n process -o 2; exec_check "tcf_create_encrypt_key_on_policy sm4"
	#./user/test/tcf/encrypt -k s://encrypt/a -d abcdefg -p 123456 -e Encrypt; exec_check "encrypt"
	#./user/test/tcs/update_pcr 7;exec_check "update_pcr"
	#./user/test/tcf/decrypt -k s://encrypt/a -p 123456 -e Encrypt; right_check "decrypt"
!
	rm Encrypt Export Seal *_keytree.tar.gz emig auth -rf
}
#default loop time is 1
store_test()
{
	echo ">>> store_test <<<"
	./user/test/tcs/tcs_init $OWNER_PWD
	./user/test/tcs/generate_tpcm_pik $OWNER_PWD; exec_check "generate_tpcm_pik"
	dd if=/dev/zero of=testfileloop bs=1K count=1
	loop=${1:-1}
	echo "*** define space test  loop=$loop ***"
	j=1
	while [ $j -le $loop ];do
		./user/test/tcf/nv_define_space -I $j -s 1024 -w $OWNER_PWD -p 123456 -o 0; exec_check "tcf_nv_define_space"
		./user/test/tcf/nv_write -I $j -F testfileloop -p 123456; exec_check "tcf_nv_write"
#		./user/test/tcf/nv_read -I $j -p 123456; exec_check "tcf_nv_read"
		echo "#######################RUN  $j  loop #######################"
		j=$((j+1))
	done

	j=1
	while [ $j -le $loop ];do
		./user/test/tcf/nv_delete_space -I $j -w $OWNER_PWD; exec_check "tcf_nv_delete_space"
		echo "#######################RUN delete $j  loop #######################"
		j=$((j+1))
	done

	echo "*** define space test ***"
	./user/test/tcf/nv_define_space -I 6 -s 128 -w $OWNER_PWD -p 123456 -o 0; exec_check "tcf_nv_define_space"
	./user/test/tcf/nv_define_space -I 7 -s 128 -w $OWNER_PWD -p 123456 -f 0x8020 -i 0 -o 1; exec_check "tcf_nv_define_space_on_policy"
	./user/test/tcf/nv_define_name_space -s 128 -N one -w $OWNER_PWD -p 123456 -o 0; exec_check "tcf_nv_define_name_space"
	./user/test/tcf/nv_define_name_space -s 128 -N one -w $OWNER_PWD -p 123456 -o 0; right_check "recreate tcf_nv_define_name_space"
	./user/test/tcf/nv_define_name_space -s 128 -N two -w $OWNER_PWD -p 123456 -f 0x8020 -i 0 -o 1; exec_check "tcf_nv_define_name_space_on_policy"
	./user/test/tcf/nv_define_name_space -s 128 -N two -w $OWNER_PWD -p 123456 -f 0x8020 -i 0 -o 1; right_check "recreate tcf_nv_define_name_space_on_policy"

	echo "*** write test ***"
	./user/test/tcf/nv_write -I 6 -d helloworld! -p 123456; exec_check "tcf_nv_write"
	./user/test/tcf/nv_write -I 7 -d helloworld! -p 123456; exec_check "tcf_nv_write policy"
	./user/test/tcf/nv_named_write -N one -d helloworld! -p 123456; exec_check "tcf_nv_named_write"
	./user/test/tcf/nv_named_write -N two -d hellobeauty! -p 123456; exec_check "tcf_nv_named_write"
	./user/test/tcf/nv_write -I 6 -d helloworld! -p 123123; right_check "tcf_nv_write"
	./user/test/tcf/nv_write -I 120 -d helloworld! -p 123456; right_check "tcf_nv_write"
	./user/test/tcf/nv_named_write -N three -d hellobeauty! -p 123456; right_check "tcf_nv_named_write"

	echo "*** read test ***"
	./user/test/tcf/nv_read -I 6 -p 123456; exec_check "tcf_nv_read"
	./user/test/tcf/nv_read -I 7 -p 123456; exec_check "tcf_nv_read"
	./user/test/tcf/nv_named_read -N one -p 123456; exec_check "tcf_nv_named_read"
	./user/test/tcf/nv_named_read -N two -p 123456; exec_check "tcf_nv_named_read"
	./user/test/tcf/nv_read -I 6 -p 123123; right_check "tcf_nv_read"
	./user/test/tcf/nv_read -I 120 -p 123456; right_check "tcf_nv_read"
	./user/test/tcf/nv_named_read -N three -p 123456; right_check "tcf_nv_named_read"

	echo "*** nvlist test ***"
	./user/test/tcf/read_nv_list; exec_check "tcf_read_nv_list"
	cp -f /usr/local/httcsec/conf/nvinfo ./nvinfos
	mv /usr/local/httcsec/conf/nvinfo /usr/local/httcsec/conf/bak
	./user/test/tcf/set_nv_list -f nvinfos -n `cat number.txt`; exec_check "tcf_set_nv_list"
	./user/test/tcf/is_nv_defined 6; right_check "tcf_is_nv_defined index 6"
	./user/test/tcf/is_nv_defined 10; exec_check "tcf_is_nv_defined index 10"

	echo "*** delete list test ***"
	./user/test/tcf/nv_delete_space -I 6 -w $OWNER_PWD; exec_check "tcf_nv_delete_space"
	./user/test/tcf/nv_delete_name_space -N one -w $OWNER_PWD; exec_check "tcf_nv_delete_name_space"
	./user/test/tcf/is_nv_defined 6; exec_check "tcf_is_nv_defined index 6"
	./user/test/tcf/is_nv_defined 8; exec_check "tcf_is_nv_defined index 8"
#	./user/test/tcs/nv_delete_space -I 120 -w $OWNER_PWD; right_check "tcf_nv_delete_space"
#	./user/test/tcs/nv_delete_name_space -N three -w $OWNER_PWD; right_check "tcf_nv_delete_name_space"

	./user/test/tcf/nv_delete_space -I 7 -w $OWNER_PWD; exec_check "tcf_nv_delete_space"
	./user/test/tcf/nv_delete_name_space -N two -w $OWNER_PWD; exec_check "tcf_nv_delete_name_space"
:<<!
	#./user/test/tcf/nv_define_space -I 7 -s 128 -w $OWNER_PWD -p 123456 -f 0x9028 -n process -o 1; exec_check "tcf_nv_define_space_on_policy"
	#./user/test/tcf/nv_write -I 7 -d helloworld! -p 123456; exec_check "tcf_nv_write policy"
	#./user/test/tcs/update_pcr 7;exec_check "update_pcr"
	#./user/test/tcf/nv_read -I 7 -p 123456; right_check "tcf_nv_read"
	#./user/test/tcf/nv_delete_space -I 7 -w $OWNER_PWD; exec_check "tcf_nv_delete_space"
!
	./user/test/tcf/read_nv_list; exec_check "tcf_read_nv_list"
	rm number.txt nvinfos testfileloop -rf

}

license_test ()
{
	echo ">>> license_test <<<"

	echo "获得license状态"
	./user/test/tcf/get_license_status; exec_check "get_license_status"
	echo "获得license信息"
	./user/test/tcf/get_license_info; exec_check "get_license_info"
	# 判断版本号是 2.1 还是 2.0
	if [ $version = "V2.1" ]; then
		echo "版本号为 2.1"
		echo "获得license实体信息"
		./user/test/tcf/get_license_entity; exec_check "get_license_entity"
	elif [ $version = "V2.0" ]; then
		echo "版本号为 2.0"
	else
		echo "无法识别的版本号"
	fi

	echo "TCM初始化"
	./user/test/tcs/tcs_init $OWNER_PWD
	echo "生成tpcm PIK"
	./user/test/tcs/generate_tpcm_pik $OWNER_PWD

	echo "获得license状态"
	./user/test/tcf/get_license_status; exec_check "get_license_status"
	echo "获得license信息"
	./user/test/tcf/get_license_info; exec_check "get_license_info"
	# 判断固件版本号是 2.1 还是 2.0
	if [ $version = "V2.1" ]; then
		echo "版本号为 2.1"
		echo "获得license实体信息"
		./user/test/tcf/get_license_entity; exec_check "get_license_entity"
	elif [ $version = "V2.0" ]; then
		echo "版本号为 2.0"
	else
		echo "无法识别的版本号"
	fi

	echo "重置license"
	./user/test/tcf/reset_test_license; exec_check "reset_test_license"
	echo "获得license状态"
	./user/test/tcf/get_license_status; exec_check "get_license_status"
	echo "获得license信息"
	./user/test/tcf/get_license_info; exec_check "get_license_info"
	# 判断固件版本号是 2.1 还是 2.0
	if [ $version = "V2.1" ]; then
		echo "版本号为 2.1"
		echo "获得license实体信息"
		./user/test/tcf/get_license_entity; exec_check "get_license_entity"
	elif [ $version = "V2.0" ]; then
		echo "版本号为 2.0"
	else
		echo "无法识别的版本号"
	fi

	echo "TCM初始化"
	./user/test/tcs/tcs_init $OWNER_PWD
	echo "生成tpcm PIK"
	./user/test/tcs/generate_tpcm_pik $OWNER_PWD
	#./user/test/tcf/license_request; exec_check "license_request"
	if [ $version = "V2.1" ]; then
		echo "版本号为 2.1"
		echo "请求license"
		./user/utils/tcs/license_tool -a 1 -v 1 -f ./ -o 0; exec_check "license_request"
	elif [ $version = "V2.0" ]; then
		echo "版本号为 2.0"
		echo "请求license"
		./user/utils/tcs/license_tool -a 2 -v 0 -f ./ -o 0; exec_check "license_request"
	else
		echo "无法识别的版本号"
	fi

	echo "获得license状态"
	./user/test/tcf/get_license_status; exec_check "get_license_status"
	echo "获得license信息"
	./user/test/tcf/get_license_info; exec_check "get_license_info"
	# 判断固件版本号是 2.1 还是 2.0
	if [ $version = "V2.1" ]; then
		echo "版本号为 2.1"
		echo "获得license实体信息"
		./user/test/tcf/get_license_entity; exec_check "get_license_entity"
	elif [ $version = "V2.0" ]; then
		echo "版本号为 2.0"
	else
		echo "无法识别的版本号"
	fi

	# 判断固件版本号是 2.1 还是 2.0
	if [ $version = "V2.1" ]; then
		echo "版本号为 2.1"
	elif [ $version = "V2.0" ]; then
		echo "版本号为 2.0"
		echo "导入TPCM的license"
		./user/test/tcf/import_license -t 2; exec_check "import_license"
		echo "获得license状态"
		./user/test/tcf/get_license_status; exec_check "get_license_status"
		echo "获得license信息"
		./user/test/tcf/get_license_info; exec_check "get_license_info"
	else
		echo "无法识别的版本号"
	fi

	echo "内核态获取license状态"
	insmod ./kernel/test/tcs/get_license_status.ko; exec_check "get_license_status.ko"
	rmmod get_license_status
	echo "内核态获取license信息"
	insmod ./kernel/test/tcs/get_license_info.ko; exec_check "get_license_info.ko"
	rmmod get_license_info
	# 判断固件版本号是 2.1 还是 2.0
	if [ $version = "V2.1" ]; then
		echo "版本号为 2.1"
		echo "内核态获取license实体信息"
		insmod ./kernel/test/tcs/get_license_entity.ko; exec_check "get_license_entity.ko"
		rmmod get_license_entity
	elif [ $version = "V2.0" ]; then
		echo "版本号为 2.0"
	else
		echo "无法识别的版本号"
	fi
}
fileacl_test(){
		./user/test/tcf/set_file_protect_policy -n 5 -p helloworld one two three /opt/home; exec_check "set_file_protect_policy"
		./user/test/tcf/set_file_protect_policy -n 0; exec_check "set_file_protect_policy 0"
		./user/test/tcf/set_privilege_process_policy -n 5 -p helloworld one two three /opt/home; exec_check "set_privilege_process_policy"
		./user/test/tcf/set_privilege_process_policy -n 0; exec_check "set_privilege_process_policy 0"
}


file_protect_test ()
{
	echo ">>> file_protect_test <<<"
	./user/test/tcs/tcs_init $OWNER_PWD
	./user/test/tcs/generate_tpcm_pik $OWNER_PWD; exec_check "generate_tpcm_pik"

	echo "设置根证书"
	./user/test/tcs/auth -n $ROOT_CERT_ID -c 1 -d $ROOT_PUBKEY -o 0 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_set_admin_cert"
	echo "设置二级证书"
	./user/test/tcs/auth -n $FILE_PROTECT_UID -c 1 -d $FILE_PROTECT_PUBKEY -o 1 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_grant_admin_role"

	echo "设置文件访问控制策略"
	./user/test/tcf/update_file_protect_policy -c 1 -k $FILE_PROTECT_PRIVKEY$FILE_PROTECT_PUBKEY -u $FILE_PROTECT_UID -p /usr/lib -o 1 -a 0; exec_check "tcf_update_file_protect_policy set"

	echo "获取文件访问控制策略"
	./user/test/tcf/get_file_protect_policy; exec_check "tcf_get_file_protect_policy"

	echo "增加文件访问控制策略"
	./user/test/tcf/update_file_protect_policy -c 1 -k $FILE_PROTECT_PRIVKEY$FILE_PROTECT_PUBKEY -u $FILE_PROTECT_UID -N 2 -p /usr/lib/one /usr/lib/two -o 1 -a 1; exec_check "tcf_update_file_protect_policy add"
	echo "获取文件访问控制策略"
	./user/test/tcs/get_file_protect_policy; exec_check "tcf_get_file_protect_policy"

	echo "增加文件访问控制策略"
	./user/test/tcf/update_file_protect_policy -c 1 -k $FILE_PROTECT_PRIVKEY$FILE_PROTECT_PUBKEY -u $FILE_PROTECT_UID -p /usr/lib -o 1 -a 1; right_check "tcf_update_file_protect_policy add"

	echo "删除文件访问控制策略"
	./user/test/tcf/update_file_protect_policy -c 1 -k $FILE_PROTECT_PRIVKEY$FILE_PROTECT_PUBKEY -u $FILE_PROTECT_UID -p /usr/lib -o 1 -a 2; exec_check "tcf_update_file_protect_policy delete"
	echo "获取文件访问控制策略"
	./user/test/tcs/get_file_protect_policy; exec_check "tcf_get_file_protect_policy"

	echo "删除文件访问控制策略"
	./user/test/tcf/update_file_protect_policy -c 1 -k $FILE_PROTECT_PRIVKEY$FILE_PROTECT_PUBKEY -u $FILE_PROTECT_UID -N 2 -p /usr/lib/one /usr/lib/two -o 1 -a 2; exec_check "tcf_update_file_protect_policy add"
	echo "获取文件访问控制策略"
	./user/test/tcs/get_file_protect_policy; exec_check "tcf_get_file_protect_policy"
}

dev_protect_test ()
{
	echo ">>> dev_protect_test <<<"
	./user/test/tcs/tcs_init $OWNER_PWD
	./user/test/tcs/generate_tpcm_pik $OWNER_PWD; exec_check "generate_tpcm_pik"

	echo "设置根证书"
	./user/test/tcs/auth -n $ROOT_CERT_ID -c 1 -d $ROOT_PUBKEY -o 0 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_set_admin_cert"
	echo "设置二级证书"
	./user/test/tcs/auth -n $FILE_PROTECT_UID -c 1 -d $FILE_PROTECT_PUBKEY -o 1 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_grant_admin_role"

	echo "设置CDROM访问控制策略"
	./user/test/tcf/update_dev_protect_policy -c 1 -k $FILE_PROTECT_PRIVKEY$FILE_PROTECT_PUBKEY -u $FILE_PROTECT_UID  -o 1 -a 0; exec_check "tcf_update_dev_protect_policy set"

	echo "获取CDROM访问控制策略"
	./user/test/tcf/get_dev_protect_policy; exec_check "tcf_get_dev_protect_policy"

	echo "增加CDROM访问控制策略"
	./user/test/tcf/update_dev_protect_policy -c 1 -k $FILE_PROTECT_PRIVKEY$FILE_PROTECT_PUBKEY -u $FILE_PROTECT_UID  -o 0 -a 1; exec_check "tcf_update_dev_protect_policy add"

	echo "获取CDROM访问控制策略"
	./user/test/tcf/get_dev_protect_policy; exec_check "tcf_get_dev_protect_policy"

    echo "增加CDROM访问控制策略"
	./user/test/tcf/update_dev_protect_policy -c 1 -k $FILE_PROTECT_PRIVKEY$FILE_PROTECT_PUBKEY -u $FILE_PROTECT_UID  -o 0 -a 0; exec_check "tcf_update_dev_protect_policy add"

	echo "获取CDROM访问控制策略"
	./user/test/tcf/get_dev_protect_policy; exec_check "tcf_get_dev_protect_policy"


	echo "删除CDROM访问控制策略"
	./user/test/tcf/update_dev_protect_policy -c 1 -k $FILE_PROTECT_PRIVKEY$FILE_PROTECT_PUBKEY -u $FILE_PROTECT_UID  -o 1 -a 2; exec_check "tcf_update_dev_protect_policy delete"

	echo "获取CDROM访问控制策略"
	./user/test/tcf/get_dev_protect_policy; exec_check "tcf_get_dev_protect_policy"
}

udisk_protect_test ()
{
	echo ">>> udisk_protect_test <<<"
	./user/test/tcs/tcs_init $OWNER_PWD
	./user/test/tcs/generate_tpcm_pik $OWNER_PWD; exec_check "generate_tpcm_pik"

	echo "设置根证书"
	./user/test/tcs/auth -n $ROOT_CERT_ID -c 1 -d $ROOT_PUBKEY -o 0 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_set_admin_cert"
	echo "设置二级证书"
	./user/test/tcs/auth -n $FILE_PROTECT_UID -c 1 -d $FILE_PROTECT_PUBKEY -o 1 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_grant_admin_role"

	echo "设置udisk访问控制策略"
	./user/test/tcf/update_udisk_protect_policy -c 1 -k $FILE_PROTECT_PRIVKEY$FILE_PROTECT_PUBKEY -u $FILE_PROTECT_UID -T 1 -N 1 -g "guid1" -o 1 -a 0; exec_check "tcf_update_udisk_protect_policy set"

	echo "获取外设udisk访问控制策略"
	./user/test/tcf/get_udisk_protect_policy; exec_check "tcf_get_file_protect_policy"

	echo "增加外设udisk访问控制策略"
	./user/test/tcf/update_udisk_protect_policy -c 1 -k $FILE_PROTECT_PRIVKEY$FILE_PROTECT_PUBKEY -u $FILE_PROTECT_UID -T 2 -N 2 -g "guid2" "guid3" -o 1 -a 1; exec_check "tcf_update_udisk_protect_policy add"
	echo "获取外设udisk访问控制策略"
	./user/test/tcf/get_udisk_protect_policy; exec_check "tcf_get_udisk_protect_policy"

	echo "增加外设udisk访问控制策略"
	./user/test/tcf/update_udisk_protect_policy -c 1 -k $FILE_PROTECT_PRIVKEY$FILE_PROTECT_PUBKEY -u $FILE_PROTECT_UID -T 1 -N 1 -g "guid1" -o 1 -a 1; right_check "tcf_update_udisk_protect_policy add"

	echo "获取外设udisk访问控制策略"
	./user/test/tcf/get_udisk_protect_policy; exec_check "tcf_get_udisk_protect_policy"

	echo "删除外设udisk访问控制策略"
	./user/test/tcf/update_udisk_protect_policy -c 1 -k $FILE_PROTECT_PRIVKEY$FILE_PROTECT_PUBKEY -u $FILE_PROTECT_UID -T 1 -N 1 -g "guid1" -o 1 -a 2; exec_check "tcf_update_udisk_protect_policy delete"
	echo "获取外设udisk访问控制策略"
	./user/test/tcf/get_udisk_protect_policy; exec_check "tcf_get_udisk_protect_policy"

}

network_control_test ()
{
	echo ">>> network_control_test <<<"
	./user/test/tcs/tcs_init $OWNER_PWD
	./user/test/tcs/generate_tpcm_pik $OWNER_PWD; exec_check "generate_tpcm_pik"

	echo "设置根证书"
	./user/test/tcs/auth -n $ROOT_CERT_ID -c 1 -d $ROOT_PUBKEY -o 0 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_set_admin_cert"
	echo "设置二级证书"
	./user/test/tcs/auth -n $NETWORK_CONTROL_UID -c 1 -d $FILE_PROTECT_PUBKEY -o 1 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_grant_admin_role"

	echo "设置网络控制策略"
	./user/test/tcf/update_network_control -c 1 -k $FILE_PROTECT_PRIVKEY$FILE_PROTECT_PUBKEY -u $NETWORK_CONTROL_UID -w 0 -d 1 -f 16951488  -t 1677895872 -s 2  -a 0; exec_check "tcf_update_network_control set"
	echo "获取网络控制策略"
	./user/test/tcf/get_network_control_policy; exec_check "tcf_get_network_control_policy"

	#echo "增加网络控制策略"
	#./user/test/tcf/update_network_control -c 1 -k $FILE_PROTECT_PRIVKEY$FILE_PROTECT_PUBKEY -u $NETWORK_CONTROL_UID -w 0 -d 2 -f 100 -t 200 -s 0x00000001 -a 1; exec_check "tcf_update_network_control add"
	#echo "获取网络控制策略"
	#./user/test/tcf/get_network_control_policy; exec_check "tcf_get_network_control_policy"
	echo "增加外设网络控制策略"
	./user/test/tcf/update_network_control -c 1 -k $FILE_PROTECT_PRIVKEY$FILE_PROTECT_PUBKEY -u $NETWORK_CONTROL_UID -w 0 -d 1 -f 16951488 -t 1677895872 -s 3 -a 1; exec_check "tcf_update_network_control add"

	echo "获取网络控制策略"
	./user/test/tcf/get_network_control_policy; exec_check "tcf_get_network_control_policy"

	echo "增加外设网络控制策略"
	./user/test/tcf/update_network_control -c 1 -k $FILE_PROTECT_PRIVKEY$FILE_PROTECT_PUBKEY -u $NETWORK_CONTROL_UID -w 0 -d 1 -f 16951488 -t 1677895872 -s 3 -a 1; right_check "tcf_update_network_control add"

	echo "获取网络控制策略"
	./user/test/tcf/get_network_control_policy; exec_check "tcf_get_network_control_policy"

#echo "删除外设网络控制策略"
#	./user/test/tcf/update_network_control -c 1 -k $FILE_PROTECT_PRIVKEY$FILE_PROTECT_PUBKEY -u $NETWORK_CONTROL_UID -w 0 -d 1 -f 100 -t 200 -s 0x00000003 -a 2; exec_check "tcf_update_network_control delete"
#	echo "获取网络控制策略"
#	./user/test/tcf/get_network_control_policy; exec_check "tcf_get_network_control_policy"

}

set_tpcm_shell_auth_test ()
{
	echo "设置根证书"
	./user/test/tcs/auth -n $ROOT_CERT_ID -c 1 -d $ROOT_PUBKEY -o 0 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_set_admin_cert"

	echo "设置TPCM SHELL AUTH"
	./user/test/tcs/set_tpcm_shell_auth -p 12345678 -u $ROOT_CERT_ID -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "set_tpcm_shell_auth"
	./user/test/tcs/set_tpcm_shell_auth -p 12345678123456781234567812345678 -u $ROOT_CERT_ID -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "set_tpcm_shell_auth"
	./user/test/tcs/set_tpcm_shell_auth -p 123456 -u $ROOT_CERT_ID -k $ROOT_PRIVKEY$ROOT_PUBKEY; right_check "set_tpcm_shell_auth"
	./user/test/tcs/set_tpcm_shell_auth -p 123456781234567812345678123456780 -u $ROOT_CERT_ID -k $ROOT_PRIVKEY$ROOT_PUBKEY; right_check "set_tpcm_shell_auth"
}

linked_switch_status_test ()
{
	echo ">>> linked_switch_status_test <<<"

	echo "获取联动开关状态"
	./user/test/tcs/get_linked_switch_status; exec_check "get_linked_switch_status"
	echo "清除联动开关状态"
	./user/test/tcs/clear_linked_switch_status; exec_check "get_linked_switch_status"
	echo "获取联动开关状态"
	./user/test/tcs/get_linked_switch_status; exec_check "get_linked_switch_status"
}

test90()
{
	feature_check
	admin_auth_test
	global_policy_test
	process_id_role_test
	boot_measure_test
	#file_integrity_test
	#intercept_measure_test
	#simple_intercept_measure_test
	critical_file_integrity_test
	dynamic_measure_test
	process_dmeasure_test
	ptrace_protect_test
	attest_test
	trusted_evidence
	maintain_test
	tnc_test
	log_notice
	store_test 15
	key_test
	fileacl_test
	license_test
	file_protect_test
	set_tpcm_shell_auth_test
	#linked_switch_status_test
}

test91()
{
	feature_check
	admin_auth_test
	global_policy_test
	process_id_role_test
	boot_measure_test
	file_integrity_test
	if [ $imeasure -eq 0 ]; then
	intercept_measure_test
	simple_intercept_measure_test
	fi
	critical_file_integrity_test
	dynamic_measure_test
	process_dmeasure_test
	ptrace_protect_test
	attest_test
	trusted_evidence
	maintain_test
	tnc_test
	log_notice
	store_test 15
	key_test
	fileacl_test
	file_protect_test
	license_test
	set_tpcm_shell_auth_test
	#linked_switch_status_test
}


test94()
{
	feature_check
	admin_auth_test
	global_policy_test
	process_id_role_test
	boot_measure_test
#	file_integrity_test
	if [ $imeasure -eq 0 ]; then
	intercept_measure_test
	simple_intercept_measure_test
	fi
	critical_file_integrity_test
#	dynamic_measure_test
#	process_dmeasure_test
#	ptrace_protect_test
	attest_test
	trusted_evidence
	maintain_test
#	tnc_test
	log_notice
	store_test 0
	key_test 0
	fileacl_test
#	license_test
	file_protect_test
	set_tpcm_shell_auth_test
	#linked_switch_status_test
}

test941()
{
	feature_check
	admin_auth_test
	global_policy_test
	process_id_role_test
	boot_measure_test
	file_integrity_test
	#intercept_measure_test
	#simple_intercept_measure_test
	critical_file_integrity_test
	dynamic_measure_test
	process_dmeasure_test
	ptrace_protect_test
	attest_test
	trusted_evidence
	maintain_test
	#tnc_test
	log_notice
	store_test 0
	key_test  0
	#fileacl_test
	#license_test
	#file_protect_test
	#set_tpcm_shell_auth_test
	#linked_switch_status_test
}

remove_test_certs(){
	./user/test/tcf/tcf_auth -n $GRANT_CERT_ID -c 1 -d $GRANT_PUBKEY -o 2 -k $ROOT_PRIVKEY$ROOT_PUBKEY
	./user/test/tcf/tcf_auth -n $FILE_INTEGRITY_UID -c 1 -d $FILE_INTEGRITY_PUBKEY -o 2 -k $ROOT_PRIVKEY$ROOT_PUBKEY
	./user/test/tcf/tcf_auth -n $BMEASURE_UID -c 1 -d $BMEASURE_PUBKEY -o 2 -k $ROOT_PRIVKEY$ROOT_PUBKEY
	./user/test/tcf/tcf_auth -n $DMEASURE_UID -c 1 -d $DMEASURE_PUBKEY -o 2 -k $ROOT_PRIVKEY$ROOT_PUBKEY
	./user/test/tcf/tcf_auth -n $GLOBAL_POLICY_UID -c 1 -d $GLOBAL_POLICY_PUBKEY -o 2 -k $ROOT_PRIVKEY$ROOT_PUBKEY
	./user/test/tcf/tcf_auth -n $PROCESS_UID -c 1 -d $PROCESS_PUBKEY -o 2 -k $ROOT_PRIVKEY$ROOT_PUBKEY
	./user/test/tcs/auth -n $TNC_UID -c 1 -d $TNC_PUBKEY -o 2 -k $ROOT_PRIVKEY$ROOT_PUBKEY


	}

test_soft()
{
	feature_check
	admin_auth_test
	global_policy_test
	process_id_role_test
	#boot_measure_test
	file_integrity_test
	if [ $imeasure -eq 0 ]; then
	intercept_measure_test
	simple_intercept_measure_test
	fi
	critical_file_integrity_test
	dynamic_measure_test
	process_dmeasure_test
	ptrace_protect_test
	attest_test
	trusted_evidence
	maintain_test
	tnc_test
	log_notice
	#store_test 15
	#key_test
	fileacl_test
	file_protect_test
	#license_test
	#set_tpcm_shell_auth_test
	#linked_switch_status_test
}


Usage()
{
	echo "##################################################################"
	echo "Enter  the  number  to   test   !!!!!!!!"
	echo "	Press Ctrl+c to exit the synclient program ! "
	echo "  0     :  Help"
	echo "  1     :  admin_auth_test"
	echo "  2     :  global_policy_test"
	echo "  3     :  process_id_role_test"
	echo "  4     :  boot_measure_test"
	echo "  5     :  file_integrity_test"
	echo "  6     :  intercept_measure_test"
	echo "  7     :  simple_intercept_measure_test"
	echo "  8     :  critical_file_integrity_test"
	echo "  9     :  dynamic_measure_test"
	echo "  10    :  process_dmeasure_test"
	echo "  11    :  ptrace_protect_test"
	echo "  12    :  attest_test"
	echo "  13    :  trusted_evidence"
	echo "  14    :  maintain_test"
	echo "  15    :  tnc_test"
	echo "  16    :  log_notice"
	echo "  17    :  store_test(15 nvloop)"
	echo "  57    :  store_test(1 nvloop)"
	echo "  18    :  key_test(with nvstore test)"
	echo "  58    :  key_test(without nvstore test)"
	echo "  19    :  license_test"
	echo "  20    :  fileacl_test"
	echo "  21    :  file_protect_test"
	echo "  22    :  dev_protect_test"
	echo "  23    :  udisk_protect_test"
	echo "  24    :  network_control_test"
	echo "  25    :  set_tpcm_shell_auth_test"
	echo "  26    :  linked_switch_status_test"
	echo "  80    :  test_soft"
	echo "  90    :  TEST_ALL except 5、6、7"
	echo "  91    :  TEST_ALL"
	echo "  92    :  REMOVE TEST CERTs"
	echo "  94    :  pantum-test"
	echo "  95    :  file_integrity_test_limit set"
	echo "  96    :  file_integrity_test_limit add"
	echo "  97    :  file_integrity_test_limit del"
	echo "  98    :  file_integrity_test_limit get"
	echo "  99    :  dynamic_measure_test_simple"
	echo "##################################################################"
}
i=0
main(){

	#insmod ./kernel/test/tcs/get_tpcmlog.ko;
	Usage
	while :
	do
		echo -n "Please enter an integer to start test -> "
		read opt
		case $opt  in
			0)
				Usage;;
			1)
				admin_auth_test;;
			2)
				global_policy_test;;
			3)
				process_id_role_test;;
			4)
				boot_measure_test;;
			5)
				file_integrity_test;;
			6)
				intercept_measure_test;;
			7)
				simple_intercept_measure_test;;
			8)
				critical_file_integrity_test;;
			9)
				dynamic_measure_test;;
			10)
				process_dmeasure_test;;
			11)
				ptrace_protect_test;;
			12)
				attest_test;;
			13)
				trusted_evidence;;
			14)
				maintain_test;;
			15)
				tnc_test;;
			16)
				log_notice;;
			17)
				store_test 15;;
			57)
				store_test 1;;
			18)
				key_test;;
			58)
				key_test 0;;
			19)
				license_test;;
			20)
				fileacl_test;;
			21)
				file_protect_test;;
			22)
				dev_protect_test;;
			23)
				udisk_protect_test;;
			24)
				network_control_test;;
			25)
				set_tpcm_shell_auth_test;;
			26)
				linked_switch_status_test;;
			80)
				echo -n "Please enter an integer about how many cycles you want to test  ->"
				read cycles
				case $cycles in
					0)
						echo "Input value $cycles is not an right choice!!!!." >&2;;
					*)
						while [ $i -lt $cycles ];do
							test_soft
							i=$((i+1))
							echo "#######################RUN  $i  Cycles #######################"
						done
					;;
				esac
				;;
			90)
				echo -n "Please enter an integer about how many cycles you want to test  ->"
				read cycles
				case $cycles in
					0)
						echo "Input value $cycles is not an right choice!!!!." >&2;;
					*)
						while [ $i -lt $cycles ];do
							test90
							i=$((i+1))
							echo "#######################RUN  $i  Cycles #######################"
						done
					;;
				esac
				;;
			91)
				echo -n "Please enter an integer about how many cycles you want to test  ->"
				read cycles
				case $cycles in
					0)
						echo "Input value $cycles is not an right choice!!!!." >&2;;
					*)
						while [ $i -lt $cycles ];do
							test91
							i=$((i+1))
							echo "#######################RUN  $i  Cycles #######################"
						done
					;;
				esac
				;;
			94)
				echo -n "Please enter an integer about how many cycles you want to test  ->"
				read cycles
				case $cycles in
					0)
						echo "Input value $cycles is not an right choice!!!!." >&2;;
					*)
						while [ $i -lt $cycles ];do
							test94
							i=$((i+1))
							echo "#######################RUN  $i  Cycles #######################"
						done
					;;
				esac
				;;
			92)
				remove_test_certs;;
			95)
				file_integrity_test_limit 0;;
			96)
				file_integrity_test_limit 1;;
			97)
				file_integrity_test_limit 2;;
			98)
				file_integrity_test_limit 9;;
			99)
				dynamic_measure_test_simple;;
		esac
		#rmmod get_tpcmlog
		rm $TPCM_PIK_HANDLE_FILE -fr

	done
}

main
