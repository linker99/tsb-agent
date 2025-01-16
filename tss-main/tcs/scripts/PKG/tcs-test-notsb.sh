#!/bin/sh

OWNER_PWD="httc@123"
ROOT_CERT_ID="root-cert"
GRANT_CERT_ID="grant-cert"
BMEASURE_UID="bmeasure-uid"
FILE_INTEGRITY_UID="file-integrity-uid"
DMEASURE_UID="dmeasure-uid"
GLOBAL_POLICY_UID="global-uid"
PROCESS_UID="process-uid"
PTRACE_PROTECT_UID="ptrace-protect-uid"
TNC_UID="tnc-uid"
ADMIN_POLICY_NAME="tpcmpolicy"

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

exec_check ()
{
	if [ ! $? -eq 0 ]; then
		error "$1 error!"
		exit 1
	else
		info "$1 pass!"
	fi
}

right_check ()
{
	if [ $? -eq 0 ]; then
		error "$1 error!"
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
	./user/test/tcs/update_file_integrity -o 0 -F 0x1 -d $im_dir -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "update_file_integrity"	
	
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
}

simple_intercept_measure_test ()
{
	echo ">>> simple_intercept_measure_test <<<"
	
	echo "设置根证书"
	./user/test/tcs/auth -n $ROOT_CERT_ID -c 1 -d $ROOT_PUBKEY -o 0 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_set_admin_cert"
	echo "设置二级证书"
	./user/test/tcs/auth -n $FILE_INTEGRITY_UID -c 1 -d $FILE_INTEGRITY_PUBKEY -o 1 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_grant_admin_role"
	echo "设置默认全局策略"	
	./user/test/tcs/global_control_policy -a 1 -o 0 -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "tcs_set_global_control_policy"
	echo "更新文件完整性基准库"
	./user/test/tcs/update_file_integrity -o 0 -F 0x1 -d $im_dir -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "update_file_integrity"
	
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
}

global_policy_test ()
{
	echo ">>> global_policy_test <<<"
	echo "测试设置默认全局控制策略"
	./user/test/tcs/tcs_init $OWNER_PWD
	./user/test/tcs/generate_tpcm_pik $OWNER_PWD; exec_check "generate_tpcm_pik"
	./user/test/tcs/auth -n $GLOBAL_POLICY_UID -c 1 -d $GLOBAL_POLICY_PUBKEY -o 1 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_grant_admin_role"
	### 设置全局控制策略
	./user/test/tcs/global_control_policy -a 1 -k $GLOBAL_POLICY_PRIVKEY$GLOBAL_POLICY_PUBKEY -u $GLOBAL_POLICY_UID -o 0; exec_check "tcs_set_global_control_policy"
	### 获取全局控制策略
	./user/test/tcs/global_control_policy -o 1; exec_check "tcs_get_global_control_policy"
	
	echo "测试设置全局控制策略，策略防重放开启"
	### 设置全局控制策略  policy_replay_check check
	./user/test/tcs/global_control_policy -a 1 -k $GLOBAL_POLICY_PRIVKEY$GLOBAL_POLICY_PUBKEY -u $GLOBAL_POLICY_UID -o 0 -p 6 -v 1; exec_check "tcs_set_global_control_policy [policy_replay_check check]"
	./user/test/tcs/global_control_policy -o 1; exec_check "tcs_get_global_control_policy [policy_replay_check check]"
	./user/test/tcs/global_control_policy -a 1 -k $GLOBAL_POLICY_PRIVKEY$GLOBAL_POLICY_PUBKEY -u $GLOBAL_POLICY_UID -o 0; exec_check "tcs_set_global_control_policy"
	./user/test/tcs/global_control_policy -o 1; exec_check "tcs_get_global_control_policy"
	echo "测试获取策略报告"
	### 获取策略报告
	./user/test/tcs/global_control_policy -o 2; exec_check "tcs_get_policy_report"
}

boot_measure_test ()
{
	echo ">>> boot_measure_test <<<"
	
	### 设置根证书
	./user/test/tcs/auth -n $ROOT_CERT_ID -c 1 -d $ROOT_PUBKEY -o 0 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_set_admin_cert"
	### 设置二级证书
	./user/test/tcs/auth -n $BMEASURE_UID -c 1 -d $BMEASURE_PUBKEY -o 1 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_grant_admin_role"
	
	echo "设置默认全局策略"	
	./user/test/tcs/global_control_policy -a 1 -o 0 -u $BMEASURE_UID -k $BMEASURE_PRIVKEY$BMEASURE_PUBKEY; exec_check "tcs_set_global_control_policy"
	echo "打开启动度量开关"
	./user/test/tcs/global_control_policy -a 1 -o 0 -p 1 -v 1 -u $BMEASURE_UID -k $BMEASURE_PRIVKEY$BMEASURE_PUBKEY; exec_check "tcs_set_global_control_policy"
	echo "打开启动度量控制开关"
	./user/test/tcs/global_control_policy -a 1 -o 0 -p 4 -v 1 -u $BMEASURE_UID -k $BMEASURE_PRIVKEY$BMEASURE_PUBKEY; exec_check "tcs_set_global_control_policy"
	
	echo "获取启动度量记录"
	./user/test/tcs/get_bmeasure_records; exec_check "get_bmeasure_records"
	echo "获取启动度量基准值"
	./user/test/tcs/get_bmeasure_references; exec_check "get_bmeasure_references"

	#echo "设置管理认证策略，证书认证"
	#./user/test/tcs/admin_auth_policy -U $ROOT_CERT_ID  -o 0 -i 1 -a 0 -f 0x28 -c 1 -k $ROOT_PRIVKEY$ROOT_PUBKEY -n $ADMIN_POLICY_NAME; exec_check "tcs_set_admin_auth_policies"
	echo "根证书认证，不指定证书，携带认证参数"
	./user/test/tcs/update_bmeasure_references -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "update_bmeasure_references"
	echo "根证书认证，指定证书，携带认证参数"
	./user/test/tcs/update_bmeasure_references -u $ROOT_CERT_ID -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "update_bmeasure_references"
	echo "根证书认证，指定证书，不携带认证参数"
	./user/test/tcs/update_bmeasure_references -u $ROOT_CERT_ID; right_check "update_bmeasure_references"
	echo "根证书认证，不指定证书，不携带认证参数"
	./user/test/tcs/update_bmeasure_references; right_check "update_bmeasure_references"
	echo "二级证书认证，不指定证书，携带认证参数"
	./user/test/tcs/update_bmeasure_references -k $BMEASURE_PRIVKEY$BMEASURE_PUBKEY; right_check "update_bmeasure_references"
	echo "二级证书认证，指定证书，不携带认证参数"
	./user/test/tcs/update_bmeasure_references -u $BMEASURE_UID; right_check "update_bmeasure_references"
	echo "二级证书认证，指定证书，携带认证参数"
	./user/test/tcs/update_bmeasure_references -u $BMEASURE_UID -k $BMEASURE_PRIVKEY$BMEASURE_PUBKEY; exec_check "update_bmeasure_references"
:<<!
	#echo "设置管理认证策略，策略认证"
	#./user/test/tcs/admin_auth_policy -U $ROOT_CERT_ID -o 0 -i 1 -a 1 -f 0x28 -c 1 -k $ROOT_PRIVKEY$ROOT_PUBKEY -n $ADMIN_POLICY_NAME; exec_check "tcs_set_admin_auth_policies"	
	
	echo "根证书认证，不指定证书，携带认证参数"
	./user/test/tcs/update_bmeasure_references -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "update_bmeasure_references"
	echo "根证书认证，指定证书，携带认证参数"
	./user/test/tcs/update_bmeasure_references -u $ROOT_CERT_ID -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "update_bmeasure_references"
	echo "根证书认证，指定证书，不携带认证参数"
	./user/test/tcs/update_bmeasure_references -u $ROOT_CERT_ID; exec_check "update_bmeasure_references"
	echo "根证书认证，不指定证书，不携带认证参数"
	./user/test/tcs/update_bmeasure_references; exec_check "update_bmeasure_references"
	echo "二级证书认证，不指定证书，携带认证参数"
	./user/test/tcs/update_bmeasure_references -k $BMEASURE_PRIVKEY$BMEASURE_PUBKEY; exec_check "update_bmeasure_references"
	echo "二级证书认证，指定证书，不携带认证参数"
	./user/test/tcs/update_bmeasure_references -u $BMEASURE_UID; exec_check "update_bmeasure_references"
	echo "二级证书认证，指定证书，携带认证参数"
	./user/test/tcs/update_bmeasure_references -u $BMEASURE_UID -k $BMEASURE_PRIVKEY$BMEASURE_PUBKEY; exec_check "update_bmeasure_references"

    echo "修改策略，使策略认证失败"
	rmmod update_auth_policy
	insmod ./kernel/test/tcs/update_auth_policy.ko ;exec_check " insmod update_auth_policy.ko"
	echo "根证书认证，不指定证书，携带认证参数"
	./user/test/tcs/update_bmeasure_references -k $ROOT_PRIVKEY$ROOT_PUBKEY; right_check "update_bmeasure_references"
	echo "根证书认证，指定证书，携带认证参数"
	./user/test/tcs/update_bmeasure_references -u $ROOT_CERT_ID -k $ROOT_PRIVKEY$ROOT_PUBKEY; right_check "update_bmeasure_references"
	echo "根证书认证，指定证书，不携带认证参数"
	./user/test/tcs/update_bmeasure_references -u $ROOT_CERT_ID; right_check "update_bmeasure_references"
	echo "根证书认证，不指定证书，不携带认证参数"
	./user/test/tcs/update_bmeasure_references; right_check "update_bmeasure_references"
	echo "二级证书认证，不指定证书，携带认证参数"
	./user/test/tcs/update_bmeasure_references -k $BMEASURE_PRIVKEY$BMEASURE_PUBKEY; right_check "update_bmeasure_references"
	echo "二级证书认证，指定证书，不携带认证参数"
	./user/test/tcs/update_bmeasure_references -u $BMEASURE_UID; right_check "update_bmeasure_references"
	echo "二级证书认证，指定证书，携带认证参数"
	./user/test/tcs/update_bmeasure_references -u $BMEASURE_UID -k $BMEASURE_PRIVKEY$BMEASURE_PUBKEY; right_check "update_bmeasure_references"	
	echo "修改策略，使策略认证成功"
	rmmod update_auth_policy.ko ;exec_check "rmmod update_auth_policy.ko"
!	

	#echo "设置管理认证策略，策略或证书认证"
	#./user/test/tcs/admin_auth_policy -U $ROOT_CERT_ID -o 0 -i 1 -a 2 -f 0x28 -c 1 -k $ROOT_PRIVKEY$ROOT_PUBKEY -n $ADMIN_POLICY_NAME; exec_check "tcs_set_admin_auth_policies"
	echo "根证书认证，不指定证书，携带认证参数"
	./user/test/tcs/update_bmeasure_references -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "update_bmeasure_references"
	echo "根证书认证，指定证书，携带认证参数"
	./user/test/tcs/update_bmeasure_references -u $ROOT_CERT_ID -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "update_bmeasure_references"
	echo "根证书认证，指定证书，不携带认证参数"
	./user/test/tcs/update_bmeasure_references -u $ROOT_CERT_ID; exec_check "update_bmeasure_references"
	echo "根证书认证，不指定证书，不携带认证参数"
	./user/test/tcs/update_bmeasure_references; exec_check "update_bmeasure_references"
	echo "二级证书认证，不指定证书，携带认证参数"
	./user/test/tcs/update_bmeasure_references -k $BMEASURE_PRIVKEY$BMEASURE_PUBKEY; exec_check "update_bmeasure_references"
	echo "二级证书认证，指定证书，不携带认证参数"
	./user/test/tcs/update_bmeasure_references -u $BMEASURE_UID; exec_check "update_bmeasure_references"
:<<!
	echo "修改策略，使策略认证失败"
	rmmod update_auth_policy
	rmmod update_auth_policy.ko
	insmod ./kernel/test/tcs/update_auth_policy.ko ;exec_check " insmod update_auth_policy.ko"
	echo "根证书认证，不指定证书，携带认证参数"
	./user/test/tcs/update_bmeasure_references -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "update_bmeasure_references"
	echo "根证书认证，指定证书，携带认证参数"
	./user/test/tcs/update_bmeasure_references -u $ROOT_CERT_ID -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "update_bmeasure_references"
	echo "根证书认证，指定证书，不携带认证参数"
	./user/test/tcs/update_bmeasure_references -u $ROOT_CERT_ID; right_check "update_bmeasure_references"
	echo "根证书认证，不指定证书，不携带认证参数"
	./user/test/tcs/update_bmeasure_references; right_check "update_bmeasure_references"
	echo "二级证书认证，不指定证书，携带认证参数"
	./user/test/tcs/update_bmeasure_references -k $BMEASURE_PRIVKEY$BMEASURE_PUBKEY; right_check "update_bmeasure_references"
	echo "二级证书认证，指定证书，不携带认证参数"
	./user/test/tcs/update_bmeasure_references -u $BMEASURE_UID; right_check "update_bmeasure_references"
	echo "二级证书认证，指定证书，携带认证参数"
	./user/test/tcs/update_bmeasure_references -u $BMEASURE_UID -k $BMEASURE_PRIVKEY$BMEASURE_PUBKEY; exec_check "update_bmeasure_references"	
	echo "修改策略，使策略认证成功"
	rmmod update_auth_policy.ko	;exec_check "rmmod update_auth_policy.ko"
!
	
	#echo "设置管理认证策略，策略和证书认证"
	#./user/test/tcs/admin_auth_policy -U $ROOT_CERT_ID -o 0 -i 1 -a 3 -f 0x28 -c 1 -k $ROOT_PRIVKEY$ROOT_PUBKEY -n $ADMIN_POLICY_NAME; exec_check "tcs_set_admin_auth_policies"
	echo "根证书认证，不指定证书，携带认证参数"
	./user/test/tcs/update_bmeasure_references -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "update_bmeasure_references"
	echo "根证书认证，指定证书，携带认证参数"
	./user/test/tcs/update_bmeasure_references -u $ROOT_CERT_ID -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "update_bmeasure_references"
	echo "根证书认证，指定证书，不携带认证参数"
	./user/test/tcs/update_bmeasure_references -u $ROOT_CERT_ID; right_check "update_bmeasure_references"
	echo "根证书认证，不指定证书，不携带认证参数"
	./user/test/tcs/update_bmeasure_references; right_check "update_bmeasure_references"
	echo "二级证书认证，不指定证书，携带认证参数"
	./user/test/tcs/update_bmeasure_references -k $BMEASURE_PRIVKEY$BMEASURE_PUBKEY; right_check "update_bmeasure_references"
	echo "二级证书认证，指定证书，不携带认证参数"
	./user/test/tcs/update_bmeasure_references -u $BMEASURE_UID; right_check "update_bmeasure_references"
	echo "二级证书认证，指定证书，携带认证参数"
	./user/test/tcs/update_bmeasure_references -u $BMEASURE_UID -k $BMEASURE_PRIVKEY$BMEASURE_PUBKEY; exec_check "update_bmeasure_references"
:<<!
	echo "修改策略，使策略认证失败"
	rmmod update_auth_policy
	rmmod update_auth_policy.ko
	insmod ./kernel/test/tcs/update_auth_policy.ko ;exec_check " insmod update_auth_policy.ko"
	echo "根证书认证，不指定证书，携带认证参数"
	./user/test/tcs/update_bmeasure_references -k $ROOT_PRIVKEY$ROOT_PUBKEY; right_check "update_bmeasure_references"
	echo "根证书认证，指定证书，携带认证参数"
	./user/test/tcs/update_bmeasure_references -u $ROOT_CERT_ID -k $ROOT_PRIVKEY$ROOT_PUBKEY; right_check "update_bmeasure_references"
	echo "根证书认证，指定证书，不携带认证参数"
	./user/test/tcs/update_bmeasure_references -u $ROOT_CERT_ID; right_check "update_bmeasure_references"
	echo "根证书认证，不指定证书，不携带认证参数"
	./user/test/tcs/update_bmeasure_references; right_check "update_bmeasure_references"
	echo "二级证书认证，不指定证书，携带认证参数"
	./user/test/tcs/update_bmeasure_references -k $BMEASURE_PRIVKEY$BMEASURE_PUBKEY; right_check "update_bmeasure_references"
	echo "二级证书认证，指定证书，不携带认证参数"
	./user/test/tcs/update_bmeasure_references -u $BMEASURE_UID; right_check "update_bmeasure_references"
	echo "二级证书认证，指定证书，携带认证参数"
	./user/test/tcs/update_bmeasure_references -u $BMEASURE_UID -k $BMEASURE_PRIVKEY$BMEASURE_PUBKEY; right_check "update_bmeasure_references"
	echo "修改策略，使策略认证成功"
	rmmod update_auth_policy.ko ;exec_check "rmmod update_auth_policy.ko"
!
	#echo "设置管理认证策略，证书认证"
	#./user/test/tcs/admin_auth_policy -U $ROOT_CERT_ID  -o 0 -i 1 -a 0 -f 0x28 -c 1 -k $ROOT_PRIVKEY$ROOT_PUBKEY -n $ADMIN_POLICY_NAME; exec_check "tcs_set_admin_auth_policies"
	echo "获取启动度量记录"
	./user/test/tcs/get_bmeasure_records; exec_check "get_bmeasure_records"
	echo "获取启动度量基准值"
	./user/test/tcs/get_bmeasure_references; exec_check "get_bmeasure_references"
	echo "更新启动度量基准值"
	./user/test/tcs/update_bmeasure_references -u $BMEASURE_UID -k $BMEASURE_PRIVKEY$BMEASURE_PUBKEY; exec_check "update_bmeasure_references"
	echo "获取启动度量基准值"
	./user/test/tcs/get_bmeasure_references; exec_check "get_bmeasure_references"
	
	#./user/test/tcs/update_bmeasure_references -m 1000 -u $BMEASURE_UID -k $BMEASURE_PRIVKEY$BMEASURE_PUBKEY; exec_check "update_bmeasure_references"
	#./user/test/tcs/get_bmeasure_references; exec_check "get_bmeasure_references"	
}

dynamic_measure_test ()
{
	echo ">>> dynamic_measure_test <<<"	
	./user/test/tcs/tcs_init $OWNER_PWD
	./user/test/tcs/generate_tpcm_pik $OWNER_PWD; exec_check "generate_tpcm_pik"
	
	echo "设置根证书"
	./user/test/tcs/auth -n $ROOT_CERT_ID -c 1 -d $ROOT_PUBKEY -o 0 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_set_admin_cert"
	echo "设置二级证书"
	./user/test/tcs/auth -n $DMEASURE_UID -c 1 -d $DMEASURE_PUBKEY -o 1 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_grant_admin_role"
	
	echo "打开动态度量控制开关"
	./user/test/tcs/global_control_policy -a 1 -o 0 -p 3 -v 1 -u $DMEASURE_UID -k $DMEASURE_PRIVKEY$DMEASURE_PUBKEY; exec_check "tcs_set_global_control_policy"

	echo "获取动态度量策略"
	./user/test/tcs/get_dmeasure_policy; exec_check "get_dmeasure_policy"
	
	echo "根证书认证，不指定证书，携带认证参数"
	./user/test/tcs/update_dmeasure_policy -o 0 -d 10000 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "update_dmeasure_policy"
	echo "根证书认证，指定证书，携带认证参数"
	./user/test/tcs/update_dmeasure_policy -o 0 -d 10000 -u $ROOT_CERT_ID -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "update_dmeasure_policy"
	echo "根证书认证，指定证书，不携带认证参数"
	./user/test/tcs/update_dmeasure_policy -o 0 -d 10000 -u $ROOT_CERT_ID; right_check "update_dmeasure_policy"
	echo "根证书认证，不指定证书，不携带认证参数"
	./user/test/tcs/update_dmeasure_policy -o 0 -d 10000; right_check "update_dmeasure_policy"
	echo "二级证书认证，不指定证书，携带认证参数"
	./user/test/tcs/update_dmeasure_policy -o 0 -d 10000 -k $DMEASURE_PRIVKEY$DMEASURE_PUBKEY; right_check "update_dmeasure_policy"
	echo "二级证书认证，指定证书，不携带认证参数"
	./user/test/tcs/update_dmeasure_policy -o 0 -d 10000 -u $DMEASURE_UID; right_check "update_dmeasure_policy"

	echo "获取动态度量策略"
	./user/test/tcs/get_dmeasure_policy; exec_check "get_dmeasure_policy"
	echo "清空动态度量策略"
	./user/test/tcs/update_dmeasure_policy -o 0 -d 10000 -n none -u $DMEASURE_UID -k $DMEASURE_PRIVKEY$DMEASURE_PUBKEY; exec_check "update_dmeasure_policy"
	echo "获取动态度量策略"
	./user/test/tcs/get_dmeasure_policy; exec_check "get_dmeasure_policy"

	echo "下发动态度量策略"
	./user/test/tcs/update_dmeasure_policy -o 0 -d 10000 -u $DMEASURE_UID -k $DMEASURE_PRIVKEY$DMEASURE_PUBKEY; exec_check "update_dmeasure_policy"
	echo "获取动态度量策略"
	./user/test/tcs/get_dmeasure_policy; exec_check "get_dmeasure_policy"
	echo "采集度量"
	insmod ./kernel/test/tcs/collect_measure.ko ; exec_check "collect_measure.ko"
	rmmod collect_measure

	### 删除syscall_table
	#./user/test/tcs/update_dmeasure_policy -o 2 -n syscall_table -d 10000 -u $DMEASURE_UID -k $DMEASURE_PRIVKEY$DMEASURE_PUBKEY; exec_check "update_dmeasure_policy"
	#./user/test/tcs/get_dmeasure_policy; exec_check "get_dmeasure_policy"
	
	### 清空动态度量策略
	#./user/test/tcs/update_dmeasure_policy -o 0 -n none -u $DMEASURE_UID -k $DMEASURE_PRIVKEY$DMEASURE_PUBKEY; exec_check "update_dmeasure_policy"
	#./user/test/tcs/get_dmeasure_policy; exec_check "get_dmeasure_policy"

	#./user/test/tcs/update_dmeasure_policy -o 0 -n tsb_test -d 10 -u $DMEASURE_UID -k $DMEASURE_PRIVKEY$DMEASURE_PUBKEY; exec_check "update_dmeasure_policy"
	#insmod ./kernel/test/tcs/collect_measure.ko dmname=tsb_test ; exec_check "collect_measure.ko"
	#rmmod collect_measure	
}

process_dmeasure_test ()
{
	echo ">>> process_dmeasure_test <<<"
	
	echo "设置根证书"
	./user/test/tcs/auth -n $ROOT_CERT_ID -c 1 -d $ROOT_PUBKEY -o 0 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_set_admin_cert"
	echo "设置二级证书"
	./user/test/tcs/auth -n $DMEASURE_UID -c 1 -d $DMEASURE_PUBKEY -o 1 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_grant_admin_role"
	
	echo "根证书认证，不指定证书，携带认证参数"
	./user/test/tcs/update_dmeasure_process_policy -n 1 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "update_dmeasure_process_policy"
	echo "根证书认证，指定证书，携带认证参数"
	./user/test/tcs/update_dmeasure_process_policy -n 1 -u $ROOT_CERT_ID -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "update_dmeasure_process_policy"
	echo "根证书认证，指定证书，不携带认证参数"
	./user/test/tcs/update_dmeasure_process_policy -n 1 -u $ROOT_CERT_ID; right_check "update_dmeasure_process_policy"
	echo "根证书认证，不指定证书，不携带认证参数"
	./user/test/tcs/update_dmeasure_process_policy -n 1; right_check "update_dmeasure_process_policy"
	echo "二级证书认证，不指定证书，携带认证参数"
	./user/test/tcs/update_dmeasure_process_policy -n 1 -k $DMEASURE_PRIVKEY$DMEASURE_PUBKEY; right_check "update_dmeasure_process_policy"
	echo "二级证书认证，指定证书，不携带认证参数"
	./user/test/tcs/update_dmeasure_process_policy -n 1 -u $DMEASURE_UID; right_check "update_dmeasure_process_policy"
	
	echo "获取进程动态度量策略"
	./user/test/tcs/get_dmeasure_process_policy; exec_check "get_dmeasure_process_policy"
	echo "清空进程动态度量策略"
	./user/test/tcs/update_dmeasure_process_policy -n 0 -u $DMEASURE_UID -k $DMEASURE_PRIVKEY$DMEASURE_PUBKEY; exec_check "update_dmeasure_process_policy"
	echo "获取进程动态度量策略"
	./user/test/tcs/get_dmeasure_process_policy; exec_check "get_dmeasure_process_policy"
	echo "更新进程动态度量策略"
	./user/test/tcs/update_dmeasure_process_policy -n 3 -u $DMEASURE_UID -k $DMEASURE_PRIVKEY$DMEASURE_PUBKEY; exec_check "update_dmeasure_process_policy"
	echo "获取进程动态度量策略"
	./user/test/tcs/get_dmeasure_process_policy; exec_check "get_dmeasure_process_policy"
	echo "清空进程动态度量策略"
	./user/test/tcs/update_dmeasure_process_policy -n 0 -u $DMEASURE_UID -k $DMEASURE_PRIVKEY$DMEASURE_PUBKEY; exec_check "update_dmeasure_process_policy"
	echo "获取进程动态度量策略"
	./user/test/tcs/get_dmeasure_process_policy; exec_check "get_dmeasure_process_policy"
}

ptrace_protect_test ()
{
	echo ">>> ptrace_protect_test <<<"
	
	echo "设置根证书"
	./user/test/tcs/auth -n $ROOT_CERT_ID -c 1 -d $ROOT_PUBKEY -o 0 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_set_admin_cert"
	echo "设置二级证书"
	./user/test/tcs/auth -n $PTRACE_PROTECT_UID -c 1 -d $PTRACE_PROTECT_PUBKEY -o 1 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_grant_admin_role"

	echo "获取进程跟踪防护策略"
	./user/test/tcs/get_ptrace_protect_policy; exec_check "get_ptrace_protect_policy"

	echo "根证书认证，不指定证书，携带认证参数"
	./user/test/tcs/update_ptrace_protect_policy -o 0 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "update_ptrace_protect_policy"
	echo "根证书认证，指定证书，携带认证参数"
	./user/test/tcs/update_ptrace_protect_policy -o 0 -u $ROOT_CERT_ID -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "update_ptrace_protect_policy"
	echo "根证书认证，指定证书，不携带认证参数"
	./user/test/tcs/update_ptrace_protect_policy -o 0 -u $ROOT_CERT_ID; right_check "update_ptrace_protect_policy"
	echo "根证书认证，不指定证书，不携带认证参数"
	./user/test/tcs/update_ptrace_protect_policy -o 0; right_check "update_ptrace_protect_policy"
	echo "二级证书认证，不指定证书，携带认证参数"
	./user/test/tcs/update_ptrace_protect_policy -o 0 -k $PTRACE_PROTECT_PRIVKEY$PTRACE_PROTECT_PUBKEY; right_check "update_ptrace_protect_policy"
	echo "二级证书认证，指定证书，不携带认证参数"
	./user/test/tcs/update_ptrace_protect_policy -o 0 -u $PTRACE_PROTECT_UID; right_check "update_ptrace_protect_policy"
	
	echo "获取进程跟踪防护策略"
	./user/test/tcs/get_ptrace_protect_policy; exec_check "get_ptrace_protect_policy"
	echo "清空进程跟踪防护策略"
	./user/test/tcs/update_ptrace_protect_policy -o 2 -u $PTRACE_PROTECT_UID -k $PTRACE_PROTECT_PRIVKEY$PTRACE_PROTECT_PUBKEY; exec_check "update_ptrace_protect_policy"
	echo "获取进程跟踪防护策略"
	./user/test/tcs/get_ptrace_protect_policy; exec_check "get_ptrace_protect_policy"
	echo "更新进程跟踪防护策略"
	./user/test/tcs/update_ptrace_protect_policy -o 0 -u $PTRACE_PROTECT_UID -k $PTRACE_PROTECT_PRIVKEY$PTRACE_PROTECT_PUBKEY; exec_check "update_ptrace_protect_policy"
	echo "获取进程跟踪防护策略"
	./user/test/tcs/get_ptrace_protect_policy; exec_check "get_ptrace_protect_policy"
}

file_integrity_test ()
{
	echo ">>> file_integrity_test <<<"
	echo "设置根证书"
	./user/test/tcs/auth -n $ROOT_CERT_ID -c 1 -d $ROOT_PUBKEY -o 0 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_set_admin_cert"
	echo "设置二级证书"
	./user/test/tcs/auth -n $FILE_INTEGRITY_UID -c 1 -d $FILE_INTEGRITY_PUBKEY -o 1 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_grant_admin_role"

	echo "设置默认全局策略"	
	./user/test/tcs/global_control_policy -a 1 -o 0 -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "tcs_set_global_control_policy"

	echo "打开文件完整性度量开关"
	./user/test/tcs/global_control_policy -a 1 -o 0 -p 2 -v 1 -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "tcs_set_global_control_policy"
	echo "打开文件完整性度量控制开关"
	./user/test/tcs/global_control_policy -a 1 -o 0 -p 5 -v 1 -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "tcs_set_global_control_policy"
	#./user/test/tcs/global_control_policy -o 1; exec_check "tcs_get_global_control_policy [policy_replay_check check]"
	
	echo "获取文件完整性基准库单次可更改条数限制"
	./user/test/tcs/get_file_integrity_modify_number_limit; exec_check "get_file_integrity_modify_number_limit"
	echo "获取文件完整性基准库总条数"
	./user/test/tcs/get_file_integrity_total_number; exec_check "get_file_integrity_total_number"
	echo "获取文件完整性基准库有效条数"
	./user/test/tcs/get_file_integrity_valid_number; exec_check "get_file_integrity_valid_number"
	
	#echo "证书认证"
	#./user/test/tcs/admin_auth_policy -U $ROOT_CERT_ID -o 0 -i 2 -a 0 -f 0x28 -c 1 -n $ADMIN_POLICY_NAME -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_set_admin_auth_policies"
	echo "根证书认证，不指定证书，携带认证参数"
	./user/test/tcs/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "update_file_integrity"
	echo "根证书认证，指定证书，携带认证参数"
	./user/test/tcs/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls -u $ROOT_CERT_ID -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "update_file_integrity"
	echo "根证书认证，指定证书，不携带认证参数"
	./user/test/tcs/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls -u $ROOT_CERT_ID; right_check "update_file_integrity"
	echo "根证书认证，不指定证书，不携带认证参数"
	./user/test/tcs/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls; right_check "update_file_integrity"
	echo "二级证书认证，不指定证书，携带认证参数"
	./user/test/tcs/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; right_check "update_file_integrity"
	echo "二级证书认证，指定证书，不携带认证参数"
	./user/test/tcs/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls -u $FILE_INTEGRITY_UID; right_check "update_file_integrity"
((0))&&{
	echo "设置管理认证策略，策略认证"
	./user/test/tcs/admin_auth_policy -U $ROOT_CERT_ID -o 0 -i 2 -a 1 -f 0x28 -c 1 -n $ADMIN_POLICY_NAME -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_set_admin_auth_policies"
	echo "修改策略，使策略认证失败"
	insmod ./kernel/test/tcs/update_auth_policy.ko ;exec_check "update_auth_policy.ko"

	echo "根证书认证，不指定证书，携带认证参数"
	./user/test/tcs/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls -k $ROOT_PRIVKEY$ROOT_PUBKEY; right_check "update_file_integrity"
	echo "根证书认证，指定证书，携带认证参数"
	./user/test/tcs/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls -u $ROOT_CERT_ID -k $ROOT_PRIVKEY$ROOT_PUBKEY; right_check "update_file_integrity"
	echo "根证书认证，指定证书，不携带认证参数"
	./user/test/tcs/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls -u $ROOT_CERT_ID; right_check "update_file_integrity"
	echo "根证书认证，不指定证书，不携带认证参数"
	./user/test/tcs/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls; right_check "update_file_integrity"
	echo "二级证书认证，不指定证书，携带认证参数"
	./user/test/tcs/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; right_check "update_file_integrity"
	echo "二级证书认证，指定证书，不携带认证参数"
	./user/test/tcs/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls -u $FILE_INTEGRITY_UID; right_check "update_file_integrity"

	echo "修改策略，使策略认证成功"
	rmmod update_auth_policy.ko	
	echo "根证书认证，不指定证书，携带认证参数"
	./user/test/tcs/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "update_file_integrity"
	echo "根证书认证，指定证书，携带认证参数"
	./user/test/tcs/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls -u $ROOT_CERT_ID -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "update_file_integrity"
	echo "根证书认证，指定证书，不携带认证参数"
	./user/test/tcs/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls -u $ROOT_CERT_ID; exec_check "update_file_integrity"
	echo "根证书认证，不指定证书，不携带认证参数"
	./user/test/tcs/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls; exec_check "update_file_integrity"
	echo "二级证书认证，不指定证书，携带认证参数"
	./user/test/tcs/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "update_file_integrity"
	echo "二级证书认证，指定证书，不携带认证参数"
	./user/test/tcs/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls -u $FILE_INTEGRITY_UID; exec_check "update_file_integrity"

	echo "设置管理认证策略，证书或策略认证"
	./user/test/tcs/admin_auth_policy -U $ROOT_CERT_ID -o 0 -i 2 -a 2 -f 0x28 -c 1 -n $ADMIN_POLICY_NAME -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_set_admin_auth_policies"

	echo "修改策略，使策略认证失败"
	insmod ./kernel/test/tcs/update_auth_policy.ko ;exec_check "update_auth_policy.ko"
	echo "根证书认证，不指定证书，携带认证参数"
	./user/test/tcs/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "update_file_integrity"
	echo "根证书认证，指定证书，携带认证参数"
	./user/test/tcs/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls -u $ROOT_CERT_ID -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "update_file_integrity"
	echo "根证书认证，指定证书，不携带认证参数"
	./user/test/tcs/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls -u $ROOT_CERT_ID; right_check "update_file_integrity"
	echo "根证书认证，不指定证书，不携带认证参数"
	./user/test/tcs/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls; right_check "update_file_integrity"
	echo "二级证书认证，不指定证书，携带认证参数"
	./user/test/tcs/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; right_check "update_file_integrity"
	echo "二级证书认证，指定证书，不携带认证参数"
	./user/test/tcs/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls -u $FILE_INTEGRITY_UID; right_check "update_file_integrity"
	echo "修改策略，使策略认证成功"
	rmmod update_auth_policy.ko	
	echo "根证书认证，不指定证书，携带认证参数"
	./user/test/tcs/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "update_file_integrity"
	echo "根证书认证，指定证书，携带认证参数"
	./user/test/tcs/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls -u $ROOT_CERT_ID -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "update_file_integrity"
	echo "根证书认证，指定证书，不携带认证参数"
	./user/test/tcs/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls -u $ROOT_CERT_ID; exec_check "update_file_integrity"
	echo "根证书认证，不指定证书，不携带认证参数"
	./user/test/tcs/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls; exec_check "update_file_integrity"
	echo "二级证书认证，不指定证书，携带认证参数"
	./user/test/tcs/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "update_file_integrity"
	echo "二级证书认证，指定证书，不携带认证参数"
	./user/test/tcs/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls -u $FILE_INTEGRITY_UID; exec_check "update_file_integrity"


	echo "设置管理认证策略，证书和策略认证"
	./user/test/tcs/admin_auth_policy -U $ROOT_CERT_ID -o 0 -i 2 -a 3 -f 0x28 -c 1 -n $ADMIN_POLICY_NAME -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_set_admin_auth_policies"

	echo "修改策略，使策略认证失败"
	insmod ./kernel/test/tcs/update_auth_policy.ko ;exec_check "update_auth_policy.ko"
	echo "根证书认证，不指定证书，携带认证参数"
	./user/test/tcs/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls -k $ROOT_PRIVKEY$ROOT_PUBKEY; right_check "update_file_integrity"
	echo "根证书认证，指定证书，携带认证参数"
	./user/test/tcs/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls -u $ROOT_CERT_ID -k $ROOT_PRIVKEY$ROOT_PUBKEY; right_check "update_file_integrity"
	echo "根证书认证，指定证书，不携带认证参数"
	./user/test/tcs/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls -u $ROOT_CERT_ID; right_check "update_file_integrity"
	echo "根证书认证，不指定证书，不携带认证参数"
	./user/test/tcs/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls; right_check "update_file_integrity"
	echo "二级证书认证，不指定证书，携带认证参数"
	./user/test/tcs/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; right_check "update_file_integrity"
	echo "二级证书认证，指定证书，不携带认证参数"
	./user/test/tcs/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls -u $FILE_INTEGRITY_UID; right_check "update_file_integrity"
	echo "修改策略，使策略认证成功"
	rmmod update_auth_policy.ko	
	echo "根证书认证，不指定证书，携带认证参数"
	./user/test/tcs/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "update_file_integrity"
	echo "根证书认证，指定证书，携带认证参数"
	./user/test/tcs/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls -u $ROOT_CERT_ID -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "update_file_integrity"
	echo "根证书认证，指定证书，不携带认证参数"
	./user/test/tcs/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls -u $ROOT_CERT_ID; right_check "update_file_integrity"
	echo "根证书认证，不指定证书，不携带认证参数"
	./user/test/tcs/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls; right_check "update_file_integrity"
	echo "二级证书认证，不指定证书，携带认证参数"
	./user/test/tcs/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; right_check "update_file_integrity"
	echo "二级证书认证，指定证书，不携带认证参数"
	./user/test/tcs/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls -u $FILE_INTEGRITY_UID; right_check "update_file_integrity"	
}	
	feature_check
	if [ $imeasure -eq 0 ];then
		echo "使能，不含扩展，全路径"
		./user/test/tcs/update_file_integrity -o 0 -p -F 0x5 -f /bin/ls -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "update_file_integrity"
		insmod ./kernel/test/tcs/intercept_measure.ko imname=/bin/ls imtype=1; exec_check "intercept_measure.ko"
		rmmod intercept_measure

		echo "使能，含扩展数据，路径HASH"
		./user/test/tcs/update_file_integrity -o 0 -e -p -F 0x1 -f /bin/ls -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "update_file_integrity"
		insmod ./kernel/test/tcs/intercept_measure.ko imname=/bin/ls imtype=1; exec_check "intercept_measure.ko"
		rmmod intercept_measure

		echo "使能，控制标记置位，全路径，匹配HASH+路径"
		./user/test/tcs/global_control_policy -a 1 -o 0 -p 14 -v 1 -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "tcs_set_global_control_policy"
		./user/test/tcs/update_file_integrity -o 0 -p -F 0x07 -f /bin/ls -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "update_file_integrity"
		insmod ./kernel/test/tcs/intercept_measure.ko imname=/bin/ls imtype=1; exec_check "intercept_measure.ko"
		rmmod intercept_measure
		echo "切换文件路径，匹配CHECK"
		cp /bin/ls `pwd`/
		insmod ./kernel/test/tcs/intercept_measure.ko imname=`pwd`/ls imtype=1; right_check "intercept_measure.ko"
		rmmod intercept_measure
		rm `pwd`/ls -rf
		./user/test/tcs/global_control_policy -a 1 -o 0 -p 14 -v 0 -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "tcs_set_global_control_policy"

		echo "禁用，不含扩展，全路径"
		./user/test/tcs/update_file_integrity -o 0 -p -F 0x4 -f /bin/ls -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "update_file_integrity"
		insmod ./kernel/test/tcs/intercept_measure.ko imname=/bin/ls imtype=1; right_check "intercept_measure.ko"
		rmmod intercept_measure
	fi

	echo "测试追加"
	./user/test/tcs/update_file_integrity -o 0 -F 0x01 -f /bin/ls -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "update_file_integrity"
	./user/test/tcs/update_file_integrity -o 1 -l 20 -F 0x1 -d /usr/bin/ -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "update_file_integrity"
	./user/test/tcs/update_file_integrity -o 1 -F 0x01 -f /bin/bash -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "update_file_integrity"
	./user/test/tcs/get_file_integrity_total_number; exec_check "get_file_integrity_total_number"
	./user/test/tcs/get_file_integrity_valid_number; exec_check "get_file_integrity_valid_number"
	feature_check
	if [ $imeasure -eq 0 ];then
		insmod ./kernel/test/tcs/intercept_measure.ko imname=/bin/bash imtype=1; exec_check "intercept_measure.ko"
		rmmod intercept_measure
	fi

	echo "测试修改"
	./user/test/tcs/update_file_integrity -o 3 -F 0x01 -f /bin/ls -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "update_file_integrity"
	./user/test/tcs/update_file_integrity -o 3 -F 0x01 -f /bin/bash -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "update_file_integrity"
	./user/test/tcs/get_file_integrity_total_number; exec_check "get_file_integrity_total_number"
	./user/test/tcs/get_file_integrity_valid_number; exec_check "get_file_integrity_valid_number"
	
	echo "测试删除"
	./user/test/tcs/update_file_integrity -o 2 -F 0x01 -f /bin/ls -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "update_file_integrity"
	./user/test/tcs/update_file_integrity -o 2 -F 0x01 -f /bin/bash -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "update_file_integrity"
	./user/test/tcs/get_file_integrity_total_number; exec_check "get_file_integrity_total_number"
	./user/test/tcs/get_file_integrity_valid_number; exec_check "get_file_integrity_valid_number"
	feature_check
	if [ $imeasure -eq 0 ];then
		insmod ./kernel/test/tcs/intercept_measure.ko imname=/bin/ls imtype=1; right_check "intercept_measure.ko"
		rmmod intercept_measure
		insmod ./kernel/test/tcs/intercept_measure.ko imname=/bin/bash imtype=1; right_check "intercept_measure.ko"
		rmmod intercept_measure
	fi

	echo "读取文件完整性基准库"
	./user/test/tcs/update_file_integrity -o 0 -p -F 0x5 -d $im_dir -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "update_file_integrity"
	./user/test/tcs/read_file_integrity; exec_check "read_file_integrity"
}

critical_file_integrity_test ()
{
	echo ">>> critical_file_integrity_test <<<"
	echo "设置根证书"
	./user/test/tcs/auth -n $ROOT_CERT_ID -c 1 -d $ROOT_PUBKEY -o 0 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_set_admin_cert"
	echo "设置二级证书"
	./user/test/tcs/auth -n $FILE_INTEGRITY_UID -c 1 -d $FILE_INTEGRITY_PUBKEY -o 1 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_grant_admin_role"

	echo "使能，不含扩展，全路径"
	./user/test/tcs/update_critical_file_integrity -o 0 -p -F 0x5 -f /bin/ls -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "update_critical_file_integrity"
	
	echo "使能，含扩展数据，路径HASH"
	./user/test/tcs/update_critical_file_integrity -o 0 -e -p -F 0x1 -f /bin/ls -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "update_critical_file_integrity"
	
	echo "禁用，不含扩展，全路径"
	./user/test/tcs/update_critical_file_integrity -o 0 -p -F 0x4 -f /bin/ls -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "update_critical_file_integrity"
	
	echo "更新关键文件完整性基准库"
	./user/test/tcs/update_critical_file_integrity -o 0 -p -F 0x5 -l 10 -d $im_dir -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "update_critical_file_integrity"
	echo "获取关键文件完整性基准库摘要值"
	insmod ./kernel/test/tcs/get_critical_file_integrity_digest.ko; exec_check "get_critical_file_integrity_digest.ko"
    rmmod get_critical_file_integrity_digest
	
	echo "清空关键文件完整性基准库"
	./user/test/tcs/update_critical_file_integrity -o 0 -p -F 0x5 -u $FILE_INTEGRITY_UID -k $FILE_INTEGRITY_PRIVKEY$FILE_INTEGRITY_PUBKEY; exec_check "update_critical_file_integrity"
	echo "获取关键文件完整性基准库摘要值"
	insmod ./kernel/test/tcs/get_critical_file_integrity_digest.ko; right_check "get_critical_file_integrity_digest.ko"
    rmmod get_critical_file_integrity_digest
}

license_test ()
{
	echo ">>> license_test <<<"

	echo "获得license状态"
	./user/test/tcs/get_license_status; exec_check "get_license_status"
	echo "获得license信息"
	./user/test/tcs/get_license_info; exec_check "get_license_info"
	echo "获得license实体信息"
	./user/test/tcs/get_license_entity; exec_check "get_license_entity"
	
	echo "TCM初始化"
	./user/test/tcs/tcs_init $OWNER_PWD
	echo "生成tpcm PIK"
	./user/test/tcs/generate_tpcm_pik $OWNER_PWD
	
	echo "获得license状态"
	./user/test/tcs/get_license_status; exec_check "get_license_status"
	echo "获得license信息"
	./user/test/tcs/get_license_info; exec_check "get_license_info"
	echo "获得license实体信息"
	./user/test/tcs/get_license_entity; exec_check "get_license_entity"
	
	echo "重置license"
	./user/test/tcs/reset_test_license; exec_check "reset_test_license"
	echo "获得license状态"
	./user/test/tcs/get_license_status; exec_check "get_license_status"
	echo "获得license信息"
	./user/test/tcs/get_license_info; exec_check "get_license_info"
	echo "获得license实体信息"
	./user/test/tcs/get_license_entity; exec_check "get_license_entity"
	
	echo "TCM初始化"
	./user/test/tcs/tcs_init $OWNER_PWD
	echo "生成tpcm PIK"
	./user/test/tcs/generate_tpcm_pik $OWNER_PWD
	
	echo "请求license"
	./user/test/tcs/license_request; exec_check "license_request"
	echo "获得license状态"
	./user/test/tcs/get_license_status; exec_check "get_license_status"
	echo "获得license信息"
	./user/test/tcs/get_license_info; exec_check "get_license_info"
	echo "获得license实体信息"
	./user/test/tcs/get_license_entity; exec_check "get_license_entity"
	
	echo "导入试用版TPCM的license"
	./user/test/tcs/import_license -t 1; exec_check "import_license"
	echo "获得license状态"
	./user/test/tcs/get_license_status; exec_check "get_license_status"
	echo "获得license信息"
	./user/test/tcs/get_license_info; exec_check "get_license_info"
	echo "获得license实体信息"
	./user/test/tcs/get_license_entity; exec_check "get_license_entity"
	
	echo "导入试用版TSB的license"
	./user/test/tcs/import_license -t 2; exec_check "import_license"
	echo "获得license状态"
	./user/test/tcs/get_license_status; exec_check "get_license_status"
	echo "获得license信息"
	./user/test/tcs/get_license_info; exec_check "get_license_info"
	echo "获得license实体信息"
	./user/test/tcs/get_license_entity; exec_check "get_license_entity"
	
	echo "导入试用版TTM的license"
	./user/test/tcs/import_license -t 3; exec_check "import_license"
	echo "获得license状态"
	./user/test/tcs/get_license_status; exec_check "get_license_status"
	echo "获得license信息"
	./user/test/tcs/get_license_info; exec_check "get_license_info"
	echo "获得license实体信息"
	./user/test/tcs/get_license_entity; exec_check "get_license_entity"

	echo "重置license"
	./user/test/tcs/reset_test_license; exec_check "reset_test_license"
	echo "内核态获取license状态"
	insmod ./kernel/test/tcs/get_license_status.ko; exec_check "get_license_status.ko"
	rmmod get_license_status
	echo "内核态获取license信息"
	insmod ./kernel/test/tcs/get_license_info.ko; exec_check "get_license_info.ko"
	rmmod get_license_info
	echo "内核态获取license实体信息"
	insmod ./kernel/test/tcs/get_license_entity.ko; exec_check "get_license_entity.ko"
	rmmod get_license_entity
}

attest_test ()
{
	echo ">>> attest_test <<<"

	echo "获得tpcm特征"
	./user/test/tcs/get_tpcm_features; exec_check "get_tpcm_features"

	echo "获得tpcm id"
	./user/test/tcs/get_tpcm_id; exec_check "get_tpcm_id"

	echo "获得可信状态"
	./user/test/tcs/get_trust_status; exec_check "get_trust_status"
	feature_check
	
	echo "TCM初始化"
	./user/test/tcs/tcs_init $OWNER_PWD
	echo "生成tpcm PIK"
	./user/test/tcs/generate_tpcm_pik $OWNER_PWD; exec_check "generate_tpcm_pik"

	echo "获取tpcm PIK公钥"
	./user/test/tcs/get_pik_pubkey; exec_check "get_pik_pubkey"

	echo "获取tpcm状态信息"
	./user/test/tcs/get_tpcm_info

	echo "获取可信报告"
	./user/test/tcs/get_trust_report; exec_check "get_trust_report"
	
	echo "HOST ID设置与获取"	
	./user/test/tcs/host_id_set_and_get; exec_check "host_id_set_and_get"
}

volatile_data ()
{
	echo ">>> volatile_data <<<"

	### 存储易失数据
	echo "*** save_mem_data ***"
    echo "index=1 8位密码存储数据"
	insmod ./kernel/test/tcs/save_mem_data.ko index=1 data=01234567 usepasswd=12345678; exec_check "save_mem_data.ko"
	rmmod save_mem_data
    echo "index=2密码小于8位存储数据"
	insmod ./kernel/test/tcs/save_mem_data.ko index=2 data=01234567 usepasswd=123456; right_check "save_mem_data.ko"
    echo "index=3密码大于8位小于32位存储数据"
	insmod ./kernel/test/tcs/save_mem_data.ko index=3 data=01234567 usepasswd=1234567890; exec_check "save_mem_data.ko"
	rmmod save_mem_data
    echo "index=4 32位密码存储数据"
	insmod ./kernel/test/tcs/save_mem_data.ko index=4 data=01234567 usepasswd=01234567890123456789012345678901; exec_check "save_mem_data.ko"
	rmmod save_mem_data
    echo "index=5 密码大于32位存储数据"
	insmod ./kernel/test/tcs/save_mem_data.ko index=5 data=01234567 usepasswd=0123456789012345678901234567890123; right_check "save_mem_data.ko"
    echo "index=6 正常存储存储数据"
	insmod ./kernel/test/tcs/save_mem_data.ko index=6 data=01234567 usepasswd=123456789abc; exec_check "save_mem_data.ko"
	rmmod save_mem_data
    echo "index=6 不同数据存储"
	insmod ./kernel/test/tcs/save_mem_data.ko index=6 data=012345679999 usepasswd=123456789abc; exec_check "save_mem_data.ko"
	rmmod save_mem_data
    echo "index=6 错误密码相同数据存储"
	insmod ./kernel/test/tcs/save_mem_data.ko index=6 data=012345679999 usepasswd=12345678; right_check "save_mem_data.ko"
	echo ""
	
	### 存储易失数据
	 echo "index=7 8位密码存储数据"
	./user/test/tcs/save_mem_data -i 7 -p 12345678 -d helloworld; exec_check "tcs_save_mem_data"
	echo "index=8 密码小于8位存储数据"
	./user/test/tcs/save_mem_data -i 8 -p 123 -d helloworld; right_check "tcs_save_mem_data"
	echo "index=9 密码大于8位小于32位存储数据"
	./user/test/tcs/save_mem_data -i 9 -p 123456789abc -d helloworld; exec_check "tcs_save_mem_data"
	echo "index=10 32位密码存储数据"
	./user/test/tcs/save_mem_data -i 10 -p 01234567890123456789012345678901 -d helloworld; exec_check "tcs_save_mem_data"
	echo "index=11 密码大于32位存储数据"
	./user/test/tcs/save_mem_data -i 11 -p 01234567890123456789012345678901abc -d helloworld; right_check "tcs_save_mem_data"
	echo "index=7 错误密码 相同index存储"
	./user/test/tcs/save_mem_data -i 7 -p 12345678922 -d helloworld; right_check "tcs_save_mem_data"
	
	
	
	
	### 读取易失数据
	echo "*** read_mem_data ***"
    echo "index=1 8位密码读取数据"
	insmod ./kernel/test/tcs/read_mem_data.ko index=1 usepasswd=12345678; exec_check "read_mem_data.ko"
	rmmod read_mem_data
    echo "index=2密码小于8位读取数据"
	insmod ./kernel/test/tcs/read_mem_data.ko index=2 usepasswd=123456; right_check "read_mem_data.ko"
    echo "index=3密码大于8位小于32位读取数据"
	insmod ./kernel/test/tcs/read_mem_data.ko index=3 usepasswd=1234567890; exec_check "read_mem_data.ko"
	rmmod read_mem_data
    echo "index=4 32位密码读取数据"
	insmod ./kernel/test/tcs/read_mem_data.ko index=4 usepasswd=01234567890123456789012345678901; exec_check "read_mem_data.ko"
	rmmod read_mem_data
    echo "index=5 密码大于32位读取数据"
	insmod ./kernel/test/tcs/read_mem_data.ko index=5 usepasswd=0123456789012345678901234567890123; right_check "read_mem_data.ko"
    echo "index=6 正常存读取数据"
	insmod ./kernel/test/tcs/read_mem_data.ko index=6 usepasswd=123456789abc; exec_check "read_mem_data.ko"
	rmmod read_mem_data
    echo "index=6 错误密码读取数据"
	insmod ./kernel/test/tcs/read_mem_data.ko index=6 usepasswd=12345678; right_check "read_mem_data.ko"
	echo ""
	
	### 读取易失数据
	 echo "index=7 8位密码存储数据"
	 ./user/test/tcs/read_mem_data -i 7 -p 12345678; exec_check "tcs_read_mem_data"
	 echo "index=7 错误密码"
	 ./user/test/tcs/read_mem_data -i 7 -p 012345678; right_check "tcs_read_mem_data"
	 echo "index=66 错误index"
	 ./user/test/tcs/read_mem_data -i 66 -p 12345678; right_check "tcs_read_mem_data"
	 
:<<!
	echo "index=12 最大传输存储数据"
	dd if=/dev/zero of=savetestfile bs=2097024 count=1
	./user/test/tcs/save_mem_data -i 12 -p 12345678 -f savetestfile; exec_check "tcs_save_mem_data"
	echo "index=13 超出最大传输存储数据"
	rm -rf savetestfile
	dd if=/dev/zero of=savetestfile bs=2097280 count=1
	./user/test/tcs/save_mem_data -i 13 -p 12345678 -f savetestfile; right_check "tcs_save_mem_data"
	rm -rf savetestfile
	echo "index=12 最大传输存储数据"
	./user/test/tcs/read_mem_data -i 12 -p 12345678; exec_check "tcs_read_mem_data"
!
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
	./user/test/tcs/auth -n $PROCESS_UID -c 1 -d $PROCESS_PUBKEY -o 1 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_grant_admin_role"
	echo "测试进程角色新增"
	### 更新进程角色库
	./user/test/tcs/role -c 1 -k $PROCESS_PRIVKEY$PROCESS_PUBKEY -u $PROCESS_UID -n role -o 0 -t 0; exec_check "tcs_update_process_roles [set]"
	### 更新进程角色库
	./user/test/tcs/role -c 1 -k $PROCESS_PRIVKEY$PROCESS_PUBKEY -u $PROCESS_UID -n role-one -o 0 -t 1; right_check "tcs_update_process_roles [add]"
	### 读取全部进程角色
	./user/test/tcs/role -o 1; exec_check "tcs_get_process_roles"
	
	echo "测试进程角色删除"
	### 更新进程角色库
	./user/test/tcs/role -c 1 -k $PROCESS_PRIVKEY$PROCESS_PUBKEY -u $PROCESS_UID -n role-one -o 0 -t 2; right_check "tcs_update_process_roles [replace]"
	### 更新进程角色库
	./user/test/tcs/role -c 1 -k $PROCESS_PRIVKEY$PROCESS_PUBKEY -u $PROCESS_UID -n role-one -o 0 -t 3; right_check "tcs_update_process_roles [delete]"
	./user/test/tcs/role -o 1; exec_check "tcs_get_process_roles"
	
	echo "测试进程角色设置"
	./user/test/tcs/role -c 1 -k $PROCESS_PRIVKEY$PROCESS_PUBKEY -u $PROCESS_UID -n set-role -o 0 -t 0; exec_check "tcs_update_process_roles [set]"
	./user/test/tcs/role -o 1; exec_check "tcs_get_process_roles"
	
	echo "测试进程身份新增"
	### 更新进程身份
	./user/test/tcs/process -c 1 -k $PROCESS_PRIVKEY$PROCESS_PUBKEY -u $PROCESS_UID -n identity -o 0 -t 0; exec_check "tcs_update_process_identity [set]"	
	### 更新进程身份
	./user/test/tcs/process -c 1 -k $PROCESS_PRIVKEY$PROCESS_PUBKEY -u $PROCESS_UID -n one -o 0 -t 1; right_check "tcs_update_process_identity [add]"
	### 读取全部进程身份
	./user/test/tcs/process -o 1; exec_check "tcs_get_process_ids"
	
	echo "测试进程身份删除"
	### 更新进程身份
	./user/test/tcs/process -c 1 -k $PROCESS_PRIVKEY$PROCESS_PUBKEY -u $PROCESS_UID -n one -o 0 -t 2; right_check "tcs_update_process_identity [replace]"
	### 更新进程身份
	./user/test/tcs/process -c 1 -k $PROCESS_PRIVKEY$PROCESS_PUBKEY -u $PROCESS_UID -n one -o 0 -t 3; right_check "tcs_update_process_identity [delete]"
	./user/test/tcs/process -o 1; exec_check "tcs_get_process_ids"
	
	echo "测试进程身份设置"
	./user/test/tcs/process -c 1 -k $PROCESS_PRIVKEY$PROCESS_PUBKEY -u $PROCESS_UID -n set-identity -o 0 -t 0; exec_check "tcs_update_process_identity [set]"
	./user/test/tcs/process -o 1; exec_check "tcs_get_process_ids"
}

admin_auth_test ()
{
	echo "测试设置根证书和二级证书"
	### 设置根证书
	./user/test/tcs/auth -n $ROOT_CERT_ID -c 1 -d $ROOT_PUBKEY -o 0 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_set_admin_cert"
	### 设置二级证书
	./user/test/tcs/auth -n $GRANT_CERT_ID -c 1 -d $GRANT_PUBKEY -o 1 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_grant_admin_role"
	### 读取证书列表
	./user/test/tcs/auth -o 3; exec_check "tcf_get_admin_list"
			
	echo "测试删除根证书，期望删除失败"
	./user/test/tcs/auth -n $ROOT_CERT_ID -c 1 -d $ROOT_PUBKEY -o 2 -k $ROOT_PRIVKEY$ROOT_PUBKEY; right_check "tcs_remove_admin_role"
	./user/test/tcs/auth -o 3; exec_check "tcf_get_admin_list"
	
	echo "测试管理认证策略新增"
	### 设置TPCM管理认证策略
	./user/test/tcs/admin_auth_policy -U $ROOT_CERT_ID -c 1 -k $ROOT_PRIVKEY$ROOT_PUBKEY -n $ADMIN_POLICY_NAME -o 0 -t 0 -i 1 -a 1 -f 0x1 -u 0; exec_check "tcs_set_admin_auth_policies [set]"
	./user/test/tcs/admin_auth_policy -U $ROOT_CERT_ID -c 1 -k $ROOT_PRIVKEY$ROOT_PUBKEY -n addpolicy -o 0 -t 1; right_check "tcs_set_admin_auth_policies [add]"
    ./user/test/tcs/admin_auth_policy -U $ROOT_CERT_ID -c 1 -k $ROOT_PRIVKEY$ROOT_PUBKEY -n secondaddpolicy -o 0 -t 1; right_check "tcs_set_admin_auth_policies [add]"	
	### 读取TPCM管理认证策略
	./user/test/tcs/admin_auth_policy -o 1; exec_check "tcs_get_admin_auth_policies"	
	
	echo "测试管理认证策略删除"
	./user/test/tcs/admin_auth_policy -U $ROOT_CERT_ID -c 1 -k $ROOT_PRIVKEY$ROOT_PUBKEY -n secondaddpolicy -o 0 -t 3; right_check "tcs_set_admin_auth_policies [delete]"	
	./user/test/tcs/admin_auth_policy -o 1; exec_check "tcs_get_admin_auth_policies"
	
	echo "测试多条管理认证策略设置"
	./user/test/tcs/admin_auth_policy -U $ROOT_CERT_ID -c 1 -k $ROOT_PRIVKEY$ROOT_PUBKEY -o 0 -t 0 -N 4 -n one -i 1 -a 1 -f 0x1 -u 0 -n two -i 2 -a 1 -f 0xb -u 0 -n three -i 3 -a 1 -f 0xc -u 0 -n four -i 4 -a 1 -f 0xd -u 0; exec_check "tcs_set_admin_auth_policies"
	./user/test/tcs/admin_auth_policy -o 1; exec_check "tcs_get_admin_auth_policies"
	
	echo "测试管理认证策略设置"
	./user/test/tcs/admin_auth_policy -U $ROOT_CERT_ID -c 1 -k $ROOT_PRIVKEY$ROOT_PUBKEY -n $ADMIN_POLICY_NAME -o 0 -t 0; exec_check "tcs_set_admin_auth_policies [set]"
	./user/test/tcs/admin_auth_policy -o 1; exec_check "tcs_get_admin_auth_policies"
	
	echo "测试管理认证策略设置 二级证书"
	./user/test/tcs/admin_auth_policy -U $GRANT_CERT_ID -c 1 -k $GRANT_PRIVKEY$GRANT_PUBKEY -n $ADMIN_POLICY_NAME -o 0 -t 0; exec_check "tcs_set_admin_auth_policies [set]"
	./user/test/tcs/admin_auth_policy -o 1; exec_check "tcs_get_admin_auth_policies"
	
	echo "测试删除二级证书"
	./user/test/tcs/auth -n $GRANT_CERT_ID -c 1 -d $GRANT_PUBKEY -o 2 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_remove_admin_role"
	./user/test/tcs/auth -o 3; exec_check "tcs_get_admin_list"
	
}

tsb_test()
{
	### 设置二级证书
	./user/test/tcs/auth -n $BMEASURE_UID -c 1 -d $BMEASURE_PUBKEY -o 1 -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_grant_admin_role"
	
	echo "设置默认全局策略"	
	./user/test/tcs/global_control_policy -a 1 -o 0 -u $BMEASURE_UID -k $BMEASURE_PRIVKEY$BMEASURE_PUBKEY; exec_check "tcs_set_global_control_policy"
	echo "打开启动度量开关"
	./user/test/tcs/global_control_policy -a 1 -o 0 -p 1 -v 1 -u $BMEASURE_UID -k $BMEASURE_PRIVKEY$BMEASURE_PUBKEY; exec_check "tcs_set_global_control_policy"
	echo "打开启动度量控制开关"
	./user/test/tcs/global_control_policy -a 1 -o 0 -p 4 -v 1 -u $BMEASURE_UID -k $BMEASURE_PRIVKEY$BMEASURE_PUBKEY; exec_check "tcs_set_global_control_policy"	
	
	echo ">>> process <<<"	
	echo "设置管理认证策略 进程身份"	
	./user/test/tcs/admin_auth_policy -U $ROOT_CERT_ID -o 0 -t 0 -i 1 -a 1 -f 0x28 -c 1 -n tsb-identity -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_set_admin_auth_policies"
	./user/test/tcs/admin_auth_policy -o 1; exec_check "tcs_get_admin_auth_policies"
	
	echo "进程身份设置"
	./user/test/tcs/process -c 1 -k $PROCESS_PRIVKEY$PROCESS_PUBKEY -u $PROCESS_UID -n tsb-identity -o 0 -t 0; exec_check "tcs_update_process_identity [set]"
	./user/test/tcs/process -o 1; exec_check "tcs_get_process_ids"
	
	echo "更新启动度量基准值"
	./user/test/tcs/update_bmeasure_references -u $BMEASURE_UID -k $BMEASURE_PRIVKEY$BMEASURE_PUBKEY; exec_check "update_bmeasure_references"
	
	echo "设置管理认证策略 进程角色"	
	./user/test/tcs/admin_auth_policy -U $ROOT_CERT_ID -o 0 -t 0 -i 1 -a 1 -f 0x30 -c 1 -n tsb-role -k $ROOT_PRIVKEY$ROOT_PUBKEY; exec_check "tcs_set_admin_auth_policies"
	./user/test/tcs/admin_auth_policy -o 1; exec_check "tcs_get_admin_auth_policies"
	
	echo "进程角色设置"
	./user/test/tcs/role -c 1 -k $PROCESS_PRIVKEY$PROCESS_PUBKEY -u $PROCESS_UID -n tsb-role -o 0 -t 0; exec_check "tcs_update_process_roles [set]"
	./user/test/tcs/role -o 1; exec_check "tcs_get_process_roles"
	
	echo "更新启动度量基准值"
	./user/test/tcs/update_bmeasure_references -u $BMEASURE_UID -k $BMEASURE_PRIVKEY$BMEASURE_PUBKEY; exec_check "update_bmeasure_references"
}

trusted_evidence ()
{
	echo ">>> trusted_evidence <<<"
	### 获得可信证明
	echo "*** get_trust_evidence ***"
	./user/test/tcs/get_trust_evidence; exec_check "get_trust_evidence"
	echo ""
}
passwd=123456
seladata="34698314407573100255831612788187137315597522067776129489932861655785948359942593336517254214491661143868173074802246745646063494732398162924690508701324194196223535610868257798415783826709598"
errorprocess="3469831440757310025583161278818713731559752206777612948993286165578594835994259333651725421449166114386817307480224674564606349473239816292469050870132419419622353561086825779841578382670959834698314407573100255831612788187137315597522067776129489932861655785948359942593336517254214491661143868173074802246745646063494732398162924690508701324194196223535610868257798415783826709598"
encryptkey="6CCFDD53BDD70C2CFDAFD9A94855F874FC8D0A2550F324CE2EC0A26E6A5B13B2"
key_test ()
{

	echo ">>> ket_test <<<"

	./user/test/tcs/tcs_init $OWNER_PWD
	./user/test/tcs/generate_tpcm_pik $OWNER_PWD; exec_check "generate_tpcm_pik"
	./user/test/tcs/delete_keytree -k s://; exec_check "tcs_delete_keytree"
	./user/test/tcs/delete_keytree -k p://; exec_check "tcs_delete_keytree"

	echo "*** signkey test ***"
	./user/test/tcs/create_sign_key -k s:/// -p $passwd; right_check "create_sign_key error path"
	./user/test/tcs/create_sign_key -k s://  -p $passwd; right_check "create_sign_key error path"
	./user/test/tcs/create_sign_key -k s:// abc  -p $passwd; right_check "create_sign_key error path"
	
	./user/test/tcs/create_sign_key -k s://sign/a -p $passwd; exec_check "create_sign_key"
	./user/test/tcs/sign -k s://sign/a -d aaaaaaaaa -p $passwd; exec_check "sign"
	
        echo "*** signkey on policy test ***"
#	./user/test/tcs/create_sign_key -k s://sign/b -p $passwd -f 0x8018 -n process -o 1; right_check "create_sign_key_on_policy error policy"	
#	./user/test/tcs/create_sign_key -k s://sign/b -p $passwd -f 0x8060 -i 200 -o 1; right_check "create_sign_key_on_policy error policy"
#	./user/test/tcs/create_sign_key -k s://sign/b -p $passwd -f 0x8008 -n $errorprocess -o 1; right_check "create_sign_key_on_policy error policy name"
#	./user/test/tcs/create_sign_key -k s://sign/b -p $passwd -f 0x8020 -i 65536 -o 1; right_check "create_sign_key_on_policy error policy id"
	
	#./user/test/tcs/create_sign_key -k s://sign/b -p $passwd -f 0x8028 -n process -o 1; exec_check "create_sign_key_on_policy"
	#./user/test/tcs/sign -k s://sign/b -d aaaaaaaaa -p $passwd; exec_check "sign"
	
	#./user/test/tcs/create_sign_key -k s://sign/c -f 0x0 -o 1; exec_check "create_sign_key_on_policy flag=0"
	#./user/test/tcs/sign -k s://sign/c -d bbbbbbbbb; exec_check "sign"

     echo "*** encryptkey test ***"
	#./user/test/tcs/create_encrypt_key -k s://encrypt/a -t 0 -p $passwd -o 0; right_check "create_encrypt_key sm2"
	#./user/test/tcs/create_encrypt_key -k s://encrypt/b -t 0 -p $passwd -o 1; right_check "tcs_create_inner_encrypt_key sm2"	
	#./user/test/tcs/create_encrypt_key -k s://encrypt/c -t 0 -p $passwd -f 0x8028 -n process -o 2; right_check "tcs_create_encrypt_key_on_policy sm2"
	#./user/test/tcs/create_encrypt_key -k s://encrypt/d -t 0 -p $passwd -f 0x8028 -n process -o 3; right_check "tcs_create_inner_encrypt_key_on_policy sm2"
	
	./user/test/tcs/create_encrypt_key -k s://encrypt/a -t 1 -p $passwd -o 0; exec_check "create_encrypt_key sm4"
	./user/test/tcs/seal_data -k s://seal/a -d 123456789 -p $passwd  -s Seal; right_check "tcs_seal_data encrypt key"
	./user/test/tcs/encrypt -k s://encrypt/a -d abcdefg -p $passwd -e Encrypt; exec_check "encrypt sm4"
	./user/test/tcs/decrypt -k s://encrypt/a -p $passwd -e Encrypt; exec_check "decrypt sm4"
	
	./user/test/tcs/create_encrypt_key -k s://encrypt/b -t 1 -p $passwd  -o 1; exec_check "tcs_create_inner_encrypt_key sm4"
	./user/test/tcs/encrypt -k s://encrypt/b -d abcdefg -p $passwd  -e Encrypt; exec_check "encrypt sm4"
	./user/test/tcs/decrypt -k s://encrypt/b -p $passwd  -e Encrypt; exec_check "decrypt sm4"

	#./user/test/tcs/create_encrypt_key -k s://encrypt/c -t 1 -p $passwd  -f 0x8028 -n process -o 2; exec_check "tcs_create_encrypt_key_on_policy sm4"
	#./user/test/tcs/encrypt -k s://encrypt/c -d abcdefg -p $passwd  -e Encrypt; exec_check "encrypt"
	#./user/test/tcs/decrypt -k s://encrypt/c -p $passwd  -e Encrypt; exec_check "decrypt"	
	
	#./user/test/tcs/create_encrypt_key -k s://encrypt/d -t 1 -p $passwd  -f 0x8028 -n process -o 3; exec_check "tcs_create_inner_encrypt_key_on_policy sm4"
	#./user/test/tcs/encrypt -k s://encrypt/d -d abcdefg -p $passwd  -e Encrypt; exec_check "encrypt"
	#./user/test/tcs/decrypt -k s://encrypt/d -p $passwd  -e Encrypt; exec_check "decrypt"
	
	./user/test/tcs/get_encrypt_key -k s://encrypt/a -p $passwd; exec_check "get_encrypt_key"
	./user/test/tcs/set_encrypt_key -k s://encrypt/a -p $passwd -d $encryptkey; exec_check "set_encrypt_key"
	./user/test/tcs/encrypt -k s://encrypt/a -d abcdefg -p $passwd -e Encrypt; exec_check "encrypt sm4"
	./user/test/tcs/decrypt -k s://encrypt/a -p $passwd -e Encrypt; exec_check "decrypt sm4"	
	

	 echo "*** sealkey test ***"
	./user/test/tcs/create_seal_key -k s://seal/a -t 0 -p $passwd  -o 0; exec_check "create_seal_key sm2"
#	./user/test/tcs/create_seal_key -k s://seal/b -t 1 -p $passwd  -f 0x8028 -n process -o 1; exec_check "create_seal_key sm4"
	./user/test/tcs/seal_data -k s://seal/a -d 123456789 -p $passwd  -s Seal; exec_check "tcs_seal_data sm2"
	./user/test/tcs/unseal_data -k s://seal/a -p $passwd  -s Seal; exec_check "tcs_unseal_data sm2"
#	./user/test/tcs/seal_data_store -k s://seal/b -d $seladata -p $passwd  -s Seal; exec_check "tcs_seal_data_store sm4"
#	./user/test/tcs/unseal_stored_data -k s://seal/b -p $passwd  -s Seal; exec_check "tcs_unseal_stored_data sm4"
#	./user/test/tcs/get_sealed_data -k s://seal/b -s Seal; exec_check "tcs_get_sealed_data"
	./user/test/tcs/save_sealed_data -k s://seal/a -d Seal -s Seal; exec_check "save_sealed_data"
	
	echo "*** pathkey test ***"	
	./user/test/tcs/create_path_key -k s://mig//a -t 1 -o 0; right_check "errpath sm4"
	./user/test/tcs/create_path_key -k s://test/?*#@/ -t 1 -o 0; right_check "errpath sm4"
	./user/test/tcs/create_path_key -k s://migara/a -t 1 -o 0; exec_check "tcs_create_path_key sm4"
	./user/test/tcs/create_path_key -k s:///a/b -t 0 -o 0; right_check "tcs_create_path_key sm2"
	./user/test/tcs/create_path_key -k s://migara/a/b -t 1 -o 1; exec_check "tcs_create_migratable_path_key"
	
	echo "*** get_public_key test ***"	
	./user/test/tcs/get_pubkey -k s://sign/a; exec_check "tcs_get_public_key"
	
	echo "*** change_leaf_auth test ***"    
	./user/test/tcs/changeauth -k s://seal/a -o 123456 -n 123123; exec_check "tcs_change_leaf_auth"
	./user/test/tcs/seal_data -k s://seal/a -d changetest -p 123456 -s Seal; right_check "seal oldpasswd"	
	./user/test/tcs/seal_data -k s://seal/a -d changetest -p 123123 -s Seal; exec_check "seal newpasswd"	
	./user/test/tcs/unseal_data -k s://seal/a -p 123123 -s Seal; exec_check "unseal newpasswd"


#	./user/test/tcs/changeauth -k s://encrypt/c -o 123456 -n 123123; exec_check "tcs_change_leaf_auth encrypt_key"
#	./user/test/tcs/encrypt -k s://encrypt/c -d abcdefg -p 123456 -e Encrypt; right_check "encrypt oldpasswd"	
#	./user/test/tcs/encrypt -k s://encrypt/c -d changetest -p 123123 -e Encrypt; exec_check "encrypt newpasswd"	
#	./user/test/tcs/decrypt -k s://encrypt/c -p 123123 -e Encrypt; exec_check "decrypt newpasswd"

#	./user/test/tcs/changeauth -k s://encrypt/d -o 123456; exec_check "tcs_change_leaf_auth encrypt_key_on_policy"
	#./user/test/tcs/encrypt -k s://encrypt/d -d changetest -e Encrypt; exec_check "encrypt"
	#./user/test/tcs/decrypt -k s://encrypt/d -e Encrypt; exec_check "decrypt"

	echo "*** get_keyinfo test ***" 
	./user/test/tcs/get_key_info -k s://sign/a -o 0; exec_check "tcs_get_keyinfo"
	./user/test/tcs/get_key_info -k s://sign/a -o 1; exec_check "tcm_get_keyinfo_path"
	
	echo "*** keytree test ***" 
	./user/test/tcs/read_tree -k s://sign  -l 2 -r 1; exec_check "tcs_read_keytree tcs_free_keynode"

	./user/test/tcs/create_keytree_storespace -w $OWNER_PWD -n 123123 -s 4000; exec_check "tcs_create_shared_keytree_storespace"
	./user/test/tcs/delete_keytree -k s://sign; exec_check "tcs_delete_keytree"
	./user/test/tcs/delete_keytree -k s://encrypt; exec_check "tcs_delete_keytree"
	./user/test/tcs/save_shared_keytree -p 123123; exec_check "tcs_save_shared_keytree"
	./user/test/tcs/load_shared_keytree -p 123123; exec_check "tcs_load_shared_keytree"
	./user/test/tcs/remove_keytree_storespace -w $OWNER_PWD; exec_check "tcs_remove_shared_keytree_storespace"	
	./user/test/tcs/save_shared_keytree -p 123123; right_check "tcs_save_shared_keytree"

	./user/test/tcs/create_sign_key -k p://sign/a -p $passwd; exec_check "create_sign_key"
	./user/test/tcs/set_private_keytree_storespace_index -i 66; exec_check "tcs_set_private_keytree_storespace_index"	
	./user/test/tcs/nv_define_space -I 66 -s 4000 -w $OWNER_PWD -p 123123 -o 0; exec_check "tcs_nv_define_space"
	./user/test/tcs/save_private_keytree -p 123123; exec_check "tcs_save_private_keytree"
	./user/test/tcs/load_private_keytree -p 123123; exec_check "tcs_load_private_keytree"
	./user/test/tcs/export_keytree -k s://seal -n Export; exec_check "tcs_export_keytree"
	./user/test/tcs/import_keytree -k s://seal -n Export; right_check "tcf_import_keytree"
	./user/test/tcs/delete_keytree -k s://seal; exec_check "tcs_delete_keytree"	
	./user/test/tcs/import_keytree -k s://Seal -n Export; right_check "tcs_import_keytree"
	./user/test/tcs/import_keytree -k s://seal -n Export; exec_check "tcs_import_keytree"	
	./user/test/tcs/seal_data -k s://seal/a -d changetest -p 123123 -s Seal; exec_check "seal newpasswd"
	
	./user/test/tcs/nv_delete_space -I 66 -w $OWNER_PWD; exec_check "tcs_nv_delete_space"


	echo "*** migrate test ***"
	./user/test/tcs/create_path_key -k s://m -t 1 -o 1; exec_check "tcs_create_path_key"
	./user/test/tcs/create_encrypt_key -k s://m/encrypt/d -t 1 -p $passwd -o 0; exec_check "migrate create_encrypt_key sm4"
	./user/test/tcs/create_path_key -k s://f -t 1 -o 1; exec_check "tcs_create_path_key"
	./user/test/tcs/get_migrate_auth -n auth; exec_check "tcs_get_migrate_auth"
	
	echo "*** migrate node key test ***"
	./user/test/tcs/create_path_key -k s://m/a -t 1 -o 1; exec_check "tcs_create_path_key"
	./user/test/tcs/create_sign_key -k s://m/a/b -t 0 -p 123456 -o 0; exec_check "tcs_create_sign_key"
	./user/test/tcs/emigrate_keytree -k s://m -w httc@123 -d auth -e emig; exec_check "tcs_emigrate_keytree"
	./user/test/tcs/immigrate_keytree -k s:// -e emig; exec_check "tcs_immigrate_keytree"
	./user/test/tcs/immigrate_keytree -k s://f -e emig; exec_check "tcs_immigrate_keytree"
	./user/test/tcs/immigrate_keytree -k s://abc -e emig; exec_check "tcs_immigrate_keytree"
	./user/test/tcs/sign -k s://f/m/a/b -d aaaaaaaaa -p 123456; exec_check "sign"
	
	echo "*** migrate leaf key test ***"
	./user/test/tcs/create_sign_key -k s://m/c -t 0 -p 123456 -o 0; exec_check "tcs_create_sign_key"
	./user/test/tcs/emigrate_keytree -k s://m/c -p 123456 -w httc@123 -d auth -e emig; exec_check "tcs_emigrate_keytree"
	./user/test/tcs/immigrate_keytree -k s://efg -e emig; exec_check "tcs_immigrate_keytree"
	./user/test/tcs/immigrate_keytree -k s://f/m/a/b -e emig; right_check "tcs_immigrate_keytree"

	rm Encrypt Export Seal *_keytree.tar.gz emig auth -rf
}


store_test ()
{
	echo ">>> store_test <<<"
	./user/test/tcs/tcs_init $OWNER_PWD
	./user/test/tcs/generate_tpcm_pik $OWNER_PWD; exec_check "generate_tpcm_pik"

	echo "*** define space test ***"
	./user/test/tcs/nv_define_space -I 6 -s 128 -w $OWNER_PWD -p 123456 -o 0; exec_check "tcs_nv_define_space"	
#	./user/test/tcs/nv_define_space -I 7 -s 128 -w $OWNER_PWD -p 123456 -f 0x8028 -n process -o 1; exec_check "tcs_nv_define_space_on_policy"
#	./user/test/tcs/nv_define_space -I 8 -s 128 -w $OWNER_PWD -f 0x0 -o 1; exec_check "tcs_nv_define_space_on_policy flag 0"
	./user/test/tcs/nv_define_name_space -s 128 -N one -w $OWNER_PWD -p 123456 -o 0; exec_check "tcs_nv_define_name_space"
	./user/test/tcs/nv_define_name_space -s 128 -N one -w $OWNER_PWD -p 123456 -o 0; right_check "recreate tcs_nv_define_name_space"
#	./user/test/tcs/nv_define_name_space -s 128 -N two -w $OWNER_PWD -p 123456 -f 0x8028 -n process -o 1; exec_check "tcs_nv_define_name_space_on_policy"
#	./user/test/tcs/nv_define_name_space -s 128 -N two -w $OWNER_PWD -p 123456 -f 0x8028 -n process -o 1; right_check "recreate tcs_nv_define_name_space_on_policy"
	
	echo "*** write test ***"
	./user/test/tcs/nv_write -I 6 -d helloworld! -p 123456; exec_check "tcs_nv_write"	
	#./user/test/tcs/nv_write -I 7 -d helloworld! -p 123456; exec_check "tcs_nv_write policy"
	#./user/test/tcs/nv_write -I 8 -d helloworld!; exec_check "tcs_nv_write policy flag 0"
	./user/test/tcs/nv_named_write -N one -d helloworld! -p 123456; exec_check "tcs_nv_named_write"	
	#./user/test/tcs/nv_named_write -N two -d hellobeauty! -p 123456; exec_check "tcs_nv_named_write"
	./user/test/tcs/nv_write -I 6 -d helloworld! -p 123123; right_check "tcs_nv_write"
	./user/test/tcs/nv_write -I 120 -d helloworld! -p 123456; right_check "tcs_nv_write"
	./user/test/tcs/nv_named_write -N three -d hellobeauty! -p 123456; right_check "tcs_nv_named_write"
        
	echo "*** read test ***"
	./user/test/tcs/nv_read -I 6 -p 123456; exec_check "tcs_nv_read"
	#./user/test/tcs/nv_read -I 7 -p 123456; exec_check "tcs_nv_read policy"	
	#./user/test/tcs/nv_read -I 8; exec_check "tcs_nv_read policy flag 0"	
	./user/test/tcs/nv_named_read -N one -p 123456; exec_check "tcs_nv_named_read"	
	#./user/test/tcs/nv_named_read -N two -p 123456; exec_check "tcs_nv_named_read"
	./user/test/tcs/nv_read -I 6 -p 123123; right_check "tcs_nv_read"
	./user/test/tcs/nv_read -I 120 -p 123456; right_check "tcs_nv_read"
	./user/test/tcs/nv_named_read -N three -p 123456; right_check "tcs_nv_named_read"
	
	echo "*** nvlist test ***"	
	./user/test/tcs/read_nv_list; exec_check "tcs_read_nv_list"
	#mv /usr/local/httcsec/conf/nvinfo /usr/local/httcsec/conf/bak
	#./user/test/tcs/set_nv_list -f nvinfos -n `cat number.txt`; exec_check "tcs_set_nv_list"
	./user/test/tcs/is_nv_defined 6; right_check "tcs_is_nv_defined index 6"
	./user/test/tcs/is_nv_defined 10; exec_check "tcs_is_nv_defined index 10"
	
	echo "*** delete list test ***"	
	./user/test/tcs/nv_delete_space -I 6 -w $OWNER_PWD; exec_check "tcs_nv_delete_space 6"
	./user/test/tcs/nv_delete_name_space -N one -w $OWNER_PWD; exec_check "tcs_nv_delete_name_space one"
	./user/test/tcs/is_nv_defined 6; exec_check "tcs_is_nv_defined index 6"
	./user/test/tcs/nv_delete_space -I 7 -w $OWNER_PWD; exec_check "tcs_nv_delete_space 7"
	./user/test/tcs/nv_delete_space -I 8 -w $OWNER_PWD; exec_check "tcs_nv_delete_space 8"
#	./user/test/tcs/nv_delete_name_space -N two -w $OWNER_PWD; exec_check "tcs_nv_delete_name_space two"	

	./user/test/tcs/read_nv_list; exec_check "tcs_read_nv_list"
	rm number.txt nvinfos
}

pcr_test(){
	
	echo "*** pcr_test***"
	./user/test/tcs/tcs_init $OWNER_PWD
	./user/test/tcs/generate_tpcm_pik $OWNER_PWD; exec_check "generate_tpcm_pik"
	
	./user/test/tcs/create_encrypt_key -k s://pcrtest/a -t 1 -p 123456 -f 0x8100 -o 2; exec_check "tcs_create_encrypt_key_on_policy sm4"
	./user/test/tcs/encrypt -k s://pcrtest/a -d abcdefg -p 123456 -e Encrypt; exec_check "encrypt"	
	./user/test/tcs/nv_define_space -I 99 -s 128 -w $OWNER_PWD -p 123456 -f 0x8200 -o 1; exec_check "tcs_nv_define_space_on_policy"
	./user/test/tcs/nv_write -I 99 -d helloworld! -p 123456; exec_check "tcs_nv_write policy"	
	./user/test/tcs/sync_trust_status 0;exec_check "sync_trust_status"
	./user/test/tcs/decrypt -k s://pcrtest/a -p 123456 -e Encrypt; right_check "decrypt"
	./user/test/tcs/sync_trust_status 1;exec_check "sync_trust_status"
	./user/test/tcs/nv_read -I 99 -p 123456; right_check "tcs_nv_read"
	./user/test/tcs/nv_delete_space -I 99 -w $OWNER_PWD; exec_check "tcs_nv_delete_space"
	
	rm -rf Encrypt
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
	./user/test/tcs/update_tnc_policy -u $TNC_UID -k $TNC_PRIVKEY$TNC_PUBKEY -n 1 -a 1 -i 0 -I 0 -p 22 -P 22; exec_check "tcs_update_tnc_policy"
	
	echo "获取可信链接策略"
	./user/test/tcs/get_tnc_policy; exec_check "tcs_get_tnc_policy"
	
	echo "设置多条可信链接策略"
	./user/test/tcs/update_tnc_policy -u $TNC_UID -k $TNC_PRIVKEY$TNC_PUBKEY -n 2 -a 1 -i 0 -I 0 -p 22 -P 22 -a 2 -i 2 -I 2 -p 22 -P 22; exec_check "tcs_update_tnc_policy"
	
	echo "获取可信链接策略"
	./user/test/tcs/get_tnc_policy; exec_check "tcs_get_tnc_policy"
	
	
}


extern_boot_measure_pcr_test()
{
	echo ">>> extern_boot_measure_pcr_test <<<"

	echo "TCS 初始化"
	./user/test/tcs/tcs_init httc@123
	echo "生成TPCM PIK"
	./user/test/tcs/generate_tpcm_pik httc@123
	echo "获取可信报告"
	./user/test/tcs/get_trust_report
	echo "扩展启动度量"
	insmod kernel/test/tcs/extern_bmeasure_selftest.ko
	rmmod extern_bmeasure_selftest
	echo "获取可信报告"
	./user/test/tcs/get_trust_report
}

extern_simple_boot_measure_pcr_test()
{
	echo ">>> extern_simple_boot_measure_pcr_test <<<"

	echo "TCS 初始化"
	./user/test/tcs/tcs_init httc@123
	echo "生成TPCM PIK"
	./user/test/tcs/generate_tpcm_pik httc@123
	echo "获取可信报告"
	./user/test/tcs/get_trust_report
	echo "扩展启动度量"
	insmod kernel/test/tcs/extern_simple_bmeasure_selftest.ko
	echo "获取可信报告"
	./user/test/tcs/get_trust_report
}

sm234_test()
{
	echo ">>>sm234_test<<<"

	echo "SM2签名测试"
	./user/test/tcs/sm2_speed -t 100     # 100 times	
	./user/test/tcs/sm2_speed -t 200     # 200 times	
	./user/test/tcs/sm2_speed -t 500     # 500 times	

	echo "SM2压缩签名测试"
	./user/test/tcs/sm2_speed_E -s 0x80 	-t 	20     # 128B * 20 times
        ./user/test/tcs/sm2_speed_E -s 0x200 	-t 	20     # 512B * 20 times
        ./user/test/tcs/sm2_speed_E -s 0x400    -t 	20     # 1KB  * 20 times
        ./user/test/tcs/sm2_speed_E -s 0x2000   -t 	20     # 8KB  * 20 times
        ./user/test/tcs/sm2_speed_E -s 0x10000  -t 	20     # 64KB * 20 times

	echo "SM3加解密"
	./user/test/tcs/sm3_speed -s 0x400      -t 	20    # 1KB   *  20 times
	./user/test/tcs/sm3_speed -s 0x20000    -t 	20    # 128KB * 20 times
	./user/test/tcs/sm3_speed -s 0x80000    -t 	20    # 512KB * 20 times
	./user/test/tcs/sm3_speed -s 0x100000   -t 	20    # 1MB   * 20 times
	./user/test/tcs/sm3_speed -s 0x800000   -t 	20    # 8MB   * 20 times
	./user/test/tcs/sm3_speed -s 0x4000000  -t 	20    # 64MB  * 20 times

	echo "SM4-ECB加解密"
	./user/test/tcs/sm4_ecb_speed -s 0x400      -t 	20    # 1MB * 20 times
	./user/test/tcs/sm4_ecb_speed -s 0x20000    -t 	20    # 4MB * 20 times
	./user/test/tcs/sm4_ecb_speed -s 0x80000    -t 	20    # 8MB * 20 times
	./user/test/tcs/sm4_ecb_speed -s 0x100000   -t 	20    # 1MB * 20 times
	./user/test/tcs/sm4_ecb_speed -s 0x800000   -t 	20    # 4MB * 20 times
	./user/test/tcs/sm4_ecb_speed -s 0x4000000  -t 	20    # 8MB * 20 times
	
	echo "SM4-CBC加解密"
	./user/test/tcs/sm4_cbc_speed -s 0x400      -t 	20    # 1MB * 20 times
	./user/test/tcs/sm4_cbc_speed -s 0x20000    -t 	20    # 4MB * 20 times
	./user/test/tcs/sm4_cbc_speed -s 0x80000    -t 	20    # 8MB * 20 times
	./user/test/tcs/sm4_cbc_speed -s 0x100000   -t 	20    # 1MB * 20 times
	./user/test/tcs/sm4_cbc_speed -s 0x800000   -t 	20    # 4MB * 20 times
	./user/test/tcs/sm4_cbc_speed -s 0x4000000  -t 	20    # 8MB * 20 times
	
	echo "获取随机数"
 	./user/test/tcs/sm_get_random -s 0x10000

}


test90()
{
		  admin_auth_test
          global_policy_test
          process_id_role_test
          boot_measure_test
		  key_test
          store_test
          file_integrity_test
		  feature_check
		  if [ $imeasure -eq 0 ]; then
          intercept_measure_test
          simple_intercept_measure_test
		  fi
          dynamic_measure_test
          process_dmeasure_test 
          ptrace_protect_test   
          attest_test
          trusted_evidence
          volatile_data
          maintain_test   
          tnc_test
          #extern_boot_measure_pcr_test
          extern_simple_boot_measure_pcr_test
          #license_test
          #pcr_test
          critical_file_integrity_test
}

test91()
{
		  admin_auth_test
          global_policy_test
          process_id_role_test
          boot_measure_test
		  key_test
          store_test
          file_integrity_test
	      feature_check
		  if [ $imeasure -eq 0 ]; then
          intercept_measure_test
          simple_intercept_measure_test
		  fi
          dynamic_measure_test
          process_dmeasure_test 
          ptrace_protect_test   
          attest_test
          trusted_evidence
          volatile_data
          maintain_test
          tnc_test
          extern_boot_measure_pcr_test
          #extern_simple_boot_measure_pcr_test
          license_test
          #pcr_test
          critical_file_integrity_test
}

test92()
{
		  admin_auth_test
          global_policy_test
          process_id_role_test
          boot_measure_test
		  key_test
          store_test
          file_integrity_test
		  feature_check
		  if [ $imeasure -eq 0 ]; then
          intercept_measure_test
          simple_intercept_measure_test
		  fi
          dynamic_measure_test
          process_dmeasure_test 
          ptrace_protect_test   
          attest_test
          trusted_evidence
          volatile_data
          maintain_test         
          tnc_test
          #extern_boot_measure_pcr_test
          #extern_simple_boot_measure_pcr_test
          #license_test
          #pcr_test
          critical_file_integrity_test
}



test93()
{
	      admin_auth_test
          global_policy_test
          process_id_role_test
          boot_measure_test
		  key_test
          store_test
          #file_integrity_test   
          #intercept_measure_test
          #simple_intercept_measure_test
          dynamic_measure_test
          process_dmeasure_test 
          ptrace_protect_test   
          attest_test
          trusted_evidence
          volatile_data
          maintain_test
          tnc_test
          #extern_boot_measure_pcr_test
          #extern_simple_boot_measure_pcr_test
          #license_test
          #pcr_test
          critical_file_integrity_test
}

test94()
{
		  admin_auth_test
          global_policy_test
#         process_id_role_test
          boot_measure_test
#		  key_test
          store_test
#         file_integrity_test   
#         intercept_measure_test
#         simple_intercept_measure_test
#         dynamic_measure_test
#         process_dmeasure_test 
#         ptrace_protect_test   
          attest_test
          trusted_evidence
          volatile_data
          maintain_test   
#         tnc_test
         #extern_boot_measure_pcr_test
#         extern_simple_boot_measure_pcr_test
          #license_test
          #pcr_test
#          critical_file_integrity_test
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
	echo "  8     :  dynamic_measure_test"
	echo "  9     :  process_dmeasure_test"	
	echo "  10    :  ptrace_protect_test"	
	echo "  11    :  attest_test"
	echo "  12    :  trusted_evidence"
	echo "  13    :  volatile_data"
	echo "  14    :  maintain_test"		
	echo "  15    :  key_test"
	echo "  16    :  store_test"
	echo "  17    :  tnc_test"
	echo "  18    :  extern_boot_measure_pcr_test"
	echo "  19    :  extern_simple_boot_measure_pcr_test"
	echo "  20    :  license_test"
	echo "  21    :  pcr_test"
	echo "  22    :  critical_file_integrity_test"
	echo "  23    :  sm234_test"
	echo "  90    :  TEST_ALL expect 17"
	echo "  91    :  TEST_ALL expect 18"
	echo "  92    :  TEST_ALL expect 17、18 and 19"
	echo "  93    :  TEST_ALL expect 18 、19 and intercept"
	echo "  94    :  test for pantum"
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
				dynamic_measure_test;;
			9)
				process_dmeasure_test;;
			10)
				ptrace_protect_test;;
			11)
				attest_test;;
			12)
				trusted_evidence;;
			13)
				volatile_data;;
			14)
				maintain_test;;			
			15)
				key_test;;
			16)
				store_test;;
			17)
				tnc_test;;
			18)
				extern_boot_measure_pcr_test;;
			19)
				extern_simple_boot_measure_pcr_test;;
			20)
				license_test;;			
			21)
				pcr_test;;			
			22)	
				critical_file_integrity_test;;	
			23)
				sm234_test;;		
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
			92)
				echo -n "Please enter an integer about how many cycles you want to test  ->"
				read cycles 
				case $cycles in
					0)
						echo "Input value $cycles is not an right choice!!!!." >&2;;
					*)
						while [ $i -lt $cycles ];do
							test92
							i=$((i+1))
							echo "#######################RUN  $i  Cycles #######################"
						done	
					;;
				esac
				;;

			93)
				echo -n "Please enter an integer about how many cycles you want to test  ->"
				read cycles 
				case $cycles in
					0)
						echo "Input value $cycles is not an right choice!!!!." >&2;;
					*)
						while [ $i -lt $cycles ];do
							test93
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
			
			*)
				echo "Input value $int is not an right choice!!!!." >&2;;
		esac
		#rmmod get_tpcmlog
		rm $TPCM_PIK_HANDLE_FILE -fr
		
	done
}

main
