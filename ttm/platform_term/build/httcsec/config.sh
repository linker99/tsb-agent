#!/bin/bash

enforce=0
success=0

INSTALL_PATH=/usr/local/httcsec
SYSCTL_PATH=/lib/systemd/system

#白名单扫描是否处理压缩包 0-不处理 1-对压缩包中的ko文件加白 2-对压缩包中符合白名单的文件加白 默认为1
HAS_UNZIP=0

#check veth network adaptor
NET_FLAG=`cat /proc/net/dev | awk '{i++; if(i>2){print $1}}' | sed 's/^[t]*//g' | sed 's/[:]*$//g'| grep veth |wc -l`

is_exist()
{
	res=`whereis $1`
	if [[ $res == "$1:" ]];then
		return 0
        else
                return 1
        fi
}

httc_init_path()
{
	echo -n "初始化目录..." 

	mkdir -p $INSTALL_PATH/conf
	mkdir -p $INSTALL_PATH/log
	mkdir -p $INSTALL_PATH/lib
     
	echo "完成"
}

httc_install_module()
{
	if [ $1 == "" ]; then
		echo "param error!"
	fi

	#如果已经有这个目录，先删除
	new_dir=$INSTALL_PATH/$1
	if [ -d $new_dir ]; then
		rm -rf $new_dir
	fi

	echo -n "安装$1..."

	cp $1 $INSTALL_PATH -frd

	if [ -f $new_dir/srv ]; then
		chmod +x $new_dir/srv
	fi
	echo "完成"
}

httc_update_ttm_module()
{
	echo -n "升级ttm..."

	rm -rf $INSTALL_PATH/ttm/bin/
	rm -rf $INSTALL_PATH/ttm/lib/
	rm -rf $INSTALL_PATH/ttm/srv

	cp ttm/bin/ $INSTALL_PATH/ttm/ -frd
	cp ttm/lib/ $INSTALL_PATH/ttm/ -frd
	cp ttm/srv  $INSTALL_PATH/ttm/srv
	chmod +x $INSTALL_PATH/ttm/srv

	echo "完成"
}

httc_copy_lib()
{
	cp $INSTALL_PATH/tss/user/lib* $INSTALL_PATH/lib -frd
	cp $INSTALL_PATH/tss/user/tcm-lib/lib/* $INSTALL_PATH/lib -frd

	cp $INSTALL_PATH/tsb/libhttctsb.so $INSTALL_PATH/lib -frd
}

sysctl_allow_selinux()
{
	echo -n "添加selinux对sysctl的支持..."

	#命令不存在则返回
	[[ `whereis ausearch` == "ausearch:" ]] && return
	[[ `whereis audit2allow` == "audit2allow:" ]] && return
	ausearch -c 'insmod' --raw | audit2allow -M sysctl_allow-insmod > /dev/null 2>&1

	[[ `whereis semodule` == "semodule:" ]] && return
	semodule -i sysctl_allow-insmod.pp > /dev/null 2>&1
	rm -f sysctl_allow-insmod.*

	echo "完成"
}

install_sysctl_service()
{
	echo -n "安装系统服务..."
	cp -f $INSTALL_PATH/sysctl/httcsec.service ${SYSCTL_PATH}/
	sysctl_allow_selinux
	systemctl daemon-reload &1>/dev/null
	echo "完成"
}

check_tsb_module() {
	lhttcfac=$(lsmod |grep httcfac)
	if [ "$lhttcfac" ]; then
		echo "httcfac mod is running!"  
		return 0
	fi
	lhttcdmeasure=$(lsmod |grep httcdmeasure)
	if [ "$lhttcdmeasure" ]; then
		echo "httcdmeasure mod is running!" 
		return 0
	fi
	lhttcsmeasure=$(lsmod |grep httcsmeasure)
	if [ "$lhttcsmeasure" ]; then
		echo "httcsmeasure mod is running!"
		return 0
	fi
	lplatform=$(lsmod |grep -w "platform")
	if [ "$lplatform" ]; then
		echo "platform mod is running!"
		return 0
	fi

	return 1
}

check_tss_module() {
	lhttctcs=$(lsmod |grep httctcs)
	if [ "$lhttctcs" ]; then
		echo "httctcs mod is running!"
		return 0
	fi
	ltddl=$(lsmod |grep tddl)
	if [ "$ltddl" ]; then
		echo "tddl mod is running!"
		return 0
	fi
	lhttctdd=$(lsmod |grep httctdd)
	if [ "$lhttctdd" ]; then
		echo "httctdd mod is running! "
		return 0
	fi
	lread_sysram=$(lsmod |grep read_sysram)
	if [ "$lread_sysram" ]; then
		echo "read_sysram mod is running!"
		return 0
	fi

	return 1
}

check_mod_status() {

	check_tsb_module
	tsb_result=$?
	if [ $tsb_result  -eq 0 ]; then
		$INSTALL_PATH/tsb/srv stop
	fi
	check_tsb_module
	tsb_result=$?
	if [ $tsb_result  -eq 0 ]; then
		return 0
	fi

	check_tss_module
	tss_result=$?
	if [ $tss_result  -eq 0 ]; then
		$INSTALL_PATH/tss/srv stop
	fi
	check_tss_module
	tss_result=$?
	if [ $tss_result  -eq 0 ]; then
		return 0
	fi

	return 1
}

update_backup()
{
	mkdir -p ./backup/
	cp -rf $INSTALL_PATH ./backup/
}

update()
{
	agent_conf_path="/usr/local/httcsec/ttm/etc/agent.conf"

	echo "停止httcsec产品服务..."
	systemctl stop httcsec
	check_mod_status
	check_result=$?
	if [ $check_result  -eq 0 ]; then
		echo "停止服务模块未全部停止，请检查服务"
		exit 1
	fi
	echo "停止httcsec产品服务成功..."

	echo "开始备份数据"
	update_backup
	echo "备份数据完成"

	echo "开始升级安装包.."
	httc_init_path

	httc_install_module tss
	httc_install_module tsb
	httc_update_ttm_module

	httc_copy_lib

	cp ./sysctl $INSTALL_PATH/ -frd
	cp ./httcsec.conf $INSTALL_PATH/ttm/etc/ -frd
	cp ./version.txt $INSTALL_PATH/ -frd
	cp ./release     $INSTALL_PATH/ -frd
	cp ./Copyright_note.txt $INSTALL_PATH/ -frd
	cp ./sysctl/httcsec.service ${SYSCTL_PATH}/ -frd
	systemctl daemon-reload &1>/dev/null

	echo "升级安装包成功.."
	echo "开始对升级数据加白.."
	$INSTALL_PATH/tss/srv start
	$INSTALL_PATH/ttm/bin/ht_whitelist -s $INSTALL_PATH/
	$INSTALL_PATH/tss/srv stop
	echo "升级数据加白完成.."

	echo "启动httcsec产品服务..."
	systemctl start httcsec
	echo "启动httcsec产品服务成功..."
}


install()
{
	httc_init_path

	httc_install_module tss
	httc_install_module tsb
	httc_install_module ttm

	httc_copy_lib

	cp ./sysctl $INSTALL_PATH/ -frd
	cp ./httcsec.conf $INSTALL_PATH/ttm/etc/ -frd
	cp ./version.txt $INSTALL_PATH/ -frd
	cp ./release     $INSTALL_PATH/ -frd
	cp ./Copyright_note.txt $INSTALL_PATH/ -frd
}

pre_init()
{
	install_sysctl_service

	res=`getenforce`
	if [ ${res} == "Enforcing" ]; then
		enforce=1
		setenforce 0
	fi

	$INSTALL_PATH/tss/srv start
	$INSTALL_PATH/tsb/srv disk

	if [ ${enforce} -eq 1 ]; then
		setenforce 1
	fi
}

after_init()
{
	$INSTALL_PATH/tss/srv stop
	
	systemctl enable httcsec &1>/dev/null
	sleep 1
}

fin_init()
{
	if [ ${enforce} -eq 1 ]; then
		setenforce 0
		$INSTALL_PATH/tss/srv stop
		setenforce 1
	else
		$INSTALL_PATH/tss/srv stop
	fi

	if [ ${success} -eq 1 ]; then
		systemctl enable httcsec &1>/dev/null
	fi

	sleep 1

	exit $((${success} == 0 ? 1 : 0))
}

do_init()
{	
	echo "修改配置文件成功, 开始采集白名单..."
	sleep 1
		
	if [ $HAS_UNZIP -eq 1 ]; then
		$INSTALL_PATH/ttm/bin/ht_init scan  accuracy_first  unzip_ko
	elif [ $HAS_UNZIP -eq 2 ]; then
		$INSTALL_PATH/ttm/bin/ht_init scan  accuracy_first  unzip_all
	else
		$INSTALL_PATH/ttm/bin/ht_init scan  accuracy_first  nounzip
	fi

	if [ $? -ne 0 ]; then
		echo "白名单扫描失败，退出"
		fin_init
	fi
	echo "白名单采集成功, 开始重置LICENSE..."
	sleep 1
		
	$INSTALL_PATH/ttm/bin/ht_init reset
	RESET_RES=$?

	if [ $RESET_RES -eq 0 ]; then
		echo "LICENSE重置成功, 设置管理员..."

	elif [ $RESET_RES -eq 14 ]; then
		echo "检测到已有正式LICENSE授权，不能重置"
		echo "设置管理员..."

	else
		echo "重置LICENSE失败，退出"
		fin_init
	fi
	sleep 1
		
	$INSTALL_PATH/ttm/bin/ht_init set-admin
	if [ $? -ne 0 ]; then
		echo "设置管理员失败，退出"
		fin_init
	fi
	echo "设置管理员成功, 开始下发基础策略(耗时较长)..."
	sleep 1
		
	$INSTALL_PATH/ttm/bin/ht_init set-default-policy all
	if [ $? -ne 0 ]; then
		echo "配置基础策略失败，退出"
		fin_init
	fi
	echo "配置基础策略成功"
	success=1
}

init()
{
	pre_init
	
	do_init
	
	fin_init
}

uninstall()
{
	echo "管理中心有残留数据，需要管理员清除。"
	echo "开始卸载..."

	echo -n "停止服务和驱动......"
	systemctl disable httcsec
	$INSTALL_PATH/ttm/srv stop >/dev/null
	systemctl stop httcsec
	sleep 1
	echo "完成"

	echo -n "卸载服务......"
	rm -f ${SYSCTL_PATH}/httcsec.service
	systemctl daemon-reload >/dev/null
	echo "完成"
	
	echo -n "删除所有目录和配置......"
	rm -rf ${INSTALL_PATH}

	echo "完成"
}

usage()
{
	echo "usage:"
	echo "    $0 install"
	echo "    $0 init"
	echo "    $0 uninstall"
	echo "    $0 update"
	exit 1
}

menu_option()
{
	case $1 in

		install)
			install
			;;

		init)
			init
			;;
			
		uninstall)
			uninstall
			;;

		update)
			update
			;;

		*)
			usage
			;;
	esac
}

menu_option $*
