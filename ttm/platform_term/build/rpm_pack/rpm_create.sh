#!/bin/bash

work_dir=`pwd`
httc_version=$1
httc_release=$2
httc_name="httcsec"
spec_name="rpm.spec"
rpm_root_dir="/root/rpmbuild"
install_dir="/usr/local/${httc_name}"
sysctl_dir=/lib/systemd/system
desktop_path=/usr/share/applications

usage()
{
	echo "./rpm_create.sh version release"
	echo "ege :./rpm_create.sh FWQ.102.203.09.3.01 28407"
}

if [ $# != 2 ];then
	usage
	exit 1
fi

chmod_exec()
{
	if [ -f $1/srv ]; then
		chmod +x $1/srv
	fi
}

init_rpm_path()
{
	cd ${work_dir}/../${httc_name}
	mkdir -p log
	mkdir -p lib
	mkdir -p conf

	chmod_exec tss
	chmod_exec tsb
	chmod_exec tnc
	chmod_exec ttm

	cp tss/user/lib*		lib/ -frd
	cp tss/user/tcm-lib/lib/*	lib/ -frd
	cp tsb/libhttctsb.so		lib/ -frd
}

init_rpm_path

#create the rpm.spec
rpm_str="Name:\t\t${httc_name}\n"
rpm_str+="Version:\t${httc_version}\n"
rpm_str+="Release:\t${httc_release}%{?dist}\n"
rpm_str+="Summary:\t${httc_name} rpm build\n"
rpm_str+="\n"
rpm_str+="License:\tGPLv3+\n"
#rpm_str+="Source0:\t${httc_name}-${httc_version}-${httc_release}.tar.gz\n"
rpm_str+="\n\n"
rpm_str+="%description\n"
rpm_str+="test rpm build description\n"

rpm_str+="%pre\n"
rpm_str+="case \$1 in\n"
rpm_str+="1)\n"
rpm_str+="\techo \"###准备安装${httc_name}。。。###\"\n"
rpm_str+="\t;;\n"
rpm_str+="2)\n"
rpm_str+="\techo \"###准备升级${httc_name}。。。###\"\n"
rpm_str+="\t${install_dir}/ttm/srv stop > /dev/null 2>&1\n"
rpm_str+="\tsystemctl stop ${httc_name} > /dev/null 2>&1\n"
rpm_str+="\t;;\n"
rpm_str+="esac\n"
rpm_str+="%post\n"
rpm_str+="case \$1 in\n"
rpm_str+="1)\n"
rpm_str+="\techo \"###安装完成，准备初始化。。。###\"\n"
rpm_str+="\tsleep 1\n"
rpm_str+="\t${install_dir}/config.sh init offline\n"
rpm_str+="\techo \"###完成###\"\n"
rpm_str+="\t;;\n"
rpm_str+="2)\n"
rpm_str+="\techo \"###安装完成，对更新程序和动态库添加白名单。。。###\"\n"
rpm_str+="\t${install_dir}/ttm/bin/ht_whitelist -s ${install_dir}/ttm/bin > /dev/null 2>&1\n"
rpm_str+="\t${install_dir}/ttm/bin/ht_whitelist -s ${install_dir}/lib > /dev/null 2>&1\n"
rpm_str+="\techo \"###完成###\"\n"
rpm_str+="\t;;\n"
rpm_str+="esac\n"

rpm_str+="%preun\n"
rpm_str+="systemctl disable ${httc_name} > /dev/null 2>&1\n"
rpm_str+="${install_dir}/ttm/srv stop > /dev/null 2>&1\n"
rpm_str+="systemctl stop ${httc_name} > /dev/null 2>&1\n"
rpm_str+="%postun\n"
rpm_str+="find ${install_dir} -name *.rpmsave |xargs rm -f > /dev/null 2>&1\n"
rpm_str+="find ${install_dir} -name *.rpmorig |xargs rm -f > /dev/null 2>&1\n"
rpm_str+="\n"

rpm_str+="%install\n"
rpm_str+="mkdir -p %{buildroot}\n"
rpm_str+="mkdir -p %{buildroot}/usr/local/\n"
rpm_str+="mkdir -p %{buildroot}/${sysctl_dir}\n"
rpm_str+="mkdir -p %{buildroot}/${desktop_path}\n"
rpm_str+="cp -frd ${work_dir}/../${httc_name} %{buildroot}/usr/local/\n"
rpm_str+="cp -frd ${work_dir}/../${httc_name}/sysctl/${httc_name}.service %{buildroot}/${sysctl_dir}\n"
rpm_str+="cp -frd ${work_dir}/../${httc_name}/sysctl/${httc_name}.desktop %{buildroot}/${desktop_path}\n"
rpm_str+="\n"

rpm_str+="%files\n"
rpm_str+="${install_dir}/*\n"
rpm_str+="${sysctl_dir}/${httc_name}.service\n"
rpm_str+="${desktop_path}/${httc_name}.desktop\n"

rpm_str+="%config ${install_dir}/ttm/db/*\n"
rpm_str+="%config ${install_dir}/ttm/etc/*\n"
rpm_str+="%config ${install_dir}/ttm/ui/info.db\n"
rpm_str+="%config ${install_dir}/ttm/ui/msglog\n"
rpm_str+="%config ${install_dir}/ui_DevOpsTool/info.db\n"
rpm_str+="%config ${install_dir}/ui_DevOpsTool/msglog\n"
rpm_str+="\n"

rpm_str+="%changelog\n"

echo -e "${rpm_str}" > ${rpm_root_dir}/SPECS/${spec_name}

#create rpm
rpmbuild -ba ${rpm_root_dir}/SPECS/${spec_name}

cp -frd ${rpm_root_dir}/RPMS/`uname -m`/${httc_name}-${httc_version}-${httc_release}*.rpm ${work_dir}
