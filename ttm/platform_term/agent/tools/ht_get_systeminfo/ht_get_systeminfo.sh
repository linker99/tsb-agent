#!/bin/bash

# 设备型号
cmd=$(dmidecode | grep -m 1 'Product Name'  |uniq | cut -d: -f2)
echo "设备型号:"$cmd


# 系统架构
cmd=$(uname -p)
echo "系统架构:"$cmd

# CPU型号
cmd=$(lscpu |grep "Model name" | uniq | cut -d: -f2)
cmd1=$(lscpu |grep "型号名称" | uniq | cut -d： -f2)
if [ -z "$cmd1" ];then
  echo "CPU型号:" $cmd
else
  echo "CPU型号:" $cmd1
fi

# 主板信息

echo "主板信息:"
dmidecode -t baseboard

#BIOS版本
cmd=$(dmidecode -s bios-version)
echo "BIOS 固件版本:" $cmd

# 系统版本
cmd=$(cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2-)
echo "系统版本:" $cmd

# 内核版本
cmd=$(uname -r)
echo "内核版本:" $cmd

# QT版本
cmd=$(rpm -qa|grep -i qt)
if [ -z "$cmd" ];then
  echo "QT版本:" $cmd
else
  echo "未获取到QT版本"
fi
