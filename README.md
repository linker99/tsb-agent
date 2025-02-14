# TSB-agent

#### 介绍
可信软件基代理(TSB-Agent) 部署于操作系统，在可信根的支撑下，建立可信终端设备的主动免疫防御体系，提升终端安全能力。其实现自主可信计算（Initiative Trusted Computing）体系中系统层要素采集、基础通信、控制执行功能。是实现自主可信计算（Initiative Trusted Computing）的重要部件。

#### 功能说明
静态度量：对应用程序进行白名单完整性检查，防止病毒、木马等未知恶意程序运行。
动态度量：可定期对运行环境进行检查，在恶意软件在程序运行阶段进行内存注入攻击是进行告警。
审计信息：记录关键的告警行为和操作的详细信息。

#### 系统要求
操作系统： OpenEuler22.03

#### 硬件要求
CPU：3 GHz及以上级别
内存：64GB 及以上级别
硬盘：500G 以上
网卡：100 Mb base 及以上级别

#### 运行依赖
libsqlite3.so
libcjson.so
veth虚拟网卡

#### 安装
cp -rf tss-main/tcf/scripts/tss  /usr/local/httcsec/
cp -rf proxy/tpcmproxy  /usr/local/httcsec/tss/
cp -rf tsb/tsb /usr/local/httcsec/
cp -rf ttm/platform_term/build/ttm  /usr/local/httcsec/
启动tss服务
/usr/local/httcsec/tss/srv start
全局扫描白名单
/usr/local/httcsec/ttm/bin/ht_init scan  accuracy_first  nounzip
重置license
/usr/local/httcsec/ttm/bin/ht_init reset
设置管理员
/usr/local/httcsec/ttm/bin/ht_init set-admin
下发全局策略
/usr/local/httcsec/ttm/bin/ht_init set-default-policy all
停止tss服务
/usr/local/httcsec/tss/srv stop
启动服务
/usr/local/httcsec/ttm/srv start

#### 使用说明：
运行命令
白名单管理：
/usr/local/httcsec/ttm/bin/ht_whitelist  [-s/-d]  scan_dir
全局策略开关管理：
/usr/local/httcsec/ttm/bin/ht_global_policy_switch  [show/dmeasure/smeasure   on/off] 
动态度量管理：
/usr/local/httcsec/ttm/bin/ht_dmeasure  [get_dmeasure_policy/get_dmeasure_process_policy/update_dmeasure_process_policy]
审计策略管理：
/usr/local/httcsec/ttm/bin/ht_audit_switch [show; dmeasure/smeasure  success/fail/no/all]
