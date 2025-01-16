## 编译

```sh
cd tcf/scripts
./tcs-com.sh   #根据提示输入参数，编译 tcs
./tcf-com.sh   #根据提示输入参数, 编译 tcf
```

完成之后会生成 tss 文件夹和一个 tss文件夹的 tar.gz 压缩包。

>tcs-clean.sh 和 tcf-clean.sh 会进行一些清理操作

## 安装

```sh
#tss 安装包内容如下
[root@localhost tss]# ls
change-log.md  install.sh  mk-env.sh    srv        tcf-test.sh       tcs-test-notsb.sh  uninstall.sh  wl_rate.sh
demo           kernel      Readme       srv.bak    tcf-utils.sh      tcs-test.sh        upgrade.sh
init.sh        loop.sh     release.txt  symbol.sh  tcs-test-3310.sh  tcs-utils.sh       user
[root@localhost tss]#

#安装
[root@localhost tss]#./install.sh
#卸载
[root@localhost tss]#./uninstall.sh
```

## 测试

debug 版本可使用脚本 tcf-test.sh 、tcs-test.sh 、tcs-utils.sh 做一些自动化测试。
