#!/bin/sh
pid=`pgrep printname`
echo $pid
gdb -x gdbcmd -p $pid

