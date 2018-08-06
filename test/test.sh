#!/bin/bash

#/usr/sbin/setenforce 0 

YF_SO="$HOME/yifei/src/.libs/"

SO_LIB_PATH=$YF_SO:/usr/local/mysql/lib/
export LD_PRELOAD="$YFR_SO"

#--dns--
export DNS_THREADS_NUM=3
#--mysql--
export mysql_host=localhost
export mysql_user=root
export mysql_psd=sd-9898w
export mysql_ops=1024000

ulimit -c unlimited
rm -rf log/coroutine.log*

check_rv()
{
	if [ $? -ne 0 ];then
		exit -1
	fi
}

./yf_coroutine_testor --gtest_filter=CoroutineTestor.CreateRunExit
check_rv
./yf_coroutine_testor --gtest_filter=CoroutineTestor.Fcall
#gdb .libs/yf_coroutine_testor 
check_rv
./yf_coroutine_testor --gtest_filter=CoroutineTestor.Switch
check_rv
./yf_coroutine_testor --gtest_filter=CoroutineTestor.Sleep
check_rv
./yf_coroutine_testor --gtest_filter=CoroutineTestor.IpcCond
check_rv
./yf_coroutine_testor --gtest_filter=CoroutineTestor.IpcLock
check_rv
./yf_coroutine_testor --gtest_filter=CoroutineTestor.Dns
check_rv
#./yf_coroutine_testor --gtest_filter=CoroutineTestor.Mysql 
#check_rv
./yf_coroutine_testor --gtest_filter=CoroutineTestor.SocketActive 2>/dev/null
check_rv
#strace -o strace.log ./yf_coroutine_testor --gtest_filter=CoroutineTestor.Dns
exit

i=0
cnt=10000
while [ $i -lt $cnt ]; 
do
        #./yf_coroutine_testor --gtest_filter=CoroutineTestor.IpcLock
        ./yf_coroutine_testor 2>/dev/null
        if [ $? -ne 0 ];then
                exit
        fi
        let i++
done
