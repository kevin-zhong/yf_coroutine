#!/bin/bash

#/usr/sbin/setenforce 0 

YFR_SO="$HOME/yf_coroutine/src/.libs/libyf_coroutine.so"
YF_SO="$HOME/yifei/src/.libs/"

SO_LIB_PATH=$YF_SO:/usr/local/mysql/lib/

#linux
export LD_PRELOAD="$YFR_SO"
export LD_LIBRARY_PATH=$SO_LIB_PATH:$LD_LIBRARY_PATH

#mac
export DYLD_FORCE_FLAT_NAMESPACE=1
export DYLD_INSERT_LIBRARIES=`echo $LD_PRELOAD | sed 's/\.so/\.dylib/g'`
export DYLD_LIBRARY_PATH=$SO_LIB_PATH:$DYLD_LIBRARY_PATH

#--dns--
export DNS_THREADS_NUM=3
#--mysql--
export mysql_host=localhost
export mysql_user=root
export mysql_psd=sd-9898w
export mysql_ops=1024

#ulimit -c unlimited
rm -rf log/coroutine.log

#./yf_coroutine_testor --gtest_filter=CoroutineTestor.Switch
#./yf_coroutine_testor --gtest_filter=CoroutineTestor.Sleep
#./yf_coroutine_testor --gtest_filter=CoroutineTestor.IpcCond
#./yf_coroutine_testor --gtest_filter=CoroutineTestor.IpcLock
#./yf_coroutine_testor --gtest_filter=CoroutineTestor.SocketActive 2>/dev/null
#./yf_coroutine_testor --gtest_filter=CoroutineTestor.Dns
./yf_coroutine_testor --gtest_filter=CoroutineTestor.Mysql 
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
