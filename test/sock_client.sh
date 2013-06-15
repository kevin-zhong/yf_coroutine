#!/bin/bash

#/usr/sbin/setenforce 0 

ulimit -c unlimited

YFR_SO="$HOME/yf_coroutine/src/.libs/libyf_coroutine.so"
YF_SO="$HOME/yifei/src/.libs/"

#linux
export LD_PRELOAD="$YFR_SO"
export LD_LIBRARY_PATH=$YF_SO:$LD_LIBRARY_PATH

#mac
export DYLD_FORCE_FLAT_NAMESPACE=1
export DYLD_INSERT_LIBRARIES=`echo $LD_PRELOAD | sed 's/\.so/\.dylib/g'`
export DYLD_LIBRARY_PATH=$YF_SO:$DYLD_LIBRARY_PATH

rm log/sock_client.log

./yf_sock_testor 10240000 2>&1 > /tmp/client.log

echo "test finished !!"
sleep 36

last_block_r=`grep "coroutine ended" log/sock_svr.log | tail -1 | awk -F"=" '{print $4}'`
if [ ! "a"$last_block_r == 'a4' ];then
	echo "exception last_block_r cnt=$last_block_r, errrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr"
fi

echo "all done !!"

