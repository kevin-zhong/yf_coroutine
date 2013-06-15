#!/bin/bash

#/usr/sbin/setenforce 0 

ulimit -c unlimited
rm -rf log/sock_svr.log
rm -rf log/*.sock

YFR_SO="$HOME/yf_coroutine/src/.libs/libyf_coroutine.so"
YF_SO="$HOME/yifei/src/.libs/"

#linux
export LD_PRELOAD="$YFR_SO"
export LD_LIBRARY_PATH=$YF_SO:$LD_LIBRARY_PATH

#mac
export DYLD_FORCE_FLAT_NAMESPACE=1
export DYLD_INSERT_LIBRARIES=`echo $LD_PRELOAD | sed 's/\.so/\.dylib/g'`
export DYLD_LIBRARY_PATH=$YF_SO:$DYLD_LIBRARY_PATH

./yf_sock_testor 0

echo "exit status=$?"

