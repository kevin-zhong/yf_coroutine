#AM_CPPFLAGS=-I/Users/qq2000zhong/Library/gtest-1.7.0/include -I${top_srcdir}/src ${mysql_include} -DGTEST_USE_OWN_TR1_TUPLE=1 
AM_CPPFLAGS=-I${top_srcdir}/src ${mysql_include} -fno-omit-frame-pointer
AM_LDFLAGS=-L/usr/local/lib/ -lgtest ${top_srcdir}/src/.libs/libyf_coroutine.a ${mysql_lib} -ldl -lstdc++
#AM_LDFLAGS=-L/Users/qq2000zhong/Library/gtest-1.7.0/lib/.libs/ -lgtest -L${top_srcdir}/src/.libs/ -lyf_coroutine ${mysql_lib} -ldl -lstdc++

noinst_PROGRAMS=yf_coroutine_testor yf_sock_testor yf_echo_svr

yf_coroutine_testor_SOURCES=yf_coroutine_testor.cpp
yf_sock_testor_SOURCES=yf_sock_testor.cpp
yf_echo_svr_SOURCES=yf_echo_svr.cpp

