AM_CPPFLAGS=-I${top_srcdir}/src ${mysql_include}
AM_LDFLAGS=/usr/local/lib/libgtest.a -L${top_srcdir}/src/.libs -lyf_coroutine ${mysql_lib}

noinst_PROGRAMS=yf_coroutine_testor yf_sock_testor

yf_coroutine_testor_SOURCES=yf_coroutine_testor.cpp
yf_sock_testor_SOURCES=yf_sock_testor.cpp

