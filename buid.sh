autoheader
aclocal
autoconf
glibtoolize -f -c
automake -a
mkdir -p m4
mkdir -p test/log
rm aclocal.m4
#./configure  --enable-unit-test
#make
