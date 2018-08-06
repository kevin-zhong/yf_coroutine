autoheader
aclocal
autoconf
libtoolize -f -c
automake -a
mkdir -p m4
rm aclocal.m4
#./configure  --enable-unit-test --enable-multi-evt-driver
#make