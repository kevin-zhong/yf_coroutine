includedir=@prefix@/yf_coroutine/include
libdir=@prefix@/yf_coroutine/lib

nobase_include_HEADERS= yfr_config.h yfr_head.h \
    ./coroutine/yfr_coroutine.h \
    ./syscall_hook/*.h
    
lib_LTLIBRARIES=libyf_coroutine.la

#ldd yf_coroutine.so with dl+pthread, so the user dont need to add this to makefile
AM_LDFLAGS=-lpthread -ldl

libyf_coroutine_la_SOURCES= \
./coroutine/yfr_coroutine.c \
./coroutine/yfr_greenlet.c \
./syscall_hook/yfr_dlsym.c \
./syscall_hook/yfr_syscall.c \
./syscall_hook/yfr_syscall_raw.c \
./syscall_hook/yfr_ipc.c \
./syscall_hook/yfr_syscall_socket.c \
./syscall_hook/yfr_socket_ext.c \
./syscall_hook/yfr_syscall_bridge.c \
./syscall_hook/yfr_syscall_dns.c \
./syscall_hook/yfr_syscall_va.S \
./coroutine/greenlet-asm.S


