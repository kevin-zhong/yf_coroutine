lib_LTLIBRARIES=libyf_coroutine.la

#ldd yf_coroutine.so with dl+pthread, so the user dont need to add this to makefile
AM_LDFLAGS=-lpthread -ldl

libyf_coroutine_la_SOURCES= \
./coroutine/yfr_coroutine.c \
./coroutine/yfr_greenlet.c \
./syscall_hook/yfr_dlsym.c \
./syscall_hook/yfr_syscall.c \
./syscall_hook/yfr_ipc.c \
./syscall_hook/yfr_syscall_socket.c \
./syscall_hook/yfr_socket_ext.c \
./syscall_hook/yfr_syscall_bridge.c \
./syscall_hook/yfr_syscall_dns.c \
./coroutine/greenlet-asm.S


