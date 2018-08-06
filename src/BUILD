cc_library(
    name = 'yf_coroutine',
    srcs = [
         'coroutine/yfr_coroutine.c',
         'coroutine/yfr_greenlet.c',
         'syscall_hook/yfr_dlsym.c',
         'syscall_hook/yfr_syscall.c',
         'syscall_hook/yfr_syscall_raw.c',
         'syscall_hook/yfr_ipc.c',
         'syscall_hook/yfr_syscall_socket.c',
         'syscall_hook/yfr_socket_ext.c',
         'syscall_hook/yfr_syscall_bridge.c',
         'syscall_hook/yfr_syscall_dns.c',
         'coroutine/greenlet-asm.S',
         'syscall_hook/yfr_syscall_va.S',
    ],
    incs = ['.'],
    export_incs = ['.'],
    deps = ['//thirdparty/yifei_coroutine/yifei:yifei'],
    #defs=['_COR_TRACE'],
    #extra_cppflags = ['-Wno-unused-variable', '-Wno-sign-compare', '-Wno-return-type', '-Wno-empty-body', '-Wno-char-subscripts'],
)

