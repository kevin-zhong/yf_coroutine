#ifndef _YFR_DLSYM_H_20130227_H
#define _YFR_DLSYM_H_20130227_H
/*
* copyright@: kevin_zhong, mail:qq2000zhong@gmail.com
* time: 20130227-19:32:24
*/

#include <yfr_head.h>

typedef struct
{
        const char* target_fnname;
        const char* target_soname;
        void** org_fn;
}
yfr_dlsym_info_t;


//cant use log in this func...
yf_int_t  yfr_dlsym_lookup(yfr_dlsym_info_t* hooks/*, yf_log_t* log*/);
yf_int_t  yfr_syscall_init();

extern yf_int_t yfr_syscall_inited;

#define yfr_syscall_rinit do { \
                if (!yfr_syscall_inited) { \
                        yfr_syscall_init(); \
                        assert(yfr_syscall_inited); \
                } \
        } while (0)

#endif

