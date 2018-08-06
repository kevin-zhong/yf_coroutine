#include "yfr_dlsym.h"
#include <dlfcn.h>

typedef struct _dlsym_loaded_so_s
{
        const char* soname;
        void* sohandle;
}
_dlsym_loaded_so_t;

yf_int_t yfr_syscall_inited = 0;
static yf_lock_t  _yfr_syscall_init_lock = YF_LOCK_INITIALIZER;


yf_int_t  yfr_dlsym_lookup(yfr_dlsym_info_t* hooks)
{
        yf_u32_t i1 = 0;
        yf_int_t ret = YF_OK;
        void* sohandle = NULL;
        char* dlopen_err = NULL;
        
        _dlsym_loaded_so_t  loaded_sos[32];
        yf_memzero_st(loaded_sos);

        for (; hooks->target_fnname; ++hooks)
        {
                for (i1 = 0; i1 < YF_ARRAY_SIZE(loaded_sos) && loaded_sos[i1].soname; i1++)
                {
                        if (yf_strcmp(loaded_sos[i1].soname, hooks->target_soname) == 0)
                                break;
                }
                
                if (i1 == YF_ARRAY_SIZE(loaded_sos))
                {
                        fprintf(stderr, "too many so to hook...");
                        ret = YF_ERROR;
                        break;
                }

                if (loaded_sos[i1].soname == NULL)
                {
                        sohandle = dlopen(hooks->target_soname, RTLD_LAZY);
                        if ((dlopen_err = dlerror()) != NULL)//if err != NULL
                        {
                                fprintf(stderr, "dlopen failed, soname=%s, err=%s", 
                                                hooks->target_soname, dlopen_err);
                                ret = YF_ERROR;
                                break;
                        }
                        
                        loaded_sos[i1].sohandle = sohandle;
                        loaded_sos[i1].soname = hooks->target_soname;
                }

                *hooks->org_fn = dlsym(loaded_sos[i1].sohandle, hooks->target_fnname);
                if ((dlopen_err = dlerror()) != NULL)//if err != NULL
                {
                        fprintf(stderr, "dlsym failed, soname=%s, fnname=%s, err=%s", 
                                        hooks->target_soname, hooks->target_fnname, 
                                        dlopen_err);
                        ret = YF_ERROR;
                        break;
                }                
        }

        for ( i1 = 0; i1 < YF_ARRAY_SIZE(loaded_sos); i1++ )
        {
                if (loaded_sos[i1].soname == NULL)
                        break;

                dlclose(loaded_sos[i1].sohandle);
        }
        
        return  ret;
}


yf_int_t  yfr_syscall_init()
{

#ifdef YF_DARWIN
        const char* lib_name = "libSystem.dylib";
#else
        const char* lib_name = "libc.so.6";
#endif

#define _DLSYM_SYSCALL(n) {# n, lib_name, (void**)&yf_##n}

        yfr_dlsym_info_t dlsym_infos[] = {
                _DLSYM_SYSCALL(usleep),
                _DLSYM_SYSCALL(sleep),
                _DLSYM_SYSCALL(close),
                _DLSYM_SYSCALL(shutdown),
                _DLSYM_SYSCALL(read),
                _DLSYM_SYSCALL(write),
                _DLSYM_SYSCALL(recvfrom),
                _DLSYM_SYSCALL(sendto),
                _DLSYM_SYSCALL(sendmsg),
                _DLSYM_SYSCALL(recvmsg),
                _DLSYM_SYSCALL(readv),
                _DLSYM_SYSCALL(writev),
                _DLSYM_SYSCALL(socket),
                _DLSYM_SYSCALL(connect), 
                _DLSYM_SYSCALL(accept),
                _DLSYM_SYSCALL(fcntl),
                _DLSYM_SYSCALL(getsockopt),
                _DLSYM_SYSCALL(setsockopt), 
                _DLSYM_SYSCALL(gethostbyname),
                _DLSYM_SYSCALL(getaddrinfo), 
                _DLSYM_SYSCALL(ioctl), 
#ifdef  HAVE_SYS_SELECT_H
                _DLSYM_SYSCALL(select),
#endif
#ifdef  HAVE_POLL_H
                _DLSYM_SYSCALL(poll),
#endif

#ifdef HAVE_GETHOSTBYNAME2
                _DLSYM_SYSCALL(gethostbyname2),
#endif
#ifdef HAVE_GETHOSTBYNAME_R
                _DLSYM_SYSCALL(gethostbyname_r),
#endif
#ifdef HAVE_GETHOSTBYNAME2_R
                _DLSYM_SYSCALL(gethostbyname2_r),
#endif
                {NULL, NULL, NULL}
        };

        yf_int_t ret = YF_OK;
        yf_lock(&_yfr_syscall_init_lock);
        if (!yfr_syscall_inited)
        {
                ret = yfr_dlsym_lookup(dlsym_infos);
                if (ret == YF_OK)
                        yfr_syscall_inited = 1;
        }
        yf_unlock(&_yfr_syscall_init_lock);

        return ret;
}

