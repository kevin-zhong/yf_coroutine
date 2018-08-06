#include "yfr_syscall.h"


extern yf_int_t  yfr_syscall_socket_coroutine_attach(
                yfr_coroutine_mgr_t* mgr, yf_log_t* log);
extern yf_int_t  yfr_syscall_ipc_coroutine_attach(
                yfr_coroutine_mgr_t* mgr, yf_log_t* log);
extern yf_int_t  yfr_syscall_socket_ext_coroutine_attach(
                yfr_coroutine_mgr_t* mgr, yf_log_t* log);
extern yf_int_t  yfr_syscall_dns_coroutine_attach(
                yfr_coroutine_mgr_t* mgr, yf_log_t* log);

extern yf_int_t  yfr_syscall_poll_coroutine_attach(yfr_coroutine_mgr_t* mgr, yf_log_t* log);


yf_int_t  yfr_syscall_coroutine_attach(yfr_coroutine_mgr_t* mgr, yf_log_t* log)
{
        if (yfr_syscall_socket_coroutine_attach(mgr, log) != YF_OK)
                return YF_ERROR;
        if (yfr_syscall_ipc_coroutine_attach(mgr, log) != YF_OK)
                return YF_ERROR;
        if (yfr_syscall_socket_ext_coroutine_attach(mgr, log) != YF_OK)
                return YF_ERROR;
        if (yfr_syscall_poll_coroutine_attach(mgr, log) != YF_OK)
                return YF_ERROR;
        if (yfr_syscall_dns_coroutine_attach(mgr, log) != YF_OK)
                return YF_ERROR;
        return YF_OK;
}


static void _yfr_syscall_sleep_timeout_handler(
                struct yf_tm_evt_s* evt, yf_time_t* start)
{
        yfr_coroutine_t* r = evt->data;

        yf_int_t ret = yfr_coroutine_resume(r, evt->data3[0]);
        assert(ret == 0);
}


static inline yf_int_t _yfr_syscall_sleep(yfr_coroutine_t* r, 
                unsigned int s, unsigned int ms)
{
        yf_evt_driver_t* evt_driver = yfr_coroutine_mgr_ctx(r)->evt_driver;
        yf_tm_evt_t* tm_evt = NULL;
        yf_time_t tm = {s, ms};

#ifdef _COR_TRACE
        yf_log_debug(YF_LOG_DEBUG, r->log, 0,
                "syscall.sleep(%d ms)", ms);
#endif
        
        CHECK_RV(yf_alloc_tm_evt(evt_driver, &tm_evt, r->log), YF_ERROR);

        tm_evt->data = r;
        tm_evt->timeout_handler = _yfr_syscall_sleep_timeout_handler;
        yf_register_tm_evt(tm_evt, &tm);

        yfr_coroutine_block(r, &tm_evt->data3[0]);

        //after resume
        yf_free_tm_evt(tm_evt);
        return YF_OK;
}


yf_usleep_ret_t usleep(unsigned int us)
{
        yfr_coroutine_t* r = yfr_coroutine_addr(us);
        if (unlikely(!yfr_coroutine_check(r)))
        {
                yfr_syscall_rinit;
#ifndef YF_FREEBSD
                return yf_usleep(us);
#else
                yf_usleep(us);
                return;
#endif
        }

        yf_int_t ret = _yfr_syscall_sleep(r, 0, us / 1000);
#ifndef YF_FREEBSD
        return ret == YF_OK ? 0 : -1;
#endif
}

unsigned int sleep(unsigned int s)
{
        yfr_coroutine_t* r = yfr_coroutine_addr(s);
        if (unlikely(!yfr_coroutine_check(r)))
        {
                yfr_syscall_rinit;
                return yf_sleep(s);
        }

        return _yfr_syscall_sleep(r, s, 0) == YF_OK ? 0 : s;
}


inline char* yfr_coroutine_log(char* buf, char* last, yf_uint_t level)
{
        int rlen = 0;
        yfr_coroutine_t* r = yfr_coroutine_addr(buf);
        if (unlikely(!yfr_coroutine_check(r)))
        {
                yf_strncpy2(buf, last, "_", 1, rlen);
        }
        else
                buf = yf_sprintf_num(buf, last, r->id, 0, 0, 0);

        return buf;
}


