#include "yfr_syscall.h"

#define  _YFR_SYSCALL_DNS_GETHOST     1
#define  _YFR_SYSCALL_DNS_GETHOST2   2
#define  _YFR_SYSCALL_DNS_GETHOSTR   3
#define  _YFR_SYSCALL_DNS_GETHOSTR2  4
#define  _YFR_SYSCALL_DNS_GETADDR     5

static yf_lock_t  _yfr_syscall_dns_lock = YF_LOCK_INITIALIZER;

#define _yfr_syscall_dns_argset(t, v, i) *((t*)yf_mem_off(buf, i*YF_SIZEOF_PTR)) = v
#define _yfr_syscall_dns_argget(t, i) *((t*)yf_mem_off(buf, i*YF_SIZEOF_PTR))

#define _YFR_SYSCALL_DNS_BUF_SIZE 1024


void yfr_syscall_dns_hostent_cpy(struct hostent* rhost
                , char* rbuf, size_t buf_len, struct hostent* hret)
{
        char *rbuf_tmp, * rbuf_end = rbuf + buf_len;
        char **hpptr = NULL, **hpptr2 = NULL;
        int hcnt = 0, str_len = 0;
        
        rhost->h_addrtype = hret->h_addrtype;
        rhost->h_length = hret->h_length;
        
        //copy host
        rbuf_tmp = rbuf;
        
        hcnt = 0;
        for (hpptr = hret->h_addr_list; *hpptr != NULL; ++hpptr)
                ++hcnt;
        hcnt = yf_min(hcnt, buf_len * 2 /3 /(hret->h_length + sizeof(char*)));

        rhost->h_addr_list = (char**)rbuf_tmp;
        rbuf_tmp += sizeof(char*) * (hcnt + 1);//last end

        hpptr = hret->h_addr_list;
        hpptr2 = rhost->h_addr_list;
        while (hcnt)
        {
                yf_memcpy(rbuf_tmp, *(hpptr++), hret->h_length);
                *hpptr2++ = rbuf_tmp;
                
                rbuf_tmp += hret->h_length;
                --hcnt;
        }
        *hpptr2 = NULL;

        //copy name
        rhost->h_name = rbuf_tmp;
        assert(rbuf_end - 16 > rbuf_tmp);
        str_len = yf_strlen(hret->h_name);
        hcnt = yf_min(str_len + 1, rbuf_end -16 - rbuf_tmp);//include '0'-str end
        yf_memcpy(rhost->h_name, hret->h_name, hcnt - 1);//last end
        rhost->h_name[hcnt-1] = 0;
        rbuf_tmp += hcnt;

        //copy h_aliases
        hcnt = 0;
        for (hpptr = hret->h_aliases; *hpptr != NULL; ++hpptr)
                ++hcnt;

        rbuf_tmp = yf_align_ptr(rbuf_tmp, YF_ALIGNMENT);
        assert(rbuf_end > rbuf_tmp);
        hcnt = yf_min(hcnt, (rbuf_end - rbuf_tmp) / sizeof(char*));

        rhost->h_aliases = (char**)rbuf_tmp;
        rbuf_tmp += sizeof(char*) * (hcnt + 1);//last end

        hpptr = hret->h_aliases;
        hpptr2 = rhost->h_aliases;
        while (hcnt)
        {
                str_len = yf_strlen(hpptr) + 1;
                if (rbuf_end - rbuf_tmp < str_len)
                        break;

                *hpptr2++ = rbuf_tmp;
                rbuf_tmp = yf_cpymem(rbuf_tmp, *(hpptr++), str_len);
                
                --hcnt;
        }
        *hpptr2 = NULL;        
}


void _yfr_syscall_dns_on_query(yf_bridge_t* bridge
                , void* task, size_t len, yf_u64_t id, yf_log_t* log)
{
        char* buf = task;
        int qtype = _yfr_syscall_dns_argget(int, 0);
        yfr_coroutine_t* r = _yfr_syscall_dns_argget(yfr_coroutine_t*, 1);
        
        if (qtype == _YFR_SYSCALL_DNS_GETHOST
                || qtype == _YFR_SYSCALL_DNS_GETHOST2)
        {
                const char *name = _yfr_syscall_dns_argget(const char*, 2);
                struct hostent* rhost = _yfr_syscall_dns_argget(struct hostent*, 3);
                char* rbuf = _yfr_syscall_dns_argget(char*, 4);
                int af = _yfr_syscall_dns_argget(int, 5);

                struct hostent* hret = NULL;
                
                yf_lock(&_yfr_syscall_dns_lock);
                if (qtype == _YFR_SYSCALL_DNS_GETHOST)
                        hret = yf_gethostbyname(name);
#ifdef HAVE_GETHOSTBYNAME2
                else
                        hret = yf_gethostbyname2(name, af);
#endif
                //cause blocked by os, so after wakeup, need to update time
                yf_update_time(NULL, NULL, log);

                if (hret)
                {
                        yfr_syscall_dns_hostent_cpy(rhost, rbuf, _YFR_SYSCALL_DNS_BUF_SIZE, hret);
                        hret = rhost;
                }
                yf_unlock(&_yfr_syscall_dns_lock);

                if (yf_send_task_res(bridge, &hret, sizeof(struct hostent*), id, 0, log) != YF_OK)
                {
                        yf_log_error(YF_LOG_WARN, log, 0, 
                                        "send task res failed, id=%L, try again\n", id);
                }
        }
        
        else if (qtype == _YFR_SYSCALL_DNS_GETHOSTR
                || qtype == _YFR_SYSCALL_DNS_GETHOSTR2)
        {
                const char *name = _yfr_syscall_dns_argget(const char*, 2);
                struct hostent* ret = _yfr_syscall_dns_argget(struct hostent*, 3);
                char* cbuf = _yfr_syscall_dns_argget(char*, 4);
                size_t buflen = _yfr_syscall_dns_argget(size_t, 5);
                struct hostent** result = _yfr_syscall_dns_argget(struct hostent**, 6);
                int* h_errnop = _yfr_syscall_dns_argget(int*, 7);
                int af = _yfr_syscall_dns_argget(int, 8);
                int rflag = 0;

                if (qtype == _YFR_SYSCALL_DNS_GETHOSTR)
                        rflag = yf_gethostbyname_r(name, ret, cbuf, buflen, result, h_errnop);
                else
                        rflag = yf_gethostbyname2_r(name, af, ret, cbuf, buflen, result, h_errnop);

                //cause blocked by os, so after wakeup, need to update time
                yf_update_time(NULL, NULL, log);                

                if (yf_send_task_res(bridge, &rflag, sizeof(int), id, 0, log) != YF_OK)
                {
                        yf_log_error(YF_LOG_WARN, log, 0, 
                                        "send task res failed, id=%L, try again\n", id);
                }
        }

        else if (qtype == _YFR_SYSCALL_DNS_GETADDR)
        {
                const char* node = _yfr_syscall_dns_argget(const char*, 2);
                const char* service = _yfr_syscall_dns_argget(const char*, 3);
                const struct addrinfo* hints = _yfr_syscall_dns_argget(const struct addrinfo*, 4);
                struct addrinfo** res = _yfr_syscall_dns_argget(struct addrinfo**, 5);

                int rflag = getaddrinfo(node, service, hints, res);

                //cause blocked by os, so after wakeup, need to update time
                yf_update_time(NULL, NULL, log);

                if (yf_send_task_res(bridge, &rflag, sizeof(int), id, 0, log) != YF_OK)
                {
                        yf_log_error(YF_LOG_WARN, log, 0, 
                                        "send task res failed, id=%L, try again\n", id);
                }
        }
}

yf_thread_value_t _yfr_syscall_dns_thread_exe(void *arg)
{
        yf_bridge_t* bridge = (yf_bridge_t*)arg;

        yf_int_t ret = yf_attach_bridge(bridge, NULL, _yfr_syscall_dns_on_query, NULL);
        assert(ret == YF_OK);
        
        while (1)
        {
                yf_poll_task(bridge, NULL);
        }
        return NULL;
}


yf_int_t  yfr_syscall_dns_coroutine_attach(yfr_coroutine_mgr_t* mgr, yf_log_t* log)
{
        return YF_OK;
}

typedef struct _yfr_syscall_dns_ctx_s
{
        yf_bridge_t* dns_bridge;
        yf_s8_t  specific_key;
}
_yfr_syscall_dns_ctx_t;


static yf_int_t _yfr_syscall_dns_bridge_init(yfr_coroutine_t* r)
{
        yfr_coroutine_init_t* ctx = yfr_coroutine_mgr_ctx(r);
        _yfr_syscall_dns_ctx_t* dns_ctx = ctx->data[YFR_SYSCALL_DNS];
        if (dns_ctx)
        {
                return dns_ctx->specific_key >= 0 ? YF_OK : YF_ERROR;
        }
        
        dns_ctx = yf_alloc(sizeof(_yfr_syscall_dns_ctx_t));
        CHECK_RV(dns_ctx == NULL, YF_ERROR);
        ctx->data[YFR_SYSCALL_DNS] = dns_ctx;

        dns_ctx->specific_key = yfr_coroutine_mgr_specific_key_alloc(
                                yfr_coroutine_get_mgr(r));
        if (dns_ctx->specific_key < 0)
        {
                yf_log_error(YF_LOG_ERR, r->log, 0, "cant alloc dns specific key");
                return YF_ERROR;
        }

        char* dns_thread_env = getenv("DNS_THREADS_NUM");
        int dns_thread_num = dns_thread_env ? atoi(dns_thread_env) : 1;
        dns_thread_num = yf_max(1, yf_min(dns_thread_num, 16));

        yf_bridge_cxt_t bridge_ctx = {
                        YF_BRIDGE_INS_PROC, 
                        YF_BRIDGE_INS_THREAD,
                        YF_BRIDGE_EVT_DRIVED,
                        YF_BRIDGE_BLOCKED,
                        YF_TASK_DISTPATCH_IDLE,
                        (void*)_yfr_syscall_dns_thread_exe, 
                        dns_thread_num, 
                        1024, 32*dns_thread_num, 512 * 32 * dns_thread_num
                };
        
        yf_bridge_t* dns_bridge = yfr_bridge_create(&bridge_ctx, r->log);
        assert(dns_bridge);
        yf_int_t ret = yfr_attach_res_bridge(dns_bridge, ctx->evt_driver, r->log);
        assert(ret == YF_OK);

        dns_ctx->dns_bridge = dns_bridge;

        return YF_OK;
}

#define _yfr_syscall_dns_specific_get(r, dns_ctx) \
        void** dns_mem = yfr_coroutine_specific(r, dns_ctx->specific_key); \
        struct hostent* hbuf = (struct hostent*)*dns_mem; \
        if (hbuf == NULL) \
        { \
                hbuf = yf_palloc(r->pool, yf_align_mem(sizeof(struct hostent)) + 128 + _YFR_SYSCALL_DNS_BUF_SIZE); \
                CHECK_RV(hbuf == NULL, NULL); \
                *((struct hostent**)dns_mem) = hbuf; \
        } \
        char* cbuf = yf_mem_off(hbuf, yf_align_mem(sizeof(struct hostent)));

#define __yfr_syscall_dns_gethost_args \
        _yfr_syscall_dns_argset(yfr_coroutine_t*, r, 1); \
        _yfr_syscall_dns_argset(const char*, name, 2); \
        _yfr_syscall_dns_argset(struct hostent*, hbuf, 3); \
        _yfr_syscall_dns_argset(char*, cbuf, 4);

struct hostent* gethostbyname(const char *name)
{
        struct hostent* hret = NULL;
        
        yfr_coroutine_t* r = yfr_coroutine_addr(name);
        if (!yfr_coroutine_check(r))
        {
                yfr_syscall_rinit;
                yf_lock(&_yfr_syscall_dns_lock);
                hret = yf_gethostbyname(name);
                yf_unlock(&_yfr_syscall_dns_lock);
                return hret;
        }
        
        if (_yfr_syscall_dns_bridge_init(r) != YF_OK)
                return NULL;

        yfr_coroutine_init_t* ctx = yfr_coroutine_mgr_ctx(r);
        _yfr_syscall_dns_ctx_t* dns_ctx = ctx->data[YFR_SYSCALL_DNS];
   
        _yfr_syscall_dns_specific_get(r, dns_ctx);
        
#ifdef HAVE_GETHOSTBYNAME_R
        struct hostent *r_host = NULL;
        int r_herrno = 0;
        yf_int_t  ret = gethostbyname_r(name, hbuf, cbuf, 
                        _YFR_SYSCALL_DNS_BUF_SIZE, &r_host, &r_herrno);
        if (ret == 0)
                return r_host;
        else {
                yf_log_error(YF_LOG_WARN, r->log, 0, "gethost_r error=%s", hstrerror(r_herrno));
                return NULL;
        }
#else
#ifdef __GNUC__
#warning "no gethostbyname_r, use global lock"
#else
#pragma message("no gethostbyname_r, use global lock")
#endif
        char  buf[6*YF_SIZEOF_PTR] = {0};
        *(int*)buf = _YFR_SYSCALL_DNS_GETHOST;
        
        __yfr_syscall_dns_gethost_args;

#ifdef _COR_TRACE
        yf_log_debug(YF_LOG_DEBUG, r->log, 0,
                "syscall.gethostbyname(%s)", name);
#endif

        //time must == 0
        size_t hhost_size = sizeof(struct hostent*);
        yf_int_t ret = yfr_process_bridge_task(dns_ctx->dns_bridge, buf, sizeof(buf), 0, 0, 
                                &hret, &hhost_size);
        return ret == YF_OK ? hret : NULL;
#endif        
}


#ifdef HAVE_GETHOSTBYNAME2
struct hostent* gethostbyname2(const char *name, int af)
{
        struct hostent* hret = NULL;
        
        yfr_coroutine_t* r = yfr_coroutine_addr(name);
        if (!yfr_coroutine_check(r))
        {
                yfr_syscall_rinit;
                yf_lock(&_yfr_syscall_dns_lock);
                hret = yf_gethostbyname2(name, af);
                yf_unlock(&_yfr_syscall_dns_lock);
                return hret;
        }
        
        if (_yfr_syscall_dns_bridge_init(r) != YF_OK)
                return NULL;

        yfr_coroutine_init_t* ctx = yfr_coroutine_mgr_ctx(r);
        _yfr_syscall_dns_ctx_t* dns_ctx = ctx->data[YFR_SYSCALL_DNS];

        _yfr_syscall_dns_specific_get(r, dns_ctx);

#ifdef HAVE_GETHOSTBYNAME_R
        struct hostent *r_host = NULL;
        int r_herrno = 0;
        yf_int_t  ret = gethostbyname2_r(name, af, hbuf, cbuf, 
                        _YFR_SYSCALL_DNS_BUF_SIZE, &r_host, &r_herrno);
        if (ret == 0)
                return r_host;
        else {
                yf_log_error(YF_LOG_WARN, r->log, 0, "gethost_r error=%s", hstrerror(r_herrno));
                return NULL;
        }
#else
#ifdef __GNUC__
#warning "no gethostbyname2_r, use global lock"
#else
#pragma message("no gethostbyname2_r, use global lock")
#endif        
        char  buf[6*YF_SIZEOF_PTR] = {0};
        *(int*)buf = _YFR_SYSCALL_DNS_GETHOST2;

        __yfr_syscall_dns_gethost_args;
        _yfr_syscall_dns_argset(int, af, 5);

#ifdef _COR_TRACE
        yf_log_debug(YF_LOG_DEBUG, r->log, 0,
                "syscall.gethostbyname2(%s)", name);
#endif

        //time must == 0
        size_t  hhost_size = sizeof(struct hostent*);
        yf_int_t ret = yfr_process_bridge_task(dns_ctx->dns_bridge, buf, sizeof(buf), 0, 0, 
                                &hret, &hhost_size);
        return ret == YF_OK ? hret : NULL;
#endif        
}
#endif

#define __yfr_syscall_dns_gethostr_args \
        _yfr_syscall_dns_argset(yfr_coroutine_t*, r, 1); \
        _yfr_syscall_dns_argset(const char*, name, 2); \
        _yfr_syscall_dns_argset(struct hostent*, ret, 3); \
        _yfr_syscall_dns_argset(char*, cbuf, 4); \
        _yfr_syscall_dns_argset(size_t, buflen, 5); \
        _yfr_syscall_dns_argset(struct hostent**, result, 6); \
        _yfr_syscall_dns_argset(int*, h_errnop, 7);

#ifdef HAVE_GETHOSTBYNAME_R
int gethostbyname_r(const char *name,
       struct hostent *ret, char *cbuf, size_t buflen,
       struct hostent **result, int *h_errnop)
{
        yfr_coroutine_t* r = yfr_coroutine_addr(name);
        if (!yfr_coroutine_check(r))
        {
                yfr_syscall_rinit;
                return yf_gethostbyname_r(name, ret, cbuf, buflen, result, h_errnop);
        }
        
        if (_yfr_syscall_dns_bridge_init(r) != YF_OK)
                return -1;

#ifdef _COR_TRACE
        yf_log_debug(YF_LOG_DEBUG, r->log, 0,
                "syscall.gethostbyname_r(%s)", name);
#endif

        yfr_coroutine_init_t* ctx = yfr_coroutine_mgr_ctx(r);
        _yfr_syscall_dns_ctx_t* dns_ctx = ctx->data[YFR_SYSCALL_DNS];
        
        char  buf[9*YF_SIZEOF_PTR] = {0};
        *(int*)buf = _YFR_SYSCALL_DNS_GETHOSTR;
        
        __yfr_syscall_dns_gethostr_args;
        
        //time must == 0
        int rflag = 0;
        size_t flag_size = sizeof(int);
        yf_int_t bret = yfr_process_bridge_task(dns_ctx->dns_bridge, buf, sizeof(buf), 0, 0, 
                                &rflag, &flag_size);
        return bret == YF_OK ? rflag : -1;
}
#endif


#ifdef HAVE_GETHOSTBYNAME2_R
int gethostbyname2_r(const char *name, int af,
       struct hostent *ret, char *cbuf, size_t buflen,
       struct hostent **result, int *h_errnop)
{
        yfr_coroutine_t* r = yfr_coroutine_addr(name);
        if (!yfr_coroutine_check(r))
        {
                yfr_syscall_rinit;
                return yf_gethostbyname2_r(name, af, ret, cbuf, buflen, result, h_errnop);
        }
        
        if (_yfr_syscall_dns_bridge_init(r) != YF_OK)
                return -1;

#ifdef _COR_TRACE
        yf_log_debug(YF_LOG_DEBUG, r->log, 0,
                "syscall.gethostbyname2_r(%s)", name);
#endif

        yfr_coroutine_init_t* ctx = yfr_coroutine_mgr_ctx(r);
        _yfr_syscall_dns_ctx_t* dns_ctx = ctx->data[YFR_SYSCALL_DNS];
        
        char  buf[9*YF_SIZEOF_PTR] = {0};
        *(int*)buf = _YFR_SYSCALL_DNS_GETHOSTR2;
        
        __yfr_syscall_dns_gethostr_args;
        _yfr_syscall_dns_argset(int, af, 8);
        
        //time must == 0
        int rflag = 0;
        size_t flag_size = sizeof(int);
        yf_int_t bret = yfr_process_bridge_task(dns_ctx->dns_bridge, buf, sizeof(buf), 0, 0, 
                                &rflag, &flag_size);
        return bret == YF_OK ? rflag : -1;
}
#endif


int getaddrinfo(const char *node, const char *service, 
               const struct addrinfo *hints, 
               struct addrinfo **res)
{
        yfr_coroutine_t* r = yfr_coroutine_addr(node);
        if (!yfr_coroutine_check(r))
        {
                yfr_syscall_rinit;
                return yf_getaddrinfo(node, service, hints, res);
        }
        
        if (_yfr_syscall_dns_bridge_init(r) != YF_OK)
                return -1;

#ifdef _COR_TRACE
        yf_log_debug(YF_LOG_DEBUG, r->log, 0,
                "syscall.getaddrinfo(node:%s, service:%s)", node, service);
#endif

        yfr_coroutine_init_t* ctx = yfr_coroutine_mgr_ctx(r);
        _yfr_syscall_dns_ctx_t* dns_ctx = ctx->data[YFR_SYSCALL_DNS];
        
        char  buf[6*YF_SIZEOF_PTR] = {0};
        *(int*)buf = _YFR_SYSCALL_DNS_GETADDR;
        _yfr_syscall_dns_argset(yfr_coroutine_t*, r, 1);
        
        _yfr_syscall_dns_argset(const char*, node, 2);
        _yfr_syscall_dns_argset(const char*, service, 3);
        _yfr_syscall_dns_argset(const struct addrinfo*, hints, 4);
        _yfr_syscall_dns_argset(struct addrinfo**, res, 5);
        
        //time must == 0
        int rflag = 0;
        size_t flag_size = sizeof(int);
        yf_int_t ret = yfr_process_bridge_task(dns_ctx->dns_bridge, buf, sizeof(buf), 0, 0, 
                                &rflag, &flag_size);
        return ret == YF_OK ? rflag : -1;
}

