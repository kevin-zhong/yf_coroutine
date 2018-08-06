#include "yfr_syscall.h"
#include <mio_driver/yf_send_recv.h>

typedef struct _yfr_syscall_socket_ctx_s
{
        //SOCK_STREAM, SOCK_DGRAM
        int  type;
        yf_u32_t  opened:1;
        yf_u32_t  unblocked:1;
        yf_u32_t  notsock:1;
        
        yf_fd_event_t*  evt[2];

        //lock exist and active always, even if fd closed...
        yfr_ipc_lock_t  lock[2];
        
        yf_u32_t  timeout[2];//ms

        yf_u32_t  conn_timeout;//ms
}
_yfr_syscall_socket_ctx_t;


yf_int_t  yfr_syscall_socket_coroutine_attach(yfr_coroutine_mgr_t* mgr, yf_log_t* log)
{
        yf_u32_t i1 = 0;
        yfr_coroutine_init_t* ctx = yfr_coroutine_mgr_ctx2(mgr);

        yf_u32_t  fds = yf_evt_driver_ctx(ctx->evt_driver)->nfds;
        
        _yfr_syscall_socket_ctx_t* socket_ctx = yf_alloc(
                        sizeof(_yfr_syscall_socket_ctx_t) * fds);
        CHECK_RV(socket_ctx == NULL, YF_ERROR);

        ctx->data[YFR_SYSCALL_SOCKET] = socket_ctx;

        for ( i1 = 0; i1 < fds ; i1++ )
        {
                yfr_ipc_lock_init(socket_ctx[i1].lock);
                yfr_ipc_lock_init(socket_ctx[i1].lock + 1);
        }

        yf_log_debug(YF_LOG_DEBUG, log, 0, "syscall socket atatch fd num=%d", fds);
        
        return  YF_OK;
}


static const char*  _yfr_syscall_socket_desc[] = {"read", "write"};

/*
* check fd is file or dir...
*/
#define _yfr_syscall_socket_verify(r, fd, ctx, _do) do { \
        if (!ctx->opened) { \
                if (!ctx->notsock) { \
                        struct stat stat_buf; \
                        if (yf_fd_info(fd, &stat_buf) < 0) { \
                                yf_log_error(YF_LOG_WARN, r->log, yf_errno, "fd=%d %s error", fd, # _do); \
                                return YF_ERROR; \
                        } \
                        ctx->notsock = yf_is_file(&stat_buf) || yf_is_dir(&stat_buf) || yf_is_link(&stat_buf); \
                } \
                if (ctx->notsock) { \
                        return (_do); \
                } \
        } \
} while (0)

/*
* check fd opened by coroutine socket
*/
#define _yfr_syscall_socket_valid(r, fd, ctx) do { \
        if (!ctx->opened) { \
                yf_log_error(YF_LOG_WARN, r->log, 0, "socket=%d not opened", fd); \
                yf_socket_errno = YF_EBADF; \
                return -1; \
        } \
} while(0)

/*
* lock + unlock socket
*/
#define _yfr_syscall_socket_lock(fd, ctx, r, type, waited, tm) \
        YFR_WAIT_REC_BEGIN; \
        yf_s32_t  time_left = tm; \
        yf_time_t  _time; \
        yf_time_t* tmptr = tm ? &_time : NULL; \
        \
        ret = yfr_ipc_lock(ctx->lock + type, tm, &waited); \
        if (unlikely(ret != YF_OK)) \
        { \
                if (r) { \
                        yf_log_error(YF_LOG_WARN, r->log, yf_errno, \
                                        "fd=%d %s lock err", \
                                        fd, _yfr_syscall_socket_desc[type]); \
                } \
                return -1; \
        } \
        if (unlikely(waited && tmptr)) { \
                time_left = yfr_wait_time_left(time_left); \
        }

/*
* check socket if it's ok
*/
#define _yfr_syscall_socket_status_chck(fd, ctx, evt, r, type) \
        if (!ctx->opened) { \
                yf_log_error(YF_LOG_WARN, r->log, 0, "fd=%d already closed", fd); \
                if (already_locked) \
                        yfr_ipc_unlock(ctx->lock + type); \
                return -1; \
        } \
        if (evt->eof || evt->error || evt->shutdown) \
        { \
                yf_log_error(YF_LOG_WARN, r->log, YF_EPIPE, \
                                "fd=%d %s status=%d,%d,%d", \
                                fd, _yfr_syscall_socket_desc[type], \
                                evt->eof, evt->error, evt->shutdown); \
                if (already_locked) \
                        yfr_ipc_unlock(ctx->lock + type); \
                yf_socket_errno = YF_EPIPE; \
                return -1; \
        }


/*
* block coroutine, regist fd evt
* why check status again after lock success ? just think...
*/

/*
* found big bug, org yf_socket_errno = YF_EAGAINNO; was before yf_log_debug2
* but if yf_log_debug2 call log4plus..., errno will be set to 0 !!!!
* so, dont call log as will
*
* FIXED: in unblocking mode, if call send/recv without poll/select before, then
* will return err forever..., cause no chance to register evt...
* when 2017/05/02 18:50
*/

#define  _yfr_syscall_socket_rw(r, fd, ctx, type, _unblock) \
        yf_int_t ret = 0; \
        yf_int_t waited = 0, already_locked = 0; \
        yf_fd_event_t* evt = ctx->evt[type]; \
        \
        _yfr_syscall_socket_status_chck(fd, ctx, evt, r, type); \
        _yfr_syscall_socket_lock(fd, ctx, r, type, waited, ctx->timeout[type]); \
        already_locked = 1; \
        if (unlikely(waited)) { \
                _yfr_syscall_socket_status_chck(fd, ctx, evt, r, type); \
        } \
        evt->data = r; \
        evt->fd_evt_handler = _yfr_syscall_on_rwable; \
        fd_rw_ctx_t  rw_ctx = {0, evt, NULL}; \
        \
rw_again: \
        if (!evt->ready) \
        { \
                if (_unblock) \
                { \
                        yf_log_debug2(YF_LOG_DEBUG, r->log, YF_EAGAINNO, \
                                        "fd=%d %s not ready now", \
                                        fd, _yfr_syscall_socket_desc[type]); \
                        yf_socket_errno = YF_EAGAINNO; \
                        rr = YF_ERROR; \
                        yf_activate_fd_evt(evt); \
                        goto end; \
                } \
                if (tmptr) \
                        yf_ms_2_time(time_left, tmptr); \
                \
                ret = yf_register_fd_evt(evt, tmptr); \
                assert(ret == YF_OK); \
                yfr_coroutine_block(r, &evt->data3[0]); \
                \
                if (evt->timeout) \
                { \
                        yf_log_error(YF_LOG_WARN, r->log, YF_ETIMEDOUT, \
                                        "fd=%d %s wait data timeout", \
                                        fd, _yfr_syscall_socket_desc[type]); \
                        yf_socket_errno = YF_ETIMEDOUT; \
                        rr = YF_ERROR; \
                        goto end; \
                } \
        }


/*
* check read write result
*/
#define _yfr_syscall_socket_rw_check(r, fd, ctx, type, oc) \
        if (rr == YF_AGAIN oc(rr)) \
        { \
                if (tmptr) \
                { \
                        time_left = yfr_wait_time_left(time_left); \
                        if (time_left < 0) \
                                time_left = 2; \
                } \
                goto rw_again; \
        } \
end: \
        assert (already_locked); \
        yfr_ipc_unlock(ctx->lock + type);

#define _YFR_SYSCALL_RWN(rr)


static yf_int_t  _yfr_socket_lock_helper(yfr_coroutine_t* r
                , _yfr_syscall_socket_ctx_t* ctx, int fd
                , int rwtype
                , yf_u32_t tm)
{
        yf_int_t ret = 0;
        yf_int_t waited = 0;
        _yfr_syscall_socket_lock(fd, ctx, r, rwtype, waited, tm);
        return ret;
}

#define _yfr_syscall_socket_ctx(r, fd) \
        ((_yfr_syscall_socket_ctx_t*)(yfr_coroutine_mgr_ctx(r)->data[YFR_SYSCALL_SOCKET])) + fd


/*
* shutdown & close all lock read+write, so dead lock may happen
* 2013/05/24 found a dead lock in yfr_socket_ext.c if read & write error at the same time...
*/
int close_impl(int fd, yfr_coroutine_init_t* init_info, yfr_coroutine_t* r)
{
        _yfr_syscall_socket_ctx_t* ctx = (_yfr_syscall_socket_ctx_t*)
                                init_info->data[YFR_SYSCALL_SOCKET] + fd;

        yf_log_debug(YF_LOG_DEBUG, r->log, 0, "close fd impl..%d", fd);
        _yfr_syscall_socket_valid(r, fd, ctx);
        
        while (_yfr_socket_lock_helper(r, ctx, fd, 0, 0) != YF_OK)
                usleep(1000);
        while (_yfr_socket_lock_helper(r, ctx, fd, 1, 0) != YF_OK)
                usleep(1000);

        //must check, maybe close by other coroutine
        if (ctx->opened)
        {
                yf_free_fd_evt(ctx->evt[0], ctx->evt[1]);
                ctx->evt[0] = NULL;
                ctx->evt[1] = NULL;
                ctx->opened = 0;
                yf_close(fd);
                yf_log_debug(YF_LOG_DEBUG, r->log, 0, "fd=%d closed", fd);
        }

        yfr_ipc_unlock(ctx->lock);
        yfr_ipc_unlock(ctx->lock+1);
        
        //TODO, support keepalive conn
        
        return YF_OK;
}


int  close(int fd)
{
        yfr_coroutine_t* r = yfr_coroutine_addr(fd);
        if (!yfr_coroutine_check(r))
        {
                yfr_syscall_rinit;
                assert(yf_close != close);
                return yf_close(fd);
        }

        yf_log_debug(YF_LOG_DEBUG, r->log, 0,
                "syscall.close(fd:%d)", fd);

        _yfr_syscall_socket_ctx_t* ctx = _yfr_syscall_socket_ctx(r, fd);
        if (!ctx->opened)
        {
                ctx->notsock = 0;
                return yf_close(fd);
        }
        
        return  close_impl(fd, yfr_coroutine_mgr_ctx(r), r);
}

int shutdown(int fd, int howto)
{
        yfr_coroutine_t* r = yfr_coroutine_addr(fd);
        if (!yfr_coroutine_check(r))
        {
                yfr_syscall_rinit;
                return yf_shutdown(fd, howto);
        }

        _yfr_syscall_socket_ctx_t* ctx = _yfr_syscall_socket_ctx(r, fd);
        _yfr_syscall_socket_valid(r, fd, ctx);

        if (SHUT_RD == howto || SHUT_RDWR == howto)
        {
                while (_yfr_socket_lock_helper(r, ctx, fd, 0, 0) != YF_OK)
                        usleep(1000);
        }

        if (SHUT_WR == howto || SHUT_RDWR == howto)
        {
                while (_yfr_socket_lock_helper(r, ctx, fd, 1, 0) != YF_OK)
                        usleep(1000);
        }

#ifdef _COR_TRACE
        yf_log_debug(YF_LOG_DEBUG, r->log, 0,
                "syscall.shutdown(fd:%d, howto:%d)", fd, howto);
#endif

        // TODO, check valid 2015/06/15
        if (SHUT_RD == howto || SHUT_RDWR == howto)
        {
                if (!ctx->evt[0]->shutdown)
                {
                        yf_shutdown(fd, howto);
                        ctx->evt[0]->shutdown = 1;
                }
        }
        if (SHUT_WR == howto || SHUT_RDWR == howto)
        {
                if (!ctx->evt[1]->shutdown)
                {
                        yf_shutdown(fd, howto);
                        ctx->evt[1]->shutdown = 1;
                }
        }

        if (ctx->evt[0]->shutdown && ctx->evt[1]->shutdown)
        {
                yf_close(fd);
                yf_free_fd_evt(ctx->evt[0], ctx->evt[1]);
                ctx->evt[0] = NULL;
                ctx->evt[1] = NULL;
                ctx->opened = 0;

                yf_log_debug(YF_LOG_DEBUG, r->log, 0, 
                                "fd=%d closed, cause of shutdown", fd);
        }

        if (SHUT_RD == howto || SHUT_RDWR == howto)
                yfr_ipc_unlock(ctx->lock);

        if (SHUT_WR == howto || SHUT_RDWR == howto)
                yfr_ipc_unlock(ctx->lock+1);
        return 0;
}



yf_int_t  yfr_socket_lock(int fd, int rwtype)
{
        yfr_coroutine_t* r = yfr_coroutine_addr(fd);
        if (!yfr_coroutine_check(r))
                return  YF_ERROR;

        _yfr_syscall_socket_ctx_t* ctx = _yfr_syscall_socket_ctx(r, fd);
        //just opend socket can be locked
        _yfr_syscall_socket_valid(r, fd, ctx);

        yf_int_t  rlocked = 0;
        if (rwtype == YFR_SOCKET_READ_T || rwtype == YFR_SOCKET_RW_T)
        {
                if (yfr_ipc_lock(ctx->lock + YFR_SOCKET_READ_T, 
                                ctx->timeout[YFR_SOCKET_READ_T], NULL))
                                return  YF_ERROR;
                rlocked = 1;
        }
        if (rwtype == YFR_SOCKET_WRITE_T || rwtype == YFR_SOCKET_RW_T)
        {
                if (yfr_ipc_lock(ctx->lock + YFR_SOCKET_WRITE_T, 
                                ctx->timeout[YFR_SOCKET_WRITE_T], NULL))
                {
                        if (rlocked)
                                yfr_ipc_unlock(ctx->lock + YFR_SOCKET_READ_T);
                        return  YF_ERROR;
                }
        }
        return  YF_OK;
}


yf_int_t  yfr_socket_unlock(int fd, int rwtype)
{
        yfr_coroutine_t* r = yfr_coroutine_addr(fd);
        if (!yfr_coroutine_check(r))
                return  YF_ERROR;

        _yfr_syscall_socket_ctx_t* ctx = _yfr_syscall_socket_ctx(r, fd);
        //_yfr_syscall_socket_valid(r, fd, ctx);
        
        if (rwtype == YFR_SOCKET_READ_T || rwtype == YFR_SOCKET_RW_T)
        {
                yfr_ipc_unlock(ctx->lock + YFR_SOCKET_READ_T);
        }
        if (rwtype == YFR_SOCKET_WRITE_T || rwtype == YFR_SOCKET_RW_T)
        {
                yfr_ipc_unlock(ctx->lock + YFR_SOCKET_WRITE_T);
        }
        return 0;
}


static void _yfr_syscall_on_rwable(yf_fd_event_t* evt)
{
        yfr_coroutine_t* r = evt->data;
        yf_int_t ret = yfr_coroutine_resume(r, evt->data3[0]);
        assert (ret == 0);

#if defined (YFR_DEBUG) || defined (_COR_TRACE)
        yf_log_debug2(YF_LOG_DEBUG, r->log, 0, 
                "coroutine r=%L will be resumed on evt=[%V]", 
                r->id, &yf_evt_tn(evt));
#endif
}


ssize_t read(int fd, void *buf, size_t count)
{
        yfr_coroutine_t* r = yfr_coroutine_addr(fd);
        if (!yfr_coroutine_check(r))
        {
                yfr_syscall_rinit;
                return yf_read(fd, buf, count);
        }

#ifdef _COR_TRACE
        yf_log_debug(YF_LOG_DEBUG, r->log, 0,
                "syscall.read(fd:%d, count:%z)", fd, count);
#endif

        _yfr_syscall_socket_ctx_t* ctx = _yfr_syscall_socket_ctx(r, fd);
        _yfr_syscall_socket_verify(r, fd, ctx, yf_read(fd, buf, count));

        return  recvfrom(fd, buf, count, 0, 0, 0);
}


ssize_t write(int fd, const void *buf, size_t count)
{
        yfr_coroutine_t* r = yfr_coroutine_addr(fd);
        if (!yfr_coroutine_check(r))
        {
                yfr_syscall_rinit;
                return yf_write(fd, buf, count);
        }

#ifdef _COR_TRACE
        yf_log_debug(YF_LOG_DEBUG, r->log, 0,
                "syscall.write(fd:%d, count:%z)", fd, count);
#endif

        _yfr_syscall_socket_ctx_t* ctx = _yfr_syscall_socket_ctx(r, fd);
        _yfr_syscall_socket_verify(r, fd, ctx, yf_write(fd, buf, count));

        return  sendto(fd, buf, count, 0, 0, 0);
}


ssize_t recv(int s, void *buf, size_t len, int flags)
{
        yfr_coroutine_t* r = yfr_coroutine_addr(s);
        if (!yfr_coroutine_check(r))
        {
                yfr_syscall_rinit;
                return yf_recv(s, buf, len, flags);
        }

        return  recvfrom(s, buf, len, flags, 0, 0);        
}

ssize_t send(int s, const void *buf, size_t len, int flags)
{
        yfr_coroutine_t* r = yfr_coroutine_addr(s);
        if (!yfr_coroutine_check(r))
        {
                yfr_syscall_rinit;
                return yf_send(s, buf, len, flags);
        }

        return  sendto(s, buf, len, flags, 0, 0);
}

/*
* MSG_WAITALL ignored, support MSG_DONTWAIT
*/
ssize_t recvfrom(int s, void *buf, size_t len, int flags,
                struct sockaddr *from, socklen_t *fromlen)
{
        yfr_coroutine_t* r = yfr_coroutine_addr(s);
        if (!yfr_coroutine_check(r))
        {
                yfr_syscall_rinit;
                return yf_recvfrom(s, buf, len, flags, from, fromlen);
        }

#if defined (YFR_DEBUG) || defined (_COR_TRACE)
        yf_log_debug3(YF_LOG_DEBUG, r->log, 0, "syscall.recvfrom(fd:%d blen:%d, flags:%d)", 
                s, len, flags);
#endif
        ssize_t  rr = 0;

        _yfr_syscall_socket_ctx_t* ctx = _yfr_syscall_socket_ctx(r, s);
        yf_u32_t unblocked = ctx->unblocked 
#ifdef MSG_WAITALL
            || (flags & MSG_DONTWAIT)
#endif
        ;
        
        _yfr_syscall_socket_rw(r, s, ctx, YFR_SOCKET_READ_T, unblocked);
        
        rr = yf_unix_recvfrom(&rw_ctx, buf, len, flags, from, fromlen);

        _yfr_syscall_socket_rw_check(r, s, ctx, YFR_SOCKET_READ_T, _YFR_SYSCALL_RWN);
        return rr;
}


ssize_t sendto(int s, const void *buf, size_t len, int flags, 
                const struct sockaddr *to, socklen_t tolen)
{
        yfr_coroutine_t* r = yfr_coroutine_addr(s);
        if (!yfr_coroutine_check(r))
        {
                yfr_syscall_rinit;
                return yf_sendto(s, buf, len, flags, to, tolen);
        }

#if defined (YFR_DEBUG) || defined (_COR_TRACE)
        yf_log_debug3(YF_LOG_DEBUG, r->log, 0, "syscall.sendto(fd:%d, blen:%d, flags:%d)", 
                s, len, flags);
#endif
        ssize_t  rr = 0;

        _yfr_syscall_socket_ctx_t* ctx = _yfr_syscall_socket_ctx(r, s);
        
        _yfr_syscall_socket_rw(r, s, ctx, YFR_SOCKET_WRITE_T, ctx->unblocked);
        
        rr = yf_unix_sendto(&rw_ctx, (char*)buf, len, flags, to, tolen);

        _yfr_syscall_socket_rw_check(r, s, ctx, YFR_SOCKET_WRITE_T, _YFR_SYSCALL_RWN);
        return rr;
}


ssize_t recvn(int s, void *buf, size_t len, int flags)
{
        ssize_t  rr = 0, total = 0;
        yfr_coroutine_t* r = yfr_coroutine_addr(s);
        
        if (!yfr_coroutine_check(r))
        {
                do {
                        rr = yf_recvfrom(s, buf+total, len-total, flags, NULL, NULL);
                        if (rr <= 0)
                                return total;
                        total += rr;
                } 
                while (total < len);
                return total;
        }

#ifdef _COR_TRACE
        yf_log_debug(YF_LOG_DEBUG, r->log, 0,
                "syscall.recvn(fd:%d, len:%z)", s, len);
#endif

#define _yfr_syscall_rrest_check(rr) ||(rr > 0 && rw_ctx.rw_cnt < len)

        _yfr_syscall_socket_ctx_t* ctx = _yfr_syscall_socket_ctx(r, s);
        
        _yfr_syscall_socket_rw(r, s, ctx, YFR_SOCKET_READ_T, ctx->unblocked);
        
        rr = yf_unix_recvfrom(&rw_ctx, buf+rw_ctx.rw_cnt, len-rw_ctx.rw_cnt, 
                        flags, NULL, NULL);

        _yfr_syscall_socket_rw_check(r, s, ctx, YFR_SOCKET_READ_T, _yfr_syscall_rrest_check);
        return  rw_ctx.rw_cnt;
}

ssize_t sendn(int s, const void *buf, size_t len, int flags)
{
        ssize_t  rr = 0, total = 0;
        yfr_coroutine_t* r = yfr_coroutine_addr(s);
        
        if (!yfr_coroutine_check(r))
        {
                do {
                        rr = yf_sendto(s, buf+total, len-total, flags, NULL, 0);
                        if (rr < 0)
                                return total;
                        total += rr;
                } 
                while (total < len);
                return total;
        }

#ifdef _COR_TRACE
        yf_log_debug(YF_LOG_DEBUG, r->log, 0,
                "syscall.sendn(fd:%d, len:%z, flags:%d)", s, len, flags);
#endif

#define _yfr_syscall_wrest_check(rr) ||(rr > 0 && rw_ctx.rw_cnt < len)

        _yfr_syscall_socket_ctx_t* ctx = _yfr_syscall_socket_ctx(r, s);
        
        _yfr_syscall_socket_rw(r, s, ctx, YFR_SOCKET_WRITE_T, ctx->unblocked);
        
        rr = yf_unix_sendto(&rw_ctx, (char*)buf+rw_ctx.rw_cnt, len-rw_ctx.rw_cnt, 
                        flags, NULL, 0);

        _yfr_syscall_socket_rw_check(r, s, ctx, YFR_SOCKET_WRITE_T, _yfr_syscall_wrest_check);
        return  rw_ctx.rw_cnt;
}


ssize_t writevn(int fd, const struct iovec *vector, int count, size_t* req_size)
{
        yf_u32_t i1 = 0;
        yfr_coroutine_t* r = yfr_coroutine_addr(fd);
        ssize_t  rr = 0, total = 0, rr_tmp;
        struct iovec* restv = (struct iovec*)vector, *alloc_addr = NULL;
        int  restc = count;
        *req_size = 0;

        for ( i1 = 0; i1 < count ; i1++ )
        {
                *req_size += vector[i1].iov_len;
        }

#ifdef _COR_TRACE
        yf_log_debug(YF_LOG_DEBUG, r->log, 0,
                "syscall.writevn(fd:%d, size:%z)", fd, *req_size);
#endif

        if (*req_size == 0)
                return 0;

#define _yfr_syscall_alloc_vbuf   yf_alloc(sizeof(struct iovec)*count)
#define _yfr_syscall_alloc_vbuf1 yf_palloc(r->pool, sizeof(struct iovec)*count)

#define _yfr_syscall_fix_writev(pm) \
        if (alloc_addr == NULL) { \
                alloc_addr = pm; \
                yf_memcpy(alloc_addr, vector, sizeof(struct iovec)*count); \
                restv = alloc_addr; \
        } \
        rr_tmp = rr; \
        while (1) { \
                if (restv->iov_len <= rr_tmp) { \
                        rr_tmp -= restv->iov_len; \
                        ++restv; \
                        --restc; \
                } \
                else { \
                        restv->iov_base += rr_tmp; \
                        restv->iov_len -= rr_tmp; \
                        break; \
                } \
        }
        
        if (!yfr_coroutine_check(r))
        {
                while(1) {
                        rr = yf_writev(fd, restv, restc);
                        if (rr < 0)
                                break;
                        total += rr;
                        if (total >= *req_size)
                                break;
                        _yfr_syscall_fix_writev(_yfr_syscall_alloc_vbuf);
                }
                if (alloc_addr)
                        yf_free(alloc_addr);
                return total;
        }

#define _yfr_syscall_wvrest_check(rr) ||(rr > 0 && rw_ctx.rw_cnt < *req_size)

        _yfr_syscall_socket_ctx_t* ctx = _yfr_syscall_socket_ctx(r, fd);
        
        _yfr_syscall_socket_rw(r, fd, ctx, YFR_SOCKET_WRITE_T, ctx->unblocked);

        if (rr > 0) { //cautions, dont erase {} !! not if (rr), fix this bug on 2013-05-16, cause rr may == EAGAIN
                _yfr_syscall_fix_writev(_yfr_syscall_alloc_vbuf1);
        }
        
        yf_log_debug(YF_LOG_DEBUG, r->log, 0, "vsize=%d, restc=%d, restsize=%d", 
                        count, restc, *req_size-rw_ctx.rw_cnt);
        assert(restc >= 0);
        rr = yf_unix_writev(&rw_ctx, restv, restc);

        _yfr_syscall_socket_rw_check(r, fd, ctx, YFR_SOCKET_WRITE_T, _yfr_syscall_wvrest_check);
        return  rw_ctx.rw_cnt;
}



ssize_t recvmsg(int s, struct msghdr *msg, int flags)
{
        yfr_coroutine_t* r = yfr_coroutine_addr(s);
        if (!yfr_coroutine_check(r))
        {
                yfr_syscall_rinit;
                return yf_recvmsg(s, msg, flags);
        }

#ifdef _COR_TRACE
        yf_log_debug(YF_LOG_DEBUG, r->log, 0,
                "syscall.recvmsg(fd:%d, flags:%d)", s, flags);
#endif

        _yfr_syscall_socket_ctx_t* ctx = _yfr_syscall_socket_ctx(r, s);
        _yfr_syscall_socket_verify(r, s, ctx, yf_recvmsg(s, msg, flags));        

        ssize_t  rr = 0;
        
        _yfr_syscall_socket_rw(r, s, ctx, YFR_SOCKET_READ_T, ctx->unblocked);
        
        rr = yf_unix_recvmsg(&rw_ctx, msg, flags);

        _yfr_syscall_socket_rw_check(r, s, ctx, YFR_SOCKET_READ_T, _YFR_SYSCALL_RWN);
        return rr;
}

ssize_t sendmsg(int s, const struct msghdr *msg, int flags)
{
        yfr_coroutine_t* r = yfr_coroutine_addr(s);
        if (!yfr_coroutine_check(r))
        {
                yfr_syscall_rinit;
                return yf_sendmsg(s, msg, flags);
        }

#ifdef _COR_TRACE
        yf_log_debug(YF_LOG_DEBUG, r->log, 0,
                "syscall.sendmsg(fd:%d, flags:%d)", s, flags);
#endif

        ssize_t  rr = 0;

        _yfr_syscall_socket_ctx_t* ctx = _yfr_syscall_socket_ctx(r, s);
        
        _yfr_syscall_socket_rw(r, s, ctx, YFR_SOCKET_WRITE_T, ctx->unblocked);
        
        rr = yf_unix_sendmsg(&rw_ctx, msg, flags);

        _yfr_syscall_socket_rw_check(r, s, ctx, YFR_SOCKET_WRITE_T, _YFR_SYSCALL_RWN);
        return rr;
}


ssize_t readv(int fd, const struct iovec *vector, int count)
{
        yfr_coroutine_t* r = yfr_coroutine_addr(fd);
        if (!yfr_coroutine_check(r))
        {
                yfr_syscall_rinit;
                return yf_readv(fd, vector, count);
        }

#ifdef _COR_TRACE
        yf_log_debug(YF_LOG_DEBUG, r->log, 0,
                "syscall.readv(fd:%d)", fd);
#endif

        _yfr_syscall_socket_ctx_t* ctx = _yfr_syscall_socket_ctx(r, fd);
        _yfr_syscall_socket_verify(r, fd, ctx, yf_readv(fd, vector, count));        

        ssize_t  rr = 0;
        
        _yfr_syscall_socket_rw(r, fd, ctx, YFR_SOCKET_READ_T, ctx->unblocked);
        
        rr = yf_unix_readv(&rw_ctx, vector, count);

        _yfr_syscall_socket_rw_check(r, fd, ctx, YFR_SOCKET_READ_T, _YFR_SYSCALL_RWN);
        return rr;
}

ssize_t writev(int fd, const struct iovec *vector, int count)
{
        yfr_coroutine_t* r = yfr_coroutine_addr(fd);
        if (!yfr_coroutine_check(r))
        {
                yfr_syscall_rinit;
                return yf_writev(fd, vector, count);
        }

#ifdef _COR_TRACE
        yf_log_debug(YF_LOG_DEBUG, r->log, 0,
                "syscall.writev(fd:%d)", fd);
#endif

        _yfr_syscall_socket_ctx_t* ctx = _yfr_syscall_socket_ctx(r, fd);
        _yfr_syscall_socket_verify(r, fd, ctx, yf_writev(fd, vector, count));

        ssize_t  rr = 0;
        
        _yfr_syscall_socket_rw(r, fd, ctx, YFR_SOCKET_WRITE_T, ctx->unblocked);
        
        rr = yf_unix_writev(&rw_ctx, vector, count);

        _yfr_syscall_socket_rw_check(r, fd, ctx, YFR_SOCKET_WRITE_T, _YFR_SYSCALL_RWN);
        return rr;
}


static int _yfr_syscall_socket_new(yfr_coroutine_t* r, int fd, int type)
{
        yf_evt_driver_t* evt_driver = yfr_coroutine_mgr_ctx(r)->evt_driver;
        
        yf_fd_event_t *revt, *wevt;
        yf_int_t  ret = yf_alloc_fd_evt(evt_driver, fd, &revt, &wevt, r->log);
        if (ret != YF_OK)
        {
                yf_log_error(YF_LOG_ERR, r->log, YF_ENFILE, 
                                "alloc fd=%d evt failed, maybe you should enlarge evt dirver's fd num", 
                                fd);
                yf_close(fd);
                // errno muset be after yf_close, cause yf_close may fail, then errno will be invalid
                yf_socket_errno = YF_ENFILE;
                return -1;
        }

        revt->fd_evt_handler = NULL;
        wevt->fd_evt_handler = NULL;

        _yfr_syscall_socket_ctx_t* ctx = _yfr_syscall_socket_ctx(r, fd);

        //wait pre sock's coroutine exit
        while (yfr_ipc_locked(ctx->lock))
        {
                yf_log_debug1(YF_LOG_DEBUG, r->log, 0, "wait for fd=%d read lock empty !", fd);
                usleep(1000);
        }
        while (yfr_ipc_locked(ctx->lock + 1))
        {
                yf_log_debug1(YF_LOG_DEBUG, r->log, 0, "wait for fd=%d write lock empty !", fd);
                usleep(1000);
        }

        yf_nonblocking(fd);

        ctx->type = type;
        ctx->opened = 1;
        ctx->unblocked = 0;
        ctx->notsock = 0;
        ctx->evt[0] = revt;
        ctx->evt[1] = wevt;
        ctx->timeout[0] = 0;
        ctx->timeout[1] = 0;
        ctx->conn_timeout = 0;

        yf_log_debug2(YF_LOG_DEBUG, r->log, 0, "revt addr=%p, wevt addr=%p", 
                        revt, wevt);

        return  fd;
}


int socket(int domain, int type, int protocol)
{
        yfr_syscall_rinit;
        yf_fd_t fd = yf_socket(domain, type, protocol);
        
        yfr_coroutine_t* r = yfr_coroutine_addr(domain);
        if (!yfr_coroutine_check(r))
                return fd;

        yf_log_debug4(YF_LOG_DEBUG, r->log, 0, 
                        "syscall.socket(domain:%d, type:%d, protocol:%d) -> (fd:%d)",
                        domain, type, protocol, fd);
        
        return _yfr_syscall_socket_new(r, fd, type);
}


int yfr_coroutine_open(int sockfd, int type)
{
       yfr_syscall_rinit;
        yfr_coroutine_t* r = yfr_coroutine_addr(sockfd);
        if (!yfr_coroutine_check(r))
                return -1;

        _yfr_syscall_socket_ctx_t* ctx = _yfr_syscall_socket_ctx(r, sockfd);
        if (ctx->opened)
                return 0;

        yf_log_debug4(YF_LOG_DEBUG, r->log, 0, 
                        "open fd=%d : {type=%d}", 
                        sockfd, type);
        int sockfd_ret = _yfr_syscall_socket_new(r, sockfd, type);
        if (sockfd_ret < 0) 
        {
                yf_log_error(YF_LOG_ERR, r->log, 0, 
                                "socket new failed, fd=%d", sockfd);
                return 0;            
        }
        return 0;
}


yf_int_t  yfr_socket_conn_tmset(int fd, yf_u32_t ms)
{
        yfr_coroutine_t* r = yfr_coroutine_addr(fd);
        if (!yfr_coroutine_check(r))
                return -1;

        _yfr_syscall_socket_ctx_t* ctx = _yfr_syscall_socket_ctx(r, fd);
        _yfr_syscall_socket_valid(r, fd, ctx);

        ctx->conn_timeout = ms;
        return  0;
}


int connect(int fd, const struct sockaddr *serv_addr, socklen_t addrlen)
{
        yfr_syscall_rinit;
        int ret = yf_connect(fd, serv_addr, addrlen);
        int errno_conn = yf_errno;

        yfr_coroutine_t* r = yfr_coroutine_addr(fd);
        if (!yfr_coroutine_check(r))
                return ret;

#ifdef _COR_TRACE
        yf_log_debug(YF_LOG_DEBUG, r->log, 0,
                "syscall.connect(fd:%d)", fd);
#endif

        _yfr_syscall_socket_ctx_t* ctx = _yfr_syscall_socket_ctx(r, fd);
        _yfr_syscall_socket_valid(r, fd, ctx);

        if (ret == 0)
        {
                yf_log_debug(YF_LOG_DEBUG, r->log, 0, 
                                "connect complete immediately, fd=%d", fd);
                return 0;
        }
        if (errno_conn != YF_EINPROGRESS)
        {
                ret = errno_conn;
                yf_log_debug(YF_LOG_DEBUG, r->log, ret, 
                                "connect fail immediately, fd=%d", fd);
                yf_errno = ret;
                return -1;
        }

        yf_time_t  time;
        yf_time_t* tptr = NULL;
        if (ctx->conn_timeout)
        {
                tptr = &time;
                yf_ms_2_time(ctx->conn_timeout, &time);
        }
        
        //watch revt+wevt, just need one timer
        //ctx->evt[0]->data = r;
        ctx->evt[1]->data = r;
        //yf_register_fd_evt(ctx->evt[0], tptr);
        ctx->evt[1]->fd_evt_handler = _yfr_syscall_on_rwable;
        yf_register_fd_evt(ctx->evt[1], tptr);

        yfr_coroutine_block(r, &ctx->evt[1]->data3[0]);
        
        //yf_unregister_fd_evt(ctx->evt[0]);
        //yf_unregister_fd_evt(ctx->evt[1]);

        if (ctx->evt[1]->timeout)
        {
                yf_log_debug(YF_LOG_DEBUG, r->log, YF_ETIMEDOUT, 
                                "connect timeout fd=%d, timeout ms=%d", 
                                fd, ctx->conn_timeout);
                
                yf_errno = YF_ETIMEDOUT;
                return -1;                
        }

        socklen_t len = sizeof(ret);
        if (yf_getsockopt(fd, SOL_SOCKET, SO_ERROR, &ret, &len) < 0)
                return -1;

        if (ret)
        {
                yf_errno = ret;
                return -1;
        }

        //reconnect again to test
        /*ret = yf_connect(fd, serv_addr, addrlen);
        if (ret == 0 || EISCONN != yf_errno)
        {
                yf_log_debug(YF_LOG_DEBUG, r->log, yf_errno, 
                                "reconnect test ret=%d", ret);
                return -1;
        }*/
        return 0;
}


int accept(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
        yfr_coroutine_t* r = yfr_coroutine_addr(fd);
        if (!yfr_coroutine_check(r))
        {
                yfr_syscall_rinit;
                return yf_accept(fd, addr, addrlen);
        }

#ifdef _COR_TRACE
        yf_log_debug(YF_LOG_DEBUG, r->log, 0,
                "syscall.accept(fd:%d)", fd);
#endif

        _yfr_syscall_socket_ctx_t* ctx = _yfr_syscall_socket_ctx(r, fd);
        _yfr_syscall_socket_valid(r, fd, ctx);

        while (_yfr_socket_lock_helper(r, ctx, fd, 0, 0) != YF_OK)
                usleep(1000);

        int  nfd;
        ctx->evt[0]->data = r;
        ctx->evt[0]->fd_evt_handler = _yfr_syscall_on_rwable;

try_again:
        yf_register_fd_evt(ctx->evt[0], NULL);
        yfr_coroutine_block(r, &ctx->evt[0]->data3[0]);

        nfd = yf_accept(fd, addr, addrlen);
        if (unlikely(nfd < 0))
        {
                if (YF_EAGAIN(yf_errno) 
                        || yf_errno == YF_ECONNABORTED 
                        || yf_errno == YF_EINTR)
                {
                        yf_log_debug(YF_LOG_DEBUG, r->log, 0, 
                                        "fd accept no incoming conn, errno=%d",
                                        yf_errno);
                        ctx->evt[0]->ready = 0;//must tell evt driver...
                        goto try_again;
                }
                
                yf_log_error(YF_LOG_WARN, r->log, yf_errno, "accept fd=%d err", fd);
        }
        else {
                nfd = _yfr_syscall_socket_new(r, nfd, SOCK_STREAM);
        }

        yfr_ipc_unlock(ctx->lock);
        return  nfd;
}


int fcntl(int fd, int cmd, ...)
{
        int ret = 0;
        long flags;
        va_list  args;
        struct flock* pflock;

        yfr_coroutine_t* r = yfr_coroutine_addr(fd);
        if (!yfr_coroutine_check(r) || cmd != F_SETFL)
        {
                yfr_syscall_rinit;
normal:
                va_start(args, cmd);
                //if in ubutn os, this will fail
                //ret = yf_fcntl(fd, cmd, args);
                switch (cmd)
                {
                        case F_DUPFD:
#ifdef F_DUPFD_CLOEXEC
                        case F_DUPFD_CLOEXEC:
#endif
                        case F_SETFD:
                        case F_SETFL:
                                flags = va_arg(args, long);
                                ret = yf_fcntl(fd, cmd, flags);
                                break;
                        case F_GETFD:
                        case F_GETFL:
                                ret = yf_fcntl(fd, cmd);
                                break;
                        case F_SETLK:
                        case F_SETLKW:
                        case F_GETLK:
                                pflock = va_arg(args, struct flock*);
                                ret = yf_fcntl(fd, cmd, pflock);
                                break;
                }
                va_end(args);
                return ret;
        }

#ifdef _COR_TRACE
        yf_log_debug(YF_LOG_DEBUG, r->log, 0,
                "syscall.fcntl(fd:%d, cmd:%d)", fd, cmd);
#endif

        _yfr_syscall_socket_ctx_t* ctx = _yfr_syscall_socket_ctx(r, fd);
        if (!ctx->opened)
                goto normal;

        va_start(args, cmd);
        flags = va_arg(args, long);
        va_end(args);

        if (!(flags & O_NONBLOCK))
        {
                yf_log_debug(YF_LOG_DEBUG, r->log, 0, 
                                "fcntl fd=%d blocked", fd);
                //in yf, all fd should be unblocked
                flags |= O_NONBLOCK;
                ctx->unblocked = 0;
        }
        else {
                yf_log_debug(YF_LOG_DEBUG, r->log, 0, 
                                "fcntl fd=%d unblocked", fd);
                ctx->unblocked = 1;

                yf_activate_fd_evt(ctx->evt[0]);
                yf_activate_fd_evt(ctx->evt[1]);
        }
        return  yf_fcntl(fd, cmd, flags);
}


int setsockopt(int s, int level, int optname, 
                const void *optval, socklen_t optlen)
{
        yfr_syscall_rinit;
        int ret = yf_setsockopt(s, level, optname, optval, optlen);
        if (ret != 0)
                return ret;
        yfr_coroutine_t* r = yfr_coroutine_addr(s);
        if (!yfr_coroutine_check(r))
                return 0;

#ifdef _COR_TRACE
        yf_log_debug(YF_LOG_DEBUG, r->log, 0,
                "syscall.setsockopt(fd:%d, level:%d, optname:%d)", s, level, optname);
#endif

        _yfr_syscall_socket_ctx_t* ctx = _yfr_syscall_socket_ctx(r, s);
        _yfr_syscall_socket_valid(r, s, ctx);
        
        if (level == SOL_SOCKET)
        {
                if (optname == SO_RCVTIMEO) {
                        ctx->timeout[0] = yf_utime_2_ms((const yf_utime_t*)optval);
                }
                else if (optname == SO_SNDTIMEO) {
                        ctx->timeout[1] = yf_utime_2_ms((const yf_utime_t*)optval);
                }
        }
        return  0;
}

static int __yfr_ioctl_refer(int s)
{
        return ioctl(s, 0, NULL);
}


// ret=0, replaced syscall, otherwise will call org syscal
int yfr_ioctl_hook(int fd, unsigned long int request, ...)
{
        yfr_syscall_rinit;
        if (request != FIONBIO) {
                return -1;
        }

        yfr_coroutine_t* r = yfr_coroutine_addr(fd);
        if (!yfr_coroutine_check(r))
                return -1;

#ifdef _COR_TRACE
        yf_log_debug(YF_LOG_DEBUG, r->log, 0,
                "syscall.ioctl(fd:%d)", fd);
#endif

        _yfr_syscall_socket_ctx_t* ctx = _yfr_syscall_socket_ctx(r, fd);
        _yfr_syscall_socket_valid(r, fd, ctx);

        va_list  args;
        va_start(args, request);
        int* nb = va_arg(args, int*);
        va_end(args);

        ctx->unblocked = (*nb ? 1 : 0);

        yf_log_debug(YF_LOG_DEBUG, r->log, 0, 
                        "ioctl fd=%d unblocked to %d", fd, ctx->unblocked);
        return 0;
}


/*
* poll + select
*/
typedef struct _yfr_poll_ctx_s
{
        yf_u32_t  block_id;
        yf_fd_t    revt_fds[4];
        char        revts[4];
}
_yfr_poll_ctx_t;


yf_int_t  yfr_syscall_poll_coroutine_attach(yfr_coroutine_mgr_t* mgr, yf_log_t* log)
{
        yfr_coroutine_init_t* ctx = yfr_coroutine_mgr_ctx2(mgr);

        yf_hnpool_t* hp = yf_hnpool_create(sizeof(_yfr_poll_ctx_t),
                                                          yf_max(ctx->run_max_num>>5, 8), 32, log);
        CHECK_RV(hp == NULL, YF_ERROR);
        ctx->data[YFR_SYSCALL_POLL] = hp;
        
        return  YF_OK;
}


static  void __yfr_syscall_poll_evt_handler(struct yf_fd_event_s* evt)
{
        yf_u32_t i1 = 0;
        yfr_coroutine_t* r = evt->data;
        yf_u64_t  ctx_id = evt->data2;

        yf_hnpool_t* hpool = yfr_coroutine_mgr_ctx(r)->data[YFR_SYSCALL_POLL];
        _yfr_poll_ctx_t* poll_ctx = yf_hnpool_id2node(hpool, ctx_id, r->log);
        if (poll_ctx == NULL)
        {
                yf_log_error(YF_LOG_WARN, r->log, 0, 
                                "cant find poll ctx, fd=%d, ctx_id=%L", 
                                evt->fd, ctx_id);
                return;
        }
        yf_log_debug(YF_LOG_DEBUG, r->log, 0, 
                        "poll evt arrive, r=%L fd=%d, ctx_id=%L, evt->ready=%d, timeout=%d", 
                        r->id, evt->fd, ctx_id, evt->ready, evt->timeout);
        
        if (evt->ready)
        {
                for ( i1 = 0; i1 < YF_ARRAY_SIZE(poll_ctx->revts); i1++ )
                {
                        if (poll_ctx->revts[i1] < 0)
                                break;
                }
                if (i1 == YF_ARRAY_SIZE(poll_ctx->revts))
                {
                        yf_log_error(YF_LOG_WARN, r->log, 0, "too many effective evts");
                }
                else {
                        poll_ctx->revts[i1] = evt->type == YF_REVT ? 0 : 1;
                        poll_ctx->revt_fds[i1] = evt->fd;
                }
        }
        else if (evt->timeout)
        {
                yf_log_debug(YF_LOG_INFO, r->log, 0, 
                                "poll but timeout, no evts, fd=%d, ctx_id=%L", 
                                evt->fd, ctx_id);
        }
        else
                assert(0);

        yf_int_t ret = yfr_coroutine_resume(r, poll_ctx->block_id);
        assert(ret == YF_OK);
}


static  yf_int_t __yfr_syscall_poll_set(yfr_coroutine_t* r
                , yf_fd_t fd, _yfr_syscall_socket_ctx_t* ctx
                , yf_int_t rwtype, yf_u64_t  ctx_id, yf_time_t* tm)
{
        yf_int_t already_locked = 0;
        yf_fd_event_t* evt = ctx->evt[rwtype];
        
        _yfr_syscall_socket_status_chck(fd, ctx, evt, r, rwtype);

        if (yfr_ipc_locked(ctx->lock + rwtype))
        {
                yf_log_error(YF_LOG_WARN, r->log, 0, 
                                "fd=%d's rw evt=[%s] locked, poll set failed", 
                                fd, _yfr_syscall_socket_desc[rwtype]);
                return YF_ERROR;
        }

        yf_int_t ret = yfr_ipc_lock(ctx->lock + rwtype, 0, NULL);
        assert(ret == YF_OK);
        evt->data = r;
        evt->data2 = ctx_id;
        evt->fd_evt_handler = __yfr_syscall_poll_evt_handler;

        yf_register_fd_evt(evt, tm);
        
        return YF_OK;
}


#define _yfr_poll_ctx_alloc \
        yf_hnpool_t* hpool = yfr_coroutine_mgr_ctx(r)->data[YFR_SYSCALL_POLL]; \
        yf_u64_t  id = 0; \
        _yfr_poll_ctx_t* poll_ctx = yf_hnpool_alloc(hpool, &id, r->log); \
        if (poll_ctx == NULL) \
        { \
                yf_log_error(YF_LOG_WARN, r->log, 0, "poll ctx usedout..."); \
                return -1; \
        } \
        yf_memset(poll_ctx, -1, sizeof(_yfr_poll_ctx_t)); \
        yf_log_debug(YF_LOG_DEBUG, r->log, 0, \
                        "poll evt alloc ctx_id=%L,", id); \
        yf_fd_t  efds[32] = {0}; \
        char etypes[32] = {0}; \
        yf_int_t  efd_cnt = 0;

#define _yfr_poll_add_eevt(fd, rwtype, ctx, tm) \
        if (__yfr_syscall_poll_set(r, fd, ctx, rwtype, id, &tm) == YF_OK) \
        { \
                efds[efd_cnt] = fd; \
                etypes[efd_cnt] = rwtype; \
                if (++efd_cnt >= YF_ARRAY_SIZE(efds)) \
                        break; \
        }

#define _yfr_poll_process \
        if (efd_cnt == 0) \
        { \
                yf_log_error(YF_LOG_WARN, r->log, 0, "no effective evts, ret 0"); \
                yf_hnpool_free(hpool, id, poll_ctx, r->log); \
                return 0; \
        } \
        yfr_coroutine_block(r, &poll_ctx->block_id); \
        for ( i1 = 0; i1 < YF_ARRAY_SIZE(poll_ctx->revts); i1++ ) \
        { \
                if (poll_ctx->revts[i1] < 0) \
                        break; \
                _yfr_poll_set_res(poll_ctx->revt_fds[i1], poll_ctx->revts[i1]); \
        } \
        yf_hnpool_free(hpool, id, poll_ctx, r->log); \
        \
        for (i1 = 0; i1 < efd_cnt; ++i1) \
        { \
                ctx = _yfr_syscall_socket_ctx(r, efds[i1]); \
                assert(yfr_ipc_locked_by(ctx->lock+etypes[i1], r)); \
                \
                yfr_ipc_unlock(ctx->lock+etypes[i1]); \
                yf_unregister_fd_evt(ctx->evt[etypes[i1]]); \
        } \
        yf_log_debug(YF_LOG_DEBUG, r->log, 0, \
                        "ctx_id=%L, last poll evt fd num=%d, input fd num=%d", \
                        id, rcnt, nfds); \
        if (rcnt == 0) \
                yf_socket_errno = 0; \
        return rcnt;
        

#ifdef  HAVE_POLL_H
/*
* If timeout is greater than zero, it specifies a maximum interval (in milliseconds) to 
* wait for any file descriptor to become ready.  If timeout is zero, then poll() will return
* without blocking. If the value of timeout is -1, the poll blocks indefinitely.
*/
#ifndef POLLRDNORM
#define POLLRDNORM 0x040
#endif
#ifndef POLLRDBAND
#define POLLRDBAND 0x080
#endif
#ifndef POLLWRNORM
#define POLLWRNORM 0x100
#endif
#ifndef POLLWRBAND
#define POLLWRBAND 0x200
#endif


int poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
        yf_u32_t i1 = 0, i2 = 0, rcnt = 0;
        yfr_coroutine_t* r = yfr_coroutine_addr(fds);
        if (likely(!yfr_coroutine_check(r)))
        {
                yfr_syscall_rinit;
                return  yf_poll(fds, nfds, timeout);
        }

#if defined (YFR_DEBUG) || defined (_COR_TRACE)
        yf_log_debug2(YF_LOG_DEBUG, r->log, 0, "syscall.poll(nfds:%d, timeout:%d)", 
                nfds, timeout);
#endif
        if (nfds == 0)
                return 0;
        if (timeout < 0)
                timeout = 1000*120;//two minutes

        yf_time_t  tm;
        yf_fd_t  fd;
        _yfr_syscall_socket_ctx_t* ctx;
        yf_s16_t  poll_evt_set;

        yf_ms_2_time(timeout, &tm);

        _yfr_poll_ctx_alloc;
        
        for (i1 = 0; i1 < nfds; ++i1)
        {
                fds[i1].revents = 0;
                
                fd = fds[i1].fd;
                ctx = _yfr_syscall_socket_ctx(r, fd);

                poll_evt_set = fds[i1].events;

                if ((poll_evt_set & POLLIN) || (poll_evt_set & POLLRDNORM)
                            || (poll_evt_set & POLLRDBAND) || (poll_evt_set & POLLPRI))
                {
                        _yfr_poll_add_eevt(fd, 0, ctx, tm);
                }
                if ((poll_evt_set & POLLOUT) || (poll_evt_set & POLLWRNORM)
                            || (poll_evt_set & POLLWRBAND))
                {
                        _yfr_poll_add_eevt(fd, 1, ctx, tm);
                }
        }

#define __yfr_mrevent(_e) if (poll_evt_set & _e) fds[i2].revents |= _e;

#define _yfr_poll_set_res(_rfd, _revts) \
        for ( i2 = 0; i2 < nfds ; i2++ ) \
        { \
                if (fds[i2].fd != _rfd) \
                        continue; \
                if (fds[i2].revents == 0) \
                        ++rcnt; \
                poll_evt_set = fds[i2].events; \
                if (_revts == YFR_SOCKET_READ_T) { \
                        __yfr_mrevent(POLLIN); \
                        __yfr_mrevent(POLLRDNORM); \
                        __yfr_mrevent(POLLRDBAND); \
                } \
                else { \
                        __yfr_mrevent(POLLOUT); \
                        __yfr_mrevent(POLLWRNORM); \
                        __yfr_mrevent(POLLWRBAND); \
                } \
        }
        
        _yfr_poll_process;

#undef _yfr_poll_set_res        
}
#endif


#ifdef  HAVE_SYS_SELECT_H
int select(int nfds, fd_set *readfds, fd_set *writefds,
                fd_set *exceptfds, struct timeval *timeout)
{
        yf_u32_t i1 = 0, i2 = 0, rcnt = 0;
        yfr_coroutine_t* r = yfr_coroutine_addr(nfds);
        if (likely(!yfr_coroutine_check(r)))
        {
                yfr_syscall_rinit;
                return yf_select(nfds, readfds, writefds, exceptfds, timeout);
        }

#if defined (YFR_DEBUG) || defined (_COR_TRACE)
        yf_log_debug1(YF_LOG_DEBUG, r->log, 0, "syscall.select(nfds:%d)", 
                nfds);
#endif

        yf_time_t  tm;
        _yfr_syscall_socket_ctx_t* ctx;

        int  tm_ms = timeout ? yf_utime_2_ms(timeout) : 1000*120;
        yf_ms_2_time(tm_ms, &tm);

        _yfr_poll_ctx_alloc;

        int fdno_limit = yf_min(nfds, FD_SETSIZE);

#define _yfr_poll_fdset_iter(_fds, _rwtype) \
        if (_fds) \
        { \
                for (i1 = 0; i1 < fdno_limit; ++i1) \
                { \
                        if (FD_ISSET(i1, _fds)) \
                        { \
                                ctx = _yfr_syscall_socket_ctx(r, i1); \
                                _yfr_poll_add_eevt(i1, _rwtype, ctx, tm); \
                        } \
                } \
                FD_ZERO(_fds); \
        }
        
        _yfr_poll_fdset_iter(readfds, 0);
        _yfr_poll_fdset_iter(writefds, 1);

#define _yfr_poll_set_res(_rfd, _revts) do { \
                FD_SET(_rfd, _revts == YFR_SOCKET_READ_T ? readfds : writefds); \
                ++rcnt; \
        } while (0)
        
        _yfr_poll_process;

#undef _yfr_poll_set_res
}
#endif

