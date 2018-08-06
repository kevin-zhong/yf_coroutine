#include "yfr_ipc.h"
#include "yfr_syscall.h"


typedef struct _yfr_ipc_wait_coroutine_s
{
        yf_u64_t     coroutine_id;
        yf_u32_t     block_id;
        yf_list_part_t  linker;
}
_yfr_ipc_wait_coroutine_t;


yf_hnpool_t* yfr_ipc_ctx_pool_create(yf_u32_t guess_num, 
        yf_u32_t max_num, yf_log_t* log)
{
        guess_num = yf_align_2pow(guess_num);
        max_num = yf_align_2pow(max_num);
        
        return yf_hnpool_create(sizeof(_yfr_ipc_wait_coroutine_t), 
                        guess_num, max_num /guess_num, log);
}


yf_int_t  yfr_syscall_ipc_coroutine_attach(yfr_coroutine_mgr_t* mgr, yf_log_t* log)
{
        yfr_coroutine_init_t* ctx = yfr_coroutine_mgr_ctx2(mgr);

        yf_u32_t run_max = ctx->run_max_num;

        ctx->data[YFR_SYSCALL_IPC] = yfr_ipc_ctx_pool_create(
                                run_max, run_max * 16, log);
        
        return ctx->data[YFR_SYSCALL_IPC] ? YF_OK : YF_ERROR;
}


//just wakeup one...
static void _yfr_ipc_wakeup_waiting_coroutines(yfr_coroutine_t* r
                , yf_list_part_t* l, yf_int_t wakeup_all, yf_u32_t* ready_cnt);


#define _yfr_ipc_ilock(r, l, tm) \
        YFR_WAIT_REC_BEGIN; \
        yf_hnpool_t* _p = yfr_coroutine_mgr_ctx(r)->data[YFR_SYSCALL_IPC]; \
        yf_u64_t _wid; \
        _yfr_ipc_wait_coroutine_t* _wait_ctx = yf_hnpool_alloc(_p, &_wid, r->log); \
        if (unlikely(_wait_ctx == NULL)) \
        { \
                yf_log_error(YF_LOG_WARN, r->log, 0, "alloc wait ctx failed"); \
                yf_errno = YF_ENOMEM; \
                return  YF_ERROR; \
        } \
        \
        _wait_ctx->coroutine_id = r->id; \
        yf_list_add_tail(&_wait_ctx->linker, &l->head); \
        yfr_coroutine_block(r, &_wait_ctx->block_id); \
        \
        l->ready_cnt--; \
        yf_hnpool_free(_p, _wid, _wait_ctx, r->log); \
        \
        if (yfr_wait_timeout(tm)) \
        { \
                yf_log_error(YF_LOG_WARN, r->log, 0, "wait lock timeout, coroutine id=%L",  \
                                r->id); \
                \
                if (!yf_list_empty(&l->head)) \
                        _yfr_ipc_wakeup_waiting_coroutines(r, &l->head, 0, &l->ready_cnt); \
                yf_errno = YF_ETIMEDOUT; \
                return  YF_ERROR; \
        }


yf_int_t  yfr_ipc_lock(yfr_ipc_lock_t* l, yf_u32_t tm, yf_int_t* waited)
{
        yfr_coroutine_t* r = yfr_coroutine_addr(l);
        if (unlikely(!yfr_coroutine_check(r)))
                return YF_ERROR;

        //changed on 2013/04/11 20:50, see wiki...
        if (likely((l->lock_rid == 0 && l->ready_cnt == 0) 
                || l->lock_rid == r->id))
        {
                assert(l->lock_times < 255);
                l->lock_rid = r->id;
                l->lock_times++;
                if (waited)
                        *waited = 0;
                return YF_OK;
        }
        
        _yfr_ipc_ilock(r, l, tm);
        if (waited)
                *waited = 1;

        assert(l->lock_rid == 0 && l->lock_times == 0 && l->ready_cnt == 0);
        l->lock_rid = r->id;
        l->lock_times++;

        return YF_OK;
}


void yfr_ipc_unlock(yfr_ipc_lock_t* l)
{
        yfr_coroutine_t* r = yfr_coroutine_addr(l);
        assert(yfr_coroutine_check(r));

        assert(l->ready_cnt == 0);
        assert(l->lock_rid == r->id && l->lock_times);
        
        if (--l->lock_times == 0)
        {
                l->lock_rid = 0;
                if (!yf_list_empty(&l->head))
                        _yfr_ipc_wakeup_waiting_coroutines(r, &l->head, 0, &l->ready_cnt);
        }
}



yf_int_t  yfr_ipc_mlock(yfr_ipc_mlock_t* l, yf_u32_t tm, yf_int_t* waited)
{
        yfr_coroutine_t* r = yfr_coroutine_addr(l);
        if (unlikely(!yfr_coroutine_check(r)))
                return YF_ERROR;
        
        if (likely(l->now_share + l->ready_cnt < l->max_share))
        {
                l->now_share++;
                if (waited)
                        *waited = 0;
                return YF_OK;
        }

        _yfr_ipc_ilock(r, l, tm);
        if (waited)
                *waited = 1;

        assert(l->now_share + l->ready_cnt < l->max_share);

        l->now_share++;
        return YF_OK;
}


void yfr_ipc_munlock(yfr_ipc_mlock_t* l)
{
        yfr_coroutine_t* r = yfr_coroutine_addr(l);
        assert(yfr_coroutine_check(r));
        assert(l->now_share);
        l->now_share--;
        
        if (!yf_list_empty(&l->head))
                _yfr_ipc_wakeup_waiting_coroutines(r, &l->head, 0, &l->ready_cnt);
}


void  yfr_ipc_cond_wait(yfr_ipc_cond_t* c)
{
        yfr_coroutine_t* r = yfr_coroutine_addr(c);
        assert(yfr_coroutine_check(r));

        yf_hnpool_t* p = yfr_coroutine_mgr_ctx(r)->data[YFR_SYSCALL_IPC];
        
        yf_u64_t id;
        _yfr_ipc_wait_coroutine_t* wait_ctx = yf_hnpool_alloc(p, &id, r->log);
        assert (wait_ctx);

        wait_ctx->coroutine_id = r->id;

        yf_list_add_tail(&wait_ctx->linker, &c->head);
        yfr_coroutine_block(r, &wait_ctx->block_id);

        //after resume
        yf_hnpool_free(p, id, wait_ctx, r->log);
}


void  yfr_ipc_cond_sig(yfr_ipc_cond_t* c)
{
        yfr_coroutine_t* r = yfr_coroutine_addr(c);
        assert(yfr_coroutine_check(r));

        _yfr_ipc_wakeup_waiting_coroutines(r, &c->head, 1, NULL);
}


void  yfr_ipc_cond_sig_one(yfr_ipc_cond_t* c)
{
        yfr_coroutine_t* r = yfr_coroutine_addr(c);
        assert(yfr_coroutine_check(r));

        _yfr_ipc_wakeup_waiting_coroutines(r, &c->head, 0, NULL);
}


static void _yfr_ipc_wakeup_waiting_coroutines(yfr_coroutine_t* r
                , yf_list_part_t* l, yf_int_t wakeup_all, yf_u32_t* ready_cnt)
{
        yf_int_t  ret = 0;
        do {
                yf_list_part_t* part = yf_list_pop_head(l);
                if (part == NULL)
                        return;
                
                _yfr_ipc_wait_coroutine_t* wait_ctx = container_of(part, 
                                _yfr_ipc_wait_coroutine_t, linker);
                
                yfr_coroutine_t* to_wakeup = yfr_coroutine_getby_id(
                                yfr_coroutine_get_mgr(r), wait_ctx->coroutine_id);
                assert (to_wakeup);
                
                ret = yfr_coroutine_resume(to_wakeup, wait_ctx->block_id);
                assert(ret == 0);

                if (ready_cnt)
                        *ready_cnt += 1;
        } 
        while (wakeup_all);
}

