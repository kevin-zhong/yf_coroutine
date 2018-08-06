#include "yfr_coroutine.h"

/*
* global static config+set
*/

static yf_s32_t  yfr_coroutine_stack_size = 0;
static yf_s32_t  yfr_coroutine_take_bit = 0;
yf_s32_t  yfr_coroutine_take_size = 0;
char* yfr_coroutine_mem_begin = NULL;
char* yfr_coroutine_mem_end = NULL;
yf_s8_t yfr_coroutine_specific_num = 0;


/*
* mem pad:
*
* mprotect      statck_addr*                                                        coroutine_mgr*
* |--barrier--|-------------------stack-----------------|-----meta-----|
*       4096          _YFR_COROUTINE_VSS(stack_size-meta_size)      meta_size
* |-------------------------take_size----------------------------------|
*                     |---------------------------stack_size---------------------|
*                                                                                                |-head-|-specific-|
*/

#define _YFR_COROUTINE_VSS (yfr_coroutine_stack_size - yfr_coroutine_meta_size)


#define _yfr_coroutine_m2r(m)  yf_mem_off(m, \
                yfr_coroutine_take_size - yfr_coroutine_meta_size)
                
#define _yfr_coroutine_r2s(r)  yf_mem_off((r), -_YFR_COROUTINE_VSS)
#define _yfr_coroutine_s2m(s)  yf_mem_off(s, -(yf_s32_t)yf_pagesize)

#define _yfr_coroutine_vswatch(r, rest_percent) ((yf_u32_t*)_yfr_coroutine_r2s(r) \
                + (_YFR_COROUTINE_VSS>>2) * rest_percent / YFR_COROUTINE_STACK_WATCH_SPLIT)

#define _YFR_COROUTINE_VSWATCH_MAGIC 0x68A1DE5B

#ifdef YFR_DEBUG
static const yf_int_t _yfr_coroutine_watches[] = {6, 5, 4, 3, 2, 1};
#else
static const yf_int_t _yfr_coroutine_watches[] = {5, 4, 3, 2, 1};
#endif

static struct {
        yf_lock_t  lock;
        yf_u32_t  total_num;
        yf_u32_t  alloced_num;
} 
yfr_coroutine_stack_mgr;


yf_int_t yfr_coroutine_global_set(yf_u32_t coroutine_total_max
                , yf_u32_t stack_size, yf_u32_t specific_num, yf_log_t* log)
{
        stack_size = yf_max(stack_size, yf_pagesize * 2);

        yfr_coroutine_specific_num = yf_min(32, specific_num ? specific_num : 4);
        yf_u32_t specific_size = yf_align_mem(yfr_coroutine_specific_num * sizeof(void*));
        
        yfr_coroutine_meta_size = yf_align(yfr_coroutine_head_size + specific_size, 
                        yf_cacheline_size);
        
        yfr_coroutine_take_bit = yf_bit_cnt(stack_size);
        if (yf_bitcnt2val(yfr_coroutine_take_bit) < stack_size)
                ++yfr_coroutine_take_bit;
        
        yfr_coroutine_take_size = yf_bitcnt2val(yfr_coroutine_take_bit);
        yfr_coroutine_stack_size = yfr_coroutine_take_size - yf_pagesize;

        coroutine_total_max = yf_max(32, coroutine_total_max);

        yf_lock_init(&yfr_coroutine_stack_mgr.lock);
        yfr_coroutine_stack_mgr.alloced_num = 0;
        yfr_coroutine_stack_mgr.total_num = coroutine_total_max;

        char* cor_mem = yf_memalign(yfr_coroutine_take_size, 
                        yfr_coroutine_take_size * coroutine_total_max, log);
        if (cor_mem == NULL)
                return  YF_ERROR;

        yfr_coroutine_mem_begin = cor_mem;
        yfr_coroutine_mem_end = cor_mem 
                        + yfr_coroutine_take_size * coroutine_total_max;
        return YF_OK;
}


static  char* _yfr_coroutine_stack_alloc(yf_u32_t num, yf_log_t* log)
{
        yf_lock(&yfr_coroutine_stack_mgr.lock);
        if (num > yfr_coroutine_stack_mgr.total_num - yfr_coroutine_stack_mgr.alloced_num)
        {
                yf_log_error(YF_LOG_ERR, log, 0, 
                                "require num=%d > rest stack num, total=%d, alloced=%d", 
                                num, yfr_coroutine_stack_mgr.total_num, 
                                yfr_coroutine_stack_mgr.alloced_num);
                yf_unlock(&yfr_coroutine_stack_mgr.lock);
                return NULL;
        }

        char* mem = yfr_coroutine_mem_begin 
                        + yfr_coroutine_stack_mgr.alloced_num * yfr_coroutine_take_size;
        yfr_coroutine_stack_mgr.alloced_num += num;
        yf_unlock(&yfr_coroutine_stack_mgr.lock);

        return mem;
}


/*
* coroutine + mgr
*/

#define YFR_COROUTINE_UNSTARTED 0
#define YFR_COROUTINE_BLOCKED 1
#define YFR_COROUTINE_READY 2

//just one coroutine have the status of run in each mgr...
#define YFR_COROUTINE_RUN 3

static const char* yfr_coroutine_status_desc[] = {"unstarted", "blocked", "ready", "run"};

#define  YFR_COROUTINE_MAX_CALLBACK 4

struct yfr_coroutine_mgr_s;

typedef struct yfr_coroutine_in_s
{
        yfr_coroutine_t  base;

        union {
                yf_list_part_t   linker;
                yf_slist_part_t  free_linker;
        };
        yf_u32_t    status:3;
        yf_u32_t    used_times:8;//max=255
        yf_u32_t    virgin:1;
        yf_u32_t    sys_reserved:1;
        yf_u32_t    hidden:1;
        yf_u32_t    fcall_started:1;
        yf_u32_t    fcall_status:1;
        yf_u32_t    index;
        yf_s32_t     exit_status;

        yf_u32_t    last_run_time;

        yf_u32_t     block_id;

        struct yfr_coroutine_mgr_s* mgr;

        yfr_greenlet_t  greenlet;

        // for child fcall
        struct yfr_coroutine_in_s*  fcall_parent;
        yf_list_part_t   fcall_child_list;
        yf_list_part_t   fcall_child_linker;

        yfr_coroutine_exit_callback_t  callbacks[YFR_COROUTINE_MAX_CALLBACK];

        yf_u32_t  end_flag;
}
yfr_coroutine_in_t;


const yf_s32_t yfr_coroutine_head_size = yf_align_mem(sizeof(yfr_coroutine_in_t));
yf_s32_t yfr_coroutine_meta_size = 0;


struct yfr_coroutine_mgr_s
{
        yfr_coroutine_init_t  init_info;

        yf_s8_t  specific_num_used;
        
        yf_slist_part_t  free_list;
        yf_slist_part_t  sys_free_list;
        yf_list_part_t   ready_list;
        yf_list_part_t   blocked_list;
        yf_list_part_t   yield_list;

        yf_u32_t  ready_cnt;
        yf_u32_t  blocked_cnt;
        yf_u32_t  yield_cnt;

        yf_u64_t  running_rid;

        char* mem;
        yf_log_t* log;

        yf_id_seed_group_t  id_seed;

        yfr_greenlet_t  root_gr;
};


static void yfr_coroutine_init(yfr_coroutine_mgr_t* mgr
                , yfr_coroutine_in_t* coroutine, yf_u32_t index);
static void* _yfr_coroutine_end(yfr_coroutine_in_t* coroutine);
static void* _yfr_coroutine_proc(void* arg, yfr_greenlet_t* gr);


yfr_coroutine_mgr_t*  yfr_coroutine_mgr_create(
                yfr_coroutine_init_t* init_info, yf_log_t* log)
{
        yf_u32_t i1 = 0;

        if (!yfr_coroutine_take_bit)
        {
                yf_log_error(YF_LOG_ERR, log, 0, "you should config global coroutine first");
                return NULL;
        }
        
        yfr_coroutine_mgr_t* mgr = yf_alloc(sizeof(yfr_coroutine_mgr_t));
        mgr->init_info = *init_info;
        mgr->init_info.reset_after_used_times = yf_min(255, 
                        init_info->reset_after_used_times);
        mgr->log = log;
        
        yf_u32_t num = yf_max(16, init_info->run_max_num);
        yf_u32_t sys_num = yf_min(num>>1, yf_max(4, init_info->sys_reserved_num));
        
        mgr->init_info.run_max_num = num;
        mgr->init_info.sys_reserved_num = sys_num;
        
        yf_init_slist_head(&mgr->free_list);
        yf_init_slist_head(&mgr->sys_free_list);
        yf_init_list_head(&mgr->ready_list);
        yf_init_list_head(&mgr->blocked_list);
        yf_init_list_head(&mgr->yield_list);

        yfr_greenlet_root_init(&mgr->root_gr);

        yfr_coroutine_in_t* coroutines = NULL;

        char* cor_mem = _yfr_coroutine_stack_alloc(num, log);
        if (cor_mem == NULL)
                goto fail;

        mgr->mem = cor_mem;

        coroutines = _yfr_coroutine_m2r(cor_mem);

        if (yf_id_seed_group_init(&mgr->id_seed, init_info->run_max_num) != YF_OK)
        {
                yf_log_error(YF_LOG_ERR, log, 0, 
                                "maybe too many run max num, alloc seed group fail");
                goto fail;
        }

        for ( i1 = 0; i1 < num ; i1++ )
        {
                yfr_coroutine_init(mgr, coroutines, i1);

                if (i1 < sys_num)
                {
                        yf_slist_push(&coroutines->free_linker, &mgr->sys_free_list);
                        coroutines->sys_reserved = 1;                        
                }
                else {
                        yf_slist_push(&coroutines->free_linker, &mgr->free_list);
                }

                //next coroutine
                coroutines = yf_mem_off(coroutines, yfr_coroutine_take_size);
        }

        return (yfr_coroutine_mgr_t*)mgr;

fail:
        yf_free(mgr);
        if (cor_mem)
                assert(0);
        return NULL;
}


void yfr_coroutine_schedule(yfr_coroutine_mgr_t* mgr)
{
        yfr_coroutine_mgr_t* mgr_in = (yfr_coroutine_mgr_t*)mgr;
        yf_list_part_t* part = NULL;
        yfr_coroutine_in_t* coroutine = NULL;

        if (mgr_in->yield_cnt)
        {
                yf_list_splice(&mgr_in->yield_list, &mgr_in->ready_list);
                mgr_in->ready_cnt += mgr_in->yield_cnt;
                mgr_in->yield_cnt = 0;
        }

        yf_s32_t sec_now = yf_now_times.clock_time.tv_sec;
        
        while ((part = yf_list_pop_head(&mgr_in->ready_list)) != NULL)
        {
                mgr_in->ready_cnt--;
                
                coroutine = container_of(part, yfr_coroutine_in_t, linker);
                coroutine->status = YFR_COROUTINE_RUN;
                coroutine->block_id = 0;//rest block id

                coroutine->last_run_time = sec_now;

                mgr_in->running_rid = coroutine->base.id;

                yfr_greenlet_switch(&coroutine->greenlet, &mgr_in->root_gr, NULL);
        }
        assert(mgr_in->ready_cnt == 0);
}


static void* _yfr_coroutine_proc(void* arg, yfr_greenlet_t* gr)
{
        yfr_coroutine_in_t* coroutine = container_of(gr, yfr_coroutine_in_t, greenlet);
        assert(yf_check_magic(coroutine->end_flag));

        yfr_coroutine_t* base = &coroutine->base;
        coroutine->exit_status = base->pfn(base);

        return _yfr_coroutine_end(coroutine);
}

static void* _yfr_coroutine_end(yfr_coroutine_in_t* coroutine)
{
        yf_u32_t i1 = 0;
        yfr_coroutine_mgr_t* mgr = coroutine->mgr;
        yfr_coroutine_t* base = &coroutine->base;

        for ( i1 = 0; i1 < YFR_COROUTINE_MAX_CALLBACK; i1++ )
        {
                if (coroutine->callbacks[i1] == NULL)
                        break;
                coroutine->callbacks[i1](base, coroutine->exit_status);
                coroutine->callbacks[i1] = NULL;
        }
        
        if (unlikely(++(coroutine->used_times) >= 
                        mgr->init_info.reset_after_used_times))
        {
                coroutine->used_times = 0;
                yf_destroy_pool(coroutine->base.pool);
                coroutine->base.pool = NULL;
        }
        else 
                yf_reset_pool(coroutine->base.pool);
        
        if (mgr->init_info.cleanup)
                mgr->init_info.cleanup(base, coroutine->used_times);
        
        yf_slist_push(&coroutine->free_linker, 
                        coroutine->sys_reserved ? &mgr->sys_free_list : &mgr->free_list);
        coroutine->status = YFR_COROUTINE_UNSTARTED;
        coroutine->exit_status = 0;
        coroutine->fcall_status = 0;

        yf_log_debug(YF_LOG_DEBUG, base->log, 0, 
                        "coroutine ended, id=%L, ready cnt=%d, block cnt=%d", 
                        base->id, 
                        mgr->ready_cnt, 
                        mgr->blocked_cnt);
        
        return NULL;
}


yf_int_t yfr_coroutine_check(yfr_coroutine_t* r)
{
        if ((char*)(r) > yfr_coroutine_mem_begin
                && (char*)(r) < yfr_coroutine_mem_end)
        {
                yfr_coroutine_in_t* coroutine = container_of(r, yfr_coroutine_in_t, base);
                assert(yf_check_magic(coroutine->end_flag));
                yfr_coroutine_mgr_t* mgr_in = coroutine->mgr;
                
                if (mgr_in->running_rid && r->id != mgr_in->running_rid)
                {
                        yf_u64_t  running_rid = mgr_in->running_rid;
                        mgr_in->running_rid = 0;

                        //will call yfr_coroutine_check again in log_ext..., so must
                        yf_log_error(YF_LOG_EMERG, mgr_in->log, 0, 
                                    "running coroutine stack overflow, you should enlarge your stack size conf,"
                                    "running_rid=%L stack overflow to rid=%L",
                                    running_rid, r->id);
                        
                        yf_exit_with_sig(yf_signal_value(YF_SHUTDOWN_SIGNAL));
                        assert(0);
                }

                //yfr_coroutine_block will call log_debug, will check coroutine...
                //assert(coroutine->status == YFR_COROUTINE_RUN);
                return coroutine->hidden ? 0 : 1;
        }
        return 0;
}


yf_int_t yfr_coroutine_hidden_set(yfr_coroutine_t* r, yf_int_t hidden)
{
        yfr_coroutine_in_t* coroutine = container_of(r, yfr_coroutine_in_t, base);
        assert(yf_check_magic(coroutine->end_flag));

#ifdef YFR_DEBUG
        yf_log_debug(YF_LOG_DEBUG, r->log, 0,
                        "coroutine hidden set, id=%L, org=%d, to=%d",
                        coroutine->base.id, coroutine->hidden, hidden);
#endif
        coroutine->hidden = hidden;
        return 0;
}


static void yfr_coroutine_init(yfr_coroutine_mgr_t* mgr
                , yfr_coroutine_in_t* coroutine, yf_u32_t index)
{
        yf_memzero(coroutine, sizeof(yfr_coroutine_in_t));
        
        yf_set_magic(coroutine->base.begin_flag);
        yf_set_magic(coroutine->end_flag);

        coroutine->index = index;
        coroutine->mgr = mgr;
        coroutine->status = YFR_COROUTINE_UNSTARTED;
        coroutine->exit_status = 0;
        coroutine->virgin = 1;
        
        char* stack_addr = _yfr_coroutine_r2s(coroutine);

        yfr_greenlet_make(&coroutine->greenlet, 
                        &mgr->root_gr, 
                        stack_addr, _YFR_COROUTINE_VSS, 
                        _yfr_coroutine_proc);
        
        char* barrier_addr = _yfr_coroutine_s2m(stack_addr);

        yf_log_debug(YF_LOG_DEBUG, coroutine->base.log, 0, 
                        "coroutine init, stack_addr=%p, barrier_addr=%p", 
                        stack_addr, 
                        barrier_addr);

        int ret = mprotect(barrier_addr, yf_pagesize, PROT_NONE);
        assert(ret == 0);
}


yfr_coroutine_t*  yfr_coroutine_create_impl(yfr_coroutine_mgr_t* mgr, 
                yfr_coroutine_pfn_t pfn, 
                void* arg, yf_log_t* log, yf_int_t sys)
{
        yf_u32_t i1 = 0;
        yfr_coroutine_mgr_t* mgr_in = (yfr_coroutine_mgr_t*)mgr;
        yf_u32_t* flags;

        yf_slist_part_t* flist = sys ? &mgr_in->sys_free_list : &mgr_in->free_list;
        
        if (unlikely(yf_slist_empty(flist)))
        {
                if (sys)
                {
                        flist = &mgr_in->free_list;
                        if (unlikely(yf_slist_empty(flist)))
                        {
                                yf_log_error(YF_LOG_WARN, log, 0, 
                                                "sys coroutine used out, get from biz pool");
                        }
                        else {
                                yf_log_error(YF_LOG_WARN, log, 0, "biz+sys coroutine used out...");
                                return NULL;
                        }
                }
                else {
                        yf_log_error(YF_LOG_WARN, log, 0, "biz coroutine used out...");
                        return NULL;
                }
        }

        yf_slist_part_t* part = yf_slist_pop(flist);
        yfr_coroutine_in_t* coroutine = container_of(part, yfr_coroutine_in_t, free_linker);

        if (coroutine->base.pool == NULL)
        {
                coroutine->base.pool = yf_create_pool(yf_pagesize, log);
                if (coroutine->base.pool == NULL)
                {
                        yf_slist_push(part, flist);
                        yf_log_error(YF_LOG_WARN, log, 0, "create coroutine mem pool failed");
                        return NULL;
                }
        }

        yfr_greenlet_reset(&coroutine->greenlet, _yfr_coroutine_proc);
        coroutine->status = YFR_COROUTINE_UNSTARTED;
        coroutine->exit_status = 0;
        coroutine->fcall_status = 0;
        coroutine->base.id = yf_u32tou64_merge(coroutine->index, 
                        yf_id_seed_alloc(&mgr_in->id_seed));
        coroutine->sys_reserved = sys;

        yfr_coroutine_t* base = &coroutine->base;
        assert(yf_check_magic(base->begin_flag));

        if (unlikely(coroutine->virgin))
        {
                //why fill specail flag just here ?? I think about it already
                for ( i1 = 0; i1 < YF_ARRAY_SIZE(_yfr_coroutine_watches); i1++ )
                {
                        flags = _yfr_coroutine_vswatch(coroutine, _yfr_coroutine_watches[i1]);
                        *flags = _YFR_COROUTINE_VSWATCH_MAGIC;
                }
                
                coroutine->virgin = 0;
        }
        
        base->arg = arg;
        base->pfn = pfn;
        base->log = log;

        //specific data
        void** specific_addr = yfr_coroutine_specific_addr(base);
        yf_memzero(specific_addr, sizeof(void*) * yfr_coroutine_specific_num);

        yf_list_add_tail(&coroutine->linker, &mgr_in->ready_list);
        mgr_in->ready_cnt++;

        yf_log_debug(YF_LOG_DEBUG, log, 0, 
                        "new coroutine created, id=%L, ready cnt=%d, block cnt=%d", 
                        coroutine->base.id, 
                        mgr_in->ready_cnt, 
                        mgr_in->blocked_cnt);

        return base;
}


yfr_coroutine_t*  yfr_coroutine_getby_id(yfr_coroutine_mgr_t* mgr, 
                yf_u64_t  id)
{
        yfr_coroutine_mgr_t* mgr_in = (yfr_coroutine_mgr_t*)mgr;
        
        yf_u32_t index = yf_u32tou64_geth(id);
        if (index >= mgr_in->init_info.run_max_num)
        {
                yf_log_error(YF_LOG_ERR, mgr_in->log, 0, 
                                "illegal id=%L with index=%d", 
                                id, index);
                return NULL;
        }
        
        yfr_coroutine_in_t* coroutine = yf_mem_off(mgr_in->mem, 
                        (index << (yfr_coroutine_take_bit-1)) + 
                        yfr_coroutine_take_size - yfr_coroutine_meta_size);
        assert(coroutine->index == index);

        if (coroutine->base.id == id)
                return &coroutine->base;

        yf_log_error(YF_LOG_WARN, mgr_in->log, 0, 
                        "cant find coroutine by id=%L, now id=%L", 
                        id, coroutine->base.id);
        return NULL;
}


inline yfr_coroutine_mgr_t* yfr_coroutine_get_mgr(yfr_coroutine_t* r)
{
        yfr_coroutine_in_t* coroutine = container_of(r, yfr_coroutine_in_t, base);
        assert(yf_check_magic(coroutine->end_flag));

        return  (yfr_coroutine_mgr_t*)coroutine->mgr;
}


inline yfr_coroutine_init_t* yfr_coroutine_mgr_ctx(yfr_coroutine_t* r)
{
        yfr_coroutine_in_t* coroutine = container_of(r, yfr_coroutine_in_t, base);
        assert(yf_check_magic(coroutine->end_flag));

        return  &coroutine->mgr->init_info;
}

inline yfr_coroutine_init_t* yfr_coroutine_mgr_ctx2(yfr_coroutine_mgr_t* mgr)
{
        yfr_coroutine_mgr_t* mgr_in = (yfr_coroutine_mgr_t*)mgr;
        return &mgr_in->init_info;
}


yf_s8_t  yfr_coroutine_mgr_specific_key_alloc(yfr_coroutine_mgr_t* mgr)
{
        yfr_coroutine_mgr_t* mgr_in = (yfr_coroutine_mgr_t*)mgr;
        if (mgr_in->specific_num_used >= yfr_coroutine_specific_num)
        {
                yf_log_error(YF_LOG_ERR, mgr_in->log, 0, 
                                "specific used out, max=%d", yfr_coroutine_specific_num);
                return -1;
        }
        return mgr_in->specific_num_used++;
}


inline yf_int_t  yfr_coroutine_add_callback(yfr_coroutine_t* r
                , yfr_coroutine_exit_callback_t cb)
{
        yf_u32_t i1 = 0;
        yfr_coroutine_in_t* coroutine = container_of(r, yfr_coroutine_in_t, base);
        assert(yf_check_magic(coroutine->end_flag));

        for ( i1 = 0; i1 < YFR_COROUTINE_MAX_CALLBACK; i1++ )
        {
                if (coroutine->callbacks[i1] == NULL)
                {
                        coroutine->callbacks[i1] = cb;
                        return YF_OK;
                }
        }
        return YF_ERROR;
}



void yfr_coroutine_block(yfr_coroutine_t* r, yf_u32_t* block_id)
{
        yfr_coroutine_in_t* coroutine = container_of(r, yfr_coroutine_in_t, base);
        assert(yf_check_magic(coroutine->end_flag));
        assert(coroutine->status == YFR_COROUTINE_RUN);

        yfr_coroutine_mgr_t* mgr_in = coroutine->mgr;

        coroutine->status = YFR_COROUTINE_BLOCKED;
        coroutine->block_id = yf_id_seed_alloc(&mgr_in->id_seed);
        if (block_id)
                *block_id = coroutine->block_id;

        /*
        *schedule already done this before run this coroutine
        *mgr_in->ready_cnt--;
        *yf_list_del(&coroutine->linker);
        */
        mgr_in->blocked_cnt++;
        
        yf_list_add_tail(&coroutine->linker, &mgr_in->blocked_list);

#ifdef _COR_TRACE
        yf_log_debug(YF_LOG_DEBUG, r->log, 0, 
                        "syscall.coroutine block, id=%L, block_id=%d", 
                        coroutine->base.id,
                        coroutine->block_id);
#endif

        yfr_greenlet_switch(&mgr_in->root_gr, &coroutine->greenlet, NULL);
}


yf_int_t yfr_coroutine_resume(yfr_coroutine_t* r, yf_u32_t block_id)
{
        yfr_coroutine_in_t* coroutine = container_of(r, yfr_coroutine_in_t, base);
        assert(yf_check_magic(coroutine->end_flag));
        
        if (block_id && coroutine->block_id != block_id)
        {
                yf_log_error(YF_LOG_WARN, coroutine->base.log, 0, 
                                "coroutine_%L bid=%d != ibid=%d", 
                                coroutine->base.id, coroutine->block_id, block_id);
                return -1;
        }

        if (coroutine->status == YFR_COROUTINE_READY)
        {
                yf_log_debug2(YF_LOG_DEBUG, coroutine->base.log, 0, 
                                "coroutine_%L already resumed for run, blockid=%d", 
                                coroutine->base.id, coroutine->block_id);
                return 0;
        }
        
        assert(coroutine->status == YFR_COROUTINE_BLOCKED);

        coroutine->status = YFR_COROUTINE_READY;

        coroutine->mgr->ready_cnt++;
        coroutine->mgr->blocked_cnt--;

        yf_list_del(&coroutine->linker);
        yf_list_add_tail(&coroutine->linker, &coroutine->mgr->ready_list);

#ifdef _COR_TRACE
        yf_log_debug(YF_LOG_DEBUG, r->log, 0, 
                        "syscall.coroutine resume, id=%L, block_id=%d", 
                        coroutine->base.id,
                        coroutine->block_id);
#endif
        //let schedule switch it back...

        return  0;
}


void yfr_coroutine_yield(yfr_coroutine_t* r)
{
        yfr_coroutine_in_t* coroutine = container_of(r, yfr_coroutine_in_t, base);
        assert(yf_check_magic(coroutine->end_flag));
        assert(coroutine->status == YFR_COROUTINE_RUN);

        coroutine->status = YFR_COROUTINE_READY;

        yfr_coroutine_mgr_t* mgr_in = coroutine->mgr;
        
        mgr_in->yield_cnt++;

        yf_list_add_tail(&coroutine->linker, &mgr_in->yield_list);

#ifdef _COR_TRACE
        yf_log_debug(YF_LOG_DEBUG, r->log, 0, 
                        "syscall.coroutine yield, id=%L", 
                        coroutine->base.id);
#endif

        yfr_greenlet_switch(&mgr_in->root_gr, &coroutine->greenlet, NULL);        
}


yf_int_t yfr_coroutine_cancel(yfr_coroutine_t* r)
{
        yfr_coroutine_in_t* coroutine = container_of(r, yfr_coroutine_in_t, base);
        assert(yf_check_magic(coroutine->end_flag));
        if (coroutine->status != YFR_COROUTINE_UNSTARTED)
        {
                yf_log_error(YF_LOG_WARN, r->log, 0, "cant cancel !unstarted coroutine");
                return YF_ERROR;
        }

        yfr_coroutine_mgr_t* mgr_in = coroutine->mgr;

        yf_list_del(&coroutine->linker);
        yf_slist_push(&coroutine->free_linker, 
                        coroutine->sys_reserved ? &mgr_in->sys_free_list : &mgr_in->free_list);
        coroutine->status = YFR_COROUTINE_UNSTARTED;
        coroutine->exit_status = 0;
        coroutine->fcall_status = 0;
        
        mgr_in->ready_cnt--;
        
        yf_log_debug(YF_LOG_DEBUG, mgr_in->log, 0, 
                        "coroutine cancelled, id=%L, ready cnt=%d, block cnt=%d", 
                        r->id, 
                        mgr_in->ready_cnt, 
                        mgr_in->blocked_cnt);
        return YF_OK;
}


inline yf_int_t  yfr_coroutine_exit_status(yfr_coroutine_t* r)
{
        yfr_coroutine_in_t* coroutine = container_of(r, yfr_coroutine_in_t, base);
        assert(yf_check_magic(coroutine->end_flag));
        
        return coroutine->exit_status;
}


yf_u32_t  yfr_coroutine_stack_check(yf_log_t* log
                , yf_u32_t coroutine_leak_secs)
{
        yf_u32_t i1 = 0;
        static yf_int_t last_check = 0;

        char* mem_check = yfr_coroutine_mem_begin + last_check * yfr_coroutine_take_size;
        yfr_coroutine_in_t* coroutine;

        yf_s32_t sec_now = yf_now_times.clock_time.tv_sec;
        coroutine_leak_secs = yf_max(coroutine_leak_secs, 60);
        
        yf_u32_t rest_percent_min = 100;
        yf_u32_t* swatch = NULL;
        yf_int_t cnt;
        for (cnt = 0; cnt < 1024; ++cnt)
        {
                coroutine = _yfr_coroutine_m2r(mem_check);
                if (!coroutine->virgin)
                {
                        //check run status, if lost or leak
                        if (coroutine->status != YFR_COROUTINE_UNSTARTED)
                        {
                                if (sec_now > coroutine->last_run_time + coroutine_leak_secs)
                                {
                                        if (!coroutine->sys_reserved)
                                        {
                                                yf_log_error(YF_LOG_WARN, log, 0, 
                                                        "coroutine id=%L not run for long time, last_run_time=%d, now time=%d", 
                                                        coroutine->base.id, coroutine->last_run_time, sec_now);
                                        }
                                }
                        }

                        //check stack overflow
                        for ( i1 = 0; i1 < YF_ARRAY_SIZE(_yfr_coroutine_watches); i1++ )
                        {
                                swatch = _yfr_coroutine_vswatch(coroutine, _yfr_coroutine_watches[i1]);
                                
                                if (*swatch == _YFR_COROUTINE_VSWATCH_MAGIC)
                                {
                                        rest_percent_min = yf_min(rest_percent_min, 
                                                        _yfr_coroutine_watches[i1]);
                                        break;
                                }
                        }
                        
                        if (i1 == YF_ARRAY_SIZE(_yfr_coroutine_watches))
                        {
                                yf_log_error(YF_LOG_WARN, log, 0, "r=%L stack last barrier broken !!",
                                        coroutine->base.id);
                                rest_percent_min = 0;
                        }
                }
                
                if (++last_check >= yfr_coroutine_stack_mgr.alloced_num)
                {
                        last_check = 0;
                        break;
                }
                mem_check += yfr_coroutine_take_size;
        }

        return  rest_percent_min;
}


yf_int_t yfr_coroutine_fcall_start()
{
        yfr_coroutine_t* r = NULL;
        r = yfr_coroutine_addr(r);
        if (unlikely(!yfr_coroutine_check(r)))
                return YF_ERROR;

        yfr_coroutine_in_t* coroutine = container_of(r, yfr_coroutine_in_t, base);
        if (coroutine->fcall_started) {
                yf_log_error(YF_LOG_WARN, r->log, 0, "you have call this before!!");
                return YF_ERROR;
        }

        yf_init_list_head(&coroutine->fcall_child_list);
        coroutine->fcall_started = 1;
        coroutine->fcall_status = 0;
        return YF_OK;
}


yfr_coroutine_t* _yfr_coroutine_fcall_child_pre(yfr_coroutine_t* r,
        yfr_greenlet_t** greenlet_self,
        yfr_greenlet_t** greenlet_child)
{
        yfr_coroutine_in_t* self = container_of(r, yfr_coroutine_in_t, base);
        assert(yf_check_magic(self->end_flag));
        yfr_coroutine_mgr_t* mgr = self->mgr;

        if (!self->fcall_started) {
                yf_log_error(YF_LOG_WARN, r->log, 0,
                        "you should call yfr_coroutine_fcall_start first...");
                self->fcall_status = 1;
                return NULL;
        }

        *greenlet_self = &self->greenlet;
        *greenlet_child = NULL;

        yfr_coroutine_t* child = yfr_coroutine_create_impl(mgr, NULL, NULL, r->log, 0);
        if (child == NULL) {
                yf_log_error(YF_LOG_WARN, r->log, 0, "coroutine used out, cant run in child...");
                self->fcall_status = 1;
                return NULL;
        }

        yfr_coroutine_in_t* cor_child = container_of(child, yfr_coroutine_in_t, base);
        *greenlet_child = &cor_child->greenlet;

        yf_list_add_tail(&cor_child->fcall_child_linker, &self->fcall_child_list);
        cor_child->fcall_parent = self;

        return &cor_child->base;
}


yf_int_t yfr_coroutine_fcall_wait()
{
        yfr_coroutine_t* r = NULL;
        r = yfr_coroutine_addr(r);
        if (unlikely(!yfr_coroutine_check(r)))
                return YF_ERROR;

        yfr_coroutine_in_t* coroutine = container_of(r, yfr_coroutine_in_t, base);
        if (!coroutine->fcall_started) {
                yf_log_error(YF_LOG_WARN, r->log, 0,
                        "you should call yfr_coroutine_fcall_start first...");
                return YF_ERROR;
        }

        while (!yf_list_empty(&coroutine->fcall_child_list)) {
                yfr_coroutine_block(r, NULL);
        }
        coroutine->fcall_started = 0;

        return coroutine->fcall_status ? YF_ERROR : YF_OK;
}


void* _yfr_coroutine_fcall_endcb(void* arg, yfr_greenlet_t* gr)
{
        yfr_coroutine_in_t* self = container_of(gr, yfr_coroutine_in_t, greenlet);
        assert(yf_check_magic(self->end_flag));

        yfr_coroutine_in_t* parent = self->fcall_parent;
        assert(parent);
        self->fcall_parent = NULL;

        yf_list_del(&self->fcall_child_linker);
        if (yf_list_empty(&parent->fcall_child_list)) {
                yfr_coroutine_resume(&parent->base, 0);
        }

        return _yfr_coroutine_end(self);
}


