#ifndef _YFR_COROUTINE_H_20130227_H
#define _YFR_COROUTINE_H_20130227_H
/*
* copyright@: kevin_zhong, mail:qq2000zhong@gmail.com
* time: 20130227-18:30:38
*/

#include <yfr_head.h>
#include "yfr_greenlet.h"

typedef struct yfr_coroutine_s yfr_coroutine_t;

typedef yf_int_t (*yfr_coroutine_pfn_t)(yfr_coroutine_t*);

typedef void (*yfr_coroutine_exit_callback_t)(yfr_coroutine_t*, yf_int_t);

struct yfr_coroutine_s
{
        yf_u32_t  begin_flag;
        yf_u32_t  data;//can be used by user
        yf_u64_t  id;

        yfr_coroutine_pfn_t  pfn;
        void *arg;

        yf_pool_t* pool;
        
        yf_log_t* log;
};


//assume that the stack from high addr to low addr
extern const yf_s32_t yfr_coroutine_head_size;
extern yf_s32_t  yfr_coroutine_meta_size;
extern yf_s32_t  yfr_coroutine_take_size;
extern char* yfr_coroutine_mem_begin;
extern char* yfr_coroutine_mem_end;
extern yf_s8_t yfr_coroutine_specific_num;

#define yfr_coroutine_addr(stack_val) ((yfr_coroutine_t*) \
                (yf_align((yf_uint_ptr_t)&stack_val, (yf_uint_ptr_t)yfr_coroutine_take_size) \
                        - yfr_coroutine_meta_size))

#define yfr_coroutine_specific_addr(r) yf_mem_off(r, yfr_coroutine_head_size)

yf_int_t yfr_coroutine_check(yfr_coroutine_t* r);

/*
* for yfr_coroutine_check ret false to stop replace sys hook
*/
yf_int_t yfr_coroutine_hidden_set(yfr_coroutine_t* r, yf_int_t hidden);


#define YFR_COROUTINE_STACK_WATCH_SPLIT 8

/*
* if stack_size == 0, use yf_pagesize * 8 as default
* if specific_num == 0, use 4 as default, max<=32
*/
yf_int_t yfr_coroutine_global_set(yf_u32_t coroutine_total_max
                , yf_u32_t stack_size, yf_u32_t specific_num, yf_log_t* log);

yf_u32_t  yfr_coroutine_stack_check(yf_log_t* log
                , yf_u32_t coroutine_leak_secs);


typedef struct yfr_coroutine_init_s
{
        yf_u32_t  run_max_num;
        yf_u16_t  sys_reserved_num;
        yf_u32_t  reset_after_used_times;
        
        yf_evt_driver_t* evt_driver;

        //second arg: if the coroutine need reset all
        void (*cleanup)(yfr_coroutine_t*, yf_int_t);

        void* data[8];
}
yfr_coroutine_init_t;


typedef struct yfr_coroutine_mgr_s yfr_coroutine_mgr_t;

yfr_coroutine_mgr_t*  yfr_coroutine_mgr_create(
                yfr_coroutine_init_t* init_info, yf_log_t* log);

void yfr_coroutine_schedule(yfr_coroutine_mgr_t* mgr);

/*
* after created, you also can alter pfn or arg in this coroutine
*/
yfr_coroutine_t*  yfr_coroutine_create_impl(yfr_coroutine_mgr_t* mgr, 
                yfr_coroutine_pfn_t pfn, 
                void* arg, yf_log_t* log, yf_int_t sys);

#define yfr_coroutine_create(mgr, pfn, arg, log) \
                yfr_coroutine_create_impl(mgr, pfn, arg, log, 0)
                
#define yfr_coroutine_sys_create(mgr, pfn, arg, log) \
                yfr_coroutine_create_impl(mgr, pfn, arg, log, 1)                

yfr_coroutine_t*  yfr_coroutine_getby_id(yfr_coroutine_mgr_t* mgr, 
                yf_u64_t  id);


yfr_coroutine_mgr_t* yfr_coroutine_get_mgr(yfr_coroutine_t* r);
yfr_coroutine_init_t* yfr_coroutine_mgr_ctx(yfr_coroutine_t* r);
yfr_coroutine_init_t* yfr_coroutine_mgr_ctx2(yfr_coroutine_mgr_t* mgr);

yf_s8_t  yfr_coroutine_mgr_specific_key_alloc(yfr_coroutine_mgr_t* mgr);

//get val = void**
#define yfr_coroutine_specific(r, k) ((void**)yfr_coroutine_specific_addr(r) + k)


yf_int_t  yfr_coroutine_add_callback(yfr_coroutine_t* r
                , yfr_coroutine_exit_callback_t cb);

/*
* switch out from r into other coroutine
* you must call resume to let it run follow...
*/
void yfr_coroutine_block(yfr_coroutine_t* r, yf_u32_t* block_id);

/*
* ret 0 if success, else -1(block may cancel or resume by other callback)
*/
yf_int_t yfr_coroutine_resume(yfr_coroutine_t* r, yf_u32_t block_id);

/*
* just give up the schedule, next schedule will run agin, no need to resume
*/
void yfr_coroutine_yield(yfr_coroutine_t* r);

/*
* cancel, just unstarted coroutine can cancel
*/
yf_int_t yfr_coroutine_cancel(yfr_coroutine_t* r);

yf_int_t  yfr_coroutine_exit_status(yfr_coroutine_t* r);


yfr_coroutine_t* _yfr_coroutine_fcall_child_pre(yfr_coroutine_t* r,
        yfr_greenlet_t** greenlet_self,
        yfr_greenlet_t** greenlet_child);

void* _yfr_coroutine_fcall_endcb(void* arg, yfr_greenlet_t* gr);


#define yfr_fcall_api int __attribute__ ((noinline))

/*
* this func just can be call in coroutine
*/
yf_int_t yfr_coroutine_fcall_start();

#define yfr_coroutine_fcall_child do { \
        yfr_greenlet_t* greenlet_self = NULL; \
        yfr_greenlet_t* greenlet_child = NULL; \
        yfr_coroutine_t* cor_self = yfr_coroutine_addr(greenlet_self); \
        if (unlikely(!yfr_coroutine_check(cor_self))) { \
                return -1; \
        } \
        yfr_coroutine_t* cor_child = _yfr_coroutine_fcall_child_pre( \
                cor_self, &greenlet_self, &greenlet_child); \
        if (cor_child == NULL) { \
                return 0; \
        } \
        yfr_greenlet_fcall(greenlet_self, greenlet_child, _yfr_coroutine_fcall_endcb); \
} while (0)


yf_int_t yfr_coroutine_fcall_wait();


#endif

