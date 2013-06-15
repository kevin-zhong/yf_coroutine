#ifndef _YFR_IPC_H_20130304_H
#define _YFR_IPC_H_20130304_H
/*
* copyright@: kevin_zhong, mail:qq2000zhong@gmail.com
* time: 20130304-18:20:29
*/

#include <yfr_head.h>
#include <coroutine/yfr_coroutine.h>

/*
* tm == 0, will wait forever
*/


/*
* single lock, support lock more than once by same coroutine
* if lock>1, should unlock with the same times
*/
typedef struct yfr_ipc_lock_s
{
        yf_u64_t  lock_rid;
        yf_u8_t    lock_times;//max 255 times
        yf_u32_t  ready_cnt;
        yf_list_part_t  head;
}
yfr_ipc_lock_t;

#define yfr_ipc_lock_init(l)  do { \
                (l)->lock_rid = 0; \
                (l)->lock_times = 0; \
                (l)->ready_cnt = 0; \
                yf_init_list_head(&(l)->head); \
        } while(0)
        
#define  yfr_ipc_locked(l) ((l)->lock_rid)
#define  yfr_ipc_locked_by(l, r) ((l)->lock_rid == (r)->id)

//waited: the flag if lock success immediately, set NULL if you dont wann know
yf_int_t  yfr_ipc_lock(yfr_ipc_lock_t* l, yf_u32_t tm, yf_int_t* waited);

void yfr_ipc_unlock(yfr_ipc_lock_t* l);

/*
* support multi lockers
*/
typedef struct yfr_ipc_mlock_s
{
        yf_u32_t  max_share;
        yf_u32_t  now_share;
        yf_u32_t  ready_cnt;
        yf_list_part_t  head;
}
yfr_ipc_mlock_t;


#define yfr_ipc_lock_mlock_init(l, m) do { \
                (l)->max_share = m; \
                (l)->now_share = 0; \
                (l)->ready_cnt = 0; \
                yf_init_list_head(&(l)->head); \
        } while(0)

#define  yfr_ipc_mlocked(l) ((l)->now_share)        

yf_int_t  yfr_ipc_mlock(yfr_ipc_mlock_t* l, yf_u32_t tm, yf_int_t* waited);

void yfr_ipc_munlock(yfr_ipc_mlock_t* l);


/*
* note, this cond not equall to the cond in thread..., just 1->1 or 1->n for broadcast
*/
typedef struct yfr_ipc_cond_s
{
        yf_list_part_t  head;
}
yfr_ipc_cond_t;

#define yfr_ipc_cond_init(c) yf_init_list_head(&(c)->head)

#define yfr_ipc_cond_have_waits(c) (!yf_list_empty(&(c)->head))

void  yfr_ipc_cond_wait(yfr_ipc_cond_t* c);

void  yfr_ipc_cond_sig(yfr_ipc_cond_t* c);

#endif

