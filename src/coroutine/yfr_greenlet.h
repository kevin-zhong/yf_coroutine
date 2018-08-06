#ifndef _YFR_GREENLET_H_20130301_H
#define _YFR_GREENLET_H_20130301_H
/*
* copyright@: kevin_zhong, mail:qq2000zhong@gmail.com
* time: 20130301-18:49:49
* add new feature:
*       support run a func in child coroutine...
*       very hard work, 7 days spent, but it's worth...
*       learned a lot of assembly and function call/frame inners...
*/

#include <yfr_head.h>

#define YFR_GREENLET_STARTED 0x1
#define YFR_GREENLET_DEAD 0X2

typedef struct yfr_greenlet_s  yfr_greenlet_t;

typedef void *(*yfr_greenlet_proc_t)(void*, yfr_greenlet_t*);
typedef void (*yfr_greenlet_inject_func_t)(void*);

struct yfr_greenlet_s
{
        yfr_greenlet_t *gr_parent;
        
        void *gr_stack;
        long  gr_stacksize;
        int    gr_flags;
        
        yfr_greenlet_proc_t gr_proc;
        void *gr_arg;//used to transfer data between grs
        yfr_greenlet_inject_func_t gr_inject;
        void *gr_frame[8];
};

#define  yfr_greenlet_make(gr, parent, stack, stacksize, pfn) do { \
        yf_memzero(gr, sizeof(struct yfr_greenlet_s)); \
        (gr)->gr_parent = parent; \
        (gr)->gr_stack = stack; \
        (gr)->gr_stacksize = stacksize; \
        (gr)->gr_proc = pfn; \
} while(0)

#define yfr_greenlet_root_init(gr) do { \
        yf_memzero(gr, sizeof(struct yfr_greenlet_s)); \
        (gr)->gr_flags = YFR_GREENLET_STARTED; \
} while(0)

//arg used to :
//if ngr not started, to set gr_arg
//else transfer info between greenlets, if no info transfered, set NULL
void* yfr_greenlet_switch(yfr_greenlet_t *ngr, yfr_greenlet_t *ogr, void *arg);

void yfr_greenlet_inject(yfr_greenlet_t *gr, yfr_greenlet_inject_func_t inject_func);

//if start_func!=NULL, will replace old func
void yfr_greenlet_reset(yfr_greenlet_t *gr, yfr_greenlet_proc_t start_func);

void yfr_greenlet_start_wrapper(void *arg);

#define yfr_greenlet_isstarted(gr) (((gr)->gr_flags & YFR_GREENLET_STARTED))
#define yfr_greenlet_isdead(gr) (((gr)->gr_flags & YFR_GREENLET_DEAD))


extern void _greenlet_switchcontext(void***, yfr_greenlet_inject_func_t, void* arg);
extern int _greenlet_savecontext(void***);
extern void _greenlet_newstack(char*, void (*)(void*), yfr_greenlet_t*);
extern void _greenlet_fcall_end();


#if defined(__x86_64__)
#define yfr_asm_switch_statck(_bp, _sp) \
    __asm__ __volatile__("movq %0, %%rbp; movq %1, %%rsp;" \
        "" \
        : : "r"(_bp), "r"(_sp):"rbp", "rsp")

#define yfr_asm_get_stack(_bp, _sp) \
    __asm__ __volatile__("movq %%rbp, %0; movq %%rsp, %1": "=g"(_bp),"=g"(_sp))

#define _YFR_FRAME_ARG_MAX_SIZE 48
#else

#define yfr_asm_switch_statck(_bp, _sp) \
    __asm__ __volatile__("movl %0, %%ebp; movl %1, %%esp;" : : "g"(_bp), "g"(_sp): "ebp", "esp")

#define yfr_asm_get_stack(_bp, _sp) \
    __asm__ __volatile__("movl %%ebp, %0; movl %%esp %1": "=g"(_bp),"=g"(_sp))

#define _YFR_FRAME_ARG_MAX_SIZE 48
#endif


#define _YFR_ESP_ALIGN(_p) (char*)(((yf_uint_ptr_t)(_p)) & ~(yf_uint_ptr_t(31)))

/*
* max args num=12
*/
#define yfr_greenlet_fcall(gr_self, gr, pfn_end) do { \
    if (!_greenlet_savecontext((void***)&(gr)->gr_frame)) { \
        (gr)->gr_flags |= YFR_GREENLET_STARTED; \
        (gr)->gr_proc = pfn_end; \
        \
        ssize_t _ldiff; \
        char* _sstart = (char*)(gr)->gr_stack + (gr)->gr_stacksize - YF_SIZEOF_PTR; \
        char* _sp = NULL; \
        char* _bp = NULL; \
        char* _nsp = NULL; \
        char* _nbp = NULL; \
        yfr_asm_get_stack(_bp, _sp); \
        _sp = (char*)(gr)->gr_frame[1]; \
        \
        /* ... */ \
        _ldiff = _bp + _YFR_FRAME_ARG_MAX_SIZE - _sp; \
        _nsp = _YFR_ESP_ALIGN(_sstart -YF_SIZEOF_PTR - _ldiff); \
        _nbp = _nsp + (_bp - _sp); \
        \
        /* switch stack to new greenlet, and save rigisters context * \
        yfr_asm_switch_statck(_nbp, _nsp); */\
        /* copy agrs in stack, aligned * \
        memcpy(_nbp + 2*YF_SIZEOF_PTR, _bp + 2*YF_SIZEOF_PTR, _YFR_FRAME_ARG_MAX_SIZE);*/ \
        memcpy(_nsp, _sp, _ldiff); \
        (gr)->gr_frame[1] = _nsp; \
        (gr)->gr_frame[2] = _nbp; \
        \
        /* set caller eip & ebp, will call yfr_greenlet_start_wrapper */ \
        *((void**)(_nbp + YF_SIZEOF_PTR)) = (void*)_greenlet_fcall_end; \
        *((void**)(_nbp)) = _sstart; \
        /* preprare for _greenlet_fcall_end */ \
        *((void**)(_sstart)) = (gr); \
        *((void**)(_sstart - YF_SIZEOF_PTR)) = (void*)yfr_greenlet_start_wrapper; \
        return 0; \
    } \
} while (0)


#define yfr_greenlet_fcall_end(gr_self)

#endif

