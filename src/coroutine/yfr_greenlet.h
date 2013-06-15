#ifndef _YFR_GREENLET_H_20130301_H
#define _YFR_GREENLET_H_20130301_H
/*
* copyright@: kevin_zhong, mail:qq2000zhong@gmail.com
* time: 20130301-18:49:49
*/

#include <yfr_head.h>

#define YFR_GREENLET_STARTED 0x1
#define YFR_GREENLET_DEAD 0X2

typedef struct yfr_greenlet_s  yfr_greenlet_t;

typedef void *(*yfr_greenlet_start_func_t)(void*, yfr_greenlet_t*);
typedef void (*yfr_greenlet_inject_func_t)(void*);

struct yfr_greenlet_s
{
        yfr_greenlet_t *gr_parent;
        
        void *gr_stack;
        long  gr_stacksize;
        int    gr_flags;
        
        yfr_greenlet_start_func_t gr_start;
        void *gr_arg;//used to transfer data between grs
        yfr_greenlet_inject_func_t gr_inject;
        void *gr_frame[8];
};

#define  yfr_greenlet_make(gr, parent, stack, stacksize, pfn) do { \
        yf_memzero(gr, sizeof(struct yfr_greenlet_s)); \
        (gr)->gr_parent = parent; \
        (gr)->gr_stack = stack; \
        (gr)->gr_stacksize = stacksize; \
        (gr)->gr_start = pfn; \
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
void yfr_greenlet_reset(yfr_greenlet_t *gr, yfr_greenlet_start_func_t start_func);

#define yfr_greenlet_isstarted(gr) (((gr)->gr_flags & YFR_GREENLET_STARTED))
#define yfr_greenlet_isdead(gr) (((gr)->gr_flags & YFR_GREENLET_DEAD))


#endif

