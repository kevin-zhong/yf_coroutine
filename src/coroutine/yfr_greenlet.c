#include "yfr_greenlet.h"

void yfr_greenlet_start_wrapper(void *arg)
{
        yfr_greenlet_t *greenlet = (yfr_greenlet_t *)arg;
        void *ret;
        
        greenlet->gr_flags |= YFR_GREENLET_STARTED;
        
        if (unlikely(greenlet->gr_inject))
                greenlet->gr_inject(greenlet->gr_arg);
        greenlet->gr_inject = NULL;
        ret = greenlet->gr_proc(greenlet->gr_arg, greenlet);
        
        greenlet->gr_flags |= YFR_GREENLET_DEAD;

        //greenlet ret
        while (yfr_greenlet_isdead(greenlet))
                greenlet = greenlet->gr_parent;

        greenlet->gr_arg = ret;
        _greenlet_switchcontext(&greenlet->gr_frame, greenlet->gr_inject, ret);
}

void *yfr_greenlet_switch(yfr_greenlet_t *ngr, yfr_greenlet_t *ogr, void *arg)
{
        if (_greenlet_savecontext(&ogr->gr_frame))
        {
                ogr->gr_inject = NULL;
                return ogr->gr_arg;
        }

        if (!yfr_greenlet_isstarted(ngr))
        {
                ngr->gr_arg = arg;
                _greenlet_newstack((char *)ngr->gr_stack + ngr->gr_stacksize,
                                   yfr_greenlet_start_wrapper, ngr);
        }

        //greenlet ret
        while (yfr_greenlet_isdead(ngr))
                ngr = ngr->gr_parent;

        ngr->gr_arg = arg;
        _greenlet_switchcontext(&ngr->gr_frame, ngr->gr_inject, arg);

        return NULL;
}


inline void yfr_greenlet_inject(yfr_greenlet_t *gr, yfr_greenlet_inject_func_t inject_func)
{
        gr->gr_inject = inject_func;
}

inline void yfr_greenlet_reset(yfr_greenlet_t *gr, yfr_greenlet_proc_t start_func)
{
        gr->gr_flags = 0;
        if (start_func)
                gr->gr_proc = start_func;
}

