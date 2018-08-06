#include "yfr_greenlet.h"

/*
* 此函数永远不会返回到caller，它是新的greelet的入口函数
* 执行完毕后，不会ret到callert，而是直接切回到parent（实际即：root）的执行环境
*/
void yfr_greenlet_start_wrapper(void *arg)
{
        // printf("yfr_greenlet_start_wrapper now arg=%p\n", arg);
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
        // greenlet self over now
        // switch to parent greenlet
        _greenlet_switchcontext(&greenlet->gr_frame, greenlet->gr_inject, ret);
}

/*
* 从 ogr greelet 切换到 ngr...
* 1 - 先保存org的寄存器栈上下文，_greenlet_savecontext 保存的最重要的是调用_greenlet_savecontext 
*     前的eip（即call指令代表的第一条：pushl %eip）
* 2 - 无论后面的ngr是怎么执行的，ogr在切换后，其栈环境, 寄存器的值停留在了 _greenlet_savecontext 里面
*     _greenlet_savecontext的作用有点像对此时的环境做来个快照！
*     注意：即使ngr调用完savecontext后，还是会继续执行到函数尾部，但ogr的环境快照其实是停留在 _greenlet_savecontext 里面的.
*          理解这点至关重要
* 3 - 如果ngr是新的greelet，栈未初始化，需走 _greenlet_newstack 流程：即将esp指向ngr的stack
*     然后模拟调用 _greenlet_start（i：push参数，ii：因无ret，但又必须符合c函数调用协议规范中的call指令需在实参后保存eip，所以pushl $0
*     对此，_greenlet_start对此完全无感知）
* 4 - 如果ngr是一个被暂停过的greelet，此时相当于切换进去，_greenlet_switchcontext 的作用是将之前切走并保存的
*     环境快照（参考步骤2）取回来，并继续执行！所以 _greenlet_savecontext 实际会返回两次：
*     第一次是：正常的savecontext，然后立即返回，这次调用的作用就是保存上下文快照
*     然后ogr继续运行，eip其实会走到yfr_greenlet_switch尾部，然后被_greenlet_switchcontext切换走
*     第二次：原来的ogr变成来ngr，被 _greenlet_switchcontext 唤醒，唤醒适合的栈环境寄存器其实就是2里面的快照，即还在
*     _greenlet_savecontext 里面，然后返回1，因if判断，于是直接返回
*/
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
                // printf("_greenlet_newstack\n");
                _greenlet_newstack((char *)ngr->gr_stack + ngr->gr_stacksize,
                                   yfr_greenlet_start_wrapper, ngr);
        }

        //greenlet ret
        while (yfr_greenlet_isdead(ngr))
                ngr = ngr->gr_parent;

        ngr->gr_arg = arg;
        // 切换后，ogr 的栈环境与寄存器已经不匹配，所以后面的切换只能会切到 savecontext 那个快照那里
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

