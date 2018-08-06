#include "yfr_greenlet.h"

/*
* �˺�����Զ���᷵�ص�caller�������µ�greelet����ں���
* ִ����Ϻ󣬲���ret��callert������ֱ���лص�parent��ʵ�ʼ���root����ִ�л���
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
* �� ogr greelet �л��� ngr...
* 1 - �ȱ���org�ļĴ���ջ�����ģ�_greenlet_savecontext ���������Ҫ���ǵ���_greenlet_savecontext 
*     ǰ��eip����callָ�����ĵ�һ����pushl %eip��
* 2 - ���ۺ����ngr����ôִ�еģ�ogr���л�����ջ����, �Ĵ�����ֵͣ������ _greenlet_savecontext ����
*     _greenlet_savecontext�������е���Դ�ʱ�Ļ������������գ�
*     ע�⣺��ʹngr������savecontext�󣬻��ǻ����ִ�е�����β������ogr�Ļ���������ʵ��ͣ���� _greenlet_savecontext �����.
*          ������������Ҫ
* 3 - ���ngr���µ�greelet��ջδ��ʼ�������� _greenlet_newstack ���̣�����espָ��ngr��stack
*     Ȼ��ģ����� _greenlet_start��i��push������ii������ret�����ֱ������c��������Э��淶�е�callָ������ʵ�κ󱣴�eip������pushl $0
*     �Դˣ�_greenlet_start�Դ���ȫ�޸�֪��
* 4 - ���ngr��һ������ͣ����greelet����ʱ�൱���л���ȥ��_greenlet_switchcontext �������ǽ�֮ǰ���߲������
*     �������գ��ο�����2��ȡ������������ִ�У����� _greenlet_savecontext ʵ�ʻ᷵�����Σ�
*     ��һ���ǣ�������savecontext��Ȼ���������أ���ε��õ����þ��Ǳ��������Ŀ���
*     Ȼ��ogr�������У�eip��ʵ���ߵ�yfr_greenlet_switchβ����Ȼ��_greenlet_switchcontext�л���
*     �ڶ��Σ�ԭ����ogr�����ngr���� _greenlet_switchcontext ���ѣ������ʺϵ�ջ�����Ĵ�����ʵ����2����Ŀ��գ�������
*     _greenlet_savecontext ���棬Ȼ�󷵻�1����if�жϣ�����ֱ�ӷ���
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
        // �л���ogr ��ջ������Ĵ����Ѿ���ƥ�䣬���Ժ�����л�ֻ�ܻ��е� savecontext �Ǹ���������
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

