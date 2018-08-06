/*
 * @copyright: kevin_zhong on 2016/10/10
 */

#if defined(__WIN32__) || defined(__APPLE__)
# define cdecl(s) _##s
#else
# define cdecl(s) s
#endif

.extern int (*yf_ioctl)(int fd, unsigned long int request, ...);
.extern int yfr_ioctl_hook(int fd, unsigned long int request, ...);

.text

.globl cdecl(ioctl)

#if defined(__x86_64__)
/*
* TODO, if called with arg num>6, bug will appear...
*/
cdecl(ioctl):
    pushq %rdi
    pushq %rsi
    pushq %rdx
    pushq %rcx
    pushq %r8
    pushq %r9
    callq yfr_ioctl_hook
    popq %r9
    popq %r8
    popq %rcx
    popq %rdx
    popq %rsi
    popq %rdi
    test %eax,%eax
    je 1f
    callq *yf_ioctl
1:
    ret
 
#elif defined(__i386__)
/*
* TODO, bug still exists in 32byte machine...
*/
cdecl(ioctl):
    call yfr_ioctl_hook
    test %eax,%eax
    je 1f
    call *yf_ioctl
1:
    ret

#endif
