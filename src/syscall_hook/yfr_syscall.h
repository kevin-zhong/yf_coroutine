#ifndef _YFR_SYSCALL_H_20130227_H
#define _YFR_SYSCALL_H_20130227_H
/*
* copyright@: kevin_zhong, mail:qq2000zhong@gmail.com
* time: 20130227-18:11:36
*/

#include <yfr_head.h>
#include <bridge/yf_bridge.h>
#include <coroutine/yfr_coroutine.h>
#include "yfr_dlsym.h"
#include "yfr_ipc.h"

/*
* each coroutine mgr should call this
*/
yf_int_t  yfr_syscall_coroutine_attach(yfr_coroutine_mgr_t* mgr, yf_log_t* log);

#define  YFR_SYSCALL_SOCKET  0
#define  YFR_SYSCALL_DNS 1
#define  YFR_SYSCALL_IPC  2
#define  YFR_SYSCALL_SOCKET_EXT 3
#define  YFR_SYSCALL_POLL 4


yf_usleep_ret_t usleep(unsigned int us);
unsigned int sleep(unsigned int s);

/*
* note, socket can be operated by more than 1 coroutine at the same time
* the lock inside is very important
*/

int close(int fd);
int shutdown(int fd, int howto);

ssize_t read(int fd, void *buf, size_t count);
ssize_t write(int fd, const void *buf, size_t count);

/*
* if you want to read from or write into a socket continuity 
* with more than one sys api call,
* then you must lock it first, then you can call api freely, 
* after all call, you should unlock it...
* desc when: 2013/03/07 18:29
*/
#define YFR_SOCKET_READ_T 0
#define YFR_SOCKET_WRITE_T 1
#define YFR_SOCKET_RW_T 2

/*
* support lock>1 times by same coroutine, and should unlock
* the same times with lock
*/
yf_int_t  yfr_socket_lock(int fd, int rwtype);
yf_int_t  yfr_socket_unlock(int fd, int rwtype);

yf_int_t  yfr_socket_conn_tmset(int fd, yf_u32_t ms);

ssize_t recv(int s, void *buf, size_t len, int flags);
ssize_t send(int s, const void *buf, size_t len, int flags);

/*
* MSG_WAITALL ignored, support MSG_DONTWAIT
*/
ssize_t recvfrom(int s, void *buf, size_t len, int flags,
                struct sockaddr *from, socklen_t *fromlen);

ssize_t sendto(int s, const void *buf, size_t len, int flags, 
                const struct sockaddr *to, socklen_t tolen);

/*
* not impleted..
*/
ssize_t recvmsg(int s, struct msghdr *msg, int flags);
ssize_t sendmsg(int s, const struct msghdr *msg, int flags);

ssize_t readv(int fd, const struct iovec *vector, int count);
ssize_t writev(int fd, const struct iovec *vector, int count);

/*
* will recv or send required len if fd not shutdown or closed or timeout, ret==len
* else ret < len(fd have been shutdown or closed or timeout)
*/
ssize_t recvn(int s, void *buf, size_t len, int flags);
ssize_t sendn(int s, const void *buf, size_t len, int flags);
//note, if req_size!=NULL, then after ret, it's val=all required len
ssize_t writevn(int fd, const struct iovec *vector, int count, size_t* req_size);


int socket(int domain, int type, int protocol);
int connect(int sockfd, const struct sockaddr *serv_addr, socklen_t addrlen);
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);

int yfr_coroutine_open(int sockfd, int type);


int fcntl(int fd, int cmd, ...);
int setsockopt(int s, int level, int optname, 
                const void *optval, socklen_t optlen);

int ioctl(int fd, unsigned long int request, ...);

// ret=0, replaced syscall, otherwise will call org syscal
int yfr_ioctl_hook(int fd, unsigned long int request, ...);


/*
* select + poll...
*/
#ifdef  HAVE_SYS_SELECT_H
int select(int nfds, fd_set *readfds, fd_set *writefds,
                fd_set *exceptfds, struct timeval *timeout);
#endif
#ifdef  HAVE_POLL_H
int poll(struct pollfd *fds, nfds_t nfds, int timeout);
#endif

//utils func
void yfr_syscall_dns_hostent_cpy(struct hostent* rhost
                , char* rbuf, size_t buf_len, struct hostent* hret);

struct hostent* gethostbyname(const char *name);

#ifdef HAVE_GETHOSTBYNAME2
struct hostent* gethostbyname2(const char *name, int af);
#endif

#ifdef HAVE_GETHOSTBYNAME_R
int gethostbyname_r(const char *name,
       struct hostent *ret, char *buf, size_t buflen,
       struct hostent **result, int *h_errnop);
#endif

#ifdef HAVE_GETHOSTBYNAME2_R
int gethostbyname2_r(const char *name, int af,
       struct hostent *ret, char *buf, size_t buflen,
       struct hostent **result, int *h_errnop);
#endif

int getaddrinfo(const char *node, const char *service, 
               const struct addrinfo *hints, 
               struct addrinfo **res);


char* yfr_coroutine_log(char* buf, char* last, yf_uint_t level);


/*
* bridge syscall, res_data, res_len, input+output args
* if succes, ret 0, else -1
* just can be used in coroutine...
*/
yf_int_t yfr_process_bridge_task(yf_bridge_t* bridge
                , void* task, size_t len, yf_u32_t hash
                , yf_u32_t timeout_ms, void* res_data, size_t* res_len);


//bridge_ctx.data used by syscall, dont use it outside
yf_bridge_t* yfr_bridge_create(yf_bridge_cxt_t* bridge_ctx
                , yf_log_t* log);
yf_int_t  yfr_bridge_destory(yf_bridge_t* bridge, yf_log_t* log);

yf_int_t yfr_attach_res_bridge(yf_bridge_t* bridge
                , yf_evt_driver_t* evt_driver, yf_log_t* log);


#endif

