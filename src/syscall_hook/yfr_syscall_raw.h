#ifndef _YFR_SYSCALL_RAW_H_20150309_H
#define _YFR_SYSCALL_RAW_H_20150309_H
/*
* copyright@: kevin_zhong, mail:qq2000zhong@gmail.com
* time: 20150309-19:12:25
*/

#include "yfr_syscall.h"

extern yf_usleep_ret_t (*yfr_usleep)(unsigned int us);
extern unsigned int (*yfr_sleep)(unsigned int s);

extern int (*yfr_close)(int fd);
extern int (*yfr_shutdown)(int fd, int howto);

extern ssize_t (*yfr_read)(int fd, void *buf, size_t count);
extern ssize_t (*yfr_write)(int fd, const void *buf, size_t count);

extern ssize_t (*yfr_recvfrom)(int s, void *buf, size_t len, int flags,
                              struct sockaddr *from, socklen_t *fromlen);
extern ssize_t (*yfr_sendto)(int s, const void *buf, size_t len, int flags,
                            const struct sockaddr *to, socklen_t tolen);

extern ssize_t (*yfr_recvmsg)(int s, struct msghdr *msg, int flags);
extern ssize_t (*yfr_sendmsg)(int s, const struct msghdr *msg, int flags);

extern ssize_t (*yfr_readv)(int fd, const struct iovec *vector, int count);
extern ssize_t (*yfr_writev)(int fd, const struct iovec *vector, int count);

extern int (*yfr_socket)(int domain, int type, int protocol);
extern int (*yfr_connect)(int sockfd, const struct sockaddr *serv_addr, socklen_t addrlen);
extern int (*yfr_accept)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);

extern int (*yfr_fcntl)(int fd, int cmd, ...);

extern int (*yfr_getsockopt)(int sockfd, int level, int optname,
                            void *optval, socklen_t *optlen);
extern int (*yfr_setsockopt)(int s, int level, int optname,
                            const void *optval, socklen_t optlen);

extern struct hostent* (*yfr_gethostbyname)(const char *name);
extern int (*yfr_getaddrinfo)(const char *node, const char *service,
                             const struct addrinfo *hints,
                             struct addrinfo **res);

#ifdef  HAVE_SYS_SELECT_H
extern int (*yfr_select)(int nfds, fd_set *readfds, fd_set *writefds,
                        fd_set *exceptfds, struct timeval *timeout);
#endif

#ifdef  HAVE_POLL_H
extern int (*yfr_poll)(struct pollfd *fds, nfds_t nfds, int timeout);
#endif

#ifdef HAVE_GETHOSTBYNAME2
extern struct hostent* (*yfr_gethostbyname2)(const char *name, int af);
#endif

#ifdef HAVE_GETHOSTBYNAME_R
extern int (*yfr_gethostbyname_r)(const char *name,
                                 struct hostent *ret, char *buf, size_t buflen,
                                 struct hostent **result, int *h_errnop);
#endif

#ifdef HAVE_GETHOSTBYNAME2_R
extern int (*yfr_gethostbyname2_r)(const char *name, int af,
                                  struct hostent *ret, char *buf, size_t buflen,
                                  struct hostent **result, int *h_errnop);
#endif


#endif

