#include "yfr_syscall_raw.h"

yf_usleep_ret_t (*yfr_usleep)(unsigned int us) = usleep;
unsigned int (*yfr_sleep)(unsigned int s) = sleep;

int (*yfr_close)(int fd) = close;
int (*yfr_shutdown)(int fd, int howto) = shutdown;

ssize_t (*yfr_read)(int fd, void *buf, size_t count) = read;
ssize_t (*yfr_write)(int fd, const void *buf, size_t count) = write;

ssize_t (*yfr_recvfrom)(int s, void *buf, size_t len, int flags,
                       struct sockaddr *from, socklen_t *fromlen) = recvfrom;
ssize_t (*yfr_sendto)(int s, const void *buf, size_t len, int flags,
                     const struct sockaddr *to, socklen_t tolen) = sendto;

ssize_t (*yfr_recvmsg)(int s, struct msghdr *msg, int flags) = recvmsg;
ssize_t (*yfr_sendmsg)(int s, const struct msghdr *msg, int flags) = sendmsg;

ssize_t (*yfr_readv)(int fd, const struct iovec *vector, int count) = readv;
ssize_t (*yfr_writev)(int fd, const struct iovec *vector, int count) = writev;

int (*yfr_socket)(int domain, int type, int protocol) = socket;
int (*yfr_connect)(int sockfd, const struct sockaddr *serv_addr, socklen_t addrlen) = connect;
int (*yfr_accept)(int sockfd, struct sockaddr *addr, socklen_t *addrlen) = accept;

int (*yfr_fcntl)(int fd, int cmd, ...) = fcntl;

int (*yfr_getsockopt)(int sockfd, int level, int optname,
                     void *optval, socklen_t *optlen) = getsockopt;
int (*yfr_setsockopt)(int s, int level, int optname,
                     const void *optval, socklen_t optlen) = setsockopt;

struct hostent* (*yfr_gethostbyname)(const char *name) = gethostbyname;
int (*yfr_getaddrinfo)(const char *node, const char *service,
                      const struct addrinfo *hints,
                      struct addrinfo **res) = getaddrinfo;

#ifdef  HAVE_SYS_SELECT_H
int (*yfr_select)(int nfds, fd_set *readfds, fd_set *writefds,
                 fd_set *exceptfds, struct timeval *timeout) = select;
#endif

#ifdef  HAVE_POLL_H
int (*yfr_poll)(struct pollfd *fds, nfds_t nfds, int timeout) = poll;
#endif

#ifdef HAVE_GETHOSTBYNAME2
struct hostent* (*yfr_gethostbyname2)(const char *name, int af) = gethostbyname2;
#endif

#ifdef HAVE_GETHOSTBYNAME_R
int (*yfr_gethostbyname_r)(const char *name,
                          struct hostent *ret, char *buf, size_t buflen,
                          struct hostent **result, int *h_errnop) = gethostbyname_r;
#endif

#ifdef HAVE_GETHOSTBYNAME2_R
int (*yfr_gethostbyname2_r)(const char *name, int af,
                           struct hostent *ret, char *buf, size_t buflen,
                           struct hostent **result, int *h_errnop) = gethostbyname2_r;
#endif


