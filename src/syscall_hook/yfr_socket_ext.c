#include "yfr_socket_ext.h"
#include "yfr_syscall.h"

/*
* recv + write policy:
* recv: one tpd_fd just one recv coroutine that run on backgroud..
*       timeout - forever long, no time limit !
*       if error - then 
*               1) del tpd_fd from pool to protect from connecting or selecting
*               2) set r_close flag
*               3) shutdown fd's read way
*               4) sleep with send_tm..., cause maybe some coroutine writing+using tpd_fd's ctx
*               5) after all writing coroutine ends, close fd, destory tpd_fd's ctx, recollect tpd_fd
* write: maybe many coroutines use tpd_fd...
*       timeout - send_tm, default 16s
*       if error - then
*               1) del tpd_fd from pool to protect from connecting or selecting
*               2) set w_close flag
*               3) shutdown fd's write way
*
* still some questions: if write error, then shutdown, but read success always, 
*       then sockt other end dont close socket..., but if the other is yf socket, then no problem,
*       cause the other will read end, then close the socket, last all over
*/

const yf_str_t yfr_datagram_type_n[] = {
                yf_str("require_more"), yf_str("err_format"), 
                yf_str("request"), yf_str("response"), 
                yf_str("end")};

#define _YFR_SOCKET_EXT_ADDR_HASH 97
#define _YFR_SOCKET_EXT_UDP_MAX_DTSIZE (65536 * 2)

struct yfr_tdp_ctx_hash_s;

typedef struct _yfr_tdp_fd_ctx_s
{
        yf_fd_t                    fd;
        yf_u8_t                    rclose : 1;
        yf_u8_t                    wclose : 1;
        yf_u8_t                    rerr_datgram : 1;
        yf_u8_t                    rerr_read : 1;

        yf_u32_t                  send_coroutines;

        yf_u32_t                  recv_blockid;

        yfr_ipc_lock_t             locks[2];
        struct yfr_tdp_ctx_hash_s *tdp_ctx_hash;

        yfr_coroutine_t *          recv_coroutine;
        yfr_datagram_framer_t *   recv_framer;

        yf_circular_buf_t *        cic_buf;

        //just for udp 'accept'(not active connect)
        yf_sockaddr_storage_t *    addr_from;
        socklen_t                  addr_fromlen;

        yf_list_part_t    fd_linker;
}
_yfr_tdp_fd_ctx_t;


typedef struct _yfr_resp_wait_ctx_s
{
        yf_u32_t     wait_ms : 24;
        yf_u32_t     timeout : 1;
        yf_u32_t     resped : 1;
        yf_u32_t     block_id;
        yf_u64_t     wait_rid;
        yf_u64_t     req_id;
        yfr_tdp_fd_t resp_fd;
        yf_tm_evt_t *evt;
}
_yfr_resp_wait_ctx_t;


typedef struct _yfr_socket_ext_s
{
        yf_slist_part_t mltplx_addr_hash[_YFR_SOCKET_EXT_ADDR_HASH];
        yf_pool_t *      mem_pool;
        
        yf_node_pool_t   tdp_fd_pool;
        
        yf_hnpool_t *    resp_wait_ctx_pool;
        yf_64to32map_t * seq_64to32_map;
        
        yf_log_t *       log;
}
_yfr_socket_ext_t;

#define _yfr_tdp_get_ctx_fd(fd_ctx, se) yf_get_id_by_node(&(se)->tdp_fd_pool, fd_ctx, NULL)
#define _yfr_tdp_get_fd_ctx(se, fd, log) yf_get_node_by_id(&(se)->tdp_fd_pool, fd, log)


#define _YFR_SOCKET_RESP_REQ_MAX_MAP 32

yf_int_t  yfr_syscall_socket_ext_coroutine_attach(yfr_coroutine_mgr_t *mgr, yf_log_t *log)
{
        yf_u32_t i1 = 0;
        yfr_coroutine_init_t *ctx = yfr_coroutine_mgr_ctx2(mgr);
        yf_u32_t fds = yf_evt_driver_ctx(ctx->evt_driver)->nfds;
        yf_u32_t run_max = ctx->run_max_num;

        yf_u32_t tdpfd_taken_size = yf_node_taken_size(sizeof(_yfr_tdp_fd_ctx_t));

        _yfr_socket_ext_t *socket_ext = yf_alloc(sizeof(_yfr_socket_ext_t)
                                                 + tdpfd_taken_size * fds
                                                 + yf_64to32map_mem_len(run_max * _YFR_SOCKET_RESP_REQ_MAX_MAP));

        CHECK_RV(socket_ext == NULL, YF_ERROR);

        //fd pool
        socket_ext->tdp_fd_pool.each_taken_size = tdpfd_taken_size;
        socket_ext->tdp_fd_pool.total_num = fds;
        socket_ext->tdp_fd_pool.nodes_array
                        = yf_mem_off(socket_ext, sizeof(_yfr_socket_ext_t));
        yf_init_node_pool(&socket_ext->tdp_fd_pool, log);

        socket_ext->seq_64to32_map = yf_mem_off(socket_ext->tdp_fd_pool.nodes_array,
                                                tdpfd_taken_size * fds);

        yf_64to32map_init(socket_ext->seq_64to32_map,
                          run_max * _YFR_SOCKET_RESP_REQ_MAX_MAP, 0);
        /*
         * resp wait ctx pool
         */
        socket_ext->resp_wait_ctx_pool = yf_hnpool_create(sizeof(_yfr_resp_wait_ctx_t),
                                                          run_max, _YFR_SOCKET_RESP_REQ_MAX_MAP, log);
        assert(socket_ext->resp_wait_ctx_pool);

        //addr hash
        for (i1 = 0; i1 < _YFR_SOCKET_EXT_ADDR_HASH; i1++)
        {
                yf_init_slist_head(socket_ext->mltplx_addr_hash + i1);
        }

        //mem pool
        socket_ext->mem_pool = yf_create_pool(yf_pagesize, log);
        if (socket_ext->mem_pool == NULL)
        {
                yf_free(socket_ext);
                return YF_ERROR;
        }

        //log
        socket_ext->log = log;

        ctx->data[YFR_SYSCALL_SOCKET_EXT] = socket_ext;
        return YF_OK;
}


typedef struct yfr_tdp_ctx_hash_s
{
        yfr_coroutine_mgr_t *mgr;
        yf_u32_t  magic;

        yfr_tdp_ctx_t        ctx;

        yf_int_t             type; //SOCK_STREAM, SOCK_DGRAM
        yf_int_t             protocol;

        yf_u8_t              addrlen;
        yf_u8_t              is_accept : 1; //conn or accept
        yf_u8_t              framer_num : 3;//max=7

        yf_int_t              connected_num;

        yf_list_part_t     conn_list;
        yf_list_part_t*    used_conn;
        
        union {
                yfr_tdp_listen_ctx_t   listen_ctx;
                yfr_tdp_connect_ctx_t  connect_ctx;
        };

        //used for accept
        yfr_tdp_fd_t       accept_fd;

        //used for connect
        yf_u8_t              connecting : 1;
        
        yf_slist_part_t      linker;
}
yfr_tdp_ctx_hash_t;


#define _yfr_tdp_isstream(ctx_hash) ((ctx_hash)->type == SOCK_STREAM)
#define _yfr_tdp_isdgram(ctx_hash) ((ctx_hash)->type == SOCK_DGRAM)

#define _yfr_tdp_conn_hash_addr(h) yf_mem_off(h, sizeof(yfr_tdp_ctx_hash_t))
#define _yfr_tdp_conn_hash_len(addrlen, conn_num) (sizeof(yfr_tdp_ctx_hash_t) \
                                                   + yf_align_mem(addrlen))


extern int close_impl(int fd, yfr_coroutine_init_t *init_info, yfr_coroutine_t *r);

static void _yfr_resp_on_timeout(struct yf_tm_evt_s *evt, yf_time_t* start);

static yf_int_t _yfr_tdp_accept_coroutine_pfn(yfr_coroutine_t *r);
static yf_int_t _yfr_tdp_recv_coroutine_pfn(yfr_coroutine_t *r);
static void _yfr_tdp_on_rw_error(_yfr_tdp_fd_ctx_t *fd_ctx, int rwtype);
static void _yfr_tdp_recv_resp(yfr_coroutine_t *r, yf_u64_t resp_id);
static int _yfr_tdp_close(yfr_tdp_fd_t tdp_fd);

static yfr_tdp_ctx_hash_t* _yfr_tdp_init_conn_hash(const yfr_tdp_addr_t *addr
                             , const yfr_tdp_ctx_t *ctx, yfr_coroutine_mgr_t *mgr
                             , yf_int_t max_fds)
{
        yf_u32_t i1 = 0;
        yfr_coroutine_init_t *coroutine_initinfo = yfr_coroutine_mgr_ctx2(mgr);
        _yfr_socket_ext_t *sockext_ctx = coroutine_initinfo->data[YFR_SYSCALL_SOCKET_EXT];

        yf_u32_t hash_len = _yfr_tdp_conn_hash_len(
                                addr->addrlen, max_fds);
        yfr_tdp_ctx_hash_t *conn_hash = yf_palloc(sockext_ctx->mem_pool, hash_len);
        yf_memzero(conn_hash, hash_len);

        yf_set_magic(conn_hash->magic);

        conn_hash->mgr = mgr;
        conn_hash->protocol = addr->protocol;
        conn_hash->type = addr->type;
        conn_hash->addrlen = addr->addrlen;
        conn_hash->ctx = *ctx;
        if (ctx->send_tm == 0)
                conn_hash->ctx.send_tm = 16000;

        for ( i1 = 0; i1 < YFR_TDP_MAX_DECODERS ; i1++ )
        {
                if (ctx->framers[i1].detect == NULL)
                {
                        if (i1 == 0)
                                return NULL;
                        conn_hash->framer_num = i1;
                        break;
                }
        }
        if (conn_hash->framer_num == 0)
                conn_hash->framer_num = YFR_TDP_MAX_DECODERS;

        yf_init_list_head(&conn_hash->conn_list);
        conn_hash->used_conn = &conn_hash->conn_list;

        char* cret = yf_cpymem(_yfr_tdp_conn_hash_addr(conn_hash), 
                        &addr->addr, addr->addrlen);

        if (_yfr_tdp_isstream(conn_hash)) 
        {
                if (conn_hash->ctx.tcp_buf_chunk_size == 0)
                        conn_hash->ctx.tcp_buf_chunk_size = yf_pagesize * 64;
        }
        return  conn_hash;
}


static void _yfr_tdp_destory_fdctx(_yfr_tdp_fd_ctx_t* tfd_ctx
                , _yfr_socket_ext_t *sockext_ctx, yf_log_t* log)
{
        if (tfd_ctx->cic_buf)
        {
                yf_circular_buf_destory(tfd_ctx->cic_buf);
                yf_free(tfd_ctx->cic_buf);
        }
        if (tfd_ctx->fd >= 0)
                close(tfd_ctx->fd);

        //yf_lock_destory(&tfd_ctx->locks[0]);
        //yf_lock_destory(&tfd_ctx->locks[1]);
        yf_free_node_to_pool(&sockext_ctx->tdp_fd_pool, tfd_ctx, log);
}


static  _yfr_tdp_fd_ctx_t*  _yfr_tdp_create_fdctx(yfr_tdp_ctx_hash_t* conn_hash
                , yf_fd_t  fd, _yfr_socket_ext_t *sockext_ctx
                , yf_log_t* log)
{
        yf_utime_t  utime;
        _yfr_tdp_fd_ctx_t* tfd_ctx = yf_alloc_node_from_pool(&sockext_ctx->tdp_fd_pool, log);
        if (tfd_ctx == NULL)
                return NULL;

        yf_memzero(tfd_ctx, sizeof(_yfr_tdp_fd_ctx_t));
        tfd_ctx->fd = fd;
        tfd_ctx->tdp_ctx_hash = conn_hash;
        yfr_ipc_lock_init(&tfd_ctx->locks[0]);
        yfr_ipc_lock_init(&tfd_ctx->locks[1]);
        
        tfd_ctx->cic_buf = yf_alloc(sizeof(yf_circular_buf_t)
                                + (_yfr_tdp_isstream(conn_hash) ? 0 : sizeof(yf_sockaddr_storage_t)));
        if (tfd_ctx->cic_buf == NULL)
                goto nfailed;
        
        if (yf_circular_buf_init(tfd_ctx->cic_buf, _yfr_tdp_isstream(conn_hash) ? 
                                     conn_hash->ctx.tcp_buf_chunk_size : 
                                     _YFR_SOCKET_EXT_UDP_MAX_DTSIZE, log) != YF_OK)
                goto nfailed;

        if (_yfr_tdp_isdgram(conn_hash) && conn_hash->is_accept)
                tfd_ctx->addr_from = yf_mem_off(tfd_ctx->cic_buf, sizeof(yf_sockaddr_storage_t));

        if (_yfr_tdp_isstream(conn_hash))
        {
                //no cork, no delay, btw: they are not the same to each other
                yf_tcp_nocork(tfd_ctx->fd);
                int on = 0;
                if (setsockopt(tfd_ctx->fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(int)) != 0)
                {
                        yf_log_error(YF_LOG_WARN, log, yf_errno, "set tcp_nodelay failed");
                        //goto nfailed;
                }
        }

        yf_ms_2_utime(conn_hash->ctx.send_tm, &utime);
        if (setsockopt(tfd_ctx->fd, SOL_SOCKET, SO_SNDTIMEO, &utime, sizeof(utime)) != 0)
                goto nfailed;

        if (conn_hash->ctx.recv_buf_size)
        {
                if (yf_setsock_bufsize(tfd_ctx->fd, 1, 
                        yf_max(conn_hash->ctx.recv_buf_size, 1024*128), log) != 0)
                        goto nfailed;
        }
        if (conn_hash->ctx.send_buf_size)
        {
                if (yf_setsock_bufsize(tfd_ctx->fd, 0, 
                        yf_max(conn_hash->ctx.send_buf_size, 1024*128), log) != 0)
                        goto nfailed;
        }
        
        return tfd_ctx;
        
nfailed:
        _yfr_tdp_destory_fdctx(tfd_ctx, sockext_ctx, log);
        return NULL;
}



yfr_tdp_matrix* yfr_tdp_listen(const yfr_tdp_addr_t* addr
                                , const yfr_tdp_ctx_t* ctx, const yfr_tdp_listen_ctx_t* listen_ctx)
{
        if (addr->type != SOCK_STREAM && addr->type != SOCK_DGRAM)
                return NULL;
        
        yfr_coroutine_t *r = yfr_coroutine_addr(addr);
        if (!yfr_coroutine_check(r))
                return NULL;

        yfr_coroutine_mgr_t *mgr = yfr_coroutine_get_mgr(r);
        yfr_coroutine_init_t *coroutine_initinfo = yfr_coroutine_mgr_ctx2(mgr);
        _yfr_socket_ext_t *sockext_ctx = coroutine_initinfo->data[YFR_SYSCALL_SOCKET_EXT];
        yfr_tdp_ctx_hash_t *listen_hash = NULL;
        _yfr_tdp_fd_ctx_t *tfd_ctx = NULL;
        int flag = 1, accept_fd = 0;

        listen_hash = _yfr_tdp_init_conn_hash(addr, ctx, mgr, 1);
        CHECK_RV(listen_hash == NULL, NULL);
        if (listen_ctx)
                listen_hash->listen_ctx = *listen_ctx;

        accept_fd = socket(addr->addr.ss_family, addr->type, addr->protocol);
        if (accept_fd < 0)
        {
                return NULL;
        }

        listen_hash->accept_fd = accept_fd;
        tfd_ctx = _yfr_tdp_create_fdctx(listen_hash, accept_fd, sockext_ctx, r->log);

        if (setsockopt(tfd_ctx->fd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(int)) != 0)
        {
                yf_log_error(YF_LOG_WARN, r->log, yf_errno, "set reuseaddr failed");
                goto nfailed;
        }

        if (bind(tfd_ctx->fd, (yf_sock_addr_t*)&addr->addr, addr->addrlen) != 0)
        {
                yf_log_error(YF_LOG_WARN, r->log, yf_errno, "bind failed");
                goto nfailed;
        }
        
        if (_yfr_tdp_isdgram(listen_hash))
        {
                tfd_ctx->recv_coroutine = yfr_coroutine_sys_create(mgr,
                                                                   _yfr_tdp_recv_coroutine_pfn,
                                                                   tfd_ctx, sockext_ctx->log);
        }
        else {
                if (listen(tfd_ctx->fd, listen_ctx ? listen_ctx->backlog : 512) != 0)
                {
                        yf_log_error(YF_LOG_WARN, r->log, yf_errno, "listen failed");
                        goto nfailed;
                }
                tfd_ctx->recv_coroutine = yfr_coroutine_sys_create(mgr,
                                                                   _yfr_tdp_accept_coroutine_pfn,
                                                                   tfd_ctx, sockext_ctx->log);
        }

        if (tfd_ctx->recv_coroutine == NULL)
                goto nfailed;

        yf_list_add_tail(&tfd_ctx->fd_linker, &listen_hash->conn_list);
        listen_hash->connected_num++;
        return (yfr_tdp_matrix*)listen_hash;

nfailed:
        _yfr_tdp_destory_fdctx(tfd_ctx, sockext_ctx, r->log);
        return NULL;
}


yfr_tdp_matrix* yfr_tdp_connect(const yfr_tdp_addr_t *addr
                             , const yfr_tdp_ctx_t *ctx, const yfr_tdp_connect_ctx_t* connect_ctx)
{
        if (addr->type != SOCK_STREAM && addr->type != SOCK_DGRAM)
                return NULL;
        
        yfr_coroutine_t *r = yfr_coroutine_addr(addr);
        if (!yfr_coroutine_check(r))
                return NULL;

        yf_u32_t addrhash = addr->addrhash;
        if (addrhash == 0)
                addrhash = yf_sock_hash((yf_sock_addr_t*)&addr->addr);

        yfr_coroutine_mgr_t *mgr = yfr_coroutine_get_mgr(r);
        yfr_coroutine_init_t *coroutine_initinfo = yfr_coroutine_mgr_ctx2(mgr);
        _yfr_socket_ext_t *sockext_ctx = coroutine_initinfo->data[YFR_SYSCALL_SOCKET_EXT];
        yf_slist_part_t *pos, *head = sockext_ctx->mltplx_addr_hash +
                                                        addrhash % _YFR_SOCKET_EXT_ADDR_HASH;
        yfr_tdp_ctx_hash_t *conn_hash = NULL;

        yf_slist_for_each(pos, head)
        {
                conn_hash = container_of(pos, yfr_tdp_ctx_hash_t, linker);

                if (conn_hash->type == addr->type
                    && conn_hash->protocol == addr->protocol
                    && yf_sock_cmp((const yf_sock_addr_t *)&addr->addr,
                                   (const yf_sock_addr_t *)_yfr_tdp_conn_hash_addr(conn_hash)) == 0)
                {
                        return  (yfr_tdp_matrix*)conn_hash;
                }
        }

        yfr_tdp_connect_ctx_t tconnect_ctx = {16000, 2};
        if (connect_ctx)
        {
                if (connect_ctx->time_ms)
                        tconnect_ctx.time_ms = connect_ctx->time_ms;
                if (connect_ctx->max_connections)
                        tconnect_ctx.max_connections = connect_ctx->max_connections;
        }
        
        conn_hash = _yfr_tdp_init_conn_hash(addr, ctx, mgr, connect_ctx->max_connections);
        CHECK_RV(conn_hash == NULL, NULL);
        
        conn_hash->connect_ctx = tconnect_ctx;
        
        yf_slist_push(&conn_hash->linker, head);
        return (yfr_tdp_matrix*)conn_hash;
}


//select one connection
yfr_tdp_fd_t yfr_tdp_select(yfr_tdp_matrix* matrix)
{
        yfr_coroutine_t *r = yfr_coroutine_addr(matrix);
        if (!yfr_coroutine_check(r))
                return -1;
        
        yfr_coroutine_mgr_t *mgr = yfr_coroutine_get_mgr(r);
        yfr_coroutine_init_t *coroutine_initinfo = yfr_coroutine_mgr_ctx2(mgr);
        _yfr_socket_ext_t *sockext_ctx = coroutine_initinfo->data[YFR_SYSCALL_SOCKET_EXT];
        
        yfr_tdp_ctx_hash_t *conn_hash = (yfr_tdp_ctx_hash_t*)matrix;
        _yfr_tdp_fd_ctx_t *tfd_ctx = NULL;
        yf_fd_t  fdin = 0;
        yf_u32_t sleep_times = 0;
        yf_sockaddr_storage_t* sockaddr = NULL;
        yfr_tdp_fd_t  fdout = 0;

        if (!yf_check_magic(conn_hash->magic))
        {
                yf_log_error(YF_LOG_WARN, r->log, 0, 
                                "wrong magic=%d in hash", conn_hash->magic);
                return -1;
        }

        if (conn_hash->is_accept)
        {
                if (_yfr_tdp_isdgram(conn_hash))
                        return  conn_hash->accept_fd;

                //tcp accept
                goto use_exsist;
        }

        //tcp conn
        sockaddr = _yfr_tdp_conn_hash_addr(conn_hash);
        
        if (conn_hash->connecting
            || conn_hash->connected_num == conn_hash->connect_ctx.max_connections)
                goto use_exsist;

        fdin = socket(sockaddr->ss_family, conn_hash->type, conn_hash->protocol);
        if (fdin < 0)
                goto nfailed;
        tfd_ctx = _yfr_tdp_create_fdctx(conn_hash, fdin, sockext_ctx, r->log);
        if (tfd_ctx == NULL)
                goto nfailed;

        yfr_socket_conn_tmset(tfd_ctx->fd, conn_hash->connect_ctx.time_ms);
        conn_hash->connecting = 1;

        if (connect(tfd_ctx->fd, (const yf_sock_addr_t *)sockaddr, conn_hash->addrlen) < 0)
                goto nfailed;

        tfd_ctx->recv_coroutine = yfr_coroutine_sys_create(mgr,
                                                           _yfr_tdp_recv_coroutine_pfn,
                                                           tfd_ctx, sockext_ctx->log);
        if (tfd_ctx->recv_coroutine == NULL)
                goto nfailed;

        yf_list_add_tail(&tfd_ctx->fd_linker, &conn_hash->conn_list);
        conn_hash->connected_num++;
        conn_hash->connecting = 0;
        
        goto use_exsist;

nfailed:
        yf_log_error(YF_LOG_WARN, r->log, 0, 
                        "create new conn failed, use exsist in hash");
        conn_hash->connecting = 0;
        if (tfd_ctx)
                _yfr_tdp_destory_fdctx(tfd_ctx, sockext_ctx, r->log);

use_exsist:
        if (conn_hash->connected_num == 0)
        {
                if (conn_hash->connecting && sleep_times < 8)
                {
                        usleep(conn_hash->connect_ctx.time_ms << 7);//~=1000/8
                        ++sleep_times;
                        goto use_exsist;
                }
                else {
                        yf_log_error(YF_LOG_WARN, r->log, 0, "after try, still no connections");
                        return -1;
                }
        }

        conn_hash->used_conn = conn_hash->used_conn->next;
        if (conn_hash->used_conn == &conn_hash->conn_list)
                conn_hash->used_conn = conn_hash->used_conn->next;
        assert(conn_hash->used_conn != &conn_hash->conn_list);
        
        tfd_ctx = container_of(conn_hash->used_conn, _yfr_tdp_fd_ctx_t, fd_linker);
        fdout = _yfr_tdp_get_ctx_fd(tfd_ctx, sockext_ctx);
        
        yf_log_debug(YF_LOG_DEBUG, r->log, 0, "connect use tdp_fd=%L, fdin=%d", 
                        fdout, fdin);
        return  fdout;
}


void yfr_tdp_matrix_iter(yfr_tdp_matrix* matrix, yfr_tdp_matrix_iter_pt iter, void* arg)
{
        yfr_coroutine_t *r = yfr_coroutine_addr(matrix);
        if (!yfr_coroutine_check(r))
                return;

        yfr_coroutine_mgr_t *mgr = yfr_coroutine_get_mgr(r);
        yfr_coroutine_init_t *coroutine_initinfo = yfr_coroutine_mgr_ctx2(mgr);
        _yfr_socket_ext_t *sockext_ctx = coroutine_initinfo->data[YFR_SYSCALL_SOCKET_EXT];        
        
        yfr_tdp_ctx_hash_t *conn_hash = (yfr_tdp_ctx_hash_t*)matrix;
        _yfr_tdp_fd_ctx_t *fd_ctx, *fd_ctx_n;
        yfr_tdp_fd_t fdout;
        yf_int_t ret;
        
        yf_list_for_each_entry_safe(fd_ctx, fd_ctx_n, &conn_hash->conn_list, fd_linker)
        {
                fdout = _yfr_tdp_get_ctx_fd(fd_ctx, sockext_ctx);
                ret = iter(fdout, arg);
                if (ret == YF_ABORT)
                        break;
        }
}


yf_u64_t  yfr_tdp_reqid_alloc(yf_u32_t wait_ms, yf_int_t use32bit)
{
        yfr_coroutine_t *r = yfr_coroutine_addr(use32bit);

        if (!yfr_coroutine_check(r))
                return 0;

        yf_time_t time_out;
        yfr_coroutine_mgr_t *mgr = yfr_coroutine_get_mgr(r);
        yfr_coroutine_init_t *coroutine_initinfo = yfr_coroutine_mgr_ctx2(mgr);
        _yfr_socket_ext_t *sockext_ctx = coroutine_initinfo->data[YFR_SYSCALL_SOCKET_EXT];
        yf_u64_t id;
        _yfr_resp_wait_ctx_t *wait_ctx = yf_hnpool_alloc(
                                        sockext_ctx->resp_wait_ctx_pool, &id, r->log);
        if (wait_ctx == NULL)
        {
                yf_log_error(YF_LOG_WARN, r->log, 0, "alloc reqid failed");
                return 0;
        }

        yf_tm_evt_t *tm_evt = NULL;
        if (yf_alloc_tm_evt(coroutine_initinfo->evt_driver, &tm_evt, r->log) != YF_OK)
        {
                yf_hnpool_free(sockext_ctx->resp_wait_ctx_pool, id, wait_ctx, r->log);
                return 0;
        }
        if (wait_ms == 0)
                wait_ms = 1000 * 3600 * 2;

        yf_memzero(wait_ctx, sizeof(_yfr_resp_wait_ctx_t));
        
        wait_ctx->wait_ms = wait_ms;
        wait_ctx->wait_rid = r->id;
        wait_ctx->req_id = id;
        wait_ctx->block_id = 0;
        wait_ctx->evt = tm_evt;

        yf_ms_2_time(wait_ms, &time_out);
        tm_evt->data = wait_ctx;
        tm_evt->data4 = mgr;
        tm_evt->timeout_handler = _yfr_resp_on_timeout;
        yf_register_tm_evt(tm_evt, &time_out);

        if (unlikely(!use32bit))
                return id;

        yf_u32_t maped_id = yf_64to32map_map(sockext_ctx->seq_64to32_map, id);
        yf_log_debug(YF_LOG_DEBUG, r->log, 0, 
                        "alloc 64id=%L, mapto 32id=%d", id, maped_id);
        return maped_id;
}


//may timeout...
yf_int_t  yfr_tdp_wait_resp(yfr_datagram_ctx_t* datagram_ctx, yf_u64_t reqid)
{
        yfr_coroutine_t *r = yfr_coroutine_addr(datagram_ctx);

        if (!yfr_coroutine_check(r))
                return YF_ERROR;

        yfr_coroutine_mgr_t *mgr = yfr_coroutine_get_mgr(r);
        yfr_coroutine_init_t *coroutine_initinfo = yfr_coroutine_mgr_ctx2(mgr);
        _yfr_socket_ext_t *sockext_ctx = coroutine_initinfo->data[YFR_SYSCALL_SOCKET_EXT];
        _yfr_resp_wait_ctx_t *wait_ctx = NULL;
        _yfr_tdp_fd_ctx_t *fd_ctx = NULL, *fd_ctx_res = NULL;
        yf_int_t ret = YF_OK;

        yf_u64_t real_id = reqid;
        if (reqid <= UINT32_MAX)
                real_id = yf_64to32map_rmap(sockext_ctx->seq_64to32_map, reqid);

        if (real_id)
                wait_ctx = yf_hnpool_id2node(sockext_ctx->resp_wait_ctx_pool, real_id, r->log);

        if (wait_ctx == NULL)
        {
                yf_log_error(YF_LOG_WARN, r->log, 0,
                             "cant find reqid=%L, real_id=%L, maybe timeout already...", 
                             reqid, real_id);
                return YF_ERROR;
        }

        if (datagram_ctx->tdp_fd)
        {
                fd_ctx = _yfr_tdp_get_fd_ctx(sockext_ctx, datagram_ctx->tdp_fd, r->log);
                if (fd_ctx == NULL || fd_ctx->rclose)
                {
                        yf_log_error(YF_LOG_WARN, r->log, 0,
                                     "fd_ctx cant find or have closed, reqid=%L, tdp_fd=%L",
                                     wait_ctx->req_id, datagram_ctx->tdp_fd);
                        ret = YF_ERROR;
                        goto end;
                }
        }

        yf_log_debug(YF_LOG_DEBUG, r->log, 0, "wait resp seq=%L, tdp_fd=%L", 
                        reqid, datagram_ctx->tdp_fd);
        yfr_coroutine_block(r, &wait_ctx->block_id);

        //after resume by resp evt or timeout evt

        //may timeout and resp arrive on same evt loop, so must check...
        if (wait_ctx->timeout)
        {
                if (wait_ctx->resped)
                {
                        yf_log_debug(YF_LOG_DEBUG, r->log, 0, 
                                     "timeout+resp arrive on the same evt loop, reqid_out=%L, reqid_in=%L", 
                                     reqid, wait_ctx->req_id);
                }
                else {
                        yf_log_error(YF_LOG_WARN, r->log, 0,
                                     "wait resp timeout, reqid_out=%L, reqid_in=%L, tm_ms=%d",
                                     reqid, wait_ctx->req_id, wait_ctx->wait_ms);
                        ret = YF_ERROR;
                        goto  end;
                }
        }
        
        fd_ctx_res = _yfr_tdp_get_fd_ctx(sockext_ctx, wait_ctx->resp_fd, r->log);

        if (fd_ctx && fd_ctx_res && fd_ctx_res != fd_ctx)
        {
                yf_log_error(YF_LOG_WARN, r->log, 0,
                             "resp from other fd, reqid_out=%L, reqid_in=%L, req_fd=%L, resp_fd=%L",
                             reqid, wait_ctx->req_id, datagram_ctx->tdp_fd, wait_ctx->resp_fd);
                ret = YF_ERROR;
                goto  end;
        }

        fd_ctx = fd_ctx_res;
        if (fd_ctx)
        {
                datagram_ctx->tdp_fd = wait_ctx->resp_fd;
                datagram_ctx->cic_buf = fd_ctx->cic_buf;
                datagram_ctx->framer = fd_ctx->recv_framer;
                datagram_ctx->from = (struct sockaddr *)fd_ctx->addr_from;
                datagram_ctx->fromlen = fd_ctx->addr_fromlen;
        }
        else {  //fd closed
                yf_log_error(YF_LOG_WARN, r->log, 0,
                             "after resume, fd_ctx cant find or have closed, reqid_out=%L, reqid_in=%L, tdp_fd=%L",
                             reqid, wait_ctx->req_id, wait_ctx->resp_fd);
                ret = YF_ERROR;
        }

end:
        assert(wait_ctx->evt);
        yf_free_tm_evt(wait_ctx->evt);
        
        yf_hnpool_free(sockext_ctx->resp_wait_ctx_pool,
                       wait_ctx->req_id, wait_ctx, r->log);
        return ret;
}



static yf_int_t _yfr_tdp_accept_coroutine_pfn(yfr_coroutine_t *r)
{
        _yfr_tdp_fd_ctx_t *tfd_ctx = r->arg, *child_ctx = NULL;
        yfr_tdp_ctx_hash_t *ctx_hash = tfd_ctx->tdp_ctx_hash;
        yfr_coroutine_mgr_t *mgr = yfr_coroutine_get_mgr(r);
        yfr_coroutine_init_t *coroutine_initinfo = yfr_coroutine_mgr_ctx2(mgr);
        _yfr_socket_ext_t *sockext_ctx = coroutine_initinfo->data[YFR_SYSCALL_SOCKET_EXT];
        
        yf_sockaddr_storage_t  sock_addr;
        socklen_t  sock_len;
        int  accpet_fd, err, conn_new;
        yfr_tdp_fd_t  tdp_fd;

        yf_log_debug(YF_LOG_DEBUG, r->log, 0, "accept parent fd=%d", tfd_ctx->fd);

        while (1)
        {
                conn_new = 0;
                err = 1;
                accpet_fd = accept(tfd_ctx->fd, (yf_sock_addr_t*)&sock_addr, &sock_len);
                if (accpet_fd < 0)
                {
                        usleep(2048);
                        continue;
                }
                yf_log_debug(YF_LOG_DEBUG, r->log, 0, "accept new fd=%d", accpet_fd);

                if (ctx_hash->listen_ctx.max_connectors
                        && ctx_hash->connected_num >= ctx_hash->listen_ctx.max_connectors)
                {
                        yf_log_error(YF_LOG_WARN, r->log, 0, 
                                        "too many connectors=%d", ctx_hash->connected_num);
                        close(accpet_fd);
                        usleep(16384);
                        continue;
                }
                
                child_ctx = _yfr_tdp_create_fdctx(ctx_hash, accpet_fd, sockext_ctx, r->log);
                if (child_ctx == NULL)
                {
                        yf_log_error(YF_LOG_WARN, r->log, 0, 
                                        "create fdctx failed, connectors=%d", ctx_hash->connected_num);
                        close(accpet_fd);
                        usleep(8192);
                        continue;
                }
                
                tdp_fd = _yfr_tdp_get_ctx_fd(child_ctx, sockext_ctx);
                yf_log_debug(YF_LOG_DEBUG, r->log, 0, 
                                "map accepted new fd=%d->tdp_fd=%L", 
                                accpet_fd, tdp_fd);
                
                child_ctx->recv_coroutine = yfr_coroutine_sys_create(mgr,
                                                                   _yfr_tdp_recv_coroutine_pfn,
                                                                   child_ctx, sockext_ctx->log);
                if (child_ctx->recv_coroutine == NULL)
                        goto nfail;

                if (ctx_hash->listen_ctx.on_conn_new)
                {
                        if (ctx_hash->listen_ctx.on_conn_new(tdp_fd, 
                                        (const yf_sock_addr_t*)&sock_addr, sock_len) != YF_OK)
                        {
                                err = 0;
                                goto nfail;
                        }
                }
                
                conn_new = 1;
                
                ++ctx_hash->connected_num;
                continue;
                
nfail:
                if (conn_new && ctx_hash->listen_ctx.on_conn_delete)
                {
                        ctx_hash->listen_ctx.on_conn_delete(tdp_fd);
                }
                
                if (child_ctx->recv_coroutine)
                {
                        yfr_coroutine_cancel(child_ctx->recv_coroutine);
                }
                _yfr_tdp_destory_fdctx(child_ctx, sockext_ctx, r->log);
                if (err) 
                {
                        yf_log_error(YF_LOG_WARN, r->log, 0, "accept new fd, but init failed");
                        usleep(1024);
                }
        }
        
        return  YF_OK;
}


static yf_int_t _yfr_tdp_recv_sockdata(yfr_coroutine_t *r
        , yfr_tdp_ctx_hash_t *ctx_hash, _yfr_tdp_fd_ctx_t *tfd_ctx)
{
        yf_circular_buf_t* cic_buf = tfd_ctx->cic_buf;
        
        ssize_t recv_ret = 0;
        yf_s32_t buf_size = 0;
        yf_s32_t woffset = 0, wrest = 0;
        char* tcp_rbufs[2] = {NULL};
        char** _tcp_rbufs = tcp_rbufs;
        struct iovec read_vec[2];
        
        if (_yfr_tdp_isstream(ctx_hash))
        {
                //seek cursor to end
                yf_cb_fseek(cic_buf, 0, YF_SEEK_END);
                
                buf_size = yf_cb_space_write_alloc(cic_buf, cic_buf->buf_size, 
                                &_tcp_rbufs, &woffset);
                if (buf_size < 32)
                {
                        yf_log_error(YF_LOG_WARN, r->log, 0, 
                                        "alloc ret writable size too small, now bsize=%d", 
                                        yf_cb_fsize(cic_buf));
                        return YF_BUSY;
                }

                wrest = yf_min(buf_size, cic_buf->buf_size-woffset);
                assert(wrest);
                
                read_vec[0].iov_base = tcp_rbufs[0] + woffset;
                read_vec[0].iov_len = wrest;
                
                if (likely(wrest < buf_size))
                {
                        read_vec[1].iov_base = tcp_rbufs[1];
                        read_vec[1].iov_len = buf_size - wrest;
                }
                else
                        read_vec[1].iov_len = 0;
                
                recv_ret = readv(tfd_ctx->fd, read_vec, wrest<buf_size ? 2 : 1);

                yf_log_debug(YF_LOG_DEBUG, r->log, 0, "readv len=[%d,%d], recv ret=%d", 
                                read_vec[0].iov_len, read_vec[1].iov_len, 
                                recv_ret);
        }
        else {
                tfd_ctx->addr_fromlen = sizeof(yf_sockaddr_storage_t);

                recv_ret = recvfrom(tfd_ctx->fd, cic_buf->buf[0],
                                    _YFR_SOCKET_EXT_UDP_MAX_DTSIZE, 0,
                                    (yf_sock_addr_t*)tfd_ctx->addr_from, &tfd_ctx->addr_fromlen);
                
                yf_log_debug(YF_LOG_DEBUG, r->log, 0, "udp recv ret=%d, addrlen=%d", 
                                recv_ret, tfd_ctx->addr_from ? tfd_ctx->addr_fromlen : 0);
        }

        if (recv_ret <= 0) //closed or err
                return YF_ERROR;

        yf_cb_space_write_bytes(cic_buf, recv_ret);
        return  YF_OK;
}


static yf_int_t _yfr_tdp_recv_coroutine_pfn(yfr_coroutine_t *r)
{
        _yfr_tdp_fd_ctx_t *tfd_ctx = r->arg;
        yfr_tdp_ctx_hash_t *ctx_hash = tfd_ctx->tdp_ctx_hash;
        yfr_coroutine_init_t *coroutine_initinfo = yfr_coroutine_mgr_ctx(r);
        _yfr_socket_ext_t *sockext_ctx = coroutine_initinfo->data[YFR_SYSCALL_SOCKET_EXT];

        yfr_datagram_framer_t *tmp_framer = NULL;
        yf_int_t ret = 0, too_big = 0, detect_type = 0;
        yf_u64_t datagram_id = 0;
        yf_u8_t decode_flags[YFR_TDP_MAX_DECODERS] = { 0 };

        yfr_tdp_fd_t  tdp_fd = _yfr_tdp_get_ctx_fd(tfd_ctx, sockext_ctx);
        yfr_datagram_ctx_t  datagram_ctx = {tdp_fd, tfd_ctx->cic_buf, 
                                        NULL, NULL, (struct sockaddr *)tfd_ctx->addr_from, 0};

        yf_circular_buf_t* cic_buf = tfd_ctx->cic_buf;
        yf_u32_t i1 = 0;
        yf_s32_t last_tcpdt_cpos = 0, buf_size = 0;

        //some problems here, wait maybe too long, fd may used out...
#define __yfr_socket_rreror_handle \
                _yfr_tdp_on_rw_error(tfd_ctx, YFR_SOCKET_READ_T); \
                if (tfd_ctx->send_coroutines) { \
                        yf_log_debug(YF_LOG_DEBUG, r->log, 0, \
                                "fd=%l,tdp_fd=%L will close read way, still %d write coroutines", \
                                tfd_ctx->fd, tdp_fd, tfd_ctx->send_coroutines); \
                } \
                sleep(32); \
                while (tfd_ctx->send_coroutines) \
                        usleep(1000 * ctx_hash->ctx.send_tm); \
                _yfr_tdp_close(tdp_fd);

        if (_yfr_tdp_isstream(ctx_hash))
        {
                ret = yf_cb_space_enlarge(cic_buf, 
                                _YFR_SOCKET_EXT_UDP_MAX_DTSIZE);
                if (ret < _YFR_SOCKET_EXT_UDP_MAX_DTSIZE)
                {
                        yf_log_error(YF_LOG_WARN, r->log, 0,
                                     "to close, space enlarge failed, fd=%l,tdp_fd=%L", 
                                     tfd_ctx->fd, tdp_fd);
                        
                        __yfr_socket_rreror_handle;
                        return YF_OK;
                }
        }

        yf_log_debug(YF_LOG_DEBUG, sockext_ctx->log, 0, 
                        "recv begin, framer num=%d, fd=%l,tdp_fd=%L", 
                        ctx_hash->framer_num, tfd_ctx->fd, tdp_fd);

again:
        if (tfd_ctx->rerr_read)
        {
                if (_yfr_tdp_isdgram(ctx_hash) && ctx_hash->is_accept)
                {
                        yf_log_debug(YF_LOG_WARN, sockext_ctx->log, 0, 
                                        "accept udp read error, what? should ignore?");
                        tfd_ctx->rerr_read = 0;
                        assert(0);
                        yf_exit_with_sig(yf_signal_value(YF_SHUTDOWN_SIGNAL));
                }

                yf_log_error(YF_LOG_WARN, r->log, 0,
                             "to close, read err, fd=%l,tdp_fd=%L", 
                             tfd_ctx->fd, tdp_fd);

                __yfr_socket_rreror_handle;
                return YF_OK;
        }
        
        if (tfd_ctx->rerr_datgram) //udp ignore err datagram
        {
                yf_log_error(YF_LOG_WARN, sockext_ctx->log, 0, 
                                "datagram framer error");
                
                if (_yfr_tdp_isstream(ctx_hash))
                {
                        yf_log_error(YF_LOG_WARN, r->log, 0,
                                     "to close, frame err, fd=%l,tdp_fd=%L", 
                                     tfd_ctx->fd, tdp_fd);

                        __yfr_socket_rreror_handle;
                        return YF_OK;
                }
                tfd_ctx->rerr_datgram = 0;
        }
        
        yf_memzero_st(decode_flags);
        too_big = 0;

        if (_yfr_tdp_isstream(ctx_hash))
        {
                yf_cb_fhead_set(cic_buf, last_tcpdt_cpos);
                yf_cb_fseek(cic_buf, 0, YF_SEEK_END);
        }
        else {
                yf_circular_buf_reset(cic_buf);
        }
        yf_circular_buf_shrink(cic_buf, r->log);

read_more:
        yf_cb_fseek(cic_buf, 0, YF_SEEK_END);
        ret = _yfr_tdp_recv_sockdata(r, ctx_hash, tfd_ctx);
        
        if (ret != YF_OK)
        {
                tfd_ctx->rerr_read = 1;
                goto again;
        }
        
        buf_size = yf_cb_fsize(cic_buf);

        //reset seek for detect
        yf_cb_fseek(cic_buf, 0, YF_SEEK_SET);

        for (i1 = 0; i1 < ctx_hash->framer_num; i1++)
        {
                tmp_framer = ctx_hash->ctx.framers + i1;
                if (tmp_framer->min_head_len > buf_size
                    || decode_flags[i1] == YFR_DATAGRAM_WRONG_FORMAT)
                        continue;

                detect_type = tmp_framer->detect(cic_buf);

                //reset cursor
                yf_cb_fseek(cic_buf, 0, YF_SEEK_SET);
                
                switch (detect_type)
                {
                        case YFR_DATAGRAM_REQUIRE_MORE:
                                break;
                        case YFR_DATAGRAM_WRONG_FORMAT:
                                decode_flags[i1] = detect_type;
                                break;
                        case YFR_DATAGRAM_REQ:
                        case YFR_DATAGRAM_RESP:
                                goto new_datagram;
                }
        }

        if (_yfr_tdp_isdgram(ctx_hash))
        {
                yf_log_error(YF_LOG_WARN, r->log, 0,
                             "sock dgram detect all fail, fd=%l,tdp_fd=%L", tfd_ctx->fd, tdp_fd);
                goto again;
        }

        //tcp
        for (i1 = 0; i1 < ctx_hash->framer_num; i1++)
        {
                if (decode_flags[i1] == YFR_DATAGRAM_REQUIRE_MORE)
                        goto read_more;
        }

        yf_log_error(YF_LOG_WARN, r->log, 0,
                     "sock stream detect all fail, fd=%l,tdp_fd=%L", tfd_ctx->fd, tdp_fd);

        tfd_ctx->rerr_datgram = 1;
        goto again;

new_datagram:
        tfd_ctx->recv_framer = tmp_framer;

        //scan
        datagram_ctx.scan_ctx = tmp_framer->create_scan_ctx(cic_buf->mpool);
        assert(datagram_ctx.scan_ctx);
        
        //reset seek for scan
        yf_cb_fseek(cic_buf, 0, YF_SEEK_SET);
        ret = tmp_framer->scan(cic_buf, datagram_ctx.scan_ctx, &datagram_id);
        
        if (_yfr_tdp_isstream(ctx_hash))
        {
                while (ret == YFR_DATAGRAM_REQUIRE_MORE)
                {
                        //record the last scanned pos
                        yf_cb_fseek(cic_buf, 0, YF_SEEK_END);
                        last_tcpdt_cpos = yf_cb_ftell(cic_buf);

                        //read more data
                        ret = _yfr_tdp_recv_sockdata(r, ctx_hash, tfd_ctx);
                        if (ret != YF_OK)
                        {
                                if (ret == YF_BUSY)
                                {
                                        //drop readed buf, just to continue...
                                        yf_circular_buf_reset(cic_buf);
                                        too_big = 1;
                                        ret = YFR_DATAGRAM_REQUIRE_MORE;
                                        continue;
                                }
                                else {
                                        tfd_ctx->rerr_read = 1;
                                        goto again;
                                }
                        }
                        //seek to last scan pos, and scan the buf just readed newly
                        yf_cb_fseek(cic_buf, last_tcpdt_cpos, YF_SEEK_SET);
                        ret = tmp_framer->scan(cic_buf, datagram_ctx.scan_ctx, &datagram_id);
                }

                if (ret != YFR_DATAGRAM_END)
                {
                        tfd_ctx->rerr_datgram = 1;
                        goto again;
                }
                last_tcpdt_cpos = yf_cb_ftell(cic_buf);

                if (too_big) 
                {
                        yf_log_error(YF_LOG_WARN, r->log, 0,
                                     "sock stream recv too long msg, fd=%l,tdp_fd=%L", tfd_ctx->fd, tdp_fd);
                        goto again;
                }
        }
        else if (ret != YFR_DATAGRAM_END)
        {
                yf_log_error(YF_LOG_WARN, r->log, 0,
                             "sock dgram scan udp datagram ret fail, fd=%l,tdp_fd=%L", 
                             tfd_ctx->fd, tdp_fd);
                goto again;
        }

        //reset seek for process
        yf_cb_fseek(cic_buf, 0, YF_SEEK_SET);

        yf_log_debug(YF_LOG_DEBUG, r->log, 0, 
                        "recv datagram{type=%V, id=%L, alllen=%d}, tdp_fd=%L", 
                        &yfr_datagram_type_n[detect_type], 
                        datagram_id, last_tcpdt_cpos, 
                        tdp_fd);
        
        //process
        if (detect_type == YFR_DATAGRAM_RESP)
        {
                _yfr_tdp_recv_resp(r, datagram_id);
        }
        else {
                if (ctx_hash->ctx.on_req)
                {
                        datagram_ctx.fromlen = tfd_ctx->addr_fromlen;
                        datagram_ctx.framer = tmp_framer;
                        ret = ctx_hash->ctx.on_req(&datagram_ctx);
                        if (ret == YF_BUSY)
                        {
                                yfr_coroutine_block(r, &tfd_ctx->recv_blockid);
                        }
                        else //next datagram
                                ;
                }
                else {
                        yf_log_error(YF_LOG_WARN, r->log, 0,
                                     "no on_req handle, fd=%l, req datagram droped", tfd_ctx->fd);
                }
        }
        goto again;
}


static void _yfr_tdp_recv_resp(yfr_coroutine_t *r, yf_u64_t resp_id)
{
        _yfr_tdp_fd_ctx_t *tfd_ctx = r->arg;
        yfr_coroutine_mgr_t *mgr = tfd_ctx->tdp_ctx_hash->mgr;
        _yfr_socket_ext_t *sockext_ctx = yfr_coroutine_mgr_ctx2(mgr)->data[YFR_SYSCALL_SOCKET_EXT];

        _yfr_resp_wait_ctx_t *wait_ctx = NULL;
        yfr_coroutine_t *rbiz = NULL;
        yf_u64_t tdid = resp_id;

        if (resp_id <= UINT32_MAX)
        {
                tdid = yf_64to32map_rmap(sockext_ctx->seq_64to32_map, resp_id);
                if (tdid == 0)
                {
                        yf_log_error(YF_LOG_WARN, r->log, 0,
                                     "cant find 32bit resp_id=%L's rmap, overwited...", resp_id);
                        return;
                }
        }
        wait_ctx = yf_hnpool_id2node(sockext_ctx->resp_wait_ctx_pool,
                                     tdid, r->log);
        if (wait_ctx == NULL)
        {
                yf_log_error(YF_LOG_WARN, r->log, 0,
                             "cant find resp_id=%L's wait ctx, may timeout...", tdid);
                return;
        }

        assert(wait_ctx->req_id == tdid);
        wait_ctx->resp_fd = _yfr_tdp_get_ctx_fd(tfd_ctx, sockext_ctx);
        wait_ctx->resped = 1;

        rbiz = yfr_coroutine_getby_id(mgr, wait_ctx->wait_rid);
        
        if (yfr_coroutine_resume(rbiz, wait_ctx->block_id) == 0)
        {
                yfr_coroutine_block(r, &tfd_ctx->recv_blockid);
        }
        else {
                yf_log_error(YF_LOG_WARN, r->log, 0, 
                                "resp arrive but cant match resp waiting ctx, reqid_in=%L, idout=%L", 
                                resp_id, tdid);
        }
}


static void _yfr_tdp_on_rw_error(_yfr_tdp_fd_ctx_t *tfd_ctx, int rwtype)
{
        yfr_tdp_ctx_hash_t *ctx_hash = tfd_ctx->tdp_ctx_hash;
        yfr_coroutine_mgr_t *mgr = tfd_ctx->tdp_ctx_hash->mgr;
        yfr_coroutine_init_t *coroutine_initinfo = yfr_coroutine_mgr_ctx2(mgr);
        _yfr_socket_ext_t *sockext_ctx = coroutine_initinfo->data[YFR_SYSCALL_SOCKET_EXT];

        if (_yfr_tdp_isdgram(ctx_hash) && ctx_hash->is_accept)
        {
                yf_log_debug(YF_LOG_WARN, sockext_ctx->log, 0, 
                                "accept udp rwtype=%d error, what? just ignore", rwtype);
                return;
        }

        if (rwtype == YFR_SOCKET_READ_T)
        {
                if (tfd_ctx->rclose)
                        return;

                //destroy cic buf
                yf_circular_buf_destory(tfd_ctx->cic_buf);
                yf_free(tfd_ctx->cic_buf);

                shutdown(tfd_ctx->fd, SHUT_RD);
                tfd_ctx->rclose = 1;
        }
        else if (rwtype == YFR_SOCKET_WRITE_T)
        {
                if (tfd_ctx->wclose)
                        return;

                shutdown(tfd_ctx->fd, SHUT_WR);
                tfd_ctx->wclose = 1;
        }

        if (!tfd_ctx->rclose || !tfd_ctx->wclose)
        {
                //delete from conn pool to protect from reuse again
                assert(ctx_hash->connected_num);
                --ctx_hash->connected_num;
                yf_log_debug(YF_LOG_DEBUG, sockext_ctx->log, 0, 
                                "rw error, type=%d, delete from conn pool, rest conn num=%d", 
                                rwtype, ctx_hash->connected_num);
                
                if (ctx_hash->used_conn == &tfd_ctx->fd_linker)
                        ctx_hash->used_conn = ctx_hash->used_conn->next;
                
                yf_list_del(&tfd_ctx->fd_linker);
        }
}


static void _yfr_resp_on_timeout(struct yf_tm_evt_s *evt, yf_time_t* start)
{
        _yfr_resp_wait_ctx_t *wait_ctx = evt->data;
        yfr_coroutine_mgr_t *mgr = evt->data4;
        _yfr_socket_ext_t *sockext_ctx = yfr_coroutine_mgr_ctx2(mgr)
                                         ->data[YFR_SYSCALL_SOCKET_EXT];
        yfr_coroutine_t *r = NULL;

        if (wait_ctx->block_id == 0)
        {
                yf_free_tm_evt(evt);
                fprintf(stderr, "[warn] block id==0, you should wait after alloc\n");
                yf_hnpool_free(sockext_ctx->resp_wait_ctx_pool,
                               wait_ctx->req_id, wait_ctx, NULL);
                return;
        }

        wait_ctx->timeout = 1;

        r = yfr_coroutine_getby_id(mgr, wait_ctx->wait_rid);
        if (r) {
                if (yfr_coroutine_resume(r, wait_ctx->block_id) == 0)
                {
                        yf_log_error(YF_LOG_DEBUG, r->log, 0, 
                                        "wait resp=%L timeout, rid=%L", 
                                        wait_ctx->req_id, r->id);
                }
                else {
                        yf_log_error(YF_LOG_WARN, r->log, 0, 
                                        "wait resp=%L timeout, but cant match waiting ctx", 
                                        wait_ctx->req_id);
                }
        }
}


void  yfr_tdp_recv_next(yfr_tdp_fd_t tdp_fd)
{
        yfr_coroutine_t *r = yfr_coroutine_addr(tdp_fd);
        if (!yfr_coroutine_check(r))
                return;

        yfr_coroutine_mgr_t *mgr = yfr_coroutine_get_mgr(r);
        yfr_coroutine_init_t *coroutine_initinfo = yfr_coroutine_mgr_ctx2(mgr);
        _yfr_socket_ext_t *sockext_ctx = coroutine_initinfo->data[YFR_SYSCALL_SOCKET_EXT];
        yf_int_t ret = YF_OK;
        _yfr_tdp_fd_ctx_t *fd_ctx = _yfr_tdp_get_fd_ctx(
                                sockext_ctx, tdp_fd, r->log);
        
        if (fd_ctx == NULL)
        {
                yf_log_error(YF_LOG_WARN, r->log, 0, "cant find tdp_fd=%L", tdp_fd);
                return;
        }
        if (fd_ctx->recv_blockid == 0)
        {
                yf_log_error(YF_LOG_WARN, r->log, 0, "tdp_fd=%L not blocked", tdp_fd);
                return;
        }

        ret = yfr_coroutine_resume(fd_ctx->recv_coroutine, fd_ctx->recv_blockid);
        assert(ret == YF_OK);
        fd_ctx->recv_blockid = 0;
}



static int _yfr_tdp_close(yfr_tdp_fd_t tdp_fd)
{
        yfr_coroutine_t *r = yfr_coroutine_addr(tdp_fd);
        if (!yfr_coroutine_check(r))
                return YF_ERROR;

        yfr_coroutine_mgr_t *mgr = yfr_coroutine_get_mgr(r);
        yfr_coroutine_init_t *coroutine_initinfo = yfr_coroutine_mgr_ctx2(mgr);
        _yfr_socket_ext_t *sockext_ctx = coroutine_initinfo->data[YFR_SYSCALL_SOCKET_EXT];
        _yfr_tdp_fd_ctx_t *fd_ctx = _yfr_tdp_get_fd_ctx(
                                sockext_ctx, tdp_fd, r->log);

        if (fd_ctx == NULL)
        {
                yf_log_error(YF_LOG_WARN, r->log, 0, "cant find tdp_fd=%L", tdp_fd);
                return YF_ERROR;
        }

        assert(fd_ctx->send_coroutines == 0);
        
        //close this fd and clear
        yf_log_debug(YF_LOG_DEBUG, r->log, 0, "close tdp_fd=%L,fd=%d, rclose=%d, wclose=%d", 
                tdp_fd, fd_ctx->fd, fd_ctx->rclose, fd_ctx->wclose);
        
        //cause rclose&wclose, shutdown all, so no need to close again
        if (!fd_ctx->rclose || !fd_ctx->wclose)
                close_impl(fd_ctx->fd, coroutine_initinfo, r);
        fd_ctx->fd = 0;

        //yf_lock_destory(&fd_ctx->locks[0]);
        //yf_lock_destory(&fd_ctx->locks[1]);
        yf_free_node_to_pool(&sockext_ctx->tdp_fd_pool, fd_ctx, NULL);
        
        return YF_OK;
}


yf_int_t  yfr_tdp_send(yfr_tdp_fd_t tdp_fd, const void *buf, size_t len
                        , const struct sockaddr *to, socklen_t tolen)
{
        yfr_coroutine_t *r = yfr_coroutine_addr(tdp_fd);
        if (!yfr_coroutine_check(r))
                return YF_ERROR;

        yfr_coroutine_mgr_t *mgr = yfr_coroutine_get_mgr(r);
        yfr_coroutine_init_t *coroutine_initinfo = yfr_coroutine_mgr_ctx2(mgr);
        _yfr_socket_ext_t *sockext_ctx = coroutine_initinfo->data[YFR_SYSCALL_SOCKET_EXT];
        _yfr_tdp_fd_ctx_t *fd_ctx = _yfr_tdp_get_fd_ctx(
                                sockext_ctx, tdp_fd, r->log);
        ssize_t  send_ret;
        yf_int_t  rret = YF_OK;

        if (fd_ctx->wclose)
        {
                yf_log_error(YF_LOG_WARN, r->log, 0, "tdp_fd=%L,fd=%d write closed", 
                                tdp_fd, fd_ctx->fd);
                return YF_ERROR;
        }

        if (yfr_socket_lock(fd_ctx->fd, YFR_SOCKET_WRITE_T) != YF_OK)
        {
                yf_log_error(YF_LOG_WARN, r->log, 0, "tdp_fd=%L write lock", tdp_fd);
                return YF_ERROR;
        }
        
        fd_ctx->send_coroutines++;

        if (_yfr_tdp_isdgram(fd_ctx->tdp_ctx_hash))
        {
                if (fd_ctx->tdp_ctx_hash->is_accept)
                {
                        send_ret = sendto(fd_ctx->fd, buf, len, 0, to, tolen);
                }
                else {
                        send_ret = send(fd_ctx->fd, buf, len, 0);
                }
        }
        else {
                send_ret = sendn(fd_ctx->fd, buf, len, 0);
        }

        if (send_ret != len)
        {
                yf_log_error(YF_LOG_WARN, r->log, 0, 
                                "tdp_fd=%L,fd=%d send ret=%d != request_len=%d", 
                                tdp_fd, fd_ctx->fd, send_ret, len);
                
                _yfr_tdp_on_rw_error(fd_ctx, YFR_SOCKET_WRITE_T);
                
                rret = YF_ERROR;
        }
        else {
                yf_log_debug(YF_LOG_DEBUG, r->log, 0, 
                                "tdp_fd=%L,fd=%d send=%d, ret=%d", 
                                tdp_fd, fd_ctx->fd, len, send_ret);
        }

        fd_ctx->send_coroutines--;
        yfr_socket_unlock(fd_ctx->fd, YFR_SOCKET_WRITE_T);
        
        return rret;
}


yf_int_t  yfr_tdp_sendv(yfr_tdp_fd_t tdp_fd, const struct iovec *vector, int count)
{
        yfr_coroutine_t *r = yfr_coroutine_addr(tdp_fd);
        if (!yfr_coroutine_check(r))
                return YF_ERROR;

        yfr_coroutine_mgr_t *mgr = yfr_coroutine_get_mgr(r);
        yfr_coroutine_init_t *coroutine_initinfo = yfr_coroutine_mgr_ctx2(mgr);
        _yfr_socket_ext_t *sockext_ctx = coroutine_initinfo->data[YFR_SYSCALL_SOCKET_EXT];
        _yfr_tdp_fd_ctx_t *fd_ctx = _yfr_tdp_get_fd_ctx(
                                sockext_ctx, tdp_fd, r->log);
        ssize_t  send_ret = 0;
        size_t  req_size = 0;
        yf_int_t  rret = YF_OK;

        if (fd_ctx == NULL)
        {
                yf_log_error(YF_LOG_WARN, r->log, 0, "tdp_fd=%L unexsist anymore", tdp_fd);
                return YF_ERROR;
        }
        if (fd_ctx->wclose)
        {
                yf_log_error(YF_LOG_WARN, r->log, 0, "tdp_fd=%L write closed", tdp_fd);
                return YF_ERROR;
        }

        if (yfr_socket_lock(fd_ctx->fd, YFR_SOCKET_WRITE_T) != YF_OK)
        {
                yf_log_error(YF_LOG_WARN, r->log, 0, "tdp_fd=%L write lock", tdp_fd);
                return YF_ERROR;
        }
        
        fd_ctx->send_coroutines++;

        if (_yfr_tdp_isdgram(fd_ctx->tdp_ctx_hash))
        {
                if (fd_ctx->tdp_ctx_hash->is_accept)
                {
                        yf_log_error(YF_LOG_WARN, r->log, 0, 
                                        "tdp_fd=%L is accept datagram, cant use sendv", tdp_fd);
                        rret = YF_ERROR;
                        goto end;
                }
                else {
                        req_size = 0;
                        int i1 = 0;
                        for (i1 = 0; i1 < count; ++i1)
                                req_size += vector[i1].iov_len;

                        send_ret = writev(fd_ctx->fd, vector, count);
                }
        }
        else {
                send_ret = writevn(fd_ctx->fd, vector, count, &req_size);
        }

        if (send_ret != req_size)
        {
                yf_log_error(YF_LOG_WARN, r->log, 0, 
                                "tdp_fd=%L,fd=%d send ret=%d != request_len=%d", 
                                tdp_fd, fd_ctx->fd, send_ret, req_size);
                
                _yfr_tdp_on_rw_error(fd_ctx, YFR_SOCKET_WRITE_T);
                
                rret = YF_ERROR;
        }
        else {
                yf_log_debug(YF_LOG_DEBUG, r->log, 0, 
                                "tdp_fd=%L,fd=%d send=%d, ret=%d", 
                                tdp_fd, fd_ctx->fd, req_size, send_ret);
        }

end:
        fd_ctx->send_coroutines--;
        yfr_socket_unlock(fd_ctx->fd, YFR_SOCKET_WRITE_T);
        
        return rret;        
}


/*
 * 64->32 map
 */
yf_int_t yf_64to32map_init(yf_64to32map_t *intmap
                           , yf_u32_t capacity, yf_u32_t seed_val)
{
        if (capacity < 4)
                return YF_ERROR;
        intmap->capacity = capacity;
        intmap->last_index = 0;
        intmap->seed_val = seed_val ? seed_val : yf_now_times.clock_time.tv_sec;
        intmap->last_val = intmap->seed_val;

        yf_memzero(intmap->data, capacity * sizeof(yf_u64_t));
        return YF_OK;
}

yf_u32_t yf_64to32map_map(yf_64to32map_t *intmap
                          , yf_u64_t src)
{
        if (intmap->last_index == intmap->capacity - 1)
                intmap->last_index = 0;
        else
                intmap->last_index++;

        if (intmap->last_val >= UINT32_MAX)
                intmap->last_val = intmap->seed_val;
        else
                intmap->last_val++;

        intmap->data[intmap->last_index] = src;
        return intmap->last_val;
}

//ret 0  if not found
yf_u64_t yf_64to32map_rmap(yf_64to32map_t *intmap
                           , yf_u32_t dst)
{
        yf_s32_t diff = (yf_s32_t)intmap->last_val - (yf_s32_t)dst, src_index;

        if (diff < 0 || intmap->capacity <= diff)
                return 0;

        src_index = (yf_s32_t)intmap->last_index - diff;
        if (src_index < 0)
                return intmap->data[src_index + intmap->capacity];
        else
                return intmap->data[src_index];
}

