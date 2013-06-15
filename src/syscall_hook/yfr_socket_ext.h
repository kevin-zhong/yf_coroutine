#ifndef _YFR_SOCKET_EXT_H_20130314_H
#define _YFR_SOCKET_EXT_H_20130314_H
/*
* copyright@: kevin_zhong, mail:qq2000zhong@gmail.com
* time: 20130314-19:20:58
*/

#include <yfr_head.h>
#include "yfr_syscall.h"


typedef  yf_s64_t  yfr_tdp_fd_t;

#define YFR_DATAGRAM_REQUIRE_MORE 0
#define YFR_DATAGRAM_WRONG_FORMAT 1
#define YFR_DATAGRAM_REQ  2
#define YFR_DATAGRAM_RESP 3
#define YFR_DATAGRAM_END 4

extern const yf_str_t yfr_datagram_type_n[];

typedef struct yfr_datagram_framer_s
{
        yf_u16_t  id:4;//max=15
        yf_u16_t  min_head_len;

        //ret detect datagram status= 0|1|2|3
        yf_int_t (*detect)(yf_circular_buf_t* cic_buf);

        void* (*create_scan_ctx)(yf_pool_t* pool);
        //just scan, status=0|1|4
        //if the end, cursor must at the datagram end pos
        yf_int_t (*scan)(yf_circular_buf_t* cic_buf, void* decode_ctx, yf_u64_t* id);
}
yfr_datagram_framer_t;


//cautions, after call next_recv, cant be used anymore
typedef struct yfr_datagram_ctx_s
{
        yfr_tdp_fd_t  tdp_fd;

        //raw data include all(head,body...)
        yf_circular_buf_t* cic_buf;
        void* scan_ctx;
        
        yfr_datagram_framer_t* framer;
        
        struct sockaddr* from;
        socklen_t           fromlen;
}
yfr_datagram_ctx_t;


#define  YFR_TDP_MAX_DECODERS  4

typedef struct yfr_tdp_ctx_s
{
        yfr_datagram_framer_t  framers[YFR_TDP_MAX_DECODERS];

        yf_u16_t send_tm;
        yf_u32_t recv_buf_size;//kb, if==0, use default
        yf_u32_t send_buf_size;//kb, if==0, use default
        
        //just for tcp
        yf_u32_t  tcp_buf_chunk_size;

        //if == NULL, req datagram droped
        //this called by recv coroutine
        //ret YF_BUSY=recved dt processing; else YF_OK dt droped or no need to process;
        yf_int_t  (*on_req)(yfr_datagram_ctx_t* datagram_ctx);
}
yfr_tdp_ctx_t;


typedef struct yfr_tdp_addr_s
{
        int type; //SOCK_STREAM, SOCK_DGRAM
        int protocol;
        
        yf_sockaddr_storage_t  addr;
        socklen_t  addrlen;
        yf_u32_t   addrhash;
}
yfr_tdp_addr_t;

#define yfr_tdp_addr_init(tdpaddr, _domain, _type, _protocal, ip, port) do { \
        (tdpaddr)->type = _type; \
        (tdpaddr)->protocol = _protocal; \
        (tdpaddr)->addr.ss_family = _domain; \
        yf_sock_set_addr((yf_sock_addr_t*)&(tdpaddr)->addr, ip); \
        yf_sock_set_port((yf_sock_addr_t*)&(tdpaddr)->addr, port); \
        (tdpaddr)->addrlen = yf_sock_len((yf_sock_addr_t*)&(tdpaddr)->addr); \
} while (0)

#define yfr_tdp_unixaddr_init(tdpaddr, _domain, _type, _protocal, path) do { \
        (tdpaddr)->type = _type; \
        (tdpaddr)->protocol = _protocal; \
        (tdpaddr)->addr.ss_family = _domain; \
        yf_sock_set_addr((yf_sock_addr_t*)&(tdpaddr)->addr, path); \
        (tdpaddr)->addrlen = yf_sock_len((yf_sock_addr_t*)&(tdpaddr)->addr); \
} while (0)


typedef struct yfr_tdp_listen_ctx_s
{
        int  backlog;
        int  max_connectors;//if==0, no limit
        
        yf_int_t (*on_conn_new)(yfr_tdp_fd_t tdp_fd
                        , const struct sockaddr *addr, socklen_t addrlen);
        void (*on_conn_delete)(yfr_tdp_fd_t tdp_fd);
}
yfr_tdp_listen_ctx_t;


typedef struct yfr_tdp_connect_ctx_s
{
        //if==0, forever
        yf_u16_t time_ms;
        yf_u8_t   max_connections;
}
yfr_tdp_connect_ctx_t;

/*
* matrix, just can be called in coroutine
* this name is so bt...ÖÐÎÄ·­Òë-Ä¸Ìå...hehe
*/
#define yfr_tdp_matrix yf_u64_t

yfr_tdp_matrix* yfr_tdp_listen(const yfr_tdp_addr_t* addr
                        , const yfr_tdp_ctx_t* ctx, const yfr_tdp_listen_ctx_t* listen_ctx);

//udp must connect also...
yfr_tdp_matrix* yfr_tdp_connect(const yfr_tdp_addr_t* addr
                        , const yfr_tdp_ctx_t* ctx, const yfr_tdp_connect_ctx_t* connect_ctx);

//select one connection
yfr_tdp_fd_t yfr_tdp_select(yfr_tdp_matrix* matrix);

//iter all, ret YF_OK, YF_ABORT
typedef  yf_int_t (*yfr_tdp_matrix_iter_pt)(yfr_tdp_fd_t fd, void* arg);
void yfr_tdp_matrix_iter(yfr_tdp_matrix* matrix, yfr_tdp_matrix_iter_pt iter, void* arg);

yf_int_t yfr_tdp_close(yfr_tdp_matrix* matrix);


/*
* you should wait req|resp, after ret success, you can call recv
* else if you call recv directly without wait, will ret -1 directly
* in fact, in udp, datagram just recv once, so no need to call recv
*/
//may timeout...
//if *tdp_fd == 0, resp from any fds all right, else just the same fd
yf_int_t  yfr_tdp_wait_resp(yfr_datagram_ctx_t* datagram_ctx, yf_u64_t reqid);

//just can be called by coroutine
void  yfr_tdp_recv_next(yfr_tdp_fd_t tdp_fd);
/*
* send
*/
//fail,ret==0, else>0
yf_u64_t  yfr_tdp_reqid_alloc(yf_u32_t wait_ms, yf_int_t use32bit);

//ret YF_OK or YF_SUCCESS
yf_int_t  yfr_tdp_send(yfr_tdp_fd_t tdp_fd, const void *buf, size_t len
                        , const struct sockaddr *to, socklen_t tolen);
yf_int_t  yfr_tdp_sendv(yfr_tdp_fd_t tdp_fd, const struct iovec *vector, int count);

//TODO, send_req with arg=reqid
//yfr_tdp_send_req()
//yfr_tdp_resp_req()...


/*
* helpers
*/
typedef struct yf_64to32map_s
{
        yf_u32_t  last_index;
        yf_u32_t  last_val;
        yf_u32_t  capacity;
        yf_u32_t  seed_val;
        yf_u64_t  data[1];
}
yf_64to32map_t;

#define yf_64to32map_mem_len(capacity) (4*sizeof(yf_u32_t) + capacity * sizeof(yf_u64_t))

yf_int_t yf_64to32map_init(yf_64to32map_t* intmap
                , yf_u32_t capacity, yf_u32_t seed_val);
yf_u32_t yf_64to32map_map(yf_64to32map_t* intmap
                , yf_u64_t src);
//ret 0  if not found
yf_u64_t yf_64to32map_rmap(yf_64to32map_t* intmap
                , yf_u32_t dst);

#endif

