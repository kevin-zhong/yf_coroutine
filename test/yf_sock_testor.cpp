#include <algorithm>

extern "C" {
#include <coroutine/yfr_coroutine.h>
#include <syscall_hook/yfr_syscall.h>
#include <syscall_hook/yfr_dlsym.h>
#include <syscall_hook/yfr_ipc.h>
#include <syscall_hook/yfr_socket_ext.h>
#include <log_ext/yf_log_file.h>
}


yf_pool_t *_mem_pool;
yf_log_t* _log;
yf_evt_driver_t *_evt_driver = NULL;
yfr_coroutine_mgr_t* _test_coroutine_mgr = NULL;

yfr_tdp_addr_t  _test_tdp_addr[4];
yfr_tdp_matrix* _test_matrix[4];

yf_s32_t  _test_query_cnt = 0, _test_resp_cnt = 0, _test_max_query = 0;

//protocal
struct _test_sock_head
{
        yf_u32_t  magic;
        yf_u32_t  type;
        yf_u32_t  seq;
        yf_u32_t  body_len;
};

yf_u32_t  _test_req_type = 0x1, _test_resp_type = 0x81;


//ret detect datagram status= 0|1|2|3
yf_int_t _test_sock_detect(yf_circular_buf_t* cic_buf)
{
        _test_sock_head*  tmp_head = NULL;
        yf_u32_t ret = yf_cb_fread(cic_buf, sizeof(_test_sock_head), 0, (char**)&tmp_head);
        if (ret < sizeof(_test_sock_head) || !yf_check_magic(tmp_head->magic))
        {
                fprintf(stderr, "read ret=%d, magic=%d\n", ret, tmp_head ? tmp_head->magic : 0);
                return  YFR_DATAGRAM_WRONG_FORMAT;
        }

        fprintf(stdout, "datagram type=%d\n", tmp_head->type);
        return (tmp_head->type & 0x80) ? YFR_DATAGRAM_RESP : YFR_DATAGRAM_REQ;
}

struct _test_sock_scan_ctx
{
        yf_u32_t  body_len;
        yf_u32_t  read_len;
};

void* _test_sock_create_scan_ctx(yf_pool_t* pool)
{
        return yf_pcalloc(pool, sizeof(_test_sock_scan_ctx));
}

//just scan, status=0|1|4
//if the end, cursor must at the datagram end pos
yf_int_t _test_sock_scan(yf_circular_buf_t* cic_buf, void* decode_ctx, yf_u64_t* id)
{
        _test_sock_scan_ctx* scan_ctx = (_test_sock_scan_ctx*)decode_ctx;
        if (scan_ctx->body_len == 0)
        {
                _test_sock_head*  tmp_head = NULL;
                yf_u32_t ret = yf_cb_fread(cic_buf, sizeof(_test_sock_head), 
                                0, (char**)&tmp_head);
                assert(ret == sizeof(_test_sock_head));
                scan_ctx->body_len = tmp_head->body_len;

                *id = tmp_head->seq;
        }
        if (scan_ctx->body_len == 0)
                return YFR_DATAGRAM_END;

        yf_int_t ret;
        yf_u32_t readable_len = yf_circular_buf_rest_rsize(cic_buf);
        if (scan_ctx->body_len <= readable_len + scan_ctx->read_len)
        {
                ret = yf_cb_fseek(cic_buf, scan_ctx->body_len - scan_ctx->read_len, YF_SEEK_CUR);
                assert(ret == YF_OK);
                return YFR_DATAGRAM_END;
        }

        ret = yf_cb_fseek(cic_buf, 0, YF_SEEK_END);
        assert(ret == YF_OK);
        scan_ctx->read_len += readable_len;
        return  YFR_DATAGRAM_REQUIRE_MORE;
}

yfr_tdp_ctx_t _test_sock_ctx;
yfr_datagram_framer_t  _test_sock_framer = {5, sizeof(_test_sock_head), 
                _test_sock_detect, 
                _test_sock_create_scan_ctx, 
                _test_sock_scan};

#define _TEST_SOCK_WAIT_RESP_MS  6000

//test biz
yf_int_t _test_sock_coroutine_client(yfr_coroutine_t* r)
{
        char* send_buf = (char*)malloc(yf_pagesize*128 + sizeof(_test_sock_head));

        _test_sock_head*  req_head = (_test_sock_head*)send_buf, *resp_head;
        send_buf += sizeof(_test_sock_head);
        
        yf_set_magic(req_head->magic);
        req_head->type = _test_req_type;

        yfr_datagram_ctx_t  resp_datagram_ctx;
        
        while (_test_query_cnt < _test_max_query)
        {
                int choice = yf_mod(random(), 2);//just test STREAM
                
                yfr_tdp_fd_t fdout = yfr_tdp_select(_test_matrix[choice]);
                if (fdout < 0)
                {
                        fprintf(stderr, "choice=%d, select fdout failed\n", choice);
                        continue;
                }
                resp_datagram_ctx.tdp_fd = fdout;
                
                yf_u64_t reqid = yfr_tdp_reqid_alloc(_TEST_SOCK_WAIT_RESP_MS, 1);
                if (reqid == 0)
                {
                        fprintf(stderr, "alloc reqid failed\n");
                        sleep(yf_mod(random(), 8));
                        continue;
                }
                
                yf_u32_t body_len = yf_mod(random(), yf_pagesize*128);
                yf_memset(send_buf, yf_mod(random(), 128), body_len);

                req_head->seq = reqid;
                req_head->body_len = body_len;

                yf_int_t ret = yfr_tdp_send(fdout, 
                                req_head, body_len+sizeof(_test_sock_head), NULL, 0);
                if (ret != YF_OK)
                {
                        fprintf(stderr, "choice=%d, send req blen=%d failed\n", choice, body_len);
                        sleep(yf_mod(random(), 8));
                        continue;
                }

                ++_test_query_cnt;
                ret = yfr_tdp_wait_resp(&resp_datagram_ctx, reqid);
                ++_test_resp_cnt;
                if (ret != YF_OK)
                {
                        fprintf(stderr, "choice=%d, recv req=%d blen=%d resp failed\n", 
                                        choice, (int)reqid, body_len);
                        sleep(yf_mod(random(), 8));
                        continue;
                }

                fprintf(stdout, "choice=%d, recv resp=%d, blen=%d\n", 
                                choice, (int)reqid, body_len);

                resp_head = NULL;
                yf_s32_t read_len = yf_cb_fread(resp_datagram_ctx.cic_buf, 
                                sizeof(_test_sock_head), 
                                0, (char**)&resp_head);
                assert(resp_head->type == _test_resp_type);
                assert(resp_head->body_len == req_head->body_len);

                //very important !!
                yfr_tdp_recv_next(fdout);
        }
        
        free(req_head);
}

yf_int_t _test_sock_client(yfr_coroutine_t* r)
{
        yfr_tdp_connect_ctx_t  connect_ctx = {6000, 4};
        yf_u32_t i1 = 0;
        for ( i1 = 0; i1 < YF_ARRAY_SIZE(_test_tdp_addr); i1++ )
        {
                _test_matrix[i1] = yfr_tdp_connect(_test_tdp_addr+i1, 
                                &_test_sock_ctx, &connect_ctx);
                assert(_test_matrix[i1]);
        }

        yfr_coroutine_t* rchild = NULL;
        for (int i = 0; i < yf_min(256, _test_max_query); ++i)
        {
                rchild = yfr_coroutine_create(_test_coroutine_mgr, 
                                _test_sock_coroutine_client, NULL, _log);
                assert(rchild);
        }
        
        return YF_OK;
}


yf_bridge_t*  _test_bridge;


yf_int_t  _test_sock_coroutine_svr(yfr_coroutine_t* r)
{
        yfr_datagram_ctx_t* datagram_ctx = (yfr_datagram_ctx_t*)r->arg;
        
        assert(datagram_ctx->framer->id == _test_sock_framer.id);
        _test_sock_head *req_head = NULL, *resp_head = NULL;

        yf_s32_t read_len = yf_cb_fread(datagram_ctx->cic_buf, 
                        sizeof(_test_sock_head), 
                        0, (char**)&req_head);
        assert(read_len && req_head->type == _test_req_type);

        resp_head = (_test_sock_head*)malloc(req_head->body_len + sizeof(_test_sock_head));
        *resp_head = *req_head;
        resp_head->type = _test_resp_type;
        
        char* resp_buf = (char*)yf_mem_off(resp_head, sizeof(_test_sock_head));
        if (resp_head->body_len)
        {
                char* req_buf = NULL;
                read_len = yf_cb_fread(datagram_ctx->cic_buf, 
                                resp_head->body_len, 0, &req_buf);
                assert(read_len == resp_head->body_len);
                yf_memcpy(resp_buf, req_buf, resp_head->body_len);
        }

        yf_sockaddr_storage_t  req_addr;
        socklen_t req_addlen = 0;
        if (datagram_ctx->from)
        {
                yf_memcpy(&req_addr, datagram_ctx->from, datagram_ctx->fromlen);
                req_addlen = datagram_ctx->fromlen;
        }

        yfr_tdp_fd_t  fd_req = datagram_ctx->tdp_fd;
        
        //very important !!
        yfr_tdp_recv_next(fd_req);

        yf_log_debug(YF_LOG_DEBUG, _log, 0, "recv req=%d len=%d before process", 
                        resp_head->seq, resp_head->body_len);

        //send to biz thread
        void* test_resp_head = NULL;
        size_t  res_len = sizeof(void*);
        yf_int_t pres = yfr_process_bridge_task(_test_bridge, &resp_head, sizeof(void*), 
                        0, 3000, &test_resp_head, &res_len);
        if (pres != YF_OK)
        {
                fprintf(stderr, "bridge task process failed...req=%d len=%d\n", 
                                resp_head->seq, resp_head->body_len);
                yf_free(resp_head);
                return YF_OK;
        }
        assert(test_resp_head == resp_head);
        assert(res_len == sizeof(void*));

        yf_log_debug(YF_LOG_DEBUG, _log, 0, "recv req=%d len=%d after process", 
                        resp_head->seq, resp_head->body_len);
        yf_u32_t sleep_ms = random() % (_TEST_SOCK_WAIT_RESP_MS);
        usleep(sleep_ms * 1000);
        yf_log_debug(YF_LOG_DEBUG, _log, 0, "req=%d len=%d deal with sleep=%d ms", 
                        resp_head->seq, resp_head->body_len, sleep_ms);

        yf_int_t  send_ret;
        if (req_addlen == 0)
        {
                struct iovec iov[2];
                iov[0].iov_base = resp_head;
                iov[0].iov_len = sizeof(_test_sock_head);
                iov[1].iov_base = resp_buf;
                iov[1].iov_len = resp_head->body_len;         
                send_ret = yfr_tdp_sendv(fd_req, iov, 2);
        }
        else {
                send_ret = yfr_tdp_send(fd_req, resp_head, 
                                sizeof(_test_sock_head) + resp_head->body_len, 
                                (yf_sock_addr_t*)&req_addr, req_addlen);
        }

        yf_log_debug(YF_LOG_DEBUG, _log, 0, "send resp ret=[%d], req=%d, len=%d, sleep=%d\n", 
                        send_ret, resp_head->seq, resp_head->body_len, sleep_ms);
        
        fprintf(send_ret==YF_OK ? stdout : stderr, 
                        "send resp ret=[%d], req=%d, len=%d, sleep=%d\n", 
                        send_ret, resp_head->seq, resp_head->body_len, sleep_ms);
        
        yf_free(resp_head);
        return YF_OK;
}


yf_int_t  _test_on_req(yfr_datagram_ctx_t* datagram_ctx)
{
        yfr_coroutine_t* r = yfr_coroutine_create(_test_coroutine_mgr, 
                        _test_sock_coroutine_svr, 
                        datagram_ctx, _log);
        if (r == NULL)
        {
                fprintf(stderr, "coroutine pool used out\n");
                return YF_AGAIN;
        }
        return YF_BUSY;
}


yf_int_t _test_on_conn(yfr_tdp_fd_t tdp_fd
                , const struct sockaddr *addr, socklen_t addrlen)
{
        return  YF_OK;
}

void _test_on_task_fparent(yf_bridge_t* bridge
                , void* task, size_t len, yf_u64_t id, yf_log_t* log)
{
        while (yf_send_task_res(bridge, task, len, id, 0, log) != YF_OK)
        {
                fprintf(stderr, "send task res to parent failed, try again\n");
                usleep(4000);
        }
        
        if (random() % 8 == 0) 
        {
                int ms = yf_mod(random(), 512);
                usleep(ms * 1000);
                yf_update_time(NULL, NULL, log);
                yf_log_debug(YF_LOG_DEBUG, log, 0, 
                                "task=%L process with sleep ms=%d", id, ms);
        }
}

yf_thread_value_t _test_thread_exe(void *arg)
{
        yf_bridge_t* bridge = (yf_bridge_t*)arg;

        yf_int_t ret = yf_attach_bridge(bridge, NULL, _test_on_task_fparent, _log);
        assert(ret == YF_OK);
        
        while (1)
        {
                yf_poll_task(bridge, _log);
        }
        return NULL;
}


yf_int_t _test_sock_svr(yfr_coroutine_t* r)
{
        _test_sock_ctx.on_req = _test_on_req;
        
        yfr_tdp_listen_ctx_t  listen_ctx = {256, 64, _test_on_conn, NULL};
        yf_u32_t i1 = 0;
        for ( i1 = 0; i1 < YF_ARRAY_SIZE(_test_tdp_addr); i1++ )
        {
                _test_matrix[i1] = yfr_tdp_listen(_test_tdp_addr+i1, 
                                &_test_sock_ctx, &listen_ctx);
                assert(_test_matrix[i1]);
        }

        yf_bridge_cxt_t bridge_ctx = {YF_BRIDGE_INS_PROC, 
                        YF_BRIDGE_INS_THREAD,
                        YF_BRIDGE_EVT_DRIVED,
                        YF_BRIDGE_BLOCKED,
                        YF_TASK_DISTPATCH_IDLE,
                        (void*)_test_thread_exe, 
                        4, 10240, 800, 1024 * 1024
                };
        _test_bridge = yfr_bridge_create(&bridge_ctx, _log);
        assert(_test_bridge);
        yf_int_t ret = yfr_attach_res_bridge(_test_bridge, _evt_driver, _log);
        assert(ret == YF_OK);
        
        
        return  YF_OK;
}

//poll
void _test_on_client_poll(yf_evt_driver_t* evt_driver, void* data, yf_log_t* log)
{
        if (_test_resp_cnt >= _test_max_query 
                && _test_query_cnt == _test_resp_cnt)
        {
                fprintf(stdout, "test end, should exit from evt poll\n");
                yf_evt_driver_stop(evt_driver);
                return;
        }
        yfr_coroutine_schedule(_test_coroutine_mgr);
}

void _test_on_svr_poll(yf_evt_driver_t* evt_driver, void* data, yf_log_t* log)
{
        yfr_coroutine_schedule(_test_coroutine_mgr);
}


yf_time_t  _test_stack_watch_tm;

void _test_coroutine_stack_watch_handle(struct yf_tm_evt_s* evt, yf_time_t* start)
{
        yf_u32_t  min_percent = yfr_coroutine_stack_check(_log, 120);
        
        printf("coroutine stack left percent=%d/%d\n", 
                        min_percent, YFR_COROUTINE_STACK_WATCH_SPLIT);
        
        yf_register_tm_evt(evt, &_test_stack_watch_tm);
}


static int _test_sock_main(int argc, char **argv, yf_int_t is_client)
{
        yf_u32_t i1 = 0;
        srandom(time(NULL));
        yf_pagesize = getpagesize();
        printf("pagesize=%d\n", yf_pagesize);

        yf_cpuinfo();

        yf_int_t ret = yfr_syscall_init();
        assert(ret == YF_OK);

        //first need init threads before init log file
        ret = yf_init_threads(36, 1024 * 1024, 1, NULL);
        assert(ret == YF_OK);
        
        yf_log_file_init(NULL);
        yf_log_file_init_ctx_t log_file_init = {1024*128, 1024*1024*64, 8, 
                        is_client ? "log/sock_client.log" : "log/sock_svr.log", 
                        "%t [%f:%l]-[%v]-[%d-%r]"};

        _log = yf_log_open(YF_LOG_DEBUG, 8192, (void*)&log_file_init);
        
        _mem_pool = yf_create_pool(102400, _log);

        yf_init_bit_indexs();

        yf_init_time(_log);
        yf_update_time(NULL, NULL, _log);

        ret = yf_strerror_init();
        assert(ret == YF_OK);

        ret = yf_save_argv(_log, argc, argv);
        assert(ret == YF_OK);

        ret = yf_init_setproctitle(_log);
        assert(ret == YF_OK);

        ret = yf_init_processs(_log);
        assert(ret == YF_OK);

        yf_evt_driver_init_t driver_init = {0, 
                        128, 1024, _log, YF_DEFAULT_DRIVER_CB};
        
        driver_init.poll_cb = is_client ? _test_on_client_poll : _test_on_svr_poll;
        
        _evt_driver = yf_evt_driver_create(&driver_init);
        assert(_evt_driver != NULL);
        yf_log_file_flush_drive(_evt_driver, 5000, NULL);

        //ignore SIGPIPE signal
        yf_set_sig_handler(SIGPIPE, SIG_IGN, _log);

        //init global coroutine set
        ret = yfr_coroutine_global_set(1024, 4096*8, 0, _log);
        assert(ret == 0);
        
        //init coroutine _test_coroutine_mgr
        yfr_coroutine_init_t init_info = {1024, 128, 64, _evt_driver};
        _test_coroutine_mgr = yfr_coroutine_mgr_create(&init_info, _log);
        assert(_test_coroutine_mgr);

        yfr_syscall_coroutine_attach(_test_coroutine_mgr, _log);

        //should after mgr created
        yf_log_file_add_handle(_log, 'r', yfr_coroutine_log);

        //add coroutine stack watch timer
        yf_tm_evt_t* tm_evt = NULL;
        yf_alloc_tm_evt(_evt_driver, &tm_evt, _log);
        tm_evt->timeout_handler = _test_coroutine_stack_watch_handle;
        yf_ms_2_time(16000, &_test_stack_watch_tm);
        yf_register_tm_evt(tm_evt, &_test_stack_watch_tm);        

        //protocal
        yf_memzero_st(_test_sock_ctx);
        _test_sock_ctx.framers[0] = _test_sock_framer;

        //addr
        yfr_tdp_addr_init(_test_tdp_addr, AF_INET, SOCK_STREAM, 
                        0, "127.0.0.1", 9090);
        assert(_test_tdp_addr->addrlen > 0);
        yfr_tdp_unixaddr_init(_test_tdp_addr+1, AF_LOCAL, SOCK_STREAM, 
                        0, "log/tcp_conn.sock");
        yfr_tdp_addr_init(_test_tdp_addr+2, AF_INET, SOCK_DGRAM, 
                        0, "127.0.0.1", 9090);
        yfr_tdp_unixaddr_init(_test_tdp_addr+3, AF_LOCAL, SOCK_DGRAM, 
                        0, "log/udp_conn.sock");
        return ret;
}


int main(int argc, char **argv)
{
        int choice = atoi(argv[1]);
        int ret = _test_sock_main(argc, argv, choice);
        if (choice)
        {
                _test_max_query = choice;
                yfr_coroutine_create(_test_coroutine_mgr, 
                                _test_sock_client, NULL, _log);
        }
        else
        {
                yfr_coroutine_create(_test_coroutine_mgr, 
                                _test_sock_svr, NULL, _log);
        }

        yf_evt_driver_start(_evt_driver);

        fprintf(stdout, "test exit\n");
        return ret;
}
