#include <gtest/gtest.h>
#include <list>
#include <vector>
#include <algorithm>

#ifdef  HAVE_UCONTEXT_H
#include <ucontext.h>
#endif

extern "C" {
#include <coroutine/yfr_coroutine.h>
#include <coroutine/yfr_greenlet.h>
#include <syscall_hook/yfr_syscall.h>
#include <syscall_hook/yfr_dlsym.h>
#include <syscall_hook/yfr_ipc.h>
#include <log_ext/yf_log_file.h>

}
extern "C" int _greenlet_savecontext(void***);
extern "C" void _greenlet_fcall_end();

#define _ASSERT(r) if (!(r)) {printf("_ASSERT failed: " #r "\n"); yf_exit_with_sig(11);}

yf_pool_t *_mem_pool;
yf_log_t* _log;
yf_evt_driver_t *_evt_driver = NULL;
yfr_coroutine_mgr_t* _test_coroutine_mgr = NULL;

yf_s32_t  _test_switch_total = 0;

void _test_on_poll_evt_driver(yf_evt_driver_t* evt_driver, void* data, yf_log_t* log)
{
        if (_test_switch_total == 0)
        {
                yf_evt_driver_stop(evt_driver);
                return;
        }
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

class CoroutineTestor : public testing::Test
{
public:
        virtual ~CoroutineTestor()
        {
        }
        virtual void SetUp()
        {
                yf_evt_driver_init_t driver_init = {0, 
                                512, 2048, _log, YF_DEFAULT_DRIVER_CB};
                
                driver_init.poll_cb = _test_on_poll_evt_driver;
                
                _evt_driver = yf_evt_driver_create(&driver_init);
                ASSERT_TRUE(_evt_driver != NULL);
                yf_log_file_flush_drive(_evt_driver, 5000, NULL);

                //cause epoll wil ret error if no fd evts...
                yf_fd_t fds[2];
                socketpair(AF_LOCAL, SOCK_STREAM, 0, fds);
                yf_fd_event_t* fd_evts[2];
                yf_alloc_fd_evt(_evt_driver, fds[0], fd_evts, fd_evts + 1, _log);
                yf_register_fd_evt(fd_evts[0], NULL);

                //add coroutine stack watch timer
                yf_tm_evt_t* tm_evt = NULL;
                yf_alloc_tm_evt(_evt_driver, &tm_evt, _log);
                tm_evt->timeout_handler = _test_coroutine_stack_watch_handle;
                yf_ms_2_time(3000, &_test_stack_watch_tm);
                yf_register_tm_evt(tm_evt, &_test_stack_watch_tm);

                //init global coroutine set
                yf_int_t ret = yfr_coroutine_global_set(1024, 4096*8, 0, _log);
                assert(ret == 0);
                
                //init coroutine _test_coroutine_mgr
                yfr_coroutine_init_t init_info = {1024, 8, 64, _evt_driver};
                _test_coroutine_mgr = yfr_coroutine_mgr_create(&init_info, _log);
                assert(_test_coroutine_mgr);

                yfr_syscall_coroutine_attach(_test_coroutine_mgr, _log);

                //should after mgr created
                yf_log_file_add_handle(_log, 'r', yfr_coroutine_log);
        }

        virtual void TearDown()
        {
                yf_evt_driver_destory(_evt_driver);
        }        
};


/*
* if no evt dirver and core in main thread, log cant flush
*/
static void _test_reset_switch(int* icnt, int size, int area)
{
        _test_switch_total = 0;
        for (int i = 0; i < size; ++i)
        {
                icnt[i] = area;  // (i + 1) * area;
                _test_switch_total += icnt[i];
        }
        std::random_shuffle(icnt, icnt + (YF_ARRAY_SIZE(icnt) - 1));        
}


#ifdef  HAVE_UCONTEXT_H

/*
* 2016/01/18 test
--8  Intel(R) Xeon(R) CPU           X3440  @ 2.53GHz
--cache size      : 8192 KB
-- physical(1) {cpu cores(4), core ids(8)} // cpu cores -4, siblings - 8
*  switch total cnt=100000000 // 500 coroutines, each switch 200 thousand times
*   case : -fno-omit-frame-pointer -O2
        real    0m42.594s       42.998s     42.488s
        user    0m29.302s       28.966s     29.038s
        sys     0m13.281s       14.017s     13.437s
        avg: 238 million switch per sec
*/

typedef struct {
    ucontext_t context;
    yf_list_part_t linker;
    yf_u32_t id;
    int switch_cnt;
}
UcontextInfo;

yf_list_part_t  _ucontext_ready_list;
ucontext_t _ucontext_main;
UcontextInfo* _ucontext_now;

void _ucontext_switch_proc()
{
        UcontextInfo* context_info = _ucontext_now;
        int icnt = context_info->switch_cnt;

        printf("r(%u) switch cnt=%d\n", context_info->id, icnt);
        while (icnt)
        {
                yf_list_add_tail(&context_info->linker, &_ucontext_ready_list);
                --icnt;
                --_test_switch_total;
                swapcontext(&context_info->context, &_ucontext_main);
        }
        printf("r(%u) exit\n", context_info->id);
}


TEST_F(CoroutineTestor, UContextSwitch)
{
        int icnt[500];
        _test_reset_switch(icnt, YF_ARRAY_SIZE(icnt), 200000);

        printf("switch total cnt=%d\n", _test_switch_total);
        // _ASSERT(0);

        size_t stack_size = 4096 * 4;
        char* stack_ptrs = new char[stack_size * YF_ARRAY_SIZE(icnt)];
        assert(stack_ptrs);
        UcontextInfo* contexts = new UcontextInfo[YF_ARRAY_SIZE(icnt)];
        assert(contexts);

        getcontext(&_ucontext_main);
        yf_init_list_head(&_ucontext_ready_list);

        for (size_t i = 0; i < YF_ARRAY_SIZE(icnt); ++i) {
                getcontext(&contexts[i].context);

                contexts[i].id = i;
                contexts[i].switch_cnt = icnt[i];
                contexts[i].context.uc_link = &_ucontext_main;
                contexts[i].context.uc_stack.ss_sp = stack_ptrs + (stack_size * i);
                contexts[i].context.uc_stack.ss_size = stack_size;
                contexts[i].context.uc_stack.ss_flags = 0;

                makecontext(&contexts[i].context, _ucontext_switch_proc, 2, contexts + i, icnt[i]);

                yf_list_add_tail(&contexts[i].linker, &_ucontext_ready_list);
        }

        yf_list_part_t ready_list;
        yf_init_list_head(&ready_list);
        yf_list_part_t *pos, *keep;

        while (_test_switch_total) {
                yf_list_splice(&_ucontext_ready_list, &ready_list);

                yf_list_for_each_safe(pos, keep, &ready_list) {
                        yf_list_del(pos);

                        UcontextInfo* context_info = container_of(pos, UcontextInfo, linker);
                        _ucontext_now = context_info;
                        swapcontext(&_ucontext_main, &context_info->context);
                }
        }

        delete stack_ptrs;
        delete []contexts;
}

#endif


/*
* 2016/01/18 test
--8  Intel(R) Xeon(R) CPU           X3440  @ 2.53GHz
--cache size      : 8192 KB
-- physical(1) {cpu cores(4), core ids(8)} // cpu cores -4, siblings - 8
*  switch total cnt=100000000 // 500 coroutines, each switch 200 thousand times
*   case : -fno-omit-frame-pointer -O2
        real    0m8.489s        8.431s      8.532s
        user    0m8.457s
        sys     0m0.012s
        avg: 1176 million switch per sec ~= [[4.94*makecontext's witch]]
*   case : -fno-omit-frame-pointer -g -O0
        real    0m15.869s       16.029s     16.150s
        user    0m15.845s
        sys     0m0.016s
*/

yf_int_t _coroutine_switch_proc(yfr_coroutine_t* r)
{
        int icnt = *(int*)r->arg;
        printf("r id=%lld, switch cnt=%d\n", r->id, icnt);
        while (icnt)
        {
                --icnt;
                --_test_switch_total;
                yfr_coroutine_yield(r);
        }
        printf("r id=%lld,  exit\n", r->id);
        return  0;
}


TEST_F(CoroutineTestor, Switch)
{
        int icnt[500];
        _test_reset_switch(icnt, YF_ARRAY_SIZE(icnt), 200000);

        printf("switch total cnt=%d\n", _test_switch_total);
        // _ASSERT(0);

        yfr_coroutine_t* r = NULL;
        for (int i = 0; i < YF_ARRAY_SIZE(icnt); ++i)
        {
                r = yfr_coroutine_create(_test_coroutine_mgr, _coroutine_switch_proc, icnt+i, _log);
                assert(r);
        }
        
        while (_test_switch_total > 0)
        {
                yfr_coroutine_schedule(_test_coroutine_mgr);
        }
}


static yf_s32_t _cor_run_total = 0;
static yf_s32_t _cor_running_num = 0;

yf_int_t _coroutine_cre_proc(yfr_coroutine_t* r)
{
        for (int i = 0; i < 3; ++i) {
                yfr_coroutine_yield(r);
        }
        --_cor_run_total;
        --_cor_running_num;
        return  0;
}


TEST_F(CoroutineTestor, CreateRunExit)
{
        yfr_coroutine_t* r = NULL;
        yf_s32_t run_max = 0;

        _cor_run_total = 10000000;
        _cor_running_num = 0;

        while (_cor_run_total > 0) {
                run_max = 800 + (random() & 127);
                for (; _cor_running_num < std::min(_cor_run_total, run_max);
                                ++_cor_running_num) {
                        r = yfr_coroutine_create(_test_coroutine_mgr,
                                _coroutine_cre_proc,
                                NULL, _log);
                        assert(r);
                }
                yfr_coroutine_schedule(_test_coroutine_mgr);
        }
}


yf_int_t _coroutine_sleep_proc(yfr_coroutine_t* r)
{
        int icnt = *(int*)r->arg;
        printf("r id=%lld, sleep cnt=%d\n", r->id, icnt);
        while (icnt)
        {
                --icnt;
                --_test_switch_total;
                if ((icnt & 15) == 0)
                        usleep(yf_mod(random(), 1024));
        }
        printf("r id=%lld,  exit\n", r->id);
        return 0;
}

TEST_F(CoroutineTestor, Sleep)
{       
        int icnt[100];
        _test_reset_switch(icnt, YF_ARRAY_SIZE(icnt), 10);

        printf("sleep total cnt=%d\n", _test_switch_total);

        yfr_coroutine_t* r = NULL;
        for (int i = 0; i < YF_ARRAY_SIZE(icnt); ++i)
        {
                r = yfr_coroutine_create(_test_coroutine_mgr, _coroutine_sleep_proc, icnt+i, _log);
                assert(r);
        }
        
        yf_evt_driver_start(_evt_driver);
}


yfr_ipc_lock_t  _test_lock;

yf_int_t _coroutine_lock_proc(yfr_coroutine_t* r)
{
        int icnt = *(int*)r->arg;
        usleep(yf_mod(random(), 4096));

        int lock_cnt = yf_mod(random(), 7);
        lock_cnt = yf_max(1, lock_cnt);

        printf("r id=%lld, lock cnt in lock=%d\n", r->id, lock_cnt);
        
        yf_int_t ret = 0;
        int i = 0;
        for (; i < lock_cnt / 2; ++i)
        {
                yfr_ipc_lock(&_test_lock, 0, NULL);
                assert(ret == YF_OK);
        }
        
        while (icnt)
        {
                --icnt;
                --_test_switch_total;
                if ((icnt & 31) == 0)
                {
                        printf("r id=%lld, sleep now\n", r->id);
                        usleep(yf_mod(random(), 1024));
                }
                if (i < lock_cnt)
                {
                        yfr_ipc_lock(&_test_lock, 0, NULL);
                        assert(ret == YF_OK);
                        ++i;
                }
        }

        for (--i; i >= 0; --i)
                yfr_ipc_unlock(&_test_lock);
        printf("r id=%lld,  exit\n", r->id);
        return  0;
}


TEST_F(CoroutineTestor, IpcLock)
{
        yfr_ipc_lock_init(&_test_lock);
        
        int icnt[32];
        _test_reset_switch(icnt, YF_ARRAY_SIZE(icnt), 1);

        printf("sleep total cnt=%d\n", _test_switch_total);

        yfr_coroutine_t* r = NULL;
        for (int i = 0; i < YF_ARRAY_SIZE(icnt); ++i)
        {
                r = yfr_coroutine_create(_test_coroutine_mgr, _coroutine_lock_proc, icnt+i, _log);
                assert(r);
        }
        
        yf_evt_driver_start(_evt_driver);        
}


yfr_ipc_cond_t  _test_cond;
std::list<yf_u32_t>  _notify_queue;

yf_int_t _coroutine_cond_produce_proc(yfr_coroutine_t* r)
{
        int icnt = *(int*)r->arg;
        printf("r id=%lld, produce cnt=%d\n", r->id, icnt);
        while (icnt)
        {
                --icnt;
                _notify_queue.push_back(yf_mod(random(), 4096));
                
                if (yfr_ipc_cond_have_waits(&_test_cond))
                {
                        printf("consume wait, sig it from sleep now\n");
                        yfr_ipc_cond_sig(&_test_cond);
                }

                if ((icnt & 3) == 0)
                        usleep(yf_mod(random(), 8192*2));
        }
        printf("r id=%lld,  exit\n", r->id);
        return 0;
}


yf_int_t _coroutine_cond_consume_proc(yfr_coroutine_t* r)
{
        while (_test_switch_total)
        {
                int icnt = 0;
                while (!_notify_queue.empty())
                {
                        _notify_queue.pop_front();
                        --_test_switch_total;
                        if ((++icnt % 64) == 0)
                        {
                                printf("consume sleep now, rest cnt=%d...\n", _test_switch_total);
                                usleep(yf_mod(random(), 1024));
                        }
                }
                
                printf("queue empty, consume should wait now...\n");
                
                yfr_ipc_cond_wait(&_test_cond);
        }
        return 0;
}


TEST_F(CoroutineTestor, IpcCond)
{
        yfr_ipc_cond_init(&_test_cond);
        
        int icnt[25];
        _test_reset_switch(icnt, YF_ARRAY_SIZE(icnt), 10);

        printf("cond total cnt=%d\n", _test_switch_total);

        yfr_coroutine_t* r = NULL, * cmpr = NULL;
        for (int i = 0; i < YF_ARRAY_SIZE(icnt); ++i)
        {
                r = yfr_coroutine_create(_test_coroutine_mgr, 
                                _coroutine_cond_produce_proc, icnt+i, _log);

                assert(r);
                cmpr = yfr_coroutine_getby_id(_test_coroutine_mgr, r->id);
                ASSERT_EQ(cmpr, r);
        }

        r = yfr_coroutine_create(_test_coroutine_mgr, 
                                _coroutine_cond_consume_proc,  NULL, _log);
        assert(r);
        
        yf_evt_driver_start(_evt_driver);
}



yf_int_t _coroutine_serach_kwd(yfr_coroutine_t* r)
{
        int isearch = *(int*)r->arg;
        printf("r id=%lld, serach=%d\n", r->id, isearch);
        yf_int_t  ret = 0, head_recved = 0;

        char  send_buf[2048] = {0};
        int send_len = sprintf(send_buf, "GET /s?wd=%d HTTP/1.0\r\nUser-Agent: Wget/1.11.4 Red Hat modified\r\n"
                                "Accept: */*\r\nHost: www.baidu.com\r\nConnection: Close\r\n\r\n", 
                                isearch);
        int  all_recv_len = 0, body_len = 82888899, body_recv = 0;
        
        yf_utime_t  utime;
        yf_ms_2_utime(1000 * 12, &utime);

        int sockfd = -1;

        if (random()%2)
        {
                printf("r id=%lld, use set ip=220.181.111.148\n", r->id);

                yf_sockaddr_storage_t sock_addr;
                yf_memzero_st(sock_addr);
                sock_addr.ss_family = AF_INET;
                yf_sock_set_addr((yf_sock_addr_t*)&sock_addr, "220.181.111.148");
                yf_sock_set_port((yf_sock_addr_t*)&sock_addr, 80);

                sockfd = socket(AF_INET, SOCK_STREAM, 0);

                assert(sockfd);
                yfr_socket_conn_tmset(sockfd, 1000 * 25);
                
                ret = connect(sockfd, (yf_sock_addr_t*)&sock_addr, 
                                yf_sock_len((yf_sock_addr_t*)&sock_addr));
        }
        else {
                struct addrinfo hints;
                yf_memzero_st(hints);
                hints.ai_socktype = SOCK_STREAM;
                
                struct addrinfo *res = NULL, *riter;
                if ((ret = getaddrinfo("baidu.com", "80", &hints, &res)) != 0)
                {
                        printf("errrrrrrrrrr, getaddrinfo failed, err_str=%s\n", gai_strerror(ret));
                        goto end;
                }

                std::vector<struct addrinfo*> avres;
                for (riter = res; riter != NULL; riter = riter->ai_next)
                        avres.push_back(riter);

                if (avres.empty()) 
                {
                        printf("errrrrrrrrrr, getaddrinfo empty\n");
                        goto end;
                }

                riter = avres[random()%avres.size()];

                char ip_buf[64] = {0};
                yf_sock_ntop(riter->ai_addr, ip_buf, sizeof(ip_buf), 0);              
                printf("r id=%lld, use getaddrinfo's ip=%s\n", r->id, ip_buf);
                
                sockfd = socket(riter->ai_family, riter->ai_socktype, riter->ai_protocol);
                assert(sockfd);
                yfr_socket_conn_tmset(sockfd, 1000 * 25);

                ret = connect(sockfd, riter->ai_addr, riter->ai_addrlen);
                
                freeaddrinfo(res);
        }
        
        if (ret != 0)
        {
                printf("connect failed, err=%d, desc=%s]\n", yf_errno, strerror(yf_errno));
                goto end;
        }
        
        ret = setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &utime, sizeof(utime));
        assert(ret == 0);

        //printf("req send len=%d\n", send_len);
        
        ret = write(sockfd, send_buf, send_len);
        if (ret < 0)
        {
                printf("write failed, err=%d]\n", yf_errno);
                goto end;
        }
        assert(ret == send_len);

        //poll
        struct pollfd poll_fds[1];
        poll_fds[0].fd = sockfd;
        poll_fds[0].events = POLLIN;
        
        poll_fds[0].revents = 0;
        if ((ret = poll(poll_fds, 1, 12*1000)) != 1)
        {
                printf("errrrrrrrrrrrrrrrrrrrr first poll ret = %d, end now!!\n", ret);
                goto end;
        }
        //select
        fd_set select_fds;
        
        while ((ret = read(sockfd, send_buf, sizeof(send_buf) - 1)) > 0)
        {
                send_buf[ret] = 0;
                fprintf(stderr, "r id=%lld, recv=-----\n%s\n_______\n", r->id, send_buf);
                
                all_recv_len += ret;
                if (!head_recved)
                {
                        char* cl = strcasestr(send_buf, "Content-Length: ");
                        if (cl)
                                body_len = atoi(cl + strlen("Content-Length: "));
                        cl = strstr(send_buf, "\r\n\r\n");
                        if (cl)
                        {
                                head_recved = 1;
                                body_recv = send_buf + ret - (cl + 4);
                        }
                }
                else {
                        body_recv += ret;
                        if (body_recv >= body_len) 
                        {
                                printf("r id=%lld recv all body, len=%d\n", r->id, body_len);
                                break;
                        }
                }

                yf_log_debug(YF_LOG_DEBUG, r->log, 0, 
                                "r id=%lld, prepare for next poll", r->id);

                int poll_choice = random() % 3;
                
                if (poll_choice == 0)
                {
                        poll_fds[0].revents = 0;
                        if ((ret = poll(poll_fds, 1, 12*1000)) != 1)
                        {
                                printf("errrrrrrrrrrrrrrrrrrrr poll ret = %d\n", ret);
                                goto end;
                        }
                        yf_log_debug(YF_LOG_DEBUG, r->log, 0, 
                                        "r id=%lld, poll ret now, revents=%d", 
                                        r->id, poll_fds[0].revents);
                }
                else if (poll_choice == 1) {
                        FD_ZERO(&select_fds);
                        FD_SET(sockfd, &select_fds);
                        if ((ret = select(sockfd + 1, &select_fds, NULL, NULL, &utime)) != 1)
                        {
                                printf("errrrrrrrrrrrrrrrrrrrr select ret = %d\n", ret);
                                goto end;
                        }
                        yf_log_debug(YF_LOG_DEBUG, r->log, 0, 
                                        "r id=%lld, select ret now, fd is set=%d", 
                                        r->id, FD_ISSET(sockfd, &select_fds));
                }
        }
        
        if (ret < 0) {
                printf("r id=%lld recv ret errrrrrrrrrrrrrrrrrrrr=%d, all_recv_len=%d, body_len=%d, "
                        "err=%d, str='%s'\n", r->id, 
                        ret, all_recv_len, body_len, 
                        yf_errno, strerror(yf_errno));
        }
        else if (ret == 0)
        {
                printf("r id=%lld recv ret closed fd, all_recv_len=%d, body_len=%d, \n", 
                        r->id, all_recv_len, body_len);
        }

end:
        if (sockfd >= 0)
                close(sockfd);
        --_test_switch_total;
        printf("r id=%lld,  exit, rest cnt=%d\n", r->id, _test_switch_total);
        return 0;
}


TEST_F(CoroutineTestor, SocketActive)
{
        yfr_coroutine_t* r = NULL;
        int iserach[36];
        
        _test_switch_total = YF_ARRAY_SIZE(iserach);
        for (int i = 0; i < YF_ARRAY_SIZE(iserach); ++i)
        {
                iserach[i] = yf_mod(random(), 8192*16);
                
                r = yfr_coroutine_create(_test_coroutine_mgr, 
                                _coroutine_serach_kwd, 
                                iserach+i, _log);
                assert(r);
        }
        yf_evt_driver_start(_evt_driver);
}


yf_int_t _coroutine_nslookup(yfr_coroutine_t* r)
{
        const char* domain = (const char*)r->arg;
        printf("r id=%lld\n", r->id);

        poll(NULL, 0, 5000);

        struct hostent* hret;
        struct hostent  hcopy;
        char cbuf[1024];

        printf("r id=%lld, nslookup=%s\n", r->id, domain);
        hret = gethostbyname(domain);
        if (hret == NULL)
        {
                fprintf(stderr, "nslookup err, errno=%d, str=%s", h_errno, hstrerror(h_errno));
        }
        else {
again:                
                printf("domain=%s, official_name=%s, addrtype=%d, h_length=%d\n", 
                                domain, hret->h_name, hret->h_addrtype, hret->h_length);

                char ipstr[32];
                char** addr = hret->h_addr_list;
                while (*addr)
                {
                        printf("\t[%s]\n",  inet_ntop(hret->h_addrtype, *addr, 
                                        ipstr, sizeof(ipstr)));
                        addr++;
                }
                printf("\tfirst alias=%s\n", hret->h_aliases[0]);
                char** alias = hret->h_aliases;
                while (*alias)
                {
                        printf("\t[%s]\n", *alias);
                        alias++;
                }

                if (hret != &hcopy)
                {
                        yfr_syscall_dns_hostent_cpy(&hcopy, cbuf, sizeof(cbuf), hret);
                        hret = &hcopy;
                        printf("\ttest copy\n");
                        goto again;
                }
        }

end:        
        printf("r id=%lld,  exit\n\n", r->id);
        --_test_switch_total;        
        return  0;
}

const char* domains[] = {"google.com", "xunlei.com", "baidu.com", 
                "qq.com", "g.cn", "aabb.cn", "sina.com.cn", "sina.com", 
                "jd.com", "360buy.com", 
                "taobao.com", "tmall.com"};

TEST_F(CoroutineTestor, Dns)
{
        yfr_coroutine_t* r = NULL;
        
        _test_switch_total = YF_ARRAY_SIZE(domains);
        //_test_switch_total = 1;
        
        for (int i = 0; i < _test_switch_total; ++i)
        {
                r = yfr_coroutine_create(_test_coroutine_mgr, 
                                _coroutine_nslookup, 
                                (void*)domains[i], _log);
                assert(r);
        }
        
        yf_evt_driver_start(_evt_driver);
}

#define _proc_args(a1, a2, a3, a4) \
        if (a1 != YF_MAGIC_VAL) { \
                printf("illegal first arg: %d\n", a1); \
                _ASSERT(0); \
        } \
        if (a2 != a3) { \
                printf("illegal last 2 args:(%p - %p)\n", a2, a3); \
                _ASSERT(0); \
        } \
        *a4 = *a2; \
        printf("all args checked legal, a2=%p\n", a2);

yfr_fcall_api _coroutine_fcall_child1(int a1, int* a2, void* a3, int* a4)
{
        yfr_coroutine_fcall_child;
        _proc_args(a1, a2, a3, a4);

        yf_log_debug(YF_LOG_DEBUG, _log, 0, "_coroutine_fcall_child1 begin");
        usleep(random() % 16384);
        yf_log_debug(YF_LOG_DEBUG, _log, 0, "_coroutine_fcall_child1 done");
        return 0;
}

yfr_fcall_api _coroutine_fcall_child2(int a1, int* a2, void* a3, int* a4,
        int* a5, const void* a6, int* a7, int* a8, void* a9, int* a10)
{
         yfr_coroutine_fcall_child;
        _proc_args(a1, a2, a9, a10);
        assert(a4 == NULL && a7 == NULL);
        usleep(random() % 8192);

        struct hostent* hret;
        const char* domain = (const char*)a6;
        hret = gethostbyname(domain);
        if (hret == NULL)
        {
                fprintf(stderr, "nslookup err domain=%s, errno=%d, str=%s\n",
                        domain, h_errno, hstrerror(h_errno));
        }
        else {
                printf("domain=%s, official_name=%s, addrtype=%d, h_length=%d\n", 
                                domain, hret->h_name, hret->h_addrtype, hret->h_length);

                char ipstr[64];
                char** addr = hret->h_addr_list;
                while (*addr) {
                        printf("\t[%s]\n",  inet_ntop(hret->h_addrtype, *addr, 
                                        ipstr, sizeof(ipstr)));
                        addr++;
                }
                printf("\tfirst alias=%s\n", hret->h_aliases[0]);
                char** alias = hret->h_aliases;
                while (*alias) {
                        printf("\t[%s]\n", *alias);
                        alias++;
                }
        }

        yf_log_debug(YF_LOG_DEBUG, _log, 0, "_coroutine_fcall_child2 done");
        FILE* f = fopen(".tst.txt", "a+");
        if (f) {
                char szbuf[128];
                snprintf(szbuf, sizeof(szbuf), "a6=%p, a8=%p, a9=%p\n", a6, a8, a9);
                fwrite(szbuf, strlen(szbuf), 1, f);
                fclose(f);
        }
        return 0;
}


class _CorFcallClassTest
{
public:
        _CorFcallClassTest() : _a(0) {
                bzero(_b, sizeof(_b));
                _a = random();
        }

        yfr_fcall_api Test(yf_s64_t a, yf_u64_t* r) {
                yfr_coroutine_fcall_child;

                yf_log_debug(YF_LOG_DEBUG, _log, 0, "_CorFcallClassTest begin, _a=%L, a=%L", _a, a);
                _a += a;

                yf_u64_t atmp = _a;
                yf_u64_t* rv = new yf_u64_t[YF_ARRAY_SIZE(_b)];
                usleep(random() % 1024);

                yf_int_t ret = yfr_coroutine_fcall_start();
                _ASSERT(ret == 0);
                for (int i = 0; i < YF_ARRAY_SIZE(_b); ++i) {
                        rv[i] = _b[i];
                        _ClsMethod(rv[i], rv+i);
                }
                ret = yfr_coroutine_fcall_wait();
                _ASSERT(ret == 0);

                for (int i = 0; i < YF_ARRAY_SIZE(_b); ++i) {
                        _ASSERT(rv[i] == _Caculate(_b[i]));
                        _b[i] = rv[i];
                        atmp += _b[i];
                }

                delete []rv;
                _a = atmp;
                *r = _a;
                yf_log_debug(YF_LOG_DEBUG, _log, 0, "_CorFcallClassTest end, _a=%L", _a);
                return 0;
        }

        yf_u64_t Get() {
                return _a;
        }

private:
        yfr_fcall_api _ClsMethod(yf_u64_t val, yf_u64_t* pval) {
                yfr_coroutine_fcall_child;
                _ASSERT(val == *pval);

                yf_log_debug(YF_LOG_DEBUG, _log, 0,
                        "_CorFcallClassTest Method begin, val=%L, pval=%p", *pval, pval);
                if ((random() % 5) == 0) {
                        usleep(random() % 8192);
                }
                *pval = _Caculate(val);
                yf_log_debug(YF_LOG_DEBUG, _log, 0,
                        "_CorFcallClassTest Method end, val=%L, pval=%p", *pval, pval);
                return 0;
        }

        yf_u64_t __attribute__ ((noinline)) _Caculate(yf_u64_t v) {
                return ((_a) >> 8) + (v * 3 / 2);
        }
private:
        yf_u64_t _a;
        yf_u64_t _b[10];
};

yfr_fcall_api _coroutine_fcall_class()
{

}

yf_int_t _coroutine_fcall_parent(yfr_coroutine_t* r)
{
        _CorFcallClassTest cls_test;
        yf_u64_t val;
        for (; _test_switch_total > 0; --_test_switch_total)
        {
                int testas[16], testbs[16];
                int child_num1 = random() % YF_ARRAY_SIZE(testas);
                int test2as[32], test2bs[32];
                int child_num2 = random() % YF_ARRAY_SIZE(test2as);
                // child_num1 = 0;
                // child_num2 = 0;

                printf("fcall trying %d, child_num1=%d, child_num2=%d\n",
                        _test_switch_total, child_num1, child_num2);

                yf_int_t ret = yfr_coroutine_fcall_start();
                _ASSERT(ret == 0);

                for (int j = 0; j < child_num1; ++j)
                {
                        testas[j] = random();
                        _coroutine_fcall_child1(YF_MAGIC_VAL, testas + j, testas + j, testbs + j);
                }
                for (int j = 0; j < child_num2; ++j)
                {
                        test2as[j] = random();
                        _coroutine_fcall_child2(YF_MAGIC_VAL, test2as + j,
                                NULL, NULL, NULL, domains[random()%YF_ARRAY_SIZE(domains)],
                                NULL, NULL,
                                test2as + j, test2bs + j);
                }

                cls_test.Test(random(), &val);

                ret = yfr_coroutine_fcall_wait();
                assert(ret == 0);
                for (int j = 0; j < child_num1; ++j)
                {
                        if (testas[j] != testbs[j]) {
                                printf("result error (%d - %d)\n", testas[j], testbs[j]);
                                _ASSERT(0);
                        }
                }
                for (int j = 0; j < child_num2; ++j)
                {
                        if (test2as[j] != test2bs[j]) {
                                printf("result error (%d - %d)\n", test2as[j], test2bs[j]);
                                _ASSERT(0);
                        }
                }
                _ASSERT(val == cls_test.Get());
        }
        return 0;

}


TEST_F(CoroutineTestor, Fcall)
{
        printf("Fcall begin\n");
        _test_switch_total = 100000;

        yfr_coroutine_t* r = NULL;
        r = yfr_coroutine_create(_test_coroutine_mgr,
                                _coroutine_fcall_parent,
                                NULL, _log);
        assert(r);
        yf_evt_driver_start(_evt_driver);
}

#ifdef HAVE_MYSQL
#include <mysql.h>
const char* mysql_host = NULL;
const char* mysql_user = NULL;
const char* mysql_psd = NULL;
int mysql_ops = 1024;

yf_int_t _coroutine_mysql_query(yfr_coroutine_t* r)
{
        char sql_buf[512];
        char db_table[128];
        MYSQL *conn;
        conn = mysql_init(NULL);
        int insert_cnt = 0;

#define _MYSQL_ERR_CHCK(_do) \
        if (_do) { \
                printf("Error on do{%s} %u: %s\n", #_do, \
                        mysql_errno(conn), mysql_error(conn)); \
                goto test_err; \
        } 
        if (conn == NULL) 
        {
                printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
                return 0;                
        }
        _MYSQL_ERR_CHCK(mysql_real_connect(conn, mysql_host, mysql_user, mysql_psd, 
                NULL, 3306, NULL, 0) == NULL);
        _MYSQL_ERR_CHCK(mysql_query(conn, "create database if not EXISTS mysql_coroutine_test;"));

        sprintf(db_table, "mysql_coroutine_test.test_%lld", r->id);

        sprintf(sql_buf, "create table if not EXISTS %s"
                "(id int auto_increment, val int default 0, "
                "time  timestamp DEFAULT CURRENT_TIMESTAMP, "
                "PRIMARY KEY (id)) ENGINE=myisam", db_table);
        printf("%s\n", sql_buf);
        _MYSQL_ERR_CHCK(mysql_query(conn, sql_buf));

        for (int i = 0; i < mysql_ops; ++i)
        {
                if (insert_cnt == 0 || random() & 3)
                {
                        sprintf(sql_buf, "insert into %s set val=%d", db_table, random()%((1<<24)-1));
                        _MYSQL_ERR_CHCK(mysql_query(conn, sql_buf));
                        ++insert_cnt;
                }
                else {
                        int start = random() % insert_cnt;
                        int select_cnt = random() % insert_cnt;
                        sprintf(sql_buf, "select * from %s limit %d,%d", db_table, start, select_cnt);
                        _MYSQL_ERR_CHCK(mysql_query(conn, sql_buf));

                        MYSQL_RES *result = mysql_store_result(conn);
                        MYSQL_ROW row;
                        int num_fields = mysql_num_fields(result);
                        assert(num_fields == 3);
                        while (row = mysql_fetch_row(result))
                        {
                                yf_log_debug4(YF_LOG_DEBUG, r->log, 0, 
                                        "ops=%d -> {%s,%s,%s}\n", i, 
                                        row[0], row[1], row[2]);
                        }
                        mysql_free_result(result);
                }
        }

test_err:
        sprintf(sql_buf, "drop table if EXISTS %s", db_table);
        _MYSQL_ERR_CHCK(mysql_query(conn, sql_buf));

        mysql_close(conn);
        printf("r id=%lld,  exit\n\n", r->id);
        --_test_switch_total;        
        return 0;
}

TEST_F(CoroutineTestor, Mysql)
{
        mysql_host = getenv("mysql_host");
        mysql_user = getenv("mysql_user");
        mysql_psd = getenv("mysql_psd");
        if (NULL == mysql_host || NULL == mysql_user || NULL == mysql_psd)
        {
                printf("should set mysql_host+mysql_user+mysql_psd\n");
                return;
        }
        const char* insert_cnt = getenv("mysql_ops");
        if (insert_cnt)
                mysql_ops = atoi(insert_cnt);
        yfr_coroutine_t* r = NULL;
        _test_switch_total = 16;

        for (int i = 0; i < _test_switch_total; ++i)
        {
                r = yfr_coroutine_create(_test_coroutine_mgr, 
                                _coroutine_mysql_query, NULL, _log);
                assert(r);
        }
        yf_evt_driver_start(_evt_driver);
}
#endif


#ifdef TEST_F_INIT
#ifdef  HAVE_UCONTEXT_H
TEST_F_INIT(CoroutineTestor, UContextSwitch);
#endif
TEST_F_INIT(CoroutineTestor, Switch);
TEST_F_INIT(CoroutineTestor, CreateRunExit);
TEST_F_INIT(CoroutineTestor, Sleep);
TEST_F_INIT(CoroutineTestor, IpcCond);
TEST_F_INIT(CoroutineTestor, IpcLock);
TEST_F_INIT(CoroutineTestor, SocketActive);
TEST_F_INIT(CoroutineTestor, Dns);
TEST_F_INIT(CoroutineTestor, Fcall);
#ifdef HAVE_MYSQL
TEST_F_INIT(CoroutineTestor, Mysql);
#endif
#endif

int main(int argc, char **argv)
{
        std::vector<int> aVec;
        aVec.push_back(1122);
        aVec.reserve(45);
        aVec.clear();

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
                        "log/coroutine.log", "%t [%f:%l]-[%v]-[%r]"};

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

        testing::InitGoogleTest(&argc, (char **)argv);
        ret = RUN_ALL_TESTS();

        yf_destroy_pool(_mem_pool);

        return ret;
}



