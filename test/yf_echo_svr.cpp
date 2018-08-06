#include <list>
#include <vector>

extern "C" {
#include <coroutine/yfr_coroutine.h>
#include <coroutine/yfr_greenlet.h>
#include <syscall_hook/yfr_syscall.h>
#include <syscall_hook/yfr_dlsym.h>
#include <syscall_hook/yfr_ipc.h>
#include <log_ext/yf_log_file.h>
}

yf_pool_t *_mem_pool;
yf_log_t* _log;
yf_evt_driver_t *_evt_driver = NULL;
yfr_coroutine_mgr_t* _test_coroutine_mgr = NULL;

const char* _svr_ip = NULL;
int _svr_port = 0;
const char* _backend_ip = NULL;
int _backend_port = 0;

inline void _test_on_poll_evt_driver(yf_evt_driver_t* evt_driver, void* data, yf_log_t* log)
{
        yfr_coroutine_schedule(_test_coroutine_mgr);
}


yf_int_t echo_svr_worker(yfr_coroutine_t* r) {
        int fd = r->data;
        int backend_fd = 0;
        char buf[1024 * 16];
        int ret;

        printf("new client fd=%d\n", fd);

        yf_utime_t  utime;
        yf_ms_2_utime(1000 * 2, &utime);
        ret = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &utime, sizeof(utime));
        assert(ret == 0);

        if (_backend_ip) {
                yf_sockaddr_storage_t sock_addr;
                yf_memzero_st(sock_addr);
                sock_addr.ss_family = AF_INET;
                yf_sock_set_addr((yf_sock_addr_t*)&sock_addr, _backend_ip);
                yf_sock_set_port((yf_sock_addr_t*)&sock_addr, _backend_port);

                backend_fd = socket(AF_INET, SOCK_STREAM, 0);
                assert(backend_fd);
                yfr_socket_conn_tmset(backend_fd, 1000 * 2);

                ret = connect(backend_fd, (yf_sock_addr_t*)&sock_addr, 
                                yf_sock_len((yf_sock_addr_t*)&sock_addr));

                if (ret != 0) {
                        printf("connect(%s:%d) failed\n", _backend_ip, _backend_port);
                        goto error;
                }

                ret = setsockopt(backend_fd, SOL_SOCKET, SO_RCVTIMEO, &utime, sizeof(utime));
                assert(ret == 0);
        }

        for(;;) {
                ret = read(fd, buf, sizeof(buf));
                if (ret <= 0)
                    goto error;

                if (backend_fd) {
                    ret = write(backend_fd, buf, ret);
                    if (ret < 0)
                        goto error;

                    int backedn_ret = read(backend_fd, buf, sizeof(buf));
                    if (backedn_ret <= 0 || backedn_ret != ret) {
                        goto error;
                    }
                }

                ret = write(fd, buf, ret);
                if (ret < 0)
                    goto error;
        }

error:
        printf("close fd=%d, backend fd=%d\n", fd, backend_fd);
        close(fd);
        if (backend_fd) {
                close(backend_fd);
                backend_fd = 0;
        }
}

yf_int_t echo_svr_main(yfr_coroutine_t* r) {
        int listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if( listen_fd < 0 ) {
                printf("socket failed\n");
                exit(-1);
        }

        int reuse = 1;
        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

        yf_sockaddr_storage_t sock_addr;
        yf_memzero_st(sock_addr);
        sock_addr.ss_family = AF_INET;
        yf_sock_set_addr((yf_sock_addr_t*)&sock_addr, _svr_ip);
        yf_sock_set_port((yf_sock_addr_t*)&sock_addr, _svr_port);

        int ret = bind(listen_fd, (yf_sock_addr_t*)&sock_addr, 
                                yf_sock_len((yf_sock_addr_t*)&sock_addr));
        if( ret != 0) {
                printf("svr_main bind failed, svr_ip=%s, svr_port=%d, err=%s\n",
                                _svr_ip, _svr_port, strerror(errno));
                close(listen_fd);
                return -1;
        }

        ret = listen(listen_fd, 1024);
        if( ret != 0) {
                printf("listen failed\n");
                close(listen_fd);
                return -1;
        }

        struct sockaddr_in addr;
        while (1) {
            memset(&addr, 0, sizeof(addr));
            socklen_t len = sizeof(addr);

            int fd = accept(listen_fd, (struct sockaddr *)&addr, &len);
            if (fd < 0) {
                    continue;
            }
            yfr_coroutine_t* r = yfr_coroutine_create(_test_coroutine_mgr,
                    echo_svr_worker, NULL, _log);
            r->data = fd;
            assert(r);
        }
}


int main(int argc, char **argv)
{
        yf_pagesize = getpagesize();
        printf("pagesize=%d\n", yf_pagesize);

        yf_cpuinfo();

        yf_int_t ret = yfr_syscall_init();
        assert(ret == YF_OK);

        //first need init threads before init log file
        ret = yf_init_threads(8, 1024 * 1024, 1, NULL);
        assert(ret == YF_OK);
        
        yf_log_file_init(NULL);
        yf_log_file_init_ctx_t log_file_init = {1024*128, 1024*1024*64, 8, 
                        "log/echo_svr.log", "%t [%f:%l]-[%v]-[%r]"};

        _log = yf_log_open(YF_LOG_INFO, 8192, (void*)&log_file_init);
        
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
                        2048, 4096, _log, YF_DEFAULT_DRIVER_CB};
        driver_init.poll_cb = _test_on_poll_evt_driver;

        _evt_driver = yf_evt_driver_create(&driver_init);
        assert(_evt_driver != NULL);
        yf_log_file_flush_drive(_evt_driver, 5000, NULL);

        //init global coroutine set
        ret = yfr_coroutine_global_set(1024, 4096*32, 0, _log);
        assert(ret == 0);

        //init coroutine _test_coroutine_mgr
        yfr_coroutine_init_t init_info = {1024, 8, 64, _evt_driver};
        _test_coroutine_mgr = yfr_coroutine_mgr_create(&init_info, _log);
        assert(_test_coroutine_mgr);

        yfr_syscall_coroutine_attach(_test_coroutine_mgr, _log);

        //should after mgr created
        yf_log_file_add_handle(_log, 'r', yfr_coroutine_log);

        _svr_ip = argv[1];
        _svr_port = atoi(argv[2]);
        if (argc > 4) {
                _backend_ip = argv[3];
                _backend_port = atoi(argv[4]);
        }
        yfr_coroutine_t* r = yfr_coroutine_create(_test_coroutine_mgr,
                echo_svr_main, NULL, _log);
        assert(r);

        //cause epoll wil ret error if no fd evts...
        yf_fd_t fds[2];
        socketpair(AF_LOCAL, SOCK_STREAM, 0, fds);
        yf_fd_event_t* fd_evts[2];
        yf_alloc_fd_evt(_evt_driver, fds[0], fd_evts, fd_evts + 1, _log);
        yf_register_fd_evt(fd_evts[0], NULL);

        yf_evt_driver_start(_evt_driver);

        yf_destroy_pool(_mem_pool);
        return ret;
}



