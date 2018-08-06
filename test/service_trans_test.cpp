// Copyright 2015, Tencent Inc.
// Author: kevin<kevinjzhong@tencent.com>
// Create: 2015-04-24
// Encoding: utf8

// 测试用例 :
// 1 - 动态添加删除地址
// 2 - client主动关连接 (主动删除地址后，会主动关连接)
//       trans deleted begin, ip=(0:40482:1)
// 3 - svr主动关连接 (通知client，且client回包后，关连接，client被动关)
//       close channel by id(5725176399)
// 4 - sock发送缓冲不足 (通过设置 socket 的write buffer size，然后发送一些大的包)
//       a) 利用 biz 的缓冲
//           ctx{fd:37, ip:[0-39458-1], channel:0x1f03d90}, sock wbuf full, need biz wbuf(7160)
//       b) biz 缓冲都不够
//           ctx{fd:37, ip:[0-39458-1], channel:0x1f03d90}, len(13420)>free_size(3916)
// 5 - client read 不完整的包 (svr故意发送包的时候，发送片段，并中间加一些随机停顿)
//      这个测试非常重要，因 service_trans.c 的数据读缓冲buf机制比较复杂!
//      ctx{fd:20, ip:[0-40482-1], channel:0xab2f88}, read buf free_size(11758),
//          should memove rsize(5578) to head
// 6 - 其他
//      ctx{fd:19, ip:[0-39202-1], channel:0x1548bf0}, connect err, fd:19,
//          errno:111(Connection refused)
// 7 - 地址添加后，连接中，立即删除
//      ctx{fd:13, ip:[0-39458-1], channel:0x15489c8}, connect inprogess, fd:13
//           channel:0x15489c8}, channel deleted begin, fd:13, close_begin_tv=1430208870
//           channel:0x15489c8}, connect success, fd:13, self port=4827
//           channel:0x15489c8}, channel deleted end, fd:13
// 8 -连接失败
//      channel:0x1547e48}, connect err, fd:13, errno:111(Connection refused)

// some bugs fixed record:
// 1, send 出错，svr端日志就没收到这个连接...非常诡异...
//     ctx{fd:30, ip:[0-39458-1], channel:0xf99d90}, send err, err=32(Broken pipe)
//     蛋疼的发现是svr端的 evt driver 的fd数设的有问题，原来是 YF_ARRAY_SIZE(g_test_ports) * 8
//     这个不一定够...所以 +128
//
// 2, core 了，跟踪日志，发现有个fd日志有点奇怪 :
//     channel:0x1547e48}, connect inprogess, fd:13
//     channel:0x1547e48}, channel deleted begin, fd:13, close_begin_tv=1430208977
//     channel:0x1547e48}, connect err, fd:13, errno:111(Connection refused)
//     channel:0x1547e48}, channel deleted end, fd:13
//     呃, 异步害死人啊...这个bug是这样造成的:
//     a) 连接开始 b)连接中，立即delete addr，投入到了 closing_channel_list 中(
//          cross_service_channel_close_delay)
//     c) 连接失败，直接删除了连接的上下文，此时，closing channel link 还在 list 中...
//     fix, cross_service_channel_close_delay 加入如下几行:
//             if (channel->close_begin_tv) {yf_list_del(&channel->closing_linker);}

#undef _WIN32
#undef _WIN64

#include <algorithm>
#include <map>
#include <set>
#include <vector>

#ifdef __cplusplus
extern "C" {
#endif

#include "common/tsf4g/include/tloghelp/tlogload.h"
#include "common/tsf4g_cross/base/cross_in.h"
#include "common/tsf4g_cross/service/service_trans.h"
#include "common/tsf4g_cross/service/test_def.h"

#ifdef __cplusplus
}
#endif

#include "thirdparty/gtest/gtest.h"

extern unsigned char g_szMetalib_testdef[];

cross_service_pkg_sinfo_t  g_test_service_pkg_sinfo = {
    reinterpret_cast<char*>(g_szMetalib_testdef),
    "TestPkg",
    NULL,
    "Head.HeadLen",
    "Head.BodyLen"
};

#define SERVICE_TRANS_TEST_SETMAGIC(msg) \
    msg.Head.Magic = 0x8787;


TEST(ServiceTransTest, test_codec) {
    srandom(time(NULL));
    cross_service_codec_ctx_t* codec_ctx = cross_service_codec_ctx_init(
            &g_test_service_pkg_sinfo);

    ASSERT_TRUE(codec_ctx != NULL);
    ASSERT_EQ(codec_ctx->pkg_len.offset, TDR_INVALID_OFFSET);
    ASSERT_EQ(codec_ctx->head_len.offset, 6);
    ASSERT_EQ(codec_ctx->head_len.unitsize, static_cast<size_t>(4));
    ASSERT_EQ(codec_ctx->body_len.offset, 10);
    ASSERT_EQ(codec_ctx->body_len.unitsize, static_cast<size_t>(4));

    ASSERT_EQ(codec_ctx->head_min_size, 14);

    ASSERT_TRUE(codec_ctx->pkg_hostsize >= sizeof(tagTestPkg));
}

#define TEST_ASSERT(_v) if (!(_v)) yf_exit_with_sig(yf_signal_value(YF_SHUTDOWN_SIGNAL));

// svr listen port
static const size_t TEST_PORT_NUM = 4;

uint16_t g_test_ports[TEST_PORT_NUM] = {0};
int g_test_listenfds[TEST_PORT_NUM] = {0};
cross_service_codec_ctx_t* g_test_codec_ctx;
yfr_coroutine_mgr_t* g_test_coroutine_mgr;
yf_log_t* g_test_log;

void service_trans_test_ports_init() {
    int ret = 0;
    int flag = 1;
    struct sockaddr_in addr;
    uint16_t port_begin = 8855;

    for (size_t i = 0; i < YF_ARRAY_SIZE(g_test_ports); ++i) {
        int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
        TEST_ASSERT(listen_fd >= 0);

        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));

        bzero(&addr, sizeof(struct sockaddr_in));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        for (; port_begin < 11996; ++port_begin) {
            addr.sin_port = htons(port_begin);
            ret = bind(listen_fd, (struct sockaddr*)&addr, sizeof(struct sockaddr));
            if (ret == 0) {
                g_test_ports[i] = port_begin++;
                break;
            }
        }
        TEST_ASSERT(g_test_ports[i]);
        ret = listen(listen_fd, 128);
        TEST_ASSERT(ret == 0);

        g_test_listenfds[i] = listen_fd;
    }
}


static void service_trans_test_set_idlist(tagTestPkg* msg, uint16_t rsp_num) {
    msg->Body.GetRolesRsp.num = rsp_num;
    uint32_t sum_val = 0;
    uint32_t random_val = 0;
    for (int i = 0; i < rsp_num - 1; ++i) {
        random_val = random() & 65535;
        msg->Body.GetRolesRsp.roleid_list[i] = random_val;
        sum_val += random_val;
    }
    msg->Body.GetRolesRsp.roleid_list[rsp_num - 1] = sum_val;
}


uint32_t g_test_sec_check = 0;
void service_test_svr_coroutine(yf_evt_driver_t* evt_driver,
            void* data, yf_log_t* log) {
    uint32_t sec_now = yf_now_times.clock_time.tv_sec;
    if (g_test_sec_check != sec_now) {
        g_test_sec_check = sec_now;
        if (getppid() == 1) {
            exit(0);
        }
    }
    yfr_coroutine_schedule(g_test_coroutine_mgr);
}


static yf_int_t  service_trans_test_on_new_conn(yfr_coroutine_t* r) {
    int ret;
    int sock_fd = static_cast<int>(r->data);

    yf_log_error(YF_LOG_INFO, r->log, 0,
                 "new conn, fd=%d",
                 sock_fd);

    tagTestPkg req_msg;
    tagTestPkg resp_msg;
    SERVICE_TRANS_TEST_SETMAGIC(resp_msg);

    char* rbuf = reinterpret_cast<char*>(malloc(g_test_codec_ctx->pkg_netsize_max));
    char* wbuf = reinterpret_cast<char*>(malloc(g_test_codec_ctx->pkg_netsize_max));

    TDRDATA net_data;
    TDRDATA host_data;

    ssize_t recv_ret;
    ssize_t send_ret;
    size_t send_len;
    size_t send_once;
    size_t pkg_size;
    size_t head_size;
    size_t recv_len = 0;
    int send_batch = 0;
    uint32_t disconn_sent_time = 0;

#define _SEND_RSP(_msg, cmd, _cnt) \
    _msg.Head.Cmd = cmd; \
    net_data.pszBuff = wbuf; \
    host_data.pszBuff = reinterpret_cast<char*>(&_msg); \
    net_data.iBuff = g_test_codec_ctx->pkg_netsize_max; \
    host_data.iBuff = sizeof(_msg); \
    ret = tdr_hton(g_test_codec_ctx->pkg_meta, &net_data, &host_data, \
            tdr_get_metalib_version(g_test_codec_ctx->metalib)); \
    TEST_ASSERT(ret == 0); \
    for (send_batch = 0; send_batch < _cnt; ++send_batch) { \
        send_len = 0; \
        while (1) { \
            send_once = random() % (net_data.iBuff - send_len); \
            send_once = yf_min(net_data.iBuff - send_len, \
                                    yf_max(static_cast<size_t>(6), send_once)); \
            send_ret = sendn(sock_fd, net_data.pszBuff + send_len, send_once, 0); \
            if (send_ret < static_cast<ssize_t>(send_once)) { \
                yf_log_error(YF_LOG_ERR, r->log, 0, "sent errrrrr, fd=%d, ask=%u, ret=%u", \
                        sock_fd, static_cast<uint32_t>(send_once), \
                        static_cast<uint32_t>(send_ret)); \
                goto end; \
            } \
            send_len += send_ret; \
            if (send_len >= net_data.iBuff) { \
                break; \
            } \
            if (random() % 2) { \
                yfr_usleep(random() % 2500); \
            } \
        } \
    }

    while (1) {
        // head
        if (static_cast<int>(recv_len) < g_test_codec_ctx->head_min_size) {
            recv_ret = recvn(sock_fd, rbuf + recv_len,
                g_test_codec_ctx->head_min_size - recv_len,
                0);
            if (recv_ret == 0) {
                yf_log_error(YF_LOG_INFO, r->log, 0, "conn broken, fd=%d", sock_fd);
                goto end;
            }
            recv_len += (recv_ret > 0 ? recv_ret : 0);
        }
        if (static_cast<int>(recv_len) < g_test_codec_ctx->head_min_size) {
            yf_log_error(YF_LOG_ERR, r->log, 0, "recv errrrrr, fd=%d, recv size=%d",
                    sock_fd, static_cast<int>(recv_len));
            goto end;
        }

        // pkg len
        pkg_size = 0;
#define __GET_LEN(_b, _t, _s) TDR_GET_UINT_NET(_t, _s.unitsize, _b + _s.offset)

        if (g_test_codec_ctx->pkg_len.offset != TDR_INVALID_OFFSET) {
            __GET_LEN(rbuf, pkg_size, g_test_codec_ctx->pkg_len);
        } else {
            __GET_LEN(rbuf, head_size, g_test_codec_ctx->head_len);
            __GET_LEN(rbuf, pkg_size, g_test_codec_ctx->body_len);
            pkg_size += head_size;
        }
        TEST_ASSERT(static_cast<int>(pkg_size) >= g_test_codec_ctx->head_min_size
            && pkg_size <= g_test_codec_ctx->pkg_netsize_max);

        // pkg all
        if (recv_len < pkg_size) {
            recv_ret = recvn(sock_fd, rbuf + recv_len,
                pkg_size - recv_len,
                0);
            recv_len += (recv_ret > 0 ? recv_ret : 0);
        }
        if (recv_len < pkg_size) {
            yf_log_error(YF_LOG_ERR, r->log, 0,
                    "recv errrrrr, fd=%d, recv_len=%d, pkg_size=%d",
                    sock_fd, static_cast<int>(recv_len), static_cast<int>(pkg_size));
            goto end;
        }

        // decode
        net_data.pszBuff = rbuf;
        host_data.pszBuff = reinterpret_cast<char*>(&req_msg);
        net_data.iBuff = pkg_size;
        host_data.iBuff = sizeof(req_msg);
        ret = tdr_ntoh(g_test_codec_ctx->pkg_meta, &host_data, &net_data,
                tdr_get_metalib_version(g_test_codec_ctx->metalib));
        TEST_ASSERT(ret == 0);

        // biz process
        resp_msg.Head = req_msg.Head;
        if (req_msg.Head.Cmd == TEST_CMD_GET_ROLES_REQ) {
            // biz
            uint16_t rsp_num = yf_max(1,
                    yf_min(req_msg.Body.GetRolesReq.num, TEST_MAX_ID_NUM));
            service_trans_test_set_idlist(&req_msg, rsp_num);

            _SEND_RSP(resp_msg, TEST_CMD_GET_ROLES_RSP, 2);

            // yf_log_debug(YF_LOG_DEBUG, r->log, 0, "recv roles req, num=%u", rsp_num);

            if (random() % 512 == 0 && disconn_sent_time == 0) {
                yf_log_error(YF_LOG_INFO, r->log, 0,
                        "try to disconn, sockfd=%d", sock_fd);
                _SEND_RSP(resp_msg, TEST_CMD_DISCONN_REQ, 1);
                disconn_sent_time = yf_now_times.clock_time.tv_sec;
            }
        } else if (req_msg.Head.Cmd == TEST_CMD_DISCONN_RSP) {
            yf_log_error(YF_LOG_INFO, r->log, 0,
                    "client notified, can disconn, sockfd=%d", sock_fd);

            sleep(3);
            goto end;
        } else if (req_msg.Head.Cmd == TEST_CMD_GET_ROLES_RSP) {
            _SEND_RSP(req_msg, TEST_CMD_GET_ROLES_RSP, 2);
        } else {
            yf_log_error(YF_LOG_WARN, r->log, 0, "unreconisged req cmd=%d",
                    req_msg.Head.Cmd);
            TEST_ASSERT(0);
        }

        // next pkg
        memmove(rbuf, rbuf + pkg_size, recv_len - pkg_size);
        recv_len -= pkg_size;

        if (disconn_sent_time && yf_now_times.clock_time.tv_sec - disconn_sent_time > 60) {
            yf_log_error(YF_LOG_WARN, r->log, 0, "sockfd=%d disconn err",
                    sock_fd);
            TEST_ASSERT(0);
        }
    }

end:
    free(rbuf);
    free(wbuf);
    yfr_close(sock_fd);
    return 0;
}

static yf_int_t service_trans_test_accept_coroutine(yfr_coroutine_t* r) {
    int* plisten_fd = reinterpret_cast<int*>(r->arg);
    int listen_fd = *plisten_fd;

    int ret;
    yf_nonblocking(listen_fd);
    ret = yfr_coroutine_open(listen_fd, SOCK_STREAM);
    TEST_ASSERT(ret == 0);

    yfr_coroutine_t* coroutine = NULL;
    struct sockaddr_in remote_addr;
    socklen_t sock_len;

    int fd = 0;
    while (1) {
        sock_len = sizeof(remote_addr);
        fd = yfr_accept(listen_fd, (struct sockaddr*)&remote_addr, &sock_len);
        if (fd < 0) {
            yf_log_error(YF_LOG_WARN, g_test_log, errno, "accept fd error");
            goto error;
        }

        yf_log_error(YF_LOG_INFO, r->log, 0,
                     "new conn, fd=%d, remote port=%d",
                     fd, static_cast<int>(ntohs(remote_addr.sin_port)));

        coroutine = yfr_coroutine_create(g_test_coroutine_mgr,
                        service_trans_test_on_new_conn, NULL, g_test_log);
        if (coroutine == NULL) {
            yf_log_error(YF_LOG_WARN, g_test_log, 0, "create coroutine failed");
            goto error;
        }

        coroutine->data = (yf_u32_t)fd;
        continue;

error:
        if (fd >= 0) {
            yfr_close(fd);
        }
        yfr_usleep(10000);  // 10ms
    }

    return 0;
}


void service_trans_test_svr() {
    int ret;
    yf_pagesize = getpagesize();
    yf_cpuinfo();
    ret = yf_init_threads(4, 512 * 1024, 1, NULL);
    assert(ret == YF_OK);
    yf_init_bit_indexs();

    yf_log_t* log = yf_log_open(YF_LOG_DEBUG, 8192, NULL);
    g_test_log = log;

    yf_init_time(log);
    yf_update_time(NULL, NULL, log);

    ret = yf_strerror_init();
    TEST_ASSERT(ret == YF_OK);
    ret = yf_init_processs(log);
    TEST_ASSERT(ret == YF_OK);

    int fd_num_max = YF_ARRAY_SIZE(g_test_ports) * 8 + 128;
    size_t coroutine_num_min = fd_num_max;

    yf_evt_driver_init_t driver_init = {0, fd_num_max, fd_num_max * 2,
                                        log, NULL, NULL, NULL, NULL,
                                        NULL};

    driver_init.poll_cb = service_test_svr_coroutine;

    yf_evt_driver_t* evt_driver = yf_evt_driver_create(&driver_init);
    TEST_ASSERT(evt_driver != NULL);

    // init global coroutine set
    ret = yfr_coroutine_global_set(coroutine_num_min + 24,
                                   512 * 1024, 0, log);
    TEST_ASSERT(ret == 0);

    // init coroutine mgr->hm.coroutine_mgr
    yfr_coroutine_init_t init_info = {coroutine_num_min + 24, 16, 64, evt_driver};
    g_test_coroutine_mgr = yfr_coroutine_mgr_create(&init_info, log);

    yfr_syscall_coroutine_attach(g_test_coroutine_mgr, log);

    yf_log_file_add_handle(log, 'r', yfr_coroutine_log);

    yfr_coroutine_t* coroutine;
    for (size_t i = 0; i < YF_ARRAY_SIZE(g_test_listenfds); ++i) {
        coroutine = yfr_coroutine_create(g_test_coroutine_mgr,
                        service_trans_test_accept_coroutine,
                        g_test_listenfds + i, log);
        TEST_ASSERT(coroutine);
    }

    // start evt driver
    yf_evt_driver_start(evt_driver);
}


static struct timeval g_test_tv;
static cross_service_trans_mgr_t* g_test_trans_mgr = NULL;
static int g_test_req_cnt = 0;
static std::map<uint16_t, std::set<uint64_t> >  g_test_addr_channel_ref;
static LPTLOGCATEGORYINST g_test_log_category = NULL;
static std::set<uint32_t> g_test_seqids;

void service_trans_test_on_channel_open(cross_service_info_t* service_info,
        cross_service_addr_t* addr, uint64_t channel_id) {
    uint16_t port = ntohs(addr->port);
    std::set<uint64_t>& channels = g_test_addr_channel_ref[port];
    channels.insert(channel_id);
    tlog_info(g_test_log_category, 0, 0, "trans addr connected, port=%u,np=%u",
            port, addr->port);
}

void service_trans_test_on_channel_closed(cross_service_info_t* service_info,
        cross_service_addr_t* addr, uint64_t channel_id) {
    uint16_t port = ntohs(addr->port);
    std::set<uint64_t>& channels = g_test_addr_channel_ref[port];
    channels.erase(channel_id);

    tlog_info(g_test_log_category, 0, 0, "trans addr disconnected, port=%u,np=%u",
            port, addr->port);
}


// if ret < 0, will close this channel
int service_trans_test_on_msg(cross_service_info_t* service_info,
        cross_service_addr_t* addr, uint64_t channel_id,
        void* msg, size_t msg_len) {
    TEST_ASSERT(msg_len >= sizeof(tagTestPkg));
    tagTestPkg* svr_msg = reinterpret_cast<tagTestPkg*>(msg);
    tagTestPkg resp_msg;
    int ret;

    SERVICE_TRANS_TEST_SETMAGIC(resp_msg);

    if (svr_msg->Head.Cmd == TEST_CMD_DISCONN_REQ) {
        tlog_info(g_test_log_category, 0, 0, "recv disconn req, need to stop channel");

        resp_msg.Head.Cmd = TEST_CMD_DISCONN_RSP;
        for (int i = 0; i < 100; ++i) {
            ret = cross_service_channel_send_msg(g_test_trans_mgr, channel_id,
                    &resp_msg, sizeof(resp_msg));
            if (ret == CROSS_SERVICE_SEND_WBUF_FULL) {
                usleep(5000);
                continue;
            } else if (ret == CROSS_SERVICE_SEND_SUCCESS) {
                break;
            } else {
                tlog_info(g_test_log_category, 0, 0, "send disconn resp errrrrr");
                break;
            }
        }

        ret = cross_service_channel_close(g_test_trans_mgr, channel_id);
        TEST_ASSERT(ret == 0);
        // ;
    } else if (svr_msg->Head.Cmd == TEST_CMD_GET_ROLES_RSP) {
        std::set<uint32_t>::iterator iter = g_test_seqids.find(svr_msg->Head.MsgSeqID);
        if (iter == g_test_seqids.end()) {
            return 0;
        }

        g_test_seqids.erase(iter);

        tlog_info(g_test_log_category, 0, 0, "recv resp(%u), rest to recv resp(%u)",
                static_cast<uint32_t>(svr_msg->Head.MsgSeqID),
                static_cast<uint32_t>(g_test_seqids.size()));

        int rsp_num = svr_msg->Body.GetRolesRsp.num;
        uint32_t sum_val = 0;
        for (int i = 0; i < rsp_num - 1; ++i) {
            sum_val += svr_msg->Body.GetRolesRsp.roleid_list[i];
        }
        uint32_t cmp_val = svr_msg->Body.GetRolesRsp.roleid_list[rsp_num - 1];
        TEST_ASSERT(cmp_val == sum_val);
    } else {
        TEST_ASSERT(0);
    }
    return 0;
}


void service_trans_test_client() {
    int ret;
    for (size_t i = 0; i < YF_ARRAY_SIZE(g_test_listenfds); ++i) {
        close(g_test_listenfds[i]);
        g_test_listenfds[i] = 0;
    }

    LPTLOGCTX log_ctx = tlog_init_from_file(".test_log_cfg.xml");

    g_test_log_category = tlog_get_category(log_ctx, "texttrace");
    TEST_ASSERT(g_test_log_category != NULL);

    g_test_trans_mgr = cross_service_trans_mgr_init(
        YF_ARRAY_SIZE(g_test_listenfds) * 6, &g_test_tv, g_test_log_category);
    TEST_ASSERT(g_test_trans_mgr);

    cross_service_info_t service_info;
    bzero(&service_info, sizeof(service_info));

    service_info.max_conn = 3;
    service_info.write_buf_size = 4096;
    service_info.pkg_sinfo = g_test_service_pkg_sinfo;
    service_info.route_type = SERVICE_ROUTE_RANDOM;
    service_info.handler.on_channel_open = service_trans_test_on_channel_open;
    service_info.handler.on_channel_closed = service_trans_test_on_channel_closed;
    service_info.handler.on_channel_msg = service_trans_test_on_msg;

    std::vector<uint16_t> addr_to_add;
    std::vector<uint16_t> addr_added;

    for (size_t i = 0; i < TEST_PORT_NUM; ++i) {
        addr_to_add.push_back(g_test_ports[i]);
    }

    cross_service_addr_t service_addr;
    service_addr.ip = INADDR_ANY;
    service_addr.type = SOCK_STREAM;

    tagTestPkg req_msg;
    SERVICE_TRANS_TEST_SETMAGIC(req_msg);
    uint32_t seq_id = time(NULL);

    while (1) {
        gettimeofday(&g_test_tv, NULL);

        if (addr_to_add.size() * 2 > TEST_PORT_NUM
            || (!addr_to_add.empty() && random() % 512 == 0)) {
            std::random_shuffle(addr_to_add.begin(), addr_to_add.end());

            int index = random() % addr_to_add.size();
            service_addr.port = htons(addr_to_add[index]);
            tlog_info(g_test_log_category, 0, 0, "trans addr added, port=%d", addr_to_add[index]);

            ret = cross_service_trans_add(g_test_trans_mgr,
                    &service_info, g_test_codec_ctx, &service_addr);
            TEST_ASSERT(ret == 0);

            addr_added.push_back(addr_to_add[index]);
            addr_to_add.erase(addr_to_add.begin() + index);

            usleep(1000);
        }

        if (addr_added.size() > 1 && random() % 512 == 0) {
            std::random_shuffle(addr_added.begin(), addr_added.end());

            int index = random() % addr_added.size();
            service_addr.port = htons(addr_added[index]);

            ret = cross_service_trans_del(g_test_trans_mgr, &service_addr);
            TEST_ASSERT(ret == 0);

            tlog_info(g_test_log_category, 0, 0, "trans addr deled, port=%d", addr_added[index]);

            addr_to_add.push_back(addr_added[index]);
            addr_added.erase(addr_added.begin() + index);
        }

        cross_service_trans_mgr_proc(g_test_trans_mgr);
        int idnum = random() % TEST_MAX_ID_NUM;
        idnum = yf_max(idnum, 1);

        if (random() % 2) {
            req_msg.Head.Cmd = TEST_CMD_GET_ROLES_REQ;
            req_msg.Body.GetRolesReq.num = idnum;
        } else {
            req_msg.Head.Cmd = TEST_CMD_GET_ROLES_RSP;
            service_trans_test_set_idlist(&req_msg, idnum);
        }
        req_msg.Head.MsgSeqID = ++seq_id;

        int index = random() % addr_added.size();
        uint16_t target_port = addr_added[index];

        std::set<uint64_t>& channels = g_test_addr_channel_ref[target_port];
        if (channels.empty()) {
            tlog_info(g_test_log_category, 0, 0, "trans addr(p=%u) no conn, jump", target_port);
        } else {
            service_addr.port = htons(target_port);
            ret = cross_service_trans_send(g_test_trans_mgr, &service_addr,
                    &req_msg, sizeof(req_msg));

            switch (ret) {
                case CROSS_SERVICE_SEND_SUCCESS:
                    g_test_seqids.insert(seq_id);
                    tlog_info(g_test_log_category, 0, 0, "send req(%u), cmd(%u)",
                            seq_id, req_msg.Head.Cmd);
                    break;
                case CROSS_SERVICE_SEND_WBUF_FULL:
                    tlog_info(g_test_log_category, 0, 0, "send req, buf full");
                    break;
                default:
                    tlog_error(g_test_log_category, 0, 0, "send req errrrrrrr....");
                    // TEST_ASSERT(0);
                    break;
            }

            if (++g_test_req_cnt > 200000) {
                break;
            }
        }

        usleep(1000 * (random() % 8));
    }
}


TEST(ServiceTransTest, test_service) {
    srandom(time(NULL));
    g_test_codec_ctx = cross_service_codec_ctx_init(
            &g_test_service_pkg_sinfo);

    yf_set_sig_handler(SIGPIPE, SIG_IGN, NULL);
    service_trans_test_ports_init();

    pid_t svr_proc_pid = fork();
    if (svr_proc_pid == 0) {
        // child, svr
        service_trans_test_svr();
    } else {
        // parent, client
        service_trans_test_client();
    }
}


#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>


TEST(ServiceTransTest, test_ioctl) {
    int inet_sock;
    struct ifreq ifr;
    inet_sock = socket(AF_INET, SOCK_DGRAM, 0);
    assert(inet_sock >= 0);

    char local_inner_ip[16];

    strcpy(ifr.ifr_name, "eth1");
    int ret = ioctl(inet_sock, SIOCGIFADDR, &ifr);
    if (ret == 0) {
        if (inet_ntop(AF_INET, (char*)&((struct sockaddr_in*)&(ifr.ifr_addr))->sin_addr,
                local_inner_ip, sizeof(local_inner_ip)) == NULL) {
            local_inner_ip[0] = 0;
            printf("get eth1 ip failed\n");
        } else {
            printf("get eth1 ip success (%s)\n", local_inner_ip);
        }
    } else {
        local_inner_ip[0] = 0;
        int err = errno;
        printf("ioctl failed, errno=%d, errstr=%s\n", err, strerror(err));
    }

    int fds[2];
    ret = socketpair(AF_LOCAL, SOCK_STREAM, 0, fds);
    ASSERT_EQ(ret, 0);

    int nb = 1;
    ret = ioctl(fds[0], FIONBIO, &nb);
    if (ret != 0) {
        printf("ioctl fd=%d nb=%d failed, errno=%d:%s\n", fds[0], nb, errno, strerror(errno));
    }
    ASSERT_EQ(ret, 0);

    char buf[64];
    ret  = read(fds[0], buf, sizeof(buf));
    int errno_ret = errno;
    printf("read 0 ret=%d, errno=%d\n", ret, errno_ret);
    ASSERT_EQ(ret, -1);
    ASSERT_EQ(errno_ret, EAGAIN);
}


