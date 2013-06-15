Name
====

yf_coroutine


Desc
====

已知的史上 功能最强大 的协程库；
最大的特点：非侵入的兼容所有的已存在的同步阻塞库--例如mysql,memcache客户端；
用阻塞的方式写socket程序！！新概念少，直接采用现有的socket api，使用异常简单；

Aim at
====
实用的协程库，实用易用，彻底改变c，c++语言svr异步和回调导致的痛苦异常的现象！

Like
====
Erlang，Go

api 包括：
1，操作系统已有的socket接口，如：
        socket, connect, listen, bind, recv, send, read, write...已有的都支持
        头文件为 syscall_hook/yfr_syscall.h
2, dns 查询接口
3, 特殊的可复用的tcp常连接api，此为此库提供的非os api
        头文件为 syscall_hook/yfr_socket_ext.h


所有的api底层都是异步的，但使用完全采用同步阻塞--即瀑布流方式即可；
现只提供头文件以及测试程序

1,2 的测试见 test/yfr_coroutine_testor.cpp，测试功能如下：
        TEST_F_INIT(CoroutineTestor, Switch);        - coroutine切换
        TEST_F_INIT(CoroutineTestor, Sleep);         - sleep api
        TEST_F_INIT(CoroutineTestor, IpcCond);       - cond api
        TEST_F_INIT(CoroutineTestor, IpcLock);       - lock api
        TEST_F_INIT(CoroutineTestor, SocketActive);  - socket api，模拟的是多个协程的wget
        TEST_F_INIT(CoroutineTestor, Dns);           - dns api，模拟多个协程同时查询不同的域名
        #ifdef HAVE_MYSQL
        TEST_F_INIT(CoroutineTestor, Mysql);         - mysql client lib test，多个协程调用mysql客户端读写mysql
        #endif

3 的测试较复杂见 test/yfr_sock_testor.cpp，测试功能是：
        一个常驻内存svr
        一个client

Author
======

name: kevin_zhong
mail: qq2000zhong@gmail.com


