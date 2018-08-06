#ifndef _YFR_HEAD_H_20130227_H
#define _YFR_HEAD_H_20130227_H
/*
* copyright@: kevin_zhong, mail:qq2000zhong@gmail.com
* time: 20130227-11:34:21
*/

#include "yfr_config.h"
#include <ppc/yf_header.h>
#include <base_struct/yf_core.h>
#include <mio_driver/yf_event.h>
#include <bridge/yf_bridge.h>

#define YFR_WAIT_REC_BEGIN yf_time_t  wait_begin = yf_now_times.clock_time, wait_end

#define yfr_wait_time_left(ms) ({wait_end = yf_now_times.clock_time; \
                ms - yf_time_diff_ms(&wait_end, &wait_begin);})
                
#define yfr_wait_timeout(ms) ({wait_end = yf_now_times.clock_time; \
                ms && ms < yf_time_diff_ms(&wait_end, &wait_begin);})

#endif

