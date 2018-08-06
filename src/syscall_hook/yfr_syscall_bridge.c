#include "yfr_syscall.h"


typedef struct _yfr_bridge_syscall_ctx_s
{
        yf_uint_t  resp_status:2;
        yf_uint_t  error:1;
        yf_uint_t  res_len:29;
        yf_u32_t  block_id;
        yfr_coroutine_t* r;
        yf_u64_t  task_id;
        void*  res_data;
}
_yfr_bridge_syscall_ctx_t;


static void _yfr_task_res_handle(yf_bridge_t* bridge
                , void* task_res, size_t len, yf_u64_t id
                , yf_int_t status, void* data, yf_log_t* log)
{
        _yfr_bridge_syscall_ctx_t* ctx = data;
        assert(ctx->task_id == id);
        
        ctx->resp_status = status;

        if (status == YF_TASK_SUCESS)
        {
                if (ctx->res_len < len)
                {
                        ctx->error = 1;
                        yf_log_error(YF_LOG_WARN, log, 0, "resp overflow output buf, %d>%d", 
                                        len, ctx->res_len);
                }
                else if (task_res) {
                        ctx->res_len = len;
                        yf_memcpy(ctx->res_data, task_res, len);
                }
        }
        
        if (yfr_coroutine_resume(ctx->r, ctx->block_id) != 0)
        {
                yf_bridge_cxt_t* bridge_ctx = yf_bridge_ctx(bridge);
                yf_free_node_to_pool((yf_node_pool_t*)(bridge_ctx->data), 
                                ctx, log);
        }
}


yf_int_t yfr_process_bridge_task(yf_bridge_t* bridge
                , void* task, size_t len, yf_u32_t hash
                , yf_u32_t timeout_ms, void* res_data, size_t* res_len)
{
        yfr_coroutine_t* r = yfr_coroutine_addr(bridge);
        if (!yfr_coroutine_check(r))
                return YF_ERROR;
        
        yf_bridge_cxt_t* bridge_ctx = yf_bridge_ctx(bridge);
        yf_node_pool_t* ctx_pool = bridge_ctx->data;
        _yfr_bridge_syscall_ctx_t* ctx = yf_alloc_node_from_pool(ctx_pool, r->log);
        if (ctx == NULL)
        {
                yf_log_error(YF_LOG_WARN, r->log, 0, 
                                "task ctx pool used out, max_num=%d", bridge_ctx->max_task_num);
                return YF_ERROR;
        }

        yf_int_t  ret = YF_OK;
        yf_memzero(ctx, sizeof(_yfr_bridge_syscall_ctx_t));
        ctx->task_id = yf_send_task(bridge, task, len, hash, ctx, timeout_ms, r->log);
        if (ctx->task_id == (yf_u64_t)(-1))
        {
                ret = YF_ERROR;
                goto end;
        }

        if (res_len)
        {
                ctx->res_data = res_data;
                ctx->res_len = *res_len;
        }
        else {
                ctx->res_data = NULL;
                ctx->res_len = 0;
        }
        ctx->r = r;

        yfr_coroutine_block(r, &ctx->block_id);

        if (ctx->error || ctx->resp_status != YF_TASK_SUCESS)
        {
                yf_log_error(YF_LOG_WARN, r->log, 0, "task=%L resp err=%d, status=%V", 
                                ctx->task_id, ctx->error, &yf_task_rstatus_n[ctx->resp_status]);
                ret = YF_ERROR;
        }
        else if (res_len) {
                *res_len = ctx->res_len;
        }

end:
        yf_free_node_to_pool(ctx_pool, ctx, r->log);
        return  ret;
}


//bridge_ctx.data used by syscall, dont use it outside
yf_bridge_t* yfr_bridge_create(yf_bridge_cxt_t* bridge_ctx
                , yf_log_t* log)
{
        if (bridge_ctx->data != NULL)
                return NULL;

        size_t task_ctx_size = yf_node_taken_size(sizeof(_yfr_bridge_syscall_ctx_t));
        yf_node_pool_t* ctx_pool = yf_alloc(sizeof(yf_node_pool_t) + 
                        bridge_ctx->max_task_num * task_ctx_size);
        
        ctx_pool->each_taken_size = task_ctx_size;
        ctx_pool->total_num = bridge_ctx->max_task_num;
        ctx_pool->nodes_array = yf_mem_off(ctx_pool, sizeof(yf_node_pool_t));
        
        yf_init_node_pool(ctx_pool, log);
        
        bridge_ctx->data = ctx_pool;

        yf_bridge_t*  bridge = yf_bridge_create(bridge_ctx, log);
        if (bridge == NULL) {
                yf_free(ctx_pool);
        }
        return  bridge;
}


yf_int_t  yfr_bridge_destory(yf_bridge_t* bridge, yf_log_t* log)
{
        yf_bridge_cxt_t* bridge_ctx = yf_bridge_ctx(bridge);
        yf_free(bridge_ctx->data);
        
        return  yfr_bridge_destory(bridge, log);
}


yf_int_t yfr_attach_res_bridge(yf_bridge_t* bridge
                , yf_evt_driver_t* evt_driver, yf_log_t* log)
{
        return  yf_attach_res_bridge(bridge, evt_driver, 
                        _yfr_task_res_handle, log);
}


