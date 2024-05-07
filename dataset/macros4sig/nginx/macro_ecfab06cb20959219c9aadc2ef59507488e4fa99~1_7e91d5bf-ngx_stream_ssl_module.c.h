



#define NGX_STREAM_BAD_GATEWAY               502
#define NGX_STREAM_BAD_REQUEST               400
#define NGX_STREAM_FORBIDDEN                 403
#define NGX_STREAM_INTERNAL_SERVER_ERROR     500
#define NGX_STREAM_MAIN_CONF    0x02000000
#define NGX_STREAM_MAIN_CONF_OFFSET  offsetof(ngx_stream_conf_ctx_t, main_conf)
#define NGX_STREAM_MODULE       0x4d525453     
#define NGX_STREAM_OK                        200
#define NGX_STREAM_SERVICE_UNAVAILABLE       503
#define NGX_STREAM_SRV_CONF     0x04000000
#define NGX_STREAM_SRV_CONF_OFFSET   offsetof(ngx_stream_conf_ctx_t, srv_conf)
#define NGX_STREAM_UPS_CONF     0x08000000
#define NGX_STREAM_WRITE_BUFFERED  0x10

#define ngx_stream_conf_get_module_main_conf(cf, module)                       \
    ((ngx_stream_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
#define ngx_stream_conf_get_module_srv_conf(cf, module)                        \
    ((ngx_stream_conf_ctx_t *) cf->ctx)->srv_conf[module.ctx_index]
#define ngx_stream_cycle_get_module_main_conf(cycle, module)                   \
    (cycle->conf_ctx[ngx_stream_module.index] ?                                \
        ((ngx_stream_conf_ctx_t *) cycle->conf_ctx[ngx_stream_module.index])   \
            ->main_conf[module.ctx_index]:                                     \
        NULL)
#define ngx_stream_delete_ctx(s, module)       s->ctx[module.ctx_index] = NULL;
#define ngx_stream_get_module_ctx(s, module)   (s)->ctx[module.ctx_index]
#define ngx_stream_get_module_main_conf(s, module)                             \
    (s)->main_conf[module.ctx_index]
#define ngx_stream_get_module_srv_conf(s, module)                              \
    (s)->srv_conf[module.ctx_index]
#define ngx_stream_set_ctx(s, c, module)       s->ctx[module.ctx_index] = c;

#define ngx_stream_upstream_rr_peer_lock(peers, peer)                         \
                                                                              \
    if (peers->shpool) {                                                      \
        ngx_rwlock_wlock(&peer->lock);                                        \
    }
#define ngx_stream_upstream_rr_peer_unlock(peers, peer)                       \
                                                                              \
    if (peers->shpool) {                                                      \
        ngx_rwlock_unlock(&peer->lock);                                       \
    }



#define NGX_STREAM_UPSTREAM_BACKUP        0x0020
#define NGX_STREAM_UPSTREAM_CREATE        0x0001
#define NGX_STREAM_UPSTREAM_DOWN          0x0010
#define NGX_STREAM_UPSTREAM_FAIL_TIMEOUT  0x0008
#define NGX_STREAM_UPSTREAM_MAX_CONNS     0x0100
#define NGX_STREAM_UPSTREAM_MAX_FAILS     0x0004
#define NGX_STREAM_UPSTREAM_NOTIFY_CONNECT     0x1
#define NGX_STREAM_UPSTREAM_WEIGHT        0x0002

#define ngx_stream_conf_upstream_srv_conf(uscf, module)                       \
    uscf->srv_conf[module.ctx_index]

#define NGX_STREAM_VAR_CHANGEABLE   1
#define NGX_STREAM_VAR_INDEXED      4
#define NGX_STREAM_VAR_NOCACHEABLE  2
#define NGX_STREAM_VAR_NOHASH       8
#define NGX_STREAM_VAR_PREFIX       32
#define NGX_STREAM_VAR_WEAK         16

#define ngx_stream_null_variable  { ngx_null_string, NULL, NULL, 0, 0, 0 }
#define ngx_stream_variable(v)     { sizeof(v) - 1, 1, 0, 0, 0, (u_char *) v }

