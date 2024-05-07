



#define EPOLLRDHUP         0
#define NGX_CLEAR_EVENT    EV_CLEAR
#define NGX_CLOSE_EVENT    1
#define NGX_DISABLE_EVENT  2
#define NGX_EVENT_CONF        0x02000000
#define NGX_EVENT_MODULE      0x544E5645  
#define NGX_EXCLUSIVE_EVENT  EPOLLEXCLUSIVE
#define NGX_FLUSH_EVENT    4
#define NGX_INVALID_INDEX  0xd0d0d0d0
#define NGX_IOCP_ACCEPT      0
#define NGX_IOCP_CONNECT     2
#define NGX_IOCP_IO          1
#define NGX_LEVEL_EVENT    0
#define NGX_LOWAT_EVENT    0
#define NGX_ONESHOT_EVENT  EV_ONESHOT
#define NGX_POST_EVENTS         2
#define NGX_READ_EVENT     EVFILT_READ
#define NGX_UPDATE_TIME         1
#define NGX_USE_AIO_EVENT        0x00000100
#define NGX_USE_CLEAR_EVENT      0x00000004
#define NGX_USE_EPOLL_EVENT      0x00000040
#define NGX_USE_EVENTPORT_EVENT  0x00001000
#define NGX_USE_FD_EVENT         0x00000400
#define NGX_USE_GREEDY_EVENT     0x00000020
#define NGX_USE_IOCP_EVENT       0x00000200
#define NGX_USE_KQUEUE_EVENT     0x00000008
#define NGX_USE_LEVEL_EVENT      0x00000001
#define NGX_USE_LOWAT_EVENT      0x00000010
#define NGX_USE_ONESHOT_EVENT    0x00000002
#define NGX_USE_RTSIG_EVENT      0x00000080
#define NGX_USE_TIMER_EVENT      0x00000800
#define NGX_USE_VNODE_EVENT      0x00002000
#define NGX_VNODE_EVENT    0
#define NGX_WRITE_EVENT    EVFILT_WRITE

#define ngx_add_conn         ngx_event_actions.add_conn
#define ngx_add_event        ngx_event_actions.add
#define ngx_add_timer        ngx_event_add_timer
#define ngx_del_conn         ngx_event_actions.del_conn
#define ngx_del_event        ngx_event_actions.del
#define ngx_del_timer        ngx_event_del_timer
#define ngx_done_events      ngx_event_actions.done
#define ngx_event_get_conf(conf_ctx, module)                                  \
             (*(ngx_get_conf(conf_ctx, ngx_events_module))) [module.ctx_index]
#define ngx_event_ident(p)  ((ngx_connection_t *) (p))->fd
#define ngx_notify           ngx_event_actions.notify
#define ngx_process_events   ngx_event_actions.process_events
#define ngx_recv             ngx_io.recv
#define ngx_recv_chain       ngx_io.recv_chain
#define ngx_send             ngx_io.send
#define ngx_send_chain       ngx_io.send_chain
#define ngx_udp_recv         ngx_io.udp_recv
#define ngx_udp_send         ngx_io.udp_send
#define ngx_udp_send_chain   ngx_io.udp_send_chain

#define ngx_delete_posted_event(ev)                                           \
                                                                              \
    (ev)->posted = 0;                                                         \
    ngx_queue_remove(&(ev)->queue);                                           \
                                                                              \
    ngx_log_debug1(NGX_LOG_DEBUG_CORE, (ev)->log, 0,                          \
                   "delete posted event %p", ev);
#define ngx_post_event(ev, q)                                                 \
                                                                              \
    if (!(ev)->posted) {                                                      \
        (ev)->posted = 1;                                                     \
        ngx_queue_insert_tail(q, &(ev)->queue);                               \
                                                                              \
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, (ev)->log, 0, "post event %p", ev);\
                                                                              \
    } else  {                                                                 \
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, (ev)->log, 0,                      \
                       "update posted event %p", ev);                         \
    }
#define NGX_TIMER_INFINITE  (ngx_msec_t) -1
#define NGX_TIMER_LAZY_DELAY  300

