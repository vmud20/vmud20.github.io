




#include<zlib.h>



#define NGX_HTTP_FLUSH  2
#define NGX_HTTP_LAST   1

#define ngx_http_ephemeral(r)  (void *) (&r->uri_start)
#define ngx_http_get_module_ctx(r, module)  (r)->ctx[module.ctx_index]
#define ngx_http_set_ctx(r, c, module)      r->ctx[module.ctx_index] = c;
#define NGX_HTTP_CACHE_BYPASS        2
#define NGX_HTTP_CACHE_EXPIRED       3
#define NGX_HTTP_CACHE_HIT           6
#define NGX_HTTP_CACHE_KEY_LEN       16
#define NGX_HTTP_CACHE_MISS          1
#define NGX_HTTP_CACHE_SCARCE        7
#define NGX_HTTP_CACHE_STALE         4
#define NGX_HTTP_CACHE_UPDATING      5

#define NGX_SPDY_CTL_BIT              1
#define NGX_SPDY_DATA_DISCARD         1
#define NGX_SPDY_DATA_ERROR           2
#define NGX_SPDY_DATA_INTERNAL_ERROR  3
#define NGX_SPDY_FLAG_CLEAR_SETTINGS  0x01
#define NGX_SPDY_FLAG_FIN             0x01
#define NGX_SPDY_FLAG_UNIDIRECTIONAL  0x02
#define NGX_SPDY_FRAME_HEADER_SIZE    8
#define NGX_SPDY_GOAWAY               7
#define NGX_SPDY_GOAWAY_SIZE          4
#define NGX_SPDY_HEADERS              8
#define NGX_SPDY_HIGHEST_PRIORITY     0
#define NGX_SPDY_LOWEST_PRIORITY      3
#define NGX_SPDY_MAX_FRAME_SIZE       ((1 << 24) - 1)
#define NGX_SPDY_NOOP                 5
#define NGX_SPDY_NPN_ADVERTISE        "\x06spdy/2"
#define NGX_SPDY_NPN_NEGOTIATED       "spdy/2"
#define NGX_SPDY_NV_NLEN_SIZE         2
#define NGX_SPDY_NV_NUM_SIZE          2
#define NGX_SPDY_NV_VLEN_SIZE         2
#define NGX_SPDY_PING                 6
#define NGX_SPDY_PING_SIZE            4
#define NGX_SPDY_RST_STREAM           3
#define NGX_SPDY_RST_STREAM_SIZE      8
#define NGX_SPDY_SETTINGS             4
#define NGX_SPDY_SETTINGS_IDF_SIZE    4
#define NGX_SPDY_SETTINGS_NUM_SIZE    4
#define NGX_SPDY_SETTINGS_PAIR_SIZE                                           \
    (NGX_SPDY_SETTINGS_IDF_SIZE + NGX_SPDY_SETTINGS_VAL_SIZE)
#define NGX_SPDY_SETTINGS_VAL_SIZE    4
#define NGX_SPDY_SID_SIZE             4
#define NGX_SPDY_STATE_BUFFER_SIZE    16
#define NGX_SPDY_SYN_REPLY            2
#define NGX_SPDY_SYN_REPLY_SIZE       6
#define NGX_SPDY_SYN_STREAM           1
#define NGX_SPDY_SYN_STREAM_SIZE      10
#define NGX_SPDY_VERSION              2

#define ngx_spdy_ctl_frame_head(t)                                            \
    ((uint32_t) NGX_SPDY_CTL_BIT << 31 | NGX_SPDY_VERSION << 16 | (t))
#define ngx_spdy_frame_aligned_write_uint16(p, s)                             \
    (*(uint16_t *) (p) = htons((uint16_t) (s)), (p) + sizeof(uint16_t))
#define ngx_spdy_frame_aligned_write_uint32(p, s)                             \
    (*(uint32_t *) (p) = htonl((uint32_t) (s)), (p) + sizeof(uint32_t))
#define ngx_spdy_frame_write_flags_and_len(p, f, l)                           \
    ngx_spdy_frame_aligned_write_uint32(p, (f) << 24 | (l))
#define ngx_spdy_frame_write_head(p, t)                                       \
    ngx_spdy_frame_aligned_write_uint32(p, ngx_spdy_ctl_frame_head(t))
#define ngx_spdy_frame_write_sid  ngx_spdy_frame_aligned_write_uint32
#define ngx_spdy_frame_write_uint16  ngx_spdy_frame_aligned_write_uint16
#define ngx_spdy_frame_write_uint32  ngx_spdy_frame_aligned_write_uint32
#define NGX_HTTP_AIO_OFF                0
#define NGX_HTTP_AIO_ON                 1
#define NGX_HTTP_AIO_SENDFILE           2
#define NGX_HTTP_GZIP_PROXIED_ANY       0x0200
#define NGX_HTTP_GZIP_PROXIED_AUTH      0x0100
#define NGX_HTTP_GZIP_PROXIED_EXPIRED   0x0004
#define NGX_HTTP_GZIP_PROXIED_NO_CACHE  0x0008
#define NGX_HTTP_GZIP_PROXIED_NO_ETAG   0x0080
#define NGX_HTTP_GZIP_PROXIED_NO_LM     0x0040
#define NGX_HTTP_GZIP_PROXIED_NO_STORE  0x0010
#define NGX_HTTP_GZIP_PROXIED_OFF       0x0002
#define NGX_HTTP_GZIP_PROXIED_PRIVATE   0x0020
#define NGX_HTTP_IMS_BEFORE             2
#define NGX_HTTP_IMS_EXACT              1
#define NGX_HTTP_IMS_OFF                0
#define NGX_HTTP_KEEPALIVE_DISABLE_MSIE6   0x0004
#define NGX_HTTP_KEEPALIVE_DISABLE_NONE    0x0002
#define NGX_HTTP_KEEPALIVE_DISABLE_SAFARI  0x0008
#define NGX_HTTP_LINGERING_ALWAYS       2
#define NGX_HTTP_LINGERING_OFF          0
#define NGX_HTTP_LINGERING_ON           1
#define NGX_HTTP_SATISFY_ALL            0
#define NGX_HTTP_SATISFY_ANY            1

#define ngx_http_clear_accept_ranges(r)                                       \
                                                                              \
    r->allow_ranges = 0;                                                      \
    if (r->headers_out.accept_ranges) {                                       \
        r->headers_out.accept_ranges->hash = 0;                               \
        r->headers_out.accept_ranges = NULL;                                  \
    }
#define ngx_http_clear_content_length(r)                                      \
                                                                              \
    r->headers_out.content_length_n = -1;                                     \
    if (r->headers_out.content_length) {                                      \
        r->headers_out.content_length->hash = 0;                              \
        r->headers_out.content_length = NULL;                                 \
    }
#define ngx_http_clear_etag(r)                                                \
                                                                              \
    if (r->headers_out.etag) {                                                \
        r->headers_out.etag->hash = 0;                                        \
        r->headers_out.etag = NULL;                                           \
    }
#define ngx_http_clear_last_modified(r)                                       \
                                                                              \
    r->headers_out.last_modified_time = -1;                                   \
    if (r->headers_out.last_modified) {                                       \
        r->headers_out.last_modified->hash = 0;                               \
        r->headers_out.last_modified = NULL;                                  \
    }
#define ngx_http_clear_location(r)                                            \
                                                                              \
    if (r->headers_out.location) {                                            \
        r->headers_out.location->hash = 0;                                    \
        r->headers_out.location = NULL;                                       \
    }


#define NGX_HTTP_UPSTREAM_BACKUP        0x0020
#define NGX_HTTP_UPSTREAM_CREATE        0x0001
#define NGX_HTTP_UPSTREAM_DOWN          0x0010
#define NGX_HTTP_UPSTREAM_FAIL_TIMEOUT  0x0008
#define NGX_HTTP_UPSTREAM_FT_BUSY_LOCK       0x00000400
#define NGX_HTTP_UPSTREAM_FT_ERROR           0x00000002
#define NGX_HTTP_UPSTREAM_FT_HTTP_404        0x00000100
#define NGX_HTTP_UPSTREAM_FT_HTTP_500        0x00000010
#define NGX_HTTP_UPSTREAM_FT_HTTP_502        0x00000020
#define NGX_HTTP_UPSTREAM_FT_HTTP_503        0x00000040
#define NGX_HTTP_UPSTREAM_FT_HTTP_504        0x00000080
#define NGX_HTTP_UPSTREAM_FT_INVALID_HEADER  0x00000008
#define NGX_HTTP_UPSTREAM_FT_MAX_WAITING     0x00000800
#define NGX_HTTP_UPSTREAM_FT_NOLIVE          0x40000000
#define NGX_HTTP_UPSTREAM_FT_OFF             0x80000000
#define NGX_HTTP_UPSTREAM_FT_STATUS          (NGX_HTTP_UPSTREAM_FT_HTTP_500  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_502  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_503  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_504  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_404)
#define NGX_HTTP_UPSTREAM_FT_TIMEOUT         0x00000004
#define NGX_HTTP_UPSTREAM_FT_UPDATING        0x00000200
#define NGX_HTTP_UPSTREAM_IGN_CACHE_CONTROL  0x00000010
#define NGX_HTTP_UPSTREAM_IGN_EXPIRES        0x00000008
#define NGX_HTTP_UPSTREAM_IGN_SET_COOKIE     0x00000020
#define NGX_HTTP_UPSTREAM_IGN_XA_BUFFERING   0x00000080
#define NGX_HTTP_UPSTREAM_IGN_XA_CHARSET     0x00000100
#define NGX_HTTP_UPSTREAM_IGN_XA_EXPIRES     0x00000004
#define NGX_HTTP_UPSTREAM_IGN_XA_LIMIT_RATE  0x00000040
#define NGX_HTTP_UPSTREAM_IGN_XA_REDIRECT    0x00000002
#define NGX_HTTP_UPSTREAM_INVALID_HEADER     40
#define NGX_HTTP_UPSTREAM_MAX_FAILS     0x0004
#define NGX_HTTP_UPSTREAM_WEIGHT        0x0002

#define ngx_http_conf_upstream_srv_conf(uscf, module)                         \
    uscf->srv_conf[module.ctx_index]

#define NGX_HTTPS_CERT_ERROR               495
#define NGX_HTTPS_NO_CERT                  496
#define NGX_HTTP_ACCEPTED                  202
#define NGX_HTTP_BAD_GATEWAY               502
#define NGX_HTTP_BAD_REQUEST               400
#define NGX_HTTP_CLIENT_CLOSED_REQUEST     499
#define NGX_HTTP_CLIENT_ERROR              10
#define NGX_HTTP_CLOSE                     444
#define NGX_HTTP_CONFLICT                  409
#define NGX_HTTP_CONNECTION_CLOSE          1
#define NGX_HTTP_CONNECTION_KEEP_ALIVE     2
#define NGX_HTTP_CONTINUE                  100
#define NGX_HTTP_COPY                      0x0080
#define NGX_HTTP_COPY_BUFFERED             0x04
#define NGX_HTTP_CREATED                   201
#define NGX_HTTP_DELETE                    0x0020
#define NGX_HTTP_DISCARD_BUFFER_SIZE       4096
#define NGX_HTTP_FORBIDDEN                 403
#define NGX_HTTP_GATEWAY_TIME_OUT          504
#define NGX_HTTP_GET                       0x0002
#define NGX_HTTP_GZIP_BUFFERED             0x20
#define NGX_HTTP_HEAD                      0x0004
#define NGX_HTTP_INSUFFICIENT_STORAGE      507
#define NGX_HTTP_INTERNAL_SERVER_ERROR     500
#define NGX_HTTP_LC_HEADER_LEN             32
#define NGX_HTTP_LENGTH_REQUIRED           411
#define NGX_HTTP_LINGERING_BUFFER_SIZE     4096
#define NGX_HTTP_LOCK                      0x1000
#define NGX_HTTP_LOG_UNSAFE                8
#define NGX_HTTP_LOWLEVEL_BUFFERED         0xf0
#define NGX_HTTP_MAX_SUBREQUESTS           200
#define NGX_HTTP_MAX_URI_CHANGES           10
#define NGX_HTTP_MKCOL                     0x0040
#define NGX_HTTP_MOVE                      0x0100
#define NGX_HTTP_MOVED_PERMANENTLY         301
#define NGX_HTTP_MOVED_TEMPORARILY         302
#define NGX_HTTP_NGINX_CODES               494
#define NGX_HTTP_NOT_ALLOWED               405
#define NGX_HTTP_NOT_FOUND                 404
#define NGX_HTTP_NOT_IMPLEMENTED           501
#define NGX_HTTP_NOT_MODIFIED              304
#define NGX_HTTP_NO_CONTENT                204
#define NGX_HTTP_OK                        200
#define NGX_HTTP_OPTIONS                   0x0200
#define NGX_HTTP_PARSE_HEADER_DONE         1
#define NGX_HTTP_PARSE_INVALID_09_METHOD   12
#define NGX_HTTP_PARSE_INVALID_HEADER      13
#define NGX_HTTP_PARSE_INVALID_METHOD      10
#define NGX_HTTP_PARSE_INVALID_REQUEST     11
#define NGX_HTTP_PARTIAL_CONTENT           206
#define NGX_HTTP_PATCH                     0x4000
#define NGX_HTTP_POST                      0x0008
#define NGX_HTTP_PRECONDITION_FAILED       412
#define NGX_HTTP_PROCESSING                102
#define NGX_HTTP_PROPFIND                  0x0400
#define NGX_HTTP_PROPPATCH                 0x0800
#define NGX_HTTP_PUT                       0x0010
#define NGX_HTTP_RANGE_NOT_SATISFIABLE     416
#define NGX_HTTP_REQUEST_ENTITY_TOO_LARGE  413
#define NGX_HTTP_REQUEST_HEADER_TOO_LARGE  494
#define NGX_HTTP_REQUEST_TIME_OUT          408
#define NGX_HTTP_REQUEST_URI_TOO_LARGE     414
#define NGX_HTTP_SEE_OTHER                 303
#define NGX_HTTP_SERVICE_UNAVAILABLE       503
#define NGX_HTTP_SPECIAL_RESPONSE          300
#define NGX_HTTP_SSI_BUFFERED              0x01
#define NGX_HTTP_SUBREQUEST_IN_MEMORY      2
#define NGX_HTTP_SUBREQUEST_WAITED         4
#define NGX_HTTP_SUB_BUFFERED              0x02
#define NGX_HTTP_SWITCHING_PROTOCOLS       101
#define NGX_HTTP_TEMPORARY_REDIRECT        307
#define NGX_HTTP_TO_HTTPS                  497
#define NGX_HTTP_TRACE                     0x8000
#define NGX_HTTP_UNAUTHORIZED              401
#define NGX_HTTP_UNKNOWN                   0x0001
#define NGX_HTTP_UNLOCK                    0x2000
#define NGX_HTTP_UNSUPPORTED_MEDIA_TYPE    415
#define NGX_HTTP_VERSION_10                1000
#define NGX_HTTP_VERSION_11                1001
#define NGX_HTTP_VERSION_9                 9
#define NGX_HTTP_WRITE_BUFFERED            0x10
#define NGX_NONE                           1

#define ngx_http_set_connection_log(c, l)                                     \
                                                                              \
    c->log->file = l->file;                                                   \
    if (!(c->log->log_level & NGX_LOG_DEBUG_CONNECTION)) {                    \
        c->log->log_level = l->log_level;                                     \
    }
#define NGX_HTTP_LIF_CONF         0x40000000
#define NGX_HTTP_LMT_CONF         0x80000000
#define NGX_HTTP_LOC_CONF         0x08000000
#define NGX_HTTP_LOC_CONF_OFFSET   offsetof(ngx_http_conf_ctx_t, loc_conf)
#define NGX_HTTP_MAIN_CONF        0x02000000
#define NGX_HTTP_MAIN_CONF_OFFSET  offsetof(ngx_http_conf_ctx_t, main_conf)
#define NGX_HTTP_MODULE           0x50545448   
#define NGX_HTTP_SIF_CONF         0x20000000
#define NGX_HTTP_SRV_CONF         0x04000000
#define NGX_HTTP_SRV_CONF_OFFSET   offsetof(ngx_http_conf_ctx_t, srv_conf)
#define NGX_HTTP_UPS_CONF         0x10000000

#define ngx_http_conf_get_module_loc_conf(cf, module)                         \
    ((ngx_http_conf_ctx_t *) cf->ctx)->loc_conf[module.ctx_index]
#define ngx_http_conf_get_module_main_conf(cf, module)                        \
    ((ngx_http_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
#define ngx_http_conf_get_module_srv_conf(cf, module)                         \
    ((ngx_http_conf_ctx_t *) cf->ctx)->srv_conf[module.ctx_index]
#define ngx_http_cycle_get_module_main_conf(cycle, module)                    \
    (cycle->conf_ctx[ngx_http_module.index] ?                                 \
        ((ngx_http_conf_ctx_t *) cycle->conf_ctx[ngx_http_module.index])      \
            ->main_conf[module.ctx_index]:                                    \
        NULL)
#define ngx_http_get_module_loc_conf(r, module)  (r)->loc_conf[module.ctx_index]
#define ngx_http_get_module_main_conf(r, module)                             \
    (r)->main_conf[module.ctx_index]
#define ngx_http_get_module_srv_conf(r, module)  (r)->srv_conf[module.ctx_index]
#define NGX_HTTP_VAR_CHANGEABLE   1
#define NGX_HTTP_VAR_INDEXED      4
#define NGX_HTTP_VAR_NOCACHEABLE  2
#define NGX_HTTP_VAR_NOHASH       8

#define ngx_http_variable(v)     { sizeof(v) - 1, 1, 0, 0, 0, (u_char *) v }
