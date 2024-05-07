












#include<stdio.h>
#include<setjmp.h>

#include<assert.h>

#include<stdarg.h>
#include<stdint.h>

#       define LUA_HAVE_PCRE_JIT 1
#   define MD5_DIGEST_LENGTH 16
#       define NGX_HAVE_SHA1 1
#define NGX_HTTP_LUA_CONTEXT_ACCESS         0x0004
#define NGX_HTTP_LUA_CONTEXT_BALANCER       0x0200
#define NGX_HTTP_LUA_CONTEXT_BODY_FILTER    0x0040
#define NGX_HTTP_LUA_CONTEXT_CONTENT        0x0008
#define NGX_HTTP_LUA_CONTEXT_HEADER_FILTER  0x0020
#define NGX_HTTP_LUA_CONTEXT_INIT_WORKER    0x0100
#define NGX_HTTP_LUA_CONTEXT_LOG            0x0010
#define NGX_HTTP_LUA_CONTEXT_REWRITE        0x0002
#define NGX_HTTP_LUA_CONTEXT_SET            0x0001
#define NGX_HTTP_LUA_CONTEXT_SSL_CERT       0x0400
#define NGX_HTTP_LUA_CONTEXT_SSL_SESS_FETCH 0x1000
#define NGX_HTTP_LUA_CONTEXT_SSL_SESS_STORE 0x0800
#define NGX_HTTP_LUA_CONTEXT_TIMER          0x0080
#define NGX_HTTP_LUA_FFI_BAD_CONTEXT        -101
#define NGX_HTTP_LUA_FFI_NO_REQ_CTX         -100
#define NGX_HTTP_LUA_FILE_KEY_LEN                                            \
    (NGX_HTTP_LUA_FILE_TAG_LEN + 2 * MD5_DIGEST_LENGTH)
#define NGX_HTTP_LUA_FILE_TAG "nhlf_"
#define NGX_HTTP_LUA_FILE_TAG_LEN                                            \
    (sizeof(NGX_HTTP_LUA_FILE_TAG) - 1)
#define NGX_HTTP_LUA_INLINE_KEY_LEN                                          \
    (NGX_HTTP_LUA_INLINE_TAG_LEN + 2 * MD5_DIGEST_LENGTH)
#define NGX_HTTP_LUA_INLINE_TAG "nhli_"
#define NGX_HTTP_LUA_INLINE_TAG_LEN                                          \
    (sizeof(NGX_HTTP_LUA_INLINE_TAG) - 1)
#   define NGX_HTTP_LUA_MAX_ARGS 100
#   define NGX_HTTP_LUA_MAX_HEADERS 100
#   define NGX_HTTP_LUA_USE_OCSP 1
#   define NGX_HTTP_PERMANENT_REDIRECT 308

#   define ngx_http_lua_assert(a)  assert(a)
#   define ngx_http_lua_lightudata_mask(ludata)                              \
        ((void *) ((uintptr_t) (&ngx_http_lua_##ludata) & ((1UL << 47) - 1)))


#define NGX_HTTP_LUA_ESCAPE_HEADER_NAME  7
#define NGX_HTTP_LUA_ESCAPE_HEADER_VALUE  8
#   define NGX_HTTP_SWITCHING_PROTOCOLS 101
#   define NGX_UNESCAPE_URI_COMPONENT 0

#define ngx_http_lua_check_context(L, ctx, flags)                            \
    if (!((ctx)->context & (flags))) {                                       \
        return luaL_error(L, "API disabled in the context of %s",            \
                          ngx_http_lua_context_name((ctx)->context));        \
    }
#define ngx_http_lua_check_fake_request(L, r)                                \
    if ((r)->connection->fd == (ngx_socket_t) -1) {                          \
        return luaL_error(L, "API disabled in the current context");         \
    }
#define ngx_http_lua_check_fake_request2(L, r, ctx)                          \
    if ((r)->connection->fd == (ngx_socket_t) -1) {                          \
        return luaL_error(L, "API disabled in the context of %s",            \
                          ngx_http_lua_context_name((ctx)->context));        \
    }
#define ngx_http_lua_check_if_abortable(L, ctx)                              \
    if ((ctx)->no_abort) {                                                   \
        return luaL_error(L, "attempt to abort with pending subrequests");   \
    }
#define ngx_http_lua_context_name(c)                                         \
    ((c) == NGX_HTTP_LUA_CONTEXT_SET ? "set_by_lua*"                         \
     : (c) == NGX_HTTP_LUA_CONTEXT_REWRITE ? "rewrite_by_lua*"               \
     : (c) == NGX_HTTP_LUA_CONTEXT_ACCESS ? "access_by_lua*"                 \
     : (c) == NGX_HTTP_LUA_CONTEXT_CONTENT ? "content_by_lua*"               \
     : (c) == NGX_HTTP_LUA_CONTEXT_LOG ? "log_by_lua*"                       \
     : (c) == NGX_HTTP_LUA_CONTEXT_HEADER_FILTER ? "header_filter_by_lua*"   \
     : (c) == NGX_HTTP_LUA_CONTEXT_BODY_FILTER ? "body_filter_by_lua*"       \
     : (c) == NGX_HTTP_LUA_CONTEXT_TIMER ? "ngx.timer"                       \
     : (c) == NGX_HTTP_LUA_CONTEXT_INIT_WORKER ? "init_worker_by_lua*"       \
     : (c) == NGX_HTTP_LUA_CONTEXT_BALANCER ? "balancer_by_lua*"             \
     : (c) == NGX_HTTP_LUA_CONTEXT_SSL_CERT ? "ssl_certificate_by_lua*"      \
     : (c) == NGX_HTTP_LUA_CONTEXT_SSL_SESS_STORE ?                          \
                                                 "ssl_session_store_by_lua*" \
     : (c) == NGX_HTTP_LUA_CONTEXT_SSL_SESS_FETCH ?                          \
                                                 "ssl_session_fetch_by_lua*" \
     : "(unknown)")
#define ngx_http_lua_ctx_tables_key  "ngx_lua_ctx_tables"
#define ngx_http_lua_hash_literal(s)                                         \
    ngx_http_lua_hash_str((u_char *) s, sizeof(s) - 1)
#define ngx_http_lua_req_key  "__ngx_req"
#define ngx_http_lua_ssl_get_ctx(ssl_conn)                                   \
    SSL_get_ex_data(ssl_conn, ngx_http_lua_ssl_ctx_index)

#       define dd(...) fprintf(stderr, "lua *** %s: ", __func__);            \
            fprintf(stderr, __VA_ARGS__);                                    \
            fprintf(stderr, " at %s line %d.\n", "__FILE__", "__LINE__")
#define dd_check_read_event_handler(r)                                       \
    dd("r->read_event_handler = %s",                                         \
        r->read_event_handler == ngx_http_block_reading ?                    \
            "ngx_http_block_reading" :                                       \
        r->read_event_handler == ngx_http_test_reading ?                     \
            "ngx_http_test_reading" :                                        \
        r->read_event_handler == ngx_http_request_empty_handler ?            \
            "ngx_http_request_empty_handler" : "UNKNOWN")
#define dd_check_write_event_handler(r)                                      \
    dd("r->write_event_handler = %s",                                        \
        r->write_event_handler == ngx_http_handler ?                         \
            "ngx_http_handler" :                                             \
        r->write_event_handler == ngx_http_core_run_phases ?                 \
            "ngx_http_core_run_phases" :                                     \
        r->write_event_handler == ngx_http_request_empty_handler ?           \
            "ngx_http_request_empty_handler" : "UNKNOWN")

