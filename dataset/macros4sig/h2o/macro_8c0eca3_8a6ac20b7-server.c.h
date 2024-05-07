#include<stdlib.h>
#include<sys/types.h>




#include<sys/socket.h>

#include<stdint.h>
#include<string.h>
#include<stdio.h>


#include<netinet/in.h>

#include<stddef.h>
#include<inttypes.h>

#include<pthread.h>
#include<time.h>


#include<unistd.h>


#include<sys/un.h>
#include<netdb.h>
#include<arpa/inet.h>

#include<sys/time.h>

#include<errno.h>
#include<alloca.h>
#include<assert.h>

#include<sys/stat.h>










#define H2O_ALIGNOF(type) (__alignof__(type))
#define H2O_BUILD_ASSERT(condition) ((void)sizeof(char[2 * !!(!__builtin_constant_p(condition) || (condition)) - 1]))
#define H2O_GNUC_VERSION (("__GNUC__" << 16) | ("__GNUC_MINOR__" << 8) | "__GNUC_PATCHLEVEL__")
#define H2O_LIKELY(x) __builtin_expect(!!(x), 1)
#define H2O_NORETURN _Noreturn
#define H2O_RETURNS_NONNULL __attribute__((returns_nonnull))
#define H2O_STRUCT_FROM_MEMBER(s, m, p) ((s *)((char *)(p)-offsetof(s, m)))
#define H2O_TMP_FILE_TEMPLATE_MAX 256
#define H2O_TO_STR(n) H2O_TO__STR(n)
#define H2O_TO__STR(n) #n
#define H2O_UNLIKELY(x) __builtin_expect(!!(x), 0)
#define H2O_VECTOR(type)                                                                                                           \
    struct {                                                                                                                       \
        type *entries;                                                                                                             \
        size_t size;                                                                                                               \
        size_t capacity;                                                                                                           \
    }

#define h2o_error_printf(...) fprintf(stderr, __VA_ARGS__)
#define h2o_fatal(...) h2o__fatal("__FILE__", "__LINE__", __VA_ARGS__)
#define h2o_mem_alloc_pool(pool, type, cnt) h2o_mem_alloc_pool_aligned(pool, H2O_ALIGNOF(type), sizeof(type) * (cnt))
#define h2o_vector_erase(vector, index) h2o_vector__erase((h2o_vector_t *)(void *)(vector), sizeof((vector)->entries[0]), (index))
#define h2o_vector_reserve(pool, vector, new_capacity)                                                                             \
    h2o_vector__reserve((pool), (h2o_vector_t *)(void *)(vector), H2O_ALIGNOF((vector)->entries[0]), sizeof((vector)->entries[0]), \
                        (new_capacity))

#define COMPUTE_DURATION(name, from, until)                                                                                        \
    static inline int h2o_time_compute_##name(struct st_h2o_req_t *req, int64_t *delta_usec)                                       \
    {                                                                                                                              \
        if (h2o_timeval_is_null((from)) || h2o_timeval_is_null((until))) {                                                         \
            return 0;                                                                                                              \
        }                                                                                                                          \
        *delta_usec = h2o_timeval_subtract((from), (until));                                                                       \
        return 1;                                                                                                                  \
    }
#define H2O_COMPRESSIBLE_BROTLI 2
#define H2O_COMPRESSIBLE_GZIP 1
#define H2O_DEFAULT_FASTCGI_IO_TIMEOUT 30000
#define H2O_DEFAULT_HANDSHAKE_TIMEOUT (H2O_DEFAULT_HANDSHAKE_TIMEOUT_IN_SECS * 1000)
#define H2O_DEFAULT_HANDSHAKE_TIMEOUT_IN_SECS 10
#define H2O_DEFAULT_HTTP1_REQ_IO_TIMEOUT (H2O_DEFAULT_HTTP1_REQ_IO_TIMEOUT_IN_SECS * 1000)
#define H2O_DEFAULT_HTTP1_REQ_IO_TIMEOUT_IN_SECS 5
#define H2O_DEFAULT_HTTP1_REQ_TIMEOUT (H2O_DEFAULT_HTTP1_REQ_TIMEOUT_IN_SECS * 1000)
#define H2O_DEFAULT_HTTP1_REQ_TIMEOUT_IN_SECS 10
#define H2O_DEFAULT_HTTP1_UPGRADE_TO_HTTP2 1
#define H2O_DEFAULT_HTTP2_ACTIVE_STREAM_WINDOW_SIZE H2O_HTTP2_MAX_STREAM_WINDOW_SIZE
#define H2O_DEFAULT_HTTP2_GRACEFUL_SHUTDOWN_TIMEOUT (H2O_DEFAULT_HTTP2_GRACEFUL_SHUTDOWN_TIMEOUT_IN_SECS * 1000)
#define H2O_DEFAULT_HTTP2_GRACEFUL_SHUTDOWN_TIMEOUT_IN_SECS 0 
#define H2O_DEFAULT_HTTP2_IDLE_TIMEOUT (H2O_DEFAULT_HTTP2_IDLE_TIMEOUT_IN_SECS * 1000)
#define H2O_DEFAULT_HTTP2_IDLE_TIMEOUT_IN_SECS 10
#define H2O_DEFAULT_HTTP3_ACTIVE_STREAM_WINDOW_SIZE H2O_DEFAULT_HTTP2_ACTIVE_STREAM_WINDOW_SIZE
#define H2O_DEFAULT_MAX_DELEGATIONS 5
#define H2O_DEFAULT_MAX_REQUEST_ENTITY_SIZE (1024 * 1024 * 1024)
#define H2O_DEFAULT_PROXY_HTTP2_MAX_CONCURRENT_STREAMS 100
#define H2O_DEFAULT_PROXY_IO_TIMEOUT (H2O_DEFAULT_PROXY_IO_TIMEOUT_IN_SECS * 1000)
#define H2O_DEFAULT_PROXY_IO_TIMEOUT_IN_SECS 30
#define H2O_DEFAULT_PROXY_SSL_SESSION_CACHE_CAPACITY 4096
#define H2O_DEFAULT_PROXY_SSL_SESSION_CACHE_DURATION 86400000 
#define H2O_DEFAULT_PROXY_TUNNEL_TIMEOUT_IN_SECS 300
#define H2O_HTTP2_MAX_STREAM_WINDOW_SIZE 16777216
#define H2O_HTTP2_MIN_STREAM_WINDOW_SIZE 65535
#define H2O_MAX_HEADERS 100
#define H2O_MAX_REQLEN (8192 + 4096 * (H2O_MAX_HEADERS))
#define H2O_PROXY_HEADER_MAX_LENGTH                                                                                                \
    (sizeof("PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n") - 1)
#define H2O_PULL_SENDVEC_MAX_SIZE 65536
#define H2O_QUIC_AGGREGATED_STATS_APPLY(func) \
    func(num_packets.received, "num-packets.received") \
    func(num_packets.decryption_failed, "num-packets.decryption-failed") \
    func(num_packets.sent, "num-packets.sent") \
    func(num_packets.lost, "num-packets.lost") \
    func(num_packets.lost_time_threshold, "num-packets.lost-time-threshold") \
    func(num_packets.ack_received, "num-packets.ack-received") \
    func(num_packets.late_acked, "num-packets.late-acked") \
    func(num_bytes.received, "num-bytes.received") \
    func(num_bytes.sent, "num-bytes.sent") \
    func(num_bytes.lost, "num-bytes.lost") \
    func(num_bytes.stream_data_sent, "num-bytes.stream-data-sent") \
    func(num_bytes.stream_data_resent, "num-bytes.stream-data-resent") \
    func(num_frames_sent.padding, "num-frames-sent.padding") \
    func(num_frames_sent.ping, "num-frames-sent.ping") \
    func(num_frames_sent.ack, "num-frames-sent.ack") \
    func(num_frames_sent.reset_stream, "num-frames-sent.reset_stream") \
    func(num_frames_sent.stop_sending, "num-frames-sent.stop_sending") \
    func(num_frames_sent.crypto, "num-frames-sent.crypto") \
    func(num_frames_sent.new_token, "num-frames-sent.new_token") \
    func(num_frames_sent.stream, "num-frames-sent.stream") \
    func(num_frames_sent.max_data, "num-frames-sent.max_data") \
    func(num_frames_sent.max_stream_data, "num-frames-sent.max_stream_data") \
    func(num_frames_sent.max_streams_bidi, "num-frames-sent.max_streams_bidi") \
    func(num_frames_sent.max_streams_uni, "num-frames-sent.max_streams_uni") \
    func(num_frames_sent.data_blocked, "num-frames-sent.data_blocked") \
    func(num_frames_sent.stream_data_blocked, "num-frames-sent.stream_data_blocked") \
    func(num_frames_sent.streams_blocked, "num-frames-sent.streams_blocked") \
    func(num_frames_sent.new_connection_id, "num-frames-sent.new_connection_id") \
    func(num_frames_sent.retire_connection_id, "num-frames-sent.retire_connection_id") \
    func(num_frames_sent.path_challenge, "num-frames-sent.path_challenge") \
    func(num_frames_sent.path_response, "num-frames-sent.path_response") \
    func(num_frames_sent.transport_close, "num-frames-sent.transport_close") \
    func(num_frames_sent.application_close, "num-frames-sent.application_close") \
    func(num_frames_sent.handshake_done, "num-frames-sent.handshake_done") \
    func(num_frames_sent.datagram, "num-frames-sent.datagram") \
    func(num_frames_sent.ack_frequency, "num-frames-sent.ack_frequency") \
    func(num_frames_received.padding, "num-frames-received.padding") \
    func(num_frames_received.ping, "num-frames-received.ping") \
    func(num_frames_received.ack, "num-frames-received.ack") \
    func(num_frames_received.reset_stream, "num-frames-received.reset_stream") \
    func(num_frames_received.stop_sending, "num-frames-received.stop_sending") \
    func(num_frames_received.crypto, "num-frames-received.crypto") \
    func(num_frames_received.new_token, "num-frames-received.new_token") \
    func(num_frames_received.stream, "num-frames-received.stream") \
    func(num_frames_received.max_data, "num-frames-received.max_data") \
    func(num_frames_received.max_stream_data, "num-frames-received.max_stream_data") \
    func(num_frames_received.max_streams_bidi, "num-frames-received.max_streams_bidi") \
    func(num_frames_received.max_streams_uni, "num-frames-received.max_streams_uni") \
    func(num_frames_received.data_blocked, "num-frames-received.data_blocked") \
    func(num_frames_received.stream_data_blocked, "num-frames-received.stream_data_blocked") \
    func(num_frames_received.streams_blocked, "num-frames-received.streams_blocked") \
    func(num_frames_received.new_connection_id, "num-frames-received.new_connection_id") \
    func(num_frames_received.retire_connection_id, "num-frames-received.retire_connection_id") \
    func(num_frames_received.path_challenge, "num-frames-received.path_challenge") \
    func(num_frames_received.path_response, "num-frames-received.path_response") \
    func(num_frames_received.transport_close, "num-frames-received.transport_close") \
    func(num_frames_received.application_close, "num-frames-received.application_close") \
    func(num_frames_received.handshake_done, "num-frames-received.handshake_done") \
    func(num_frames_received.datagram, "num-frames-received.datagram") \
    func(num_frames_received.ack_frequency, "num-frames-received.ack_frequency") \
    func(num_ptos, "num-ptos")
#define H2O_SEND_ERROR_XXX(status)                                                                                                 \
    static inline void h2o_send_error_##status(h2o_req_t *req, const char *reason, const char *body, int flags)                    \
    {                                                                                                                              \
        req->conn->ctx->emitted_error_status[H2O_STATUS_ERROR_##status]++;                                                         \
        h2o_send_error_generic(req, status, reason, body, flags);                                                                  \
    }
#define H2O_SEND_SERVER_TIMING_BASIC 1
#define H2O_SEND_SERVER_TIMING_PROXY 2
#define H2O_SOMAXCONN 65535
#define H2O_USE_BROTLI 0


#define H2O_HTTP2_DEFAULT_OUTBUF_SIZE 81920 
#define H2O_HTTP2_DEFAULT_OUTBUF_SOFT_MAX_SIZE 524288 
#define H2O_HTTP2_DEFAULT_OUTBUF_WRITE_TIMEOUT 60000  
#define H2O_HTTP2_ERROR_CANCEL -8
#define H2O_HTTP2_ERROR_COMPRESSION -9
#define H2O_HTTP2_ERROR_CONNECT -10
#define H2O_HTTP2_ERROR_ENHANCE_YOUR_CALM -11
#define H2O_HTTP2_ERROR_FLOW_CONTROL -3
#define H2O_HTTP2_ERROR_FRAME_SIZE -6
#define H2O_HTTP2_ERROR_INADEQUATE_SECURITY -12
#define H2O_HTTP2_ERROR_INCOMPLETE -255 
#define H2O_HTTP2_ERROR_INTERNAL -2
#define H2O_HTTP2_ERROR_INVALID_HEADER_CHAR                                                                                        \
    -254 
#define H2O_HTTP2_ERROR_MAX 13
#define H2O_HTTP2_ERROR_NONE 0
#define H2O_HTTP2_ERROR_PROTOCOL -1
#define H2O_HTTP2_ERROR_PROTOCOL_CLOSE_IMMEDIATELY -256
#define H2O_HTTP2_ERROR_REFUSED_STREAM -7
#define H2O_HTTP2_ERROR_SETTINGS_TIMEOUT -4
#define H2O_HTTP2_ERROR_STREAM_CLOSED -5
#define H2O_HTTP2_FRAME_FLAG_ACK 0x1
#define H2O_HTTP2_FRAME_FLAG_END_HEADERS 0x4
#define H2O_HTTP2_FRAME_FLAG_END_STREAM 0x1
#define H2O_HTTP2_FRAME_FLAG_PADDED 0x8
#define H2O_HTTP2_FRAME_FLAG_PRIORITY 0x20
#define H2O_HTTP2_FRAME_HEADER_SIZE 9
#define H2O_HTTP2_FRAME_TYPE_CONTINUATION 9
#define H2O_HTTP2_FRAME_TYPE_DATA 0
#define H2O_HTTP2_FRAME_TYPE_GOAWAY 7
#define H2O_HTTP2_FRAME_TYPE_HEADERS 1
#define H2O_HTTP2_FRAME_TYPE_ORIGIN 12
#define H2O_HTTP2_FRAME_TYPE_PING 6
#define H2O_HTTP2_FRAME_TYPE_PRIORITY 2
#define H2O_HTTP2_FRAME_TYPE_PUSH_PROMISE 5
#define H2O_HTTP2_FRAME_TYPE_RST_STREAM 3
#define H2O_HTTP2_FRAME_TYPE_SETTINGS 4
#define H2O_HTTP2_FRAME_TYPE_WINDOW_UPDATE 8
#define H2O_HTTP2_SETTINGS_ENABLE_PUSH 2
#define H2O_HTTP2_SETTINGS_HEADER_TABLE_SIZE 1
#define H2O_HTTP2_SETTINGS_INITIAL_WINDOW_SIZE 4
#define H2O_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS 3
#define H2O_HTTP2_SETTINGS_MAX_FRAME_SIZE 5
#define H2O_HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE 6

#define h2o_http2_encode_rst_stream_frame(buf, stream_id, errnum)                                                                  \
    h2o_http2__encode_rst_stream_frame(buf, stream_id, (H2O_BUILD_ASSERT((errnum) > 0), errnum))


#define H2O_INT16_LONGEST_STR "-32768"
#define H2O_INT32_LONGEST_STR "-2147483648"
#define H2O_INT64_LONGEST_STR "-9223372036854775808"
#define H2O_SIZE_T_LONGEST_STR                                                                                                     \
    H2O_UINT64_LONGEST_STR 
#define H2O_STRLIT(s) (s), sizeof(s) - 1
#define H2O_UINT16_LONGEST_STR "65535"
#define H2O_UINT32_LONGEST_STR "4294967295"
#define H2O_UINT64_LONGEST_HEX_STR "FFFFFFFFFFFFFFFF"
#define H2O_UINT64_LONGEST_STR "18446744073709551615"

#define h2o_concat(pool, ...)                                                                                                      \
    h2o_concat_list(pool, (h2o_iovec_t[]){__VA_ARGS__}, sizeof((h2o_iovec_t[]){__VA_ARGS__}) / sizeof(h2o_iovec_t))

#define H2O_MAX_TOKENS 100

#define H2O_TOKEN_ACCEPT (h2o__tokens + 5)
#define H2O_TOKEN_ACCEPT_CHARSET (h2o__tokens + 6)
#define H2O_TOKEN_ACCEPT_ENCODING (h2o__tokens + 7)
#define H2O_TOKEN_ACCEPT_LANGUAGE (h2o__tokens + 8)
#define H2O_TOKEN_ACCEPT_RANGES (h2o__tokens + 9)
#define H2O_TOKEN_ACCESS_CONTROL_ALLOW_CREDENTIALS (h2o__tokens + 10)
#define H2O_TOKEN_ACCESS_CONTROL_ALLOW_HEADERS (h2o__tokens + 11)
#define H2O_TOKEN_ACCESS_CONTROL_ALLOW_METHODS (h2o__tokens + 12)
#define H2O_TOKEN_ACCESS_CONTROL_ALLOW_ORIGIN (h2o__tokens + 13)
#define H2O_TOKEN_ACCESS_CONTROL_EXPOSE_HEADERS (h2o__tokens + 14)
#define H2O_TOKEN_ACCESS_CONTROL_REQUEST_HEADERS (h2o__tokens + 15)
#define H2O_TOKEN_ACCESS_CONTROL_REQUEST_METHOD (h2o__tokens + 16)
#define H2O_TOKEN_AGE (h2o__tokens + 17)
#define H2O_TOKEN_ALLOW (h2o__tokens + 18)
#define H2O_TOKEN_ALT_SVC (h2o__tokens + 19)
#define H2O_TOKEN_AUTHORITY (h2o__tokens + 0)
#define H2O_TOKEN_AUTHORIZATION (h2o__tokens + 20)
#define H2O_TOKEN_CACHE_CONTROL (h2o__tokens + 21)
#define H2O_TOKEN_CACHE_DIGEST (h2o__tokens + 22)
#define H2O_TOKEN_CONNECTION (h2o__tokens + 23)
#define H2O_TOKEN_CONTENT_DISPOSITION (h2o__tokens + 24)
#define H2O_TOKEN_CONTENT_ENCODING (h2o__tokens + 25)
#define H2O_TOKEN_CONTENT_LANGUAGE (h2o__tokens + 26)
#define H2O_TOKEN_CONTENT_LENGTH (h2o__tokens + 27)
#define H2O_TOKEN_CONTENT_LOCATION (h2o__tokens + 28)
#define H2O_TOKEN_CONTENT_RANGE (h2o__tokens + 29)
#define H2O_TOKEN_CONTENT_SECURITY_POLICY (h2o__tokens + 30)
#define H2O_TOKEN_CONTENT_TYPE (h2o__tokens + 31)
#define H2O_TOKEN_COOKIE (h2o__tokens + 32)
#define H2O_TOKEN_DATE (h2o__tokens + 33)
#define H2O_TOKEN_EARLY_DATA (h2o__tokens + 34)
#define H2O_TOKEN_ETAG (h2o__tokens + 35)
#define H2O_TOKEN_EXPECT (h2o__tokens + 36)
#define H2O_TOKEN_EXPECT_CT (h2o__tokens + 37)
#define H2O_TOKEN_EXPIRES (h2o__tokens + 38)
#define H2O_TOKEN_FORWARDED (h2o__tokens + 39)
#define H2O_TOKEN_FROM (h2o__tokens + 40)
#define H2O_TOKEN_HOST (h2o__tokens + 41)
#define H2O_TOKEN_HTTP2_SETTINGS (h2o__tokens + 42)
#define H2O_TOKEN_IF_MATCH (h2o__tokens + 43)
#define H2O_TOKEN_IF_MODIFIED_SINCE (h2o__tokens + 44)
#define H2O_TOKEN_IF_NONE_MATCH (h2o__tokens + 45)
#define H2O_TOKEN_IF_RANGE (h2o__tokens + 46)
#define H2O_TOKEN_IF_UNMODIFIED_SINCE (h2o__tokens + 47)
#define H2O_TOKEN_KEEP_ALIVE (h2o__tokens + 48)
#define H2O_TOKEN_LAST_MODIFIED (h2o__tokens + 49)
#define H2O_TOKEN_LINK (h2o__tokens + 50)
#define H2O_TOKEN_LOCATION (h2o__tokens + 51)
#define H2O_TOKEN_MAX_FORWARDS (h2o__tokens + 52)
#define H2O_TOKEN_METHOD (h2o__tokens + 1)
#define H2O_TOKEN_NO_EARLY_HINTS (h2o__tokens + 53)
#define H2O_TOKEN_ORIGIN (h2o__tokens + 54)
#define H2O_TOKEN_PATH (h2o__tokens + 2)
#define H2O_TOKEN_PRIORITY (h2o__tokens + 55)
#define H2O_TOKEN_PROXY_AUTHENTICATE (h2o__tokens + 56)
#define H2O_TOKEN_PROXY_AUTHORIZATION (h2o__tokens + 57)
#define H2O_TOKEN_PURPOSE (h2o__tokens + 58)
#define H2O_TOKEN_RANGE (h2o__tokens + 59)
#define H2O_TOKEN_REFERER (h2o__tokens + 60)
#define H2O_TOKEN_REFRESH (h2o__tokens + 61)
#define H2O_TOKEN_RETRY_AFTER (h2o__tokens + 62)
#define H2O_TOKEN_SCHEME (h2o__tokens + 3)
#define H2O_TOKEN_SERVER (h2o__tokens + 63)
#define H2O_TOKEN_SET_COOKIE (h2o__tokens + 64)
#define H2O_TOKEN_STATUS (h2o__tokens + 4)
#define H2O_TOKEN_STRICT_TRANSPORT_SECURITY (h2o__tokens + 65)
#define H2O_TOKEN_TE (h2o__tokens + 66)
#define H2O_TOKEN_TIMING_ALLOW_ORIGIN (h2o__tokens + 67)
#define H2O_TOKEN_TRANSFER_ENCODING (h2o__tokens + 68)
#define H2O_TOKEN_UPGRADE (h2o__tokens + 69)
#define H2O_TOKEN_UPGRADE_INSECURE_REQUESTS (h2o__tokens + 70)
#define H2O_TOKEN_USER_AGENT (h2o__tokens + 71)
#define H2O_TOKEN_VARY (h2o__tokens + 72)
#define H2O_TOKEN_VIA (h2o__tokens + 73)
#define H2O_TOKEN_WWW_AUTHENTICATE (h2o__tokens + 74)
#define H2O_TOKEN_X_COMPRESS_HINT (h2o__tokens + 75)
#define H2O_TOKEN_X_CONTENT_TYPE_OPTIONS (h2o__tokens + 76)
#define H2O_TOKEN_X_FORWARDED_FOR (h2o__tokens + 77)
#define H2O_TOKEN_X_FRAME_OPTIONS (h2o__tokens + 78)
#define H2O_TOKEN_X_REPROXY_URL (h2o__tokens + 79)
#define H2O_TOKEN_X_TRAFFIC (h2o__tokens + 80)
#define H2O_TOKEN_X_XSS_PROTECTION (h2o__tokens + 81)


#define H2O_SOCKETPOOL_TARGET_MAX_WEIGHT 256

#define H2O_SESSID_CTX ((const uint8_t *)"h2o")
#define H2O_SESSID_CTX_LEN (sizeof("h2o") - 1)
#define H2O_SOCKET_DEFAULT_SSL_BUFFER_SIZE ((5 + 16384 + 32) * 4)
#define H2O_SOCKET_INITIAL_INPUT_BUFFER_SIZE 4096
#define H2O_USE_ALPN 1
#define H2O_USE_LIBUV 0
#define H2O_USE_NPN 1

#define BIO_get_data(bio) ((bio)->ptr)
#define BIO_get_init(bio) ((bio)->init)
#define BIO_get_shutdown(bio) ((bio)->shutdown)
#define BIO_meth_set_ctrl(bm, cb) ((bm)->ctrl = cb)
#define BIO_meth_set_puts(bm, cb) ((bm)->bputs = cb)
#define BIO_meth_set_read(bm, cb) ((bm)->bread = cb)
#define BIO_meth_set_write(bm, cb) ((bm)->bwrite = cb)
#define BIO_set_data(bio, p) ((bio)->ptr = (p))
#define BIO_set_init(bio, i) ((bio)->init = (i))
#define BIO_set_shutdown(bio, shut) ((bio)->shutdown = (shut))
#define OPENSSL_VERSION SSLEAY_VERSION
#define OpenSSL_version SSLeay_version
#define SSL_CTX_up_ref(ctx) CRYPTO_add(&(ctx)->references, 1, CRYPTO_LOCK_SSL_CTX)
#define SSL_is_server(ssl) ((ssl)->server)
#define X509_STORE_get0_param(p) ((p)->param)
#define X509_STORE_up_ref(store) CRYPTO_add(&(store)->references, 1, CRYPTO_LOCK_X509_STORE)

#define H2O_EBPF_FLAGS_QUIC_SEND_RETRY_BITS_OFF 0x04
#define H2O_EBPF_FLAGS_QUIC_SEND_RETRY_BITS_ON 0x02
#define H2O_EBPF_FLAGS_QUIC_SEND_RETRY_MASK 0x06
#define H2O_EBPF_FLAGS_SKIP_TRACING_BIT 0x01
#define H2O_EBPF_MAP_PATH "/sys/fs/bpf/h2o_map"
#define H2O_EBPF_RETURN_MAP_NAME "h2o_return"
#define H2O_EBPF_RETURN_MAP_PATH "/sys/fs/bpf/" H2O_EBPF_RETURN_MAP_NAME
#define H2O_EBPF_RETURN_MAP_SIZE 1024



#define H2O_BARRIER_INITIALIZER(count_)                                                                                            \
    {                                                                                                                              \
        PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, count_                                                                \
    }
#define H2O_ERROR_REPORTER_INITIALIZER(s)                                                                                          \
    ((h2o_error_reporter_t){                                                                                                       \
        ._mutex = PTHREAD_MUTEX_INITIALIZER, ._timer = {.cb = h2o_error_reporter__on_timeout}, ._report_errors = (s)})
#define H2O_MULTITHREAD_ONCE(block)                                                                                                \
    do {                                                                                                                           \
        static volatile int lock = 0;                                                                                              \
        int lock_loaded = lock;                                                                                                    \
        __sync_synchronize();                                                                                                      \
        if (!lock_loaded) {                                                                                                        \
            static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;                                                              \
            pthread_mutex_lock(&mutex);                                                                                            \
            if (!lock) {                                                                                                           \
                do {                                                                                                               \
                    block                                                                                                          \
                } while (0);                                                                                                       \
                __sync_synchronize();                                                                                              \
                lock = 1;                                                                                                          \
            }                                                                                                                      \
            pthread_mutex_unlock(&mutex);                                                                                          \
        }                                                                                                                          \
    } while (0)

#define H2O_LIBRARY_VERSION_MAJOR 0
#define H2O_LIBRARY_VERSION_MINOR 16
#define H2O_LIBRARY_VERSION_PATCH 0
#define H2O_VERSION "2.3.0-DEV@" H2O_TO_STR(H2O_GITREV)
#define H2O_VERSION_MAJOR 2
#define H2O_VERSION_MINOR 3
#define H2O_VERSION_PATCH 0

#define H2O_TIMESTR_LOG_LEN (sizeof("29/Aug/2014:15:34:38 +0900") - 1)
#define H2O_TIMESTR_RFC1123_LEN (sizeof("Sun, 06 Nov 1994 08:49:37 GMT") - 1)

#define H2O_DEFINE_RAND 1
#define H2O_UUID_STR_RFC4122_LEN (sizeof("01234567-0123-4000-8000-0123456789ab") - 1)

#define h2o_rand() arc4random()


#define H2O_HTTP3_CHECK_SUCCESS(expr)                                                                                              \
    do {                                                                                                                           \
        if (!(expr))                                                                                                               \
            h2o_fatal(H2O_TO_STR(expr));                                                                                           \
    } while (0)
#define H2O_HTTP3_ERROR_CLOSED_CRITICAL_STREAM QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x104)
#define H2O_HTTP3_ERROR_CONNECT_ERROR QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x10f)
#define H2O_HTTP3_ERROR_EARLY_RESPONSE QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x10e)
#define H2O_HTTP3_ERROR_EXCESSIVE_LOAD QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x107)
#define H2O_HTTP3_ERROR_FRAME QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x106)
#define H2O_HTTP3_ERROR_FRAME_UNEXPECTED QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x105)
#define H2O_HTTP3_ERROR_GENERAL_PROTOCOL QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x101)
#define H2O_HTTP3_ERROR_ID QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x108)
#define H2O_HTTP3_ERROR_INCOMPLETE -1
#define H2O_HTTP3_ERROR_INTERNAL QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x102)
#define H2O_HTTP3_ERROR_MISSING_SETTINGS QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x10a)
#define H2O_HTTP3_ERROR_NONE QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x100)
#define H2O_HTTP3_ERROR_QPACK_DECODER_STREAM QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x202)
#define H2O_HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x200)
#define H2O_HTTP3_ERROR_QPACK_ENCODER_STREAM QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x201)
#define H2O_HTTP3_ERROR_REQUEST_CANCELLED QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x10c)
#define H2O_HTTP3_ERROR_REQUEST_INCOMPLETE QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x10d)
#define H2O_HTTP3_ERROR_REQUEST_REJECTED QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x10b)
#define H2O_HTTP3_ERROR_SETTINGS QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x109)
#define H2O_HTTP3_ERROR_STREAM_CREATION QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x103)
#define H2O_HTTP3_ERROR_TRANSPORT -2
#define H2O_HTTP3_ERROR_USER1 -256
#define H2O_HTTP3_ERROR_VERSION_FALLBACK QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x110)
#define H2O_HTTP3_FRAME_TYPE_CANCEL_PUSH 3
#define H2O_HTTP3_FRAME_TYPE_DATA 0
#define H2O_HTTP3_FRAME_TYPE_GOAWAY 7
#define H2O_HTTP3_FRAME_TYPE_HEADERS 1
#define H2O_HTTP3_FRAME_TYPE_MAX_PUSH_ID 13
#define H2O_HTTP3_FRAME_TYPE_PRIORITY_UPDATE 15
#define H2O_HTTP3_FRAME_TYPE_PUSH_PROMISE 5
#define H2O_HTTP3_FRAME_TYPE_SETTINGS 4
#define H2O_HTTP3_INITIAL_REQUEST_STREAM_WINDOW_SIZE (H2O_HTTP3_MAX_FRAME_PAYLOAD_SIZE * 2)
#define H2O_HTTP3_MAX_FRAME_PAYLOAD_SIZE 16384
#define H2O_HTTP3_PRIORITY_UPDATE_FRAME_CAPACITY (1  + 1  + 8 + sizeof("u=1,i=?0") - 1)
#define H2O_HTTP3_SETTINGS_MAX_FIELD_SECTION_SIZE 6
#define H2O_HTTP3_SETTINGS_QPACK_BLOCKED_STREAMS 7
#define H2O_HTTP3_SETTINGS_QPACK_MAX_TABLE_CAPACITY 1
#define H2O_HTTP3_STREAM_TYPE_CONTROL 0
#define H2O_HTTP3_STREAM_TYPE_PUSH_STREAM 1
#define H2O_HTTP3_STREAM_TYPE_QPACK_DECODER 3
#define H2O_HTTP3_STREAM_TYPE_QPACK_ENCODER 2
#define H2O_HTTP3_STREAM_TYPE_REQUEST 0x4000000000000000 
#define H2O_QUIC_ACCEPT_CONN_DECRYPTION_FAILED ((h2o_quic_conn_t *)1)


#define H2O_HPACK_ENCODE_INT_MAX_LENGTH 10 
#define H2O_HPACK_PARSE_HEADERS_AUTHORITY_EXISTS 8
#define H2O_HPACK_PARSE_HEADERS_METHOD_EXISTS 1
#define H2O_HPACK_PARSE_HEADERS_PATH_EXISTS 4
#define H2O_HPACK_PARSE_HEADERS_SCHEME_EXISTS 2
#define H2O_HPACK_SOFT_ERROR_BIT_INVALID_NAME 0x1
#define H2O_HPACK_SOFT_ERROR_BIT_INVALID_VALUE 0x2

#define H2O_ABSPRIO_DEFAULT_URGENCY 3
#define H2O_ABSPRIO_NUM_URGENCY_LEVELS 8




#define H2O_MEMCACHED_ENCODE_KEY 0x1
#define H2O_MEMCACHED_ENCODE_VALUE 0x2

#define H2O_FILECACHE_ETAG_MAXLEN (sizeof("\"deadbeef-deadbeefdeadbeef\"") - 1)

