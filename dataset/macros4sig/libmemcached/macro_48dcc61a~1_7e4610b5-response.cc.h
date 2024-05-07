







#include<sys/types.h>

#include<fcntl.h>
#define memcached_literal_param(str)          (str),strlen(str)
#define memcached_literal_param_size(str)     strlen(str)
#define memcached_string_make_from_cstr(str)  (str),((str)?strlen(str):0)
#define HUGE_STRING_LEN                8196
#define MEMCACHED_BLOCK_SIZE           1024
#define MEMCACHED_DEFAULT_COMMAND_SIZE 350
#define SMALL_STRING_LEN               1024
#  define likely(x)   if ((x))
#define memcached_instance_response_decrement(A) do {   \
    WATCHPOINT_ASSERT((A)->cursor_active_ > 0);         \
    if ((A)->cursor_active_ > 0) {                      \
        (A)->cursor_active_--;                          \
    }                                                   \
} while (0)
#define memcached_instance_response_increment(A) (A)->cursor_active_++
#define memcached_instance_response_reset(A)     (A)->cursor_active_ = 0
#define memcached_server_response_decrement(A) do {     \
    WATCHPOINT_ASSERT((A)->cursor_active_ > 0);         \
    if ((A)->cursor_active_ > 0) {                      \
        (A)->cursor_active_--;                          \
    }                                                   \
} while (0)
#define memcached_server_response_reset(A)       (A)->cursor_active_ = 0
#  define unlikely(x) if ((x))
#  define LIBMEMCACHED_MEMCACHED_ADD_END()
#  define LIBMEMCACHED_MEMCACHED_ADD_END_ENABLED() (0)
#  define LIBMEMCACHED_MEMCACHED_ADD_START()
#  define LIBMEMCACHED_MEMCACHED_ADD_START_ENABLED() (0)
#  define LIBMEMCACHED_MEMCACHED_CONNECT_END()
#  define LIBMEMCACHED_MEMCACHED_CONNECT_END_ENABLED() (0)
#  define LIBMEMCACHED_MEMCACHED_CONNECT_START()
#  define LIBMEMCACHED_MEMCACHED_CONNECT_START_ENABLED() (0)
#  define LIBMEMCACHED_MEMCACHED_DECREMENT_END()
#  define LIBMEMCACHED_MEMCACHED_DECREMENT_END_ENABLED() (0)
#  define LIBMEMCACHED_MEMCACHED_DECREMENT_START()
#  define LIBMEMCACHED_MEMCACHED_DECREMENT_START_ENABLED() (0)
#  define LIBMEMCACHED_MEMCACHED_DECREMENT_WITH_INITIAL_END()
#  define LIBMEMCACHED_MEMCACHED_DECREMENT_WITH_INITIAL_END_ENABLED() (0)
#  define LIBMEMCACHED_MEMCACHED_DECREMENT_WITH_INITIAL_START()
#  define LIBMEMCACHED_MEMCACHED_DECREMENT_WITH_INITIAL_START_ENABLED() (0)
#  define LIBMEMCACHED_MEMCACHED_DELETE_END()
#  define LIBMEMCACHED_MEMCACHED_DELETE_END_ENABLED() (0)
#  define LIBMEMCACHED_MEMCACHED_DELETE_START()
#  define LIBMEMCACHED_MEMCACHED_DELETE_START_ENABLED() (0)
#  define LIBMEMCACHED_MEMCACHED_FLUSH_END()
#  define LIBMEMCACHED_MEMCACHED_FLUSH_END_ENABLED() (0)
#  define LIBMEMCACHED_MEMCACHED_FLUSH_START()
#  define LIBMEMCACHED_MEMCACHED_FLUSH_START_ENABLED() (0)
#  define LIBMEMCACHED_MEMCACHED_GET_END()
#  define LIBMEMCACHED_MEMCACHED_GET_END_ENABLED() (0)
#  define LIBMEMCACHED_MEMCACHED_GET_START()
#  define LIBMEMCACHED_MEMCACHED_GET_START_ENABLED() (0)
#  define LIBMEMCACHED_MEMCACHED_INCREMENT_END()
#  define LIBMEMCACHED_MEMCACHED_INCREMENT_END_ENABLED() (0)
#  define LIBMEMCACHED_MEMCACHED_INCREMENT_START()
#  define LIBMEMCACHED_MEMCACHED_INCREMENT_START_ENABLED() (0)
#  define LIBMEMCACHED_MEMCACHED_INCREMENT_WITH_INITIAL_END()
#  define LIBMEMCACHED_MEMCACHED_INCREMENT_WITH_INITIAL_END_ENABLED() (0)
#  define LIBMEMCACHED_MEMCACHED_INCREMENT_WITH_INITIAL_START()
#  define LIBMEMCACHED_MEMCACHED_INCREMENT_WITH_INITIAL_START_ENABLED() (0)
#  define LIBMEMCACHED_MEMCACHED_MGET_END()
#  define LIBMEMCACHED_MEMCACHED_MGET_END_ENABLED() (0)
#  define LIBMEMCACHED_MEMCACHED_MGET_START()
#  define LIBMEMCACHED_MEMCACHED_MGET_START_ENABLED() (0)
#  define LIBMEMCACHED_MEMCACHED_REPLACE_END()
#  define LIBMEMCACHED_MEMCACHED_REPLACE_END_ENABLED() (0)
#  define LIBMEMCACHED_MEMCACHED_REPLACE_START()
#  define LIBMEMCACHED_MEMCACHED_REPLACE_START_ENABLED() (0)
#  define LIBMEMCACHED_MEMCACHED_SERVER_ADD_END()
#  define LIBMEMCACHED_MEMCACHED_SERVER_ADD_END_ENABLED() (0)
#  define LIBMEMCACHED_MEMCACHED_SERVER_ADD_START()
#  define LIBMEMCACHED_MEMCACHED_SERVER_ADD_START_ENABLED() (0)
#  define LIBMEMCACHED_MEMCACHED_SET_END()
#  define LIBMEMCACHED_MEMCACHED_SET_END_ENABLED() (0)
#  define LIBMEMCACHED_MEMCACHED_SET_START()
#  define LIBMEMCACHED_MEMCACHED_SET_START_ENABLED() (0)
#  define LIBMEMCACHED_MEMCACHED_TOUCH_END()
#  define LIBMEMCACHED_MEMCACHED_TOUCH_END_ENABLED() (0)
#  define LIBMEMCACHED_MEMCACHED_TOUCH_START()
#  define LIBMEMCACHED_MEMCACHED_TOUCH_START_ENABLED() (0)
#  define memcached_param_array(X) memcached_array_string(X), memcached_array_size(X)
#  define memcached_print_array(X) \
    static_cast<int>(memcached_array_size(X)), memcached_array_string(X)
#define libmemcached_xcalloc(__memcachd_st, __nelem, __type) \
  ((__type *) libmemcached_calloc((__memcachd_st), (__nelem), sizeof(__type)))
#define libmemcached_xmalloc(__memcachd_st, __type) \
  ((__type *) libmemcached_malloc((__memcachd_st), sizeof(__type)))
#define libmemcached_xrealloc(__memcachd_st, __mem, __nelem, __type) \
  ((__type *) libmemcached_realloc((__memcachd_st), (__mem), (__nelem), sizeof(__type)))
#define libmemcached_xvalloc(__memcachd_st, __nelem, __type) \
  ((__type *) libmemcached_realloc((__memcachd_st), NULL, (__nelem), sizeof(__type)))
#  define MEMCACHED_AT "__FILE__" ":" TOSTRING("__LINE__")
#  define STRINGIFY(x) #  x
#  define TOSTRING(x)  STRINGIFY(x)
#define memcached2Memcached(__obj) (__obj)
#define memcached_has_error(__object) ((__object)->error_messages)
#define memcached_has_replicas(__object) ((__object)->root->number_of_replicas)
#define memcached_has_root(__object) ((__object)->root)
#define memcached_is_aes(__object)                    ((__object)->flags.is_aes)
#define memcached_is_allocated(__object)        ((__object)->options.is_allocated)
#define memcached_is_auto_eject_hosts(__object)       ((__object)->flags.auto_eject_hosts)
#define memcached_is_binary(__object)                 ((__object)->flags.binary_protocol)
#define memcached_is_buffering(__object)              ((__object)->flags.buffer_requests)
#define memcached_is_cas(__object)                    ((__object)->flags.reply)
#define memcached_is_encrypted(__object)        (!!(__object)->hashkit._key)
#define memcached_is_fetching_version(__object)       ((__object)->flags.is_fetching_version)
#define memcached_is_hash_with_namespace(__object)    ((__object)->flags.hash_with_namespace)
#define memcached_is_initialized(__object)      ((__object)->options.is_initialized)
#define memcached_is_no_block(__object)               ((__object)->flags.no_block)
#define memcached_is_processing_input(__object) ((__object)->state.is_processing_input)
#define memcached_is_purging(__object)          ((__object)->state.is_purging)
#define memcached_is_randomize_replica_read(__object) ((__object)->flags.randomize_replica_read)
#define memcached_is_ready(__object) ((__object)->options.ready)
#define memcached_is_replying(__object)               ((__object)->flags.reply)
#define memcached_is_tcp_nodelay(__object)            ((__object)->flags.tcp_nodelay)
#define memcached_is_udp(__object)                    ((__object)->flags.use_udp)
#define memcached_is_use_sort_hosts(__object)         ((__object)->flags.use_sort_hosts)
#define memcached_is_verify_key(__object)             ((__object)->flags.verify_key)
#define memcached_is_weighted_ketama(__object) ((__object)->ketama.weighted_)
#define memcached_set_aes(__object, __flag)        ((__object).flags.is_aes = __flag)
#define memcached_set_allocated(__object, __value) ((__object)->options.is_allocated = (__value))
#define memcached_set_auto_eject_hosts(__object, __flag) \
  ((__object).flags.auto_eject_hosts = __flag)
#define memcached_set_binary(__object, __flag)     ((__object).flags.binary_protocol = __flag)
#define memcached_set_buffering(__object, __flag) ((__object).flags.buffer_requests = __flag)
#define memcached_set_cas(__object, __flag)       ((__object).flags.reply = __flag)
#define memcached_set_fetching_version(__object, __flag) \
  ((__object).flags.is_fetching_version = __flag)
#define memcached_set_hash_with_namespace(__object, __flag) \
  ((__object).flags.hash_with_namespace = __flag)
#define memcached_set_initialized(__object, __value) \
  ((__object)->options.is_initialized = (__value))
#define memcached_set_no_block(__object, __flag) ((__object).flags.no_block = __flag)
#define memcached_set_processing_input(__object, __value) \
  ((__object)->state.is_processing_input = (__value))
#define memcached_set_randomize_replica_read(__object, __flag) \
  ((__object).flags.randomize_replica_read = __flag)
#define memcached_set_ready(__object, __flag) ((__object)->options.ready = (__flag))
#define memcached_set_replying(__object, __flag)  ((__object).flags.reply = __flag)
#define memcached_set_tcp_nodelay(__object, __flag) ((__object).flags.tcp_nodelay = __flag)
#define memcached_set_udp(__object, __flag)        ((__object).flags.use_udp = __flag)
#define memcached_set_use_sort_hosts(__object, __flag) ((__object).flags.use_sort_hosts = __flag)
#define memcached_set_verify_key(__object, __flag) ((__object).flags.verify_key = __flag)
#define memcached_set_weighted_ketama(__object, __value) ((__object)->ketama.weighted_ = (__value))

#define WATCHPOINT_ASSERT(A) (void) (A)

#define WATCHPOINT_ASSERT_PRINT(A, B, C)


#define WATCHPOINT_IFERROR(__memcached_return_t) (void) (__memcached_return_t)
#define WATCHPOINT_IF_LABELED_NUMBER(A, B, C)
#define WATCHPOINT_LABELED_NUMBER(A, B)



#  define sasl_callback_t void
#  define MEMCACHED_NI_MAXHOST NI_MAXHOST
#  define MEMCACHED_NI_MAXSERV NI_MAXSERV
#define memcached_c_str(X)        (X).c_str;
#define memcached_size(X)         (X).size;
#define memcached_string_param(X) (X).c_str, (X).size
#  define memcached_string_printf(X) int((X).size), (X).c_str
#    define HASHKIT_API   __attribute__((visibility("default")))
#    define HASHKIT_LOCAL __attribute__((visibility("hidden")))
#define memcached_continue(__memcached_return_t) ((__memcached_return_t) == MEMCACHED_IN_PROGRESS)
#define MEMCACHED_CONTINUUM_ADDITION \
  10 
#define MEMCACHED_CONTINUUM_SIZE \
  MEMCACHED_POINTS_PER_SERVER * 100 
#define MEMCACHED_DEFAULT_CONNECT_TIMEOUT 4000
#define MEMCACHED_DEFAULT_PORT             11211
#define MEMCACHED_DEFAULT_PORT_STRING      "11211"
#define MEMCACHED_DEFAULT_TIMEOUT         5000
#define MEMCACHED_EXPIRATION_NOT_ADD           0xffffffffU
#define MEMCACHED_POINTS_PER_SERVER        100
#define MEMCACHED_POINTS_PER_SERVER_KETAMA 160
#define MEMCACHED_SERVER_FAILURE_DEAD_TIMEOUT  0
#define MEMCACHED_SERVER_FAILURE_LIMIT         5
#define MEMCACHED_SERVER_FAILURE_RETRY_TIMEOUT 2
#define MEMCACHED_SERVER_TIMEOUT_LIMIT         0
#define MEMCACHED_STRIDE                  4
#define MEMCACHED_MAXIMUM_INTEGER_DISPLAY_LENGTH MEMCACHED_MAX_INTEGER_DISPLAY_LENGTH
#define MEMCACHED_MAX_BUFFER    8196
#define MEMCACHED_MAX_HOST_SORT_LENGTH       86 
#define MEMCACHED_MAX_INTEGER_DISPLAY_LENGTH 20
#define MEMCACHED_MAX_KEY       251 
#define MEMCACHED_MAX_NAMESPACE 128
#define MEMCACHED_PREFIX_KEY_MAX_SIZE            MEMCACHED_MAX_NAMESPACE
#define MEMCACHED_VERSION_STRING_LENGTH      24
# define WINVER 0x0600
# define _WIN32_WINNT 0x0600
#  define __STDC_FORMAT_MACROS
#      define LIBMEMCACHED_API   __attribute__((visibility("default")))
#      define LIBMEMCACHED_LOCAL __attribute__((visibility("hidden")))
#  define EAI_SYSTEM (-1)
#  define FD_CLOEXEC 0
#  define MSG_MORE 0
#  define MSG_NOSIGNAL 0
# define P9Y_NEED_GET_SOCKET_ERRNO
#  define SHUT_RD SD_RECEIVE
#  define SHUT_RDWR SD_BOTH
#  define SHUT_WR SD_SEND
#  define SOCK_CLOEXEC 0
#  define SOCK_NONBLOCK 0
#  define SO_NOSIGPIPE 0
#  define TCP_KEEPIDLE 0
#  define TCP_NODELAY 0
