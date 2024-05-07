#include<sys/param.h>

#include<stdlib.h>
#include<sys/types.h>
#include<limits.h>
#include<errno.h>
#include<stdio.h>
#include<time.h>
#include<assert.h>
#include<sys/sysmacros.h>
#include<unistd.h>
#include<poll.h>

#include<syslog.h>
#include<inttypes.h>
#include<stdint.h>
#include<stddef.h>
#include<stdbool.h>
#include<stdarg.h>
#include<sys/uio.h>
#define DUAL_TIMESTAMP_HAS_CLOCK(clock)                               \
        IN_SET(clock, CLOCK_REALTIME, CLOCK_REALTIME_ALARM, CLOCK_MONOTONIC)
#define DUAL_TIMESTAMP_NULL ((struct dual_timestamp) {})
#define FORMAT_TIMESPAN_MAX 64
#define FORMAT_TIMESTAMP_MAX (3+1+10+1+8+1+6+1+6+1)
#define FORMAT_TIMESTAMP_RELATIVE_MAX 256
#define FORMAT_TIMESTAMP_WIDTH 28 
#define MSEC_PER_SEC  1000ULL
#define NSEC_FMT "%" PRI_NSEC
#define NSEC_INFINITY ((nsec_t) -1)
#define NSEC_PER_DAY ((nsec_t) (24ULL*NSEC_PER_HOUR))
#define NSEC_PER_HOUR ((nsec_t) (60ULL*NSEC_PER_MINUTE))
#define NSEC_PER_MINUTE ((nsec_t) (60ULL*NSEC_PER_SEC))
#define NSEC_PER_MONTH ((nsec_t) (2629800ULL*NSEC_PER_SEC))
#define NSEC_PER_MSEC ((nsec_t) 1000000ULL)
#define NSEC_PER_SEC  ((nsec_t) 1000000000ULL)
#define NSEC_PER_USEC ((nsec_t) 1000ULL)
#define NSEC_PER_WEEK ((nsec_t) (7ULL*NSEC_PER_DAY))
#define NSEC_PER_YEAR ((nsec_t) (31557600ULL*NSEC_PER_SEC))
#define PRI_NSEC PRIu64
#define PRI_USEC PRIu64
#define TIME_T_MAX (time_t)((UINTMAX_C(1) << ((sizeof(time_t) << 3) - 1)) - 1)
#define TRIPLE_TIMESTAMP_HAS_CLOCK(clock)                               \
        IN_SET(clock, CLOCK_REALTIME, CLOCK_REALTIME_ALARM, CLOCK_MONOTONIC, CLOCK_BOOTTIME, CLOCK_BOOTTIME_ALARM)
#define TRIPLE_TIMESTAMP_NULL ((struct triple_timestamp) {})
#define USEC_FMT "%" PRI_USEC
#define USEC_INFINITY ((usec_t) -1)
#define USEC_PER_DAY ((usec_t) (24ULL*USEC_PER_HOUR))
#define USEC_PER_HOUR ((usec_t) (60ULL*USEC_PER_MINUTE))
#define USEC_PER_MINUTE ((usec_t) (60ULL*USEC_PER_SEC))
#define USEC_PER_MONTH ((usec_t) (2629800ULL*USEC_PER_SEC))
#define USEC_PER_MSEC ((usec_t) 1000ULL)
#define USEC_PER_SEC  ((usec_t) 1000000ULL)
#define USEC_PER_WEEK ((usec_t) (7ULL*USEC_PER_DAY))
#define USEC_PER_YEAR ((usec_t) (31557600ULL*USEC_PER_SEC))
#define USEC_TIMESTAMP_FORMATTABLE_MAX ((usec_t) 253402214399000000)
#define ALIGN(l) ALIGN8(l)
#define ALIGN4(l) (((l) + 3) & ~3)
#define ALIGN4_PTR(p) ((void*) ALIGN4((unsigned long) (p)))
#define ALIGN8(l) (((l) + 7) & ~7)
#define ALIGN8_PTR(p) ((void*) ALIGN8((unsigned long) (p)))
#define ALIGN_PTR(p) ((void*) ALIGN((unsigned long) (p)))
#define ALIGN_TO_PTR(p, ali) ((void*) ALIGN_TO((unsigned long) (p), (ali)))
#define BUILTIN_FFS_U32(x) __builtin_ffs(x);
#define CASE_F(X) case X:
#define CASE_F_1(CASE, X) CASE_F(X)
#define CASE_F_10(CASE, X, ...) CASE(X) CASE_F_9(CASE, __VA_ARGS__)
#define CASE_F_11(CASE, X, ...) CASE(X) CASE_F_10(CASE, __VA_ARGS__)
#define CASE_F_12(CASE, X, ...) CASE(X) CASE_F_11(CASE, __VA_ARGS__)
#define CASE_F_13(CASE, X, ...) CASE(X) CASE_F_12(CASE, __VA_ARGS__)
#define CASE_F_14(CASE, X, ...) CASE(X) CASE_F_13(CASE, __VA_ARGS__)
#define CASE_F_15(CASE, X, ...) CASE(X) CASE_F_14(CASE, __VA_ARGS__)
#define CASE_F_16(CASE, X, ...) CASE(X) CASE_F_15(CASE, __VA_ARGS__)
#define CASE_F_17(CASE, X, ...) CASE(X) CASE_F_16(CASE, __VA_ARGS__)
#define CASE_F_18(CASE, X, ...) CASE(X) CASE_F_17(CASE, __VA_ARGS__)
#define CASE_F_19(CASE, X, ...) CASE(X) CASE_F_18(CASE, __VA_ARGS__)
#define CASE_F_2(CASE, X, ...)  CASE(X) CASE_F_1(CASE, __VA_ARGS__)
#define CASE_F_20(CASE, X, ...) CASE(X) CASE_F_19(CASE, __VA_ARGS__)
#define CASE_F_3(CASE, X, ...)  CASE(X) CASE_F_2(CASE, __VA_ARGS__)
#define CASE_F_4(CASE, X, ...)  CASE(X) CASE_F_3(CASE, __VA_ARGS__)
#define CASE_F_5(CASE, X, ...)  CASE(X) CASE_F_4(CASE, __VA_ARGS__)
#define CASE_F_6(CASE, X, ...)  CASE(X) CASE_F_5(CASE, __VA_ARGS__)
#define CASE_F_7(CASE, X, ...)  CASE(X) CASE_F_6(CASE, __VA_ARGS__)
#define CASE_F_8(CASE, X, ...)  CASE(X) CASE_F_7(CASE, __VA_ARGS__)
#define CASE_F_9(CASE, X, ...)  CASE(X) CASE_F_8(CASE, __VA_ARGS__)
#define CHAR_TO_STR(x) ((char[2]) { x, 0 })
#define CLAMP(x, low, high) __CLAMP(UNIQ, (x), UNIQ, (low), UNIQ, (high))
#define CMP(a, b) __CMP(UNIQ, (a), UNIQ, (b))
#define CONCATENATE(x, y) XCONCATENATE(x, y)
#define CONST_MAX(_A, _B) \
        (__builtin_choose_expr(                                         \
                __builtin_constant_p(_A) &&                             \
                __builtin_constant_p(_B) &&                             \
                __builtin_types_compatible_p(typeof(_A), typeof(_B)),   \
                ((_A) > (_B)) ? (_A) : (_B),                            \
                VOID_0))
#define DECIMAL_STR_MAX(type)                                           \
        (2+(sizeof(type) <= 1 ? 3 :                                     \
            sizeof(type) <= 2 ? 5 :                                     \
            sizeof(type) <= 4 ? 10 :                                    \
            sizeof(type) <= 8 ? 20 : sizeof(int[-2*(sizeof(type) > 8)])))
#define DECIMAL_STR_WIDTH(x)                            \
        ({                                              \
                typeof(x) _x_ = (x);                    \
                unsigned ans = 1;                       \
                while ((_x_ /= 10) != 0)                \
                        ans++;                          \
                ans;                                    \
        })
#define DEFINE_PRIVATE_TRIVIAL_REF_FUNC(type, name)     \
        _DEFINE_TRIVIAL_REF_FUNC(type, name, static)
#define DEFINE_PRIVATE_TRIVIAL_REF_UNREF_FUNC(type, name, free_func)    \
        DEFINE_PRIVATE_TRIVIAL_REF_FUNC(type, name);                    \
        DEFINE_PRIVATE_TRIVIAL_UNREF_FUNC(type, name, free_func);
#define DEFINE_PRIVATE_TRIVIAL_UNREF_FUNC(type, name, free_func)        \
        _DEFINE_TRIVIAL_UNREF_FUNC(type, name, free_func, static)
#define DEFINE_PUBLIC_TRIVIAL_REF_FUNC(type, name)      \
        _DEFINE_TRIVIAL_REF_FUNC(type, name, _public_)
#define DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC(type, name, free_func)    \
        DEFINE_PUBLIC_TRIVIAL_REF_FUNC(type, name);                    \
        DEFINE_PUBLIC_TRIVIAL_UNREF_FUNC(type, name, free_func);
#define DEFINE_PUBLIC_TRIVIAL_UNREF_FUNC(type, name, free_func)         \
        _DEFINE_TRIVIAL_UNREF_FUNC(type, name, free_func, _public_)
#define DEFINE_TRIVIAL_CLEANUP_FUNC(type, func)                 \
        static inline void func##p(type *p) {                   \
                if (*p)                                         \
                        func(*p);                               \
        }
#define DEFINE_TRIVIAL_DESTRUCTOR(name, type, func)             \
        static inline void name(type *p) {                      \
                func(p);                                        \
        }
#define DEFINE_TRIVIAL_REF_FUNC(type, name)     \
        _DEFINE_TRIVIAL_REF_FUNC(type, name,)
#define DEFINE_TRIVIAL_REF_UNREF_FUNC(type, name, free_func)    \
        DEFINE_TRIVIAL_REF_FUNC(type, name);                    \
        DEFINE_TRIVIAL_UNREF_FUNC(type, name, free_func);
#define DEFINE_TRIVIAL_UNREF_FUNC(type, name, free_func)        \
        _DEFINE_TRIVIAL_UNREF_FUNC(type, name, free_func,)
#define DISABLE_WARNING_FORMAT_NONLITERAL                               \
        _Pragma("GCC diagnostic push");                                 \
        _Pragma("GCC diagnostic ignored \"-Wformat-nonliteral\"")
#define DISABLE_WARNING_INCOMPATIBLE_POINTER_TYPES                      \
        _Pragma("GCC diagnostic push");                                 \
        _Pragma("GCC diagnostic ignored \"-Wincompatible-pointer-types\"")
#define DISABLE_WARNING_MISSING_PROTOTYPES                              \
        _Pragma("GCC diagnostic push");                                 \
        _Pragma("GCC diagnostic ignored \"-Wmissing-prototypes\"")
#define DISABLE_WARNING_NONNULL                                         \
        _Pragma("GCC diagnostic push");                                 \
        _Pragma("GCC diagnostic ignored \"-Wnonnull\"")
#define DISABLE_WARNING_SHADOW                                          \
        _Pragma("GCC diagnostic push");                                 \
        _Pragma("GCC diagnostic ignored \"-Wshadow\"")
#define DIV_ROUND_UP(x, y) __DIV_ROUND_UP(UNIQ, (x), UNIQ, (y))
#define ELEMENTSOF(x)                                                   \
        (__builtin_choose_expr(                                         \
                !__builtin_types_compatible_p(typeof(x), typeof(&*(x))), \
                sizeof(x)/sizeof((x)[0]),                               \
                VOID_0))
#define EXIT_TEST_SKIP 77
#define FLAGS_SET(v, flags) \
        ((~(v) & (flags)) == 0)
#define FOR_EACH_MAKE_CASE(...) \
        GET_CASE_F(__VA_ARGS__,CASE_F_20,CASE_F_19,CASE_F_18,CASE_F_17,CASE_F_16,CASE_F_15,CASE_F_14,CASE_F_13,CASE_F_12,CASE_F_11, \
                               CASE_F_10,CASE_F_9,CASE_F_8,CASE_F_7,CASE_F_6,CASE_F_5,CASE_F_4,CASE_F_3,CASE_F_2,CASE_F_1) \
                   (CASE_F,__VA_ARGS__)
#define GET_CASE_F(_1,_2,_3,_4,_5,_6,_7,_8,_9,_10,_11,_12,_13,_14,_15,_16,_17,_18,_19,_20,NAME,...) NAME
#      define HAS_FEATURE_ADDRESS_SANITIZER 1
#      define HAS_FEATURE_MEMORY_SANITIZER 1
#define INT32_TO_PTR(u) ((void *) ((intptr_t) (u)))
#define INT64_TO_PTR(u) ((void *) ((intptr_t) (u)))
#define INT_TO_PTR(u) ((void *) ((intptr_t) (u)))
#define IN_SET(x, ...)                          \
        ({                                      \
                bool _found = false;            \
                         \
                assert_cc((sizeof((long double[]){__VA_ARGS__})/sizeof(long double)) <= 20); \
                switch(x) {                     \
                FOR_EACH_MAKE_CASE(__VA_ARGS__) \
                        _found = true;          \
                        break;                  \
                default:                        \
                        break;                  \
                }                               \
                _found;                         \
        })
#define LESS_BY(a, b) __LESS_BY(UNIQ, (a), UNIQ, (b))
#define LONG_TO_PTR(u) ((void *) ((intptr_t) (u)))
#define MAX(a, b) __MAX(UNIQ, (a), UNIQ, (b))
#define MAX3(x, y, z)                                   \
        ({                                              \
                const typeof(x) _c = MAX(x, y);         \
                MAX(_c, z);                             \
        })
#define MAXSIZE(A, B) (sizeof(union _packed_ { typeof(A) a; typeof(B) b; }))
#define MIN(a, b) __MIN(UNIQ, (a), UNIQ, (b))
#define MIN3(x, y, z)                                   \
        ({                                              \
                const typeof(x) _c = MIN(x, y);         \
                MIN(_c, z);                             \
        })
#define PTR_TO_INT(p) ((int) ((intptr_t) (p)))
#define PTR_TO_INT32(p) ((int32_t) ((intptr_t) (p)))
#define PTR_TO_INT64(p) ((int64_t) ((intptr_t) (p)))
#define PTR_TO_LONG(p) ((long) ((intptr_t) (p)))
#define PTR_TO_SIZE(p) ((size_t) ((uintptr_t) (p)))
#define PTR_TO_UINT(p) ((unsigned) ((uintptr_t) (p)))
#define PTR_TO_UINT32(p) ((uint32_t) ((uintptr_t) (p)))
#define PTR_TO_UINT64(p) ((uint64_t) ((uintptr_t) (p)))
#define PTR_TO_ULONG(p) ((unsigned long) ((uintptr_t) (p)))
#define REENABLE_WARNING                                                \
        _Pragma("GCC diagnostic pop")
#define SET_FLAG(v, flag, b) \
        (v) = (b) ? ((v) | (flag)) : ((v) & ~(flag))
#define SIZE_TO_PTR(u) ((void *) ((uintptr_t) (u)))
#define STRINGIFY(x) XSTRINGIFY(x)
#define STRLEN(x) (sizeof(""x"") - 1)
#define SWAP_TWO(x, y) do {                        \
                typeof(x) _t = (x);                \
                (x) = (y);                         \
                (y) = (_t);                        \
        } while (false)
#define UINT32_TO_PTR(u) ((void *) ((uintptr_t) (u)))
#define UINT64_TO_PTR(u) ((void *) ((uintptr_t) (u)))
#define UINT_TO_PTR(u) ((void *) ((uintptr_t) (u)))
#define ULONG_TO_PTR(u) ((void *) ((uintptr_t) (u)))
#define UNIQ __COUNTER__
#define UNIQ_T(x, uniq) CONCATENATE(__unique_prefix_, CONCATENATE(x, uniq))
#  define VOID_0 ((void)0)
#define XCONCATENATE(x, y) x ## y
#define XSTRINGIFY(x) #x
#define _DEFINE_TRIVIAL_REF_FUNC(type, name, scope)             \
        scope type *name##_ref(type *p) {                       \
                if (!p)                                         \
                        return NULL;                            \
                                                                \
                assert(p->n_ref > 0);                           \
                p->n_ref++;                                     \
                return p;                                       \
        }
#define _DEFINE_TRIVIAL_UNREF_FUNC(type, name, free_func, scope) \
        scope type *name##_unref(type *p) {                      \
                if (!p)                                          \
                        return NULL;                             \
                                                                 \
                assert(p->n_ref > 0);                            \
                p->n_ref--;                                      \
                if (p->n_ref > 0)                                \
                        return NULL;                             \
                                                                 \
                return free_func(p);                             \
        }
#define __CLAMP(xq, x, lowq, low, highq, high)                          \
        ({                                                              \
                const typeof(x) UNIQ_T(X, xq) = (x);                    \
                const typeof(low) UNIQ_T(LOW, lowq) = (low);            \
                const typeof(high) UNIQ_T(HIGH, highq) = (high);        \
                        UNIQ_T(X, xq) > UNIQ_T(HIGH, highq) ?           \
                                UNIQ_T(HIGH, highq) :                   \
                                UNIQ_T(X, xq) < UNIQ_T(LOW, lowq) ?     \
                                        UNIQ_T(LOW, lowq) :             \
                                        UNIQ_T(X, xq);                  \
        })
#define __CMP(aq, a, bq, b)                             \
        ({                                              \
                const typeof(a) UNIQ_T(A, aq) = (a);    \
                const typeof(b) UNIQ_T(B, bq) = (b);    \
                UNIQ_T(A, aq) < UNIQ_T(B, bq) ? -1 :    \
                UNIQ_T(A, aq) > UNIQ_T(B, bq) ? 1 : 0;  \
        })
#define __DIV_ROUND_UP(xq, x, yq, y)                                    \
        ({                                                              \
                const typeof(x) UNIQ_T(X, xq) = (x);                    \
                const typeof(y) UNIQ_T(Y, yq) = (y);                    \
                (UNIQ_T(X, xq) / UNIQ_T(Y, yq) + !!(UNIQ_T(X, xq) % UNIQ_T(Y, yq))); \
        })
#define __LESS_BY(aq, a, bq, b)                         \
        ({                                              \
                const typeof(a) UNIQ_T(A, aq) = (a);    \
                const typeof(b) UNIQ_T(B, bq) = (b);    \
                UNIQ_T(A, aq) > UNIQ_T(B, bq) ? UNIQ_T(A, aq) - UNIQ_T(B, bq) : 0; \
        })
#define __MAX(aq, a, bq, b)                             \
        ({                                              \
                const typeof(a) UNIQ_T(A, aq) = (a);    \
                const typeof(b) UNIQ_T(B, bq) = (b);    \
                UNIQ_T(A, aq) > UNIQ_T(B, bq) ? UNIQ_T(A, aq) : UNIQ_T(B, bq); \
        })
#define __MIN(aq, a, bq, b)                             \
        ({                                              \
                const typeof(a) UNIQ_T(A, aq) = (a);    \
                const typeof(b) UNIQ_T(B, bq) = (b);    \
                UNIQ_T(A, aq) < UNIQ_T(B, bq) ? UNIQ_T(A, aq) : UNIQ_T(B, bq); \
        })
#define __container_of(uniq, ptr, type, member)                         \
        ({                                                              \
                const typeof( ((type*)0)->member ) *UNIQ_T(A, uniq) = (ptr); \
                (type*)( (char *)UNIQ_T(A, uniq) - offsetof(type, member) ); \
        })
#define _align_(x) __attribute__((__aligned__(x)))
#define _alignas_(x) __attribute__((__aligned__(__alignof(x))))
#define _alignptr_ __attribute__((__aligned__(sizeof(void*))))
#  define _alloc_(...)
#define _cleanup_(x) __attribute__((__cleanup__(x)))
#define _const_ __attribute__((__const__))
#define _deprecated_ __attribute__((__deprecated__))
#define _destructor_ __attribute__((__destructor__))
#define _fallthrough_ __attribute__((__fallthrough__))
#define _hidden_ __attribute__((__visibility__("hidden")))
#define _likely_(x) (__builtin_expect(!!(x), 1))
#define _malloc_ __attribute__((__malloc__))
#define _noreturn_ _Noreturn
#define _packed_ __attribute__((__packed__))
#define _printf_(a, b) __attribute__((__format__(printf, a, b)))
#define _public_ __attribute__((__visibility__("default")))
#define _pure_ __attribute__((__pure__))
#define _section_(x) __attribute__((__section__(x)))
#define _sentinel_ __attribute__((__sentinel__))
#define _unlikely_(x) (__builtin_expect(!!(x), 0))
#define _unused_ __attribute__((__unused__))
#define _used_ __attribute__((__used__))
#define _variable_no_sanitize_address_ __attribute__((__no_sanitize_address__))
#define _weak_ __attribute__((__weak__))
#define _weakref_(x) __attribute__((__weakref__(#x)))
#define assert(expr) do {} while (false)
#define assert_cc(expr)                                                 \
        static_assert(expr, #expr);
#define assert_log(expr, message) __coverity_check__(!!(expr))
#define assert_message_se(expr, message)                                \
        do {                                                            \
                if (__coverity_check__(!(expr)))                        \
                        __coverity_panic__();                           \
        } while (false)
#define assert_not_reached(t)                                           \
        do {                                                            \
                log_assert_failed_unreachable(t, "__FILE__", "__LINE__", __PRETTY_FUNCTION__); \
        } while (false)
#define assert_return(expr, r)                                          \
        do {                                                            \
                if (!assert_log(expr, #expr))                           \
                        return (r);                                     \
        } while (false)
#define assert_return_errno(expr, r, err)                               \
        do {                                                            \
                if (!assert_log(expr, #expr)) {                         \
                        errno = err;                                    \
                        return (r);                                     \
                }                                                       \
        } while (false)
#define assert_se(expr) assert_message_se(expr, #expr)
#define char_array_0(x) x[sizeof(x)-1] = 0;
#define container_of(ptr, type, member) __container_of(UNIQ, (ptr), type, member)
#define return_with_errno(r, err)                     \
        do {                                          \
                errno = abs(err);                     \
                return r;                             \
        } while (false)
#define thread_local _Thread_local
#define DEBUG_LOGGING _unlikely_(log_get_max_level() >= LOG_DEBUG)
#define ERRNO_VALUE(val)                    (abs(val) & 255)
#define IS_SYNTHETIC_ERRNO(val)             ((val) >> 30 & 1)
#define LOG_MESSAGE(fmt, ...) "MESSAGE=" fmt, ##__VA_ARGS__
#  define LOG_REALM LOG_REALM_SYSTEMD
#define LOG_REALM_PLUS_LEVEL(realm, level)  ((realm) << 10 | (level))
#define LOG_REALM_REMOVE_LEVEL(realm_level) ((realm_level) >> 10)
#define SYNTHETIC_ERRNO(num)                (1 << 30 | (num))
#define log_assert_failed(text, ...) \
        log_assert_failed_realm(LOG_REALM, (text), __VA_ARGS__)
#define log_assert_failed_return(text, ...) \
        log_assert_failed_return_realm(LOG_REALM, (text), __VA_ARGS__)
#define log_assert_failed_unreachable(text, ...) \
        log_assert_failed_unreachable_realm(LOG_REALM, (text), __VA_ARGS__)
#define log_debug(...)     log_full(LOG_DEBUG,   __VA_ARGS__)
#define log_debug_errno(error, ...)     log_full_errno(LOG_DEBUG,   error, __VA_ARGS__)
#define log_dispatch(level, error, buffer)                              \
        log_dispatch_internal(level, error, "__FILE__", "__LINE__", __func__, NULL, NULL, NULL, NULL, buffer)
#define log_dump(level, buffer) \
        log_dump_internal(LOG_REALM_PLUS_LEVEL(LOG_REALM, level), \
                          0, "__FILE__", "__LINE__", __func__, buffer)
#define log_emergency(...) log_full(log_emergency_level(), __VA_ARGS__)
#define log_emergency_errno(error, ...) log_full_errno(log_emergency_level(), error, __VA_ARGS__)
#define log_error(...)     log_full(LOG_ERR,     __VA_ARGS__)
#define log_error_errno(error, ...)     log_full_errno(LOG_ERR,     error, __VA_ARGS__)
#define log_full(level, ...) log_full_errno((level), 0, __VA_ARGS__)
#define log_full_errno(level, error, ...)                               \
        log_full_errno_realm(LOG_REALM, (level), (error), __VA_ARGS__)
#define log_full_errno_realm(realm, level, error, ...)                  \
        ({                                                              \
                int _level = (level), _e = (error), _realm = (realm);   \
                (log_get_max_level_realm(_realm) >= LOG_PRI(_level))    \
                        ? log_internal_realm(LOG_REALM_PLUS_LEVEL(_realm, _level), _e, \
                                             "__FILE__", "__LINE__", __func__, __VA_ARGS__) \
                        : -ERRNO_VALUE(_e);                             \
        })
#define log_get_max_level()                     \
        log_get_max_level_realm(LOG_REALM)
#define log_info(...)      log_full(LOG_INFO,    __VA_ARGS__)
#define log_info_errno(error, ...)      log_full_errno(LOG_INFO,    error, __VA_ARGS__)
#define log_internal(level, ...) \
        log_internal_realm(LOG_REALM_PLUS_LEVEL(LOG_REALM, (level)), __VA_ARGS__)
#define log_internalv(level, ...) \
        log_internalv_realm(LOG_REALM_PLUS_LEVEL(LOG_REALM, (level)), __VA_ARGS__)
#define log_notice(...)    log_full(LOG_NOTICE,  __VA_ARGS__)
#define log_notice_errno(error, ...)    log_full_errno(LOG_NOTICE,  error, __VA_ARGS__)
#define log_oom() log_oom_internal(LOG_REALM, "__FILE__", "__LINE__", __func__)
#define log_parse_environment() \
        log_parse_environment_realm(LOG_REALM)
#define log_set_max_level(level)                \
        log_set_max_level_realm(LOG_REALM, (level))
#define log_set_max_level_from_string(e)        \
        log_set_max_level_from_string_realm(LOG_REALM, (e))
#define log_struct(level, ...) log_struct_errno(level, 0, __VA_ARGS__)
#define log_struct_errno(level, error, ...) \
        log_struct_internal(LOG_REALM_PLUS_LEVEL(LOG_REALM, level), \
                            error, "__FILE__", "__LINE__", __func__, __VA_ARGS__, NULL)
#define log_struct_iovec(level, iovec, n_iovec) log_struct_iovec_errno(level, 0, iovec, n_iovec)
#define log_struct_iovec_errno(level, error, iovec, n_iovec)            \
        log_struct_iovec_internal(LOG_REALM_PLUS_LEVEL(LOG_REALM, level), \
                                  error, "__FILE__", "__LINE__", __func__, iovec, n_iovec)
#define log_syntax(unit, level, config_file, config_line, error, ...)   \
        ({                                                              \
                int _level = (level), _e = (error);                     \
                (log_get_max_level() >= LOG_PRI(_level))                \
                        ? log_syntax_internal(unit, _level, config_file, config_line, _e, "__FILE__", "__LINE__", __func__, __VA_ARGS__) \
                        : -abs(_e);                                     \
        })
#define log_syntax_invalid_utf8(unit, level, config_file, config_line, rvalue) \
        ({                                                              \
                int _level = (level);                                   \
                (log_get_max_level() >= LOG_PRI(_level))                \
                        ? log_syntax_invalid_utf8_internal(unit, _level, config_file, config_line, "__FILE__", "__LINE__", __func__, rvalue) \
                        : -EINVAL;                                      \
        })
#  define log_trace(...) log_debug(__VA_ARGS__)
#define log_warning(...)   log_full(LOG_WARNING, __VA_ARGS__)
#define log_warning_errno(error, ...)   log_full_errno(LOG_WARNING, error, __VA_ARGS__)
#define IOVEC_INIT(base, len) { .iov_base = (base), .iov_len = (len) }
#define IOVEC_INIT_STRING(string) IOVEC_INIT((char*) string, strlen(string))
#define IOVEC_MAKE(base, len) (struct iovec) IOVEC_INIT(base, len)
#define IOVEC_MAKE_STRING(string) (struct iovec) IOVEC_INIT_STRING(string)
