
#include<limits.h>
#include<string.h>
#include<stdint.h>
#include<locale.h>
#include<sys/param.h>
#include<stddef.h>
#include<sys/sysmacros.h>
#include<time.h>

#include<errno.h>

#include<alloca.h>

#include<glob.h>
#include<sys/types.h>
#include<stdbool.h>
#include<inttypes.h>
#include<libintl.h>
#include<stdarg.h>

#include<syslog.h>
#include<fnmatch.h>
#include<assert.h>

#include<stdio.h>

#include<stdlib.h>
#define UNIT_NAME_MAX 256
#define ALIGN(l) ALIGN8(l)
#define ALIGN4(l) (((l) + 3) & ~3)
#define ALIGN4_PTR(p) ((void*) ALIGN4((unsigned long) (p)))
#define ALIGN8(l) (((l) + 7) & ~7)
#define ALIGN8_PTR(p) ((void*) ALIGN8((unsigned long) (p)))
#define ALIGN_PTR(p) ((void*) ALIGN((unsigned long) (p)))
#define ALIGN_TO_PTR(p, ali) ((void*) ALIGN_TO((unsigned long) (p), (ali)))
#define BUILTIN_FFS_U32(x) __builtin_ffs(x);
#define CHAR_TO_STR(x) ((char[2]) { x, 0 })
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
                        *p = func(*p);                          \
        }
#define DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(type, func, empty)     \
        static inline void func##p(type *p) {                   \
                if (*p != (empty)) {                            \
                        func(*p);                               \
                        *p = (empty);                           \
                }                                               \
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
#define DISABLE_WARNING_DEPRECATED_DECLARATIONS                         \
        _Pragma("GCC diagnostic push");                                 \
        _Pragma("GCC diagnostic ignored \"-Wdeprecated-declarations\"")
#define DISABLE_WARNING_FLOAT_EQUAL \
        _Pragma("GCC diagnostic push");                                 \
        _Pragma("GCC diagnostic ignored \"-Wfloat-equal\"")
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
#  define DISABLE_WARNING_STRINGOP_TRUNCATION                           \
        _Pragma("GCC diagnostic push");                                 \
        _Pragma("GCC diagnostic ignored \"-Wstringop-truncation\"")
#define DISABLE_WARNING_TYPE_LIMITS \
        _Pragma("GCC diagnostic push");                                 \
        _Pragma("GCC diagnostic ignored \"-Wtype-limits\"")
#define EXIT_TEST_SKIP 77
#define FLAGS_SET(v, flags) \
        ((~(v) & (flags)) == 0)
#define FOREACH_POINTER(p, x, ...)                                                       \
        for (typeof(p) *_l = (typeof(p)[]) { ({ p = x; }), ##__VA_ARGS__, POINTER_MAX }; \
             p != (typeof(p)) POINTER_MAX;                                               \
             p = *(++_l))
#      define HAS_FEATURE_ADDRESS_SANITIZER 1
#      define HAS_FEATURE_MEMORY_SANITIZER 1
#define INT32_TO_PTR(u) ((void *) ((intptr_t) (u)))
#define INT64_TO_PTR(u) ((void *) ((intptr_t) (u)))
#define INT_TO_PTR(u) ((void *) ((intptr_t) (u)))
#define LONG_TO_PTR(u) ((void *) ((intptr_t) (u)))
#define POINTER_MAX ((void*) UINTPTR_MAX)
#define PTR_TO_INT(p) ((int) ((intptr_t) (p)))
#define PTR_TO_INT32(p) ((int32_t) ((intptr_t) (p)))
#define PTR_TO_INT64(p) ((int64_t) ((intptr_t) (p)))
#define PTR_TO_LONG(p) ((long) ((intptr_t) (p)))
#define PTR_TO_SIZE(p) ((size_t) ((uintptr_t) (p)))
#define PTR_TO_UINT(p) ((unsigned) ((uintptr_t) (p)))
#define PTR_TO_UINT32(p) ((uint32_t) ((uintptr_t) (p)))
#define PTR_TO_UINT64(p) ((uint64_t) ((uintptr_t) (p)))
#define PTR_TO_UINT8(p) ((uint8_t) ((uintptr_t) (p)))
#define PTR_TO_ULONG(p) ((unsigned long) ((uintptr_t) (p)))
#define READ_NOW(x)                                                     \
        ({                                                              \
                typeof(x) _copy;                                        \
                memcpy(&_copy, &(x), sizeof(_copy));                    \
                asm volatile ("" : : : "memory");                       \
                _copy;                                                  \
        })
#define REENABLE_WARNING                                                \
        _Pragma("GCC diagnostic pop")
#define SET_FLAG(v, flag, b) \
        (v) = UPDATE_FLAG(v, flag, b)
#define SIZE_TO_PTR(u) ((void *) ((uintptr_t) (u)))
#define STRLEN(x) (sizeof(""x"") - 1)
#define STRV_MAKE(...) ((char**) ((const char*[]) { __VA_ARGS__, NULL }))
#define STRV_MAKE_CONST(...) ((const char* const*) ((const char*[]) { __VA_ARGS__, NULL }))
#define STRV_MAKE_EMPTY ((char*[1]) { NULL })
#define SWAP_TWO(x, y) do {                        \
                typeof(x) _t = (x);                \
                (x) = (y);                         \
                (y) = (_t);                        \
        } while (false)
#define UINT32_TO_PTR(u) ((void *) ((uintptr_t) (u)))
#define UINT64_TO_PTR(u) ((void *) ((uintptr_t) (u)))
#define UINT8_TO_PTR(u) ((void *) ((uintptr_t) (u)))
#define UINT_TO_PTR(u) ((void *) ((uintptr_t) (u)))
#define ULONG_TO_PTR(u) ((void *) ((uintptr_t) (u)))
#define UPDATE_FLAG(orig, flag, b)                      \
        ((b) ? ((orig) | (flag)) : ((orig) & ~(flag)))
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
#define __container_of(uniq, ptr, type, member)                         \
        ({                                                              \
                const typeof( ((type*)0)->member ) *UNIQ_T(A, uniq) = (ptr); \
                (type*)( (char *)UNIQ_T(A, uniq) - offsetof(type, member) ); \
        })
#define _alignas_(x) __attribute__((__aligned__(__alignof(x))))
#define _alignptr_ __attribute__((__aligned__(sizeof(void*))))
#  define _alloc_(...)
#define _deprecated_ __attribute__((__deprecated__))
#define _destructor_ __attribute__((__destructor__))
#define _fallthrough_ __attribute__((__fallthrough__))
#define _function_no_sanitize_float_cast_overflow_ __attribute__((no_sanitize("float-cast-overflow")))
#define _hidden_ __attribute__((__visibility__("hidden")))
#define _likely_(x) (__builtin_expect(!!(x), 1))
#define _malloc_ __attribute__((__malloc__))
#define _noreturn_ _Noreturn
#define _packed_ __attribute__((__packed__))
#define _printf_(a, b) __attribute__((__format__(printf, a, b)))
#define _public_ __attribute__((__visibility__("default")))
#define _sentinel_ __attribute__((__sentinel__))
#define _unlikely_(x) (__builtin_expect(!!(x), 0))
#define _variable_no_sanitize_address_ __attribute__((__no_sanitize_address__))
#define _weak_ __attribute__((__weak__))
#define _weakref_(x) __attribute__((__weakref__(#x)))
#define assert(expr) do {} while (false)
#define assert_log(expr, message) __coverity_check_and_return__(!!(expr))
#define assert_message_se(expr, message) __coverity_check__(!!(expr))
#define assert_not_reached(t)                                           \
        log_assert_failed_unreachable(t, PROJECT_FILE, "__LINE__", __PRETTY_FUNCTION__)
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
#define sizeof_field(struct_type, member) sizeof(((struct_type *) 0)->member)
#define thread_local _Thread_local
#  define ASSERT_NON_ZERO(x) assert((x) != 0)
#define DEBUG_LOGGING _unlikely_(log_get_max_level() >= LOG_DEBUG)
#define ERRNO_VALUE(val)                    (abs(val) & 255)
#define IS_SYNTHETIC_ERRNO(val)             ((val) >> 30 & 1)
#define LOG_MESSAGE(fmt, ...) "MESSAGE=" fmt, ##__VA_ARGS__
#define PROJECT_FILE (&"__FILE__"[STRLEN(RELATIVE_SOURCE_PATH) + 1])
#define SYNTHETIC_ERRNO(num)                (1 << 30 | (num))
#define log_debug(...)     log_full(LOG_DEBUG,   __VA_ARGS__)
#define log_debug_errno(error, ...)     log_full_errno(LOG_DEBUG,   error, __VA_ARGS__)
#define log_dispatch(level, error, buffer)                              \
        log_dispatch_internal(level, error, PROJECT_FILE, "__LINE__", __func__, NULL, NULL, NULL, NULL, buffer)
#define log_dump(level, buffer)                                         \
        log_dump_internal(level, 0, PROJECT_FILE, "__LINE__", __func__, buffer)
#define log_emergency(...) log_full(log_emergency_level(), __VA_ARGS__)
#define log_emergency_errno(error, ...) log_full_errno(log_emergency_level(), error, __VA_ARGS__)
#define log_error(...)     log_full(LOG_ERR,     __VA_ARGS__)
#define log_error_errno(error, ...)     log_full_errno(LOG_ERR,     error, __VA_ARGS__)
#define log_full(level, fmt, ...)                                      \
        ({                                                             \
                if (BUILD_MODE_DEVELOPER)                              \
                        assert(!strstr(fmt, "%m"));                    \
                (void) log_full_errno_zerook(level, 0, fmt, ##__VA_ARGS__); \
        })
#define log_full_errno(level, error, ...)                               \
        ({                                                              \
                int _error = (error);                                   \
                ASSERT_NON_ZERO(_error);                                \
                log_full_errno_zerook(level, _error, __VA_ARGS__);      \
        })
#define log_full_errno_zerook(level, error, ...)                        \
        ({                                                              \
                int _level = (level), _e = (error);                     \
                _e = (log_get_max_level() >= LOG_PRI(_level))           \
                        ? log_internal(_level, _e, PROJECT_FILE, "__LINE__", __func__, __VA_ARGS__) \
                        : -ERRNO_VALUE(_e);                             \
                _e < 0 ? _e : -ESTRPIPE;                                \
        })
#define log_info(...)      log_full(LOG_INFO,    __VA_ARGS__)
#define log_info_errno(error, ...)      log_full_errno(LOG_INFO,    error, __VA_ARGS__)
#define log_notice(...)    log_full(LOG_NOTICE,  __VA_ARGS__)
#define log_notice_errno(error, ...)    log_full_errno(LOG_NOTICE,  error, __VA_ARGS__)
#define log_once(level, ...)                                             \
        ({                                                               \
                if (ONCE)                                                \
                        log_full(level, __VA_ARGS__);                    \
                else if (LOG_PRI(level) != LOG_DEBUG)                    \
                        log_debug(__VA_ARGS__);                          \
        })
#define log_once_errno(level, error, ...)                                \
        ({                                                               \
                int _err = (error);                                      \
                if (ONCE)                                                \
                        _err = log_full_errno(level, _err, __VA_ARGS__); \
                else if (LOG_PRI(level) != LOG_DEBUG)                    \
                        _err = log_debug_errno(_err, __VA_ARGS__);       \
                else                                                     \
                        _err = -ERRNO_VALUE(_err);                       \
                _err;                                                    \
        })
#define log_oom() log_oom_internal(LOG_ERR, PROJECT_FILE, "__LINE__", __func__)
#define log_oom_debug() log_oom_internal(LOG_DEBUG, PROJECT_FILE, "__LINE__", __func__)
#define log_struct(level, ...) log_struct_errno(level, 0, __VA_ARGS__)
#define log_struct_errno(level, error, ...)                             \
        log_struct_internal(level, error, PROJECT_FILE, "__LINE__", __func__, __VA_ARGS__, NULL)
#define log_struct_iovec(level, iovec, n_iovec) log_struct_iovec_errno(level, 0, iovec, n_iovec)
#define log_struct_iovec_errno(level, error, iovec, n_iovec)            \
        log_struct_iovec_internal(level, error, PROJECT_FILE, "__LINE__", __func__, iovec, n_iovec)
#define log_syntax(unit, level, config_file, config_line, error, ...)   \
        ({                                                              \
                int _level = (level), _e = (error);                     \
                (log_get_max_level() >= LOG_PRI(_level))                \
                        ? log_syntax_internal(unit, _level, config_file, config_line, _e, PROJECT_FILE, "__LINE__", __func__, __VA_ARGS__) \
                        : -ERRNO_VALUE(_e);                             \
        })
#define log_syntax_invalid_utf8(unit, level, config_file, config_line, rvalue) \
        ({                                                              \
                int _level = (level);                                   \
                (log_get_max_level() >= LOG_PRI(_level))                \
                        ? log_syntax_invalid_utf8_internal(unit, _level, config_file, config_line, PROJECT_FILE, "__LINE__", __func__, rvalue) \
                        : -EINVAL;                                      \
        })
#  define log_trace(...) log_debug(__VA_ARGS__)
#define log_warning(...)   log_full(LOG_WARNING, __VA_ARGS__)
#define log_warning_errno(error, ...)   log_full_errno(LOG_WARNING, error, __VA_ARGS__)
#define N_(String) String
#define _(String) gettext(String)
#define ERRNO_MAX 4095
#define ENDSWITH_SET(p, ...)                                    \
        ({                                                      \
                const char *_p = (p);                           \
                char  *_found = NULL, **_i;                     \
                STRV_FOREACH(_i, STRV_MAKE(__VA_ARGS__)) {      \
                        _found = endswith(_p, *_i);             \
                        if (_found)                             \
                                break;                          \
                }                                               \
                _found;                                         \
        })
#define FOREACH_STRING(x, y, ...)                                       \
        for (char **_l = STRV_MAKE(({ x = y; }), ##__VA_ARGS__);        \
             x;                                                         \
             x = *(++_l))
#define STARTSWITH_SET(p, ...)                                  \
        ({                                                      \
                const char *_p = (p);                           \
                char  *_found = NULL, **_i;                     \
                STRV_FOREACH(_i, STRV_MAKE(__VA_ARGS__)) {      \
                        _found = startswith(_p, *_i);           \
                        if (_found)                             \
                                break;                          \
                }                                               \
                _found;                                         \
        })
#define STRCASEPTR_IN_SET(x, ...)                                    \
        ({                                                       \
                const char* _x = (x);                            \
                _x && strv_contains_case(STRV_MAKE(__VA_ARGS__), _x); \
        })
#define STRCASE_IN_SET(x, ...) strv_contains_case(STRV_MAKE(__VA_ARGS__), x)
#define STRPTR_IN_SET(x, ...)                                    \
        ({                                                       \
                const char* _x = (x);                            \
                _x && strv_contains(STRV_MAKE(__VA_ARGS__), _x); \
        })
#define STRV_FOREACH(s, l)                      \
        for ((s) = (l); (s) && *(s); (s)++)
#define STRV_FOREACH_BACKWARDS(s, l)                                \
        for (s = ({                                                 \
                        typeof(l) _l = l;                           \
                        _l ? _l + strv_length(_l) - 1U : NULL;      \
                        });                                         \
             (l) && ((s) >= (l));                                   \
             (s)--)
#define STRV_FOREACH_PAIR(x, y, l)               \
        for ((x) = (l), (y) = (x) ? (x+1) : NULL; (x) && *(x) && *(y); (x) += 2, (y) = (x + 1))
#define STRV_IGNORE ((const char *) POINTER_MAX)
#define STR_IN_SET(x, ...) strv_contains(STRV_MAKE(__VA_ARGS__), x)
#define _cleanup_strv_free_ _cleanup_(strv_freep)
#define _cleanup_strv_free_erase_ _cleanup_(strv_free_erasep)
#define string_strv_hashmap_put(h, k, v) _string_strv_hashmap_put(h, k, v  HASHMAP_DEBUG_SRC_ARGS)
#define string_strv_ordered_hashmap_put(h, k, v) _string_strv_ordered_hashmap_put(h, k, v  HASHMAP_DEBUG_SRC_ARGS)
#define strv_contains(l, s) (!!strv_find((l), (s)))
#define strv_contains_case(l, s) (!!strv_find_case((l), (s)))
#define strv_free_and_replace(a, b)             \
        ({                                      \
                strv_free(a);                   \
                (a) = (b);                      \
                (b) = NULL;                     \
                0;                              \
        })
#define strv_from_stdarg_alloca(first)                          \
        ({                                                      \
                char **_l;                                      \
                                                                \
                if (!first)                                     \
                        _l = (char**) &first;                   \
                else {                                          \
                        size_t _n;                              \
                        va_list _ap;                            \
                                                                \
                        _n = 1;                                 \
                        va_start(_ap, first);                   \
                        while (va_arg(_ap, char*))              \
                                _n++;                           \
                        va_end(_ap);                            \
                                                                \
                        _l = newa(char*, _n+1);                 \
                        _l[_n = 0] = (char*) first;             \
                        va_start(_ap, first);                   \
                        for (;;) {                              \
                                _l[++_n] = va_arg(_ap, char*);  \
                                if (!_l[_n])                    \
                                        break;                  \
                        }                                       \
                        va_end(_ap);                            \
                }                                               \
                _l;                                             \
        })
#define strv_new(...) strv_new_internal(__VA_ARGS__, NULL)
#define ALPHANUMERICAL    LETTERS DIGITS
#define CELLESCAPE_DEFAULT_LENGTH 64
#define COMMENTS          "#;"
#define DIGITS            "0123456789"
#define GLOB_CHARS        "*?["
#define HEXDIGITS         DIGITS "abcdefABCDEF"
#define LETTERS           LOWERCASE_LETTERS UPPERCASE_LETTERS
#define LOWERCASE_LETTERS "abcdefghijklmnopqrstuvwxyz"
#define NEWLINE           "\n\r"
#define QUOTES            "\"\'"
#define UPPERCASE_LETTERS "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define WHITESPACE        " \t\n\r"
#define strextend(x, ...) strextend_with_separator_internal(x, NULL, __VA_ARGS__, NULL)
#define strextend_with_separator(x, separator, ...) strextend_with_separator_internal(x, separator, __VA_ARGS__, NULL)
#define strextendf(x, ...) strextendf_with_separator(x, NULL, __VA_ARGS__)
#define strjoin(a, ...) strjoin_real((a), __VA_ARGS__, NULL)
#define strjoina(a, ...)                                                \
        ({                                                              \
                const char *_appendees_[] = { a, __VA_ARGS__ };         \
                char *_d_, *_p_;                                        \
                size_t _len_ = 0;                                       \
                size_t _i_;                                             \
                for (_i_ = 0; _i_ < ELEMENTSOF(_appendees_) && _appendees_[_i_]; _i_++) \
                        _len_ += strlen(_appendees_[_i_]);              \
                _p_ = _d_ = newa(char, _len_ + 1);                      \
                for (_i_ = 0; _i_ < ELEMENTSOF(_appendees_) && _appendees_[_i_]; _i_++) \
                        _p_ = stpcpy(_p_, _appendees_[_i_]);            \
                *_p_ = 0;                                               \
                _d_;                                                    \
        })
#define ALLOCA_MAX (4U*1024U*1024U)
#define GREEDY_REALLOC(array, need)                                     \
        greedy_realloc((void**) &(array), (need), sizeof((array)[0]))
#define GREEDY_REALLOC0(array, need)                                    \
        greedy_realloc0((void**) &(array), (need), sizeof((array)[0]))
#define MALLOC_ELEMENTSOF(x) \
        (__builtin_choose_expr(                                         \
                __builtin_types_compatible_p(typeof(x), typeof(&*(x))), \
                MALLOC_SIZEOF_SAFE(x)/sizeof((x)[0]),                   \
                VOID_0))
#define MALLOC_SIZEOF_SAFE(x) \
        MIN(malloc_usable_size(x), __builtin_object_size(x, 0))
#define _cleanup_free_ _cleanup_(freep)
#define alloca0(n)                                      \
        ({                                              \
                char *_new_;                            \
                size_t _len_ = n;                       \
                assert(_len_ <= ALLOCA_MAX);            \
                _new_ = alloca(_len_ ?: 1);             \
                (void *) memset(_new_, 0, _len_);       \
        })
#define alloca0_align(size, align)                                      \
        ({                                                              \
                void *_new_;                                            \
                size_t _xsize_ = (size);                                \
                _new_ = alloca_align(_xsize_, (align));                 \
                (void*)memset(_new_, 0, _xsize_);                       \
        })
#define alloca_align(size, align)                                       \
        ({                                                              \
                void *_ptr_;                                            \
                size_t _mask_ = (align) - 1;                            \
                size_t _size_ = size;                                   \
                assert(_size_ <= ALLOCA_MAX);                           \
                _ptr_ = alloca((_size_ + _mask_) ?: 1);                 \
                (void*)(((uintptr_t)_ptr_ + _mask_) & ~_mask_);         \
        })
#define free_and_replace(a, b)                  \
        ({                                      \
                free(a);                        \
                (a) = (b);                      \
                (b) = NULL;                     \
                0;                              \
        })
#define malloc0(n) (calloc(1, (n) ?: 1))
#define memdupa(p, l)                           \
        ({                                      \
                void *_q_;                      \
                size_t _l_ = l;                 \
                assert(_l_ <= ALLOCA_MAX);      \
                _q_ = alloca(_l_ ?: 1);         \
                memcpy_safe(_q_, p, _l_);       \
        })
#define memdupa_suffix0(p, l)                   \
        ({                                      \
                void *_q_;                      \
                size_t _l_ = l;                 \
                assert(_l_ <= ALLOCA_MAX);      \
                _q_ = alloca(_l_ + 1);          \
                ((uint8_t*) _q_)[_l_] = 0;      \
                memcpy_safe(_q_, p, _l_);       \
        })
#  define msan_unpoison(r, s) __msan_unpoison(r, s)
#define new(t, n) ((t*) malloc_multiply(sizeof(t), (n)))
#define new0(t, n) ((t*) calloc((n) ?: 1, sizeof(t)))
#define newa(t, n)                                                      \
        ({                                                              \
                size_t _n_ = n;                                         \
                assert(!size_multiply_overflow(sizeof(t), _n_));        \
                assert(sizeof(t)*_n_ <= ALLOCA_MAX);                    \
                (t*) alloca((sizeof(t)*_n_) ?: 1);                      \
        })
#define newa0(t, n)                                                     \
        ({                                                              \
                size_t _n_ = n;                                         \
                assert(!size_multiply_overflow(sizeof(t), _n_));        \
                assert(sizeof(t)*_n_ <= ALLOCA_MAX);                    \
                (t*) alloca0((sizeof(t)*_n_) ?: 1);                     \
        })
#define newdup(t, p, n) ((t*) memdup_multiply(p, sizeof(t), (n)))
#define newdup_suffix0(t, p, n) ((t*) memdup_suffix0_multiply(p, sizeof(t), (n)))
#define HASHMAP_BASE(h) \
        __builtin_choose_expr(PTR_COMPATIBLE_WITH_HASHMAP_BASE(h), \
                (HashmapBase*)(h), \
                (void)0)
# define HASHMAP_DEBUG_PARAMS , const char *func, const char *file, int line
# define HASHMAP_DEBUG_PASS_ARGS   , func, file, line
# define HASHMAP_DEBUG_SRC_ARGS   , __func__, PROJECT_FILE, "__LINE__"
#define HASHMAP_FOREACH(e, h) \
        _HASHMAP_FOREACH(e, h, UNIQ_T(i, UNIQ))
#define HASHMAP_FOREACH_KEY(e, k, h) \
        _HASHMAP_FOREACH_KEY(e, k, h, UNIQ_T(i, UNIQ))
#define HASH_KEY_SIZE 16
#define ITERATOR_FIRST ((Iterator) { .idx = _IDX_ITERATOR_FIRST, .next_key = NULL })
#define ITERATOR_IS_FIRST(i) ((i).idx == _IDX_ITERATOR_FIRST)
#define ORDERED_HASHMAP_FOREACH(e, h) \
        _ORDERED_HASHMAP_FOREACH(e, h, UNIQ_T(i, UNIQ))
#define ORDERED_HASHMAP_FOREACH_KEY(e, k, h) \
        _ORDERED_HASHMAP_FOREACH_KEY(e, k, h, UNIQ_T(i, UNIQ))
#define PLAIN_HASHMAP(h) \
        __builtin_choose_expr(PTR_COMPATIBLE_WITH_PLAIN_HASHMAP(h), \
                (Hashmap*)(h), \
                (void)0)
#define PTR_COMPATIBLE_WITH_HASHMAP_BASE(h) \
        (__builtin_types_compatible_p(typeof(h), HashmapBase*) || \
         __builtin_types_compatible_p(typeof(h), Hashmap*) || \
         __builtin_types_compatible_p(typeof(h), OrderedHashmap*) || \
         __builtin_types_compatible_p(typeof(h), Set*))
#define PTR_COMPATIBLE_WITH_PLAIN_HASHMAP(h) \
        (__builtin_types_compatible_p(typeof(h), Hashmap*) || \
         __builtin_types_compatible_p(typeof(h), OrderedHashmap*)) \

#define _HASHMAP_FOREACH(e, h, i) \
        for (Iterator i = ITERATOR_FIRST; hashmap_iterate((h), &i, (void**)&(e), NULL); )
#define _HASHMAP_FOREACH_KEY(e, k, h, i) \
        for (Iterator i = ITERATOR_FIRST; hashmap_iterate((h), &i, (void**)&(e), (const void**) &(k)); )
#define _IDX_ITERATOR_FIRST (UINT_MAX - 1)
#define _ORDERED_HASHMAP_FOREACH(e, h, i) \
        for (Iterator i = ITERATOR_FIRST; ordered_hashmap_iterate((h), &i, (void**)&(e), NULL); )
#define _ORDERED_HASHMAP_FOREACH_KEY(e, k, h, i) \
        for (Iterator i = ITERATOR_FIRST; ordered_hashmap_iterate((h), &i, (void**)&(e), (const void**) &(k)); )
#define _cleanup_hashmap_free_ _cleanup_(hashmap_freep)
#define _cleanup_hashmap_free_free_ _cleanup_(hashmap_free_freep)
#define _cleanup_hashmap_free_free_free_ _cleanup_(hashmap_free_free_freep)
#define _cleanup_iterated_cache_free_ _cleanup_(iterated_cache_freep)
#define _cleanup_ordered_hashmap_free_ _cleanup_(ordered_hashmap_freep)
#define _cleanup_ordered_hashmap_free_free_ _cleanup_(ordered_hashmap_free_freep)
#define _cleanup_ordered_hashmap_free_free_free_ _cleanup_(ordered_hashmap_free_free_freep)
#define hashmap_clear_with_destructor(h, f)                     \
        ({                                                      \
                Hashmap *_h = (h);                              \
                void *_item;                                    \
                while ((_item = hashmap_steal_first(_h)))       \
                        f(_item);                               \
                _h;                                             \
        })
#define hashmap_copy(h) ((Hashmap*) _hashmap_copy(HASHMAP_BASE(h)  HASHMAP_DEBUG_SRC_ARGS))
#define hashmap_ensure_allocated(h, ops) _hashmap_ensure_allocated(h, ops  HASHMAP_DEBUG_SRC_ARGS)
#define hashmap_ensure_put(s, ops, key, value) _hashmap_ensure_put(s, ops, key, value  HASHMAP_DEBUG_SRC_ARGS)
#define hashmap_free_and_replace(a, b)          \
        ({                                      \
                hashmap_free(a);                \
                (a) = (b);                      \
                (b) = NULL;                     \
                0;                              \
        })
#define hashmap_free_with_destructor(h, f)                      \
        hashmap_free(hashmap_clear_with_destructor(h, f))
#define hashmap_merge(h, other) _hashmap_merge(PLAIN_HASHMAP(h), PLAIN_HASHMAP(other))
#define hashmap_new(ops) _hashmap_new(ops  HASHMAP_DEBUG_SRC_ARGS)
#define hashmap_put_strdup(h, k, v) hashmap_put_strdup_full(h, &string_hash_ops_free_free, k, v)
#define hashmap_put_strdup_full(h, hash_ops, k, v) _hashmap_put_strdup_full(h, hash_ops, k, v  HASHMAP_DEBUG_SRC_ARGS)
#define ordered_hashmap_clear_with_destructor(h, f)                     \
        ({                                                              \
                OrderedHashmap *_h = (h);                               \
                void *_item;                                            \
                while ((_item = ordered_hashmap_steal_first(_h)))       \
                        f(_item);                                       \
                _h;                                                     \
        })
#define ordered_hashmap_copy(h) ((OrderedHashmap*) _hashmap_copy(HASHMAP_BASE(h)  HASHMAP_DEBUG_SRC_ARGS))
#define ordered_hashmap_ensure_allocated(h, ops) _ordered_hashmap_ensure_allocated(h, ops  HASHMAP_DEBUG_SRC_ARGS)
#define ordered_hashmap_ensure_put(s, ops, key, value) _ordered_hashmap_ensure_put(s, ops, key, value  HASHMAP_DEBUG_SRC_ARGS)
#define ordered_hashmap_free_with_destructor(h, f)                      \
        ordered_hashmap_free(ordered_hashmap_clear_with_destructor(h, f))
#define ordered_hashmap_merge(h, other) hashmap_merge(h, other)
#define ordered_hashmap_new(ops) _ordered_hashmap_new(ops  HASHMAP_DEBUG_SRC_ARGS)
#define DEFINE_HASH_OPS(name, type, hash_func, compare_func)            \
        _DEFINE_HASH_OPS(UNIQ, name, type, hash_func, compare_func, NULL, NULL,)
#define DEFINE_HASH_OPS_FULL(name, type, hash_func, compare_func, free_key_func, value_type, free_value_func) \
        _DEFINE_HASH_OPS_FULL(UNIQ, name, type, hash_func, compare_func, free_key_func, value_type, free_value_func,)
#define DEFINE_HASH_OPS_WITH_KEY_DESTRUCTOR(name, type, hash_func, compare_func, free_func) \
        _DEFINE_HASH_OPS_WITH_KEY_DESTRUCTOR(UNIQ, name, type, hash_func, compare_func, free_func,)
#define DEFINE_HASH_OPS_WITH_VALUE_DESTRUCTOR(name, type, hash_func, compare_func, value_type, free_func) \
        _DEFINE_HASH_OPS_WITH_VALUE_DESTRUCTOR(UNIQ, name, type, hash_func, compare_func, value_type, free_func,)
#define DEFINE_PRIVATE_HASH_OPS(name, type, hash_func, compare_func)    \
        _DEFINE_HASH_OPS(UNIQ, name, type, hash_func, compare_func, NULL, NULL, static)
#define DEFINE_PRIVATE_HASH_OPS_FULL(name, type, hash_func, compare_func, free_key_func, value_type, free_value_func) \
        _DEFINE_HASH_OPS_FULL(UNIQ, name, type, hash_func, compare_func, free_key_func, value_type, free_value_func, static)
#define DEFINE_PRIVATE_HASH_OPS_WITH_KEY_DESTRUCTOR(name, type, hash_func, compare_func, free_func) \
        _DEFINE_HASH_OPS_WITH_KEY_DESTRUCTOR(UNIQ, name, type, hash_func, compare_func, free_func, static)
#define DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(name, type, hash_func, compare_func, value_type, free_func) \
        _DEFINE_HASH_OPS_WITH_VALUE_DESTRUCTOR(UNIQ, name, type, hash_func, compare_func, value_type, free_func, static)
#define _DEFINE_FREE_FUNC(uq, type, wrapper_name, func)                 \
                                           \
        static void UNIQ_T(wrapper_name, uq)(void *a) {                 \
                type *_a = a;                                           \
                func(_a);                                               \
        }
#define _DEFINE_HASH_OPS(uq, name, type, hash_func, compare_func, free_key_func, free_value_func, scope) \
        _unused_ static void (* UNIQ_T(static_hash_wrapper, uq))(const type *, struct siphash *) = hash_func; \
        _unused_ static int (* UNIQ_T(static_compare_wrapper, uq))(const type *, const type *) = compare_func; \
        scope const struct hash_ops name = {                            \
                .hash = (hash_func_t) hash_func,                        \
                .compare = (compare_func_t) compare_func,               \
                .free_key = free_key_func,                              \
                .free_value = free_value_func,                          \
        }
#define _DEFINE_HASH_OPS_FULL(uq, name, type, hash_func, compare_func, free_key_func, type_value, free_value_func, scope) \
        _DEFINE_FREE_FUNC(uq, type, static_free_key_wrapper, free_key_func); \
        _DEFINE_FREE_FUNC(uq, type_value, static_free_value_wrapper, free_value_func); \
        _DEFINE_HASH_OPS(uq, name, type, hash_func, compare_func,       \
                         UNIQ_T(static_free_key_wrapper, uq),           \
                         UNIQ_T(static_free_value_wrapper, uq), scope)
#define _DEFINE_HASH_OPS_WITH_KEY_DESTRUCTOR(uq, name, type, hash_func, compare_func, free_func, scope) \
        _DEFINE_FREE_FUNC(uq, type, static_free_wrapper, free_func);    \
        _DEFINE_HASH_OPS(uq, name, type, hash_func, compare_func,       \
                         UNIQ_T(static_free_wrapper, uq), NULL, scope)
#define _DEFINE_HASH_OPS_WITH_VALUE_DESTRUCTOR(uq, name, type, hash_func, compare_func, type_value, free_func, scope) \
        _DEFINE_FREE_FUNC(uq, type_value, static_free_wrapper, free_func); \
        _DEFINE_HASH_OPS(uq, name, type, hash_func, compare_func,       \
                         NULL, UNIQ_T(static_free_wrapper, uq), scope)
#define devt_compare_func uint64_compare_func
#define devt_hash_func uint64_hash_func
#define devt_hash_ops uint64_hash_ops
#define string_compare_func strcmp
#define siphash24_compress_byte(byte, state) siphash24_compress((const uint8_t[]) { (byte) }, 1, (state))
#define DUAL_TIMESTAMP_HAS_CLOCK(clock)                               \
        IN_SET(clock, CLOCK_REALTIME, CLOCK_REALTIME_ALARM, CLOCK_MONOTONIC)
#define DUAL_TIMESTAMP_NULL ((struct dual_timestamp) {})
#define FORMAT_TIMESPAN_MAX 64U
#define FORMAT_TIMESTAMP_MAX (3U+1U+10U+1U+8U+1U+6U+1U+6U+1U)
#define FORMAT_TIMESTAMP_RELATIVE_MAX 256U
#define FORMAT_TIMESTAMP_WIDTH 28U 
#define MSEC_PER_SEC  1000ULL
#define NSEC_FMT "%" PRI_NSEC
#define NSEC_INFINITY ((nsec_t) UINT64_MAX)
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
#define USEC_INFINITY ((usec_t) UINT64_MAX)
#define USEC_PER_DAY ((usec_t) (24ULL*USEC_PER_HOUR))
#define USEC_PER_HOUR ((usec_t) (60ULL*USEC_PER_MINUTE))
#define USEC_PER_MINUTE ((usec_t) (60ULL*USEC_PER_SEC))
#define USEC_PER_MONTH ((usec_t) (2629800ULL*USEC_PER_SEC))
#define USEC_PER_MSEC ((usec_t) 1000ULL)
#define USEC_PER_SEC  ((usec_t) 1000000ULL)
#define USEC_PER_WEEK ((usec_t) (7ULL*USEC_PER_DAY))
#define USEC_PER_YEAR ((usec_t) (31557600ULL*USEC_PER_SEC))
#define USEC_TIMESTAMP_FORMATTABLE_MAX ((usec_t) 253402214399000000)
#define SPECIAL_APP_SLICE "app.slice"
#define SPECIAL_BACKGROUND_SLICE "background.slice"
#define SPECIAL_BASIC_TARGET "basic.target"
#define SPECIAL_CTRL_ALT_DEL_TARGET "ctrl-alt-del.target"
#define SPECIAL_DBUS_SERVICE "dbus.service"
#define SPECIAL_DBUS_SOCKET "dbus.socket"
#define SPECIAL_DEFAULT_TARGET "default.target"
#define SPECIAL_EMERGENCY_TARGET "emergency.target"
#define SPECIAL_EXIT_TARGET "exit.target"
#define SPECIAL_FSCK_ROOT_SERVICE "systemd-fsck-root.service"
#define SPECIAL_FSCK_SERVICE "systemd-fsck@.service"
#define SPECIAL_FSCK_USR_SERVICE "systemd-fsck-usr.service"
#define SPECIAL_GRAPHICAL_TARGET "graphical.target"
#define SPECIAL_HALT_TARGET "halt.target"
#define SPECIAL_HIBERNATE_TARGET "hibernate.target"
#define SPECIAL_HYBRID_SLEEP_TARGET "hybrid-sleep.target"
#define SPECIAL_INITRD_FS_TARGET "initrd-fs.target"
#define SPECIAL_INITRD_ROOT_DEVICE_TARGET "initrd-root-device.target"
#define SPECIAL_INITRD_ROOT_FS_TARGET "initrd-root-fs.target"
#define SPECIAL_INITRD_TARGET "initrd.target"
#define SPECIAL_INITRD_USR_FS_TARGET "initrd-usr-fs.target"
#define SPECIAL_INIT_SCOPE "init.scope"
#define SPECIAL_JOURNALD_SERVICE "systemd-journald.service"
#define SPECIAL_JOURNALD_SOCKET "systemd-journald.socket"
#define SPECIAL_KBREQUEST_TARGET "kbrequest.target"
#define SPECIAL_KEXEC_TARGET "kexec.target"
#define SPECIAL_LOCAL_FS_PRE_TARGET "local-fs-pre.target"
#define SPECIAL_LOCAL_FS_TARGET "local-fs.target"
#define SPECIAL_MACHINE_SLICE "machine.slice"
#define SPECIAL_MULTI_USER_TARGET "multi-user.target"
#define SPECIAL_NETWORK_ONLINE_TARGET "network-online.target"
#define SPECIAL_NETWORK_TARGET "network.target"           
#define SPECIAL_NSS_LOOKUP_TARGET "nss-lookup.target"     
#define SPECIAL_PATHS_TARGET "paths.target"
#define SPECIAL_POWEROFF_TARGET "poweroff.target"
#define SPECIAL_QUOTACHECK_SERVICE "systemd-quotacheck.service"
#define SPECIAL_QUOTAON_SERVICE "quotaon.service"
#define SPECIAL_REBOOT_TARGET "reboot.target"
#define SPECIAL_REMOTE_FS_PRE_TARGET "remote-fs-pre.target"
#define SPECIAL_REMOTE_FS_TARGET "remote-fs.target"       
#define SPECIAL_REMOUNT_FS_SERVICE "systemd-remount-fs.service"
#define SPECIAL_RESCUE_TARGET "rescue.target"
#define SPECIAL_ROOT_MOUNT "-.mount"
#define SPECIAL_ROOT_SLICE "-.slice"
#define SPECIAL_RPCBIND_TARGET "rpcbind.target"           
#define SPECIAL_SESSION_SLICE "session.slice"
#define SPECIAL_SHUTDOWN_TARGET "shutdown.target"
#define SPECIAL_SIGPWR_TARGET "sigpwr.target"
#define SPECIAL_SOCKETS_TARGET "sockets.target"
#define SPECIAL_SUSPEND_TARGET "suspend.target"
#define SPECIAL_SUSPEND_THEN_HIBERNATE_TARGET "suspend-then-hibernate.target"
#define SPECIAL_SWAP_TARGET "swap.target"
#define SPECIAL_SYSINIT_TARGET "sysinit.target"
#define SPECIAL_SYSTEM_SLICE "system.slice"
#define SPECIAL_TIMERS_TARGET "timers.target"
#define SPECIAL_TIME_SET_TARGET "time-set.target"
#define SPECIAL_TIME_SYNC_TARGET "time-sync.target"       
#define SPECIAL_TMPFILES_SETUP_SERVICE "systemd-tmpfiles-setup.service"
#define SPECIAL_UDEVD_SERVICE "systemd-udevd.service"
#define SPECIAL_UMOUNT_TARGET "umount.target"
#define SPECIAL_USER_SLICE "user.slice"
#define SPECIAL_VOLATILE_ROOT_SERVICE "systemd-volatile-root.service"
#  define DEFAULT_PATH DEFAULT_PATH_SPLIT_USR
#define DEFAULT_PATH_COMPAT PATH_SPLIT_SBIN_BIN("/usr/local/") ":" PATH_SPLIT_SBIN_BIN("/usr/") ":" PATH_SPLIT_SBIN_BIN("/")
#define DEFAULT_PATH_NORMAL PATH_SBIN_BIN("/usr/local/") ":" PATH_SBIN_BIN("/usr/")
#define DEFAULT_PATH_NORMAL_NULSTR PATH_SBIN_BIN_NULSTR("/usr/local/") PATH_SBIN_BIN_NULSTR("/usr/")
#  define DEFAULT_PATH_NULSTR DEFAULT_PATH_SPLIT_USR_NULSTR
#define DEFAULT_PATH_SPLIT_USR DEFAULT_PATH_NORMAL ":" PATH_SBIN_BIN("/")
#define DEFAULT_PATH_SPLIT_USR_NULSTR DEFAULT_PATH_NORMAL_NULSTR PATH_SBIN_BIN_NULSTR("/")
#  define DEFAULT_USER_PATH DEFAULT_PATH
#define PATH_FOREACH_PREFIX(prefix, path)                               \
        for (char *_slash = ({                                          \
                                path_simplify(strcpy(prefix, path));    \
                                streq(prefix, "/") ? NULL : strrchr(prefix, '/'); \
                        });                                             \
             _slash && ((*_slash = 0), true);                           \
             _slash = strrchr((prefix), '/'))
#define PATH_FOREACH_PREFIX_MORE(prefix, path)                          \
        for (char *_slash = ({                                          \
                                path_simplify(strcpy(prefix, path));    \
                                if (streq(prefix, "/"))                 \
                                        prefix[0] = 0;                  \
                                strrchr(prefix, 0);                     \
                        });                                             \
             _slash && ((*_slash = 0), true);                           \
             _slash = strrchr((prefix), '/'))
#define PATH_IN_SET(p, ...) path_strv_contains(STRV_MAKE(__VA_ARGS__), p)
#define PATH_NORMAL_SBIN_BIN(x) x "bin"
#define PATH_NORMAL_SBIN_BIN_NULSTR(x) x "bin\0"
#  define PATH_SBIN_BIN(x) PATH_SPLIT_SBIN_BIN(x)
#  define PATH_SBIN_BIN_NULSTR(x) PATH_SPLIT_SBIN_BIN_NULSTR(x)
#define PATH_SPLIT_SBIN_BIN(x) x "sbin:" x "bin"
#define PATH_SPLIT_SBIN_BIN_NULSTR(x) x "sbin\0" x "bin\0"
#define PATH_STARTSWITH_SET(p, ...) path_startswith_strv(p, STRV_MAKE(__VA_ARGS__))
#define path_extend(x, ...) path_extend_internal(x, __VA_ARGS__, POINTER_MAX)
#define path_join(...) path_extend_internal(NULL, __VA_ARGS__, POINTER_MAX)
#define prefix_roota(root, path)                                        \
        ({                                                              \
                const char* _path = (path), *_root = (root), *_ret;     \
                char *_p, *_n;                                          \
                size_t _l;                                              \
                while (_path[0] == '/' && _path[1] == '/')              \
                        _path ++;                                       \
                if (isempty(_root))                                     \
                        _ret = _path;                                   \
                else {                                                  \
                        _l = strlen(_root) + 1 + strlen(_path) + 1;     \
                        _n = newa(char, _l);                            \
                        _p = stpcpy(_n, _root);                         \
                        while (_p > _n && _p[-1] == '/')                \
                                _p--;                                   \
                        if (_path[0] != '/')                            \
                                *(_p++) = '/';                          \
                        strcpy(_p, _path);                              \
                        _ret = _n;                                      \
                }                                                       \
                _ret;                                                   \
        })
#define _cleanup_globfree_ _cleanup_(globfree)
