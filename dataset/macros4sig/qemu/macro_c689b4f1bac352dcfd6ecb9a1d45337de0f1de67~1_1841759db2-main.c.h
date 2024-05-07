

#include<stddef.h>

#include<sys/signal.h>
#include<sys/uio.h>


#include<inttypes.h>
#include<sys/time.h>
#include<fcntl.h>

#include<string.h>
#include<sys/types.h>
#include<ctype.h>
#include<stdint.h>


#include<assert.h>


#include<strings.h>
#include<sys/wait.h>
#include<syslog.h>
#include<errno.h>
#include<stdbool.h>
#include<stdarg.h>
#include<signal.h>

#include<limits.h>
#include<sys/stat.h>



#include<getopt.h>

#include<stdio.h>

#include<linux/fs.h>
#include<unistd.h>



#include<time.h>
#include<emmintrin.h>


#include<stdlib.h>
#define QGA_SERVICE_DESCRIPTION  "Enables integration with QEMU machine emulator and virtualizer."
#define QGA_SERVICE_DISPLAY_NAME "QEMU Guest Agent"

#define QGA_SERVICE_NAME         "qemu-ga"

#define CPU_CONVERT(endian, size, type)\
static inline type endian ## size ## _to_cpu(type v)\
{\
    return glue(endian, _bswap)(v, size);\
}\
\
static inline type cpu_to_ ## endian ## size(type v)\
{\
    return glue(endian, _bswap)(v, size);\
}\
\
static inline void endian ## size ## _to_cpus(type *p)\
{\
    glue(endian, _bswaps)(p, size);\
}\
\
static inline void cpu_to_ ## endian ## size ## s(type *p)\
{\
    glue(endian, _bswaps)(p, size);\
}\
\
static inline type endian ## size ## _to_cpup(const type *p)\
{\
    return glue(glue(endian, size), _to_cpu)(*p);\
}\
\
static inline void cpu_to_ ## endian ## size ## w(type *p, type v)\
{\
    *p = glue(glue(cpu_to_, endian), size)(v);\
}
#define be_bswap(v, size) (v)
#define be_bswaps(v, size)
#define le_bswap(v, size) glue(bswap, size)(v)
#define le_bswaps(p, size) do { *p = glue(bswap, size)(*p); } while(0)
#define INLINE static inline
#define LIT64( a ) a##LL

#define STATUS(field) status->field
#define STATUS_PARAM , float_status *status
#define STATUS_VAR , status
#define const_float16(x) (x)
#define const_float32(x) { x }
#define const_float64(x) { x }
#define float128_zero make_float128(0, 0)
#define float16_val(x) (x)
#define float32_half make_float32(0x3f000000)
#define float32_infinity make_float32(0x7f800000)
#define float32_ln2 make_float32(0x3f317218)
#define float32_one make_float32(0x3f800000)
#define float32_pi make_float32(0x40490fdb)
#define float32_val(x) (((float32)(x)).v)
#define float32_zero make_float32(0)
#define float64_half make_float64(0x3fe0000000000000LL)
#define float64_infinity make_float64(0x7ff0000000000000LL)
#define float64_ln2 make_float64(0x3fe62e42fefa39efLL)
#define float64_one make_float64(0x3ff0000000000000LL)
#define float64_pi make_float64(0x400921fb54442d18LL)
#define float64_val(x) (((float64)(x)).v)
#define float64_zero make_float64(0)
#define floatx80_half make_floatx80(0x3ffe, 0x8000000000000000LL)
#define floatx80_infinity make_floatx80(0x7fff, 0x8000000000000000LL)
#define floatx80_ln2 make_floatx80(0x3ffe, 0xb17217f7d1cf79acLL)
#define floatx80_one make_floatx80(0x3fff, 0x8000000000000000LL)
#define floatx80_pi make_floatx80(0x4000, 0xc90fdaa22168c235LL)
#define floatx80_zero make_floatx80(0x0000, 0x0000000000000000LL)
#define make_float128(high_, low_) ((float128) { .high = high_, .low = low_ })
#define make_float128_init(high_, low_) { .high = high_, .low = low_ }
#define make_float16(x) (x)
#define make_float32(x) __extension__ ({ float32 f32_val = {x}; f32_val; })
#define make_float64(x) __extension__ ({ float64 f64_val = {x}; f64_val; })
#define make_floatx80(exp, mant) ((floatx80) { mant, exp })
#define make_floatx80_init(exp, mant) { .low = mant, .high = exp }
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#define DO_UPCAST(type, field, dev) ( __extension__ ( { \
    char __attribute__((unused)) offset_must_be_zero[ \
        -offsetof(type, field)]; \
    container_of(dev, type, field);}))
#define FMT_pid "%ld"
#define IOV_MAX 1024
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define QEMU_MADV_DONTDUMP MADV_DONTDUMP
#define QEMU_MADV_DONTFORK  MADV_DONTFORK
#define QEMU_MADV_DONTNEED  MADV_DONTNEED
#define QEMU_MADV_HUGEPAGE MADV_HUGEPAGE
#define QEMU_MADV_INVALID -1
#define QEMU_MADV_MERGEABLE MADV_MERGEABLE
#define QEMU_MADV_WILLNEED  MADV_WILLNEED

#define ROUND_UP(n,d) (((n) + (d) - 1) & -(d))
#define WEXITSTATUS(x) (x)
#define WIFEXITED(x)   1
#define __builtin_expect(x, n) (x)
#define container_of(ptr, type, member) ({                      \
        const typeof(((type *) 0)->member) *__mptr = (ptr);     \
        (type *) ((char *) __mptr - offsetof(type, member));})
#define glue(x, y) xglue(x, y)
#define inline __attribute__ (( always_inline )) __inline__
#define likely(x)   __builtin_expect(!!(x), 1)
#define qemu_printf printf
#define qemu_timersub timersub
#define stringify(s)	tostring(s)
#define tostring(s)	#s
#define type_check(t1,t2) ((t1*)0 - (t2*)0)
#define typeof_field(type, field) typeof(((type *)0)->field)
#define unlikely(x)   __builtin_expect(!!(x), 0)
#define xglue(x, y) x ## y



#define error_setg(err, fmt, ...) \
    error_set(err, ERROR_CLASS_GENERIC_ERROR, fmt, ## __VA_ARGS__)
#define error_setg_errno(err, os_error, fmt, ...) \
    error_set_errno(err, os_error, ERROR_CLASS_GENERIC_ERROR, fmt, ## __VA_ARGS__)

#  define GCC_ATTR __attribute__((__unused__, format(printf, 1, 2)))
#  define GCC_FMT_ATTR(n, m) __attribute__((format(printf, n, m)))
#define QEMU_BUILD_BUG_ON(x) \
    typedef char cat2(qemu_build_bug_on__,"__LINE__")[(x)?-1:1] __attribute__((unused));
# define QEMU_GNUC_PREREQ(maj, min) \
         (("__GNUC__" << 16) + "__GNUC_MINOR__" >= ((maj) << 16) + (min))
#define QEMU_NORETURN __attribute__ ((__noreturn__))
# define QEMU_PACKED __attribute__((gcc_struct, packed))
#define QEMU_WARN_UNUSED_RESULT __attribute__((warn_unused_result))
#   define __printf__ __gnu_printf__
#define cat(x,y) x ## y
#define cat2(x,y) cat(x,y)
#define QDICT_BUCKET_MAX 512

#define qdict_put(qdict, key, obj) \
        qdict_put_obj(qdict, key, QOBJECT(obj))

#define QLIST_EMPTY(head)                ((head)->lh_first == NULL)
#define QLIST_ENTRY(type)                                               \
struct {                                                                \
        struct type *le_next;                         \
        struct type **le_prev;    \
}
#define QLIST_FIRST(head)                ((head)->lh_first)
#define QLIST_FOREACH(var, head, field)                                 \
        for ((var) = ((head)->lh_first);                                \
                (var);                                                  \
                (var) = ((var)->field.le_next))
#define QLIST_FOREACH_SAFE(var, head, field, next_var)                  \
        for ((var) = ((head)->lh_first);                                \
                (var) && ((next_var) = ((var)->field.le_next), 1);      \
                (var) = (next_var))
#define QLIST_HEAD(name, type)                                          \
struct name {                                                           \
        struct type *lh_first;                       \
}
#define QLIST_HEAD_INITIALIZER(head)                                    \
        { NULL }
#define QLIST_INIT(head) do {                                           \
        (head)->lh_first = NULL;                                        \
} while (0)
#define QLIST_INSERT_AFTER(listelm, elm, field) do {                    \
        if (((elm)->field.le_next = (listelm)->field.le_next) != NULL)  \
                (listelm)->field.le_next->field.le_prev =               \
                    &(elm)->field.le_next;                              \
        (listelm)->field.le_next = (elm);                               \
        (elm)->field.le_prev = &(listelm)->field.le_next;               \
} while (0)
#define QLIST_INSERT_BEFORE(listelm, elm, field) do {                   \
        (elm)->field.le_prev = (listelm)->field.le_prev;                \
        (elm)->field.le_next = (listelm);                               \
        *(listelm)->field.le_prev = (elm);                              \
        (listelm)->field.le_prev = &(elm)->field.le_next;               \
} while (0)
#define QLIST_INSERT_HEAD(head, elm, field) do {                        \
        if (((elm)->field.le_next = (head)->lh_first) != NULL)          \
                (head)->lh_first->field.le_prev = &(elm)->field.le_next;\
        (head)->lh_first = (elm);                                       \
        (elm)->field.le_prev = &(head)->lh_first;                       \
} while (0)
#define QLIST_INSERT_HEAD_RCU(head, elm, field) do {                    \
        (elm)->field.le_prev = &(head)->lh_first;                       \
        (elm)->field.le_next = (head)->lh_first;                        \
        smp_wmb();                      \
        if ((head)->lh_first != NULL)  {                                \
            (head)->lh_first->field.le_prev = &(elm)->field.le_next;    \
        }                                                               \
        (head)->lh_first = (elm);                                       \
        smp_wmb();                                                      \
} while (0)
#define QLIST_NEXT(elm, field)           ((elm)->field.le_next)
#define QLIST_REMOVE(elm, field) do {                                   \
        if ((elm)->field.le_next != NULL)                               \
                (elm)->field.le_next->field.le_prev =                   \
                    (elm)->field.le_prev;                               \
        *(elm)->field.le_prev = (elm)->field.le_next;                   \
} while (0)
#define QSIMPLEQ_CONCAT(head1, head2) do {                              \
    if (!QSIMPLEQ_EMPTY((head2))) {                                     \
        *(head1)->sqh_last = (head2)->sqh_first;                        \
        (head1)->sqh_last = (head2)->sqh_last;                          \
        QSIMPLEQ_INIT((head2));                                         \
    }                                                                   \
} while (0)
#define QSIMPLEQ_EMPTY(head)        ((head)->sqh_first == NULL)
#define QSIMPLEQ_ENTRY(type)                                            \
struct {                                                                \
    struct type *sqe_next;                            \
}
#define QSIMPLEQ_FIRST(head)        ((head)->sqh_first)
#define QSIMPLEQ_FOREACH(var, head, field)                              \
    for ((var) = ((head)->sqh_first);                                   \
        (var);                                                          \
        (var) = ((var)->field.sqe_next))
#define QSIMPLEQ_FOREACH_SAFE(var, head, field, next)                   \
    for ((var) = ((head)->sqh_first);                                   \
        (var) && ((next = ((var)->field.sqe_next)), 1);                 \
        (var) = (next))
#define QSIMPLEQ_HEAD(name, type)                                       \
struct name {                                                           \
    struct type *sqh_first;                          \
    struct type **sqh_last;              \
}
#define QSIMPLEQ_HEAD_INITIALIZER(head)                                 \
    { NULL, &(head).sqh_first }
#define QSIMPLEQ_INIT(head) do {                                        \
    (head)->sqh_first = NULL;                                           \
    (head)->sqh_last = &(head)->sqh_first;                              \
} while (0)
#define QSIMPLEQ_INSERT_AFTER(head, listelm, elm, field) do {           \
    if (((elm)->field.sqe_next = (listelm)->field.sqe_next) == NULL)    \
        (head)->sqh_last = &(elm)->field.sqe_next;                      \
    (listelm)->field.sqe_next = (elm);                                  \
} while (0)
#define QSIMPLEQ_INSERT_HEAD(head, elm, field) do {                     \
    if (((elm)->field.sqe_next = (head)->sqh_first) == NULL)            \
        (head)->sqh_last = &(elm)->field.sqe_next;                      \
    (head)->sqh_first = (elm);                                          \
} while (0)
#define QSIMPLEQ_INSERT_TAIL(head, elm, field) do {                     \
    (elm)->field.sqe_next = NULL;                                       \
    *(head)->sqh_last = (elm);                                          \
    (head)->sqh_last = &(elm)->field.sqe_next;                          \
} while (0)
#define QSIMPLEQ_LAST(head, type, field)                                \
    (QSIMPLEQ_EMPTY((head)) ?                                           \
        NULL :                                                          \
            ((struct type *)(void *)                                    \
        ((char *)((head)->sqh_last) - offsetof(struct type, field))))
#define QSIMPLEQ_NEXT(elm, field)   ((elm)->field.sqe_next)
#define QSIMPLEQ_REMOVE(head, elm, type, field) do {                    \
    if ((head)->sqh_first == (elm)) {                                   \
        QSIMPLEQ_REMOVE_HEAD((head), field);                            \
    } else {                                                            \
        struct type *curelm = (head)->sqh_first;                        \
        while (curelm->field.sqe_next != (elm))                         \
            curelm = curelm->field.sqe_next;                            \
        if ((curelm->field.sqe_next =                                   \
            curelm->field.sqe_next->field.sqe_next) == NULL)            \
                (head)->sqh_last = &(curelm)->field.sqe_next;           \
    }                                                                   \
} while (0)
#define QSIMPLEQ_REMOVE_HEAD(head, field) do {                          \
    if (((head)->sqh_first = (head)->sqh_first->field.sqe_next) == NULL)\
        (head)->sqh_last = &(head)->sqh_first;                          \
} while (0)
#define QSLIST_EMPTY(head)       ((head)->slh_first == NULL)
#define QSLIST_ENTRY(type)                                               \
struct {                                                                \
        struct type *sle_next;                        \
}
#define QSLIST_FIRST(head)       ((head)->slh_first)
#define QSLIST_FOREACH(var, head, field)                                 \
        for((var) = (head)->slh_first; (var); (var) = (var)->field.sle_next)
#define QSLIST_FOREACH_SAFE(var, head, field, tvar)                      \
        for ((var) = QSLIST_FIRST((head));                               \
            (var) && ((tvar) = QSLIST_NEXT((var), field), 1);            \
            (var) = (tvar))
#define QSLIST_HEAD(name, type)                                          \
struct name {                                                           \
        struct type *slh_first;                      \
}
#define QSLIST_HEAD_INITIALIZER(head)                                    \
        { NULL }
#define QSLIST_INIT(head) do {                                           \
        (head)->slh_first = NULL;                                       \
} while (0)
#define QSLIST_INSERT_AFTER(slistelm, elm, field) do {                   \
        (elm)->field.sle_next = (slistelm)->field.sle_next;             \
        (slistelm)->field.sle_next = (elm);                             \
} while (0)
#define QSLIST_INSERT_HEAD(head, elm, field) do {                        \
        (elm)->field.sle_next = (head)->slh_first;                      \
        (head)->slh_first = (elm);                                      \
} while (0)
#define QSLIST_NEXT(elm, field)  ((elm)->field.sle_next)
#define QSLIST_REMOVE_AFTER(slistelm, field) do {                        \
        (slistelm)->field.sle_next =                                    \
            QSLIST_NEXT(QSLIST_NEXT((slistelm), field), field);           \
} while (0)
#define QSLIST_REMOVE_HEAD(head, field) do {                             \
        (head)->slh_first = (head)->slh_first->field.sle_next;          \
} while (0)
#define QTAILQ_EMPTY(head)               ((head)->tqh_first == NULL)
#define QTAILQ_ENTRY(type)       Q_TAILQ_ENTRY(struct type,)
#define QTAILQ_FIRST(head)               ((head)->tqh_first)
#define QTAILQ_FOREACH(var, head, field)                                \
        for ((var) = ((head)->tqh_first);                               \
                (var);                                                  \
                (var) = ((var)->field.tqe_next))
#define QTAILQ_FOREACH_REVERSE(var, head, headname, field)              \
        for ((var) = (*(((struct headname *)((head)->tqh_last))->tqh_last));    \
                (var);                                                  \
                (var) = (*(((struct headname *)((var)->field.tqe_prev))->tqh_last)))
#define QTAILQ_FOREACH_SAFE(var, head, field, next_var)                 \
        for ((var) = ((head)->tqh_first);                               \
                (var) && ((next_var) = ((var)->field.tqe_next), 1);     \
                (var) = (next_var))
#define QTAILQ_HEAD(name, type)  Q_TAILQ_HEAD(name, struct type,)
#define QTAILQ_HEAD_INITIALIZER(head)                                   \
        { NULL, &(head).tqh_first }
#define QTAILQ_INIT(head) do {                                          \
        (head)->tqh_first = NULL;                                       \
        (head)->tqh_last = &(head)->tqh_first;                          \
} while (0)
#define QTAILQ_INSERT_AFTER(head, listelm, elm, field) do {             \
        if (((elm)->field.tqe_next = (listelm)->field.tqe_next) != NULL)\
                (elm)->field.tqe_next->field.tqe_prev =                 \
                    &(elm)->field.tqe_next;                             \
        else                                                            \
                (head)->tqh_last = &(elm)->field.tqe_next;              \
        (listelm)->field.tqe_next = (elm);                              \
        (elm)->field.tqe_prev = &(listelm)->field.tqe_next;             \
} while (0)
#define QTAILQ_INSERT_BEFORE(listelm, elm, field) do {                  \
        (elm)->field.tqe_prev = (listelm)->field.tqe_prev;              \
        (elm)->field.tqe_next = (listelm);                              \
        *(listelm)->field.tqe_prev = (elm);                             \
        (listelm)->field.tqe_prev = &(elm)->field.tqe_next;             \
} while (0)
#define QTAILQ_INSERT_HEAD(head, elm, field) do {                       \
        if (((elm)->field.tqe_next = (head)->tqh_first) != NULL)        \
                (head)->tqh_first->field.tqe_prev =                     \
                    &(elm)->field.tqe_next;                             \
        else                                                            \
                (head)->tqh_last = &(elm)->field.tqe_next;              \
        (head)->tqh_first = (elm);                                      \
        (elm)->field.tqe_prev = &(head)->tqh_first;                     \
} while (0)
#define QTAILQ_INSERT_TAIL(head, elm, field) do {                       \
        (elm)->field.tqe_next = NULL;                                   \
        (elm)->field.tqe_prev = (head)->tqh_last;                       \
        *(head)->tqh_last = (elm);                                      \
        (head)->tqh_last = &(elm)->field.tqe_next;                      \
} while (0)
#define QTAILQ_LAST(head, headname) \
        (*(((struct headname *)((head)->tqh_last))->tqh_last))
#define QTAILQ_NEXT(elm, field)          ((elm)->field.tqe_next)
#define QTAILQ_PREV(elm, headname, field) \
        (*(((struct headname *)((elm)->field.tqe_prev))->tqh_last))
#define QTAILQ_REMOVE(head, elm, field) do {                            \
        if (((elm)->field.tqe_next) != NULL)                            \
                (elm)->field.tqe_next->field.tqe_prev =                 \
                    (elm)->field.tqe_prev;                              \
        else                                                            \
                (head)->tqh_last = (elm)->field.tqe_prev;               \
        *(elm)->field.tqe_prev = (elm)->field.tqe_next;                 \
} while (0)
#define Q_TAILQ_ENTRY(type, qual)                                       \
struct {                                                                \
        qual type *tqe_next;                          \
        qual type *qual *tqe_prev;      \
}
#define Q_TAILQ_HEAD(name, type, qual)                                  \
struct name {                                                           \
        qual type *tqh_first;                        \
        qual type *qual *tqh_last;       \
}
#define __QEMU_BARRIER_H 1
#define barrier()   asm volatile("" ::: "memory")
#define smp_mb() __sync_synchronize()
#define smp_rmb()   barrier()
#define smp_wmb()   barrier()
#define QLIST_FOREACH_ENTRY(qlist, var)             \
        for ((var) = ((qlist)->head.tqh_first);     \
            (var);                                  \
            (var) = ((var)->next.tqe_next))

#define qlist_append(qlist, obj) \
        qlist_append_obj(qlist, QOBJECT(obj))
#define QDECREF(obj)              \
    qobject_decref(obj ? QOBJECT(obj) : NULL)
#define QINCREF(obj)      \
    qobject_incref(QOBJECT(obj))
#define QOBJECT(obj) (&(obj)->base)

#define QOBJECT_INIT(obj, qtype_type)   \
    obj->base.refcnt = 1;               \
    obj->base.type   = qtype_type
#define QObject_HEAD  \
    QObject base

#define QERR_ADD_CLIENT_FAILED \
    ERROR_CLASS_GENERIC_ERROR, "Could not add client"
#define QERR_AMBIGUOUS_PATH \
    ERROR_CLASS_GENERIC_ERROR, "Path '%s' does not uniquely identify an object"
#define QERR_BAD_BUS_FOR_DEVICE \
    ERROR_CLASS_GENERIC_ERROR, "Device '%s' can't go on a %s bus"
#define QERR_BASE_NOT_FOUND \
    ERROR_CLASS_GENERIC_ERROR, "Base '%s' not found"
#define QERR_BLOCK_FORMAT_FEATURE_NOT_SUPPORTED \
    ERROR_CLASS_GENERIC_ERROR, "Block format '%s' used by device '%s' does not support feature '%s'"
#define QERR_BLOCK_JOB_NOT_ACTIVE \
    ERROR_CLASS_DEVICE_NOT_ACTIVE, "No active block job on device '%s'"
#define QERR_BLOCK_JOB_NOT_READY \
    ERROR_CLASS_GENERIC_ERROR, "The active block job for device '%s' cannot be completed"
#define QERR_BLOCK_JOB_PAUSED \
    ERROR_CLASS_GENERIC_ERROR, "The block job for device '%s' is currently paused"
#define QERR_BUFFER_OVERRUN \
    ERROR_CLASS_GENERIC_ERROR, "An internal buffer overran"
#define QERR_BUS_NOT_FOUND \
    ERROR_CLASS_GENERIC_ERROR, "Bus '%s' not found"
#define QERR_BUS_NO_HOTPLUG \
    ERROR_CLASS_GENERIC_ERROR, "Bus '%s' does not support hotplugging"
#define QERR_COMMAND_DISABLED \
    ERROR_CLASS_GENERIC_ERROR, "The command %s has been disabled for this instance"
#define QERR_COMMAND_NOT_FOUND \
    ERROR_CLASS_COMMAND_NOT_FOUND, "The command %s has not been found"
#define QERR_DEVICE_ENCRYPTED \
    ERROR_CLASS_DEVICE_ENCRYPTED, "'%s' (%s) is encrypted"
#define QERR_DEVICE_FEATURE_BLOCKS_MIGRATION \
    ERROR_CLASS_GENERIC_ERROR, "Migration is disabled when using feature '%s' in device '%s'"
#define QERR_DEVICE_HAS_NO_MEDIUM \
    ERROR_CLASS_GENERIC_ERROR, "Device '%s' has no medium"
#define QERR_DEVICE_INIT_FAILED \
    ERROR_CLASS_GENERIC_ERROR, "Device '%s' could not be initialized"
#define QERR_DEVICE_IN_USE \
    ERROR_CLASS_GENERIC_ERROR, "Device '%s' is in use"
#define QERR_DEVICE_IS_READ_ONLY \
    ERROR_CLASS_GENERIC_ERROR, "Device '%s' is read only"
#define QERR_DEVICE_LOCKED \
    ERROR_CLASS_GENERIC_ERROR, "Device '%s' is locked"
#define QERR_DEVICE_MULTIPLE_BUSSES \
    ERROR_CLASS_GENERIC_ERROR, "Device '%s' has multiple child busses"
#define QERR_DEVICE_NOT_ACTIVE \
    ERROR_CLASS_DEVICE_NOT_ACTIVE, "Device '%s' has not been activated"
#define QERR_DEVICE_NOT_ENCRYPTED \
    ERROR_CLASS_GENERIC_ERROR, "Device '%s' is not encrypted"
#define QERR_DEVICE_NOT_FOUND \
    ERROR_CLASS_DEVICE_NOT_FOUND, "Device '%s' not found"
#define QERR_DEVICE_NOT_REMOVABLE \
    ERROR_CLASS_GENERIC_ERROR, "Device '%s' is not removable"
#define QERR_DEVICE_NO_BUS \
    ERROR_CLASS_GENERIC_ERROR, "Device '%s' has no child bus"
#define QERR_DEVICE_NO_HOTPLUG \
    ERROR_CLASS_GENERIC_ERROR, "Device '%s' does not support hotplugging"
#define QERR_DUPLICATE_ID \
    ERROR_CLASS_GENERIC_ERROR, "Duplicate ID '%s' for %s"
#define QERR_FD_NOT_FOUND \
    ERROR_CLASS_GENERIC_ERROR, "File descriptor named '%s' not found"
#define QERR_FD_NOT_SUPPLIED \
    ERROR_CLASS_GENERIC_ERROR, "No file descriptor supplied via SCM_RIGHTS"
#define QERR_FEATURE_DISABLED \
    ERROR_CLASS_GENERIC_ERROR, "The feature '%s' is not enabled"
#define QERR_INVALID_BLOCK_FORMAT \
    ERROR_CLASS_GENERIC_ERROR, "Invalid block format '%s'"
#define QERR_INVALID_OPTION_GROUP \
    ERROR_CLASS_GENERIC_ERROR, "There is no option group '%s'"
#define QERR_INVALID_PARAMETER \
    ERROR_CLASS_GENERIC_ERROR, "Invalid parameter '%s'"
#define QERR_INVALID_PARAMETER_COMBINATION \
    ERROR_CLASS_GENERIC_ERROR, "Invalid parameter combination"
#define QERR_INVALID_PARAMETER_TYPE \
    ERROR_CLASS_GENERIC_ERROR, "Invalid parameter type for '%s', expected: %s"
#define QERR_INVALID_PARAMETER_VALUE \
    ERROR_CLASS_GENERIC_ERROR, "Parameter '%s' expects %s"
#define QERR_INVALID_PASSWORD \
    ERROR_CLASS_GENERIC_ERROR, "Password incorrect"
#define QERR_IO_ERROR \
    ERROR_CLASS_GENERIC_ERROR, "An IO error has occurred"
#define QERR_JSON_PARSE_ERROR \
    ERROR_CLASS_GENERIC_ERROR, "JSON parse error, %s"
#define QERR_JSON_PARSING \
    ERROR_CLASS_GENERIC_ERROR, "Invalid JSON syntax"
#define QERR_KVM_MISSING_CAP \
    ERROR_CLASS_K_V_M_MISSING_CAP, "Using KVM without %s, %s unavailable"
#define QERR_MIGRATION_ACTIVE \
    ERROR_CLASS_GENERIC_ERROR, "There's a migration process in progress"
#define QERR_MIGRATION_NOT_SUPPORTED \
    ERROR_CLASS_GENERIC_ERROR, "State blocked by non-migratable device '%s'"
#define QERR_MISSING_PARAMETER \
    ERROR_CLASS_GENERIC_ERROR, "Parameter '%s' is missing"
#define QERR_NOT_SUPPORTED \
    ERROR_CLASS_GENERIC_ERROR, "Not supported"
#define QERR_NO_BUS_FOR_DEVICE \
    ERROR_CLASS_GENERIC_ERROR, "No '%s' bus found for device '%s'"
#define QERR_OPEN_FILE_FAILED \
    ERROR_CLASS_GENERIC_ERROR, "Could not open '%s'"
#define QERR_PERMISSION_DENIED \
    ERROR_CLASS_GENERIC_ERROR, "Insufficient permission to perform this operation"
#define QERR_PROPERTY_NOT_FOUND \
    ERROR_CLASS_GENERIC_ERROR, "Property '%s.%s' not found"
#define QERR_PROPERTY_VALUE_BAD \
    ERROR_CLASS_GENERIC_ERROR, "Property '%s.%s' doesn't take value '%s'"
#define QERR_PROPERTY_VALUE_IN_USE \
    ERROR_CLASS_GENERIC_ERROR, "Property '%s.%s' can't take value '%s', it's in use"
#define QERR_PROPERTY_VALUE_NOT_FOUND \
    ERROR_CLASS_GENERIC_ERROR, "Property '%s.%s' can't find value '%s'"
#define QERR_PROPERTY_VALUE_NOT_POWER_OF_2 \
    ERROR_CLASS_GENERIC_ERROR, "Property %s.%s doesn't take value '%" PRId64 "', it's not a power of 2"
#define QERR_PROPERTY_VALUE_OUT_OF_RANGE \
    ERROR_CLASS_GENERIC_ERROR, "Property %s.%s doesn't take value %" PRId64 " (minimum: %" PRId64 ", maximum: %" PRId64 ")"
#define QERR_QGA_COMMAND_FAILED \
    ERROR_CLASS_GENERIC_ERROR, "Guest agent command failed, error was '%s'"
#define QERR_QGA_LOGGING_FAILED \
    ERROR_CLASS_GENERIC_ERROR, "Guest agent failed to log non-optional log statement"
#define QERR_QMP_BAD_INPUT_OBJECT \
    ERROR_CLASS_GENERIC_ERROR, "Expected '%s' in QMP input"
#define QERR_QMP_BAD_INPUT_OBJECT_MEMBER \
    ERROR_CLASS_GENERIC_ERROR, "QMP input object member '%s' expects '%s'"
#define QERR_QMP_EXTRA_MEMBER \
    ERROR_CLASS_GENERIC_ERROR, "QMP input object member '%s' is unexpected"
#define QERR_RESET_REQUIRED \
    ERROR_CLASS_GENERIC_ERROR, "Resetting the Virtual Machine is required"
#define QERR_SET_PASSWD_FAILED \
    ERROR_CLASS_GENERIC_ERROR, "Could not set password"
#define QERR_SOCKET_BIND_FAILED \
    ERROR_CLASS_GENERIC_ERROR, "Failed to bind socket"
#define QERR_SOCKET_CONNECT_FAILED \
    ERROR_CLASS_GENERIC_ERROR, "Failed to connect to socket"
#define QERR_SOCKET_CREATE_FAILED \
    ERROR_CLASS_GENERIC_ERROR, "Failed to create socket"
#define QERR_SOCKET_LISTEN_FAILED \
    ERROR_CLASS_GENERIC_ERROR, "Failed to set socket to listening mode"
#define QERR_TOO_MANY_FILES \
    ERROR_CLASS_GENERIC_ERROR, "Too many open files"
#define QERR_UNDEFINED_ERROR \
    ERROR_CLASS_GENERIC_ERROR, "An undefined error has occurred"
#define QERR_UNKNOWN_BLOCK_FORMAT_FEATURE \
    ERROR_CLASS_GENERIC_ERROR, "'%s' uses a %s feature which is not supported by this qemu version: %s"
#define QERR_UNSUPPORTED \
    ERROR_CLASS_GENERIC_ERROR, "this feature or command is not currently supported"
#define QERR_VIRTFS_FEATURE_BLOCKS_MIGRATION \
    ERROR_CLASS_GENERIC_ERROR, "Migration is disabled when VirtFS export path '%s' is mounted in the guest using mount_tag '%s'"



#define block_init(function) module_init(function, MODULE_INIT_BLOCK)
#define machine_init(function) module_init(function, MODULE_INIT_MACHINE)
#define module_init(function, type)                                         \
static void __attribute__((constructor)) do_qemu_init_ ## function(void) {  \
    register_module_init(function, type);                                   \
}
#define qapi_init(function) module_init(function, MODULE_INIT_QAPI)
#define type_init(function) module_init(function, MODULE_INIT_QOM)
#define QGA_READ_COUNT_DEFAULT 4096
#define ALL_EQ(v1, v2) vec_all_eq(v1, v2)
#define BUFFER_FIND_NONZERO_OFFSET_UNROLL_FACTOR 8
#define ECANCELED 4097
#define EMEDIUMTYPE 4098
#define ENOMEDIUM ENODEV
#define ENOTSUP 4096
# define HOST_LONG_BITS 32
#define MAP_ANONYMOUS MAP_ANON
#define O_BINARY 0
#define O_LARGEFILE 0
#define QEMU_ALIGN_DOWN(n, m) ((n) / (m) * (m))
#define QEMU_ALIGN_UP(n, m) QEMU_ALIGN_DOWN((n) + (m) - 1, (m))

#define QEMU_FILE_TYPE_BIOS   0
#define QEMU_FILE_TYPE_KEYMAP 1
#define SPLAT(p)       vec_splat(vec_ld(0, p), 0)
#define TFR(expr) do { if ((expr) != -1) break; } while (errno == EINTR)
#define TIME_MAX LONG_MAX
#define VECTYPE        vector unsigned char

#define bool _Bool
#define fsync _commit
# define ftruncate qemu_ftruncate64
# define lseek _lseeki64
#define qemu_co_recv(sockfd, buf, bytes) \
  qemu_co_send_recv(sockfd, buf, bytes, false)
#define qemu_co_recvv(sockfd, iov, iov_cnt, offset, bytes) \
  qemu_co_sendv_recvv(sockfd, iov, iov_cnt, offset, bytes, false)
#define qemu_co_send(sockfd, buf, bytes) \
  qemu_co_send_recv(sockfd, buf, bytes, true)
#define qemu_co_sendv(sockfd, iov, iov_cnt, offset, bytes) \
  qemu_co_sendv_recvv(sockfd, iov, iov_cnt, offset, bytes, true)
#define qemu_getsockopt(sockfd, level, optname, optval, optlen) \
    getsockopt(sockfd, level, optname, (void *)optval, optlen)
#define qemu_isalnum(c)		isalnum((unsigned char)(c))
#define qemu_isalpha(c)		isalpha((unsigned char)(c))
#define qemu_isascii(c)		isascii((unsigned char)(c))
#define qemu_iscntrl(c)		iscntrl((unsigned char)(c))
#define qemu_isdigit(c)		isdigit((unsigned char)(c))
#define qemu_isgraph(c)		isgraph((unsigned char)(c))
#define qemu_islower(c)		islower((unsigned char)(c))
#define qemu_isprint(c)		isprint((unsigned char)(c))
#define qemu_ispunct(c)		ispunct((unsigned char)(c))
#define qemu_isspace(c)		isspace((unsigned char)(c))
#define qemu_isupper(c)		isupper((unsigned char)(c))
#define qemu_isxdigit(c)	isxdigit((unsigned char)(c))
#define qemu_recv(sockfd, buf, len, flags) recv(sockfd, (void *)buf, len, flags)
#define qemu_sendto(sockfd, buf, len, flags, destaddr, addrlen) \
    sendto(sockfd, (const void *)buf, len, flags, destaddr, addrlen)
#define qemu_setsockopt(sockfd, level, optname, optval, optlen) \
    setsockopt(sockfd, level, optname, (const void *)optval, optlen)
#define qemu_toascii(c)		toascii((unsigned char)(c))
#define qemu_tolower(c)		tolower((unsigned char)(c))
#define qemu_toupper(c)		toupper((unsigned char)(c))

# define UTIME_NOW     ((1l << 30) - 1l)
# define UTIME_OMIT    ((1l << 30) - 2l)
#define qemu_gettimeofday(tp) gettimeofday(tp, NULL)
# define ECONNREFUSED WSAECONNREFUSED
# define EHOSTUNREACH WSAEHOSTUNREACH
# define EINPROGRESS  WSAEINPROGRESS
# define EINTR        WSAEINTR
# define ENETUNREACH  WSAENETUNREACH
# define ENOTCONN     WSAENOTCONN
# define EPROTONOSUPPORT EINVAL
# define EWOULDBLOCK  WSAEWOULDBLOCK

# define setjmp(env) _setjmp(env, NULL)
#define sigjmp_buf jmp_buf
#define siglongjmp(env, val) longjmp(env, val)
#define sigsetjmp(env, savemask) setjmp(env)







