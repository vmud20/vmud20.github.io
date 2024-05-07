#include<inttypes.h>
#include<unistd.h>
#include<netinet/tcp.h>
#include<sys/sysmacros.h>
#include<time.h>
#include<setjmp.h>
#include<sys/stat.h>
#include<stdint.h>
#include<sys/shm.h>

#include<sys/file.h>
#include<ctype.h>
#include<sys/resource.h>
#include<netdb.h>
#include<sys/time.h>
#include<syslog.h>
#include<stdlib.h>
#include<stdbool.h>
#include<strings.h>
#include<utime.h>
#include<sys/xattr.h>
#include<arpa/inet.h>
#include<sys/uio.h>

#include<stddef.h>

#include<stdarg.h>
#include<sys/mount.h>
#include<limits.h>
#include<assert.h>

#include<pwd.h>
#include<errno.h>
#include<dirent.h>
#include<sys/statvfs.h>
#include<sys/mman.h>
#include<netinet/in.h>


#include<sys/wait.h>
#include<sys/un.h>
#include<sys/socket.h>

#include<sys/prctl.h>

#include<getopt.h>
#include<string.h>

#include<sys/syscall.h>
#include<pthread.h>

#include<sys/types.h>

#include<stdio.h>
#include<fcntl.h>
#include<signal.h>




#define STR_OR_NULL(str) ((str) ? (str) : "null")
#define CUSE_INIT_INFO_MAX 4096
#define FUSE_ATTR_SUBMOUNT      (1 << 0)
#define FUSE_COMPAT_22_INIT_OUT_SIZE 24
#define FUSE_COMPAT_ATTR_OUT_SIZE 96
#define FUSE_COMPAT_ENTRY_OUT_SIZE 120
#define FUSE_COMPAT_INIT_OUT_SIZE 8
#define FUSE_COMPAT_MKNOD_IN_SIZE 8
#define FUSE_COMPAT_STATFS_SIZE 48
#define FUSE_COMPAT_WRITE_IN_SIZE 24
#define FUSE_DIRENTPLUS_SIZE(d) \
	FUSE_DIRENT_ALIGN(FUSE_NAME_OFFSET_DIRENTPLUS + (d)->dirent.namelen)
#define FUSE_DIRENT_ALIGN(x) \
	(((x) + sizeof(uint64_t) - 1) & ~(sizeof(uint64_t) - 1))
#define FUSE_DIRENT_SIZE(d) \
	FUSE_DIRENT_ALIGN(FUSE_NAME_OFFSET + (d)->namelen)
#define FUSE_EXPLICIT_INVAL_DATA (1 << 25)
#define FUSE_KERNEL_MINOR_VERSION 33
#define FUSE_KERNEL_VERSION 7
#define FUSE_MIN_READ_BUFFER 8192
#define FUSE_NAME_OFFSET offsetof(struct fuse_dirent, name)
#define FUSE_NAME_OFFSET_DIRENTPLUS \
	offsetof(struct fuse_direntplus, dirent.name)
#define FUSE_NO_OPENDIR_SUPPORT (1 << 24)
#define FUSE_PARALLEL_DIROPS    (1 << 18)
#define FUSE_POLL_SCHEDULE_NOTIFY (1 << 0)
#define FUSE_REMOVEMAPPING_MAX_ENTRY   \
		(PAGE_SIZE / sizeof(struct fuse_removemapping_one))
#define FUSE_ROOT_ID 1
#define FUSE_SETUPMAPPING_FLAG_READ (1ull << 1)
#define FUSE_SETUPMAPPING_FLAG_WRITE (1ull << 0)
#define FUSE_WRITE_KILL_SUIDGID (1 << 2)


#define FUSE_SET_ATTR_ATIME (1 << 4)
#define FUSE_SET_ATTR_ATIME_NOW (1 << 7)
#define FUSE_SET_ATTR_CTIME (1 << 10)
#define FUSE_SET_ATTR_GID (1 << 2)
#define FUSE_SET_ATTR_KILL_SUIDGID (1 << 11)
#define FUSE_SET_ATTR_MODE (1 << 0)
#define FUSE_SET_ATTR_MTIME (1 << 5)
#define FUSE_SET_ATTR_MTIME_NOW (1 << 8)
#define FUSE_SET_ATTR_SIZE (1 << 3)
#define FUSE_SET_ATTR_UID (1 << 1)
#define FUSE_BUFVEC_INIT(size__)                                      \
    ((struct fuse_bufvec){  1,                           \
                            0,                           \
                            0,              \
                           {  {                            \
                                (size__),               \
                                (enum fuse_buf_flags)0, \
                                NULL,                   \
                                -1,                     \
                                0,                      \
                           } } })
#define FUSE_CAP_ASYNC_DIO (1 << 15)
#define FUSE_CAP_ASYNC_READ (1 << 0)
#define FUSE_CAP_ATOMIC_O_TRUNC (1 << 3)
#define FUSE_CAP_AUTO_INVAL_DATA (1 << 12)
#define FUSE_CAP_DONT_MASK (1 << 6)
#define FUSE_CAP_EXPORT_SUPPORT (1 << 4)
#define FUSE_CAP_FLOCK_LOCKS (1 << 10)
#define FUSE_CAP_HANDLE_KILLPRIV (1 << 20)
#define FUSE_CAP_HANDLE_KILLPRIV_V2 (1 << 28)
#define FUSE_CAP_IOCTL_DIR (1 << 11)
#define FUSE_CAP_NO_OPENDIR_SUPPORT (1 << 24)
#define FUSE_CAP_NO_OPEN_SUPPORT (1 << 17)
#define FUSE_CAP_PARALLEL_DIROPS (1 << 18)
#define FUSE_CAP_POSIX_ACL (1 << 19)
#define FUSE_CAP_POSIX_LOCKS (1 << 1)
#define FUSE_CAP_READDIRPLUS (1 << 13)
#define FUSE_CAP_READDIRPLUS_AUTO (1 << 14)
#define FUSE_CAP_SPLICE_MOVE (1 << 8)
#define FUSE_CAP_SPLICE_READ (1 << 9)
#define FUSE_CAP_SPLICE_WRITE (1 << 7)
#define FUSE_CAP_SUBMOUNTS (1 << 27)
#define FUSE_CAP_WRITEBACK_CACHE (1 << 16)

#define FUSE_IOCTL_COMPAT (1 << 0)
#define FUSE_IOCTL_DIR (1 << 4)
#define FUSE_IOCTL_MAX_IOV 256
#define FUSE_IOCTL_RETRY (1 << 2)
#define FUSE_IOCTL_UNRESTRICTED (1 << 1)
#define FUSE_MAJOR_VERSION 3
#define FUSE_MAKE_VERSION(maj, min) ((maj) * 10 + (min))
#define FUSE_MBUF_ITER_INIT(fbuf) \
    ((struct fuse_mbuf_iter){     \
        .mem = fbuf->mem,         \
        .size = fbuf->size,       \
        .pos = 0,                 \
    })
#define FUSE_MINOR_VERSION 2
#define FUSE_VERSION FUSE_MAKE_VERSION(FUSE_MAJOR_VERSION, FUSE_MINOR_VERSION)
#define FUSE_ARGS_INIT(argc, argv) \
    {                              \
        argc, argv, 0              \
    }
#define FUSE_OPT_END \
    {                \
        NULL, 0, 0   \
    }

#define FUSE_OPT_KEY(templ, key) \
    {                            \
        templ, -1U, key          \
    }
#define FUSE_OPT_KEY_DISCARD -4
#define FUSE_OPT_KEY_KEEP -3
#define FUSE_OPT_KEY_NONOPT -2
#define FUSE_OPT_KEY_OPT -1


#define FUSE_BUFFER_HEADER_SIZE 0x1000
#define FUSE_DEFAULT_MAX_PAGES_PER_REQ 32

#define FUSE_MAX_MAX_PAGES 256
#define FUSE_USE_VERSION 31
#define MIPS_RDHWR(rd, value) {                         \
        __asm__ __volatile__ (".set   push\n\t"         \
                              ".set mips32r2\n\t"       \
                              "rdhwr  %0, "rd"\n\t"     \
                              ".set   pop"              \
                              : "=r" (value));          \
    }
#define NANOSECONDS_PER_SECOND 1000000000LL
#define QEMU_TIMER_ATTR_ALL      0xffffffff
#define QEMU_TIMER_ATTR_EXTERNAL ((int)BIT(0))

#define SCALE_MS 1000000
#define SCALE_NS 1
#define SCALE_US 1000

# define clol   clo32
# define clzl   clz32
# define ctol   cto32
# define ctpopl ctpop32
# define ctzl   ctz32
# define revbitl revbit32

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
}
#define DO_STN_LDN_P(END) \
    static inline void stn_## END ## _p(void *ptr, int sz, uint64_t v)  \
    {                                                                   \
        switch (sz) {                                                   \
        case 1:                                                         \
            stb_p(ptr, v);                                              \
            break;                                                      \
        case 2:                                                         \
            stw_ ## END ## _p(ptr, v);                                  \
            break;                                                      \
        case 4:                                                         \
            stl_ ## END ## _p(ptr, v);                                  \
            break;                                                      \
        case 8:                                                         \
            stq_ ## END ## _p(ptr, v);                                  \
            break;                                                      \
        default:                                                        \
            g_assert_not_reached();                                     \
        }                                                               \
    }                                                                   \
    static inline uint64_t ldn_## END ## _p(const void *ptr, int sz)    \
    {                                                                   \
        switch (sz) {                                                   \
        case 1:                                                         \
            return ldub_p(ptr);                                         \
        case 2:                                                         \
            return lduw_ ## END ## _p(ptr);                             \
        case 4:                                                         \
            return (uint32_t)ldl_ ## END ## _p(ptr);                    \
        case 8:                                                         \
            return ldq_ ## END ## _p(ptr);                              \
        default:                                                        \
            g_assert_not_reached();                                     \
        }                                                               \
    }
#define be_bswap(v, size) (v)
#define be_bswaps(v, size)
# define const_le16(_x)                          \
    ((((_x) & 0x00ff) << 8) |                    \
     (((_x) & 0xff00) >> 8))
# define const_le32(_x)                          \
    ((((_x) & 0x000000ffU) << 24) |              \
     (((_x) & 0x0000ff00U) <<  8) |              \
     (((_x) & 0x00ff0000U) >>  8) |              \
     (((_x) & 0xff000000U) >> 24))
#define le_bswap(v, size) glue(bswap, size)(v)
#define le_bswaps(p, size) do { *p = glue(bswap, size)(*p); } while(0)

#define const_float16(x) (x)
#define const_float32(x) (x)
#define const_float64(x) (x)
#define float16_val(x) (x)
#define float32_val(x) (x)
#define float64_val(x) (x)
#define float_tininess_after_rounding  false
#define float_tininess_before_rounding true
#define make_float128(high_, low_) ((float128) { .high = high_, .low = low_ })
#define make_float128_init(high_, low_) { .high = high_, .low = low_ }
#define make_float16(x) (x)
#define make_float32(x) (x)
#define make_float64(x) (x)
#define make_floatx80(exp, mant) ((floatx80) { mant, exp })
#define make_floatx80_init(exp, mant) { .low = mant, .high = exp }
#define NOTIFIER_LIST_INITIALIZER(head) \
    { QLIST_HEAD_INITIALIZER((head).notifiers) }
#define NOTIFIER_WITH_RETURN_LIST_INITIALIZER(head) \
    { QLIST_HEAD_INITIALIZER((head).notifiers) }


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
#define QLIST_IS_INSERTED(elm, field) ((elm)->field.le_prev != NULL)
#define QLIST_NEXT(elm, field)           ((elm)->field.le_next)
#define QLIST_RAW_FIRST(head)                                                  \
        field_at_offset(head, 0, void *)
#define QLIST_RAW_FOREACH(elm, head, entry)                                    \
        for ((elm) = *QLIST_RAW_FIRST(head);                                   \
             (elm);                                                            \
             (elm) = *QLIST_RAW_NEXT(elm, entry))
#define QLIST_RAW_INSERT_AFTER(head, prev, elem, entry) do {                   \
        *QLIST_RAW_NEXT(prev, entry) = elem;                                   \
        *QLIST_RAW_PREVIOUS(elem, entry) = QLIST_RAW_NEXT(prev, entry);        \
        *QLIST_RAW_NEXT(elem, entry) = NULL;                                   \
} while (0)
#define QLIST_RAW_INSERT_HEAD(head, elm, entry) do {                           \
        void *first = *QLIST_RAW_FIRST(head);                                  \
        *QLIST_RAW_FIRST(head) = elm;                                          \
        *QLIST_RAW_PREVIOUS(elm, entry) = QLIST_RAW_FIRST(head);               \
        if (first) {                                                           \
            *QLIST_RAW_NEXT(elm, entry) = first;                               \
            *QLIST_RAW_PREVIOUS(first, entry) = QLIST_RAW_NEXT(elm, entry);    \
        } else {                                                               \
            *QLIST_RAW_NEXT(elm, entry) = NULL;                                \
        }                                                                      \
} while (0)
#define QLIST_RAW_NEXT(elm, entry)                                             \
        field_at_offset(elm, entry, void *)
#define QLIST_RAW_PREVIOUS(elm, entry)                                         \
        field_at_offset(elm, entry + sizeof(void *), void *)
#define QLIST_REMOVE(elm, field) do {                                   \
        if ((elm)->field.le_next != NULL)                               \
                (elm)->field.le_next->field.le_prev =                   \
                    (elm)->field.le_prev;                               \
        *(elm)->field.le_prev = (elm)->field.le_next;                   \
        (elm)->field.le_next = NULL;                                    \
        (elm)->field.le_prev = NULL;                                    \
} while (0)
#define QLIST_SAFE_REMOVE(elm, field) do {                              \
        if ((elm)->field.le_prev != NULL) {                             \
                if ((elm)->field.le_next != NULL)                       \
                        (elm)->field.le_next->field.le_prev =           \
                            (elm)->field.le_prev;                       \
                *(elm)->field.le_prev = (elm)->field.le_next;           \
                (elm)->field.le_next = NULL;                            \
                (elm)->field.le_prev = NULL;                            \
        }                                                               \
} while (0)
#define QLIST_SWAP(dstlist, srclist, field) do {                        \
        void *tmplist;                                                  \
        tmplist = (srclist)->lh_first;                                  \
        (srclist)->lh_first = (dstlist)->lh_first;                      \
        if ((srclist)->lh_first != NULL) {                              \
            (srclist)->lh_first->field.le_prev = &(srclist)->lh_first;  \
        }                                                               \
        (dstlist)->lh_first = tmplist;                                  \
        if ((dstlist)->lh_first != NULL) {                              \
            (dstlist)->lh_first->field.le_prev = &(dstlist)->lh_first;  \
        }                                                               \
} while (0)
#define QSIMPLEQ_CONCAT(head1, head2) do {                              \
    if (!QSIMPLEQ_EMPTY((head2))) {                                     \
        *(head1)->sqh_last = (head2)->sqh_first;                        \
        (head1)->sqh_last = (head2)->sqh_last;                          \
        QSIMPLEQ_INIT((head2));                                         \
    }                                                                   \
} while (0)
#define QSIMPLEQ_EMPTY(head)        ((head)->sqh_first == NULL)
#define QSIMPLEQ_EMPTY_ATOMIC(head) \
    (qatomic_read(&((head)->sqh_first)) == NULL)
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
#define QSIMPLEQ_PREPEND(head1, head2) do {                             \
    if (!QSIMPLEQ_EMPTY((head2))) {                                     \
        *(head2)->sqh_last = (head1)->sqh_first;                        \
        (head1)->sqh_first = (head2)->sqh_first;                          \
        QSIMPLEQ_INIT((head2));                                         \
    }                                                                   \
} while (0)
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
        (elm)->field.sqe_next = NULL;                                   \
    }                                                                   \
} while (0)
#define QSIMPLEQ_REMOVE_HEAD(head, field) do {                          \
    typeof((head)->sqh_first) elm = (head)->sqh_first;                  \
    if (((head)->sqh_first = elm->field.sqe_next) == NULL)              \
        (head)->sqh_last = &(head)->sqh_first;                          \
    elm->field.sqe_next = NULL;                                         \
} while (0)
#define QSIMPLEQ_SPLIT_AFTER(head, elm, field, removed) do {            \
    QSIMPLEQ_INIT(removed);                                             \
    if (((removed)->sqh_first = (head)->sqh_first) != NULL) {           \
        if (((head)->sqh_first = (elm)->field.sqe_next) == NULL) {      \
            (head)->sqh_last = &(head)->sqh_first;                      \
        }                                                               \
        (removed)->sqh_last = &(elm)->field.sqe_next;                   \
        (elm)->field.sqe_next = NULL;                                   \
    }                                                                   \
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
        (elm)->field.sle_next = (head)->slh_first;                       \
        (head)->slh_first = (elm);                                       \
} while (0)
#define QSLIST_INSERT_HEAD_ATOMIC(head, elm, field) do {                     \
        typeof(elm) save_sle_next;                                           \
        do {                                                                 \
            save_sle_next = (elm)->field.sle_next = (head)->slh_first;       \
        } while (qatomic_cmpxchg(&(head)->slh_first, save_sle_next, (elm)) !=\
                 save_sle_next);                                             \
} while (0)
#define QSLIST_MOVE_ATOMIC(dest, src) do {                               \
        (dest)->slh_first = qatomic_xchg(&(src)->slh_first, NULL);       \
} while (0)
#define QSLIST_NEXT(elm, field)  ((elm)->field.sle_next)
#define QSLIST_REMOVE(head, elm, type, field) do {                      \
    if ((head)->slh_first == (elm)) {                                   \
        QSLIST_REMOVE_HEAD((head), field);                              \
    } else {                                                            \
        struct type *curelm = (head)->slh_first;                        \
        while (curelm->field.sle_next != (elm))                         \
            curelm = curelm->field.sle_next;                            \
        curelm->field.sle_next = curelm->field.sle_next->field.sle_next; \
        (elm)->field.sle_next = NULL;                                   \
    }                                                                   \
} while (0)
#define QSLIST_REMOVE_AFTER(slistelm, field) do {                       \
        typeof(slistelm) next = (slistelm)->field.sle_next;             \
        (slistelm)->field.sle_next = next->field.sle_next;              \
        next->field.sle_next = NULL;                                    \
} while (0)
#define QSLIST_REMOVE_HEAD(head, field) do {                             \
        typeof((head)->slh_first) elm = (head)->slh_first;               \
        (head)->slh_first = elm->field.sle_next;                         \
        elm->field.sle_next = NULL;                                      \
} while (0)
#define QTAILQ_EMPTY(head)               ((head)->tqh_first == NULL)
#define QTAILQ_ENTRY(type)                                              \
union {                                                                 \
        struct type *tqe_next;                        \
        QTailQLink tqe_circ;           \
}
#define QTAILQ_FIRST(head)               ((head)->tqh_first)
#define QTAILQ_FOREACH(var, head, field)                                \
        for ((var) = ((head)->tqh_first);                               \
                (var);                                                  \
                (var) = ((var)->field.tqe_next))
#define QTAILQ_FOREACH_REVERSE(var, head, field)                        \
        for ((var) = QTAILQ_LAST(head);                                 \
                (var);                                                  \
                (var) = QTAILQ_PREV(var, field))
#define QTAILQ_FOREACH_REVERSE_SAFE(var, head, field, prev_var)         \
        for ((var) = QTAILQ_LAST(head);                                 \
             (var) && ((prev_var) = QTAILQ_PREV(var, field), 1);        \
             (var) = (prev_var))
#define QTAILQ_FOREACH_SAFE(var, head, field, next_var)                 \
        for ((var) = ((head)->tqh_first);                               \
                (var) && ((next_var) = ((var)->field.tqe_next), 1);     \
                (var) = (next_var))
#define QTAILQ_HEAD(name, type)                                         \
union name {                                                            \
        struct type *tqh_first;                      \
        QTailQLink tqh_circ;           \
}
#define QTAILQ_HEAD_INITIALIZER(head)                                   \
        { .tqh_circ = { NULL, &(head).tqh_circ } }
#define QTAILQ_INIT(head) do {                                          \
        (head)->tqh_first = NULL;                                       \
        (head)->tqh_circ.tql_prev = &(head)->tqh_circ;                  \
} while (0)
#define QTAILQ_INSERT_AFTER(head, listelm, elm, field) do {             \
        if (((elm)->field.tqe_next = (listelm)->field.tqe_next) != NULL)\
            (elm)->field.tqe_next->field.tqe_circ.tql_prev =            \
                &(elm)->field.tqe_circ;                                 \
        else                                                            \
            (head)->tqh_circ.tql_prev = &(elm)->field.tqe_circ;         \
        (listelm)->field.tqe_next = (elm);                              \
        (elm)->field.tqe_circ.tql_prev = &(listelm)->field.tqe_circ;    \
} while (0)
#define QTAILQ_INSERT_BEFORE(listelm, elm, field) do {                       \
        (elm)->field.tqe_circ.tql_prev = (listelm)->field.tqe_circ.tql_prev; \
        (elm)->field.tqe_next = (listelm);                                   \
        (listelm)->field.tqe_circ.tql_prev->tql_next = (elm);                \
        (listelm)->field.tqe_circ.tql_prev = &(elm)->field.tqe_circ;         \
} while (0)
#define QTAILQ_INSERT_HEAD(head, elm, field) do {                       \
        if (((elm)->field.tqe_next = (head)->tqh_first) != NULL)        \
            (head)->tqh_first->field.tqe_circ.tql_prev =                \
                &(elm)->field.tqe_circ;                                 \
        else                                                            \
            (head)->tqh_circ.tql_prev = &(elm)->field.tqe_circ;         \
        (head)->tqh_first = (elm);                                      \
        (elm)->field.tqe_circ.tql_prev = &(head)->tqh_circ;             \
} while (0)
#define QTAILQ_INSERT_TAIL(head, elm, field) do {                       \
        (elm)->field.tqe_next = NULL;                                   \
        (elm)->field.tqe_circ.tql_prev = (head)->tqh_circ.tql_prev;     \
        (head)->tqh_circ.tql_prev->tql_next = (elm);                    \
        (head)->tqh_circ.tql_prev = &(elm)->field.tqe_circ;             \
} while (0)
#define QTAILQ_IN_USE(elm, field)        ((elm)->field.tqe_circ.tql_prev != NULL)
#define QTAILQ_LAST(head)                                               \
        ((typeof((head)->tqh_first)) QTAILQ_LINK_PREV((head)->tqh_circ))
#define QTAILQ_LINK_PREV(link)                                          \
        ((link).tql_prev->tql_prev->tql_next)
#define QTAILQ_NEXT(elm, field)          ((elm)->field.tqe_next)
#define QTAILQ_PREV(elm, field)                                         \
        ((typeof((elm)->field.tqe_next)) QTAILQ_LINK_PREV((elm)->field.tqe_circ))
#define QTAILQ_RAW_FIRST(head)                                                 \
        field_at_offset(head, 0, void *)
#define QTAILQ_RAW_FOREACH(elm, head, entry)                                   \
        for ((elm) = *QTAILQ_RAW_FIRST(head);                                  \
             (elm);                                                            \
             (elm) = *QTAILQ_RAW_NEXT(elm, entry))
#define QTAILQ_RAW_INSERT_TAIL(head, elm, entry) do {                           \
        *QTAILQ_RAW_NEXT(elm, entry) = NULL;                                    \
        QTAILQ_RAW_TQE_CIRC(elm, entry)->tql_prev = QTAILQ_RAW_TQH_CIRC(head)->tql_prev; \
        QTAILQ_RAW_TQH_CIRC(head)->tql_prev->tql_next = (elm);                  \
        QTAILQ_RAW_TQH_CIRC(head)->tql_prev = QTAILQ_RAW_TQE_CIRC(elm, entry);  \
} while (0)
#define QTAILQ_RAW_NEXT(elm, entry)                                            \
        field_at_offset(elm, entry, void *)
#define QTAILQ_RAW_TQE_CIRC(elm, entry)                                        \
        field_at_offset(elm, entry, QTailQLink)
#define QTAILQ_RAW_TQH_CIRC(head)                                              \
        field_at_offset(head, 0, QTailQLink)
#define QTAILQ_REMOVE(head, elm, field) do {                            \
        if (((elm)->field.tqe_next) != NULL)                            \
            (elm)->field.tqe_next->field.tqe_circ.tql_prev =            \
                (elm)->field.tqe_circ.tql_prev;                         \
        else                                                            \
            (head)->tqh_circ.tql_prev = (elm)->field.tqe_circ.tql_prev; \
        (elm)->field.tqe_circ.tql_prev->tql_next = (elm)->field.tqe_next; \
        (elm)->field.tqe_circ.tql_prev = NULL;                          \
        (elm)->field.tqe_circ.tql_next = NULL;                          \
        (elm)->field.tqe_next = NULL;                                   \
} while (0)
#define QTAILQ_REMOVE_SEVERAL(head, left, right, field) do {            \
        if (((right)->field.tqe_next) != NULL)                          \
            (right)->field.tqe_next->field.tqe_circ.tql_prev =          \
                (left)->field.tqe_circ.tql_prev;                        \
        else                                                            \
            (head)->tqh_circ.tql_prev = (left)->field.tqe_circ.tql_prev; \
        (left)->field.tqe_circ.tql_prev->tql_next = (right)->field.tqe_next; \
    } while (0)
#define field_at_offset(base, offset, type)                                    \
        ((type *) (((char *) (base)) + (offset)))
#define BIT(nr)                 (1UL << (nr))

#define BITS_PER_BYTE           CHAR_BIT
#define BITS_PER_LONG           (sizeof (unsigned long) * BITS_PER_BYTE)
#define BITS_TO_LONGS(nr)       DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))
#define BIT_MASK(nr)            (1UL << ((nr) % BITS_PER_LONG))
#define BIT_ULL(nr)             (1ULL << (nr))
#define BIT_WORD(nr)            ((nr) / BITS_PER_LONG)
#define MAKE_64BIT_MASK(shift, length) \
    (((~0ULL) >> (64 - (length))) << (shift))
#define ARRAY_SIZE(x) ((sizeof(x) / sizeof((x)[0])) + \
                       QEMU_BUILD_BUG_ON_ZERO(!QEMU_IS_ARRAY(x)))
#define BUS_MCEERR_AO 5
#define BUS_MCEERR_AR 4
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define ECANCELED 4097
#define EMEDIUMTYPE 4098
#define ENOMEDIUM ENODEV
#define ENOTSUP 4096
#define ESHUTDOWN 4099
#define FMT_pid "%ld"
#define HAVE_CHARDEV_PARPORT 1
#define HAVE_CHARDEV_SERIAL 1
# define HOST_LONG_BITS 32
#define IOV_MAX 1024
#define MAP_ANONYMOUS MAP_ANON
#define MAP_FIXED_NOREPLACE 0
#define MAX(a, b)                                       \
    ({                                                  \
        typeof(1 ? (a) : (b)) _a = (a), _b = (b);       \
        _a > _b ? _a : _b;                              \
    })
# define MAX_CONST(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b)                                       \
    ({                                                  \
        typeof(1 ? (a) : (b)) _a = (a), _b = (b);       \
        _a < _b ? _a : _b;                              \
    })
# define MIN_CONST(a, b) ((a) < (b) ? (a) : (b))
#define MIN_NON_ZERO(a, b)                              \
    ({                                                  \
        typeof(1 ? (a) : (b)) _a = (a), _b = (b);       \
        _a == 0 ? _b : (_b == 0 || _b > _a) ? _a : _b;  \
    })
#define O_BINARY 0
#define O_LARGEFILE 0
#define QEMU_ALIGN_DOWN(n, m) ((n) / (m) * (m))
#define QEMU_ALIGN_PTR_DOWN(p, n) \
    ((typeof(p))QEMU_ALIGN_DOWN((uintptr_t)(p), (n)))
#define QEMU_ALIGN_PTR_UP(p, n) \
    ((typeof(p))QEMU_ALIGN_UP((uintptr_t)(p), (n)))
#define QEMU_ALIGN_UP(n, m) QEMU_ALIGN_DOWN((n) + (m) - 1, (m))
#define QEMU_HW_VERSION "2.5+"
#define QEMU_IS_ALIGNED(n, m) (((n) % (m)) == 0)
#define QEMU_IS_ARRAY(x) (!__builtin_types_compatible_p(typeof(x), \
                                                        typeof(&(x)[0])))
#define QEMU_MADV_DODUMP MADV_DODUMP
#define QEMU_MADV_DONTDUMP MADV_DONTDUMP
#define QEMU_MADV_DONTFORK  MADV_DONTFORK
#define QEMU_MADV_DONTNEED  MADV_DONTNEED
#define QEMU_MADV_HUGEPAGE MADV_HUGEPAGE
#define QEMU_MADV_INVALID -1
#define QEMU_MADV_MERGEABLE MADV_MERGEABLE
#define QEMU_MADV_NOHUGEPAGE MADV_NOHUGEPAGE
#define QEMU_MADV_REMOVE MADV_REMOVE
#define QEMU_MADV_UNMERGEABLE MADV_UNMERGEABLE
#define QEMU_MADV_WILLNEED  MADV_WILLNEED

#define QEMU_PTR_IS_ALIGNED(p, n) QEMU_IS_ALIGNED((uintptr_t)(p), (n))
#  define QEMU_VMALLOC_ALIGN (512 * 4096)
#define ROUND_UP(n, d) (((n) + (d) - 1) & -(0 ? (n) : (d)))
#define SIGIO SIGPOLL
#define SIZE_MAX ((size_t)-1)
#define TIME_MAX TYPE_MAXIMUM(time_t)
#define TYPE_MAXIMUM(t)                                                \
  ((t) (!TYPE_SIGNED(t)                                                \
        ? (t)-1                                                        \
        : ((((t)1 << (TYPE_WIDTH(t) - 2)) - 1) * 2 + 1)))
#define TYPE_SIGNED(t) (!((t)0 < (t)-1))
#define TYPE_WIDTH(t) (sizeof(t) * CHAR_BIT)
#define WCOREDUMP(status) 0
#define WEXITSTATUS(x) (x)
#define WIFEXITED(x)   1

#define _WIN32_WINNT 0x0600 



#define __USE_MINGW_ANSI_STDIO 1
#define assert(x)  g_assert(x)
#define daemon qemu_fake_daemon_function
#define qemu_timersub timersub
#define system platform_does_not_support_system

#define GLIB_VERSION_MAX_ALLOWED GLIB_VERSION_2_48
#define GLIB_VERSION_MIN_REQUIRED GLIB_VERSION_2_48

#define g_poll(fds, nfds, timeout) g_poll_fixed(fds, nfds, timeout)

#define closesocket(s) close(s)
#define ioctlsocket(s, r, v) ioctl(s, r, v)
#define qemu_gettimeofday(tp) gettimeofday(tp, NULL)
# define EPROTONOSUPPORT EINVAL

#define accept qemu_accept_wrap
#define bind qemu_bind_wrap
#define connect qemu_connect_wrap
#define fsync _commit
# define ftruncate qemu_ftruncate64
#define getpeername qemu_getpeername_wrap
#define getsockname qemu_getsockname_wrap
#define getsockopt qemu_getsockopt_wrap
#define listen qemu_listen_wrap
# define lseek _lseeki64
#define recv qemu_recv_wrap
#define recvfrom qemu_recvfrom_wrap
#define send qemu_send_wrap
#define sendto qemu_sendto_wrap
# define setjmp(env) _setjmp(env, NULL)
#define setsockopt qemu_setsockopt_wrap
#define shutdown qemu_shutdown_wrap
#define sigjmp_buf jmp_buf
#define siglongjmp(env, val) longjmp(env, val)
#define sigsetjmp(env, savemask) setjmp(env)
#define socket qemu_socket_wrap

#define DO_UPCAST(type, field, dev) ( __extension__ ( { \
    char __attribute__((unused)) offset_must_be_zero[ \
        -offsetof(type, field)]; \
    container_of(dev, type, field);}))
# define GCC_FMT_ATTR(n, m) __attribute__((format(printf, n, m)))

#define QEMU_ALIGNED(X) __attribute__((aligned(X)))
#define QEMU_ALWAYS_INLINE  __attribute__((always_inline))
#define QEMU_BUILD_BUG_MSG(x, msg) _Static_assert(!(x), msg)
#define QEMU_BUILD_BUG_ON(x) QEMU_BUILD_BUG_MSG(x, "not expecting: " #x)
#define QEMU_BUILD_BUG_ON_STRUCT(x) \
    struct { \
        int:(x) ? -1 : 1; \
    }
#define QEMU_BUILD_BUG_ON_ZERO(x) (sizeof(QEMU_BUILD_BUG_ON_STRUCT(x)) - \
                                   sizeof(QEMU_BUILD_BUG_ON_STRUCT(x)))
#define QEMU_DISABLE_CFI __attribute__((no_sanitize("cfi-icall")))
# define QEMU_ERROR(X) __attribute__((error(X)))
# define QEMU_FALLTHROUGH __attribute__((fallthrough))
#define QEMU_FIRST_(a, b) a
# define QEMU_FLATTEN __attribute__((flatten))
#define QEMU_GENERIC(x, ...) \
    QEMU_GENERIC_(typeof(x), __VA_ARGS__, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
#define QEMU_GENERIC1(x, a0, ...) (a0)
#define QEMU_GENERIC10(x, a0, ...) QEMU_GENERIC_IF(x, a0, QEMU_GENERIC9(x, __VA_ARGS__))
#define QEMU_GENERIC2(x, a0, ...) QEMU_GENERIC_IF(x, a0, QEMU_GENERIC1(x, __VA_ARGS__))
#define QEMU_GENERIC3(x, a0, ...) QEMU_GENERIC_IF(x, a0, QEMU_GENERIC2(x, __VA_ARGS__))
#define QEMU_GENERIC4(x, a0, ...) QEMU_GENERIC_IF(x, a0, QEMU_GENERIC3(x, __VA_ARGS__))
#define QEMU_GENERIC5(x, a0, ...) QEMU_GENERIC_IF(x, a0, QEMU_GENERIC4(x, __VA_ARGS__))
#define QEMU_GENERIC6(x, a0, ...) QEMU_GENERIC_IF(x, a0, QEMU_GENERIC5(x, __VA_ARGS__))
#define QEMU_GENERIC7(x, a0, ...) QEMU_GENERIC_IF(x, a0, QEMU_GENERIC6(x, __VA_ARGS__))
#define QEMU_GENERIC8(x, a0, ...) QEMU_GENERIC_IF(x, a0, QEMU_GENERIC7(x, __VA_ARGS__))
#define QEMU_GENERIC9(x, a0, ...) QEMU_GENERIC_IF(x, a0, QEMU_GENERIC8(x, __VA_ARGS__))
#define QEMU_GENERIC_(x, a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, count, ...) \
    QEMU_GENERIC##count(x, a0, a1, a2, a3, a4, a5, a6, a7, a8, a9)
#define QEMU_GENERIC_IF(x, type_then, else_)                                   \
    __builtin_choose_expr(__builtin_types_compatible_p(x,                      \
                                                       QEMU_FIRST_ type_then), \
                          QEMU_SECOND_ type_then, else_)
# define QEMU_NONSTRING __attribute__((nonstring))
#define QEMU_NORETURN __attribute__ ((__noreturn__))
# define QEMU_PACKED __attribute__((gcc_struct, packed))
#define QEMU_SECOND_(a, b) b
#define QEMU_SENTINEL __attribute__((sentinel))
#define QEMU_STATIC_ANALYSIS 1
#define QEMU_WARN_UNUSED_RESULT __attribute__((warn_unused_result))
#define __has_attribute(x) 0 
#define __has_builtin(x) 0 
#define __has_feature(x) 0 
#define __has_warning(x) 0 
#  define __printf__ __gnu_printf__
#define container_of(ptr, type, member) ({                      \
        const typeof(((type *) 0)->member) *__mptr = (ptr);     \
        (type *) ((char *) __mptr - offsetof(type, member));})
#define endof(container, field) \
    (offsetof(container, field) + sizeof_field(container, field))
#define glue(x, y) xglue(x, y)
#define likely(x)   __builtin_expect(!!(x), 1)
#define qemu_build_not_reached()  qemu_build_not_reached_always()
#define sizeof_field(type, field) sizeof(((type *)0)->field)
#define stringify(s)	tostring(s)
#define tostring(s)	#s
#define type_check(t1,t2) ((t1*)0 - (t2*)0)
#define typeof_field(type, field) typeof(((type *)0)->field)
#define unlikely(x)   __builtin_expect(!!(x), 0)
#define xglue(x, y) x ## y

