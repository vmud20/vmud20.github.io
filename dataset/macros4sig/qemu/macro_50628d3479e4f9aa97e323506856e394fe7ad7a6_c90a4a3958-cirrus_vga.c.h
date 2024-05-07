


#include<inttypes.h>


#include<assert.h>
#include<errno.h>
#include<ctype.h>

#include<setjmp.h>





#include<stdlib.h>




#include<sys/mman.h>
#include<semaphore.h>

#include<sys/wait.h>
#include<netinet/tcp.h>
#include<stdbool.h>

#include<limits.h>




#include<signal.h>
#include<sys/uio.h>

#include<time.h>

#include<sys/socket.h>
#include<netinet/in.h>


#include<string.h>



#include<sys/signal.h>
#include<pthread.h>
#include<stdarg.h>
#include<arpa/inet.h>

#include<sys/time.h>
#include<unistd.h>


#include<sys/types.h>

#include<fcntl.h>





#include<netdb.h>



#include<strings.h>

#include<sys/sysmacros.h>
#include<stdio.h>
#include<stdint.h>

#include<sys/stat.h>
#include<sys/un.h>



#include<stddef.h>
#define DEPTH 8
#define ROP_OP(d, s) glue(rop_8_,ROP_NAME)(d, s)
#define ROP_OP_16(d, s) glue(rop_16_,ROP_NAME)(d, s)
#define ROP_OP_32(d, s) glue(rop_32_,ROP_NAME)(d, s)
#define PUTPIXEL()    ROP_OP(&d[0], col)
#define ELF_LOAD_FAILED       -1
#define ELF_LOAD_NOT_ELF      -2
#define ELF_LOAD_WRONG_ARCH   -3
#define ELF_LOAD_WRONG_ENDIAN -4

#define LOAD_IMAGE_MAX_GUNZIP_BYTES (256 << 20)
#define PC_ROM_ALIGN       0x800
#define PC_ROM_MAX         0xe0000
#define PC_ROM_MIN_OPTION  0xc8000
#define PC_ROM_MIN_VGA     0xc0000
#define PC_ROM_SIZE        (PC_ROM_MAX - PC_ROM_MIN_VGA)
#define UBOOT_MAX_GUNZIP_BYTES (64 << 20)
#define rom_add_blob_fixed(_f, _b, _l, _a)      \
    rom_add_blob(_f, _b, _l, _l, _a, NULL, NULL, NULL, NULL, true)
#define rom_add_blob_fixed_as(_f, _b, _l, _a, _as)      \
    rom_add_blob(_f, _b, _l, _l, _a, NULL, NULL, NULL, _as, true)
#define rom_add_file_as(_f, _as, _i)            \
    rom_add_file(_f, NULL, 0, _i, false, NULL, _as)
#define rom_add_file_fixed(_f, _a, _i)          \
    rom_add_file(_f, NULL, _a, _i, false, NULL, NULL)
#define rom_add_file_fixed_as(_f, _a, _i, _as)          \
    rom_add_file(_f, NULL, _a, _i, false, NULL, _as)
#define rom_add_file_mr(_f, _mr, _i)            \
    rom_add_file(_f, NULL, 0, _i, false, _mr, NULL)

#define FW_CFG_ORDER_OVERRIDE_DEVICE 110
#define FW_CFG_ORDER_OVERRIDE_NIC    80
#define FW_CFG_ORDER_OVERRIDE_USER   100
#define FW_CFG_ORDER_OVERRIDE_VGA    70
#define FW_CFG_ARCH_LOCAL       0x8000
#define FW_CFG_BOOT_DEVICE      0x0c
#define FW_CFG_BOOT_MENU        0x0e
#define FW_CFG_CMDLINE_ADDR     0x13
#define FW_CFG_CMDLINE_DATA     0x15
#define FW_CFG_CMDLINE_SIZE     0x14
#define FW_CFG_CTL_SIZE         0x02
#define FW_CFG_ENTRY_MASK       (~(FW_CFG_WRITE_CHANNEL | FW_CFG_ARCH_LOCAL))
#define FW_CFG_FILE_DIR         0x19
#define FW_CFG_FILE_FIRST       0x20
#define FW_CFG_FILE_SLOTS_MIN   0x10
#define FW_CFG_ID               0x01
#define FW_CFG_INITRD_ADDR      0x0a
#define FW_CFG_INITRD_DATA      0x12
#define FW_CFG_INITRD_SIZE      0x0b
#define FW_CFG_INVALID          0xffff
#define FW_CFG_KERNEL_ADDR      0x07
#define FW_CFG_KERNEL_CMDLINE   0x09
#define FW_CFG_KERNEL_DATA      0x11
#define FW_CFG_KERNEL_ENTRY     0x10
#define FW_CFG_KERNEL_SIZE      0x08

#define FW_CFG_MACHINE_ID       0x06
#define FW_CFG_MAX_CPUS         0x0f
#define FW_CFG_MAX_FILE_PATH    56
#define FW_CFG_NB_CPUS          0x05
#define FW_CFG_NOGRAPHIC        0x04
#define FW_CFG_NUMA             0x0d
#define FW_CFG_RAM_SIZE         0x03
#define FW_CFG_SETUP_ADDR       0x16
#define FW_CFG_SETUP_DATA       0x18
#define FW_CFG_SETUP_SIZE       0x17
#define FW_CFG_SIGNATURE        0x00
#define FW_CFG_UUID             0x02
#define FW_CFG_WRITE_CHANNEL    0x4000
#define HWADDR_BITS 64

#define HWADDR_MAX UINT64_MAX
#define HWADDR_PRIX PRIX64
#define HWADDR_PRId PRId64
#define HWADDR_PRIi PRIi64
#define HWADDR_PRIo PRIo64
#define HWADDR_PRIu PRIu64
#define HWADDR_PRIx PRIx64
#define TARGET_FMT_plx "%016" PRIx64
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
#define QLIST_NEXT(elm, field)           ((elm)->field.le_next)
#define QLIST_REMOVE(elm, field) do {                                   \
        if ((elm)->field.le_next != NULL)                               \
                (elm)->field.le_next->field.le_prev =                   \
                    (elm)->field.le_prev;                               \
        *(elm)->field.le_prev = (elm)->field.le_next;                   \
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
        } while (atomic_cmpxchg(&(head)->slh_first, save_sle_next, (elm)) != \
                 save_sle_next);                                             \
} while (0)
#define QSLIST_MOVE_ATOMIC(dest, src) do {                               \
        (dest)->slh_first = atomic_xchg(&(src)->slh_first, NULL);        \
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
#define QTAILQ_FIRST_OFFSET (offsetof(typeof(dummy_q->head), tqh_first))
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
#define QTAILQ_IN_USE(elm, field)        ((elm)->field.tqe_prev != NULL)
#define QTAILQ_LAST(head, headname) \
        (*(((struct headname *)((head)->tqh_last))->tqh_last))
#define QTAILQ_LAST_OFFSET  (offsetof(typeof(dummy_q->head), tqh_last))
#define QTAILQ_NEXT(elm, field)          ((elm)->field.tqe_next)
#define QTAILQ_NEXT_OFFSET (offsetof(typeof(dummy_qe->next), tqe_next))
#define QTAILQ_PREV(elm, headname, field) \
        (*(((struct headname *)((elm)->field.tqe_prev))->tqh_last))
#define QTAILQ_PREV_OFFSET (offsetof(typeof(dummy_qe->next), tqe_prev))
#define QTAILQ_RAW_FIRST(head)                                                 \
        (*field_at_offset(head, QTAILQ_FIRST_OFFSET, void **))
#define QTAILQ_RAW_FOREACH(elm, head, entry)                                   \
        for ((elm) = QTAILQ_RAW_FIRST(head);                                   \
             (elm);                                                            \
             (elm) = QTAILQ_RAW_NEXT(elm, entry))
#define QTAILQ_RAW_INSERT_TAIL(head, elm, entry) do {                          \
        QTAILQ_RAW_NEXT(elm, entry) = NULL;                                    \
        QTAILQ_RAW_TQE_PREV(elm, entry) = QTAILQ_RAW_TQH_LAST(head);           \
        *QTAILQ_RAW_TQH_LAST(head) = (elm);                                    \
        QTAILQ_RAW_TQH_LAST(head) = &QTAILQ_RAW_NEXT(elm, entry);              \
} while (0)
#define QTAILQ_RAW_NEXT(elm, entry)                                            \
        (*field_at_offset(elm, entry + QTAILQ_NEXT_OFFSET, void **))
#define QTAILQ_RAW_TQE_PREV(elm, entry)                                        \
        (*field_at_offset(elm, entry + QTAILQ_PREV_OFFSET, void ***))
#define QTAILQ_RAW_TQH_LAST(head)                                              \
        (*field_at_offset(head, QTAILQ_LAST_OFFSET, void ***))
#define QTAILQ_REMOVE(head, elm, field) do {                            \
        if (((elm)->field.tqe_next) != NULL)                            \
                (elm)->field.tqe_next->field.tqe_prev =                 \
                    (elm)->field.tqe_prev;                              \
        else                                                            \
                (head)->tqh_last = (elm)->field.tqe_prev;               \
        *(elm)->field.tqe_prev = (elm)->field.tqe_next;                 \
        (elm)->field.tqe_prev = NULL;                                   \
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
#define dummy_q ((DUMMY_Q *) 0)
#define dummy_qe ((DUMMY_Q_ENTRY *) 0)
#define field_at_offset(base, offset, type)                                    \
        ((type) (((char *) (base)) + (offset)))

#define atomic_add(ptr, n) ((void) __atomic_fetch_add(ptr, n, __ATOMIC_SEQ_CST))
#define atomic_add_fetch(ptr, n) __atomic_add_fetch(ptr, n, __ATOMIC_SEQ_CST)
#define atomic_and(ptr, n) ((void) __atomic_fetch_and(ptr, n, __ATOMIC_SEQ_CST))
#define atomic_and_fetch(ptr, n) __atomic_and_fetch(ptr, n, __ATOMIC_SEQ_CST)
#define atomic_cmpxchg(ptr, old, new)    ({                             \
    QEMU_BUILD_BUG_ON(sizeof(*ptr) > sizeof(void *));                   \
    atomic_cmpxchg__nocheck(ptr, old, new);                             \
})
#define atomic_cmpxchg__nocheck(ptr, old, new)    ({                    \
    typeof_strip_qual(*ptr) _old = (old);                               \
    __atomic_compare_exchange_n(ptr, &_old, new, false,                 \
                              __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);      \
    _old;                                                               \
})
#define atomic_dec(ptr)    ((void) __atomic_fetch_sub(ptr, 1, __ATOMIC_SEQ_CST))
#define atomic_dec_fetch(ptr)    __atomic_sub_fetch(ptr, 1, __ATOMIC_SEQ_CST)
#define atomic_fetch_add(ptr, n) __atomic_fetch_add(ptr, n, __ATOMIC_SEQ_CST)
#define atomic_fetch_and(ptr, n) __atomic_fetch_and(ptr, n, __ATOMIC_SEQ_CST)
#define atomic_fetch_dec(ptr)  __atomic_fetch_sub(ptr, 1, __ATOMIC_SEQ_CST)
#define atomic_fetch_inc(ptr)  __atomic_fetch_add(ptr, 1, __ATOMIC_SEQ_CST)
#define atomic_fetch_or(ptr, n)  __atomic_fetch_or(ptr, n, __ATOMIC_SEQ_CST)
#define atomic_fetch_sub(ptr, n) __atomic_fetch_sub(ptr, n, __ATOMIC_SEQ_CST)
#define atomic_fetch_xor(ptr, n) __atomic_fetch_xor(ptr, n, __ATOMIC_SEQ_CST)
#define atomic_inc(ptr)    ((void) __atomic_fetch_add(ptr, 1, __ATOMIC_SEQ_CST))
#define atomic_inc_fetch(ptr)    __atomic_add_fetch(ptr, 1, __ATOMIC_SEQ_CST)
#define atomic_load_acquire(ptr)                        \
    ({                                                  \
    QEMU_BUILD_BUG_ON(sizeof(*ptr) > sizeof(void *));   \
    typeof_strip_qual(*ptr) _val;                       \
    __atomic_load(ptr, &_val, __ATOMIC_ACQUIRE);        \
    _val;                                               \
    })
#define atomic_mb_read(ptr)                             \
    atomic_load_acquire(ptr)
#define atomic_mb_set(ptr, i)  ((void)atomic_xchg(ptr, i))
#define atomic_or(ptr, n)  ((void) __atomic_fetch_or(ptr, n, __ATOMIC_SEQ_CST))
#define atomic_or_fetch(ptr, n)  __atomic_or_fetch(ptr, n, __ATOMIC_SEQ_CST)
#define atomic_rcu_read(ptr)                          \
    ({                                                \
    QEMU_BUILD_BUG_ON(sizeof(*ptr) > sizeof(void *)); \
    typeof_strip_qual(*ptr) _val;                     \
    atomic_rcu_read__nocheck(ptr, &_val);             \
    _val;                                             \
    })
#define atomic_rcu_read__nocheck(ptr, valptr)           \
    __atomic_load(ptr, valptr, __ATOMIC_CONSUME);
#define atomic_rcu_set(ptr, i) do {                   \
    QEMU_BUILD_BUG_ON(sizeof(*ptr) > sizeof(void *)); \
    __atomic_store_n(ptr, i, __ATOMIC_RELEASE);       \
} while(0)
#define atomic_read(ptr)                              \
    ({                                                \
    QEMU_BUILD_BUG_ON(sizeof(*ptr) > sizeof(void *)); \
    atomic_read__nocheck(ptr);                        \
    })
#define atomic_read__nocheck(ptr) \
    __atomic_load_n(ptr, __ATOMIC_RELAXED)
#define atomic_set(ptr, i)  do {                      \
    QEMU_BUILD_BUG_ON(sizeof(*ptr) > sizeof(void *)); \
    atomic_set__nocheck(ptr, i);                      \
} while(0)
#define atomic_set__nocheck(ptr, i) \
    __atomic_store_n(ptr, i, __ATOMIC_RELAXED)
#define atomic_store_release(ptr, i)  do {              \
    QEMU_BUILD_BUG_ON(sizeof(*ptr) > sizeof(void *));   \
    __atomic_store_n(ptr, i, __ATOMIC_RELEASE);         \
} while(0)
#define atomic_sub(ptr, n) ((void) __atomic_fetch_sub(ptr, n, __ATOMIC_SEQ_CST))
#define atomic_sub_fetch(ptr, n) __atomic_sub_fetch(ptr, n, __ATOMIC_SEQ_CST)
#define atomic_xchg(ptr, i)    ({                           \
    QEMU_BUILD_BUG_ON(sizeof(*ptr) > sizeof(void *));       \
    atomic_xchg__nocheck(ptr, i);                           \
})
#define atomic_xchg__nocheck  atomic_xchg
#define atomic_xor(ptr, n) ((void) __atomic_fetch_xor(ptr, n, __ATOMIC_SEQ_CST))
#define atomic_xor_fetch(ptr, n) __atomic_xor_fetch(ptr, n, __ATOMIC_SEQ_CST)
#define barrier()   ({ asm volatile("" ::: "memory"); (void)0; })
#define smp_mb()    ({ asm volatile("mfence" ::: "memory"); (void)0; })
#define smp_mb_acquire()   barrier()
#define smp_mb_release()   barrier()
#define smp_read_barrier_depends()   asm volatile("mb":::"memory")
#define smp_rmb()   smp_mb_acquire()
#define smp_wmb()          ({ asm volatile("eieio" ::: "memory"); (void)0; })
#define typeof_strip_qual(expr)                                                    \
  typeof(                                                                          \
    __builtin_choose_expr(                                                         \
      __builtin_types_compatible_p(typeof(expr), bool) ||                          \
        __builtin_types_compatible_p(typeof(expr), const bool) ||                  \
        __builtin_types_compatible_p(typeof(expr), volatile bool) ||               \
        __builtin_types_compatible_p(typeof(expr), const volatile bool),           \
        (bool)1,                                                                   \
    __builtin_choose_expr(                                                         \
      __builtin_types_compatible_p(typeof(expr), signed char) ||                   \
        __builtin_types_compatible_p(typeof(expr), const signed char) ||           \
        __builtin_types_compatible_p(typeof(expr), volatile signed char) ||        \
        __builtin_types_compatible_p(typeof(expr), const volatile signed char),    \
        (signed char)1,                                                            \
    __builtin_choose_expr(                                                         \
      __builtin_types_compatible_p(typeof(expr), unsigned char) ||                 \
        __builtin_types_compatible_p(typeof(expr), const unsigned char) ||         \
        __builtin_types_compatible_p(typeof(expr), volatile unsigned char) ||      \
        __builtin_types_compatible_p(typeof(expr), const volatile unsigned char),  \
        (unsigned char)1,                                                          \
    __builtin_choose_expr(                                                         \
      __builtin_types_compatible_p(typeof(expr), signed short) ||                  \
        __builtin_types_compatible_p(typeof(expr), const signed short) ||          \
        __builtin_types_compatible_p(typeof(expr), volatile signed short) ||       \
        __builtin_types_compatible_p(typeof(expr), const volatile signed short),   \
        (signed short)1,                                                           \
    __builtin_choose_expr(                                                         \
      __builtin_types_compatible_p(typeof(expr), unsigned short) ||                \
        __builtin_types_compatible_p(typeof(expr), const unsigned short) ||        \
        __builtin_types_compatible_p(typeof(expr), volatile unsigned short) ||     \
        __builtin_types_compatible_p(typeof(expr), const volatile unsigned short), \
        (unsigned short)1,                                                         \
      (expr)+0))))))
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

#define CH_ATTR_SIZE (160 * 100)

#define ST01_DISP_ENABLE    0x01
#define ST01_V_RETRACE      0x08
#define VBE_DISPI_8BIT_DAC              0x20
#define VBE_DISPI_DISABLED              0x00
#define VBE_DISPI_ENABLED               0x01
#define VBE_DISPI_GETCAPS               0x02
#define VBE_DISPI_ID0                   0xB0C0
#define VBE_DISPI_ID1                   0xB0C1
#define VBE_DISPI_ID2                   0xB0C2
#define VBE_DISPI_ID3                   0xB0C3
#define VBE_DISPI_ID4                   0xB0C4
#define VBE_DISPI_ID5                   0xB0C5
#define VBE_DISPI_INDEX_BANK            0x5
#define VBE_DISPI_INDEX_BPP             0x3
#define VBE_DISPI_INDEX_ENABLE          0x4
#define VBE_DISPI_INDEX_ID              0x0
#define VBE_DISPI_INDEX_NB              0xa 
#define VBE_DISPI_INDEX_VIDEO_MEMORY_64K 0xa 
#define VBE_DISPI_INDEX_VIRT_HEIGHT     0x7
#define VBE_DISPI_INDEX_VIRT_WIDTH      0x6
#define VBE_DISPI_INDEX_XRES            0x1
#define VBE_DISPI_INDEX_X_OFFSET        0x8
#define VBE_DISPI_INDEX_YRES            0x2
#define VBE_DISPI_INDEX_Y_OFFSET        0x9
#define VBE_DISPI_LFB_ENABLED           0x40
#define VBE_DISPI_LFB_PHYSICAL_ADDRESS  0xE0000000
#define VBE_DISPI_MAX_BPP               32
#define VBE_DISPI_MAX_XRES              16000
#define VBE_DISPI_MAX_YRES              12000
#define VBE_DISPI_NOCLEARMEM            0x80
#define VGABIOS_CIRRUS_FILENAME "vgabios-cirrus.bin"
#define VGABIOS_FILENAME "vgabios.bin"
#define VGA_MAX_HEIGHT 2048
#define IOMMU_NOTIFIER_ALL (IOMMU_NOTIFIER_MAP | IOMMU_NOTIFIER_UNMAP)
#define MAX_PHYS_ADDR            (((hwaddr)1 << MAX_PHYS_ADDR_SPACE_BITS) - 1)
#define MAX_PHYS_ADDR_SPACE_BITS 62

#define MEMORY_REGION(obj) \
        OBJECT_CHECK(MemoryRegion, (obj), TYPE_MEMORY_REGION)
#define MEMORY_REGION_CACHE_INVALID ((MemoryRegionCache) { .mr = NULL })
#define MEMTX_DECODE_ERROR      (1U << 1) 
#define MEMTX_ERROR             (1U << 0) 
#define MEMTX_OK 0
#define RAM_ADDR_INVALID (~(ram_addr_t)0)
#define TYPE_MEMORY_REGION "qemu:memory-region"

#define call_rcu(head, func, field)                                      \
    call_rcu1(({                                                         \
         char __attribute__((unused))                                    \
            offset_must_be_zero[-offsetof(typeof(*(head)), field)],      \
            func_type_invalid = (func) - (void (*)(typeof(head)))(func); \
         &(head)->field;                                                 \
      }),                                                                \
      (RCUCBFunc *)(func))
#define g_free_rcu(obj, field) \
    call_rcu1(({                                                         \
        char __attribute__((unused))                                     \
            offset_must_be_zero[-offsetof(typeof(*(obj)), field)];       \
        &(obj)->field;                                                   \
      }),                                                                \
      (RCUCBFunc *)g_free);
#define rcu_assert(args...)    assert(args)
#define QEMU_THREAD_DETACHED 1

#define QEMU_THREAD_JOINABLE 0

#define qemu_rec_mutex_destroy qemu_mutex_destroy
#define qemu_rec_mutex_lock qemu_mutex_lock
#define qemu_rec_mutex_try_lock qemu_mutex_try_lock
#define qemu_rec_mutex_unlock qemu_mutex_unlock


# define cpu_relax() asm volatile("rep; nop" ::: "memory")
#define INTERFACE_CHECK(interface, obj, name) \
    ((interface *)object_dynamic_cast_assert(OBJECT((obj)), (name), \
                                             "__FILE__", "__LINE__", __func__))
#define INTERFACE_CLASS(klass) \
    OBJECT_CLASS_CHECK(InterfaceClass, klass, TYPE_INTERFACE)
#define OBJECT(obj) \
    ((Object *)(obj))
#define OBJECT_CHECK(type, obj, name) \
    ((type *)object_dynamic_cast_assert(OBJECT(obj), (name), \
                                        "__FILE__", "__LINE__", __func__))
#define OBJECT_CLASS(class) \
    ((ObjectClass *)(class))
#define OBJECT_CLASS_CAST_CACHE 4
#define OBJECT_CLASS_CHECK(class_type, class, name) \
    ((class_type *)object_class_dynamic_cast_assert(OBJECT_CLASS(class), (name), \
                                               "__FILE__", "__LINE__", __func__))
#define OBJECT_GET_CLASS(class, obj, name) \
    OBJECT_CLASS_CHECK(class, object_get_class(OBJECT(obj)), name)

#define TYPE_INTERFACE "interface"
#define TYPE_OBJECT "object"
#define NOTIFIER_LIST_INITIALIZER(head) \
    { QLIST_HEAD_INITIALIZER((head).notifiers) }
#define NOTIFIER_WITH_RETURN_LIST_INITIALIZER(head) \
    { QLIST_HEAD_INITIALIZER((head).notifiers) }



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
#define LIT64( a ) a##LL

#define const_float16(x) { x }
#define const_float32(x) { x }
#define const_float64(x) { x }
#define float128_zero make_float128(0, 0)
#define float16_val(x) (((float16)(x)).v)
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
#define make_float16(x) __extension__ ({ float16 f16_val = {x}; f16_val; })
#define make_float32(x) __extension__ ({ float32 f32_val = {x}; f32_val; })
#define make_float64(x) __extension__ ({ float64 f64_val = {x}; f64_val; })
#define make_floatx80(exp, mant) ((floatx80) { mant, exp })
#define make_floatx80_init(exp, mant) { .low = mant, .high = exp }
#define DIRTY_MEMORY_BLOCK_SIZE ((ram_addr_t)256 * 1024 * 8)
#define DIRTY_MEMORY_CODE      1
#define DIRTY_MEMORY_MIGRATION 2
#define DIRTY_MEMORY_NUM       3        
#define DIRTY_MEMORY_VGA       0


#define MEMTXATTRS_UNSPECIFIED ((MemTxAttrs) { .unspecified = 1 })

#define DEVICE_HOST_ENDIAN DEVICE_BIG_ENDIAN
#  define RAM_ADDR_FMT "%" PRIx64
#  define RAM_ADDR_MAX UINT64_MAX



#define DSO_STAMP_FUN         glue(qemu_stamp, CONFIG_STAMP)
#define DSO_STAMP_FUN_STR     stringify(DSO_STAMP_FUN)

#define block_init(function) module_init(function, MODULE_INIT_BLOCK)
#define block_module_load_one(lib) module_load_one("block-", lib)
#define module_init(function, type)                                         \
static void __attribute__((constructor)) do_qemu_init_ ## function(void)    \
{                                                                           \
    register_dso_module_init(function, type);                               \
}
#define opts_init(function) module_init(function, MODULE_INIT_OPTS)
#define trace_init(function) module_init(function, MODULE_INIT_TRACE)
#define type_init(function) module_init(function, MODULE_INIT_QOM)

#define SELF_ANNOUNCE_ROUNDS 5
#define VMSTATE_2DARRAY(_field, _state, _n1, _n2, _version, _info, _type) { \
    .name       = (stringify(_field)),                                      \
    .version_id = (_version),                                               \
    .num        = (_n1) * (_n2),                                            \
    .info       = &(_info),                                                 \
    .size       = sizeof(_type),                                            \
    .flags      = VMS_ARRAY,                                                \
    .offset     = vmstate_offset_2darray(_state, _field, _type, _n1, _n2),  \
}
#define VMSTATE_ARRAY(_field, _state, _num, _version, _info, _type) {\
    .name       = (stringify(_field)),                               \
    .version_id = (_version),                                        \
    .num        = (_num),                                            \
    .info       = &(_info),                                          \
    .size       = sizeof(_type),                                     \
    .flags      = VMS_ARRAY,                                         \
    .offset     = vmstate_offset_array(_state, _field, _type, _num), \
}
#define VMSTATE_ARRAY_INT32_UNSAFE(_field, _state, _field_num, _info, _type) {\
    .name       = (stringify(_field)),                               \
    .num_offset = vmstate_offset_value(_state, _field_num, int32_t), \
    .info       = &(_info),                                          \
    .size       = sizeof(_type),                                     \
    .flags      = VMS_VARRAY_INT32,                                  \
    .offset     = offsetof(_state, _field),                          \
}
#define VMSTATE_ARRAY_OF_POINTER(_field, _state, _num, _version, _info, _type) {\
    .name       = (stringify(_field)),                               \
    .version_id = (_version),                                        \
    .num        = (_num),                                            \
    .info       = &(_info),                                          \
    .size       = sizeof(_type),                                     \
    .flags      = VMS_ARRAY|VMS_ARRAY_OF_POINTER,                    \
    .offset     = vmstate_offset_array(_state, _field, _type, _num), \
}
#define VMSTATE_ARRAY_OF_POINTER_TO_STRUCT(_f, _s, _n, _v, _vmsd, _type) { \
    .name       = (stringify(_f)),                                   \
    .version_id = (_v),                                              \
    .num        = (_n),                                              \
    .vmsd       = &(_vmsd),                                          \
    .size       = sizeof(_type *),                                    \
    .flags      = VMS_ARRAY|VMS_STRUCT|VMS_ARRAY_OF_POINTER,         \
    .offset     = vmstate_offset_array(_s, _f, _type*, _n),          \
}
#define VMSTATE_ARRAY_TEST(_field, _state, _num, _test, _info, _type) {\
    .name         = (stringify(_field)),                              \
    .field_exists = (_test),                                          \
    .num          = (_num),                                           \
    .info         = &(_info),                                         \
    .size         = sizeof(_type),                                    \
    .flags        = VMS_ARRAY,                                        \
    .offset       = vmstate_offset_array(_state, _field, _type, _num),\
}
#define VMSTATE_BITMAP(_field, _state, _version, _field_size) {      \
    .name         = (stringify(_field)),                             \
    .version_id   = (_version),                                      \
    .size_offset  = vmstate_offset_value(_state, _field_size, int32_t),\
    .info         = &vmstate_info_bitmap,                            \
    .flags        = VMS_VBUFFER|VMS_POINTER,                         \
    .offset       = offsetof(_state, _field),                        \
}
#define VMSTATE_BOOL(_f, _s)                                          \
    VMSTATE_BOOL_V(_f, _s, 0)
#define VMSTATE_BOOL_ARRAY(_f, _s, _n)                               \
    VMSTATE_BOOL_ARRAY_V(_f, _s, _n, 0)
#define VMSTATE_BOOL_ARRAY_V(_f, _s, _n, _v)                         \
    VMSTATE_ARRAY(_f, _s, _n, _v, vmstate_info_bool, bool)
#define VMSTATE_BOOL_V(_f, _s, _v)                                    \
    VMSTATE_SINGLE(_f, _s, _v, vmstate_info_bool, bool)
#define VMSTATE_BUFFER(_f, _s)                                        \
    VMSTATE_BUFFER_V(_f, _s, 0)
#define VMSTATE_BUFFER_POINTER_UNSAFE(_field, _state, _version, _size) { \
    .name       = (stringify(_field)),                               \
    .version_id = (_version),                                        \
    .size       = (_size),                                           \
    .info       = &vmstate_info_buffer,                              \
    .flags      = VMS_BUFFER|VMS_POINTER,                            \
    .offset     = offsetof(_state, _field),                          \
}
#define VMSTATE_BUFFER_START_MIDDLE(_f, _s, _start) \
    VMSTATE_BUFFER_START_MIDDLE_V(_f, _s, _start, 0)
#define VMSTATE_BUFFER_START_MIDDLE_V(_f, _s, _start, _v) \
    VMSTATE_STATIC_BUFFER(_f, _s, _v, NULL, _start, sizeof(typeof_field(_s, _f)))
#define VMSTATE_BUFFER_TEST(_f, _s, _test)                            \
    VMSTATE_STATIC_BUFFER(_f, _s, 0, _test, 0, sizeof(typeof_field(_s, _f)))
#define VMSTATE_BUFFER_UNSAFE(_field, _state, _version, _size)        \
    VMSTATE_BUFFER_UNSAFE_INFO(_field, _state, _version, vmstate_info_buffer, _size)
#define VMSTATE_BUFFER_UNSAFE_INFO(_field, _state, _version, _info, _size) \
    VMSTATE_BUFFER_UNSAFE_INFO_TEST(_field, _state, NULL, _version, _info, \
            _size)
#define VMSTATE_BUFFER_UNSAFE_INFO_TEST(_field, _state, _test, _version, _info, _size) { \
    .name       = (stringify(_field)),                               \
    .version_id = (_version),                                        \
    .field_exists = (_test),                                         \
    .size       = (_size),                                           \
    .info       = &(_info),                                          \
    .flags      = VMS_BUFFER,                                        \
    .offset     = offsetof(_state, _field),                          \
}
#define VMSTATE_BUFFER_V(_f, _s, _v)                                  \
    VMSTATE_STATIC_BUFFER(_f, _s, _v, NULL, 0, sizeof(typeof_field(_s, _f)))
#define VMSTATE_CPUDOUBLE_ARRAY(_f, _s, _n)                           \
    VMSTATE_CPUDOUBLE_ARRAY_V(_f, _s, _n, 0)
#define VMSTATE_CPUDOUBLE_ARRAY_V(_f, _s, _n, _v)                     \
    VMSTATE_ARRAY(_f, _s, _n, _v, vmstate_info_cpudouble, CPU_DoubleU)
#define VMSTATE_END_OF_LIST()                                         \
    {}
#define VMSTATE_FLOAT64(_f, _s)                                       \
    VMSTATE_FLOAT64_V(_f, _s, 0)
#define VMSTATE_FLOAT64_ARRAY(_f, _s, _n)                             \
    VMSTATE_FLOAT64_ARRAY_V(_f, _s, _n, 0)
#define VMSTATE_FLOAT64_ARRAY_V(_f, _s, _n, _v)                       \
    VMSTATE_ARRAY(_f, _s, _n, _v, vmstate_info_float64, float64)
#define VMSTATE_FLOAT64_V(_f, _s, _v)                                 \
    VMSTATE_SINGLE(_f, _s, _v, vmstate_info_float64, float64)
#define VMSTATE_INT16(_f, _s)                                         \
    VMSTATE_INT16_V(_f, _s, 0)
#define VMSTATE_INT16_ARRAY(_f, _s, _n)                               \
    VMSTATE_INT16_ARRAY_V(_f, _s, _n, 0)
#define VMSTATE_INT16_ARRAY_V(_f, _s, _n, _v)                         \
    VMSTATE_ARRAY(_f, _s, _n, _v, vmstate_info_int16, int16_t)
#define VMSTATE_INT16_TEST(_f, _s, _t)                               \
    VMSTATE_SINGLE_TEST(_f, _s, _t, 0, vmstate_info_int16, int16_t)
#define VMSTATE_INT16_V(_f, _s, _v)                                   \
    VMSTATE_SINGLE(_f, _s, _v, vmstate_info_int16, int16_t)
#define VMSTATE_INT32(_f, _s)                                         \
    VMSTATE_INT32_V(_f, _s, 0)
#define VMSTATE_INT32_ARRAY(_f, _s, _n)                               \
    VMSTATE_INT32_ARRAY_V(_f, _s, _n, 0)
#define VMSTATE_INT32_ARRAY_V(_f, _s, _n, _v)                         \
    VMSTATE_ARRAY(_f, _s, _n, _v, vmstate_info_int32, int32_t)
#define VMSTATE_INT32_EQUAL(_f, _s)                                   \
    VMSTATE_SINGLE(_f, _s, 0, vmstate_info_int32_equal, int32_t)
#define VMSTATE_INT32_POSITIVE_LE(_f, _s)                             \
    VMSTATE_SINGLE(_f, _s, 0, vmstate_info_int32_le, int32_t)
#define VMSTATE_INT32_TEST(_f, _s, _t)                                  \
    VMSTATE_SINGLE_TEST(_f, _s, _t, 0, vmstate_info_int32, int32_t)
#define VMSTATE_INT32_V(_f, _s, _v)                                   \
    VMSTATE_SINGLE(_f, _s, _v, vmstate_info_int32, int32_t)
#define VMSTATE_INT64(_f, _s)                                         \
    VMSTATE_INT64_V(_f, _s, 0)
#define VMSTATE_INT64_ARRAY(_f, _s, _n)                               \
    VMSTATE_INT64_ARRAY_V(_f, _s, _n, 0)
#define VMSTATE_INT64_ARRAY_V(_f, _s, _n, _v)                         \
    VMSTATE_ARRAY(_f, _s, _n, _v, vmstate_info_int64, int64_t)
#define VMSTATE_INT64_TEST(_f, _s, _t)                                  \
    VMSTATE_SINGLE_TEST(_f, _s, _t, 0, vmstate_info_int64, int64_t)
#define VMSTATE_INT64_V(_f, _s, _v)                                   \
    VMSTATE_SINGLE(_f, _s, _v, vmstate_info_int64, int64_t)
#define VMSTATE_INT8(_f, _s)                                          \
    VMSTATE_INT8_V(_f, _s, 0)
#define VMSTATE_INT8_TEST(_f, _s, _t)                               \
    VMSTATE_SINGLE_TEST(_f, _s, _t, 0, vmstate_info_int8, int8_t)
#define VMSTATE_INT8_V(_f, _s, _v)                                    \
    VMSTATE_SINGLE(_f, _s, _v, vmstate_info_int8, int8_t)
#define VMSTATE_PARTIAL_BUFFER(_f, _s, _size)                         \
    VMSTATE_STATIC_BUFFER(_f, _s, 0, NULL, 0, _size)
#define VMSTATE_PARTIAL_VBUFFER(_f, _s, _size)                        \
    VMSTATE_VBUFFER(_f, _s, 0, NULL, _size)
#define VMSTATE_PARTIAL_VBUFFER_UINT32(_f, _s, _size)                        \
    VMSTATE_VBUFFER_UINT32(_f, _s, 0, NULL, _size)
#define VMSTATE_POINTER(_field, _state, _version, _info, _type) {    \
    .name       = (stringify(_field)),                               \
    .version_id = (_version),                                        \
    .info       = &(_info),                                          \
    .size       = sizeof(_type),                                     \
    .flags      = VMS_SINGLE|VMS_POINTER,                            \
    .offset     = vmstate_offset_value(_state, _field, _type),       \
}
#define VMSTATE_POINTER_TEST(_field, _state, _test, _info, _type) {  \
    .name       = (stringify(_field)),                               \
    .info       = &(_info),                                          \
    .field_exists = (_test),                                         \
    .size       = sizeof(_type),                                     \
    .flags      = VMS_SINGLE|VMS_POINTER,                            \
    .offset     = vmstate_offset_value(_state, _field, _type),       \
}
#define VMSTATE_QTAILQ_V(_field, _state, _version, _vmsd, _type, _next)  \
{                                                                        \
    .name         = (stringify(_field)),                                 \
    .version_id   = (_version),                                          \
    .vmsd         = &(_vmsd),                                            \
    .size         = sizeof(_type),                                       \
    .info         = &vmstate_info_qtailq,                                \
    .offset       = offsetof(_state, _field),                            \
    .start        = offsetof(_type, _next),                              \
}
#define VMSTATE_SINGLE(_field, _state, _version, _info, _type)        \
    VMSTATE_SINGLE_TEST(_field, _state, NULL, _version, _info, _type)
#define VMSTATE_SINGLE_TEST(_field, _state, _test, _version, _info, _type) { \
    .name         = (stringify(_field)),                             \
    .version_id   = (_version),                                      \
    .field_exists = (_test),                                         \
    .size         = sizeof(_type),                                   \
    .info         = &(_info),                                        \
    .flags        = VMS_SINGLE,                                      \
    .offset       = vmstate_offset_value(_state, _field, _type),     \
}
#define VMSTATE_STATIC_BUFFER(_field, _state, _version, _test, _start, _size) { \
    .name         = (stringify(_field)),                             \
    .version_id   = (_version),                                      \
    .field_exists = (_test),                                         \
    .size         = (_size - _start),                                \
    .info         = &vmstate_info_buffer,                            \
    .flags        = VMS_BUFFER,                                      \
    .offset       = vmstate_offset_buffer(_state, _field) + _start,  \
}
#define VMSTATE_STRUCT(_field, _state, _version, _vmsd, _type)        \
    VMSTATE_STRUCT_TEST(_field, _state, NULL, _version, _vmsd, _type)
#define VMSTATE_STRUCT_ARRAY(_field, _state, _num, _version, _vmsd, _type) \
    VMSTATE_STRUCT_ARRAY_TEST(_field, _state, _num, NULL, _version,   \
            _vmsd, _type)
#define VMSTATE_STRUCT_ARRAY_TEST(_field, _state, _num, _test, _version, _vmsd, _type) { \
    .name         = (stringify(_field)),                             \
    .num          = (_num),                                          \
    .field_exists = (_test),                                         \
    .version_id   = (_version),                                      \
    .vmsd         = &(_vmsd),                                        \
    .size         = sizeof(_type),                                   \
    .flags        = VMS_STRUCT|VMS_ARRAY,                            \
    .offset       = vmstate_offset_array(_state, _field, _type, _num),\
}
#define VMSTATE_STRUCT_POINTER(_field, _state, _vmsd, _type)          \
    VMSTATE_STRUCT_POINTER_V(_field, _state, 0, _vmsd, _type)
#define VMSTATE_STRUCT_POINTER_TEST(_field, _state, _test, _vmsd, _type)     \
    VMSTATE_STRUCT_POINTER_TEST_V(_field, _state, _test, 0, _vmsd, _type)
#define VMSTATE_STRUCT_POINTER_TEST_V(_field, _state, _test, _version, _vmsd, _type) { \
    .name         = (stringify(_field)),                             \
    .version_id   = (_version),                                        \
    .field_exists = (_test),                                         \
    .vmsd         = &(_vmsd),                                        \
    .size         = sizeof(_type *),                                 \
    .flags        = VMS_STRUCT|VMS_POINTER,                          \
    .offset       = vmstate_offset_pointer(_state, _field, _type),   \
}
#define VMSTATE_STRUCT_POINTER_V(_field, _state, _version, _vmsd, _type) { \
    .name         = (stringify(_field)),                             \
    .version_id   = (_version),                                        \
    .vmsd         = &(_vmsd),                                        \
    .size         = sizeof(_type *),                                 \
    .flags        = VMS_STRUCT|VMS_POINTER,                          \
    .offset       = vmstate_offset_pointer(_state, _field, _type),   \
}
#define VMSTATE_STRUCT_SUB_ARRAY(_field, _state, _start, _num, _version, _vmsd, _type) { \
    .name       = (stringify(_field)),                                     \
    .version_id = (_version),                                              \
    .num        = (_num),                                                  \
    .vmsd       = &(_vmsd),                                                \
    .size       = sizeof(_type),                                           \
    .flags      = VMS_STRUCT|VMS_ARRAY,                                    \
    .offset     = vmstate_offset_sub_array(_state, _field, _type, _start), \
}
#define VMSTATE_STRUCT_TEST(_field, _state, _test, _version, _vmsd, _type) { \
    .name         = (stringify(_field)),                             \
    .version_id   = (_version),                                      \
    .field_exists = (_test),                                         \
    .vmsd         = &(_vmsd),                                        \
    .size         = sizeof(_type),                                   \
    .flags        = VMS_STRUCT,                                      \
    .offset       = vmstate_offset_value(_state, _field, _type),     \
}
#define VMSTATE_STRUCT_VARRAY_ALLOC(_field, _state, _field_num, _version, _vmsd, _type) {\
    .name       = (stringify(_field)),                               \
    .version_id = (_version),                                        \
    .vmsd       = &(_vmsd),                                          \
    .num_offset = vmstate_offset_value(_state, _field_num, int32_t), \
    .size       = sizeof(_type),                                     \
    .flags      = VMS_STRUCT|VMS_VARRAY_INT32|VMS_ALLOC|VMS_POINTER, \
    .offset     = vmstate_offset_pointer(_state, _field, _type),     \
}
#define VMSTATE_STRUCT_VARRAY_INT32(_field, _state, _field_num, _version, _vmsd, _type) { \
    .name       = (stringify(_field)),                               \
    .num_offset = vmstate_offset_value(_state, _field_num, int32_t), \
    .version_id = (_version),                                        \
    .vmsd       = &(_vmsd),                                          \
    .size       = sizeof(_type),                                     \
    .flags      = VMS_STRUCT|VMS_VARRAY_INT32,                       \
    .offset     = offsetof(_state, _field),                          \
}
#define VMSTATE_STRUCT_VARRAY_POINTER_INT32(_field, _state, _field_num, _vmsd, _type) { \
    .name       = (stringify(_field)),                               \
    .version_id = 0,                                                 \
    .num_offset = vmstate_offset_value(_state, _field_num, int32_t), \
    .size       = sizeof(_type),                                     \
    .vmsd       = &(_vmsd),                                          \
    .flags      = VMS_POINTER | VMS_VARRAY_INT32 | VMS_STRUCT,       \
    .offset     = vmstate_offset_pointer(_state, _field, _type),     \
}
#define VMSTATE_STRUCT_VARRAY_POINTER_KNOWN(_field, _state, _num, _version, _vmsd, _type) { \
    .name       = (stringify(_field)),                               \
    .num          = (_num),                                          \
    .version_id = (_version),                                        \
    .vmsd       = &(_vmsd),                                          \
    .size       = sizeof(_type),                                     \
    .flags      = VMS_STRUCT|VMS_ARRAY|VMS_POINTER,                  \
    .offset     = offsetof(_state, _field),                          \
}
#define VMSTATE_STRUCT_VARRAY_POINTER_UINT16(_field, _state, _field_num, _vmsd, _type) { \
    .name       = (stringify(_field)),                               \
    .version_id = 0,                                                 \
    .num_offset = vmstate_offset_value(_state, _field_num, uint16_t),\
    .size       = sizeof(_type),                                     \
    .vmsd       = &(_vmsd),                                          \
    .flags      = VMS_POINTER | VMS_VARRAY_UINT16 | VMS_STRUCT,      \
    .offset     = vmstate_offset_pointer(_state, _field, _type),     \
}
#define VMSTATE_STRUCT_VARRAY_POINTER_UINT32(_field, _state, _field_num, _vmsd, _type) { \
    .name       = (stringify(_field)),                               \
    .version_id = 0,                                                 \
    .num_offset = vmstate_offset_value(_state, _field_num, uint32_t),\
    .size       = sizeof(_type),                                     \
    .vmsd       = &(_vmsd),                                          \
    .flags      = VMS_POINTER | VMS_VARRAY_INT32 | VMS_STRUCT,       \
    .offset     = vmstate_offset_pointer(_state, _field, _type),     \
}
#define VMSTATE_STRUCT_VARRAY_UINT32(_field, _state, _field_num, _version, _vmsd, _type) { \
    .name       = (stringify(_field)),                               \
    .num_offset = vmstate_offset_value(_state, _field_num, uint32_t), \
    .version_id = (_version),                                        \
    .vmsd       = &(_vmsd),                                          \
    .size       = sizeof(_type),                                     \
    .flags      = VMS_STRUCT|VMS_VARRAY_UINT32,                      \
    .offset     = offsetof(_state, _field),                          \
}
#define VMSTATE_STRUCT_VARRAY_UINT8(_field, _state, _field_num, _version, _vmsd, _type) { \
    .name       = (stringify(_field)),                               \
    .num_offset = vmstate_offset_value(_state, _field_num, uint8_t), \
    .version_id = (_version),                                        \
    .vmsd       = &(_vmsd),                                          \
    .size       = sizeof(_type),                                     \
    .flags      = VMS_STRUCT|VMS_VARRAY_UINT8,                       \
    .offset     = offsetof(_state, _field),                          \
}
#define VMSTATE_SUB_ARRAY(_field, _state, _start, _num, _version, _info, _type) { \
    .name       = (stringify(_field)),                               \
    .version_id = (_version),                                        \
    .num        = (_num),                                            \
    .info       = &(_info),                                          \
    .size       = sizeof(_type),                                     \
    .flags      = VMS_ARRAY,                                         \
    .offset     = vmstate_offset_sub_array(_state, _field, _type, _start), \
}
#define VMSTATE_TIMER(_f, _s)                                         \
    VMSTATE_TIMER_V(_f, _s, 0)
#define VMSTATE_TIMER_ARRAY(_f, _s, _n)                              \
    VMSTATE_ARRAY(_f, _s, _n, 0, vmstate_info_timer, QEMUTimer)
#define VMSTATE_TIMER_PTR(_f, _s)                                         \
    VMSTATE_TIMER_PTR_V(_f, _s, 0)
#define VMSTATE_TIMER_PTR_ARRAY(_f, _s, _n)                              \
    VMSTATE_ARRAY_OF_POINTER(_f, _s, _n, 0, vmstate_info_timer, QEMUTimer *)
#define VMSTATE_TIMER_PTR_TEST(_f, _s, _test)                             \
    VMSTATE_POINTER_TEST(_f, _s, _test, vmstate_info_timer, QEMUTimer *)
#define VMSTATE_TIMER_PTR_V(_f, _s, _v)                                   \
    VMSTATE_POINTER(_f, _s, _v, vmstate_info_timer, QEMUTimer *)
#define VMSTATE_TIMER_TEST(_f, _s, _test)                             \
    VMSTATE_SINGLE_TEST(_f, _s, _test, 0, vmstate_info_timer, QEMUTimer)
#define VMSTATE_TIMER_V(_f, _s, _v)                                   \
    VMSTATE_SINGLE(_f, _s, _v, vmstate_info_timer, QEMUTimer)
#define VMSTATE_UINT16(_f, _s)                                        \
    VMSTATE_UINT16_V(_f, _s, 0)
#define VMSTATE_UINT16_2DARRAY(_f, _s, _n1, _n2)                      \
    VMSTATE_UINT16_2DARRAY_V(_f, _s, _n1, _n2, 0)
#define VMSTATE_UINT16_2DARRAY_V(_f, _s, _n1, _n2, _v)                \
    VMSTATE_2DARRAY(_f, _s, _n1, _n2, _v, vmstate_info_uint16, uint16_t)
#define VMSTATE_UINT16_ARRAY(_f, _s, _n)                               \
    VMSTATE_UINT16_ARRAY_V(_f, _s, _n, 0)
#define VMSTATE_UINT16_ARRAY_V(_f, _s, _n, _v)                         \
    VMSTATE_ARRAY(_f, _s, _n, _v, vmstate_info_uint16, uint16_t)
#define VMSTATE_UINT16_EQUAL(_f, _s)                                  \
    VMSTATE_SINGLE(_f, _s, 0, vmstate_info_uint16_equal, uint16_t)
#define VMSTATE_UINT16_EQUAL_V(_f, _s, _v)                            \
    VMSTATE_SINGLE(_f, _s, _v, vmstate_info_uint16_equal, uint16_t)
#define VMSTATE_UINT16_TEST(_f, _s, _t)                               \
    VMSTATE_SINGLE_TEST(_f, _s, _t, 0, vmstate_info_uint16, uint16_t)
#define VMSTATE_UINT16_V(_f, _s, _v)                                  \
    VMSTATE_SINGLE(_f, _s, _v, vmstate_info_uint16, uint16_t)
#define VMSTATE_UINT32(_f, _s)                                        \
    VMSTATE_UINT32_V(_f, _s, 0)
#define VMSTATE_UINT32_2DARRAY(_f, _s, _n1, _n2)                      \
    VMSTATE_UINT32_2DARRAY_V(_f, _s, _n1, _n2, 0)
#define VMSTATE_UINT32_2DARRAY_V(_f, _s, _n1, _n2, _v)                \
    VMSTATE_2DARRAY(_f, _s, _n1, _n2, _v, vmstate_info_uint32, uint32_t)
#define VMSTATE_UINT32_ARRAY(_f, _s, _n)                              \
    VMSTATE_UINT32_ARRAY_V(_f, _s, _n, 0)
#define VMSTATE_UINT32_ARRAY_V(_f, _s, _n, _v)                        \
    VMSTATE_ARRAY(_f, _s, _n, _v, vmstate_info_uint32, uint32_t)
#define VMSTATE_UINT32_EQUAL(_f, _s)                                  \
    VMSTATE_UINT32_EQUAL_V(_f, _s, 0)
#define VMSTATE_UINT32_EQUAL_V(_f, _s, _v)                            \
    VMSTATE_SINGLE(_f, _s, _v, vmstate_info_uint32_equal, uint32_t)
#define VMSTATE_UINT32_SUB_ARRAY(_f, _s, _start, _num)                \
    VMSTATE_SUB_ARRAY(_f, _s, _start, _num, 0, vmstate_info_uint32, uint32_t)
#define VMSTATE_UINT32_TEST(_f, _s, _t)                                  \
    VMSTATE_SINGLE_TEST(_f, _s, _t, 0, vmstate_info_uint32, uint32_t)
#define VMSTATE_UINT32_V(_f, _s, _v)                                  \
    VMSTATE_SINGLE(_f, _s, _v, vmstate_info_uint32, uint32_t)
#define VMSTATE_UINT64(_f, _s)                                        \
    VMSTATE_UINT64_V(_f, _s, 0)
#define VMSTATE_UINT64_2DARRAY(_f, _s, _n1, _n2)                      \
    VMSTATE_UINT64_2DARRAY_V(_f, _s, _n1, _n2, 0)
#define VMSTATE_UINT64_2DARRAY_V(_f, _s, _n1, _n2, _v)                 \
    VMSTATE_2DARRAY(_f, _s, _n1, _n2, _v, vmstate_info_uint64, uint64_t)
#define VMSTATE_UINT64_ARRAY(_f, _s, _n)                              \
    VMSTATE_UINT64_ARRAY_V(_f, _s, _n, 0)
#define VMSTATE_UINT64_ARRAY_V(_f, _s, _n, _v)                        \
    VMSTATE_ARRAY(_f, _s, _n, _v, vmstate_info_uint64, uint64_t)
#define VMSTATE_UINT64_EQUAL(_f, _s)                                  \
    VMSTATE_UINT64_EQUAL_V(_f, _s, 0)
#define VMSTATE_UINT64_EQUAL_V(_f, _s, _v)                            \
    VMSTATE_SINGLE(_f, _s, _v, vmstate_info_uint64_equal, uint64_t)
#define VMSTATE_UINT64_TEST(_f, _s, _t)                                  \
    VMSTATE_SINGLE_TEST(_f, _s, _t, 0, vmstate_info_uint64, uint64_t)
#define VMSTATE_UINT64_V(_f, _s, _v)                                  \
    VMSTATE_SINGLE(_f, _s, _v, vmstate_info_uint64, uint64_t)
#define VMSTATE_UINT8(_f, _s)                                         \
    VMSTATE_UINT8_V(_f, _s, 0)
#define VMSTATE_UINT8_2DARRAY(_f, _s, _n1, _n2)                       \
    VMSTATE_UINT8_2DARRAY_V(_f, _s, _n1, _n2, 0)
#define VMSTATE_UINT8_2DARRAY_V(_f, _s, _n1, _n2, _v)                 \
    VMSTATE_2DARRAY(_f, _s, _n1, _n2, _v, vmstate_info_uint8, uint8_t)
#define VMSTATE_UINT8_ARRAY(_f, _s, _n)                               \
    VMSTATE_UINT8_ARRAY_V(_f, _s, _n, 0)
#define VMSTATE_UINT8_ARRAY_V(_f, _s, _n, _v)                         \
    VMSTATE_ARRAY(_f, _s, _n, _v, vmstate_info_uint8, uint8_t)
#define VMSTATE_UINT8_EQUAL(_f, _s)                                   \
    VMSTATE_SINGLE(_f, _s, 0, vmstate_info_uint8_equal, uint8_t)
#define VMSTATE_UINT8_SUB_ARRAY(_f, _s, _start, _num)                \
    VMSTATE_SUB_ARRAY(_f, _s, _start, _num, 0, vmstate_info_uint8, uint8_t)
#define VMSTATE_UINT8_TEST(_f, _s, _t)                               \
    VMSTATE_SINGLE_TEST(_f, _s, _t, 0, vmstate_info_uint8, uint8_t)
#define VMSTATE_UINT8_V(_f, _s, _v)                                   \
    VMSTATE_SINGLE(_f, _s, _v, vmstate_info_uint8, uint8_t)
#define VMSTATE_UNUSED(_size)                                         \
    VMSTATE_UNUSED_V(0, _size)
#define VMSTATE_UNUSED_BUFFER(_test, _version, _size) {              \
    .name         = "unused",                                        \
    .field_exists = (_test),                                         \
    .version_id   = (_version),                                      \
    .size         = (_size),                                         \
    .info         = &vmstate_info_unused_buffer,                     \
    .flags        = VMS_BUFFER,                                      \
}
#define VMSTATE_UNUSED_TEST(_test, _size)                             \
    VMSTATE_UNUSED_BUFFER(_test, 0, _size)
#define VMSTATE_UNUSED_V(_v, _size)                                   \
    VMSTATE_UNUSED_BUFFER(NULL, _v, _size)
#define VMSTATE_UNUSED_VARRAY_UINT32(_state, _test, _version, _field_num, _size) {\
    .name         = "unused",                                        \
    .field_exists = (_test),                                         \
    .num_offset   = vmstate_offset_value(_state, _field_num, uint32_t),\
    .version_id   = (_version),                                      \
    .size         = (_size),                                         \
    .info         = &vmstate_info_unused_buffer,                     \
    .flags        = VMS_VARRAY_UINT32 | VMS_BUFFER,                  \
}
#define VMSTATE_VALIDATE(_name, _test) { \
    .name         = (_name),                                         \
    .field_exists = (_test),                                         \
    .flags        = VMS_ARRAY | VMS_MUST_EXIST,                      \
    .num          = 0,      \
}
#define VMSTATE_VARRAY_INT32(_field, _state, _field_num, _version, _info, _type) {\
    .name       = (stringify(_field)),                               \
    .version_id = (_version),                                        \
    .num_offset = vmstate_offset_value(_state, _field_num, int32_t), \
    .info       = &(_info),                                          \
    .size       = sizeof(_type),                                     \
    .flags      = VMS_VARRAY_INT32|VMS_POINTER,                      \
    .offset     = vmstate_offset_pointer(_state, _field, _type),     \
}
#define VMSTATE_VARRAY_MULTIPLY(_field, _state, _field_num, _multiply, _info, _type) { \
    .name       = (stringify(_field)),                               \
    .num_offset = vmstate_offset_value(_state, _field_num, uint32_t),\
    .num        = (_multiply),                                       \
    .info       = &(_info),                                          \
    .size       = sizeof(_type),                                     \
    .flags      = VMS_VARRAY_UINT32|VMS_MULTIPLY_ELEMENTS,           \
    .offset     = offsetof(_state, _field),                          \
}
#define VMSTATE_VARRAY_UINT16_UNSAFE(_field, _state, _field_num, _version, _info, _type) {\
    .name       = (stringify(_field)),                               \
    .version_id = (_version),                                        \
    .num_offset = vmstate_offset_value(_state, _field_num, uint16_t),\
    .info       = &(_info),                                          \
    .size       = sizeof(_type),                                     \
    .flags      = VMS_VARRAY_UINT16,                                 \
    .offset     = offsetof(_state, _field),                          \
}
#define VMSTATE_VARRAY_UINT32(_field, _state, _field_num, _version, _info, _type) {\
    .name       = (stringify(_field)),                               \
    .version_id = (_version),                                        \
    .num_offset = vmstate_offset_value(_state, _field_num, uint32_t),\
    .info       = &(_info),                                          \
    .size       = sizeof(_type),                                     \
    .flags      = VMS_VARRAY_UINT32|VMS_POINTER,                     \
    .offset     = vmstate_offset_pointer(_state, _field, _type),     \
}
#define VMSTATE_VARRAY_UINT32_ALLOC(_field, _state, _field_num, _version, _info, _type) {\
    .name       = (stringify(_field)),                               \
    .version_id = (_version),                                        \
    .num_offset = vmstate_offset_value(_state, _field_num, uint32_t),\
    .info       = &(_info),                                          \
    .size       = sizeof(_type),                                     \
    .flags      = VMS_VARRAY_UINT32|VMS_POINTER|VMS_ALLOC,           \
    .offset     = vmstate_offset_pointer(_state, _field, _type),     \
}
#define VMSTATE_VBUFFER(_field, _state, _version, _test, _field_size) { \
    .name         = (stringify(_field)),                             \
    .version_id   = (_version),                                      \
    .field_exists = (_test),                                         \
    .size_offset  = vmstate_offset_value(_state, _field_size, int32_t),\
    .info         = &vmstate_info_buffer,                            \
    .flags        = VMS_VBUFFER|VMS_POINTER,                         \
    .offset       = offsetof(_state, _field),                        \
}
#define VMSTATE_VBUFFER_ALLOC_UINT32(_field, _state, _version,       \
                                     _test, _field_size) {           \
    .name         = (stringify(_field)),                             \
    .version_id   = (_version),                                      \
    .field_exists = (_test),                                         \
    .size_offset  = vmstate_offset_value(_state, _field_size, uint32_t),\
    .info         = &vmstate_info_buffer,                            \
    .flags        = VMS_VBUFFER|VMS_POINTER|VMS_ALLOC,               \
    .offset       = offsetof(_state, _field),                        \
}
#define VMSTATE_VBUFFER_MULTIPLY(_field, _state, _version, _test,    \
                                 _field_size, _multiply) {           \
    .name         = (stringify(_field)),                             \
    .version_id   = (_version),                                      \
    .field_exists = (_test),                                         \
    .size_offset  = vmstate_offset_value(_state, _field_size, uint32_t),\
    .size         = (_multiply),                                      \
    .info         = &vmstate_info_buffer,                            \
    .flags        = VMS_VBUFFER|VMS_POINTER|VMS_MULTIPLY,            \
    .offset       = offsetof(_state, _field),                        \
}
#define VMSTATE_VBUFFER_UINT32(_field, _state, _version, _test, _field_size) { \
    .name         = (stringify(_field)),                             \
    .version_id   = (_version),                                      \
    .field_exists = (_test),                                         \
    .size_offset  = vmstate_offset_value(_state, _field_size, uint32_t),\
    .info         = &vmstate_info_buffer,                            \
    .flags        = VMS_VBUFFER|VMS_POINTER,                         \
    .offset       = offsetof(_state, _field),                        \
}
#define VMSTATE_WITH_TMP(_state, _tmp_type, _vmsd) {                 \
    .name         = "tmp",                                           \
    .size         = sizeof(_tmp_type) +                              \
                    QEMU_BUILD_BUG_ON_ZERO(offsetof(_tmp_type, parent) != 0) + \
                    type_check_pointer(_state,                       \
                        typeof_field(_tmp_type, parent)),            \
    .vmsd         = &(_vmsd),                                        \
    .info         = &vmstate_info_tmp,                               \
}
#define VMS_NULLPTR_MARKER (0x30U) 
#define type_check_2darray(t1,t2,n,m) ((t1(*)[n][m])0 - (t2*)0)
#define type_check_array(t1,t2,n) ((t1(*)[n])0 - (t2*)0)
#define type_check_pointer(t1,t2) ((t1**)0 - (t2*)0)
#define vmstate_offset_2darray(_state, _field, _type, _n1, _n2)      \
    (offsetof(_state, _field) +                                      \
     type_check_2darray(_type, typeof_field(_state, _field), _n1, _n2))
#define vmstate_offset_array(_state, _field, _type, _num)            \
    (offsetof(_state, _field) +                                      \
     type_check_array(_type, typeof_field(_state, _field), _num))
#define vmstate_offset_buffer(_state, _field)                        \
    vmstate_offset_array(_state, _field, uint8_t,                    \
                         sizeof(typeof_field(_state, _field)))
#define vmstate_offset_pointer(_state, _field, _type)                \
    (offsetof(_state, _field) +                                      \
     type_check_pointer(_type, typeof_field(_state, _field)))
#define vmstate_offset_sub_array(_state, _field, _type, _start)      \
    vmstate_offset_value(_state, _field[_start], _type)
#define vmstate_offset_value(_state, _field, _type)                  \
    (offsetof(_state, _field) +                                      \
     type_check(_type, typeof_field(_state, _field)))


#define RAM_CONTROL_BLOCK_REG 4
#define RAM_CONTROL_FINISH    3
#define RAM_CONTROL_HOOK      2
#define RAM_CONTROL_ROUND     1
#define RAM_CONTROL_SETUP     0
#define qemu_get_sbyte qemu_get_byte
#define qemu_put_sbyte qemu_put_byte
#define QIO_CHANNEL(obj)                                    \
    OBJECT_CHECK(QIOChannel, (obj), TYPE_QIO_CHANNEL)
#define QIO_CHANNEL_CLASS(klass)                                    \
    OBJECT_CLASS_CHECK(QIOChannelClass, klass, TYPE_QIO_CHANNEL)
#define QIO_CHANNEL_ERR_BLOCK -2
#define QIO_CHANNEL_GET_CLASS(obj)                                  \
    OBJECT_GET_CLASS(QIOChannelClass, obj, TYPE_QIO_CHANNEL)

#define TYPE_QIO_CHANNEL "qio-channel"

#define MIPS_RDHWR(rd, value) {                         \
        __asm__ __volatile__ (".set   push\n\t"         \
                              ".set mips32r2\n\t"       \
                              "rdhwr  %0, "rd"\n\t"     \
                              ".set   pop"              \
                              : "=r" (value));          \
    }
#define NANOSECONDS_PER_SECOND 1000000000LL

#define SCALE_MS 1000000
#define SCALE_NS 1
#define SCALE_US 1000

# define clol   clo32
# define clzl   clz32
# define ctol   cto32
# define ctpopl ctpop32
# define ctzl   ctz32
# define revbitl revbit32

#define QEMU_COPYRIGHT "Copyright (c) 2003-2017 " \
    "Fabrice Bellard and the QEMU Project developers"
#define QEMU_FILE_TYPE_BIOS   0
#define QEMU_FILE_TYPE_KEYMAP 1
#define TFR(expr) do { if ((expr) != -1) break; } while (errno == EINTR)
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





#define TYPE_IRQ "irq"
#define ATTR2CHTYPE(c, fg, bg, bold) \
    ((bold) << 21 | (bg) << 11 | (fg) << 8 | (c))

#define GUI_REFRESH_INTERVAL_DEFAULT    30
#define GUI_REFRESH_INTERVAL_IDLE     3000
#define MOUSE_EVENT_LBUTTON 0x01
#define MOUSE_EVENT_MBUTTON 0x04
#define MOUSE_EVENT_RBUTTON 0x02
#define MOUSE_EVENT_WHEELDN 0x10
#define MOUSE_EVENT_WHEELUP 0x08
#define QEMU_ALLOCATED_FLAG     0x01
#define QEMU_CAPS_LOCK_LED   (1 << 2)
#define QEMU_CONSOLE(obj) \
    OBJECT_CHECK(QemuConsole, (obj), TYPE_QEMU_CONSOLE)
#define QEMU_CONSOLE_CLASS(klass) \
    OBJECT_CLASS_CHECK(QemuConsoleClass, (klass), TYPE_QEMU_CONSOLE)
#define QEMU_CONSOLE_GET_CLASS(obj) \
    OBJECT_GET_CLASS(QemuConsoleClass, (obj), TYPE_QEMU_CONSOLE)
#define QEMU_KEY_BACKSPACE  0x007f
#define QEMU_KEY_CTRL_DOWN       0xe401
#define QEMU_KEY_CTRL_END        0xe405
#define QEMU_KEY_CTRL_HOME       0xe404
#define QEMU_KEY_CTRL_LEFT       0xe402
#define QEMU_KEY_CTRL_PAGEDOWN   0xe407
#define QEMU_KEY_CTRL_PAGEUP     0xe406
#define QEMU_KEY_CTRL_RIGHT      0xe403
#define QEMU_KEY_CTRL_UP         0xe400
#define QEMU_KEY_DELETE     QEMU_KEY_ESC1(3)
#define QEMU_KEY_DOWN       QEMU_KEY_ESC1('B')
#define QEMU_KEY_END        QEMU_KEY_ESC1(4)
#define QEMU_KEY_ESC1(c) ((c) | 0xe100)
#define QEMU_KEY_HOME       QEMU_KEY_ESC1(1)
#define QEMU_KEY_LEFT       QEMU_KEY_ESC1('D')
#define QEMU_KEY_PAGEDOWN   QEMU_KEY_ESC1(6)
#define QEMU_KEY_PAGEUP     QEMU_KEY_ESC1(5)
#define QEMU_KEY_RIGHT      QEMU_KEY_ESC1('C')
#define QEMU_KEY_UP         QEMU_KEY_ESC1('A')
#define QEMU_NUM_LOCK_LED    (1 << 1)
#define QEMU_SCROLL_LOCK_LED (1 << 0)
#define TYPE_QEMU_CONSOLE "qemu-console"

#define error_set(errp, err_class, fmt, ...)                    \
    error_set_internal((errp), "__FILE__", "__LINE__", __func__,    \
                       (err_class), (fmt), ## __VA_ARGS__)
#define error_setg(errp, fmt, ...)                              \
    error_setg_internal((errp), "__FILE__", "__LINE__", __func__,   \
                        (fmt), ## __VA_ARGS__)
#define error_setg_errno(errp, os_error, fmt, ...)                      \
    error_setg_errno_internal((errp), "__FILE__", "__LINE__", __func__,     \
                              (os_error), (fmt), ## __VA_ARGS__)
#define error_setg_file_open(errp, os_errno, filename)                  \
    error_setg_file_open_internal((errp), "__FILE__", "__LINE__", __func__, \
                                  (os_errno), (filename))
#define error_setg_win32(errp, win32_err, fmt, ...)                     \
    error_setg_win32_internal((errp), "__FILE__", "__LINE__", __func__,     \
                              (win32_err), (fmt), ## __VA_ARGS__)

# define PIXMAN_BE_a8b8g8r8   PIXMAN_a8b8g8r8
# define PIXMAN_BE_a8r8g8b8   PIXMAN_a8r8g8b8
# define PIXMAN_BE_b8g8r8a8   PIXMAN_b8g8r8a8
# define PIXMAN_BE_b8g8r8x8   PIXMAN_b8g8r8x8
# define PIXMAN_BE_r8g8b8     PIXMAN_r8g8b8
# define PIXMAN_BE_r8g8b8a8   PIXMAN_r8g8b8a8
# define PIXMAN_BE_r8g8b8x8   PIXMAN_r8g8b8x8
# define PIXMAN_BE_x8b8g8r8   PIXMAN_x8b8g8r8
# define PIXMAN_BE_x8r8g8b8   PIXMAN_x8r8g8b8
# define PIXMAN_LE_x8r8g8b8   PIXMAN_b8g8r8x8

#define FMT_PCIBUS                      PRIx64
#define PCIE_CONFIG_SPACE_SIZE  0x1000
#define PCI_BAR_UNMAPPED (~(pcibus_t)0)
#define PCI_BUILD_BDF(bus, devfn)     ((bus << 8) | (devfn))
#define PCI_BUS(obj) OBJECT_CHECK(PCIBus, (obj), TYPE_PCI_BUS)
#define PCI_BUS_CLASS(klass) OBJECT_CLASS_CHECK(PCIBusClass, (klass), TYPE_PCI_BUS)
#define PCI_BUS_GET_CLASS(obj) OBJECT_GET_CLASS(PCIBusClass, (obj), TYPE_PCI_BUS)
#define PCI_BUS_MAX             256
#define PCI_BUS_NUM(x)          (((x) >> 8) & 0xff)
#define PCI_CONFIG_HEADER_SIZE 0x40
#define PCI_CONFIG_SPACE_SIZE 0x100
#define PCI_DEVFN(slot, func)   ((((slot) & 0x1f) << 3) | ((func) & 0x07))
#define PCI_DEVFN_MAX           256
#define PCI_DEVICE(obj) \
     OBJECT_CHECK(PCIDevice, (obj), TYPE_PCI_DEVICE)
#define PCI_DEVICE_CLASS(klass) \
     OBJECT_CLASS_CHECK(PCIDeviceClass, (klass), TYPE_PCI_DEVICE)
#define PCI_DEVICE_GET_CLASS(obj) \
     OBJECT_GET_CLASS(PCIDeviceClass, (obj), TYPE_PCI_DEVICE)
#define PCI_DEVICE_ID_APPLE_343S1201     0x0010
#define PCI_DEVICE_ID_APPLE_IPID_USB     0x003f
#define PCI_DEVICE_ID_APPLE_UNI_N_I_PCI  0x001e
#define PCI_DEVICE_ID_APPLE_UNI_N_KEYL   0x0022
#define PCI_DEVICE_ID_APPLE_UNI_N_PCI    0x001f
#define PCI_DEVICE_ID_HITACHI_SH7751R    0x350e
#define PCI_DEVICE_ID_IBM_440GX          0x027f
#define PCI_DEVICE_ID_IBM_OPENPIC2       0xffff
#define PCI_DEVICE_ID_INTEL_82551IT      0x1209
#define PCI_DEVICE_ID_INTEL_82557        0x1229
#define PCI_DEVICE_ID_INTEL_82801IR      0x2922
#define PCI_DEVICE_ID_MARVELL_GT6412X    0x4620
#define PCI_DEVICE_ID_QEMU_VGA           0x1111
#define PCI_DEVICE_ID_REALTEK_8029       0x8029
#define PCI_DEVICE_ID_REDHAT_BRIDGE      0x0001
#define PCI_DEVICE_ID_REDHAT_BRIDGE_SEAT 0x000a
#define PCI_DEVICE_ID_REDHAT_PCIE_HOST   0x0008
#define PCI_DEVICE_ID_REDHAT_PCIE_RP     0x000c
#define PCI_DEVICE_ID_REDHAT_PXB         0x0009
#define PCI_DEVICE_ID_REDHAT_PXB_PCIE    0x000b
#define PCI_DEVICE_ID_REDHAT_QXL         0x0100
#define PCI_DEVICE_ID_REDHAT_ROCKER      0x0006
#define PCI_DEVICE_ID_REDHAT_SDHCI       0x0007
#define PCI_DEVICE_ID_REDHAT_SERIAL      0x0002
#define PCI_DEVICE_ID_REDHAT_SERIAL2     0x0003
#define PCI_DEVICE_ID_REDHAT_SERIAL4     0x0004
#define PCI_DEVICE_ID_REDHAT_TEST        0x0005
#define PCI_DEVICE_ID_REDHAT_XHCI        0x000d
#define PCI_DEVICE_ID_VIRTIO_9P          0x1009
#define PCI_DEVICE_ID_VIRTIO_BALLOON     0x1002
#define PCI_DEVICE_ID_VIRTIO_BLOCK       0x1001
#define PCI_DEVICE_ID_VIRTIO_CONSOLE     0x1003
#define PCI_DEVICE_ID_VIRTIO_NET         0x1000
#define PCI_DEVICE_ID_VIRTIO_RNG         0x1005
#define PCI_DEVICE_ID_VIRTIO_SCSI        0x1004
#define PCI_DEVICE_ID_VIRTIO_VSOCK       0x1012
#define PCI_DEVICE_ID_VMWARE_IDE         0x1729
#define PCI_DEVICE_ID_VMWARE_NET         0x0720
#define PCI_DEVICE_ID_VMWARE_PVSCSI      0x07C0
#define PCI_DEVICE_ID_VMWARE_SCSI        0x0730
#define PCI_DEVICE_ID_VMWARE_SVGA        0x0710
#define PCI_DEVICE_ID_VMWARE_SVGA2       0x0405
#define PCI_DEVICE_ID_VMWARE_VMXNET3     0x07B0
#define PCI_DEVICE_ID_XILINX_XC2VP30     0x0300
#define PCI_DMA_DEFINE_LDST(_l, _s, _bits)                              \
    static inline uint##_bits##_t ld##_l##_pci_dma(PCIDevice *dev,      \
                                                   dma_addr_t addr)     \
    {                                                                   \
        return ld##_l##_dma(pci_get_address_space(dev), addr);          \
    }                                                                   \
    static inline void st##_s##_pci_dma(PCIDevice *dev,                 \
                                        dma_addr_t addr, uint##_bits##_t val) \
    {                                                                   \
        st##_s##_dma(pci_get_address_space(dev), addr, val);            \
    }
#define PCI_FUNC(devfn)         ((devfn) & 0x07)
#define PCI_FUNC_MAX            8
#define  PCI_HEADER_TYPE_MULTI_FUNCTION 0x80
#define PCI_NUM_PINS 4 
#define PCI_NUM_REGIONS 7
#define PCI_ROM_SLOT 6
#define PCI_SLOT(devfn)         (((devfn) >> 3) & 0x1f)
#define PCI_SLOT_MAX            32
#define PCI_SUBDEVICE_ID_QEMU            0x1100
#define PCI_SUBVENDOR_ID_REDHAT_QUMRANET 0x1af4
#define PCI_VENDOR_ID_HITACHI            0x1054
#define PCI_VENDOR_ID_QEMU               0x1234
#define PCI_VENDOR_ID_REDHAT             0x1b36
#define PCI_VENDOR_ID_REDHAT_QUMRANET    0x1af4
#define PCI_VENDOR_ID_VMWARE             0x15ad
#define QEMU_PCIE_LNKSTA_DLLLA_BITNR 8
#define QEMU_PCIE_SLTCAP_PCP_BITNR 7
#define QEMU_PCI_CAP_MULTIFUNCTION_BITNR        3
#define QEMU_PCI_CAP_SERR_BITNR 4

#define QEMU_PCI_SHPC_BITNR 5
#define QEMU_PCI_SLOTID_BITNR 6
#define QEMU_PCI_VGA_IO_HI_BASE 0x3c0
#define QEMU_PCI_VGA_IO_HI_SIZE 0x20
#define QEMU_PCI_VGA_IO_LO_BASE 0x3b0
#define QEMU_PCI_VGA_IO_LO_SIZE 0xc
#define QEMU_PCI_VGA_MEM_BASE 0xa0000
#define QEMU_PCI_VGA_MEM_SIZE 0x20000
#define TYPE_PCIE_BUS "PCIE"
#define TYPE_PCI_BUS "PCI"
#define TYPE_PCI_DEVICE "pci-device"
#define VMSTATE_PCI_DEVICE(_field, _state) {                         \
    .name       = (stringify(_field)),                               \
    .size       = sizeof(PCIDevice),                                 \
    .vmsd       = &vmstate_pci_device,                               \
    .flags      = VMS_STRUCT,                                        \
    .offset     = vmstate_offset_value(_state, _field, PCIDevice),   \
}
#define VMSTATE_PCI_DEVICE_POINTER(_field, _state) {                 \
    .name       = (stringify(_field)),                               \
    .size       = sizeof(PCIDevice),                                 \
    .vmsd       = &vmstate_pci_device,                               \
    .flags      = VMS_STRUCT|VMS_POINTER,                            \
    .offset     = vmstate_offset_pointer(_state, _field, PCIDevice), \
}
#define  PCI_PM_CAP_VER_1_1     0x0002  
#define HT_CAPTYPE_REMAPPING_64 0xA2	

#define  PCI_AGP_COMMAND_RQ_MASK 0xff000000  
#define  PCI_ARI_CAP_NFN(x)	(((x) >> 8) & 0xff) 
#define  PCI_ARI_CTRL_FG(x)	(((x) >> 4) & 7) 
#define  PCI_ATS_CAP_QDEP(x)	((x) & 0x1f)	
#define  PCI_ATS_CTRL_STU(x)	((x) & 0x1f)	
#define  PCI_CB_BRIDGE_CTL_PREFETCH_MEM0 0x100	
#define  PCI_CB_BRIDGE_CTL_PREFETCH_MEM1 0x200
#define  PCI_COMMAND_INTX_DISABLE 0x400 
#define  PCI_COMMAND_VGA_PALETTE 0x20	
#define  PCI_ERR_CAP_FEP(x)	((x) & 31)	
#define  PCI_EXP_DEVCAP_FLR     0x10000000 
#define  PCI_EXP_DEVCTL_BCR_FLR 0x8000  
#define  PCI_EXP_DEVCTL_NOSNOOP_EN 0x0800  
#define  PCI_EXP_DEVCTL_READRQ_1024B 0x3000 
#define  PCI_EXP_DEVCTL_READRQ_128B  0x0000 
#define  PCI_EXP_DEVCTL_READRQ_256B  0x1000 
#define  PCI_EXP_DEVCTL_READRQ_512B  0x2000 
#define  PCI_EXP_DEVCTL_RELAX_EN 0x0010 
#define  PCI_EXP_DPC_CTL_EN_NONFATAL 	0x02	
#define  PCI_EXP_DPC_CTL_INT_EN 	0x08	
#define  PCI_EXP_LNKCAP_SLS_2_5GB 0x00000001 
#define  PCI_EXP_LNKCAP_SLS_5_0GB 0x00000002 
#define  PCI_EXP_LNKCTL_ASPM_L0S 0x0001	
#define  PCI_EXP_LNKCTL_ASPM_L1  0x0002	
#define  PCI_EXP_LNKCTL_CLKREQ_EN 0x0100 
#define  PCI_EXP_LNKSTA_CLS_2_5GB 0x0001 
#define  PCI_EXP_LNKSTA_CLS_5_0GB 0x0002 
#define  PCI_EXP_LNKSTA_CLS_8_0GB 0x0003 
#define  PCI_EXP_LNKSTA_NLW_SHIFT 4	
#define  PCI_EXP_SLTCTL_ATTN_IND_BLINK 0x0080 
#define  PCI_EXP_SLTCTL_ATTN_IND_OFF   0x00c0 
#define  PCI_EXP_SLTCTL_ATTN_IND_ON    0x0040 
#define  PCI_EXP_SLTCTL_PWR_IND_BLINK  0x0200 
#define  PCI_EXP_SLTCTL_PWR_IND_OFF    0x0300 
#define  PCI_EXP_SLTCTL_PWR_IND_ON     0x0100 
#define  PCI_EXP_SLTCTL_PWR_OFF        0x0400 
#define  PCI_EXP_SLTCTL_PWR_ON         0x0000 
#define  PCI_EXP_TYPE_DOWNSTREAM 0x6	
#define  PCI_EXP_TYPE_PCIE_BRIDGE 0x8	
#define  PCI_EXP_TYPE_PCI_BRIDGE 0x7	
#define  PCI_EXP_TYPE_ROOT_PORT 0x4	
#define PCI_EXT_CAP_ID(header)		(header & 0x0000ffff)
#define PCI_EXT_CAP_MCAST_ENDPOINT_SIZEOF 40
#define PCI_EXT_CAP_NEXT(header)	((header >> 20) & 0xffc)
#define PCI_EXT_CAP_SRIOV_SIZEOF 64
#define PCI_EXT_CAP_VER(header)		((header >> 16) & 0xf)
#define  PCI_MEMORY_RANGE_TYPE_MASK 0x0fUL
#define  PCI_PM_CAP_RESERVED    0x0010  
#define  PCI_PREF_RANGE_TYPE_MASK 0x0fUL
#define  PCI_PWR_CAP_BUDGET(x)	((x) & 1)	
#define  PCI_PWR_DATA_BASE(x)	((x) & 0xff)	    
#define  PCI_PWR_DATA_PM_STATE(x) (((x) >> 13) & 3) 
#define  PCI_PWR_DATA_PM_SUB(x)	(((x) >> 10) & 7)   
#define  PCI_PWR_DATA_RAIL(x)	(((x) >> 18) & 7)   
#define  PCI_PWR_DATA_SCALE(x)	(((x) >> 8) & 3)    
#define  PCI_PWR_DATA_TYPE(x)	(((x) >> 15) & 7)   
#define  PCI_SRIOV_CAP_INTR(x)	((x) >> 21) 
#define  PCI_SRIOV_VFM_BIR(x)	((x) & 7)	
#define  PCI_SRIOV_VFM_OFFSET(x) ((x) & ~7)	
#define PCI_SSVID_DEVICE_ID     6	
#define PCI_SSVID_VENDOR_ID     4	
#define  PCI_VNDR_HEADER_ID(x)	((x) & 0xffff)
#define  PCI_VNDR_HEADER_LEN(x)	(((x) >> 20) & 0xfff)
#define  PCI_VNDR_HEADER_REV(x)	(((x) >> 16) & 0xf)
#define  PCI_X_CMD_VERSION(x)	(((x) >> 12) & 3) 

#define PCI_BASE_CLASS_BRIDGE            0x06
#define PCI_BASE_CLASS_COMMUNICATION     0x07
#define PCI_BASE_CLASS_CRYPT             0x10
#define PCI_BASE_CLASS_DISPLAY           0x03
#define PCI_BASE_CLASS_DOCKING           0x0a
#define PCI_BASE_CLASS_INPUT             0x09
#define PCI_BASE_CLASS_MEMORY            0x05
#define PCI_BASE_CLASS_MULTIMEDIA        0x04
#define PCI_BASE_CLASS_NETWORK           0x02
#define PCI_BASE_CLASS_PROCESSOR         0x0b
#define PCI_BASE_CLASS_SATELLITE         0x0f
#define PCI_BASE_CLASS_SERIAL            0x0c
#define PCI_BASE_CLASS_SIGNAL_PROCESSING 0x11
#define PCI_BASE_CLASS_STORAGE           0x01
#define PCI_BASE_CLASS_SYSTEM            0x08
#define PCI_BASE_CLASS_WIRELESS          0x0d
#define PCI_CLASS_BRIDGE_CARDBUS         0x0607
#define PCI_CLASS_BRIDGE_EISA            0x0602
#define PCI_CLASS_BRIDGE_HOST            0x0600
#define PCI_CLASS_BRIDGE_IB_PCI          0x060a
#define PCI_CLASS_BRIDGE_ISA             0x0601
#define PCI_CLASS_BRIDGE_MC              0x0603
#define PCI_CLASS_BRIDGE_NUBUS           0x0606
#define PCI_CLASS_BRIDGE_OTHER           0x0680
#define PCI_CLASS_BRIDGE_PCI             0x0604
#define PCI_CLASS_BRIDGE_PCI_INF_SUB     0x01
#define PCI_CLASS_BRIDGE_PCI_SEMITP      0x0609
#define PCI_CLASS_BRIDGE_PCMCIA          0x0605
#define PCI_CLASS_BRIDGE_RACEWAY         0x0608
#define PCI_CLASS_COMMUNICATION_GPIB     0x0704
#define PCI_CLASS_COMMUNICATION_MODEM    0x0703
#define PCI_CLASS_COMMUNICATION_MULTISERIAL 0x0702
#define PCI_CLASS_COMMUNICATION_OTHER    0x0780
#define PCI_CLASS_COMMUNICATION_PARALLEL 0x0701
#define PCI_CLASS_COMMUNICATION_SC       0x0705
#define PCI_CLASS_COMMUNICATION_SERIAL   0x0700
#define PCI_CLASS_CRYPT_ENTERTAINMENT    0x1001
#define PCI_CLASS_CRYPT_NETWORK          0x1000
#define PCI_CLASS_CRYPT_OTHER            0x1080
#define PCI_CLASS_DISPLAY_3D             0x0302
#define PCI_CLASS_DISPLAY_OTHER          0x0380
#define PCI_CLASS_DISPLAY_VGA            0x0300
#define PCI_CLASS_DISPLAY_XGA            0x0301
#define PCI_CLASS_DOCKING_GENERIC        0x0a00
#define PCI_CLASS_DOCKING_OTHER          0x0a80
#define PCI_CLASS_INPUT_GAMEPORT         0x0904
#define PCI_CLASS_INPUT_KEYBOARD         0x0900
#define PCI_CLASS_INPUT_MOUSE            0x0902
#define PCI_CLASS_INPUT_OTHER            0x0980
#define PCI_CLASS_INPUT_PEN              0x0901
#define PCI_CLASS_INPUT_SCANNER          0x0903
#define PCI_CLASS_MEMORY_FLASH           0x0501
#define PCI_CLASS_MEMORY_OTHER           0x0580
#define PCI_CLASS_MEMORY_RAM             0x0500
#define PCI_CLASS_MULTIMEDIA_AUDIO       0x0401
#define PCI_CLASS_MULTIMEDIA_OTHER       0x0480
#define PCI_CLASS_MULTIMEDIA_PHONE       0x0402
#define PCI_CLASS_MULTIMEDIA_VIDEO       0x0400
#define PCI_CLASS_NETWORK_ATM            0x0203
#define PCI_CLASS_NETWORK_ETHERNET       0x0200
#define PCI_CLASS_NETWORK_FDDI           0x0202
#define PCI_CLASS_NETWORK_ISDN           0x0204
#define PCI_CLASS_NETWORK_OTHER          0x0280
#define PCI_CLASS_NETWORK_PICMG214       0x0206
#define PCI_CLASS_NETWORK_TOKEN_RING     0x0201
#define PCI_CLASS_NETWORK_WORLDFIP       0x0205
#define PCI_CLASS_NOT_DEFINED            0x0000
#define PCI_CLASS_NOT_DEFINED_VGA        0x0001
#define PCI_CLASS_OTHERS                 0xff
#define PCI_CLASS_PROCESSOR_CO           0x0b40
#define PCI_CLASS_PROCESSOR_MIPS         0x0b30
#define PCI_CLASS_PROCESSOR_PENTIUM      0x0b02
#define PCI_CLASS_PROCESSOR_POWERPC      0x0b20
#define PCI_CLASS_SATELLITE_AUDIO        0x0f01
#define PCI_CLASS_SATELLITE_DATA         0x0f04
#define PCI_CLASS_SATELLITE_TV           0x0f00
#define PCI_CLASS_SATELLITE_VOICE        0x0f03
#define PCI_CLASS_SERIAL_ACCESS          0x0c01
#define PCI_CLASS_SERIAL_CANBUS          0x0c09
#define PCI_CLASS_SERIAL_FIBER           0x0c04
#define PCI_CLASS_SERIAL_FIREWIRE        0x0c00
#define PCI_CLASS_SERIAL_IB              0x0c06
#define PCI_CLASS_SERIAL_IPMI            0x0c07
#define PCI_CLASS_SERIAL_SERCOS          0x0c08
#define PCI_CLASS_SERIAL_SMBUS           0x0c05
#define PCI_CLASS_SERIAL_SSA             0x0c02
#define PCI_CLASS_SERIAL_USB             0x0c03
#define PCI_CLASS_SERIAL_USB_DEVICE      0x0c03fe
#define PCI_CLASS_SERIAL_USB_EHCI        0x0c0320
#define PCI_CLASS_SERIAL_USB_OHCI        0x0c0310
#define PCI_CLASS_SERIAL_USB_UHCI        0x0c0300
#define PCI_CLASS_SERIAL_USB_UNKNOWN     0x0c0380
#define PCI_CLASS_SERIAL_USB_XHCI        0x0c0330
#define PCI_CLASS_SP_DPIO                0x1100
#define PCI_CLASS_SP_MANAGEMENT          0x1120
#define PCI_CLASS_SP_OTHER               0x1180
#define PCI_CLASS_SP_PERF                0x1101
#define PCI_CLASS_SP_SYNCH               0x1110
#define PCI_CLASS_STORAGE_ATA            0x0105
#define PCI_CLASS_STORAGE_EXPRESS        0x0108
#define PCI_CLASS_STORAGE_FLOPPY         0x0102
#define PCI_CLASS_STORAGE_IDE            0x0101
#define PCI_CLASS_STORAGE_IPI            0x0103
#define PCI_CLASS_STORAGE_OTHER          0x0180
#define PCI_CLASS_STORAGE_RAID           0x0104
#define PCI_CLASS_STORAGE_SAS            0x0107
#define PCI_CLASS_STORAGE_SATA           0x0106
#define PCI_CLASS_STORAGE_SCSI           0x0100
#define PCI_CLASS_SYSTEM_DMA             0x0801
#define PCI_CLASS_SYSTEM_OTHER           0x0880
#define PCI_CLASS_SYSTEM_PCI_HOTPLUG     0x0804
#define PCI_CLASS_SYSTEM_PIC             0x0800
#define PCI_CLASS_SYSTEM_PIC_IOAPIC      0x080010
#define PCI_CLASS_SYSTEM_PIC_IOXAPIC     0x080020
#define PCI_CLASS_SYSTEM_RTC             0x0803
#define PCI_CLASS_SYSTEM_SDHCI           0x0805
#define PCI_CLASS_SYSTEM_TIMER           0x0802
#define PCI_CLASS_WIRELESS_BLUETOOTH     0x0d11
#define PCI_CLASS_WIRELESS_BROADBAND     0x0d12
#define PCI_CLASS_WIRELESS_CIR           0x0d01
#define PCI_CLASS_WIRELESS_IRDA          0x0d00
#define PCI_CLASS_WIRELESS_OTHER         0x0d80
#define PCI_CLASS_WIRELESS_RF_CONTROLLER 0x0d10
#define PCI_DEVICE_ID_AMD_LANCE          0x2000
#define PCI_DEVICE_ID_AMD_SCSI           0x2020
#define PCI_DEVICE_ID_APPLE_U3_AGP       0x004b
#define PCI_DEVICE_ID_APPLE_UNI_N_AGP    0x0020
#define PCI_DEVICE_ID_CMD_646            0x0646
#define PCI_DEVICE_ID_DEC_21154          0x0026
#define PCI_DEVICE_ID_ENSONIQ_ES1370     0x5000
#define PCI_DEVICE_ID_INTEL_82371AB      0x7111
#define PCI_DEVICE_ID_INTEL_82371AB_0    0x7110
#define PCI_DEVICE_ID_INTEL_82371AB_2    0x7112
#define PCI_DEVICE_ID_INTEL_82371AB_3    0x7113
#define PCI_DEVICE_ID_INTEL_82371SB_0    0x7000
#define PCI_DEVICE_ID_INTEL_82371SB_1    0x7010
#define PCI_DEVICE_ID_INTEL_82371SB_2    0x7020
#define PCI_DEVICE_ID_INTEL_82378        0x0484
#define PCI_DEVICE_ID_INTEL_82441        0x1237
#define PCI_DEVICE_ID_INTEL_82599_SFP_VF 0x10ed
#define PCI_DEVICE_ID_INTEL_82801AA_5    0x2415
#define PCI_DEVICE_ID_INTEL_82801BA_11   0x244e
#define PCI_DEVICE_ID_INTEL_82801D       0x24CD
#define PCI_DEVICE_ID_INTEL_82801I_EHCI1 0x293a
#define PCI_DEVICE_ID_INTEL_82801I_EHCI2 0x293c
#define PCI_DEVICE_ID_INTEL_82801I_UHCI1 0x2934
#define PCI_DEVICE_ID_INTEL_82801I_UHCI2 0x2935
#define PCI_DEVICE_ID_INTEL_82801I_UHCI3 0x2936
#define PCI_DEVICE_ID_INTEL_82801I_UHCI4 0x2937
#define PCI_DEVICE_ID_INTEL_82801I_UHCI5 0x2938
#define PCI_DEVICE_ID_INTEL_82801I_UHCI6 0x2939
#define PCI_DEVICE_ID_INTEL_ESB_9        0x25ab
#define PCI_DEVICE_ID_INTEL_ICH9_0       0x2910
#define PCI_DEVICE_ID_INTEL_ICH9_1       0x2917
#define PCI_DEVICE_ID_INTEL_ICH9_2       0x2912
#define PCI_DEVICE_ID_INTEL_ICH9_3       0x2913
#define PCI_DEVICE_ID_INTEL_ICH9_4       0x2914
#define PCI_DEVICE_ID_INTEL_ICH9_5       0x2919
#define PCI_DEVICE_ID_INTEL_ICH9_6       0x2930
#define PCI_DEVICE_ID_INTEL_ICH9_7       0x2916
#define PCI_DEVICE_ID_INTEL_ICH9_8       0x2918
#define PCI_DEVICE_ID_INTEL_Q35_MCH      0x29c0
#define PCI_DEVICE_ID_LSI_53C810         0x0001
#define PCI_DEVICE_ID_LSI_53C895A        0x0012
#define PCI_DEVICE_ID_LSI_SAS0079        0x0079
#define PCI_DEVICE_ID_LSI_SAS1068        0x0054
#define PCI_DEVICE_ID_LSI_SAS1078        0x0060
#define PCI_DEVICE_ID_MOTOROLA_MPC106    0x0002
#define PCI_DEVICE_ID_MOTOROLA_RAVEN     0x4801
#define PCI_DEVICE_ID_MPC8533E           0x0030
#define PCI_DEVICE_ID_NEC_UPD720200      0x0194
#define PCI_DEVICE_ID_REALTEK_8139       0x8139
#define PCI_DEVICE_ID_SUN_EBUS           0x1000
#define PCI_DEVICE_ID_SUN_SABRE          0xa000
#define PCI_DEVICE_ID_SUN_SIMBA          0x5000
#define PCI_DEVICE_ID_TEWS_TPCI200       0x30C8
#define PCI_DEVICE_ID_VIA_AC97           0x3058
#define PCI_DEVICE_ID_VIA_ACPI           0x3057
#define PCI_DEVICE_ID_VIA_IDE            0x0571
#define PCI_DEVICE_ID_VIA_ISA_BRIDGE     0x0686
#define PCI_DEVICE_ID_VIA_MC97           0x3068
#define PCI_DEVICE_ID_VIA_UHCI           0x3038
#define PCI_DEVICE_ID_XEN_PLATFORM       0x0001
#define PCI_VENDOR_ID_AMD                0x1022
#define PCI_VENDOR_ID_APPLE              0x106b
#define PCI_VENDOR_ID_CHELSIO            0x1425
#define PCI_VENDOR_ID_CIRRUS             0x1013
#define PCI_VENDOR_ID_CMD                0x1095
#define PCI_VENDOR_ID_DEC                0x1011
#define PCI_VENDOR_ID_ENSONIQ            0x1274
#define PCI_VENDOR_ID_FREESCALE          0x1957
#define PCI_VENDOR_ID_IBM                0x1014
#define PCI_VENDOR_ID_INTEL              0x8086
#define PCI_VENDOR_ID_LSI_LOGIC          0x1000
#define PCI_VENDOR_ID_MARVELL            0x11ab
#define PCI_VENDOR_ID_MOTOROLA           0x1057
#define PCI_VENDOR_ID_NEC                0x1033
#define PCI_VENDOR_ID_REALTEK            0x10ec
#define PCI_VENDOR_ID_SUN                0x108e
#define PCI_VENDOR_ID_TEWS               0x1498
#define PCI_VENDOR_ID_TI                 0x104c
#define PCI_VENDOR_ID_VIA                0x1106
#define PCI_VENDOR_ID_XEN                0x5853
#define PCI_VENDOR_ID_XILINX             0x10ee
#define COMPAT_PROP_PCP "power_controller_present"


#define HOTPLUG_HANDLER(obj) \
     INTERFACE_CHECK(HotplugHandler, (obj), TYPE_HOTPLUG_HANDLER)
#define HOTPLUG_HANDLER_CLASS(klass) \
     OBJECT_CLASS_CHECK(HotplugHandlerClass, (klass), TYPE_HOTPLUG_HANDLER)
#define HOTPLUG_HANDLER_GET_CLASS(obj) \
     OBJECT_GET_CLASS(HotplugHandlerClass, (obj), TYPE_HOTPLUG_HANDLER)
#define TYPE_HOTPLUG_HANDLER "hotplug-handler"
#define PCIE_AER_ERR_HEADER_VALID       0x4     
#define PCIE_AER_ERR_IS_CORRECTABLE     0x1     
#define PCIE_AER_ERR_MAYBE_ADVISORY     0x2     
#define PCIE_AER_ERR_TLP_PREFIX_PRESENT 0x8     
#define PCIE_AER_LOG_MAX_DEFAULT        8
#define PCIE_AER_LOG_MAX_LIMIT          128

#define PCI_ARI_SIZEOF                  8
#define PCI_ARI_VER                     1
#define PCI_ERR_CAP_FEP_MASK            0x0000001f
#define PCI_ERR_CAP_MHRC                0x00000200
#define PCI_ERR_CAP_MHRE                0x00000400
#define PCI_ERR_CAP_TLP                 0x00000800
#define PCI_ERR_COR_ADV_NONFATAL        0x00002000      
#define PCI_ERR_COR_HL_OVERFLOW         0x00008000      
#define PCI_ERR_COR_INTERNAL            0x00004000      
#define PCI_ERR_COR_MASK_DEFAULT        (PCI_ERR_COR_ADV_NONFATAL |     \
                                         PCI_ERR_COR_INTERNAL |         \
                                         PCI_ERR_COR_HL_OVERFLOW)
#define PCI_ERR_COR_SUPPORTED           (PCI_ERR_COR_RCVR |             \
                                         PCI_ERR_COR_BAD_TLP |          \
                                         PCI_ERR_COR_BAD_DLLP |         \
                                         PCI_ERR_COR_REP_ROLL |         \
                                         PCI_ERR_COR_REP_TIMER |        \
                                         PCI_ERR_COR_ADV_NONFATAL |     \
                                         PCI_ERR_COR_INTERNAL |         \
                                         PCI_ERR_COR_HL_OVERFLOW)
#define PCI_ERR_HEADER_LOG_SIZE         16
#define PCI_ERR_ROOT_CMD_EN_MASK        (PCI_ERR_ROOT_CMD_COR_EN |      \
                                         PCI_ERR_ROOT_CMD_NONFATAL_EN | \
                                         PCI_ERR_ROOT_CMD_FATAL_EN)
#define PCI_ERR_ROOT_IRQ                0xf8000000
#define PCI_ERR_ROOT_IRQ_MAX            32
#define PCI_ERR_ROOT_IRQ_SHIFT          ctz32(PCI_ERR_ROOT_IRQ)
#define PCI_ERR_ROOT_STATUS_REPORT_MASK (PCI_ERR_ROOT_COR_RCV |         \
                                         PCI_ERR_ROOT_MULTI_COR_RCV |   \
                                         PCI_ERR_ROOT_UNCOR_RCV |       \
                                         PCI_ERR_ROOT_MULTI_UNCOR_RCV | \
                                         PCI_ERR_ROOT_FIRST_FATAL |     \
                                         PCI_ERR_ROOT_NONFATAL_RCV |    \
                                         PCI_ERR_ROOT_FATAL_RCV)
#define PCI_ERR_SIZEOF                  0x48
#define PCI_ERR_TLP_PREFIX_LOG          0x38
#define PCI_ERR_TLP_PREFIX_LOG_SIZE     16
#define PCI_ERR_UNC_ACSV                0x00200000      
#define PCI_ERR_UNC_ATOP_EBLOCKED       0x01000000      
#define PCI_ERR_UNC_INTN                0x00400000      
#define PCI_ERR_UNC_MCBTLP              0x00800000      
#define PCI_ERR_UNC_SDN                 0x00000020      
#define PCI_ERR_UNC_SEVERITY_DEFAULT    (PCI_ERR_UNC_DLP |              \
                                         PCI_ERR_UNC_SDN |              \
                                         PCI_ERR_UNC_FCP |              \
                                         PCI_ERR_UNC_RX_OVER |          \
                                         PCI_ERR_UNC_MALF_TLP |         \
                                         PCI_ERR_UNC_INTN)
#define PCI_ERR_UNC_SUPPORTED           (PCI_ERR_UNC_DLP |              \
                                         PCI_ERR_UNC_SDN |              \
                                         PCI_ERR_UNC_POISON_TLP |       \
                                         PCI_ERR_UNC_FCP |              \
                                         PCI_ERR_UNC_COMP_TIME |        \
                                         PCI_ERR_UNC_COMP_ABORT |       \
                                         PCI_ERR_UNC_UNX_COMP |         \
                                         PCI_ERR_UNC_RX_OVER |          \
                                         PCI_ERR_UNC_MALF_TLP |         \
                                         PCI_ERR_UNC_ECRC |             \
                                         PCI_ERR_UNC_UNSUP |            \
                                         PCI_ERR_UNC_ACSV |             \
                                         PCI_ERR_UNC_INTN |             \
                                         PCI_ERR_UNC_MCBTLP |           \
                                         PCI_ERR_UNC_ATOP_EBLOCKED |    \
                                         PCI_ERR_UNC_TLP_PRF_BLOCKED)
#define PCI_ERR_UNC_TLP_PRF_BLOCKED     0x02000000      
#define PCI_ERR_VER                     2
#define PCI_EXP_DEVCAP2_EETLPP          0x200000
#define PCI_EXP_DEVCAP2_EFF             0x100000
#define PCI_EXP_DEVCTL2_EETLPPB         0x8000
#define PCI_EXP_FLAGS_IRQ_SHIFT         ctz32(PCI_EXP_FLAGS_IRQ)
#define PCI_EXP_FLAGS_TYPE_SHIFT        ctz32(PCI_EXP_FLAGS_TYPE)
#define PCI_EXP_FLAGS_VER1              1
#define PCI_EXP_FLAGS_VER2              2
#define PCI_EXP_LNKCAP_ASPMS_0S         (1 << PCI_EXP_LNKCAP_ASPMS_SHIFT)
#define PCI_EXP_LNKCAP_ASPMS_SHIFT      ctz32(PCI_EXP_LNKCAP_ASPMS)
#define PCI_EXP_LNKCAP_PN_SHIFT         ctz32(PCI_EXP_LNKCAP_PN)
#define PCI_EXP_LNK_LS_25               1
#define PCI_EXP_LNK_MLW_1               (1 << PCI_EXP_LNK_MLW_SHIFT)
#define PCI_EXP_LNK_MLW_SHIFT           ctz32(PCI_EXP_LNKCAP_MLW)
#define PCI_EXP_SLTCAP_PSN_SHIFT        ctz32(PCI_EXP_SLTCAP_PSN)
#define PCI_EXP_SLTCTL_AIC_OFF                          \
    (PCI_EXP_SLTCTL_IND_OFF << PCI_EXP_SLTCTL_AIC_SHIFT)
#define PCI_EXP_SLTCTL_AIC_SHIFT        ctz32(PCI_EXP_SLTCTL_AIC)
#define PCI_EXP_SLTCTL_IND_BLINK        0x2
#define PCI_EXP_SLTCTL_IND_OFF          0x3
#define PCI_EXP_SLTCTL_IND_ON           0x1
#define PCI_EXP_SLTCTL_IND_RESERVED     0x0
#define PCI_EXP_SLTCTL_PIC_OFF                          \
    (PCI_EXP_SLTCTL_IND_OFF << PCI_EXP_SLTCTL_PIC_SHIFT)
#define PCI_EXP_SLTCTL_PIC_ON                          \
    (PCI_EXP_SLTCTL_IND_ON << PCI_EXP_SLTCTL_PIC_SHIFT)
#define PCI_EXP_SLTCTL_PIC_SHIFT        ctz32(PCI_EXP_SLTCTL_PIC)
#define PCI_EXP_SLTCTL_SUPPORTED        \
            (PCI_EXP_SLTCTL_ABPE |      \
             PCI_EXP_SLTCTL_PDCE |      \
             PCI_EXP_SLTCTL_CCIE |      \
             PCI_EXP_SLTCTL_HPIE |      \
             PCI_EXP_SLTCTL_AIC |       \
             PCI_EXP_SLTCTL_PCC |       \
             PCI_EXP_SLTCTL_EIC)
#define PCI_EXP_VER1_SIZEOF             0x14 
#define PCI_EXP_VER2_SIZEOF             0x3c 
#define PCI_EXT_CAP(id, ver, next)                                      \
    ((id) |                                                             \
     ((ver) << PCI_EXT_CAP_VER_SHIFT) |                                 \
     ((next) << PCI_EXT_CAP_NEXT_SHIFT))
#define PCI_EXT_CAP_ALIGN               4
#define PCI_EXT_CAP_ALIGNUP(x)                                  \
    (((x) + PCI_EXT_CAP_ALIGN - 1) & ~(PCI_EXT_CAP_ALIGN - 1))
#define PCI_EXT_CAP_NEXT_MASK           (0xffc << PCI_EXT_CAP_NEXT_SHIFT)
#define PCI_EXT_CAP_NEXT_SHIFT          20
#define PCI_EXT_CAP_VER_SHIFT           16
#define PCI_SEC_STATUS_RCV_SYSTEM_ERROR         0x4000

#define APPLESMC_MAX_DATA_LENGTH       32
#define APPLESMC_PROP_IO_BASE "iobase"

#define ISADMA(obj) \
    INTERFACE_CHECK(IsaDma, (obj), TYPE_ISADMA)
#define ISADMA_CLASS(klass) \
    OBJECT_CLASS_CHECK(IsaDmaClass, (klass), TYPE_ISADMA)
#define ISADMA_GET_CLASS(obj) \
    OBJECT_GET_CLASS(IsaDmaClass, (obj), TYPE_ISADMA)
#define ISA_BUS(obj) OBJECT_CHECK(ISABus, (obj), TYPE_ISA_BUS)
#define ISA_DEVICE(obj) \
     OBJECT_CHECK(ISADevice, (obj), TYPE_ISA_DEVICE)
#define ISA_DEVICE_CLASS(klass) \
     OBJECT_CLASS_CHECK(ISADeviceClass, (klass), TYPE_ISA_DEVICE)
#define ISA_DEVICE_GET_CLASS(obj) \
     OBJECT_GET_CLASS(ISADeviceClass, (obj), TYPE_ISA_DEVICE)
#define ISA_NUM_IRQS 16
#define TYPE_APPLE_SMC "isa-applesmc"
#define TYPE_ISADMA "isa-dma"
#define TYPE_ISA_BUS "ISA"
#define TYPE_ISA_DEVICE "isa-device"

#define DEFINE_PROP(_name, _state, _field, _prop, _type) { \
        .name      = (_name),                                    \
        .info      = &(_prop),                                   \
        .offset    = offsetof(_state, _field)                    \
            + type_check(_type, typeof_field(_state, _field)),   \
        }
#define DEFINE_PROP_ARRAY(_name, _state, _field,                        \
                          _arrayfield, _arrayprop, _arraytype) {        \
        .name = (PROP_ARRAY_LEN_PREFIX _name),                          \
        .info = &(qdev_prop_arraylen),                                  \
        .offset = offsetof(_state, _field)                              \
            + type_check(uint32_t, typeof_field(_state, _field)),       \
        .qtype = QTYPE_QINT,                                            \
        .arrayinfo = &(_arrayprop),                                     \
        .arrayfieldsize = sizeof(_arraytype),                           \
        .arrayoffset = offsetof(_state, _arrayfield),                   \
        }
#define DEFINE_PROP_BIOS_CHS_TRANS(_n, _s, _f, _d) \
    DEFINE_PROP_DEFAULT(_n, _s, _f, _d, qdev_prop_bios_chs_trans, int)
#define DEFINE_PROP_BIT(_name, _state, _field, _bit, _defval) {  \
        .name      = (_name),                                    \
        .info      = &(qdev_prop_bit),                           \
        .bitnr    = (_bit),                                      \
        .offset    = offsetof(_state, _field)                    \
            + type_check(uint32_t,typeof_field(_state, _field)), \
        .qtype     = QTYPE_QBOOL,                                \
        .defval    = (bool)_defval,                              \
        }
#define DEFINE_PROP_BIT64(_name, _state, _field, _bit, _defval) {       \
        .name      = (_name),                                           \
        .info      = &(qdev_prop_bit64),                                \
        .bitnr    = (_bit),                                             \
        .offset    = offsetof(_state, _field)                           \
            + type_check(uint64_t, typeof_field(_state, _field)),       \
        .qtype     = QTYPE_QBOOL,                                       \
        .defval    = (bool)_defval,                                     \
        }
#define DEFINE_PROP_BLOCKDEV_ON_ERROR(_n, _s, _f, _d) \
    DEFINE_PROP_DEFAULT(_n, _s, _f, _d, qdev_prop_blockdev_on_error, \
                        BlockdevOnError)
#define DEFINE_PROP_BLOCKSIZE(_n, _s, _f) \
    DEFINE_PROP_DEFAULT(_n, _s, _f, 0, qdev_prop_blocksize, uint16_t)
#define DEFINE_PROP_BOOL(_name, _state, _field, _defval) {       \
        .name      = (_name),                                    \
        .info      = &(qdev_prop_bool),                          \
        .offset    = offsetof(_state, _field)                    \
            + type_check(bool, typeof_field(_state, _field)),    \
        .qtype     = QTYPE_QBOOL,                                \
        .defval    = (bool)_defval,                              \
        }
#define DEFINE_PROP_CHR(_n, _s, _f)             \
    DEFINE_PROP(_n, _s, _f, qdev_prop_chr, CharBackend)
#define DEFINE_PROP_DEFAULT(_name, _state, _field, _defval, _prop, _type) { \
        .name      = (_name),                                           \
        .info      = &(_prop),                                          \
        .offset    = offsetof(_state, _field)                           \
            + type_check(_type,typeof_field(_state, _field)),           \
        .qtype     = QTYPE_QINT,                                        \
        .defval    = (_type)_defval,                                    \
        }
#define DEFINE_PROP_DRIVE(_n, _s, _f) \
    DEFINE_PROP(_n, _s, _f, qdev_prop_drive, BlockBackend *)
#define DEFINE_PROP_END_OF_LIST()               \
    {}
#define DEFINE_PROP_INT32(_n, _s, _f, _d)                      \
    DEFINE_PROP_DEFAULT(_n, _s, _f, _d, qdev_prop_int32, int32_t)
#define DEFINE_PROP_LOSTTICKPOLICY(_n, _s, _f, _d) \
    DEFINE_PROP_DEFAULT(_n, _s, _f, _d, qdev_prop_losttickpolicy, \
                        LostTickPolicy)
#define DEFINE_PROP_MACADDR(_n, _s, _f)         \
    DEFINE_PROP(_n, _s, _f, qdev_prop_macaddr, MACAddr)
#define DEFINE_PROP_NETDEV(_n, _s, _f)             \
    DEFINE_PROP(_n, _s, _f, qdev_prop_netdev, NICPeers)
#define DEFINE_PROP_ON_OFF_AUTO(_n, _s, _f, _d) \
    DEFINE_PROP_DEFAULT(_n, _s, _f, _d, qdev_prop_on_off_auto, OnOffAuto)
#define DEFINE_PROP_PCI_DEVFN(_n, _s, _f, _d)                   \
    DEFINE_PROP_DEFAULT(_n, _s, _f, _d, qdev_prop_pci_devfn, int32_t)
#define DEFINE_PROP_PCI_HOST_DEVADDR(_n, _s, _f) \
    DEFINE_PROP(_n, _s, _f, qdev_prop_pci_host_devaddr, PCIHostDeviceAddress)
#define DEFINE_PROP_PTR(_n, _s, _f)             \
    DEFINE_PROP(_n, _s, _f, qdev_prop_ptr, void*)
#define DEFINE_PROP_SIZE(_n, _s, _f, _d)                       \
    DEFINE_PROP_DEFAULT(_n, _s, _f, _d, qdev_prop_size, uint64_t)
#define DEFINE_PROP_STRING(_n, _s, _f)             \
    DEFINE_PROP(_n, _s, _f, qdev_prop_string, char*)
#define DEFINE_PROP_UINT16(_n, _s, _f, _d)                      \
    DEFINE_PROP_DEFAULT(_n, _s, _f, _d, qdev_prop_uint16, uint16_t)
#define DEFINE_PROP_UINT32(_n, _s, _f, _d)                      \
    DEFINE_PROP_DEFAULT(_n, _s, _f, _d, qdev_prop_uint32, uint32_t)
#define DEFINE_PROP_UINT64(_n, _s, _f, _d)                      \
    DEFINE_PROP_DEFAULT(_n, _s, _f, _d, qdev_prop_uint64, uint64_t)
#define DEFINE_PROP_UINT8(_n, _s, _f, _d)                       \
    DEFINE_PROP_DEFAULT(_n, _s, _f, _d, qdev_prop_uint8, uint8_t)
#define DEFINE_PROP_VLAN(_n, _s, _f)             \
    DEFINE_PROP(_n, _s, _f, qdev_prop_vlan, NICPeers)
#define PROP_ARRAY_LEN_PREFIX "len-"

#define BUS(obj) OBJECT_CHECK(BusState, (obj), TYPE_BUS)
#define BUS_CLASS(klass) OBJECT_CLASS_CHECK(BusClass, (klass), TYPE_BUS)
#define BUS_GET_CLASS(obj) OBJECT_GET_CLASS(BusClass, (obj), TYPE_BUS)
#define DEVICE(obj) OBJECT_CHECK(DeviceState, (obj), TYPE_DEVICE)
#define DEVICE_CLASS(klass) OBJECT_CLASS_CHECK(DeviceClass, (klass), TYPE_DEVICE)
#define DEVICE_GET_CLASS(obj) OBJECT_GET_CLASS(DeviceClass, (obj), TYPE_DEVICE)

#define QDEV_HOTPLUG_HANDLER_PROPERTY "hotplug-handler"
#define TYPE_BUS "bus"
#define TYPE_DEVICE "device"
#define BITMAP_FIRST_WORD_MASK(start) (~0UL << ((start) & (BITS_PER_LONG - 1)))

#define BITMAP_LAST_WORD_MASK(nbits) (~0UL >> (-(nbits) & (BITS_PER_LONG - 1)))
#define DECLARE_BITMAP(name,bits)                  \
        unsigned long name[BITS_TO_LONGS(bits)]
#define small_nbits(nbits)                      \
        ((nbits) <= BITS_PER_LONG)
#define BIT(nr)                 (1UL << (nr))

#define BITS_PER_BYTE           CHAR_BIT
#define BITS_PER_LONG           (sizeof (unsigned long) * BITS_PER_BYTE)
#define BITS_TO_LONGS(nr)       DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))
#define BIT_MASK(nr)            (1UL << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr)            ((nr) / BITS_PER_LONG)
#define MAKE_64BIT_MASK(shift, length) \
    (((~0ULL) >> (64 - (length))) << (shift))
#define IOPORTS_MASK    (MAX_IOPORTS - 1)

#define MAX_IOPORTS     (64 * 1024)
#define PORTIO_END_OF_LIST() { }
#define DEFINE_LDST_DMA(_lname, _sname, _bits, _end) \
    static inline uint##_bits##_t ld##_lname##_##_end##_dma(AddressSpace *as, \
                                                            dma_addr_t addr) \
    {                                                                   \
        uint##_bits##_t val;                                            \
        dma_memory_read(as, addr, &val, (_bits) / 8);                   \
        return _end##_bits##_to_cpu(val);                               \
    }                                                                   \
    static inline void st##_sname##_##_end##_dma(AddressSpace *as,      \
                                                 dma_addr_t addr,       \
                                                 uint##_bits##_t val)   \
    {                                                                   \
        val = cpu_to_##_end##_bits(val);                                \
        dma_memory_write(as, addr, &val, (_bits) / 8);                  \
    }
#define DMA_ADDR_BITS 64
#define DMA_ADDR_FMT "%" PRIx64



#define BDRV_BLOCK_ALLOCATED    0x10
#define BDRV_BLOCK_DATA         0x01
#define BDRV_BLOCK_OFFSET_MASK  BDRV_SECTOR_MASK
#define BDRV_BLOCK_OFFSET_VALID 0x04
#define BDRV_BLOCK_RAW          0x08
#define BDRV_BLOCK_ZERO         0x02
#define BDRV_OPT_CACHE_DIRECT   "cache.direct"
#define BDRV_OPT_CACHE_NO_FLUSH "cache.no-flush"
#define BDRV_OPT_CACHE_WB       "cache.writeback"
#define BDRV_OPT_DISCARD        "discard"
#define BDRV_OPT_READ_ONLY      "read-only"
#define BDRV_O_ALLOW_RDWR  0x2000  
#define BDRV_O_CACHE_MASK  (BDRV_O_NOCACHE | BDRV_O_NO_FLUSH)
#define BDRV_O_CHECK       0x1000  
#define BDRV_O_COPY_ON_READ 0x0400 
#define BDRV_O_INACTIVE    0x0800  
#define BDRV_O_NATIVE_AIO  0x0080 
#define BDRV_O_NOCACHE     0x0020 
#define BDRV_O_NO_BACKING  0x0100 
#define BDRV_O_NO_FLUSH    0x0200 
#define BDRV_O_NO_IO       0x10000 
#define BDRV_O_PROTOCOL    0x8000  
#define BDRV_O_RDWR        0x0002
#define BDRV_O_RESIZE      0x0004 
#define BDRV_O_SNAPSHOT    0x0008 
#define BDRV_O_TEMPORARY   0x0010 
#define BDRV_O_UNMAP       0x4000  
#define BDRV_POLL_WHILE(bs, cond) ({                       \
    bool waited_ = false;                                  \
    BlockDriverState *bs_ = (bs);                          \
    AioContext *ctx_ = bdrv_get_aio_context(bs_);          \
    if (aio_context_in_iothread(ctx_)) {                   \
        while ((cond)) {                                   \
            aio_poll(ctx_, true);                          \
            waited_ = true;                                \
        }                                                  \
    } else {                                               \
        assert(qemu_get_current_aio_context() ==           \
               qemu_get_aio_context());                    \
                                                        \
        assert(!bs_->wakeup);                              \
        bs_->wakeup = true;                                \
        while ((cond)) {                                   \
            aio_context_release(ctx_);                     \
            aio_poll(qemu_get_aio_context(), true);        \
            aio_context_acquire(ctx_);                     \
            waited_ = true;                                \
        }                                                  \
        bs_->wakeup = false;                               \
    }                                                      \
    waited_; })
#define BDRV_REQUEST_MAX_BYTES (BDRV_REQUEST_MAX_SECTORS << BDRV_SECTOR_BITS)
#define BDRV_REQUEST_MAX_SECTORS MIN(SIZE_MAX >> BDRV_SECTOR_BITS, \
                                     INT_MAX >> BDRV_SECTOR_BITS)
#define BDRV_SECTOR_BITS   9
#define BDRV_SECTOR_MASK   ~(BDRV_SECTOR_SIZE - 1)
#define BDRV_SECTOR_SIZE   (1ULL << BDRV_SECTOR_BITS)
#define BLKDBG_EVENT(child, evt) \
    do { \
        if (child) { \
            bdrv_debug_event(child->bs, evt); \
        } \
    } while (0)

#define BITS_PER_LEVEL         (BITS_PER_LONG == 32 ? 5 : 6)

#define HBITMAP_LEVELS         ((HBITMAP_LOG_MAX_SIZE / BITS_PER_LEVEL) + 1)
#define HBITMAP_LOG_MAX_SIZE   (BITS_PER_LONG == 32 ? 34 : 41)



#define iov_recv(sockfd, iov, iov_cnt, offset, bytes) \
  iov_send_recv(sockfd, iov, iov_cnt, offset, bytes, false)
#define iov_send(sockfd, iov, iov_cnt, offset, bytes) \
  iov_send_recv(sockfd, iov, iov_cnt, offset, bytes, true)

#define ARRAY_SIZE(x) ((sizeof(x) / sizeof((x)[0])) + \
                       QEMU_BUILD_BUG_ON_ZERO(!QEMU_IS_ARRAY(x)))
#define BUS_MCEERR_AO 5
#define BUS_MCEERR_AR 4
#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#define ECANCELED 4097
#define EMEDIUMTYPE 4098
#define ENOMEDIUM ENODEV
#define ENOTSUP 4096
#define ESHUTDOWN 4099
#define FMT_pid "%ld"
# define HOST_LONG_BITS 32
#define IOV_MAX 1024
#define MAP_ANONYMOUS MAP_ANON
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MIN_NON_ZERO(a, b) ((a) == 0 ? (b) : \
                                ((b) == 0 ? (a) : (MIN(a, b))))
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
#define QEMU_MADV_UNMERGEABLE MADV_UNMERGEABLE
#define QEMU_MADV_WILLNEED  MADV_WILLNEED

#define QEMU_PTR_IS_ALIGNED(p, n) QEMU_IS_ALIGNED((uintptr_t)(p), (n))
#  define QEMU_VMALLOC_ALIGN (512 * 4096)
#define ROUND_UP(n,d) (((n) + (d) - 1) & -(d))
#define SIZE_MAX ((size_t)-1)
#define TIME_MAX LONG_MAX
#define WEXITSTATUS(x) (x)
#define WIFEXITED(x)   1



#define daemon qemu_fake_daemon_function
#define qemu_timersub timersub

#define CompatGCond GCond
#define CompatGMutex GMutex
#define G_TIME_SPAN_SECOND              (G_GINT64_CONSTANT(1000000))

#define g_assert_cmpmem(m1, l1, m2, l2)                                        \
    do {                                                                       \
        gconstpointer __m1 = m1, __m2 = m2;                                    \
        int __l1 = l1, __l2 = l2;                                              \
        if (__l1 != __l2) {                                                    \
            g_assertion_message_cmpnum(                                        \
                G_LOG_DOMAIN, "__FILE__", "__LINE__", G_STRFUNC,                   \
                #l1 " (len(" #m1 ")) == " #l2 " (len(" #m2 "))", __l1, "==",   \
                __l2, 'i');                                                    \
        } else if (memcmp(__m1, __m2, __l1) != 0) {                            \
            g_assertion_message(G_LOG_DOMAIN, "__FILE__", "__LINE__", G_STRFUNC,   \
                                "assertion failed (" #m1 " == " #m2 ")");      \
        }                                                                      \
    } while (0)
#define g_assert_false(expr)                                                   \
    do {                                                                       \
        if (G_LIKELY(!(expr))) {                                               \
        } else {                                                               \
            g_assertion_message(G_LOG_DOMAIN, "__FILE__", "__LINE__", G_STRFUNC,   \
                                "'" #expr "' should be FALSE");                \
        }                                                                      \
    } while (0)
#define g_assert_nonnull(expr)                                                 \
    do {                                                                       \
        if (G_LIKELY((expr) != NULL)) {                                        \
        } else {                                                               \
            g_assertion_message(G_LOG_DOMAIN, "__FILE__", "__LINE__", G_STRFUNC,   \
                                "'" #expr "' should not be NULL");             \
        }                                                                      \
    } while (0)
#define g_assert_null(expr)                                                    \
    do {                                                                       \
        if (G_LIKELY((expr) == NULL)) {                                        \
        } else {                                                               \
            g_assertion_message(G_LOG_DOMAIN, "__FILE__", "__LINE__", G_STRFUNC,   \
                                "'" #expr "' should be NULL");                 \
        }                                                                      \
    } while (0)
#define g_assert_true(expr)                                                    \
    do {                                                                       \
        if (G_LIKELY(expr)) {                                                  \
        } else {                                                               \
            g_assertion_message(G_LOG_DOMAIN, "__FILE__", "__LINE__", G_STRFUNC,   \
                                "'" #expr "' should be TRUE");                 \
        }                                                                      \
    } while (0)
#define g_dir_make_tmp(tmpl, error) qemu_g_dir_make_tmp(tmpl, error)
#define g_get_monotonic_time() qemu_g_get_monotonic_time()
#define g_poll(fds, nfds, timeout) g_poll_fixed(fds, nfds, timeout)
#define g_test_initialized() (0)
#define g_test_subprocess() (0)

# define UTIME_NOW     ((1l << 30) - 1l)
# define UTIME_OMIT    ((1l << 30) - 2l)
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
#  define GCC_FMT_ATTR(n, m) __attribute__((format(printf, n, m)))
#define QEMU_ALIGNED(X) __attribute__((aligned(X)))
#define QEMU_ARTIFICIAL __attribute__((always_inline, artificial))
#define QEMU_BUILD_BUG_ON(x) typedef QEMU_BUILD_BUG_ON_STRUCT(x) \
    glue(qemu_build_bug_on__, __COUNTER__) __attribute__((unused))
#define QEMU_BUILD_BUG_ON_STRUCT(x) \
    struct { \
        int:(x) ? -1 : 1; \
    }
#define QEMU_BUILD_BUG_ON_ZERO(x) (sizeof(QEMU_BUILD_BUG_ON_STRUCT(x)) - \
                                   sizeof(QEMU_BUILD_BUG_ON_STRUCT(x)))
# define QEMU_GNUC_PREREQ(maj, min) \
         (("__GNUC__" << 16) + "__GNUC_MINOR__" >= ((maj) << 16) + (min))
#define QEMU_NORETURN __attribute__ ((__noreturn__))
# define QEMU_PACKED __attribute__((gcc_struct, packed))
#define QEMU_SENTINEL __attribute__((sentinel))
#define QEMU_STATIC_ANALYSIS 1
#define QEMU_WARN_UNUSED_RESULT __attribute__((warn_unused_result))
#define __builtin_expect(x, n) (x)
#   define __printf__ __gnu_printf__
#define container_of(ptr, type, member) ({                      \
        const typeof(((type *) 0)->member) *__mptr = (ptr);     \
        (type *) ((char *) __mptr - offsetof(type, member));})
#define glue(x, y) xglue(x, y)
#define likely(x)   __builtin_expect(!!(x), 1)
#define stringify(s)	tostring(s)
#define tostring(s)	#s
#define type_check(t1,t2) ((t1*)0 - (t2*)0)
#define typeof_field(type, field) typeof(((type *)0)->field)
#define unlikely(x)   __builtin_expect(!!(x), 0)
#define xglue(x, y) x ## y

