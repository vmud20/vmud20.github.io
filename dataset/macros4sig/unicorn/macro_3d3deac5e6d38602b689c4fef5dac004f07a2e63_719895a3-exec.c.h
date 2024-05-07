
#include<stdint.h>
#include<errno.h>


#include<stddef.h>

#include<unistd.h>
#include<ctype.h>
#include<stdlib.h>
#include<stdarg.h>
#include<pthread.h>
#include<sys/timeb.h>

#include<setjmp.h>


#include<math.h>







#include<sys/types.h>
#include<string.h>

#include<fcntl.h>




#include<sys/stat.h>
#include<inttypes.h>



#include<sys/signal.h>


#include<linux/falloc.h>


#include<sys/mman.h>
#include<stdbool.h>

#include<limits.h>




#include<semaphore.h>

#include<time.h>


#include<signal.h>
#include<float.h>
#include<assert.h>





#include<stdio.h>

#include<sys/wait.h>
#include<sys/shm.h>


















#include<sys/time.h>
#define ARR_SIZE(a) (sizeof(a) / sizeof(a[0]))
#define HOOK_BOUND_CHECK(hh, addr)                                             \
    ((((addr) >= (hh)->begin && (addr) <= (hh)->end) ||                        \
      (hh)->begin > (hh)->end) &&                                              \
     !((hh)->to_delete))
#define HOOK_EXISTS(uc, idx) ((uc)->hook[idx##_IDX].head != NULL)
#define HOOK_EXISTS_BOUNDED(uc, idx, addr)                                     \
    _hook_exists_bounded((uc)->hook[idx##_IDX].head, addr)
#define HOOK_FOREACH(uc, hh, idx)                                              \
    for (cur = (uc)->hook[idx##_IDX].head;                                     \
         cur != NULL && ((hh) = (struct hook *)cur->data); cur = cur->next)
#define HOOK_FOREACH_VAR_DECLARE struct list_item *cur
#define MEM_BLOCK_INCR 32
#define READ_BYTE_H(x) ((x & 0xffff) >> 8)
#define READ_BYTE_L(x) (x & 0xff)
#define READ_DWORD(x) (x & 0xffffffff)
#define READ_QWORD(x) ((uint64_t)x)
#define READ_WORD(x) (x & 0xffff)
#define UC_HOOK_FLAG_MASK (~(UC_HOOK_IDX_MASK))
#define UC_HOOK_FLAG_NO_STOP                                                   \
    (1 << 6) 
#define UC_HOOK_IDX_MASK ((1 << 6) - 1)
#define UC_MAX_NESTED_LEVEL (64)
#define UC_MODE_ARM_MASK                                                       \
    (UC_MODE_ARM | UC_MODE_THUMB | UC_MODE_LITTLE_ENDIAN | UC_MODE_MCLASS |    \
     UC_MODE_ARM926 | UC_MODE_ARM946 | UC_MODE_ARM1176 | UC_MODE_BIG_ENDIAN |  \
     UC_MODE_ARMBE8)
#define UC_MODE_M68K_MASK (UC_MODE_BIG_ENDIAN)
#define UC_MODE_MIPS_MASK                                                      \
    (UC_MODE_MIPS32 | UC_MODE_MIPS64 | UC_MODE_LITTLE_ENDIAN |                 \
     UC_MODE_BIG_ENDIAN)
#define UC_MODE_PPC_MASK (UC_MODE_PPC32 | UC_MODE_PPC64 | UC_MODE_BIG_ENDIAN)
#define UC_MODE_RISCV_MASK                                                     \
    (UC_MODE_RISCV32 | UC_MODE_RISCV64 | UC_MODE_LITTLE_ENDIAN)
#define UC_MODE_S390X_MASK (UC_MODE_BIG_ENDIAN)
#define UC_MODE_SPARC_MASK                                                     \
    (UC_MODE_SPARC32 | UC_MODE_SPARC64 | UC_MODE_BIG_ENDIAN)
#define UC_MODE_X86_MASK                                                       \
    (UC_MODE_16 | UC_MODE_32 | UC_MODE_64 | UC_MODE_LITTLE_ENDIAN)

#define UC_TB_COPY(uc_tb, tb)                                                  \
    do {                                                                       \
        (uc_tb)->pc = tb->pc;                                                  \
        (uc_tb)->icount = tb->icount;                                          \
        (uc_tb)->size = tb->size;                                              \
    } while (0)
#define UC_TRACE_END(loc, fmt, ...)                                            \
    trace_end(get_tracer(), loc, fmt, __VA_ARGS__)
#define UC_TRACE_START(loc) trace_start(get_tracer(), loc)
#define WRITE_BYTE_H(x, b) (x = (x & ~0xff00) | ((b & 0xff) << 8))
#define WRITE_BYTE_L(x, b) (x = (x & ~0xff) | (b & 0xff))
#define WRITE_DWORD(x, w) (x = (x & ~0xffffffffLL) | (w & 0xffffffff))
#define WRITE_WORD(x, w) (x = (x & ~0xffff) | (w & 0xffff))

#define INT16_MAX 32767i16
#define INT16_MIN (-32767i16 - 1)
#define INT32_MAX 2147483647i32
#define INT32_MIN (-2147483647i32 - 1)
#define INT64_MAX 9223372036854775807i64
#define INT64_MIN (-9223372036854775807i64 - 1)
#define INT8_MAX 127i8
#define INT8_MIN (-127i8 - 1)
#define INTPTR_MAX INT64_MAX
#define INTPTR_MIN INT64_MIN
#define INT_FAST16_MAX INT32_MAX
#define INT_FAST16_MIN INT32_MIN
#define INT_FAST32_MAX INT32_MAX
#define INT_FAST32_MIN INT32_MIN
#define INT_FAST64_MAX INT64_MAX
#define INT_FAST64_MIN INT64_MIN
#define INT_FAST8_MAX INT8_MAX
#define INT_FAST8_MIN INT8_MIN
#define MSC_VER_VS2003 1310
#define MSC_VER_VS2005 1400
#define MSC_VER_VS2008 1500
#define MSC_VER_VS2010 1600
#define MSC_VER_VS2012 1700
#define MSC_VER_VS2013 1800
#define MSC_VER_VS2015 1900
#define PRIX16 "hX"
#define PRIX32 "lX"
#define PRIX64 __PRI_64_LENGTH_MODIFIER__ "X"
#define PRIX8 __PRI_8_LENGTH_MODIFIER__ "X"
#define PRId16 "hd"
#define PRId32 "ld"
#define PRId64 __PRI_64_LENGTH_MODIFIER__ "d"
#define PRId8 __PRI_8_LENGTH_MODIFIER__ "d"
#define PRIi16 "hi"
#define PRIi32 "li"
#define PRIi64 __PRI_64_LENGTH_MODIFIER__ "i"
#define PRIi8 __PRI_8_LENGTH_MODIFIER__ "i"
#define PRIo16 "ho"
#define PRIo32 "lo"
#define PRIo64 __PRI_64_LENGTH_MODIFIER__ "o"
#define PRIo8 __PRI_8_LENGTH_MODIFIER__ "o"
#define PRIu16 "hu"
#define PRIu32 "lu"
#define PRIu64 __PRI_64_LENGTH_MODIFIER__ "u"
#define PRIu8 __PRI_8_LENGTH_MODIFIER__ "u"
#define PRIx16 "hx"
#define PRIx32 "lx"
#define PRIx64 __PRI_64_LENGTH_MODIFIER__ "x"
#define PRIx8 __PRI_8_LENGTH_MODIFIER__ "x"
#define UINT16_MAX 0xffffui16
#define UINT32_MAX 0xffffffffui32
#define UINT64_MAX 0xffffffffffffffffui64
#define UINT8_MAX 0xffui8
#define UINTPTR_MAX UINT64_MAX
#define UINT_FAST16_MAX UINT32_MAX
#define UINT_FAST32_MAX UINT32_MAX
#define UINT_FAST64_MAX UINT64_MAX
#define UINT_FAST8_MAX UINT8_MAX

#define _INTPTR 2


#define _W64 __w64
#define __PRI_64_LENGTH_MODIFIER__ "ll"
#define __PRI_8_LENGTH_MODIFIER__ "hh"
#define false 0
#define snprintf _snprintf
#define strcasecmp _stricmp
#define strtoll _strtoi64
#define strtoull _strtoui64
#define true 1
#define va_copy(d, s) ((d) = (s))
#define DEFAULT_VISIBILITY __attribute__((visibility("default")))
#define UC_API_EXTRA 6
#define UC_API_MAJOR 2
#define UC_API_MINOR 0
#define UC_API_PATCH 0
#define UC_CTL(type, nr, rw)                                                   \
    (uc_control_type)((type) | ((nr) << 26) | ((rw) << 30))
#define UC_CTL_IO_NONE (0)
#define UC_CTL_IO_READ (2)
#define UC_CTL_IO_READ_WRITE (UC_CTL_IO_WRITE | UC_CTL_IO_READ)
#define UC_CTL_IO_WRITE (1)
#define UC_CTL_NONE(type, nr) UC_CTL(type, nr, UC_CTL_IO_NONE)
#define UC_CTL_READ(type, nr) UC_CTL(type, nr, UC_CTL_IO_READ)
#define UC_CTL_READ_WRITE(type, nr) UC_CTL(type, nr, UC_CTL_IO_READ_WRITE)
#define UC_CTL_WRITE(type, nr) UC_CTL(type, nr, UC_CTL_IO_WRITE)
#define UC_HOOK_MEM_FETCH_INVALID                                              \
    (UC_HOOK_MEM_FETCH_PROT + UC_HOOK_MEM_FETCH_UNMAPPED)
#define UC_HOOK_MEM_INVALID (UC_HOOK_MEM_UNMAPPED + UC_HOOK_MEM_PROT)
#define UC_HOOK_MEM_PROT                                                       \
    (UC_HOOK_MEM_READ_PROT + UC_HOOK_MEM_WRITE_PROT + UC_HOOK_MEM_FETCH_PROT)
#define UC_HOOK_MEM_READ_INVALID                                               \
    (UC_HOOK_MEM_READ_PROT + UC_HOOK_MEM_READ_UNMAPPED)
#define UC_HOOK_MEM_UNMAPPED                                                   \
    (UC_HOOK_MEM_READ_UNMAPPED + UC_HOOK_MEM_WRITE_UNMAPPED +                  \
     UC_HOOK_MEM_FETCH_UNMAPPED)
#define UC_HOOK_MEM_VALID                                                      \
    (UC_HOOK_MEM_READ + UC_HOOK_MEM_WRITE + UC_HOOK_MEM_FETCH)
#define UC_HOOK_MEM_WRITE_INVALID                                              \
    (UC_HOOK_MEM_WRITE_PROT + UC_HOOK_MEM_WRITE_UNMAPPED)
#define UC_MAKE_VERSION(major, minor) ((major << 8) + minor)
#define UC_MILISECOND_SCALE 1000
#define UC_SECOND_SCALE 1000000
#define UC_VERSION_EXTRA UC_API_EXTRA
#define UC_VERSION_MAJOR UC_API_MAJOR
#define UC_VERSION_MINOR UC_API_MINOR
#define UC_VERSION_PATCH UC_API_PATCH
#define UNICORN_DEPRECATED __attribute__((deprecated))

#define UNICORN_EXPORT __declspec(dllexport)
#define uc_ctl_exits_disable(uc)                                               \
    uc_ctl(uc, UC_CTL_WRITE(UC_CTL_UC_USE_EXITS, 1), 0)
#define uc_ctl_exits_enable(uc)                                                \
    uc_ctl(uc, UC_CTL_WRITE(UC_CTL_UC_USE_EXITS, 1), 1)
#define uc_ctl_get_arch(uc, arch)                                              \
    uc_ctl(uc, UC_CTL_READ(UC_CTL_UC_ARCH, 1), (arch))
#define uc_ctl_get_cpu_model(uc, model)                                        \
    uc_ctl(uc, UC_CTL_READ(UC_CTL_CPU_MODEL, 1), (model))
#define uc_ctl_get_exits(uc, buffer, len)                                      \
    uc_ctl(uc, UC_CTL_READ(UC_CTL_UC_EXITS, 2), (buffer), (len))
#define uc_ctl_get_exits_cnt(uc, ptr)                                          \
    uc_ctl(uc, UC_CTL_READ(UC_CTL_UC_EXITS_CNT, 1), (ptr))
#define uc_ctl_get_mode(uc, mode)                                              \
    uc_ctl(uc, UC_CTL_READ(UC_CTL_UC_MODE, 1), (mode))
#define uc_ctl_get_page_size(uc, ptr)                                          \
    uc_ctl(uc, UC_CTL_READ(UC_CTL_UC_PAGE_SIZE, 1), (ptr))
#define uc_ctl_get_timeout(uc, ptr)                                            \
    uc_ctl(uc, UC_CTL_READ(UC_CTL_UC_TIMEOUT, 1), (ptr))
#define uc_ctl_remove_cache(uc, address, end)                                  \
    uc_ctl(uc, UC_CTL_WRITE(UC_CTL_TB_REMOVE_CACHE, 2), (address), (end))
#define uc_ctl_request_cache(uc, address, tb)                                  \
    uc_ctl(uc, UC_CTL_READ_WRITE(UC_CTL_TB_REQUEST_CACHE, 2), (address), (tb))
#define uc_ctl_set_cpu_model(uc, model)                                        \
    uc_ctl(uc, UC_CTL_WRITE(UC_CTL_CPU_MODEL, 1), (model))
#define uc_ctl_set_exits(uc, buffer, len)                                      \
    uc_ctl(uc, UC_CTL_WRITE(UC_CTL_UC_EXITS, 2), (buffer), (len))
#define uc_ctl_set_page_size(uc, page_size)                                    \
    uc_ctl(uc, UC_CTL_WRITE(UC_CTL_UC_PAGE_SIZE, 1), (page_size))
#define OPC_BUF_SIZE 640


#define QLIST_EMPTY_RCU(head) (atomic_read(&(head)->lh_first) == NULL)
#define QLIST_FIRST_RCU(head) (atomic_rcu_read(&(head)->lh_first))
#define QLIST_FOREACH_RCU(var, head, field)                 \
        for ((var) = atomic_rcu_read(&(head)->lh_first);    \
                (var);                                      \
                (var) = atomic_rcu_read(&(var)->field.le_next))
#define QLIST_FOREACH_SAFE_RCU(var, head, field, next_var)           \
    for ((var) = (atomic_rcu_read(&(head)->lh_first));               \
      (var) &&                                                       \
          ((next_var) = atomic_rcu_read(&(var)->field.le_next), 1);  \
           (var) = (next_var))
#define QLIST_INSERT_AFTER_RCU(listelm, elm, field) do {    \
    (elm)->field.le_next = (listelm)->field.le_next;        \
    (elm)->field.le_prev = &(listelm)->field.le_next;       \
    atomic_rcu_set(&(listelm)->field.le_next, (elm));       \
    if ((elm)->field.le_next != NULL) {                     \
       (elm)->field.le_next->field.le_prev =                \
        &(elm)->field.le_next;                              \
    }                                                       \
} while (0)
#define QLIST_INSERT_BEFORE_RCU(listelm, elm, field) do {   \
    (elm)->field.le_prev = (listelm)->field.le_prev;        \
    (elm)->field.le_next = (listelm);                       \
    atomic_rcu_set((listelm)->field.le_prev, (elm));        \
    (listelm)->field.le_prev = &(elm)->field.le_next;       \
} while (0)
#define QLIST_INSERT_HEAD_RCU(head, elm, field) do {    \
    (elm)->field.le_prev = &(head)->lh_first;           \
    (elm)->field.le_next = (head)->lh_first;            \
    atomic_rcu_set((&(head)->lh_first), (elm));         \
    if ((elm)->field.le_next != NULL) {                 \
       (elm)->field.le_next->field.le_prev =            \
        &(elm)->field.le_next;                          \
    }                                                   \
} while (0)
#define QLIST_NEXT_RCU(elm, field) (atomic_rcu_read(&(elm)->field.le_next))
#define QLIST_REMOVE_RCU(elm, field) do {           \
    if ((elm)->field.le_next != NULL) {             \
       (elm)->field.le_next->field.le_prev =        \
        (elm)->field.le_prev;                       \
    }                                               \
    atomic_set((elm)->field.le_prev, (elm)->field.le_next); \
} while (0)
#define QSIMPLEQ_EMPTY_RCU(head)      (atomic_read(&(head)->sqh_first) == NULL)
#define QSIMPLEQ_FIRST_RCU(head)       atomic_rcu_read(&(head)->sqh_first)
#define QSIMPLEQ_FOREACH_RCU(var, head, field)                          \
    for ((var) = atomic_rcu_read(&(head)->sqh_first);                   \
         (var);                                                         \
         (var) = atomic_rcu_read(&(var)->field.sqe_next))
#define QSIMPLEQ_FOREACH_SAFE_RCU(var, head, field, next)                \
    for ((var) = atomic_rcu_read(&(head)->sqh_first);                    \
         (var) && ((next) = atomic_rcu_read(&(var)->field.sqe_next), 1); \
         (var) = (next))
#define QSIMPLEQ_INSERT_AFTER_RCU(head, listelm, elm, field) do {       \
    (elm)->field.sqe_next = (listelm)->field.sqe_next;                  \
    if ((elm)->field.sqe_next == NULL) {                                \
        (head)->sqh_last = &(elm)->field.sqe_next;                      \
    }                                                                   \
    atomic_rcu_set(&(listelm)->field.sqe_next, (elm));                  \
} while (0)
#define QSIMPLEQ_INSERT_HEAD_RCU(head, elm, field) do {         \
    (elm)->field.sqe_next = (head)->sqh_first;                  \
    if ((elm)->field.sqe_next == NULL) {                        \
        (head)->sqh_last = &(elm)->field.sqe_next;              \
    }                                                           \
    atomic_rcu_set(&(head)->sqh_first, (elm));                  \
} while (0)
#define QSIMPLEQ_INSERT_TAIL_RCU(head, elm, field) do {    \
    (elm)->field.sqe_next = NULL;                          \
    atomic_rcu_set((head)->sqh_last, (elm));               \
    (head)->sqh_last = &(elm)->field.sqe_next;             \
} while (0)
#define QSIMPLEQ_NEXT_RCU(elm, field)  atomic_rcu_read(&(elm)->field.sqe_next)
#define QSIMPLEQ_REMOVE_HEAD_RCU(head, field) do {                     \
    atomic_set(&(head)->sqh_first, (head)->sqh_first->field.sqe_next); \
    if ((head)->sqh_first == NULL) {                                   \
        (head)->sqh_last = &(head)->sqh_first;                         \
    }                                                                  \
} while (0)
#define QSIMPLEQ_REMOVE_RCU(head, elm, type, field) do {            \
    if ((head)->sqh_first == (elm)) {                               \
        QSIMPLEQ_REMOVE_HEAD_RCU((head), field);                    \
    } else {                                                        \
        struct type *curr = (head)->sqh_first;                      \
        while (curr->field.sqe_next != (elm)) {                     \
            curr = curr->field.sqe_next;                            \
        }                                                           \
        atomic_set(&curr->field.sqe_next,                           \
                   curr->field.sqe_next->field.sqe_next);           \
        if (curr->field.sqe_next == NULL) {                         \
            (head)->sqh_last = &(curr)->field.sqe_next;             \
        }                                                           \
    }                                                               \
} while (0)
#define QTAILQ_EMPTY_RCU(head)      (atomic_read(&(head)->tqh_first) == NULL)
#define QTAILQ_FIRST_RCU(head)       atomic_rcu_read(&(head)->tqh_first)
#define QTAILQ_FOREACH_RCU(var, head, field)                            \
    for ((var) = atomic_rcu_read(&(head)->tqh_first);                   \
         (var);                                                         \
         (var) = atomic_rcu_read(&(var)->field.tqe_next))
#define QTAILQ_FOREACH_SAFE_RCU(var, head, field, next)                  \
    for ((var) = atomic_rcu_read(&(head)->tqh_first);                    \
         (var) && ((next) = atomic_rcu_read(&(var)->field.tqe_next), 1); \
         (var) = (next))
#define QTAILQ_INSERT_AFTER_RCU(head, listelm, elm, field) do {         \
    (elm)->field.tqe_next = (listelm)->field.tqe_next;                  \
    if ((elm)->field.tqe_next != NULL) {                                \
        (elm)->field.tqe_next->field.tqe_circ.tql_prev =                \
            &(elm)->field.tqe_circ;                                     \
    } else {                                                            \
        (head)->tqh_circ.tql_prev = &(elm)->field.tqe_circ;             \
    }                                                                   \
    atomic_rcu_set(&(listelm)->field.tqe_next, (elm));                  \
    (elm)->field.tqe_circ.tql_prev = &(listelm)->field.tqe_circ;        \
} while (0)
#define QTAILQ_INSERT_BEFORE_RCU(listelm, elm, field) do {                \
    (elm)->field.tqe_circ.tql_prev = (listelm)->field.tqe_circ.tql_prev;  \
    (elm)->field.tqe_next = (listelm);                                    \
    atomic_rcu_set(&(listelm)->field.tqe_circ.tql_prev->tql_next, (elm)); \
    (listelm)->field.tqe_circ.tql_prev = &(elm)->field.tqe_circ;          \
} while (0)
#define QTAILQ_INSERT_HEAD_RCU(head, elm, field) do {                   \
    (elm)->field.tqe_next = (head)->tqh_first;                          \
    if ((elm)->field.tqe_next != NULL) {                                \
        (head)->tqh_first->field.tqe_circ.tql_prev =                    \
            &(elm)->field.tqe_circ;                                     \
    } else {                                                            \
        (head)->tqh_circ.tql_prev = &(elm)->field.tqe_circ;             \
    }                                                                   \
    atomic_rcu_set(&(head)->tqh_first, (elm));                          \
    (elm)->field.tqe_circ.tql_prev = &(head)->tqh_circ;                 \
} while (0)
#define QTAILQ_INSERT_TAIL_RCU(head, elm, field) do {                   \
    (elm)->field.tqe_next = NULL;                                       \
    (elm)->field.tqe_circ.tql_prev = (head)->tqh_circ.tql_prev;         \
    atomic_rcu_set(&(head)->tqh_circ.tql_prev->tql_next, (elm));        \
    (head)->tqh_circ.tql_prev = &(elm)->field.tqe_circ;                 \
} while (0)
#define QTAILQ_NEXT_RCU(elm, field)  atomic_rcu_read(&(elm)->field.tqe_next)
#define QTAILQ_REMOVE_RCU(head, elm, field) do {                        \
    if (((elm)->field.tqe_next) != NULL) {                              \
        (elm)->field.tqe_next->field.tqe_circ.tql_prev =                \
            (elm)->field.tqe_circ.tql_prev;                             \
    } else {                                                            \
        (head)->tqh_circ.tql_prev = (elm)->field.tqe_circ.tql_prev;     \
    }                                                                   \
    atomic_set(&(elm)->field.tqe_circ.tql_prev->tql_next, (elm)->field.tqe_next); \
    (elm)->field.tqe_circ.tql_prev = NULL;                              \
} while (0)
# define ATOMIC_REG_SIZE  8

#define atomic_add(ptr, n) ((void) __atomic_fetch_add(ptr, n, __ATOMIC_SEQ_CST))
#define atomic_add_fetch(ptr, n)      (InterlockedExchangeAdd((long*)ptr, n) + n)
#define atomic_and(ptr, n) ((void) __atomic_fetch_and(ptr, n, __ATOMIC_SEQ_CST))
#define atomic_and_fetch(ptr, n)      (InterlockedAnd((long*)ptr, n) & n)
#define atomic_cmpxchg(ptr, old, new)    ({                             \
    QEMU_BUILD_BUG_ON(sizeof(*ptr) > ATOMIC_REG_SIZE);                  \
    atomic_cmpxchg__nocheck(ptr, old, new);                             \
})
#define atomic_cmpxchg__nocheck(ptr, old, new)    ({                    \
    typeof_strip_qual(*ptr) _old = (old);                               \
    (void)__atomic_compare_exchange_n(ptr, &_old, new, false,           \
                              __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);      \
    _old;                                                               \
})
#define atomic_dec(ptr)    ((void) __atomic_fetch_sub(ptr, 1, __ATOMIC_SEQ_CST))
#define atomic_dec_fetch(ptr)    __atomic_sub_fetch(ptr, 1, __ATOMIC_SEQ_CST)
#define atomic_fetch_add(ptr, n)      ((InterlockedAdd(ptr,  n))-n)
#define atomic_fetch_and(ptr, n)      ((InterlockedAnd(ptr, n)))
#define atomic_fetch_dec(ptr)  __atomic_fetch_sub(ptr, 1, __ATOMIC_SEQ_CST)
#define atomic_fetch_inc(ptr)  __atomic_fetch_add(ptr, 1, __ATOMIC_SEQ_CST)
#define atomic_fetch_or(ptr, n)       ((InterlockedOr(ptr, n)))
#define atomic_fetch_sub(ptr, n)      ((InterlockedAdd(ptr, -n))+n)
#define atomic_fetch_xor(ptr, n)      ((InterlockedXor(ptr, n)))
#define atomic_inc(ptr)    ((void) __atomic_fetch_add(ptr, 1, __ATOMIC_SEQ_CST))
#define atomic_inc_fetch(ptr)    __atomic_add_fetch(ptr, 1, __ATOMIC_SEQ_CST)
#define atomic_or(ptr, n)  ((void) __atomic_fetch_or(ptr, n, __ATOMIC_SEQ_CST))
#define atomic_or_fetch(ptr, n)       (InterlockedOr((long*)ptr, n) | n)
#define atomic_rcu_read(ptr)                          \
    ({                                                \
    QEMU_BUILD_BUG_ON(sizeof(*ptr) > ATOMIC_REG_SIZE); \
    typeof_strip_qual(*ptr) _val;                     \
    atomic_rcu_read__nocheck(ptr, &_val);             \
    _val;                                             \
    })
#define atomic_rcu_set(ptr, i) do {                   \
    QEMU_BUILD_BUG_ON(sizeof(*ptr) > ATOMIC_REG_SIZE); \
    __atomic_store_n(ptr, i, __ATOMIC_RELEASE);       \
} while(0)
#define atomic_read(ptr)                          \
    ({                                            \
    QEMU_BUILD_BUG_ON(sizeof(*ptr) > ATOMIC_REG_SIZE); \
    atomic_read__nocheck(ptr);                        \
    })
#define atomic_read__nocheck(ptr) \
    __atomic_load_n(ptr, __ATOMIC_RELAXED)
#define atomic_set(ptr, i)  do {                  \
    QEMU_BUILD_BUG_ON(sizeof(*ptr) > ATOMIC_REG_SIZE); \
    atomic_set__nocheck(ptr, i);                      \
} while(0)
#define atomic_set__nocheck(ptr, i) \
    __atomic_store_n(ptr, i, __ATOMIC_RELAXED)
#define atomic_sub(ptr, n) ((void) __atomic_fetch_sub(ptr, n, __ATOMIC_SEQ_CST))
#define atomic_sub_fetch(ptr, n)      (InterlockedExchangeAdd((long*)ptr, n) - n)
#define atomic_xchg(ptr, i)    ({                           \
    QEMU_BUILD_BUG_ON(sizeof(*ptr) > ATOMIC_REG_SIZE);      \
    atomic_xchg__nocheck(ptr, i);                           \
})
#define atomic_xchg__nocheck  atomic_xchg
#define atomic_xor(ptr, n) ((void) __atomic_fetch_xor(ptr, n, __ATOMIC_SEQ_CST))
#define atomic_xor_fetch(ptr, n)      (InterlockedXor((long*)ptr, n) ^ n)




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

#define DO_UPCAST(type, field, dev) ( __extension__ ( { \
    char __attribute__((unused)) offset_must_be_zero[ \
        -offsetof(type, field)]; \
    container_of(dev, type, field);}))
#  define GCC_FMT_ATTR(n, m) __attribute__((format(printf, n, m)))

#define NAN (__NAN.Value)
#define QEMU_ALIGN(A, B) B __attribute__((aligned(A)))
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
#define QEMU_DIV0 __pragma(warning(suppress:2124))	
# define QEMU_ERROR(X) __attribute__((error(X)))
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
# define QEMU_GNUC_PREREQ(maj, min) \
         (("__GNUC__" << 16) + "__GNUC_MINOR__" >= ((maj) << 16) + (min))
#define QEMU_NOINLINE __attribute__((noinline))
# define QEMU_NONSTRING __attribute__((nonstring))
#define QEMU_NORETURN __attribute__ ((__noreturn__))
# define QEMU_PACK( __Declaration__ ) __Declaration__ __attribute__((gcc_struct, packed))
# define QEMU_PACKED __attribute__((gcc_struct, packed))
#define QEMU_SECOND_(a, b) b
#define QEMU_SENTINEL __attribute__((sentinel))
#define QEMU_STATIC_ANALYSIS 1
#define QEMU_UNUSED_FUNC __attribute__((unused))
#define QEMU_UNUSED_VAR __attribute__((unused))
#define QEMU_WARN_UNUSED_RESULT __attribute__((warn_unused_result))
#define __builtin_expect(x, n) (x)
#define __has_attribute(x) 0 
#define __has_builtin(x) 0 
#define __has_feature(x) 0 
#define __has_warning(x) 0 
#   define __printf__ __gnu_printf__
#define cat(x,y) x ## y
#define cat2(x,y) cat(x,y)
#define container_of(ptr, type, member) ({                      \
        const typeof(((type *) 0)->member) *__mptr = (ptr);     \
        (type *) ((char *) __mptr - offsetof(type, member));})
#define endof(container, field) \
    (offsetof(container, field) + sizeof_field(container, field))
#define glue(x, y) xglue(x, y)
#define inline		__inline
#define isinf(x) (!_finite(x))
#define likely(x)   __builtin_expect(!!(x), 1)
#define qemu_build_not_reached()  g_assert_not_reached()
#define sizeof_field(type, field) sizeof(((type *)0)->field)
#define stringify(s)	tostring(s)
#define tostring(s)	#s
#define type_check(t1,t2) ((t1*)0 - (t2*)0)
#define typeof_field(type, field) typeof(((type *)0)->field)
#define unlikely(x)   __builtin_expect(!!(x), 0)
#define xglue(x, y) x ## y

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
#define QSIMPLEQ_EMPTY_ATOMIC(head) (atomic_read(&((head)->sqh_first)) == NULL)
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
        } while (atomic_cmpxchg(&(head)->slh_first, save_sle_next, (elm)) != \
                 save_sle_next);                                             \
} while (0)
#define QSLIST_MOVE_ATOMIC(dest, src) do {                               \
        (dest)->slh_first = atomic_xchg(&(src)->slh_first, NULL);        \
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

#define range_empty ((Range){ .lob = 1, .upb = 0 })
#define DIRTY_CLIENTS_ALL     ((1 << DIRTY_MEMORY_NUM) - 1)
#define DIRTY_CLIENTS_NOCODE  (DIRTY_CLIENTS_ALL & ~(1 << DIRTY_MEMORY_CODE))


#define DIRTY_MEMORY_CODE      1
#define DIRTY_MEMORY_MIGRATION 2
#define DIRTY_MEMORY_NUM       3        
#define DIRTY_MEMORY_VGA       0
#define  INTERNAL_RAMBLOCK_FOREACH(block)  \
    QLIST_FOREACH(block, &uc->ram_list.blocks, next)
#define RAMBLOCK_FOREACH(block) INTERNAL_RAMBLOCK_FOREACH(block)

#define QEMU_THREAD_DETACHED 1

#define QEMU_THREAD_JOINABLE 0



# define cpu_relax() asm volatile("rep; nop" ::: "memory")



#define CF_CLUSTER_MASK 0xff000000 
#define CF_CLUSTER_SHIFT 24
#define CF_COUNT_MASK  0x00007fff
#define CF_HASH_MASK   \
    (CF_COUNT_MASK | CF_LAST_IO | CF_USE_ICOUNT | CF_PARALLEL | CF_CLUSTER_MASK)
#define CF_INVALID     0x00040000 
#define CF_LAST_IO     0x00008000 
#define CF_NOCACHE     0x00010000 
#define CF_PARALLEL    0x00080000 
#define CF_USE_ICOUNT  0x00020000
#define CODE_GEN_ALIGN           16 
#define CODE_GEN_AVG_BLOCK_SIZE 400


# define GETPC() (uintptr_t)_ReturnAddress()
#define GETPC_ADJ   2
#define TB_JMP_RESET_OFFSET_INVALID 0xffff 
#define TB_PAGE_ADDR_FMT RAM_ADDR_FMT
#define CPU_LOG_EXEC       (1 << 5)
#define CPU_LOG_INT        (1 << 4)
#define CPU_LOG_MMU        (1 << 12)
#define CPU_LOG_PAGE       (1 << 14)
#define CPU_LOG_PCALL      (1 << 6)
#define CPU_LOG_PLUGIN     (1 << 18)
#define CPU_LOG_RESET      (1 << 9)
#define CPU_LOG_TB_CPU     (1 << 8)
#define CPU_LOG_TB_FPU     (1 << 17)
#define CPU_LOG_TB_IN_ASM  (1 << 1)
#define CPU_LOG_TB_NOCHAIN (1 << 13)
#define CPU_LOG_TB_OP      (1 << 2)
#define CPU_LOG_TB_OP_IND  (1 << 16)
#define CPU_LOG_TB_OP_OPT  (1 << 3)
#define CPU_LOG_TB_OUT_ASM (1 << 0)
#define LOG_GUEST_ERROR    (1 << 11)
#define LOG_STRACE         (1 << 19)
#define LOG_UNIMP          (1 << 10)

#define qemu_log_mask(MASK, FMT, ...)
#define qemu_log_mask_and_addr(MASK, ADDR, FMT, ...)

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
            break;                         \
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
            return 0;                      \
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
#define make_float128(high_, low_) ((float128) { .high = high_, .low = low_ })
#define make_float128_init(high_, low_) { .high = high_, .low = low_ }
#define make_float16(x) (x)
#define make_float32(x) (x)
#define make_float64(x) (x)
#define make_floatx80(exp, mant) ((floatx80) { mant, exp })
#define make_floatx80_init(exp, mant) { .low = mant, .high = exp }
#define BIT(nr)                 (1UL << (nr))

#define BITS_PER_BYTE           CHAR_BIT
#define BITS_PER_LONG           (sizeof (unsigned long) * BITS_PER_BYTE)
#define BITS_TO_LONGS(nr)       DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))
#define BIT_MASK(nr)            (1UL << ((nr) % BITS_PER_LONG))
#define BIT_ULL(nr)             (1ULL << (nr))
#define BIT_WORD(nr)            ((nr) / BITS_PER_LONG)
#define MAKE_64BIT_MASK(shift, length) \
    (((~0ULL) >> (64 - (length))) << (shift))

#define TARGET_ABI_FMT_ptr TARGET_ABI_FMT_lx
#define CPU_TEMP_BUF_NLONGS 128
#define DEAD_ARG  4
#define DEF(name, oargs, iargs, cargs, flags) INDEX_op_ ## name,
#define GEN_ATOMIC_HELPER(NAME, TYPE, SUFFIX)         \
TYPE helper_atomic_ ## NAME ## SUFFIX ## _mmu         \
    (CPUArchState *env, target_ulong addr, TYPE val,  \
     TCGMemOpIdx oi, uintptr_t retaddr);
#define GEN_ATOMIC_HELPER_ALL(NAME)          \
    GEN_ATOMIC_HELPER(NAME, uint32_t, b)     \
    GEN_ATOMIC_HELPER(NAME, uint32_t, w_le)  \
    GEN_ATOMIC_HELPER(NAME, uint32_t, w_be)  \
    GEN_ATOMIC_HELPER(NAME, uint32_t, l_le)  \
    GEN_ATOMIC_HELPER(NAME, uint32_t, l_be)  \
    GEN_ATOMIC_HELPER(NAME, uint64_t, q_le)  \
    GEN_ATOMIC_HELPER(NAME, uint64_t, q_be)
#define MAX_OPC_PARAM (4 + (MAX_OPC_PARAM_PER_ARG * MAX_OPC_PARAM_ARGS))
#define MAX_OPC_PARAM_ARGS (MAX_OPC_PARAM_IARGS + MAX_OPC_PARAM_OARGS)
#define MAX_OPC_PARAM_IARGS 6
#define MAX_OPC_PARAM_OARGS 1
#define MAX_OPC_PARAM_PER_ARG 2
#define MAX_OP_PER_INSTR 266
#define SYNC_ARG  1
# define TARGET_INSN_START_WORDS 1
#define TB_EXIT_IDX0      0
#define TB_EXIT_IDX1      1
#define TB_EXIT_IDXMAX    1
#define TB_EXIT_MASK      3
#define TB_EXIT_REQUESTED 3
#define TCGOP_CALLI(X)    (X)->param1
#define TCGOP_CALLO(X)    (X)->param2
#define TCGOP_VECE(X)     (X)->param2
#define TCGOP_VECL(X)     (X)->param1
#define TCG_CALL_DUMMY_ARG      ((TCGArg)0)
#define TCG_CALL_NO_READ_GLOBALS    0x0001
#define TCG_CALL_NO_RETURN          0x0008
#define TCG_CALL_NO_RWG         TCG_CALL_NO_READ_GLOBALS
#define TCG_CALL_NO_RWG_SE      (TCG_CALL_NO_RWG | TCG_CALL_NO_SE)
#define TCG_CALL_NO_SE          TCG_CALL_NO_SIDE_EFFECTS
#define TCG_CALL_NO_SIDE_EFFECTS    0x0004
#define TCG_CALL_NO_WG          TCG_CALL_NO_WRITE_GLOBALS
#define TCG_CALL_NO_WG_SE       (TCG_CALL_NO_WG | TCG_CALL_NO_SE)
#define TCG_CALL_NO_WRITE_GLOBALS   0x0002
#define TCG_CT_ALIAS  0x80
#define TCG_CT_CONST  0x02 
#define TCG_CT_IALIAS 0x40
#define TCG_CT_NEWREG 0x20 
#define TCG_CT_REG    0x01

#define TCG_MAX_INSNS 512
#define TCG_MAX_OP_ARGS 16
#define TCG_MAX_TEMPS 512
#define TCG_OVERSIZED_GUEST 1
#define TCG_POOL_CHUNK_SIZE 32768
#define TCG_PRIld PRId32
#define TCG_PRIlx PRIx32
#define TCG_STATIC_CALL_ARGS_SIZE 128
#define TCG_TARGET_HAS_abs_vec          0
#define TCG_TARGET_HAS_add2_i32         1
#define TCG_TARGET_HAS_add2_i64         0
#define TCG_TARGET_HAS_andc_i64         0
#define TCG_TARGET_HAS_andc_vec         0
#define TCG_TARGET_HAS_bitsel_vec       0
#define TCG_TARGET_HAS_bswap16_i64      0
#define TCG_TARGET_HAS_bswap32_i64      0
#define TCG_TARGET_HAS_bswap64_i64      0
#define TCG_TARGET_HAS_clz_i64          0
#define TCG_TARGET_HAS_cmpsel_vec       0
#define TCG_TARGET_HAS_ctpop_i64        0
#define TCG_TARGET_HAS_ctz_i64          0
#define TCG_TARGET_HAS_deposit_i64      0
#define TCG_TARGET_HAS_div2_i32         0
#define TCG_TARGET_HAS_div2_i64         0
#define TCG_TARGET_HAS_div_i32          0
#define TCG_TARGET_HAS_div_i64          0
#define TCG_TARGET_HAS_eqv_i64          0
#define TCG_TARGET_HAS_ext16s_i64       0
#define TCG_TARGET_HAS_ext16u_i64       0
#define TCG_TARGET_HAS_ext32s_i64       0
#define TCG_TARGET_HAS_ext32u_i64       0
#define TCG_TARGET_HAS_ext8s_i64        0
#define TCG_TARGET_HAS_ext8u_i64        0
#define TCG_TARGET_HAS_extract2_i64     0
#define TCG_TARGET_HAS_extract_i64      0
#define TCG_TARGET_HAS_extrh_i64_i32    0
#define TCG_TARGET_HAS_extrl_i64_i32    0
#define TCG_TARGET_HAS_minmax_vec       0
#define TCG_TARGET_HAS_movcond_i64      0
#define TCG_TARGET_HAS_mul_vec          0
#define TCG_TARGET_HAS_muls2_i64        0
#define TCG_TARGET_HAS_mulsh_i64        0
#define TCG_TARGET_HAS_mulu2_i64        0
#define TCG_TARGET_HAS_muluh_i64        0
#define TCG_TARGET_HAS_nand_i64         0
#define TCG_TARGET_HAS_neg_i64          0
#define TCG_TARGET_HAS_neg_vec          0
#define TCG_TARGET_HAS_nor_i64          0
#define TCG_TARGET_HAS_not_i64          0
#define TCG_TARGET_HAS_not_vec          0
#define TCG_TARGET_HAS_orc_i64          0
#define TCG_TARGET_HAS_orc_vec          0
#define TCG_TARGET_HAS_rem_i32          0
#define TCG_TARGET_HAS_rem_i64          0
#define TCG_TARGET_HAS_rot_i64          0
#define TCG_TARGET_HAS_sat_vec          0
#define TCG_TARGET_HAS_sextract_i64     0
#define TCG_TARGET_HAS_shi_vec          0
#define TCG_TARGET_HAS_shs_vec          0
#define TCG_TARGET_HAS_shv_vec          0
#define TCG_TARGET_HAS_sub2_i32         1
#define TCG_TARGET_HAS_sub2_i64         0
#define TCG_TARGET_HAS_v128             0
#define TCG_TARGET_HAS_v256             0
#define TCG_TARGET_HAS_v64              0
#define TCG_TARGET_MAYBE_vec            0
#  define TCG_TARGET_REG_BITS 32
#define TCG_TARGET_deposit_i32_valid(ofs, len) 1
#define TCG_TARGET_deposit_i64_valid(ofs, len) 1
#define TCG_TARGET_extract_i32_valid(ofs, len) 1
#define TCG_TARGET_extract_i64_valid(ofs, len) 1
#define TCGv TCGv_i32
#define dup_const(VECE, C)                                         \
    (__builtin_constant_p(VECE)                                    \
     ? (  (VECE) == MO_8  ? 0x0101010101010101ull * (uint8_t)(C)   \
        : (VECE) == MO_16 ? 0x0001000100010001ull * (uint16_t)(C)  \
        : (VECE) == MO_32 ? 0x0000000100000001ull * (uint32_t)(C)  \
        : dup_const_func(VECE, C))                                      \
     : dup_const_func(VECE, C))
# define helper_ret_ldl_mmu   helper_be_ldul_mmu
# define helper_ret_ldq_mmu   helper_be_ldq_mmu
# define helper_ret_ldsl_mmu  helper_be_ldsl_mmu
# define helper_ret_ldsw_mmu  helper_be_ldsw_mmu
# define helper_ret_ldul_mmu  helper_be_ldul_mmu
# define helper_ret_lduw_mmu  helper_be_lduw_mmu
# define helper_ret_stl_mmu   helper_be_stl_mmu
# define helper_ret_stq_mmu   helper_be_stq_mmu
# define helper_ret_stw_mmu   helper_be_stw_mmu
#define tcg_abort() \
do {\
    fprintf(stderr, "%s:%d: tcg fatal error\n", "__FILE__", "__LINE__");\
    abort();\
} while (0)
#define tcg_check_temp_count() 0
#define tcg_clear_temp_count() do { } while (0)
# define tcg_const_local_ptr(tcg_ctx, x)  ((TCGv_ptr)tcg_const_local_i32(tcg_ctx, (intptr_t)(x)))
# define tcg_const_ptr(tcg_ctx, x)        ((TCGv_ptr)tcg_const_i32(tcg_ctx, (intptr_t)(x)))
# define tcg_debug_assert(X) do { assert(X); } while (0)
# define tcg_qemu_tb_exec(env, tb_ptr) \
    ((uintptr_t (*)(void *, void *))env->uc->tcg_ctx->code_gen_prologue)(env, tb_ptr)
#define tcg_regset_reset_reg(d, r) ((d) &= ~((TCGRegSet)1 << (r)))
#define tcg_regset_set_reg(d, r)   ((d) |= (TCGRegSet)1 << (r))
#define tcg_regset_test_reg(d, r)  (((d) >> (r)) & 1)
#define DATA64_ARGS  (TCG_TARGET_REG_BITS == 64 ? 1 : 2)
#define IMPL(X) (__builtin_constant_p(X) && (X) <= 0 ? TCG_OPF_NOT_PRESENT : 0)
# define IMPL64  TCG_OPF_64BIT | TCG_OPF_NOT_PRESENT
#define IMPLVEC  TCG_OPF_VECTOR | IMPL(TCG_TARGET_MAYBE_vec)
#define TLADDR_ARGS  (TARGET_LONG_BITS <= TCG_TARGET_REG_BITS ? 1 : 2)

#define CODE_GEN_HTABLE_BITS     15
#define CODE_GEN_HTABLE_SIZE     (1 << CODE_GEN_HTABLE_BITS)


#define QHT_MODE_AUTO_RESIZE 0x1 
#define QHT_MODE_RAW_MUTEXES 0x2 
#define QDIST_PR_100X       BIT(4)
#define QDIST_PR_BORDER     BIT(0)
#define QDIST_PR_LABELS     BIT(1)
#define QDIST_PR_NOBINRANGE BIT(5)
#define QDIST_PR_NODECIMAL  BIT(2)
#define QDIST_PR_PERCENT    BIT(3)


#define BP_ANY                (BP_GDB | BP_CPU)
#define BP_CPU                0x20
#define BP_GDB                0x10
#define BP_MEM_ACCESS         (BP_MEM_READ | BP_MEM_WRITE)
#define BP_MEM_READ           0x01
#define BP_MEM_WRITE          0x02
#define BP_STOP_BEFORE_ACCESS 0x04
#define BP_WATCHPOINT_HIT (BP_WATCHPOINT_HIT_READ | BP_WATCHPOINT_HIT_WRITE)
#define BP_WATCHPOINT_HIT_READ 0x40
#define BP_WATCHPOINT_HIT_WRITE 0x80
#define CPU(obj) ((CPUState *)(obj))
#define CPU_CLASS(class) ((CPUClass *)class)
#define CPU_GET_CLASS(obj) (((CPUState *)obj)->cc)
#define CPU_TRACE_DSTATE_MAX_EVENTS 32
#define CPU_UNSET_NUMA_NODE_ID -1

#define RUN_ON_CPU_HOST_INT(i)    ((run_on_cpu_data){.host_int = (i)})
#define RUN_ON_CPU_HOST_PTR(p)    ((run_on_cpu_data){.host_ptr = (p)})
#define RUN_ON_CPU_HOST_ULONG(ul) ((run_on_cpu_data){.host_ulong = (ul)})
#define RUN_ON_CPU_NULL           RUN_ON_CPU_HOST_PTR(NULL)
#define RUN_ON_CPU_TARGET_PTR(v)  ((run_on_cpu_data){.target_ptr = (v)})
#define SSTEP_ENABLE  0x1  
#define SSTEP_NOIRQ   0x2  
#define SSTEP_NOTIMER 0x4  
#define TB_JMP_CACHE_BITS 12
#define TB_JMP_CACHE_SIZE (1 << TB_JMP_CACHE_BITS)
#define UNASSIGNED_CLUSTER_INDEX -1
#define UNASSIGNED_CPU_INDEX -1
#define VADDR_MAX UINT64_MAX
#define VADDR_PRIX PRIX64
#define VADDR_PRId PRId64
#define VADDR_PRIo PRIo64
#define VADDR_PRIu PRIu64
#define VADDR_PRIx PRIx64
#define BITMAP_FIRST_WORD_MASK(start) (~0UL << ((start) & (BITS_PER_LONG - 1)))

#define BITMAP_LAST_WORD_MASK(nbits) (~0UL >> (-(nbits) & (BITS_PER_LONG - 1)))
#define DECLARE_BITMAP(name,bits)                  \
        unsigned long name[BITS_TO_LONGS(bits)]
#define small_nbits(nbits)                      \
        ((nbits) <= BITS_PER_LONG)

#define MEMTXATTRS_UNSPECIFIED ((MemTxAttrs) { .unspecified = 1 })
#define MEMTX_DECODE_ERROR      (1U << 1) 
#define MEMTX_ERROR             (1U << 0) 
#define MEMTX_OK 0
#define HWADDR_BITS 64

#define HWADDR_MAX UINT64_MAX
#define HWADDR_PRIX PRIX64
#define HWADDR_PRId PRId64
#define HWADDR_PRIi PRIi64
#define HWADDR_PRIo PRIo64
#define HWADDR_PRIu PRIu64
#define HWADDR_PRIx PRIx64
#define TARGET_FMT_plx "%016" PRIx64
#define IOPORTS_MASK    (MAX_IOPORTS - 1)

#define MAX_IOPORTS     (64 * 1024)
#define PORTIO_END_OF_LIST() { }
#define ARG1         cache
#define ARG1_DECL    MemoryRegionCache *cache
#define ENDIANNESS   _le
#define IOMMU_ACCESS_FLAG(r, w) (((r) ? IOMMU_RO : 0) | ((w) ? IOMMU_WO : 0))
#define IOMMU_MEMORY_REGION(obj) ((IOMMUMemoryRegion *)obj)
#define IOMMU_MEMORY_REGION_CLASS(klass) ((IOMMUMemoryRegionClass *)klass)
#define IOMMU_MEMORY_REGION_GET_CLASS(obj) (&((IOMMUMemoryRegion *)obj)->cc)
#define IOMMU_NOTIFIER_ALL (IOMMU_NOTIFIER_MAP | IOMMU_NOTIFIER_UNMAP)
#define IOMMU_NOTIFIER_FOREACH(n, mr) \
    QLIST_FOREACH((n), &(mr)->iommu_notify, node)
#define MAX_PHYS_ADDR            (((hwaddr)1 << MAX_PHYS_ADDR_SPACE_BITS) - 1)
#define MAX_PHYS_ADDR_SPACE_BITS 62

#define MEMORY_REGION(obj) ((MemoryRegion *)obj)
#define MEMORY_REGION_CACHE_INVALID ((MemoryRegionCache) { .mrs.mr = NULL })
#define RAM_ADDR_INVALID (~(ram_addr_t)0)
#define RAM_MIGRATABLE (1 << 4)
#define RAM_PMEM (1 << 5)
#define RAM_PREALLOC   (1 << 0)
#define RAM_RESIZEABLE (1 << 2)
#define RAM_SHARED     (1 << 1)
#define RAM_UF_ZEROPAGE (1 << 3)
#define SUFFIX       glue(_cached, UNICORN_ARCH_POSTFIX)
#define ADDRESS_SPACE_LD_CACHED(size) \
    glue(glue(glue(address_space_ld, size), glue(ENDIANNESS, _cached)), UNICORN_ARCH_POSTFIX)
#define ADDRESS_SPACE_LD_CACHED_SLOW(size) \
    glue(glue(glue(address_space_ld, size), glue(ENDIANNESS, _cached_slow)), UNICORN_ARCH_POSTFIX)
#define ADDRESS_SPACE_ST_CACHED(size) \
    glue(glue(glue(address_space_st, size), glue(ENDIANNESS, _cached)), UNICORN_ARCH_POSTFIX)
#define ADDRESS_SPACE_ST_CACHED_SLOW(size) \
    glue(glue(glue(address_space_st, size), glue(ENDIANNESS, _cached_slow)), UNICORN_ARCH_POSTFIX)
#define LD_P(size) \
    glue(glue(ld, size), glue(ENDIANNESS, _p))
#define ST_P(size) \
    glue(glue(st, size), glue(ENDIANNESS, _p))

#define DEVICE_HOST_ENDIAN DEVICE_BIG_ENDIAN
#  define RAM_ADDR_FMT "%" PRIxPTR
#  define RAM_ADDR_MAX UINTPTR_MAX




#define CPU_TLB_DYN_DEFAULT_BITS 8
#  define CPU_TLB_DYN_MAX_BITS (32 - TARGET_PAGE_BITS)
#define CPU_TLB_DYN_MIN_BITS 6
#define CPU_TLB_ENTRY_BITS 4
#define CPU_VTLB_SIZE 8
#define TARGET_FMT_ld "%d"
#define TARGET_FMT_lu "%u"
#define TARGET_FMT_lx "%08x"
#define TARGET_LONG_SIZE (TARGET_LONG_BITS / 8)
#define TLB_MASK_TABLE_OFS(IDX) \
    ((int)offsetof(ArchCPU, neg.tlb.f[IDX]) - (int)offsetof(ArchCPU, env))

#define QEMU_COPYRIGHT "Copyright (c) 2003-2020 " \
    "Fabrice Bellard and the QEMU Project developers"
#define QEMU_HELP_BOTTOM \
    "See <https://qemu.org/contribute/report-a-bug> for how to report bugs.\n" \
    "More information on the QEMU project at <https://qemu.org>."
#define TFR(expr) do { if ((expr) != -1) break; } while (errno == EINTR)
#define qemu_getsockopt(sockfd, level, optname, optval, optlen) \
    getsockopt(sockfd, level, optname, (void *)optval, optlen)
#define qemu_recv(sockfd, buf, len, flags) recv(sockfd, (void *)buf, len, flags)
#define qemu_sendto(sockfd, buf, len, flags, destaddr, addrlen) \
    sendto(sockfd, (const void *)buf, len, flags, destaddr, addrlen)
#define qemu_setsockopt(sockfd, level, optname, optval, optlen) \
    setsockopt(sockfd, level, optname, (const void *)optval, optlen)

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
#define MAP_ANONYMOUS MAP_ANON
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MIN_NON_ZERO(a, b) ((a) == 0 ? (b) : \
                                ((b) == 0 ? (a) : (MIN(a, b))))
#define O_BINARY 0
#define O_LARGEFILE 0
#define QEMU_ALIGN_DOWN(n, m) ((n) / (m) * (m))
#define QEMU_ALIGN_PTR_DOWN(p, n) (QEMU_ALIGN_DOWN((uintptr_t)(p), (n)))
#define QEMU_ALIGN_PTR_UP(p, n) ((typeof(p))QEMU_ALIGN_UP((uintptr_t)(p), (n)))
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
#define ROUND_UP(n, d) (((n) + (d) - 1) & (0 - (0 ? (n) : (d))))
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
#define qemu_timersub timersub

#define setjmp(env) _setjmp(env, NULL)
#define sigjmp_buf jmp_buf
#define siglongjmp(env, val) longjmp(env, val)
#define sigsetjmp(env, savemask) setjmp(env)

