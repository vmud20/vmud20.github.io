


#include<features.h>
#include<fcntl.h>
#include<string.h>



#include<malloc.h>
#include<sys/procfs.h>
#include<linux/version.h>

#include<stdio.h>
#include<sys/sysctl.h>
#include<sys/stat.h>
#include<unistd.h>
#include<stdint.h>


#include<sys/types.h>
#include<stdlib.h>

#include<stdatomic.h>

#include<sys/user.h>
#include<pthread.h>

#define ANNOTATE_HAPPENS_AFTER(v)  ((void) v)
#define ANNOTATE_HAPPENS_BEFORE(v) ((void) v)
#define REDIS_ATOMIC_API "c11-builtin"

#define atomicDecr(var,count) __atomic_sub_fetch(&var,(count),__ATOMIC_RELAXED)
#define atomicGet(var,dstvar) do { \
    dstvar = __atomic_load_n(&var,__ATOMIC_RELAXED); \
} while(0)
#define atomicGetIncr(var,oldvalue_var,count) do { \
    oldvalue_var = __atomic_fetch_add(&var,(count),__ATOMIC_RELAXED); \
} while(0)
#define atomicGetWithSync(var,dstvar) do { \
    dstvar = atomic_load_explicit(&var,memory_order_seq_cst); \
} while(0)
#define atomicIncr(var,count) __atomic_add_fetch(&var,(count),__ATOMIC_RELAXED)
#define atomicSet(var,value) atomic_store_explicit(&var,value,memory_order_relaxed)
#define atomicSetWithSync(var,value) \
    atomic_store_explicit(&var,value,memory_order_seq_cst)
#define redisAtomic _Atomic
#define BIG_ENDIAN __BIG_ENDIAN
#define BYTE_ORDER    LITTLE_ENDIAN
#define ESOCKTNOSUPPORT 0
#define GNUC_VERSION ("__GNUC__" * 10000 + "__GNUC_MINOR__" * 100 + "__GNUC_PATCHLEVEL__")

#define HAVE_BACKTRACE 1
#define HAVE_EPOLL 1
#define HAVE_EVPORT 1
#define HAVE_KQUEUE 1
#define HAVE_MSG_NOSIGNAL 1
#define HAVE_PROC_MAPS 1
#define HAVE_PROC_OOM_SCORE_ADJ 1
#define HAVE_PROC_SMAPS 1
#define HAVE_PROC_SOMAXCONN 1
#define HAVE_PROC_STAT 1
#define HAVE_PSINFO 1
#define HAVE_SYNC_FILE_RANGE 1
#define HAVE_TASKINFO 1

#define LITTLE_ENDIAN __LITTLE_ENDIAN







#define likely(x) __builtin_expect(!!(x), 1)
#define rdb_fsync_range(fd,off,size) sync_file_range(fd,off,size,SYNC_FILE_RANGE_WAIT_BEFORE|SYNC_FILE_RANGE_WRITE)
#define redis_fstat fstat64
#define redis_fsync fdatasync
#define redis_set_thread_title(name) pthread_setname_np(pthread_self(), name)
#define redis_stat stat64
#define redis_unreachable __builtin_unreachable
#define unlikely(x) __builtin_expect(!!(x), 0)

#define HAVE_MALLOC_SIZE 1
#define ZMALLOC_LIB ("tcmalloc-" __xstr(TC_VERSION_MAJOR) "." __xstr(TC_VERSION_MINOR))

#define __str(s) #s
#define __xstr(s) __str(s)
#define zmalloc_size(p) tc_malloc_size(p)
#define zmalloc_usable_size(p) zmalloc_size(p)
