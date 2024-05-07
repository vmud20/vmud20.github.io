
#include<malloc.h>


#include<stdint.h>

#include<features.h>


#include<time.h>
#include<fcntl.h>
#include<stdlib.h>
#include<pthread.h>

#include<stdio.h>

#include<string.h>
#include<sys/time.h>
#include<sys/types.h>


#define assert(_e) (likely((_e))?(void)0 : (_serverAssert(#_e,"__FILE__","__LINE__"),redis_unreachable()))
#define panic(...) _serverPanic("__FILE__","__LINE__",__VA_ARGS__),redis_unreachable()
#define BIG_ENDIAN __BIG_ENDIAN
#define BYTE_ORDER    LITTLE_ENDIAN
#define ESOCKTNOSUPPORT 0
#define GNUC_VERSION ("__GNUC__" * 10000 + "__GNUC_MINOR__" * 100 + "__GNUC_PATCHLEVEL__")
#define HAVE_ACCEPT4 1

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

#define htonu64(v) (v)
#define intrev16ifbe(v) (v)
#define intrev32ifbe(v) (v)
#define intrev64ifbe(v) (v)
#define memrev16ifbe(p) ((void)(0))
#define memrev32ifbe(p) ((void)(0))
#define memrev64ifbe(p) ((void)(0))
#define ntohu64(v) (v)

#define HAVE_MALLOC_SIZE 1
#define ZMALLOC_LIB ("tcmalloc-" __xstr(TC_VERSION_MAJOR) "." __xstr(TC_VERSION_MINOR))

#define __str(s) #s
#define __xstr(s) __str(s)
#define zmalloc_size(p) tc_malloc_size(p)
#define zmalloc_usable_size(p) zmalloc_size(p)

