
#include<pthread.h>
#include<unistd.h>


#include<sys/time.h>
#include<stdio.h>

#include<stdlib.h>
#include<string.h>
#include<stdint.h>
#include<features.h>


#include<stdarg.h>
#include<sys/types.h>
#include<limits.h>

#include<malloc.h>
#define SDS_HDR(T,s) ((struct sdshdr##T *)((s)-(sizeof(struct sdshdr##T))))
#define SDS_HDR_VAR(T,s) struct sdshdr##T *sh = (void*)((s)-(sizeof(struct sdshdr##T)));
#define SDS_MAX_PREALLOC (1024*1024)
#define SDS_TYPE_16 2
#define SDS_TYPE_32 3
#define SDS_TYPE_5  0
#define SDS_TYPE_5_LEN(f) ((f)>>SDS_TYPE_BITS)
#define SDS_TYPE_64 4
#define SDS_TYPE_8  1
#define SDS_TYPE_BITS 3
#define SDS_TYPE_MASK 7

#define AL_START_HEAD 0
#define AL_START_TAIL 1

#define listFirst(l) ((l)->head)
#define listGetDupMethod(l) ((l)->dup)
#define listGetFreeMethod(l) ((l)->free)
#define listGetMatchMethod(l) ((l)->match)
#define listLast(l) ((l)->tail)
#define listLength(l) ((l)->len)
#define listNextNode(n) ((n)->next)
#define listNodeValue(n) ((n)->value)
#define listPrevNode(n) ((n)->prev)
#define listSetDupMethod(l,m) ((l)->dup = (m))
#define listSetFreeMethod(l,m) ((l)->free = (m))
#define listSetMatchMethod(l,m) ((l)->match = (m))

#define assert(_e) ((_e)?(void)0 : (_serverAssert(#_e,"__FILE__","__LINE__"),_exit(1)))
#define panic(...) _serverPanic("__FILE__","__LINE__",__VA_ARGS__),_exit(1)

#define htonu64(v) (v)
#define intrev16ifbe(v) (v)
#define intrev32ifbe(v) (v)
#define intrev64ifbe(v) (v)
#define memrev16ifbe(p) ((void)(0))
#define memrev32ifbe(p) ((void)(0))
#define memrev64ifbe(p) ((void)(0))
#define ntohu64(v) (v)
#define	BIG_ENDIAN	4321	
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
#define HAVE_TASKINFO 1

#define	LITTLE_ENDIAN	1234	
#define	PDP_ENDIAN	3412	







#define rdb_fsync_range(fd,off,size) sync_file_range(fd,off,size,SYNC_FILE_RANGE_WAIT_BEFORE|SYNC_FILE_RANGE_WRITE)
#define redis_fstat fstat64
#define redis_fsync fdatasync
#define redis_set_thread_title(name) pthread_setname_np(pthread_self(), name)
#define redis_stat stat64
#define ZIPLIST_HEAD 0
#define ZIPLIST_TAIL 1

#define MAX_LONG_DOUBLE_CHARS 5*1024


#define HAVE_MALLOC_SIZE 1
#define ZMALLOC_LIB ("tcmalloc-" __xstr(TC_VERSION_MAJOR) "." __xstr(TC_VERSION_MINOR))

#define __str(s) #s
#define __xstr(s) __str(s)
#define zmalloc_size(p) tc_malloc_size(p)
#define zmalloc_usable(p) zmalloc_size(p)
