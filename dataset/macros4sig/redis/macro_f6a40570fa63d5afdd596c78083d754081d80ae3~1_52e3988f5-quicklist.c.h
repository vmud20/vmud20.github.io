
#include<string.h>
#include<stdint.h>
#include<sys/time.h>
#include<stdio.h>

#include<stdarg.h>
#include<malloc.h>

#include<sys/types.h>

#define LZF_VERSION 0x0105 
#define MAX_LONG_DOUBLE_CHARS 5*1024

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

#define ZIPLIST_HEAD 0
#define ZIPLIST_TAIL 1


#define HAVE_MALLOC_SIZE 1
#define ZMALLOC_LIB ("tcmalloc-" __xstr(TC_VERSION_MAJOR) "." __xstr(TC_VERSION_MINOR))

#define __str(s) #s
#define __xstr(s) __str(s)
#define zmalloc_size(p) tc_malloc_size(p)
#define zmalloc_usable(p) zmalloc_size(p)
#define AL_START_HEAD 0
#define AL_START_TAIL 1
#   define QL_BM_BITS 4
#   define QL_COMP_BITS 14
#   define QL_FILL_BITS 14
#define QUICKLIST_HEAD 0
#define QUICKLIST_NOCOMPRESS 0
#define QUICKLIST_NODE_CONTAINER_NONE 1
#define QUICKLIST_NODE_CONTAINER_ZIPLIST 2
#define QUICKLIST_NODE_ENCODING_LZF 2
#define QUICKLIST_NODE_ENCODING_RAW 1
#define QUICKLIST_TAIL -1

#define quicklistNodeIsCompressed(node)                                        \
    ((node)->encoding == QUICKLIST_NODE_ENCODING_LZF)
