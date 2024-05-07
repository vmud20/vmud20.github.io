#include<unistd.h>

#include<fcntl.h>
#include<string.h>

#include<errno.h>
#include<malloc.h>

#include<sys/types.h>
#include<sys/stat.h>

#include<stdio.h>


#include<stdlib.h>
#include<stdbool.h>
#include<inttypes.h>
#define O_BINARY 0

#define SDB_KSZ 0xff
#define SDB_LIST_SORTED 1
#define SDB_LIST_UNSORTED 0
#define SDB_MAX_KEY 0xff
#define SDB_MAX_PATH 256
#define SDB_MAX_VALUE 0xffffff
#define SDB_MIN_KEY 1
#define SDB_MIN_VALUE 1
#define SDB_MODE _S_IWRITE | _S_IREAD
#define SDB_NUM_BASE 16
#define SDB_NUM_BUFSZ 64
#define SDB_OPTION_ALL 0xff
#define SDB_OPTION_FS      (1 << 2)
#define SDB_OPTION_JOURNAL (1 << 3)
#define SDB_OPTION_NONE 0
#define SDB_OPTION_NOSTAMP (1 << 1)
#define SDB_OPTION_SYNC    (1 << 0)
#define SDB_RS ','
#define SDB_SS ","
#define SDB_VSZ 0xffffff
#define SZT_ADD_OVFCHK(x, y) ((SIZE_MAX - (x)) <= (y))
#define sdb_aforeach(x,y) \
	{ char *next; \
	if (y) for (x=y;;) { \
		x = sdb_anext (x, &next);
#define sdb_aforeach_next(x) \
	if (!next) break; \
	*(next-1) = ','; \
	x = next; } }
#define sdb_json_format_free(x) free ((x)->buf)
#define CDB_HPLIST 1000

#define DIRSEP '\\'
#define HAVE_MMAN 0
#define R_FREE(x) { free (x); x = NULL; }
#define R_MAX(x,y) (((x)>(y))?(x):(y))
#define R_MAX_DEFINED 1
#define R_MIN(x,y) (((x)>(y))?(y):(x))
#define R_MIN_DEFINED 1
#define R_NEW(x) (x*)malloc(sizeof(x))
#define R_NEW0(x) (x*)calloc(1, sizeof(x))
#define SDB_API __attribute__((visibility("default")))
#define SDB_IPI static

#define ULLFMT "I64"
#      define UNUSED __attribute__((__unused__))
#define USE_MMAN HAVE_MMAN
#define UT32_MAX ((ut32)0xffffffff)
#define UT64_MAX ((ut64)(0xffffffffffffffffLL))
#define __MINGW__ 1
#define __SDB_WINDOWS__ 1
#define boolt int
#define eprintf(...) fprintf(stderr,__VA_ARGS__)
#define st64 long long
#define ut32 unsigned int
#define ut64 unsigned long long
#define ut8 unsigned char

#define SDB_KEYSIZE 32
#define SDB_KT ut64
#define USE_MONOTONIC_CLOCK 0

#define BUFFER_INIT(op,fd,buf,len) { (buf), 0, (len), (fd), (op) }
#define BUFFER_INSIZE 8192
#define BUFFER_OUTSIZE 8192
#define buffer_GETC(s,c) \
  ( ((s)->p > 0) \
    ? ( *(c) = (s)->x[(s)->n], buffer_SEEK((s),1), 1 ) \
    : buffer_get((s),(c),1) \
  )
#define buffer_PEEK(s) ( (s)->x + (s)->n )
#define buffer_PUTC(s,c) \
  ( ((s)->n != (s)->p) \
    ? ( (s)->x[(s)->p++] = (c), 0 ) \
    : buffer_put((s),&(c),1) \
  )
#define buffer_SEEK(s,len) ( ( (s)->p -= (len) ) , ( (s)->n += (len) ) )

#define CDB_HASHSTART 5381
#define CDB_MAX_KEY 0xff
#define CDB_MAX_VALUE 0xffffff
#define KVLSZ 4
#define cdb_datalen(c) ((c)->dlen)
#define cdb_datapos(c) ((c)->dpos)
#define MHTNO 0
#define MHTSZ 32

#define ls_empty(x) (!x || !x->length)
#define ls_foreach(list, it, pos) \
	if ((list))               \
		for (it = (list)->head; it && (pos = it->data); it = it->n)
#define ls_foreach_prev(list, it, pos) \
	if ((list))                    \
		for (it = list->tail; it && (pos = it->data); it = it->p)
#define ls_foreach_safe(list, it, tmp, pos) \
	if ((list))                         \
		for (it = list->head;       \
		     it && (pos = it->data) && ((tmp = it->n) || 1); it = tmp)
#define ls_head(x) x->head
#define ls_iter_cur(x) x->p
#define ls_iter_get(x) x->data; x=x->n
#define ls_iter_next(x) (x?1:0)
#define ls_iter_unref(x) x
#define ls_iterator(x) (x)?(x)->head:NULL
#define ls_length(x) x->length
#define ls_push(x,y) ls_append(x,y)
#define ls_tail(x) x->tail
#define ls_unref(x) x

#define HT_TYPE 1

#define HT_(name) HtPP##name
#define HT_NULL_VALUE NULL
#define HtName_(name) name##PP
#define Ht_(name) ht_pp_##name
#define KEY_TO_HASH(x) ((ut32)(uintptr_t)(x))
#define KEY_TYPE void *
#define VALUE_TYPE void *
