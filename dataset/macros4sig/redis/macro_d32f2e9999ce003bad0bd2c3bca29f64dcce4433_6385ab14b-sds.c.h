#include<limits.h>
#include<stdio.h>
#include<assert.h>
#include<malloc.h>
#include<string.h>
#include<stdlib.h>
#include<stdint.h>


#include<stdarg.h>

#include<ctype.h>
#include<sys/types.h>

#define test_cond(descr,_c) do { \
    __test_num++; printf("%d - %s: ", __test_num, descr); \
    if(_c) printf("PASSED\n"); else {printf("FAILED\n"); __failed_tests++;} \
} while(0)
#define test_report() do { \
    printf("%d tests, %d passed, %d failed\n", __test_num, \
                    __test_num-__failed_tests, __failed_tests); \
    if (__failed_tests) { \
        printf("=== WARNING === We have failed tests here...\n"); \
        exit(1); \
    } \
} while(0)

#define s_free zfree
#define s_free_usable zfree_usable
#define s_malloc zmalloc
#define s_malloc_usable zmalloc_usable
#define s_realloc zrealloc
#define s_realloc_usable zrealloc_usable
#define s_trymalloc ztrymalloc
#define s_trymalloc_usable ztrymalloc_usable
#define s_tryrealloc ztryrealloc
#define s_tryrealloc_usable ztryrealloc_usable

#define HAVE_MALLOC_SIZE 1
#define ZMALLOC_LIB ("tcmalloc-" __xstr(TC_VERSION_MAJOR) "." __xstr(TC_VERSION_MINOR))

#define __str(s) #s
#define __xstr(s) __str(s)
#define zmalloc_size(p) tc_malloc_size(p)
#define zmalloc_usable_size(p) zmalloc_size(p)
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

