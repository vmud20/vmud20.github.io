
#include<sys/types.h>
#include<string.h>
#include<stdint.h>
#include<stdio.h>
#include<limits.h>


#include<stdlib.h>
#include<malloc.h>

#define lp_free zfree
#define lp_malloc zmalloc
#define lp_realloc zrealloc

#define HAVE_MALLOC_SIZE 1
#define ZMALLOC_LIB ("tcmalloc-" __xstr(TC_VERSION_MAJOR) "." __xstr(TC_VERSION_MINOR))

#define __str(s) #s
#define __xstr(s) __str(s)
#define zmalloc_size(p) tc_malloc_size(p)
#define zmalloc_usable(p) zmalloc_size(p)
#define LP_AFTER 1
#define LP_BEFORE 0
#define LP_INTBUF_SIZE 21 
#define LP_REPLACE 2

