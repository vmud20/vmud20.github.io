#include<stddef.h>


#include<errno.h>
#include<semaphore.h>
#include<arpa/inet.h>
#include<sys/types.h>


#include<sys/stat.h>


#include<ctype.h>




#include<sys/param.h>


#include<math.h>


#include<sys/ptrace.h>
#include<sys/time.h>


#include<stdlib.h>

#include<stdarg.h>

#include<time.h>





#include<netinet/in.h>
#include<sys/un.h>
#include<stdio.h>

#include<netinet/tcp.h>

#include<sys/socket.h>




#include<stdint.h>




#include<wchar.h>




#include<inttypes.h>



#include<dirent.h>



#include<sys/ioctl.h>
#include<netdb.h>


#include<sched.h>

#include<limits.h>



#include<stdbool.h>


#include<signal.h>
#include<sys/wait.h>
#include<pthread.h>
#include<unistd.h>
#include<fcntl.h>
#include<string.h>
#include<poll.h>
#include<assert.h>
#include<termios.h>



#define NTSTATUS DWORD

#define TEXT(x) (TCHAR*)(x)

#define R_REF_NAME ref
#define R_REF_TYPE RRef R_REF_NAME;
#define USE_DEBUG_REFS 0
#define USE_DEBUG_REFS_MAX 100
#define USE_THREADSAFE_REFS 0
#define r_ref(x) r_ref_((x), (x)?&(x)->R_REF_NAME: NULL)
#define r_ref_count(x) (x)->R_REF_NAME.count
#define r_ref_init(x,y) {\
	(x)->R_REF_NAME.lock = r_th_lock_new (false);\
	(x)->ref.count = 1;\
	(x)->ref.free = (void *)(y);\
}
#define r_ref_set(x,y) do { void *a = r_ref((y)); r_unref(x); x=y; } while(0)
#define r_unref(x) r_unref_(x, (x)?&(x)->R_REF_NAME: NULL)
#define HAVE_PTHREAD 0
#define HAVE_PTHREAD_NP 0
# define HAVE_STDATOMIC_H 0
# define HAVE_TH_LOCAL 0

# define R_ATOMIC_BOOL int
#define R_CRITICAL_ENTER(x) r_th_lock_enter((x)->lock)
#define R_CRITICAL_LEAVE(x) r_th_lock_leave((x)->lock)
#define R_THREAD_LOCK_INIT {0}
#define R_TH_COND_T int
# define R_TH_LOCAL __thread
#define R_TH_LOCK_T int
#define R_TH_SEM_T int
#define R_TH_TID int
#define WANT_THREADS 1




#define r_list_empty(x) (!(x) || !(x)->length)
#define r_list_foreach(list, it, pos)\
	if (list)\
		for (it = list->head; it && (pos = it->data, 1); it = it->n)
#define r_list_foreach_iter(list, it)\
	if (list)\
		for (it = list->head; it; it = it->n)
#define r_list_foreach_prev(list, it, pos)\
	if (list)\
		for (it = list->tail; it && (pos = it->data, 1); it = it->p)
#define r_list_foreach_prev_safe(list, it, tmp, pos) \
	for (it = list->tail; it && (pos = it->data, tmp = it->p, 1); it = tmp)
#define r_list_foreach_safe(list, it, tmp, pos)\
	if (list)\
		for (it = list->head; it && (pos = it->data, tmp = it->n, 1); it = tmp)
#define r_list_head(x) ((x)? (x)->head: NULL)
#define r_list_iter_cur(x) (x)->p
#define r_list_iter_free(x) (x)
#define r_list_iter_get(x) (x)->data; (x)=(x)->n
#define r_list_iter_next(x) ((x)? 1: 0)
#define r_list_iterator(x) (x)? (x)->head: NULL
#define r_list_push(x, y) r_list_append ((x), (y))
#define r_list_tail(x) ((x)? (x)->tail: NULL)
#define r_oflist_append(x, y) r_oflist_deserialize (x), r_list_append (x, y)
#define r_oflist_array(x) x->array? x->array: (x->array = r_oflist_serialize (x)), x->array
#define r_oflist_delete(x, y) r_oflist_deserialize (x), r_list_delete (x, y)
#define r_oflist_deserialize(x)\
	free (x->array - 1), x->array = 0
#define r_oflist_destroy(x) r_oflist_deserialize (x)
#define r_oflist_free(x) r_oflist_deserialize (x), r_list_free (x)
#define r_oflist_length(x, y) r_list_length (x, y)
#define r_oflist_prepend(x, y) r_oflist_deserialize (x), r_list_prepend (x, y)
#define r_oflist_serialize(x)\
	x->array = r_flist_new (r_list_length (x)), { \
		int idx = 0;\
		void *ptr;\
		RListIter *iter;\
		r_list_foreach (x, iter, ptr) r_flist_set (x->array, idx++, ptr);\
	}\
	x->array;
#define BITS2BYTES(x) (((x)/8)+(((x)%8)?1:0))
#define CLOCK_MONOTONIC 0
#define CTA(x,y,z) (x+CTO(y,z))
#define CTI(x,y,z) (*((size_t*)(CTA(x,y,z))))
#define CTO(y,z) ((size_t) &((y*)0)->z)
#define CTS(x,y,z,t,v) {t* _=(t*)CTA(x,y,z);*_=v;}













#define EPRINT_VAR_WRAPPER(name, fmt, ...) {				\
	char *eprint_env = r_sys_getenv ("R2_NO_EPRINT_MACROS");	\
	if (!eprint_env || strcmp (eprint_env, "1")) {			\
		eprintf (#name ": " fmt "\n", __VA_ARGS__);		\
	}								\
	free (eprint_env);						\
}
#define FS '\\'
  #define FUNC_ATTR_ALLOC_ALIGN(x) __attribute__((alloc_align(x)))
  #define FUNC_ATTR_ALLOC_SIZE(x) __attribute__((alloc_size(x)))
  #define FUNC_ATTR_ALLOC_SIZE_PROD(x,y) __attribute__((alloc_size(x,y)))
  #define FUNC_ATTR_ALWAYS_INLINE __attribute__((always_inline))
  #define FUNC_ATTR_CONST __attribute__((const))
  #define FUNC_ATTR_MALLOC __attribute__((malloc))
  #define FUNC_ATTR_PURE __attribute__ ((pure))
  #define FUNC_ATTR_USED __attribute__((used))
  #define FUNC_ATTR_WARN_UNUSED_RESULT __attribute__((warn_unused_result))
# define HAS_CLOCK_MONOTONIC 0
#  define HAS_CLOCK_NANOSLEEP 1
#define HAVE_PTY 0
#define HAVE_REGEXP 0
#define HAVE_SYSTEM 0
#define HHXFMT  "x"
#define LDBLFMT "f"
#define LIBC_HAVE_FORK 1
#define LIBC_HAVE_PLEDGE 1
#define LIBC_HAVE_PRIV_SET 1
#define LIBC_HAVE_PTRACE 0
#define LIBC_HAVE_SYSTEM 0
#define MONOTONIC_APPLE (__APPLE__ && CLOCK_MONOTONIC_RAW)
#define MONOTONIC_FREEBSD (__FreeBSD__ && __FreeBSD_version >= 1101000)
#define MONOTONIC_LINUX (__linux__ && _POSIX_C_SOURCE >= 199309L)
#define MONOTONIC_NETBSD (__NetBSD__ && __NetBSD_Version__ >= 700000000)
#define MONOTONIC_UNIX (MONOTONIC_APPLE || MONOTONIC_LINUX || MONOTONIC_FREEBSD || MONOTONIC_NETBSD)
#define O_BINARY 0
#define PERROR_WITH_FILELINE 0
#define PFMT32d "d"
#define PFMT32o "o"
#define PFMT32u "u"
#define PFMT32x "x"
#define PFMT64d "I64d"
#define PFMT64o "I64o"
#define PFMT64u "I64u"
#define PFMT64x "I64x"
#define PFMTDPTR "td"
#define PFMTSZd "Id"
#define PFMTSZo "Io"
#define PFMTSZu "Iu"
#define PFMTSZx "Ix"
#define R2_DEBUG_EPRINT 0

  #define R2__BSD__ 0
  #define R2__UNIX__ 1
  #define R2__WINDOWS__ 1
    #define R_API __declspec(dllexport)
#define R_ARRAY_SIZE(x) (sizeof (x) / sizeof ((x)[0]))
#define R_BIT_CHK(x,y) (*(x) & (1<<(y)))
#define R_BIT_SET(x,y) (((ut8*)x)[y>>4] |= (1<<(y&0xf)))
#define R_BIT_TOGGLE(x, y) ( R_BIT_CHK (x, y) ? \
		R_BIT_UNSET (x, y): R_BIT_SET (x, y))
#define R_BIT_UNSET(x,y) (((ut8*)x)[y>>4] &= ~(1<<(y&0xf)))
#define R_BORROW 
#  define R_DEPRECATE
#  define R_DEPRECATED __attribute__((deprecated))
#define R_FREE(x) { free((void *)x); x = NULL; }

#define R_HIDDEN __attribute__((visibility("hidden")))
#define R_IFNULL(x) 
#define R_IN 
#define R_INOUT 

#define R_JOIN_2_PATHS(p1, p2) p1 R_SYS_DIR p2
#define R_JOIN_3_PATHS(p1, p2, p3) p1 R_SYS_DIR p2 R_SYS_DIR p3
#define R_JOIN_4_PATHS(p1, p2, p3, p4) p1 R_SYS_DIR p2 R_SYS_DIR p3 R_SYS_DIR p4
#define R_JOIN_5_PATHS(p1, p2, p3, p4, p5) p1 R_SYS_DIR p2 R_SYS_DIR p3 R_SYS_DIR p4 R_SYS_DIR p5
#define R_LIB_VERSION(x) \
R_API const char *x##_version(void) { return "" R2_GITTAP; }
#define R_LIB_VERSION_HEADER(x) \
R_API const char *x##_version(void)
#define R_MEM_ALIGN(x) ((void *)(size_t)(((ut64)(size_t)x) & 0xfffffffffffff000LL))
#define R_MODE_ARRAY 0x010
#define R_MODE_CLASSDUMP 0x040
#define R_MODE_EQUAL 0x080
#define R_MODE_JSON 0x008
#define R_MODE_PRINT 0x000
#define R_MODE_RADARE 0x001
#define R_MODE_SET 0x002
#define R_MODE_SIMPLE 0x004
#define R_MODE_SIMPLEST 0x020
#define R_NEW(x) (x*)malloc(sizeof (x))
#define R_NEW0(x) (x*)calloc(1,sizeof (x))
#define R_NEWCOPY(x,y) (x*)r_new_copy(sizeof (x), y)
#define R_NEWS(x,y) (x*)malloc(sizeof (x)*(y))
#define R_NEWS0(x,y) (x*)calloc(y,sizeof (x))
#define R_NEW_COPY(x,y) x=(void*)malloc(sizeof (y));memcpy(x,y,sizeof (y))
#define R_NONNULL 
#define R_NULLABLE 
#define R_OUT 
#define R_OWN 
#define R_PRINTF_CHECK(fmt, dots) __attribute__ ((format (printf, fmt, dots)))
#define R_PTR_ALIGN(v,t) \
	((char *)(((size_t)(v) ) \
	& ~(t - 1)))
#define R_PTR_ALIGN_NEXT(v,t) \
	((char *)(((size_t)(v) + (t - 1)) \
	& ~(t - 1)))
#define R_PTR_MOVE(d,s) d=s;s=NULL;
# define R_SYS_ARCH "ppc"
# define R_SYS_BASE ((ut64)0x1000)
#  define R_SYS_BITS (R_SYS_BITS_32 | R_SYS_BITS_64)
#define R_SYS_DIR "\\"
#  define R_SYS_ENDIAN 0
#define R_SYS_ENDIAN_BI 3
#define R_SYS_ENDIAN_BIG 2
#define R_SYS_ENDIAN_LITTLE 1
#define R_SYS_ENDIAN_NONE 0
#define R_SYS_ENVSEP ";"
#define R_SYS_HOME "USERPROFILE"
#define R_SYS_OS "qnx"
#define R_SYS_TMP "TEMP"
#define R_UNUSED_RESULT(x) if ((x)) {}
#  define R_WIP __attribute__((deprecated))
#define TARGET_OS_IPHONE 1
#define TODO(x) eprintf(__func__"  " x)
#  define UNUSED_FUNCTION(x) __attribute__((__unused__)) UNUSED_ ## x

#define ZERO_FILL(x) memset (&x, 0, sizeof (x))
#define _FILE_OFFSET_BITS 64
#define __KFBSD__ 1
#define __POWERPC__ 1

#define __func__ __FUNCTION__
#define __i386__ 1
#define __packed __attribute__((__packed__))
#define __x86_64__ 1
#define _perror(str,file,line,func) \
  { \
	  char buf[256]; \
	  snprintf(buf,sizeof (buf),"[%s:%d %s] %s",file,line,func,str); \
	  r_sys_perror_str(buf); \
  }
#define container_of(ptr, type, member) (ptr? ((type *)((char *)(ptr) - r_offsetof(type, member))): NULL)
#define eprintf(...) fprintf (stderr, __VA_ARGS__)
#define mips mips
#define perror(x) _perror(x,"__FILE__","__LINE__",__func__)
#define r_offsetof(type, member) offsetof(type, member)
#define r_sys_perror(x) _perror(x,"__FILE__","__LINE__",__func__)

  #define strcasecmp stricmp
  #define strncasecmp strnicmp
#define typeof(arg) __typeof__(arg)

#define ut8p_b(x) ((x)[0])
#define ut8p_bd(x) ((x)[0]|((x)[1]<<8)|((x)[2]<<16)|((x)[3]<<24))
#define ut8p_bq(x) ((x)[0]|((x)[1]<<8)|((x)[2]<<16)|((x)[3]<<24)|((x)[4]<<32)|((x)[5]<<40)|((x)[6]<<48)|((x)[7]<<56))
#define ut8p_bw(x) ((x)[0]|((x)[1]<<8))
#define ut8p_ld(x) ((x)[3]|((x)[2]<<8)|((x)[1]<<16)|((x)[0]<<24))
#define ut8p_lq(x) ((x)[7]|((x)[6]<<8)|((x)[5]<<16)|((x)[4]<<24)|((x)[3]<<32)|((x)[2]<<40)|((x)[1]<<48)|((x)[0]<<56))
#define ut8p_lw(x) ((x)[1]|((x)[0]<<8))
#define IS_DIGIT(x) ((x) >= '0' && (x) <= '9')
#define IS_HEXCHAR(x) (((x) >= '0' && (x) <= '9') || ((x) >= 'a' && (x) <= 'f') || ((x) >= 'A' && (x) <= 'F'))
#define IS_LOWER(c) ((c) >= 'a' && (c) <= 'z')
#define IS_NULLSTR(x) (!(x) || !*(x))
#define IS_OCTAL(x) ((x) >= '0' && (x) <= '7')
#define IS_PRINTABLE(x) ((x) >=' ' && (x) <= '~')
#define IS_SEPARATOR(x) ((x) == ' ' || (x)=='\t' || (x) == '\n' || (x) == '\r' || (x) == ' '|| \
		(x) == ',' || (x) == ';' || (x) == ':' || (x) == '[' || (x) == ']' || \
		(x) == '(' || (x) == ')' || (x) == '{' || (x) == '}')
#define IS_UPPER(c) ((c) >= 'A' && (c) <= 'Z')
#define IS_WHITECHAR(x) ((x) == ' ' || (x)=='\t' || (x) == '\n' || (x) == '\r')
#define IS_WHITESPACE(x) ((x) == ' ' || (x) == '\t')

#define ASCII_MAX 127
#define ASCII_MIN 32
#define B0000 0
#define B0001 1
#define B0010 2
#define B0011 3
#define B0100 4
#define B0101 5
#define B0110 6
#define B0111 7
#define B1000 8
#define B10000 16
#define B10001 17
#define B1001 9
#define B10010 18
#define B10011 19
#define B1010 10
#define B10100 20
#define B10101 21
#define B1011 11
#define B10110 22
#define B10111 23
#define B1100 12
#define B11000 24
#define B11001 25
#define B1101 13
#define B11010 26
#define B11011 27
#define B1110 14
#define B11100 28
#define B11101 29
#define B1111 15
#define B11110 30
#define B11111 31
#define B4(a,b,c,d) ((a<<12)|(b<<8)|(c<<4)|(d))
#define B_EVEN(x)        (((x) & 1) == 0)
#define B_IS_SET(x, n)   (((x) & (1ULL << (n)))? 1: 0)
#define B_ODD(x)         (!B_EVEN((x)))
#define B_SET(x, n)      ((x) |= (1ULL << (n)))
#define B_TOGGLE(x, n)   ((x) ^= (1ULL << (n)))
#define B_UNSET(x, n)    ((x) &= ~(1ULL << (n)))
#define DEBUGGER 0
#define F128_NAN  (strtold("NAN", NULL))
#define F128_NINF (-strtold("INF", NULL))
#define F128_PINF (strtold("INF", NULL))
#define F32_NAN   (strtof("NAN", NULL))
#define F32_NINF  (-strtof("INF", NULL))
#define F32_PINF  (strtof("INF", NULL))
#define F64_NAN   (strtod("NAN", NULL))
#define F64_NINF  (-strtod("INF", NULL))
#define F64_PINF  (strtod("INF", NULL))
#define HEAPTYPE(x) \
	static x* x##_new(x n) {\
		x *m = malloc(sizeof (x));\
		return m? *m = n, m: m; \
	}
#define INFINITY (1.0f/0.0f)
#define NAN (0.0f/0.0f)

#define R_ABS(x) (((x)<0)?-(x):(x))
# define R_ALIGNED(x) __declspec(align(x))
#define R_BETWEEN(x,y,z) (((y)>=(x)) && ((y)<=(z)))
#define R_BTW(x,y,z) (((x)>=(y))&&((y)<=(z)))?y:x
#define R_DIM(x,y,z) (((x)<(y))?(y):((x)>(z))?(z):(x))
#define R_DIRTY(x) (x)->is_dirty = true
#define R_DIRTY_VAR bool is_dirty
#define R_IGNORE_RETURN(x) if ((x)) {;}
#define R_IS_DIRTY(x) (x)->is_dirty
#define R_LIKELY(x) __builtin_expect((size_t)(x),1)
#define R_MAX(x,y) (((x)>(y))?(x):(y))

#define R_MIN(x,y) (((x)>(y))?(y):(x))

#define R_MUSTUSE __attribute__((warn_unused_result))
#define R_PACKED( __Declaration__ ) __pragma( pack(push, 1) ) __Declaration__ __pragma( pack(pop) )
#define R_ROUND(x,y) ((x)%(y))?(x)+((y)-((x)%(y))):(x)
#define R_UNLIKELY(x) __builtin_expect((size_t)(x),0)
#define R_UNUSED __attribute__((__unused__))
#define R_UNWRAP2(a,b) ((a)? a->b: NULL)
#define R_UNWRAP3(a,b,c) ((a)? a->b? a->b->c: NULL: NULL)
#define R_UNWRAP4(a,b,c,d) ((a)? a->b? a->b->c? a->b->c->d: NULL: NULL: NULL)
#define R_UNWRAP5(a,b,c,d,e) ((a)? a->b? a->b->c? a->b->c->d? a->b->c->d->e: NULL: NULL: NULL: NULL)
#define R_UNWRAP6(a,b,c,d,e,f) ((a)? a->b? a->b->c? a->b->c->d? a->b->c->d->e? a->b->c->d->e: NULL, NULL: NULL: NULL: NULL)
#define R_WEAK __attribute__ ((weak))
#define SSZT_MAX  ST32_MAX
#define SSZT_MIN  ST32_MIN
#define ST16_MAX 0x7FFF
#define ST16_MIN (-ST16_MAX-1)
#define ST32_MAX 0x7FFFFFFF
#define ST32_MIN (-ST32_MAX-1)
#define ST64_MAX ((st64)0x7FFFFFFFFFFFFFFFULL)
#define ST64_MIN ((st64)(-ST64_MAX-1))
#define ST8_MAX  0x7F
#define ST8_MIN  (-ST8_MAX - 1)
#define SZT_MAX  UT32_MAX
#define SZT_MIN  UT32_MIN
#define UT16_ALIGN(x) (x + (x - (x % sizeof (ut16))))
#define UT16_GT0 0x8000U
#define UT16_MAX 0xFFFFU
#define UT16_MIN 0U
#define UT32_ALIGN(x) (x + (x - (x % sizeof (ut32))))
#define UT32_GT0 0x80000000U
#define UT32_HI(x) ((ut32)(((ut64)(x))>>32)&UT32_MAX)
#define UT32_LO(x) ((ut32)((x)&UT32_MAX))
#define UT32_LT0 0x7FFFFFFFU
#define UT32_MAX 0xFFFFFFFFU
#define UT32_MIN 0U
#define UT64_16U 0xFFFFFFFFFFFF0000ULL
#define UT64_32U 0xFFFFFFFF00000000ULL
#define UT64_8U  0xFFFFFFFFFFFFFF00ULL
#define UT64_ALIGN(x) (x + (x - (x % sizeof (ut64))))
#define UT64_GT0 ((ut64)0x8000000000000000ULL)
#define UT64_LT0 ((ut64)0x7FFFFFFFFFFFFFFFULL)
#define UT64_MAX ((ut64)0xFFFFFFFFFFFFFFFFULL)
#define UT64_MIN 0ULL
#define UT8_GT0  0x80U
#define UT8_MAX  0xFFU
#define UT8_MIN  0x00U
#define cut8 const uint8_t
#define st16 int16_t
#define st32 int32_t
#define st64 int64_t
#define st8 int8_t
#define ut16 uint16_t
#define ut32 uint32_t
#define ut64 uint64_t
#define ut8 uint8_t

#define SIGNED_DIV_OVERFLOW_CHECK(overflow_name, type_base, type_mid, type_max) \
static inline bool overflow_name(type_base a, type_base b) { \
	return (!b || (a == type_mid && b == type_max)); \
}
#define SIGNED_MUL_OVERFLOW_CHECK(overflow_name, type_base, type_min, type_max) \
static inline bool overflow_name(type_base a, type_base b) { \
	if (a > 0) { \
		if (b > 0) { return a > type_max / b; } \
		return b < type_min / a; \
	} \
	if (b > 0) { return a < type_min / b; } \
	return a && b < type_max / a; \
}
#define SSZT_ADD_OVFCHK(a,x) ((((x) > 0) && ((a) > SSIZE_MAX - (x))) || (((x) < 0) && (a) < SSIZE_MIN - (x)))
#define SSZT_SUB_OVFCHK(a,b) SSZT_ADD_OVFCHK(a,-(b))
#define ST16_ADD_OVFCHK(a,b) ((((b) > 0) && ((a) > ST16_MAX - (b))) || (((b) < 0) && ((a) < ST16_MIN - (b))))
#define ST16_SUB_OVFCHK(a,b) ST16_ADD_OVFCHK(a,-(b))
#define ST32_ADD_OVFCHK(a,x) ((((x) > 0) && ((a) > ST32_MAX - (x))) || (((x) < 0) && (a) < ST32_MIN - (x)))
#define ST32_SUB_OVFCHK(a,b) ST32_ADD_OVFCHK(a,-(b))
#define ST64_ADD_OVFCHK(a,x) ((((x) > 0) && ((a) > ST64_MAX - (x))) || (((x) < 0) && (a) < ST64_MIN - (x)))
#define ST64_SUB_OVFCHK(a,b) ST64_ADD_OVFCHK(a,-(b))
#define ST8_ADD_OVFCHK(a,x) ((((x) > 0) && ((a) > ST8_MAX - (x))) || ((x) < 0 && (a) < ST8_MIN - (x)))
#define ST8_SUB_OVFCHK(a,b) ST8_ADD_OVFCHK(a,-(b))
#define SZT_ADD_OVFCHK(x,y) ((SIZE_MAX - (x)) < (y))
#define SZT_SUB_OVFCHK(a,b) SZT_ADD_OVFCHK(a,-(b))
#define UNSIGNED_DIV_OVERFLOW_CHECK(overflow_name, type_base, type_min, type_max) \
static inline bool overflow_name(type_base a, type_base b) { \
	(void)(a); \
	return !b; \
}
#define UNSIGNED_MUL_OVERFLOW_CHECK(overflow_name, type_base, type_min, type_max) \
static inline bool overflow_name(type_base a, type_base b) { \
	return (a > 0 && b > 0 && a > type_max / b); \
}
#define UT16_ADD_OVFCHK(x,y) ((UT16_MAX - (x)) < (y))
#define UT16_SUB_OVFCHK(a,b) UT16_ADD_OVFCHK(a,-(b))
#define UT32_ADD_OVFCHK(x,y) ((UT32_MAX - (x)) < (y))
#define UT32_SUB_OVFCHK(a,b) UT32_ADD_OVFCHK(a,-(b))
#define UT64_ADD_OVFCHK(x,y) ((UT64_MAX - (x)) < (y))
#define UT64_SUB_OVFCHK(a,b) UT64_ADD_OVFCHK(a,-(b))
#define UT8_ADD_OVFCHK(x,y) ((UT8_MAX - (x)) < (y))
#define UT8_SUB_OVFCHK(a,b) UT8_ADD_OVFCHK(a,-(b))
#define RNumBig mpz_t





#define R_PJ_H 1
#define R_PRINT_JSON_DEPTH_LIMIT 128

#define R_STRBUF_SAFEGET(sb) (r_strbuf_get (sb) ? r_strbuf_get (sb) : "")

#define CN_BOOL  0x000001
#define CN_INT   0x000002
#define CN_RO    0x000010
#define CN_RW    0x000020
#define CN_STR   0x000008

#define R_CONFIG_NODE_TYPE_BOOL  0x000001
#define R_CONFIG_NODE_TYPE_INT   0x000002
#define R_CONFIG_NODE_TYPE_RO    0x000010
#define R_CONFIG_NODE_TYPE_RW    0x000020
#define R_CONFIG_NODE_TYPE_STR   0x000008
#define ASN1_CLASS    0xC0 
#define ASN1_FORM     0x20 
#define ASN1_JSON_EMPTY "{}"
#define ASN1_JSON_NULL  "null"
#define ASN1_LENLONG  0x80 
#define ASN1_LENSHORT 0x7F 
#define ASN1_OID_LEN  64
#define ASN1_TAG      0x1F 
#define CLASS_APPLICATION  0x40 
#define CLASS_CONTEXT      0x80 
#define CLASS_PRIVATE      0xC0 
#define CLASS_UNIVERSAL    0x00 
#define FORM_CONSTRUCTED   0x20 
#define FORM_PRIMITIVE     0x00 

#define TAG_BITSTRING       0x03 
#define TAG_BMPSTRING       0x1E 
#define TAG_BOOLEAN         0x01 
#define TAG_EMBEDDED_PDV    0x0B 
#define TAG_ENUMERATED      0x0A 
#define TAG_EOC             0x00 
#define TAG_EXTERNAL        0x08 
#define TAG_GENERALIZEDTIME 0x18 
#define TAG_GENERALSTRING   0x1B 
#define TAG_GRAPHICSTRING   0x19 
#define TAG_IA5STRING       0x16 
#define TAG_INTEGER         0x02 
#define TAG_NULL            0x05 
#define TAG_NUMERICSTRING   0x12 
#define TAG_OBJDESCRIPTOR   0x07 
#define TAG_OCTETSTRING     0x04 
#define TAG_OID             0x06 
#define TAG_PRINTABLESTRING 0x13 
#define TAG_REAL            0x09 
#define TAG_SEQUENCE        0x10 
#define TAG_SET             0x11 
#define TAG_T61STRING       0x14 
#define TAG_UNIVERSALSTRING 0x1C 
#define TAG_UTCTIME         0x17 
#define TAG_UTF8STRING      0x0C 
#define TAG_VIDEOTEXSTRING  0x15 
#define TAG_VISIBLESTRING   0x1A 







#define r_acp_to_utf8(str) r_acp_to_utf8_l ((char *)str, -1)
#define r_utf16_to_utf8(wc) r_utf16_to_utf8_l ((wchar_t *)wc, -1)
#define r_utf8_to_acp(cstring) r_utf8_to_acp_l ((char *)cstring, -1)
#define r_utf8_to_utf16(cstring) r_utf8_to_utf16_l ((char *)cstring, -1)


#define R_SYS_BITS_CHECK(x, y) (bool)( \
	(((x) & R_SYS_BITS_MASK) == (y)) || \
	((((x) >> R_SYS_BITS_SIZE) & R_SYS_BITS_MASK) == (y)) || \
	((((x) >> (R_SYS_BITS_SIZE*2)) & R_SYS_BITS_MASK) == (y)) || \
	((((x) >> (R_SYS_BITS_SIZE*3)) & R_SYS_BITS_MASK) == (y)) \
)
#define R_SYS_BITS_MASK 0xff
#define R_SYS_BITS_PACK(x) (RSysBits)(x)
#define R_SYS_BITS_PACK1(x) (RSysBits)(x)
#define R_SYS_BITS_PACK2(x,y) (RSysBits)((x) | ((y)<<R_SYS_BITS_SIZE))
#define R_SYS_BITS_PACK3(x,y,z) (RSysBits)((x) | ((y)<<R_SYS_BITS_SIZE) | ((z) << (R_SYS_BITS_SIZE*2)))
#define R_SYS_BITS_PACK4(x,y,z,q) (RSysBits)((x) | ((y)<<R_SYS_BITS_SIZE) | ((z) << (R_SYS_BITS_SIZE*2)) | ((q) << (R_SYS_BITS_SIZE*3)) )
#define R_SYS_BITS_SIZE 8
#define R_SYS_DEVNULL "/dev/null"

#define W32_TCALL(name) name"W"
#define W32_TCHAR_FSTR "%S"
#    define r_sys_breakpoint() __asm__ volatile ("bkpt $0");
#define r_sys_conv_utf8_to_win(buf) r_utf8_to_utf16 (buf)
#define r_sys_conv_utf8_to_win_l(buf, len) r_utf8_to_utf16_l (buf, len)
#define r_sys_conv_win_to_utf8(buf) r_utf16_to_utf8 (buf)
#define r_sys_conv_win_to_utf8_l(buf, len) r_utf16_to_utf8_l ((wchar_t *)buf, len)
#define r_sys_mkdir_failed() (GetLastError () != ERROR_ALREADY_EXISTS)
#  define r_sys_trap() __asm__ __volatile__ (".word 0");


#define R_STRPOOL_INC 1024

#define R_STR_DUP(x) (((x) != NULL) ? strdup ((x)) : NULL)

#define R_STR_ISEMPTY(x) (!(x) || !*(x))
#define R_STR_ISNOTEMPTY(x) ((x) && *(x))
#define r_str_array(x,y) ((y >= 0 && y < (sizeof (x) / sizeof (*(x))))?(x)[(y)]: "")
#define r_str_cat(x,y) memmove ((x) + strlen (x), (y), strlen (y) + 1);
#define r_str_cpy(x,y) memmove ((x), (y), strlen (y) + 1);
#define r_str_startswith r_str_startswith_inline
#define r_strf(s,...) (snprintf (strbuf, sizeof (strbuf), s, __VA_ARGS__)?strbuf: strbuf)
#define r_strf_buffer(s) char strbuf[s]
#define r_strf_var(n,s, f, ...) char n[s]; snprintf (n, s, f, __VA_ARGS__);


#define R_SPACES_MAX 512
#define r_spaces_foreach(sp, it, s) \
	r_crbtree_foreach ((sp)->spaces, (it), RSpace, (s))

#define HAVE_CAPSICUM 1
#define R_SANDBOX_GRAIN_ALL (8|4|2|1)
#define R_SANDBOX_GRAIN_DISK (2)
#define R_SANDBOX_GRAIN_EXEC (8)
#define R_SANDBOX_GRAIN_FILES (4)
#define R_SANDBOX_GRAIN_NONE (0)
#define R_SANDBOX_GRAIN_SOCKET (1)



#define Color_BGDELETE "\x1b[48;5;52m"
#define Color_BGINSERT "\x1b[48;5;22m"
#define Color_DELETE Color_BRED
#define Color_HLDELETE Color_BGDELETE Color_DELETE
#define Color_HLINSERT Color_BGINSERT Color_INSERT
#define Color_INSERT Color_BGREEN

#define ARROW_LEFT 9
#define ARROW_RIGHT 8
#define CONS_BUFSZ 0x4f00
#define CONS_COLORS_SIZE 21
#define CONS_MAX_ATTR_SZ 16
#define CONS_PALETTE_SIZE 22
#define CORNER_BL 5
#define CORNER_BR 4
#define CORNER_TL 6
#define CORNER_TR 6
#define Color_BBGBLACK   Color_BGGRAY
#define Color_BBGBLUE    "\x1b[104m"
#define Color_BBGCYAN    "\x1b[106m"
#define Color_BBGGREEN   "\x1b[102m"
#define Color_BBGMAGENTA "\x1b[105m"
#define Color_BBGRED     "\x1b[101m"
#define Color_BBGWHITE   "\x1b[107m"
#define Color_BBGYELLOW  "\x1b[103m"
#define Color_BBLACK     Color_GRAY
#define Color_BBLUE      "\x1b[94m"
#define Color_BCYAN      "\x1b[96m"
#define Color_BGBLACK    "\x1b[40m"
#define Color_BGBLUE     "\x1b[44m"
#define Color_BGCYAN     "\x1b[46m"
#define Color_BGGRAY     "\x1b[100m"
#define Color_BGGREEN    "\x1b[42m"
#define Color_BGMAGENTA  "\x1b[45m"
#define Color_BGRED      "\x1b[41m"
#define Color_BGREEN     "\x1b[92m"
#define Color_BGWHITE    "\x1b[47m"
#define Color_BGYELLOW   "\x1b[43m"
#define Color_BLACK      "\x1b[30m"
#define Color_BLINK        "\x1b[5m"
#define Color_BLUE       "\x1b[34m"
#define Color_BMAGENTA   "\x1b[95m"
#define Color_BRED       "\x1b[91m"
#define Color_BWHITE     "\x1b[97m"
#define Color_BYELLOW    "\x1b[93m"
#define Color_CYAN       "\x1b[36m"
#define Color_GRAY       "\x1b[90m"
#define Color_GREEN      "\x1b[32m"
#define Color_INVERT       "\x1b[7m"
#define Color_INVERT_RESET "\x1b[27m"
#define Color_MAGENTA    "\x1b[35m"
#define Color_RED        "\x1b[31m"
#define Color_RESET      "\x1b[0m" 
#define Color_RESET_BG   "\x1b[49m" 
#define Color_RESET_NOBG "\x1b[27;22;24;25;28;39m"  
#define Color_RESET_TERMINAL  "\x1b" "c\x1b(K\x1b[0m\x1b[J\x1b[?25h"
#define Color_WHITE      "\x1b[37m"
#define Color_YELLOW     "\x1b[33m"
#define Colors_PLAIN { \
	Color_BLACK, Color_RED, Color_WHITE, \
	Color_GREEN, Color_MAGENTA, Color_YELLOW, \
	Color_CYAN, Color_BLUE, Color_GRAY}
#define DOT_STYLE_BACKEDGE 2
#define DOT_STYLE_CONDITIONAL 1
#define DOT_STYLE_NORMAL 0
# define ENABLE_VIRTUAL_TERMINAL_INPUT 0x0200
# define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#define HUD_BUF_SIZE 512
#define LINE_CROSS 1
#define LINE_HORIZ 2
#define LINE_UP 3
#define LINE_VERT 0

#define RCOLOR(a, r, g, b, bgr, bgg, bgb, id16) {0, a, r, g, b, bgr, bgg, bgb, id16}
#define RColor_BBGBLACK   RCOLOR(ALPHA_BG, 0x80, 0x80, 0x80, 0x00, 0x00, 0x00,  8)
#define RColor_BBGBLUE    RCOLOR(ALPHA_BG, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 12)
#define RColor_BBGCYAN    RCOLOR(ALPHA_BG, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 14)
#define RColor_BBGGREEN   RCOLOR(ALPHA_BG, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 10)
#define RColor_BBGMAGENTA RCOLOR(ALPHA_BG, 0xff, 0x00, 0xff, 0x00, 0x00, 0x00, 13)
#define RColor_BBGRED     RCOLOR(ALPHA_BG, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,  9)
#define RColor_BBGWHITE   RCOLOR(ALPHA_BG, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 15)
#define RColor_BBGYELLOW  RCOLOR(ALPHA_BG, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 11)
#define RColor_BBLACK     RCOLOR(ALPHA_FG, 0x80, 0x80, 0x80, 0x00, 0x00, 0x00,  8)
#define RColor_BBLUE      RCOLOR(ALPHA_FG, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 12)
#define RColor_BCYAN      RCOLOR(ALPHA_FG, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 14)
#define RColor_BGBLACK    RCOLOR(ALPHA_BG, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0)
#define RColor_BGBLUE     RCOLOR(ALPHA_BG, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,  4)
#define RColor_BGCYAN     RCOLOR(ALPHA_BG, 0x00, 0x80, 0x80, 0x00, 0x00, 0x00,  6)
#define RColor_BGGRAY     RColor_BBGBLACK
#define RColor_BGGREEN    RCOLOR(ALPHA_BG, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00,  2)
#define RColor_BGMAGENTA  RCOLOR(ALPHA_BG, 0x80, 0x00, 0x80, 0x00, 0x00, 0x00,  5)
#define RColor_BGRED      RCOLOR(ALPHA_BG, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,  1)
#define RColor_BGREEN     RCOLOR(ALPHA_FG, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 10)
#define RColor_BGWHITE    RCOLOR(ALPHA_BG, 0xc0, 0xc0, 0xc0, 0x00, 0x00, 0x00,  7)
#define RColor_BGYELLOW   RCOLOR(ALPHA_BG, 0x80, 0x80, 0x00, 0x00, 0x00, 0x00,  3)
#define RColor_BLACK      RCOLOR(ALPHA_FG, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0)
#define RColor_BLUE       RCOLOR(ALPHA_FG, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,  4)
#define RColor_BMAGENTA   RCOLOR(ALPHA_FG, 0xff, 0x00, 0xff, 0x00, 0x00, 0x00, 13)
#define RColor_BRED       RCOLOR(ALPHA_FG, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,  9)
#define RColor_BWHITE     RCOLOR(ALPHA_FG, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 15)
#define RColor_BYELLOW    RCOLOR(ALPHA_FG, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 11)
#define RColor_CYAN       RCOLOR(ALPHA_FG, 0x00, 0x80, 0x80, 0x00, 0x00, 0x00,  6)
#define RColor_GRAY       RColor_BBLACK
#define RColor_GREEN      RCOLOR(ALPHA_FG, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00,  2)
#define RColor_MAGENTA    RCOLOR(ALPHA_FG, 0x80, 0x00, 0x80, 0x00, 0x00, 0x00,  5)
#define RColor_NULL       RCOLOR(0x00,     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, -1)
#define RColor_RED        RCOLOR(ALPHA_FG, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,  1)
#define RColor_WHITE      RCOLOR(ALPHA_FG, 0xc0, 0xc0, 0xc0, 0x00, 0x00, 0x00,  7)
#define RColor_YELLOW     RCOLOR(ALPHA_FG, 0x80, 0x80, 0x00, 0x00, 0x00, 0x00,  3)
#define RUNECODESTR_ARROW_LEFT "\xcd"
#define RUNECODESTR_ARROW_RIGHT "\xcc"
#define RUNECODESTR_CORNER_BL "\xcb"
#define RUNECODESTR_CORNER_BR "\xca"
#define RUNECODESTR_CORNER_TL "\xcf"
#define RUNECODESTR_CORNER_TR "\xd0"
#define RUNECODESTR_CURVE_CORNER_BL "\xd5"
#define RUNECODESTR_CURVE_CORNER_BR "\xd4"
#define RUNECODESTR_CURVE_CORNER_TL "\xd2"
#define RUNECODESTR_CURVE_CORNER_TR "\xd3"
#define RUNECODESTR_LINE_CROSS "\xc9"
#define RUNECODESTR_LINE_HORIZ "\xce"
#define RUNECODESTR_LINE_UP "\xd1"
#define RUNECODESTR_LINE_VERT "\xc8"
#define RUNECODESTR_MAX 0xd5
#define RUNECODESTR_MIN 0xc8 
#define RUNECODE_ARROW_LEFT 0xcd
#define RUNECODE_ARROW_RIGHT 0xcc
#define RUNECODE_CORNER_BL 0xcb
#define RUNECODE_CORNER_BR 0xca
#define RUNECODE_CORNER_TL 0xcf
#define RUNECODE_CORNER_TR 0xd0
#define RUNECODE_CURVE_CORNER_BL 0xd5
#define RUNECODE_CURVE_CORNER_BR 0xd4
#define RUNECODE_CURVE_CORNER_TL 0xd2
#define RUNECODE_CURVE_CORNER_TR 0xd3
#define RUNECODE_LINE_CROSS 0xc9
#define RUNECODE_LINE_HORIZ 0xce
#define RUNECODE_LINE_UP 0xd1
#define RUNECODE_LINE_VERT 0xc8
#define RUNECODE_MAX 0xd6
#define RUNECODE_MIN 0xc8 
#define RUNE_ARROW_LEFT "<"
#define RUNE_ARROW_RIGHT ">"
#define RUNE_CORNER_BL "└"
#define RUNE_CORNER_BR "┘"
#define RUNE_CORNER_TL "┌"
#define RUNE_CORNER_TR "┐"
#define RUNE_CURVE_CORNER_BL "╰"
#define RUNE_CURVE_CORNER_BR "╯"
#define RUNE_CURVE_CORNER_TL "╭"
#define RUNE_CURVE_CORNER_TR "╮"
#define RUNE_LINE_CROSS "┼" 
#define RUNE_LINE_HORIZ "─"
#define RUNE_LINE_UP "↑"
#define RUNE_LINE_VERT "│"
#define RUNE_LONG_LINE_HORIZ "―"
#define R_CONS_CLEAR_FROM_CURSOR_TO_END "\x1b[0J\r"
#define R_CONS_CLEAR_FROM_CURSOR_TO_EOL "\x1b[0K\r"
#define R_CONS_CLEAR_LINE "\x1b[2K\r"
#define R_CONS_CLEAR_SCREEN "\x1b[2J\r"
#define R_CONS_CMD_DEPTH 100
#define R_CONS_CURSOR_DOWN "\x1b[B"
#define R_CONS_CURSOR_LEFT "\x1b[D"
#define R_CONS_CURSOR_RESTORE "\x1b[u"
#define R_CONS_CURSOR_RIGHT "\x1b[C"
#define R_CONS_CURSOR_SAVE "\x1b[s"
#define R_CONS_CURSOR_UP "\x1b[A"
#define R_CONS_GET_CURSOR_POSITION "\x1b[6n"
#define R_CONS_GREP_COUNT 10
#define R_CONS_GREP_TOKENS 64
#define R_CONS_GREP_WORDS 10
#define R_CONS_GREP_WORD_SIZE 64
#define R_CONS_INVERT(x,y) (y? (x?Color_INVERT: Color_INVERT_RESET): (x?"[":"]"))
#define R_CONS_KEY_ESC 0x1b
#define R_CONS_KEY_F1 0xf1
#define R_CONS_KEY_F10 0xfa
#define R_CONS_KEY_F11 0xfb
#define R_CONS_KEY_F12 0xfc
#define R_CONS_KEY_F2 0xf2
#define R_CONS_KEY_F3 0xf3
#define R_CONS_KEY_F4 0xf4
#define R_CONS_KEY_F5 0xf5
#define R_CONS_KEY_F6 0xf6
#define R_CONS_KEY_F7 0xf7
#define R_CONS_KEY_F8 0xf8
#define R_CONS_KEY_F9 0xf9
#define R_EDGES_X_INC 4
#define R_LINE_BUFSIZE 4096
#define R_LINE_HISTSIZE 256
#define R_SELWIDGET_DIR_DOWN 1
#define R_SELWIDGET_DIR_UP 0
#define R_SELWIDGET_MAXH 15
#define R_SELWIDGET_MAXW 30
#define R_UTF8_BLOCK "\u2588"
#define R_UTF8_CIRCLE "\u25EF"
#define R_UTF8_DOOR "🚪"
#define R_UTF8_KEYBOARD "⌨"
#define R_UTF8_LEFT_POINTING_MAGNIFYING_GLASS "🔍"
#define R_UTF8_POLICE_CARS_REVOLVING_LIGHT "🚨"
#define R_UTF8_SEE_NO_EVIL_MONKEY "🙈"
#define R_UTF8_SKULL_AND_CROSSBONES "☠"
#define R_UTF8_VS16 "\xef\xb8\x8f"
#define R_UTF8_WHITE_HEAVY_CHECK_MARK "✅"
#define STR_IS_NULL(x) (!x || !x[0])
#define r_cons_print(x) r_cons_strcat (x)

#define r_pvector_foreach(vec, it) \
	if ((vec)->v.len > 0) \
	for (it = (void **)(vec)->v.a; it != (void **)(vec)->v.a + (vec)->v.len; it++)
#define r_pvector_foreach_prev(vec, it) \
	if ((vec)->v.len > 0) \
	for (it = ((vec)->v.len == 0 ? NULL : (void **)(vec)->v.a + (vec)->v.len - 1); it != NULL && it != (void **)(vec)->v.a - 1; it--)
#define r_pvector_lower_bound(vec, x, i, cmp) \
	do { \
		size_t h = (vec)->v.len, m; \
		for (i = 0; i < h; ) { \
			m = i + ((h - i) >> 1); \
			if ((cmp ((x), ((void **)(vec)->v.a)[m])) > 0) { \
				i = m + 1; \
			} else { \
				h = m; \
			} \
		} \
	} while (0) \

#define r_vector_enumerate(vec, it, i) \
	if (!r_vector_empty (vec)) \
		for (it = (void *)(vec)->a, i = 0; i < (vec)->len; it = (void *)((char *)it + (vec)->elem_size), i++)
#define r_vector_foreach(vec, it) \
	if (!r_vector_empty (vec)) \
		for (it = (void *)(vec)->a; (char *)it != (char *)(vec)->a + ((vec)->len * (vec)->elem_size); it = (void *)((char *)it + (vec)->elem_size))
#define r_vector_foreach_prev(vec, it) \
	if (!r_vector_empty (vec)) \
		for (it = (void *)((char *)(vec)->a + (((vec)->len - 1)* (vec)->elem_size)); (char *)it != (char *)(vec)->a; it = (void *)((char *)it - (vec)->elem_size))
#define r_vector_lower_bound(vec, x, i, cmp) \
	do { \
		size_t h = (vec)->len, m; \
		for (i = 0; i < h; ) { \
			m = i + ((h - i) >> 1); \
			if ((cmp (x, ((char *)(vec)->a + (vec)->elem_size * m))) > 0) { \
				i = m + 1; \
			} else { \
				h = m; \
			} \
		} \
	} while (0) \

#define r_vector_upper_bound(vec, x, i, cmp) \
	do { \
		size_t h = (vec)->len, m; \
		for (i = 0; i < h; ) { \
			m = i + ((h - i) >> 1); \
			if ((cmp (x, ((char *)(vec)->a + (vec)->elem_size * m))) < 0) { \
				h = m; \
			} else { \
				i = m + 1; \
			} \
		} \
	} while (0) \

#define H_LOG_(loglevel, fmt, ...)

#define R_CHECKS_LEVEL 2
#define R_FUNCTION ((const char*) (__PRETTY_FUNCTION__))
#define R_STATIC_ASSERT(x) switch (0) { case 0: case (x):; }
#define r_return_if_fail(expr) do { assert (expr); } while(0)
#define r_return_if_reached() \
	do { \
		H_LOG_ (R_LOGLVL_ERROR, "file %s: line %d (%s): should not be reached", "__FILE__", "__LINE__", R_FUNCTION); \
		return; \
	} while (0)
#define r_return_val_if_fail(expr, val) do { assert (expr); } while(0)
#define r_return_val_if_reached(val) \
	do { \
		H_LOG_ (R_LOGLVL_ERROR, "file %s: line %d (%s): should not be reached", "__FILE__", "__LINE__", R_FUNCTION); \
		return (val); \
	} while (0)
#define r_warn_if_fail(expr) \
	do { \
		if (!(expr)) { \
			r_assert_log (R_LOGLVL_WARN, R_LOG_ORIGIN, "WARNING (%s:%d):%s%s runtime check failed: (%s)", \
				"__FILE__", "__LINE__", R_FUNCTION, R_FUNCTION[0] ? ":" : "", #expr); \
		} \
	} while (0)
#define r_warn_if_reached() \
	do { \
		r_assert_log (R_LOGLVL_WARN, R_LOG_ORIGIN, "(%s:%d):%s%s code should not be reached", \
			"__FILE__", "__LINE__", R_FUNCTION, R_FUNCTION[0] ? ":" : ""); \
	} while (0)

#define SHELL_PATH "/bin/sh"
#define TERMUX_PREFIX "/data/data/com.termux/files/usr"

#define R_NUMCALC_STRSZ 1024

#define R_LOG(f,...) do {} while(0)
#define R_LOGLVL_DEFAULT R_LOGLVL_WARN
#define R_LOG_DEBUG(f,...) do {} while(0)
#define R_LOG_DISABLE 0
#define R_LOG_ERROR(f,...) do {} while(0)
#define R_LOG_FATAL(f,...) do {} while(0)

#define R_LOG_INFO(f,...) do {} while(0)
#define R_LOG_ORIGIN __FUNCTION__
#define R_LOG_SOURCE "__FILE__"
#define R_LOG_TODO(f,...) do {} while(0)
#define R_LOG_WARN(f,...) do {} while(0)
#define etrace(m) eprintf ("--> %s:%d : %s\n", __FUNCTION__, "__LINE__", m)







#define ASCTIME_BUF_MAXLEN (26)

#define R_NSEC_PER_MSEC 1000000ULL
#define R_NSEC_PER_SEC  1000000000ULL
#define R_NSEC_PER_USEC 1000ULL
#define R_TIME_PROFILE_BEGIN ut64 __now__ = r_time_now_mono()
#define R_TIME_PROFILE_ENABLED 0
#define R_TIME_PROFILE_END eprintf ("%s %"PFMT64d"\n", __FUNCTION__, r_time_now_mono() - __now__)
#define R_USEC_PER_MSEC 1000ULL
#define R_USEC_PER_SEC  1000000ULL
#define BITWORD_BITS_SHIFT 5
#define RBitword ut32

#define R_BUF_CUR 1
#define R_BUF_END 2

#define R_BUF_SET 0



#define r_interval_tree_foreach(tree, it, dat) \
	if ((tree)->root) \
	for ((it) = r_rbtree_first (&(tree)->root->node); r_rbtree_iter_has (&it) && (dat = r_interval_tree_iter_get (&it)->data); r_rbtree_iter_next (&(it)))
#define r_interval_tree_foreach_prev(tree, it, dat) \
	if ((tree)->root) \
	for ((it) = r_rbtree_last (&(tree)->root->node); r_rbtree_iter_has (&it) && (dat = r_rbtree_iter_get (&it, RIntervalNode, node)->data); r_rbtree_iter_prev (&(it)))

#define r_crbtree_foreach(tree, iter, type, stuff) \
	for (iter = (tree != NULL)? r_crbtree_first_node (tree): NULL, stuff = (type*)((iter != NULL)? iter->data: NULL); iter; iter = r_rbnode_next (iter), stuff = (type*)((iter != NULL)? iter->data: NULL))

#define R_RBTREE_MAX_HEIGHT 62
#define r_rbtree_foreach(root, it, data, struc, rb) \
	for ((it) = r_rbtree_first (root); r_rbtree_iter_has(&it) && (data = r_rbtree_iter_get (&it, struc, rb)); r_rbtree_iter_next (&(it)))
#define r_rbtree_foreach_prev(root, it, data, struc, rb) \
	for ((it) = r_rbtree_last (root); r_rbtree_iter_has(&it) && (data = r_rbtree_iter_get (&it, struc, rb)); r_rbtree_iter_prev (&(it)))
#define r_rbtree_iter_get(it, struc, rb) (container_of ((it)->path[(it)->len-1], struc, rb))
#define r_rbtree_iter_has(it) ((it)->len)
#define r_rbtree_iter_while(it, data, struc, rb) \
	for (; r_rbtree_iter_has(&it) && (data = r_rbtree_iter_get (&it, struc, rb)); r_rbtree_iter_next (&(it)))
#define r_rbtree_iter_while_prev(it, data, struc, rb) \
	for (; r_rbtree_iter_has(&it) && (data = r_rbtree_iter_get (&it, struc, rb)); r_rbtree_iter_prev (&(it)))
#define R_MALLOC_GLOBAL 0
#define R_MALLOC_WRAPPER 0
#define _R_UTIL_ALLOC_H_ 1
#define _r_calloc r_calloc
#define _r_free r_free
#define _r_malloc r_malloc
#define _r_realloc r_realloc
#define r_calloc(x,y) calloc((x),(y))
#define r_free(x) free((x))
#define r_malloc(x) malloc((x))
#define r_realloc(x,y) realloc((x),(y))



#define r_skiplist_foreach(list, it, pos)\
	if (list)\
		for (it = list->head->forward[0]; it != list->head && ((pos = it->data) || 1); it = it->forward[0])
#define r_skiplist_foreach_safe(list, it, tmp, pos)\
	if (list)\
		for (it = list->head->forward[0]; it != list->head && ((pos = it->data) || 1) && ((tmp = it->forward[0]) || 1); it = tmp)
#define r_skiplist_islast(list, el) (el->forward[0] == list->head)
#define r_skiplist_length(list) (list->size)
#define R_GETOPT_H 1

#define RBinSectionName r_offsetof(RBinSection, name)
#define RBinSectionOffset r_offsetof(RBinSection, offset)
#define REBASE_PADDR(o, l, type_t)\
	do { \
		RListIter *_it;\
		type_t *_el;\
		r_list_foreach ((l), _it, _el) { \
			_el->paddr += (o)->loadaddr;\
		}\
	} while (0)
#define R_BIN_BIND_GLOBAL_STR "GLOBAL"
#define R_BIN_BIND_HIOS_STR "HIOS"
#define R_BIN_BIND_HIPROC_STR "HIPROC"
#define R_BIN_BIND_LOCAL_STR "LOCAL"
#define R_BIN_BIND_LOOS_STR "LOOS"
#define R_BIN_BIND_LOPROC_STR "LOPROC"
#define R_BIN_BIND_NUM_STR "NUM"
#define R_BIN_BIND_UNKNOWN_STR "UNKNOWN"
#define R_BIN_BIND_WEAK_STR "WEAK"
#define R_BIN_DBG_LINENUMS 0x04
#define R_BIN_DBG_RELOCS   0x10
#define R_BIN_DBG_STATIC   0x02
#define R_BIN_DBG_STRIPPED 0x01
#define R_BIN_DBG_SYMS     0x08
#define R_BIN_ENTRY_TYPE_FINI    3
#define R_BIN_ENTRY_TYPE_INIT    2
#define R_BIN_ENTRY_TYPE_MAIN    1
#define R_BIN_ENTRY_TYPE_PREINIT 5
#define R_BIN_ENTRY_TYPE_PROGRAM 0
#define R_BIN_ENTRY_TYPE_TLS     4
#define R_BIN_MAX_ARCH 1024
#define R_BIN_METH_ABSTRACT 0x0000000000001000L
#define R_BIN_METH_BRIDGE 0x0000000000008000L
#define R_BIN_METH_CLASS 0x0000000000000001L
#define R_BIN_METH_CONST 0x0000000000000400L
#define R_BIN_METH_CONSTRUCTOR 0x0000000000100000L
#define R_BIN_METH_DECLARED_SYNCHRONIZED 0x0000000000200000L
#define R_BIN_METH_FILEPRIVATE 0x0000000000000080L
#define R_BIN_METH_FINAL 0x0000000000000100L
#define R_BIN_METH_INTERNAL 0x0000000000000020L
#define R_BIN_METH_MIRANDA 0x0000000000080000L
#define R_BIN_METH_MUTATING 0x0000000000000800L
#define R_BIN_METH_NATIVE 0x0000000000004000L
#define R_BIN_METH_OPEN 0x0000000000000040L
#define R_BIN_METH_PRIVATE 0x0000000000000008L
#define R_BIN_METH_PROTECTED 0x0000000000000010L
#define R_BIN_METH_PUBLIC 0x0000000000000004L
#define R_BIN_METH_STATIC 0x0000000000000002L
#define R_BIN_METH_STRICT 0x0000000000040000L
#define R_BIN_METH_SYNCHRONIZED 0x0000000000002000L
#define R_BIN_METH_SYNTHETIC 0x0000000000020000L
#define R_BIN_METH_VARARGS 0x0000000000010000L
#define R_BIN_METH_VIRTUAL 0x0000000000000200L
#define R_BIN_REQ_ALL       UT64_MAX
#define R_BIN_REQ_CLASSES   0x010000
#define R_BIN_REQ_CREATE    0x008000
#define R_BIN_REQ_DLOPEN    0x200000
#define R_BIN_REQ_DWARF     0x020000
#define R_BIN_REQ_ENTRIES   0x000001
#define R_BIN_REQ_EXPORTS   0x400000
#define R_BIN_REQ_EXTRACT   0x001000
#define R_BIN_REQ_FIELDS    0x000100
#define R_BIN_REQ_HASHES    0x40000000
#define R_BIN_REQ_HEADER    0x2000000
#define R_BIN_REQ_HELP      0x000040
#define R_BIN_REQ_IMPORTS   0x000002
#define R_BIN_REQ_INFO      0x000010
#define R_BIN_REQ_INITFINI  0x10000000
#define R_BIN_REQ_LIBS      0x000200
#define R_BIN_REQ_LISTARCHS 0x004000
#define R_BIN_REQ_LISTPLUGINS 0x4000000
#define R_BIN_REQ_MAIN      0x000800
#define R_BIN_REQ_OPERATION 0x000020
#define R_BIN_REQ_PACKAGE   0x1000000
#define R_BIN_REQ_PDB       0x080000
#define R_BIN_REQ_PDB_DWNLD 0x100000
#define R_BIN_REQ_RELOCS    0x002000
#define R_BIN_REQ_RESOURCES 0x8000000
#define R_BIN_REQ_SECTIONS  0x000008
#define R_BIN_REQ_SECTIONS_MAPPING 0x200000000
#define R_BIN_REQ_SEGMENTS  0x20000000
#define R_BIN_REQ_SIGNATURE 0x80000000
#define R_BIN_REQ_SIZE      0x040000
#define R_BIN_REQ_SRCLINE   0x000400
#define R_BIN_REQ_STRINGS   0x000080
#define R_BIN_REQ_SYMBOLS   0x000004
#define R_BIN_REQ_TRYCATCH 0x100000000
#define R_BIN_REQ_UNK       0x000000
#define R_BIN_REQ_VERSIONINFO 0x800000
#define R_BIN_SIZEOF_STRINGS 512
#define R_BIN_TYPE_COMMON_STR "COMMON"
#define R_BIN_TYPE_FILE_STR "FILE"
#define R_BIN_TYPE_FUNC_STR "FUNC"
#define R_BIN_TYPE_HIOS_STR "HIOS"
#define R_BIN_TYPE_HIPROC_STR "HIPROC"
#define R_BIN_TYPE_LOOS_STR "LOOS"
#define R_BIN_TYPE_LOPROC_STR "LOPROC"
#define R_BIN_TYPE_METH_STR "METH"
#define R_BIN_TYPE_NOTYPE_STR "NOTYPE"
#define R_BIN_TYPE_NUM_STR "NUM"
#define R_BIN_TYPE_OBJECT_STR "OBJ"
#define R_BIN_TYPE_SECTION_STR "SECT"
#define R_BIN_TYPE_SPECIAL_SYM_STR "SPCL"
#define R_BIN_TYPE_STATIC_STR "STATIC"
#define R_BIN_TYPE_TLS_STR "TLS"
#define R_BIN_TYPE_UNKNOWN_STR "UNK"
#define FILE_NAME_LEN 256


#define DW_ACCESS_private               0x03
#define DW_ACCESS_protected             0x02
#define DW_ACCESS_public                0x01
#define DW_ATE_UTF                      0x10
#define DW_ATE_address                  0x01
#define DW_ATE_boolean                  0x02
#define DW_ATE_complex_float            0x03
#define DW_ATE_decimal_float            0x0f
#define DW_ATE_edited                   0x0c
#define DW_ATE_float                    0x04
#define DW_ATE_hi_user                  0xff
#define DW_ATE_imaginary_float          0x09
#define DW_ATE_lo_user                  0x80
#define DW_ATE_numeric_string           0x0b
#define DW_ATE_packed_decimal           0x0a
#define DW_ATE_signed                   0x05
#define DW_ATE_signed_char              0x06
#define DW_ATE_signed_fixed             0x0d
#define DW_ATE_unsigned                 0x07
#define DW_ATE_unsigned_char            0x08
#define DW_ATE_unsigned_fixed           0x0e
#define DW_AT_GNU_addr_base             0x2133
#define DW_AT_GNU_all_call_sites        0x2117
#define DW_AT_GNU_all_source_call_sites 0x2118
#define DW_AT_GNU_all_tail_call_sites   0x2116
#define DW_AT_GNU_call_site_data_value  0x2112
#define DW_AT_GNU_call_site_target      0x2113
#define DW_AT_GNU_call_site_target_clobbered   0x2114
#define DW_AT_GNU_call_site_value       0x2111
#define DW_AT_GNU_deleted               0x211a
#define DW_AT_GNU_dwo_id                0x2131
#define DW_AT_GNU_dwo_name              0x2130
#define DW_AT_GNU_macros                0x2119
#define DW_AT_GNU_pubnames              0x2134
#define DW_AT_GNU_pubtypes              0x2135
#define DW_AT_GNU_ranges_base           0x2132
#define DW_AT_GNU_tail_call             0x2115
#define DW_AT_MIPS_linkage_name         0x2007 
#define DW_AT_abstract_origin           0x31
#define DW_AT_accessibility             0x32
#define DW_AT_addr_base                 0x73
#define DW_AT_address_class             0x33
#define DW_AT_alignment                 0x88
#define DW_AT_allocated                 0x4e 
#define DW_AT_artificial                0x34
#define DW_AT_associated                0x4f
#define DW_AT_base_types                0x35
#define DW_AT_binary_scale              0x5b
#define DW_AT_bit_offset                0x0c
#define DW_AT_bit_size                  0x0d
#define DW_AT_byte_size                 0x0b
#define DW_AT_byte_stride               0x51
#define DW_AT_call_all_calls            0x7a
#define DW_AT_call_all_source_calls     0x7b
#define DW_AT_call_all_tail_calls       0x7c
#define DW_AT_call_column               0x57
#define DW_AT_call_data_location        0x85
#define DW_AT_call_data_value           0x86
#define DW_AT_call_file                 0x58
#define DW_AT_call_line                 0x59
#define DW_AT_call_origin               0x7f
#define DW_AT_call_parameter            0x80
#define DW_AT_call_pc                   0x81
#define DW_AT_call_return_pc            0x7d
#define DW_AT_call_tail_call            0x82
#define DW_AT_call_target               0x83
#define DW_AT_call_target_clobbered     0x84
#define DW_AT_call_value                0x7e
#define DW_AT_calling_convention        0x36
#define DW_AT_common_reference          0x1a
#define DW_AT_comp_dir                  0x1b
#define DW_AT_const_expr                0x6c
#define DW_AT_const_value               0x1c
#define DW_AT_containing_type           0x1d
#define DW_AT_count                     0x37
#define DW_AT_data_bit_offset           0x6b
#define DW_AT_data_location             0x50
#define DW_AT_data_member_location      0x38
#define DW_AT_decimal_scale             0x5c
#define DW_AT_decimal_sign              0x5e
#define DW_AT_decl_column               0x39
#define DW_AT_decl_file                 0x3a
#define DW_AT_decl_line                 0x3b
#define DW_AT_declaration               0x3c
#define DW_AT_default_value             0x1e
#define DW_AT_defaulted                 0x8b
#define DW_AT_deleted                   0x8a
#define DW_AT_description               0x5a
#define DW_AT_digit_count               0x5f
#define DW_AT_discr                     0x15
#define DW_AT_discr_list                0x3d
#define DW_AT_discr_value               0x16
#define DW_AT_dwo_name                  0x76
#define DW_AT_elemental                 0x66
#define DW_AT_encoding                  0x3e
#define DW_AT_endianity                 0x65
#define DW_AT_entry_pc                  0x52
#define DW_AT_enum_class                0x6d
#define DW_AT_explicit                  0x63
#define DW_AT_export_symbols            0x89
#define DW_AT_extension                 0x54
#define DW_AT_external                  0x3f
#define DW_AT_frame_base                0x40
#define DW_AT_friend                    0x41
#define DW_AT_hi_user                   0x3fff
#define DW_AT_high_pc                   0x12
#define DW_AT_identifier_case           0x42
#define DW_AT_import                    0x18
#define DW_AT_inline                    0x20
#define DW_AT_is_optional               0x21
#define DW_AT_language                  0x13
#define DW_AT_linkage_name              0x6e
#define DW_AT_lo_user                   0x2000
#define DW_AT_location                  0x02
#define DW_AT_loclists_base             0x8c
#define DW_AT_low_pc                    0x11
#define DW_AT_lower_bound               0x22
#define DW_AT_macro_info                0x43
#define DW_AT_macros                    0x79
#define DW_AT_main_subprogram           0x6a
#define DW_AT_mutable                   0x61
#define DW_AT_name                      0x03
#define DW_AT_namelist_item             0x44
#define DW_AT_noreturn                  0x87
#define DW_AT_object_pointer            0x64
#define DW_AT_ordering                  0x09
#define DW_AT_picture_string            0x60
#define DW_AT_priority                  0x45
#define DW_AT_producer                  0x25
#define DW_AT_prototyped                0x27
#define DW_AT_pure                      0x67
#define DW_AT_ranges                    0x55
#define DW_AT_rank                      0x71
#define DW_AT_recursive                 0x68 
#define DW_AT_reference                 0x77
#define DW_AT_return_addr               0x2a
#define DW_AT_rnglists_base             0x74
#define DW_AT_rvalue_reference          0x78
#define DW_AT_segment                   0x46
#define DW_AT_sibling                   0x01
#define DW_AT_signature                 0x69
#define DW_AT_small                     0x5d
#define DW_AT_specification             0x47
#define DW_AT_start_scope               0x2c
#define DW_AT_static_link               0x48
#define DW_AT_stmt_list                 0x10
#define DW_AT_str_offsets_base          0x72
#define DW_AT_stride_size               0x2e
#define DW_AT_string_length             0x19
#define DW_AT_string_length_bit_size    0x6f
#define DW_AT_string_length_byte_size   0x70
#define DW_AT_threads_scaled            0x62
#define DW_AT_trampoline                0x56
#define DW_AT_type                      0x49
#define DW_AT_upper_bound               0x2f
#define DW_AT_use_UTF8                  0x53
#define DW_AT_use_location              0x4a
#define DW_AT_variable_parameter        0x4b
#define DW_AT_virtuality                0x4c
#define DW_AT_visibility                0x17
#define DW_AT_vtable_elem_location      0x4d
#define DW_CC_hi_user                   0xff
#define DW_CC_lo_user                   0x40
#define DW_CC_nocall                    0x03
#define DW_CC_normal                    0x01
#define DW_CC_program                   0x02
#define DW_CFA_advance_loc              0x40
#define DW_CFA_advance_loc1             0x02
#define DW_CFA_advance_loc2             0x03
#define DW_CFA_advance_loc4             0x04
#define DW_CFA_def_cfa                  0x0c
#define DW_CFA_def_cfa_expression       0x0f
#define DW_CFA_def_cfa_offset           0x0e
#define DW_CFA_def_cfa_offset_sf        0x13
#define DW_CFA_def_cfa_register         0x0d
#define DW_CFA_def_cfa_sf               0x12
#define DW_CFA_expression               0x10
#define DW_CFA_hi_user                  0x3f
#define DW_CFA_lo_user                  0x1c
#define DW_CFA_nop                      0x00
#define DW_CFA_offse_extended           0x05
#define DW_CFA_offset                   0x80
#define DW_CFA_offset_extended_sf       0x11
#define DW_CFA_register                 0x09
#define DW_CFA_remember_state           0x0a
#define DW_CFA_restore                  0xc0
#define DW_CFA_restore_extended         0x06
#define DW_CFA_restore_state            0x0b
#define DW_CFA_same_value               0x08
#define DW_CFA_set_loc                  0x01
#define DW_CFA_undefined                0x07
#define DW_CFA_val_expression           0x16
#define DW_CFA_val_offset               0x14
#define DW_CFA_val_offset_sf            0x15
#define DW_CHILDREN_no                  0x00
#define DW_CHILDREN_yes                 0x01
#define DW_DSC_label                    0x00
#define DW_DSC_range                    0x01
#define DW_DS_leading_overpunch         0x02
#define DW_DS_leading_separate          0x04
#define DW_DS_trailing_overpunch        0x03
#define DW_DS_trailing_separate         0x05
#define DW_DS_unsigned                  0x01
#define DW_END_big                      0x01
#define DW_END_default                  0x00
#define DW_END_hi_user                  0xff
#define DW_END_little                   0x02
#define DW_END_lo_user                  0x40
#define DW_EXTENDED_OPCODE 0
#define DW_FORM_addr                    0x01
#define DW_FORM_addrx                   0x1b
#define DW_FORM_addrx1                  0x29
#define DW_FORM_addrx2                  0x2a
#define DW_FORM_addrx3                  0x2b
#define DW_FORM_addrx4                  0x2c
#define DW_FORM_block                   0x09
#define DW_FORM_block1                  0x0a
#define DW_FORM_block2                  0x03
#define DW_FORM_block4                  0x04
#define DW_FORM_data1                   0x0b
#define DW_FORM_data16                  0x1e
#define DW_FORM_data2                   0x05
#define DW_FORM_data4                   0x06
#define DW_FORM_data8                   0x07
#define DW_FORM_exprloc                 0x18
#define DW_FORM_flag                    0x0c
#define DW_FORM_flag_present            0x19
#define DW_FORM_implicit_const          0x21
#define DW_FORM_indirect                0x16
#define DW_FORM_line_ptr                0x1f
#define DW_FORM_loclistx                0x22
#define DW_FORM_ref1                    0x11
#define DW_FORM_ref2                    0x12
#define DW_FORM_ref4                    0x13
#define DW_FORM_ref8                    0x14
#define DW_FORM_ref_addr                0x10
#define DW_FORM_ref_sig8                0x20
#define DW_FORM_ref_sup4                0x1c
#define DW_FORM_ref_sup8                0x24
#define DW_FORM_ref_udata               0x15
#define DW_FORM_rnglistx                0x23
#define DW_FORM_sdata                   0x0d
#define DW_FORM_sec_offset              0x17 
#define DW_FORM_string                  0x08
#define DW_FORM_strp                    0x0e
#define DW_FORM_strp_sup                0x1d
#define DW_FORM_strx                    0x1a
#define DW_FORM_strx1                   0x25
#define DW_FORM_strx2                   0x26
#define DW_FORM_strx3                   0x27
#define DW_FORM_strx4                   0x28
#define DW_FORM_udata                   0x0f
#define DW_ID_case_insensitive          0x03
#define DW_ID_case_sensitive            0x00
#define DW_ID_down_case                 0x02
#define DW_ID_up_case                   0x01
#define DW_INL_declared_inlined         0x03
#define DW_INL_declared_not_inlined     0x02
#define DW_INL_inlined                  0x01
#define DW_INL_not_inlined              0x00
#define DW_LANG_Ada83                   0x0003
#define DW_LANG_Ada95                   0x000d
#define DW_LANG_C                       0x0002
#define DW_LANG_C11                     0x001d
#define DW_LANG_C89                     0x0001
#define DW_LANG_C99                     0x000c
#define DW_LANG_C_plus_plus             0x0004
#define DW_LANG_C_plus_plus_14          0x0021
#define DW_LANG_Cobol74                 0x0005
#define DW_LANG_Cobol85                 0x0006
#define DW_LANG_D                       0x0013
#define DW_LANG_Dylan                   0x0020
#define DW_LANG_Fortran03               0x0022
#define DW_LANG_Fortran08               0x0023
#define DW_LANG_Fortran77               0x0007
#define DW_LANG_Fortran90               0x0008
#define DW_LANG_Fortran95               0x000e
#define DW_LANG_Java                    0x000b
#define DW_LANG_Julia                   0x001f
#define DW_LANG_Modula2                 0x000a
#define DW_LANG_ObjC                    0x0010
#define DW_LANG_ObjC_plus_plus          0x0011
#define DW_LANG_PLI                     0x000f
#define DW_LANG_Pascal83                0x0009
#define DW_LANG_Python                  0x0014
#define DW_LANG_Rust                    0x001c
#define DW_LANG_Swift                   0x001e
#define DW_LANG_UPC                     0x0012
#define DW_LANG_hi_user                 0xffff
#define DW_LANG_lo_user                 0x8000
#define DW_LNE_HP_define_proc               0x20 
#define DW_LNE_HP_negate_front_end_logical  0x19 
#define DW_LNE_HP_negate_function_exit      0x18 
#define DW_LNE_HP_negate_is_UV_update       0x11 
#define DW_LNE_HP_negate_post_semantics     0x17 
#define DW_LNE_HP_pop_context               0x13 
#define DW_LNE_HP_push_context              0x12 
#define DW_LNE_HP_set_file_line_column      0x14 
#define DW_LNE_HP_set_routine_name          0x15 
#define DW_LNE_HP_set_sequence              0x16 
#define DW_LNE_define_file              0x03
#define DW_LNE_end_sequence             0x01
#define DW_LNE_hi_user                  0xff
#define DW_LNE_lo_user                  0x80
#define DW_LNE_set_address              0x02
#define DW_LNE_set_discriminator        0x04  
#define DW_LNS_advance_line             0x03
#define DW_LNS_advance_pc               0x02
#define DW_LNS_const_add_pc             0x08
#define DW_LNS_copy                     0x01
#define DW_LNS_fixed_advance_pc         0x09
#define DW_LNS_negate_stmt              0x06
#define DW_LNS_set_basic_block          0x07
#define DW_LNS_set_column               0x05
#define DW_LNS_set_epilogue_begin       0x0b 
#define DW_LNS_set_file                 0x04
#define DW_LNS_set_isa                  0x0c 
#define DW_LNS_set_prologue_end         0x0a 
#define DW_MACINFO_define               0x01
#define DW_MACINFO_end_file             0x04
#define DW_MACINFO_start_file           0x03
#define DW_MACINFO_undef                0x02
#define DW_MACINFO_vendor_ext           0xff
#define DW_OP_abs                       0x19
#define DW_OP_addr                      0x03
#define DW_OP_and                       0x1a
#define DW_OP_bit_piece                 0x9d
#define DW_OP_bra                       0x28
#define DW_OP_breg0                     0x70
#define DW_OP_breg1                     0x71
#define DW_OP_breg10                    0x7a
#define DW_OP_breg11                    0x7b
#define DW_OP_breg12                    0x7c
#define DW_OP_breg13                    0x7d
#define DW_OP_breg14                    0x7e
#define DW_OP_breg15                    0x7f
#define DW_OP_breg16                    0x80
#define DW_OP_breg17                    0x81
#define DW_OP_breg18                    0x82
#define DW_OP_breg19                    0x83
#define DW_OP_breg2                     0x72
#define DW_OP_breg20                    0x84
#define DW_OP_breg21                    0x85
#define DW_OP_breg22                    0x86
#define DW_OP_breg23                    0x87
#define DW_OP_breg24                    0x88
#define DW_OP_breg25                    0x89
#define DW_OP_breg26                    0x8a
#define DW_OP_breg27                    0x8b
#define DW_OP_breg28                    0x8c
#define DW_OP_breg29                    0x8d
#define DW_OP_breg3                     0x73
#define DW_OP_breg30                    0x8e
#define DW_OP_breg31                    0x8f
#define DW_OP_breg4                     0x74
#define DW_OP_breg5                     0x75
#define DW_OP_breg6                     0x76
#define DW_OP_breg7                     0x77
#define DW_OP_breg8                     0x78
#define DW_OP_breg9                     0x79
#define DW_OP_bregx                     0x92
#define DW_OP_call2                     0x98
#define DW_OP_call4                     0x99
#define DW_OP_call_frame_cfa            0x9c
#define DW_OP_call_ref                  0x9a
#define DW_OP_const1s                   0x09
#define DW_OP_const1u                   0x08
#define DW_OP_const2s                   0x0b
#define DW_OP_const2u                   0x0a
#define DW_OP_const4s                   0x0d
#define DW_OP_const4u                   0x0c
#define DW_OP_const8s                   0x0f
#define DW_OP_const8u                   0x0e
#define DW_OP_consts                    0x11
#define DW_OP_constu                    0x10
#define DW_OP_deref                     0x06
#define DW_OP_deref_size                0x94
#define DW_OP_div                       0x1b
#define DW_OP_drop                      0x13
#define DW_OP_dup                       0x12
#define DW_OP_eq                        0x29
#define DW_OP_fbreg                     0x91
#define DW_OP_form_tls_address          0x9b
#define DW_OP_ge                        0x2a
#define DW_OP_gt                        0x2b
#define DW_OP_hi_user                   0xff
#define DW_OP_implicit_value            0x9e
#define DW_OP_le                        0x2c
#define DW_OP_lit0                      0x30
#define DW_OP_lit1                      0x31
#define DW_OP_lit10                     0x3a
#define DW_OP_lit11                     0x3b
#define DW_OP_lit12                     0x3c
#define DW_OP_lit13                     0x3d
#define DW_OP_lit14                     0x3e
#define DW_OP_lit15                     0x3f
#define DW_OP_lit16                     0x40
#define DW_OP_lit17                     0x41
#define DW_OP_lit18                     0x42
#define DW_OP_lit19                     0x43
#define DW_OP_lit2                      0x32
#define DW_OP_lit20                     0x44
#define DW_OP_lit21                     0x45
#define DW_OP_lit22                     0x46
#define DW_OP_lit23                     0x47
#define DW_OP_lit24                     0x48
#define DW_OP_lit25                     0x49
#define DW_OP_lit26                     0x4a
#define DW_OP_lit27                     0x4b
#define DW_OP_lit28                     0x4c
#define DW_OP_lit29                     0x4d
#define DW_OP_lit3                      0x33
#define DW_OP_lit30                     0x4e
#define DW_OP_lit31                     0x4f
#define DW_OP_lit4                      0x34
#define DW_OP_lit5                      0x35
#define DW_OP_lit6                      0x36
#define DW_OP_lit7                      0x37
#define DW_OP_lit8                      0x38
#define DW_OP_lit9                      0x39
#define DW_OP_lo_user                   0xe0
#define DW_OP_lt                        0x2d
#define DW_OP_minus                     0x1c
#define DW_OP_mod                       0x1d
#define DW_OP_mul                       0x1e
#define DW_OP_ne                        0x2e
#define DW_OP_neg                       0x1f
#define DW_OP_nop                       0x96
#define DW_OP_not                       0x20
#define DW_OP_or                        0x21
#define DW_OP_over                      0x14
#define DW_OP_pick                      0x15
#define DW_OP_piece                     0x93
#define DW_OP_plus                      0x22
#define DW_OP_plus_uconst               0x23
#define DW_OP_push_object_address       0x97
#define DW_OP_reg0                      0x50
#define DW_OP_reg1                      0x51
#define DW_OP_reg10                     0x5a
#define DW_OP_reg11                     0x5b
#define DW_OP_reg12                     0x5c
#define DW_OP_reg13                     0x5d
#define DW_OP_reg14                     0x5e
#define DW_OP_reg15                     0x5f
#define DW_OP_reg16                     0x60
#define DW_OP_reg17                     0x61
#define DW_OP_reg18                     0x62
#define DW_OP_reg19                     0x63
#define DW_OP_reg2                      0x52
#define DW_OP_reg20                     0x64
#define DW_OP_reg21                     0x65
#define DW_OP_reg22                     0x66
#define DW_OP_reg23                     0x67
#define DW_OP_reg24                     0x68
#define DW_OP_reg25                     0x69
#define DW_OP_reg26                     0x6a
#define DW_OP_reg27                     0x6b
#define DW_OP_reg28                     0x6c
#define DW_OP_reg29                     0x6d
#define DW_OP_reg3                      0x53
#define DW_OP_reg30                     0x6e
#define DW_OP_reg31                     0x6f
#define DW_OP_reg4                      0x54
#define DW_OP_reg5                      0x55
#define DW_OP_reg6                      0x56
#define DW_OP_reg7                      0x57
#define DW_OP_reg8                      0x58
#define DW_OP_reg9                      0x59
#define DW_OP_regx                      0x90
#define DW_OP_rot                       0x17
#define DW_OP_shl                       0x24
#define DW_OP_shr                       0x25
#define DW_OP_shra                      0x26
#define DW_OP_skip                      0x2f
#define DW_OP_stack_value               0x9f
#define DW_OP_swap                      0x16
#define DW_OP_xderef                    0x18
#define DW_OP_xderef_size               0x95
#define DW_OP_xor                       0x27
#define DW_ORD_col_major                0x01
#define DW_ORD_row_major                0x00
#define DW_TAG_LAST                     0x44  
#define DW_TAG_access_declaration       0x23
#define DW_TAG_array_type               0x01
#define DW_TAG_base_type                0x24
#define DW_TAG_catch_block              0x25
#define DW_TAG_class_type               0x02
#define DW_TAG_common_block             0x1a
#define DW_TAG_common_inclusion         0x1b
#define DW_TAG_compile_unit             0x11
#define DW_TAG_condition                0x3f  
#define DW_TAG_const_type               0x26
#define DW_TAG_constant                 0x27
#define DW_TAG_dwarf_procedure          0x36  
#define DW_TAG_entry_point              0x03
#define DW_TAG_enumeration_type         0x04
#define DW_TAG_enumerator               0x28
#define DW_TAG_file_type                0x29
#define DW_TAG_formal_parameter         0x05
#define DW_TAG_friend                   0x2a
#define DW_TAG_hi_user                  0xffff
#define DW_TAG_imported_declaration     0x08
#define DW_TAG_imported_module          0x3a  
#define DW_TAG_imported_unit            0x3d  
#define DW_TAG_inheritance              0x1c
#define DW_TAG_inlined_subroutine       0x1d
#define DW_TAG_interface_type           0x38  
#define DW_TAG_label                    0x0a
#define DW_TAG_lexical_block            0x0b
#define DW_TAG_lo_user                  0x4080
#define DW_TAG_member                   0x0d
#define DW_TAG_module                   0x1e
#define DW_TAG_mutable_type 			0x3e 
#define DW_TAG_namelist                 0x2b
#define DW_TAG_namelist_item            0x2c 
#define DW_TAG_namelist_items           0x2c 
#define DW_TAG_namespace                0x39  
#define DW_TAG_null_entry               0x00
#define DW_TAG_packed_type              0x2d
#define DW_TAG_partial_unit             0x3c  
#define DW_TAG_pointer_type             0x0f
#define DW_TAG_ptr_to_member_type       0x1f
#define DW_TAG_reference_type           0x10
#define DW_TAG_restrict_type            0x37  
#define DW_TAG_rvalue_reference_type    0x42  
#define DW_TAG_set_type                 0x20
#define DW_TAG_shared_type              0x40  
#define DW_TAG_string_type              0x12
#define DW_TAG_structure_type           0x13
#define DW_TAG_subprogram               0x2e
#define DW_TAG_subrange_type            0x21
#define DW_TAG_subroutine_type          0x15
#define DW_TAG_template_alias           0x43  
#define DW_TAG_template_type_param      0x2f 
#define DW_TAG_template_type_parameter  0x2f 
#define DW_TAG_template_value_param     0x30 
#define DW_TAG_template_value_parameter 0x30 
#define DW_TAG_thrown_type              0x31
#define DW_TAG_try_block                0x32
#define DW_TAG_type_unit                0x41  
#define DW_TAG_typedef                  0x16
#define DW_TAG_union_type               0x17
#define DW_TAG_unspecified_parameters   0x18
#define DW_TAG_unspecified_type         0x3b  
#define DW_TAG_variable                 0x34
#define DW_TAG_variant                  0x19
#define DW_TAG_variant_part             0x33
#define DW_TAG_volatile_type            0x35
#define DW_TAG_with_stmt                0x22
#define DW_UT_compile                   0x01
#define DW_UT_hi_user                   0xff
#define DW_UT_lo_user                   0x80
#define DW_UT_partial                   0x03
#define DW_UT_skeleton                  0x04
#define DW_UT_split_compile             0x05
#define DW_UT_split_type                0x06
#define DW_UT_type                      0x02
#define DW_VIRTUALITY_none              0x00
#define DW_VIRTUALITY_pure_virtual      0x02
#define DW_VIRTUALITY_virtual           0x01
#define DW_VIS_exported                 0x02
#define DW_VIS_local                    0x01
#define DW_VIS_qualified                0x03
#define LOP_DISCARD  2
#define LOP_EXTENDED 1
#define LOP_SPECIAL  4
#define LOP_STANDARD 3

#define R_BIN_DWARF_INFO_HEADER_FILE_LENGTH(x) (sizeof (x->file)/sizeof (*(x->file)))
#define r_bin_dwarf_line_new(o,a,f,l) o->address=a, o->file = strdup (r_str_get (f)), o->line = l, o->column =0,o

#define R_IO_DESC_CACHE_SIZE (sizeof (ut64) * 8)
#define R_IO_SEEK_CUR 1
#define R_IO_SEEK_END 2
#define R_IO_SEEK_SET 0
#define R_IO_UNDOS 64
#define R_PTRACE_NODATA NULL
#define r_io_bind_init(x) memset (&(x), 0, sizeof (x))
#define r_io_map_begin(map) r_itv_begin (map->itv)
#define r_io_map_contain(map, addr) r_itv_contain (map->itv, addr)
#define r_io_map_end(map) r_itv_end (map->itv)
#define r_io_map_from r_io_map_begin
#define r_io_map_set_begin(map, new_addr)	\
	do {					\
		map->itv.addr = new_addr;	\
	} while (0)
#define r_io_map_set_size(map, new_size)	\
	do {					\
		map->itv.size = new_size;	\
	} while (0)
#define r_io_map_size(map) r_itv_size (map->itv)
#define r_io_map_to(map) ( r_itv_end (map->itv) - 1 )
#define r_io_range_free(x)	free(x)
#define r_io_range_new()	R_NEW0(RIORange)
#define r_io_submap_contain(sm, addr) r_io_map_contain (sm, addr)
#define r_io_submap_from(sm) (r_io_map_begin (sm))
#define r_io_submap_overlap(bd, sm) r_itv_overlap(bd->itv, sm->itv)
#define r_io_submap_to(sm) (r_io_map_to (sm))

#define r_w32dw_err(inst) (SetLastError (inst->params.err), inst->params.err)
#define r_w32dw_ret(inst) inst->params.ret

#define MSG_DONTWAIT 0

#define R_INVALID_SOCKET INVALID_SOCKET
#define R_RUN_PROFILE_NARGS 512
#define R_SOCKET_PROTO_CAN 0xc42b05
#define R_SOCKET_PROTO_DEFAULT R_SOCKET_PROTO_TCP
#define R_SOCKET_PROTO_NONE 0
#define R_SOCKET_PROTO_SERIAL 0x534147
#define R_SOCKET_PROTO_TCP IPPROTO_TCP
#define R_SOCKET_PROTO_UDP IPPROTO_UDP
#define R_SOCKET_PROTO_UNIX 0x1337
#define SD_BOTH 2
#define SD_RECEIVE  0
#define SD_SEND 1
#define r_socket_connect_tcp(a, b, c, d) r_socket_connect (a, b, c, R_SOCKET_PROTO_TCP, d)
#define r_socket_connect_udp(a, b, c, d) r_socket_connect (a, b, c, R_SOCKET_PROTO_UDP, d)
#define r_socket_connect_unix(a, b) r_socket_connect (a, b, b, R_SOCKET_PROTO_UNIX, 0)

