


#include<sys/wait.h>
#include<netdb.h>
#include<sys/ioctl.h>





#include<assert.h>










#include<sys/un.h>
#include<limits.h>
#include<errno.h>
#include<dirent.h>

#include<sched.h>
#include<ctype.h>





#include<time.h>

#include<inttypes.h>

#include<netinet/tcp.h>
#include<netinet/in.h>


#include<fcntl.h>

#include<unistd.h>
#include<wchar.h>

#include<sys/types.h>



#include<stdio.h>
#include<poll.h>


#include<stdarg.h>

#include<sys/param.h>
#include<arpa/inet.h>

#include<pthread.h>

#include<sys/socket.h>
#include<stdbool.h>






#include<string.h>


#include<stdint.h>
#include<termios.h>

#include<stddef.h>
#include<sys/time.h>
#include<signal.h>
#include<semaphore.h>
#include<sys/ptrace.h>


#include<sys/stat.h>
#include<stdlib.h>

#define R_DIRTY(x) (x)->is_dirty = true
#define R_DIRTY_VAR bool is_dirty
#define R_IS_DIRTY(x) (x)->is_dirty

#define NTSTATUS DWORD

#define TEXT(x) (TCHAR*)(x)
#define RNumBig mpz_t





#define R_PJ_H 1
#define R_PRINT_JSON_DEPTH_LIMIT 128

#define R_STRBUF_SAFEGET(sb) (r_strbuf_get (sb) ? r_strbuf_get (sb) : "")
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

#define BITS2BYTES(x) (((x)/8)+(((x)%8)?1:0))
#define CLOCK_MONOTONIC 0
#define CTA(x,y,z) (x+CTO(y,z))
#define CTI(x,y,z) (*((size_t*)(CTA(x,y,z))))
#define CTO(y,z) ((size_t) &((y*)0)->z)
#define CTS(x,y,z,t,v) {t* _=(t*)CTA(x,y,z);*_=v;}
#define EPRINT_BOOL(x) eprintf (#x ": %s\n", x? "true": "false")
#define EPRINT_CHAR(x) eprintf (#x ": '%c' (0x%x)\n", x, x)
#define EPRINT_INT(x) eprintf (#x ": %d (0x%x)\n", x, x)
#define EPRINT_PTR(x) eprintf (#x ": %p\n", x)
#define EPRINT_ST16(x) eprintf (#x ": %hd (0x%hx)\n", x, x)
#define EPRINT_ST32(x) eprintf (#x ": %" PFMT32d " (0x%" PFMT32x ")\n", x, x)
#define EPRINT_ST64(x) eprintf (#x ": %" PFMT64d " (0x%" PFMT64x ")\n", x, x)
#define EPRINT_ST8(x) eprintf (#x ": %hhd (0x%hhx)\n", x, x)
#define EPRINT_STR(x) eprintf (#x ": \"%s\"\n", x)
#define EPRINT_UT16(x) eprintf (#x ": %hu (0x%hx)\n", x, x)
#define EPRINT_UT32(x) eprintf (#x ": %" PFMT32u " (0x%" PFMT32x ")\n", x, x)
#define EPRINT_UT64(x) eprintf (#x ": %" PFMT64u " (0x%" PFMT64x ")\n", x, x)
#define EPRINT_UT8(x) eprintf (#x ": %hhu (0x%hhx)\n", x, x)
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
# define HAS_CLOCK_MONOTONIC 1
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

    #define R_API __declspec(dllexport)
#define R_ARRAY_SIZE(x) (sizeof (x) / sizeof ((x)[0]))
#define R_BIT_CHK(x,y) (*(x) & (1<<(y)))
#define R_BIT_SET(x,y) (((ut8*)x)[y>>4] |= (1<<(y&0xf)))
#define R_BIT_TOGGLE(x, y) ( R_BIT_CHK (x, y) ? \
		R_BIT_UNSET (x, y): R_BIT_SET (x, y))
#define R_BIT_UNSET(x,y) (((ut8*)x)[y>>4] &= ~(1<<(y&0xf)))
#define R_BORROW 
#define R_DEPRECATE 
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
#define R_NEW(x) (x*)malloc(sizeof(x))
#define R_NEW0(x) (x*)calloc(1,sizeof(x))
#define R_NEWCOPY(x,y) (x*)r_new_copy(sizeof(x), y)
#define R_NEWS(x,y) (x*)malloc(sizeof(x)*(y))
#define R_NEWS0(x,y) (x*)calloc(y,sizeof(x))
#define R_NEW_COPY(x,y) x=(void*)malloc(sizeof(y));memcpy(x,y,sizeof(y))
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
#define R_REF_FUNCTIONS(s, n) \
static inline void n##_ref(s *x) { x->R_REF_NAME++; } \
static inline void n##_unref(s *x) { r_unref(x, n##_free); }
#define R_REF_NAME refcount
#define R_REF_TYPE RRef R_REF_NAME
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
#define R_UNUSED __attribute__((__unused__))
#define TARGET_OS_IPHONE 1
#define TODO(x) eprintf(__func__"  " x)
#  define UNUSED_FUNCTION(x) __attribute__((__unused__)) UNUSED_ ## x

#define ZERO_FILL(x) memset (&x, 0, sizeof (x))
#define _FILE_OFFSET_BITS 64

  #define __BSD__ 0
#define __KFBSD__ 1
#define __POWERPC__ 1
  #define __UNIX__ 1
  #define __WINDOWS__ 1

#define __func__ __FUNCTION__
#define __i386__ 1
#define __packed __attribute__((__packed__))
#define __x86_64__ 1
#define _perror(str,file,line,func) \
  { \
	  char buf[256]; \
	  snprintf(buf,sizeof(buf),"[%s:%d %s] %s",file,line,func,str); \
	  r_sys_perror_str(buf); \
  }
#  define container_of(ptr, type, member) ((type *)((char *)(ptr) - offsetof(type, member)))
#define eprintf(...) fprintf (stderr, __VA_ARGS__)
#define mips mips
#define perror(x) _perror(x,"__FILE__","__LINE__",__func__)
#define r_offsetof(type, member) offsetof(type, member)
#define r_ref(x) x->R_REF_NAME++;
#define r_ref_init(x) x->R_REF_NAME = 1
#define r_sys_perror(x) _perror(x,"__FILE__","__LINE__",__func__)
#define r_unref(x,f) { assert (x->R_REF_NAME> 0); if (!--(x->R_REF_NAME)) { f(x); } }

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
#define R_EMPTY { 0 }
#define R_EMPTY2 {{ 0 }}
#define R_IGNORE_RETURN(x) if ((x)) {;}
#define R_MAX(x,y) (((x)>(y))?(x):(y))

#define R_MIN(x,y) (((x)>(y))?(y):(x))

#define R_PACKED( __Declaration__ ) __pragma( pack(push, 1) ) __Declaration__ __pragma( pack(pop) )
#define R_ROUND(x,y) ((x)%(y))?(x)+((y)-((x)%(y))):(x)
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






#define r_acp_to_utf8(str) r_acp_to_utf8_l ((char *)str, -1)
#define r_utf16_to_utf8(wc) r_utf16_to_utf8_l ((wchar_t *)wc, -1)
#define r_utf8_to_acp(cstring) r_utf8_to_acp_l ((char *)cstring, -1)
#define r_utf8_to_utf16(cstring) r_utf8_to_utf16_l ((char *)cstring, -1)



#define ROFList_Parent RList

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

#define RFList void**
#define r_flist_foreach(it, pos) \
	r_flist_rewind(it); \
	while (r_flist_next (it) && (pos = r_flist_get (it)))
#define r_flist_get(it) *(it++)
#define r_flist_iterator(x) x
#define r_flist_next(it) *it!=0
#define r_flist_rewind(it) while(it!=*it) it--; it++;
#define r_flist_t void**
#define r_flist_unref(x) x
#define R_SYS_BITS_16 2
#define R_SYS_BITS_27 16
#define R_SYS_BITS_32 4
#define R_SYS_BITS_64 8
#define R_SYS_BITS_8 1
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

#define R_STR_DUP(x) ((x) ? strdup ((x)) : NULL)

#define R_STR_ISEMPTY(x) (!(x) || !*(x))
#define R_STR_ISNOTEMPTY(x) ((x) && *(x))
#define r_str_array(x,y) ((y>=0 && y<(sizeof(x)/sizeof(*x)))?x[y]:"")
#define r_str_cat(x,y) memmove ((x) + strlen (x), (y), strlen (y) + 1);
#define r_str_cpy(x,y) memmove ((x), (y), strlen (y) + 1);
#define r_strf(s,...) (snprintf (strbuf, sizeof(strbuf), s, __VA_ARGS__)?strbuf: strbuf)
#define r_strf_buffer(s) char strbuf[s]
#define r_strf_var(n,s, f, ...) char n[s]; snprintf (n, s, f, __VA_ARGS__);


#define R_SPACES_MAX 512
#define r_spaces_foreach(sp, it, s) \
	r_crbtree_foreach ((sp)->spaces, (it), (s))

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
#define CONS_MAX_USER 102400
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
#define Color_RESET_ALL  "\x1b[0m\x1b[49m"
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
	for (it = (void **)(vec)->v.a; it != (void **)(vec)->v.a + (vec)->v.len; it++)
#define r_pvector_foreach_prev(vec, it) \
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
#define R_STATIC_ASSERT(x)\
	switch (0) {\
	case 0:\
	case (x):;\
	}
#define r_return_if_fail(expr) do { assert (expr); } while(0)
#define r_return_if_reached() \
	do { \
		H_LOG_ (R_LOGLVL_ERROR, "file %s: line %d (%s): should not be reached\n", "__FILE__", "__LINE__", R_FUNCTION); \
		return; \
	} while (0)
#define r_return_val_if_fail(expr, val) do { assert (expr); } while(0)
#define r_return_val_if_reached(val) \
	do { \
		H_LOG_ (R_LOGLVL_ERROR, "file %s: line %d (%s): should not be reached\n", "__FILE__", "__LINE__", R_FUNCTION); \
		return (val); \
	} while (0)
#define r_warn_if_fail(expr) \
	do { \
		if (!(expr)) { \
			r_assert_log (R_LOGLVL_WARN, "WARNING (%s:%d):%s%s runtime check failed: (%s)\n", \
				"__FILE__", "__LINE__", R_FUNCTION, R_FUNCTION[0] ? ":" : "", #expr); \
		} \
	} while (0)
#define r_warn_if_reached() \
	do { \
		r_assert_log (R_LOGLVL_WARN, "(%s:%d):%s%s code should not be reached\n", \
			"__FILE__", "__LINE__", R_FUNCTION, R_FUNCTION[0] ? ":" : ""); \
	} while (0)

#define SHELL_PATH "/bin/sh"
#define TERMUX_PREFIX "/data/data/com.termux/files/usr"

#define R_NUMCALC_STRSZ 1024

#define MACRO_LOG_FUNC __func__
#define MACRO_WEAK_SYM __attribute__ ((weak))
#define R_DEFAULT_LOGLVL R_LOGLVL_WARN
#define R_LOG(lvl, tag, fmtstr, ...) r_log (MACRO_LOG_FUNC, "__FILE__", \
	"__LINE__", lvl, tag, fmtstr, ##__VA_ARGS__);
#define R_LOG_DEBUG(fmtstr, ...) r_log (MACRO_LOG_FUNC, "__FILE__", \
	"__LINE__", R_LOGLVL_DEBUG, NULL, fmtstr, ##__VA_ARGS__);
#define R_LOG_ERROR(fmtstr, ...) r_log (MACRO_LOG_FUNC, "__FILE__", \
	"__LINE__", R_LOGLVL_ERROR, NULL, fmtstr, ##__VA_ARGS__);
#define R_LOG_FATAL(fmtstr, ...) r_log (MACRO_LOG_FUNC, "__FILE__", \
	"__LINE__", R_LOGLVL_FATAL, NULL, fmtstr, ##__VA_ARGS__);

#define R_LOG_INFO(fmtstr, ...) r_log (MACRO_LOG_FUNC, "__FILE__", \
	"__LINE__", R_LOGLVL_INFO, NULL, fmtstr, ##__VA_ARGS__);
#define R_LOG_SILLY(fmtstr, ...) r_log (MACRO_LOG_FUNC, "__FILE__", \
	"__LINE__", R_LOGLVL_SILLY, NULL, fmtstr, ##__VA_ARGS__);
#define R_LOG_VERBOSE(fmtstr, ...) r_log (MACRO_LOG_FUNC, "__FILE__", \
	"__LINE__", R_LOGLVL_VERBOSE, NULL, fmtstr, ##__VA_ARGS__);
#define R_LOG_WARN(fmtstr, ...) r_log (MACRO_LOG_FUNC, "__FILE__", \
	"__LINE__", R_LOGLVL_WARN, NULL, fmtstr, ##__VA_ARGS__);
#define R_VLOG(lvl, tag, fmtstr, args) r_vlog (MACRO_LOG_FUNC, "__FILE__", \
	"__LINE__", lvl, tag, fmtstr, args);







#define ASCTIME_BUF_MINLEN (26)

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

#define r_crbtree_foreach(tree, iter, stuff) \
	for (iter = tree? r_crbtree_first_node (tree): NULL, stuff = iter? iter->data: NULL; iter; iter = r_rbnode_next (iter), stuff = iter? iter->data: NULL)

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


#define HAVE_PTHREAD 0
#define HAVE_PTHREAD_NP 0
# define HAVE_STDATOMIC_H 0
# define HAVE_TH_LOCAL 1
# define R_ATOMIC_BOOL int
#define R_THREAD_LOCK_INIT {0}
#define R_TH_COND_T CONDITION_VARIABLE

# define R_TH_LOCAL __thread
#define R_TH_LOCK_T CRITICAL_SECTION
#define R_TH_SEM_T HANDLE
#define R_TH_TID HANDLE
#define WANT_THREADS 1



#define r_skiplist_foreach(list, it, pos)\
	if (list)\
		for (it = list->head->forward[0]; it != list->head && ((pos = it->data) || 1); it = it->forward[0])
#define r_skiplist_foreach_safe(list, it, tmp, pos)\
	if (list)\
		for (it = list->head->forward[0]; it != list->head && ((pos = it->data) || 1) && ((tmp = it->forward[0]) || 1); it = tmp)
#define r_skiplist_islast(list, el) (el->forward[0] == list->head)
#define r_skiplist_length(list) (list->size)
#define R_GETOPT_H 1

#define R_IO_DESC_CACHE_SIZE (sizeof(ut64) * 8)
#define R_IO_UNDOS 64
#define R_PTRACE_NODATA NULL
#define r_io_bind_init(x) memset(&x,0,sizeof(x))
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
#define R_SOCKET_PROTO_TCP IPPROTO_TCP
#define R_SOCKET_PROTO_UDP IPPROTO_UDP
#define R_SOCKET_PROTO_UNIX 0x1337
#define SD_BOTH 2
#define SD_RECEIVE  0
#define SD_SEND 1
#define r_socket_connect_tcp(a, b, c, d) r_socket_connect (a, b, c, R_SOCKET_PROTO_TCP, d)
#define r_socket_connect_udp(a, b, c, d) r_socket_connect (a, b, c, R_SOCKET_PROTO_UDP, d)
#define r_socket_connect_unix(a, b) r_socket_connect (a, b, b, R_SOCKET_PROTO_UNIX, 0)

