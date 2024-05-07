
#include<sys/socket.h>


#include<limits.h>


#include<assert.h>

#include<errno.h>
#include<ctype.h>
#include<stdint.h>

#include<signal.h>








#include<stdarg.h>

#include<stdlib.h>
#include<sys/ptrace.h>





#include<time.h>



#include<dirent.h>

#include<stddef.h>



#include<sys/param.h>
#include<unistd.h>
#include<wchar.h>



#include<sys/time.h>
#include<stdio.h>
#include<sys/stat.h>


#include<fcntl.h>

#include<sys/wait.h>
#include<string.h>
#include<sys/types.h>



#include<sys/ioctl.h>
#include<inttypes.h>



#include<termios.h>




#include<stdbool.h>



#define BITS2BYTES(x)    (((x) / 8) + (((x) % 8) ? 1 : 0))
#define CTA(x, y, z) (x + CTO(y, z))
#define CTI(x, y, z) (*((size_t *)(CTA(x, y, z))))
#define CTO(y, z)    ((size_t) & ((y *)0)->z)
#define CTS(x, y, z, t, v) \
	{ \
		t *_ = (t *)CTA(x, y, z); \
		*_ = v; \
	}
#define FUNC_ATTR_ALLOC_ALIGN(x)        __attribute__((alloc_align(x)))
#define FUNC_ATTR_ALLOC_SIZE(x)         __attribute__((alloc_size(x)))
#define FUNC_ATTR_ALLOC_SIZE_PROD(x, y) __attribute__((alloc_size(x, y)))
#define FUNC_ATTR_ALWAYS_INLINE         __attribute__((always_inline))
#define FUNC_ATTR_CONST                 __attribute__((const))
#define FUNC_ATTR_MALLOC                __attribute__((malloc))
#define FUNC_ATTR_PURE                  __attribute__((pure))
#define FUNC_ATTR_USED                  __attribute__((used))
#define FUNC_ATTR_WARN_UNUSED_RESULT    __attribute__((warn_unused_result))
#define HAVE_EPRINTF 1
#define HHXFMT  "x"
#define LDBLFMT "f"
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
#define RZ_API inline
#define RZ_ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define RZ_BIT_CHK(x, y) (*(x) & (1 << (y)))
#define RZ_BIT_MASK32(x, y) ((1UL << (x)) - (1UL << (y)))
#define RZ_BIT_SET(x, y)    (((ut8 *)x)[y >> 4] |= (1 << (y & 0xf)))
#define RZ_BIT_TOGGLE(x, y) (RZ_BIT_CHK(x, y) ? RZ_BIT_UNSET(x, y) : RZ_BIT_SET(x, y))
#define RZ_BIT_UNSET(x, y)  (((ut8 *)x)[y >> 4] &= ~(1 << (y & 0xf)))
#define RZ_BORROW    
#define RZ_DEPRECATE 
#define RZ_FREE(x) \
	{ \
		free((void *)x); \
		x = NULL; \
	}
#define RZ_FREE_CUSTOM(x, y) \
	{ \
		y(x); \
		x = NULL; \
	}

#define RZ_IFNULL(x) 
#define RZ_IN    
#define RZ_INOUT 

#define RZ_JOIN_2_PATHS(p1, p2)             p1 RZ_SYS_DIR p2
#define RZ_JOIN_3_PATHS(p1, p2, p3)         p1 RZ_SYS_DIR p2 RZ_SYS_DIR p3
#define RZ_JOIN_4_PATHS(p1, p2, p3, p4)     p1 RZ_SYS_DIR p2 RZ_SYS_DIR p3 RZ_SYS_DIR p4
#define RZ_JOIN_5_PATHS(p1, p2, p3, p4, p5) p1 RZ_SYS_DIR p2 RZ_SYS_DIR p3 RZ_SYS_DIR p4 RZ_SYS_DIR p5
#define RZ_LIB_VERSION(x) \
	RZ_API const char *x##_version(void) { \
		return "" RZ_VERSION; \
	}
#define RZ_LIB_VERSION_HEADER(x) \
	RZ_API const char *x##_version(void)
#define RZ_MEM_ALIGN(x)  ((void *)(size_t)(((ut64)(size_t)x) & 0xfffffffffffff000LL))
#define RZ_MODE_ARRAY     0x010
#define RZ_MODE_CLASSDUMP 0x040
#define RZ_MODE_EQUAL     0x080
#define RZ_MODE_JSON      0x008
#define RZ_MODE_PRINT     0x000
#define RZ_MODE_RIZINCMD  0x001
#define RZ_MODE_SET       0x002
#define RZ_MODE_SIMPLE    0x004
#define RZ_MODE_SIMPLEST  0x020
#define RZ_NEW(x)        (x *)malloc(sizeof(x))
#define RZ_NEW0(x)       (x *)calloc(1, sizeof(x))
#define RZ_NEWCOPY(x, y) (x *)rz_new_copy(sizeof(x), y)
#define RZ_NEWS(x, y)    (x *)malloc(sizeof(x) * (y))
#define RZ_NEWS0(x, y)   (x *)calloc(y, sizeof(x))
#define RZ_NEW_COPY(x, y) \
	x = (void *)malloc(sizeof(y)); \
	memcpy(x, y, sizeof(y))
#define RZ_NONNULL   __attribute__((annotate("RZ_NONNULL")))
#define RZ_NULLABLE  __attribute__((annotate("RZ_NULLABLE")))
#define RZ_OUT   
#define RZ_OWN    __attribute__((annotate("RZ_OWN")))
#define RZ_PERM_ACCESS 32
#define RZ_PERM_CREAT  64
#define RZ_PERM_PRIV   16
#define RZ_PERM_R      4
#define RZ_PERM_RW     (RZ_PERM_R | RZ_PERM_W)
#define RZ_PERM_RWX    (RZ_PERM_R | RZ_PERM_W | RZ_PERM_X)
#define RZ_PERM_RX     (RZ_PERM_R | RZ_PERM_X)
#define RZ_PERM_SHAR   8
#define RZ_PERM_W      2
#define RZ_PERM_WX     (RZ_PERM_W | RZ_PERM_X)
#define RZ_PERM_X      1
#define RZ_PRINTF_CHECK(fmt, dots) __attribute__((format(printf, fmt, dots)))
#define RZ_PTR_ALIGN(v, t) \
	((char *)(((size_t)(v)) & ~(t - 1)))
#define RZ_PTR_ALIGN_NEXT(v, t) \
	((char *)(((size_t)(v) + (t - 1)) & ~(t - 1)))
#define RZ_PTR_MOVE(d, s) \
	d = s; \
	s = NULL;
#define RZ_REF_FUNCTIONS(s, n) \
	static inline void n##_ref(s *x) { \
		x->RZ_REF_NAME++; \
	} \
	static inline void n##_unref(s *x) { \
		rz_unref(x, n##_free); \
	}
#define RZ_REF_NAME    refcount
#define RZ_REF_TYPE RzRef RZ_REF_NAME
#define RZ_SYS_ARCH   "x86"
#define RZ_SYS_BASE ((ut64)0x1000)
#define RZ_SYS_BITS   (RZ_SYS_BITS_32)
#define RZ_SYS_DIR    "\\"
#define RZ_SYS_ENDIAN 0
#define RZ_SYS_ENDIAN_BI     3
#define RZ_SYS_ENDIAN_BIG    2
#define RZ_SYS_ENDIAN_LITTLE 1
#define RZ_SYS_ENDIAN_NONE   0
#define RZ_SYS_ENVSEP ";"
#define RZ_SYS_HOME   "USERPROFILE"
#define RZ_SYS_OS "qnx"
#define RZ_SYS_TMP    "TEMP"

#define RZ_UNUSED __attribute__((__unused__))
#define RZ_V_NOT(op, fail_ret) \
	if ((op) == (fail_ret)) \
	RZ_LOG_WARN(#op " at %s:%d failed: %s\n", "__FILE__", "__LINE__", strerror(errno))
#define TARGET_OS_IPHONE 1
#define UNUSED_FUNCTION(x) __attribute__((__unused__)) UNUSED_##x
#define ZERO_FILL(x)     memset(&x, 0, sizeof(x))
#define _FILE_OFFSET_BITS 64

#define _WINSOCKAPI_ 
#define __BSD__  0
#define __KFBSD__ 1
#define __POWERPC__ 1
#define __UNIX__ 1
#define __WINDOWS__ 1
#define __arm64__     1
#define __arm__       1
#define __func__ __FUNCTION__
#define __i386__      1
#define __packed __attribute__((__packed__))
#define __x86_64__    1
#define _perror(str, file, line, func) \
	{ \
		char buf[256]; \
		snprintf(buf, sizeof(buf), "[%s:%d %s] %s", file, line, func, str); \
		rz_sys_perror_str(buf); \
	}
#define container_of(ptr, type, member) ((type *)((char *)(ptr)-offsetof(type, member)))
#define eprintf(...) fprintf(stderr, __VA_ARGS__)
#define perror(x)        _perror(x, "__FILE__", "__LINE__", __func__)

#define rz_offsetof(type, member) offsetof(type, member)
#define rz_ref(x)      x->RZ_REF_NAME++;
#define rz_ref_init(x) x->RZ_REF_NAME = 1
#define rz_sys_perror(x) _perror(x, "__FILE__", "__LINE__", __func__)
#define rz_unref(x, f) \
	{ \
		assert(x->RZ_REF_NAME > 0); \
		if (!--(x->RZ_REF_NAME)) { \
			f(x); \
		} \
	}
#define rz_xfreopen(pathname, mode, stream) RZ_V_NOT(freopen(pathname, mode, stream), NULL)
#define rz_xread(fd, buf, count)            RZ_V_NOT(read(fd, buf, count), -1)
#define rz_xwrite(fd, buf, count)           RZ_V_NOT(write(fd, buf, count), -1)
#define strcasecmp  stricmp
#define strncasecmp strnicmp
#define typeof(arg) __typeof__(arg)

#define RZ_DEFINE_CONSTRUCTOR(_func) \
	static void _func(void);
#define RZ_DEFINE_CONSTRUCTOR_NEEDS_PRAGMA 1
#define RZ_DEFINE_CONSTRUCTOR_PRAGMA_ARGS(_func) \
	init(_func)
#define RZ_DEFINE_DESTRUCTOR(_func) \
	static void _func(void); \
	static int _func##_constructor(void) { \
		atexit(_func); \
		return 0; \
	} \
	__declspec(allocate(".CRT$XCU")) static int (*_array##_func)(void) = _func##_constructor;
#define RZ_DEFINE_DESTRUCTOR_NEEDS_PRAGMA  1
#define RZ_DEFINE_DESTRUCTOR_PRAGMA_ARGS(_func) \
	section(".CRT$XCU", read)
#define RZ_HAS_CONSTRUCTORS 1
#define RZ_MSVC_CTOR(_func, _sym_prefix) \
	static void _func(void); \
	extern int (*_array##_func)(void); \
	int _func##_wrapper(void) { \
		_func(); \
		char *_func##_var = rz_str_new(""); \
		free(_func##_var); \
		return 0; \
	} \
	__pragma(comment(linker, "/include:" _sym_prefix #_func "_wrapper")) \
		__pragma(section(".CRT$XCU", read)) __declspec(allocate(".CRT$XCU")) int (*_array##_func)(void) = _func##_wrapper;
#define RZ_MSVC_DTOR(_func, _sym_prefix) \
	static void _func(void); \
	extern int (*_array##_func)(void); \
	int _func##_constructor(void) { \
		atexit(_func); \
		char *_func##_var = rz_str_new(""); \
		free(_func##_var); \
		return 0; \
	} \
	__pragma(comment(linker, "/include:" _sym_prefix #_func "_constructor")) \
		__pragma(section(".CRT$XCU", read)) __declspec(allocate(".CRT$XCU")) int (*_array##_func)(void) = _func##_constructor;
#define RZ_MSVC_SYMBOL_PREFIX "_"

#define ASCII_MAX 127
#define ASCII_MIN 32
#define B0000  0
#define B0001  1
#define B0010  2
#define B0011  3
#define B0100  4
#define B0101  5
#define B0110  6
#define B0111  7
#define B1000  8
#define B10000 16
#define B10001 17
#define B1001  9
#define B10010 18
#define B10011 19
#define B1010  10
#define B10100 20
#define B10101 21
#define B1011  11
#define B10110 22
#define B10111 23
#define B1100  12
#define B11000 24
#define B11001 25
#define B1101  13
#define B11010 26
#define B11011 27
#define B1110  14
#define B11100 28
#define B11101 29
#define B1111  15
#define B11110 30
#define B11111 31
#define B4(a, b, c, d) ((a << 12) | (b << 8) | (c << 4) | (d))
#define B_EVEN(x)      (((x)&1) == 0)
#define B_IS_SET(x, n) (((x) & (1ULL << (n))) ? 1 : 0)
#define B_ODD(x)       (!B_EVEN((x)))
#define B_SET(x, n)    ((x) |= (1ULL << (n)))
#define B_TOGGLE(x, n) ((x) ^= (1ULL << (n)))
#define B_UNSET(x, n)  ((x) &= ~(1ULL << (n)))
#define DEBUGGER 0
#define HEAPTYPE(x) \
	static x *x##_new(x n) { \
		x *m = malloc(sizeof(x)); \
		return m ? *m = n, m : m; \
	}
#define INFINITY (1.0f / 0.0f)
#define NAN (0.0f / 0.0f)
#define RZ_ABS(x)       (((x) < 0) ? -(x) : (x))
#define RZ_ALIGNED(x) __declspec(align(x))
#define RZ_BETWEEN(x, y, z) (((y) >= (x)) && ((y) <= (z)))
#define RZ_BTW(x, y, z) (((x) >= (y)) && ((y) <= (z))) ? y : x
#define RZ_DIM(x, y, z)     (((x) < (y)) ? (y) : ((x) > (z)) ? (z) \
							     : (x))
#define RZ_EMPTY \
	{ 0 }
#define RZ_EMPTY2 \
	{ \
		{ 0 } \
	}
#define RZ_MAX(x, y) (((x) > (y)) ? (x) : (y))

#define RZ_MIN(x, y) (((x) > (y)) ? (y) : (x))

#define RZ_PACKED(__Declaration__) __pragma(pack(push, 1)) __Declaration__ __pragma(pack(pop))
#define RZ_ROUND(x, y)      ((x) % (y)) ? (x) + ((y) - ((x) % (y))) : (x)

#define SSZT_MAX ST32_MAX
#define SSZT_MIN ST32_MIN
#define ST16_MAX  0x7FFF
#define ST16_MIN  (-ST16_MAX - 1)
#define ST32_MAX  0x7FFFFFFF
#define ST32_MIN  (-ST32_MAX - 1)
#define ST64_MAX  ((st64)0x7FFFFFFFFFFFFFFFULL)
#define ST64_MIN  ((st64)(-ST64_MAX - 1))
#define ST8_MAX   0x7F
#define ST8_MIN   (-ST8_MAX - 1)
#define SZT_MAX  UT32_MAX
#define SZT_MIN  UT32_MIN
#define UT16_ALIGN(x) (x + (x - (x % sizeof(ut16))))
#define UT16_GT0  0x8000U
#define UT16_MAX  0xFFFFU
#define UT16_MIN  0U
#define UT32_ALIGN(x) (x + (x - (x % sizeof(ut32))))
#define UT32_GT0  0x80000000U
#define UT32_HI(x) ((ut32)(((ut64)(x)) >> 32) & UT32_MAX)
#define UT32_LO(x) ((ut32)((x)&UT32_MAX))
#define UT32_LT0  0x7FFFFFFFU
#define UT32_MAX  0xFFFFFFFFU
#define UT32_MIN  0U
#define UT64_16U  0xFFFFFFFFFFFF0000ULL
#define UT64_32U  0xFFFFFFFF00000000ULL
#define UT64_8U   0xFFFFFFFFFFFFFF00ULL
#define UT64_ALIGN(x) (x + (x - (x % sizeof(ut64))))
#define UT64_GT0  0x8000000000000000ULL
#define UT64_LT0  0x7FFFFFFFFFFFFFFFULL
#define UT64_MAX  0xFFFFFFFFFFFFFFFFULL
#define UT64_MIN  0ULL
#define UT8_GT0   0x80U
#define UT8_MAX   0xFFU
#define UT8_MIN   0x00U
#define boolt int
#define cut8  const unsigned char
#define st16  short
#define st32  int
#define st64  long long
#define st8   signed char
#define ut16  unsigned short
#define ut32  unsigned int
#define ut64  unsigned long long
#define ut8   unsigned char

#define SIGNED_DIV_OVERFLOW_CHECK(overflow_name, type_base, type_mid, type_max) \
	static inline bool overflow_name(type_base a, type_base b) { \
		return (!b || (a == type_mid && b == type_max)); \
	}
#define SIGNED_MUL_OVERFLOW_CHECK(overflow_name, type_base, type_min, type_max) \
	static inline bool overflow_name(type_base a, type_base b) { \
		if (a > 0) { \
			if (b > 0) { \
				return a > type_max / b; \
			} \
			return b < type_min / a; \
		} \
		if (b > 0) { \
			return a < type_min / b; \
		} \
		return a && b < type_max / a; \
	}
#define SSZT_ADD_OVFCHK(a, x) ((((x) > 0) && ((a) > SSIZE_MAX - (x))) || (((x) < 0) && (a) < SSIZE_MIN - (x)))
#define SSZT_SUB_OVFCHK(a, b) SSZT_ADD_OVFCHK(a, -(b))
#define ST16_ADD_OVFCHK(a, b) ((((b) > 0) && ((a) > ST16_MAX - (b))) || (((b) < 0) && ((a) < ST16_MIN - (b))))
#define ST16_SUB_OVFCHK(a, b) ST16_ADD_OVFCHK(a, -(b))
#define ST32_ADD_OVFCHK(a, x) ((((x) > 0) && ((a) > ST32_MAX - (x))) || (((x) < 0) && (a) < ST32_MIN - (x)))
#define ST32_SUB_OVFCHK(a, b) ST32_ADD_OVFCHK(a, -(b))
#define ST64_ADD_OVFCHK(a, x) ((((x) > 0) && ((a) > ST64_MAX - (x))) || (((x) < 0) && (a) < ST64_MIN - (x)))
#define ST64_SUB_OVFCHK(a, b) ST64_ADD_OVFCHK(a, -(b))
#define ST8_ADD_OVFCHK(a, x)  ((((x) > 0) && ((a) > ST8_MAX - (x))) || ((x) < 0 && (a) < ST8_MIN - (x)))
#define ST8_SUB_OVFCHK(a, b)  ST8_ADD_OVFCHK(a, -(b))
#define SZT_ADD_OVFCHK(x, y)  ((SIZE_MAX - (x)) < (y))
#define SZT_SUB_OVFCHK(a, b)  SZT_ADD_OVFCHK(a, -(b))
#define UNSIGNED_DIV_OVERFLOW_CHECK(overflow_name, type_base, type_min, type_max) \
	static inline bool overflow_name(type_base a, type_base b) { \
		(void)a; \
		return !b; \
	}
#define UNSIGNED_MUL_OVERFLOW_CHECK(overflow_name, type_base, type_min, type_max) \
	static inline bool overflow_name(type_base a, type_base b) { \
		return (a > 0 && b > 0 && a > type_max / b); \
	}
#define UT16_ADD_OVFCHK(x, y) ((UT16_MAX - (x)) < (y))
#define UT16_SUB_OVFCHK(a, b) UT16_ADD_OVFCHK(a, -(b))
#define UT32_ADD_OVFCHK(x, y) ((UT32_MAX - (x)) < (y))
#define UT32_SUB_OVFCHK(a, b) UT32_ADD_OVFCHK(a, -(b))
#define UT64_ADD_OVFCHK(x, y) ((UT64_MAX - (x)) < (y))
#define UT64_SUB_OVFCHK(a, b) UT64_ADD_OVFCHK(a, -(b))
#define UT8_ADD_OVFCHK(x, y)  ((UT8_MAX - (x)) < (y))
#define UT8_SUB_OVFCHK(a, b)  UT8_ADD_OVFCHK(a, -(b))
#define IS_DIGIT(x)      ((x) >= '0' && (x) <= '9')
#define IS_HEXCHAR(x)    (((x) >= '0' && (x) <= '9') || ((x) >= 'a' && (x) <= 'f') || ((x) >= 'A' && (x) <= 'F'))
#define IS_LOWER(c)      ((c) >= 'a' && (c) <= 'z')
#define IS_NULLSTR(x)   (!(x) || !*(x))
#define IS_OCTAL(x)      ((x) >= '0' && (x) <= '7')
#define IS_PRINTABLE(x)  ((x) >= ' ' && (x) <= '~')
#define IS_SEPARATOR(x) ((x) == ' ' || (x) == '\t' || (x) == '\n' || (x) == '\r' || (x) == ' ' || \
	(x) == ',' || (x) == ';' || (x) == ':' || (x) == '[' || (x) == ']' || \
	(x) == '(' || (x) == ')' || (x) == '{' || (x) == '}')
#define IS_UPPER(c)      ((c) >= 'A' && (c) <= 'Z')
#define IS_WHITECHAR(x) ((x) == ' ' || (x) == '\t' || (x) == '\n' || (x) == '\r')
#define IS_WHITESPACE(x) ((x) == ' ' || (x) == '\t')



#define RZ_SUBPROCESS_STDERR (1 << 2)
#define RZ_SUBPROCESS_STDIN  (1 << 0)
#define RZ_SUBPROCESS_STDOUT (1 << 1)


#define RZ_STRBUF_SAFEGET(sb) (rz_strbuf_get(sb) ? rz_strbuf_get(sb) : "")

#define RzNumBig mpz_t




#define RZ_PRINT_JSON_DEPTH_LIMIT 128
#define ASN1_CLASS    0xC0 
#define ASN1_FORM     0x20 
#define ASN1_JSON_EMPTY "{}"
#define ASN1_JSON_NULL  "null"
#define ASN1_LENLONG  0x80 
#define ASN1_LENSHORT 0x7F 
#define ASN1_OID_LEN 64
#define ASN1_TAG      0x1F 
#define CLASS_APPLICATION 0x40 
#define CLASS_CONTEXT     0x80 
#define CLASS_PRIVATE     0xC0 
#define CLASS_UNIVERSAL   0x00 
#define FORM_CONSTRUCTED 0x20 
#define FORM_PRIMITIVE   0x00 

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


#define rz_list_empty(x) (!(x) || !(x)->length)
#define rz_list_foreach(list, it, pos) \
	if (list) \
		for (it = list->head; it && (pos = it->data, 1); it = it->n)
#define rz_list_foreach_iter(list, it) \
	if (list) \
		for (it = list->head; it; it = it->n)
#define rz_list_foreach_prev(list, it, pos) \
	if (list) \
		for (it = list->tail; it && (pos = it->data, 1); it = it->p)
#define rz_list_foreach_prev_safe(list, it, tmp, pos) \
	for (it = list->tail; it && (pos = it->data, tmp = it->p, 1); it = tmp)
#define rz_list_foreach_safe(list, it, tmp, pos) \
	if (list) \
		for (it = list->head; it && (pos = it->data, tmp = it->n, 1); it = tmp)
#define rz_list_head(x)  ((x) ? (x)->head : NULL)
#define rz_list_iter_cur(x)  x->p
#define rz_list_iter_get(x) \
	x->data; \
	x = x->n
#define rz_list_iter_next(x) (x ? 1 : 0)
#define rz_list_tail(x)  ((x) ? (x)->tail : NULL)

#define rz_array_find(array, x, itr, start, stop, cmp) \
	do { \
		for (itr = start; itr < stop; itr++) { \
			if (cmp((array[itr]), x) == 0) { \
				break; \
			} \
		} \
		return itr; \
	} while (0)
#define rz_array_lower_bound(array, len, x, i, cmp) \
	do { \
		size_t h = len, m; \
		for (i = 0; i < h;) { \
			m = i + ((h - i) >> 1); \
			if (cmp((x), ((array)[m])) > 0) { \
				i = m + 1; \
			} else { \
				h = m; \
			} \
		} \
	} while (0)
#define rz_array_upper_bound(array, len, x, i, cmp) \
	do { \
		size_t h = len, m; \
		for (i = 0; i < h;) { \
			m = i + ((h - i) >> 1); \
			if (cmp((x), ((array)[m])) < 0) { \
				h = m; \
			} else { \
				i = m + 1; \
			} \
		} \
	} while (0)
#define rz_pvector_foreach(vec, it) \
	for (it = (void **)(vec)->v.a; (vec)->v.len && it != (void **)(vec)->v.a + (vec)->v.len; it++)
#define rz_pvector_foreach_prev(vec, it) \
	for (it = ((vec)->v.len == 0 ? NULL : (void **)(vec)->v.a + (vec)->v.len - 1); it && it != (void **)(vec)->v.a - 1; it--)
#define rz_pvector_lower_bound(vec, x, i, cmp) \
	rz_array_lower_bound((void **)(vec)->v.a, (vec)->v.len, x, i, cmp)
#define rz_pvector_upper_bound(vec, x, i, cmp) \
	rz_array_upper_bound((void **)(vec)->v.a, (vec)->v.len, x, i, cmp)
#define rz_vector_enumerate(vec, it, i) \
	if (!rz_vector_empty(vec)) \
		for (it = (void *)(vec)->a, i = 0; i < (vec)->len; it = (void *)((char *)it + (vec)->elem_size), i++)
#define rz_vector_foreach(vec, it) \
	if (!rz_vector_empty(vec)) \
		for (it = (void *)(vec)->a; (char *)it != (char *)(vec)->a + ((vec)->len * (vec)->elem_size); it = (void *)((char *)it + (vec)->elem_size))
#define rz_vector_foreach_prev(vec, it) \
	if (!rz_vector_empty(vec)) \
		for (it = (void *)((char *)(vec)->a + (((vec)->len - 1) * (vec)->elem_size)); (char *)it != (char *)(vec)->a - (vec)->elem_size; it = (void *)((char *)it - (vec)->elem_size))
#define rz_vector_lower_bound(vec, x, i, cmp) \
	do { \
		size_t h = (vec)->len, m; \
		for (i = 0; i < h;) { \
			m = i + ((h - i) >> 1); \
			if ((cmp(x, ((char *)(vec)->a + (vec)->elem_size * m))) > 0) { \
				i = m + 1; \
			} else { \
				h = m; \
			} \
		} \
	} while (0)
#define rz_vector_upper_bound(vec, x, i, cmp) \
	do { \
		size_t h = (vec)->len, m; \
		for (i = 0; i < h;) { \
			m = i + ((h - i) >> 1); \
			if ((cmp(x, ((char *)(vec)->a + (vec)->elem_size * m))) < 0) { \
				h = m; \
			} else { \
				i = m + 1; \
			} \
		} \
	} while (0)
#define H_LOG_(loglevel, fmt, ...)

#define RZ_CHECKS_LEVEL 2
#define RZ_FUNCTION ((const char *)(__PRETTY_FUNCTION__))
#define RZ_STATIC_ASSERT(x) \
	switch (0) { \
	case 0: \
	case (x):; \
	}
#define rz_goto_if_reached(where) \
	do { \
		H_LOG_(RZ_LOGLVL_ERROR, "file %s: line %d (%s): should not be reached; jumping to %s\n", "__FILE__", "__LINE__", RZ_FUNCTION, #where); \
		goto where; \
	} while (0)
#define rz_return_if_fail(expr) \
	do { \
		if (!(expr)) { \
			H_LOG_(RZ_LOGLVL_WARN, "%s: assertion '%s' failed (line %d)\n", RZ_FUNCTION, #expr, "__LINE__"); \
			return; \
		} \
	} while (0)
#define rz_return_if_reached() \
	do { \
		H_LOG_(RZ_LOGLVL_ERROR, "file %s: line %d (%s): should not be reached\n", "__FILE__", "__LINE__", RZ_FUNCTION); \
		return; \
	} while (0)
#define rz_return_val_if_fail(expr, val) \
	do { \
		if (!(expr)) { \
			H_LOG_(RZ_LOGLVL_WARN, "%s: assertion '%s' failed (line %d)\n", RZ_FUNCTION, #expr, "__LINE__"); \
			return (val); \
		} \
	} while (0)
#define rz_return_val_if_reached(val) \
	do { \
		H_LOG_(RZ_LOGLVL_ERROR, "file %s: line %d (%s): should not be reached\n", "__FILE__", "__LINE__", RZ_FUNCTION); \
		return (val); \
	} while (0)
#define rz_warn_if_fail(expr) \
	do { \
		if (!(expr)) { \
			rz_assert_log(RZ_LOGLVL_WARN, "(%s:%d):%s%s runtime check failed: (%s)\n", \
				"__FILE__", "__LINE__", RZ_FUNCTION, RZ_FUNCTION[0] ? ":" : "", #expr); \
		} \
	} while (0)
#define rz_warn_if_reached() \
	do { \
		rz_assert_log(RZ_LOGLVL_WARN, "(%s:%d):%s%s code should not be reached\n", \
			"__FILE__", "__LINE__", RZ_FUNCTION, RZ_FUNCTION[0] ? ":" : ""); \
	} while (0)



#define rz_acp_to_utf8(str)     rz_acp_to_utf8_l((char *)str, -1)
#define rz_utf16_to_utf8(wc)      rz_utf16_to_utf8_l((wchar_t *)wc, -1)
#define rz_utf8_to_acp(cstring) rz_utf8_to_acp_l((char *)cstring, -1)
#define rz_utf8_to_utf16(cstring) rz_utf8_to_utf16_l((char *)cstring, -1)


#define RZ_SYS_DEVNULL "/dev/null"

#define W32_TCALL(name)                     name "W"
#define W32_TCHAR_FSTR                      "%S"
#define __has_builtin(n) (0)
#define rz_sys_breakpoint() __builtin_debugtrap()
#define rz_sys_conv_utf8_to_win(buf)        rz_utf8_to_utf16(buf)
#define rz_sys_conv_utf8_to_win_l(buf, len) rz_utf8_to_utf16_l(buf, len)
#define rz_sys_conv_win_to_utf8(buf)        rz_utf16_to_utf8(buf)
#define rz_sys_conv_win_to_utf8_l(buf, len) rz_utf16_to_utf8_l((wchar_t *)buf, len)
#define rz_sys_execl execl
#define rz_sys_execv execv
#define rz_sys_execve execve
#define rz_sys_execvp execvp
#define rz_sys_mkdir_failed() (errno != EEXIST)
#define rz_sys_pipe       pipe
#define rz_sys_pipe_close close
#define rz_sys_system system
#define rz_sys_trap() __asm__ __volatile__(".word 0");
#define rz_sys_xsystem(cmd) RZ_V_NOT(rz_sys_system(cmd), -1)


#define RZ_STRPOOL_INC 1024

#define DEFINE_RZ_BUF_READ_BLE(size) \
	static inline bool rz_buf_read_ble##size(RZ_NONNULL RzBuffer *b, RZ_NONNULL RZ_OUT ut##size *result, bool big_endian) { \
		rz_return_val_if_fail(b &&result, false); \
\
		ut8 tmp[sizeof(ut##size)]; \
		if (rz_buf_read(b, tmp, sizeof(tmp)) != sizeof(tmp)) { \
			return false; \
		} \
\
		*result = rz_read_ble##size(tmp, big_endian); \
		return true; \
	} \
\
	static inline bool rz_buf_read_ble##size##_at(RZ_NONNULL RzBuffer *b, ut64 addr, RZ_NONNULL RZ_OUT ut##size *result, bool big_endian) { \
		rz_return_val_if_fail(b &&result, false); \
\
		ut8 tmp[sizeof(ut##size)]; \
		if (rz_buf_read_at(b, addr, tmp, sizeof(tmp)) != sizeof(tmp)) { \
			return false; \
		} \
\
		*result = rz_read_ble##size(tmp, big_endian); \
		return true; \
	}
#define DEFINE_RZ_BUF_READ_OFFSET_BLE(size) \
	static inline bool rz_buf_read_ble##size##_offset(RZ_NONNULL RzBuffer *b, RZ_NONNULL RZ_INOUT ut64 *offset, RZ_NONNULL RZ_OUT ut##size *result, bool big_endian) { \
		rz_return_val_if_fail(b &&offset &&result, false); \
		if (!rz_buf_read_ble##size##_at(b, *offset, result, big_endian)) { \
			return false; \
		} \
		*offset += sizeof(*result); \
		return true; \
	}
#define DEFINE_RZ_BUF_WRITE_BLE(size) \
	static inline bool rz_buf_write_ble##size(RZ_NONNULL RzBuffer *b, ut##size value, bool big_endian) { \
		ut8 tmp[sizeof(ut##size)]; \
		rz_write_ble##size(tmp, value, big_endian); \
\
		return rz_buf_write(b, tmp, sizeof(tmp)) == sizeof(tmp); \
	} \
\
	static inline bool rz_buf_write_ble##size##_at(RZ_NONNULL RzBuffer *b, ut64 addr, ut##size value, bool big_endian) { \
		ut8 tmp[sizeof(ut##size)]; \
		rz_write_ble##size(tmp, value, big_endian); \
\
		return rz_buf_write_at(b, addr, tmp, sizeof(tmp)) == sizeof(tmp); \
	}
#define DEFINE_RZ_BUF_WRITE_OFFSET_BLE(size) \
	static inline bool rz_buf_write_ble##size##_offset(RZ_NONNULL RzBuffer *b, RZ_NONNULL RZ_INOUT ut64 *offset, ut##size value, bool big_endian) { \
		rz_return_val_if_fail(b &&offset, false); \
		if (!rz_buf_write_ble##size##_at(b, *offset, value, big_endian)) { \
			return false; \
		} \
		*offset += sizeof(value); \
		return true; \
	}
#define RZ_BUF_CUR 1
#define RZ_BUF_END 2

#define RZ_BUF_SET 0
#define rz_buf_read8_offset(b, offset, result) rz_buf_read_ble8_offset(b, offset, result, false)
#define rz_buf_read_be16(b, result) rz_buf_read_ble16(b, result, true)
#define rz_buf_read_be16_at(b, addr, result) rz_buf_read_ble16_at(b, addr, result, true)
#define rz_buf_read_be16_offset(b, offset, result) rz_buf_read_ble16_offset(b, offset, result, true)
#define rz_buf_read_be32(b, result) rz_buf_read_ble32(b, result, true)
#define rz_buf_read_be32_at(b, addr, result) rz_buf_read_ble32_at(b, addr, result, true)
#define rz_buf_read_be32_offset(b, offset, result) rz_buf_read_ble32_offset(b, offset, result, true)
#define rz_buf_read_be64(b, result) rz_buf_read_ble64(b, result, true)
#define rz_buf_read_be64_at(b, addr, result) rz_buf_read_ble64_at(b, addr, result, true)
#define rz_buf_read_be64_offset(b, offset, result) rz_buf_read_ble64_offset(b, offset, result, true)
#define rz_buf_read_ble8_at(b, addr, result, endian) ((void)endian, rz_buf_read8_at(b, addr, result))
#define rz_buf_read_le16(b, result) rz_buf_read_ble16(b, result, false)
#define rz_buf_read_le16_at(b, addr, result) rz_buf_read_ble16_at(b, addr, result, false)
#define rz_buf_read_le16_offset(b, offset, result) rz_buf_read_ble16_offset(b, offset, result, false)
#define rz_buf_read_le32(b, result) rz_buf_read_ble32(b, result, false)
#define rz_buf_read_le32_at(b, addr, result) rz_buf_read_ble32_at(b, addr, result, false)
#define rz_buf_read_le32_offset(b, offset, result) rz_buf_read_ble32_offset(b, offset, result, false)
#define rz_buf_read_le64(b, result) rz_buf_read_ble64(b, result, false)
#define rz_buf_read_le64_at(b, addr, result) rz_buf_read_ble64_at(b, addr, result, false)
#define rz_buf_read_le64_offset(b, offset, result) rz_buf_read_ble64_offset(b, offset, result, false)
#define rz_buf_write8_offset(b, offset, value) rz_buf_write_ble8_offset(b, offset, value, false)
#define rz_buf_write_be16(b, value) rz_buf_write_ble16(b, value, true)
#define rz_buf_write_be16_at(b, addr, value) rz_buf_write_ble16_at(b, addr, value, true)
#define rz_buf_write_be16_offset(b, offset, value) rz_buf_write_ble16_offset(b, offset, value, true)
#define rz_buf_write_be32(b, value) rz_buf_write_ble32(b, value, true)
#define rz_buf_write_be32_at(b, addr, value) rz_buf_write_ble32_at(b, addr, value, true)
#define rz_buf_write_be32_offset(b, offset, value) rz_buf_write_ble32_offset(b, offset, value, true)
#define rz_buf_write_be64(b, value) rz_buf_write_ble64(b, value, true)
#define rz_buf_write_be64_at(b, addr, value) rz_buf_write_ble64_at(b, addr, value, true)
#define rz_buf_write_be64_offset(b, offset, value) rz_buf_write_ble64_offset(b, offset, value, true)
#define rz_buf_write_ble8_at(b, addr, value, endian) ((void)endian, rz_buf_write8_at(b, addr, value))
#define rz_buf_write_le16(b, value) rz_buf_write_ble16(b, value, false)
#define rz_buf_write_le16_at(b, addr, value) rz_buf_write_ble16_at(b, addr, value, false)
#define rz_buf_write_le16_offset(b, offset, value) rz_buf_write_ble16_offset(b, offset, value, false)
#define rz_buf_write_le32(b, value) rz_buf_write_ble32(b, value, false)
#define rz_buf_write_le32_at(b, addr, value) rz_buf_write_ble32_at(b, addr, value, false)
#define rz_buf_write_le32_offset(b, offset, value) rz_buf_write_ble32_offset(b, offset, value, false)
#define rz_buf_write_le64(b, value) rz_buf_write_ble64(b, value, false)
#define rz_buf_write_le64_at(b, addr, value) rz_buf_write_ble64_at(b, addr, value, false)
#define rz_buf_write_le64_offset(b, offset, value) rz_buf_write_ble64_offset(b, offset, value, false)

#define RZ_STR_DUP(x)        ((x) ? strdup((x)) : NULL)

#define RZ_STR_ISEMPTY(x)    (!(x) || !*(x))
#define RZ_STR_ISNOTEMPTY(x) ((x) && *(x))
#define rz_str_array(x, y)   ((y >= 0 && y < (sizeof(x) / sizeof(*x))) ? x[y] : "")
#define rz_str_cat(x, y) memmove((x) + strlen(x), (y), strlen(y) + 1);
#define rz_str_cpy(x, y) memmove((x), (y), strlen(y) + 1);
#define rz_strf(buf, ...) ( \
	snprintf(buf, sizeof(buf), __VA_ARGS__) < 0 \
	? rz_assert_log(RZ_LOGLVL_FATAL, "rz_strf error while using snprintf"), \
	NULL \
	: buf)



#define RZ_SPACES_MAX 512
#define rz_spaces_foreach(sp, it, s) \
	rz_rbtree_foreach ((sp)->spaces, (it), (s), RzSpace, rb)







#define CONVERT_TO_TWO_COMPLEMENT(x) \
	static inline st##x convert_to_two_complement_##x(ut##x value) { \
		if (value <= ST##x##_MAX) { \
			return (st##x)value; \
		} \
\
		value = ~value + 1; \
		return -(st##x)value; \
	}
#define RZ_NUMCALC_STRSZ 1024
#define RZ_NUM_CMP(a, b) ((a) > (b) ? 1 : ((b) > (a) ? -1 : 0))


#define MACRO_LOG_FUNC __func__
#define RZ_DEFAULT_LOGLVL RZ_LOGLVL_WARN
#define RZ_LOG(lvl, tag, fmtstr, ...) rz_log(MACRO_LOG_FUNC, "__FILE__", \
	"__LINE__", lvl, tag, fmtstr, ##__VA_ARGS__);
#define RZ_LOG_DEBUG(fmtstr, ...) rz_log(MACRO_LOG_FUNC, "__FILE__", \
	"__LINE__", RZ_LOGLVL_DEBUG, NULL, fmtstr, ##__VA_ARGS__);
#define RZ_LOG_ERROR(fmtstr, ...) rz_log(MACRO_LOG_FUNC, "__FILE__", \
	"__LINE__", RZ_LOGLVL_ERROR, NULL, fmtstr, ##__VA_ARGS__);
#define RZ_LOG_FATAL(fmtstr, ...) rz_log(MACRO_LOG_FUNC, "__FILE__", \
	"__LINE__", RZ_LOGLVL_FATAL, NULL, fmtstr, ##__VA_ARGS__);

#define RZ_LOG_INFO(fmtstr, ...) rz_log(MACRO_LOG_FUNC, "__FILE__", \
	"__LINE__", RZ_LOGLVL_INFO, NULL, fmtstr, ##__VA_ARGS__);
#define RZ_LOG_SILLY(fmtstr, ...) rz_log(MACRO_LOG_FUNC, "__FILE__", \
	"__LINE__", RZ_LOGLVL_SILLY, NULL, fmtstr, ##__VA_ARGS__);
#define RZ_LOG_VERBOSE(fmtstr, ...) rz_log(MACRO_LOG_FUNC, "__FILE__", \
	"__LINE__", RZ_LOGLVL_VERBOSE, NULL, fmtstr, ##__VA_ARGS__);
#define RZ_LOG_WARN(fmtstr, ...) rz_log(MACRO_LOG_FUNC, "__FILE__", \
	"__LINE__", RZ_LOGLVL_WARN, NULL, fmtstr, ##__VA_ARGS__);
#define RZ_VLOG(lvl, tag, fmtstr, args) rz_vlog(MACRO_LOG_FUNC, "__FILE__", \
	"__LINE__", lvl, tag, fmtstr, args);



#define ASCTIME_BUF_MINLEN 26
#define RZ_NSEC_PER_MSEC 1000000ULL
#define RZ_NSEC_PER_SEC  1000000000ULL
#define RZ_NSEC_PER_USEC 1000ULL

#define RZ_TIME_PROFILE_BEGIN ut64 __now__ = rz_time_now_mono()
#define RZ_TIME_PROFILE_ENABLED 0
#define RZ_TIME_PROFILE_END   eprintf("%s %" PFMT64d "\n", __FUNCTION__, rz_time_now_mono() - __now__)
#define RZ_USEC_PER_MSEC 1000ULL
#define RZ_USEC_PER_SEC  1000000ULL
#define rz_time_date_unix_to_string rz_time_stamp_to_str

#define rz_bv_neg rz_bv_complement_2
#define rz_bv_new_minus_one(l) rz_bv_new_from_st64(l, -1)
#define rz_bv_new_one(l)       rz_bv_new_from_ut64(l, 1)
#define rz_bv_new_two(l)       rz_bv_new_from_ut64(l, 2)
#define rz_bv_new_zero(l)      rz_bv_new(l)
#define rz_bv_not rz_bv_complement_1
#define BITWORD_BITS_SHIFT 6
#define RBitword           ut64




#define rz_interval_tree_foreach(tree, it, dat) \
	for ((it) = rz_rbtree_first(&(tree)->root->node); rz_rbtree_iter_has(&it) && (dat = rz_interval_tree_iter_get(&it)->data); rz_rbtree_iter_next(&(it)))
#define rz_interval_tree_foreach_prev(tree, it, dat) \
	for ((it) = rz_rbtree_last(&(tree)->root->node); rz_rbtree_iter_has(&it) && (dat = rz_rbtree_iter_get(&it, RzIntervalNode, node)->data); rz_rbtree_iter_prev(&(it)))

#define RZ_RBTREE_MAX_HEIGHT 62
#define rz_rbtree_cont_foreach(tree, it, dat) \
	for ((it) = rz_rbtree_first((tree)->root ? &(tree)->root->node : NULL); rz_rbtree_iter_has(&it) && (dat = rz_rbtree_iter_get(&it, RContRBNode, node)->data); rz_rbtree_iter_next(&(it)))
#define rz_rbtree_cont_foreach_prev(tree, it, dat) \
	for ((it) = rz_rbtree_last((tree)->root ? &(tree)->root->node : NULL); rz_rbtree_iter_has(&it) && (dat = rz_rbtree_iter_get(&it, RContRBNode, node)->data); rz_rbtree_iter_prev(&(it)))
#define rz_rbtree_foreach(root, it, data, struc, rb) \
	for ((it) = rz_rbtree_first(root); rz_rbtree_iter_has(&it) && (data = rz_rbtree_iter_get(&it, struc, rb)); rz_rbtree_iter_next(&(it)))
#define rz_rbtree_foreach_prev(root, it, data, struc, rb) \
	for ((it) = rz_rbtree_last(root); rz_rbtree_iter_has(&it) && (data = rz_rbtree_iter_get(&it, struc, rb)); rz_rbtree_iter_prev(&(it)))
#define rz_rbtree_iter_get(it, struc, rb) (container_of((it)->path[(it)->len - 1], struc, rb))
#define rz_rbtree_iter_has(it) ((it)->len)
#define rz_rbtree_iter_while(it, data, struc, rb) \
	for (; rz_rbtree_iter_has(&it) && (data = rz_rbtree_iter_get(&it, struc, rb)); rz_rbtree_iter_next(&(it)))
#define rz_rbtree_iter_while_prev(it, data, struc, rb) \
	for (; rz_rbtree_iter_has(&it) && (data = rz_rbtree_iter_get(&it, struc, rb)); rz_rbtree_iter_prev(&(it)))
#define RZ_MALLOC_GLOBAL  0
#define RZ_MALLOC_WRAPPER 0
#define _R_UTIL_ALLOC_H_ 1
#define _r_calloc  rz_calloc
#define _r_free    rz_free
#define _r_malloc  rz_malloc
#define _r_realloc rz_realloc
#define rz_calloc(x, y)  calloc((x), (y))
#define rz_free(x)       free((x))
#define rz_malloc(x)     malloc((x))
#define rz_realloc(x, y) realloc((x), (y))



#define RZ_THREAD_POOL_ALL_CORES  (0)
#define RZ_THREAD_QUEUE_UNLIMITED (0)



#define rz_skiplist_foreach(list, it, pos) \
	if (list) \
		for (it = list->head->forward[0]; it != list->head && ((pos = it->data) || 1); it = it->forward[0])
#define rz_skiplist_foreach_safe(list, it, tmp, pos) \
	if (list) \
		for (it = list->head->forward[0]; it != list->head && ((pos = it->data) || 1) && ((tmp = it->forward[0]) || 1); it = tmp)
#define rz_skiplist_islast(list, el) (el->forward[0] == list->head)
#define rz_skiplist_length(list) (list->size)

#define RZ_REGEX_ASSERT   15
#define RZ_REGEX_ATOI     255 
#define RZ_REGEX_BACKR    02000 
#define RZ_REGEX_BADBR    10
#define RZ_REGEX_BADPAT   2
#define RZ_REGEX_BADRPT   13
#define RZ_REGEX_BASIC    0000
#define RZ_REGEX_DUMP     0200
#define RZ_REGEX_EBRACE   9
#define RZ_REGEX_EBRACK   7
#define RZ_REGEX_ECOLLATE 3
#define RZ_REGEX_ECTYPE   4
#define RZ_REGEX_EESCAPE  5
#define RZ_REGEX_EMPTY    14
#define RZ_REGEX_ENOSYS   (-1) 
#define RZ_REGEX_EPAREN   8
#define RZ_REGEX_ERANGE   11
#define RZ_REGEX_ESPACE   12
#define RZ_REGEX_ESUBREG  6
#define RZ_REGEX_EXTENDED 0001

#define RZ_REGEX_ICASE    0002
#define RZ_REGEX_ILLSEQ   17
#define RZ_REGEX_INVARG   16
#define RZ_REGEX_ITOA     0400 
#define RZ_REGEX_LARGE    01000 
#define RZ_REGEX_NEWLINE  0010
#define RZ_REGEX_NOMATCH  1
#define RZ_REGEX_NOSPEC   0020
#define RZ_REGEX_NOSUB    0004
#define RZ_REGEX_NOTBOL   00001
#define RZ_REGEX_NOTEOL   00002
#define RZ_REGEX_PEND     0040
#define RZ_REGEX_STARTEND 00004
#define RZ_REGEX_TRACE    00400 
#define RZ_DIFF_DEFAULT_N_GROUPS 3

#define RZ_DIFF_OP_SIZE_A(op)    (((op)->a_end) - ((op)->a_beg))
#define RZ_DIFF_OP_SIZE_B(op)    (((op)->b_end) - ((op)->b_beg))
#define DEX_CLASS_DEF_SIZE (0x20)
#define DEX_FIELD_ID_SIZE (8)
#define DEX_MAP_ITEM_SIZE (12)
#define DEX_METHOD_ID_SIZE (8)
#define DEX_PROTO_ID_SIZE (0xC)
#define DEX_TYPE_ID_SIZE (sizeof(DexTypeId))

#define RZ_DEX_RELOC_ADDRESS 0x8000000000
#define RZ_DEX_RELOC_TARGETS "reloc-targets"
#define RZ_DEX_VIRT_ADDRESS  0x0100000000
#define REBASE_PADDR(o, l, type_t) \
	do { \
		if ((o)->opts.loadaddr) { \
			RzListIter *_it; \
			type_t *_el; \
			rz_list_foreach ((l), _it, _el) { \
				_el->paddr += (o)->opts.loadaddr; \
			} \
		} \
	} while (0)
#define RZ_BIN_BIND_GLOBAL_STR  "GLOBAL"
#define RZ_BIN_BIND_HIOS_STR    "HIOS"
#define RZ_BIN_BIND_HIPROC_STR  "HIPROC"
#define RZ_BIN_BIND_IMPORT_STR  "IMPORT"
#define RZ_BIN_BIND_LOCAL_STR   "LOCAL"
#define RZ_BIN_BIND_LOOS_STR    "LOOS"
#define RZ_BIN_BIND_LOPROC_STR  "LOPROC"
#define RZ_BIN_BIND_NUM_STR     "NUM"
#define RZ_BIN_BIND_UNKNOWN_STR "UNKNOWN"
#define RZ_BIN_BIND_WEAK_STR    "WEAK"
#define RZ_BIN_DBG_LINENUMS 0x04
#define RZ_BIN_DBG_RELOCS   0x10
#define RZ_BIN_DBG_STATIC   0x02
#define RZ_BIN_DBG_STRIPPED 0x01
#define RZ_BIN_DBG_SYMS     0x08
#define RZ_BIN_ENTRY_TYPE_FINI    3
#define RZ_BIN_ENTRY_TYPE_INIT    2
#define RZ_BIN_ENTRY_TYPE_MAIN    1
#define RZ_BIN_ENTRY_TYPE_PREINIT 5
#define RZ_BIN_ENTRY_TYPE_PROGRAM 0
#define RZ_BIN_ENTRY_TYPE_TLS     4

#define RZ_BIN_LANGUAGE_HAS_BLOCKS(x) ((x)&RZ_BIN_LANGUAGE_BLOCKS)
#define RZ_BIN_LANGUAGE_MASK(x)       ((x) & ~RZ_BIN_LANGUAGE_BLOCKS)
#define RZ_BIN_MAX_ARCH       1024
#define RZ_BIN_METH_ABSTRACT              0x0000000000001000L
#define RZ_BIN_METH_BRIDGE                0x0000000000008000L
#define RZ_BIN_METH_CLASS                 0x0000000000000001L
#define RZ_BIN_METH_CONST                 0x0000000000000400L
#define RZ_BIN_METH_CONSTRUCTOR           0x0000000000100000L
#define RZ_BIN_METH_DECLARED_SYNCHRONIZED 0x0000000000200000L
#define RZ_BIN_METH_FILEPRIVATE           0x0000000000000080L
#define RZ_BIN_METH_FINAL                 0x0000000000000100L
#define RZ_BIN_METH_INTERNAL              0x0000000000000020L
#define RZ_BIN_METH_MIRANDA               0x0000000000080000L
#define RZ_BIN_METH_MUTATING              0x0000000000000800L
#define RZ_BIN_METH_NATIVE                0x0000000000004000L
#define RZ_BIN_METH_OPEN                  0x0000000000000040L
#define RZ_BIN_METH_PRIVATE               0x0000000000000008L
#define RZ_BIN_METH_PROTECTED             0x0000000000000010L
#define RZ_BIN_METH_PUBLIC                0x0000000000000004L
#define RZ_BIN_METH_STATIC                0x0000000000000002L
#define RZ_BIN_METH_STRICT                0x0000000000040000L
#define RZ_BIN_METH_SYNCHRONIZED          0x0000000000002000L
#define RZ_BIN_METH_SYNTHETIC             0x0000000000020000L
#define RZ_BIN_METH_VARARGS               0x0000000000010000L
#define RZ_BIN_METH_VIRTUAL               0x0000000000000200L
#define RZ_BIN_REQ_ALL              UT64_MAX
#define RZ_BIN_REQ_BASEFIND         0x800000000
#define RZ_BIN_REQ_CLASSES          0x010000
#define RZ_BIN_REQ_CLASSES_SOURCES  0x400000000
#define RZ_BIN_REQ_CREATE           0x008000
#define RZ_BIN_REQ_DLOPEN           0x200000
#define RZ_BIN_REQ_DWARF            0x020000
#define RZ_BIN_REQ_ENTRIES          0x000001
#define RZ_BIN_REQ_EXPORTS          0x400000
#define RZ_BIN_REQ_EXTRACT          0x001000
#define RZ_BIN_REQ_FIELDS           0x000100
#define RZ_BIN_REQ_HASHES           0x40000000
#define RZ_BIN_REQ_HEADER           0x2000000
#define RZ_BIN_REQ_HELP             0x000040
#define RZ_BIN_REQ_IMPORTS          0x000002
#define RZ_BIN_REQ_INFO             0x000010
#define RZ_BIN_REQ_INITFINI         0x10000000
#define RZ_BIN_REQ_LIBS             0x000200
#define RZ_BIN_REQ_LISTARCHS        0x004000
#define RZ_BIN_REQ_LISTPLUGINS      0x4000000
#define RZ_BIN_REQ_MAIN             0x000800
#define RZ_BIN_REQ_OPERATION        0x000020
#define RZ_BIN_REQ_PACKAGE          0x1000000
#define RZ_BIN_REQ_PDB              0x080000
#define RZ_BIN_REQ_PDB_DWNLD        0x100000
#define RZ_BIN_REQ_RELOCS           0x002000
#define RZ_BIN_REQ_RESOURCES        0x8000000
#define RZ_BIN_REQ_SECTIONS         0x000008
#define RZ_BIN_REQ_SECTIONS_MAPPING 0x200000000
#define RZ_BIN_REQ_SEGMENTS         0x20000000
#define RZ_BIN_REQ_SIGNATURE        0x80000000
#define RZ_BIN_REQ_SIZE             0x040000
#define RZ_BIN_REQ_SRCLINE          0x000400
#define RZ_BIN_REQ_STRINGS          0x000080
#define RZ_BIN_REQ_SYMBOLS          0x000004
#define RZ_BIN_REQ_TRYCATCH         0x100000000
#define RZ_BIN_REQ_UNK              0x000000
#define RZ_BIN_REQ_VERSIONINFO      0x800000
#define RZ_BIN_SIZEOF_STRINGS 512
#define RZ_BIN_TYPE_COMMON_STR      "COMMON"
#define RZ_BIN_TYPE_FIELD_STR       "FIELD"
#define RZ_BIN_TYPE_FILE_STR        "FILE"
#define RZ_BIN_TYPE_FUNC_STR        "FUNC"
#define RZ_BIN_TYPE_HIOS_STR        "HIOS"
#define RZ_BIN_TYPE_HIPROC_STR      "HIPROC"
#define RZ_BIN_TYPE_IFACE_STR       "IFACE"
#define RZ_BIN_TYPE_LOOS_STR        "LOOS"
#define RZ_BIN_TYPE_LOPROC_STR      "LOPROC"
#define RZ_BIN_TYPE_METH_STR        "METH"
#define RZ_BIN_TYPE_NOTYPE_STR      "NOTYPE"
#define RZ_BIN_TYPE_NUM_STR         "NUM"
#define RZ_BIN_TYPE_OBJECT_STR      "OBJ"
#define RZ_BIN_TYPE_SECTION_STR     "SECT"
#define RZ_BIN_TYPE_SPECIAL_SYM_STR "SPCL"
#define RZ_BIN_TYPE_STATIC_STR      "STATIC"
#define RZ_BIN_TYPE_TLS_STR         "TLS"
#define RZ_BIN_TYPE_UNKNOWN_STR     "UNK"
#define RzBinSectionName   rz_offsetof(RzBinSection, name)
#define RzBinSectionOffset rz_offsetof(RzBinSection, offset)
#define CAB_SIGNATURE     "MSCF"
#define GET_BF(value, start, len) (((value) >> (start)) & ((1 << len) - 1))
#define PDB_SIGNATURE     "Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\x00\x00\x00"
#define PDB_SIGNATURE_LEN 32

#define MACRO_LABELS  20
#define MACRO_LIMIT   1024
#define RZ_CMD_ARG_FLAG_ARRAY (1 << 1)
#define RZ_CMD_ARG_FLAG_LAST (1 << 0)
#define RZ_CMD_ARG_FLAG_OPTION (1 << 2)

#define RZ_CMD_MAXLEN 4096
#define rz_cmd_desc_children_foreach(root, it_cd) rz_pvector_foreach (&root->children, it_cd)
#define rz_cmd_parsed_args_foreach_arg(args, i, arg) for ((i) = 1; (i) < (args->argc) && ((arg) = (args)->argv[i]); (i)++)


#define RZ_IO_DESC_CACHE_SIZE (sizeof(ut64) * 8)

#define RZ_IO_SEEK_CUR 1
#define RZ_IO_SEEK_END 2
#define RZ_IO_SEEK_SET 0
#define RZ_PTRACE_NODATA NULL
#define rz_io_bind_init(x) memset(&x, 0, sizeof(x))
#define rz_io_map_get_from(map) map->itv.addr
#define rz_io_map_get_to(map)   (rz_itv_size(map->itv) ? rz_itv_end(map->itv) - 1 : 0)
#define rz_io_range_free(x) free(x)
#define rz_io_range_new()   RZ_NEW0(RzIORange)

#define JSONOUTPUT -3
#define RZ_PRINT_DOT       (1 << 7)
#define RZ_PRINT_FLAGS_ADDRDEC  0x00000200
#define RZ_PRINT_FLAGS_ADDRMOD  0x00000002
#define RZ_PRINT_FLAGS_ALIGN    0x00040000
#define RZ_PRINT_FLAGS_BGFILL   0x00100000
#define RZ_PRINT_FLAGS_COLOR    0x00000001
#define RZ_PRINT_FLAGS_COMMENT  0x00000400
#define RZ_PRINT_FLAGS_COMPACT  0x00000800
#define RZ_PRINT_FLAGS_CURSOR   0x00000004
#define RZ_PRINT_FLAGS_DIFFOUT  0x00000100 
#define RZ_PRINT_FLAGS_HDROFF   0x00008000
#define RZ_PRINT_FLAGS_HEADER   0x00000008
#define RZ_PRINT_FLAGS_NONASCII 0x00020000
#define RZ_PRINT_FLAGS_NONHEX   0x00001000
#define RZ_PRINT_FLAGS_OFFSET   0x00000040
#define RZ_PRINT_FLAGS_RAINBOW  0x00004000
#define RZ_PRINT_FLAGS_REFS     0x00000080
#define RZ_PRINT_FLAGS_SECSUB   0x00002000
#define RZ_PRINT_FLAGS_SECTION  0x00200000
#define RZ_PRINT_FLAGS_SEGOFF   0x00000020
#define RZ_PRINT_FLAGS_SPARSE   0x00000010
#define RZ_PRINT_FLAGS_STYLE    0x00010000
#define RZ_PRINT_FLAGS_UNALLOC  0x00080000

#define RZ_PRINT_ISFIELD   (1 << 1)
#define RZ_PRINT_JSON      (1 << 3)
#define RZ_PRINT_MUSTSEE   (1) 
#define RZ_PRINT_MUSTSET   (1 << 4)
#define RZ_PRINT_QUIET     (1 << 8)
#define RZ_PRINT_SEEFLAGS  (1 << 2)
#define RZ_PRINT_STRUCT    (1 << 9)
#define RZ_PRINT_UNIONMODE (1 << 5)
#define RZ_PRINT_VALUE     (1 << 6)
#define SEEFLAG    -2
#define RZ_REG_COND_CARRY    2
#define RZ_REG_COND_CF       2
#define RZ_REG_COND_EQ       0
#define RZ_REG_COND_GE   9
#define RZ_REG_COND_GT   10
#define RZ_REG_COND_HE  6
#define RZ_REG_COND_HI  5
#define RZ_REG_COND_LAST 13
#define RZ_REG_COND_LE   12
#define RZ_REG_COND_LO  7
#define RZ_REG_COND_LOE 8
#define RZ_REG_COND_LT   11
#define RZ_REG_COND_NE       1
#define RZ_REG_COND_NEG      3
#define RZ_REG_COND_NEGATIVE 3
#define RZ_REG_COND_OF       4
#define RZ_REG_COND_OVERFLOW 4

#define ARROW_LEFT  9
#define ARROW_RIGHT 8
#define CONS_BUFSZ     0x4f00
#define CONS_COLORS_SIZE  21
#define CONS_MAX_ATTR_SZ 16
#define CONS_MAX_USER  102400
#define CONS_PALETTE_SIZE 22
#define CORNER_BL   5
#define CORNER_BR   4
#define CORNER_TL   6
#define CORNER_TR   6
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
#define Color_RESET_TERMINAL "\x1b" \
			     "c\x1b(K\x1b[0m\x1b[J\x1b[?25h"
#define Color_WHITE      "\x1b[37m"
#define Color_YELLOW     "\x1b[33m"
#define Colors_PLAIN \
	{ \
		Color_BLACK, Color_RED, Color_WHITE, \
			Color_GREEN, Color_MAGENTA, Color_YELLOW, \
			Color_CYAN, Color_BLUE, Color_GRAY \
	}
#define DOT_STYLE_BACKEDGE    2
#define DOT_STYLE_CONDITIONAL 1
#define DOT_STYLE_NORMAL      0
#define HUD_BUF_SIZE 512
#define LINE_CROSS  1
#define LINE_HORIZ  2
#define LINE_UP     3
#define LINE_VERT   0
#define RUNECODESTR_ARROW_LEFT      "\xcd"
#define RUNECODESTR_ARROW_RIGHT     "\xcc"
#define RUNECODESTR_CORNER_BL       "\xcb"
#define RUNECODESTR_CORNER_BR       "\xca"
#define RUNECODESTR_CORNER_TL       "\xcf"
#define RUNECODESTR_CORNER_TR       "\xd0"
#define RUNECODESTR_CURVE_CORNER_BL "\xd5"
#define RUNECODESTR_CURVE_CORNER_BR "\xd4"
#define RUNECODESTR_CURVE_CORNER_TL "\xd2"
#define RUNECODESTR_CURVE_CORNER_TR "\xd3"
#define RUNECODESTR_LINE_CROSS      "\xc9"
#define RUNECODESTR_LINE_HORIZ      "\xce"
#define RUNECODESTR_LINE_UP         "\xd1"
#define RUNECODESTR_LINE_VERT       "\xc8"
#define RUNECODESTR_MAX             0xd5
#define RUNECODESTR_MIN             0xc8 
#define RUNECODE_ARROW_LEFT      0xcd
#define RUNECODE_ARROW_RIGHT     0xcc
#define RUNECODE_CORNER_BL       0xcb
#define RUNECODE_CORNER_BR       0xca
#define RUNECODE_CORNER_TL       0xcf
#define RUNECODE_CORNER_TR       0xd0
#define RUNECODE_CURVE_CORNER_BL 0xd5
#define RUNECODE_CURVE_CORNER_BR 0xd4
#define RUNECODE_CURVE_CORNER_TL 0xd2
#define RUNECODE_CURVE_CORNER_TR 0xd3
#define RUNECODE_LINE_CROSS      0xc9
#define RUNECODE_LINE_HORIZ      0xce
#define RUNECODE_LINE_UP         0xd1
#define RUNECODE_LINE_VERT       0xc8
#define RUNECODE_MAX             0xd6
#define RUNECODE_MIN             0xc8 
#define RUNE_ARROW_DOWN      "ᐯ"
#define RUNE_ARROW_LEFT      "ᐸ"
#define RUNE_ARROW_RIGHT     "ᐳ"
#define RUNE_ARROW_UP        "ᐱ"
#define RUNE_CORNER_BL       "└"
#define RUNE_CORNER_BR       "┘"
#define RUNE_CORNER_TL       "┌"
#define RUNE_CORNER_TR       "┐"
#define RUNE_CURVE_CORNER_BL "╰"
#define RUNE_CURVE_CORNER_BR "╯"
#define RUNE_CURVE_CORNER_TL "╭"
#define RUNE_CURVE_CORNER_TR "╮"
#define RUNE_LINE_CROSS      "┼" 
#define RUNE_LINE_HORIZ      "─"
#define RUNE_LINE_UP         "↑"
#define RUNE_LINE_VERT       "│"
#define RUNE_LONG_LINE_HORIZ "―"
#define RZCOLOR(a, r, g, b, bgr, bgg, bgb, id16) \
	{ 0, a, r, g, b, bgr, bgg, bgb, id16 }
#define RZ_CONS_CLEAR_FROM_CURSOR_TO_END "\x1b[0J\r"
#define RZ_CONS_CLEAR_LINE               "\x1b[2K\r"
#define RZ_CONS_CLEAR_SCREEN             "\x1b[2J\r"
#define RZ_CONS_CMD_DEPTH 100
#define RZ_CONS_CURSOR_DOWN         "\x1b[B"
#define RZ_CONS_CURSOR_LEFT         "\x1b[D"
#define RZ_CONS_CURSOR_RESTORE      "\x1b[u"
#define RZ_CONS_CURSOR_RIGHT        "\x1b[C"
#define RZ_CONS_CURSOR_SAVE         "\x1b[s"
#define RZ_CONS_CURSOR_UP           "\x1b[A"
#define RZ_CONS_GET_CURSOR_POSITION "\x1b[6n"
#define RZ_CONS_GREP_TOKENS    64
#define RZ_CONS_GREP_WORDS     10
#define RZ_CONS_GREP_WORD_SIZE 64

#define RZ_CONS_INVERT(x, y) (y ? (x ? Color_INVERT : Color_INVERT_RESET) : (x ? "[" : "]"))
#define RZ_CONS_KEY_ESC 0x1b
#define RZ_CONS_KEY_F1  0xf1
#define RZ_CONS_KEY_F10 0xfa
#define RZ_CONS_KEY_F11 0xfb
#define RZ_CONS_KEY_F12 0xfc
#define RZ_CONS_KEY_F2  0xf2
#define RZ_CONS_KEY_F3  0xf3
#define RZ_CONS_KEY_F4  0xf4
#define RZ_CONS_KEY_F5  0xf5
#define RZ_CONS_KEY_F6  0xf6
#define RZ_CONS_KEY_F7  0xf7
#define RZ_CONS_KEY_F8  0xf8
#define RZ_CONS_KEY_F9  0xf9
#define RZ_EDGES_X_INC 4
#define RZ_LINE_BUFSIZE  4096
#define RZ_LINE_HISTSIZE 256
#define RZ_SELWIDGET_DIR_DOWN 1
#define RZ_SELWIDGET_DIR_UP   0
#define RZ_SELWIDGET_MAXH     15
#define RZ_SELWIDGET_MAXW     30
#define RzColor_BBGBLACK   RZCOLOR(ALPHA_BG, 0x80, 0x80, 0x80, 0x00, 0x00, 0x00, 8)
#define RzColor_BBGBLUE    RZCOLOR(ALPHA_BG, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 12)
#define RzColor_BBGCYAN    RZCOLOR(ALPHA_BG, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 14)
#define RzColor_BBGGREEN   RZCOLOR(ALPHA_BG, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 10)
#define RzColor_BBGMAGENTA RZCOLOR(ALPHA_BG, 0xff, 0x00, 0xff, 0x00, 0x00, 0x00, 13)
#define RzColor_BBGRED     RZCOLOR(ALPHA_BG, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 9)
#define RzColor_BBGWHITE   RZCOLOR(ALPHA_BG, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 15)
#define RzColor_BBGYELLOW  RZCOLOR(ALPHA_BG, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 11)
#define RzColor_BBLACK     RZCOLOR(ALPHA_FG, 0x80, 0x80, 0x80, 0x00, 0x00, 0x00, 8)
#define RzColor_BBLUE      RZCOLOR(ALPHA_FG, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 12)
#define RzColor_BCYAN      RZCOLOR(ALPHA_FG, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 14)
#define RzColor_BGBLACK    RZCOLOR(ALPHA_BG, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0)
#define RzColor_BGBLUE     RZCOLOR(ALPHA_BG, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 4)
#define RzColor_BGCYAN     RZCOLOR(ALPHA_BG, 0x00, 0x80, 0x80, 0x00, 0x00, 0x00, 6)
#define RzColor_BGGRAY RzColor_BBGBLACK
#define RzColor_BGGREEN    RZCOLOR(ALPHA_BG, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 2)
#define RzColor_BGMAGENTA  RZCOLOR(ALPHA_BG, 0x80, 0x00, 0x80, 0x00, 0x00, 0x00, 5)
#define RzColor_BGRED      RZCOLOR(ALPHA_BG, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 1)
#define RzColor_BGREEN     RZCOLOR(ALPHA_FG, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 10)
#define RzColor_BGWHITE    RZCOLOR(ALPHA_BG, 0xc0, 0xc0, 0xc0, 0x00, 0x00, 0x00, 7)
#define RzColor_BGYELLOW   RZCOLOR(ALPHA_BG, 0x80, 0x80, 0x00, 0x00, 0x00, 0x00, 3)
#define RzColor_BLACK      RZCOLOR(ALPHA_FG, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0)
#define RzColor_BLUE       RZCOLOR(ALPHA_FG, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 4)
#define RzColor_BMAGENTA   RZCOLOR(ALPHA_FG, 0xff, 0x00, 0xff, 0x00, 0x00, 0x00, 13)
#define RzColor_BRED       RZCOLOR(ALPHA_FG, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 9)
#define RzColor_BWHITE     RZCOLOR(ALPHA_FG, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 15)
#define RzColor_BYELLOW    RZCOLOR(ALPHA_FG, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 11)
#define RzColor_CYAN       RZCOLOR(ALPHA_FG, 0x00, 0x80, 0x80, 0x00, 0x00, 0x00, 6)
#define RzColor_GRAY   RzColor_BBLACK
#define RzColor_GREEN      RZCOLOR(ALPHA_FG, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 2)
#define RzColor_MAGENTA    RZCOLOR(ALPHA_FG, 0x80, 0x00, 0x80, 0x00, 0x00, 0x00, 5)
#define RzColor_NULL RZCOLOR(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, -1)
#define RzColor_RED        RZCOLOR(ALPHA_FG, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 1)
#define RzColor_WHITE      RZCOLOR(ALPHA_FG, 0xc0, 0xc0, 0xc0, 0x00, 0x00, 0x00, 7)
#define RzColor_YELLOW     RZCOLOR(ALPHA_FG, 0x80, 0x80, 0x00, 0x00, 0x00, 0x00, 3)
#define SELF_LOOP   10
#define STR_IS_NULL(x) (!x || !x[0])
#define UTF8_DOOR                           "🚪"
#define UTF8_KEYBOARD                       "⌨"
#define UTF8_LEFT_POINTING_MAGNIFYING_GLASS "🔍"
#define UTF8_POLICE_CARS_REVOLVING_LIGHT    "🚨"
#define UTF8_SEE_NO_EVIL_MONKEY             "🙈"
#define UTF8_SKULL_AND_CROSSBONES           "☠"
#define UTF8_VS16 "\xef\xb8\x8f"
#define UTF8_WHITE_HEAVY_CHECK_MARK         "✅"
#define UTF_BLOCK            "\u2588"
#define UTF_CIRCLE           "\u25EF"
#define rz_cons_print(x) rz_cons_strcat(x)
#define ABBREV_DECL_CAP 8
#define COMP_UNIT_CAPACITY  8
#define DEBUG_ABBREV_CAP 32
#define DEBUG_INFO_CAPACITY 8
#define DWARF_FALSE 0
#define DWARF_INIT_LEN_64 0xffffffff
#define DWARF_TRUE  1
#define DW_ACCESS_private   0x03
#define DW_ACCESS_protected 0x02
#define DW_ACCESS_public    0x01
#define DW_ATE_UTF             0x10
#define DW_ATE_address         0x01
#define DW_ATE_boolean         0x02
#define DW_ATE_complex_float   0x03
#define DW_ATE_decimal_float   0x0f
#define DW_ATE_edited          0x0c
#define DW_ATE_float           0x04
#define DW_ATE_hi_user 0xff
#define DW_ATE_imaginary_float 0x09
#define DW_ATE_lo_user 0x80
#define DW_ATE_numeric_string  0x0b
#define DW_ATE_packed_decimal  0x0a
#define DW_ATE_signed          0x05
#define DW_ATE_signed_char     0x06
#define DW_ATE_signed_fixed    0x0d
#define DW_ATE_unsigned        0x07
#define DW_ATE_unsigned_char   0x08
#define DW_ATE_unsigned_fixed  0x0e
#define DW_AT_GNU_addr_base                  0x2133
#define DW_AT_GNU_all_call_sites             0x2117
#define DW_AT_GNU_all_source_call_sites      0x2118
#define DW_AT_GNU_all_tail_call_sites        0x2116
#define DW_AT_GNU_call_site_data_value       0x2112
#define DW_AT_GNU_call_site_target           0x2113
#define DW_AT_GNU_call_site_target_clobbered 0x2114
#define DW_AT_GNU_call_site_value            0x2111
#define DW_AT_GNU_deleted                    0x211a
#define DW_AT_GNU_dwo_id                     0x2131
#define DW_AT_GNU_dwo_name                   0x2130
#define DW_AT_GNU_macros                     0x2119
#define DW_AT_GNU_pubnames                   0x2134
#define DW_AT_GNU_pubtypes                   0x2135
#define DW_AT_GNU_ranges_base                0x2132
#define DW_AT_GNU_tail_call                  0x2115
#define DW_AT_MIPS_linkage_name              0x2007 
#define DW_AT_abstract_origin      0x31
#define DW_AT_accessibility        0x32
#define DW_AT_addr_base               0x73
#define DW_AT_address_class        0x33
#define DW_AT_alignment             0x88
#define DW_AT_allocated            0x4e 
#define DW_AT_artificial           0x34
#define DW_AT_associated           0x4f
#define DW_AT_base_types           0x35
#define DW_AT_binary_scale         0x5b
#define DW_AT_bit_offset           0x0c
#define DW_AT_bit_size             0x0d
#define DW_AT_byte_size            0x0b
#define DW_AT_byte_stride          0x51
#define DW_AT_call_all_calls        0x7a
#define DW_AT_call_all_source_calls 0x7b
#define DW_AT_call_all_tail_calls   0x7c
#define DW_AT_call_column          0x57
#define DW_AT_call_data_location    0x85
#define DW_AT_call_data_value       0x86
#define DW_AT_call_file            0x58
#define DW_AT_call_line            0x59
#define DW_AT_call_origin           0x7f
#define DW_AT_call_parameter        0x80
#define DW_AT_call_pc               0x81
#define DW_AT_call_return_pc        0x7d
#define DW_AT_call_tail_call        0x82
#define DW_AT_call_target           0x83
#define DW_AT_call_target_clobbered 0x84
#define DW_AT_call_value            0x7e
#define DW_AT_calling_convention   0x36
#define DW_AT_common_reference     0x1a
#define DW_AT_comp_dir             0x1b
#define DW_AT_const_expr           0x6c
#define DW_AT_const_value          0x1c
#define DW_AT_containing_type      0x1d
#define DW_AT_count                0x37
#define DW_AT_data_bit_offset      0x6b
#define DW_AT_data_location        0x50
#define DW_AT_data_member_location 0x38
#define DW_AT_decimal_scale        0x5c
#define DW_AT_decimal_sign         0x5e
#define DW_AT_decl_column          0x39
#define DW_AT_decl_file            0x3a
#define DW_AT_decl_line            0x3b
#define DW_AT_declaration          0x3c
#define DW_AT_default_value        0x1e
#define DW_AT_defaulted             0x8b
#define DW_AT_deleted               0x8a
#define DW_AT_description          0x5a
#define DW_AT_digit_count          0x5f
#define DW_AT_discr                0x15
#define DW_AT_discr_list           0x3d
#define DW_AT_discr_value          0x16
#define DW_AT_dwo_name              0x76
#define DW_AT_elemental            0x66
#define DW_AT_encoding             0x3e
#define DW_AT_endianity            0x65
#define DW_AT_entry_pc             0x52
#define DW_AT_enum_class           0x6d
#define DW_AT_explicit             0x63
#define DW_AT_export_symbols        0x89
#define DW_AT_extension            0x54
#define DW_AT_external             0x3f
#define DW_AT_frame_base           0x40
#define DW_AT_friend               0x41
#define DW_AT_hi_user                        0x3fff
#define DW_AT_high_pc              0x12
#define DW_AT_identifier_case      0x42
#define DW_AT_import               0x18
#define DW_AT_inline               0x20
#define DW_AT_is_optional          0x21
#define DW_AT_language             0x13
#define DW_AT_linkage_name         0x6e
#define DW_AT_lo_user 0x2000
#define DW_AT_location             0x02
#define DW_AT_loclists_base         0x8c
#define DW_AT_low_pc               0x11
#define DW_AT_lower_bound          0x22
#define DW_AT_macro_info           0x43
#define DW_AT_macros                0x79
#define DW_AT_main_subprogram      0x6a
#define DW_AT_mutable              0x61
#define DW_AT_name                 0x03
#define DW_AT_namelist_item        0x44
#define DW_AT_noreturn              0x87
#define DW_AT_object_pointer       0x64
#define DW_AT_ordering             0x09
#define DW_AT_picture_string       0x60
#define DW_AT_priority             0x45
#define DW_AT_producer             0x25
#define DW_AT_prototyped           0x27
#define DW_AT_pure                 0x67
#define DW_AT_ranges               0x55
#define DW_AT_rank                    0x71
#define DW_AT_recursive            0x68 
#define DW_AT_reference             0x77
#define DW_AT_return_addr          0x2a
#define DW_AT_rnglists_base           0x74
#define DW_AT_rvalue_reference      0x78
#define DW_AT_segment              0x46
#define DW_AT_sibling              0x01
#define DW_AT_signature            0x69
#define DW_AT_small                0x5d
#define DW_AT_specification        0x47
#define DW_AT_start_scope          0x2c
#define DW_AT_static_link          0x48
#define DW_AT_stmt_list            0x10
#define DW_AT_str_offsets_base        0x72
#define DW_AT_stride_size          0x2e
#define DW_AT_string_length        0x19
#define DW_AT_string_length_bit_size  0x6f
#define DW_AT_string_length_byte_size 0x70
#define DW_AT_threads_scaled       0x62
#define DW_AT_trampoline           0x56
#define DW_AT_type                 0x49
#define DW_AT_upper_bound          0x2f
#define DW_AT_use_UTF8             0x53
#define DW_AT_use_location         0x4a
#define DW_AT_variable_parameter   0x4b
#define DW_AT_virtuality           0x4c
#define DW_AT_visibility           0x17
#define DW_AT_vtable_elem_location 0x4d
#define DW_CC_hi_user 0xff
#define DW_CC_lo_user 0x40
#define DW_CC_nocall  0x03
#define DW_CC_normal  0x01
#define DW_CC_program 0x02
#define DW_CFA_advance_loc 0x40
#define DW_CFA_advance_loc1       0x02
#define DW_CFA_advance_loc2       0x03
#define DW_CFA_advance_loc4       0x04
#define DW_CFA_def_cfa            0x0c
#define DW_CFA_def_cfa_expression 0x0f
#define DW_CFA_def_cfa_offset     0x0e
#define DW_CFA_def_cfa_offset_sf  0x13
#define DW_CFA_def_cfa_register   0x0d
#define DW_CFA_def_cfa_sf         0x12
#define DW_CFA_expression         0x10
#define DW_CFA_hi_user            0x3f
#define DW_CFA_lo_user            0x1c
#define DW_CFA_nop                0x00
#define DW_CFA_offse_extended     0x05
#define DW_CFA_offset      0x80
#define DW_CFA_offset_extended_sf 0x11
#define DW_CFA_register           0x09
#define DW_CFA_remember_state     0x0a
#define DW_CFA_restore     0xc0
#define DW_CFA_restore_extended   0x06
#define DW_CFA_restore_state      0x0b
#define DW_CFA_same_value         0x08
#define DW_CFA_set_loc            0x01
#define DW_CFA_undefined          0x07
#define DW_CFA_val_expression     0x16
#define DW_CFA_val_offset         0x14
#define DW_CFA_val_offset_sf      0x15
#define DW_CHILDREN_no  0x00
#define DW_CHILDREN_yes 0x01
#define DW_DSC_label 0x00
#define DW_DSC_range 0x01
#define DW_DS_leading_overpunch  0x02
#define DW_DS_leading_separate   0x04
#define DW_DS_trailing_overpunch 0x03
#define DW_DS_trailing_separate  0x05
#define DW_DS_unsigned           0x01
#define DW_END_big     0x01
#define DW_END_default 0x00
#define DW_END_hi_user 0xff
#define DW_END_little  0x02
#define DW_END_lo_user 0x40
#define DW_EXTENDED_OPCODE 0
#define DW_FORM_addr           0x01
#define DW_FORM_addrx          0x1b
#define DW_FORM_addrx1         0x29
#define DW_FORM_addrx2         0x2a
#define DW_FORM_addrx3         0x2b
#define DW_FORM_addrx4         0x2c
#define DW_FORM_block          0x09
#define DW_FORM_block1         0x0a
#define DW_FORM_block2         0x03
#define DW_FORM_block4         0x04
#define DW_FORM_data1          0x0b
#define DW_FORM_data16         0x1e
#define DW_FORM_data2          0x05
#define DW_FORM_data4          0x06
#define DW_FORM_data8          0x07
#define DW_FORM_exprloc        0x18
#define DW_FORM_flag           0x0c
#define DW_FORM_flag_present   0x19
#define DW_FORM_implicit_const 0x21
#define DW_FORM_indirect       0x16
#define DW_FORM_line_ptr       0x1f
#define DW_FORM_loclistx       0x22
#define DW_FORM_ref1           0x11
#define DW_FORM_ref2           0x12
#define DW_FORM_ref4           0x13
#define DW_FORM_ref8           0x14
#define DW_FORM_ref_addr       0x10
#define DW_FORM_ref_sig8       0x20
#define DW_FORM_ref_sup4       0x1c
#define DW_FORM_ref_sup8       0x24
#define DW_FORM_ref_udata      0x15
#define DW_FORM_rnglistx       0x23
#define DW_FORM_sdata          0x0d
#define DW_FORM_sec_offset     0x17 
#define DW_FORM_string         0x08
#define DW_FORM_strp           0x0e
#define DW_FORM_strp_sup       0x1d
#define DW_FORM_strx           0x1a
#define DW_FORM_strx1          0x25
#define DW_FORM_strx2          0x26
#define DW_FORM_strx3          0x27
#define DW_FORM_strx4          0x28
#define DW_FORM_udata          0x0f
#define DW_ID_case_insensitive 0x03
#define DW_ID_case_sensitive   0x00
#define DW_ID_down_case        0x02
#define DW_ID_up_case          0x01
#define DW_INL_declared_inlined     0x03
#define DW_INL_declared_not_inlined 0x02
#define DW_INL_inlined              0x01
#define DW_INL_not_inlined          0x00
#define DW_LANG_Ada83          0x0003
#define DW_LANG_Ada95          0x000d
#define DW_LANG_C              0x0002
#define DW_LANG_C11            0x001d
#define DW_LANG_C89            0x0001
#define DW_LANG_C99            0x000c
#define DW_LANG_C_plus_plus    0x0004
#define DW_LANG_C_plus_plus_14 0x0021
#define DW_LANG_Cobol74        0x0005
#define DW_LANG_Cobol85        0x0006
#define DW_LANG_D              0x0013
#define DW_LANG_Dylan          0x0020
#define DW_LANG_Fortran03      0x0022
#define DW_LANG_Fortran08      0x0023
#define DW_LANG_Fortran77      0x0007
#define DW_LANG_Fortran90      0x0008
#define DW_LANG_Fortran95      0x000e
#define DW_LANG_Java           0x000b
#define DW_LANG_Julia          0x001f
#define DW_LANG_Modula2        0x000a
#define DW_LANG_ObjC           0x0010
#define DW_LANG_ObjC_plus_plus 0x0011
#define DW_LANG_PLI            0x000f
#define DW_LANG_Pascal83       0x0009
#define DW_LANG_Python         0x0014
#define DW_LANG_Rust           0x001c
#define DW_LANG_Swift          0x001e
#define DW_LANG_UPC            0x0012
#define DW_LANG_hi_user        0xffff
#define DW_LANG_lo_user        0x8000
#define DW_LNE_HP_define_proc              0x20 
#define DW_LNE_HP_negate_front_end_logical 0x19 
#define DW_LNE_HP_negate_function_exit     0x18 
#define DW_LNE_HP_negate_is_UV_update      0x11 
#define DW_LNE_HP_negate_post_semantics    0x17 
#define DW_LNE_HP_pop_context              0x13 
#define DW_LNE_HP_push_context             0x12 
#define DW_LNE_HP_set_file_line_column     0x14 
#define DW_LNE_HP_set_routine_name         0x15 
#define DW_LNE_HP_set_sequence             0x16 
#define DW_LNE_define_file       0x03
#define DW_LNE_end_sequence      0x01
#define DW_LNE_hi_user           0xff 
#define DW_LNE_lo_user           0x80 
#define DW_LNE_set_address       0x02
#define DW_LNE_set_discriminator 0x04 
#define DW_LNS_advance_line       0x03
#define DW_LNS_advance_pc         0x02
#define DW_LNS_const_add_pc       0x08
#define DW_LNS_copy               0x01
#define DW_LNS_fixed_advance_pc   0x09
#define DW_LNS_negate_stmt        0x06
#define DW_LNS_set_basic_block    0x07
#define DW_LNS_set_column         0x05
#define DW_LNS_set_epilogue_begin 0x0b 
#define DW_LNS_set_file           0x04
#define DW_LNS_set_isa            0x0c 
#define DW_LNS_set_prologue_end   0x0a 
#define DW_MACINFO_define     0x01
#define DW_MACINFO_end_file   0x04
#define DW_MACINFO_start_file 0x03
#define DW_MACINFO_undef      0x02
#define DW_MACINFO_vendor_ext 0xff
#define DW_OP_abs                 0x19
#define DW_OP_addr                0x03
#define DW_OP_and                 0x1a
#define DW_OP_bit_piece           0x9d
#define DW_OP_bra                 0x28
#define DW_OP_breg0               0x70
#define DW_OP_breg1               0x71
#define DW_OP_breg10              0x7a
#define DW_OP_breg11              0x7b
#define DW_OP_breg12              0x7c
#define DW_OP_breg13              0x7d
#define DW_OP_breg14              0x7e
#define DW_OP_breg15              0x7f
#define DW_OP_breg16              0x80
#define DW_OP_breg17              0x81
#define DW_OP_breg18              0x82
#define DW_OP_breg19              0x83
#define DW_OP_breg2               0x72
#define DW_OP_breg20              0x84
#define DW_OP_breg21              0x85
#define DW_OP_breg22              0x86
#define DW_OP_breg23              0x87
#define DW_OP_breg24              0x88
#define DW_OP_breg25              0x89
#define DW_OP_breg26              0x8a
#define DW_OP_breg27              0x8b
#define DW_OP_breg28              0x8c
#define DW_OP_breg29              0x8d
#define DW_OP_breg3               0x73
#define DW_OP_breg30              0x8e
#define DW_OP_breg31              0x8f
#define DW_OP_breg4               0x74
#define DW_OP_breg5               0x75
#define DW_OP_breg6               0x76
#define DW_OP_breg7               0x77
#define DW_OP_breg8               0x78
#define DW_OP_breg9               0x79
#define DW_OP_bregx               0x92
#define DW_OP_call2               0x98
#define DW_OP_call4               0x99
#define DW_OP_call_frame_cfa      0x9c
#define DW_OP_call_ref            0x9a
#define DW_OP_const1s             0x09
#define DW_OP_const1u             0x08
#define DW_OP_const2s             0x0b
#define DW_OP_const2u             0x0a
#define DW_OP_const4s             0x0d
#define DW_OP_const4u             0x0c
#define DW_OP_const8s             0x0f
#define DW_OP_const8u             0x0e
#define DW_OP_consts              0x11
#define DW_OP_constu              0x10
#define DW_OP_deref               0x06
#define DW_OP_deref_size          0x94
#define DW_OP_div                 0x1b
#define DW_OP_drop                0x13
#define DW_OP_dup                 0x12
#define DW_OP_eq                  0x29
#define DW_OP_fbreg               0x91
#define DW_OP_form_tls_address    0x9b
#define DW_OP_ge                  0x2a
#define DW_OP_gt                  0x2b
#define DW_OP_hi_user 0xff
#define DW_OP_implicit_value      0x9e
#define DW_OP_le                  0x2c
#define DW_OP_lit0                0x30
#define DW_OP_lit1                0x31
#define DW_OP_lit10               0x3a
#define DW_OP_lit11               0x3b
#define DW_OP_lit12               0x3c
#define DW_OP_lit13               0x3d
#define DW_OP_lit14               0x3e
#define DW_OP_lit15               0x3f
#define DW_OP_lit16               0x40
#define DW_OP_lit17               0x41
#define DW_OP_lit18               0x42
#define DW_OP_lit19               0x43
#define DW_OP_lit2                0x32
#define DW_OP_lit20               0x44
#define DW_OP_lit21               0x45
#define DW_OP_lit22               0x46
#define DW_OP_lit23               0x47
#define DW_OP_lit24               0x48
#define DW_OP_lit25               0x49
#define DW_OP_lit26               0x4a
#define DW_OP_lit27               0x4b
#define DW_OP_lit28               0x4c
#define DW_OP_lit29               0x4d
#define DW_OP_lit3                0x33
#define DW_OP_lit30               0x4e
#define DW_OP_lit31               0x4f
#define DW_OP_lit4                0x34
#define DW_OP_lit5                0x35
#define DW_OP_lit6                0x36
#define DW_OP_lit7                0x37
#define DW_OP_lit8                0x38
#define DW_OP_lit9                0x39
#define DW_OP_lo_user 0xe0
#define DW_OP_lt                  0x2d
#define DW_OP_minus               0x1c
#define DW_OP_mod                 0x1d
#define DW_OP_mul                 0x1e
#define DW_OP_ne                  0x2e
#define DW_OP_neg                 0x1f
#define DW_OP_nop                 0x96
#define DW_OP_not                 0x20
#define DW_OP_or                  0x21
#define DW_OP_over                0x14
#define DW_OP_pick                0x15
#define DW_OP_piece               0x93
#define DW_OP_plus                0x22
#define DW_OP_plus_uconst         0x23
#define DW_OP_push_object_address 0x97
#define DW_OP_reg0                0x50
#define DW_OP_reg1                0x51
#define DW_OP_reg10               0x5a
#define DW_OP_reg11               0x5b
#define DW_OP_reg12               0x5c
#define DW_OP_reg13               0x5d
#define DW_OP_reg14               0x5e
#define DW_OP_reg15               0x5f
#define DW_OP_reg16               0x60
#define DW_OP_reg17               0x61
#define DW_OP_reg18               0x62
#define DW_OP_reg19               0x63
#define DW_OP_reg2                0x52
#define DW_OP_reg20               0x64
#define DW_OP_reg21               0x65
#define DW_OP_reg22               0x66
#define DW_OP_reg23               0x67
#define DW_OP_reg24               0x68
#define DW_OP_reg25               0x69
#define DW_OP_reg26               0x6a
#define DW_OP_reg27               0x6b
#define DW_OP_reg28               0x6c
#define DW_OP_reg29               0x6d
#define DW_OP_reg3                0x53
#define DW_OP_reg30               0x6e
#define DW_OP_reg31               0x6f
#define DW_OP_reg4                0x54
#define DW_OP_reg5                0x55
#define DW_OP_reg6                0x56
#define DW_OP_reg7                0x57
#define DW_OP_reg8                0x58
#define DW_OP_reg9                0x59
#define DW_OP_regx                0x90
#define DW_OP_rot                 0x17
#define DW_OP_shl                 0x24
#define DW_OP_shr                 0x25
#define DW_OP_shra                0x26
#define DW_OP_skip                0x2f
#define DW_OP_stack_value         0x9f
#define DW_OP_swap                0x16
#define DW_OP_xderef              0x18
#define DW_OP_xderef_size         0x95
#define DW_OP_xor                 0x27
#define DW_ORD_col_major 0x01
#define DW_ORD_row_major 0x00
#define DW_TAG_LAST 0x44 
#define DW_TAG_access_declaration     0x23
#define DW_TAG_array_type             0x01
#define DW_TAG_base_type              0x24
#define DW_TAG_catch_block            0x25
#define DW_TAG_class_type             0x02
#define DW_TAG_common_block           0x1a
#define DW_TAG_common_inclusion       0x1b
#define DW_TAG_compile_unit           0x11 
#define DW_TAG_condition             0x3f 
#define DW_TAG_const_type             0x26
#define DW_TAG_constant               0x27
#define DW_TAG_dwarf_procedure          0x36 
#define DW_TAG_entry_point            0x03
#define DW_TAG_enumeration_type       0x04
#define DW_TAG_enumerator             0x28
#define DW_TAG_file_type              0x29
#define DW_TAG_formal_parameter       0x05
#define DW_TAG_friend                 0x2a
#define DW_TAG_hi_user 0xffff
#define DW_TAG_imported_declaration   0x08
#define DW_TAG_imported_module          0x3a 
#define DW_TAG_imported_unit            0x3d 
#define DW_TAG_inheritance            0x1c
#define DW_TAG_inlined_subroutine     0x1d
#define DW_TAG_interface_type           0x38 
#define DW_TAG_label                  0x0a
#define DW_TAG_lexical_block          0x0b
#define DW_TAG_lo_user 0x4080
#define DW_TAG_member                 0x0d
#define DW_TAG_module                 0x1e
#define DW_TAG_mutable_type          0x3e 
#define DW_TAG_namelist               0x2b
#define DW_TAG_namelist_item  0x2c 
#define DW_TAG_namelist_items 0x2c 
#define DW_TAG_namespace                0x39 
#define DW_TAG_null_entry             0x00
#define DW_TAG_packed_type    0x2d
#define DW_TAG_partial_unit             0x3c 
#define DW_TAG_pointer_type           0x0f
#define DW_TAG_ptr_to_member_type     0x1f
#define DW_TAG_reference_type         0x10
#define DW_TAG_restrict_type            0x37 
#define DW_TAG_rvalue_reference_type 0x42 
#define DW_TAG_set_type               0x20
#define DW_TAG_shared_type           0x40 
#define DW_TAG_string_type            0x12
#define DW_TAG_structure_type         0x13
#define DW_TAG_subprogram     0x2e
#define DW_TAG_subrange_type          0x21
#define DW_TAG_subroutine_type        0x15
#define DW_TAG_template_alias        0x43 
#define DW_TAG_template_type_param      0x2f 
#define DW_TAG_template_type_parameter  0x2f 
#define DW_TAG_template_value_param     0x30 
#define DW_TAG_template_value_parameter 0x30 
#define DW_TAG_thrown_type              0x31
#define DW_TAG_try_block                0x32
#define DW_TAG_type_unit             0x41 
#define DW_TAG_typedef                0x16
#define DW_TAG_union_type             0x17
#define DW_TAG_unspecified_parameters 0x18
#define DW_TAG_unspecified_type         0x3b 
#define DW_TAG_variable                 0x34
#define DW_TAG_variant                0x19
#define DW_TAG_variant_part             0x33
#define DW_TAG_volatile_type            0x35
#define DW_TAG_with_stmt              0x22
#define DW_UT_compile       0x01
#define DW_UT_hi_user       0xff
#define DW_UT_lo_user       0x80
#define DW_UT_partial       0x03
#define DW_UT_skeleton      0x04
#define DW_UT_split_compile 0x05
#define DW_UT_split_type    0x06
#define DW_UT_type          0x02
#define DW_VIRTUALITY_none         0x00
#define DW_VIRTUALITY_pure_virtual 0x02
#define DW_VIRTUALITY_virtual      0x01
#define DW_VIS_exported  0x02
#define DW_VIS_local     0x01
#define DW_VIS_qualified 0x03
#define LOP_DISCARD        2
#define LOP_EXTENDED       1
#define LOP_SPECIAL        4
#define LOP_STANDARD       3

#define RZ_BIN_DWARF_INFO_HEADER_FILE_LENGTH(x) (sizeof(x->file) / sizeof(*(x->file)))
#define RZ_BIN_DWARF_LINE_OP_STD_ARGS_MAX 1
#define rz_bin_dwarf_line_new(o, a, f, l) o->address = a, o->file = strdup(f ? f : ""), o->line = l, o->column = 0, o

#define rz_hash_cfg_new_with_algo2(rh, name) rz_hash_cfg_new_with_algo(rh, name, NULL, 0);

#define rz_demangler_plugin_demangle(x, y) ((x) && RZ_STR_ISNOTEMPTY(y) ? (x)->demangle(y) : NULL)
