#include<stdio.h>

#include<dirent.h>

#include<assert.h>
#include<signal.h>












#include<math.h>


#include<inttypes.h>

#include<stddef.h>


#include<dlfcn.h>

#include<stdlib.h>
#include<fcntl.h>
#include<string.h>



#include<unistd.h>


#include<errno.h>
#include<sys/param.h>
#include<sys/types.h>
#include<sys/stat.h>

#include<stdbool.h>

#include<sys/time.h>
#include<stdint.h>
#include<stdarg.h>




#include<ctype.h>
#include<wchar.h>
#include<time.h>
#include<limits.h>

#define RZ_LIB_ENV "RZ_LIBR_PLUGINS"
#define RZ_LIB_EXT "dll"

#define RZ_LIB_SYMFUNC "rizin_plugin_function"
#define RZ_LIB_SYMNAME "rizin_plugin"
#define RZ_PLUGIN_CHECK_AND_ADD(plugins, plugin, py_type) \
	do { \
		RzListIter *_it; \
		py_type *_p; \
		rz_list_foreach ((plugins), _it, _p) { \
			if (!strcmp(_p->name, (plugin)->name)) { \
				return false; \
			} \
		} \
		rz_list_append(plugins, plugin); \
	} while (0)

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
#define HHXFMT   "x"
#define LDBLFMTf "f"
#define LDBLFMTg "g"
#define O_BINARY 0
#define PERROR_WITH_FILELINE 0
#define PFMT32d "d"
#define PFMT32o "o"
#define PFMT32u "u"
#define PFMT32x "x"
#define PFMT64d  "I64d"
#define PFMT64o  "I64o"
#define PFMT64u  "I64u"
#define PFMT64x  "I64x"
#define PFMTDPTR "td"
#define PFMTSZd  "Id"
#define PFMTSZo  "Io"
#define PFMTSZu  "Iu"
#define PFMTSZx  "Ix"
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

#define rz_swap_st16 __builtin_bswap16
#define rz_swap_st32 __builtin_bswap32
#define rz_swap_st64 __builtin_bswap64
#define rz_swap_ut16 __builtin_bswap16
#define rz_swap_ut32 __builtin_bswap32
#define rz_swap_ut64 __builtin_bswap64
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
#define IS_ALPHANUM(c)   (IS_DIGIT(c) || IS_UPPER(c) || IS_LOWER(c))
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




#define RZ_SUBPROCESS_STDERR (1 << 2)
#define RZ_SUBPROCESS_STDIN  (1 << 0)
#define RZ_SUBPROCESS_STDOUT (1 << 1)


#define RZ_STRBUF_SAFEGET(sb) (rz_strbuf_get(sb) ? rz_strbuf_get(sb) : "")

#define RzNumBig mpz_t




#define RZ_PRINT_JSON_DEPTH_LIMIT 128
#define RZ_ASN1_CLASS    0xC0 
#define RZ_ASN1_CLASS_APPLICATION 0x40 
#define RZ_ASN1_CLASS_CONTEXT     0x80 
#define RZ_ASN1_CLASS_PRIVATE     0xC0 
#define RZ_ASN1_CLASS_UNIVERSAL   0x00 
#define RZ_ASN1_FORM     0x20 
#define RZ_ASN1_FORM_CONSTRUCTED 0x20 
#define RZ_ASN1_FORM_PRIMITIVE   0x00 

#define RZ_ASN1_JSON_EMPTY "{}"
#define RZ_ASN1_JSON_NULL  "null"
#define RZ_ASN1_LENLONG  0x80 
#define RZ_ASN1_LENSHORT 0x7F 
#define RZ_ASN1_OID_LEN 64
#define RZ_ASN1_TAG      0x1F 
#define RZ_ASN1_TAG_BITSTRING       0x03 
#define RZ_ASN1_TAG_BMPSTRING       0x1E 
#define RZ_ASN1_TAG_BOOLEAN         0x01 
#define RZ_ASN1_TAG_EMBEDDED_PDV    0x0B 
#define RZ_ASN1_TAG_ENUMERATED      0x0A 
#define RZ_ASN1_TAG_EOC             0x00 
#define RZ_ASN1_TAG_EXTERNAL        0x08 
#define RZ_ASN1_TAG_GENERALIZEDTIME 0x18 
#define RZ_ASN1_TAG_GENERALSTRING   0x1B 
#define RZ_ASN1_TAG_GRAPHICSTRING   0x19 
#define RZ_ASN1_TAG_IA5STRING       0x16 
#define RZ_ASN1_TAG_INTEGER         0x02 
#define RZ_ASN1_TAG_NULL            0x05 
#define RZ_ASN1_TAG_NUMERICSTRING   0x12 
#define RZ_ASN1_TAG_OBJDESCRIPTOR   0x07 
#define RZ_ASN1_TAG_OCTETSTRING     0x04 
#define RZ_ASN1_TAG_OID             0x06 
#define RZ_ASN1_TAG_PRINTABLESTRING 0x13 
#define RZ_ASN1_TAG_REAL            0x09 
#define RZ_ASN1_TAG_SEQUENCE        0x10 
#define RZ_ASN1_TAG_SET             0x11 
#define RZ_ASN1_TAG_T61STRING       0x14 
#define RZ_ASN1_TAG_UNIVERSALSTRING 0x1C 
#define RZ_ASN1_TAG_UTCTIME         0x17 
#define RZ_ASN1_TAG_UTF8STRING      0x0C 
#define RZ_ASN1_TAG_VIDEOTEXSTRING  0x15 
#define RZ_ASN1_TAG_VISIBLESTRING   0x1A 


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

#define F128_NAN  (rz_types_gen_f128_nan())
#define F128_NINF (-rz_types_gen_f128_inf())
#define F128_PINF (rz_types_gen_f128_inf())
#define F32_NAN   (rz_types_gen_f32_nan())
#define F32_NINF  (-rz_types_gen_f32_inf())
#define F32_PINF  (rz_types_gen_f32_inf())
#define F64_NAN   (rz_types_gen_f64_nan())
#define F64_NINF  (-rz_types_gen_f64_inf())
#define F64_PINF  (rz_types_gen_f64_inf())
#define F80_NAN   (rz_types_gen_f128_nan())
#define F80_NINF  (-rz_types_gen_f128_inf())
#define F80_PINF  (rz_types_gen_f128_inf())



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

#define RzBitword          ut64



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

