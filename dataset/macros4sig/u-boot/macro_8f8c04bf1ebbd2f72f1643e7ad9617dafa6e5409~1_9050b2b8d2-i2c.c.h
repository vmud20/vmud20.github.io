

#include<asm/posix_types.h>



#include<linux/stddef.h>
#include<asm/byteorder.h>
#include<features.h>
#include<limits.h>
#include<linux/errno.h>
#include<stdint.h>



#include<stdio.h>




#include<asm/types.h>
#include<stdarg.h>

#include<string.h>
#include<linux/string.h>
#include<malloc.h>



#include<errno.h>


#include<unistd.h>
#include<stdlib.h>
#include<time.h>
#include<stddef.h>
#include<fcntl.h>





#include<sys/types.h>
#include<stdbool.h>

#include<sys/mman.h>

#include<linux/types.h>

#include<linux/kernel.h>

# define MAP_FAILED ((void *)-1)
# define __BIG_ENDIAN BIG_ENDIAN
# define __BYTE_ORDER BYTE_ORDER

# define __LITTLE_ENDIAN LITTLE_ENDIAN
#define _uswap_64(x, sfx) \
	((((x) & 0xff00000000000000##sfx) >> 56) | \
	 (((x) & 0x00ff000000000000##sfx) >> 40) | \
	 (((x) & 0x0000ff0000000000##sfx) >> 24) | \
	 (((x) & 0x000000ff00000000##sfx) >>  8) | \
	 (((x) & 0x00000000ff000000##sfx) <<  8) | \
	 (((x) & 0x0000000000ff0000##sfx) << 24) | \
	 (((x) & 0x000000000000ff00##sfx) << 40) | \
	 (((x) & 0x00000000000000ff##sfx) << 56))
# define be16_to_cpu(x)		uswap_16(x)
# define be32_to_cpu(x)		uswap_32(x)
# define be64_to_cpu(x)		uswap_64(x)
# define cpu_to_be16(x)		uswap_16(x)
# define cpu_to_be32(x)		uswap_32(x)
# define cpu_to_be64(x)		uswap_64(x)
# define cpu_to_le16(x)		uswap_16(x)
# define cpu_to_le32(x)		uswap_32(x)
# define cpu_to_le64(x)		(x)
# define le16_to_cpu(x)		(x)
# define le32_to_cpu(x)		(x)
# define le64_to_cpu(x)		(x)
#define likely(x)	__builtin_expect(!!(x), 1)
#define unlikely(x)	__builtin_expect(!!(x), 0)
#define uswap_16(x) \
	((((x) & 0xff00) >> 8) | \
	 (((x) & 0x00ff) << 8))
#define uswap_32(x) \
	((((x) & 0xff000000) >> 24) | \
	 (((x) & 0x00ff0000) >>  8) | \
	 (((x) & 0x0000ff00) <<  8) | \
	 (((x) & 0x000000ff) << 24))
# define uswap_64(x) _uswap_64(x, ull)
#define DECLARE_BITMAP(name, bits) \
	unsigned long name[BITS_TO_LONGS(bits)]








#define __bitwise __bitwise__
#define __bitwise__ __attribute__((bitwise))
#define aligned_be64 __be64 __aligned(8)
#define aligned_le64 __le64 __aligned(8)
#define aligned_u64 __u64 __aligned(8)

#define NULL ((void *)0)

#define offsetof(TYPE, MEMBER)	((size_t)&((TYPE *)0)->MEMBER)
# define ACCESS_PRIVATE(p, member) (*((typeof((p)->member) __force *) &(p)->member))

#define __PASTE(a,b) ___PASTE(a,b)
#define ___PASTE(a,b) a##b
# define __acquire(x)	__context__(x,1)
# define __acquires(x)	__attribute__((context(x,0,1)))
# define __builtin_warning(x, y...) (1)
# define __chk_io_ptr(x) (void)0
# define __chk_user_ptr(x) (void)0
#define __compiler_offsetof(a, b)	__builtin_offsetof(a, b)
# define __cond_lock(x,c)	((c) ? ({ __acquire(x); 1; }) : 0)

#define __diag_GCC(version, severity, string)
#define __diag_error(compiler, version, option, comment) \
	__diag_ ## compiler(version, error, option)
#define __diag_ignore(compiler, version, option, comment) \
	__diag_ ## compiler(version, ignore, option)
#define __diag_pop()	__diag(pop)
#define __diag_push()	__diag(push)
#define __diag_warn(compiler, version, option, comment) \
	__diag_ ## compiler(version, warn, option)
# define __force
#define __inline__ inline
#define __inline_maybe_unused __maybe_unused
# define __iomem
# define __kernel
# define __latent_entropy

# define __must_hold(x)	__attribute__((context(x,1,1)))
#define __naked			__attribute__((__naked__)) notrace
#define __native_word(t) \
	(sizeof(t) == sizeof(char) || sizeof(t) == sizeof(short) || \
	 sizeof(t) == sizeof(int) || sizeof(t) == sizeof(long))
# define __no_fgcse
# define __no_randomize_layout
# define __nocast
# define __percpu
# define __private
# define __randomize_layout __designated_init
# define __rcu
# define __release(x)	__context__(x,-1)
# define __releases(x)	__attribute__((context(x,1,0)))
# define __safe
#define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#  define __user __attribute__((user))
#define asm_inline asm __inline
#define asm_volatile_goto(x...) asm goto(x)
#define inline inline                                    __gnu_inline \
	__inline_maybe_unused notrace
#define noinline_for_stack noinline
# define randomized_struct_fields_end
# define randomized_struct_fields_start
#define COMPILER_HAS_GENERIC_BUILTIN_OVERFLOW 1
#define GCC_VERSION ("__GNUC__" * 10000		\
		     + "__GNUC_MINOR__" * 100	\
		     + "__GNUC_PATCHLEVEL__")
#define KASAN_ABI_VERSION 5
#define RELOC_HIDE(ptr, off)						\
({									\
	unsigned long __ptr;						\
	__asm__ ("" : "=r"(__ptr) : "0"(ptr));				\
	(typeof(ptr)) (__ptr + (off));					\
})



#define __UNIQUE_ID(prefix) __PASTE(__PASTE(__UNIQUE_ID_, prefix), __COUNTER__)
#define __compiletime_error(message) __attribute__((__error__(message)))
#define __compiletime_object_size(obj) __builtin_object_size(obj, 0)
#define __compiletime_warning(message) __attribute__((__warning__(message)))
#define __diag_GCC_8(s)		__diag(s)
#define __diag_str(s)		__diag_str1(s)
#define __diag_str1(s)		#s
#define __no_sanitize_address __attribute__((no_sanitize_address))
#define __noretpoline __attribute__((__indirect_branch__("keep")))
#define barrier() __asm__ __volatile__("": : :"memory")
#define barrier_before_unreachable() asm volatile("")
#define barrier_data(ptr) __asm__ __volatile__("": :"r"(ptr) :"memory")
#define uninitialized_var(x) x = x
#define unreachable() \
	do {					\
		annotate_unreachable();		\
		barrier_before_unreachable();	\
		__builtin_unreachable();	\
	} while (0)
#define OPTIMIZER_HIDE_VAR(var) barrier()
#define __builtin_bswap16 _bswap16

# define __GCC4_has_attribute___assume_aligned__      ("__GNUC_MINOR__" >= 9)
# define __GCC4_has_attribute___copy__                0
# define __GCC4_has_attribute___designated_init__     0
# define __GCC4_has_attribute___externally_visible__  1
# define __GCC4_has_attribute___fallthrough__         0
# define __GCC4_has_attribute___no_sanitize_address__ ("__GNUC_MINOR__" >= 8)
# define __GCC4_has_attribute___noclone__             1
# define __GCC4_has_attribute___nonstring__           0

#define __alias(symbol)                 __attribute__((__alias__(#symbol)))
#define __aligned(x)                    __attribute__((__aligned__(x)))
#define __aligned_largest               __attribute__((__aligned__))
#define __always_inline                 inline __attribute__((__always_inline__))
#define __always_unused                 __attribute__((__unused__))
# define __assume_aligned(a, ...)
#define __attribute_const__             __attribute__((__const__))
#define __cold                          __attribute__((__cold__))
# define __copy(symbol)

# define __designated_init              __attribute__((__designated_init__))
#define __gnu_inline                    __attribute__((__gnu_inline__))
# define __has_attribute(x) __GCC4_has_attribute_##x
#define __malloc                        __attribute__((__malloc__))
#define __maybe_unused                  __attribute__((__unused__))
#define __mode(x)                       __attribute__((__mode__(x)))
# define __noclone                      __attribute__((__noclone__))
# define __nonstring                    __attribute__((__nonstring__))
#define __noreturn                      __attribute__((__noreturn__))
#define __packed                        __attribute__((__packed__))
#define __printf(a, b)                  __attribute__((__format__(printf, a, b)))
#define __pure                          __attribute__((__pure__))
#define __scanf(a, b)                   __attribute__((__format__(scanf, a, b)))
#define __section(S)                    __attribute__((__section__(S)))
#define __used                          __attribute__((__used__))
# define __visible                      __attribute__((__externally_visible__))
#define __weak                          __attribute__((__weak__))
# define fallthrough                    __attribute__((__fallthrough__))
#define   noinline                      __attribute__((__noinline__))

# define strdup		sandbox_strdup
# define strndup		sandbox_strndup


#define time_after(a,b)		\
	(typecheck(unsigned long, a) && \
	 typecheck(unsigned long, b) && \
	 ((long)((b) - (a)) < 0))
#define time_after_eq(a,b)	\
	(typecheck(unsigned long, a) && \
	 typecheck(unsigned long, b) && \
	 ((long)((a) - (b)) >= 0))
#define time_before(a,b)	time_after(b,a)
#define time_before_eq(a,b)	time_after_eq(b,a)
#define time_in_range(a,b,c) \
	(time_after_eq(a,b) && \
	 time_before_eq(a,c))
#define time_in_range_open(a,b,c) \
	(time_after_eq(a,b) && \
	 time_before(a,c))

#define typecheck(type,x) \
({	type __dummy; \
	typeof(x) __dummy2; \
	(void)(&__dummy == &__dummy2); \
	1; \
})
#define typecheck_fn(type,function) \
({	typeof(type) __tmp = function; \
	(void)__tmp; \
})

#define eprintf(fmt, args...)	fprintf(stderr, fmt, ##args)
#define eputc(c)		fputc(stderr, c)
#define eputs(s)		fputs(stderr, s)
# define ASM_UNREACHABLE
# define KENTRY(sym)						\
	extern typeof(sym) sym;					\
	static const unsigned long __kentry_##sym		\
	__used							\
	__section("___kentry" "+" #sym )			\
	= (unsigned long)&sym;
#define OPTIMIZER_HIDE_VAR(var)						\
	__asm__ ("" : "=r" (var) : "0" (var))
#define READ_ONCE(x) __READ_ONCE(x, 1)
#define READ_ONCE_NOCHECK(x) __READ_ONCE(x, 0)
# define RELOC_HIDE(ptr, off)					\
  ({ unsigned long __ptr;					\
     __ptr = (unsigned long) (ptr);				\
    (typeof(ptr)) (__ptr + (off)); })
#define WRITE_ONCE(x, val) \
({							\
	union { typeof(x) __val; char __c[1]; } __u =	\
		{ .__val = (__force typeof(x)) (val) }; \
	__write_once_size(&(x), __u.__c, sizeof(x));	\
	__u.__val;					\
})
#define __ADDRESSABLE(sym) \
	static void * __section(".discard.addressable") __used \
		__UNIQUE_ID(__PASTE(__addressable_,sym)) = (void *)&sym;

#define __READ_ONCE(x, check)						\
({									\
	union { typeof(x) __val; char __c[1]; } __u;			\
	if (check)							\
		__read_once_size(&(x), __u.__c, sizeof(x));		\
	else								\
		__read_once_size_nocheck(&(x), __u.__c, sizeof(x));	\
	__u.__val;							\
})
# define __UNIQUE_ID(prefix) __PASTE(__PASTE(__UNIQUE_ID_, prefix), "__LINE__")
#define __annotate_jump_table __section(".rodata..c_jump_table")
#define __branch_check__(x, expect, is_constant) ({			\
			long ______r;					\
			static struct ftrace_likely_data		\
				__aligned(4)				\
				__section("_ftrace_annotated_branch")	\
				______f = {				\
				.data.func = __func__,			\
				.data.file = "__FILE__",			\
				.data.line = "__LINE__",			\
			};						\
			______r = __builtin_expect(!!(x), expect);	\
			ftrace_likely_update(&______f, ______r,		\
					     expect, is_constant);	\
			______r;					\
		})
# define __compiletime_assert(condition, msg, prefix, suffix)		\
	do {								\
		extern void prefix ## suffix(void) __compiletime_error(msg); \
		if (!(condition))					\
			prefix ## suffix();				\
	} while (0)
# define __compiletime_error(message)
# define __compiletime_object_size(obj) -1
# define __compiletime_warning(message)
#define __must_be_array(a)	BUILD_BUG_ON_ZERO(__same_type((a), &(a)[0]))
# define __no_kasan_or_inline __no_sanitize_address notrace __maybe_unused
#define __trace_if_value(cond) ({			\
	static struct ftrace_branch_data		\
		__aligned(4)				\
		__section("_ftrace_branch")		\
		__if_trace = {				\
			.func = __func__,		\
			.file = "__FILE__",		\
			.line = "__LINE__",		\
		};					\
	(cond) ?					\
		(__if_trace.miss_hit[1]++,1) :		\
		(__if_trace.miss_hit[0]++,0);		\
})
#define __trace_if_var(cond) (__builtin_constant_p(cond) ? (cond) : __trace_if_value(cond))
#define _compiletime_assert(condition, msg, prefix, suffix) \
	__compiletime_assert(condition, msg, prefix, suffix)
#define annotate_reachable() ({						\
	asm volatile("%c0:\n\t"						\
		     ".pushsection .discard.reachable\n\t"		\
		     ".long %c0b - .\n\t"				\
		     ".popsection\n\t" : : "i" (__COUNTER__));		\
})
#define annotate_unreachable() ({					\
	asm volatile("%c0:\n\t"						\
		     ".pushsection .discard.unreachable\n\t"		\
		     ".long %c0b - .\n\t"				\
		     ".popsection\n\t" : : "i" (__COUNTER__));		\
})
# define barrier() __memory_barrier()
# define barrier_before_unreachable() do { } while (0)
# define barrier_data(ptr) barrier()
#define compiletime_assert(condition, msg) \
	_compiletime_assert(condition, msg, __compiletime_assert_, __COUNTER__)
#define compiletime_assert_atomic_type(t)				\
	compiletime_assert(__native_word(t),				\
		"Need native word sized stores/loads for atomicity.")
#define if(cond, ...) if ( __trace_if_var( !!(cond , ## __VA_ARGS__) ) )
#define likely_notrace(x)	__builtin_expect(!!(x), 1)
#define unlikely_notrace(x)	__builtin_expect(!!(x), 0)
# define unreachable() do {		\
	annotate_unreachable();		\
	__builtin_unreachable();	\
} while (0)


#define DEFAULT_MMAP_MAX       (64)
#define DEFAULT_MMAP_THRESHOLD (128 * 1024)
#define DEFAULT_TOP_PAD        (0)
#define DEFAULT_TRIM_THRESHOLD (128 * 1024)

#define HAVE_MMAP 0
#define INTERNAL_SIZE_T size_t


#define MALLOC_COPY(dest,src,nbytes)                                          \
do {                                                                          \
  INTERNAL_SIZE_T mcsz = (nbytes);                                            \
  if(mcsz <= 9*sizeof(mcsz)) {                                                \
    INTERNAL_SIZE_T* mcsrc = (INTERNAL_SIZE_T*) (src);                        \
    INTERNAL_SIZE_T* mcdst = (INTERNAL_SIZE_T*) (dest);                       \
    if(mcsz >= 5*sizeof(mcsz)) {     *mcdst++ = *mcsrc++;                     \
				     *mcdst++ = *mcsrc++;                     \
      if(mcsz >= 7*sizeof(mcsz)) {   *mcdst++ = *mcsrc++;                     \
				     *mcdst++ = *mcsrc++;                     \
	if(mcsz >= 9*sizeof(mcsz)) { *mcdst++ = *mcsrc++;                     \
				     *mcdst++ = *mcsrc++; }}}                 \
				     *mcdst++ = *mcsrc++;                     \
				     *mcdst++ = *mcsrc++;                     \
				     *mcdst   = *mcsrc  ;                     \
  } else memcpy(dest, src, mcsz);                                             \
} while(0)
#define MALLOC_ZERO(charp, nbytes)                                            \
do {                                                                          \
  INTERNAL_SIZE_T mzsz = (nbytes);                                            \
  if(mzsz <= 9*sizeof(mzsz)) {                                                \
    INTERNAL_SIZE_T* mz = (INTERNAL_SIZE_T*) (charp);                         \
    if(mzsz >= 5*sizeof(mzsz)) {     *mz++ = 0;                               \
				     *mz++ = 0;                               \
      if(mzsz >= 7*sizeof(mzsz)) {   *mz++ = 0;                               \
				     *mz++ = 0;                               \
	if(mzsz >= 9*sizeof(mzsz)) { *mz++ = 0;                               \
				     *mz++ = 0; }}}                           \
				     *mz++ = 0;                               \
				     *mz++ = 0;                               \
				     *mz   = 0;                               \
  } else memset((charp), 0, mzsz);                                            \
} while(0)
#define MAP_ANONYMOUS MAP_ANON
#define MORECORE wsbrk
#define MORECORE_CLEARS 1
#define MORECORE_FAILURE 0
#define M_MMAP_MAX          -4
#define M_MMAP_THRESHOLD    -3
#define M_TOP_PAD           -2
#define M_TRIM_THRESHOLD    -1

#define USE_MEMCPY 1
#define Void_t      void

#      define _SC_PAGE_SIZE _SC_PAGESIZE

#define __STD_C     1
#define calloc dlcalloc
#define free free_simple
#define mallinfo() dlmallinfo()
#define malloc malloc_simple
#    define malloc_getpagesize sysconf(_SC_PAGE_SIZE)
#define malloc_stats dlmalloc_stats
#define malloc_trim dlmalloc_trim
#define malloc_usable_size dlmalloc_usable_size
#define mallopt dlmallopt
#define memalign dlmemalign
#define pvalloc dlpvalloc
#define realloc dlrealloc
#define valloc dlvalloc
#define M_ARENA_MAX         -8
#define M_ARENA_TEST        -7
#define M_CHECK_ACTION      -5
# define M_GRAIN   3    
# define M_KEEP    4    
# define M_MXFAST  1    
# define M_NLBLKS  2    
#define M_PERTURB           -6
#define _MALLOC_H 1
# define __MALLOC_DEPRECATED __attribute_deprecated__
# define __MALLOC_HOOK_VOLATILE volatile

#define __errno_asm_label asm("__u_boot_errno")
#define __set_errno(val) do { errno = val; } while (0)
#define ERESTART_RESTARTBLOCK 516 


#define ALIGN(x,a)		__ALIGN_MASK((x),(typeof(x))(a)-1)
#define ALIGN_DOWN(x, a)	ALIGN((x) - ((a) - 1), (a))
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define DIV_ROUND_CLOSEST(x, divisor)(			\
{							\
	typeof(x) __x = x;				\
	typeof(divisor) __d = divisor;			\
	(((typeof(x))-1) > 0 ||				\
	 ((typeof(divisor))-1) > 0 || (__x) > 0) ?	\
		(((__x) + ((__d) / 2)) / (__d)) :	\
		(((__x) - ((__d) / 2)) / (__d));	\
}							\
)
#define DIV_ROUND_CLOSEST_ULL(x, divisor)(		\
{							\
	typeof(divisor) __d = divisor;			\
	unsigned long long _tmp = (x) + (__d) / 2;	\
	do_div(_tmp, __d);				\
	_tmp;						\
}							\
)
#define DIV_ROUND_DOWN_ULL(ll, d) \
	({ unsigned long long _tmp = (ll); do_div(_tmp, d); _tmp; })
#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
# define DIV_ROUND_UP_SECTOR_T(ll,d) DIV_ROUND_UP_ULL(ll, d)
#define DIV_ROUND_UP_ULL(ll, d)		DIV_ROUND_DOWN_ULL((ll) + (d) - 1, (d))
#define FIELD_SIZEOF(t, f) (sizeof(((t*)0)->f))
#define IS_ALIGNED(x, a)		(((x) & ((typeof(x))(a) - 1)) == 0)
#define PTR_ALIGN(p, a)		((typeof(p))ALIGN((unsigned long)(p), (a)))
#define REPEAT_BYTE(x)	((~0ul / 0xff) * (x))
#define ROUND(a, b)		(((a) + (b) - 1) & ~((b) - 1))

#define __ALIGN_MASK(x,mask)	(((x)+(mask))&~(mask))
#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define abs(x) ({						\
		long ret;					\
		if (sizeof(x) == sizeof(long)) {		\
			long __x = (x);				\
			ret = (__x < 0) ? -__x : __x;		\
		} else {					\
			int __x = (x);				\
			ret = (__x < 0) ? -__x : __x;		\
		}						\
		ret;						\
	})
#define abs64(x) ({				\
		s64 __x = (x);			\
		(__x < 0) ? -__x : __x;		\
	})
#define check_member(structure, member, offset) _Static_assert( \
	offsetof(struct structure, member) == (offset), \
	"`struct " #structure "` offset for `" #member "` is not " #offset)
#define clamp(val, lo, hi) min((typeof(val))max(val, lo), hi)
#define clamp_t(type, val, lo, hi) min_t(type, max_t(type, val, lo), hi)
#define clamp_val(val, lo, hi) clamp_t(typeof(val), val, lo, hi)
#define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})
#define lower_32_bits(n) ((u32)(n))
#define max(x, y) ({				\
	typeof(x) _max1 = (x);			\
	typeof(y) _max2 = (y);			\
	(void) (&_max1 == &_max2);		\
	_max1 > _max2 ? _max1 : _max2; })
#define max3(x, y, z) max((typeof(x))max(x, y), z)
#define max_t(type, x, y) ({			\
	type __max1 = (x);			\
	type __max2 = (y);			\
	__max1 > __max2 ? __max1: __max2; })
#define min(x, y) ({				\
	typeof(x) _min1 = (x);			\
	typeof(y) _min2 = (y);			\
	(void) (&_min1 == &_min2);		\
	_min1 < _min2 ? _min1 : _min2; })
#define min3(x, y, z) min((typeof(x))min(x, y), z)
#define min_not_zero(x, y) ({			\
	typeof(x) __x = (x);			\
	typeof(y) __y = (y);			\
	__x == 0 ? __y : ((__y == 0) ? __x : min(__x, __y)); })
#define min_t(type, x, y) ({			\
	type __min1 = (x);			\
	type __min2 = (y);			\
	__min1 < __min2 ? __min1: __min2; })
#define mult_frac(x, numer, denom)(			\
{							\
	typeof(x) quot = (x) / (denom);			\
	typeof(x) rem  = (x) % (denom);			\
	(quot * (numer)) + ((rem * (numer)) / (denom));	\
}							\
)
#define round_down(x, y) ((x) & ~__round_mask(x, y))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)
#define rounddown(x, y) (				\
{							\
	typeof(x) __x = (x);				\
	__x - (__x % (y));				\
}							\
)
#define roundup(x, y) (					\
{							\
	const typeof(y) __y = y;			\
	(((x) + (__y - 1)) / __y) * __y;		\
}							\
)
#define swap(a, b) \
	do { typeof(a) __tmp = (a); (a) = (b); (b) = __tmp; } while (0)
#define upper_32_bits(n) ((u32)(((n) >> 16) >> 16))










#define no_printk(fmt, ...)				\
({							\
	if (0)						\
		printk(fmt, ##__VA_ARGS__);		\
	0;						\
})
#define pr_alert(fmt, ...)						\
({									\
	CONFIG_LOGLEVEL > 1 ? log_alert(fmt, ##__VA_ARGS__) : 0;	\
})
#define pr_cont(fmt, ...)						\
({									\
	gd->logl_prev < CONFIG_LOGLEVEL ?				\
		log_cont(fmt, ##__VA_ARGS__) : 0;			\
})
#define pr_crit(fmt, ...)						\
({									\
	CONFIG_LOGLEVEL > 2 ? log_crit(fmt, ##__VA_ARGS__) : 0;		\
})
#define pr_debug(fmt, ...)						\
({									\
	CONFIG_LOGLEVEL > 7 ? log_debug(fmt, ##__VA_ARGS__) : 0;	\
})
#define pr_devel(fmt, ...)						\
({									\
	CONFIG_LOGLEVEL > 7 ? log_debug(fmt, ##__VA_ARGS__) : 0;	\
})
#define pr_emerg(fmt, ...)						\
({									\
	CONFIG_LOGLEVEL > 0 ? log_emerg(fmt, ##__VA_ARGS__) : 0;	\
})
#define pr_err(fmt, ...)						\
({									\
	CONFIG_LOGLEVEL > 3 ? log_err(fmt, ##__VA_ARGS__) : 0;		\
})
#define pr_fmt(fmt) fmt
#define pr_info(fmt, ...)						\
({									\
	CONFIG_LOGLEVEL > 6 ? log_info(fmt, ##__VA_ARGS__) : 0;		\
})
#define pr_notice(fmt, ...)						\
({									\
	CONFIG_LOGLEVEL > 5 ? log_notice(fmt, ##__VA_ARGS__) : 0;	\
})
#define pr_warn(fmt, ...)						\
({									\
	CONFIG_LOGLEVEL > 4 ? log_warning(fmt, ##__VA_ARGS__) : 0;	\
})
#define printk(fmt, ...) \
	printf(fmt, ##__VA_ARGS__)
#define printk_once(fmt, ...) \
	printk(fmt, ##__VA_ARGS__)
#define LOG_CATEGORY LOGC_NONE
#define LOG_DRIVER(_name) \
	ll_entry_declare(struct log_driver, _name, log_driver)
#define LOG_GET_DRIVER(__name)						\
	ll_entry_get(struct log_driver, __name, log_driver)
#define _LOG_MAX_LEVEL CONFIG_VAL(LOG_MAX_LEVEL)

#define assert(x) \
	({ if (!(x) && _DEBUG) \
		__assert_fail(#x, "__FILE__", "__LINE__", __func__); })
#define assert_noisy(x) \
	({ bool _val = (x); \
	if (!_val) \
		__assert_fail(#x, "?", "__LINE__", __func__); \
	_val; \
	})
#define debug(fmt, args...)			\
	debug_cond(_DEBUG, fmt, ##args)
#define debug_cond(cond, fmt, args...)					\
({									\
	if (cond)							\
		log(LOG_CATEGORY,					\
		    (enum log_level_t)(LOGL_FORCE_DEBUG | _LOG_DEBUG),	\
		    fmt, ##args);					\
})
#define log(_cat, _level, _fmt, _args...) ({ \
	int _l = _level; \
	if (_LOG_DEBUG != 0 || _l <= _LOG_MAX_LEVEL) \
		_log((enum log_category_t)(_cat), \
		     (enum log_level_t)(_l | _LOG_DEBUG), "__FILE__", \
		     "__LINE__", __func__, \
		      pr_fmt(_fmt), ##_args); \
	})
#define log_alert(_fmt...)	log(LOG_CATEGORY, LOGL_ALERT, ##_fmt)
#define log_buffer(_cat, _level, _addr, _data, _width, _count, _linelen)  ({ \
	int _l = _level; \
	if (_LOG_DEBUG != 0 || _l <= _LOG_MAX_LEVEL) \
		_log_buffer((enum log_category_t)(_cat), \
			    (enum log_level_t)(_l | _LOG_DEBUG), "__FILE__", \
			    "__LINE__", __func__, _addr, _data, \
			    _width, _count, _linelen); \
	})
#define log_cont(_fmt...)	log(LOGC_CONT, LOGL_CONT, ##_fmt)
#define log_content(_fmt...)	log(LOG_CATEGORY, LOGL_DEBUG_CONTENT, ##_fmt)
#define log_crit(_fmt...)	log(LOG_CATEGORY, LOGL_CRIT, ##_fmt)
#define log_debug(_fmt...)	log(LOG_CATEGORY, LOGL_DEBUG, ##_fmt)
#define log_emer(_fmt...)	log(LOG_CATEGORY, LOGL_EMERG, ##_fmt)
#define log_err(_fmt...)	log(LOG_CATEGORY, LOGL_ERR, ##_fmt)
#define log_info(_fmt...)	log(LOG_CATEGORY, LOGL_INFO, ##_fmt)
#define log_io(_fmt...)		log(LOG_CATEGORY, LOGL_DEBUG_IO, ##_fmt)
#define log_msg_ret(_msg, _ret) ({ \
	int __ret = (_ret); \
	if (__ret < 0) \
		log(LOG_CATEGORY, LOGL_ERR, "%s: returning err=%d\n", _msg, \
		    __ret); \
	__ret; \
	})
#define log_msg_retz(_msg, _ret) ({ \
	int __ret = (_ret); \
	if (__ret) \
		log(LOG_CATEGORY, LOGL_ERR, "%s: returning err=%d\n", _msg, \
		    __ret); \
	__ret; \
	})
#define log_nop(_cat, _level, _fmt, _args...) ({ \
	int _l = _level; \
	_log_nop((enum log_category_t)(_cat), _l, "__FILE__", "__LINE__", \
		      __func__, pr_fmt(_fmt), ##_args); \
})
#define log_notice(_fmt...)	log(LOG_CATEGORY, LOGL_NOTICE, ##_fmt)
#define log_ret(_ret) ({ \
	int __ret = (_ret); \
	if (__ret < 0) \
		log(LOG_CATEGORY, LOGL_ERR, "returning err=%d\n", __ret); \
	__ret; \
	})
#define log_retz(_ret) ({ \
	int __ret = (_ret); \
	if (__ret) \
		log(LOG_CATEGORY, LOGL_ERR, "returning err=%d\n", __ret); \
	__ret; \
	})
#define log_warning(_fmt...)	log(LOG_CATEGORY, LOGL_WARNING, ##_fmt)
#define warn_non_spl(fmt, args...)			\
	debug_cond(!_SPL_BUILD, fmt, ##args)

#define HLIST_HEAD(name) struct hlist_head name = {  .first = NULL }
#define HLIST_HEAD_INIT { .first = NULL }
#define INIT_HLIST_HEAD(ptr) ((ptr)->first = NULL)
#define LIST_HEAD(name) \
	struct list_head name = LIST_HEAD_INIT(name)
#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define __list_for_each(pos, head) \
	for (pos = (head)->next; pos != (head); pos = pos->next)
#define hlist_entry(ptr, type, member) container_of(ptr,type,member)
#define hlist_for_each(pos, head) \
	for (pos = (head)->first; pos && ({ prefetch(pos->next); 1; }); \
	     pos = pos->next)
#define hlist_for_each_entry(tpos, pos, head, member)			 \
	for (pos = (head)->first;					 \
	     pos && ({ prefetch(pos->next); 1;}) &&			 \
		({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = pos->next)
#define hlist_for_each_entry_continue(tpos, pos, member)		 \
	for (pos = (pos)->next;						 \
	     pos && ({ prefetch(pos->next); 1;}) &&			 \
		({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = pos->next)
#define hlist_for_each_entry_from(tpos, pos, member)			 \
	for (; pos && ({ prefetch(pos->next); 1;}) &&			 \
		({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = pos->next)
#define hlist_for_each_entry_safe(tpos, pos, n, head, member)		 \
	for (pos = (head)->first;					 \
	     pos && ({ n = pos->next; 1; }) &&				 \
		({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = n)
#define hlist_for_each_safe(pos, n, head) \
	for (pos = (head)->first; pos && ({ n = pos->next; 1; }); \
	     pos = n)
#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)
#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)
#define list_first_entry_or_null(ptr, type, member) ({ \
	struct list_head *head__ = (ptr); \
	struct list_head *pos__ = READ_ONCE(head__->next); \
	pos__ != head__ ? list_entry(pos__, type, member) : NULL; \
})
#define list_for_each(pos, head) \
	for (pos = (head)->next; prefetch(pos->next), pos != (head); \
		pos = pos->next)
#define list_for_each_entry(pos, head, member)				\
	for (pos = list_entry((head)->next, typeof(*pos), member);	\
	     prefetch(pos->member.next), &pos->member != (head);	\
	     pos = list_entry(pos->member.next, typeof(*pos), member))
#define list_for_each_entry_continue(pos, head, member)			\
	for (pos = list_entry(pos->member.next, typeof(*pos), member);	\
	     prefetch(pos->member.next), &pos->member != (head);	\
	     pos = list_entry(pos->member.next, typeof(*pos), member))
#define list_for_each_entry_continue_reverse(pos, head, member)		\
	for (pos = list_entry(pos->member.prev, typeof(*pos), member);	\
	     prefetch(pos->member.prev), &pos->member != (head);	\
	     pos = list_entry(pos->member.prev, typeof(*pos), member))
#define list_for_each_entry_from(pos, head, member)			\
	for (; prefetch(pos->member.next), &pos->member != (head);	\
	     pos = list_entry(pos->member.next, typeof(*pos), member))
#define list_for_each_entry_reverse(pos, head, member)			\
	for (pos = list_entry((head)->prev, typeof(*pos), member);	\
	     prefetch(pos->member.prev), &pos->member != (head);	\
	     pos = list_entry(pos->member.prev, typeof(*pos), member))
#define list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = list_entry((head)->next, typeof(*pos), member),	\
		n = list_entry(pos->member.next, typeof(*pos), member);	\
	     &pos->member != (head);					\
	     pos = n, n = list_entry(n->member.next, typeof(*n), member))
#define list_for_each_entry_safe_continue(pos, n, head, member)			\
	for (pos = list_entry(pos->member.next, typeof(*pos), member),		\
		n = list_entry(pos->member.next, typeof(*pos), member);		\
	     &pos->member != (head);						\
	     pos = n, n = list_entry(n->member.next, typeof(*n), member))
#define list_for_each_entry_safe_from(pos, n, head, member)			\
	for (n = list_entry(pos->member.next, typeof(*pos), member);		\
	     &pos->member != (head);						\
	     pos = n, n = list_entry(n->member.next, typeof(*n), member))
#define list_for_each_entry_safe_reverse(pos, n, head, member)		\
	for (pos = list_entry((head)->prev, typeof(*pos), member),	\
		n = list_entry(pos->member.prev, typeof(*pos), member);	\
	     &pos->member != (head);					\
	     pos = n, n = list_entry(n->member.prev, typeof(*n), member))
#define list_for_each_prev(pos, head) \
	for (pos = (head)->prev; prefetch(pos->prev), pos != (head); \
		pos = pos->prev)
#define list_for_each_prev_safe(pos, n, head) \
	for (pos = (head)->prev, n = pos->prev; \
	     prefetch(pos->prev), pos != (head); \
	     pos = n, n = pos->prev)
#define list_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
		pos = n, n = pos->next)
#define list_last_entry(ptr, type, member) \
	list_entry((ptr)->prev, type, member)
#define list_prepare_entry(pos, head, member) \
	((pos) ? : list_entry(head, typeof(*pos), member))
#define LIST_POISON1  ((void *) 0x0)
#define LIST_POISON2  ((void *) 0x0)

#define BIT(nr)			(1UL << (nr))
#define BITS_TO_LONGS(nr)	DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))
#define BIT_MASK(nr)		(1UL << ((nr) % BITS_PER_LONG))
#define BIT_ULL(nr)		(1ULL << (nr))
#define BIT_ULL_MASK(nr)	(1ULL << ((nr) % BITS_PER_LONG_LONG))
#define BIT_ULL_WORD(nr)	((nr) / BITS_PER_LONG_LONG)
#define BIT_WORD(nr)		((nr) / BITS_PER_LONG)
#define GENMASK(h, l) \
	(((~0UL) << (l)) & (~0UL >> (CONFIG_SANDBOX_BITS_PER_LONG - 1 - (h))))
#define GENMASK_ULL(h, l) \
	(((~0ULL) << (l)) & (~0ULL >> (BITS_PER_LONG_LONG - 1 - (h))))

# define __clear_bit generic_clear_bit
# define __set_bit generic_set_bit
# define ffs generic_ffs
# define fls generic_fls
#define BITS_PER_LONG_LONG 64



#define ll_end(_type)							\
({									\
	static char end[0] __aligned(4) __attribute__((unused))		\
		__section(".u_boot_list_3");				\
	(_type *)&end;							\
})
#define ll_entry_count(_type, _list)					\
	({								\
		_type *start = ll_entry_start(_type, _list);		\
		_type *end = ll_entry_end(_type, _list);		\
		unsigned int _ll_result = end - start;			\
		_ll_result;						\
	})
#define ll_entry_declare(_type, _name, _list)				\
	_type _u_boot_list_2_##_list##_2_##_name __aligned(4)		\
			__attribute__((unused))				\
			__section(".u_boot_list_2_"#_list"_2_"#_name)
#define ll_entry_declare_list(_type, _name, _list)			\
	_type _u_boot_list_2_##_list##_2_##_name[] __aligned(4)		\
			__attribute__((unused))				\
			__section(".u_boot_list_2_"#_list"_2_"#_name)
#define ll_entry_end(_type, _list)					\
({									\
	static char end[0] __aligned(4) __attribute__((unused))		\
		__section(".u_boot_list_2_"#_list"_3");			\
	(_type *)&end;							\
})
#define ll_entry_get(_type, _name, _list)				\
	({								\
		extern _type _u_boot_list_2_##_list##_2_##_name;	\
		_type *_ll_result =					\
			&_u_boot_list_2_##_list##_2_##_name;		\
		_ll_result;						\
	})
#define ll_entry_ref(_type, _name, _list)				\
	((_type *)&_u_boot_list_2_##_list##_2_##_name)
#define ll_entry_start(_type, _list)					\
({									\
	static char start[0] __aligned(CONFIG_LINKER_LIST_ALIGN)	\
		__attribute__((unused))					\
		__section(".u_boot_list_2_"#_list"_1");			\
	(_type *)&start;						\
})
#define ll_start(_type)							\
({									\
	static char start[0] __aligned(4) __attribute__((unused))	\
		__section(".u_boot_list_1");				\
	(_type *)&start;						\
})
#define llsym(_type, _name, _list) \
		((_type *)&_u_boot_list_2_##_list##_2_##_name)
#define I2C_ADAPTER(bus)	i2c_bus[bus].adapter
#define I2C_MUX_PCA9540		{I2C_MUX_PCA9540_ID, "PCA9540B"
#define I2C_MUX_PCA9542		{I2C_MUX_PCA9542_ID, "PCA9542A"
#define I2C_MUX_PCA9544		{I2C_MUX_PCA9544_ID, "PCA9544A"
#define I2C_MUX_PCA9547		{I2C_MUX_PCA9547_ID, "PCA9547A"
#define I2C_MUX_PCA9548		{I2C_MUX_PCA9548_ID, "PCA9548"
#  define I2C_SOFT_DECLARATIONS
#define U_BOOT_I2C_ADAP_COMPLETE(_name, _init, _probe, _read, _write, \
			_set_speed, _speed, _slaveaddr, _hwadapnr) \
	ll_entry_declare(struct i2c_adapter, _name, i2c) = \
	U_BOOT_I2C_MKENT_COMPLETE(_init, _probe, _read, _write, \
		 _set_speed, _speed, _slaveaddr, _hwadapnr, _name);
#define U_BOOT_I2C_MKENT_COMPLETE(_init, _probe, _read, _write, \
		_set_speed, _speed, _slaveaddr, _hwadapnr, _name) \
	{ \
		.init		=	_init, \
		.probe		=	_probe, \
		.read		=	_read, \
		.write		=	_write, \
		.set_bus_speed	=	_set_speed, \
		.speed		=	_speed, \
		.slaveaddr	=	_slaveaddr, \
		.init_done	=	0, \
		.hwadapnr	=	_hwadapnr, \
		.name		=	#_name \
};

#define i2c_get_ops(dev)	((struct dm_i2c_ops *)(dev)->driver->ops)
#define i2c_mux_get_ops(dev)	((struct i2c_mux_ops *)(dev)->driver->ops)
#define EDID1_INFO_ESTABLISHED_TIMING_1024X768_60(_x) \
	GET_BIT(((_x).established_timings[1]), 3)
#define EDID1_INFO_ESTABLISHED_TIMING_1024X768_70(_x) \
	GET_BIT(((_x).established_timings[1]), 2)
#define EDID1_INFO_ESTABLISHED_TIMING_1024X768_75(_x) \
	GET_BIT(((_x).established_timings[1]), 1)
#define EDID1_INFO_ESTABLISHED_TIMING_1024X768_87I(_x) \
	GET_BIT(((_x).established_timings[1]), 4)
#define EDID1_INFO_ESTABLISHED_TIMING_1152X870_75(_x) \
	GET_BIT(((_x).established_timings[2]), 7)
#define EDID1_INFO_ESTABLISHED_TIMING_1280X1024_75(_x) \
	GET_BIT(((_x).established_timings[1]), 0)
#define EDID1_INFO_ESTABLISHED_TIMING_640X480_60(_x) \
	GET_BIT(((_x).established_timings[0]), 5)
#define EDID1_INFO_ESTABLISHED_TIMING_640X480_67(_x) \
	GET_BIT(((_x).established_timings[0]), 4)
#define EDID1_INFO_ESTABLISHED_TIMING_640X480_72(_x) \
	GET_BIT(((_x).established_timings[0]), 3)
#define EDID1_INFO_ESTABLISHED_TIMING_640X480_75(_x) \
	GET_BIT(((_x).established_timings[0]), 2)
#define EDID1_INFO_ESTABLISHED_TIMING_720X400_70(_x) \
	GET_BIT(((_x).established_timings[0]), 7)
#define EDID1_INFO_ESTABLISHED_TIMING_720X400_88(_x) \
	GET_BIT(((_x).established_timings[0]), 6)
#define EDID1_INFO_ESTABLISHED_TIMING_800X600_56(_x) \
	GET_BIT(((_x).established_timings[0]), 1)
#define EDID1_INFO_ESTABLISHED_TIMING_800X600_60(_x) \
	GET_BIT(((_x).established_timings[0]), 0)
#define EDID1_INFO_ESTABLISHED_TIMING_800X600_72(_x) \
	GET_BIT(((_x).established_timings[1]), 7)
#define EDID1_INFO_ESTABLISHED_TIMING_800X600_75(_x) \
	GET_BIT(((_x).established_timings[1]), 6)
#define EDID1_INFO_ESTABLISHED_TIMING_832X624_75(_x) \
	GET_BIT(((_x).established_timings[1]), 5)
#define EDID1_INFO_FEATURE_ACTIVE_OFF(_x) \
	GET_BIT(((_x).feature_support), 5)
#define EDID1_INFO_FEATURE_DEFAULT_GTF_SUPPORT(_x) \
	GET_BIT(((_x).feature_support), 0)
#define EDID1_INFO_FEATURE_DISPLAY_TYPE(_x) \
	GET_BITS(((_x).feature_support), 4, 3)
#define EDID1_INFO_FEATURE_PREFERRED_TIMING_MODE(_x) \
	GET_BIT(((_x).feature_support), 1)
#define EDID1_INFO_FEATURE_RGB(_x) \
	GET_BIT(((_x).feature_support), 2)
#define EDID1_INFO_FEATURE_STANDBY(_x) \
	GET_BIT(((_x).feature_support), 7)
#define EDID1_INFO_FEATURE_SUSPEND(_x) \
	GET_BIT(((_x).feature_support), 6)
#define EDID1_INFO_MANUFACTURER_NAME_CHAR1(_x) \
	GET_BITS(((_x).manufacturer_name[0]), 6, 2)
#define EDID1_INFO_MANUFACTURER_NAME_CHAR2(_x) \
	((GET_BITS(((_x).manufacturer_name[0]), 1, 0) << 3) + \
	 GET_BITS(((_x).manufacturer_name[1]), 7, 5))
#define EDID1_INFO_MANUFACTURER_NAME_CHAR3(_x) \
	GET_BITS(((_x).manufacturer_name[1]), 4, 0)
#define EDID1_INFO_MANUFACTURER_NAME_ZERO(_x) \
	GET_BIT(((_x).manufacturer_name[0]), 7)
#define EDID1_INFO_PRODUCT_CODE(_x) \
	(((uint16_t)(_x).product_code[1] << 8) + (_x).product_code[0])
#define EDID1_INFO_SERIAL_NUMBER(_x) \
	(((uint32_t)(_x).serial_number[3] << 24) + \
	 ((_x).serial_number[2] << 16) + ((_x).serial_number[1] << 8) + \
	 (_x).serial_number[0])
#define EDID1_INFO_STANDARD_TIMING_ASPECT(_x, _i) \
	GET_BITS(((_x).standard_timings[_i].aspect_vfreq), 7, 6)
#define EDID1_INFO_STANDARD_TIMING_VFREQ(_x, _i) \
	GET_BITS(((_x).standard_timings[_i].aspect_vfreq), 5, 0)
#define EDID1_INFO_STANDARD_TIMING_XRESOLUTION(_x, _i) \
	(((_x).standard_timings[_i]).xresolution)
#define EDID1_INFO_VIDEO_INPUT_BLANK_TO_BLACK(_x) \
	GET_BIT(((_x).video_input_definition), 4)
#define EDID1_INFO_VIDEO_INPUT_COMPOSITE_SYNC(_x) \
	GET_BIT(((_x).video_input_definition), 2)
#define EDID1_INFO_VIDEO_INPUT_DIGITAL(_x) \
	GET_BIT(((_x).video_input_definition), 7)
#define EDID1_INFO_VIDEO_INPUT_SEPARATE_SYNC(_x) \
	GET_BIT(((_x).video_input_definition), 3)
#define EDID1_INFO_VIDEO_INPUT_SERRATION_V(_x) \
	GET_BIT(((_x).video_input_definition), 0)
#define EDID1_INFO_VIDEO_INPUT_SYNC_ON_GREEN(_x) \
	GET_BIT(((_x).video_input_definition), 1)
#define EDID1_INFO_VIDEO_INPUT_VOLTAGE_LEVEL(_x) \
	GET_BITS(((_x).video_input_definition), 6, 5)
#define EDID_CEA861_DB_LEN(_x, offset) \
	GET_BITS((_x).data[offset], 4, 0)
#define EDID_CEA861_DB_TYPE(_x, offset) \
	GET_BITS((_x).data[offset], 7, 5)
#define EDID_CEA861_DTD_COUNT(_x) \
	GET_BITS(((_x).dtd_count), 3, 0)
#define EDID_CEA861_SUPPORTS_BASIC_AUDIO(_x) \
	GET_BIT(((_x).dtd_count), 6)
#define EDID_CEA861_SUPPORTS_UNDERSCAN(_x) \
	GET_BIT(((_x).dtd_count), 7)
#define EDID_CEA861_SUPPORTS_YUV422(_x) \
	GET_BIT(((_x).dtd_count), 4)
#define EDID_CEA861_SUPPORTS_YUV444(_x) \
	GET_BIT(((_x).dtd_count), 5)
#define EDID_DETAILED_TIMING_FLAG_DIGITAL_COMPOSITE(_x) \
	GET_BITS((_x).flags, 4, 3)
#define EDID_DETAILED_TIMING_FLAG_HSYNC_POLARITY(_x) \
	GET_BIT((_x).flags, 1)
#define EDID_DETAILED_TIMING_FLAG_INTERLACED(_x) \
	GET_BIT((_x).flags, 7)
#define EDID_DETAILED_TIMING_FLAG_INTERLEAVED(_x) \
	GET_BIT((_x).flags, 0)
#define EDID_DETAILED_TIMING_FLAG_POLARITY(_x) \
	GET_BITS((_x).flags, 2, 1)
#define EDID_DETAILED_TIMING_FLAG_STEREO(_x) \
	GET_BITS((_x).flags, 6, 5)
#define EDID_DETAILED_TIMING_FLAG_VSYNC_POLARITY(_x) \
	GET_BIT((_x).flags, 2)
#define EDID_DETAILED_TIMING_HIMAGE_SIZE(_x) \
	((GET_BITS((_x).himage_vimage_size_hi, 7, 4) << 8) + (_x).himage_size)
#define EDID_DETAILED_TIMING_HORIZONTAL_ACTIVE(_x) \
	((GET_BITS((_x).horizontal_active_blanking_hi, 7, 4) << 8) + \
	 (_x).horizontal_active)
#define EDID_DETAILED_TIMING_HORIZONTAL_BLANKING(_x) \
	((GET_BITS((_x).horizontal_active_blanking_hi, 3, 0) << 8) + \
	 (_x).horizontal_blanking)
#define EDID_DETAILED_TIMING_HSYNC_OFFSET(_x) \
	((GET_BITS((_x).hsync_vsync_offset_pulse_width_hi, 7, 6) << 8) + \
	 (_x).hsync_offset)
#define EDID_DETAILED_TIMING_HSYNC_PULSE_WIDTH(_x) \
	((GET_BITS((_x).hsync_vsync_offset_pulse_width_hi, 5, 4) << 8) + \
	 (_x).hsync_pulse_width)
#define EDID_DETAILED_TIMING_PIXEL_CLOCK(_x) \
	(((((uint32_t)(_x).pixel_clock[1]) << 8) + \
	 (_x).pixel_clock[0]) * 10000)
#define EDID_DETAILED_TIMING_VERTICAL_ACTIVE(_x) \
	((GET_BITS((_x).vertical_active_blanking_hi, 7, 4) << 8) + \
	 (_x).vertical_active)
#define EDID_DETAILED_TIMING_VERTICAL_BLANKING(_x) \
	((GET_BITS((_x).vertical_active_blanking_hi, 3, 0) << 8) + \
	 (_x).vertical_blanking)
#define EDID_DETAILED_TIMING_VIMAGE_SIZE(_x) \
	((GET_BITS((_x).himage_vimage_size_hi, 3, 0) << 8) + (_x).vimage_size)
#define EDID_DETAILED_TIMING_VSYNC_OFFSET(_x) \
	((GET_BITS((_x).hsync_vsync_offset_pulse_width_hi, 3, 2) << 4) + \
	 GET_BITS((_x).vsync_offset_pulse_width, 7, 4))
#define EDID_DETAILED_TIMING_VSYNC_PULSE_WIDTH(_x) \
	((GET_BITS((_x).hsync_vsync_offset_pulse_width_hi, 1, 0) << 4) + \
	 GET_BITS((_x).vsync_offset_pulse_width, 3, 0))
#define GET_BIT(_x, _pos) \
	(((_x) >> (_pos)) & 1)
#define GET_BITS(_x, _pos_msb, _pos_lsb) \
	(((_x) >> (_pos_lsb)) & ((1 << ((_pos_msb) - (_pos_lsb) + 1)) - 1))
#define HDMI_IEEE_OUI 0x000c03


#define DM_UCLASS_DRIVER_REF(_name)					\
	ll_entry_ref(struct uclass_driver, _name, uclass_driver)
#define UCLASS_DRIVER(__name)						\
	ll_entry_declare(struct uclass_driver, __name, uclass_driver)

#define uclass_foreach_dev(pos, uc)	\
	list_for_each_entry(pos, &uc->dev_head, uclass_node)
#define uclass_foreach_dev_probe(id, dev)	\
	for (int _ret = uclass_first_device_err(id, &dev); !_ret && dev; \
	     _ret = uclass_next_device_err(&dev))
#define uclass_foreach_dev_safe(pos, next, uc)	\
	list_for_each_entry_safe(pos, next, &uc->dev_head, uclass_node)
#define uclass_id_foreach_dev(id, pos, uc) \
	if (!uclass_get(id, &uc)) \
		list_for_each_entry(pos, &uc->dev_head, uclass_node)

#define ofnode_for_each_compatible_node(node, compat) \
	for (node = ofnode_by_compatible(ofnode_null(), compat); \
	     ofnode_valid(node); \
	     node = ofnode_by_compatible(node, compat))
#define ofnode_for_each_subnode(node, parent) \
	for (node = ofnode_first_subnode(parent); \
	     ofnode_valid(node); \
	     node = ofnode_next_subnode(node))


#define for_each_of_allnodes(dn) for_each_of_allnodes_from(NULL, dn)
#define for_each_of_allnodes_from(from, dn) \
	for (dn = of_find_all_nodes(from); dn; dn = of_find_all_nodes(dn))
#define of_node_get(x) (x)
#define OF_MAX_PHANDLE_ARGS 16
#define OF_ROOT_NODE_ADDR_CELLS_DEFAULT 2
#define OF_ROOT_NODE_SIZE_CELLS_DEFAULT 1

#define of_compat_cmp(s1, s2, l)	strcasecmp((s1), (s2))
#define of_node_cmp(s1, s2)		strcasecmp((s1), (s2))
#define of_prop_cmp(s1, s2)		strcmp((s1), (s2))
#define FDTDEC_RESERVED_MEMORY_NO_MAP (1 << 0)
#define FDT_ADDR_T_NONE ((ulong)(-1))
#define FDT_SIZE_T_NONE (-1U)
#define MAX_PHANDLE_ARGS 16

#define cpu_to_fdt_addr(reg) cpu_to_be64(reg)
#define cpu_to_fdt_size(reg) cpu_to_be64(reg)
#define fdt_addr_to_cpu(reg) be64_to_cpu(reg)
#define fdt_size_to_cpu(reg) be64_to_cpu(reg)
#define CAP_START_POS 0x40
#define PCIE_ECAM_OFFSET(bus, dev, func, where) \
	(PCIE_ECAM_BUS(bus) | \
	 PCIE_ECAM_DEV(dev) | \
	 PCIE_ECAM_FUNC(func) | \
	 PCIE_ECAM_REG(where))
#define PCI_ADD_BUS(bus, devfn)	(((bus) << 16) | (devfn))
#define  PCI_AGP_COMMAND_RQ_MASK 0xff000000  
#define  PCI_AGP_STATUS_RQ_MASK 0xff000000	
#define  PCI_BASE_ADDRESS_MEM_TYPE_MASK 0x06
#define  PCI_BASE_ADDRESS_SPACE 0x01	
#define  PCI_BASE_ADDRESS_SPACE_IO 0x01
#define  PCI_BASE_ADDRESS_SPACE_MEMORY 0x00
#define PCI_BDF(b, d, f)	((b) << 16 | PCI_DEVFN(d, f))
#define  PCI_BRIDGE_CTL_BUS_RESET 0x40	
#define  PCI_BRIDGE_CTL_FAST_BACK 0x80	
#define  PCI_BRIDGE_CTL_MASTER_ABORT 0x20  
#define PCI_BUS(d)		(((d) >> 16) & 0xff)
#define  PCI_CB_BRIDGE_CTL_MASTER_ABORT 0x20
#define  PCI_CB_BRIDGE_CTL_PREFETCH_MEM0 0x100	
#define  PCI_CB_BRIDGE_CTL_PREFETCH_MEM1 0x200
#define PCI_CB_LEGACY_MODE_BASE 0x44	
#define PCI_CB_SUBSYSTEM_VENDOR_ID 0x40
#define  PCI_COMMAND_INVALIDATE 0x10	
#define  PCI_COMMAND_VGA_PALETTE 0x20	
#define PCI_CONF1_ADDRESS(bus, dev, func, reg) \
	(PCI_CONF1_ENABLE | \
	 PCI_CONF1_BUS(bus) | \
	 PCI_CONF1_DEV(dev) | \
	 PCI_CONF1_FUNC(func) | \
	 PCI_CONF1_REG(reg))
#define PCI_CONF1_EXT_ADDRESS(bus, dev, func, reg) \
	(PCI_CONF1_ADDRESS(bus, dev, func, reg) | \
	 PCI_CONF1_EXT_REG(reg))
#define PCI_DEV(d)		(((d) >> 11) & 0x1f)
#define PCI_DEVFN(d, f)		((d) << 11 | (f) << 8)
#define PCI_DEVICE(vend, dev) \
	.vendor = (vend), .device = (dev), \
	.subvendor = PCI_ANY_ID, .subdevice = PCI_ANY_ID
#define PCI_DEVICE_CLASS(dev_class, dev_class_mask) \
	.class = (dev_class), .class_mask = (dev_class_mask), \
	.vendor = PCI_ANY_ID, .device = PCI_ANY_ID, \
	.subvendor = PCI_ANY_ID, .subdevice = PCI_ANY_ID
#define PCI_DEVICE_SUB(vend, dev, subvend, subdev) \
	.vendor = (vend), .device = (dev), \
	.subvendor = (subvend), .subdevice = (subdev)
#define  PCI_ERR_CAP_FEP(x)	((x) & 31)	
#define  PCI_EXP_DEVCTL_NOSNOOP_EN 0x0800  
#define  PCI_EXP_DEVCTL_PAYLOAD_1024B 0x0060 
#define  PCI_EXP_DEVCTL_PAYLOAD_128B 0x0000 
#define  PCI_EXP_DEVCTL_PAYLOAD_2048B 0x0080 
#define  PCI_EXP_DEVCTL_PAYLOAD_256B 0x0020 
#define  PCI_EXP_DEVCTL_PAYLOAD_4096B 0x00a0 
#define  PCI_EXP_DEVCTL_PAYLOAD_512B 0x0040 
#define  PCI_EXP_DEVCTL_READRQ_1024B 0x3000 
#define  PCI_EXP_DEVCTL_READRQ_128B  0x0000 
#define  PCI_EXP_DEVCTL_READRQ_2048B 0x4000 
#define  PCI_EXP_DEVCTL_READRQ_256B  0x1000 
#define  PCI_EXP_DEVCTL_READRQ_4096B 0x5000 
#define  PCI_EXP_DEVCTL_READRQ_512B  0x2000 
#define  PCI_EXP_DEVCTL_RELAX_EN 0x0010 
#define  PCI_EXP_LNKCAP_SLS_2_5GB 0x00000001 
#define  PCI_EXP_LNKCAP_SLS_5_0GB 0x00000002 
#define  PCI_EXP_LNKCAP_SLS_8_0GB 0x00000003 
#define  PCI_EXP_LNKCTL2_TLS_2_5GT 0x0001 
#define  PCI_EXP_LNKCTL2_TLS_5_0GT 0x0002 
#define  PCI_EXP_LNKCTL2_TLS_8_0GT 0x0003 
#define  PCI_EXP_LNKSTA_CLS_2_5GB 0x0001 
#define  PCI_EXP_LNKSTA_CLS_5_0GB 0x0002 
#define  PCI_EXP_LNKSTA_CLS_8_0GB 0x0003 
#define  PCI_EXP_LNKSTA_NLW_SHIFT 4	
#define   PCI_EXP_TYPE_DOWNSTREAM  0x6	
#define   PCI_EXP_TYPE_PCIE_BRIDGE 0x8	
#define   PCI_EXP_TYPE_ROOT_PORT   0x4	
#define PCI_EXT_CAP_ID(header)		(header & 0x0000ffff)
#define PCI_EXT_CAP_NEXT(header)	((header >> 20) & 0xffc)
#define PCI_EXT_CAP_VER(header)		((header >> 16) & 0xf)
#define PCI_FIND_CAP_TTL 0x48
#define PCI_FUNC(d)		(((d) >> 8) & 0x7)
#define  PCI_HEADER_TYPE_BRIDGE 1
#define  PCI_HEADER_TYPE_CARDBUS 2
#define  PCI_HEADER_TYPE_NORMAL 0
#define  PCI_IO_RANGE_TYPE_MASK 0x0f	
#define PCI_MASK_BUS(bdf)	((bdf) & 0xffff)
#define  PCI_MEMORY_RANGE_TYPE_MASK 0x0f
#define  PCI_PM_CTRL_PME_ENABLE 0x0100	
#define  PCI_PM_CTRL_PME_STATUS 0x8000	
#define  PCI_PM_CTRL_STATE_MASK 0x0003	
#define  PCI_PREF_RANGE_TYPE_32 0x00
#define  PCI_PREF_RANGE_TYPE_64 0x01
#define  PCI_PREF_RANGE_TYPE_MASK 0x0f
#define  PCI_ROM_ADDRESS_ENABLE 0x01
#define  PCI_STATUS_DETECTED_PARITY 0x8000 
#define  PCI_STATUS_DEVSEL_FAST 0x000
#define  PCI_STATUS_DEVSEL_MASK 0x600	
#define  PCI_STATUS_DEVSEL_MEDIUM 0x200
#define  PCI_STATUS_DEVSEL_SLOW 0x400
#define  PCI_STATUS_REC_MASTER_ABORT 0x2000 
#define  PCI_STATUS_REC_TARGET_ABORT 0x1000 
#define  PCI_STATUS_SIG_SYSTEM_ERROR 0x4000 
#define  PCI_STATUS_SIG_TARGET_ABORT 0x800 
#define PCI_SUBSYSTEM_VENDOR_ID 0x2c
#define PCI_TO_BDF(val)		((val) << 8)
#define PCI_VDEVICE(vend, dev) \
	.vendor = PCI_VENDOR_ID_##vend, .device = (dev), \
	.subvendor = PCI_ANY_ID, .subdevice = PCI_ANY_ID, 0, 0
#define  PCI_X_CMD_DPERR_E      0x0001  
#define  PCI_X_CMD_ERO          0x0002  
#define  PCI_X_CMD_MAX_READ     0x0000  
#define  PCI_X_CMD_MAX_SPLIT    0x0030  
#define  PCI_X_CMD_VERSION(x)   (((x) >> 12) & 3) 
#define U_BOOT_PCI_DEVICE(__name, __match)				\
	ll_entry_declare(struct pci_driver_entry, __name, pci_driver_entry) = {\
		.driver = llsym(struct driver, __name, driver), \
		.match = __match, \
		}

#define dm_pci_bus_to_virt(dev, addr, len, mask, flags, map_flags)	\
({									\
	size_t _len = (len);						\
	phys_addr_t phys_addr = dm_pci_bus_to_phys((dev), (addr), _len,	\
						   (mask), (flags));	\
	map_physmem(phys_addr, _len, (map_flags));			\
})
#define dm_pci_io_to_phys(dev, addr) \
	dm_pci_bus_to_phys((dev), (addr), 0, PCI_REGION_TYPE, PCI_REGION_IO)
#define dm_pci_io_to_virt(dev, addr, len, map_flags) \
	dm_pci_bus_to_virt((dev), (addr), (len), PCI_REGION_TYPE, \
			   PCI_REGION_IO, (map_flags))
#define dm_pci_mem_to_phys(dev, addr) \
	dm_pci_bus_to_phys((dev), (addr), 0, PCI_REGION_TYPE, PCI_REGION_MEM)
#define dm_pci_mem_to_virt(dev, addr, len, map_flags) \
	dm_pci_bus_to_virt((dev), (addr), (len), PCI_REGION_TYPE, \
			   PCI_REGION_MEM, (map_flags))
#define dm_pci_phys_to_io(dev, addr) \
	dm_pci_phys_to_bus((dev), (addr), 0, PCI_REGION_TYPE, PCI_REGION_IO)
#define dm_pci_phys_to_mem(dev, addr) \
	dm_pci_phys_to_bus((dev), (addr), 0, PCI_REGION_TYPE, PCI_REGION_MEM)
#define dm_pci_virt_to_bus(dev, addr, flags) \
	dm_pci_phys_to_bus(dev, (virt_to_phys(addr)), 0, PCI_REGION_TYPE, (flags))
#define dm_pci_virt_to_io(dev, addr) \
	dm_pci_virt_to_bus((dev), (addr), PCI_REGION_IO)
#define dm_pci_virt_to_mem(dev, addr) \
	dm_pci_virt_to_bus((dev), (addr), PCI_REGION_MEM)
#define pci_bus_to_phys(dev, addr, flags) \
	pci_hose_bus_to_phys(pci_bus_to_hose(PCI_BUS(dev)), (addr), (flags))
#define pci_bus_to_virt(dev, addr, flags, len, map_flags) \
	map_physmem(pci_hose_bus_to_phys(pci_bus_to_hose(PCI_BUS(dev)), \
					 (addr), (flags)), \
		    (len), (map_flags))
#define pci_get_emul_ops(dev)	((struct dm_pci_emul_ops *)(dev)->driver->ops)
#define pci_get_ops(dev)	((struct dm_pci_ops *)(dev)->driver->ops)
#define pci_io_to_phys(dev, addr)  pci_bus_to_phys((dev), (addr), PCI_REGION_IO)
#define pci_io_to_virt(dev, addr, len, map_flags) \
	pci_bus_to_virt((dev), (addr), PCI_REGION_IO, (len), (map_flags))
#define pci_mem_to_phys(dev, addr) \
	pci_bus_to_phys((dev), (addr), PCI_REGION_MEM)
#define pci_mem_to_virt(dev, addr, len, map_flags) \
	pci_bus_to_virt((dev), (addr), PCI_REGION_MEM, (len), (map_flags))
#define pci_offset_to_barnum(offset)	\
		(((offset) - PCI_BASE_ADDRESS_0) / sizeof(u32))
#define pci_phys_to_bus(dev, addr, flags) \
	pci_hose_phys_to_bus(pci_bus_to_hose(PCI_BUS(dev)), (addr), (flags))
#define pci_phys_to_io(dev, addr)  pci_phys_to_bus((dev), (addr), PCI_REGION_IO)
#define pci_phys_to_mem(dev, addr) \
	pci_phys_to_bus((dev), (addr), PCI_REGION_MEM)
#define pci_virt_to_bus(dev, addr, flags) \
	pci_hose_phys_to_bus(pci_bus_to_hose(PCI_BUS(dev)), \
			     (virt_to_phys(addr)), (flags))
#define pci_virt_to_io(dev, addr) \
	pci_virt_to_bus((dev), (addr), PCI_REGION_IO)
#define pci_virt_to_mem(dev, addr) \
	pci_virt_to_bus((dev), (addr), PCI_REGION_MEM)

#define PCIE_DEVICE_ID_NEO_4_IBM        0x00F4
#define PCIE_DEVICE_ID_NVIDIA_GEFORCE_6200_ALT1 0x00f3
#define PCIE_DEVICE_ID_NVIDIA_GEFORCE_6600_ALT1 0x00f1
#define PCIE_DEVICE_ID_NVIDIA_GEFORCE_6600_ALT2 0x00f2
#define PCIE_DEVICE_ID_NVIDIA_GEFORCE_6800_ALT1 0x00f0
#define PCIE_DEVICE_ID_NVIDIA_GEFORCE_6800_GT   0x00f9
#define PCI_BASE_CLASS_SIGNAL_PROCESSING 0x11
#define PCI_CLASS_COMMUNICATION_MULTISERIAL 0x0702
#define PCI_CLASS_COMMUNICATION_PARALLEL 0x0701
#define PCI_DEVICE_ID_ABOCOM_2BD1       0x2BD1
#define PCI_DEVICE_ID_ADAPTEC2_OBSIDIAN   0x0500
#define PCI_DEVICE_ID_ADDIDATA_APCI7300        0x7002
#define PCI_DEVICE_ID_ADDIDATA_APCI7300_2      0x700B
#define PCI_DEVICE_ID_ADDIDATA_APCI7300_3      0x700E
#define PCI_DEVICE_ID_ADDIDATA_APCI7420        0x7001
#define PCI_DEVICE_ID_ADDIDATA_APCI7420_2      0x700A
#define PCI_DEVICE_ID_ADDIDATA_APCI7420_3      0x700D
#define PCI_DEVICE_ID_ADDIDATA_APCI7500        0x7000
#define PCI_DEVICE_ID_ADDIDATA_APCI7500_2      0x7009
#define PCI_DEVICE_ID_ADDIDATA_APCI7500_3      0x700C
#define PCI_DEVICE_ID_ADDIDATA_APCI7800        0x818E
#define PCI_DEVICE_ID_ADDIDATA_APCI7800_3      0x700F
#define PCI_DEVICE_ID_ADDIDATA_APCIe7300       0x7010
#define PCI_DEVICE_ID_ADDIDATA_APCIe7420       0x7011
#define PCI_DEVICE_ID_ADDIDATA_APCIe7500       0x7012
#define PCI_DEVICE_ID_ADDIDATA_APCIe7800       0x7013
#define PCI_DEVICE_ID_AMD_15H_M30H_NB_F3 0x141d
#define PCI_DEVICE_ID_AMD_15H_M30H_NB_F4 0x141e
#define PCI_DEVICE_ID_AMD_16H_M30H_NB_F3 0x1583
#define PCI_DEVICE_ID_AMD_16H_M30H_NB_F4 0x1584
#define PCI_DEVICE_ID_AMD_CS5535_IDE    0x208F
#define PCI_DEVICE_ID_AMD_CS5536_AUDIO  0x2093
#define PCI_DEVICE_ID_AMD_CS5536_EHC    0x2095
#define PCI_DEVICE_ID_AMD_CS5536_FLASH  0x2091
#define PCI_DEVICE_ID_AMD_CS5536_IDE    0x209A
#define PCI_DEVICE_ID_AMD_CS5536_ISA    0x2090
#define PCI_DEVICE_ID_AMD_CS5536_OHC    0x2094
#define PCI_DEVICE_ID_AMD_CS5536_UDC    0x2096
#define PCI_DEVICE_ID_AMD_CS5536_UOC    0x2097
#define PCI_DEVICE_ID_AMD_LX_AES    0x2082
#define PCI_DEVICE_ID_AMD_LX_VIDEO  0x2081
#define PCI_DEVICE_ID_APPLE_SH_ATA      0x0050
#define PCI_DEVICE_ID_APPLE_SH_SUNGEM   0x0051
#define PCI_DEVICE_ID_APPLICOM_PCI2000IBS_CAN 0x0002
#define PCI_DEVICE_ID_APPLICOM_PCI2000PFB 0x0003
#define PCI_DEVICE_ID_APPLICOM_PCIGENERIC 0x0001
#define PCI_DEVICE_ID_ATI_EVERGREEN     0x9802
#define PCI_DEVICE_ID_ATI_EVERGREEN2    0x9804
#define PCI_DEVICE_ID_ATI_IXP300_SATA   0x436e
#define PCI_DEVICE_ID_ATI_IXP400_SATA   0x4379
#define PCI_DEVICE_ID_ATI_RAGE128_MF    0x4d46
#define PCI_DEVICE_ID_ATI_RAGE128_ML    0x4d4c
#define PCI_DEVICE_ID_ATI_RS350_100     0x7830
#define PCI_DEVICE_ID_ATI_RS350_133     0x7831
#define PCI_DEVICE_ID_ATI_RS350_166     0x7832
#define PCI_DEVICE_ID_ATI_RS350_200     0x7833
#define PCI_DEVICE_ID_ATI_RS400_100     0x5a30
#define PCI_DEVICE_ID_ATI_RS400_133     0x5a31
#define PCI_DEVICE_ID_ATI_RS400_166     0x5a32
#define PCI_DEVICE_ID_ATI_RS400_200     0x5a33
#define PCI_DEVICE_ID_ATI_RS480         0x5950
#define PCI_DEVICE_ID_ATI_WRESTLER      0x9806
#define PCI_DEVICE_ID_BUSLOGIC_FLASHPOINT     0x8130
#define PCI_DEVICE_ID_BUSLOGIC_MULTIMASTER    0x1040
#define PCI_DEVICE_ID_BUSLOGIC_MULTIMASTER_NC 0x0140
#define PCI_DEVICE_ID_COMPAQ_TRIFLEX_IDE 0xae33
#define PCI_DEVICE_ID_ESDGMBH_CPCIASIO4 0x0111
#define PCI_DEVICE_ID_FARSITE_T1U       0x0610
#define PCI_DEVICE_ID_FARSITE_T2P       0x0400
#define PCI_DEVICE_ID_FARSITE_T2U       0x0620
#define PCI_DEVICE_ID_FARSITE_T4P       0x0440
#define PCI_DEVICE_ID_FARSITE_T4U       0x0640
#define PCI_DEVICE_ID_FARSITE_TE1       0x1610
#define PCI_DEVICE_ID_FARSITE_TE1C      0x1612
#define PCI_DEVICE_ID_GEFORCE_6800A             0x00c1
#define PCI_DEVICE_ID_GEFORCE_6800A_LE          0x00c2
#define PCI_DEVICE_ID_GEFORCE_GO_6800           0x00c8
#define PCI_DEVICE_ID_GEFORCE_GO_6800_ULTRA     0x00c9
#define PCI_DEVICE_ID_HINT_VXPROII_IDE 0x8013
#define PCI_DEVICE_ID_IBM_ICOM_V2_ONE_PORT_RVX_ONE_PORT_MDM_PCIE 0x0361
#define PCI_DEVICE_ID_INTEL_80003ES2LAN_COPPER_DPT     0x1096
#define PCI_DEVICE_ID_INTEL_80003ES2LAN_COPPER_SPT     0x10BA
#define PCI_DEVICE_ID_INTEL_80003ES2LAN_SERDES_DPT     0x1098
#define PCI_DEVICE_ID_INTEL_80003ES2LAN_SERDES_SPT     0x10BB
#define PCI_DEVICE_ID_INTEL_82454NX     0x84cb
#define PCI_DEVICE_ID_INTEL_82546GB_QUAD_COPPER_KSP3 0x10B5
#define PCI_DEVICE_ID_INTEL_82571EB_COPPER      0x105E
#define PCI_DEVICE_ID_INTEL_82571EB_FIBER       0x105F
#define PCI_DEVICE_ID_INTEL_82571EB_QUAD_COPPER 0x10A4
#define PCI_DEVICE_ID_INTEL_82571EB_QUAD_COPPER_LOWPROFILE  0x10BC
#define PCI_DEVICE_ID_INTEL_82571EB_QUAD_FIBER  0x10A5
#define PCI_DEVICE_ID_INTEL_82571EB_SERDES      0x1060
#define PCI_DEVICE_ID_INTEL_82571EB_SERDES_DUAL 0x10D9
#define PCI_DEVICE_ID_INTEL_82571EB_SERDES_QUAD 0x10DA
#define PCI_DEVICE_ID_INTEL_82571PT_QUAD_COPPER 0x10D5
#define PCI_DEVICE_ID_INTEL_82572EI             0x10B9
#define PCI_DEVICE_ID_INTEL_82572EI_COPPER      0x107D
#define PCI_DEVICE_ID_INTEL_82572EI_FIBER       0x107E
#define PCI_DEVICE_ID_INTEL_82572EI_SERDES      0x107F
#define PCI_DEVICE_ID_INTEL_82573E              0x108B
#define PCI_DEVICE_ID_INTEL_82573E_IAMT         0x108C
#define PCI_DEVICE_ID_INTEL_82573L              0x109A
#define PCI_DEVICE_ID_INTEL_82574L              0x10D3
#define PCI_DEVICE_ID_INTEL_82801DB_12  0x24cc
#define PCI_DEVICE_ID_INTEL_I7300_MCH_ERR 0x360c
#define PCI_DEVICE_ID_INTEL_I7300_MCH_FB0 0x360f
#define PCI_DEVICE_ID_INTEL_I7300_MCH_FB1 0x3610
#define PCI_DEVICE_ID_INTEL_I7_MC_CH0_ADDR  0x2c21
#define PCI_DEVICE_ID_INTEL_I7_MC_CH0_CTRL  0x2c20
#define PCI_DEVICE_ID_INTEL_I7_MC_CH0_RANK  0x2c22
#define PCI_DEVICE_ID_INTEL_I7_MC_CH0_TC    0x2c23
#define PCI_DEVICE_ID_INTEL_I7_MC_CH1_ADDR  0x2c29
#define PCI_DEVICE_ID_INTEL_I7_MC_CH1_CTRL  0x2c28
#define PCI_DEVICE_ID_INTEL_I7_MC_CH1_RANK  0x2c2a
#define PCI_DEVICE_ID_INTEL_I7_MC_CH1_TC    0x2c2b
#define PCI_DEVICE_ID_INTEL_I7_MC_CH2_ADDR  0x2c31
#define PCI_DEVICE_ID_INTEL_I7_MC_CH2_CTRL  0x2c30
#define PCI_DEVICE_ID_INTEL_I7_MC_CH2_RANK  0x2c32
#define PCI_DEVICE_ID_INTEL_I7_MC_CH2_TC    0x2c33
#define PCI_DEVICE_ID_INTEL_I7_NONCORE_ALT 0x2c40
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MCR         0x2c98
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MCR_REV2          0x2d98
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_CH0_ADDR 0x2ca1
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_CH0_ADDR_REV2  0x2da1
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_CH0_CTRL 0x2ca0
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_CH0_CTRL_REV2  0x2da0
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_CH0_RANK 0x2ca2
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_CH0_RANK_REV2  0x2da2
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_CH0_TC   0x2ca3
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_CH0_TC_REV2    0x2da3
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_CH1_ADDR 0x2ca9
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_CH1_ADDR_REV2  0x2da9
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_CH1_CTRL 0x2ca8
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_CH1_CTRL_REV2  0x2da8
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_CH1_RANK 0x2caa
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_CH1_RANK_REV2  0x2daa
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_CH1_TC   0x2cab
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_CH1_TC_REV2    0x2dab
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_CH2_ADDR_REV2  0x2db1
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_CH2_CTRL_REV2  0x2db0
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_CH2_RANK_REV2  0x2db2
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_CH2_TC_REV2    0x2db3
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_RAS_REV2       0x2d9a
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_TAD      0x2c99
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_TAD_REV2       0x2d99
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_TEST     0x2c9C
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_TEST_REV2      0x2d9c
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_NONCORE     0x2c50
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_NONCORE_ALT 0x2c51
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_NONCORE_REV2 0x2c70
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_QPI_LINK0   0x2c90
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_QPI_PHY0    0x2c91
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_SAD         0x2c81
#define PCI_DEVICE_ID_INTEL_PANTHERPOINT_LPC_MBL_SAMPLE 0x1e42
#define PCI_DEVICE_ID_INTEL_PANTHERPOINT_LPC_SFF_SAMPLE 0x1e43
#define PCI_DEVICE_ID_INTEL_X58_HUB_MGMT 0x342e
#define PCI_DEVICE_ID_JMICRON_JMB388_ESD 0x2392
#define PCI_DEVICE_ID_JMICRON_JMB38X_MMC 0x2382
#define PCI_DEVICE_ID_MELLANOX_ARBEL_COMPAT 0x6278
#define PCI_DEVICE_ID_MELLANOX_SINAI_OLD 0x5e8c
#define PCI_DEVICE_ID_NEC_PC9821CS01    0x800c 
#define PCI_DEVICE_ID_NEC_PC9821NRB06   0x800d 
#define PCI_DEVICE_ID_NEC_VRC5476       0x009b
#define PCI_DEVICE_ID_NEC_VRC5477_AC97  0x00a6
#define PCI_DEVICE_ID_NEOMAGIC_NM256AV_AUDIO 0x8005
#define PCI_DEVICE_ID_NEOMAGIC_NM256XL_PLUS_AUDIO 0x8016
#define PCI_DEVICE_ID_NEOMAGIC_NM256ZX_AUDIO 0x8006
#define PCI_DEVICE_ID_NEO_2DB9          0x00C8
#define PCI_DEVICE_ID_NEO_2DB9PRI       0x00C9
#define PCI_DEVICE_ID_NEO_2RJ45         0x00CA
#define PCI_DEVICE_ID_NEO_2RJ45PRI      0x00CB
#define PCI_DEVICE_ID_NS_GX_HOST_BRIDGE  0x0028
#define PCI_DEVICE_ID_NVIDIA_GEFORCE4_410_GO_M16 0x017D
#define PCI_DEVICE_ID_NVIDIA_GEFORCE4_4200_GO       0x0286
#define PCI_DEVICE_ID_NVIDIA_GEFORCE4_420_GO_M32 0x0176
#define PCI_DEVICE_ID_NVIDIA_GEFORCE4_440_GO_M64 0x0179
#define PCI_DEVICE_ID_NVIDIA_GEFORCE4_448_GO    0x0186
#define PCI_DEVICE_ID_NVIDIA_GEFORCE4_460_GO    0x0177
#define PCI_DEVICE_ID_NVIDIA_GEFORCE4_488_GO    0x0187
#define PCI_DEVICE_ID_NVIDIA_GEFORCE4_MX_4000   0x0185
#define PCI_DEVICE_ID_NVIDIA_GEFORCE4_MX_420_8X 0x0183
#define PCI_DEVICE_ID_NVIDIA_GEFORCE4_MX_440SE_8X 0x0182
#define PCI_DEVICE_ID_NVIDIA_GEFORCE4_MX_440_8X 0x0181
#define PCI_DEVICE_ID_NVIDIA_GEFORCE4_MX_MAC    0x0189
#define PCI_DEVICE_ID_NVIDIA_GEFORCE4_TI_4800SE     0x0282
#define PCI_DEVICE_ID_NVIDIA_GEFORCE4_TI_4800_8X    0x0281
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_6200_TURBOCACHE 0x0161
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_6800       0x0041
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_6800B      0x0211
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_6800B_GT   0x0215
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_6800B_LE   0x0212
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_6800_GT    0x0045
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_6800_LE    0x0042
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_6800_ULTRA 0x0040
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_7800_GT   0x0090
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5100        0x0327
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5200        0x0320
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5200SE      0x0323
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5200_1      0x0322
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5200_ULTRA  0x0321
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5500        0x0326
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5600        0x0312
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5600SE      0x0314
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5600_ULTRA  0x0311
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5700        0x0342
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5700LE      0x0343
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5700VE      0x0344
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5700_ULTRA  0x0341
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5800        0x0302
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5800_ULTRA  0x0301
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5900        0x0331
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5900XT      0x0332
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5900ZT      0x0334
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5900_ULTRA  0x0330
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5950_ULTRA  0x0333
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_GO5100      0x032D
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_GO5200      0x0324
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_GO5250      0x0325
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_GO5250_32   0x0328
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_GO5300      0x032C
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_GO5600      0x031A
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_GO5650      0x031B
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_GO5700_1    0x0347
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_GO5700_2    0x0348
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_GO_6200    0x0164
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_GO_6200_1  0x0167
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_GO_6250    0x0166
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_GO_6250_1  0x0168
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_GO_7800   0x0098
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_GO_7800_GTX 0x0099
#define PCI_DEVICE_ID_NVIDIA_NFORCE_MCP61_IDE       0x03EC
#define PCI_DEVICE_ID_NVIDIA_NFORCE_MCP61_SATA      0x03E7
#define PCI_DEVICE_ID_NVIDIA_NFORCE_MCP61_SATA2     0x03F6
#define PCI_DEVICE_ID_NVIDIA_NFORCE_MCP61_SATA3     0x03F7
#define PCI_DEVICE_ID_NVIDIA_NFORCE_MCP67_IDE       0x0560
#define PCI_DEVICE_ID_NVIDIA_NFORCE_MCP67_SMBUS     0x0542
#define PCI_DEVICE_ID_NVIDIA_NFORCE_MCP73_IDE       0x056C
#define PCI_DEVICE_ID_NVIDIA_NFORCE_MCP73_SMBUS     0x07D8
#define PCI_DEVICE_ID_NVIDIA_NFORCE_MCP77_IDE       0x0759
#define PCI_DEVICE_ID_NVIDIA_NFORCE_MCP78S_SMBUS    0x0752
#define PCI_DEVICE_ID_NVIDIA_NFORCE_MCP79_SMBUS     0x0AA2
#define PCI_DEVICE_ID_NVIDIA_NVENET_15              0x0373
#define PCI_DEVICE_ID_NVIDIA_QUADRO4_280_NVS    0x018A
#define PCI_DEVICE_ID_NVIDIA_QUADRO4_380_XGL    0x018B
#define PCI_DEVICE_ID_NVIDIA_QUADRO4_580_XGL    0x0188
#define PCI_DEVICE_ID_NVIDIA_QUADRO4_700_GOGL       0x028C
#define PCI_DEVICE_ID_NVIDIA_QUADRO4_780_XGL        0x0289
#define PCI_DEVICE_ID_NVIDIA_QUADRO4_980_XGL        0x0288
#define PCI_DEVICE_ID_NVIDIA_QUADRO_FX_1000         0x0309
#define PCI_DEVICE_ID_NVIDIA_QUADRO_FX_1100         0x034E
#define PCI_DEVICE_ID_NVIDIA_QUADRO_FX_2000         0x0308
#define PCI_DEVICE_ID_NVIDIA_QUADRO_FX_3000         0x0338
#define PCI_DEVICE_ID_NVIDIA_QUADRO_FX_4000     0x004E
#define PCI_DEVICE_ID_NVIDIA_QUADRO_FX_500          0x032B
#define PCI_DEVICE_ID_NVIDIA_QUADRO_FX_700          0x033F
#define PCI_DEVICE_ID_NVIDIA_QUADRO_FX_GO1000       0x034C
#define PCI_DEVICE_ID_NVIDIA_QUADRO_FX_GO700        0x031C
#define PCI_DEVICE_ID_NVIDIA_QUADRO_NVS_280_PCI     0x032A
#define PCI_DEVICE_ID_NVIDIA_SGS_RIVA128 0x0018
#define PCI_DEVICE_ID_NVIDIA_TNT_UNKNOWN        0x002a
#define PCI_DEVICE_ID_PCTECH_SAMURAI_IDE 0x3020
#define PCI_DEVICE_ID_PLX_9030          0x9030
#define PCI_DEVICE_ID_QUADRO_FX_1400            0x00ce
#define PCI_DEVICE_ID_QUADRO_FX_GO1400          0x00cc
#define PCI_DEVICE_ID_QUATECH_SPPXP_100 0x0278
#define PCI_DEVICE_ID_RME_DIGI96_8_PAD_OR_PST 0x3fc3
#define PCI_DEVICE_ID_SERVERWORKS_CSB5IDE 0x0212
#define PCI_DEVICE_ID_SERVERWORKS_CSB6    0x0203
#define PCI_DEVICE_ID_SERVERWORKS_CSB6IDE 0x0213
#define PCI_DEVICE_ID_SERVERWORKS_CSB6IDE2 0x0217
#define PCI_DEVICE_ID_SERVERWORKS_CSB6LPC 0x0227
#define PCI_DEVICE_ID_SERVERWORKS_GCNB_LE 0x0017
#define PCI_DEVICE_ID_SERVERWORKS_HT1000IDE 0x0214
#define PCI_DEVICE_ID_SERVERWORKS_HT1000SB 0x0205
#define PCI_DEVICE_ID_SERVERWORKS_HT1100LD 0x0408
#define PCI_DEVICE_ID_SERVERWORKS_OSB4IDE 0x0211
#define PCI_DEVICE_ID_SIEMENS_DSCC4     0x2102
#define PCI_DEVICE_ID_STMICRO_AUDIO_ROUTER_MSPS 0xCC10
#define PCI_DEVICE_ID_STMICRO_AUDIO_ROUTER_SRCS 0xCC0F
#define PCI_DEVICE_ID_STMICRO_SDIO_EMMC 0xCC0A
#define PCI_DEVICE_ID_STMICRO_UART_HWFC 0xCC03
#define PCI_DEVICE_ID_TDI_EHCI          0x0101
#define PCI_DEVICE_ID_TOSHIBA_SPIDER_NET 0x01b3
#define PCI_DEVICE_ID_UNISYS_DMA_DIRECTOR 0x001C
#define PCI_DEVICE_ID_XILINX_HAMMERFALL_DSP 0x3fc5
#define PCI_DEVICE_ID_XILINX_HAMMERFALL_DSP_MADI 0x3fc6
#define PCI_SUBDEVICE_ID_PCI_RAS4       0xf001
#define PCI_SUBDEVICE_ID_PCI_RAS8       0xf010
#define PCI_SUBDEVICE_ID_SPECIALIX_SPEED4 0xa004
#define PCI_SUBVENDOR_ID_PERLE          0x155f
#define PCI_VENDOR_ID_ADDIDATA                 0x15B8
#define PCI_VENDOR_ID_ADDIDATA_OLD             0x10E8
#define PCI_VENDOR_ID_BCM_GVC          0x14a4
#define PCI_VENDOR_ID_ELECTRONICDESIGNGMBH 0x12f8
#define PCI_VENDOR_ID_FARSITE           0x1619
#define PCI_VENDOR_ID_HINT             0x3388
#define PCI_VENDOR_ID_SIEMENS           0x110A
#define PCI_VENDOR_ID_TDI               0x192E


#define cpu_to_fdt32(x) cpu_to_be32(x)
#define cpu_to_fdt64(x) cpu_to_be64(x)
#define fdt32_to_cpu(x) be32_to_cpu(x)
#define fdt64_to_cpu(x) be64_to_cpu(x)

#define CPU_TO_FDT16(x) ((EXTRACT_BYTE(x, 0) << 8) | EXTRACT_BYTE(x, 1))
#define CPU_TO_FDT32(x) ((EXTRACT_BYTE(x, 0) << 24) | (EXTRACT_BYTE(x, 1) << 16) | \
			 (EXTRACT_BYTE(x, 2) << 8) | EXTRACT_BYTE(x, 3))
#define CPU_TO_FDT64(x) ((EXTRACT_BYTE(x, 0) << 56) | (EXTRACT_BYTE(x, 1) << 48) | \
			 (EXTRACT_BYTE(x, 2) << 40) | (EXTRACT_BYTE(x, 3) << 32) | \
			 (EXTRACT_BYTE(x, 4) << 24) | (EXTRACT_BYTE(x, 5) << 16) | \
			 (EXTRACT_BYTE(x, 6) << 8) | EXTRACT_BYTE(x, 7))
#define EXTRACT_BYTE(x, n)	((unsigned long long)((uint8_t *)&x)[n])
#define FDT_BITWISE __attribute__((bitwise))
#define FDT_FORCE __attribute__((force))
#define strnlen fdt_strnlen
#define U_BOOT_DRVINFO(__name)	_Static_assert(false, \
	"Cannot use U_BOOT_DRVINFO with of-platdata. Please use devicetree instead")
#define U_BOOT_DRVINFOS(__name)						\
	ll_entry_declare_list(struct driver_info, __name, driver_info)

#define driver_info_parent_id(driver_info)	driver_info->parent_idx

#define dev_for_each_property(prop, dev) \
	for (int ret_prop = dev_read_first_prop(dev, &prop); \
	     !ret_prop; \
	     ret_prop = dev_read_next_prop(&prop))
#define dev_for_each_subnode(subnode, dev) \
	for (subnode = dev_read_first_subnode(dev); \
	     ofnode_valid(subnode); \
	     subnode = ofnode_next_subnode(subnode))

#define DM_DRIVER_ALIAS(__name, __alias)
#define DM_DRIVER_GET(__name)						\
	ll_entry_get(struct driver, __name, driver)
#define DM_DRIVER_REF(_name)					\
	ll_entry_ref(struct driver, _name, driver)


#define U_BOOT_DRIVER(__name)						\
	ll_entry_declare(struct driver, __name, driver)

#define dev_get_dma_offset(_dev)		_dev->dma_offset
#define dev_set_dma_offset(_dev, _offset)	_dev->dma_offset = _offset
#define device_active(dev)	(dev_get_flags(dev) & DM_FLAG_ACTIVATED)
#define device_foreach_child(pos, parent)	\
	list_for_each_entry(pos, &parent->child_head, sibling_node)
#define device_foreach_child_of_to_plat(pos, parent)	\
	for (int _ret = device_first_child_ofdata_err(parent, &pos); !_ret; \
	     _ret = device_next_child_ofdata_err(&pos))
#define device_foreach_child_probe(pos, parent)	\
	for (int _ret = device_first_child_err(parent, &pos); !_ret; \
	     _ret = device_next_child_err(&pos))
#define device_foreach_child_safe(pos, next, parent)	\
	list_for_each_entry_safe(pos, next, &parent->child_head, sibling_node)
#define device_get_ops(dev)	((dev)->driver->ops)
#define of_match_ptr(_ptr)	(_ptr)


#define for_each_console_dev(i, file, dev)				\
	for (i = 0;							\
	     i < cd_count[file] && (dev = console_devices[file][i]);	\
	     i++)
#define DEV_FLAGS_DM     0x00000004	
#define DEV_FLAGS_OUTPUT 0x00000002	


#define U_BOOT_CMD(_name, _maxargs, _rep, _cmd, _usage, _help)		\
	U_BOOT_CMD_COMPLETE(_name, _maxargs, _rep, _cmd, _usage, _help, NULL)
#define U_BOOT_CMDREP_COMPLETE(_name, _maxargs, _cmd_rep, _usage,	\
			       _help, _comp)				\
	ll_entry_declare(struct cmd_tbl, _name, cmd) =			\
		U_BOOT_CMDREP_MKENT_COMPLETE(_name, _maxargs, _cmd_rep,	\
					     _usage, _help, _comp)
#define U_BOOT_CMDREP_MKENT_COMPLETE(_name, _maxargs, _cmd_rep,		\
				     _usage, _help, _comp)		\
		{ #_name, _maxargs, _cmd_rep, cmd_discard_repeatable,	\
		  _usage, _CMD_HELP(_help) _CMD_COMPLETE(_comp) }
#define U_BOOT_CMD_COMPLETE(_name, _maxargs, _rep, _cmd, _usage, _help, _comp) \
	ll_entry_declare(struct cmd_tbl, _name, cmd) =			\
		U_BOOT_CMD_MKENT_COMPLETE(_name, _maxargs, _rep, _cmd,	\
						_usage, _help, _comp);
#define U_BOOT_CMD_MKENT(_name, _maxargs, _rep, _cmd, _usage, _help)	\
	U_BOOT_CMD_MKENT_COMPLETE(_name, _maxargs, _rep, _cmd,		\
					_usage, _help, NULL)
#define U_BOOT_CMD_MKENT_COMPLETE(_name, _maxargs, _rep, _cmd,		\
				_usage, _help, _comp)			\
		{ #_name, _maxargs,					\
		 _rep ? cmd_always_repeatable : cmd_never_repeatable,	\
		 _cmd, _usage, _CMD_HELP(_help) _CMD_COMPLETE(_comp) }
#define U_BOOT_CMD_WITH_SUBCMDS(_name, _usage, _help, ...)		\
	U_BOOT_SUBCMDS(_name, __VA_ARGS__)				\
	U_BOOT_CMDREP_COMPLETE(_name, CONFIG_SYS_MAXARGS, do_##_name,	\
			       _usage, _help, complete_##_name)
#define U_BOOT_SUBCMDS(_cmdname, ...)					\
	static struct cmd_tbl _cmdname##_subcmds[] = { __VA_ARGS__ };	\
	U_BOOT_SUBCMDS_RELOC(_cmdname)					\
	U_BOOT_SUBCMDS_DO_CMD(_cmdname)					\
	U_BOOT_SUBCMDS_COMPLETE(_cmdname)
#define U_BOOT_SUBCMDS_COMPLETE(_cmdname)				\
	static int complete_##_cmdname(int argc, char *const argv[],	\
				       char last_char, int maxv,	\
				       char *cmdv[])			\
	{								\
		return complete_subcmdv(_cmdname##_subcmds,		\
					ARRAY_SIZE(_cmdname##_subcmds),	\
					argc - 1, argv + 1, last_char,	\
					maxv, cmdv);			\
	}
#define U_BOOT_SUBCMDS_DO_CMD(_cmdname)					\
	static int do_##_cmdname(struct cmd_tbl *cmdtp, int flag,	\
				 int argc, char *const argv[],		\
				 int *repeatable)			\
	{								\
		struct cmd_tbl *subcmd;					\
									\
		_cmdname##_subcmds_reloc();				\
									\
			\
		if (argc < 2 || argc > CONFIG_SYS_MAXARGS)		\
			return CMD_RET_USAGE;				\
									\
		subcmd = find_cmd_tbl(argv[1], _cmdname##_subcmds,	\
				      ARRAY_SIZE(_cmdname##_subcmds));	\
		if (!subcmd || argc - 1 > subcmd->maxargs)		\
			return CMD_RET_USAGE;				\
									\
		if (flag == CMD_FLAG_REPEAT &&				\
		    !cmd_is_repeatable(subcmd))				\
			return CMD_RET_SUCCESS;				\
									\
		return subcmd->cmd_rep(subcmd, flag, argc - 1,		\
				       argv + 1, repeatable);		\
	}
#define U_BOOT_SUBCMDS_RELOC(_cmdname)					\
	static void _cmdname##_subcmds_reloc(void)			\
	{								\
		static int relocated;					\
									\
		if (relocated)						\
			return;						\
									\
		fixup_cmdtable(_cmdname##_subcmds,			\
			       ARRAY_SIZE(_cmdname##_subcmds));		\
		relocated = 1;						\
	}

#define U_BOOT_SUBCMD_MKENT(_name, _maxargs, _rep, _do_cmd)		\
	U_BOOT_SUBCMD_MKENT_COMPLETE(_name, _maxargs, _rep, _do_cmd,	\
				     NULL)
#define U_BOOT_SUBCMD_MKENT_COMPLETE(_name, _maxargs, _rep, _do_cmd,	\
				     _comp)				\
	U_BOOT_CMD_MKENT_COMPLETE(_name, _maxargs, _rep, _do_cmd,	\
				  "", "", _comp)
#define U_BOOT_SUBCMD_START(name)	static struct cmd_tbl name[] = {};
# define _CMD_COMPLETE(x) x,
# define _CMD_HELP(x) x,
#define _CMD_REMOVE(_name, _cmd)					\
	int __remove_ ## _name(void)					\
	{								\
		if (0)							\
			_cmd(NULL, 0, 0, NULL);				\
		return 0;						\
	}
#define _CMD_REMOVE_REP(_name, _cmd)					\
	int __remove_ ## _name(void)					\
	{								\
		if (0)							\
			_cmd(NULL, 0, 0, NULL, NULL);			\
		return 0;						\
	}

#define U_BOOT_ENV_CALLBACK(name, callback) \
	static inline __maybe_unused void _u_boot_env_noop_##name(void) \
	{ \
		(void)callback; \
	}


#define endtick(seconds) (get_ticks() + (uint64_t)(seconds) * get_tbclk())

#define HEXDUMP_MAX_BUF_LENGTH(bytes)	(9 + (bytes) * 4 + 3)

