#include<linux/uuid.h>


#include<linux/elf-em.h>





#include<unistd.h>
#include<errno.h>
#include<linux/sysinfo.h>
#include<linux/time_types.h>




#include<linux/fs.h>





#include<linux/kdev_t.h>






#include<asm/poll.h>



#include<linux/stddef.h>












#include<linux/media.h>



#include<linux/string.h>

#include<asm/ipcbuf.h>
#include<sys/types.h>
#include<asm/siginfo.h>

#include<linux/sched.h>


#include<linux/ipc.h>


#include<ctype.h>
#include<linux/types.h>



#include<linux/time.h>

#include<time.h>
#include<asm/ptrace.h>




#include<linux/sysctl.h>



#include<stdio.h>







#include<linux/ioctl.h>
#include<linux/videodev2.h>


#include<sys/time.h>




#include<linux/stat.h>





#include<asm/signal.h>









#include<stdarg.h>

#include<linux/pps.h>
#include<asm/fcntl.h>




#include<fcntl.h>











#include<linux/dqblk_xfs.h>

#include<asm/sembuf.h>














#include<asm/shmbuf.h>



#include<linux/errno.h>


#include<asm/errno.h>




#include<signal.h>



#include<linux/const.h>
#include<linux/v4l2-common.h>













#include<asm/stat.h>



#include<asm/bitsperlong.h>
#include<linux/v4l2-mediabus.h>

#include<linux/kernel.h>
#include<linux/module.h>



#include<linux/fiemap.h>

#include<linux/v4l2-subdev.h>
#include<linux/param.h>

#include<linux/rseq.h>
#include<linux/wait.h>



#include<linux/ptp_clock.h>




#include<asm/types.h>


#include<linux/resource.h>
#include<stdlib.h>


#include<asm/resource.h>
#include<linux/fcntl.h>
#include<linux/limits.h>



#include<asm/param.h>




#include<asm-generic/hugetlb_encode.h>
#include<linux/poll.h>
#include<asm/swab.h>

#include<string.h>
#include<asm/auxvec.h>

#include<asm/byteorder.h>




#include<sys/ioctl.h>

#include<linux/v4l2-controls.h>
#include<linux/posix_types.h>



#define UV_QUANTABLE (&sd->jpeg_hdr[JPEG_QT1_OFFSET])
#define W9968CF_I2C_BUS_DELAY    4 
#define Y_QUANTABLE (&sd->jpeg_hdr[JPEG_QT0_OFFSET])
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#define JPEG_H 1
#define JPEG_HDR_SZ 556
#define JPEG_QT0_OFFSET 7
#define JPEG_QT1_OFFSET 72
#define D_CONF   2
#define D_FRAM   4
#define D_PACK   5
#define D_PROBE  1
#define D_STREAM 3
#define D_USBI   6
#define D_USBO   7

#define GSPCA_MAX_FRAMES 16	
#define MAX_NURBS 4		
#define USB_BUF_SZ 64
#define gspca_dbg(gspca_dev, level, fmt, ...)			\
	v4l2_dbg(level, gspca_debug, &(gspca_dev)->v4l2_dev,	\
		 fmt, ##__VA_ARGS__)
#define gspca_err(gspca_dev, fmt, ...)				\
	v4l2_err(&(gspca_dev)->v4l2_dev, fmt, ##__VA_ARGS__)
#define DEFINE_MUTEX(mutexname) \
	struct mutex mutexname = __MUTEX_INITIALIZER(mutexname)
# define __DEBUG_MUTEX_INITIALIZER(lockname)
# define __DEP_MAP_MUTEX_INITIALIZER(lockname) \
		, .dep_map = { .name = #lockname }

#define __MUTEX_INITIALIZER(lockname) \
		{ .owner = ATOMIC_LONG_INIT(0) \
		, .wait_lock = __SPIN_LOCK_UNLOCKED(lockname.wait_lock) \
		, .wait_list = LIST_HEAD_INIT(lockname.wait_list) \
		__DEBUG_MUTEX_INITIALIZER(lockname) \
		__DEP_MAP_MUTEX_INITIALIZER(lockname) }
#define mutex_init(mutex)						\
do {									\
	static struct lock_class_key __key;				\
									\
	__mutex_init((mutex), #mutex, &__key);				\
} while (0)
#define mutex_lock(lock) mutex_lock_nested(lock, 0)
#define mutex_lock_interruptible(lock) mutex_lock_interruptible_nested(lock, 0)
# define mutex_lock_interruptible_nested(lock, subclass) mutex_lock_interruptible(lock)
#define mutex_lock_io(lock) mutex_lock_io_nested(lock, 0)
# define mutex_lock_io_nested(lock, subclass) mutex_lock(lock)
#define mutex_lock_killable(lock) mutex_lock_killable_nested(lock, 0)
# define mutex_lock_killable_nested(lock, subclass) mutex_lock_killable(lock)
# define mutex_lock_nest_lock(lock, nest_lock) mutex_lock(lock)
# define mutex_lock_nested(lock, subclass) mutex_lock(lock)
#define DEBUG_LOCKS_WARN_ON(c)						\
({									\
	int __ret = 0;							\
									\
	if (!oops_in_progress && unlikely(c)) {				\
		if (debug_locks_off() && !debug_locks_silent)		\
			WARN(1, "DEBUG_LOCKS_WARN_ON(%s)", #c);		\
		__ret = 1;						\
	}								\
	__ret;								\
})
# define SMP_DEBUG_LOCKS_WARN_ON(c)			DEBUG_LOCKS_WARN_ON(c)

# define locking_selftest()	do { } while (0)
#define CHECK_DATA_CORRUPTION(condition, fmt, ...)			 \
	check_data_corruption(({					 \
		bool corruption = unlikely(condition);			 \
		if (corruption) {					 \
			if (IS_ENABLED(CONFIG_BUG_ON_DATA_CORRUPTION)) { \
				pr_err(fmt, ##__VA_ARGS__);		 \
				BUG();					 \
			} else						 \
				WARN(1, fmt, ##__VA_ARGS__);		 \
		}							 \
		corruption;						 \
	}))
#define MAYBE_BUILD_BUG_ON(cond) (0)

#define BUG() do {} while (1)
#define BUGFLAG_TAINT(taint)	((taint) << 8)
#define BUG_GET_TAINT(bug)	((bug)->flags >> 8)
#define BUG_ON(condition) do { if (unlikely(condition)) BUG(); } while (0)
#define WARN(condition, format...) ({					\
	int __ret_warn_on = !!(condition);				\
	if (unlikely(__ret_warn_on))					\
		__WARN_printf(TAINT_WARN, format);			\
	unlikely(__ret_warn_on);					\
})
#define WARN_ON(condition) ({						\
	int __ret_warn_on = !!(condition);				\
	if (unlikely(__ret_warn_on))					\
		__WARN();						\
	unlikely(__ret_warn_on);					\
})
#define WARN_ONCE(condition, format...)	({			\
	static bool __section(.data.once) __warned;		\
	int __ret_warn_once = !!(condition);			\
								\
	if (unlikely(__ret_warn_once && !__warned)) {		\
		__warned = true;				\
		WARN(1, format);				\
	}							\
	unlikely(__ret_warn_once);				\
})
#define WARN_ON_ONCE(condition)	({				\
	static bool __section(.data.once) __warned;		\
	int __ret_warn_once = !!(condition);			\
								\
	if (unlikely(__ret_warn_once && !__warned)) {		\
		__warned = true;				\
		WARN_ON(1);					\
	}							\
	unlikely(__ret_warn_once);				\
})
# define WARN_ON_SMP(x)			WARN_ON(x)
#define WARN_TAINT(condition, taint, format...) ({			\
	int __ret_warn_on = !!(condition);				\
	if (unlikely(__ret_warn_on))					\
		__WARN_printf(taint, format);				\
	unlikely(__ret_warn_on);					\
})
#define WARN_TAINT_ONCE(condition, taint, format...)	({	\
	static bool __section(.data.once) __warned;		\
	int __ret_warn_once = !!(condition);			\
								\
	if (unlikely(__ret_warn_once && !__warned)) {		\
		__warned = true;				\
		WARN_TAINT(1, taint, format);			\
	}							\
	unlikely(__ret_warn_once);				\
})

#define __WARN()		__WARN_printf(TAINT_WARN, NULL)
#define __WARN_printf(taint, arg...)					\
	warn_slowpath_fmt("__FILE__", "__LINE__", taint, arg)
#define ALIGN(x, a)		__ALIGN_KERNEL((x), (a))
#define ALIGN_DOWN(x, a)	__ALIGN_KERNEL((x) - ((a) - 1), (a))
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]) + __must_be_array(arr))
#define CONCATENATE(a, b) __CONCAT(a, b)
#define COUNT_ARGS(X...) __COUNT_ARGS(, ##X, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
#define DIV_ROUND_CLOSEST(x, divisor)(			\
{							\
	typeof(x) __x = x;				\
	typeof(divisor) __d = divisor;			\
	(((typeof(x))-1) > 0 ||				\
	 ((typeof(divisor))-1) > 0 ||			\
	 (((__x) > 0) == ((__d) > 0))) ?		\
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
#define DIV_ROUND_UP __KERNEL_DIV_ROUND_UP
# define DIV_ROUND_UP_SECTOR_T(ll,d) DIV_ROUND_UP_ULL(ll, d)
#define DIV_ROUND_UP_ULL(ll, d) \
	DIV_ROUND_DOWN_ULL((unsigned long long)(ll) + (d) - 1, (d))
#define IS_ALIGNED(x, a)		(((x) & ((typeof(x))(a) - 1)) == 0)
#define PTR_ALIGN(p, a)		((typeof(p))ALIGN((unsigned long)(p), (a)))
# define REBUILD_DUE_TO_FTRACE_MCOUNT_RECORD
#define REPEAT_BYTE(x)	((~0ul / 0xff) * (x))
#define VERIFY_OCTAL_PERMISSIONS(perms)						\
	(BUILD_BUG_ON_ZERO((perms) < 0) +					\
	 BUILD_BUG_ON_ZERO((perms) > 0777) +					\
	 		\
	 BUILD_BUG_ON_ZERO((((perms) >> 6) & 4) < (((perms) >> 3) & 4)) +	\
	 BUILD_BUG_ON_ZERO((((perms) >> 3) & 4) < ((perms) & 4)) +		\
	 					\
	 BUILD_BUG_ON_ZERO((((perms) >> 6) & 2) < (((perms) >> 3) & 2)) +	\
	 		\
	 BUILD_BUG_ON_ZERO((perms) & 2) +					\
	 (perms))

#define _THIS_IP_  ({ __label__ __here; __here: (unsigned long)&&__here; })
#define __ALIGN_MASK(x, mask)	__ALIGN_KERNEL_MASK((x), (mask))
#define __CONCAT(a, b) a ## b
#define __COUNT_ARGS(_0, _1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _n, X...) _n
#define __abs_choose_expr(x, type, other) __builtin_choose_expr(	\
	__builtin_types_compatible_p(typeof(x),   signed type) ||	\
	__builtin_types_compatible_p(typeof(x), unsigned type),		\
	({ signed type __x = (x); __x < 0 ? -__x : __x; }), other)
#define __careful_cmp(x, y, op) \
	__builtin_choose_expr(__safe_cmp(x, y), \
		__cmp(x, y, op), \
		__cmp_once(x, y, __UNIQUE_ID(__x), __UNIQUE_ID(__y), op))
#define __cmp(x, y, op)	((x) op (y) ? (x) : (y))
#define __cmp_once(x, y, unique_x, unique_y, op) ({	\
		typeof(x) unique_x = (x);		\
		typeof(y) unique_y = (y);		\
		__cmp(unique_x, unique_y, op); })
#define __is_constexpr(x) \
	(sizeof(int) == sizeof(*(8 ? ((void *)((long)(x) * 0l)) : (int *)8)))
#define __no_side_effects(x, y) \
		(__is_constexpr(x) && __is_constexpr(y))
#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define __safe_cmp(x, y) \
		(__typecheck(x, y) && __no_side_effects(x, y))
#define __trace_printk_check_format(fmt, args...)			\
do {									\
	if (0)								\
		____trace_printk_check_format(fmt, ##args);		\
} while (0)
#define __typecheck(x, y) \
		(!!(sizeof((typeof(x) *)1 == (typeof(y) *)1)))
# define cant_sleep() \
	do { __cant_sleep("__FILE__", "__LINE__", 0); } while (0)
#define clamp(val, lo, hi) min((typeof(val))max(val, lo), hi)
#define clamp_t(type, val, lo, hi) min_t(type, max_t(type, val, lo), hi)
#define clamp_val(val, lo, hi) clamp_t(typeof(val), val, lo, hi)
#define container_of(ptr, type, member) ({				\
	void *__mptr = (void *)(ptr);					\
	BUILD_BUG_ON_MSG(!__same_type(*(ptr), ((type *)0)->member) &&	\
			 !__same_type(*(ptr), void),			\
			 "pointer type mismatch in container_of()");	\
	((type *)(__mptr - offsetof(type, member))); })
#define container_of_safe(ptr, type, member) ({				\
	void *__mptr = (void *)(ptr);					\
	BUILD_BUG_ON_MSG(!__same_type(*(ptr), ((type *)0)->member) &&	\
			 !__same_type(*(ptr), void),			\
			 "pointer type mismatch in container_of()");	\
	IS_ERR_OR_NULL(__mptr) ? ERR_CAST(__mptr) :			\
		((type *)(__mptr - offsetof(type, member))); })
#define do_trace_printk(fmt, args...)					\
do {									\
	static const char *trace_printk_fmt __used			\
		__attribute__((section("__trace_printk_fmt"))) =	\
		__builtin_constant_p(fmt) ? fmt : NULL;			\
									\
	__trace_printk_check_format(fmt, ##args);			\
									\
	if (__builtin_constant_p(fmt))					\
		__trace_bprintk(_THIS_IP_, trace_printk_fmt, ##args);	\
	else								\
		__trace_printk(_THIS_IP_, fmt, ##args);			\
} while (0)
#define ftrace_vprintk(fmt, vargs)					\
do {									\
	if (__builtin_constant_p(fmt)) {				\
		static const char *trace_printk_fmt __used		\
		  __attribute__((section("__trace_printk_fmt"))) =	\
			__builtin_constant_p(fmt) ? fmt : NULL;		\
									\
		__ftrace_vbprintk(_THIS_IP_, trace_printk_fmt, vargs);	\
	} else								\
		__ftrace_vprintk(_THIS_IP_, fmt, vargs);		\
} while (0)
#define hex_asc_hi(x)	hex_asc[((x) & 0xf0) >> 4]
#define hex_asc_lo(x)	hex_asc[((x) & 0x0f)]
#define hex_asc_upper_hi(x)	hex_asc_upper[((x) & 0xf0) >> 4]
#define hex_asc_upper_lo(x)	hex_asc_upper[((x) & 0x0f)]
#define lower_32_bits(n) ((u32)(n))
#define max(x, y)	__careful_cmp(x, y, >)
#define max3(x, y, z) max((typeof(x))max(x, y), z)
#define max_t(type, x, y)	__careful_cmp((type)(x), (type)(y), >)
#define might_fault() __might_fault("__FILE__", "__LINE__")
# define might_resched() _cond_resched()
# define might_sleep() \
	do { __might_sleep("__FILE__", "__LINE__", 0); might_resched(); } while (0)
#define might_sleep_if(cond) do { if (cond) might_sleep(); } while (0)
#define min(x, y)	__careful_cmp(x, y, <)
#define min3(x, y, z) min((typeof(x))min(x, y), z)
#define min_not_zero(x, y) ({			\
	typeof(x) __x = (x);			\
	typeof(y) __y = (y);			\
	__x == 0 ? __y : ((__y == 0) ? __x : min(__x, __y)); })
#define min_t(type, x, y)	__careful_cmp((type)(x), (type)(y), <)
#define mult_frac(x, numer, denom)(			\
{							\
	typeof(x) quot = (x) / (denom);			\
	typeof(x) rem  = (x) % (denom);			\
	(quot * (numer)) + ((rem * (numer)) / (denom));	\
}							\
)
# define non_block_end() WARN_ON(current->non_block_count-- == 0)
# define non_block_start() (current->non_block_count++)
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
	typeof(y) __y = y;				\
	(((x) + (__y - 1)) / __y) * __y;		\
}							\
)
# define sched_annotate_sleep()	(current->task_state_change = 0)
#define sector_div(a, b) do_div(a, b)
#define swap(a, b) \
	do { typeof(a) __tmp = (a); (a) = (b); (b) = __tmp; } while (0)
#define trace_printk(fmt, ...)				\
do {							\
	char _______STR[] = __stringify((__VA_ARGS__));	\
	if (sizeof(_______STR) > 3)			\
		do_trace_printk(fmt, ##__VA_ARGS__);	\
	else						\
		trace_puts(fmt);			\
} while (0)
#define trace_puts(str) ({						\
	static const char *trace_printk_fmt __used			\
		__attribute__((section("__trace_printk_fmt"))) =	\
		__builtin_constant_p(str) ? str : NULL;			\
									\
	if (__builtin_constant_p(str))					\
		__trace_bputs(_THIS_IP_, trace_printk_fmt);		\
	else								\
		__trace_puts(_THIS_IP_, str, strlen(str));		\
})
#define typeof_member(T, m)	typeof(((T*)0)->m)
#define u64_to_user_ptr(x) (		\
{					\
	typecheck(u64, (x));		\
	(void __user *)(uintptr_t)(x);	\
}					\
)
#define upper_32_bits(n) ((u32)(((n) >> 16) >> 16))

#define __ALIGN_KERNEL(x, a)		__ALIGN_KERNEL_MASK(x, (typeof(x))(a) - 1)
#define __ALIGN_KERNEL_MASK(x, mask)	(((x) + (mask)) & ~(mask))
#define __KERNEL_DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define BUILD_BUG() BUILD_BUG_ON_MSG(1, "BUILD_BUG failed")
#define BUILD_BUG_ON(condition) \
	BUILD_BUG_ON_MSG(condition, "BUILD_BUG_ON failed: " #condition)
#define BUILD_BUG_ON_INVALID(e) ((void)(sizeof((__force long)(e))))
#define BUILD_BUG_ON_MSG(cond, msg) compiletime_assert(!(cond), msg)
#define BUILD_BUG_ON_NOT_POWER_OF_2(n)			\
	BUILD_BUG_ON((n) == 0 || (((n) & ((n) - 1)) != 0))
#define BUILD_BUG_ON_ZERO(e) ((int)(sizeof(struct { int:(-!!(e)); })))

#define __BUILD_BUG_ON_NOT_POWER_OF_2(n)	\
	BUILD_BUG_ON(((n) & ((n) - 1)) != 0)
#define __static_assert(expr, msg, ...) _Static_assert(expr, msg)
#define static_assert(expr, ...) __static_assert(expr, ##__VA_ARGS__, #expr)
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
	static void * __section(.discard.addressable) __used \
		__PASTE(__addressable_##sym, "__LINE__") = (void *)&sym;

#define __READ_ONCE(x, check)						\
({									\
	union { typeof(x) __val; char __c[1]; } __u;			\
	if (check)							\
		__read_once_size(&(x), __u.__c, sizeof(x));		\
	else								\
		__read_once_size_nocheck(&(x), __u.__c, sizeof(x));	\
	smp_read_barrier_depends();  \
	__u.__val;							\
})

#define __annotate_jump_table __section(.rodata..c_jump_table)
#define __branch_check__(x, expect, is_constant) ({			\
			long ______r;					\
			static struct ftrace_likely_data		\
				__aligned(4)				\
				__section(_ftrace_annotated_branch)	\
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
		__section(_ftrace_branch)		\
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

#define compiletime_assert_atomic_type(t)				\
	compiletime_assert(__native_word(t),				\
		"Need native word sized stores/loads for atomicity.")
#define if(cond, ...) if ( __trace_if_var( !!(cond , ## __VA_ARGS__) ) )
#  define likely(x)	(__branch_check__(x, 1, __builtin_constant_p(x)))
#define likely_notrace(x)	__builtin_expect(!!(x), 1)
#  define unlikely(x)	(__branch_check__(x, 0, __builtin_constant_p(x)))
#define unlikely_notrace(x)	__builtin_expect(!!(x), 0)
# define unreachable() do {		\
	annotate_unreachable();		\
	__builtin_unreachable();	\
} while (0)

#define kasan_check_read __kasan_check_read
#define kasan_check_write __kasan_check_write
#define DECLARE_BITMAP(name,bits) \
	unsigned long name[BITS_TO_LONGS(bits)]









#define aligned_be64		__aligned_be64
#define aligned_le64		__aligned_le64
#define aligned_u64		__aligned_u64
#define pgoff_t unsigned long
#define rcu_head callback_head

#define __aligned_be64 __be64 __attribute__((aligned(8)))
#define __aligned_le64 __le64 __attribute__((aligned(8)))
#define __aligned_u64 __u64 __attribute__((aligned(8)))
#define __bitwise __bitwise__
#define __bitwise__ __attribute__((bitwise))
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



#define __diag_GCC_8(s)		__diag(s)
#define __diag_str(s)		__diag_str1(s)
#define __diag_str1(s)		#s
#define __no_sanitize_address __attribute__((no_sanitize_address))
#define __noretpoline __attribute__((__indirect_branch__("keep")))
#define uninitialized_var(x) x = x
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
#define __section(S)                    __attribute__((__section__(#S)))
#define __used                          __attribute__((__used__))
# define __visible                      __attribute__((__externally_visible__))
#define __weak                          __attribute__((__weak__))
# define fallthrough                    __attribute__((__fallthrough__))
#define   noinline                      __attribute__((__noinline__))
#define CONSOLE_LOGLEVEL_DEFAULT CONFIG_CONSOLE_LOGLEVEL_DEFAULT
#define CONSOLE_LOGLEVEL_MOTORMOUTH 15	
#define CONSOLE_LOGLEVEL_QUIET	 CONFIG_CONSOLE_LOGLEVEL_QUIET
#define CONSOLE_LOGLEVEL_SILENT  0 
#define DEVKMSG_STR_MAX_SIZE 10
#define MESSAGE_LOGLEVEL_DEFAULT CONFIG_MESSAGE_LOGLEVEL_DEFAULT
#define PRINTK_MAX_SINGLE_HEADER_LEN 2

#define console_loglevel (console_printk[0])
#define default_console_loglevel (console_printk[3])
#define default_message_loglevel (console_printk[1])
#define minimum_console_loglevel (console_printk[2])
#define no_printk(fmt, ...)				\
({							\
	if (0)						\
		printk(fmt, ##__VA_ARGS__);		\
	0;						\
})
#define pr_alert(fmt, ...) \
	printk(KERN_ALERT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_alert_once(fmt, ...)					\
	printk_once(KERN_ALERT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_alert_ratelimited(fmt, ...)					\
	printk_ratelimited(KERN_ALERT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_cont(fmt, ...) \
	printk(KERN_CONT fmt, ##__VA_ARGS__)
#define pr_cont_once(fmt, ...)					\
	printk_once(KERN_CONT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_crit(fmt, ...) \
	printk(KERN_CRIT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_crit_once(fmt, ...)					\
	printk_once(KERN_CRIT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_crit_ratelimited(fmt, ...)					\
	printk_ratelimited(KERN_CRIT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_debug(fmt, ...) \
	dynamic_pr_debug(fmt, ##__VA_ARGS__)
#define pr_debug_once(fmt, ...)					\
	printk_once(KERN_DEBUG pr_fmt(fmt), ##__VA_ARGS__)
#define pr_debug_ratelimited(fmt, ...)					\
do {									\
	static DEFINE_RATELIMIT_STATE(_rs,				\
				      DEFAULT_RATELIMIT_INTERVAL,	\
				      DEFAULT_RATELIMIT_BURST);		\
	DEFINE_DYNAMIC_DEBUG_METADATA(descriptor, pr_fmt(fmt));		\
	if (DYNAMIC_DEBUG_BRANCH(descriptor) &&				\
	    __ratelimit(&_rs))						\
		__dynamic_pr_debug(&descriptor, pr_fmt(fmt), ##__VA_ARGS__);	\
} while (0)
#define pr_devel(fmt, ...) \
	printk(KERN_DEBUG pr_fmt(fmt), ##__VA_ARGS__)
#define pr_devel_once(fmt, ...)					\
	printk_once(KERN_DEBUG pr_fmt(fmt), ##__VA_ARGS__)
#define pr_devel_ratelimited(fmt, ...)					\
	printk_ratelimited(KERN_DEBUG pr_fmt(fmt), ##__VA_ARGS__)
#define pr_emerg(fmt, ...) \
	printk(KERN_EMERG pr_fmt(fmt), ##__VA_ARGS__)
#define pr_emerg_once(fmt, ...)					\
	printk_once(KERN_EMERG pr_fmt(fmt), ##__VA_ARGS__)
#define pr_emerg_ratelimited(fmt, ...)					\
	printk_ratelimited(KERN_EMERG pr_fmt(fmt), ##__VA_ARGS__)
#define pr_err(fmt, ...) \
	printk(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)
#define pr_err_once(fmt, ...)					\
	printk_once(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)
#define pr_err_ratelimited(fmt, ...)					\
	printk_ratelimited(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)
#define pr_info(fmt, ...) \
	printk(KERN_INFO pr_fmt(fmt), ##__VA_ARGS__)
#define pr_info_once(fmt, ...)					\
	printk_once(KERN_INFO pr_fmt(fmt), ##__VA_ARGS__)
#define pr_info_ratelimited(fmt, ...)					\
	printk_ratelimited(KERN_INFO pr_fmt(fmt), ##__VA_ARGS__)
#define pr_notice(fmt, ...) \
	printk(KERN_NOTICE pr_fmt(fmt), ##__VA_ARGS__)
#define pr_notice_once(fmt, ...)				\
	printk_once(KERN_NOTICE pr_fmt(fmt), ##__VA_ARGS__)
#define pr_notice_ratelimited(fmt, ...)					\
	printk_ratelimited(KERN_NOTICE pr_fmt(fmt), ##__VA_ARGS__)
#define pr_warn(fmt, ...) \
	printk(KERN_WARNING pr_fmt(fmt), ##__VA_ARGS__)
#define pr_warn_once(fmt, ...)					\
	printk_once(KERN_WARNING pr_fmt(fmt), ##__VA_ARGS__)
#define pr_warn_ratelimited(fmt, ...)					\
	printk_ratelimited(KERN_WARNING pr_fmt(fmt), ##__VA_ARGS__)
#define print_hex_dump_bytes(prefix_str, prefix_type, buf, len)	\
	print_hex_dump_debug(prefix_str, prefix_type, 16, 1, buf, len, true)
#define print_hex_dump_debug(prefix_str, prefix_type, rowsize,	\
			     groupsize, buf, len, ascii)	\
	dynamic_hex_dump(prefix_str, prefix_type, rowsize,	\
			 groupsize, buf, len, ascii)
#define printk_deferred_once(fmt, ...)				\
({								\
	static bool __section(.data.once) __print_once;		\
	bool __ret_print_once = !__print_once;			\
								\
	if (!__print_once) {					\
		__print_once = true;				\
		printk_deferred(fmt, ##__VA_ARGS__);		\
	}							\
	unlikely(__ret_print_once);				\
})
#define printk_once(fmt, ...)					\
({								\
	static bool __section(.data.once) __print_once;		\
	bool __ret_print_once = !__print_once;			\
								\
	if (!__print_once) {					\
		__print_once = true;				\
		printk(fmt, ##__VA_ARGS__);			\
	}							\
	unlikely(__ret_print_once);				\
})
#define printk_ratelimit() __printk_ratelimit(__func__)
#define printk_ratelimited(fmt, ...)					\
({									\
	static DEFINE_RATELIMIT_STATE(_rs,				\
				      DEFAULT_RATELIMIT_INTERVAL,	\
				      DEFAULT_RATELIMIT_BURST);		\
									\
	if (__ratelimit(&_rs))						\
		printk(fmt, ##__VA_ARGS__);				\
})
#define DEFINE_DYNAMIC_DEBUG_METADATA(name, fmt)		\
	static struct _ddebug  __aligned(8)			\
	__attribute__((section("__verbose"))) name = {		\
		.modname = KBUILD_MODNAME,			\
		.function = __func__,				\
		.filename = "__FILE__",				\
		.format = (fmt),				\
		.lineno = "__LINE__",				\
		.flags = _DPRINTK_FLAGS_DEFAULT,		\
		_DPRINTK_KEY_INIT				\
	}
#define DYNAMIC_DEBUG_BRANCH(descriptor) \
	static_branch_unlikely(&descriptor.key.dd_key_false)
#define _DPRINTK_FLAGS_DEFAULT _DPRINTK_FLAGS_PRINT
#define _DPRINTK_KEY_INIT .key.dd_key_false = (STATIC_KEY_FALSE_INIT)

#define __dynamic_func_call(id, fmt, func, ...) do {	\
	DEFINE_DYNAMIC_DEBUG_METADATA(id, fmt);		\
	if (DYNAMIC_DEBUG_BRANCH(id))			\
		func(&id, ##__VA_ARGS__);		\
} while (0)
#define __dynamic_func_call_no_desc(id, fmt, func, ...) do {	\
	DEFINE_DYNAMIC_DEBUG_METADATA(id, fmt);			\
	if (DYNAMIC_DEBUG_BRANCH(id))				\
		func(__VA_ARGS__);				\
} while (0)
#define _dynamic_func_call(fmt, func, ...)				\
	__dynamic_func_call(__UNIQUE_ID(ddebug), fmt, func, ##__VA_ARGS__)
#define _dynamic_func_call_no_desc(fmt, func, ...)	\
	__dynamic_func_call_no_desc(__UNIQUE_ID(ddebug), fmt, func, ##__VA_ARGS__)
#define dynamic_dev_dbg(dev, fmt, ...)				\
	_dynamic_func_call(fmt,__dynamic_dev_dbg, 		\
			   dev, fmt, ##__VA_ARGS__)
#define dynamic_hex_dump(prefix_str, prefix_type, rowsize,		\
			 groupsize, buf, len, ascii)			\
	_dynamic_func_call_no_desc(__builtin_constant_p(prefix_str) ? prefix_str : "hexdump", \
				   print_hex_dump,			\
				   KERN_DEBUG, prefix_str, prefix_type,	\
				   rowsize, groupsize, buf, len, ascii)
#define dynamic_ibdev_dbg(dev, fmt, ...)			\
	_dynamic_func_call(fmt, __dynamic_ibdev_dbg,		\
			   dev, fmt, ##__VA_ARGS__)
#define dynamic_netdev_dbg(dev, fmt, ...)			\
	_dynamic_func_call(fmt, __dynamic_netdev_dbg,		\
			   dev, fmt, ##__VA_ARGS__)
#define dynamic_pr_debug(fmt, ...)				\
	_dynamic_func_call(fmt,	__dynamic_pr_debug,		\
			   pr_fmt(fmt), ##__VA_ARGS__)
#define ERESTART_RESTARTBLOCK 516 


#define __FORTIFY_INLINE extern __always_inline __attribute__((gnu_inline))
#define __RENAME(x) __asm__(#x)
#define memcat_p(a, b) ({					\
	BUILD_BUG_ON_MSG(!__same_type(*(a), *(b)),		\
			 "type mismatch in memcat_p()");	\
	(typeof(*a) *)__memcat_p((void **)(a), (void **)(b));	\
})
#define sysfs_match_string(_a, _s) __sysfs_match_string(_a, ARRAY_SIZE(_a), _s)

#define NULL ((void *)0)

#define offsetof(TYPE, MEMBER)	((size_t)&((TYPE *)0)->MEMBER)
#define offsetofend(TYPE, MEMBER) \
	(offsetof(TYPE, MEMBER)	+ sizeof_field(TYPE, MEMBER))
#define sizeof_field(TYPE, MEMBER) sizeof((((TYPE *)0)->MEMBER))
#define DECLARE_STATIC_KEY_FALSE(name)	\
	extern struct static_key_false name
#define DECLARE_STATIC_KEY_TRUE(name)	\
	extern struct static_key_true name
#define DEFINE_STATIC_KEY_ARRAY_FALSE(name, count)		\
	struct static_key_false name[count] = {			\
		[0 ... (count) - 1] = STATIC_KEY_FALSE_INIT,	\
	}
#define DEFINE_STATIC_KEY_ARRAY_TRUE(name, count)		\
	struct static_key_true name[count] = {			\
		[0 ... (count) - 1] = STATIC_KEY_TRUE_INIT,	\
	}
#define DEFINE_STATIC_KEY_FALSE(name)	\
	struct static_key_false name = STATIC_KEY_FALSE_INIT
#define DEFINE_STATIC_KEY_FALSE_RO(name)	\
	struct static_key_false name __ro_after_init = STATIC_KEY_FALSE_INIT
#define DEFINE_STATIC_KEY_TRUE(name)	\
	struct static_key_true name = STATIC_KEY_TRUE_INIT
#define DEFINE_STATIC_KEY_TRUE_RO(name)	\
	struct static_key_true name __ro_after_init = STATIC_KEY_TRUE_INIT
#define STATIC_KEY_CHECK_USE(key) WARN(!static_key_initialized,		      \
				    "%s(): static key '%pS' used before call to jump_label_init()", \
				    __func__, (key))
#define STATIC_KEY_FALSE_INIT (struct static_key_false){ .key = STATIC_KEY_INIT_FALSE, }
#define STATIC_KEY_INIT STATIC_KEY_INIT_FALSE
#define STATIC_KEY_TRUE_INIT  (struct static_key_true) { .key = STATIC_KEY_INIT_TRUE,  }

#define jump_label_enabled static_key_enabled
#define static_branch_dec(x)		static_key_slow_dec(&(x)->key)
#define static_branch_dec_cpuslocked(x)	static_key_slow_dec_cpuslocked(&(x)->key)
#define static_branch_disable(x)		static_key_disable(&(x)->key)
#define static_branch_disable_cpuslocked(x)	static_key_disable_cpuslocked(&(x)->key)
#define static_branch_enable(x)			static_key_enable(&(x)->key)
#define static_branch_enable_cpuslocked(x)	static_key_enable_cpuslocked(&(x)->key)
#define static_branch_inc(x)		static_key_slow_inc(&(x)->key)
#define static_branch_inc_cpuslocked(x)	static_key_slow_inc_cpuslocked(&(x)->key)
#define static_branch_likely(x)							\
({										\
	bool branch;								\
	if (__builtin_types_compatible_p(typeof(*x), struct static_key_true))	\
		branch = !arch_static_branch(&(x)->key, true);			\
	else if (__builtin_types_compatible_p(typeof(*x), struct static_key_false)) \
		branch = !arch_static_branch_jump(&(x)->key, true);		\
	else									\
		branch = ____wrong_branch_error();				\
	likely(branch);								\
})
#define static_branch_unlikely(x)						\
({										\
	bool branch;								\
	if (__builtin_types_compatible_p(typeof(*x), struct static_key_true))	\
		branch = arch_static_branch_jump(&(x)->key, false);		\
	else if (__builtin_types_compatible_p(typeof(*x), struct static_key_false)) \
		branch = arch_static_branch(&(x)->key, false);			\
	else									\
		branch = ____wrong_branch_error();				\
	unlikely(branch);							\
})
#define static_key_disable_cpuslocked(k)	static_key_disable((k))
#define static_key_enable_cpuslocked(k)		static_key_enable((k))
#define static_key_enabled(x)							\
({										\
	if (!__builtin_types_compatible_p(typeof(*x), struct static_key) &&	\
	    !__builtin_types_compatible_p(typeof(*x), struct static_key_true) &&\
	    !__builtin_types_compatible_p(typeof(*x), struct static_key_false))	\
		____wrong_branch_error();					\
	static_key_count((struct static_key *)x) > 0;				\
})
#define static_key_slow_dec_cpuslocked(key) static_key_slow_dec(key)
#define static_key_slow_inc_cpuslocked(key) static_key_slow_inc(key)

#define __atomic_op_acquire(op, args...)				\
({									\
	typeof(op##_relaxed(args)) __ret  = op##_relaxed(args);		\
	__atomic_acquire_fence();					\
	__ret;								\
})
#define __atomic_op_fence(op, args...)					\
({									\
	typeof(op##_relaxed(args)) __ret;				\
	__atomic_pre_full_fence();					\
	__ret = op##_relaxed(args);					\
	__atomic_post_full_fence();					\
	__ret;								\
})
#define __atomic_op_release(op, args...)				\
({									\
	__atomic_release_fence();					\
	op##_relaxed(args);						\
})
#define ATOMIC_LONG_INIT(i)		ATOMIC64_INIT(i)


#define atomic64_add_negative atomic64_add_negative
#define atomic64_add_return atomic64_add_return
#define atomic64_add_return_acquire atomic64_add_return
#define atomic64_add_return_relaxed atomic64_add_return
#define atomic64_add_return_release atomic64_add_return
#define atomic64_add_unless atomic64_add_unless
#define atomic64_andnot atomic64_andnot
#define atomic64_cmpxchg atomic64_cmpxchg
#define atomic64_cmpxchg_acquire atomic64_cmpxchg
#define atomic64_cmpxchg_relaxed atomic64_cmpxchg
#define atomic64_cmpxchg_release atomic64_cmpxchg
#define atomic64_cond_read_acquire(v, c) smp_cond_load_acquire(&(v)->counter, (c))
#define atomic64_cond_read_relaxed(v, c) smp_cond_load_relaxed(&(v)->counter, (c))
#define atomic64_dec atomic64_dec
#define atomic64_dec_and_test atomic64_dec_and_test
#define atomic64_dec_if_positive atomic64_dec_if_positive
#define atomic64_dec_return atomic64_dec_return
#define atomic64_dec_return_acquire atomic64_dec_return
#define atomic64_dec_return_relaxed atomic64_dec_return
#define atomic64_dec_return_release atomic64_dec_return
#define atomic64_dec_unless_positive atomic64_dec_unless_positive
#define atomic64_fetch_add atomic64_fetch_add
#define atomic64_fetch_add_acquire atomic64_fetch_add
#define atomic64_fetch_add_relaxed atomic64_fetch_add
#define atomic64_fetch_add_release atomic64_fetch_add
#define atomic64_fetch_add_unless atomic64_fetch_add_unless
#define atomic64_fetch_and atomic64_fetch_and
#define atomic64_fetch_and_acquire atomic64_fetch_and
#define atomic64_fetch_and_relaxed atomic64_fetch_and
#define atomic64_fetch_and_release atomic64_fetch_and
#define atomic64_fetch_andnot atomic64_fetch_andnot
#define atomic64_fetch_andnot_acquire atomic64_fetch_andnot
#define atomic64_fetch_andnot_relaxed atomic64_fetch_andnot
#define atomic64_fetch_andnot_release atomic64_fetch_andnot
#define atomic64_fetch_dec atomic64_fetch_dec
#define atomic64_fetch_dec_acquire atomic64_fetch_dec
#define atomic64_fetch_dec_relaxed atomic64_fetch_dec
#define atomic64_fetch_dec_release atomic64_fetch_dec
#define atomic64_fetch_inc atomic64_fetch_inc
#define atomic64_fetch_inc_acquire atomic64_fetch_inc
#define atomic64_fetch_inc_relaxed atomic64_fetch_inc
#define atomic64_fetch_inc_release atomic64_fetch_inc
#define atomic64_fetch_or atomic64_fetch_or
#define atomic64_fetch_or_acquire atomic64_fetch_or
#define atomic64_fetch_or_relaxed atomic64_fetch_or
#define atomic64_fetch_or_release atomic64_fetch_or
#define atomic64_fetch_sub atomic64_fetch_sub
#define atomic64_fetch_sub_acquire atomic64_fetch_sub
#define atomic64_fetch_sub_relaxed atomic64_fetch_sub
#define atomic64_fetch_sub_release atomic64_fetch_sub
#define atomic64_fetch_xor atomic64_fetch_xor
#define atomic64_fetch_xor_acquire atomic64_fetch_xor
#define atomic64_fetch_xor_relaxed atomic64_fetch_xor
#define atomic64_fetch_xor_release atomic64_fetch_xor
#define atomic64_inc atomic64_inc
#define atomic64_inc_and_test atomic64_inc_and_test
#define atomic64_inc_not_zero atomic64_inc_not_zero
#define atomic64_inc_return atomic64_inc_return
#define atomic64_inc_return_acquire atomic64_inc_return
#define atomic64_inc_return_relaxed atomic64_inc_return
#define atomic64_inc_return_release atomic64_inc_return
#define atomic64_inc_unless_negative atomic64_inc_unless_negative
#define atomic64_read_acquire atomic64_read_acquire
#define atomic64_set_release atomic64_set_release
#define atomic64_sub_and_test atomic64_sub_and_test
#define atomic64_sub_return atomic64_sub_return
#define atomic64_sub_return_acquire atomic64_sub_return
#define atomic64_sub_return_relaxed atomic64_sub_return
#define atomic64_sub_return_release atomic64_sub_return
#define atomic64_try_cmpxchg atomic64_try_cmpxchg
#define atomic64_try_cmpxchg_acquire atomic64_try_cmpxchg
#define atomic64_try_cmpxchg_relaxed atomic64_try_cmpxchg
#define atomic64_try_cmpxchg_release atomic64_try_cmpxchg
#define atomic64_xchg atomic64_xchg
#define atomic64_xchg_acquire atomic64_xchg
#define atomic64_xchg_relaxed atomic64_xchg
#define atomic64_xchg_release atomic64_xchg
#define atomic_add_negative atomic_add_negative
#define atomic_add_return atomic_add_return
#define atomic_add_return_acquire atomic_add_return
#define atomic_add_return_relaxed atomic_add_return
#define atomic_add_return_release atomic_add_return
#define atomic_add_unless atomic_add_unless
#define atomic_andnot atomic_andnot
#define atomic_cmpxchg atomic_cmpxchg
#define atomic_cmpxchg_acquire atomic_cmpxchg
#define atomic_cmpxchg_relaxed atomic_cmpxchg
#define atomic_cmpxchg_release atomic_cmpxchg
#define atomic_cond_read_acquire(v, c) smp_cond_load_acquire(&(v)->counter, (c))
#define atomic_cond_read_relaxed(v, c) smp_cond_load_relaxed(&(v)->counter, (c))
#define atomic_dec atomic_dec
#define atomic_dec_and_test atomic_dec_and_test
#define atomic_dec_if_positive atomic_dec_if_positive
#define atomic_dec_return atomic_dec_return
#define atomic_dec_return_acquire atomic_dec_return
#define atomic_dec_return_relaxed atomic_dec_return
#define atomic_dec_return_release atomic_dec_return
#define atomic_dec_unless_positive atomic_dec_unless_positive
#define atomic_fetch_add atomic_fetch_add
#define atomic_fetch_add_acquire atomic_fetch_add
#define atomic_fetch_add_relaxed atomic_fetch_add
#define atomic_fetch_add_release atomic_fetch_add
#define atomic_fetch_add_unless atomic_fetch_add_unless
#define atomic_fetch_and atomic_fetch_and
#define atomic_fetch_and_acquire atomic_fetch_and
#define atomic_fetch_and_relaxed atomic_fetch_and
#define atomic_fetch_and_release atomic_fetch_and
#define atomic_fetch_andnot atomic_fetch_andnot
#define atomic_fetch_andnot_acquire atomic_fetch_andnot
#define atomic_fetch_andnot_relaxed atomic_fetch_andnot
#define atomic_fetch_andnot_release atomic_fetch_andnot
#define atomic_fetch_dec atomic_fetch_dec
#define atomic_fetch_dec_acquire atomic_fetch_dec
#define atomic_fetch_dec_relaxed atomic_fetch_dec
#define atomic_fetch_dec_release atomic_fetch_dec
#define atomic_fetch_inc atomic_fetch_inc
#define atomic_fetch_inc_acquire atomic_fetch_inc
#define atomic_fetch_inc_relaxed atomic_fetch_inc
#define atomic_fetch_inc_release atomic_fetch_inc
#define atomic_fetch_or atomic_fetch_or
#define atomic_fetch_or_acquire atomic_fetch_or
#define atomic_fetch_or_relaxed atomic_fetch_or
#define atomic_fetch_or_release atomic_fetch_or
#define atomic_fetch_sub atomic_fetch_sub
#define atomic_fetch_sub_acquire atomic_fetch_sub
#define atomic_fetch_sub_relaxed atomic_fetch_sub
#define atomic_fetch_sub_release atomic_fetch_sub
#define atomic_fetch_xor atomic_fetch_xor
#define atomic_fetch_xor_acquire atomic_fetch_xor
#define atomic_fetch_xor_relaxed atomic_fetch_xor
#define atomic_fetch_xor_release atomic_fetch_xor
#define atomic_inc atomic_inc
#define atomic_inc_and_test atomic_inc_and_test
#define atomic_inc_not_zero atomic_inc_not_zero
#define atomic_inc_return atomic_inc_return
#define atomic_inc_return_acquire atomic_inc_return
#define atomic_inc_return_relaxed atomic_inc_return
#define atomic_inc_return_release atomic_inc_return
#define atomic_inc_unless_negative atomic_inc_unless_negative
#define atomic_read_acquire atomic_read_acquire
#define atomic_set_release atomic_set_release
#define atomic_sub_and_test atomic_sub_and_test
#define atomic_sub_return atomic_sub_return
#define atomic_sub_return_acquire atomic_sub_return
#define atomic_sub_return_relaxed atomic_sub_return
#define atomic_sub_return_release atomic_sub_return
#define atomic_try_cmpxchg atomic_try_cmpxchg
#define atomic_try_cmpxchg_acquire atomic_try_cmpxchg
#define atomic_try_cmpxchg_relaxed atomic_try_cmpxchg
#define atomic_try_cmpxchg_release atomic_try_cmpxchg
#define atomic_xchg atomic_xchg
#define atomic_xchg_acquire atomic_xchg
#define atomic_xchg_relaxed atomic_xchg
#define atomic_xchg_release atomic_xchg
#define cmpxchg(...) \
	__atomic_op_fence(cmpxchg, __VA_ARGS__)
#define cmpxchg64(...) \
	__atomic_op_fence(cmpxchg64, __VA_ARGS__)
#define cmpxchg64_acquire(...) \
	__atomic_op_acquire(cmpxchg64, __VA_ARGS__)
#define cmpxchg64_release(...) \
	__atomic_op_release(cmpxchg64, __VA_ARGS__)
#define cmpxchg_acquire(...) \
	__atomic_op_acquire(cmpxchg, __VA_ARGS__)
#define cmpxchg_release(...) \
	__atomic_op_release(cmpxchg, __VA_ARGS__)
#define xchg(...) \
	__atomic_op_fence(xchg, __VA_ARGS__)
#define xchg_acquire(...) \
	__atomic_op_acquire(xchg, __VA_ARGS__)
#define xchg_release(...) \
	__atomic_op_release(xchg, __VA_ARGS__)
#define ATOMIC64_FETCH_OP(op)						\
extern s64 atomic64_fetch_##op(s64 a, atomic64_t *v);
#define ATOMIC64_INIT(i)	{ (i) }
#define ATOMIC64_OP(op)							\
extern void	 atomic64_##op(s64 a, atomic64_t *v);
#define ATOMIC64_OPS(op)	ATOMIC64_OP(op) ATOMIC64_OP_RETURN(op) ATOMIC64_FETCH_OP(op)
#define ATOMIC64_OP_RETURN(op)						\
extern s64 atomic64_##op##_return(s64 a, atomic64_t *v);

#define INTERNODE_CACHE_SHIFT L1_CACHE_SHIFT
#define L1_CACHE_ALIGN(x) __ALIGN_KERNEL(x, L1_CACHE_BYTES)
#define SMP_CACHE_BYTES L1_CACHE_BYTES

#define ____cacheline_aligned __attribute__((__aligned__(SMP_CACHE_BYTES)))
#define ____cacheline_aligned_in_smp ____cacheline_aligned
#define ____cacheline_internodealigned_in_smp \
	__attribute__((__aligned__(1 << (INTERNODE_CACHE_SHIFT))))
#define __cacheline_aligned_in_smp __cacheline_aligned

#define __ro_after_init __attribute__((__section__(".data..ro_after_init")))
#define cache_line_size()	L1_CACHE_BYTES
#define CPP_ASMLINKAGE extern "C"
#define SYSCALL_ALIAS(alias, name) asm(			\
	".globl " __stringify(alias) "\n\t"		\
	".set   " __stringify(alias) ","		\
		  __stringify(name))

#define asmlinkage CPP_ASMLINKAGE
# define asmlinkage_protect(n, ret, args...)	do { } while (0)
#define cond_syscall(x)	asm(				\
	".weak " __stringify(x) "\n\t"			\
	".set  " __stringify(x) ","			\
		 __stringify(sys_ni_syscall))
#define EXPORT_SYMBOL(sym)		_EXPORT_SYMBOL(sym, "")
#define EXPORT_SYMBOL_GPL(sym)		_EXPORT_SYMBOL(sym, "_gpl")
#define EXPORT_SYMBOL_GPL_FUTURE(sym)	_EXPORT_SYMBOL(sym, "_gpl_future")
#define EXPORT_SYMBOL_NS(sym, ns)	__EXPORT_SYMBOL(sym, "", #ns)
#define EXPORT_SYMBOL_NS_GPL(sym, ns)	__EXPORT_SYMBOL(sym, "_gpl", #ns)
#define EXPORT_UNUSED_SYMBOL(sym)	_EXPORT_SYMBOL(sym, "_unused")
#define EXPORT_UNUSED_SYMBOL_GPL(sym)	_EXPORT_SYMBOL(sym, "_unused_gpl")
#define THIS_MODULE (&__this_module)

#define __CRC_SYMBOL(sym, sec)						\
	asm("	.section \"___kcrctab" sec "+" #sym "\", \"a\"	\n"	\
	    "	.weak	__crc_" #sym "				\n"	\
	    "	.long	__crc_" #sym " - .			\n"	\
	    "	.previous					\n")
#define __EXPORT_SYMBOL(sym, sec, ns)
#define __KSYMTAB_ENTRY(sym, sec)					\
	__ADDRESSABLE(sym)						\
	asm("	.section \"___ksymtab" sec "+" #sym "\", \"a\"	\n"	\
	    "	.balign	4					\n"	\
	    "__ksymtab_" #sym ":				\n"	\
	    "	.long	" #sym "- .				\n"	\
	    "	.long	__kstrtab_" #sym "- .			\n"	\
	    "	.long	__kstrtabns_" #sym "- .			\n"	\
	    "	.previous					\n")
#define ___EXPORT_SYMBOL(sym, sec, ns)	__GENKSYMS_EXPORT_SYMBOL(sym)
#define ___cond_export_sym(sym, sec, ns, enabled)			\
	__cond_export_sym_##enabled(sym, sec, ns)
#define __cond_export_sym(sym, sec, ns, conf)				\
	___cond_export_sym(sym, sec, ns, conf)
#define __cond_export_sym_1(sym, sec, ns) ___EXPORT_SYMBOL(sym, sec, ns)
#define __ksym_marker(sym)	\
	static int __ksym_marker_##sym[0] __section(".discard.ksym") __used

#define __stringify_1(x...)	#x


#define __MEMINIT        .section	".meminit.text", "ax"
#define __MEMINITDATA    .section	".meminit.data", "aw"
#define __MEMINITRODATA  .section	".meminit.rodata", "a"
#define __REF            .section       ".ref.text", "ax"
#define __REFCONST       .section       ".ref.rodata", "a"
#define __REFDATA        .section       ".ref.data", "aw"
#define ___define_initcall(fn, id, __sec)			\
	__ADDRESSABLE(fn)					\
	asm(".section	\"" #__sec ".init\", \"a\"	\n"	\
	"__initcall_" #fn #id ":			\n"	\
	    ".long	" #fn " - .			\n"	\
	    ".previous					\n");
#define __define_initcall(fn, id) ___define_initcall(fn, id, .initcall##id)
#define __exit          __section(.exit.text) __exitused __cold notrace
#define __exit_p(x) x
#define __exitcall(fn)						\
	static exitcall_t __exitcall_##fn __exit_call = fn
#define __exitused  __used
#define __initcall(fn) device_initcall(fn)
#define __memexit        __section(.memexit.text) __exitused __cold notrace
#define __memexitconst   __section(.memexit.rodata)
#define __memexitdata    __section(.memexit.data)
#define __meminit        __section(.meminit.text) __cold notrace \
						  __latent_entropy
#define __meminitconst   __section(.meminit.rodata)
#define __meminitdata    __section(.meminit.data)
#define __noinitretpoline __noretpoline
#define __nosavedata __section(.data..nosave)
#define __ref            __section(.ref.text) noinline
#define __refconst       __section(.ref.rodata)
#define __refdata        __section(.ref.data)
#define __setup(str, fn)						\
	__setup_param(str, fn, fn, 0)
#define __setup_param(str, unique_id, fn, early)			\
	static const char __setup_str_##unique_id[] __initconst		\
		__aligned(1) = str; 					\
	static struct obs_kernel_param __setup_##unique_id		\
		__used __section(.init.setup)				\
		__attribute__((aligned((sizeof(long)))))		\
		= { __setup_str_##unique_id, fn, early }
#define arch_initcall(fn)		__define_initcall(fn, 3)
#define arch_initcall_sync(fn)		__define_initcall(fn, 3s)
#define console_initcall(fn)	___define_initcall(fn,, .con_initcall)
#define core_initcall(fn)		__define_initcall(fn, 1)
#define core_initcall_sync(fn)		__define_initcall(fn, 1s)
#define device_initcall(fn)		__define_initcall(fn, 6)
#define device_initcall_sync(fn)	__define_initcall(fn, 6s)
#define early_initcall(fn)		__define_initcall(fn, early)
#define early_param(str, fn)						\
	__setup_param(str, fn, fn, 1)
#define early_param_on_off(str_on, str_off, var, config)		\
									\
	int var = IS_ENABLED(config);					\
									\
	static int __init parse_##var##_on(char *arg)			\
	{								\
		var = 1;						\
		return 0;						\
	}								\
	__setup_param(str_on, parse_##var##_on, parse_##var##_on, 1);	\
									\
	static int __init parse_##var##_off(char *arg)			\
	{								\
		var = 0;						\
		return 0;						\
	}								\
	__setup_param(str_off, parse_##var##_off, parse_##var##_off, 1)
#define fs_initcall(fn)			__define_initcall(fn, 5)
#define fs_initcall_sync(fn)		__define_initcall(fn, 5s)
#define late_initcall(fn)		__define_initcall(fn, 7)
#define late_initcall_sync(fn)		__define_initcall(fn, 7s)
#define postcore_initcall(fn)		__define_initcall(fn, 2)
#define postcore_initcall_sync(fn)	__define_initcall(fn, 2s)
#define pure_initcall(fn)		__define_initcall(fn, 0)
#define rootfs_initcall(fn)		__define_initcall(fn, rootfs)
#define subsys_initcall(fn)		__define_initcall(fn, 4)
#define subsys_initcall_sync(fn)	__define_initcall(fn, 4s)

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

#define bits_per(n)				\
(						\
	__builtin_constant_p(n) ? (		\
		((n) == 0 || (n) == 1)		\
			? 1 : ilog2(n) + 1	\
	) :					\
	__bits_per(n)				\
)
#define const_ilog2(n)				\
(						\
	__builtin_constant_p(n) ? (		\
		(n) < 2 ? 0 :			\
		(n) & (1ULL << 63) ? 63 :	\
		(n) & (1ULL << 62) ? 62 :	\
		(n) & (1ULL << 61) ? 61 :	\
		(n) & (1ULL << 60) ? 60 :	\
		(n) & (1ULL << 59) ? 59 :	\
		(n) & (1ULL << 58) ? 58 :	\
		(n) & (1ULL << 57) ? 57 :	\
		(n) & (1ULL << 56) ? 56 :	\
		(n) & (1ULL << 55) ? 55 :	\
		(n) & (1ULL << 54) ? 54 :	\
		(n) & (1ULL << 53) ? 53 :	\
		(n) & (1ULL << 52) ? 52 :	\
		(n) & (1ULL << 51) ? 51 :	\
		(n) & (1ULL << 50) ? 50 :	\
		(n) & (1ULL << 49) ? 49 :	\
		(n) & (1ULL << 48) ? 48 :	\
		(n) & (1ULL << 47) ? 47 :	\
		(n) & (1ULL << 46) ? 46 :	\
		(n) & (1ULL << 45) ? 45 :	\
		(n) & (1ULL << 44) ? 44 :	\
		(n) & (1ULL << 43) ? 43 :	\
		(n) & (1ULL << 42) ? 42 :	\
		(n) & (1ULL << 41) ? 41 :	\
		(n) & (1ULL << 40) ? 40 :	\
		(n) & (1ULL << 39) ? 39 :	\
		(n) & (1ULL << 38) ? 38 :	\
		(n) & (1ULL << 37) ? 37 :	\
		(n) & (1ULL << 36) ? 36 :	\
		(n) & (1ULL << 35) ? 35 :	\
		(n) & (1ULL << 34) ? 34 :	\
		(n) & (1ULL << 33) ? 33 :	\
		(n) & (1ULL << 32) ? 32 :	\
		(n) & (1ULL << 31) ? 31 :	\
		(n) & (1ULL << 30) ? 30 :	\
		(n) & (1ULL << 29) ? 29 :	\
		(n) & (1ULL << 28) ? 28 :	\
		(n) & (1ULL << 27) ? 27 :	\
		(n) & (1ULL << 26) ? 26 :	\
		(n) & (1ULL << 25) ? 25 :	\
		(n) & (1ULL << 24) ? 24 :	\
		(n) & (1ULL << 23) ? 23 :	\
		(n) & (1ULL << 22) ? 22 :	\
		(n) & (1ULL << 21) ? 21 :	\
		(n) & (1ULL << 20) ? 20 :	\
		(n) & (1ULL << 19) ? 19 :	\
		(n) & (1ULL << 18) ? 18 :	\
		(n) & (1ULL << 17) ? 17 :	\
		(n) & (1ULL << 16) ? 16 :	\
		(n) & (1ULL << 15) ? 15 :	\
		(n) & (1ULL << 14) ? 14 :	\
		(n) & (1ULL << 13) ? 13 :	\
		(n) & (1ULL << 12) ? 12 :	\
		(n) & (1ULL << 11) ? 11 :	\
		(n) & (1ULL << 10) ? 10 :	\
		(n) & (1ULL <<  9) ?  9 :	\
		(n) & (1ULL <<  8) ?  8 :	\
		(n) & (1ULL <<  7) ?  7 :	\
		(n) & (1ULL <<  6) ?  6 :	\
		(n) & (1ULL <<  5) ?  5 :	\
		(n) & (1ULL <<  4) ?  4 :	\
		(n) & (1ULL <<  3) ?  3 :	\
		(n) & (1ULL <<  2) ?  2 :	\
		1) :				\
	-1)
#define ilog2(n) \
( \
	__builtin_constant_p(n) ?	\
	const_ilog2(n) :		\
	(sizeof(n) <= 4) ?		\
	__ilog2_u32(n) :		\
	__ilog2_u64(n)			\
 )
#define order_base_2(n)				\
(						\
	__builtin_constant_p(n) ? (		\
		((n) == 0 || (n) == 1) ? 0 :	\
		ilog2((n) - 1) + 1) :		\
	__order_base_2(n)			\
)
#define rounddown_pow_of_two(n)			\
(						\
	__builtin_constant_p(n) ? (		\
		(1UL << ilog2(n))) :		\
	__rounddown_pow_of_two(n)		\
 )
#define roundup_pow_of_two(n)			\
(						\
	__builtin_constant_p(n) ? (		\
		(n == 1) ? 1 :			\
		(1UL << (ilog2((n) - 1) + 1))	\
				   ) :		\
	__roundup_pow_of_two(n)			\
 )
#define BITS_PER_TYPE(type)	(sizeof(type) * BITS_PER_BYTE)
#define BITS_TO_BYTES(nr)	DIV_ROUND_UP(nr, BITS_PER_TYPE(char))
#define BITS_TO_LONGS(nr)	DIV_ROUND_UP(nr, BITS_PER_TYPE(long))
#define BITS_TO_U32(nr)		DIV_ROUND_UP(nr, BITS_PER_TYPE(u32))
#define BITS_TO_U64(nr)		DIV_ROUND_UP(nr, BITS_PER_TYPE(u64))

#  define aligned_byte_mask(n) (~0xffUL << (BITS_PER_LONG - 8 - 8*(n)))
#define bit_clear_unless(ptr, clear, test)	\
({								\
	const typeof(*(ptr)) clear__ = (clear), test__ = (test);\
	typeof(*(ptr)) old__, new__;				\
								\
	do {							\
		old__ = READ_ONCE(*(ptr));			\
		new__ = old__ & ~clear__;			\
	} while (!(old__ & test__) &&				\
		 cmpxchg(ptr, old__, new__) != old__);		\
								\
	!(old__ & test__);					\
})
#define for_each_clear_bit(bit, addr, size) \
	for ((bit) = find_first_zero_bit((addr), (size));	\
	     (bit) < (size);					\
	     (bit) = find_next_zero_bit((addr), (size), (bit) + 1))
#define for_each_clear_bit_from(bit, addr, size) \
	for ((bit) = find_next_zero_bit((addr), (size), (bit));	\
	     (bit) < (size);					\
	     (bit) = find_next_zero_bit((addr), (size), (bit) + 1))
#define for_each_set_bit(bit, addr, size) \
	for ((bit) = find_first_bit((addr), (size));		\
	     (bit) < (size);					\
	     (bit) = find_next_bit((addr), (size), (bit) + 1))
#define for_each_set_bit_from(bit, addr, size) \
	for ((bit) = find_next_bit((addr), (size), (bit));	\
	     (bit) < (size);					\
	     (bit) = find_next_bit((addr), (size), (bit) + 1))
#define for_each_set_clump8(start, clump, bits, size) \
	for ((start) = find_first_clump8(&(clump), (bits), (size)); \
	     (start) < (size); \
	     (start) = find_next_clump8(&(clump), (bits), (size), (start) + 8))
#define set_mask_bits(ptr, mask, bits)	\
({								\
	const typeof(*(ptr)) mask__ = (mask), bits__ = (bits);	\
	typeof(*(ptr)) old__, new__;				\
								\
	do {							\
		old__ = READ_ONCE(*(ptr));			\
		new__ = (old__ & ~mask__) | bits__;		\
	} while (cmpxchg(ptr, old__, new__) != old__);		\
								\
	old__;							\
})
#define BIT(nr)			(UL(1) << (nr))
#define BIT_MASK(nr)		(UL(1) << ((nr) % BITS_PER_LONG))
#define BIT_ULL(nr)		(ULL(1) << (nr))
#define BIT_ULL_MASK(nr)	(ULL(1) << ((nr) % BITS_PER_LONG_LONG))
#define BIT_ULL_WORD(nr)	((nr) / BITS_PER_LONG_LONG)
#define BIT_WORD(nr)		((nr) / BITS_PER_LONG)
#define GENMASK(h, l) \
	(((~UL(0)) - (UL(1) << (l)) + 1) & \
	 (~UL(0) >> (BITS_PER_LONG - 1 - (h))))
#define GENMASK_ULL(h, l) \
	(((~ULL(0)) - (ULL(1) << (l)) + 1) & \
	 (~ULL(0) >> (BITS_PER_LONG_LONG - 1 - (h))))

#define UL(x)		(_UL(x))
#define ULL(x)		(_ULL(x))

#define _AT(T,X)	((T)(X))
#define _BITUL(x)	(_UL(1) << (x))
#define _BITULL(x)	(_ULL(1) << (x))

#define _UL(x)		(_AC(x, UL))
#define _ULL(x)		(_AC(x, ULL))
#define __AC(X,Y)	(X##Y)

#define ARG_MAX       131072	
#define LINK_MAX         127	
#define MAX_CANON        255	
#define MAX_INPUT        255	
#define NAME_MAX         255	
#define NGROUPS_MAX    65536	
#define PATH_MAX        4096	
#define PIPE_BUF        4096	
#define XATTR_LIST_MAX 65536	
#define XATTR_NAME_MAX   255	
#define XATTR_SIZE_MAX 65536	

#define OSQ_LOCK_UNLOCKED { ATOMIC_INIT(OSQ_UNLOCKED_VAL) }
#define OSQ_UNLOCKED_VAL (0)

#define LOCK_CONTENDED(_lock, try, lock)			\
do {								\
	if (!try(_lock)) {					\
		lock_contended(&(_lock)->dep_map, _RET_IP_);	\
		lock(_lock);					\
	}							\
	lock_acquired(&(_lock)->dep_map, _RET_IP_);			\
} while (0)
#define LOCK_CONTENDED_FLAGS(_lock, try, lock, lockfl, flags) \
	LOCK_CONTENDED((_lock), (try), (lock))
#define LOCK_CONTENDED_RETURN(_lock, try, lock)			\
({								\
	int ____err = 0;					\
	if (!try(_lock)) {					\
		lock_contended(&(_lock)->dep_map, _RET_IP_);	\
		____err = lock(_lock);				\
	}							\
	if (!____err)						\
		lock_acquired(&(_lock)->dep_map, _RET_IP_);	\
	____err;						\
})
#define MAX_LOCKDEP_KEYS		(1UL << MAX_LOCKDEP_KEYS_BITS)
#define NIL_COOKIE (struct pin_cookie){ .val = 0U, }
#define STATIC_LOCKDEP_MAP_INIT(_name, _key) \
	{ .name = (_name), .key = (void *)(_key), }

# define lock_acquire(l, s, t, r, c, n, i)	do { } while (0)
#define lock_acquire_exclusive(l, s, t, n, i)		lock_acquire(l, s, t, 0, 1, n, i)
#define lock_acquire_shared(l, s, t, n, i)		lock_acquire(l, s, t, 1, 1, n, i)
#define lock_acquire_shared_recursive(l, s, t, n, i)	lock_acquire(l, s, t, 2, 1, n, i)
#define lock_acquired(lockdep_map, ip) do {} while (0)
#define lock_contended(lockdep_map, ip) do {} while (0)
# define lock_downgrade(l, i)			do { } while (0)
#define lock_map_acquire(l)			lock_acquire_exclusive(l, 0, 0, NULL, _THIS_IP_)
#define lock_map_acquire_read(l)		lock_acquire_shared_recursive(l, 0, 0, NULL, _THIS_IP_)
#define lock_map_acquire_tryread(l)		lock_acquire_shared_recursive(l, 0, 1, NULL, _THIS_IP_)
#define lock_map_release(l)			lock_release(l, _THIS_IP_)
# define lock_release(l, i)			do { } while (0)
# define lock_set_class(l, n, k, s, i)		do { } while (0)
# define lock_set_subclass(l, s, i)		do { } while (0)
#define lockdep_assert_held(l)	do {				\
		WARN_ON(debug_locks && !lockdep_is_held(l));	\
	} while (0)
#define lockdep_assert_held_once(l)	do {				\
		WARN_ON_ONCE(debug_locks && !lockdep_is_held(l));	\
	} while (0)
#define lockdep_assert_held_read(l)	do {				\
		WARN_ON(debug_locks && !lockdep_is_held_type(l, 1));	\
	} while (0)
#define lockdep_assert_held_write(l)	do {			\
		WARN_ON(debug_locks && !lockdep_is_held_type(l, 0));	\
	} while (0)
# define lockdep_assert_in_irq() do { } while (0)
# define lockdep_assert_irqs_disabled() do { } while (0)
# define lockdep_assert_irqs_enabled() do { } while (0)
#define lockdep_depth(tsk)	(0)
# define lockdep_free_key_range(start, size)	do { } while (0)
# define lockdep_init()				do { } while (0)
# define lockdep_init_map(lock, name, key, sub) \
		do { (void)(name); (void)(key); } while (0)
#define lockdep_init_map_crosslock(m, n, k, s) do {} while (0)
#define lockdep_is_held(lock)		lock_is_held(&(lock)->dep_map)
#define lockdep_is_held_type(lock, r)	lock_is_held_type(&(lock)->dep_map, (r))
#define lockdep_match_class(lock, key) lockdep_match_key(&(lock)->dep_map, key)
#define lockdep_pin_lock(l)	lock_pin_lock(&(l)->dep_map)
#define lockdep_recursing(tsk)	((tsk)->lockdep_recursion)
#define lockdep_repin_lock(l,c)	lock_repin_lock(&(l)->dep_map, (c))
# define lockdep_reset()		do { debug_locks = 1; } while (0)
# define lockdep_set_class(lock, key)		do { (void)(key); } while (0)
# define lockdep_set_class_and_name(lock, key, name) \
		do { (void)(key); (void)(name); } while (0)
#define lockdep_set_class_and_subclass(lock, key, sub) \
		lockdep_init_map(&(lock)->dep_map, #key, key, sub)
#define lockdep_set_novalidate_class(lock) \
	lockdep_set_class_and_name(lock, &__lockdep_no_validate__, #lock)
#define lockdep_set_subclass(lock, sub)	\
		lockdep_init_map(&(lock)->dep_map, #lock, \
				 (lock)->dep_map.key, sub)
# define lockdep_sys_exit() 			do { } while (0)
#define lockdep_unpin_lock(l,c)	lock_unpin_lock(&(l)->dep_map, (c))
# define might_lock(lock) 						\
do {									\
	typecheck(struct lockdep_map *, &(lock)->dep_map);		\
	lock_acquire(&(lock)->dep_map, 0, 0, 0, 1, NULL, _THIS_IP_);	\
	lock_release(&(lock)->dep_map, _THIS_IP_);			\
} while (0)
# define might_lock_nested(lock, subclass) 				\
do {									\
	typecheck(struct lockdep_map *, &(lock)->dep_map);		\
	lock_acquire(&(lock)->dep_map, subclass, 0, 1, 1, NULL,		\
		     _THIS_IP_);					\
	lock_release(&(lock)->dep_map, _THIS_IP_);			\
} while (0)
# define might_lock_read(lock) 						\
do {									\
	typecheck(struct lockdep_map *, &(lock)->dep_map);		\
	lock_acquire(&(lock)->dep_map, 0, 0, 1, 1, NULL, _THIS_IP_);	\
	lock_release(&(lock)->dep_map, _THIS_IP_);			\
} while (0)
#define mutex_acquire(l, s, t, i)		lock_acquire_exclusive(l, s, t, NULL, i)
#define mutex_acquire_nest(l, s, t, n, i)	lock_acquire_exclusive(l, s, t, n, i)
#define mutex_release(l, i)			lock_release(l, i)
#define rwlock_acquire(l, s, t, i)		lock_acquire_exclusive(l, s, t, NULL, i)
#define rwlock_acquire_read(l, s, t, i)		lock_acquire_shared_recursive(l, s, t, NULL, i)
#define rwlock_release(l, i)			lock_release(l, i)
#define rwsem_acquire(l, s, t, i)		lock_acquire_exclusive(l, s, t, NULL, i)
#define rwsem_acquire_nest(l, s, t, n, i)	lock_acquire_exclusive(l, s, t, n, i)
#define rwsem_acquire_read(l, s, t, i)		lock_acquire_shared(l, s, t, NULL, i)
#define rwsem_release(l, i)			lock_release(l, i)
#define seqcount_acquire(l, s, t, i)		lock_acquire_exclusive(l, s, t, NULL, i)
#define seqcount_acquire_read(l, s, t, i)	lock_acquire_shared_recursive(l, s, t, NULL, i)
#define seqcount_release(l, i)			lock_release(l, i)
#define spin_acquire(l, s, t, i)		lock_acquire_exclusive(l, s, t, NULL, i)
#define spin_acquire_nest(l, s, t, n, i)	lock_acquire_exclusive(l, s, t, n, i)
#define spin_release(l, i)			lock_release(l, i)

#define HLIST_HEAD(name) struct hlist_head name = {  .first = NULL }
#define HLIST_HEAD_INIT { .first = NULL }
#define INIT_HLIST_HEAD(ptr) ((ptr)->first = NULL)
#define LIST_HEAD(name) \
	struct list_head name = LIST_HEAD_INIT(name)
#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define hlist_entry(ptr, type, member) container_of(ptr,type,member)
#define hlist_entry_safe(ptr, type, member) \
	({ typeof(ptr) ____ptr = (ptr); \
	   ____ptr ? hlist_entry(____ptr, type, member) : NULL; \
	})
#define hlist_for_each(pos, head) \
	for (pos = (head)->first; pos ; pos = pos->next)
#define hlist_for_each_entry(pos, head, member)				\
	for (pos = hlist_entry_safe((head)->first, typeof(*(pos)), member);\
	     pos;							\
	     pos = hlist_entry_safe((pos)->member.next, typeof(*(pos)), member))
#define hlist_for_each_entry_continue(pos, member)			\
	for (pos = hlist_entry_safe((pos)->member.next, typeof(*(pos)), member);\
	     pos;							\
	     pos = hlist_entry_safe((pos)->member.next, typeof(*(pos)), member))
#define hlist_for_each_entry_from(pos, member)				\
	for (; pos;							\
	     pos = hlist_entry_safe((pos)->member.next, typeof(*(pos)), member))
#define hlist_for_each_entry_safe(pos, n, head, member) 		\
	for (pos = hlist_entry_safe((head)->first, typeof(*pos), member);\
	     pos && ({ n = pos->member.next; 1; });			\
	     pos = hlist_entry_safe(n, typeof(*pos), member))
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
	for (pos = (head)->next; pos != (head); pos = pos->next)
#define list_for_each_continue(pos, head) \
	for (pos = pos->next; pos != (head); pos = pos->next)
#define list_for_each_entry(pos, head, member)				\
	for (pos = list_first_entry(head, typeof(*pos), member);	\
	     &pos->member != (head);					\
	     pos = list_next_entry(pos, member))
#define list_for_each_entry_continue(pos, head, member) 		\
	for (pos = list_next_entry(pos, member);			\
	     &pos->member != (head);					\
	     pos = list_next_entry(pos, member))
#define list_for_each_entry_continue_reverse(pos, head, member)		\
	for (pos = list_prev_entry(pos, member);			\
	     &pos->member != (head);					\
	     pos = list_prev_entry(pos, member))
#define list_for_each_entry_from(pos, head, member) 			\
	for (; &pos->member != (head);					\
	     pos = list_next_entry(pos, member))
#define list_for_each_entry_from_reverse(pos, head, member)		\
	for (; &pos->member != (head);					\
	     pos = list_prev_entry(pos, member))
#define list_for_each_entry_reverse(pos, head, member)			\
	for (pos = list_last_entry(head, typeof(*pos), member);		\
	     &pos->member != (head); 					\
	     pos = list_prev_entry(pos, member))
#define list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = list_first_entry(head, typeof(*pos), member),	\
		n = list_next_entry(pos, member);			\
	     &pos->member != (head); 					\
	     pos = n, n = list_next_entry(n, member))
#define list_for_each_entry_safe_continue(pos, n, head, member) 		\
	for (pos = list_next_entry(pos, member), 				\
		n = list_next_entry(pos, member);				\
	     &pos->member != (head);						\
	     pos = n, n = list_next_entry(n, member))
#define list_for_each_entry_safe_from(pos, n, head, member) 			\
	for (n = list_next_entry(pos, member);					\
	     &pos->member != (head);						\
	     pos = n, n = list_next_entry(n, member))
#define list_for_each_entry_safe_reverse(pos, n, head, member)		\
	for (pos = list_last_entry(head, typeof(*pos), member),		\
		n = list_prev_entry(pos, member);			\
	     &pos->member != (head); 					\
	     pos = n, n = list_prev_entry(n, member))
#define list_for_each_prev(pos, head) \
	for (pos = (head)->prev; pos != (head); pos = pos->prev)
#define list_for_each_prev_safe(pos, n, head) \
	for (pos = (head)->prev, n = pos->prev; \
	     pos != (head); \
	     pos = n, n = pos->prev)
#define list_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
		pos = n, n = pos->next)
#define list_last_entry(ptr, type, member) \
	list_entry((ptr)->prev, type, member)
#define list_next_entry(pos, member) \
	list_entry((pos)->member.next, typeof(*(pos)), member)
#define list_prepare_entry(pos, head, member) \
	((pos) ? : list_entry(head, typeof(*pos), member))
#define list_prev_entry(pos, member) \
	list_entry((pos)->member.prev, typeof(*(pos)), member)
#define list_safe_reset_next(pos, n, member)				\
	n = list_next_entry(pos, member)
#define LIST_POISON1  ((void *) 0x100 + POISON_POINTER_DELTA)
#define LIST_POISON2  ((void *) 0x122 + POISON_POINTER_DELTA)
#define PAGE_POISON 0x00
# define POISON_POINTER_DELTA _AC(CONFIG_ILLEGAL_POINTER_VALUE, UL)

#define DEFINE_RAW_SPINLOCK(x)	raw_spinlock_t x = __RAW_SPIN_LOCK_UNLOCKED(x)
#define DEFINE_SPINLOCK(x)	spinlock_t x = __SPIN_LOCK_UNLOCKED(x)
# define LOCK_PADSIZE (offsetof(struct raw_spinlock, dep_map))
# define SPIN_DEBUG_INIT(lockname)		\
	.magic = SPINLOCK_MAGIC,		\
	.owner_cpu = -1,			\
	.owner = SPINLOCK_OWNER_INIT,
# define SPIN_DEP_MAP_INIT(lockname)	.dep_map = { .name = #lockname }

#define __RAW_SPIN_LOCK_INITIALIZER(lockname)	\
	{					\
	.raw_lock = __ARCH_SPIN_LOCK_UNLOCKED,	\
	SPIN_DEBUG_INIT(lockname)		\
	SPIN_DEP_MAP_INIT(lockname) }
#define __RAW_SPIN_LOCK_UNLOCKED(lockname)	\
	(raw_spinlock_t) __RAW_SPIN_LOCK_INITIALIZER(lockname)
#define __SPIN_LOCK_INITIALIZER(lockname) \
	{ { .rlock = __RAW_SPIN_LOCK_INITIALIZER(lockname) } }
#define __SPIN_LOCK_UNLOCKED(lockname) \
	(spinlock_t ) __SPIN_LOCK_INITIALIZER(lockname)
#define DEFINE_RWLOCK(x)	rwlock_t x = __RW_LOCK_UNLOCKED(x)
# define RW_DEP_MAP_INIT(lockname)	.dep_map = { .name = #lockname }

#define __RW_LOCK_UNLOCKED(lockname)					\
	(rwlock_t)	{	.raw_lock = __ARCH_RW_LOCK_UNLOCKED,	\
				.magic = RWLOCK_MAGIC,			\
				.owner = SPINLOCK_OWNER_INIT,		\
				.owner_cpu = -1,			\
				RW_DEP_MAP_INIT(lockname) }

#define VB2_V4L2_FL_SUPPORTS_M2M_HOLD_CAPTURE_BUF (1 << 0)

#define to_vb2_v4l2_buffer(vb) \
	container_of(vb, struct vb2_v4l2_buffer, vb2_buf)



#define media_device_for_each_entity(entity, mdev)			\
	list_for_each_entry(entity, &(mdev)->entities, graph_obj.list)
#define media_device_for_each_intf(intf, mdev)			\
	list_for_each_entry(intf, &(mdev)->interfaces, graph_obj.list)
#define media_device_for_each_link(link, mdev)			\
	list_for_each_entry(link, &(mdev)->links, graph_obj.list)
#define media_device_for_each_pad(pad, mdev)			\
	list_for_each_entry(pad, &(mdev)->pads, graph_obj.list)
#define media_device_register(mdev) __media_device_register(mdev, THIS_MODULE)
#define media_device_usb_init(mdev, udev, name) \
	__media_device_usb_init(mdev, udev, name, KBUILD_MODNAME)

#define gobj_to_entity(gobj) \
		container_of(gobj, struct media_entity, graph_obj)
#define gobj_to_intf(gobj) \
		container_of(gobj, struct media_interface, graph_obj)
#define gobj_to_link(gobj) \
		container_of(gobj, struct media_link, graph_obj)
#define gobj_to_pad(gobj) \
		container_of(gobj, struct media_pad, graph_obj)
#define intf_to_devnode(intf) \
		container_of(intf, struct media_intf_devnode, intf)
#define media_entity_call(entity, operation, args...)			\
	(((entity)->ops && (entity)->ops->operation) ?			\
	 (entity)->ops->operation((entity) , ##args) : -ENOIOCTLCMD)
#define media_entity_cleanup(entity) do { } while (false)

#define fwnode_call_bool_op(fwnode, op, ...)		\
	(fwnode_has_op(fwnode, op) ?			\
	 (fwnode)->ops->op(fwnode, ## __VA_ARGS__) : false)
#define fwnode_call_int_op(fwnode, op, ...)				\
	(fwnode ? (fwnode_has_op(fwnode, op) ?				\
		   (fwnode)->ops->op(fwnode, ## __VA_ARGS__) : -ENXIO) : \
	 -EINVAL)
#define fwnode_call_ptr_op(fwnode, op, ...)		\
	(fwnode_has_op(fwnode, op) ?			\
	 (fwnode)->ops->op(fwnode, ## __VA_ARGS__) : NULL)
#define fwnode_call_void_op(fwnode, op, ...)				\
	do {								\
		if (fwnode_has_op(fwnode, op))				\
			(fwnode)->ops->op(fwnode, ## __VA_ARGS__);	\
	} while (false)
#define fwnode_has_op(fwnode, op)				\
	((fwnode) && (fwnode)->ops && (fwnode)->ops->op)
#define get_dev_from_fwnode(fwnode)	get_device((fwnode)->dev)
#define BITMAP_FIRST_WORD_MASK(start) (~0UL << ((start) & (BITS_PER_LONG - 1)))
#define BITMAP_FROM_U64(n) (n)
#define BITMAP_LAST_WORD_MASK(nbits) (~0UL >> (-(nbits) & (BITS_PER_LONG - 1)))
#define BITMAP_MEM_ALIGNMENT 8
#define BITMAP_MEM_MASK (BITMAP_MEM_ALIGNMENT - 1)

#define bitmap_copy_le bitmap_copy
#define bitmap_for_each_clear_region(bitmap, rs, re, start, end)	     \
	for ((rs) = (start),						     \
	     bitmap_next_clear_region((bitmap), &(rs), &(re), (end));	     \
	     (rs) < (re);						     \
	     (rs) = (re) + 1,						     \
	     bitmap_next_clear_region((bitmap), &(rs), &(re), (end)))
#define bitmap_for_each_set_region(bitmap, rs, re, start, end)		     \
	for ((rs) = (start),						     \
	     bitmap_next_set_region((bitmap), &(rs), &(re), (end));	     \
	     (rs) < (re);						     \
	     (rs) = (re) + 1,						     \
	     bitmap_next_set_region((bitmap), &(rs), &(re), (end)))
#define bitmap_from_arr32(bitmap, buf, nbits)			\
	bitmap_copy_clear_tail((unsigned long *) (bitmap),	\
			(const unsigned long *) (buf), (nbits))
#define bitmap_to_arr32(buf, bitmap, nbits)			\
	bitmap_copy_clear_tail((unsigned long *) (buf),		\
			(const unsigned long *) (bitmap), (nbits))
#define small_const_nbits(nbits) \
	(__builtin_constant_p(nbits) && (nbits) <= BITS_PER_LONG && (nbits) > 0)

#define to_media_devnode(cd) container_of(cd, struct media_devnode, dev)

#define DEVICE_ATTR(_name, _mode, _show, _store) \
	struct device_attribute dev_attr_##_name = __ATTR(_name, _mode, _show, _store)
#define DEVICE_ATTR_IGNORE_LOCKDEP(_name, _mode, _show, _store) \
	struct device_attribute dev_attr_##_name =		\
		__ATTR_IGNORE_LOCKDEP(_name, _mode, _show, _store)
#define DEVICE_ATTR_PREALLOC(_name, _mode, _show, _store) \
	struct device_attribute dev_attr_##_name = \
		__ATTR_PREALLOC(_name, _mode, _show, _store)
#define DEVICE_ATTR_RO(_name) \
	struct device_attribute dev_attr_##_name = __ATTR_RO(_name)
#define DEVICE_ATTR_RW(_name) \
	struct device_attribute dev_attr_##_name = __ATTR_RW(_name)
#define DEVICE_ATTR_WO(_name) \
	struct device_attribute dev_attr_##_name = __ATTR_WO(_name)
#define DEVICE_BOOL_ATTR(_name, _mode, _var) \
	struct dev_ext_attribute dev_attr_##_name = \
		{ __ATTR(_name, _mode, device_show_bool, device_store_bool), &(_var) }
#define DEVICE_INT_ATTR(_name, _mode, _var) \
	struct dev_ext_attribute dev_attr_##_name = \
		{ __ATTR(_name, _mode, device_show_int, device_store_int), &(_var) }
#define DEVICE_ULONG_ATTR(_name, _mode, _var) \
	struct dev_ext_attribute dev_attr_##_name = \
		{ __ATTR(_name, _mode, device_show_ulong, device_store_ulong), &(_var) }
#define MODULE_ALIAS_CHARDEV(major,minor) \
	MODULE_ALIAS("char-major-" __stringify(major) "-" __stringify(minor))
#define MODULE_ALIAS_CHARDEV_MAJOR(major) \
	MODULE_ALIAS("char-major-" __stringify(major) "-*")

#define devm_alloc_percpu(dev, type)      \
	((typeof(type) __percpu *)__devm_alloc_percpu((dev), sizeof(type), \
						      __alignof__(type)))
#define devres_alloc(release, size, gfp) \
	__devres_alloc_node(release, size, gfp, NUMA_NO_NODE, #release)
#define devres_alloc_node(release, size, gfp, nid) \
	__devres_alloc_node(release, size, gfp, nid, #release)
#define root_device_register(name) \
	__root_device_register(name, THIS_MODULE)
#define sysfs_deprecated 0

#define for_each_wakeup_source(ws) \
	for ((ws) = wakeup_sources_walk_start();	\
	     (ws);					\
	     (ws) = wakeup_sources_walk_next((ws)))
#define DRIVER_ATTR_RO(_name) \
	struct driver_attribute driver_attr_##_name = __ATTR_RO(_name)
#define DRIVER_ATTR_RW(_name) \
	struct driver_attribute driver_attr_##_name = __ATTR_RW(_name)
#define DRIVER_ATTR_WO(_name) \
	struct driver_attribute driver_attr_##_name = __ATTR_WO(_name)

#define builtin_driver(__driver, __register, ...) \
static int __init __driver##_init(void) \
{ \
	return __register(&(__driver) , ##__VA_ARGS__); \
} \
device_initcall(__driver##_init);
#define module_driver(__driver, __register, __unregister, ...) \
static int __init __driver##_init(void) \
{ \
	return __register(&(__driver) , ##__VA_ARGS__); \
} \
module_init(__driver##_init); \
static void __exit __driver##_exit(void) \
{ \
	__unregister(&(__driver) , ##__VA_ARGS__); \
} \
module_exit(__driver##_exit);
#define BUS_ATTR_RO(_name) \
	struct bus_attribute bus_attr_##_name = __ATTR_RO(_name)
#define BUS_ATTR_RW(_name) \
	struct bus_attribute bus_attr_##_name = __ATTR_RW(_name)
#define BUS_ATTR_WO(_name) \
	struct bus_attribute bus_attr_##_name = __ATTR_WO(_name)

#define PMSG_IS_AUTO(msg)	(((msg).event & PM_EVENT_AUTO) != 0)
#define PM_EVENT_PRETHAW PM_EVENT_QUIESCE
#define SET_LATE_SYSTEM_SLEEP_PM_OPS(suspend_fn, resume_fn) \
	.suspend_late = suspend_fn, \
	.resume_early = resume_fn, \
	.freeze_late = suspend_fn, \
	.thaw_early = resume_fn, \
	.poweroff_late = suspend_fn, \
	.restore_early = resume_fn,
#define SET_NOIRQ_SYSTEM_SLEEP_PM_OPS(suspend_fn, resume_fn) \
	.suspend_noirq = suspend_fn, \
	.resume_noirq = resume_fn, \
	.freeze_noirq = suspend_fn, \
	.thaw_noirq = resume_fn, \
	.poweroff_noirq = suspend_fn, \
	.restore_noirq = resume_fn,
#define SET_RUNTIME_PM_OPS(suspend_fn, resume_fn, idle_fn) \
	.runtime_suspend = suspend_fn, \
	.runtime_resume = resume_fn, \
	.runtime_idle = idle_fn,
#define SET_SYSTEM_SLEEP_PM_OPS(suspend_fn, resume_fn) \
	.suspend = suspend_fn, \
	.resume = resume_fn, \
	.freeze = suspend_fn, \
	.thaw = resume_fn, \
	.poweroff = suspend_fn, \
	.restore = resume_fn,
#define SIMPLE_DEV_PM_OPS(name, suspend_fn, resume_fn) \
const struct dev_pm_ops name = { \
	SET_SYSTEM_SLEEP_PM_OPS(suspend_fn, resume_fn) \
}
#define UNIVERSAL_DEV_PM_OPS(name, suspend_fn, resume_fn, idle_fn) \
const struct dev_pm_ops name = { \
	SET_SYSTEM_SLEEP_PM_OPS(suspend_fn, resume_fn) \
	SET_RUNTIME_PM_OPS(suspend_fn, resume_fn, idle_fn) \
}

#define device_pm_lock() do {} while (0)
#define device_pm_unlock() do {} while (0)
#define suspend_report_result(fn, ret)					\
	do {								\
		__suspend_report_result(__func__, fn, ret);		\
	} while (0)
#define COMPLETION_INITIALIZER(work) \
	{ 0, __WAIT_QUEUE_HEAD_INITIALIZER((work).wait) }
#define COMPLETION_INITIALIZER_ONSTACK(work) \
	(*({ init_completion(&work); &work; }))
#define COMPLETION_INITIALIZER_ONSTACK_MAP(work, map) \
	(*({ init_completion_map(&(work), &(map)); &(work); }))
#define DECLARE_COMPLETION(work) \
	struct completion work = COMPLETION_INITIALIZER(work)
# define DECLARE_COMPLETION_ONSTACK(work) \
	struct completion work = COMPLETION_INITIALIZER_ONSTACK(work)
# define DECLARE_COMPLETION_ONSTACK_MAP(work, map) \
	struct completion work = COMPLETION_INITIALIZER_ONSTACK_MAP(work, map)

#define init_completion(x) __init_completion(x)
#define init_completion_map(x, m) __init_completion(x)
#define DECLARE_WAITQUEUE(name, tsk)						\
	struct wait_queue_entry name = __WAITQUEUE_INITIALIZER(name, tsk)
#define DECLARE_WAIT_QUEUE_HEAD(name) \
	struct wait_queue_head name = __WAIT_QUEUE_HEAD_INITIALIZER(name)
# define DECLARE_WAIT_QUEUE_HEAD_ONSTACK(name) \
	struct wait_queue_head name = __WAIT_QUEUE_HEAD_INIT_ONSTACK(name)
#define DEFINE_WAIT(name) DEFINE_WAIT_FUNC(name, autoremove_wake_function)
#define DEFINE_WAIT_FUNC(name, function)					\
	struct wait_queue_entry name = {					\
		.private	= current,					\
		.func		= function,					\
		.entry		= LIST_HEAD_INIT((name).entry),			\
	}

#define __WAITQUEUE_INITIALIZER(name, tsk) {					\
	.private	= tsk,							\
	.func		= default_wake_function,				\
	.entry		= { NULL, NULL } }
#define __WAIT_QUEUE_HEAD_INITIALIZER(name) {					\
	.lock		= __SPIN_LOCK_UNLOCKED(name.lock),			\
	.head		= { &(name).head, &(name).head } }
# define __WAIT_QUEUE_HEAD_INIT_ONSTACK(name) \
	({ init_waitqueue_head(&name); name; })
#define ___wait_cond_timeout(condition)						\
({										\
	bool __cond = (condition);						\
	if (__cond && !__ret)							\
		__ret = 1;							\
	__cond || !__ret;							\
})
#define ___wait_event(wq_head, condition, state, exclusive, ret, cmd)		\
({										\
	__label__ __out;							\
	struct wait_queue_entry __wq_entry;					\
	long __ret = ret;					\
										\
	init_wait_entry(&__wq_entry, exclusive ? WQ_FLAG_EXCLUSIVE : 0);	\
	for (;;) {								\
		long __int = prepare_to_wait_event(&wq_head, &__wq_entry, state);\
										\
		if (condition)							\
			break;							\
										\
		if (___wait_is_interruptible(state) && __int) {			\
			__ret = __int;						\
			goto __out;						\
		}								\
										\
		cmd;								\
	}									\
	finish_wait(&wq_head, &__wq_entry);					\
__out:	__ret;									\
})
#define ___wait_is_interruptible(state)						\
	(!__builtin_constant_p(state) ||					\
		state == TASK_INTERRUPTIBLE || state == TASK_KILLABLE)		\

#define __io_wait_event(wq_head, condition)					\
	(void)___wait_event(wq_head, condition, TASK_UNINTERRUPTIBLE, 0, 0,	\
			    io_schedule())
#define __wait_event(wq_head, condition)					\
	(void)___wait_event(wq_head, condition, TASK_UNINTERRUPTIBLE, 0, 0,	\
			    schedule())
#define __wait_event_cmd(wq_head, condition, cmd1, cmd2)			\
	(void)___wait_event(wq_head, condition, TASK_UNINTERRUPTIBLE, 0, 0,	\
			    cmd1; schedule(); cmd2)
#define __wait_event_exclusive_cmd(wq_head, condition, cmd1, cmd2)		\
	(void)___wait_event(wq_head, condition, TASK_UNINTERRUPTIBLE, 1, 0,	\
			    cmd1; schedule(); cmd2)
#define __wait_event_freezable(wq_head, condition)				\
	___wait_event(wq_head, condition, TASK_INTERRUPTIBLE, 0, 0,		\
			    freezable_schedule())
#define __wait_event_freezable_exclusive(wq, condition)				\
	___wait_event(wq, condition, TASK_INTERRUPTIBLE, 1, 0,			\
			freezable_schedule())
#define __wait_event_freezable_timeout(wq_head, condition, timeout)		\
	___wait_event(wq_head, ___wait_cond_timeout(condition),			\
		      TASK_INTERRUPTIBLE, 0, timeout,				\
		      __ret = freezable_schedule_timeout(__ret))
#define __wait_event_hrtimeout(wq_head, condition, timeout, state)		\
({										\
	int __ret = 0;								\
	struct hrtimer_sleeper __t;						\
										\
	hrtimer_init_sleeper_on_stack(&__t, CLOCK_MONOTONIC,			\
				      HRTIMER_MODE_REL);			\
	if ((timeout) != KTIME_MAX)						\
		hrtimer_start_range_ns(&__t.timer, timeout,			\
				       current->timer_slack_ns,			\
				       HRTIMER_MODE_REL);			\
										\
	__ret = ___wait_event(wq_head, condition, state, 0, 0,			\
		if (!__t.task) {						\
			__ret = -ETIME;						\
			break;							\
		}								\
		schedule());							\
										\
	hrtimer_cancel(&__t.timer);						\
	destroy_hrtimer_on_stack(&__t.timer);					\
	__ret;									\
})
#define __wait_event_idle_exclusive_timeout(wq_head, condition, timeout)	\
	___wait_event(wq_head, ___wait_cond_timeout(condition),			\
		      TASK_IDLE, 1, timeout,					\
		      __ret = schedule_timeout(__ret))
#define __wait_event_idle_timeout(wq_head, condition, timeout)			\
	___wait_event(wq_head, ___wait_cond_timeout(condition),			\
		      TASK_IDLE, 0, timeout,					\
		      __ret = schedule_timeout(__ret))
#define __wait_event_interruptible(wq_head, condition)				\
	___wait_event(wq_head, condition, TASK_INTERRUPTIBLE, 0, 0,		\
		      schedule())
#define __wait_event_interruptible_exclusive(wq, condition)			\
	___wait_event(wq, condition, TASK_INTERRUPTIBLE, 1, 0,			\
		      schedule())
#define __wait_event_interruptible_lock_irq(wq_head, condition, lock, cmd)	\
	___wait_event(wq_head, condition, TASK_INTERRUPTIBLE, 0, 0,		\
		      spin_unlock_irq(&lock);					\
		      cmd;							\
		      schedule();						\
		      spin_lock_irq(&lock))
#define __wait_event_interruptible_locked(wq, condition, exclusive, fn)		\
({										\
	int __ret;								\
	DEFINE_WAIT(__wait);							\
	if (exclusive)								\
		__wait.flags |= WQ_FLAG_EXCLUSIVE;				\
	do {									\
		__ret = fn(&(wq), &__wait);					\
		if (__ret)							\
			break;							\
	} while (!(condition));							\
	__remove_wait_queue(&(wq), &__wait);					\
	__set_current_state(TASK_RUNNING);					\
	__ret;									\
})
#define __wait_event_interruptible_timeout(wq_head, condition, timeout)		\
	___wait_event(wq_head, ___wait_cond_timeout(condition),			\
		      TASK_INTERRUPTIBLE, 0, timeout,				\
		      __ret = schedule_timeout(__ret))
#define __wait_event_killable(wq, condition)					\
	___wait_event(wq, condition, TASK_KILLABLE, 0, 0, schedule())
#define __wait_event_killable_exclusive(wq, condition)				\
	___wait_event(wq, condition, TASK_KILLABLE, 1, 0,			\
		      schedule())
#define __wait_event_killable_timeout(wq_head, condition, timeout)		\
	___wait_event(wq_head, ___wait_cond_timeout(condition),			\
		      TASK_KILLABLE, 0, timeout,				\
		      __ret = schedule_timeout(__ret))
#define __wait_event_lock_irq(wq_head, condition, lock, cmd)			\
	(void)___wait_event(wq_head, condition, TASK_UNINTERRUPTIBLE, 0, 0,	\
			    spin_unlock_irq(&lock);				\
			    cmd;						\
			    schedule();						\
			    spin_lock_irq(&lock))
#define __wait_event_lock_irq_timeout(wq_head, condition, lock, timeout, state)	\
	___wait_event(wq_head, ___wait_cond_timeout(condition),			\
		      state, 0, timeout,					\
		      spin_unlock_irq(&lock);					\
		      __ret = schedule_timeout(__ret);				\
		      spin_lock_irq(&lock));
#define __wait_event_timeout(wq_head, condition, timeout)			\
	___wait_event(wq_head, ___wait_cond_timeout(condition),			\
		      TASK_UNINTERRUPTIBLE, 0, timeout,				\
		      __ret = schedule_timeout(__ret))
#define init_wait(wait)								\
	do {									\
		(wait)->private = current;					\
		(wait)->func = autoremove_wake_function;			\
		INIT_LIST_HEAD(&(wait)->entry);					\
		(wait)->flags = 0;						\
	} while (0)
#define init_waitqueue_head(wq_head)						\
	do {									\
		static struct lock_class_key __key;				\
										\
		__init_waitqueue_head((wq_head), #wq_head, &__key);		\
	} while (0)
#define io_wait_event(wq_head, condition)					\
do {										\
	might_sleep();								\
	if (condition)								\
		break;								\
	__io_wait_event(wq_head, condition);					\
} while (0)
#define key_to_poll(m) ((__force __poll_t)(uintptr_t)(void *)(m))
#define poll_to_key(m) ((void *)(__force uintptr_t)(__poll_t)(m))
#define wait_event(wq_head, condition)						\
do {										\
	might_sleep();								\
	if (condition)								\
		break;								\
	__wait_event(wq_head, condition);					\
} while (0)
#define wait_event_cmd(wq_head, condition, cmd1, cmd2)				\
do {										\
	if (condition)								\
		break;								\
	__wait_event_cmd(wq_head, condition, cmd1, cmd2);			\
} while (0)
#define wait_event_exclusive_cmd(wq_head, condition, cmd1, cmd2)		\
do {										\
	if (condition)								\
		break;								\
	__wait_event_exclusive_cmd(wq_head, condition, cmd1, cmd2);		\
} while (0)
#define wait_event_freezable(wq_head, condition)				\
({										\
	int __ret = 0;								\
	might_sleep();								\
	if (!(condition))							\
		__ret = __wait_event_freezable(wq_head, condition);		\
	__ret;									\
})
#define wait_event_freezable_exclusive(wq, condition)				\
({										\
	int __ret = 0;								\
	might_sleep();								\
	if (!(condition))							\
		__ret = __wait_event_freezable_exclusive(wq, condition);	\
	__ret;									\
})
#define wait_event_freezable_timeout(wq_head, condition, timeout)		\
({										\
	long __ret = timeout;							\
	might_sleep();								\
	if (!___wait_cond_timeout(condition))					\
		__ret = __wait_event_freezable_timeout(wq_head, condition, timeout); \
	__ret;									\
})
#define wait_event_hrtimeout(wq_head, condition, timeout)			\
({										\
	int __ret = 0;								\
	might_sleep();								\
	if (!(condition))							\
		__ret = __wait_event_hrtimeout(wq_head, condition, timeout,	\
					       TASK_UNINTERRUPTIBLE);		\
	__ret;									\
})
#define wait_event_idle(wq_head, condition)					\
do {										\
	might_sleep();								\
	if (!(condition))							\
		___wait_event(wq_head, condition, TASK_IDLE, 0, 0, schedule());	\
} while (0)
#define wait_event_idle_exclusive(wq_head, condition)				\
do {										\
	might_sleep();								\
	if (!(condition))							\
		___wait_event(wq_head, condition, TASK_IDLE, 1, 0, schedule());	\
} while (0)
#define wait_event_idle_exclusive_timeout(wq_head, condition, timeout)		\
({										\
	long __ret = timeout;							\
	might_sleep();								\
	if (!___wait_cond_timeout(condition))					\
		__ret = __wait_event_idle_exclusive_timeout(wq_head, condition, timeout);\
	__ret;									\
})
#define wait_event_idle_timeout(wq_head, condition, timeout)			\
({										\
	long __ret = timeout;							\
	might_sleep();								\
	if (!___wait_cond_timeout(condition))					\
		__ret = __wait_event_idle_timeout(wq_head, condition, timeout);	\
	__ret;									\
})
#define wait_event_interruptible(wq_head, condition)				\
({										\
	int __ret = 0;								\
	might_sleep();								\
	if (!(condition))							\
		__ret = __wait_event_interruptible(wq_head, condition);		\
	__ret;									\
})
#define wait_event_interruptible_exclusive(wq, condition)			\
({										\
	int __ret = 0;								\
	might_sleep();								\
	if (!(condition))							\
		__ret = __wait_event_interruptible_exclusive(wq, condition);	\
	__ret;									\
})
#define wait_event_interruptible_exclusive_locked(wq, condition)		\
	((condition)								\
	 ? 0 : __wait_event_interruptible_locked(wq, condition, 1, do_wait_intr))
#define wait_event_interruptible_exclusive_locked_irq(wq, condition)		\
	((condition)								\
	 ? 0 : __wait_event_interruptible_locked(wq, condition, 1, do_wait_intr_irq))
#define wait_event_interruptible_hrtimeout(wq, condition, timeout)		\
({										\
	long __ret = 0;								\
	might_sleep();								\
	if (!(condition))							\
		__ret = __wait_event_hrtimeout(wq, condition, timeout,		\
					       TASK_INTERRUPTIBLE);		\
	__ret;									\
})
#define wait_event_interruptible_lock_irq(wq_head, condition, lock)		\
({										\
	int __ret = 0;								\
	if (!(condition))							\
		__ret = __wait_event_interruptible_lock_irq(wq_head,		\
						condition, lock,);		\
	__ret;									\
})
#define wait_event_interruptible_lock_irq_cmd(wq_head, condition, lock, cmd)	\
({										\
	int __ret = 0;								\
	if (!(condition))							\
		__ret = __wait_event_interruptible_lock_irq(wq_head,		\
						condition, lock, cmd);		\
	__ret;									\
})
#define wait_event_interruptible_lock_irq_timeout(wq_head, condition, lock,	\
						  timeout)			\
({										\
	long __ret = timeout;							\
	if (!___wait_cond_timeout(condition))					\
		__ret = __wait_event_lock_irq_timeout(				\
					wq_head, condition, lock, timeout,	\
					TASK_INTERRUPTIBLE);			\
	__ret;									\
})
#define wait_event_interruptible_locked(wq, condition)				\
	((condition)								\
	 ? 0 : __wait_event_interruptible_locked(wq, condition, 0, do_wait_intr))
#define wait_event_interruptible_locked_irq(wq, condition)			\
	((condition)								\
	 ? 0 : __wait_event_interruptible_locked(wq, condition, 0, do_wait_intr_irq))
#define wait_event_interruptible_timeout(wq_head, condition, timeout)		\
({										\
	long __ret = timeout;							\
	might_sleep();								\
	if (!___wait_cond_timeout(condition))					\
		__ret = __wait_event_interruptible_timeout(wq_head,		\
						condition, timeout);		\
	__ret;									\
})
#define wait_event_killable(wq_head, condition)					\
({										\
	int __ret = 0;								\
	might_sleep();								\
	if (!(condition))							\
		__ret = __wait_event_killable(wq_head, condition);		\
	__ret;									\
})
#define wait_event_killable_exclusive(wq, condition)				\
({										\
	int __ret = 0;								\
	might_sleep();								\
	if (!(condition))							\
		__ret = __wait_event_killable_exclusive(wq, condition);		\
	__ret;									\
})
#define wait_event_killable_timeout(wq_head, condition, timeout)		\
({										\
	long __ret = timeout;							\
	might_sleep();								\
	if (!___wait_cond_timeout(condition))					\
		__ret = __wait_event_killable_timeout(wq_head,			\
						condition, timeout);		\
	__ret;									\
})
#define wait_event_lock_irq(wq_head, condition, lock)				\
do {										\
	if (condition)								\
		break;								\
	__wait_event_lock_irq(wq_head, condition, lock, );			\
} while (0)
#define wait_event_lock_irq_cmd(wq_head, condition, lock, cmd)			\
do {										\
	if (condition)								\
		break;								\
	__wait_event_lock_irq(wq_head, condition, lock, cmd);			\
} while (0)
#define wait_event_lock_irq_timeout(wq_head, condition, lock, timeout)		\
({										\
	long __ret = timeout;							\
	if (!___wait_cond_timeout(condition))					\
		__ret = __wait_event_lock_irq_timeout(				\
					wq_head, condition, lock, timeout,	\
					TASK_UNINTERRUPTIBLE);			\
	__ret;									\
})
#define wait_event_timeout(wq_head, condition, timeout)				\
({										\
	long __ret = timeout;							\
	might_sleep();								\
	if (!___wait_cond_timeout(condition))					\
		__ret = __wait_event_timeout(wq_head, condition, timeout);	\
	__ret;									\
})
#define wake_up(x)			__wake_up(x, TASK_NORMAL, 1, NULL)
#define wake_up_all(x)			__wake_up(x, TASK_NORMAL, 0, NULL)
#define wake_up_all_locked(x)		__wake_up_locked((x), TASK_NORMAL, 0)
#define wake_up_interruptible(x)	__wake_up(x, TASK_INTERRUPTIBLE, 1, NULL)
#define wake_up_interruptible_all(x)	__wake_up(x, TASK_INTERRUPTIBLE, 0, NULL)
#define wake_up_interruptible_nr(x, nr)	__wake_up(x, TASK_INTERRUPTIBLE, nr, NULL)
#define wake_up_interruptible_poll(x, m)					\
	__wake_up(x, TASK_INTERRUPTIBLE, 1, poll_to_key(m))
#define wake_up_interruptible_sync(x)	__wake_up_sync((x), TASK_INTERRUPTIBLE)
#define wake_up_interruptible_sync_poll(x, m)					\
	__wake_up_sync_key((x), TASK_INTERRUPTIBLE, poll_to_key(m))
#define wake_up_interruptible_sync_poll_locked(x, m)				\
	__wake_up_locked_sync_key((x), TASK_INTERRUPTIBLE, poll_to_key(m))
#define wake_up_locked(x)		__wake_up_locked((x), TASK_NORMAL, 1)
#define wake_up_locked_poll(x, m)						\
	__wake_up_locked_key((x), TASK_NORMAL, poll_to_key(m))
#define wake_up_nr(x, nr)		__wake_up(x, TASK_NORMAL, nr, NULL)
#define wake_up_poll(x, m)							\
	__wake_up(x, TASK_NORMAL, 1, poll_to_key(m))

#define LOCK_SECTION_END                        \
        ".previous\n\t"
#define LOCK_SECTION_NAME ".text..lock."KBUILD_BASENAME
#define LOCK_SECTION_START(extra)               \
        ".subsection 1\n\t"                     \
        extra                                   \
        ".ifndef " LOCK_SECTION_NAME "\n\t"     \
        LOCK_SECTION_NAME ":\n\t"               \
        ".endif\n"

#define __lockfunc __attribute__((section(".spinlock.text")))
#define alloc_bucket_spinlocks(locks, lock_mask, max_size, cpu_mult, gfp)    \
	({								     \
		static struct lock_class_key key;			     \
		int ret;						     \
									     \
		ret = __alloc_bucket_spinlocks(locks, lock_mask, max_size,   \
					       cpu_mult, gfp, #locks, &key); \
		ret;							     \
	})
#define arch_spin_lock_flags(lock, flags)	arch_spin_lock(lock)
#define assert_spin_locked(lock)	assert_raw_spin_locked(&(lock)->rlock)
#define atomic_dec_and_lock(atomic, lock) \
		__cond_lock(lock, _atomic_dec_and_lock(atomic, lock))
#define atomic_dec_and_lock_irqsave(atomic, lock, flags) \
		__cond_lock(lock, _atomic_dec_and_lock_irqsave(atomic, lock, &(flags)))
#define do_raw_spin_lock_flags(lock, flags) do_raw_spin_lock(lock)
#define raw_spin_is_contended(lock)	arch_spin_is_contended(&(lock)->raw_lock)
#define raw_spin_is_locked(lock)	arch_spin_is_locked(&(lock)->raw_lock)
#define raw_spin_lock_bh(lock)		_raw_spin_lock_bh(lock)
# define raw_spin_lock_init(lock)				\
	do { *(lock) = __RAW_SPIN_LOCK_UNLOCKED(lock); } while (0)
#define raw_spin_lock_irq(lock)		_raw_spin_lock_irq(lock)
#define raw_spin_lock_irqsave(lock, flags)			\
	do {						\
		typecheck(unsigned long, flags);	\
		flags = _raw_spin_lock_irqsave(lock);	\
	} while (0)
#define raw_spin_lock_irqsave_nested(lock, flags, subclass)		\
	do {								\
		typecheck(unsigned long, flags);			\
		flags = _raw_spin_lock_irqsave_nested(lock, subclass);	\
	} while (0)
# define raw_spin_lock_nest_lock(lock, nest_lock)			\
	 do {								\
		 typecheck(struct lockdep_map *, &(nest_lock)->dep_map);\
		 _raw_spin_lock_nest_lock(lock, &(nest_lock)->dep_map);	\
	 } while (0)
# define raw_spin_lock_nested(lock, subclass) \
	_raw_spin_lock_nested(lock, subclass)
#define raw_spin_trylock_bh(lock) \
	__cond_lock(lock, _raw_spin_trylock_bh(lock))
#define raw_spin_trylock_irq(lock) \
({ \
	local_irq_disable(); \
	raw_spin_trylock(lock) ? \
	1 : ({ local_irq_enable(); 0;  }); \
})
#define raw_spin_trylock_irqsave(lock, flags) \
({ \
	local_irq_save(flags); \
	raw_spin_trylock(lock) ? \
	1 : ({ local_irq_restore(flags); 0; }); \
})
#define raw_spin_unlock(lock)		_raw_spin_unlock(lock)
#define raw_spin_unlock_irqrestore(lock, flags)		\
	do {							\
		typecheck(unsigned long, flags);		\
		_raw_spin_unlock_irqrestore(lock, flags);	\
	} while (0)
#define smp_mb__after_spinlock()	do { } while (0)
#define spin_lock_init(_lock)				\
do {							\
	spinlock_check(_lock);				\
	raw_spin_lock_init(&(_lock)->rlock);		\
} while (0)
#define spin_lock_irqsave(lock, flags)				\
do {								\
	raw_spin_lock_irqsave(spinlock_check(lock), flags);	\
} while (0)
#define spin_lock_irqsave_nested(lock, flags, subclass)			\
do {									\
	raw_spin_lock_irqsave_nested(spinlock_check(lock), flags, subclass); \
} while (0)
#define spin_lock_nest_lock(lock, nest_lock)				\
do {									\
	raw_spin_lock_nest_lock(spinlock_check(lock), nest_lock);	\
} while (0)
#define spin_lock_nested(lock, subclass)			\
do {								\
	raw_spin_lock_nested(spinlock_check(lock), subclass);	\
} while (0)
#define spin_trylock_irqsave(lock, flags)			\
({								\
	raw_spin_trylock_irqsave(spinlock_check(lock), flags); \
})

# define arch_read_lock_flags(lock, flags)	arch_read_lock(lock)
# define arch_write_lock_flags(lock, flags)	arch_write_lock(lock)
# define do_raw_read_lock(rwlock)	do {__acquire(lock); arch_read_lock(&(rwlock)->raw_lock); } while (0)
# define do_raw_read_lock_flags(lock, flags) \
		do {__acquire(lock); arch_read_lock_flags(&(lock)->raw_lock, *(flags)); } while (0)
# define do_raw_read_trylock(rwlock)	arch_read_trylock(&(rwlock)->raw_lock)
# define do_raw_read_unlock(rwlock)	do {arch_read_unlock(&(rwlock)->raw_lock); __release(lock); } while (0)
# define do_raw_write_lock(rwlock)	do {__acquire(lock); arch_write_lock(&(rwlock)->raw_lock); } while (0)
# define do_raw_write_lock_flags(lock, flags) \
		do {__acquire(lock); arch_write_lock_flags(&(lock)->raw_lock, *(flags)); } while (0)
# define do_raw_write_trylock(rwlock)	arch_write_trylock(&(rwlock)->raw_lock)
# define do_raw_write_unlock(rwlock)	do {arch_write_unlock(&(rwlock)->raw_lock); __release(lock); } while (0)
#define read_lock(lock)		_raw_read_lock(lock)
#define read_lock_bh(lock)		_raw_read_lock_bh(lock)
#define read_lock_irq(lock)		_raw_read_lock_irq(lock)
#define read_lock_irqsave(lock, flags)			\
	do {						\
		typecheck(unsigned long, flags);	\
		flags = _raw_read_lock_irqsave(lock);	\
	} while (0)
#define read_unlock(lock)		_raw_read_unlock(lock)
#define read_unlock_bh(lock)		_raw_read_unlock_bh(lock)
#define read_unlock_irq(lock)		_raw_read_unlock_irq(lock)
#define read_unlock_irqrestore(lock, flags)			\
	do {							\
		typecheck(unsigned long, flags);		\
		_raw_read_unlock_irqrestore(lock, flags);	\
	} while (0)
# define rwlock_init(lock)					\
do {								\
	static struct lock_class_key __key;			\
								\
	__rwlock_init((lock), #lock, &__key);			\
} while (0)
#define write_lock_bh(lock)		_raw_write_lock_bh(lock)
#define write_lock_irq(lock)		_raw_write_lock_irq(lock)
#define write_lock_irqsave(lock, flags)			\
	do {						\
		typecheck(unsigned long, flags);	\
		flags = _raw_write_lock_irqsave(lock);	\
	} while (0)
#define write_trylock_irqsave(lock, flags) \
({ \
	local_irq_save(flags); \
	write_trylock(lock) ? \
	1 : ({ local_irq_restore(flags); 0; }); \
})
#define write_unlock(lock)		_raw_write_unlock(lock)
#define write_unlock_bh(lock)		_raw_write_unlock_bh(lock)
#define write_unlock_irq(lock)		_raw_write_unlock_irq(lock)
#define write_unlock_irqrestore(lock, flags)		\
	do {						\
		typecheck(unsigned long, flags);	\
		_raw_write_unlock_irqrestore(lock, flags);	\
	} while (0)

#define SOFTIRQ_LOCK_OFFSET (SOFTIRQ_DISABLE_OFFSET + PREEMPT_LOCK_OFFSET)
#define __IRQ_MASK(x)	((1UL << (x))-1)

#define __preempt_count_dec() __preempt_count_sub(1)
#define __preempt_count_inc() __preempt_count_add(1)
#define hardirq_count()	(preempt_count() & HARDIRQ_MASK)
#define in_atomic()	(preempt_count() != 0)
#define in_atomic_preempt_off() (preempt_count() != PREEMPT_DISABLE_OFFSET)
#define in_interrupt()		(irq_count())
#define in_irq()		(hardirq_count())
#define in_nmi()		(preempt_count() & NMI_MASK)
#define in_serving_softirq()	(softirq_count() & SOFTIRQ_OFFSET)
#define in_softirq()		(softirq_count())
#define in_task()		(!(preempt_count() & \
				   (NMI_MASK | HARDIRQ_MASK | SOFTIRQ_OFFSET)))
#define irq_count()	(preempt_count() & (HARDIRQ_MASK | SOFTIRQ_MASK \
				 | NMI_MASK))
#define preempt_check_resched() \
do { \
	if (should_resched(0)) \
		__preempt_schedule(); \
} while (0)
#define preempt_count_dec() preempt_count_sub(1)
#define preempt_count_dec_and_test() __preempt_count_dec_and_test()
#define preempt_count_inc() preempt_count_add(1)
#define preempt_disable() \
do { \
	preempt_count_inc(); \
	barrier(); \
} while (0)
#define preempt_disable_notrace() \
do { \
	__preempt_count_inc(); \
	barrier(); \
} while (0)
#define preempt_enable() \
do { \
	barrier(); \
	if (unlikely(preempt_count_dec_and_test())) \
		__preempt_schedule(); \
} while (0)
#define preempt_enable_no_resched() sched_preempt_enable_no_resched()
#define preempt_enable_no_resched_notrace() \
do { \
	barrier(); \
	__preempt_count_dec(); \
} while (0)
#define preempt_enable_notrace() \
do { \
	barrier(); \
	if (unlikely(__preempt_count_dec_and_test())) \
		__preempt_schedule_notrace(); \
} while (0)
#define preempt_fold_need_resched() \
do { \
	if (tif_need_resched()) \
		set_preempt_need_resched(); \
} while (0)
#define preempt_set_need_resched() \
do { \
	set_preempt_need_resched(); \
} while (0)
#define preemptible()	(preempt_count() == 0 && !irqs_disabled())
#define sched_preempt_enable_no_resched() \
do { \
	barrier(); \
	preempt_count_dec(); \
} while (0)
#define softirq_count()	(preempt_count() & SOFTIRQ_MASK)

#define clear_thread_flag(flag) \
	clear_ti_thread_flag(current_thread_info(), flag)
#define current_thread_info() ((struct thread_info *)current)
#define set_thread_flag(flag) \
	set_ti_thread_flag(current_thread_info(), flag)
#define test_and_clear_thread_flag(flag) \
	test_and_clear_ti_thread_flag(current_thread_info(), flag)
#define test_and_set_thread_flag(flag) \
	test_and_set_ti_thread_flag(current_thread_info(), flag)
#define test_thread_flag(flag) \
	test_ti_thread_flag(current_thread_info(), flag)
#define tif_need_resched() test_thread_flag(TIF_NEED_RESCHED)
#define update_thread_flag(flag, value) \
	update_ti_thread_flag(current_thread_info(), flag, value)




#define DIV64_U64_ROUND_CLOSEST(dividend, divisor)	\
	({ u64 _tmp = (divisor); div64_u64((dividend) + _tmp / 2, _tmp); })
#define DIV64_U64_ROUND_UP(ll, d)	\
	({ u64 _tmp = (d); div64_u64((ll) + _tmp - 1, _tmp); })

#define div64_long(x, y) div64_s64((x), (y))
#define div64_ul(x, y)   div64_u64((x), (y))

#define irqs_disabled()					\
	({						\
		unsigned long _flags;			\
		raw_local_save_flags(_flags);		\
		raw_irqs_disabled_flags(_flags);	\
	})
#define irqs_disabled_flags(flags) raw_irqs_disabled_flags(flags)
#define local_irq_disable() \
	do { raw_local_irq_disable(); trace_hardirqs_off(); } while (0)
#define local_irq_enable() \
	do { trace_hardirqs_on(); raw_local_irq_enable(); } while (0)
#define local_irq_restore(flags)			\
	do {						\
		if (raw_irqs_disabled_flags(flags)) {	\
			raw_local_irq_restore(flags);	\
			trace_hardirqs_off();		\
		} else {				\
			trace_hardirqs_on();		\
			raw_local_irq_restore(flags);	\
		}					\
	} while (0)
#define local_irq_save(flags)				\
	do {						\
		raw_local_irq_save(flags);		\
		trace_hardirqs_off();			\
	} while (0)
# define lockdep_softirq_enter()		\
do {						\
	current->softirq_context++;		\
} while (0)
# define lockdep_softirq_exit()			\
do {						\
	current->softirq_context--;		\
} while (0)
#define raw_irqs_disabled()		(arch_irqs_disabled())
#define raw_irqs_disabled_flags(flags)			\
	({						\
		typecheck(unsigned long, flags);	\
		arch_irqs_disabled_flags(flags);	\
	})
#define raw_local_irq_disable()		arch_local_irq_disable()
#define raw_local_irq_enable()		arch_local_irq_enable()
#define raw_local_irq_restore(flags)			\
	do {						\
		typecheck(unsigned long, flags);	\
		arch_local_irq_restore(flags);		\
	} while (0)
#define raw_local_irq_save(flags)			\
	do {						\
		typecheck(unsigned long, flags);	\
		flags = arch_local_irq_save();		\
	} while (0)
#define raw_local_save_flags(flags)			\
	do {						\
		typecheck(unsigned long, flags);	\
		flags = arch_local_save_flags();	\
	} while (0)
#define raw_safe_halt()			arch_safe_halt()
#define safe_halt()		do { raw_safe_halt(); } while (0)
# define start_critical_timings() do { } while (0)
# define stop_critical_timings() do { } while (0)
# define trace_hardirq_context(p)	((p)->hardirq_context)
# define trace_hardirq_enter()			\
do {						\
	current->hardirq_context++;		\
} while (0)
# define trace_hardirq_exit()			\
do {						\
	current->hardirq_context--;		\
} while (0)
# define trace_hardirqs_enabled(p)	((p)->hardirqs_enabled)
# define trace_hardirqs_off()		do { } while (0)
# define trace_hardirqs_on()		do { } while (0)
# define trace_softirq_context(p)	((p)->softirq_context)
# define trace_softirqs_enabled(p)	((p)->softirqs_enabled)

# define __hrtimer_clock_base_align


#define ktime_add(lhs, rhs)	((lhs) + (rhs))
#define ktime_add_ns(kt, nsval)		((kt) + (nsval))
#define ktime_add_unsafe(lhs, rhs)	((u64) (lhs) + (rhs))
#define ktime_sub(lhs, rhs)	((lhs) - (rhs))
#define ktime_sub_ns(kt, nsval)		((kt) - (nsval))
#define ktime_to_timespec(kt)		ns_to_timespec((kt))
#define ktime_to_timespec64(kt)		ns_to_timespec64((kt))
#define ktime_to_timeval(kt)		ns_to_timeval((kt))
#define INITIAL_JIFFIES ((unsigned long)(unsigned int) (-300*HZ))
#define LATCH ((CLOCK_TICK_RATE + HZ/2) / HZ)	
#define MAX_JIFFY_OFFSET ((LONG_MAX >> 1)-1)
# define MAX_SEC_IN_JIFFIES \
	(long)((u64)((u64)MAX_JIFFY_OFFSET * TICK_NSEC) / NSEC_PER_SEC)
#define NSEC_CONVERSION ((unsigned long)((((u64)1 << NSEC_JIFFIE_SC) +\
                                        TICK_NSEC -1) / (u64)TICK_NSEC))
#define NSEC_JIFFIE_SC (SEC_JIFFIE_SC + 29)
#define SEC_CONVERSION ((unsigned long)((((u64)NSEC_PER_SEC << SEC_JIFFIE_SC) +\
                                TICK_NSEC -1) / (u64)TICK_NSEC))
#define SEC_JIFFIE_SC (31 - SHIFT_HZ)
#define SH_DIV(NOM,DEN,LSH) (   (((NOM) / (DEN)) << (LSH))              \
                             + ((((NOM) % (DEN)) << (LSH)) + (DEN) / 2) / (DEN))
#define TICK_NSEC ((NSEC_PER_SEC+HZ/2)/HZ)
#define TICK_USEC ((USEC_PER_SEC + HZ/2) / HZ)
#define USER_TICK_USEC ((1000000UL + USER_HZ/2) / USER_HZ)


#define time_after(a,b)		\
	(typecheck(unsigned long, a) && \
	 typecheck(unsigned long, b) && \
	 ((long)((b) - (a)) < 0))
#define time_after64(a,b)	\
	(typecheck(__u64, a) &&	\
	 typecheck(__u64, b) && \
	 ((__s64)((b) - (a)) < 0))
#define time_after_eq(a,b)	\
	(typecheck(unsigned long, a) && \
	 typecheck(unsigned long, b) && \
	 ((long)((a) - (b)) >= 0))
#define time_after_eq64(a,b)	\
	(typecheck(__u64, a) && \
	 typecheck(__u64, b) && \
	 ((__s64)((a) - (b)) >= 0))
#define time_before(a,b)	time_after(b,a)
#define time_before64(a,b)	time_after64(b,a)
#define time_before_eq(a,b)	time_after_eq(b,a)
#define time_before_eq64(a,b)	time_after_eq64(b,a)
#define time_in_range(a,b,c) \
	(time_after_eq(a,b) && \
	 time_before_eq(a,c))
#define time_in_range64(a, b, c) \
	(time_after_eq64(a, b) && \
	 time_before_eq64(a, c))
#define time_in_range_open(a,b,c) \
	(time_after_eq(a,b) && \
	 time_before(a,c))
#define time_is_after_eq_jiffies(a) time_before_eq(jiffies, a)
#define time_is_after_eq_jiffies64(a) time_before_eq64(get_jiffies_64(), a)
#define time_is_after_jiffies(a) time_before(jiffies, a)
#define time_is_after_jiffies64(a) time_before64(get_jiffies_64(), a)
#define time_is_before_eq_jiffies(a) time_after_eq(jiffies, a)
#define time_is_before_eq_jiffies64(a) time_after_eq64(get_jiffies_64(), a)
#define time_is_before_jiffies(a) time_after(jiffies, a)
#define time_is_before_jiffies64(a) time_after64(get_jiffies_64(), a)
#define MAXFREQ 500000		
#define MAXFREQ_SCALED ((s64)MAXFREQ << NTP_SCALE_SHIFT)
#define MAXPHASE 500000000L	
#define MAXSEC 2048		
#define MINSEC 256		
#define NTP_INTERVAL_FREQ  (HZ)
#define NTP_INTERVAL_LENGTH (NSEC_PER_SEC/NTP_INTERVAL_FREQ)
#define NTP_PHASE_LIMIT ((MAXPHASE / NSEC_PER_USEC) << 5) 
#define PIT_TICK_RATE 1193182ul
#define PPM_SCALE ((s64)NSEC_PER_USEC << (NTP_SCALE_SHIFT - SHIFT_USEC))
#define PPM_SCALE_INV ((1LL << (PPM_SCALE_INV_SHIFT + NTP_SCALE_SHIFT)) / \
		       PPM_SCALE + 1)
#define PPM_SCALE_INV_SHIFT 19
#define SHIFT_USEC 16		

#define random_get_entropy()	get_cycles()
#define shift_right(x, s) ({	\
	__typeof__(x) __x = (x);	\
	__typeof__(s) __s = (s);	\
	__x < 0 ? -(-__x >> __s) : __x >> __s;	\
})
#define STA_RONLY (STA_PPSSIGNAL | STA_PPSJITTER | STA_PPSWANDER | \
	STA_PPSERROR | STA_CLOCKERR | STA_NANO | STA_MODE | STA_CLK)


#define time_after32(a, b)	((s32)((u32)(b) - (u32)(a)) < 0)
#define time_before32(b, a)	time_after32(a, b)
#define time_between32(t, l, h) ((u32)(h) - (u32)(l) >= (u32)(t) - (u32)(l))
#define RB_CLEAR_NODE(node)  \
	((node)->__rb_parent_color = (unsigned long)(node))
#define RB_EMPTY_NODE(node)  \
	((node)->__rb_parent_color == (unsigned long)(node))
#define RB_EMPTY_ROOT(root)  (READ_ONCE((root)->rb_node) == NULL)
#define RB_ROOT_CACHED (struct rb_root_cached) { {NULL, }, NULL }
#define rb_entry_safe(ptr, type, member) \
	({ typeof(ptr) ____ptr = (ptr); \
	   ____ptr ? rb_entry(____ptr, type, member) : NULL; \
	})
#define rb_first_cached(root) (root)->rb_leftmost
#define rb_parent(r)   ((struct rb_node *)((r)->__rb_parent_color & ~3))
#define rbtree_postorder_for_each_entry_safe(pos, n, root, field) \
	for (pos = rb_entry_safe(rb_first_postorder(root), typeof(*pos), field); \
	     pos && ({ n = rb_entry_safe(rb_next_postorder(&pos->field), \
			typeof(*pos), field); 1; }); \
	     pos = n)
#define RCU_INITIALIZER(v) (typeof(*(v)) __force __rcu *)(v)
#define RCU_INIT_POINTER(p, v) \
	do { \
		rcu_check_sparse(p, __rcu); \
		WRITE_ONCE(p, RCU_INITIALIZER(v)); \
	} while (0)
#define RCU_LOCKDEP_WARN(c, s)						\
	do {								\
		static bool __section(.data.unlikely) __warned;		\
		if (debug_lockdep_rcu_enabled() && !__warned && (c)) {	\
			__warned = true;				\
			lockdep_rcu_suspicious("__FILE__", "__LINE__", s);	\
		}							\
	} while (0)
#define RCU_NONIDLE(a) \
	do { \
		rcu_irq_enter_irqson(); \
		do { a; } while (0); \
		rcu_irq_exit_irqson(); \
	} while (0)
#define RCU_POINTER_INITIALIZER(p, v) \
		.p = RCU_INITIALIZER(v)
#define ULONG_CMP_GE(a, b)	(ULONG_MAX / 2 >= (a) - (b))
#define ULONG_CMP_LT(a, b)	(ULONG_MAX / 2 < (a) - (b))

#define __is_kfree_rcu_offset(offset) ((offset) < 4096)
#define __kfree_rcu(head, offset) \
	do { \
		BUILD_BUG_ON(!__is_kfree_rcu_offset(offset)); \
		kfree_call_rcu(head, (rcu_callback_t)(unsigned long)(offset)); \
	} while (0)
#define __rcu_access_pointer(p, space) \
({ \
	typeof(*p) *_________p1 = (typeof(*p) *__force)READ_ONCE(p); \
	rcu_check_sparse(p, space); \
	((typeof(*p) __force __kernel *)(_________p1)); \
})
#define __rcu_dereference_check(p, c, space) \
({ \
	 \
	typeof(*p) *________p1 = (typeof(*p) *__force)READ_ONCE(p); \
	RCU_LOCKDEP_WARN(!(c), "suspicious rcu_dereference_check() usage"); \
	rcu_check_sparse(p, space); \
	((typeof(*p) __force __kernel *)(________p1)); \
})
#define __rcu_dereference_protected(p, c, space) \
({ \
	RCU_LOCKDEP_WARN(!(c), "suspicious rcu_dereference_protected() usage"); \
	rcu_check_sparse(p, space); \
	((typeof(*p) __force __kernel *)(p)); \
})
#define call_rcu_tasks call_rcu
#define cond_resched_tasks_rcu_qs() \
do { \
	rcu_tasks_qs(current); \
	cond_resched(); \
} while (0)
#define kfree_rcu(ptr, rhf)						\
do {									\
	typeof (ptr) ___p = (ptr);					\
									\
	if (___p)							\
		__kfree_rcu(&((___p)->rhf), offsetof(typeof(*(ptr)), rhf)); \
} while (0)
#define rcu_access_pointer(p) __rcu_access_pointer((p), __rcu)
#define rcu_assign_pointer(p, v)					      \
do {									      \
	uintptr_t _r_a_p__v = (uintptr_t)(v);				      \
	rcu_check_sparse(p, __rcu);					      \
									      \
	if (__builtin_constant_p(v) && (_r_a_p__v) == (uintptr_t)NULL)	      \
		WRITE_ONCE((p), (typeof(p))(_r_a_p__v));		      \
	else								      \
		smp_store_release(&p, RCU_INITIALIZER((typeof(p))_r_a_p__v)); \
} while (0)
#define rcu_check_sparse(p, space) \
	((void)(((typeof(*p) space *)p) == p))
#define rcu_dereference(p) rcu_dereference_check(p, 0)
#define rcu_dereference_bh(p) rcu_dereference_bh_check(p, 0)
#define rcu_dereference_bh_check(p, c) \
	__rcu_dereference_check((p), (c) || rcu_read_lock_bh_held(), __rcu)
#define rcu_dereference_check(p, c) \
	__rcu_dereference_check((p), (c) || rcu_read_lock_held(), __rcu)
#define rcu_dereference_protected(p, c) \
	__rcu_dereference_protected((p), (c), __rcu)
#define rcu_dereference_raw(p) \
({ \
	 \
	typeof(p) ________p1 = READ_ONCE(p); \
	((typeof(*p) __force __kernel *)(________p1)); \
})
#define rcu_dereference_raw_check(p) __rcu_dereference_check((p), 1, __rcu)
#define rcu_dereference_sched(p) rcu_dereference_sched_check(p, 0)
#define rcu_dereference_sched_check(p, c) \
	__rcu_dereference_check((p), (c) || rcu_read_lock_sched_held(), \
				__rcu)
# define rcu_lock_acquire(a)		do { } while (0)
# define rcu_lock_release(a)		do { } while (0)
#define rcu_note_voluntary_context_switch(t) rcu_tasks_qs(t)
#define rcu_pointer_handoff(p) (p)
#define rcu_preempt_depth() (current->rcu_read_lock_nesting)
#define rcu_replace_pointer(rcu_ptr, ptr, c)				\
({									\
	typeof(ptr) __tmp = rcu_dereference_protected((rcu_ptr), (c));	\
	rcu_assign_pointer((rcu_ptr), (ptr));				\
	__tmp;								\
})
#define rcu_sleep_check()						\
	do {								\
		rcu_preempt_sleep_check();				\
		RCU_LOCKDEP_WARN(lock_is_held(&rcu_bh_lock_map),	\
				 "Illegal context switch in RCU-bh read-side critical section"); \
		RCU_LOCKDEP_WARN(lock_is_held(&rcu_sched_lock_map),	\
				 "Illegal context switch in RCU-sched read-side critical section"); \
	} while (0)
#define rcu_tasks_qs(t) \
	do { \
		if (READ_ONCE((t)->rcu_tasks_holdout)) \
			WRITE_ONCE((t)->rcu_tasks_holdout, false); \
	} while (0)
#define smp_mb__after_unlock_lock()	smp_mb()  
#define synchronize_rcu_tasks synchronize_rcu
#define ulong2long(a)		(*(long *)(&(a)))

#define rcu_note_context_switch(preempt) \
	do { \
		rcu_qs(); \
		rcu_tasks_qs(current); \
	} while (0)
#define rcutree_dead_cpu         NULL
#define rcutree_dying_cpu        NULL
#define rcutree_offline_cpu      NULL
#define rcutree_online_cpu       NULL
#define rcutree_prepare_cpu      NULL



#define cpu_active(cpu)		((cpu) == 0)
#define cpu_active_mask   ((const struct cpumask *)&__cpu_active_mask)
#define cpu_all_mask to_cpumask(cpu_all_bits)
#define cpu_is_offline(cpu)	unlikely(!cpu_online(cpu))
#define cpu_none_mask to_cpumask(cpu_bit_bitmap[0])
#define cpu_online(cpu)		((cpu) == 0)
#define cpu_online_mask   ((const struct cpumask *)&__cpu_online_mask)
#define cpu_possible(cpu)	((cpu) == 0)
#define cpu_possible_mask ((const struct cpumask *)&__cpu_possible_mask)
#define cpu_present(cpu)	((cpu) == 0)
#define cpu_present_mask  ((const struct cpumask *)&__cpu_present_mask)
#define cpumask_any(srcp) cpumask_first(srcp)
#define cpumask_any_and(mask1, mask2) cpumask_first_and((mask1), (mask2))
#define cpumask_bits(maskp) ((maskp)->bits)
#define cpumask_first_and(src1p, src2p) cpumask_next_and(-1, (src1p), (src2p))
#define cpumask_of(cpu) (get_cpu_mask(cpu))
#define cpumask_pr_args(maskp)		nr_cpu_ids, cpumask_bits(maskp)
#define for_each_cpu(cpu, mask)			\
	for ((cpu) = 0; (cpu) < 1; (cpu)++, (void)mask)
#define for_each_cpu_and(cpu, mask1, mask2)	\
	for ((cpu) = 0; (cpu) < 1; (cpu)++, (void)mask1, (void)mask2)
#define for_each_cpu_not(cpu, mask)		\
	for ((cpu) = 0; (cpu) < 1; (cpu)++, (void)mask)
#define for_each_cpu_wrap(cpu, mask, start)	\
	for ((cpu) = 0; (cpu) < 1; (cpu)++, (void)mask, (void)(start))
#define for_each_online_cpu(cpu)   for_each_cpu((cpu), cpu_online_mask)
#define for_each_possible_cpu(cpu) for_each_cpu((cpu), cpu_possible_mask)
#define for_each_present_cpu(cpu)  for_each_cpu((cpu), cpu_present_mask)
#define num_active_cpus()	cpumask_weight(cpu_active_mask)
#define num_online_cpus()	1U
#define num_possible_cpus()	cpumask_weight(cpu_possible_mask)
#define num_present_cpus()	cpumask_weight(cpu_present_mask)
#define this_cpu_cpumask_var_ptr(x)	this_cpu_read(x)
#define to_cpumask(bitmap)						\
	((struct cpumask *)(1 ? (bitmap)				\
			    : (void *)sizeof(__check_is_bitmap(bitmap))))
#define MIN_THREADS_LEFT_FOR_ROOT 4
#define NR_CPUS		CONFIG_NR_CPUS
#define PID_MAX_DEFAULT (CONFIG_BASE_SMALL ? 0x1000 : 0x8000)
#define PID_MAX_LIMIT (CONFIG_BASE_SMALL ? PAGE_SIZE * 8 : \
	(sizeof(long) > 4 ? 4 * 1024 * 1024 : PID_MAX_DEFAULT))

#define DEFINE_TIMER(_name, _function)				\
	struct timer_list _name =				\
		__TIMER_INITIALIZER(_function, 0)

#define __TIMER_INITIALIZER(_function, _flags) {		\
		.entry = { .next = TIMER_ENTRY_STATIC },	\
		.function = (_function),			\
		.flags = (_flags),				\
		__TIMER_LOCKDEP_MAP_INITIALIZER(		\
			"__FILE__" ":" __stringify("__LINE__"))	\
	}
#define __TIMER_LOCKDEP_MAP_INITIALIZER(_kn)				\
	.lockdep_map = STATIC_LOCKDEP_MAP_INIT(_kn, &_kn),
#define __init_timer(_timer, _fn, _flags)				\
	do {								\
		static struct lock_class_key __key;			\
		init_timer_key((_timer), (_fn), (_flags), #_timer, &__key);\
	} while (0)
#define __init_timer_on_stack(_timer, _fn, _flags)			\
	do {								\
		static struct lock_class_key __key;			\
		init_timer_on_stack_key((_timer), (_fn), (_flags),	\
					#_timer, &__key);		 \
	} while (0)
#define del_singleshot_timer_sync(t) del_timer_sync(t)
# define del_timer_sync(t)		del_timer(t)
#define from_timer(var, callback_timer, timer_fieldname) \
	container_of(callback_timer, typeof(*var), timer_fieldname)
#define timer_setup(timer, callback, flags)			\
	__init_timer((timer), (callback), (flags))
#define timer_setup_on_stack(timer, callback, flags)		\
	__init_timer_on_stack((timer), (callback), (flags))


#define alloc_percpu(type)						\
	(typeof(type) __percpu *)__alloc_percpu(sizeof(type),		\
						__alignof__(type))
#define alloc_percpu_gfp(type, gfp)					\
	(typeof(type) __percpu *)__alloc_percpu_gfp(sizeof(type),	\
						__alignof__(type), gfp)
#define PFN_ALIGN(x)	(((unsigned long)(x) + (PAGE_SIZE - 1)) & PAGE_MASK)
#define PFN_DOWN(x)	((x) >> PAGE_SHIFT)
#define PFN_PHYS(x)	((phys_addr_t)(x) << PAGE_SHIFT)
#define PFN_UP(x)	(((x) + PAGE_SIZE-1) >> PAGE_SHIFT)
#define PHYS_PFN(x)	((unsigned long)((x) >> PAGE_SHIFT))


#define __smp_processor_id(x) raw_smp_processor_id(x)
#define generic_smp_call_function_interrupt \
	generic_smp_call_function_single_interrupt
#define get_cpu()		({ preempt_disable(); __smp_processor_id(); })
#define put_cpu()		preempt_enable()
#define raw_smp_processor_id()			0
#define smp_call_function(func, info, wait) \
			(up_smp_call_function(func, info))
#define smp_call_function_many(mask, func, info, wait) \
			(up_smp_call_function(func, info))
#define smp_prepare_boot_cpu()			do {} while (0)
# define smp_processor_id() __smp_processor_id()

#define LLIST_HEAD_INIT(name)	{ NULL }
#define llist_entry(ptr, type, member)		\
	container_of(ptr, type, member)
#define llist_for_each(pos, node)			\
	for ((pos) = (node); pos; (pos) = (pos)->next)
#define llist_for_each_entry(pos, node, member)				\
	for ((pos) = llist_entry((node), typeof(*(pos)), member);	\
	     member_address_is_nonnull(pos, member);			\
	     (pos) = llist_entry((pos)->member.next, typeof(*(pos)), member))
#define llist_for_each_entry_safe(pos, n, node, member)			       \
	for (pos = llist_entry((node), typeof(*pos), member);		       \
	     member_address_is_nonnull(pos, member) &&			       \
	        (n = llist_entry(pos->member.next, typeof(*n), member), true); \
	     pos = n)
#define llist_for_each_safe(pos, n, node)			\
	for ((pos) = (node); (pos) && ((n) = (pos)->next, true); (pos) = (n))
#define member_address_is_nonnull(ptr, member)	\
	((uintptr_t)(ptr) + offsetof(typeof(*(ptr)), member) != 0)
#define LINUX_MM_DEBUG_H 1
#define VIRTUAL_BUG_ON(cond) BUG_ON(cond)
#define VM_BUG_ON(cond) BUG_ON(cond)
#define VM_BUG_ON_MM(cond, mm)						\
	do {								\
		if (unlikely(cond)) {					\
			dump_mm(mm);					\
			BUG();						\
		}							\
	} while (0)
#define VM_BUG_ON_PAGE(cond, page)					\
	do {								\
		if (unlikely(cond)) {					\
			dump_page(page, "VM_BUG_ON_PAGE(" __stringify(cond)")");\
			BUG();						\
		}							\
	} while (0)
#define VM_BUG_ON_PGFLAGS(cond, page) VM_BUG_ON_PAGE(cond, page)
#define VM_BUG_ON_VMA(cond, vma)					\
	do {								\
		if (unlikely(cond)) {					\
			dump_vma(vma);					\
			BUG();						\
		}							\
	} while (0)
#define VM_WARN(cond, format...) (void)WARN(cond, format)
#define VM_WARN_ON(cond) (void)WARN_ON(cond)
#define VM_WARN_ONCE(cond, format...) (void)WARN_ONCE(cond, format)
#define VM_WARN_ON_ONCE(cond) (void)WARN_ON_ONCE(cond)

#define DECLARE_DEFERRABLE_WORK(n, f)					\
	struct delayed_work n = __DELAYED_WORK_INITIALIZER(n, f, TIMER_DEFERRABLE)
#define DECLARE_DELAYED_WORK(n, f)					\
	struct delayed_work n = __DELAYED_WORK_INITIALIZER(n, f, 0)
#define DECLARE_WORK(n, f)						\
	struct work_struct n = __WORK_INITIALIZER(n, f)
#define INIT_DEFERRABLE_WORK(_work, _func)				\
	__INIT_DELAYED_WORK(_work, _func, TIMER_DEFERRABLE)
#define INIT_DEFERRABLE_WORK_ONSTACK(_work, _func)			\
	__INIT_DELAYED_WORK_ONSTACK(_work, _func, TIMER_DEFERRABLE)
#define INIT_DELAYED_WORK(_work, _func)					\
	__INIT_DELAYED_WORK(_work, _func, 0)
#define INIT_DELAYED_WORK_ONSTACK(_work, _func)				\
	__INIT_DELAYED_WORK_ONSTACK(_work, _func, 0)
#define INIT_RCU_WORK(_work, _func)					\
	INIT_WORK(&(_work)->work, (_func))
#define INIT_RCU_WORK_ONSTACK(_work, _func)				\
	INIT_WORK_ONSTACK(&(_work)->work, (_func))
#define INIT_WORK(_work, _func)						\
	__INIT_WORK((_work), (_func), 0)
#define INIT_WORK_ONSTACK(_work, _func)					\
	__INIT_WORK((_work), (_func), 1)
#define WORK_DATA_INIT()	ATOMIC_LONG_INIT((unsigned long)WORK_STRUCT_NO_POOL)
#define WORK_DATA_STATIC_INIT()	\
	ATOMIC_LONG_INIT((unsigned long)(WORK_STRUCT_NO_POOL | WORK_STRUCT_STATIC))

#define __DELAYED_WORK_INITIALIZER(n, f, tflags) {			\
	.work = __WORK_INITIALIZER((n).work, (f)),			\
	.timer = __TIMER_INITIALIZER(delayed_work_timer_fn,\
				     (tflags) | TIMER_IRQSAFE),		\
	}
#define __INIT_DELAYED_WORK(_work, _func, _tflags)			\
	do {								\
		INIT_WORK(&(_work)->work, (_func));			\
		__init_timer(&(_work)->timer,				\
			     delayed_work_timer_fn,			\
			     (_tflags) | TIMER_IRQSAFE);		\
	} while (0)
#define __INIT_DELAYED_WORK_ONSTACK(_work, _func, _tflags)		\
	do {								\
		INIT_WORK_ONSTACK(&(_work)->work, (_func));		\
		__init_timer_on_stack(&(_work)->timer,			\
				      delayed_work_timer_fn,		\
				      (_tflags) | TIMER_IRQSAFE);	\
	} while (0)
#define __INIT_WORK(_work, _func, _onstack)				\
	do {								\
		static struct lock_class_key __key;			\
									\
		__init_work((_work), _onstack);				\
		(_work)->data = (atomic_long_t) WORK_DATA_INIT();	\
		lockdep_init_map(&(_work)->lockdep_map, "(work_completion)"#_work, &__key, 0); \
		INIT_LIST_HEAD(&(_work)->entry);			\
		(_work)->func = (_func);				\
	} while (0)
#define __WORK_INITIALIZER(n, f) {					\
	.data = WORK_DATA_STATIC_INIT(),				\
	.entry	= { &(n).entry, &(n).entry },				\
	.func = (f),							\
	__WORK_INIT_LOCKDEP_MAP(#n, &(n))				\
	}
#define __WORK_INIT_LOCKDEP_MAP(n, k) \
	.lockdep_map = STATIC_LOCKDEP_MAP_INIT(n, k),
#define alloc_ordered_workqueue(fmt, flags, args...)			\
	alloc_workqueue(fmt, WQ_UNBOUND | __WQ_ORDERED |		\
			__WQ_ORDERED_EXPLICIT | (flags), 1, ##args)
#define create_freezable_workqueue(name)				\
	alloc_workqueue("%s", __WQ_LEGACY | WQ_FREEZABLE | WQ_UNBOUND |	\
			WQ_MEM_RECLAIM, 1, (name))
#define create_singlethread_workqueue(name)				\
	alloc_ordered_workqueue("%s", __WQ_LEGACY | WQ_MEM_RECLAIM, name)
#define create_workqueue(name)						\
	alloc_workqueue("%s", __WQ_LEGACY | WQ_MEM_RECLAIM, 1, (name))
#define delayed_work_pending(w) \
	work_pending(&(w)->work)
#define work_data_bits(work) ((unsigned long *)(&(work)->data))
#define work_pending(work) \
	test_bit(WORK_STRUCT_PENDING_BIT, work_data_bits(work))
#define DEFINE_KLIST(_name, _get, _put)					\
	struct klist _name = KLIST_INIT(_name, _get, _put)
#define KLIST_INIT(_name, _get, _put)					\
	{ .k_lock	= __SPIN_LOCK_UNLOCKED(_name.k_lock),		\
	  .k_list	= LIST_HEAD_INIT(_name.k_list),			\
	  .get		= _get,						\
	  .put		= _put, }

#define KREF_INIT(n)	{ .refcount = REFCOUNT_INIT(n), }

#define REFCOUNT_INIT(n)	{ .refs = ATOMIC_INIT(n), }


#define GLOBAL_ROOT_GID KGIDT_INIT(0)
#define GLOBAL_ROOT_UID KUIDT_INIT(0)
#define INVALID_GID KGIDT_INIT(-1)
#define INVALID_UID KUIDT_INIT(-1)
#define KGIDT_INIT(value) (kgid_t){ value }
#define KUIDT_INIT(value) (kuid_t){ value }

#define SET_GID(var, gid) do { (var) = __convert_gid(sizeof(var), (gid)); } while (0)
#define SET_UID(var, uid) do { (var) = __convert_uid(sizeof(var), (uid)); } while (0)

#define __convert_gid(size, gid) \
	(size >= sizeof(gid) ? (gid) : high2lowgid(gid))
#define __convert_uid(size, uid) \
	(size >= sizeof(uid) ? (uid) : high2lowuid(uid))
#define fs_high2lowgid(gid) ((gid) & ~0xFFFF ? (gid16_t)fs_overflowgid : (gid16_t)(gid))
#define fs_high2lowuid(uid) ((uid) & ~0xFFFF ? (uid16_t)fs_overflowuid : (uid16_t)(uid))
#define high2lowgid(gid) ((gid) & ~0xFFFF ? (old_gid_t)overflowgid : (old_gid_t)(gid))
#define high2lowuid(uid) ((uid) & ~0xFFFF ? (old_uid_t)overflowuid : (old_uid_t)(uid))
#define high_16_bits(x)	(((x) & 0xFFFF0000) >> 16)
#define low2highgid(gid) ((gid) == (old_gid_t)-1 ? (gid_t)-1 : (gid_t)(gid))
#define low2highuid(uid) ((uid) == (old_uid_t)-1 ? (uid_t)-1 : (uid_t)(uid))
#define low_16_bits(x)	((x) & 0xFFFF)

#define ATTRIBUTE_GROUPS(_name)					\
static const struct attribute_group _name##_group = {		\
	.attrs = _name##_attrs,					\
};								\
__ATTRIBUTE_GROUPS(_name)
#define BIN_ATTR(_name, _mode, _read, _write, _size)			\
struct bin_attribute bin_attr_##_name = __BIN_ATTR(_name, _mode, _read,	\
					_write, _size)
#define BIN_ATTR_RO(_name, _size)					\
struct bin_attribute bin_attr_##_name = __BIN_ATTR_RO(_name, _size)
#define BIN_ATTR_RW(_name, _size)					\
struct bin_attribute bin_attr_##_name = __BIN_ATTR_RW(_name, _size)
#define BIN_ATTR_WO(_name, _size)					\
struct bin_attribute bin_attr_##_name = __BIN_ATTR_WO(_name, _size)
#define SYSFS_PREALLOC 010000

#define __ATTR(_name, _mode, _show, _store) {				\
	.attr = {.name = __stringify(_name),				\
		 .mode = VERIFY_OCTAL_PERMISSIONS(_mode) },		\
	.show	= _show,						\
	.store	= _store,						\
}
#define __ATTRIBUTE_GROUPS(_name)				\
static const struct attribute_group *_name##_groups[] = {	\
	&_name##_group,						\
	NULL,							\
}
#define __ATTR_IGNORE_LOCKDEP(_name, _mode, _show, _store) {	\
	.attr = {.name = __stringify(_name), .mode = _mode,	\
			.ignore_lockdep = true },		\
	.show		= _show,				\
	.store		= _store,				\
}
#define __ATTR_NULL { .attr = { .name = NULL } }
#define __ATTR_PREALLOC(_name, _mode, _show, _store) {			\
	.attr = {.name = __stringify(_name),				\
		 .mode = SYSFS_PREALLOC | VERIFY_OCTAL_PERMISSIONS(_mode) },\
	.show	= _show,						\
	.store	= _store,						\
}
#define __ATTR_RO(_name) {						\
	.attr	= { .name = __stringify(_name), .mode = 0444 },		\
	.show	= _name##_show,						\
}
#define __ATTR_RO_MODE(_name, _mode) {					\
	.attr	= { .name = __stringify(_name),				\
		    .mode = VERIFY_OCTAL_PERMISSIONS(_mode) },		\
	.show	= _name##_show,						\
}
#define __ATTR_RW(_name) __ATTR(_name, 0644, _name##_show, _name##_store)
#define __ATTR_WO(_name) {						\
	.attr	= { .name = __stringify(_name), .mode = 0200 },		\
	.store	= _name##_store,					\
}
#define __BIN_ATTR(_name, _mode, _read, _write, _size) {		\
	.attr = { .name = __stringify(_name), .mode = _mode },		\
	.read	= _read,						\
	.write	= _write,						\
	.size	= _size,						\
}
#define __BIN_ATTR_NULL __ATTR_NULL
#define __BIN_ATTR_RO(_name, _size) {					\
	.attr	= { .name = __stringify(_name), .mode = 0444 },		\
	.read	= _name##_read,						\
	.size	= _size,						\
}
#define __BIN_ATTR_RW(_name, _size)					\
	__BIN_ATTR(_name, 0644, _name##_read, _name##_write, _size)
#define __BIN_ATTR_WO(_name, _size) {					\
	.attr	= { .name = __stringify(_name), .mode = 0200 },		\
	.write	= _name##_write,					\
	.size	= _size,						\
}
#define sysfs_attr_init(attr)				\
do {							\
	static struct lock_class_key __key;		\
							\
	(attr)->key = &__key;				\
} while (0)
#define sysfs_bin_attr_init(bin_attr) sysfs_attr_init(&(bin_attr)->attr)
#define KSTAT_QUERY_FLAGS (AT_STATX_SYNC_TYPE)

#define S_IFBLK  0060000
#define S_IFCHR  0020000
#define S_IFDIR  0040000
#define S_IFIFO  0010000
#define S_IFMT  00170000
#define S_IFREG  0100000
#define S_IFSOCK 0140000
#define S_IRGRP 00040
#define S_IROTH 00004
#define S_IRUSR 00400
#define S_IRWXG 00070
#define S_IRWXO 00007
#define S_IRWXU 00700
#define S_ISBLK(m)	(((m) & S_IFMT) == S_IFBLK)
#define S_ISCHR(m)	(((m) & S_IFMT) == S_IFCHR)
#define S_ISDIR(m)	(((m) & S_IFMT) == S_IFDIR)
#define S_ISFIFO(m)	(((m) & S_IFMT) == S_IFIFO)
#define S_ISGID  0002000
#define S_ISLNK(m)	(((m) & S_IFMT) == S_IFLNK)
#define S_ISREG(m)	(((m) & S_IFMT) == S_IFREG)
#define S_ISSOCK(m)	(((m) & S_IFMT) == S_IFSOCK)
#define S_ISUID  0004000
#define S_ISVTX  0001000
#define S_IWGRP 00020
#define S_IWOTH 00002
#define S_IWUSR 00200
#define S_IXGRP 00010
#define S_IXOTH 00001
#define S_IXUSR 00100


#define DEFINE_IDA(name)	struct ida name = IDA_INIT(name)
#define DEFINE_IDR(name)	struct idr name = IDR_INIT(name)
#define IDA_BITMAP_BITS 	(IDA_BITMAP_LONGS * sizeof(long) * 8)
#define IDA_INIT(name)	{						\
	.xa = XARRAY_INIT(name, IDA_INIT_FLAGS)				\
}
#define IDR_INIT_BASE(name, base) {					\
	.idr_rt = RADIX_TREE_INIT(name, IDR_RT_MARKER),			\
	.idr_base = (base),						\
	.idr_next = 0,							\
}

#define ida_simple_get(ida, start, end, gfp)	\
			ida_alloc_range(ida, start, (end) - 1, gfp)
#define ida_simple_remove(ida, id)	ida_free(ida, id)
#define idr_for_each_entry(idr, entry, id)			\
	for (id = 0; ((entry) = idr_get_next(idr, &(id))) != NULL; id += 1U)
#define idr_for_each_entry_continue(idr, entry, id)			\
	for ((entry) = idr_get_next((idr), &(id));			\
	     entry;							\
	     ++id, (entry) = idr_get_next((idr), &(id)))
#define idr_for_each_entry_continue_ul(idr, entry, tmp, id)		\
	for (tmp = id;							\
	     tmp <= id && ((entry) = idr_get_next_ul(idr, &(id))) != NULL; \
	     tmp = id, ++id)
#define idr_for_each_entry_ul(idr, entry, tmp, id)			\
	for (tmp = 0, id = 0;						\
	     tmp <= id && ((entry) = idr_get_next_ul(idr, &(id))) != NULL; \
	     tmp = id, ++id)
#define idr_lock(idr)		xa_lock(&(idr)->idr_rt)
#define idr_lock_bh(idr)	xa_lock_bh(&(idr)->idr_rt)
#define idr_lock_irq(idr)	xa_lock_irq(&(idr)->idr_rt)
#define idr_lock_irqsave(idr, flags) \
				xa_lock_irqsave(&(idr)->idr_rt, flags)
#define idr_unlock(idr)		xa_unlock(&(idr)->idr_rt)
#define idr_unlock_bh(idr)	xa_unlock_bh(&(idr)->idr_rt)
#define idr_unlock_irq(idr)	xa_unlock_irq(&(idr)->idr_rt)
#define idr_unlock_irqrestore(idr, flags) \
				xa_unlock_irqrestore(&(idr)->idr_rt, flags)
#define GFP_DMA		__GFP_DMA
#define GFP_KERNEL_ACCOUNT (GFP_KERNEL | __GFP_ACCOUNT)
#define GFP_MOVABLE_MASK (__GFP_RECLAIMABLE|__GFP_MOVABLE)
#define GFP_MOVABLE_SHIFT 3
#define GFP_ZONES_SHIFT 2
#define GFP_ZONE_BAD ( \
	1 << (___GFP_DMA | ___GFP_HIGHMEM)				      \
	| 1 << (___GFP_DMA | ___GFP_DMA32)				      \
	| 1 << (___GFP_DMA32 | ___GFP_HIGHMEM)				      \
	| 1 << (___GFP_DMA | ___GFP_DMA32 | ___GFP_HIGHMEM)		      \
	| 1 << (___GFP_MOVABLE | ___GFP_HIGHMEM | ___GFP_DMA)		      \
	| 1 << (___GFP_MOVABLE | ___GFP_DMA32 | ___GFP_DMA)		      \
	| 1 << (___GFP_MOVABLE | ___GFP_DMA32 | ___GFP_HIGHMEM)		      \
	| 1 << (___GFP_MOVABLE | ___GFP_DMA32 | ___GFP_DMA | ___GFP_HIGHMEM)  \
)
#define GFP_ZONE_TABLE ( \
	(ZONE_NORMAL << 0 * GFP_ZONES_SHIFT)				       \
	| (OPT_ZONE_DMA << ___GFP_DMA * GFP_ZONES_SHIFT)		       \
	| (OPT_ZONE_HIGHMEM << ___GFP_HIGHMEM * GFP_ZONES_SHIFT)	       \
	| (OPT_ZONE_DMA32 << ___GFP_DMA32 * GFP_ZONES_SHIFT)		       \
	| (ZONE_NORMAL << ___GFP_MOVABLE * GFP_ZONES_SHIFT)		       \
	| (OPT_ZONE_DMA << (___GFP_MOVABLE | ___GFP_DMA) * GFP_ZONES_SHIFT)    \
	| (ZONE_MOVABLE << (___GFP_MOVABLE | ___GFP_HIGHMEM) * GFP_ZONES_SHIFT)\
	| (OPT_ZONE_DMA32 << (___GFP_MOVABLE | ___GFP_DMA32) * GFP_ZONES_SHIFT)\
)
#define OPT_ZONE_DMA ZONE_DMA
#define OPT_ZONE_DMA32 ZONE_DMA32
#define OPT_ZONE_HIGHMEM ZONE_HIGHMEM
#define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) - 1))
#define __GFP_BITS_SHIFT (23 + IS_ENABLED(CONFIG_LOCKDEP))
#define __GFP_HARDWALL   ((__force gfp_t)___GFP_HARDWALL)
#define __GFP_NOLOCKDEP ((__force gfp_t)___GFP_NOLOCKDEP)
#define __GFP_NOMEMALLOC ((__force gfp_t)___GFP_NOMEMALLOC)
#define __GFP_RECLAIM ((__force gfp_t)(___GFP_DIRECT_RECLAIM|___GFP_KSWAPD_RECLAIM))
#define __GFP_RECLAIMABLE ((__force gfp_t)___GFP_RECLAIMABLE)

#define __free_page(page) __free_pages((page), 0)
#define __get_dma_pages(gfp_mask, order) \
		__get_free_pages((gfp_mask) | GFP_DMA, (order))
#define __get_free_page(gfp_mask) \
		__get_free_pages((gfp_mask), 0)
#define alloc_hugepage_vma(gfp_mask, vma, addr, order) \
	alloc_pages_vma(gfp_mask, order, vma, addr, numa_node_id(), true)
#define alloc_page(gfp_mask) alloc_pages(gfp_mask, 0)
#define alloc_page_vma(gfp_mask, vma, addr)			\
	alloc_pages_vma(gfp_mask, 0, vma, addr, numa_node_id(), false)
#define alloc_page_vma_node(gfp_mask, vma, addr, node)		\
	alloc_pages_vma(gfp_mask, 0, vma, addr, node, false)
#define alloc_pages(gfp_mask, order) \
		alloc_pages_node(numa_node_id(), gfp_mask, order)
#define alloc_pages_vma(gfp_mask, order, vma, addr, node, false)\
	alloc_pages(gfp_mask, order)
#define free_page(addr) free_pages((addr), 0)
#define RECLAIM_DISTANCE 30

#define for_each_node_with_cpus(node)			\
	for_each_online_node(node)			\
		if (nr_cpus_node(node))
#define node_distance(from,to)	((from) == (to) ? LOCAL_DISTANCE : REMOTE_DISTANCE)
#define nr_cpus_node(node) cpumask_weight(cpumask_of_node(node))
#define topology_core_cpumask(cpu)		cpumask_of(cpu)
#define topology_core_id(cpu)			((void)(cpu), 0)
#define topology_die_cpumask(cpu)		cpumask_of(cpu)
#define topology_die_id(cpu)			((void)(cpu), -1)
#define topology_physical_package_id(cpu)	((void)(cpu), -1)
#define topology_sibling_cpumask(cpu)		cpumask_of(cpu)
#define DEF_PRIORITY 12
#define LRU_ACTIVE 1
#define LRU_BASE 0
#define LRU_FILE 2
#define MAX_ORDER 11
#define MAX_ORDER_NR_PAGES (1 << (MAX_ORDER - 1))
#define MAX_ZONES_PER_ZONELIST (MAX_NUMNODES * MAX_NR_ZONES)
#define MIGRATETYPE_MASK ((1UL << NR_MIGRATETYPE_BITS) - 1)
#define NODE_DATA(nid)		(&contig_page_data)
#define NODE_MEM_MAP(nid)	mem_map
#define NR_MIGRATETYPE_BITS (PB_migrate_end - PB_migrate + 1)
#define NR_VM_NUMA_STAT_ITEMS 0
#define PAGES_PER_SECTION       (1UL << PFN_SECTION_SHIFT)
#define PAGES_PER_SUBSECTION (1UL << PFN_SUBSECTION_SHIFT)
#define PAGE_ALLOC_COSTLY_ORDER 3
#define PAGE_SUBSECTION_MASK (~(PAGES_PER_SUBSECTION-1))
#define PFN_SUBSECTION_SHIFT (SUBSECTION_SHIFT - PAGE_SHIFT)
#define SECTIONS_PER_ROOT       (PAGE_SIZE / sizeof (struct mem_section))
#define SECTION_ALIGN_DOWN(pfn)	((pfn) & PAGE_SECTION_MASK)
#define SECTION_ALIGN_UP(pfn)	(((pfn) + PAGES_PER_SECTION - 1) & PAGE_SECTION_MASK)
#define SECTION_BLOCKFLAGS_BITS \
	((1UL << (PFN_SECTION_SHIFT - pageblock_order)) * NR_PAGEBLOCK_BITS)
#define SECTION_NR_TO_ROOT(sec)	((sec) / SECTIONS_PER_ROOT)
#define SUBSECTIONS_PER_SECTION (1UL << (SECTION_SIZE_BITS - SUBSECTION_SHIFT))
#define SUBSECTION_ALIGN_DOWN(pfn) ((pfn) & PAGE_SUBSECTION_MASK)
#define SUBSECTION_ALIGN_UP(pfn) ALIGN((pfn), PAGES_PER_SUBSECTION)
#define SUBSECTION_SHIFT 21
#define ZONE_PADDING(name)	struct zone_padding name;

#define early_pfn_valid(pfn)	pfn_valid(pfn)
#define for_each_evictable_lru(lru) for (lru = 0; lru <= LRU_ACTIVE_FILE; lru++)
#define for_each_lru(lru) for (lru = 0; lru < NR_LRU_LISTS; lru++)
#define for_each_migratetype_order(order, type) \
	for (order = 0; order < MAX_ORDER; order++) \
		for (type = 0; type < MIGRATE_TYPES; type++)
#define for_each_online_pgdat(pgdat)			\
	for (pgdat = first_online_pgdat();		\
	     pgdat;					\
	     pgdat = next_online_pgdat(pgdat))
#define for_each_populated_zone(zone)		        \
	for (zone = (first_online_pgdat())->node_zones; \
	     zone;					\
	     zone = next_zone(zone))			\
		if (!populated_zone(zone))		\
			; 		\
		else
#define for_each_zone(zone)			        \
	for (zone = (first_online_pgdat())->node_zones; \
	     zone;					\
	     zone = next_zone(zone))
#define for_each_zone_zonelist(zone, z, zlist, highidx) \
	for_each_zone_zonelist_nodemask(zone, z, zlist, highidx, NULL)
#define for_each_zone_zonelist_nodemask(zone, z, zlist, highidx, nodemask) \
	for (z = first_zones_zonelist(zlist, highidx, nodemask), zone = zonelist_zone(z);	\
		zone;							\
		z = next_zones_zonelist(++z, highidx, nodemask),	\
			zone = zonelist_zone(z))
#define for_next_zone_zonelist_nodemask(zone, z, zlist, highidx, nodemask) \
	for (zone = z->zone;	\
		zone;							\
		z = next_zones_zonelist(++z, highidx, nodemask),	\
			zone = zonelist_zone(z))
#define get_pageblock_migratetype(page)					\
	get_pfnblock_flags_mask(page, page_to_pfn(page),		\
			PB_migrate_end, MIGRATETYPE_MASK)
#define high_wmark_pages(z) (z->_watermark[WMARK_HIGH] + z->watermark_boost)
#  define is_migrate_cma(migratetype) unlikely((migratetype) == MIGRATE_CMA)
#  define is_migrate_cma_page(_page) (get_pageblock_migratetype(_page) == MIGRATE_CMA)
#define low_wmark_pages(z) (z->_watermark[WMARK_LOW] + z->watermark_boost)
#define min_wmark_pages(z) (z->_watermark[WMARK_MIN] + z->watermark_boost)
#define nid_page_nr(nid, pagenr) 	pgdat_page_nr(NODE_DATA(nid),(pagenr))
#define node_end_pfn(nid) pgdat_end_pfn(NODE_DATA(nid))
#define pfn_present pfn_valid
#define pfn_to_nid(pfn)		(0)
#define pfn_valid_within(pfn) pfn_valid(pfn)
#define pgdat_page_nr(pgdat, pagenr)	((pgdat)->node_mem_map + (pagenr))
#define sparse_index_init(_sec, _nid)  do {} while (0)
#define sparse_init()	do {} while (0)
#define subsection_map_init(_pfn, _nr_pages) do {} while (0)
#define wmark_pages(z, i) (z->_watermark[i] + z->watermark_boost)
#define zone_idx(zone)		((zone) - (zone)->zone_pgdat->node_zones)

#define arch_alloc_nodedata(nid)	generic_alloc_nodedata(nid)
#define arch_free_nodedata(pgdat)	generic_free_nodedata(pgdat)
#define generic_alloc_nodedata(nid)				\
({								\
	kzalloc(sizeof(pg_data_t), GFP_KERNEL);			\
})
#define generic_free_nodedata(pgdat)	kfree(pgdat)
#define pfn_to_online_page(pfn)			\
({						\
	struct page *___page = NULL;		\
	if (pfn_valid(pfn))			\
		___page = pfn_to_page(pfn);	\
	___page;				\
 })
#define ATOMIC_INIT_NOTIFIER_HEAD(name) do {	\
		spin_lock_init(&(name)->lock);	\
		(name)->head = NULL;		\
	} while (0)
#define ATOMIC_NOTIFIER_HEAD(name)				\
	struct atomic_notifier_head name =			\
		ATOMIC_NOTIFIER_INIT(name)
#define ATOMIC_NOTIFIER_INIT(name) {				\
		.lock = __SPIN_LOCK_UNLOCKED(name.lock),	\
		.head = NULL }
#define BLOCKING_INIT_NOTIFIER_HEAD(name) do {	\
		init_rwsem(&(name)->rwsem);	\
		(name)->head = NULL;		\
	} while (0)
#define BLOCKING_NOTIFIER_HEAD(name)				\
	struct blocking_notifier_head name =			\
		BLOCKING_NOTIFIER_INIT(name)
#define BLOCKING_NOTIFIER_INIT(name) {				\
		.rwsem = __RWSEM_INITIALIZER((name).rwsem),	\
		.head = NULL }
#define NOTIFY_STOP		(NOTIFY_OK|NOTIFY_STOP_MASK)
#define RAW_INIT_NOTIFIER_HEAD(name) do {	\
		(name)->head = NULL;		\
	} while (0)
#define RAW_NOTIFIER_HEAD(name)					\
	struct raw_notifier_head name =				\
		RAW_NOTIFIER_INIT(name)
#define RAW_NOTIFIER_INIT(name)	{				\
		.head = NULL }
#define SRCU_NOTIFIER_HEAD(name)				\
	_SRCU_NOTIFIER_HEAD(name, )
#define SRCU_NOTIFIER_HEAD_STATIC(name)				\
	_SRCU_NOTIFIER_HEAD(name, static)
#define SRCU_NOTIFIER_INIT(name, pcpu)				\
	{							\
		.mutex = __MUTEX_INITIALIZER(name.mutex),	\
		.head = NULL,					\
		.srcu = __SRCU_STRUCT_INIT(name.srcu, pcpu),	\
	}

#define _SRCU_NOTIFIER_HEAD(name, mod)				\
	static DEFINE_PER_CPU(struct srcu_data, name##_head_srcu_data); \
	mod struct srcu_notifier_head name =			\
			SRCU_NOTIFIER_INIT(name, name##_head_srcu_data)
#define srcu_cleanup_notifier_head(name)	\
		cleanup_srcu_struct(&(name)->srcu);

#define __SRCU_DEP_MAP_INIT(srcu_name)	.dep_map = { .name = #srcu_name },
#define init_srcu_struct(ssp) \
({ \
	static struct lock_class_key __srcu_key; \
	\
	__init_srcu_struct((ssp), #ssp, &__srcu_key); \
})
#define srcu_dereference(p, ssp) srcu_dereference_check((p), (ssp), 0)
#define srcu_dereference_check(p, ssp, c) \
	__rcu_dereference_check((p), (c) || srcu_read_lock_held(ssp), __rcu)
#define srcu_dereference_notrace(p, ssp) srcu_dereference_check((p), (ssp), 1)
#define DEFINE_SRCU(name)		__DEFINE_SRCU(name, )
#define DEFINE_STATIC_SRCU(name)	__DEFINE_SRCU(name, static)

# define __DEFINE_SRCU(name, is_static)					\
	is_static struct srcu_struct name;				\
	struct srcu_struct * const __srcu_struct_##name			\
		__section("___srcu_struct_ptrs") = &name
#define __SRCU_STRUCT_INIT(name, pcpu_name)				\
{									\
	.sda = &pcpu_name,						\
	.lock = __SPIN_LOCK_UNLOCKED(name.lock),			\
	.srcu_gp_seq_needed = -1UL,					\
	.work = __DELAYED_WORK_INITIALIZER(name.work, NULL, 0),		\
	__SRCU_DEP_MAP_INIT(name)					\
}
#  define NUM_RCU_LVL_INIT    { NUM_RCU_LVL_0 }
# define RCU_FANOUT 64
#define RCU_FANOUT_LEAF 16
#  define RCU_FQS_NAME_INIT   { "rcu_node_fqs_0" }
#  define RCU_NODE_NAME_INIT  { "rcu_node_0" }


#define DECLARE_SWAITQUEUE(name)					\
	struct swait_queue name = __SWAITQUEUE_INITIALIZER(name)
#define DECLARE_SWAIT_QUEUE_HEAD(name)					\
	struct swait_queue_head name = __SWAIT_QUEUE_HEAD_INITIALIZER(name)
# define DECLARE_SWAIT_QUEUE_HEAD_ONSTACK(name)			\
	struct swait_queue_head name = __SWAIT_QUEUE_HEAD_INIT_ONSTACK(name)

#define __SWAITQUEUE_INITIALIZER(name) {				\
	.task		= current,					\
	.task_list	= LIST_HEAD_INIT((name).task_list),		\
}
#define __SWAIT_QUEUE_HEAD_INITIALIZER(name) {				\
	.lock		= __RAW_SPIN_LOCK_UNLOCKED(name.lock),		\
	.task_list	= LIST_HEAD_INIT((name).task_list),		\
}
# define __SWAIT_QUEUE_HEAD_INIT_ONSTACK(name)			\
	({ init_swait_queue_head(&name); name; })
#define ___swait_event(wq, condition, state, ret, cmd)			\
({									\
	__label__ __out;						\
	struct swait_queue __wait;					\
	long __ret = ret;						\
									\
	INIT_LIST_HEAD(&__wait.task_list);				\
	for (;;) {							\
		long __int = prepare_to_swait_event(&wq, &__wait, state);\
									\
		if (condition)						\
			break;						\
									\
		if (___wait_is_interruptible(state) && __int) {		\
			__ret = __int;					\
			goto __out;					\
		}							\
									\
		cmd;							\
	}								\
	finish_swait(&wq, &__wait);					\
__out:	__ret;								\
})
#define __swait_event(wq, condition)					\
	(void)___swait_event(wq, condition, TASK_UNINTERRUPTIBLE, 0,	\
			    schedule())
#define __swait_event_idle(wq, condition)				\
	(void)___swait_event(wq, condition, TASK_IDLE, 0, schedule())
#define __swait_event_idle_timeout(wq, condition, timeout)		\
	___swait_event(wq, ___wait_cond_timeout(condition),		\
		       TASK_IDLE, timeout,				\
		       __ret = schedule_timeout(__ret))
#define __swait_event_interruptible(wq, condition)			\
	___swait_event(wq, condition, TASK_INTERRUPTIBLE, 0,		\
		      schedule())
#define __swait_event_interruptible_timeout(wq, condition, timeout)	\
	___swait_event(wq, ___wait_cond_timeout(condition),		\
		      TASK_INTERRUPTIBLE, timeout,			\
		      __ret = schedule_timeout(__ret))
#define __swait_event_timeout(wq, condition, timeout)			\
	___swait_event(wq, ___wait_cond_timeout(condition),		\
		      TASK_UNINTERRUPTIBLE, timeout,			\
		      __ret = schedule_timeout(__ret))
#define init_swait_queue_head(q)				\
	do {							\
		static struct lock_class_key __key;		\
		__init_swait_queue_head((q), #q, &__key);	\
	} while (0)
#define swait_event_exclusive(wq, condition)				\
do {									\
	if (condition)							\
		break;							\
	__swait_event(wq, condition);					\
} while (0)
#define swait_event_idle_exclusive(wq, condition)			\
do {									\
	if (condition)							\
		break;							\
	__swait_event_idle(wq, condition);				\
} while (0)
#define swait_event_idle_timeout_exclusive(wq, condition, timeout)	\
({									\
	long __ret = timeout;						\
	if (!___wait_cond_timeout(condition))				\
		__ret = __swait_event_idle_timeout(wq,			\
						   condition, timeout);	\
	__ret;								\
})
#define swait_event_interruptible_exclusive(wq, condition)		\
({									\
	int __ret = 0;							\
	if (!(condition))						\
		__ret = __swait_event_interruptible(wq, condition);	\
	__ret;								\
})
#define swait_event_interruptible_timeout_exclusive(wq, condition, timeout)\
({									\
	long __ret = timeout;						\
	if (!___wait_cond_timeout(condition))				\
		__ret = __swait_event_interruptible_timeout(wq,		\
						condition, timeout);	\
	__ret;								\
})
#define swait_event_timeout_exclusive(wq, condition, timeout)		\
({									\
	long __ret = timeout;						\
	if (!___wait_cond_timeout(condition))				\
		__ret = __swait_event_timeout(wq, condition, timeout);	\
	__ret;								\
})
#define RCU_CBLIST_INITIALIZER(n) { .head = NULL, .tail = &n.head }
#define RCU_SEGCBLIST_INITIALIZER(n) \
{ \
	.head = NULL, \
	.tails[RCU_DONE_TAIL] = &n.head, \
	.tails[RCU_WAIT_TAIL] = &n.head, \
	.tails[RCU_NEXT_READY_TAIL] = &n.head, \
	.tails[RCU_NEXT_TAIL] = &n.head, \
}

#define DECLARE_RWSEM(name) \
	struct rw_semaphore name = __RWSEM_INITIALIZER(name)

# define __DEBUG_RWSEM_INITIALIZER(lockname) , .magic = &lockname
# define __RWSEM_DEP_MAP_INIT(lockname) , .dep_map = { .name = #lockname }
#define __RWSEM_INITIALIZER(name)				\
	{ __RWSEM_INIT_COUNT(name),				\
	  .owner = ATOMIC_LONG_INIT(0),				\
	  .wait_list = LIST_HEAD_INIT((name).wait_list),	\
	  .wait_lock = __RAW_SPIN_LOCK_UNLOCKED(name.wait_lock)	\
	  __RWSEM_OPT_INIT(name)				\
	  __DEBUG_RWSEM_INITIALIZER(name)			\
	  __RWSEM_DEP_MAP_INIT(name) }
#define __RWSEM_INIT_COUNT(name)	.count = ATOMIC_LONG_INIT(RWSEM_UNLOCKED_VALUE)
#define __RWSEM_OPT_INIT(lockname) , .osq = OSQ_LOCK_UNLOCKED
# define down_read_nested(sem, subclass)		down_read(sem)
# define down_read_non_owner(sem)		down_read(sem)
# define down_write_killable_nested(sem, subclass)	down_write_killable(sem)
# define down_write_nest_lock(sem, nest_lock)			\
do {								\
	typecheck(struct lockdep_map *, &(nest_lock)->dep_map);	\
	_down_write_nest_lock(sem, &(nest_lock)->dep_map);	\
} while (0);
# define down_write_nested(sem, subclass)	down_write(sem)
#define init_rwsem(sem)						\
do {								\
	static struct lock_class_key __key;			\
								\
	__init_rwsem((sem), #sem, &__key);			\
} while (0)
# define up_read_non_owner(sem)			up_read(sem)
#define IS_ERR_VALUE(x) unlikely((unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO)
#define PTR_RET(p) PTR_ERR_OR_ZERO(p)

#define CLEARPAGEFLAG(uname, lname, policy)				\
static __always_inline void ClearPage##uname(struct page *page)		\
	{ clear_bit(PG_##lname, &policy(page, 1)->flags); }
#define CLEARPAGEFLAG_NOOP(uname)					\
static inline void ClearPage##uname(struct page *page) {  }
#define PAGEFLAG(uname, lname, policy)					\
	TESTPAGEFLAG(uname, lname, policy)				\
	SETPAGEFLAG(uname, lname, policy)				\
	CLEARPAGEFLAG(uname, lname, policy)
#define PAGEFLAG_FALSE(uname) TESTPAGEFLAG_FALSE(uname)			\
	SETPAGEFLAG_NOOP(uname) CLEARPAGEFLAG_NOOP(uname)

#define PAGE_TYPE_OPS(uname, lname)					\
static __always_inline int Page##uname(struct page *page)		\
{									\
	return PageType(page, PG_##lname);				\
}									\
static __always_inline void __SetPage##uname(struct page *page)		\
{									\
	VM_BUG_ON_PAGE(!PageType(page, 0), page);			\
	page->page_type &= ~PG_##lname;					\
}									\
static __always_inline void __ClearPage##uname(struct page *page)	\
{									\
	VM_BUG_ON_PAGE(!Page##uname(page), page);			\
	page->page_type |= PG_##lname;					\
}
#define PF_ANY(page, enforce)	PF_POISONED_CHECK(page)
#define PF_HEAD(page, enforce)	PF_POISONED_CHECK(compound_head(page))
#define PF_NO_COMPOUND(page, enforce) ({				\
		VM_BUG_ON_PGFLAGS(enforce && PageCompound(page), page);	\
		PF_POISONED_CHECK(page); })
#define PF_NO_TAIL(page, enforce) ({					\
		VM_BUG_ON_PGFLAGS(enforce && PageTail(page), page);	\
		PF_POISONED_CHECK(compound_head(page)); })
#define PF_ONLY_HEAD(page, enforce) ({					\
		VM_BUG_ON_PGFLAGS(PageTail(page), page);		\
		PF_POISONED_CHECK(page); })
#define PF_POISONED_CHECK(page) ({					\
		VM_BUG_ON_PGFLAGS(PagePoisoned(page), page);		\
		page; })
#define PG_head_mask ((1UL << PG_head))
#define PageHighMem(__p) is_highmem_idx(page_zonenum(__p))
#define PageType(page, flag)						\
	((page->page_type & (PAGE_TYPE_BASE | flag)) == PAGE_TYPE_BASE)
#define SETPAGEFLAG(uname, lname, policy)				\
static __always_inline void SetPage##uname(struct page *page)		\
	{ set_bit(PG_##lname, &policy(page, 1)->flags); }
#define SETPAGEFLAG_NOOP(uname)						\
static inline void SetPage##uname(struct page *page) {  }
#define TESTCLEARFLAG(uname, lname, policy)				\
static __always_inline int TestClearPage##uname(struct page *page)	\
	{ return test_and_clear_bit(PG_##lname, &policy(page, 1)->flags); }
#define TESTCLEARFLAG_FALSE(uname)					\
static inline int TestClearPage##uname(struct page *page) { return 0; }
#define TESTPAGEFLAG(uname, lname, policy)				\
static __always_inline int Page##uname(struct page *page)		\
	{ return test_bit(PG_##lname, &policy(page, 0)->flags); }
#define TESTPAGEFLAG_FALSE(uname)					\
static inline int Page##uname(const struct page *page) { return 0; }
#define TESTSCFLAG(uname, lname, policy)				\
	TESTSETFLAG(uname, lname, policy)				\
	TESTCLEARFLAG(uname, lname, policy)
#define TESTSCFLAG_FALSE(uname)						\
	TESTSETFLAG_FALSE(uname) TESTCLEARFLAG_FALSE(uname)
#define TESTSETFLAG(uname, lname, policy)				\
static __always_inline int TestSetPage##uname(struct page *page)	\
	{ return test_and_set_bit(PG_##lname, &policy(page, 1)->flags); }
#define TESTSETFLAG_FALSE(uname)					\
static inline int TestSetPage##uname(struct page *page) { return 0; }
#define __CLEARPAGEFLAG(uname, lname, policy)				\
static __always_inline void __ClearPage##uname(struct page *page)	\
	{ __clear_bit(PG_##lname, &policy(page, 1)->flags); }
#define __CLEARPAGEFLAG_NOOP(uname)					\
static inline void __ClearPage##uname(struct page *page) {  }
#define __PAGEFLAG(uname, lname, policy)				\
	TESTPAGEFLAG(uname, lname, policy)				\
	__SETPAGEFLAG(uname, lname, policy)				\
	__CLEARPAGEFLAG(uname, lname, policy)
#define __PG_HWPOISON (1UL << PG_hwpoison)
#define __SETPAGEFLAG(uname, lname, policy)				\
static __always_inline void __SetPage##uname(struct page *page)		\
	{ __set_bit(PG_##lname, &policy(page, 1)->flags); }
#define test_set_page_writeback(page)			\
	__test_set_page_writeback(page, false)
#define test_set_page_writeback_keepwrite(page)	\
	__test_set_page_writeback(page, true)
#define AT_VECTOR_SIZE (2*(AT_VECTOR_SIZE_ARCH + AT_VECTOR_SIZE_BASE + 1))
#define AT_VECTOR_SIZE_ARCH 0
#define NULL_VM_UFFD_CTX ((struct vm_userfaultfd_ctx) { NULL, })
#define VM_FAULT_ERROR (VM_FAULT_OOM | VM_FAULT_SIGBUS |	\
			VM_FAULT_SIGSEGV | VM_FAULT_HWPOISON |	\
			VM_FAULT_HWPOISON_LARGE | VM_FAULT_FALLBACK)
#define VM_FAULT_GET_HINDEX(x) (((__force unsigned int)(x) >> 16) & 0xf)
#define VM_FAULT_RESULT_TRACE \
	{ VM_FAULT_OOM,                 "OOM" },	\
	{ VM_FAULT_SIGBUS,              "SIGBUS" },	\
	{ VM_FAULT_MAJOR,               "MAJOR" },	\
	{ VM_FAULT_WRITE,               "WRITE" },	\
	{ VM_FAULT_HWPOISON,            "HWPOISON" },	\
	{ VM_FAULT_HWPOISON_LARGE,      "HWPOISON_LARGE" },	\
	{ VM_FAULT_SIGSEGV,             "SIGSEGV" },	\
	{ VM_FAULT_NOPAGE,              "NOPAGE" },	\
	{ VM_FAULT_LOCKED,              "LOCKED" },	\
	{ VM_FAULT_RETRY,               "RETRY" },	\
	{ VM_FAULT_FALLBACK,            "FALLBACK" },	\
	{ VM_FAULT_DONE_COW,            "DONE_COW" },	\
	{ VM_FAULT_NEEDDSYNC,           "NEEDDSYNC" }
#define VM_FAULT_SET_HINDEX(x) ((__force vm_fault_t)((x) << 16))


#define page_private(page)		((page)->private)
#define set_page_private(page, v)	((page)->private = (v))
#define KASAN_TAG_WIDTH 8

#define LAST_CPUPID_SHIFT (LAST__PID_SHIFT+LAST__CPU_SHIFT)
#define LAST_CPUPID_WIDTH LAST_CPUPID_SHIFT
#define LAST__CPU_MASK  ((1 << LAST__CPU_SHIFT)-1)
#define LAST__CPU_SHIFT NR_CPUS_BITS
#define LAST__PID_MASK  ((1 << LAST__PID_SHIFT)-1)
#define LAST__PID_SHIFT 8


#define ZONES_SHIFT 0
#define MAX_NUMNODES    (1 << NODES_SHIFT)
#define NODES_SHIFT     CONFIG_NODES_SHIFT


#define uprobe_get_trap_addr(regs)	instruction_pointer(regs)
#define AT_VECTOR_SIZE_BASE 20 

#define AT_BASE   7	
#define AT_BASE_PLATFORM 24	
#define AT_CLKTCK 17	
#define AT_EGID   14	
#define AT_ENTRY  9	
#define AT_EUID   12	
#define AT_EXECFD 2	
#define AT_EXECFN  31	
#define AT_FLAGS  8	
#define AT_GID    13	
#define AT_HWCAP  16    
#define AT_HWCAP2 26	
#define AT_IGNORE 1	
#define AT_NOTELF 10	
#define AT_NULL   0	
#define AT_PAGESZ 6	
#define AT_PHDR   3	
#define AT_PHENT  4	
#define AT_PHNUM  5	
#define AT_PLATFORM 15  
#define AT_RANDOM 25	
#define AT_SECURE 23   
#define AT_UID    11	


#define VMACACHE_BITS 2
#define VMACACHE_MASK (VMACACHE_SIZE - 1)
#define VMACACHE_SIZE (1U << VMACACHE_BITS)


#define PB_migratetype_bits 3
#define clear_pageblock_skip(page) \
			set_pageblock_flags_group(page, 0, PB_migrate_skip,  \
							PB_migrate_skip)
#define get_pageblock_flags_group(page, start_bitidx, end_bitidx) \
	get_pfnblock_flags_mask(page, page_to_pfn(page),		\
			end_bitidx,					\
			(1 << (end_bitidx - start_bitidx + 1)) - 1)
#define get_pageblock_skip(page) \
			get_pageblock_flags_group(page, PB_migrate_skip,     \
							PB_migrate_skip)
#define set_pageblock_flags_group(page, flags, start_bitidx, end_bitidx) \
	set_pfnblock_flags_mask(page, flags, page_to_pfn(page),		\
			end_bitidx,					\
			(1 << (end_bitidx - start_bitidx + 1)) - 1)
#define set_pageblock_skip(page) \
			set_pageblock_flags_group(page, 1, PB_migrate_skip,  \
							PB_migrate_skip)
#define NODEMASK_ALLOC(type, name, gfp_flags)	\
			type *name = kmalloc(sizeof(*name), gfp_flags)
#define NODEMASK_FREE(m)			kfree(m)
#define NODEMASK_SCRATCH(x)						\
			NODEMASK_ALLOC(struct nodemask_scratch, x,	\
					GFP_KERNEL | __GFP_NORETRY)
#define NODEMASK_SCRATCH_FREE(x)	NODEMASK_FREE(x)
#define NODE_MASK_LAST_WORD BITMAP_LAST_WORD_MASK(MAX_NUMNODES)

#define first_node(src) __first_node(&(src))
#define first_unset_node(mask) __first_unset_node(&(mask))
#define for_each_node(node)	   for_each_node_state(node, N_POSSIBLE)
#define for_each_node_mask(node, mask)			\
	for ((node) = first_node(mask);			\
		(node) < MAX_NUMNODES;			\
		(node) = next_node((node), (mask)))
#define for_each_node_state(__node, __state) \
	for_each_node_mask((__node), node_states[__state])
#define for_each_online_node(node) for_each_node_state(node, N_ONLINE)
#define next_node(n, src) __next_node((n), &(src))
#define next_node_in(n, src) __next_node_in((n), &(src))
#define next_online_node(nid)	(MAX_NUMNODES)
#define node_clear(node, dst) __node_clear((node), &(dst))
#define node_isset(node, nodemask) test_bit((node), (nodemask).bits)
#define node_online(node)	node_state((node), N_ONLINE)
#define node_online_map 	node_states[N_ONLINE]
#define node_possible(node)	node_state((node), N_POSSIBLE)
#define node_possible_map 	node_states[N_POSSIBLE]
#define node_remap(oldbit, old, new) \
		__node_remap((oldbit), &(old), &(new), MAX_NUMNODES)
#define node_set(node, dst) __node_set((node), &(dst))
#define node_set_offline(node)	   node_clear_state((node), N_ONLINE)
#define node_set_online(node)	   node_set_state((node), N_ONLINE)
#define node_test_and_set(node, nodemask) \
			__node_test_and_set((node), &(nodemask))
#define nodelist_parse(buf, dst) __nodelist_parse((buf), &(dst), MAX_NUMNODES)
#define nodemask_of_node(node)						\
({									\
	typeof(_unused_nodemask_arg_) m;				\
	if (sizeof(m) == sizeof(unsigned long)) {			\
		m.bits[0] = 1UL << (node);				\
	} else {							\
		init_nodemask_of_node(&m, (node));			\
	}								\
	m;								\
})
#define nodemask_parse_user(ubuf, ulen, dst) \
		__nodemask_parse_user((ubuf), (ulen), &(dst), MAX_NUMNODES)
#define nodemask_pr_args(maskp)	__nodemask_pr_numnodes(maskp), \
				__nodemask_pr_bits(maskp)
#define nodes_addr(src) ((src).bits)
#define nodes_and(dst, src1, src2) \
			__nodes_and(&(dst), &(src1), &(src2), MAX_NUMNODES)
#define nodes_andnot(dst, src1, src2) \
			__nodes_andnot(&(dst), &(src1), &(src2), MAX_NUMNODES)
#define nodes_clear(dst) __nodes_clear(&(dst), MAX_NUMNODES)
#define nodes_complement(dst, src) \
			__nodes_complement(&(dst), &(src), MAX_NUMNODES)
#define nodes_empty(src) __nodes_empty(&(src), MAX_NUMNODES)
#define nodes_equal(src1, src2) \
			__nodes_equal(&(src1), &(src2), MAX_NUMNODES)
#define nodes_fold(dst, orig, sz) \
		__nodes_fold(&(dst), &(orig), sz, MAX_NUMNODES)
#define nodes_full(nodemask) __nodes_full(&(nodemask), MAX_NUMNODES)
#define nodes_intersects(src1, src2) \
			__nodes_intersects(&(src1), &(src2), MAX_NUMNODES)
#define nodes_onto(dst, orig, relmap) \
		__nodes_onto(&(dst), &(orig), &(relmap), MAX_NUMNODES)
#define nodes_or(dst, src1, src2) \
			__nodes_or(&(dst), &(src1), &(src2), MAX_NUMNODES)
#define nodes_remap(dst, src, old, new) \
		__nodes_remap(&(dst), &(src), &(old), &(new), MAX_NUMNODES)
#define nodes_setall(dst) __nodes_setall(&(dst), MAX_NUMNODES)
#define nodes_shift_left(dst, src, n) \
			__nodes_shift_left(&(dst), &(src), (n), MAX_NUMNODES)
#define nodes_shift_right(dst, src, n) \
			__nodes_shift_right(&(dst), &(src), (n), MAX_NUMNODES)
#define nodes_subset(src1, src2) \
			__nodes_subset(&(src1), &(src2), MAX_NUMNODES)
#define nodes_weight(nodemask) __nodes_weight(&(nodemask), MAX_NUMNODES)
#define nodes_xor(dst, src1, src2) \
			__nodes_xor(&(dst), &(src1), &(src2), MAX_NUMNODES)
#define num_online_nodes()	num_node_state(N_ONLINE)
#define num_possible_nodes()	num_node_state(N_POSSIBLE)
#define DEFINE_SEQLOCK(x) \
		seqlock_t x = __SEQLOCK_UNLOCKED(x)
#define SEQCNT_ZERO(lockname) { .sequence = 0, SEQCOUNT_DEP_MAP_INIT(lockname)}
# define SEQCOUNT_DEP_MAP_INIT(lockname) \
		.dep_map = { .name = #lockname } \


#define __SEQLOCK_UNLOCKED(lockname)			\
	{						\
		.seqcount = SEQCNT_ZERO(lockname),	\
		.lock =	__SPIN_LOCK_UNLOCKED(lockname)	\
	}
#define read_seqlock_excl_irqsave(lock, flags)				\
	do { flags = __read_seqlock_excl_irqsave(lock); } while (0)
# define seqcount_init(s)				\
	do {						\
		static struct lock_class_key __key;	\
		__seqcount_init((s), #s, &__key);	\
	} while (0)
# define seqcount_lockdep_reader_access(x)
#define seqlock_init(x)					\
	do {						\
		seqcount_init(&(x)->seqcount);		\
		spin_lock_init(&(x)->lock);		\
	} while (0)
#define write_seqlock_irqsave(lock, flags)				\
	do { flags = __write_seqlock_irqsave(lock); } while (0)

#define topology_llc_cpumask(cpu)	(&cpu_topology[cpu].llc_sibling)
#define INIT_RADIX_TREE(root, mask) xa_init_flags(root, mask)
#define RADIX_TREE(name, mask) \
	struct radix_tree_root name = RADIX_TREE_INIT(name, mask)
#define RADIX_TREE_INDEX_BITS  (8  * sizeof(unsigned long))
#define RADIX_TREE_INIT(name, mask)	XARRAY_INIT(name, mask)
#define RADIX_TREE_MAX_PATH (DIV_ROUND_UP(RADIX_TREE_INDEX_BITS, \
					  RADIX_TREE_MAP_SHIFT))

#define radix_tree_for_each_slot(slot, root, iter, start)		\
	for (slot = radix_tree_iter_init(iter, start) ;			\
	     slot || (slot = radix_tree_next_chunk(root, iter, 0)) ;	\
	     slot = radix_tree_next_slot(slot, iter, 0))
#define radix_tree_for_each_tagged(slot, root, iter, start, tag)	\
	for (slot = radix_tree_iter_init(iter, start) ;			\
	     slot || (slot = radix_tree_next_chunk(root, iter,		\
			      RADIX_TREE_ITER_TAGGED | tag)) ;		\
	     slot = radix_tree_next_slot(slot, iter,			\
				RADIX_TREE_ITER_TAGGED | tag))
#define DEFINE_XARRAY(name) DEFINE_XARRAY_FLAGS(name, 0)
#define DEFINE_XARRAY_ALLOC(name) DEFINE_XARRAY_FLAGS(name, XA_FLAGS_ALLOC)
#define DEFINE_XARRAY_ALLOC1(name) DEFINE_XARRAY_FLAGS(name, XA_FLAGS_ALLOC1)
#define DEFINE_XARRAY_FLAGS(name, flags)				\
	struct xarray name = XARRAY_INIT(name, flags)
#define XARRAY_INIT(name, flags) {				\
	.xa_lock = __SPIN_LOCK_UNLOCKED(name.xa_lock),		\
	.xa_flags = flags,					\
	.xa_head = NULL,					\
}
#define XA_BUG_ON(xa, x) do {					\
		if (x) {					\
			xa_dump(xa);				\
			BUG();					\
		}						\
	} while (0)
#define XA_ERROR(errno) ((struct xa_node *)(((unsigned long)errno << 2) | 2UL))
#define XA_FLAGS_MARK(mark)	((__force gfp_t)((1U << __GFP_BITS_SHIFT) << \
						(__force unsigned)(mark)))
#define XA_LIMIT(_min, _max) (struct xa_limit) { .min = _min, .max = _max }
#define XA_NODE_BUG_ON(node, x) do {				\
		if (x) {					\
			if (node) xa_dump_node(node);		\
			BUG();					\
		}						\
	} while (0)
#define XA_STATE(name, array, index)				\
	struct xa_state name = __XA_STATE(array, index, 0, 0)
#define XA_STATE_ORDER(name, array, index, order)		\
	struct xa_state name = __XA_STATE(array,		\
			(index >> order) << order,		\
			order - (order % XA_CHUNK_SHIFT),	\
			(1U << (order % XA_CHUNK_SHIFT)) - 1)

#define __XA_STATE(array, index, shift, sibs)  {	\
	.xa = array,					\
	.xa_index = index,				\
	.xa_shift = shift,				\
	.xa_sibs = sibs,				\
	.xa_offset = 0,					\
	.xa_pad = 0,					\
	.xa_node = XAS_RESTART,				\
	.xa_alloc = NULL,				\
	.xa_update = NULL				\
}
#define xa_for_each(xa, index, entry) \
	xa_for_each_start(xa, index, entry, 0)
#define xa_for_each_marked(xa, index, entry, filter) \
	for (index = 0, entry = xa_find(xa, &index, ULONG_MAX, filter); \
	     entry; entry = xa_find_after(xa, &index, ULONG_MAX, filter))
#define xa_for_each_range(xa, index, entry, start, last)		\
	for (index = start,						\
	     entry = xa_find(xa, &index, last, XA_PRESENT);		\
	     entry;							\
	     entry = xa_find_after(xa, &index, last, XA_PRESENT))
#define xa_for_each_start(xa, index, entry, start) \
	xa_for_each_range(xa, index, entry, start, ULONG_MAX)
#define xa_lock(xa)		spin_lock(&(xa)->xa_lock)
#define xa_lock_bh(xa)		spin_lock_bh(&(xa)->xa_lock)
#define xa_lock_bh_nested(xa, subclass) \
				spin_lock_bh_nested(&(xa)->xa_lock, subclass)
#define xa_lock_irq(xa)		spin_lock_irq(&(xa)->xa_lock)
#define xa_lock_irq_nested(xa, subclass) \
				spin_lock_irq_nested(&(xa)->xa_lock, subclass)
#define xa_lock_irqsave(xa, flags) \
				spin_lock_irqsave(&(xa)->xa_lock, flags)
#define xa_lock_irqsave_nested(xa, flags, subclass) \
		spin_lock_irqsave_nested(&(xa)->xa_lock, flags, subclass)
#define xa_lock_nested(xa, subclass) \
				spin_lock_nested(&(xa)->xa_lock, subclass)
#define xa_trylock(xa)		spin_trylock(&(xa)->xa_lock)
#define xa_unlock(xa)		spin_unlock(&(xa)->xa_lock)
#define xa_unlock_bh(xa)	spin_unlock_bh(&(xa)->xa_lock)
#define xa_unlock_irq(xa)	spin_unlock_irq(&(xa)->xa_lock)
#define xa_unlock_irqrestore(xa, flags) \
				spin_unlock_irqrestore(&(xa)->xa_lock, flags)
#define xas_for_each(xas, entry, max) \
	for (entry = xas_find(xas, max); entry; \
	     entry = xas_next_entry(xas, max))
#define xas_for_each_conflict(xas, entry) \
	while ((entry = xas_find_conflict(xas)))
#define xas_for_each_marked(xas, entry, max, mark) \
	for (entry = xas_find_marked(xas, max, mark); entry; \
	     entry = xas_next_marked(xas, max, mark))
#define xas_lock(xas)		xa_lock((xas)->xa)
#define xas_lock_bh(xas)	xa_lock_bh((xas)->xa)
#define xas_lock_irq(xas)	xa_lock_irq((xas)->xa)
#define xas_lock_irqsave(xas, flags) \
				xa_lock_irqsave((xas)->xa, flags)
#define xas_marked(xas, mark)	xa_marked((xas)->xa, (mark))
#define xas_trylock(xas)	xa_trylock((xas)->xa)
#define xas_unlock(xas)		xa_unlock((xas)->xa)
#define xas_unlock_bh(xas)	xa_unlock_bh((xas)->xa)
#define xas_unlock_irq(xas)	xa_unlock_irq((xas)->xa)
#define xas_unlock_irqrestore(xas, flags) \
				xa_unlock_irqrestore((xas)->xa, flags)
#define IS_BUILTIN(option) __is_defined(option)
#define IS_ENABLED(option) __or(IS_BUILTIN(option), IS_MODULE(option))
#define IS_MODULE(option) __is_defined(option##_MODULE)
#define IS_REACHABLE(option) __or(IS_BUILTIN(option), \
				__and(IS_MODULE(option), __is_defined(MODULE)))
#define __ARG_PLACEHOLDER_1 0,
#define __BIG_ENDIAN 4321

#define __LITTLE_ENDIAN 1234
#define ____and(arg1_or_junk, y)	__take_second_arg(arg1_or_junk y, 0)
#define ____is_defined(arg1_or_junk)	__take_second_arg(arg1_or_junk 1, 0)
#define ____or(arg1_or_junk, y)		__take_second_arg(arg1_or_junk 1, y)
#define ___and(x, y)			____and(__ARG_PLACEHOLDER_##x, y)
#define ___is_defined(val)		____is_defined(__ARG_PLACEHOLDER_##val)
#define ___or(x, y)			____or(__ARG_PLACEHOLDER_##x, y)
#define __and(x, y)			___and(x, y)
#define __is_defined(x)			___is_defined(x)
#define __or(x, y)			___or(x, y)
#define __take_second_arg(__ignored, val, ...) val
#define CLASS_ATTR_RO(_name) \
	struct class_attribute class_attr_##_name = __ATTR_RO(_name)
#define CLASS_ATTR_RW(_name) \
	struct class_attribute class_attr_##_name = __ATTR_RW(_name)
#define CLASS_ATTR_STRING(_name, _mode, _str) \
	struct class_attribute_string class_attr_##_name = \
		_CLASS_ATTR_STRING(_name, _mode, _str)
#define CLASS_ATTR_WO(_name) \
	struct class_attribute class_attr_##_name = __ATTR_WO(_name)
#define _CLASS_ATTR_STRING(_name, _mode, _str) \
	{ __ATTR(_name, _mode, show_class_attr_string, NULL), _str }

#define class_create(owner, name)		\
({						\
	static struct lock_class_key __key;	\
	__class_create(owner, name, &__key);	\
})
#define class_register(class)			\
({						\
	static struct lock_class_key __key;	\
	__class_register(class, &__key);	\
})

#define __signed_add_overflow(a, b, d) ({	\
	typeof(a) __a = (a);			\
	typeof(b) __b = (b);			\
	typeof(d) __d = (d);			\
	(void) (&__a == &__b);			\
	(void) (&__a == __d);			\
	*__d = (u64)__a + (u64)__b;		\
	(((~(__a ^ __b)) & (*__d ^ __a))	\
		& type_min(typeof(__a))) != 0;	\
})
#define __signed_mul_overflow(a, b, d) ({				\
	typeof(a) __a = (a);						\
	typeof(b) __b = (b);						\
	typeof(d) __d = (d);						\
	typeof(a) __tmax = type_max(typeof(a));				\
	typeof(a) __tmin = type_min(typeof(a));				\
	(void) (&__a == &__b);						\
	(void) (&__a == __d);						\
	*__d = (u64)__a * (u64)__b;					\
	(__b > 0   && (__a > __tmax/__b || __a < __tmin/__b)) ||	\
	(__b < (typeof(__b))-1  && (__a > __tmin/__b || __a < __tmax/__b)) || \
	(__b == (typeof(__b))-1 && __a == __tmin);			\
})
#define __signed_sub_overflow(a, b, d) ({	\
	typeof(a) __a = (a);			\
	typeof(b) __b = (b);			\
	typeof(d) __d = (d);			\
	(void) (&__a == &__b);			\
	(void) (&__a == __d);			\
	*__d = (u64)__a - (u64)__b;		\
	((((__a ^ __b)) & (*__d ^ __a))		\
		& type_min(typeof(__a))) != 0;	\
})
#define __type_half_max(type) ((type)1 << (8*sizeof(type) - 1 - is_signed_type(type)))
#define __unsigned_add_overflow(a, b, d) ({	\
	typeof(a) __a = (a);			\
	typeof(b) __b = (b);			\
	typeof(d) __d = (d);			\
	(void) (&__a == &__b);			\
	(void) (&__a == __d);			\
	*__d = __a + __b;			\
	*__d < __a;				\
})
#define __unsigned_mul_overflow(a, b, d) ({		\
	typeof(a) __a = (a);				\
	typeof(b) __b = (b);				\
	typeof(d) __d = (d);				\
	(void) (&__a == &__b);				\
	(void) (&__a == __d);				\
	*__d = __a * __b;				\
	__builtin_constant_p(__b) ?			\
	  __b > 0 && __a > type_max(typeof(__a)) / __b : \
	  __a > 0 && __b > type_max(typeof(__b)) / __a;	 \
})
#define __unsigned_sub_overflow(a, b, d) ({	\
	typeof(a) __a = (a);			\
	typeof(b) __b = (b);			\
	typeof(d) __d = (d);			\
	(void) (&__a == &__b);			\
	(void) (&__a == __d);			\
	*__d = __a - __b;			\
	__a < __b;				\
})
#define check_add_overflow(a, b, d)					\
	__builtin_choose_expr(is_signed_type(typeof(a)),		\
			__signed_add_overflow(a, b, d),			\
			__unsigned_add_overflow(a, b, d))
#define check_mul_overflow(a, b, d)					\
	__builtin_choose_expr(is_signed_type(typeof(a)),		\
			__signed_mul_overflow(a, b, d),			\
			__unsigned_mul_overflow(a, b, d))
#define check_shl_overflow(a, s, d) ({					\
	typeof(a) _a = a;						\
	typeof(s) _s = s;						\
	typeof(d) _d = d;						\
	u64 _a_full = _a;						\
	unsigned int _to_shift =					\
		is_non_negative(_s) && _s < 8 * sizeof(*d) ? _s : 0;	\
	*_d = (_a_full << _to_shift);					\
	(_to_shift != _s || is_negative(*_d) || is_negative(_a) ||	\
	(*_d >> _to_shift) != _a);					\
})
#define check_sub_overflow(a, b, d)					\
	__builtin_choose_expr(is_signed_type(typeof(a)),		\
			__signed_sub_overflow(a, b, d),			\
			__unsigned_sub_overflow(a, b, d))
#define is_negative(a) (!(is_non_negative(a)))
#define is_non_negative(a) ((a) > 0 || (a) == 0)
#define is_signed_type(type)       (((type)(-1)) < (type)1)
#define struct_size(p, member, n)					\
	__ab_c_size(n,							\
		    sizeof(*(p)->member) + __must_be_array((p)->member),\
		    sizeof(*(p)))
#define type_max(T) ((T)((__type_half_max(T) - 1) + __type_half_max(T)))
#define type_min(T) ((T)((T)-type_max(T)-(T)1))
#define DEFINE_RES_DMA(_dma)						\
	DEFINE_RES_DMA_NAMED((_dma), NULL)
#define DEFINE_RES_DMA_NAMED(_dma, _name)				\
	DEFINE_RES_NAMED((_dma), 1, (_name), IORESOURCE_DMA)
#define DEFINE_RES_IO(_start, _size)					\
	DEFINE_RES_IO_NAMED((_start), (_size), NULL)
#define DEFINE_RES_IO_NAMED(_start, _size, _name)			\
	DEFINE_RES_NAMED((_start), (_size), (_name), IORESOURCE_IO)
#define DEFINE_RES_IRQ(_irq)						\
	DEFINE_RES_IRQ_NAMED((_irq), NULL)
#define DEFINE_RES_IRQ_NAMED(_irq, _name)				\
	DEFINE_RES_NAMED((_irq), 1, (_name), IORESOURCE_IRQ)
#define DEFINE_RES_MEM(_start, _size)					\
	DEFINE_RES_MEM_NAMED((_start), (_size), NULL)
#define DEFINE_RES_MEM_NAMED(_start, _size, _name)			\
	DEFINE_RES_NAMED((_start), (_size), (_name), IORESOURCE_MEM)
#define DEFINE_RES_NAMED(_start, _size, _name, _flags)			\
	{								\
		.start = (_start),					\
		.end = (_start) + (_size) - 1,				\
		.name = (_name),					\
		.flags = (_flags),					\
		.desc = IORES_DESC_NONE,				\
	}
#define IORESOURCE_EXT_TYPE_BITS 0x01000000	
#define IORESOURCE_IRQ_OPTIONAL 	(1<<5)

#define __request_mem_region(start,n,name, excl) __request_region(&iomem_resource, (start), (n), (name), excl)
#define devm_release_mem_region(dev, start, n) \
	__devm_release_region(dev, &iomem_resource, (start), (n))
#define devm_release_region(dev, start, n) \
	__devm_release_region(dev, &ioport_resource, (start), (n))
#define devm_request_mem_region(dev,start,n,name) \
	__devm_request_region(dev, &iomem_resource, (start), (n), (name))
#define devm_request_region(dev,start,n,name) \
	__devm_request_region(dev, &ioport_resource, (start), (n), (name))
#define release_mem_region(start,n)	__release_region(&iomem_resource, (start), (n))
#define rename_region(region, newname) do { (region)->name = (newname); } while (0)
#define request_mem_region(start,n,name) __request_region(&iomem_resource, (start), (n), (name), 0)
#define request_mem_region_exclusive(start,n,name) \
	__request_region(&iomem_resource, (start), (n), (name), IORESOURCE_EXCLUSIVE)
#define request_muxed_region(start,n,name)	__request_region(&ioport_resource, (start), (n), (name), IORESOURCE_MUXED)
#define request_region(start,n,name)		__request_region(&ioport_resource, (start), (n), (name), 0)

#define dev_WARN(dev, format, arg...) \
	WARN(1, "%s %s: " format, dev_driver_string(dev), dev_name(dev), ## arg);
#define dev_WARN_ONCE(dev, condition, format, arg...) \
	WARN_ONCE(condition, "%s %s: " format, \
			dev_driver_string(dev), dev_name(dev), ## arg)
#define dev_alert(dev, fmt, ...)					\
	_dev_alert(dev, dev_fmt(fmt), ##__VA_ARGS__)
#define dev_alert_once(dev, fmt, ...)					\
	dev_level_once(dev_alert, dev, fmt, ##__VA_ARGS__)
#define dev_alert_ratelimited(dev, fmt, ...)				\
	dev_level_ratelimited(dev_alert, dev, fmt, ##__VA_ARGS__)
#define dev_crit(dev, fmt, ...)						\
	_dev_crit(dev, dev_fmt(fmt), ##__VA_ARGS__)
#define dev_crit_once(dev, fmt, ...)					\
	dev_level_once(dev_crit, dev, fmt, ##__VA_ARGS__)
#define dev_crit_ratelimited(dev, fmt, ...)				\
	dev_level_ratelimited(dev_crit, dev, fmt, ##__VA_ARGS__)
#define dev_dbg(dev, fmt, ...)						\
	dynamic_dev_dbg(dev, dev_fmt(fmt), ##__VA_ARGS__)
#define dev_dbg_once(dev, fmt, ...)					\
	dev_level_once(dev_dbg, dev, fmt, ##__VA_ARGS__)
#define dev_dbg_ratelimited(dev, fmt, ...)				\
do {									\
	static DEFINE_RATELIMIT_STATE(_rs,				\
				      DEFAULT_RATELIMIT_INTERVAL,	\
				      DEFAULT_RATELIMIT_BURST);		\
	DEFINE_DYNAMIC_DEBUG_METADATA(descriptor, fmt);			\
	if (DYNAMIC_DEBUG_BRANCH(descriptor) &&				\
	    __ratelimit(&_rs))						\
		__dynamic_dev_dbg(&descriptor, dev, dev_fmt(fmt),	\
				  ##__VA_ARGS__);			\
} while (0)
#define dev_emerg(dev, fmt, ...)					\
	_dev_emerg(dev, dev_fmt(fmt), ##__VA_ARGS__)
#define dev_emerg_once(dev, fmt, ...)					\
	dev_level_once(dev_emerg, dev, fmt, ##__VA_ARGS__)
#define dev_emerg_ratelimited(dev, fmt, ...)				\
	dev_level_ratelimited(dev_emerg, dev, fmt, ##__VA_ARGS__)
#define dev_err(dev, fmt, ...)						\
	_dev_err(dev, dev_fmt(fmt), ##__VA_ARGS__)
#define dev_err_once(dev, fmt, ...)					\
	dev_level_once(dev_err, dev, fmt, ##__VA_ARGS__)
#define dev_err_ratelimited(dev, fmt, ...)				\
	dev_level_ratelimited(dev_err, dev, fmt, ##__VA_ARGS__)
#define dev_fmt(fmt) fmt
#define dev_info(dev, fmt, ...)						\
	_dev_info(dev, dev_fmt(fmt), ##__VA_ARGS__)
#define dev_info_once(dev, fmt, ...)					\
	dev_level_once(dev_info, dev, fmt, ##__VA_ARGS__)
#define dev_info_ratelimited(dev, fmt, ...)				\
	dev_level_ratelimited(dev_info, dev, fmt, ##__VA_ARGS__)
#define dev_level_once(dev_level, dev, fmt, ...)			\
do {									\
	static bool __print_once __read_mostly;				\
									\
	if (!__print_once) {						\
		__print_once = true;					\
		dev_level(dev, fmt, ##__VA_ARGS__);			\
	}								\
} while (0)
#define dev_level_ratelimited(dev_level, dev, fmt, ...)			\
do {									\
	static DEFINE_RATELIMIT_STATE(_rs,				\
				      DEFAULT_RATELIMIT_INTERVAL,	\
				      DEFAULT_RATELIMIT_BURST);		\
	if (__ratelimit(&_rs))						\
		dev_level(dev, fmt, ##__VA_ARGS__);			\
} while (0)
#define dev_notice(dev, fmt, ...)					\
	_dev_notice(dev, dev_fmt(fmt), ##__VA_ARGS__)
#define dev_notice_once(dev, fmt, ...)					\
	dev_level_once(dev_notice, dev, fmt, ##__VA_ARGS__)
#define dev_notice_ratelimited(dev, fmt, ...)				\
	dev_level_ratelimited(dev_notice, dev, fmt, ##__VA_ARGS__)
#define dev_vdbg(dev, fmt, ...)						\
({									\
	if (0)								\
		dev_printk(KERN_DEBUG, dev, dev_fmt(fmt), ##__VA_ARGS__); \
})
#define dev_warn(dev, fmt, ...)						\
	_dev_warn(dev, dev_fmt(fmt), ##__VA_ARGS__)
#define dev_warn_once(dev, fmt, ...)					\
	dev_level_once(dev_warn, dev, fmt, ##__VA_ARGS__)
#define dev_warn_ratelimited(dev, fmt, ...)				\
	dev_level_ratelimited(dev_warn, dev, fmt, ##__VA_ARGS__)
#define DEFINE_RATELIMIT_STATE(name, interval_init, burst_init)		\
									\
	struct ratelimit_state name =					\
		RATELIMIT_STATE_INIT(name, interval_init, burst_init)	\

#define RATELIMIT_STATE_INIT(name, interval_init, burst_init) {		\
		.lock		= __RAW_SPIN_LOCK_UNLOCKED(name.lock),	\
		.interval	= interval_init,			\
		.burst		= burst_init,				\
	}
#define WARN_ON_RATELIMIT(condition, state)			\
	WARN_ON(condition)
#define WARN_RATELIMIT(condition, format, ...)			\
({								\
	int rtn = WARN(condition, format, ##__VA_ARGS__);	\
	rtn;							\
})

#define __ratelimit(state) ___ratelimit(state, __func__)
#define TASK_PFA_CLEAR(name, func)					\
	static inline void task_clear_##func(struct task_struct *p)	\
	{ clear_bit(PFA_##name, &p->atomic_flags); }
#define TASK_PFA_SET(name, func)					\
	static inline void task_set_##func(struct task_struct *p)	\
	{ set_bit(PFA_##name, &p->atomic_flags); }
#define TASK_PFA_TEST(name, func)					\
	static inline bool task_##func(struct task_struct *p)		\
	{ return test_bit(PFA_##name, &p->atomic_flags); }
#define TASK_SIZE_OF(tsk)	TASK_SIZE
#define TASK_STOPPED			(TASK_WAKEKILL | __TASK_STOPPED)
#define TASK_TRACED			(TASK_WAKEKILL | __TASK_TRACED)
#define UCLAMP_BUCKETS CONFIG_UCLAMP_BUCKETS_COUNT

#define __set_current_state(state_value)			\
	do {							\
		WARN_ON_ONCE(is_special_task_state(state_value));\
		current->task_state_change = _THIS_IP_;		\
		current->state = (state_value);			\
	} while (0)
#define clear_stopped_child_used_math(child)	do { (child)->flags &= ~PF_USED_MATH; } while (0)
#define clear_used_math()			clear_stopped_child_used_math(current)
#define cond_resched() ({			\
	___might_sleep("__FILE__", "__LINE__", 0);	\
	_cond_resched();			\
})
#define cond_resched_lock(lock) ({				\
	___might_sleep("__FILE__", "__LINE__", PREEMPT_LOCK_OFFSET);\
	__cond_resched_lock(lock);				\
})
#define conditional_stopped_child_used_math(condition, child) \
	do { (child)->flags &= ~PF_USED_MATH, (child)->flags |= (condition) ? PF_USED_MATH : 0; } while (0)
#define conditional_used_math(condition)	conditional_stopped_child_used_math(condition, current)
#define copy_to_stopped_child_used_math(child) \
	do { (child)->flags &= ~PF_USED_MATH, (child)->flags |= current->flags & PF_USED_MATH; } while (0)
#define get_task_comm(buf, tsk) ({			\
	BUILD_BUG_ON(sizeof(buf) != TASK_COMM_LEN);	\
	__get_task_comm(buf, sizeof(buf), tsk);		\
})
#define is_special_task_state(state)				\
	((state) & (__TASK_STOPPED | __TASK_TRACED | TASK_PARKED | TASK_DEAD))
#define set_current_state(state_value)				\
	do {							\
		WARN_ON_ONCE(is_special_task_state(state_value));\
		current->task_state_change = _THIS_IP_;		\
		smp_store_mb(current->state, (state_value));	\
	} while (0)
#define set_special_state(state_value)					\
	do {								\
		unsigned long flags; 			\
		WARN_ON_ONCE(!is_special_task_state(state_value));	\
		raw_spin_lock_irqsave(&current->pi_lock, flags);	\
		current->task_state_change = _THIS_IP_;			\
		current->state = (state_value);				\
		raw_spin_unlock_irqrestore(&current->pi_lock, flags);	\
	} while (0)
#define set_stopped_child_used_math(child)	do { (child)->flags |= PF_USED_MATH; } while (0)
#define set_used_math()				set_stopped_child_used_math(current)
#define task_contributes_to_load(task)	((task->state & TASK_UNINTERRUPTIBLE) != 0 && \
					 (task->flags & PF_FROZEN) == 0 && \
					 (task->state & TASK_NOLOAD) == 0)
#define task_is_stopped(task)		((task->state & __TASK_STOPPED) != 0)
#define task_is_stopped_or_traced(task)	((task->state & (__TASK_STOPPED | __TASK_TRACED)) != 0)
#define task_is_traced(task)		((task->state & __TASK_TRACED) != 0)
# define task_thread_info(task)	((struct thread_info *)(task)->stack)
#define tsk_used_math(p)			((p)->flags & PF_USED_MATH)
#define used_math()				tsk_used_math(current)
#define CPUCLOCK_PERTHREAD(clock) \
	(((clock) & (clockid_t) CPUCLOCK_PERTHREAD_MASK) != 0)
#define CPUCLOCK_PID(clock)		((pid_t) ~((clock) >> 3))
#define CPUCLOCK_WHICH(clock)	((clock) & (clockid_t) CPUCLOCK_CLOCK_MASK)
#define INIT_CPU_TIMERBASE(b) {						\
	.nextevt	= U64_MAX,					\
}
#define INIT_CPU_TIMERBASES(b) {					\
	INIT_CPU_TIMERBASE(b[0]),					\
	INIT_CPU_TIMERBASE(b[1]),					\
	INIT_CPU_TIMERBASE(b[2]),					\
}
#define INIT_CPU_TIMERS(s)						\
	.posix_cputimers = {						\
		.bases = INIT_CPU_TIMERBASES(s.posix_cputimers.bases),	\
	},
#define REQUEUE_PENDING 1





#define NICE_TO_PRIO(nice)	((nice) + DEFAULT_PRIO)
#define PRIO_TO_NICE(prio)	((prio) - DEFAULT_PRIO)
#define TASK_USER_PRIO(p)	USER_PRIO((p)->static_prio)
#define USER_PRIO(p)		((p)-MAX_RT_PRIO)





#define SECCOMP_IO(nr)			_IO(SECCOMP_IOC_MAGIC, nr)
#define SECCOMP_IOR(nr, type)		_IOR(SECCOMP_IOC_MAGIC, nr, type)
#define SECCOMP_IOW(nr, type)		_IOW(SECCOMP_IOC_MAGIC, nr, type)
#define SECCOMP_IOWR(nr, type)		_IOWR(SECCOMP_IOC_MAGIC, nr, type)
#define SECCOMP_RET_KILL	 SECCOMP_RET_KILL_THREAD
#define SECCOMP_RET_KILL_PROCESS 0x80000000U 
#define SECCOMP_USER_NOTIF_FLAG_CONTINUE (1UL << 0)

#define PLIST_HEAD(head) \
	struct plist_head head = PLIST_HEAD_INIT(head)
#define PLIST_HEAD_INIT(head)				\
{							\
	.node_list = LIST_HEAD_INIT((head).node_list)	\
}
#define PLIST_NODE_INIT(node, __prio)			\
{							\
	.prio  = (__prio),				\
	.prio_list = LIST_HEAD_INIT((node).prio_list),	\
	.node_list = LIST_HEAD_INIT((node).node_list),	\
}

# define plist_first_entry(head, type, member)	\
({ \
	WARN_ON(plist_head_empty(head)); \
	container_of(plist_first(head), type, member); \
})
#define plist_for_each(pos, head)	\
	 list_for_each_entry(pos, &(head)->node_list, node_list)
#define plist_for_each_continue(pos, head)	\
	 list_for_each_entry_continue(pos, &(head)->node_list, node_list)
#define plist_for_each_entry(pos, head, mem)	\
	 list_for_each_entry(pos, &(head)->node_list, mem.node_list)
#define plist_for_each_entry_continue(pos, head, m)	\
	list_for_each_entry_continue(pos, &(head)->node_list, m.node_list)
#define plist_for_each_entry_safe(pos, n, head, m)	\
	list_for_each_entry_safe(pos, n, &(head)->node_list, m.node_list)
#define plist_for_each_safe(pos, n, head)	\
	 list_for_each_entry_safe(pos, n, &(head)->node_list, node_list)
# define plist_last_entry(head, type, member)	\
({ \
	WARN_ON(plist_head_empty(head)); \
	container_of(plist_last(head), type, member); \
})
#define plist_next(pos) \
	list_next_entry(pos, node_list)
#define plist_prev(pos) \
	list_prev_entry(pos, node_list)

#define kcov_finish_switch(t)			\
do {						\
	(t)->kcov_mode &= ~KCOV_IN_CTXSW;	\
} while (0)
#define kcov_prepare_switch(t)			\
do {						\
	(t)->kcov_mode |= KCOV_IN_CTXSW;	\
} while (0)
#define KCOV_CMP_CONST          (1 << 0)
#define KCOV_CMP_MASK           KCOV_CMP_SIZE(3)
#define KCOV_CMP_SIZE(n)        ((n) << 1)


#define shm_init_task(task) INIT_LIST_HEAD(&(task)->sysvshm.shm_clist)
#define SHMALL (ULONG_MAX - (1UL << 24)) 
#define SHMMAX (ULONG_MAX - (1UL << 24)) 
#define SHMMIN 1			 
#define SHMMNI 4096			 
#define SHMSEG SHMMNI			 
#define SHM_LOCK 	11
#define SHM_STAT_ANY    15
#define SHM_UNLOCK 	12


#define DIPC            25
#define IPCCALL(version,op)	((version)<<16 | (op))
#define IPC_64  0x0100  
#define IPC_CREAT  00001000   
#define IPC_DIPC 00010000  
#define IPC_EXCL   00002000   
#define IPC_INFO 3     
#define IPC_NOWAIT 00004000   
#define IPC_OLD 0	
#define IPC_OWN  00020000  
#define IPC_PRIVATE ((__kernel_key_t) 0)  
#define IPC_RMID 0     
#define IPC_SET  1     
#define IPC_STAT 2     



#define GETALL  13       
#define GETNCNT 14       
#define GETPID  11       
#define GETVAL  12       
#define GETZCNT 15       
#define SEMAEM  SEMVMX          
#define SEMMAP  SEMMNS          
#define SEMMNI  32000           
#define SEMMNS  (SEMMNI*SEMMSL) 
#define SEMMNU  SEMMNS          
#define SEMMSL  32000           
#define SEMOPM  500	        
#define SEMUME  SEMOPM          
#define SEMUSZ  20		
#define SEMVMX  32767           
#define SEM_INFO 19
#define SEM_STAT 18
#define SEM_STAT_ANY 20
#define SEM_UNDO        0x1000  
#define SETALL  17       
#define SETVAL  16       


#define do_each_pid_task(pid, type, task)				\
	do {								\
		if ((pid) != NULL)					\
			hlist_for_each_entry_rcu((task),		\
				&(pid)->tasks[type], pid_links[type]) {
#define do_each_pid_thread(pid, type, task)				\
	do_each_pid_task(pid, type, task) {				\
		struct task_struct *tg___ = task;			\
		for_each_thread(tg___, task) {
#define while_each_pid_task(pid, type, task)				\
				if (type == PIDTYPE_PID)		\
					break;				\
			}						\
	} while (0)
#define while_each_pid_thread(pid, type, task)				\
		}							\
		task = tg___;						\
	} while_each_pid_task(pid, type, task)

#define __hlist_for_each_rcu(pos, head)				\
	for (pos = rcu_dereference(hlist_first_rcu(head));	\
	     pos;						\
	     pos = rcu_dereference(hlist_next_rcu(pos)))
#define __list_check_rcu(dummy, cond, extra...)				\
	({								\
	check_arg_count_one(extra);					\
	RCU_LOCKDEP_WARN(!cond && !rcu_read_lock_any_held(),		\
			 "RCU-list traversed in non-reader section!");	\
	 })

#define hlist_first_rcu(head)	(*((struct hlist_node __rcu **)(&(head)->first)))
#define hlist_for_each_entry_continue_rcu(pos, member)			\
	for (pos = hlist_entry_safe(rcu_dereference_raw(hlist_next_rcu( \
			&(pos)->member)), typeof(*(pos)), member);	\
	     pos;							\
	     pos = hlist_entry_safe(rcu_dereference_raw(hlist_next_rcu(	\
			&(pos)->member)), typeof(*(pos)), member))
#define hlist_for_each_entry_continue_rcu_bh(pos, member)		\
	for (pos = hlist_entry_safe(rcu_dereference_bh(hlist_next_rcu(  \
			&(pos)->member)), typeof(*(pos)), member);	\
	     pos;							\
	     pos = hlist_entry_safe(rcu_dereference_bh(hlist_next_rcu(	\
			&(pos)->member)), typeof(*(pos)), member))
#define hlist_for_each_entry_from_rcu(pos, member)			\
	for (; pos;							\
	     pos = hlist_entry_safe(rcu_dereference_raw(hlist_next_rcu(	\
			&(pos)->member)), typeof(*(pos)), member))
#define hlist_for_each_entry_rcu(pos, head, member, cond...)		\
	for (__list_check_rcu(dummy, ## cond, 0),			\
	     pos = hlist_entry_safe(rcu_dereference_raw(hlist_first_rcu(head)),\
			typeof(*(pos)), member);			\
		pos;							\
		pos = hlist_entry_safe(rcu_dereference_raw(hlist_next_rcu(\
			&(pos)->member)), typeof(*(pos)), member))
#define hlist_for_each_entry_rcu_bh(pos, head, member)			\
	for (pos = hlist_entry_safe(rcu_dereference_bh(hlist_first_rcu(head)),\
			typeof(*(pos)), member);			\
		pos;							\
		pos = hlist_entry_safe(rcu_dereference_bh(hlist_next_rcu(\
			&(pos)->member)), typeof(*(pos)), member))
#define hlist_for_each_entry_rcu_notrace(pos, head, member)			\
	for (pos = hlist_entry_safe(rcu_dereference_raw_check(hlist_first_rcu(head)),\
			typeof(*(pos)), member);			\
		pos;							\
		pos = hlist_entry_safe(rcu_dereference_raw_check(hlist_next_rcu(\
			&(pos)->member)), typeof(*(pos)), member))
#define hlist_next_rcu(node)	(*((struct hlist_node __rcu **)(&(node)->next)))
#define hlist_pprev_rcu(node)	(*((struct hlist_node __rcu **)((node)->pprev)))
#define list_entry_lockless(ptr, type, member) \
	container_of((typeof(ptr))READ_ONCE(ptr), type, member)
#define list_entry_rcu(ptr, type, member) \
	container_of(READ_ONCE(ptr), type, member)
#define list_first_or_null_rcu(ptr, type, member) \
({ \
	struct list_head *__ptr = (ptr); \
	struct list_head *__next = READ_ONCE(__ptr->next); \
	likely(__ptr != __next) ? list_entry_rcu(__next, type, member) : NULL; \
})
#define list_for_each_entry_continue_rcu(pos, head, member) 		\
	for (pos = list_entry_rcu(pos->member.next, typeof(*pos), member); \
	     &pos->member != (head);	\
	     pos = list_entry_rcu(pos->member.next, typeof(*pos), member))
#define list_for_each_entry_from_rcu(pos, head, member)			\
	for (; &(pos)->member != (head);					\
		pos = list_entry_rcu(pos->member.next, typeof(*(pos)), member))
#define list_for_each_entry_lockless(pos, head, member) \
	for (pos = list_entry_lockless((head)->next, typeof(*pos), member); \
	     &pos->member != (head); \
	     pos = list_entry_lockless(pos->member.next, typeof(*pos), member))
#define list_for_each_entry_rcu(pos, head, member, cond...)		\
	for (__list_check_rcu(dummy, ## cond, 0),			\
	     pos = list_entry_rcu((head)->next, typeof(*pos), member);	\
		&pos->member != (head);					\
		pos = list_entry_rcu(pos->member.next, typeof(*pos), member))
#define list_next_or_null_rcu(head, ptr, type, member) \
({ \
	struct list_head *__head = (head); \
	struct list_head *__ptr = (ptr); \
	struct list_head *__next = READ_ONCE(__ptr->next); \
	likely(__next != __head) ? list_entry_rcu(__next, type, \
						  member) : NULL; \
})
#define list_next_rcu(list)	(*((struct list_head __rcu **)(&(list)->next)))
#define list_tail_rcu(head)	(*((struct list_head __rcu **)(&(head)->prev)))
#define CLONE_ARGS_SIZE_VER0 64 
#define CLONE_ARGS_SIZE_VER1 80 
#define CLONE_CLEAR_SIGHAND 0x100000000ULL 
#define SCHED_RESET_ON_FORK     0x40000000

#define MAJOR(dev)	((unsigned int) ((dev) >> MINORBITS))
#define MKDEV(ma,mi)	(((ma) << MINORBITS) | (mi))

#define format_dev_t(buffer, dev)					\
	({								\
		sprintf(buffer, "%u:%u", MAJOR(dev), MINOR(dev));	\
		buffer;							\
	})
#define print_dev_t(buffer, dev)					\
	sprintf((buffer), "%u:%u\n", MAJOR(dev), MINOR(dev))
#define MINOR(dev)	((dev) & 0xff)

#define ACC_MODE(x) ("\004\002\006\006"[(x)&O_ACCMODE])
#define ACL_DONT_CACHE ((void *)(-3))
#define ACL_NOT_CACHED ((void *)(-1))
#define CHECK_IOVEC_ONLY -1
#define CHRDEV_MAJOR_DYN_END 234
#define CHRDEV_MAJOR_DYN_EXT_END 384
#define CHRDEV_MAJOR_DYN_EXT_START 511
#define CHRDEV_MAJOR_MAX 512
#define DEFINE_SIMPLE_ATTRIBUTE(__fops, __get, __set, __fmt)		\
static int __fops ## _open(struct inode *inode, struct file *file)	\
{									\
	__simple_attr_check_format(__fmt, 0ull);			\
	return simple_attr_open(inode, file, __get, __set, __fmt);	\
}									\
static const struct file_operations __fops = {				\
	.owner	 = THIS_MODULE,						\
	.open	 = __fops ## _open,					\
	.release = simple_attr_release,					\
	.read	 = simple_attr_read,					\
	.write	 = simple_attr_write,					\
	.llseek	 = generic_file_llseek,					\
}
#define FASYNC_MAGIC 0x4601
#define FILESYSTEM_MAX_STACK_DEPTH 2
#define FILE_LOCK_DEFERRED 1
#define FL_CLOSE_POSIX (FL_POSIX | FL_CLOSE)
#define FMODE_32BITHASH         ((__force fmode_t)0x200)
#define FMODE_64BITHASH         ((__force fmode_t)0x400)
#define FMODE_CAN_READ          ((__force fmode_t)0x20000)
#define FMODE_CAN_WRITE         ((__force fmode_t)0x40000)
#define HAVE_COMPAT_IOCTL 1
#define HAVE_UNLOCKED_IOCTL 1
#define INT_LIMIT(x)	(~((x)1 << (sizeof(x)*8 - 1)))
#define IS_APPEND(inode)	((inode)->i_flags & S_APPEND)
#define IS_AUTOMOUNT(inode)	((inode)->i_flags & S_AUTOMOUNT)
#define IS_CASEFOLDED(inode)	((inode)->i_flags & S_CASEFOLD)
#define IS_DAX(inode)		((inode)->i_flags & S_DAX)
#define IS_DEADDIR(inode)	((inode)->i_flags & S_DEAD)
#define IS_DIRSYNC(inode)	(__IS_FLG(inode, SB_SYNCHRONOUS|SB_DIRSYNC) || \
					((inode)->i_flags & (S_SYNC|S_DIRSYNC)))
#define IS_ENCRYPTED(inode)	((inode)->i_flags & S_ENCRYPTED)
#define IS_IMA(inode)		((inode)->i_flags & S_IMA)
#define IS_IMMUTABLE(inode)	((inode)->i_flags & S_IMMUTABLE)
#define IS_I_VERSION(inode)	__IS_FLG(inode, SB_I_VERSION)
#define IS_MANDLOCK(inode)	__IS_FLG(inode, SB_MANDLOCK)
#define IS_NOATIME(inode)	__IS_FLG(inode, SB_RDONLY|SB_NOATIME)
#define IS_NOCMTIME(inode)	((inode)->i_flags & S_NOCMTIME)
#define IS_NOQUOTA(inode)	((inode)->i_flags & S_NOQUOTA)
#define IS_NOSEC(inode)		((inode)->i_flags & S_NOSEC)
#define IS_POSIXACL(inode)	__IS_FLG(inode, SB_POSIXACL)
#define IS_PRIVATE(inode)	((inode)->i_flags & S_PRIVATE)
#define IS_RDONLY(inode)	sb_rdonly((inode)->i_sb)
#define IS_SWAPFILE(inode)	((inode)->i_flags & S_SWAPFILE)
#define IS_SYNC(inode)		(__IS_FLG(inode, SB_SYNCHRONOUS) || \
					((inode)->i_flags & S_SYNC))
#define IS_VERITY(inode)	((inode)->i_flags & S_VERITY)
#define IS_WHITEOUT(inode)	(S_ISCHR(inode->i_mode) && \
				 (inode)->i_rdev == WHITEOUT_DEV)
#define I_DIO_WAKEUP		(1 << __I_DIO_WAKEUP)
#define I_DIRTY (I_DIRTY_INODE | I_DIRTY_PAGES)
#define I_DIRTY_ALL (I_DIRTY | I_DIRTY_TIME)
#define I_DIRTY_INODE (I_DIRTY_SYNC | I_DIRTY_DATASYNC)
#define I_NEW			(1 << __I_NEW)
#define I_SYNC			(1 << __I_SYNC)
#define MAX_LFS_FILESIZE 	((loff_t)LLONG_MAX)
#define MAX_RW_COUNT (INT_MAX & PAGE_MASK)
#define MODULE_ALIAS_FS(NAME) MODULE_ALIAS("fs-" NAME)
#define NOMMU_VMFLAGS \
	(NOMMU_MAP_READ | NOMMU_MAP_WRITE | NOMMU_MAP_EXEC)
#define OPEN_FMODE(flag) ((__force fmode_t)(((flag + 1) & O_ACCMODE) | \
					    (flag & __FMODE_NONOTIFY)))
#define SB_FORCE    	(1<<27)
#define SB_FREEZE_LEVELS (SB_FREEZE_COMPLETE - 1)
#define SB_SUBMOUNT     (1<<26)
#define SIMPLE_TRANSACTION_LIMIT (PAGE_SIZE - sizeof(struct simple_transaction_argresp))
#define WHITEOUT_DEV 0
#define WHITEOUT_MODE 0

#define __IS_FLG(inode, flg)	((inode)->i_sb->s_flags & (flg))

#define __fid_enumify(ENUM, dummy) READING_ ## ENUM,
#define __fid_stringify(dummy, str) #str,
#define __getname()		kmem_cache_alloc(names_cachep, GFP_KERNEL)
#define __kernel_read_file_id(id) \
	id(UNKNOWN, unknown)		\
	id(FIRMWARE, firmware)		\
	id(FIRMWARE_PREALLOC_BUFFER, firmware)	\
	id(MODULE, kernel-module)		\
	id(KEXEC_IMAGE, kexec-image)		\
	id(KEXEC_INITRAMFS, kexec-initramfs)	\
	id(POLICY, security-policy)		\
	id(X509_CERTIFICATE, x509-certificate)	\
	id(MAX_ID, )
#define __putname(name)		kmem_cache_free(names_cachep, (void *)(name))
#define __sb_writers_acquired(sb, lev)	\
	percpu_rwsem_acquire(&(sb)->s_writers.rw_sem[(lev)-1], 1, _THIS_IP_)
#define __sb_writers_release(sb, lev)	\
	percpu_rwsem_release(&(sb)->s_writers.rw_sem[(lev)-1], 1, _THIS_IP_)
#define buffer_migrate_page NULL
#define buffer_migrate_page_norefs NULL
#define compat_ptr_ioctl NULL
#define file_count(x)	atomic_long_read(&(x)->f_count)
#define fops_get(fops) \
	(((fops) && try_module_get((fops)->owner) ? (fops) : NULL))
#define fops_put(fops) \
	do { if (fops) module_put((fops)->owner); } while(0)
#define get_file_rcu(x) get_file_rcu_many((x), 1)
#define get_file_rcu_many(x, cnt)	\
	atomic_long_add_unless(&(x)->f_count, (cnt), 0)
#define i_size_ordered_init(inode) seqcount_init(&inode->i_size_seqcount)
#define locks_inode(f) file_inode(f)
#define replace_fops(f, fops) \
	do {	\
		struct file *__file = (f); \
		fops_put(__file->f_op); \
		BUG_ON(!(__file->f_op = (fops))); \
	} while(0)
#define special_file(m) (S_ISCHR(m)||S_ISBLK(m)||S_ISFIFO(m)||S_ISSOCK(m))

#define DQF_GETINFO_MASK (DQF_ROOT_SQUASH | DQF_SYS_FILE)
#define DQF_INFO_DIRTY (1 << DQF_INFO_DIRTY_B)	
#define DQF_SETINFO_MASK DQF_ROOT_SQUASH
#define DQUOT_DEL_ALLOC max(V1_DEL_ALLOC, V2_DEL_ALLOC)
#define DQUOT_DEL_REWRITE max(V1_DEL_REWRITE, V2_DEL_REWRITE)
#define DQUOT_INIT_ALLOC max(V1_INIT_ALLOC, V2_INIT_ALLOC)
#define DQUOT_INIT_REWRITE max(V1_INIT_REWRITE, V2_INIT_REWRITE)
#define DQUOT_SUSPENDED		(1 << _DQUOT_SUSPENDED * MAXQUOTAS)
#define INIT_QUOTA_MODULE_NAMES {\
	{QFMT_VFS_OLD, "quota_v1",\
	{QFMT_VFS_V0, "quota_v2",\
	{QFMT_VFS_V1, "quota_v2",\
	{0, NULL}}
#define QC_ACCT_MASK (QC_SPACE | QC_INO_COUNT | QC_RT_SPACE)
#define QC_LIMIT_MASK (QC_INO_SOFT | QC_INO_HARD | QC_SPC_SOFT | QC_SPC_HARD | \
		       QC_RT_SPC_SOFT | QC_RT_SPC_HARD)
#define QC_TIMER_MASK (QC_SPC_TIMER | QC_INO_TIMER | QC_RT_SPC_TIMER)
#define QC_WARNS_MASK (QC_SPC_WARNS | QC_INO_WARNS | QC_RT_SPC_WARNS)
#define QTYPE_MASK_GRP (1 << GRPQUOTA)
#define QTYPE_MASK_PRJ (1 << PRJQUOTA)
#define QTYPE_MASK_USR (1 << USRQUOTA)

#define GRPQUOTA  1		
#define INITQFNAMES { \
	"user",     \
	"group",    \
	"project",  \
	"undefined", \
};
#define MAXQUOTAS 3
#define PRJQUOTA  2		
#define QCMD(cmd, type)  (((cmd) << SUBCMDSHIFT) | ((type) & SUBCMDMASK))
#define QFMT_OCFS2 3
#define QIF_DQBLKSIZE (1 << QIF_DQBLKSIZE_BITS)
#define QIF_DQBLKSIZE_BITS 10
#define QUOTA_NL_A_MAX (__QUOTA_NL_A_MAX - 1)
#define QUOTA_NL_BHARDBELOW 9		
#define QUOTA_NL_BHARDWARN 4		
#define QUOTA_NL_BSOFTBELOW 10		
#define QUOTA_NL_BSOFTLONGWARN 5	
#define QUOTA_NL_BSOFTWARN 6		
#define QUOTA_NL_C_MAX (__QUOTA_NL_C_MAX - 1)
#define QUOTA_NL_IHARDBELOW 7		
#define QUOTA_NL_IHARDWARN 1		
#define QUOTA_NL_ISOFTBELOW 8		
#define QUOTA_NL_ISOFTLONGWARN 2 	
#define QUOTA_NL_ISOFTWARN 3		
#define QUOTA_NL_NOWARN 0
#define Q_GETFMT   0x800004	
#define Q_GETINFO  0x800005	
#define Q_GETNEXTQUOTA 0x800009	
#define Q_GETQUOTA 0x800007	
#define Q_QUOTAOFF 0x800003	
#define Q_QUOTAON  0x800002	
#define Q_SETINFO  0x800006	
#define Q_SETQUOTA 0x800008	
#define Q_SYNC     0x800001	
#define SUBCMDMASK  0x00ff
#define SUBCMDSHIFT 8
#define USRQUOTA  0		

#define INVALID_PROJID KPROJIDT_INIT(-1)
#define KPROJIDT_INIT(value) (kprojid_t){ value }
#define OVERFLOW_PROJID 65534

#define V2_DEL_ALLOC QTREE_DEL_ALLOC
#define V2_DEL_REWRITE QTREE_DEL_REWRITE
#define V2_INIT_ALLOC QTREE_INIT_ALLOC
#define V2_INIT_REWRITE QTREE_INIT_REWRITE

#define QTREE_DEL_ALLOC 0
#define QTREE_DEL_REWRITE 6
#define QTREE_INIT_ALLOC 4
#define QTREE_INIT_REWRITE 2

#define V1_DEL_ALLOC 0
#define V1_DEL_REWRITE 2
#define V1_INIT_ALLOC 1
#define V1_INIT_REWRITE 1


#define percpu_counter_init(fbc, value, gfp)				\
	({								\
		static struct lock_class_key __key;			\
									\
		__percpu_counter_init(fbc, value, gfp, &__key);		\
	})
#define BLKALIGNOFF _IO(0x12,122)
#define BLKBSZGET  _IOR(0x12,112,size_t)
#define BLKBSZSET  _IOW(0x12,113,size_t)
#define BLKDISCARD _IO(0x12,119)
#define BLKDISCARDZEROES _IO(0x12,124)
#define BLKFLSBUF  _IO(0x12,97)	
#define BLKFRAGET  _IO(0x12,101)
#define BLKFRASET  _IO(0x12,100)
#define BLKGETSIZE _IO(0x12,96)	
#define BLKGETSIZE64 _IOR(0x12,114,size_t)	
#define BLKIOMIN _IO(0x12,120)
#define BLKIOOPT _IO(0x12,121)
#define BLKPBSZGET _IO(0x12,123)
#define BLKRAGET   _IO(0x12,99)	
#define BLKRASET   _IO(0x12,98)	
#define BLKROGET   _IO(0x12,94)	
#define BLKROSET   _IO(0x12,93)	
#define BLKROTATIONAL _IO(0x12,126)
#define BLKRRPART  _IO(0x12,95)	
#define BLKSECDISCARD _IO(0x12,125)
#define BLKSECTGET _IO(0x12,103)
#define BLKSECTSET _IO(0x12,102)
#define BLKSSZGET  _IO(0x12,104)
#define BLKTRACESETUP _IOWR(0x12,115,struct blk_user_trace_setup)
#define BLKTRACESTART _IO(0x12,116)
#define BLKTRACESTOP _IO(0x12,117)
#define BLKTRACETEARDOWN _IO(0x12,118)
#define BLKZEROOUT _IO(0x12,127)
#define BLOCK_SIZE (1<<BLOCK_SIZE_BITS)
#define BLOCK_SIZE_BITS 10
#define BMAP_IOCTL 1		
#define FIGETBSZ   _IO(0x00,2)	
#define FSLABEL_MAX 256	
#define INR_OPEN_CUR 1024	
#define INR_OPEN_MAX 4096	
#define NR_FILE  8192	

#define MNT_ATIME_MASK (MNT_NOATIME | MNT_NODIRATIME | MNT_RELATIME )
#define MNT_INTERNAL_FLAGS (MNT_SHARED | MNT_WRITE_HOLD | MNT_INTERNAL | \
			    MNT_DOOMED | MNT_SYNC_UMOUNT | MNT_MARKED)
#define MNT_USER_SETTABLE_MASK  (MNT_NOSUID | MNT_NODEV | MNT_NOEXEC \
				 | MNT_NOATIME | MNT_NODIRATIME | MNT_RELATIME \
				 | MNT_READONLY)

#define FSTR_INIT(n, l)		{ .name = n, .len = l }
#define FSTR_TO_QSTR(f)		QSTR_INIT((f)->name, (f)->len)
#define FS_CFLG_OWN_PAGES (1U << 1)

#define fname_len(p)		((p)->disk_name.len)
#define fname_name(p)		((p)->disk_name.name)
#define FSCRYPT_KEY_STATUS_FLAG_ADDED_BY_SELF   0x00000001

#define ARCH_KMALLOC_MINALIGN ARCH_DMA_MINALIGN
#define ARCH_SLAB_MINALIGN __alignof__(unsigned long long)
#define KMALLOC_MIN_SIZE ARCH_DMA_MINALIGN
#define KMALLOC_SHIFT_LOW ilog2(ARCH_DMA_MINALIGN)
#define KMEM_CACHE(__struct, __flags)					\
		kmem_cache_create(#__struct, sizeof(struct __struct),	\
			__alignof__(struct __struct), (__flags), NULL)
#define KMEM_CACHE_USERCOPY(__struct, __flags, __field)			\
		kmem_cache_create_usercopy(#__struct,			\
			sizeof(struct __struct),			\
			__alignof__(struct __struct), (__flags),	\
			offsetof(struct __struct, __field),		\
			sizeof_field(struct __struct, __field), NULL)
#define SLAB_OBJ_MIN_SIZE      (KMALLOC_MIN_SIZE < 16 ? \
                               (KMALLOC_MIN_SIZE) : 16)
#define ZERO_OR_NULL_PTR(x) ((unsigned long)(x) <= \
				(unsigned long)ZERO_SIZE_PTR)
#define ZERO_SIZE_PTR ((void *)16)
#define __assume_kmalloc_alignment __assume_aligned(ARCH_KMALLOC_MINALIGN)
#define __assume_page_alignment __assume_aligned(PAGE_SIZE)
#define __assume_slab_alignment __assume_aligned(ARCH_SLAB_MINALIGN)
#define kmalloc_node_track_caller(size, flags, node) \
	__kmalloc_node_track_caller(size, flags, node, \
			_RET_IP_)
#define kmalloc_track_caller(size, flags) \
	__kmalloc_track_caller(size, flags, _RET_IP_)
#define KASAN_SHADOW_INIT 0


#define FAULT_FLAG_INSTRUCTION  0x100	
#define FAULT_FLAG_TRACE \
	{ FAULT_FLAG_WRITE,		"WRITE" }, \
	{ FAULT_FLAG_MKWRITE,		"MKWRITE" }, \
	{ FAULT_FLAG_ALLOW_RETRY,	"ALLOW_RETRY" }, \
	{ FAULT_FLAG_RETRY_NOWAIT,	"RETRY_NOWAIT" }, \
	{ FAULT_FLAG_KILLABLE,		"KILLABLE" }, \
	{ FAULT_FLAG_TRIED,		"TRIED" }, \
	{ FAULT_FLAG_USER,		"USER" }, \
	{ FAULT_FLAG_REMOTE,		"REMOTE" }, \
	{ FAULT_FLAG_INSTRUCTION,	"INSTRUCTION" }

#define PAGE_ALIGN(addr) ALIGN(addr, PAGE_SIZE)
#define PAGE_ALIGNED(addr)	IS_ALIGNED((unsigned long)(addr), PAGE_SIZE)

#define TLB_FLUSH_VMA(mm,flags) { .vm_mm = (mm), .vm_flags = (flags) }
#define VM_IO           0x00004000	
# define VM_PKEY_BIT4  VM_HIGH_ARCH_4
#define VM_SPECIAL (VM_IO | VM_DONTEXPAND | VM_PFNMAP | VM_MIXEDMAP)
#define VM_STACK_DEFAULT_FLAGS VM_DATA_DEFAULT_FLAGS
#define VM_UNMAPPED_AREA_TOPDOWN 1

#define __pa_symbol(x)  __pa(RELOC_HIDE((unsigned long)(x), 0))
#define anon_vma_interval_tree_foreach(avc, root, start, last)		 \
	for (avc = anon_vma_interval_tree_iter_first(root, start, last); \
	     avc; avc = anon_vma_interval_tree_iter_next(avc, start, last))
#define cpupid_match_pid(task, cpupid) __cpupid_match_pid(task->pid, cpupid)
  #define expand_upwards(vma, address) (0)
#define is_ioremap_addr(x) is_vmalloc_addr(x)
#define lm_alias(x)	__va(__pa_symbol(x))
#define lru_to_page(head) (list_entry((head)->prev, struct page, lru))
#define mm_forbids_zeropage(X)	(0)
#define mm_zero_struct_page(pp)  ((void)memset((pp), 0, sizeof(struct page)))
#define nth_page(page,n) pfn_to_page(page_to_pfn((page)) + (n))
#define offset_in_page(p)	((unsigned long)(p) & ~PAGE_MASK)
#define page_address(page) lowmem_page_address(page)
#define page_address_init()  do { } while(0)
#define page_ref_zero_or_close_to_overflow(page) \
	((unsigned int) page_ref_count(page) + 127u <= 127u)
#define page_to_virt(x)	__va(PFN_PHYS(page_to_pfn(x)))
#define pmd_huge_pte(mm, pmd) ((mm)->pmd_huge_pte)
#define pte_alloc(mm, pmd) (unlikely(pmd_none(*(pmd))) && __pte_alloc(mm, pmd))
#define pte_alloc_kernel(pmd, address)			\
	((unlikely(pmd_none(*(pmd))) && __pte_alloc_kernel(pmd))? \
		NULL: pte_offset_kernel(pmd, address))
#define pte_alloc_map(mm, pmd, address)			\
	(pte_alloc(mm, pmd) ? NULL : pte_offset_map(pmd, address))
#define pte_alloc_map_lock(mm, pmd, address, ptlp)	\
	(pte_alloc(mm, pmd) ?			\
		 NULL : pte_offset_map_lock(mm, pmd, address, ptlp))
#define pte_offset_map_lock(mm, pmd, address, ptlp)	\
({							\
	spinlock_t *__ptl = pte_lockptr(mm, pmd);	\
	pte_t *__pte = pte_offset_map(pmd, address);	\
	*(ptlp) = __ptl;				\
	spin_lock(__ptl);				\
	__pte;						\
})
#define pte_unmap_unlock(pte, ptl)	do {		\
	spin_unlock(ptl);				\
	pte_unmap(pte);					\
} while (0)
#define put_hwpoison_page(page)	put_page(page)
#define randomize_va_space 0
#define set_page_address(page, address)  do { } while(0)
#define sysctl_legacy_va_layout 0
#define untagged_addr(addr) (addr)
#define vma_interval_tree_foreach(vma, root, start, last)		\
	for (vma = vma_interval_tree_iter_first(root, start, last);	\
	     vma; vma = vma_interval_tree_iter_next(vma, start, last))
#define DISABLE_NUMA_STAT   0
#define ENABLE_NUMA_STAT   1

#define __count_zid_vm_events(item, zid, delta) \
	__count_vm_events(item##_NORMAL - ZONE_NORMAL + zid, delta)
#define count_vm_numa_event(x)     count_vm_event(x)
#define count_vm_numa_events(x, y) count_vm_events(x, y)
#define count_vm_tlb_event(x)	   count_vm_event(x)
#define count_vm_tlb_events(x, y)  count_vm_events(x, y)
#define count_vm_vmacache_event(x) count_vm_event(x)
#define dec_node_page_state __dec_node_page_state
#define dec_zone_page_state __dec_zone_page_state
#define dec_zone_state __dec_zone_state
#define inc_node_page_state __inc_node_page_state
#define inc_node_state __inc_node_state
#define inc_zone_page_state __inc_zone_page_state
#define inc_zone_state __inc_zone_state
#define mod_node_page_state __mod_node_page_state
#define mod_zone_page_state __mod_zone_page_state
#define node_page_state(node, item) global_node_page_state(item)
#define set_pgdat_percpu_threshold(pgdat, callback) { }
#define sum_zone_node_page_state(node, item) global_zone_page_state(item)
#define DMA32_ZONE(xx) xx##_DMA32,
#define DMA_ZONE(xx) xx##_DMA,
#define FOR_ALL_ZONES(xx) DMA_ZONE(xx) DMA32_ZONE(xx) xx##_NORMAL, HIGHMEM_ZONE(xx) xx##_MOVABLE
#define HIGHMEM_ZONE(xx) xx##_HIGH,
#define THP_FILE_ALLOC ({ BUILD_BUG(); 0; })
#define THP_FILE_MAPPED ({ BUILD_BUG(); 0; })

#define HPAGE_CACHE_INDEX_MASK (HPAGE_PMD_NR - 1)
#define HPAGE_PMD_MASK ({ BUILD_BUG(); 0; })
#define HPAGE_PMD_NR (1<<HPAGE_PMD_ORDER)
#define HPAGE_PMD_ORDER (HPAGE_PMD_SHIFT-PAGE_SHIFT)
#define HPAGE_PMD_SHIFT ({ BUILD_BUG(); 0; })
#define HPAGE_PMD_SIZE ({ BUILD_BUG(); 0; })
#define HPAGE_PUD_MASK ({ BUILD_BUG(); 0; })
#define HPAGE_PUD_SHIFT ({ BUILD_BUG(); 0; })
#define HPAGE_PUD_SIZE ({ BUILD_BUG(); 0; })

#define hpage_nr_pages(x) 1
#define mk_huge_pmd(page, prot) pmd_mkhuge(mk_pmd(page, prot))
#define split_huge_pmd(__vma, __pmd, __address)				\
	do {								\
		pmd_t *____pmd = (__pmd);				\
		if (is_swap_pmd(*____pmd) || pmd_trans_huge(*____pmd)	\
					|| pmd_devmap(*____pmd))	\
			__split_huge_pmd(__vma, __pmd, __address,	\
						false, NULL);		\
	}  while (0)
#define split_huge_pud(__vma, __pud, __address)				\
	do {								\
		pud_t *____pud = (__pud);				\
		if (pud_trans_huge(*____pud)				\
					|| pud_devmap(*____pud))	\
			__split_huge_pud(__vma, __pud, __address);	\
	}  while (0)
#define transparent_hugepage_debug_cow()				\
	(transparent_hugepage_flags &					\
	 (1<<TRANSPARENT_HUGEPAGE_DEBUG_COW_FLAG))
#define transparent_hugepage_flags 0UL
#define transparent_hugepage_use_zero_page()				\
	(transparent_hugepage_flags &					\
	 (1<<TRANSPARENT_HUGEPAGE_USE_ZERO_PAGE_FLAG))
#define MMF_DUMPABLE_BITS 2
#define MMF_DUMPABLE_MASK ((1 << MMF_DUMPABLE_BITS) - 1)
#define MMF_DUMP_FILTER_DEFAULT \
	((1 << MMF_DUMP_ANON_PRIVATE) |	(1 << MMF_DUMP_ANON_SHARED) |\
	 (1 << MMF_DUMP_HUGETLB_PRIVATE) | MMF_DUMP_MASK_DEFAULT_ELF)
#define MMF_DUMP_FILTER_MASK \
	(((1 << MMF_DUMP_FILTER_BITS) - 1) << MMF_DUMP_FILTER_SHIFT)
#define MMF_DUMP_HUGETLB_PRIVATE 7
#define MMF_DUMP_HUGETLB_SHARED  8




#define page_ref_tracepoint_active(t) static_key_false(&(t).key)
#define TRACEPOINT_DEFS_H 1


#define DEFAULT_SEEKS 2 
#define SHRINK_EMPTY (~0UL - 1)
#define SHRINK_STOP (~0UL)


#define MAX_RESOURCE ((resource_size_t)~0)



#define IOPRIO_PRIO_CLASS(mask)	((mask) >> IOPRIO_CLASS_SHIFT)
#define IOPRIO_PRIO_DATA(mask)	((mask) & IOPRIO_PRIO_MASK)
#define IOPRIO_PRIO_VALUE(class, data)	(((class) << IOPRIO_CLASS_SHIFT) | data)
#define ioprio_valid(mask)	(IOPRIO_PRIO_CLASS((mask)) != IOPRIO_CLASS_NONE)


# define rt_mutex_adjust_pi(p)		do { } while (0)

#define UUID_INIT(a, b, c, d0, d1, d2, d3, d4, d5, d6, d7)			\
((uuid_t)								\
{{ ((a) >> 24) & 0xff, ((a) >> 16) & 0xff, ((a) >> 8) & 0xff, (a) & 0xff, \
   ((b) >> 8) & 0xff, (b) & 0xff,					\
   ((c) >> 8) & 0xff, (c) & 0xff,					\
   (d0), (d1), (d2), (d3), (d4), (d5), (d6), (d7) }})
#define UUID_SIZE 16

#define uuid_le_gen(u)		guid_gen(u)
#define uuid_le_to_bin(guid, u)	guid_parse(guid, u)
#define GUID_INIT(a, b, c, d0, d1, d2, d3, d4, d5, d6, d7)			\
((guid_t)								\
{{ (a) & 0xff, ((a) >> 8) & 0xff, ((a) >> 16) & 0xff, ((a) >> 24) & 0xff, \
   (b) & 0xff, ((b) >> 8) & 0xff,					\
   (c) & 0xff, ((c) >> 8) & 0xff,					\
   (d0), (d1), (d2), (d3), (d4), (d5), (d6), (d7) }})
#define UUID_LE(a, b, c, d0, d1, d2, d3, d4, d5, d6, d7)		\
	GUID_INIT(a, b, c, d0, d1, d2, d3, d4, d5, d6, d7)

#define DEFINE_DELAYED_CALL(name) struct delayed_call name = {NULL, NULL}

#define DEFINE_PERCPU_RWSEM(name)		\
	__DEFINE_PERCPU_RWSEM(name, )
#define DEFINE_STATIC_PERCPU_RWSEM(name)	\
	__DEFINE_PERCPU_RWSEM(name, static)

#define __DEFINE_PERCPU_RWSEM(name, is_static)				\
static DEFINE_PER_CPU(unsigned int, __percpu_rwsem_rc_##name);		\
is_static struct percpu_rw_semaphore name = {				\
	.rss = __RCU_SYNC_INITIALIZER(name.rss),			\
	.read_count = &__percpu_rwsem_rc_##name,			\
	.rw_sem = __RWSEM_INITIALIZER(name.rw_sem),			\
	.writer = __RCUWAIT_INITIALIZER(name.writer),			\
}
#define percpu_init_rwsem(sem)					\
({								\
	static struct lock_class_key rwsem_key;			\
	__percpu_init_rwsem(sem, #sem, &rwsem_key);		\
})
#define percpu_rwsem_assert_held(sem)				\
	lockdep_assert_held(&(sem)->rw_sem)
#define percpu_rwsem_is_held(sem) lockdep_is_held(&(sem)->rw_sem)

#define __RCU_SYNC_INITIALIZER(name) {					\
		.gp_state = 0,						\
		.gp_count = 0,						\
		.gp_wait = __WAIT_QUEUE_HEAD_INITIALIZER(name.gp_wait),	\
	}

#define __RCUWAIT_INITIALIZER(name)		\
	{ .task = NULL, }
#define rcuwait_wait_event(w, condition)				\
({									\
	rcu_assign_pointer((w)->task, current);				\
	for (;;) {							\
									\
		set_current_state(TASK_UNINTERRUPTIBLE);		\
		if (condition)						\
			break;						\
									\
		schedule();						\
	}								\
									\
	WRITE_ONCE((w)->task, NULL);					\
	__set_current_state(TASK_RUNNING);				\
})


#define hlist_bl_for_each_entry_rcu(tpos, pos, head, member)		\
	for (pos = hlist_bl_first_rcu(head);				\
		pos &&							\
		({ tpos = hlist_bl_entry(pos, typeof(*tpos), member); 1; }); \
		pos = rcu_dereference_raw(pos->next))
#define INIT_HLIST_BL_HEAD(ptr) \
	((ptr)->first = NULL)
#define LIST_BL_BUG_ON(x) BUG_ON(x)

#define hlist_bl_entry(ptr, type, member) container_of(ptr,type,member)
#define hlist_bl_for_each_entry(tpos, pos, head, member)		\
	for (pos = hlist_bl_first(head);				\
	     pos &&							\
		({ tpos = hlist_bl_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = pos->next)
#define hlist_bl_for_each_entry_safe(tpos, pos, n, head, member)	 \
	for (pos = hlist_bl_first(head);				 \
	     pos && ({ n = pos->next; 1; }) && 				 \
		({ tpos = hlist_bl_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = n)
#define IS_GETLK32(cmd)		((cmd) == F_GETLK)
#define IS_GETLK64(cmd)		((cmd) == F_GETLK64)
#define IS_SETLK32(cmd)		((cmd) == F_SETLK)
#define IS_SETLK64(cmd)		((cmd) == F_SETLK64)
#define IS_SETLKW32(cmd)	((cmd) == F_SETLKW)
#define IS_SETLKW64(cmd)	((cmd) == F_SETLKW64)
#define VALID_OPEN_FLAGS \
	(O_RDONLY | O_WRONLY | O_RDWR | O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC | \
	 O_APPEND | O_NDELAY | O_NONBLOCK | O_NDELAY | __O_SYNC | O_DSYNC | \
	 FASYNC	| O_DIRECT | O_LARGEFILE | O_DIRECTORY | O_NOFOLLOW | \
	 O_NOATIME | O_CLOEXEC | O_PATH | __O_TMPFILE)
#define VALID_RESOLVE_FLAGS \
	(RESOLVE_NO_XDEV | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS | \
	 RESOLVE_BENEATH | RESOLVE_IN_ROOT)
#define VALID_UPGRADE_FLAGS \
	(UPGRADE_NOWRITE | UPGRADE_NOREAD)

#define force_o_largefile() (!IS_ENABLED(CONFIG_ARCH_32BIT_OFF_T))

#define DEFINE_SEMAPHORE(name)	\
	struct semaphore name = __SEMAPHORE_INITIALIZER(name, 1)

#define __SEMAPHORE_INITIALIZER(name, n)				\
{									\
	.lock		= __RAW_SPIN_LOCK_UNLOCKED((name).lock),	\
	.count		= n,						\
	.wait_list	= LIST_HEAD_INIT((name).wait_list),		\
}
#define CAP_BOP_ALL(c, a, b, OP)                                    \
do {                                                                \
	unsigned __capi;                                            \
	CAP_FOR_EACH_U32(__capi) {                                  \
		c.cap[__capi] = a.cap[__capi] OP b.cap[__capi];     \
	}                                                           \
} while (0)
# define CAP_EMPTY_SET    ((kernel_cap_t){{ 0, 0 }})
#define CAP_FOR_EACH_U32(__capi)  \
	for (__capi = 0; __capi < _KERNEL_CAPABILITY_U32S; ++__capi)
# define CAP_FS_MASK_B0     (CAP_TO_MASK(CAP_CHOWN)		\
			    | CAP_TO_MASK(CAP_MKNOD)		\
			    | CAP_TO_MASK(CAP_DAC_OVERRIDE)	\
			    | CAP_TO_MASK(CAP_DAC_READ_SEARCH)	\
			    | CAP_TO_MASK(CAP_FOWNER)		\
			    | CAP_TO_MASK(CAP_FSETID))
# define CAP_FS_MASK_B1     (CAP_TO_MASK(CAP_MAC_OVERRIDE))
# define CAP_FS_SET       ((kernel_cap_t){{ CAP_FS_MASK_B0 \
				    | CAP_TO_MASK(CAP_LINUX_IMMUTABLE), \
				    CAP_FS_MASK_B1 } })
# define CAP_FULL_SET     ((kernel_cap_t){{ ~0, CAP_LAST_U32_VALID_MASK }})
# define CAP_NFSD_SET     ((kernel_cap_t){{ CAP_FS_MASK_B0 \
				    | CAP_TO_MASK(CAP_SYS_RESOURCE), \
				    CAP_FS_MASK_B1 } })
#define CAP_UOP_ALL(c, a, OP)                                       \
do {                                                                \
	unsigned __capi;                                            \
	CAP_FOR_EACH_U32(__capi) {                                  \
		c.cap[__capi] = OP a.cap[__capi];                   \
	}                                                           \
} while (0)
#define _KERNEL_CAPABILITY_U32S    _LINUX_CAPABILITY_U32S_3
#define _KERNEL_CAPABILITY_VERSION _LINUX_CAPABILITY_VERSION_3
#define _KERNEL_CAP_T_SIZE     (sizeof(kernel_cap_t))

#define _USER_CAP_HEADER_SIZE  (sizeof(struct __user_cap_header_struct))
# define cap_clear(c)         do { (c) = __cap_empty_set; } while (0)
#define cap_lower(c, flag)  ((c).cap[CAP_TO_INDEX(flag)] &= ~CAP_TO_MASK(flag))
#define cap_raise(c, flag)  ((c).cap[CAP_TO_INDEX(flag)] |= CAP_TO_MASK(flag))
#define cap_raised(c, flag) ((c).cap[CAP_TO_INDEX(flag)] & CAP_TO_MASK(flag))
#define CAP_AUDIT_CONTROL    30
#define CAP_AUDIT_WRITE      29
#define CAP_BLOCK_SUSPEND    36
#define CAP_CHOWN            0
#define CAP_DAC_OVERRIDE     1
#define CAP_DAC_READ_SEARCH  2
#define CAP_FOWNER           3
#define CAP_FSETID           4
#define CAP_IPC_LOCK         14
#define CAP_IPC_OWNER        15
#define CAP_KILL             5
#define CAP_LAST_CAP         CAP_AUDIT_READ
#define CAP_LEASE            28
#define CAP_LINUX_IMMUTABLE  9
#define CAP_MAC_ADMIN        33
#define CAP_MAC_OVERRIDE     32
#define CAP_MKNOD            27
#define CAP_NET_ADMIN        12
#define CAP_NET_BIND_SERVICE 10
#define CAP_NET_BROADCAST    11
#define CAP_NET_RAW          13
#define CAP_SETGID           6
#define CAP_SETPCAP          8
#define CAP_SETUID           7
#define CAP_SYSLOG           34
#define CAP_SYS_ADMIN        21
#define CAP_SYS_BOOT         22
#define CAP_SYS_CHROOT       18
#define CAP_SYS_MODULE       16
#define CAP_SYS_NICE         23
#define CAP_SYS_PACCT        20
#define CAP_SYS_PTRACE       19
#define CAP_SYS_RAWIO        17
#define CAP_SYS_RESOURCE     24
#define CAP_SYS_TIME         25
#define CAP_SYS_TTY_CONFIG   26
#define CAP_TO_INDEX(x)     ((x) >> 5)        
#define CAP_TO_MASK(x)      (1 << ((x) & 31)) 
#define CAP_WAKE_ALARM            35
#define VFS_CAP_U32             VFS_CAP_U32_3
#define VFS_CAP_U32_1           1
#define VFS_CAP_U32_2           2
#define VFS_CAP_U32_3           2
#define XATTR_CAPS_SZ           XATTR_CAPS_SZ_3
#define XATTR_CAPS_SZ_1         (sizeof(__le32)*(1 + 2*VFS_CAP_U32_1))
#define XATTR_CAPS_SZ_2         (sizeof(__le32)*(1 + 2*VFS_CAP_U32_2))
#define XATTR_CAPS_SZ_3         (sizeof(__le32)*(2 + 2*VFS_CAP_U32_3))
#define _LINUX_CAPABILITY_U32S     _LINUX_CAPABILITY_U32S_1
#define _LINUX_CAPABILITY_U32S_1     1
#define _LINUX_CAPABILITY_U32S_2     2
#define _LINUX_CAPABILITY_U32S_3     2
#define _LINUX_CAPABILITY_VERSION  _LINUX_CAPABILITY_VERSION_1
#define _LINUX_CAPABILITY_VERSION_1  0x19980330
#define _LINUX_CAPABILITY_VERSION_2  0x20071026  
#define _LINUX_CAPABILITY_VERSION_3  0x20080522

#define cap_valid(x) ((x) >= 0 && (x) <= CAP_LAST_CAP)

#define list_lru_init(lru)				\
	__list_lru_init((lru), false, NULL, NULL)
#define list_lru_init_key(lru, key)			\
	__list_lru_init((lru), false, (key), NULL)
#define list_lru_init_memcg(lru, shrinker)		\
	__list_lru_init((lru), true, NULL, shrinker)

#define DCACHE_MANAGED_DENTRY \
	(DCACHE_MOUNTED|DCACHE_NEED_AUTOMOUNT|DCACHE_MANAGE_TRANSIT)
#  define DNAME_INLINE_LEN 36 
 #define HASH_LEN_DECLARE u32 hash; u32 len
#define IS_ROOT(x) ((x) == (x)->d_parent)
#define QSTR_INIT(n,l) { { { .len = l } }, .name = n }

 #define bytemask_from_count(cnt)	(~(~0ul << (cnt)*8))

#define hashlen_create(hash, len) ((u64)(len)<<32 | (u32)(hash))
#define hashlen_hash(hashlen) ((u32)(hashlen))
#define hashlen_len(hashlen)  ((u32)((hashlen) >> 32))
#define init_name_hash(salt)		(unsigned long)(salt)
#define GOLDEN_RATIO_32 0x61C88647
#define GOLDEN_RATIO_64 0x61C8864680B583EBull
#define GOLDEN_RATIO_PRIME GOLDEN_RATIO_32

#define __hash_32 __hash_32_generic
#define hash_32 hash_32_generic
#define hash_64 hash_64_generic
#define hash_long(val, bits) hash_32(val, bits)
#define USE_CMPXCHG_LOCKREF \
	(IS_ENABLED(CONFIG_ARCH_USE_CMPXCHG_LOCKREF) && \
	 IS_ENABLED(CONFIG_SMP) && SPINLOCK_SIZE <= 4)

#define DEFINE_WAIT_BIT(name, word, bit)					\
	struct wait_bit_queue_entry name = {					\
		.key = __WAIT_BIT_KEY_INITIALIZER(word, bit),			\
		.wq_entry = {							\
			.private	= current,				\
			.func		= wake_bit_function,			\
			.entry		=					\
				LIST_HEAD_INIT((name).wq_entry.entry),		\
		},								\
	}

#define __WAIT_BIT_KEY_INITIALIZER(word, bit)					\
	{ .flags = word, .bit_nr = bit, }
#define ___wait_var_event(var, condition, state, exclusive, ret, cmd)	\
({									\
	__label__ __out;						\
	struct wait_queue_head *__wq_head = __var_waitqueue(var);	\
	struct wait_bit_queue_entry __wbq_entry;			\
	long __ret = ret; 				\
									\
	init_wait_var_entry(&__wbq_entry, var,				\
			    exclusive ? WQ_FLAG_EXCLUSIVE : 0);		\
	for (;;) {							\
		long __int = prepare_to_wait_event(__wq_head,		\
						   &__wbq_entry.wq_entry, \
						   state);		\
		if (condition)						\
			break;						\
									\
		if (___wait_is_interruptible(state) && __int) {		\
			__ret = __int;					\
			goto __out;					\
		}							\
									\
		cmd;							\
	}								\
	finish_wait(__wq_head, &__wbq_entry.wq_entry);			\
__out:	__ret;								\
})
#define __wait_var_event(var, condition)				\
	___wait_var_event(var, condition, TASK_UNINTERRUPTIBLE, 0, 0,	\
			  schedule())
#define __wait_var_event_interruptible(var, condition)			\
	___wait_var_event(var, condition, TASK_INTERRUPTIBLE, 0, 0,	\
			  schedule())
#define __wait_var_event_killable(var, condition)			\
	___wait_var_event(var, condition, TASK_KILLABLE, 0, 0,		\
			  schedule())
#define __wait_var_event_timeout(var, condition, timeout)		\
	___wait_var_event(var, ___wait_cond_timeout(condition),		\
			  TASK_UNINTERRUPTIBLE, 0, timeout,		\
			  __ret = schedule_timeout(__ret))
#define wait_var_event(var, condition)					\
do {									\
	might_sleep();							\
	if (condition)							\
		break;							\
	__wait_var_event(var, condition);				\
} while (0)
#define wait_var_event_interruptible(var, condition)			\
({									\
	int __ret = 0;							\
	might_sleep();							\
	if (!(condition))						\
		__ret = __wait_var_event_interruptible(var, condition);	\
	__ret;								\
})
#define wait_var_event_killable(var, condition)				\
({									\
	int __ret = 0;							\
	might_sleep();							\
	if (!(condition))						\
		__ret = __wait_var_event_killable(var, condition);	\
	__ret;								\
})
#define wait_var_event_timeout(var, condition, timeout)			\
({									\
	long __ret = timeout;						\
	might_sleep();							\
	if (!___wait_cond_timeout(condition))				\
		__ret = __wait_var_event_timeout(var, condition, timeout); \
	__ret;								\
})
#define DEFAULT_POLLMASK (EPOLLIN | EPOLLOUT | EPOLLRDNORM | EPOLLWRNORM)
#define M(X) (__force __poll_t)__MAP(val, POLL##X, (__force __u16)EPOLL##X)
#define MAX_INT64_SECONDS (((s64)(~((u64)0)>>1)/HZ)-1)
#define MAX_STACK_ALLOC 768

#define __MAP(v, from, to) \
	(from < to ? (v & from) * (to/from) : (v & from) / (from/to))
#define EPOLL_CLOEXEC O_CLOEXEC
#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLL_CTL_MOD 3
#define EPOLL_PACKED __attribute__((packed))


#define faulthandler_disabled() (pagefault_disabled() || in_atomic())
#define probe_kernel_address(addr, retval)		\
	probe_kernel_read(&retval, addr, sizeof(retval))
#define uaccess_kernel() segment_eq(get_fs(), KERNEL_DS)
#define unsafe_copy_to_user(d,s,l,e) unsafe_op_wrap(__copy_to_user(d,s,l),e)
#define unsafe_get_user(x,p,e) unsafe_op_wrap(__get_user(x,p),e)
#define unsafe_op_wrap(op, err) do { if (unlikely(op)) goto err; } while (0)
#define unsafe_put_user(x,p,e) unsafe_op_wrap(__put_user(x,p),e)
#define user_access_begin(ptr,len) access_ok(ptr, len)
#define user_access_end() do { } while (0)
#define DEFINE_CTL_TABLE_POLL(name)					\
	struct ctl_table_poll name = __CTL_TABLE_POLL_INITIALIZER(name)

#define __CTL_TABLE_POLL_INITIALIZER(name) {				\
	.event = ATOMIC_INIT(0),					\
	.wait = __WAIT_QUEUE_HEAD_INITIALIZER(name.wait) }
#define CTL_MAXNAME 10		

#define DEFINE_DMA_BUF_EXPORT_INFO(name)	\
	struct dma_buf_export_info name = { .exp_name = KBUILD_MODNAME, \
					 .owner = THIS_MODULE }

#define DMA_FENCE_ERR(f, fmt, args...) \
	do {								\
		struct dma_fence *__ff = (f);				\
		pr_err("f %llu#%llu: " fmt, __ff->context, __ff->seqno,	\
			##args);					\
	} while (0)
#define DMA_FENCE_TRACE(f, fmt, args...) \
	do {								\
		struct dma_fence *__ff = (f);				\
		if (IS_ENABLED(CONFIG_DMA_FENCE_TRACE))			\
			pr_info("f %llu#%llu: " fmt,			\
				__ff->context, __ff->seqno, ##args);	\
	} while (0)
#define DMA_FENCE_WARN(f, fmt, args...) \
	do {								\
		struct dma_fence *__ff = (f);				\
		pr_warn("f %llu#%llu: " fmt, __ff->context, __ff->seqno,\
			 ##args);					\
	} while (0)

#define DEFINE_DMA_UNMAP_ADDR(ADDR_NAME)        dma_addr_t ADDR_NAME
#define DEFINE_DMA_UNMAP_LEN(LEN_NAME)          __u32 LEN_NAME
#define DMA_BIT_MASK(n)	(((n) == 64) ? ~0ULL : ((1ULL<<(n))-1))

#define dma_alloc_from_dev_coherent(dev, size, handle, ret) (0)
#define dma_get_sgtable(d, t, v, h, s) dma_get_sgtable_attrs(d, t, v, h, s, 0)
#define dma_map_page(d, p, o, s, r) dma_map_page_attrs(d, p, o, s, r, 0)
#define dma_map_sg(d, s, n, r) dma_map_sg_attrs(d, s, n, r, 0)
#define dma_map_single(d, a, s, r) dma_map_single_attrs(d, a, s, r, 0)
#define dma_mmap_coherent(d, v, c, h, s) dma_mmap_attrs(d, v, c, h, s, 0)
#define dma_mmap_from_dev_coherent(dev, vma, vaddr, order, ret) (0)
#define dma_release_from_dev_coherent(dev, order, vaddr) (0)
#define dma_unmap_addr(PTR, ADDR_NAME)           ((PTR)->ADDR_NAME)
#define dma_unmap_addr_set(PTR, ADDR_NAME, VAL)  (((PTR)->ADDR_NAME) = (VAL))
#define dma_unmap_len(PTR, LEN_NAME)             ((PTR)->LEN_NAME)
#define dma_unmap_len_set(PTR, LEN_NAME, VAL)    (((PTR)->LEN_NAME) = (VAL))
#define dma_unmap_page(d, a, s, r) dma_unmap_page_attrs(d, a, s, r, 0)
#define dma_unmap_sg(d, s, n, r) dma_unmap_sg_attrs(d, s, n, r, 0)
#define dma_unmap_single(d, a, s, r) dma_unmap_single_attrs(d, a, s, r, 0)

#define __sme_clr(x)		((x) & ~sme_me_mask)
#define __sme_set(x)		((x) | sme_me_mask)
#define SCATTERLIST_MAX_SEGMENT (UINT_MAX & PAGE_MASK)

#define for_each_sg(sglist, sg, nr, __i)	\
	for (__i = 0, sg = (sglist); __i < (nr); __i++, sg = sg_next(sg))
#define for_each_sg_dma_page(sglist, dma_iter, dma_nents, pgoffset)            \
	for (__sg_page_iter_start(&(dma_iter)->base, sglist, dma_nents,        \
				  pgoffset);                                   \
	     __sg_page_iter_dma_next(dma_iter);)
#define for_each_sg_page(sglist, piter, nents, pgoffset)		   \
	for (__sg_page_iter_start((piter), (sglist), (nents), (pgoffset)); \
	     __sg_page_iter_next(piter);)
#define sg_chain_ptr(sg)	\
	((struct scatterlist *) ((sg)->page_link & ~(SG_CHAIN | SG_END)))
#define sg_dma_address(sg)	((sg)->dma_address)
#define sg_dma_len(sg)		((sg)->dma_length)
#define sg_is_chain(sg)		((sg)->page_link & SG_CHAIN)
#define sg_is_last(sg)		((sg)->page_link & SG_END)


#define FDPUT_FPUT       1
#define FDPUT_POS_UNLOCK 2


#define V4L2_CAP_ASYNCIO                0x02000000  
#define V4L2_CAP_DEVICE_CAPS            0x80000000  
#define V4L2_CAP_READWRITE              0x01000000  
#define V4L2_CAP_STREAMING              0x04000000  
#define V4L2_CAP_TOUCH                  0x10000000  
#define V4L2_CHIP_FL_READABLE (1 << 0)
#define V4L2_CHIP_FL_WRITABLE (1 << 1)
#define V4L2_CHIP_MATCH_AC97        3  
#define V4L2_CHIP_MATCH_BRIDGE      0  
#define V4L2_CHIP_MATCH_HOST V4L2_CHIP_MATCH_BRIDGE
#define V4L2_CHIP_MATCH_I2C_ADDR    2  
#define V4L2_CHIP_MATCH_I2C_DRIVER  1  
#define V4L2_CHIP_MATCH_SUBDEV      4  
#define V4L2_COLORSPACE_ADOBERGB V4L2_COLORSPACE_OPRGB
#define V4L2_CTRL_DRIVER_PRIV(id) (((id) & 0xffff) >= 0x1000)
#define V4L2_CTRL_ID2CLASS(id)    ((id) & 0x0fff0000UL)
#define V4L2_CTRL_ID2WHICH(id)    ((id) & 0x0fff0000UL)
#define V4L2_CTRL_WHICH_CUR_VAL   0
#define V4L2_CTRL_WHICH_DEF_VAL   0x0f000000
#define V4L2_CTRL_WHICH_REQUEST_VAL 0x0f010000
#define V4L2_DEC_CMD_FLUSH       (4)
#define V4L2_DEC_CMD_PAUSE       (2)
#define V4L2_DEC_CMD_RESUME      (3)
#define V4L2_DEC_CMD_START       (0)
#define V4L2_DEC_CMD_STOP        (1)
#define V4L2_DV_BT_BLANKING_HEIGHT(bt) \
	((bt)->vfrontporch + (bt)->vsync + (bt)->vbackporch + \
	 (bt)->il_vfrontporch + (bt)->il_vsync + (bt)->il_vbackporch)
#define V4L2_DV_BT_BLANKING_WIDTH(bt) \
	((bt)->hfrontporch + (bt)->hsync + (bt)->hbackporch)
#define V4L2_DV_BT_FRAME_HEIGHT(bt) \
	((bt)->height + V4L2_DV_BT_BLANKING_HEIGHT(bt))
#define V4L2_DV_BT_FRAME_WIDTH(bt) \
	((bt)->width + V4L2_DV_BT_BLANKING_WIDTH(bt))
#define V4L2_ENC_CMD_PAUSE      (2)
#define V4L2_ENC_CMD_RESUME     (3)
#define V4L2_ENC_CMD_START      (0)
#define V4L2_ENC_CMD_STOP       (1)
#define V4L2_ENC_CMD_STOP_AT_GOP_END    (1 << 0)
#define V4L2_ENC_IDX_ENTRIES (64)
#define V4L2_ENC_IDX_FRAME_B    (2)
#define V4L2_ENC_IDX_FRAME_I    (0)
#define V4L2_ENC_IDX_FRAME_MASK (0xf)
#define V4L2_ENC_IDX_FRAME_P    (1)
#define V4L2_FBUF_CAP_LIST_CLIPPING     0x0004
#define V4L2_FIELD_HAS_BOTH(field)	\
	((field) == V4L2_FIELD_INTERLACED ||\
	 (field) == V4L2_FIELD_INTERLACED_TB ||\
	 (field) == V4L2_FIELD_INTERLACED_BT ||\
	 (field) == V4L2_FIELD_SEQ_TB ||\
	 (field) == V4L2_FIELD_SEQ_BT)
#define V4L2_FIELD_HAS_BOTTOM(field)	\
	((field) == V4L2_FIELD_BOTTOM	||\
	 (field) == V4L2_FIELD_INTERLACED ||\
	 (field) == V4L2_FIELD_INTERLACED_TB ||\
	 (field) == V4L2_FIELD_INTERLACED_BT ||\
	 (field) == V4L2_FIELD_SEQ_TB	||\
	 (field) == V4L2_FIELD_SEQ_BT)
#define V4L2_FIELD_HAS_TOP(field)	\
	((field) == V4L2_FIELD_TOP	||\
	 (field) == V4L2_FIELD_INTERLACED ||\
	 (field) == V4L2_FIELD_INTERLACED_TB ||\
	 (field) == V4L2_FIELD_INTERLACED_BT ||\
	 (field) == V4L2_FIELD_SEQ_TB	||\
	 (field) == V4L2_FIELD_SEQ_BT)
#define V4L2_FIELD_HAS_T_OR_B(field)	\
	((field) == V4L2_FIELD_BOTTOM ||\
	 (field) == V4L2_FIELD_TOP ||\
	 (field) == V4L2_FIELD_ALTERNATE)
#define V4L2_FIELD_IS_INTERLACED(field) \
	((field) == V4L2_FIELD_INTERLACED ||\
	 (field) == V4L2_FIELD_INTERLACED_TB ||\
	 (field) == V4L2_FIELD_INTERLACED_BT)
#define V4L2_FIELD_IS_SEQUENTIAL(field) \
	((field) == V4L2_FIELD_SEQ_TB ||\
	 (field) == V4L2_FIELD_SEQ_BT)
#define V4L2_IN_ST_COLOR_KILL  0x00000200  
#define V4L2_IN_ST_HFLIP       0x00000010 
#define V4L2_IN_ST_MACROVISION 0x01000000  
#define V4L2_IN_ST_NO_ACCESS   0x02000000  
#define V4L2_IN_ST_NO_CARRIER  0x00040000  
#define V4L2_IN_ST_NO_COLOR    0x00000004
#define V4L2_IN_ST_NO_EQU      0x00020000  
#define V4L2_IN_ST_NO_H_LOCK   0x00000100  
#define V4L2_IN_ST_NO_POWER    0x00000001  
#define V4L2_IN_ST_NO_SIGNAL   0x00000002
#define V4L2_IN_ST_NO_STD_LOCK 0x00000800  
#define V4L2_IN_ST_NO_SYNC     0x00010000  
#define V4L2_IN_ST_NO_V_LOCK   0x00000400  
#define V4L2_IN_ST_VFLIP       0x00000020 
#define V4L2_IN_ST_VTR         0x04000000  
#define V4L2_JPEG_MARKER_APP (1<<7)    
#define V4L2_JPEG_MARKER_COM (1<<6)    
#define V4L2_JPEG_MARKER_DHT (1<<3)    
#define V4L2_JPEG_MARKER_DQT (1<<4)    
#define V4L2_JPEG_MARKER_DRI (1<<5)    
#define V4L2_MAP_COLORSPACE_DEFAULT(is_sdtv, is_hdtv) \
	((is_sdtv) ? V4L2_COLORSPACE_SMPTE170M : \
	 ((is_hdtv) ? V4L2_COLORSPACE_REC709 : V4L2_COLORSPACE_SRGB))
#define V4L2_MAP_QUANTIZATION_DEFAULT(is_rgb_or_hsv, colsp, ycbcr_enc) \
	(((is_rgb_or_hsv) && (colsp) == V4L2_COLORSPACE_BT2020) ? \
	 V4L2_QUANTIZATION_LIM_RANGE : \
	 (((is_rgb_or_hsv) || (colsp) == V4L2_COLORSPACE_JPEG) ? \
	 V4L2_QUANTIZATION_FULL_RANGE : V4L2_QUANTIZATION_LIM_RANGE))
#define V4L2_MAP_XFER_FUNC_DEFAULT(colsp) \
	((colsp) == V4L2_COLORSPACE_OPRGB ? V4L2_XFER_FUNC_OPRGB : \
	 ((colsp) == V4L2_COLORSPACE_SMPTE240M ? V4L2_XFER_FUNC_SMPTE240M : \
	  ((colsp) == V4L2_COLORSPACE_DCI_P3 ? V4L2_XFER_FUNC_DCI_P3 : \
	   ((colsp) == V4L2_COLORSPACE_RAW ? V4L2_XFER_FUNC_NONE : \
	    ((colsp) == V4L2_COLORSPACE_SRGB || (colsp) == V4L2_COLORSPACE_JPEG ? \
	     V4L2_XFER_FUNC_SRGB : V4L2_XFER_FUNC_709)))))
#define V4L2_MAP_YCBCR_ENC_DEFAULT(colsp) \
	(((colsp) == V4L2_COLORSPACE_REC709 || \
	  (colsp) == V4L2_COLORSPACE_DCI_P3) ? V4L2_YCBCR_ENC_709 : \
	 ((colsp) == V4L2_COLORSPACE_BT2020 ? V4L2_YCBCR_ENC_BT2020 : \
	  ((colsp) == V4L2_COLORSPACE_SMPTE240M ? V4L2_YCBCR_ENC_SMPTE240M : \
	   V4L2_YCBCR_ENC_601)))
#define V4L2_META_FMT_D4XX        v4l2_fourcc('D', '4', 'X', 'X') 
#define V4L2_META_FMT_UVC         v4l2_fourcc('U', 'V', 'C', 'H') 
#define V4L2_META_FMT_VSP1_HGO    v4l2_fourcc('V', 'S', 'P', 'H') 
#define V4L2_META_FMT_VSP1_HGT    v4l2_fourcc('V', 'S', 'P', 'T') 
#define V4L2_MPEG_VBI_IVTV_CAPTION_525    (4)
#define V4L2_MPEG_VBI_IVTV_TELETEXT_B     (1)
#define V4L2_MPEG_VBI_IVTV_VPS            (7)
#define V4L2_MPEG_VBI_IVTV_WSS_625        (5)
#define V4L2_PIX_FMT_ABGR32  v4l2_fourcc('A', 'R', '2', '4') 
#define V4L2_PIX_FMT_ABGR444 v4l2_fourcc('A', 'B', '1', '2') 
#define V4L2_PIX_FMT_ABGR555 v4l2_fourcc('A', 'B', '1', '5') 
#define V4L2_PIX_FMT_ARGB32  v4l2_fourcc('B', 'A', '2', '4') 
#define V4L2_PIX_FMT_ARGB444 v4l2_fourcc('A', 'R', '1', '2') 
#define V4L2_PIX_FMT_ARGB555 v4l2_fourcc('A', 'R', '1', '5') 
#define V4L2_PIX_FMT_ARGB555X v4l2_fourcc_be('A', 'R', '1', '5') 
#define V4L2_PIX_FMT_AYUV32  v4l2_fourcc('A', 'Y', 'U', 'V') 
#define V4L2_PIX_FMT_BGR24   v4l2_fourcc('B', 'G', 'R', '3') 
#define V4L2_PIX_FMT_BGR32   v4l2_fourcc('B', 'G', 'R', '4') 
#define V4L2_PIX_FMT_BGR666  v4l2_fourcc('B', 'G', 'R', 'H') 
#define V4L2_PIX_FMT_BGRA32  v4l2_fourcc('R', 'A', '2', '4') 
#define V4L2_PIX_FMT_BGRA444 v4l2_fourcc('G', 'A', '1', '2') 
#define V4L2_PIX_FMT_BGRA555 v4l2_fourcc('B', 'A', '1', '5') 
#define V4L2_PIX_FMT_BGRX32  v4l2_fourcc('R', 'X', '2', '4') 
#define V4L2_PIX_FMT_BGRX444 v4l2_fourcc('B', 'X', '1', '2') 
#define V4L2_PIX_FMT_BGRX555 v4l2_fourcc('B', 'X', '1', '5') 
#define V4L2_PIX_FMT_CIT_YYVYUY v4l2_fourcc('C', 'I', 'T', 'V') 
#define V4L2_PIX_FMT_CNF4     v4l2_fourcc('C', 'N', 'F', '4') 
#define V4L2_PIX_FMT_CPIA1    v4l2_fourcc('C', 'P', 'I', 'A') 
#define V4L2_PIX_FMT_DV       v4l2_fourcc('d', 'v', 's', 'd') 
#define V4L2_PIX_FMT_ET61X251 v4l2_fourcc('E', '6', '2', '5') 
#define V4L2_PIX_FMT_FWHT     v4l2_fourcc('F', 'W', 'H', 'T') 
#define V4L2_PIX_FMT_FWHT_STATELESS     v4l2_fourcc('S', 'F', 'W', 'H') 
#define V4L2_PIX_FMT_GREY    v4l2_fourcc('G', 'R', 'E', 'Y') 
#define V4L2_PIX_FMT_H263     v4l2_fourcc('H', '2', '6', '3') 
#define V4L2_PIX_FMT_H264     v4l2_fourcc('H', '2', '6', '4') 
#define V4L2_PIX_FMT_H264_MVC v4l2_fourcc('M', '2', '6', '4') 
#define V4L2_PIX_FMT_H264_NO_SC v4l2_fourcc('A', 'V', 'C', '1') 
#define V4L2_PIX_FMT_HEVC     v4l2_fourcc('H', 'E', 'V', 'C') 
#define V4L2_PIX_FMT_HI240   v4l2_fourcc('H', 'I', '2', '4') 
#define V4L2_PIX_FMT_HM12    v4l2_fourcc('H', 'M', '1', '2') 
#define V4L2_PIX_FMT_HSV24 v4l2_fourcc('H', 'S', 'V', '3')
#define V4L2_PIX_FMT_HSV32 v4l2_fourcc('H', 'S', 'V', '4')
#define V4L2_PIX_FMT_INZI     v4l2_fourcc('I', 'N', 'Z', 'I') 
#define V4L2_PIX_FMT_JL2005BCD v4l2_fourcc('J', 'L', '2', '0') 
#define V4L2_PIX_FMT_JPEG     v4l2_fourcc('J', 'P', 'E', 'G') 
#define V4L2_PIX_FMT_KONICA420  v4l2_fourcc('K', 'O', 'N', 'I') 
#define V4L2_PIX_FMT_M420    v4l2_fourcc('M', '4', '2', '0') 
#define V4L2_PIX_FMT_MJPEG    v4l2_fourcc('M', 'J', 'P', 'G') 
#define V4L2_PIX_FMT_MPEG     v4l2_fourcc('M', 'P', 'E', 'G') 
#define V4L2_PIX_FMT_MPEG1    v4l2_fourcc('M', 'P', 'G', '1') 
#define V4L2_PIX_FMT_MPEG2    v4l2_fourcc('M', 'P', 'G', '2') 
#define V4L2_PIX_FMT_MPEG2_SLICE v4l2_fourcc('M', 'G', '2', 'S') 
#define V4L2_PIX_FMT_MPEG4    v4l2_fourcc('M', 'P', 'G', '4') 
#define V4L2_PIX_FMT_MR97310A v4l2_fourcc('M', '3', '1', '0') 
#define V4L2_PIX_FMT_MT21C    v4l2_fourcc('M', 'T', '2', '1') 
#define V4L2_PIX_FMT_NV12    v4l2_fourcc('N', 'V', '1', '2') 
#define V4L2_PIX_FMT_NV12M   v4l2_fourcc('N', 'M', '1', '2') 
#define V4L2_PIX_FMT_NV12MT  v4l2_fourcc('T', 'M', '1', '2') 
#define V4L2_PIX_FMT_NV12MT_16X16 v4l2_fourcc('V', 'M', '1', '2') 
#define V4L2_PIX_FMT_NV16    v4l2_fourcc('N', 'V', '1', '6') 
#define V4L2_PIX_FMT_NV16M   v4l2_fourcc('N', 'M', '1', '6') 
#define V4L2_PIX_FMT_NV21    v4l2_fourcc('N', 'V', '2', '1') 
#define V4L2_PIX_FMT_NV21M   v4l2_fourcc('N', 'M', '2', '1') 
#define V4L2_PIX_FMT_NV24    v4l2_fourcc('N', 'V', '2', '4') 
#define V4L2_PIX_FMT_NV42    v4l2_fourcc('N', 'V', '4', '2') 
#define V4L2_PIX_FMT_NV61    v4l2_fourcc('N', 'V', '6', '1') 
#define V4L2_PIX_FMT_NV61M   v4l2_fourcc('N', 'M', '6', '1') 
#define V4L2_PIX_FMT_OV511    v4l2_fourcc('O', '5', '1', '1') 
#define V4L2_PIX_FMT_OV518    v4l2_fourcc('O', '5', '1', '8') 
#define V4L2_PIX_FMT_PAC207   v4l2_fourcc('P', '2', '0', '7') 
#define V4L2_PIX_FMT_PAL8    v4l2_fourcc('P', 'A', 'L', '8') 
#define V4L2_PIX_FMT_PJPG     v4l2_fourcc('P', 'J', 'P', 'G') 
#define V4L2_PIX_FMT_PWC1     v4l2_fourcc('P', 'W', 'C', '1') 
#define V4L2_PIX_FMT_PWC2     v4l2_fourcc('P', 'W', 'C', '2') 
#define V4L2_PIX_FMT_RGB24   v4l2_fourcc('R', 'G', 'B', '3') 
#define V4L2_PIX_FMT_RGB32   v4l2_fourcc('R', 'G', 'B', '4') 
#define V4L2_PIX_FMT_RGB332  v4l2_fourcc('R', 'G', 'B', '1') 
#define V4L2_PIX_FMT_RGB444  v4l2_fourcc('R', '4', '4', '4') 
#define V4L2_PIX_FMT_RGB555  v4l2_fourcc('R', 'G', 'B', 'O') 
#define V4L2_PIX_FMT_RGB555X v4l2_fourcc('R', 'G', 'B', 'Q') 
#define V4L2_PIX_FMT_RGB565  v4l2_fourcc('R', 'G', 'B', 'P') 
#define V4L2_PIX_FMT_RGB565X v4l2_fourcc('R', 'G', 'B', 'R') 
#define V4L2_PIX_FMT_RGBA32  v4l2_fourcc('A', 'B', '2', '4') 
#define V4L2_PIX_FMT_RGBA444 v4l2_fourcc('R', 'A', '1', '2') 
#define V4L2_PIX_FMT_RGBA555 v4l2_fourcc('R', 'A', '1', '5') 
#define V4L2_PIX_FMT_RGBX32  v4l2_fourcc('X', 'B', '2', '4') 
#define V4L2_PIX_FMT_RGBX444 v4l2_fourcc('R', 'X', '1', '2') 
#define V4L2_PIX_FMT_RGBX555 v4l2_fourcc('R', 'X', '1', '5') 
#define V4L2_PIX_FMT_S5C_UYVY_JPG v4l2_fourcc('S', '5', 'C', 'I') 
#define V4L2_PIX_FMT_SBGGR10 v4l2_fourcc('B', 'G', '1', '0') 
#define V4L2_PIX_FMT_SBGGR10ALAW8 v4l2_fourcc('a', 'B', 'A', '8')
#define V4L2_PIX_FMT_SBGGR10DPCM8 v4l2_fourcc('b', 'B', 'A', '8')
#define V4L2_PIX_FMT_SBGGR10P v4l2_fourcc('p', 'B', 'A', 'A')
#define V4L2_PIX_FMT_SBGGR12 v4l2_fourcc('B', 'G', '1', '2') 
#define V4L2_PIX_FMT_SBGGR12P v4l2_fourcc('p', 'B', 'C', 'C')
#define V4L2_PIX_FMT_SBGGR14P v4l2_fourcc('p', 'B', 'E', 'E')
#define V4L2_PIX_FMT_SBGGR16 v4l2_fourcc('B', 'Y', 'R', '2') 
#define V4L2_PIX_FMT_SBGGR8  v4l2_fourcc('B', 'A', '8', '1') 
#define V4L2_PIX_FMT_SE401      v4l2_fourcc('S', '4', '0', '1') 
#define V4L2_PIX_FMT_SGBRG10 v4l2_fourcc('G', 'B', '1', '0') 
#define V4L2_PIX_FMT_SGBRG10ALAW8 v4l2_fourcc('a', 'G', 'A', '8')
#define V4L2_PIX_FMT_SGBRG10DPCM8 v4l2_fourcc('b', 'G', 'A', '8')
#define V4L2_PIX_FMT_SGBRG10P v4l2_fourcc('p', 'G', 'A', 'A')
#define V4L2_PIX_FMT_SGBRG12 v4l2_fourcc('G', 'B', '1', '2') 
#define V4L2_PIX_FMT_SGBRG12P v4l2_fourcc('p', 'G', 'C', 'C')
#define V4L2_PIX_FMT_SGBRG14P v4l2_fourcc('p', 'G', 'E', 'E')
#define V4L2_PIX_FMT_SGBRG16 v4l2_fourcc('G', 'B', '1', '6') 
#define V4L2_PIX_FMT_SGBRG8  v4l2_fourcc('G', 'B', 'R', 'G') 
#define V4L2_PIX_FMT_SGRBG10 v4l2_fourcc('B', 'A', '1', '0') 
#define V4L2_PIX_FMT_SGRBG10ALAW8 v4l2_fourcc('a', 'g', 'A', '8')
#define V4L2_PIX_FMT_SGRBG10DPCM8 v4l2_fourcc('B', 'D', '1', '0')
#define V4L2_PIX_FMT_SGRBG10P v4l2_fourcc('p', 'g', 'A', 'A')
#define V4L2_PIX_FMT_SGRBG12 v4l2_fourcc('B', 'A', '1', '2') 
#define V4L2_PIX_FMT_SGRBG12P v4l2_fourcc('p', 'g', 'C', 'C')
#define V4L2_PIX_FMT_SGRBG14P v4l2_fourcc('p', 'g', 'E', 'E')
#define V4L2_PIX_FMT_SGRBG16 v4l2_fourcc('G', 'R', '1', '6') 
#define V4L2_PIX_FMT_SGRBG8  v4l2_fourcc('G', 'R', 'B', 'G') 
#define V4L2_PIX_FMT_SN9C10X  v4l2_fourcc('S', '9', '1', '0') 
#define V4L2_PIX_FMT_SN9C2028 v4l2_fourcc('S', 'O', 'N', 'X') 
#define V4L2_PIX_FMT_SN9C20X_I420 v4l2_fourcc('S', '9', '2', '0') 
#define V4L2_PIX_FMT_SPCA501  v4l2_fourcc('S', '5', '0', '1') 
#define V4L2_PIX_FMT_SPCA505  v4l2_fourcc('S', '5', '0', '5') 
#define V4L2_PIX_FMT_SPCA508  v4l2_fourcc('S', '5', '0', '8') 
#define V4L2_PIX_FMT_SPCA561  v4l2_fourcc('S', '5', '6', '1') 
#define V4L2_PIX_FMT_SQ905C   v4l2_fourcc('9', '0', '5', 'C') 
#define V4L2_PIX_FMT_SRGGB10 v4l2_fourcc('R', 'G', '1', '0') 
#define V4L2_PIX_FMT_SRGGB10ALAW8 v4l2_fourcc('a', 'R', 'A', '8')
#define V4L2_PIX_FMT_SRGGB10DPCM8 v4l2_fourcc('b', 'R', 'A', '8')
#define V4L2_PIX_FMT_SRGGB10P v4l2_fourcc('p', 'R', 'A', 'A')
#define V4L2_PIX_FMT_SRGGB12 v4l2_fourcc('R', 'G', '1', '2') 
#define V4L2_PIX_FMT_SRGGB12P v4l2_fourcc('p', 'R', 'C', 'C')
#define V4L2_PIX_FMT_SRGGB14P v4l2_fourcc('p', 'R', 'E', 'E')
#define V4L2_PIX_FMT_SRGGB16 v4l2_fourcc('R', 'G', '1', '6') 
#define V4L2_PIX_FMT_SRGGB8  v4l2_fourcc('R', 'G', 'G', 'B') 
#define V4L2_PIX_FMT_STV0680  v4l2_fourcc('S', '6', '8', '0') 
#define V4L2_PIX_FMT_SUNXI_TILED_NV12 v4l2_fourcc('S', 'T', '1', '2') 
#define V4L2_PIX_FMT_TM6000   v4l2_fourcc('T', 'M', '6', '0') 
#define V4L2_PIX_FMT_UV8     v4l2_fourcc('U', 'V', '8', ' ') 
#define V4L2_PIX_FMT_UYVY    v4l2_fourcc('U', 'Y', 'V', 'Y') 
#define V4L2_PIX_FMT_VC1_ANNEX_G v4l2_fourcc('V', 'C', '1', 'G') 
#define V4L2_PIX_FMT_VC1_ANNEX_L v4l2_fourcc('V', 'C', '1', 'L') 
#define V4L2_PIX_FMT_VP8      v4l2_fourcc('V', 'P', '8', '0') 
#define V4L2_PIX_FMT_VP9      v4l2_fourcc('V', 'P', '9', '0') 
#define V4L2_PIX_FMT_VUYA32  v4l2_fourcc('V', 'U', 'Y', 'A') 
#define V4L2_PIX_FMT_VUYX32  v4l2_fourcc('V', 'U', 'Y', 'X') 
#define V4L2_PIX_FMT_VYUY    v4l2_fourcc('V', 'Y', 'U', 'Y') 
#define V4L2_PIX_FMT_WNVA     v4l2_fourcc('W', 'N', 'V', 'A') 
#define V4L2_PIX_FMT_XBGR32  v4l2_fourcc('X', 'R', '2', '4') 
#define V4L2_PIX_FMT_XBGR444 v4l2_fourcc('X', 'B', '1', '2') 
#define V4L2_PIX_FMT_XBGR555 v4l2_fourcc('X', 'B', '1', '5') 
#define V4L2_PIX_FMT_XRGB32  v4l2_fourcc('B', 'X', '2', '4') 
#define V4L2_PIX_FMT_XRGB444 v4l2_fourcc('X', 'R', '1', '2') 
#define V4L2_PIX_FMT_XRGB555 v4l2_fourcc('X', 'R', '1', '5') 
#define V4L2_PIX_FMT_XRGB555X v4l2_fourcc_be('X', 'R', '1', '5') 
#define V4L2_PIX_FMT_XVID     v4l2_fourcc('X', 'V', 'I', 'D') 
#define V4L2_PIX_FMT_XYUV32  v4l2_fourcc('X', 'Y', 'U', 'V') 
#define V4L2_PIX_FMT_Y10     v4l2_fourcc('Y', '1', '0', ' ') 
#define V4L2_PIX_FMT_Y10BPACK    v4l2_fourcc('Y', '1', '0', 'B') 
#define V4L2_PIX_FMT_Y10P    v4l2_fourcc('Y', '1', '0', 'P') 
#define V4L2_PIX_FMT_Y12     v4l2_fourcc('Y', '1', '2', ' ') 
#define V4L2_PIX_FMT_Y12I     v4l2_fourcc('Y', '1', '2', 'I') 
#define V4L2_PIX_FMT_Y16     v4l2_fourcc('Y', '1', '6', ' ') 
#define V4L2_PIX_FMT_Y16_BE  v4l2_fourcc_be('Y', '1', '6', ' ') 
#define V4L2_PIX_FMT_Y4      v4l2_fourcc('Y', '0', '4', ' ') 
#define V4L2_PIX_FMT_Y41P    v4l2_fourcc('Y', '4', '1', 'P') 
#define V4L2_PIX_FMT_Y6      v4l2_fourcc('Y', '0', '6', ' ') 
#define V4L2_PIX_FMT_Y8I      v4l2_fourcc('Y', '8', 'I', ' ') 
#define V4L2_PIX_FMT_YUV32   v4l2_fourcc('Y', 'U', 'V', '4') 
#define V4L2_PIX_FMT_YUV410  v4l2_fourcc('Y', 'U', 'V', '9') 
#define V4L2_PIX_FMT_YUV411P v4l2_fourcc('4', '1', '1', 'P') 
#define V4L2_PIX_FMT_YUV420  v4l2_fourcc('Y', 'U', '1', '2') 
#define V4L2_PIX_FMT_YUV420M v4l2_fourcc('Y', 'M', '1', '2') 
#define V4L2_PIX_FMT_YUV422M v4l2_fourcc('Y', 'M', '1', '6') 
#define V4L2_PIX_FMT_YUV422P v4l2_fourcc('4', '2', '2', 'P') 
#define V4L2_PIX_FMT_YUV444  v4l2_fourcc('Y', '4', '4', '4') 
#define V4L2_PIX_FMT_YUV444M v4l2_fourcc('Y', 'M', '2', '4') 
#define V4L2_PIX_FMT_YUV555  v4l2_fourcc('Y', 'U', 'V', 'O') 
#define V4L2_PIX_FMT_YUV565  v4l2_fourcc('Y', 'U', 'V', 'P') 
#define V4L2_PIX_FMT_YUYV    v4l2_fourcc('Y', 'U', 'Y', 'V') 
#define V4L2_PIX_FMT_YVU410  v4l2_fourcc('Y', 'V', 'U', '9') 
#define V4L2_PIX_FMT_YVU420  v4l2_fourcc('Y', 'V', '1', '2') 
#define V4L2_PIX_FMT_YVU420M v4l2_fourcc('Y', 'M', '2', '1') 
#define V4L2_PIX_FMT_YVU422M v4l2_fourcc('Y', 'M', '6', '1') 
#define V4L2_PIX_FMT_YVU444M v4l2_fourcc('Y', 'M', '4', '2') 
#define V4L2_PIX_FMT_YVYU    v4l2_fourcc('Y', 'V', 'Y', 'U') 
#define V4L2_PIX_FMT_YYUV    v4l2_fourcc('Y', 'Y', 'U', 'V') 
#define V4L2_PIX_FMT_Z16      v4l2_fourcc('Z', '1', '6', ' ') 
#define V4L2_RDS_BLOCK_CORRECTED 0x40
#define V4L2_SDR_FMT_CS14LE       v4l2_fourcc('C', 'S', '1', '4') 
#define V4L2_SDR_FMT_CS8          v4l2_fourcc('C', 'S', '0', '8') 
#define V4L2_SDR_FMT_CU16LE       v4l2_fourcc('C', 'U', '1', '6') 
#define V4L2_SDR_FMT_CU8          v4l2_fourcc('C', 'U', '0', '8') 
#define V4L2_SDR_FMT_RU12LE       v4l2_fourcc('R', 'U', '1', '2') 
#define V4L2_SLICED_CAPTION_525         (0x1000)
#define V4L2_SLICED_TELETEXT_B          (0x0001)
#define V4L2_SLICED_VBI_525             (V4L2_SLICED_CAPTION_525)
#define V4L2_SLICED_VBI_625             (V4L2_SLICED_TELETEXT_B | V4L2_SLICED_VPS | V4L2_SLICED_WSS_625)
#define V4L2_SLICED_VPS                 (0x0400)
#define V4L2_SLICED_WSS_625             (0x4000)
#define V4L2_STD_ALL            (V4L2_STD_525_60	|\
				 V4L2_STD_625_50)
#define V4L2_STD_ATSC           (V4L2_STD_ATSC_8_VSB    |\
				 V4L2_STD_ATSC_16_VSB)
#define V4L2_STD_ATSC_16_VSB    ((v4l2_std_id)0x02000000)
#define V4L2_STD_ATSC_8_VSB     ((v4l2_std_id)0x01000000)
#define V4L2_STD_NTSC           (V4L2_STD_NTSC_M	|\
				 V4L2_STD_NTSC_M_JP     |\
				 V4L2_STD_NTSC_M_KR)
#define V4L2_STD_NTSC_443       ((v4l2_std_id)0x00004000)
#define V4L2_STD_NTSC_M         ((v4l2_std_id)0x00001000)	
#define V4L2_STD_NTSC_M_JP      ((v4l2_std_id)0x00002000)	
#define V4L2_STD_NTSC_M_KR      ((v4l2_std_id)0x00008000)	
#define V4L2_STD_PAL		(V4L2_STD_PAL_BG	|\
				 V4L2_STD_PAL_DK	|\
				 V4L2_STD_PAL_H		|\
				 V4L2_STD_PAL_I)
#define V4L2_STD_PAL_60         ((v4l2_std_id)0x00000800)
#define V4L2_STD_PAL_B          ((v4l2_std_id)0x00000001)
#define V4L2_STD_PAL_B1         ((v4l2_std_id)0x00000002)
#define V4L2_STD_PAL_D          ((v4l2_std_id)0x00000020)
#define V4L2_STD_PAL_D1         ((v4l2_std_id)0x00000040)
#define V4L2_STD_PAL_G          ((v4l2_std_id)0x00000004)
#define V4L2_STD_PAL_H          ((v4l2_std_id)0x00000008)
#define V4L2_STD_PAL_I          ((v4l2_std_id)0x00000010)
#define V4L2_STD_PAL_K          ((v4l2_std_id)0x00000080)
#define V4L2_STD_PAL_M          ((v4l2_std_id)0x00000100)
#define V4L2_STD_PAL_N          ((v4l2_std_id)0x00000200)
#define V4L2_STD_PAL_Nc         ((v4l2_std_id)0x00000400)
#define V4L2_STD_SECAM		(V4L2_STD_SECAM_B	|\
				 V4L2_STD_SECAM_G	|\
				 V4L2_STD_SECAM_H	|\
				 V4L2_STD_SECAM_DK	|\
				 V4L2_STD_SECAM_L       |\
				 V4L2_STD_SECAM_LC)
#define V4L2_STD_SECAM_B        ((v4l2_std_id)0x00010000)
#define V4L2_STD_SECAM_D        ((v4l2_std_id)0x00020000)
#define V4L2_STD_SECAM_G        ((v4l2_std_id)0x00040000)
#define V4L2_STD_SECAM_H        ((v4l2_std_id)0x00080000)
#define V4L2_STD_SECAM_K        ((v4l2_std_id)0x00100000)
#define V4L2_STD_SECAM_K1       ((v4l2_std_id)0x00200000)
#define V4L2_STD_SECAM_L        ((v4l2_std_id)0x00400000)
#define V4L2_STD_SECAM_LC       ((v4l2_std_id)0x00800000)
#define V4L2_STD_UNKNOWN        0
#define V4L2_TUNER_ADC  V4L2_TUNER_SDR
#define V4L2_TYPE_IS_MULTIPLANAR(type)			\
	((type) == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE	\
	 || (type) == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE)
#define V4L2_TYPE_IS_OUTPUT(type)				\
	((type) == V4L2_BUF_TYPE_VIDEO_OUTPUT			\
	 || (type) == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE		\
	 || (type) == V4L2_BUF_TYPE_VIDEO_OVERLAY		\
	 || (type) == V4L2_BUF_TYPE_VIDEO_OUTPUT_OVERLAY	\
	 || (type) == V4L2_BUF_TYPE_VBI_OUTPUT			\
	 || (type) == V4L2_BUF_TYPE_SLICED_VBI_OUTPUT		\
	 || (type) == V4L2_BUF_TYPE_SDR_OUTPUT			\
	 || (type) == V4L2_BUF_TYPE_META_OUTPUT)
#define V4L2_VBI_ITU_525_F1_START (1)
#define V4L2_VBI_ITU_525_F2_START (264)
#define V4L2_VBI_ITU_625_F1_START (1)
#define V4L2_VBI_ITU_625_F2_START (314)
#define V4L2_XFER_FUNC_ADOBERGB  V4L2_XFER_FUNC_OPRGB
#define VIDEO_MAX_FRAME               32
#define VIDEO_MAX_PLANES               8
#define VIDIOC_DBG_G_CHIP_INFO  _IOWR('V', 102, struct v4l2_dbg_chip_info)
#define VIDIOC_DV_TIMINGS_CAP   _IOWR('V', 100, struct v4l2_dv_timings_cap)
#define VIDIOC_ENCODER_CMD      _IOWR('V', 77, struct v4l2_encoder_cmd)
#define VIDIOC_ENUM_DV_TIMINGS  _IOWR('V', 98, struct v4l2_enum_dv_timings)
#define VIDIOC_ENUM_FMT         _IOWR('V',  2, struct v4l2_fmtdesc)
#define VIDIOC_ENUM_FRAMEINTERVALS _IOWR('V', 75, struct v4l2_frmivalenum)
#define VIDIOC_G_ENC_INDEX       _IOR('V', 76, struct v4l2_enc_idx)
#define VIDIOC_G_SLICED_VBI_CAP _IOWR('V', 69, struct v4l2_sliced_vbi_cap)
#define VIDIOC_LOG_STATUS         _IO('V', 70)
#define VIDIOC_QUERY_DV_TIMINGS  _IOR('V', 99, struct v4l2_dv_timings)
#define VIDIOC_TRY_ENCODER_CMD  _IOWR('V', 78, struct v4l2_encoder_cmd)

#define v4l2_fourcc(a, b, c, d)\
	((__u32)(a) | ((__u32)(b) << 8) | ((__u32)(c) << 16) | ((__u32)(d) << 24))
#define v4l2_fourcc_be(a, b, c, d)	(v4l2_fourcc(a, b, c, d) | (1U << 31))
#define V4L2_DEVICE_NAME_SIZE (20 + 16)

#define __v4l2_device_call_subdevs(v4l2_dev, cond, o, f, args...)	\
	do {								\
		struct v4l2_subdev *__sd;				\
									\
		__v4l2_device_call_subdevs_p(v4l2_dev, __sd, cond, o,	\
						f , ##args);		\
	} while (0)
#define __v4l2_device_call_subdevs_p(v4l2_dev, sd, cond, o, f, args...)	\
	do {								\
		list_for_each_entry((sd), &(v4l2_dev)->subdevs, list)	\
			if ((cond) && (sd)->ops->o && (sd)->ops->o->f)	\
				(sd)->ops->o->f((sd) , ##args);		\
	} while (0)
#define __v4l2_device_call_subdevs_until_err(v4l2_dev, cond, o, f, args...) \
({									\
	struct v4l2_subdev *__sd;					\
	__v4l2_device_call_subdevs_until_err_p(v4l2_dev, __sd, cond, o,	\
						f , ##args);		\
})
#define __v4l2_device_call_subdevs_until_err_p(v4l2_dev, sd, cond, o, f, args...) \
({									\
	long __err = 0;							\
									\
	list_for_each_entry((sd), &(v4l2_dev)->subdevs, list) {		\
		if ((cond) && (sd)->ops->o && (sd)->ops->o->f)		\
			__err = (sd)->ops->o->f((sd) , ##args);		\
		if (__err && __err != -ENOIOCTLCMD)			\
			break;						\
	}								\
	(__err == -ENOIOCTLCMD) ? 0 : __err;				\
})
#define v4l2_device_call_all(v4l2_dev, grpid, o, f, args...)		\
	do {								\
		struct v4l2_subdev *__sd;				\
									\
		__v4l2_device_call_subdevs_p(v4l2_dev, __sd,		\
			(grpid) == 0 || __sd->grp_id == (grpid), o, f ,	\
			##args);					\
	} while (0)
#define v4l2_device_call_until_err(v4l2_dev, grpid, o, f, args...)	\
({									\
	struct v4l2_subdev *__sd;					\
	__v4l2_device_call_subdevs_until_err_p(v4l2_dev, __sd,		\
			(grpid) == 0 || __sd->grp_id == (grpid), o, f ,	\
			##args);					\
})
#define v4l2_device_for_each_subdev(sd, v4l2_dev)			\
	list_for_each_entry(sd, &(v4l2_dev)->subdevs, list)
#define v4l2_device_has_op(v4l2_dev, grpid, o, f)			\
({									\
	struct v4l2_subdev *__sd;					\
	bool __result = false;						\
	list_for_each_entry(__sd, &(v4l2_dev)->subdevs, list) {		\
		if ((grpid) && __sd->grp_id != (grpid))			\
			continue;					\
		if (v4l2_subdev_has_op(__sd, o, f)) {			\
			__result = true;				\
			break;						\
		}							\
	}								\
	__result;							\
})
#define v4l2_device_mask_call_all(v4l2_dev, grpmsk, o, f, args...)	\
	do {								\
		struct v4l2_subdev *__sd;				\
									\
		__v4l2_device_call_subdevs_p(v4l2_dev, __sd,		\
			(grpmsk) == 0 || (__sd->grp_id & (grpmsk)), o,	\
			f , ##args);					\
	} while (0)
#define v4l2_device_mask_call_until_err(v4l2_dev, grpmsk, o, f, args...) \
({									\
	struct v4l2_subdev *__sd;					\
	__v4l2_device_call_subdevs_until_err_p(v4l2_dev, __sd,		\
			(grpmsk) == 0 || (__sd->grp_id & (grpmsk)), o,	\
			f , ##args);					\
})
#define v4l2_device_mask_has_op(v4l2_dev, grpmsk, o, f)			\
({									\
	struct v4l2_subdev *__sd;					\
	bool __result = false;						\
	list_for_each_entry(__sd, &(v4l2_dev)->subdevs, list) {		\
		if ((grpmsk) && !(__sd->grp_id & (grpmsk)))		\
			continue;					\
		if (v4l2_subdev_has_op(__sd, o, f)) {			\
			__result = true;				\
			break;						\
		}							\
	}								\
	__result;							\
})

#define media_entity_to_video_device(__entity) \
	container_of(__entity, struct video_device, entity)
#define to_video_device(cd) container_of(cd, struct video_device, dev)
#define V4L2_SUBDEV_NAME_SIZE 32

#define media_entity_to_v4l2_subdev(ent)				\
({									\
	typeof(ent) __me_sd_ent = (ent);				\
									\
	__me_sd_ent ?							\
		container_of(__me_sd_ent, struct v4l2_subdev, entity) :	\
		NULL;							\
})
#define to_v4l2_subdev_fh(fh)	\
	container_of(fh, struct v4l2_subdev_fh, vfh)
#define v4l2_subdev_call(sd, o, f, args...)				\
	({								\
		struct v4l2_subdev *__sd = (sd);			\
		int __result;						\
		if (!__sd)						\
			__result = -ENODEV;				\
		else if (!(__sd->ops->o && __sd->ops->o->f))		\
			__result = -ENOIOCTLCMD;			\
		else if (v4l2_subdev_call_wrappers.o &&			\
			 v4l2_subdev_call_wrappers.o->f)		\
			__result = v4l2_subdev_call_wrappers.o->f(	\
							__sd, ##args);	\
		else							\
			__result = __sd->ops->o->f(__sd, ##args);	\
		__result;						\
	})
#define v4l2_subdev_has_op(sd, o, f) \
	((sd)->ops->o && (sd)->ops->o->f)
#define vdev_to_v4l2_subdev(vdev) \
	((struct v4l2_subdev *)video_get_drvdata(vdev))


#define TUNER_SET_CONFIG           _IOW('d', 92, struct v4l2_priv_tun_config)

#define V4L2_FRACT_COMPARE(a, OP, b)			\
	((u64)(a).numerator * (b).denominator OP	\
	(u64)(b).numerator * (a).denominator)
#define dev_dbg_lvl(__dev, __level, __debug, __fmt, __arg...)		\
	do {								\
		if (__debug >= (__level))				\
			dev_printk(KERN_DEBUG, __dev, __fmt, ##__arg);	\
	} while (0)
#define v4l2_dbg(level, debug, dev, fmt, arg...)			\
	do {								\
		if (debug >= (level))					\
			v4l2_printk(KERN_DEBUG, dev, fmt , ## arg);	\
	} while (0)
#define v4l2_err(dev, fmt, arg...) \
	v4l2_printk(KERN_ERR, dev, fmt , ## arg)
#define v4l2_find_nearest_size(array, array_size, width_field, height_field, \
			       width, height)				\
	({								\
		BUILD_BUG_ON(sizeof((array)->width_field) != sizeof(u32) || \
			     sizeof((array)->height_field) != sizeof(u32)); \
		(typeof(&(array)[0]))__v4l2_find_nearest_size(		\
			(array), array_size, sizeof(*(array)),		\
			offsetof(typeof(*(array)), width_field),	\
			offsetof(typeof(*(array)), height_field),	\
			width, height);					\
	})
#define v4l2_info(dev, fmt, arg...) \
	v4l2_printk(KERN_INFO, dev, fmt , ## arg)
#define v4l2_printk(level, dev, fmt, arg...) \
	printk(level "%s: " fmt, (dev)->name , ## arg)
#define v4l2_warn(dev, fmt, arg...) \
	v4l2_printk(KERN_WARNING, dev, fmt , ## arg)
#define v4l_client_printk(level, client, fmt, arg...)			    \
	v4l_printk(level, (client)->dev.driver->name, (client)->adapter, \
		   (client)->addr, fmt , ## arg)
#define v4l_dbg(level, debug, client, fmt, arg...)			     \
	do {								     \
		if (debug >= (level))					     \
			v4l_client_printk(KERN_DEBUG, client, fmt , ## arg); \
	} while (0)
#define v4l_err(client, fmt, arg...) \
	v4l_client_printk(KERN_ERR, client, fmt , ## arg)
#define v4l_info(client, fmt, arg...) \
	v4l_client_printk(KERN_INFO, client, fmt , ## arg)
#define v4l_printk(level, name, adapter, addr, fmt, arg...) \
	printk(level "%s %d-%04x: " fmt, name, i2c_adapter_id(adapter), addr , ## arg)
#define v4l_warn(client, fmt, arg...) \
	v4l_client_printk(KERN_WARNING, client, fmt , ## arg)
#define SPI_BPW_MASK(bits) BIT((bits) - 1)
#define SPI_BPW_RANGE_MASK(min, max) GENMASK((max) - 1, (min) - 1)
#define SPI_STATISTICS_ADD_TO_FIELD(stats, field, count)	\
	do {							\
		unsigned long flags;				\
		spin_lock_irqsave(&(stats)->lock, flags);	\
		(stats)->field += count;			\
		spin_unlock_irqrestore(&(stats)->lock, flags);	\
	} while (0)
#define SPI_STATISTICS_HISTO_SIZE 17
#define SPI_STATISTICS_INCREMENT_FIELD(stats, field)	\
	SPI_STATISTICS_ADD_TO_FIELD(stats, field, 1)

#define devm_spi_register_master(_dev, _ctlr) \
	devm_spi_register_controller(_dev, _ctlr)
#define module_spi_driver(__spi_driver) \
	module_driver(__spi_driver, spi_register_driver, \
			spi_unregister_driver)
#define spi_master_get(_ctlr)		spi_controller_get(_ctlr)
#define spi_master_get_devdata(_ctlr)	spi_controller_get_devdata(_ctlr)
#define spi_master_put(_ctlr)		spi_controller_put(_ctlr)
#define spi_master_resume(_ctlr)	spi_controller_resume(_ctlr)
#define spi_master_set_devdata(_ctlr, _data)	\
	spi_controller_set_devdata(_ctlr, _data)
#define spi_master_suspend(_ctlr)	spi_controller_suspend(_ctlr)
#define spi_register_driver(driver) \
	__spi_register_driver(THIS_MODULE, driver)
#define spi_register_master(_ctlr)	spi_register_controller(_ctlr)
#define spi_unregister_master(_ctlr)	spi_unregister_controller(_ctlr)



#define DEFINE_KTHREAD_DELAYED_WORK(dwork, fn)				\
	struct kthread_delayed_work dwork =				\
		KTHREAD_DELAYED_WORK_INIT(dwork, fn)
#define DEFINE_KTHREAD_WORK(work, fn)					\
	struct kthread_work work = KTHREAD_WORK_INIT(work, fn)
#define DEFINE_KTHREAD_WORKER(worker)					\
	struct kthread_worker worker = KTHREAD_WORKER_INIT(worker)
# define DEFINE_KTHREAD_WORKER_ONSTACK(worker)				\
	struct kthread_worker worker = KTHREAD_WORKER_INIT_ONSTACK(worker)
#define KTHREAD_DELAYED_WORK_INIT(dwork, fn) {				\
	.work = KTHREAD_WORK_INIT((dwork).work, (fn)),			\
	.timer = __TIMER_INITIALIZER(kthread_delayed_work_timer_fn,\
				     TIMER_IRQSAFE),			\
	}
#define KTHREAD_WORKER_INIT(worker)	{				\
	.lock = __RAW_SPIN_LOCK_UNLOCKED((worker).lock),		\
	.work_list = LIST_HEAD_INIT((worker).work_list),		\
	.delayed_work_list = LIST_HEAD_INIT((worker).delayed_work_list),\
	}
# define KTHREAD_WORKER_INIT_ONSTACK(worker)				\
	({ kthread_init_worker(&worker); worker; })
#define KTHREAD_WORK_INIT(work, fn)	{				\
	.node = LIST_HEAD_INIT((work).node),				\
	.func = (fn),							\
	}

#define kthread_create(threadfn, data, namefmt, arg...) \
	kthread_create_on_node(threadfn, data, NUMA_NO_NODE, namefmt, ##arg)
#define kthread_init_delayed_work(dwork, fn)				\
	do {								\
		kthread_init_work(&(dwork)->work, (fn));		\
		timer_setup(&(dwork)->timer,				\
			     kthread_delayed_work_timer_fn, 0);		\
	} while (0)
#define kthread_init_work(work, fn)					\
	do {								\
		memset((work), 0, sizeof(struct kthread_work));		\
		INIT_LIST_HEAD(&(work)->node);				\
		(work)->func = (fn);					\
	} while (0)
#define kthread_init_worker(worker)					\
	do {								\
		static struct lock_class_key __key;			\
		__kthread_init_worker((worker), "("#worker")->lock", &__key); \
	} while (0)
#define kthread_run(threadfn, data, namefmt, ...)			   \
({									   \
	struct task_struct *__k						   \
		= kthread_create(threadfn, data, namefmt, ## __VA_ARGS__); \
	if (!IS_ERR(__k))						   \
		wake_up_process(__k);					   \
	__k;								   \
})
#define APR_MODULE_PREFIX "apr:"
#define BCMA_CORE(_manuf, _id, _rev, _class)  \
	{ .manuf = _manuf, .id = _id, .rev = _rev, .class = _class, }
#define DMI_EXACT_MATCH(a, b)	{ .slot = a, .substr = b, .exact_match = 1 }
#define DMI_MATCH(a, b)	{ .slot = a, .substr = b }
#define EISA_DEVICE_MODALIAS_FMT "eisa:s%s"
#define EISA_SIG_LEN   8
#define I2C_MODULE_PREFIX "i2c:"
#define IPACK_ANY_FORMAT 0xff
#define IPACK_ANY_ID (~0)

#define MDIO_ID_ARGS(_id) \
	((_id)>>31) & 1, ((_id)>>30) & 1, ((_id)>>29) & 1, ((_id)>>28) & 1, \
	((_id)>>27) & 1, ((_id)>>26) & 1, ((_id)>>25) & 1, ((_id)>>24) & 1, \
	((_id)>>23) & 1, ((_id)>>22) & 1, ((_id)>>21) & 1, ((_id)>>20) & 1, \
	((_id)>>19) & 1, ((_id)>>18) & 1, ((_id)>>17) & 1, ((_id)>>16) & 1, \
	((_id)>>15) & 1, ((_id)>>14) & 1, ((_id)>>13) & 1, ((_id)>>12) & 1, \
	((_id)>>11) & 1, ((_id)>>10) & 1, ((_id)>>9) & 1, ((_id)>>8) & 1, \
	((_id)>>7) & 1, ((_id)>>6) & 1, ((_id)>>5) & 1, ((_id)>>4) & 1, \
	((_id)>>3) & 1, ((_id)>>2) & 1, ((_id)>>1) & 1, (_id) & 1
#define MDIO_ID_FMT "%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u"
#define MEI_CL_MODULE_PREFIX "mei:"
#define MEI_CL_NAME_SIZE 32
#define MEI_CL_VERSION_ANY 0xff
#define PCI_ANY_ID (~0)
#define SDIO_ANY_ID (~0)
#define SPI_MODULE_PREFIX "spi:"
#define SPMI_MODULE_PREFIX "spmi:"
#define SSB_DEVICE(_vendor, _coreid, _revision)  \
	{ .vendor = _vendor, .coreid = _coreid, .revision = _revision, }
#define X86_FAMILY_ANY 0
#define X86_FEATURE_ANY 0	
#define X86_FEATURE_MATCH(x) \
	{ X86_VENDOR_ANY, X86_FAMILY_ANY, X86_MODEL_ANY, x }
#define X86_MODEL_ANY  0
#define X86_VENDOR_ANY 0xffff
#define dmi_device_id dmi_system_id
#define x86cpu_device_id x86_cpu_id
#define I2C_ADDRS(addr, addrs...) \
	((const unsigned short []){ addr, ## addrs, I2C_CLIENT_END })
#define I2C_AQ_NO_ZERO_LEN		(I2C_AQ_NO_ZERO_LEN_READ | I2C_AQ_NO_ZERO_LEN_WRITE)
#define I2C_BOARD_INFO(dev_type, dev_addr) \
	.type = dev_type, .addr = (dev_addr)
#define I2C_DEVICE_ID_ANALOG_DEVICES                    5
#define I2C_DEVICE_ID_ATMEL                            13
#define I2C_DEVICE_ID_ESPROS_PHOTONICS_AG               9
#define I2C_DEVICE_ID_FLIR                             11
#define I2C_DEVICE_ID_FUJITSU_SEMICONDUCTOR            10
#define I2C_DEVICE_ID_NONE                         0xffff
#define I2C_DEVICE_ID_NXP_SEMICONDUCTORS                0
#define I2C_DEVICE_ID_NXP_SEMICONDUCTORS_1              1
#define I2C_DEVICE_ID_NXP_SEMICONDUCTORS_2              2
#define I2C_DEVICE_ID_NXP_SEMICONDUCTORS_3              3
#define I2C_DEVICE_ID_O2MICRO                          12
#define I2C_DEVICE_ID_ON_SEMICONDUCTOR                  7
#define I2C_DEVICE_ID_RAMTRON_INTERNATIONAL             4
#define I2C_DEVICE_ID_SPRINTEK_CORPORATION              8
#define I2C_DEVICE_ID_STMICROELECTRONICS                6
#define I2C_LOCK_ROOT_ADAPTER BIT(0)
#define I2C_LOCK_SEGMENT      BIT(1)

#define builtin_i2c_driver(__i2c_driver) \
	builtin_driver(__i2c_driver, i2c_add_driver)
#define i2c_add_driver(driver) \
	i2c_register_driver(THIS_MODULE, driver)
#define module_i2c_driver(__i2c_driver) \
	module_driver(__i2c_driver, i2c_add_driver, \
			i2c_del_driver)
#define to_i2c_adapter(d) container_of(d, struct i2c_adapter, dev)
#define to_i2c_client(d) container_of(d, struct i2c_client, dev)
#define to_i2c_driver(d) container_of(d, struct i2c_driver, driver)
#define I2C_FUNC_SMBUS_WRITE_BLOCK_DATA 0x02000000
#define I2C_SMBUS_BLOCK_PROC_CALL   7		
#define I2C_SMBUS_I2C_BLOCK_BROKEN  6
#define I2C_SMBUS_I2C_BLOCK_DATA    8


# define swab __swab
# define swab16 __swab16
# define swab16p __swab16p
# define swab16s __swab16s
# define swab32 __swab32
# define swab32p __swab32p
# define swab32s __swab32s
# define swab64 __swab64
# define swab64p __swab64p
# define swab64s __swab64s
# define swahb32 __swahb32
# define swahb32p __swahb32p
# define swahb32s __swahb32s
# define swahw32 __swahw32
# define swahw32p __swahw32p
# define swahw32s __swahw32s

#define ___constant_swab16(x) ((__u16)(				\
	(((__u16)(x) & (__u16)0x00ffU) << 8) |			\
	(((__u16)(x) & (__u16)0xff00U) >> 8)))
#define ___constant_swab32(x) ((__u32)(				\
	(((__u32)(x) & (__u32)0x000000ffUL) << 24) |		\
	(((__u32)(x) & (__u32)0x0000ff00UL) <<  8) |		\
	(((__u32)(x) & (__u32)0x00ff0000UL) >>  8) |		\
	(((__u32)(x) & (__u32)0xff000000UL) >> 24)))
#define ___constant_swab64(x) ((__u64)(				\
	(((__u64)(x) & (__u64)0x00000000000000ffULL) << 56) |	\
	(((__u64)(x) & (__u64)0x000000000000ff00ULL) << 40) |	\
	(((__u64)(x) & (__u64)0x0000000000ff0000ULL) << 24) |	\
	(((__u64)(x) & (__u64)0x00000000ff000000ULL) <<  8) |	\
	(((__u64)(x) & (__u64)0x000000ff00000000ULL) >>  8) |	\
	(((__u64)(x) & (__u64)0x0000ff0000000000ULL) >> 24) |	\
	(((__u64)(x) & (__u64)0x00ff000000000000ULL) >> 40) |	\
	(((__u64)(x) & (__u64)0xff00000000000000ULL) >> 56)))
#define ___constant_swahb32(x) ((__u32)(			\
	(((__u32)(x) & (__u32)0x00ff00ffUL) << 8) |		\
	(((__u32)(x) & (__u32)0xff00ff00UL) >> 8)))
#define ___constant_swahw32(x) ((__u32)(			\
	(((__u32)(x) & (__u32)0x0000ffffUL) << 16) |		\
	(((__u32)(x) & (__u32)0xffff0000UL) >> 16)))
#define __swab16(x) (__u16)__builtin_bswap16((__u16)(x))
#define __swab32(x) (__u32)__builtin_bswap32((__u32)(x))
#define __swab64(x) (__u64)__builtin_bswap64((__u64)(x))
#define __swahb32(x)				\
	(__builtin_constant_p((__u32)(x)) ?	\
	___constant_swahb32(x) :		\
	__fswahb32(x))
#define __swahw32(x)				\
	(__builtin_constant_p((__u32)(x)) ?	\
	___constant_swahw32(x) :		\
	__fswahw32(x))
#define MAX_PHANDLE_ARGS 16
#define OF_DECLARE_1(table, name, compat, fn) \
		_OF_DECLARE(table, name, compat, fn, of_init_fn_1)
#define OF_DECLARE_1_RET(table, name, compat, fn) \
		_OF_DECLARE(table, name, compat, fn, of_init_fn_1_ret)
#define OF_DECLARE_2(table, name, compat, fn) \
		_OF_DECLARE(table, name, compat, fn, of_init_fn_2)
#define OF_IS_DYNAMIC(x) test_bit(OF_DYNAMIC, &x->_flags)
#define OF_MARK_DYNAMIC(x) set_bit(OF_DYNAMIC, &x->_flags)

#define _OF_DECLARE(table, name, compat, fn, fn_type)			\
	static const struct of_device_id __of_table_##name		\
		__used __section(__##table##_of_table)			\
		 = { .compatible = compat,				\
		     .data = (fn == (fn_type)NULL) ? fn : fn  }
#define for_each_available_child_of_node(parent, child) \
	for (child = of_get_next_available_child(parent, NULL); child != NULL; \
	     child = of_get_next_available_child(parent, child))
#define for_each_child_of_node(parent, child) \
	for (child = of_get_next_child(parent, NULL); child != NULL; \
	     child = of_get_next_child(parent, child))
#define for_each_compatible_node(dn, type, compatible) \
	for (dn = of_find_compatible_node(NULL, type, compatible); dn; \
	     dn = of_find_compatible_node(dn, type, compatible))
#define for_each_matching_node(dn, matches) \
	for (dn = of_find_matching_node(NULL, matches); dn; \
	     dn = of_find_matching_node(dn, matches))
#define for_each_matching_node_and_match(dn, matches, match) \
	for (dn = of_find_matching_node_and_match(NULL, matches, match); \
	     dn; dn = of_find_matching_node_and_match(dn, matches, match))
#define for_each_node_by_name(dn, name) \
	for (dn = of_find_node_by_name(NULL, name); dn; \
	     dn = of_find_node_by_name(dn, name))
#define for_each_node_by_type(dn, type) \
	for (dn = of_find_node_by_type(NULL, type); dn; \
	     dn = of_find_node_by_type(dn, type))
#define for_each_node_with_property(dn, prop_name) \
	for (dn = of_find_node_with_property(NULL, prop_name); dn; \
	     dn = of_find_node_with_property(dn, prop_name))
#define for_each_of_allnodes(dn) for_each_of_allnodes_from(NULL, dn)
#define for_each_of_allnodes_from(from, dn) \
	for (dn = __of_find_all_nodes(from); dn; dn = __of_find_all_nodes(dn))
#define for_each_of_cpu_node(cpu) \
	for (cpu = of_get_next_cpu_node(NULL); cpu != NULL; \
	     cpu = of_get_next_cpu_node(cpu))
#define for_each_property_of_node(dn, pp) \
	for (pp = dn->properties; pp != NULL; pp = pp->next)
#define of_compat_cmp(s1, s2, l)	strcasecmp((s1), (s2))
#define of_for_each_phandle(it, err, np, ln, cn, cc)			\
	for (of_phandle_iterator_init((it), (np), (ln), (cn), (cc)),	\
	     err = of_phandle_iterator_next(it);			\
	     err == 0;							\
	     err = of_phandle_iterator_next(it))
#define of_fwnode_handle(node)						\
	({								\
		typeof(node) __of_fwnode_handle_node = (node);		\
									\
		__of_fwnode_handle_node ?				\
			&__of_fwnode_handle_node->fwnode : NULL;	\
	})
#define of_match_node(_matches, _node)	NULL
#define of_match_ptr(_ptr)	(_ptr)
#define of_node_cmp(s1, s2)		strcasecmp((s1), (s2))
#define of_node_kobj(n) (&(n)->kobj)
#define of_prop_cmp(s1, s2)		strcmp((s1), (s2))
#define of_property_for_each_string(np, propname, prop, s)	\
	for (prop = of_find_property(np, propname, NULL),	\
		s = of_prop_next_string(prop, NULL);		\
		s;						\
		s = of_prop_next_string(prop, s))
#define of_property_for_each_u32(np, propname, prop, p, u)	\
	for (prop = of_find_property(np, propname, NULL),	\
		p = of_prop_next_u32(prop, NULL, &u);		\
		p;						\
		p = of_prop_next_u32(prop, p, &u))
#define to_of_node(__fwnode)						\
	({								\
		typeof(__fwnode) __to_of_node_fwnode = (__fwnode);	\
									\
		is_of_node(__to_of_node_fwnode) ?			\
			container_of(__to_of_node_fwnode,		\
				     struct device_node, fwnode) :	\
			NULL;						\
	})
#define PROPERTY_ENTRY_BOOL(_name_)		\
(struct property_entry) {			\
	.name = _name_,				\
	.is_inline = true,			\
}
#define PROPERTY_ENTRY_REF(_name_, _ref_, ...)				\
(struct property_entry) {						\
	.name = _name_,							\
	.length = sizeof(struct software_node_ref_args),		\
	.type = DEV_PROP_REF,						\
	{ .pointer = &(const struct software_node_ref_args) {		\
		.node = _ref_,						\
		.nargs = ARRAY_SIZE(((u64[]){ 0, ##__VA_ARGS__ })) - 1,	\
		.args = { __VA_ARGS__ },				\
	} },								\
}
#define PROPERTY_ENTRY_REF_ARRAY(_name_, _val_)			\
	PROPERTY_ENTRY_REF_ARRAY_LEN(_name_, _val_, ARRAY_SIZE(_val_))
#define PROPERTY_ENTRY_REF_ARRAY_LEN(_name_, _val_, _len_)		\
	__PROPERTY_ENTRY_ARRAY_ELSIZE_LEN(_name_,			\
				sizeof(struct software_node_ref_args),	\
				REF, _val_, _len_)
#define PROPERTY_ENTRY_STRING(_name_, _val_)				\
	__PROPERTY_ENTRY_ELEMENT(_name_, str, STRING, _val_)
#define PROPERTY_ENTRY_STRING_ARRAY(_name_, _val_)			\
	PROPERTY_ENTRY_STRING_ARRAY_LEN(_name_, _val_, ARRAY_SIZE(_val_))
#define PROPERTY_ENTRY_STRING_ARRAY_LEN(_name_, _val_, _len_)		\
	__PROPERTY_ENTRY_ARRAY_LEN(_name_, str, STRING, _val_, _len_)
#define PROPERTY_ENTRY_U16(_name_, _val_)				\
	__PROPERTY_ENTRY_ELEMENT(_name_, u16_data, U16, _val_)
#define PROPERTY_ENTRY_U16_ARRAY(_name_, _val_)				\
	PROPERTY_ENTRY_U16_ARRAY_LEN(_name_, _val_, ARRAY_SIZE(_val_))
#define PROPERTY_ENTRY_U16_ARRAY_LEN(_name_, _val_, _len_)		\
	__PROPERTY_ENTRY_ARRAY_LEN(_name_, u16_data, U16, _val_, _len_)
#define PROPERTY_ENTRY_U32(_name_, _val_)				\
	__PROPERTY_ENTRY_ELEMENT(_name_, u32_data, U32, _val_)
#define PROPERTY_ENTRY_U32_ARRAY(_name_, _val_)				\
	PROPERTY_ENTRY_U32_ARRAY_LEN(_name_, _val_, ARRAY_SIZE(_val_))
#define PROPERTY_ENTRY_U32_ARRAY_LEN(_name_, _val_, _len_)		\
	__PROPERTY_ENTRY_ARRAY_LEN(_name_, u32_data, U32, _val_, _len_)
#define PROPERTY_ENTRY_U64(_name_, _val_)				\
	__PROPERTY_ENTRY_ELEMENT(_name_, u64_data, U64, _val_)
#define PROPERTY_ENTRY_U64_ARRAY(_name_, _val_)				\
	PROPERTY_ENTRY_U64_ARRAY_LEN(_name_, _val_, ARRAY_SIZE(_val_))
#define PROPERTY_ENTRY_U64_ARRAY_LEN(_name_, _val_, _len_)		\
	__PROPERTY_ENTRY_ARRAY_LEN(_name_, u64_data, U64, _val_, _len_)
#define PROPERTY_ENTRY_U8(_name_, _val_)				\
	__PROPERTY_ENTRY_ELEMENT(_name_, u8_data, U8, _val_)
#define PROPERTY_ENTRY_U8_ARRAY(_name_, _val_)				\
	PROPERTY_ENTRY_U8_ARRAY_LEN(_name_, _val_, ARRAY_SIZE(_val_))
#define PROPERTY_ENTRY_U8_ARRAY_LEN(_name_, _val_, _len_)		\
	__PROPERTY_ENTRY_ARRAY_LEN(_name_, u8_data, U8, _val_, _len_)

#define __PROPERTY_ENTRY_ARRAY_ELSIZE_LEN(_name_, _elsize_, _Type_,	\
					  _val_, _len_)			\
(struct property_entry) {						\
	.name = _name_,							\
	.length = (_len_) * (_elsize_),					\
	.type = DEV_PROP_##_Type_,					\
	{ .pointer = _val_ },						\
}
#define __PROPERTY_ENTRY_ARRAY_LEN(_name_, _elem_, _Type_, _val_, _len_)\
	__PROPERTY_ENTRY_ARRAY_ELSIZE_LEN(_name_,			\
				__PROPERTY_ENTRY_ELEMENT_SIZE(_elem_),	\
				_Type_, _val_, _len_)
#define __PROPERTY_ENTRY_ELEMENT(_name_, _elem_, _Type_, _val_)		\
(struct property_entry) {						\
	.name = _name_,							\
	.length = __PROPERTY_ENTRY_ELEMENT_SIZE(_elem_),		\
	.is_inline = true,						\
	.type = DEV_PROP_##_Type_,					\
	{ .value = { ._elem_[0] = _val_ } },				\
}
#define __PROPERTY_ENTRY_ELEMENT_SIZE(_elem_)				\
	sizeof(((struct property_entry *)NULL)->value._elem_[0])
#define device_for_each_child_node(dev, child)				\
	for (child = device_get_next_child_node(dev, NULL); child;	\
	     child = device_get_next_child_node(dev, child))
#define fwnode_for_each_available_child_node(fwnode, child)		       \
	for (child = fwnode_get_next_available_child_node(fwnode, NULL); child;\
	     child = fwnode_get_next_available_child_node(fwnode, child))
#define fwnode_for_each_child_node(fwnode, child)			\
	for (child = fwnode_get_next_child_node(fwnode, NULL); child;	\
	     child = fwnode_get_next_child_node(fwnode, child))
#define fwnode_graph_for_each_endpoint(fwnode, child)			\
	for (child = NULL;						\
	     (child = fwnode_graph_get_next_endpoint(fwnode, child)); )
#define IRQ_DOMAIN_IRQ_SPEC_PARAMS 16


#define DEFINE_RT_MUTEX(mutexname) \
	struct rt_mutex mutexname = __RT_MUTEX_INITIALIZER(mutexname)
# define __DEBUG_RT_MUTEX_INITIALIZER(mutexname) \
	, .name = #mutexname, .file = "__FILE__", .line = "__LINE__"
#define __DEP_MAP_RT_MUTEX_INITIALIZER(mutexname) \
	, .dep_map = { .name = #mutexname }

#define __RT_MUTEX_INITIALIZER(mutexname) \
	{ .wait_lock = __RAW_SPIN_LOCK_UNLOCKED(mutexname.wait_lock) \
	, .waiters = RB_ROOT_CACHED \
	, .owner = NULL \
	__DEBUG_RT_MUTEX_INITIALIZER(mutexname) \
	__DEP_MAP_RT_MUTEX_INITIALIZER(mutexname)}
# define rt_mutex_debug_check_no_locks_held(task)	do { } while (0)
# define rt_mutex_debug_task_free(t)			do { } while (0)
# define rt_mutex_init(mutex) \
do { \
	static struct lock_class_key __key; \
	__rt_mutex_init(mutex, __func__, &__key); \
} while (0)
#define rt_mutex_lock(lock) rt_mutex_lock_nested(lock, 0)
#define rt_mutex_lock_nested(lock, subclass) rt_mutex_lock(lock)
#define ACPI_COMPANION(dev)		to_acpi_device_node((dev)->fwnode)
#define ACPI_COMPANION_SET(dev, adev)	set_primary_fwnode(dev, (adev) ? \
	acpi_fwnode_handle(adev) : NULL)
#define ACPI_DECLARE_PROBE_ENTRY(table, name, table_id, subtable, valid, data, fn)	\
	static const struct acpi_probe_entry __acpi_probe_##name	\
		__used __section(__##table##_acpi_probe_table)		\
		 = {							\
			.id = table_id,					\
			.type = subtable,				\
			.subtable_valid = valid,			\
			.probe_table = (acpi_tbl_table_handler)fn,	\
			.driver_data = data, 				\
		   }
#define ACPI_DEVICE_CLASS(_cls, _msk)	.cls = (0), .cls_msk = (0),
#define ACPI_GSB_ACCESS_ATTRIB_SEND_RCV         0x00000004
#define ACPI_HANDLE(dev)		acpi_device_handle(ACPI_COMPANION(dev))
#define ACPI_HANDLE_FWNODE(fwnode)	\
				acpi_device_handle(to_acpi_device_node(fwnode))

#define ACPI_PROBE_TABLE(name)		__##name##_acpi_probe_table
#define ACPI_PROBE_TABLE_END(name)	__##name##_acpi_probe_table_end
#define ACPI_PTR(_ptr)	(_ptr)
#define BAD_MADT_ENTRY(entry, end) (					    \
		(!entry) || (unsigned long)entry + sizeof(*entry) > end ||  \
		((struct acpi_subtable_header *)entry)->length < sizeof(*entry))
#define PHYS_CPUID_INVALID (phys_cpuid_t)(-1)


#define acpi_disabled 1
#define acpi_handle_alert(handle, fmt, ...)				\
	acpi_handle_printk(KERN_ALERT, handle, fmt, ##__VA_ARGS__)
#define acpi_handle_crit(handle, fmt, ...)				\
	acpi_handle_printk(KERN_CRIT, handle, fmt, ##__VA_ARGS__)
#define acpi_handle_debug(handle, fmt, ...)				\
	acpi_handle_printk(KERN_DEBUG, handle, fmt, ##__VA_ARGS__)
#define acpi_handle_emerg(handle, fmt, ...)				\
	acpi_handle_printk(KERN_EMERG, handle, fmt, ##__VA_ARGS__)
#define acpi_handle_err(handle, fmt, ...)				\
	acpi_handle_printk(KERN_ERR, handle, fmt, ##__VA_ARGS__)
#define acpi_handle_info(handle, fmt, ...)				\
	acpi_handle_printk(KERN_INFO, handle, fmt, ##__VA_ARGS__)
#define acpi_handle_notice(handle, fmt, ...)				\
	acpi_handle_printk(KERN_NOTICE, handle, fmt, ##__VA_ARGS__)
#define acpi_handle_warn(handle, fmt, ...)				\
	acpi_handle_printk(KERN_WARNING, handle, fmt, ##__VA_ARGS__)
#define acpi_os_set_prepare_sleep(func, pm1a_ctrl, pm1b_ctrl) do { } while (0)
#define acpi_probe_device_table(t)					\
	({ 								\
		extern struct acpi_probe_entry ACPI_PROBE_TABLE(t),	\
			                       ACPI_PROBE_TABLE_END(t);	\
		__acpi_probe_device_table(&ACPI_PROBE_TABLE(t),		\
					  (&ACPI_PROBE_TABLE_END(t) -	\
					   &ACPI_PROBE_TABLE(t)));	\
	})

#define IOMEM_ERR_PTR(err) (__force void __iomem *)ERR_PTR(err)

#define arch_has_dev_port()     (1)
#define arch_phys_wc_add arch_phys_wc_add
#define arch_phys_wc_index arch_phys_wc_index
#define pci_remap_cfgspace pci_remap_cfgspace
#define MAX_PXM_DOMAINS MAX_NUMNODES



#define acpi_device_adr(d)	((d)->pnp.bus_address)
#define acpi_device_bid(d)	((d)->pnp.bus_id)
#define acpi_device_class(d)	((d)->pnp.device_class)
#define acpi_device_dir(d)	((d)->dir.entry)
#define acpi_device_name(d)	((d)->pnp.device_name)
#define acpi_device_uid(d)	((d)->pnp.unique_id)
#define module_acpi_driver(__acpi_driver) \
	module_driver(__acpi_driver, acpi_bus_register_driver, \
		      acpi_bus_unregister_driver)
#define to_acpi_data_node(__fwnode)					\
	({								\
		typeof(__fwnode) __to_acpi_data_node_fwnode = __fwnode;	\
									\
		is_acpi_data_node(__to_acpi_data_node_fwnode) ?		\
			container_of(__to_acpi_data_node_fwnode,	\
				     struct acpi_data_node, fwnode) :	\
			NULL;						\
	})
#define to_acpi_device(d)	container_of(d, struct acpi_device, dev)
#define to_acpi_device_node(__fwnode)					\
	({								\
		typeof(__fwnode) __to_acpi_device_node_fwnode = __fwnode; \
									\
		is_acpi_device_node(__to_acpi_device_node_fwnode) ?	\
			container_of(__to_acpi_device_node_fwnode,	\
				     struct acpi_device, fwnode) :	\
			NULL;						\
	})
#define to_acpi_driver(d)	container_of(d, struct acpi_driver, drv)

#define proc_create(name, mode, parent, proc_ops) ({NULL;})
#define proc_create_data(name, mode, parent, proc_ops, data) ({NULL;})
#define proc_create_net(name, mode, parent, state_size, ops) ({NULL;})
#define proc_create_net_data(name, mode, parent, ops, state_size, data) ({NULL;})
#define proc_create_net_single(name, mode, parent, show, data) ({NULL;})
#define proc_create_seq(name, mode, parent, ops) ({NULL;})
#define proc_create_seq_data(name, mode, parent, ops, data) ({NULL;})
#define proc_create_seq_private(name, mode, parent, ops, size, data) ({NULL;})
#define proc_create_single(name, mode, parent, show) ({NULL;})
#define proc_create_single_data(name, mode, parent, show, data) ({NULL;})
#define remove_proc_entry(name, parent) do {} while (0)
#define MODULE_ALIAS(_alias) MODULE_INFO(alias, _alias)
#define MODULE_ARCH_INIT {}
#define MODULE_AUTHOR(_author) MODULE_INFO(author, _author)
#define MODULE_DESCRIPTION(_description) MODULE_INFO(description, _description)
#define MODULE_DEVICE_TABLE(type, name)					\
extern typeof(name) __mod_##type##__##name##_device_table		\
  __attribute__ ((unused, alias(__stringify(name))))

#define MODULE_FIRMWARE(_firmware) MODULE_INFO(firmware, _firmware)
#define MODULE_IMPORT_NS(ns) MODULE_INFO(import_ns, #ns)
#define MODULE_INFO(tag, info) __MODULE_INFO(tag, tag, info)
#define MODULE_LICENSE(_license) MODULE_FILE MODULE_INFO(license, _license)
#define MODULE_NAME_LEN MAX_PARAM_PREFIX_LEN
#define MODULE_SOFTDEP(_softdep) MODULE_INFO(softdep, _softdep)

#define MODULE_VERSION(_version) MODULE_INFO(version, _version)

#define __INITDATA_OR_MODULE __INITDATA
#define __INITRODATA_OR_MODULE __INITRODATA
#define __INIT_OR_MODULE __INIT
#define __MODULE_STRING(x) __stringify(x)
#define __init_or_module __init
#define __initconst_or_module __initconst
#define __initdata_or_module __initdata
#define __module_layout_align ____cacheline_aligned
#define arch_initcall(fn)		module_init(fn)
#define console_initcall(fn)		module_init(fn)
#define core_initcall(fn)		module_init(fn)
#define core_initcall_sync(fn)		module_init(fn)
#define device_initcall(fn)		module_init(fn)
#define device_initcall_sync(fn)	module_init(fn)
#define early_initcall(fn)		module_init(fn)
#define fs_initcall(fn)			module_init(fn)
#define fs_initcall_sync(fn)		module_init(fn)
#define late_initcall(fn)		module_init(fn)
#define late_initcall_sync(fn)		module_init(fn)
#define module_exit(x)	__exitcall(x);
#define module_init(initfn)					\
	static inline initcall_t __maybe_unused __inittest(void)		\
	{ return initfn; }					\
	int init_module(void) __copy(initfn) __attribute__((alias(#initfn)));
#define module_name(mod)			\
({						\
	struct module *__mod = (mod);		\
	__mod ? __mod->name : "kernel";		\
})
#define module_put_and_exit(code) do_exit(code)
#define postcore_initcall(fn)		module_init(fn)
#define postcore_initcall_sync(fn)	module_init(fn)
#define rootfs_initcall(fn)		module_init(fn)
#define subsys_initcall(fn)		module_init(fn)
#define subsys_initcall_sync(fn)	module_init(fn)
#define symbol_get(x) ({ extern typeof(x) x __attribute__((weak)); &(x); })
#define symbol_put(x) do { } while (0)
#define symbol_put_addr(p) do { } while (0)
#define symbol_request(x) try_then_request_module(symbol_get(x), "symbol:" #x)

#define ALLOW_ERROR_INJECTION(fname, _etype)				\
static struct error_injection_entry __used				\
	__attribute__((__section__("_error_injection_whitelist")))	\
	_eil_addr_##fname = {						\
		.addr = (unsigned long)fname,				\
		.etype = EI_ETYPE_##_etype,				\
	};


#define MAX_PARAM_PREFIX_LEN (64 - sizeof(unsigned long))
#define MODULE_PARAM_PREFIX 
#define MODULE_PARM_DESC(_parm, desc) \
	__MODULE_INFO(parm, _parm, #_parm ":" desc)

#define __MODULE_INFO(tag, name, info)					  \
static const char __UNIQUE_ID(name)[]					  \
  __used __attribute__((section(".modinfo"), unused, aligned(1)))	  \
  = __MODULE_INFO_PREFIX __stringify(tag) "=" info
#define __MODULE_INFO_PREFIX 
#define __MODULE_PARM_TYPE(name, _type)					  \
  __MODULE_INFO(parmtype, name##type, #name ":" _type)
#define __level_param_cb(name, ops, arg, perm, level)			\
	__module_param_call(MODULE_PARAM_PREFIX, name, ops, arg, perm, level, 0)
#define __module_param_call(prefix, name, ops, arg, perm, level, flags)	\
				\
	static const char __param_str_##name[] = prefix #name;		\
	static struct kernel_param __moduleparam_const __param_##name	\
	__used								\
    __attribute__ ((unused,__section__ ("__param"),aligned(sizeof(void *)))) \
	= { __param_str_##name, THIS_MODULE, ops,			\
	    VERIFY_OCTAL_PERMISSIONS(perm), level, flags, { arg } }
#define __moduleparam_const const
#define __param_check(name, p, type) \
	static inline type __always_unused *__check_##name(void) { return(p); }
#define arch_param_cb(name, ops, arg, perm)		\
	__level_param_cb(name, ops, arg, perm, 3)
#define core_param(name, var, type, perm)				\
	param_check_##type(name, &(var));				\
	__module_param_call("", name, &param_ops_##type, &var, perm, -1, 0)
#define core_param_cb(name, ops, arg, perm)		\
	__level_param_cb(name, ops, arg, perm, 1)
#define core_param_unsafe(name, var, type, perm)		\
	param_check_##type(name, &(var));				\
	__module_param_call("", name, &param_ops_##type, &var, perm,	\
			    -1, KERNEL_PARAM_FL_UNSAFE)
#define device_param_cb(name, ops, arg, perm)		\
	__level_param_cb(name, ops, arg, perm, 6)
#define fs_param_cb(name, ops, arg, perm)		\
	__level_param_cb(name, ops, arg, perm, 5)
#define late_param_cb(name, ops, arg, perm)		\
	__level_param_cb(name, ops, arg, perm, 7)
#define module_param(name, type, perm)				\
	module_param_named(name, name, type, perm)
#define module_param_array(name, type, nump, perm)		\
	module_param_array_named(name, name, type, nump, perm)
#define module_param_array_named(name, array, type, nump, perm)		\
	param_check_##type(name, &(array)[0]);				\
	static const struct kparam_array __param_arr_##name		\
	= { .max = ARRAY_SIZE(array), .num = nump,                      \
	    .ops = &param_ops_##type,					\
	    .elemsize = sizeof(array[0]), .elem = array };		\
	__module_param_call(MODULE_PARAM_PREFIX, name,			\
			    &param_array_ops,				\
			    .arr = &__param_arr_##name,			\
			    perm, -1, 0);				\
	__MODULE_PARM_TYPE(name, "array of " #type)
#define module_param_call(name, _set, _get, arg, perm)			\
	static const struct kernel_param_ops __param_ops_##name =	\
		{ .flags = 0, .set = _set, .get = _get };		\
	__module_param_call(MODULE_PARAM_PREFIX,			\
			    name, &__param_ops_##name, arg, perm, -1, 0)
#define module_param_cb(name, ops, arg, perm)				      \
	__module_param_call(MODULE_PARAM_PREFIX, name, ops, arg, perm, -1, 0)
#define module_param_cb_unsafe(name, ops, arg, perm)			      \
	__module_param_call(MODULE_PARAM_PREFIX, name, ops, arg, perm, -1,    \
			    KERNEL_PARAM_FL_UNSAFE)
#define module_param_hw(name, type, hwtype, perm)		\
	module_param_hw_named(name, name, type, hwtype, perm)
#define module_param_hw_array(name, type, hwtype, nump, perm)		\
	param_check_##type(name, &(name)[0]);				\
	static const struct kparam_array __param_arr_##name		\
	= { .max = ARRAY_SIZE(name), .num = nump,			\
	    .ops = &param_ops_##type,					\
	    .elemsize = sizeof(name[0]), .elem = name };		\
	__module_param_call(MODULE_PARAM_PREFIX, name,			\
			    &param_array_ops,				\
			    .arr = &__param_arr_##name,			\
			    perm, -1,					\
			    KERNEL_PARAM_FL_HWPARAM | (hwparam_##hwtype & 0));	\
	__MODULE_PARM_TYPE(name, "array of " #type)
#define module_param_hw_named(name, value, type, hwtype, perm)		\
	param_check_##type(name, &(value));				\
	__module_param_call(MODULE_PARAM_PREFIX, name,			\
			    &param_ops_##type, &value,			\
			    perm, -1,					\
			    KERNEL_PARAM_FL_HWPARAM | (hwparam_##hwtype & 0));	\
	__MODULE_PARM_TYPE(name, #type)
#define module_param_named(name, value, type, perm)			   \
	param_check_##type(name, &(value));				   \
	module_param_cb(name, &param_ops_##type, &value, perm);		   \
	__MODULE_PARM_TYPE(name, #type)
#define module_param_named_unsafe(name, value, type, perm)		\
	param_check_##type(name, &(value));				\
	module_param_cb_unsafe(name, &param_ops_##type, &value, perm);	\
	__MODULE_PARM_TYPE(name, #type)
#define module_param_string(name, string, len, perm)			\
	static const struct kparam_string __param_string_##name		\
		= { len, string };					\
	__module_param_call(MODULE_PARAM_PREFIX, name,			\
			    &param_ops_string,				\
			    .str = &__param_string_##name, perm, -1, 0);\
	__MODULE_PARM_TYPE(name, "string")
#define module_param_unsafe(name, type, perm)			\
	module_param_named_unsafe(name, name, type, perm)
#define param_check_bint param_check_int
#define param_check_bool(name, p) __param_check(name, p, bool)
#define param_check_bool_enable_only param_check_bool
#define param_check_byte(name, p) __param_check(name, p, unsigned char)
#define param_check_charp(name, p) __param_check(name, p, char *)
#define param_check_int(name, p) __param_check(name, p, int)
#define param_check_invbool(name, p) __param_check(name, p, bool)
#define param_check_long(name, p) __param_check(name, p, long)
#define param_check_short(name, p) __param_check(name, p, short)
#define param_check_uint(name, p) __param_check(name, p, unsigned int)
#define param_check_ullong(name, p) __param_check(name, p, unsigned long long)
#define param_check_ulong(name, p) __param_check(name, p, unsigned long)
#define param_check_ushort(name, p) __param_check(name, p, unsigned short)
#define param_get_bint param_get_int
#define postcore_param_cb(name, ops, arg, perm)		\
	__level_param_cb(name, ops, arg, perm, 2)
#define subsys_param_cb(name, ops, arg, perm)		\
	__level_param_cb(name, ops, arg, perm, 4)
#define SET_PERSONALITY(ex) \
	set_personality(PER_LINUX | (current->personality & (~PER_MASK)))
#define SET_PERSONALITY2(ex, state) \
	SET_PERSONALITY(ex)

# define elf_read_implies_exec(ex, have_pt_gnu_stack)	0
#define DT_RPATH 	15
#define ELF32_R_SYM(x) ((x) >> 8)
#define ELF32_R_TYPE(x) ((x) & 0xff)
#define ELF32_ST_BIND(x)	ELF_ST_BIND(x)
#define ELF32_ST_TYPE(x)	ELF_ST_TYPE(x)
#define ELF64_R_SYM(i)			((i) >> 32)
#define ELF64_R_TYPE(i)			((i) & 0xffffffff)
#define ELF64_ST_BIND(x)	ELF_ST_BIND(x)
#define ELF64_ST_TYPE(x)	ELF_ST_TYPE(x)
#define ELF_OSABI ELFOSABI_NONE
#define ELF_ST_BIND(x)		((x) >> 4)
#define ELF_ST_TYPE(x)		(((unsigned int) x) & 0xf)
#define ET_CORE   4
#define ET_DYN    3
#define ET_EXEC   2
#define ET_HIPROC 0xffff
#define ET_LOPROC 0xff00
#define ET_NONE   0
#define ET_REL    1
#define NT_FILE         0x46494c45
#define NT_PRXFPREG     0x46e62b7f      
#define NT_SIGINFO      0x53494749
#define OLD_DT_HIOS     0x6fffffff
#define PN_XNUM 0xffff
#define PT_DYNAMIC 2
#define PT_HIOS    0x6fffffff      
#define PT_HIPROC  0x7fffffff
#define PT_INTERP  3
#define PT_LOAD    1
#define PT_LOOS    0x60000000      
#define PT_LOPROC  0x70000000
#define PT_NOTE    4
#define PT_NULL    0
#define PT_PHDR    6
#define PT_SHLIB   5
#define PT_TLS     7               
#define STB_GLOBAL 1
#define STB_LOCAL  0
#define STB_WEAK   2
#define STT_COMMON  5
#define STT_FILE    4
#define STT_FUNC    2
#define STT_NOTYPE  0
#define STT_OBJECT  1
#define STT_SECTION 3
#define STT_TLS     6

#define KMOD_PATH_LEN 256

#define request_module(mod...) __request_module(true, mod)
#define request_module_nowait(mod...) __request_module(false, mod)
#define try_then_request_module(x, mod...) \
	((x) ?: (__request_module(true, mod), (x)))


#define ACPI_APP_DEPENDENT_RETURN_VOID(prototype) \
	prototype;
#define ACPI_CA_VERSION                 0x20200110
#define ACPI_DBG_DEPENDENT_RETURN_VOID(prototype) \
	prototype;
#define ACPI_DBR_DEPENDENT_RETURN_OK(prototype) \
	ACPI_EXTERNAL_RETURN_OK(prototype)
#define ACPI_DBR_DEPENDENT_RETURN_VOID(prototype) \
	ACPI_EXTERNAL_RETURN_VOID(prototype)
#define ACPI_EXTERNAL_RETURN_OK(prototype) \
	prototype;
#define ACPI_EXTERNAL_RETURN_PTR(prototype) \
	prototype;
#define ACPI_EXTERNAL_RETURN_STATUS(prototype) \
	prototype;
#define ACPI_EXTERNAL_RETURN_UINT32(prototype) \
	prototype;
#define ACPI_EXTERNAL_RETURN_VOID(prototype) \
	prototype;
#define ACPI_GLOBAL(type,name) \
	extern type name; \
	type name
#define ACPI_HW_DEPENDENT_RETURN_OK(prototype) \
	ACPI_EXTERNAL_RETURN_OK(prototype)
#define ACPI_HW_DEPENDENT_RETURN_STATUS(prototype) \
	ACPI_EXTERNAL_RETURN_STATUS(prototype)
#define ACPI_HW_DEPENDENT_RETURN_UINT32(prototype) \
	ACPI_EXTERNAL_RETURN_UINT32(prototype)
#define ACPI_HW_DEPENDENT_RETURN_VOID(prototype) \
	ACPI_EXTERNAL_RETURN_VOID(prototype)
#define ACPI_INIT_GLOBAL(type,name,value) \
	type name=value
#define ACPI_MSG_DEPENDENT_RETURN_VOID(prototype) \
	prototype;

#define ACPI_PLD_BUFFER_SIZE                    20	
#define ACPI_PLD_GET_BAY(dword)                 ACPI_GET_BITS (dword, 31, ACPI_1BIT_MASK)
#define ACPI_PLD_GET_BLUE(dword)                ACPI_GET_BITS (dword, 24, ACPI_8BIT_MASK)
#define ACPI_PLD_GET_CABINET(dword)             ACPI_GET_BITS (dword, 2, ACPI_8BIT_MASK)
#define ACPI_PLD_GET_CARD_CAGE(dword)           ACPI_GET_BITS (dword, 10, ACPI_8BIT_MASK)
#define ACPI_PLD_GET_DOCK(dword)                ACPI_GET_BITS (dword, 1, ACPI_1BIT_MASK)
#define ACPI_PLD_GET_EJECTABLE(dword)           ACPI_GET_BITS (dword, 0, ACPI_1BIT_MASK)
#define ACPI_PLD_GET_GREEN(dword)               ACPI_GET_BITS (dword, 16, ACPI_8BIT_MASK)
#define ACPI_PLD_GET_HEIGHT(dword)              ACPI_GET_BITS (dword, 16, ACPI_16BIT_MASK)
#define ACPI_PLD_GET_HORIZONTAL(dword)          ACPI_GET_BITS (dword, 8, ACPI_2BIT_MASK)
#define ACPI_PLD_GET_HORIZ_OFFSET(dword)        ACPI_GET_BITS (dword, 16, ACPI_16BIT_MASK)
#define ACPI_PLD_GET_IGNORE_COLOR(dword)        ACPI_GET_BITS (dword, 7, ACPI_1BIT_MASK)
#define ACPI_PLD_GET_LID(dword)                 ACPI_GET_BITS (dword, 2, ACPI_1BIT_MASK)
#define ACPI_PLD_GET_ORDER(dword)               ACPI_GET_BITS (dword, 23, ACPI_5BIT_MASK)
#define ACPI_PLD_GET_ORIENTATION(dword)         ACPI_GET_BITS (dword, 14, ACPI_1BIT_MASK)
#define ACPI_PLD_GET_OSPM_EJECT(dword)          ACPI_GET_BITS (dword, 1, ACPI_1BIT_MASK)
#define ACPI_PLD_GET_PANEL(dword)               ACPI_GET_BITS (dword, 3, ACPI_3BIT_MASK)
#define ACPI_PLD_GET_POSITION(dword)            ACPI_GET_BITS (dword, 23, ACPI_8BIT_MASK)
#define ACPI_PLD_GET_RED(dword)                 ACPI_GET_BITS (dword, 8, ACPI_8BIT_MASK)
#define ACPI_PLD_GET_REFERENCE(dword)           ACPI_GET_BITS (dword, 18, ACPI_1BIT_MASK)
#define ACPI_PLD_GET_REVISION(dword)            ACPI_GET_BITS (dword, 0, ACPI_7BIT_MASK)
#define ACPI_PLD_GET_ROTATION(dword)            ACPI_GET_BITS (dword, 19, ACPI_4BIT_MASK)
#define ACPI_PLD_GET_SHAPE(dword)               ACPI_GET_BITS (dword, 10, ACPI_4BIT_MASK)
#define ACPI_PLD_GET_TOKEN(dword)               ACPI_GET_BITS (dword, 15, ACPI_8BIT_MASK)
#define ACPI_PLD_GET_USER_VISIBLE(dword)        ACPI_GET_BITS (dword, 0, ACPI_1BIT_MASK)
#define ACPI_PLD_GET_VERTICAL(dword)            ACPI_GET_BITS (dword, 6, ACPI_2BIT_MASK)
#define ACPI_PLD_GET_VERT_OFFSET(dword)         ACPI_GET_BITS (dword, 0, ACPI_16BIT_MASK)
#define ACPI_PLD_GET_WIDTH(dword)               ACPI_GET_BITS (dword, 0, ACPI_16BIT_MASK)
#define ACPI_PLD_REV1_BUFFER_SIZE               16	
#define ACPI_PLD_REV2_BUFFER_SIZE               20	
#define ACPI_PLD_SET_BAY(dword,value)           ACPI_SET_BITS (dword, 31, ACPI_1BIT_MASK, value)	
#define ACPI_PLD_SET_BLUE(dword,value)          ACPI_SET_BITS (dword, 24, ACPI_8BIT_MASK, value)	
#define ACPI_PLD_SET_CABINET(dword,value)       ACPI_SET_BITS (dword, 2, ACPI_8BIT_MASK, value)	
#define ACPI_PLD_SET_CARD_CAGE(dword,value)     ACPI_SET_BITS (dword, 10, ACPI_8BIT_MASK, value)	
#define ACPI_PLD_SET_DOCK(dword,value)          ACPI_SET_BITS (dword, 1, ACPI_1BIT_MASK, value)	
#define ACPI_PLD_SET_EJECTABLE(dword,value)     ACPI_SET_BITS (dword, 0, ACPI_1BIT_MASK, value)	
#define ACPI_PLD_SET_GREEN(dword,value)         ACPI_SET_BITS (dword, 16, ACPI_8BIT_MASK, value)	
#define ACPI_PLD_SET_HEIGHT(dword,value)        ACPI_SET_BITS (dword, 16, ACPI_16BIT_MASK, value)	
#define ACPI_PLD_SET_HORIZONTAL(dword,value)    ACPI_SET_BITS (dword, 8, ACPI_2BIT_MASK, value)	
#define ACPI_PLD_SET_HORIZ_OFFSET(dword,value)  ACPI_SET_BITS (dword, 16, ACPI_16BIT_MASK, value)	
#define ACPI_PLD_SET_IGNORE_COLOR(dword,value)  ACPI_SET_BITS (dword, 7, ACPI_1BIT_MASK, value)	
#define ACPI_PLD_SET_LID(dword,value)           ACPI_SET_BITS (dword, 2, ACPI_1BIT_MASK, value)	
#define ACPI_PLD_SET_ORDER(dword,value)         ACPI_SET_BITS (dword, 23, ACPI_5BIT_MASK, value)	
#define ACPI_PLD_SET_ORIENTATION(dword,value)   ACPI_SET_BITS (dword, 14, ACPI_1BIT_MASK, value)	
#define ACPI_PLD_SET_OSPM_EJECT(dword,value)    ACPI_SET_BITS (dword, 1, ACPI_1BIT_MASK, value)	
#define ACPI_PLD_SET_PANEL(dword,value)         ACPI_SET_BITS (dword, 3, ACPI_3BIT_MASK, value)	
#define ACPI_PLD_SET_POSITION(dword,value)      ACPI_SET_BITS (dword, 23, ACPI_8BIT_MASK, value)	
#define ACPI_PLD_SET_RED(dword,value)           ACPI_SET_BITS (dword, 8, ACPI_8BIT_MASK, value)	
#define ACPI_PLD_SET_REFERENCE(dword,value)     ACPI_SET_BITS (dword, 18, ACPI_1BIT_MASK, value)	
#define ACPI_PLD_SET_REVISION(dword,value)      ACPI_SET_BITS (dword, 0, ACPI_7BIT_MASK, value)	
#define ACPI_PLD_SET_ROTATION(dword,value)      ACPI_SET_BITS (dword, 19, ACPI_4BIT_MASK, value)	
#define ACPI_PLD_SET_SHAPE(dword,value)         ACPI_SET_BITS (dword, 10, ACPI_4BIT_MASK, value)	
#define ACPI_PLD_SET_TOKEN(dword,value)         ACPI_SET_BITS (dword, 15, ACPI_8BIT_MASK, value)	
#define ACPI_PLD_SET_USER_VISIBLE(dword,value)  ACPI_SET_BITS (dword, 0, ACPI_1BIT_MASK, value)	
#define ACPI_PLD_SET_VERTICAL(dword,value)      ACPI_SET_BITS (dword, 6, ACPI_2BIT_MASK, value)	
#define ACPI_PLD_SET_VERT_OFFSET(dword,value)   ACPI_SET_BITS (dword, 0, ACPI_16BIT_MASK, value)	
#define ACPI_PLD_SET_WIDTH(dword,value)         ACPI_SET_BITS (dword, 0, ACPI_16BIT_MASK, value)	

#define ACPI_FACS_64BIT_ENVIRONMENT (1)	
#define ACPI_FACS_64BIT_WAKE        (1<<1)	
#define ACPI_FACS_S4_BIOS_PRESENT   (1)	
#define ACPI_FADT_32BIT_TIMER       (1<<8)	
#define ACPI_FADT_8042              (1<<1)	
#define ACPI_FADT_APIC_CLUSTER      (1<<18)	
#define ACPI_FADT_APIC_PHYSICAL     (1<<19)	
#define ACPI_FADT_C1_SUPPORTED      (1<<2)	
#define ACPI_FADT_C2_MP_SUPPORTED   (1<<3)	
#define ACPI_FADT_CONFORMANCE   "ACPI 6.1 (FADT version 6)"
#define ACPI_FADT_DOCKING_SUPPORTED (1<<9)	
#define ACPI_FADT_FIXED_RTC         (1<<6)	
#define ACPI_FADT_HEADLESS          (1<<12)	
#define ACPI_FADT_HW_REDUCED        (1<<20)	
#define ACPI_FADT_LEGACY_DEVICES    (1)  	
#define ACPI_FADT_LOW_POWER_S0      (1<<21)	
#define ACPI_FADT_NO_ASPM           (1<<4)	
#define ACPI_FADT_NO_CMOS_RTC       (1<<5)	
#define ACPI_FADT_NO_MSI            (1<<3)	
#define ACPI_FADT_NO_VGA            (1<<2)	
#define ACPI_FADT_OFFSET(f)             (u16) ACPI_OFFSET (struct acpi_table_fadt, f)
#define ACPI_FADT_PCI_EXPRESS_WAKE  (1<<14)	
#define ACPI_FADT_PLATFORM_CLOCK    (1<<15)	
#define ACPI_FADT_POWER_BUTTON      (1<<4)	
#define ACPI_FADT_PSCI_COMPLIANT    (1)	
#define ACPI_FADT_PSCI_USE_HVC      (1<<1)	
#define ACPI_FADT_REMOTE_POWER_ON   (1<<17)	
#define ACPI_FADT_RESET_REGISTER    (1<<10)	
#define ACPI_FADT_S4_RTC_VALID      (1<<16)	
#define ACPI_FADT_S4_RTC_WAKE       (1<<7)	
#define ACPI_FADT_SEALED_CASE       (1<<11)	
#define ACPI_FADT_SLEEP_BUTTON      (1<<5)	
#define ACPI_FADT_SLEEP_TYPE        (1<<13)	
#define ACPI_FADT_V1_SIZE       (u32) (ACPI_FADT_OFFSET (flags) + 4)
#define ACPI_FADT_V2_SIZE       (u32) (ACPI_FADT_OFFSET (minor_revision) + 1)
#define ACPI_FADT_V3_SIZE       (u32) (ACPI_FADT_OFFSET (sleep_control))
#define ACPI_FADT_V5_SIZE       (u32) (ACPI_FADT_OFFSET (hypervisor_id))
#define ACPI_FADT_V6_SIZE       (u32) (sizeof (struct acpi_table_fadt))
#define ACPI_FADT_WBINVD            (1)	
#define ACPI_FADT_WBINVD_FLUSH      (1<<1)	
#define ACPI_GLOCK_OWNED            (1<<1)	
#define ACPI_GLOCK_PENDING          (1)	
#define ACPI_MAX_TABLE_VALIDATIONS          ACPI_UINT16_MAX
#define ACPI_OEM_NAME           "OEM"	
#define ACPI_RSDP_NAME          "RSDP"	
#define ACPI_RSDT_ENTRY_SIZE        (sizeof (u32))
#define ACPI_SIG_DSDT           "DSDT"	
#define ACPI_SIG_FACS           "FACS"	
#define ACPI_SIG_FADT           "FACP"	
#define ACPI_SIG_OSDT           "OSDT"	
#define ACPI_SIG_PSDT           "PSDT"	
#define ACPI_SIG_RSDP           "RSD PTR "	
#define ACPI_SIG_RSDT           "RSDT"	
#define ACPI_SIG_SSDT           "SSDT"	
#define ACPI_SIG_XSDT           "XSDT"	
#define ACPI_TABLE_IS_LOADED                (8)
#define ACPI_TABLE_IS_VERIFIED              (4)
#define ACPI_TABLE_ORIGIN_EXTERNAL_VIRTUAL  (0)	
#define ACPI_TABLE_ORIGIN_INTERNAL_PHYSICAL (1)	
#define ACPI_TABLE_ORIGIN_INTERNAL_VIRTUAL  (2)	
#define ACPI_TABLE_ORIGIN_MASK              (3)
#define ACPI_XSDT_ENTRY_SIZE        (sizeof (u64))
#define ACPI_X_SLEEP_ENABLE         0x20
#define ACPI_X_SLEEP_TYPE_MASK      0x1C
#define ACPI_X_SLEEP_TYPE_POSITION  0x02
#define ACPI_X_WAKE_STATUS          0x80
#define FADT2_REVISION_ID               3

#define ACPI_SIG_SLIC           "SLIC"	
#define ACPI_SIG_SLIT           "SLIT"	
#define ACPI_SIG_SPCR           "SPCR"	
#define ACPI_SIG_SPMI           "SPMI"	
#define ACPI_SIG_SRAT           "SRAT"	
#define ACPI_SIG_STAO           "STAO"	
#define ACPI_SIG_TCPA           "TCPA"	
#define ACPI_SIG_TPM2           "TPM2"	
#define ACPI_SIG_UEFI           "UEFI"	
#define ACPI_SIG_VRTC           "VRTC"	
#define ACPI_SIG_WAET           "WAET"	
#define ACPI_SIG_WDAT           "WDAT"	
#define ACPI_SIG_WDDT           "WDDT"	
#define ACPI_SIG_WDRT           "WDRT"	
#define ACPI_SIG_WPBT           "WPBT"	
#define ACPI_SIG_WSMT           "WSMT"	
#define ACPI_SIG_XENV           "XENV"	
#define ACPI_SIG_XXXX           "XXXX"	
#define ACPI_SPCR_DO_NOT_DISABLE    (1)
#define ACPI_SRAT_CPU_ENABLED       (1)	
#define ACPI_SRAT_CPU_USE_AFFINITY  (1)	
#define ACPI_SRAT_GENERIC_AFFINITY_ENABLED (1)	
#define ACPI_SRAT_GICC_ENABLED     (1)	
#define ACPI_SRAT_MEM_ENABLED       (1)	
#define ACPI_SRAT_MEM_HOT_PLUGGABLE (1<<1)	
#define ACPI_SRAT_MEM_NON_VOLATILE  (1<<2)	
#define ACPI_TCPA_ADDRESS_VALID         (1<<2)
#define ACPI_TCPA_BUS_PNP               (1<<1)
#define ACPI_TCPA_CLIENT_TABLE          0
#define ACPI_TCPA_GLOBAL_INTERRUPT      (1<<3)
#define ACPI_TCPA_INTERRUPT_MODE        (1)
#define ACPI_TCPA_INTERRUPT_POLARITY    (1<<1)
#define ACPI_TCPA_PCI_DEVICE            (1)
#define ACPI_TCPA_SCI_VIA_GPE           (1<<2)
#define ACPI_TCPA_SERVER_TABLE          1
#define ACPI_TPM23_ACPI_START_METHOD                 2
#define ACPI_TPM2_COMMAND_BUFFER                    7
#define ACPI_TPM2_COMMAND_BUFFER_WITH_ARM_SMC       11	
#define ACPI_TPM2_COMMAND_BUFFER_WITH_START_METHOD  8
#define ACPI_TPM2_IDLE_SUPPORT          (1)
#define ACPI_TPM2_INTERRUPT_SUPPORT     (1)
#define ACPI_TPM2_MEMORY_MAPPED                     6
#define ACPI_TPM2_NOT_ALLOWED                       0
#define ACPI_TPM2_RESERVED                          12
#define ACPI_TPM2_RESERVED1                         1
#define ACPI_TPM2_RESERVED10                        10
#define ACPI_TPM2_RESERVED3                         3
#define ACPI_TPM2_RESERVED4                         4
#define ACPI_TPM2_RESERVED5                         5
#define ACPI_TPM2_RESERVED9                         9
#define ACPI_TPM2_START_METHOD                      2
#define ACPI_WAET_RTC_NO_ACK        (1)	
#define ACPI_WAET_TIMER_ONE_READ    (1<<1)	
#define ACPI_WDAT_ENABLED           (1)
#define ACPI_WDAT_STOPPED           0x80
#define ACPI_WDDT_ACTIVE        (1<<1)
#define ACPI_WDDT_ALERT_SUPPORT (1<<1)
#define ACPI_WDDT_AUTO_RESET    (1)
#define ACPI_WDDT_AVAILABLE     (1)
#define ACPI_WDDT_POWER_FAIL    (1<<13)
#define ACPI_WDDT_TCO_OS_OWNED  (1<<2)
#define ACPI_WDDT_UNKNOWN_RESET (1<<14)
#define ACPI_WDDT_USER_RESET    (1<<11)
#define ACPI_WDDT_WDT_RESET     (1<<12)
#define ACPI_WSMT_COMM_BUFFER_NESTED_PTR_PROTECTION (2)
#define ACPI_WSMT_FIXED_COMM_BUFFERS                (1)
#define ACPI_WSMT_SYSTEM_RESOURCE_PROTECTION        (4)

#define ACPI_IORT_ATS_SUPPORTED         0x00000001	
#define ACPI_IORT_ATS_UNSUPPORTED       0x00000000	
#define ACPI_IORT_HT_OVERRIDE           (1<<3)
#define ACPI_IORT_HT_READ               (1<<2)
#define ACPI_IORT_HT_TRANSIENT          (1)
#define ACPI_IORT_HT_WRITE              (1<<1)
#define ACPI_IORT_ID_SINGLE_MAPPING (1)
#define ACPI_IORT_MF_ATTRIBUTES         (1<<1)
#define ACPI_IORT_MF_COHERENCY          (1)
#define ACPI_IORT_NC_PASID_BITS         (31<<1)
#define ACPI_IORT_NC_STALL_SUPPORTED    (1)
#define ACPI_IORT_NODE_COHERENT         0x00000001	
#define ACPI_IORT_NODE_NOT_COHERENT     0x00000000	
#define ACPI_IORT_SMMU_CAVIUM_THUNDERX  0x00000005	
#define ACPI_IORT_SMMU_COHERENT_WALK    (1<<1)
#define ACPI_IORT_SMMU_CORELINK_MMU400  0x00000002	
#define ACPI_IORT_SMMU_CORELINK_MMU401  0x00000004	
#define ACPI_IORT_SMMU_CORELINK_MMU500  0x00000003	
#define ACPI_IORT_SMMU_DVM_SUPPORTED    (1)
#define ACPI_IORT_SMMU_V1               0x00000000	
#define ACPI_IORT_SMMU_V2               0x00000001	
#define ACPI_IORT_SMMU_V3_CAVIUM_CN99XX     0x00000002	
#define ACPI_IORT_SMMU_V3_COHACC_OVERRIDE   (1)
#define ACPI_IORT_SMMU_V3_GENERIC           0x00000000	
#define ACPI_IORT_SMMU_V3_HISILICON_HI161X  0x00000001	
#define ACPI_IORT_SMMU_V3_HTTU_OVERRIDE     (3<<1)
#define ACPI_IORT_SMMU_V3_PXM_VALID         (1<<3)
#define ACPI_IVHD_ATS_DISABLED      (1<<31)
#define ACPI_IVHD_EINT_PASS         (1<<1)
#define ACPI_IVHD_ENTRY_LENGTH      0xC0
#define ACPI_IVHD_HPET              2
#define ACPI_IVHD_INIT_PASS         (1)
#define ACPI_IVHD_IOAPIC            1
#define ACPI_IVHD_IOTLB             (1<<4)
#define ACPI_IVHD_ISOC              (1<<3)
#define ACPI_IVHD_LINT0_PASS        (1<<6)
#define ACPI_IVHD_LINT1_PASS        (1<<7)
#define ACPI_IVHD_MSI_NUMBER_MASK   0x001F	
#define ACPI_IVHD_NMI_PASS          (1<<2)
#define ACPI_IVHD_PASS_PW           (1<<1)
#define ACPI_IVHD_RES_PASS_PW       (1<<2)
#define ACPI_IVHD_SYSTEM_MGMT       (3<<4)
#define ACPI_IVHD_TT_ENABLE         (1)
#define ACPI_IVHD_UNIT_ID_MASK      0x1F00	
#define ACPI_IVMD_EXCLUSION_RANGE   (1<<3)
#define ACPI_IVMD_READ              (1<<1)
#define ACPI_IVMD_UNITY             (1)
#define ACPI_IVMD_WRITE             (1<<2)
#define ACPI_IVRS_ATS_RESERVED      0x00400000	
#define ACPI_IVRS_PHYSICAL_SIZE     0x00007F00	
#define ACPI_IVRS_VIRTUAL_SIZE      0x003F8000	
#define ACPI_LPIT_NO_COUNTER        (1<<1)
#define ACPI_LPIT_STATE_DISABLED    (1)
#define ACPI_MADT_CPEI_OVERRIDE     (1)
#define ACPI_MADT_DUAL_PIC          1
#define ACPI_MADT_ENABLED           (1)	
#define ACPI_MADT_MULTIPLE_APIC     0
#define ACPI_MADT_OVERRIDE_SPI_VALUES   (1)
#define ACPI_MADT_PCAT_COMPAT       (1)	
#define ACPI_MADT_PERFORMANCE_IRQ_MODE  (1<<1)	
#define ACPI_MADT_POLARITY_ACTIVE_HIGH    1
#define ACPI_MADT_POLARITY_ACTIVE_LOW     3
#define ACPI_MADT_POLARITY_CONFORMS       0
#define ACPI_MADT_POLARITY_MASK     (3)	
#define ACPI_MADT_POLARITY_RESERVED       2
#define ACPI_MADT_TRIGGER_CONFORMS        (0)
#define ACPI_MADT_TRIGGER_EDGE            (1<<2)
#define ACPI_MADT_TRIGGER_LEVEL           (3<<2)
#define ACPI_MADT_TRIGGER_MASK      (3<<2)	
#define ACPI_MADT_TRIGGER_RESERVED        (2<<2)
#define ACPI_MADT_VGIC_IRQ_MODE         (1<<2)	
#define ACPI_MPST_AUTOENTRY             2
#define ACPI_MPST_AUTOEXIT              4
#define ACPI_MPST_CHANNEL_INFO \
	u8                              channel_id; \
	u8                              reserved1[3]; \
	u16                             power_node_count; \
	u16                             reserved2;
#define ACPI_MPST_ENABLED               1
#define ACPI_MPST_HOT_PLUG_CAPABLE      4
#define ACPI_MPST_POWER_MANAGED         2
#define ACPI_MPST_PRESERVE              1
#define ACPI_NFIT_ADD_ONLINE_ONLY       (1)	
#define ACPI_NFIT_BUILD_DEVICE_HANDLE(dimm, channel, memory, socket, node) \
	((dimm)                                         | \
	((channel) << ACPI_NFIT_CHANNEL_NUMBER_OFFSET)  | \
	((memory)  << ACPI_NFIT_MEMORY_ID_OFFSET)       | \
	((socket)  << ACPI_NFIT_SOCKET_ID_OFFSET)       | \
	((node)    << ACPI_NFIT_NODE_ID_OFFSET))
#define ACPI_NFIT_CAPABILITY_CACHE_FLUSH       (1)	
#define ACPI_NFIT_CAPABILITY_MEM_FLUSH         (1<<1)	
#define ACPI_NFIT_CAPABILITY_MEM_MIRRORING     (1<<2)	
#define ACPI_NFIT_CHANNEL_NUMBER_MASK           0x000000F0
#define ACPI_NFIT_CHANNEL_NUMBER_OFFSET         4
#define ACPI_NFIT_CONTROL_BUFFERED          (1)	
#define ACPI_NFIT_CONTROL_MFG_INFO_VALID    (1)	
#define ACPI_NFIT_DIMM_NUMBER_MASK              0x0000000F
#define ACPI_NFIT_DIMM_NUMBER_OFFSET            0
#define ACPI_NFIT_GET_CHANNEL_NUMBER(handle) \
	(((handle) & ACPI_NFIT_CHANNEL_NUMBER_MASK) >> ACPI_NFIT_CHANNEL_NUMBER_OFFSET)
#define ACPI_NFIT_GET_DIMM_NUMBER(handle) \
	((handle) & ACPI_NFIT_DIMM_NUMBER_MASK)
#define ACPI_NFIT_GET_MEMORY_ID(handle) \
	(((handle) & ACPI_NFIT_MEMORY_ID_MASK)      >> ACPI_NFIT_MEMORY_ID_OFFSET)
#define ACPI_NFIT_GET_NODE_ID(handle) \
	(((handle) & ACPI_NFIT_NODE_ID_MASK)        >> ACPI_NFIT_NODE_ID_OFFSET)
#define ACPI_NFIT_GET_SOCKET_ID(handle) \
	(((handle) & ACPI_NFIT_SOCKET_ID_MASK)      >> ACPI_NFIT_SOCKET_ID_OFFSET)
#define ACPI_NFIT_MEMORY_ID_MASK                0x00000F00
#define ACPI_NFIT_MEMORY_ID_OFFSET              8
#define ACPI_NFIT_MEM_FLUSH_FAILED      (1<<2)	
#define ACPI_NFIT_MEM_HEALTH_ENABLED    (1<<5)	
#define ACPI_NFIT_MEM_HEALTH_OBSERVED   (1<<4)	
#define ACPI_NFIT_MEM_MAP_FAILED        (1<<6)	
#define ACPI_NFIT_MEM_NOT_ARMED         (1<<3)	
#define ACPI_NFIT_MEM_RESTORE_FAILED    (1<<1)	
#define ACPI_NFIT_MEM_SAVE_FAILED       (1)	
#define ACPI_NFIT_NODE_ID_MASK                  0x0FFF0000
#define ACPI_NFIT_NODE_ID_OFFSET                16
#define ACPI_NFIT_PROXIMITY_VALID       (1<<1)	
#define ACPI_NFIT_SOCKET_ID_MASK                0x0000F000
#define ACPI_NFIT_SOCKET_ID_OFFSET              12
#define ACPI_PCCT_DOORBELL              1
#define ACPI_PCCT_INTERRUPT_MODE        (1<<1)
#define ACPI_PCCT_INTERRUPT_POLARITY    (1)
#define ACPI_PDTT_RUNTIME_TRIGGER           (1)
#define ACPI_PDTT_TRIGGER_ORDER             (1<<2)
#define ACPI_PDTT_WAIT_COMPLETION           (1<<1)
#define ACPI_PMTT_MEMORY_TYPE           0x000C
#define ACPI_PMTT_PHYSICAL              0x0002
#define ACPI_PMTT_TOP_LEVEL             0x0001
#define ACPI_PMTT_TYPE_CONTROLLER       1
#define ACPI_PMTT_TYPE_DIMM             2
#define ACPI_PMTT_TYPE_RESERVED         3	
#define ACPI_PMTT_TYPE_SOCKET           0
#define ACPI_PPTT_ACPI_IDENTICAL            (1<<4)	
#define ACPI_PPTT_ACPI_LEAF_NODE            (1<<3)	
#define ACPI_PPTT_ACPI_PROCESSOR_ID_VALID   (1<<1)
#define ACPI_PPTT_ACPI_PROCESSOR_IS_THREAD  (1<<2)	
#define ACPI_PPTT_ALLOCATION_TYPE_VALID     (1<<3)	
#define ACPI_PPTT_ASSOCIATIVITY_VALID       (1<<2)	
#define ACPI_PPTT_CACHE_POLICY_WB           (0x0)	
#define ACPI_PPTT_CACHE_POLICY_WT           (1<<4)	
#define ACPI_PPTT_CACHE_READ_ALLOCATE       (0x0)	
#define ACPI_PPTT_CACHE_RW_ALLOCATE         (0x02)	
#define ACPI_PPTT_CACHE_RW_ALLOCATE_ALT     (0x03)	
#define ACPI_PPTT_CACHE_TYPE_DATA           (0x0)	
#define ACPI_PPTT_CACHE_TYPE_INSTR          (1<<2)	
#define ACPI_PPTT_CACHE_TYPE_UNIFIED        (2<<2)	
#define ACPI_PPTT_CACHE_TYPE_UNIFIED_ALT    (3<<2)	
#define ACPI_PPTT_CACHE_TYPE_VALID          (1<<4)	
#define ACPI_PPTT_CACHE_WRITE_ALLOCATE      (0x01)	
#define ACPI_PPTT_LINE_SIZE_VALID           (1<<6)	
#define ACPI_PPTT_MASK_ALLOCATION_TYPE      (0x03)	
#define ACPI_PPTT_MASK_CACHE_TYPE           (0x0C)	
#define ACPI_PPTT_MASK_WRITE_POLICY         (0x10)	
#define ACPI_PPTT_NUMBER_OF_SETS_VALID      (1<<1)	
#define ACPI_PPTT_PHYSICAL_PACKAGE          (1)
#define ACPI_PPTT_SIZE_PROPERTY_VALID       (1)	
#define ACPI_PPTT_WRITE_POLICY_VALID        (1<<5)	
#define ACPI_RASF_COMMAND_COMPLETE      (1)
#define ACPI_RASF_ERROR                 (1<<2)
#define ACPI_RASF_GENERATE_SCI          (1<<15)
#define ACPI_RASF_SCI_DOORBELL          (1<<1)
#define ACPI_RASF_SCRUBBER_RUNNING      1
#define ACPI_RASF_SPEED                 (7<<1)
#define ACPI_RASF_SPEED_FAST            (7<<1)
#define ACPI_RASF_SPEED_MEDIUM          (4<<1)
#define ACPI_RASF_SPEED_SLOW            (0<<1)
#define ACPI_RASF_STATUS                (0x1F<<3)
#define ACPI_SDEV_HANDOFF_TO_UNSECURE_OS    (1)
#define ACPI_SIG_IORT           "IORT"	
#define ACPI_SIG_IVRS           "IVRS"	
#define ACPI_SIG_LPIT           "LPIT"	
#define ACPI_SIG_MADT           "APIC"	
#define ACPI_SIG_MCFG           "MCFG"	
#define ACPI_SIG_MCHI           "MCHI"	
#define ACPI_SIG_MPST           "MPST"	
#define ACPI_SIG_MSCT           "MSCT"	
#define ACPI_SIG_MSDM           "MSDM"	
#define ACPI_SIG_MTMR           "MTMR"	
#define ACPI_SIG_NFIT           "NFIT"	
#define ACPI_SIG_PCCT           "PCCT"	
#define ACPI_SIG_PDTT           "PDTT"	
#define ACPI_SIG_PMTT           "PMTT"	
#define ACPI_SIG_PPTT           "PPTT"	
#define ACPI_SIG_RASF           "RASF"	
#define ACPI_SIG_SBST           "SBST"	
#define ACPI_SIG_SDEI           "SDEI"	
#define ACPI_SIG_SDEV           "SDEV"	

#define ACPI_ASF_SMBUS_PROTOCOLS    (1)
#define ACPI_BERT_CORRECTABLE               (1<<1)
#define ACPI_BERT_ERROR_ENTRY_COUNT         (0xFF<<4)	
#define ACPI_BERT_MULTIPLE_CORRECTABLE      (1<<3)
#define ACPI_BERT_MULTIPLE_UNCORRECTABLE    (1<<2)
#define ACPI_BERT_UNCORRECTABLE             (1)
#define ACPI_BGRT_DISPLAYED                 (1)
#define ACPI_BGRT_ORIENTATION_OFFSET        (3 << 1)
#define ACPI_CSRT_DMA_CHANNEL       0x0000
#define ACPI_CSRT_DMA_CONTROLLER    0x0001
#define ACPI_CSRT_TIMER             0x0000
#define ACPI_CSRT_TYPE_DMA          0x0003
#define ACPI_CSRT_TYPE_INTERRUPT    0x0001
#define ACPI_CSRT_TYPE_TIMER        0x0002
#define ACPI_CSRT_XRUPT_CONTROLLER  0x0001
#define ACPI_CSRT_XRUPT_LINE        0x0000
#define ACPI_DBG2_1394_PORT         0x8001
#define ACPI_DBG2_1394_STANDARD     0x0000
#define ACPI_DBG2_16550_COMPATIBLE  0x0000
#define ACPI_DBG2_16550_SUBSET      0x0001
#define ACPI_DBG2_ARM_DCC           0x000F
#define ACPI_DBG2_ARM_PL011         0x0003
#define ACPI_DBG2_ARM_SBSA_32BIT    0x000D
#define ACPI_DBG2_ARM_SBSA_GENERIC  0x000E
#define ACPI_DBG2_BCM2835           0x0010
#define ACPI_DBG2_NET_PORT          0x8003
#define ACPI_DBG2_SERIAL_PORT       0x8000
#define ACPI_DBG2_USB_EHCI          0x0001
#define ACPI_DBG2_USB_PORT          0x8002
#define ACPI_DBG2_USB_XHCI          0x0000
#define ACPI_DMAR_ALLOW_ALL         (1)
#define ACPI_DMAR_ALL_PORTS         (1)
#define ACPI_DMAR_INCLUDE_ALL       (1)
#define ACPI_DMAR_INTR_REMAP        (1)
#define ACPI_DMAR_X2APIC_MODE       (1<<2)
#define ACPI_DMAR_X2APIC_OPT_OUT    (1<<1)
#define ACPI_DRTM_ACCESS_ALLOWED            (1)
#define ACPI_DRTM_AUTHORITY_ORDER           (1<<3)
#define ACPI_DRTM_ENABLE_GAP_CODE           (1<<1)
#define ACPI_DRTM_INCOMPLETE_MEASUREMENTS   (1<<2)
#define ACPI_EINJ_MEMORY_CORRECTABLE        (1<<3)
#define ACPI_EINJ_MEMORY_FATAL              (1<<5)
#define ACPI_EINJ_MEMORY_UNCORRECTABLE      (1<<4)
#define ACPI_EINJ_PCIX_CORRECTABLE          (1<<6)
#define ACPI_EINJ_PCIX_FATAL                (1<<8)
#define ACPI_EINJ_PCIX_UNCORRECTABLE        (1<<7)
#define ACPI_EINJ_PLATFORM_CORRECTABLE      (1<<9)
#define ACPI_EINJ_PLATFORM_FATAL            (1<<11)
#define ACPI_EINJ_PLATFORM_UNCORRECTABLE    (1<<10)
#define ACPI_EINJ_PRESERVE          (1)
#define ACPI_EINJ_PROCESSOR_CORRECTABLE     (1)
#define ACPI_EINJ_PROCESSOR_FATAL           (1<<2)
#define ACPI_EINJ_PROCESSOR_UNCORRECTABLE   (1<<1)
#define ACPI_EINJ_VENDOR_DEFINED            (1<<31)
#define ACPI_ERST_PRESERVE          (1)
#define ACPI_GTDT_ALWAYS_ON             (1<<2)
#define ACPI_GTDT_GT_ALWAYS_ON              (1<<1)
#define ACPI_GTDT_GT_IRQ_MODE               (1)
#define ACPI_GTDT_GT_IRQ_POLARITY           (1<<1)
#define ACPI_GTDT_GT_IS_SECURE_TIMER        (1)
#define ACPI_GTDT_INTERRUPT_MODE        (1)
#define ACPI_GTDT_INTERRUPT_POLARITY    (1<<1)
#define ACPI_GTDT_WATCHDOG_IRQ_MODE         (1)
#define ACPI_GTDT_WATCHDOG_IRQ_POLARITY     (1<<1)
#define ACPI_GTDT_WATCHDOG_SECURE           (1<<2)
#define ACPI_HEST_BUS(bus)              ((bus) & 0xFF)
#define ACPI_HEST_CORRECTABLE               (1<<1)
#define ACPI_HEST_ERROR_ENTRY_COUNT         (0xFF<<4)	
#define ACPI_HEST_ERR_THRESHOLD_VALUE   (1<<4)
#define ACPI_HEST_ERR_THRESHOLD_WINDOW  (1<<5)
#define ACPI_HEST_FIRMWARE_FIRST        (1)
#define ACPI_HEST_GEN_ERROR_CORRECTED       2
#define ACPI_HEST_GEN_ERROR_FATAL           1
#define ACPI_HEST_GEN_ERROR_NONE            3
#define ACPI_HEST_GEN_ERROR_RECOVERABLE     0
#define ACPI_HEST_GEN_VALID_FRU_ID          (1)
#define ACPI_HEST_GEN_VALID_FRU_STRING      (1<<1)
#define ACPI_HEST_GEN_VALID_TIMESTAMP       (1<<2)
#define ACPI_HEST_GHES_ASSIST           (1<<2)
#define ACPI_HEST_GLOBAL                (1<<1)
#define ACPI_HEST_MULTIPLE_CORRECTABLE      (1<<3)
#define ACPI_HEST_MULTIPLE_UNCORRECTABLE    (1<<2)
#define ACPI_HEST_POLL_INTERVAL         (1<<1)
#define ACPI_HEST_POLL_THRESHOLD_VALUE  (1<<2)
#define ACPI_HEST_POLL_THRESHOLD_WINDOW (1<<3)
#define ACPI_HEST_SEGMENT(bus)          (((bus) >> 8) & 0xFFFF)
#define ACPI_HEST_TYPE                  (1)
#define ACPI_HEST_UNCORRECTABLE             (1)
#define ACPI_HMAT_1ST_LEVEL_CACHE   2
#define ACPI_HMAT_2ND_LEVEL_CACHE   3
#define ACPI_HMAT_3RD_LEVEL_CACHE   4
#define ACPI_HMAT_ACCESS_BANDWIDTH  3
#define ACPI_HMAT_ACCESS_LATENCY    0
#define ACPI_HMAT_CACHE_ASSOCIATIVITY   (0x00000F00)
#define ACPI_HMAT_CACHE_LEVEL           (0x000000F0)
#define ACPI_HMAT_CACHE_LINE_SIZE       (0xFFFF0000)
#define ACPI_HMAT_CA_COMPLEX_CACHE_INDEXING   (2)
#define ACPI_HMAT_CA_DIRECT_MAPPED            (1)
#define ACPI_HMAT_CA_NONE                     (0)
#define ACPI_HMAT_CP_NONE   (0)
#define ACPI_HMAT_CP_WB     (1)
#define ACPI_HMAT_CP_WT     (2)
#define ACPI_HMAT_LAST_LEVEL_CACHE  1
#define ACPI_HMAT_MEMORY            0
#define ACPI_HMAT_MEMORY_HIERARCHY  (0x0F)
#define ACPI_HMAT_MEMORY_PD_VALID       (1<<1)	
#define ACPI_HMAT_PROCESSOR_PD_VALID    (1)	
#define ACPI_HMAT_READ_BANDWIDTH    4
#define ACPI_HMAT_READ_LATENCY      1
#define ACPI_HMAT_RESERVATION_HINT      (1<<2)	
#define ACPI_HMAT_TOTAL_CACHE_LEVEL     (0x0000000F)
#define ACPI_HMAT_WRITE_BANDWIDTH   5
#define ACPI_HMAT_WRITE_LATENCY     2
#define ACPI_HMAT_WRITE_POLICY          (0x0000F000)
#define ACPI_HPET_PAGE_PROTECT_MASK (3)
#define ACPI_SIG_ASF            "ASF!"	
#define ACPI_SIG_ATKG           "ATKG"
#define ACPI_SIG_BERT           "BERT"	
#define ACPI_SIG_BGRT           "BGRT"	
#define ACPI_SIG_BOOT           "BOOT"	
#define ACPI_SIG_CPEP           "CPEP"	
#define ACPI_SIG_CSRT           "CSRT"	
#define ACPI_SIG_DBG2           "DBG2"	
#define ACPI_SIG_DBGP           "DBGP"	
#define ACPI_SIG_DMAR           "DMAR"	
#define ACPI_SIG_DRTM           "DRTM"	
#define ACPI_SIG_ECDT           "ECDT"	
#define ACPI_SIG_EINJ           "EINJ"	
#define ACPI_SIG_ERST           "ERST"	
#define ACPI_SIG_FPDT           "FPDT"	
#define ACPI_SIG_GSCI           "GSCI"	
#define ACPI_SIG_GTDT           "GTDT"	
#define ACPI_SIG_HEST           "HEST"	
#define ACPI_SIG_HMAT           "HMAT"	
#define ACPI_SIG_HPET           "HPET"	
#define ACPI_SIG_IBFT           "IBFT"	
#define ACPI_SIG_IEIT           "IEIT"
#define ACPI_SIG_MATR           "MATR"	
#define ACPI_SIG_PCCS           "PCC"	
#define ACPI_SIG_S3PT           "S3PT"	

#define ACPI_100NSEC_PER_MSEC           10000L
#define ACPI_100NSEC_PER_SEC            10000000L
#define ACPI_100NSEC_PER_USEC           10L
#define ACPI_ACCESS_BIT_WIDTH(size)     (1 << ((size) + 2))
#define ACPI_ADD_PTR(t, a, b)           ACPI_CAST_PTR (t, (ACPI_CAST_PTR (u8, (a)) + (acpi_size)(b)))
#define ACPI_ADR_SPACE_CMOS             (acpi_adr_space_type) 5
#define ACPI_ADR_SPACE_DATA_TABLE       (acpi_adr_space_type) 0x7E	
#define ACPI_ADR_SPACE_EC               (acpi_adr_space_type) 3
#define ACPI_ADR_SPACE_FIXED_HARDWARE   (acpi_adr_space_type) 0x7F
#define ACPI_ADR_SPACE_GPIO             (acpi_adr_space_type) 8
#define ACPI_ADR_SPACE_GSBUS            (acpi_adr_space_type) 9
#define ACPI_ADR_SPACE_IPMI             (acpi_adr_space_type) 7
#define ACPI_ADR_SPACE_PCI_BAR_TARGET   (acpi_adr_space_type) 6
#define ACPI_ADR_SPACE_PCI_CONFIG       (acpi_adr_space_type) 2
#define ACPI_ADR_SPACE_PLATFORM_COMM    (acpi_adr_space_type) 10
#define ACPI_ADR_SPACE_SMBUS            (acpi_adr_space_type) 4
#define ACPI_ADR_SPACE_SYSTEM_IO        (acpi_adr_space_type) 1
#define ACPI_ADR_SPACE_SYSTEM_MEMORY    (acpi_adr_space_type) 0
#define ACPI_ALLOCATE(a)                NULL
#define ACPI_ALLOCATE_BUFFER        (acpi_size) (0)
#define ACPI_ALLOCATE_LOCAL_BUFFER  (acpi_size) (0)
#define ACPI_ALLOCATE_ZEROED(a)         NULL
#define ACPI_ALL_NOTIFY                 (ACPI_SYSTEM_NOTIFY | ACPI_DEVICE_NOTIFY)
#define ACPI_ARRAY_LENGTH(x)            (sizeof(x) / sizeof((x)[0]))
#define ACPI_ASCII_MAX                  0x7F
#define ACPI_BITREG_ARB_DISABLE                 0x13
#define ACPI_BITREG_BUS_MASTER_RLD              0x0F
#define ACPI_BITREG_BUS_MASTER_STATUS           0x01
#define ACPI_BITREG_GLOBAL_LOCK_ENABLE          0x09
#define ACPI_BITREG_GLOBAL_LOCK_RELEASE         0x10
#define ACPI_BITREG_GLOBAL_LOCK_STATUS          0x02
#define ACPI_BITREG_MAX                         0x13
#define ACPI_BITREG_PCIEXP_WAKE_DISABLE         0x0D
#define ACPI_BITREG_PCIEXP_WAKE_STATUS          0x07
#define ACPI_BITREG_POWER_BUTTON_ENABLE         0x0A
#define ACPI_BITREG_POWER_BUTTON_STATUS         0x03
#define ACPI_BITREG_RT_CLOCK_ENABLE             0x0C
#define ACPI_BITREG_RT_CLOCK_STATUS             0x05
#define ACPI_BITREG_SCI_ENABLE                  0x0E
#define ACPI_BITREG_SLEEP_BUTTON_ENABLE         0x0B
#define ACPI_BITREG_SLEEP_BUTTON_STATUS         0x04
#define ACPI_BITREG_SLEEP_ENABLE                0x12
#define ACPI_BITREG_SLEEP_TYPE                  0x11
#define ACPI_BITREG_TIMER_ENABLE                0x08
#define ACPI_BITREG_TIMER_STATUS                0x00
#define ACPI_BITREG_WAKE_STATUS                 0x06
#define ACPI_CAST_INDIRECT_PTR(t, p)    ((t **) (acpi_uintptr_t) (p))
#define ACPI_CAST_PTR(t, p)             ((t *) (acpi_uintptr_t) (p))
#define ACPI_CLEAR_BIT(target,bit)      ((target) &= ~(bit))
#define ACPI_CLEAR_STATUS                       1
#define ACPI_COMPARE_NAMESEG(a,b)       (*ACPI_CAST_PTR (u32, (a)) == *ACPI_CAST_PTR (u32, (b)))
#define ACPI_COPY_NAMESEG(dest,src)     (*ACPI_CAST_PTR (u32, (dest)) = *ACPI_CAST_PTR (u32, (src)))
#define ACPI_C_STATES_MAX               ACPI_STATE_C3
#define ACPI_C_STATE_COUNT              4

#define ACPI_DEFAULT_HANDLER            NULL
#define ACPI_DEVICE_HANDLER_LIST        1	
#define ACPI_DEVICE_NOTIFY              0x2
#define ACPI_DISABLE_ALL_FEATURE_STRINGS    (ACPI_DISABLE_INTERFACES | ACPI_FEATURE_STRINGS)
#define ACPI_DISABLE_ALL_STRINGS            (ACPI_DISABLE_INTERFACES | ACPI_VENDOR_STRINGS | ACPI_FEATURE_STRINGS)
#define ACPI_DISABLE_ALL_VENDOR_STRINGS     (ACPI_DISABLE_INTERFACES | ACPI_VENDOR_STRINGS)
#define ACPI_DISABLE_EVENT                      0
#define ACPI_DISABLE_INTERFACES             0x04
#define ACPI_DO_NOT_WAIT                0
#define ACPI_D_STATES_MAX               ACPI_STATE_D3
#define ACPI_D_STATE_COUNT              5
#define ACPI_EISAID_STRING_SIZE         8	
#define ACPI_ENABLE_ALL_FEATURE_STRINGS     (ACPI_ENABLE_INTERFACES | ACPI_FEATURE_STRINGS)
#define ACPI_ENABLE_ALL_STRINGS             (ACPI_ENABLE_INTERFACES | ACPI_VENDOR_STRINGS | ACPI_FEATURE_STRINGS)
#define ACPI_ENABLE_ALL_VENDOR_STRINGS      (ACPI_ENABLE_INTERFACES | ACPI_VENDOR_STRINGS)
#define ACPI_ENABLE_EVENT                       1
#define ACPI_ENABLE_INTERFACES              0x00
#define ACPI_EVENT_FLAG_DISABLED        (acpi_event_status) 0x00
#define ACPI_EVENT_FLAG_ENABLED         (acpi_event_status) 0x01
#define ACPI_EVENT_FLAG_ENABLE_SET      (acpi_event_status) 0x08
#define ACPI_EVENT_FLAG_HAS_HANDLER     (acpi_event_status) 0x10
#define ACPI_EVENT_FLAG_MASKED          (acpi_event_status) 0x20
#define ACPI_EVENT_FLAG_SET             ACPI_EVENT_FLAG_STATUS_SET
#define ACPI_EVENT_FLAG_STATUS_SET      (acpi_event_status) 0x04
#define ACPI_EVENT_FLAG_WAKE_ENABLED    (acpi_event_status) 0x02
#define ACPI_EVENT_GLOBAL               1
#define ACPI_EVENT_MAX                  4
#define ACPI_EVENT_PMTIMER              0
#define ACPI_EVENT_POWER_BUTTON         2
#define ACPI_EVENT_RTC                  4
#define ACPI_EVENT_SLEEP_BUTTON         3
#define ACPI_EVENT_TYPE_FIXED       1
#define ACPI_EVENT_TYPE_GPE         0


#define ACPI_FEATURE_STRINGS                0x02

#define ACPI_FULL_INITIALIZATION        0x0000
#define ACPI_FULL_PATHNAME              0
#define ACPI_FULL_PATHNAME_NO_TRAILING  2
#define ACPI_GENERIC_NOTIFY_MAX         0x0F
#define ACPI_GPE_AUTO_ENABLED           (u8) 0x20
#define ACPI_GPE_CAN_WAKE               (u8) 0x10
#define ACPI_GPE_CONDITIONAL_ENABLE     2
#define ACPI_GPE_DISABLE                1
#define ACPI_GPE_DISPATCH_HANDLER       (u8) 0x02
#define ACPI_GPE_DISPATCH_MASK          (u8) 0x07
#define ACPI_GPE_DISPATCH_METHOD        (u8) 0x01
#define ACPI_GPE_DISPATCH_NONE          (u8) 0x00
#define ACPI_GPE_DISPATCH_NOTIFY        (u8) 0x03
#define ACPI_GPE_DISPATCH_RAW_HANDLER   (u8) 0x04
#define ACPI_GPE_DISPATCH_TYPE(flags)   ((u8) ((flags) & ACPI_GPE_DISPATCH_MASK))
#define ACPI_GPE_EDGE_TRIGGERED         (u8) 0x00
#define ACPI_GPE_ENABLE                 0
#define ACPI_GPE_INITIALIZED            (u8) 0x40
#define ACPI_GPE_LEVEL_TRIGGERED        (u8) 0x08
#define ACPI_GPE_REGISTER_WIDTH         8
#define ACPI_GPE_XRUPT_TYPE_MASK        (u8) 0x08
#define ACPI_HIBYTE(integer)            ((u8) (((u16)(integer)) >> 8))
#define ACPI_HIDWORD(integer64)         ((u32)(((u64)(integer64)) >> 32))
#define ACPI_HIWORD(integer)            ((u16)(((u32)(integer)) >> 16))
#define ACPI_INITIALIZED_OK             0x02
#define ACPI_INIT_DEVICE_INI        1
#define ACPI_INTEGER_BIT_SIZE           64
#define ACPI_INTEGER_MAX                ACPI_UINT64_MAX
#define ACPI_INTERRUPT_HANDLED          0x01
#define ACPI_INTERRUPT_NOT_HANDLED      0x00
#define ACPI_IO_MASK                    1
#define ACPI_ISR                        0x0
#define ACPI_IS_OEM_SIG(a)        (!strncmp (ACPI_CAST_PTR (char, (a)), ACPI_OEM_NAME, 3) &&\
	 strnlen (a, ACPI_NAMESEG_SIZE) == ACPI_NAMESEG_SIZE)
#define ACPI_LOBYTE(integer)            ((u8)   (u16)(integer))
#define ACPI_LODWORD(integer64)         ((u32)  (u64)(integer64))
#define ACPI_LOWORD(integer)            ((u16)  (u32)(integer))
#define ACPI_MAKE_RSDP_SIG(dest)        (memcpy (ACPI_CAST_PTR (char, (dest)), ACPI_SIG_RSDP, 8))
#define ACPI_MAX(a,b)                   (((a)>(b))?(a):(b))
#define ACPI_MAX16_DECIMAL_DIGITS        5
#define ACPI_MAX32_DECIMAL_DIGITS       10
#define ACPI_MAX64_DECIMAL_DIGITS       20
#define ACPI_MAX8_DECIMAL_DIGITS         3
#define ACPI_MAX_DECIMAL_DIGITS         20	
#define ACPI_MAX_DEVICE_SPECIFIC_NOTIFY 0xBF
#define ACPI_MAX_GPE_BLOCKS             2
#define ACPI_MAX_NOTIFY_HANDLER_TYPE    0x3
#define ACPI_MAX_PTR                    ACPI_UINT64_MAX
#define ACPI_MAX_SYS_NOTIFY             0x7F
#define ACPI_MEM_PARAMETERS             _COMPONENT, _acpi_module_name, "__LINE__"

#define ACPI_MIN(a,b)                   (((a)<(b))?(a):(b))

#define ACPI_MSEC_PER_SEC               1000L
#define ACPI_NAMESEG_SIZE               4	
#define ACPI_NAME_TYPE_MAX              2
#define ACPI_NOTIFY_AFFINITY_UPDATE     (u8) 0x0D
#define ACPI_NOTIFY_BUS_CHECK           (u8) 0x00
#define ACPI_NOTIFY_BUS_MODE_MISMATCH   (u8) 0x06
#define ACPI_NOTIFY_CAPABILITIES_CHECK  (u8) 0x08
#define ACPI_NOTIFY_DEVICE_CHECK        (u8) 0x01
#define ACPI_NOTIFY_DEVICE_CHECK_LIGHT  (u8) 0x04
#define ACPI_NOTIFY_DEVICE_PLD_CHECK    (u8) 0x09
#define ACPI_NOTIFY_DEVICE_WAKE         (u8) 0x02
#define ACPI_NOTIFY_DISCONNECT_RECOVER  (u8) 0x0F
#define ACPI_NOTIFY_EJECT_REQUEST       (u8) 0x03
#define ACPI_NOTIFY_FREQUENCY_MISMATCH  (u8) 0x05
#define ACPI_NOTIFY_LOCALITY_UPDATE     (u8) 0x0B
#define ACPI_NOTIFY_MEMORY_UPDATE       (u8) 0x0E
#define ACPI_NOTIFY_POWER_FAULT         (u8) 0x07
#define ACPI_NOTIFY_RESERVED            (u8) 0x0A
#define ACPI_NOTIFY_SHUTDOWN_REQUEST    (u8) 0x0C
#define ACPI_NOT_ISR                    0x1
#define ACPI_NO_ACPI_ENABLE             0x0002
#define ACPI_NO_ADDRESS_SPACE_INIT      0x0080
#define ACPI_NO_BUFFER              0
#define ACPI_NO_DEVICE_INIT             0x0040
#define ACPI_NO_EVENT_INIT              0x0008
#define ACPI_NO_FACS_INIT               0x0001
#define ACPI_NO_HANDLER_INIT            0x0010
#define ACPI_NO_HARDWARE_INIT           0x0004
#define ACPI_NO_OBJECT_INIT             0x0020
#define ACPI_NSEC_PER_MSEC              1000000L
#define ACPI_NSEC_PER_SEC               1000000000L
#define ACPI_NSEC_PER_USEC              1000L
#define ACPI_NUM_BITREG                         ACPI_BITREG_MAX + 1
#define ACPI_NUM_FIXED_EVENTS           ACPI_EVENT_MAX + 1
#define ACPI_NUM_NOTIFY_TYPES           2
#define ACPI_NUM_NS_TYPES               (ACPI_TYPE_INVALID + 1)
#define ACPI_NUM_PREDEFINED_REGIONS     11
#define ACPI_NUM_TABLE_EVENTS           4
#define ACPI_NUM_TYPES                  (ACPI_TYPE_EXTERNAL_MAX + 1)
#define ACPI_OEM_ID_SIZE                6
#define ACPI_OEM_TABLE_ID_SIZE          8
#define ACPI_OFFSET(d, f)               ACPI_PTR_DIFF (&(((d *) 0)->f), (void *) 0)
#define ACPI_OPT_END                    -1
#define ACPI_OSI_WINSRV_2003            0x04
#define ACPI_OSI_WINSRV_2003_SP1        0x06
#define ACPI_OSI_WINSRV_2008            0x08
#define ACPI_OSI_WIN_10                 0x0E
#define ACPI_OSI_WIN_10_19H1            0x14
#define ACPI_OSI_WIN_10_RS1             0x0F
#define ACPI_OSI_WIN_10_RS2             0x10
#define ACPI_OSI_WIN_10_RS3             0x11
#define ACPI_OSI_WIN_10_RS4             0x12
#define ACPI_OSI_WIN_10_RS5             0x13
#define ACPI_OSI_WIN_2000               0x01
#define ACPI_OSI_WIN_7                  0x0B
#define ACPI_OSI_WIN_8                  0x0C
#define ACPI_OSI_WIN_8_1                0x0D
#define ACPI_OSI_WIN_VISTA              0x07
#define ACPI_OSI_WIN_VISTA_SP1          0x09
#define ACPI_OSI_WIN_VISTA_SP2          0x0A
#define ACPI_OSI_WIN_XP                 0x02
#define ACPI_OSI_WIN_XP_SP1             0x03
#define ACPI_OSI_WIN_XP_SP2             0x05
#define ACPI_OWNER_ID_MAX               0xFFF	
#define ACPI_PATH_SEGMENT_LENGTH        5	
#define ACPI_PATH_SEPARATOR             '.'
#define ACPI_PCICLS_STRING_SIZE         7	
#define ACPI_PCI_ROOT_BRIDGE            0x01
#define ACPI_PHYSADDR_TO_PTR(i)         ACPI_TO_POINTER(i)
#define ACPI_PM1_REGISTER_WIDTH         16
#define ACPI_PM2_REGISTER_WIDTH         8
#define ACPI_PM_TIMER_FREQUENCY         3579545
#define ACPI_PM_TIMER_WIDTH             32

#define ACPI_PTR_DIFF(a, b)             ((acpi_size) (ACPI_CAST_PTR (u8, (a)) - ACPI_CAST_PTR (u8, (b))))
#define ACPI_PTR_TO_PHYSADDR(i)         ACPI_TO_INTEGER(i)
#define ACPI_READ                       0
#define ACPI_REENABLE_GPE               0x80
#define ACPI_REGION_ACTIVATE    0
#define ACPI_REGION_DEACTIVATE  1
#define ACPI_REG_CONNECT                1
#define ACPI_REG_DISCONNECT             0
#define ACPI_RESET_REGISTER_WIDTH       8
#define ACPI_ROOT_OBJECT                ((acpi_handle) ACPI_TO_POINTER (ACPI_MAX_PTR))
#define ACPI_SET_BIT(target,bit)        ((target) |= (bit))
#define ACPI_SINGLE_NAME                1
#define ACPI_SIZE_MAX                   ACPI_UINT64_MAX
#define ACPI_SLEEP_TYPE_INVALID         0xFF
#define ACPI_SLEEP_TYPE_MAX             0x7
#define ACPI_SPECIFIC_NOTIFY_MAX        0x84
#define ACPI_STATE_C0                   (u8) 0
#define ACPI_STATE_C1                   (u8) 1
#define ACPI_STATE_C2                   (u8) 2
#define ACPI_STATE_C3                   (u8) 3
#define ACPI_STATE_D0                   (u8) 0
#define ACPI_STATE_D1                   (u8) 1
#define ACPI_STATE_D2                   (u8) 2
#define ACPI_STATE_D3                   (u8) 4
#define ACPI_STATE_D3_COLD              ACPI_STATE_D3
#define ACPI_STATE_D3_HOT               (u8) 3
#define ACPI_STATE_S0                   (u8) 0
#define ACPI_STATE_S1                   (u8) 1
#define ACPI_STATE_S2                   (u8) 2
#define ACPI_STATE_S3                   (u8) 3
#define ACPI_STATE_S4                   (u8) 4
#define ACPI_STATE_S5                   (u8) 5
#define ACPI_STATE_UNKNOWN              (u8) 0xFF
#define ACPI_STA_BATTERY_PRESENT        0x10
#define ACPI_STA_DEVICE_ENABLED         0x02
#define ACPI_STA_DEVICE_FUNCTIONING     0x08
#define ACPI_STA_DEVICE_OK              0x08	
#define ACPI_STA_DEVICE_PRESENT         0x01
#define ACPI_STA_DEVICE_UI              0x04
#define ACPI_SUBSYSTEM_INITIALIZE       0x01
#define ACPI_SUB_PTR(t, a, b)           ACPI_CAST_PTR (t, (ACPI_CAST_PTR (u8, (a)) - (acpi_size)(b)))
#define ACPI_SYSTEM_HANDLER_LIST        0	
#define ACPI_SYSTEM_NOTIFY              0x1
#define ACPI_SYS_MODES_MASK             0x0003
#define ACPI_SYS_MODE_ACPI              0x0001
#define ACPI_SYS_MODE_LEGACY            0x0002
#define ACPI_SYS_MODE_UNKNOWN           0x0000
#define ACPI_S_STATES_MAX               ACPI_STATE_S5
#define ACPI_S_STATE_COUNT              6
#define ACPI_TABLE_EVENT_INSTALL        0x2
#define ACPI_TABLE_EVENT_LOAD           0x0
#define ACPI_TABLE_EVENT_UNINSTALL      0x3
#define ACPI_TABLE_EVENT_UNLOAD         0x1
#define ACPI_TIME_AFTER(a, b)           ((s64)((b) - (a)) < 0)
#define ACPI_TOTAL_TYPES                (ACPI_TYPE_NS_NODE_MAX + 1)
#define ACPI_TO_INTEGER(p)              ACPI_PTR_DIFF (p, (void *) 0)
#define ACPI_TO_POINTER(i)              ACPI_CAST_PTR (void, (acpi_size) (i))
#define ACPI_TYPE_ANY                   0x00
#define ACPI_TYPE_BUFFER                0x03
#define ACPI_TYPE_BUFFER_FIELD          0x0E
#define ACPI_TYPE_DDB_HANDLE            0x0F
#define ACPI_TYPE_DEBUG_OBJECT          0x10
#define ACPI_TYPE_DEVICE                0x06	
#define ACPI_TYPE_EVENT                 0x07
#define ACPI_TYPE_EXTERNAL_MAX          0x10
#define ACPI_TYPE_FIELD_UNIT            0x05
#define ACPI_TYPE_INTEGER               0x01	
#define ACPI_TYPE_INVALID               0x1E
#define ACPI_TYPE_LOCAL_ADDRESS_HANDLER 0x18
#define ACPI_TYPE_LOCAL_ALIAS           0x15
#define ACPI_TYPE_LOCAL_BANK_FIELD      0x12
#define ACPI_TYPE_LOCAL_DATA            0x1D
#define ACPI_TYPE_LOCAL_EXTRA           0x1C
#define ACPI_TYPE_LOCAL_INDEX_FIELD     0x13
#define ACPI_TYPE_LOCAL_MAX             0x1D
#define ACPI_TYPE_LOCAL_METHOD_ALIAS    0x16
#define ACPI_TYPE_LOCAL_NOTIFY          0x17
#define ACPI_TYPE_LOCAL_REFERENCE       0x14	
#define ACPI_TYPE_LOCAL_REGION_FIELD    0x11
#define ACPI_TYPE_LOCAL_RESOURCE        0x19
#define ACPI_TYPE_LOCAL_RESOURCE_FIELD  0x1A
#define ACPI_TYPE_LOCAL_SCOPE           0x1B	
#define ACPI_TYPE_METHOD                0x08	
#define ACPI_TYPE_MUTEX                 0x09
#define ACPI_TYPE_NOT_FOUND             0xFF
#define ACPI_TYPE_NS_NODE_MAX           0x1B	
#define ACPI_TYPE_PACKAGE               0x04	
#define ACPI_TYPE_POWER                 0x0B	
#define ACPI_TYPE_PROCESSOR             0x0C	
#define ACPI_TYPE_REGION                0x0A
#define ACPI_TYPE_STRING                0x02
#define ACPI_TYPE_THERMAL               0x0D	
#define ACPI_UINT16_MAX                 (u16)(~((u16) 0))	
#define ACPI_UINT32_MAX                 (u32)(~((u32) 0))	
#define ACPI_UINT64_MAX                 (u64)(~((u64) 0))	
#define ACPI_UINT8_MAX                  (u8) (~((u8)  0))	

#define ACPI_USEC_PER_MSEC              1000L
#define ACPI_USEC_PER_SEC               1000000L
#define ACPI_UUID_LENGTH                16
#define ACPI_VALIDATE_RSDP_SIG(a)       (!strncmp (ACPI_CAST_PTR (char, (a)), ACPI_SIG_RSDP, 8))
#define ACPI_VALID_ADR                  0x0002
#define ACPI_VALID_CID                  0x0020
#define ACPI_VALID_CLS                  0x0040
#define ACPI_VALID_HID                  0x0004
#define ACPI_VALID_SXDS                 0x0100
#define ACPI_VALID_SXWS                 0x0200
#define ACPI_VALID_UID                  0x0008
#define ACPI_VENDOR_STRINGS                 0x01
#define ACPI_WAIT_FOREVER               0xFFFF	
#define ACPI_WRITE                      1
#define FALSE                           (1 == 0)
#define NULL                            (void *) 0
#define PCI_EXPRESS_ROOT_HID_STRING     "PNP0A08"
#define PCI_ROOT_HID_STRING             "PNP0A03"
#define TRUE                            (1 == 1)

#define acpi_cache_t                    struct acpi_memory_list
#define acpi_mutex                      acpi_semaphore
#define acpi_os_acquire_mutex(handle,time) acpi_os_wait_semaphore (handle, 1, time)
#define acpi_os_create_mutex(out_handle) acpi_os_create_semaphore (1, 1, out_handle)
#define acpi_os_delete_mutex(handle)    (void) acpi_os_delete_semaphore (handle)
#define acpi_os_release_mutex(handle)   (void) acpi_os_signal_semaphore (handle, 1)
#define acpi_semaphore                  void *
#define acpi_spinlock                   void *
#define acpi_thread_id                  u64
#define acpi_uintptr_t                  void *
#define ACPI_ADDRESS_RANGE_MAX          2
#define ACPI_CA_SUPPORT_LEVEL           5
#define ACPI_CHECKSUM_ABORT             FALSE
#define ACPI_DB_LINE_BUFFER_SIZE        512
#define ACPI_DEBUGGER_COMMAND_PROMPT    '-'
#define ACPI_DEBUGGER_EXECUTE_PROMPT    '%'
#define ACPI_DEBUGGER_MAX_ARGS          ACPI_METHOD_NUM_ARGS + 4	
#define ACPI_DEFAULT_PAGE_SIZE          4096	
#define ACPI_EBDA_PTR_LENGTH            2
#define ACPI_EBDA_PTR_LOCATION          0x0000040E	
#define ACPI_EBDA_WINDOW_SIZE           1024
#define ACPI_HI_RSDP_WINDOW_BASE        0x000E0000	
#define ACPI_HI_RSDP_WINDOW_SIZE        0x00020000
#define ACPI_IPMI_BUFFER_SIZE           ACPI_SERIAL_HEADER_SIZE + ACPI_IPMI_DATA_SIZE
#define ACPI_IPMI_DATA_SIZE             64
#define ACPI_MAX_ADDRESS_SPACE          255
#define ACPI_MAX_COMMENT_CACHE_DEPTH    96	
#define ACPI_MAX_EXTPARSE_CACHE_DEPTH   96	
#define ACPI_MAX_GSBUS_BUFFER_SIZE      ACPI_SERIAL_HEADER_SIZE + ACPI_MAX_GSBUS_DATA_SIZE
#define ACPI_MAX_GSBUS_DATA_SIZE        255
#define ACPI_MAX_LOOP_TIMEOUT           30
#define ACPI_MAX_MATCH_OPCODE           5
#define ACPI_MAX_NAMESPACE_CACHE_DEPTH  96	
#define ACPI_MAX_OBJECT_CACHE_DEPTH     96	
#define ACPI_MAX_PARSE_CACHE_DEPTH      96	
#define ACPI_MAX_REFERENCE_COUNT        0x4000
#define ACPI_MAX_SEMAPHORE_COUNT        256
#define ACPI_MAX_SLEEP                  2000	
#define ACPI_MAX_STATE_CACHE_DEPTH      96	
#define ACPI_METHOD_MAX_ARG             6
#define ACPI_METHOD_MAX_LOCAL           7
#define ACPI_METHOD_NUM_ARGS            7
#define ACPI_METHOD_NUM_LOCALS          8
#define ACPI_NUM_DEFAULT_SPACES         4
#define ACPI_NUM_OWNERID_MASKS          128
#define ACPI_NUM_sx_d_METHODS           4
#define ACPI_NUM_sx_w_METHODS           5
#define ACPI_OBJ_MAX_OPERAND            7
#define ACPI_OBJ_NUM_OPERANDS           8
#define ACPI_OS_NAME                    "Microsoft Windows NT"
#define ACPI_REDUCED_HARDWARE           FALSE
#define ACPI_RESULTS_FRAME_OBJ_NUM      8
#define ACPI_RESULTS_OBJ_NUM_MAX        255
#define ACPI_ROOT_TABLE_SIZE_INCREMENT  4
#define ACPI_RSDP_CHECKSUM_LENGTH       20
#define ACPI_RSDP_SCAN_STEP             16
#define ACPI_RSDP_XCHECKSUM_LENGTH      36
#define ACPI_SERIAL_HEADER_SIZE         2	
#define ACPI_SMBUS_BUFFER_SIZE          ACPI_SERIAL_HEADER_SIZE + ACPI_SMBUS_DATA_SIZE
#define ACPI_SMBUS_DATA_SIZE            32
#define ACPI_USER_REGION_BEGIN          0x80
#define UUID_BUFFER_LENGTH          16	
#define UUID_HYPHEN1_OFFSET         8
#define UUID_HYPHEN2_OFFSET         13
#define UUID_HYPHEN3_OFFSET         18
#define UUID_HYPHEN4_OFFSET         23
#define UUID_STRING_LENGTH          36	

#define ACPI_MUTEX_SEM              1
#define ACPI_NO_UNIT_LIMIT          ((u32) -1)
#define ACPI_SIGNAL_BREAKPOINT      1
#define ACPI_SIGNAL_FATAL           0
#define REQUEST_DIR_ONLY                    1
#define REQUEST_FILE_ONLY                   0

# define acpi_os_acquire_raw_lock(handle)	acpi_os_acquire_lock(handle)
# define acpi_os_create_raw_lock(out_handle)	acpi_os_create_lock(out_handle)
# define acpi_os_delete_raw_lock(handle)	acpi_os_delete_lock(handle)
# define acpi_os_release_raw_lock(handle, flags)	\
	acpi_os_release_lock(handle, flags)

#define ACPI_ACQUIRE_GLOBAL_LOCK(Glptr, acquired) acquired = 1

#define ACPI_BINARY_SEMAPHORE       0



#define ACPI_DEBUGGER 1

#define ACPI_DISASSEMBLER 1

#define ACPI_FILE              FILE *
#define ACPI_FILE_ERR          stderr
#define ACPI_FILE_OUT          stdout








#define ACPI_MUTEX_TYPE             ACPI_BINARY_SEMAPHORE

#define ACPI_OSL_MUTEX              1
#define ACPI_RELEASE_GLOBAL_LOCK(Glptr, pending) pending = 0

#define ACPI_SRC_OS_LF_ONLY 0
#define ACPI_STRUCT_INIT(field, value)  value




#define COMPILER_DEPENDENT_INT64   long long
#define COMPILER_DEPENDENT_UINT64  unsigned long long
#define DEBUGGER_MULTI_THREADED     1
#define DEBUGGER_SINGLE_THREADED    0
#define DEBUGGER_THREADING          DEBUGGER_MULTI_THREADED


#define ACPI_CAST_PTHREAD_T(pthread) ((acpi_thread_id) (pthread))
#define ACPI_DEBUG_DEFAULT          (ACPI_LV_INFO | ACPI_LV_REPAIR)

#define ACPI_MACHINE_WIDTH          BITS_PER_LONG
#define ACPI_MSG_BIOS_ERROR     KERN_ERR "ACPI BIOS Error (bug): "
#define ACPI_MSG_BIOS_WARNING   KERN_WARNING "ACPI BIOS Warning (bug): "
#define ACPI_MSG_ERROR          KERN_ERR "ACPI Error: "
#define ACPI_MSG_EXCEPTION      KERN_ERR "ACPI Exception: "
#define ACPI_MSG_INFO           KERN_INFO "ACPI: "
#define ACPI_MSG_WARNING        KERN_WARNING "ACPI Warning: "



































#define acpi_cpu_flags                      unsigned long
#define acpi_raw_spinlock                   raw_spinlock_t *
#define strtoul                     simple_strtoul

#define __ismask(x) (_ctype[(int)(unsigned char)(x)])
#define isalnum(c)	((__ismask(c)&(_U|_L|_D)) != 0)
#define isalpha(c)	((__ismask(c)&(_U|_L)) != 0)
#define isascii(c) (((unsigned char)(c))<=0x7f)
#define iscntrl(c)	((__ismask(c)&(_C)) != 0)
#define isgraph(c)	((__ismask(c)&(_P|_U|_L|_D)) != 0)
#define islower(c)	((__ismask(c)&(_L)) != 0)
#define isprint(c)	((__ismask(c)&(_P|_U|_L|_D|_SP)) != 0)
#define ispunct(c)	((__ismask(c)&(_P)) != 0)
#define isspace(c)	((__ismask(c)&(_S)) != 0)
#define isupper(c)	((__ismask(c)&(_U)) != 0)
#define isxdigit(c)	((__ismask(c)&(_D|_X)) != 0)
#define toascii(c) (((unsigned char)(c))&0x7f)
#define tolower(c) __tolower(c)
#define toupper(c) __toupper(c)

#define ACPI_GET_FUNCTION_NAME          __func__
#define COMPILER_VA_MACRO               1

#define va_arg(v, l)            __builtin_va_arg(v, l)
#define va_copy(d, s)           __builtin_va_copy(d, s)
#define va_end(v)               __builtin_va_end(v)
#define va_start(v, l)          __builtin_va_start(v, l)
#define ACPI_ACTUAL_DEBUG(level, line, filename, modulename, component, ...) \
	ACPI_DO_DEBUG_PRINT (acpi_debug_print, level, line, \
		filename, modulename, component, __VA_ARGS__)
#define ACPI_ACTUAL_DEBUG_RAW(level, line, filename, modulename, component, ...) \
	ACPI_DO_DEBUG_PRINT (acpi_debug_print_raw, level, line, \
		filename, modulename, component, __VA_ARGS__)
#define ACPI_ALL_COMPONENTS         0x0001FFFF
#define ACPI_ALL_DRIVERS            0xFFFF0000
#define ACPI_BIOS_ERROR(plist)          acpi_bios_error plist
#define ACPI_BIOS_EXCEPTION(plist)      acpi_bios_exception plist
#define ACPI_BIOS_WARNING(plist)        acpi_bios_warning plist
#define ACPI_CA_DEBUGGER            0x00000200
#define ACPI_CA_DISASSEMBLER        0x00000800
#define ACPI_COMPILER               0x00001000
#define ACPI_COMPONENT_DEFAULT      (ACPI_ALL_COMPONENTS)
#define ACPI_DB_ALL                 ACPI_DEBUG_LEVEL (ACPI_LV_ALL)
#define ACPI_DB_ALLOCATIONS         ACPI_DEBUG_LEVEL (ACPI_LV_ALLOCATIONS)
#define ACPI_DB_ALL_EXCEPTIONS      ACPI_DEBUG_LEVEL (ACPI_LV_ALL_EXCEPTIONS)
#define ACPI_DB_BFIELD              ACPI_DEBUG_LEVEL (ACPI_LV_BFIELD)
#define ACPI_DB_DEBUG_OBJECT        ACPI_DEBUG_LEVEL (ACPI_LV_DEBUG_OBJECT)
#define ACPI_DB_DISPATCH            ACPI_DEBUG_LEVEL (ACPI_LV_DISPATCH)
#define ACPI_DB_EVALUATION          ACPI_DEBUG_LEVEL (ACPI_LV_EVALUATION)
#define ACPI_DB_EVENTS              ACPI_DEBUG_LEVEL (ACPI_LV_EVENTS)
#define ACPI_DB_EXEC                ACPI_DEBUG_LEVEL (ACPI_LV_EXEC)
#define ACPI_DB_FUNCTIONS           ACPI_DEBUG_LEVEL (ACPI_LV_FUNCTIONS)
#define ACPI_DB_INFO                ACPI_DEBUG_LEVEL (ACPI_LV_INFO)
#define ACPI_DB_INIT                ACPI_DEBUG_LEVEL (ACPI_LV_INIT)
#define ACPI_DB_INIT_NAMES          ACPI_DEBUG_LEVEL (ACPI_LV_INIT_NAMES)
#define ACPI_DB_INTERRUPTS          ACPI_DEBUG_LEVEL (ACPI_LV_INTERRUPTS)
#define ACPI_DB_IO                  ACPI_DEBUG_LEVEL (ACPI_LV_IO)
#define ACPI_DB_LOAD                ACPI_DEBUG_LEVEL (ACPI_LV_LOAD)
#define ACPI_DB_MUTEX               ACPI_DEBUG_LEVEL (ACPI_LV_MUTEX)
#define ACPI_DB_NAMES               ACPI_DEBUG_LEVEL (ACPI_LV_NAMES)
#define ACPI_DB_OBJECTS             ACPI_DEBUG_LEVEL (ACPI_LV_OBJECTS)
#define ACPI_DB_OPREGION            ACPI_DEBUG_LEVEL (ACPI_LV_OPREGION)
#define ACPI_DB_OPTIMIZATIONS       ACPI_DEBUG_LEVEL (ACPI_LV_OPTIMIZATIONS)
#define ACPI_DB_PACKAGE             ACPI_DEBUG_LEVEL (ACPI_LV_PACKAGE)
#define ACPI_DB_PARSE               ACPI_DEBUG_LEVEL (ACPI_LV_PARSE)
#define ACPI_DB_PARSE_TREES         ACPI_DEBUG_LEVEL (ACPI_LV_PARSE_TREES)
#define ACPI_DB_REPAIR              ACPI_DEBUG_LEVEL (ACPI_LV_REPAIR)
#define ACPI_DB_RESOURCES           ACPI_DEBUG_LEVEL (ACPI_LV_RESOURCES)
#define ACPI_DB_TABLES              ACPI_DEBUG_LEVEL (ACPI_LV_TABLES)
#define ACPI_DB_THREADS             ACPI_DEBUG_LEVEL (ACPI_LV_THREADS)
#define ACPI_DB_TRACE_POINT         ACPI_DEBUG_LEVEL (ACPI_LV_TRACE_POINT)
#define ACPI_DB_USER_REQUESTS       ACPI_DEBUG_LEVEL (ACPI_LV_USER_REQUESTS)
#define ACPI_DB_VALUES              ACPI_DEBUG_LEVEL (ACPI_LV_VALUES)
#define ACPI_DEBUG_ALL              (ACPI_LV_AML_DISASSEMBLE | ACPI_LV_ALL_EXCEPTIONS | ACPI_LV_ALL)
#define ACPI_DEBUG_DEFAULT          (ACPI_LV_INIT | ACPI_LV_DEBUG_OBJECT | ACPI_LV_EVALUATION | ACPI_LV_REPAIR)
#define ACPI_DEBUG_EXEC(a)              a
#define ACPI_DEBUG_LEVEL(dl)        (u32) dl,ACPI_DEBUG_PARAMETERS
#define ACPI_DEBUG_OBJECT(obj,l,i)      acpi_ex_do_debug_object(obj,l,i)
#define ACPI_DEBUG_ONLY_MEMBERS(a)      a;
#define ACPI_DEBUG_PARAMETERS \
	"__LINE__", ACPI_GET_FUNCTION_NAME, _acpi_module_name, _COMPONENT
#define ACPI_DEBUG_PRINT(plist)         acpi_debug_print plist
#define ACPI_DEBUG_PRINT_RAW(plist)     acpi_debug_print_raw plist
#define ACPI_DISPATCHER             0x00000040
#define ACPI_DO_DEBUG_PRINT(function, level, line, filename, modulename, component, ...) \
	ACPI_DO_WHILE0 ({ \
		if (ACPI_IS_DEBUG_ENABLED (level, component)) \
		{ \
			function (level, line, filename, modulename, component, __VA_ARGS__); \
		} \
	})
#define ACPI_DO_WHILE0(a)               do a while(0)
#define ACPI_DRIVER                 0x00008000
#define ACPI_DUMP_BUFFER(a, b)          acpi_ut_debug_dump_buffer((u8 *) a, b, DB_BYTE_DISPLAY, _COMPONENT)
#define ACPI_DUMP_ENTRY(a, b)           acpi_ns_dump_entry (a, b)
#define ACPI_DUMP_OPERANDS(a, b ,c)     acpi_ex_dump_operands(a, b, c)
#define ACPI_DUMP_PATHNAME(a, b, c, d)  acpi_ns_dump_pathname(a, b, c, d)
#define ACPI_DUMP_STACK_ENTRY(a)        acpi_ex_dump_operand((a), 0)
#define ACPI_ERROR(plist)               acpi_error plist
#define ACPI_EVENTS                 0x00000004
#define ACPI_EXAMPLE                0x00004000
#define ACPI_EXCEPTION(plist)           acpi_exception plist
#define ACPI_EXECUTER               0x00000080
#define ACPI_FUNCTION_ENTRY() \
	acpi_ut_track_stack_ptr()
#define ACPI_FUNCTION_NAME(name)        static const char _acpi_function_name[] = #name;
#define ACPI_FUNCTION_TRACE(name) \
	ACPI_FUNCTION_NAME(name) \
	acpi_ut_trace (ACPI_DEBUG_PARAMETERS)
#define ACPI_FUNCTION_TRACE_PTR(name, pointer) \
	ACPI_TRACE_ENTRY (name, acpi_ut_trace_ptr, void *, pointer)
#define ACPI_FUNCTION_TRACE_STR(name, string) \
	ACPI_TRACE_ENTRY (name, acpi_ut_trace_str, const char *, string)
#define ACPI_FUNCTION_TRACE_U32(name, value) \
	ACPI_TRACE_ENTRY (name, acpi_ut_trace_u32, u32, value)
#define ACPI_GET_FUNCTION_NAME          _acpi_function_name
#define ACPI_HARDWARE               0x00000002
#define ACPI_INFO(plist)                acpi_info plist
#define ACPI_IS_DEBUG_ENABLED(level, component) \
	((level & acpi_dbg_level) && (component & acpi_dbg_layer))
#define ACPI_LV_ALL                 ACPI_LV_VERBOSITY2
#define ACPI_LV_ALLOCATIONS         0x00100000
#define ACPI_LV_ALL_EXCEPTIONS      0x0000001F
#define ACPI_LV_AML_DISASSEMBLE     0x10000000
#define ACPI_LV_BFIELD              0x00001000
#define ACPI_LV_DEBUG_OBJECT        0x00000002
#define ACPI_LV_DISPATCH            0x00000100
#define ACPI_LV_EVALUATION          0x00080000
#define ACPI_LV_EVENTS              0x80000000
#define ACPI_LV_EXEC                0x00000200
#define ACPI_LV_FULL_TABLES         0x40000000
#define ACPI_LV_FUNCTIONS           0x00200000
#define ACPI_LV_INFO                0x00000004
#define ACPI_LV_INIT                0x00000001
#define ACPI_LV_INIT_NAMES          0x00000020
#define ACPI_LV_INTERRUPTS          0x08000000
#define ACPI_LV_IO                  0x04000000
#define ACPI_LV_LOAD                0x00000080
#define ACPI_LV_MUTEX               0x01000000
#define ACPI_LV_NAMES               0x00000400
#define ACPI_LV_OBJECTS             0x00008000
#define ACPI_LV_OPREGION            0x00000800
#define ACPI_LV_OPTIMIZATIONS       0x00400000
#define ACPI_LV_PACKAGE             0x00040000
#define ACPI_LV_PARSE               0x00000040
#define ACPI_LV_PARSE_TREES         0x00800000
#define ACPI_LV_REPAIR              0x00000008
#define ACPI_LV_RESOURCES           0x00010000
#define ACPI_LV_TABLES              0x00002000
#define ACPI_LV_THREADS             0x02000000
#define ACPI_LV_TRACE_POINT         0x00000010
#define ACPI_LV_USER_REQUESTS       0x00020000
#define ACPI_LV_VALUES              0x00004000
#define ACPI_LV_VERBOSE             0xF0000000
#define ACPI_LV_VERBOSE_INFO        0x20000000
#define ACPI_LV_VERBOSITY1          0x000FFF40 | ACPI_LV_ALL_EXCEPTIONS
#define ACPI_LV_VERBOSITY2          0x00F00000 | ACPI_LV_VERBOSITY1
#define ACPI_LV_VERBOSITY3          0x0F000000 | ACPI_LV_VERBOSITY2
#define ACPI_MODULE_NAME(name)          static const char ACPI_UNUSED_VAR _acpi_module_name[] = name;
#define ACPI_NAMESPACE              0x00000010
#define ACPI_NORMAL_DEFAULT         (ACPI_LV_INIT | ACPI_LV_DEBUG_OBJECT | ACPI_LV_REPAIR)
#define ACPI_OS_SERVICES            0x00000400
#define ACPI_PARSER                 0x00000020
#define ACPI_RESOURCES              0x00000100
#define ACPI_TABLES                 0x00000008
#define ACPI_TOOLS                  0x00002000
#define ACPI_TRACE_ENABLED          ((u32) 4)
#define ACPI_TRACE_ENTRY(name, function, type, param) \
	ACPI_FUNCTION_NAME (name) \
	function (ACPI_DEBUG_PARAMETERS, (type) (param))
#define ACPI_TRACE_EXIT(function, type, param) \
	ACPI_DO_WHILE0 ({ \
		register type _param = (type) (param); \
		function (ACPI_DEBUG_PARAMETERS, _param); \
		return (_param); \
	})
#define ACPI_TRACE_LAYER_ALL        0x000001FF
#define ACPI_TRACE_LAYER_DEFAULT    ACPI_EXECUTER
#define ACPI_TRACE_LEVEL_ALL        ACPI_LV_ALL
#define ACPI_TRACE_LEVEL_DEFAULT    ACPI_LV_TRACE_POINT
#define ACPI_TRACE_ONESHOT          ((u32) 2)
#define ACPI_TRACE_OPCODE           ((u32) 1)
#define ACPI_TRACE_POINT(a, b, c, d)    acpi_trace_point (a, b, c, d)
#define ACPI_UTILITIES              0x00000001
#define ACPI_WARNING(plist)             acpi_warning plist
#define AE_INFO                         _acpi_module_name, "__LINE__"
#define ASL_PREPROCESSOR            0x00020000
#define DT_COMPILER                 0x00010000


#define _acpi_module_name ""
#define return_ACPI_STATUS(status) \
	ACPI_TRACE_EXIT (acpi_ut_status_exit, acpi_status, status)
#define return_PTR(pointer) \
	ACPI_TRACE_EXIT (acpi_ut_ptr_exit, void *, pointer)
#define return_STR(string) \
	ACPI_TRACE_EXIT (acpi_ut_str_exit, const char *, string)
#define return_UINT32(value) \
	ACPI_TRACE_EXIT (acpi_ut_value_exit, u32, value)
#define return_UINT8(value) \
	ACPI_TRACE_EXIT (acpi_ut_value_exit, u8, value)
#define return_VALUE(value) \
	ACPI_TRACE_EXIT (acpi_ut_value_exit, u64, value)
#define return_VOID \
	ACPI_DO_WHILE0 ({ \
		acpi_ut_exit (ACPI_DEBUG_PARAMETERS); \
		return; \
	})

#define ACPI_DIV_64_BY_32(n_hi, n_lo, d32, q32, r32) \
	do { \
		u64 (__n) = ((u64) n_hi) << 32 | (n_lo); \
		(r32) = do_div ((__n), (d32)); \
		(q32) = (u32) (__n); \
	} while (0)
#define ACPI_SHIFT_RIGHT_64(n_hi, n_lo) \
	do { \
		(n_lo) >>= 1; \
		(n_lo) |= (((n_hi) & 1) << 31); \
		(n_hi) >>= 1; \
	} while (0)

#define acpi_os_create_lock(__handle) \
	({ \
		spinlock_t *lock = ACPI_ALLOCATE(sizeof(*lock)); \
		if (lock) { \
			*(__handle) = lock; \
			spin_lock_init(*(__handle)); \
		} \
		lock ? AE_OK : AE_NO_MEMORY; \
	})
#define ACPI_ACCEPTABLE_CONFIGURATION   (u8) 0x01
#define ACPI_ACTIVE_BOTH                (u8) 0x02
#define ACPI_ACTIVE_HIGH                (u8) 0x00
#define ACPI_ACTIVE_LOW                 (u8) 0x01
#define ACPI_ADDRESS_FIXED              (u8) 0x01
#define ACPI_ADDRESS_NOT_FIXED          (u8) 0x00
#define ACPI_BUS_MASTER                 (u8) 0x01
#define ACPI_BUS_NUMBER_RANGE           (u8) 0x02
#define ACPI_CACHABLE_MEMORY            (u8) 0x01
#define ACPI_COMPATIBILITY              (u8) 0x00
#define ACPI_CONSUMER                   (u8) 0x01
#define ACPI_CONTROLLER_INITIATED               0
#define ACPI_DECODE_10                  (u8) 0x00	
#define ACPI_DECODE_16                  (u8) 0x01	
#define ACPI_DEVICE_INITIATED                   1
#define ACPI_DMA_WIDTH128                       4
#define ACPI_DMA_WIDTH16                        1
#define ACPI_DMA_WIDTH256                       5
#define ACPI_DMA_WIDTH32                        2
#define ACPI_DMA_WIDTH64                        3
#define ACPI_DMA_WIDTH8                         0
#define ACPI_EDGE_SENSITIVE             (u8) 0x01
#define ACPI_ENTIRE_RANGE               (ACPI_NON_ISA_ONLY_RANGES | ACPI_ISA_ONLY_RANGES)
#define ACPI_EXCLUSIVE                  (u8) 0x00
#define ACPI_GOOD_CONFIGURATION         (u8) 0x00
#define ACPI_I2C_10BIT_MODE                     1
#define ACPI_I2C_7BIT_MODE                      0
#define ACPI_IO_RANGE                   (u8) 0x01
#define ACPI_IO_RESTRICT_INPUT                  1
#define ACPI_IO_RESTRICT_NONE                   0
#define ACPI_IO_RESTRICT_NONE_PRESERVE          3
#define ACPI_IO_RESTRICT_OUTPUT                 2
#define ACPI_ISA_ONLY_RANGES            (u8) 0x02
#define ACPI_LEVEL_SENSITIVE            (u8) 0x00
#define ACPI_MEMORY_RANGE               (u8) 0x00
#define ACPI_NEXT_RESOURCE(res) \
	ACPI_ADD_PTR (struct acpi_resource, (res), (res)->length)
#define ACPI_NON_CACHEABLE_MEMORY       (u8) 0x00
#define ACPI_NON_ISA_ONLY_RANGES        (u8) 0x01
#define ACPI_NOT_BUS_MASTER             (u8) 0x00
#define ACPI_NOT_WAKE_CAPABLE           (u8) 0x00
#define ACPI_PIN_CONFIG_BIAS_BUS_HOLD           6
#define ACPI_PIN_CONFIG_BIAS_DEFAULT            3
#define ACPI_PIN_CONFIG_BIAS_DISABLE            4
#define ACPI_PIN_CONFIG_BIAS_HIGH_IMPEDANCE     5
#define ACPI_PIN_CONFIG_BIAS_PULL_DOWN          2
#define ACPI_PIN_CONFIG_BIAS_PULL_UP            1
#define ACPI_PIN_CONFIG_DEFAULT                 0
#define ACPI_PIN_CONFIG_DRIVE_OPEN_DRAIN        7
#define ACPI_PIN_CONFIG_DRIVE_OPEN_SOURCE       8
#define ACPI_PIN_CONFIG_DRIVE_PUSH_PULL         9
#define ACPI_PIN_CONFIG_DRIVE_STRENGTH          10
#define ACPI_PIN_CONFIG_INPUT_DEBOUNCE          12
#define ACPI_PIN_CONFIG_INPUT_SCHMITT_TRIGGER   13
#define ACPI_PIN_CONFIG_NOPULL                  3
#define ACPI_PIN_CONFIG_PULLDOWN                2
#define ACPI_PIN_CONFIG_PULLUP                  1
#define ACPI_PIN_CONFIG_SLEW_RATE               11
#define ACPI_POS_DECODE                 (u8) 0x00
#define ACPI_PREFETCHABLE_MEMORY        (u8) 0x03
#define ACPI_PRODUCER                   (u8) 0x00
#define ACPI_READ_ONLY_MEMORY           (u8) 0x00
#define ACPI_READ_WRITE_MEMORY          (u8) 0x01
#define ACPI_RESOURCE_ADDRESS_COMMON \
	u8                                      resource_type; \
	u8                                      producer_consumer; \
	u8                                      decode; \
	u8                                      min_address_fixed; \
	u8                                      max_address_fixed; \
	union acpi_resource_attribute           info;
#define ACPI_RESOURCE_GPIO_TYPE_INT             0
#define ACPI_RESOURCE_GPIO_TYPE_IO              1
#define ACPI_RESOURCE_SERIAL_COMMON \
	u8                                      revision_id; \
	u8                                      type; \
	u8                                      producer_consumer;   \
	u8                                      slave_mode; \
	u8                                      connection_sharing; \
	u8                                      type_revision_id; \
	u16                                     type_data_length; \
	u16                                     vendor_length; \
	struct acpi_resource_source             resource_source; \
	u8                                      *vendor_data;
#define ACPI_RESOURCE_SERIAL_TYPE_I2C           1
#define ACPI_RESOURCE_SERIAL_TYPE_SPI           2
#define ACPI_RESOURCE_SERIAL_TYPE_UART          3
#define ACPI_RESOURCE_TYPE_ADDRESS16            11
#define ACPI_RESOURCE_TYPE_ADDRESS32            12
#define ACPI_RESOURCE_TYPE_ADDRESS64            13
#define ACPI_RESOURCE_TYPE_DMA                  1
#define ACPI_RESOURCE_TYPE_END_DEPENDENT        3
#define ACPI_RESOURCE_TYPE_END_TAG              7
#define ACPI_RESOURCE_TYPE_EXTENDED_ADDRESS64   14	
#define ACPI_RESOURCE_TYPE_EXTENDED_IRQ         15
#define ACPI_RESOURCE_TYPE_FIXED_DMA            18	
#define ACPI_RESOURCE_TYPE_FIXED_IO             5
#define ACPI_RESOURCE_TYPE_FIXED_MEMORY32       10
#define ACPI_RESOURCE_TYPE_GENERIC_REGISTER     16
#define ACPI_RESOURCE_TYPE_GPIO                 17	
#define ACPI_RESOURCE_TYPE_IO                   4
#define ACPI_RESOURCE_TYPE_IRQ                  0
#define ACPI_RESOURCE_TYPE_MAX                  24
#define ACPI_RESOURCE_TYPE_MEMORY24             8
#define ACPI_RESOURCE_TYPE_MEMORY32             9
#define ACPI_RESOURCE_TYPE_PIN_CONFIG           21	
#define ACPI_RESOURCE_TYPE_PIN_FUNCTION         20	
#define ACPI_RESOURCE_TYPE_PIN_GROUP            22	
#define ACPI_RESOURCE_TYPE_PIN_GROUP_CONFIG     24	
#define ACPI_RESOURCE_TYPE_PIN_GROUP_FUNCTION   23	
#define ACPI_RESOURCE_TYPE_SERIAL_BUS           19	
#define ACPI_RESOURCE_TYPE_START_DEPENDENT      2
#define ACPI_RESOURCE_TYPE_VENDOR               6
#define ACPI_RS_SIZE(type)                  (u32) (ACPI_RS_SIZE_NO_DATA + sizeof (type))
#define ACPI_RS_SIZE_MIN                    (u32) ACPI_ROUND_UP_TO_NATIVE_WORD (12)
#define ACPI_RS_SIZE_NO_DATA                8	
#define ACPI_SHARED                     (u8) 0x01
#define ACPI_SPARSE_TRANSLATION         (u8) 0x01
#define ACPI_SPI_3WIRE_MODE                     1
#define ACPI_SPI_4WIRE_MODE                     0
#define ACPI_SPI_ACTIVE_HIGH                    1
#define ACPI_SPI_ACTIVE_LOW                     0
#define ACPI_SPI_FIRST_PHASE                    0
#define ACPI_SPI_SECOND_PHASE                   1
#define ACPI_SPI_START_HIGH                     1
#define ACPI_SPI_START_LOW                      0
#define ACPI_SUB_DECODE                 (u8) 0x01
#define ACPI_SUB_OPTIMAL_CONFIGURATION  (u8) 0x02
#define ACPI_TRANSFER_16                (u8) 0x02
#define ACPI_TRANSFER_8                 (u8) 0x00
#define ACPI_TRANSFER_8_16              (u8) 0x01
#define ACPI_TYPE_A                     (u8) 0x01
#define ACPI_TYPE_B                     (u8) 0x02
#define ACPI_TYPE_F                     (u8) 0x03
#define ACPI_UART_1P5_STOP_BITS                 2
#define ACPI_UART_1_STOP_BIT                    1
#define ACPI_UART_2_STOP_BITS                   3
#define ACPI_UART_5_DATA_BITS                   0
#define ACPI_UART_6_DATA_BITS                   1
#define ACPI_UART_7_DATA_BITS                   2
#define ACPI_UART_8_DATA_BITS                   3
#define ACPI_UART_9_DATA_BITS                   4
#define ACPI_UART_BIG_ENDIAN                    1
#define ACPI_UART_CARRIER_DETECT                (1<<2)
#define ACPI_UART_CLEAR_TO_SEND                 (1<<6)
#define ACPI_UART_DATA_SET_READY                (1<<4)
#define ACPI_UART_DATA_TERMINAL_READY           (1<<5)
#define ACPI_UART_FLOW_CONTROL_HW               1
#define ACPI_UART_FLOW_CONTROL_NONE             0
#define ACPI_UART_FLOW_CONTROL_XON_XOFF         2
#define ACPI_UART_LITTLE_ENDIAN                 0
#define ACPI_UART_NO_STOP_BITS                  0
#define ACPI_UART_PARITY_EVEN                   1
#define ACPI_UART_PARITY_MARK                   3
#define ACPI_UART_PARITY_NONE                   0
#define ACPI_UART_PARITY_ODD                    2
#define ACPI_UART_PARITY_SPACE                  4
#define ACPI_UART_REQUEST_TO_SEND               (1<<7)
#define ACPI_UART_RING_INDICATOR                (1<<3)
#define ACPI_WAKE_CAPABLE               (u8) 0x01
#define ACPI_WRITE_COMBINING_MEMORY     (u8) 0x02

#define ACPI_AML_EXCEPTION(status)      (status & AE_CODE_AML)
#define ACPI_CNTL_EXCEPTION(status)     (status & AE_CODE_CONTROL)
#define ACPI_ENV_EXCEPTION(status)      (status & AE_CODE_ENVIRONMENTAL)
#define ACPI_FAILURE(a)                 (a)
#define ACPI_PROG_EXCEPTION(status)     (status & AE_CODE_PROGRAMMER)
#define ACPI_SUCCESS(a)                 (!(a))
#define ACPI_TABLE_EXCEPTION(status)    (status & AE_CODE_ACPI_TABLES)
#define AE_ABORT_METHOD                 EXCEP_ENV (0x0018)
#define AE_ACCESS                       EXCEP_ENV (0x001D)
#define AE_ACQUIRE_DEADLOCK             EXCEP_ENV (0x0012)
#define AE_ALREADY_ACQUIRED             EXCEP_ENV (0x0015)
#define AE_ALREADY_EXISTS               EXCEP_ENV (0x0007)
#define AE_AML_ALIGNMENT                EXCEP_AML (0x001B)
#define AE_AML_BAD_NAME                 EXCEP_AML (0x000D)
#define AE_AML_BAD_OPCODE               EXCEP_AML (0x0001)
#define AE_AML_BAD_RESOURCE_LENGTH      EXCEP_AML (0x001F)
#define AE_AML_BAD_RESOURCE_VALUE       EXCEP_AML (0x001D)
#define AE_AML_BUFFER_LENGTH            EXCEP_AML (0x0025)
#define AE_AML_BUFFER_LIMIT             EXCEP_AML (0x000A)
#define AE_AML_CIRCULAR_REFERENCE       EXCEP_AML (0x001E)
#define AE_AML_DIVIDE_BY_ZERO           EXCEP_AML (0x000C)
#define AE_AML_ILLEGAL_ADDRESS          EXCEP_AML (0x0020)
#define AE_AML_INTERNAL                 EXCEP_AML (0x000F)
#define AE_AML_INVALID_INDEX            EXCEP_AML (0x0018)
#define AE_AML_INVALID_RESOURCE_TYPE    EXCEP_AML (0x0017)
#define AE_AML_INVALID_SPACE_ID         EXCEP_AML (0x0010)
#define AE_AML_LOOP_TIMEOUT             EXCEP_AML (0x0021)
#define AE_AML_METHOD_LIMIT             EXCEP_AML (0x0013)
#define AE_AML_MUTEX_NOT_ACQUIRED       EXCEP_AML (0x0016)
#define AE_AML_MUTEX_ORDER              EXCEP_AML (0x0015)
#define AE_AML_NAME_NOT_FOUND           EXCEP_AML (0x000E)
#define AE_AML_NOT_OWNER                EXCEP_AML (0x0014)
#define AE_AML_NO_OPERAND               EXCEP_AML (0x0002)
#define AE_AML_NO_RESOURCE_END_TAG      EXCEP_AML (0x001C)
#define AE_AML_NO_RETURN_VALUE          EXCEP_AML (0x0012)
#define AE_AML_NO_WHILE                 EXCEP_AML (0x001A)
#define AE_AML_NUMERIC_OVERFLOW         EXCEP_AML (0x0008)
#define AE_AML_OPERAND_TYPE             EXCEP_AML (0x0003)
#define AE_AML_OPERAND_VALUE            EXCEP_AML (0x0004)
#define AE_AML_PACKAGE_LIMIT            EXCEP_AML (0x000B)
#define AE_AML_PROTOCOL                 EXCEP_AML (0x0024)
#define AE_AML_REGION_LIMIT             EXCEP_AML (0x0009)
#define AE_AML_REGISTER_LIMIT           EXCEP_AML (0x0019)
#define AE_AML_STRING_LIMIT             EXCEP_AML (0x0011)
#define AE_AML_TARGET_TYPE              EXCEP_AML (0x0023)
#define AE_AML_UNINITIALIZED_ARG        EXCEP_AML (0x0006)
#define AE_AML_UNINITIALIZED_ELEMENT    EXCEP_AML (0x0007)
#define AE_AML_UNINITIALIZED_LOCAL      EXCEP_AML (0x0005)
#define AE_AML_UNINITIALIZED_NODE       EXCEP_AML (0x0022)
#define AE_BAD_ADDRESS                  EXCEP_PGM (0x0009)
#define AE_BAD_CHARACTER                EXCEP_PGM (0x0002)
#define AE_BAD_CHECKSUM                 EXCEP_TBL (0x0003)
#define AE_BAD_DATA                     EXCEP_PGM (0x0004)
#define AE_BAD_DECIMAL_CONSTANT         EXCEP_PGM (0x0007)
#define AE_BAD_HEADER                   EXCEP_TBL (0x0002)
#define AE_BAD_HEX_CONSTANT             EXCEP_PGM (0x0005)
#define AE_BAD_OCTAL_CONSTANT           EXCEP_PGM (0x0006)
#define AE_BAD_PARAMETER                EXCEP_PGM (0x0001)
#define AE_BAD_PATHNAME                 EXCEP_PGM (0x0003)
#define AE_BAD_SIGNATURE                EXCEP_TBL (0x0001)
#define AE_BAD_VALUE                    EXCEP_TBL (0x0004)
#define AE_BUFFER_OVERFLOW              EXCEP_ENV (0x000B)
#define AE_CODE_ACPI_TABLES             0x2000	
#define AE_CODE_AML                     0x3000	
#define AE_CODE_AML_MAX                 0x0025
#define AE_CODE_CONTROL                 0x4000	
#define AE_CODE_CTRL_MAX                0x000C
#define AE_CODE_ENVIRONMENTAL           0x0000	
#define AE_CODE_ENV_MAX                 0x0023
#define AE_CODE_MASK                    0xF000
#define AE_CODE_MAX                     0x4000
#define AE_CODE_PGM_MAX                 0x0009
#define AE_CODE_PROGRAMMER              0x1000	
#define AE_CODE_TBL_MAX                 0x0005
#define AE_CTRL_BREAK                   EXCEP_CTL (0x0009)
#define AE_CTRL_CONTINUE                EXCEP_CTL (0x000A)
#define AE_CTRL_DEPTH                   EXCEP_CTL (0x0006)
#define AE_CTRL_END                     EXCEP_CTL (0x0007)
#define AE_CTRL_FALSE                   EXCEP_CTL (0x0005)
#define AE_CTRL_PARSE_CONTINUE          EXCEP_CTL (0x000B)
#define AE_CTRL_PARSE_PENDING           EXCEP_CTL (0x000C)
#define AE_CTRL_PENDING                 EXCEP_CTL (0x0002)
#define AE_CTRL_RETURN_VALUE            EXCEP_CTL (0x0001)
#define AE_CTRL_TERMINATE               EXCEP_CTL (0x0003)
#define AE_CTRL_TRANSFER                EXCEP_CTL (0x0008)
#define AE_CTRL_TRUE                    EXCEP_CTL (0x0004)
#define AE_DECIMAL_OVERFLOW             EXCEP_ENV (0x0021)
#define AE_END_OF_TABLE                 EXCEP_ENV (0x0023)
#define AE_ERROR                        EXCEP_ENV (0x0001)
#define AE_HEX_OVERFLOW                 EXCEP_ENV (0x0020)
#define AE_INVALID_TABLE_LENGTH         EXCEP_TBL (0x0005)
#define AE_IO_ERROR                     EXCEP_ENV (0x001E)
#define AE_LIMIT                        EXCEP_ENV (0x0010)
#define AE_MISSING_ARGUMENTS            EXCEP_PGM (0x0008)
#define AE_NOT_ACQUIRED                 EXCEP_ENV (0x0014)
#define AE_NOT_CONFIGURED               EXCEP_ENV (0x001C)
#define AE_NOT_EXIST                    EXCEP_ENV (0x0006)
#define AE_NOT_FOUND                    EXCEP_ENV (0x0005)
#define AE_NOT_IMPLEMENTED              EXCEP_ENV (0x000E)
#define AE_NO_ACPI_TABLES               EXCEP_ENV (0x0002)
#define AE_NO_GLOBAL_LOCK               EXCEP_ENV (0x0017)
#define AE_NO_HANDLER                   EXCEP_ENV (0x001A)
#define AE_NO_HARDWARE_RESPONSE         EXCEP_ENV (0x0016)
#define AE_NO_MEMORY                    EXCEP_ENV (0x0004)
#define AE_NO_NAMESPACE                 EXCEP_ENV (0x0003)
#define AE_NULL_ENTRY                   EXCEP_ENV (0x000A)
#define AE_NULL_OBJECT                  EXCEP_ENV (0x0009)
#define AE_NUMERIC_OVERFLOW             EXCEP_ENV (0x001F)
#define AE_OCTAL_OVERFLOW               EXCEP_ENV (0x0022)
#define AE_OK                           (acpi_status) 0x0000
#define AE_OWNER_ID_LIMIT               EXCEP_ENV (0x001B)
#define AE_RELEASE_DEADLOCK             EXCEP_ENV (0x0013)
#define AE_SAME_HANDLER                 EXCEP_ENV (0x0019)
#define AE_STACK_OVERFLOW               EXCEP_ENV (0x000C)
#define AE_STACK_UNDERFLOW              EXCEP_ENV (0x000D)
#define AE_SUPPORT                      EXCEP_ENV (0x000F)
#define AE_TIME                         EXCEP_ENV (0x0011)
#define AE_TYPE                         EXCEP_ENV (0x0008)
#define EXCEP_AML(code)                 ((acpi_status) (code | AE_CODE_AML))
#define EXCEP_CTL(code)                 ((acpi_status) (code | AE_CODE_CONTROL))
#define EXCEP_ENV(code)                 ((acpi_status) (code | AE_CODE_ENVIRONMENTAL))
#define EXCEP_PGM(code)                 ((acpi_status) (code | AE_CODE_PROGRAMMER))
#define EXCEP_TBL(code)                 ((acpi_status) (code | AE_CODE_ACPI_TABLES))
#define EXCEP_TXT(name,description)     {name, description}

#define ACPI_NAMESPACE_ROOT     "Namespace Root"
#define ACPI_NS_ROOT_PATH       "\\"
#define ACPI_PREFIX_LOWER       (u32) 0x69706361	
#define ACPI_PREFIX_MIXED       (u32) 0x69706341	
#define ACPI_ROOT_NAME          (u32) 0x5F5F5F5C	
#define ACPI_ROOT_PATHNAME      "\\___"
#define ACPI_UNKNOWN_NAME       (u32) 0x3F3F3F3F	
#define METHOD_NAME__ADR        "_ADR"
#define METHOD_NAME__AEI        "_AEI"
#define METHOD_NAME__BBN        "_BBN"
#define METHOD_NAME__CBA        "_CBA"
#define METHOD_NAME__CID        "_CID"
#define METHOD_NAME__CLS        "_CLS"
#define METHOD_NAME__CRS        "_CRS"
#define METHOD_NAME__DDN        "_DDN"
#define METHOD_NAME__DMA        "_DMA"
#define METHOD_NAME__DSD        "_DSD"
#define METHOD_NAME__HID        "_HID"
#define METHOD_NAME__INI        "_INI"
#define METHOD_NAME__PLD        "_PLD"
#define METHOD_NAME__PRS        "_PRS"
#define METHOD_NAME__PRT        "_PRT"
#define METHOD_NAME__PRW        "_PRW"
#define METHOD_NAME__PS0        "_PS0"
#define METHOD_NAME__PS1        "_PS1"
#define METHOD_NAME__PS2        "_PS2"
#define METHOD_NAME__PS3        "_PS3"
#define METHOD_NAME__REG        "_REG"
#define METHOD_NAME__SB_        "_SB_"
#define METHOD_NAME__SEG        "_SEG"
#define METHOD_NAME__SRS        "_SRS"
#define METHOD_NAME__STA        "_STA"
#define METHOD_NAME__SUB        "_SUB"
#define METHOD_NAME__UID        "_UID"
#define METHOD_PATHNAME__PTS    "\\_PTS"
#define METHOD_PATHNAME__SST    "\\_SI._SST"
#define METHOD_PATHNAME__WAK    "\\_WAK"


#define resource_list_for_each_entry(entry, list)	\
	list_for_each_entry((entry), (list), node)
#define resource_list_for_each_entry_safe(entry, tmp, list)	\
	list_for_each_entry_safe((entry), (tmp), (list), node)


#define v4l2_ctrl_handler_init(hdl, nr_of_controls_hint)		\
(									\
	({								\
		static struct lock_class_key _key;			\
		v4l2_ctrl_handler_init_class(hdl, nr_of_controls_hint,	\
					&_key,				\
					KBUILD_BASENAME ":"		\
					__stringify("__LINE__") ":"	\
					"(" #hdl ")->_lock");		\
	})								\
)
#define V4L2_CTRL_TYPE_HEVC_PPS 0x0121
#define V4L2_CTRL_TYPE_HEVC_SLICE_PARAMS 0x0122
#define V4L2_CTRL_TYPE_HEVC_SPS 0x0120
#define V4L2_HEVC_PPS_FLAG_PPS_LOOP_FILTER_ACROSS_SLICES_ENABLED (1ULL << 14)
#define V4L2_HEVC_PPS_FLAG_SLICE_SEGMENT_HEADER_EXTENSION_PRESENT (1ULL << 18)
#define V4L2_HEVC_SLICE_PARAMS_FLAG_SLICE_DEBLOCKING_FILTER_DISABLED (1ULL << 7)
#define V4L2_HEVC_SLICE_PARAMS_FLAG_SLICE_LOOP_FILTER_ACROSS_SLICES_ENABLED (1ULL << 8)
#define V4L2_PIX_FMT_HEVC_SLICE v4l2_fourcc('S', '2', '6', '5') 

#define V4L2_CID_MPEG_VIDEO_VP8_FRAME_HEADER (V4L2_CID_MPEG_BASE + 2000)
#define V4L2_CTRL_TYPE_VP8_FRAME_HEADER 0x301
#define V4L2_PIX_FMT_VP8_FRAME v4l2_fourcc('V', 'P', '8', 'F')
#define V4L2_VP8_SEGMENT_HEADER_FLAG_DELTA_VALUE_MODE     0x08
#define V4L2_VP8_SEGMENT_HEADER_FLAG_ENABLED              0x01
#define V4L2_VP8_SEGMENT_HEADER_FLAG_UPDATE_FEATURE_DATA  0x04
#define V4L2_VP8_SEGMENT_HEADER_FLAG_UPDATE_MAP           0x02
#define VP8_FRAME_IS_KEY_FRAME(hdr) \
	(!!((hdr)->flags & V4L2_VP8_FRAME_HEADER_FLAG_KEY_FRAME))

#define V4L2_PIX_FMT_H264_SLICE v4l2_fourcc('S', '2', '6', '4') 

#define V4L2_CTRL_TYPE_FWHT_PARAMS 0x0105

#define V4L2_CTRL_TYPE_MPEG2_SLICE_PARAMS 0x0103

#define USB_DEVICE(vend, prod) \
	.match_flags = USB_DEVICE_ID_MATCH_DEVICE, \
	.idVendor = (vend), \
	.idProduct = (prod)
#define USB_DEVICE_AND_INTERFACE_INFO(vend, prod, cl, sc, pr) \
	.match_flags = USB_DEVICE_ID_MATCH_INT_INFO \
		| USB_DEVICE_ID_MATCH_DEVICE, \
	.idVendor = (vend), \
	.idProduct = (prod), \
	.bInterfaceClass = (cl), \
	.bInterfaceSubClass = (sc), \
	.bInterfaceProtocol = (pr)
#define USB_DEVICE_ID_MATCH_DEVICE \
		(USB_DEVICE_ID_MATCH_VENDOR | USB_DEVICE_ID_MATCH_PRODUCT)
#define USB_DEVICE_ID_MATCH_DEVICE_AND_VERSION \
		(USB_DEVICE_ID_MATCH_DEVICE | USB_DEVICE_ID_MATCH_DEV_RANGE)
#define USB_DEVICE_ID_MATCH_DEV_INFO \
		(USB_DEVICE_ID_MATCH_DEV_CLASS | \
		USB_DEVICE_ID_MATCH_DEV_SUBCLASS | \
		USB_DEVICE_ID_MATCH_DEV_PROTOCOL)
#define USB_DEVICE_ID_MATCH_DEV_RANGE \
		(USB_DEVICE_ID_MATCH_DEV_LO | USB_DEVICE_ID_MATCH_DEV_HI)
#define USB_DEVICE_ID_MATCH_INT_INFO \
		(USB_DEVICE_ID_MATCH_INT_CLASS | \
		USB_DEVICE_ID_MATCH_INT_SUBCLASS | \
		USB_DEVICE_ID_MATCH_INT_PROTOCOL)
#define USB_DEVICE_INFO(cl, sc, pr) \
	.match_flags = USB_DEVICE_ID_MATCH_DEV_INFO, \
	.bDeviceClass = (cl), \
	.bDeviceSubClass = (sc), \
	.bDeviceProtocol = (pr)
#define USB_DEVICE_INTERFACE_CLASS(vend, prod, cl) \
	.match_flags = USB_DEVICE_ID_MATCH_DEVICE | \
		       USB_DEVICE_ID_MATCH_INT_CLASS, \
	.idVendor = (vend), \
	.idProduct = (prod), \
	.bInterfaceClass = (cl)
#define USB_DEVICE_INTERFACE_NUMBER(vend, prod, num) \
	.match_flags = USB_DEVICE_ID_MATCH_DEVICE | \
		       USB_DEVICE_ID_MATCH_INT_NUMBER, \
	.idVendor = (vend), \
	.idProduct = (prod), \
	.bInterfaceNumber = (num)
#define USB_DEVICE_INTERFACE_PROTOCOL(vend, prod, pr) \
	.match_flags = USB_DEVICE_ID_MATCH_DEVICE | \
		       USB_DEVICE_ID_MATCH_INT_PROTOCOL, \
	.idVendor = (vend), \
	.idProduct = (prod), \
	.bInterfaceProtocol = (pr)
#define USB_DEVICE_VER(vend, prod, lo, hi) \
	.match_flags = USB_DEVICE_ID_MATCH_DEVICE_AND_VERSION, \
	.idVendor = (vend), \
	.idProduct = (prod), \
	.bcdDevice_lo = (lo), \
	.bcdDevice_hi = (hi)
#define USB_INTERFACE_INFO(cl, sc, pr) \
	.match_flags = USB_DEVICE_ID_MATCH_INT_INFO, \
	.bInterfaceClass = (cl), \
	.bInterfaceSubClass = (sc), \
	.bInterfaceProtocol = (pr)
#define USB_VENDOR_AND_INTERFACE_INFO(vend, cl, sc, pr) \
	.match_flags = USB_DEVICE_ID_MATCH_INT_INFO \
		| USB_DEVICE_ID_MATCH_VENDOR, \
	.idVendor = (vend), \
	.bInterfaceClass = (cl), \
	.bInterfaceSubClass = (sc), \
	.bInterfaceProtocol = (pr)

#define module_usb_driver(__usb_driver) \
	module_driver(__usb_driver, usb_register, \
		       usb_deregister)
#define usb_get_extra_descriptor(ifpoint, type, ptr) \
				__usb_get_extra_descriptor((ifpoint)->extra, \
				(ifpoint)->extralen, \
				type, (void **)ptr, sizeof(**(ptr)))
#define usb_hub_for_each_child(hdev, port1, child) \
	for (port1 = 1,	child =	usb_hub_find_child(hdev, port1); \
			port1 <= hdev->maxchild; \
			child = usb_hub_find_child(hdev, ++port1)) \
		if (!child) continue; else
#define usb_lock_device(udev)			device_lock(&(udev)->dev)
#define usb_lock_device_interruptible(udev)	device_lock_interruptible(&(udev)->dev)
#define usb_pipebulk(pipe)	(usb_pipetype((pipe)) == PIPE_BULK)
#define usb_pipecontrol(pipe)	(usb_pipetype((pipe)) == PIPE_CONTROL)
#define usb_pipedevice(pipe)	(((pipe) >> 8) & 0x7f)
#define usb_pipeendpoint(pipe)	(((pipe) >> 15) & 0xf)
#define usb_pipein(pipe)	((pipe) & USB_DIR_IN)
#define usb_pipeint(pipe)	(usb_pipetype((pipe)) == PIPE_INTERRUPT)
#define usb_pipeisoc(pipe)	(usb_pipetype((pipe)) == PIPE_ISOCHRONOUS)
#define usb_pipeout(pipe)	(!usb_pipein(pipe))
#define usb_pipetype(pipe)	(((pipe) >> 30) & 3)
#define usb_put_urb usb_free_urb
#define usb_rcvbulkpipe(dev, endpoint)	\
	((PIPE_BULK << 30) | __create_pipe(dev, endpoint) | USB_DIR_IN)
#define usb_rcvctrlpipe(dev, endpoint)	\
	((PIPE_CONTROL << 30) | __create_pipe(dev, endpoint) | USB_DIR_IN)
#define usb_rcvintpipe(dev, endpoint)	\
	((PIPE_INTERRUPT << 30) | __create_pipe(dev, endpoint) | USB_DIR_IN)
#define usb_rcvisocpipe(dev, endpoint)	\
	((PIPE_ISOCHRONOUS << 30) | __create_pipe(dev, endpoint) | USB_DIR_IN)
#define usb_register(driver) \
	usb_register_driver(driver, THIS_MODULE, KBUILD_MODNAME)
#define usb_sndbulkpipe(dev, endpoint)	\
	((PIPE_BULK << 30) | __create_pipe(dev, endpoint))
#define usb_sndctrlpipe(dev, endpoint)	\
	((PIPE_CONTROL << 30) | __create_pipe(dev, endpoint))
#define usb_sndintpipe(dev, endpoint)	\
	((PIPE_INTERRUPT << 30) | __create_pipe(dev, endpoint))
#define usb_sndisocpipe(dev, endpoint)	\
	((PIPE_ISOCHRONOUS << 30) | __create_pipe(dev, endpoint))
#define usb_trylock_device(udev)		device_trylock(&(udev)->dev)
#define usb_unlock_device(udev)			device_unlock(&(udev)->dev)

#define DECLARE_TASKLET(name, func, data) \
struct tasklet_struct name = { NULL, 0, ATOMIC_INIT(0), func, data }
#define DECLARE_TASKLET_DISABLED(name, func, data) \
struct tasklet_struct name = { NULL, 0, ATOMIC_INIT(1), func, data }
#define IRQF_TIMER		(__IRQF_TIMER | IRQF_NO_SUSPEND | IRQF_NO_THREAD)
#define SOFTIRQ_STOP_IDLE_MASK (~(1 << RCU_SOFTIRQ))

#define __softirq_entry  \
	__attribute__((__section__(".softirqentry.text")))
#define hard_irq_disable()	do { } while(0)
# define local_irq_enable_in_hardirq()	do { } while (0)
#define local_softirq_pending_ref irq_stat.__softirq_pending
#define or_softirq_pending(x)	(__this_cpu_or(local_softirq_pending_ref, (x)))
#define set_softirq_pending(x)	(__this_cpu_write(local_softirq_pending_ref, (x)))
#define tasklet_trylock(t) 1
#define tasklet_unlock(t) do { } while (0)
#define tasklet_unlock_wait(t) do { } while (0)

#define __irq_enter()					\
	do {						\
		account_irq_enter_time(current);	\
		preempt_count_add(HARDIRQ_OFFSET);	\
		trace_hardirq_enter();			\
	} while (0)
#define __irq_exit()					\
	do {						\
		trace_hardirq_exit();			\
		account_irq_exit_time(current);		\
		preempt_count_sub(HARDIRQ_OFFSET);	\
	} while (0)
#define arch_nmi_enter()	do { } while (0)
#define arch_nmi_exit()		do { } while (0)
#define nmi_enter()						\
	do {							\
		arch_nmi_enter();				\
		printk_nmi_enter();				\
		lockdep_off();					\
		ftrace_nmi_enter();				\
		BUG_ON(in_nmi());				\
		preempt_count_add(NMI_OFFSET + HARDIRQ_OFFSET);	\
		rcu_nmi_enter();				\
		trace_hardirq_enter();				\
	} while (0)
#define nmi_exit()						\
	do {							\
		trace_hardirq_exit();				\
		rcu_nmi_exit();					\
		BUG_ON(!in_nmi());				\
		preempt_count_sub(NMI_OFFSET + HARDIRQ_OFFSET);	\
		ftrace_nmi_exit();				\
		lockdep_on();					\
		printk_nmi_exit();				\
		arch_nmi_exit();				\
	} while (0)




# define for_each_active_irq(irq)			\
	for (irq = irq_get_next_irq(0); irq < nr_irqs;	\
	     irq = irq_get_next_irq(irq + 1))
# define for_each_irq_desc(irq, desc)					\
	for (irq = 0, desc = irq_to_desc(irq); irq < nr_irqs;		\
	     irq++, desc = irq_to_desc(irq))				\
		if (!desc)						\
			;						\
		else
# define for_each_irq_desc_reverse(irq, desc)				\
	for (irq = nr_irqs - 1, desc = irq_to_desc(irq); irq >= 0;	\
	     irq--, desc = irq_to_desc(irq))				\
		if (!desc)						\
			;						\
		else
#define for_each_irq_nr(irq)                   \
       for (irq = 0; irq < nr_irqs; irq++)
#define IRQ_RETVAL(x)	((x) ? IRQ_HANDLED : IRQ_NONE)


#define mdelay(n) (\
	(__builtin_constant_p(n) && (n)<=MAX_UDELAY_MS) ? udelay((n)*1000) : \
	({unsigned long __ms=(n); while (__ms--) udelay(1000);}))
#define ndelay(x) ndelay(x)

#define USB_DT_USB_SSP_CAP_SIZE(ssac)	(12 + (ssac + 1) * 4)
#define USB_EP_MAXP_MULT(m) \
	(((m) & USB_EP_MAXP_MULT_MASK) >> USB_EP_MAXP_MULT_SHIFT)
#define USB_GET_BESL_BASELINE(p)	(((p) & (0xf << 8)) >> 8)
#define USB_GET_BESL_DEEP(p)		(((p) & (0xf << 12)) >> 12)
#define USB_INTRF_STAT_FUNC_RW         2
#define USB_INTRF_STAT_FUNC_RW_CAP     1
#define USB_PD_CAP_CONSUMER_UNKNOWN_PEAK_POWER_TIME 0xffff
#define USB_SET_BESL_BASELINE(p)	(((p) & 0xf) << 8)
#define USB_SET_BESL_DEEP(p)		(((p) & 0xf) << 12)
#define USB_SS_MULT(p)			(1 + ((p) & 0x3))
#define USB_SS_SSP_ISOC_COMP(p)		((p) & (1 << 7))

#define INPUT_DEVICE_ID_MATCH_DEVICE \
	(INPUT_DEVICE_ID_MATCH_BUS | INPUT_DEVICE_ID_MATCH_VENDOR | INPUT_DEVICE_ID_MATCH_PRODUCT)
#define INPUT_DEVICE_ID_MATCH_DEVICE_AND_VERSION \
	(INPUT_DEVICE_ID_MATCH_DEVICE | INPUT_DEVICE_ID_MATCH_VERSION)
#define INPUT_GENERATE_ABS_ACCESSORS(_suffix, _item)			\
static inline int input_abs_get_##_suffix(struct input_dev *dev,	\
					  unsigned int axis)		\
{									\
	return dev->absinfo ? dev->absinfo[axis]._item : 0;		\
}									\
									\
static inline void input_abs_set_##_suffix(struct input_dev *dev,	\
					   unsigned int axis, int val)	\
{									\
	input_alloc_absinfo(dev);					\
	if (dev->absinfo)						\
		dev->absinfo[axis]._item = val;				\
}

#define to_input_dev(d) container_of(d, struct input_dev, dev)
#define EVIOCGABS(abs)		_IOR('E', 0x40 + (abs), struct input_absinfo)	
#define EVIOCGBIT(ev,len)	_IOC(_IOC_READ, 'E', 0x20 + (ev), len)	
#define EVIOCGKEY(len)		_IOC(_IOC_READ, 'E', 0x18, len)		
#define EVIOCGLED(len)		_IOC(_IOC_READ, 'E', 0x19, len)		
#define EVIOCGMTSLOTS(len)	_IOC(_IOC_READ, 'E', 0x0a, len)
#define EVIOCGNAME(len)		_IOC(_IOC_READ, 'E', 0x06, len)		
#define EVIOCGPHYS(len)		_IOC(_IOC_READ, 'E', 0x07, len)		
#define EVIOCGPROP(len)		_IOC(_IOC_READ, 'E', 0x09, len)		
#define EVIOCGSND(len)		_IOC(_IOC_READ, 'E', 0x1a, len)		
#define EVIOCGSW(len)		_IOC(_IOC_READ, 'E', 0x1b, len)		
#define EVIOCGUNIQ(len)		_IOC(_IOC_READ, 'E', 0x08, len)		
#define EVIOCSABS(abs)		_IOW('E', 0xc0 + (abs), struct input_absinfo)	

#define input_event_sec time.tv_sec
#define input_event_usec time.tv_usec
