


#include<linux/errno.h>
#include<asm/resource.h>
#include<asm/sembuf.h>





#include<asm/types.h>




#include<linux/stat.h>




#include<linux/limits.h>



#include<asm/shmbuf.h>
#include<linux/stddef.h>
#include<linux/sched.h>















#include<linux/ipc.h>




#include<stdarg.h>







#include<asm/ipcbuf.h>



#include<linux/param.h>





#include<linux/types.h>




#include<linux/ioctl.h>









#include<asm/ptrace.h>




#include<asm/siginfo.h>
#include<asm-generic/hugetlb_encode.h>

#include<linux/const.h>








#include<linux/fiemap.h>
#include<linux/string.h>


#include<linux/kernel.h>





#include<linux/time.h>
#include<asm/errno.h>
#include<linux/dqblk_xfs.h>

#include<linux/resource.h>



#include<asm/byteorder.h>








#include<asm/auxvec.h>

#include<linux/kvm.h>


#include<string.h>
#include<asm/stat.h>


#include<linux/sysinfo.h>
#include<linux/posix_types.h>
#include<asm/param.h>

#include<asm/fcntl.h>
#include<asm/kvm_para.h>






#include<linux/uuid.h>

#include<linux/wait.h>


#include<unistd.h>

#include<asm/signal.h>
#include<linux/timex.h>



#define fixed_ctrl_field(ctrl_reg, idx) (((ctrl_reg) >> ((idx)*4)) & 0xf)
#define pmc_to_pmu(pmc)   (&(pmc)->vcpu->arch.pmu)
#define pmu_to_vcpu(pmu)  (container_of((pmu), struct kvm_vcpu, arch.pmu))
#define vcpu_to_pmu(vcpu) (&(vcpu)->arch.pmu)
#define PT32E_ROOT_LEVEL 3
#define PT32_DIR_PSE36_MASK \
	(((1ULL << PT32_DIR_PSE36_SIZE) - 1) << PT32_DIR_PSE36_SHIFT)
#define PT32_DIR_PSE36_SHIFT 13
#define PT32_DIR_PSE36_SIZE 4
#define PT32_ENT_PER_PAGE (1 << PT32_PT_BITS)
#define PT32_PT_BITS 10
#define PT32_ROOT_LEVEL 2
#define PT64_ENT_PER_PAGE (1 << PT64_PT_BITS)
#define PT64_NX_MASK (1ULL << PT64_NX_SHIFT)
#define PT64_NX_SHIFT 63
#define PT64_PT_BITS 9
#define PT64_ROOT_4LEVEL 4
#define PT64_ROOT_5LEVEL 5
#define PT_ACCESSED_MASK (1ULL << PT_ACCESSED_SHIFT)
#define PT_ACCESSED_SHIFT 5
#define PT_DIRECTORY_LEVEL 2
#define PT_DIRTY_MASK (1ULL << PT_DIRTY_SHIFT)
#define PT_DIRTY_SHIFT 6
#define PT_DIR_PAT_MASK (1ULL << PT_DIR_PAT_SHIFT)
#define PT_DIR_PAT_SHIFT 12
#define PT_GLOBAL_MASK (1ULL << 8)
#define PT_MAX_HUGEPAGE_LEVEL (PT_PAGE_TABLE_LEVEL + KVM_NR_PAGE_SIZES - 1)
#define PT_PAGE_SIZE_MASK (1ULL << PT_PAGE_SIZE_SHIFT)
#define PT_PAGE_SIZE_SHIFT 7
#define PT_PAGE_TABLE_LEVEL 1
#define PT_PAT_MASK (1ULL << 7)
#define PT_PAT_SHIFT 7
#define PT_PCD_MASK (1ULL << 4)
#define PT_PDPE_LEVEL 3
#define PT_PRESENT_MASK (1ULL << 0)
#define PT_PWT_MASK (1ULL << 3)
#define PT_USER_MASK (1ULL << PT_USER_SHIFT)
#define PT_USER_SHIFT 2
#define PT_WRITABLE_MASK (1ULL << PT_WRITABLE_SHIFT)
#define PT_WRITABLE_SHIFT 1


#define KVM_POSSIBLE_CR0_GUEST_BITS X86_CR0_TS
#define KVM_ARCH_REQ(nr)           KVM_ARCH_REQ_FLAGS(nr, 0)
#define KVM_ARCH_REQ_FLAGS(nr, flags) ({ \
	BUILD_BUG_ON((unsigned)(nr) >= 32 - KVM_REQUEST_ARCH_BASE); \
	(unsigned)(((nr) + KVM_REQUEST_ARCH_BASE) | (flags)); \
})
#define KVM_MAX_IRQ_ROUTES 4096 
#define KVM_MAX_VCPU_ID KVM_MAX_VCPUS
#define KVM_MEM_MAX_NR_PAGES ((1UL << 31) - 1)
#define KVM_MEM_SLOTS_NUM (KVM_USER_MEM_SLOTS + KVM_PRIVATE_MEM_SLOTS)
#define KVM_PRIVATE_MEM_SLOTS 0
#define KVM_REQUEST_ARCH_BASE     8
#define KVM_REQUEST_MASK           GENMASK(7,0)
#define KVM_REQUEST_NO_WAKEUP      BIT(8)
#define KVM_REQUEST_WAIT           BIT(9)
#define KVM_REQ_MMU_RELOAD        (1 | KVM_REQUEST_WAIT | KVM_REQUEST_NO_WAKEUP)
#define KVM_REQ_PENDING_TIMER     2
#define KVM_REQ_TLB_FLUSH         (0 | KVM_REQUEST_WAIT | KVM_REQUEST_NO_WAKEUP)
#define KVM_REQ_UNHALT            3
#define NR_IOBUS_DEVS 1000

#define kvm_debug(fmt, ...) \
	pr_debug("kvm [%i]: " fmt, task_pid_nr(current), ## __VA_ARGS__)
#define kvm_debug_ratelimited(fmt, ...) \
	pr_debug_ratelimited("kvm [%i]: " fmt, task_pid_nr(current), \
			     ## __VA_ARGS__)
#define kvm_err(fmt, ...) \
	pr_err("kvm [%i]: " fmt, task_pid_nr(current), ## __VA_ARGS__)
#define kvm_for_each_memslot(memslot, slots)	\
	for (memslot = &slots->memslots[0];	\
	      memslot < slots->memslots + KVM_MEM_SLOTS_NUM && memslot->npages;\
		memslot++)
#define kvm_for_each_vcpu(idx, vcpup, kvm) \
	for (idx = 0; \
	     idx < atomic_read(&kvm->online_vcpus) && \
	     (vcpup = kvm_get_vcpu(kvm, idx)) != NULL; \
	     idx++)
#define kvm_info(fmt, ...) \
	pr_info("kvm [%i]: " fmt, task_pid_nr(current), ## __VA_ARGS__)
#define kvm_pr_unimpl(fmt, ...) \
	pr_err_ratelimited("kvm [%i]: " fmt, \
			   task_tgid_nr(current), ## __VA_ARGS__)
#define vcpu_debug(vcpu, fmt, ...)					\
	kvm_debug("vcpu%i " fmt, (vcpu)->vcpu_id, ## __VA_ARGS__)
#define vcpu_debug_ratelimited(vcpu, fmt, ...)				\
	kvm_debug_ratelimited("vcpu%i " fmt, (vcpu)->vcpu_id,           \
			      ## __VA_ARGS__)
#define vcpu_err(vcpu, fmt, ...)					\
	kvm_err("vcpu%i " fmt, (vcpu)->vcpu_id, ## __VA_ARGS__)
#define vcpu_unimpl(vcpu, fmt, ...)					\
	kvm_pr_unimpl("vcpu%i, guest rIP: 0x%lx " fmt,			\
			(vcpu)->vcpu_id, kvm_rip_read(vcpu), ## __VA_ARGS__)



#define REFCOUNT_INIT(n)	{ .refs = ATOMIC_INIT(n), }

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
#define DIV_ROUND_UP_ULL(ll, d)		DIV_ROUND_DOWN_ULL((ll) + (d) - 1, (d))
#define FIELD_SIZEOF(t, f) (sizeof(((t*)0)->f))
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
#define abs(x)	__abs_choose_expr(x, long long,				\
		__abs_choose_expr(x, long,				\
		__abs_choose_expr(x, int,				\
		__abs_choose_expr(x, short,				\
		__abs_choose_expr(x, char,				\
		__builtin_choose_expr(					\
			__builtin_types_compatible_p(typeof(x), char),	\
			(char)({ signed char __x = (x); __x<0?-__x:__x; }), \
			((void)0)))))))
#define clamp(val, lo, hi) min((typeof(val))max(val, lo), hi)
#define clamp_t(type, val, lo, hi) min_t(type, max_t(type, val, lo), hi)
#define clamp_val(val, lo, hi) clamp_t(typeof(val), val, lo, hi)
#define container_of(ptr, type, member) ({				\
	void *__mptr = (void *)(ptr);					\
	BUILD_BUG_ON_MSG(!__same_type(*(ptr), ((type *)0)->member) &&	\
			 !__same_type(*(ptr), void),			\
			 "pointer type mismatch in container_of()");	\
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
# define sched_annotate_sleep()	(current->task_state_change = 0)
# define sector_div(a, b) do_div(a, b)
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
#define u64_to_user_ptr(x) (		\
{					\
	typecheck(u64, x);		\
	(void __user *)(uintptr_t)x;	\
}					\
)
#define upper_32_bits(n) ((u32)(((n) >> 16) >> 16))

#define __ALIGN_KERNEL(x, a)		__ALIGN_KERNEL_MASK(x, (typeof(x))(a) - 1)
#define __ALIGN_KERNEL_MASK(x, mask)	(((x) + (mask)) & ~(mask))
#define __KERNEL_DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define BUILD_BUG() (0)
#define BUILD_BUG_ON(condition) (0)
#define BUILD_BUG_ON_INVALID(e) (0)
#define BUILD_BUG_ON_MSG(cond, msg) (0)
#define BUILD_BUG_ON_NOT_POWER_OF_2(n)			\
	BUILD_BUG_ON((n) == 0 || (((n) & ((n) - 1)) != 0))
#define BUILD_BUG_ON_ZERO(e) (0)

#define __BUILD_BUG_ON_NOT_POWER_OF_2(n)	\
	BUILD_BUG_ON(((n) & ((n) - 1)) != 0)
# define ASM_UNREACHABLE
# define KENTRY(sym)						\
	extern typeof(sym) sym;					\
	static const unsigned long __kentry_##sym		\
	__used							\
	__attribute__((section("___kentry" "+" #sym ), used))	\
	= (unsigned long)&sym;
#define OPTIMIZER_HIDE_VAR(var) barrier()
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

#define __branch_check__(x, expect, is_constant) ({			\
			int ______r;					\
			static struct ftrace_likely_data		\
				__attribute__((__aligned__(4)))		\
				__attribute__((section("_ftrace_annotated_branch"))) \
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
		bool __cond = !(condition);				\
		extern void prefix ## suffix(void) __compiletime_error(msg); \
		if (__cond)						\
			prefix ## suffix();				\
		__compiletime_error_fallback(__cond);			\
	} while (0)
# define __compiletime_error(message)
#  define __compiletime_error_fallback(condition) \
	do { ((void)sizeof(char[1 - 2 * condition])); } while (0)
# define __compiletime_object_size(obj) -1
# define __compiletime_warning(message)
# define __no_kasan_or_inline __no_sanitize_address __maybe_unused
# define __optimize(level)
#define __trace_if(cond) \
	if (__builtin_constant_p(!!(cond)) ? !!(cond) :			\
	({								\
		int ______r;						\
		static struct ftrace_branch_data			\
			__attribute__((__aligned__(4)))			\
			__attribute__((section("_ftrace_branch")))	\
			______f = {					\
				.func = __func__,			\
				.file = "__FILE__",			\
				.line = "__LINE__",			\
			};						\
		______r = !!(cond);					\
		______f.miss_hit[______r]++;					\
		______r;						\
	}))
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
	_compiletime_assert(condition, msg, __compiletime_assert_, "__LINE__")
#define compiletime_assert_atomic_type(t)				\
	compiletime_assert(__native_word(t),				\
		"Need native word sized stores/loads for atomicity.")
#define if(cond, ...) __trace_if( (cond , ## __VA_ARGS__) )
#  define likely(x)	(__branch_check__(x, 1, __builtin_constant_p(x)))
#define likely_notrace(x)	__builtin_expect(!!(x), 1)
#  define unlikely(x)	(__branch_check__(x, 0, __builtin_constant_p(x)))
#define unlikely_notrace(x)	__builtin_expect(!!(x), 0)
# define unreachable() do { annotate_reachable(); do { } while (1); } while (0)


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
#define __always_inline inline
#define __assume_aligned(a, ...)
# define __builtin_warning(x, y...) (1)
# define __chk_io_ptr(x) (void)0
# define __chk_user_ptr(x) (void)0

# define __cond_lock(x,c)	((c) ? ({ __acquire(x); 1; }) : 0)

#define __deprecated_for_modules __deprecated
# define __designated_init
# define __force
# define __iomem
# define __kernel
# define __latent_entropy


# define __must_hold(x)	__attribute__((context(x,1,1)))
# define __native_word(t) (sizeof(t) == sizeof(char) || sizeof(t) == sizeof(short) || sizeof(t) == sizeof(int) || sizeof(t) == sizeof(long))
# define __no_randomize_layout
# define __nocast
# define __nostackprotector
# define __percpu
# define __private
# define __randomize_layout __designated_init
# define __rcu
# define __release(x)	__context__(x,-1)
# define __releases(x)	__attribute__((context(x,1,0)))
# define __safe
# define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
# define __section(S) __attribute__ ((__section__(#S)))
#  define __user __attribute__((user))


#define noinline_for_stack noinline
#define notrace __attribute__((hotpatch(0,0)))
# define randomized_struct_fields_end
# define randomized_struct_fields_start
#define KASAN_ABI_VERSION 5

#define __no_sanitize_address __attribute__((no_sanitize("address")))
#define uninitialized_var(x) x = *(&(x))
#define GCC_VERSION ("__GNUC__" * 10000		\
		     + "__GNUC_MINOR__" * 100	\
		     + "__GNUC_PATCHLEVEL__")



#define __alias(symbol)	__attribute__((alias(#symbol)))
#define __aligned(x)		__attribute__((aligned(x)))
#define __compiler_offsetof(a, b)					\
	__builtin_offsetof(a, b)
#define __inline __inline	__attribute__((always_inline,unused)) notrace
#define __inline__ __inline__	__attribute__((always_inline,unused)) notrace
#define __mode(x)               __attribute__((mode(x)))
#define __must_be_array(a)	0
#define __noretpoline __attribute__((indirect_branch("keep")))
#define __printf(a, b)		__attribute__((format(printf, a, b)))
#define __scanf(a, b)		__attribute__((format(scanf, a, b)))
#define asm_volatile_goto(x...)	do { asm goto(x); asm (""); } while (0)
#define inline inline		__attribute__((always_inline,unused)) notrace
#define CONSOLE_LOGLEVEL_DEFAULT CONFIG_CONSOLE_LOGLEVEL_DEFAULT
#define CONSOLE_LOGLEVEL_MOTORMOUTH 15	
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
	if (unlikely(descriptor.flags & _DPRINTK_FLAGS_PRINT) &&	\
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
#define pr_fmt(fmt) fmt
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
#define pr_warn pr_warning
#define pr_warn_once(fmt, ...)					\
	printk_once(KERN_WARNING pr_fmt(fmt), ##__VA_ARGS__)
#define pr_warn_ratelimited(fmt, ...)					\
	printk_ratelimited(KERN_WARNING pr_fmt(fmt), ##__VA_ARGS__)
#define pr_warning(fmt, ...) \
	printk(KERN_WARNING pr_fmt(fmt), ##__VA_ARGS__)
#define print_hex_dump_bytes(prefix_str, prefix_type, buf, len)	\
	dynamic_hex_dump(prefix_str, prefix_type, 16, 1, buf, len, true)
#define print_hex_dump_debug(prefix_str, prefix_type, rowsize,	\
			     groupsize, buf, len, ascii)	\
	dynamic_hex_dump(prefix_str, prefix_type, rowsize,	\
			 groupsize, buf, len, ascii)
#define printk_deferred_once(fmt, ...)				\
({								\
	static bool __print_once __read_mostly;			\
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
	static bool __print_once __read_mostly;			\
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
#define DEFINE_DYNAMIC_DEBUG_METADATA(name, fmt) \
	DEFINE_DYNAMIC_DEBUG_METADATA_KEY(name, fmt, 0, 0)
#define DEFINE_DYNAMIC_DEBUG_METADATA_KEY(name, fmt, key, init)	\
	static struct _ddebug  __aligned(8)			\
	__attribute__((section("__verbose"))) name = {		\
		.modname = KBUILD_MODNAME,			\
		.function = __func__,				\
		.filename = "__FILE__",				\
		.format = (fmt),				\
		.lineno = "__LINE__",				\
		.flags = _DPRINTK_FLAGS_DEFAULT,		\
		dd_key_init(key, init)				\
	}
#define DYNAMIC_DEBUG_BRANCH(descriptor) \
	static_branch_unlikely(&descriptor.key.dd_key_false)
#define _DPRINTK_FLAGS_DEFAULT _DPRINTK_FLAGS_PRINT

#define dd_key_init(key, init)
#define dynamic_dev_dbg(dev, fmt, ...)				\
do {								\
	DEFINE_DYNAMIC_DEBUG_METADATA(descriptor, fmt);		\
	if (DYNAMIC_DEBUG_BRANCH(descriptor))			\
		__dynamic_dev_dbg(&descriptor, dev, fmt,	\
				  ##__VA_ARGS__);		\
} while (0)
#define dynamic_hex_dump(prefix_str, prefix_type, rowsize,	\
			 groupsize, buf, len, ascii)		\
do {								\
	DEFINE_DYNAMIC_DEBUG_METADATA(descriptor,		\
		__builtin_constant_p(prefix_str) ? prefix_str : "hexdump");\
	if (DYNAMIC_DEBUG_BRANCH(descriptor))			\
		print_hex_dump(KERN_DEBUG, prefix_str,		\
			       prefix_type, rowsize, groupsize,	\
			       buf, len, ascii);		\
} while (0)
#define dynamic_netdev_dbg(dev, fmt, ...)			\
do {								\
	DEFINE_DYNAMIC_DEBUG_METADATA(descriptor, fmt);		\
	if (DYNAMIC_DEBUG_BRANCH(descriptor))			\
		__dynamic_netdev_dbg(&descriptor, dev, fmt,	\
				     ##__VA_ARGS__);		\
} while (0)
#define dynamic_pr_debug(fmt, ...)				\
do {								\
	DEFINE_DYNAMIC_DEBUG_METADATA(descriptor, fmt);		\
	if (DYNAMIC_DEBUG_BRANCH(descriptor))			\
		__dynamic_pr_debug(&descriptor, pr_fmt(fmt),	\
				   ##__VA_ARGS__);		\
} while (0)
#define ERESTART_RESTARTBLOCK 516 


#define __FORTIFY_INLINE extern __always_inline __attribute__((gnu_inline))
#define __RENAME(x) __asm__(#x)
#define sysfs_match_string(_a, _s) __sysfs_match_string(_a, ARRAY_SIZE(_a), _s)

#define NULL ((void *)0)

#define offsetof(TYPE, MEMBER)	__compiler_offsetof(TYPE, MEMBER)
#define offsetofend(TYPE, MEMBER) \
	(offsetof(TYPE, MEMBER)	+ sizeof_field(TYPE, MEMBER))
#define sizeof_field(TYPE, MEMBER) sizeof((((TYPE *)0)->MEMBER))
#define DECLARE_BITMAP(name,bits) \
	unsigned long name[BITS_TO_LONGS(bits)]









#define aligned_be64 __be64 __attribute__((aligned(8)))
#define aligned_le64 __le64 __attribute__((aligned(8)))
#define aligned_u64 __u64 __attribute__((aligned(8)))
#define pgoff_t unsigned long
#define rcu_head callback_head
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
#define DEFINE_STATIC_KEY_TRUE(name)	\
	struct static_key_true name = STATIC_KEY_TRUE_INIT
# define HAVE_JUMP_LABEL
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
#define BUG_ON(condition) do { if (condition) BUG(); } while (0)

#define WARN(condition, format...) ({					\
	int __ret_warn_on = !!(condition);				\
	if (unlikely(__ret_warn_on))					\
		__WARN_printf(format);					\
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
		__WARN_printf_taint(taint, format);			\
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

#define __WARN()		warn_slowpath_null("__FILE__", "__LINE__")
#define __WARN_ONCE_TAINT(taint)	__WARN_FLAGS(BUGFLAG_ONCE|BUGFLAG_TAINT(taint))
#define __WARN_TAINT(taint)		__WARN_FLAGS(BUGFLAG_TAINT(taint))
#define __WARN_printf(arg...)	warn_slowpath_fmt("__FILE__", "__LINE__", arg)
#define __WARN_printf_taint(taint, arg...)				\
	warn_slowpath_fmt_taint("__FILE__", "__LINE__", taint, arg)

#define __atomic64_try_cmpxchg(type, _p, _po, _n)			\
({									\
	typeof(_po) __po = (_po);					\
	typeof(*(_po)) __r, __o = *__po;				\
	__r = atomic64_cmpxchg##type((_p), __o, (_n));			\
	if (unlikely(__r != __o))					\
		*__po = __r;						\
	likely(__r == __o);						\
})
#define __atomic_op_acquire(op, args...)				\
({									\
	typeof(op##_relaxed(args)) __ret  = op##_relaxed(args);		\
	smp_mb__after_atomic();						\
	__ret;								\
})
#define __atomic_op_fence(op, args...)					\
({									\
	typeof(op##_relaxed(args)) __ret;				\
	smp_mb__before_atomic();					\
	__ret = op##_relaxed(args);					\
	smp_mb__after_atomic();						\
	__ret;								\
})
#define __atomic_op_release(op, args...)				\
({									\
	smp_mb__before_atomic();					\
	op##_relaxed(args);						\
})
#define __atomic_try_cmpxchg(type, _p, _po, _n)				\
({									\
	typeof(_po) __po = (_po);					\
	typeof(*(_po)) __r, __o = *__po;				\
	__r = atomic_cmpxchg##type((_p), __o, (_n));			\
	if (unlikely(__r != __o))					\
		*__po = __r;						\
	likely(__r == __o);						\
})
#define  atomic64_add_return(...)					\
	__atomic_op_fence(atomic64_add_return, __VA_ARGS__)
#define  atomic64_add_return_acquire(...)				\
	__atomic_op_acquire(atomic64_add_return, __VA_ARGS__)
#define  atomic64_add_return_release(...)				\
	__atomic_op_release(atomic64_add_return, __VA_ARGS__)
#define  atomic64_cmpxchg(...)						\
	__atomic_op_fence(atomic64_cmpxchg, __VA_ARGS__)
#define  atomic64_cmpxchg_acquire(...)					\
	__atomic_op_acquire(atomic64_cmpxchg, __VA_ARGS__)
#define  atomic64_cmpxchg_release(...)					\
	__atomic_op_release(atomic64_cmpxchg, __VA_ARGS__)
#define atomic64_cond_read_acquire(v, c)	smp_cond_load_acquire(&(v)->counter, (c))
#define  atomic64_dec_return(...)					\
	__atomic_op_fence(atomic64_dec_return, __VA_ARGS__)
#define  atomic64_dec_return_acquire(...)				\
	__atomic_op_acquire(atomic64_dec_return, __VA_ARGS__)
#define  atomic64_dec_return_release(...)				\
	__atomic_op_release(atomic64_dec_return, __VA_ARGS__)
#define atomic64_fetch_add(...)						\
	__atomic_op_fence(atomic64_fetch_add, __VA_ARGS__)
#define atomic64_fetch_add_acquire(...)					\
	__atomic_op_acquire(atomic64_fetch_add, __VA_ARGS__)
#define atomic64_fetch_add_release(...)					\
	__atomic_op_release(atomic64_fetch_add, __VA_ARGS__)
#define atomic64_fetch_and(...)						\
	__atomic_op_fence(atomic64_fetch_and, __VA_ARGS__)
#define atomic64_fetch_and_acquire(...)					\
	__atomic_op_acquire(atomic64_fetch_and, __VA_ARGS__)
#define atomic64_fetch_and_release(...)					\
	__atomic_op_release(atomic64_fetch_and, __VA_ARGS__)
#define atomic64_fetch_andnot(...)						\
	__atomic_op_fence(atomic64_fetch_andnot, __VA_ARGS__)
#define atomic64_fetch_andnot_acquire(...)					\
	__atomic_op_acquire(atomic64_fetch_andnot, __VA_ARGS__)
#define atomic64_fetch_andnot_release(...)					\
	__atomic_op_release(atomic64_fetch_andnot, __VA_ARGS__)
#define atomic64_fetch_dec(v)		atomic64_fetch_sub(1, (v))
#define atomic64_fetch_dec_acquire(v)	atomic64_fetch_sub_acquire(1, (v))
#define atomic64_fetch_dec_relaxed(v)	atomic64_fetch_sub_relaxed(1, (v))
#define atomic64_fetch_dec_release(v)	atomic64_fetch_sub_release(1, (v))
#define atomic64_fetch_inc(v)		atomic64_fetch_add(1, (v))
#define atomic64_fetch_inc_acquire(v)	atomic64_fetch_add_acquire(1, (v))
#define atomic64_fetch_inc_relaxed(v)	atomic64_fetch_add_relaxed(1, (v))
#define atomic64_fetch_inc_release(v)	atomic64_fetch_add_release(1, (v))
#define atomic64_fetch_or(...)						\
	__atomic_op_fence(atomic64_fetch_or, __VA_ARGS__)
#define atomic64_fetch_or_acquire(...)					\
	__atomic_op_acquire(atomic64_fetch_or, __VA_ARGS__)
#define atomic64_fetch_or_release(...)					\
	__atomic_op_release(atomic64_fetch_or, __VA_ARGS__)
#define atomic64_fetch_sub(...)						\
	__atomic_op_fence(atomic64_fetch_sub, __VA_ARGS__)
#define atomic64_fetch_sub_acquire(...)					\
	__atomic_op_acquire(atomic64_fetch_sub, __VA_ARGS__)
#define atomic64_fetch_sub_release(...)					\
	__atomic_op_release(atomic64_fetch_sub, __VA_ARGS__)
#define atomic64_fetch_xor(...)						\
	__atomic_op_fence(atomic64_fetch_xor, __VA_ARGS__)
#define atomic64_fetch_xor_acquire(...)					\
	__atomic_op_acquire(atomic64_fetch_xor, __VA_ARGS__)
#define atomic64_fetch_xor_release(...)					\
	__atomic_op_release(atomic64_fetch_xor, __VA_ARGS__)
#define  atomic64_inc_return(...)					\
	__atomic_op_fence(atomic64_inc_return, __VA_ARGS__)
#define  atomic64_inc_return_acquire(...)				\
	__atomic_op_acquire(atomic64_inc_return, __VA_ARGS__)
#define  atomic64_inc_return_release(...)				\
	__atomic_op_release(atomic64_inc_return, __VA_ARGS__)
#define  atomic64_read_acquire(v)	smp_load_acquire(&(v)->counter)
#define  atomic64_set_release(v, i)	smp_store_release(&(v)->counter, (i))
#define  atomic64_sub_return(...)					\
	__atomic_op_fence(atomic64_sub_return, __VA_ARGS__)
#define  atomic64_sub_return_acquire(...)				\
	__atomic_op_acquire(atomic64_sub_return, __VA_ARGS__)
#define  atomic64_sub_return_release(...)				\
	__atomic_op_release(atomic64_sub_return, __VA_ARGS__)
#define atomic64_try_cmpxchg(_p, _po, _n)		__atomic64_try_cmpxchg(, _p, _po, _n)
#define atomic64_try_cmpxchg_acquire(_p, _po, _n)	__atomic64_try_cmpxchg(_acquire, _p, _po, _n)
#define atomic64_try_cmpxchg_relaxed(_p, _po, _n)	__atomic64_try_cmpxchg(_relaxed, _p, _po, _n)
#define atomic64_try_cmpxchg_release(_p, _po, _n)	__atomic64_try_cmpxchg(_release, _p, _po, _n)
#define  atomic64_xchg(...)						\
	__atomic_op_fence(atomic64_xchg, __VA_ARGS__)
#define  atomic64_xchg_acquire(...)					\
	__atomic_op_acquire(atomic64_xchg, __VA_ARGS__)
#define  atomic64_xchg_release(...)					\
	__atomic_op_release(atomic64_xchg, __VA_ARGS__)
#define  atomic_add_return(...)						\
	__atomic_op_fence(atomic_add_return, __VA_ARGS__)
#define  atomic_add_return_acquire(...)					\
	__atomic_op_acquire(atomic_add_return, __VA_ARGS__)
#define  atomic_add_return_release(...)					\
	__atomic_op_release(atomic_add_return, __VA_ARGS__)
#define  atomic_cmpxchg(...)						\
	__atomic_op_fence(atomic_cmpxchg, __VA_ARGS__)
#define  atomic_cmpxchg_acquire(...)					\
	__atomic_op_acquire(atomic_cmpxchg, __VA_ARGS__)
#define  atomic_cmpxchg_release(...)					\
	__atomic_op_release(atomic_cmpxchg, __VA_ARGS__)
#define atomic_cond_read_acquire(v, c)	smp_cond_load_acquire(&(v)->counter, (c))
#define  atomic_dec_return(...)						\
	__atomic_op_fence(atomic_dec_return, __VA_ARGS__)
#define  atomic_dec_return_acquire(...)					\
	__atomic_op_acquire(atomic_dec_return, __VA_ARGS__)
#define  atomic_dec_return_release(...)					\
	__atomic_op_release(atomic_dec_return, __VA_ARGS__)
#define atomic_fetch_add(...)						\
	__atomic_op_fence(atomic_fetch_add, __VA_ARGS__)
#define atomic_fetch_add_acquire(...)					\
	__atomic_op_acquire(atomic_fetch_add, __VA_ARGS__)
#define atomic_fetch_add_release(...)					\
	__atomic_op_release(atomic_fetch_add, __VA_ARGS__)
#define atomic_fetch_and(...)						\
	__atomic_op_fence(atomic_fetch_and, __VA_ARGS__)
#define atomic_fetch_and_acquire(...)					\
	__atomic_op_acquire(atomic_fetch_and, __VA_ARGS__)
#define atomic_fetch_and_release(...)					\
	__atomic_op_release(atomic_fetch_and, __VA_ARGS__)
#define atomic_fetch_andnot(...)						\
	__atomic_op_fence(atomic_fetch_andnot, __VA_ARGS__)
#define atomic_fetch_andnot_acquire(...)					\
	__atomic_op_acquire(atomic_fetch_andnot, __VA_ARGS__)
#define atomic_fetch_andnot_release(...)					\
	__atomic_op_release(atomic_fetch_andnot, __VA_ARGS__)
#define atomic_fetch_dec(v)	        atomic_fetch_sub(1, (v))
#define atomic_fetch_dec_acquire(v)	atomic_fetch_sub_acquire(1, (v))
#define atomic_fetch_dec_relaxed(v)	atomic_fetch_sub_relaxed(1, (v))
#define atomic_fetch_dec_release(v)	atomic_fetch_sub_release(1, (v))
#define atomic_fetch_inc(v)	        atomic_fetch_add(1, (v))
#define atomic_fetch_inc_acquire(v)	atomic_fetch_add_acquire(1, (v))
#define atomic_fetch_inc_relaxed(v)	atomic_fetch_add_relaxed(1, (v))
#define atomic_fetch_inc_release(v)	atomic_fetch_add_release(1, (v))
#define atomic_fetch_or(...)						\
	__atomic_op_fence(atomic_fetch_or, __VA_ARGS__)
#define atomic_fetch_or_acquire(...)					\
	__atomic_op_acquire(atomic_fetch_or, __VA_ARGS__)
#define atomic_fetch_or_release(...)					\
	__atomic_op_release(atomic_fetch_or, __VA_ARGS__)
#define atomic_fetch_sub(...)						\
	__atomic_op_fence(atomic_fetch_sub, __VA_ARGS__)
#define atomic_fetch_sub_acquire(...)					\
	__atomic_op_acquire(atomic_fetch_sub, __VA_ARGS__)
#define atomic_fetch_sub_release(...)					\
	__atomic_op_release(atomic_fetch_sub, __VA_ARGS__)
#define atomic_fetch_xor(...)						\
	__atomic_op_fence(atomic_fetch_xor, __VA_ARGS__)
#define atomic_fetch_xor_acquire(...)					\
	__atomic_op_acquire(atomic_fetch_xor, __VA_ARGS__)
#define atomic_fetch_xor_release(...)					\
	__atomic_op_release(atomic_fetch_xor, __VA_ARGS__)
#define atomic_inc_not_zero(v)		atomic_add_unless((v), 1, 0)
#define  atomic_inc_return(...)						\
	__atomic_op_fence(atomic_inc_return, __VA_ARGS__)
#define  atomic_inc_return_acquire(...)					\
	__atomic_op_acquire(atomic_inc_return, __VA_ARGS__)
#define  atomic_inc_return_release(...)					\
	__atomic_op_release(atomic_inc_return, __VA_ARGS__)
#define  atomic_read_acquire(v)		smp_load_acquire(&(v)->counter)
#define  atomic_set_release(v, i)	smp_store_release(&(v)->counter, (i))
#define  atomic_sub_return(...)						\
	__atomic_op_fence(atomic_sub_return, __VA_ARGS__)
#define  atomic_sub_return_acquire(...)					\
	__atomic_op_acquire(atomic_sub_return, __VA_ARGS__)
#define  atomic_sub_return_release(...)					\
	__atomic_op_release(atomic_sub_return, __VA_ARGS__)
#define atomic_try_cmpxchg(_p, _po, _n)		__atomic_try_cmpxchg(, _p, _po, _n)
#define atomic_try_cmpxchg_acquire(_p, _po, _n)	__atomic_try_cmpxchg(_acquire, _p, _po, _n)
#define atomic_try_cmpxchg_relaxed(_p, _po, _n)	__atomic_try_cmpxchg(_relaxed, _p, _po, _n)
#define atomic_try_cmpxchg_release(_p, _po, _n)	__atomic_try_cmpxchg(_release, _p, _po, _n)
#define  atomic_xchg(...)						\
	__atomic_op_fence(atomic_xchg, __VA_ARGS__)
#define  atomic_xchg_acquire(...)					\
	__atomic_op_acquire(atomic_xchg, __VA_ARGS__)
#define  atomic_xchg_release(...)					\
	__atomic_op_release(atomic_xchg, __VA_ARGS__)
#define  cmpxchg(...)							\
	__atomic_op_fence(cmpxchg, __VA_ARGS__)
#define  cmpxchg64(...)							\
	__atomic_op_fence(cmpxchg64, __VA_ARGS__)
#define  cmpxchg64_acquire(...)						\
	__atomic_op_acquire(cmpxchg64, __VA_ARGS__)
#define  cmpxchg64_release(...)						\
	__atomic_op_release(cmpxchg64, __VA_ARGS__)
#define  cmpxchg_acquire(...)						\
	__atomic_op_acquire(cmpxchg, __VA_ARGS__)
#define  cmpxchg_release(...)						\
	__atomic_op_release(cmpxchg, __VA_ARGS__)
#define  xchg(...)			__atomic_op_fence(xchg, __VA_ARGS__)
#define  xchg_acquire(...)		__atomic_op_acquire(xchg, __VA_ARGS__)
#define  xchg_release(...)		__atomic_op_release(xchg, __VA_ARGS__)
#define ATOMIC_LONG_ADD_SUB_OP(op, mo)					\
static inline long							\
atomic_long_##op##_return##mo(long i, atomic_long_t *l)			\
{									\
	ATOMIC_LONG_PFX(_t) *v = (ATOMIC_LONG_PFX(_t) *)l;		\
									\
	return (long)ATOMIC_LONG_PFX(_##op##_return##mo)(i, v);		\
}
#define ATOMIC_LONG_FETCH_INC_DEC_OP(op, mo)					\
static inline long							\
atomic_long_fetch_##op##mo(atomic_long_t *l)				\
{									\
	ATOMIC_LONG_PFX(_t) *v = (ATOMIC_LONG_PFX(_t) *)l;		\
									\
	return (long)ATOMIC_LONG_PFX(_fetch_##op##mo)(v);		\
}
#define ATOMIC_LONG_FETCH_OP(op, mo)					\
static inline long							\
atomic_long_fetch_##op##mo(long i, atomic_long_t *l)			\
{									\
	ATOMIC_LONG_PFX(_t) *v = (ATOMIC_LONG_PFX(_t) *)l;		\
									\
	return (long)ATOMIC_LONG_PFX(_fetch_##op##mo)(i, v);		\
}
#define ATOMIC_LONG_INC_DEC_OP(op, mo)					\
static inline long							\
atomic_long_##op##_return##mo(atomic_long_t *l)				\
{									\
	ATOMIC_LONG_PFX(_t) *v = (ATOMIC_LONG_PFX(_t) *)l;		\
									\
	return (long)ATOMIC_LONG_PFX(_##op##_return##mo)(v);		\
}
#define ATOMIC_LONG_INIT(i)	ATOMIC64_INIT(i)
#define ATOMIC_LONG_OP(op)						\
static __always_inline void						\
atomic_long_##op(long i, atomic_long_t *l)				\
{									\
	ATOMIC_LONG_PFX(_t) *v = (ATOMIC_LONG_PFX(_t) *)l;		\
									\
	ATOMIC_LONG_PFX(_##op)(i, v);					\
}
#define ATOMIC_LONG_PFX(x)	atomic64 ## x
#define ATOMIC_LONG_READ_OP(mo)						\
static inline long atomic_long_read##mo(const atomic_long_t *l)		\
{									\
	ATOMIC_LONG_PFX(_t) *v = (ATOMIC_LONG_PFX(_t) *)l;		\
									\
	return (long)ATOMIC_LONG_PFX(_read##mo)(v);			\
}
#define ATOMIC_LONG_SET_OP(mo)						\
static inline void atomic_long_set##mo(atomic_long_t *l, long i)	\
{									\
	ATOMIC_LONG_PFX(_t) *v = (ATOMIC_LONG_PFX(_t) *)l;		\
									\
	ATOMIC_LONG_PFX(_set##mo)(v, i);				\
}

#define atomic_long_cmpxchg(l, old, new) \
	(ATOMIC_LONG_PFX(_cmpxchg)((ATOMIC_LONG_PFX(_t) *)(l), (old), (new)))
#define atomic_long_cmpxchg_acquire(l, old, new) \
	(ATOMIC_LONG_PFX(_cmpxchg_acquire)((ATOMIC_LONG_PFX(_t) *)(l), \
					   (old), (new)))
#define atomic_long_cmpxchg_relaxed(l, old, new) \
	(ATOMIC_LONG_PFX(_cmpxchg_relaxed)((ATOMIC_LONG_PFX(_t) *)(l), \
					   (old), (new)))
#define atomic_long_cmpxchg_release(l, old, new) \
	(ATOMIC_LONG_PFX(_cmpxchg_release)((ATOMIC_LONG_PFX(_t) *)(l), \
					   (old), (new)))
#define atomic_long_cond_read_acquire(v, c) \
	ATOMIC_LONG_PFX(_cond_read_acquire)((ATOMIC_LONG_PFX(_t) *)(v), (c))
#define atomic_long_inc_not_zero(l) \
	ATOMIC_LONG_PFX(_inc_not_zero)((ATOMIC_LONG_PFX(_t) *)(l))
#define atomic_long_xchg(v, new) \
	(ATOMIC_LONG_PFX(_xchg)((ATOMIC_LONG_PFX(_t) *)(v), (new)))
#define atomic_long_xchg_acquire(v, new) \
	(ATOMIC_LONG_PFX(_xchg_acquire)((ATOMIC_LONG_PFX(_t) *)(v), (new)))
#define atomic_long_xchg_relaxed(v, new) \
	(ATOMIC_LONG_PFX(_xchg_relaxed)((ATOMIC_LONG_PFX(_t) *)(v), (new)))
#define atomic_long_xchg_release(v, new) \
	(ATOMIC_LONG_PFX(_xchg_release)((ATOMIC_LONG_PFX(_t) *)(v), (new)))
#define ATOMIC64_FETCH_OP(op)						\
extern long long atomic64_fetch_##op(long long a, atomic64_t *v);
#define ATOMIC64_INIT(i)	{ (i) }
#define ATOMIC64_OP(op)							\
extern void	 atomic64_##op(long long a, atomic64_t *v);
#define ATOMIC64_OPS(op)	ATOMIC64_OP(op) ATOMIC64_OP_RETURN(op) ATOMIC64_FETCH_OP(op)
#define ATOMIC64_OP_RETURN(op)						\
extern long long atomic64_##op##_return(long long a, atomic64_t *v);

#define atomic64_add_negative(a, v)	(atomic64_add_return((a), (v)) < 0)
#define atomic64_dec(v)			atomic64_sub(1LL, (v))
#define atomic64_dec_and_test(v)	(atomic64_dec_return((v)) == 0)
#define atomic64_inc(v)			atomic64_add(1LL, (v))
#define atomic64_inc_and_test(v) 	(atomic64_inc_return(v) == 0)
#define atomic64_inc_not_zero(v) 	atomic64_add_unless((v), 1LL, 0LL)
#define atomic64_sub_and_test(a, v)	(atomic64_sub_return((a), (v)) == 0)
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
#define ALIGN_STR __ALIGN_STR
#define CPP_ASMLINKAGE extern "C"
#define END(name) \
	.size name, .-name
#define ENDPROC(name) \
	.type name, @function ASM_NL \
	END(name)
#define ENTRY(name) \
	.globl name ASM_NL \
	ALIGN ASM_NL \
	name:
#define SYSCALL_ALIAS(alias, name) asm(			\
	".globl " VMLINUX_SYMBOL_STR(alias) "\n\t"	\
	".set   " VMLINUX_SYMBOL_STR(alias) ","		\
		  VMLINUX_SYMBOL_STR(name))
#define WEAK(name)	   \
	.weak name ASM_NL   \
	name:

#define asmlinkage CPP_ASMLINKAGE
# define asmlinkage_protect(n, ret, args...)	do { } while (0)
#define cond_syscall(x)	asm(				\
	".weak " VMLINUX_SYMBOL_STR(x) "\n\t"		\
	".set  " VMLINUX_SYMBOL_STR(x) ","		\
		 VMLINUX_SYMBOL_STR(sys_ni_syscall))
#define EXPORT_SYMBOL(sym)					\
	__EXPORT_SYMBOL(sym, "")
#define EXPORT_SYMBOL_GPL(sym)					\
	__EXPORT_SYMBOL(sym, "_gpl")
#define EXPORT_SYMBOL_GPL_FUTURE(sym)				\
	__EXPORT_SYMBOL(sym, "_gpl_future")
#define EXPORT_UNUSED_SYMBOL(sym) __EXPORT_SYMBOL(sym, "_unused")
#define EXPORT_UNUSED_SYMBOL_GPL(sym) __EXPORT_SYMBOL(sym, "_unused_gpl")
#define THIS_MODULE (&__this_module)
#define VMLINUX_SYMBOL(x) __VMLINUX_SYMBOL(x)
#define VMLINUX_SYMBOL_STR(x) __VMLINUX_SYMBOL_STR(x)

#define __CRC_SYMBOL(sym, sec)						\
	asm("	.section \"___kcrctab" sec "+" #sym "\", \"a\"	\n"	\
	    "	.weak	" VMLINUX_SYMBOL_STR(__crc_##sym) "	\n"	\
	    "	.long	" VMLINUX_SYMBOL_STR(__crc_##sym) " - .	\n"	\
	    "	.previous					\n");
#define __EXPORT_SYMBOL ___EXPORT_SYMBOL
#define __VMLINUX_SYMBOL(x) _##x
#define __VMLINUX_SYMBOL_STR(x) "_" #x
#define ___EXPORT_SYMBOL(sym, sec)					\
	extern typeof(sym) sym;						\
	__CRC_SYMBOL(sym, sec)						\
	static const char __kstrtab_##sym[]				\
	__attribute__((section("__ksymtab_strings"), aligned(1)))	\
	= VMLINUX_SYMBOL_STR(sym);					\
	static const struct kernel_symbol __ksymtab_##sym		\
	__used								\
	__attribute__((section("___ksymtab" sec "+" #sym), used))	\
	= { (unsigned long)&sym, __kstrtab_##sym }
#define ___cond_export_sym(sym, sec, enabled)			\
	__cond_export_sym_##enabled(sym, sec)
#define __cond_export_sym(sym, sec, conf)			\
	___cond_export_sym(sym, sec, conf)
#define __cond_export_sym_1(sym, sec) ___EXPORT_SYMBOL(sym, sec)

#define __stringify(x...)	__stringify_1(x)
#define __stringify_1(x...)	#x


#define __MEMINIT        .section	".meminit.text", "ax"
#define __MEMINITDATA    .section	".meminit.data", "aw"
#define __MEMINITRODATA  .section	".meminit.rodata", "a"
#define __REF            .section       ".ref.text", "ax"
#define __REFCONST       .section       ".ref.rodata", "a"
#define __REFDATA        .section       ".ref.data", "aw"
#define __define_initcall(fn, id) \
	static initcall_t __initcall_##fn##id __used \
	__attribute__((__section__(".initcall" #id ".init"))) = fn;
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
#define console_initcall(fn)					\
	static initcall_t __initcall_##fn			\
	__used __section(.con_initcall.init) = fn
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
#define security_initcall(fn)					\
	static initcall_t __initcall_##fn			\
	__used __section(.security_initcall.init) = fn
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

#define ilog2(n)				\
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
		1 ) :				\
	(sizeof(n) <= 4) ?			\
	__ilog2_u32(n) :			\
	__ilog2_u64(n)				\
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
#define BIT(nr)			(1UL << (nr))
#define BITS_TO_LONGS(nr)	DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))
#define BIT_MASK(nr)		(1UL << ((nr) % BITS_PER_LONG))
#define BIT_ULL(nr)		(1ULL << (nr))
#define BIT_ULL_MASK(nr)	(1ULL << ((nr) % BITS_PER_LONG_LONG))
#define BIT_ULL_WORD(nr)	((nr) / BITS_PER_LONG_LONG)
#define BIT_WORD(nr)		((nr) / BITS_PER_LONG)
#define GENMASK(h, l) \
	(((~0UL) - (1UL << (l)) + 1) & (~0UL >> (BITS_PER_LONG - 1 - (h))))
#define GENMASK_ULL(h, l) \
	(((~0ULL) - (1ULL << (l)) + 1) & \
	 (~0ULL >> (BITS_PER_LONG_LONG - 1 - (h))))

#define bit_clear_unless(ptr, _clear, _test)	\
({								\
	const typeof(*ptr) clear = (_clear), test = (_test);	\
	typeof(*ptr) old, new;					\
								\
	do {							\
		old = READ_ONCE(*ptr);			\
		new = old & ~clear;				\
	} while (!(old & test) &&				\
		 cmpxchg(ptr, old, new) != old);		\
								\
	!(old & test);						\
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
#define set_mask_bits(ptr, _mask, _bits)	\
({								\
	const typeof(*ptr) mask = (_mask), bits = (_bits);	\
	typeof(*ptr) old, new;					\
								\
	do {							\
		old = READ_ONCE(*ptr);			\
		new = (old & ~mask) | bits;			\
	} while (cmpxchg(ptr, old, new) != old);		\
								\
	new;							\
})
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
#define arch_spin_lock_flags(lock, flags)	arch_spin_lock(lock)
#define assert_spin_locked(lock)	assert_raw_spin_locked(&(lock)->rlock)
#define atomic_dec_and_lock(atomic, lock) \
		__cond_lock(lock, _atomic_dec_and_lock(atomic, lock))
#define do_raw_spin_lock_flags(lock, flags) do_raw_spin_lock(lock)
#define raw_spin_is_contended(lock)	arch_spin_is_contended(&(lock)->raw_lock)
#define raw_spin_is_locked(lock)	arch_spin_is_locked(&(lock)->raw_lock)
#define raw_spin_lock(lock)	_raw_spin_lock(lock)
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
#define raw_spin_trylock(lock)	__cond_lock(lock, _raw_spin_trylock(lock))
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
#define raw_spin_unlock_bh(lock)	_raw_spin_unlock_bh(lock)
#define raw_spin_unlock_irq(lock)	_raw_spin_unlock_irq(lock)
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
#define read_trylock(lock)	__cond_lock(lock, _raw_read_trylock(lock))
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
#define write_lock(lock)	_raw_write_lock(lock)
#define write_lock_bh(lock)		_raw_write_lock_bh(lock)
#define write_lock_irq(lock)		_raw_write_lock_irq(lock)
#define write_lock_irqsave(lock, flags)			\
	do {						\
		typecheck(unsigned long, flags);	\
		flags = _raw_write_lock_irqsave(lock);	\
	} while (0)
#define write_trylock(lock)	__cond_lock(lock, _raw_write_trylock(lock))
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
#define lock_map_release(l)			lock_release(l, 1, _THIS_IP_)
# define lock_release(l, n, i)			do { } while (0)
# define lock_set_class(l, n, k, s, i)		do { } while (0)
# define lock_set_subclass(l, s, i)		do { } while (0)
#define lockdep_assert_held(l)	do {				\
		WARN_ON(debug_locks && !lockdep_is_held(l));	\
	} while (0)
#define lockdep_assert_held_exclusive(l)	do {			\
		WARN_ON(debug_locks && !lockdep_is_held_type(l, 0));	\
	} while (0)
#define lockdep_assert_held_once(l)	do {				\
		WARN_ON_ONCE(debug_locks && !lockdep_is_held(l));	\
	} while (0)
#define lockdep_assert_held_read(l)	do {				\
		WARN_ON(debug_locks && !lockdep_is_held_type(l, 1));	\
	} while (0)
# define lockdep_assert_irqs_disabled() do { } while (0)
# define lockdep_assert_irqs_enabled() do { } while (0)
#define lockdep_depth(tsk)	(debug_locks ? (tsk)->lockdep_depth : 0)
# define lockdep_free_key_range(start, size)	do { } while (0)
# define lockdep_info()				do { } while (0)
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
	lock_release(&(lock)->dep_map, 0, _THIS_IP_);			\
} while (0)
# define might_lock_read(lock) 						\
do {									\
	typecheck(struct lockdep_map *, &(lock)->dep_map);		\
	lock_acquire(&(lock)->dep_map, 0, 0, 1, 1, NULL, _THIS_IP_);	\
	lock_release(&(lock)->dep_map, 0, _THIS_IP_);			\
} while (0)
#define mutex_acquire(l, s, t, i)		lock_acquire_exclusive(l, s, t, NULL, i)
#define mutex_acquire_nest(l, s, t, n, i)	lock_acquire_exclusive(l, s, t, n, i)
#define mutex_release(l, n, i)			lock_release(l, n, i)
#define rwlock_acquire(l, s, t, i)		lock_acquire_exclusive(l, s, t, NULL, i)
#define rwlock_acquire_read(l, s, t, i)		lock_acquire_shared_recursive(l, s, t, NULL, i)
#define rwlock_release(l, n, i)			lock_release(l, n, i)
#define rwsem_acquire(l, s, t, i)		lock_acquire_exclusive(l, s, t, NULL, i)
#define rwsem_acquire_nest(l, s, t, n, i)	lock_acquire_exclusive(l, s, t, n, i)
#define rwsem_acquire_read(l, s, t, i)		lock_acquire_shared(l, s, t, NULL, i)
#define rwsem_release(l, n, i)			lock_release(l, n, i)
#define seqcount_acquire(l, s, t, i)		lock_acquire_exclusive(l, s, t, NULL, i)
#define seqcount_acquire_read(l, s, t, i)	lock_acquire_shared_recursive(l, s, t, NULL, i)
#define seqcount_release(l, n, i)		lock_release(l, n, i)
#define spin_acquire(l, s, t, i)		lock_acquire_exclusive(l, s, t, NULL, i)
#define spin_acquire_nest(l, s, t, n, i)	lock_acquire_exclusive(l, s, t, n, i)
#define spin_release(l, n, i)			lock_release(l, n, i)

# define print_stack_trace(trace, spaces)		do { } while (0)
# define save_stack_trace(trace)			do { } while (0)
# define save_stack_trace_tsk(tsk, trace)		do { } while (0)
# define save_stack_trace_tsk_reliable(tsk, trace)	({ -ENOSYS; })
# define save_stack_trace_user(trace)              do { } while (0)
# define snprint_stack_trace(buf, size, trace, spaces)	do { } while (0)
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
#define UL(x)		(_UL(x))
#define ULL(x)		(_ULL(x))

#define _AC(X,Y)	X
#define _AT(T,X)	X
#define _BITUL(x)	(_UL(1) << (x))
#define _BITULL(x)	(_ULL(1) << (x))

#define _UL(x)		(_AC(x, UL))
#define _ULL(x)		(_AC(x, ULL))
#define __AC(X,Y)	(X##Y)
#define LIST_POISON1  ((void *) 0x100 + POISON_POINTER_DELTA)
#define LIST_POISON2  ((void *) 0x200 + POISON_POINTER_DELTA)
#define PAGE_POISON 0x00
# define POISON_POINTER_DELTA _AC(CONFIG_ILLEGAL_POINTER_VALUE, UL)


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
#define preempt_count_add(val)	__preempt_count_add(val)
#define preempt_count_dec() preempt_count_sub(1)
#define preempt_count_dec_and_test() \
	({ preempt_count_sub(1); should_resched(0); })
#define preempt_count_inc() preempt_count_add(1)
#define preempt_count_sub(val)	__preempt_count_sub(val)
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
#define local_save_flags(flags)	raw_local_save_flags(flags)
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
#define safe_halt()				\
	do {					\
		trace_hardirqs_on();		\
		raw_safe_halt();		\
	} while (0)
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
# define trace_softirqs_off(ip)		do { } while (0)
# define trace_softirqs_on(ip)		do { } while (0)
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
#define OSQ_LOCK_UNLOCKED { ATOMIC_INIT(OSQ_UNLOCKED_VAL) }
#define OSQ_UNLOCKED_VAL (0)

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
			break;						\
		}							\
									\
		cmd;							\
	}								\
	finish_swait(&wq, &__wait);					\
	__ret;								\
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
#define swait_event(wq, condition)					\
do {									\
	if (condition)							\
		break;							\
	__swait_event(wq, condition);					\
} while (0)
#define swait_event_idle(wq, condition)					\
do {									\
	if (condition)							\
		break;							\
	__swait_event_idle(wq, condition);				\
} while (0)
#define swait_event_idle_timeout(wq, condition, timeout)		\
({									\
	long __ret = timeout;						\
	if (!___wait_cond_timeout(condition))				\
		__ret = __swait_event_idle_timeout(wq,			\
						   condition, timeout);	\
	__ret;								\
})
#define swait_event_interruptible(wq, condition)			\
({									\
	int __ret = 0;							\
	if (!(condition))						\
		__ret = __swait_event_interruptible(wq, condition);	\
	__ret;								\
})
#define swait_event_interruptible_timeout(wq, condition, timeout)	\
({									\
	long __ret = timeout;						\
	if (!___wait_cond_timeout(condition))				\
		__ret = __swait_event_interruptible_timeout(wq,		\
						condition, timeout);	\
	__ret;								\
})
#define swait_event_timeout(wq, condition, timeout)			\
({									\
	long __ret = timeout;						\
	if (!___wait_cond_timeout(condition))				\
		__ret = __swait_event_timeout(wq, condition, timeout);	\
	__ret;								\
})

#define CT_WARN_ON(cond) WARN_ON(context_tracking_is_enabled() && (cond))



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



#define cpu_active(cpu)		cpumask_test_cpu((cpu), cpu_active_mask)
#define cpu_active_mask   ((const struct cpumask *)&__cpu_active_mask)
#define cpu_all_mask to_cpumask(cpu_all_bits)
#define cpu_is_offline(cpu)	unlikely(!cpu_online(cpu))
#define cpu_none_mask to_cpumask(cpu_bit_bitmap[0])
#define cpu_online(cpu)		cpumask_test_cpu((cpu), cpu_online_mask)
#define cpu_online_mask   ((const struct cpumask *)&__cpu_online_mask)
#define cpu_possible(cpu)	cpumask_test_cpu((cpu), cpu_possible_mask)
#define cpu_possible_mask ((const struct cpumask *)&__cpu_possible_mask)
#define cpu_present(cpu)	cpumask_test_cpu((cpu), cpu_present_mask)
#define cpu_present_mask  ((const struct cpumask *)&__cpu_present_mask)
#define cpumask_any(srcp) cpumask_first(srcp)
#define cpumask_any_and(mask1, mask2) cpumask_first_and((mask1), (mask2))
#define cpumask_bits(maskp) ((maskp)->bits)
#define cpumask_first_and(src1p, src2p) cpumask_next_and(-1, (src1p), (src2p))
#define cpumask_of(cpu) (get_cpu_mask(cpu))
#define cpumask_pr_args(maskp)		nr_cpu_ids, cpumask_bits(maskp)
#define for_each_cpu(cpu, mask)			\
	for ((cpu) = 0; (cpu) < 1; (cpu)++, (void)mask)
#define for_each_cpu_and(cpu, mask, and)	\
	for ((cpu) = 0; (cpu) < 1; (cpu)++, (void)mask, (void)and)
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
#define BITMAP_FIRST_WORD_MASK(start) (~0UL << ((start) & (BITS_PER_LONG - 1)))
#define BITMAP_FROM_U64(n) (n)
#define BITMAP_LAST_WORD_MASK(nbits) (~0UL >> (-(nbits) & (BITS_PER_LONG - 1)))
#define BITMAP_MEM_ALIGNMENT 8
#define BITMAP_MEM_MASK (BITMAP_MEM_ALIGNMENT - 1)

#define bitmap_copy_le bitmap_copy
#define bitmap_from_arr32(bitmap, buf, nbits)			\
	bitmap_copy_clear_tail((unsigned long *) (bitmap),	\
			(const unsigned long *) (buf), (nbits))
#define bitmap_to_arr32(buf, bitmap, nbits)			\
	bitmap_copy_clear_tail((unsigned long *) (buf),		\
			(const unsigned long *) (bitmap), (nbits))
#define small_const_nbits(nbits) \
	(__builtin_constant_p(nbits) && (nbits) <= BITS_PER_LONG)
#define MIN_THREADS_LEFT_FOR_ROOT 4
#define PID_MAX_DEFAULT (CONFIG_BASE_SMALL ? 0x1000 : 0x8000)
#define PID_MAX_LIMIT (CONFIG_BASE_SMALL ? PAGE_SIZE * 8 : \
	(sizeof(long) > 4 ? 4 * 1024 * 1024 : PID_MAX_DEFAULT))


#define generic_smp_call_function_interrupt \
	generic_smp_call_function_single_interrupt
#define get_cpu()		({ preempt_disable(); smp_processor_id(); })
#define put_cpu()		preempt_enable()
#define raw_smp_processor_id()			0
#define smp_call_function(func, info, wait) \
			(up_smp_call_function(func, info))
#define smp_call_function_many(mask, func, info, wait) \
			(up_smp_call_function(func, info))
#define smp_prepare_boot_cpu()			do {} while (0)
# define smp_processor_id() debug_smp_processor_id()

#define LLIST_HEAD(name)	struct llist_head name = LLIST_HEAD_INIT(name)
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
#define cond_resched_softirq() ({					\
	___might_sleep("__FILE__", "__LINE__", SOFTIRQ_DISABLE_OFFSET);	\
	__cond_resched_softirq();					\
})
#define conditional_stopped_child_used_math(condition, child) \
	do { (child)->flags &= ~PF_USED_MATH, (child)->flags |= (condition) ? PF_USED_MATH : 0; } while (0)
#define conditional_used_math(condition)	conditional_stopped_child_used_math(condition, current)
#define copy_to_stopped_child_used_math(child) \
	do { (child)->flags &= ~PF_USED_MATH, (child)->flags |= current->flags & PF_USED_MATH; } while (0)
#define cpu_relax_yield() cpu_relax()
#define get_task_comm(buf, tsk) ({			\
	BUILD_BUG_ON(sizeof(buf) != TASK_COMM_LEN);	\
	__get_task_comm(buf, sizeof(buf), tsk);		\
})
#define is_special_task_state(state)				\
	((state) & (__TASK_STOPPED | __TASK_TRACED | TASK_DEAD))
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
# define vcpu_is_preempted(cpu)	false

#define VMACACHE_BITS 2
#define VMACACHE_MASK (VMACACHE_SIZE - 1)
#define VMACACHE_SIZE (1U << VMACACHE_BITS)



#define NICE_TO_PRIO(nice)	((nice) + DEFAULT_PRIO)
#define PRIO_TO_NICE(prio)	((prio) - DEFAULT_PRIO)
#define TASK_USER_PRIO(p)	USER_PRIO((p)->static_prio)
#define USER_PRIO(p)		((p)-MAX_RT_PRIO)





#define time_after32(a, b)	((s32)((u32)(b) - (u32)(a)) < 0)
#define time_before32(b, a)	time_after32(a, b)
#define RCU_INITIALIZER(v) (typeof(*(v)) __force __rcu *)(v)
#define RCU_INIT_POINTER(p, v) \
	do { \
		rcu_dereference_sparse(p, __rcu); \
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
	rcu_dereference_sparse(p, space); \
	((typeof(*p) __force __kernel *)(_________p1)); \
})
#define __rcu_dereference_check(p, c, space) \
({ \
	 \
	typeof(*p) *________p1 = (typeof(*p) *__force)READ_ONCE(p); \
	RCU_LOCKDEP_WARN(!(c), "suspicious rcu_dereference_check() usage"); \
	rcu_dereference_sparse(p, space); \
	((typeof(*p) __force __kernel *)(________p1)); \
})
#define __rcu_dereference_protected(p, c, space) \
({ \
	RCU_LOCKDEP_WARN(!(c), "suspicious rcu_dereference_protected() usage"); \
	rcu_dereference_sparse(p, space); \
	((typeof(*p) __force __kernel *)(p)); \
})
#define call_rcu_tasks call_rcu_sched
#define cond_resched_rcu_qs() \
do { \
	if (!cond_resched()) \
		rcu_note_voluntary_context_switch_lite(current); \
} while (0)
#define kfree_rcu(ptr, rcu_head)					\
	__kfree_rcu(&((ptr)->rcu_head), offsetof(typeof(*(ptr)), rcu_head))
#define rcu_access_pointer(p) __rcu_access_pointer((p), __rcu)
#define rcu_assign_pointer(p, v)					      \
({									      \
	uintptr_t _r_a_p__v = (uintptr_t)(v);				      \
									      \
	if (__builtin_constant_p(v) && (_r_a_p__v) == (uintptr_t)NULL)	      \
		WRITE_ONCE((p), (typeof(p))(_r_a_p__v));		      \
	else								      \
		smp_store_release(&p, RCU_INITIALIZER((typeof(p))_r_a_p__v)); \
	_r_a_p__v;							      \
})
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
#define rcu_dereference_raw_notrace(p) __rcu_dereference_check((p), 1, __rcu)
#define rcu_dereference_sched(p) rcu_dereference_sched_check(p, 0)
#define rcu_dereference_sched_check(p, c) \
	__rcu_dereference_check((p), (c) || rcu_read_lock_sched_held(), \
				__rcu)
#define rcu_dereference_sparse(p, space) \
	((void)(((typeof(*p) space *)p) == p))
# define rcu_lock_acquire(a)		do { } while (0)
# define rcu_lock_release(a)		do { } while (0)
#define rcu_note_voluntary_context_switch(t) \
	do { \
		rcu_all_qs(); \
		rcu_note_voluntary_context_switch_lite(t); \
	} while (0)
#define rcu_note_voluntary_context_switch_lite(t) \
	do { \
		if (READ_ONCE((t)->rcu_tasks_holdout)) \
			WRITE_ONCE((t)->rcu_tasks_holdout, false); \
	} while (0)
#define rcu_pointer_handoff(p) (p)
#define rcu_preempt_depth() (current->rcu_read_lock_nesting)
#define rcu_sleep_check()						\
	do {								\
		rcu_preempt_sleep_check();				\
		RCU_LOCKDEP_WARN(lock_is_held(&rcu_bh_lock_map),	\
				 "Illegal context switch in RCU-bh read-side critical section"); \
		RCU_LOCKDEP_WARN(lock_is_held(&rcu_sched_lock_map),	\
				 "Illegal context switch in RCU-sched read-side critical section"); \
	} while (0)
#define rcu_swap_protected(rcu_ptr, ptr, c) do {			\
	typeof(ptr) __tmp = rcu_dereference_protected((rcu_ptr), (c));	\
	rcu_assign_pointer((rcu_ptr), (ptr));				\
	(ptr) = __tmp;							\
} while (0)
#define smp_mb__after_unlock_lock()	smp_mb()  
#define synchronize_rcu_tasks synchronize_sched
#define ulong2long(a)		(*(long *)(&(a)))

#define rcu_note_context_switch(preempt) \
	do { \
		rcu_sched_qs(); \
		rcu_note_voluntary_context_switch_lite(current); \
	} while (0)
#define rcutree_dead_cpu         NULL
#define rcutree_dying_cpu        NULL
#define rcutree_offline_cpu      NULL
#define rcutree_online_cpu       NULL
#define rcutree_prepare_cpu      NULL

#define ktime_add(lhs, rhs)	((lhs) + (rhs))
#define ktime_add_ns(kt, nsval)		((kt) + (nsval))
#define ktime_add_unsafe(lhs, rhs)	((u64) (lhs) + (rhs))
#define ktime_sub(lhs, rhs)	((lhs) - (rhs))
#define ktime_sub_ns(kt, nsval)		((kt) - (nsval))
#define ktime_to_ns(kt)			(kt)
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


#define div64_long(x, y) div64_s64((x), (y))
#define div64_ul(x, y)   div64_u64((x), (y))

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
#define MAX_NUMNODES    (1 << NODES_SHIFT)
#define NODES_SHIFT     CONFIG_NODES_SHIFT


#define SECCOMP_RET_KILL_PROCESS 0x80000000U 


# define __hrtimer_clock_base_align

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

#define INIT_RHT_NULLS_HEAD(ptr, ht, hash) \
	((ptr) = (typeof(ptr)) rht_marker(ht, hash))

#define rhl_for_each_entry_rcu(tpos, pos, list, member)			\
	for (pos = list; pos && rht_entry(tpos, pos, member);		\
	     pos = rcu_dereference_raw(pos->next))
#define rhl_for_each_rcu(pos, list)					\
	for (pos = list; pos; pos = rcu_dereference_raw(pos->next))
#define rht_dereference(p, ht) \
	rcu_dereference_protected(p, lockdep_rht_mutex_is_held(ht))
#define rht_dereference_bucket(p, tbl, hash) \
	rcu_dereference_protected(p, lockdep_rht_bucket_is_held(tbl, hash))
#define rht_dereference_bucket_rcu(p, tbl, hash) \
	rcu_dereference_check(p, lockdep_rht_bucket_is_held(tbl, hash))
#define rht_dereference_rcu(p, ht) \
	rcu_dereference_check(p, lockdep_rht_mutex_is_held(ht))
#define rht_entry(tpos, pos, member) \
	({ tpos = container_of(pos, typeof(*tpos), member); 1; })
#define rht_for_each(pos, tbl, hash) \
	rht_for_each_continue(pos, *rht_bucket(tbl, hash), tbl, hash)
#define rht_for_each_continue(pos, head, tbl, hash) \
	for (pos = rht_dereference_bucket(head, tbl, hash); \
	     !rht_is_a_nulls(pos); \
	     pos = rht_dereference_bucket((pos)->next, tbl, hash))
#define rht_for_each_entry(tpos, pos, tbl, hash, member)		\
	rht_for_each_entry_continue(tpos, pos, *rht_bucket(tbl, hash),	\
				    tbl, hash, member)
#define rht_for_each_entry_continue(tpos, pos, head, tbl, hash, member)	\
	for (pos = rht_dereference_bucket(head, tbl, hash);		\
	     (!rht_is_a_nulls(pos)) && rht_entry(tpos, pos, member);	\
	     pos = rht_dereference_bucket((pos)->next, tbl, hash))
#define rht_for_each_entry_rcu(tpos, pos, tbl, hash, member)		   \
	rht_for_each_entry_rcu_continue(tpos, pos, *rht_bucket(tbl, hash), \
					tbl, hash, member)
#define rht_for_each_entry_rcu_continue(tpos, pos, head, tbl, hash, member) \
	for (({barrier(); }),						    \
	     pos = rht_dereference_bucket_rcu(head, tbl, hash);		    \
	     (!rht_is_a_nulls(pos)) && rht_entry(tpos, pos, member);	    \
	     pos = rht_dereference_bucket_rcu(pos->next, tbl, hash))
#define rht_for_each_entry_safe(tpos, pos, next, tbl, hash, member)	      \
	for (pos = rht_dereference_bucket(*rht_bucket(tbl, hash), tbl, hash), \
	     next = !rht_is_a_nulls(pos) ?				      \
		       rht_dereference_bucket(pos->next, tbl, hash) : NULL;   \
	     (!rht_is_a_nulls(pos)) && rht_entry(tpos, pos, member);	      \
	     pos = next,						      \
	     next = !rht_is_a_nulls(pos) ?				      \
		       rht_dereference_bucket(pos->next, tbl, hash) : NULL)
#define rht_for_each_rcu(pos, tbl, hash)				\
	rht_for_each_rcu_continue(pos, *rht_bucket(tbl, hash), tbl, hash)
#define rht_for_each_rcu_continue(pos, head, tbl, hash)			\
	for (({barrier(); }),						\
	     pos = rht_dereference_bucket_rcu(head, tbl, hash);		\
	     !rht_is_a_nulls(pos);					\
	     pos = rcu_dereference_raw(pos->next))

#define __hlist_for_each_rcu(pos, head)				\
	for (pos = rcu_dereference(hlist_first_rcu(head));	\
	     pos;						\
	     pos = rcu_dereference(hlist_next_rcu(pos)))
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
#define hlist_for_each_entry_rcu(pos, head, member)			\
	for (pos = hlist_entry_safe (rcu_dereference_raw(hlist_first_rcu(head)),\
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
	for (pos = hlist_entry_safe (rcu_dereference_raw_notrace(hlist_first_rcu(head)),\
			typeof(*(pos)), member);			\
		pos;							\
		pos = hlist_entry_safe(rcu_dereference_raw_notrace(hlist_next_rcu(\
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
#define list_for_each_entry_lockless(pos, head, member) \
	for (pos = list_entry_lockless((head)->next, typeof(*pos), member); \
	     &pos->member != (head); \
	     pos = list_entry_lockless(pos->member.next, typeof(*pos), member))
#define list_for_each_entry_rcu(pos, head, member) \
	for (pos = list_entry_rcu((head)->next, typeof(*pos), member); \
		&pos->member != (head); \
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
#define alloc_workqueue(fmt, flags, max_active, args...)		\
({									\
	static struct lock_class_key __key;				\
	const char *__lock_name;					\
									\
	__lock_name = "(wq_completion)"#fmt#args;			\
									\
	__alloc_workqueue_key((fmt), (flags), (max_active),		\
			      &__key, __lock_name, ##args);		\
})
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
#define INIT_HLIST_NULLS_HEAD(ptr, nulls) \
	((ptr)->first = (struct hlist_nulls_node *) NULLS_MARKER(nulls))
#define NULLS_MARKER(value) (1UL | (((long)value) << 1))

#define hlist_nulls_entry(ptr, type, member) container_of(ptr,type,member)
#define hlist_nulls_entry_safe(ptr, type, member) \
	({ typeof(ptr) ____ptr = (ptr); \
	   !is_a_nulls(____ptr) ? hlist_nulls_entry(____ptr, type, member) : NULL; \
	})
#define hlist_nulls_for_each_entry(tpos, pos, head, member)		       \
	for (pos = (head)->first;					       \
	     (!is_a_nulls(pos)) &&					       \
		({ tpos = hlist_nulls_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = pos->next)
#define hlist_nulls_for_each_entry_from(tpos, pos, member)	\
	for (; (!is_a_nulls(pos)) && 				\
		({ tpos = hlist_nulls_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = pos->next)

#define __jhash_final(a, b, c)			\
{						\
	c ^= b; c -= rol32(b, 14);		\
	a ^= c; a -= rol32(c, 11);		\
	b ^= a; b -= rol32(a, 25);		\
	c ^= b; c -= rol32(b, 16);		\
	a ^= c; a -= rol32(c, 4);		\
	b ^= a; b -= rol32(a, 14);		\
	c ^= b; c -= rol32(b, 24);		\
}
#define __jhash_mix(a, b, c)			\
{						\
	a -= c;  a ^= rol32(c, 4);  c += b;	\
	b -= a;  b ^= rol32(a, 6);  a += c;	\
	c -= b;  c ^= rol32(b, 8);  b += a;	\
	a -= c;  a ^= rol32(c, 16); c += b;	\
	b -= a;  b ^= rol32(a, 19); a += c;	\
	c -= b;  c ^= rol32(b, 4);  b += a;	\
}
#define jhash_mask(n)   (jhash_size(n)-1)
#define jhash_size(n)   ((u32)1<<(n))

#define IS_ERR_VALUE(x) unlikely((unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO)
#define PTR_RET(p) PTR_ERR_OR_ZERO(p)

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
				&(pid)->tasks[type], pids[type].node) {
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
#define SCHED_RESET_ON_FORK     0x40000000

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
#define VMALLOC_TOTAL (VMALLOC_END - VMALLOC_START)

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
#define __GFP_BITS_SHIFT (25 + IS_ENABLED(CONFIG_LOCKDEP))
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
#define alloc_hugepage_vma(gfp_mask, vma, addr, order)	\
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
#define topology_physical_package_id(cpu)	((void)(cpu), -1)
#define topology_sibling_cpumask(cpu)		cpumask_of(cpu)
#define DEF_PRIORITY 12
#define LRU_ACTIVE 1
#define LRU_ALL_ANON (BIT(LRU_INACTIVE_ANON) | BIT(LRU_ACTIVE_ANON))
#define LRU_ALL_FILE (BIT(LRU_INACTIVE_FILE) | BIT(LRU_ACTIVE_FILE))
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
#define PAGE_ALLOC_COSTLY_ORDER 3
#define SECTIONS_PER_ROOT       (PAGE_SIZE / sizeof (struct mem_section))
#define SECTION_ALIGN_DOWN(pfn)	((pfn) & PAGE_SECTION_MASK)
#define SECTION_ALIGN_UP(pfn)	(((pfn) + PAGES_PER_SECTION - 1) & PAGE_SECTION_MASK)
#define SECTION_BLOCKFLAGS_BITS \
	((1UL << (PFN_SECTION_SHIFT - pageblock_order)) * NR_PAGEBLOCK_BITS)
#define SECTION_NR_TO_ROOT(sec)	((sec) / SECTIONS_PER_ROOT)
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
#define high_wmark_pages(z) (z->watermark[WMARK_HIGH])
#  define is_migrate_cma(migratetype) unlikely((migratetype) == MIGRATE_CMA)
#  define is_migrate_cma_page(_page) (get_pageblock_migratetype(_page) == MIGRATE_CMA)
#define low_wmark_pages(z) (z->watermark[WMARK_LOW])
#define min_wmark_pages(z) (z->watermark[WMARK_MIN])
#define nid_page_nr(nid, pagenr) 	pgdat_page_nr(NODE_DATA(nid),(pagenr))
#define node_end_pfn(nid) pgdat_end_pfn(NODE_DATA(nid))
#define node_present_pages(nid)	(NODE_DATA(nid)->node_present_pages)
#define node_spanned_pages(nid)	(NODE_DATA(nid)->node_spanned_pages)
#define node_start_pfn(nid)	(NODE_DATA(nid)->node_start_pfn)
#define pfn_to_nid(pfn)		(0)
#define pfn_valid_within(pfn) pfn_valid(pfn)
#define pgdat_page_nr(pgdat, pagenr)	((pgdat)->node_mem_map + (pagenr))
#define sparse_index_init(_sec, _nid)  do {} while (0)
#define sparse_init()	do {} while (0)
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
#define RAW_INIT_NOTIFIER_HEAD(name) do {	\
		(name)->head = NULL;		\
	} while (0)
#define RAW_NOTIFIER_HEAD(name)					\
	struct raw_notifier_head name =				\
		RAW_NOTIFIER_INIT(name)
#define RAW_NOTIFIER_INIT(name)	{				\
		.head = NULL }

#define srcu_cleanup_notifier_head(name)	\
		cleanup_srcu_struct(&(name)->srcu);

#define __SRCU_DEP_MAP_INIT(srcu_name)	.dep_map = { .name = #srcu_name },
#define init_srcu_struct(sp) \
({ \
	static struct lock_class_key __srcu_key; \
	\
	__init_srcu_struct((sp), #sp, &__srcu_key); \
})
#define srcu_dereference(p, sp) srcu_dereference_check((p), (sp), 0)
#define srcu_dereference_check(p, sp, c) \
	__rcu_dereference_check((p), (c) || srcu_read_lock_held(sp), __rcu)
#define DEFINE_SRCU(name)		__DEFINE_SRCU(name, )
#define DEFINE_STATIC_SRCU(name)	__DEFINE_SRCU(name, static)

#define __DEFINE_SRCU(name, is_static)					\
	static DEFINE_PER_CPU(struct srcu_data, name##_srcu_data);\
	is_static struct srcu_struct name = __SRCU_STRUCT_INIT(name)
#define __SRCU_STRUCT_INIT(name)					\
	{								\
		.sda = &name##_srcu_data,				\
		.lock = __SPIN_LOCK_UNLOCKED(name.lock),		\
		.srcu_gp_seq_needed = 0 - 1,				\
		__SRCU_DEP_MAP_INIT(name)				\
	}
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
			    schedule(); try_to_freeze())
#define __wait_event_freezable_exclusive(wq, condition)				\
	___wait_event(wq, condition, TASK_INTERRUPTIBLE, 1, 0,			\
			schedule(); try_to_freeze())
#define __wait_event_freezable_timeout(wq_head, condition, timeout)		\
	___wait_event(wq_head, ___wait_cond_timeout(condition),			\
		      TASK_INTERRUPTIBLE, 0, timeout,				\
		      __ret = schedule_timeout(__ret); try_to_freeze())
#define __wait_event_hrtimeout(wq_head, condition, timeout, state)		\
({										\
	int __ret = 0;								\
	struct hrtimer_sleeper __t;						\
										\
	hrtimer_init_on_stack(&__t.timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);	\
	hrtimer_init_sleeper(&__t, current);					\
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
#define __wait_event_interruptible_lock_irq_timeout(wq_head, condition,		\
						    lock, timeout)		\
	___wait_event(wq_head, ___wait_cond_timeout(condition),			\
		      TASK_INTERRUPTIBLE, 0, timeout,				\
		      spin_unlock_irq(&lock);					\
		      __ret = schedule_timeout(__ret);				\
		      spin_lock_irq(&lock));
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
		__ret = __wait_event_interruptible_lock_irq_timeout(		\
					wq_head, condition, lock, timeout);	\
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
#define wake_up_interruptible_sync(x)	__wake_up_sync((x), TASK_INTERRUPTIBLE, 1)
#define wake_up_interruptible_sync_poll(x, m)					\
	__wake_up_sync_key((x), TASK_INTERRUPTIBLE, 1, poll_to_key(m))
#define wake_up_locked(x)		__wake_up_locked((x), TASK_NORMAL, 1)
#define wake_up_locked_poll(x, m)						\
	__wake_up_locked_key((x), TASK_NORMAL, poll_to_key(m))
#define wake_up_nr(x, nr)		__wake_up(x, TASK_NORMAL, nr, NULL)
#define wake_up_poll(x, m)							\
	__wake_up(x, TASK_NORMAL, 1, poll_to_key(m))

#  define NUM_RCU_LVL_INIT    { NUM_RCU_LVL_0 }
# define RCU_FANOUT 64
#define RCU_FANOUT_LEAF CONFIG_RCU_FANOUT_LEAF
#  define RCU_FQS_NAME_INIT   { "rcu_node_fqs_0" }
#  define RCU_NODE_NAME_INIT  { "rcu_node_0" }


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

# define __RWSEM_DEP_MAP_INIT(lockname) , .dep_map = { .name = #lockname }
#define __RWSEM_INITIALIZER(name)				\
	{ __RWSEM_INIT_COUNT(name),				\
	  .wait_list = LIST_HEAD_INIT((name).wait_list),	\
	  .wait_lock = __RAW_SPIN_LOCK_UNLOCKED(name.wait_lock)	\
	  __RWSEM_OPT_INIT(name)				\
	  __RWSEM_DEP_MAP_INIT(name) }
#define __RWSEM_INIT_COUNT(name)	.count = RWSEM_UNLOCKED_VALUE
#define __RWSEM_OPT_INIT(lockname) , .osq = OSQ_LOCK_UNLOCKED, .owner = NULL
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


#define LAST_CPUPID_SHIFT (LAST__PID_SHIFT+LAST__CPU_SHIFT)
#define LAST_CPUPID_WIDTH LAST_CPUPID_SHIFT
#define LAST__CPU_MASK  ((1 << LAST__CPU_SHIFT)-1)
#define LAST__CPU_SHIFT NR_CPUS_BITS
#define LAST__PID_MASK  ((1 << LAST__PID_SHIFT)-1)
#define LAST__PID_SHIFT 8


#define ZONES_SHIFT 0

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

#define dev_to_msi_list(dev)		(&(dev)->msi_list)
#define first_msi_entry(dev)		\
	list_first_entry(dev_to_msi_list((dev)), struct msi_desc, list)
#define first_pci_msi_entry(pdev)	first_msi_entry(&(pdev)->dev)
#define for_each_msi_entry(desc, dev)	\
	list_for_each_entry((desc), dev_to_msi_list((dev)), list)
#define for_each_pci_msi_entry(desc, pdev)	\
	for_each_msi_entry((desc), &(pdev)->dev)
#define msi_desc_to_dev(desc)		((desc)->dev)



#define KREF_INIT(n)	{ .refcount = REFCOUNT_INIT(n), }

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
	.ida_rt = RADIX_TREE_INIT(name, IDR_RT_MARKER | GFP_NOWAIT),	\
}
#define IDR_INIT(name)	IDR_INIT_BASE(name, 0)
#define IDR_INIT_BASE(name, base) {					\
	.idr_rt = RADIX_TREE_INIT(name, IDR_RT_MARKER),			\
	.idr_base = (base),						\
	.idr_next = 0,							\
}

#define idr_for_each_entry(idr, entry, id)			\
	for (id = 0; ((entry) = idr_get_next(idr, &(id))) != NULL; ++id)
#define idr_for_each_entry_continue(idr, entry, id)			\
	for ((entry) = idr_get_next((idr), &(id));			\
	     entry;							\
	     ++id, (entry) = idr_get_next((idr), &(id)))
#define idr_for_each_entry_ul(idr, entry, id)			\
	for (id = 0; ((entry) = idr_get_next_ul(idr, &(id))) != NULL; ++id)
#define INIT_RADIX_TREE(root, mask)					\
do {									\
	spin_lock_init(&(root)->xa_lock);				\
	(root)->gfp_mask = (mask);					\
	(root)->rnode = NULL;						\
} while (0)
#define RADIX_TREE(name, mask) \
	struct radix_tree_root name = RADIX_TREE_INIT(name, mask)
#define RADIX_TREE_INDEX_BITS  (8  * sizeof(unsigned long))
#define RADIX_TREE_INIT(name, mask)	{				\
	.xa_lock = __SPIN_LOCK_UNLOCKED(name.xa_lock),			\
	.gfp_mask = (mask),						\
	.rnode = NULL,							\
}
#define RADIX_TREE_MAX_PATH (DIV_ROUND_UP(RADIX_TREE_INDEX_BITS, \
					  RADIX_TREE_MAP_SHIFT))
#define RADIX_TREE_MAX_TAGS 3

#define radix_tree_for_each_contig(slot, root, iter, start)		\
	for (slot = radix_tree_iter_init(iter, start) ;			\
	     slot || (slot = radix_tree_next_chunk(root, iter,		\
				RADIX_TREE_ITER_CONTIG)) ;		\
	     slot = radix_tree_next_slot(slot, iter,			\
				RADIX_TREE_ITER_CONTIG))
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

#define pmdp_clear_flush_young_notify pmdp_clear_flush_young
#define pmdp_clear_young_notify pmdp_test_and_clear_young
#define pmdp_huge_clear_flush_notify pmdp_huge_clear_flush
#define ptep_clear_flush_young_notify ptep_clear_flush_young
#define ptep_clear_young_notify ptep_test_and_clear_young
#define pudp_huge_clear_flush_notify pudp_huge_clear_flush
#define set_pte_at_notify set_pte_at
#define AT_VECTOR_SIZE (2*(AT_VECTOR_SIZE_ARCH + AT_VECTOR_SIZE_BASE + 1))
#define AT_VECTOR_SIZE_ARCH 0
#define NULL_VM_UFFD_CTX ((struct vm_userfaultfd_ctx) { NULL, })



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

#define IS_HMM_ENABLED static_branch_unlikely(&device_private_key)
#define PAGE_ALIGN(addr) ALIGN(addr, PAGE_SIZE)
#define PAGE_ALIGNED(addr)	IS_ALIGNED((unsigned long)(addr), PAGE_SIZE)

#define VM_FAULT_DONE_COW   0x1000	
#define VM_FAULT_FALLBACK 0x0800	
#define VM_FAULT_GET_HINDEX(x) (((x) >> 12) & 0xf)
#define VM_FAULT_HWPOISON 0x0010	
#define VM_FAULT_HWPOISON_LARGE 0x0020  
#define VM_FAULT_NEEDDSYNC  0x2000	
#define VM_FAULT_RESULT_TRACE \
	{ VM_FAULT_OOM,			"OOM" }, \
	{ VM_FAULT_SIGBUS,		"SIGBUS" }, \
	{ VM_FAULT_MAJOR,		"MAJOR" }, \
	{ VM_FAULT_WRITE,		"WRITE" }, \
	{ VM_FAULT_HWPOISON,		"HWPOISON" }, \
	{ VM_FAULT_HWPOISON_LARGE,	"HWPOISON_LARGE" }, \
	{ VM_FAULT_SIGSEGV,		"SIGSEGV" }, \
	{ VM_FAULT_NOPAGE,		"NOPAGE" }, \
	{ VM_FAULT_LOCKED,		"LOCKED" }, \
	{ VM_FAULT_RETRY,		"RETRY" }, \
	{ VM_FAULT_FALLBACK,		"FALLBACK" }, \
	{ VM_FAULT_DONE_COW,		"DONE_COW" }, \
	{ VM_FAULT_NEEDDSYNC,		"NEEDDSYNC" }
#define VM_FAULT_SET_HINDEX(x) ((x) << 12)
#define VM_FAULT_SIGSEGV 0x0040
#define VM_IO           0x00004000	
#define VM_SPECIAL (VM_IO | VM_DONTEXPAND | VM_PFNMAP | VM_MIXEDMAP)
#define VM_STACK_DEFAULT_FLAGS VM_DATA_DEFAULT_FLAGS
#define VM_UNMAPPED_AREA_TOPDOWN 1

#define __pa_symbol(x)  __pa(RELOC_HIDE((unsigned long)(x), 0))
#define anon_vma_interval_tree_foreach(avc, root, start, last)		 \
	for (avc = anon_vma_interval_tree_iter_first(root, start, last); \
	     avc; avc = anon_vma_interval_tree_iter_next(avc, start, last))
#define cpupid_match_pid(task, cpupid) __cpupid_match_pid(task->pid, cpupid)
  #define expand_upwards(vma, address) (0)
#define lm_alias(x)	__va(__pa_symbol(x))
#define mm_forbids_zeropage(X)	(0)
#define mm_zero_struct_page(pp)  ((void)memset((pp), 0, sizeof(struct page)))
#define nth_page(page,n) pfn_to_page(page_to_pfn((page)) + (n))
#define offset_in_page(p)	((unsigned long)(p) & ~PAGE_MASK)
#define page_address(page) lowmem_page_address(page)
#define page_address_init()  do { } while(0)
#define page_private(page)		((page)->private)
#define page_to_virt(x)	__va(PFN_PHYS(page_to_pfn(x)))
#define pmd_huge_pte(mm, pmd) (pmd_to_page(pmd)->pmd_huge_pte)
#define pte_alloc(mm, pmd, address)			\
	(unlikely(pmd_none(*(pmd))) && __pte_alloc(mm, pmd, address))
#define pte_alloc_kernel(pmd, address)			\
	((unlikely(pmd_none(*(pmd))) && __pte_alloc_kernel(pmd, address))? \
		NULL: pte_offset_kernel(pmd, address))
#define pte_alloc_map(mm, pmd, address)			\
	(pte_alloc(mm, pmd, address) ? NULL : pte_offset_map(pmd, address))
#define pte_alloc_map_lock(mm, pmd, address, ptlp)	\
	(pte_alloc(mm, pmd, address) ?			\
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
#define set_page_private(page, v)	((page)->private = (v))
#define sysctl_legacy_va_layout 0
#define vm_normal_page(vma, addr, pte) _vm_normal_page(vma, addr, pte, false)
#define vma_interval_tree_foreach(vma, root, start, last)		\
	for (vma = vma_interval_tree_iter_first(root, start, last);	\
	     vma; vma = vma_interval_tree_iter_next(vma, start, last))
#define DISABLE_NUMA_STAT   0
#define ENABLE_NUMA_STAT   1

#define __count_zid_vm_events(item, zid, delta) \
	__count_vm_events(item##_NORMAL - ZONE_NORMAL + zid, delta)
#define add_node_page_state(__p, __i, __d) mod_node_page_state(__p, __i, __d)
#define add_zone_page_state(__z, __i, __d) mod_zone_page_state(__z, __i, __d)
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
#define sub_node_page_state(__p, __i, __d) mod_node_page_state(__p, __i, -(__d))
#define sub_zone_page_state(__z, __i, __d) mod_zone_page_state(__z, __i, -(__d))
#define sum_zone_node_page_state(node, item) global_zone_page_state(item)
#define DMA32_ZONE(xx) xx##_DMA32,
#define DMA_ZONE(xx) xx##_DMA,
#define FOR_ALL_ZONES(xx) DMA_ZONE(xx) DMA32_ZONE(xx) xx##_NORMAL, HIGHMEM_ZONE(xx) xx##_MOVABLE
#define HIGHMEM_ZONE(xx) xx##_HIGH,
#define THP_FILE_ALLOC ({ BUILD_BUG(); 0; })
#define THP_FILE_MAPPED ({ BUILD_BUG(); 0; })

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
#define IS_WHITEOUT(inode)	(S_ISCHR(inode->i_mode) && \
				 (inode)->i_rdev == WHITEOUT_DEV)
#define I_DIRTY (I_DIRTY_INODE | I_DIRTY_PAGES)
#define I_DIRTY_ALL (I_DIRTY | I_DIRTY_TIME)
#define I_DIRTY_INODE (I_DIRTY_SYNC | I_DIRTY_DATASYNC)
#define MAX_LFS_FILESIZE 	((loff_t)LLONG_MAX)
#define MAX_RW_COUNT (INT_MAX & PAGE_MASK)
#define MODULE_ALIAS_FS(NAME) MODULE_ALIAS("fs-" NAME)
#define NOMMU_VMFLAGS \
	(NOMMU_MAP_READ | NOMMU_MAP_WRITE | NOMMU_MAP_EXEC)
#define OPEN_FMODE(flag) ((__force fmode_t)(((flag + 1) & O_ACCMODE) | \
					    (flag & __FMODE_NONOTIFY)))
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
#define file_count(x)	atomic_long_read(&(x)->f_count)
#define fops_get(fops) \
	(((fops) && try_module_get((fops)->owner) ? (fops) : NULL))
#define fops_put(fops) \
	do { if (fops) module_put((fops)->owner); } while(0)
#define fput_atomic(x)	atomic_long_add_unless(&(x)->f_count, -1, 1)
#define get_file_rcu(x) atomic_long_inc_not_zero(&(x)->f_count)
#define i_size_ordered_init(inode) seqcount_init(&inode->i_size_seqcount)
#define kern_mount(type) kern_mount_data(type, NULL)
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
#define INR_OPEN_CUR 1024	
#define INR_OPEN_MAX 4096	
#define MS_MGC_MSK 0xffff0000
#define MS_MGC_VAL 0xC0ED0000
#define MS_SUBMOUNT     (1<<26)
#define NR_FILE  8192	


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

#define DEFINE_STATIC_PERCPU_RWSEM(name)				\
static DEFINE_PER_CPU(unsigned int, __percpu_rwsem_rc_##name);		\
static struct percpu_rw_semaphore name = {				\
	.rss = __RCU_SYNC_INITIALIZER(name.rss, RCU_SCHED_SYNC),	\
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
#define DEFINE_RCU_BH_SYNC(name)	\
	__DEFINE_RCU_SYNC(name, RCU_BH_SYNC)
#define DEFINE_RCU_SCHED_SYNC(name)	\
	__DEFINE_RCU_SYNC(name, RCU_SCHED_SYNC)
#define DEFINE_RCU_SYNC(name)		\
	__DEFINE_RCU_SYNC(name, RCU_SYNC)

#define __RCU_SYNC_INITIALIZER(name, type) {				\
		.gp_state = 0,						\
		.gp_count = 0,						\
		.gp_wait = __WAIT_QUEUE_HEAD_INITIALIZER(name.gp_wait),	\
		.cb_state = 0,						\
		.gp_type = type,					\
	}

#define __RCUWAIT_INITIALIZER(name)		\
	{ .task = NULL, }
#define rcuwait_wait_event(w, condition)				\
({									\
	                                                             \
	WARN_ON(current->exit_state);                                   \
									\
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

#define DEFAULT_SEEKS 2 
#define SHRINK_STOP (~0UL)


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

#define IS_GETLK(cmd)	(IS_GETLK32(cmd)  || IS_GETLK64(cmd))
#define IS_GETLK32(cmd)		((cmd) == F_GETLK)
#define IS_GETLK64(cmd)		((cmd) == F_GETLK64)
#define IS_SETLK(cmd)	(IS_SETLK32(cmd)  || IS_SETLK64(cmd))
#define IS_SETLK32(cmd)		((cmd) == F_SETLK)
#define IS_SETLK64(cmd)		((cmd) == F_SETLK64)
#define IS_SETLKW(cmd)	(IS_SETLKW32(cmd) || IS_SETLKW64(cmd))
#define IS_SETLKW32(cmd)	((cmd) == F_SETLKW)
#define IS_SETLKW64(cmd)	((cmd) == F_SETLKW64)
#define VALID_OPEN_FLAGS \
	(O_RDONLY | O_WRONLY | O_RDWR | O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC | \
	 O_APPEND | O_NDELAY | O_NONBLOCK | O_NDELAY | __O_SYNC | O_DSYNC | \
	 FASYNC	| O_DIRECT | O_LARGEFILE | O_DIRECTORY | O_NOFOLLOW | \
	 O_NOATIME | O_CLOEXEC | O_PATH | __O_TMPFILE)

#define force_o_largefile() (BITS_PER_LONG != 32)

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

#define xa_lock(xa)		spin_lock(&(xa)->xa_lock)
#define xa_lock_bh(xa)		spin_lock_bh(&(xa)->xa_lock)
#define xa_lock_irq(xa)		spin_lock_irq(&(xa)->xa_lock)
#define xa_lock_irqsave(xa, flags) \
				spin_lock_irqsave(&(xa)->xa_lock, flags)
#define xa_trylock(xa)		spin_trylock(&(xa)->xa_lock)
#define xa_unlock(xa)		spin_unlock(&(xa)->xa_lock)
#define xa_unlock_bh(xa)	spin_unlock_bh(&(xa)->xa_lock)
#define xa_unlock_irq(xa)	spin_unlock_irq(&(xa)->xa_lock)
#define xa_unlock_irqrestore(xa, flags) \
				spin_unlock_irqrestore(&(xa)->xa_lock, flags)

#define list_lru_init(lru)		__list_lru_init((lru), false, NULL)
#define list_lru_init_key(lru, key)	__list_lru_init((lru), false, (key))
#define list_lru_init_memcg(lru)	__list_lru_init((lru), true, NULL)

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

#define MAJOR(dev)	((unsigned int) ((dev) >> MINORBITS))
#define MINOR(dev)	((unsigned int) ((dev) & MINORMASK))
#define MKDEV(ma,mi)	(((ma) << MINORBITS) | (mi))

#define format_dev_t(buffer, dev)					\
	({								\
		sprintf(buffer, "%u:%u", MAJOR(dev), MINOR(dev));	\
		buffer;							\
	})
#define print_dev_t(buffer, dev)					\
	sprintf((buffer), "%u:%u\n", MAJOR(dev), MINOR(dev))

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
#define MMF_DUMPABLE_BITS 2
#define MMF_DUMPABLE_MASK ((1 << MMF_DUMPABLE_BITS) - 1)
#define MMF_DUMP_FILTER_DEFAULT \
	((1 << MMF_DUMP_ANON_PRIVATE) |	(1 << MMF_DUMP_ANON_SHARED) |\
	 (1 << MMF_DUMP_HUGETLB_PRIVATE) | MMF_DUMP_MASK_DEFAULT_ELF)
#define MMF_DUMP_FILTER_MASK \
	(((1 << MMF_DUMP_FILTER_BITS) - 1) << MMF_DUMP_FILTER_SHIFT)
#define MMF_DUMP_HUGETLB_PRIVATE 7
#define MMF_DUMP_HUGETLB_SHARED  8

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

#define PAGE_MAPCOUNT_OPS(uname, lname)					\
static __always_inline int Page##uname(struct page *page)		\
{									\
	return atomic_read(&page->_mapcount) ==				\
				PAGE_##lname##_MAPCOUNT_VALUE;		\
}									\
static __always_inline void __SetPage##uname(struct page *page)		\
{									\
	VM_BUG_ON_PAGE(atomic_read(&page->_mapcount) != -1, page);	\
	atomic_set(&page->_mapcount, PAGE_##lname##_MAPCOUNT_VALUE);	\
}									\
static __always_inline void __ClearPage##uname(struct page *page)	\
{									\
	VM_BUG_ON_PAGE(!Page##uname(page), page);			\
	atomic_set(&page->_mapcount, -1);				\
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
#define release_region(start,n)	__release_region(&ioport_resource, (start), (n))
#define rename_region(region, newname) do { (region)->name = (newname); } while (0)
#define request_mem_region(start,n,name) __request_region(&iomem_resource, (start), (n), (name), 0)
#define request_mem_region_exclusive(start,n,name) \
	__request_region(&iomem_resource, (start), (n), (name), IORESOURCE_EXCLUSIVE)
#define request_muxed_region(start,n,name)	__request_region(&ioport_resource, (start), (n), (name), IORESOURCE_MUXED)
#define request_region(start,n,name)		__request_region(&ioport_resource, (start), (n), (name), 0)

#define page_ref_tracepoint_active(t) static_key_false(&(t).key)
#define TRACEPOINT_DEFS_H 1


#define MAX_RESOURCE ((resource_size_t)~0)

#define SIG_KERNEL_COREDUMP_MASK (\
        rt_sigmask(SIGQUIT)   |  rt_sigmask(SIGILL)    | \
	rt_sigmask(SIGTRAP)   |  rt_sigmask(SIGABRT)   | \
        rt_sigmask(SIGFPE)    |  rt_sigmask(SIGSEGV)   | \
	rt_sigmask(SIGBUS)    |  rt_sigmask(SIGSYS)    | \
        rt_sigmask(SIGXCPU)   |  rt_sigmask(SIGXFSZ)   | \
	SIGEMT_MASK				       )
#define SIG_KERNEL_IGNORE_MASK (\
        rt_sigmask(SIGCONT)   |  rt_sigmask(SIGCHLD)   | \
	rt_sigmask(SIGWINCH)  |  rt_sigmask(SIGURG)    )
#define SIG_KERNEL_ONLY_MASK (\
	rt_sigmask(SIGKILL)   |  rt_sigmask(SIGSTOP))
#define SIG_KERNEL_STOP_MASK (\
	rt_sigmask(SIGSTOP)   |  rt_sigmask(SIGTSTP)   | \
	rt_sigmask(SIGTTIN)   |  rt_sigmask(SIGTTOU)   )
#define SIG_SPECIFIC_SICODES_MASK (\
	rt_sigmask(SIGILL)    |  rt_sigmask(SIGFPE)    | \
	rt_sigmask(SIGSEGV)   |  rt_sigmask(SIGBUS)    | \
	rt_sigmask(SIGTRAP)   |  rt_sigmask(SIGCHLD)   | \
	rt_sigmask(SIGPOLL)   |  rt_sigmask(SIGSYS)    | \
	SIGEMT_MASK                                    )

#define _SIG_SET_BINOP(name, op)					\
static inline void name(sigset_t *r, const sigset_t *a, const sigset_t *b) \
{									\
	unsigned long a0, a1, a2, a3, b0, b1, b2, b3;			\
									\
	switch (_NSIG_WORDS) {						\
	case 4:								\
		a3 = a->sig[3]; a2 = a->sig[2];				\
		b3 = b->sig[3]; b2 = b->sig[2];				\
		r->sig[3] = op(a3, b3);					\
		r->sig[2] = op(a2, b2);					\
	case 2:								\
		a1 = a->sig[1]; b1 = b->sig[1];				\
		r->sig[1] = op(a1, b1);					\
	case 1:								\
		a0 = a->sig[0]; b0 = b->sig[0];				\
		r->sig[0] = op(a0, b0);					\
		break;							\
	default:							\
		BUILD_BUG();						\
	}								\
}
#define _SIG_SET_OP(name, op)						\
static inline void name(sigset_t *set)					\
{									\
	switch (_NSIG_WORDS) {						\
	case 4:	set->sig[3] = op(set->sig[3]);				\
		set->sig[2] = op(set->sig[2]);				\
	case 2:	set->sig[1] = op(set->sig[1]);				\
	case 1:	set->sig[0] = op(set->sig[0]);				\
		    break;						\
	default:							\
		BUILD_BUG();						\
	}								\
}
#define _sig_and(x,y)	((x) & (y))
#define _sig_andn(x,y)	((x) & ~(y))
#define _sig_not(x)	(~(x))
#define _sig_or(x,y)	((x) | (y))
#define rt_sigmask(sig)	(1ULL << ((sig)-1))
#define save_altstack_ex(uss, sp) do { \
	stack_t __user *__uss = uss; \
	struct task_struct *t = current; \
	put_user_ex((void __user *)t->sas_ss_sp, &__uss->ss_sp); \
	put_user_ex(t->sas_ss_flags, &__uss->ss_flags); \
	put_user_ex(t->sas_ss_size, &__uss->ss_size); \
	if (t->sas_ss_flags & SS_AUTODISARM) \
		sas_ss_reset(t); \
} while (0);
#define sig_fatal(t, signr) \
	(!siginmask(signr, SIG_KERNEL_IGNORE_MASK|SIG_KERNEL_STOP_MASK) && \
	 (t)->sighand->action[(signr)-1].sa.sa_handler == SIG_DFL)
#define sig_kernel_coredump(sig)	siginmask(sig, SIG_KERNEL_COREDUMP_MASK)
#define sig_kernel_ignore(sig)		siginmask(sig, SIG_KERNEL_IGNORE_MASK)
#define sig_kernel_only(sig)		siginmask(sig, SIG_KERNEL_ONLY_MASK)
#define sig_kernel_stop(sig)		siginmask(sig, SIG_KERNEL_STOP_MASK)
#define sig_specific_sicodes(sig)	siginmask(sig, SIG_SPECIFIC_SICODES_MASK)
#define siginmask(sig, mask) \
	((sig) < SIGRTMIN && (rt_sigmask(sig) & (mask)))
#define sigmask(sig)	(1UL << ((sig) - 1))

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
#define nmi_enter()						\
	do {							\
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
	} while (0)



#define KVM_SUPPORTED_XCR0     (XFEATURE_MASK_FP | XFEATURE_MASK_SSE \
				| XFEATURE_MASK_YMM | XFEATURE_MASK_BNDREGS \
				| XFEATURE_MASK_BNDCSR | XFEATURE_MASK_AVX512 \
				| XFEATURE_MASK_PKRU)
#define MMIO_GVA_ANY (~(gva_t)0)
#define MSR_IA32_CR_PAT_DEFAULT  0x0007040600070406ULL
#define do_shl32_div32(n, base)					\
	({							\
	    u32 __quot, __rem;					\
	    asm("divl %2" : "=a" (__quot), "=d" (__rem)		\
			: "rm" (base), "0" (0), "1" ((u32) n));	\
	    n = __quot;						\
	    __rem;						\
	 })
#define PVTI_SIZE sizeof(struct pvclock_vsyscall_time_info)

#define PVCLOCK_COUNTS_FROM_ZERO (1 << 2)

#define CLOCKSOURCE_MASK(bits) GENMASK_ULL((bits) - 1, 0)
#define CLOCKSOURCE_OF_DECLARE(name, compat, fn) \
	TIMER_OF_DECLARE(name, compat, fn)
#define TIMER_ACPI_DECLARE(name, table_id, fn)		\
	ACPI_DECLARE_PROBE_ENTRY(timer, name, table_id, 0, NULL, 0, fn)
#define TIMER_OF_DECLARE(name, compat, fn) \
	OF_DECLARE_1_RET(timer, name, compat, fn)

#define MAX_PHANDLE_ARGS 16
#define OF_DECLARE_1(table, name, compat, fn) \
		_OF_DECLARE(table, name, compat, fn, of_init_fn_1)
#define OF_DECLARE_1_RET(table, name, compat, fn) \
		_OF_DECLARE(table, name, compat, fn, of_init_fn_1_ret)
#define OF_DECLARE_2(table, name, compat, fn) \
		_OF_DECLARE(table, name, compat, fn, of_init_fn_2)
#define OF_IS_DYNAMIC(x) test_bit(OF_DYNAMIC, &x->_flags)
#define OF_MARK_DYNAMIC(x) set_bit(OF_DYNAMIC, &x->_flags)
#define OF_ROOT_NODE_ADDR_CELLS_DEFAULT 1
#define OF_ROOT_NODE_SIZE_CELLS_DEFAULT 1

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
}
#define PROPERTY_ENTRY_INTEGER(_name_, _type_, _val_)	\
(struct property_entry) {				\
	.name = _name_,					\
	.length = sizeof(_type_),			\
	.is_string = false,				\
	{ .value = { ._type_##_data = _val_ } },	\
}
#define PROPERTY_ENTRY_INTEGER_ARRAY(_name_, _type_, _val_)	\
(struct property_entry) {					\
	.name = _name_,						\
	.length = ARRAY_SIZE(_val_) * sizeof(_type_),		\
	.is_array = true,					\
	.is_string = false,					\
	{ .pointer = { ._type_##_data = _val_ } },		\
}
#define PROPERTY_ENTRY_STRING(_name_, _val_)		\
(struct property_entry) {				\
	.name = _name_,					\
	.length = sizeof(_val_),			\
	.is_string = true,				\
	{ .value = { .str = _val_ } },			\
}
#define PROPERTY_ENTRY_STRING_ARRAY(_name_, _val_)		\
(struct property_entry) {					\
	.name = _name_,						\
	.length = ARRAY_SIZE(_val_) * sizeof(const char *),	\
	.is_array = true,					\
	.is_string = true,					\
	{ .pointer = { .str = _val_ } },			\
}
#define PROPERTY_ENTRY_U16(_name_, _val_)		\
	PROPERTY_ENTRY_INTEGER(_name_, u16, _val_)
#define PROPERTY_ENTRY_U16_ARRAY(_name_, _val_)			\
	PROPERTY_ENTRY_INTEGER_ARRAY(_name_, u16, _val_)
#define PROPERTY_ENTRY_U32(_name_, _val_)		\
	PROPERTY_ENTRY_INTEGER(_name_, u32, _val_)
#define PROPERTY_ENTRY_U32_ARRAY(_name_, _val_)			\
	PROPERTY_ENTRY_INTEGER_ARRAY(_name_, u32, _val_)
#define PROPERTY_ENTRY_U64(_name_, _val_)		\
	PROPERTY_ENTRY_INTEGER(_name_, u64, _val_)
#define PROPERTY_ENTRY_U64_ARRAY(_name_, _val_)			\
	PROPERTY_ENTRY_INTEGER_ARRAY(_name_, u64, _val_)
#define PROPERTY_ENTRY_U8(_name_, _val_)		\
	PROPERTY_ENTRY_INTEGER(_name_, u8, _val_)
#define PROPERTY_ENTRY_U8_ARRAY(_name_, _val_)			\
	PROPERTY_ENTRY_INTEGER_ARRAY(_name_, u8, _val_)

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

#define fwnode_call_bool_op(fwnode, op, ...)				\
	(fwnode ? (fwnode_has_op(fwnode, op) ?				\
		   (fwnode)->ops->op(fwnode, ## __VA_ARGS__) : false) : \
	 false)
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
	(_id)>>31, ((_id)>>30) & 1, ((_id)>>29) & 1, ((_id)>>28) & 1,	\
	((_id)>>27) & 1, ((_id)>>26) & 1, ((_id)>>25) & 1, ((_id)>>24) & 1, \
	((_id)>>23) & 1, ((_id)>>22) & 1, ((_id)>>21) & 1, ((_id)>>20) & 1, \
	((_id)>>19) & 1, ((_id)>>18) & 1, ((_id)>>17) & 1, ((_id)>>16) & 1, \
	((_id)>>15) & 1, ((_id)>>14) & 1, ((_id)>>13) & 1, ((_id)>>12) & 1, \
	((_id)>>11) & 1, ((_id)>>10) & 1, ((_id)>>9) & 1, ((_id)>>8) & 1, \
	((_id)>>7) & 1, ((_id)>>6) & 1, ((_id)>>5) & 1, ((_id)>>4) & 1, \
	((_id)>>3) & 1, ((_id)>>2) & 1, ((_id)>>1) & 1, (_id) & 1
#define MDIO_ID_FMT "%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d"
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
# define RETPOLINE_RAX_BPF_JIT()				\
	EMIT1_off32(0xE8, 7);	 		\
						\
	EMIT2(0xF3, 0x90);       			\
	EMIT3(0x0F, 0xAE, 0xE8); 			\
	EMIT2(0xEB, 0xF9);       		\
							\
	EMIT4(0x48, 0x89, 0x04, 0x24); 	\
	EMIT1(0xC3);             

#define __FILL_RETURN_BUFFER(reg, nr, sp)	\
	mov	$(nr/2), reg;			\
771:						\
	call	772f;				\
773:				\
	pause;					\
	lfence;					\
	jmp	773b;				\
772:						\
	call	774f;				\
775:				\
	pause;					\
	lfence;					\
	jmp	775b;				\
774:						\
	dec	reg;				\
	jnz	771b;				\
	add	$(BITS_PER_LONG/8) * nr, sp;
#define FAM10H_MMIO_CONF_BUSRANGE_SHIFT 2
#define HWP_ACTIVITY_WINDOW(x)		((unsigned long long)(x & 0xff3) << 32)
#define HWP_CHANGE_TO_GUARANTEED_INT(x)	(x & 0x1)
#define HWP_DESIRED_PERF(x)		((x & 0xff) << 16)
#define HWP_ENERGY_PERF_PREFERENCE(x)	(((unsigned long long) x & 0xff) << 24)
#define HWP_EXCURSION_TO_MINIMUM(x)	(x & 0x4)
#define HWP_EXCURSION_TO_MINIMUM_INT(x)	(x & 0x2)
#define HWP_GUARANTEED_CHANGE(x)	(x & 0x1)
#define HWP_GUARANTEED_PERF(x)		(((x) >> 8) & 0xff)
#define HWP_HIGHEST_PERF(x)		(((x) >> 0) & 0xff)
#define HWP_LOWEST_PERF(x)		(((x) >> 24) & 0xff)
#define HWP_MAX_PERF(x) 		((x & 0xff) << 8)
#define HWP_MIN_PERF(x) 		(x & 0xff)
#define HWP_MOSTEFFICIENT_PERF(x)	(((x) >> 16) & 0xff)
#define HWP_PACKAGE_CONTROL(x)		((unsigned long long)(x & 0x1) << 42)
#define MSR_AMD64_MCx_MASK(x)		(MSR_AMD64_MC0_MASK + (x))
#define MSR_HWP_REQUEST 		0x00000774
#define MSR_IA32_FEATURE_CONTROL        0x0000003a
#define MSR_IA32_MCx_ADDR(x)		(MSR_IA32_MC0_ADDR + 4*(x))
#define MSR_IA32_MCx_CTL(x)		(MSR_IA32_MC0_CTL + 4*(x))
#define MSR_IA32_MCx_CTL2(x)		(MSR_IA32_MC0_CTL2 + (x))
#define MSR_IA32_MCx_MISC(x)		(MSR_IA32_MC0_MISC + 4*(x))
#define MSR_IA32_MCx_STATUS(x)		(MSR_IA32_MC0_STATUS + 4*(x))
#define MSR_IA32_TSC_ADJUST             0x0000003b
#define MSR_IA32_VMX_BASIC              0x00000480
#define MSR_IA32_VMX_CR0_FIXED0         0x00000486
#define MSR_IA32_VMX_CR0_FIXED1         0x00000487
#define MSR_IA32_VMX_CR4_FIXED0         0x00000488
#define MSR_IA32_VMX_CR4_FIXED1         0x00000489
#define MSR_IA32_VMX_ENTRY_CTLS         0x00000484
#define MSR_IA32_VMX_EPT_VPID_CAP       0x0000048c
#define MSR_IA32_VMX_EXIT_CTLS          0x00000483
#define MSR_IA32_VMX_MISC               0x00000485
#define MSR_IA32_VMX_MISC_PREEMPTION_TIMER_SCALE   0x1F
#define MSR_IA32_VMX_MISC_VMWRITE_SHADOW_RO_FIELDS (1ULL << 29)
#define MSR_IA32_VMX_PINBASED_CTLS      0x00000481
#define MSR_IA32_VMX_PROCBASED_CTLS     0x00000482
#define MSR_IA32_VMX_PROCBASED_CTLS2    0x0000048b
#define MSR_IA32_VMX_TRUE_ENTRY_CTLS     0x00000490
#define MSR_IA32_VMX_TRUE_EXIT_CTLS      0x0000048f
#define MSR_IA32_VMX_TRUE_PINBASED_CTLS  0x0000048d
#define MSR_IA32_VMX_TRUE_PROCBASED_CTLS 0x0000048e
#define MSR_IA32_VMX_VMCS_ENUM          0x0000048a
#define MSR_IA32_VMX_VMFUNC             0x00000491
#define MSR_KNC_EVNTSEL0               0x00000028
#define MSR_KNC_EVNTSEL1               0x00000029
#define MSR_KNC_PERFCTR0               0x00000020
#define MSR_KNC_PERFCTR1               0x00000021
#define MSR_VM_CR                       0xc0010114
#define MSR_VM_HSAVE_PA                 0xc0010117
#define MSR_VM_IGNNE                    0xc0010115
#define THERM_INT_THRESHOLD0_ENABLE    (1 << 15)
#define THERM_INT_THRESHOLD1_ENABLE    (1 << 23)
#define THERM_LOG_THRESHOLD0           (1 << 7)
#define THERM_LOG_THRESHOLD1           (1 << 9)
#define THERM_MASK_THRESHOLD0          (0x7f << THERM_SHIFT_THRESHOLD0)
#define THERM_MASK_THRESHOLD1          (0x7f << THERM_SHIFT_THRESHOLD1)
#define THERM_SHIFT_THRESHOLD0        8
#define THERM_SHIFT_THRESHOLD1        16
#define THERM_STATUS_THRESHOLD0        (1 << 6)
#define THERM_STATUS_THRESHOLD1        (1 << 8)

#define X86_BUG(x)			(NCAPINTS*32 + (x))

#define DISABLED_MASK_CHECK BUILD_BUG_ON_ZERO(NCAPINTS != 19)

#define REQUIRED_MASK_CHECK BUILD_BUG_ON_ZERO(NCAPINTS != 19)


#define alt_max_short(a, b)	((a) ^ (((a) ^ (b)) & -(-((a) < (b)))))
#define ASM_CALL_CONSTRAINT "+r" (current_stack_pointer)
# define CC_OUT(c) "=@cc" #c
# define CC_SET(c) "\n\t/* output condition code " #c "*/\n"
# define _ASM_EXTABLE(from, to)					\
	_ASM_EXTABLE_HANDLE(from, to, ex_handler_default)
# define _ASM_EXTABLE_EX(from, to)				\
	_ASM_EXTABLE_HANDLE(from, to, ex_handler_ext)
# define _ASM_EXTABLE_FAULT(from, to)				\
	_ASM_EXTABLE_HANDLE(from, to, ex_handler_fault)
# define _ASM_EXTABLE_HANDLE(from, to, handler)			\
	.pushsection "__ex_table","a" ;				\
	.balign 4 ;						\
	.long (from) - . ;					\
	.long (to) - . ;					\
	.long (handler) - . ;					\
	.popsection
# define _ASM_EXTABLE_REFCOUNT(from, to)			\
	_ASM_EXTABLE_HANDLE(from, to, ex_handler_refcount)
# define _ASM_NOKPROBE(entry)					\
	.pushsection "_kprobe_blacklist","aw" ;			\
	_ASM_ALIGN ;						\
	_ASM_PTR (entry);					\
	.popsection

# define __ASM_FORM(x)	" " #x " "
# define __ASM_FORM_COMMA(x) " " #x ","
# define __ASM_FORM_RAW(x)     #x
#define __ASM_REG(reg)         __ASM_SEL_RAW(e##reg, r##reg)
# define __ASM_SEL(a,b) __ASM_FORM(a)
# define __ASM_SEL_RAW(a,b) __ASM_FORM_RAW(a)
#define __ASM_SIZE(inst, ...)	__ASM_SEL(inst##l##__VA_ARGS__, \
					  inst##q##__VA_ARGS__)
#define ALTERNATIVE(oldinstr, newinstr, feature)			\
	OLDINSTR(oldinstr, 1)						\
	".pushsection .altinstructions,\"a\"\n"				\
	ALTINSTR_ENTRY(feature, 1)					\
	".popsection\n"							\
	".pushsection .altinstr_replacement, \"ax\"\n"			\
	ALTINSTR_REPLACEMENT(newinstr, feature, 1)			\
	".popsection\n"
#define ALTERNATIVE_2(oldinstr, newinstr1, feature1, newinstr2, feature2)\
	OLDINSTR_2(oldinstr, 1, 2)					\
	".pushsection .altinstructions,\"a\"\n"				\
	ALTINSTR_ENTRY(feature1, 1)					\
	ALTINSTR_ENTRY(feature2, 2)					\
	".popsection\n"							\
	".pushsection .altinstr_replacement, \"ax\"\n"			\
	ALTINSTR_REPLACEMENT(newinstr1, feature1, 1)			\
	ALTINSTR_REPLACEMENT(newinstr2, feature2, 2)			\
	".popsection\n"
#define ALTINSTR_ENTRY(feature, num)					      \
	" .long 661b - .\n"				 \
	" .long " b_replacement(num)"f - .\n"		 \
	" .word " __stringify(feature) "\n"		 \
	" .byte " alt_total_slen "\n"			 \
	" .byte " alt_rlen(num) "\n"			 \
	" .byte " alt_pad_len "\n"			
#define ALTINSTR_REPLACEMENT(newinstr, feature, num)	     \
	b_replacement(num)":\n\t" newinstr "\n" e_replacement(num) ":\n\t"
#define ASM_NO_INPUT_CLOBBER(clbr...) "i" (0) : clbr
#define ASM_OUTPUT2(a...) a
#define LOCK_PREFIX LOCK_PREFIX_HERE "\n\tlock; "
#define LOCK_PREFIX_HERE \
		".pushsection .smp_locks,\"a\"\n"	\
		".balign 4\n"				\
		".long 671f - .\n" 		\
		".popsection\n"				\
		"671:"
#define OLDINSTR(oldinstr, num)						\
	__OLDINSTR(oldinstr, num)					\
	alt_end_marker ":\n"
#define OLDINSTR_2(oldinstr, num1, num2) \
	"661:\n\t" oldinstr "\n662:\n"								\
	".skip -((" alt_max_short(alt_rlen(num1), alt_rlen(num2)) " - (" alt_slen ")) > 0) * "	\
		"(" alt_max_short(alt_rlen(num1), alt_rlen(num2)) " - (" alt_slen ")), 0x90\n"	\
	alt_end_marker ":\n"

#define __OLDINSTR(oldinstr, num)					\
	"661:\n\t" oldinstr "\n662:\n"					\
	".skip -(((" alt_rlen(num) ")-(" alt_slen ")) > 0) * "		\
		"((" alt_rlen(num) ")-(" alt_slen ")),0x90\n"
#define alt_rlen(num)		e_replacement(num)"f-"b_replacement(num)"f"
#define alternative(oldinstr, newinstr, feature)			\
	asm volatile (ALTERNATIVE(oldinstr, newinstr, feature) : : : "memory")
#define alternative_2(oldinstr, newinstr1, feature1, newinstr2, feature2) \
	asm volatile(ALTERNATIVE_2(oldinstr, newinstr1, feature1, newinstr2, feature2) ::: "memory")
#define alternative_call(oldfunc, newfunc, feature, output, input...)	\
	asm volatile (ALTERNATIVE("call %P[old]", "call %P[new]", feature) \
		: output : [old] "i" (oldfunc), [new] "i" (newfunc), ## input)
#define alternative_call_2(oldfunc, newfunc1, feature1, newfunc2, feature2,   \
			   output, input...)				      \
	asm volatile (ALTERNATIVE_2("call %P[old]", "call %P[new1]", feature1,\
		"call %P[new2]", feature2)				      \
		: output, ASM_CALL_CONSTRAINT				      \
		: [old] "i" (oldfunc), [new1] "i" (newfunc1),		      \
		  [new2] "i" (newfunc2), ## input)
#define alternative_input(oldinstr, newinstr, feature, input...)	\
	asm volatile (ALTERNATIVE(oldinstr, newinstr, feature)		\
		: : "i" (0), ## input)
#define alternative_input_2(oldinstr, newinstr1, feature1, newinstr2,	     \
			   feature2, input...)				     \
	asm volatile(ALTERNATIVE_2(oldinstr, newinstr1, feature1,	     \
		newinstr2, feature2)					     \
		: : "i" (0), ## input)
#define alternative_io(oldinstr, newinstr, feature, output, input...)	\
	asm volatile (ALTERNATIVE(oldinstr, newinstr, feature)		\
		: output : "i" (0), ## input)
#define b_replacement(num)	"664"#num
#define e_replacement(num)	"665"#num

#define get_debugreg(var, register)				\
	(var) = native_get_debugreg(register)
#define set_debugreg(value, register)				\
	native_set_debugreg(register, value)
#define DR_CONTROL 7          
#define DR_CONTROL_RESERVED (0xFC00) 
#define DR_CONTROL_SHIFT 16 
#define DR_CONTROL_SIZE 4   
#define DR_ENABLE_SIZE 2           
#define DR_FIRSTADDR 0        
#define DR_GLOBAL_ENABLE (0x2)     
#define DR_GLOBAL_ENABLE_MASK (0xAA) 
#define DR_GLOBAL_ENABLE_SHIFT 1   
#define DR_GLOBAL_SLOWDOWN (0x200)  
#define DR_LASTADDR 3         
#define DR_LEN_1 (0x0) 
#define DR_LEN_2 (0x4)
#define DR_LEN_4 (0xC)
#define DR_LEN_8 (0x8)
#define DR_LOCAL_ENABLE (0x1)      
#define DR_LOCAL_ENABLE_MASK (0x55)  
#define DR_LOCAL_ENABLE_SHIFT 0    
#define DR_LOCAL_SLOWDOWN (0x100)   
#define DR_RW_EXECUTE (0x0)   
#define DR_RW_READ (0x3)
#define DR_RW_WRITE (0x1)
#define DR_STATUS 6           

#define EMULATION_FAILED -1
#define EMULATION_INTERCEPTED 2
#define EMULATION_OK 0
#define EMULATION_RESTART 1
#define X86EMUL_CMPXCHG_FAILED  4 
#define X86EMUL_CONTINUE        0
#define X86EMUL_CPUID_VENDOR_AMDisbetterI_ebx 0x69444d41
#define X86EMUL_CPUID_VENDOR_AMDisbetterI_ecx 0x21726574
#define X86EMUL_CPUID_VENDOR_AMDisbetterI_edx 0x74656273
#define X86EMUL_CPUID_VENDOR_AuthenticAMD_ebx 0x68747541
#define X86EMUL_CPUID_VENDOR_AuthenticAMD_ecx 0x444d4163
#define X86EMUL_CPUID_VENDOR_AuthenticAMD_edx 0x69746e65
#define X86EMUL_CPUID_VENDOR_GenuineIntel_ebx 0x756e6547
#define X86EMUL_CPUID_VENDOR_GenuineIntel_ecx 0x6c65746e
#define X86EMUL_CPUID_VENDOR_GenuineIntel_edx 0x49656e69
#define X86EMUL_GUEST_MASK           (1 << 5) 
#define X86EMUL_INTERCEPTED     6 
#define X86EMUL_IO_NEEDED       5 
#define X86EMUL_MODE_HOST X86EMUL_MODE_PROT32
#define X86EMUL_PROPAGATE_FAULT 2 
#define X86EMUL_RETRY_INSTR     3 
#define X86EMUL_SMM_INSIDE_NMI_MASK  (1 << 7)
#define X86EMUL_SMM_MASK             (1 << 6)
#define X86EMUL_UNHANDLEABLE    1

#define GDT_ENTRY_INIT(flags, base, limit)			\
	{							\
		.limit0		= (u16) (limit),		\
		.limit1		= ((limit) >> 16) & 0x0F,	\
		.base0		= (u16) (base),			\
		.base1		= ((base) >> 16) & 0xFF,	\
		.base2		= ((base) >> 24) & 0xFF,	\
		.type		= (flags & 0x0f),		\
		.s		= (flags >> 4) & 0x01,		\
		.dpl		= (flags >> 5) & 0x03,		\
		.p		= (flags >> 7) & 0x01,		\
		.avl		= (flags >> 12) & 0x01,		\
		.l		= (flags >> 13) & 0x01,		\
		.d		= (flags >> 14) & 0x01,		\
		.g		= (flags >> 15) & 0x01,		\
	}

