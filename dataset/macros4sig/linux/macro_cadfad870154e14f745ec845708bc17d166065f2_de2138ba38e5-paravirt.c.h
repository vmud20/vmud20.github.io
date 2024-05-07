


#include<linux/limits.h>










#include<asm/stat.h>

#include<asm/signal.h>





#include<asm-generic/hugetlb_encode.h>




#include<asm/ptrace.h>

#include<asm/shmbuf.h>
#include<linux/ipc.h>






#include<asm/errno.h>




#include<linux/ioctl.h>



#include<asm/ptrace-abi.h>

#include<unistd.h>
#include<asm/fcntl.h>

#include<linux/sched.h>


#include<linux/blkzoned.h>

#include<linux/fcntl.h>



#include<linux/elf-em.h>





#include<asm/resource.h>






#include<asm/processor-flags.h>






#include<linux/fs.h>
















#include<linux/time_types.h>
#include<asm/types.h>
#include<linux/seccomp.h>




#include<linux/major.h>






#include<asm/ipcbuf.h>






#include<linux/module.h>


#include<linux/sysctl.h>

#include<linux/cgroupstats.h>












#include<linux/wait.h>
























#include<linux/types.h>

#include<linux/kernel.h>






#include<linux/const.h>

#include<linux/dqblk_xfs.h>






#include<stdarg.h>

#include<linux/bpf_common.h>





#include<linux/sysinfo.h>



#include<asm/byteorder.h>
#include<asm/param.h>










#include<linux/posix_types.h>


#include<linux/capability.h>


#include<linux/stddef.h>



#include<asm/ldt.h>


#include<linux/uuid.h>
















#include<asm/poll.h>

#include<asm/auxvec.h>




#include<linux/string.h>


#include<asm/bootparam.h>







#include<linux/rseq.h>
#include<linux/time.h>


#include<asm/sembuf.h>
#include<asm/siginfo.h>
#include<linux/param.h>




#include<linux/resource.h>
#include<linux/kdev_t.h>

#include<asm/bitsperlong.h>








#include<string.h>


#include<asm/msr.h>



#include<linux/stat.h>



#include<linux/timex.h>
#include<linux/errno.h>





#define tss_invalidate_io_bitmap native_tss_invalidate_io_bitmap
#define tss_update_io_bitmap native_tss_update_io_bitmap
#define COND_POP(set, mask, reg)			\
	.if ((~(set)) & mask); pop %reg; .endif
#define COND_PUSH(set, mask, reg)			\
	.if ((~(set)) & mask); push %reg; .endif
#define DISABLE_INTERRUPTS(clobbers)					\
	PARA_SITE(PARA_PATCH(PV_IRQ_irq_disable),			\
		  PV_SAVE_REGS(clobbers | CLBR_CALLEE_SAVE);		\
		  ANNOTATE_RETPOLINE_SAFE;				\
		  call PARA_INDIRECT(pv_ops+PV_IRQ_irq_disable);	\
		  PV_RESTORE_REGS(clobbers | CLBR_CALLEE_SAVE);)
#define ENABLE_INTERRUPTS(clobbers)					\
	PARA_SITE(PARA_PATCH(PV_IRQ_irq_enable),			\
		  PV_SAVE_REGS(clobbers | CLBR_CALLEE_SAVE);		\
		  ANNOTATE_RETPOLINE_SAFE;				\
		  call PARA_INDIRECT(pv_ops+PV_IRQ_irq_enable);		\
		  PV_RESTORE_REGS(clobbers | CLBR_CALLEE_SAVE);)
#define PARA_INDIRECT(addr)	*addr(%rip)
#define PARA_PATCH(off)		((off) / 8)
#define PARA_SITE(ptype, ops)	_PVSITE(ptype, ops, .quad, 8)
#define PV_CALLEE_SAVE(func)						\
	((struct paravirt_callee_save) { __raw_callee_save_##func })
#define PV_CALLEE_SAVE_REGS_THUNK(func)					\
	extern typeof(func) __raw_callee_save_##func;			\
									\
	asm(".pushsection .text;"					\
	    ".globl " PV_THUNK_NAME(func) ";"				\
	    ".type " PV_THUNK_NAME(func) ", @function;"			\
	    PV_THUNK_NAME(func) ":"					\
	    FRAME_BEGIN							\
	    PV_SAVE_ALL_CALLER_REGS					\
	    "call " #func ";"						\
	    PV_RESTORE_ALL_CALLER_REGS					\
	    FRAME_END							\
	    "ret;"							\
	    ".size " PV_THUNK_NAME(func) ", .-" PV_THUNK_NAME(func) ";"	\
	    ".popsection")
#define PV_EXTRA_CLOBBERS EXTRA_CLOBBERS, "rcx" , "rdx", "rsi"
#define PV_FLAGS_ARG "0"
#define PV_RESTORE_REGS "popl %edx; popl %ecx;"
#define PV_SAVE_REGS "pushl %ecx; pushl %edx;"
#define PV_THUNK_NAME(func) "__raw_callee_save_" #func
#define PV_VEXTRA_CLOBBERS EXTRA_CLOBBERS, "rdi", "rcx" , "rdx", "rsi"
#define SAVE_FLAGS(clobbers)                                        \
	PARA_SITE(PARA_PATCH(PV_IRQ_save_fl),			    \
		  PV_SAVE_REGS(clobbers | CLBR_CALLEE_SAVE);        \
		  ANNOTATE_RETPOLINE_SAFE;			    \
		  call PARA_INDIRECT(pv_ops+PV_IRQ_save_fl);	    \
		  PV_RESTORE_REGS(clobbers | CLBR_CALLEE_SAVE);)

#define _PVSITE(ptype, ops, word, algn)		\
771:;						\
	ops;					\
772:;						\
	.pushsection .parainstructions,"a";	\
	 .align	algn;				\
	 word 771b;				\
	 .byte ptype;				\
	 .byte 772b-771b;			\
	.popsection
#define  __HAVE_ARCH_ENTER_LAZY_MMU_MODE
#define  __HAVE_ARCH_PTEP_MODIFY_PROT_TRANSACTION
#define  __HAVE_ARCH_START_CONTEXT_SWITCH
#define __PV_IS_CALLEE_SAVE(func)			\
	((struct paravirt_callee_save) { func })
# define default_banner x86_init_noop
#define get_debugreg(var, reg) var = paravirt_get_debugreg(reg)
#define get_kernel_rpl()  (pv_info.kernel_rpl)
#define pgd_clear(pgdp) do {						\
	if (pgtable_l5_enabled())						\
		set_pgd(pgdp, __pgd(0));				\
} while (0)
#define rdmsr(msr, val1, val2)			\
do {						\
	u64 _l = paravirt_read_msr(msr);	\
	val1 = (u32)_l;				\
	val2 = _l >> 32;			\
} while (0)
#define rdmsr_safe(msr, a, b)				\
({							\
	int _err;					\
	u64 _l = paravirt_read_msr_safe(msr, &_err);	\
	(*a) = (u32)_l;					\
	(*b) = _l >> 32;				\
	_err;						\
})
#define rdmsrl(msr, val)			\
do {						\
	val = paravirt_read_msr(msr);		\
} while (0)
#define rdpmc(counter, low, high)		\
do {						\
	u64 _l = paravirt_read_pmc(counter);	\
	low = (u32)_l;				\
	high = _l >> 32;			\
} while (0)
#define rdpmcl(counter, val) ((val) = paravirt_read_pmc(counter))
#define set_pgd(pgdp, pgdval) do {					\
	if (pgtable_l5_enabled())						\
		__set_pgd(pgdp, pgdval);				\
	else								\
		set_p4d((p4d_t *)(pgdp), (p4d_t) { (pgdval).pgd });	\
} while (0)
#define wrmsr(msr, val1, val2)			\
do {						\
	paravirt_write_msr(msr, val1, val2);	\
} while (0)
#define wrmsr_safe(msr, a, b)	paravirt_write_msr_safe(msr, a, b)


#define FRAME_END "pop %" _ASM_BP "\n"
#define FRAME_OFFSET __ASM_SEL(4, 8)

#define ASM_CALL_CONSTRAINT "+r" (current_stack_pointer)
# define CC_OUT(c) "=@cc" #c
# define CC_SET(c) "\n\t/* output condition code " #c "*/\n"
# define _ASM_EXTABLE(from, to)					\
	_ASM_EXTABLE_HANDLE(from, to, ex_handler_default)
# define _ASM_EXTABLE_FAULT(from, to)				\
	_ASM_EXTABLE_HANDLE(from, to, ex_handler_fault)
# define _ASM_EXTABLE_HANDLE(from, to, handler)			\
	" .pushsection \"__ex_table\",\"a\"\n"			\
	" .balign 4\n"						\
	" .long (" #from ") - .\n"				\
	" .long (" #to ") - .\n"				\
	" .long (" _EXPAND_EXTABLE_HANDLE(handler) ") - .\n"	\
	" .popsection\n"
# define _ASM_EXTABLE_UA(from, to)				\
	_ASM_EXTABLE_HANDLE(from, to, ex_handler_uaccess)

# define _EXPAND_EXTABLE_HANDLE(x) #x
# define __ASM_FORM(x)	" " __stringify(x) " "
# define __ASM_FORM_COMMA(x) " " __stringify(x) ","
# define __ASM_FORM_RAW(x)     __stringify(x)
#define __ASM_REG(reg)         __ASM_SEL_RAW(e##reg, r##reg)
# define __ASM_SEL(a,b) __ASM_FORM(a)
# define __ASM_SEL_RAW(a,b) __ASM_FORM_RAW(a)
#define __ASM_SIZE(inst, ...)	__ASM_SEL(inst##l##__VA_ARGS__, \
					  inst##q##__VA_ARGS__)

#define __stringify_1(x...)	#x


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
#define WARN_ON_ONCE(condition) ({				\
	int __ret_warn_on = !!(condition);			\
	if (unlikely(__ret_warn_on))				\
		__WARN_FLAGS(BUGFLAG_ONCE |			\
			     BUGFLAG_TAINT(TAINT_WARN));	\
	unlikely(__ret_warn_on);				\
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
#define __WARN_printf(taint, arg...) do {				\
		instrumentation_begin();				\
		warn_slowpath_fmt("__FILE__", "__LINE__", taint, arg);	\
		instrumentation_end();					\
	} while (0)
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
# define cant_migrate()		cant_sleep()
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
#define sysctl_oops_all_cpu_backtrace 0
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
#define READ_ONCE(x)							\
({									\
	compiletime_assert_rwonce_type(x);				\
	__READ_ONCE_SCALAR(x);						\
})
#define READ_ONCE_NOCHECK(x)						\
({									\
	unsigned long __x;						\
	compiletime_assert(sizeof(x) == sizeof(__x),			\
		"Unsupported access size for READ_ONCE_NOCHECK().");	\
	__x = __read_once_word_nocheck(&(x));				\
	smp_read_barrier_depends();					\
	(typeof(x))__x;							\
})
# define RELOC_HIDE(ptr, off)					\
  ({ unsigned long __ptr;					\
     __ptr = (unsigned long) (ptr);				\
    (typeof(ptr)) (__ptr + (off)); })
#define WRITE_ONCE(x, val)						\
do {									\
	compiletime_assert_rwonce_type(x);				\
	__WRITE_ONCE(x, val);						\
} while (0)
#define __ADDRESSABLE(sym) \
	static void * __section(.discard.addressable) __used \
		__PASTE(__addressable_##sym, "__LINE__") = (void *)&sym;

#define __READ_ONCE(x)	(*(const volatile __unqual_scalar_typeof(x) *)&(x))
#define __READ_ONCE_SCALAR(x)						\
({									\
	__unqual_scalar_typeof(x) __x = __READ_ONCE(x);			\
	smp_read_barrier_depends();					\
	(typeof(x))__x;							\
})
# define __UNIQUE_ID(prefix) __PASTE(__PASTE(__UNIQUE_ID_, prefix), "__LINE__")
#define __WRITE_ONCE(x, val)						\
do {									\
	*(volatile typeof(x) *)&(x) = (val);				\
} while (0)
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
	_compiletime_assert(condition, msg, __compiletime_assert_, __COUNTER__)
#define compiletime_assert_atomic_type(t)				\
	compiletime_assert(__native_word(t),				\
		"Need native word sized stores/loads for atomicity.")
#define compiletime_assert_rwonce_type(t)					\
	compiletime_assert(__native_word(t) || sizeof(t) == sizeof(long long),	\
		"Unsupported access size for {READ,WRITE}_ONCE().")
#define data_race(expr)							\
({									\
	__unqual_scalar_typeof(({ expr; })) __v = ({			\
		__kcsan_disable_current();				\
		expr;							\
	});								\
	__kcsan_enable_current();					\
	__v;								\
})
#define if(cond, ...) if ( __trace_if_var( !!(cond , ## __VA_ARGS__) ) )
#define instrumentation_begin() ({					\
	asm volatile("%c0:\n\t"						\
		     ".pushsection .discard.instr_begin\n\t"		\
		     ".long %c0b - .\n\t"				\
		     ".popsection\n\t" : : "i" (__COUNTER__));		\
})
#define instrumentation_end() ({					\
	asm volatile("%c0: nop\n\t"					\
		     ".pushsection .discard.instr_end\n\t"		\
		     ".long %c0b - .\n\t"				\
		     ".popsection\n\t" : : "i" (__COUNTER__));		\
})
#  define likely(x)	(__branch_check__(x, 1, __builtin_constant_p(x)))
#define likely_notrace(x)	__builtin_expect(!!(x), 1)
#define prevent_tail_call_optimization()	mb()
#  define unlikely(x)	(__branch_check__(x, 0, __builtin_constant_p(x)))
#define unlikely_notrace(x)	__builtin_expect(!!(x), 0)
# define unreachable() do {		\
	annotate_unreachable();		\
	__builtin_unreachable();	\
} while (0)
#define ASSERT_EXCLUSIVE_ACCESS(var)                                           \
	__kcsan_check_access(&(var), sizeof(var), KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT)
#define ASSERT_EXCLUSIVE_ACCESS_SCOPED(var)                                    \
	__ASSERT_EXCLUSIVE_SCOPED(var, KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT, __COUNTER__)
#define ASSERT_EXCLUSIVE_BITS(var, mask)                                       \
	do {                                                                   \
		kcsan_set_access_mask(mask);                                   \
		__kcsan_check_access(&(var), sizeof(var), KCSAN_ACCESS_ASSERT);\
		kcsan_set_access_mask(0);                                      \
		kcsan_atomic_next(1);                                          \
	} while (0)
#define ASSERT_EXCLUSIVE_WRITER(var)                                           \
	__kcsan_check_access(&(var), sizeof(var), KCSAN_ACCESS_ASSERT)
#define ASSERT_EXCLUSIVE_WRITER_SCOPED(var)                                    \
	__ASSERT_EXCLUSIVE_SCOPED(var, KCSAN_ACCESS_ASSERT, __COUNTER__)
#define KCSAN_ACCESS_ASSERT 0x4
#define KCSAN_ACCESS_ATOMIC 0x2
#define KCSAN_ACCESS_SCOPED 0x8
#define KCSAN_ACCESS_WRITE  0x1

#define __ASSERT_EXCLUSIVE_SCOPED(var, type, id)                               \
	struct kcsan_scoped_access __kcsan_scoped_name(id, _)                  \
		__kcsan_cleanup_scoped;                                        \
	struct kcsan_scoped_access *__kcsan_scoped_name(id, _dummy_p)          \
		__maybe_unused = kcsan_begin_scoped_access(                    \
			&(var), sizeof(var), KCSAN_ACCESS_SCOPED | (type),     \
			&__kcsan_scoped_name(id, _))
#define __kcsan_check_read(ptr, size) __kcsan_check_access(ptr, size, 0)
#define __kcsan_check_write(ptr, size)                                         \
	__kcsan_check_access(ptr, size, KCSAN_ACCESS_WRITE)
#define __kcsan_cleanup_scoped                                                 \
	__maybe_unused __attribute__((__cleanup__(kcsan_end_scoped_access)))
#define __kcsan_disable_current kcsan_disable_current
#define __kcsan_enable_current kcsan_enable_current_nowarn
#define __kcsan_scoped_name(c, suffix) __kcsan_scoped_##c##suffix
#define kcsan_check_access __kcsan_check_access
#define kcsan_check_atomic_read(...)	do { } while (0)
#define kcsan_check_atomic_write(...)	do { } while (0)
#define kcsan_check_read(ptr, size) kcsan_check_access(ptr, size, 0)
#define kcsan_check_write(ptr, size)                                           \
	kcsan_check_access(ptr, size, KCSAN_ACCESS_WRITE)
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

#define kasan_check_read __kasan_check_read
#define kasan_check_write __kasan_check_write
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
# define __no_kasan_or_inline __no_sanitize_address notrace __maybe_unused
#define __no_kcsan __no_sanitize_thread
# define __no_kcsan_or_inline __no_kcsan notrace __maybe_unused
# define __no_randomize_layout
# define __no_sanitize_or_inline __no_kasan_or_inline
# define __nocast
# define __noscs
# define __percpu
#define __pick_integer_type(x, type, otherwise)					\
	__pick_scalar_type(x, type,						\
		__pick_scalar_type(x, unsigned type,				\
			__pick_scalar_type(x, signed type, otherwise)))
#define __pick_scalar_type(x, type, otherwise)					\
	__builtin_choose_expr(__same_type(x, type), (type)0, otherwise)
# define __private
# define __randomize_layout __designated_init
# define __rcu		__attribute__((noderef, address_space(__rcu)))
# define __release(x)	__context__(x,-1)
# define __releases(x)	__attribute__((context(x,1,0)))
# define __safe
#define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#define __scalar_type_to_expr_cases(type)				\
		unsigned type:	(unsigned type)0,			\
		signed type:	(signed type)0
#define __unqual_scalar_typeof(x) typeof(					\
	__pick_integer_type(x, char,						\
		__pick_integer_type(x, short,					\
			__pick_integer_type(x, int,				\
				__pick_integer_type(x, long,			\
					__pick_integer_type(x, long long, x))))))
#  define __user __attribute__((user))
#define asm_inline asm __inline
#define asm_volatile_goto(x...) asm goto(x)
#define inline inline __gnu_inline __inline_maybe_unused notrace
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
#define __no_sanitize_thread __attribute__((no_sanitize_thread))
#define __noretpoline __attribute__((__indirect_branch__("keep")))
#define uninitialized_var(x) x = x
#define __builtin_bswap16 _bswap16


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
#define pr_crit(fmt, ...) \
	printk(KERN_CRIT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_crit_once(fmt, ...)					\
	printk_once(KERN_CRIT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_crit_ratelimited(fmt, ...)					\
	printk_ratelimited(KERN_CRIT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_debug(fmt, ...)			\
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
#define atomic64_cond_read_acquire(v, c) smp_cond_load_acquire(&(v)->counter, (c))
#define atomic64_cond_read_relaxed(v, c) smp_cond_load_relaxed(&(v)->counter, (c))
#define atomic_cond_read_acquire(v, c) smp_cond_load_acquire(&(v)->counter, (c))
#define atomic_cond_read_relaxed(v, c) smp_cond_load_relaxed(&(v)->counter, (c))
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


#define atomic64_add atomic64_add
#define atomic64_and atomic64_and
#define atomic64_or atomic64_or
#define atomic64_read atomic64_read
#define atomic64_set atomic64_set
#define atomic64_sub atomic64_sub
#define atomic64_xor atomic64_xor
#define atomic_add atomic_add
#define atomic_and atomic_and
#define atomic_or atomic_or
#define atomic_read atomic_read
#define atomic_set atomic_set
#define atomic_sub atomic_sub
#define atomic_xor atomic_xor
#define cmpxchg64_local(ptr, ...)						\
({									\
	typeof(ptr) __ai_ptr = (ptr);					\
	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr));		\
	arch_cmpxchg64_local(__ai_ptr, __VA_ARGS__);				\
})
#define cmpxchg64_relaxed(ptr, ...)						\
({									\
	typeof(ptr) __ai_ptr = (ptr);					\
	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr));		\
	arch_cmpxchg64_relaxed(__ai_ptr, __VA_ARGS__);				\
})
#define cmpxchg_double(ptr, ...)						\
({									\
	typeof(ptr) __ai_ptr = (ptr);					\
	instrument_atomic_write(__ai_ptr, 2 * sizeof(*__ai_ptr));		\
	arch_cmpxchg_double(__ai_ptr, __VA_ARGS__);				\
})
#define cmpxchg_double_local(ptr, ...)						\
({									\
	typeof(ptr) __ai_ptr = (ptr);					\
	instrument_atomic_write(__ai_ptr, 2 * sizeof(*__ai_ptr));		\
	arch_cmpxchg_double_local(__ai_ptr, __VA_ARGS__);				\
})
#define cmpxchg_local(ptr, ...)						\
({									\
	typeof(ptr) __ai_ptr = (ptr);					\
	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr));		\
	arch_cmpxchg_local(__ai_ptr, __VA_ARGS__);				\
})
#define cmpxchg_relaxed(ptr, ...)						\
({									\
	typeof(ptr) __ai_ptr = (ptr);					\
	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr));		\
	arch_cmpxchg_relaxed(__ai_ptr, __VA_ARGS__);				\
})
#define sync_cmpxchg(ptr, ...)						\
({									\
	typeof(ptr) __ai_ptr = (ptr);					\
	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr));		\
	arch_sync_cmpxchg(__ai_ptr, __VA_ARGS__);				\
})
#define xchg_relaxed(ptr, ...)						\
({									\
	typeof(ptr) __ai_ptr = (ptr);					\
	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr));		\
	arch_xchg_relaxed(__ai_ptr, __VA_ARGS__);				\
})

#define arch_atomic64_add_negative arch_atomic64_add_negative
#define arch_atomic64_add_return arch_atomic64_add_return
#define arch_atomic64_add_return_acquire arch_atomic64_add_return
#define arch_atomic64_add_return_relaxed arch_atomic64_add_return
#define arch_atomic64_add_return_release arch_atomic64_add_return
#define arch_atomic64_add_unless arch_atomic64_add_unless
#define arch_atomic64_andnot arch_atomic64_andnot
#define arch_atomic64_cmpxchg arch_atomic64_cmpxchg
#define arch_atomic64_cmpxchg_acquire arch_atomic64_cmpxchg
#define arch_atomic64_cmpxchg_relaxed arch_atomic64_cmpxchg
#define arch_atomic64_cmpxchg_release arch_atomic64_cmpxchg
#define arch_atomic64_dec arch_atomic64_dec
#define arch_atomic64_dec_and_test arch_atomic64_dec_and_test
#define arch_atomic64_dec_if_positive arch_atomic64_dec_if_positive
#define arch_atomic64_dec_return arch_atomic64_dec_return
#define arch_atomic64_dec_return_acquire arch_atomic64_dec_return
#define arch_atomic64_dec_return_relaxed arch_atomic64_dec_return
#define arch_atomic64_dec_return_release arch_atomic64_dec_return
#define arch_atomic64_dec_unless_positive arch_atomic64_dec_unless_positive
#define arch_atomic64_fetch_add arch_atomic64_fetch_add
#define arch_atomic64_fetch_add_acquire arch_atomic64_fetch_add
#define arch_atomic64_fetch_add_relaxed arch_atomic64_fetch_add
#define arch_atomic64_fetch_add_release arch_atomic64_fetch_add
#define arch_atomic64_fetch_add_unless arch_atomic64_fetch_add_unless
#define arch_atomic64_fetch_and arch_atomic64_fetch_and
#define arch_atomic64_fetch_and_acquire arch_atomic64_fetch_and
#define arch_atomic64_fetch_and_relaxed arch_atomic64_fetch_and
#define arch_atomic64_fetch_and_release arch_atomic64_fetch_and
#define arch_atomic64_fetch_andnot arch_atomic64_fetch_andnot
#define arch_atomic64_fetch_andnot_acquire arch_atomic64_fetch_andnot
#define arch_atomic64_fetch_andnot_relaxed arch_atomic64_fetch_andnot
#define arch_atomic64_fetch_andnot_release arch_atomic64_fetch_andnot
#define arch_atomic64_fetch_dec arch_atomic64_fetch_dec
#define arch_atomic64_fetch_dec_acquire arch_atomic64_fetch_dec
#define arch_atomic64_fetch_dec_relaxed arch_atomic64_fetch_dec
#define arch_atomic64_fetch_dec_release arch_atomic64_fetch_dec
#define arch_atomic64_fetch_inc arch_atomic64_fetch_inc
#define arch_atomic64_fetch_inc_acquire arch_atomic64_fetch_inc
#define arch_atomic64_fetch_inc_relaxed arch_atomic64_fetch_inc
#define arch_atomic64_fetch_inc_release arch_atomic64_fetch_inc
#define arch_atomic64_fetch_or arch_atomic64_fetch_or
#define arch_atomic64_fetch_or_acquire arch_atomic64_fetch_or
#define arch_atomic64_fetch_or_relaxed arch_atomic64_fetch_or
#define arch_atomic64_fetch_or_release arch_atomic64_fetch_or
#define arch_atomic64_fetch_sub arch_atomic64_fetch_sub
#define arch_atomic64_fetch_sub_acquire arch_atomic64_fetch_sub
#define arch_atomic64_fetch_sub_relaxed arch_atomic64_fetch_sub
#define arch_atomic64_fetch_sub_release arch_atomic64_fetch_sub
#define arch_atomic64_fetch_xor arch_atomic64_fetch_xor
#define arch_atomic64_fetch_xor_acquire arch_atomic64_fetch_xor
#define arch_atomic64_fetch_xor_relaxed arch_atomic64_fetch_xor
#define arch_atomic64_fetch_xor_release arch_atomic64_fetch_xor
#define arch_atomic64_inc arch_atomic64_inc
#define arch_atomic64_inc_and_test arch_atomic64_inc_and_test
#define arch_atomic64_inc_not_zero arch_atomic64_inc_not_zero
#define arch_atomic64_inc_return arch_atomic64_inc_return
#define arch_atomic64_inc_return_acquire arch_atomic64_inc_return
#define arch_atomic64_inc_return_relaxed arch_atomic64_inc_return
#define arch_atomic64_inc_return_release arch_atomic64_inc_return
#define arch_atomic64_inc_unless_negative arch_atomic64_inc_unless_negative
#define arch_atomic64_read_acquire arch_atomic64_read_acquire
#define arch_atomic64_set_release arch_atomic64_set_release
#define arch_atomic64_sub_and_test arch_atomic64_sub_and_test
#define arch_atomic64_sub_return arch_atomic64_sub_return
#define arch_atomic64_sub_return_acquire arch_atomic64_sub_return
#define arch_atomic64_sub_return_relaxed arch_atomic64_sub_return
#define arch_atomic64_sub_return_release arch_atomic64_sub_return
#define arch_atomic64_try_cmpxchg arch_atomic64_try_cmpxchg
#define arch_atomic64_try_cmpxchg_acquire arch_atomic64_try_cmpxchg
#define arch_atomic64_try_cmpxchg_relaxed arch_atomic64_try_cmpxchg
#define arch_atomic64_try_cmpxchg_release arch_atomic64_try_cmpxchg
#define arch_atomic64_xchg arch_atomic64_xchg
#define arch_atomic64_xchg_acquire arch_atomic64_xchg
#define arch_atomic64_xchg_relaxed arch_atomic64_xchg
#define arch_atomic64_xchg_release arch_atomic64_xchg
#define arch_atomic_add_negative arch_atomic_add_negative
#define arch_atomic_add_return arch_atomic_add_return
#define arch_atomic_add_return_acquire arch_atomic_add_return
#define arch_atomic_add_return_relaxed arch_atomic_add_return
#define arch_atomic_add_return_release arch_atomic_add_return
#define arch_atomic_add_unless arch_atomic_add_unless
#define arch_atomic_andnot arch_atomic_andnot
#define arch_atomic_cmpxchg arch_atomic_cmpxchg
#define arch_atomic_cmpxchg_acquire arch_atomic_cmpxchg
#define arch_atomic_cmpxchg_relaxed arch_atomic_cmpxchg
#define arch_atomic_cmpxchg_release arch_atomic_cmpxchg
#define arch_atomic_dec arch_atomic_dec
#define arch_atomic_dec_and_test arch_atomic_dec_and_test
#define arch_atomic_dec_if_positive arch_atomic_dec_if_positive
#define arch_atomic_dec_return arch_atomic_dec_return
#define arch_atomic_dec_return_acquire arch_atomic_dec_return
#define arch_atomic_dec_return_relaxed arch_atomic_dec_return
#define arch_atomic_dec_return_release arch_atomic_dec_return
#define arch_atomic_dec_unless_positive arch_atomic_dec_unless_positive
#define arch_atomic_fetch_add arch_atomic_fetch_add
#define arch_atomic_fetch_add_acquire arch_atomic_fetch_add
#define arch_atomic_fetch_add_relaxed arch_atomic_fetch_add
#define arch_atomic_fetch_add_release arch_atomic_fetch_add
#define arch_atomic_fetch_add_unless arch_atomic_fetch_add_unless
#define arch_atomic_fetch_and arch_atomic_fetch_and
#define arch_atomic_fetch_and_acquire arch_atomic_fetch_and
#define arch_atomic_fetch_and_relaxed arch_atomic_fetch_and
#define arch_atomic_fetch_and_release arch_atomic_fetch_and
#define arch_atomic_fetch_andnot arch_atomic_fetch_andnot
#define arch_atomic_fetch_andnot_acquire arch_atomic_fetch_andnot
#define arch_atomic_fetch_andnot_relaxed arch_atomic_fetch_andnot
#define arch_atomic_fetch_andnot_release arch_atomic_fetch_andnot
#define arch_atomic_fetch_dec arch_atomic_fetch_dec
#define arch_atomic_fetch_dec_acquire arch_atomic_fetch_dec
#define arch_atomic_fetch_dec_relaxed arch_atomic_fetch_dec
#define arch_atomic_fetch_dec_release arch_atomic_fetch_dec
#define arch_atomic_fetch_inc arch_atomic_fetch_inc
#define arch_atomic_fetch_inc_acquire arch_atomic_fetch_inc
#define arch_atomic_fetch_inc_relaxed arch_atomic_fetch_inc
#define arch_atomic_fetch_inc_release arch_atomic_fetch_inc
#define arch_atomic_fetch_or arch_atomic_fetch_or
#define arch_atomic_fetch_or_acquire arch_atomic_fetch_or
#define arch_atomic_fetch_or_relaxed arch_atomic_fetch_or
#define arch_atomic_fetch_or_release arch_atomic_fetch_or
#define arch_atomic_fetch_sub arch_atomic_fetch_sub
#define arch_atomic_fetch_sub_acquire arch_atomic_fetch_sub
#define arch_atomic_fetch_sub_relaxed arch_atomic_fetch_sub
#define arch_atomic_fetch_sub_release arch_atomic_fetch_sub
#define arch_atomic_fetch_xor arch_atomic_fetch_xor
#define arch_atomic_fetch_xor_acquire arch_atomic_fetch_xor
#define arch_atomic_fetch_xor_relaxed arch_atomic_fetch_xor
#define arch_atomic_fetch_xor_release arch_atomic_fetch_xor
#define arch_atomic_inc arch_atomic_inc
#define arch_atomic_inc_and_test arch_atomic_inc_and_test
#define arch_atomic_inc_not_zero arch_atomic_inc_not_zero
#define arch_atomic_inc_return arch_atomic_inc_return
#define arch_atomic_inc_return_acquire arch_atomic_inc_return
#define arch_atomic_inc_return_relaxed arch_atomic_inc_return
#define arch_atomic_inc_return_release arch_atomic_inc_return
#define arch_atomic_inc_unless_negative arch_atomic_inc_unless_negative
#define arch_atomic_read_acquire arch_atomic_read_acquire
#define arch_atomic_set_release arch_atomic_set_release
#define arch_atomic_sub_and_test arch_atomic_sub_and_test
#define arch_atomic_sub_return arch_atomic_sub_return
#define arch_atomic_sub_return_acquire arch_atomic_sub_return
#define arch_atomic_sub_return_relaxed arch_atomic_sub_return
#define arch_atomic_sub_return_release arch_atomic_sub_return
#define arch_atomic_try_cmpxchg arch_atomic_try_cmpxchg
#define arch_atomic_try_cmpxchg_acquire arch_atomic_try_cmpxchg
#define arch_atomic_try_cmpxchg_relaxed arch_atomic_try_cmpxchg
#define arch_atomic_try_cmpxchg_release arch_atomic_try_cmpxchg
#define arch_atomic_xchg arch_atomic_xchg
#define arch_atomic_xchg_acquire arch_atomic_xchg
#define arch_atomic_xchg_relaxed arch_atomic_xchg
#define arch_atomic_xchg_release arch_atomic_xchg
#define arch_cmpxchg(...) \
	__atomic_op_fence(arch_cmpxchg, __VA_ARGS__)
#define arch_cmpxchg64(...) \
	__atomic_op_fence(arch_cmpxchg64, __VA_ARGS__)
#define arch_cmpxchg64_acquire(...) \
	__atomic_op_acquire(arch_cmpxchg64, __VA_ARGS__)
#define arch_cmpxchg64_release(...) \
	__atomic_op_release(arch_cmpxchg64, __VA_ARGS__)
#define arch_cmpxchg_acquire(...) \
	__atomic_op_acquire(arch_cmpxchg, __VA_ARGS__)
#define arch_cmpxchg_release(...) \
	__atomic_op_release(arch_cmpxchg, __VA_ARGS__)
#define arch_xchg(...) \
	__atomic_op_fence(arch_xchg, __VA_ARGS__)
#define arch_xchg_acquire(...) \
	__atomic_op_acquire(arch_xchg, __VA_ARGS__)
#define arch_xchg_release(...) \
	__atomic_op_release(arch_xchg, __VA_ARGS__)
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
#define BIT_MASK(nr)		(UL(1) << ((nr) % BITS_PER_LONG))
#define BIT_ULL(nr)		(ULL(1) << (nr))
#define BIT_ULL_MASK(nr)	(ULL(1) << ((nr) % BITS_PER_LONG_LONG))
#define BIT_ULL_WORD(nr)	((nr) / BITS_PER_LONG_LONG)
#define BIT_WORD(nr)		((nr) / BITS_PER_LONG)
#define GENMASK(h, l) \
	(GENMASK_INPUT_CHECK(h, l) + __GENMASK(h, l))
#define GENMASK_INPUT_CHECK(h, l) \
	(BUILD_BUG_ON_ZERO(__builtin_choose_expr( \
		__builtin_constant_p((l) > (h)), (l) > (h), 0)))
#define GENMASK_ULL(h, l) \
	(GENMASK_INPUT_CHECK(h, l) + __GENMASK_ULL(h, l))
#define __GENMASK(h, l) \
	(((~UL(0)) - (UL(1) << (l)) + 1) & \
	 (~UL(0) >> (BITS_PER_LONG - 1 - (h))))
#define __GENMASK_ULL(h, l) \
	(((~ULL(0)) - (ULL(1) << (l)) + 1) & \
	 (~ULL(0) >> (BITS_PER_LONG_LONG - 1 - (h))))

#define BIT(nr)			(UL(1) << (nr))

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
#define MIN_THREADS_LEFT_FOR_ROOT 4
#define NR_CPUS		CONFIG_NR_CPUS
#define PID_MAX_DEFAULT (CONFIG_BASE_SMALL ? 0x1000 : 0x8000)
#define PID_MAX_LIMIT (CONFIG_BASE_SMALL ? PAGE_SIZE * 8 : \
	(sizeof(long) > 4 ? 4 * 1024 * 1024 : PID_MAX_DEFAULT))

#define CLBR_ANY  ((1 << 4) - 1)
#define CLBR_CALLEE_SAVE ((CLBR_ARG_REGS | CLBR_SCRATCH) & ~CLBR_RET_REG)
#define CLBR_EAX  (1 << 0)
#define CLBR_ECX  (1 << 1)
#define CLBR_EDI  (1 << 3)
#define CLBR_EDX  (1 << 2)
#define CLBR_NONE 0
#define CLBR_R10  (1 << 7)
#define CLBR_R11  (1 << 8)
#define CLBR_R8   (1 << 5)
#define CLBR_R9   (1 << 6)
#define CLBR_RAX  CLBR_EAX
#define CLBR_RCX  CLBR_ECX
#define CLBR_RDI  CLBR_EDI
#define CLBR_RDX  CLBR_EDX
#define CLBR_RSI  (1 << 4)

#define NATIVE_LABEL(a,x,b) "\n\t.globl " a #x "_" #b "\n" a #x "_" #b ":\n\t"
#define PARAVIRT_PATCH(x)					\
	(offsetof(struct paravirt_patch_template, x) / sizeof(void *))
#define PVOP_CALL0(rettype, op)						\
	__PVOP_CALL(rettype, op, "", "")
#define PVOP_CALL1(rettype, op, arg1)					\
	__PVOP_CALL(rettype, op, "", "", PVOP_CALL_ARG1(arg1))
#define PVOP_CALL2(rettype, op, arg1, arg2)				\
	__PVOP_CALL(rettype, op, "", "", PVOP_CALL_ARG1(arg1),		\
		    PVOP_CALL_ARG2(arg2))
#define PVOP_CALL3(rettype, op, arg1, arg2, arg3)			\
	__PVOP_CALL(rettype, op, "", "", PVOP_CALL_ARG1(arg1),		\
		    PVOP_CALL_ARG2(arg2), PVOP_CALL_ARG3(arg3))
#define PVOP_CALL4(rettype, op, arg1, arg2, arg3, arg4)			\
	__PVOP_CALL(rettype, op,					\
		    "push %[_arg4];", "lea 4(%%esp),%%esp;",		\
		    PVOP_CALL_ARG1(arg1), PVOP_CALL_ARG2(arg2),		\
		    PVOP_CALL_ARG3(arg3), [_arg4] "mr" ((u32)(arg4)))
#define PVOP_CALLEE0(rettype, op)					\
	__PVOP_CALLEESAVE(rettype, op, "", "")
#define PVOP_CALLEE1(rettype, op, arg1)					\
	__PVOP_CALLEESAVE(rettype, op, "", "", PVOP_CALL_ARG1(arg1))
#define PVOP_CALLEE2(rettype, op, arg1, arg2)				\
	__PVOP_CALLEESAVE(rettype, op, "", "", PVOP_CALL_ARG1(arg1),	\
			  PVOP_CALL_ARG2(arg2))
#define PVOP_CALL_ARG1(x)		"a" ((unsigned long)(x))
#define PVOP_CALL_ARG2(x)		"d" ((unsigned long)(x))
#define PVOP_CALL_ARG3(x)		"c" ((unsigned long)(x))
#define PVOP_CALL_ARG4(x)		"c" ((unsigned long)(x))
#define PVOP_RETMASK(rettype)						\
	({	unsigned long __mask = ~0UL;				\
		switch (sizeof(rettype)) {				\
		case 1: __mask =       0xffUL; break;			\
		case 2: __mask =     0xffffUL; break;			\
		case 4: __mask = 0xffffffffUL; break;			\
		default: break;						\
		}							\
		__mask;							\
	})
#define PVOP_TEST_NULL(op)	BUG_ON(pv_ops.op == NULL)
#define PVOP_VCALL0(op)							\
	__PVOP_VCALL(op, "", "")
#define PVOP_VCALL1(op, arg1)						\
	__PVOP_VCALL(op, "", "", PVOP_CALL_ARG1(arg1))
#define PVOP_VCALL2(op, arg1, arg2)					\
	__PVOP_VCALL(op, "", "", PVOP_CALL_ARG1(arg1),			\
		     PVOP_CALL_ARG2(arg2))
#define PVOP_VCALL3(op, arg1, arg2, arg3)				\
	__PVOP_VCALL(op, "", "", PVOP_CALL_ARG1(arg1),			\
		     PVOP_CALL_ARG2(arg2), PVOP_CALL_ARG3(arg3))
#define PVOP_VCALL4(op, arg1, arg2, arg3, arg4)				\
	__PVOP_VCALL(op,						\
		    "push %[_arg4];", "lea 4(%%esp),%%esp;",		\
		    "0" ((u32)(arg1)), "1" ((u32)(arg2)),		\
		    "2" ((u32)(arg3)), [_arg4] "mr" ((u32)(arg4)))
#define PVOP_VCALLEE0(op)						\
	__PVOP_VCALLEESAVE(op, "", "")
#define PVOP_VCALLEE1(op, arg1)						\
	__PVOP_VCALLEESAVE(op, "", "", PVOP_CALL_ARG1(arg1))
#define PVOP_VCALLEE2(op, arg1, arg2)					\
	__PVOP_VCALLEESAVE(op, "", "", PVOP_CALL_ARG1(arg1),		\
			   PVOP_CALL_ARG2(arg2))


#define __PVOP_CALL(rettype, op, pre, post, ...)			\
	____PVOP_CALL(rettype, op, CLBR_ANY, PVOP_CALL_CLOBBERS,	\
		      EXTRA_CLOBBERS, pre, post, ##__VA_ARGS__)
#define __PVOP_CALLEESAVE(rettype, op, pre, post, ...)			\
	____PVOP_CALL(rettype, op.func, CLBR_RET_REG,			\
		      PVOP_CALLEE_CLOBBERS, ,				\
		      pre, post, ##__VA_ARGS__)
#define __PVOP_VCALL(op, pre, post, ...)				\
	____PVOP_VCALL(op, CLBR_ANY, PVOP_VCALL_CLOBBERS,		\
		       VEXTRA_CLOBBERS,					\
		       pre, post, ##__VA_ARGS__)
#define __PVOP_VCALLEESAVE(op, pre, post, ...)				\
	____PVOP_VCALL(op.func, CLBR_RET_REG,				\
		      PVOP_VCALLEE_CLOBBERS, ,				\
		      pre, post, ##__VA_ARGS__)
#define ____PVOP_CALL(rettype, op, clbr, call_clbr, extra_clbr,		\
		      pre, post, ...)					\
	({								\
		rettype __ret;						\
		PVOP_CALL_ARGS;						\
		PVOP_TEST_NULL(op);					\
			\
				\
		if (sizeof(rettype) > sizeof(unsigned long)) {		\
			asm volatile(pre				\
				     paravirt_alt(PARAVIRT_CALL)	\
				     post				\
				     : call_clbr, ASM_CALL_CONSTRAINT	\
				     : paravirt_type(op),		\
				       paravirt_clobber(clbr),		\
				       ##__VA_ARGS__			\
				     : "memory", "cc" extra_clbr);	\
			__ret = (rettype)((((u64)__edx) << 32) | __eax); \
		} else {						\
			asm volatile(pre				\
				     paravirt_alt(PARAVIRT_CALL)	\
				     post				\
				     : call_clbr, ASM_CALL_CONSTRAINT	\
				     : paravirt_type(op),		\
				       paravirt_clobber(clbr),		\
				       ##__VA_ARGS__			\
				     : "memory", "cc" extra_clbr);	\
			__ret = (rettype)(__eax & PVOP_RETMASK(rettype));	\
		}							\
		__ret;							\
	})
#define ____PVOP_VCALL(op, clbr, call_clbr, extra_clbr, pre, post, ...)	\
	({								\
		PVOP_VCALL_ARGS;					\
		PVOP_TEST_NULL(op);					\
		asm volatile(pre					\
			     paravirt_alt(PARAVIRT_CALL)		\
			     post					\
			     : call_clbr, ASM_CALL_CONSTRAINT		\
			     : paravirt_type(op),			\
			       paravirt_clobber(clbr),			\
			       ##__VA_ARGS__				\
			     : "memory", "cc" extra_clbr);		\
	})
#define _paravirt_alt(insn_string, type, clobber)	\
	"771:\n\t" insn_string "\n" "772:\n"		\
	".pushsection .parainstructions,\"a\"\n"	\
	_ASM_ALIGN "\n"					\
	_ASM_PTR " 771b\n"				\
	"  .byte " type "\n"				\
	"  .byte 772b-771b\n"				\
	"  .short " clobber "\n"			\
	".popsection\n"
#define paravirt_alt(insn_string)					\
	_paravirt_alt(insn_string, "%c[paravirt_typenum]", "%c[paravirt_clobber]")
#define paravirt_clobber(clobber)		\
	[paravirt_clobber] "i" (clobber)
#define paravirt_type(op)				\
	[paravirt_typenum] "i" (PARAVIRT_PATCH(op)),	\
	[paravirt_opptr] "i" (&(pv_ops.op))



# define CALL_NOSPEC "call *%[thunk_target]\n"
#  define RETPOLINE_EDX_BPF_JIT()				\
do {								\
	EMIT1_off32(0xE8, 7);	 		\
						\
	EMIT2(0xF3, 0x90);       			\
	EMIT3(0x0F, 0xAE, 0xE8); 			\
	EMIT2(0xEB, 0xF9);       		\
							\
	EMIT3(0x89, 0x14, 0x24); 		\
	EMIT1(0xC3);             			\
} while (0)
#  define RETPOLINE_RAX_BPF_JIT()				\
do {								\
	EMIT1_off32(0xE8, 7);	 		\
						\
	EMIT2(0xF3, 0x90);       			\
	EMIT3(0x0F, 0xAE, 0xE8); 			\
	EMIT2(0xEB, 0xF9);       		\
							\
	EMIT4(0x48, 0x89, 0x04, 0x24); 	\
	EMIT1(0xC3);             			\
} while (0)
# define THUNK_TARGET(addr) [thunk_target] "r" (addr)

#define __FILL_RETURN_BUFFER(reg, nr, sp)	\
	mov	$(nr/2), reg;			\
771:						\
	ANNOTATE_INTRA_FUNCTION_CALL;		\
	call	772f;				\
773:				\
	UNWIND_HINT_EMPTY;			\
	pause;					\
	lfence;					\
	jmp	773b;				\
772:						\
	ANNOTATE_INTRA_FUNCTION_CALL;		\
	call	774f;				\
775:				\
	UNWIND_HINT_EMPTY;			\
	pause;					\
	lfence;					\
	jmp	775b;				\
774:						\
	add	$(BITS_PER_LONG/8) * 2, sp;	\
	dec	reg;				\
	jnz	771b;
#define firmware_restrict_branch_speculation_end()			\
do {									\
	u64 val = x86_spec_ctrl_base;					\
									\
	alternative_msr_write(MSR_IA32_SPEC_CTRL, val,			\
			      X86_FEATURE_USE_IBRS_FW);			\
	preempt_enable();						\
} while (0)
#define firmware_restrict_branch_speculation_start()			\
do {									\
	u64 val = x86_spec_ctrl_base | SPEC_CTRL_IBRS;			\
									\
	preempt_disable();						\
	alternative_msr_write(MSR_IA32_SPEC_CTRL, val,			\
			      X86_FEATURE_USE_IBRS_FW);			\
} while (0)
#define EARLY_IDT_HANDLER_SIZE 9
#define GDT_ENTRY(flags, base, limit)			\
	((((base)  & _AC(0xff000000,ULL)) << (56-24)) |	\
	 (((flags) & _AC(0x0000f0ff,ULL)) << 40) |	\
	 (((limit) & _AC(0x000f0000,ULL)) << (48-16)) |	\
	 (((base)  & _AC(0x00ffffff,ULL)) << 16) |	\
	 (((limit) & _AC(0x0000ffff,ULL))))
#define GDT_ENTRY_TLS_MAX 		(GDT_ENTRY_TLS_MIN + GDT_ENTRY_TLS_ENTRIES - 1)
#define SEGMENT_IS_PNP_CODE(x)		(((x) & 0xf4) == PNP_CS32)
#define XEN_EARLY_IDT_HANDLER_SIZE 8

#define __loadsegment_ds(value) __loadsegment_simple(ds, (value))
#define __loadsegment_es(value) __loadsegment_simple(es, (value))
#define __loadsegment_fs(value) __loadsegment_simple(fs, (value))
#define __loadsegment_gs(value) __loadsegment_simple(gs, (value))
#define __loadsegment_simple(seg, value)				\
do {									\
	unsigned short __val = (value);					\
									\
	asm volatile("						\n"	\
		     "1:	movl %k0,%%" #seg "		\n"	\
									\
		     ".section .fixup,\"ax\"			\n"	\
		     "2:	xorl %k0,%k0			\n"	\
		     "		jmp 1b				\n"	\
		     ".previous					\n"	\
									\
		     _ASM_EXTABLE(1b, 2b)				\
									\
		     : "+r" (__val) : : "memory");			\
} while (0)
#define __loadsegment_ss(value) __loadsegment_simple(ss, (value))
#  define get_user_gs(regs)		(u16)({ unsigned long v; savesegment(gs, v); v; })
#  define lazy_load_gs(v)		loadsegment(gs, (v))
#  define lazy_save_gs(v)		savesegment(gs, (v))
#define loadsegment(seg, value) __loadsegment_ ## seg (value)
#define savesegment(seg, value)				\
	asm("mov %%" #seg ",%0":"=r" (value) : : "memory")
#  define set_user_gs(regs, v)		loadsegment(gs, (unsigned long)(v))
#  define task_user_gs(tsk)		((tsk)->thread.gs)
#define INTERNODE_CACHE_BYTES (1 << INTERNODE_CACHE_SHIFT)
#define INTERNODE_CACHE_SHIFT CONFIG_X86_INTERNODE_CACHE_SHIFT

#define __read_mostly __attribute__((__section__(".data..read_mostly")))
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
#define ALTERNATIVE_3(oldinsn, newinsn1, feat1, newinsn2, feat2, newinsn3, feat3) \
	OLDINSTR_3(oldinsn, 1, 2, 3)						\
	".pushsection .altinstructions,\"a\"\n"					\
	ALTINSTR_ENTRY(feat1, 1)						\
	ALTINSTR_ENTRY(feat2, 2)						\
	ALTINSTR_ENTRY(feat3, 3)						\
	".popsection\n"								\
	".pushsection .altinstr_replacement, \"ax\"\n"				\
	ALTINSTR_REPLACEMENT(newinsn1, feat1, 1)				\
	ALTINSTR_REPLACEMENT(newinsn2, feat2, 2)				\
	ALTINSTR_REPLACEMENT(newinsn3, feat3, 3)				\
	".popsection\n"
#define ALTINSTR_ENTRY(feature, num)					      \
	" .long 661b - .\n"				 \
	" .long " b_replacement(num)"f - .\n"		 \
	" .word " __stringify(feature) "\n"		 \
	" .byte " alt_total_slen "\n"			 \
	" .byte " alt_rlen(num) "\n"			 \
	" .byte " alt_pad_len "\n"			
#define ALTINSTR_REPLACEMENT(newinstr, feature, num)		\
	"# ALT: replacement " #num "\n"						\
	b_replacement(num)":\n\t" newinstr "\n" e_replacement(num) ":\n"
#define ASM_NO_INPUT_CLOBBER(clbr...) "i" (0) : clbr
#define ASM_OUTPUT2(a...) a
#define LOCK_PREFIX ""
#define LOCK_PREFIX_HERE \
		".pushsection .smp_locks,\"a\"\n"	\
		".balign 4\n"				\
		".long 671f - .\n" 		\
		".popsection\n"				\
		"671:"
#define OLDINSTR(oldinstr, num)						\
	"# ALT: oldnstr\n"						\
	"661:\n\t" oldinstr "\n662:\n"					\
	"# ALT: padding\n"						\
	".skip -(((" alt_rlen(num) ")-(" alt_slen ")) > 0) * "		\
		"((" alt_rlen(num) ")-(" alt_slen ")),0x90\n"		\
	alt_end_marker ":\n"
#define OLDINSTR_2(oldinstr, num1, num2) \
	"# ALT: oldinstr2\n"									\
	"661:\n\t" oldinstr "\n662:\n"								\
	"# ALT: padding2\n"									\
	".skip -((" alt_max_short(alt_rlen(num1), alt_rlen(num2)) " - (" alt_slen ")) > 0) * "	\
		"(" alt_max_short(alt_rlen(num1), alt_rlen(num2)) " - (" alt_slen ")), 0x90\n"	\
	alt_end_marker ":\n"
#define OLDINSTR_3(oldinsn, n1, n2, n3)								\
	"# ALT: oldinstr3\n"									\
	"661:\n\t" oldinsn "\n662:\n"								\
	"# ALT: padding3\n"									\
	".skip -((" alt_max_short(alt_max_short(alt_rlen(n1), alt_rlen(n2)), alt_rlen(n3))	\
		" - (" alt_slen ")) > 0) * "							\
		"(" alt_max_short(alt_max_short(alt_rlen(n1), alt_rlen(n2)), alt_rlen(n3))	\
		" - (" alt_slen ")), 0x90\n"							\
	alt_end_marker ":\n"

#define alt_max_short(a, b)	"((" a ") ^ (((" a ") ^ (" b ")) & -(-((" a ") < (" b ")))))"
#define alt_rlen(num)		e_replacement(num)"f-"b_replacement(num)"f"
#define alternative(oldinstr, newinstr, feature)			\
	asm_inline volatile (ALTERNATIVE(oldinstr, newinstr, feature) : : : "memory")
#define alternative_2(oldinstr, newinstr1, feature1, newinstr2, feature2) \
	asm_inline volatile(ALTERNATIVE_2(oldinstr, newinstr1, feature1, newinstr2, feature2) ::: "memory")
#define alternative_call(oldfunc, newfunc, feature, output, input...)	\
	asm_inline volatile (ALTERNATIVE("call %P[old]", "call %P[new]", feature) \
		: output : [old] "i" (oldfunc), [new] "i" (newfunc), ## input)
#define alternative_call_2(oldfunc, newfunc1, feature1, newfunc2, feature2,   \
			   output, input...)				      \
	asm_inline volatile (ALTERNATIVE_2("call %P[old]", "call %P[new1]", feature1,\
		"call %P[new2]", feature2)				      \
		: output, ASM_CALL_CONSTRAINT				      \
		: [old] "i" (oldfunc), [new1] "i" (newfunc1),		      \
		  [new2] "i" (newfunc2), ## input)
#define alternative_input(oldinstr, newinstr, feature, input...)	\
	asm_inline volatile (ALTERNATIVE(oldinstr, newinstr, feature)	\
		: : "i" (0), ## input)
#define alternative_input_2(oldinstr, newinstr1, feature1, newinstr2,	     \
			   feature2, input...)				     \
	asm_inline volatile(ALTERNATIVE_2(oldinstr, newinstr1, feature1,     \
		newinstr2, feature2)					     \
		: : "i" (0), ## input)
#define alternative_io(oldinstr, newinstr, feature, output, input...)	\
	asm_inline volatile (ALTERNATIVE(oldinstr, newinstr, feature)	\
		: output : "i" (0), ## input)
#define b_replacement(num)	"664"#num
#define e_replacement(num)	"665"#num

#define EFER_FFXSR		(1<<_EFER_FFXSR)
#define EFER_LMA		(1<<_EFER_LMA)
#define EFER_LME		(1<<_EFER_LME)
#define EFER_LMSLE		(1<<_EFER_LMSLE)
#define EFER_NX			(1<<_EFER_NX)
#define EFER_SCE		(1<<_EFER_SCE)
#define EFER_SVME		(1<<_EFER_SVME)
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
#define MSR_AMD64_SEV_ENABLED		BIT_ULL(MSR_AMD64_SEV_ENABLED_BIT)
#define MSR_CORE_PERF_GLOBAL_OVF_CTRL_COND_CHGD			(1ULL << MSR_CORE_PERF_GLOBAL_OVF_CTRL_COND_CHGD_BIT)
#define MSR_CORE_PERF_GLOBAL_OVF_CTRL_OVF_BUF			(1ULL <<  MSR_CORE_PERF_GLOBAL_OVF_CTRL_OVF_BUF_BIT)
#define MSR_CORE_PERF_GLOBAL_OVF_CTRL_TRACE_TOPA_PMI		(1ULL << MSR_CORE_PERF_GLOBAL_OVF_CTRL_TRACE_TOPA_PMI_BIT)
#define MSR_F10H_DECFG_LFENCE_SERIALIZE		BIT_ULL(MSR_F10H_DECFG_LFENCE_SERIALIZE_BIT)
#define MSR_HWP_REQUEST 		0x00000774
#define MSR_IA32_CORE_CAPS_SPLIT_LOCK_DETECT	  BIT(MSR_IA32_CORE_CAPS_SPLIT_LOCK_DETECT_BIT)
#define MSR_IA32_CORE_CAPS_SPLIT_LOCK_DETECT_BIT  5
#define MSR_IA32_MCx_ADDR(x)		(MSR_IA32_MC0_ADDR + 4*(x))
#define MSR_IA32_MCx_CTL(x)		(MSR_IA32_MC0_CTL + 4*(x))
#define MSR_IA32_MCx_CTL2(x)		(MSR_IA32_MC0_CTL2 + (x))
#define MSR_IA32_MCx_MISC(x)		(MSR_IA32_MC0_MISC + 4*(x))
#define MSR_IA32_MCx_STATUS(x)		(MSR_IA32_MC0_STATUS + 4*(x))
#define MSR_IA32_MISC_ENABLE_ADJ_PREF_DISABLE		(1ULL << MSR_IA32_MISC_ENABLE_ADJ_PREF_DISABLE_BIT)
#define MSR_IA32_MISC_ENABLE_BTS_UNAVAIL		(1ULL << MSR_IA32_MISC_ENABLE_BTS_UNAVAIL_BIT)
#define MSR_IA32_MISC_ENABLE_DCU_PREF_DISABLE		(1ULL << MSR_IA32_MISC_ENABLE_DCU_PREF_DISABLE_BIT)
#define MSR_IA32_MISC_ENABLE_EMON			(1ULL << MSR_IA32_MISC_ENABLE_EMON_BIT)
#define MSR_IA32_MISC_ENABLE_ENHANCED_SPEEDSTEP		(1ULL << MSR_IA32_MISC_ENABLE_ENHANCED_SPEEDSTEP_BIT)
#define MSR_IA32_MISC_ENABLE_FAST_STRING		(1ULL << MSR_IA32_MISC_ENABLE_FAST_STRING_BIT)
#define MSR_IA32_MISC_ENABLE_FERR			(1ULL << MSR_IA32_MISC_ENABLE_FERR_BIT)
#define MSR_IA32_MISC_ENABLE_FERR_MULTIPLEX		(1ULL << MSR_IA32_MISC_ENABLE_FERR_MULTIPLEX_BIT)
#define MSR_IA32_MISC_ENABLE_IP_PREF_DISABLE		(1ULL << MSR_IA32_MISC_ENABLE_IP_PREF_DISABLE_BIT)
#define MSR_IA32_MISC_ENABLE_L1D_CONTEXT		(1ULL << MSR_IA32_MISC_ENABLE_L1D_CONTEXT_BIT)
#define MSR_IA32_MISC_ENABLE_L3CACHE_DISABLE		(1ULL << MSR_IA32_MISC_ENABLE_L3CACHE_DISABLE_BIT)
#define MSR_IA32_MISC_ENABLE_LIMIT_CPUID		(1ULL << MSR_IA32_MISC_ENABLE_LIMIT_CPUID_BIT)
#define MSR_IA32_MISC_ENABLE_MWAIT			(1ULL << MSR_IA32_MISC_ENABLE_MWAIT_BIT)
#define MSR_IA32_MISC_ENABLE_PEBS_UNAVAIL		(1ULL << MSR_IA32_MISC_ENABLE_PEBS_UNAVAIL_BIT)
#define MSR_IA32_MISC_ENABLE_PREFETCH_DISABLE		(1ULL << MSR_IA32_MISC_ENABLE_PREFETCH_DISABLE_BIT)
#define MSR_IA32_MISC_ENABLE_SPEEDSTEP_LOCK		(1ULL << MSR_IA32_MISC_ENABLE_SPEEDSTEP_LOCK_BIT)
#define MSR_IA32_MISC_ENABLE_SPLIT_LOCK_DISABLE		(1ULL << MSR_IA32_MISC_ENABLE_SPLIT_LOCK_DISABLE_BIT)
#define MSR_IA32_MISC_ENABLE_SUPPRESS_LOCK		(1ULL << MSR_IA32_MISC_ENABLE_SUPPRESS_LOCK_BIT)
#define MSR_IA32_MISC_ENABLE_TCC			(1ULL << MSR_IA32_MISC_ENABLE_TCC_BIT)
#define MSR_IA32_MISC_ENABLE_TM1			(1ULL << MSR_IA32_MISC_ENABLE_TM1_BIT)
#define MSR_IA32_MISC_ENABLE_TM2			(1ULL << MSR_IA32_MISC_ENABLE_TM2_BIT)
#define MSR_IA32_MISC_ENABLE_TURBO_DISABLE		(1ULL << MSR_IA32_MISC_ENABLE_TURBO_DISABLE_BIT)
#define MSR_IA32_MISC_ENABLE_X87_COMPAT			(1ULL << MSR_IA32_MISC_ENABLE_X87_COMPAT_BIT)
#define MSR_IA32_MISC_ENABLE_XD_DISABLE			(1ULL << MSR_IA32_MISC_ENABLE_XD_DISABLE_BIT)
#define MSR_IA32_MISC_ENABLE_XTPR_DISABLE		(1ULL << MSR_IA32_MISC_ENABLE_XTPR_DISABLE_BIT)
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
#define MSR_IA32_VMX_MISC_INTEL_PT                 (1ULL << 14)
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
#define MSR_K7_HWCR_IRPERF_EN		BIT_ULL(MSR_K7_HWCR_IRPERF_EN_BIT)
#define MSR_K7_HWCR_SMMLOCK		BIT_ULL(MSR_K7_HWCR_SMMLOCK_BIT)
#define MSR_KNC_EVNTSEL0               0x00000028
#define MSR_KNC_EVNTSEL1               0x00000029
#define MSR_KNC_PERFCTR0               0x00000020
#define MSR_KNC_PERFCTR1               0x00000021
#define MSR_MISC_FEATURES_ENABLES_CPUID_FAULT		BIT_ULL(MSR_MISC_FEATURES_ENABLES_CPUID_FAULT_BIT)
#define MSR_PLATFORM_INFO_CPUID_FAULT		BIT_ULL(MSR_PLATFORM_INFO_CPUID_FAULT_BIT)
#define MSR_TEST_CTRL_SPLIT_LOCK_DETECT		BIT(MSR_TEST_CTRL_SPLIT_LOCK_DETECT_BIT)
#define MSR_TFA_RTM_FORCE_ABORT		BIT_ULL(MSR_TFA_RTM_FORCE_ABORT_BIT)
#define MSR_VM_CR                       0xc0010114
#define MSR_VM_HSAVE_PA                 0xc0010117
#define MSR_VM_IGNNE                    0xc0010115
#define RTIT_CTL_ADDR0			(0x0full << RTIT_CTL_ADDR0_OFFSET)
#define RTIT_CTL_ADDR1			(0x0full << RTIT_CTL_ADDR1_OFFSET)
#define RTIT_CTL_ADDR2			(0x0full << RTIT_CTL_ADDR2_OFFSET)
#define RTIT_CTL_ADDR3			(0x0full << RTIT_CTL_ADDR3_OFFSET)
#define RTIT_CTL_CYC_THRESH		(0x0full << RTIT_CTL_CYC_THRESH_OFFSET)
#define RTIT_CTL_MTC_RANGE		(0x0full << RTIT_CTL_MTC_RANGE_OFFSET)
#define RTIT_CTL_PSB_FREQ		(0x0full << RTIT_CTL_PSB_FREQ_OFFSET)
#define RTIT_STATUS_BYTECNT		(0x1ffffull << RTIT_STATUS_BYTECNT_OFFSET)
#define SPEC_CTRL_SSBD			BIT(SPEC_CTRL_SSBD_SHIFT)	
#define SPEC_CTRL_STIBP			BIT(SPEC_CTRL_STIBP_SHIFT)	
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
#define X86_FEATURE_AVX512_VP2INTERSECT (18*32+ 8) 

#define DISABLED_MASK_CHECK BUILD_BUG_ON_ZERO(NCAPINTS != 19)

#define REQUIRED_MASK_CHECK BUILD_BUG_ON_ZERO(NCAPINTS != 19)



#define STACK_FRAME_NON_STANDARD(func) \
	static void __used __section(.discard.func_stack_frame_non_standard) \
		*__func_stack_frame_non_standard_##func = func

#define PAGE_COPY_NOEXEC     __pg(__PP|   0|_USR|___A|__NX|   0|   0|   0)
#define PAGE_KERNEL		__pgprot_mask(__PAGE_KERNEL            | _ENC)
#define PAGE_KERNEL_IO		__pgprot_mask(__PAGE_KERNEL_IO)
#define PAGE_KERNEL_RO		__pgprot_mask(__PAGE_KERNEL_RO         | _ENC)
#define PAGE_READONLY_EXEC   __pg(__PP|   0|_USR|___A|   0|   0|   0|   0)
#define PAGE_SHARED_EXEC     __pg(__PP|__RW|_USR|___A|   0|   0|   0|   0)

#define _ENC _PAGE_ENC
#define _HPAGE_CHG_MASK (_PAGE_CHG_MASK | _PAGE_PSE)
#define _PAGE_KNL_ERRATUM_MASK (_PAGE_DIRTY | _PAGE_ACCESSED)
#define _PAGE_PAT_LARGE (_AT(pteval_t, 1) << _PAGE_BIT_PAT_LARGE)
#define _PAGE_PKEY_MASK (_PAGE_PKEY_BIT0 | \
			 _PAGE_PKEY_BIT1 | \
			 _PAGE_PKEY_BIT2 | \
			 _PAGE_PKEY_BIT3)
#define _PSE _PAGE_PSE
#define _USR _PAGE_USER


#define __NC _PAGE_NOCACHE
#define __NX _PAGE_NX
#define __PAGE_KERNEL_LARGE_EXEC (__PP|__RW|   0|___A|   0|___D|_PSE|___G)
#define __PP _PAGE_PRESENT
#define __RW _PAGE_RW
#define __WP _PAGE_CACHE_WP
#define ___A _PAGE_ACCESSED
#define ___D _PAGE_DIRTY
#define ___G _PAGE_GLOBAL
#define __cm_idx2pte(i)					\
	((((i) & 4) << (_PAGE_BIT_PAT - 2)) |		\
	 (((i) & 2) << (_PAGE_BIT_PCD - 1)) |		\
	 (((i) & 1) << _PAGE_BIT_PWT))
#define __pg(x)			__pgprot(x)
#define __pgprot(x)		((pgprot_t) { (x) } )
#define __pgprot_mask(x)	__pgprot((x) & __default_kernel_pte_mask)
#define __pte2cm_idx(cb)				\
	((((cb) >> (_PAGE_BIT_PAT - 2)) & 4) |		\
	 (((cb) >> (_PAGE_BIT_PCD - 1)) & 2) |		\
	 (((cb) >> _PAGE_BIT_PWT) & 1))
#define native_pagetable_init        paging_init
#define pgprot_nx pgprot_nx
#define pgprot_val(x)		((x).pgprot)
#define PMD_MASK  	(~(PMD_SIZE-1))
#define PMD_SIZE  	(1UL << PMD_SHIFT)

#define __PAGETABLE_PMD_FOLDED 1
#define __pmd(x)				((pmd_t) { __pud(x) } )
#define pmd_ERROR(pmd)				(pud_ERROR((pmd).pud))
#define pmd_addr_end(addr, end)			(end)
#define pmd_alloc_one(mm, address)		NULL
#define pmd_free_tlb(tlb, x, a)		do { } while (0)
#define pmd_offset pmd_offset
#define pmd_val(x)				(pud_val((x).pud))
#define pud_page(pud)				(pmd_page((pmd_t){ pud }))
#define pud_page_vaddr(pud)			(pmd_page_vaddr((pmd_t){ pud }))
#define pud_populate(mm, pmd, pte)		do { } while (0)
#define set_pud(pudptr, pudval)			set_pmd((pmd_t *)(pudptr), (pmd_t) { pudval })
#define PUD_MASK  	(~(PUD_SIZE-1))
#define PUD_SIZE  	(1UL << PUD_SHIFT)

#define __PAGETABLE_PUD_FOLDED 1
#define __pud(x)				((pud_t) { __p4d(x) })
#define p4d_page(p4d)				(pud_page((pud_t){ p4d }))
#define p4d_page_vaddr(p4d)			(pud_page_vaddr((pud_t){ p4d }))
#define p4d_populate(mm, p4d, pud)		do { } while (0)
#define p4d_populate_safe(mm, p4d, pud)		do { } while (0)
#define pud_ERROR(pud)				(p4d_ERROR((pud).p4d))
#define pud_addr_end(addr, end)			(end)
#define pud_alloc_one(mm, address)		NULL
#define pud_free(mm, x)				do { } while (0)
#define pud_free_tlb(tlb, x, a)		        do { } while (0)
#define pud_offset pud_offset
#define pud_val(x)				(p4d_val((x).p4d))
#define set_p4d(p4dptr, p4dval)	set_pud((pud_t *)(p4dptr), (pud_t) { p4dval })

#define __PAGETABLE_P4D_FOLDED 1
#define __p4d(x)				((p4d_t) { __pgd(x) })
#define p4d_ERROR(p4d)				(pgd_ERROR((p4d).pgd))
#define p4d_addr_end(addr, end)			(end)
#define p4d_alloc_one(mm, address)		NULL
#define p4d_free(mm, x)				do { } while (0)
#define p4d_free_tlb(tlb, x, a)			do { } while (0)
#define p4d_val(x)				(pgd_val((x).pgd))
#define pgd_page(pgd)				(p4d_page((p4d_t){ pgd }))
#define pgd_page_vaddr(pgd)			(p4d_page_vaddr((p4d_t){ pgd }))
#define pgd_populate(mm, pgd, p4d)		do { } while (0)
#define pgd_populate_safe(mm, pgd, p4d)		do { } while (0)
#define HUGE_MAX_HSTATE 2
#define IOREMAP_MAX_ORDER       (PUD_SHIFT)
#define PAGE_OFFSET		((unsigned long)__PAGE_OFFSET)

#define __PHYSICAL_MASK		((phys_addr_t)((1ULL << __PHYSICAL_MASK_SHIFT) - 1))
#define __START_KERNEL		(__START_KERNEL_map + __PHYSICAL_START)
#define __VIRTUAL_MASK		((1UL << __VIRTUAL_MASK_SHIFT) - 1)
#define THREAD_SIZE		(PAGE_SIZE << THREAD_SIZE_ORDER)

#define __PAGE_OFFSET		__PAGE_OFFSET_BASE
#define EXCEPTION_STACK_ORDER (0 + KASAN_STACK_ORDER)
#define EXCEPTION_STKSZ (PAGE_SIZE << EXCEPTION_STACK_ORDER)
#define IRQ_STACK_ORDER (2 + KASAN_STACK_ORDER)
#define IRQ_STACK_SIZE (PAGE_SIZE << IRQ_STACK_ORDER)
#define KASAN_STACK_ORDER 1



#define __sme_clr(x)		((x) & ~sme_me_mask)
#define __sme_set(x)		((x) | sme_me_mask)

#define  __WITH_KM_FENCE
# define KM_TYPE_NR 41

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

# define ARCH_HAS_PREFETCH


#define GET_TSC_CTL(adr)	get_tsc_mode((adr))
#define HAVE_ARCH_PICK_MMAP_LAYOUT 1
#define HBP_NUM 4
#define INIT_THREAD  {							  \
	.sp0			= TOP_OF_INIT_STACK,			  \
	.sysenter_cs		= __KERNEL_CS,				  \
	.addr_limit		= KERNEL_DS,				  \
}
#define KSTK_EIP(task)		(task_pt_regs(task)->ip)
#define KSTK_ESP(task)		(task_pt_regs(task)->sp)
#define SET_TSC_CTL(val)	set_tsc_mode((val))
#define TASK_SIZE_OF(child)	((test_tsk_thread_flag(child, TIF_ADDR32)) ? \
					IA32_PAGE_OFFSET : TASK_SIZE_MAX)
#define TASK_UNMAPPED_BASE		__TASK_UNMAPPED_BASE(TASK_SIZE_LOW)
#define TOP_OF_INIT_STACK ((unsigned long)&init_stack + sizeof(init_stack) - \
			   TOP_OF_KERNEL_STACK_PADDING)

#define __TASK_UNMAPPED_BASE(task_size)	(PAGE_ALIGN(task_size / 3))
#define cache_line_size()	(boot_cpu_data.x86_cache_alignment)
#define cpu_current_top_of_stack cpu_tss_rw.x86_tss.sp1
#define cpu_data(cpu)		per_cpu(cpu_info, cpu)
#define native_cpuid_reg(reg)					\
static inline unsigned int native_cpuid_##reg(unsigned int op)	\
{								\
	unsigned int eax = op, ebx, ecx = 0, edx;		\
								\
	native_cpuid(&eax, &ebx, &ecx, &edx);			\
								\
	return reg;						\
}
#define task_pt_regs(task) \
({									\
	unsigned long __ptr = (unsigned long)task_stack_page(task);	\
	__ptr += THREAD_SIZE - TOP_OF_KERNEL_STACK_PADDING;		\
	((struct pt_regs *)__ptr) - 1;					\
})
#define task_top_of_stack(task) ((unsigned long)(task_pt_regs(task) + 1))
#define xen_set_default_idle 0

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
# define lockdep_hardirq_context(p)	0
# define lockdep_hardirq_enter()	do { } while (0)
# define lockdep_hardirq_exit()		do { } while (0)
# define lockdep_hardirq_threaded()	do { } while (0)
# define lockdep_hardirqs_enabled(p)	0
# define lockdep_hrtimer_enter(__hrtimer)	false
# define lockdep_hrtimer_exit(__context)	do { } while (0)
# define lockdep_irq_work_enter(__work)		do { } while (0)
# define lockdep_irq_work_exit(__work)		do { } while (0)
# define lockdep_posixtimer_enter()		do { } while (0)
# define lockdep_posixtimer_exit()		do { } while (0)
# define lockdep_softirq_context(p)	0
# define lockdep_softirq_enter()	do { } while (0)
# define lockdep_softirq_exit()		do { } while (0)
# define lockdep_softirqs_enabled(p)	0
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
# define trace_hardirqs_off()		do { } while (0)
# define trace_hardirqs_off_finish()		do { } while (0)
# define trace_hardirqs_on()		do { } while (0)
# define trace_hardirqs_on_prepare()		do { } while (0)
#define IS_ERR_VALUE(x) unlikely((unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO)

#define DIV64_U64_ROUND_CLOSEST(dividend, divisor)	\
	({ u64 _tmp = (divisor); div64_u64((dividend) + _tmp / 2, _tmp); })
#define DIV64_U64_ROUND_UP(ll, d)	\
	({ u64 _tmp = (d); div64_u64((ll) + _tmp - 1, _tmp); })

#define div64_long(x, y) div64_s64((x), (y))
#define div64_ul(x, y)   div64_u64((x), (y))


#define personality(pers)	(pers & PER_MASK)
#define set_personality(pers)	(current->personality = (pers))
#define PER_CLEAR_ON_SETID (READ_IMPLIES_EXEC  | \
			    ADDR_NO_RANDOMIZE  | \
			    ADDR_COMPAT_LAYOUT | \
			    MMAP_PAGE_ZERO)


#define VMX_FEATURE_INTR_WINDOW_EXITING ( 1*32+  2) 

#define MXCSR_AND_FLAGS_SIZE sizeof(u64)
#define XCOMP_BV_COMPACTED_FORMAT ((u64)1 << 63)


#define nop() asm volatile ("nop")

#define X86_CR0_AM		_BITUL(X86_CR0_AM_BIT)
#define X86_CR0_CD		_BITUL(X86_CR0_CD_BIT)
#define X86_CR0_EM		_BITUL(X86_CR0_EM_BIT)
#define X86_CR0_ET		_BITUL(X86_CR0_ET_BIT)
#define X86_CR0_MP		_BITUL(X86_CR0_MP_BIT)
#define X86_CR0_NE		_BITUL(X86_CR0_NE_BIT)
#define X86_CR0_NW		_BITUL(X86_CR0_NW_BIT)
#define X86_CR0_PE		_BITUL(X86_CR0_PE_BIT)
#define X86_CR0_PG		_BITUL(X86_CR0_PG_BIT)
#define X86_CR0_TS		_BITUL(X86_CR0_TS_BIT)
#define X86_CR0_WP		_BITUL(X86_CR0_WP_BIT)
#define X86_CR3_PCD		_BITUL(X86_CR3_PCD_BIT)
#define X86_CR3_PCID_NOFLUSH    _BITULL(X86_CR3_PCID_NOFLUSH_BIT)
#define X86_CR3_PCID_NOFLUSH_BIT 63 
#define X86_CR3_PWT		_BITUL(X86_CR3_PWT_BIT)
#define X86_CR4_DE		_BITUL(X86_CR4_DE_BIT)
#define X86_CR4_LA57		_BITUL(X86_CR4_LA57_BIT)
#define X86_CR4_MCE		_BITUL(X86_CR4_MCE_BIT)
#define X86_CR4_OSFXSR		_BITUL(X86_CR4_OSFXSR_BIT)
#define X86_CR4_OSXSAVE		_BITUL(X86_CR4_OSXSAVE_BIT)
#define X86_CR4_PAE		_BITUL(X86_CR4_PAE_BIT)
#define X86_CR4_PCE		_BITUL(X86_CR4_PCE_BIT)
#define X86_CR4_PCIDE		_BITUL(X86_CR4_PCIDE_BIT)
#define X86_CR4_PGE		_BITUL(X86_CR4_PGE_BIT)
#define X86_CR4_PKE		_BITUL(X86_CR4_PKE_BIT)
#define X86_CR4_PSE		_BITUL(X86_CR4_PSE_BIT)
#define X86_CR4_PVI		_BITUL(X86_CR4_PVI_BIT)
#define X86_CR4_SMAP		_BITUL(X86_CR4_SMAP_BIT)
#define X86_CR4_SMEP		_BITUL(X86_CR4_SMEP_BIT)
#define X86_CR4_SMXE		_BITUL(X86_CR4_SMXE_BIT)
#define X86_CR4_TSD		_BITUL(X86_CR4_TSD_BIT)
#define X86_CR4_UMIP		_BITUL(X86_CR4_UMIP_BIT)
#define X86_CR4_VME		_BITUL(X86_CR4_VME_BIT)
#define X86_CR4_VMXE		_BITUL(X86_CR4_VMXE_BIT)
#define X86_EFLAGS_AC		_BITUL(X86_EFLAGS_AC_BIT)
#define X86_EFLAGS_AF		_BITUL(X86_EFLAGS_AF_BIT)
#define X86_EFLAGS_CF		_BITUL(X86_EFLAGS_CF_BIT)
#define X86_EFLAGS_DF		_BITUL(X86_EFLAGS_DF_BIT)
#define X86_EFLAGS_ID		_BITUL(X86_EFLAGS_ID_BIT)
#define X86_EFLAGS_IF		_BITUL(X86_EFLAGS_IF_BIT)
#define X86_EFLAGS_IOPL		(_AC(3,UL) << X86_EFLAGS_IOPL_BIT)
#define X86_EFLAGS_NT		_BITUL(X86_EFLAGS_NT_BIT)
#define X86_EFLAGS_OF		_BITUL(X86_EFLAGS_OF_BIT)
#define X86_EFLAGS_PF		_BITUL(X86_EFLAGS_PF_BIT)
#define X86_EFLAGS_RF		_BITUL(X86_EFLAGS_RF_BIT)
#define X86_EFLAGS_SF		_BITUL(X86_EFLAGS_SF_BIT)
#define X86_EFLAGS_TF		_BITUL(X86_EFLAGS_TF_BIT)
#define X86_EFLAGS_VIF		_BITUL(X86_EFLAGS_VIF_BIT)
#define X86_EFLAGS_VIP		_BITUL(X86_EFLAGS_VIP_BIT)
#define X86_EFLAGS_VM		_BITUL(X86_EFLAGS_VM_BIT)
#define X86_EFLAGS_ZF		_BITUL(X86_EFLAGS_ZF_BIT)

#define ASM_NOP1 _ASM_MK_NOP(P6_NOP1)
#define ASM_NOP2 _ASM_MK_NOP(P6_NOP2)
#define ASM_NOP3 _ASM_MK_NOP(K7_NOP3)
#define ASM_NOP4 _ASM_MK_NOP(K7_NOP4)
#define ASM_NOP5 _ASM_MK_NOP(K7_NOP5)
#define ASM_NOP5_ATOMIC _ASM_MK_NOP(K7_NOP5_ATOMIC)
#define ASM_NOP6 _ASM_MK_NOP(K7_NOP6)
#define ASM_NOP7 _ASM_MK_NOP(K7_NOP7)
#define ASM_NOP8 _ASM_MK_NOP(K7_NOP8)
#define ASM_NOP_MAX 8
#define GENERIC_NOP1 0x90
#define GENERIC_NOP2 0x89,0xf6
#define GENERIC_NOP3 0x8d,0x76,0x00
#define GENERIC_NOP4 0x8d,0x74,0x26,0x00
#define GENERIC_NOP5 GENERIC_NOP1,GENERIC_NOP4
#define GENERIC_NOP5_ATOMIC NOP_DS_PREFIX,GENERIC_NOP4
#define GENERIC_NOP6 0x8d,0xb6,0x00,0x00,0x00,0x00
#define GENERIC_NOP7 0x8d,0xb4,0x26,0x00,0x00,0x00,0x00
#define GENERIC_NOP8 GENERIC_NOP1,GENERIC_NOP7
#define K7_NOP5_ATOMIC NOP_DS_PREFIX,K7_NOP4
#define K8_NOP1 GENERIC_NOP1
#define K8_NOP5_ATOMIC 0x66,K8_NOP4
#define NOP_ATOMIC5 (ASM_NOP_MAX+1)	
#define NOP_DS_PREFIX 0x3e
#define P6_NOP5_ATOMIC P6_NOP5
#define _ASM_MK_NOP(x) ".byte " __stringify(x) "\n"

#define DECLARE_ARGS(val, low, high)	unsigned long low, high
#define EAX_EDX_RET(val, low, high)	"=a" (low), "=d" (high)
#define EAX_EDX_VAL(val, low, high)	((low) | (high) << 32)

#define msr_tracepoint_active(t) static_key_false(&(t).key)
#define native_rdmsr(msr, val1, val2)			\
do {							\
	u64 __val = __rdmsr((msr));			\
	(void)((val1) = (u32)__val);			\
	(void)((val2) = (u32)(__val >> 32));		\
} while (0)
#define native_wrmsr(msr, low, high)			\
	__wrmsr(msr, low, high)
#define native_wrmsrl(msr, val)				\
	__wrmsr((msr), (u32)((u64)(val)),		\
		       (u32)((u64)(val) >> 32))
#define write_rdtscp_aux(val) wrmsr(MSR_TSC_AUX, (val), 0)
#define write_tsc(low, high) wrmsr(MSR_IA32_TSC, (low), (high))
#define TRACEPOINT_DEFS_H 1

#define ATOMIC_INIT(i)	{ (i) }

#define arch_atomic_add_negative arch_atomic_add_negative
#define arch_atomic_add_return arch_atomic_add_return
#define arch_atomic_cmpxchg arch_atomic_cmpxchg
#define arch_atomic_dec arch_atomic_dec
#define arch_atomic_dec_and_test arch_atomic_dec_and_test
#define arch_atomic_fetch_add arch_atomic_fetch_add
#define arch_atomic_fetch_and arch_atomic_fetch_and
#define arch_atomic_fetch_or arch_atomic_fetch_or
#define arch_atomic_fetch_sub arch_atomic_fetch_sub
#define arch_atomic_fetch_xor arch_atomic_fetch_xor
#define arch_atomic_inc arch_atomic_inc
#define arch_atomic_inc_and_test arch_atomic_inc_and_test
#define arch_atomic_sub_and_test arch_atomic_sub_and_test
#define arch_atomic_sub_return arch_atomic_sub_return
#define arch_atomic_try_cmpxchg arch_atomic_try_cmpxchg
#define arch_atomic_xchg arch_atomic_xchg

#define __smp_load_acquire(p)						\
({									\
	typeof(*p) ___p1 = READ_ONCE(*p);				\
	compiletime_assert_atomic_type(*p);				\
	barrier();							\
	___p1;								\
})
#define __smp_mb()	asm volatile("lock; addl $0,-4(%%esp)" ::: "memory", "cc")
#define __smp_mb__after_atomic()	do { } while (0)
#define __smp_mb__before_atomic()	do { } while (0)
#define __smp_rmb()	dma_rmb()
#define __smp_store_mb(var, value) do { (void)xchg(&var, value); } while (0)
#define __smp_store_release(p, v)					\
do {									\
	compiletime_assert_atomic_type(*p);				\
	barrier();							\
	WRITE_ONCE(*p, v);						\
} while (0)
#define __smp_wmb()	barrier()
#define array_index_mask_nospec array_index_mask_nospec
#define barrier_nospec() alternative("", "lfence", X86_FEATURE_LFENCE_RDTSC)
#define dma_rmb()	barrier()
#define dma_wmb()	barrier()
#define mb() asm volatile(ALTERNATIVE("lock; addl $0,-4(%%esp)", "mfence", \
				      X86_FEATURE_XMM2) ::: "memory", "cc")
#define rmb() asm volatile(ALTERNATIVE("lock; addl $0,-4(%%esp)", "lfence", \
				       X86_FEATURE_XMM2) ::: "memory", "cc")
#define wmb() asm volatile(ALTERNATIVE("lock; addl $0,-4(%%esp)", "sfence", \
				       X86_FEATURE_XMM2) ::: "memory", "cc")

#define __smp_read_barrier_depends()	read_barrier_depends()
#define read_barrier_depends()		do { } while (0)
#define smp_acquire__after_ctrl_dep()		smp_rmb()
#define smp_cond_load_acquire(ptr, cond_expr) ({		\
	__unqual_scalar_typeof(*ptr) _val;			\
	_val = smp_cond_load_relaxed(ptr, cond_expr);		\
	smp_acquire__after_ctrl_dep();				\
	(typeof(*ptr))_val;					\
})
#define smp_cond_load_relaxed(ptr, cond_expr) ({		\
	typeof(ptr) __PTR = (ptr);				\
	__unqual_scalar_typeof(*ptr) VAL;			\
	for (;;) {						\
		VAL = READ_ONCE(*__PTR);			\
		if (cond_expr)					\
			break;					\
		cpu_relax();					\
	}							\
	(typeof(*ptr))VAL;					\
})
#define smp_load_acquire(p)						\
({									\
	__unqual_scalar_typeof(*p) ___p1 = READ_ONCE(*p);		\
	compiletime_assert_atomic_type(*p);				\
	barrier();							\
	(typeof(*p))___p1;						\
})
#define smp_mb()	barrier()
#define smp_mb__after_atomic()	barrier()
#define smp_mb__before_atomic()	barrier()
#define smp_read_barrier_depends()	do { } while (0)
#define smp_rmb()	barrier()
#define smp_store_mb(var, value)  do { WRITE_ONCE(var, value); barrier(); } while (0)
#define smp_store_release(p, v)						\
do {									\
	compiletime_assert_atomic_type(*p);				\
	barrier();							\
	WRITE_ONCE(*p, v);						\
} while (0)
#define smp_wmb()	barrier()
#define virt_load_acquire(p) __smp_load_acquire(p)
#define virt_mb() __smp_mb()
#define virt_mb__after_atomic()	__smp_mb__after_atomic()
#define virt_mb__before_atomic() __smp_mb__before_atomic()
#define virt_read_barrier_depends() __smp_read_barrier_depends()
#define virt_rmb() __smp_rmb()
#define virt_store_mb(var, value) __smp_store_mb(var, value)
#define virt_store_release(p, v) __smp_store_release(p, v)
#define virt_wmb() __smp_wmb()
#define GEN_BINARY_RMWcc(X...) RMWcc_CONCAT(GEN_BINARY_RMWcc_, RMWcc_ARGS(X))(X)
#define GEN_BINARY_RMWcc_5(op, var, cc, vcon, val)			\
	GEN_BINARY_RMWcc_6(op, var, cc, vcon, val, "%[var]")
#define GEN_BINARY_RMWcc_6(op, var, cc, vcon, _val, arg0)		\
	__GEN_RMWcc(op " %[val], " arg0, var, cc,			\
		    __CLOBBERS_MEM(), [val] vcon (_val))
#define GEN_BINARY_SUFFIXED_RMWcc(op, suffix, var, cc, vcon, _val, clobbers...)\
	__GEN_RMWcc(op " %[val], %[var]\n\t" suffix, var, cc,		\
		    __CLOBBERS_MEM(clobbers), [val] vcon (_val))
#define GEN_UNARY_RMWcc(X...) RMWcc_CONCAT(GEN_UNARY_RMWcc_, RMWcc_ARGS(X))(X)
#define GEN_UNARY_RMWcc_3(op, var, cc)					\
	GEN_UNARY_RMWcc_4(op, var, cc, "%[var]")
#define GEN_UNARY_RMWcc_4(op, var, cc, arg0)				\
	__GEN_RMWcc(op " " arg0, var, cc, __CLOBBERS_MEM())
#define GEN_UNARY_SUFFIXED_RMWcc(op, suffix, var, cc, clobbers...)	\
	__GEN_RMWcc(op " %[var]\n\t" suffix, var, cc,			\
		    __CLOBBERS_MEM(clobbers))
#define RMWcc_ARGS(X...) __RMWcc_ARGS(, ##X, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
#define RMWcc_CONCAT(a, b) __RMWcc_CONCAT(a, b)

#define __CLOBBERS_MEM(clb...)	"memory", ## clb
#define __GEN_RMWcc(fullop, _var, cc, clobbers, ...)			\
({									\
	bool c = false;							\
	asm_volatile_goto (fullop "; j" #cc " %l[cc_label]"		\
			: : [var] "m" (_var), ## __VA_ARGS__		\
			: clobbers : cc_label);				\
	if (0) {							\
cc_label:	c = true;						\
	}								\
	c;								\
})
#define __RMWcc_ARGS(_0, _1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _n, X...) _n
#define __RMWcc_CONCAT(a, b) a ## b

#define __cmpxchg(ptr, old, new, size)					\
	__raw_cmpxchg((ptr), (old), (new), (size), LOCK_PREFIX)
#define __cmpxchg_double(pfx, p1, p2, o1, o2, n1, n2)			\
({									\
	bool __ret;							\
	__typeof__(*(p1)) __old1 = (o1), __new1 = (n1);			\
	__typeof__(*(p2)) __old2 = (o2), __new2 = (n2);			\
	BUILD_BUG_ON(sizeof(*(p1)) != sizeof(long));			\
	BUILD_BUG_ON(sizeof(*(p2)) != sizeof(long));			\
	VM_BUG_ON((unsigned long)(p1) % (2 * sizeof(long)));		\
	VM_BUG_ON((unsigned long)((p1) + 1) != (unsigned long)(p2));	\
	asm volatile(pfx "cmpxchg%c5b %1"				\
		     CC_SET(e)						\
		     : CC_OUT(e) (__ret),				\
		       "+m" (*(p1)), "+m" (*(p2)),			\
		       "+a" (__old1), "+d" (__old2)			\
		     : "i" (2 * sizeof(long)),				\
		       "b" (__new1), "c" (__new2));			\
	__ret;								\
})
#define __cmpxchg_local(ptr, old, new, size)				\
	__raw_cmpxchg((ptr), (old), (new), (size), "")
#define __raw_cmpxchg(ptr, old, new, size, lock)			\
({									\
	__typeof__(*(ptr)) __ret;					\
	__typeof__(*(ptr)) __old = (old);				\
	__typeof__(*(ptr)) __new = (new);				\
	switch (size) {							\
	case __X86_CASE_B:						\
	{								\
		volatile u8 *__ptr = (volatile u8 *)(ptr);		\
		asm volatile(lock "cmpxchgb %2,%1"			\
			     : "=a" (__ret), "+m" (*__ptr)		\
			     : "q" (__new), "0" (__old)			\
			     : "memory");				\
		break;							\
	}								\
	case __X86_CASE_W:						\
	{								\
		volatile u16 *__ptr = (volatile u16 *)(ptr);		\
		asm volatile(lock "cmpxchgw %2,%1"			\
			     : "=a" (__ret), "+m" (*__ptr)		\
			     : "r" (__new), "0" (__old)			\
			     : "memory");				\
		break;							\
	}								\
	case __X86_CASE_L:						\
	{								\
		volatile u32 *__ptr = (volatile u32 *)(ptr);		\
		asm volatile(lock "cmpxchgl %2,%1"			\
			     : "=a" (__ret), "+m" (*__ptr)		\
			     : "r" (__new), "0" (__old)			\
			     : "memory");				\
		break;							\
	}								\
	case __X86_CASE_Q:						\
	{								\
		volatile u64 *__ptr = (volatile u64 *)(ptr);		\
		asm volatile(lock "cmpxchgq %2,%1"			\
			     : "=a" (__ret), "+m" (*__ptr)		\
			     : "r" (__new), "0" (__old)			\
			     : "memory");				\
		break;							\
	}								\
	default:							\
		__cmpxchg_wrong_size();					\
	}								\
	__ret;								\
})
#define __raw_try_cmpxchg(_ptr, _pold, _new, size, lock)		\
({									\
	bool success;							\
	__typeof__(_ptr) _old = (__typeof__(_ptr))(_pold);		\
	__typeof__(*(_ptr)) __old = *_old;				\
	__typeof__(*(_ptr)) __new = (_new);				\
	switch (size) {							\
	case __X86_CASE_B:						\
	{								\
		volatile u8 *__ptr = (volatile u8 *)(_ptr);		\
		asm volatile(lock "cmpxchgb %[new], %[ptr]"		\
			     CC_SET(z)					\
			     : CC_OUT(z) (success),			\
			       [ptr] "+m" (*__ptr),			\
			       [old] "+a" (__old)			\
			     : [new] "q" (__new)			\
			     : "memory");				\
		break;							\
	}								\
	case __X86_CASE_W:						\
	{								\
		volatile u16 *__ptr = (volatile u16 *)(_ptr);		\
		asm volatile(lock "cmpxchgw %[new], %[ptr]"		\
			     CC_SET(z)					\
			     : CC_OUT(z) (success),			\
			       [ptr] "+m" (*__ptr),			\
			       [old] "+a" (__old)			\
			     : [new] "r" (__new)			\
			     : "memory");				\
		break;							\
	}								\
	case __X86_CASE_L:						\
	{								\
		volatile u32 *__ptr = (volatile u32 *)(_ptr);		\
		asm volatile(lock "cmpxchgl %[new], %[ptr]"		\
			     CC_SET(z)					\
			     : CC_OUT(z) (success),			\
			       [ptr] "+m" (*__ptr),			\
			       [old] "+a" (__old)			\
			     : [new] "r" (__new)			\
			     : "memory");				\
		break;							\
	}								\
	case __X86_CASE_Q:						\
	{								\
		volatile u64 *__ptr = (volatile u64 *)(_ptr);		\
		asm volatile(lock "cmpxchgq %[new], %[ptr]"		\
			     CC_SET(z)					\
			     : CC_OUT(z) (success),			\
			       [ptr] "+m" (*__ptr),			\
			       [old] "+a" (__old)			\
			     : [new] "r" (__new)			\
			     : "memory");				\
		break;							\
	}								\
	default:							\
		__cmpxchg_wrong_size();					\
	}								\
	if (unlikely(!success))						\
		*_old = __old;						\
	likely(success);						\
})
#define __sync_cmpxchg(ptr, old, new, size)				\
	__raw_cmpxchg((ptr), (old), (new), (size), "lock; ")
#define __try_cmpxchg(ptr, pold, new, size)				\
	__raw_try_cmpxchg((ptr), (pold), (new), (size), LOCK_PREFIX)
#define __xadd(ptr, inc, lock)	__xchg_op((ptr), (inc), xadd, lock)
#define __xchg_op(ptr, arg, op, lock)					\
	({								\
	        __typeof__ (*(ptr)) __ret = (arg);			\
		switch (sizeof(*(ptr))) {				\
		case __X86_CASE_B:					\
			asm volatile (lock #op "b %b0, %1\n"		\
				      : "+q" (__ret), "+m" (*(ptr))	\
				      : : "memory", "cc");		\
			break;						\
		case __X86_CASE_W:					\
			asm volatile (lock #op "w %w0, %1\n"		\
				      : "+r" (__ret), "+m" (*(ptr))	\
				      : : "memory", "cc");		\
			break;						\
		case __X86_CASE_L:					\
			asm volatile (lock #op "l %0, %1\n"		\
				      : "+r" (__ret), "+m" (*(ptr))	\
				      : : "memory", "cc");		\
			break;						\
		case __X86_CASE_Q:					\
			asm volatile (lock #op "q %q0, %1\n"		\
				      : "+r" (__ret), "+m" (*(ptr))	\
				      : : "memory", "cc");		\
			break;						\
		default:						\
			__ ## op ## _wrong_size();			\
		}							\
		__ret;							\
	})
#define arch_cmpxchg(ptr, old, new)					\
	__cmpxchg(ptr, old, new, sizeof(*(ptr)))
#define arch_cmpxchg_double(p1, p2, o1, o2, n1, n2) \
	__cmpxchg_double(LOCK_PREFIX, p1, p2, o1, o2, n1, n2)
#define arch_cmpxchg_double_local(p1, p2, o1, o2, n1, n2) \
	__cmpxchg_double(, p1, p2, o1, o2, n1, n2)
#define arch_cmpxchg_local(ptr, old, new)				\
	__cmpxchg_local(ptr, old, new, sizeof(*(ptr)))
#define arch_sync_cmpxchg(ptr, old, new)				\
	__sync_cmpxchg(ptr, old, new, sizeof(*(ptr)))
#define arch_xchg(ptr, v)	__xchg_op((ptr), (v), xchg, "")
#define try_cmpxchg(ptr, pold, new) 					\
	__try_cmpxchg((ptr), (pold), (new), sizeof(*(ptr)))
#define xadd(ptr, inc)		__xadd((ptr), (inc), LOCK_PREFIX)


#define DECLARE_EARLY_PER_CPU(_type, _name)			\
	DECLARE_PER_CPU(_type, _name);				\
	extern __typeof__(_type) *_name##_early_ptr;		\
	extern __typeof__(_type)  _name##_early_map[]
#define DECLARE_EARLY_PER_CPU_READ_MOSTLY(_type, _name)		\
	DECLARE_PER_CPU_READ_MOSTLY(_type, _name);		\
	extern __typeof__(_type) *_name##_early_ptr;		\
	extern __typeof__(_type)  _name##_early_map[]
#define DECLARE_INIT_PER_CPU(var) \
       extern typeof(var) init_per_cpu_var(var)
#define DEFINE_EARLY_PER_CPU_READ_MOSTLY(_type, _name, _initvalue)	\
	DEFINE_PER_CPU_READ_MOSTLY(_type, _name) = _initvalue;		\
	__typeof__(_type) _name##_early_map[NR_CPUS] __initdata =	\
				{ [0 ... NR_CPUS-1] = _initvalue };	\
	__typeof__(_type) *_name##_early_ptr __refdata = _name##_early_map
#define EXPORT_EARLY_PER_CPU_SYMBOL(_name)			\
	EXPORT_PER_CPU_SYMBOL(_name)

#define __percpu_arg(x)		__percpu_prefix "%" #x
#define arch_raw_cpu_ptr(ptr)				\
({							\
	unsigned long tcp_ptr__;			\
	asm volatile("add " __percpu_arg(1) ", %0"	\
		     : "=r" (tcp_ptr__)			\
		     : "m" (this_cpu_off), "0" (ptr));	\
	(typeof(*(ptr)) __kernel __force *)tcp_ptr__;	\
})
#define init_per_cpu_var(var)  init_per_cpu__##var
#define percpu_add_op(qual, var, val)					\
do {									\
	typedef typeof(var) pao_T__;					\
	const int pao_ID__ = (__builtin_constant_p(val) &&		\
			      ((val) == 1 || (val) == -1)) ?		\
				(int)(val) : 0;				\
	if (0) {							\
		pao_T__ pao_tmp__;					\
		pao_tmp__ = (val);					\
		(void)pao_tmp__;					\
	}								\
	switch (sizeof(var)) {						\
	case 1:								\
		if (pao_ID__ == 1)					\
			asm qual ("incb "__percpu_arg(0) : "+m" (var));	\
		else if (pao_ID__ == -1)				\
			asm qual ("decb "__percpu_arg(0) : "+m" (var));	\
		else							\
			asm qual ("addb %1, "__percpu_arg(0)		\
			    : "+m" (var)				\
			    : "qi" ((pao_T__)(val)));			\
		break;							\
	case 2:								\
		if (pao_ID__ == 1)					\
			asm qual ("incw "__percpu_arg(0) : "+m" (var));	\
		else if (pao_ID__ == -1)				\
			asm qual ("decw "__percpu_arg(0) : "+m" (var));	\
		else							\
			asm qual ("addw %1, "__percpu_arg(0)		\
			    : "+m" (var)				\
			    : "ri" ((pao_T__)(val)));			\
		break;							\
	case 4:								\
		if (pao_ID__ == 1)					\
			asm qual ("incl "__percpu_arg(0) : "+m" (var));	\
		else if (pao_ID__ == -1)				\
			asm qual ("decl "__percpu_arg(0) : "+m" (var));	\
		else							\
			asm qual ("addl %1, "__percpu_arg(0)		\
			    : "+m" (var)				\
			    : "ri" ((pao_T__)(val)));			\
		break;							\
	case 8:								\
		if (pao_ID__ == 1)					\
			asm qual ("incq "__percpu_arg(0) : "+m" (var));	\
		else if (pao_ID__ == -1)				\
			asm qual ("decq "__percpu_arg(0) : "+m" (var));	\
		else							\
			asm qual ("addq %1, "__percpu_arg(0)		\
			    : "+m" (var)				\
			    : "re" ((pao_T__)(val)));			\
		break;							\
	default: __bad_percpu_size();					\
	}								\
} while (0)
#define percpu_add_return_op(qual, var, val)				\
({									\
	typeof(var) paro_ret__ = val;					\
	switch (sizeof(var)) {						\
	case 1:								\
		asm qual ("xaddb %0, "__percpu_arg(1)			\
			    : "+q" (paro_ret__), "+m" (var)		\
			    : : "memory");				\
		break;							\
	case 2:								\
		asm qual ("xaddw %0, "__percpu_arg(1)			\
			    : "+r" (paro_ret__), "+m" (var)		\
			    : : "memory");				\
		break;							\
	case 4:								\
		asm qual ("xaddl %0, "__percpu_arg(1)			\
			    : "+r" (paro_ret__), "+m" (var)		\
			    : : "memory");				\
		break;							\
	case 8:								\
		asm qual ("xaddq %0, "__percpu_arg(1)			\
			    : "+re" (paro_ret__), "+m" (var)		\
			    : : "memory");				\
		break;							\
	default: __bad_percpu_size();					\
	}								\
	paro_ret__ += val;						\
	paro_ret__;							\
})
#define percpu_cmpxchg16b_double(pcp1, pcp2, o1, o2, n1, n2)		\
({									\
	bool __ret;							\
	typeof(pcp1) __o1 = (o1), __n1 = (n1);				\
	typeof(pcp2) __o2 = (o2), __n2 = (n2);				\
	alternative_io("leaq %P1,%%rsi\n\tcall this_cpu_cmpxchg16b_emu\n\t", \
		       "cmpxchg16b " __percpu_arg(1) "\n\tsetz %0\n\t",	\
		       X86_FEATURE_CX16,				\
		       ASM_OUTPUT2("=a" (__ret), "+m" (pcp1),		\
				   "+m" (pcp2), "+d" (__o2)),		\
		       "b" (__n1), "c" (__n2), "a" (__o1) : "rsi");	\
	__ret;								\
})
#define percpu_cmpxchg8b_double(pcp1, pcp2, o1, o2, n1, n2)		\
({									\
	bool __ret;							\
	typeof(pcp1) __o1 = (o1), __n1 = (n1);				\
	typeof(pcp2) __o2 = (o2), __n2 = (n2);				\
	asm volatile("cmpxchg8b "__percpu_arg(1)			\
		     CC_SET(z)						\
		     : CC_OUT(z) (__ret), "+m" (pcp1), "+m" (pcp2), "+a" (__o1), "+d" (__o2) \
		     : "b" (__n1), "c" (__n2));				\
	__ret;								\
})
#define percpu_cmpxchg_op(qual, var, oval, nval)			\
({									\
	typeof(var) pco_ret__;						\
	typeof(var) pco_old__ = (oval);					\
	typeof(var) pco_new__ = (nval);					\
	switch (sizeof(var)) {						\
	case 1:								\
		asm qual ("cmpxchgb %2, "__percpu_arg(1)		\
			    : "=a" (pco_ret__), "+m" (var)		\
			    : "q" (pco_new__), "0" (pco_old__)		\
			    : "memory");				\
		break;							\
	case 2:								\
		asm qual ("cmpxchgw %2, "__percpu_arg(1)		\
			    : "=a" (pco_ret__), "+m" (var)		\
			    : "r" (pco_new__), "0" (pco_old__)		\
			    : "memory");				\
		break;							\
	case 4:								\
		asm qual ("cmpxchgl %2, "__percpu_arg(1)		\
			    : "=a" (pco_ret__), "+m" (var)		\
			    : "r" (pco_new__), "0" (pco_old__)		\
			    : "memory");				\
		break;							\
	case 8:								\
		asm qual ("cmpxchgq %2, "__percpu_arg(1)		\
			    : "=a" (pco_ret__), "+m" (var)		\
			    : "r" (pco_new__), "0" (pco_old__)		\
			    : "memory");				\
		break;							\
	default: __bad_percpu_size();					\
	}								\
	pco_ret__;							\
})
#define percpu_from_op(qual, op, var)			\
({							\
	typeof(var) pfo_ret__;				\
	switch (sizeof(var)) {				\
	case 1:						\
		asm qual (op "b "__percpu_arg(1)",%0"	\
		    : "=q" (pfo_ret__)			\
		    : "m" (var));			\
		break;					\
	case 2:						\
		asm qual (op "w "__percpu_arg(1)",%0"	\
		    : "=r" (pfo_ret__)			\
		    : "m" (var));			\
		break;					\
	case 4:						\
		asm qual (op "l "__percpu_arg(1)",%0"	\
		    : "=r" (pfo_ret__)			\
		    : "m" (var));			\
		break;					\
	case 8:						\
		asm qual (op "q "__percpu_arg(1)",%0"	\
		    : "=r" (pfo_ret__)			\
		    : "m" (var));			\
		break;					\
	default: __bad_percpu_size();			\
	}						\
	pfo_ret__;					\
})
#define percpu_stable_op(op, var)			\
({							\
	typeof(var) pfo_ret__;				\
	switch (sizeof(var)) {				\
	case 1:						\
		asm(op "b "__percpu_arg(P1)",%0"	\
		    : "=q" (pfo_ret__)			\
		    : "p" (&(var)));			\
		break;					\
	case 2:						\
		asm(op "w "__percpu_arg(P1)",%0"	\
		    : "=r" (pfo_ret__)			\
		    : "p" (&(var)));			\
		break;					\
	case 4:						\
		asm(op "l "__percpu_arg(P1)",%0"	\
		    : "=r" (pfo_ret__)			\
		    : "p" (&(var)));			\
		break;					\
	case 8:						\
		asm(op "q "__percpu_arg(P1)",%0"	\
		    : "=r" (pfo_ret__)			\
		    : "p" (&(var)));			\
		break;					\
	default: __bad_percpu_size();			\
	}						\
	pfo_ret__;					\
})
#define percpu_to_op(qual, op, var, val)		\
do {							\
	typedef typeof(var) pto_T__;			\
	if (0) {					\
		pto_T__ pto_tmp__;			\
		pto_tmp__ = (val);			\
		(void)pto_tmp__;			\
	}						\
	switch (sizeof(var)) {				\
	case 1:						\
		asm qual (op "b %1,"__percpu_arg(0)	\
		    : "+m" (var)			\
		    : "qi" ((pto_T__)(val)));		\
		break;					\
	case 2:						\
		asm qual (op "w %1,"__percpu_arg(0)	\
		    : "+m" (var)			\
		    : "ri" ((pto_T__)(val)));		\
		break;					\
	case 4:						\
		asm qual (op "l %1,"__percpu_arg(0)	\
		    : "+m" (var)			\
		    : "ri" ((pto_T__)(val)));		\
		break;					\
	case 8:						\
		asm qual (op "q %1,"__percpu_arg(0)	\
		    : "+m" (var)			\
		    : "re" ((pto_T__)(val)));		\
		break;					\
	default: __bad_percpu_size();			\
	}						\
} while (0)
#define percpu_unary_op(qual, op, var)			\
({							\
	switch (sizeof(var)) {				\
	case 1:						\
		asm qual (op "b "__percpu_arg(0)	\
		    : "+m" (var));			\
		break;					\
	case 2:						\
		asm qual (op "w "__percpu_arg(0)	\
		    : "+m" (var));			\
		break;					\
	case 4:						\
		asm qual (op "l "__percpu_arg(0)	\
		    : "+m" (var));			\
		break;					\
	case 8:						\
		asm qual (op "q "__percpu_arg(0)	\
		    : "+m" (var));			\
		break;					\
	default: __bad_percpu_size();			\
	}						\
})
#define percpu_xchg_op(qual, var, nval)					\
({									\
	typeof(var) pxo_ret__;						\
	typeof(var) pxo_new__ = (nval);					\
	switch (sizeof(var)) {						\
	case 1:								\
		asm qual ("\n\tmov "__percpu_arg(1)",%%al"		\
		    "\n1:\tcmpxchgb %2, "__percpu_arg(1)		\
		    "\n\tjnz 1b"					\
			    : "=&a" (pxo_ret__), "+m" (var)		\
			    : "q" (pxo_new__)				\
			    : "memory");				\
		break;							\
	case 2:								\
		asm qual ("\n\tmov "__percpu_arg(1)",%%ax"		\
		    "\n1:\tcmpxchgw %2, "__percpu_arg(1)		\
		    "\n\tjnz 1b"					\
			    : "=&a" (pxo_ret__), "+m" (var)		\
			    : "r" (pxo_new__)				\
			    : "memory");				\
		break;							\
	case 4:								\
		asm qual ("\n\tmov "__percpu_arg(1)",%%eax"		\
		    "\n1:\tcmpxchgl %2, "__percpu_arg(1)		\
		    "\n\tjnz 1b"					\
			    : "=&a" (pxo_ret__), "+m" (var)		\
			    : "r" (pxo_new__)				\
			    : "memory");				\
		break;							\
	case 8:								\
		asm qual ("\n\tmov "__percpu_arg(1)",%%rax"		\
		    "\n1:\tcmpxchgq %2, "__percpu_arg(1)		\
		    "\n\tjnz 1b"					\
			    : "=&a" (pxo_ret__), "+m" (var)		\
			    : "r" (pxo_new__)				\
			    : "memory");				\
		break;							\
	default: __bad_percpu_size();					\
	}								\
	pxo_ret__;							\
})
#define raw_cpu_add_1(pcp, val)		percpu_add_op(, (pcp), val)
#define raw_cpu_add_2(pcp, val)		percpu_add_op(, (pcp), val)
#define raw_cpu_add_4(pcp, val)		percpu_add_op(, (pcp), val)
#define raw_cpu_add_8(pcp, val)			percpu_add_op(, (pcp), val)
#define raw_cpu_add_return_1(pcp, val)		percpu_add_return_op(, pcp, val)
#define raw_cpu_add_return_2(pcp, val)		percpu_add_return_op(, pcp, val)
#define raw_cpu_add_return_4(pcp, val)		percpu_add_return_op(, pcp, val)
#define raw_cpu_add_return_8(pcp, val)		percpu_add_return_op(, pcp, val)
#define raw_cpu_and_1(pcp, val)		percpu_to_op(, "and", (pcp), val)
#define raw_cpu_and_2(pcp, val)		percpu_to_op(, "and", (pcp), val)
#define raw_cpu_and_4(pcp, val)		percpu_to_op(, "and", (pcp), val)
#define raw_cpu_and_8(pcp, val)			percpu_to_op(, "and", (pcp), val)
#define raw_cpu_cmpxchg_1(pcp, oval, nval)	percpu_cmpxchg_op(, pcp, oval, nval)
#define raw_cpu_cmpxchg_2(pcp, oval, nval)	percpu_cmpxchg_op(, pcp, oval, nval)
#define raw_cpu_cmpxchg_4(pcp, oval, nval)	percpu_cmpxchg_op(, pcp, oval, nval)
#define raw_cpu_cmpxchg_8(pcp, oval, nval)	percpu_cmpxchg_op(, pcp, oval, nval)
#define raw_cpu_or_1(pcp, val)		percpu_to_op(, "or", (pcp), val)
#define raw_cpu_or_2(pcp, val)		percpu_to_op(, "or", (pcp), val)
#define raw_cpu_or_4(pcp, val)		percpu_to_op(, "or", (pcp), val)
#define raw_cpu_or_8(pcp, val)			percpu_to_op(, "or", (pcp), val)
#define raw_cpu_read_1(pcp)		percpu_from_op(, "mov", pcp)
#define raw_cpu_read_2(pcp)		percpu_from_op(, "mov", pcp)
#define raw_cpu_read_4(pcp)		percpu_from_op(, "mov", pcp)
#define raw_cpu_read_8(pcp)			percpu_from_op(, "mov", pcp)
#define raw_cpu_write_1(pcp, val)	percpu_to_op(, "mov", (pcp), val)
#define raw_cpu_write_2(pcp, val)	percpu_to_op(, "mov", (pcp), val)
#define raw_cpu_write_4(pcp, val)	percpu_to_op(, "mov", (pcp), val)
#define raw_cpu_write_8(pcp, val)		percpu_to_op(, "mov", (pcp), val)
#define raw_cpu_xchg_1(pcp, val)	raw_percpu_xchg_op(pcp, val)
#define raw_cpu_xchg_2(pcp, val)	raw_percpu_xchg_op(pcp, val)
#define raw_cpu_xchg_4(pcp, val)	raw_percpu_xchg_op(pcp, val)
#define raw_cpu_xchg_8(pcp, nval)		raw_percpu_xchg_op(pcp, nval)
#define raw_percpu_xchg_op(var, nval)					\
({									\
	typeof(var) pxo_ret__ = raw_cpu_read(var);			\
	raw_cpu_write(var, (nval));					\
	pxo_ret__;							\
})
#define this_cpu_add_1(pcp, val)	percpu_add_op(volatile, (pcp), val)
#define this_cpu_add_2(pcp, val)	percpu_add_op(volatile, (pcp), val)
#define this_cpu_add_4(pcp, val)	percpu_add_op(volatile, (pcp), val)
#define this_cpu_add_8(pcp, val)		percpu_add_op(volatile, (pcp), val)
#define this_cpu_add_return_1(pcp, val)		percpu_add_return_op(volatile, pcp, val)
#define this_cpu_add_return_2(pcp, val)		percpu_add_return_op(volatile, pcp, val)
#define this_cpu_add_return_4(pcp, val)		percpu_add_return_op(volatile, pcp, val)
#define this_cpu_add_return_8(pcp, val)		percpu_add_return_op(volatile, pcp, val)
#define this_cpu_and_1(pcp, val)	percpu_to_op(volatile, "and", (pcp), val)
#define this_cpu_and_2(pcp, val)	percpu_to_op(volatile, "and", (pcp), val)
#define this_cpu_and_4(pcp, val)	percpu_to_op(volatile, "and", (pcp), val)
#define this_cpu_and_8(pcp, val)		percpu_to_op(volatile, "and", (pcp), val)
#define this_cpu_cmpxchg_1(pcp, oval, nval)	percpu_cmpxchg_op(volatile, pcp, oval, nval)
#define this_cpu_cmpxchg_2(pcp, oval, nval)	percpu_cmpxchg_op(volatile, pcp, oval, nval)
#define this_cpu_cmpxchg_4(pcp, oval, nval)	percpu_cmpxchg_op(volatile, pcp, oval, nval)
#define this_cpu_cmpxchg_8(pcp, oval, nval)	percpu_cmpxchg_op(volatile, pcp, oval, nval)
#define this_cpu_or_1(pcp, val)		percpu_to_op(volatile, "or", (pcp), val)
#define this_cpu_or_2(pcp, val)		percpu_to_op(volatile, "or", (pcp), val)
#define this_cpu_or_4(pcp, val)		percpu_to_op(volatile, "or", (pcp), val)
#define this_cpu_or_8(pcp, val)			percpu_to_op(volatile, "or", (pcp), val)
#define this_cpu_read_1(pcp)		percpu_from_op(volatile, "mov", pcp)
#define this_cpu_read_2(pcp)		percpu_from_op(volatile, "mov", pcp)
#define this_cpu_read_4(pcp)		percpu_from_op(volatile, "mov", pcp)
#define this_cpu_read_8(pcp)			percpu_from_op(volatile, "mov", pcp)
#define this_cpu_read_stable(var)	percpu_stable_op("mov", var)
#define this_cpu_write_1(pcp, val)	percpu_to_op(volatile, "mov", (pcp), val)
#define this_cpu_write_2(pcp, val)	percpu_to_op(volatile, "mov", (pcp), val)
#define this_cpu_write_4(pcp, val)	percpu_to_op(volatile, "mov", (pcp), val)
#define this_cpu_write_8(pcp, val)		percpu_to_op(volatile, "mov", (pcp), val)
#define this_cpu_xchg_1(pcp, nval)	percpu_xchg_op(volatile, pcp, nval)
#define this_cpu_xchg_2(pcp, nval)	percpu_xchg_op(volatile, pcp, nval)
#define this_cpu_xchg_4(pcp, nval)	percpu_xchg_op(volatile, pcp, nval)
#define this_cpu_xchg_8(pcp, nval)		percpu_xchg_op(volatile, pcp, nval)
#define x86_this_cpu_test_bit(nr, addr)			\
	(__builtin_constant_p((nr))			\
	 ? x86_this_cpu_constant_test_bit((nr), (addr))	\
	 : x86_this_cpu_variable_test_bit((nr), (addr)))

#define PER_CPU_BASE_SECTION ".data..percpu"

#define __my_cpu_offset per_cpu_offset(raw_smp_processor_id())
#define __this_cpu_generic_read_noirq(pcp)				\
({									\
	typeof(pcp) __ret;						\
	unsigned long __flags;						\
	raw_local_irq_save(__flags);					\
	__ret = raw_cpu_generic_read(pcp);				\
	raw_local_irq_restore(__flags);					\
	__ret;								\
})
#define __this_cpu_generic_read_nopreempt(pcp)				\
({									\
	typeof(pcp) __ret;						\
	preempt_disable_notrace();					\
	__ret = READ_ONCE(*raw_cpu_ptr(&(pcp)));			\
	preempt_enable_notrace();					\
	__ret;								\
})
#define my_cpu_offset per_cpu_offset(smp_processor_id())
#define per_cpu_offset(x) (__per_cpu_offset[x])
#define raw_cpu_cmpxchg_double_1(pcp1, pcp2, oval1, oval2, nval1, nval2) \
	raw_cpu_generic_cmpxchg_double(pcp1, pcp2, oval1, oval2, nval1, nval2)
#define raw_cpu_cmpxchg_double_2(pcp1, pcp2, oval1, oval2, nval1, nval2) \
	raw_cpu_generic_cmpxchg_double(pcp1, pcp2, oval1, oval2, nval1, nval2)
#define raw_cpu_cmpxchg_double_4(pcp1, pcp2, oval1, oval2, nval1, nval2) \
	raw_cpu_generic_cmpxchg_double(pcp1, pcp2, oval1, oval2, nval1, nval2)
#define raw_cpu_cmpxchg_double_8(pcp1, pcp2, oval1, oval2, nval1, nval2) \
	raw_cpu_generic_cmpxchg_double(pcp1, pcp2, oval1, oval2, nval1, nval2)
#define raw_cpu_generic_add_return(pcp, val)				\
({									\
	typeof(pcp) *__p = raw_cpu_ptr(&(pcp));				\
									\
	*__p += val;							\
	*__p;								\
})
#define raw_cpu_generic_cmpxchg(pcp, oval, nval)			\
({									\
	typeof(pcp) *__p = raw_cpu_ptr(&(pcp));				\
	typeof(pcp) __ret;						\
	__ret = *__p;							\
	if (__ret == (oval))						\
		*__p = nval;						\
	__ret;								\
})
#define raw_cpu_generic_cmpxchg_double(pcp1, pcp2, oval1, oval2, nval1, nval2) \
({									\
	typeof(pcp1) *__p1 = raw_cpu_ptr(&(pcp1));			\
	typeof(pcp2) *__p2 = raw_cpu_ptr(&(pcp2));			\
	int __ret = 0;							\
	if (*__p1 == (oval1) && *__p2  == (oval2)) {			\
		*__p1 = nval1;						\
		*__p2 = nval2;						\
		__ret = 1;						\
	}								\
	(__ret);							\
})
#define raw_cpu_generic_read(pcp)					\
({									\
	*raw_cpu_ptr(&(pcp));						\
})
#define raw_cpu_generic_to_op(pcp, val, op)				\
do {									\
	*raw_cpu_ptr(&(pcp)) op val;					\
} while (0)
#define raw_cpu_generic_xchg(pcp, nval)					\
({									\
	typeof(pcp) *__p = raw_cpu_ptr(&(pcp));				\
	typeof(pcp) __ret;						\
	__ret = *__p;							\
	*__p = nval;							\
	__ret;								\
})
#define this_cpu_cmpxchg_double_1(pcp1, pcp2, oval1, oval2, nval1, nval2) \
	this_cpu_generic_cmpxchg_double(pcp1, pcp2, oval1, oval2, nval1, nval2)
#define this_cpu_cmpxchg_double_2(pcp1, pcp2, oval1, oval2, nval1, nval2) \
	this_cpu_generic_cmpxchg_double(pcp1, pcp2, oval1, oval2, nval1, nval2)
#define this_cpu_cmpxchg_double_4(pcp1, pcp2, oval1, oval2, nval1, nval2) \
	this_cpu_generic_cmpxchg_double(pcp1, pcp2, oval1, oval2, nval1, nval2)
#define this_cpu_cmpxchg_double_8(pcp1, pcp2, oval1, oval2, nval1, nval2) \
	this_cpu_generic_cmpxchg_double(pcp1, pcp2, oval1, oval2, nval1, nval2)
#define this_cpu_generic_add_return(pcp, val)				\
({									\
	typeof(pcp) __ret;						\
	unsigned long __flags;						\
	raw_local_irq_save(__flags);					\
	__ret = raw_cpu_generic_add_return(pcp, val);			\
	raw_local_irq_restore(__flags);					\
	__ret;								\
})
#define this_cpu_generic_cmpxchg(pcp, oval, nval)			\
({									\
	typeof(pcp) __ret;						\
	unsigned long __flags;						\
	raw_local_irq_save(__flags);					\
	__ret = raw_cpu_generic_cmpxchg(pcp, oval, nval);		\
	raw_local_irq_restore(__flags);					\
	__ret;								\
})
#define this_cpu_generic_cmpxchg_double(pcp1, pcp2, oval1, oval2, nval1, nval2)	\
({									\
	int __ret;							\
	unsigned long __flags;						\
	raw_local_irq_save(__flags);					\
	__ret = raw_cpu_generic_cmpxchg_double(pcp1, pcp2,		\
			oval1, oval2, nval1, nval2);			\
	raw_local_irq_restore(__flags);					\
	__ret;								\
})
#define this_cpu_generic_read(pcp)					\
({									\
	typeof(pcp) __ret;						\
	if (__native_word(pcp))						\
		__ret = __this_cpu_generic_read_nopreempt(pcp);		\
	else								\
		__ret = __this_cpu_generic_read_noirq(pcp);		\
	__ret;								\
})
#define this_cpu_generic_to_op(pcp, val, op)				\
do {									\
	unsigned long __flags;						\
	raw_local_irq_save(__flags);					\
	raw_cpu_generic_to_op(pcp, val, op);				\
	raw_local_irq_restore(__flags);					\
} while (0)
#define this_cpu_generic_xchg(pcp, nval)				\
({									\
	typeof(pcp) __ret;						\
	unsigned long __flags;						\
	raw_local_irq_save(__flags);					\
	__ret = raw_cpu_generic_xchg(pcp, nval);			\
	raw_local_irq_restore(__flags);					\
	__ret;								\
})
#define DECLARE_PER_CPU(type, name)					\
	DECLARE_PER_CPU_SECTION(type, name, "")
#define DECLARE_PER_CPU_ALIGNED(type, name)				\
	DECLARE_PER_CPU_SECTION(type, name, PER_CPU_ALIGNED_SECTION)	\
	____cacheline_aligned
#define DECLARE_PER_CPU_DECRYPTED(type, name)				\
	DECLARE_PER_CPU_SECTION(type, name, "..decrypted")
#define DECLARE_PER_CPU_FIRST(type, name)				\
	DECLARE_PER_CPU_SECTION(type, name, PER_CPU_FIRST_SECTION)
#define DECLARE_PER_CPU_PAGE_ALIGNED(type, name)			\
	DECLARE_PER_CPU_SECTION(type, name, "..page_aligned")		\
	__aligned(PAGE_SIZE)
#define DECLARE_PER_CPU_READ_MOSTLY(type, name)			\
	DECLARE_PER_CPU_SECTION(type, name, "..read_mostly")
#define DECLARE_PER_CPU_SECTION(type, name, sec)			\
	extern __PCPU_ATTRS(sec) __typeof__(type) name
#define DECLARE_PER_CPU_SHARED_ALIGNED(type, name)			\
	DECLARE_PER_CPU_SECTION(type, name, PER_CPU_SHARED_ALIGNED_SECTION) \
	____cacheline_aligned_in_smp
#define DEFINE_PER_CPU(type, name)					\
	DEFINE_PER_CPU_SECTION(type, name, "")
#define DEFINE_PER_CPU_ALIGNED(type, name)				\
	DEFINE_PER_CPU_SECTION(type, name, PER_CPU_ALIGNED_SECTION)	\
	____cacheline_aligned
#define DEFINE_PER_CPU_DECRYPTED(type, name)				\
	DEFINE_PER_CPU_SECTION(type, name, "..decrypted")
#define DEFINE_PER_CPU_FIRST(type, name)				\
	DEFINE_PER_CPU_SECTION(type, name, PER_CPU_FIRST_SECTION)
#define DEFINE_PER_CPU_PAGE_ALIGNED(type, name)				\
	DEFINE_PER_CPU_SECTION(type, name, "..page_aligned")		\
	__aligned(PAGE_SIZE)
#define DEFINE_PER_CPU_READ_MOSTLY(type, name)				\
	DEFINE_PER_CPU_SECTION(type, name, "..read_mostly")
#define DEFINE_PER_CPU_SECTION(type, name, sec)				\
	__PCPU_ATTRS(sec) __typeof__(type) name
#define DEFINE_PER_CPU_SHARED_ALIGNED(type, name)			\
	DEFINE_PER_CPU_SECTION(type, name, PER_CPU_SHARED_ALIGNED_SECTION) \
	____cacheline_aligned_in_smp
#define EXPORT_PER_CPU_SYMBOL(var) EXPORT_SYMBOL(var)
#define EXPORT_PER_CPU_SYMBOL_GPL(var) EXPORT_SYMBOL_GPL(var)
#define PER_CPU_ALIGNED_SECTION ""
#define PER_CPU_FIRST_SECTION "..first"
#define PER_CPU_SHARED_ALIGNED_SECTION ""
#define SHIFT_PERCPU_PTR(__p, __offset)					\
	RELOC_HIDE((typeof(*(__p)) __kernel __force *)(__p), (__offset))
#define VERIFY_PERCPU_PTR(__p)						\
({									\
	__verify_pcpu_ptr(__p);						\
	(typeof(*(__p)) __kernel __force *)(__p);			\
})

#define __PCPU_ATTRS(sec)						\
	__percpu __attribute__((section(PER_CPU_BASE_SECTION sec)))	\
	PER_CPU_ATTRIBUTES
#define __pcpu_double_call_return_bool(stem, pcp1, pcp2, ...)		\
({									\
	bool pdcrb_ret__;						\
	__verify_pcpu_ptr(&(pcp1));					\
	BUILD_BUG_ON(sizeof(pcp1) != sizeof(pcp2));			\
	VM_BUG_ON((unsigned long)(&(pcp1)) % (2 * sizeof(pcp1)));	\
	VM_BUG_ON((unsigned long)(&(pcp2)) !=				\
		  (unsigned long)(&(pcp1)) + sizeof(pcp1));		\
	switch(sizeof(pcp1)) {						\
	case 1: pdcrb_ret__ = stem##1(pcp1, pcp2, __VA_ARGS__); break;	\
	case 2: pdcrb_ret__ = stem##2(pcp1, pcp2, __VA_ARGS__); break;	\
	case 4: pdcrb_ret__ = stem##4(pcp1, pcp2, __VA_ARGS__); break;	\
	case 8: pdcrb_ret__ = stem##8(pcp1, pcp2, __VA_ARGS__); break;	\
	default:							\
		__bad_size_call_parameter(); break;			\
	}								\
	pdcrb_ret__;							\
})
#define __pcpu_size_call(stem, variable, ...)				\
do {									\
	__verify_pcpu_ptr(&(variable));					\
	switch(sizeof(variable)) {					\
		case 1: stem##1(variable, __VA_ARGS__);break;		\
		case 2: stem##2(variable, __VA_ARGS__);break;		\
		case 4: stem##4(variable, __VA_ARGS__);break;		\
		case 8: stem##8(variable, __VA_ARGS__);break;		\
		default: 						\
			__bad_size_call_parameter();break;		\
	}								\
} while (0)
#define __pcpu_size_call_return(stem, variable)				\
({									\
	typeof(variable) pscr_ret__;					\
	__verify_pcpu_ptr(&(variable));					\
	switch(sizeof(variable)) {					\
	case 1: pscr_ret__ = stem##1(variable); break;			\
	case 2: pscr_ret__ = stem##2(variable); break;			\
	case 4: pscr_ret__ = stem##4(variable); break;			\
	case 8: pscr_ret__ = stem##8(variable); break;			\
	default:							\
		__bad_size_call_parameter(); break;			\
	}								\
	pscr_ret__;							\
})
#define __pcpu_size_call_return2(stem, variable, ...)			\
({									\
	typeof(variable) pscr2_ret__;					\
	__verify_pcpu_ptr(&(variable));					\
	switch(sizeof(variable)) {					\
	case 1: pscr2_ret__ = stem##1(variable, __VA_ARGS__); break;	\
	case 2: pscr2_ret__ = stem##2(variable, __VA_ARGS__); break;	\
	case 4: pscr2_ret__ = stem##4(variable, __VA_ARGS__); break;	\
	case 8: pscr2_ret__ = stem##8(variable, __VA_ARGS__); break;	\
	default:							\
		__bad_size_call_parameter(); break;			\
	}								\
	pscr2_ret__;							\
})
#define __this_cpu_add(pcp, val)					\
({									\
	__this_cpu_preempt_check("add");				\
	raw_cpu_add(pcp, val);						\
})
#define __this_cpu_add_return(pcp, val)					\
({									\
	__this_cpu_preempt_check("add_return");				\
	raw_cpu_add_return(pcp, val);					\
})
#define __this_cpu_and(pcp, val)					\
({									\
	__this_cpu_preempt_check("and");				\
	raw_cpu_and(pcp, val);						\
})
#define __this_cpu_cmpxchg(pcp, oval, nval)				\
({									\
	__this_cpu_preempt_check("cmpxchg");				\
	raw_cpu_cmpxchg(pcp, oval, nval);				\
})
#define __this_cpu_cmpxchg_double(pcp1, pcp2, oval1, oval2, nval1, nval2) \
({	__this_cpu_preempt_check("cmpxchg_double");			\
	raw_cpu_cmpxchg_double(pcp1, pcp2, oval1, oval2, nval1, nval2);	\
})
#define __this_cpu_dec(pcp)		__this_cpu_sub(pcp, 1)
#define __this_cpu_dec_return(pcp)	__this_cpu_add_return(pcp, -1)
#define __this_cpu_inc(pcp)		__this_cpu_add(pcp, 1)
#define __this_cpu_inc_return(pcp)	__this_cpu_add_return(pcp, 1)
#define __this_cpu_or(pcp, val)						\
({									\
	__this_cpu_preempt_check("or");					\
	raw_cpu_or(pcp, val);						\
})
#define __this_cpu_read(pcp)						\
({									\
	__this_cpu_preempt_check("read");				\
	raw_cpu_read(pcp);						\
})
#define __this_cpu_sub(pcp, val)	__this_cpu_add(pcp, -(typeof(pcp))(val))
#define __this_cpu_sub_return(pcp, val)	__this_cpu_add_return(pcp, -(typeof(pcp))(val))
#define __this_cpu_write(pcp, val)					\
({									\
	__this_cpu_preempt_check("write");				\
	raw_cpu_write(pcp, val);					\
})
#define __this_cpu_xchg(pcp, nval)					\
({									\
	__this_cpu_preempt_check("xchg");				\
	raw_cpu_xchg(pcp, nval);					\
})
#define __verify_pcpu_ptr(ptr)						\
do {									\
	const void __percpu *__vpp_verify = (typeof((ptr) + 0))NULL;	\
	(void)__vpp_verify;						\
} while (0)
#define get_cpu_ptr(var)						\
({									\
	preempt_disable();						\
	this_cpu_ptr(var);						\
})
#define get_cpu_var(var)						\
(*({									\
	preempt_disable();						\
	this_cpu_ptr(&var);						\
}))
#define per_cpu_ptr(ptr, cpu)						\
({									\
	__verify_pcpu_ptr(ptr);						\
	SHIFT_PERCPU_PTR((ptr), per_cpu_offset((cpu)));			\
})
#define put_cpu_ptr(var)						\
do {									\
	(void)(var);							\
	preempt_enable();						\
} while (0)
#define put_cpu_var(var)						\
do {									\
	(void)&(var);							\
	preempt_enable();						\
} while (0)
#define raw_cpu_add(pcp, val)		__pcpu_size_call(raw_cpu_add_, pcp, val)
#define raw_cpu_and(pcp, val)		__pcpu_size_call(raw_cpu_and_, pcp, val)
#define raw_cpu_cmpxchg(pcp, oval, nval) \
	__pcpu_size_call_return2(raw_cpu_cmpxchg_, pcp, oval, nval)
#define raw_cpu_cmpxchg_double(pcp1, pcp2, oval1, oval2, nval1, nval2) \
	__pcpu_double_call_return_bool(raw_cpu_cmpxchg_double_, pcp1, pcp2, oval1, oval2, nval1, nval2)
#define raw_cpu_dec(pcp)		raw_cpu_sub(pcp, 1)
#define raw_cpu_dec_return(pcp)		raw_cpu_add_return(pcp, -1)
#define raw_cpu_inc(pcp)		raw_cpu_add(pcp, 1)
#define raw_cpu_inc_return(pcp)		raw_cpu_add_return(pcp, 1)
#define raw_cpu_or(pcp, val)		__pcpu_size_call(raw_cpu_or_, pcp, val)
#define raw_cpu_ptr(ptr)						\
({									\
	__verify_pcpu_ptr(ptr);						\
	arch_raw_cpu_ptr(ptr);						\
})
#define raw_cpu_read(pcp)		__pcpu_size_call_return(raw_cpu_read_, pcp)
#define raw_cpu_sub(pcp, val)		raw_cpu_add(pcp, -(val))
#define raw_cpu_sub_return(pcp, val)	raw_cpu_add_return(pcp, -(typeof(pcp))(val))
#define raw_cpu_write(pcp, val)		__pcpu_size_call(raw_cpu_write_, pcp, val)
#define raw_cpu_xchg(pcp, nval)		__pcpu_size_call_return2(raw_cpu_xchg_, pcp, nval)
#define this_cpu_add(pcp, val)		__pcpu_size_call(this_cpu_add_, pcp, val)
#define this_cpu_and(pcp, val)		__pcpu_size_call(this_cpu_and_, pcp, val)
#define this_cpu_cmpxchg(pcp, oval, nval) \
	__pcpu_size_call_return2(this_cpu_cmpxchg_, pcp, oval, nval)
#define this_cpu_cmpxchg_double(pcp1, pcp2, oval1, oval2, nval1, nval2) \
	__pcpu_double_call_return_bool(this_cpu_cmpxchg_double_, pcp1, pcp2, oval1, oval2, nval1, nval2)
#define this_cpu_dec(pcp)		this_cpu_sub(pcp, 1)
#define this_cpu_dec_return(pcp)	this_cpu_add_return(pcp, -1)
#define this_cpu_inc(pcp)		this_cpu_add(pcp, 1)
#define this_cpu_inc_return(pcp)	this_cpu_add_return(pcp, 1)
#define this_cpu_or(pcp, val)		__pcpu_size_call(this_cpu_or_, pcp, val)
#define this_cpu_ptr(ptr)						\
({									\
	__verify_pcpu_ptr(ptr);						\
	SHIFT_PERCPU_PTR(ptr, my_cpu_offset);				\
})
#define this_cpu_read(pcp)		__pcpu_size_call_return(this_cpu_read_, pcp)
#define this_cpu_sub(pcp, val)		this_cpu_add(pcp, -(typeof(pcp))(val))
#define this_cpu_sub_return(pcp, val)	this_cpu_add_return(pcp, -(typeof(pcp))(val))



#define __alloc_zeroed_user_highpage(movableflags, vma, vaddr) \
	alloc_page_vma(GFP_HIGHUSER | __GFP_ZERO | movableflags, vma, vaddr)
#define __boot_pa(x)		__pa(x)
#define __boot_va(x)		__va(x)
#define __pa(x)		__phys_addr((unsigned long)(x))
#define __pa_nodebug(x)	__phys_addr_nodebug((unsigned long)(x))
#define __pa_symbol(x) \
	__phys_addr_symbol(__phys_reloc_hide((unsigned long)(x)))
#define __va(x)			((void *)((unsigned long)(x)+PAGE_OFFSET))
#define pfn_to_kaddr(pfn)      __va((pfn) << PAGE_SHIFT)
#define virt_to_page(kaddr)	pfn_to_page(__pa(kaddr) >> PAGE_SHIFT)


#define __page_to_pfn(page)	((unsigned long)((page) - mem_map) + \
				 ARCH_PFN_OFFSET)
#define __pfn_to_page(pfn)	(mem_map + ((pfn) - ARCH_PFN_OFFSET))
#define arch_local_page_offset(pfn, nid)	\
	((pfn) - NODE_DATA(nid)->node_start_pfn)
#define arch_pfn_to_nid(pfn)	pfn_to_nid(pfn)
#define page_to_pfn __page_to_pfn
#define pfn_to_page __pfn_to_page
#define PFN_ALIGN(x)	(((unsigned long)(x) + (PAGE_SIZE - 1)) & PAGE_MASK)
#define PFN_DOWN(x)	((x) >> PAGE_SHIFT)
#define PFN_PHYS(x)	((phys_addr_t)(x) << PAGE_SHIFT)
#define PFN_UP(x)	(((x) + PAGE_SIZE-1) >> PAGE_SHIFT)
#define PHYS_PFN(x)	((unsigned long)((x) >> PAGE_SHIFT))

#define MAX_RESOURCE ((resource_size_t)~0)


#define __phys_addr(x)		__phys_addr_nodebug(x)
#define __phys_addr_nodebug(x)	((x) - PAGE_OFFSET)
#define __phys_addr_symbol(x)	__phys_addr(x)
#define __phys_reloc_hide(x)	RELOC_HIDE((x), 0)
#define pfn_valid(pfn)		((pfn) < max_mapnr)


# define __HAVE_ARCH_GATE_AREA 1

#define current get_current()

# define _fpstate _fpstate_32
#  define sigcontext sigcontext_32


#define MAX_REG_OFFSET (offsetof(struct pt_regs, ss))
#define NR_REG_ARGUMENTS 3

#define arch_has_block_step()	(1)
#define arch_has_single_step()	(1)
#define compat_user_stack_pointer()	current_pt_regs()->sp
#define current_user_stack_pointer()	current_pt_regs()->sp
# define do_set_thread_area_64(p, s, t)	do_arch_prctl_64(p, s, t)

#define REFCOUNT_INIT(n)	{ .refs = ATOMIC_INIT(n), }

#define DEFINE_RAW_SPINLOCK(x)	raw_spinlock_t x = __RAW_SPIN_LOCK_UNLOCKED(x)
#define DEFINE_SPINLOCK(x)	spinlock_t x = __SPIN_LOCK_UNLOCKED(x)
# define LOCK_PADSIZE (offsetof(struct raw_spinlock, dep_map))
# define RAW_SPIN_DEP_MAP_INIT(lockname)		\
	.dep_map = {					\
		.name = #lockname,			\
		.wait_type_inner = LD_WAIT_SPIN,	\
	}
# define SPIN_DEBUG_INIT(lockname)		\
	.magic = SPINLOCK_MAGIC,		\
	.owner_cpu = -1,			\
	.owner = SPINLOCK_OWNER_INIT,
# define SPIN_DEP_MAP_INIT(lockname)			\
	.dep_map = {					\
		.name = #lockname,			\
		.wait_type_inner = LD_WAIT_CONFIG,	\
	}

#define __RAW_SPIN_LOCK_INITIALIZER(lockname)	\
	{					\
	.raw_lock = __ARCH_SPIN_LOCK_UNLOCKED,	\
	SPIN_DEBUG_INIT(lockname)		\
	RAW_SPIN_DEP_MAP_INIT(lockname) }
#define __RAW_SPIN_LOCK_UNLOCKED(lockname)	\
	(raw_spinlock_t) __RAW_SPIN_LOCK_INITIALIZER(lockname)
#define __SPIN_LOCK_INITIALIZER(lockname) \
	{ { .rlock = ___SPIN_LOCK_INITIALIZER(lockname) } }
#define __SPIN_LOCK_UNLOCKED(lockname) \
	(spinlock_t) __SPIN_LOCK_INITIALIZER(lockname)
#define ___SPIN_LOCK_INITIALIZER(lockname)	\
	{					\
	.raw_lock = __ARCH_SPIN_LOCK_UNLOCKED,	\
	SPIN_DEBUG_INIT(lockname)		\
	SPIN_DEP_MAP_INIT(lockname) }
#define DEFINE_RWLOCK(x)	rwlock_t x = __RW_LOCK_UNLOCKED(x)
# define RW_DEP_MAP_INIT(lockname)					\
	.dep_map = {							\
		.name = #lockname,					\
		.wait_type_inner = LD_WAIT_CONFIG,			\
	}

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
# define lockdep_assert_RT_in_threaded_ctx() do {			\
		WARN_ONCE(debug_locks && !current->lockdep_recursion &&	\
			  current->hardirq_context &&			\
			  !(current->hardirq_threaded || current->irq_config),	\
			  "Not in threaded context on PREEMPT_RT as expected\n");	\
} while (0)
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
# define lockdep_init_map_wait(lock, name, key, sub, inner) \
		do { (void)(name); (void)(key); } while (0)
# define lockdep_init_map_waits(lock, name, key, sub, inner, outer) \
		do { (void)(name); (void)(key); } while (0)
#define lockdep_is_held(lock)		lock_is_held(&(lock)->dep_map)
#define lockdep_is_held_type(lock, r)	lock_is_held_type(&(lock)->dep_map, (r))
#define lockdep_match_class(lock, key) lockdep_match_key(&(lock)->dep_map, key)
#define lockdep_off()					\
do {							\
	current->lockdep_recursion += LOCKDEP_OFF;	\
} while (0)
#define lockdep_on()					\
do {							\
	current->lockdep_recursion -= LOCKDEP_OFF;	\
} while (0)
#define lockdep_pin_lock(l)	lock_pin_lock(&(l)->dep_map)
#define lockdep_recursing(tsk)	((tsk)->lockdep_recursion)
#define lockdep_repin_lock(l,c)	lock_repin_lock(&(l)->dep_map, (c))
# define lockdep_reset()		do { debug_locks = 1; } while (0)
# define lockdep_set_class(lock, key)		do { (void)(key); } while (0)
# define lockdep_set_class_and_name(lock, key, name) \
		do { (void)(key); (void)(name); } while (0)
#define lockdep_set_class_and_subclass(lock, key, sub)		\
	lockdep_init_map_waits(&(lock)->dep_map, #key, key, sub,\
			       (lock)->dep_map.wait_type_inner,	\
			       (lock)->dep_map.wait_type_outer)
#define lockdep_set_novalidate_class(lock) \
	lockdep_set_class_and_name(lock, &__lockdep_no_validate__, #lock)
#define lockdep_set_subclass(lock, sub)					\
	lockdep_init_map_waits(&(lock)->dep_map, #lock, (lock)->dep_map.key, sub,\
			       (lock)->dep_map.wait_type_inner,		\
			       (lock)->dep_map.wait_type_outer)
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


#define __tlb_remove_tlb_entry(tlb, ptep, address) do { } while (0)
#define tlb_end_vma(tlb, vma) do { } while (0)
#define tlb_flush tlb_flush
#define tlb_start_vma(tlb, vma) do { } while (0)

#define __tlb_remove_pmd_tlb_entry(tlb, pmdp, address) do {} while (0)
#define __tlb_remove_pud_tlb_entry(tlb, pudp, address) do {} while (0)
# define nmi_uaccess_okay() true
#define p4d_free_tlb(tlb, pudp, address)			\
	do {							\
		__tlb_adjust_range(tlb, address, PAGE_SIZE);	\
		tlb->freed_tables = 1;				\
		__p4d_free_tlb(tlb, pudp, address);		\
	} while (0)
#define pmd_free_tlb(tlb, pmdp, address)			\
	do {							\
		__tlb_adjust_range(tlb, address, PAGE_SIZE);	\
		tlb->freed_tables = 1;				\
		tlb->cleared_puds = 1;				\
		__pmd_free_tlb(tlb, pmdp, address);		\
	} while (0)
#define pte_free_tlb(tlb, ptep, address)			\
	do {							\
		__tlb_adjust_range(tlb, address, PAGE_SIZE);	\
		tlb->freed_tables = 1;				\
		tlb->cleared_pmds = 1;				\
		__pte_free_tlb(tlb, ptep, address);		\
	} while (0)
#define pud_free_tlb(tlb, pudp, address)			\
	do {							\
		__tlb_adjust_range(tlb, address, PAGE_SIZE);	\
		tlb->freed_tables = 1;				\
		tlb->cleared_p4ds = 1;				\
		__pud_free_tlb(tlb, pudp, address);		\
	} while (0)
#define tlb_needs_table_invalidate() (true)
#define tlb_remove_huge_tlb_entry(h, tlb, ptep, address)	\
	do {							\
		unsigned long _sz = huge_page_size(h);		\
		__tlb_adjust_range(tlb, address, _sz);		\
		if (_sz == PMD_SIZE)				\
			tlb->cleared_pmds = 1;			\
		else if (_sz == PUD_SIZE)			\
			tlb->cleared_puds = 1;			\
		__tlb_remove_tlb_entry(tlb, ptep, address);	\
	} while (0)
#define tlb_remove_pmd_tlb_entry(tlb, pmdp, address)			\
	do {								\
		__tlb_adjust_range(tlb, address, HPAGE_PMD_SIZE);	\
		tlb->cleared_pmds = 1;					\
		__tlb_remove_pmd_tlb_entry(tlb, pmdp, address);		\
	} while (0)
#define tlb_remove_pud_tlb_entry(tlb, pudp, address)			\
	do {								\
		__tlb_adjust_range(tlb, address, HPAGE_PUD_SIZE);	\
		tlb->cleared_puds = 1;					\
		__tlb_remove_pud_tlb_entry(tlb, pudp, address);		\
	} while (0)
#define tlb_remove_table(tlb, page) tlb_remove_page((tlb), (page))
#define tlb_remove_tlb_entry(tlb, ptep, address)		\
	do {							\
		__tlb_adjust_range(tlb, address, PAGE_SIZE);	\
		tlb->cleared_ptes = 1;				\
		__tlb_remove_tlb_entry(tlb, ptep, address);	\
	} while (0)

#define FAULT_FLAG_DEFAULT  (FAULT_FLAG_ALLOW_RETRY | \
			     FAULT_FLAG_KILLABLE | \
			     FAULT_FLAG_INTERRUPTIBLE)
#define FAULT_FLAG_INSTRUCTION  		0x100
#define FAULT_FLAG_TRACE \
	{ FAULT_FLAG_WRITE,		"WRITE" }, \
	{ FAULT_FLAG_MKWRITE,		"MKWRITE" }, \
	{ FAULT_FLAG_ALLOW_RETRY,	"ALLOW_RETRY" }, \
	{ FAULT_FLAG_RETRY_NOWAIT,	"RETRY_NOWAIT" }, \
	{ FAULT_FLAG_KILLABLE,		"KILLABLE" }, \
	{ FAULT_FLAG_TRIED,		"TRIED" }, \
	{ FAULT_FLAG_USER,		"USER" }, \
	{ FAULT_FLAG_REMOTE,		"REMOTE" }, \
	{ FAULT_FLAG_INSTRUCTION,	"INSTRUCTION" }, \
	{ FAULT_FLAG_INTERRUPTIBLE,	"INTERRUPTIBLE" }
#define GUP_PIN_COUNTING_BIAS (1U << 10)

#define  MM_CP_DIRTY_ACCT                  (1UL << 0)
#define  MM_CP_PROT_NUMA                   (1UL << 1)
#define  MM_CP_UFFD_WP                     (1UL << 2) 
#define  MM_CP_UFFD_WP_ALL                 (MM_CP_UFFD_WP | \
					    MM_CP_UFFD_WP_RESOLVE)
#define  MM_CP_UFFD_WP_RESOLVE             (1UL << 3) 
#define PAGE_ALIGN(addr) ALIGN(addr, PAGE_SIZE)
#define PAGE_ALIGNED(addr)	IS_ALIGNED((unsigned long)(addr), PAGE_SIZE)

#define TASK_EXEC ((current->personality & READ_IMPLIES_EXEC) ? VM_EXEC : 0)
#define TLB_FLUSH_VMA(mm,flags) { .vm_mm = (mm), .vm_flags = (flags) }
#define VM_ACCESS_FLAGS (VM_READ | VM_WRITE | VM_EXEC)
#define VM_DATA_DEFAULT_FLAGS  VM_DATA_FLAGS_EXEC
#define VM_IO           0x00004000	
#define VM_NO_KHUGEPAGED (VM_SPECIAL | VM_HUGETLB)
# define VM_PKEY_BIT4  VM_HIGH_ARCH_4
#define VM_SPECIAL (VM_IO | VM_DONTEXPAND | VM_PFNMAP | VM_MIXEDMAP)
#define VM_STACK_DEFAULT_FLAGS VM_DATA_DEFAULT_FLAGS
#define VM_UNMAPPED_AREA_TOPDOWN 1

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
#define pte_alloc_kernel_track(pmd, address, mask)			\
	((unlikely(pmd_none(*(pmd))) &&					\
	  (__pte_alloc_kernel(pmd) || ({*(mask)|=PGTBL_PMD_MODIFIED;0;})))?\
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
#define THP_FILE_FALLBACK ({ BUILD_BUG(); 0; })
#define THP_FILE_FALLBACK_CHARGE ({ BUILD_BUG(); 0; })
#define THP_FILE_MAPPED ({ BUILD_BUG(); 0; })

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
#define SUBSECTION_SIZE (1UL << SUBSECTION_SHIFT)
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
#define pfn_in_present_section pfn_valid
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
#define COMPLETION_INITIALIZER(work) \
	{ 0, __SWAIT_QUEUE_HEAD_INITIALIZER((work).wait) }
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
# define spin_lock_init(lock)					\
do {								\
	static struct lock_class_key __key;			\
								\
	__raw_spin_lock_init(spinlock_check(lock),		\
			     #lock, &__key, LD_WAIT_CONFIG);	\
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





#  define NUM_RCU_LVL_INIT    { NUM_RCU_LVL_0 }
# define RCU_FANOUT 64
#define RCU_FANOUT_LEAF 16
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
# define call_rcu_tasks call_rcu
#define cond_resched_tasks_rcu_qs() \
do { \
	rcu_tasks_qs(current, false); \
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
#define rcu_note_voluntary_context_switch(t) rcu_tasks_qs(t, false)
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
# define rcu_tasks_classic_qs(t, preempt)				\
	do {								\
		if (!(preempt) && READ_ONCE((t)->rcu_tasks_holdout))	\
			WRITE_ONCE((t)->rcu_tasks_holdout, false);	\
	} while (0)
#define rcu_tasks_qs(t, preempt)					\
do {									\
	rcu_tasks_classic_qs((t), (preempt));				\
	rcu_tasks_trace_qs((t));					\
} while (0)
# define rcu_tasks_trace_qs(t)						\
	do {								\
		if (!likely(READ_ONCE((t)->trc_reader_checked)) &&	\
		    !unlikely(READ_ONCE((t)->trc_reader_nesting))) {	\
			smp_store_release(&(t)->trc_reader_checked, true); \
			smp_mb(); 	\
		}							\
	} while (0)
#define smp_mb__after_unlock_lock()	smp_mb()  
# define synchronize_rcu_tasks synchronize_rcu
#define ulong2long(a)		(*(long *)(&(a)))

#define rcu_note_context_switch(preempt) \
	do { \
		rcu_qs(); \
		rcu_tasks_qs(current, (preempt)); \
	} while (0)
#define rcutree_dead_cpu         NULL
#define rcutree_dying_cpu        NULL
#define rcutree_offline_cpu      NULL
#define rcutree_online_cpu       NULL
#define rcutree_prepare_cpu      NULL

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


#define ktime_add(lhs, rhs)	((lhs) + (rhs))
#define ktime_add_ns(kt, nsval)		((kt) + (nsval))
#define ktime_add_unsafe(lhs, rhs)	((u64) (lhs) + (rhs))
#define ktime_sub(lhs, rhs)	((lhs) - (rhs))
#define ktime_sub_ns(kt, nsval)		((kt) - (nsval))
#define ktime_to_timespec64(kt)		ns_to_timespec64((kt))

#define TICK_NSEC ((NSEC_PER_SEC+HZ/2)/HZ)

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
#define DEFINE_MUTEX(mutexname) \
	struct mutex mutexname = __MUTEX_INITIALIZER(mutexname)
# define __DEBUG_MUTEX_INITIALIZER(lockname)
# define __DEP_MAP_MUTEX_INITIALIZER(lockname)			\
		, .dep_map = {					\
			.name = #lockname,			\
			.wait_type_inner = LD_WAIT_SLEEP,	\
		}

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

#define DECLARE_RWSEM(name) \
	struct rw_semaphore name = __RWSEM_INITIALIZER(name)

# define __DEBUG_RWSEM_INITIALIZER(lockname) , .magic = &lockname
# define __RWSEM_DEP_MAP_INIT(lockname)			\
	, .dep_map = {					\
		.name = #lockname,			\
		.wait_type_inner = LD_WAIT_SLEEP,	\
	}
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

#define __initdata_or_meminfo __initdata

#define uprobe_get_trap_addr(regs)	instruction_pointer(regs)
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
#define KCSAN_SEQLOCK_REGION_MAX 1000
#define SEQCNT_ZERO(lockname) { .sequence = 0, SEQCOUNT_DEP_MAP_INIT(lockname)}
# define SEQCOUNT_DEP_MAP_INIT(lockname)

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

#define alloc_percpu(type)						\
	(typeof(type) __percpu *)__alloc_percpu(sizeof(type),		\
						__alignof__(type))
#define alloc_percpu_gfp(type, gfp)					\
	(typeof(type) __percpu *)__alloc_percpu_gfp(sizeof(type),	\
						__alignof__(type), gfp)

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
#define HPAGE_CACHE_INDEX_MASK (HPAGE_PMD_NR - 1)
#define HPAGE_PMD_MASK ({ BUILD_BUG(); 0; })
#define HPAGE_PMD_NR (1<<HPAGE_PMD_ORDER)
#define HPAGE_PMD_ORDER (HPAGE_PMD_SHIFT-PAGE_SHIFT)
#define HPAGE_PMD_SHIFT PMD_SHIFT
#define HPAGE_PMD_SIZE ({ BUILD_BUG(); 0; })
#define HPAGE_PUD_MASK ({ BUILD_BUG(); 0; })
#define HPAGE_PUD_SHIFT PUD_SHIFT
#define HPAGE_PUD_SIZE ({ BUILD_BUG(); 0; })

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
	id(FIRMWARE_EFI_EMBEDDED, firmware)	\
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

#define topology_llc_cpumask(cpu)	(&cpu_topology[cpu].llc_sibling)
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
			    MNT_DOOMED | MNT_SYNC_UMOUNT | MNT_MARKED | \
			    MNT_CURSOR)
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

# define PAGE_KERNEL_EXEC PAGE_KERNEL


#define arch_enter_lazy_mmu_mode()	do {} while (0)
#define arch_flush_lazy_mmu_mode()	do {} while (0)
#define arch_leave_lazy_mmu_mode()	do {} while (0)
#define arch_needs_pgtable_deposit() (false)
#define arch_start_context_switch(prev)	do {} while (0)
#define flush_pmd_tlb_range(vma, addr, end)	flush_tlb_range(vma, addr, end)
#define flush_pud_tlb_range(vma, addr, end)	flush_tlb_range(vma, addr, end)
#define flush_tlb_fix_spurious_fault(vma, address) flush_tlb_page(vma, address)
#define has_transparent_hugepage() 1
#define io_remap_pfn_range remap_pfn_range
#define mm_p4d_folded(mm)	__is_defined(__PAGETABLE_P4D_FOLDED)
#define mm_pmd_folded(mm)	__is_defined(__PAGETABLE_PMD_FOLDED)
#define mm_pud_folded(mm)	__is_defined(__PAGETABLE_PUD_FOLDED)
#define move_pte(pte, prot, old_addr, new_addr)	(pte)
#define my_zero_pfn(addr)	page_to_pfn(ZERO_PAGE(addr))
#define p4d_access_permitted(p4d, write) \
	(p4d_present(p4d) && (!(write) || p4d_write(p4d)))
#define p4d_clear_bad(p4d)        do { } while (0)
#define p4d_leaf(x)	0
#define pgd_access_permitted(pgd, write) \
	(pgd_present(pgd) && (!(write) || pgd_write(pgd)))
#define pgd_addr_end(addr, end)						\
({	unsigned long __boundary = ((addr) + PGDIR_SIZE) & PGDIR_MASK;	\
	(__boundary - 1 < (end) - 1)? __boundary: (end);		\
})
#define pgd_index(a)  (((a) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1))
#define pgd_leaf(x)	0
#define pgd_offset(mm, address)		pgd_offset_pgd((mm)->pgd, (address))
#define pgd_offset_gate(mm, addr)	pgd_offset(mm, addr)
#define pgd_offset_k(address)		pgd_offset(&init_mm, (address))
#define pgprot_decrypted(prot)	(prot)
#define pgprot_device pgprot_noncached
#define pgprot_encrypted(prot)	(prot)
#define pgprot_modify pgprot_modify
#define pgprot_noncached(prot)	(prot)
#define pgprot_writecombine pgprot_noncached
#define pgprot_writethrough pgprot_noncached
#define pmd_access_permitted(pmd, write) \
	(pmd_present(pmd) && (!(write) || pmd_write(pmd)))
#define pmd_clear_savedwrite pmd_wrprotect
#define pmd_index pmd_index
#define pmd_leaf(x)	0
#define pmd_mk_savedwrite pmd_mkwrite
#define pmd_savedwrite pmd_write
#define pmdp_collapse_flush pmdp_collapse_flush
#define pte_access_permitted(pte, write) \
	(pte_present(pte) && (!(write) || pte_write(pte)))
# define pte_accessible(mm, pte)	((void)(pte), 1)
#define pte_clear_savedwrite pte_wrprotect
#define pte_mk_savedwrite pte_mkwrite
#define pte_offset_kernel pte_offset_kernel
#define pte_offset_map(dir, address)				\
	((pte_t *)kmap_atomic(pmd_page(*(dir))) +		\
	 pte_index((address)))
#define pte_savedwrite pte_write
#define pte_unmap(pte) kunmap_atomic((pte))
#define pud_access_permitted(pud, write) \
	(pud_present(pud) && (!(write) || pud_write(pud)))
#define pud_clear_bad(p4d)        do { } while (0)
#define pud_index pud_index
#define pud_leaf(x)	0
#define set_p4d_safe(p4dp, p4d) \
({ \
	WARN_ON_ONCE(p4d_present(*p4dp) && !p4d_same(*p4dp, p4d)); \
	set_p4d(p4dp, p4d); \
})
#define set_pgd_safe(pgdp, pgd) \
({ \
	WARN_ON_ONCE(pgd_present(*pgdp) && !pgd_same(*pgdp, pgd)); \
	set_pgd(pgdp, pgd); \
})
#define set_pmd_safe(pmdp, pmd) \
({ \
	WARN_ON_ONCE(pmd_present(*pmdp) && !pmd_same(*pmdp, pmd)); \
	set_pmd(pmdp, pmd); \
})
#define set_pte_safe(ptep, pte) \
({ \
	WARN_ON_ONCE(pte_present(*ptep) && !pte_same(*ptep, pte)); \
	set_pte(ptep, pte); \
})
#define set_pud_safe(pudp, pud) \
({ \
	WARN_ON_ONCE(pud_present(*pudp) && !pud_same(*pudp, pud)); \
	set_pud(pudp, pud); \
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
#define flex_array_size(p, member, count)				\
	array_size(count,						\
		    sizeof(*(p)->member) + __must_be_array((p)->member))
#define is_negative(a) (!(is_non_negative(a)))
#define is_non_negative(a) ((a) > 0 || (a) == 0)
#define is_signed_type(type)       (((type)(-1)) < (type)1)
#define struct_size(p, member, count)					\
	__ab_c_size(count,						\
		    sizeof(*(p)->member) + __must_be_array((p)->member),\
		    sizeof(*(p)))
#define type_max(T) ((T)((__type_half_max(T) - 1) + __type_half_max(T)))
#define type_min(T) ((T)((T)-type_max(T)-(T)1))



#define IOPRIO_PRIO_CLASS(mask)	((mask) >> IOPRIO_CLASS_SHIFT)
#define IOPRIO_PRIO_DATA(mask)	((mask) & IOPRIO_PRIO_MASK)
#define IOPRIO_PRIO_VALUE(class, data)	(((class) << IOPRIO_CLASS_SHIFT) | data)
#define ioprio_valid(mask)	(IOPRIO_PRIO_CLASS((mask)) != IOPRIO_CLASS_NONE)

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

#define local_lock(lock)		__local_lock(lock)
#define local_lock_init(lock)		__local_lock_init(lock)
#define local_lock_irq(lock)		__local_lock_irq(lock)
#define local_lock_irqsave(lock, flags)				\
	__local_lock_irqsave(lock, flags)
#define local_unlock(lock)		__local_unlock(lock)
#define local_unlock_irq(lock)		__local_unlock_irq(lock)
#define local_unlock_irqrestore(lock, flags)			\
	__local_unlock_irqrestore(lock, flags)
#define INIT_LOCAL_LOCK(lockname)	{ LL_DEP_MAP_INIT(lockname) }
# define LL_DEP_MAP_INIT(lockname)			\
	.dep_map = {					\
		.name = #lockname,			\
		.wait_type_inner = LD_WAIT_CONFIG,	\
	}
#define __local_lock(lock)					\
	do {							\
		preempt_disable();				\
		local_lock_acquire(this_cpu_ptr(lock));		\
	} while (0)
#define __local_lock_init(lock)					\
do {								\
	static struct lock_class_key __key;			\
								\
	debug_check_no_locks_freed((void *)lock, sizeof(*lock));\
	lockdep_init_map_wait(&(lock)->dep_map, #lock, &__key, 0, LD_WAIT_CONFIG);\
} while (0)
#define __local_lock_irq(lock)					\
	do {							\
		local_irq_disable();				\
		local_lock_acquire(this_cpu_ptr(lock));		\
	} while (0)
#define __local_lock_irqsave(lock, flags)			\
	do {							\
		local_irq_save(flags);				\
		local_lock_acquire(this_cpu_ptr(lock));		\
	} while (0)
#define __local_unlock(lock)					\
	do {							\
		local_lock_release(this_cpu_ptr(lock));		\
		preempt_enable();				\
	} while (0)
#define __local_unlock_irq(lock)				\
	do {							\
		local_lock_release(this_cpu_ptr(lock));		\
		local_irq_enable();				\
	} while (0)
#define __local_unlock_irqrestore(lock, flags)			\
	do {							\
		local_lock_release(this_cpu_ptr(lock));		\
		local_irq_restore(flags);			\
	} while (0)
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

# define rt_mutex_adjust_pi(p)		do { } while (0)
#define TASK_PFA_CLEAR(name, func)					\
	static inline void task_clear_##func(struct task_struct *p)	\
	{ clear_bit(PFA_##name, &p->atomic_flags); }
#define TASK_PFA_SET(name, func)					\
	static inline void task_set_##func(struct task_struct *p)	\
	{ set_bit(PFA_##name, &p->atomic_flags); }
#define TASK_PFA_TEST(name, func)					\
	static inline bool task_##func(struct task_struct *p)		\
	{ return test_bit(PFA_##name, &p->atomic_flags); }
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




# define __hrtimer_clock_base_align




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
	RCU_LOCKDEP_WARN(!(cond) && !rcu_read_lock_any_held(),		\
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
#define CLONE_ARGS_SIZE_VER2 88 
#define CLONE_CLEAR_SIGHAND 0x100000000ULL 
#define CLONE_INTO_CGROUP 0x200000000ULL 
#define SCHED_RESET_ON_FORK     0x40000000


#define UUID_INIT(a, b, c, d0, d1, d2, d3, d4, d5, d6, d7)			\
((uuid_t)								\
{{ ((a) >> 24) & 0xff, ((a) >> 16) & 0xff, ((a) >> 8) & 0xff, (a) & 0xff, \
   ((b) >> 8) & 0xff, (b) & 0xff,					\
   ((c) >> 8) & 0xff, (c) & 0xff,					\
   (d0), (d1), (d2), (d3), (d4), (d5), (d6), (d7) }})
#define UUID_SIZE 16

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
	.writer = __RCUWAIT_INITIALIZER(name.writer),			\
	.waiters = __WAIT_QUEUE_HEAD_INITIALIZER(name.waiters),		\
	.block = ATOMIC_INIT(0),					\
	__PERCPU_RWSEM_DEP_MAP_INIT(name)				\
}
#define __PERCPU_RWSEM_DEP_MAP_INIT(lockname)	.dep_map = { .name = #lockname },
#define percpu_init_rwsem(sem)					\
({								\
	static struct lock_class_key rwsem_key;			\
	__percpu_init_rwsem(sem, #sem, &rwsem_key);		\
})
#define percpu_rwsem_assert_held(sem)	lockdep_assert_held(sem)
#define percpu_rwsem_is_held(sem)	lockdep_is_held(sem)

#define __RCU_SYNC_INITIALIZER(name) {					\
		.gp_state = 0,						\
		.gp_count = 0,						\
		.gp_wait = __WAIT_QUEUE_HEAD_INITIALIZER(name.gp_wait),	\
	}

#define __RCUWAIT_INITIALIZER(name)		\
	{ .task = NULL, }
#define rcuwait_wait_event(w, condition, state)				\
({									\
	int __ret = 0;							\
	prepare_to_rcuwait(w);						\
	for (;;) {							\
									\
		set_current_state(state);				\
		if (condition)						\
			break;						\
									\
		if (signal_pending_state(state, current)) {		\
			__ret = -EINTR;					\
			break;						\
		}							\
									\
		schedule();						\
	}								\
	finish_rcuwait(w);						\
	__ret;								\
})
#define INIT_CPUTIME_ATOMIC \
	(struct task_cputime_atomic) {				\
		.utime = ATOMIC64_INIT(0),			\
		.stime = ATOMIC64_INIT(0),			\
		.sum_exec_runtime = ATOMIC64_INIT(0),		\
	}
#define SEND_SIG_NOINFO ((struct kernel_siginfo *) 0)
#define SIGNAL_STOP_MASK (SIGNAL_CLD_MASK | SIGNAL_STOP_STOPPED | \
			  SIGNAL_STOP_CONTINUED)

# define ___ARCH_SI_IA64(_a1, _a2, _a3) , _a1, _a2, _a3
# define ___ARCH_SI_TRAPNO(_a1) , _a1
#define __for_each_thread(signal, t)	\
	list_for_each_entry_rcu(t, &(signal)->thread_head, thread_node)
#define delay_group_leader(p) \
		(thread_group_leader(p) && !thread_group_empty(p))
#define do_each_thread(g, t) \
	for (g = t = &init_task ; (g = t = next_task(g)) != &init_task ; ) do
#define for_each_process(p) \
	for (p = &init_task ; (p = next_task(p)) != &init_task ; )
#define for_each_process_thread(p, t)	\
	for_each_process(p) for_each_thread(p, t)
#define for_each_thread(p, t)		\
	__for_each_thread((p)->signal, t)
#define next_task(p) \
	list_entry_rcu((p)->tasks.next, struct task_struct, tasks)
#define tasklist_empty() \
	list_empty(&init_task.tasks)
#define while_each_thread(g, t) \
	while ((t = next_thread(t)) != g)

#define __task_cred(task)	\
	rcu_dereference((task)->real_cred)
#define current_cap()		(current_cred_xxx(cap_effective))
#define current_cred() \
	rcu_dereference_protected(current->cred, 1)
#define current_cred_xxx(xxx)			\
({						\
	current_cred()->xxx;			\
})
#define current_egid()		(current_cred_xxx(egid))
#define current_euid()		(current_cred_xxx(euid))
#define current_euid_egid(_euid, _egid)		\
do {						\
	const struct cred *__cred;		\
	__cred = current_cred();		\
	*(_euid) = __cred->euid;		\
	*(_egid) = __cred->egid;		\
} while(0)
#define current_fsgid() 	(current_cred_xxx(fsgid))
#define current_fsuid() 	(current_cred_xxx(fsuid))
#define current_fsuid_fsgid(_fsuid, _fsgid)	\
do {						\
	const struct cred *__cred;		\
	__cred = current_cred();		\
	*(_fsuid) = __cred->fsuid;		\
	*(_fsgid) = __cred->fsgid;		\
} while(0)
#define current_gid()		(current_cred_xxx(gid))
#define current_real_cred() \
	rcu_dereference_protected(current->real_cred, 1)
#define current_sgid()		(current_cred_xxx(sgid))
#define current_suid()		(current_cred_xxx(suid))
#define current_uid()		(current_cred_xxx(uid))
#define current_uid_gid(_uid, _gid)		\
do {						\
	const struct cred *__cred;		\
	__cred = current_cred();		\
	*(_uid) = __cred->uid;			\
	*(_gid) = __cred->gid;			\
} while(0)
#define current_user()		(current_cred_xxx(user))
#define current_user_ns()	(current_cred_xxx(user_ns))
#define get_current_cred()				\
	(get_cred(current_cred()))
#define get_current_groups()				\
({							\
	struct group_info *__groups;			\
	const struct cred *__cred;			\
	__cred = current_cred();			\
	__groups = get_group_info(__cred->group_info);	\
	__groups;					\
})
#define get_current_user()				\
({							\
	struct user_struct *__u;			\
	const struct cred *__cred;			\
	__cred = current_cred();			\
	__u = get_uid(__cred->user);			\
	__u;						\
})
#define put_group_info(group_info)			\
do {							\
	if (atomic_dec_and_test(&(group_info)->usage))	\
		groups_free(group_info);		\
} while (0)
#define task_cred_xxx(task, xxx)			\
({							\
	__typeof__(((struct cred *)NULL)->xxx) ___val;	\
	rcu_read_lock();				\
	___val = __task_cred((task))->xxx;		\
	rcu_read_unlock();				\
	___val;						\
})
#define task_euid(task)		(task_cred_xxx((task), euid))
#define task_uid(task)		(task_cred_xxx((task), uid))
#define validate_creds(cred)				\
do {							\
	__validate_creds((cred), "__FILE__", "__LINE__");	\
} while(0)
#define validate_process_creds()				\
do {								\
	__validate_process_creds(current, "__FILE__", "__LINE__");	\
} while(0)
#define INIT_USER (&root_user)

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

#define dereference_key_locked(KEY)					\
	(rcu_dereference_protected((KEY)->payload.rcu_data0,		\
				   rwsem_is_locked(&((struct key *)(KEY))->sem)))
#define dereference_key_rcu(KEY)					\
	(rcu_dereference((KEY)->payload.rcu_data0))
#define is_key_possessed(k)		0
#define key_free_user_ns(ns)		do { } while(0)
#define key_fsgid_changed(c)		do { } while(0)
#define key_fsuid_changed(c)		do { } while(0)
#define key_get(k) 			({ NULL; })
#define key_init()			do { } while(0)
#define key_invalidate(k)		do { } while(0)
#define key_put(k)			do { } while(0)
#define key_ref_put(k)			do { } while(0)
#define key_ref_to_ptr(k)		NULL
#define key_remove_domain(d)		do { } while(0)
#define key_revoke(k)			do { } while(0)
#define key_serial(k)			0
#define key_validate(k)			0
#define make_key_ref(k, p)		NULL
#define rcu_assign_keypointer(KEY, PAYLOAD)				\
do {									\
	rcu_assign_pointer((KEY)->payload.rcu_data0, (PAYLOAD));	\
} while (0)
#define request_key_net(type, description, net, callout_info) \
	request_key_tag(type, description, net->key_domain, callout_info);
#define request_key_net_rcu(type, description, net) \
	request_key_rcu(type, description, net->key_domain);
#define ASSOC_ARRAY_KEY_CHUNK_SIZE BITS_PER_LONG 

#define DEFINE_CTL_TABLE_POLL(name)					\
	struct ctl_table_poll name = __CTL_TABLE_POLL_INITIALIZER(name)

#define __CTL_TABLE_POLL_INITIALIZER(name) {				\
	.event = ATOMIC_INIT(0),					\
	.wait = __WAIT_QUEUE_HEAD_INITIALIZER(name.wait) }
#define CTL_MAXNAME 10		

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
#define CAP_LAST_CAP         CAP_BPF
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
#define CLONE_LEGACY_FLAGS 0xffffffffULL

# define arch_task_struct_size (sizeof(struct task_struct))
#define sched_exec()   {}

#define faulthandler_disabled() (pagefault_disabled() || in_atomic())
#define get_kernel_nofault(val, ptr) ({				\
	const typeof(val) *__gk_ptr = (ptr);			\
	copy_from_kernel_nofault(&(val), __gk_ptr, sizeof(val));\
})
#define uaccess_kernel() segment_eq(get_fs(), KERNEL_DS)
#define unsafe_copy_to_user(d,s,l,e) unsafe_op_wrap(__copy_to_user(d,s,l),e)
#define unsafe_get_user(x,p,e) unsafe_op_wrap(__get_user(x,p),e)
#define unsafe_op_wrap(op, err) do { if (unlikely(op)) goto err; } while (0)
#define unsafe_put_user(x,p,e) unsafe_op_wrap(__put_user(x,p),e)
#define user_access_begin(ptr,len) access_ok(ptr, len)
#define user_access_end() do { } while (0)
#define user_read_access_begin user_access_begin
#define user_read_access_end user_access_end
#define user_write_access_begin user_access_begin
#define user_write_access_end user_access_end
#define JOBCTL_STOP_DEQUEUED_BIT 16	
#define JOBCTL_TRAPPING		(1UL << JOBCTL_TRAPPING_BIT)

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
#define SIG_KTHREAD ((__force __sighandler_t)2)
#define SIG_KTHREAD_KERNEL ((__force __sighandler_t)3)
#define SIG_SPECIFIC_SICODES_MASK (\
	rt_sigmask(SIGILL)    |  rt_sigmask(SIGFPE)    | \
	rt_sigmask(SIGSEGV)   |  rt_sigmask(SIGBUS)    | \
	rt_sigmask(SIGTRAP)   |  rt_sigmask(SIGCHLD)   | \
	rt_sigmask(SIGPOLL)   |  rt_sigmask(SIGSYS)    | \
	SIGEMT_MASK                                    )
#define SI_EXPANSION_SIZE (sizeof(struct siginfo) - sizeof(struct kernel_siginfo))

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
							\
	case 2:								\
		a1 = a->sig[1]; b1 = b->sig[1];				\
		r->sig[1] = op(a1, b1);					\
							\
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
							\
	case 2:	set->sig[1] = op(set->sig[1]);				\
							\
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
#define sig_fatal(t, signr) \
	(!siginmask(signr, SIG_KERNEL_IGNORE_MASK|SIG_KERNEL_STOP_MASK) && \
	 (t)->sighand->action[(signr)-1].sa.sa_handler == SIG_DFL)
#define sig_kernel_coredump(sig)	siginmask(sig, SIG_KERNEL_COREDUMP_MASK)
#define sig_kernel_ignore(sig)		siginmask(sig, SIG_KERNEL_IGNORE_MASK)
#define sig_kernel_only(sig)		siginmask(sig, SIG_KERNEL_ONLY_MASK)
#define sig_kernel_stop(sig)		siginmask(sig, SIG_KERNEL_STOP_MASK)
#define sig_specific_sicodes(sig)	siginmask(sig, SIG_SPECIFIC_SICODES_MASK)
#define siginmask(sig, mask) \
	((sig) > 0 && (sig) < SIGRTMIN && (rt_sigmask(sig) & (mask)))
#define sigmask(sig)	(1UL << ((sig) - 1))
#define unsafe_save_altstack(uss, sp, label) do { \
	stack_t __user *__uss = uss; \
	struct task_struct *t = current; \
	unsafe_put_user((void __user *)t->sas_ss_sp, &__uss->ss_sp, label); \
	unsafe_put_user(t->sas_ss_flags, &__uss->ss_flags, label); \
	unsafe_put_user(t->sas_ss_size, &__uss->ss_size, label); \
	if (t->sas_ss_flags & SS_AUTODISARM) \
		sas_ss_reset(t); \
} while (0);

#define DEFAULT_SEEKS 2 
#define SHRINK_EMPTY (~0UL - 1)
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

#define DEFINE_SEMAPHORE(name)	\
	struct semaphore name = __SEMAPHORE_INITIALIZER(name, 1)

#define __SEMAPHORE_INITIALIZER(name, n)				\
{									\
	.lock		= __RAW_SPIN_LOCK_UNLOCKED((name).lock),	\
	.count		= n,						\
	.wait_list	= LIST_HEAD_INIT((name).wait_list),		\
}

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
#define MMF_DUMPABLE_BITS 2
#define MMF_DUMPABLE_MASK ((1 << MMF_DUMPABLE_BITS) - 1)
#define MMF_DUMP_FILTER_DEFAULT \
	((1 << MMF_DUMP_ANON_PRIVATE) |	(1 << MMF_DUMP_ANON_SHARED) |\
	 (1 << MMF_DUMP_HUGETLB_PRIVATE) | MMF_DUMP_MASK_DEFAULT_ELF)
#define MMF_DUMP_FILTER_MASK \
	(((1 << MMF_DUMP_FILTER_BITS) - 1) << MMF_DUMP_FILTER_SHIFT)
#define MMF_DUMP_HUGETLB_PRIVATE 7
#define MMF_DUMP_HUGETLB_SHARED  8



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

#define page_ref_tracepoint_active(t) static_key_false(&(t).key)


#define MMAP_LOCK_INITIALIZER(name) \
	.mmap_lock = __RWSEM_INITIALIZER((name).mmap_lock),

#define CLUSTER_FLAG_FREE 1 
#define CLUSTER_FLAG_HUGE 4 
#define CLUSTER_FLAG_NEXT_NULL 2 
#define COMPACT_CLUSTER_MAX SWAP_CLUSTER_MAX
#define MAX_SWAPFILES \
	((1 << MAX_SWAPFILES_SHIFT) - SWP_DEVICE_NUM - \
	SWP_MIGRATION_NUM - SWP_HWPOISON_NUM)
#define MAX_SWAP_BADPAGES \
	((offsetof(union swap_header, magic.magic) - \
	  offsetof(union swap_header, info.badpages)) / sizeof(int))
#define SWAP_BATCH 64
#define SWAP_CLUSTER_MAX 32UL
#define SWAP_FLAG_DISCARD_PAGES 0x40000 
#define SWP_DEVICE_NUM 2
#define SWP_DEVICE_READ (MAX_SWAPFILES+SWP_HWPOISON_NUM+SWP_MIGRATION_NUM+1)
#define SWP_DEVICE_WRITE (MAX_SWAPFILES+SWP_HWPOISON_NUM+SWP_MIGRATION_NUM)
#define SWP_HWPOISON_NUM 1
#define SWP_MIGRATION_NUM 2

#define free_page_and_swap_cache(page) \
	put_page(page)
#define free_pages_and_swap_cache(pages, nr) \
	release_pages((pages), (nr));
#define free_swap_and_cache(e) ({(is_migration_entry(e) || is_device_private_entry(e));})
#define get_nr_swap_pages()			0L
#define mapping_set_update(xas, mapping) do {				\
	if (!dax_mapping(mapping) && !shmem_mapping(mapping))		\
		xas_set_update(xas, workingset_update_node);		\
} while (0)
#define node_reclaim_mode 0
#define nr_free_pages() global_zone_page_state(NR_FREE_PAGES)
#define reuse_swap_page(page, total_map_swapcount) \
	(page_trans_huge_mapcount(page, total_map_swapcount) == 1)
#define si_swapinfo(val) \
	do { (val)->freeswap = (val)->totalswap = 0; } while (0)
#define swap_address_space(entry)			    \
	(&swapper_spaces[swp_type(entry)][swp_offset(entry) \
		>> SWAP_ADDRESS_SPACE_SHIFT])
#define swapcache_prepare(e) ({(is_migration_entry(e) || is_device_private_entry(e));})
#define total_swapcache_pages()			0UL
#define vm_swap_full()				0
#define BIO_ISSUE_RES_BITS      1
#define BIO_ISSUE_RES_MASK      (~((1ULL << BIO_ISSUE_RES_SHIFT) - 1))
#define BIO_ISSUE_RES_SHIFT     (64 - BIO_ISSUE_RES_BITS)
#define BIO_ISSUE_SIZE_BITS     12
#define BIO_ISSUE_SIZE_MASK     \
	(((1ULL << BIO_ISSUE_SIZE_BITS) - 1) << BIO_ISSUE_SIZE_SHIFT)
#define BIO_ISSUE_SIZE_SHIFT    (BIO_ISSUE_RES_SHIFT - BIO_ISSUE_SIZE_BITS)
#define BIO_ISSUE_THROTL_SKIP_LATENCY (1ULL << 63)
#define BIO_ISSUE_TIME_MASK     ((1ULL << BIO_ISSUE_SIZE_SHIFT) - 1)
#define BLK_STS_DM_REQUEUE    ((__force blk_status_t)11)
#define BVEC_POOL_IDX(bio)	((bio)->bi_flags >> BVEC_POOL_OFFSET)
#define REQ_BACKGROUND		(1ULL << __REQ_BACKGROUND)
#define REQ_CGROUP_PUNT		(1ULL << __REQ_CGROUP_PUNT)
#define REQ_DRV			(1ULL << __REQ_DRV)
#define REQ_FAILFAST_MASK \
	(REQ_FAILFAST_DEV | REQ_FAILFAST_TRANSPORT | REQ_FAILFAST_DRIVER)
#define REQ_FUA			(1ULL << __REQ_FUA)
#define REQ_HIPRI		(1ULL << __REQ_HIPRI)
#define REQ_IDLE		(1ULL << __REQ_IDLE)
#define REQ_INTEGRITY		(1ULL << __REQ_INTEGRITY)
#define REQ_META		(1ULL << __REQ_META)
#define REQ_NOMERGE		(1ULL << __REQ_NOMERGE)
#define REQ_NOMERGE_FLAGS \
	(REQ_NOMERGE | REQ_PREFLUSH | REQ_FUA)
#define REQ_NOUNMAP		(1ULL << __REQ_NOUNMAP)
#define REQ_NOWAIT		(1ULL << __REQ_NOWAIT)
#define REQ_PREFLUSH		(1ULL << __REQ_PREFLUSH)
#define REQ_PRIO		(1ULL << __REQ_PRIO)
#define REQ_RAHEAD		(1ULL << __REQ_RAHEAD)
#define REQ_SWAP		(1ULL << __REQ_SWAP)
#define REQ_SYNC		(1ULL << __REQ_SYNC)

#define bio_op(bio) \
	((bio)->bi_opf & REQ_OP_MASK)
#define req_op(req) \
	((req)->cmd_flags & REQ_OP_MASK)
#define BVEC_ITER_ALL_INIT (struct bvec_iter)				\
{									\
	.bi_sector	= 0,						\
	.bi_size	= UINT_MAX,					\
	.bi_idx		= 0,						\
	.bi_bvec_done	= 0,						\
}

#define __bvec_iter_bvec(bvec, iter)	(&(bvec)[(iter).bi_idx])
#define bvec_iter_bvec(bvec, iter)				\
((struct bio_vec) {						\
	.bv_page	= bvec_iter_page((bvec), (iter)),	\
	.bv_len		= bvec_iter_len((bvec), (iter)),	\
	.bv_offset	= bvec_iter_offset((bvec), (iter)),	\
})
#define bvec_iter_len(bvec, iter)				\
	min_t(unsigned, mp_bvec_iter_len((bvec), (iter)),		\
	      PAGE_SIZE - bvec_iter_offset((bvec), (iter)))
 #define bvec_iter_offset(bvec, iter)				\
	(mp_bvec_iter_offset((bvec), (iter)) % PAGE_SIZE)
#define bvec_iter_page(bvec, iter)				\
	(mp_bvec_iter_page((bvec), (iter)) +			\
	 mp_bvec_iter_page_idx((bvec), (iter)))
#define for_each_bvec(bvl, bio_vec, iter, start)			\
	for (iter = (start);						\
	     (iter).bi_size &&						\
		((bvl = bvec_iter_bvec((bio_vec), (iter))), 1);	\
	     bvec_iter_advance((bio_vec), &(iter), (bvl).bv_len))
#define mp_bvec_iter_bvec(bvec, iter)				\
((struct bio_vec) {						\
	.bv_page	= mp_bvec_iter_page((bvec), (iter)),	\
	.bv_len		= mp_bvec_iter_len((bvec), (iter)),	\
	.bv_offset	= mp_bvec_iter_offset((bvec), (iter)),	\
})
#define mp_bvec_iter_len(bvec, iter)				\
	min((iter).bi_size,					\
	    __bvec_iter_bvec((bvec), (iter))->bv_len - (iter).bi_bvec_done)
#define mp_bvec_iter_offset(bvec, iter)				\
	(__bvec_iter_bvec((bvec), (iter))->bv_offset + (iter).bi_bvec_done)
#define mp_bvec_iter_page(bvec, iter)				\
	(__bvec_iter_bvec((bvec), (iter))->bv_page)
#define mp_bvec_iter_page_idx(bvec, iter)			\
	(mp_bvec_iter_offset((bvec), (iter)) / PAGE_SIZE)

#define to_node(device) container_of(device, struct node, dev)
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
#define DEFINE_KLIST(_name, _get, _put)					\
	struct klist _name = KLIST_INIT(_name, _get, _put)
#define KLIST_INIT(_name, _get, _put)					\
	{ .k_lock	= __SPIN_LOCK_UNLOCKED(_name.k_lock),		\
	  .k_list	= LIST_HEAD_INIT(_name.k_list),			\
	  .get		= _get,						\
	  .put		= _put, }

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
#define MEMCG_CHARGE_BATCH 32U
#define MEMCG_PADDING(name)      struct memcg_padding name;

#define for_each_memcg_cache_index(_idx)	\
	for ((_idx) = 0; (_idx) < memcg_nr_cache_ids; (_idx)++)
#define mem_cgroup_from_counter(counter, member)	\
	container_of(counter, struct mem_cgroup, member)
#define mem_cgroup_sockets_enabled static_branch_unlikely(&memcg_sockets_enabled_key)



#define BIO_POOL_SIZE 2
#define BIO_SPLIT_ENTRIES 2

#define __bio_for_each_bvec(bvl, bio, iter, start)		\
	for (iter = (start);						\
	     (iter).bi_size &&						\
		((bvl = mp_bvec_iter_bvec((bio)->bi_io_vec, (iter))), 1); \
	     bio_advance_iter((bio), &(iter), (bvl).bv_len))
#define __bio_for_each_segment(bvl, bio, iter, start)			\
	for (iter = (start);						\
	     (iter).bi_size &&						\
		((bvl = bio_iter_iovec((bio), (iter))), 1);		\
	     bio_advance_iter((bio), &(iter), (bvl).bv_len))
#define bio_copy_dev(dst, src)			\
do {						\
	(dst)->bi_disk = (src)->bi_disk;	\
	(dst)->bi_partno = (src)->bi_partno;	\
	bio_clone_blkg_association(dst, src);	\
} while (0)
#define bio_data_dir(bio) \
	(op_is_write(bio_op(bio)) ? WRITE : READ)
#define bio_dev(bio) \
	disk_devt((bio)->bi_disk)
#define bio_end_sector(bio)	bvec_iter_end_sector((bio)->bi_iter)
#define bio_for_each_bvec(bvl, bio, iter)			\
	__bio_for_each_bvec(bvl, bio, iter, (bio)->bi_iter)
#define bio_for_each_bvec_all(bvl, bio, i)		\
	for (i = 0, bvl = bio_first_bvec_all(bio);	\
	     i < (bio)->bi_vcnt; i++, bvl++)		\

#define bio_for_each_integrity_vec(_bvl, _bio, _iter)			\
	for_each_bio(_bio)						\
		bip_for_each_vec(_bvl, _bio->bi_integrity, _iter)
#define bio_for_each_segment(bvl, bio, iter)				\
	__bio_for_each_segment(bvl, bio, iter, (bio)->bi_iter)
#define bio_for_each_segment_all(bvl, bio, iter) \
	for (bvl = bvec_init_iter_all(&iter); bio_next_segment((bio), &iter); )
#define bio_iovec(bio)		bio_iter_iovec((bio), (bio)->bi_iter)
#define bio_iter_iovec(bio, iter)				\
	bvec_iter_bvec((bio)->bi_io_vec, (iter))
#define bio_iter_last(bvec, iter) ((iter).bi_size == (bvec).bv_len)
#define bio_iter_len(bio, iter)					\
	bvec_iter_len((bio)->bi_io_vec, (iter))
#define bio_iter_offset(bio, iter)				\
	bvec_iter_offset((bio)->bi_io_vec, (iter))
#define bio_iter_page(bio, iter)				\
	bvec_iter_page((bio)->bi_io_vec, (iter))
#define bio_list_for_each(bio, bl) \
	for (bio = (bl)->head; bio; bio = bio->bi_next)
#define bio_multiple_segments(bio)				\
	((bio)->bi_iter.bi_size != bio_iovec(bio).bv_len)
#define bio_offset(bio)		bio_iter_offset((bio), (bio)->bi_iter)
#define bio_page(bio)		bio_iter_page((bio), (bio)->bi_iter)
#define bio_prio(bio)			(bio)->bi_ioprio
#define bio_sectors(bio)	bvec_iter_sectors((bio)->bi_iter)
#define bio_set_dev(bio, bdev) 			\
do {						\
	if ((bio)->bi_disk != (bdev)->bd_disk)	\
		bio_clear_flag(bio, BIO_THROTTLED);\
	(bio)->bi_disk = (bdev)->bd_disk;	\
	(bio)->bi_partno = (bdev)->bd_partno;	\
	bio_associate_blkg(bio);		\
} while (0)
#define bio_set_prio(bio, prio)		((bio)->bi_ioprio = prio)
#define bip_for_each_vec(bvl, bip, iter)				\
	for_each_bvec(bvl, (bip)->bip_vec, iter, (bip)->bip_iter)
#define bvec_iter_end_sector(iter) ((iter).bi_sector + bvec_iter_sectors((iter)))
#define bvec_iter_sectors(iter)	((iter).bi_size >> 9)


#define kmap_atomic_pfn(pfn)	kmap_atomic(pfn_to_page(pfn))
#define kmap_atomic_prot(page, prot)	kmap_atomic(page)
#define kmap_flush_unused()	do {} while(0)
#define kmap_prot PAGE_KERNEL
#define kunmap_atomic(addr)                                     \
do {                                                            \
	BUILD_BUG_ON(__same_type((addr), struct page *));       \
	kunmap_atomic_high(addr);                                  \
	pagefault_enable();                                     \
	preempt_enable();                                       \
} while (0)

#define __irq_enter()					\
	do {						\
		account_irq_enter_time(current);	\
		preempt_count_add(HARDIRQ_OFFSET);	\
		lockdep_hardirq_enter();		\
	} while (0)
#define __irq_enter_raw()				\
	do {						\
		preempt_count_add(HARDIRQ_OFFSET);	\
		lockdep_hardirq_enter();		\
	} while (0)
#define __irq_exit()					\
	do {						\
		lockdep_hardirq_exit();			\
		account_irq_exit_time(current);		\
		preempt_count_sub(HARDIRQ_OFFSET);	\
	} while (0)
#define __irq_exit_raw()				\
	do {						\
		lockdep_hardirq_exit();			\
		preempt_count_sub(HARDIRQ_OFFSET);	\
	} while (0)
#define arch_nmi_enter()	do { } while (0)
#define arch_nmi_exit()		do { } while (0)
#define nmi_enter()						\
	do {							\
		arch_nmi_enter();				\
		printk_nmi_enter();				\
		lockdep_off();					\
		BUG_ON(in_nmi() == NMI_MASK);			\
		__preempt_count_add(NMI_OFFSET + HARDIRQ_OFFSET);	\
		rcu_nmi_enter();				\
		lockdep_hardirq_enter();			\
		instrumentation_begin();			\
		ftrace_nmi_enter();				\
		instrumentation_end();				\
	} while (0)
#define nmi_exit()						\
	do {							\
		instrumentation_begin();			\
		ftrace_nmi_exit();				\
		instrumentation_end();				\
		lockdep_hardirq_exit();				\
		rcu_nmi_exit();					\
		BUG_ON(!in_nmi());				\
		__preempt_count_sub(NMI_OFFSET + HARDIRQ_OFFSET);	\
		lockdep_on();					\
		printk_nmi_exit();				\
		arch_nmi_exit();				\
	} while (0)



#define SUBSYS(_x) extern struct cgroup_subsys _x ## _cgrp_subsys;

#define cgroup_subsys_enabled(ss)						\
	static_branch_likely(&ss ## _enabled_key)
#define cgroup_subsys_on_dfl(ss)						\
	static_branch_likely(&ss ## _on_dfl_key)
#define cgroup_taskset_for_each(task, dst_css, tset)			\
	for ((task) = cgroup_taskset_first((tset), &(dst_css));		\
	     (task);							\
	     (task) = cgroup_taskset_next((tset), &(dst_css)))
#define cgroup_taskset_for_each_leader(leader, dst_css, tset)		\
	for ((leader) = cgroup_taskset_first((tset), &(dst_css));	\
	     (leader);							\
	     (leader) = cgroup_taskset_next((tset), &(dst_css)))	\
		if ((leader) != (leader)->group_leader)			\
			;						\
		else
#define css_for_each_child(pos, parent)					\
	for ((pos) = css_next_child(NULL, (parent)); (pos);		\
	     (pos) = css_next_child((pos), (parent)))
#define css_for_each_descendant_post(pos, css)				\
	for ((pos) = css_next_descendant_post(NULL, (css)); (pos);	\
	     (pos) = css_next_descendant_post((pos), (css)))
#define css_for_each_descendant_pre(pos, css)				\
	for ((pos) = css_next_descendant_pre(NULL, (css)); (pos);	\
	     (pos) = css_next_descendant_pre((pos), (css)))
#define task_css_check(task, subsys_id, __c)				\
	task_css_set_check((task), (__c))->subsys[(subsys_id)]
#define task_css_set_check(task, __c)					\
	rcu_dereference_check((task)->cgroups,				\
		lockdep_is_held(&cgroup_mutex) ||			\
		lockdep_is_held(&css_set_lock) ||			\
		((task)->flags & PF_EXITING) || (__c))
#define CGROUP_SUBSYS_COUNT 0
#define MAX_CGROUP_ROOT_NAMELEN 64
#define MAX_CGROUP_TYPE_NAMELEN 32


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
			     kthread_delayed_work_timer_fn,		\
			     TIMER_IRQSAFE);				\
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
#define BPF_CGROUP_GETSOCKOPT_MAX_OPTLEN(optlen)			       \
({									       \
	int __ret = 0;							       \
	if (cgroup_bpf_enabled)						       \
		get_user(__ret, optlen);				       \
	__ret;								       \
})
#define BPF_CGROUP_PRE_CONNECT_ENABLED(sk) (cgroup_bpf_enabled && \
					    sk->sk_prot->pre_connect)
#define BPF_CGROUP_RUN_PROG_DEVICE_CGROUP(type, major, minor, access)	      \
({									      \
	int __ret = 0;							      \
	if (cgroup_bpf_enabled)						      \
		__ret = __cgroup_bpf_check_dev_permission(type, major, minor, \
							  access,	      \
							  BPF_CGROUP_DEVICE); \
									      \
	__ret;								      \
})
#define BPF_CGROUP_RUN_PROG_GETSOCKOPT(sock, level, optname, optval, optlen,   \
				       max_optlen, retval)		       \
({									       \
	int __ret = retval;						       \
	if (cgroup_bpf_enabled)						       \
		__ret = __cgroup_bpf_run_filter_getsockopt(sock, level,	       \
							   optname, optval,    \
							   optlen, max_optlen, \
							   retval);	       \
	__ret;								       \
})
#define BPF_CGROUP_RUN_PROG_INET4_BIND(sk, uaddr)			       \
	BPF_CGROUP_RUN_SA_PROG(sk, uaddr, BPF_CGROUP_INET4_BIND)
#define BPF_CGROUP_RUN_PROG_INET4_CONNECT(sk, uaddr)			       \
	BPF_CGROUP_RUN_SA_PROG(sk, uaddr, BPF_CGROUP_INET4_CONNECT)
#define BPF_CGROUP_RUN_PROG_INET4_CONNECT_LOCK(sk, uaddr)		       \
	BPF_CGROUP_RUN_SA_PROG_LOCK(sk, uaddr, BPF_CGROUP_INET4_CONNECT, NULL)
#define BPF_CGROUP_RUN_PROG_INET4_POST_BIND(sk)				       \
	BPF_CGROUP_RUN_SK_PROG(sk, BPF_CGROUP_INET4_POST_BIND)
#define BPF_CGROUP_RUN_PROG_INET6_BIND(sk, uaddr)			       \
	BPF_CGROUP_RUN_SA_PROG(sk, uaddr, BPF_CGROUP_INET6_BIND)
#define BPF_CGROUP_RUN_PROG_INET6_CONNECT(sk, uaddr)			       \
	BPF_CGROUP_RUN_SA_PROG(sk, uaddr, BPF_CGROUP_INET6_CONNECT)
#define BPF_CGROUP_RUN_PROG_INET6_CONNECT_LOCK(sk, uaddr)		       \
	BPF_CGROUP_RUN_SA_PROG_LOCK(sk, uaddr, BPF_CGROUP_INET6_CONNECT, NULL)
#define BPF_CGROUP_RUN_PROG_INET6_POST_BIND(sk)				       \
	BPF_CGROUP_RUN_SK_PROG(sk, BPF_CGROUP_INET6_POST_BIND)
#define BPF_CGROUP_RUN_PROG_INET_EGRESS(sk, skb)			       \
({									       \
	int __ret = 0;							       \
	if (cgroup_bpf_enabled && sk && sk == skb->sk) {		       \
		typeof(sk) __sk = sk_to_full_sk(sk);			       \
		if (sk_fullsock(__sk))					       \
			__ret = __cgroup_bpf_run_filter_skb(__sk, skb,	       \
						      BPF_CGROUP_INET_EGRESS); \
	}								       \
	__ret;								       \
})
#define BPF_CGROUP_RUN_PROG_INET_INGRESS(sk, skb)			      \
({									      \
	int __ret = 0;							      \
	if (cgroup_bpf_enabled)						      \
		__ret = __cgroup_bpf_run_filter_skb(sk, skb,		      \
						    BPF_CGROUP_INET_INGRESS); \
									      \
	__ret;								      \
})
#define BPF_CGROUP_RUN_PROG_INET_SOCK(sk)				       \
	BPF_CGROUP_RUN_SK_PROG(sk, BPF_CGROUP_INET_SOCK_CREATE)
#define BPF_CGROUP_RUN_PROG_SETSOCKOPT(sock, level, optname, optval, optlen,   \
				       kernel_optval)			       \
({									       \
	int __ret = 0;							       \
	if (cgroup_bpf_enabled)						       \
		__ret = __cgroup_bpf_run_filter_setsockopt(sock, level,	       \
							   optname, optval,    \
							   optlen,	       \
							   kernel_optval);     \
	__ret;								       \
})
#define BPF_CGROUP_RUN_PROG_SOCK_OPS(sock_ops)				       \
({									       \
	int __ret = 0;							       \
	if (cgroup_bpf_enabled && (sock_ops)->sk) {	       \
		typeof(sk) __sk = sk_to_full_sk((sock_ops)->sk);	       \
		if (__sk && sk_fullsock(__sk))				       \
			__ret = __cgroup_bpf_run_filter_sock_ops(__sk,	       \
								 sock_ops,     \
							 BPF_CGROUP_SOCK_OPS); \
	}								       \
	__ret;								       \
})
#define BPF_CGROUP_RUN_PROG_SYSCTL(head, table, write, buf, count, pos)  \
({									       \
	int __ret = 0;							       \
	if (cgroup_bpf_enabled)						       \
		__ret = __cgroup_bpf_run_filter_sysctl(head, table, write,     \
						       buf, count, pos,        \
						       BPF_CGROUP_SYSCTL);     \
	__ret;								       \
})
#define BPF_CGROUP_RUN_PROG_UDP4_RECVMSG_LOCK(sk, uaddr)			\
	BPF_CGROUP_RUN_SA_PROG_LOCK(sk, uaddr, BPF_CGROUP_UDP4_RECVMSG, NULL)
#define BPF_CGROUP_RUN_PROG_UDP4_SENDMSG_LOCK(sk, uaddr, t_ctx)		       \
	BPF_CGROUP_RUN_SA_PROG_LOCK(sk, uaddr, BPF_CGROUP_UDP4_SENDMSG, t_ctx)
#define BPF_CGROUP_RUN_PROG_UDP6_RECVMSG_LOCK(sk, uaddr)			\
	BPF_CGROUP_RUN_SA_PROG_LOCK(sk, uaddr, BPF_CGROUP_UDP6_RECVMSG, NULL)
#define BPF_CGROUP_RUN_PROG_UDP6_SENDMSG_LOCK(sk, uaddr, t_ctx)		       \
	BPF_CGROUP_RUN_SA_PROG_LOCK(sk, uaddr, BPF_CGROUP_UDP6_SENDMSG, t_ctx)
#define BPF_CGROUP_RUN_SA_PROG(sk, uaddr, type)				       \
({									       \
	int __ret = 0;							       \
	if (cgroup_bpf_enabled)						       \
		__ret = __cgroup_bpf_run_filter_sock_addr(sk, uaddr, type,     \
							  NULL);	       \
	__ret;								       \
})
#define BPF_CGROUP_RUN_SA_PROG_LOCK(sk, uaddr, type, t_ctx)		       \
({									       \
	int __ret = 0;							       \
	if (cgroup_bpf_enabled)	{					       \
		lock_sock(sk);						       \
		__ret = __cgroup_bpf_run_filter_sock_addr(sk, uaddr, type,     \
							  t_ctx);	       \
		release_sock(sk);					       \
	}								       \
	__ret;								       \
})
#define BPF_CGROUP_RUN_SK_PROG(sk, type)				       \
({									       \
	int __ret = 0;							       \
	if (cgroup_bpf_enabled) {					       \
		__ret = __cgroup_bpf_run_filter_sk(sk, type);		       \
	}								       \
	__ret;								       \
})

#define cgroup_bpf_enabled (0)
#define for_each_cgroup_storage_type(stype) \
	for (stype = 0; stype < MAX_BPF_CGROUP_STORAGE_TYPE; stype++)
#define BPF_BUILD_ID_SIZE 20
#define BPF_F_ADJ_ROOM_ENCAP_L2(len)	(((__u64)len & \
					  BPF_ADJ_ROOM_ENCAP_L2_MASK) \
					 << BPF_ADJ_ROOM_ENCAP_L2_SHIFT)
#define BPF_LINE_INFO_LINE_COL(line_col)	((line_col) & 0x3ff)
#define BPF_LINE_INFO_LINE_NUM(line_col)	((line_col) >> 10)
#define BPF_OBJ_NAME_LEN 16U
#define MAX_BPF_ATTACH_TYPE __MAX_BPF_ATTACH_TYPE
#define XDP_PACKET_HEADROOM 256

#define __BPF_ENUM_FN(x) BPF_FUNC_ ## x
#define __BPF_FUNC_MAPPER(FN)		\
	FN(unspec),			\
	FN(map_lookup_elem),		\
	FN(map_update_elem),		\
	FN(map_delete_elem),		\
	FN(probe_read),			\
	FN(ktime_get_ns),		\
	FN(trace_printk),		\
	FN(get_prandom_u32),		\
	FN(get_smp_processor_id),	\
	FN(skb_store_bytes),		\
	FN(l3_csum_replace),		\
	FN(l4_csum_replace),		\
	FN(tail_call),			\
	FN(clone_redirect),		\
	FN(get_current_pid_tgid),	\
	FN(get_current_uid_gid),	\
	FN(get_current_comm),		\
	FN(get_cgroup_classid),		\
	FN(skb_vlan_push),		\
	FN(skb_vlan_pop),		\
	FN(skb_get_tunnel_key),		\
	FN(skb_set_tunnel_key),		\
	FN(perf_event_read),		\
	FN(redirect),			\
	FN(get_route_realm),		\
	FN(perf_event_output),		\
	FN(skb_load_bytes),		\
	FN(get_stackid),		\
	FN(csum_diff),			\
	FN(skb_get_tunnel_opt),		\
	FN(skb_set_tunnel_opt),		\
	FN(skb_change_proto),		\
	FN(skb_change_type),		\
	FN(skb_under_cgroup),		\
	FN(get_hash_recalc),		\
	FN(get_current_task),		\
	FN(probe_write_user),		\
	FN(current_task_under_cgroup),	\
	FN(skb_change_tail),		\
	FN(skb_pull_data),		\
	FN(csum_update),		\
	FN(set_hash_invalid),		\
	FN(get_numa_node_id),		\
	FN(skb_change_head),		\
	FN(xdp_adjust_head),		\
	FN(probe_read_str),		\
	FN(get_socket_cookie),		\
	FN(get_socket_uid),		\
	FN(set_hash),			\
	FN(setsockopt),			\
	FN(skb_adjust_room),		\
	FN(redirect_map),		\
	FN(sk_redirect_map),		\
	FN(sock_map_update),		\
	FN(xdp_adjust_meta),		\
	FN(perf_event_read_value),	\
	FN(perf_prog_read_value),	\
	FN(getsockopt),			\
	FN(override_return),		\
	FN(sock_ops_cb_flags_set),	\
	FN(msg_redirect_map),		\
	FN(msg_apply_bytes),		\
	FN(msg_cork_bytes),		\
	FN(msg_pull_data),		\
	FN(bind),			\
	FN(xdp_adjust_tail),		\
	FN(skb_get_xfrm_state),		\
	FN(get_stack),			\
	FN(skb_load_bytes_relative),	\
	FN(fib_lookup),			\
	FN(sock_hash_update),		\
	FN(msg_redirect_hash),		\
	FN(sk_redirect_hash),		\
	FN(lwt_push_encap),		\
	FN(lwt_seg6_store_bytes),	\
	FN(lwt_seg6_adjust_srh),	\
	FN(lwt_seg6_action),		\
	FN(rc_repeat),			\
	FN(rc_keydown),			\
	FN(skb_cgroup_id),		\
	FN(get_current_cgroup_id),	\
	FN(get_local_storage),		\
	FN(sk_select_reuseport),	\
	FN(skb_ancestor_cgroup_id),	\
	FN(sk_lookup_tcp),		\
	FN(sk_lookup_udp),		\
	FN(sk_release),			\
	FN(map_push_elem),		\
	FN(map_pop_elem),		\
	FN(map_peek_elem),		\
	FN(msg_push_data),		\
	FN(msg_pop_data),		\
	FN(rc_pointer_rel),		\
	FN(spin_lock),			\
	FN(spin_unlock),		\
	FN(sk_fullsock),		\
	FN(tcp_sock),			\
	FN(skb_ecn_set_ce),		\
	FN(get_listener_sock),		\
	FN(skc_lookup_tcp),		\
	FN(tcp_check_syncookie),	\
	FN(sysctl_get_name),		\
	FN(sysctl_get_current_value),	\
	FN(sysctl_get_new_value),	\
	FN(sysctl_set_new_value),	\
	FN(strtol),			\
	FN(strtoul),			\
	FN(sk_storage_get),		\
	FN(sk_storage_delete),		\
	FN(send_signal),		\
	FN(tcp_gen_syncookie),		\
	FN(skb_output),			\
	FN(probe_read_user),		\
	FN(probe_read_kernel),		\
	FN(probe_read_user_str),	\
	FN(probe_read_kernel_str),	\
	FN(tcp_send_ack),		\
	FN(send_signal_thread),		\
	FN(jiffies64),			\
	FN(read_branch_records),	\
	FN(get_ns_current_pid_tgid),	\
	FN(xdp_output),			\
	FN(get_netns_cookie),		\
	FN(get_current_ancestor_cgroup_id),	\
	FN(sk_assign),			\
	FN(ktime_get_boot_ns),		\
	FN(seq_printf),			\
	FN(seq_write),			\
	FN(sk_cgroup_id),		\
	FN(sk_ancestor_cgroup_id),	\
	FN(ringbuf_output),		\
	FN(ringbuf_reserve),		\
	FN(ringbuf_submit),		\
	FN(ringbuf_discard),		\
	FN(ringbuf_query),		\
	FN(csum_level),
#define __bpf_md_ptr(type, name)	\
union {					\
	type name;			\
	__u64 :64;			\
} __attribute__((aligned(8)))
#define BPF_COMPLEXITY_LIMIT_INSNS      1000000 
#define BPF_DISPATCHER_FUNC(name) bpf_dispatcher_##name##_func
#define BPF_DISPATCHER_INIT(_name) {				\
	.mutex = __MUTEX_INITIALIZER(_name.mutex),		\
	.func = &_name##_func,					\
	.progs = {},						\
	.num_progs = 0,						\
	.image = NULL,						\
	.image_off = 0,						\
	.ksym = {						\
		.name  = #_name,				\
		.lnode = LIST_HEAD_INIT(_name.ksym.lnode),	\
	},							\
}
#define BPF_DISPATCHER_MAX 48 
#define BPF_DISPATCHER_PTR(name) (&bpf_dispatcher_##name)
#define BPF_ITER_CTX_ARG_MAX 2
#define BPF_ITER_FUNC_PREFIX "bpf_iter_"
#define BPF_LINK_TYPE(_id, _name)
#define BPF_MAP_TYPE(_id, _ops) \
	extern const struct bpf_map_ops _ops;
#define BPF_MAX_TRAMP_PROGS 40
#define BPF_MODULE_OWNER ((void *)((0xeB9FUL << 2) + POISON_POINTER_DELTA))
#define BPF_PROG_CGROUP_INET_EGRESS_RUN_ARRAY(array, ctx, func)		\
	({						\
		struct bpf_prog_array_item *_item;	\
		struct bpf_prog *_prog;			\
		struct bpf_prog_array *_array;		\
		u32 ret;				\
		u32 _ret = 1;				\
		u32 _cn = 0;				\
		migrate_disable();			\
		rcu_read_lock();			\
		_array = rcu_dereference(array);	\
		_item = &_array->items[0];		\
		while ((_prog = READ_ONCE(_item->prog))) {		\
			bpf_cgroup_storage_set(_item->cgroup_storage);	\
			ret = func(_prog, ctx);		\
			_ret &= (ret & 1);		\
			_cn |= (ret & 2);		\
			_item++;			\
		}					\
		rcu_read_unlock();			\
		migrate_enable();			\
		if (_ret)				\
			_ret = (_cn ? NET_XMIT_CN : NET_XMIT_SUCCESS);	\
		else					\
			_ret = (_cn ? NET_XMIT_DROP : -EPERM);		\
		_ret;					\
	})
#define BPF_PROG_RUN_ARRAY(array, ctx, func)		\
	__BPF_PROG_RUN_ARRAY(array, ctx, func, false)
#define BPF_PROG_RUN_ARRAY_CHECK(array, ctx, func)	\
	__BPF_PROG_RUN_ARRAY(array, ctx, func, true)
#define BPF_PROG_TYPE(_id, _name, prog_ctx_type, kern_ctx_type) \
	extern const struct bpf_prog_ops _name ## _prog_ops; \
	extern const struct bpf_verifier_ops _name ## _verifier_ops;
#define BPF_STRUCT_OPS_MAX_NR_MEMBERS 64
#define DECLARE_BPF_DISPATCHER(name)					\
	unsigned int bpf_dispatcher_##name##_func(			\
		const void *ctx,					\
		const struct bpf_insn *insnsi,				\
		unsigned int (*bpf_func)(const void *,			\
					 const struct bpf_insn *));	\
	extern struct bpf_dispatcher bpf_dispatcher_##name;
#define DEFINE_BPF_DISPATCHER(name)					\
	noinline unsigned int bpf_dispatcher_##name##_func(		\
		const void *ctx,					\
		const struct bpf_insn *insnsi,				\
		unsigned int (*bpf_func)(const void *,			\
					 const struct bpf_insn *))	\
	{								\
		return bpf_func(ctx, insnsi);				\
	}								\
	EXPORT_SYMBOL(bpf_dispatcher_##name##_func);			\
	struct bpf_dispatcher bpf_dispatcher_##name =			\
		BPF_DISPATCHER_INIT(bpf_dispatcher_##name);
#define DEFINE_BPF_ITER_FUNC(target, args...)			\
	extern int bpf_iter_ ## target(args);			\
	int __init bpf_iter_ ## target(args) { return 0; }
#define MAX_BPF_CGROUP_STORAGE_TYPE __BPF_CGROUP_STORAGE_MAX
#define MAX_BPF_FUNC_ARGS 12
#define MAX_TAIL_CALL_CNT 32
#define _LINUX_BPF_H 1
#define __BPF_PROG_RUN_ARRAY(array, ctx, func, check_non_null)	\
	({						\
		struct bpf_prog_array_item *_item;	\
		struct bpf_prog *_prog;			\
		struct bpf_prog_array *_array;		\
		u32 _ret = 1;				\
		migrate_disable();			\
		rcu_read_lock();			\
		_array = rcu_dereference(array);	\
		if (unlikely(check_non_null && !_array))\
			goto _out;			\
		_item = &_array->items[0];		\
		while ((_prog = READ_ONCE(_item->prog))) {		\
			bpf_cgroup_storage_set(_item->cgroup_storage);	\
			_ret &= func(_prog, ctx);	\
			_item++;			\
		}					\
_out:							\
		rcu_read_unlock();			\
		migrate_enable();			\
		_ret;					\
	 })
#define KSYM_NAME_LEN 128
#define KSYM_SYMBOL_LEN (sizeof("%s+%#lx/%#lx [%s]") + (KSYM_NAME_LEN - 1) + \
			 2*(BITS_PER_LONG*3/10) + (MODULE_NAME_LEN - 1) + 1)

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


#define FDPUT_FPUT       1
#define FDPUT_POS_UNLOCK 2


#define kcpustat_cpu(cpu) per_cpu(kernel_cpustat, cpu)
#define kcpustat_this_cpu this_cpu_ptr(&kernel_cpustat)
#define kstat_cpu(cpu) per_cpu(kstat, cpu)
#define kstat_this_cpu this_cpu_ptr(&kstat)
#define DECLARE_TASKLET(name, func, data) \
struct tasklet_struct name = { NULL, 0, ATOMIC_INIT(0), func, data }
#define DECLARE_TASKLET_DISABLED(name, func, data) \
struct tasklet_struct name = { NULL, 0, ATOMIC_INIT(1), func, data }
#define IRQF_TIMER		(__IRQF_TIMER | IRQF_NO_SUSPEND | IRQF_NO_THREAD)
#define SOFTIRQ_STOP_IDLE_MASK (~(1 << RCU_SOFTIRQ))

#define __softirq_entry  __attribute__((__section__(".softirqentry.text")))
#define hard_irq_disable()	do { } while(0)
# define local_irq_enable_in_hardirq()	do { } while (0)
#define local_softirq_pending_ref irq_stat.__softirq_pending
#define or_softirq_pending(x)	(__this_cpu_or(local_softirq_pending_ref, (x)))
#define set_softirq_pending(x)	(__this_cpu_write(local_softirq_pending_ref, (x)))
#define tasklet_trylock(t) 1
#define tasklet_unlock(t) do { } while (0)
#define tasklet_unlock_wait(t) do { } while (0)

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

#define UID_GID_MAP_MAX_BASE_EXTENTS 5
#define UID_GID_MAP_MAX_EXTENTS 340
#define USERNS_INIT_FLAGS USERNS_SETGROUPS_ALLOWED
#define USERNS_SETGROUPS_ALLOWED 1UL



#define DEFINE_PROC_SHOW_ATTRIBUTE(__name)				\
static int __name ## _open(struct inode *inode, struct file *file)	\
{									\
	return single_open(file, __name ## _show, inode->i_private);	\
}									\
									\
static const struct proc_ops __name ## _proc_ops = {			\
	.proc_open	= __name ## _open,				\
	.proc_read	= seq_read,					\
	.proc_lseek	= seq_lseek,					\
	.proc_release	= single_release,				\
}
#define DEFINE_SEQ_ATTRIBUTE(__name)					\
static int __name ## _open(struct inode *inode, struct file *file)	\
{									\
	int ret = seq_open(file, &__name ## _sops);			\
	if (!ret && inode->i_private) {					\
		struct seq_file *seq_f = file->private_data;		\
		seq_f->private = inode->i_private;			\
	}								\
	return ret;							\
}									\
									\
static const struct file_operations __name ## _fops = {			\
	.owner		= THIS_MODULE,					\
	.open		= __name ## _open,				\
	.read		= seq_read,					\
	.llseek		= seq_lseek,					\
	.release	= seq_release,					\
}
#define DEFINE_SHOW_ATTRIBUTE(__name)					\
static int __name ## _open(struct inode *inode, struct file *file)	\
{									\
	return single_open(file, __name ## _show, inode->i_private);	\
}									\
									\
static const struct file_operations __name ## _fops = {			\
	.owner		= THIS_MODULE,					\
	.open		= __name ## _open,				\
	.read		= seq_read,					\
	.llseek		= seq_lseek,					\
	.release	= single_release,				\
}
#define SEQ_SKIP 1
#define SEQ_START_TOKEN ((void *)1)

#define seq_show_option_n(m, name, value, length) {	\
	char val_buf[length + 1];			\
	strncpy(val_buf, value, length);		\
	val_buf[length] = '\0';				\
	seq_show_option(m, name, val_buf);		\
}

#define blk_queue_for_each_rl(rl, q)	\
	for ((rl) = &(q)->root_rl; (rl); (rl) = NULL)
#define blkg_for_each_descendant_post(d_blkg, pos_css, p_blkg)		\
	css_for_each_descendant_post((pos_css), &(p_blkg)->blkcg->css)	\
		if (((d_blkg) = __blkg_lookup(css_to_blkcg(pos_css),	\
					      (p_blkg)->q, false)))
#define blkg_for_each_descendant_pre(d_blkg, pos_css, p_blkg)		\
	css_for_each_descendant_pre((pos_css), &(p_blkg)->blkcg->css)	\
		if (((d_blkg) = __blkg_lookup(css_to_blkcg(pos_css),	\
					      (p_blkg)->q, false)))
#define BLK_ALL_ZONES  ((unsigned int)-1)
#define BLK_MAX_REQUEST_COUNT 16
#define BLK_MQ_POLL_CLASSIC -1
#define BLK_MQ_POLL_STATS_BKTS 16
#define BLK_PLUG_FLUSH_SIZE (128 * 1024)
#define BLK_TAG_ALLOC_FIFO 0 
#define BLK_TAG_ALLOC_RR 1 
#define MODULE_ALIAS_BLOCKDEV(major,minor) \
	MODULE_ALIAS("block-major-" __stringify(major) "-" __stringify(minor))
#define MODULE_ALIAS_BLOCKDEV_MAJOR(major) \
	MODULE_ALIAS("block-major-" __stringify(major) "-*")
#define QUEUE_FLAG_NOMERGES     3	
#define QUEUE_FLAG_RQ_ALLOC_TIME 27	
#define QUEUE_FLAG_SCSI_PASSTHROUGH 23	
#define QUEUE_FLAG_ZONE_RESETALL 26	
#define RQF_NOMERGE_FLAGS \
	(RQF_STARTED | RQF_SOFTBARRIER | RQF_FLUSH_SEQ | RQF_SPECIAL_PAYLOAD)
#define SECTOR_SHIFT 9
#define SECTOR_SIZE (1 << SECTOR_SHIFT)

#define __rq_for_each_bio(_bio, rq)	\
	if ((rq->bio))			\
		for (_bio = (rq)->bio; _bio; _bio = _bio->bi_next)
#define blk_noretry_request(rq) \
	((rq)->cmd_flags & (REQ_FAILFAST_DEV|REQ_FAILFAST_TRANSPORT| \
			     REQ_FAILFAST_DRIVER))
#define blk_queue_add_random(q)	test_bit(QUEUE_FLAG_ADD_RANDOM, &(q)->queue_flags)
#define blk_queue_dax(q)	test_bit(QUEUE_FLAG_DAX, &(q)->queue_flags)
#define blk_queue_dead(q)	test_bit(QUEUE_FLAG_DEAD, &(q)->queue_flags)
#define blk_queue_discard(q)	test_bit(QUEUE_FLAG_DISCARD, &(q)->queue_flags)
#define blk_queue_dying(q)	test_bit(QUEUE_FLAG_DYING, &(q)->queue_flags)
#define blk_queue_fua(q)	test_bit(QUEUE_FLAG_FUA, &(q)->queue_flags)
#define blk_queue_init_done(q)	test_bit(QUEUE_FLAG_INIT_DONE, &(q)->queue_flags)
#define blk_queue_io_stat(q)	test_bit(QUEUE_FLAG_IO_STAT, &(q)->queue_flags)
#define blk_queue_nomerges(q)	test_bit(QUEUE_FLAG_NOMERGES, &(q)->queue_flags)
#define blk_queue_nonrot(q)	test_bit(QUEUE_FLAG_NONROT, &(q)->queue_flags)
#define blk_queue_noxmerges(q)	\
	test_bit(QUEUE_FLAG_NOXMERGES, &(q)->queue_flags)
#define blk_queue_pci_p2pdma(q)	\
	test_bit(QUEUE_FLAG_PCI_P2PDMA, &(q)->queue_flags)
#define blk_queue_pm_only(q)	atomic_read(&(q)->pm_only)
#define blk_queue_quiesced(q)	test_bit(QUEUE_FLAG_QUIESCED, &(q)->queue_flags)
#define blk_queue_registered(q)	test_bit(QUEUE_FLAG_REGISTERED, &(q)->queue_flags)
#define blk_queue_rq_alloc_time(q)	\
	test_bit(QUEUE_FLAG_RQ_ALLOC_TIME, &(q)->queue_flags)
#define blk_queue_scsi_passthrough(q)	\
	test_bit(QUEUE_FLAG_SCSI_PASSTHROUGH, &(q)->queue_flags)
#define blk_queue_secure_erase(q) \
	(test_bit(QUEUE_FLAG_SECERASE, &(q)->queue_flags))
#define blk_queue_stopped(q)	test_bit(QUEUE_FLAG_STOPPED, &(q)->queue_flags)
#define blk_queue_zone_resetall(q)	\
	test_bit(QUEUE_FLAG_ZONE_RESETALL, &(q)->queue_flags)
#define blkdev_compat_ptr_ioctl NULL
#define buffer_heads_over_limit 0
#define dma_map_bvec(dev, bv, dir, attrs) \
	dma_map_page_attrs(dev, (bv)->bv_page, (bv)->bv_offset, (bv)->bv_len, \
	(dir), (attrs))
#define for_each_bio(_bio)		\
	for (; _bio; _bio = _bio->bi_next)
#define list_entry_rq(ptr)	list_entry((ptr), struct request, queuelist)
#define rq_data_dir(rq)		(op_is_write(req_op(rq)) ? WRITE : READ)
#define rq_dma_dir(rq) \
	(op_is_write(req_op(rq)) ? DMA_TO_DEVICE : DMA_FROM_DEVICE)
#define rq_for_each_bvec(bvl, _rq, _iter)			\
	__rq_for_each_bio(_iter.bio, _rq)			\
		bio_for_each_bvec(bvl, _iter.bio, _iter.iter)
#define rq_for_each_segment(bvl, _rq, _iter)			\
	__rq_for_each_bio(_iter.bio, _rq)			\
		bio_for_each_segment(bvl, _iter.bio, _iter.iter)
#define rq_iter_last(bvec, _iter)				\
		(_iter.bio->bi_next == NULL &&			\
		 bio_iter_last(bvec, _iter.iter))
#define ELV_HASH_BITS 6

#define rb_entry_rq(node)	rb_entry((node), struct request, rb_node)
#define rq_end_sector(rq)	(blk_rq_pos(rq) + blk_rq_sectors(rq))
#define rq_entry_fifo(ptr)	list_entry((ptr), struct request, queuelist)
#define rq_fifo_clear(rq)	list_del_init(&(rq)->queuelist)
#define DECLARE_HASHTABLE(name, bits)                                   	\
	struct hlist_head name[1 << (bits)]
#define DEFINE_HASHTABLE(name, bits)						\
	struct hlist_head name[1 << (bits)] =					\
			{ [0 ... ((1 << (bits)) - 1)] = HLIST_HEAD_INIT }
#define DEFINE_READ_MOSTLY_HASHTABLE(name, bits)				\
	struct hlist_head name[1 << (bits)] __read_mostly =			\
			{ [0 ... ((1 << (bits)) - 1)] = HLIST_HEAD_INIT }
#define HASH_BITS(name) ilog2(HASH_SIZE(name))
#define HASH_SIZE(name) (ARRAY_SIZE(name))

#define hash_add(hashtable, node, key)						\
	hlist_add_head(node, &hashtable[hash_min(key, HASH_BITS(hashtable))])
#define hash_add_rcu(hashtable, node, key)					\
	hlist_add_head_rcu(node, &hashtable[hash_min(key, HASH_BITS(hashtable))])
#define hash_empty(hashtable) __hash_empty(hashtable, HASH_SIZE(hashtable))
#define hash_for_each(name, bkt, obj, member)				\
	for ((bkt) = 0, obj = NULL; obj == NULL && (bkt) < HASH_SIZE(name);\
			(bkt)++)\
		hlist_for_each_entry(obj, &name[bkt], member)
#define hash_for_each_possible(name, obj, member, key)			\
	hlist_for_each_entry(obj, &name[hash_min(key, HASH_BITS(name))], member)
#define hash_for_each_possible_rcu(name, obj, member, key)		\
	hlist_for_each_entry_rcu(obj, &name[hash_min(key, HASH_BITS(name))],\
		member)
#define hash_for_each_possible_rcu_notrace(name, obj, member, key) \
	hlist_for_each_entry_rcu_notrace(obj, \
		&name[hash_min(key, HASH_BITS(name))], member)
#define hash_for_each_possible_safe(name, obj, tmp, member, key)	\
	hlist_for_each_entry_safe(obj, tmp,\
		&name[hash_min(key, HASH_BITS(name))], member)
#define hash_for_each_rcu(name, bkt, obj, member)			\
	for ((bkt) = 0, obj = NULL; obj == NULL && (bkt) < HASH_SIZE(name);\
			(bkt)++)\
		hlist_for_each_entry_rcu(obj, &name[bkt], member)
#define hash_for_each_safe(name, bkt, tmp, obj, member)			\
	for ((bkt) = 0, obj = NULL; obj == NULL && (bkt) < HASH_SIZE(name);\
			(bkt)++)\
		hlist_for_each_entry_safe(obj, tmp, &name[bkt], member)
#define hash_init(hashtable) __hash_init(hashtable, HASH_SIZE(hashtable))
#define hash_min(val, bits)							\
	(sizeof(val) <= 4 ? hash_32(val, bits) : hash_long(val, bits))
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
#define for_each_sgtable_dma_page(sgt, dma_iter, pgoffset)	\
	for_each_sg_dma_page(sgt->sgl, dma_iter, sgt->nents, pgoffset)
#define for_each_sgtable_dma_sg(sgt, sg, i)	\
	for_each_sg(sgt->sgl, sg, sgt->nents, i)
#define for_each_sgtable_page(sgt, piter, pgoffset)	\
	for_each_sg_page(sgt->sgl, piter, sgt->orig_nents, pgoffset)
#define for_each_sgtable_sg(sgt, sg, i)		\
	for_each_sg(sgt->sgl, sg, sgt->orig_nents, i)
#define sg_chain_ptr(sg)	\
	((struct scatterlist *) ((sg)->page_link & ~(SG_CHAIN | SG_END)))
#define sg_dma_address(sg)	((sg)->dma_address)
#define sg_dma_len(sg)		((sg)->dma_length)
#define sg_is_chain(sg)		((sg)->page_link & SG_CHAIN)
#define sg_is_last(sg)		((sg)->page_link & SG_END)

#define BSG_FLAG_Q_AT_HEAD 0x20
#define BSG_FLAG_Q_AT_TAIL 0x10 

#define DEFINE_WB_COMPLETION(cmpl, bdi)	\
	struct wb_completion cmpl = WB_COMPLETION_INIT(bdi)
#define WB_COMPLETION_INIT(bdi)		__WB_COMPLETION_INIT(&(bdi)->wb_waitq)
#define WB_STAT_BATCH (8*(1+ilog2(nr_cpu_ids)))

#define __WB_COMPLETION_INIT(_waitq)	\
	(struct wb_completion){ .cnt = ATOMIC_INIT(1), .waitq = (_waitq) }
#define FPROP_FRAC_BASE (1UL << FPROP_FRAC_SHIFT)
#define FPROP_FRAC_SHIFT 10
#define INIT_FPROP_LOCAL_SINGLE(name)			\
{	.lock = __RAW_SPIN_LOCK_UNLOCKED(name.lock),	\
}


#define readahead_page_batch(rac, array)				\
	__readahead_batch(rac, array, ARRAY_SIZE(array))
#define DISK_PITER_INCL_EMPTY_PART0 (1 << 3) 

#define alloc_disk(minors) alloc_disk_node(minors, NUMA_NO_NODE)
#define alloc_disk_node(minors, node_id)				\
({									\
	static struct lock_class_key __key;				\
	const char *__name;						\
	struct gendisk *__disk;						\
									\
	__name = "(gendisk_completion)"#minors"("#node_id")";		\
									\
	__disk = __alloc_disk_node(minors, node_id);			\
									\
	if (__disk)							\
		lockdep_init_map(&__disk->lockdep_map, __name, &__key, 0); \
									\
	__disk;								\
})
#define dev_to_disk(device)	container_of((device), struct gendisk, part0.__dev)
#define dev_to_part(device)	container_of((device), struct hd_struct, __dev)
#define disk_to_cdi(disk)	((disk)->cdi)
#define disk_to_dev(disk)	(&(disk)->part0.__dev)
#define part_to_dev(part)	(&((part)->__dev))

#define EFD_CLOEXEC O_CLOEXEC
#define EFD_FLAGS_SET (EFD_SHARED_FCNTL_FLAGS | EFD_SEMAPHORE)
#define EFD_NONBLOCK O_NONBLOCK
#define EFD_SEMAPHORE (1 << 0)
#define EFD_SHARED_FCNTL_FLAGS (O_CLOEXEC | O_NONBLOCK)


#define PAGE_COUNTER_MAX LONG_MAX

#define MMU_NOTIFIER_RANGE_BLOCKABLE (1 << 0)

#define mmu_notifier_range_init(range,event,flags,vma,mm,start,end)  \
	_mmu_notifier_range_init(range, start, end)
#define mmu_notifier_range_update_to_read_only(r) false
#define pmdp_clear_flush_young_notify pmdp_clear_flush_young
#define pmdp_clear_young_notify pmdp_test_and_clear_young
#define pmdp_huge_clear_flush_notify pmdp_huge_clear_flush
#define ptep_clear_flush_young_notify ptep_clear_flush_young
#define ptep_clear_young_notify ptep_test_and_clear_young
#define pudp_huge_clear_flush_notify pudp_huge_clear_flush
#define set_pte_at_notify set_pte_at

#define TICK_SIZE (tick_nsec / 1000)

#define LOADED_MM_SWITCHING ((struct mm_struct *)1UL)

#define flush_tlb_mm(mm)						\
		flush_tlb_mm_range(mm, 0UL, TLB_FLUSH_ALL, 0UL, true)
#define flush_tlb_range(vma, start, end)				\
	flush_tlb_mm_range((vma)->vm_mm, start, end,			\
			   ((vma)->vm_flags & VM_HUGETLB)		\
				? huge_page_shift(hstate_vma(vma))	\
				: PAGE_SHIFT, false)
#define nmi_uaccess_okay nmi_uaccess_okay



#define __smp_processor_id() __this_cpu_read(cpu_number)
#define cpu_acpi_id(cpu)	per_cpu(x86_cpu_to_acpiid, cpu)
#define cpu_physical_id(cpu)	per_cpu(x86_cpu_to_apicid, cpu)
#define hard_smp_processor_id()	0
#define nmi_selftest() do { } while (0)
#define raw_smp_processor_id()  this_cpu_read(cpu_number)
# define safe_smp_processor_id()	smp_processor_id()
#define wbinvd_on_cpu(cpu)     wbinvd()
#define INIT_THREAD_INFO(tsk)			\
{						\
	.flags		= 0,			\
}
#  define TOP_OF_KERNEL_STACK_PADDING 16

#define arch_setup_new_exec arch_setup_new_exec
#define in_ia32_syscall() true
#define CHECK_BIT_IN_MASK_WORD(maskname, word, bit)	\
	(((bit)>>5)==(word) && (1UL<<((bit)&31) & maskname##word ))
#define DISABLED_MASK_BIT_SET(feature_bit)				\
	 ( CHECK_BIT_IN_MASK_WORD(DISABLED_MASK,  0, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(DISABLED_MASK,  1, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(DISABLED_MASK,  2, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(DISABLED_MASK,  3, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(DISABLED_MASK,  4, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(DISABLED_MASK,  5, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(DISABLED_MASK,  6, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(DISABLED_MASK,  7, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(DISABLED_MASK,  8, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(DISABLED_MASK,  9, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(DISABLED_MASK, 10, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(DISABLED_MASK, 11, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(DISABLED_MASK, 12, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(DISABLED_MASK, 13, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(DISABLED_MASK, 14, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(DISABLED_MASK, 15, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(DISABLED_MASK, 16, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(DISABLED_MASK, 17, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(DISABLED_MASK, 18, feature_bit) ||	\
	   DISABLED_MASK_CHECK					  ||	\
	   BUILD_BUG_ON_ZERO(NCAPINTS != 19))
#define REQUIRED_MASK_BIT_SET(feature_bit)		\
	 ( CHECK_BIT_IN_MASK_WORD(REQUIRED_MASK,  0, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(REQUIRED_MASK,  1, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(REQUIRED_MASK,  2, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(REQUIRED_MASK,  3, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(REQUIRED_MASK,  4, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(REQUIRED_MASK,  5, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(REQUIRED_MASK,  6, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(REQUIRED_MASK,  7, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(REQUIRED_MASK,  8, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(REQUIRED_MASK,  9, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(REQUIRED_MASK, 10, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(REQUIRED_MASK, 11, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(REQUIRED_MASK, 12, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(REQUIRED_MASK, 13, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(REQUIRED_MASK, 14, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(REQUIRED_MASK, 15, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(REQUIRED_MASK, 16, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(REQUIRED_MASK, 17, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(REQUIRED_MASK, 18, feature_bit) ||	\
	   REQUIRED_MASK_CHECK					  ||	\
	   BUILD_BUG_ON_ZERO(NCAPINTS != 19))
#define X86_CAP_FMT "%s"

#define boot_cpu_has(bit)	cpu_has(&boot_cpu_data, bit)
#define boot_cpu_has_bug(bit)		cpu_has_bug(&boot_cpu_data, (bit))
#define boot_cpu_set_bug(bit)		set_cpu_cap(&boot_cpu_data, (bit))
#define clear_cpu_bug(c, bit)		clear_cpu_cap(c, (bit))
#define cpu_feature_enabled(bit)	\
	(__builtin_constant_p(bit) && DISABLED_MASK_BIT_SET(bit) ? 0 : static_cpu_has(bit))
#define cpu_has(c, bit)							\
	(__builtin_constant_p(bit) && REQUIRED_MASK_BIT_SET(bit) ? 1 :	\
	 test_cpu_cap(c, bit))
#define cpu_has_bug(c, bit)		cpu_has(c, (bit))
#define set_cpu_bug(c, bit)		set_cpu_cap(c, (bit))
#define set_cpu_cap(c, bit)	set_bit(bit, (unsigned long *)((c)->x86_capability))
#define setup_force_cpu_bug(bit) setup_force_cpu_cap(bit)
#define setup_force_cpu_cap(bit) do { \
	set_cpu_cap(&boot_cpu_data, bit);	\
	set_bit(bit, (unsigned long *)cpu_caps_set);	\
} while (0)
#define static_cpu_has(bit)            boot_cpu_has(bit)
#define static_cpu_has_bug(bit)		static_cpu_has((bit))
#define test_cpu_cap(c, bit)						\
	 test_bit(bit, (unsigned long *)((c)->x86_capability))
#define this_cpu_has(bit)						\
	(__builtin_constant_p(bit) && REQUIRED_MASK_BIT_SET(bit) ? 1 :	\
	 x86_this_cpu_test_bit(bit,					\
		(unsigned long __percpu *)&cpu_info.x86_capability))
#define x86_cap_flag(flag) ((flag) >> 5), ((flag) & 31)
#define APIC_DEBUG   2
#define APIC_QUIET   0
#define APIC_VERBOSE 1

#define apic_driver(sym)					\
	static const struct apic *__apicdrivers_##sym __used		\
	__aligned(sizeof(struct apic *))			\
	__section(.apicdrivers) = { &sym }
#define apic_drivers(sym1, sym2)					\
	static struct apic *__apicdrivers_##sym1##sym2[2] __used	\
	__aligned(sizeof(struct apic *))				\
	__section(.apicdrivers) = { &sym1, &sym2 }
#define apic_printk(v, s, a...) do {       \
		if ((v) <= apic_verbosity) \
			printk(s, ##a);    \
	} while (0)
# define setup_boot_APIC_clock x86_init_noop
# define setup_secondary_APIC_clock x86_init_noop
#define x2apic_supported()	(boot_cpu_has(X86_FEATURE_X2APIC))


#define arch_irq_stat		arch_irq_stat
#define inc_irq_stat(member)	this_cpu_inc(irq_stat.member)

#define default_find_smp_config x86_init_noop
#define default_get_smp_config x86_init_uint_noop
#define default_mpc_apic_id NULL
#  define default_mpc_oem_bus_info NULL
#define default_smp_read_mpc_oem NULL
#define enable_update_mptable 0
#define physid_clear(physid, map)		clear_bit(physid, (map).mask)
#define physid_isset(physid, map)		test_bit(physid, (map).mask)
#define physid_set(physid, map)			set_bit(physid, (map).mask)
#define physid_test_and_set(physid, map)			\
	test_and_set_bit(physid, (map).mask)
#define physids_and(dst, src1, src2)					\
	bitmap_and((dst).mask, (src1).mask, (src2).mask, MAX_LOCAL_APIC)
#define physids_clear(map)					\
	bitmap_zero((map).mask, MAX_LOCAL_APIC)
#define physids_complement(dst, src)				\
	bitmap_complement((dst).mask, (src).mask, MAX_LOCAL_APIC)
#define physids_empty(map)					\
	bitmap_empty((map).mask, MAX_LOCAL_APIC)
#define physids_equal(map1, map2)				\
	bitmap_equal((map1).mask, (map2).mask, MAX_LOCAL_APIC)
#define physids_or(dst, src1, src2)					\
	bitmap_or((dst).mask, (src1).mask, (src2).mask, MAX_LOCAL_APIC)
#define physids_shift_left(d, s, n)				\
	bitmap_shift_left((d).mask, (s).mask, n, MAX_LOCAL_APIC)
#define physids_shift_right(d, s, n)				\
	bitmap_shift_right((d).mask, (s).mask, n, MAX_LOCAL_APIC)
#define physids_weight(map)					\
	bitmap_weight((map).mask, MAX_LOCAL_APIC)
# define smp_found_config 0
#define APIC_BASE (fix_to_virt(FIX_APIC_BASE))
#define APIC_CLUSTER(apicid)	((apicid) & XAPIC_DEST_CLUSTER_MASK)
#define APIC_CLUSTERID(apicid)	(APIC_CLUSTER(apicid) >> XAPIC_DEST_CPUS_SHIFT)
#define APIC_CPUID(apicid)	((apicid) & XAPIC_DEST_CPUS_MASK)
#define		APIC_EILVT_LVTOFF(x)	(((x) >> 4) & 0xF)
#define APIC_EILVTn(n)	(0x500 + 0x10 * n)
#define		APIC_EXT_SPACE(x)	((x) & 0x80000000)
#define		APIC_XAPIC(x)		((x) >= 0x14)
 #define BAD_APICID 0xFFu
#define		GET_APIC_DELIVERY_MODE(x)	(((x) >> 8) & 0x7)
#define		GET_APIC_DEST_FIELD(x)	(((x) >> 24) & 0xFF)
#define		GET_APIC_LOGICAL_ID(x)	(((x) >> 24) & 0xFFu)
#define		GET_APIC_MAXLVT(x)	(((x) >> 16) & 0xFFu)
#define		GET_APIC_TIMER_BASE(x)		(((x) >> 18) & 0x3)
#define		GET_APIC_VERSION(x)	((x) & 0xFFu)
# define MAX_IO_APICS 64
# define MAX_LOCAL_APIC 256
#define		SET_APIC_DELIVERY_MODE(x, y)	(((x) & ~0x700) | ((y) << 8))
#define		SET_APIC_DEST_FIELD(x)	((x) << 24)
#define		SET_APIC_LOGICAL_ID(x)	(((x) << 24))
#define		SET_APIC_TIMER_BASE(x)		(((x) << 18))

#define u32 unsigned int

# define MAX_MPC_ENTRY 1024
#define MPC_OEM_SIGNATURE "_OEM"
#define MPC_SIGNATURE "PCMP"

#define FIXMAP_PAGE_NOCACHE PAGE_KERNEL_IO_NOCACHE

#define __late_clear_fixmap(idx) __set_fixmap(idx, 0, __pgprot(0))
#define __late_set_fixmap(idx, phys, flags) __set_fixmap(idx, phys, flags)
#define FIXMAP_PAGE_CLEAR __pgprot(0)
#define FIXMAP_PAGE_IO PAGE_KERNEL_IO
#define FIXMAP_PAGE_NORMAL PAGE_KERNEL
#define FIXMAP_PAGE_RO PAGE_KERNEL_RO

#define __fix_to_virt(x)	(FIXADDR_TOP - ((x) << PAGE_SHIFT))
#define __set_fixmap_offset(idx, phys, flags)				\
({									\
	unsigned long ________addr;					\
	__set_fixmap(idx, phys, flags);					\
	________addr = fix_to_virt(idx) + ((phys) & (PAGE_SIZE - 1));	\
	________addr;							\
})
#define __virt_to_fix(x)	((FIXADDR_TOP - ((x)&PAGE_MASK)) >> PAGE_SHIFT)
#define clear_fixmap(idx)			\
	__set_fixmap(idx, 0, FIXMAP_PAGE_CLEAR)
#define set_fixmap(idx, phys)				\
	__set_fixmap(idx, phys, FIXMAP_PAGE_NORMAL)
#define set_fixmap_io(idx, phys) \
	__set_fixmap(idx, phys, FIXMAP_PAGE_IO)
#define set_fixmap_nocache(idx, phys) \
	__set_fixmap(idx, phys, FIXMAP_PAGE_NOCACHE)
#define set_fixmap_offset(idx, phys) \
	__set_fixmap_offset(idx, phys, FIXMAP_PAGE_NORMAL)
#define set_fixmap_offset_io(idx, phys) \
	__set_fixmap_offset(idx, phys, FIXMAP_PAGE_IO)
#define set_fixmap_offset_nocache(idx, phys) \
	__set_fixmap_offset(idx, phys, FIXMAP_PAGE_NOCACHE)
#define VSYSCALL_ADDR (-10UL << 20)



#define ACPI_TABLE_UPGRADE_MAX_PHYS (max_low_pfn_mapped << PAGE_SHIFT)

#define acpi_disable_cmcff 0
#define acpi_ioapic 0
#define acpi_lapic 0
#define acpi_unlazy_tlb(x)	leave_mm(x)
#define INIT_MM_CONTEXT(mm)						\
	.context = {							\
		.ctx_id = 1,						\
		.lock = __MUTEX_INITIALIZER(mm.context.lock),		\
	}

#define NODE_MIN_SIZE (4*1024*1024)


#define arch_scale_freq_capacity arch_scale_freq_capacity
#define arch_scale_freq_invariant() static_branch_likely(&arch_scale_freq_key)
#define arch_scale_freq_tick arch_scale_freq_tick
#define cpu_to_node __cpu_to_node
#define node_distance(a, b) __node_distance(a, b)
#define numa_node_id numa_node_id
#define pcibus_to_node(bus) __pcibus_to_node(bus)
#define topology_core_cpumask(cpu)		(per_cpu(cpu_core_map, cpu))
#define topology_core_id(cpu)			(cpu_data(cpu).cpu_core_id)
#define topology_die_cpumask(cpu)		(per_cpu(cpu_die_map, cpu))
#define topology_die_id(cpu)			(cpu_data(cpu).cpu_die_id)
#define topology_logical_die_id(cpu)		(cpu_data(cpu).logical_die_id)
#define topology_logical_package_id(cpu)	(cpu_data(cpu).logical_proc_id)
#define topology_max_packages()			(__max_logical_packages)
#define topology_physical_package_id(cpu)	(cpu_data(cpu).phys_proc_id)
#define topology_sibling_cpumask(cpu)		(per_cpu(cpu_sibling_map, cpu))

#define cpu_to_mem(cpu)		((void)(cpu),0)
    #define cpumask_of_node(node)	((node) == 0 ? cpu_online_mask : cpu_none_mask)
#define cpumask_of_pcibus(bus)	(pcibus_to_node(bus) == -1 ?		\
				 cpu_all_mask :				\
				 cpumask_of_node(pcibus_to_node(bus)))
#define set_cpu_numa_mem(cpu, node)
#define set_cpu_numa_node(cpu, node)





#define ndelay(n)							\
	({								\
		if (__builtin_constant_p(n)) {				\
			if ((n) / 20000 >= 1)				\
				__bad_ndelay();				\
			else						\
				__const_udelay((n) * 5ul);		\
		} else {						\
			__ndelay(n);					\
		}							\
	})
#define udelay(n)							\
	({								\
		if (__builtin_constant_p(n)) {				\
			if ((n) / 20000 >= 1)				\
				 __bad_udelay();			\
			else						\
				__const_udelay((n) * 0x10c7ul);		\
		} else {						\
			__udelay(n);					\
		}							\
	})


#define __irq_entry __invalid_section
#define arch_trigger_cpumask_backtrace arch_trigger_cpumask_backtrace
#define ISA_IRQ_VECTOR(irq)		(((FIRST_EXTERNAL_VECTOR + 16) & ~15) + irq)
#define NR_IRQS				NR_IRQS_LEGACY

#define PGD_ALLOCATION_ORDER 1


#define pmd_pgtable(pmd) pmd_page(pmd)


#define CMOS_READ(addr) rtc_cmos_read(addr)
#define CMOS_WRITE(val, addr) rtc_cmos_write(val, addr)
#define RTC_IRQ 8
#define RTC_PORT(x)	(0x70 + (x))

#define current_lock_cmos_reg() 0
#define do_i_have_lock_cmos() 0
#define lock_cmos(reg) do { } while (0)
#define lock_cmos_prefix(reg)			\
	do {					\
		unsigned long cmos_flags;	\
		local_irq_save(cmos_flags);	\
		lock_cmos(reg)
#define lock_cmos_suffix(reg)			\
	unlock_cmos();				\
	local_irq_restore(cmos_flags);		\
	} while (0)
#define unlock_cmos() do { } while (0)



#define BUILDIO(bwl, bw, type)						\
static inline void out##bwl(unsigned type value, int port)		\
{									\
	asm volatile("out" #bwl " %" #bw "0, %w1"			\
		     : : "a"(value), "Nd"(port));			\
}									\
									\
static inline unsigned type in##bwl(int port)				\
{									\
	unsigned type value;						\
	asm volatile("in" #bwl " %w1, %" #bw "0"			\
		     : "=a"(value) : "Nd"(port));			\
	return value;							\
}									\
									\
static inline void out##bwl##_p(unsigned type value, int port)		\
{									\
	out##bwl(value, port);						\
	slow_down_io();							\
}									\
									\
static inline unsigned type in##bwl##_p(int port)			\
{									\
	unsigned type value = in##bwl(port);				\
	slow_down_io();							\
	return value;							\
}									\
									\
static inline void outs##bwl(int port, const void *addr, unsigned long count) \
{									\
	if (sev_key_active()) {						\
		unsigned type *value = (unsigned type *)addr;		\
		while (count) {						\
			out##bwl(*value, port);				\
			value++;					\
			count--;					\
		}							\
	} else {							\
		asm volatile("rep; outs" #bwl				\
			     : "+S"(addr), "+c"(count)			\
			     : "d"(port) : "memory");			\
	}								\
}									\
									\
static inline void ins##bwl(int port, void *addr, unsigned long count)	\
{									\
	if (sev_key_active()) {						\
		unsigned type *value = (unsigned type *)addr;		\
		while (count) {						\
			*value = in##bwl(port);				\
			value++;					\
			count--;					\
		}							\
	} else {							\
		asm volatile("rep; ins" #bwl				\
			     : "+D"(addr), "+c"(count)			\
			     : "d"(port) : "memory");			\
	}								\
}
#define IO_SPACE_LIMIT 0xffff

#define __ISA_IO_base ((char __iomem *)(PAGE_OFFSET))
#define __raw_readb __readb
#define __raw_readl __readl
#define __raw_readw __readw
#define __raw_writeb __writeb
#define __raw_writel __writel
#define __raw_writew __writew
#define arch_io_reserve_memtype_wc arch_io_reserve_memtype_wc
#define arch_memremap_can_ram_remap arch_memremap_can_ram_remap
#define arch_phys_wc_add arch_phys_wc_add
#define arch_phys_wc_index arch_phys_wc_index
#define build_mmio_read(name, size, type, reg, barrier) \
static inline type name(const volatile void __iomem *addr) \
{ type ret; asm volatile("mov" size " %1,%0":reg (ret) \
:"m" (*(volatile type __force *)addr) barrier); return ret; }
#define build_mmio_write(name, size, type, reg, barrier) \
static inline void name(type val, volatile void __iomem *addr) \
{ asm volatile("mov" size " %0,%1": :reg (val), \
"m" (*(volatile type __force *)addr) barrier); }
#define bus_to_virt phys_to_virt
#define inb inb
#define inb_p inb_p
#define inl inl
#define inl_p inl_p
#define insb insb
#define insl insl
#define insw insw
#define inw inw
#define inw_p inw_p
#define ioremap ioremap
#define ioremap_cache ioremap_cache
#define ioremap_encrypted ioremap_encrypted
#define ioremap_prot ioremap_prot
#define ioremap_uc ioremap_uc
#define ioremap_wc ioremap_wc
#define ioremap_wt ioremap_wt
#define iounmap iounmap
#define memcpy_fromio memcpy_fromio
#define memcpy_toio memcpy_toio
#define memset_io memset_io
#define outb outb
#define outb_p outb_p
#define outl outl
#define outl_p outl_p
#define outsb outsb
#define outsl outsl
#define outsw outsw
#define outw outw
#define outw_p outw_p
#define page_to_phys(page)    ((dma_addr_t)page_to_pfn(page) << PAGE_SHIFT)
#define phys_to_virt phys_to_virt
#define readb readb
#define readb_relaxed(a) __readb(a)
#define readl readl
#define readl_relaxed(a) __readl(a)
#define readq			readq
#define readq_relaxed(a)	__readq(a)
#define readw readw
#define readw_relaxed(a) __readw(a)
#define unxlate_dev_mem_ptr unxlate_dev_mem_ptr
#define virt_to_bus virt_to_phys
#define virt_to_phys virt_to_phys
#define writeb writeb
#define writeb_relaxed(v, a) __writeb(v, a)
#define writel writel
#define writel_relaxed(v, a) __writel(v, a)
#define writeq			writeq
#define writeq_relaxed(v, a)	__writeq(v, a)
#define writew writew
#define writew_relaxed(v, a) __writew(v, a)
#define xlate_dev_mem_ptr xlate_dev_mem_ptr
#define PCI_IOBASE ((void __iomem *)0)

#define __io_ar(v)      rmb()
#define __io_aw()      mmiowb_set_pending()
#define __io_br()      barrier()
#define __io_bw()      wmb()
#define __io_par(v)     __io_ar(v)
#define __io_paw()     __io_aw()
#define __io_pbr()     __io_br()
#define __io_pbw()     __io_bw()
#define __io_virt(x) ((void __force *)(x))
#define __raw_readq __raw_readq
#define __raw_writeq __raw_writeq
#define _inb _inb
#define _inl _inl
#define _inw _inw
#define _outb _outb
#define _outl _outl
#define _outw _outw
#define insb_p insb_p
#define insl_p insl_p
#define insw_p insw_p
#define ioport_map ioport_map
#define ioport_unmap ioport_unmap
#define ioread16 ioread16
#define ioread16_rep ioread16_rep
#define ioread16be ioread16be
#define ioread32 ioread32
#define ioread32_rep ioread32_rep
#define ioread32be ioread32be
#define ioread64 ioread64
#define ioread64_rep ioread64_rep
#define ioread64be ioread64be
#define ioread8 ioread8
#define ioread8_rep ioread8_rep
#define iowrite16 iowrite16
#define iowrite16_rep iowrite16_rep
#define iowrite16be iowrite16be
#define iowrite32 iowrite32
#define iowrite32_rep iowrite32_rep
#define iowrite32be iowrite32be
#define iowrite64 iowrite64
#define iowrite64_rep iowrite64_rep
#define iowrite64be iowrite64be
#define iowrite8 iowrite8
#define iowrite8_rep iowrite8_rep
#define outsb_p outsb_p
#define outsl_p outsl_p
#define outsw_p outsw_p
#define pci_iounmap pci_iounmap
#define readsb readsb
#define readsl readsl
#define readsq readsq
#define readsw readsw
#define writesb writesb
#define writesl writesl
#define writesq writesq
#define writesw writesw
#define xlate_dev_kmem_ptr xlate_dev_kmem_ptr
#define ARCH_PAGE_TABLE_SYNC_MASK 0
#define VMALLOC_TOTAL (VMALLOC_END - VMALLOC_START)

#define map_kernel_range map_kernel_range_noflush
#define unmap_kernel_range unmap_kernel_range_noflush
#define MMIO_UPPER_LIMIT (IO_SPACE_LIMIT - PIO_INDIRECT_SIZE)
#define PIO_INDIRECT_SIZE 0x4000


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

#define __pci_ioport_map(dev, port, nr) ioport_map((port), (nr))

#define ioread64_hi_lo ioread64_hi_lo
#define ioread64_lo_hi ioread64_lo_hi
#define ioread64be_hi_lo ioread64be_hi_lo
#define ioread64be_lo_hi ioread64be_lo_hi
#define iowrite64_hi_lo iowrite64_hi_lo
#define iowrite64_lo_hi iowrite64_lo_hi
#define iowrite64be_hi_lo iowrite64be_hi_lo
#define iowrite64be_lo_hi iowrite64be_lo_hi
#define CLOCKSOURCE_MASK(bits) GENMASK_ULL((bits) - 1, 0)
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
#define MHI_DEVICE_MODALIAS_FMT "mhi:%s"
#define MHI_NAME_SIZE 32
#define PCI_ANY_ID (~0)
#define SDIO_ANY_ID (~0)
#define SPI_MODULE_PREFIX "spi:"
#define SPMI_MODULE_PREFIX "spmi:"
#define SSB_DEVICE(_vendor, _coreid, _revision)  \
	{ .vendor = _vendor, .coreid = _coreid, .revision = _revision, }
#define X86_FAMILY_ANY 0
#define X86_FEATURE_ANY 0	
#define X86_MODEL_ANY  0
#define X86_STEPPING_ANY 0
#define X86_VENDOR_ANY 0xffff
#define dmi_device_id dmi_system_id
#define x86cpu_device_id x86_cpu_id
#define COMMAND_LINE_SIZE 2048
#define LOWMEMSIZE()	(0x9f000)
#define PARAM_SIZE 4096		
#define RESERVE_BRK(name,sz)						\
	static void __section(.discard.text) __used notrace		\
	__brk_reservation_fn_##name##__(void) {				\
		asm volatile (						\
			".pushsection .brk_reservation,\"aw\",@nobits;" \
			".brk." #name ":"				\
			" 1:.skip %c0;"					\
			" .size .brk." #name ", . - 1b;"		\
			" .popsection"					\
			: : "i" (sz));					\
	}
#define RESERVE_BRK_ARRAY(type, name, entries)		\
	type *name;					\
	RESERVE_BRK(name, sizeof(type) * entries)


#define LDT_empty(info)					\
	((info)->base_addr		== 0	&&	\
	 (info)->limit			== 0	&&	\
	 (info)->contents		== 0	&&	\
	 (info)->read_exec_only		== 1	&&	\
	 (info)->seg_32bit		== 0	&&	\
	 (info)->limit_in_pages		== 0	&&	\
	 (info)->seg_not_present	== 1	&&	\
	 (info)->useable		== 0)

#define load_TLS(t, cpu)			native_load_tls(t, cpu)
#define load_TR_desc()				native_load_tr_desc()
#define load_gdt(dtr)				native_load_gdt(dtr)
#define load_idt(dtr)				native_load_idt(dtr)
#define load_ldt(ldt)				asm volatile("lldt %0"::"m" (ldt))
#define load_tr(tr)				asm volatile("ltr %0"::"m" (tr))
#define set_ldt					native_set_ldt
#define set_tss_desc(cpu, addr) __set_tss_desc(cpu, GDT_ENTRY_TSS, addr)
#define store_gdt(dtr)				native_store_gdt(dtr)
#define store_ldt(ldt) asm("sldt %0" : "=m"(ldt))
#define store_tr(tr)				(tr = native_store_tr())
#define write_idt_entry(dt, entry, g)		native_write_idt_entry(dt, entry, g)
#define CEA_ESTACK_BOT(ceastp, st)				\
	((unsigned long)&(ceastp)->st## _stack)
#define CEA_ESTACK_OFFS(st)					\
	offsetof(struct cea_exception_stacks, st## _stack)
#define CEA_ESTACK_SIZE(st)					\
	sizeof(((struct cea_exception_stacks *)0)->st## _stack)
#define CEA_ESTACK_TOP(ceastp, st)				\
	(CEA_ESTACK_BOT(ceastp, st) + CEA_ESTACK_SIZE(st))
#define ESTACKS_MEMBERS(guardsize)		\
	char	DF_stack_guard[guardsize];	\
	char	DF_stack[EXCEPTION_STKSZ];	\
	char	NMI_stack_guard[guardsize];	\
	char	NMI_stack[EXCEPTION_STKSZ];	\
	char	DB_stack_guard[guardsize];	\
	char	DB_stack[EXCEPTION_STKSZ];	\
	char	MCE_stack_guard[guardsize];	\
	char	MCE_stack[EXCEPTION_STKSZ];	\
	char	IST_top_guard[guardsize];	\


#define __this_cpu_ist_top_va(name)					\
	CEA_ESTACK_TOP(__this_cpu_read(cea_exception_stacks), name)



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

#define BUG()							\
do {								\
	instrumentation_begin();				\
	_BUG_FLAGS(ASM_UD2, 0);					\
	unreachable();						\
} while (0)


#define _BUG_FLAGS(ins, flags)						\
do {									\
	asm_inline volatile("1:\t" ins "\n"				\
		     ".pushsection __bug_table,\"aw\"\n"		\
		     "2:\t" __BUG_REL(1b) "\t# bug_entry::bug_addr\n"	\
		     "\t"  __BUG_REL(%c0) "\t# bug_entry::file\n"	\
		     "\t.word %c1"        "\t# bug_entry::line\n"	\
		     "\t.word %c2"        "\t# bug_entry::flags\n"	\
		     "\t.org 2b+%c3\n"					\
		     ".popsection"					\
		     : : "i" ("__FILE__"), "i" ("__LINE__"),		\
			 "i" (flags),					\
			 "i" (sizeof(struct bug_entry)));		\
} while (0)
# define __BUG_REL(val)	".long " __stringify(val)
#define __WARN_FLAGS(flags)					\
do {								\
	instrumentation_begin();				\
	_BUG_FLAGS(ASM_UD2, BUGFLAG_WARNING|(flags));		\
	annotate_reachable();					\
	instrumentation_end();					\
} while (0)
#define DEFINE_INSN_CACHE_OPS(__name)					\
extern struct kprobe_insn_cache kprobe_##__name##_slots;		\
									\
static inline kprobe_opcode_t *get_##__name##_slot(void)		\
{									\
	return __get_insn_slot(&kprobe_##__name##_slots);		\
}									\
									\
static inline void free_##__name##_slot(kprobe_opcode_t *slot, int dirty)\
{									\
	__free_insn_slot(&kprobe_##__name##_slots, slot, dirty);	\
}									\
									\
static inline bool is_kprobe_##__name##_slot(unsigned long addr)	\
{									\
	return __is_insn_slot_addr(&kprobe_##__name##_slots, addr);	\
}

# define NOKPROBE_SYMBOL(fname)

# define __NOKPROBE_SYMBOL(fname)				\
static unsigned long __used					\
	__attribute__((__section__("_kprobe_blacklist")))	\
	_kbl_addr_##fname = (unsigned long)fname;
# define __kprobes
#define ARCH_SUPPORTS_FTRACE_OPS 0
#define CALLER_ADDR0 ((unsigned long)ftrace_return_address0)
#define CALLER_ADDR1 ((unsigned long)ftrace_return_address(1))
#define CALLER_ADDR2 ((unsigned long)ftrace_return_address(2))
#define CALLER_ADDR3 ((unsigned long)ftrace_return_address(3))
#define CALLER_ADDR4 ((unsigned long)ftrace_return_address(4))
#define CALLER_ADDR5 ((unsigned long)ftrace_return_address(5))
#define CALLER_ADDR6 ((unsigned long)ftrace_return_address(6))
#define FTRACE_ADDR ((unsigned long)ftrace_caller)
#define FTRACE_FL_MASK		(FTRACE_FL_MASKED_BITS << FTRACE_REF_MAX_SHIFT)
# define FTRACE_FORCE_LIST_FUNC 1
#define FTRACE_GRAPH_ADDR ((unsigned long)ftrace_graph_caller)
#define FTRACE_GRAPH_TRAMP_ADDR ((unsigned long) 0)
#define FTRACE_REF_MAX		((1UL << FTRACE_REF_MAX_SHIFT) - 1)
# define FTRACE_REGS_ADDR ((unsigned long)ftrace_regs_caller)
#define FTRACE_RETFUNC_DEPTH 50
#define FTRACE_RETSTACK_ALLOC_SIZE 32


#define do_for_each_ftrace_op(op, list)			\
	op = rcu_dereference_raw_check(list);			\
	do
#define for_ftrace_rec_iter(iter)		\
	for (iter = ftrace_rec_iter_start();	\
	     iter;				\
	     iter = ftrace_rec_iter_next(iter))
# define ftrace_direct_func_count 0
#define ftrace_free_filter(ops) do { } while (0)
#define ftrace_ops_set_global_filter(ops) do { } while (0)
#define ftrace_rec_count(rec)	((rec)->flags & ~FTRACE_FL_MASK)
#define ftrace_regex_open(ops, flag, inod, file) ({ -ENODEV; })
#  define ftrace_return_address(n) __builtin_return_address(n)
# define ftrace_return_address0 __builtin_return_address(0)
#define ftrace_set_early_filter(ops, buf, enable) do { } while (0)
#define ftrace_set_filter(ops, buf, len, reset) ({ -ENODEV; })
#define ftrace_set_filter_ip(ops, ip, remove, reset) ({ -ENODEV; })
#define ftrace_set_notrace(ops, buf, len, reset) ({ -ENODEV; })
#define register_ftrace_function(ops) ({ 0; })
#define register_ftrace_graph(ops) ({ -1; })
# define trace_preempt_off(a0, a1) do { } while (0)
# define trace_preempt_on(a0, a1) do { } while (0)
#define unregister_ftrace_function(ops) ({ 0; })
#define unregister_ftrace_graph(ops) do { } while (0)
#define while_for_each_ftrace_op(op)				\
	while (likely(op = rcu_dereference_raw_check((op)->next)) &&	\
	       unlikely((op) != &ftrace_list_end))
#define PTRACE_MODE_ATTACH_FSCREDS (PTRACE_MODE_ATTACH | PTRACE_MODE_FSCREDS)
#define PTRACE_MODE_ATTACH_REALCREDS (PTRACE_MODE_ATTACH | PTRACE_MODE_REALCREDS)
#define PTRACE_MODE_READ_FSCREDS (PTRACE_MODE_READ | PTRACE_MODE_FSCREDS)
#define PTRACE_MODE_READ_REALCREDS (PTRACE_MODE_READ | PTRACE_MODE_REALCREDS)
#define PT_BLOCKSTEP		(1<<PT_BLOCKSTEP_BIT)
#define PT_EVENT_FLAG(event)	(1 << (PT_OPT_FLAG_SHIFT + (event)))
#define PT_SINGLESTEP		(1<<PT_SINGLESTEP_BIT)

#define arch_has_block_step()		(0)
#define arch_has_single_step()		(0)
#define arch_ptrace_stop(code, info)		do { } while (0)
#define arch_ptrace_stop_needed(code, info)	(0)
#define current_pt_regs() task_pt_regs(current)
#define current_user_stack_pointer() user_stack_pointer(current_pt_regs())
#define force_successful_syscall_return() do { } while (0)
#define is_syscall_success(regs) (!IS_ERR_VALUE((unsigned long)(regs_return_value(regs))))
#define signal_pt_regs() task_pt_regs(current)

#define MAX_PID_NS_LEVEL 32
#define PIDNS_ADDING (1U << 31)



#define bcd2bin(x)					\
		(__builtin_constant_p((u8 )(x)) ?	\
		const_bcd2bin(x) :			\
		_bcd2bin(x))
#define bin2bcd(x)					\
		(__builtin_constant_p((u8 )(x)) ?	\
		const_bin2bcd(x) :			\
		_bin2bcd(x))
#define const_bcd2bin(x)	(((x) & 0x0f) + ((x) >> 4) * 10)
#define const_bin2bcd(x)	((((x) / 10) << 4) + (x) % 10)
#define EFIVARS_DATA_SIZE_MAX 1024
#define EFI_1_02_SYSTEM_TABLE_REVISION  ((1 << 16) | (02))
#define EFI_1_10_SYSTEM_TABLE_REVISION  ((1 << 16) | (10))
#define EFI_2_00_SYSTEM_TABLE_REVISION  ((2 << 16) | (00))
#define EFI_2_10_SYSTEM_TABLE_REVISION  ((2 << 16) | (10))
#define EFI_2_20_SYSTEM_TABLE_REVISION  ((2 << 16) | (20))
#define EFI_2_30_SYSTEM_TABLE_REVISION  ((2 << 16) | (30))
#define EFI_BAD_BUFFER_SIZE     ( 4 | (1UL << (BITS_PER_LONG-1)))
#define EFI_GUID(a,b,c,d0,d1,d2,d3,d4,d5,d6,d7) \
	GUID_INIT(a, b, c, d0, d1, d2, d3, d4, d5, d6, d7)
#define EFI_LOAD_ERROR          ( 1 | (1UL << (BITS_PER_LONG-1)))
#define EFI_MEMMAP_LATE (1UL << 0)
#define EFI_MEMMAP_MEMBLOCK (1UL << 1)
#define EFI_MEMMAP_SLAB (1UL << 2)
#define EFI_MEMORY_MORE_RELIABLE \
				((u64)0x0000000000010000ULL)	
#define EFI_MEMRESERVE_COUNT(size) (((size) - sizeof(struct linux_efi_memreserve)) \
	/ sizeof(((struct linux_efi_memreserve *)0)->entry[0]))
#define EFI_MEMRESERVE_SIZE(count) (sizeof(struct linux_efi_memreserve) + \
	(count) * sizeof(((struct linux_efi_memreserve *)0)->entry[0]))
#define EFI_RESET_COLD 0
#define EFI_RESET_SHUTDOWN 2
#define EFI_RESET_WARM 1
#define EFI_RT_SUPPORTED_GET_TIME 				0x0001
#define EFI_RT_SUPPORTED_SET_TIME 				0x0002
#define EFI_RUNTIME_SERVICES_REVISION  0x00010000
#define EFI_RUNTIME_SERVICES_SIGNATURE ((u64)0x5652453544e5552ULL)
#define EFI_SYSTEM_TABLE_SIGNATURE ((u64)0x5453595320494249ULL)
#define EFI_TIME_ADJUST_DAYLIGHT 0x1
#define EFI_TIME_IN_DAYLIGHT     0x2
#define EFI_UNSPECIFIED_TIMEZONE 0x07ff
#define EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS 0x0000000000000010
#define EFI_VARIABLE_BOOTSERVICE_ACCESS 0x0000000000000002
#define EFI_VARIABLE_HARDWARE_ERROR_RECORD 0x0000000000000008
#define EFI_VARIABLE_MASK 	(EFI_VARIABLE_NON_VOLATILE | \
				EFI_VARIABLE_BOOTSERVICE_ACCESS | \
				EFI_VARIABLE_RUNTIME_ACCESS | \
				EFI_VARIABLE_HARDWARE_ERROR_RECORD | \
				EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS | \
				EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS | \
				EFI_VARIABLE_APPEND_WRITE)
#define EFI_VARIABLE_NON_VOLATILE       0x0000000000000001
#define EFI_VARIABLE_RUNTIME_ACCESS     0x0000000000000004
#define EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS 0x0000000000000020

#define __efi_call_virt_pointer(p, f, args...)				\
({									\
	unsigned long __flags;						\
									\
	arch_efi_call_virt_setup();					\
									\
	__flags = efi_call_virt_save_flags();				\
	arch_efi_call_virt(p, f, args);					\
	efi_call_virt_check_flags(__flags, __stringify(f));		\
									\
	arch_efi_call_virt_teardown();					\
})
#define __efiapi __attribute__((ms_abi))
#define efi_call_virt_pointer(p, f, args...)				\
({									\
	efi_status_t __s;						\
	unsigned long __flags;						\
									\
	arch_efi_call_virt_setup();					\
									\
	__flags = efi_call_virt_save_flags();				\
	__s = arch_efi_call_virt(p, f, args);				\
	efi_call_virt_check_flags(__flags, __stringify(f));		\
									\
	arch_efi_call_virt_teardown();					\
									\
	__s;								\
})
#define efi_early_memdesc_ptr(map, desc_size, n)			\
	(efi_memory_desc_t *)((void *)(map) + ((n) * (desc_size)))
#define for_each_efi_memory_desc(md) \
	for_each_efi_memory_desc_in_map(&efi.memmap, md)
#define for_each_efi_memory_desc_in_map(m, md)				   \
	for ((md) = (m)->map;						   \
	     (md) && ((void *)(md) + (m)->desc_size) <= (m)->map_end;	   \
	     (md) = (void *)(md) + (m)->desc_size)

#define VIDEO_TYPE_SGI          0x33    
#define VIDEO_TYPE_SUN          0x50    
#define VIDEO_TYPE_SUNPCI       0x51    



#define PSTORE_CPU_IN_IP 0x1
#define TS_CPU_MASK (BIT(TS_CPU_SHIFT) - 1)
#define TS_CPU_SHIFT 8


#define RTC_DEV_BUSY 0

#define rtc_hctosys_ret -ENODEV
#define rtc_lock(d) mutex_lock(&d->ops_lock)
#define rtc_register_device(device) \
	__rtc_register_device(THIS_MODULE, device)
#define rtc_unlock(d) mutex_unlock(&d->ops_lock)
#define to_rtc_device(d) container_of(d, struct rtc_device, dev)
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


#define RTC_AF 0x20	
#define RTC_IRQF 0x80	
#define RTC_PF 0x40	
#define RTC_UF 0x10	




#define proc_create(name, mode, parent, proc_ops) ({NULL;})
#define proc_create_data(name, mode, parent, proc_ops, data) ({NULL;})
#define proc_create_net(name, mode, parent, ops, state_size) \
	proc_create_net_data(name, mode, parent, ops, state_size, NULL)
#define proc_create_net_data(name, mode, parent, ops, state_size, data) ({NULL;})
#define proc_create_net_single(name, mode, parent, show, data) ({NULL;})
#define proc_create_seq(name, mode, parent, ops) ({NULL;})
#define proc_create_seq_data(name, mode, parent, ops, data) ({NULL;})
#define proc_create_seq_private(name, mode, parent, ops, size, data) ({NULL;})
#define proc_create_single(name, mode, parent, show) ({NULL;})
#define proc_create_single_data(name, mode, parent, show, data) ({NULL;})
#define remove_proc_entry(name, parent) do {} while (0)
