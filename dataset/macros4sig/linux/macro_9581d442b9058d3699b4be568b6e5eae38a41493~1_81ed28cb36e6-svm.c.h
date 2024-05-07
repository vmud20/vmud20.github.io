






#include<asm/stat.h>

#include<linux/fs.h>
#include<asm/signal.h>



#include<stdarg.h>



#include<linux/string.h>

#include<linux/time.h>
#include<linux/const.h>
#include<linux/types.h>
#include<linux/stat.h>



#include<asm/byteorder.h>






#include<asm/resource.h>
#include<asm/kvm.h>



#include<linux/wait.h>

#include<linux/errno.h>

#include<asm/posix_types.h>













#include<linux/stddef.h>

#include<linux/module.h>
#include<asm/bitsperlong.h>

#include<asm/siginfo.h>






#include<string.h>







#include<asm/param.h>











#include<linux/timex.h>






#include<asm/types.h>


#include<linux/param.h>

#include<linux/ioctl.h>
#include<asm/vm86.h>
#include<asm/sembuf.h>



#include<linux/signal.h>


#include<asm/kvm_para.h>
#include<linux/sched.h>



#include<linux/capability.h>






#include<linux/kernel.h>



#include<asm/fcntl.h>




#include<asm/auxvec.h>


#include<asm/ipcbuf.h>
#include<asm/processor-flags.h>




#include<asm/errno.h>
#include<asm/hw_breakpoint.h>


#include<asm/ioctl.h>





#include<asm/ptrace.h>

#define AREG(x) { APIC_##x, "APIC_" #x }
#define EXS(x) { x##_VECTOR, "#" #x }
#define KVM_EMUL_INSN_F_CR0_PE (1 << 0)
#define KVM_EMUL_INSN_F_CS_D   (1 << 2)
#define KVM_EMUL_INSN_F_CS_L   (1 << 3)
#define KVM_EMUL_INSN_F_EFL_VM (1 << 1)
#define TRACE_INCLUDE_FILE trace
#define TRACE_INCLUDE_PATH arch/x86/kvm
#define TRACE_SYSTEM kvm

#define __print_insn(insn, ilen) ({		                 \
	int i;							 \
	const char *ret = p->buffer + p->len;			 \
								 \
	for (i = 0; i < ilen; ++i)				 \
		trace_seq_printf(p, " %02x", insn[i]);		 \
	trace_seq_printf(p, "%c", 0);				 \
	ret;							 \
	})
#define kei_decode_mode(mode) ({			\
	u8 flags = 0xff;				\
	switch (mode) {					\
	case X86EMUL_MODE_REAL:				\
		flags = 0;				\
		break;					\
	case X86EMUL_MODE_VM86:				\
		flags = KVM_EMUL_INSN_F_EFL_VM;		\
		break;					\
	case X86EMUL_MODE_PROT16:			\
		flags = KVM_EMUL_INSN_F_CR0_PE;		\
		break;					\
	case X86EMUL_MODE_PROT32:			\
		flags = KVM_EMUL_INSN_F_CR0_PE		\
			| KVM_EMUL_INSN_F_CS_D;		\
		break;					\
	case X86EMUL_MODE_PROT64:			\
		flags = KVM_EMUL_INSN_F_CR0_PE		\
			| KVM_EMUL_INSN_F_CS_L;		\
		break;					\
	}						\
	flags;						\
	})
#define trace_kvm_apic_read(reg, val)		trace_kvm_apic(0, reg, val)
#define trace_kvm_apic_write(reg, val)		trace_kvm_apic(1, reg, val)
#define trace_kvm_cr_read(cr, val)		trace_kvm_cr(0, cr, val)
#define trace_kvm_cr_write(cr, val)		trace_kvm_cr(1, cr, val)
#define trace_kvm_emulate_insn_failed(vcpu) trace_kvm_emulate_insn(vcpu, 1)
#define trace_kvm_emulate_insn_start(vcpu) trace_kvm_emulate_insn(vcpu, 0)
#define trace_kvm_msr_read(ecx, data)      trace_kvm_msr(0, ecx, data, false)
#define trace_kvm_msr_read_ex(ecx)         trace_kvm_msr(0, ecx, 0, true)
#define trace_kvm_msr_write(ecx, data)     trace_kvm_msr(1, ecx, data, false)
#define trace_kvm_msr_write_ex(ecx, data)  trace_kvm_msr(1, ecx, data, true)

#define DECLARE_TRACE(name, proto, args)	\
	DEFINE_TRACE(name)
#define DEFINE_EVENT(template, name, proto, args) \
	DEFINE_TRACE(name)
#define DEFINE_EVENT_PRINT(template, name, proto, args, print)	\
	DEFINE_TRACE(name)
#define TRACE_EVENT(name, proto, args, tstruct, assign, print)	\
	DEFINE_TRACE(name)
#define TRACE_EVENT_FN(name, proto, args, tstruct,		\
		assign, print, reg, unreg)			\
	DEFINE_TRACE_FN(name, reg, unreg)

# define TRACE_INCLUDE(system) __TRACE_INCLUDE(system)
# define UNDEF_TRACE_INCLUDE_FILE
# define UNDEF_TRACE_INCLUDE_PATH
# define __TRACE_INCLUDE(system) <trace/events/system.h>
#define DECLARE_EVENT_CLASS(call, proto, args, tstruct, assign, print)	\
	struct ftrace_data_offsets_##call {				\
		tstruct;						\
	};
#define TP_STRUCT__entry(args...) args
#define TP_fast_assign(args...) args

#define TP_printk(fmt, args...) fmt "\n", args
#define _TRACE_PERF_INIT(call)						\
	.perf_probe		= perf_trace_##call,
#define _TRACE_PERF_PROTO(call, proto)					\
	static notrace void						\
	perf_trace_##call(void *__data, proto);
#define __array(type, item, len)
#define __assign_str(dst, src)						\
	strcpy(__get_str(dst), src);
#define __dynamic_array(type, item, len)	u32 item;
#define __entry field
#define __field(type, item)
#define __field_ext(type, item, filter_type)
#define __get_dynamic_array(field)	\
		((void *)__entry + (__entry->__data_loc_##field & 0xffff))
#define __get_str(field) (char *)__get_dynamic_array(field)
#define __perf_addr(a) __addr = (a)
#define __perf_count(c) __count = (c)
#define __print_flags(flag, delim, flag_array...)			\
	({								\
		static const struct trace_print_flags __flags[] =	\
			{ flag_array, { -1, NULL }};			\
		ftrace_print_flags_seq(p, delim, flag, __flags);	\
	})
#define __print_hex(buf, buf_len) ftrace_print_hex_seq(p, buf, buf_len)
#define __print_symbolic(value, symbol_array...)			\
	({								\
		static const struct trace_print_flags symbols[] =	\
			{ symbol_array, { -1, NULL }};			\
		ftrace_print_symbols_seq(p, value, symbols);		\
	})
#define __string(item, src) __dynamic_array(char, item, -1)

#define event_trace_printk(ip, fmt, args...)				\
do {									\
	__trace_printk_check_format(fmt, ##args);			\
	tracing_record_cmdline(current);				\
	if (__builtin_constant_p(fmt)) {				\
		static const char *trace_printk_fmt			\
		  __attribute__((section("__trace_printk_fmt"))) =	\
			__builtin_constant_p(fmt) ? fmt : NULL;		\
									\
		__trace_bprintk(ip, trace_printk_fmt, ##args);		\
	} else								\
		__trace_printk(ip, fmt, ##args);			\
} while (0)
#define is_signed_type(type)	(((type)(-1)) < 0)
#define PERF_EVENT_TXN 0x1

#define perf_cpu_notifier(fn)					\
do {								\
	static struct notifier_block fn##_nb __cpuinitdata =	\
		{ .notifier_call = fn, .priority = CPU_PRI_PERF }; \
	fn(&fn##_nb, (unsigned long)CPU_UP_PREPARE,		\
		(void *)(unsigned long)smp_processor_id());	\
	fn(&fn##_nb, (unsigned long)CPU_STARTING,		\
		(void *)(unsigned long)smp_processor_id());	\
	fn(&fn##_nb, (unsigned long)CPU_ONLINE,			\
		(void *)(unsigned long)smp_processor_id());	\
	register_cpu_notifier(&fn##_nb);			\
} while (0)
#define perf_instruction_pointer(regs)	instruction_pointer(regs)
#define perf_misc_flags(regs)	(user_mode(regs) ? PERF_RECORD_MISC_USER : \
				 PERF_RECORD_MISC_KERNEL)
#define perf_output_put(handle, x) \
	perf_output_copy((handle), &(x), sizeof(x))

#define cpu_notifier(fn, pri)	do { (void)(fn); } while (0)
#define get_online_cpus()	do { } while (0)
#define hotcpu_notifier(fn, pri)	cpu_notifier(fn, pri)
#define put_online_cpus()	do { } while (0)
#define register_hotcpu_notifier(nb)	register_cpu_notifier(nb)
#define unregister_hotcpu_notifier(nb)	unregister_cpu_notifier(nb)
#define CPU_MASK_LAST_WORD BITMAP_LAST_WORD_MASK(NR_CPUS)

#define any_online_cpu(mask)	0
#define cpu_active(cpu)		((cpu) == 0)
#define cpu_all_mask to_cpumask(cpu_all_bits)
#define cpu_clear(cpu, dst) __cpu_clear((cpu), &(dst))
#define cpu_is_offline(cpu)	unlikely(!cpu_online(cpu))
#define cpu_isset(cpu, cpumask) test_bit((cpu), (cpumask).bits)
#define cpu_none_mask to_cpumask(cpu_bit_bitmap[0])
#define cpu_online(cpu)		cpumask_test_cpu((cpu), cpu_online_mask)
#define cpu_possible(cpu)	cpumask_test_cpu((cpu), cpu_possible_mask)
#define cpu_present(cpu)	cpumask_test_cpu((cpu), cpu_present_mask)
#define cpu_set(cpu, dst) __cpu_set((cpu), &(dst))
#define cpu_test_and_set(cpu, cpumask) __cpu_test_and_set((cpu), &(cpumask))
#define cpumask_any(srcp) cpumask_first(srcp)
#define cpumask_any_and(mask1, mask2) cpumask_first_and((mask1), (mask2))
#define cpumask_bits(maskp) ((maskp)->bits)
#define cpumask_first_and(src1p, src2p) cpumask_next_and(-1, (src1p), (src2p))
#define cpumask_of(cpu) (get_cpu_mask(cpu))
#define cpumask_of_cpu(cpu) (*get_cpu_mask(cpu))
#define cpumask_test_cpu(cpu, cpumask) \
	test_bit(cpumask_check(cpu), cpumask_bits((cpumask)))
#define cpus_addr(src) ((src).bits)
#define cpus_and(dst, src1, src2) __cpus_and(&(dst), &(src1), &(src2), NR_CPUS)
#define cpus_andnot(dst, src1, src2) \
				__cpus_andnot(&(dst), &(src1), &(src2), NR_CPUS)
#define cpus_clear(dst) __cpus_clear(&(dst), NR_CPUS)
#define cpus_empty(src) __cpus_empty(&(src), NR_CPUS)
#define cpus_equal(src1, src2) __cpus_equal(&(src1), &(src2), NR_CPUS)
#define cpus_intersects(src1, src2) __cpus_intersects(&(src1), &(src2), NR_CPUS)
#define cpus_or(dst, src1, src2) __cpus_or(&(dst), &(src1), &(src2), NR_CPUS)
#define cpus_setall(dst) __cpus_setall(&(dst), NR_CPUS)
#define cpus_shift_left(dst, src, n) \
			__cpus_shift_left(&(dst), &(src), (n), NR_CPUS)
#define cpus_subset(src1, src2) __cpus_subset(&(src1), &(src2), NR_CPUS)
#define cpus_weight(cpumask) __cpus_weight(&(cpumask), NR_CPUS)
#define cpus_xor(dst, src1, src2) __cpus_xor(&(dst), &(src1), &(src2), NR_CPUS)
#define first_cpu(src)		({ (void)(src); 0; })
#define for_each_cpu(cpu, mask)			\
	for ((cpu) = 0; (cpu) < 1; (cpu)++, (void)mask)
#define for_each_cpu_and(cpu, mask, and)	\
	for ((cpu) = 0; (cpu) < 1; (cpu)++, (void)mask, (void)and)
#define for_each_cpu_mask(cpu, mask)	\
	for ((cpu) = 0; (cpu) < 1; (cpu)++, (void)mask)
#define for_each_cpu_mask_nr(cpu, mask)	for_each_cpu_mask(cpu, mask)
#define for_each_cpu_not(cpu, mask)		\
	for ((cpu) = 0; (cpu) < 1; (cpu)++, (void)mask)
#define for_each_online_cpu(cpu)   for_each_cpu((cpu), cpu_online_mask)
#define for_each_possible_cpu(cpu) for_each_cpu((cpu), cpu_possible_mask)
#define for_each_present_cpu(cpu)  for_each_cpu((cpu), cpu_present_mask)
#define next_cpu(n, src)	({ (void)(src); 1; })
#define num_active_cpus()	cpumask_weight(cpu_active_mask)
#define num_online_cpus()	cpumask_weight(cpu_online_mask)
#define num_possible_cpus()	cpumask_weight(cpu_possible_mask)
#define num_present_cpus()	cpumask_weight(cpu_present_mask)
#define to_cpumask(bitmap)						\
	((struct cpumask *)(1 ? (bitmap)				\
			    : (void *)sizeof(__check_is_bitmap(bitmap))))
#define BITMAP_LAST_WORD_MASK(nbits)					\
(									\
	((nbits) % BITS_PER_LONG) ?					\
		(1UL<<((nbits) % BITS_PER_LONG))-1 : ~0UL		\
)

#define small_const_nbits(nbits) \
	(__builtin_constant_p(nbits) && (nbits) <= BITS_PER_LONG)
#define ALIGN(x, a)		__ALIGN_KERNEL((x), (a))
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]) + __must_be_array(arr))
#define BUILD_BUG_ON(condition) ((void)BUILD_BUG_ON_ZERO(condition))
#define BUILD_BUG_ON_NOT_POWER_OF_2(n)			\
	BUILD_BUG_ON((n) == 0 || (((n) & ((n) - 1)) != 0))
#define BUILD_BUG_ON_NULL(e) ((void *)sizeof(struct { int:-!!(e); }))
#define BUILD_BUG_ON_ZERO(e) (sizeof(struct { int:-!!(e); }))
#define DIV_ROUND_CLOSEST(x, divisor)(			\
{							\
	typeof(divisor) __divisor = divisor;		\
	(((x) + ((__divisor) / 2)) / (__divisor));	\
}							\
)
#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#define FIELD_SIZEOF(t, f) (sizeof(((t*)0)->f))
#define IS_ALIGNED(x, a)		(((x) & ((typeof(x))(a) - 1)) == 0)
#define MAYBE_BUILD_BUG_ON(cond) ((void)sizeof(char[1 - 2 * !!(cond)]))
#define NUMA_BUILD 1
#define PTR_ALIGN(p, a)		((typeof(p))ALIGN((unsigned long)(p), (a)))
# define REBUILD_DUE_TO_FTRACE_MCOUNT_RECORD

#define _THIS_IP_  ({ __label__ __here; __here: (unsigned long)&&__here; })
#define __ALIGN_KERNEL(x, a)		__ALIGN_KERNEL_MASK(x, (typeof(x))(a) - 1)
#define __ALIGN_KERNEL_MASK(x, mask)	(((x) + (mask)) & ~(mask))
#define __ALIGN_MASK(x, mask)	__ALIGN_KERNEL_MASK((x), (mask))
#define __FUNCTION__ (__func__)
#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define __trace_printk_check_format(fmt, args...)			\
do {									\
	if (0)								\
		____trace_printk_check_format(fmt, ##args);		\
} while (0)
#define abs(x) ({				\
		long __x = (x);			\
		(__x < 0) ? -__x : __x;		\
	})
#define clamp(val, min, max) ({			\
	typeof(val) __val = (val);		\
	typeof(min) __min = (min);		\
	typeof(max) __max = (max);		\
	(void) (&__val == &__min);		\
	(void) (&__val == &__max);		\
	__val = __val < __min ? __min: __val;	\
	__val > __max ? __max: __val; })
#define clamp_t(type, val, min, max) ({		\
	type __val = (val);			\
	type __min = (min);			\
	type __max = (max);			\
	__val = __val < __min ? __min: __val;	\
	__val > __max ? __max: __val; })
#define clamp_val(val, min, max) ({		\
	typeof(val) __val = (val);		\
	typeof(val) __min = (min);		\
	typeof(val) __max = (max);		\
	__val = __val < __min ? __min: __val;	\
	__val > __max ? __max: __val; })
#define console_loglevel (console_printk[0])
#define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})
#define default_console_loglevel (console_printk[3])
#define default_message_loglevel (console_printk[1])
#define ftrace_vprintk(fmt, vargs)					\
do {									\
	if (__builtin_constant_p(fmt)) {				\
		static const char *trace_printk_fmt			\
		  __attribute__((section("__trace_printk_fmt"))) =	\
			__builtin_constant_p(fmt) ? fmt : NULL;		\
									\
		__ftrace_vbprintk(_THIS_IP_, trace_printk_fmt, vargs);	\
	} else								\
		__ftrace_vprintk(_THIS_IP_, fmt, vargs);		\
} while (0)
#define hex_asc_hi(x)	hex_asc[((x) & 0xf0) >> 4]
#define hex_asc_lo(x)	hex_asc[((x) & 0x0f)]
#define lower_32_bits(n) ((u32)(n))
#define max(x, y) ({				\
	typeof(x) _max1 = (x);			\
	typeof(y) _max2 = (y);			\
	(void) (&_max1 == &_max2);		\
	_max1 > _max2 ? _max1 : _max2; })
#define max_t(type, x, y) ({			\
	type __max1 = (x);			\
	type __max2 = (y);			\
	__max1 > __max2 ? __max1: __max2; })
# define might_resched() _cond_resched()
# define might_sleep() \
	do { __might_sleep("__FILE__", "__LINE__", 0); might_resched(); } while (0)
#define might_sleep_if(cond) do { if (cond) might_sleep(); } while (0)
#define min(x, y) ({				\
	typeof(x) _min1 = (x);			\
	typeof(y) _min2 = (y);			\
	(void) (&_min1 == &_min2);		\
	_min1 < _min2 ? _min1 : _min2; })
#define min_t(type, x, y) ({			\
	type __min1 = (x);			\
	type __min2 = (y);			\
	__min1 < __min2 ? __min1: __min2; })
#define minimum_console_loglevel (console_printk[2])
#define pr_alert(fmt, ...) \
        printk(KERN_ALERT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_alert_ratelimited(fmt, ...) \
	printk_ratelimited(KERN_ALERT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_cont(fmt, ...) \
	printk(KERN_CONT fmt, ##__VA_ARGS__)
#define pr_crit(fmt, ...) \
        printk(KERN_CRIT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_crit_ratelimited(fmt, ...) \
	printk_ratelimited(KERN_CRIT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_debug(fmt, ...) \
	printk(KERN_DEBUG pr_fmt(fmt), ##__VA_ARGS__)
#define pr_debug_ratelimited(fmt, ...) \
	printk_ratelimited(KERN_DEBUG pr_fmt(fmt), ##__VA_ARGS__)
#define pr_devel(fmt, ...) \
	printk(KERN_DEBUG pr_fmt(fmt), ##__VA_ARGS__)
#define pr_emerg(fmt, ...) \
        printk(KERN_EMERG pr_fmt(fmt), ##__VA_ARGS__)
#define pr_emerg_ratelimited(fmt, ...) \
	printk_ratelimited(KERN_EMERG pr_fmt(fmt), ##__VA_ARGS__)
#define pr_err(fmt, ...) \
        printk(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)
#define pr_err_ratelimited(fmt, ...) \
	printk_ratelimited(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)
#define pr_fmt(fmt) fmt
#define pr_info(fmt, ...) \
        printk(KERN_INFO pr_fmt(fmt), ##__VA_ARGS__)
#define pr_info_ratelimited(fmt, ...) \
	printk_ratelimited(KERN_INFO pr_fmt(fmt), ##__VA_ARGS__)
#define pr_notice(fmt, ...) \
        printk(KERN_NOTICE pr_fmt(fmt), ##__VA_ARGS__)
#define pr_notice_ratelimited(fmt, ...) \
	printk_ratelimited(KERN_NOTICE pr_fmt(fmt), ##__VA_ARGS__)
#define pr_warn pr_warning
#define pr_warn_ratelimited pr_warning_ratelimited
#define pr_warning(fmt, ...) \
        printk(KERN_WARNING pr_fmt(fmt), ##__VA_ARGS__)
#define pr_warning_ratelimited(fmt, ...) \
	printk_ratelimited(KERN_WARNING pr_fmt(fmt), ##__VA_ARGS__)
#define printk_once(x...) ({			\
	static bool __print_once;		\
						\
	if (!__print_once) {			\
		__print_once = true;		\
		printk(x);			\
	}					\
})
#define printk_ratelimit() __printk_ratelimit(__func__)
#define printk_ratelimited printk
#define round_down(x, y) ((x) & ~__round_mask(x, y))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)
#define roundup(x, y) ((((x) + ((y) - 1)) / (y)) * (y))
# define sector_div(a, b) do_div(a, b)
#define swap(a, b) \
	do { typeof(a) __tmp = (a); (a) = (b); (b) = __tmp; } while (0)
#define trace_printk(fmt, args...)					\
do {									\
	__trace_printk_check_format(fmt, ##args);			\
	if (__builtin_constant_p(fmt)) {				\
		static const char *trace_printk_fmt			\
		  __attribute__((section("__trace_printk_fmt"))) =	\
			__builtin_constant_p(fmt) ? fmt : NULL;		\
									\
		__trace_bprintk(_THIS_IP_, trace_printk_fmt, ##args);	\
	} else								\
		__trace_printk(_THIS_IP_, fmt, ##args);		\
} while (0)
#define upper_32_bits(n) ((u32)(((n) >> 16) >> 16))
#define _DPRINTK_FLAGS_DEFAULT 0
#define _DPRINTK_FLAGS_PRINT   (1<<0)  

#define __dynamic_dbg_enabled(dd)  ({	     \
	int __ret = 0;							     \
	if (unlikely((dynamic_debug_enabled & (1LL << DEBUG_HASH)) &&	     \
			(dynamic_debug_enabled2 & (1LL << DEBUG_HASH2))))   \
				if (unlikely(dd.flags))			     \
					__ret = 1;			     \
	__ret; })
#define dynamic_dev_dbg(dev, fmt, ...) do {				\
	static struct _ddebug descriptor				\
	__used								\
	__attribute__((section("__verbose"), aligned(8))) =		\
	{ KBUILD_MODNAME, __func__, "__FILE__", fmt, DEBUG_HASH,	\
		DEBUG_HASH2, "__LINE__", _DPRINTK_FLAGS_DEFAULT };	\
	if (__dynamic_dbg_enabled(descriptor))				\
		dev_printk(KERN_DEBUG, dev, fmt, ##__VA_ARGS__);	\
	} while (0)
#define dynamic_pr_debug(fmt, ...) do {					\
	static struct _ddebug descriptor				\
	__used								\
	__attribute__((section("__verbose"), aligned(8))) =		\
	{ KBUILD_MODNAME, __func__, "__FILE__", fmt, DEBUG_HASH,	\
		DEBUG_HASH2, "__LINE__", _DPRINTK_FLAGS_DEFAULT };	\
	if (__dynamic_dbg_enabled(descriptor))				\
		printk(KERN_DEBUG pr_fmt(fmt),	##__VA_ARGS__);		\
	} while (0)

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
		(n) < 1 ? ____ilog2_NaN() :	\
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
		(n) & (1ULL <<  1) ?  1 :	\
		(n) & (1ULL <<  0) ?  0 :	\
		____ilog2_NaN()			\
				   ) :		\
	(sizeof(n) <= 4) ?			\
	__ilog2_u32(n) :			\
	__ilog2_u64(n)				\
 )
#define order_base_2(n) ilog2(roundup_pow_of_two(n))
#define rounddown_pow_of_two(n)			\
(						\
	__builtin_constant_p(n) ? (		\
		(n == 1) ? 0 :			\
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
#define BIT_WORD(nr)		((nr) / BITS_PER_LONG)

#define for_each_set_bit(bit, addr, size) \
	for ((bit) = find_first_bit((addr), (size)); \
	     (bit) < (size); \
	     (bit) = find_next_bit((addr), (size), (bit) + 1))
#define DECLARE_BITMAP(name,bits) \
	unsigned long name[BITS_TO_LONGS(bits)]








#define __aligned_be64 __be64 __attribute__((aligned(8)))
#define __aligned_le64 __le64 __attribute__((aligned(8)))
#define __aligned_u64 __u64 __attribute__((aligned(8)))
#define __bitwise __bitwise__
#define __bitwise__ __attribute__((bitwise))
#define aligned_be64 __be64 __attribute__((aligned(8)))
#define aligned_le64 __le64 __attribute__((aligned(8)))
#define aligned_u64 __u64 __attribute__((aligned(8)))
#define pgoff_t unsigned long

#define NULL ((void *)0)

#define offsetof(TYPE,MEMBER) __compiler_offsetof(TYPE,MEMBER)
#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))
# define RELOC_HIDE(ptr, off)					\
  ({ unsigned long __ptr;					\
     __ptr = (unsigned long) (ptr);				\
    (typeof(ptr)) (__ptr + (off)); })

# define __acquire(x)	__context__(x,1)
# define __acquires(x)	__attribute__((context(x,0,1)))
#define __always_inline inline
#define __branch_check__(x, expect) ({					\
			int ______r;					\
			static struct ftrace_branch_data		\
				__attribute__((__aligned__(4)))		\
				__attribute__((section("_ftrace_annotated_branch"))) \
				______f = {				\
				.func = __func__,			\
				.file = "__FILE__",			\
				.line = "__LINE__",			\
			};						\
			______r = likely_notrace(x);			\
			ftrace_likely_update(&______f, ______r, expect); \
			______r;					\
		})
# define __builtin_warning(x, y...) (1)
# define __chk_io_ptr(x) (void)0
# define __chk_user_ptr(x) (void)0

# define __compiletime_error(message)
# define __compiletime_object_size(obj) -1
# define __compiletime_warning(message)
# define __cond_lock(x,c)	((c) ? ({ __acquire(x); 1; }) : 0)

#define __deprecated_for_modules __deprecated
# define __force
# define __iomem
# define __kernel

# define __nocast
# define __percpu
# define __rcu
# define __release(x)	__context__(x,-1)
# define __releases(x)	__attribute__((context(x,1,0)))
# define __safe
# define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
# define __section(S) __attribute__ ((__section__(#S)))
#define __trace_if(cond) \
	if (__builtin_constant_p((cond)) ? !!(cond) :			\
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
# define __user
# define barrier() __memory_barrier()
#define if(cond, ...) __trace_if( (cond , ## __VA_ARGS__) )
#  define likely(x)	(__builtin_constant_p(x) ? !!(x) : __branch_check__(x, 1))
#define likely_notrace(x)	__builtin_expect(!!(x), 1)

#define noinline_for_stack noinline
#define notrace __attribute__((no_instrument_function))
#  define unlikely(x)	(__builtin_constant_p(x) ? !!(x) : __branch_check__(x, 0))
#define unlikely_notrace(x)	__builtin_expect(!!(x), 0)
# define unreachable() do { } while (1)
#define __aligned(x)			__attribute__((aligned(x)))
#define __gcc_header(x) #x
#define __must_be_array(a) BUILD_BUG_ON_ZERO(__same_type((a), &(a)[0]))
#define __printf(a,b)			__attribute__((format(printf,a,b)))
#define _gcc_header(x) __gcc_header(linux/compiler-gcc##x.h)
#define gcc_header(x) _gcc_header(x)
#define ALIGN_STR __ALIGN_STR
#define ATTRIB_NORET  __attribute__((noreturn))
#define CPP_ASMLINKAGE extern "C"
#define END(name) \
  .size name, .-name
#define ENDPROC(name) \
  .type name, @function; \
  END(name)
#define ENTRY(name) \
  .globl name; \
  ALIGN; \
  name:
#define NORET_AND     noreturn,
#define NORET_TYPE    
#define WEAK(name)	   \
	.weak name;	   \
	name:

#define asmlinkage CPP_ASMLINKAGE
# define asmlinkage_protect(n, ret, args...)	do { } while (0)
# define asmregparm

#define MIN_THREADS_LEFT_FOR_ROOT 4
#define PID_MAX_DEFAULT (CONFIG_BASE_SMALL ? 0x1000 : 0x8000)
#define PID_MAX_LIMIT (CONFIG_BASE_SMALL ? PAGE_SIZE * 8 : \
	(sizeof(long) > 4 ? 4 * 1024 * 1024 : PID_MAX_DEFAULT))


#define to_node(sys_device) container_of(sys_device, struct node, sysdev)
#define DECLARE_DELAYED_WORK(n, f)				\
	struct delayed_work n = __DELAYED_WORK_INITIALIZER(n, f)
#define DECLARE_WORK(n, f)					\
	struct work_struct n = __WORK_INITIALIZER(n, f)
#define INIT_DELAYED_WORK(_work, _func)				\
	do {							\
		INIT_WORK(&(_work)->work, (_func));		\
		init_timer(&(_work)->timer);			\
	} while (0)
#define INIT_DELAYED_WORK_DEFERRABLE(_work, _func)		\
	do {							\
		INIT_WORK(&(_work)->work, (_func));		\
		init_timer_deferrable(&(_work)->timer);		\
	} while (0)
#define INIT_DELAYED_WORK_ON_STACK(_work, _func)		\
	do {							\
		INIT_WORK_ON_STACK(&(_work)->work, (_func));	\
		init_timer_on_stack(&(_work)->timer);		\
	} while (0)
#define INIT_WORK(_work, _func)					\
	do {							\
		__INIT_WORK((_work), (_func), 0);		\
	} while (0)
#define INIT_WORK_ON_STACK(_work, _func)			\
	do {							\
		__INIT_WORK((_work), (_func), 1);		\
	} while (0)
#define PREPARE_DELAYED_WORK(_work, _func)			\
	PREPARE_WORK(&(_work)->work, (_func))
#define PREPARE_WORK(_work, _func)				\
	do {							\
		(_work)->func = (_func);			\
	} while (0)
#define WORK_DATA_INIT()	ATOMIC_LONG_INIT(WORK_STRUCT_NO_CPU)
#define WORK_DATA_STATIC_INIT()	\
	ATOMIC_LONG_INIT(WORK_STRUCT_NO_CPU | WORK_STRUCT_STATIC)

#define __DELAYED_WORK_INITIALIZER(n, f) {			\
	.work = __WORK_INITIALIZER((n).work, (f)),		\
	.timer = TIMER_INITIALIZER(NULL, 0, 0),			\
	}
#define __INIT_WORK(_work, _func, _onstack)				\
	do {								\
		static struct lock_class_key __key;			\
									\
		__init_work((_work), _onstack);				\
		(_work)->data = (atomic_long_t) WORK_DATA_INIT();	\
		lockdep_init_map(&(_work)->lockdep_map, #_work, &__key, 0);\
		INIT_LIST_HEAD(&(_work)->entry);			\
		PREPARE_WORK((_work), (_func));				\
	} while (0)
#define __WORK_INITIALIZER(n, f) {				\
	.data = WORK_DATA_STATIC_INIT(),			\
	.entry	= { &(n).entry, &(n).entry },			\
	.func = (f),						\
	__WORK_INIT_LOCKDEP_MAP(#n, &(n))			\
	}
#define __WORK_INIT_LOCKDEP_MAP(n, k) \
	.lockdep_map = STATIC_LOCKDEP_MAP_INIT(n, k),
#define alloc_workqueue(name, flags, max_active)		\
({								\
	static struct lock_class_key __key;			\
	const char *__lock_name;				\
								\
	if (__builtin_constant_p(name))				\
		__lock_name = (name);				\
	else							\
		__lock_name = #name;				\
								\
	__alloc_workqueue_key((name), (flags), (max_active),	\
			      &__key, __lock_name);		\
})
#define create_freezeable_workqueue(name)			\
	alloc_workqueue((name), WQ_FREEZEABLE | WQ_UNBOUND | WQ_RESCUER, 1)
#define create_singlethread_workqueue(name)			\
	alloc_workqueue((name), WQ_UNBOUND | WQ_RESCUER, 1)
#define create_workqueue(name)					\
	alloc_workqueue((name), WQ_RESCUER, 1)
#define delayed_work_pending(w) \
	work_pending(&(w)->work)
#define work_clear_pending(work) \
	clear_bit(WORK_STRUCT_PENDING_BIT, work_data_bits(work))
#define work_data_bits(work) ((unsigned long *)(&(work)->data))
#define work_pending(work) \
	test_bit(WORK_STRUCT_PENDING_BIT, work_data_bits(work))
# define INIT_LOCKDEP
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
#define STATIC_LOCKDEP_MAP_INIT(_name, _key) \
	{ .name = (_name), .key = (void *)(_key), }

# define lock_acquire(l, s, t, r, c, n, i)	do { } while (0)
#define lock_acquired(lockdep_map, ip) do {} while (0)
#define lock_contended(lockdep_map, ip) do {} while (0)
#  define lock_map_acquire(l)		lock_acquire(l, 0, 0, 0, 2, NULL, _THIS_IP_)
# define lock_map_release(l)			lock_release(l, 1, _THIS_IP_)
# define lock_release(l, n, i)			do { } while (0)
# define lock_set_class(l, n, k, s, i)		do { } while (0)
# define lock_set_subclass(l, s, i)		do { } while (0)
#define lockdep_assert_held(l)	WARN_ON(debug_locks && !lockdep_is_held(l))
# define lockdep_clear_current_reclaim_state()	do { } while (0)
#define lockdep_depth(tsk)	(debug_locks ? (tsk)->lockdep_depth : 0)
# define lockdep_free_key_range(start, size)	do { } while (0)
# define lockdep_info()				do { } while (0)
# define lockdep_init()				do { } while (0)
# define lockdep_init_map(lock, name, key, sub) \
		do { (void)(name); (void)(key); } while (0)
#define lockdep_is_held(lock)	lock_is_held(&(lock)->dep_map)
#define lockdep_match_class(lock, key) lockdep_match_key(&(lock)->dep_map, key)
# define lockdep_reset()		do { debug_locks = 1; } while (0)
# define lockdep_set_class(lock, key)		do { (void)(key); } while (0)
# define lockdep_set_class_and_name(lock, key, name) \
		do { (void)(key); (void)(name); } while (0)
#define lockdep_set_class_and_subclass(lock, key, sub) \
		lockdep_init_map(&(lock)->dep_map, #key, key, sub)
# define lockdep_set_current_reclaim_state(g)	do { } while (0)
#define lockdep_set_novalidate_class(lock) \
	lockdep_set_class(lock, &__lockdep_no_validate__)
#define lockdep_set_subclass(lock, sub)	\
		lockdep_init_map(&(lock)->dep_map, #lock, \
				 (lock)->dep_map.key, sub)
# define lockdep_sys_exit() 			do { } while (0)
# define lockdep_trace_alloc(g)			do { } while (0)
# define might_lock(lock) 						\
do {									\
	typecheck(struct lockdep_map *, &(lock)->dep_map);		\
	lock_acquire(&(lock)->dep_map, 0, 0, 0, 2, NULL, _THIS_IP_);	\
	lock_release(&(lock)->dep_map, 0, _THIS_IP_);			\
} while (0)
# define might_lock_read(lock) 						\
do {									\
	typecheck(struct lockdep_map *, &(lock)->dep_map);		\
	lock_acquire(&(lock)->dep_map, 0, 0, 1, 2, NULL, _THIS_IP_);	\
	lock_release(&(lock)->dep_map, 0, _THIS_IP_);			\
} while (0)
#  define mutex_acquire(l, s, t, i)		lock_acquire(l, s, t, 0, 2, NULL, i)
# define mutex_release(l, n, i)			lock_release(l, n, i)
#  define rwlock_acquire(l, s, t, i)		lock_acquire(l, s, t, 0, 2, NULL, i)
#  define rwlock_acquire_read(l, s, t, i)	lock_acquire(l, s, t, 2, 2, NULL, i)
# define rwlock_release(l, n, i)		lock_release(l, n, i)
#  define rwsem_acquire(l, s, t, i)		lock_acquire(l, s, t, 0, 2, NULL, i)
#  define rwsem_acquire_read(l, s, t, i)	lock_acquire(l, s, t, 1, 2, NULL, i)
# define rwsem_release(l, n, i)			lock_release(l, n, i)
#  define spin_acquire(l, s, t, i)		lock_acquire(l, s, t, 0, 2, NULL, i)
#  define spin_acquire_nest(l, s, t, n, i)	lock_acquire(l, s, t, 0, 2, n, i)
# define spin_release(l, n, i)			lock_release(l, n, i)

# define print_stack_trace(trace, spaces)		do { } while (0)
# define save_stack_trace(trace)			do { } while (0)
# define save_stack_trace_tsk(tsk, trace)		do { } while (0)
# define save_stack_trace_user(trace)              do { } while (0)
#define DEBUG_LOCKS_WARN_ON(c)						\
({									\
	int __ret = 0;							\
									\
	if (!oops_in_progress && unlikely(c)) {				\
		if (debug_locks_off() && !debug_locks_silent)		\
			WARN_ON(1);					\
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
#define hlist_for_each_entry_safe(tpos, pos, n, head, member) 		 \
	for (pos = (head)->first;					 \
	     pos && ({ n = pos->next; 1; }) && 				 \
		({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = n)
#define hlist_for_each_safe(pos, n, head) \
	for (pos = (head)->first; pos && ({ n = pos->next; 1; }); \
	     pos = n)
#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)
#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)
#define list_for_each(pos, head) \
	for (pos = (head)->next; prefetch(pos->next), pos != (head); \
        	pos = pos->next)
#define list_for_each_entry(pos, head, member)				\
	for (pos = list_entry((head)->next, typeof(*pos), member);	\
	     prefetch(pos->member.next), &pos->member != (head); 	\
	     pos = list_entry(pos->member.next, typeof(*pos), member))
#define list_for_each_entry_continue(pos, head, member) 		\
	for (pos = list_entry(pos->member.next, typeof(*pos), member);	\
	     prefetch(pos->member.next), &pos->member != (head);	\
	     pos = list_entry(pos->member.next, typeof(*pos), member))
#define list_for_each_entry_continue_reverse(pos, head, member)		\
	for (pos = list_entry(pos->member.prev, typeof(*pos), member);	\
	     prefetch(pos->member.prev), &pos->member != (head);	\
	     pos = list_entry(pos->member.prev, typeof(*pos), member))
#define list_for_each_entry_from(pos, head, member) 			\
	for (; prefetch(pos->member.next), &pos->member != (head);	\
	     pos = list_entry(pos->member.next, typeof(*pos), member))
#define list_for_each_entry_reverse(pos, head, member)			\
	for (pos = list_entry((head)->prev, typeof(*pos), member);	\
	     prefetch(pos->member.prev), &pos->member != (head); 	\
	     pos = list_entry(pos->member.prev, typeof(*pos), member))
#define list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = list_entry((head)->next, typeof(*pos), member),	\
		n = list_entry(pos->member.next, typeof(*pos), member);	\
	     &pos->member != (head); 					\
	     pos = n, n = list_entry(n->member.next, typeof(*n), member))
#define list_for_each_entry_safe_continue(pos, n, head, member) 		\
	for (pos = list_entry(pos->member.next, typeof(*pos), member), 		\
		n = list_entry(pos->member.next, typeof(*pos), member);		\
	     &pos->member != (head);						\
	     pos = n, n = list_entry(n->member.next, typeof(*n), member))
#define list_for_each_entry_safe_from(pos, n, head, member) 			\
	for (n = list_entry(pos->member.next, typeof(*pos), member);		\
	     &pos->member != (head);						\
	     pos = n, n = list_entry(n->member.next, typeof(*n), member))
#define list_for_each_entry_safe_reverse(pos, n, head, member)		\
	for (pos = list_entry((head)->prev, typeof(*pos), member),	\
		n = list_entry(pos->member.prev, typeof(*pos), member);	\
	     &pos->member != (head); 					\
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
#define list_prepare_entry(pos, head, member) \
	((pos) ? : list_entry(head, typeof(*pos), member))
#define list_safe_reset_next(pos, n, member)				\
	n = list_entry(pos->member.next, typeof(*pos), member)
#define PREFETCH_STRIDE (4*L1_CACHE_BYTES)

#define prefetch(x) __builtin_prefetch(x)
#define prefetchw(x) __builtin_prefetch(x,1)
#define spin_lock_prefetch(x) prefetchw(x)
#define LIST_POISON1  ((void *) 0x00100100 + POISON_POINTER_DELTA)
#define LIST_POISON2  ((void *) 0x00200200 + POISON_POINTER_DELTA)
#define PAGE_POISON 0xaa
# define POISON_POINTER_DELTA _AC(CONFIG_ILLEGAL_POINTER_VALUE, UL)

#define DEFINE_TIMER(_name, _function, _expires, _data)		\
	struct timer_list _name =				\
		TIMER_INITIALIZER(_function, _expires, _data)
#define TIMER_INITIALIZER(_function, _expires, _data) {		\
		.entry = { .prev = TIMER_ENTRY_STATIC },	\
		.function = (_function),			\
		.expires = (_expires),				\
		.data = (_data),				\
		.base = &boot_tvec_bases,			\
		__TIMER_LOCKDEP_MAP_INITIALIZER(		\
			"__FILE__" ":" __stringify("__LINE__"))	\
	}

#define __TIMER_LOCKDEP_MAP_INITIALIZER(_kn)				\
	.lockdep_map = STATIC_LOCKDEP_MAP_INIT(_kn, &_kn),
#define del_singleshot_timer_sync(t) del_timer_sync(t)
# define del_timer_sync(t)		del_timer(t)
#define init_timer(timer)\
	init_timer_key((timer), NULL, NULL)
#define init_timer_deferrable(timer)\
	init_timer_deferrable_key((timer), NULL, NULL)
#define init_timer_on_stack(timer)\
	init_timer_on_stack_key((timer), NULL, NULL)
#define setup_deferrable_timer_on_stack(timer, fn, data)		\
	do {								\
		static struct lock_class_key __key;			\
		setup_deferrable_timer_on_stack_key((timer), #timer,	\
						    &__key, (fn),	\
						    (data));		\
	} while (0)
#define setup_timer(timer, fn, data)\
	setup_timer_key((timer), NULL, NULL, (fn), (data))
#define setup_timer_on_stack(timer, fn, data)\
	setup_timer_on_stack_key((timer), NULL, NULL, (fn), (data))
# define try_to_del_timer_sync(t)	del_timer(t)

#define __stringify(x...)	__stringify_1(x)
#define __stringify_1(x...)	#x

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
#define atomic_dec_and_lock(atomic, lock) \
		__cond_lock(lock, _atomic_dec_and_lock(atomic, lock))
#define do_raw_spin_lock_flags(lock, flags) do_raw_spin_lock(lock)
#define raw_spin_can_lock(lock)	(!raw_spin_is_locked(lock))
#define raw_spin_is_contended(lock) ((lock)->break_lock)
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
#define raw_spin_unlock_wait(lock)	arch_spin_unlock_wait(&(lock)->raw_lock)
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
#define read_can_lock(rwlock)		arch_read_can_lock(&(rwlock)->raw_lock)
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
#define write_can_lock(rwlock)		arch_write_can_lock(&(rwlock)->raw_lock)
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


#define clear_need_resched()	clear_thread_flag(TIF_NEED_RESCHED)
#define clear_thread_flag(flag) \
	clear_ti_thread_flag(current_thread_info(), flag)
#define set_need_resched()	set_thread_flag(TIF_NEED_RESCHED)
#define set_thread_flag(flag) \
	set_ti_thread_flag(current_thread_info(), flag)
#define test_and_clear_thread_flag(flag) \
	test_and_clear_ti_thread_flag(current_thread_info(), flag)
#define test_and_set_thread_flag(flag) \
	test_and_set_ti_thread_flag(current_thread_info(), flag)
#define test_thread_flag(flag) \
	test_ti_thread_flag(current_thread_info(), flag)

# define add_preempt_count(val)	do { preempt_count() += (val); } while (0)
#define add_preempt_count_notrace(val)			\
	do { preempt_count() += (val); } while (0)
#define dec_preempt_count() sub_preempt_count(1)
#define dec_preempt_count_notrace() sub_preempt_count_notrace(1)
#define inc_preempt_count() add_preempt_count(1)
#define inc_preempt_count_notrace() add_preempt_count_notrace(1)
#define preempt_check_resched() \
do { \
	if (unlikely(test_thread_flag(TIF_NEED_RESCHED))) \
		preempt_schedule(); \
} while (0)
#define preempt_count()	(current_thread_info()->preempt_count)
#define preempt_disable() \
do { \
	inc_preempt_count(); \
	barrier(); \
} while (0)
#define preempt_disable_notrace() \
do { \
	inc_preempt_count_notrace(); \
	barrier(); \
} while (0)
#define preempt_enable() \
do { \
	preempt_enable_no_resched(); \
	barrier(); \
	preempt_check_resched(); \
} while (0)
#define preempt_enable_no_resched() \
do { \
	barrier(); \
	dec_preempt_count(); \
} while (0)
#define preempt_enable_no_resched_notrace() \
do { \
	barrier(); \
	dec_preempt_count_notrace(); \
} while (0)
#define preempt_enable_notrace() \
do { \
	preempt_enable_no_resched_notrace(); \
	barrier(); \
	preempt_check_resched(); \
} while (0)
# define sub_preempt_count(val)	do { preempt_count() -= (val); } while (0)
#define sub_preempt_count_notrace(val)			\
	do { preempt_count() -= (val); } while (0)

#define ktime_add(lhs, rhs) \
		({ (ktime_t){ .tv64 = (lhs).tv64 + (rhs).tv64 }; })
#define ktime_add_ns(kt, nsval) \
		({ (ktime_t){ .tv64 = (kt).tv64 + (nsval) }; })
#define ktime_get_real_ts(ts)	getnstimeofday(ts)
#define ktime_sub(lhs, rhs) \
		({ (ktime_t){ .tv64 = (lhs).tv64 - (rhs).tv64 }; })
#define ktime_sub_ns(kt, nsval) \
		({ (ktime_t){ .tv64 = (kt).tv64 - (nsval) }; })
#define ktime_to_ns(kt)			((kt).tv64)
#define ktime_to_timespec(kt)		ns_to_timespec((kt).tv64)
#define ktime_to_timeval(kt)		ns_to_timeval((kt).tv64)
#define ACTHZ (SH_DIV (CLOCK_TICK_RATE, LATCH, 8))
#define INITIAL_JIFFIES ((unsigned long)(unsigned int) (-300*HZ))
#define LATCH  ((CLOCK_TICK_RATE + HZ/2) / HZ)	
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
#define TICK_NSEC (SH_DIV (1000000UL * 1000, ACTHZ, 8))
#define TICK_USEC ((1000000UL + USER_HZ/2) / USER_HZ)
#define TICK_USEC_TO_NSEC(TUSEC) (SH_DIV (TUSEC * USER_HZ * 1000, ACTHZ, 8))
#define USEC_CONVERSION  \
                    ((unsigned long)((((u64)NSEC_PER_USEC << USEC_JIFFIE_SC) +\
                                        TICK_NSEC -1) / (u64)TICK_NSEC))
#define USEC_JIFFIE_SC (SEC_JIFFIE_SC + 19)
#define USEC_ROUND (u64)(((u64)1 << USEC_JIFFIE_SC) - 1)

#define __jiffy_data  __attribute__((section(".data")))
#define time_after(a,b)		\
	(typecheck(unsigned long, a) && \
	 typecheck(unsigned long, b) && \
	 ((long)(b) - (long)(a) < 0))
#define time_after64(a,b)	\
	(typecheck(__u64, a) &&	\
	 typecheck(__u64, b) && \
	 ((__s64)(b) - (__s64)(a) < 0))
#define time_after_eq(a,b)	\
	(typecheck(unsigned long, a) && \
	 typecheck(unsigned long, b) && \
	 ((long)(a) - (long)(b) >= 0))
#define time_after_eq64(a,b)	\
	(typecheck(__u64, a) && \
	 typecheck(__u64, b) && \
	 ((__s64)(a) - (__s64)(b) >= 0))
#define time_before(a,b)	time_after(b,a)
#define time_before64(a,b)	time_after64(b,a)
#define time_before_eq(a,b)	time_after_eq(b,a)
#define time_before_eq64(a,b)	time_after_eq64(b,a)
#define time_in_range(a,b,c) \
	(time_after_eq(a,b) && \
	 time_before_eq(a,c))
#define time_in_range_open(a,b,c) \
	(time_after_eq(a,b) && \
	 time_before(a,c))
#define time_is_after_eq_jiffies(a) time_before_eq(jiffies, a)
#define time_is_after_jiffies(a) time_before(jiffies, a)
#define time_is_before_eq_jiffies(a) time_after_eq(jiffies, a)
#define time_is_before_jiffies(a) time_after(jiffies, a)
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
#define STA_RONLY (STA_PPSSIGNAL | STA_PPSJITTER | STA_PPSWANDER | \
	STA_PPSERROR | STA_CLOCKERR | STA_NANO | STA_MODE | STA_CLK)

#define shift_right(x, s) ({	\
	__typeof__(x) __x = (x);	\
	__typeof__(s) __s = (s);	\
	__x < 0 ? -(-__x >> __s) : __x >> __s;	\
})

#define FD_CLR(fd,fdsetp)	__FD_CLR(fd,fdsetp)
#define FD_ISSET(fd,fdsetp)	__FD_ISSET(fd,fdsetp)
#define FD_SET(fd,fdsetp)	__FD_SET(fd,fdsetp)
#define FD_ZERO(fdsetp)		__FD_ZERO(fdsetp)


#define do_posix_clock_monotonic_gettime(ts) ktime_get_ts(ts)
#define timespec_valid(ts) \
	(((ts)->tv_sec >= 0) && (((unsigned long) (ts)->tv_nsec) < NSEC_PER_SEC))

#define SYSDEV_ATTR(_name, _mode, _show, _store)		\
	struct sysdev_attribute attr_##_name =			\
		_SYSDEV_ATTR(_name, _mode, _show, _store);
#define SYSDEV_CLASS_ATTR(_name,_mode,_show,_store) 		\
	struct sysdev_class_attribute attr_##_name = 		\
		_SYSDEV_CLASS_ATTR(_name,_mode,_show,_store)
#define SYSDEV_INT_ATTR(_name, _mode, _var)			\
	struct sysdev_ext_attribute attr_##_name = 		\
		_SYSDEV_INT_ATTR(_name, _mode, _var);
#define SYSDEV_ULONG_ATTR(_name, _mode, _var)			\
	struct sysdev_ext_attribute attr_##_name = 		\
		_SYSDEV_ULONG_ATTR(_name, _mode, _var);
#define _SYSDEV_ATTR(_name, _mode, _show, _store)		\
{								\
	.attr = { .name = __stringify(_name), .mode = _mode },	\
	.show	= _show,					\
	.store	= _store,					\
}
#define _SYSDEV_CLASS_ATTR(_name,_mode,_show,_store) 		\
{					 			\
	.attr = {.name = __stringify(_name), .mode = _mode },	\
	.show	= _show,					\
	.store	= _store,					\
}

#define _SYSDEV_INT_ATTR(_name, _mode, _var)				\
	{ _SYSDEV_ATTR(_name, _mode, sysdev_show_int, sysdev_store_int), \
	  &(_var) }
#define _SYSDEV_ULONG_ATTR(_name, _mode, _var)				\
	{ _SYSDEV_ATTR(_name, _mode, sysdev_show_ulong, sysdev_store_ulong), \
	  &(_var) }
#define PM_EVENT_FREEZE 	0x0001
#define PM_EVENT_PRETHAW PM_EVENT_QUIESCE
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
	({ init_completion(&work); work; })
#define DECLARE_COMPLETION(work) \
	struct completion work = COMPLETION_INITIALIZER(work)
# define DECLARE_COMPLETION_ONSTACK(work) \
	struct completion work = COMPLETION_INITIALIZER_ONSTACK(work)
#define INIT_COMPLETION(x)	((x).done = 0)

#define DECLARE_WAITQUEUE(name, tsk)					\
	wait_queue_t name = __WAITQUEUE_INITIALIZER(name, tsk)
#define DECLARE_WAIT_QUEUE_HEAD(name) \
	wait_queue_head_t name = __WAIT_QUEUE_HEAD_INITIALIZER(name)
# define DECLARE_WAIT_QUEUE_HEAD_ONSTACK(name) \
	wait_queue_head_t name = __WAIT_QUEUE_HEAD_INIT_ONSTACK(name)
#define DEFINE_WAIT(name) DEFINE_WAIT_FUNC(name, autoremove_wake_function)
#define DEFINE_WAIT_BIT(name, word, bit)				\
	struct wait_bit_queue name = {					\
		.key = __WAIT_BIT_KEY_INITIALIZER(word, bit),		\
		.wait	= {						\
			.private	= current,			\
			.func		= wake_bit_function,		\
			.task_list	=				\
				LIST_HEAD_INIT((name).wait.task_list),	\
		},							\
	}
#define DEFINE_WAIT_FUNC(name, function)				\
	wait_queue_t name = {						\
		.private	= current,				\
		.func		= function,				\
		.task_list	= LIST_HEAD_INIT((name).task_list),	\
	}

#define __WAITQUEUE_INITIALIZER(name, tsk) {				\
	.private	= tsk,						\
	.func		= default_wake_function,			\
	.task_list	= { NULL, NULL } }
#define __WAIT_BIT_KEY_INITIALIZER(word, bit)				\
	{ .flags = word, .bit_nr = bit, }
#define __WAIT_QUEUE_HEAD_INITIALIZER(name) {				\
	.lock		= __SPIN_LOCK_UNLOCKED(name.lock),		\
	.task_list	= { &(name).task_list, &(name).task_list } }
# define __WAIT_QUEUE_HEAD_INIT_ONSTACK(name) \
	({ init_waitqueue_head(&name); name; })
#define __wait_event(wq, condition) 					\
do {									\
	DEFINE_WAIT(__wait);						\
									\
	for (;;) {							\
		prepare_to_wait(&wq, &__wait, TASK_UNINTERRUPTIBLE);	\
		if (condition)						\
			break;						\
		schedule();						\
	}								\
	finish_wait(&wq, &__wait);					\
} while (0)
#define __wait_event_interruptible(wq, condition, ret)			\
do {									\
	DEFINE_WAIT(__wait);						\
									\
	for (;;) {							\
		prepare_to_wait(&wq, &__wait, TASK_INTERRUPTIBLE);	\
		if (condition)						\
			break;						\
		if (!signal_pending(current)) {				\
			schedule();					\
			continue;					\
		}							\
		ret = -ERESTARTSYS;					\
		break;							\
	}								\
	finish_wait(&wq, &__wait);					\
} while (0)
#define __wait_event_interruptible_exclusive(wq, condition, ret)	\
do {									\
	DEFINE_WAIT(__wait);						\
									\
	for (;;) {							\
		prepare_to_wait_exclusive(&wq, &__wait,			\
					TASK_INTERRUPTIBLE);		\
		if (condition) {					\
			finish_wait(&wq, &__wait);			\
			break;						\
		}							\
		if (!signal_pending(current)) {				\
			schedule();					\
			continue;					\
		}							\
		ret = -ERESTARTSYS;					\
		abort_exclusive_wait(&wq, &__wait, 			\
				TASK_INTERRUPTIBLE, NULL);		\
		break;							\
	}								\
} while (0)
#define __wait_event_interruptible_locked(wq, condition, exclusive, irq) \
({									\
	int __ret = 0;							\
	DEFINE_WAIT(__wait);						\
	if (exclusive)							\
		__wait.flags |= WQ_FLAG_EXCLUSIVE;			\
	do {								\
		if (likely(list_empty(&__wait.task_list)))		\
			__add_wait_queue_tail(&(wq), &__wait);		\
		set_current_state(TASK_INTERRUPTIBLE);			\
		if (signal_pending(current)) {				\
			__ret = -ERESTARTSYS;				\
			break;						\
		}							\
		if (irq)						\
			spin_unlock_irq(&(wq).lock);			\
		else							\
			spin_unlock(&(wq).lock);			\
		schedule();						\
		if (irq)						\
			spin_lock_irq(&(wq).lock);			\
		else							\
			spin_lock(&(wq).lock);				\
	} while (!(condition));						\
	__remove_wait_queue(&(wq), &__wait);				\
	__set_current_state(TASK_RUNNING);				\
	__ret;								\
})
#define __wait_event_interruptible_timeout(wq, condition, ret)		\
do {									\
	DEFINE_WAIT(__wait);						\
									\
	for (;;) {							\
		prepare_to_wait(&wq, &__wait, TASK_INTERRUPTIBLE);	\
		if (condition)						\
			break;						\
		if (!signal_pending(current)) {				\
			ret = schedule_timeout(ret);			\
			if (!ret)					\
				break;					\
			continue;					\
		}							\
		ret = -ERESTARTSYS;					\
		break;							\
	}								\
	finish_wait(&wq, &__wait);					\
} while (0)
#define __wait_event_killable(wq, condition, ret)			\
do {									\
	DEFINE_WAIT(__wait);						\
									\
	for (;;) {							\
		prepare_to_wait(&wq, &__wait, TASK_KILLABLE);		\
		if (condition)						\
			break;						\
		if (!fatal_signal_pending(current)) {			\
			schedule();					\
			continue;					\
		}							\
		ret = -ERESTARTSYS;					\
		break;							\
	}								\
	finish_wait(&wq, &__wait);					\
} while (0)
#define __wait_event_timeout(wq, condition, ret)			\
do {									\
	DEFINE_WAIT(__wait);						\
									\
	for (;;) {							\
		prepare_to_wait(&wq, &__wait, TASK_UNINTERRUPTIBLE);	\
		if (condition)						\
			break;						\
		ret = schedule_timeout(ret);				\
		if (!ret)						\
			break;						\
	}								\
	finish_wait(&wq, &__wait);					\
} while (0)
#define init_wait(wait)							\
	do {								\
		(wait)->private = current;				\
		(wait)->func = autoremove_wake_function;		\
		INIT_LIST_HEAD(&(wait)->task_list);			\
		(wait)->flags = 0;					\
	} while (0)
#define init_waitqueue_head(q)				\
	do {						\
		static struct lock_class_key __key;	\
							\
		__init_waitqueue_head((q), &__key);	\
	} while (0)
#define wait_event(wq, condition) 					\
do {									\
	if (condition)	 						\
		break;							\
	__wait_event(wq, condition);					\
} while (0)
#define wait_event_interruptible(wq, condition)				\
({									\
	int __ret = 0;							\
	if (!(condition))						\
		__wait_event_interruptible(wq, condition, __ret);	\
	__ret;								\
})
#define wait_event_interruptible_exclusive(wq, condition)		\
({									\
	int __ret = 0;							\
	if (!(condition))						\
		__wait_event_interruptible_exclusive(wq, condition, __ret);\
	__ret;								\
})
#define wait_event_interruptible_exclusive_locked(wq, condition)	\
	((condition)							\
	 ? 0 : __wait_event_interruptible_locked(wq, condition, 1, 0))
#define wait_event_interruptible_exclusive_locked_irq(wq, condition)	\
	((condition)							\
	 ? 0 : __wait_event_interruptible_locked(wq, condition, 1, 1))
#define wait_event_interruptible_locked(wq, condition)			\
	((condition)							\
	 ? 0 : __wait_event_interruptible_locked(wq, condition, 0, 0))
#define wait_event_interruptible_locked_irq(wq, condition)		\
	((condition)							\
	 ? 0 : __wait_event_interruptible_locked(wq, condition, 0, 1))
#define wait_event_interruptible_timeout(wq, condition, timeout)	\
({									\
	long __ret = timeout;						\
	if (!(condition))						\
		__wait_event_interruptible_timeout(wq, condition, __ret); \
	__ret;								\
})
#define wait_event_killable(wq, condition)				\
({									\
	int __ret = 0;							\
	if (!(condition))						\
		__wait_event_killable(wq, condition, __ret);		\
	__ret;								\
})
#define wait_event_timeout(wq, condition, timeout)			\
({									\
	long __ret = timeout;						\
	if (!(condition)) 						\
		__wait_event_timeout(wq, condition, __ret);		\
	__ret;								\
})
#define wake_up(x)			__wake_up(x, TASK_NORMAL, 1, NULL)
#define wake_up_all(x)			__wake_up(x, TASK_NORMAL, 0, NULL)
#define wake_up_interruptible(x)	__wake_up(x, TASK_INTERRUPTIBLE, 1, NULL)
#define wake_up_interruptible_all(x)	__wake_up(x, TASK_INTERRUPTIBLE, 0, NULL)
#define wake_up_interruptible_nr(x, nr)	__wake_up(x, TASK_INTERRUPTIBLE, nr, NULL)
#define wake_up_interruptible_poll(x, m)			\
	__wake_up(x, TASK_INTERRUPTIBLE, 1, (void *) (m))
#define wake_up_interruptible_sync(x)	__wake_up_sync((x), TASK_INTERRUPTIBLE, 1)
#define wake_up_interruptible_sync_poll(x, m)				\
	__wake_up_sync_key((x), TASK_INTERRUPTIBLE, 1, (void *) (m))
#define wake_up_locked(x)		__wake_up_locked((x), TASK_NORMAL)
#define wake_up_locked_poll(x, m)				\
	__wake_up_locked_key((x), TASK_NORMAL, (void *) (m))
#define wake_up_nr(x, nr)		__wake_up(x, TASK_NORMAL, nr, NULL)
#define wake_up_poll(x, m)				\
	__wake_up(x, TASK_NORMAL, 1, (void *) (m))
#define EXPORT_SYMBOL(sym)					\
	__EXPORT_SYMBOL(sym, "")
#define EXPORT_SYMBOL_GPL(sym)					\
	__EXPORT_SYMBOL(sym, "_gpl")
#define EXPORT_SYMBOL_GPL_FUTURE(sym)				\
	__EXPORT_SYMBOL(sym, "_gpl_future")
#define EXPORT_UNUSED_SYMBOL(sym) __EXPORT_SYMBOL(sym, "_unused")
#define EXPORT_UNUSED_SYMBOL_GPL(sym) __EXPORT_SYMBOL(sym, "_unused_gpl")
#define MODULE_ALIAS(_alias) MODULE_INFO(alias, _alias)
#define MODULE_ARCH_INIT {}
#define MODULE_AUTHOR(_author) MODULE_INFO(author, _author)
#define MODULE_DESCRIPTION(_description) MODULE_INFO(description, _description)
#define MODULE_DEVICE_TABLE(type,name)		\
  MODULE_GENERIC_TABLE(type##_device,name)
#define MODULE_FIRMWARE(_firmware) MODULE_INFO(firmware, _firmware)
#define MODULE_GENERIC_TABLE(gtype,name)			\
extern const struct gtype##_id __mod_##gtype##_table		\
  __attribute__ ((unused, alias(__stringify(name))))
#define MODULE_INFO(tag, info) __MODULE_INFO(tag, tag, info)
#define MODULE_LICENSE(_license) MODULE_INFO(license, _license)
#define MODULE_NAME_LEN MAX_PARAM_PREFIX_LEN
#define MODULE_PARM_DESC(_parm, desc) \
	__MODULE_INFO(parm, _parm, #_parm ":" desc)

#define MODULE_SYMBOL_PREFIX CONFIG_SYMBOL_PREFIX
#define MODULE_VERSION(_version) MODULE_INFO(version, _version)
#define THIS_MODULE (&__this_module)

#define __CRC_SYMBOL(sym, sec)					\
	extern void *__crc_##sym __attribute__((weak));		\
	static const unsigned long __kcrctab_##sym		\
	__used							\
	__attribute__((section("__kcrctab" sec), unused))	\
	= (unsigned long) &__crc_##sym;
#define __EXPORT_SYMBOL(sym, sec)				\
	extern typeof(sym) sym;					\
	__CRC_SYMBOL(sym, sec)					\
	static const char __kstrtab_##sym[]			\
	__attribute__((section("__ksymtab_strings"), aligned(1))) \
	= MODULE_SYMBOL_PREFIX #sym;                    	\
	static const struct kernel_symbol __ksymtab_##sym	\
	__used							\
	__attribute__((section("__ksymtab" sec), unused))	\
	= { (unsigned long)&sym, __kstrtab_##sym }
#define __MODULE_STRING(x) __stringify(x)
#define module_name(mod)			\
({						\
	struct module *__mod = (mod);		\
	__mod ? __mod->name : "kernel";		\
})
#define module_put_and_exit(code) __module_put_and_exit(THIS_MODULE, code);
#define symbol_get(x) ((typeof(&x))(__symbol_get(MODULE_SYMBOL_PREFIX #x)))
#define symbol_put(x) __symbol_put(MODULE_SYMBOL_PREFIX #x)
#define symbol_put_addr(p) do { } while(0)
#define symbol_request(x) try_then_request_module(symbol_get(x), "symbol:" #x)

#define show_module_flags(flags) __print_flags(flags, "",	\
	{ (1UL << TAINT_PROPRIETARY_MODULE),	"P" },		\
	{ (1UL << TAINT_FORCED_MODULE),		"F" },		\
	{ (1UL << TAINT_CRAP),			"C" })
#define DECLARE_TRACE_NOARGS(name)					\
		__DECLARE_TRACE(name, void, , void *__data, __data)
#define DEFINE_TRACE(name)						\
	DEFINE_TRACE_FN(name, NULL, NULL);
#define DEFINE_TRACE_FN(name, reg, unreg)				\
	static const char __tpstrtab_##name[]				\
	__attribute__((section("__tracepoints_strings"))) = #name;	\
	struct tracepoint __tracepoint_##name				\
	__attribute__((section("__tracepoints"), aligned(32))) =	\
		{ __tpstrtab_##name, 0, reg, unreg, NULL }
#define EXPORT_TRACEPOINT_SYMBOL(name)					\
	EXPORT_SYMBOL(__tracepoint_##name)
#define EXPORT_TRACEPOINT_SYMBOL_GPL(name)				\
	EXPORT_SYMBOL_GPL(__tracepoint_##name)
#define PARAMS(args...) args
#define TP_ARGS(args...)	args
#define TP_PROTO(args...)	args

#define __DECLARE_TRACE(name, proto, args, data_proto, data_args)	\
	extern struct tracepoint __tracepoint_##name;			\
	static inline void trace_##name(proto)				\
	{								\
		if (unlikely(__tracepoint_##name.state))		\
			__DO_TRACE(&__tracepoint_##name,		\
				TP_PROTO(data_proto),			\
				TP_ARGS(data_args));			\
	}								\
	static inline int						\
	register_trace_##name(void (*probe)(data_proto), void *data)	\
	{								\
		return tracepoint_probe_register(#name, (void *)probe,	\
						 data);			\
	}								\
	static inline int						\
	unregister_trace_##name(void (*probe)(data_proto), void *data)	\
	{								\
		return tracepoint_probe_unregister(#name, (void *)probe, \
						   data);		\
	}								\
	static inline void						\
	check_trace_callback_type_##name(void (*cb)(data_proto))	\
	{								\
	}
#define __DO_TRACE(tp, proto, args)					\
	do {								\
		struct tracepoint_func *it_func_ptr;			\
		void *it_func;						\
		void *__data;						\
									\
		rcu_read_lock_sched_notrace();				\
		it_func_ptr = rcu_dereference_sched((tp)->funcs);	\
		if (it_func_ptr) {					\
			do {						\
				it_func = (it_func_ptr)->func;		\
				__data = (it_func_ptr)->data;		\
				((void(*)(proto))(it_func))(args);	\
			} while ((++it_func_ptr)->func);		\
		}							\
		rcu_read_unlock_sched_notrace();			\
	} while (0)
#define INIT_RCU_HEAD(ptr) do { \
       (ptr)->next = NULL; (ptr)->func = NULL; \
} while (0)
#define RCU_HEAD(head) struct rcu_head head = RCU_HEAD_INIT

#define __do_rcu_dereference_check(c)					\
	do {								\
		static bool __warned;					\
		if (debug_lockdep_rcu_enabled() && !__warned && !(c)) {	\
			__warned = true;				\
			lockdep_rcu_dereference("__FILE__", "__LINE__");	\
		}							\
	} while (0)
#define __rcu_dereference_index_check(p, c) \
	({ \
		typeof(p) _________p1 = ACCESS_ONCE(p); \
		__do_rcu_dereference_check(c); \
		smp_read_barrier_depends(); \
		(_________p1); \
	})
#define rcu_access_pointer(p)	ACCESS_ONCE(p)
#define rcu_assign_pointer(p, v) \
	({ \
		if (!__builtin_constant_p(v) || \
		    ((v) != NULL)) \
			smp_wmb(); \
		(p) = (v); \
	})
#define rcu_dereference(p) \
	rcu_dereference_check(p, rcu_read_lock_held())
#define rcu_dereference_bh(p) \
		rcu_dereference_check(p, rcu_read_lock_bh_held() || irqs_disabled())
#define rcu_dereference_check(p, c) \
	({ \
		__do_rcu_dereference_check(c); \
		rcu_dereference_raw(p); \
	})
#define rcu_dereference_index_check(p, c) \
	__rcu_dereference_index_check((p), (c))
#define rcu_dereference_protected(p, c) \
	({ \
		__do_rcu_dereference_check(c); \
		(p); \
	})
#define rcu_dereference_raw(p)	({ \
				typeof(p) _________p1 = ACCESS_ONCE(p); \
				smp_read_barrier_depends(); \
				(_________p1); \
				})
#define rcu_dereference_sched(p) \
		rcu_dereference_check(p, rcu_read_lock_sched_held())
# define rcu_read_acquire() \
		lock_acquire(&rcu_lock_map, 0, 0, 2, 1, NULL, _THIS_IP_)
# define rcu_read_acquire_bh() \
		lock_acquire(&rcu_bh_lock_map, 0, 0, 2, 1, NULL, _THIS_IP_)
# define rcu_read_acquire_sched() \
		lock_acquire(&rcu_sched_lock_map, 0, 0, 2, 1, NULL, _THIS_IP_)
# define rcu_read_release()	lock_release(&rcu_lock_map, 1, _THIS_IP_)
# define rcu_read_release_bh()	lock_release(&rcu_bh_lock_map, 1, _THIS_IP_)
# define rcu_read_release_sched() \
		lock_release(&rcu_sched_lock_map, 1, _THIS_IP_)

#define __rcu_read_lock()	preempt_disable()
#define __rcu_read_lock_bh()	local_bh_disable()
#define __rcu_read_unlock()	preempt_enable()
#define __rcu_read_unlock_bh()	local_bh_enable()
#define rcu_init_sched()	do { } while (0)
#define INTERNODE_CACHE_SHIFT L1_CACHE_SHIFT
#define L1_CACHE_ALIGN(x) ALIGN(x, L1_CACHE_BYTES)
#define SMP_CACHE_BYTES L1_CACHE_BYTES

#define ____cacheline_aligned __attribute__((__aligned__(SMP_CACHE_BYTES)))
#define ____cacheline_aligned_in_smp ____cacheline_aligned
#define ____cacheline_internodealigned_in_smp \
	__attribute__((__aligned__(1 << (INTERNODE_CACHE_SHIFT))))
#define __cacheline_aligned_in_smp __cacheline_aligned

#define cache_line_size()	L1_CACHE_BYTES

#define rcu_preempt_depth() (current->rcu_read_lock_nesting)
#define synchronize_rcu synchronize_sched
#define DEFINE_SEQLOCK(x) \
		seqlock_t x = __SEQLOCK_UNLOCKED(x)
#define SEQCNT_ZERO { 0 }
#define SEQLOCK_UNLOCKED \
		 __SEQLOCK_UNLOCKED(old_style_seqlock_init)

#define __SEQLOCK_UNLOCKED(lockname) \
		 { 0, __SPIN_LOCK_UNLOCKED(lockname) }
#define read_seqbegin_irqsave(lock, flags)				\
	({ local_irq_save(flags);   read_seqbegin(lock); })
#define read_seqretry_irqrestore(lock, iv, flags)			\
	({								\
		int ret = read_seqretry(lock, iv);			\
		local_irq_restore(flags);				\
		ret;							\
	})
#define seqcount_init(x)	do { *(x) = (seqcount_t) SEQCNT_ZERO; } while (0)
#define seqlock_init(x)					\
	do {						\
		(x)->sequence = 0;			\
		spin_lock_init(&(x)->lock);		\
	} while (0)
#define write_seqlock_bh(lock)						\
        do { local_bh_disable();    write_seqlock(lock); } while (0)
#define write_seqlock_irq(lock)						\
	do { local_irq_disable();   write_seqlock(lock); } while (0)
#define write_seqlock_irqsave(lock, flags)				\
	do { local_irq_save(flags); write_seqlock(lock); } while (0)
#define write_sequnlock_bh(lock)					\
	do { write_sequnlock(lock); local_bh_enable(); } while(0)
#define write_sequnlock_irq(lock)					\
	do { write_sequnlock(lock); local_irq_enable(); } while(0)
#define write_sequnlock_irqrestore(lock, flags)				\
	do { write_sequnlock(lock); local_irq_restore(flags); } while(0)
#define ERESTART_RESTARTBLOCK 516 


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
({	typeof(variable) pscr_ret__;					\
	__verify_pcpu_ptr(&(variable));					\
	switch(sizeof(variable)) {					\
	case 1: pscr_ret__ = stem##1(variable);break;			\
	case 2: pscr_ret__ = stem##2(variable);break;			\
	case 4: pscr_ret__ = stem##4(variable);break;			\
	case 8: pscr_ret__ = stem##8(variable);break;			\
	default:							\
		__bad_size_call_parameter();break;			\
	}								\
	pscr_ret__;							\
})
#define __percpu_generic_to_op(var, val, op)				\
do {									\
	typeof(var) *pgto_ptr__ = &(var);				\
	get_cpu_var(*pgto_ptr__) op val;				\
	put_cpu_var(*pgto_ptr__);					\
} while (0)
# define __this_cpu_add(pcp, val)	__pcpu_size_call(__this_cpu_add_, (pcp), (val))
#  define __this_cpu_add_1(pcp, val)	__this_cpu_generic_to_op((pcp), (val), +=)
#  define __this_cpu_add_2(pcp, val)	__this_cpu_generic_to_op((pcp), (val), +=)
#  define __this_cpu_add_4(pcp, val)	__this_cpu_generic_to_op((pcp), (val), +=)
#  define __this_cpu_add_8(pcp, val)	__this_cpu_generic_to_op((pcp), (val), +=)
# define __this_cpu_and(pcp, val)	__pcpu_size_call(__this_cpu_and_, (pcp), (val))
#  define __this_cpu_and_1(pcp, val)	__this_cpu_generic_to_op((pcp), (val), &=)
#  define __this_cpu_and_2(pcp, val)	__this_cpu_generic_to_op((pcp), (val), &=)
#  define __this_cpu_and_4(pcp, val)	__this_cpu_generic_to_op((pcp), (val), &=)
#  define __this_cpu_and_8(pcp, val)	__this_cpu_generic_to_op((pcp), (val), &=)
# define __this_cpu_dec(pcp)		__this_cpu_sub((pcp), 1)
#define __this_cpu_generic_to_op(pcp, val, op)				\
do {									\
	*__this_cpu_ptr(&(pcp)) op val;					\
} while (0)
# define __this_cpu_inc(pcp)		__this_cpu_add((pcp), 1)
# define __this_cpu_or(pcp, val)	__pcpu_size_call(__this_cpu_or_, (pcp), (val))
#  define __this_cpu_or_1(pcp, val)	__this_cpu_generic_to_op((pcp), (val), |=)
#  define __this_cpu_or_2(pcp, val)	__this_cpu_generic_to_op((pcp), (val), |=)
#  define __this_cpu_or_4(pcp, val)	__this_cpu_generic_to_op((pcp), (val), |=)
#  define __this_cpu_or_8(pcp, val)	__this_cpu_generic_to_op((pcp), (val), |=)
# define __this_cpu_read(pcp)	__pcpu_size_call_return(__this_cpu_read_, (pcp))
#  define __this_cpu_read_1(pcp)	(*__this_cpu_ptr(&(pcp)))
#  define __this_cpu_read_2(pcp)	(*__this_cpu_ptr(&(pcp)))
#  define __this_cpu_read_4(pcp)	(*__this_cpu_ptr(&(pcp)))
#  define __this_cpu_read_8(pcp)	(*__this_cpu_ptr(&(pcp)))
# define __this_cpu_sub(pcp, val)	__this_cpu_add((pcp), -(val))
# define __this_cpu_write(pcp, val)	__pcpu_size_call(__this_cpu_write_, (pcp), (val))
#  define __this_cpu_write_1(pcp, val)	__this_cpu_generic_to_op((pcp), (val), =)
#  define __this_cpu_write_2(pcp, val)	__this_cpu_generic_to_op((pcp), (val), =)
#  define __this_cpu_write_4(pcp, val)	__this_cpu_generic_to_op((pcp), (val), =)
#  define __this_cpu_write_8(pcp, val)	__this_cpu_generic_to_op((pcp), (val), =)
# define __this_cpu_xor(pcp, val)	__pcpu_size_call(__this_cpu_xor_, (pcp), (val))
#  define __this_cpu_xor_1(pcp, val)	__this_cpu_generic_to_op((pcp), (val), ^=)
#  define __this_cpu_xor_2(pcp, val)	__this_cpu_generic_to_op((pcp), (val), ^=)
#  define __this_cpu_xor_4(pcp, val)	__this_cpu_generic_to_op((pcp), (val), ^=)
#  define __this_cpu_xor_8(pcp, val)	__this_cpu_generic_to_op((pcp), (val), ^=)
#define _this_cpu_generic_read(pcp)					\
({	typeof(pcp) ret__;						\
	preempt_disable();						\
	ret__ = *this_cpu_ptr(&(pcp));					\
	preempt_enable();						\
	ret__;								\
})
#define _this_cpu_generic_to_op(pcp, val, op)				\
do {									\
	preempt_disable();						\
	*__this_cpu_ptr(&(pcp)) op val;					\
	preempt_enable();						\
} while (0)
#define alloc_percpu(type)	\
	(typeof(type) __percpu *)__alloc_percpu(sizeof(type), __alignof__(type))
#define get_cpu_var(var) (*({				\
	preempt_disable();				\
	&__get_cpu_var(var); }))
# define irqsafe_cpu_add(pcp, val) __pcpu_size_call(irqsafe_cpu_add_, (pcp), (val))
#  define irqsafe_cpu_add_1(pcp, val) irqsafe_cpu_generic_to_op((pcp), (val), +=)
#  define irqsafe_cpu_add_2(pcp, val) irqsafe_cpu_generic_to_op((pcp), (val), +=)
#  define irqsafe_cpu_add_4(pcp, val) irqsafe_cpu_generic_to_op((pcp), (val), +=)
#  define irqsafe_cpu_add_8(pcp, val) irqsafe_cpu_generic_to_op((pcp), (val), +=)
# define irqsafe_cpu_and(pcp, val) __pcpu_size_call(irqsafe_cpu_and_, (val))
#  define irqsafe_cpu_and_1(pcp, val) irqsafe_cpu_generic_to_op((pcp), (val), &=)
#  define irqsafe_cpu_and_2(pcp, val) irqsafe_cpu_generic_to_op((pcp), (val), &=)
#  define irqsafe_cpu_and_4(pcp, val) irqsafe_cpu_generic_to_op((pcp), (val), &=)
#  define irqsafe_cpu_and_8(pcp, val) irqsafe_cpu_generic_to_op((pcp), (val), &=)
# define irqsafe_cpu_dec(pcp)	irqsafe_cpu_sub((pcp), 1)
#define irqsafe_cpu_generic_to_op(pcp, val, op)				\
do {									\
	unsigned long flags;						\
	local_irq_save(flags);						\
	*__this_cpu_ptr(&(pcp)) op val;					\
	local_irq_restore(flags);					\
} while (0)
# define irqsafe_cpu_inc(pcp)	irqsafe_cpu_add((pcp), 1)
# define irqsafe_cpu_or(pcp, val) __pcpu_size_call(irqsafe_cpu_or_, (val))
#  define irqsafe_cpu_or_1(pcp, val) irqsafe_cpu_generic_to_op((pcp), (val), |=)
#  define irqsafe_cpu_or_2(pcp, val) irqsafe_cpu_generic_to_op((pcp), (val), |=)
#  define irqsafe_cpu_or_4(pcp, val) irqsafe_cpu_generic_to_op((pcp), (val), |=)
#  define irqsafe_cpu_or_8(pcp, val) irqsafe_cpu_generic_to_op((pcp), (val), |=)
# define irqsafe_cpu_sub(pcp, val)	irqsafe_cpu_add((pcp), -(val))
# define irqsafe_cpu_xor(pcp, val) __pcpu_size_call(irqsafe_cpu_xor_, (val))
#  define irqsafe_cpu_xor_1(pcp, val) irqsafe_cpu_generic_to_op((pcp), (val), ^=)
#  define irqsafe_cpu_xor_2(pcp, val) irqsafe_cpu_generic_to_op((pcp), (val), ^=)
#  define irqsafe_cpu_xor_4(pcp, val) irqsafe_cpu_generic_to_op((pcp), (val), ^=)
#  define irqsafe_cpu_xor_8(pcp, val) irqsafe_cpu_generic_to_op((pcp), (val), ^=)
#define per_cpu_ptr(ptr, cpu)	SHIFT_PERCPU_PTR((ptr), per_cpu_offset((cpu)))
# define percpu_add(var, val)		__percpu_generic_to_op(var, (val), +=)
# define percpu_and(var, val)		__percpu_generic_to_op(var, (val), &=)
# define percpu_or(var, val)		__percpu_generic_to_op(var, (val), |=)
# define percpu_read(var)						\
  ({									\
	typeof(var) *pr_ptr__ = &(var);					\
	typeof(var) pr_ret__;						\
	pr_ret__ = get_cpu_var(*pr_ptr__);				\
	put_cpu_var(*pr_ptr__);						\
	pr_ret__;							\
  })
# define percpu_sub(var, val)		__percpu_generic_to_op(var, (val), -=)
# define percpu_write(var, val)		__percpu_generic_to_op(var, (val), =)
# define percpu_xor(var, val)		__percpu_generic_to_op(var, (val), ^=)
#define put_cpu_var(var) do {				\
	(void)&(var);					\
	preempt_enable();				\
} while (0)
# define this_cpu_add(pcp, val)		__pcpu_size_call(this_cpu_add_, (pcp), (val))
#  define this_cpu_add_1(pcp, val)	_this_cpu_generic_to_op((pcp), (val), +=)
#  define this_cpu_add_2(pcp, val)	_this_cpu_generic_to_op((pcp), (val), +=)
#  define this_cpu_add_4(pcp, val)	_this_cpu_generic_to_op((pcp), (val), +=)
#  define this_cpu_add_8(pcp, val)	_this_cpu_generic_to_op((pcp), (val), +=)
# define this_cpu_and(pcp, val)		__pcpu_size_call(this_cpu_and_, (pcp), (val))
#  define this_cpu_and_1(pcp, val)	_this_cpu_generic_to_op((pcp), (val), &=)
#  define this_cpu_and_2(pcp, val)	_this_cpu_generic_to_op((pcp), (val), &=)
#  define this_cpu_and_4(pcp, val)	_this_cpu_generic_to_op((pcp), (val), &=)
#  define this_cpu_and_8(pcp, val)	_this_cpu_generic_to_op((pcp), (val), &=)
# define this_cpu_dec(pcp)		this_cpu_sub((pcp), 1)
# define this_cpu_inc(pcp)		this_cpu_add((pcp), 1)
# define this_cpu_or(pcp, val)		__pcpu_size_call(this_cpu_or_, (pcp), (val))
#  define this_cpu_or_1(pcp, val)	_this_cpu_generic_to_op((pcp), (val), |=)
#  define this_cpu_or_2(pcp, val)	_this_cpu_generic_to_op((pcp), (val), |=)
#  define this_cpu_or_4(pcp, val)	_this_cpu_generic_to_op((pcp), (val), |=)
#  define this_cpu_or_8(pcp, val)	_this_cpu_generic_to_op((pcp), (val), |=)
# define this_cpu_read(pcp)	__pcpu_size_call_return(this_cpu_read_, (pcp))
#  define this_cpu_read_1(pcp)	_this_cpu_generic_read(pcp)
#  define this_cpu_read_2(pcp)	_this_cpu_generic_read(pcp)
#  define this_cpu_read_4(pcp)	_this_cpu_generic_read(pcp)
#  define this_cpu_read_8(pcp)	_this_cpu_generic_read(pcp)
# define this_cpu_sub(pcp, val)		this_cpu_add((pcp), -(val))
# define this_cpu_write(pcp, val)	__pcpu_size_call(this_cpu_write_, (pcp), (val))
#  define this_cpu_write_1(pcp, val)	_this_cpu_generic_to_op((pcp), (val), =)
#  define this_cpu_write_2(pcp, val)	_this_cpu_generic_to_op((pcp), (val), =)
#  define this_cpu_write_4(pcp, val)	_this_cpu_generic_to_op((pcp), (val), =)
#  define this_cpu_write_8(pcp, val)	_this_cpu_generic_to_op((pcp), (val), =)
# define this_cpu_xor(pcp, val)		__pcpu_size_call(this_cpu_or_, (pcp), (val))
#  define this_cpu_xor_1(pcp, val)	_this_cpu_generic_to_op((pcp), (val), ^=)
#  define this_cpu_xor_2(pcp, val)	_this_cpu_generic_to_op((pcp), (val), ^=)
#  define this_cpu_xor_4(pcp, val)	_this_cpu_generic_to_op((pcp), (val), ^=)
#  define this_cpu_xor_8(pcp, val)	_this_cpu_generic_to_op((pcp), (val), ^=)

#define __CPUINIT        .section	".cpuinit.text", "ax"
#define __CPUINITDATA    .section	".cpuinit.data", "aw"
#define __CPUINITRODATA  .section	".cpuinit.rodata", "a"
#define __DEVINIT        .section	".devinit.text", "ax"
#define __DEVINITDATA    .section	".devinit.data", "aw"
#define __DEVINITRODATA  .section	".devinit.rodata", "a"
#define __INITDATA_OR_MODULE __INITDATA
#define __INITRODATA_OR_MODULE __INITRODATA
#define __INIT_OR_MODULE __INIT
#define __MEMINIT        .section	".meminit.text", "ax"
#define __MEMINITDATA    .section	".meminit.data", "aw"
#define __MEMINITRODATA  .section	".meminit.rodata", "a"
#define __REF            .section       ".ref.text", "ax"
#define __REFCONST       .section       ".ref.rodata", "a"
#define __REFDATA        .section       ".ref.data", "aw"
#define __cpuexit        __section(.cpuexit.text) __exitused __cold
#define __cpuexitconst   __section(.cpuexit.rodata)
#define __cpuexitdata    __section(.cpuexit.data)
#define __cpuinit        __section(.cpuinit.text) __cold
#define __cpuinitconst   __section(.cpuinit.rodata)
#define __cpuinitdata    __section(.cpuinit.data)
#define __define_initcall(level,fn,id) \
	static initcall_t __initcall_##fn##id __used \
	__attribute__((__section__(".initcall" level ".init"))) = fn
#define __devexit        __section(.devexit.text) __exitused __cold
#define __devexit_p(x) x
#define __devexitconst   __section(.devexit.rodata)
#define __devexitdata    __section(.devexit.data)
#define __devinit        __section(.devinit.text) __cold
#define __devinitconst   __section(.devinit.rodata)
#define __devinitdata    __section(.devinit.data)
#define __exit          __section(.exit.text) __exitused __cold
#define __exit_p(x) x
#define __exit_refok     __ref
#define __exitcall(fn) \
	static exitcall_t __exitcall_##fn __exit_call = fn
#define __exitused  __used
#define __init_or_module __init
#define __init_refok     __ref
#define __initcall(fn) device_initcall(fn)
#define __initconst_or_module __initconst
#define __initdata_or_module __initdata
#define __initdata_refok __refdata
#define __memexit        __section(.memexit.text) __exitused __cold
#define __memexitconst   __section(.memexit.rodata)
#define __memexitdata    __section(.memexit.data)
#define __meminit        __section(.meminit.text) __cold
#define __meminitconst   __section(.meminit.rodata)
#define __meminitdata    __section(.meminit.data)
#define __nosavedata __section(.data..nosave)
#define __ref            __section(.ref.text) noinline
#define __refconst       __section(.ref.rodata)
#define __refdata        __section(.ref.data)
#define __setup(str, fn)					\
	__setup_param(str, fn, fn, 0)
#define __setup_param(str, unique_id, fn, early)			\
	static const char __setup_str_##unique_id[] __initconst	\
		__aligned(1) = str; \
	static struct obs_kernel_param __setup_##unique_id	\
		__used __section(.init.setup)			\
		__attribute__((aligned((sizeof(long)))))	\
		= { __setup_str_##unique_id, fn, early }
#define arch_initcall(fn)		__define_initcall("3",fn,3)
#define arch_initcall_sync(fn)		__define_initcall("3s",fn,3s)
#define console_initcall(fn) \
	static initcall_t __initcall_##fn \
	__used __section(.con_initcall.init) = fn
#define core_initcall(fn)		__define_initcall("1",fn,1)
#define core_initcall_sync(fn)		__define_initcall("1s",fn,1s)
#define device_initcall(fn)		__define_initcall("6",fn,6)
#define device_initcall_sync(fn)	__define_initcall("6s",fn,6s)
#define early_initcall(fn)		__define_initcall("early",fn,early)
#define early_param(str, fn)					\
	__setup_param(str, fn, fn, 1)
#define fs_initcall(fn)			__define_initcall("5",fn,5)
#define fs_initcall_sync(fn)		__define_initcall("5s",fn,5s)
#define late_initcall(fn)		__define_initcall("7",fn,7)
#define late_initcall_sync(fn)		__define_initcall("7s",fn,7s)
#define module_exit(x)	__exitcall(x);
#define module_init(x)	__initcall(x);
#define postcore_initcall(fn)		__define_initcall("2",fn,2)
#define postcore_initcall_sync(fn)	__define_initcall("2s",fn,2s)
#define pure_initcall(fn)		__define_initcall("0",fn,0)
#define rootfs_initcall(fn)		__define_initcall("rootfs",fn,rootfs)
#define security_initcall(fn) \
	static initcall_t __initcall_##fn \
	__used __section(.security_initcall.init) = fn
#define subsys_initcall(fn)		__define_initcall("4",fn,4)
#define subsys_initcall_sync(fn)	__define_initcall("4s",fn,4s)
#define PFN_ALIGN(x)	(((unsigned long)(x) + (PAGE_SIZE - 1)) & PAGE_MASK)
#define PFN_DOWN(x)	((x) >> PAGE_SHIFT)
#define PFN_PHYS(x)	((phys_addr_t)(x) << PAGE_SHIFT)
#define PFN_UP(x)	(((x) + PAGE_SIZE-1) >> PAGE_SHIFT)

#define MSG_CALL_FUNCTION       0x0004  

#define get_cpu()		({ preempt_disable(); smp_processor_id(); })
#define num_booting_cpus()			1
#define on_each_cpu(func,info,wait)		\
	({					\
		local_irq_disable();		\
		func(info);			\
		local_irq_enable();		\
		0;				\
	})
#define put_cpu()		preempt_enable()
#define raw_smp_processor_id()			0
#define smp_call_function(func, info, wait) \
			(up_smp_call_function(func, info))
#define smp_call_function_many(mask, func, info, wait) \
			(up_smp_call_function(func, info))
#define smp_prepare_boot_cpu()			do {} while (0)
# define smp_processor_id() debug_smp_processor_id()
#define MAX_PARAM_PREFIX_LEN (64 - sizeof(unsigned long))
#define MODULE_PARAM_PREFIX 

#define __MODULE_INFO(tag, name, info)					  \
static const char __module_cat(name,"__LINE__")[]				  \
  __used								  \
  __attribute__((section(".modinfo"),unused)) = __stringify(tag) "=" info
#define __MODULE_PARM_TYPE(name, _type)					  \
  __MODULE_INFO(parmtype, name##type, #name ":" _type)

#define __module_cat(a,b) ___module_cat(a,b)
#define __module_param_call(prefix, name, ops, arg, isbool, perm)	\
				\
	static int __param_perm_check_##name __attribute__((unused)) =	\
	BUILD_BUG_ON_ZERO((perm) < 0 || (perm) > 0777 || ((perm) & 2))	\
	+ BUILD_BUG_ON_ZERO(sizeof(""prefix) > MAX_PARAM_PREFIX_LEN);	\
	static const char __param_str_##name[] = prefix #name;		\
	static struct kernel_param __moduleparam_const __param_##name	\
	__used								\
    __attribute__ ((unused,__section__ ("__param"),aligned(sizeof(void *)))) \
	= { __param_str_##name, ops, perm, isbool ? KPARAM_ISBOOL : 0,	\
	    { arg } }
#define __moduleparam_const const
#define __param_check(name, p, type) \
	static inline type *__check_##name(void) { return(p); }
#define core_param(name, var, type, perm)				\
	param_check_##type(name, &(var));				\
	__module_param_call("", name, &param_ops_##type,		\
			    &var, __same_type(var, bool), perm)
#define kparam_block_sysfs_read(name)			\
	do {						\
		BUG_ON(!(__param_##name.perm & 0444));	\
		__kernel_param_lock();			\
	} while (0)
#define kparam_block_sysfs_write(name)			\
	do {						\
		BUG_ON(!(__param_##name.perm & 0222));	\
		__kernel_param_lock();			\
	} while (0)
#define kparam_unblock_sysfs_read(name)			\
	do {						\
		BUG_ON(!(__param_##name.perm & 0444));	\
		__kernel_param_unlock();		\
	} while (0)
#define kparam_unblock_sysfs_write(name)		\
	do {						\
		BUG_ON(!(__param_##name.perm & 0222));	\
		__kernel_param_unlock();		\
	} while (0)
#define module_param(name, type, perm)				\
	module_param_named(name, name, type, perm)
#define module_param_array(name, type, nump, perm)		\
	module_param_array_named(name, name, type, nump, perm)
#define module_param_array_named(name, array, type, nump, perm)		\
	static const struct kparam_array __param_arr_##name		\
	= { ARRAY_SIZE(array), nump, &param_ops_##type,			\
	    sizeof(array[0]), array };					\
	__module_param_call(MODULE_PARAM_PREFIX, name,			\
			    &param_array_ops,				\
			    .arr = &__param_arr_##name,			\
			    __same_type(array[0], bool), perm);		\
	__MODULE_PARM_TYPE(name, "array of " #type)
#define module_param_call(name, set, get, arg, perm)			\
	static struct kernel_param_ops __param_ops_##name =		\
		 { (void *)set, (void *)get };				\
	__module_param_call(MODULE_PARAM_PREFIX,			\
			    name, &__param_ops_##name, arg,		\
			    __same_type(arg, bool *),			\
			    (perm) + sizeof(__check_old_set_param(set))*0)
#define module_param_cb(name, ops, arg, perm)				      \
	__module_param_call(MODULE_PARAM_PREFIX,			      \
			    name, ops, arg, __same_type((arg), bool *), perm)
#define module_param_named(name, value, type, perm)			   \
	param_check_##type(name, &(value));				   \
	module_param_cb(name, &param_ops_##type, &value, perm);		   \
	__MODULE_PARM_TYPE(name, #type)
#define module_param_string(name, string, len, perm)			\
	static const struct kparam_string __param_string_##name		\
		= { len, string };					\
	__module_param_call(MODULE_PARAM_PREFIX, name,			\
			    &param_ops_string,				\
			    .str = &__param_string_##name, 0, perm);	\
	__MODULE_PARM_TYPE(name, "string")
#define param_check_bool(name, p)					\
	static inline void __check_##name(void)				\
	{								\
		BUILD_BUG_ON(!__same_type((p), bool *) &&		\
			     !__same_type((p), unsigned int *) &&	\
			     !__same_type((p), int *));			\
	}
#define param_check_byte(name, p) __param_check(name, p, unsigned char)
#define param_check_charp(name, p) __param_check(name, p, char *)
#define param_check_int(name, p) __param_check(name, p, int)
#define param_check_invbool(name, p) __param_check(name, p, bool)
#define param_check_long(name, p) __param_check(name, p, long)
#define param_check_short(name, p) __param_check(name, p, short)
#define param_check_uint(name, p) __param_check(name, p, unsigned int)
#define param_check_ulong(name, p) __param_check(name, p, unsigned long)
#define param_check_ushort(name, p) __param_check(name, p, unsigned short)




#define __ATTR(_name,_mode,_show,_store) { \
	.attr = {.name = __stringify(_name), .mode = _mode },	\
	.show	= _show,					\
	.store	= _store,					\
}
#define __ATTR_NULL { .attr = { .name = NULL } }
#define __ATTR_RO(_name) { \
	.attr	= { .name = __stringify(_name), .mode = 0444 },	\
	.show	= _name##_show,					\
}
#define attr_name(_attr) (_attr).attr.name
#define sysfs_attr_init(attr)				\
do {							\
	static struct lock_class_key __key;		\
							\
	(attr)->key = &__key;				\
} while(0)
#define sysfs_bin_attr_init(bin_attr) sysfs_attr_init(&(bin_attr)->attr)
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
#define NT_PRXFPREG     0x46e62b7f      
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

# define elf_read_implies_exec(ex, have_pt_gnu_stack)	0
#define EM_BLACKFIN     106     
#define EM_CYGNUS_MN10300 0xbeef

#define KMOD_PATH_LEN 256

#define request_module(mod...) __request_module(true, mod)
#define request_module_nowait(mod...) __request_module(false, mod)
#define try_then_request_module(x, mod...) \
	((x) ?: (__request_module(true, mod), (x)))
#define GFP_BOOT_MASK (__GFP_BITS_MASK & ~(__GFP_WAIT|__GFP_IO|__GFP_FS))
#define GFP_CONSTRAINT_MASK (__GFP_HARDWALL|__GFP_THISNODE)
#define GFP_MOVABLE_MASK (__GFP_RECLAIMABLE|__GFP_MOVABLE)
#define GFP_RECLAIM_MASK (__GFP_WAIT|__GFP_HIGH|__GFP_IO|__GFP_FS|\
			__GFP_NOWARN|__GFP_REPEAT|__GFP_NOFAIL|\
			__GFP_NORETRY|__GFP_NOMEMALLOC)
#define GFP_SLAB_BUG_MASK (__GFP_DMA32|__GFP_HIGHMEM|~__GFP_BITS_MASK)
#define GFP_ZONE_BAD ( \
	1 << (__GFP_DMA | __GFP_HIGHMEM)				\
	| 1 << (__GFP_DMA | __GFP_DMA32)				\
	| 1 << (__GFP_DMA32 | __GFP_HIGHMEM)				\
	| 1 << (__GFP_DMA | __GFP_DMA32 | __GFP_HIGHMEM)		\
	| 1 << (__GFP_MOVABLE | __GFP_HIGHMEM | __GFP_DMA)		\
	| 1 << (__GFP_MOVABLE | __GFP_DMA32 | __GFP_DMA)		\
	| 1 << (__GFP_MOVABLE | __GFP_DMA32 | __GFP_HIGHMEM)		\
	| 1 << (__GFP_MOVABLE | __GFP_DMA32 | __GFP_DMA | __GFP_HIGHMEM)\
)
#define GFP_ZONE_TABLE ( \
	(ZONE_NORMAL << 0 * ZONES_SHIFT)				\
	| (OPT_ZONE_DMA << __GFP_DMA * ZONES_SHIFT)			\
	| (OPT_ZONE_HIGHMEM << __GFP_HIGHMEM * ZONES_SHIFT)		\
	| (OPT_ZONE_DMA32 << __GFP_DMA32 * ZONES_SHIFT)			\
	| (ZONE_NORMAL << __GFP_MOVABLE * ZONES_SHIFT)			\
	| (OPT_ZONE_DMA << (__GFP_MOVABLE | __GFP_DMA) * ZONES_SHIFT)	\
	| (ZONE_MOVABLE << (__GFP_MOVABLE | __GFP_HIGHMEM) * ZONES_SHIFT)\
	| (OPT_ZONE_DMA32 << (__GFP_MOVABLE | __GFP_DMA32) * ZONES_SHIFT)\
)
#define OPT_ZONE_DMA ZONE_DMA
#define OPT_ZONE_DMA32 ZONE_DMA32
#define OPT_ZONE_HIGHMEM ZONE_HIGHMEM
#define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) - 1))
#define __GFP_BITS_SHIFT 22	
#define __GFP_HARDWALL   ((__force gfp_t)0x20000u) 
#define __GFP_NOMEMALLOC ((__force gfp_t)0x10000u) 
#define __GFP_NOTRACK_FALSE_POSITIVE (__GFP_NOTRACK)
#define __GFP_RECLAIMABLE ((__force gfp_t)0x80000u) 

#define __free_page(page) __free_pages((page), 0)
#define __get_dma_pages(gfp_mask, order) \
		__get_free_pages((gfp_mask) | GFP_DMA, (order))
#define __get_free_page(gfp_mask) \
		__get_free_pages((gfp_mask), 0)
#define alloc_page(gfp_mask) alloc_pages(gfp_mask, 0)
#define alloc_page_vma(gfp_mask, vma, addr) alloc_pages(gfp_mask, 0)
#define alloc_pages(gfp_mask, order) \
		alloc_pages_node(numa_node_id(), gfp_mask, order)
#define free_page(addr) free_pages((addr), 0)
#define LINUX_MM_DEBUG_H 1
#define VIRTUAL_BUG_ON(cond) BUG_ON(cond)
#define VM_BUG_ON(cond) BUG_ON(cond)

#define RECLAIM_DISTANCE 20
#define SD_ALLNODES_INIT (struct sched_domain) {			\
	.min_interval		= 64,					\
	.max_interval		= 64*num_online_cpus(),			\
	.busy_factor		= 128,					\
	.imbalance_pct		= 133,					\
	.cache_nice_tries	= 1,					\
	.busy_idx		= 3,					\
	.idle_idx		= 3,					\
	.flags			= 1*SD_LOAD_BALANCE			\
				| 1*SD_BALANCE_NEWIDLE			\
				| 0*SD_BALANCE_EXEC			\
				| 0*SD_BALANCE_FORK			\
				| 0*SD_BALANCE_WAKE			\
				| 0*SD_WAKE_AFFINE			\
				| 0*SD_SHARE_CPUPOWER			\
				| 0*SD_POWERSAVINGS_BALANCE		\
				| 0*SD_SHARE_PKG_RESOURCES		\
				| 1*SD_SERIALIZE			\
				| 0*SD_PREFER_SIBLING			\
				,					\
	.last_balance		= jiffies,				\
	.balance_interval	= 64,					\
}
#define SD_CPU_INIT (struct sched_domain) {				\
	.min_interval		= 1,					\
	.max_interval		= 4,					\
	.busy_factor		= 64,					\
	.imbalance_pct		= 125,					\
	.cache_nice_tries	= 1,					\
	.busy_idx		= 2,					\
	.idle_idx		= 1,					\
	.newidle_idx		= 0,					\
	.wake_idx		= 0,					\
	.forkexec_idx		= 0,					\
									\
	.flags			= 1*SD_LOAD_BALANCE			\
				| 1*SD_BALANCE_NEWIDLE			\
				| 1*SD_BALANCE_EXEC			\
				| 1*SD_BALANCE_FORK			\
				| 0*SD_BALANCE_WAKE			\
				| 1*SD_WAKE_AFFINE			\
				| 0*SD_PREFER_LOCAL			\
				| 0*SD_SHARE_CPUPOWER			\
				| 0*SD_SHARE_PKG_RESOURCES		\
				| 0*SD_SERIALIZE			\
				| sd_balance_for_package_power()	\
				| sd_power_saving_flags()		\
				,					\
	.last_balance		= jiffies,				\
	.balance_interval	= 1,					\
}
#define SD_MC_INIT (struct sched_domain) {				\
	.min_interval		= 1,					\
	.max_interval		= 4,					\
	.busy_factor		= 64,					\
	.imbalance_pct		= 125,					\
	.cache_nice_tries	= 1,					\
	.busy_idx		= 2,					\
	.wake_idx		= 0,					\
	.forkexec_idx		= 0,					\
									\
	.flags			= 1*SD_LOAD_BALANCE			\
				| 1*SD_BALANCE_NEWIDLE			\
				| 1*SD_BALANCE_EXEC			\
				| 1*SD_BALANCE_FORK			\
				| 0*SD_BALANCE_WAKE			\
				| 1*SD_WAKE_AFFINE			\
				| 0*SD_PREFER_LOCAL			\
				| 0*SD_SHARE_CPUPOWER			\
				| 1*SD_SHARE_PKG_RESOURCES		\
				| 0*SD_SERIALIZE			\
				| sd_balance_for_mc_power()		\
				| sd_power_saving_flags()		\
				,					\
	.last_balance		= jiffies,				\
	.balance_interval	= 1,					\
}
#define SD_SIBLING_INIT (struct sched_domain) {				\
	.min_interval		= 1,					\
	.max_interval		= 2,					\
	.busy_factor		= 64,					\
	.imbalance_pct		= 110,					\
									\
	.flags			= 1*SD_LOAD_BALANCE			\
				| 1*SD_BALANCE_NEWIDLE			\
				| 1*SD_BALANCE_EXEC			\
				| 1*SD_BALANCE_FORK			\
				| 0*SD_BALANCE_WAKE			\
				| 1*SD_WAKE_AFFINE			\
				| 1*SD_SHARE_CPUPOWER			\
				| 0*SD_POWERSAVINGS_BALANCE		\
				| 1*SD_SHARE_PKG_RESOURCES		\
				| 0*SD_SERIALIZE			\
				| 0*SD_PREFER_SIBLING			\
				| arch_sd_sibling_asym_packing()	\
				,					\
	.last_balance		= jiffies,				\
	.balance_interval	= 1,					\
	.smt_gain		= 1178,				\
}

#define for_each_node_with_cpus(node)			\
	for_each_online_node(node)			\
		if (nr_cpus_node(node))
#define node_distance(from,to)	((from) == (to) ? LOCAL_DISTANCE : REMOTE_DISTANCE)
#define node_has_online_mem(nid) (1)
#define nr_cpus_node(node) cpumask_weight(cpumask_of_node(node))
#define topology_core_cpumask(cpu)		cpumask_of(cpu)
#define topology_core_id(cpu)			((void)(cpu), 0)
#define topology_physical_package_id(cpu)	((void)(cpu), -1)
#define topology_thread_cpumask(cpu)		cpumask_of(cpu)
#define DEF_PRIORITY 12
#define LRU_ACTIVE 1
#define LRU_BASE 0
#define LRU_FILE 2
#define MAX_ORDER 11
#define MAX_ORDER_NR_PAGES (1 << (MAX_ORDER - 1))
#define MAX_ZONELISTS 2
#define MAX_ZONES_PER_ZONELIST (MAX_NUMNODES * MAX_NR_ZONES)
#define MIGRATE_ISOLATE       4 
#define MIGRATE_MOVABLE       2
#define MIGRATE_PCPTYPES      3 
#define MIGRATE_RECLAIMABLE   1
#define MIGRATE_RESERVE       3
#define MIGRATE_TYPES         5
#define MIGRATE_UNMOVABLE     0
#define NODE_DATA(nid)		(&contig_page_data)
#define NODE_MEM_MAP(nid)	mem_map
#define NUMA_ZONELIST_ORDER_LEN 16	
#define PAGES_PER_SECTION       (1UL << PFN_SECTION_SHIFT)
#define PAGE_ALLOC_COSTLY_ORDER 3
#define SECTIONS_PER_ROOT       (PAGE_SIZE / sizeof (struct mem_section))
#define SECTION_BLOCKFLAGS_BITS \
	((1UL << (PFN_SECTION_SHIFT - pageblock_order)) * NR_PAGEBLOCK_BITS)
#define SECTION_NR_TO_ROOT(sec)	((sec) / SECTIONS_PER_ROOT)
#define ZONES_SHIFT 0
#define ZONE_PADDING(name)	struct zone_padding name;

#define early_pfn_in_nid(pfn, nid)	(1)
#define early_pfn_valid(pfn)	pfn_valid(pfn)
#define for_each_evictable_lru(l) for (l = 0; l <= LRU_ACTIVE_FILE; l++)
#define for_each_lru(l) for (l = 0; l < NR_LRU_LISTS; l++)
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
	for (z = first_zones_zonelist(zlist, highidx, nodemask, &zone);	\
		zone;							\
		z = next_zones_zonelist(++z, highidx, nodemask, &zone))	\

#define high_wmark_pages(z) (z->watermark[WMARK_HIGH])
#define low_wmark_pages(z) (z->watermark[WMARK_LOW])
#define min_wmark_pages(z) (z->watermark[WMARK_MIN])
#define nid_page_nr(nid, pagenr) 	pgdat_page_nr(NODE_DATA(nid),(pagenr))
#define node_present_pages(nid)	(NODE_DATA(nid)->node_present_pages)
#define node_spanned_pages(nid)	(NODE_DATA(nid)->node_spanned_pages)
#define pfn_to_nid(pfn)							\
({									\
	unsigned long __pfn_to_nid_pfn = (pfn);				\
	page_to_nid(pfn_to_page(__pfn_to_nid_pfn));			\
})
#define pfn_to_section_nr(pfn) ((pfn) >> PFN_SECTION_SHIFT)
#define pfn_valid_within(pfn) pfn_valid(pfn)
#define pgdat_page_nr(pgdat, pagenr)	((pgdat)->node_mem_map + (pagenr))
#define section_nr_to_pfn(sec) ((sec) << PFN_SECTION_SHIFT)
#define sparse_index_init(_sec, _nid)  do {} while (0)
#define sparse_init()	do {} while (0)
#define zone_idx(zone)		((zone) - (zone)->zone_pgdat->node_zones)
#define zone_nr_free_pages(zone) zone_page_state(zone, NR_FREE_PAGES)

#define arch_alloc_nodedata(nid)	generic_alloc_nodedata(nid)
#define arch_free_nodedata(pgdat)	generic_free_nodedata(pgdat)
#define generic_alloc_nodedata(nid)				\
({								\
	kzalloc(sizeof(pg_data_t), GFP_KERNEL);			\
})
#define generic_free_nodedata(pgdat)	kfree(pgdat)
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
#define NETDEV_BONDING_DESLAVE  0x0012
#define NETDEV_BONDING_FAILOVER 0x000C
#define NETDEV_REGISTER 0x0005
#define NETDEV_UNREGISTER_BATCH 0x0011
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

#define init_srcu_struct(sp) \
({ \
	static struct lock_class_key __srcu_key; \
	\
	__init_srcu_struct((sp), #sp, &__srcu_key); \
})
#define srcu_barrier() barrier()
#define srcu_dereference(p, sp) \
		rcu_dereference_check(p, srcu_read_lock_held(sp))
# define srcu_read_acquire(sp) \
		lock_acquire(&(sp)->dep_map, 0, 0, 2, 1, NULL, _THIS_IP_)
# define srcu_read_release(sp) \
		lock_release(&(sp)->dep_map, 1, _THIS_IP_)
#define DEFINE_MUTEX(mutexname) \
	struct mutex mutexname = __MUTEX_INITIALIZER(mutexname)
# define __DEBUG_MUTEX_INITIALIZER(lockname)
# define __DEP_MAP_MUTEX_INITIALIZER(lockname)

#define __MUTEX_INITIALIZER(lockname) \
		{ .count = ATOMIC_INIT(1) \
		, .wait_lock = __SPIN_LOCK_UNLOCKED(lockname.wait_lock) \
		, .wait_list = LIST_HEAD_INIT(lockname.wait_list) \
		__DEBUG_MUTEX_INITIALIZER(lockname) \
		__DEP_MAP_MUTEX_INITIALIZER(lockname) }
# define mutex_destroy(mutex)				do { } while (0)
# define mutex_init(mutex) \
do {							\
	static struct lock_class_key __key;		\
							\
	__mutex_init((mutex), #mutex, &__key);		\
} while (0)
#define mutex_lock(lock) mutex_lock_nested(lock, 0)
#define mutex_lock_interruptible(lock) mutex_lock_interruptible_nested(lock, 0)
# define mutex_lock_interruptible_nested(lock, subclass) mutex_lock_interruptible(lock)
#define mutex_lock_killable(lock) mutex_lock_killable_nested(lock, 0)
# define mutex_lock_killable_nested(lock, subclass) mutex_lock_killable(lock)
# define mutex_lock_nested(lock, subclass) mutex_lock(lock)

# define down_read_nested(sem, subclass)		down_read(sem)
# define down_read_non_owner(sem)		down_read(sem)
# define down_write_nested(sem, subclass)	down_write(sem)
# define up_read_non_owner(sem)			up_read(sem)
#define DECLARE_RWSEM(name) \
	struct rw_semaphore name = __RWSEM_INITIALIZER(name)

# define __RWSEM_DEP_MAP_INIT(lockname) , .dep_map = { .name = #lockname }
#define __RWSEM_INITIALIZER(name) \
{ 0, __SPIN_LOCK_UNLOCKED(name.wait_lock), LIST_HEAD_INIT((name).wait_list) \
  __RWSEM_DEP_MAP_INIT(name) }
#define init_rwsem(sem)						\
do {								\
	static struct lock_class_key __key;			\
								\
	__init_rwsem((sem), #sem, &__key);			\
} while (0)

#define get_pageblock_flags(page) \
			get_pageblock_flags_group(page, 0, NR_PAGEBLOCK_BITS-1)
#define set_pageblock_flags(page) \
			set_pageblock_flags_group(page, 0, NR_PAGEBLOCK_BITS-1)
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
#define next_online_node(nid)	next_node((nid), node_states[N_ONLINE])
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
#define nodelist_scnprintf(buf, len, src) \
			__nodelist_scnprintf((buf), (len), &(src), MAX_NUMNODES)
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
#define nodemask_scnprintf(buf, len, src) \
			__nodemask_scnprintf((buf), (len), &(src), MAX_NUMNODES)
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

#  define CALLER_ADDR0 ((unsigned long)__builtin_return_address(0))
#  define CALLER_ADDR1 ((unsigned long)__builtin_return_address(1))
#  define CALLER_ADDR2 ((unsigned long)__builtin_return_address(2))
#  define CALLER_ADDR3 ((unsigned long)__builtin_return_address(3))
#  define CALLER_ADDR4 ((unsigned long)__builtin_return_address(4))
#  define CALLER_ADDR5 ((unsigned long)__builtin_return_address(5))
#  define CALLER_ADDR6 ((unsigned long)__builtin_return_address(6))
#define FTRACE_ADDR ((unsigned long)ftrace_caller)
#define FTRACE_RETFUNC_DEPTH 50
#define FTRACE_RETSTACK_ALLOC_SIZE 32





#define register_ftrace_function(ops) ({ 0; })
#define unregister_ftrace_function(ops) ({ 0; })
#define ACC_MODE(x) ("\004\002\006\006"[(x)&O_ACCMODE])
#define ACL_NOT_CACHED ((void *)(-1))
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
#define BLKRRPART  _IO(0x12,95)	
#define BLKSECDISCARD _IO(0x12,125)
#define BLKSECTGET _IO(0x12,103)
#define BLKSECTSET _IO(0x12,102)
#define BLKSSZGET  _IO(0x12,104)
#define BLKTRACESETUP _IOWR(0x12,115,struct blk_user_trace_setup)
#define BLKTRACESTART _IO(0x12,116)
#define BLKTRACESTOP _IO(0x12,117)
#define BLKTRACETEARDOWN _IO(0x12,118)
#define BLOCK_SIZE (1<<BLOCK_SIZE_BITS)
#define BLOCK_SIZE_BITS 10
#define BMAP_IOCTL 1		
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
};
#define FASYNC_MAGIC 0x4601
#define FIGETBSZ   _IO(0x00,2)	
#define FILE_LOCK_DEFERRED 1
#define FLOCK_VERIFY_READ  1
#define FLOCK_VERIFY_WRITE 2
#define FS_BINARY_MOUNTDATA 2
#define FS_HAS_SUBTYPE 4
#define FS_REQUIRES_DEV 1 
#define HAVE_COMPAT_IOCTL 1
#define HAVE_UNLOCKED_IOCTL 1
#define INR_OPEN 1024		
#define INT_LIMIT(x)	(~((x)1 << (sizeof(x)*8 - 1)))
#define IS_APPEND(inode)	((inode)->i_flags & S_APPEND)
#define IS_DEADDIR(inode)	((inode)->i_flags & S_DEAD)
#define IS_DIRSYNC(inode)	(__IS_FLG(inode, MS_SYNCHRONOUS|MS_DIRSYNC) || \
					((inode)->i_flags & (S_SYNC|S_DIRSYNC)))
#define IS_IMMUTABLE(inode)	((inode)->i_flags & S_IMMUTABLE)
#define IS_I_VERSION(inode)   __IS_FLG(inode, MS_I_VERSION)
#define IS_MANDLOCK(inode)	__IS_FLG(inode, MS_MANDLOCK)
#define IS_NOATIME(inode)   __IS_FLG(inode, MS_RDONLY|MS_NOATIME)
#define IS_NOCMTIME(inode)	((inode)->i_flags & S_NOCMTIME)
#define IS_NOQUOTA(inode)	((inode)->i_flags & S_NOQUOTA)
#define IS_POSIXACL(inode)	__IS_FLG(inode, MS_POSIXACL)
#define IS_PRIVATE(inode)	((inode)->i_flags & S_PRIVATE)
#define IS_RDONLY(inode) ((inode)->i_sb->s_flags & MS_RDONLY)
#define IS_SWAPFILE(inode)	((inode)->i_flags & S_SWAPFILE)
#define IS_SYNC(inode)		(__IS_FLG(inode, MS_SYNCHRONOUS) || \
					((inode)->i_flags & S_SYNC))
#define I_DIRTY (I_DIRTY_SYNC | I_DIRTY_DATASYNC | I_DIRTY_PAGES)
#define MAX_LFS_FILESIZE 	0x7fffffffffffffffUL
#define MAY_ACCESS 16
#define MAY_APPEND 8
#define MAY_CHDIR 64
#define MAY_EXEC 1
#define MAY_OPEN 32
#define MAY_READ 4
#define MAY_WRITE 2
#define MS_MGC_MSK 0xffff0000
#define MS_MGC_VAL 0xC0ED0000
#define NR_FILE  8192	
#define OPEN_FMODE(flag) ((__force fmode_t)(((flag + 1) & O_ACCMODE) | \
					    (flag & FMODE_NONOTIFY)))
#define SIMPLE_TRANSACTION_LIMIT (PAGE_SIZE - sizeof(struct simple_transaction_argresp))

#define __IS_FLG(inode,flg) ((inode)->i_sb->s_flags & (flg))

#define __getname()		__getname_gfp(GFP_KERNEL)
#define __getname_gfp(gfp)	kmem_cache_alloc(names_cachep, (gfp))
#define __putname(name)		kmem_cache_free(names_cachep, (void *)(name))
#define bd_claim_by_disk(bdev, holder, disk)	bd_claim(bdev, holder)
#define bd_release_from_disk(bdev, disk)	bd_release(bdev)
#define bio_data_dir(bio)	((bio)->bi_rw & 1)
#define bio_rw(bio)		((bio)->bi_rw & (RW_MASK | RWA_MASK))
#define buffer_migrate_page NULL
#define file_count(x)	atomic_long_read(&(x)->f_count)
#define fops_get(fops) \
	(((fops) && try_module_get((fops)->owner) ? (fops) : NULL))
#define fops_put(fops) \
	do { if (fops) module_put((fops)->owner); } while(0)
#define fput_atomic(x)	atomic_long_add_unless(&(x)->f_count, -1, 1)
#define get_file(x)	atomic_long_inc(&(x)->f_count)
#define get_fs_excl() atomic_inc(&current->fs_excl)
#define has_fs_excl() atomic_read(&current->fs_excl)
#define i_size_ordered_init(inode) seqcount_init(&inode->i_size_seqcount)
#define is_owner_or_cap(inode)	\
	((current_fsuid() == (inode)->i_uid) || capable(CAP_FOWNER))
#define kern_mount(type) kern_mount_data(type, NULL)
#define lock_flocks() lock_kernel()
#define put_fs_excl() atomic_dec(&current->fs_excl)
#define putname(name)   __putname(name)
#define special_file(m) (S_ISCHR(m)||S_ISBLK(m)||S_ISFIFO(m)||S_ISSOCK(m))
#define unlock_flocks() unlock_kernel()
#define vfs_check_frozen(sb, level) \
	wait_event((sb)->s_wait_unfrozen, ((sb)->s_frozen < (level)))
#define IS_ERR_VALUE(x) unlikely((x) >= (unsigned long)-MAX_ERRNO)

#define IS_GETLK(cmd)	(IS_GETLK32(cmd)  || IS_GETLK64(cmd))
#define IS_GETLK32(cmd)		((cmd) == F_GETLK)
#define IS_GETLK64(cmd)		((cmd) == F_GETLK64)
#define IS_SETLK(cmd)	(IS_SETLK32(cmd)  || IS_SETLK64(cmd))
#define IS_SETLK32(cmd)		((cmd) == F_SETLK)
#define IS_SETLK64(cmd)		((cmd) == F_SETLK64)
#define IS_SETLKW(cmd)	(IS_SETLKW32(cmd) || IS_SETLKW64(cmd))
#define IS_SETLKW32(cmd)	((cmd) == F_SETLKW)
#define IS_SETLKW64(cmd)	((cmd) == F_SETLKW64)

#define force_o_largefile() (BITS_PER_LONG != 32)


#define RPC_MAX_AUTH_SIZE (400)
#define RPC_MAX_HEADER_WITH_AUTH \
	(RPC_CALLHDRSIZE + 2*(2+RPC_MAX_AUTH_SIZE/4))
#define RPC_VERSION 2


#define DQF_INFO_DIRTY (1 << DQF_INFO_DIRTY_B)	
#define DQF_INFO_DIRTY_B 16
#define DQF_MASK 0xffff		
#define DQUOT_DEL_ALLOC max(V1_DEL_ALLOC, V2_DEL_ALLOC)
#define DQUOT_DEL_REWRITE max(V1_DEL_REWRITE, V2_DEL_REWRITE)
#define DQUOT_INIT_ALLOC max(V1_INIT_ALLOC, V2_INIT_ALLOC)
#define DQUOT_INIT_REWRITE max(V1_INIT_REWRITE, V2_INIT_REWRITE)
#define GRPQUOTA  1		
#define INITQFNAMES { \
	"user",     \
	"group",    \
	"undefined", \
};
#define INIT_QUOTA_MODULE_NAMES {\
	{QFMT_VFS_OLD, "quota_v1",\
	{QFMT_VFS_V0, "quota_v2",\
	{0, NULL}}
#define MAXQUOTAS 2
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
#define Q_GETQUOTA 0x800007	
#define Q_QUOTAOFF 0x800003	
#define Q_QUOTAON  0x800002	
#define Q_SETINFO  0x800006	
#define Q_SETQUOTA 0x800008	
#define Q_SYNC     0x800001	
#define SUBCMDMASK  0x00ff
#define SUBCMDSHIFT 8
#define USRQUOTA  0		

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
#define V1_DQF_RSQUASH 1
#define V1_INIT_ALLOC 1
#define V1_INIT_REWRITE 1

#define FS_DQ_BHARD 	(1<<3)
#define FS_DQ_RTBTIMER 	(1<<8)
#define XQM_CMD(x)	(('X'<<8)+(x))	
#define XQM_COMMAND(x)	(((x) & (0xff<<8)) == ('X'<<8))	


#define percpu_counter_init(fbc, value)					\
	({								\
		static struct lock_class_key __key;			\
									\
		__percpu_counter_init(fbc, value, &__key);		\
	})

#define DECLARE_MUTEX(name)	\
	struct semaphore name = __SEMAPHORE_INITIALIZER(name, 1)
#define DEFINE_SEMAPHORE(name)	\
	struct semaphore name = __SEMAPHORE_INITIALIZER(name, 1)

#define __SEMAPHORE_INITIALIZER(name, n)				\
{									\
	.lock		= __SPIN_LOCK_UNLOCKED((name).lock),		\
	.count		= n,						\
	.wait_list	= LIST_HEAD_INIT((name).wait_list),		\
}
#define init_MUTEX(sem)		sema_init(sem, 1)
#define init_MUTEX_LOCKED(sem)	sema_init(sem, 0)
#define CAP_AUDIT_CONTROL    30
#define CAP_AUDIT_WRITE      29
#define CAP_BOP_ALL(c, a, b, OP)                                    \
do {                                                                \
	unsigned __capi;                                            \
	CAP_FOR_EACH_U32(__capi) {                                  \
		c.cap[__capi] = a.cap[__capi] OP b.cap[__capi];     \
	}                                                           \
} while (0)
#define CAP_CHOWN            0
#define CAP_DAC_OVERRIDE     1
#define CAP_DAC_READ_SEARCH  2
# define CAP_EMPTY_SET    ((kernel_cap_t){{ 0, 0 }})
#define CAP_FOR_EACH_U32(__capi)  \
	for (__capi = 0; __capi < _KERNEL_CAPABILITY_U32S; ++__capi)
#define CAP_FOWNER           3
#define CAP_FSETID           4
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
# define CAP_FULL_SET     ((kernel_cap_t){{ ~0, ~0 }})
# define CAP_INIT_EFF_SET ((kernel_cap_t){{ ~CAP_TO_MASK(CAP_SETPCAP), ~0 }})
#define CAP_INIT_INH_SET    CAP_EMPTY_SET
#define CAP_IPC_LOCK         14
#define CAP_IPC_OWNER        15
#define CAP_KILL             5
#define CAP_LAST_CAP         CAP_MAC_ADMIN
#define CAP_LEASE            28
#define CAP_LINUX_IMMUTABLE  9
#define CAP_MAC_ADMIN        33
#define CAP_MAC_OVERRIDE     32
#define CAP_MKNOD            27
#define CAP_NET_ADMIN        12
#define CAP_NET_BIND_SERVICE 10
#define CAP_NET_BROADCAST    11
#define CAP_NET_RAW          13
# define CAP_NFSD_SET     ((kernel_cap_t){{ CAP_FS_MASK_B0 \
				    | CAP_TO_MASK(CAP_SYS_RESOURCE), \
				    CAP_FS_MASK_B1 } })
#define CAP_SETGID           6
#define CAP_SETPCAP          8
#define CAP_SETUID           7
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
#define CAP_UOP_ALL(c, a, OP)                                       \
do {                                                                \
	unsigned __capi;                                            \
	CAP_FOR_EACH_U32(__capi) {                                  \
		c.cap[__capi] = OP a.cap[__capi];                   \
	}                                                           \
} while (0)
#define VFS_CAP_U32             VFS_CAP_U32_2
#define VFS_CAP_U32_1           1
#define VFS_CAP_U32_2           2
#define XATTR_CAPS_SZ           XATTR_CAPS_SZ_2
#define XATTR_CAPS_SZ_1         (sizeof(__le32)*(1 + 2*VFS_CAP_U32_1))
#define XATTR_CAPS_SZ_2         (sizeof(__le32)*(1 + 2*VFS_CAP_U32_2))
#define _KERNEL_CAPABILITY_U32S    _LINUX_CAPABILITY_U32S_3
#define _KERNEL_CAPABILITY_VERSION _LINUX_CAPABILITY_VERSION_3
#define _KERNEL_CAP_T_SIZE     (sizeof(kernel_cap_t))

#define _LINUX_CAPABILITY_U32S     _LINUX_CAPABILITY_U32S_1
#define _LINUX_CAPABILITY_U32S_1     1
#define _LINUX_CAPABILITY_U32S_2     2
#define _LINUX_CAPABILITY_U32S_3     2
#define _LINUX_CAPABILITY_VERSION  _LINUX_CAPABILITY_VERSION_1
#define _LINUX_CAPABILITY_VERSION_1  0x19980330
#define _LINUX_CAPABILITY_VERSION_2  0x20071026  
#define _LINUX_CAPABILITY_VERSION_3  0x20080522
#define _USER_CAP_HEADER_SIZE  (sizeof(struct __user_cap_header_struct))
# define cap_clear(c)         do { (c) = __cap_empty_set; } while (0)
#define cap_lower(c, flag)  ((c).cap[CAP_TO_INDEX(flag)] &= ~CAP_TO_MASK(flag))
#define cap_raise(c, flag)  ((c).cap[CAP_TO_INDEX(flag)] |= CAP_TO_MASK(flag))
#define cap_raised(c, flag) ((c).cap[CAP_TO_INDEX(flag)] & CAP_TO_MASK(flag))
# define cap_set_full(c)      do { (c) = __cap_full_set; } while (0)
# define cap_set_init_eff(c)  do { (c) = __cap_init_eff_set; } while (0)
#define cap_valid(x) ((x) >= 0 && (x) <= CAP_LAST_CAP)
#define has_capability(t, cap) (security_real_capable((t), (cap)) == 0)
#define has_capability_noaudit(t, cap) \
	(security_real_capable_noaudit((t), (cap)) == 0)

#define do_each_pid_task(pid, type, task)				\
	do {								\
		struct hlist_node *pos___;				\
		if ((pid) != NULL)					\
			hlist_for_each_entry_rcu((task), pos___,	\
				&(pid)->tasks[type], pids[type].node) {
#define do_each_pid_thread(pid, type, task)				\
	do_each_pid_task(pid, type, task) {				\
		struct task_struct *tg___ = task;			\
		do {
#define while_each_pid_task(pid, type, task)				\
				if (type == PIDTYPE_PID)		\
					break;				\
			}						\
	} while (0)
#define while_each_pid_thread(pid, type, task)				\
		} while_each_thread(tg___, task);			\
		task = tg___;						\
	} while_each_pid_task(pid, type, task)
#define INIT_PRIO_TREE_ITER(ptr)	\
do {					\
	(ptr)->cur = NULL;		\
	(ptr)->mask = 0UL;		\
	(ptr)->value = 0UL;		\
	(ptr)->size_level = 0;		\
} while (0)
#define INIT_PRIO_TREE_NODE(ptr)				\
do {								\
	(ptr)->left = (ptr)->right = (ptr)->parent = (ptr);	\
} while (0)
#define INIT_PRIO_TREE_ROOT(ptr)	__INIT_PRIO_TREE_ROOT(ptr, 0)
#define INIT_RAW_PRIO_TREE_ROOT(ptr)	__INIT_PRIO_TREE_ROOT(ptr, 1)

#define __INIT_PRIO_TREE_ROOT(ptr, _raw)	\
do {					\
	(ptr)->prio_tree_node = NULL;	\
	(ptr)->index_bits = 1;		\
	(ptr)->raw = (_raw);		\
} while (0)
#define prio_tree_entry(ptr, type, member) \
       ((type *)((char *)(ptr)-(unsigned long)(&((type *)0)->member)))
#define raw_prio_tree_insert(root, node) \
	prio_tree_insert(root, (struct prio_tree_node *) (node))
#define raw_prio_tree_remove(root, node) \
	prio_tree_remove(root, (struct prio_tree_node *) (node))
#define raw_prio_tree_replace(root, old, node) \
	prio_tree_replace(root, (struct prio_tree_node *) (old), \
	    (struct prio_tree_node *) (node))
#define INIT_RADIX_TREE(root, mask)					\
do {									\
	(root)->height = 0;						\
	(root)->gfp_mask = (mask);					\
	(root)->rnode = NULL;						\
} while (0)
#define RADIX_TREE(name, mask) \
	struct radix_tree_root name = RADIX_TREE_INIT(mask)
#define RADIX_TREE_INIT(mask)	{					\
	.height = 0,							\
	.gfp_mask = (mask),						\
	.rnode = NULL,							\
}
#define RADIX_TREE_MAX_TAGS 3
#define RADIX_TREE_RETRY ((void *)-1UL)


#define DCACHE_AUTOFS_PENDING 0x0001    
#define DCACHE_NFSFS_RENAMED  0x0002    
#define DNAME_INLINE_LEN_MIN 32 
#define IS_ROOT(x) ((x) == (x)->d_parent)

#define init_name_hash()		0

#define __hlist_for_each_rcu(pos, head)			\
	for (pos = rcu_dereference((head)->first);	\
	     pos && ({ prefetch(pos->next); 1; });	\
	     pos = rcu_dereference(pos->next))
#define __list_for_each_rcu(pos, head) \
	for (pos = rcu_dereference_raw((head)->next); \
		pos != (head); \
		pos = rcu_dereference_raw(pos->next))
#define hlist_for_each_entry_continue_rcu(tpos, pos, member)		\
	for (pos = rcu_dereference((pos)->next);			\
	     pos && ({ prefetch(pos->next); 1; }) &&			\
	     ({ tpos = hlist_entry(pos, typeof(*tpos), member); 1; });  \
	     pos = rcu_dereference(pos->next))
#define hlist_for_each_entry_continue_rcu_bh(tpos, pos, member)		\
	for (pos = rcu_dereference_bh((pos)->next);			\
	     pos && ({ prefetch(pos->next); 1; }) &&			\
	     ({ tpos = hlist_entry(pos, typeof(*tpos), member); 1; });  \
	     pos = rcu_dereference_bh(pos->next))
#define hlist_for_each_entry_rcu(tpos, pos, head, member)		 \
	for (pos = rcu_dereference_raw((head)->first);			 \
		pos && ({ prefetch(pos->next); 1; }) &&			 \
		({ tpos = hlist_entry(pos, typeof(*tpos), member); 1; }); \
		pos = rcu_dereference_raw(pos->next))
#define hlist_for_each_entry_rcu_bh(tpos, pos, head, member)		 \
	for (pos = rcu_dereference_bh((head)->first);			 \
		pos && ({ prefetch(pos->next); 1; }) &&			 \
		({ tpos = hlist_entry(pos, typeof(*tpos), member); 1; }); \
		pos = rcu_dereference_bh(pos->next))
#define list_entry_rcu(ptr, type, member) \
	container_of(rcu_dereference_raw(ptr), type, member)
#define list_first_entry_rcu(ptr, type, member) \
	list_entry_rcu((ptr)->next, type, member)
#define list_for_each_continue_rcu(pos, head) \
	for ((pos) = rcu_dereference_raw((pos)->next); \
		prefetch((pos)->next), (pos) != (head); \
		(pos) = rcu_dereference_raw((pos)->next))
#define list_for_each_entry_continue_rcu(pos, head, member) 		\
	for (pos = list_entry_rcu(pos->member.next, typeof(*pos), member); \
	     prefetch(pos->member.next), &pos->member != (head);	\
	     pos = list_entry_rcu(pos->member.next, typeof(*pos), member))
#define list_for_each_entry_rcu(pos, head, member) \
	for (pos = list_entry_rcu((head)->next, typeof(*pos), member); \
		prefetch(pos->member.next), &pos->member != (head); \
		pos = list_entry_rcu(pos->member.next, typeof(*pos), member))
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
#define BIO_FS_INTEGRITY 10	
#define BIO_NULL_MAPPED 9	
#define BIO_POOL_IDX(bio)	((bio)->bi_flags >> BIO_POOL_OFFSET)
#define BIO_USER_MAPPED 6	
#define REQ_COMMON_MASK \
	(REQ_WRITE | REQ_FAILFAST_MASK | REQ_HARDBARRIER | REQ_SYNC | \
	 REQ_META| REQ_DISCARD | REQ_NOIDLE)
#define REQ_FAILFAST_MASK \
	(REQ_FAILFAST_DEV | REQ_FAILFAST_TRANSPORT | REQ_FAILFAST_DRIVER)

#define bio_flagged(bio, flag)	((bio)->bi_flags & (1 << (flag)))

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

#define CALC_LOAD(load,exp,n) \
	load *= exp; \
	load += n*(FIXED_1-exp); \
	load >>= FSHIFT;
#define INIT_USER (&root_user)
# define MAX_LOCK_DEPTH 48UL
#define MMF_DUMPABLE      0  
#define MMF_DUMPABLE_BITS 2
#define MMF_DUMPABLE_MASK ((1 << MMF_DUMPABLE_BITS) - 1)
#define MMF_DUMP_FILTER_DEFAULT \
	((1 << MMF_DUMP_ANON_PRIVATE) |	(1 << MMF_DUMP_ANON_SHARED) |\
	 (1 << MMF_DUMP_HUGETLB_PRIVATE) | MMF_DUMP_MASK_DEFAULT_ELF)
#define MMF_DUMP_FILTER_MASK \
	(((1 << MMF_DUMP_FILTER_BITS) - 1) << MMF_DUMP_FILTER_SHIFT)
#define MMF_DUMP_HUGETLB_PRIVATE 7
#define MMF_DUMP_HUGETLB_SHARED  8
#define MMF_DUMP_SECURELY 1  
#define PF_FREEZER_NOSIG 0x80000000	
#define PF_LESS_THROTTLE 0x00100000	
#define PF_MCE_EARLY    0x08000000      
#define PF_MCE_PROCESS  0x00000080      
#define RCU_READ_UNLOCK_BLOCKED (1 << 0) 
#define RCU_READ_UNLOCK_NEED_QS (1 << 1) 
#define SCHED_RESET_ON_FORK     0x40000000
#define SEND_SIG_NOINFO ((struct siginfo *) 0)
#define TASK_COMM_LEN 16
#define TASK_SIZE_OF(tsk)	TASK_SIZE
#define TASK_STATE_TO_CHAR_STR "RSDTtZXxKW"

# define __ARCH_WANT_UNLOCKED_CTXSW
#define __set_current_state(state_value)			\
	do { current->state = (state_value); } while (0)
#define __set_task_state(tsk, state_value)		\
	do { (tsk)->state = (state_value); } while (0)
#define clear_stopped_child_used_math(child) do { (child)->flags &= ~PF_USED_MATH; } while (0)
#define clear_used_math() clear_stopped_child_used_math(current)
#define cond_resched() ({			\
	__might_sleep("__FILE__", "__LINE__", 0);	\
	_cond_resched();			\
})
#define cond_resched_lock(lock) ({				\
	__might_sleep("__FILE__", "__LINE__", PREEMPT_LOCK_OFFSET);	\
	__cond_resched_lock(lock);				\
})
#define cond_resched_softirq() ({				\
	__might_sleep("__FILE__", "__LINE__", SOFTIRQ_OFFSET);	\
	__cond_resched_softirq();				\
})
#define conditional_stopped_child_used_math(condition, child) \
	do { (child)->flags &= ~PF_USED_MATH, (child)->flags |= (condition) ? PF_USED_MATH : 0; } while (0)
#define conditional_used_math(condition) \
	conditional_stopped_child_used_math(condition, current)
#define copy_to_stopped_child_used_math(child) \
	do { (child)->flags &= ~PF_USED_MATH, (child)->flags |= current->flags & PF_USED_MATH; } while (0)
#define delay_group_leader(p) \
		(thread_group_leader(p) && !thread_group_empty(p))
#define do_each_thread(g, t) \
	for (g = t = &init_task ; (g = t = next_task(g)) != &init_task ; ) do
#define for_each_process(p) \
	for (p = &init_task ; (p = next_task(p)) != &init_task ; )
#define get_task_struct(tsk) do { atomic_inc(&(tsk)->usage); } while(0)
#define next_task(p) \
	list_entry_rcu((p)->tasks.next, struct task_struct, tasks)
# define rt_mutex_adjust_pi(p)		do { } while (0)
#define sched_exec()   {}
#define set_current_state(state_value)		\
	set_mb(current->state, (state_value))
#define set_stopped_child_used_math(child) do { (child)->flags |= PF_USED_MATH; } while (0)
#define set_task_state(tsk, state_value)		\
	set_mb((tsk)->state, (state_value))
#define set_used_math() set_stopped_child_used_math(current)
#define task_contributes_to_load(task)	\
				((task->state & TASK_UNINTERRUPTIBLE) != 0 && \
				 (task->flags & PF_FREEZING) == 0)
#define task_is_dead(task)	((task)->exit_state != 0)
#define task_is_stopped(task)	((task->state & __TASK_STOPPED) != 0)
#define task_is_stopped_or_traced(task)	\
			((task->state & (__TASK_STOPPED | __TASK_TRACED)) != 0)
#define task_is_traced(task)	((task->state & __TASK_TRACED) != 0)
#define task_stack_page(task)	((task)->stack)
#define task_thread_info(task)	((struct thread_info *)(task)->stack)
#define thread_group_leader(p)	(p == p->group_leader)
#define tsk_cpus_allowed(tsk) (&(tsk)->cpus_allowed)
#define tsk_used_math(p) ((p)->flags & PF_USED_MATH)
#define used_math() tsk_used_math(current)
#define while_each_thread(g, t) \
	while ((t = next_thread(t)) != g)

#define aio_ring_avail(info, ring)	(((ring)->head + (info)->nr - 1 - (ring)->tail) % (info)->nr)
#define init_sync_kiocb(x, filp)			\
	do {						\
		struct task_struct *tsk = current;	\
		(x)->ki_flags = 0;			\
		(x)->ki_users = 1;			\
		(x)->ki_key = KIOCB_SYNC_KEY;		\
		(x)->ki_filp = (filp);			\
		(x)->ki_ctx = NULL;			\
		(x)->ki_cancel = NULL;			\
		(x)->ki_retry = NULL;			\
		(x)->ki_dtor = NULL;			\
		(x)->ki_obj.tsk = tsk;			\
		(x)->ki_user_data = 0;                  \
	} while (0)
#define is_sync_kiocb(iocb)	((iocb)->ki_key == KIOCB_SYNC_KEY)
#define kiocbClearCancelled(iocb)	clear_bit(KIF_CANCELLED, &(iocb)->ki_flags)
#define kiocbClearKicked(iocb)	clear_bit(KIF_KICKED, &(iocb)->ki_flags)
#define kiocbClearLocked(iocb)	clear_bit(KIF_LOCKED, &(iocb)->ki_flags)
#define kiocbIsCancelled(iocb)	test_bit(KIF_CANCELLED, &(iocb)->ki_flags)
#define kiocbIsKicked(iocb)	test_bit(KIF_KICKED, &(iocb)->ki_flags)
#define kiocbIsLocked(iocb)	test_bit(KIF_LOCKED, &(iocb)->ki_flags)
#define kiocbSetCancelled(iocb)	set_bit(KIF_CANCELLED, &(iocb)->ki_flags)
#define kiocbSetKicked(iocb)	set_bit(KIF_KICKED, &(iocb)->ki_flags)
#define kiocbSetLocked(iocb)	set_bit(KIF_LOCKED, &(iocb)->ki_flags)
#define kiocbTryKick(iocb)	test_and_set_bit(KIF_KICKED, &(iocb)->ki_flags)
#define kiocbTryLock(iocb)	test_and_set_bit(KIF_LOCKED, &(iocb)->ki_flags)

#define PADDED(x,y)	x, y

#define GROUP_AT(gi, i) \
	((gi)->blocks[(i) / NGROUPS_PER_BLOCK][(i) % NGROUPS_PER_BLOCK])

#define __task_cred(task)						\
	({								\
		const struct task_struct *__t = (task);			\
		rcu_dereference_check(__t->real_cred,			\
				      rcu_read_lock_held() ||		\
				      task_is_dead(__t));		\
	})
#define current_cap()		(current_cred_xxx(cap_effective))
#define current_cred() \
	(current->cred)
#define current_cred_xxx(xxx)			\
({						\
	current->cred->xxx;			\
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
#define current_security()	(current_cred_xxx(security))
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
#define current_user_ns()	(current_cred_xxx(user)->user_ns)
#define get_current_cred()				\
	(get_cred(current_cred()))
#define get_current_groups()				\
({							\
	struct group_info *__groups;			\
	struct cred *__cred;				\
	__cred = (struct cred *) current_cred();	\
	__groups = get_group_info(__cred->group_info);	\
	__groups;					\
})
#define get_current_user()				\
({							\
	struct user_struct *__u;			\
	struct cred *__cred;				\
	__cred = (struct cred *) current_cred();	\
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


#define is_key_possessed(k)		0
#define key_fsgid_changed(t)		do { } while(0)
#define key_fsuid_changed(t)		do { } while(0)
#define key_get(k) 			({ NULL; })
#define key_init()			do { } while(0)
#define key_put(k)			do { } while(0)
#define key_ref_put(k)			do { } while(0)
#define key_ref_to_ptr(k)		NULL
#define key_replace_session_keyring()	do { } while(0)
#define key_revoke(k)			do { } while(0)
#define key_serial(k)			0
#define key_validate(k)			0
#define make_key_ref(k, p)		NULL
#define CTL_MAXNAME 10		

#define RB_CLEAR_NODE(node)	(rb_set_parent(node, node))
#define RB_EMPTY_NODE(node)	(rb_parent(node) == node)
#define RB_EMPTY_ROOT(root)	((root)->rb_node == NULL)
#define rb_color(r)   ((r)->rb_parent_color & 1)
#define rb_is_black(r) rb_color(r)
#define rb_is_red(r)   (!rb_color(r))
#define rb_parent(r)   ((struct rb_node *)((r)->rb_parent_color & ~3))
#define rb_set_black(r)  do { (r)->rb_parent_color |= 1; } while (0)
#define rb_set_red(r)  do { (r)->rb_parent_color &= ~1; } while (0)

#define HRTIMER_MAX_CLOCK_BASES 2

# define ktime_divns(kt, div)		(u64)((kt).tv64 / (div))

#define DEFINE_RT_MUTEX(mutexname) \
	struct rt_mutex mutexname = __RT_MUTEX_INITIALIZER(mutexname)
# define INIT_RT_MUTEXES(tsk)						\
	.pi_waiters	= PLIST_HEAD_INIT(tsk.pi_waiters, tsk.pi_lock),	\
	INIT_RT_MUTEX_DEBUG(tsk)
# define __DEBUG_RT_MUTEX_INITIALIZER(mutexname) \
	, .name = #mutexname, .file = "__FILE__", .line = "__LINE__"

#define __RT_MUTEX_INITIALIZER(mutexname) \
	{ .wait_lock = __RAW_SPIN_LOCK_UNLOCKED(mutexname.wait_lock) \
	, .wait_list = PLIST_HEAD_INIT_RAW(mutexname.wait_list, mutexname.wait_lock) \
	, .owner = NULL \
	__DEBUG_RT_MUTEX_INITIALIZER(mutexname)}
# define rt_mutex_debug_check_no_locks_held(task)	do { } while (0)
# define rt_mutex_debug_task_free(t)			do { } while (0)
# define rt_mutex_init(mutex)			__rt_mutex_init(mutex, __func__)
#define PLIST_HEAD_INIT(head, _lock)			\
{							\
	_PLIST_HEAD_INIT(head),				\
	PLIST_HEAD_LOCK_INIT(&(_lock))			\
}
#define PLIST_HEAD_INIT_RAW(head, _lock)		\
{							\
	_PLIST_HEAD_INIT(head),				\
	PLIST_HEAD_LOCK_INIT_RAW(&(_lock))		\
}
# define PLIST_HEAD_LOCK_INIT(_lock)		.spinlock = _lock
# define PLIST_HEAD_LOCK_INIT_RAW(_lock)	.rawlock = _lock
#define PLIST_NODE_INIT(node, __prio)			\
{							\
	.prio  = (__prio),				\
	.plist = { _PLIST_HEAD_INIT((node).plist) },	\
}

#define _PLIST_HEAD_INIT(head)				\
	.prio_list = LIST_HEAD_INIT((head).prio_list),	\
	.node_list = LIST_HEAD_INIT((head).node_list)
# define plist_first_entry(head, type, member)	\
({ \
	WARN_ON(plist_head_empty(head)); \
	container_of(plist_first(head), type, member); \
})
#define plist_for_each(pos, head)	\
	 list_for_each_entry(pos, &(head)->node_list, plist.node_list)
#define plist_for_each_entry(pos, head, mem)	\
	 list_for_each_entry(pos, &(head)->node_list, mem.plist.node_list)
#define plist_for_each_entry_safe(pos, n, head, m)	\
	list_for_each_entry_safe(pos, n, &(head)->node_list, m.plist.node_list)
#define plist_for_each_safe(pos, n, head)	\
	 list_for_each_entry_safe(pos, n, &(head)->node_list, plist.node_list)
# define plist_last_entry(head, type, member)	\
({ \
	WARN_ON(plist_head_empty(head)); \
	container_of(plist_last(head), type, member); \
})

#define secure_computing(x) do { } while (0)
#define INIT_PROP_LOCAL_SINGLE(name)			\
{	.lock = __SPIN_LOCK_UNLOCKED(name.lock),	\
}
#define PROP_MAX_SHIFT (3*BITS_PER_LONG/4)

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

#define _SIG_SET_BINOP(name, op)					\
static inline void name(sigset_t *r, const sigset_t *a, const sigset_t *b) \
{									\
	extern void _NSIG_WORDS_is_unsupported_size(void);		\
	unsigned long a0, a1, a2, a3, b0, b1, b2, b3;			\
									\
	switch (_NSIG_WORDS) {						\
	    case 4:							\
		a3 = a->sig[3]; a2 = a->sig[2];				\
		b3 = b->sig[3]; b2 = b->sig[2];				\
		r->sig[3] = op(a3, b3);					\
		r->sig[2] = op(a2, b2);					\
	    case 2:							\
		a1 = a->sig[1]; b1 = b->sig[1];				\
		r->sig[1] = op(a1, b1);					\
	    case 1:							\
		a0 = a->sig[0]; b0 = b->sig[0];				\
		r->sig[0] = op(a0, b0);					\
		break;							\
	    default:							\
		_NSIG_WORDS_is_unsupported_size();			\
	}								\
}
#define _SIG_SET_OP(name, op)						\
static inline void name(sigset_t *set)					\
{									\
	extern void _NSIG_WORDS_is_unsupported_size(void);		\
									\
	switch (_NSIG_WORDS) {						\
	    case 4: set->sig[3] = op(set->sig[3]);			\
		    set->sig[2] = op(set->sig[2]);			\
	    case 2: set->sig[1] = op(set->sig[1]);			\
	    case 1: set->sig[0] = op(set->sig[0]);			\
		    break;						\
	    default:							\
		_NSIG_WORDS_is_unsupported_size();			\
	}								\
}
#define _sig_and(x,y)	((x) & (y))
#define _sig_nand(x,y)	((x) & ~(y))
#define _sig_not(x)	(~(x))
#define _sig_or(x,y)	((x) | (y))
#define rt_sigmask(sig)	(1ULL << ((sig)-1))
#define sig_fatal(t, signr) \
	(!siginmask(signr, SIG_KERNEL_IGNORE_MASK|SIG_KERNEL_STOP_MASK) && \
	 (t)->sighand->action[(signr)-1].sa.sa_handler == SIG_DFL)
#define sig_kernel_coredump(sig) \
	(((sig) < SIGRTMIN) && siginmask(sig, SIG_KERNEL_COREDUMP_MASK))
#define sig_kernel_ignore(sig) \
	(((sig) < SIGRTMIN) && siginmask(sig, SIG_KERNEL_IGNORE_MASK))
#define sig_kernel_only(sig) \
	(((sig) < SIGRTMIN) && siginmask(sig, SIG_KERNEL_ONLY_MASK))
#define sig_kernel_stop(sig) \
	(((sig) < SIGRTMIN) && siginmask(sig, SIG_KERNEL_STOP_MASK))
#define sig_user_defined(t, signr) \
	(((t)->sighand->action[(signr)-1].sa.sa_handler != SIG_DFL) &&	\
	 ((t)->sighand->action[(signr)-1].sa.sa_handler != SIG_IGN))
#define siginmask(sig, mask) (rt_sigmask(sig) & (mask))
#define sigmask(sig)	(1UL << ((sig) - 1))
#define GETALL  13       
#define GETNCNT 14       
#define GETPID  11       
#define GETVAL  12       
#define GETZCNT 15       
#define SEMAEM  SEMVMX          
#define SEMMAP  SEMMNS          
#define SEMMNI  128             
#define SEMMNS  (SEMMNI*SEMMSL) 
#define SEMMNU  SEMMNS          
#define SEMMSL  250             
#define SEMOPM  32	        
#define SEMUME  SEMOPM          
#define SEMUSZ  20		
#define SEMVMX  32767           
#define SEM_INFO 19
#define SEM_STAT 18
#define SEM_UNDO        0x1000  
#define SETALL  17       
#define SETVAL  16       

#define DIPC            25
#define IPCCALL(version,op)	((version)<<16 | (op))
#define IPCMNI 32768  
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

#define AT_VECTOR_SIZE (2*(AT_VECTOR_SIZE_ARCH + AT_VECTOR_SIZE_BASE + 1))
#define AT_VECTOR_SIZE_ARCH 0


#define mm_cpumask(mm) (&(mm)->cpu_vm_mask)
#define  LINUX_PAGE_DEBUG_FLAGS_H
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
#define AT_VECTOR_SIZE_BASE 19 

#define KSYM_NAME_LEN 128
#define KSYM_SYMBOL_LEN (sizeof("%s+%#lx/%#lx [%s]") + (KSYM_NAME_LEN - 1) + \
			 2*(BITS_PER_LONG*3/10) + (MODULE_NAME_LEN - 1) + 1)

#define __print_symbol(fmt, addr)

#define PIDMAP_ENTRIES         ((PID_MAX_LIMIT + 8*PAGE_SIZE - 1)/PAGE_SIZE/8)


#define DEFAULT_SEEKS 2 


#define PAGE_ALIGN(addr) ALIGN(addr, PAGE_SIZE)
#define PFN_SECTION_SHIFT 0
#define VM_CAN_NONLINEAR 0x08000000	
#define VM_ClearReadHint(v)		(v)->vm_flags &= ~VM_READHINTMASK
#define VM_FAULT_HWPOISON 0x0010	
#define VM_IO           0x00004000	
#define VM_NormalReadHint(v)		(!((v)->vm_flags & VM_READHINTMASK))
#define VM_RandomReadHint(v)		((v)->vm_flags & VM_RAND_READ)
#define VM_SPECIAL (VM_IO | VM_DONTEXPAND | VM_RESERVED | VM_PFNMAP)
#define VM_STACK_DEFAULT_FLAGS VM_DATA_DEFAULT_FLAGS
#define VM_SequentialReadHint(v)	((v)->vm_flags & VM_SEQ_READ)

#define __pte_lockptr(page)	&((page)->ptl)
  #define expand_upwards(vma, address) do { } while (0)
#define in_gate_area(task, addr) ({(void)task; in_gate_area_no_task(addr);})
#define nth_page(page,n) pfn_to_page(page_to_pfn((page)) + (n))
#define offset_in_page(p)	((unsigned long)(p) & ~PAGE_MASK)
#define page_address(page) ((page)->virtual)
#define page_address_init()  do { } while(0)
#define page_private(page)		((page)->private)
#define pte_alloc_kernel(pmd, address)			\
	((unlikely(!pmd_present(*(pmd))) && __pte_alloc_kernel(pmd, address))? \
		NULL: pte_offset_kernel(pmd, address))
#define pte_alloc_map(mm, pmd, address)			\
	((unlikely(!pmd_present(*(pmd))) && __pte_alloc(mm, pmd, address))? \
		NULL: pte_offset_map(pmd, address))
#define pte_alloc_map_lock(mm, pmd, address, ptlp)	\
	((unlikely(!pmd_present(*(pmd))) && __pte_alloc(mm, pmd, address))? \
		NULL: pte_offset_map_lock(mm, pmd, address, ptlp))
#define pte_lock_deinit(page)	((page)->mapping = NULL)
#define pte_lock_init(_page)	do {					\
	spin_lock_init(__pte_lockptr(_page));				\
} while (0)
#define pte_lockptr(mm, pmd)	({(void)(mm); __pte_lockptr(pmd_page(*(pmd)));})
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
#define randomize_va_space 0
#define set_page_address(page, address)			\
	do {						\
		(page)->virtual = (address);		\
	} while(0)
#define set_page_private(page, v)	((page)->private = (v))
#define sysctl_legacy_va_layout 0
#define vma_prio_tree_foreach(vma, iter, root, begin, end)	\
	for (prio_tree_iter_init(iter, root, begin, end), vma = NULL;	\
		(vma = vma_prio_tree_next(vma, iter)); )
#define DMA32_ZONE(xx) xx##_DMA32,
#define DMA_ZONE(xx) xx##_DMA,
#define FOR_ALL_ZONES(xx) DMA_ZONE(xx) DMA32_ZONE(xx) xx##_NORMAL HIGHMEM_ZONE(xx) , xx##_MOVABLE
#define HIGHMEM_ZONE(xx) , xx##_HIGH

#define __count_zone_vm_events(item, zone, delta) \
		__count_vm_events(item##_NORMAL - ZONE_NORMAL + \
		zone_idx(zone), delta)
#define add_zone_page_state(__z, __i, __d) mod_zone_page_state(__z, __i, __d)
#define dec_zone_page_state __dec_zone_page_state
#define inc_zone_page_state __inc_zone_page_state
#define mod_zone_page_state __mod_zone_page_state
#define node_page_state(node, item) global_page_state(item)
#define sub_zone_page_state(__z, __i, __d) mod_zone_page_state(__z, __i, -(__d))
#define zone_statistics(_zl,_z) do { } while (0)
#define CLEARPAGEFLAG(uname, lname)					\
static inline void ClearPage##uname(struct page *page)			\
			{ clear_bit(PG_##lname, &page->flags); }
#define CLEARPAGEFLAG_NOOP(uname)					\
static inline void ClearPage##uname(struct page *page) {  }
#define PAGEFLAG(uname, lname) TESTPAGEFLAG(uname, lname)		\
	SETPAGEFLAG(uname, lname) CLEARPAGEFLAG(uname, lname)
#define PAGEFLAG_FALSE(uname) 						\
static inline int Page##uname(struct page *page) 			\
			{ return 0; }
#define PAGE_FLAGS_CHECK_AT_FREE \
	(1 << PG_lru	 | 1 << PG_locked    | \
	 1 << PG_private | 1 << PG_private_2 | \
	 1 << PG_buddy	 | 1 << PG_writeback | 1 << PG_reserved | \
	 1 << PG_slab	 | 1 << PG_swapcache | 1 << PG_active | \
	 1 << PG_unevictable | __PG_MLOCKED | __PG_HWPOISON)

#define PG_head_tail_mask ((1L << PG_compound) | (1L << PG_reclaim))
#define PageHighMem(__p) is_highmem(page_zone(__p))
#define SETPAGEFLAG(uname, lname)					\
static inline void SetPage##uname(struct page *page)			\
			{ set_bit(PG_##lname, &page->flags); }
#define SETPAGEFLAG_NOOP(uname)						\
static inline void SetPage##uname(struct page *page) {  }
#define TESTCLEARFLAG(uname, lname)					\
static inline int TestClearPage##uname(struct page *page)		\
		{ return test_and_clear_bit(PG_##lname, &page->flags); }
#define TESTCLEARFLAG_FALSE(uname)					\
static inline int TestClearPage##uname(struct page *page) { return 0; }
#define TESTPAGEFLAG(uname, lname)					\
static inline int Page##uname(struct page *page) 			\
			{ return test_bit(PG_##lname, &page->flags); }
#define TESTSCFLAG(uname, lname)					\
	TESTSETFLAG(uname, lname) TESTCLEARFLAG(uname, lname)
#define TESTSETFLAG(uname, lname)					\
static inline int TestSetPage##uname(struct page *page)			\
		{ return test_and_set_bit(PG_##lname, &page->flags); }
#define __CLEARPAGEFLAG(uname, lname)					\
static inline void __ClearPage##uname(struct page *page)		\
			{ __clear_bit(PG_##lname, &page->flags); }
#define __CLEARPAGEFLAG_NOOP(uname)					\
static inline void __ClearPage##uname(struct page *page) {  }
#define __PAGEFLAG(uname, lname) TESTPAGEFLAG(uname, lname)		\
	__SETPAGEFLAG(uname, lname)  __CLEARPAGEFLAG(uname, lname)
#define __PG_HWPOISON (1UL << PG_hwpoison)
#define __SETPAGEFLAG(uname, lname)					\
static inline void __SetPage##uname(struct page *page)			\
			{ __set_bit(PG_##lname, &page->flags); }
#define __TESTCLEARFLAG(uname, lname)					\
static inline int __TestClearPage##uname(struct page *page)		\
		{ return __test_and_clear_bit(PG_##lname, &page->flags); }
#define __TESTCLEARFLAG_FALSE(uname)					\
static inline int __TestClearPage##uname(struct page *page) { return 0; }
#define MAX_RESOURCE ((resource_size_t)~0)

# define IRQ_EXIT_OFFSET (HARDIRQ_OFFSET-1)

#define MAX_HARDIRQ_BITS 10
# define PREEMPT_CHECK_OFFSET 0
# define PREEMPT_INATOMIC_BASE kernel_locked()
#define __IRQ_MASK(x)	((1UL << (x))-1)
#define __irq_enter()					\
	do {						\
		account_system_vtime(current);		\
		add_preempt_count(HARDIRQ_OFFSET);	\
		trace_hardirq_enter();			\
	} while (0)
#define __irq_exit()					\
	do {						\
		trace_hardirq_exit();			\
		account_system_vtime(current);		\
		sub_preempt_count(HARDIRQ_OFFSET);	\
	} while (0)
#define hardirq_count()	(preempt_count() & HARDIRQ_MASK)
#define in_atomic()	((preempt_count() & ~PREEMPT_ACTIVE) != PREEMPT_INATOMIC_BASE)
#define in_atomic_preempt_off() \
		((preempt_count() & ~PREEMPT_ACTIVE) != PREEMPT_CHECK_OFFSET)
#define in_interrupt()		(irq_count())
#define in_irq()		(hardirq_count())
#define in_nmi()	(preempt_count() & NMI_MASK)
#define in_softirq()		(softirq_count())
#define irq_count()	(preempt_count() & (HARDIRQ_MASK | SOFTIRQ_MASK \
				 | NMI_MASK))
#define nmi_enter()						\
	do {							\
		ftrace_nmi_enter();				\
		BUG_ON(in_nmi());				\
		add_preempt_count(NMI_OFFSET + HARDIRQ_OFFSET);	\
		lockdep_off();					\
		rcu_nmi_enter();				\
		trace_hardirq_enter();				\
	} while (0)
#define nmi_exit()						\
	do {							\
		trace_hardirq_exit();				\
		rcu_nmi_exit();					\
		lockdep_on();					\
		BUG_ON(!in_nmi());				\
		sub_preempt_count(NMI_OFFSET + HARDIRQ_OFFSET);	\
		ftrace_nmi_exit();				\
	} while (0)
# define preemptible()	(preempt_count() == 0 && !irqs_disabled())
# define rcu_irq_enter() do { } while (0)
# define rcu_irq_exit() do { } while (0)
# define rcu_nmi_enter() do { } while (0)
# define rcu_nmi_exit() do { } while (0)
#define softirq_count()	(preempt_count() & SOFTIRQ_MASK)
# define synchronize_irq(irq)	barrier()


#define cycle_kernel_lock()			do { } while(0)
#define kernel_locked()				1
#define lock_kernel() do {					\
	_lock_kernel(__func__, "__FILE__", "__LINE__");		\
} while (0)
#define reacquire_kernel_lock(task)		0
#define release_kernel_lock(tsk) do { 		\
	if (unlikely((tsk)->lock_depth >= 0))	\
		__release_kernel_lock();	\
} while (0)
#define unlock_kernel()	do {					\
	_unlock_kernel(__func__, "__FILE__", "__LINE__");		\
} while (0)


#define ring_buffer_alloc(size, flags)			\
({							\
	static struct lock_class_key __key;		\
	__ring_buffer_alloc((size), (flags), &__key);	\
})
#define SEQ_SKIP 1
#define SEQ_START_TOKEN ((void *)1)


#define kmemcheck_annotate_bitfield(ptr, name)	\
	do {					\
	} while (0)
#define kmemcheck_annotate_variable(var)	\
	do {					\
	} while (0)


#define kmemcheck_enabled 0

#define INTERCEPT_CR0_MASK 1
#define INTERCEPT_CR3_MASK (1 << 3)
#define INTERCEPT_CR4_MASK (1 << 4)
#define INTERCEPT_CR8_MASK (1 << 8)
#define INTERCEPT_DR0_MASK 1
#define INTERCEPT_DR1_MASK (1 << 1)
#define INTERCEPT_DR2_MASK (1 << 2)
#define INTERCEPT_DR3_MASK (1 << 3)
#define INTERCEPT_DR4_MASK (1 << 4)
#define INTERCEPT_DR5_MASK (1 << 5)
#define INTERCEPT_DR6_MASK (1 << 6)
#define INTERCEPT_DR7_MASK (1 << 7)
#define SVM_CLGI   ".byte 0x0f, 0x01, 0xdd"
#define SVM_CPUID_FEATURE_SHIFT 2
#define SVM_CPUID_FUNC 0x8000000a
#define SVM_CR0_SELECTIVE_MASK (X86_CR0_TS | X86_CR0_MP)
#define SVM_EVTINJ_TYPE_EXEPT (3 << SVM_EVTINJ_TYPE_SHIFT)
#define SVM_EVTINJ_TYPE_INTR (0 << SVM_EVTINJ_TYPE_SHIFT)
#define SVM_EVTINJ_TYPE_MASK (7 << SVM_EVTINJ_TYPE_SHIFT)
#define SVM_EVTINJ_TYPE_NMI (2 << SVM_EVTINJ_TYPE_SHIFT)
#define SVM_EVTINJ_TYPE_SHIFT 8
#define SVM_EVTINJ_TYPE_SOFT (4 << SVM_EVTINJ_TYPE_SHIFT)
#define SVM_EVTINJ_VALID (1 << 31)
#define SVM_EVTINJ_VALID_ERR (1 << 11)
#define SVM_EVTINJ_VEC_MASK 0xff
#define SVM_EXITINFOSHIFT_TS_HAS_ERROR_CODE 44
#define SVM_EXITINFOSHIFT_TS_REASON_IRET 36
#define SVM_EXITINFOSHIFT_TS_REASON_JMP 38
#define SVM_EXITINTINFO_TYPE_MASK SVM_EVTINJ_TYPE_MASK
#define SVM_EXITINTINFO_VALID SVM_EVTINJ_VALID
#define SVM_EXITINTINFO_VALID_ERR SVM_EVTINJ_VALID_ERR
#define SVM_EXITINTINFO_VEC_MASK SVM_EVTINJ_VEC_MASK
#define SVM_EXIT_EXCP_BASE      0x040
#define SVM_EXIT_NPF  		0x400
#define SVM_INTERRUPT_SHADOW_MASK 1
#define SVM_INVLPGA ".byte 0x0f, 0x01, 0xdf"
#define SVM_IOIO_ASIZE_MASK (7 << SVM_IOIO_ASIZE_SHIFT)
#define SVM_IOIO_ASIZE_SHIFT 7
#define SVM_IOIO_REP_MASK (1 << SVM_IOIO_REP_SHIFT)
#define SVM_IOIO_REP_SHIFT 3
#define SVM_IOIO_SIZE_MASK (7 << SVM_IOIO_SIZE_SHIFT)
#define SVM_IOIO_SIZE_SHIFT 4
#define SVM_IOIO_STR_MASK (1 << SVM_IOIO_STR_SHIFT)
#define SVM_IOIO_STR_SHIFT 2
#define SVM_IOIO_TYPE_MASK 1
#define SVM_SELECTOR_AVL_MASK (1 << SVM_SELECTOR_AVL_SHIFT)
#define SVM_SELECTOR_AVL_SHIFT 8
#define SVM_SELECTOR_CODE_MASK (1 << 3)
#define SVM_SELECTOR_DB_MASK (1 << SVM_SELECTOR_DB_SHIFT)
#define SVM_SELECTOR_DB_SHIFT 10
#define SVM_SELECTOR_DPL_MASK (3 << SVM_SELECTOR_DPL_SHIFT)
#define SVM_SELECTOR_DPL_SHIFT 5
#define SVM_SELECTOR_G_MASK (1 << SVM_SELECTOR_G_SHIFT)
#define SVM_SELECTOR_G_SHIFT 11
#define SVM_SELECTOR_L_MASK (1 << SVM_SELECTOR_L_SHIFT)
#define SVM_SELECTOR_L_SHIFT 9
#define SVM_SELECTOR_P_MASK (1 << SVM_SELECTOR_P_SHIFT)
#define SVM_SELECTOR_P_SHIFT 7
#define SVM_SELECTOR_READ_MASK SVM_SELECTOR_WRITE_MASK
#define SVM_SELECTOR_S_MASK (1 << SVM_SELECTOR_S_SHIFT)
#define SVM_SELECTOR_S_SHIFT 4
#define SVM_SELECTOR_TYPE_MASK (0xf)
#define SVM_SELECTOR_WRITE_MASK (1 << 1)
#define SVM_STGI   ".byte 0x0f, 0x01, 0xdc"
#define SVM_VMLOAD ".byte 0x0f, 0x01, 0xda"
#define SVM_VMRUN  ".byte 0x0f, 0x01, 0xd8"
#define SVM_VMSAVE ".byte 0x0f, 0x01, 0xdb"
#define SVM_VM_CR_SVM_DISABLE 4
#define SVM_VM_CR_SVM_DIS_MASK  0x0010ULL
#define SVM_VM_CR_SVM_LOCK_MASK 0x0008ULL
#define TLB_CONTROL_DO_NOTHING 0
#define TLB_CONTROL_FLUSH_ALL_ASID 1
#define V_IGN_TPR_MASK (1 << V_IGN_TPR_SHIFT)
#define V_IGN_TPR_SHIFT 20
#define V_INTR_MASKING_MASK (1 << V_INTR_MASKING_SHIFT)
#define V_INTR_MASKING_SHIFT 24
#define V_INTR_PRIO_MASK (0x0f << V_INTR_PRIO_SHIFT)
#define V_INTR_PRIO_SHIFT 16
#define V_IRQ_MASK (1 << V_IRQ_SHIFT)
#define V_IRQ_SHIFT 8
#define V_TPR_MASK 0x0f

#define AR_DB_MASK (1 << 14)
#define AR_DPL(ar) (((ar) >> AR_DPL_SHIFT) & 3)
#define AR_DPL_SHIFT 5
#define AR_G_MASK (1 << 15)
#define AR_L_MASK (1 << 13)
#define AR_P_MASK (1 << 7)
#define AR_RESERVD_MASK 0xfffe0f00
#define AR_S_MASK (1 << 4)
#define AR_TYPE_ACCESSES_MASK 1
#define AR_TYPE_BUSY_16_TSS 3
#define AR_TYPE_BUSY_32_TSS 11
#define AR_TYPE_BUSY_64_TSS 11
#define AR_TYPE_CODE_MASK (1 << 3)
#define AR_TYPE_LDT 2
#define AR_TYPE_MASK 0x0f
#define AR_TYPE_READABLE_MASK (1 << 1)
#define AR_TYPE_WRITEABLE_MASK (1 << 2)
#define AR_UNUSABLE_MASK (1 << 16)
#define ASM_VMX_VMCLEAR_RAX       ".byte 0x66, 0x0f, 0xc7, 0x30"
#define ASM_VMX_VMLAUNCH          ".byte 0x0f, 0x01, 0xc2"
#define ASM_VMX_VMPTRLD_RAX       ".byte 0x0f, 0xc7, 0x30"
#define ASM_VMX_VMREAD_RDX_RAX    ".byte 0x0f, 0x78, 0xd0"
#define ASM_VMX_VMRESUME          ".byte 0x0f, 0x01, 0xc3"
#define ASM_VMX_VMWRITE_RAX_RDX   ".byte 0x0f, 0x79, 0xd0"
#define ASM_VMX_VMWRITE_RSP_RDX   ".byte 0x0f, 0x79, 0xd4"
#define ASM_VMX_VMXOFF            ".byte 0x0f, 0x01, 0xc4"
#define ASM_VMX_VMXON_RAX         ".byte 0xf3, 0x0f, 0xc7, 0x30"
#define CONTROL_REG_ACCESS_NUM          0x7     
#define CONTROL_REG_ACCESS_REG          0xf00   
#define CONTROL_REG_ACCESS_TYPE         0x30    
#define CPU_BASED_ACTIVATE_SECONDARY_CONTROLS   0x80000000
#define CPU_BASED_CR8_LOAD_EXITING              0x00080000
#define CPU_BASED_CR8_STORE_EXITING             0x00100000
#define CPU_BASED_HLT_EXITING                   0x00000080
#define CPU_BASED_INVLPG_EXITING                0x00000200
#define CPU_BASED_MONITOR_EXITING               0x20000000
#define CPU_BASED_MOV_DR_EXITING                0x00800000
#define CPU_BASED_MWAIT_EXITING                 0x00000400
#define CPU_BASED_PAUSE_EXITING                 0x40000000
#define CPU_BASED_RDPMC_EXITING                 0x00000800
#define CPU_BASED_RDTSC_EXITING                 0x00001000
#define CPU_BASED_TPR_SHADOW                    0x00200000
#define CPU_BASED_UNCOND_IO_EXITING             0x01000000
#define CPU_BASED_USE_IO_BITMAPS                0x02000000
#define CPU_BASED_USE_MSR_BITMAPS               0x10000000
#define CPU_BASED_USE_TSC_OFFSETING             0x00000008
#define CPU_BASED_VIRTUAL_INTR_PENDING          0x00000004
#define DEBUG_REG_ACCESS_NUM            0x7     
#define DEBUG_REG_ACCESS_REG(eq)        (((eq) >> 8) & 0xf) 
#define DEBUG_REG_ACCESS_TYPE           0x10    
#define EXIT_REASON_APIC_ACCESS         44
#define EXIT_REASON_CPUID               10
#define EXIT_REASON_CR_ACCESS           28
#define EXIT_REASON_DR_ACCESS           29
#define EXIT_REASON_EPT_MISCONFIG       49
#define EXIT_REASON_EPT_VIOLATION       48
#define EXIT_REASON_EXCEPTION_NMI       0
#define EXIT_REASON_EXTERNAL_INTERRUPT  1
#define EXIT_REASON_HLT                 12
#define EXIT_REASON_INVLPG              14
#define EXIT_REASON_IO_INSTRUCTION      30
#define EXIT_REASON_MONITOR_INSTRUCTION 39
#define EXIT_REASON_MSR_READ            31
#define EXIT_REASON_MSR_WRITE           32
#define EXIT_REASON_MWAIT_INSTRUCTION   36
#define EXIT_REASON_PAUSE_INSTRUCTION   40
#define EXIT_REASON_PENDING_INTERRUPT   7
#define EXIT_REASON_RDPMC               15
#define EXIT_REASON_RDTSC               16
#define EXIT_REASON_TASK_SWITCH         9
#define EXIT_REASON_TPR_BELOW_THRESHOLD 43
#define EXIT_REASON_TRIPLE_FAULT        2
#define EXIT_REASON_VMCALL              18
#define EXIT_REASON_VMCLEAR             19
#define EXIT_REASON_VMLAUNCH            20
#define EXIT_REASON_VMOFF               26
#define EXIT_REASON_VMON                27
#define EXIT_REASON_VMPTRLD             21
#define EXIT_REASON_VMPTRST             22
#define EXIT_REASON_VMREAD              23
#define EXIT_REASON_VMRESUME            24
#define EXIT_REASON_VMWRITE             25
#define INTR_INFO_DELIVER_CODE_MASK     0x800           
#define INTR_INFO_INTR_TYPE_MASK        0x700           
#define INTR_INFO_RESVD_BITS_MASK       0x7ffff000
#define INTR_INFO_VALID_MASK            0x80000000      
#define INTR_INFO_VECTOR_MASK           0xff            
#define INTR_TYPE_EXT_INTR              (0 << 8) 
#define INTR_TYPE_SOFT_INTR             (4 << 8) 
#define LMSW_SOURCE_DATA  (0xFFFF << LMSW_SOURCE_DATA_SHIFT) 
#define LMSW_SOURCE_DATA_SHIFT 16
#define PIN_BASED_EXT_INTR_MASK                 0x00000001
#define PIN_BASED_NMI_EXITING                   0x00000008
#define PIN_BASED_VIRTUAL_NMIS                  0x00000020
#define REG_EAX                         (0 << 8)
#define REG_EBP                         (5 << 8)
#define REG_EBX                         (3 << 8)
#define REG_ECX                         (1 << 8)
#define REG_EDI                         (7 << 8)
#define REG_EDX                         (2 << 8)
#define REG_ESI                         (6 << 8)
#define REG_ESP                         (4 << 8)
#define REG_R10                        (10 << 8)
#define REG_R11                        (11 << 8)
#define REG_R12                        (12 << 8)
#define REG_R13                        (13 << 8)
#define REG_R14                        (14 << 8)
#define REG_R15                        (15 << 8)
#define REG_R8                         (8 << 8)
#define REG_R9                         (9 << 8)
#define SECONDARY_EXEC_ENABLE_EPT               0x00000002
#define SECONDARY_EXEC_ENABLE_VPID              0x00000020
#define SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES 0x00000001
#define SEGMENT_AR_L_MASK (1 << 13)
#define TYPE_MOV_FROM_DR                (1 << 4)
#define TYPE_MOV_TO_DR                  (0 << 4)
#define VECTORING_INFO_DELIVER_CODE_MASK    	INTR_INFO_DELIVER_CODE_MASK
#define VECTORING_INFO_TYPE_MASK        	INTR_INFO_INTR_TYPE_MASK
#define VECTORING_INFO_VALID_MASK       	INTR_INFO_VALID_MASK
#define VECTORING_INFO_VECTOR_MASK           	INTR_INFO_VECTOR_MASK
#define VMX_EPT_IPAT_BIT    			(1ull << 6)
#define VMX_EXIT_REASONS_FAILED_VMENTRY         0x80000000

#define VMX_VPID_EXTENT_GLOBAL_CONTEXT_BIT      (1ull << 10) 
#define VMX_VPID_EXTENT_SINGLE_CONTEXT_BIT      (1ull << 9) 
#define VM_ENTRY_DEACT_DUAL_MONITOR             0x00000800
#define VM_ENTRY_IA32E_MODE                     0x00000200
#define VM_ENTRY_SMM                            0x00000400
#define VM_EXIT_ACK_INTR_ON_EXIT                0x00008000
#define VM_EXIT_HOST_ADDR_SPACE_SIZE            0x00000200
# define AT_VECTOR_SIZE_ARCH 2

#define RESTORE_CONTEXT "movq %%rbp,%%rsi ; popq %%rbp ; popf\t"
#define SAVE_CONTEXT    "pushf ; pushq %%rbp ; movq %%rsi,%%rbp\n\t"

#define __EXTRA_CLOBBER  \
	, "rcx", "rbx", "rdx", "r8", "r9", "r10", "r11", \
	  "r12", "r13", "r14", "r15"
#define __RESTORE(reg, offset) "movq (14-" #offset ")*8(%%rsp),%%" #reg "\n\t"
#define __SAVE(reg, offset) "movq %%" #reg ",(14-" #offset ")*8(%%rsp)\n\t"



#define clts()		(native_clts())
#define get_user_gs(regs)	(u16)({unsigned long v; savesegment(gs, v); v;})
#define lazy_load_gs(v)		loadsegment(gs, (v))
#define lazy_save_gs(v)		savesegment(gs, (v))
#define load_gs_index   native_load_gs_index
#define loadsegment(seg, value)						\
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
#define mb() alternative("lock; addl $0,0(%%esp)", "mfence", X86_FEATURE_XMM2)
#define nop() asm volatile ("nop")
#define read_barrier_depends()	do { } while (0)
#define read_cr0()	(native_read_cr0())
#define read_cr2()	(native_read_cr2())
#define read_cr3()	(native_read_cr3())
#define read_cr4()	(native_read_cr4())
#define read_cr4_safe()	(native_read_cr4_safe())
#define read_cr8()	(native_read_cr8())
#define rmb() alternative("lock; addl $0,0(%%esp)", "lfence", X86_FEATURE_XMM2)
#define savesegment(seg, value)				\
	asm("mov %%" #seg ",%0":"=r" (value) : : "memory")
#define set_mb(var, value) do { (void)xchg(&var, value); } while (0)
#define set_user_gs(regs, v)	loadsegment(gs, (unsigned long)(v))
#define smp_mb()	mb()
#define smp_read_barrier_depends()	read_barrier_depends()
# define smp_rmb()	rmb()
# define smp_wmb() 	wmb()
#define stts() write_cr0(read_cr0() | X86_CR0_TS)
#define switch_to(prev, next, last) \
	asm volatile(SAVE_CONTEXT					  \
	     "movq %%rsp,%P[threadrsp](%[prev])\n\t" 	  \
	     "movq %P[threadrsp](%[next]),%%rsp\n\t" 	  \
	     "call __switch_to\n\t"					  \
	     "movq "__percpu_arg([current_task])",%%rsi\n\t"		  \
	     __switch_canary						  \
	     "movq %P[thread_info](%%rsi),%%r8\n\t"			  \
	     "movq %%rax,%%rdi\n\t" 					  \
	     "testl  %[_tif_fork],%P[ti_flags](%%r8)\n\t"		  \
	     "jnz   ret_from_fork\n\t"					  \
	     RESTORE_CONTEXT						  \
	     : "=a" (last)					  	  \
	       __switch_canary_oparam					  \
	     : [next] "S" (next), [prev] "D" (prev),			  \
	       [threadrsp] "i" (offsetof(struct task_struct, thread.sp)), \
	       [ti_flags] "i" (offsetof(struct thread_info, flags)),	  \
	       [_tif_fork] "i" (_TIF_FORK),			  	  \
	       [thread_info] "i" (offsetof(struct task_struct, stack)),   \
	       [current_task] "m" (current_task)			  \
	       __switch_canary_iparam					  \
	     : "memory", "cc" __EXTRA_CLOBBER)
#define task_user_gs(tsk)	((tsk)->thread.gs)
#define wbinvd()	(native_wbinvd())
#define wmb() alternative("lock; addl $0,0(%%esp)", "sfence", X86_FEATURE_XMM)
#define write_cr0(x)	(native_write_cr0(x))
#define write_cr2(x)	(native_write_cr2(x))
#define write_cr3(x)	(native_write_cr3(x))
#define write_cr4(x)	(native_write_cr4(x))
#define write_cr8(x)	(native_write_cr8(x))
#define COND_POP(set, mask, reg)			\
	.if ((~(set)) & mask); pop %reg; .endif
#define COND_PUSH(set, mask, reg)			\
	.if ((~(set)) & mask); push %reg; .endif
#define DISABLE_INTERRUPTS(clobbers)					\
	PARA_SITE(PARA_PATCH(pv_irq_ops, PV_IRQ_irq_disable), clobbers, \
		  PV_SAVE_REGS(clobbers | CLBR_CALLEE_SAVE);		\
		  call PARA_INDIRECT(pv_irq_ops+PV_IRQ_irq_disable);	\
		  PV_RESTORE_REGS(clobbers | CLBR_CALLEE_SAVE);)
#define ENABLE_INTERRUPTS(clobbers)					\
	PARA_SITE(PARA_PATCH(pv_irq_ops, PV_IRQ_irq_enable), clobbers,	\
		  PV_SAVE_REGS(clobbers | CLBR_CALLEE_SAVE);		\
		  call PARA_INDIRECT(pv_irq_ops+PV_IRQ_irq_enable);	\
		  PV_RESTORE_REGS(clobbers | CLBR_CALLEE_SAVE);)
#define PARA_INDIRECT(addr)	*addr(%rip)
#define PARA_PATCH(struct, off)        ((PARAVIRT_PATCH_##struct + (off)) / 8)
#define PARA_SITE(ptype, clobbers, ops) _PVSITE(ptype, clobbers, ops, .quad, 8)
#define PV_CALLEE_SAVE(func)						\
	((struct paravirt_callee_save) { __raw_callee_save_##func })
#define PV_CALLEE_SAVE_REGS_THUNK(func)					\
	extern typeof(func) __raw_callee_save_##func;			\
	static void *__##func##__ __used = func;			\
									\
	asm(".pushsection .text;"					\
	    "__raw_callee_save_" #func ": "				\
	    PV_SAVE_ALL_CALLER_REGS					\
	    "call " #func ";"						\
	    PV_RESTORE_ALL_CALLER_REGS					\
	    "ret;"							\
	    ".popsection")
#define PV_EXTRA_CLOBBERS EXTRA_CLOBBERS, "rcx" , "rdx", "rsi"
#define PV_FLAGS_ARG "0"
#define PV_RESTORE_REGS "popl %edx; popl %ecx;"
#define PV_SAVE_REGS "pushl %ecx; pushl %edx;"
#define PV_VEXTRA_CLOBBERS EXTRA_CLOBBERS, "rdi", "rcx" , "rdx", "rsi"

#define _PVSITE(ptype, clobbers, ops, word, algn)	\
771:;						\
	ops;					\
772:;						\
	.pushsection .parainstructions,"a";	\
	 .align	algn;				\
	 word 771b;				\
	 .byte ptype;				\
	 .byte 772b-771b;			\
	 .short clobbers;			\
	.popsection
#define  __HAVE_ARCH_ENTER_LAZY_MMU_MODE
#define  __HAVE_ARCH_PTEP_MODIFY_PROT_TRANSACTION
#define  __HAVE_ARCH_START_CONTEXT_SWITCH
#define __PV_IS_CALLEE_SAVE(func)			\
	((struct paravirt_callee_save) { func })
# define default_banner x86_init_noop
#define get_debugreg(var, reg) var = paravirt_get_debugreg(reg)
#define get_kernel_rpl()  (pv_info.kernel_rpl)
#define rdmsr(msr, val1, val2)			\
do {						\
	int _err;				\
	u64 _l = paravirt_read_msr(msr, &_err);	\
	val1 = (u32)_l;				\
	val2 = _l >> 32;			\
} while (0)
#define rdmsr_safe(msr, a, b)			\
({						\
	int _err;				\
	u64 _l = paravirt_read_msr(msr, &_err);	\
	(*a) = (u32)_l;				\
	(*b) = _l >> 32;			\
	_err;					\
})
#define rdmsr_safe_regs(regs)	paravirt_rdmsr_regs(regs)
#define rdmsrl(msr, val)			\
do {						\
	int _err;				\
	val = paravirt_read_msr(msr, &_err);	\
} while (0)
#define rdpmc(counter, low, high)		\
do {						\
	u64 _l = paravirt_read_pmc(counter);	\
	low = (u32)_l;				\
	high = _l >> 32;			\
} while (0)
#define rdtscl(low)				\
do {						\
	u64 _l = paravirt_read_tsc();		\
	low = (int)_l;				\
} while (0)
#define rdtscll(val) (val = paravirt_read_tsc())
#define rdtscp(low, high, aux)				\
do {							\
	int __aux;					\
	unsigned long __val = paravirt_rdtscp(&__aux);	\
	(low) = (u32)__val;				\
	(high) = (u32)(__val >> 32);			\
	(aux) = __aux;					\
} while (0)
#define rdtscpll(val, aux)				\
do {							\
	unsigned long __aux; 				\
	val = paravirt_rdtscp(&__aux);			\
	(aux) = __aux;					\
} while (0)
#define store_tr(tr)	((tr) = paravirt_store_tr())
#define wrmsr(msr, val1, val2)			\
do {						\
	paravirt_write_msr(msr, val1, val2);	\
} while (0)
#define wrmsr_safe(msr, a, b)	paravirt_write_msr(msr, a, b)
#define wrmsr_safe_regs(regs)	paravirt_wrmsr_regs(regs)
#define wrmsrl(msr, val)	wrmsr(msr, (u32)((u64)(val)), ((u64)(val))>>32)
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
#define DEF_NATIVE(ops, name, code) 					\
	extern const char start_##ops##_##name[], end_##ops##_##name[];	\
	asm("start_" #ops "_" #name ": " code "; end_" #ops "_" #name ":")

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
#define PVOP_TEST_NULL(op)	BUG_ON(op == NULL)
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
				     : call_clbr			\
				     : paravirt_type(op),		\
				       paravirt_clobber(clbr),		\
				       ##__VA_ARGS__			\
				     : "memory", "cc" extra_clbr);	\
			__ret = (rettype)((((u64)__edx) << 32) | __eax); \
		} else {						\
			asm volatile(pre				\
				     paravirt_alt(PARAVIRT_CALL)	\
				     post				\
				     : call_clbr			\
				     : paravirt_type(op),		\
				       paravirt_clobber(clbr),		\
				       ##__VA_ARGS__			\
				     : "memory", "cc" extra_clbr);	\
			__ret = (rettype)__eax;				\
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
			     : call_clbr				\
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
	[paravirt_opptr] "i" (&(op))

#define  __WITH_KM_FENCE
# define KMAP_D(n) __KM_FENCE_##n ,

#define GDT_ENTRY_INIT(flags, base, limit) { { { \
		.a = ((limit) & 0xffff) | (((base) & 0xffff) << 16), \
		.b = (((base) & 0xff0000) >> 16) | (((flags) & 0xf0ff) << 8) | \
			((limit) & 0xf0000) | ((base) & 0xff000000), \
	} } }
#define PTR_HIGH(x) ((unsigned long long)(x) >> 32)
#define PTR_LOW(x) ((unsigned long long)(x) & 0xFFFF)
#define PTR_MIDDLE(x) (((unsigned long long)(x) >> 16) & 0xFFFF)

#define gate_offset(g) ((g).offset_low | ((unsigned long)(g).offset_middle << 16) | ((unsigned long)(g).offset_high << 32))
#define gate_segment(g) ((g).segment)
# define _ASM_EXTABLE(from,to)	    \
	__ASM_EX_SEC ;		    \
	_ASM_ALIGN ;		    \
	_ASM_PTR from , to ;	    \
	.previous

# define __ASM_FORM(x)	x
#define __ASM_REG(reg)		__ASM_SEL(e##reg, r##reg)
# define __ASM_SEL(a,b) __ASM_FORM(a)
#define __ASM_SIZE(inst)	__ASM_SEL(inst##l, inst##q)

#define _PAGE_BIT_NX           63       
#define _PAGE_PAT_LARGE (_AT(pteval_t, 1) << _PAGE_BIT_PAT_LARGE)



#define __pgprot(x)	((pgprot_t) { (x) } )
#define native_pagetable_setup_done  x86_init_pgd_noop
#define native_pagetable_setup_start x86_init_pgd_noop
#define pgprot_val(x)	((x).pgprot)
#define PMD_MASK  	(~(PMD_SIZE-1))
#define PMD_SIZE  	(1UL << PMD_SHIFT)


#define __pmd(x)				((pmd_t) { __pud(x) } )
#define __pmd_free_tlb(tlb, x, a)		do { } while (0)
#define pmd_ERROR(pmd)				(pud_ERROR((pmd).pud))
#define pmd_addr_end(addr, end)			(end)
#define pmd_alloc_one(mm, address)		NULL
#define pmd_val(x)				(pud_val((x).pud))
#define pud_page(pud)				(pmd_page((pmd_t){ pud }))
#define pud_page_vaddr(pud)			(pmd_page_vaddr((pmd_t){ pud }))
#define pud_populate(mm, pmd, pte)		do { } while (0)
#define set_pud(pudptr, pudval)			set_pmd((pmd_t *)(pudptr), (pmd_t) { pudval })
#define PUD_MASK  	(~(PUD_SIZE-1))
#define PUD_SIZE  	(1UL << PUD_SHIFT)


#define __pud(x)				((pud_t) { __pgd(x) } )
#define __pud_free_tlb(tlb, x, a)		do { } while (0)
#define pgd_page(pgd)				(pud_page((pud_t){ pgd }))
#define pgd_page_vaddr(pgd)			(pud_page_vaddr((pud_t){ pgd }))
#define pgd_populate(mm, pgd, pud)		do { } while (0)
#define pud_ERROR(pud)				(pgd_ERROR((pud).pgd))
#define pud_addr_end(addr, end)			(end)
#define pud_alloc_one(mm, address)		NULL
#define pud_free(mm, x)				do { } while (0)
#define pud_val(x)				(pgd_val((x).pgd))
#define set_pgd(pgdptr, pgdval)			set_pud((pud_t *)(pgdptr), (pud_t) { pgdval })
#define HUGE_MAX_HSTATE 2
#define VM_DATA_DEFAULT_FLAGS \
	(((current->personality & READ_IMPLIES_EXEC) ? VM_EXEC : 0 ) | \
	 VM_READ | VM_WRITE | VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC)

#define DEBUG_STACK 0
#define DOUBLEFAULT_STACK 1
#define MCE_STACK 0
#define NMI_STACK 0
#define N_EXCEPTION_STACKS 1
#define STACKFAULT_STACK 0
#define THREAD_SIZE 	(PAGE_SIZE << THREAD_ORDER)

#define _AC(X,Y)	X
#define _AT(T,X)	X

#define __AC(X,Y)	(X##Y)
#define CURRENT_MASK (~(THREAD_SIZE - 1))
#define DEBUG_STACK_ORDER (EXCEPTION_STACK_ORDER + 1)
#define DEBUG_STKSZ (PAGE_SIZE << DEBUG_STACK_ORDER)
#define EXCEPTION_STACK_ORDER 0
#define EXCEPTION_STKSZ (PAGE_SIZE << EXCEPTION_STACK_ORDER)
#define IRQ_STACK_ORDER 2
#define IRQ_STACK_SIZE (PAGE_SIZE << IRQ_STACK_ORDER)

#define __PAGE_OFFSET           _AC(0xffff880000000000, UL)
#define __phys_reloc_hide(x)	(x)
#define pfn_valid(pfn)          ((pfn) < max_pfn)
#define vmemmap ((struct page *)VMEMMAP_START)
# define INIT_TRACE_IRQFLAGS

#define irqs_disabled()						\
({								\
	unsigned long _flags;					\
								\
	raw_local_save_flags(_flags);				\
	raw_irqs_disabled_flags(_flags);			\
})
#define irqs_disabled_flags(flags)		\
({						\
	typecheck(unsigned long, flags);	\
	raw_irqs_disabled_flags(flags);		\
})
#define local_irq_disable() \
	do { raw_local_irq_disable(); trace_hardirqs_off(); } while (0)
#define local_irq_enable() \
	do { trace_hardirqs_on(); raw_local_irq_enable(); } while (0)
#define local_irq_restore(flags)			\
	do {						\
		typecheck(unsigned long, flags);	\
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
		typecheck(unsigned long, flags);	\
		raw_local_irq_save(flags);		\
		trace_hardirqs_off();			\
	} while (0)
#define local_save_flags(flags)				\
	do {						\
		typecheck(unsigned long, flags);	\
		raw_local_save_flags(flags);		\
	} while (0)
# define lockdep_softirq_enter()	do { current->softirq_context++; } while (0)
# define lockdep_softirq_exit()	do { current->softirq_context--; } while (0)
# define raw_local_irq_disable()	local_irq_disable()
# define raw_local_irq_enable()		local_irq_enable()
# define raw_local_irq_restore(flags)			\
	do {						\
		typecheck(unsigned long, flags);	\
		local_irq_restore(flags);		\
	} while (0)
# define raw_local_irq_save(flags)			\
	do {						\
		typecheck(unsigned long, flags);	\
		local_irq_save(flags);			\
	} while (0)
#define safe_halt()						\
	do {							\
		trace_hardirqs_on();				\
		raw_safe_halt();				\
	} while (0)
# define start_critical_timings() do { } while (0)
# define stop_critical_timings() do { } while (0)
# define trace_hardirq_context(p)	((p)->hardirq_context)
# define trace_hardirq_enter()	do { current->hardirq_context++; } while (0)
# define trace_hardirq_exit()	do { current->hardirq_context--; } while (0)
# define trace_hardirqs_enabled(p)	((p)->hardirqs_enabled)
# define trace_hardirqs_off()		do { } while (0)
# define trace_hardirqs_on()		do { } while (0)
# define trace_softirq_context(p)	((p)->softirq_context)
# define trace_softirqs_enabled(p)	((p)->softirqs_enabled)
# define trace_softirqs_off(ip)		do { } while (0)
# define trace_softirqs_on(ip)		do { } while (0)
#define ASM_NOP1 GENERIC_NOP1
#define ASM_NOP2 K8_NOP2
#define ASM_NOP3 K8_NOP3
#define ASM_NOP4 K8_NOP4
#define ASM_NOP5 K8_NOP5
#define ASM_NOP6 K8_NOP6
#define ASM_NOP7 K8_NOP7
#define ASM_NOP8 K8_NOP8
#define ASM_NOP_MAX 8
#define GENERIC_NOP1 ".byte 0x90\n"
#define GENERIC_NOP2 ".byte 0x89,0xf6\n"
#define GENERIC_NOP3 ".byte 0x8d,0x76,0x00\n"
#define GENERIC_NOP4 ".byte 0x8d,0x74,0x26,0x00\n"
#define GENERIC_NOP5 GENERIC_NOP1 GENERIC_NOP4
#define GENERIC_NOP6 ".byte 0x8d,0xb6,0x00,0x00,0x00,0x00\n"
#define GENERIC_NOP7 ".byte 0x8d,0xb4,0x26,0x00,0x00,0x00,0x00\n"
#define GENERIC_NOP8 GENERIC_NOP1 GENERIC_NOP7
#define K8_NOP1 GENERIC_NOP1

#define X86_FEATURE_3DNOWPREFETCH (6*32+ 8) 
#define X86_FEATURE_AMD_DCM     (3*32+27) 
#define X86_FEATURE_ARCH_PERFMON (3*32+11) 
#define X86_FEATURE_CLFLUSH_MONITOR (3*32+25) 
#define X86_FEATURE_CONSTANT_TSC (3*32+ 8) 
#define X86_FEATURE_EPT         (8*32+ 3) 
#define X86_FEATURE_FLEXPRIORITY (8*32+ 2) 
#define X86_FEATURE_FXSAVE_LEAK (3*32+10) 
#define X86_FEATURE_LFENCE_RDTSC (3*32+18) 
#define X86_FEATURE_MFENCE_RDTSC (3*32+17) 
#define X86_FEATURE_MISALIGNSSE (6*32+ 7) 
#define X86_FEATURE_POPCNT      (4*32+23) 
#define X86_FEATURE_TPR_SHADOW  (8*32+ 0) 
#define X86_FEATURE_TSC_RELIABLE (3*32+23) 
#define X86_FEATURE_VNMI        (8*32+ 1) 
#define X86_FEATURE_VPID        (8*32+ 4) 

#define boot_cpu_has(bit)	cpu_has(&boot_cpu_data, bit)
#define clear_cpu_cap(c, bit)	clear_bit(bit, (unsigned long *)((c)->x86_capability))
#define cpu_has(c, bit)							\
	(__builtin_constant_p(bit) &&					\
	 ( (((bit)>>5)==0 && (1UL<<((bit)&31) & REQUIRED_MASK0)) ||	\
	   (((bit)>>5)==1 && (1UL<<((bit)&31) & REQUIRED_MASK1)) ||	\
	   (((bit)>>5)==2 && (1UL<<((bit)&31) & REQUIRED_MASK2)) ||	\
	   (((bit)>>5)==3 && (1UL<<((bit)&31) & REQUIRED_MASK3)) ||	\
	   (((bit)>>5)==4 && (1UL<<((bit)&31) & REQUIRED_MASK4)) ||	\
	   (((bit)>>5)==5 && (1UL<<((bit)&31) & REQUIRED_MASK5)) ||	\
	   (((bit)>>5)==6 && (1UL<<((bit)&31) & REQUIRED_MASK6)) ||	\
	   (((bit)>>5)==7 && (1UL<<((bit)&31) & REQUIRED_MASK7)) ||	\
	   (((bit)>>5)==8 && (1UL<<((bit)&31) & REQUIRED_MASK8)) ||	\
	   (((bit)>>5)==9 && (1UL<<((bit)&31) & REQUIRED_MASK9)) )	\
	  ? 1 :								\
	 test_cpu_cap(c, bit))
#define set_cpu_cap(c, bit)	set_bit(bit, (unsigned long *)((c)->x86_capability))
#define setup_clear_cpu_cap(bit) do { \
	clear_cpu_cap(&boot_cpu_data, bit);	\
	set_bit(bit, (unsigned long *)cpu_caps_cleared); \
} while (0)
#define setup_force_cpu_cap(bit) do { \
	set_cpu_cap(&boot_cpu_data, bit);	\
	set_bit(bit, (unsigned long *)cpu_caps_set);	\
} while (0)
#define static_cpu_has(bit)					\
(								\
	__builtin_constant_p(boot_cpu_has(bit)) ?		\
		boot_cpu_has(bit) :				\
	__builtin_constant_p(bit) ?				\
		__static_cpu_has(bit) :				\
		boot_cpu_has(bit)				\
)
#define test_cpu_cap(c, bit)						\
	 test_bit(bit, (unsigned long *)((c)->x86_capability))

#define FS_TLS 0
#define FS_TLS_SEL ((GDT_ENTRY_TLS_MIN+FS_TLS)*8 + 3)
#define GDT_ENTRIES 32
#define GDT_ENTRY(flags, base, limit)			\
	((((base)  & 0xff000000ULL) << (56-24)) |	\
	 (((flags) & 0x0000f0ffULL) << 40) |		\
	 (((limit) & 0x000f0000ULL) << (48-16)) |	\
	 (((base)  & 0x00ffffffULL) << 16) |		\
	 (((limit) & 0x0000ffffULL)))
#define GDT_ENTRY_DEFAULT_USER32_CS 4
#define GDT_ENTRY_DEFAULT_USER_CS 6
#define GDT_ENTRY_DEFAULT_USER_DS 5
#define GDT_ENTRY_KERNEL32_CS 1
#define GDT_ENTRY_KERNEL_CS 2
#define GDT_ENTRY_KERNEL_DS 3
#define GDT_ENTRY_LDT 10 
#define GDT_ENTRY_PER_CPU 15	
#define GDT_ENTRY_TLS_ENTRIES 3
#define GDT_ENTRY_TLS_MAX 14
#define GDT_ENTRY_TLS_MIN 12
#define GDT_ENTRY_TSS 8	
#define GDT_SIZE (GDT_ENTRIES * 8)
#define GS_TLS 1
#define GS_TLS_SEL ((GDT_ENTRY_TLS_MIN+GS_TLS)*8 + 3)
#define IDT_ENTRIES 256
#define NUM_EXCEPTION_VECTORS 32
#define PNP_CS16   (GDT_ENTRY_PNPBIOS_CS16 * 8)	
#define PNP_CS32   (GDT_ENTRY_PNPBIOS_CS32 * 8)	
#define PNP_DS     (GDT_ENTRY_PNPBIOS_DS * 8)	
#define PNP_TS1    (GDT_ENTRY_PNPBIOS_TS1 * 8)	
#define PNP_TS2    (GDT_ENTRY_PNPBIOS_TS2 * 8)	
#define SEGMENT_IS_PNP_CODE(x)   (((x) & 0xf4) == GDT_ENTRY_PNPBIOS_BASE * 8)
#define TLS_SIZE (GDT_ENTRY_TLS_ENTRIES * 8)

#define __ESPFIX_SS (GDT_ENTRY_ESPFIX_SS * 8)
#define __KERNEL32_CS   (GDT_ENTRY_KERNEL32_CS * 8)
#define __KERNEL_PERCPU (GDT_ENTRY_PERCPU * 8)
#define __USER32_CS   (GDT_ENTRY_DEFAULT_USER32_CS * 8 + 3)
#define __USER_CS     (GDT_ENTRY_DEFAULT_USER_CS* 8 + 3)
#define __USER_DS     (GDT_ENTRY_DEFAULT_USER_DS* 8 + 3)
#define INTERNODE_CACHE_BYTES (1 << INTERNODE_CACHE_SHIFT)
#define INTERNODE_CACHE_SHIFT CONFIG_X86_INTERNODE_CACHE_SHIFT

#define __read_mostly __attribute__((__section__(".data..read_mostly")))
#define AMD_LEGACY_ERRATUM(...)		{ -1, __VA_ARGS__, 0 }
#define AMD_MODEL_RANGE(f, m_start, s_start, m_end, s_end) \
	((f << 24) | (m_start << 16) | (s_start << 12) | (m_end << 4) | (s_end))
#define AMD_MODEL_RANGE_END(range)	((range) & 0xfff)
#define AMD_MODEL_RANGE_FAMILY(range)	(((range) >> 24) & 0xff)
#define AMD_MODEL_RANGE_START(range)	(((range) >> 12) & 0xfff)
#define AMD_OSVW_ERRATUM(osvw_id, ...)	{ osvw_id, __VA_ARGS__, 0 }
#define APERFMPERF_SHIFT 10
# define ARCH_HAS_PREFETCH


#define GET_TSC_CTL(adr)	get_tsc_mode((adr))
#define HAVE_ARCH_PICK_MMAP_LAYOUT 1
#define HBP_NUM 4
#define INIT_THREAD  {							  \
	.sp0			= sizeof(init_stack) + (long)&init_stack, \
	.vm86_info		= NULL,					  \
	.sysenter_cs		= __KERNEL_CS,				  \
	.io_bitmap_ptr		= NULL,					  \
}
#define INIT_TSS  {							  \
	.x86_tss = {							  \
		.sp0		= sizeof(init_stack) + (long)&init_stack, \
		.ss0		= __KERNEL_DS,				  \
		.ss1		= __KERNEL_CS,				  \
		.io_bitmap_base	= INVALID_IO_BITMAP_OFFSET,		  \
	 },								  \
	.io_bitmap		= { [0 ... IO_BITMAP_LONGS] = ~0 },	  \
}
#define KSTK_EIP(task)		(task_pt_regs(task)->ip)
#define KSTK_ESP(task)		(task_pt_regs(task)->sp)
#define KSTK_TOP(info)                                                 \
({                                                                     \
       unsigned long *__ptr = (unsigned long *)(info);                 \
       (unsigned long)(&__ptr[THREAD_SIZE_LONGS]);                     \
})
#define SET_TSC_CTL(val)	set_tsc_mode((val))
#define TASK_SIZE_OF(child)	((test_tsk_thread_flag(child, TIF_IA32)) ? \
					IA32_PAGE_OFFSET : TASK_SIZE_MAX)
#define THREAD_SIZE_LONGS      (THREAD_SIZE/sizeof(unsigned long))

#define cache_line_size()	(boot_cpu_data.x86_cache_alignment)
#define cpu_data(cpu)		per_cpu(cpu_info, cpu)
#define cpu_has_amd_erratum(x)	(false)
#define get_debugreg(var, register)				\
	(var) = native_get_debugreg(register)
#define paravirt_enabled()	0
#define set_debugreg(value, register)				\
	native_set_debugreg(register, value)
#define set_iopl_mask native_set_iopl_mask
#define task_pt_regs(task)                                             \
({                                                                     \
       struct pt_regs *__regs__;                                       \
       __regs__ = (struct pt_regs *)(KSTK_TOP(task_stack_page(task))-8); \
       __regs__ - 1;                                                   \
})
#define thread_saved_pc(t)	(*(unsigned long *)((t)->thread.sp - 8))
#define PER_CLEAR_ON_SETID (READ_IMPLIES_EXEC  | \
			    ADDR_NO_RANDOMIZE  | \
			    ADDR_COMPAT_LAYOUT | \
			    MMAP_PAGE_ZERO)

#define personality(pers)	(pers & PER_MASK)
#define set_personality(pers) \
	((current->personality == (pers)) ? 0 : __set_personality(pers))
#define DECLARE_ARGS(val, low, high)	unsigned low, high
#define EAX_EDX_ARGS(val, low, high)	"a" (low), "d" (high)
#define EAX_EDX_RET(val, low, high)	"=a" (low), "=d" (high)
#define EAX_EDX_VAL(val, low, high)	((low) | ((u64)(high) << 32))

#define checking_wrmsrl(msr, val) wrmsr_safe((msr), (u32)(val),		\
					     (u32)((val) >> 32))
#define write_rdtscp_aux(val) wrmsr(MSR_TSC_AUX, (val), 0)
#define write_tsc(val1, val2) wrmsr(MSR_IA32_TSC, (val1), (val2))



#define FAM10H_MMIO_CONF_BUSRANGE_SHIFT 2
#define MSR_IA32_FEATURE_CONTROL        0x0000003a
#define MSR_IA32_MCx_ADDR(x)		(MSR_IA32_MC0_ADDR + 4*(x))
#define MSR_IA32_MCx_CTL(x)		(MSR_IA32_MC0_CTL + 4*(x))
#define MSR_IA32_MCx_CTL2(x)		(MSR_IA32_MC0_CTL2 + (x))
#define MSR_IA32_MCx_MISC(x)		(MSR_IA32_MC0_MISC + 4*(x))
#define MSR_IA32_MCx_STATUS(x)		(MSR_IA32_MC0_STATUS + 4*(x))
#define MSR_IA32_VMX_BASIC              0x00000480
#define MSR_IA32_VMX_CR0_FIXED0         0x00000486
#define MSR_IA32_VMX_CR0_FIXED1         0x00000487
#define MSR_IA32_VMX_CR4_FIXED0         0x00000488
#define MSR_IA32_VMX_CR4_FIXED1         0x00000489
#define MSR_IA32_VMX_ENTRY_CTLS         0x00000484
#define MSR_IA32_VMX_EPT_VPID_CAP       0x0000048c
#define MSR_IA32_VMX_EXIT_CTLS          0x00000483
#define MSR_IA32_VMX_MISC               0x00000485
#define MSR_IA32_VMX_PINBASED_CTLS      0x00000481
#define MSR_IA32_VMX_PROCBASED_CTLS     0x00000482
#define MSR_IA32_VMX_PROCBASED_CTLS2    0x0000048b
#define MSR_IA32_VMX_VMCS_ENUM          0x0000048a
#define MSR_VM_CR                       0xc0010114
#define MSR_VM_HSAVE_PA                 0xc0010117
#define MSR_VM_IGNNE                    0xc0010115

#define DECLARE_EARLY_PER_CPU(_type, _name)			\
	DECLARE_PER_CPU(_type, _name);				\
	extern __typeof__(_type) *_name##_early_ptr;		\
	extern __typeof__(_type)  _name##_early_map[]
#define DECLARE_INIT_PER_CPU(var) \
       extern typeof(var) init_per_cpu_var(var)
#define EXPORT_EARLY_PER_CPU_SYMBOL(_name)			\
	EXPORT_PER_CPU_SYMBOL(_name)
#define INIT_PER_CPU_VAR(var)  init_per_cpu__##var
#define PER_CPU(var, reg)						\
	__percpu_mov_op %__percpu_seg:this_cpu_off, reg;		\
	lea var(reg), reg
#define PER_CPU_VAR(var)	%__percpu_seg:var

#define __percpu_arg(x)		"%%"__stringify(__percpu_seg)":%P" #x
#define __this_cpu_add_1(pcp, val)	percpu_add_op((pcp), val)
#define __this_cpu_add_2(pcp, val)	percpu_add_op((pcp), val)
#define __this_cpu_add_4(pcp, val)	percpu_add_op((pcp), val)
#define __this_cpu_add_8(pcp, val)	percpu_add_op((pcp), val)
#define __this_cpu_and_1(pcp, val)	percpu_to_op("and", (pcp), val)
#define __this_cpu_and_2(pcp, val)	percpu_to_op("and", (pcp), val)
#define __this_cpu_and_4(pcp, val)	percpu_to_op("and", (pcp), val)
#define __this_cpu_and_8(pcp, val)	percpu_to_op("and", (pcp), val)
#define __this_cpu_or_1(pcp, val)	percpu_to_op("or", (pcp), val)
#define __this_cpu_or_2(pcp, val)	percpu_to_op("or", (pcp), val)
#define __this_cpu_or_4(pcp, val)	percpu_to_op("or", (pcp), val)
#define __this_cpu_or_8(pcp, val)	percpu_to_op("or", (pcp), val)
#define __this_cpu_read_1(pcp)		percpu_from_op("mov", (pcp), "m"(pcp))
#define __this_cpu_read_2(pcp)		percpu_from_op("mov", (pcp), "m"(pcp))
#define __this_cpu_read_4(pcp)		percpu_from_op("mov", (pcp), "m"(pcp))
#define __this_cpu_read_8(pcp)		percpu_from_op("mov", (pcp), "m"(pcp))
#define __this_cpu_write_1(pcp, val)	percpu_to_op("mov", (pcp), val)
#define __this_cpu_write_2(pcp, val)	percpu_to_op("mov", (pcp), val)
#define __this_cpu_write_4(pcp, val)	percpu_to_op("mov", (pcp), val)
#define __this_cpu_write_8(pcp, val)	percpu_to_op("mov", (pcp), val)
#define __this_cpu_xor_1(pcp, val)	percpu_to_op("xor", (pcp), val)
#define __this_cpu_xor_2(pcp, val)	percpu_to_op("xor", (pcp), val)
#define __this_cpu_xor_4(pcp, val)	percpu_to_op("xor", (pcp), val)
#define __this_cpu_xor_8(pcp, val)	percpu_to_op("xor", (pcp), val)
#define init_per_cpu_var(var)  init_per_cpu__##var
#define irqsafe_cpu_add_1(pcp, val)	percpu_add_op((pcp), val)
#define irqsafe_cpu_add_2(pcp, val)	percpu_add_op((pcp), val)
#define irqsafe_cpu_add_4(pcp, val)	percpu_add_op((pcp), val)
#define irqsafe_cpu_add_8(pcp, val)	percpu_add_op((pcp), val)
#define irqsafe_cpu_and_1(pcp, val)	percpu_to_op("and", (pcp), val)
#define irqsafe_cpu_and_2(pcp, val)	percpu_to_op("and", (pcp), val)
#define irqsafe_cpu_and_4(pcp, val)	percpu_to_op("and", (pcp), val)
#define irqsafe_cpu_and_8(pcp, val)	percpu_to_op("and", (pcp), val)
#define irqsafe_cpu_or_1(pcp, val)	percpu_to_op("or", (pcp), val)
#define irqsafe_cpu_or_2(pcp, val)	percpu_to_op("or", (pcp), val)
#define irqsafe_cpu_or_4(pcp, val)	percpu_to_op("or", (pcp), val)
#define irqsafe_cpu_or_8(pcp, val)	percpu_to_op("or", (pcp), val)
#define irqsafe_cpu_xor_1(pcp, val)	percpu_to_op("xor", (pcp), val)
#define irqsafe_cpu_xor_2(pcp, val)	percpu_to_op("xor", (pcp), val)
#define irqsafe_cpu_xor_4(pcp, val)	percpu_to_op("xor", (pcp), val)
#define irqsafe_cpu_xor_8(pcp, val)	percpu_to_op("xor", (pcp), val)
#define percpu_add(var, val)		percpu_add_op(var, val)
#define percpu_add_op(var, val)						\
do {									\
	typedef typeof(var) pao_T__;					\
	const int pao_ID__ = (__builtin_constant_p(val) &&		\
			      ((val) == 1 || (val) == -1)) ? (val) : 0;	\
	if (0) {							\
		pao_T__ pao_tmp__;					\
		pao_tmp__ = (val);					\
		(void)pao_tmp__;					\
	}								\
	switch (sizeof(var)) {						\
	case 1:								\
		if (pao_ID__ == 1)					\
			asm("incb "__percpu_arg(0) : "+m" (var));	\
		else if (pao_ID__ == -1)				\
			asm("decb "__percpu_arg(0) : "+m" (var));	\
		else							\
			asm("addb %1, "__percpu_arg(0)			\
			    : "+m" (var)				\
			    : "qi" ((pao_T__)(val)));			\
		break;							\
	case 2:								\
		if (pao_ID__ == 1)					\
			asm("incw "__percpu_arg(0) : "+m" (var));	\
		else if (pao_ID__ == -1)				\
			asm("decw "__percpu_arg(0) : "+m" (var));	\
		else							\
			asm("addw %1, "__percpu_arg(0)			\
			    : "+m" (var)				\
			    : "ri" ((pao_T__)(val)));			\
		break;							\
	case 4:								\
		if (pao_ID__ == 1)					\
			asm("incl "__percpu_arg(0) : "+m" (var));	\
		else if (pao_ID__ == -1)				\
			asm("decl "__percpu_arg(0) : "+m" (var));	\
		else							\
			asm("addl %1, "__percpu_arg(0)			\
			    : "+m" (var)				\
			    : "ri" ((pao_T__)(val)));			\
		break;							\
	case 8:								\
		if (pao_ID__ == 1)					\
			asm("incq "__percpu_arg(0) : "+m" (var));	\
		else if (pao_ID__ == -1)				\
			asm("decq "__percpu_arg(0) : "+m" (var));	\
		else							\
			asm("addq %1, "__percpu_arg(0)			\
			    : "+m" (var)				\
			    : "re" ((pao_T__)(val)));			\
		break;							\
	default: __bad_percpu_size();					\
	}								\
} while (0)
#define percpu_and(var, val)		percpu_to_op("and", var, val)
#define percpu_from_op(op, var, constraint)		\
({							\
	typeof(var) pfo_ret__;				\
	switch (sizeof(var)) {				\
	case 1:						\
		asm(op "b "__percpu_arg(1)",%0"		\
		    : "=q" (pfo_ret__)			\
		    : constraint);			\
		break;					\
	case 2:						\
		asm(op "w "__percpu_arg(1)",%0"		\
		    : "=r" (pfo_ret__)			\
		    : constraint);			\
		break;					\
	case 4:						\
		asm(op "l "__percpu_arg(1)",%0"		\
		    : "=r" (pfo_ret__)			\
		    : constraint);			\
		break;					\
	case 8:						\
		asm(op "q "__percpu_arg(1)",%0"		\
		    : "=r" (pfo_ret__)			\
		    : constraint);			\
		break;					\
	default: __bad_percpu_size();			\
	}						\
	pfo_ret__;					\
})
#define percpu_inc(var)		percpu_unary_op("inc", var)
#define percpu_or(var, val)		percpu_to_op("or", var, val)
#define percpu_read(var)		percpu_from_op("mov", var, "m" (var))
#define percpu_read_stable(var)		percpu_from_op("mov", var, "p" (&(var)))
#define percpu_sub(var, val)		percpu_add_op(var, -(val))
#define percpu_to_op(op, var, val)			\
do {							\
	typedef typeof(var) pto_T__;			\
	if (0) {					\
		pto_T__ pto_tmp__;			\
		pto_tmp__ = (val);			\
		(void)pto_tmp__;			\
	}						\
	switch (sizeof(var)) {				\
	case 1:						\
		asm(op "b %1,"__percpu_arg(0)		\
		    : "+m" (var)			\
		    : "qi" ((pto_T__)(val)));		\
		break;					\
	case 2:						\
		asm(op "w %1,"__percpu_arg(0)		\
		    : "+m" (var)			\
		    : "ri" ((pto_T__)(val)));		\
		break;					\
	case 4:						\
		asm(op "l %1,"__percpu_arg(0)		\
		    : "+m" (var)			\
		    : "ri" ((pto_T__)(val)));		\
		break;					\
	case 8:						\
		asm(op "q %1,"__percpu_arg(0)		\
		    : "+m" (var)			\
		    : "re" ((pto_T__)(val)));		\
		break;					\
	default: __bad_percpu_size();			\
	}						\
} while (0)
#define percpu_unary_op(op, var)			\
({							\
	switch (sizeof(var)) {				\
	case 1:						\
		asm(op "b "__percpu_arg(0)		\
		    : "+m" (var));			\
		break;					\
	case 2:						\
		asm(op "w "__percpu_arg(0)		\
		    : "+m" (var));			\
		break;					\
	case 4:						\
		asm(op "l "__percpu_arg(0)		\
		    : "+m" (var));			\
		break;					\
	case 8:						\
		asm(op "q "__percpu_arg(0)		\
		    : "+m" (var));			\
		break;					\
	default: __bad_percpu_size();			\
	}						\
})
#define percpu_write(var, val)		percpu_to_op("mov", var, val)
#define percpu_xor(var, val)		percpu_to_op("xor", var, val)
#define this_cpu_add_1(pcp, val)	percpu_add_op((pcp), val)
#define this_cpu_add_2(pcp, val)	percpu_add_op((pcp), val)
#define this_cpu_add_4(pcp, val)	percpu_add_op((pcp), val)
#define this_cpu_add_8(pcp, val)	percpu_add_op((pcp), val)
#define this_cpu_and_1(pcp, val)	percpu_to_op("and", (pcp), val)
#define this_cpu_and_2(pcp, val)	percpu_to_op("and", (pcp), val)
#define this_cpu_and_4(pcp, val)	percpu_to_op("and", (pcp), val)
#define this_cpu_and_8(pcp, val)	percpu_to_op("and", (pcp), val)
#define this_cpu_or_1(pcp, val)		percpu_to_op("or", (pcp), val)
#define this_cpu_or_2(pcp, val)		percpu_to_op("or", (pcp), val)
#define this_cpu_or_4(pcp, val)		percpu_to_op("or", (pcp), val)
#define this_cpu_or_8(pcp, val)		percpu_to_op("or", (pcp), val)
#define this_cpu_read_1(pcp)		percpu_from_op("mov", (pcp), "m"(pcp))
#define this_cpu_read_2(pcp)		percpu_from_op("mov", (pcp), "m"(pcp))
#define this_cpu_read_4(pcp)		percpu_from_op("mov", (pcp), "m"(pcp))
#define this_cpu_read_8(pcp)		percpu_from_op("mov", (pcp), "m"(pcp))
#define this_cpu_write_1(pcp, val)	percpu_to_op("mov", (pcp), val)
#define this_cpu_write_2(pcp, val)	percpu_to_op("mov", (pcp), val)
#define this_cpu_write_4(pcp, val)	percpu_to_op("mov", (pcp), val)
#define this_cpu_write_8(pcp, val)	percpu_to_op("mov", (pcp), val)
#define this_cpu_xor_1(pcp, val)	percpu_to_op("xor", (pcp), val)
#define this_cpu_xor_2(pcp, val)	percpu_to_op("xor", (pcp), val)
#define this_cpu_xor_4(pcp, val)	percpu_to_op("xor", (pcp), val)
#define this_cpu_xor_8(pcp, val)	percpu_to_op("xor", (pcp), val)
#define x86_test_and_clear_bit_percpu(bit, var)				\
({									\
	int old__;							\
	asm volatile("btr %2,"__percpu_arg(1)"\n\tsbbl %0,%0"		\
		     : "=r" (old__), "+m" (var)				\
		     : "dIr" (bit));					\
	old__;								\
})
#define PER_CPU_ALIGNED_SECTION "..shared_aligned"

#define PER_CPU_BASE_SECTION ".data..percpu"

#define PER_CPU_FIRST_SECTION "..first"
#define PER_CPU_SHARED_ALIGNED_SECTION "..shared_aligned"
#define SHIFT_PERCPU_PTR(__p, __offset)	({				\
	__verify_pcpu_ptr((__p));					\
	RELOC_HIDE((typeof(*(__p)) __kernel __force *)(__p), (__offset)); \
})
#define VERIFY_PERCPU_PTR(__p) ({			\
	__verify_pcpu_ptr((__p));			\
	(typeof(*(__p)) __kernel __force *)(__p);	\
})

#define __get_cpu_var(var) \
	(*SHIFT_PERCPU_PTR(&(var), my_cpu_offset))
#define __my_cpu_offset per_cpu_offset(raw_smp_processor_id())
#define __raw_get_cpu_var(var) \
	(*SHIFT_PERCPU_PTR(&(var), __my_cpu_offset))
#define __this_cpu_ptr(ptr) SHIFT_PERCPU_PTR(ptr, __my_cpu_offset)
#define my_cpu_offset per_cpu_offset(smp_processor_id())
#define per_cpu(var, cpu) \
	(*SHIFT_PERCPU_PTR(&(var), per_cpu_offset(cpu)))
#define per_cpu_offset(x) (__per_cpu_offset[x])
#define this_cpu_ptr(ptr) SHIFT_PERCPU_PTR(ptr, my_cpu_offset)
#define DECLARE_PER_CPU(type, name)					\
	DECLARE_PER_CPU_SECTION(type, name, "")
#define DECLARE_PER_CPU_ALIGNED(type, name)				\
	DECLARE_PER_CPU_SECTION(type, name, PER_CPU_ALIGNED_SECTION)	\
	____cacheline_aligned
#define DECLARE_PER_CPU_FIRST(type, name)				\
	DECLARE_PER_CPU_SECTION(type, name, PER_CPU_FIRST_SECTION)
#define DECLARE_PER_CPU_PAGE_ALIGNED(type, name)			\
	DECLARE_PER_CPU_SECTION(type, name, "..page_aligned")		\
	__aligned(PAGE_SIZE)
#define DECLARE_PER_CPU_SECTION(type, name, sec)			\
	extern __PCPU_DUMMY_ATTRS char __pcpu_scope_##name;		\
	extern __PCPU_ATTRS(sec) __typeof__(type) name
#define DECLARE_PER_CPU_SHARED_ALIGNED(type, name)			\
	DECLARE_PER_CPU_SECTION(type, name, PER_CPU_SHARED_ALIGNED_SECTION) \
	____cacheline_aligned_in_smp
#define DEFINE_PER_CPU(type, name)					\
	DEFINE_PER_CPU_SECTION(type, name, "")
#define DEFINE_PER_CPU_ALIGNED(type, name)				\
	DEFINE_PER_CPU_SECTION(type, name, PER_CPU_ALIGNED_SECTION)	\
	____cacheline_aligned
#define DEFINE_PER_CPU_FIRST(type, name)				\
	DEFINE_PER_CPU_SECTION(type, name, PER_CPU_FIRST_SECTION)
#define DEFINE_PER_CPU_PAGE_ALIGNED(type, name)				\
	DEFINE_PER_CPU_SECTION(type, name, "..page_aligned")		\
	__aligned(PAGE_SIZE)
#define DEFINE_PER_CPU_SECTION(type, name, sec)				\
	__PCPU_DUMMY_ATTRS char __pcpu_scope_##name;			\
	extern __PCPU_DUMMY_ATTRS char __pcpu_unique_##name;		\
	__PCPU_DUMMY_ATTRS char __pcpu_unique_##name;			\
	__PCPU_ATTRS(sec) PER_CPU_DEF_ATTRIBUTES __weak			\
	__typeof__(type) name
#define DEFINE_PER_CPU_SHARED_ALIGNED(type, name)			\
	DEFINE_PER_CPU_SECTION(type, name, PER_CPU_SHARED_ALIGNED_SECTION) \
	____cacheline_aligned_in_smp
#define EXPORT_PER_CPU_SYMBOL(var) EXPORT_SYMBOL(var)
#define EXPORT_PER_CPU_SYMBOL_GPL(var) EXPORT_SYMBOL_GPL(var)

#define __PCPU_ATTRS(sec)						\
	__percpu __attribute__((section(PER_CPU_BASE_SECTION sec)))	\
	PER_CPU_ATTRIBUTES
#define __verify_pcpu_ptr(ptr)	do {					\
	const void __percpu *__vpp_verify = (typeof(ptr))NULL;		\
	(void)__vpp_verify;						\
} while (0)


#define __HAVE_ARCH_GATE_AREA 1
#define __alloc_zeroed_user_highpage(movableflags, vma, vaddr) \
	alloc_page_vma(GFP_HIGHUSER | __GFP_ZERO | movableflags, vma, vaddr)
#define __boot_pa(x)		__pa(x)
#define __boot_va(x)		__va(x)
#define __pa(x)		__phys_addr((unsigned long)(x))
#define __pa_nodebug(x)	__phys_addr_nodebug((unsigned long)(x))
#define __pa_symbol(x)	__pa(__phys_reloc_hide((unsigned long)(x)))
#define __va(x)			((void *)((unsigned long)(x)+PAGE_OFFSET))
#define pfn_to_kaddr(pfn)      __va((pfn) << PAGE_SHIFT)
#define virt_addr_valid(kaddr)	__virt_addr_valid((unsigned long) (kaddr))
#define virt_to_page(kaddr)	pfn_to_page(__pa(kaddr) >> PAGE_SHIFT)


#define __page_to_pfn(page)	((unsigned long)((page) - mem_map) + \
				 ARCH_PFN_OFFSET)
#define __pfn_to_page(pfn)	(mem_map + ((pfn) - ARCH_PFN_OFFSET))
#define arch_local_page_offset(pfn, nid)	\
	((pfn) - NODE_DATA(nid)->node_start_pfn)
#define arch_pfn_to_nid(pfn)	pfn_to_nid(pfn)
#define page_to_pfn __page_to_pfn
#define pfn_to_page __pfn_to_page


#define __phys_addr(x)		__phys_addr_nodebug(x)
#define __phys_addr_nodebug(x)	((x) - PAGE_OFFSET)
#define __phys_reloc_hide(x)	RELOC_HIDE((x), 0)
#define pfn_valid(pfn)		((pfn) < max_mapnr)



#define current get_current()



#define S16_C(x) x
#define S32_C(x) x
#define S64_C(x) x ## LL
#define S8_C(x)  x
#define U16_C(x) x ## U
#define U32_C(x) x ## U
#define U64_C(x) x ## ULL
#define U8_C(x)  x ## U


#define VM86_ARG(retval)	((retval) >> 8)
#define VM86_TSS_ESP0 flags
#define VM86_TYPE(retval)	((retval) & 0xff)

#define handle_vm86_fault(a, b)


#define MAX_REG_OFFSET (offsetof(struct pt_regs, ss))

#define arch_has_block_step()	(1)
#define arch_has_single_step()	(1)
#define X86_CR4_OSXMMEXCPT 0x00000400 
#define X86_CR4_OSXSAVE 0x00040000 

#define ARGOFFSET R11
#define CS  13
#define DS 7
#define EAX 6
#define EBP 5
#define EBX 0
#define ECX 1
#define EDI 4
#define EDX 2
#define EFL 14
#define EFLAGS 144
#define EIP 12
#define ES 8
#define ESI 3
#define FRAME_SIZE 17
#define FS 9
#define GS 10
#define ORIG_EAX 11
#define ORIG_RAX 120       
#define PTRACE_GETFPREGS          14
#define PTRACE_GETFPXREGS         18
#define PTRACE_GETREGS            12
#define PTRACE_GET_THREAD_AREA    25
#define PTRACE_OLDSETOPTIONS      21
#define PTRACE_SETFPREGS          15
#define PTRACE_SETFPXREGS         19
#define PTRACE_SETREGS            13
#define PTRACE_SET_THREAD_AREA    26
#define PTRACE_SYSEMU_SINGLESTEP  32
#define R10 56
#define R11 48
#define R12 24
#define R13 16
#define R14 8
#define R15 0
#define R8 72
#define R9 64
#define RAX 80
#define RBP 32
#define RBX 40
#define RCX 88
#define RDI 112
#define RDX 96
#define RIP 128
#define RSI 104
#define RSP 152
#define SS   16
#define UESP 15

#define LDT_empty(info) (_LDT_empty(info) && ((info)->lm == 0))

#define _LDT_empty(info)				\
	((info)->base_addr		== 0	&&	\
	 (info)->limit			== 0	&&	\
	 (info)->contents		== 0	&&	\
	 (info)->read_exec_only		== 1	&&	\
	 (info)->seg_32bit		== 0	&&	\
	 (info)->limit_in_pages		== 0	&&	\
	 (info)->seg_not_present	== 1	&&	\
	 (info)->useable		== 0)
#define load_TLS(t, cpu) native_load_tls(t, cpu)
#define load_TR_desc() native_load_tr_desc()
#define load_gdt(dtr) native_load_gdt(dtr)
#define load_idt(dtr) native_load_idt(dtr)
#define load_ldt(ldt) asm volatile("lldt %0"::"m" (ldt))
#define load_tr(tr) asm volatile("ltr %0"::"m" (tr))
#define set_ldt native_set_ldt
#define set_tss_desc(cpu, addr) __set_tss_desc(cpu, GDT_ENTRY_TSS, addr)
#define store_gdt(dtr) native_store_gdt(dtr)
#define store_idt(dtr) native_store_idt(dtr)
#define store_ldt(ldt) asm("sldt %0" : "=m"(ldt))
#define store_tr(tr) (tr = native_store_tr())
#define write_gdt_entry(dt, entry, desc, type)		\
	native_write_gdt_entry(dt, entry, desc, type)
#define write_idt_entry(dt, entry, g)		\
	native_write_idt_entry(dt, entry, g)
#define write_ldt_entry(dt, entry, desc)	\
	native_write_ldt_entry(dt, entry, desc)



#define __flush_tlb() __native_flush_tlb()
#define __flush_tlb_global() __native_flush_tlb_global()
#define __flush_tlb_single(addr) __native_flush_tlb_single(addr)
#define flush_tlb()	flush_tlb_current_task()
#define flush_tlb_all() __flush_tlb_all()
#define flush_tlb_others(mask, mm, va)	native_flush_tlb_others(mask, mm, va)
#define local_flush_tlb() __flush_tlb()

#define cpu_physical_id(cpu)	per_cpu(x86_cpu_to_apicid, cpu)
#  define hard_smp_processor_id()	0
#define raw_smp_processor_id() (percpu_read(cpu_number))
#define safe_smp_processor_id()		smp_processor_id()
#define stack_smp_processor_id()					\
({								\
	struct thread_info *ti;						\
	__asm__("andq %%rsp,%0; ":"=r" (ti) : "0" (CURRENT_MASK));	\
	ti->cpu;							\
})
#define startup_ipi_hook(phys_apicid, start_eip, start_esp) do { } while (0)
#define wbinvd_on_cpu(cpu)     wbinvd()
#define GET_THREAD_INFO(reg)	 \
	movl $-THREAD_SIZE, reg; \
	andl %esp, reg
#define GET_THREAD_INFO_WITH_ESP(reg) \
	andl $-THREAD_SIZE, reg
#define INIT_THREAD_INFO(tsk)			\
{						\
	.task		= &tsk,			\
	.exec_domain	= &default_exec_domain,	\
	.flags		= 0,			\
	.cpu		= 0,			\
	.preempt_count	= INIT_PREEMPT_COUNT,	\
	.addr_limit	= KERNEL_DS,		\
	.restart_block = {			\
		.fn = do_no_restart_syscall,	\
	},					\
}
#define KERNEL_STACK_OFFSET (5*8)
#define THREAD_FLAGS (GFP_KERNEL | __GFP_NOTRACK | __GFP_ZERO)

#define _TIF_WORK_CTXSW_NEXT (_TIF_WORK_CTXSW|_TIF_DEBUG)
#define _TIF_WORK_CTXSW_PREV (_TIF_WORK_CTXSW|_TIF_USER_RETURN_NOTIFY)

#define alloc_thread_info(tsk)						\
	((struct thread_info *)__get_free_pages(THREAD_FLAGS, THREAD_ORDER))
#define arch_task_cache_init arch_task_cache_init
#define tsk_is_polling(t) (task_thread_info(t)->status & TS_POLLING)
#define ATOMIC_INIT(i)	{ (i) }

#define atomic_clear_mask(mask, addr)				\
	asm volatile(LOCK_PREFIX "andl %0,%1"			\
		     : : "r" (~(mask)), "m" (*(addr)) : "memory")
#define atomic_dec_return(v)  (atomic_sub_return(1, v))
#define atomic_inc_not_zero(v) atomic_add_unless((v), 1, 0)
#define atomic_inc_return(v)  (atomic_add_return(1, v))
#define atomic_set_mask(mask, addr)				\
	asm volatile(LOCK_PREFIX "orl %0,%1"			\
		     : : "r" ((unsigned)(mask)), "m" (*(addr))	\
		     : "memory")
#define smp_mb__after_atomic_dec()	barrier()
#define smp_mb__after_atomic_inc()	barrier()
#define smp_mb__before_atomic_dec()	barrier()
#define smp_mb__before_atomic_inc()	barrier()
#define ATOMIC_LONG_INIT(i)	ATOMIC_INIT(i)

#define atomic_long_cmpxchg(l, old, new) \
	(atomic64_cmpxchg((atomic64_t *)(l), (old), (new)))
#define atomic_long_inc_not_zero(l) atomic64_inc_not_zero((atomic64_t *)(l))
#define atomic_long_xchg(v, new) \
	(atomic64_xchg((atomic64_t *)(v), (new)))
#define ALTERNATIVE(oldinstr, newinstr, feature)			\
									\
      "661:\n\t" oldinstr "\n662:\n"					\
      ".section .altinstructions,\"a\"\n"				\
      _ASM_ALIGN "\n"							\
      _ASM_PTR "661b\n"					\
      _ASM_PTR "663f\n"					\
      "	 .word " __stringify(feature) "\n"		\
      "	 .byte 662b-661b\n"				\
      "	 .byte 664f-663f\n"				\
      ".previous\n"							\
      ".section .discard,\"aw\",@progbits\n"				\
      "	 .byte 0xff + (664f-663f) - (662b-661b)\n" 	\
      ".previous\n"							\
      ".section .altinstr_replacement, \"ax\"\n"			\
      "663:\n\t" newinstr "\n664:\n"			\
      ".previous"
#define ASM_OUTPUT2(a...) a
#define LOCK_PREFIX LOCK_PREFIX_HERE "\n\tlock; "
#define LOCK_PREFIX_HERE \
		".section .smp_locks,\"a\"\n"	\
		".balign 4\n"			\
		".long 671f - .\n" 	\
		".previous\n"			\
		"671:"

#define alternative(oldinstr, newinstr, feature)			\
	asm volatile (ALTERNATIVE(oldinstr, newinstr, feature) : : : "memory")
#define alternative_call(oldfunc, newfunc, feature, output, input...)	\
	asm volatile (ALTERNATIVE("call %P[old]", "call %P[new]", feature) \
		: output : [old] "i" (oldfunc), [new] "i" (newfunc), ## input)
#define alternative_input(oldinstr, newinstr, feature, input...)	\
	asm volatile (ALTERNATIVE(oldinstr, newinstr, feature)		\
		: : "i" (0), ## input)
#define alternative_io(oldinstr, newinstr, feature, output, input...)	\
	asm volatile (ALTERNATIVE(oldinstr, newinstr, feature)		\
		: output : "i" (0), ## input)

#define KMEM_CACHE(__struct, __flags) kmem_cache_create(#__struct,\
		sizeof(struct __struct), __alignof__(struct __struct),\
		(__flags), NULL)
#define ZERO_OR_NULL_PTR(x) ((unsigned long)(x) <= \
				(unsigned long)ZERO_SIZE_PTR)
#define ZERO_SIZE_PTR ((void *)16)
#define kmalloc_node_track_caller(size, flags, node) \
	__kmalloc_node_track_caller(size, flags, node, \
			_RET_IP_)
#define kmalloc_track_caller(size, flags) \
	__kmalloc_track_caller(size, flags, _RET_IP_)
#define ARCH_KMALLOC_MINALIGN ARCH_DMA_MINALIGN
#define ARCH_SLAB_MINALIGN 0
#define CACHE(x) \
		if (size <= x) \
			goto found; \
		else \
			i++;


#define KMALLOC_CACHES (2 * SLUB_PAGE_SHIFT)
#define KMALLOC_MIN_SIZE ARCH_DMA_MINALIGN
#define KMALLOC_SHIFT_LOW ilog2(KMALLOC_MIN_SIZE)
#define SLUB_DMA __GFP_DMA
#define SLUB_MAX_SIZE (2 * PAGE_SIZE)
#define SLUB_PAGE_SHIFT (PAGE_SHIFT + 2)



#define kmap_atomic_pfn(pfn, idx)	kmap_atomic(pfn_to_page(pfn), (idx))
#define kmap_atomic_prot(page, idx, prot)	kmap_atomic(page, idx)
#define kmap_atomic_to_page(ptr)	virt_to_page(ptr)
#define kmap_flush_unused()	do {} while(0)
#define kunmap_atomic(addr, idx) do { \
		BUILD_BUG_ON(__same_type((addr), struct page *)); \
		kunmap_atomic_notypecheck((addr), (idx)); \
	} while (0)
#define totalhigh_pages 0UL

#define probe_kernel_address(addr, retval)		\
	({						\
		long ret;				\
		mm_segment_t old_fs = get_fs();		\
							\
		set_fs(KERNEL_DS);			\
		pagefault_disable();			\
		ret = __copy_from_user_inatomic(&(retval), (__force typeof(retval) __user *)(addr), sizeof(retval));		\
		pagefault_enable();			\
		set_fs(old_fs);				\
		ret;					\
	})



#define KVM_POSSIBLE_CR0_GUEST_BITS X86_CR0_TS
#define HPA_ERR_MASK ((hpa_t)1 << HPA_MSB)
#define HPA_MSB ((sizeof(hpa_t) * 8) - 1)
#define KVM_MAX_IRQ_ROUTES 1024
#define KVM_MEM_MAX_NR_PAGES ((1UL << 31) - 1)
#define KVM_REQ_DEACTIVATE_FPU    10
#define KVM_REQ_KICK               9
#define KVM_REQ_KVMCLOCK_UPDATE    8
#define KVM_REQ_MIGRATE_TIMER      1
#define KVM_REQ_MMU_RELOAD         3
#define KVM_REQ_MMU_SYNC           7
#define KVM_REQ_PENDING_TIMER      5
#define KVM_REQ_REPORT_TPR_ACCESS  2
#define KVM_REQ_TLB_FLUSH          0
#define KVM_REQ_TRIPLE_FAULT       4
#define KVM_REQ_UNHALT             6
#define NR_IOBUS_DEVS 200

#define kvm_for_each_vcpu(idx, vcpup, kvm) \
	for (idx = 0, vcpup = kvm_get_vcpu(kvm, idx); \
	     idx < atomic_read(&kvm->online_vcpus) && vcpup; \
	     vcpup = kvm_get_vcpu(kvm, ++idx))
#define kvm_printf(kvm, fmt ...) printk(KERN_DEBUG fmt)
#define pr_unimpl(vcpu, fmt, ...)					\
 do {									\
	if (printk_ratelimit())						\
		printk(KERN_ERR "kvm: %i: cpu%i " fmt,			\
		       current->tgid, (vcpu)->vcpu_id , ## __VA_ARGS__); \
 } while (0)
#define vcpu_printf(vcpu, fmt...) kvm_printf(vcpu->kvm, fmt)


#define kvm_guest_init() do { } while (0)
#define KVMIO 0xAE
#define KVM_API_VERSION 12
#define KVM_ASSIGN_DEV_IRQ        _IOW(KVMIO,  0x70, struct kvm_assigned_irq)
#define KVM_ASSIGN_IRQ            __KVM_DEPRECATED_VM_R_0x70
#define KVM_ASSIGN_PCI_DEVICE     _IOR(KVMIO,  0x69, \
				       struct kvm_assigned_pci_dev)
#define KVM_ASSIGN_SET_MSIX_ENTRY _IOW(KVMIO,  0x74, \
				       struct kvm_assigned_msix_entry)
#define KVM_ASSIGN_SET_MSIX_NR    _IOW(KVMIO,  0x73, \
				       struct kvm_assigned_msix_nr)
#define KVM_CAP_ADJUST_CLOCK 39
#define KVM_CAP_ASSIGN_DEV_IRQ 29
#define KVM_CAP_CLOCKSOURCE 8
#define KVM_CAP_COALESCED_MMIO 15
#define KVM_CAP_DEBUGREGS 50
#define KVM_CAP_DESTROY_MEMORY_REGION_WORKS 21
#define KVM_CAP_DEVICE_ASSIGNMENT 17
#define KVM_CAP_DEVICE_DEASSIGNMENT 27
#define KVM_CAP_DEVICE_MSI 20
#define KVM_CAP_DEVICE_MSIX 28
#define KVM_CAP_ENABLE_CAP 54
#define KVM_CAP_EXT_CPUID 7
#define KVM_CAP_HYPERV 44
#define KVM_CAP_HYPERV_SPIN 46
#define KVM_CAP_HYPERV_VAPIC 45
#define KVM_CAP_INTERNAL_ERROR_DATA 40
#define KVM_CAP_INTR_SHADOW 49
#define KVM_CAP_IOEVENTFD 36
#define KVM_CAP_IOMMU 18
#define KVM_CAP_IRQFD 32
#define KVM_CAP_IRQ_INJECT_STATUS 26
#define KVM_CAP_IRQ_ROUTING 25
#define KVM_CAP_JOIN_MEMORY_REGIONS_WORKS 30
#define KVM_CAP_MCE 31
#define KVM_CAP_MMU_SHADOW_CACHE_CONTROL 2
#define KVM_CAP_MP_STATE 14
#define KVM_CAP_NOP_IO_DELAY 12
#define KVM_CAP_NR_MEMSLOTS 10   
#define KVM_CAP_NR_VCPUS 9       
#define KVM_CAP_PCI_SEGMENT 47
#define KVM_CAP_PIT 11
#define KVM_CAP_PIT2 33
#define KVM_CAP_PIT_STATE2 35
#define KVM_CAP_PPC_OSI 52
#define KVM_CAP_PPC_PAIRED_SINGLES 48
#define KVM_CAP_PPC_SEGSTATE 43
#define KVM_CAP_PPC_UNSET_IRQ 53
#define KVM_CAP_PV_MMU 13
#define KVM_CAP_REINJECT_CONTROL 24
#define KVM_CAP_S390_PSW 42
#define KVM_CAP_SET_BOOT_CPU_ID 34
#define KVM_CAP_SET_GUEST_DEBUG 23
#define KVM_CAP_SET_IDENTITY_MAP_ADDR 37
#define KVM_CAP_SET_TSS_ADDR 4
#define KVM_CAP_SYNC_MMU 16  
#define KVM_CAP_USER_MEMORY 3
#define KVM_CAP_USER_NMI 22
#define KVM_CAP_VAPIC 6
#define KVM_CAP_VCPU_EVENTS 41
#define KVM_CAP_X86_ROBUST_SINGLESTEP 51
#define KVM_CAP_XCRS 56
#define KVM_CAP_XEN_HVM 38
#define KVM_CAP_XSAVE 55
#define KVM_CHECK_EXTENSION       _IO(KVMIO,   0x03)
#define KVM_COALESCED_MMIO_MAX \
	((PAGE_SIZE - sizeof(struct kvm_coalesced_mmio_ring)) / \
	 sizeof(struct kvm_coalesced_mmio))
#define KVM_CREATE_IRQCHIP        _IO(KVMIO,   0x60)
#define KVM_CREATE_PIT            _IO(KVMIO,   0x64)
#define KVM_CREATE_VCPU           _IO(KVMIO,   0x41)
#define KVM_CREATE_VM             _IO(KVMIO,   0x01) 
#define KVM_DEASSIGN_DEV_IRQ      _IOW(KVMIO,  0x75, struct kvm_assigned_irq)
#define KVM_DEASSIGN_PCI_DEVICE   _IOW(KVMIO,  0x72, \
				       struct kvm_assigned_pci_dev)
#define KVM_DEBUG_GUEST           __KVM_DEPRECATED_VCPU_W_0x87
#define KVM_DEV_IRQ_GUEST_INTX   (1 << 8)
#define KVM_DEV_IRQ_GUEST_MASK   0xff00
#define KVM_DEV_IRQ_GUEST_MSI    (1 << 9)
#define KVM_DEV_IRQ_GUEST_MSIX   (1 << 10)
#define KVM_DEV_IRQ_HOST_INTX    (1 << 0)
#define KVM_DEV_IRQ_HOST_MSI     (1 << 1)
#define KVM_DEV_IRQ_HOST_MSIX    (1 << 2)
#define KVM_ENABLE_CAP            _IOW(KVMIO,  0xa3, struct kvm_enable_cap)
#define KVM_EXIT_DCR              15
#define KVM_EXIT_DEBUG            4
#define KVM_EXIT_EXCEPTION        1
#define KVM_EXIT_FAIL_ENTRY       9
#define KVM_EXIT_HLT              5
#define KVM_EXIT_HYPERCALL        3
#define KVM_EXIT_INTERNAL_ERROR   17
#define KVM_EXIT_INTR             10
#define KVM_EXIT_IO               2
#define KVM_EXIT_IO_IN  0
#define KVM_EXIT_IO_OUT 1
#define KVM_EXIT_IRQ_WINDOW_OPEN  7
#define KVM_EXIT_MMIO             6
#define KVM_EXIT_NMI              16
#define KVM_EXIT_OSI              18
#define KVM_EXIT_S390_RESET       14
#define KVM_EXIT_S390_SIEIC       13
#define KVM_EXIT_SET_TPR          11
#define KVM_EXIT_SHUTDOWN         8
#define KVM_EXIT_TPR_ACCESS       12
#define KVM_EXIT_UNKNOWN          0
#define KVM_GET_API_VERSION       _IO(KVMIO,   0x00)
#define KVM_GET_CLOCK             _IOR(KVMIO,  0x7c, struct kvm_clock_data)
#define KVM_GET_CPUID2            _IOWR(KVMIO, 0x91, struct kvm_cpuid2)
#define KVM_GET_DEBUGREGS         _IOR(KVMIO,  0xa1, struct kvm_debugregs)
#define KVM_GET_DIRTY_LOG         _IOW(KVMIO,  0x42, struct kvm_dirty_log)
#define KVM_GET_FPU               _IOR(KVMIO,  0x8c, struct kvm_fpu)
#define KVM_GET_IRQCHIP           _IOWR(KVMIO, 0x62, struct kvm_irqchip)
#define KVM_GET_LAPIC             _IOR(KVMIO,  0x8e, struct kvm_lapic_state)
#define KVM_GET_MP_STATE          _IOR(KVMIO,  0x98, struct kvm_mp_state)
#define KVM_GET_MSRS              _IOWR(KVMIO, 0x88, struct kvm_msrs)
#define KVM_GET_MSR_INDEX_LIST    _IOWR(KVMIO, 0x02, struct kvm_msr_list)
#define KVM_GET_NR_MMU_PAGES      _IO(KVMIO,   0x45)
#define KVM_GET_PIT               _IOWR(KVMIO, 0x65, struct kvm_pit_state)
#define KVM_GET_PIT2              _IOR(KVMIO,  0x9f, struct kvm_pit_state2)
#define KVM_GET_REGS              _IOR(KVMIO,  0x81, struct kvm_regs)
#define KVM_GET_SREGS             _IOR(KVMIO,  0x83, struct kvm_sregs)
#define KVM_GET_SUPPORTED_CPUID   _IOWR(KVMIO, 0x05, struct kvm_cpuid2)
#define KVM_GET_VCPU_EVENTS       _IOR(KVMIO,  0x9f, struct kvm_vcpu_events)
#define KVM_GET_VCPU_MMAP_SIZE    _IO(KVMIO,   0x04) 
#define KVM_IA64_VCPU_GET_STACK   _IOR(KVMIO,  0x9a, void *)
#define KVM_IA64_VCPU_SET_STACK   _IOW(KVMIO,  0x9b, void *)
#define KVM_INTERNAL_ERROR_EMULATION 1
#define KVM_INTERNAL_ERROR_SIMUL_EX 2
#define KVM_INTERRUPT             _IOW(KVMIO,  0x86, struct kvm_interrupt)
#define KVM_IOEVENTFD             _IOW(KVMIO,  0x79, struct kvm_ioeventfd)
#define KVM_IOEVENTFD_FLAG_DATAMATCH (1 << kvm_ioeventfd_flag_nr_datamatch)
#define KVM_IOEVENTFD_FLAG_DEASSIGN  (1 << kvm_ioeventfd_flag_nr_deassign)
#define KVM_IOEVENTFD_FLAG_PIO       (1 << kvm_ioeventfd_flag_nr_pio)
#define KVM_IOEVENTFD_VALID_FLAG_MASK  ((1 << kvm_ioeventfd_flag_nr_max) - 1)
#define KVM_IRQFD                 _IOW(KVMIO,  0x76, struct kvm_irqfd)
#define KVM_IRQFD_FLAG_DEASSIGN (1 << 0)
#define KVM_IRQ_LINE              _IOW(KVMIO,  0x61, struct kvm_irq_level)
#define KVM_IRQ_LINE_STATUS       _IOWR(KVMIO, 0x67, struct kvm_irq_level)
#define KVM_IRQ_ROUTING_IRQCHIP 1
#define KVM_IRQ_ROUTING_MSI 2
#define KVM_MEMSLOT_INVALID      (1UL << 1)
#define KVM_MEM_LOG_DIRTY_PAGES  1UL
#define KVM_MP_STATE_HALTED            3
#define KVM_MP_STATE_INIT_RECEIVED     2
#define KVM_MP_STATE_RUNNABLE          0
#define KVM_MP_STATE_SIPI_RECEIVED     4
#define KVM_MP_STATE_UNINITIALIZED     1
#define KVM_NMI                   _IO(KVMIO,   0x9a)
#define KVM_PIT_SPEAKER_DUMMY     1
#define KVM_REGISTER_COALESCED_MMIO \
			_IOW(KVMIO,  0x67, struct kvm_coalesced_mmio_zone)
#define KVM_REINJECT_CONTROL      _IO(KVMIO,   0x71)
#define KVM_RUN                   _IO(KVMIO,   0x80)
#define KVM_S390_ENABLE_SIE       _IO(KVMIO,   0x06)
#define KVM_S390_INITIAL_RESET    _IO(KVMIO,   0x97)
#define KVM_S390_INTERRUPT        _IOW(KVMIO,  0x94, struct kvm_s390_interrupt)
#define KVM_S390_RESET_CLEAR     2
#define KVM_S390_RESET_CPU_INIT  8
#define KVM_S390_RESET_IPL       16
#define KVM_S390_RESET_POR       1
#define KVM_S390_RESET_SUBSYSTEM 4
#define KVM_S390_SET_INITIAL_PSW  _IOW(KVMIO,  0x96, struct kvm_s390_psw)
#define KVM_S390_STORE_STATUS_NOADDR    (-1ul)
#define KVM_S390_STORE_STATUS_PREFIXED  (-2ul)
#define KVM_SET_BOOT_CPU_ID       _IO(KVMIO,   0x78)
#define KVM_SET_CLOCK             _IOW(KVMIO,  0x7b, struct kvm_clock_data)
#define KVM_SET_CPUID             _IOW(KVMIO,  0x8a, struct kvm_cpuid)
#define KVM_SET_CPUID2            _IOW(KVMIO,  0x90, struct kvm_cpuid2)
#define KVM_SET_DEBUGREGS         _IOW(KVMIO,  0xa2, struct kvm_debugregs)
#define KVM_SET_FPU               _IOW(KVMIO,  0x8d, struct kvm_fpu)
#define KVM_SET_GSI_ROUTING       _IOW(KVMIO,  0x6a, struct kvm_irq_routing)
#define KVM_SET_GUEST_DEBUG       _IOW(KVMIO,  0x9b, struct kvm_guest_debug)
#define KVM_SET_IDENTITY_MAP_ADDR _IOW(KVMIO,  0x48, __u64)
#define KVM_SET_IRQCHIP           _IOR(KVMIO,  0x63, struct kvm_irqchip)
#define KVM_SET_LAPIC             _IOW(KVMIO,  0x8f, struct kvm_lapic_state)
#define KVM_SET_MEMORY_ALIAS      _IOW(KVMIO,  0x43, struct kvm_memory_alias)
#define KVM_SET_MEMORY_REGION     _IOW(KVMIO,  0x40, struct kvm_memory_region)
#define KVM_SET_MP_STATE          _IOW(KVMIO,  0x99, struct kvm_mp_state)
#define KVM_SET_MSRS              _IOW(KVMIO,  0x89, struct kvm_msrs)
#define KVM_SET_NR_MMU_PAGES      _IO(KVMIO,   0x44)
#define KVM_SET_PIT               _IOR(KVMIO,  0x66, struct kvm_pit_state)
#define KVM_SET_PIT2              _IOW(KVMIO,  0xa0, struct kvm_pit_state2)
#define KVM_SET_REGS              _IOW(KVMIO,  0x82, struct kvm_regs)
#define KVM_SET_SIGNAL_MASK       _IOW(KVMIO,  0x8b, struct kvm_signal_mask)
#define KVM_SET_SREGS             _IOW(KVMIO,  0x84, struct kvm_sregs)
#define KVM_SET_TSS_ADDR          _IO(KVMIO,   0x47)
#define KVM_SET_USER_MEMORY_REGION _IOW(KVMIO, 0x46, \
					struct kvm_userspace_memory_region)
#define KVM_SET_VAPIC_ADDR        _IOW(KVMIO,  0x93, struct kvm_vapic_addr)
#define KVM_SET_VCPU_EVENTS       _IOW(KVMIO,  0xa0, struct kvm_vcpu_events)
#define KVM_TPR_ACCESS_REPORTING  _IOWR(KVMIO, 0x92, struct kvm_tpr_access_ctl)
#define KVM_TRACE_DISABLE         __KVM_DEPRECATED_MAIN_0x08
#define KVM_TRACE_ENABLE          __KVM_DEPRECATED_MAIN_W_0x06
#define KVM_TRACE_PAUSE           __KVM_DEPRECATED_MAIN_0x07
#define KVM_TRANSLATE             _IOWR(KVMIO, 0x85, struct kvm_translation)
#define KVM_TRC_APIC_ACCESS      (KVM_TRC_HANDLER + 0x14)
#define KVM_TRC_CLTS             (KVM_TRC_HANDLER + 0x12)
#define KVM_TRC_CPUID            (KVM_TRC_HANDLER + 0x0D)
#define KVM_TRC_CR_READ          (KVM_TRC_HANDLER + 0x07)
#define KVM_TRC_CR_WRITE         (KVM_TRC_HANDLER + 0x08)
#define KVM_TRC_CYCLE_SIZE      8
#define KVM_TRC_DR_READ          (KVM_TRC_HANDLER + 0x09)
#define KVM_TRC_DR_WRITE         (KVM_TRC_HANDLER + 0x0A)
#define KVM_TRC_ENTRYEXIT       (1 << KVM_TRC_SHIFT)
#define KVM_TRC_EXTRA_MAX       7
#define KVM_TRC_GTLB_WRITE       (KVM_TRC_HANDLER + 0x16)
#define KVM_TRC_HANDLER         (1 << (KVM_TRC_SHIFT + 1))
#define KVM_TRC_HEAD_SIZE       12
#define KVM_TRC_HLT              (KVM_TRC_HANDLER + 0x11)
#define KVM_TRC_INJ_VIRQ         (KVM_TRC_HANDLER + 0x02)
#define KVM_TRC_INTR             (KVM_TRC_HANDLER + 0x0E)
#define KVM_TRC_IO_READ          (KVM_TRC_HANDLER + 0x05)
#define KVM_TRC_IO_WRITE         (KVM_TRC_HANDLER + 0x06)
#define KVM_TRC_LMSW             (KVM_TRC_HANDLER + 0x13)
#define KVM_TRC_MSR_READ         (KVM_TRC_HANDLER + 0x0B)
#define KVM_TRC_MSR_WRITE        (KVM_TRC_HANDLER + 0x0C)
#define KVM_TRC_NMI              (KVM_TRC_HANDLER + 0x0F)
#define KVM_TRC_PAGE_FAULT      (KVM_TRC_HANDLER + 0x01)
#define KVM_TRC_PEND_INTR        (KVM_TRC_HANDLER + 0x04)
#define KVM_TRC_PPC_INSTR        (KVM_TRC_HANDLER + 0x19)
#define KVM_TRC_REDELIVER_EVT    (KVM_TRC_HANDLER + 0x03)
#define KVM_TRC_SHIFT           16
#define KVM_TRC_STLB_INVAL       (KVM_TRC_HANDLER + 0x18)
#define KVM_TRC_STLB_WRITE       (KVM_TRC_HANDLER + 0x17)
#define KVM_TRC_TDP_FAULT        (KVM_TRC_HANDLER + 0x15)
#define KVM_TRC_VMENTRY         (KVM_TRC_ENTRYEXIT + 0x01)
#define KVM_TRC_VMEXIT          (KVM_TRC_ENTRYEXIT + 0x02)
#define KVM_TRC_VMMCALL          (KVM_TRC_HANDLER + 0x10)
#define KVM_UNREGISTER_COALESCED_MMIO \
			_IOW(KVMIO,  0x68, struct kvm_coalesced_mmio_zone)
#define KVM_X86_GET_MCE_CAP_SUPPORTED _IOR(KVMIO,  0x9d, __u64)
#define KVM_X86_SETUP_MCE         _IOW(KVMIO,  0x9c, __u64)
#define KVM_X86_SET_MCE           _IOW(KVMIO,  0x9e, struct kvm_x86_mce)
#define KVM_XEN_HVM_CONFIG        _IOW(KVMIO,  0x7a, struct kvm_xen_hvm_config)
#define __KVM_DEPRECATED_MAIN_0x07 _IO(KVMIO, 0x07)
#define __KVM_DEPRECATED_MAIN_0x08 _IO(KVMIO, 0x08)
#define __KVM_DEPRECATED_MAIN_W_0x06 \
	_IOW(KVMIO, 0x06, struct kvm_user_trace_setup)
#define __KVM_DEPRECATED_VCPU_W_0x87 _IOW(KVMIO, 0x87, struct kvm_debug_guest)
#define __KVM_DEPRECATED_VM_R_0x70 _IOR(KVMIO, 0x70, struct kvm_assigned_irq)


#define PFERR_FETCH_MASK (1U << 4)
#define PFERR_PRESENT_MASK (1U << 0)
#define PFERR_RSVD_MASK (1U << 3)
#define PFERR_USER_MASK (1U << 2)
#define PFERR_WRITE_MASK (1U << 1)
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
#define PT64_ROOT_LEVEL 4
#define PT_ACCESSED_MASK (1ULL << PT_ACCESSED_SHIFT)
#define PT_ACCESSED_SHIFT 5
#define PT_DIRECTORY_LEVEL 2
#define PT_DIRTY_MASK (1ULL << 6)
#define PT_DIR_PAT_MASK (1ULL << PT_DIR_PAT_SHIFT)
#define PT_DIR_PAT_SHIFT 12
#define PT_GLOBAL_MASK (1ULL << 8)
#define PT_PAGE_SIZE_MASK (1ULL << 7)
#define PT_PAGE_TABLE_LEVEL 1
#define PT_PAT_MASK (1ULL << 7)
#define PT_PAT_SHIFT 7
#define PT_PCD_MASK (1ULL << 4)
#define PT_PDPE_LEVEL 3
#define PT_PRESENT_MASK (1ULL << 0)
#define PT_PWT_MASK (1ULL << 3)
#define PT_USER_MASK (1ULL << 2)
#define PT_WRITABLE_MASK (1ULL << PT_WRITABLE_SHIFT)
#define PT_WRITABLE_SHIFT 1

#define PIC_NUM_PINS 16
#define SELECT_PIC(irq) \
	((irq) < 8 ? KVM_IRQCHIP_PIC_MASTER : KVM_IRQCHIP_PIC_SLAVE)


