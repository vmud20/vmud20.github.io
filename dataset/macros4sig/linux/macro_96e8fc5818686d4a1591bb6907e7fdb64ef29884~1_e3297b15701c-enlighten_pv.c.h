
#include<linux/kernel.h>





#include<asm/errno.h>
#include<unistd.h>



#include<linux/dqblk_xfs.h>









#include<asm/bpf_perf_event.h>



#include<linux/param.h>









#include<asm/types.h>
#include<asm/ptrace.h>
#include<asm/siginfo.h>








#include<asm/bitsperlong.h>


#include<linux/pci_regs.h>








#include<asm/ldt.h>

#include<linux/wait.h>


#include<stdio.h>




#include<linux/module.h>


#include<asm/ptrace-abi.h>














#include<linux/elf-em.h>



#include<linux/mount.h>








#include<fcntl.h>



#include<linux/posix_types.h>
#include<linux/seccomp.h>









#include<linux/sem.h>






#include<asm/stat.h>



#include<linux/errno.h>
#include<linux/string.h>


















#include<linux/sysctl.h>
#include<asm/signal.h>







#include<linux/const.h>

#include<linux/stddef.h>


#include<asm-generic/hugetlb_encode.h>







#include<linux/signal.h>



#include<stdlib.h>



#include<linux/magic.h>





#include<linux/unistd.h>


#include<linux/fs.h>






#include<linux/sched.h>



#include<ctype.h>


#include<linux/resource.h>



#include<asm/param.h>









#include<linux/rseq.h>
#include<linux/limits.h>

#include<asm/fcntl.h>







#include<asm/sembuf.h>

#include<linux/fcntl.h>

#include<asm/hw_breakpoint.h>




#include<linux/personality.h>













#include<asm/auxvec.h>










#include<linux/irqnr.h>
#include<linux/time_types.h>




#include<asm/poll.h>
#include<asm/bootparam.h>







#include<linux/cgroupstats.h>













#include<linux/ioctl.h>












#include<linux/stat.h>








#include<linux/capability.h>





#include<string.h>



#include<stdarg.h>
#include<asm/msr.h>
#include<linux/aio_abi.h>


#include<linux/ptrace.h>
#include<time.h>

#include<errno.h>












#include<linux/quota.h>
#include<linux/sysinfo.h>
#include<asm/shmbuf.h>
#include<linux/timex.h>





#include<asm/processor-flags.h>


#include<signal.h>



#include<linux/types.h>







#include<asm/byteorder.h>


#include<linux/time.h>





#include<linux/random.h>


#include<asm/resource.h>










#include<linux/uuid.h>






#include<asm/perf_regs.h>



#include<asm/ipcbuf.h>
#include<linux/ipc.h>




#define cpu_dev_register(cpu_devX) \
	static const struct cpu_dev *const __cpu_dev_##cpu_devX __used \
	__section(".x86_cpu_dev.init") = \
	&cpu_devX;

#define XENPMU_FEATURE_INTEL_BTS  1
#define XENPMU_MODE_ALL           (1<<2)
#define XENPMU_MODE_HV            (1<<1)
#define XENPMU_MODE_OFF           0
#define XENPMU_MODE_SELF          (1<<0)
#define XENPMU_VER_MAJ    0
#define XENPMU_VER_MIN    1
#define XENPMU_feature_get     2
#define XENPMU_feature_set     3
#define XENPMU_finish          5
#define XENPMU_flush           7
#define XENPMU_init            4
#define XENPMU_lvtpc_set       6
#define XENPMU_mode_get        0 
#define XENPMU_mode_set        1



#define IRQ_RETVAL(x)	((x) ? IRQ_HANDLED : IRQ_NONE)

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
		__used __section("__" #table "_of_table")		\
		__aligned(__alignof__(struct of_device_id))		\
		 = { .compatible = compat,				\
		     .data = (fn == (fn_type)NULL) ? fn : fn  }
#define _OF_DECLARE_STUB(table, name, compat, fn, fn_type)		\
	static const struct of_device_id __of_table_##name		\
		__attribute__((unused))					\
		 = { .compatible = compat,				\
		     .data = (fn == (fn_type)NULL) ? fn : fn }
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
#define list_entry_is_head(pos, head, member)				\
	(&pos->member == (head))
#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)
#define list_first_entry_or_null(ptr, type, member) ({ \
	struct list_head *head__ = (ptr); \
	struct list_head *pos__ = READ_ONCE(head__->next); \
	pos__ != head__ ? list_entry(pos__, type, member) : NULL; \
})
#define list_for_each(pos, head) \
	for (pos = (head)->next; !list_is_head(pos, (head)); pos = pos->next)
#define list_for_each_continue(pos, head) \
	for (pos = pos->next; !list_is_head(pos, (head)); pos = pos->next)
#define list_for_each_entry(pos, head, member)				\
	for (pos = list_first_entry(head, typeof(*pos), member);	\
	     !list_entry_is_head(pos, head, member);			\
	     pos = list_next_entry(pos, member))
#define list_for_each_entry_continue(pos, head, member) 		\
	for (pos = list_next_entry(pos, member);			\
	     !list_entry_is_head(pos, head, member);			\
	     pos = list_next_entry(pos, member))
#define list_for_each_entry_continue_reverse(pos, head, member)		\
	for (pos = list_prev_entry(pos, member);			\
	     !list_entry_is_head(pos, head, member);			\
	     pos = list_prev_entry(pos, member))
#define list_for_each_entry_from(pos, head, member) 			\
	for (; !list_entry_is_head(pos, head, member);			\
	     pos = list_next_entry(pos, member))
#define list_for_each_entry_from_reverse(pos, head, member)		\
	for (; !list_entry_is_head(pos, head, member);			\
	     pos = list_prev_entry(pos, member))
#define list_for_each_entry_reverse(pos, head, member)			\
	for (pos = list_last_entry(head, typeof(*pos), member);		\
	     !list_entry_is_head(pos, head, member); 			\
	     pos = list_prev_entry(pos, member))
#define list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = list_first_entry(head, typeof(*pos), member),	\
		n = list_next_entry(pos, member);			\
	     !list_entry_is_head(pos, head, member); 			\
	     pos = n, n = list_next_entry(n, member))
#define list_for_each_entry_safe_continue(pos, n, head, member) 		\
	for (pos = list_next_entry(pos, member), 				\
		n = list_next_entry(pos, member);				\
	     !list_entry_is_head(pos, head, member);				\
	     pos = n, n = list_next_entry(n, member))
#define list_for_each_entry_safe_from(pos, n, head, member) 			\
	for (n = list_next_entry(pos, member);					\
	     !list_entry_is_head(pos, head, member);				\
	     pos = n, n = list_next_entry(n, member))
#define list_for_each_entry_safe_reverse(pos, n, head, member)		\
	for (pos = list_last_entry(head, typeof(*pos), member),		\
		n = list_prev_entry(pos, member);			\
	     !list_entry_is_head(pos, head, member); 			\
	     pos = n, n = list_prev_entry(n, member))
#define list_for_each_prev(pos, head) \
	for (pos = (head)->prev; !list_is_head(pos, (head)); pos = pos->prev)
#define list_for_each_prev_safe(pos, n, head) \
	for (pos = (head)->prev, n = pos->prev; \
	     !list_is_head(pos, (head)); \
	     pos = n, n = pos->prev)
#define list_for_each_rcu(pos, head)		  \
	for (pos = rcu_dereference((head)->next); \
	     !list_is_head(pos, (head)); \
	     pos = rcu_dereference(pos->next))
#define list_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; \
	     !list_is_head(pos, (head)); \
	     pos = n, n = pos->next)
#define list_last_entry(ptr, type, member) \
	list_entry((ptr)->prev, type, member)
#define list_next_entry(pos, member) \
	list_entry((pos)->member.next, typeof(*(pos)), member)
#define list_next_entry_circular(pos, head, member) \
	(list_is_last(&(pos)->member, head) ? \
	list_first_entry(head, typeof(*(pos)), member) : list_next_entry(pos, member))
#define list_prepare_entry(pos, head, member) \
	((pos) ? : list_entry(head, typeof(*pos), member))
#define list_prev_entry(pos, member) \
	list_entry((pos)->member.prev, typeof(*(pos)), member)
#define list_prev_entry_circular(pos, head, member) \
	(list_is_first(&(pos)->member, head) ? \
	list_last_entry(head, typeof(*(pos)), member) : list_prev_entry(pos, member))
#define list_safe_reset_next(pos, n, member)				\
	n = list_next_entry(pos, member)

#define __is_constexpr(x) \
	(sizeof(int) == sizeof(*(8 ? ((void *)((long)(x) * 0l)) : (int *)8)))
#define UL(x)		(_UL(x))
#define ULL(x)		(_ULL(x))

#define _AT(T,X)	((T)(X))
#define _BITUL(x)	(_UL(1) << (x))
#define _BITULL(x)	(_ULL(1) << (x))

#define _UL(x)		(_AC(x, UL))
#define _ULL(x)		(_AC(x, ULL))
#define __AC(X,Y)	(X##Y)
#define __ALIGN_KERNEL(x, a)		__ALIGN_KERNEL_MASK(x, (typeof(x))(a) - 1)
#define __ALIGN_KERNEL_MASK(x, mask)	(((x) + (mask)) & ~(mask))
#define __KERNEL_DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define LIST_POISON1  ((void *) 0x100 + POISON_POINTER_DELTA)
#define LIST_POISON2  ((void *) 0x122 + POISON_POINTER_DELTA)
#define PAGE_POISON 0xaa
# define POISON_POINTER_DELTA _AC(CONFIG_ILLEGAL_POINTER_VALUE, UL)

#define DECLARE_FLEX_ARRAY(TYPE, NAME) \
	__DECLARE_FLEX_ARRAY(TYPE, NAME)
#define NULL ((void *)0)

#define offsetofend(TYPE, MEMBER) \
	(offsetof(TYPE, MEMBER)	+ sizeof_field(TYPE, MEMBER))
#define sizeof_field(TYPE, MEMBER) sizeof((((TYPE *)0)->MEMBER))
#define struct_group(NAME, MEMBERS...)	\
	__struct_group(, NAME, , MEMBERS)
#define struct_group_attr(NAME, ATTRS, MEMBERS...) \
	__struct_group(, NAME, ATTRS, MEMBERS)
#define struct_group_tagged(TAG, NAME, MEMBERS...) \
	__struct_group(TAG, NAME, , MEMBERS)

#define __DECLARE_FLEX_ARRAY(TYPE, NAME)	\
	struct { \
		struct { } __empty_ ## NAME; \
		TYPE NAME[]; \
	}
#define __always_inline inline
#define __struct_group(TAG, NAME, ATTRS, MEMBERS...) \
	union { \
		struct { MEMBERS } ATTRS; \
		struct TAG { MEMBERS } ATTRS NAME; \
	}
# define ACCESS_PRIVATE(p, member) (*((typeof((p)->member) __force *) &(p)->member))

#define __PASTE(a,b) ___PASTE(a,b)
#define ___PASTE(a,b) a##b
# define __acquire(x)	__context__(x,1)
# define __acquires(x)	__attribute__((context(x,0,1)))
# define __alloc_size(x, ...)	__malloc
# define __builtin_warning(x, y...) (1)
# define __cficanonical
# define __chk_io_ptr(x)	(void)0
# define __chk_user_ptr(x)	(void)0
# define __compiletime_assert(condition, msg, prefix, suffix)		\
	do {								\
									\
		__noreturn extern void prefix ## suffix(void)		\
			__compiletime_error(msg);			\
		if (!(condition))					\
			prefix ## suffix();				\
	} while (0)
# define __cond_lock(x,c)	((c) ? ({ __acquire(x); 1; }) : 0)

#define __diag_GCC(version, severity, string)
#define __diag_error(compiler, version, option, comment) \
	__diag_ ## compiler(version, error, option)
#define __diag_ignore(compiler, version, option, comment) \
	__diag_ ## compiler(version, ignore, option)
#define __diag_ignore_all(option, comment)
#define __diag_pop()	__diag(pop)
#define __diag_push()	__diag(push)
#define __diag_warn(compiler, version, option, comment) \
	__diag_ ## compiler(version, warn, option)
# define __force
#define __has_builtin(x) (0)
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
# define __no_kasan_or_inline __no_sanitize_address notrace __maybe_unused
# define __no_kcsan __no_sanitize_thread __disable_sanitizer_instrumentation
# define __no_randomize_layout __attribute__((no_randomize_layout))
# define __no_sanitize_or_inline __no_kasan_or_inline
# define __nocast
# define __nocfi
# define __noscs
# define __private
# define __randomize_layout __designated_init __attribute__((randomize_layout))
# define __rcu		__attribute__((noderef, address_space(__rcu)))
# define __release(x)	__context__(x,-1)
# define __releases(x)	__attribute__((context(x,1,0)))
# define __safe
#define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#define __scalar_type_to_expr_cases(type)				\
		unsigned type:	(unsigned type)0,			\
		signed type:	(signed type)0
#define __unqual_scalar_typeof(x) typeof(				\
		_Generic((x),						\
			 char:	(char)0,				\
			 __scalar_type_to_expr_cases(char),		\
			 __scalar_type_to_expr_cases(short),		\
			 __scalar_type_to_expr_cases(int),		\
			 __scalar_type_to_expr_cases(long),		\
			 __scalar_type_to_expr_cases(long long),	\
			 default: (x)))
# define __user		__attribute__((noderef, address_space(__user)))
#define _compiletime_assert(condition, msg, prefix, suffix) \
	__compiletime_assert(condition, msg, prefix, suffix)
#define asm_inline asm __inline
#define asm_volatile_goto(x...) asm goto(x)
#define compiletime_assert(condition, msg) \
	_compiletime_assert(condition, msg, __compiletime_assert_, __COUNTER__)
#define compiletime_assert_atomic_type(t)				\
	compiletime_assert(__native_word(t),				\
		"Need native word sized stores/loads for atomicity.")
#define inline inline __gnu_inline __inline_maybe_unused notrace
#define noinline_for_stack noinline
# define randomized_struct_fields_end
# define randomized_struct_fields_start
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
#define __diag_GCC_8(s)		__diag(s)
#define __diag_str(s)		__diag_str1(s)
#define __diag_str1(s)		#s
#define __no_sanitize_address __attribute__((no_sanitize_address))
#define __no_sanitize_coverage __attribute__((no_sanitize_coverage))
#define __no_sanitize_thread __attribute__((no_sanitize_thread))
#define __no_sanitize_undefined __attribute__((no_sanitize_undefined))
#define __noretpoline __attribute__((__indirect_branch__("keep")))
#define barrier_before_unreachable() asm volatile("")
#define unreachable() \
	do {					\
		annotate_unreachable();		\
		barrier_before_unreachable();	\
		__builtin_unreachable();	\
	} while (0)
#define OPTIMIZER_HIDE_VAR(var) barrier()
#define __builtin_bswap16 _bswap16
#define barrier() __memory_barrier()
#define barrier_data(ptr) barrier()

#define __diag_clang(version, severity, s) \
	__diag_clang_ ## version(__diag_clang_ ## severity s)

#define function_nocfi(x)	__builtin_function_start(x)

#define __alias(symbol)                 __attribute__((__alias__(#symbol)))
#define __aligned(x)                    __attribute__((__aligned__(x)))
#define __aligned_largest               __attribute__((__aligned__))
#define __alloc_size__(x, ...)		__attribute__((__alloc_size__(x, ## __VA_ARGS__)))
#define __always_unused                 __attribute__((__unused__))
# define __assume_aligned(a, ...)
#define __attribute_const__             __attribute__((__const__))
#define __cold                          __attribute__((__cold__))
# define __compiletime_error(msg)       __attribute__((__error__(msg)))
# define __compiletime_warning(msg)     __attribute__((__warning__(msg)))
# define __copy(symbol)

# define __designated_init              __attribute__((__designated_init__))
# define __diagnose_as(builtin...)
# define __disable_sanitizer_instrumentation \
	 __attribute__((disable_sanitizer_instrumentation))
#define __gnu_inline                    __attribute__((__gnu_inline__))
#define __malloc                        __attribute__((__malloc__))
#define __maybe_unused                  __attribute__((__unused__))
#define __mode(x)                       __attribute__((__mode__(x)))
#define __must_check                    __attribute__((__warn_unused_result__))
# define __no_caller_saved_registers
# define __no_profile                  __attribute__((__no_profile_instrument_function__))
# define __noclone                      __attribute__((__noclone__))
# define __nonstring                    __attribute__((__nonstring__))
#define __noreturn                      __attribute__((__noreturn__))
# define __overloadable			__attribute__((__overloadable__))
#define __packed                        __attribute__((__packed__))
# define __pass_object_size(type)
#define __printf(a, b)                  __attribute__((__format__(printf, a, b)))
#define __pure                          __attribute__((__pure__))
#define __scanf(a, b)                   __attribute__((__format__(scanf, a, b)))
#define __section(section)              __attribute__((__section__(section)))
#define __used                          __attribute__((__used__))
# define __visible                      __attribute__((__externally_visible__))
#define __weak                          __attribute__((__weak__))
# define fallthrough                    __attribute__((__fallthrough__))
#define   noinline                      __attribute__((__noinline__))
#define ATOMIC_INIT(i) { (i) }
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

#define __bitwise__ __bitwise

#define container_of(ptr, type, member) ({				\
	void *__mptr = (void *)(ptr);					\
	static_assert(__same_type(*(ptr), ((type *)0)->member) ||	\
		      __same_type(*(ptr), void),			\
		      "pointer type mismatch in container_of()");	\
	((type *)(__mptr - offsetof(type, member))); })
#define container_of_safe(ptr, type, member) ({				\
	void *__mptr = (void *)(ptr);					\
	static_assert(__same_type(*(ptr), ((type *)0)->member) ||	\
		      __same_type(*(ptr), void),			\
		      "pointer type mismatch in container_of_safe()");	\
	IS_ERR_OR_NULL(__mptr) ? ERR_CAST(__mptr) :			\
		((type *)(__mptr - offsetof(type, member))); })
#define typeof_member(T, m)	typeof(((T*)0)->m)
#define IS_ERR_VALUE(x) unlikely((unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO)

# define KENTRY(sym)						\
	extern typeof(sym) sym;					\
	static const unsigned long __kentry_##sym		\
	__used							\
	__attribute__((__section__("___kentry+" #sym)))		\
	= (unsigned long)&sym;
#define OPTIMIZER_HIDE_VAR(var)						\
	__asm__ ("" : "=r" (var) : "0" (var))
# define RELOC_HIDE(ptr, off)					\
  ({ unsigned long __ptr;					\
     __ptr = (unsigned long) (ptr);				\
    (typeof(ptr)) (__ptr + (off)); })
#define __ADDRESSABLE(sym) \
	static void * __section(".discard.addressable") __used \
		__UNIQUE_ID(__PASTE(__addressable_,sym)) = (void *)&sym;

# define __UNIQUE_ID(prefix) __PASTE(__PASTE(__UNIQUE_ID_, prefix), "__LINE__")
#define __annotate_jump_table __section(".rodata..c_jump_table")
#define __annotate_unreachable(c) ({					\
	asm volatile(__stringify_label(c) ":\n\t"			\
		     ".pushsection .discard.unreachable\n\t"		\
		     ".long " __stringify_label(c) "b - .\n\t"		\
		     ".popsection\n\t" : : "i" (c));			\
})
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
#define __must_be_array(a)	BUILD_BUG_ON_ZERO(__same_type((a), &(a)[0]))
#define __stringify_label(n) #n
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
#define absolute_pointer(val)	RELOC_HIDE((void *)(val), 0)
#define annotate_unreachable() __annotate_unreachable(__COUNTER__)
# define barrier() __asm__ __volatile__("": : :"memory")
# define barrier_before_unreachable() do { } while (0)
# define barrier_data(ptr) __asm__ __volatile__("": :"r"(ptr) :"memory")
#define data_race(expr)							\
({									\
	__unqual_scalar_typeof(({ expr; })) __v = ({			\
		__kcsan_disable_current();				\
		expr;							\
	});								\
	__kcsan_enable_current();					\
	__v;								\
})
#define function_nocfi(x) (x)
#define if(cond, ...) if ( __trace_if_var( !!(cond , ## __VA_ARGS__) ) )
#  define likely(x)	(__branch_check__(x, 1, __builtin_constant_p(x)))
# define likely_notrace(x)	likely(x)
#define prevent_tail_call_optimization()	mb()
#  define unlikely(x)	(__branch_check__(x, 0, __builtin_constant_p(x)))
# define unlikely_notrace(x)	unlikely(x)
# define unreachable() do {		\
	annotate_unreachable();		\
	__builtin_unreachable();	\
} while (0)
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
	{ .pointer = &SOFTWARE_NODE_REFERENCE(_ref_, ##__VA_ARGS__), },	\
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
#define SOFTWARE_NODE_REFERENCE(_ref_, ...)			\
(const struct software_node_ref_args) {				\
	.node = _ref_,						\
	.nargs = ARRAY_SIZE(((u64[]){ 0, ##__VA_ARGS__ })) - 1,	\
	.args = { __VA_ARGS__ },				\
}

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
#define fwnode_for_each_parent_node(fwnode, parent)		\
	for (parent = fwnode_get_parent(fwnode); parent;	\
	     parent = fwnode_get_next_parent(parent))
#define fwnode_graph_for_each_endpoint(fwnode, child)			\
	for (child = NULL;						\
	     (child = fwnode_graph_get_next_endpoint(fwnode, child)); )

#define fwnode_call_bool_op(fwnode, op, ...)		\
	(fwnode_has_op(fwnode, op) ?			\
	 (fwnode)->ops->op(fwnode, ## __VA_ARGS__) : false)
#define fwnode_call_int_op(fwnode, op, ...)				\
	(fwnode_has_op(fwnode, op) ?					\
	 (fwnode)->ops->op(fwnode, ## __VA_ARGS__) : (IS_ERR_OR_NULL(fwnode) ? -EINVAL : -ENXIO))
#define fwnode_call_ptr_op(fwnode, op, ...)		\
	(fwnode_has_op(fwnode, op) ?			\
	 (fwnode)->ops->op(fwnode, ## __VA_ARGS__) : NULL)
#define fwnode_call_void_op(fwnode, op, ...)				\
	do {								\
		if (fwnode_has_op(fwnode, op))				\
			(fwnode)->ops->op(fwnode, ## __VA_ARGS__);	\
	} while (false)
#define fwnode_has_op(fwnode, op)					\
	(!IS_ERR_OR_NULL(fwnode) && (fwnode)->ops && (fwnode)->ops->op)
#define get_dev_from_fwnode(fwnode)	get_device((fwnode)->dev)
#define BIT_MASK(nr)		(UL(1) << ((nr) % BITS_PER_LONG))
#define BIT_ULL(nr)		(ULL(1) << (nr))
#define BIT_ULL_MASK(nr)	(ULL(1) << ((nr) % BITS_PER_LONG_LONG))
#define BIT_ULL_WORD(nr)	((nr) / BITS_PER_LONG_LONG)
#define BIT_WORD(nr)		((nr) / BITS_PER_LONG)
#define GENMASK(h, l) \
	(GENMASK_INPUT_CHECK(h, l) + __GENMASK(h, l))
#define GENMASK_INPUT_CHECK(h, l) \
	(BUILD_BUG_ON_ZERO(__builtin_choose_expr( \
		__is_constexpr((l) > (h)), (l) > (h), 0)))
#define GENMASK_ULL(h, l) \
	(GENMASK_INPUT_CHECK(h, l) + __GENMASK_ULL(h, l))
#define __GENMASK(h, l) \
	(((~UL(0)) - (UL(1) << (l)) + 1) & \
	 (~UL(0) >> (BITS_PER_LONG - 1 - (h))))
#define __GENMASK_ULL(h, l) \
	(((~ULL(0)) - (ULL(1) << (l)) + 1) & \
	 (~ULL(0) >> (BITS_PER_LONG_LONG - 1 - (h))))

#define BIT(nr)			(UL(1) << (nr))

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
	__rcu_dereference_check((p), __UNIQUE_ID(rcu), \
				(c) || srcu_read_lock_held(ssp), __rcu)
#define srcu_dereference_notrace(p, ssp) srcu_dereference_check((p), (ssp), 1)
#define DEFINE_SRCU(name)		__DEFINE_SRCU(name, )
#define DEFINE_STATIC_SRCU(name)	__DEFINE_SRCU(name, static)

# define __DEFINE_SRCU(name, is_static)					\
	is_static struct srcu_struct name;				\
	extern struct srcu_struct * const __srcu_struct_##name;		\
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

#define init_completion_map(x, m) init_completion(x)
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
	.head		= LIST_HEAD_INIT(name.head) }
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

#define __lockfunc __section(".spinlock.text")
#define alloc_bucket_spinlocks(locks, lock_mask, max_size, cpu_mult, gfp)    \
	({								     \
		static struct lock_class_key key;			     \
		int ret;						     \
									     \
		ret = __alloc_bucket_spinlocks(locks, lock_mask, max_size,   \
					       cpu_mult, gfp, #locks, &key); \
		ret;							     \
	})
#define assert_spin_locked(lock)	assert_raw_spin_locked(&(lock)->rlock)
#define atomic_dec_and_lock(atomic, lock) \
		__cond_lock(lock, _atomic_dec_and_lock(atomic, lock))
#define atomic_dec_and_lock_irqsave(atomic, lock, flags) \
		__cond_lock(lock, _atomic_dec_and_lock_irqsave(atomic, lock, &(flags)))
#define raw_spin_is_contended(lock)	arch_spin_is_contended(&(lock)->raw_lock)
#define raw_spin_is_locked(lock)	arch_spin_is_locked(&(lock)->raw_lock)
#define raw_spin_lock_bh(lock)		_raw_spin_lock_bh(lock)
# define raw_spin_lock_init(lock)					\
do {									\
	static struct lock_class_key __key;				\
									\
	__raw_spin_lock_init((lock), #lock, &__key, LD_WAIT_SPIN);	\
} while (0)
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
#define smp_mb__after_spinlock()	kcsan_mb()
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

#define cmpxchg(ptr, ...) \
({ \
	typeof(ptr) __ai_ptr = (ptr); \
	kcsan_mb(); \
	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
	arch_cmpxchg(__ai_ptr, __VA_ARGS__); \
})
#define cmpxchg64(ptr, ...) \
({ \
	typeof(ptr) __ai_ptr = (ptr); \
	kcsan_mb(); \
	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
	arch_cmpxchg64(__ai_ptr, __VA_ARGS__); \
})
#define cmpxchg64_acquire(ptr, ...) \
({ \
	typeof(ptr) __ai_ptr = (ptr); \
	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
	arch_cmpxchg64_acquire(__ai_ptr, __VA_ARGS__); \
})
#define cmpxchg64_local(ptr, ...) \
({ \
	typeof(ptr) __ai_ptr = (ptr); \
	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
	arch_cmpxchg64_local(__ai_ptr, __VA_ARGS__); \
})
#define cmpxchg64_relaxed(ptr, ...) \
({ \
	typeof(ptr) __ai_ptr = (ptr); \
	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
	arch_cmpxchg64_relaxed(__ai_ptr, __VA_ARGS__); \
})
#define cmpxchg64_release(ptr, ...) \
({ \
	typeof(ptr) __ai_ptr = (ptr); \
	kcsan_release(); \
	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
	arch_cmpxchg64_release(__ai_ptr, __VA_ARGS__); \
})
#define cmpxchg_acquire(ptr, ...) \
({ \
	typeof(ptr) __ai_ptr = (ptr); \
	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
	arch_cmpxchg_acquire(__ai_ptr, __VA_ARGS__); \
})
#define cmpxchg_double(ptr, ...) \
({ \
	typeof(ptr) __ai_ptr = (ptr); \
	kcsan_mb(); \
	instrument_atomic_write(__ai_ptr, 2 * sizeof(*__ai_ptr)); \
	arch_cmpxchg_double(__ai_ptr, __VA_ARGS__); \
})
#define cmpxchg_double_local(ptr, ...) \
({ \
	typeof(ptr) __ai_ptr = (ptr); \
	instrument_atomic_write(__ai_ptr, 2 * sizeof(*__ai_ptr)); \
	arch_cmpxchg_double_local(__ai_ptr, __VA_ARGS__); \
})
#define cmpxchg_local(ptr, ...) \
({ \
	typeof(ptr) __ai_ptr = (ptr); \
	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
	arch_cmpxchg_local(__ai_ptr, __VA_ARGS__); \
})
#define cmpxchg_relaxed(ptr, ...) \
({ \
	typeof(ptr) __ai_ptr = (ptr); \
	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
	arch_cmpxchg_relaxed(__ai_ptr, __VA_ARGS__); \
})
#define cmpxchg_release(ptr, ...) \
({ \
	typeof(ptr) __ai_ptr = (ptr); \
	kcsan_release(); \
	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
	arch_cmpxchg_release(__ai_ptr, __VA_ARGS__); \
})
#define sync_cmpxchg(ptr, ...) \
({ \
	typeof(ptr) __ai_ptr = (ptr); \
	kcsan_mb(); \
	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
	arch_sync_cmpxchg(__ai_ptr, __VA_ARGS__); \
})
#define try_cmpxchg(ptr, oldp, ...) \
({ \
	typeof(ptr) __ai_ptr = (ptr); \
	typeof(oldp) __ai_oldp = (oldp); \
	kcsan_mb(); \
	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
	instrument_atomic_write(__ai_oldp, sizeof(*__ai_oldp)); \
	arch_try_cmpxchg(__ai_ptr, __ai_oldp, __VA_ARGS__); \
})
#define try_cmpxchg64(ptr, oldp, ...) \
({ \
	typeof(ptr) __ai_ptr = (ptr); \
	typeof(oldp) __ai_oldp = (oldp); \
	kcsan_mb(); \
	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
	instrument_atomic_write(__ai_oldp, sizeof(*__ai_oldp)); \
	arch_try_cmpxchg64(__ai_ptr, __ai_oldp, __VA_ARGS__); \
})
#define try_cmpxchg64_acquire(ptr, oldp, ...) \
({ \
	typeof(ptr) __ai_ptr = (ptr); \
	typeof(oldp) __ai_oldp = (oldp); \
	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
	instrument_atomic_write(__ai_oldp, sizeof(*__ai_oldp)); \
	arch_try_cmpxchg64_acquire(__ai_ptr, __ai_oldp, __VA_ARGS__); \
})
#define try_cmpxchg64_relaxed(ptr, oldp, ...) \
({ \
	typeof(ptr) __ai_ptr = (ptr); \
	typeof(oldp) __ai_oldp = (oldp); \
	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
	instrument_atomic_write(__ai_oldp, sizeof(*__ai_oldp)); \
	arch_try_cmpxchg64_relaxed(__ai_ptr, __ai_oldp, __VA_ARGS__); \
})
#define try_cmpxchg64_release(ptr, oldp, ...) \
({ \
	typeof(ptr) __ai_ptr = (ptr); \
	typeof(oldp) __ai_oldp = (oldp); \
	kcsan_release(); \
	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
	instrument_atomic_write(__ai_oldp, sizeof(*__ai_oldp)); \
	arch_try_cmpxchg64_release(__ai_ptr, __ai_oldp, __VA_ARGS__); \
})
#define try_cmpxchg_acquire(ptr, oldp, ...) \
({ \
	typeof(ptr) __ai_ptr = (ptr); \
	typeof(oldp) __ai_oldp = (oldp); \
	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
	instrument_atomic_write(__ai_oldp, sizeof(*__ai_oldp)); \
	arch_try_cmpxchg_acquire(__ai_ptr, __ai_oldp, __VA_ARGS__); \
})
#define try_cmpxchg_relaxed(ptr, oldp, ...) \
({ \
	typeof(ptr) __ai_ptr = (ptr); \
	typeof(oldp) __ai_oldp = (oldp); \
	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
	instrument_atomic_write(__ai_oldp, sizeof(*__ai_oldp)); \
	arch_try_cmpxchg_relaxed(__ai_ptr, __ai_oldp, __VA_ARGS__); \
})
#define try_cmpxchg_release(ptr, oldp, ...) \
({ \
	typeof(ptr) __ai_ptr = (ptr); \
	typeof(oldp) __ai_oldp = (oldp); \
	kcsan_release(); \
	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
	instrument_atomic_write(__ai_oldp, sizeof(*__ai_oldp)); \
	arch_try_cmpxchg_release(__ai_ptr, __ai_oldp, __VA_ARGS__); \
})
#define xchg(ptr, ...) \
({ \
	typeof(ptr) __ai_ptr = (ptr); \
	kcsan_mb(); \
	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
	arch_xchg(__ai_ptr, __VA_ARGS__); \
})
#define xchg_acquire(ptr, ...) \
({ \
	typeof(ptr) __ai_ptr = (ptr); \
	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
	arch_xchg_acquire(__ai_ptr, __VA_ARGS__); \
})
#define xchg_relaxed(ptr, ...) \
({ \
	typeof(ptr) __ai_ptr = (ptr); \
	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
	arch_xchg_relaxed(__ai_ptr, __VA_ARGS__); \
})
#define xchg_release(ptr, ...) \
({ \
	typeof(ptr) __ai_ptr = (ptr); \
	kcsan_release(); \
	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
	arch_xchg_release(__ai_ptr, __VA_ARGS__); \
})

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

#define __ASSERT_EXCLUSIVE_SCOPED(var, type, id)                               \
	struct kcsan_scoped_access __kcsan_scoped_name(id, _)                  \
		__kcsan_cleanup_scoped;                                        \
	struct kcsan_scoped_access *__kcsan_scoped_name(id, _dummy_p)          \
		__maybe_unused = kcsan_begin_scoped_access(                    \
			&(var), sizeof(var), KCSAN_ACCESS_SCOPED | (type),     \
			&__kcsan_scoped_name(id, _))
#define __KCSAN_BARRIER_TO_SIGNAL_FENCE(name)					\
	do {									\
		barrier();							\
		__atomic_signal_fence(__KCSAN_BARRIER_TO_SIGNAL_FENCE_##name);	\
		barrier();							\
	} while (0)
#define __kcsan_check_read(ptr, size) __kcsan_check_access(ptr, size, 0)
#define __kcsan_check_read_write(ptr, size)                                    \
	__kcsan_check_access(ptr, size, KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE)
#define __kcsan_check_write(ptr, size)                                         \
	__kcsan_check_access(ptr, size, KCSAN_ACCESS_WRITE)
#define __kcsan_cleanup_scoped                                                 \
	__maybe_unused __attribute__((__cleanup__(kcsan_end_scoped_access)))
#define __kcsan_disable_current kcsan_disable_current
#define __kcsan_enable_current kcsan_enable_current_nowarn
#define __kcsan_scoped_name(c, suffix) __kcsan_scoped_##c##suffix
#define kcsan_check_access __kcsan_check_access
#define kcsan_check_atomic_read(...)		do { } while (0)
#define kcsan_check_atomic_read_write(...)	do { } while (0)
#define kcsan_check_atomic_write(...)		do { } while (0)
#define kcsan_check_read(ptr, size) kcsan_check_access(ptr, size, 0)
#define kcsan_check_read_write(ptr, size)                                      \
	kcsan_check_access(ptr, size, KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE)
#define kcsan_check_write(ptr, size)                                           \
	kcsan_check_access(ptr, size, KCSAN_ACCESS_WRITE)
#define kcsan_mb()	__KCSAN_BARRIER_TO_SIGNAL_FENCE(mb)
#define kcsan_release()	__KCSAN_BARRIER_TO_SIGNAL_FENCE(release)
#define kcsan_rmb()	__KCSAN_BARRIER_TO_SIGNAL_FENCE(rmb)
#define kcsan_wmb()	__KCSAN_BARRIER_TO_SIGNAL_FENCE(wmb)

#define kasan_check_read __kasan_check_read
#define kasan_check_write __kasan_check_write
#define ATOMIC_LONG_INIT(i)		ATOMIC64_INIT(i)


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
#define arch_cmpxchg64_acquire arch_cmpxchg64
#define arch_cmpxchg64_relaxed arch_cmpxchg64
#define arch_cmpxchg64_release arch_cmpxchg64
#define arch_cmpxchg_acquire arch_cmpxchg
#define arch_cmpxchg_relaxed arch_cmpxchg
#define arch_cmpxchg_release arch_cmpxchg
#define arch_try_cmpxchg(...) \
	__atomic_op_fence(arch_try_cmpxchg, __VA_ARGS__)
#define arch_try_cmpxchg64(_ptr, _oldp, _new) \
({ \
	typeof(*(_ptr)) *___op = (_oldp), ___o = *___op, ___r; \
	___r = arch_cmpxchg64((_ptr), ___o, (_new)); \
	if (unlikely(___r != ___o)) \
		*___op = ___r; \
	likely(___r == ___o); \
})
#define arch_try_cmpxchg64_acquire arch_try_cmpxchg64
#define arch_try_cmpxchg64_relaxed arch_try_cmpxchg64
#define arch_try_cmpxchg64_release arch_try_cmpxchg64
#define arch_try_cmpxchg_acquire arch_try_cmpxchg
#define arch_try_cmpxchg_relaxed arch_try_cmpxchg
#define arch_try_cmpxchg_release arch_try_cmpxchg
#define arch_xchg(...) \
	__atomic_op_fence(arch_xchg, __VA_ARGS__)
#define arch_xchg_acquire arch_xchg
#define arch_xchg_relaxed arch_xchg
#define arch_xchg_release arch_xchg
#define ATOMIC64_FETCH_OP(op)						\
extern s64 generic_atomic64_fetch_##op(s64 a, atomic64_t *v);
#define ATOMIC64_INIT(i)	{ (i) }
#define ATOMIC64_OP(op)							\
extern void generic_atomic64_##op(s64 a, atomic64_t *v);
#define ATOMIC64_OPS(op)	ATOMIC64_OP(op) ATOMIC64_OP_RETURN(op) ATOMIC64_FETCH_OP(op)
#define ATOMIC64_OP_RETURN(op)						\
extern s64 generic_atomic64_##op##_return(s64 a, atomic64_t *v);


# define do_raw_read_lock(rwlock)	do {__acquire(lock); arch_read_lock(&(rwlock)->raw_lock); } while (0)
# define do_raw_read_trylock(rwlock)	arch_read_trylock(&(rwlock)->raw_lock)
# define do_raw_read_unlock(rwlock)	do {arch_read_unlock(&(rwlock)->raw_lock); __release(lock); } while (0)
# define do_raw_write_lock(rwlock)	do {__acquire(lock); arch_write_lock(&(rwlock)->raw_lock); } while (0)
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
#define rwlock_is_contended(lock) \
	 arch_rwlock_is_contended(&(lock)->raw_lock)
#define write_lock_bh(lock)		_raw_write_lock_bh(lock)
#define write_lock_irq(lock)		_raw_write_lock_irq(lock)
#define write_lock_irqsave(lock, flags)			\
	do {						\
		typecheck(unsigned long, flags);	\
		flags = _raw_write_lock_irqsave(lock);	\
	} while (0)
#define write_lock_nested(lock, subclass)	_raw_write_lock(lock)
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
#define DEFINE_SPINLOCK(x)	spinlock_t x = __SPIN_LOCK_UNLOCKED(x)
# define LOCK_PADSIZE (offsetof(struct raw_spinlock, dep_map))

#define __LOCAL_SPIN_LOCK_UNLOCKED(name)			\
	{							\
		.lock = __RT_MUTEX_BASE_INITIALIZER(name.lock),	\
		LOCAL_SPIN_DEP_MAP_INIT(name)			\
	}
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
# define RW_DEP_MAP_INIT(lockname)

#define __RWLOCK_RT_INITIALIZER(name)					\
{									\
	.rwbase = __RWBASE_INITIALIZER(name),				\
	RW_DEP_MAP_INIT(name)						\
}
#define __RW_LOCK_UNLOCKED(lockname)					\
	(rwlock_t)	{	.raw_lock = __ARCH_RW_LOCK_UNLOCKED,	\
				.magic = RWLOCK_MAGIC,			\
				.owner = SPINLOCK_OWNER_INIT,		\
				.owner_cpu = -1,			\
				RW_DEP_MAP_INIT(lockname) }

#define __RWBASE_INITIALIZER(name)				\
{								\
	.readers = ATOMIC_INIT(READER_BIAS),			\
	.rtmutex = __RT_MUTEX_BASE_INITIALIZER(name.rtmutex),	\
}
#define init_rwbase_rt(rwbase)					\
	do {							\
		rt_mutex_base_init(&(rwbase)->rtmutex);		\
		atomic_set(&(rwbase)->readers, READER_BIAS);	\
	} while (0)
#define DEFINE_RT_MUTEX(mutexname) \
	struct rt_mutex mutexname = __RT_MUTEX_INITIALIZER(mutexname)
#define __DEP_MAP_RT_MUTEX_INITIALIZER(mutexname)	\
	.dep_map = {					\
		.name = #mutexname,			\
		.wait_type_inner = LD_WAIT_SLEEP,	\
	}

#define __RT_MUTEX_BASE_INITIALIZER(rtbasename)				\
{									\
	.wait_lock = __RAW_SPIN_LOCK_UNLOCKED(rtbasename.wait_lock),	\
	.waiters = RB_ROOT_CACHED,					\
	.owner = NULL							\
}
#define __RT_MUTEX_INITIALIZER(mutexname)				\
{									\
	.rtmutex = __RT_MUTEX_BASE_INITIALIZER(mutexname.rtmutex),	\
	__DEP_MAP_RT_MUTEX_INITIALIZER(mutexname)			\
}
#define rt_mutex_init(mutex) \
do { \
	static struct lock_class_key __key; \
	__rt_mutex_init(mutex, __func__, &__key); \
} while (0)
#define rt_mutex_lock(lock) rt_mutex_lock_nested(lock, 0)
#define rt_mutex_lock_nest_lock(lock, nest_lock)			\
	do {								\
		typecheck(struct lockdep_map *, &(nest_lock)->dep_map);	\
		_rt_mutex_lock_nest_lock(lock, &(nest_lock)->dep_map);	\
	} while (0)
#define rt_mutex_lock_nested(lock, subclass) rt_mutex_lock(lock)
#define DEFINE_RAW_SPINLOCK(x)  raw_spinlock_t x = __RAW_SPIN_LOCK_UNLOCKED(x)
# define LOCAL_SPIN_DEP_MAP_INIT(lockname)		\
	.dep_map = {					\
		.name = #lockname,			\
		.wait_type_inner = LD_WAIT_CONFIG,	\
		.lock_type = LD_LOCK_PERCPU,		\
	}
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
{						\
	.raw_lock = __ARCH_SPIN_LOCK_UNLOCKED,	\
	SPIN_DEBUG_INIT(lockname)		\
	RAW_SPIN_DEP_MAP_INIT(lockname) }
#define __RAW_SPIN_LOCK_UNLOCKED(lockname)	\
	(raw_spinlock_t) __RAW_SPIN_LOCK_INITIALIZER(lockname)

#define RB_ROOT (struct rb_root) { NULL, }
#define RB_ROOT_CACHED (struct rb_root_cached) { {NULL, }, NULL }

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
#define EXPORT_SYMBOL_NS(sym, ns)	__EXPORT_SYMBOL(sym, "", __stringify(ns))
#define EXPORT_SYMBOL_NS_GPL(sym, ns)	__EXPORT_SYMBOL(sym, "_gpl", __stringify(ns))
#define THIS_MODULE (&__this_module)

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
#define __cond_export_sym_0(sym, sec, ns) __GENKSYMS_EXPORT_SYMBOL(sym)
#define __cond_export_sym_1(sym, sec, ns) ___EXPORT_SYMBOL(sym, sec, ns)
#define __ksym_marker(sym)	\
	static int __ksym_marker_##sym[0] __section(".discard.ksym") __used

#define __stringify_1(x...)	#x
#define LOCK_CONTENDED(_lock, try, lock)			\
do {								\
	if (!try(_lock)) {					\
		lock_contended(&(_lock)->dep_map, _RET_IP_);	\
		lock(_lock);					\
	}							\
	lock_acquired(&(_lock)->dep_map, _RET_IP_);			\
} while (0)
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

#define force_read_lock_recursive 0
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
# define lock_set_class(l, n, key, s, i)	do { (void)(key); } while (0)
# define lock_set_novalidate_class(l, n, i)	do { } while (0)
# define lock_set_subclass(l, s, i)		do { } while (0)
#define lockdep_assert(cond)		\
	do { WARN_ON(debug_locks && !(cond)); } while (0)
# define lockdep_assert_RT_in_threaded_ctx() do {			\
		WARN_ONCE(debug_locks && !current->lockdep_recursion &&	\
			  lockdep_hardirq_context() &&			\
			  !(current->hardirq_threaded || current->irq_config),	\
			  "Not in threaded context on PREEMPT_RT as expected\n");	\
} while (0)
#define lockdep_assert_held(l)		\
	lockdep_assert(lockdep_is_held(l) != LOCK_STATE_NOT_HELD)
#define lockdep_assert_held_once(l)		\
	lockdep_assert_once(lockdep_is_held(l) != LOCK_STATE_NOT_HELD)
#define lockdep_assert_held_read(l)	\
	lockdep_assert(lockdep_is_held_type(l, 1))
#define lockdep_assert_held_write(l)	\
	lockdep_assert(lockdep_is_held_type(l, 0))
# define lockdep_assert_in_irq() do { } while (0)
# define lockdep_assert_in_softirq() do { } while (0)
# define lockdep_assert_irqs_disabled() do { } while (0)
# define lockdep_assert_irqs_enabled() do { } while (0)
#define lockdep_assert_none_held_once()		\
	lockdep_assert_once(!current->lockdep_depth)
#define lockdep_assert_not_held(l)	\
	lockdep_assert(lockdep_is_held(l) != LOCK_STATE_HELD)
#define lockdep_assert_once(cond)	\
	do { WARN_ON_ONCE(debug_locks && !(cond)); } while (0)
# define lockdep_assert_preemption_disabled() do { } while (0)
# define lockdep_assert_preemption_enabled() do { } while (0)
#define lockdep_depth(tsk)	(0)
# define lockdep_free_key_range(start, size)	do { } while (0)
# define lockdep_init()				do { } while (0)
# define lockdep_init_map(lock, name, key, sub) \
		do { (void)(name); (void)(key); } while (0)
#define lockdep_init_map_crosslock(m, n, k, s) do {} while (0)
# define lockdep_init_map_type(lock, name, key, sub, inner, outer, type) \
		do { (void)(name); (void)(key); } while (0)
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
# define might_lock(lock)						\
do {									\
	typecheck(struct lockdep_map *, &(lock)->dep_map);		\
	lock_acquire(&(lock)->dep_map, 0, 0, 0, 1, NULL, _THIS_IP_);	\
	lock_release(&(lock)->dep_map, _THIS_IP_);			\
} while (0)
# define might_lock_nested(lock, subclass)				\
do {									\
	typecheck(struct lockdep_map *, &(lock)->dep_map);		\
	lock_acquire(&(lock)->dep_map, subclass, 0, 1, 1, NULL,		\
		     _THIS_IP_);					\
	lock_release(&(lock)->dep_map, _THIS_IP_);			\
} while (0)
# define might_lock_read(lock)						\
do {									\
	typecheck(struct lockdep_map *, &(lock)->dep_map);		\
	lock_acquire(&(lock)->dep_map, 0, 0, 1, 1, NULL, _THIS_IP_);	\
	lock_release(&(lock)->dep_map, _THIS_IP_);			\
} while (0)
#define mutex_acquire(l, s, t, i)		lock_acquire_exclusive(l, s, t, NULL, i)
#define mutex_acquire_nest(l, s, t, n, i)	lock_acquire_exclusive(l, s, t, n, i)
#define mutex_release(l, i)			lock_release(l, i)
#define read_lock_is_recursive() 0
#define rwlock_acquire(l, s, t, i)		lock_acquire_exclusive(l, s, t, NULL, i)
#define rwlock_acquire_read(l, s, t, i)					\
do {									\
	if (read_lock_is_recursive())					\
		lock_acquire_shared_recursive(l, s, t, NULL, i);	\
	else								\
		lock_acquire_shared(l, s, t, NULL, i);			\
} while (0)
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
		instrumentation_begin();				\
		if (debug_locks_off() && !debug_locks_silent)		\
			WARN(1, "DEBUG_LOCKS_WARN_ON(%s)", #c);		\
		instrumentation_end();					\
		__ret = 1;						\
	}								\
	__ret;								\
})
# define SMP_DEBUG_LOCKS_WARN_ON(c)			DEBUG_LOCKS_WARN_ON(c)

# define locking_selftest()	do { } while (0)
#define INTERNODE_CACHE_SHIFT L1_CACHE_SHIFT
#define L1_CACHE_ALIGN(x) __ALIGN_KERNEL(x, L1_CACHE_BYTES)
#define SMP_CACHE_BYTES L1_CACHE_BYTES

#define ____cacheline_aligned __attribute__((__aligned__(SMP_CACHE_BYTES)))
#define ____cacheline_aligned_in_smp ____cacheline_aligned
#define ____cacheline_internodealigned_in_smp \
	__attribute__((__aligned__(1 << (INTERNODE_CACHE_SHIFT))))
#define __cacheline_aligned_in_smp __cacheline_aligned

#define __ro_after_init __section(".data..ro_after_init")
#define cache_line_size()	L1_CACHE_BYTES

#define CSD_INIT(_func, _info) \
	(struct __call_single_data){ .func = (_func), .info = (_info), }
#define INIT_CSD(_csd, _func, _info)		\
do {						\
	*(_csd) = CSD_INIT((_func), (_info));	\
} while (0)

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
#define SYSCALL_WORK_SYSCALL_USER_DISPATCH BIT(SYSCALL_WORK_BIT_SYSCALL_USER_DISPATCH)

#define arch_set_restart_data(restart) do { } while (0)
#define clear_syscall_work(fl) \
	clear_bit(SYSCALL_WORK_BIT_##fl, &current_thread_info()->syscall_work)
#define clear_task_syscall_work(t, fl) \
	clear_bit(SYSCALL_WORK_BIT_##fl, &task_thread_info(t)->syscall_work)
#define clear_thread_flag(flag) \
	clear_ti_thread_flag(current_thread_info(), flag)
#define current_thread_info() ((struct thread_info *)current)
#define read_task_thread_flags(t) \
	read_ti_thread_flags(task_thread_info(t))
#define read_thread_flags() \
	read_ti_thread_flags(current_thread_info())
#define set_syscall_work(fl) \
	set_bit(SYSCALL_WORK_BIT_##fl, &current_thread_info()->syscall_work)
#define set_task_syscall_work(t, fl) \
	set_bit(SYSCALL_WORK_BIT_##fl, &task_thread_info(t)->syscall_work)
#define set_thread_flag(flag) \
	set_ti_thread_flag(current_thread_info(), flag)
#define test_and_clear_thread_flag(flag) \
	test_and_clear_ti_thread_flag(current_thread_info(), flag)
#define test_and_set_thread_flag(flag) \
	test_and_set_ti_thread_flag(current_thread_info(), flag)
#define test_syscall_work(fl) \
	test_bit(SYSCALL_WORK_BIT_##fl, &current_thread_info()->syscall_work)
#define test_task_syscall_work(t, fl) \
	test_bit(SYSCALL_WORK_BIT_##fl, &task_thread_info(t)->syscall_work)
#define test_thread_flag(flag) \
	test_ti_thread_flag(current_thread_info(), flag)
#define tif_need_resched() test_thread_flag(TIF_NEED_RESCHED)
#define update_thread_flag(flag, value) \
	update_ti_thread_flag(current_thread_info(), flag, value)
#define BITS_PER_TYPE(type)	(sizeof(type) * BITS_PER_BYTE)
#define BITS_TO_BYTES(nr)	__KERNEL_DIV_ROUND_UP(nr, BITS_PER_TYPE(char))
#define BITS_TO_LONGS(nr)	__KERNEL_DIV_ROUND_UP(nr, BITS_PER_TYPE(long))
#define BITS_TO_U32(nr)		__KERNEL_DIV_ROUND_UP(nr, BITS_PER_TYPE(u32))
#define BITS_TO_U64(nr)		__KERNEL_DIV_ROUND_UP(nr, BITS_PER_TYPE(u64))

#define __ptr_clear_bit(nr, addr)                         \
	({                                                \
		typecheck_pointer(*(addr));               \
		__clear_bit(nr, (unsigned long *)(addr)); \
	})
#define __ptr_set_bit(nr, addr)                         \
	({                                              \
		typecheck_pointer(*(addr));             \
		__set_bit(nr, (unsigned long *)(addr)); \
	})
#define __ptr_test_bit(nr, addr)                       \
	({                                             \
		typecheck_pointer(*(addr));            \
		test_bit(nr, (unsigned long *)(addr)); \
	})
#  define aligned_byte_mask(n) ((1UL << 8*(n))-1)
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
#define typecheck_pointer(x) \
({	typeof(x) __dummy; \
	(void)sizeof(*__dummy); \
	1; \
})
#define ERESTART_RESTARTBLOCK 516 






#define DIV64_U64_ROUND_CLOSEST(dividend, divisor)	\
	({ u64 _tmp = (divisor); div64_u64((dividend) + _tmp / 2, _tmp); })
#define DIV64_U64_ROUND_UP(ll, d)	\
	({ u64 _tmp = (d); div64_u64((ll) + _tmp - 1, _tmp); })
#define DIV_S64_ROUND_CLOSEST(dividend, divisor)(	\
{							\
	s64 __x = (dividend);				\
	s32 __d = (divisor);				\
	((__x > 0) == (__d > 0)) ?			\
		div_s64((__x + (__d / 2)), __d) :	\
		div_s64((__x - (__d / 2)), __d);	\
}							\
)
#define DIV_U64_ROUND_CLOSEST(dividend, divisor)	\
	({ u32 _tmp = (divisor); div_u64((u64)(dividend) + _tmp / 2, _tmp); })

#define div64_long(x, y) div64_s64((x), (y))
#define div64_ul(x, y)   div64_u64((x), (y))

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

#define __STRUCT_FRACT(type)				\
struct type##_fract {					\
	__##type numerator;				\
	__##type denominator;				\
};
#define __abs_choose_expr(x, type, other) __builtin_choose_expr(	\
	__builtin_types_compatible_p(typeof(x),   signed type) ||	\
	__builtin_types_compatible_p(typeof(x), unsigned type),		\
	({ signed type __x = (x); __x < 0 ? -__x : __x; }), other)
#define __round_mask(x, y) ((__typeof__(x))((y)-1))
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
	typeof(y) __y = y;				\
	(((x) + (__y - 1)) / __y) * __y;		\
}							\
)
#define sector_div(a, b) do_div(a, b)
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
#define WARN_ONCE(condition, format...)				\
	DO_ONCE_LITE_IF(condition, WARN, 1, format)
# define WARN_ON_FUNCTION_MISMATCH(x, fn) ({ 0; })
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
#define WARN_TAINT_ONCE(condition, taint, format...)		\
	DO_ONCE_LITE_IF(condition, WARN_TAINT, 1, taint, format)

#define __WARN()		__WARN_FLAGS(BUGFLAG_TAINT(TAINT_WARN))
#define __WARN_printf(taint, arg...) do {				\
		instrumentation_begin();				\
		__warn_printk(arg);					\
		__WARN_FLAGS(BUGFLAG_NO_CUT_HERE | BUGFLAG_TAINT(taint));\
		instrumentation_end();					\
	} while (0)
#define CONSOLE_LOGLEVEL_DEFAULT CONFIG_CONSOLE_LOGLEVEL_DEFAULT
#define CONSOLE_LOGLEVEL_MOTORMOUTH 15	
#define CONSOLE_LOGLEVEL_QUIET	 CONFIG_CONSOLE_LOGLEVEL_QUIET
#define CONSOLE_LOGLEVEL_SILENT  0 
#define DEVKMSG_STR_MAX_SIZE 10
#define MESSAGE_LOGLEVEL_DEFAULT CONFIG_MESSAGE_LOGLEVEL_DEFAULT
#define PRINTK_MAX_SINGLE_HEADER_LEN 2


#define __printk_cpu_sync_try_get() true

#define __printk_index_emit(_fmt, _level, _subsys_fmt_prefix)		\
	do {								\
		if (__builtin_constant_p(_fmt) && __builtin_constant_p(_level)) { \
									\
			static const struct pi_entry _entry		\
			__used = {					\
				.fmt = __builtin_constant_p(_fmt) ? (_fmt) : NULL, \
				.func = __func__,			\
				.file = "__FILE__",			\
				.line = "__LINE__",			\
				.level = __builtin_constant_p(_level) ? (_level) : NULL, \
				.subsys_fmt_prefix = _subsys_fmt_prefix,\
			};						\
			static const struct pi_entry *_entry_ptr	\
			__used __section(".printk_index") = &_entry;	\
		}							\
	} while (0)
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
#define printk(fmt, ...) printk_index_wrap(_printk, fmt, ##__VA_ARGS__)
#define printk_cpu_sync_get_irqsave(flags)		\
	for (;;) {					\
		local_irq_save(flags);			\
		if (__printk_cpu_sync_try_get())	\
			break;				\
		local_irq_restore(flags);		\
		__printk_cpu_sync_wait();		\
	}
#define printk_cpu_sync_put_irqrestore(flags)	\
	do {					\
		__printk_cpu_sync_put();	\
		local_irq_restore(flags);	\
	} while (0)
#define printk_deferred(fmt, ...)					\
	printk_index_wrap(_printk_deferred, fmt, ##__VA_ARGS__)
#define printk_deferred_enter __printk_safe_enter
#define printk_deferred_exit __printk_safe_exit
#define printk_deferred_once(fmt, ...)				\
	DO_ONCE_LITE(printk_deferred, fmt, ##__VA_ARGS__)
#define printk_index_subsys_emit(subsys_fmt_prefix, level, fmt, ...) \
	__printk_index_emit(fmt, level, subsys_fmt_prefix)
#define printk_index_wrap(_p_func, _fmt, ...)				\
	({								\
		__printk_index_emit(_fmt, NULL, NULL);			\
		_p_func(_fmt, ##__VA_ARGS__);				\
	})
#define printk_once(fmt, ...)					\
	DO_ONCE_LITE(printk, fmt, ##__VA_ARGS__)
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
	__section("__dyndbg") name = {				\
		.modname = KBUILD_MODNAME,			\
		.function = __func__,				\
		.filename = "__FILE__",				\
		.format = (fmt),				\
		.lineno = "__LINE__",				\
		.flags = _DPRINTK_FLAGS_DEFAULT,		\
		_DPRINTK_KEY_INIT				\
	}
#define DYNAMIC_DEBUG_BRANCH(descriptor) \
	static_branch_likely(&descriptor.key.dd_key_true)
#define _DPRINTK_FLAGS_DEFAULT _DPRINTK_FLAGS_PRINT
#define _DPRINTK_KEY_INIT .key.dd_key_true = (STATIC_KEY_TRUE_INIT)

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

#define memcat_p(a, b) ({					\
	BUILD_BUG_ON_MSG(!__same_type(*(a), *(b)),		\
			 "type mismatch in memcat_p()");	\
	(typeof(*a) *)__memcat_p((void **)(a), (void **)(b));	\
})
#define memset_after(obj, v, member)					\
({									\
	u8 *__ptr = (u8 *)(obj);					\
	typeof(v) __val = (v);						\
	memset(__ptr + offsetofend(typeof(*(obj)), member), __val,	\
	       sizeof(*(obj)) - offsetofend(typeof(*(obj)), member));	\
})
#define memset_startat(obj, v, member)					\
({									\
	u8 *__ptr = (u8 *)(obj);					\
	typeof(v) __val = (v);						\
	memset(__ptr + offsetof(typeof(*(obj)), member), __val,		\
	       sizeof(*(obj)) - offsetof(typeof(*(obj)), member));	\
})
#define sysfs_match_string(_a, _s) __sysfs_match_string(_a, ARRAY_SIZE(_a), _s)
#define unsafe_memcpy(dst, src, bytes, justification)		\
	memcpy(dst, src, bytes)

#define __FORTIFY_INLINE extern __always_inline __gnu_inline __overloadable
#define __RENAME(x) __asm__(#x)
#define __compiletime_strlen(p)					\
({								\
	unsigned char *__p = (unsigned char *)(p);		\
	size_t __ret = (size_t)-1;				\
	size_t __p_size = __builtin_object_size(p, 1);		\
	if (__p_size != (size_t)-1) {				\
		size_t __p_len = __p_size - 1;			\
		if (__builtin_constant_p(__p[__p_len]) &&	\
		    __p[__p_len] == '\0')			\
			__ret = __builtin_strlen(__p);		\
	}							\
	__ret;							\
})
#define __fortify_memcpy_chk(p, q, size, p_size, q_size,		\
			     p_size_field, q_size_field, op) ({		\
	size_t __fortify_size = (size_t)(size);				\
	fortify_memcpy_chk(__fortify_size, p_size, q_size,		\
			   p_size_field, q_size_field, #op);		\
	__underlying_##op(p, q, __fortify_size);			\
})
#define __fortify_memset_chk(p, c, size, p_size, p_size_field) ({	\
	size_t __fortify_size = (size_t)(size);				\
	fortify_memset_chk(__fortify_size, p_size, p_size_field),	\
	__underlying_memset(p, c, __fortify_size);			\
})
#define memcpy(p, q, s)  __fortify_memcpy_chk(p, q, s,			\
		__builtin_object_size(p, 0), __builtin_object_size(q, 0), \
		__builtin_object_size(p, 1), __builtin_object_size(q, 1), \
		memcpy)
#define memmove(p, q, s)  __fortify_memcpy_chk(p, q, s,			\
		__builtin_object_size(p, 0), __builtin_object_size(q, 0), \
		__builtin_object_size(p, 1), __builtin_object_size(q, 1), \
		memmove)
#define memset(p, c, s) __fortify_memset_chk(p, c, s,			\
		__builtin_object_size(p, 0), __builtin_object_size(p, 1))
#define strlen(p)							\
	__builtin_choose_expr(__is_constexpr(__builtin_strlen(p)),	\
		__builtin_strlen(p), __fortify_strlen(p))


#define DECLARE_STATIC_KEY_FALSE(name)	\
	extern struct static_key_false name
#define DECLARE_STATIC_KEY_MAYBE(cfg, name)			\
	__PASTE(_DECLARE_STATIC_KEY_, IS_ENABLED(cfg))(name)
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
#define DEFINE_STATIC_KEY_MAYBE(cfg, name)			\
	__PASTE(_DEFINE_STATIC_KEY_, IS_ENABLED(cfg))(name)
#define DEFINE_STATIC_KEY_MAYBE_RO(cfg, name)			\
	__PASTE(_DEFINE_STATIC_KEY_RO_, IS_ENABLED(cfg))(name)
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
#define _DECLARE_STATIC_KEY_0(name)	DECLARE_STATIC_KEY_FALSE(name)
#define _DECLARE_STATIC_KEY_1(name)	DECLARE_STATIC_KEY_TRUE(name)
#define _DEFINE_STATIC_KEY_0(name)	DEFINE_STATIC_KEY_FALSE(name)
#define _DEFINE_STATIC_KEY_1(name)	DEFINE_STATIC_KEY_TRUE(name)
#define _DEFINE_STATIC_KEY_RO_0(name)	DEFINE_STATIC_KEY_FALSE_RO(name)
#define _DEFINE_STATIC_KEY_RO_1(name)	DEFINE_STATIC_KEY_TRUE_RO(name)

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
	likely_notrace(branch);								\
})
#define static_branch_maybe(config, x)					\
	(IS_ENABLED(config) ? static_branch_likely(x)			\
			    : static_branch_unlikely(x))
#define static_branch_unlikely(x)						\
({										\
	bool branch;								\
	if (__builtin_types_compatible_p(typeof(*x), struct static_key_true))	\
		branch = arch_static_branch_jump(&(x)->key, false);		\
	else if (__builtin_types_compatible_p(typeof(*x), struct static_key_false)) \
		branch = arch_static_branch(&(x)->key, false);			\
	else									\
		branch = ____wrong_branch_error();				\
	unlikely_notrace(branch);							\
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
#define DO_ONCE_LITE(func, ...)						\
	DO_ONCE_LITE_IF(true, func, ##__VA_ARGS__)
#define DO_ONCE_LITE_IF(condition, func, ...)				\
	({								\
		static bool __section(".data.once") __already_done;	\
		bool __ret_do_once = !!(condition);			\
									\
		if (unlikely(__ret_do_once && !__already_done)) {	\
			__already_done = true;				\
			func(__VA_ARGS__);				\
		}							\
		unlikely(__ret_do_once);				\
	})

#define DEFINE_RATELIMIT_STATE(name, interval_init, burst_init)		\
									\
	struct ratelimit_state name =					\
		RATELIMIT_STATE_INIT(name, interval_init, burst_init)	\

#define RATELIMIT_STATE_INIT(name, interval_init, burst_init) \
	RATELIMIT_STATE_INIT_FLAGS(name, interval_init, burst_init, 0)
#define RATELIMIT_STATE_INIT_FLAGS(name, interval_init, burst_init, flags_init) { \
		.lock		= __RAW_SPIN_LOCK_UNLOCKED(name.lock),		  \
		.interval	= interval_init,				  \
		.burst		= burst_init,					  \
		.flags		= flags_init,					  \
	}

#define __ratelimit(state) ___ratelimit(state, __func__)


#define __MEMINIT        .section	".meminit.text", "ax"
#define __MEMINITDATA    .section	".meminit.data", "aw"
#define __MEMINITRODATA  .section	".meminit.rodata", "a"
#define __REF            .section       ".ref.text", "ax"
#define __REFCONST       .section       ".ref.rodata", "a"
#define __REFDATA        .section       ".ref.data", "aw"
#define ____define_initcall(fn, __stub, __name, __sec)		\
	__define_initcall_stub(__stub, fn)			\
	asm(".section	\"" __sec "\", \"a\"		\n"	\
	    __stringify(__name) ":			\n"	\
	    ".long	" __stringify(__stub) " - .	\n"	\
	    ".previous					\n");	\
	static_assert(__same_type(initcall_t, &fn));
#define ___define_initcall(fn, id, __sec)			\
	__unique_initcall(fn, id, __sec, __initcall_id(fn))
#define __define_initcall(fn, id) ___define_initcall(fn, id, .initcall##id)
#define __define_initcall_stub(__stub, fn)			\
	int __init __cficanonical __stub(void);			\
	int __init __cficanonical __stub(void)			\
	{ 							\
		return fn();					\
	}							\
	__ADDRESSABLE(__stub)
#define __exit          __section(".exit.text") __exitused __cold notrace
#define __exit_p(x) x
#define __exitcall(fn)						\
	static exitcall_t __exitcall_##fn __exit_call = fn
#define __exitused  __used
#define __initcall(fn) device_initcall(fn)
#define __initcall_id(fn)					\
	__PASTE(__KBUILD_MODNAME,				\
	__PASTE(__,						\
	__PASTE(__COUNTER__,					\
	__PASTE(_,						\
	__PASTE("__LINE__",					\
	__PASTE(_, fn))))))
#define __initcall_name(prefix, __iid, id)			\
	__PASTE(__,						\
	__PASTE(prefix,						\
	__PASTE(__,						\
	__PASTE(__iid, id))))
#define __initcall_section(__sec, __iid)			\
	#__sec ".init.." #__iid
#define __initcall_stub(fn, __iid, id)				\
	__initcall_name(initstub, __iid, id)
#define __memexit        __section(".memexit.text") __exitused __cold notrace
#define __memexitconst   __section(".memexit.rodata")
#define __memexitdata    __section(".memexit.data")
#define __meminit        __section(".meminit.text") __cold notrace \
						  __latent_entropy
#define __meminitconst   __section(".meminit.rodata")
#define __meminitdata    __section(".meminit.data")
#define __noinitretpoline __noretpoline
#define __nosavedata __section(".data..nosave")
#define __ref            __section(".ref.text") noinline
#define __refconst       __section(".ref.rodata")
#define __refdata        __section(".ref.data")
#define __setup(str, fn)						\
	__setup_param(str, fn, fn, 0)
#define __setup_param(str, unique_id, fn, early)			\
	static const char __setup_str_##unique_id[] __initconst		\
		__aligned(1) = str; 					\
	static struct obs_kernel_param __setup_##unique_id		\
		__used __section(".init.setup")				\
		__aligned(__alignof__(struct obs_kernel_param))		\
		= { __setup_str_##unique_id, fn, early }
#define __unique_initcall(fn, id, __sec, __iid)			\
	____define_initcall(fn,					\
		__initcall_stub(fn, __iid, id),			\
		__initcall_name(initcall, __iid, id),		\
		__initcall_section(__sec, __iid))
#define arch_initcall(fn)		__define_initcall(fn, 3)
#define arch_initcall_sync(fn)		__define_initcall(fn, 3s)
#define console_initcall(fn)	___define_initcall(fn, con, .con_initcall)
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
	early_param(str_on, parse_##var##_on);				\
									\
	static int __init parse_##var##_off(char *arg)			\
	{								\
		var = 0;						\
		return 0;						\
	}								\
	early_param(str_off, parse_##var##_off)
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


#define __instrumentation_begin(c) ({					\
	asm volatile(__stringify(c) ": nop\n\t"				\
		     ".pushsection .discard.instr_begin\n\t"		\
		     ".long " __stringify(c) "b - .\n\t"		\
		     ".popsection\n\t" : : "i" (c));			\
})
#define __instrumentation_end(c) ({					\
	asm volatile(__stringify(c) ": nop\n\t"				\
		     ".pushsection .discard.instr_end\n\t"		\
		     ".long " __stringify(c) "b - .\n\t"		\
		     ".popsection\n\t" : : "i" (c));			\
})
# define instrumentation_begin()	do { } while(0)
# define instrumentation_end()		do { } while(0)

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

#define SOFTIRQ_LOCK_OFFSET (SOFTIRQ_DISABLE_OFFSET + PREEMPT_LOCK_OFFSET)
#define __IRQ_MASK(x)	((1UL << (x))-1)

#define __preempt_count_dec() __preempt_count_sub(1)
#define __preempt_count_inc() __preempt_count_add(1)
#define hardirq_count()	(preempt_count() & HARDIRQ_MASK)
#define in_atomic()	(preempt_count() != 0)
#define in_atomic_preempt_off() (preempt_count() != PREEMPT_DISABLE_OFFSET)
#define in_hardirq()		(hardirq_count())
#define in_interrupt()		(irq_count())
#define in_irq()		(hardirq_count())
#define in_nmi()		(nmi_count())
#define in_serving_softirq()	(softirq_count() & SOFTIRQ_OFFSET)
#define in_softirq()		(softirq_count())
#define in_task()		(!(in_nmi() | in_hardirq() | in_serving_softirq()))
#define nmi_count()	(preempt_count() & NMI_MASK)
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
# define softirq_count()	(current->softirq_disable_cnt & SOFTIRQ_MASK)


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


#define cpu_active_mask   ((const struct cpumask *)&__cpu_active_mask)
#define cpu_all_mask to_cpumask(cpu_all_bits)
#define cpu_dying_mask    ((const struct cpumask *)&__cpu_dying_mask)
#define cpu_is_offline(cpu)	unlikely(!cpu_online(cpu))
#define cpu_none_mask to_cpumask(cpu_bit_bitmap[0])
#define cpu_online_mask   ((const struct cpumask *)&__cpu_online_mask)
#define cpu_possible_mask ((const struct cpumask *)&__cpu_possible_mask)
#define cpu_present_mask  ((const struct cpumask *)&__cpu_present_mask)
#define cpumask_any(srcp) cpumask_first(srcp)
#define cpumask_any_and(mask1, mask2) cpumask_first_and((mask1), (mask2))
#define cpumask_bits(maskp) ((maskp)->bits)
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
#define BITMAP_FIRST_WORD_MASK(start) (~0UL << ((start) & (BITS_PER_LONG - 1)))
#define BITMAP_FROM_U64(n) (n)
#define BITMAP_LAST_WORD_MASK(nbits) (~0UL >> (-(nbits) & (BITS_PER_LONG - 1)))
#define BITMAP_MEM_ALIGNMENT 8
#define BITMAP_MEM_MASK (BITMAP_MEM_ALIGNMENT - 1)

#define bitmap_copy_le bitmap_copy
#define bitmap_from_arr32(bitmap, buf, nbits)			\
	bitmap_copy_clear_tail((unsigned long *) (bitmap),	\
			(const unsigned long *) (buf), (nbits))
#define bitmap_from_arr64(bitmap, buf, nbits)			\
	bitmap_copy_clear_tail((unsigned long *)(bitmap), (const unsigned long *)(buf), (nbits))
#define bitmap_to_arr32(buf, bitmap, nbits)			\
	bitmap_copy_clear_tail((unsigned long *) (buf),		\
			(const unsigned long *) (bitmap), (nbits))
#define bitmap_to_arr64(buf, bitmap, nbits)			\
	bitmap_copy_clear_tail((unsigned long *)(buf), (const unsigned long *)(bitmap), (nbits))

#define find_first_clump8(clump, bits, size) \
	find_next_clump8((clump), (bits), (size), 0)
#define find_first_zero_bit_le(addr, size) \
	find_next_zero_bit_le((addr), (size), 0)
#define for_each_clear_bit(bit, addr, size) \
	for ((bit) = find_next_zero_bit((addr), (size), 0);	\
	     (bit) < (size);					\
	     (bit) = find_next_zero_bit((addr), (size), (bit) + 1))
#define for_each_clear_bit_from(bit, addr, size) \
	for ((bit) = find_next_zero_bit((addr), (size), (bit));	\
	     (bit) < (size);					\
	     (bit) = find_next_zero_bit((addr), (size), (bit) + 1))
#define for_each_clear_bitrange(b, e, addr, size)		\
	for ((b) = find_next_zero_bit((addr), (size), 0),	\
	     (e) = find_next_bit((addr), (size), (b) + 1);	\
	     (b) < (size);					\
	     (b) = find_next_zero_bit((addr), (size), (e) + 1),	\
	     (e) = find_next_bit((addr), (size), (b) + 1))
#define for_each_clear_bitrange_from(b, e, addr, size)		\
	for ((b) = find_next_zero_bit((addr), (size), (b)),	\
	     (e) = find_next_bit((addr), (size), (b) + 1);	\
	     (b) < (size);					\
	     (b) = find_next_zero_bit((addr), (size), (e) + 1),	\
	     (e) = find_next_bit((addr), (size), (b) + 1))
#define for_each_set_bit(bit, addr, size) \
	for ((bit) = find_next_bit((addr), (size), 0);		\
	     (bit) < (size);					\
	     (bit) = find_next_bit((addr), (size), (bit) + 1))
#define for_each_set_bit_from(bit, addr, size) \
	for ((bit) = find_next_bit((addr), (size), (bit));	\
	     (bit) < (size);					\
	     (bit) = find_next_bit((addr), (size), (bit) + 1))
#define for_each_set_bitrange(b, e, addr, size)			\
	for ((b) = find_next_bit((addr), (size), 0),		\
	     (e) = find_next_zero_bit((addr), (size), (b) + 1);	\
	     (b) < (size);					\
	     (b) = find_next_bit((addr), (size), (e) + 1),	\
	     (e) = find_next_zero_bit((addr), (size), (b) + 1))
#define for_each_set_bitrange_from(b, e, addr, size)		\
	for ((b) = find_next_bit((addr), (size), (b)),		\
	     (e) = find_next_zero_bit((addr), (size), (b) + 1);	\
	     (b) < (size);					\
	     (b) = find_next_bit((addr), (size), (e) + 1),	\
	     (e) = find_next_zero_bit((addr), (size), (b) + 1))
#define for_each_set_clump8(start, clump, bits, size) \
	for ((start) = find_first_clump8(&(clump), (bits), (size)); \
	     (start) < (size); \
	     (start) = find_next_clump8(&(clump), (bits), (size), (start) + 8))
#define ALIGN(x, a)		__ALIGN_KERNEL((x), (a))
#define ALIGN_DOWN(x, a)	__ALIGN_KERNEL((x) - ((a) - 1), (a))
#define IS_ALIGNED(x, a)		(((x) & ((typeof(x))(a) - 1)) == 0)
#define PTR_ALIGN(p, a)		((typeof(p))ALIGN((unsigned long)(p), (a)))
#define PTR_ALIGN_DOWN(p, a)	((typeof(p))ALIGN_DOWN((unsigned long)(p), (a)))

#define __ALIGN_MASK(x, mask)	__ALIGN_KERNEL_MASK((x), (mask))
#define MIN_THREADS_LEFT_FOR_ROOT 4
#define NR_CPUS		CONFIG_NR_CPUS
#define PID_MAX_DEFAULT (CONFIG_BASE_SMALL ? 0x1000 : 0x8000)
#define PID_MAX_LIMIT (CONFIG_BASE_SMALL ? PAGE_SIZE * 8 : \
	(sizeof(long) > 4 ? 4 * 1024 * 1024 : PID_MAX_DEFAULT))

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]) + __must_be_array(arr))
#define CONCATENATE(a, b) __CONCAT(a, b)
#define COUNT_ARGS(X...) __COUNT_ARGS(, ##X, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
#define PTR_IF(cond, ptr)	((cond) ? (ptr) : NULL)
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

#define __CONCAT(a, b) a ## b
#define __COUNT_ARGS(_0, _1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _n, X...) _n
#define __trace_printk_check_format(fmt, args...)			\
do {									\
	if (0)								\
		____trace_printk_check_format(fmt, ##args);		\
} while (0)
# define cant_migrate()							\
	do {								\
		if (IS_ENABLED(CONFIG_SMP))				\
			__cant_migrate("__FILE__", "__LINE__");		\
	} while (0)
# define cant_sleep() \
	do { __cant_sleep("__FILE__", "__LINE__", 0); } while (0)
#define do_trace_printk(fmt, args...)					\
do {									\
	static const char *trace_printk_fmt __used			\
		__section("__trace_printk_fmt") =			\
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
		  __section("__trace_printk_fmt") =			\
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
#define lower_16_bits(n) ((u16)((n) & 0xffff))
#define lower_32_bits(n) ((u32)((n) & 0xffffffff))
#define might_fault() __might_fault("__FILE__", "__LINE__")
# define might_resched() dynamic_might_resched()
# define might_sleep() \
	do { __might_sleep("__FILE__", "__LINE__"); might_resched(); } while (0)
#define might_sleep_if(cond) do { if (cond) might_sleep(); } while (0)
# define non_block_end() WARN_ON(current->non_block_count-- == 0)
# define non_block_start() (current->non_block_count++)
# define sched_annotate_sleep()	(current->task_state_change = 0)
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
		__section("__trace_printk_fmt") =			\
		__builtin_constant_p(str) ? str : NULL;			\
									\
	if (__builtin_constant_p(str))					\
		__trace_bputs(_THIS_IP_, trace_printk_fmt);		\
	else								\
		__trace_puts(_THIS_IP_, str, strlen(str));		\
})
#define u64_to_user_ptr(x) (		\
{					\
	typecheck(u64, (x));		\
	(void __user *)(uintptr_t)(x);	\
}					\
)
#define upper_16_bits(n) ((u16)((n) >> 16))
#define upper_32_bits(n) ((u32)(((n) >> 16) >> 16))

#define _THIS_IP_  ({ __label__ __here; __here: (unsigned long)&&__here; })
#define DECLARE_STATIC_CALL(name, func)					\
	extern struct static_call_key STATIC_CALL_KEY(name);		\
	extern typeof(func) STATIC_CALL_TRAMP(name);
#define STATIC_CALL_KEY(name)		__PASTE(STATIC_CALL_KEY_PREFIX, name)
#define STATIC_CALL_KEY_STR(name)	__stringify(STATIC_CALL_KEY(name))
#define STATIC_CALL_SITE_FLAGS 3UL
#define STATIC_CALL_SITE_INIT 2UL	
#define STATIC_CALL_SITE_TAIL 1UL	
#define STATIC_CALL_TRAMP(name)		__PASTE(STATIC_CALL_TRAMP_PREFIX, name)
#define STATIC_CALL_TRAMP_STR(name)	__stringify(STATIC_CALL_TRAMP(name))

#define __STATIC_CALL_ADDRESSABLE(name) \
	__ADDRESSABLE(STATIC_CALL_KEY(name))

#define __raw_static_call(name)	(&STATIC_CALL_TRAMP(name))
#define __static_call(name)						\
({									\
	__STATIC_CALL_ADDRESSABLE(name);				\
	__raw_static_call(name);					\
})
#define static_call(name)						\
	((typeof(STATIC_CALL_TRAMP(name))*)(STATIC_CALL_KEY(name).func))
#define static_call_mod(name)	__raw_static_call(name)

#define __careful_cmp(x, y, op) \
	__builtin_choose_expr(__safe_cmp(x, y), \
		__cmp(x, y, op), \
		__cmp_once(x, y, __UNIQUE_ID(__x), __UNIQUE_ID(__y), op))
#define __cmp(x, y, op)	((x) op (y) ? (x) : (y))
#define __cmp_once(x, y, unique_x, unique_y, op) ({	\
		typeof(x) unique_x = (x);		\
		typeof(y) unique_y = (y);		\
		__cmp(unique_x, unique_y, op); })
#define __no_side_effects(x, y) \
		(__is_constexpr(x) && __is_constexpr(y))
#define __safe_cmp(x, y) \
		(__typecheck(x, y) && __no_side_effects(x, y))
#define __typecheck(x, y) \
	(!!(sizeof((typeof(x) *)1 == (typeof(y) *)1)))
#define clamp(val, lo, hi) min((typeof(val))max(val, lo), hi)
#define clamp_t(type, val, lo, hi) min_t(type, max_t(type, val, lo), hi)
#define clamp_val(val, lo, hi) clamp_t(typeof(val), val, lo, hi)
#define max(x, y)	__careful_cmp(x, y, >)
#define max3(x, y, z) max((typeof(x))max(x, y), z)
#define max_t(type, x, y)	__careful_cmp((type)(x), (type)(y), >)
#define min(x, y)	__careful_cmp(x, y, <)
#define min3(x, y, z) min((typeof(x))min(x, y), z)
#define min_not_zero(x, y) ({			\
	typeof(x) __x = (x);			\
	typeof(y) __y = (y);			\
	__x == 0 ? __y : ((__y == 0) ? __x : min(__x, __y)); })
#define min_t(type, x, y)	__careful_cmp((type)(x), (type)(y), <)
#define swap(a, b) \
	do { typeof(a) __tmp = (a); (a) = (b); (b) = __tmp; } while (0)

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
	((n) < 2 ? 0 :			\
	 63 - __builtin_clzll(n)) :	\
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
		((n) == 1) ? 1 :		\
		(1UL << (ilog2((n) - 1) + 1))	\
				   ) :		\
	__roundup_pow_of_two(n)			\
 )



#define irqs_disabled()					\
	({						\
		unsigned long _flags;			\
		raw_local_save_flags(_flags);		\
		raw_irqs_disabled_flags(_flags);	\
	})
#define irqs_disabled_flags(flags) raw_irqs_disabled_flags(flags)
#define local_irq_disable()				\
	do {						\
		bool was_disabled = raw_irqs_disabled();\
		raw_local_irq_disable();		\
		if (!was_disabled)			\
			trace_hardirqs_off();		\
	} while (0)
#define local_irq_enable()				\
	do {						\
		trace_hardirqs_on();			\
		raw_local_irq_enable();			\
	} while (0)
#define local_irq_restore(flags)			\
	do {						\
		if (!raw_irqs_disabled_flags(flags))	\
			trace_hardirqs_on();		\
		raw_local_irq_restore(flags);		\
	} while (0)
#define local_irq_save(flags)				\
	do {						\
		raw_local_irq_save(flags);		\
		if (!raw_irqs_disabled_flags(flags))	\
			trace_hardirqs_off();		\
	} while (0)
# define lockdep_hardirq_context()		0
# define lockdep_hardirq_enter()		do { } while (0)
# define lockdep_hardirq_exit()			do { } while (0)
# define lockdep_hardirq_threaded()		do { } while (0)
# define lockdep_hardirqs_enabled()		0
# define lockdep_hrtimer_enter(__hrtimer)	false
# define lockdep_hrtimer_exit(__context)	do { } while (0)
# define lockdep_irq_work_enter(_flags)					\
	  do {								\
		  if (!((_flags) & IRQ_WORK_HARD_IRQ))			\
			current->irq_config = 1;			\
	  } while (0)
# define lockdep_irq_work_exit(_flags)					\
	  do {								\
		  if (!((_flags) & IRQ_WORK_HARD_IRQ))			\
			current->irq_config = 0;			\
	  } while (0)
# define lockdep_posixtimer_enter()		do { } while (0)
# define lockdep_posixtimer_exit()		do { } while (0)
# define lockdep_softirq_context(p)		0
# define lockdep_softirq_enter()		do { } while (0)
# define lockdep_softirq_exit()			do { } while (0)
# define lockdep_softirqs_enabled(p)		0
#define raw_check_bogus_irq_restore()			\
	do {						\
		if (unlikely(!arch_irqs_disabled()))	\
			warn_bogus_irq_restore();	\
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
		raw_check_bogus_irq_restore();		\
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
# define trace_hardirqs_off()			do { } while (0)
# define trace_hardirqs_off_finish()		do { } while (0)
# define trace_hardirqs_on()			do { } while (0)
# define trace_hardirqs_on_prepare()		do { } while (0)
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
#define flush_scheduled_work()						\
({									\
	if (0)								\
		__warn_flushing_systemwide_wq();			\
	__flush_workqueue(system_wq);					\
})
#define flush_workqueue(wq)						\
({									\
	struct workqueue_struct *_wq = (wq);				\
									\
	if ((__builtin_constant_p(_wq == system_wq) &&			\
	     _wq == system_wq) ||					\
	    (__builtin_constant_p(_wq == system_highpri_wq) &&		\
	     _wq == system_highpri_wq) ||				\
	    (__builtin_constant_p(_wq == system_long_wq) &&		\
	     _wq == system_long_wq) ||					\
	    (__builtin_constant_p(_wq == system_unbound_wq) &&		\
	     _wq == system_unbound_wq) ||				\
	    (__builtin_constant_p(_wq == system_freezable_wq) &&	\
	     _wq == system_freezable_wq) ||				\
	    (__builtin_constant_p(_wq == system_power_efficient_wq) &&	\
	     _wq == system_power_efficient_wq) ||			\
	    (__builtin_constant_p(_wq == system_freezable_power_efficient_wq) && \
	     _wq == system_freezable_power_efficient_wq))		\
		__warn_flushing_systemwide_wq();			\
	__flush_workqueue(_wq);						\
})
#define work_data_bits(work) ((unsigned long *)(&(work)->data))
#define work_pending(work) \
	test_bit(WORK_STRUCT_PENDING_BIT, work_data_bits(work))
#define KVFREE_GET_MACRO(_1, _2, NAME, ...) NAME
#define RCU_INITIALIZER(v) (typeof(*(v)) __force __rcu *)(v)
#define RCU_INIT_POINTER(p, v) \
	do { \
		rcu_check_sparse(p, __rcu); \
		WRITE_ONCE(p, RCU_INITIALIZER(v)); \
	} while (0)
#define RCU_LOCKDEP_WARN(c, s)						\
	do {								\
		static bool __section(".data.unlikely") __warned;	\
		if ((c) && debug_lockdep_rcu_enabled() && !__warned) {	\
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
#define USHORT_CMP_GE(a, b)	(USHRT_MAX / 2 >= (unsigned short)((a) - (b)))
#define USHORT_CMP_LT(a, b)	(USHRT_MAX / 2 < (unsigned short)((a) - (b)))

#define __is_kvfree_rcu_offset(offset) ((offset) < 4096)
#define __rcu_access_pointer(p, local, space) \
({ \
	typeof(*p) *local = (typeof(*p) *__force)READ_ONCE(p); \
	rcu_check_sparse(p, space); \
	((typeof(*p) __force __kernel *)(local)); \
})
#define __rcu_dereference_check(p, local, c, space) \
({ \
	 \
	typeof(*p) *local = (typeof(*p) *__force)READ_ONCE(p); \
	RCU_LOCKDEP_WARN(!(c), "suspicious rcu_dereference_check() usage"); \
	rcu_check_sparse(p, space); \
	((typeof(*p) __force __kernel *)(local)); \
})
#define __rcu_dereference_protected(p, local, c, space) \
({ \
	RCU_LOCKDEP_WARN(!(c), "suspicious rcu_dereference_protected() usage"); \
	rcu_check_sparse(p, space); \
	((typeof(*p) __force __kernel *)(p)); \
})
#define __rcu_dereference_raw(p, local) \
({ \
	 \
	typeof(p) local = READ_ONCE(p); \
	((typeof(*p) __force __kernel *)(local)); \
})
#define __unrcu_pointer(p, local)					\
({									\
	typeof(*p) *local = (typeof(*p) *__force)(p);			\
	rcu_check_sparse(p, __rcu);					\
	((typeof(*p) __force __kernel *)(local)); 			\
})
# define call_rcu_tasks call_rcu
#define cond_resched_tasks_rcu_qs() \
do { \
	rcu_tasks_qs(current, false); \
	cond_resched(); \
} while (0)
#define kfree_rcu(ptr, rhf...) kvfree_rcu(ptr, ## rhf)
#define kvfree_rcu(...) KVFREE_GET_MACRO(__VA_ARGS__,		\
	kvfree_rcu_arg_2, kvfree_rcu_arg_1)(__VA_ARGS__)
#define kvfree_rcu_arg_1(ptr)					\
do {								\
	typeof(ptr) ___p = (ptr);				\
								\
	if (___p)						\
		kvfree_call_rcu(NULL, (rcu_callback_t) (___p));	\
} while (0)
#define kvfree_rcu_arg_2(ptr, rhf)					\
do {									\
	typeof (ptr) ___p = (ptr);					\
									\
	if (___p) {									\
		BUILD_BUG_ON(!__is_kvfree_rcu_offset(offsetof(typeof(*(ptr)), rhf)));	\
		kvfree_call_rcu(&((___p)->rhf), (rcu_callback_t)(unsigned long)		\
			(offsetof(typeof(*(ptr)), rhf)));				\
	}										\
} while (0)
#define rcu_access_pointer(p) __rcu_access_pointer((p), __UNIQUE_ID(rcu), __rcu)
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
	__rcu_dereference_check((p), __UNIQUE_ID(rcu), \
				(c) || rcu_read_lock_bh_held(), __rcu)
#define rcu_dereference_check(p, c) \
	__rcu_dereference_check((p), __UNIQUE_ID(rcu), \
				(c) || rcu_read_lock_held(), __rcu)
#define rcu_dereference_protected(p, c) \
	__rcu_dereference_protected((p), __UNIQUE_ID(rcu), (c), __rcu)
#define rcu_dereference_raw(p) __rcu_dereference_raw(p, __UNIQUE_ID(rcu))
#define rcu_dereference_raw_check(p) \
	__rcu_dereference_check((p), __UNIQUE_ID(rcu), 1, __rcu)
#define rcu_dereference_sched(p) rcu_dereference_sched_check(p, 0)
#define rcu_dereference_sched_check(p, c) \
	__rcu_dereference_check((p), __UNIQUE_ID(rcu), \
				(c) || rcu_read_lock_sched_held(), \
				__rcu)
# define rcu_lock_acquire(a)		do { } while (0)
# define rcu_lock_release(a)		do { } while (0)
#define rcu_note_voluntary_context_switch(t) rcu_tasks_qs(t, false)
#define rcu_pointer_handoff(p) (p)
#define rcu_preempt_depth() READ_ONCE(current->rcu_read_lock_nesting)
#define rcu_read_unlock_strict() do { } while (0)
#define rcu_replace_pointer(rcu_ptr, ptr, c)				\
({									\
	typeof(ptr) __tmp = rcu_dereference_protected((rcu_ptr), (c));	\
	rcu_assign_pointer((rcu_ptr), (ptr));				\
	__tmp;								\
})
#define rcu_sleep_check()						\
	do {								\
		rcu_preempt_sleep_check();				\
		if (!IS_ENABLED(CONFIG_PREEMPT_RT))			\
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
#define unrcu_pointer(p) __unrcu_pointer(p, __UNIQUE_ID(rcu))

#define rcu_is_idle_cpu(cpu) \
	(is_idle_task(current) && !in_nmi() && !in_hardirq() && !in_serving_softirq())
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

#define random_get_entropy()	((unsigned long)get_cycles())
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
		, .wait_lock = __RAW_SPIN_LOCK_UNLOCKED(lockname.wait_lock) \
		, .wait_list = LIST_HEAD_INIT(lockname.wait_list) \
		__DEBUG_MUTEX_INITIALIZER(lockname) \
		__DEP_MAP_MUTEX_INITIALIZER(lockname) }
#define __mutex_init(mutex, name, key)			\
do {							\
	rt_mutex_base_init(&(mutex)->rtmutex);		\
	__mutex_rt_init((mutex), name, key);		\
} while (0)
#define mutex_init(mutex)						\
do {									\
	static struct lock_class_key __key;				\
									\
	__mutex_init((mutex), #mutex, &__key);				\
} while (0)
#define mutex_is_locked(l)	rt_mutex_base_is_locked(&(l)->rtmutex)
#define mutex_lock(lock) mutex_lock_nested(lock, 0)
#define mutex_lock_interruptible(lock) mutex_lock_interruptible_nested(lock, 0)
# define mutex_lock_interruptible_nested(lock, subclass) mutex_lock_interruptible(lock)
#define mutex_lock_io(lock) mutex_lock_io_nested(lock, 0)
# define mutex_lock_io_nested(lock, subclass) mutex_lock_io(lock)
#define mutex_lock_killable(lock) mutex_lock_killable_nested(lock, 0)
# define mutex_lock_killable_nested(lock, subclass) mutex_lock_killable(lock)
# define mutex_lock_nest_lock(lock, nest_lock) mutex_lock(lock)
# define mutex_lock_nested(lock, subclass) mutex_lock(lock)
#define OSQ_LOCK_UNLOCKED { ATOMIC_INIT(OSQ_UNLOCKED_VAL) }
#define OSQ_UNLOCKED_VAL (0)

#define DECLARE_RWSEM(name) \
	struct rw_semaphore name = __RWSEM_INITIALIZER(name)

#define __RWSEM_COUNT_INIT(name)	.count = ATOMIC_LONG_INIT(RWSEM_UNLOCKED_VALUE)
# define __RWSEM_DEBUG_INIT(lockname) .magic = &lockname,
# define __RWSEM_DEP_MAP_INIT(lockname)			\
	.dep_map = {					\
		.name = #lockname,			\
		.wait_type_inner = LD_WAIT_SLEEP,	\
	},
#define __RWSEM_INITIALIZER(name)				\
	{							\
		.rwbase = __RWBASE_INITIALIZER(name),		\
		__RWSEM_DEP_MAP_INIT(name)			\
	}
#define __RWSEM_OPT_INIT(lockname) .osq = OSQ_LOCK_UNLOCKED,
# define down_read_killable_nested(sem, subclass)	down_read_killable(sem)
# define down_read_nested(sem, subclass)		down_read(sem)
# define down_read_non_owner(sem)		down_read(sem)
# define down_write_killable_nested(sem, subclass)	down_write_killable(sem)
# define down_write_nest_lock(sem, nest_lock)			\
do {								\
	typecheck(struct lockdep_map *, &(nest_lock)->dep_map);	\
	_down_write_nest_lock(sem, &(nest_lock)->dep_map);	\
} while (0)
# define down_write_nested(sem, subclass)	down_write(sem)
#define init_rwsem(sem)						\
do {								\
	static struct lock_class_key __key;			\
								\
	__init_rwsem((sem), #sem, &__key);			\
} while (0)
# define up_read_non_owner(sem)			up_read(sem)
#define DISTANCE_BITS           8
#define RECLAIM_DISTANCE 30





#define for_each_node_with_cpus(node)			\
	for_each_online_node(node)			\
		if (nr_cpus_node(node))
#define node_distance(from,to)	((from) == (to) ? LOCAL_DISTANCE : REMOTE_DISTANCE)
#define nr_cpus_node(node) cpumask_weight(cpumask_of_node(node))
#define topology_book_cpumask(cpu)		cpumask_of(cpu)
#define topology_book_id(cpu)			((void)(cpu), -1)
#define topology_cluster_cpumask(cpu)		cpumask_of(cpu)
#define topology_cluster_id(cpu)		((void)(cpu), -1)
#define topology_core_cpumask(cpu)		cpumask_of(cpu)
#define topology_core_id(cpu)			((void)(cpu), 0)
#define topology_die_cpumask(cpu)		cpumask_of(cpu)
#define topology_die_id(cpu)			((void)(cpu), -1)
#define topology_drawer_cpumask(cpu)		cpumask_of(cpu)
#define topology_drawer_id(cpu)			((void)(cpu), -1)
#define topology_physical_package_id(cpu)	((void)(cpu), -1)
#define topology_ppin(cpu)			((void)(cpu), 0ull)
#define topology_sibling_cpumask(cpu)		cpumask_of(cpu)

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

#define LINUX_MM_DEBUG_H 1
#define VIRTUAL_BUG_ON(cond) BUG_ON(cond)
#define VM_BUG_ON(cond) BUG_ON(cond)
#define VM_BUG_ON_FOLIO(cond, folio)					\
	do {								\
		if (unlikely(cond)) {					\
			dump_page(&folio->page, "VM_BUG_ON_FOLIO(" __stringify(cond)")");\
			BUG();						\
		}							\
	} while (0)
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
#define VM_WARN_ON_ONCE_FOLIO(cond, folio)	({			\
	static bool __section(".data.once") __warned;			\
	int __ret_warn_once = !!(cond);					\
									\
	if (unlikely(__ret_warn_once && !__warned)) {			\
		dump_page(&folio->page, "VM_WARN_ON_ONCE_FOLIO(" __stringify(cond)")");\
		__warned = true;					\
		WARN_ON(1);						\
	}								\
	unlikely(__ret_warn_once);					\
})
#define VM_WARN_ON_ONCE_PAGE(cond, page)	({			\
	static bool __section(".data.once") __warned;			\
	int __ret_warn_once = !!(cond);					\
									\
	if (unlikely(__ret_warn_once && !__warned)) {			\
		dump_page(page, "VM_WARN_ON_ONCE_PAGE(" __stringify(cond)")");\
		__warned = true;					\
		WARN_ON(1);						\
	}								\
	unlikely(__ret_warn_once);					\
})
#define ANON_AND_FILE 2
#define ASYNC_AND_SYNC 2
#define DEF_PRIORITY 12
#define LRU_ACTIVE 1
#define LRU_BASE 0
#define LRU_FILE 2
#define MAX_ORDER 11
#define MAX_ORDER_NR_PAGES (1 << (MAX_ORDER - 1))
#define MAX_ZONES_PER_ZONELIST (MAX_NUMNODES * MAX_NR_ZONES)
#define MIGRATETYPE_MASK ((1UL << PB_migratetype_bits) - 1)
#define NR_PCP_LISTS (MIGRATE_PCPTYPES * (PAGE_ALLOC_COSTLY_ORDER + 1 + NR_PCP_THP))
#define NR_PCP_ORDER_MASK ((1<<NR_PCP_ORDER_WIDTH) - 1)
#define NR_PCP_ORDER_WIDTH 8
#define NR_PCP_THP 1
#define NR_VM_NUMA_EVENT_ITEMS 0
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
#define for_next_zone_zonelist_nodemask(zone, z, highidx, nodemask) \
	for (zone = z->zone;	\
		zone;							\
		z = next_zones_zonelist(++z, highidx, nodemask),	\
			zone = zonelist_zone(z))
#define get_pageblock_migratetype(page)					\
	get_pfnblock_flags_mask(page, page_to_pfn(page), MIGRATETYPE_MASK)
#define high_wmark_pages(z) (z->_watermark[WMARK_HIGH] + z->watermark_boost)
#  define is_migrate_cma(migratetype) unlikely((migratetype) == MIGRATE_CMA)
#  define is_migrate_cma_page(_page) (get_pageblock_migratetype(_page) == MIGRATE_CMA)
#define low_wmark_pages(z) (z->_watermark[WMARK_LOW] + z->watermark_boost)
#define min_wmark_pages(z) (z->_watermark[WMARK_MIN] + z->watermark_boost)
#define node_end_pfn(nid) pgdat_end_pfn(NODE_DATA(nid))
#define pfn_in_present_section pfn_valid
#define pfn_to_nid(pfn)		(0)
#define sparse_index_init(_sec, _nid)  do {} while (0)
#define sparse_init()	do {} while (0)
#define subsection_map_init(_pfn, _nr_pages) do {} while (0)
#define wmark_pages(z, i) (z->_watermark[i] + z->watermark_boost)
#define zone_idx(zone)		((zone) - (zone)->zone_pgdat->node_zones)
#define MHP_MEMMAP_ON_MEMORY   ((__force mhp_t)BIT(1))

#define arch_alloc_nodedata(nid)	generic_alloc_nodedata(nid)
#define generic_alloc_nodedata(nid)				\
({								\
	memblock_alloc(sizeof(*pgdat), SMP_CACHE_BYTES);	\
})
#define generic_free_nodedata(pgdat)	kfree(pgdat)
#define pfn_to_online_page(pfn)			\
({						\
	struct page *___page = NULL;		\
	if (pfn_valid(pfn))			\
		___page = pfn_to_page(pfn);	\
	___page;				\
 })

#define local_lock(lock)		__local_lock(lock)
#define local_lock_init(lock)		__local_lock_init(lock)
#define local_lock_irq(lock)		__local_lock_irq(lock)
#define local_lock_irqsave(lock, flags)				\
	__local_lock_irqsave(lock, flags)
#define local_unlock(lock)		__local_unlock(lock)
#define local_unlock_irq(lock)		__local_unlock_irq(lock)
#define local_unlock_irqrestore(lock, flags)			\
	__local_unlock_irqrestore(lock, flags)
#define INIT_LOCAL_LOCK(lockname) __LOCAL_SPIN_LOCK_UNLOCKED((lockname))
# define LOCAL_LOCK_DEBUG_INIT(lockname)		\
	.dep_map = {					\
		.name = #lockname,			\
		.wait_type_inner = LD_WAIT_CONFIG,	\
		.lock_type = LD_LOCK_PERCPU,		\
	},						\
	.owner = NULL,
#define __local_lock(__lock)					\
	do {							\
		migrate_disable();				\
		spin_lock(this_cpu_ptr((__lock)));		\
	} while (0)
#define __local_lock_init(l)					\
	do {							\
		local_spin_lock_init((l));			\
	} while (0)
#define __local_lock_irq(lock)			__local_lock(lock)
#define __local_lock_irqsave(lock, flags)			\
	do {							\
		typecheck(unsigned long, flags);		\
		flags = 0;					\
		__local_lock(lock);				\
	} while (0)
#define __local_unlock(__lock)					\
	do {							\
		spin_unlock(this_cpu_ptr((__lock)));		\
		migrate_enable();				\
	} while (0)
#define __local_unlock_irq(lock)		__local_unlock(lock)
#define __local_unlock_irqrestore(lock, flags)	__local_unlock(lock)
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
#define CLEARPAGEFLAG(uname, lname, policy)				\
static __always_inline							\
void folio_clear_##lname(struct folio *folio)				\
{ clear_bit(PG_##lname, folio_flags(folio, FOLIO_##policy)); }		\
static __always_inline void ClearPage##uname(struct page *page)		\
{ clear_bit(PG_##lname, &policy(page, 1)->flags); }
#define CLEARPAGEFLAG_NOOP(uname, lname)				\
static inline void folio_clear_##lname(struct folio *folio) { }		\
static inline void ClearPage##uname(struct page *page) {  }
#define PAGEFLAG(uname, lname, policy)					\
	TESTPAGEFLAG(uname, lname, policy)				\
	SETPAGEFLAG(uname, lname, policy)				\
	CLEARPAGEFLAG(uname, lname, policy)
#define PAGEFLAG_FALSE(uname, lname) TESTPAGEFLAG_FALSE(uname, lname)	\
	SETPAGEFLAG_NOOP(uname, lname) CLEARPAGEFLAG_NOOP(uname, lname)

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
#define PF_SECOND(page, enforce) ({					\
		VM_BUG_ON_PGFLAGS(!PageHead(page), page);		\
		PF_POISONED_CHECK(&page[1]); })
#define PG_head_mask ((1UL << PG_head))
#define PageHighMem(__p) is_highmem_idx(page_zonenum(__p))
#define PageType(page, flag)						\
	((page->page_type & (PAGE_TYPE_BASE | flag)) == PAGE_TYPE_BASE)
#define SETPAGEFLAG(uname, lname, policy)				\
static __always_inline							\
void folio_set_##lname(struct folio *folio)				\
{ set_bit(PG_##lname, folio_flags(folio, FOLIO_##policy)); }		\
static __always_inline void SetPage##uname(struct page *page)		\
{ set_bit(PG_##lname, &policy(page, 1)->flags); }
#define SETPAGEFLAG_NOOP(uname, lname)					\
static inline void folio_set_##lname(struct folio *folio) { }		\
static inline void SetPage##uname(struct page *page) {  }
#define TESTCLEARFLAG(uname, lname, policy)				\
static __always_inline							\
bool folio_test_clear_##lname(struct folio *folio)			\
{ return test_and_clear_bit(PG_##lname, folio_flags(folio, FOLIO_##policy)); } \
static __always_inline int TestClearPage##uname(struct page *page)	\
{ return test_and_clear_bit(PG_##lname, &policy(page, 1)->flags); }
#define TESTCLEARFLAG_FALSE(uname, lname)				\
static inline bool folio_test_clear_##lname(struct folio *folio)	\
{ return 0; }								\
static inline int TestClearPage##uname(struct page *page) { return 0; }
#define TESTPAGEFLAG(uname, lname, policy)				\
static __always_inline bool folio_test_##lname(struct folio *folio)	\
{ return test_bit(PG_##lname, folio_flags(folio, FOLIO_##policy)); }	\
static __always_inline int Page##uname(struct page *page)		\
{ return test_bit(PG_##lname, &policy(page, 0)->flags); }
#define TESTPAGEFLAG_FALSE(uname, lname)				\
static inline bool folio_test_##lname(const struct folio *folio) { return false; } \
static inline int Page##uname(const struct page *page) { return 0; }
#define TESTSCFLAG(uname, lname, policy)				\
	TESTSETFLAG(uname, lname, policy)				\
	TESTCLEARFLAG(uname, lname, policy)
#define TESTSCFLAG_FALSE(uname, lname)					\
	TESTSETFLAG_FALSE(uname, lname) TESTCLEARFLAG_FALSE(uname, lname)
#define TESTSETFLAG(uname, lname, policy)				\
static __always_inline							\
bool folio_test_set_##lname(struct folio *folio)			\
{ return test_and_set_bit(PG_##lname, folio_flags(folio, FOLIO_##policy)); } \
static __always_inline int TestSetPage##uname(struct page *page)	\
{ return test_and_set_bit(PG_##lname, &policy(page, 1)->flags); }
#define TESTSETFLAG_FALSE(uname, lname)					\
static inline bool folio_test_set_##lname(struct folio *folio)		\
{ return 0; }								\
static inline int TestSetPage##uname(struct page *page) { return 0; }
#define __CLEARPAGEFLAG(uname, lname, policy)				\
static __always_inline							\
void __folio_clear_##lname(struct folio *folio)				\
{ __clear_bit(PG_##lname, folio_flags(folio, FOLIO_##policy)); }	\
static __always_inline void __ClearPage##uname(struct page *page)	\
{ __clear_bit(PG_##lname, &policy(page, 1)->flags); }
#define __CLEARPAGEFLAG_NOOP(uname, lname)				\
static inline void __folio_clear_##lname(struct folio *folio) { }	\
static inline void __ClearPage##uname(struct page *page) {  }
#define __PAGEFLAG(uname, lname, policy)				\
	TESTPAGEFLAG(uname, lname, policy)				\
	__SETPAGEFLAG(uname, lname, policy)				\
	__CLEARPAGEFLAG(uname, lname, policy)
#define __PG_HWPOISON (1UL << PG_hwpoison)
#define __SETPAGEFLAG(uname, lname, policy)				\
static __always_inline							\
void __folio_set_##lname(struct folio *folio)				\
{ __set_bit(PG_##lname, folio_flags(folio, FOLIO_##policy)); }		\
static __always_inline void __SetPage##uname(struct page *page)		\
{ __set_bit(PG_##lname, &policy(page, 1)->flags); }
#define folio_page(folio, n)	nth_page(&(folio)->page, n)
#define folio_start_writeback(folio)			\
	__folio_start_writeback(folio, false)
#define folio_start_writeback_keepwrite(folio)	\
	__folio_start_writeback(folio, true)
#define page_folio(p)		(_Generic((p),				\
	const struct page *:	(const struct folio *)_compound_head(p), \
	struct page *:		(struct folio *)_compound_head(p)))
#define AT_VECTOR_SIZE (2*(AT_VECTOR_SIZE_ARCH + AT_VECTOR_SIZE_BASE + 1))
#define AT_VECTOR_SIZE_ARCH 0
#define FOLIO_MATCH(pg, fl)						\
	static_assert(offsetof(struct page, pg) == offsetof(struct folio, fl))
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
#define DEFINE_SEQLOCK(sl) \
		seqlock_t sl = __SEQLOCK_UNLOCKED(sl)
#define KCSAN_SEQLOCK_REGION_MAX 1000
#define SEQCNT_LATCH_ZERO(seq_name) {					\
	.seqcount		= SEQCNT_ZERO(seq_name.seqcount),	\
}
#define SEQCNT_MUTEX_ZERO(name, lock)		SEQCOUNT_LOCKNAME_ZERO(name, lock)
#define SEQCNT_RAW_SPINLOCK_ZERO(name, lock)	SEQCOUNT_LOCKNAME_ZERO(name, lock)
#define SEQCNT_RWLOCK_ZERO(name, lock)		SEQCOUNT_LOCKNAME_ZERO(name, lock)
#define SEQCNT_SPINLOCK_ZERO(name, lock)	SEQCOUNT_LOCKNAME_ZERO(name, lock)
#define SEQCNT_WW_MUTEX_ZERO(name, lock) 	SEQCOUNT_LOCKNAME_ZERO(name, lock)
#define SEQCNT_ZERO(name) { .sequence = 0, SEQCOUNT_DEP_MAP_INIT(name) }
# define SEQCOUNT_DEP_MAP_INIT(lockname)
#define SEQCOUNT_LOCKNAME(lockname, locktype, preemptible, lockmember, lockbase, lock_acquire) \
typedef struct seqcount_##lockname {					\
	seqcount_t		seqcount;				\
	__SEQ_LOCK(locktype	*lock);					\
} seqcount_##lockname##_t;						\
									\
static __always_inline seqcount_t *					\
__seqprop_##lockname##_ptr(seqcount_##lockname##_t *s)			\
{									\
	return &s->seqcount;						\
}									\
									\
static __always_inline unsigned						\
__seqprop_##lockname##_sequence(const seqcount_##lockname##_t *s)	\
{									\
	unsigned seq = READ_ONCE(s->seqcount.sequence);			\
									\
	if (!IS_ENABLED(CONFIG_PREEMPT_RT))				\
		return seq;						\
									\
	if (preemptible && unlikely(seq & 1)) {				\
		__SEQ_LOCK(lock_acquire);				\
		__SEQ_LOCK(lockbase##_unlock(s->lock));			\
									\
									\
		seq = READ_ONCE(s->seqcount.sequence);			\
	}								\
									\
	return seq;							\
}									\
									\
static __always_inline bool						\
__seqprop_##lockname##_preemptible(const seqcount_##lockname##_t *s)	\
{									\
	if (!IS_ENABLED(CONFIG_PREEMPT_RT))				\
		return preemptible;					\
									\
			\
	return false;							\
}									\
									\
static __always_inline void						\
__seqprop_##lockname##_assert(const seqcount_##lockname##_t *s)		\
{									\
	__SEQ_LOCK(lockdep_assert_held(lockmember));			\
}
#define SEQCOUNT_LOCKNAME_ZERO(seq_name, assoc_lock) {			\
	.seqcount		= SEQCNT_ZERO(seq_name.seqcount),	\
	__SEQ_LOCK(.lock	= (assoc_lock))				\
}

#define __SEQLOCK_UNLOCKED(lockname)					\
	{								\
		.seqcount = SEQCNT_SPINLOCK_ZERO(lockname, &(lockname).lock), \
		.lock =	__SPIN_LOCK_UNLOCKED(lockname)			\
	}
#define __SEQ_LOCK(expr)	expr
#define __read_seqcount_begin(s)					\
({									\
	unsigned __seq;							\
									\
	while ((__seq = seqprop_sequence(s)) & 1)			\
		cpu_relax();						\
									\
	kcsan_atomic_next(KCSAN_SEQLOCK_REGION_MAX);			\
	__seq;								\
})
#define __read_seqcount_retry(s, start)					\
	do___read_seqcount_retry(seqprop_ptr(s), start)
#define __seqprop(s, prop) _Generic(*(s),				\
	seqcount_t:		__seqprop_##prop((void *)(s)),		\
	__seqprop_case((s),	raw_spinlock,	prop),			\
	__seqprop_case((s),	spinlock,	prop),			\
	__seqprop_case((s),	rwlock,		prop),			\
	__seqprop_case((s),	mutex,		prop))
#define __seqprop_case(s, lockname, prop)				\
	seqcount_##lockname##_t: __seqprop_##lockname##_##prop((void *)(s))
#define raw_read_seqcount(s)						\
({									\
	unsigned __seq = seqprop_sequence(s);				\
									\
	smp_rmb();							\
	kcsan_atomic_next(KCSAN_SEQLOCK_REGION_MAX);			\
	__seq;								\
})
#define raw_read_seqcount_begin(s)					\
({									\
	unsigned _seq = __read_seqcount_begin(s);			\
									\
	smp_rmb();							\
	_seq;								\
})
#define raw_seqcount_begin(s)						\
({									\
									\
	raw_read_seqcount(s) & ~1;					\
})
#define raw_write_seqcount_barrier(s)					\
	do_raw_write_seqcount_barrier(seqprop_ptr(s))
#define raw_write_seqcount_begin(s)					\
do {									\
	if (seqprop_preemptible(s))					\
		preempt_disable();					\
									\
	do_raw_write_seqcount_begin(seqprop_ptr(s));			\
} while (0)
#define raw_write_seqcount_end(s)					\
do {									\
	do_raw_write_seqcount_end(seqprop_ptr(s));			\
									\
	if (seqprop_preemptible(s))					\
		preempt_enable();					\
} while (0)
#define read_seqcount_begin(s)						\
({									\
	seqcount_lockdep_reader_access(seqprop_ptr(s));			\
	raw_read_seqcount_begin(s);					\
})
#define read_seqcount_retry(s, start)					\
	do_read_seqcount_retry(seqprop_ptr(s), start)
#define read_seqlock_excl_irqsave(lock, flags)				\
	do { flags = __read_seqlock_excl_irqsave(lock); } while (0)
#define seqcount_LOCKNAME_init(s, _lock, lockname)			\
	do {								\
		seqcount_##lockname##_t *____s = (s);			\
		seqcount_init(&____s->seqcount);			\
		__SEQ_LOCK(____s->lock = (_lock));			\
	} while (0)
# define seqcount_init(s)						\
	do {								\
		static struct lock_class_key __key;			\
		__seqcount_init((s), #s, &__key);			\
	} while (0)
#define seqcount_latch_init(s) seqcount_init(&(s)->seqcount)
# define seqcount_lockdep_reader_access(x)
#define seqcount_mutex_init(s, lock)		seqcount_LOCKNAME_init(s, lock, mutex)
#define seqcount_raw_spinlock_init(s, lock)	seqcount_LOCKNAME_init(s, lock, raw_spinlock)
#define seqcount_rwlock_init(s, lock)		seqcount_LOCKNAME_init(s, lock, rwlock)
#define seqcount_spinlock_init(s, lock)		seqcount_LOCKNAME_init(s, lock, spinlock)
#define seqlock_init(sl)						\
	do {								\
		spin_lock_init(&(sl)->lock);				\
		seqcount_spinlock_init(&(sl)->seqcount, &(sl)->lock);	\
	} while (0)
#define seqprop_assert(s)		__seqprop(s, assert)
#define seqprop_preemptible(s)		__seqprop(s, preemptible)
#define seqprop_ptr(s)			__seqprop(s, ptr)
#define seqprop_sequence(s)		__seqprop(s, sequence)
#define write_seqcount_begin(s)						\
do {									\
	seqprop_assert(s);						\
									\
	if (seqprop_preemptible(s))					\
		preempt_disable();					\
									\
	do_write_seqcount_begin(seqprop_ptr(s));			\
} while (0)
#define write_seqcount_begin_nested(s, subclass)			\
do {									\
	seqprop_assert(s);						\
									\
	if (seqprop_preemptible(s))					\
		preempt_disable();					\
									\
	do_write_seqcount_begin_nested(seqprop_ptr(s), subclass);	\
} while (0)
#define write_seqcount_end(s)						\
do {									\
	do_write_seqcount_end(seqprop_ptr(s));				\
									\
	if (seqprop_preemptible(s))					\
		preempt_enable();					\
} while (0)
#define write_seqcount_invalidate(s)					\
	do_write_seqcount_invalidate(seqprop_ptr(s))
#define write_seqlock_irqsave(lock, flags)				\
	do { flags = __write_seqlock_irqsave(lock); } while (0)
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
#define rb_entry_safe(ptr, type, member) \
	({ typeof(ptr) ____ptr = (ptr); \
	   ____ptr ? rb_entry(____ptr, type, member) : NULL; \
	})
#define rb_first_cached(root) (root)->rb_leftmost
#define rb_for_each(node, key, tree, cmp) \
	for ((node) = rb_find_first((key), (tree), (cmp)); \
	     (node); (node) = rb_next_match((key), (node), (cmp)))
#define rb_parent(r)   ((struct rb_node *)((r)->__rb_parent_color & ~3))
#define rbtree_postorder_for_each_entry_safe(pos, n, root, field) \
	for (pos = rb_entry_safe(rb_first_postorder(root), typeof(*pos), field); \
	     pos && ({ n = rb_entry_safe(rb_next_postorder(&pos->field), \
			typeof(*pos), field); 1; }); \
	     pos = n)
#define KREF_INIT(n)	{ .refcount = REFCOUNT_INIT(n), }

#define REFCOUNT_INIT(n)	{ .refs = ATOMIC_INIT(n), }

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
	set_pfnblock_flags_mask(page, 0, page_to_pfn(page),	\
			(1 << PB_migrate_skip))
#define get_pageblock_skip(page) \
	get_pfnblock_flags_mask(page, page_to_pfn(page),	\
			(1 << (PB_migrate_skip)))
#define set_pageblock_skip(page) \
	set_pfnblock_flags_mask(page, (1 << PB_migrate_skip),	\
			page_to_pfn(page),			\
			(1 << PB_migrate_skip))
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
#define for_each_node_mask(node, mask)				    \
	for ((node) = first_node(mask);				    \
	     (node >= 0) && (node) < MAX_NUMNODES;		    \
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

#define topology_llc_cpumask(cpu)	(&cpu_topology[cpu].llc_sibling)
#define APR_MODULE_PREFIX "apr:"
#define AUXILIARY_MODULE_PREFIX "auxiliary:"
#define AUXILIARY_NAME_SIZE 32
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
#define MHI_EP_DEVICE_MODALIAS_FMT "mhi_ep:%s"
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
#define UUID_INIT(a, b, c, d0, d1, d2, d3, d4, d5, d6, d7)			\
((uuid_t)								\
{{ ((a) >> 24) & 0xff, ((a) >> 16) & 0xff, ((a) >> 8) & 0xff, (a) & 0xff, \
   ((b) >> 8) & 0xff, (b) & 0xff,					\
   ((c) >> 8) & 0xff, (c) & 0xff,					\
   (d0), (d1), (d2), (d3), (d4), (d5), (d6), (d7) }})
#define UUID_SIZE 16

#define GUID_INIT(a, b, c, d0, d1, d2, d3, d4, d5, d6, d7)			\
((guid_t)								\
{{ (a) & 0xff, ((a) >> 8) & 0xff, ((a) >> 16) & 0xff, ((a) >> 24) & 0xff, \
   (b) & 0xff, ((b) >> 8) & 0xff,					\
   (c) & 0xff, ((c) >> 8) & 0xff,					\
   (d0), (d1), (d2), (d3), (d4), (d5), (d6), (d7) }})
#define UUID_LE(a, b, c, d0, d1, d2, d3, d4, d5, d6, d7)		\
	GUID_INIT(a, b, c, d0, d1, d2, d3, d4, d5, d6, d7)


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
#define BIN_ATTRIBUTE_GROUPS(_name)				\
static const struct attribute_group _name##_group = {		\
	.bin_attrs = _name##_attrs,				\
};								\
__ATTRIBUTE_GROUPS(_name)
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
#define __ATTR_RW_MODE(_name, _mode) {					\
	.attr	= { .name = __stringify(_name),				\
		    .mode = VERIFY_OCTAL_PERMISSIONS(_mode) },		\
	.show	= _name##_show,						\
	.store	= _name##_store,					\
}
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
#define __GFP_BITS_SHIFT (27 + IS_ENABLED(CONFIG_LOCKDEP))
#define __GFP_HARDWALL   ((__force gfp_t)___GFP_HARDWALL)
#define __GFP_NOLOCKDEP ((__force gfp_t)___GFP_NOLOCKDEP)
#define __GFP_NOMEMALLOC ((__force gfp_t)___GFP_NOMEMALLOC)
#define __GFP_RECLAIM ((__force gfp_t)(___GFP_DIRECT_RECLAIM|___GFP_KSWAPD_RECLAIM))
#define __GFP_RECLAIMABLE ((__force gfp_t)___GFP_RECLAIMABLE)
#define __GFP_SKIP_KASAN_POISON   ((__force gfp_t)___GFP_SKIP_KASAN_POISON)
#define __GFP_SKIP_KASAN_UNPOISON ((__force gfp_t)___GFP_SKIP_KASAN_UNPOISON)
#define __GFP_SKIP_ZERO ((__force gfp_t)___GFP_SKIP_ZERO)

#define __free_page(page) __free_pages((page), 0)
#define __get_dma_pages(gfp_mask, order) \
		__get_free_pages((gfp_mask) | GFP_DMA, (order))
#define __get_free_page(gfp_mask) \
		__get_free_pages((gfp_mask), 0)
#define alloc_page(gfp_mask) alloc_pages(gfp_mask, 0)
#define free_page(addr) free_pages((addr), 0)
#define vma_alloc_folio(gfp, order, vma, addr, hugepage)		\
	folio_alloc(gfp, order)
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
	.xa_update = NULL,				\
	.xa_lru = NULL,					\
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
#define DEFINE_XEN_MC_BATCH(name)			\
	DEFINE_EVENT(xen_mc__batch, name,		\
		TP_PROTO(enum paravirt_lazy_mode mode),	\
		     TP_ARGS(mode))
#define DEFINE_XEN_MMU_PGD_EVENT(name)				\
	DEFINE_EVENT(xen_mmu_pgd, name,				\
		TP_PROTO(struct mm_struct *mm, pgd_t *pgd),	\
		     TP_ARGS(mm, pgd))
#define DEFINE_XEN_MMU_PTEP_MODIFY_PROT(name)				\
	DEFINE_EVENT(xen_mmu_ptep_modify_prot, name,			\
		     TP_PROTO(struct mm_struct *mm, unsigned long addr,	\
			      pte_t *ptep, pte_t pteval),		\
		     TP_ARGS(mm, addr, ptep, pteval))
#define DEFINE_XEN_MMU_SET_PTE(name)				\
	DEFINE_EVENT(xen_mmu__set_pte, name,			\
		     TP_PROTO(pte_t *ptep, pte_t pteval),	\
		     TP_ARGS(ptep, pteval))
#define TRACE_SYSTEM xen


#define DECLARE_TRACE(name, proto, args)	\
	DEFINE_TRACE(name, PARAMS(proto), PARAMS(args))
#define DEFINE_EVENT(template, name, proto, args) \
	DEFINE_TRACE(name, PARAMS(proto), PARAMS(args))
#define DEFINE_EVENT_CONDITION(template, name, proto, args, cond) \
	DEFINE_EVENT(template, name, PARAMS(proto), PARAMS(args))
#define DEFINE_EVENT_FN(template, name, proto, args, reg, unreg) \
	DEFINE_TRACE_FN(name, reg, unreg, PARAMS(proto), PARAMS(args))
#define DEFINE_EVENT_NOP(template, name, proto, args)
#define DEFINE_EVENT_PRINT(template, name, proto, args, print)	\
	DEFINE_TRACE(name, PARAMS(proto), PARAMS(args))
#define TRACE_EVENT(name, proto, args, tstruct, assign, print)	\
	DEFINE_TRACE(name, PARAMS(proto), PARAMS(args))
#define TRACE_EVENT_CONDITION(name, proto, args, cond, tstruct, assign, print) \
	TRACE_EVENT(name,						\
		PARAMS(proto),						\
		PARAMS(args),						\
		PARAMS(tstruct),					\
		PARAMS(assign),						\
		PARAMS(print))
#define TRACE_EVENT_FN(name, proto, args, tstruct,		\
		assign, print, reg, unreg)			\
	DEFINE_TRACE_FN(name, reg, unreg, PARAMS(proto), PARAMS(args))
#define TRACE_EVENT_FN_COND(name, proto, args, cond, tstruct,		\
		assign, print, reg, unreg)			\
	DEFINE_TRACE_FN(name, reg, unreg, PARAMS(proto), PARAMS(args))
#define TRACE_EVENT_NOP(name, proto, args, struct, assign, print)

# define TRACE_INCLUDE(system) __TRACE_INCLUDE(system)
# define TRACE_INCLUDE_FILE TRACE_SYSTEM
# define UNDEF_TRACE_INCLUDE_FILE
# define UNDEF_TRACE_INCLUDE_PATH
# define __TRACE_INCLUDE(system) <trace/events/system.h>
#define CAST_TO_U64(...) CONCATENATE(__CAST, COUNT_ARGS(__VA_ARGS__))(__VA_ARGS__)
#define DECLARE_EVENT_CLASS(call, proto, args, tstruct, assign, print)	\
	__BPF_DECLARE_TRACE(call, PARAMS(proto), PARAMS(args))
#define DECLARE_TRACE_WRITABLE(call, proto, args, size) \
	__CHECK_WRITABLE_BUF_SIZE(call, PARAMS(proto), PARAMS(args), size) \
	__BPF_DECLARE_TRACE(call, PARAMS(proto), PARAMS(args)) \
	__DEFINE_EVENT(call, call, PARAMS(proto), PARAMS(args), size)
#define DEFINE_EVENT_WRITABLE(template, call, proto, args, size) \
	__CHECK_WRITABLE_BUF_SIZE(call, PARAMS(proto), PARAMS(args), size) \
	__DEFINE_EVENT(template, call, PARAMS(proto), PARAMS(args), size)
#define FIRST(x, ...) x
#define UINTTYPE(size) \
	__typeof__(__builtin_choose_expr(size == 1,  (u8)1, \
		   __builtin_choose_expr(size == 2, (u16)2, \
		   __builtin_choose_expr(size == 4, (u32)3, \
		   __builtin_choose_expr(size == 8, (u64)4, \
					 (void)5)))))
#define __BPF_DECLARE_TRACE(call, proto, args)				\
static notrace void							\
__bpf_trace_##call(void *__data, proto)					\
{									\
	struct bpf_prog *prog = __data;					\
	CONCATENATE(bpf_trace_run, COUNT_ARGS(args))(prog, CAST_TO_U64(args));	\
}
#define __CAST1(a,...) __CAST_TO_U64(a)
#define __CAST10(a,...) __CAST_TO_U64(a), __CAST9(__VA_ARGS__)
#define __CAST11(a,...) __CAST_TO_U64(a), __CAST10(__VA_ARGS__)
#define __CAST12(a,...) __CAST_TO_U64(a), __CAST11(__VA_ARGS__)
#define __CAST2(a,...) __CAST_TO_U64(a), __CAST1(__VA_ARGS__)
#define __CAST3(a,...) __CAST_TO_U64(a), __CAST2(__VA_ARGS__)
#define __CAST4(a,...) __CAST_TO_U64(a), __CAST3(__VA_ARGS__)
#define __CAST5(a,...) __CAST_TO_U64(a), __CAST4(__VA_ARGS__)
#define __CAST6(a,...) __CAST_TO_U64(a), __CAST5(__VA_ARGS__)
#define __CAST7(a,...) __CAST_TO_U64(a), __CAST6(__VA_ARGS__)
#define __CAST8(a,...) __CAST_TO_U64(a), __CAST7(__VA_ARGS__)
#define __CAST9(a,...) __CAST_TO_U64(a), __CAST8(__VA_ARGS__)
#define __CAST_TO_U64(x) ({ \
	typeof(x) __src = (x); \
	UINTTYPE(sizeof(x)) __dst; \
	memcpy(&__dst, &__src, sizeof(__dst)); \
	(u64)__dst; })
#define __CHECK_WRITABLE_BUF_SIZE(call, proto, args, size)		\
static inline void bpf_test_buffer_##call(void)				\
{									\
									\
	FIRST(proto);							\
	(void)BUILD_BUG_ON_ZERO(size != sizeof(*FIRST(args)));		\
}
#define __DEFINE_EVENT(template, call, proto, args, size)		\
static inline void bpf_test_probe_##call(void)				\
{									\
	check_trace_callback_type_##call(__bpf_trace_##template);	\
}									\
typedef void (*btf_trace_##call)(void *__data, proto);			\
static union {								\
	struct bpf_raw_event_map event;					\
	btf_trace_##call handler;					\
} __bpf_trace_tp_map_##call __used					\
__section("__bpf_raw_tp_map") = {					\
	.event = {							\
		.tp		= &__tracepoint_##call,			\
		.bpf_func	= __bpf_trace_##template,		\
		.num_args	= COUNT_ARGS(args),			\
		.writable_size	= size,					\
	},								\
};
#define __entry entry
#define __get_bitmask(field) (char *)__get_dynamic_array(field)
#define __get_dynamic_array(field)	\
		((void *)__entry + (__entry->__data_loc_##field & 0xffff))
#define __get_dynamic_array_len(field)	\
		((__entry->__data_loc_##field >> 16) & 0xffff)
#define __get_rel_bitmask(field) (char *)__get_rel_dynamic_array(field)
#define __get_rel_dynamic_array(field)	\
		((void *)(&__entry->__rel_loc_##field) +	\
		 sizeof(__entry->__rel_loc_##field) +		\
		 (__entry->__rel_loc_##field & 0xffff))
#define __get_rel_dynamic_array_len(field)	\
		((__entry->__rel_loc_##field >> 16) & 0xffff)
#define __get_rel_sockaddr(field) ((struct sockaddr *)__get_rel_dynamic_array(field))
#define __get_rel_str(field) ((char *)__get_rel_dynamic_array(field))
#define __get_sockaddr(field) ((struct sockaddr *)__get_dynamic_array(field))
#define __get_str(field) ((char *)__get_dynamic_array(field))
#define __perf_count(c)	(c)
#define __perf_task(t)	(t)
#define TRACE_EVENT_FLAGS(event, flag)
#define TRACE_EVENT_PERF_PERM(event, expr...)
#define TRACE_SYSTEM_VAR TRACE_SYSTEM
#define _TRACE_PERF_INIT(call)						\
	.perf_probe		= perf_trace_##call,
#define _TRACE_PERF_PROTO(call, proto)					\
	static notrace void						\
	perf_trace_##call(void *__data, proto);
#define DECLARE_CUSTOM_EVENT_CLASS(name, proto, args, tstruct, assign, print)
#define DEFINE_CUSTOM_EVENT(template, name, proto, args)
#define TRACE_CUSTOM_EVENT(name, proto, args, struct, assign, print)
#define TRACE_EVENT_FL_UKPROBE (TRACE_EVENT_FL_KPROBE | TRACE_EVENT_FL_UPROBE)
#define TRACE_FUNCTION_TYPE ((const char *)~0UL)

#define __TRACE_EVENT_FLAGS(name, value)				\
	static int __init trace_init_flags_##name(void)			\
	{								\
		event_##name.flags |= value;				\
		return 0;						\
	}								\
	early_initcall(trace_init_flags_##name);
#define __TRACE_EVENT_PERF_PERM(name, expr...)				\
	static int perf_perm_##name(struct trace_event_call *tp_event, \
				    struct perf_event *p_event)		\
	{								\
		return ({ expr; });					\
	}								\
	static int __init trace_init_perf_perm_##name(void)		\
	{								\
		event_##name.perf_perm = &perf_perm_##name;		\
		return 0;						\
	}								\
	early_initcall(trace_init_perf_perm_##name);
#define event_trace_printk(ip, fmt, args...)				\
do {									\
	__trace_printk_check_format(fmt, ##args);			\
	tracing_record_cmdline(current);				\
	if (__builtin_constant_p(fmt)) {				\
		static const char *trace_printk_fmt			\
		  __section("__trace_printk_fmt") =			\
			__builtin_constant_p(fmt) ? fmt : NULL;		\
									\
		__trace_bprintk(ip, trace_printk_fmt, ##args);		\
	} else								\
		__trace_printk(ip, fmt, ##args);			\
} while (0)
#define is_signed_type(type)	(((type)(-1)) < (type)1)
#define kprobe_event_add_field(cmd, field)	\
	__kprobe_event_add_fields(cmd, field, NULL)
#define kprobe_event_add_fields(cmd, ...)	\
	__kprobe_event_add_fields(cmd, ## __VA_ARGS__, NULL)
#define kprobe_event_gen_cmd_end(cmd)		\
	dynevent_create(cmd)
#define kprobe_event_gen_cmd_start(cmd, name, loc, ...)			\
	__kprobe_event_gen_cmd_start(cmd, false, name, loc, ## __VA_ARGS__, NULL)
#define kretprobe_event_gen_cmd_end(cmd)	\
	dynevent_create(cmd)
#define kretprobe_event_gen_cmd_start(cmd, name, loc, ...)		\
	__kprobe_event_gen_cmd_start(cmd, true, name, loc, ## __VA_ARGS__, NULL)
#define synth_event_gen_cmd_end(cmd)	\
	dynevent_create(cmd)
#define synth_event_gen_cmd_start(cmd, name, mod, ...)	\
	__synth_event_gen_cmd_start(cmd, name, mod, ## __VA_ARGS__, NULL)
#define DECLARE_EVENT_CLASS_NOP(name, proto, args, tstruct, assign, print)
#define DECLARE_EVENT_NOP(name, proto, args)				\
	static inline void trace_##name(proto)				\
	{ }								\
	static inline bool trace_##name##_enabled(void)			\
	{								\
		return false;						\
	}
#define DECLARE_TRACE_CONDITION(name, proto, args, cond)		\
	__DECLARE_TRACE(name, PARAMS(proto), PARAMS(args),		\
			cpu_online(raw_smp_processor_id()) && (PARAMS(cond)), \
			PARAMS(void *__data, proto))
#define DEFINE_TRACE(name, proto, args)		\
	DEFINE_TRACE_FN(name, NULL, NULL, PARAMS(proto), PARAMS(args));
#define DEFINE_TRACE_FN(_name, _reg, _unreg, proto, args)		\
	static const char __tpstrtab_##_name[]				\
	__section("__tracepoints_strings") = #_name;			\
	extern struct static_call_key STATIC_CALL_KEY(tp_func_##_name);	\
	int __traceiter_##_name(void *__data, proto);			\
	struct tracepoint __tracepoint_##_name	__used			\
	__section("__tracepoints") = {					\
		.name = __tpstrtab_##_name,				\
		.key = STATIC_KEY_INIT_FALSE,				\
		.static_call_key = &STATIC_CALL_KEY(tp_func_##_name),	\
		.static_call_tramp = STATIC_CALL_TRAMP_ADDR(tp_func_##_name), \
		.iterator = &__traceiter_##_name,			\
		.regfunc = _reg,					\
		.unregfunc = _unreg,					\
		.funcs = NULL };					\
	__TRACEPOINT_ENTRY(_name);					\
	int __traceiter_##_name(void *__data, proto)			\
	{								\
		struct tracepoint_func *it_func_ptr;			\
		void *it_func;						\
									\
		it_func_ptr =						\
			rcu_dereference_raw((&__tracepoint_##_name)->funcs); \
		if (it_func_ptr) {					\
			do {						\
				it_func = READ_ONCE((it_func_ptr)->func); \
				__data = (it_func_ptr)->data;		\
				((void(*)(void *, proto))(it_func))(__data, args); \
			} while ((++it_func_ptr)->func);		\
		}							\
		return 0;						\
	}								\
	DEFINE_STATIC_CALL(tp_func_##_name, __traceiter_##_name);
#define EXPORT_TRACEPOINT_SYMBOL(name)					\
	EXPORT_SYMBOL(__tracepoint_##name);				\
	EXPORT_SYMBOL(__traceiter_##name);				\
	EXPORT_STATIC_CALL(tp_func_##name)
#define EXPORT_TRACEPOINT_SYMBOL_GPL(name)				\
	EXPORT_SYMBOL_GPL(__tracepoint_##name);				\
	EXPORT_SYMBOL_GPL(__traceiter_##name);				\
	EXPORT_STATIC_CALL_GPL(tp_func_##name)
#define PARAMS(args...) args
#define TP_ARGS(args...)	args
#define TP_CONDITION(args...)	args
#define TP_PROTO(args...)	args




#define __DECLARE_TRACE(name, proto, args, cond, data_proto)		\
	extern int __traceiter_##name(data_proto);			\
	DECLARE_STATIC_CALL(tp_func_##name, __traceiter_##name);	\
	extern struct tracepoint __tracepoint_##name;			\
	static inline void trace_##name(proto)				\
	{								\
		if (static_key_false(&__tracepoint_##name.key))		\
			__DO_TRACE(name,				\
				TP_ARGS(args),				\
				TP_CONDITION(cond), 0);			\
		if (IS_ENABLED(CONFIG_LOCKDEP) && (cond)) {		\
			rcu_read_lock_sched_notrace();			\
			rcu_dereference_sched(__tracepoint_##name.funcs);\
			rcu_read_unlock_sched_notrace();		\
		}							\
	}								\
	__DECLARE_TRACE_RCU(name, PARAMS(proto), PARAMS(args),		\
			    PARAMS(cond))				\
	static inline int						\
	register_trace_##name(void (*probe)(data_proto), void *data)	\
	{								\
		return tracepoint_probe_register(&__tracepoint_##name,	\
						(void *)probe, data);	\
	}								\
	static inline int						\
	register_trace_prio_##name(void (*probe)(data_proto), void *data,\
				   int prio)				\
	{								\
		return tracepoint_probe_register_prio(&__tracepoint_##name, \
					      (void *)probe, data, prio); \
	}								\
	static inline int						\
	unregister_trace_##name(void (*probe)(data_proto), void *data)	\
	{								\
		return tracepoint_probe_unregister(&__tracepoint_##name,\
						(void *)probe, data);	\
	}								\
	static inline void						\
	check_trace_callback_type_##name(void (*cb)(data_proto))	\
	{								\
	}								\
	static inline bool						\
	trace_##name##_enabled(void)					\
	{								\
		return static_key_false(&__tracepoint_##name.key);	\
	}
#define __DECLARE_TRACE_RCU(name, proto, args, cond)			\
	static inline void trace_##name##_rcuidle(proto)		\
	{								\
		if (static_key_false(&__tracepoint_##name.key))		\
			__DO_TRACE(name,				\
				TP_ARGS(args),				\
				TP_CONDITION(cond), 1);			\
	}
#define __DO_TRACE(name, args, cond, rcuidle)				\
	do {								\
		int __maybe_unused __idx = 0;				\
									\
		if (!(cond))						\
			return;						\
									\
					\
		WARN_ON_ONCE(rcuidle && in_nmi());			\
									\
				\
		preempt_disable_notrace();				\
									\
									\
		if (rcuidle) {						\
			__idx = srcu_read_lock_notrace(&tracepoint_srcu);\
			rcu_irq_enter_irqson();				\
		}							\
									\
		__DO_TRACE_CALL(name, TP_ARGS(args));			\
									\
		if (rcuidle) {						\
			rcu_irq_exit_irqson();				\
			srcu_read_unlock_notrace(&tracepoint_srcu, __idx);\
		}							\
									\
		preempt_enable_notrace();				\
	} while (0)
#define __DO_TRACE_CALL(name, args)					\
	do {								\
		struct tracepoint_func *it_func_ptr;			\
		void *__data;						\
		it_func_ptr =						\
			rcu_dereference_raw((&__tracepoint_##name)->funcs); \
		if (it_func_ptr) {					\
			__data = (it_func_ptr)->data;			\
			static_call(tp_func_##name)(__data, args);	\
		}							\
	} while (0)
#define __TRACEPOINT_ENTRY(name)					\
	asm("	.section \"__tracepoints_ptrs\", \"a\"		\n"	\
	    "	.balign 4					\n"	\
	    "	.long 	__tracepoint_" #name " - .		\n"	\
	    "	.previous					\n")
# define __tracepoint_string
# define tracepoint_string(str) str
#define DEFINE_STATIC_CALL(name, _func)					\
	DECLARE_STATIC_CALL(name, _func);				\
	struct static_call_key STATIC_CALL_KEY(name) = {		\
		.func = _func,						\
		.type = 1,						\
	};								\
	ARCH_DEFINE_STATIC_CALL_TRAMP(name, _func)
#define DEFINE_STATIC_CALL_NULL(name, _func)				\
	DECLARE_STATIC_CALL(name, _func);				\
	struct static_call_key STATIC_CALL_KEY(name) = {		\
		.func = NULL,						\
		.type = 1,						\
	};								\
	ARCH_DEFINE_STATIC_CALL_NULL_TRAMP(name)
#define DEFINE_STATIC_CALL_RET0(name, _func)				\
	DECLARE_STATIC_CALL(name, _func);				\
	struct static_call_key STATIC_CALL_KEY(name) = {		\
		.func = __static_call_return0,				\
		.type = 1,						\
	};								\
	ARCH_DEFINE_STATIC_CALL_RET0_TRAMP(name)
#define EXPORT_STATIC_CALL(name)					\
	EXPORT_SYMBOL(STATIC_CALL_KEY(name));				\
	EXPORT_SYMBOL(STATIC_CALL_TRAMP(name))
#define EXPORT_STATIC_CALL_GPL(name)					\
	EXPORT_SYMBOL_GPL(STATIC_CALL_KEY(name));			\
	EXPORT_SYMBOL_GPL(STATIC_CALL_TRAMP(name))
#define EXPORT_STATIC_CALL_TRAMP(name)					\
	EXPORT_SYMBOL(STATIC_CALL_TRAMP(name));				\
	ARCH_ADD_TRAMP_KEY(name)
#define EXPORT_STATIC_CALL_TRAMP_GPL(name)				\
	EXPORT_SYMBOL_GPL(STATIC_CALL_TRAMP(name));			\
	ARCH_ADD_TRAMP_KEY(name)
#define STATIC_CALL_TRAMP_ADDR(name) &STATIC_CALL_TRAMP(name)

#define __DEFINE_STATIC_CALL(name, _func, _func_init)			\
	DECLARE_STATIC_CALL(name, _func);				\
	struct static_call_key STATIC_CALL_KEY(name) = {		\
		.func = _func_init,					\
	}
#define __static_call_cond(name)					\
({									\
	void *func = READ_ONCE(STATIC_CALL_KEY(name).func);		\
	if (!func)							\
		func = &__static_call_nop;				\
	(typeof(STATIC_CALL_TRAMP(name))*)func;				\
})
#define static_call_cond(name)	(void)__static_call(name)
#define static_call_query(name) (READ_ONCE(STATIC_CALL_KEY(name).func))
#define static_call_update(name, func)					\
({									\
	typeof(&STATIC_CALL_TRAMP(name)) __F = (func);			\
	__static_call_update(&STATIC_CALL_KEY(name),			\
			     STATIC_CALL_TRAMP_ADDR(name), __F);	\
})



#define to_node(device) container_of(device, struct node, dev)
#define DEVICE_ATTR(_name, _mode, _show, _store) \
	struct device_attribute dev_attr_##_name = __ATTR(_name, _mode, _show, _store)
#define DEVICE_ATTR_ADMIN_RO(_name) \
	struct device_attribute dev_attr_##_name = __ATTR_RO_MODE(_name, 0400)
#define DEVICE_ATTR_ADMIN_RW(_name) \
	struct device_attribute dev_attr_##_name = __ATTR_RW_MODE(_name, 0600)
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

#define __device_lock_set_class(dev, name, key)                        \
do {                                                                   \
	struct device *__d2 __maybe_unused = dev;                      \
	lock_set_class(&__d2->mutex.dep_map, name, key, 0, _THIS_IP_); \
} while (0)
#define device_lock_reset_class(dev) \
do { \
	struct device *__d __maybe_unused = dev;                       \
	lock_set_novalidate_class(&__d->mutex.dep_map, "&dev->mutex",  \
				  _THIS_IP_);                          \
} while (0)
#define device_lock_set_class(dev, key)                                    \
do {                                                                       \
	struct device *__d = dev;                                          \
	dev_WARN_ONCE(__d, !lockdep_match_class(&__d->mutex,               \
						&__lockdep_no_validate__), \
		 "overriding existing custom lock class\n");               \
	__device_lock_set_class(__d, #key, key);                           \
} while (0)
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
#define MODULE_ALIAS(_alias) MODULE_INFO(alias, _alias)
#define MODULE_ARCH_INIT {}
#define MODULE_AUTHOR(_author) MODULE_INFO(author, _author)
#define MODULE_DESCRIPTION(_description) MODULE_INFO(description, _description)
#define MODULE_DEVICE_TABLE(type, name)					\
extern typeof(name) __mod_##type##__##name##_device_table		\
  __attribute__ ((unused, alias(__stringify(name))))

#define MODULE_FIRMWARE(_firmware) MODULE_INFO(firmware, _firmware)
#define MODULE_IMPORT_NS(ns)	MODULE_INFO(import_ns, __stringify(ns))
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
	int init_module(void) __copy(initfn)			\
		__attribute__((alias(#initfn)));		\
	__CFI_ADDRESSABLE(init_module, __initdata);
#define module_name(mod)			\
({						\
	struct module *__mod = (mod);		\
	__mod ? __mod->name : "kernel";		\
})
#define module_put_and_kthread_exit(code) kthread_exit(code)
#define postcore_initcall(fn)		module_init(fn)
#define postcore_initcall_sync(fn)	module_init(fn)
#define rootfs_initcall(fn)		module_init(fn)
#define subsys_initcall(fn)		module_init(fn)
#define subsys_initcall_sync(fn)	module_init(fn)
#define symbol_get(x) ({ extern typeof(x) x __attribute__((weak,visibility("hidden"))); &(x); })
#define symbol_put(x) do { } while (0)
#define symbol_put_addr(p) do { } while (0)
#define symbol_request(x) try_then_request_module(symbol_get(x), "symbol:" #x)

#define __CFI_ADDRESSABLE(fn, __attr) \
	const void *__cfi_jt_ ## fn __visible __attr = (void *)&fn
#define DECLARE_TRACEPOINT(tp) \
	extern struct tracepoint __tracepoint_##tp
#define TRACEPOINT_DEFS_H 1
# define tracepoint_enabled(tp) \
	static_key_false(&(__tracepoint_##tp).key)

#define ALLOW_ERROR_INJECTION(fname, _etype)				\
static struct error_injection_entry __used				\
	__section("_error_injection_whitelist")				\
	_eil_addr_##fname = {						\
		.addr = (unsigned long)fname,				\
		.etype = EI_ETYPE_##_etype,				\
	}


#define MAX_PARAM_PREFIX_LEN (64 - sizeof(unsigned long))
#define MODULE_PARAM_PREFIX 
#define MODULE_PARM_DESC(_parm, desc) \
	__MODULE_INFO(parm, _parm, #_parm ":" desc)

#define __MODULE_INFO(tag, name, info)					  \
	static const char __UNIQUE_ID(name)[]				  \
		__used __section(".modinfo") __aligned(1)		  \
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
	__used __section("__param")					\
	__aligned(__alignof__(struct kernel_param))			\
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
#define param_check_hexint(name, p) param_check_uint(name, p)
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
#define ARCH_SETUP_ADDITIONAL_PAGES(bprm, ex, interpreter) \
	arch_setup_additional_pages(bprm, interpreter)
#define SET_PERSONALITY(ex) \
	set_personality(PER_LINUX | (current->personality & (~PER_MASK)))
#define SET_PERSONALITY2(ex, state) \
	SET_PERSONALITY(ex)
#define START_THREAD(elf_ex, regs, elf_entry, start_stack)	\
	start_thread(regs, elf_entry, start_stack)

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
#define ELF_ST_TYPE(x)		((x) & 0xf)
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
#define DECLARE_SYSCTL_BASE(_name, _table)				\
static struct ctl_table _name##_base_table[] = {			\
	{								\
		.procname	= #_name,				\
		.mode		= 0555,					\
		.child		= _table,				\
	},								\
	{ },								\
}
#define DEFINE_CTL_TABLE_POLL(name)					\
	struct ctl_table_poll name = __CTL_TABLE_POLL_INITIALIZER(name)

#define __CTL_TABLE_POLL_INITIALIZER(name) {				\
	.event = ATOMIC_INIT(0),					\
	.wait = __WAIT_QUEUE_HEAD_INITIALIZER(name.wait) }
#define register_sysctl_base(_name) __register_sysctl_base(_name##_base_table)
#define register_sysctl_init(path, table) __register_sysctl_init(path, table, #table)
#define CTL_MAXNAME 10		


#define BUILD_ID_SIZE_MAX 20

#define BUS_ATTR_RO(_name) \
	struct bus_attribute bus_attr_##_name = __ATTR_RO(_name)
#define BUS_ATTR_RW(_name) \
	struct bus_attribute bus_attr_##_name = __ATTR_RW(_name)
#define BUS_ATTR_WO(_name) \
	struct bus_attribute bus_attr_##_name = __ATTR_WO(_name)

#define DEFINE_SIMPLE_DEV_PM_OPS(name, suspend_fn, resume_fn) \
	_DEFINE_DEV_PM_OPS(name, suspend_fn, resume_fn, NULL, NULL, NULL)
#define EXPORT_GPL_SIMPLE_DEV_PM_OPS(name, suspend_fn, resume_fn) \
	_EXPORT_DEV_PM_OPS(name, suspend_fn, resume_fn, NULL, NULL, NULL, "_gpl", "")
#define EXPORT_NS_GPL_SIMPLE_DEV_PM_OPS(name, suspend_fn, resume_fn, ns)	\
	_EXPORT_DEV_PM_OPS(name, suspend_fn, resume_fn, NULL, NULL, NULL, "_gpl", #ns)
#define EXPORT_NS_SIMPLE_DEV_PM_OPS(name, suspend_fn, resume_fn, ns)	\
	_EXPORT_DEV_PM_OPS(name, suspend_fn, resume_fn, NULL, NULL, NULL, "", #ns)
#define EXPORT_SIMPLE_DEV_PM_OPS(name, suspend_fn, resume_fn) \
	_EXPORT_DEV_PM_OPS(name, suspend_fn, resume_fn, NULL, NULL, NULL, "", "")
#define LATE_SYSTEM_SLEEP_PM_OPS(suspend_fn, resume_fn) \
	.suspend_late = pm_sleep_ptr(suspend_fn), \
	.resume_early = pm_sleep_ptr(resume_fn), \
	.freeze_late = pm_sleep_ptr(suspend_fn), \
	.thaw_early = pm_sleep_ptr(resume_fn), \
	.poweroff_late = pm_sleep_ptr(suspend_fn), \
	.restore_early = pm_sleep_ptr(resume_fn),
#define NOIRQ_SYSTEM_SLEEP_PM_OPS(suspend_fn, resume_fn) \
	.suspend_noirq = pm_sleep_ptr(suspend_fn), \
	.resume_noirq = pm_sleep_ptr(resume_fn), \
	.freeze_noirq = pm_sleep_ptr(suspend_fn), \
	.thaw_noirq = pm_sleep_ptr(resume_fn), \
	.poweroff_noirq = pm_sleep_ptr(suspend_fn), \
	.restore_noirq = pm_sleep_ptr(resume_fn),
#define PMSG_IS_AUTO(msg)	(((msg).event & PM_EVENT_AUTO) != 0)
#define PM_EVENT_PRETHAW PM_EVENT_QUIESCE
#define RUNTIME_PM_OPS(suspend_fn, resume_fn, idle_fn) \
	.runtime_suspend = suspend_fn, \
	.runtime_resume = resume_fn, \
	.runtime_idle = idle_fn,
#define SET_LATE_SYSTEM_SLEEP_PM_OPS(suspend_fn, resume_fn) \
	LATE_SYSTEM_SLEEP_PM_OPS(suspend_fn, resume_fn)
#define SET_NOIRQ_SYSTEM_SLEEP_PM_OPS(suspend_fn, resume_fn) \
	NOIRQ_SYSTEM_SLEEP_PM_OPS(suspend_fn, resume_fn)
#define SET_RUNTIME_PM_OPS(suspend_fn, resume_fn, idle_fn) \
	RUNTIME_PM_OPS(suspend_fn, resume_fn, idle_fn)
#define SET_SYSTEM_SLEEP_PM_OPS(suspend_fn, resume_fn) \
	SYSTEM_SLEEP_PM_OPS(suspend_fn, resume_fn)
#define SIMPLE_DEV_PM_OPS(name, suspend_fn, resume_fn) \
const struct dev_pm_ops __maybe_unused name = { \
	SET_SYSTEM_SLEEP_PM_OPS(suspend_fn, resume_fn) \
}
#define SYSTEM_SLEEP_PM_OPS(suspend_fn, resume_fn) \
	.suspend = pm_sleep_ptr(suspend_fn), \
	.resume = pm_sleep_ptr(resume_fn), \
	.freeze = pm_sleep_ptr(suspend_fn), \
	.thaw = pm_sleep_ptr(resume_fn), \
	.poweroff = pm_sleep_ptr(suspend_fn), \
	.restore = pm_sleep_ptr(resume_fn),
#define UNIVERSAL_DEV_PM_OPS(name, suspend_fn, resume_fn, idle_fn) \
const struct dev_pm_ops __maybe_unused name = { \
	SET_SYSTEM_SLEEP_PM_OPS(suspend_fn, resume_fn) \
	SET_RUNTIME_PM_OPS(suspend_fn, resume_fn, idle_fn) \
}
#define _DEFINE_DEV_PM_OPS(name, \
			   suspend_fn, resume_fn, \
			   runtime_suspend_fn, runtime_resume_fn, idle_fn) \
const struct dev_pm_ops name = { \
	SYSTEM_SLEEP_PM_OPS(suspend_fn, resume_fn) \
	RUNTIME_PM_OPS(runtime_suspend_fn, runtime_resume_fn, idle_fn) \
}
#define _EXPORT_DEV_PM_OPS(name, suspend_fn, resume_fn, runtime_suspend_fn, \
			   runtime_resume_fn, idle_fn, sec, ns)		\
	_DEFINE_DEV_PM_OPS(name, suspend_fn, resume_fn, runtime_suspend_fn, \
			   runtime_resume_fn, idle_fn); \
	__EXPORT_SYMBOL(name, sec, ns)

#define device_pm_lock() do {} while (0)
#define device_pm_unlock() do {} while (0)
#define pm_ptr(_ptr) PTR_IF(IS_ENABLED(CONFIG_PM), (_ptr))
#define pm_sleep_ptr(_ptr) PTR_IF(IS_ENABLED(CONFIG_PM_SLEEP), (_ptr))
#define suspend_report_result(dev, fn, ret)				\
	do {								\
		__suspend_report_result(__func__, dev, fn, ret);	\
	} while (0)

# define __hrtimer_clock_base_align


#define DEFINE_KLIST(_name, _get, _put)					\
	struct klist _name = KLIST_INIT(_name, _get, _put)
#define KLIST_INIT(_name, _get, _put)					\
	{ .k_lock	= __SPIN_LOCK_UNLOCKED(_name.k_lock),		\
	  .k_list	= LIST_HEAD_INIT(_name.k_list),			\
	  .get		= _get,						\
	  .put		= _put, }

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

#define __type_half_max(type) ((type)1 << (8*sizeof(type) - 1 - is_signed_type(type)))
#define array3_size(a, b, c)	size_mul(size_mul(a, b), c)
#define array_size(a, b)	size_mul(a, b)
#define check_add_overflow(a, b, d) __must_check_overflow(({	\
	typeof(a) __a = (a);			\
	typeof(b) __b = (b);			\
	typeof(d) __d = (d);			\
	(void) (&__a == &__b);			\
	(void) (&__a == __d);			\
	__builtin_add_overflow(__a, __b, __d);	\
}))
#define check_mul_overflow(a, b, d) __must_check_overflow(({	\
	typeof(a) __a = (a);			\
	typeof(b) __b = (b);			\
	typeof(d) __d = (d);			\
	(void) (&__a == &__b);			\
	(void) (&__a == __d);			\
	__builtin_mul_overflow(__a, __b, __d);	\
}))
#define check_shl_overflow(a, s, d) __must_check_overflow(({		\
	typeof(a) _a = a;						\
	typeof(s) _s = s;						\
	typeof(d) _d = d;						\
	u64 _a_full = _a;						\
	unsigned int _to_shift =					\
		is_non_negative(_s) && _s < 8 * sizeof(*d) ? _s : 0;	\
	*_d = (_a_full << _to_shift);					\
	(_to_shift != _s || is_negative(*_d) || is_negative(_a) ||	\
	(*_d >> _to_shift) != _a);					\
}))
#define check_sub_overflow(a, b, d) __must_check_overflow(({	\
	typeof(a) __a = (a);			\
	typeof(b) __b = (b);			\
	typeof(d) __d = (d);			\
	(void) (&__a == &__b);			\
	(void) (&__a == __d);			\
	__builtin_sub_overflow(__a, __b, __d);	\
}))
#define flex_array_size(p, member, count)				\
	__builtin_choose_expr(__is_constexpr(count),			\
		(count) * sizeof(*(p)->member) + __must_be_array((p)->member),	\
		size_mul(count, sizeof(*(p)->member) + __must_be_array((p)->member)))
#define is_negative(a) (!(is_non_negative(a)))
#define is_non_negative(a) ((a) > 0 || (a) == 0)
#define struct_size(p, member, count)					\
	__builtin_choose_expr(__is_constexpr(count),			\
		sizeof(*(p)) + flex_array_size(p, member, count),	\
		size_add(sizeof(*(p)), flex_array_size(p, member, count)))
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
#define request_mem_region_muxed(start, n, name) \
	__request_region(&iomem_resource, (start), (n), (name), IORESOURCE_MUXED)
#define request_muxed_region(start,n,name)	__request_region(&ioport_resource, (start), (n), (name), IORESOURCE_MUXED)
#define request_region(start,n,name)		__request_region(&ioport_resource, (start), (n), (name), 0)
#define EM_ADV_DATA_CB(_active_power_cb, _cost_cb)	\
	{ .active_power = _active_power_cb,		\
	  .get_cost = _cost_cb }
#define EM_DATA_CB(_active_power_cb)			\
		EM_ADV_DATA_CB(_active_power_cb, NULL)
#define EM_MAX_POWER 0xFFFF
#define EM_PERF_DOMAIN_ARTIFICIAL BIT(2)
#define EM_PERF_DOMAIN_MILLIWATTS BIT(0)
#define EM_PERF_DOMAIN_SKIP_INEFFICIENCIES BIT(1)
#define EM_PERF_STATE_INEFFICIENT BIT(0)
#define EM_SET_ACTIVE_POWER_CB(em_cb, cb) ((em_cb).active_power = cb)

#define em_is_artificial(em) ((em)->flags & EM_PERF_DOMAIN_ARTIFICIAL)
#define em_scale_power(p) ((p) * 1000)
#define em_span_cpus(em) (to_cpumask((em)->cpus))
#define SD_FLAG(name, mflags) __##name,
# define SD_INIT_NAME(type)		.name = #type

#define SDF_NEEDS_GROUPS       0x4
#define SDF_SHARED_CHILD       0x1
#define SDF_SHARED_PARENT      0x2

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
#define TASK_TRACED			__TASK_TRACED
#define UCLAMP_BUCKETS CONFIG_UCLAMP_BUCKETS_COUNT

#define __set_current_state(state_value)				\
	do {								\
		debug_normal_state_change((state_value));		\
		WRITE_ONCE(current->__state, (state_value));		\
	} while (0)
#define clear_stopped_child_used_math(child)	do { (child)->flags &= ~PF_USED_MATH; } while (0)
#define clear_used_math()			clear_stopped_child_used_math(current)
#define cond_resched() ({			\
	__might_resched("__FILE__", "__LINE__", 0);	\
	_cond_resched();			\
})
#define cond_resched_lock(lock) ({						\
	__might_resched("__FILE__", "__LINE__", PREEMPT_LOCK_RESCHED_OFFSETS);	\
	__cond_resched_lock(lock);						\
})
#define cond_resched_rwlock_read(lock) ({					\
	__might_resched("__FILE__", "__LINE__", PREEMPT_LOCK_RESCHED_OFFSETS);	\
	__cond_resched_rwlock_read(lock);					\
})
#define cond_resched_rwlock_write(lock) ({					\
	__might_resched("__FILE__", "__LINE__", PREEMPT_LOCK_RESCHED_OFFSETS);	\
	__cond_resched_rwlock_write(lock);					\
})
#define conditional_stopped_child_used_math(condition, child) \
	do { (child)->flags &= ~PF_USED_MATH, (child)->flags |= (condition) ? PF_USED_MATH : 0; } while (0)
#define conditional_used_math(condition)	conditional_stopped_child_used_math(condition, current)
#define copy_to_stopped_child_used_math(child) \
	do { (child)->flags &= ~PF_USED_MATH, (child)->flags |= current->flags & PF_USED_MATH; } while (0)
#define current_restore_rtlock_saved_state()				\
	do {								\
		lockdep_assert_irqs_disabled();				\
		raw_spin_lock(&current->pi_lock);			\
		debug_rtlock_wait_restore_state();			\
		WRITE_ONCE(current->__state, current->saved_state);	\
		current->saved_state = TASK_RUNNING;			\
		raw_spin_unlock(&current->pi_lock);			\
	} while (0);
#define current_save_and_set_rtlock_wait_state()			\
	do {								\
		lockdep_assert_irqs_disabled();				\
		raw_spin_lock(&current->pi_lock);			\
		current->saved_state = current->__state;		\
		debug_rtlock_wait_set_state();				\
		WRITE_ONCE(current->__state, TASK_RTLOCK_WAIT);		\
		raw_spin_unlock(&current->pi_lock);			\
	} while (0);
# define debug_normal_state_change(state_value)				\
	do {								\
		WARN_ON_ONCE(is_special_task_state(state_value));	\
		current->task_state_change = _THIS_IP_;			\
	} while (0)
# define debug_rtlock_wait_restore_state()				\
	do {								 \
		current->task_state_change = current->saved_state_change;\
	} while (0)
# define debug_rtlock_wait_set_state()					\
	do {								 \
		current->saved_state_change = current->task_state_change;\
		current->task_state_change = _THIS_IP_;			 \
	} while (0)
# define debug_special_state_change(state_value)			\
	do {								\
		WARN_ON_ONCE(!is_special_task_state(state_value));	\
		current->task_state_change = _THIS_IP_;			\
	} while (0)
#define get_current_state()	READ_ONCE(current->__state)
#define get_task_comm(buf, tsk) ({			\
	BUILD_BUG_ON(sizeof(buf) != TASK_COMM_LEN);	\
	__get_task_comm(buf, sizeof(buf), tsk);		\
})
#define is_special_task_state(state)				\
	((state) & (__TASK_STOPPED | __TASK_TRACED | TASK_PARKED | TASK_DEAD))
#define set_current_state(state_value)					\
	do {								\
		debug_normal_state_change((state_value));		\
		smp_store_mb(current->__state, (state_value));		\
	} while (0)
#define set_special_state(state_value)					\
	do {								\
		unsigned long flags; 			\
									\
		raw_spin_lock_irqsave(&current->pi_lock, flags);	\
		debug_special_state_change((state_value));		\
		WRITE_ONCE(current->__state, (state_value));		\
		raw_spin_unlock_irqrestore(&current->pi_lock, flags);	\
	} while (0)
#define set_stopped_child_used_math(child)	do { (child)->flags |= PF_USED_MATH; } while (0)
#define set_used_math()				set_stopped_child_used_math(current)
#define task_is_running(task)		(READ_ONCE((task)->__state) == TASK_RUNNING)
#define task_is_stopped(task)		((READ_ONCE(task->jobctl) & JOBCTL_STOPPED) != 0)
#define task_is_stopped_or_traced(task)	((READ_ONCE(task->jobctl) & (JOBCTL_STOPPED | JOBCTL_TRACED)) != 0)
#define task_is_traced(task)		((READ_ONCE(task->jobctl) & JOBCTL_TRACED) != 0)
# define task_thread_info(task)	(&(task)->thread_info)
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



#define clear_syscall_work_syscall_user_dispatch(tsk) \
	clear_task_syscall_work(tsk, SYSCALL_USER_DISPATCH)
#define UAPI_SA_FLAGS                                                          \
	(SA_NOCLDSTOP | SA_NOCLDWAIT | SA_SIGINFO | SA_ONSTACK | SA_RESTART |  \
	 SA_NODEFER | SA_RESETHAND | SA_EXPOSE_TAGBITS | __ARCH_UAPI_SA_FLAGS)



#define NICE_TO_PRIO(nice)	((nice) + DEFAULT_PRIO)
#define PRIO_TO_NICE(prio)	((prio) - DEFAULT_PRIO)




#define SECCOMP_NOTIFY_ADDFD_SIZE_LATEST SECCOMP_NOTIFY_ADDFD_SIZE_VER0
#define SECCOMP_NOTIFY_ADDFD_SIZE_VER0 24

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
#define __list_check_srcu(cond)					 \
	({								 \
	RCU_LOCKDEP_WARN(!(cond),					 \
		"RCU-list traversed without holding the required lock!");\
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
#define hlist_for_each_entry_srcu(pos, head, member, cond)		\
	for (__list_check_srcu(cond),					\
	     pos = hlist_entry_safe(rcu_dereference_raw(hlist_first_rcu(head)),\
			typeof(*(pos)), member);			\
		pos;							\
		pos = hlist_entry_safe(rcu_dereference_raw(hlist_next_rcu(\
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
#define list_for_each_entry_srcu(pos, head, member, cond)		\
	for (__list_check_srcu(cond),					\
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



#define dev_WARN(dev, format, arg...) \
	WARN(1, "%s %s: " format, dev_driver_string(dev), dev_name(dev), ## arg)
#define dev_WARN_ONCE(dev, condition, format, arg...) \
	WARN_ONCE(condition, "%s %s: " format, \
			dev_driver_string(dev), dev_name(dev), ## arg)
#define dev_alert(dev, fmt, ...) \
	dev_printk_index_wrap(_dev_alert, KERN_ALERT, dev, dev_fmt(fmt), ##__VA_ARGS__)
#define dev_alert_once(dev, fmt, ...)					\
	dev_level_once(dev_alert, dev, fmt, ##__VA_ARGS__)
#define dev_alert_ratelimited(dev, fmt, ...)				\
	dev_level_ratelimited(dev_alert, dev, fmt, ##__VA_ARGS__)
#define dev_crit(dev, fmt, ...) \
	dev_printk_index_wrap(_dev_crit, KERN_CRIT, dev, dev_fmt(fmt), ##__VA_ARGS__)
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
#define dev_emerg(dev, fmt, ...) \
	dev_printk_index_wrap(_dev_emerg, KERN_EMERG, dev, dev_fmt(fmt), ##__VA_ARGS__)
#define dev_emerg_once(dev, fmt, ...)					\
	dev_level_once(dev_emerg, dev, fmt, ##__VA_ARGS__)
#define dev_emerg_ratelimited(dev, fmt, ...)				\
	dev_level_ratelimited(dev_emerg, dev, fmt, ##__VA_ARGS__)
#define dev_err(dev, fmt, ...) \
	dev_printk_index_wrap(_dev_err, KERN_ERR, dev, dev_fmt(fmt), ##__VA_ARGS__)
#define dev_err_once(dev, fmt, ...)					\
	dev_level_once(dev_err, dev, fmt, ##__VA_ARGS__)
#define dev_err_ratelimited(dev, fmt, ...)				\
	dev_level_ratelimited(dev_err, dev, fmt, ##__VA_ARGS__)
#define dev_fmt(fmt) fmt
#define dev_info(dev, fmt, ...) \
	dev_printk_index_wrap(_dev_info, KERN_INFO, dev, dev_fmt(fmt), ##__VA_ARGS__)
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
#define dev_notice(dev, fmt, ...) \
	dev_printk_index_wrap(_dev_notice, KERN_NOTICE, dev, dev_fmt(fmt), ##__VA_ARGS__)
#define dev_notice_once(dev, fmt, ...)					\
	dev_level_once(dev_notice, dev, fmt, ##__VA_ARGS__)
#define dev_notice_ratelimited(dev, fmt, ...)				\
	dev_level_ratelimited(dev_notice, dev, fmt, ##__VA_ARGS__)
#define dev_printk(level, dev, fmt, ...)				\
	({								\
		dev_printk_index_emit(level, fmt);			\
		_dev_printk(level, dev, fmt, ##__VA_ARGS__);		\
	})
#define dev_printk_index_emit(level, fmt, ...) \
	printk_index_subsys_emit("%s %s: ", level, fmt)
#define dev_printk_index_wrap(_p_func, level, dev, fmt, ...)		\
	({								\
		dev_printk_index_emit(level, fmt);			\
		_p_func(dev, fmt, ##__VA_ARGS__);			\
	})
#define dev_vdbg(dev, fmt, ...)						\
({									\
	if (0)								\
		dev_printk(KERN_DEBUG, dev, dev_fmt(fmt), ##__VA_ARGS__); \
})
#define dev_warn(dev, fmt, ...) \
	dev_printk_index_wrap(_dev_warn, KERN_WARNING, dev, dev_fmt(fmt), ##__VA_ARGS__)
#define dev_warn_once(dev, fmt, ...)					\
	dev_level_once(dev_warn, dev, fmt, ##__VA_ARGS__)
#define dev_warn_ratelimited(dev, fmt, ...)				\
	dev_level_ratelimited(dev_warn, dev, fmt, ##__VA_ARGS__)
#define WARN_ON_RATELIMIT(condition, state)	({		\
	bool __rtn_cond = !!(condition);			\
	WARN_ON(__rtn_cond && __ratelimit(state));		\
	__rtn_cond;						\
})
#define WARN_RATELIMIT(condition, format, ...)			\
({								\
	static DEFINE_RATELIMIT_STATE(_rs,			\
				      DEFAULT_RATELIMIT_INTERVAL,	\
				      DEFAULT_RATELIMIT_BURST);	\
	int rtn = !!(condition);				\
								\
	if (unlikely(rtn && __ratelimit(&_rs)))			\
		WARN(rtn, format, ##__VA_ARGS__);		\
								\
	rtn;							\
})

#define PERF_MEM_NA (PERF_MEM_S(OP, NA)   |\
		    PERF_MEM_S(LVL, NA)   |\
		    PERF_MEM_S(SNOOP, NA) |\
		    PERF_MEM_S(LOCK, NA)  |\
		    PERF_MEM_S(TLB, NA))
#define PERF_PMU_TXN_ADD  0x1		
#define PERF_PMU_TXN_READ 0x2		
#define PMU_EVENT_ATTR(_name, _var, _id, _show)				\
static struct perf_pmu_events_attr _var = {				\
	.attr = __ATTR(_name, 0444, _show, NULL),			\
	.id   =  _id,							\
};
#define PMU_EVENT_ATTR_ID(_name, _show, _id)				\
	(&((struct perf_pmu_events_attr[]) {				\
		{ .attr = __ATTR(_name, 0444, _show, NULL),		\
		  .id = _id, }						\
	})[0].attr.attr)
#define PMU_EVENT_ATTR_STRING(_name, _var, _str)			    \
static struct perf_pmu_events_attr _var = {				    \
	.attr		= __ATTR(_name, 0444, perf_event_sysfs_show, NULL), \
	.id		= 0,						    \
	.event_str	= _str,						    \
};
#define PMU_FORMAT_ATTR(_name, _format)					\
static ssize_t								\
_name##_show(struct device *dev,					\
			       struct device_attribute *attr,		\
			       char *page)				\
{									\
	BUILD_BUG_ON(sizeof(_format) >= PAGE_SIZE);			\
	return sprintf(page, _format "\n");				\
}									\
									\
static struct device_attribute format_attr_##_name = __ATTR_RO(_name)

#define for_each_sibling_event(sibling, event)			\
	if ((event)->group_leader == (event))			\
		list_for_each_entry((sibling), &(event)->sibling_list, sibling_list)
# define perf_arch_bpf_user_pt_regs(regs) regs
# define perf_instruction_pointer(regs)	instruction_pointer(regs)
# define perf_misc_flags(regs) \
		(user_mode(regs) ? PERF_RECORD_MISC_USER : PERF_RECORD_MISC_KERNEL)
#define perf_output_put(handle, x) perf_output_copy((handle), &(x), sizeof(x))
#define CAP_OPT_INSETID BIT(2)
#define CAP_OPT_NOAUDIT BIT(1)
#define CAP_OPT_NONE 0x0
#define LSM_PRLIMIT_READ  1
#define LSM_PRLIMIT_WRITE 2

#define __data_id_enumify(ENUM, dummy) LOADING_ ## ENUM,
#define __data_id_stringify(dummy, str) #str,
#define FAULT_FLAG_DEFAULT  (FAULT_FLAG_ALLOW_RETRY | \
			     FAULT_FLAG_KILLABLE | \
			     FAULT_FLAG_INTERRUPTIBLE)
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
# define VM_UFFD_MINOR		BIT(VM_UFFD_MINOR_BIT)	
#define VM_UNMAPPED_AREA_TOPDOWN 1
#define  ZAP_FLAG_DROP_MARKER        ((__force zap_flags_t) BIT(0))

#define __pa_symbol(x)  __pa(RELOC_HIDE((unsigned long)(x), 0))
#define anon_vma_interval_tree_foreach(avc, root, start, last)		 \
	for (avc = anon_vma_interval_tree_iter_first(root, start, last); \
	     avc; avc = anon_vma_interval_tree_iter_next(avc, start, last))
#define cpupid_match_pid(task, cpupid) __cpupid_match_pid(task->pid, cpupid)
  #define expand_upwards(vma, address) (0)
#define folio_page_idx(folio, p)	(page_to_pfn(p) - folio_pfn(folio))
#define folio_ref_zero_or_close_to_overflow(folio) \
	((unsigned int) folio_ref_count(folio) + 127u <= 127u)
#define free_highmem_page(page) free_reserved_page(page)
#define is_ioremap_addr(x) is_vmalloc_addr(x)
#define lm_alias(x)	__va(__pa_symbol(x))
#define lru_to_page(head) (list_entry((head)->prev, struct page, lru))
#define mm_forbids_zeropage(X)	(0)
#define mm_zero_struct_page(pp)  ((void)memset((pp), 0, sizeof(struct page)))
#define nth_page(page,n) pfn_to_page(page_to_pfn((page)) + (n))
#define offset_in_folio(folio, p) ((unsigned long)(p) & (folio_size(folio) - 1))
#define offset_in_page(p)	((unsigned long)(p) & ~PAGE_MASK)
#define offset_in_thp(page, p)	((unsigned long)(p) & (thp_size(page) - 1))
#define page_address(page) lowmem_page_address(page)
#define page_address_init()  do { } while(0)
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
#define node_page_state_pages(node, item) global_node_page_state_pages(item)
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
#define transparent_hugepage_flags 0UL
#define transparent_hugepage_use_zero_page()				\
	(transparent_hugepage_flags &					\
	 (1<<TRANSPARENT_HUGEPAGE_USE_ZERO_PAGE_FLAG))
#define ACC_MODE(x) ("\004\002\006\006"[(x)&O_ACCMODE])
#define ACL_DONT_CACHE ((void *)(-3))
#define ACL_NOT_CACHED ((void *)(-1))
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
#define FS_ALLOW_IDMAP         32      
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
#define SB_I_STABLE_WRITES 0x00000008	
#define SB_I_TS_EXPIRY_WARNED 0x00000400 
#define SB_SUBMOUNT     (1<<26)
#define SIMPLE_TRANSACTION_LIMIT (PAGE_SIZE - sizeof(struct simple_transaction_argresp))
#define WHITEOUT_DEV 0
#define WHITEOUT_MODE 0

#define __IS_FLG(inode, flg)	((inode)->i_sb->s_flags & (flg))

#define __getname()		kmem_cache_alloc(names_cachep, GFP_KERNEL)
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
#define get_file_rcu(x) atomic_long_inc_not_zero(&(x)->f_count)
#define i_size_ordered_init(inode) seqcount_init(&inode->i_size_seqcount)
#define locks_inode(f) file_inode(f)
#define replace_fops(f, fops) \
	do {	\
		struct file *__file = (f); \
		fops_put(__file->f_op); \
		BUG_ON(!(__file->f_op = (fops))); \
	} while(0)
#define sb_has_strict_encoding(sb) \
	(sb->s_encoding_flags & SB_ENC_STRICT_MODE_FL)
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
#define BLKGETDISKSEQ _IOR(0x12,128,__u64)
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
				 | MNT_READONLY | MNT_NOSYMFOLLOW)

#define FSCRYPT_CONTENTS_ALIGNMENT 16
#define FSTR_INIT(n, l)		{ .name = n, .len = l }
#define FSTR_TO_QSTR(f)		QSTR_INIT((f)->name, (f)->len)
#define FS_CFLG_OWN_PAGES (1U << 1)

#define fname_len(p)		((p)->disk_name.len)
#define fname_name(p)		((p)->disk_name.name)
#define FSCRYPT_KEY_STATUS_FLAG_ADDED_BY_SELF   0x00000001

#define fscrypt_policy			fscrypt_policy_v1
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
#define kmalloc_index(s) __kmalloc_index(s, true)
#define kmalloc_node_track_caller(size, flags, node) \
	__kmalloc_node_track_caller(size, flags, node, \
			_RET_IP_)
#define kmalloc_track_caller(size, flags) \
	__kmalloc_track_caller(size, flags, _RET_IP_)
#define KASAN_SHADOW_INIT 0xFE
#define PTE_HWTABLE_PTRS 0

#define MAX_POSSIBLE_PHYSMEM_BITS 32
#define MAX_PTRS_PER_P4D PTRS_PER_P4D
#define MAX_PTRS_PER_PMD PTRS_PER_PMD
#define MAX_PTRS_PER_PTE PTRS_PER_PTE
#define MAX_PTRS_PER_PUD PTRS_PER_PUD
# define PAGE_KERNEL_EXEC PAGE_KERNEL
# define PAGE_KERNEL_RO PAGE_KERNEL


#define arch_enter_lazy_mmu_mode()	do {} while (0)
#define arch_flush_lazy_mmu_mode()	do {} while (0)
#define arch_leave_lazy_mmu_mode()	do {} while (0)
#define arch_needs_pgtable_deposit() (false)
#define arch_start_context_switch(prev)	do {} while (0)
#define flush_pmd_tlb_range(vma, addr, end)	flush_tlb_range(vma, addr, end)
#define flush_pud_tlb_range(vma, addr, end)	flush_tlb_range(vma, addr, end)
#define flush_tlb_fix_spurious_fault(vma, address) flush_tlb_page(vma, address)
#define has_transparent_hugepage() 1
#define mm_p4d_folded(mm)	__is_defined(__PAGETABLE_P4D_FOLDED)
#define mm_pmd_folded(mm)	__is_defined(__PAGETABLE_PMD_FOLDED)
#define mm_pud_folded(mm)	__is_defined(__PAGETABLE_PUD_FOLDED)
#define move_pte(pte, prot, old_addr, new_addr)	(pte)
#define my_zero_pfn(addr)	page_to_pfn(ZERO_PAGE(addr))
#define p4d_access_permitted(p4d, write) \
	(p4d_present(p4d) && (!(write) || p4d_write(p4d)))
#define p4d_addr_end(addr, end)						\
({	unsigned long __boundary = ((addr) + P4D_SIZE) & P4D_MASK;	\
	(__boundary - 1 < (end) - 1)? __boundary: (end);		\
})
#define p4d_clear_bad(p4d)        do { } while (0)
#define p4d_leaf(x)	0
#define p4d_leaf_size(x) P4D_SIZE
#define p4d_offset_lockless(pgdp, pgd, address) p4d_offset(&(pgd), address)
#define pgd_access_permitted(pgd, write) \
	(pgd_present(pgd) && (!(write) || pgd_write(pgd)))
#define pgd_addr_end(addr, end)						\
({	unsigned long __boundary = ((addr) + PGDIR_SIZE) & PGDIR_MASK;	\
	(__boundary - 1 < (end) - 1)? __boundary: (end);		\
})
#define pgd_index(a)  (((a) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1))
#define pgd_leaf(x)	0
#define pgd_leaf_size(x) (1ULL << PGDIR_SHIFT)
#define pgd_offset(mm, address)		pgd_offset_pgd((mm)->pgd, (address))
#define pgd_offset_gate(mm, addr)	pgd_offset(mm, addr)
#define pgd_offset_k(address)		pgd_offset(&init_mm, (address))
#define pgprot_decrypted(prot)	(prot)
#define pgprot_device pgprot_noncached
#define pgprot_encrypted(prot)	(prot)
#define pgprot_mhp(prot)	(prot)
#define pgprot_modify pgprot_modify
#define pgprot_noncached(prot)	(prot)
#define pgprot_nx(prot)	(prot)
#define pgprot_writecombine pgprot_noncached
#define pgprot_writethrough pgprot_noncached
#define pmd_access_permitted(pmd, write) \
	(pmd_present(pmd) && (!(write) || pmd_write(pmd)))
#define pmd_addr_end(addr, end)						\
({	unsigned long __boundary = ((addr) + PMD_SIZE) & PMD_MASK;	\
	(__boundary - 1 < (end) - 1)? __boundary: (end);		\
})
#define pmd_clear_savedwrite pmd_wrprotect
#define pmd_index pmd_index
#define pmd_leaf(x)	0
#define pmd_leaf_size(x) PMD_SIZE
#define pmd_mk_savedwrite pmd_mkwrite
#define pmd_offset pmd_offset
#define pmd_offset_lockless(pudp, pud, address) pmd_offset(&(pud), address)
#define pmd_pgtable(pmd) pmd_page(pmd)
#define pmd_savedwrite pmd_write
#define pmdp_collapse_flush pmdp_collapse_flush
#define pte_access_permitted(pte, write) \
	(pte_present(pte) && (!(write) || pte_write(pte)))
# define pte_accessible(mm, pte)	((void)(pte), 1)
#define pte_clear_savedwrite pte_wrprotect
#define pte_index pte_index
#define pte_leaf_size(x) PAGE_SIZE
#define pte_mk_savedwrite pte_mkwrite
#define pte_offset_kernel pte_offset_kernel
#define pte_offset_map(dir, address)	pte_offset_kernel((dir), (address))
#define pte_savedwrite pte_write
#define pte_unmap(pte) kunmap_atomic((pte))
#define pud_access_permitted(pud, write) \
	(pud_present(pud) && (!(write) || pud_write(pud)))
#define pud_addr_end(addr, end)						\
({	unsigned long __boundary = ((addr) + PUD_SIZE) & PUD_MASK;	\
	(__boundary - 1 < (end) - 1)? __boundary: (end);		\
})
#define pud_clear_bad(p4d)        do { } while (0)
#define pud_index pud_index
#define pud_leaf(x)	0
#define pud_leaf_size(x) PUD_SIZE
#define pud_offset pud_offset
#define pud_offset_lockless(p4dp, p4d, address) pud_offset(&(p4d), address)
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
#define current_ucounts()	(current_cred_xxx(ucounts))
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
#define task_ucounts(task)	(task_cred_xxx((task), ucounts))
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
	request_key_tag(type, description, net->key_domain, callout_info)
#define request_key_net_rcu(type, description, net) \
	request_key_rcu(type, description, net->key_domain)
#define ASSOC_ARRAY_KEY_CHUNK_SIZE BITS_PER_LONG 

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
#define CAP_LAST_CAP         CAP_CHECKPOINT_RESTORE
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


#define IOPRIO_PRIO_CLASS(ioprio)	\
	(((ioprio) >> IOPRIO_CLASS_SHIFT) & IOPRIO_CLASS_MASK)
#define IOPRIO_PRIO_DATA(ioprio)	((ioprio) & IOPRIO_PRIO_MASK)
#define IOPRIO_PRIO_VALUE(class, data)	\
	((((class) & IOPRIO_CLASS_MASK) << IOPRIO_CLASS_SHIFT) | \
	 ((data) & IOPRIO_PRIO_MASK))



# define rt_mutex_adjust_pi(p)		do { } while (0)

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
#define CLONE_LEGACY_FLAGS 0xffffffffULL

# define arch_task_struct_size (sizeof(struct task_struct))
#define sched_exec()   {}

#define __get_kernel_nofault(dst, src, type, label)	\
do {							\
	type __user *p = (type __force __user *)(src);	\
	type data;					\
	if (__get_user(data, p))			\
		goto label;				\
	*(type *)dst = data;				\
} while (0)
#define __put_kernel_nofault(dst, src, type, label)	\
do {							\
	type __user *p = (type __force __user *)(dst);	\
	type data = *(type *)src;			\
	if (__put_user(data, p))			\
		goto label;				\
} while (0)
#define faulthandler_disabled() (pagefault_disabled() || in_atomic())
#define get_kernel_nofault(val, ptr) ({				\
	const typeof(val) *__gk_ptr = (ptr);			\
	copy_from_kernel_nofault(&(val), __gk_ptr, sizeof(val));\
})
#define unsafe_copy_from_user(d,s,l,e) unsafe_op_wrap(__copy_from_user(d,s,l),e)
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

#define JOBCTL_STOPPED		(1UL << JOBCTL_STOPPED_BIT)
#define JOBCTL_STOP_DEQUEUED_BIT 16	
#define JOBCTL_TRACED		(1UL << JOBCTL_TRACED_BIT)
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
		fallthrough;						\
	case 2:								\
		a1 = a->sig[1]; b1 = b->sig[1];				\
		r->sig[1] = op(a1, b1);					\
		fallthrough;						\
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
		fallthrough;						\
	case 2:	set->sig[1] = op(set->sig[1]);				\
		fallthrough;						\
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
	 O_APPEND | O_NDELAY | O_NONBLOCK | __O_SYNC | O_DSYNC | \
	 FASYNC	| O_DIRECT | O_LARGEFILE | O_DIRECTORY | O_NOFOLLOW | \
	 O_NOATIME | O_CLOEXEC | O_PATH | __O_TMPFILE)
#define VALID_RESOLVE_FLAGS \
	(RESOLVE_NO_XDEV | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS | \
	 RESOLVE_BENEATH | RESOLVE_IN_ROOT | RESOLVE_CACHED)

#define force_o_largefile() (!IS_ENABLED(CONFIG_ARCH_32BIT_OFF_T))

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



#define page_ref_tracepoint_active(t) tracepoint_enabled(t)


#define MAX_RESOURCE ((resource_size_t)~0)

#define MMAP_LOCK_INITIALIZER(name) \
	.mmap_lock = __RWSEM_INITIALIZER((name).mmap_lock),


#define __fid_enumify(ENUM, dummy) READING_ ## ENUM,
#define __fid_stringify(dummy, str) #str,
#define __kernel_read_file_id(id) \
	id(UNKNOWN, unknown)		\
	id(FIRMWARE, firmware)		\
	id(MODULE, kernel-module)		\
	id(KEXEC_IMAGE, kexec-image)		\
	id(KEXEC_INITRAMFS, kexec-initramfs)	\
	id(POLICY, security-policy)		\
	id(X509_CERTIFICATE, x509-certificate)	\
	id(MAX_ID, )
#define FDPUT_FPUT       1
#define FDPUT_POS_UNLOCK 2

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
		rcu_read_lock_sched_held() ||				\
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
#define KTHREAD_DELAYED_WORK_INIT(dwork, fn) {				\
	.work = KTHREAD_WORK_INIT((dwork).work, (fn)),			\
	.timer = __TIMER_INITIALIZER(kthread_delayed_work_timer_fn,\
				     TIMER_IRQSAFE),			\
	}
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


#define u64_stats_init(syncp)	seqcount_init(&(syncp)->seq)

#define kcpustat_cpu(cpu) per_cpu(kernel_cpustat, cpu)
#define kcpustat_this_cpu this_cpu_ptr(&kernel_cpustat)
#define kstat_cpu(cpu) per_cpu(kstat, cpu)
#define kstat_this_cpu this_cpu_ptr(&kstat)


#define DECLARE_TASKLET(name, _callback)		\
struct tasklet_struct name = {				\
	.count = ATOMIC_INIT(0),			\
	.callback = _callback,				\
	.use_callback = true,				\
}
#define DECLARE_TASKLET_DISABLED(name, _callback)	\
struct tasklet_struct name = {				\
	.count = ATOMIC_INIT(1),			\
	.callback = _callback,				\
	.use_callback = true,				\
}
#define DECLARE_TASKLET_DISABLED_OLD(name, _func)	\
struct tasklet_struct name = {				\
	.count = ATOMIC_INIT(1),			\
	.func = _func,					\
}
#define DECLARE_TASKLET_OLD(name, _func)		\
struct tasklet_struct name = {				\
	.count = ATOMIC_INIT(0),			\
	.func = _func,					\
}
#define IRQF_TIMER		(__IRQF_TIMER | IRQF_NO_SUSPEND | IRQF_NO_THREAD)
#define SOFTIRQ_HOTPLUG_SAFE_MASK (BIT(RCU_SOFTIRQ) | BIT(IRQ_POLL_SOFTIRQ))

#define __softirq_entry  __section(".softirqentry.text")
#  define force_irqthreads()	(true)
#define from_tasklet(var, callback_tasklet, tasklet_fieldname)	\
	container_of(callback_tasklet, typeof(*var), tasklet_fieldname)
#define hard_irq_disable()	do { } while(0)
#define local_softirq_pending_ref irq_stat.__softirq_pending
#define or_softirq_pending(x)	(__this_cpu_or(local_softirq_pending_ref, (x)))
#define set_softirq_pending(x)	(__this_cpu_write(local_softirq_pending_ref, (x)))

#define __irq_enter()					\
	do {						\
		preempt_count_add(HARDIRQ_OFFSET);	\
		lockdep_hardirq_enter();		\
		account_hardirq_enter(current);		\
	} while (0)
#define __irq_enter_raw()				\
	do {						\
		preempt_count_add(HARDIRQ_OFFSET);	\
		lockdep_hardirq_enter();		\
	} while (0)
#define __irq_exit()					\
	do {						\
		account_hardirq_exit(current);		\
		lockdep_hardirq_exit();			\
		preempt_count_sub(HARDIRQ_OFFSET);	\
	} while (0)
#define __irq_exit_raw()				\
	do {						\
		lockdep_hardirq_exit();			\
		preempt_count_sub(HARDIRQ_OFFSET);	\
	} while (0)
#define __nmi_enter()						\
	do {							\
		lockdep_off();					\
		arch_nmi_enter();				\
		BUG_ON(in_nmi() == NMI_MASK);			\
		__preempt_count_add(NMI_OFFSET + HARDIRQ_OFFSET);	\
	} while (0)
#define __nmi_exit()						\
	do {							\
		BUG_ON(!in_nmi());				\
		__preempt_count_sub(NMI_OFFSET + HARDIRQ_OFFSET);	\
		arch_nmi_exit();				\
		lockdep_on();					\
	} while (0)
#define arch_nmi_enter()	do { } while (0)
#define arch_nmi_exit()		do { } while (0)
#define nmi_enter()						\
	do {							\
		__nmi_enter();					\
		lockdep_hardirq_enter();			\
		rcu_nmi_enter();				\
		instrumentation_begin();			\
		ftrace_nmi_enter();				\
		instrumentation_end();				\
	} while (0)
#define nmi_exit()						\
	do {							\
		instrumentation_begin();			\
		ftrace_nmi_exit();				\
		instrumentation_end();				\
		rcu_nmi_exit();					\
		lockdep_hardirq_exit();				\
		__nmi_exit();					\
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
#define MAX_PER_NAMESPACE_UCOUNTS UCOUNT_RLIMIT_NPROC
#define UID_GID_MAP_MAX_BASE_EXTENTS 5
#define UID_GID_MAP_MAX_EXTENTS 340
#define USERNS_INIT_FLAGS USERNS_SETGROUPS_ALLOWED
#define USERNS_SETGROUPS_ALLOWED 1UL



#define DEFINE_PROC_SHOW_ATTRIBUTE(__name)				\
static int __name ## _open(struct inode *inode, struct file *file)	\
{									\
	return single_open(file, __name ## _show, pde_data(inode));	\
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


#define __ismask(x) (_ctype[(int)(unsigned char)(x)])
#define isalnum(c)	((__ismask(c)&(_U|_L|_D)) != 0)
#define isalpha(c)	((__ismask(c)&(_U|_L)) != 0)
#define isascii(c) (((unsigned char)(c))<=0x7f)
#define iscntrl(c)	((__ismask(c)&(_C)) != 0)
#define  isdigit(c) __builtin_isdigit(c)
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


#define setup_thread_stack(new,old)	do { } while(0)
#define task_stack_end_corrupted(task) \
		(*(end_of_stack(task)) != STACK_END_MAGIC)
#define task_stack_page(task)	((void *)(task)->stack)
#define DEFINE_STATIC_KEY_DEFERRED_FALSE(name, rl)			\
	struct static_key_false_deferred name = {			\
		.key =		{ STATIC_KEY_INIT_FALSE },		\
		.timeout =	(rl),					\
		.work =	__DELAYED_WORK_INITIALIZER((name).work,		\
						   jump_label_update_timeout, \
						   0),			\
	}
#define DEFINE_STATIC_KEY_DEFERRED_TRUE(name, rl)			\
	struct static_key_true_deferred name = {			\
		.key =		{ STATIC_KEY_INIT_TRUE },		\
		.timeout =	(rl),					\
		.work =	__DELAYED_WORK_INITIALIZER((name).work,		\
						   jump_label_update_timeout, \
						   0),			\
	}

#define static_branch_deferred_inc(x)	static_branch_inc(&(x)->key)
#define static_branch_slow_dec_deferred(x)				\
	__static_key_slow_dec_deferred(&(x)->key.key, &(x)->work, (x)->timeout)
#define static_key_deferred_flush(x)					\
	__static_key_deferred_flush((x), &(x)->work)
#define static_key_slow_dec_deferred(x)					\
	__static_key_slow_dec_deferred(&(x)->key, &(x)->work, (x)->timeout)
#define DEFINE_IRQ_WORK(name, _f)				\
	struct irq_work name = IRQ_WORK_INIT(_f)
#define IRQ_WORK_INIT(_func) __IRQ_WORK_INIT(_func, 0)
#define IRQ_WORK_INIT_HARD(_func) __IRQ_WORK_INIT(_func, IRQ_WORK_HARD_IRQ)
#define IRQ_WORK_INIT_LAZY(_func) __IRQ_WORK_INIT(_func, IRQ_WORK_LAZY)

#define __IRQ_WORK_INIT(_func, _flags) (struct irq_work){	\
	.node = { .u_flags = (_flags), },			\
	.func = (_func),					\
	.irqwait = __RCUWAIT_INITIALIZER(irqwait),		\
}
#define ARCH_SUPPORTS_FTRACE_OPS 0
#define CALLER_ADDR0 ((unsigned long)ftrace_return_address0)
#define CALLER_ADDR1 ((unsigned long)ftrace_return_address(1))
#define CALLER_ADDR2 ((unsigned long)ftrace_return_address(2))
#define CALLER_ADDR3 ((unsigned long)ftrace_return_address(3))
#define CALLER_ADDR4 ((unsigned long)ftrace_return_address(4))
#define CALLER_ADDR5 ((unsigned long)ftrace_return_address(5))
#define CALLER_ADDR6 ((unsigned long)ftrace_return_address(6))
#define FTRACE_ADDR ((unsigned long)ftrace_caller)
# define FTRACE_FORCE_LIST_FUNC 1
#define FTRACE_GRAPH_ADDR ((unsigned long)ftrace_graph_caller)
#define FTRACE_GRAPH_TRAMP_ADDR ((unsigned long) 0)
#define FTRACE_OPS_GRAPH_STUB FTRACE_OPS_FL_STUB
#define FTRACE_REF_MAX		((1UL << FTRACE_REF_MAX_SHIFT) - 1)
# define FTRACE_REGS_ADDR ((unsigned long)ftrace_regs_caller)
#define FTRACE_RETFUNC_DEPTH 50
#define FTRACE_RETSTACK_ALLOC_SIZE 32


#define arch_ftrace_get_regs(fregs) (&(fregs)->regs)
#define do_for_each_ftrace_op(op, list)			\
	op = rcu_dereference_raw_check(list);			\
	do
#define for_ftrace_rec_iter(iter)		\
	for (iter = ftrace_rec_iter_start();	\
	     iter;				\
	     iter = ftrace_rec_iter_next(iter))
# define ftrace_direct_func_count 0
#define ftrace_free_filter(ops) do { } while (0)
#define ftrace_graph_func ftrace_stub
#define ftrace_instruction_pointer_set(fregs, ip) do { } while (0)
#define ftrace_need_init_nop() (!__is_defined(CC_USING_NOP_MCOUNT))
#define ftrace_ops_set_global_filter(ops) do { } while (0)
#define ftrace_rec_count(rec)	((rec)->flags & FTRACE_REF_MAX)
#define ftrace_regex_open(ops, flag, inod, file) ({ -ENODEV; })
#  define ftrace_return_address(n) __builtin_return_address(n)
# define ftrace_return_address0 __builtin_return_address(0)
#define ftrace_set_early_filter(ops, buf, enable) do { } while (0)
#define ftrace_set_filter(ops, buf, len, reset) ({ -ENODEV; })
#define ftrace_set_filter_ip(ops, ip, remove, reset) ({ -ENODEV; })
#define ftrace_set_filter_ips(ops, ips, cnt, remove, reset) ({ -ENODEV; })
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
#define PT_EVENT_FLAG(event)	(1 << (PT_OPT_FLAG_SHIFT + (event)))

#define arch_has_block_step()		(0)
#define arch_has_single_step()		(0)
#define arch_ptrace_stop()		do { } while (0)
#define arch_ptrace_stop_needed()	(0)
#define current_pt_regs() task_pt_regs(current)
#define current_user_stack_pointer() user_stack_pointer(current_pt_regs())
#define force_successful_syscall_return() do { } while (0)
#define is_syscall_success(regs) (!IS_ERR_VALUE((unsigned long)(regs_return_value(regs))))
#define signal_pt_regs() task_pt_regs(current)

#define MAX_PID_NS_LEVEL 32
#define PIDNS_ADDING (1U << 31)

#define KSYM_NAME_LEN 128
#define KSYM_SYMBOL_LEN (sizeof("%s+%#lx/%#lx [%s %s]") + \
			(KSYM_NAME_LEN - 1) + \
			2*(BITS_PER_LONG*3/10) + (MODULE_NAME_LEN - 1) + \
			(BUILD_ID_SIZE_MAX * 2) + 1)



# define do_ftrace_record_recursion(ip, pip)				\
	do {								\
		if (!trace_recursion_test(TRACE_RECORD_RECURSION_BIT)) { \
			trace_recursion_set(TRACE_RECORD_RECURSION_BIT); \
			ftrace_record_recursion(ip, pip);		\
			trace_recursion_clear(TRACE_RECORD_RECURSION_BIT); \
		}							\
	} while (0)
#define trace_recursion_clear(bit)	do { (current)->trace_recursion &= ~(1<<(bit)); } while (0)
#define trace_recursion_depth() \
	(((current)->trace_recursion >> TRACE_GRAPH_DEPTH_START_BIT) & 3)
#define trace_recursion_set(bit)	do { (current)->trace_recursion |= (1<<(bit)); } while (0)
#define trace_recursion_set_depth(depth) \
	do {								\
		current->trace_recursion &=				\
			~(3 << TRACE_GRAPH_DEPTH_START_BIT);		\
		current->trace_recursion |=				\
			((depth) & 3) << TRACE_GRAPH_DEPTH_START_BIT;	\
	} while (0)
#define trace_recursion_test(bit)	((current)->trace_recursion & (1<<(bit)))

#define PERF_MEM_LVLNUM_ANY_CACHE 0x0b 
#define PERF_MEM_S(a, s) \
	(((__u64)PERF_MEM_##a##_##s) << PERF_MEM_##a##_SHIFT)
#define PERF_MEM_SNOOPX_SHIFT  38
#define PERF_SAMPLE_BRANCH_PLM_ALL \
	(PERF_SAMPLE_BRANCH_USER|\
	 PERF_SAMPLE_BRANCH_KERNEL|\
	 PERF_SAMPLE_BRANCH_HV)



#define RING_BUFFER_ALL_CPUS -1

#define ring_buffer_alloc(size, flags)			\
({							\
	static struct lock_class_key __key;		\
	__ring_buffer_alloc((size), (flags), &__key);	\
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




#define __boot_pa(x)		__pa(x)
#define __boot_va(x)		__va(x)
#define __pa(x)		__phys_addr((unsigned long)(x))
#define __pa_nodebug(x)	__phys_addr_nodebug((unsigned long)(x))
#define __pa_symbol(x) \
	__phys_addr_symbol(__phys_reloc_hide((unsigned long)(x)))
#define __va(x)			((void *)((unsigned long)(x)+PAGE_OFFSET))
#define alloc_zeroed_user_highpage_movable(vma, vaddr) \
	alloc_page_vma(GFP_HIGHUSER_MOVABLE | __GFP_ZERO, vma, vaddr)
#define pfn_to_kaddr(pfn)      __va((pfn) << PAGE_SHIFT)
#define virt_to_page(kaddr)	pfn_to_page(__pa(kaddr) >> PAGE_SHIFT)


#define __page_to_pfn(page)	((unsigned long)((page) - mem_map) + \
				 ARCH_PFN_OFFSET)
#define __pfn_to_page(pfn)	(mem_map + ((pfn) - ARCH_PFN_OFFSET))
#define page_to_pfn __page_to_pfn
#define pfn_to_page __pfn_to_page

#define __phys_addr(x)		__phys_addr_nodebug(x)
#define __phys_addr_nodebug(x)	((x) - PAGE_OFFSET)
#define __phys_addr_symbol(x)	__phys_addr(x)
#define __phys_reloc_hide(x)	RELOC_HIDE((x), 0)
#define pfn_valid(pfn)		((pfn) < max_mapnr)
#define THREAD_SIZE		(PAGE_SIZE << THREAD_SIZE_ORDER)

#define __PAGE_OFFSET		__PAGE_OFFSET_BASE

# define __HAVE_ARCH_GATE_AREA 1
#define ALTERNATIVE(oldinstr, newinstr, feature)			\
	OLDINSTR(oldinstr, 1)						\
	".pushsection .altinstructions,\"a\"\n"				\
	ALTINSTR_ENTRY(feature, 1)					\
	".popsection\n"							\
	".pushsection .altinstr_replacement, \"ax\"\n"			\
	ALTINSTR_REPLACEMENT(newinstr, 1)				\
	".popsection\n"
#define ALTERNATIVE_2(oldinstr, newinstr1, feature1, newinstr2, feature2)\
	OLDINSTR_2(oldinstr, 1, 2)					\
	".pushsection .altinstructions,\"a\"\n"				\
	ALTINSTR_ENTRY(feature1, 1)					\
	ALTINSTR_ENTRY(feature2, 2)					\
	".popsection\n"							\
	".pushsection .altinstr_replacement, \"ax\"\n"			\
	ALTINSTR_REPLACEMENT(newinstr1, 1)				\
	ALTINSTR_REPLACEMENT(newinstr2, 2)				\
	".popsection\n"
#define ALTERNATIVE_3(oldinsn, newinsn1, feat1, newinsn2, feat2, newinsn3, feat3) \
	OLDINSTR_3(oldinsn, 1, 2, 3)						\
	".pushsection .altinstructions,\"a\"\n"					\
	ALTINSTR_ENTRY(feat1, 1)						\
	ALTINSTR_ENTRY(feat2, 2)						\
	ALTINSTR_ENTRY(feat3, 3)						\
	".popsection\n"								\
	".pushsection .altinstr_replacement, \"ax\"\n"				\
	ALTINSTR_REPLACEMENT(newinsn1, 1)					\
	ALTINSTR_REPLACEMENT(newinsn2, 2)					\
	ALTINSTR_REPLACEMENT(newinsn3, 3)					\
	".popsection\n"
#define ALTERNATIVE_TERNARY(oldinstr, feature, newinstr_yes, newinstr_no) \
	ALTERNATIVE_2(oldinstr, newinstr_no, X86_FEATURE_ALWAYS,	\
		      newinstr_yes, feature)
#define ALTINSTR_ENTRY(feature, num)					      \
	" .long 661b - .\n"				 \
	" .long " b_replacement(num)"f - .\n"		 \
	" .word " __stringify(feature) "\n"		 \
	" .byte " alt_total_slen "\n"			 \
	" .byte " alt_rlen(num) "\n"			
#define ALTINSTR_REPLACEMENT(newinstr, num)			\
	"# ALT: replacement " #num "\n"						\
	b_replacement(num)":\n\t" newinstr "\n" e_replacement(num) ":\n"
#define ALT_NOT(feat)		((feat) | ALTINSTR_FLAG_INV)
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
#define alternative_ternary(oldinstr, feature, newinstr_yes, newinstr_no) \
	asm_inline volatile(ALTERNATIVE_TERNARY(oldinstr, feature, newinstr_yes, newinstr_no) ::: "memory")
#define b_replacement(num)	"664"#num
#define e_replacement(num)	"665"#num
#define ASM_CALL_CONSTRAINT "+r" (current_stack_pointer)
# define CC_OUT(c) "=@cc" #c
# define CC_SET(c) "\n\t/* output condition code " #c "*/\n"
# define DEFINE_EXTABLE_TYPE_REG \
	".macro extable_type_reg type:req reg:req\n"						\
	".set .Lfound, 0\n"									\
	".set .Lregnr, 0\n"									\
	".irp rs,rax,rcx,rdx,rbx,rsp,rbp,rsi,rdi,r8,r9,r10,r11,r12,r13,r14,r15\n"		\
	".ifc \\reg, %%\\rs\n"									\
	".set .Lfound, .Lfound+1\n"								\
	".long \\type + (.Lregnr << 8)\n"							\
	".endif\n"										\
	".set .Lregnr, .Lregnr+1\n"								\
	".endr\n"										\
	".set .Lregnr, 0\n"									\
	".irp rs,eax,ecx,edx,ebx,esp,ebp,esi,edi,r8d,r9d,r10d,r11d,r12d,r13d,r14d,r15d\n"	\
	".ifc \\reg, %%\\rs\n"									\
	".set .Lfound, .Lfound+1\n"								\
	".long \\type + (.Lregnr << 8)\n"							\
	".endif\n"										\
	".set .Lregnr, .Lregnr+1\n"								\
	".endr\n"										\
	".if (.Lfound != 1)\n"									\
	".error \"extable_type_reg: bad register argument\"\n"					\
	".endif\n"										\
	".endm\n"
# define UNDEFINE_EXTABLE_TYPE_REG \
	".purgem extable_type_reg\n"
#define _ASM_BYTES(x, ...)	__ASM_FORM(.byte x,##__VA_ARGS__ ;)
#define _ASM_EXTABLE(from, to)					\
	_ASM_EXTABLE_TYPE(from, to, EX_TYPE_DEFAULT)
#define _ASM_EXTABLE_CPY(from, to)				\
	_ASM_EXTABLE_TYPE(from, to, EX_TYPE_COPY)
#define _ASM_EXTABLE_FAULT(from, to)				\
	_ASM_EXTABLE_TYPE(from, to, EX_TYPE_FAULT)
# define _ASM_EXTABLE_TYPE(from, to, type)			\
	" .pushsection \"__ex_table\",\"a\"\n"			\
	" .balign 4\n"						\
	" .long (" #from ") - .\n"				\
	" .long (" #to ") - .\n"				\
	" .long " __stringify(type) " \n"			\
	" .popsection\n"
# define _ASM_EXTABLE_TYPE_REG(from, to, type, reg)				\
	" .pushsection \"__ex_table\",\"a\"\n"					\
	" .balign 4\n"								\
	" .long (" #from ") - .\n"						\
	" .long (" #to ") - .\n"						\
	DEFINE_EXTABLE_TYPE_REG							\
	"extable_type_reg reg=" __stringify(reg) ", type=" __stringify(type) " \n"\
	UNDEFINE_EXTABLE_TYPE_REG						\
	" .popsection\n"
#define _ASM_EXTABLE_UA(from, to)				\
	_ASM_EXTABLE_TYPE(from, to, EX_TYPE_UACCESS)
#define _ASM_RIP(x)	__ASM_SEL_RAW(x, x (__ASM_REGPFX rip))

# define __ASM_FORM(x, ...)		" " __stringify(x,##__VA_ARGS__) " "
# define __ASM_FORM_COMMA(x, ...)	" " __stringify(x,##__VA_ARGS__) ","
# define __ASM_FORM_RAW(x, ...)		    __stringify(x,##__VA_ARGS__)
#define __ASM_REG(reg)         __ASM_SEL_RAW(e##reg, r##reg)
# define __ASM_SEL(a,b)		__ASM_FORM(a)
# define __ASM_SEL_RAW(a,b)	__ASM_FORM_RAW(a)
#define __ASM_SIZE(inst, ...)	__ASM_SEL(inst##l##__VA_ARGS__, \
					  inst##q##__VA_ARGS__)
#define X86_BUG(x)			(NCAPINTS*32 + (x))
#define X86_FEATURE_AVX512_VP2INTERSECT (18*32+ 8) 

#define DISABLED_MASK_CHECK BUILD_BUG_ON_ZERO(NCAPINTS != 20)

#define REQUIRED_MASK_CHECK BUILD_BUG_ON_ZERO(NCAPINTS != 20)

#define EXCEPTION_STACK_ORDER (1 + KASAN_STACK_ORDER)
#define EXCEPTION_STKSZ (PAGE_SIZE << EXCEPTION_STACK_ORDER)
#define IRQ_STACK_ORDER (2 + KASAN_STACK_ORDER)
#define IRQ_STACK_SIZE (PAGE_SIZE << IRQ_STACK_ORDER)
#define KASAN_STACK_ORDER 1
#define TASK_SIZE_OF(child)	((test_tsk_thread_flag(child, TIF_ADDR32)) ? \
					IA32_PAGE_OFFSET : TASK_SIZE_MAX)

#define task_size_max()		((_AC(1,UL) << __VIRTUAL_MASK_SHIFT) - PAGE_SIZE)

#define HUGE_MAX_HSTATE 2
#define IOREMAP_MAX_ORDER       (PUD_SHIFT)
#define PAGE_OFFSET		((unsigned long)__PAGE_OFFSET)

#define __PHYSICAL_MASK		((phys_addr_t)((1ULL << __PHYSICAL_MASK_SHIFT) - 1))
#define __START_KERNEL		(__START_KERNEL_map + __PHYSICAL_START)
#define __VIRTUAL_MASK		((1UL << __VIRTUAL_MASK_SHIFT) - 1)

#define __sme_clr(x)		((x) & ~sme_me_mask)
#define __sme_set(x)		((x) | sme_me_mask)
#define QUIRK_IOAPIC_BAD_REGSEL   2 
#define QUIRK_IOAPIC_GOOD_REGSEL  3 
#define QUIRK_NOIRQBALANCING      1 
#define XENPF_ACPI_SLEEP_EXTENDED 0x00000001
#define XENPF_INTERFACE_VERSION 0x03000001
#define XENPF_add_memtype         31
#define XENPF_change_freq         52
#define XENPF_core_parking     60
#define XENPF_del_memtype         32
#define XENPF_efi_runtime_call    49
#define XENPF_enter_acpi_sleep    51
#define XENPF_firmware_info       50
#define XENPF_get_cpuinfo 55
#define XENPF_get_symbol      63
#define XENPF_getidletime         53
#define XENPF_microcode_update    35
#define XENPF_platform_quirk      39
#define XENPF_read_memtype        33
#define XENPF_set_processor_pminfo      54
#define XENPF_settime32             17
#define XENPF_settime64           62
#define XEN_CORE_PARKING_GET   2
#define XEN_CORE_PARKING_SET   1
#define XEN_EFI_GET_TIME_SET_CLEARS_NS 0x00000001
#define XEN_EFI_GET_WAKEUP_TIME_ENABLED 0x00000001
#define XEN_EFI_GET_WAKEUP_TIME_PENDING 0x00000002
#define XEN_EFI_SET_WAKEUP_TIME_ENABLE      0x00000001
#define XEN_EFI_SET_WAKEUP_TIME_ENABLE_ONLY 0x00000002
#define XEN_EFI_VARIABLE_BOOTSERVICE_ACCESS 0x00000002
#define XEN_EFI_VARIABLE_NON_VOLATILE       0x00000001
#define XEN_EFI_VARIABLE_RUNTIME_ACCESS     0x00000004
#define XEN_EFI_get_next_high_monotonic_count 5
#define XEN_EFI_get_next_variable_name        8
#define XEN_EFI_get_time                      1
#define XEN_EFI_get_variable                  6
#define XEN_EFI_get_wakeup_time               3
#define XEN_EFI_query_capsule_capabilities   10
#define XEN_EFI_query_variable_info           9
#define XEN_EFI_set_time                      2
#define XEN_EFI_set_variable                  7
#define XEN_EFI_set_wakeup_time               4
#define XEN_EFI_update_capsule               11
#define XEN_FW_DISK_INFO          1 
#define XEN_FW_DISK_MBR_SIGNATURE 2 
#define  XEN_FW_EFI_CONFIG_TABLE   1
#define XEN_FW_EFI_INFO           4 
#define  XEN_FW_EFI_MEM_INFO       3
#define  XEN_FW_EFI_RT_VERSION     4
#define  XEN_FW_EFI_VENDOR         2
#define  XEN_FW_EFI_VERSION        0
#define XEN_FW_KBD_SHIFT_FLAGS    5 
#define XEN_FW_VBEDDC_INFO        3 
#define XEN_PCPU_FLAGS_INVALID  2
#define XEN_PCPU_FLAGS_ONLINE   1
#define XEN_PM_CX   0
#define XEN_PM_PDC  3
#define XEN_PM_PX   1
#define XEN_PM_TX   2
#define XEN_PX_PCT   1
#define XEN_PX_PPC   4
#define XEN_PX_PSD   8
#define XEN_PX_PSS   2

#define CONSOLEIO_read          1
#define CONSOLEIO_write         0
#define DOMID_COW  (0x7FF3U)
#define DOMID_FIRST_RESERVED (0x7FF0U)
#define DOMID_IDLE (0x7FFFU)
#define DOMID_INVALID (0x7FF4U)
#define DOMID_IO   (0x7FF1U)
#define DOMID_SELF (0x7FF0U)
#define DOMID_XEN  (0x7FF2U)
#define MAX_GUEST_CMDLINE 1024
#define MAX_VMASST_TYPE 5
#define MMUEXT_CLEAR_PAGE       16
#define MMUEXT_COPY_PAGE        17
#define MMUEXT_FLUSH_CACHE      12
#define MMUEXT_FLUSH_CACHE_GLOBAL 18
#define MMUEXT_INVLPG_ALL       11
#define MMUEXT_INVLPG_LOCAL      7
#define MMUEXT_INVLPG_MULTI      9
#define MMUEXT_MARK_SUPER       19
#define MMUEXT_NEW_BASEPTR       5
#define MMUEXT_NEW_USER_BASEPTR 15
#define MMUEXT_PIN_L1_TABLE      0
#define MMUEXT_PIN_L2_TABLE      1
#define MMUEXT_PIN_L3_TABLE      2
#define MMUEXT_PIN_L4_TABLE      3
#define MMUEXT_SET_LDT          13
#define MMUEXT_TLB_FLUSH_ALL    10
#define MMUEXT_TLB_FLUSH_LOCAL   6
#define MMUEXT_TLB_FLUSH_MULTI   8
#define MMUEXT_UNMARK_SUPER     20
#define MMUEXT_UNPIN_TABLE       4
#define MMU_MACHPHYS_UPDATE        1 
#define MMU_NORMAL_PT_UPDATE       0 
#define MMU_PT_UPDATE_NO_TRANSLATE 3 
#define MMU_PT_UPDATE_PRESERVE_AD  2 
#define NR_VIRQS       24
#define SIF_INITDOMAIN      (1<<1)  
#define SIF_MOD_START_PFN   (1<<3)  
#define SIF_MULTIBOOT_MOD   (1<<2)  
#define SIF_PM_MASK       (0xFF<<8) 
#define SIF_PRIVILEGED      (1<<0)  
#define SIF_VIRT_P2M_4TOOLS (1<<4)  
#define TMEM_SPEC_VERSION 1
#define UVMF_ALL                (1UL<<2) 
#define UVMF_FLUSHTYPE_MASK     (3UL<<0)
#define UVMF_INVLPG             (2UL<<0) 
#define UVMF_LOCAL              (0UL<<2) 
#define UVMF_MULTI              (0UL<<2) 
#define UVMF_NONE               (0UL<<0) 
#define UVMF_TLB_FLUSH          (1UL<<0) 
#define VIRQ_ARCH_0    16
#define VIRQ_ARCH_1    17
#define VIRQ_ARCH_2    18
#define VIRQ_ARCH_3    19
#define VIRQ_ARCH_4    20
#define VIRQ_ARCH_5    21
#define VIRQ_ARCH_6    22
#define VIRQ_ARCH_7    23
#define VIRQ_CONSOLE    2  
#define VIRQ_CON_RING   8  
#define VIRQ_DEBUG      1  
#define VIRQ_DEBUGGER   6  
#define VIRQ_DOM_EXC    3  
#define VIRQ_ENOMEM     12 
#define VIRQ_MEM_EVENT  10 
#define VIRQ_PCPU_STATE 9  
#define VIRQ_TBUF       4  
#define VIRQ_TIMER      0  
#define VIRQ_XC_RESERVED 11 
#define VIRQ_XENOPROF   7  
#define VIRQ_XENPMU     13  
#define VMASST_CMD_disable               1
#define VMASST_CMD_enable                0
#define VMASST_TYPE_4gb_segments         0
#define VMASST_TYPE_4gb_segments_notify  1
#define VMASST_TYPE_architectural_iopl   4
#define VMASST_TYPE_pae_extended_cr3     3
#define VMASST_TYPE_runstate_update_flag 5
#define VMASST_TYPE_writable_pagetables  2
#define XEN_VGATYPE_EFI_LFB     0x70
#define XEN_VGATYPE_TEXT_MODE_3 0x03
#define XEN_VGATYPE_VESA_LFB    0x23
#define __HYPERVISOR_arch_0               48
#define __HYPERVISOR_arch_1               49
#define __HYPERVISOR_arch_2               50
#define __HYPERVISOR_arch_3               51
#define __HYPERVISOR_arch_4               52
#define __HYPERVISOR_arch_5               53
#define __HYPERVISOR_arch_6               54
#define __HYPERVISOR_arch_7               55
#define __HYPERVISOR_callback_op          30
#define __HYPERVISOR_console_io           18
#define __HYPERVISOR_dm_op                41
#define __HYPERVISOR_domctl               36
#define __HYPERVISOR_event_channel_op     32
#define __HYPERVISOR_event_channel_op_compat 16
#define __HYPERVISOR_fpu_taskswitch        5
#define __HYPERVISOR_get_debugreg          9
#define __HYPERVISOR_grant_table_op       20
#define __HYPERVISOR_hvm_op               34
#define __HYPERVISOR_iret                 23 
#define __HYPERVISOR_kexec_op             37
#define __HYPERVISOR_memory_op            12
#define __HYPERVISOR_mmu_update            1
#define __HYPERVISOR_mmuext_op            26
#define __HYPERVISOR_multicall            13
#define __HYPERVISOR_nmi_op               28
#define __HYPERVISOR_physdev_op           33
#define __HYPERVISOR_physdev_op_compat    19
#define __HYPERVISOR_platform_op           7
#define __HYPERVISOR_sched_op             29
#define __HYPERVISOR_sched_op_compat       6
#define __HYPERVISOR_set_callbacks         4
#define __HYPERVISOR_set_debugreg          8
#define __HYPERVISOR_set_gdt               2
#define __HYPERVISOR_set_segment_base     25 
#define __HYPERVISOR_set_timer_op         15
#define __HYPERVISOR_set_trap_table        0
#define __HYPERVISOR_stack_switch          3
#define __HYPERVISOR_sysctl               35
#define __HYPERVISOR_tmem_op              38
#define __HYPERVISOR_update_descriptor    10
#define __HYPERVISOR_update_va_mapping    14
#define __HYPERVISOR_update_va_mapping_otherdomain 22
#define __HYPERVISOR_vcpu_op              24
#define __HYPERVISOR_vm_assist            21
#define __HYPERVISOR_xc_reserved_op       39 
#define __HYPERVISOR_xen_version          17
#define __HYPERVISOR_xenoprof_op          31
#define __HYPERVISOR_xenpmu_op            40
#define __HYPERVISOR_xsm_op               27

#define __mk_unsigned_long(x) x ## UL
#define mk_unsigned_long(x) x

#define THERMAL_CSTATE_INVALID -1UL
#define THERMAL_WEIGHT_DEFAULT 0

#define THERMAL_GENL_ATTR_MAX (__THERMAL_GENL_ATTR_MAX - 1)
#define THERMAL_GENL_CMD_MAX (__THERMAL_GENL_CMD_MAX - 1)
#define THERMAL_GENL_EVENT_MAX (__THERMAL_GENL_EVENT_MAX - 1)
#define THERMAL_GENL_SAMPLING_MAX (__THERMAL_GENL_SAMPLING_MAX - 1)


#define CPUFREQ_RELATION_C 2  
#define CPUFREQ_RELATION_CE (CPUFREQ_RELATION_C | CPUFREQ_RELATION_E)
#define CPUFREQ_RELATION_E BIT(2) 
#define CPUFREQ_RELATION_H 1  
#define CPUFREQ_RELATION_HE (CPUFREQ_RELATION_H | CPUFREQ_RELATION_E)
#define CPUFREQ_RELATION_L 0  
#define CPUFREQ_RELATION_LE (CPUFREQ_RELATION_L | CPUFREQ_RELATION_E)
#define CPUFREQ_SHARED_TYPE_NONE (0) 

#define cpufreq_for_each_efficient_entry_idx(pos, table, idx, efficiencies)	\
	cpufreq_for_each_valid_entry_idx(pos, table, idx)			\
		if (efficiencies && (pos->flags & CPUFREQ_INEFFICIENT_FREQ))	\
			continue;						\
		else
#define cpufreq_for_each_entry(pos, table)	\
	for (pos = table; pos->frequency != CPUFREQ_TABLE_END; pos++)
#define cpufreq_for_each_entry_idx(pos, table, idx)	\
	for (pos = table, idx = 0; pos->frequency != CPUFREQ_TABLE_END; \
		pos++, idx++)
#define cpufreq_for_each_valid_entry(pos, table)			\
	for (pos = table; pos->frequency != CPUFREQ_TABLE_END; pos++)	\
		if (pos->frequency == CPUFREQ_ENTRY_INVALID)		\
			continue;					\
		else
#define cpufreq_for_each_valid_entry_idx(pos, table, idx)		\
	cpufreq_for_each_entry_idx(pos, table, idx)			\
		if (pos->frequency == CPUFREQ_ENTRY_INVALID)		\
			continue;					\
		else
#define cpufreq_freq_attr_ro(_name)		\
static struct freq_attr _name =			\
__ATTR(_name, 0444, show_##_name, NULL)
#define cpufreq_freq_attr_ro_perm(_name, _perm)	\
static struct freq_attr _name =			\
__ATTR(_name, _perm, show_##_name, NULL)
#define cpufreq_freq_attr_rw(_name)		\
static struct freq_attr _name =			\
__ATTR(_name, 0644, show_##_name, store_##_name)
#define cpufreq_freq_attr_wo(_name)		\
static struct freq_attr _name =			\
__ATTR(_name, 0200, NULL, store_##_name)
#define cpufreq_governor_exit(__governor)			\
static void __exit __governor##_exit(void)			\
{								\
	return cpufreq_unregister_governor(&__governor);	\
}								\
module_exit(__governor##_exit)
#define cpufreq_governor_init(__governor)			\
static int __init __governor##_init(void)			\
{								\
	return cpufreq_register_governor(&__governor);	\
}								\
core_initcall(__governor##_init)
#define define_one_global_ro(_name)		\
static struct kobj_attribute _name =		\
__ATTR(_name, 0444, show_##_name, NULL)
#define define_one_global_rw(_name)		\
static struct kobj_attribute _name =		\
__ATTR(_name, 0644, show_##_name, store_##_name)


#define OF_DEV_AUXDATA(_compat,_phys,_name,_pdata) \
	{ .compatible = _compat, .phys_addr = _phys, .name = _name, \
	  .platform_data = _pdata }

#define USE_PLATFORM_PM_SLEEP_OPS \
	.suspend = platform_pm_suspend, \
	.resume = platform_pm_resume, \
	.freeze = platform_pm_freeze, \
	.thaw = platform_pm_thaw, \
	.poweroff = platform_pm_poweroff, \
	.restore = platform_pm_restore,

#define builtin_platform_driver(__platform_driver) \
	builtin_driver(__platform_driver, platform_driver_register)
#define builtin_platform_driver_probe(__platform_driver, __platform_probe) \
static int __init __platform_driver##_init(void) \
{ \
	return platform_driver_probe(&(__platform_driver), \
				     __platform_probe);    \
} \
device_initcall(__platform_driver##_init); \

#define dev_is_platform(dev) ((dev)->bus == &platform_bus_type)
#define module_platform_driver(__platform_driver) \
	module_driver(__platform_driver, platform_driver_register, \
			platform_driver_unregister)
#define module_platform_driver_probe(__platform_driver, __platform_probe) \
static int __init __platform_driver##_init(void) \
{ \
	return platform_driver_probe(&(__platform_driver), \
				     __platform_probe);    \
} \
module_init(__platform_driver##_init); \
static void __exit __platform_driver##_exit(void) \
{ \
	platform_driver_unregister(&(__platform_driver)); \
} \
module_exit(__platform_driver##_exit);
#define platform_create_bundle(driver, probe, res, n_res, data, size) \
	__platform_create_bundle(driver, probe, res, n_res, data, size, THIS_MODULE)
#define platform_driver_probe(drv, probe) \
	__platform_driver_probe(drv, probe, THIS_MODULE)
#define platform_driver_register(drv) \
	__platform_driver_register(drv, THIS_MODULE)
#define platform_get_device_id(pdev)	((pdev)->id_entry)
#define platform_register_drivers(drivers, count) \
	__platform_register_drivers(drivers, count, THIS_MODULE)
#define to_platform_device(x) container_of((x), struct platform_device, dev)
#define to_platform_driver(drv)	(container_of((drv), struct platform_driver, \
				 driver))




#define ACPI_TABLE_UPGRADE_MAX_PHYS (max_low_pfn_mapped << PAGE_SHIFT)

#define acpi_disable_cmcff 0
#define acpi_ioapic 0
#define acpi_lapic 0


#define default_find_smp_config x86_init_noop
#define default_get_smp_config x86_init_uint_noop
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
#define		GET_APIC_VERSION(x)	((x) & 0xFFu)
# define MAX_IO_APICS 64
# define MAX_LOCAL_APIC 256
#define		SET_APIC_DELIVERY_MODE(x, y)	(((x) & ~0x700) | ((y) << 8))
#define		SET_APIC_DEST_FIELD(x)	((x) << 24)
#define		SET_APIC_LOGICAL_ID(x)	(((x) << 24))

#define u32 unsigned int
# define MAX_MPC_ENTRY 1024
#define MPC_OEM_SIGNATURE "_OEM"
#define MPC_SIGNATURE "PCMP"

#define INIT_MM_CONTEXT(mm)						\
	.context = {							\
		.ctx_id = 1,						\
		.lock = __MUTEX_INITIALIZER(mm.context.lock),		\
	}

#define leave_mm leave_mm
# define ARCH_HAS_PREFETCH


#define GET_TSC_CTL(adr)	get_tsc_mode((adr))
#define HAVE_ARCH_PICK_MMAP_LAYOUT 1
#define HBP_NUM 4
#define INIT_THREAD  {							  \
	.sp0			= TOP_OF_INIT_STACK,			  \
	.sysenter_cs		= __KERNEL_CS,				  \
}
#define KSTK_EIP(task)		(task_pt_regs(task)->ip)
#define KSTK_ESP(task)		(task_pt_regs(task)->sp)
#define SET_TSC_CTL(val)	set_tsc_mode((val))
#define TASK_UNMAPPED_BASE		__TASK_UNMAPPED_BASE(TASK_SIZE_LOW)
#define TOP_OF_INIT_STACK ((unsigned long)&init_stack + sizeof(init_stack) - \
			   TOP_OF_KERNEL_STACK_PADDING)

#define __TASK_UNMAPPED_BASE(task_size)	(PAGE_ALIGN(task_size / 3))
#define arch_is_platform_page arch_is_platform_page
#define arch_memory_failure arch_memory_failure
#define cache_line_size()	(boot_cpu_data.x86_cache_alignment)
#define cpu_data(cpu)		per_cpu(cpu_info, cpu)
#define for_each_possible_hypervisor_cpuid_base(function) \
	for (function = 0x40000000; function < 0x40010000; function += 0x100)
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
#define PARA_INDIRECT(addr)	*addr(%rip)
#define PARA_PATCH(off)		((off) / 8)
#define PARA_SITE(ptype, ops)	_PVSITE(ptype, ops, .quad, 8)
#define PV_CALLEE_SAVE(func)						\
	((struct paravirt_callee_save) { __raw_callee_save_##func })
#define PV_CALLEE_SAVE_REGS_THUNK(func)			\
	__PV_CALLEE_SAVE_REGS_THUNK(func, ".text")
#define PV_THUNK_NAME(func) "__raw_callee_save_" #func

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
#define __PV_CALLEE_SAVE_REGS_THUNK(func, section)			\
	extern typeof(func) __raw_callee_save_##func;			\
									\
	asm(".pushsection " section ", \"ax\";"				\
	    ".globl " PV_THUNK_NAME(func) ";"				\
	    ".type " PV_THUNK_NAME(func) ", @function;"			\
	    PV_THUNK_NAME(func) ":"					\
	    ASM_ENDBR							\
	    FRAME_BEGIN							\
	    PV_SAVE_ALL_CALLER_REGS					\
	    "call " #func ";"						\
	    PV_RESTORE_ALL_CALLER_REGS					\
	    FRAME_END							\
	    ASM_RET							\
	    ".size " PV_THUNK_NAME(func) ", .-" PV_THUNK_NAME(func) ";"	\
	    ".popsection")
#define __PV_IS_CALLEE_SAVE(func)			\
	((struct paravirt_callee_save) { func })
#define get_debugreg(var, reg) var = paravirt_get_debugreg(reg)
#define pgd_clear(pgdp) do {						\
	if (pgtable_l5_enabled())					\
		set_pgd(pgdp, native_make_pgd(0));			\
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
#define FRAME_OFFSET 0

#define CLBR_ANY  ((1 << 4) - 1)
#define CLBR_EAX  (1 << 0)
#define CLBR_ECX  (1 << 1)
#define CLBR_EDI  (1 << 3)
#define CLBR_EDX  (1 << 2)
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
#define PVOP_ALT_CALL0(rettype, op, alt, cond)				\
	__PVOP_ALT_CALL(rettype, op, alt, cond)
#define PVOP_ALT_CALLEE0(rettype, op, alt, cond)			\
	__PVOP_ALT_CALLEESAVE(rettype, op, alt, cond)
#define PVOP_ALT_CALLEE1(rettype, op, arg1, alt, cond)			\
	__PVOP_ALT_CALLEESAVE(rettype, op, alt, cond, PVOP_CALL_ARG1(arg1))
#define PVOP_ALT_VCALL0(op, alt, cond)					\
	__PVOP_ALT_VCALL(op, alt, cond)
#define PVOP_ALT_VCALL1(op, arg1, alt, cond)				\
	__PVOP_ALT_VCALL(op, alt, cond, PVOP_CALL_ARG1(arg1))
#define PVOP_ALT_VCALLEE0(op, alt, cond)				\
	__PVOP_ALT_VCALLEESAVE(op, alt, cond)
#define PVOP_ALT_VCALLEE1(op, arg1, alt, cond)				\
	__PVOP_ALT_VCALLEESAVE(op, alt, cond, PVOP_CALL_ARG1(arg1))
#define PVOP_CALL0(rettype, op)						\
	__PVOP_CALL(rettype, op)
#define PVOP_CALL1(rettype, op, arg1)					\
	__PVOP_CALL(rettype, op, PVOP_CALL_ARG1(arg1))
#define PVOP_CALL2(rettype, op, arg1, arg2)				\
	__PVOP_CALL(rettype, op, PVOP_CALL_ARG1(arg1), PVOP_CALL_ARG2(arg2))
#define PVOP_CALL3(rettype, op, arg1, arg2, arg3)			\
	__PVOP_CALL(rettype, op, PVOP_CALL_ARG1(arg1),			\
		    PVOP_CALL_ARG2(arg2), PVOP_CALL_ARG3(arg3))
#define PVOP_CALL4(rettype, op, arg1, arg2, arg3, arg4)			\
	__PVOP_CALL(rettype, op,					\
		    PVOP_CALL_ARG1(arg1), PVOP_CALL_ARG2(arg2),		\
		    PVOP_CALL_ARG3(arg3), PVOP_CALL_ARG4(arg4))
#define PVOP_CALLEE0(rettype, op)					\
	__PVOP_CALLEESAVE(rettype, op)
#define PVOP_CALLEE1(rettype, op, arg1)					\
	__PVOP_CALLEESAVE(rettype, op, PVOP_CALL_ARG1(arg1))
#define PVOP_CALL_ARG1(x)		"a" ((unsigned long)(x))
#define PVOP_CALL_ARG2(x)		"d" ((unsigned long)(x))
#define PVOP_CALL_ARG3(x)		"c" ((unsigned long)(x))
#define PVOP_CALL_ARG4(x)		"c" ((unsigned long)(x))
#define PVOP_RETVAL(rettype)						\
	({	unsigned long __mask = ~0UL;				\
		BUILD_BUG_ON(sizeof(rettype) > sizeof(unsigned long));	\
		switch (sizeof(rettype)) {				\
		case 1: __mask =       0xffUL; break;			\
		case 2: __mask =     0xffffUL; break;			\
		case 4: __mask = 0xffffffffUL; break;			\
		default: break;						\
		}							\
		__mask & __eax;						\
	})
#define PVOP_TEST_NULL(op)	BUG_ON(pv_ops.op == NULL)
#define PVOP_VCALL0(op)							\
	__PVOP_VCALL(op)
#define PVOP_VCALL1(op, arg1)						\
	__PVOP_VCALL(op, PVOP_CALL_ARG1(arg1))
#define PVOP_VCALL2(op, arg1, arg2)					\
	__PVOP_VCALL(op, PVOP_CALL_ARG1(arg1), PVOP_CALL_ARG2(arg2))
#define PVOP_VCALL3(op, arg1, arg2, arg3)				\
	__PVOP_VCALL(op, PVOP_CALL_ARG1(arg1),				\
		     PVOP_CALL_ARG2(arg2), PVOP_CALL_ARG3(arg3))
#define PVOP_VCALL4(op, arg1, arg2, arg3, arg4)				\
	__PVOP_VCALL(op, PVOP_CALL_ARG1(arg1), PVOP_CALL_ARG2(arg2),	\
		     PVOP_CALL_ARG3(arg3), PVOP_CALL_ARG4(arg4))
#define PVOP_VCALLEE0(op)						\
	__PVOP_VCALLEESAVE(op)
#define PVOP_VCALLEE1(op, arg1)						\
	__PVOP_VCALLEESAVE(op, PVOP_CALL_ARG1(arg1))


#define __PVOP_ALT_CALL(rettype, op, alt, cond, ...)			\
	____PVOP_ALT_CALL(PVOP_RETVAL(rettype), op, alt, cond, CLBR_ANY,\
			  PVOP_CALL_CLOBBERS, EXTRA_CLOBBERS,		\
			  ##__VA_ARGS__)
#define __PVOP_ALT_CALLEESAVE(rettype, op, alt, cond, ...)		\
	____PVOP_ALT_CALL(PVOP_RETVAL(rettype), op.func, alt, cond,	\
			  CLBR_RET_REG, PVOP_CALLEE_CLOBBERS, , ##__VA_ARGS__)
#define __PVOP_ALT_VCALL(op, alt, cond, ...)				\
	(void)____PVOP_ALT_CALL(, op, alt, cond, CLBR_ANY,		\
				PVOP_VCALL_CLOBBERS, VEXTRA_CLOBBERS,	\
				##__VA_ARGS__)
#define __PVOP_ALT_VCALLEESAVE(op, alt, cond, ...)			\
	(void)____PVOP_ALT_CALL(, op.func, alt, cond, CLBR_RET_REG,	\
				PVOP_VCALLEE_CLOBBERS, , ##__VA_ARGS__)
#define __PVOP_CALL(rettype, op, ...)					\
	____PVOP_CALL(PVOP_RETVAL(rettype), op, CLBR_ANY,		\
		      PVOP_CALL_CLOBBERS, EXTRA_CLOBBERS, ##__VA_ARGS__)
#define __PVOP_CALLEESAVE(rettype, op, ...)				\
	____PVOP_CALL(PVOP_RETVAL(rettype), op.func, CLBR_RET_REG,	\
		      PVOP_CALLEE_CLOBBERS, , ##__VA_ARGS__)
#define __PVOP_VCALL(op, ...)						\
	(void)____PVOP_CALL(, op, CLBR_ANY, PVOP_VCALL_CLOBBERS,	\
		       VEXTRA_CLOBBERS, ##__VA_ARGS__)
#define __PVOP_VCALLEESAVE(op, ...)					\
	(void)____PVOP_CALL(, op.func, CLBR_RET_REG,			\
			    PVOP_VCALLEE_CLOBBERS, , ##__VA_ARGS__)
#define ____PVOP_ALT_CALL(ret, op, alt, cond, clbr, call_clbr,		\
			  extra_clbr, ...)				\
	({								\
		PVOP_CALL_ARGS;						\
		PVOP_TEST_NULL(op);					\
		asm volatile(ALTERNATIVE(paravirt_alt(PARAVIRT_CALL),	\
					 alt, cond)			\
			     : call_clbr, ASM_CALL_CONSTRAINT		\
			     : paravirt_type(op),			\
			       paravirt_clobber(clbr),			\
			       ##__VA_ARGS__				\
			     : "memory", "cc" extra_clbr);		\
		ret;							\
	})
#define ____PVOP_CALL(ret, op, clbr, call_clbr, extra_clbr, ...)	\
	({								\
		PVOP_CALL_ARGS;						\
		PVOP_TEST_NULL(op);					\
		asm volatile(paravirt_alt(PARAVIRT_CALL)		\
			     : call_clbr, ASM_CALL_CONSTRAINT		\
			     : paravirt_type(op),			\
			       paravirt_clobber(clbr),			\
			       ##__VA_ARGS__				\
			     : "memory", "cc" extra_clbr);		\
		ret;							\
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
	[paravirt_opptr] "m" (pv_ops.op)



# define CALL_NOSPEC "call *%[thunk_target]\n"
#define GEN(reg) \
	extern retpoline_thunk_t __x86_indirect_thunk_ ## reg;
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
#define EARLY_IDT_HANDLER_SIZE (9 + ENDBR_INSN_SIZE)
#define GDT_ENTRY(flags, base, limit)			\
	((((base)  & _AC(0xff000000,ULL)) << (56-24)) |	\
	 (((flags) & _AC(0x0000f0ff,ULL)) << 40) |	\
	 (((limit) & _AC(0x000f0000,ULL)) << (48-16)) |	\
	 (((base)  & _AC(0x00ffffff,ULL)) << 16) |	\
	 (((limit) & _AC(0x0000ffff,ULL))))
#define GDT_ENTRY_TLS_MAX 		(GDT_ENTRY_TLS_MIN + GDT_ENTRY_TLS_ENTRIES - 1)
#define SEGMENT_IS_PNP_CODE(x)		(((x) & 0xf4) == PNP_CS32)
#define XEN_EARLY_IDT_HANDLER_SIZE (8 + ENDBR_INSN_SIZE)

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
		     _ASM_EXTABLE_TYPE_REG(1b, 1b, EX_TYPE_ZERO_REG, %k0)\
		     : "+r" (__val) : : "memory");			\
} while (0)
#define __loadsegment_ss(value) __loadsegment_simple(ss, (value))
#define loadsegment(seg, value) __loadsegment_ ## seg (value)
#define savesegment(seg, value)				\
	asm("mov %%" #seg ",%0":"=r" (value) : : "memory")
#define INTERNODE_CACHE_BYTES (1 << INTERNODE_CACHE_SHIFT)
#define INTERNODE_CACHE_SHIFT CONFIG_X86_INTERNODE_CACHE_SHIFT

#define __read_mostly __section(".data..read_mostly")




#define UNWIND_HINT_FUNC \
	UNWIND_HINT(ORC_REG_SP, 8, UNWIND_HINT_TYPE_FUNC, 0)

#define STACK_FRAME_NON_STANDARD(func) \
	static void __used __section(".discard.func_stack_frame_non_standard") \
		*__func_stack_frame_non_standard_##func = func
#define STACK_FRAME_NON_STANDARD_FP(func) STACK_FRAME_NON_STANDARD(func)
#define UNWIND_HINT(sp_reg, sp_offset, type, end)		\
	"987: \n\t"						\
	".pushsection .discard.unwind_hints\n\t"		\
					\
	".long 987b - .\n\t"					\
	".short " __stringify(sp_offset) "\n\t"			\
	".byte " __stringify(sp_reg) "\n\t"			\
	".byte " __stringify(type) "\n\t"			\
	".byte " __stringify(end) "\n\t"			\
	".balign 4 \n\t"					\
	".popsection\n\t"

#define AMD_CPPC_DES_PERF(x)		(((x) & 0xff) << 16)
#define AMD_CPPC_ENERGY_PERF_PREF(x)	(((x) & 0xff) << 24)
#define AMD_CPPC_HIGHEST_PERF(x)	(((x) >> 24) & 0xff)
#define AMD_CPPC_LOWEST_PERF(x)		(((x) >> 0) & 0xff)
#define AMD_CPPC_LOWNONLIN_PERF(x)	(((x) >> 8) & 0xff)
#define AMD_CPPC_MAX_PERF(x)		(((x) & 0xff) << 0)
#define AMD_CPPC_MIN_PERF(x)		(((x) & 0xff) << 8)
#define AMD_CPPC_NOMINAL_PERF(x)	(((x) >> 16) & 0xff)
#define ARCH_LBR_CTL_CPL		(0x3ull << ARCH_LBR_CTL_CPL_OFFSET)
#define ARCH_LBR_CTL_FILTER		(0x7full << ARCH_LBR_CTL_FILTER_OFFSET)
#define ARCH_LBR_CTL_STACK		(0x1ull << ARCH_LBR_CTL_STACK_OFFSET)
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
#define LBR_INFO_BR_TYPE		(0xfull << LBR_INFO_BR_TYPE_OFFSET)
#define MSR_AMD64_MCx_MASK(x)		(MSR_AMD64_MC0_MASK + (x))
#define MSR_AMD64_SEV_ENABLED		BIT_ULL(MSR_AMD64_SEV_ENABLED_BIT)
#define MSR_CORE_PERF_GLOBAL_OVF_CTRL_COND_CHGD			(1ULL << MSR_CORE_PERF_GLOBAL_OVF_CTRL_COND_CHGD_BIT)
#define MSR_CORE_PERF_GLOBAL_OVF_CTRL_OVF_BUF			(1ULL <<  MSR_CORE_PERF_GLOBAL_OVF_CTRL_OVF_BUF_BIT)
#define MSR_CORE_PERF_GLOBAL_OVF_CTRL_TRACE_TOPA_PMI		(1ULL << MSR_CORE_PERF_GLOBAL_OVF_CTRL_TRACE_TOPA_PMI_BIT)
#define MSR_F10H_DECFG_LFENCE_SERIALIZE		BIT_ULL(MSR_F10H_DECFG_LFENCE_SERIALIZE_BIT)
#define MSR_F15H_CU_MAX_PWR_ACCUMULATOR 0xc001007b
#define MSR_F15H_CU_PWR_ACCUMULATOR     0xc001007a
#define MSR_HWP_REQUEST 		0x00000774
#define MSR_IA32_CORE_CAPS_INTEGRITY_CAPS	  BIT(MSR_IA32_CORE_CAPS_INTEGRITY_CAPS_BIT)
#define MSR_IA32_CORE_CAPS_SPLIT_LOCK_DETECT	  BIT(MSR_IA32_CORE_CAPS_SPLIT_LOCK_DETECT_BIT)
#define MSR_IA32_CORE_CAPS_SPLIT_LOCK_DETECT_BIT  5
#define MSR_IA32_HW_FEEDBACK_CONFIG     0x17d1
#define MSR_IA32_HW_FEEDBACK_PTR        0x17d0
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
#define MSR_TFA_SDV_ENABLE_RTM		BIT_ULL(MSR_TFA_SDV_ENABLE_RTM_BIT)
#define MSR_TFA_TSX_CPUID_CLEAR		BIT_ULL(MSR_TFA_TSX_CPUID_CLEAR_BIT)
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

#define PAGE_COPY_NOEXEC     __pg(__PP|   0|_USR|___A|__NX|   0|   0|   0)
#define PAGE_KERNEL		__pgprot_mask(__PAGE_KERNEL            | _ENC)
#define PAGE_KERNEL_IO		__pgprot_mask(__PAGE_KERNEL_IO)
#define PAGE_KERNEL_RO		__pgprot_mask(__PAGE_KERNEL_RO         | _ENC)
#define PAGE_KERNEL_ROX		__pgprot_mask(__PAGE_KERNEL_ROX        | _ENC)
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
#define pud_pgtable(pud)			((pmd_t *)(pmd_page_vaddr((pmd_t){ pud })))
#define pud_populate(mm, pmd, pte)		do { } while (0)
#define set_pud(pudptr, pudval)			set_pmd((pmd_t *)(pudptr), (pmd_t) { pudval })
#define PUD_MASK  	(~(PUD_SIZE-1))
#define PUD_SIZE  	(1UL << PUD_SHIFT)

#define __PAGETABLE_PUD_FOLDED 1
#define __pud(x)				((pud_t) { __p4d(x) })
#define p4d_page(p4d)				(pud_page((pud_t){ p4d }))
#define p4d_pgtable(p4d)			((pud_t *)(pud_pgtable((pud_t){ p4d })))
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
#define pgd_page_vaddr(pgd)			((unsigned long)(p4d_pgtable((p4d_t){ pgd })))
#define pgd_populate(mm, pgd, p4d)		do { } while (0)
#define pgd_populate_safe(mm, pgd, p4d)		do { } while (0)
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


#define personality(pers)	(pers & PER_MASK)
#define set_personality(pers)	(current->personality = (pers))
#define PER_CLEAR_ON_SETID (READ_IMPLIES_EXEC  | \
			    ADDR_NO_RANDOMIZE  | \
			    ADDR_COMPAT_LAYOUT | \
			    MMAP_PAGE_ZERO)


#define VMX_FEATURE_INTR_WINDOW_EXITING ( 1*32+  2) 

#define MXCSR_AND_FLAGS_SIZE sizeof(u64)
#define XCOMP_BV_COMPACTED_FORMAT ((u64)1 << 63)
# define XFEATURE_MASK_XTILE		(XFEATURE_MASK_XTILE_DATA \
					 | XFEATURE_MASK_XTILE_CFG)


#define __FORCE_ORDER "m"(*(unsigned int *)0x1000UL)
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
#define X86_CR4_CET		_BITUL(X86_CR4_CET_BIT)
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

#define ASM_NOP1 _ASM_BYTES(BYTES_NOP1)
#define ASM_NOP2 _ASM_BYTES(BYTES_NOP2)
#define ASM_NOP3 _ASM_BYTES(BYTES_NOP3)
#define ASM_NOP4 _ASM_BYTES(BYTES_NOP4)
#define ASM_NOP5 _ASM_BYTES(BYTES_NOP5)
#define ASM_NOP6 _ASM_BYTES(BYTES_NOP6)
#define ASM_NOP7 _ASM_BYTES(BYTES_NOP7)
#define ASM_NOP8 _ASM_BYTES(BYTES_NOP8)
#define ASM_NOP_MAX 8

#define DECLARE_ARGS(val, low, high)	unsigned long low, high
#define EAX_EDX_RET(val, low, high)	"=a" (low), "=d" (high)
#define EAX_EDX_VAL(val, low, high)	((low) | (high) << 32)

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

#define __dma_rmb()	barrier()
#define __dma_wmb()	barrier()
#define __mb()	asm volatile("mfence":::"memory")
#define __rmb()	asm volatile("lfence":::"memory")
#define __smp_load_acquire(p)						\
({									\
	typeof(*p) ___p1 = READ_ONCE(*p);				\
	compiletime_assert_atomic_type(*p);				\
	barrier();							\
	___p1;								\
})
#define __smp_mb()	asm volatile("lock; addl $0,-4(%%" _ASM_SP ")" ::: "memory", "cc")
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
#define __wmb()	asm volatile("sfence" ::: "memory")
#define array_index_mask_nospec array_index_mask_nospec
#define barrier_nospec() alternative("", "lfence", X86_FEATURE_LFENCE_RDTSC)
#define mb() asm volatile(ALTERNATIVE("lock; addl $0,-4(%%esp)", "mfence", \
				      X86_FEATURE_XMM2) ::: "memory", "cc")
#define rmb() asm volatile(ALTERNATIVE("lock; addl $0,-4(%%esp)", "lfence", \
				       X86_FEATURE_XMM2) ::: "memory", "cc")
#define wmb() asm volatile(ALTERNATIVE("lock; addl $0,-4(%%esp)", "sfence", \
				       X86_FEATURE_XMM2) ::: "memory", "cc")

#define dma_rmb()	rmb()
#define dma_wmb()	wmb()
#define io_stop_wc() do { } while (0)
#define pmem_wmb()	wmb()
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
#define virt_mb() do { kcsan_mb(); __smp_mb(); } while (0)
#define virt_mb__after_atomic()	do { kcsan_mb(); __smp_mb__after_atomic(); } while (0)
#define virt_mb__before_atomic() do { kcsan_mb(); __smp_mb__before_atomic(); } while (0)
#define virt_rmb() do { kcsan_rmb(); __smp_rmb(); } while (0)
#define virt_store_mb(var, value) do { kcsan_mb(); __smp_store_mb(var, value); } while (0)
#define virt_store_release(p, v) do { kcsan_release(); __smp_store_release(p, v); } while (0)
#define virt_wmb() do { kcsan_wmb(); __smp_wmb(); } while (0)
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
#define arch_try_cmpxchg(ptr, pold, new) 				\
	__try_cmpxchg((ptr), (pold), (new), sizeof(*(ptr)))
#define arch_xchg(ptr, v)	__xchg_op((ptr), (v), xchg, "")
#define xadd(ptr, inc)		__xadd((ptr), (inc), LOCK_PREFIX)



#define arch_cpu_is_offline(cpu)	unlikely(!arch_cpu_online(cpu))
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

#define __pcpu_cast_1(val) ((u8)(((unsigned long) val) & 0xff))
#define __pcpu_cast_2(val) ((u16)(((unsigned long) val) & 0xffff))
#define __pcpu_cast_4(val) ((u32)(((unsigned long) val) & 0xffffffff))
#define __pcpu_cast_8(val) ((u64)(val))
#define __pcpu_op1_1(op, dst) op "b " dst
#define __pcpu_op1_2(op, dst) op "w " dst
#define __pcpu_op1_4(op, dst) op "l " dst
#define __pcpu_op1_8(op, dst) op "q " dst
#define __pcpu_op2_1(op, src, dst) op "b " src ", " dst
#define __pcpu_op2_2(op, src, dst) op "w " src ", " dst
#define __pcpu_op2_4(op, src, dst) op "l " src ", " dst
#define __pcpu_op2_8(op, src, dst) op "q " src ", " dst
#define __pcpu_reg_1(mod, x) mod "q" (x)
#define __pcpu_reg_2(mod, x) mod "r" (x)
#define __pcpu_reg_4(mod, x) mod "r" (x)
#define __pcpu_reg_8(mod, x) mod "r" (x)
#define __pcpu_reg_imm_1(x) "qi" (x)
#define __pcpu_reg_imm_2(x) "ri" (x)
#define __pcpu_reg_imm_4(x) "ri" (x)
#define __pcpu_reg_imm_8(x) "re" (x)
#define __pcpu_type_1 u8
#define __pcpu_type_2 u16
#define __pcpu_type_4 u32
#define __pcpu_type_8 u64
#define __percpu_arg(x)		__percpu_prefix "%" #x
#define arch_raw_cpu_ptr(ptr)				\
({							\
	unsigned long tcp_ptr__;			\
	asm ("add " __percpu_arg(1) ", %0"		\
	     : "=r" (tcp_ptr__)				\
	     : "m" (this_cpu_off), "0" (ptr));		\
	(typeof(*(ptr)) __kernel __force *)tcp_ptr__;	\
})
#define init_per_cpu_var(var)  init_per_cpu__##var
#define percpu_add_op(size, qual, var, val)				\
do {									\
	const int pao_ID__ = (__builtin_constant_p(val) &&		\
			      ((val) == 1 || (val) == -1)) ?		\
				(int)(val) : 0;				\
	if (0) {							\
		typeof(var) pao_tmp__;					\
		pao_tmp__ = (val);					\
		(void)pao_tmp__;					\
	}								\
	if (pao_ID__ == 1)						\
		percpu_unary_op(size, qual, "inc", var);		\
	else if (pao_ID__ == -1)					\
		percpu_unary_op(size, qual, "dec", var);		\
	else								\
		percpu_to_op(size, qual, "add", var, val);		\
} while (0)
#define percpu_add_return_op(size, qual, _var, _val)			\
({									\
	__pcpu_type_##size paro_tmp__ = __pcpu_cast_##size(_val);	\
	asm qual (__pcpu_op2_##size("xadd", "%[tmp]",			\
				     __percpu_arg([var]))		\
		  : [tmp] __pcpu_reg_##size("+", paro_tmp__),		\
		    [var] "+m" (_var)					\
		  : : "memory");					\
	(typeof(_var))(unsigned long) (paro_tmp__ + _val);		\
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
#define percpu_cmpxchg_op(size, qual, _var, _oval, _nval)		\
({									\
	__pcpu_type_##size pco_old__ = __pcpu_cast_##size(_oval);	\
	__pcpu_type_##size pco_new__ = __pcpu_cast_##size(_nval);	\
	asm qual (__pcpu_op2_##size("cmpxchg", "%[nval]",		\
				    __percpu_arg([var]))		\
		  : [oval] "+a" (pco_old__),				\
		    [var] "+m" (_var)					\
		  : [nval] __pcpu_reg_##size(, pco_new__)		\
		  : "memory");						\
	(typeof(_var))(unsigned long) pco_old__;			\
})
#define percpu_from_op(size, qual, op, _var)				\
({									\
	__pcpu_type_##size pfo_val__;					\
	asm qual (__pcpu_op2_##size(op, __percpu_arg([var]), "%[val]")	\
	    : [val] __pcpu_reg_##size("=", pfo_val__)			\
	    : [var] "m" (_var));					\
	(typeof(_var))(unsigned long) pfo_val__;			\
})
#define percpu_stable_op(size, op, _var)				\
({									\
	__pcpu_type_##size pfo_val__;					\
	asm(__pcpu_op2_##size(op, __percpu_arg(P[var]), "%[val]")	\
	    : [val] __pcpu_reg_##size("=", pfo_val__)			\
	    : [var] "p" (&(_var)));					\
	(typeof(_var))(unsigned long) pfo_val__;			\
})
#define percpu_to_op(size, qual, op, _var, _val)			\
do {									\
	__pcpu_type_##size pto_val__ = __pcpu_cast_##size(_val);	\
	if (0) {		                                        \
		typeof(_var) pto_tmp__;					\
		pto_tmp__ = (_val);					\
		(void)pto_tmp__;					\
	}								\
	asm qual(__pcpu_op2_##size(op, "%[val]", __percpu_arg([var]))	\
	    : [var] "+m" (_var)						\
	    : [val] __pcpu_reg_imm_##size(pto_val__));			\
} while (0)
#define percpu_unary_op(size, qual, op, _var)				\
({									\
	asm qual (__pcpu_op1_##size(op, __percpu_arg([var]))		\
	    : [var] "+m" (_var));					\
})
#define percpu_xchg_op(size, qual, _var, _nval)				\
({									\
	__pcpu_type_##size pxo_old__;					\
	__pcpu_type_##size pxo_new__ = __pcpu_cast_##size(_nval);	\
	asm qual (__pcpu_op2_##size("mov", __percpu_arg([var]),		\
				    "%[oval]")				\
		  "\n1:\t"						\
		  __pcpu_op2_##size("cmpxchg", "%[nval]",		\
				    __percpu_arg([var]))		\
		  "\n\tjnz 1b"						\
		  : [oval] "=&a" (pxo_old__),				\
		    [var] "+m" (_var)					\
		  : [nval] __pcpu_reg_##size(, pxo_new__)		\
		  : "memory");						\
	(typeof(_var))(unsigned long) pxo_old__;			\
})
#define raw_cpu_add_1(pcp, val)		percpu_add_op(1, , (pcp), val)
#define raw_cpu_add_2(pcp, val)		percpu_add_op(2, , (pcp), val)
#define raw_cpu_add_4(pcp, val)		percpu_add_op(4, , (pcp), val)
#define raw_cpu_add_8(pcp, val)			percpu_add_op(8, , (pcp), val)
#define raw_cpu_add_return_1(pcp, val)		percpu_add_return_op(1, , pcp, val)
#define raw_cpu_add_return_2(pcp, val)		percpu_add_return_op(2, , pcp, val)
#define raw_cpu_add_return_4(pcp, val)		percpu_add_return_op(4, , pcp, val)
#define raw_cpu_add_return_8(pcp, val)		percpu_add_return_op(8, , pcp, val)
#define raw_cpu_and_1(pcp, val)		percpu_to_op(1, , "and", (pcp), val)
#define raw_cpu_and_2(pcp, val)		percpu_to_op(2, , "and", (pcp), val)
#define raw_cpu_and_4(pcp, val)		percpu_to_op(4, , "and", (pcp), val)
#define raw_cpu_and_8(pcp, val)			percpu_to_op(8, , "and", (pcp), val)
#define raw_cpu_cmpxchg_1(pcp, oval, nval)	percpu_cmpxchg_op(1, , pcp, oval, nval)
#define raw_cpu_cmpxchg_2(pcp, oval, nval)	percpu_cmpxchg_op(2, , pcp, oval, nval)
#define raw_cpu_cmpxchg_4(pcp, oval, nval)	percpu_cmpxchg_op(4, , pcp, oval, nval)
#define raw_cpu_cmpxchg_8(pcp, oval, nval)	percpu_cmpxchg_op(8, , pcp, oval, nval)
#define raw_cpu_or_1(pcp, val)		percpu_to_op(1, , "or", (pcp), val)
#define raw_cpu_or_2(pcp, val)		percpu_to_op(2, , "or", (pcp), val)
#define raw_cpu_or_4(pcp, val)		percpu_to_op(4, , "or", (pcp), val)
#define raw_cpu_or_8(pcp, val)			percpu_to_op(8, , "or", (pcp), val)
#define raw_cpu_read_1(pcp)		percpu_from_op(1, , "mov", pcp)
#define raw_cpu_read_2(pcp)		percpu_from_op(2, , "mov", pcp)
#define raw_cpu_read_4(pcp)		percpu_from_op(4, , "mov", pcp)
#define raw_cpu_read_8(pcp)			percpu_from_op(8, , "mov", pcp)
#define raw_cpu_write_1(pcp, val)	percpu_to_op(1, , "mov", (pcp), val)
#define raw_cpu_write_2(pcp, val)	percpu_to_op(2, , "mov", (pcp), val)
#define raw_cpu_write_4(pcp, val)	percpu_to_op(4, , "mov", (pcp), val)
#define raw_cpu_write_8(pcp, val)		percpu_to_op(8, , "mov", (pcp), val)
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
#define this_cpu_add_1(pcp, val)	percpu_add_op(1, volatile, (pcp), val)
#define this_cpu_add_2(pcp, val)	percpu_add_op(2, volatile, (pcp), val)
#define this_cpu_add_4(pcp, val)	percpu_add_op(4, volatile, (pcp), val)
#define this_cpu_add_8(pcp, val)		percpu_add_op(8, volatile, (pcp), val)
#define this_cpu_add_return_1(pcp, val)		percpu_add_return_op(1, volatile, pcp, val)
#define this_cpu_add_return_2(pcp, val)		percpu_add_return_op(2, volatile, pcp, val)
#define this_cpu_add_return_4(pcp, val)		percpu_add_return_op(4, volatile, pcp, val)
#define this_cpu_add_return_8(pcp, val)		percpu_add_return_op(8, volatile, pcp, val)
#define this_cpu_and_1(pcp, val)	percpu_to_op(1, volatile, "and", (pcp), val)
#define this_cpu_and_2(pcp, val)	percpu_to_op(2, volatile, "and", (pcp), val)
#define this_cpu_and_4(pcp, val)	percpu_to_op(4, volatile, "and", (pcp), val)
#define this_cpu_and_8(pcp, val)		percpu_to_op(8, volatile, "and", (pcp), val)
#define this_cpu_cmpxchg_1(pcp, oval, nval)	percpu_cmpxchg_op(1, volatile, pcp, oval, nval)
#define this_cpu_cmpxchg_2(pcp, oval, nval)	percpu_cmpxchg_op(2, volatile, pcp, oval, nval)
#define this_cpu_cmpxchg_4(pcp, oval, nval)	percpu_cmpxchg_op(4, volatile, pcp, oval, nval)
#define this_cpu_cmpxchg_8(pcp, oval, nval)	percpu_cmpxchg_op(8, volatile, pcp, oval, nval)
#define this_cpu_or_1(pcp, val)		percpu_to_op(1, volatile, "or", (pcp), val)
#define this_cpu_or_2(pcp, val)		percpu_to_op(2, volatile, "or", (pcp), val)
#define this_cpu_or_4(pcp, val)		percpu_to_op(4, volatile, "or", (pcp), val)
#define this_cpu_or_8(pcp, val)			percpu_to_op(8, volatile, "or", (pcp), val)
#define this_cpu_read_1(pcp)		percpu_from_op(1, volatile, "mov", pcp)
#define this_cpu_read_2(pcp)		percpu_from_op(2, volatile, "mov", pcp)
#define this_cpu_read_4(pcp)		percpu_from_op(4, volatile, "mov", pcp)
#define this_cpu_read_8(pcp)			percpu_from_op(8, volatile, "mov", pcp)
#define this_cpu_read_stable_1(pcp)	percpu_stable_op(1, "mov", pcp)
#define this_cpu_read_stable_2(pcp)	percpu_stable_op(2, "mov", pcp)
#define this_cpu_read_stable_4(pcp)	percpu_stable_op(4, "mov", pcp)
#define this_cpu_read_stable_8(pcp)	percpu_stable_op(8, "mov", pcp)
#define this_cpu_write_1(pcp, val)	percpu_to_op(1, volatile, "mov", (pcp), val)
#define this_cpu_write_2(pcp, val)	percpu_to_op(2, volatile, "mov", (pcp), val)
#define this_cpu_write_4(pcp, val)	percpu_to_op(4, volatile, "mov", (pcp), val)
#define this_cpu_write_8(pcp, val)		percpu_to_op(8, volatile, "mov", (pcp), val)
#define this_cpu_xchg_1(pcp, nval)	percpu_xchg_op(1, volatile, pcp, nval)
#define this_cpu_xchg_2(pcp, nval)	percpu_xchg_op(2, volatile, pcp, nval)
#define this_cpu_xchg_4(pcp, nval)	percpu_xchg_op(4, volatile, pcp, nval)
#define this_cpu_xchg_8(pcp, nval)		percpu_xchg_op(8, volatile, pcp, nval)
#define x86_this_cpu_test_bit(nr, addr)			\
	(__builtin_constant_p((nr))			\
	 ? x86_this_cpu_constant_test_bit((nr), (addr))	\
	 : x86_this_cpu_variable_test_bit((nr), (addr)))

#define PER_CPU_BASE_SECTION ".data..percpu"

#define __my_cpu_offset per_cpu_offset(raw_smp_processor_id())
#define __this_cpu_generic_read_noirq(pcp)				\
({									\
	typeof(pcp) ___ret;						\
	unsigned long ___flags;						\
	raw_local_irq_save(___flags);					\
	___ret = raw_cpu_generic_read(pcp);				\
	raw_local_irq_restore(___flags);				\
	___ret;								\
})
#define __this_cpu_generic_read_nopreempt(pcp)				\
({									\
	typeof(pcp) ___ret;						\
	preempt_disable_notrace();					\
	___ret = READ_ONCE(*raw_cpu_ptr(&(pcp)));			\
	preempt_enable_notrace();					\
	___ret;								\
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


#define FIXMAP_PAGE_NOCACHE PAGE_KERNEL_IO_NOCACHE
# define FIXMAP_PMD_NUM (KM_PMDS + 2)

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

#define NODE_MIN_SIZE (4*1024*1024)


#define arch_init_invariance_cppc init_freq_invariance_cppc
#define arch_scale_freq_capacity arch_scale_freq_capacity
#define arch_scale_freq_invariant() static_branch_likely(&arch_scale_freq_key)
#define arch_scale_freq_tick arch_scale_freq_tick
#define cpu_to_node __cpu_to_node
#define node_distance(a, b) __node_distance(a, b)
#define numa_node_id numa_node_id
#define pcibus_to_node(bus) __pcibus_to_node(bus)
#define topology_cluster_cpumask(cpu)		(cpu_clustergroup_mask(cpu))
#define topology_cluster_id(cpu)		(per_cpu(cpu_l2c_id, cpu))
#define topology_core_cpumask(cpu)		(per_cpu(cpu_core_map, cpu))
#define topology_core_id(cpu)			(cpu_data(cpu).cpu_core_id)
#define topology_die_cpumask(cpu)		(per_cpu(cpu_die_map, cpu))
#define topology_die_id(cpu)			(cpu_data(cpu).cpu_die_id)
#define topology_logical_die_id(cpu)		(cpu_data(cpu).logical_die_id)
#define topology_logical_package_id(cpu)	(cpu_data(cpu).logical_proc_id)
#define topology_max_packages()			(__max_logical_packages)
#define topology_physical_package_id(cpu)	(cpu_data(cpu).phys_proc_id)
#define topology_ppin(cpu)			(cpu_data(cpu).ppin)
#define topology_sibling_cpumask(cpu)		(per_cpu(cpu_sibling_map, cpu))
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
	   CHECK_BIT_IN_MASK_WORD(DISABLED_MASK, 19, feature_bit) ||	\
	   DISABLED_MASK_CHECK					  ||	\
	   BUILD_BUG_ON_ZERO(NCAPINTS != 20))
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
	   CHECK_BIT_IN_MASK_WORD(REQUIRED_MASK, 19, feature_bit) ||	\
	   REQUIRED_MASK_CHECK					  ||	\
	   BUILD_BUG_ON_ZERO(NCAPINTS != 20))
#define X86_CAP_FMT "%s"
#define X86_CAP_FMT_NUM "%d:%d"

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
	 arch_test_bit(bit, (unsigned long *)((c)->x86_capability))
#define this_cpu_has(bit)						\
	(__builtin_constant_p(bit) && REQUIRED_MASK_BIT_SET(bit) ? 1 :	\
	 x86_this_cpu_test_bit(bit,					\
		(unsigned long __percpu *)&cpu_info.x86_capability))
#define x86_cap_flag x86_cap_flag_num
#define x86_cap_flag_num(flag) ((flag) >> 5), ((flag) & 31)

#define cpu_to_mem(cpu)		((void)(cpu),0)
    #define cpumask_of_node(node)	((node) == 0 ? cpu_online_mask : cpu_none_mask)
#define cpumask_of_pcibus(bus)	(pcibus_to_node(bus) == -1 ?		\
				 cpu_all_mask :				\
				 cpumask_of_node(pcibus_to_node(bus)))
#define set_cpu_numa_mem(cpu, node)
#define set_cpu_numa_node(cpu, node)


#define ACPI_COMPANION(dev)		to_acpi_device_node((dev)->fwnode)
#define ACPI_COMPANION_SET(dev, adev)	set_primary_fwnode(dev, (adev) ? \
	acpi_fwnode_handle(adev) : NULL)
#define ACPI_DECLARE_PROBE_ENTRY(table, name, table_id, subtable,	\
				 valid, data, fn)			\
	static const struct acpi_probe_entry __acpi_probe_##name	\
		__used __section("__" #table "_acpi_probe_table") = {	\
			.id = table_id,					\
			.type = subtable,				\
			.subtable_valid = valid,			\
			.probe_table = fn,				\
			.driver_data = data,				\
		}
#define ACPI_DECLARE_SUBTABLE_PROBE_ENTRY(table, name, table_id,	\
					  subtable, valid, data, fn)	\
	static const struct acpi_probe_entry __acpi_probe_##name	\
		__used __section("__" #table "_acpi_probe_table") = {	\
			.id = table_id,					\
			.type = subtable,				\
			.subtable_valid = valid,			\
			.probe_subtbl = fn,				\
			.driver_data = data,				\
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
#define EXPORT_SYMBOL_ACPI_LIB(x) EXPORT_SYMBOL_NS_GPL(x, ACPI)
#define PHYS_CPUID_INVALID (phys_cpuid_t)(-1)


#define __init_or_acpilib __init
#define __initdata_or_acpilib __initdata
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
#define MAX_PXM_DOMAINS MAX_NUMNODES


#define IOMEM_ERR_PTR(err) (__force void __iomem *)ERR_PTR(err)

#define arch_has_dev_port()     (1)
#define arch_phys_wc_add arch_phys_wc_add
#define arch_phys_wc_index arch_phys_wc_index
#define pci_remap_cfgspace pci_remap_cfgspace


#define acpi_device_adr(d)	((d)->pnp.bus_address)
#define acpi_device_bid(d)	((d)->pnp.bus_id)
#define acpi_device_class(d)	((d)->pnp.device_class)
#define acpi_device_dir(d)	((d)->dir.entry)
#define acpi_device_name(d)	((d)->pnp.device_name)
#define acpi_device_uid(d)	((d)->pnp.unique_id)
#define for_each_acpi_dev_match(adev, hid, uid, hrv)			\
	for (adev = acpi_dev_get_first_match_dev(hid, uid, hrv);	\
	     adev;							\
	     adev = acpi_dev_get_next_match_dev(adev, hid, uid, hrv))
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

#define ACPI_APP_DEPENDENT_RETURN_VOID(prototype) \
	prototype;
#define ACPI_CA_VERSION                 0x20220331
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
#define ACPI_PLD_PANEL_BACK     5
#define ACPI_PLD_PANEL_BOTTOM   1
#define ACPI_PLD_PANEL_FRONT    4
#define ACPI_PLD_PANEL_LEFT     2
#define ACPI_PLD_PANEL_RIGHT    3
#define ACPI_PLD_PANEL_TOP      0
#define ACPI_PLD_PANEL_UNKNOWN  6
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
#define ACPI_SIG_VIOT           "VIOT"	
#define ACPI_SIG_WAET           "WAET"	
#define ACPI_SIG_WDAT           "WDAT"	
#define ACPI_SIG_WDDT           "WDDT"	
#define ACPI_SIG_WDRT           "WDRT"	
#define ACPI_SIG_WPBT           "WPBT"	
#define ACPI_SIG_WSMT           "WSMT"	
#define ACPI_SIG_XENV           "XENV"	
#define ACPI_SIG_XXXX           "XXXX"	
#define ACPI_SPCR_DO_NOT_DISABLE    (1)
#define ACPI_SRAT_ARCHITECTURAL_TRANSACTIONS   (1<<1)	
#define ACPI_SRAT_CPU_ENABLED       (1)	
#define ACPI_SRAT_CPU_USE_AFFINITY  (1)	
#define ACPI_SRAT_GENERIC_AFFINITY_ENABLED     (1)	
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

#define ACPI_AEST_CACHE_DATA                0
#define ACPI_AEST_CACHE_INSTRUCTION         1
#define ACPI_AEST_CACHE_RESERVED            3	
#define ACPI_AEST_CACHE_RESOURCE            0
#define ACPI_AEST_CACHE_UNIFIED             2
#define ACPI_AEST_GENERIC_RESOURCE          2
#define ACPI_AEST_GIC_CPU                   0
#define ACPI_AEST_GIC_DISTRIBUTOR           1
#define ACPI_AEST_GIC_ERROR_NODE            4
#define ACPI_AEST_GIC_ITS                   3
#define ACPI_AEST_GIC_REDISTRIBUTOR         2
#define ACPI_AEST_GIC_RESERVED              4	
#define ACPI_AEST_MEMORY_ERROR_NODE         1
#define ACPI_AEST_NODE_ERROR_RECOVERY       1
#define ACPI_AEST_NODE_FAULT_HANDLING       0
#define ACPI_AEST_NODE_MEMORY_MAPPED        1
#define ACPI_AEST_NODE_SYSTEM_REGISTER      0
#define ACPI_AEST_NODE_TYPE_RESERVED        5	
#define ACPI_AEST_PROCESSOR_ERROR_NODE      0
#define ACPI_AEST_RESOURCE_RESERVED         3	
#define ACPI_AEST_SMMU_ERROR_NODE           2
#define ACPI_AEST_TLB_RESOURCE              1
#define ACPI_AEST_VENDOR_ERROR_NODE         3
#define ACPI_AEST_XFACE_RESERVED            2	
#define ACPI_AEST_XRUPT_RESERVED            2	
#define ACPI_AGDI_SIGNALING_MODE (1)
#define ACPI_APMT_FLAGS_AFFINITY                (1<<1)
#define ACPI_APMT_FLAGS_AFFINITY_PROC           (0<<1)
#define ACPI_APMT_FLAGS_AFFINITY_PROC_CONTAINER (1<<1)
#define ACPI_APMT_FLAGS_ATOMIC                  (1<<2)
#define ACPI_APMT_FLAGS_ATOMIC_NSUPP            (0<<2)
#define ACPI_APMT_FLAGS_ATOMIC_SUPP             (1<<2)
#define ACPI_APMT_FLAGS_DUAL_PAGE               (1<<0)
#define ACPI_APMT_FLAGS_DUAL_PAGE_NSUPP         (0<<0)
#define ACPI_APMT_FLAGS_DUAL_PAGE_SUPP          (1<<0)
#define ACPI_APMT_NODE_ID_LENGTH                4
#define ACPI_APMT_OVFLW_IRQ_FLAGS_MODE          (1<<0)
#define ACPI_APMT_OVFLW_IRQ_FLAGS_MODE_EDGE     (1<<0)
#define ACPI_APMT_OVFLW_IRQ_FLAGS_MODE_LEVEL    (0<<0)
#define ACPI_APMT_OVFLW_IRQ_FLAGS_TYPE          (1<<1)
#define ACPI_APMT_OVFLW_IRQ_FLAGS_TYPE_WIRED    (0<<1)
#define ACPI_IORT_ATS_SUPPORTED         (1)	
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
#define ACPI_IORT_PASID_FWD_SUPPORTED   (1<<2)	
#define ACPI_IORT_PASID_MAX_WIDTH       (0x1F)	
#define ACPI_IORT_PRI_SUPPORTED         (1<<1)	
#define ACPI_IORT_RMR_ACCESS_ATTRIBUTES(flags)          (((flags) >> 2) & 0xFF)
#define ACPI_IORT_RMR_ACCESS_PRIVILEGE     (1<<1)
#define ACPI_IORT_RMR_ATTR_DEVICE_GRE      0x03
#define ACPI_IORT_RMR_ATTR_DEVICE_NGNRE    0x01
#define ACPI_IORT_RMR_ATTR_DEVICE_NGNRNE   0x00
#define ACPI_IORT_RMR_ATTR_DEVICE_NGRE     0x02
#define ACPI_IORT_RMR_ATTR_NORMAL_IWB_OWB  0x05
#define ACPI_IORT_RMR_ATTR_NORMAL_NC       0x04
#define ACPI_IORT_RMR_REMAP_PERMITTED      (1)
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
#define ACPI_IVRS_UID_IS_INTEGER    1
#define ACPI_IVRS_UID_IS_STRING     2
#define ACPI_IVRS_UID_NOT_PRESENT   0
#define ACPI_IVRS_VIRTUAL_SIZE      0x003F8000	
#define ACPI_LPIT_NO_COUNTER        (1<<1)
#define ACPI_LPIT_STATE_DISABLED    (1)
#define ACPI_MADT_CPEI_OVERRIDE     (1)
#define ACPI_MADT_DUAL_PIC          1
#define ACPI_MADT_ENABLED           (1)	
#define ACPI_MADT_MULTIPLE_APIC     0
#define ACPI_MADT_ONLINE_CAPABLE    (2)	
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
#define ACPI_MP_WAKE_COMMAND_WAKEUP    1
#define ACPI_MULTIPROC_WAKEUP_MB_FIRMWARE_SIZE  2048
#define ACPI_MULTIPROC_WAKEUP_MB_OS_SIZE        2032
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
#define ACPI_NFIT_LOCATION_COOKIE_VALID (1<<2)	
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
#define ACPI_NHLT_ARRAY_TYPE_EXT_MASK               0x10
#define ACPI_NHLT_ARRAY_TYPE_MASK                   0x0F
#define ACPI_NHLT_ARRAY_TYPE_RESERVED               0x09	
#define ACPI_NHLT_BIG_LINEAR_2ELEMENT               0x0B
#define ACPI_NHLT_BT_SIDEBAND               0xAE30
#define ACPI_NHLT_CONFIG_TYPE_GENERIC              0x00
#define ACPI_NHLT_CONFIG_TYPE_MIC_ARRAY            0x01
#define ACPI_NHLT_CONFIG_TYPE_RENDER_FEEDBACK      0x03
#define ACPI_NHLT_CONFIG_TYPE_RESERVED             0x04	
#define ACPI_NHLT_DIR_CAPTURE               1
#define ACPI_NHLT_DIR_RENDER                0
#define ACPI_NHLT_DIR_RENDER_FEEDBACK       3
#define ACPI_NHLT_DIR_RENDER_LOOPBACK       2
#define ACPI_NHLT_DIR_RESERVED              4	
#define ACPI_NHLT_FIRST_GEOMETRY_LINEAR_4ELEMENT    0x0C
#define ACPI_NHLT_GENERIC                   0
#define ACPI_NHLT_I2S_TDM_CODECS            0xAE23
#define ACPI_NHLT_LINK_BT_SIDEBAND          0
#define ACPI_NHLT_LINK_FM                   1
#define ACPI_NHLT_LINK_MODEM                2
#define ACPI_NHLT_LINK_SSP_ANALOG_CODEC     4
#define ACPI_NHLT_MIC                       1
#define ACPI_NHLT_MIC_8_SHAPED              5
#define ACPI_NHLT_MIC_CARDIOID              2
#define ACPI_NHLT_MIC_HYPER_CARDIOID        4
#define ACPI_NHLT_MIC_OMNIDIRECTIONAL       0
#define ACPI_NHLT_MIC_POSITION_BACK         5
#define ACPI_NHLT_MIC_POSITION_BOTTOM       1
#define ACPI_NHLT_MIC_POSITION_FRONT        4
#define ACPI_NHLT_MIC_POSITION_LEFT         2
#define ACPI_NHLT_MIC_POSITION_RESERVED     6	
#define ACPI_NHLT_MIC_POSITION_RIGHT        3
#define ACPI_NHLT_MIC_POSITION_TOP          0
#define ACPI_NHLT_MIC_RESERVED              8	
#define ACPI_NHLT_MIC_RESERVED6             6	
#define ACPI_NHLT_MIC_SNR_SENSITIVITY_EXT           (1<<4)
#define ACPI_NHLT_MIC_SUBCARDIOID           1
#define ACPI_NHLT_MIC_SUPER_CARDIOID        3
#define ACPI_NHLT_MIC_VENDOR_DEFINED        7
#define ACPI_NHLT_NO_EXTENSION                      0x0
#define ACPI_NHLT_PDM                       2
#define ACPI_NHLT_PDM_DMIC                  0xAE20
#define ACPI_NHLT_PDM_ON_CAVS_1P5           1
#define ACPI_NHLT_PDM_ON_CAVS_1P8           0
#define ACPI_NHLT_PLANAR_LSHAPED_4ELEMENT           0x0D
#define ACPI_NHLT_RENDER                    3
#define ACPI_NHLT_RESERVED_DSP              1
#define ACPI_NHLT_RESERVED_HD_AUDIO         0
#define ACPI_NHLT_RESERVED_SLIMBUS          4
#define ACPI_NHLT_RESERVED_SOUNDWIRE        5
#define ACPI_NHLT_SECOND_GEOMETRY_LINEAR_4ELEMENT   0x0E
#define ACPI_NHLT_SMALL_LINEAR_2ELEMENT             0x0A
#define ACPI_NHLT_SPKR_BACK_CENTER            0x100
#define ACPI_NHLT_SPKR_BACK_LEFT              0x10
#define ACPI_NHLT_SPKR_BACK_RIGHT             0x20
#define ACPI_NHLT_SPKR_FRONT_CENTER           0x4
#define ACPI_NHLT_SPKR_FRONT_LEFT             0x1
#define ACPI_NHLT_SPKR_FRONT_LEFT_OF_CENTER   0x40
#define ACPI_NHLT_SPKR_FRONT_RIGHT            0x2
#define ACPI_NHLT_SPKR_FRONT_RIGHT_OF_CENTER  0x80
#define ACPI_NHLT_SPKR_LOW_FREQ               0x8
#define ACPI_NHLT_SPKR_SIDE_LEFT              0x200
#define ACPI_NHLT_SPKR_SIDE_RIGHT             0x400
#define ACPI_NHLT_SPKR_TOP_BACK_CENTER        0x10000
#define ACPI_NHLT_SPKR_TOP_BACK_LEFT          0x8000
#define ACPI_NHLT_SPKR_TOP_BACK_RIGHT         0x20000
#define ACPI_NHLT_SPKR_TOP_CENTER             0x800
#define ACPI_NHLT_SPKR_TOP_FRONT_CENTER       0x2000
#define ACPI_NHLT_SPKR_TOP_FRONT_LEFT         0x1000
#define ACPI_NHLT_SPKR_TOP_FRONT_RIGHT        0x4000
#define ACPI_NHLT_SSP                       3
#define ACPI_NHLT_TYPE_RESERVED             6	
#define ACPI_NHLT_VENDOR_DEFINED                    0x0F
#define ACPI_PCCT_DOORBELL              1
#define ACPI_PCCT_INTERRUPT_MODE        (1<<1)
#define ACPI_PCCT_INTERRUPT_POLARITY    (1)
#define ACPI_PDTT_RUNTIME_TRIGGER           (1)
#define ACPI_PDTT_TRIGGER_ORDER             (1<<2)
#define ACPI_PDTT_WAIT_COMPLETION           (1<<1)
#define ACPI_PHAT_ADVISORY              3
#define ACPI_PHAT_ERRORS_FOUND          0
#define ACPI_PHAT_NO_ERRORS             1
#define ACPI_PHAT_TYPE_FW_HEALTH_DATA   1
#define ACPI_PHAT_TYPE_FW_VERSION_DATA  0
#define ACPI_PHAT_TYPE_RESERVED         2	
#define ACPI_PHAT_UNKNOWN_ERRORS        2
#define ACPI_PMTT_MEMORY_TYPE           0x000C
#define ACPI_PMTT_PHYSICAL              0x0002
#define ACPI_PMTT_TOP_LEVEL             0x0001
#define ACPI_PMTT_TYPE_CONTROLLER       1
#define ACPI_PMTT_TYPE_DIMM             2
#define ACPI_PMTT_TYPE_RESERVED         3	
#define ACPI_PMTT_TYPE_SOCKET           0
#define ACPI_PMTT_TYPE_VENDOR           0xFF
#define ACPI_PPTT_ACPI_IDENTICAL            (1<<4)	
#define ACPI_PPTT_ACPI_LEAF_NODE            (1<<3)	
#define ACPI_PPTT_ACPI_PROCESSOR_ID_VALID   (1<<1)
#define ACPI_PPTT_ACPI_PROCESSOR_IS_THREAD  (1<<2)	
#define ACPI_PPTT_ALLOCATION_TYPE_VALID     (1<<3)	
#define ACPI_PPTT_ASSOCIATIVITY_VALID       (1<<2)	
#define ACPI_PPTT_CACHE_ID_VALID            (1<<7)	
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
#define ACPI_SDEV_SECURE_COMPONENTS_PRESENT (1<<1)
#define ACPI_SIG_AGDI           "AGDI"	
#define ACPI_SIG_APMT           "APMT"	
#define ACPI_SIG_BDAT           "BDAT"	
#define ACPI_SIG_IORT           "IORT"	
#define ACPI_SIG_IVRS           "IVRS"	
#define ACPI_SIG_LPIT           "LPIT"	
#define ACPI_SIG_MADT           "APIC"	
#define ACPI_SIG_MCFG           "MCFG"	
#define ACPI_SIG_MCHI           "MCHI"	
#define ACPI_SIG_MPST           "MPST"	
#define ACPI_SIG_MSCT           "MSCT"	
#define ACPI_SIG_MSDM           "MSDM"	
#define ACPI_SIG_NFIT           "NFIT"	
#define ACPI_SIG_NHLT           "NHLT"	
#define ACPI_SIG_PCCT           "PCCT"	
#define ACPI_SIG_PDTT           "PDTT"	
#define ACPI_SIG_PHAT           "PHAT"	
#define ACPI_SIG_PMTT           "PMTT"	
#define ACPI_SIG_PPTT           "PPTT"	
#define ACPI_SIG_PRMT           "PRMT"	
#define ACPI_SIG_RASF           "RASF"	
#define ACPI_SIG_RGRT           "RGRT"	
#define ACPI_SIG_SBST           "SBST"	
#define ACPI_SIG_SDEI           "SDEI"	
#define ACPI_SIG_SDEV           "SDEV"	
#define ACPI_SIG_SVKL           "SVKL"	
#define ACPI_SIG_TDEL           "TDEL"	

#define ACPI_ASF_SMBUS_PROTOCOLS    (1)
#define ACPI_BERT_CORRECTABLE               (1<<1)
#define ACPI_BERT_ERROR_ENTRY_COUNT         (0xFF<<4)	
#define ACPI_BERT_MULTIPLE_CORRECTABLE      (1<<3)
#define ACPI_BERT_MULTIPLE_UNCORRECTABLE    (1<<2)
#define ACPI_BERT_UNCORRECTABLE             (1)
#define ACPI_BGRT_DISPLAYED                 (1)
#define ACPI_BGRT_ORIENTATION_OFFSET        (3 << 1)
#define ACPI_CEDT_CFMWS_ARITHMETIC_MODULO   (0)
#define ACPI_CEDT_CFMWS_RESTRICT_FIXED      (1<<4)
#define ACPI_CEDT_CFMWS_RESTRICT_PMEM       (1<<3)
#define ACPI_CEDT_CFMWS_RESTRICT_TYPE2      (1)
#define ACPI_CEDT_CFMWS_RESTRICT_TYPE3      (1<<1)
#define ACPI_CEDT_CFMWS_RESTRICT_VOLATILE   (1<<2)
#define ACPI_CEDT_CHBS_LENGTH_CXL11     (0x2000)
#define ACPI_CEDT_CHBS_LENGTH_CXL20     (0x10000)
#define ACPI_CEDT_CHBS_VERSION_CXL11    (0)
#define ACPI_CEDT_CHBS_VERSION_CXL20    (1)
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
#define ACPI_DBG2_16550_NVIDIA      0x0005
#define ACPI_DBG2_16550_SUBSET      0x0001
#define ACPI_DBG2_16550_WITH_GAS    0x0012
#define ACPI_DBG2_APM88XXXX         0x0008
#define ACPI_DBG2_ARM_DCC           0x000F
#define ACPI_DBG2_ARM_PL011         0x0003
#define ACPI_DBG2_ARM_SBSA_32BIT    0x000D
#define ACPI_DBG2_ARM_SBSA_GENERIC  0x000E
#define ACPI_DBG2_BCM2835           0x0010
#define ACPI_DBG2_IMX6              0x000C
#define ACPI_DBG2_INTEL_LPSS        0x0014
#define ACPI_DBG2_INTEL_USIF        0x000B
#define ACPI_DBG2_MAX311XE_SPI      0x0002
#define ACPI_DBG2_MSM8974           0x0009
#define ACPI_DBG2_MSM8X60           0x0004
#define ACPI_DBG2_NET_PORT          0x8003
#define ACPI_DBG2_SAM5250           0x000A
#define ACPI_DBG2_SDM845_1_8432MHZ  0x0011
#define ACPI_DBG2_SDM845_7_372MHZ   0x0013
#define ACPI_DBG2_SERIAL_PORT       0x8000
#define ACPI_DBG2_TI_OMAP           0x0006
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
#define ACPI_HMAT_MINIMUM_XFER_SIZE 0x10       
#define ACPI_HMAT_NON_SEQUENTIAL_XFERS 0x20    
#define ACPI_HMAT_PROCESSOR_PD_VALID    (1)	
#define ACPI_HMAT_READ_BANDWIDTH    4
#define ACPI_HMAT_READ_LATENCY      1
#define ACPI_HMAT_RESERVATION_HINT      (1<<2)	
#define ACPI_HMAT_TOTAL_CACHE_LEVEL     (0x0000000F)
#define ACPI_HMAT_WRITE_BANDWIDTH   5
#define ACPI_HMAT_WRITE_LATENCY     2
#define ACPI_HMAT_WRITE_POLICY          (0x0000F000)
#define ACPI_HPET_PAGE_PROTECT_MASK (3)
#define ACPI_SIG_AEST           "AEST"	
#define ACPI_SIG_ASF            "ASF!"	
#define ACPI_SIG_ATKG           "ATKG"
#define ACPI_SIG_BERT           "BERT"	
#define ACPI_SIG_BGRT           "BGRT"	
#define ACPI_SIG_BOOT           "BOOT"	
#define ACPI_SIG_CEDT           "CEDT"	
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
#define ACPI_ACCESS_BIT_DEFAULT         (8 - ACPI_ACCESS_BIT_SHIFT)
#define ACPI_ACCESS_BIT_MAX             (31 - ACPI_ACCESS_BIT_SHIFT)
#define ACPI_ACCESS_BIT_SHIFT           2
#define ACPI_ACCESS_BIT_WIDTH(size)     (1 << ((size) + ACPI_ACCESS_BIT_SHIFT))
#define ACPI_ACCESS_BYTE_DEFAULT        (8 - ACPI_ACCESS_BYTE_SHIFT)
#define ACPI_ACCESS_BYTE_MAX            (31 - ACPI_ACCESS_BYTE_SHIFT)
#define ACPI_ACCESS_BYTE_SHIFT          -1
#define ACPI_ACCESS_BYTE_WIDTH(size)    (1 << ((size) + ACPI_ACCESS_BYTE_SHIFT))
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
#define ACPI_ADR_SPACE_PLATFORM_RT      (acpi_adr_space_type) 11
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


#define ACPI_FALLTHROUGH do {} while(0)
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
#define ACPI_NUM_PREDEFINED_REGIONS     12
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
#define ACPI_OSI_WIN_10_20H1            0x15
#define ACPI_OSI_WIN_10_RS1             0x0F
#define ACPI_OSI_WIN_10_RS2             0x10
#define ACPI_OSI_WIN_10_RS3             0x11
#define ACPI_OSI_WIN_10_RS4             0x12
#define ACPI_OSI_WIN_10_RS5             0x13
#define ACPI_OSI_WIN_11                 0x16
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
#define ACPI_PRM_INPUT_BUFFER_SIZE      26
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

#define ACPI_GET_FUNCTION_NAME          __func__
#define COMPILER_VA_MACRO               1

#define __has_attribute(x) 0
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
#define ACPI_DEBUG_ONLY_MEMBERS(a)      a
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
#define ACPI_RESOURCE_SERIAL_TYPE_CSI2          4
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

#define ACPI_AML_EXCEPTION(status)      (((status) & AE_CODE_MASK) == AE_CODE_AML)
#define ACPI_CNTL_EXCEPTION(status)     (((status) & AE_CODE_MASK) == AE_CODE_CONTROL)
#define ACPI_ENV_EXCEPTION(status)      (((status) & AE_CODE_MASK) == AE_CODE_ENVIRONMENTAL)
#define ACPI_FAILURE(a)                 (a)
#define ACPI_PROG_EXCEPTION(status)     (((status) & AE_CODE_MASK) == AE_CODE_PROGRAMMER)
#define ACPI_SUCCESS(a)                 (!(a))
#define ACPI_TABLE_EXCEPTION(status)    (((status) & AE_CODE_MASK) == AE_CODE_ACPI_TABLES)
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
#define METHOD_NAME__DIS        "_DIS"
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
#define IRQ_DOMAIN_IRQ_SPEC_PARAMS 16



#define tss_invalidate_io_bitmap native_tss_invalidate_io_bitmap
#define tss_update_io_bitmap native_tss_update_io_bitmap

#define cpu_acpi_id(cpu)			0
#define cpu_physical_id(cpu)			boot_cpu_physical_apicid
#define safe_smp_processor_id()			0
#define DBG(fmt, ...) printk(fmt, ##__VA_ARGS__)
#define PCI_MMCFG_BUS_OFFSET(bus)      ((bus) << 20)
#define PCI_MMCFG_RESOURCE_NAME_LEN (22 + 4 + 2 + 2)
#define pci_use_e820 false
#define CPUID5_ECX_EXTENSIONS_SUPPORTED 0x1
#define MWAIT_HINT2CSTATE(hint)		(((hint) >> MWAIT_SUBSTATE_SIZE) & MWAIT_CSTATE_MASK)
#define MWAIT_HINT2SUBSTATE(hint)	((hint) & MWAIT_CSTATE_MASK)


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
static inline void out##bwl##_p(type value, u16 port)			\
{									\
	out##bwl(value, port);						\
	slow_down_io();							\
}									\
									\
static inline type in##bwl##_p(u16 port)				\
{									\
	type value = in##bwl(port);					\
	slow_down_io();							\
	return value;							\
}									\
									\
static inline void outs##bwl(u16 port, const void *addr, unsigned long count) \
{									\
	if (cc_platform_has(CC_ATTR_GUEST_UNROLL_STRING_IO)) {		\
		type *value = (type *)addr;				\
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
static inline void ins##bwl(u16 port, void *addr, unsigned long count)	\
{									\
	if (cc_platform_has(CC_ATTR_GUEST_UNROLL_STRING_IO)) {		\
		type *value = (type *)addr;				\
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
#define build_mmio_read(name, size, type, reg, barrier) \
static inline type name(const volatile void __iomem *addr) \
{ type ret; asm volatile("mov" size " %1,%0":reg (ret) \
:"m" (*(volatile type __force *)addr) barrier); return ret; }
#define build_mmio_write(name, size, type, reg, barrier) \
static inline void name(type val, volatile void __iomem *addr) \
{ asm volatile("mov" size " %0,%1": :reg (val), \
"m" (*(volatile type __force *)addr) barrier); }
#define bus_to_virt phys_to_virt
#define inb_p inb_p
#define inl_p inl_p
#define insb insb
#define insl insl
#define insw insw
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
#define outb_p outb_p
#define outl_p outl_p
#define outsb outsb
#define outsl outsl
#define outsw outsw
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
#define inb _inb
#define inl _inl
#define insb_p insb_p
#define insl_p insl_p
#define insw_p insw_p
#define inw _inw
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
#define ioremap_np ioremap_np
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
#define outb _outb
#define outl _outl
#define outsb_p outsb_p
#define outsl_p outsl_p
#define outsw_p outsw_p
#define outw _outw
#define readsb readsb
#define readsl readsl
#define readsq readsq
#define readsw readsw
#define writesb writesb
#define writesl writesl
#define writesq writesq
#define writesw writesw
#define ARCH_PAGE_TABLE_SYNC_MASK 0
#define VMALLOC_TOTAL (VMALLOC_END - VMALLOC_START)

#define MMIO_UPPER_LIMIT (IO_SPACE_LIMIT - PIO_INDIRECT_SIZE)
#define PIO_INDIRECT_SIZE 0x4000


#define __pci_ioport_map(dev, port, nr) ioport_map((port), (nr))

#define ioread64_hi_lo ioread64_hi_lo
#define ioread64_lo_hi ioread64_lo_hi
#define ioread64be_hi_lo ioread64be_hi_lo
#define ioread64be_lo_hi ioread64be_lo_hi
#define iowrite64_hi_lo iowrite64_hi_lo
#define iowrite64_lo_hi iowrite64_lo_hi
#define iowrite64be_hi_lo iowrite64be_hi_lo
#define iowrite64be_lo_hi iowrite64be_lo_hi




#define KVM_HYPERCALL \
        ALTERNATIVE("vmcall", "vmmcall", X86_FEATURE_VMMCALL)

#define kvm_async_pf_task_wait_schedule(T) do {} while(0)
#define kvm_async_pf_task_wake(T) do {} while(0)

#define TDX_HYPERCALL_STANDARD  0

#define KVM_CLOCK_PAIRING_WALLCLOCK 0
#define KVM_FEATURE_CLOCKSOURCE2        3
#define KVM_HINTS_REALTIME      0
#define KVM_MAP_GPA_RANGE_ENC_STAT(n)	(n << 4)
#define KVM_MAX_MMU_OP_BATCH           32
#define KVM_MMU_OP_WRITE_PTE            1
#define KVM_MSR_ENABLED 1
#define KVM_PV_EOI_BIT 0
#define KVM_PV_EOI_DISABLED 0x0
#define KVM_PV_EOI_ENABLED KVM_PV_EOI_MASK
#define KVM_PV_EOI_MASK (0x1 << KVM_PV_EOI_BIT)
#define KVM_PV_REASON_PAGE_NOT_PRESENT 1
#define KVM_PV_REASON_PAGE_READY 2
#define KVM_SIGNATURE "KVMKVMKVM\0\0\0"
#define KVM_STEAL_ALIGNMENT_BITS 5
#define KVM_STEAL_RESERVED_MASK (((1 << KVM_STEAL_ALIGNMENT_BITS) - 1 ) << 1)
#define KVM_STEAL_VALID_BITS ((-1ULL << (KVM_STEAL_ALIGNMENT_BITS + 1)))
#define KVM_VCPU_FLUSH_TLB          (1 << 1)
#define KVM_VCPU_PREEMPTED          (1 << 0)
#define MSR_KVM_ASYNC_PF_EN 0x4b564d02
#define MSR_KVM_PV_EOI_EN      0x4b564d04
#define MSR_KVM_STEAL_TIME  0x4b564d03
#define MSR_KVM_SYSTEM_TIME 0x12
#define MSR_KVM_SYSTEM_TIME_NEW 0x4b564d01
#define MSR_KVM_WALL_CLOCK  0x11
#define MSR_KVM_WALL_CLOCK_NEW  0x4b564d00

#define _ASM_STACKPROTECTOR_H 1
#  define CANARY_MASK 0xffffffffffffff00UL

#define declare_get_random_var_wait(name, ret_type) \
	static inline int get_random_ ## name ## _wait(ret_type *out) { \
		int ret = wait_for_random_bytes(); \
		if (unlikely(ret)) \
			return ret; \
		*out = get_random_ ## name(); \
		return 0; \
	}

#define prandom_init_once(pcpu_state)			\
	DO_ONCE(prandom_seed_full_state, (pcpu_state))

#define DO_ONCE(func, ...)						     \
	({								     \
		bool ___ret = false;					     \
		static bool __section(".data.once") ___done = false;	     \
		static DEFINE_STATIC_KEY_TRUE(___once_key);		     \
		if (static_branch_unlikely(&___once_key)) {		     \
			unsigned long ___flags;				     \
			___ret = __do_once_start(&___done, &___flags);	     \
			if (unlikely(___ret)) {				     \
				func(__VA_ARGS__);			     \
				__do_once_done(&___done, &___once_key,	     \
					       &___flags, THIS_MODULE);	     \
			}						     \
		}							     \
		___ret;							     \
	})

#define get_random_once(buf, nbytes)					     \
	DO_ONCE(get_random_bytes, (buf), (nbytes))
#define get_random_once_wait(buf, nbytes)                                    \
	DO_ONCE(get_random_bytes_wait, (buf), (nbytes))                      \

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
#define ESTACKS_MEMBERS(guardsize, optional_stack_size)		\
	char	DF_stack_guard[guardsize];			\
	char	DF_stack[EXCEPTION_STKSZ];			\
	char	NMI_stack_guard[guardsize];			\
	char	NMI_stack[EXCEPTION_STKSZ];			\
	char	DB_stack_guard[guardsize];			\
	char	DB_stack[EXCEPTION_STKSZ];			\
	char	MCE_stack_guard[guardsize];			\
	char	MCE_stack[EXCEPTION_STKSZ];			\
	char	VC_stack_guard[guardsize];			\
	char	VC_stack[optional_stack_size];			\
	char	VC2_stack_guard[guardsize];			\
	char	VC2_stack[optional_stack_size];			\
	char	IST_top_guard[guardsize];			\


#define __this_cpu_ist_bottom_va(name)					\
	CEA_ESTACK_BOT(__this_cpu_read(cea_exception_stacks), name)
#define __this_cpu_ist_top_va(name)					\
	CEA_ESTACK_TOP(__this_cpu_read(cea_exception_stacks), name)


#define ISA_IRQ_VECTOR(irq)		(((FIRST_EXTERNAL_VECTOR + 16) & ~15) + irq)
#define NR_IRQS				NR_IRQS_LEGACY


#define get_cycles get_cycles


#define LOADED_MM_SWITCHING ((struct mm_struct *)1UL)

#define flush_tlb_mm(mm)						\
		flush_tlb_mm_range(mm, 0UL, TLB_FLUSH_ALL, 0UL, true)
#define flush_tlb_range(vma, start, end)				\
	flush_tlb_mm_range((vma)->vm_mm, start, end,			\
			   ((vma)->vm_flags & VM_HUGETLB)		\
				? huge_page_shift(hstate_vma(vma))	\
				: PAGE_SHIFT, false)
#define huge_pmd_needs_flush huge_pmd_needs_flush
#define nmi_uaccess_okay nmi_uaccess_okay
#define pte_needs_flush pte_needs_flush



#define __smp_processor_id() __this_cpu_read(cpu_number)
#define hard_smp_processor_id()	0
#define nmi_selftest() do { } while (0)
#define raw_smp_processor_id()  this_cpu_read(cpu_number)
#define wbinvd_on_cpu(cpu)     wbinvd()
#define INIT_THREAD_INFO(tsk)			\
{						\
	.flags		= 0,			\
}
#  define TOP_OF_KERNEL_STACK_PADDING 16

#define arch_set_restart_data(restart)	\
	do { restart->arch_data = current_thread_info()->status; } while (0)
#define arch_setup_new_exec arch_setup_new_exec
#define in_ia32_syscall() true
#define PGD_ALLOCATION_ORDER 1




#define DEFINE_READAHEAD(ractl, f, r, m, i)				\
	struct readahead_control ractl = {				\
		.file = f,						\
		.mapping = m,						\
		.ra = r,						\
		._index = i,						\
	}

#define readahead_page_batch(rac, array)				\
	__readahead_batch(rac, array, ARRAY_SIZE(array))
#define swapcache_index(folio)	__page_file_index(&(folio)->page)


#define ARCH_IMPLEMENTS_FLUSH_DCACHE_FOLIO 0

#define COMMAND_LINE_SIZE 2048
#define LOWMEMSIZE()	(0x9f000)
#define PARAM_SIZE 4096		
#define RESERVE_BRK(name, size)					\
	__section(".bss..brk") __aligned(1) __used	\
	static char __brk_##name[size]




#define DECLARE_IDTENTRY(vector, func)					\
	asmlinkage void asm_##func(void);				\
	asmlinkage void xen_asm_##func(void);				\
	__visible void func(struct pt_regs *regs)
# define DECLARE_IDTENTRY_DEBUG(vector, func)				\
	idtentry_mce_db vector asm_##func func
# define DECLARE_IDTENTRY_DF(vector, func)				\
	idtentry_df vector asm_##func func
#define DECLARE_IDTENTRY_ERRORCODE(vector, func)			\
	idtentry vector asm_##func func has_error_code=1
#define DECLARE_IDTENTRY_IRQ(vector, func)				\
	DECLARE_IDTENTRY_ERRORCODE(vector, func)
#define DECLARE_IDTENTRY_IST(vector, func)				\
	DECLARE_IDTENTRY_RAW(vector, func);				\
	__visible void noist_##func(struct pt_regs *regs)
# define DECLARE_IDTENTRY_MCE(vector, func)				\
	idtentry_mce_db vector asm_##func func
#define DECLARE_IDTENTRY_NMI(vector, func)
#define DECLARE_IDTENTRY_RAW(vector, func)				\
	DECLARE_IDTENTRY(vector, func)
#define DECLARE_IDTENTRY_RAW_ERRORCODE(vector, func)			\
	DECLARE_IDTENTRY_ERRORCODE(vector, func)
#define DECLARE_IDTENTRY_SW(vector, func)
#define DECLARE_IDTENTRY_SYSVEC(vector, func)				\
	DECLARE_IDTENTRY(vector, func)
# define DECLARE_IDTENTRY_VC(vector, func)				\
	idtentry_vc vector asm_##func func
# define DECLARE_IDTENTRY_XENCB(vector, func)				\
	DECLARE_IDTENTRY(vector, func)
#define DEFINE_IDTENTRY(func)						\
static __always_inline void __##func(struct pt_regs *regs);		\
									\
__visible noinstr void func(struct pt_regs *regs)			\
{									\
	irqentry_state_t state = irqentry_enter(regs);			\
									\
	instrumentation_begin();					\
	__##func (regs);						\
	instrumentation_end();						\
	irqentry_exit(regs, state);					\
}									\
									\
static __always_inline void __##func(struct pt_regs *regs)
#define DEFINE_IDTENTRY_DF(func)					\
	DEFINE_IDTENTRY_RAW_ERRORCODE(func)
#define DEFINE_IDTENTRY_ERRORCODE(func)					\
static __always_inline void __##func(struct pt_regs *regs,		\
				     unsigned long error_code);		\
									\
__visible noinstr void func(struct pt_regs *regs,			\
			    unsigned long error_code)			\
{									\
	irqentry_state_t state = irqentry_enter(regs);			\
									\
	instrumentation_begin();					\
	__##func (regs, error_code);					\
	instrumentation_end();						\
	irqentry_exit(regs, state);					\
}									\
									\
static __always_inline void __##func(struct pt_regs *regs,		\
				     unsigned long error_code)
#define DEFINE_IDTENTRY_IRQ(func)					\
static void __##func(struct pt_regs *regs, u32 vector);			\
									\
__visible noinstr void func(struct pt_regs *regs,			\
			    unsigned long error_code)			\
{									\
	irqentry_state_t state = irqentry_enter(regs);			\
	u32 vector = (u32)(u8)error_code;				\
									\
	instrumentation_begin();					\
	kvm_set_cpu_l1tf_flush_l1d();					\
	run_irq_on_irqstack_cond(__##func, regs, vector);		\
	instrumentation_end();						\
	irqentry_exit(regs, state);					\
}									\
									\
static noinline void __##func(struct pt_regs *regs, u32 vector)
#define DEFINE_IDTENTRY_IST(func)					\
	DEFINE_IDTENTRY_RAW(func)
#define DEFINE_IDTENTRY_NOIST(func)					\
	DEFINE_IDTENTRY_RAW(noist_##func)
#define DEFINE_IDTENTRY_RAW(func)					\
__visible noinstr void func(struct pt_regs *regs)
#define DEFINE_IDTENTRY_RAW_ERRORCODE(func)				\
__visible noinstr void func(struct pt_regs *regs, unsigned long error_code)
#define DEFINE_IDTENTRY_SYSVEC(func)					\
static void __##func(struct pt_regs *regs);				\
									\
__visible noinstr void func(struct pt_regs *regs)			\
{									\
	irqentry_state_t state = irqentry_enter(regs);			\
									\
	instrumentation_begin();					\
	kvm_set_cpu_l1tf_flush_l1d();					\
	run_sysvec_on_irqstack_cond(__##func, regs);			\
	instrumentation_end();						\
	irqentry_exit(regs, state);					\
}									\
									\
static noinline void __##func(struct pt_regs *regs)
#define DEFINE_IDTENTRY_SYSVEC_SIMPLE(func)				\
static __always_inline void __##func(struct pt_regs *regs);		\
									\
__visible noinstr void func(struct pt_regs *regs)			\
{									\
	irqentry_state_t state = irqentry_enter(regs);			\
									\
	instrumentation_begin();					\
	__irq_enter_raw();						\
	kvm_set_cpu_l1tf_flush_l1d();					\
	__##func (regs);						\
	__irq_exit_raw();						\
	instrumentation_end();						\
	irqentry_exit(regs, state);					\
}									\
									\
static __always_inline void __##func(struct pt_regs *regs)
#define DEFINE_IDTENTRY_VC_KERNEL(func)				\
	DEFINE_IDTENTRY_RAW_ERRORCODE(kernel_##func)
#define DEFINE_IDTENTRY_VC_USER(func)				\
	DEFINE_IDTENTRY_RAW_ERRORCODE(user_##func)


#define assert_arg_type(arg, proto)					\
	static_assert(__builtin_types_compatible_p(typeof(arg), proto))
#define assert_function_type(func, proto)				\
	static_assert(__builtin_types_compatible_p(typeof(&func), proto))
#define call_on_irqstack(func, asm_call, argconstr...)			\
	call_on_stack(__this_cpu_read(hardirq_stack_ptr),		\
		      func, asm_call, argconstr)
#define call_on_irqstack_cond(func, regs, asm_call, constr, c_args...)	\
{									\
									\
	if (user_mode(regs) || __this_cpu_read(hardirq_stack_inuse)) {	\
		irq_enter_rcu();					\
		func(c_args);						\
		irq_exit_rcu();						\
	} else {							\
									\
		__this_cpu_write(hardirq_stack_inuse, true);		\
		call_on_irqstack(func, asm_call, constr);		\
		__this_cpu_write(hardirq_stack_inuse, false);		\
	}								\
}
#define call_on_stack(stack, func, asm_call, argconstr...)		\
{									\
	register void *tos asm("r11");					\
									\
	tos = ((void *)(stack));					\
									\
	asm_inline volatile(						\
	"movq	%%rsp, (%[tos])				\n"		\
	"movq	%[tos], %%rsp				\n"		\
									\
	asm_call							\
									\
	"popq	%%rsp					\n"		\
									\
	: "+r" (tos), ASM_CALL_CONSTRAINT				\
	: [__func] "i" (func), [tos] "r" (tos) argconstr		\
	: "cc", "rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10",	\
	  "memory"							\
	);								\
}
#define do_softirq_own_stack()						\
{									\
	__this_cpu_write(hardirq_stack_inuse, true);			\
	call_on_irqstack(__do_softirq, ASM_CALL_ARG0);			\
	__this_cpu_write(hardirq_stack_inuse, false);			\
}
#define run_irq_on_irqstack_cond(func, regs, vector)			\
{									\
	assert_function_type(func, void (*)(struct pt_regs *, u32));	\
	assert_arg_type(regs, struct pt_regs *);			\
	assert_arg_type(vector, u32);					\
									\
	call_on_irqstack_cond(func, regs, ASM_CALL_IRQ,			\
			      IRQ_CONSTRAINTS, regs, vector);		\
}
#define run_sysvec_on_irqstack_cond(func, regs)				\
{									\
	assert_function_type(func, void (*)(struct pt_regs *));		\
	assert_arg_type(regs, struct pt_regs *);			\
									\
	call_on_irqstack_cond(func, regs, ASM_CALL_SYSVEC,		\
			      SYSVEC_CONSTRAINTS, regs);		\
}

#define SC_ARG64(name) u32, name##_lo, u32, name##_hi
#define SC_VAL64(type, name) ((type) name##_hi << 32 | name##_lo)
#define SYSCALL32_DEFINE1 COMPAT_SYSCALL_DEFINE1
#define SYSCALL32_DEFINE2 COMPAT_SYSCALL_DEFINE2
#define SYSCALL32_DEFINE3 COMPAT_SYSCALL_DEFINE3
#define SYSCALL32_DEFINE4 COMPAT_SYSCALL_DEFINE4
#define SYSCALL32_DEFINE5 COMPAT_SYSCALL_DEFINE5
#define SYSCALL32_DEFINE6 COMPAT_SYSCALL_DEFINE6
#define SYSCALL_DEFINE0(sname)					\
	SYSCALL_METADATA(_##sname, 0);				\
	asmlinkage long sys_##sname(void);			\
	ALLOW_ERROR_INJECTION(sys_##sname, ERRNO);		\
	asmlinkage long sys_##sname(void)
#define SYSCALL_DEFINE1(name, ...) SYSCALL_DEFINEx(1, _##name, __VA_ARGS__)
#define SYSCALL_DEFINE2(name, ...) SYSCALL_DEFINEx(2, _##name, __VA_ARGS__)
#define SYSCALL_DEFINE3(name, ...) SYSCALL_DEFINEx(3, _##name, __VA_ARGS__)
#define SYSCALL_DEFINE4(name, ...) SYSCALL_DEFINEx(4, _##name, __VA_ARGS__)
#define SYSCALL_DEFINE5(name, ...) SYSCALL_DEFINEx(5, _##name, __VA_ARGS__)
#define SYSCALL_DEFINE6(name, ...) SYSCALL_DEFINEx(6, _##name, __VA_ARGS__)
#define SYSCALL_DEFINEx(x, sname, ...)				\
	SYSCALL_METADATA(sname, x, __VA_ARGS__)			\
	__SYSCALL_DEFINEx(x, sname, __VA_ARGS__)
#define SYSCALL_METADATA(sname, nb, ...)			\
	static const char *types_##sname[] = {			\
		__MAP(nb,__SC_STR_TDECL,__VA_ARGS__)		\
	};							\
	static const char *args_##sname[] = {			\
		__MAP(nb,__SC_STR_ADECL,__VA_ARGS__)		\
	};							\
	SYSCALL_TRACE_ENTER_EVENT(sname);			\
	SYSCALL_TRACE_EXIT_EVENT(sname);			\
	static struct syscall_metadata __used			\
	  __syscall_meta_##sname = {				\
		.name 		= "sys"#sname,			\
		.syscall_nr	= -1,		\
		.nb_args 	= nb,				\
		.types		= nb ? types_##sname : NULL,	\
		.args		= nb ? args_##sname : NULL,	\
		.enter_event	= &event_enter_##sname,		\
		.exit_event	= &event_exit_##sname,		\
		.enter_fields	= LIST_HEAD_INIT(__syscall_meta_##sname.enter_fields), \
	};							\
	static struct syscall_metadata __used			\
	  __section("__syscalls_metadata")			\
	 *__p_syscall_meta_##sname = &__syscall_meta_##sname;
#define SYSCALL_TRACE_ENTER_EVENT(sname)				\
	static struct syscall_metadata __syscall_meta_##sname;		\
	static struct trace_event_call __used				\
	  event_enter_##sname = {					\
		.class			= &event_class_syscall_enter,	\
		{							\
			.name                   = "sys_enter"#sname,	\
		},							\
		.event.funcs            = &enter_syscall_print_funcs,	\
		.data			= (void *)&__syscall_meta_##sname,\
		.flags                  = TRACE_EVENT_FL_CAP_ANY,	\
	};								\
	static struct trace_event_call __used				\
	  __section("_ftrace_events")					\
	 *__event_enter_##sname = &event_enter_##sname;
#define SYSCALL_TRACE_EXIT_EVENT(sname)					\
	static struct syscall_metadata __syscall_meta_##sname;		\
	static struct trace_event_call __used				\
	  event_exit_##sname = {					\
		.class			= &event_class_syscall_exit,	\
		{							\
			.name                   = "sys_exit"#sname,	\
		},							\
		.event.funcs		= &exit_syscall_print_funcs,	\
		.data			= (void *)&__syscall_meta_##sname,\
		.flags                  = TRACE_EVENT_FL_CAP_ANY,	\
	};								\
	static struct trace_event_call __used				\
	  __section("_ftrace_events")					\
	*__event_exit_##sname = &event_exit_##sname;

#define __MAP(n,...) __MAP##n(__VA_ARGS__)

#define __MAP1(m,t,a,...) m(t,a)
#define __MAP2(m,t,a,...) m(t,a), __MAP1(m,__VA_ARGS__)
#define __MAP3(m,t,a,...) m(t,a), __MAP2(m,__VA_ARGS__)
#define __MAP4(m,t,a,...) m(t,a), __MAP3(m,__VA_ARGS__)
#define __MAP5(m,t,a,...) m(t,a), __MAP4(m,__VA_ARGS__)
#define __MAP6(m,t,a,...) m(t,a), __MAP5(m,__VA_ARGS__)
#define __PROTECT(...) asmlinkage_protect(__VA_ARGS__)
#define __SC_ARGS(t, a)	a
#define __SC_CAST(t, a)	(__force t) a
#define __SC_DECL(t, a)	t a
#define __SC_LONG(t, a) __typeof(__builtin_choose_expr(__TYPE_IS_LL(t), 0LL, 0L)) a
#define __SC_STR_ADECL(t, a)	#a
#define __SC_STR_TDECL(t, a)	#t
#define __SC_TEST(t, a) (void)BUILD_BUG_ON_ZERO(!__TYPE_IS_LL(t) && sizeof(t) > sizeof(long))
#define __SYSCALL_DEFINEx(x, name, ...)					\
	__diag_push();							\
	__diag_ignore(GCC, 8, "-Wattribute-alias",			\
		      "Type aliasing is used to sanitize syscall arguments");\
	asmlinkage long sys##name(__MAP(x,__SC_DECL,__VA_ARGS__))	\
		__attribute__((alias(__stringify(__se_sys##name))));	\
	ALLOW_ERROR_INJECTION(sys##name, ERRNO);			\
	static inline long __do_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__));\
	asmlinkage long __se_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__));	\
	asmlinkage long __se_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__))	\
	{								\
		long ret = __do_sys##name(__MAP(x,__SC_CAST,__VA_ARGS__));\
		__MAP(x,__SC_TEST,__VA_ARGS__);				\
		__PROTECT(x, ret,__MAP(x,__SC_ARGS,__VA_ARGS__));	\
		return ret;						\
	}								\
	__diag_pop();							\
	static inline long __do_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__))
#define __TYPE_AS(t, v)	__same_type((__force t)0, v)
#define __TYPE_IS_L(t)	(__TYPE_AS(t, 0L))
#define __TYPE_IS_LL(t) (__TYPE_AS(t, 0LL) || __TYPE_AS(t, 0ULL))
#define __TYPE_IS_UL(t)	(__TYPE_AS(t, 0UL))



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

#define kprobe_busy_begin()	do {} while (0)
#define kprobe_busy_end()	do {} while (0)
#define kprobe_flush_task(tk)	do {} while (0)
# define NOKPROBE_SYMBOL(fname)

# define __NOKPROBE_SYMBOL(fname)				\
static unsigned long __used					\
	__section("_kprobe_blacklist")				\
	_kbl_addr_##fname = (unsigned long)fname;
# define __kprobes

#define rethook_flush_task(tsk)	do { } while (0)

#define REFS_ON_FREELIST 0x80000000
#define XEN_CPUID_FEAT1_MMU_PT_UPDATE_PRESERVE_AD  (1u<<0)
#define XEN_CPUID_FIRST_LEAF 0x40000000
#define XEN_CPUID_LEAF(i)    (XEN_CPUID_FIRST_LEAF + (i))
#define XEN_CPUID_MACHINE_ADDRESS_WIDTH_MASK (0xffu << 0)
#define XEN_CPUID_MAX_NUM_LEAVES 5
#define XEN_CPUID_SIGNATURE_EBX 0x566e6558 
#define XEN_CPUID_SIGNATURE_ECX 0x65584d4d 
#define XEN_CPUID_SIGNATURE_EDX 0x4d4d566e 
#define XEN_HVM_CPUID_APIC_ACCESS_VIRT (1u << 0) 
#define XEN_HVM_CPUID_DOMID_PRESENT    (1u << 4) 
#define XEN_HVM_CPUID_EXT_DEST_ID      (1u << 5)
#define XEN_HVM_CPUID_IOMMU_MAPPINGS   (1u << 2)
#define XEN_HVM_CPUID_VCPU_ID_PRESENT  (1u << 3) 
#define XEN_HVM_CPUID_X2APIC_VIRT      (1u << 1) 
#define _XEN_CPUID_FEAT1_MMU_PT_UPDATE_PRESERVE_AD 0



#define __HYPERCALL_1ARG(a1)						\
	__HYPERCALL_0ARG()		__arg1 = (unsigned long)(a1);
#define __HYPERCALL_2ARG(a1,a2)						\
	__HYPERCALL_1ARG(a1)		__arg2 = (unsigned long)(a2);
#define __HYPERCALL_3ARG(a1,a2,a3)					\
	__HYPERCALL_2ARG(a1,a2)		__arg3 = (unsigned long)(a3);
#define __HYPERCALL_4ARG(a1,a2,a3,a4)					\
	__HYPERCALL_3ARG(a1,a2,a3)	__arg4 = (unsigned long)(a4);
#define __HYPERCALL_5ARG(a1,a2,a3,a4,a5)				\
	__HYPERCALL_4ARG(a1,a2,a3,a4)	__arg5 = (unsigned long)(a5);
#define __HYPERCALL_ENTRY(x)						\
	[offset] "i" (__HYPERVISOR_##x * sizeof(hypercall_page[0]))
#define _hypercall0(type, name)						\
({									\
	__HYPERCALL_DECLS;						\
	__HYPERCALL_0ARG();						\
	asm volatile (__HYPERCALL					\
		      : __HYPERCALL_0PARAM				\
		      : __HYPERCALL_ENTRY(name)				\
		      : __HYPERCALL_CLOBBER0);				\
	(type)__res;							\
})
#define _hypercall1(type, name, a1)					\
({									\
	__HYPERCALL_DECLS;						\
	__HYPERCALL_1ARG(a1);						\
	asm volatile (__HYPERCALL					\
		      : __HYPERCALL_1PARAM				\
		      : __HYPERCALL_ENTRY(name)				\
		      : __HYPERCALL_CLOBBER1);				\
	(type)__res;							\
})
#define _hypercall2(type, name, a1, a2)					\
({									\
	__HYPERCALL_DECLS;						\
	__HYPERCALL_2ARG(a1, a2);					\
	asm volatile (__HYPERCALL					\
		      : __HYPERCALL_2PARAM				\
		      : __HYPERCALL_ENTRY(name)				\
		      : __HYPERCALL_CLOBBER2);				\
	(type)__res;							\
})
#define _hypercall3(type, name, a1, a2, a3)				\
({									\
	__HYPERCALL_DECLS;						\
	__HYPERCALL_3ARG(a1, a2, a3);					\
	asm volatile (__HYPERCALL					\
		      : __HYPERCALL_3PARAM				\
		      : __HYPERCALL_ENTRY(name)				\
		      : __HYPERCALL_CLOBBER3);				\
	(type)__res;							\
})
#define _hypercall4(type, name, a1, a2, a3, a4)				\
({									\
	__HYPERCALL_DECLS;						\
	__HYPERCALL_4ARG(a1, a2, a3, a4);				\
	asm volatile (__HYPERCALL					\
		      : __HYPERCALL_4PARAM				\
		      : __HYPERCALL_ENTRY(name)				\
		      : __HYPERCALL_CLOBBER4);				\
	(type)__res;							\
})
#define MAX_UNION_SIZE 16
#define MCE_GETCLEAR_FLAGS   _IOR('M', 3, int)
#define MCE_GET_LOG_LEN      _IOR('M', 2, int)
#define MCE_GET_RECORD_LEN   _IOR('M', 1, int)
#define MCINFO_MAXSIZE 768
#define MC_ACTION_CACHE_SHRINK (0x1 << 2)
#define MC_ACTION_CPU_OFFLINE (0x1 << 1)
#define MC_ACTION_PAGE_OFFLINE (0x1 << 0)
#define MC_NCAPS 7
#define REC_ACTION_NEED_RESET (0x1 << 2)
#define REC_ACTION_NONE (0x1 << 1)
#define REC_ACTION_RECOVERED (0x1 << 0)
#define VIRQ_MCA VIRQ_ARCH_0
#define XEN_MCE_LOG_LEN 32
#define XEN_MCE_OVERFLOW 0		
#define __HYPERVISOR_mca __HYPERVISOR_arch_0
#define __MC_MSR_ARRAYSIZE 8
#define __MC_NMSRS 1

#define x86_mcinfo_first(_mi)       \
	((struct mcinfo_common *)(_mi)->mi_data)
#define x86_mcinfo_nentries(_mi)    \
	((_mi)->mi_nentries)
#define x86_mcinfo_next(_mic)       \
	((struct mcinfo_common *)((uint8_t *)(_mic) + (_mic)->size))
#define PHYSDEVOP_DBGP_BUS_PCI          1
#define PHYSDEVOP_DBGP_BUS_UNKNOWN      0
#define PHYSDEVOP_DBGP_RESET_DONE       2
#define PHYSDEVOP_DBGP_RESET_PREPARE    1
#define PHYSDEVOP_IRQ_NEEDS_UNMASK_NOTIFY XENIRQSTAT_needs_eoi
#define PHYSDEVOP_dbgp_op               29
#define PHYSDEVOP_get_free_pirq    23
#define PHYSDEVOP_get_nr_pirqs    22
#define PHYSDEVOP_pci_device_add        25
#define PHYSDEVOP_pci_device_remove     26
#define PHYSDEVOP_pci_mmcfg_reserved    24
#define PHYSDEVOP_pirq_eoi_gmfn_v1       17
#define PHYSDEVOP_pirq_eoi_gmfn_v2       28
#define PHYSDEVOP_prepare_msix          30
#define PHYSDEVOP_release_msix          31
#define PHYSDEVOP_restore_msi            19
#define PHYSDEVOP_restore_msi_ext       27
#define PHYSDEVOP_setup_gsi    21
#define XEN_PCI_DEV_EXTFN              0x1
#define XEN_PCI_DEV_PXM                0x4
#define XEN_PCI_DEV_VIRTFN             0x2
#define XEN_PCI_MMCFG_RESERVED         0x1

#define SCHEDOP_block       1
#define SCHEDOP_pin_override 7
#define SCHEDOP_poll        3
#define SCHEDOP_remote_shutdown        4
#define SCHEDOP_shutdown    2
#define SCHEDOP_shutdown_code 5
#define SCHEDOP_watchdog    6
#define SCHEDOP_yield       0
#define SHUTDOWN_MAX        5  
#define SHUTDOWN_crash      3  
#define SHUTDOWN_poweroff   0  
#define SHUTDOWN_reboot     1  
#define SHUTDOWN_soft_reset 5
#define SHUTDOWN_suspend    2  
#define SHUTDOWN_watchdog   4  

#define BIND_PIRQ__WILL_SHARE 1
#define EVTCHNOP_bind_interdomain 0
#define EVTCHNOP_expand_array    12
#define EVTCHNOP_init_control    11
#define EVTCHNOP_set_priority    13
#define EVTCHN_2L_NR_CHANNELS (sizeof(xen_ulong_t) * sizeof(xen_ulong_t) * 64)
#define EVTCHN_FIFO_BUSY    28
#define EVTCHN_FIFO_LINKED  29
#define EVTCHN_FIFO_LINK_BITS 17
#define EVTCHN_FIFO_LINK_MASK ((1 << EVTCHN_FIFO_LINK_BITS) - 1)
#define EVTCHN_FIFO_MASKED  30
#define EVTCHN_FIFO_MAX_QUEUES (EVTCHN_FIFO_PRIORITY_MIN + 1)
#define EVTCHN_FIFO_NR_CHANNELS (1 << EVTCHN_FIFO_LINK_BITS)
#define EVTCHN_FIFO_PENDING 31
#define EVTCHN_FIFO_PRIORITY_DEFAULT 7
#define EVTCHN_FIFO_PRIORITY_MAX     0
#define EVTCHN_FIFO_PRIORITY_MIN     15

#define ASM_CLAC \
	ALTERNATIVE("", __ASM_CLAC, X86_FEATURE_SMAP)
#define ASM_STAC \
	ALTERNATIVE("", __ASM_STAC, X86_FEATURE_SMAP)


#define pci_xen 0
#define pci_xen_init (0)
#define APIC_DEBUG   2
#define APIC_QUIET   0
#define APIC_VERBOSE 1

#define apic_driver(sym)					\
	static const struct apic *__apicdrivers_##sym __used		\
	__aligned(sizeof(struct apic *))			\
	__section(".apicdrivers") = { &sym }
#define apic_drivers(sym1, sym2)					\
	static struct apic *__apicdrivers_##sym1##sym2[2] __used	\
	__aligned(sizeof(struct apic *))				\
	__section(".apicdrivers") = { &sym1, &sym2 }
#define apic_printk(v, s, a...) do {       \
		if ((v) <= apic_verbosity) \
			printk(s, ##a);    \
	} while (0)
# define setup_boot_APIC_clock x86_init_noop
# define setup_secondary_APIC_clock x86_init_noop
#define x2apic_supported()	(boot_cpu_has(X86_FEATURE_X2APIC))


#define arch_irq_stat		arch_irq_stat
#define inc_irq_stat(member)	this_cpu_inc(irq_stat.member)


#define xen_domain()		(xen_domain_type != XEN_NATIVE)
#define xen_hvm_domain()	(xen_domain_type == XEN_HVM_DOMAIN)
#define xen_initial_domain()	(xen_domain() && \
				 (xen_start_flags & SIF_INITDOMAIN))
#define xen_pv_domain()		(xen_domain_type == XEN_PV_DOMAIN)
#define xen_pvh_domain()	(xen_pvh)


#define XEN_HVM_MEMMAP_TYPE_ACPI      3
#define XEN_HVM_MEMMAP_TYPE_DISABLED  6
#define XEN_HVM_MEMMAP_TYPE_NVS       4
#define XEN_HVM_MEMMAP_TYPE_PMEM      7
#define XEN_HVM_MEMMAP_TYPE_RAM       1
#define XEN_HVM_MEMMAP_TYPE_RESERVED  2
#define XEN_HVM_MEMMAP_TYPE_UNUSABLE  5
#define XEN_HVM_START_MAGIC_VALUE 0x336ec578


#define XEN_EXTRA_MEM_MAX_REGIONS 128 
#define XEN_PFN_DOWN(x)	((x) >> XEN_PAGE_SHIFT)
#define XEN_PFN_UP(x)	(((x) + XEN_PAGE_SIZE-1) >> XEN_PAGE_SHIFT)

#define page_to_xen_pfn(page)		\
	((page_to_pfn(page)) << (PAGE_SHIFT - XEN_PAGE_SHIFT))
#define xen_offset_in_page(p)	((unsigned long)(p) & ~XEN_PAGE_MASK)
#define xen_pfn_to_page(xen_pfn)	\
	(pfn_to_page((unsigned long)(xen_pfn) >> (PAGE_SHIFT - XEN_PAGE_SHIFT)))

#define XENFEAT_ARM_SMCCC_supported       14
#define XENFEAT_NR_SUBMAPS 1
#define XENFEAT_auto_translated_physmap    2
#define XENFEAT_direct_mapped             17
#define XENFEAT_dom0                      11
#define XENFEAT_gnttab_map_avail_bits      7
#define XENFEAT_highmem_assist             6
#define XENFEAT_hvm_callback_vector        8
#define XENFEAT_hvm_pirqs           10
#define XENFEAT_hvm_safe_pvclock           9
#define XENFEAT_linux_rsdp_unrestricted   15
#define XENFEAT_memory_op_vnode_supported 13
#define XENFEAT_mmu_pt_update_preserve_ad  5
#define XENFEAT_not_direct_mapped         16
#define XENFEAT_pae_pgdir_above_4gb        4
#define XENFEAT_supervisor_mode_kernel     3
#define XENFEAT_writable_descriptor_tables 1
#define XENFEAT_writable_page_tables       0

#define XENNMI_register_callback   0
#define XENNMI_unregister_callback 1
#define XEN_NMIREASON_io_error      (1UL << _XEN_NMIREASON_io_error)
#define XEN_NMIREASON_pci_serr      (1UL << _XEN_NMIREASON_pci_serr)
#define XEN_NMIREASON_unknown       (1UL << _XEN_NMIREASON_unknown)
#define _XEN_NMIREASON_io_error     0
#define _XEN_NMIREASON_pci_serr     1
#define _XEN_NMIREASON_unknown      2

#define XENMAPSPACE_dev_mmio     5 
#define XENMAPSPACE_gmfn         2 
#define XENMAPSPACE_gmfn_foreign 4 
#define XENMAPSPACE_gmfn_range   3 
#define XENMAPSPACE_grant_table  1 
#define XENMAPSPACE_shared_info  0 
#define XENMEM_acquire_resource 28
#define XENMEM_add_to_physmap      7
#define XENMEM_add_to_physmap_range 23
#define XENMEM_current_reservation  3
#define XENMEM_decrease_reservation 1
#define XENMEM_exchange             11
#define XENMEM_increase_reservation 0
#define XENMEM_machine_memory_map   10
#define XENMEM_machphys_mapping     12
#define XENMEM_machphys_mfn_list    5
#define XENMEM_maximum_ram_page     2
#define XENMEM_maximum_reservation  4
#define XENMEM_memory_map           9
#define XENMEM_populate_physmap     6
#define XENMEM_remove_from_physmap      15
#define XENMEM_resource_grant_table 1
#define XENMEM_resource_grant_table_id_shared 0
#define XENMEM_resource_grant_table_id_status 1
#define XENMEM_resource_ioreq_server 0
#define XENMEM_resource_ioreq_server_frame_bufioreq 0
#define XENMEM_resource_ioreq_server_frame_ioreq(n) (1 + (n))
#define XENMEM_rsrc_acq_caller_owned (1u << _XENMEM_rsrc_acq_caller_owned)
#define _XENMEM_rsrc_acq_caller_owned 0

#define RUNSTATE_blocked  2
#define RUNSTATE_offline  3
#define RUNSTATE_runnable 1
#define RUNSTATE_running  0
#define VCPUOP_get_physid           12 
#define VCPUOP_register_runstate_memory_area 5
#define VCPUOP_register_vcpu_info   10  
#define VCPUOP_register_vcpu_time_memory_area   13
#define VCPUOP_send_nmi             11
#define VCPUOP_stop_singleshot_timer 9 
#define VCPU_SSHOTTMR_future  (1U << _VCPU_SSHOTTMR_future)
#define _VCPU_SSHOTTMR_future (0)

#define xen_vcpu_physid_to_x86_acpiid(physid) ((uint32_t)((physid) >> 32))
#define xen_vcpu_physid_to_x86_apicid(physid) ((uint32_t)(physid))
#define XENVER_build_id 10
#define XENVER_capabilities 3
#define XENVER_changeset 4
#define XENVER_commandline 9
#define XENVER_compile_info 2
#define XENVER_extraversion 1
#define XENVER_get_features 6
#define XENVER_guest_handle 8
#define XENVER_pagesize 7
#define XENVER_platform_parameters 5
#define XENVER_version      0
#define XEN_CAPABILITIES_INFO_LEN (sizeof(struct xen_capabilities_info))
#define XEN_CHANGESET_INFO_LEN (sizeof(struct xen_changeset_info))
#define XEN_EXTRAVERSION_LEN (sizeof(struct xen_extraversion))

#define XEN_IRQ_PRIORITY_DEFAULT EVTCHN_FIFO_PRIORITY_DEFAULT
#define XEN_IRQ_PRIORITY_MAX     EVTCHN_FIFO_PRIORITY_MAX
#define XEN_IRQ_PRIORITY_MIN     EVTCHN_FIFO_PRIORITY_MIN


#define msi_desc_to_dev(desc)		((desc)->dev)
#define msi_for_each_desc(desc, dev, filter)			\
	for ((desc) = msi_first_desc((dev), (filter)); (desc);	\
	     (desc) = msi_next_desc((dev), (filter)))
#define platform_msi_create_device_domain(dev, nvec, write, ops, data)	\
	__platform_msi_create_device_domain(dev, nvec, false, write, ops, data)
#define platform_msi_create_device_tree_domain(dev, nvec, write, ops, data) \
	__platform_msi_create_device_domain(dev, nvec, true, write, ops, data)
#define IRQ_MSK(n) (u32)((n) < 32 ? ((1 << (n)) - 1) : UINT_MAX)
# define NR_IRQS_LEGACY 0

#define __irqd_to_state(d) ACCESS_PRIVATE((d)->common, state_use_accessors)
#define devm_irq_alloc_desc(dev, node)				\
	devm_irq_alloc_descs(dev, -1, 1, 1, node)
#define devm_irq_alloc_desc_at(dev, at, node)			\
	devm_irq_alloc_descs(dev, at, at, 1, node)
#define devm_irq_alloc_desc_from(dev, from, node)		\
	devm_irq_alloc_descs(dev, -1, from, 1, node)
#define devm_irq_alloc_descs(dev, irq, from, cnt, node)		\
	__devm_irq_alloc_descs(dev, irq, from, cnt, node, THIS_MODULE, NULL)
#define devm_irq_alloc_descs_from(dev, from, cnt, node)		\
	devm_irq_alloc_descs(dev, -1, from, cnt, node)
#define irq_alloc_desc(node)			\
	irq_alloc_descs(-1, 1, 1, node)
#define irq_alloc_desc_at(at, node)		\
	irq_alloc_descs(at, at, 1, node)
#define irq_alloc_desc_from(from, node)		\
	irq_alloc_descs(-1, from, 1, node)
#define irq_alloc_descs(irq, from, cnt, node)	\
	__irq_alloc_descs(irq, from, cnt, node, THIS_MODULE, NULL)
#define irq_alloc_descs_from(from, cnt, node)	\
	irq_alloc_descs(-1, from, cnt, node)
#define irq_alloc_domain_generic_chips(d, irqs_per_chip, num_ct, name,	\
				       handler,	clr, set, flags)	\
({									\
	MAYBE_BUILD_BUG_ON(irqs_per_chip > 32);				\
	__irq_alloc_domain_generic_chips(d, irqs_per_chip, num_ct, name,\
					 handler, clr, set, flags);	\
})
#define irq_gc_lock_irqsave(gc, flags)	\
	raw_spin_lock_irqsave(&(gc)->lock, flags)
#define irq_gc_unlock_irqrestore(gc, flags)	\
	raw_spin_unlock_irqrestore(&(gc)->lock, flags)
#define set_handle_irq(handle_irq)		\
	do {					\
		(void)handle_irq;		\
		WARN_ON(1);			\
	} while (0)




#define CHECKEXTENSIONSPRESENT 0x41
#define EDDEXTSIZE 8		
#define EDDMAGIC1 0x55AA
#define EDDMAGIC2 0xAA55
#define EDDMAXNR 6		
#define EDDNR 0x1e9		
#define EDDPARMSIZE 74
#define EDD_EXT_64BIT_EXTENSIONS            (1 << 3)
#define EDD_EXT_DEVICE_LOCKING_AND_EJECTING (1 << 1)
#define EDD_EXT_ENHANCED_DISK_DRIVE_SUPPORT (1 << 2)
#define EDD_EXT_FIXED_DISK_ACCESS           (1 << 0)
#define EDD_INFO_DMA_BOUNDARY_ERROR_TRANSPARENT (1 << 0)
#define EDD_INFO_GEOMETRY_VALID                (1 << 1)
#define EDD_INFO_LOCKABLE                      (1 << 5)
#define EDD_INFO_MEDIA_CHANGE_NOTIFICATION     (1 << 4)
#define EDD_INFO_NO_MEDIA_PRESENT              (1 << 6)
#define EDD_INFO_REMOVABLE                     (1 << 2)
#define EDD_INFO_USE_INT13_FN50                (1 << 7)
#define EDD_INFO_WRITE_VERIFY                  (1 << 3)
#define EDD_MBR_SIG_BUF    0x290  
#define EDD_MBR_SIG_MAX 16        
#define EDD_MBR_SIG_NR_BUF 0x1ea  
#define EDD_MBR_SIG_OFFSET 0x1B8  
#define GETDEVICEPARAMETERS 0x48
#define LEGACYGETDEVICEPARAMETERS 0x08
#define READ_SECTORS 0x02         

#define DECLARE_PCI_FIXUP_CLASS_EARLY(vendor, device, class,		\
					 class_shift, hook)		\
	DECLARE_PCI_FIXUP_SECTION(.pci_fixup_early,			\
		hook, vendor, device, class, class_shift, hook)
#define DECLARE_PCI_FIXUP_CLASS_ENABLE(vendor, device, class,		\
					 class_shift, hook)		\
	DECLARE_PCI_FIXUP_SECTION(.pci_fixup_enable,			\
		hook, vendor, device, class, class_shift, hook)
#define DECLARE_PCI_FIXUP_CLASS_FINAL(vendor, device, class,		\
					 class_shift, hook)		\
	DECLARE_PCI_FIXUP_SECTION(.pci_fixup_final,			\
		hook, vendor, device, class, class_shift, hook)
#define DECLARE_PCI_FIXUP_CLASS_HEADER(vendor, device, class,		\
					 class_shift, hook)		\
	DECLARE_PCI_FIXUP_SECTION(.pci_fixup_header,			\
		hook, vendor, device, class, class_shift, hook)
#define DECLARE_PCI_FIXUP_CLASS_RESUME(vendor, device, class,		\
					 class_shift, hook)		\
	DECLARE_PCI_FIXUP_SECTION(.pci_fixup_resume,			\
		resume##hook, vendor, device, class, class_shift, hook)
#define DECLARE_PCI_FIXUP_CLASS_RESUME_EARLY(vendor, device, class,	\
					 class_shift, hook)		\
	DECLARE_PCI_FIXUP_SECTION(.pci_fixup_resume_early,		\
		resume_early##hook, vendor, device, class, class_shift, hook)
#define DECLARE_PCI_FIXUP_CLASS_SUSPEND(vendor, device, class,		\
					 class_shift, hook)		\
	DECLARE_PCI_FIXUP_SECTION(.pci_fixup_suspend,			\
		suspend##hook, vendor, device, class, class_shift, hook)
#define DECLARE_PCI_FIXUP_CLASS_SUSPEND_LATE(vendor, device, class,	\
					 class_shift, hook)		\
	DECLARE_PCI_FIXUP_SECTION(.pci_fixup_suspend_late,		\
		suspend_late##hook, vendor, device, class, class_shift, hook)
#define DECLARE_PCI_FIXUP_EARLY(vendor, device, hook)			\
	DECLARE_PCI_FIXUP_SECTION(.pci_fixup_early,			\
		hook, vendor, device, PCI_ANY_ID, 0, hook)
#define DECLARE_PCI_FIXUP_ENABLE(vendor, device, hook)			\
	DECLARE_PCI_FIXUP_SECTION(.pci_fixup_enable,			\
		hook, vendor, device, PCI_ANY_ID, 0, hook)
#define DECLARE_PCI_FIXUP_FINAL(vendor, device, hook)			\
	DECLARE_PCI_FIXUP_SECTION(.pci_fixup_final,			\
		hook, vendor, device, PCI_ANY_ID, 0, hook)
#define DECLARE_PCI_FIXUP_HEADER(vendor, device, hook)			\
	DECLARE_PCI_FIXUP_SECTION(.pci_fixup_header,			\
		hook, vendor, device, PCI_ANY_ID, 0, hook)
#define DECLARE_PCI_FIXUP_RESUME(vendor, device, hook)			\
	DECLARE_PCI_FIXUP_SECTION(.pci_fixup_resume,			\
		resume##hook, vendor, device, PCI_ANY_ID, 0, hook)
#define DECLARE_PCI_FIXUP_RESUME_EARLY(vendor, device, hook)		\
	DECLARE_PCI_FIXUP_SECTION(.pci_fixup_resume_early,		\
		resume_early##hook, vendor, device, PCI_ANY_ID, 0, hook)
#define DECLARE_PCI_FIXUP_SECTION(sec, name, vendor, device, class,	\
				  class_shift, hook)			\
	__DECLARE_PCI_FIXUP_SECTION(sec, name, vendor, device, class,	\
				  class_shift, hook, __UNIQUE_ID(hook))
#define DECLARE_PCI_FIXUP_SUSPEND(vendor, device, hook)			\
	DECLARE_PCI_FIXUP_SECTION(.pci_fixup_suspend,			\
		suspend##hook, vendor, device, PCI_ANY_ID, 0, hook)
#define DECLARE_PCI_FIXUP_SUSPEND_LATE(vendor, device, hook)		\
	DECLARE_PCI_FIXUP_SECTION(.pci_fixup_suspend_late,		\
		suspend_late##hook, vendor, device, PCI_ANY_ID, 0, hook)

#define PCI_BRIDGE_RESOURCE_NUM 4
#define PCI_BUS_NUM(x) (((x) >> 8) & 0xff)
#define PCI_DEVICE(vend,dev) \
	.vendor = (vend), .device = (dev), \
	.subvendor = PCI_ANY_ID, .subdevice = PCI_ANY_ID
#define PCI_DEVICE_CLASS(dev_class,dev_class_mask) \
	.class = (dev_class), .class_mask = (dev_class_mask), \
	.vendor = PCI_ANY_ID, .device = PCI_ANY_ID, \
	.subvendor = PCI_ANY_ID, .subdevice = PCI_ANY_ID
#define PCI_DEVICE_DATA(vend, dev, data) \
	.vendor = PCI_VENDOR_ID_##vend, .device = PCI_DEVICE_ID_##vend##_##dev, \
	.subvendor = PCI_ANY_ID, .subdevice = PCI_ANY_ID, 0, 0, \
	.driver_data = (kernel_ulong_t)(data)
#define PCI_DEVICE_DRIVER_OVERRIDE(vend, dev, driver_override) \
	.vendor = (vend), .device = (dev), .subvendor = PCI_ANY_ID, \
	.subdevice = PCI_ANY_ID, .override_only = (driver_override)
#define PCI_DEVICE_SUB(vend, dev, subvend, subdev) \
	.vendor = (vend), .device = (dev), \
	.subvendor = (subvend), .subdevice = (subdev)
#define PCI_DEVID(bus, devfn)	((((u16)(bus)) << 8) | (devfn))
#define PCI_DOMAIN_NR_NOT_SET (-1)
#define PCI_DRIVER_OVERRIDE_DEVICE_VFIO(vend, dev) \
	PCI_DEVICE_DRIVER_OVERRIDE(vend, dev, PCI_ID_F_VFIO_DRIVER_OVERRIDE)
#define PCI_IRQ_ALL_TYPES \
	(PCI_IRQ_LEGACY | PCI_IRQ_MSI | PCI_IRQ_MSIX)
#define PCI_NUM_RESET_METHODS 7
#define PCI_POSSIBLE_ERROR(val)		((val) == ((typeof(val)) PCI_ERROR_RESPONSE))
#define PCI_SET_ERROR_RESPONSE(val)	(*(val) = ((typeof(*(val))) PCI_ERROR_RESPONSE))
#define PCI_STATUS_ERROR_BITS (PCI_STATUS_DETECTED_PARITY  | \
			       PCI_STATUS_SIG_SYSTEM_ERROR | \
			       PCI_STATUS_REC_MASTER_ABORT | \
			       PCI_STATUS_REC_TARGET_ABORT | \
			       PCI_STATUS_SIG_TARGET_ABORT | \
			       PCI_STATUS_PARITY)
#define PCI_VDEVICE(vend, dev) \
	.vendor = PCI_VENDOR_ID_##vend, .device = (dev), \
	.subvendor = PCI_ANY_ID, .subdevice = PCI_ANY_ID, 0, 0
#define PCI_VGA_STATE_CHANGE_BRIDGE (1 << 0)
#define PCI_VGA_STATE_CHANGE_DECODES (1 << 1)
#define PCI_VPD_LRDT_ID(x)		((x) | PCI_VPD_LRDT)
#define _PCI_NOP(o, s, t) \
	static inline int pci_##o##_config_##s(struct pci_dev *dev, \
						int where, t val) \
		{ return PCIBIOS_FUNC_NOT_SUPPORTED; }
#define _PCI_NOP_ALL(o, x)	_PCI_NOP(o, byte, u8 x) \
				_PCI_NOP(o, word, u16 x) \
				_PCI_NOP(o, dword, u32 x)
#define __DECLARE_PCI_FIXUP_SECTION(sec, name, vendor, device, class,	\
				  class_shift, hook, stub)		\
	void __cficanonical stub(struct pci_dev *dev);			\
	void __cficanonical stub(struct pci_dev *dev)			\
	{ 								\
		hook(dev); 						\
	}								\
	___DECLARE_PCI_FIXUP_SECTION(sec, name, vendor, device, class,	\
				  class_shift, stub)
#define ___DECLARE_PCI_FIXUP_SECTION(sec, name, vendor, device, class,	\
				    class_shift, hook)			\
	__ADDRESSABLE(hook)						\
	asm(".section "	#sec ", \"a\"				\n"	\
	    ".balign	16					\n"	\
	    ".short "	#vendor ", " #device "			\n"	\
	    ".long "	#class ", " #class_shift "		\n"	\
	    ".long "	#hook " - .				\n"	\
	    ".previous						\n");
#define arch_can_pci_mmap_io()		0
#define arch_can_pci_mmap_wc()		0
#define builtin_pci_driver(__pci_driver) \
	builtin_driver(__pci_driver, pci_register_driver)
#define dev_is_pci(d) ((d)->bus == &pci_bus_type)
#define dev_is_pf(d) ((dev_is_pci(d) ? to_pci_dev(d)->is_physfn : false))
#define for_each_pci_bridge(dev, bus)				\
	list_for_each_entry(dev, &bus->devices, bus_list)	\
		if (!pci_is_bridge(dev)) {} else
#define for_each_pci_dev(d) while ((d = pci_get_device(PCI_ANY_ID, PCI_ANY_ID, d)) != NULL)
#define module_pci_driver(__pci_driver) \
	module_driver(__pci_driver, pci_register_driver, pci_unregister_driver)
#define no_pci_devices()	(1)
#define pci_WARN(pdev, condition, fmt, arg...) \
	WARN(condition, "%s %s: " fmt, \
	     dev_driver_string(&(pdev)->dev), pci_name(pdev), ##arg)
#define pci_WARN_ONCE(pdev, condition, fmt, arg...) \
	WARN_ONCE(condition, "%s %s: " fmt, \
		  dev_driver_string(&(pdev)->dev), pci_name(pdev), ##arg)
#define pci_alert(pdev, fmt, arg...)	dev_alert(&(pdev)->dev, fmt, ##arg)
#define pci_bus_for_each_resource(bus, res, i)				\
	for (i = 0;							\
	    (res = pci_bus_resource_n(bus, i)) || i < PCI_BRIDGE_RESOURCE_NUM; \
	     i++)
#define pci_crit(pdev, fmt, arg...)	dev_crit(&(pdev)->dev, fmt, ##arg)
#define pci_dbg(pdev, fmt, arg...)	dev_dbg(&(pdev)->dev, fmt, ##arg)
#define pci_dev_put(dev)	do { } while (0)
#define pci_emerg(pdev, fmt, arg...)	dev_emerg(&(pdev)->dev, fmt, ##arg)
#define pci_err(pdev, fmt, arg...)	dev_err(&(pdev)->dev, fmt, ##arg)
#define pci_info(pdev, fmt, arg...)	dev_info(&(pdev)->dev, fmt, ##arg)
#define pci_info_ratelimited(pdev, fmt, arg...) \
	dev_info_ratelimited(&(pdev)->dev, fmt, ##arg)
#define pci_iobar_pfn(pdev, bar, vma) (-EINVAL)
#define pci_notice(pdev, fmt, arg...)	dev_notice(&(pdev)->dev, fmt, ##arg)
#define pci_notice_ratelimited(pdev, fmt, arg...) \
	dev_notice_ratelimited(&(pdev)->dev, fmt, ##arg)
#define pci_printk(level, pdev, fmt, arg...) \
	dev_printk(level, &(pdev)->dev, fmt, ##arg)
#define pci_register_driver(driver)		\
	__pci_register_driver(driver, THIS_MODULE, KBUILD_MODNAME)
#define pci_resource_end(dev, bar)	((dev)->resource[(bar)].end)
#define pci_resource_flags(dev, bar)	((dev)->resource[(bar)].flags)
#define pci_resource_len(dev,bar) \
	((pci_resource_end((dev), (bar)) == 0) ? 0 :	\
							\
	 (pci_resource_end((dev), (bar)) -		\
	  pci_resource_start((dev), (bar)) + 1))
#define pci_resource_start(dev, bar)	((dev)->resource[(bar)].start)
#define pci_root_bus_fwnode(bus)	NULL
#define pci_warn(pdev, fmt, arg...)	dev_warn(&(pdev)->dev, fmt, ##arg)
#define to_pci_bus(n)	container_of(n, struct pci_bus, dev)
#define DEFINE_DMA_UNMAP_ADDR(ADDR_NAME)        dma_addr_t ADDR_NAME
#define DEFINE_DMA_UNMAP_LEN(LEN_NAME)          __u32 LEN_NAME
#define DMA_BIT_MASK(n)	(((n) == 64) ? ~0ULL : ((1ULL<<(n))-1))

#define dma_get_sgtable(d, t, v, h, s) dma_get_sgtable_attrs(d, t, v, h, s, 0)
#define dma_map_page(d, p, o, s, r) dma_map_page_attrs(d, p, o, s, r, 0)
#define dma_map_sg(d, s, n, r) dma_map_sg_attrs(d, s, n, r, 0)
#define dma_map_single(d, a, s, r) dma_map_single_attrs(d, a, s, r, 0)
#define dma_mmap_coherent(d, v, c, h, s) dma_mmap_attrs(d, v, c, h, s, 0)
#define dma_unmap_addr(PTR, ADDR_NAME)           ((PTR)->ADDR_NAME)
#define dma_unmap_addr_set(PTR, ADDR_NAME, VAL)  (((PTR)->ADDR_NAME) = (VAL))
#define dma_unmap_len(PTR, LEN_NAME)             ((PTR)->LEN_NAME)
#define dma_unmap_len_set(PTR, LEN_NAME, VAL)    (((PTR)->LEN_NAME) = (VAL))
#define dma_unmap_page(d, a, s, r) dma_unmap_page_attrs(d, a, s, r, 0)
#define dma_unmap_sg(d, s, n, r) dma_unmap_sg_attrs(d, s, n, r, 0)
#define dma_unmap_single(d, a, s, r) dma_unmap_single_attrs(d, a, s, r, 0)
#define SG_PAGE_LINK_MASK (SG_CHAIN | SG_END)

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
	for_each_sg_dma_page((sgt)->sgl, dma_iter, (sgt)->nents, pgoffset)
#define for_each_sgtable_dma_sg(sgt, sg, i)	\
	for_each_sg((sgt)->sgl, sg, (sgt)->nents, i)
#define for_each_sgtable_page(sgt, piter, pgoffset)	\
	for_each_sg_page((sgt)->sgl, piter, (sgt)->orig_nents, pgoffset)
#define for_each_sgtable_sg(sgt, sg, i)		\
	for_each_sg((sgt)->sgl, sg, (sgt)->orig_nents, i)
#define sg_dma_address(sg)	((sg)->dma_address)
#define sg_dma_len(sg)		((sg)->dma_length)

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
#define PCI_DEVICE_ID_ADDIDATA_APCI7800_3      0x700F
#define PCI_DEVICE_ID_ADDIDATA_APCIe7300       0x7010
#define PCI_DEVICE_ID_ADDIDATA_APCIe7420       0x7011
#define PCI_DEVICE_ID_ADDIDATA_APCIe7500       0x7012
#define PCI_DEVICE_ID_ADDIDATA_APCIe7800       0x7013
#define PCI_DEVICE_ID_AMD_15H_M30H_NB_F3 0x141d
#define PCI_DEVICE_ID_AMD_15H_M30H_NB_F4 0x141e
#define PCI_DEVICE_ID_AMD_15H_M60H_NB_F3 0x1573
#define PCI_DEVICE_ID_AMD_15H_M60H_NB_F4 0x1574
#define PCI_DEVICE_ID_AMD_16H_M30H_NB_F3 0x1583
#define PCI_DEVICE_ID_AMD_16H_M30H_NB_F4 0x1584
#define PCI_DEVICE_ID_AMD_17H_M10H_DF_F3 0x15eb
#define PCI_DEVICE_ID_AMD_17H_M30H_DF_F3 0x1493
#define PCI_DEVICE_ID_AMD_17H_M60H_DF_F3 0x144b
#define PCI_DEVICE_ID_AMD_17H_M70H_DF_F3 0x1443
#define PCI_DEVICE_ID_AMD_19H_M10H_DF_F3 0x14b0
#define PCI_DEVICE_ID_AMD_19H_M40H_DF_F3 0x167c
#define PCI_DEVICE_ID_AMD_19H_M50H_DF_F3 0x166d
#define PCI_DEVICE_ID_AMD_CS5535_IDE    0x208F
#define PCI_DEVICE_ID_AMD_CS5536_AUDIO  0x2093
#define PCI_DEVICE_ID_AMD_CS5536_DEV_IDE    0x2092
#define PCI_DEVICE_ID_AMD_CS5536_EHC    0x2095
#define PCI_DEVICE_ID_AMD_CS5536_FLASH  0x2091
#define PCI_DEVICE_ID_AMD_CS5536_IDE    0x209A
#define PCI_DEVICE_ID_AMD_CS5536_ISA    0x2090
#define PCI_DEVICE_ID_AMD_CS5536_OHC    0x2094
#define PCI_DEVICE_ID_AMD_CS5536_UDC    0x2096
#define PCI_DEVICE_ID_AMD_CS5536_UOC    0x2097
#define PCI_DEVICE_ID_AMD_KERNCZ_SMBUS  0x790b
#define PCI_DEVICE_ID_AMD_LX_AES    0x2082
#define PCI_DEVICE_ID_AMD_LX_VIDEO  0x2081
#define PCI_DEVICE_ID_APPLE_SH_ATA      0x0050
#define PCI_DEVICE_ID_APPLE_SH_SUNGEM   0x0051
#define PCI_DEVICE_ID_APPLICOM_PCI2000IBS_CAN 0x0002
#define PCI_DEVICE_ID_APPLICOM_PCI2000PFB 0x0003
#define PCI_DEVICE_ID_APPLICOM_PCIGENERIC 0x0001
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
#define PCI_DEVICE_ID_INTEL_82454NX     0x84cb
#define PCI_DEVICE_ID_INTEL_82801DB_12  0x24cc
#define PCI_DEVICE_ID_INTEL_ALPINE_RIDGE_2C_BRIDGE  0x1576
#define PCI_DEVICE_ID_INTEL_ALPINE_RIDGE_2C_NHI     0x1575 
#define PCI_DEVICE_ID_INTEL_ALPINE_RIDGE_4C_BRIDGE  0x1578
#define PCI_DEVICE_ID_INTEL_ALPINE_RIDGE_4C_NHI     0x1577
#define PCI_DEVICE_ID_INTEL_CACTUS_RIDGE_2C         0x1548
#define PCI_DEVICE_ID_INTEL_CACTUS_RIDGE_4C         0x1547 
#define PCI_DEVICE_ID_INTEL_EAGLE_RIDGE             0x151a
#define PCI_DEVICE_ID_INTEL_FALCON_RIDGE_2C_BRIDGE  0x156b
#define PCI_DEVICE_ID_INTEL_FALCON_RIDGE_2C_NHI     0x156a 
#define PCI_DEVICE_ID_INTEL_FALCON_RIDGE_4C_BRIDGE  0x156d
#define PCI_DEVICE_ID_INTEL_FALCON_RIDGE_4C_NHI     0x156c
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
#define PCI_DEVICE_ID_INTEL_LIGHT_PEAK              0x151b
#define PCI_DEVICE_ID_INTEL_LIGHT_RIDGE             0x1513 
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
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_TEST     0x2c9c
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_TEST_REV2      0x2d9c
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_NONCORE     0x2c50
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_NONCORE_ALT 0x2c51
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_NONCORE_REV2 0x2c70
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_QPI_LINK0   0x2c90
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_QPI_PHY0    0x2c91
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_SAD         0x2c81
#define PCI_DEVICE_ID_INTEL_PORT_RIDGE              0x1549
#define PCI_DEVICE_ID_INTEL_REDWOOD_RIDGE_2C_BRIDGE 0x1567
#define PCI_DEVICE_ID_INTEL_REDWOOD_RIDGE_2C_NHI    0x1566 
#define PCI_DEVICE_ID_INTEL_REDWOOD_RIDGE_4C_BRIDGE 0x1569
#define PCI_DEVICE_ID_INTEL_REDWOOD_RIDGE_4C_NHI    0x1568
#define PCI_DEVICE_ID_INTEL_X58_HUB_MGMT 0x342e
#define PCI_DEVICE_ID_JMICRON_JMB388_ESD 0x2392
#define PCI_DEVICE_ID_JMICRON_JMB38X_MMC 0x2382
#define PCI_DEVICE_ID_MELLANOX_CONNECTX_EN_5_GEN2 0x6746
#define PCI_DEVICE_ID_MELLANOX_CONNECTX_EN_T_GEN2 0x675a
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
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_320M           0x08A0
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
#define PCI_SUBDEVICE_ID_QEMU            0x1100
#define PCI_SUBDEVICE_ID_SPECIALIX_SPEED4 0xa004
#define PCI_SUBVENDOR_ID_PERLE          0x155f
#define PCI_SUBVENDOR_ID_REDHAT_QUMRANET 0x1af4
#define PCI_VENDOR_ID_ADDIDATA                 0x15B8
#define PCI_VENDOR_ID_BCM_GVC          0x14a4
#define PCI_VENDOR_ID_ELECTRONICDESIGNGMBH 0x12f8
#define PCI_VENDOR_ID_FARSITE           0x1619
#define PCI_VENDOR_ID_HINT             0x3388
#define PCI_VENDOR_ID_REDHAT_QUMRANET    0x1af4
#define PCI_VENDOR_ID_SIEMENS           0x110A
#define PCI_VENDOR_ID_TDI               0x192E

#define PCI_DEVFN(slot, func)	((((slot) & 0x1f) << 3) | ((func) & 0x07))
#define PCI_FUNC(devfn)		((devfn) & 0x07)
#define PCI_SLOT(devfn)		(((devfn) >> 3) & 0x1f)

#define ARCH_LOW_ADDRESS_LIMIT  0xffffffffUL
#define HASHDIST_DEFAULT IS_ENABLED(CONFIG_64BIT)
#define MEMBLOCK_LOW_LIMIT 0

#define __for_each_mem_range(i, type_a, type_b, nid, flags,		\
			   p_start, p_end, p_nid)			\
	for (i = 0, __next_mem_range(&i, nid, flags, type_a, type_b,	\
				     p_start, p_end, p_nid);		\
	     i != (u64)ULLONG_MAX;					\
	     __next_mem_range(&i, nid, flags, type_a, type_b,		\
			      p_start, p_end, p_nid))
#define __for_each_mem_range_rev(i, type_a, type_b, nid, flags,		\
				 p_start, p_end, p_nid)			\
	for (i = (u64)ULLONG_MAX,					\
		     __next_mem_range_rev(&i, nid, flags, type_a, type_b, \
					  p_start, p_end, p_nid);	\
	     i != (u64)ULLONG_MAX;					\
	     __next_mem_range_rev(&i, nid, flags, type_a, type_b,	\
				  p_start, p_end, p_nid))
#define __init_memblock __meminit
#define __initdata_memblock __meminitdata
#define for_each_free_mem_pfn_range_in_zone(i, zone, p_start, p_end)	\
	for (i = 0,							\
	     __next_mem_pfn_range_in_zone(&i, zone, p_start, p_end);	\
	     i != U64_MAX;					\
	     __next_mem_pfn_range_in_zone(&i, zone, p_start, p_end))
#define for_each_free_mem_pfn_range_in_zone_from(i, zone, p_start, p_end) \
	for (; i != U64_MAX;					  \
	     __next_mem_pfn_range_in_zone(&i, zone, p_start, p_end))
#define for_each_free_mem_range(i, nid, flags, p_start, p_end, p_nid)	\
	__for_each_mem_range(i, &memblock.memory, &memblock.reserved,	\
			     nid, flags, p_start, p_end, p_nid)
#define for_each_free_mem_range_reverse(i, nid, flags, p_start, p_end,	\
					p_nid)				\
	__for_each_mem_range_rev(i, &memblock.memory, &memblock.reserved, \
				 nid, flags, p_start, p_end, p_nid)
#define for_each_mem_pfn_range(i, nid, p_start, p_end, p_nid)		\
	for (i = -1, __next_mem_pfn_range(&i, nid, p_start, p_end, p_nid); \
	     i >= 0; __next_mem_pfn_range(&i, nid, p_start, p_end, p_nid))
#define for_each_mem_range(i, p_start, p_end) \
	__for_each_mem_range(i, &memblock.memory, NULL, NUMA_NO_NODE,	\
			     MEMBLOCK_HOTPLUG | MEMBLOCK_DRIVER_MANAGED, \
			     p_start, p_end, NULL)
#define for_each_mem_range_rev(i, p_start, p_end)			\
	__for_each_mem_range_rev(i, &memblock.memory, NULL, NUMA_NO_NODE, \
				 MEMBLOCK_HOTPLUG | MEMBLOCK_DRIVER_MANAGED,\
				 p_start, p_end, NULL)
#define for_each_mem_region(region)					\
	for (region = memblock.memory.regions;				\
	     region < (memblock.memory.regions + memblock.memory.cnt);	\
	     region++)
#define for_each_physmem_range(i, type, p_start, p_end)			\
	for (i = 0, __next_physmem_range(&i, type, p_start, p_end);	\
	     i != (u64)ULLONG_MAX;					\
	     __next_physmem_range(&i, type, p_start, p_end))
#define for_each_reserved_mem_range(i, p_start, p_end)			\
	__for_each_mem_range(i, &memblock.reserved, NULL, NUMA_NO_NODE,	\
			     MEMBLOCK_NONE, p_start, p_end, NULL)
#define for_each_reserved_mem_region(region)				\
	for (region = memblock.reserved.regions;			\
	     region < (memblock.reserved.regions + memblock.reserved.cnt); \
	     region++)
#define hashdist (0)


#define mdelay(n) (\
	(__builtin_constant_p(n) && (n)<=MAX_UDELAY_MS) ? udelay((n)*1000) : \
	({unsigned long __ms=(n); while (__ms--) udelay(1000);}))
#define ndelay(x) ndelay(x)
