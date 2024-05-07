#include<unistd.h>
#include<features.h>


#include<time.h>
#include<stdlib.h>
#include<linux/kernel.h>
#include<stddef.h>
#include<asm/posix_types.h>
#include<stdarg.h>
#include<asm/types.h>

#include<stdio.h>


#include<fcntl.h>



#include<linux/string.h>


#include<linux/stddef.h>
#include<errno.h>

#include<asm/ptrace.h>


#include<sys/types.h>
#include<stdint.h>
#include<string.h>



#include<stdbool.h>
#include<malloc.h>




#include<asm/byteorder.h>
#include<sys/mman.h>

#include<linux/types.h>


#define ALLOC_ALIGN_BUFFER(type, name, size, align)		\
	ALLOC_ALIGN_BUFFER_PAD(type, name, size, align, 1)
#define ALLOC_ALIGN_BUFFER_PAD(type, name, size, align, pad)		\
	char __##name[ROUND(PAD_SIZE((size) * sizeof(type), pad), align)  \
		      + (align - 1)];					\
									\
	type *name = (type *)ALIGN((uintptr_t)__##name, align)
#define ALLOC_CACHE_ALIGN_BUFFER(type, name, size)			\
	ALLOC_ALIGN_BUFFER(type, name, size, ARCH_DMA_MINALIGN)
#define ALLOC_CACHE_ALIGN_BUFFER_PAD(type, name, size, pad)		\
	ALLOC_ALIGN_BUFFER_PAD(type, name, size, ARCH_DMA_MINALIGN, pad)
#define DEFINE_ALIGN_BUFFER(type, name, size, align)			\
	static char __##name[ALIGN(size * sizeof(type), align)]	\
			__aligned(align);				\
									\
	static type *name = (type *)__##name
#define DEFINE_CACHE_ALIGN_BUFFER(type, name, size)			\
	DEFINE_ALIGN_BUFFER(type, name, size, ARCH_DMA_MINALIGN)
#define PAD_COUNT(s, pad) (((s) - 1) / (pad) + 1)
#define PAD_SIZE(s, pad) (PAD_COUNT(s, pad) * pad)

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
#define M_GRAIN   3    
#define M_KEEP    4    
#define M_MMAP_MAX          -4
#define M_MMAP_THRESHOLD    -3
#define M_MXFAST  1    
#define M_NLBLKS  2    
#define M_TOP_PAD           -2
#define M_TRIM_THRESHOLD    -1
#define USE_MEMCPY 1
#define Void_t      void

#      define _SC_PAGE_SIZE _SC_PAGESIZE

#define __STD_C     1
#define malloc malloc_simple
#                define malloc_getpagesize PAGESIZE
#define memalign memalign_simple
#define realloc realloc_simple
#define M_ARENA_MAX         -8
#define M_ARENA_TEST        -7
#define M_CHECK_ACTION      -5
#define M_PERTURB           -6
#define _MALLOC_H 1
# define __MALLOC_DEPRECATED __attribute_deprecated__
# define __MALLOC_HOOK_VOLATILE volatile

#define eprintf(fmt, args...)	fprintf(stderr, fmt, ##args)
#define eputc(c)		fputc(stderr, c)
#define eputs(s)		fputs(stderr, s)
#define ACCESS_ONCE(x) (*__ACCESS_ONCE(x))
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
#define __ACCESS_ONCE(x) ({ \
	 __maybe_unused typeof(x) __var = (__force typeof(x)) 0; \
	(volatile typeof(x) *)&(x); })

#define __PASTE(a,b) ___PASTE(a,b)
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
#define ___PASTE(a,b) a##b
# define __acquire(x)	__context__(x,1)
# define __acquires(x)	__attribute__((context(x,0,1)))
#define __always_inline inline
#define __assume_aligned(a, ...)
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
# define __cond_lock(x,c)	((c) ? ({ __acquire(x); 1; }) : 0)

#define __deprecated_for_modules __deprecated
# define __force
# define __iomem
# define __kernel
# define __kprobes

# define __must_hold(x)	__attribute__((context(x,1,1)))
# define __native_word(t) (sizeof(t) == sizeof(char) || sizeof(t) == sizeof(short) || sizeof(t) == sizeof(int) || sizeof(t) == sizeof(long))
# define __nocast
# define __percpu
# define __pmem
# define __rcu
# define __release(x)	__context__(x,-1)
# define __releases(x)	__attribute__((context(x,1,0)))
# define __safe
# define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
# define __section(S) __attribute__ ((__section__(#S)))
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
# define __user

#define _compiletime_assert(condition, msg, prefix, suffix) \
	__compiletime_assert(condition, msg, prefix, suffix)
# define barrier() __memory_barrier()
# define barrier_data(ptr) barrier()
#define compiletime_assert(condition, msg) \
	_compiletime_assert(condition, msg, __compiletime_assert_, "__LINE__")
#define compiletime_assert_atomic_type(t)				\
	compiletime_assert(__native_word(t),				\
		"Need native word sized stores/loads for atomicity.")
#define if(cond, ...) __trace_if( (cond , ## __VA_ARGS__) )
#  define likely(x)	(__builtin_constant_p(x) ? !!(x) : __branch_check__(x, 1))
#define likely_notrace(x)	__builtin_expect(!!(x), 1)
#define lockless_dereference(p) \
({ \
	typeof(p) _________p1 = READ_ONCE(p); \
	smp_read_barrier_depends();  \
	(_________p1); \
})

#define noinline_for_stack noinline
#define notrace __attribute__((hotpatch(0,0)))
#define smp_cond_acquire(cond)	do {		\
	while (!(cond))				\
		cpu_relax();			\
	smp_rmb(); 	\
} while (0)
#  define unlikely(x)	(__builtin_constant_p(x) ? !!(x) : __branch_check__(x, 0))
#define unlikely_notrace(x)	__builtin_expect(!!(x), 0)
# define unreachable() do { } while (1)
#define DECLARE_BITMAP(name, bits) \
	unsigned long name[BITS_TO_LONGS(bits)]








#define __bitwise __bitwise__
#define __bitwise__ __attribute__((bitwise))
#define aligned_be64 __be64 __aligned(8)
#define aligned_le64 __le64 __aligned(8)
#define aligned_u64 __u64 __aligned(8)

#define NULL 0

#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#define uninitialized_var(x) x = *(&(x))
#define GCC_VERSION ("__GNUC__" * 10000		\
		     + "__GNUC_MINOR__" * 100	\
		     + "__GNUC_PATCHLEVEL__")
#define KASAN_ABI_VERSION 4



#define __alias(symbol)	__attribute__((alias(#symbol)))
#define __aligned(x)		__attribute__((aligned(x)))
#define __compiler_offsetof(a, b)					\
	__builtin_offsetof(a, b)
#define __must_be_array(a)	0
#define __no_sanitize_address __attribute__((no_sanitize_address))
#define __printf(a, b)		__attribute__((format(printf, a, b)))
#define __scanf(a, b)		__attribute__((format(scanf, a, b)))
#define asm_volatile_goto(x...)	do { asm goto(x); asm (""); } while (0)
#define IDE_BUS(dev)	(dev / (CONFIG_SYS_IDE_MAXDEVICE / CONFIG_SYS_IDE_MAXBUS))


#define BLOCK_CNT(size, blk_desc) (PAD_COUNT(size, blk_desc->blksz))
#define LBAF "%" LBAFlength "x"
#define LBAFU "%" LBAFlength "u"
#define LBAFlength "ll"
#define PAD_TO_BLOCKSIZE(size, blk_desc) \
	(PAD_SIZE(size, blk_desc->blksz))
#define U_BOOT_LEGACY_BLK(__name)					\
	ll_entry_declare(struct blk_driver, __name, blk_driver)
#define blk_get_ops(dev)	((struct blk_ops *)(dev)->driver->ops)

#define __set_errno(val) do { errno = val; } while (0)
#define ERESTART_RESTARTBLOCK 516 

#define EFIAPI __attribute__((ms_abi))
#define EFI_ERROR_MASK (1UL << (EFI_BITS_PER_LONG - 1))
#define EFI_GUID(a, b, c, d0, d1, d2, d3, d4, d5, d6, d7) \
	{{ (a) & 0xff, ((a) >> 8) & 0xff, ((a) >> 16) & 0xff, \
		((a) >> 24) & 0xff, \
		(b) & 0xff, ((b) >> 8) & 0xff, \
		(c) & 0xff, ((c) >> 8) & 0xff, \
		(d0), (d1), (d2), (d3), (d4), (d5), (d6), (d7) } }
#define EFI_MEMORY_DESCRIPTOR_VERSION 1
#define EFI_MEMORY_MORE_RELIABLE \
				((u64)0x0000000000010000ULL)	
#define EFI_TIME_ADJUST_DAYLIGHT 0x1
#define EFI_TIME_IN_DAYLIGHT     0x2
#define EFI_UNSPECIFIED_TIMEZONE 0x07ff
#define EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS 0x0000000000000010
#define EFI_VARIABLE_BOOTSERVICE_ACCESS 0x0000000000000002
#define EFI_VARIABLE_HARDWARE_ERROR_RECORD 0x0000000000000008
#define EFI_VARIABLE_NON_VOLATILE       0x0000000000000001
#define EFI_VARIABLE_RUNTIME_ACCESS     0x0000000000000004
#define EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS 0x0000000000000020

#define efi_va_arg __builtin_va_arg
#define efi_va_end __builtin_ms_va_end
#define efi_va_list __builtin_ms_va_list
#define efi_va_start __builtin_ms_va_start



#define END(name) \
	.size name, .-name
#define ENDPROC(name) \
	.type name STT_FUNC ASM_NL \
	END(name)
#define ENTRY(name) \
	.globl SYMBOL_NAME(name) ASM_NL \
	LENTRY(name)
#define LENTRY(name) \
	ALIGN ASM_NL \
	SYMBOL_NAME_LABEL(name)
#define SYMBOL_NAME(X)		X
#define SYMBOL_NAME_LABEL(X)	X##:
#define SYMBOL_NAME_STR(X)	#X
#define WEAK(name) \
	.weak SYMBOL_NAME(name) ASM_NL \
	LENTRY(name)

#define __ALIGN .align		4
#define asmlinkage CPP_ASMLINKAGE

#define U_BOOT_CMD(_name, _maxargs, _rep, _cmd, _usage, _help)		\
	U_BOOT_CMD_COMPLETE(_name, _maxargs, _rep, _cmd, _usage, _help, NULL)
#define U_BOOT_CMDREP_COMPLETE(_name, _maxargs, _cmd_rep, _usage,	\
			       _help, _comp)				\
	ll_entry_declare(cmd_tbl_t, _name, cmd) =			\
		U_BOOT_CMDREP_MKENT_COMPLETE(_name, _maxargs, _cmd_rep,	\
					     _usage, _help, _comp)
#define U_BOOT_CMDREP_MKENT_COMPLETE(_name, _maxargs, _cmd_rep,		\
				     _usage, _help, _comp)		\
		{ #_name, _maxargs, _cmd_rep, cmd_discard_repeatable,	\
		  _usage, _CMD_HELP(_help) _CMD_COMPLETE(_comp) }
#define U_BOOT_CMD_COMPLETE(_name, _maxargs, _rep, _cmd, _usage, _help, _comp) \
	ll_entry_declare(cmd_tbl_t, _name, cmd) =			\
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
	static cmd_tbl_t _cmdname##_subcmds[] = { __VA_ARGS__ };	\
	U_BOOT_SUBCMDS_RELOC(_cmdname)					\
	U_BOOT_SUBCMDS_DO_CMD(_cmdname)					\
	U_BOOT_SUBCMDS_COMPLETE(_cmdname)
#define U_BOOT_SUBCMDS_COMPLETE(_cmdname)				\
	static int complete_##_cmdname(int argc, char * const argv[],	\
				       char last_char, int maxv,	\
				       char *cmdv[])			\
	{								\
		return complete_subcmdv(_cmdname##_subcmds,		\
					ARRAY_SIZE(_cmdname##_subcmds),	\
					argc - 1, argv + 1, last_char,	\
					maxv, cmdv);			\
	}
#define U_BOOT_SUBCMDS_DO_CMD(_cmdname)					\
	static int do_##_cmdname(cmd_tbl_t *cmdtp, int flag, int argc,	\
				 char * const argv[], int *repeatable)	\
	{								\
		cmd_tbl_t *subcmd;					\
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
#define U_BOOT_SUBCMD_START(name)	static cmd_tbl_t name[] = {};
# define _CMD_COMPLETE(x) x,
# define _CMD_HELP(x) x,
#define _CMD_REMOVE(_name, _cmd)					\
	int __remove_ ## _name(void)					\
	{								\
		if (0)							\
			_cmd(NULL, 0, 0, NULL);				\
		return 0;						\
	}


#define ll_end(_type)							\
({									\
	static char end[0] __aligned(4) __attribute__((unused,		\
		section(".u_boot_list_3")));				\
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
			__attribute__((unused,				\
			section(".u_boot_list_2_"#_list"_2_"#_name)))
#define ll_entry_declare_list(_type, _name, _list)			\
	_type _u_boot_list_2_##_list##_2_##_name[] __aligned(4)		\
			__attribute__((unused,				\
			section(".u_boot_list_2_"#_list"_2_"#_name)))
#define ll_entry_end(_type, _list)					\
({									\
	static char end[0] __aligned(4) __attribute__((unused,		\
		section(".u_boot_list_2_"#_list"_3")));			\
	(_type *)&end;							\
})
#define ll_entry_get(_type, _name, _list)				\
	({								\
		extern _type _u_boot_list_2_##_list##_2_##_name;	\
		_type *_ll_result =					\
			&_u_boot_list_2_##_list##_2_##_name;		\
		_ll_result;						\
	})
#define ll_entry_start(_type, _list)					\
({									\
	static char start[0] __aligned(4) __attribute__((unused,	\
		section(".u_boot_list_2_"#_list"_1")));			\
	(_type *)&start;						\
})
#define ll_start(_type)							\
({									\
	static char start[0] __aligned(4) __attribute__((unused,	\
		section(".u_boot_list_1")));				\
	(_type *)&start;						\
})
#define llsym(_type, _name, _list) \
		((_type *)&_u_boot_list_2_##_list##_2_##_name)


# define CONFIG_SYS_DEF_EEPROM_ADDR CONFIG_SYS_I2C_EEPROM_ADDR

#define RAND_MAX -1U
#define ROUND(a,b)		(((a) + (b) - 1) & ~((b) - 1))
#define check_member(structure, member, offset) _Static_assert( \
	offsetof(struct structure, member) == offset, \
	"`struct " #structure "` offset for `" #member "` is not " #offset)

#define eeprom_read(dev_addr, offset, buffer, cnt) ((void)-ENOSYS)
#define eeprom_write(dev_addr, offset, buffer, cnt) ((void)-ENOSYS)
#define for_each_cpu(iter, cpu, num_cpus, mask) \
	for (iter = 0, cpu = cpumask_next(-1, mask); \
		iter < num_cpus; \
		iter++, cpu = cpumask_next(cpu, mask)) \

#define ll_boot_init()	false
#define BOOTSTAGE_MARKER()	\
		bootstage_mark_code("__FILE__", __func__, "__LINE__")


#define show_boot_progress(val) do {} while (0)
#   define ARPOP_REQUEST    1		
#define ARP_HLEN 6
#define ARP_HLEN_ASCII (ARP_HLEN * 2) + (ARP_HLEN - 1)
#define DEBUG_DEV_PKT 0		
#define DEBUG_INT_STATE 0	
#define DEBUG_LL_STATE 0	
#define DEBUG_NET_PKT 0		
#define ETH_NAME_LEN 20
#   define RARPOP_REQUEST   3		

#define eth_get_ops(dev) ((struct eth_ops *)(dev)->driver->ops)
#define ETH_P_AF_IUCV   0xFBFB	
#define ETH_P_IEEE802154 0x00F6	




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


#define LOG_CATEGORY LOGC_NONE
#define LOG_DRIVER(_name) \
	ll_entry_declare(struct log_driver, _name, log_driver)
#define _LOG_MAX_LEVEL LOGL_INFO

#define assert(x) \
	({ if (!(x) && _DEBUG) \
		__assert_fail(#x, "__FILE__", "__LINE__", __func__); })
#define debug(fmt, args...)			\
	debug_cond(_DEBUG, fmt, ##args)
#define debug_cond(cond, fmt, args...)			\
	do {						\
		if (1)					\
			log(LOG_CATEGORY, LOGL_DEBUG, fmt, ##args); \
	} while (0)
#define log(_cat, _level, _fmt, _args...) ({ \
	int _l = _level; \
	if (CONFIG_IS_ENABLED(LOG) && (_l <= _LOG_MAX_LEVEL || _LOG_DEBUG)) \
		_log((enum log_category_t)(_cat), _l, "__FILE__", "__LINE__", \
		      __func__, \
		      pr_fmt(_fmt), ##_args); \
	})
#define log_content(_fmt...)	log(LOG_CATEGORY, LOGL_DEBUG_CONTENT, ##_fmt)



#define log_io(_fmt...)		log(LOG_CATEGORY, LOGL_DEBUG_IO, ##_fmt)
#define log_msg_ret(_msg, _ret) ({ \
	int __ret = (_ret); \
	if (__ret < 0) \
		log(LOG_CATEGORY, LOGL_ERR, "%s: returning err=%d\n", _msg, \
		    __ret); \
	__ret; \
	})

#define log_ret(_ret) ({ \
	int __ret = (_ret); \
	if (__ret < 0) \
		log(LOG_CATEGORY, LOGL_ERR, "returning err=%d\n", __ret); \
	__ret; \
	})

#define pr_fmt(fmt) fmt
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
#define list_for_each(pos, head) \
	for (pos = (head)->next; prefetch(pos->next), pos != (head); \
		pos = pos->next)
#define list_for_each_entry(pos, head, member)				\
	for (pos = list_entry((head)->next, typeof(*pos), member);	\
	     prefetch(pos->member.next), &pos->member != (head);	\
	     pos = list_entry(pos->member.next, typeof(*pos), member))
#define list_for_each_entry_continue(pos, head, member) 		\
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
#define list_for_each_entry_safe_continue(pos, n, head, member) 		\
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


#define CHUNKSZ (64 * 1024)
#define CHUNKSZ_CRC32 (64 * 1024)
#define CHUNKSZ_MD5 (64 * 1024)
#define CHUNKSZ_SHA1 (64 * 1024)
#define CONFIG_FIT_ENABLE_RSASSA_PSS_SUPPORT 1



#define IMAGE_ENABLE_TIMESTAMP 1
#define U_BOOT_FIT_LOADABLE_HANDLER(_type, _handler) \
	ll_entry_declare(struct fit_loadable_tbl, _function, fit_loadable) = { \
		.type = _type, \
		.handler = _handler, \
	}

#define cpu_to_uimage(x)		cpu_to_be32(x)
#define fit_unsupported(msg)	printf("! %s:%d " \
				"FIT images not supported for '%s'\n", \
				"__FILE__", "__LINE__", (msg))
#define fit_unsupported_reset(msg)	printf("! %s:%d " \
				"FIT images not supported for '%s' " \
				"- must reset board to recover!\n", \
				"__FILE__", "__LINE__", (msg))
# define gd_fdt_blob()		image_get_host_blob()
#define image_get_hdr_b(f) \
	static inline uint8_t image_get_##f(const image_header_t *hdr) \
	{ \
		return hdr->ih_##f; \
	}
#define image_get_hdr_l(f) \
	static inline uint32_t image_get_##f(const image_header_t *hdr) \
	{ \
		return uimage_to_cpu(hdr->ih_##f); \
	}
#define image_set_hdr_b(f) \
	static inline void image_set_##f(image_header_t *hdr, uint8_t val) \
	{ \
		hdr->ih_##f = val; \
	}
#define image_set_hdr_l(f) \
	static inline void image_set_##f(image_header_t *hdr, uint32_t val) \
	{ \
		hdr->ih_##f = cpu_to_uimage(val); \
	}
#define uimage_to_cpu(x)		be32_to_cpu(x)

#define CAP_START_POS 0x40
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
#define  PCI_CLASS_CODE_MULTIMEDIA 0x04
#define  PCI_CLASS_CODE_NETWORK 0x02
#define  PCI_CLASS_CODE_PERIPHERAL 0x08
#define  PCI_CLASS_CODE_PROCESSOR 0x0B
#define  PCI_CLASS_CODE_SATELLITE 0x0F
#define  PCI_CLASS_CODE_STORAGE 0x01
#define  PCI_CLASS_CODE_WIRELESS 0x0D
#define  PCI_CLASS_SUB_CODE_CRYPTO_ENTERTAINMENT 0x10
#define  PCI_COMMAND_INVALIDATE 0x10	
#define  PCI_COMMAND_VGA_PALETTE 0x20	
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
#define  PCI_EXP_DEVCAP_FLR     0x10000000 
#define  PCI_EXP_DEVCTL_BCR_FLR 0x8000  
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
#define PCI_VDEVICE(vend, dev) \
	.vendor = PCI_VENDOR_ID_##vend, .device = (dev), \
	.subvendor = PCI_ANY_ID, .subdevice = PCI_ANY_ID, 0, 0
#define PCI_VENDEV(v, d)	(((v) << 16) | (d))
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

#define dm_pci_bus_to_virt(dev, addr, flags, len, map_flags) \
	map_physmem(dm_pci_bus_to_phys(dev, (addr), (flags)), \
		    (len), (map_flags))
#define dm_pci_io_to_phys(dev, addr) \
	dm_pci_bus_to_phys((dev), (addr), PCI_REGION_IO)
#define dm_pci_io_to_virt(dev, addr, len, map_flags) \
	dm_pci_bus_to_virt((dev), (addr), PCI_REGION_IO, (len), (map_flags))
#define dm_pci_mem_to_phys(dev, addr) \
	dm_pci_bus_to_phys((dev), (addr), PCI_REGION_MEM)
#define dm_pci_mem_to_virt(dev, addr, len, map_flags) \
	dm_pci_bus_to_virt((dev), (addr), PCI_REGION_MEM, (len), (map_flags))
#define dm_pci_phys_to_io(dev, addr) \
	dm_pci_phys_to_bus((dev), (addr), PCI_REGION_IO)
#define dm_pci_phys_to_mem(dev, addr) \
	dm_pci_phys_to_bus((dev), (addr), PCI_REGION_MEM)
#define dm_pci_virt_to_bus(dev, addr, flags) \
	dm_pci_phys_to_bus(dev, (virt_to_phys(addr)), (flags))
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
#define strtoul(cp, endp, base)	simple_strtoul(cp, endp, base)
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


#define MAX_LMB_REGIONS 8

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
# define cpu_to_le64(x)		uswap_64(x)
# define le16_to_cpu(x)		uswap_16(x)
# define le32_to_cpu(x)		uswap_32(x)
# define le64_to_cpu(x)		uswap_64(x)
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
#define AMD_ID_DL640G_2 0x22022202	
#define AMD_ID_DL640G_3 0x22012201	
#define AMD_ID_GL064MT_2 0x22102210	
#define AMD_ID_GL064MT_3 0x22012201	
#define AMD_ID_GL064M_2 0x22132213	
#define AMD_ID_GL064M_3 0x22012201	
#define AMD_ID_LV128U_2 0x22122212	
#define AMD_ID_LV128U_3 0x22002200	
#define AMD_ID_LV256U_2 0x22122212	
#define AMD_ID_LV256U_3 0x22012201	
#define AMD_ID_LV320B_2 0x221A221A	
#define AMD_ID_LV320B_3 0x22002200	
#define AMD_ID_LV640MB_2 0x22102210	
#define AMD_ID_LV640MB_3 0x22002200	
#define AMD_ID_LV640MT_2 0x22102210	
#define AMD_ID_LV640MT_3 0x22012201	
#define AMD_ID_LV640U_2 0x220C220C	
#define AMD_ID_LV640U_3 0x22012201	
#define FLASH_28F128J3A 0x00C4		
#define FLASH_28F160C3B 0x009D		
#define FLASH_28F160C3T 0x009C		
#define FLASH_28F160F3B 0x0093		
#define FLASH_28F256J3A 0x00C6		
#define FLASH_28F256L18T 0x00B0		
#define FLASH_28F320C3B 0x009F		
#define FLASH_28F320C3T 0x009E		
#define FLASH_28F320J3A 0x00C0		
#define FLASH_28F640C3B 0x00A1		
#define FLASH_28F640C3T 0x00A0		
#define FLASH_28F640J3A 0x00C2		
#define FLASH_28F800C3B 0x009B		
#define FLASH_28F800C3T 0x009A		
#define FLASH_AM29F800B 0x0084		
#define FLASH_AMDL640MB 0x0019		
#define FLASH_AMDL640MT 0x001A		
#define FLASH_AMDLV033C 0x0018
#define FLASH_AMDLV065D 0x001A
#define FLASH_INTEL160B 0x0077		
#define FLASH_INTEL160T 0x0076		
#define FLASH_INTEL320B 0x0079		
#define FLASH_INTEL320T 0x0078		
#define FLASH_INTEL640B 0x007B		
#define FLASH_INTEL640T 0x007A		
#define FLASH_INTEL800B 0x0075		
#define FLASH_INTEL800T 0x0074		
#define FLASH_LH28F016SCT 0x0092	
#define FLASH_MAN_EXCEL 0x00060000	
#define FLASH_MAN_INTEL 0x00300000
#define FLASH_MAN_SHARP 0x00500000
#define FLASH_MT28S4M16LC 0x00E1	
#define FLASH_PSD4256GV 0x00E9		
#define FLASH_S29GL064M 0x00F0		
#define FLASH_S29GL128N 0x00F1		
#define FLASH_STMW320DB 0x0053		
#define FLASH_STMW320DT 0x0052		
#define FUJI_ID_29F800BA  0x22582258	
#define FUJI_ID_29F800TA  0x22D622D6	
#define FUJI_ID_29LV650UE 0x22d722d7	
#define INTEL_ID_28F016S    0x66a066a0	
#define INTEL_ID_28F128J3   0x89188918	
#define INTEL_ID_28F128J3A  0x00180018	
#define INTEL_ID_28F128K3   0x88028802	
#define INTEL_ID_28F128P30B 0x881B881B	
#define INTEL_ID_28F128P30T 0x88188818	
#define INTEL_ID_28F160B3B  0x88918891	
#define INTEL_ID_28F160B3T  0x88908890	
#define INTEL_ID_28F160C3B  0x88C388C3	
#define INTEL_ID_28F160C3T  0x88C288C2	
#define INTEL_ID_28F160F3B  0x88F488F4	
#define INTEL_ID_28F160S3   0x00D000D0	
#define INTEL_ID_28F256J3A  0x001D001D	
#define INTEL_ID_28F256K3   0x88038803	
#define INTEL_ID_28F256L18T 0x880D880D	
#define INTEL_ID_28F256P30B 0x881C881C	
#define INTEL_ID_28F256P30T 0x88198819	
#define INTEL_ID_28F320B3B  0x88978897	
#define INTEL_ID_28F320B3T  0x88968896	
#define INTEL_ID_28F320C3B  0x88C588C5	
#define INTEL_ID_28F320C3T  0x88C488C4	
#define INTEL_ID_28F320J3A  0x00160016	
#define INTEL_ID_28F320J5   0x00140014	
#define INTEL_ID_28F320S3   0x00D400D4	
#define INTEL_ID_28F640B3B  0x88998899	
#define INTEL_ID_28F640B3T  0x88988898	
#define INTEL_ID_28F640C3B  0x88CD88CD	
#define INTEL_ID_28F640C3T  0x88CC88CC	
#define INTEL_ID_28F640J3A  0x00170017	
#define INTEL_ID_28F640J5   0x00150015	
#define INTEL_ID_28F64K3    0x88018801	
#define INTEL_ID_28F64P30B  0x881A881A	
#define INTEL_ID_28F64P30T  0x88178817	
#define INTEL_ID_28F800B3B  0x88938893	
#define INTEL_ID_28F800B3T  0x88928892	
#define INTEL_ID_28F800C3B  0x88C188C1	
#define INTEL_ID_28F800C3T  0x88C088C0	
#define SHARP_ID_28F008SC   0xA6A6A6A6	
#define SHARP_ID_28F016SCL  0xAAAAAAAA	
#define SHARP_ID_28F016SCZ  0xA0A0A0A0	
#define STM_ID_29W320DB 0x22CB22CB	
#define STM_ID_29W320DT 0x22CA22CA	
#define STM_ID_29W320EB 0x22572257	
#define STM_ID_29W320ET 0x22562256	
#define STM_ID_M29W040B 0xE3		

#define LOG2(x) (((x & 0xaaaaaaaa) ? 1 : 0) + ((x & 0xcccccccc) ? 2 : 0) + \
		 ((x & 0xf0f0f0f0) ? 4 : 0) + ((x & 0xff00ff00) ? 8 : 0) + \
		 ((x & 0xffff0000) ? 16 : 0))
#define LOG2_INVALID(type) ((type)((sizeof(type)<<3)-1))
#define MAX_SEARCH_PARTITIONS 64
#define PART_NAME_LEN 32
#define PART_TYPE_LEN 32
#define U_BOOT_PART_TYPE(__name)					\
	ll_entry_declare(struct part_driver, __name, part_driver)

#  define part_get_info_ptr(x)	x
# define part_print_ptr(x)	NULL
#define EFI_PMBR_OSTYPE_EFI 0xEF
#define EFI_PMBR_OSTYPE_EFI_GPT 0xEE
#define GPT_HEADER_REVISION_V1 0x00010000
#define GPT_HEADER_SIGNATURE_UBOOT 0x5452415020494645ULL
#define GPT_PRIMARY_PARTITION_TABLE_LBA 1ULL
#define LEGACY_MBR_PARTITION_GUID \
	EFI_GUID( 0x024DEE41, 0x33E7, 0x11d3, \
		0x9D, 0x69, 0x00, 0x08, 0xC7, 0x81, 0xF3, 0x9F)
#define MSDOS_MBR_BOOT_CODE_SIZE 440
#define MSDOS_MBR_SIGNATURE 0xAA55
#define PARTITION_BASIC_DATA_GUID \
	EFI_GUID( 0xEBD0A0A2, 0xB9E5, 0x4433, \
		0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7)
#define PARTITION_LINUX_FILE_SYSTEM_DATA_GUID \
	EFI_GUID(0x0FC63DAF, 0x8483, 0x4772, \
		0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4)
#define PARTITION_LINUX_LVM_GUID \
	EFI_GUID( 0xe6d6d379, 0xf507, 0x44c2, \
		0xa2, 0x3c, 0x23, 0x8f, 0x2a, 0x3d, 0xf9, 0x28)
#define PARTITION_LINUX_RAID_GUID \
	EFI_GUID( 0xa19d880f, 0x05fc, 0x4d3b, \
		0xa0, 0x06, 0x74, 0x3f, 0x0f, 0x84, 0x91, 0x1e)
#define PARTITION_LINUX_SWAP_GUID \
	EFI_GUID( 0x0657fd6d, 0xa4ab, 0x43c4, \
		0x84, 0xe5, 0x09, 0x33, 0xc8, 0x4b, 0x4f, 0x4f)
#define PARTITION_MSFT_RESERVED_GUID \
	EFI_GUID( 0xE3C9E316, 0x0B5C, 0x4DB8, \
		0x81, 0x7D, 0xF9, 0x2D, 0xF0, 0x02, 0x15, 0xAE)
#define PARTITION_SYSTEM_GUID \
	EFI_GUID( 0xC12A7328, 0xF81F, 0x11d2, \
		0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B)

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

#define __stringify(x...)	__stringify_1(x)
#define __stringify_1(x...)	#x










#define __printk(level, fmt, ...)					\
({									\
	level < CONFIG_LOGLEVEL ? printk(fmt, ##__VA_ARGS__) : 0;	\
})
#define no_printk(fmt, ...)				\
({							\
	if (0)						\
		printk(fmt, ##__VA_ARGS__);		\
	0;						\
})
#define pr_alert(fmt, ...) \
	__printk(1, pr_fmt(fmt), ##__VA_ARGS__)
#define pr_cont(fmt, ...) \
	printk(fmt, ##__VA_ARGS__)
#define pr_crit(fmt, ...) \
	__printk(2, pr_fmt(fmt), ##__VA_ARGS__)
#define pr_debug(fmt, ...) \
	__printk(7, pr_fmt(fmt), ##__VA_ARGS__)
#define pr_devel(fmt, ...) \
	__printk(7, pr_fmt(fmt), ##__VA_ARGS__)
#define pr_emerg(fmt, ...) \
	__printk(0, pr_fmt(fmt), ##__VA_ARGS__)
#define pr_err(fmt, ...) \
	__printk(3, pr_fmt(fmt), ##__VA_ARGS__)
#define pr_info(fmt, ...) \
	__printk(6, pr_fmt(fmt), ##__VA_ARGS__)
#define pr_notice(fmt, ...) \
	__printk(5, pr_fmt(fmt), ##__VA_ARGS__)
#define pr_warn pr_warning
#define pr_warning(fmt, ...) \
	__printk(4, pr_fmt(fmt), ##__VA_ARGS__)
#define printk(fmt, ...) \
	printf(fmt, ##__VA_ARGS__)
#define printk_once(fmt, ...) \
	printk(fmt, ##__VA_ARGS__)

#define BUG() do { \
	printk("BUG at %s:%d/%s()!\n", "__FILE__", "__LINE__", __func__); \
	panic("BUG!"); \
} while (0)
#define BUG_ON(condition) do { if (unlikely(condition)) BUG(); } while (0)
#define WARN(condition, format...) ({                   \
	int __ret_warn_on = !!(condition);              \
	if (unlikely(__ret_warn_on))                    \
		printf(format);                  \
	unlikely(__ret_warn_on);                    \
})
#define WARN_ON(condition) ({						\
	int __ret_warn_on = !!(condition);				\
	if (unlikely(__ret_warn_on))					\
		printk("WARNING at %s:%d/%s()!\n", "__FILE__", "__LINE__", __func__); \
	unlikely(__ret_warn_on);					\
})
#define WARN_ONCE(condition, format...) ({          \
	static bool __warned;     \
	int __ret_warn_once = !!(condition);            \
								\
	if (unlikely(__ret_warn_once && !__warned)) {       \
		__warned = true;                \
		WARN(1, format);                \
	}                           \
	unlikely(__ret_warn_once);              \
})
#define WARN_ON_ONCE(condition)	({				\
	static bool __warned;					\
	int __ret_warn_once = !!(condition);			\
								\
	if (unlikely(__ret_warn_once && !__warned)) {		\
		__warned = true;				\
		WARN_ON(1);					\
	}							\
	unlikely(__ret_warn_once);				\
})

#define BUILD_BUG() (0)
#define BUILD_BUG_ON(condition) (0)
#define BUILD_BUG_ON_INVALID(e) (0)
#define BUILD_BUG_ON_MSG(cond, msg) (0)
#define BUILD_BUG_ON_NOT_POWER_OF_2(n)			\
	BUILD_BUG_ON((n) == 0 || (((n) & ((n) - 1)) != 0))
#define BUILD_BUG_ON_NULL(e) ((void *)0)
#define BUILD_BUG_ON_ZERO(e) (sizeof(struct { int:(-!!(e)); }))

#define __BUILD_BUG_ON_NOT_POWER_OF_2(n)	\
	BUILD_BUG_ON(((n) & ((n) - 1)) != 0)
