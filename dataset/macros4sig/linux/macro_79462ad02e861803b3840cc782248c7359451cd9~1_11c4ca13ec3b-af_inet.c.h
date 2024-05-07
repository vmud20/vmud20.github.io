#include<linux/resource.h>


#include<linux/types.h>

#include<linux/ip.h>
#include<linux/random.h>



#include<linux/stat.h>


#include<linux/lwtunnel.h>

#include<limits.h>
#include<linux/net.h>
#include<linux/netdevice.h>
#include<linux/fiemap.h>
#include<linux/rtnetlink.h>

#include<linux/if_ether.h>
#include<linux/capability.h>



#include<string.h>

#include<linux/net_tstamp.h>

#include<linux/const.h>
#include<asm/stat.h>
#include<linux/cgroupstats.h>


#include<asm/errno.h>








#include<unistd.h>


#include<linux/if_arp.h>




#include<linux/ipv6.h>


#include<linux/if.h>

#include<linux/time.h>

#include<linux/elf-em.h>
#include<linux/uio.h>

#include<linux/sockios.h>



#include<linux/sysctl.h>



#include<linux/dqblk_xfs.h>
#include<asm/fcntl.h>


#include<linux/if_link.h>

#include<linux/pfkeyv2.h>




#include<linux/if_addr.h>


#include<linux/unistd.h>


#include<linux/limits.h>
#include<net/route.h>






#include<asm/byteorder.h>









#include<linux/poll.h>


#include<linux/snmp.h>
#include<linux/pkt_sched.h>
#include<linux/ioctl.h>



#include<linux/fcntl.h>



#include<linux/timex.h>

#include<linux/in6.h>



#include<linux/in.h>
#include<linux/ipsec.h>


#include<asm/sembuf.h>

#include<linux/in_route.h>



#include<linux/dcbnl.h>


#include<asm/poll.h>
#include<linux/sem.h>





#include<asm/siginfo.h>











#include<asm/ptrace.h>
#include<linux/ethtool.h>
#include<asm/types.h>
#include<linux/sched.h>





#include<stdarg.h>

#include<linux/bpf_common.h>


#include<linux/if_packet.h>

#include<linux/socket.h>



#include<linux/string.h>
#include<linux/kernel.h>
#include<linux/ipc.h>













#include<linux/icmp.h>
#include<linux/module.h>
#include<linux/gen_stats.h>

#include<asm/ipcbuf.h>



#include<linux/icmpv6.h>



#include<linux/wait.h>

#include<asm/resource.h>


#include<linux/pkt_cls.h>
#include<linux/param.h>



#include<linux/fib_rules.h>




#include<asm/signal.h>




#include<linux/neighbour.h>


#include<linux/xfrm.h>
#include<asm/auxvec.h>

#include<linux/aio_abi.h>




#include<linux/fs.h>
#include<asm/param.h>







#include<linux/netlink.h>


#include<linux/posix_types.h>

#include<asm/shmbuf.h>

#include<linux/route.h>



#include<linux/libc-compat.h>
#include<linux/irqnr.h>
#include<linux/stddef.h>
#include<asm/socket.h>



#include<linux/sysinfo.h>


#include<linux/tcp.h>


#include<linux/errno.h>

#include<linux/magic.h>



#define MFC_HASH(a,b)	((((__force u32)(__be32)a)^(((__force u32)(__be32)b)>>2))&(MFC_LINES-1))
#define VIFF_STATIC 0x8000

#define MFC_ASSERT_THRESH (3*HZ)		
#define VIFM_CLR(n,m)	((m)&=~(1<<(n)))
#define VIFM_CLRALL(m)	((m)=0)
#define VIFM_COPY(mfrom,mto)	((mto)=(mfrom))
#define VIFM_ISSET(n,m)	((m)&(1<<(n)))
#define VIFM_SAME(m1,m2)	((m1)==(m2))
#define VIFM_SET(n,m)	((m)|=(1<<(n)))

#define DECLARE_BITMAP(name,bits) \
	unsigned long name[BITS_TO_LONGS(bits)]









#define aligned_be64 __be64 __attribute__((aligned(8)))
#define aligned_le64 __le64 __attribute__((aligned(8)))
#define aligned_u64 __u64 __attribute__((aligned(8)))
#define pgoff_t unsigned long
#define rcu_head callback_head

#define __aligned_be64 __be64 __attribute__((aligned(8)))
#define __aligned_le64 __le64 __attribute__((aligned(8)))
#define __aligned_u64 __u64 __attribute__((aligned(8)))
#define __bitwise __bitwise__
#define __bitwise__ __attribute__((bitwise))
#define FLAGS_TS_OR_DROPS ((1UL << SOCK_RXQ_OVFL)			| \
			   (1UL << SOCK_RCVTSTAMP))
#define SK_FLAGS_TIMESTAMP ((1UL << SOCK_TIMESTAMP) | (1UL << SOCK_TIMESTAMPING_RX_SOFTWARE))
#define SK_MEM_QUANTUM ((int)PAGE_SIZE)
#define SK_MEM_QUANTUM_SHIFT ilog2(SK_MEM_QUANTUM)
#define SOCK_DEBUG(sk, msg...) do { if ((sk) && sock_flag((sk), SOCK_DBG)) \
					printk(KERN_DEBUG msg); } while (0)

#define SOCK_DESTROY_TIME (10*HZ)
#define SOCK_SKB_CB(__skb) ((struct sock_skb_cb *)((__skb)->cb + \
			    SOCK_SKB_CB_OFFSET))
#define SOCK_SKB_CB_OFFSET ((FIELD_SIZEOF(struct sk_buff, cb) - \
			    sizeof(struct sock_skb_cb)))

#define __sk_user_data(sk) ((*((void __rcu **)&(sk)->sk_user_data)))
#define bh_lock_sock(__sk)	spin_lock(&((__sk)->sk_lock.slock))
#define bh_lock_sock_nested(__sk) \
				spin_lock_nested(&((__sk)->sk_lock.slock), \
				SINGLE_DEPTH_NESTING)
#define bh_unlock_sock(__sk)	spin_unlock(&((__sk)->sk_lock.slock))
#define mem_cgroup_sockets_enabled static_key_false(&memcg_socket_limit_enabled)
#define rcu_assign_sk_user_data(sk, ptr)	rcu_assign_pointer(__sk_user_data((sk)), ptr)
#define rcu_dereference_sk_user_data(sk)	rcu_dereference(__sk_user_data((sk)))
#define sk_del_node_init_rcu(sk)	sk_del_node_init(sk)
#define sk_for_each(__sk, list) \
	hlist_for_each_entry(__sk, list, sk_node)
#define sk_for_each_bound(__sk, list) \
	hlist_for_each_entry(__sk, list, sk_bind_node)
#define sk_for_each_from(__sk) \
	hlist_for_each_entry_from(__sk, sk_node)
#define sk_for_each_rcu(__sk, list) \
	hlist_for_each_entry_rcu(__sk, list, sk_node)
#define sk_for_each_safe(__sk, tmp, list) \
	hlist_for_each_entry_safe(__sk, tmp, list, sk_node)
#define sk_nulls_for_each(__sk, node, list) \
	hlist_nulls_for_each_entry(__sk, node, list, sk_nulls_node)
#define sk_nulls_for_each_entry_offset(tpos, pos, head, offset)		       \
	for (pos = (head)->first;					       \
	     (!is_a_nulls(pos)) &&					       \
		({ tpos = (typeof(*tpos) *)((void *)pos - offset); 1;});       \
	     pos = pos->next)
#define sk_nulls_for_each_from(__sk, node) \
	if (__sk && ({ node = &(__sk)->sk_nulls_node; 1; })) \
		hlist_nulls_for_each_entry_from(__sk, node, sk_nulls_node)
#define sk_nulls_for_each_rcu(__sk, node, list) \
	hlist_nulls_for_each_entry_rcu(__sk, node, list, sk_nulls_node)
#define sk_refcnt_debug_dec(sk) do { } while (0)
#define sk_refcnt_debug_inc(sk) do { } while (0)
#define sk_refcnt_debug_release(sk) do { } while (0)
#define sk_rmem_alloc sk_backlog.rmem_alloc
#define sk_wait_event(__sk, __timeo, __condition)			\
	({	int __rc;						\
		release_sock(__sk);					\
		__rc = __condition;					\
		if (!__rc) {						\
			*(__timeo) = schedule_timeout(*(__timeo));	\
		}							\
		sched_annotate_sleep();						\
		lock_sock(__sk);					\
		__rc = __condition;					\
		__rc;							\
	})
#define sock_edemux(skb) sock_efree(skb)
#define sock_lock_init_class_and_name(sk, sname, skey, name, key)	\
do {									\
	sk->sk_lock.owned = 0;						\
	init_waitqueue_head(&sk->sk_lock.wq);				\
	spin_lock_init(&(sk)->sk_lock.slock);				\
	debug_check_no_locks_freed((void *)&(sk)->sk_lock,		\
			sizeof((sk)->sk_lock));				\
	lockdep_set_class_and_name(&(sk)->sk_lock.slock,		\
				(skey), (sname));				\
	lockdep_init_map(&(sk)->sk_lock.dep_map, (name), (key), 0);	\
} while (0)
#define sock_owned_by_user(sk)	((sk)->sk_lock.owned)
#define sock_skb_cb_check_size(size) \
	BUILD_BUG_ON((size) > SOCK_SKB_CB_OFFSET)

#define CSUM_MANGLED_0 ((__force __sum16)0xffff)

#define ERESTART_RESTARTBLOCK 516 

#define DST_METRICS_PTR(X)	__DST_METRICS_PTR((X)->_metrics)

#define __DST_METRICS_PTR(Y)	\
	((u32 *)((Y) & ~DST_METRICS_FLAGS))
#define LOCALLY_ENQUEUED 0x1
#define NEIGH_CACHE_STAT_INC(tbl, field) this_cpu_inc((tbl)->stats->field)
#define NEIGH_CB(skb)	((struct neighbour_cb *)(skb)->cb)
#define NEIGH_ENTRY_SIZE(size)	ALIGN((size), NEIGH_PRIV_ALIGN)
#define NEIGH_VAR(p, attr) ((p)->data[NEIGH_VAR_ ## attr])
#define NEIGH_VAR_DATA_MAX (NEIGH_VAR_LOCKTIME + 1)
#define NEIGH_VAR_INIT(p, attr, val) (NEIGH_VAR(p, attr) = val)
#define NEIGH_VAR_SET(p, attr, val) neigh_var_set(p, NEIGH_VAR_ ## attr, val)

#define neigh_hold(n)	atomic_inc(&(n)->refcnt)
#define MODULE_ALIAS_RTNL_LINK(kind) MODULE_ALIAS("rtnl-link-" kind)

#define NLA_TYPE_MAX (__NLA_TYPE_MAX - 1)

#define nla_for_each_attr(pos, head, len, rem) \
	for (pos = head, rem = len; \
	     nla_ok(pos, rem); \
	     pos = nla_next(pos, &(rem)))
#define nla_for_each_nested(pos, nla, rem) \
	nla_for_each_attr(pos, nla_data(nla), nla_len(nla), rem)
#define nlmsg_for_each_attr(pos, nlh, hdrlen, rem) \
	nla_for_each_attr(pos, nlmsg_attrdata(nlh, hdrlen), \
			  nlmsg_attrlen(nlh, hdrlen), rem)
#define nlmsg_for_each_msg(pos, head, len, rem) \
	for (pos = head, rem = len; \
	     nlmsg_ok(pos, rem); \
	     pos = nlmsg_next(pos, &(rem)))
#define IN6ADDR_ANY_INIT { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } } }
#define IN6ADDR_INTERFACELOCAL_ALLNODES_INIT \
		{ { { 0xff,1,0,0,0,0,0,0,0,0,0,0,0,0,0,1 } } }
#define IN6ADDR_INTERFACELOCAL_ALLROUTERS_INIT \
		{ { { 0xff,1,0,0,0,0,0,0,0,0,0,0,0,0,0,2 } } }
#define IN6ADDR_LINKLOCAL_ALLROUTERS_INIT \
		{ { { 0xff,2,0,0,0,0,0,0,0,0,0,0,0,0,0,2 } } }
#define IN6ADDR_LOOPBACK_INIT { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 } } }
#define IN6ADDR_SITELOCAL_ALLROUTERS_INIT \
		{ { { 0xff,5,0,0,0,0,0,0,0,0,0,0,0,0,0,2 } } }

#define IPV6_ORIGDSTADDR        74
#define IPV6_RECVORIGDSTADDR    IPV6_ORIGDSTADDR
#define IPV6_TRANSPARENT        75
#define IPV6_UNICAST_IF         76

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
#define TICK_USEC ((1000000UL + USER_HZ/2) / USER_HZ)

#define __jiffy_data  __attribute__((section(".data")))
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

#define random_get_entropy()	get_cycles()
#define shift_right(x, s) ({	\
	__typeof__(x) __x = (x);	\
	__typeof__(s) __s = (s);	\
	__x < 0 ? -(-__x >> __s) : __x >> __s;	\
})
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

#define __compiletime_assert(condition, msg, prefix, suffix)		\
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
#  define unlikely(x)	(__builtin_constant_p(x) ? !!(x) : __branch_check__(x, 0))
#define unlikely_notrace(x)	__builtin_expect(!!(x), 0)
# define unreachable() do { } while (1)
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
#define STA_RONLY (STA_PPSSIGNAL | STA_PPSJITTER | STA_PPSWANDER | \
	STA_PPSERROR | STA_CLOCKERR | STA_NANO | STA_MODE | STA_CLK)


#define ALIGN(x, a)		__ALIGN_KERNEL((x), (a))
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]) + __must_be_array(arr))
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
#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
# define DIV_ROUND_UP_SECTOR_T(ll,d) DIV_ROUND_UP_ULL(ll, d)
#define DIV_ROUND_UP_ULL(ll,d) \
	({ unsigned long long _tmp = (ll)+(d)-1; do_div(_tmp, d); _tmp; })
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
#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define __trace_printk_check_format(fmt, args...)			\
do {									\
	if (0)								\
		____trace_printk_check_format(fmt, ##args);		\
} while (0)
#define abs(x) __builtin_choose_expr(sizeof(x) == sizeof(s64), ({	\
		s64 __x = (x);						\
		(__x < 0) ? -__x : __x;					\
	}), ({								\
		long ret;						\
		if (sizeof(x) == sizeof(long)) {			\
			long __x = (x);					\
			ret = (__x < 0) ? -__x : __x;			\
		} else {						\
			int __x = (x);					\
			ret = (__x < 0) ? -__x : __x;			\
		}							\
		ret;							\
	}))
#define clamp(val, lo, hi) min((typeof(val))max(val, lo), hi)
#define clamp_t(type, val, lo, hi) min_t(type, max_t(type, val, lo), hi)
#define clamp_val(val, lo, hi) clamp_t(typeof(val), val, lo, hi)
#define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})
#define do_trace_printk(fmt, args...)					\
do {									\
	static const char *trace_printk_fmt				\
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
#define hex_asc_upper_hi(x)	hex_asc_upper[((x) & 0xf0) >> 4]
#define hex_asc_upper_lo(x)	hex_asc_upper[((x) & 0x0f)]
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
#define might_fault() __might_fault("__FILE__", "__LINE__")
# define might_resched() _cond_resched()
# define might_sleep() \
	do { __might_sleep("__FILE__", "__LINE__", 0); might_resched(); } while (0)
#define might_sleep_if(cond) do { if (cond) might_sleep(); } while (0)
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
	static const char *trace_printk_fmt				\
		__attribute__((section("__trace_printk_fmt"))) =	\
		__builtin_constant_p(str) ? str : NULL;			\
									\
	if (__builtin_constant_p(str))					\
		__trace_bputs(_THIS_IP_, trace_printk_fmt);		\
	else								\
		__trace_puts(_THIS_IP_, str, strlen(str));		\
})
#define upper_32_bits(n) ((u32)(((n) >> 16) >> 16))

#define __ALIGN_KERNEL(x, a)		__ALIGN_KERNEL_MASK(x, (typeof(x))(a) - 1)
#define __ALIGN_KERNEL_MASK(x, mask)	(((x) + (mask)) & ~(mask))
#define DEFINE_DYNAMIC_DEBUG_METADATA(name, fmt)		\
	static struct _ddebug  __aligned(8)			\
	__attribute__((section("__verbose"))) name = {		\
		.modname = KBUILD_MODNAME,			\
		.function = __func__,				\
		.filename = "__FILE__",				\
		.format = (fmt),				\
		.lineno = "__LINE__",				\
		.flags =  _DPRINTK_FLAGS_DEFAULT,		\
	}
#define _DPRINTK_FLAGS_DEFAULT _DPRINTK_FLAGS_PRINT

#define dynamic_dev_dbg(dev, fmt, ...)					\
	do { if (0) dev_printk(KERN_DEBUG, dev, fmt, ##__VA_ARGS__); } while (0)
#define dynamic_hex_dump(prefix_str, prefix_type, rowsize,	\
			 groupsize, buf, len, ascii)		\
do {								\
	DEFINE_DYNAMIC_DEBUG_METADATA(descriptor,		\
		__builtin_constant_p(prefix_str) ? prefix_str : "hexdump");\
	if (unlikely(descriptor.flags & _DPRINTK_FLAGS_PRINT))	\
		print_hex_dump(KERN_DEBUG, prefix_str,		\
			       prefix_type, rowsize, groupsize,	\
			       buf, len, ascii);		\
} while (0)
#define dynamic_netdev_dbg(dev, fmt, ...)			\
do {								\
	DEFINE_DYNAMIC_DEBUG_METADATA(descriptor, fmt);		\
	if (unlikely(descriptor.flags & _DPRINTK_FLAGS_PRINT))	\
		__dynamic_netdev_dbg(&descriptor, dev, fmt,	\
				     ##__VA_ARGS__);		\
} while (0)
#define dynamic_pr_debug(fmt, ...)					\
	do { if (0) printk(KERN_DEBUG pr_fmt(fmt), ##__VA_ARGS__); } while (0)


#define NULL ((void *)0)

#define offsetof(TYPE, MEMBER)	__compiler_offsetof(TYPE, MEMBER)
#define offsetofend(TYPE, MEMBER) \
	(offsetof(TYPE, MEMBER)	+ sizeof(((TYPE *)0)->MEMBER))
#define CONSOLE_LOGLEVEL_DEFAULT 7 
#define CONSOLE_LOGLEVEL_MOTORMOUTH 15	
#define CONSOLE_LOGLEVEL_SILENT  0 
#define MESSAGE_LOGLEVEL_DEFAULT CONFIG_MESSAGE_LOGLEVEL_DEFAULT

#define console_loglevel (console_printk[0])
#define default_console_loglevel (console_printk[3])
#define default_message_loglevel (console_printk[1])
#define minimum_console_loglevel (console_printk[2])
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
								\
	if (!__print_once) {					\
		__print_once = true;				\
		printk_deferred(fmt, ##__VA_ARGS__);		\
	}							\
})
#define printk_once(fmt, ...)					\
({								\
	static bool __print_once __read_mostly;			\
								\
	if (!__print_once) {					\
		__print_once = true;				\
		printk(fmt, ##__VA_ARGS__);			\
	}							\
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
#define INTERNODE_CACHE_SHIFT L1_CACHE_SHIFT
#define L1_CACHE_ALIGN(x) __ALIGN_KERNEL(x, L1_CACHE_BYTES)
#define SMP_CACHE_BYTES L1_CACHE_BYTES

#define ____cacheline_aligned __attribute__((__aligned__(SMP_CACHE_BYTES)))
#define ____cacheline_aligned_in_smp ____cacheline_aligned
#define ____cacheline_internodealigned_in_smp \
	__attribute__((__aligned__(1 << (INTERNODE_CACHE_SHIFT))))
#define __cacheline_aligned_in_smp __cacheline_aligned

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

#define __CRC_SYMBOL(sym, sec)					\
	extern __visible void *__crc_##sym __attribute__((weak));		\
	static const unsigned long __kcrctab_##sym		\
	__used							\
	__attribute__((section("___kcrctab" sec "+" #sym), unused))	\
	= (unsigned long) &__crc_##sym;
#define __EXPORT_SYMBOL(sym, sec)				\
	extern typeof(sym) sym;					\
	__CRC_SYMBOL(sym, sec)					\
	static const char __kstrtab_##sym[]			\
	__attribute__((section("__ksymtab_strings"), aligned(1))) \
	= VMLINUX_SYMBOL_STR(sym);				\
	extern const struct kernel_symbol __ksymtab_##sym;	\
	__visible const struct kernel_symbol __ksymtab_##sym	\
	__used							\
	__attribute__((section("___ksymtab" sec "+" #sym), unused))	\
	= { (unsigned long)&sym, __kstrtab_##sym }
#define __VMLINUX_SYMBOL(x) _##x
#define __VMLINUX_SYMBOL_STR(x) "_" #x

#define __stringify(x...)	__stringify_1(x)
#define __stringify_1(x...)	#x

#define LTO_REFERENCE_INITCALL(x) \
	; 			\
	static __used __exit void *reference_##x(void)	\
	{						\
		return &x;				\
	}

#define __MEMINIT        .section	".meminit.text", "ax"
#define __MEMINITDATA    .section	".meminit.data", "aw"
#define __MEMINITRODATA  .section	".meminit.rodata", "a"
#define __REF            .section       ".ref.text", "ax"
#define __REFCONST       .section       ".ref.rodata", "a"
#define __REFDATA        .section       ".ref.data", "aw"

#define __define_initcall(fn, id) \
	static initcall_t __initcall_##fn##id __used \
	__attribute__((__section__(".initcall" #id ".init"))) = fn; \
	LTO_REFERENCE_INITCALL(__initcall_##fn##id)
#define __exit          __section(.exit.text) __exitused __cold notrace
#define __exit_p(x) x
#define __exit_refok     __ref
#define __exitcall(fn) \
	static exitcall_t __exitcall_##fn __exit_call = fn
#define __exitused  __used
#define __init_refok     __ref
#define __initcall(fn) device_initcall(fn)
#define __initdata_refok __refdata
#define __memexit        __section(.memexit.text) __exitused __cold notrace
#define __memexitconst   __constsection(.memexit.rodata)
#define __memexitdata    __section(.memexit.data)
#define __meminit        __section(.meminit.text) __cold notrace
#define __meminitconst   __constsection(.meminit.rodata)
#define __meminitdata    __section(.meminit.data)
#define __nosavedata __section(.data..nosave)
#define __ref            __section(.ref.text) noinline
#define __refconst       __constsection(.ref.rodata)
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
#define console_initcall(fn) \
	static initcall_t __initcall_##fn \
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
#define security_initcall(fn) \
	static initcall_t __initcall_##fn \
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
	(((~0UL) << (l)) & (~0UL >> (BITS_PER_LONG - 1 - (h))))
#define GENMASK_ULL(h, l) \
	(((~0ULL) << (l)) & (~0ULL >> (BITS_PER_LONG_LONG - 1 - (h))))

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
		old = ACCESS_ONCE(*ptr);			\
		new = (old & ~mask) | bits;			\
	} while (cmpxchg(ptr, old, new) != old);		\
								\
	new;							\
})

#define div64_long(x, y) div_s64((x), (y))
#define div64_ul(x, y)   div64_u64((x), (y))
#define NETLINK_CB(skb)		(*(struct netlink_skb_parms*)&((skb)->cb))
#define NETLINK_CREDS(skb)	(&NETLINK_CB((skb)).creds)
#define NLMSG_DEFAULT_SIZE (NLMSG_GOODSIZE - NLMSG_HDRLEN)

#define MAX_LINKS 32		
#define NET_MAJOR 36		
#define NLA_ALIGN(len)		(((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
#define NLMSG_ALIGN(len) ( ((len)+NLMSG_ALIGNTO-1) & ~(NLMSG_ALIGNTO-1) )
#define NLMSG_DATA(nlh)  ((void*)(((char*)nlh) + NLMSG_LENGTH(0)))
#define NLMSG_LENGTH(len) ((len) + NLMSG_HDRLEN)
#define NLMSG_NEXT(nlh,len)	 ((len) -= NLMSG_ALIGN((nlh)->nlmsg_len), \
				  (struct nlmsghdr*)(((char*)(nlh)) + NLMSG_ALIGN((nlh)->nlmsg_len)))
#define NLMSG_OK(nlh,len) ((len) >= (int)sizeof(struct nlmsghdr) && \
			   (nlh)->nlmsg_len >= sizeof(struct nlmsghdr) && \
			   (nlh)->nlmsg_len <= (len))
#define NLMSG_PAYLOAD(nlh,len) ((nlh)->nlmsg_len - NLMSG_SPACE((len)))
#define NLMSG_SPACE(len) NLMSG_ALIGN(NLMSG_LENGTH(len))
#define NL_MMAP_MSG_ALIGN(sz)		__ALIGN_KERNEL(sz, NL_MMAP_MSG_ALIGNMENT)

#define CMSG_ALIGN(len) ( ((len)+sizeof(long)-1) & ~(sizeof(long)-1) )
#define CMSG_DATA(cmsg)	((void *)((char *)(cmsg) + CMSG_ALIGN(sizeof(struct cmsghdr))))
#define CMSG_FIRSTHDR(msg)	__CMSG_FIRSTHDR((msg)->msg_control, (msg)->msg_controllen)
#define CMSG_LEN(len) (CMSG_ALIGN(sizeof(struct cmsghdr)) + (len))
#define CMSG_NXTHDR(mhdr, cmsg) cmsg_nxthdr((mhdr), (cmsg))
#define CMSG_OK(mhdr, cmsg) ((cmsg)->cmsg_len >= sizeof(struct cmsghdr) && \
			     (cmsg)->cmsg_len <= (unsigned long) \
			     ((mhdr)->msg_controllen - \
			      ((char *)(cmsg) - (char *)(mhdr)->msg_control)))
#define CMSG_SPACE(len) (CMSG_ALIGN(sizeof(struct cmsghdr)) + CMSG_ALIGN(len))
#define MSG_CMSG_CLOEXEC 0x40000000	
#define MSG_EOF         MSG_FIN
#define MSG_EOR         0x80	
#define MSG_FIN         0x200
#define MSG_SENDPAGE_NOTLAST 0x20000 
#define MSG_TRYHARD     4       
#define SCM_CREDENTIALS 0x02		
#define SOL_IRDA        266

#define __CMSG_FIRSTHDR(ctl,len) ((len) >= sizeof(struct cmsghdr) ? \
				  (struct cmsghdr *)(ctl) : \
				  (struct cmsghdr *)NULL)
#define __CMSG_NXTHDR(ctl, len, cmsg) __cmsg_nxthdr((ctl),(len),(cmsg))
#define __sockaddr_check_size(size)	\
	BUILD_BUG_ON(((size) > sizeof(struct __kernel_sockaddr_storage)))
#define for_each_cmsghdr(cmsg, msg) \
	for (cmsg = CMSG_FIRSTHDR(msg); \
	     cmsg; \
	     cmsg = CMSG_NXTHDR(msg, cmsg))
#define sockaddr_storage __kernel_sockaddr_storage


#define iov_for_each(iov, iter, start)				\
	if (!((start).type & ITER_BVEC))			\
	for (iter = (start);					\
	     (iter).count &&					\
	     ((iov = iov_iter_iovec(&(iter))), 1);		\
	     iov_iter_advance(&(iter), (iov).iov_len))
#define iov_iter_rw(i) ((0 ? (struct iov_iter *)0 : (i))->type & RW_MASK)



#define CALC_LOAD(load,exp,n) \
	load *= exp; \
	load += n*(FIXED_1-exp); \
	load >>= FSHIFT;
#define INIT_CPUTIME_ATOMIC \
	(struct task_cputime_atomic) {				\
		.utime = ATOMIC64_INIT(0),			\
		.stime = ATOMIC64_INIT(0),			\
		.sum_exec_runtime = ATOMIC64_INIT(0),		\
	}
#define INIT_USER (&root_user)
#define JOBCTL_STOP_DEQUEUED_BIT 16	
# define MAX_LOCK_DEPTH 48UL
#define MMF_DUMPABLE_BITS 2
#define MMF_DUMPABLE_MASK ((1 << MMF_DUMPABLE_BITS) - 1)
#define MMF_DUMP_FILTER_DEFAULT \
	((1 << MMF_DUMP_ANON_PRIVATE) |	(1 << MMF_DUMP_ANON_SHARED) |\
	 (1 << MMF_DUMP_HUGETLB_PRIVATE) | MMF_DUMP_MASK_DEFAULT_ELF)
#define MMF_DUMP_FILTER_MASK \
	(((1 << MMF_DUMP_FILTER_BITS) - 1) << MMF_DUMP_FILTER_SHIFT)
#define MMF_DUMP_HUGETLB_PRIVATE 7
#define MMF_DUMP_HUGETLB_SHARED  8
#define PFA_NO_NEW_PRIVS 0	
#define PFA_SPREAD_PAGE  1      
#define PFA_SPREAD_SLAB  2      
#define PF_LESS_THROTTLE 0x00100000	
#define PF_MCE_EARLY    0x08000000      
#define PF_MCE_PROCESS  0x00000080      
#define PF_MEMALLOC_NOIO 0x00080000	
#define PF_NO_SETAFFINITY 0x04000000	
#define PF_NPROC_EXCEEDED 0x00001000	
#define PF_SUSPEND_TASK 0x80000000      
# define SD_INIT_NAME(type)		.name = #type
#define SEND_SIG_NOINFO ((struct siginfo *) 0)
#define TASK_COMM_LEN 16
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
#define TASK_STATE_TO_CHAR_STR "RSDTtXZxKWPN"
#define TNF_MIGRATE_FAIL 0x10
#define VMACACHE_BITS 2
#define VMACACHE_MASK (VMACACHE_SIZE - 1)
#define VMACACHE_SIZE (1U << VMACACHE_BITS)
#define WAKE_Q(name)					\
	struct wake_q_head name = { WAKE_Q_TAIL, &name.first }
#define WAKE_Q_TAIL ((struct wake_q_node *) 0x01)

#define __for_each_thread(signal, t)	\
	list_for_each_entry_rcu(t, &(signal)->thread_head, thread_node)
#define __set_current_state(state_value)			\
	do {							\
		current->task_state_change = _THIS_IP_;		\
		current->state = (state_value);			\
	} while (0)
#define __set_task_state(tsk, state_value)			\
	do {							\
		(tsk)->task_state_change = _THIS_IP_;		\
		(tsk)->state = (state_value);			\
	} while (0)
# define arch_task_struct_size (sizeof(struct task_struct))
#define clear_stopped_child_used_math(child) do { (child)->flags &= ~PF_USED_MATH; } while (0)
#define clear_used_math() clear_stopped_child_used_math(current)
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
#define for_each_process_thread(p, t)	\
	for_each_process(p) for_each_thread(p, t)
#define for_each_thread(p, t)		\
	__for_each_thread((p)->signal, t)
#define get_task_struct(tsk) do { atomic_inc(&(tsk)->usage); } while(0)
#define next_task(p) \
	list_entry_rcu((p)->tasks.next, struct task_struct, tasks)
#define sched_exec()   {}
#define set_current_state(state_value)				\
	do {							\
		current->task_state_change = _THIS_IP_;		\
		smp_store_mb(current->state, (state_value));		\
	} while (0)
#define set_stopped_child_used_math(child) do { (child)->flags |= PF_USED_MATH; } while (0)
#define set_task_state(tsk, state_value)			\
	do {							\
		(tsk)->task_state_change = _THIS_IP_;		\
		smp_store_mb((tsk)->state, (state_value));		\
	} while (0)
#define set_used_math() set_stopped_child_used_math(current)
#define task_contributes_to_load(task)	\
				((task->state & TASK_UNINTERRUPTIBLE) != 0 && \
				 (task->flags & PF_FROZEN) == 0 && \
				 (task->state & TASK_NOLOAD) == 0)
#define task_is_stopped(task)	((task->state & __TASK_STOPPED) != 0)
#define task_is_stopped_or_traced(task)	\
			((task->state & (__TASK_STOPPED | __TASK_TRACED)) != 0)
#define task_is_traced(task)	((task->state & __TASK_TRACED) != 0)
#define task_stack_end_corrupted(task) \
		(*(end_of_stack(task)) != STACK_END_MAGIC)
#define task_stack_page(task)	((task)->stack)
#define task_thread_info(task)	((struct thread_info *)(task)->stack)
#define tasklist_empty() \
	list_empty(&init_task.tasks)
#define tsk_cpus_allowed(tsk) (&(tsk)->cpus_allowed)
#define tsk_used_math(p) ((p)->flags & PF_USED_MATH)
#define used_math() tsk_used_math(current)
#define while_each_thread(g, t) \
	while ((t = next_thread(t)) != g)
#define DECLARE_RWSEM(name) \
	struct rw_semaphore name = __RWSEM_INITIALIZER(name)

# define __RWSEM_DEP_MAP_INIT(lockname) , .dep_map = { .name = #lockname }
#define __RWSEM_INITIALIZER(name)				\
	{ .count = RWSEM_UNLOCKED_VALUE,			\
	  .wait_list = LIST_HEAD_INIT((name).wait_list),	\
	  .wait_lock = __RAW_SPIN_LOCK_UNLOCKED(name.wait_lock)	\
	  __RWSEM_OPT_INIT(name)				\
	  __RWSEM_DEP_MAP_INIT(name) }
#define __RWSEM_OPT_INIT(lockname) , .osq = OSQ_LOCK_UNLOCKED, .owner = NULL
# define down_read_nested(sem, subclass)		down_read(sem)
# define down_read_non_owner(sem)		down_read(sem)
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

#define OSQ_LOCK_UNLOCKED { ATOMIC_INIT(OSQ_UNLOCKED_VAL) }
#define OSQ_UNLOCKED_VAL (0)


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
#define  atomic64_dec_return(...)					\
	__atomic_op_fence(atomic64_dec_return, __VA_ARGS__)
#define  atomic64_dec_return_acquire(...)				\
	__atomic_op_acquire(atomic64_dec_return, __VA_ARGS__)
#define  atomic64_dec_return_release(...)				\
	__atomic_op_release(atomic64_dec_return, __VA_ARGS__)
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
#define  atomic_dec_return(...)						\
	__atomic_op_fence(atomic_dec_return, __VA_ARGS__)
#define  atomic_dec_return_acquire(...)					\
	__atomic_op_acquire(atomic_dec_return, __VA_ARGS__)
#define  atomic_dec_return_release(...)					\
	__atomic_op_release(atomic_dec_return, __VA_ARGS__)
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
static inline void							\
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
#define ATOMIC64_INIT(i)	{ (i) }
#define ATOMIC64_OP(op)							\
extern void	 atomic64_##op(long long a, atomic64_t *v);
#define ATOMIC64_OPS(op)	ATOMIC64_OP(op) ATOMIC64_OP_RETURN(op)
#define ATOMIC64_OP_RETURN(op)						\
extern long long atomic64_##op##_return(long long a, atomic64_t *v);

#define atomic64_add_negative(a, v)	(atomic64_add_return((a), (v)) < 0)
#define atomic64_dec(v)			atomic64_sub(1LL, (v))
#define atomic64_dec_and_test(v)	(atomic64_dec_return((v)) == 0)
#define atomic64_inc(v)			atomic64_add(1LL, (v))
#define atomic64_inc_and_test(v) 	(atomic64_inc_return(v) == 0)
#define atomic64_inc_not_zero(v) 	atomic64_add_unless((v), 1LL, 0LL)
#define atomic64_sub_and_test(a, v)	(atomic64_sub_return((a), (v)) == 0)
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
#define assert_spin_locked(lock)	assert_raw_spin_locked(&(lock)->rlock)
#define atomic_dec_and_lock(atomic, lock) \
		__cond_lock(lock, _atomic_dec_and_lock(atomic, lock))
#define do_raw_spin_lock_flags(lock, flags) do_raw_spin_lock(lock)
#define raw_spin_can_lock(lock)	(!raw_spin_is_locked(lock))
#define raw_spin_is_contended(lock) ((lock)->break_lock)
#define raw_spin_is_locked(lock)	arch_spin_is_locked(&(lock)->raw_lock)
#define raw_spin_lock(lock)	_raw_spin_lock(lock)
#define raw_spin_lock_bh(lock)		_raw_spin_lock_bh(lock)
# define raw_spin_lock_bh_nested(lock, subclass) \
	_raw_spin_lock_bh_nested(lock, subclass)
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
#define smp_mb__before_spinlock()	smp_wmb()
#define spin_lock_bh_nested(lock, subclass)			\
do {								\
	raw_spin_lock_bh_nested(spinlock_check(lock), subclass);\
} while (0)
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
#define lock_acquire_exclusive(l, s, t, n, i)		lock_acquire(l, s, t, 0, 1, n, i)
#define lock_acquire_shared(l, s, t, n, i)		lock_acquire(l, s, t, 1, 1, n, i)
#define lock_acquire_shared_recursive(l, s, t, n, i)	lock_acquire(l, s, t, 2, 1, n, i)
#define lock_acquired(lockdep_map, ip) do {} while (0)
#define lock_contended(lockdep_map, ip) do {} while (0)
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
#define lockdep_assert_held_once(l)	do {				\
		WARN_ON_ONCE(debug_locks && !lockdep_is_held(l));	\
	} while (0)
# define lockdep_clear_current_reclaim_state()	do { } while (0)
#define lockdep_depth(tsk)	(debug_locks ? (tsk)->lockdep_depth : 0)
# define lockdep_free_key_range(start, size)	do { } while (0)
# define lockdep_info()				do { } while (0)
# define lockdep_init()				do { } while (0)
# define lockdep_init_map(lock, name, key, sub) \
		do { (void)(name); (void)(key); } while (0)
#define lockdep_is_held(lock)	lock_is_held(&(lock)->dep_map)
#define lockdep_match_class(lock, key) lockdep_match_key(&(lock)->dep_map, key)
#define lockdep_pin_lock(l)		lock_pin_lock(&(l)->dep_map)
#define lockdep_recursing(tsk)	((tsk)->lockdep_recursion)
# define lockdep_reset()		do { debug_locks = 1; } while (0)
# define lockdep_set_class(lock, key)		do { (void)(key); } while (0)
# define lockdep_set_class_and_name(lock, key, name) \
		do { (void)(key); (void)(name); } while (0)
#define lockdep_set_class_and_subclass(lock, key, sub) \
		lockdep_init_map(&(lock)->dep_map, #key, key, sub)
# define lockdep_set_current_reclaim_state(g)	do { } while (0)
#define lockdep_set_novalidate_class(lock) \
	lockdep_set_class_and_name(lock, &__lockdep_no_validate__, #lock)
#define lockdep_set_subclass(lock, sub)	\
		lockdep_init_map(&(lock)->dep_map, #lock, \
				 (lock)->dep_map.key, sub)
# define lockdep_sys_exit() 			do { } while (0)
# define lockdep_trace_alloc(g)			do { } while (0)
#define lockdep_unpin_lock(l)	lock_unpin_lock(&(l)->dep_map)
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
#define BUILD_BUG() (0)
#define BUILD_BUG_ON(condition) (0)
#define BUILD_BUG_ON_INVALID(e) (0)
#define BUILD_BUG_ON_MSG(cond, msg) (0)
#define BUILD_BUG_ON_NOT_POWER_OF_2(n) (0)
#define BUILD_BUG_ON_NULL(e) ((void*)0)
#define BUILD_BUG_ON_ZERO(e) (0)

#define BUG() do {} while (1)
#define BUGFLAG_TAINT(taint)	(BUGFLAG_WARNING | ((taint) << 8))
#define BUG_GET_TAINT(bug)	((bug)->flags >> 8)
#define BUG_ON(condition) do { if (condition) ; } while (0)

#define WARN(condition, format...) ({					\
	int __ret_warn_on = !!(condition);				\
	no_printk(format);						\
	unlikely(__ret_warn_on);					\
})
#define WARN_ON(condition) ({						\
	int __ret_warn_on = !!(condition);				\
	unlikely(__ret_warn_on);					\
})
#define WARN_ONCE(condition, format...)	({			\
	static bool __section(.data.unlikely) __warned;		\
	int __ret_warn_once = !!(condition);			\
								\
	if (unlikely(__ret_warn_once))				\
		if (WARN(!__warned, format)) 			\
			__warned = true;			\
	unlikely(__ret_warn_once);				\
})
#define WARN_ON_ONCE(condition)	({				\
	static bool __section(.data.unlikely) __warned;		\
	int __ret_warn_once = !!(condition);			\
								\
	if (unlikely(__ret_warn_once))				\
		if (WARN_ON(!__warned)) 			\
			__warned = true;			\
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
	static bool __section(.data.unlikely) __warned;		\
	int __ret_warn_once = !!(condition);			\
								\
	if (unlikely(__ret_warn_once))				\
		if (WARN_TAINT(!__warned, taint, format))	\
			__warned = true;			\
	unlikely(__ret_warn_once);				\
})

#define __WARN()		warn_slowpath_null("__FILE__", "__LINE__")
#define __WARN_printf(arg...)	warn_slowpath_fmt("__FILE__", "__LINE__", arg)
#define __WARN_printf_taint(taint, arg...)				\
	warn_slowpath_fmt_taint("__FILE__", "__LINE__", taint, arg)
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
#define list_first_entry_or_null(ptr, type, member) \
	(!list_empty(ptr) ? list_first_entry(ptr, type, member) : NULL)
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
#define LIST_POISON2  ((void *) 0x200 + POISON_POINTER_DELTA)
#define PAGE_POISON 0xaa
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
#define in_nmi()	(preempt_count() & NMI_MASK)
#define in_serving_softirq()	(softirq_count() & SOFTIRQ_OFFSET)
#define in_softirq()		(softirq_count())
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
#define set_thread_flag(flag) \
	set_ti_thread_flag(current_thread_info(), flag)
#define test_and_clear_thread_flag(flag) \
	test_and_clear_ti_thread_flag(current_thread_info(), flag)
#define test_and_set_thread_flag(flag) \
	test_and_set_ti_thread_flag(current_thread_info(), flag)
#define test_thread_flag(flag) \
	test_ti_thread_flag(current_thread_info(), flag)
#define tif_need_resched() test_thread_flag(TIF_NEED_RESCHED)
# define INIT_TRACE_IRQFLAGS

#define irqs_disabled()					\
	({						\
		unsigned long _flags;			\
		raw_local_save_flags(_flags);		\
		raw_irqs_disabled_flags(_flags);	\
	})
#define irqs_disabled_flags(flags) raw_irqs_disabled_flags(flags)
#define local_irq_disable()	do { raw_local_irq_disable(); } while (0)
#define local_irq_enable()	do { raw_local_irq_enable(); } while (0)
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
#define local_irq_save(flags)					\
	do {							\
		raw_local_irq_save(flags);			\
	} while (0)
#define local_save_flags(flags)	raw_local_save_flags(flags)
# define lockdep_softirq_enter()	do { current->softirq_context++; } while (0)
# define lockdep_softirq_exit()	do { current->softirq_context--; } while (0)
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
# define trace_hardirq_enter()	do { current->hardirq_context++; } while (0)
# define trace_hardirq_exit()	do { current->hardirq_context--; } while (0)
# define trace_hardirqs_enabled(p)	((p)->hardirqs_enabled)
# define trace_hardirqs_off()		do { } while (0)
# define trace_hardirqs_on()		do { } while (0)
# define trace_softirq_context(p)	((p)->softirq_context)
# define trace_softirqs_enabled(p)	((p)->softirqs_enabled)
# define trace_softirqs_off(ip)		do { } while (0)
# define trace_softirqs_on(ip)		do { } while (0)
#define CGROUP_CANFORK_COUNT (CGROUP_CANFORK_END - CGROUP_CANFORK_START)
#define CGROUP_SUBSYS_COUNT 0
#define MAX_CGROUP_ROOT_NAMELEN 64
#define MAX_CGROUP_TYPE_NAMELEN 32
#define SUBSYS(_x) _x ## _cgrp_id,
#define SUBSYS_TAG(_t) CGROUP_ ## _t, \
	__unused_tag_ ## _t = CGROUP_ ## _t - 1,


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
#define INIT_WORK(_work, _func)						\
	__INIT_WORK((_work), (_func), 0)
#define INIT_WORK_ONSTACK(_work, _func)					\
	__INIT_WORK((_work), (_func), 1)
#define WORK_DATA_INIT()	ATOMIC_LONG_INIT(WORK_STRUCT_NO_POOL)
#define WORK_DATA_STATIC_INIT()	\
	ATOMIC_LONG_INIT(WORK_STRUCT_NO_POOL | WORK_STRUCT_STATIC)

#define __DELAYED_WORK_INITIALIZER(n, f, tflags) {			\
	.work = __WORK_INITIALIZER((n).work, (f)),			\
	.timer = __TIMER_INITIALIZER(delayed_work_timer_fn,		\
				     0, (unsigned long)&(n),		\
				     (tflags) | TIMER_IRQSAFE),		\
	}
#define __INIT_DELAYED_WORK(_work, _func, _tflags)			\
	do {								\
		INIT_WORK(&(_work)->work, (_func));			\
		__setup_timer(&(_work)->timer, delayed_work_timer_fn,	\
			      (unsigned long)(_work),			\
			      (_tflags) | TIMER_IRQSAFE);		\
	} while (0)
#define __INIT_DELAYED_WORK_ONSTACK(_work, _func, _tflags)		\
	do {								\
		INIT_WORK_ONSTACK(&(_work)->work, (_func));		\
		__setup_timer_on_stack(&(_work)->timer,			\
				       delayed_work_timer_fn,		\
				       (unsigned long)(_work),		\
				       (_tflags) | TIMER_IRQSAFE);	\
	} while (0)
#define __INIT_WORK(_work, _func, _onstack)				\
	do {								\
		static struct lock_class_key __key;			\
									\
		__init_work((_work), _onstack);				\
		(_work)->data = (atomic_long_t) WORK_DATA_INIT();	\
		lockdep_init_map(&(_work)->lockdep_map, #_work, &__key, 0); \
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
	alloc_workqueue(fmt, WQ_UNBOUND | __WQ_ORDERED | (flags), 1, ##args)
#define alloc_workqueue(fmt, flags, max_active, args...)		\
({									\
	static struct lock_class_key __key;				\
	const char *__lock_name;					\
									\
	__lock_name = #fmt#args;					\
									\
	__alloc_workqueue_key((fmt), (flags), (max_active),		\
			      &__key, __lock_name, ##args);		\
})
#define create_freezable_workqueue(name)				\
	alloc_workqueue("%s", WQ_FREEZABLE | WQ_UNBOUND | WQ_MEM_RECLAIM, \
			1, (name))
#define create_singlethread_workqueue(name)				\
	alloc_ordered_workqueue("%s", WQ_MEM_RECLAIM, name)
#define create_workqueue(name)						\
	alloc_workqueue("%s", WQ_MEM_RECLAIM, 1, (name))
#define delayed_work_pending(w) \
	work_pending(&(w)->work)
#define work_data_bits(work) ((unsigned long *)(&(work)->data))
#define work_pending(work) \
	test_bit(WORK_STRUCT_PENDING_BIT, work_data_bits(work))

#define cpu_active(cpu)		cpumask_test_cpu((cpu), cpu_active_mask)
#define cpu_all_mask to_cpumask(cpu_all_bits)
#define cpu_is_offline(cpu)	unlikely(!cpu_online(cpu))
#define cpu_none_mask to_cpumask(cpu_bit_bitmap[0])
#define cpu_online(cpu)		((cpu) == 0)
#define cpu_possible(cpu)	((cpu) == 0)
#define cpu_present(cpu)	cpumask_test_cpu((cpu), cpu_present_mask)
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
#define for_each_online_cpu(cpu)   for_each_cpu((cpu), cpu_online_mask)
#define for_each_possible_cpu(cpu) for_each_cpu((cpu), cpu_possible_mask)
#define for_each_present_cpu(cpu)  for_each_cpu((cpu), cpu_present_mask)
#define num_active_cpus()	1U
#define num_online_cpus()	1U
#define num_possible_cpus()	1U
#define num_present_cpus()	1U
#define this_cpu_cpumask_var_ptr(x) this_cpu_read(x)
#define to_cpumask(bitmap)						\
	((struct cpumask *)(1 ? (bitmap)				\
			    : (void *)sizeof(__check_is_bitmap(bitmap))))
#define BITMAP_FIRST_WORD_MASK(start) (~0UL << ((start) & (BITS_PER_LONG - 1)))
#define BITMAP_LAST_WORD_MASK(nbits) (~0UL >> (-(nbits) & (BITS_PER_LONG - 1)))

#define bitmap_copy_le bitmap_copy
#define small_const_nbits(nbits) \
	(__builtin_constant_p(nbits) && (nbits) <= BITS_PER_LONG)
#define MIN_THREADS_LEFT_FOR_ROOT 4
#define PID_MAX_DEFAULT (CONFIG_BASE_SMALL ? 0x1000 : 0x8000)
#define PID_MAX_LIMIT (CONFIG_BASE_SMALL ? PAGE_SIZE * 8 : \
	(sizeof(long) > 4 ? 4 * 1024 * 1024 : PID_MAX_DEFAULT))

#define DEFINE_TIMER(_name, _function, _expires, _data)		\
	struct timer_list _name =				\
		TIMER_INITIALIZER(_function, _expires, _data)
#define TIMER_DEFERRED_INITIALIZER(_function, _expires, _data)	\
	__TIMER_INITIALIZER((_function), (_expires), (_data), TIMER_DEFERRABLE)
#define TIMER_INITIALIZER(_function, _expires, _data)		\
	__TIMER_INITIALIZER((_function), (_expires), (_data), 0)

#define __TIMER_INITIALIZER(_function, _expires, _data, _flags) { \
		.entry = { .next = TIMER_ENTRY_STATIC },	\
		.function = (_function),			\
		.expires = (_expires),				\
		.data = (_data),				\
		.flags = (_flags),				\
		.slack = -1,					\
		__TIMER_LOCKDEP_MAP_INITIALIZER(		\
			"__FILE__" ":" __stringify("__LINE__"))	\
	}
#define __TIMER_LOCKDEP_MAP_INITIALIZER(_kn)				\
	.lockdep_map = STATIC_LOCKDEP_MAP_INIT(_kn, &_kn),
#define __init_timer(_timer, _flags)					\
	do {								\
		static struct lock_class_key __key;			\
		init_timer_key((_timer), (_flags), #_timer, &__key);	\
	} while (0)
#define __init_timer_on_stack(_timer, _flags)				\
	do {								\
		static struct lock_class_key __key;			\
		init_timer_on_stack_key((_timer), (_flags), #_timer, &__key); \
	} while (0)
#define __setup_timer(_timer, _fn, _data, _flags)			\
	do {								\
		__init_timer((_timer), (_flags));			\
		(_timer)->function = (_fn);				\
		(_timer)->data = (_data);				\
	} while (0)
#define __setup_timer_on_stack(_timer, _fn, _data, _flags)		\
	do {								\
		__init_timer_on_stack((_timer), (_flags));		\
		(_timer)->function = (_fn);				\
		(_timer)->data = (_data);				\
	} while (0)
#define del_singleshot_timer_sync(t) del_timer_sync(t)
# define del_timer_sync(t)		del_timer(t)
#define init_timer(timer)						\
	__init_timer((timer), 0)
#define init_timer_deferrable(timer)					\
	__init_timer((timer), TIMER_DEFERRABLE)
#define init_timer_on_stack(timer)					\
	__init_timer_on_stack((timer), 0)
#define setup_deferrable_timer_on_stack(timer, fn, data)		\
	__setup_timer_on_stack((timer), (fn), (data), TIMER_DEFERRABLE)
#define setup_timer(timer, fn, data)					\
	__setup_timer((timer), (fn), (data), 0)
#define setup_timer_on_stack(timer, fn, data)				\
	__setup_timer_on_stack((timer), (fn), (data), 0)
#define DEFINE_CTL_TABLE_POLL(name)					\
	struct ctl_table_poll name = __CTL_TABLE_POLL_INITIALIZER(name)

#define __CTL_TABLE_POLL_INITIALIZER(name) {				\
	.event = ATOMIC_INIT(0),					\
	.wait = __WAIT_QUEUE_HEAD_INITIALIZER(name.wait) }
#define CTL_MAXNAME 10		

#define RB_CLEAR_NODE(node)  \
	((node)->__rb_parent_color = (unsigned long)(node))
#define RB_EMPTY_NODE(node)  \
	((node)->__rb_parent_color == (unsigned long)(node))
#define RB_EMPTY_ROOT(root)  ((root)->rb_node == NULL)
#define rb_entry_safe(ptr, type, member) \
	({ typeof(ptr) ____ptr = (ptr); \
	   ____ptr ? rb_entry(____ptr, type, member) : NULL; \
	})
#define rb_parent(r)   ((struct rb_node *)((r)->__rb_parent_color & ~3))
#define rbtree_postorder_for_each_entry_safe(pos, n, root, field) \
	for (pos = rb_entry_safe(rb_first_postorder(root), typeof(*pos), field); \
	     pos && ({ n = rb_entry_safe(rb_next_postorder(&pos->field), \
			typeof(*pos), field); 1; }); \
	     pos = n)
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
		rcu_irq_enter(); \
		do { a; } while (0); \
		rcu_irq_exit(); \
	} while (0)
#define RCU_POINTER_INITIALIZER(p, v) \
		.p = RCU_INITIALIZER(v)
#define TASKS_RCU(x) x
#define UINT_CMP_GE(a, b)	(UINT_MAX / 2 >= (a) - (b))
#define UINT_CMP_LT(a, b)	(UINT_MAX / 2 < (a) - (b))
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
	typeof(*p) *________p1 = (typeof(*p) *__force)lockless_dereference(p); \
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
#define _wait_rcu_gp(checktiny, ...) \
do {									\
	call_rcu_func_t __crcu_array[] = { __VA_ARGS__ };		\
	struct rcu_synchronize __rs_array[ARRAY_SIZE(__crcu_array)];	\
	__wait_rcu_gp(checktiny, ARRAY_SIZE(__crcu_array),		\
			__crcu_array, __rs_array);			\
} while (0)
#define cond_resched_rcu_qs() \
do { \
	if (!cond_resched()) \
		rcu_note_voluntary_context_switch(current); \
} while (0)
#define do_trace_rcu_torture_read(rcutorturename, rhp, secs, c_old, c) \
	do { } while (0)
#define kfree_rcu(ptr, rcu_head)					\
	__kfree_rcu(&((ptr)->rcu_head), offsetof(typeof(*(ptr)), rcu_head))
#define rcu_access_pointer(p) __rcu_access_pointer((p), __rcu)
#define rcu_assign_pointer(p, v) smp_store_release(&p, RCU_INITIALIZER(v))
#define rcu_dereference(p) rcu_dereference_check(p, 0)
#define rcu_dereference_bh(p) rcu_dereference_bh_check(p, 0)
#define rcu_dereference_bh_check(p, c) \
	__rcu_dereference_check((p), (c) || rcu_read_lock_bh_held(), __rcu)
#define rcu_dereference_check(p, c) \
	__rcu_dereference_check((p), (c) || rcu_read_lock_held(), __rcu)
#define rcu_dereference_protected(p, c) \
	__rcu_dereference_protected((p), (c), __rcu)
#define rcu_dereference_raw(p) rcu_dereference_check(p, 1) 
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
#define synchronize_rcu_mult(...) \
	_wait_rcu_gp(IS_ENABLED(CONFIG_TINY_RCU), __VA_ARGS__)
#define ulong2long(a)		(*(long *)(&(a)))
#define wait_rcu_gp(...) _wait_rcu_gp(false, __VA_ARGS__)



#define ktime_add(lhs, rhs) \
		({ (ktime_t){ .tv64 = (lhs).tv64 + (rhs).tv64 }; })
#define ktime_add_ns(kt, nsval) \
		({ (ktime_t){ .tv64 = (kt).tv64 + (nsval) }; })
#define ktime_sub(lhs, rhs) \
		({ (ktime_t){ .tv64 = (lhs).tv64 - (rhs).tv64 }; })
#define ktime_sub_ns(kt, nsval) \
		({ (ktime_t){ .tv64 = (kt).tv64 - (nsval) }; })
#define ktime_to_ns(kt)			((kt).tv64)
#define ktime_to_timespec(kt)		ns_to_timespec((kt).tv64)
#define ktime_to_timespec64(kt)		ns_to_timespec64((kt).tv64)
#define ktime_to_timeval(kt)		ns_to_timeval((kt).tv64)

#define COMPLETION_INITIALIZER(work) \
	{ 0, __WAIT_QUEUE_HEAD_INITIALIZER((work).wait) }
#define COMPLETION_INITIALIZER_ONSTACK(work) \
	({ init_completion(&work); work; })
#define DECLARE_COMPLETION(work) \
	struct completion work = COMPLETION_INITIALIZER(work)
# define DECLARE_COMPLETION_ONSTACK(work) \
	struct completion work = COMPLETION_INITIALIZER_ONSTACK(work)

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
#define __WAIT_ATOMIC_T_KEY_INITIALIZER(p)				\
	{ .flags = p, .bit_nr = WAIT_ATOMIC_T_BIT_NR, }
#define __WAIT_BIT_KEY_INITIALIZER(word, bit)				\
	{ .flags = word, .bit_nr = bit, }
#define __WAIT_QUEUE_HEAD_INITIALIZER(name) {				\
	.lock		= __SPIN_LOCK_UNLOCKED(name.lock),		\
	.task_list	= { &(name).task_list, &(name).task_list } }
# define __WAIT_QUEUE_HEAD_INIT_ONSTACK(name) \
	({ init_waitqueue_head(&name); name; })
#define ___wait_cond_timeout(condition)					\
({									\
	bool __cond = (condition);					\
	if (__cond && !__ret)						\
		__ret = 1;						\
	__cond || !__ret;						\
})
#define ___wait_event(wq, condition, state, exclusive, ret, cmd)	\
({									\
	__label__ __out;						\
	wait_queue_t __wait;						\
	long __ret = ret;				\
									\
	INIT_LIST_HEAD(&__wait.task_list);				\
	if (exclusive)							\
		__wait.flags = WQ_FLAG_EXCLUSIVE;			\
	else								\
		__wait.flags = 0;					\
									\
	for (;;) {							\
		long __int = prepare_to_wait_event(&wq, &__wait, state);\
									\
		if (condition)						\
			break;						\
									\
		if (___wait_is_interruptible(state) && __int) {		\
			__ret = __int;					\
			if (exclusive) {				\
				abort_exclusive_wait(&wq, &__wait,	\
						     state, NULL);	\
				goto __out;				\
			}						\
			break;						\
		}							\
									\
		cmd;							\
	}								\
	finish_wait(&wq, &__wait);					\
__out:	__ret;								\
})
#define ___wait_is_interruptible(state)					\
	(!__builtin_constant_p(state) ||				\
		state == TASK_INTERRUPTIBLE || state == TASK_KILLABLE)	\

#define __io_wait_event(wq, condition)					\
	(void)___wait_event(wq, condition, TASK_UNINTERRUPTIBLE, 0, 0,	\
			    io_schedule())
#define __wait_event(wq, condition)					\
	(void)___wait_event(wq, condition, TASK_UNINTERRUPTIBLE, 0, 0,	\
			    schedule())
#define __wait_event_cmd(wq, condition, cmd1, cmd2)			\
	(void)___wait_event(wq, condition, TASK_UNINTERRUPTIBLE, 0, 0,	\
			    cmd1; schedule(); cmd2)
#define __wait_event_exclusive_cmd(wq, condition, cmd1, cmd2)		\
	(void)___wait_event(wq, condition, TASK_UNINTERRUPTIBLE, 1, 0,	\
			    cmd1; schedule(); cmd2)
#define __wait_event_freezable(wq, condition)				\
	___wait_event(wq, condition, TASK_INTERRUPTIBLE, 0, 0,		\
			    schedule(); try_to_freeze())
#define __wait_event_freezable_exclusive(wq, condition)			\
	___wait_event(wq, condition, TASK_INTERRUPTIBLE, 1, 0,		\
			schedule(); try_to_freeze())
#define __wait_event_freezable_timeout(wq, condition, timeout)		\
	___wait_event(wq, ___wait_cond_timeout(condition),		\
		      TASK_INTERRUPTIBLE, 0, timeout,			\
		      __ret = schedule_timeout(__ret); try_to_freeze())
#define __wait_event_hrtimeout(wq, condition, timeout, state)		\
({									\
	int __ret = 0;							\
	struct hrtimer_sleeper __t;					\
									\
	hrtimer_init_on_stack(&__t.timer, CLOCK_MONOTONIC,		\
			      HRTIMER_MODE_REL);			\
	hrtimer_init_sleeper(&__t, current);				\
	if ((timeout).tv64 != KTIME_MAX)				\
		hrtimer_start_range_ns(&__t.timer, timeout,		\
				       current->timer_slack_ns,		\
				       HRTIMER_MODE_REL);		\
									\
	__ret = ___wait_event(wq, condition, state, 0, 0,		\
		if (!__t.task) {					\
			__ret = -ETIME;					\
			break;						\
		}							\
		schedule());						\
									\
	hrtimer_cancel(&__t.timer);					\
	destroy_hrtimer_on_stack(&__t.timer);				\
	__ret;								\
})
#define __wait_event_interruptible(wq, condition)			\
	___wait_event(wq, condition, TASK_INTERRUPTIBLE, 0, 0,		\
		      schedule())
#define __wait_event_interruptible_exclusive(wq, condition)		\
	___wait_event(wq, condition, TASK_INTERRUPTIBLE, 1, 0,		\
		      schedule())
#define __wait_event_interruptible_lock_irq(wq, condition, lock, cmd)	\
	___wait_event(wq, condition, TASK_INTERRUPTIBLE, 0, 0,		\
		      spin_unlock_irq(&lock);				\
		      cmd;						\
		      schedule();					\
		      spin_lock_irq(&lock))
#define __wait_event_interruptible_lock_irq_timeout(wq, condition,	\
						    lock, timeout)	\
	___wait_event(wq, ___wait_cond_timeout(condition),		\
		      TASK_INTERRUPTIBLE, 0, timeout,			\
		      spin_unlock_irq(&lock);				\
		      __ret = schedule_timeout(__ret);			\
		      spin_lock_irq(&lock));
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
#define __wait_event_interruptible_timeout(wq, condition, timeout)	\
	___wait_event(wq, ___wait_cond_timeout(condition),		\
		      TASK_INTERRUPTIBLE, 0, timeout,			\
		      __ret = schedule_timeout(__ret))
#define __wait_event_killable(wq, condition)				\
	___wait_event(wq, condition, TASK_KILLABLE, 0, 0, schedule())
#define __wait_event_lock_irq(wq, condition, lock, cmd)			\
	(void)___wait_event(wq, condition, TASK_UNINTERRUPTIBLE, 0, 0,	\
			    spin_unlock_irq(&lock);			\
			    cmd;					\
			    schedule();					\
			    spin_lock_irq(&lock))
#define __wait_event_timeout(wq, condition, timeout)			\
	___wait_event(wq, ___wait_cond_timeout(condition),		\
		      TASK_UNINTERRUPTIBLE, 0, timeout,			\
		      __ret = schedule_timeout(__ret))
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
		__init_waitqueue_head((q), #q, &__key);	\
	} while (0)
#define io_wait_event(wq, condition)					\
do {									\
	might_sleep();							\
	if (condition)							\
		break;							\
	__io_wait_event(wq, condition);					\
} while (0)
#define wait_event(wq, condition)					\
do {									\
	might_sleep();							\
	if (condition)							\
		break;							\
	__wait_event(wq, condition);					\
} while (0)
#define wait_event_cmd(wq, condition, cmd1, cmd2)			\
do {									\
	if (condition)							\
		break;							\
	__wait_event_cmd(wq, condition, cmd1, cmd2);			\
} while (0)
#define wait_event_exclusive_cmd(wq, condition, cmd1, cmd2)		\
do {									\
	if (condition)							\
		break;							\
	__wait_event_exclusive_cmd(wq, condition, cmd1, cmd2);		\
} while (0)
#define wait_event_freezable(wq, condition)				\
({									\
	int __ret = 0;							\
	might_sleep();							\
	if (!(condition))						\
		__ret = __wait_event_freezable(wq, condition);		\
	__ret;								\
})
#define wait_event_freezable_exclusive(wq, condition)			\
({									\
	int __ret = 0;							\
	might_sleep();							\
	if (!(condition))						\
		__ret = __wait_event_freezable_exclusive(wq, condition);\
	__ret;								\
})
#define wait_event_freezable_timeout(wq, condition, timeout)		\
({									\
	long __ret = timeout;						\
	might_sleep();							\
	if (!___wait_cond_timeout(condition))				\
		__ret = __wait_event_freezable_timeout(wq, condition, timeout);	\
	__ret;								\
})
#define wait_event_hrtimeout(wq, condition, timeout)			\
({									\
	int __ret = 0;							\
	might_sleep();							\
	if (!(condition))						\
		__ret = __wait_event_hrtimeout(wq, condition, timeout,	\
					       TASK_UNINTERRUPTIBLE);	\
	__ret;								\
})
#define wait_event_interruptible(wq, condition)				\
({									\
	int __ret = 0;							\
	might_sleep();							\
	if (!(condition))						\
		__ret = __wait_event_interruptible(wq, condition);	\
	__ret;								\
})
#define wait_event_interruptible_exclusive(wq, condition)		\
({									\
	int __ret = 0;							\
	might_sleep();							\
	if (!(condition))						\
		__ret = __wait_event_interruptible_exclusive(wq, condition);\
	__ret;								\
})
#define wait_event_interruptible_exclusive_locked(wq, condition)	\
	((condition)							\
	 ? 0 : __wait_event_interruptible_locked(wq, condition, 1, 0))
#define wait_event_interruptible_exclusive_locked_irq(wq, condition)	\
	((condition)							\
	 ? 0 : __wait_event_interruptible_locked(wq, condition, 1, 1))
#define wait_event_interruptible_hrtimeout(wq, condition, timeout)	\
({									\
	long __ret = 0;							\
	might_sleep();							\
	if (!(condition))						\
		__ret = __wait_event_hrtimeout(wq, condition, timeout,	\
					       TASK_INTERRUPTIBLE);	\
	__ret;								\
})
#define wait_event_interruptible_lock_irq(wq, condition, lock)		\
({									\
	int __ret = 0;							\
	if (!(condition))						\
		__ret = __wait_event_interruptible_lock_irq(wq,		\
						condition, lock,);	\
	__ret;								\
})
#define wait_event_interruptible_lock_irq_cmd(wq, condition, lock, cmd)	\
({									\
	int __ret = 0;							\
	if (!(condition))						\
		__ret = __wait_event_interruptible_lock_irq(wq,		\
						condition, lock, cmd);	\
	__ret;								\
})
#define wait_event_interruptible_lock_irq_timeout(wq, condition, lock,	\
						  timeout)		\
({									\
	long __ret = timeout;						\
	if (!___wait_cond_timeout(condition))				\
		__ret = __wait_event_interruptible_lock_irq_timeout(	\
					wq, condition, lock, timeout);	\
	__ret;								\
})
#define wait_event_interruptible_locked(wq, condition)			\
	((condition)							\
	 ? 0 : __wait_event_interruptible_locked(wq, condition, 0, 0))
#define wait_event_interruptible_locked_irq(wq, condition)		\
	((condition)							\
	 ? 0 : __wait_event_interruptible_locked(wq, condition, 0, 1))
#define wait_event_interruptible_timeout(wq, condition, timeout)	\
({									\
	long __ret = timeout;						\
	might_sleep();							\
	if (!___wait_cond_timeout(condition))				\
		__ret = __wait_event_interruptible_timeout(wq,		\
						condition, timeout);	\
	__ret;								\
})
#define wait_event_killable(wq, condition)				\
({									\
	int __ret = 0;							\
	might_sleep();							\
	if (!(condition))						\
		__ret = __wait_event_killable(wq, condition);		\
	__ret;								\
})
#define wait_event_lock_irq(wq, condition, lock)			\
do {									\
	if (condition)							\
		break;							\
	__wait_event_lock_irq(wq, condition, lock, );			\
} while (0)
#define wait_event_lock_irq_cmd(wq, condition, lock, cmd)		\
do {									\
	if (condition)							\
		break;							\
	__wait_event_lock_irq(wq, condition, lock, cmd);		\
} while (0)
#define wait_event_timeout(wq, condition, timeout)			\
({									\
	long __ret = timeout;						\
	might_sleep();							\
	if (!___wait_cond_timeout(condition))				\
		__ret = __wait_event_timeout(wq, condition, timeout);	\
	__ret;								\
})
#define wake_up(x)			__wake_up(x, TASK_NORMAL, 1, NULL)
#define wake_up_all(x)			__wake_up(x, TASK_NORMAL, 0, NULL)
#define wake_up_all_locked(x)		__wake_up_locked((x), TASK_NORMAL, 0)
#define wake_up_interruptible(x)	__wake_up(x, TASK_INTERRUPTIBLE, 1, NULL)
#define wake_up_interruptible_all(x)	__wake_up(x, TASK_INTERRUPTIBLE, 0, NULL)
#define wake_up_interruptible_nr(x, nr)	__wake_up(x, TASK_INTERRUPTIBLE, nr, NULL)
#define wake_up_interruptible_poll(x, m)				\
	__wake_up(x, TASK_INTERRUPTIBLE, 1, (void *) (m))
#define wake_up_interruptible_sync(x)	__wake_up_sync((x), TASK_INTERRUPTIBLE, 1)
#define wake_up_interruptible_sync_poll(x, m)				\
	__wake_up_sync_key((x), TASK_INTERRUPTIBLE, 1, (void *) (m))
#define wake_up_locked(x)		__wake_up_locked((x), TASK_NORMAL, 1)
#define wake_up_locked_poll(x, m)					\
	__wake_up_locked_key((x), TASK_NORMAL, (void *) (m))
#define wake_up_nr(x, nr)		__wake_up(x, TASK_NORMAL, nr, NULL)
#define wake_up_poll(x, m)						\
	__wake_up(x, TASK_NORMAL, 1, (void *) (m))

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

#define percpu_init_rwsem(brw)	\
({								\
	static struct lock_class_key rwsem_key;			\
	__percpu_init_rwsem(brw, #brw, &rwsem_key);		\
})
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
	     &(pos)->member != NULL;					\
	     (pos) = llist_entry((pos)->member.next, typeof(*(pos)), member))
#define llist_for_each_entry_safe(pos, n, node, member)			       \
	for (pos = llist_entry((node), typeof(*pos), member);		       \
	     &pos->member != NULL &&					       \
	        (n = llist_entry(pos->member.next, typeof(*n), member), true); \
	     pos = n)
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
#define VM_BUG_ON_VMA(cond, vma)					\
	do {								\
		if (unlikely(cond)) {					\
			dump_vma(vma);					\
			BUG();						\
		}							\
	} while (0)
#define VM_WARN_ON(cond) WARN_ON(cond)
#define VM_WARN_ONCE(cond, format...) WARN_ONCE(cond, format)
#define VM_WARN_ON_ONCE(cond) WARN_ON_ONCE(cond)

#define GFP_MOVABLE_MASK (__GFP_RECLAIMABLE|__GFP_MOVABLE)
#define GFP_MOVABLE_SHIFT 3
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
	(ZONE_NORMAL << 0 * ZONES_SHIFT)				      \
	| (OPT_ZONE_DMA << ___GFP_DMA * ZONES_SHIFT)			      \
	| (OPT_ZONE_HIGHMEM << ___GFP_HIGHMEM * ZONES_SHIFT)		      \
	| (OPT_ZONE_DMA32 << ___GFP_DMA32 * ZONES_SHIFT)		      \
	| (ZONE_NORMAL << ___GFP_MOVABLE * ZONES_SHIFT)			      \
	| (OPT_ZONE_DMA << (___GFP_MOVABLE | ___GFP_DMA) * ZONES_SHIFT)	      \
	| (ZONE_MOVABLE << (___GFP_MOVABLE | ___GFP_HIGHMEM) * ZONES_SHIFT)   \
	| (OPT_ZONE_DMA32 << (___GFP_MOVABLE | ___GFP_DMA32) * ZONES_SHIFT)   \
)
#define OPT_ZONE_DMA ZONE_DMA
#define OPT_ZONE_DMA32 ZONE_DMA32
#define OPT_ZONE_HIGHMEM ZONE_HIGHMEM
#define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) - 1))
#define __GFP_BITS_SHIFT 26
#define __GFP_HARDWALL   ((__force gfp_t)___GFP_HARDWALL)
#define __GFP_NOMEMALLOC ((__force gfp_t)___GFP_NOMEMALLOC)
#define __GFP_NOTRACK_FALSE_POSITIVE (__GFP_NOTRACK)
#define __GFP_OTHER_NODE ((__force gfp_t)___GFP_OTHER_NODE)
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
#define node_has_online_mem(nid) (1)
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
#define MAX_ZONELISTS 2
#define MAX_ZONES_PER_ZONELIST (MAX_NUMNODES * MAX_NR_ZONES)
#define MIGRATETYPE_MASK ((1UL << NR_MIGRATETYPE_BITS) - 1)
#define NODE_DATA(nid)		(&contig_page_data)
#define NODE_MEM_MAP(nid)	mem_map
#define NR_MIGRATETYPE_BITS (PB_migrate_end - PB_migrate + 1)
#define NUMA_ZONELIST_ORDER_LEN 16	
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
	for (z = first_zones_zonelist(zlist, highidx, nodemask, &zone);	\
		zone;							\
		z = next_zones_zonelist(++z, highidx, nodemask),	\
			zone = zonelist_zone(z))			\

#define get_pageblock_migratetype(page)					\
	get_pfnblock_flags_mask(page, page_to_pfn(page),		\
			PB_migrate_end, MIGRATETYPE_MASK)
#define high_wmark_pages(z) (z->watermark[WMARK_HIGH])
#  define is_migrate_cma(migratetype) unlikely((migratetype) == MIGRATE_CMA)
#define low_wmark_pages(z) (z->watermark[WMARK_LOW])
#define min_wmark_pages(z) (z->watermark[WMARK_MIN])
#define nid_page_nr(nid, pagenr) 	pgdat_page_nr(NODE_DATA(nid),(pagenr))
#define node_end_pfn(nid) pgdat_end_pfn(NODE_DATA(nid))
#define node_present_pages(nid)	(NODE_DATA(nid)->node_present_pages)
#define node_spanned_pages(nid)	(NODE_DATA(nid)->node_spanned_pages)
#define node_start_pfn(nid)	(NODE_DATA(nid)->node_start_pfn)
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
#define DEFINE_SRCU(name)		__DEFINE_SRCU(name, )
#define DEFINE_STATIC_SRCU(name)	__DEFINE_SRCU(name, static)
#define RCU_BATCH_INIT(name) { NULL, &(name.head) }

#define __DEFINE_SRCU(name, is_static)					\
	static DEFINE_PER_CPU(struct srcu_struct_array, name##_srcu_array);\
	is_static struct srcu_struct name = __SRCU_STRUCT_INIT(name)
#define __SRCU_DEP_MAP_INIT(srcu_name)	.dep_map = { .name = #srcu_name },
#define __SRCU_STRUCT_INIT(name)					\
	{								\
		.completed = -300,					\
		.per_cpu_ref = &name##_srcu_array,			\
		.queue_lock = __SPIN_LOCK_UNLOCKED(name.queue_lock),	\
		.running = false,					\
		.batch_queue = RCU_BATCH_INIT(name.batch_queue),	\
		.batch_check0 = RCU_BATCH_INIT(name.batch_check0),	\
		.batch_check1 = RCU_BATCH_INIT(name.batch_check1),	\
		.batch_done = RCU_BATCH_INIT(name.batch_done),		\
		.work = __DELAYED_WORK_INITIALIZER(name.work, process_srcu, 0),\
		__SRCU_DEP_MAP_INIT(name)				\
	}
#define init_srcu_struct(sp) \
({ \
	static struct lock_class_key __srcu_key; \
	\
	__init_srcu_struct((sp), #sp, &__srcu_key); \
})
#define srcu_dereference(p, sp) srcu_dereference_check((p), (sp), 0)
#define srcu_dereference_check(p, sp, c) \
	__rcu_dereference_check((p), (c) || srcu_read_lock_held(sp), __rcu)
#define DEFINE_MUTEX(mutexname) \
	struct mutex mutexname = __MUTEX_INITIALIZER(mutexname)
# define __DEBUG_MUTEX_INITIALIZER(lockname)
# define __DEP_MAP_MUTEX_INITIALIZER(lockname) \
		, .dep_map = { .name = #lockname }

#define __MUTEX_INITIALIZER(lockname) \
		{ .count = ATOMIC_INIT(1) \
		, .wait_lock = __SPIN_LOCK_UNLOCKED(lockname.wait_lock) \
		, .wait_list = LIST_HEAD_INIT(lockname.wait_list) \
		__DEBUG_MUTEX_INITIALIZER(lockname) \
		__DEP_MAP_MUTEX_INITIALIZER(lockname) }
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
# define mutex_lock_nest_lock(lock, nest_lock) mutex_lock(lock)
# define mutex_lock_nested(lock, subclass) mutex_lock(lock)

#define LAST_CPUPID_SHIFT (LAST__PID_SHIFT+LAST__CPU_SHIFT)
#define LAST_CPUPID_WIDTH LAST_CPUPID_SHIFT
#define LAST__CPU_MASK  ((1 << LAST__CPU_SHIFT)-1)
#define LAST__CPU_SHIFT NR_CPUS_BITS
#define LAST__PID_MASK  ((1 << LAST__PID_SHIFT)-1)
#define LAST__PID_SHIFT 8


#define ZONES_SHIFT 0
#define MAX_NUMNODES    (1 << NODES_SHIFT)
#define NODES_SHIFT     CONFIG_NODES_SHIFT


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
#define nodemask_pr_args(maskp)		MAX_NUMNODES, (maskp)->bits
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
#define DEFINE_IDA(name)	struct ida name = IDA_INIT(name)
#define DEFINE_IDR(name)	struct idr name = IDR_INIT(name)
#define IDA_BITMAP_BITS 	(IDA_BITMAP_LONGS * sizeof(long) * 8)
#define IDA_INIT(name)		{ .idr = IDR_INIT((name).idr), .free_bitmap = NULL, }
#define IDR_BITS 8
#define IDR_INIT(name)							\
{									\
	.lock			= __SPIN_LOCK_UNLOCKED(name.lock),	\
}
#define IDR_MASK ((1 << IDR_BITS)-1)
#define IDR_SIZE (1 << IDR_BITS)

#define idr_for_each_entry(idp, entry, id)			\
	for (id = 0; ((entry) = idr_get_next(idp, &(id))) != NULL; ++id)
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
#define GROUP_AT(gi, i) \
	((gi)->blocks[(i) / NGROUPS_PER_BLOCK][(i) % NGROUPS_PER_BLOCK])

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


#define is_key_possessed(k)		0
#define key_fsgid_changed(t)		do { } while(0)
#define key_fsuid_changed(t)		do { } while(0)
#define key_get(k) 			({ NULL; })
#define key_init()			do { } while(0)
#define key_invalidate(k)		do { } while(0)
#define key_put(k)			do { } while(0)
#define key_ref_put(k)			do { } while(0)
#define key_ref_to_ptr(k)		NULL
#define key_revoke(k)			do { } while(0)
#define key_serial(k)			0
#define key_validate(k)			0
#define make_key_ref(k, p)		NULL
#define rcu_assign_keypointer(KEY, PAYLOAD)				\
do {									\
	rcu_assign_pointer((KEY)->payload.rcu_data0, (PAYLOAD));	\
} while (0)
#define rcu_dereference_key(KEY)					\
	(rcu_dereference_protected((KEY)->payload.rcu_data0,		\
				   rwsem_is_locked(&((struct key *)(KEY))->sem)))
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
#define VFS_CAP_U32             VFS_CAP_U32_2
#define VFS_CAP_U32_1           1
#define VFS_CAP_U32_2           2
#define XATTR_CAPS_SZ           XATTR_CAPS_SZ_2
#define XATTR_CAPS_SZ_1         (sizeof(__le32)*(1 + 2*VFS_CAP_U32_1))
#define XATTR_CAPS_SZ_2         (sizeof(__le32)*(1 + 2*VFS_CAP_U32_2))
#define _LINUX_CAPABILITY_U32S     _LINUX_CAPABILITY_U32S_1
#define _LINUX_CAPABILITY_U32S_1     1
#define _LINUX_CAPABILITY_U32S_2     2
#define _LINUX_CAPABILITY_U32S_3     2
#define _LINUX_CAPABILITY_VERSION  _LINUX_CAPABILITY_VERSION_1
#define _LINUX_CAPABILITY_VERSION_1  0x19980330
#define _LINUX_CAPABILITY_VERSION_2  0x20071026  
#define _LINUX_CAPABILITY_VERSION_3  0x20080522

#define cap_valid(x) ((x) >= 0 && (x) <= CAP_LAST_CAP)





#define DEFINE_RT_MUTEX(mutexname) \
	struct rt_mutex mutexname = __RT_MUTEX_INITIALIZER(mutexname)
# define __DEBUG_RT_MUTEX_INITIALIZER(mutexname) \
	, .name = #mutexname, .file = "__FILE__", .line = "__LINE__"

#define __RT_MUTEX_INITIALIZER(mutexname) \
	{ .wait_lock = __RAW_SPIN_LOCK_UNLOCKED(mutexname.wait_lock) \
	, .waiters = RB_ROOT \
	, .owner = NULL \
	__DEBUG_RT_MUTEX_INITIALIZER(mutexname)}
# define rt_mutex_debug_check_no_locks_held(task)	do { } while (0)
# define rt_mutex_debug_task_free(t)			do { } while (0)
# define rt_mutex_init(mutex)			__rt_mutex_init(mutex, __func__)

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
#define list_entry_rcu(ptr, type, member) \
	container_of(lockless_dereference(ptr), type, member)
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
#define list_for_each_entry_rcu(pos, head, member) \
	for (pos = list_entry_rcu((head)->next, typeof(*pos), member); \
		&pos->member != (head); \
		pos = list_entry_rcu(pos->member.next, typeof(*pos), member))
#define list_next_rcu(list)	(*((struct list_head __rcu **)(&(list)->next)))


#define INIT_PROP_LOCAL_SINGLE(name)			\
{	.lock = __RAW_SPIN_LOCK_UNLOCKED(name.lock),	\
}
#define PROP_MAX_SHIFT (3*BITS_PER_LONG/4)


#define percpu_counter_init(fbc, value, gfp)				\
	({								\
		static struct lock_class_key __key;			\
									\
		__percpu_counter_init(fbc, value, gfp, &__key);		\
	})

#define do_each_pid_task(pid, type, task)				\
	do {								\
		if ((pid) != NULL)					\
			hlist_for_each_entry_rcu((task),		\
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
	put_user_ex(sas_ss_flags(sp), &__uss->ss_flags); \
	put_user_ex(t->sas_ss_size, &__uss->ss_size); \
} while (0);
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

#define SHM_HUGETLB     04000   
#define SHM_HUGE_1GB    (30 << SHM_HUGE_SHIFT)
#define SHM_HUGE_2MB    (21 << SHM_HUGE_SHIFT)
#define SHM_HUGE_MASK   0x3f
#define SHM_HUGE_SHIFT  26
#define SHM_LOCKED      02000   
#define SHM_NORESERVE   010000  

#define shm_init_task(task) INIT_LIST_HEAD(&(task)->sysvshm.shm_clist)
#define SHMALL (ULONG_MAX - (1UL << 24)) 
#define SHMMAX (ULONG_MAX - (1UL << 24)) 
#define SHMMIN 1			 
#define SHMMNI 4096			 
#define SHMSEG SHMMNI			 
#define SHM_INFO 	14
#define SHM_LOCK 	11
#define SHM_STAT 	13
#define SHM_UNLOCK 	12

#define IPCMNI 32768  

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
#define SEM_UNDO        0x1000  
#define SETALL  17       
#define SETVAL  16       


# define cputime_to_nsecs(__ct)	\
	(cputime_to_usecs(__ct) * NSEC_PER_USEC)
# define nsecs_to_cputime(__nsecs)	\
	usecs_to_cputime((__nsecs) / NSEC_PER_USEC)
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
#define NICE_TO_PRIO(nice)	((nice) + DEFAULT_PRIO)
#define PRIO_TO_NICE(prio)	((prio) - DEFAULT_PRIO)
#define TASK_USER_PRIO(p)	USER_PRIO((p)->static_prio)
#define USER_PRIO(p)		((p)-MAX_RT_PRIO)

#define SCHED_RESET_ON_FORK     0x40000000

#define SECURITY_CAP_AUDIT 1
#define SECURITY_CAP_NOAUDIT 0


#define PAGE_ALIGN(addr) ALIGN(addr, PAGE_SIZE)
#define PAGE_ALIGNED(addr)	IS_ALIGNED((unsigned long)addr, PAGE_SIZE)

#define VM_FAULT_FALLBACK 0x0800	
#define VM_FAULT_GET_HINDEX(x) (((x) >> 12) & 0xf)
#define VM_FAULT_HWPOISON 0x0010	
#define VM_FAULT_HWPOISON_LARGE 0x0020  
#define VM_FAULT_HWPOISON_LARGE_MASK 0xf000 
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
#define mm_forbids_zeropage(X)	(0)
#define nth_page(page,n) pfn_to_page(page_to_pfn((page)) + (n))
#define offset_in_page(p)	((unsigned long)(p) & ~PAGE_MASK)
#define page_address(page) lowmem_page_address(page)
#define page_address_init()  do { } while(0)
#define page_private(page)		((page)->private)
#define pmd_huge_pte(mm, pmd) (pmd_to_page(pmd)->pmd_huge_pte)
#define pte_alloc_kernel(pmd, address)			\
	((unlikely(pmd_none(*(pmd))) && __pte_alloc_kernel(pmd, address))? \
		NULL: pte_offset_kernel(pmd, address))
#define pte_alloc_map(mm, vma, pmd, address)				\
	((unlikely(pmd_none(*(pmd))) && __pte_alloc(mm, vma,	\
							pmd, address))?	\
	 NULL: pte_offset_map(pmd, address))
#define pte_alloc_map_lock(mm, pmd, address, ptlp)	\
	((unlikely(pmd_none(*(pmd))) && __pte_alloc(mm, NULL,	\
							pmd, address))?	\
		NULL: pte_offset_map_lock(mm, pmd, address, ptlp))
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
#define set_page_private(page, v)	((page)->private = (v))
#define sysctl_legacy_va_layout 0
#define vma_interval_tree_foreach(vma, root, start, last)		\
	for (vma = vma_interval_tree_iter_first(root, start, last);	\
	     vma; vma = vma_interval_tree_iter_next(vma, start, last))

#define __count_zone_vm_events(item, zone, delta) \
		__count_vm_events(item##_NORMAL - ZONE_NORMAL + \
		zone_idx(zone), delta)
#define add_zone_page_state(__z, __i, __d) mod_zone_page_state(__z, __i, __d)
#define count_vm_numa_event(x)     count_vm_event(x)
#define count_vm_numa_events(x, y) count_vm_events(x, y)
#define count_vm_tlb_event(x)	   count_vm_event(x)
#define count_vm_tlb_events(x, y)  count_vm_events(x, y)
#define count_vm_vmacache_event(x) do {} while (0)
#define dec_zone_page_state __dec_zone_page_state
#define dec_zone_state __dec_zone_state
#define inc_zone_page_state __inc_zone_page_state
#define inc_zone_state __inc_zone_state
#define mod_zone_page_state __mod_zone_page_state
#define node_page_state(node, item) global_page_state(item)
#define set_pgdat_percpu_threshold(pgdat, callback) { }
#define sub_zone_page_state(__z, __i, __d) mod_zone_page_state(__z, __i, -(__d))
#define zone_statistics(_zl, _z, gfp) do { } while (0)
#define DMA32_ZONE(xx) xx##_DMA32,
#define DMA_ZONE(xx) xx##_DMA,
#define FOR_ALL_ZONES(xx) DMA_ZONE(xx) DMA32_ZONE(xx) xx##_NORMAL, HIGHMEM_ZONE(xx) xx##_MOVABLE
#define HIGHMEM_ZONE(xx) xx##_HIGH,

#define HPAGE_PMD_MASK ({ BUILD_BUG(); 0; })
#define HPAGE_PMD_NR (1<<HPAGE_PMD_ORDER)
#define HPAGE_PMD_ORDER (HPAGE_PMD_SHIFT-PAGE_SHIFT)
#define HPAGE_PMD_SHIFT ({ BUILD_BUG(); 0; })
#define HPAGE_PMD_SIZE ({ BUILD_BUG(); 0; })

#define hpage_nr_pages(x) 1
#define split_huge_page_pmd(__vma, __address, __pmd)			\
	do {								\
		pmd_t *____pmd = (__pmd);				\
		if (unlikely(pmd_trans_huge(*____pmd)))			\
			__split_huge_page_pmd(__vma, __address,		\
					____pmd);			\
	}  while (0)
#define split_huge_page_pmd_mm(__mm, __address, __pmd)	\
	do { } while (0)
#define transparent_hugepage_debug_cow()				\
	(transparent_hugepage_flags &					\
	 (1<<TRANSPARENT_HUGEPAGE_DEBUG_COW_FLAG))
#define transparent_hugepage_defrag(__vma)				\
	((transparent_hugepage_flags &					\
	  (1<<TRANSPARENT_HUGEPAGE_DEFRAG_FLAG)) ||			\
	 (transparent_hugepage_flags &					\
	  (1<<TRANSPARENT_HUGEPAGE_DEFRAG_REQ_MADV_FLAG) &&		\
	  (__vma)->vm_flags & VM_HUGEPAGE))
#define transparent_hugepage_enabled(__vma) 0
#define transparent_hugepage_flags 0UL
#define transparent_hugepage_use_zero_page()				\
	(transparent_hugepage_flags &					\
	 (1<<TRANSPARENT_HUGEPAGE_USE_ZERO_PAGE_FLAG))
#define wait_split_huge_page(__anon_vma, __pmd)				\
	do {								\
		pmd_t *____pmd = (__pmd);				\
		anon_vma_lock_write(__anon_vma);			\
		anon_vma_unlock_write(__anon_vma);			\
		BUG_ON(pmd_trans_splitting(*____pmd) ||			\
		       pmd_trans_huge(*____pmd));			\
	} while (0)
#define CLEARPAGEFLAG(uname, lname)					\
static inline void ClearPage##uname(struct page *page)			\
			{ clear_bit(PG_##lname, &page->flags); }
#define CLEARPAGEFLAG_NOOP(uname)					\
static inline void ClearPage##uname(struct page *page) {  }
#define PAGEFLAG(uname, lname) TESTPAGEFLAG(uname, lname)		\
	SETPAGEFLAG(uname, lname) CLEARPAGEFLAG(uname, lname)
#define PAGEFLAG_FALSE(uname) TESTPAGEFLAG_FALSE(uname)			\
	SETPAGEFLAG_NOOP(uname) CLEARPAGEFLAG_NOOP(uname)
#define PAGE_BALLOON_MAPCOUNT_VALUE (-256)
#define PAGE_BUDDY_MAPCOUNT_VALUE (-128)
#define PAGE_FLAGS_CHECK_AT_FREE \
	(1 << PG_lru	 | 1 << PG_locked    | \
	 1 << PG_private | 1 << PG_private_2 | \
	 1 << PG_writeback | 1 << PG_reserved | \
	 1 << PG_slab	 | 1 << PG_swapcache | 1 << PG_active | \
	 1 << PG_unevictable | __PG_MLOCKED | \
	 __PG_COMPOUND_LOCK)

#define PG_head_mask ((1L << PG_head))
#define PageHighMem(__p) is_highmem_idx(page_zonenum(__p))
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
static inline int Page##uname(const struct page *page)			\
			{ return test_bit(PG_##lname, &page->flags); }
#define TESTPAGEFLAG_FALSE(uname)					\
static inline int Page##uname(const struct page *page) { return 0; }
#define TESTSCFLAG(uname, lname)					\
	TESTSETFLAG(uname, lname) TESTCLEARFLAG(uname, lname)
#define TESTSCFLAG_FALSE(uname)						\
	TESTSETFLAG_FALSE(uname) TESTCLEARFLAG_FALSE(uname)
#define TESTSETFLAG(uname, lname)					\
static inline int TestSetPage##uname(struct page *page)			\
		{ return test_and_set_bit(PG_##lname, &page->flags); }
#define TESTSETFLAG_FALSE(uname)					\
static inline int TestSetPage##uname(struct page *page) { return 0; }
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
#define test_set_page_writeback(page)			\
	__test_set_page_writeback(page, false)
#define test_set_page_writeback_keepwrite(page)	\
	__test_set_page_writeback(page, true)
#define IS_ERR_VALUE(x) unlikely((x) >= (unsigned long)-MAX_ERRNO)
#define PTR_RET(p) PTR_ERR_OR_ZERO(p)


#define DEFAULT_SEEKS 2 
#define SHRINK_STOP (~0UL)


#define MAX_RESOURCE ((resource_size_t)~0)

#define ARCH_KMALLOC_MINALIGN ARCH_DMA_MINALIGN
#define ARCH_SLAB_MINALIGN __alignof__(unsigned long long)
#define KMALLOC_MIN_SIZE ARCH_DMA_MINALIGN
#define KMALLOC_SHIFT_LOW ilog2(ARCH_DMA_MINALIGN)
#define KMEM_CACHE(__struct, __flags) kmem_cache_create(#__struct,\
		sizeof(struct __struct), __alignof__(struct __struct),\
		(__flags), NULL)
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
#define KASAN_SHADOW_SCALE_SHIFT 3


#define DECLARE_SOCKADDR(type, dst, src)	\
	type dst = ({ __sockaddr_check_size(sizeof(*dst)); (type) src; })
#define MODULE_ALIAS_NETPROTO(proto) \
	MODULE_ALIAS("net-pf-" __stringify(proto))
#define MODULE_ALIAS_NET_PF_PROTO(pf, proto) \
	MODULE_ALIAS("net-pf-" __stringify(pf) "-proto-" __stringify(proto))
#define MODULE_ALIAS_NET_PF_PROTO_NAME(pf, proto, name) \
	MODULE_ALIAS("net-pf-" __stringify(pf) "-proto-" __stringify(proto) \
		     name)
#define MODULE_ALIAS_NET_PF_PROTO_TYPE(pf, proto, type) \
	MODULE_ALIAS("net-pf-" __stringify(pf) "-proto-" __stringify(proto) \
		     "-type-" __stringify(type))
#define SOCK_MAX (SOCK_PACKET + 1)
#define SOCK_TYPE_MASK 0xf

#define net_alert_ratelimited(fmt, ...)				\
	net_ratelimited_function(pr_alert, fmt, ##__VA_ARGS__)
#define net_crit_ratelimited(fmt, ...)				\
	net_ratelimited_function(pr_crit, fmt, ##__VA_ARGS__)
#define net_dbg_ratelimited(fmt, ...)				\
	net_ratelimited_function(pr_debug, fmt, ##__VA_ARGS__)
#define net_emerg_ratelimited(fmt, ...)				\
	net_ratelimited_function(pr_emerg, fmt, ##__VA_ARGS__)
#define net_err_ratelimited(fmt, ...)				\
	net_ratelimited_function(pr_err, fmt, ##__VA_ARGS__)
#define net_get_random_once(buf, nbytes)			\
	get_random_once((buf), (nbytes))
#define net_info_ratelimited(fmt, ...)				\
	net_ratelimited_function(pr_info, fmt, ##__VA_ARGS__)
#define net_notice_ratelimited(fmt, ...)			\
	net_ratelimited_function(pr_notice, fmt, ##__VA_ARGS__)
#define net_ratelimited_function(function, ...)			\
do {								\
	if (net_ratelimit())					\
		function(__VA_ARGS__);				\
} while (0)
#define net_warn_ratelimited(fmt, ...)				\
	net_ratelimited_function(pr_warn, fmt, ##__VA_ARGS__)
#define		     sockfd_put(sock) fput(sock->file)

#define DO_ONCE(func, ...)						     \
	({								     \
		bool ___ret = false;					     \
		static bool ___done = false;				     \
		static struct static_key ___once_key = STATIC_KEY_INIT_TRUE; \
		if (static_key_true(&___once_key)) {			     \
			unsigned long ___flags;				     \
			___ret = __do_once_start(&___done, &___flags);	     \
			if (unlikely(___ret)) {				     \
				func(__VA_ARGS__);			     \
				__do_once_done(&___done, &___once_key,	     \
					       &___flags);		     \
			}						     \
		}							     \
		___ret;							     \
	})

#define get_random_once(buf, nbytes)					     \
	DO_ONCE(get_random_bytes, (buf), (nbytes))
#define DEFINE_STATIC_KEY_FALSE(name)	\
	struct static_key_false name = STATIC_KEY_FALSE_INIT
#define DEFINE_STATIC_KEY_TRUE(name)	\
	struct static_key_true name = STATIC_KEY_TRUE_INIT
# define HAVE_JUMP_LABEL
#define STATIC_KEY_CHECK_USE() WARN(!static_key_initialized,		      \
				    "%s used before call to jump_label_init", \
				    __func__)
#define STATIC_KEY_FALSE_INIT (struct static_key_false){ .key = STATIC_KEY_INIT_FALSE, }
#define STATIC_KEY_INIT STATIC_KEY_INIT_FALSE
#define STATIC_KEY_TRUE_INIT  (struct static_key_true) { .key = STATIC_KEY_INIT_TRUE,  }

#define jump_label_enabled static_key_enabled
#define static_branch_dec(x)		static_key_slow_dec(&(x)->key)
#define static_branch_disable(x)	static_key_disable(&(x)->key)
#define static_branch_enable(x)		static_key_enable(&(x)->key)
#define static_branch_inc(x)		static_key_slow_inc(&(x)->key)
#define static_branch_likely(x)							\
({										\
	bool branch;								\
	if (__builtin_types_compatible_p(typeof(*x), struct static_key_true))	\
		branch = !arch_static_branch(&(x)->key, true);			\
	else if (__builtin_types_compatible_p(typeof(*x), struct static_key_false)) \
		branch = !arch_static_branch_jump(&(x)->key, true);		\
	else									\
		branch = ____wrong_branch_error();				\
	branch;									\
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
	branch;									\
})
#define static_key_enabled(x)							\
({										\
	if (!__builtin_types_compatible_p(typeof(*x), struct static_key) &&	\
	    !__builtin_types_compatible_p(typeof(*x), struct static_key_true) &&\
	    !__builtin_types_compatible_p(typeof(*x), struct static_key_false))	\
		____wrong_branch_error();					\
	static_key_count((struct static_key *)x) > 0;				\
})

#define kmemcheck_annotate_bitfield(ptr, name)	\
	do {					\
	} while (0)
#define kmemcheck_annotate_variable(var)	\
	do {					\
	} while (0)


#define kmemcheck_enabled 0
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


#define prandom_init_once(pcpu_state)			\
	DO_ONCE(prandom_seed_full_state, (pcpu_state))


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
#define CHECKSUM_BREAK 76

#define MAX_SKB_FRAGS 16UL
#define NET_SKBUFF_DATA_USES_OFFSET 1
#define PKT_TYPE_OFFSET()	offsetof(struct sk_buff, __pkt_type_offset)
#define SKB_DATAREF_MASK ((1 << SKB_DATAREF_SHIFT) - 1)
#define SKB_DATAREF_SHIFT 16
#define SKB_DATA_ALIGN(X)	ALIGN(X, SMP_CACHE_BYTES)
#define SKB_FRAG_ASSERT(skb) 	BUG_ON(skb_has_frag_list(skb))
#define SKB_GSO_CB(skb) ((struct skb_gso_cb *)(skb)->cb)
#define SKB_LINEAR_ASSERT(skb)  BUG_ON(skb_is_nonlinear(skb))
#define SKB_MAX_HEAD(X)		(SKB_MAX_ORDER((X), 0))
#define SKB_MAX_ORDER(X, ORDER) \
	SKB_WITH_OVERHEAD((PAGE_SIZE << (ORDER)) - (X))
#define SKB_PAGE_ASSERT(skb) 	BUG_ON(skb_shinfo(skb)->nr_frags)
#define SKB_TRUESIZE(X) ((X) +						\
			 SKB_DATA_ALIGN(sizeof(struct sk_buff)) +	\
			 SKB_DATA_ALIGN(sizeof(struct skb_shared_info)))
#define SKB_WITH_OVERHEAD(X)	\
	((X) - SKB_DATA_ALIGN(sizeof(struct skb_shared_info)))

#define __skb_checksum_validate(skb, proto, complete,			\
				zero_okay, check, compute_pseudo)	\
({									\
	__sum16 __ret = 0;						\
	skb->csum_valid = 0;						\
	if (__skb_checksum_validate_needed(skb, zero_okay, check))	\
		__ret = __skb_checksum_validate_complete(skb,		\
				complete, compute_pseudo(skb, proto));	\
	__ret;								\
})
#define dev_kfree_skb(a)	consume_skb(a)
#define skb_checksum_init(skb, proto, compute_pseudo)			\
	__skb_checksum_validate(skb, proto, false, false, 0, compute_pseudo)
#define skb_checksum_init_zero_check(skb, proto, check, compute_pseudo)	\
	__skb_checksum_validate(skb, proto, false, true, check, compute_pseudo)
#define skb_checksum_simple_validate(skb)				\
	__skb_checksum_validate(skb, 0, true, false, 0, null_compute_pseudo)
#define skb_checksum_try_convert(skb, proto, check, compute_pseudo)	\
do {									\
	if (__skb_checksum_convert_check(skb))				\
		__skb_checksum_convert(skb, check,			\
				       compute_pseudo(skb, proto));	\
} while (0)
#define skb_checksum_validate(skb, proto, compute_pseudo)		\
	__skb_checksum_validate(skb, proto, true, false, 0, compute_pseudo)
#define skb_checksum_validate_zero_check(skb, proto, check,		\
					 compute_pseudo)		\
	__skb_checksum_validate(skb, proto, true, true, check, compute_pseudo)
#define skb_queue_reverse_walk(queue, skb) \
		for (skb = (queue)->prev;					\
		     skb != (struct sk_buff *)(queue);				\
		     skb = skb->prev)
#define skb_queue_reverse_walk_from_safe(queue, skb, tmp)			\
		for (tmp = skb->prev;						\
		     skb != (struct sk_buff *)(queue);				\
		     skb = tmp, tmp = skb->prev)
#define skb_queue_reverse_walk_safe(queue, skb, tmp)				\
		for (skb = (queue)->prev, tmp = skb->prev;			\
		     skb != (struct sk_buff *)(queue);				\
		     skb = tmp, tmp = skb->prev)
#define skb_queue_walk(queue, skb) \
		for (skb = (queue)->next;					\
		     skb != (struct sk_buff *)(queue);				\
		     skb = skb->next)
#define skb_queue_walk_from(queue, skb)						\
		for (; skb != (struct sk_buff *)(queue);			\
		     skb = skb->next)
#define skb_queue_walk_from_safe(queue, skb, tmp)				\
		for (tmp = skb->next;						\
		     skb != (struct sk_buff *)(queue);				\
		     skb = tmp, tmp = skb->next)
#define skb_queue_walk_safe(queue, skb, tmp)					\
		for (skb = (queue)->next, tmp = skb->next;			\
		     skb != (struct sk_buff *)(queue);				\
		     skb = tmp, tmp = skb->next)
#define skb_shinfo(SKB)	((struct skb_shared_info *)(skb_end_pointer(SKB)))
#define skb_walk_frags(skb, iter)	\
	for (iter = skb_shinfo(skb)->frag_list; iter; iter = iter->next)

#define FLOW_KEYS_HASH_START_FIELD basic

#define ETH_P_AF_IUCV   0xFBFB		
#define ETH_P_CUST      0x6006          
#define ETH_P_DDCMP     0x0006          
#define ETH_P_DEC       0x6000          
#define ETH_P_DIAG      0x6005          
#define ETH_P_DNA_DL    0x6001          
#define ETH_P_DNA_RC    0x6002          
#define ETH_P_DNA_RT    0x6003          
#define ETH_P_IEEE802154 0x00F6		
#define ETH_P_LAT       0x6004          
#define ETH_P_LOCALTALK 0x0009		
#define ETH_P_PPP_MP    0x0008          
#define ETH_P_RARP      0x8035		
#define ETH_P_SCA       0x6007          
#define ETH_P_WAN_PPP   0x0007          

#define SPLICE_F_NONBLOCK (0x02) 


#define NETIF_F_ALL_TSO 	(NETIF_F_TSO | NETIF_F_TSO6 | NETIF_F_TSO_ECN)
#define NETIF_F_GSO_TUNNEL_REMCSUM __NETIF_F(GSO_TUNNEL_REMCSUM)
#define NETIF_F_GSO_UDP_TUNNEL_CSUM __NETIF_F(GSO_UDP_TUNNEL_CSUM)
#define NETIF_F_HW_VLAN_CTAG_FILTER __NETIF_F(HW_VLAN_CTAG_FILTER)
#define NETIF_F_HW_VLAN_STAG_FILTER __NETIF_F(HW_VLAN_STAG_FILTER)

#define __NETIF_F(name)		__NETIF_F_BIT(NETIF_F_##name##_BIT)
#define __NETIF_F_BIT(bit)	((netdev_features_t)1 << (bit))
#define for_each_netdev_feature(mask_addr, bit)	\
	for_each_set_bit(bit, (unsigned long *)mask_addr, NETDEV_FEATURE_COUNT)
#define DEFINE_DMA_UNMAP_ADDR(ADDR_NAME)        dma_addr_t ADDR_NAME
#define DEFINE_DMA_UNMAP_LEN(LEN_NAME)          __u32 LEN_NAME
#define DMA_BIT_MASK(n)	(((n) == 64) ? ~0ULL : ((1ULL<<(n))-1))

#define dma_map_sg_attrs(dev, sgl, nents, dir, attrs) \
	dma_map_sg(dev, sgl, nents, dir)
#define dma_map_single_attrs(dev, cpu_addr, size, dir, attrs) \
	dma_map_single(dev, cpu_addr, size, dir)
#define dma_unmap_addr(PTR, ADDR_NAME)           ((PTR)->ADDR_NAME)
#define dma_unmap_addr_set(PTR, ADDR_NAME, VAL)  (((PTR)->ADDR_NAME) = (VAL))
#define dma_unmap_len(PTR, LEN_NAME)             ((PTR)->LEN_NAME)
#define dma_unmap_len_set(PTR, LEN_NAME, VAL)    (((PTR)->LEN_NAME) = (VAL))
#define dma_unmap_sg_attrs(dev, sgl, nents, dir, attrs) \
	dma_unmap_sg(dev, sgl, nents, dir)
#define dma_unmap_single_attrs(dev, dma_addr, size, dir, attrs) \
	dma_unmap_single(dev, dma_addr, size, dir)

#define dma_alloc_noncoherent(d, s, h, f) dma_alloc_coherent(d, s, h, f)
#define dma_free_noncoherent(d, s, v, h) dma_free_coherent(d, s, v, h)
#define dma_sync_sg_for_device dma_sync_sg_for_cpu
#define dma_sync_single_for_device dma_sync_single_for_cpu
#define dma_sync_single_range_for_device dma_sync_single_range_for_cpu

#define for_each_sg(sglist, sg, nr, __i)	\
	for (__i = 0, sg = (sglist); __i < (nr); __i++, sg = sg_next(sg))
#define for_each_sg_page(sglist, piter, nents, pgoffset)		   \
	for (__sg_page_iter_start((piter), (sglist), (nents), (pgoffset)); \
	     __sg_page_iter_next(piter);)
#define sg_chain_ptr(sg)	\
	((struct scatterlist *) ((sg)->page_link & ~0x03))
#define sg_dma_address(sg)	((sg)->dma_address)
#define sg_dma_len(sg)		((sg)->dma_length)
#define sg_is_chain(sg)		((sg)->page_link & 0x01)
#define sg_is_last(sg)		((sg)->page_link & 0x02)

#define DEFINE_DMA_ATTRS(x) 					\
	struct dma_attrs x = {					\
		.flags = { [0 ... __DMA_ATTRS_LONGS-1] = 0 },	\
	}

#define __DMA_ATTRS_LONGS BITS_TO_LONGS(DMA_ATTR_MAX)
#define BUS_ATTR(_name, _mode, _show, _store)	\
	struct bus_attribute bus_attr_##_name = __ATTR(_name, _mode, _show, _store)
#define BUS_ATTR_RO(_name) \
	struct bus_attribute bus_attr_##_name = __ATTR_RO(_name)
#define BUS_ATTR_RW(_name) \
	struct bus_attribute bus_attr_##_name = __ATTR_RW(_name)
#define CLASS_ATTR(_name, _mode, _show, _store) \
	struct class_attribute class_attr_##_name = __ATTR(_name, _mode, _show, _store)
#define CLASS_ATTR_RO(_name) \
	struct class_attribute class_attr_##_name = __ATTR_RO(_name)
#define CLASS_ATTR_RW(_name) \
	struct class_attribute class_attr_##_name = __ATTR_RW(_name)
#define CLASS_ATTR_STRING(_name, _mode, _str) \
	struct class_attribute_string class_attr_##_name = \
		_CLASS_ATTR_STRING(_name, _mode, _str)
#define DEVICE_ATTR(_name, _mode, _show, _store) \
	struct device_attribute dev_attr_##_name = __ATTR(_name, _mode, _show, _store)
#define DEVICE_ATTR_IGNORE_LOCKDEP(_name, _mode, _show, _store) \
	struct device_attribute dev_attr_##_name =		\
		__ATTR_IGNORE_LOCKDEP(_name, _mode, _show, _store)
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
#define DRIVER_ATTR(_name, _mode, _show, _store) \
	struct driver_attribute driver_attr_##_name = __ATTR(_name, _mode, _show, _store)
#define DRIVER_ATTR_RO(_name) \
	struct driver_attribute driver_attr_##_name = __ATTR_RO(_name)
#define DRIVER_ATTR_RW(_name) \
	struct driver_attribute driver_attr_##_name = __ATTR_RW(_name)
#define DRIVER_ATTR_WO(_name) \
	struct driver_attribute driver_attr_##_name = __ATTR_WO(_name)
#define MODULE_ALIAS_CHARDEV(major,minor) \
	MODULE_ALIAS("char-major-" __stringify(major) "-" __stringify(minor))
#define MODULE_ALIAS_CHARDEV_MAJOR(major) \
	MODULE_ALIAS("char-major-" __stringify(major) "-*")
#define _CLASS_ATTR_STRING(_name, _mode, _str) \
	{ __ATTR(_name, _mode, show_class_attr_string, NULL), _str }

#define builtin_driver(__driver, __register, ...) \
static int __init __driver##_init(void) \
{ \
	return __register(&(__driver) , ##__VA_ARGS__); \
} \
device_initcall(__driver##_init);
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
#define dev_alert_once(dev, fmt, ...)					\
	dev_level_once(dev_alert, dev, fmt, ##__VA_ARGS__)
#define dev_alert_ratelimited(dev, fmt, ...)				\
	dev_level_ratelimited(dev_alert, dev, fmt, ##__VA_ARGS__)
#define dev_crit_once(dev, fmt, ...)					\
	dev_level_once(dev_crit, dev, fmt, ##__VA_ARGS__)
#define dev_crit_ratelimited(dev, fmt, ...)				\
	dev_level_ratelimited(dev_crit, dev, fmt, ##__VA_ARGS__)
#define dev_dbg(dev, format, ...)		     \
do {						     \
	dynamic_dev_dbg(dev, format, ##__VA_ARGS__); \
} while (0)
#define dev_dbg_once(dev, fmt, ...)					\
	dev_level_once(dev_dbg, dev, fmt, ##__VA_ARGS__)
#define dev_dbg_ratelimited(dev, fmt, ...)				\
do {									\
	static DEFINE_RATELIMIT_STATE(_rs,				\
				      DEFAULT_RATELIMIT_INTERVAL,	\
				      DEFAULT_RATELIMIT_BURST);		\
	DEFINE_DYNAMIC_DEBUG_METADATA(descriptor, fmt);			\
	if (unlikely(descriptor.flags & _DPRINTK_FLAGS_PRINT) &&	\
	    __ratelimit(&_rs))						\
		__dynamic_dev_dbg(&descriptor, dev, fmt,		\
				  ##__VA_ARGS__);			\
} while (0)
#define dev_emerg_once(dev, fmt, ...)					\
	dev_level_once(dev_emerg, dev, fmt, ##__VA_ARGS__)
#define dev_emerg_ratelimited(dev, fmt, ...)				\
	dev_level_ratelimited(dev_emerg, dev, fmt, ##__VA_ARGS__)
#define dev_err_once(dev, fmt, ...)					\
	dev_level_once(dev_err, dev, fmt, ##__VA_ARGS__)
#define dev_err_ratelimited(dev, fmt, ...)				\
	dev_level_ratelimited(dev_err, dev, fmt, ##__VA_ARGS__)
#define dev_info(dev, fmt, arg...) _dev_info(dev, fmt, ##arg)
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
#define dev_notice_once(dev, fmt, ...)					\
	dev_level_once(dev_notice, dev, fmt, ##__VA_ARGS__)
#define dev_notice_ratelimited(dev, fmt, ...)				\
	dev_level_ratelimited(dev_notice, dev, fmt, ##__VA_ARGS__)
#define dev_vdbg(dev, format, arg...)				\
({								\
	if (0)							\
		dev_printk(KERN_DEBUG, dev, format, ##arg);	\
})
#define dev_warn_once(dev, fmt, ...)					\
	dev_level_once(dev_warn, dev, fmt, ##__VA_ARGS__)
#define dev_warn_ratelimited(dev, fmt, ...)				\
	dev_level_ratelimited(dev_warn, dev, fmt, ##__VA_ARGS__)
#define devres_alloc(release, size, gfp) \
	__devres_alloc_node(release, size, gfp, NUMA_NO_NODE, #release)
#define devres_alloc_node(release, size, gfp, nid) \
	__devres_alloc_node(release, size, gfp, nid, #release)
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
#define root_device_register(name) \
	__root_device_register(name, THIS_MODULE)
#define sysfs_deprecated 0

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
		WARN_ON((condition) && __ratelimit(state))
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

#define __ratelimit(state) ___ratelimit(state, __func__)
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


#define PINCTRL_STATE_DEFAULT "default"
#define PINCTRL_STATE_IDLE "idle"
#define PINCTRL_STATE_INIT "init"
#define PINCTRL_STATE_SLEEP "sleep"
#define SEQ_SKIP 1
#define SEQ_START_TOKEN ((void *)1)

#define seq_show_option_n(m, name, value, length) {	\
	char val_buf[length + 1];			\
	strncpy(val_buf, value, length);		\
	val_buf[length] = '\0';				\
	seq_show_option(m, name, val_buf);		\
}
#define DEFINE_KLIST(_name, _get, _put)					\
	struct klist _name = KLIST_INIT(_name, _get, _put)
#define KLIST_INIT(_name, _get, _put)					\
	{ .k_lock	= __SPIN_LOCK_UNLOCKED(_name.k_lock),		\
	  .k_list	= LIST_HEAD_INIT(_name.k_list),			\
	  .get		= _get,						\
	  .put		= _put, }




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
	.attr	= { .name = __stringify(_name), .mode = S_IRUGO },	\
	.show	= _name##_show,						\
}
#define __ATTR_RW(_name) __ATTR(_name, (S_IWUSR | S_IRUGO),		\
			 _name##_show, _name##_store)
#define __ATTR_WO(_name) {						\
	.attr	= { .name = __stringify(_name), .mode = S_IWUSR },	\
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
	.attr	= { .name = __stringify(_name), .mode = S_IRUGO },	\
	.read	= _name##_read,						\
	.size	= _size,						\
}
#define __BIN_ATTR_RW(_name, _size) __BIN_ATTR(_name,			\
				   (S_IWUSR | S_IRUGO), _name##_read,	\
				   _name##_write, _size)
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
	}
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

#define TS_PRIV_ALIGN(len) (((len) + TS_PRIV_ALIGNTO-1) & ~(TS_PRIV_ALIGNTO-1))

#define ASSERT_RTNL() do { \
	if (unlikely(!rtnl_is_locked())) { \
		printk(KERN_ERR "RTNL: assertion failed at %s (%d)\n", \
		       "__FILE__",  "__LINE__"); \
		dump_stack(); \
	} \
} while(0)

#define rcu_dereference_bh_rtnl(p)				\
	rcu_dereference_bh_check(p, lockdep_rtnl_is_held())
#define rcu_dereference_rtnl(p)					\
	rcu_dereference_check(p, lockdep_rtnl_is_held())
#define rtnl_dereference(p)					\
	rcu_dereference_protected(p, lockdep_rtnl_is_held())
#define RTAX_ADVMSS RTAX_ADVMSS
#define RTAX_CC_ALGO RTAX_CC_ALGO
#define RTAX_CWND RTAX_CWND
#define RTAX_FEATURES RTAX_FEATURES
#define RTAX_HOPLIMIT RTAX_HOPLIMIT
#define RTAX_INITCWND RTAX_INITCWND
#define RTAX_INITRWND RTAX_INITRWND
#define RTAX_LOCK RTAX_LOCK
#define RTAX_MAX (__RTAX_MAX - 1)
#define RTAX_MTU RTAX_MTU
#define RTAX_QUICKACK RTAX_QUICKACK
#define RTAX_REORDERING RTAX_REORDERING
#define RTAX_RTO_MIN RTAX_RTO_MIN
#define RTAX_RTT RTAX_RTT
#define RTAX_RTTVAR RTAX_RTTVAR
#define RTAX_SSTHRESH RTAX_SSTHRESH
#define RTAX_UNSPEC RTAX_UNSPEC
#define RTAX_WINDOW RTAX_WINDOW
#define RTA_ALIGN(len) ( ((len)+RTA_ALIGNTO-1) & ~(RTA_ALIGNTO-1) )
#define RTA_DATA(rta)   ((void*)(((char*)(rta)) + RTA_LENGTH(0)))
#define RTA_LENGTH(len)	(RTA_ALIGN(sizeof(struct rtattr)) + (len))
#define RTA_MAX (__RTA_MAX - 1)
#define RTA_NEXT(rta,attrlen)	((attrlen) -= RTA_ALIGN((rta)->rta_len), \
				 (struct rtattr*)(((char*)(rta)) + RTA_ALIGN((rta)->rta_len)))
#define RTA_OK(rta,len) ((len) >= (int)sizeof(struct rtattr) && \
			 (rta)->rta_len >= sizeof(struct rtattr) && \
			 (rta)->rta_len <= (len))
#define RTA_PAYLOAD(rta) ((int)((rta)->rta_len) - RTA_LENGTH(0))
#define RTA_SPACE(len)	RTA_ALIGN(RTA_LENGTH(len))
#define RTMGRP_DECnet_IFADDR    0x1000
#define RTMGRP_DECnet_ROUTE     0x4000
#define RTM_DELACTION   RTM_DELACTION
#define RTM_DELADDRLABEL RTM_DELADDRLABEL
#define RTM_DELMDB RTM_DELMDB
#define RTM_DELNSID RTM_DELNSID
#define RTM_FAM(cmd)	(((cmd) - RTM_BASE) >> 2)
#define RTM_GETACTION   RTM_GETACTION
#define RTM_GETADDRLABEL RTM_GETADDRLABEL
#define RTM_GETDCB RTM_GETDCB
#define RTM_GETMDB RTM_GETMDB
#define RTM_GETMULTICAST RTM_GETMULTICAST
#define RTM_GETNETCONF RTM_GETNETCONF
#define RTM_GETNSID RTM_GETNSID
#define RTM_NEWACTION   RTM_NEWACTION
#define RTM_NEWADDRLABEL RTM_NEWADDRLABEL
#define RTM_NEWMDB RTM_NEWMDB
#define RTM_NEWNDUSEROPT RTM_NEWNDUSEROPT
#define RTM_NEWNETCONF RTM_NEWNETCONF
#define RTM_NEWNSID RTM_NEWNSID
#define RTM_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct rtmsg))
#define RTM_RTA(r)  ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct rtmsg))))
#define RTM_SETDCB RTM_SETDCB
#define RTNETLINK_HAVE_PEERINFO 1
#define RTNH_ALIGN(len) ( ((len)+RTNH_ALIGNTO-1) & ~(RTNH_ALIGNTO-1) )
#define RTNH_DATA(rtnh)   ((struct rtattr*)(((char*)(rtnh)) + RTNH_LENGTH(0)))
#define RTNH_LENGTH(len) (RTNH_ALIGN(sizeof(struct rtnexthop)) + (len))
#define RTNH_NEXT(rtnh)	((struct rtnexthop*)(((char*)(rtnh)) + RTNH_ALIGN((rtnh)->rtnh_len)))
#define RTNH_OK(rtnh,len) ((rtnh)->rtnh_len >= sizeof(struct rtnexthop) && \
			   ((int)(rtnh)->rtnh_len) <= (len))
#define RTNH_SPACE(len)	RTNH_ALIGN(RTNH_LENGTH(len))
#define RTN_MAX (__RTN_MAX - 1)
#define TA_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct tcamsg))
#define TA_RTA(r)  ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct tcamsg))))
#define TCAA_MAX 1
#define TCA_ACT_TAB 1 	
#define TCA_MAX (__TCA_MAX - 1)
#define TCA_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct tcmsg))
#define TCA_RTA(r)  ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct tcmsg))))


#define IFLA_BRPORT_MAX (__IFLA_BRPORT_MAX - 1)
#define IFLA_COST IFLA_COST
#define IFLA_HSR_MAX (__IFLA_HSR_MAX - 1)
#define IFLA_INET_MAX (__IFLA_INET_MAX - 1)
#define IFLA_IPOIB_MAX (__IFLA_IPOIB_MAX - 1)
#define IFLA_IPVLAN_MAX (__IFLA_IPVLAN_MAX - 1)
#define IFLA_LINKINFO IFLA_LINKINFO
#define IFLA_MACVLAN_MAX (__IFLA_MACVLAN_MAX - 1)
#define IFLA_MAP IFLA_MAP
#define IFLA_MASTER IFLA_MASTER
#define IFLA_MAX (__IFLA_MAX - 1)
#define IFLA_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct ifinfomsg))
#define IFLA_PORT_MAX (__IFLA_PORT_MAX - 1)
#define IFLA_PRIORITY IFLA_PRIORITY
#define IFLA_PROMISCUITY IFLA_PROMISCUITY
#define IFLA_PROTINFO IFLA_PROTINFO
#define IFLA_RTA(r)  ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ifinfomsg))))
#define IFLA_TXQLEN IFLA_TXQLEN
#define IFLA_VF_INFO_MAX (__IFLA_VF_INFO_MAX - 1)
#define IFLA_VF_MAX (__IFLA_VF_MAX - 1)
#define IFLA_VF_PORT_MAX (__IFLA_VF_PORT_MAX - 1)
#define IFLA_VF_STATS_MAX (__IFLA_VF_STATS_MAX - 1)
#define IFLA_VRF_MAX (__IFLA_VRF_MAX - 1)
#define IFLA_WEIGHT IFLA_WEIGHT
#define IFLA_WIRELESS IFLA_WIRELESS

#define HARD_TX_LOCK(dev, txq, cpu) {			\
	if ((dev->features & NETIF_F_LLTX) == 0) {	\
		__netif_tx_lock(txq, cpu);		\
	}						\
}
#define HARD_TX_TRYLOCK(dev, txq)			\
	(((dev->features & NETIF_F_LLTX) == 0) ?	\
		__netif_tx_trylock(txq) :		\
		true )
#define HARD_TX_UNLOCK(dev, txq) {			\
	if ((dev->features & NETIF_F_LLTX) == 0) {	\
		__netif_tx_unlock(txq);			\
	}						\
}
#define HH_DATA_ALIGN(__len) \
	(((__len)+(HH_DATA_MOD-1))&~(HH_DATA_MOD - 1))
#define HH_DATA_OFF(__len) \
	(HH_DATA_MOD - (((__len - 1) & (HH_DATA_MOD - 1)) + 1))
#  define LL_MAX_HEADER 128
#define LL_RESERVED_SPACE(dev) \
	((((dev)->hard_header_len+(dev)->needed_headroom)&~(HH_DATA_MOD - 1)) + HH_DATA_MOD)
#define LL_RESERVED_SPACE_EXTRA(dev,extra) \
	((((dev)->hard_header_len+(dev)->needed_headroom+(extra))&~(HH_DATA_MOD - 1)) + HH_DATA_MOD)
#define MAX_HEADER LL_MAX_HEADER
#define MAX_PHYS_ITEM_ID_LEN 32
#define MODULE_ALIAS_NETDEV(device) \
	MODULE_ALIAS("netdev-" device)
#define NAPI_GRO_CB(skb) ((struct napi_gro_cb *)(skb)->cb)
#define NAPI_GRO_FREE_STOLEN_HEAD 2
#define NAPI_POLL_WEIGHT 64
#define NETDEV_BONDING_FAILOVER 0x000C
#define NETDEV_BOOT_SETUP_MAX 8
#define NETDEV_FCOE_WWNN 0
#define NETDEV_FCOE_WWPN 1
#define NETDEV_REGISTER 0x0005
#define NETDEV_RSS_KEY_LEN 52
#define NETDEV_UNREGISTER_FINAL 0x0011
#define QUEUE_STATE_ANY_XOFF_OR_FROZEN (QUEUE_STATE_ANY_XOFF | \
					QUEUE_STATE_FROZEN)
#define QUEUE_STATE_DRV_XOFF_OR_FROZEN (QUEUE_STATE_DRV_XOFF | \
					QUEUE_STATE_FROZEN)
#define RPS_DEV_FLOW_TABLE_SIZE(_num) (sizeof(struct rps_dev_flow_table) + \
    ((_num) * sizeof(struct rps_dev_flow)))
#define RPS_MAP_SIZE(_num) (sizeof(struct rps_map) + ((_num) * sizeof(u16)))
#define RPS_NO_CPU 0xffff
#define RPS_NO_FILTER 0xffff
#define SET_NETDEV_DEV(net, pdev)	((net)->dev.parent = (pdev))
#define SET_NETDEV_DEVTYPE(net, devtype)	((net)->dev.type = (devtype))
#define XPS_DEV_MAPS_SIZE (sizeof(struct xps_dev_maps) +		\
    (nr_cpu_ids * sizeof(struct xps_map *)))
#define XPS_MAP_SIZE(_num) (sizeof(struct xps_map) + ((_num) * sizeof(u16)))
#define XPS_MIN_MAP_ALLOC ((L1_CACHE_ALIGN(offsetof(struct xps_map, queues[1])) \
       - sizeof(struct xps_map)) / sizeof(u16))

#define __netdev_alloc_pcpu_stats(type, gfp)				\
({									\
	typeof(type) __percpu *pcpu_stats = alloc_percpu_gfp(type, gfp);\
	if (pcpu_stats)	{						\
		int __cpu;						\
		for_each_possible_cpu(__cpu) {				\
			typeof(type) *stat;				\
			stat = per_cpu_ptr(pcpu_stats, __cpu);		\
			u64_stats_init(&stat->syncp);			\
		}							\
	}								\
	pcpu_stats;							\
})
#define __skb_gro_checksum_validate(skb, proto, zero_okay, check,	\
				    compute_pseudo)			\
({									\
	__sum16 __ret = 0;						\
	if (__skb_gro_checksum_validate_needed(skb, zero_okay, check))	\
		__ret = __skb_gro_checksum_validate_complete(skb,	\
				compute_pseudo(skb, proto));		\
	if (__ret)							\
		__skb_mark_checksum_bad(skb);				\
	else								\
		skb_gro_incr_csum_unnecessary(skb);			\
	__ret;								\
})
#define alloc_netdev(sizeof_priv, name, name_assign_type, setup) \
	alloc_netdev_mqs(sizeof_priv, name, name_assign_type, setup, 1, 1)
#define alloc_netdev_mq(sizeof_priv, name, name_assign_type, setup, count) \
	alloc_netdev_mqs(sizeof_priv, name, name_assign_type, setup, count, \
			 count)
#define dev_proc_init() 0
#define for_each_dev_addr(dev, ha) \
		list_for_each_entry_rcu(ha, &dev->dev_addrs.list, list)
#define for_each_netdev(net, d)		\
		list_for_each_entry(d, &(net)->dev_base_head, dev_list)
#define for_each_netdev_continue(net, d)		\
		list_for_each_entry_continue(d, &(net)->dev_base_head, dev_list)
#define for_each_netdev_continue_rcu(net, d)		\
	list_for_each_entry_continue_rcu(d, &(net)->dev_base_head, dev_list)
#define for_each_netdev_in_bond_rcu(bond, slave)	\
		for_each_netdev_rcu(&init_net, slave)	\
			if (netdev_master_upper_dev_get_rcu(slave) == (bond))
#define for_each_netdev_rcu(net, d)		\
		list_for_each_entry_rcu(d, &(net)->dev_base_head, dev_list)
#define for_each_netdev_reverse(net, d)	\
		list_for_each_entry_reverse(d, &(net)->dev_base_head, dev_list)
#define for_each_netdev_safe(net, d, n)	\
		list_for_each_entry_safe(d, n, &(net)->dev_base_head, dev_list)
# define napi_synchronize(n)	barrier()
#define net_device_entry(lh)	list_entry(lh, struct net_device, dev_list)
#define net_xmit_errno(e)	((e) != NET_XMIT_CN ? -ENOBUFS : 0)
#define net_xmit_eval(e)	((e) == NET_XMIT_CN ? 0 : (e))
#define netdev_WARN(dev, format, args...)			\
	WARN(1, "netdevice: %s%s\n" format, netdev_name(dev),	\
	     netdev_reg_state(dev), ##args)
#define netdev_alloc_pcpu_stats(type)					\
	__netdev_alloc_pcpu_stats(type, GFP_KERNEL)
#define netdev_dbg(__dev, format, args...)			\
do {								\
	dynamic_netdev_dbg(__dev, format, ##args);		\
} while (0)
#define netdev_for_each_all_upper_dev_rcu(dev, updev, iter) \
	for (iter = &(dev)->all_adj_list.upper, \
	     updev = netdev_all_upper_get_next_dev_rcu(dev, &(iter)); \
	     updev; \
	     updev = netdev_all_upper_get_next_dev_rcu(dev, &(iter)))
#define netdev_for_each_lower_dev(dev, ldev, iter) \
	for (iter = &(dev)->adj_list.lower, \
	     ldev = netdev_lower_get_next(dev, &(iter)); \
	     ldev; \
	     ldev = netdev_lower_get_next(dev, &(iter)))
#define netdev_for_each_lower_private(dev, priv, iter) \
	for (iter = (dev)->adj_list.lower.next, \
	     priv = netdev_lower_get_next_private(dev, &(iter)); \
	     priv; \
	     priv = netdev_lower_get_next_private(dev, &(iter)))
#define netdev_for_each_lower_private_rcu(dev, priv, iter) \
	for (iter = &(dev)->adj_list.lower, \
	     priv = netdev_lower_get_next_private_rcu(dev, &(iter)); \
	     priv; \
	     priv = netdev_lower_get_next_private_rcu(dev, &(iter)))
#define netdev_for_each_mc_addr(ha, dev) \
	netdev_hw_addr_list_for_each(ha, &(dev)->mc)
#define netdev_for_each_uc_addr(ha, dev) \
	netdev_hw_addr_list_for_each(ha, &(dev)->uc)
#define netdev_for_each_upper_dev_rcu(dev, updev, iter) \
	for (iter = &(dev)->adj_list.upper, \
	     updev = netdev_upper_get_next_dev_rcu(dev, &(iter)); \
	     updev; \
	     updev = netdev_upper_get_next_dev_rcu(dev, &(iter)))
#define netdev_hw_addr_list_count(l) ((l)->count)
#define netdev_hw_addr_list_empty(l) (netdev_hw_addr_list_count(l) == 0)
#define netdev_hw_addr_list_for_each(ha, l) \
	list_for_each_entry(ha, &(l)->list, list)
#define netdev_mc_count(dev) netdev_hw_addr_list_count(&(dev)->mc)
#define netdev_mc_empty(dev) netdev_hw_addr_list_empty(&(dev)->mc)
#define netdev_uc_count(dev) netdev_hw_addr_list_count(&(dev)->uc)
#define netdev_uc_empty(dev) netdev_hw_addr_list_empty(&(dev)->uc)
#define netdev_vdbg(dev, format, args...)			\
({								\
	if (0)							\
		netdev_printk(KERN_DEBUG, dev, format, ##args);	\
	0;							\
})
#define netif_alert(priv, type, dev, fmt, args...)		\
	netif_level(alert, priv, type, dev, fmt, ##args)
#define netif_crit(priv, type, dev, fmt, args...)		\
	netif_level(crit, priv, type, dev, fmt, ##args)
#define netif_dbg(priv, type, netdev, format, args...)		\
do {								\
	if (netif_msg_##type(priv))				\
		dynamic_netdev_dbg(netdev, format, ##args);	\
} while (0)
#define netif_emerg(priv, type, dev, fmt, args...)		\
	netif_level(emerg, priv, type, dev, fmt, ##args)
#define netif_err(priv, type, dev, fmt, args...)		\
	netif_level(err, priv, type, dev, fmt, ##args)
#define netif_info(priv, type, dev, fmt, args...)		\
	netif_level(info, priv, type, dev, fmt, ##args)
#define netif_level(level, priv, type, dev, fmt, args...)	\
do {								\
	if (netif_msg_##type(priv))				\
		netdev_##level(dev, fmt, ##args);		\
} while (0)
#define netif_msg_drv(p)	((p)->msg_enable & NETIF_MSG_DRV)
#define netif_msg_hw(p)		((p)->msg_enable & NETIF_MSG_HW)
#define netif_msg_ifdown(p)	((p)->msg_enable & NETIF_MSG_IFDOWN)
#define netif_msg_ifup(p)	((p)->msg_enable & NETIF_MSG_IFUP)
#define netif_msg_intr(p)	((p)->msg_enable & NETIF_MSG_INTR)
#define netif_msg_link(p)	((p)->msg_enable & NETIF_MSG_LINK)
#define netif_msg_pktdata(p)	((p)->msg_enable & NETIF_MSG_PKTDATA)
#define netif_msg_probe(p)	((p)->msg_enable & NETIF_MSG_PROBE)
#define netif_msg_rx_err(p)	((p)->msg_enable & NETIF_MSG_RX_ERR)
#define netif_msg_rx_status(p)	((p)->msg_enable & NETIF_MSG_RX_STATUS)
#define netif_msg_timer(p)	((p)->msg_enable & NETIF_MSG_TIMER)
#define netif_msg_tx_done(p)	((p)->msg_enable & NETIF_MSG_TX_DONE)
#define netif_msg_tx_err(p)	((p)->msg_enable & NETIF_MSG_TX_ERR)
#define netif_msg_tx_queued(p)	((p)->msg_enable & NETIF_MSG_TX_QUEUED)
#define netif_msg_wol(p)	((p)->msg_enable & NETIF_MSG_WOL)
#define netif_notice(priv, type, dev, fmt, args...)		\
	netif_level(notice, priv, type, dev, fmt, ##args)
#define netif_printk(priv, type, level, dev, fmt, args...)	\
do {					  			\
	if (netif_msg_##type(priv))				\
		netdev_printk(level, (dev), fmt, ##args);	\
} while (0)
#define netif_vdbg(priv, type, dev, format, args...)		\
({								\
	if (0)							\
		netif_printk(priv, type, KERN_DEBUG, dev, format, ##args); \
	0;							\
})
#define netif_warn(priv, type, dev, fmt, args...)		\
	netif_level(warn, priv, type, dev, fmt, ##args)
#define skb_gro_checksum_simple_validate(skb)				\
	__skb_gro_checksum_validate(skb, 0, false, 0, null_compute_pseudo)
#define skb_gro_checksum_try_convert(skb, proto, check, compute_pseudo)	\
do {									\
	if (__skb_gro_checksum_convert_check(skb))			\
		__skb_gro_checksum_convert(skb, check,			\
					   compute_pseudo(skb, proto));	\
} while (0)
#define skb_gro_checksum_validate(skb, proto, compute_pseudo)		\
	__skb_gro_checksum_validate(skb, proto, false, 0, compute_pseudo)
#define skb_gro_checksum_validate_zero_check(skb, proto, check,		\
					     compute_pseudo)		\
	__skb_gro_checksum_validate(skb, proto, true, check, compute_pseudo)
#define to_net_dev(d) container_of(d, struct net_device, dev)
#define BOND_ABI_VERSION 2
#define BOND_DEFAULT_MAX_BONDS  1   
#define BOND_DEFAULT_TX_QUEUES 16   
#define BOND_LINK_BACK  3           
#define BOND_LINK_DOWN  2           
#define BOND_LINK_FAIL  1           
#define BOND_LINK_UP    0           
#define BOND_MODE_8023AD        4
#define BOND_MODE_TLB           5
#define BOND_STATE_ACTIVE       0   
#define BOND_STATE_BACKUP       1   






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
	} while (0)



#define SUBSYS(_x) extern struct cgroup_subsys _x ## _cgrp_subsys;

#define cgroup_subsys_enabled(ss)						\
	static_branch_likely(&ss ## _enabled_key)
#define cgroup_subsys_on_dfl(ss)						\
	static_branch_likely(&ss ## _on_dfl_key)
#define cgroup_taskset_for_each(task, tset)				\
	for ((task) = cgroup_taskset_first((tset)); (task);		\
	     (task) = cgroup_taskset_next((tset)))
#define cgroup_taskset_for_each_leader(leader, tset)			\
	for ((leader) = cgroup_taskset_first((tset)); (leader);		\
	     (leader) = cgroup_taskset_next((tset)))			\
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
#define ACC_MODE(x) ("\004\002\006\006"[(x)&O_ACCMODE])
#define ACL_NOT_CACHED ((void *)(-1))
#define CHECK_IOVEC_ONLY -1
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
#define FLOCK_VERIFY_READ  1
#define FLOCK_VERIFY_WRITE 2
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
#define IS_DIRSYNC(inode)	(__IS_FLG(inode, MS_SYNCHRONOUS|MS_DIRSYNC) || \
					((inode)->i_flags & (S_SYNC|S_DIRSYNC)))
#define IS_IMA(inode)		((inode)->i_flags & S_IMA)
#define IS_IMMUTABLE(inode)	((inode)->i_flags & S_IMMUTABLE)
#define IS_I_VERSION(inode)	__IS_FLG(inode, MS_I_VERSION)
#define IS_MANDLOCK(inode)	__IS_FLG(inode, MS_MANDLOCK)
#define IS_NOATIME(inode)	__IS_FLG(inode, MS_RDONLY|MS_NOATIME)
#define IS_NOCMTIME(inode)	((inode)->i_flags & S_NOCMTIME)
#define IS_NOQUOTA(inode)	((inode)->i_flags & S_NOQUOTA)
#define IS_NOSEC(inode)		((inode)->i_flags & S_NOSEC)
#define IS_POSIXACL(inode)	__IS_FLG(inode, MS_POSIXACL)
#define IS_PRIVATE(inode)	((inode)->i_flags & S_PRIVATE)
#define IS_RDONLY(inode)	((inode)->i_sb->s_flags & MS_RDONLY)
#define IS_SWAPFILE(inode)	((inode)->i_flags & S_SWAPFILE)
#define IS_SYNC(inode)		(__IS_FLG(inode, MS_SYNCHRONOUS) || \
					((inode)->i_flags & S_SYNC))
#define IS_WHITEOUT(inode)	(S_ISCHR(inode->i_mode) && \
				 (inode)->i_rdev == WHITEOUT_DEV)
#define I_DIRTY (I_DIRTY_SYNC | I_DIRTY_DATASYNC | I_DIRTY_PAGES)
#define I_DIRTY_ALL (I_DIRTY | I_DIRTY_TIME)
#define MAX_LFS_FILESIZE 	((loff_t)0x7fffffffffffffffLL)
#define MAX_RW_COUNT (INT_MAX & PAGE_CACHE_MASK)
#define MODULE_ALIAS_FS(NAME) MODULE_ALIAS("fs-" NAME)
#define NOMMU_VMFLAGS \
	(NOMMU_MAP_READ | NOMMU_MAP_WRITE | NOMMU_MAP_EXEC)
#define OPEN_FMODE(flag) ((__force fmode_t)(((flag + 1) & O_ACCMODE) | \
					    (flag & __FMODE_NONOTIFY)))
#define SB_FREEZE_LEVELS (SB_FREEZE_COMPLETE - 1)
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
#define bio_data_dir(bio)	((bio)->bi_rw & 1)
#define bio_rw(bio)		((bio)->bi_rw & (RW_MASK | RWA_MASK))
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
#define NR_FILE  8192	

#define BIO_NULL_MAPPED 5	
#define BIO_POOL_IDX(bio)	((bio)->bi_flags >> BIO_POOL_OFFSET)
#define BIO_USER_MAPPED 4	
#define REQ_COMMON_MASK \
	(REQ_WRITE | REQ_FAILFAST_MASK | REQ_SYNC | REQ_META | REQ_PRIO | \
	 REQ_DISCARD | REQ_WRITE_SAME | REQ_NOIDLE | REQ_FLUSH | REQ_FUA | \
	 REQ_SECURE | REQ_INTEGRITY)
#define REQ_FAILFAST_MASK \
	(REQ_FAILFAST_DEV | REQ_FAILFAST_TRANSPORT | REQ_FAILFAST_DRIVER)
#define REQ_NOMERGE_FLAGS \
	(REQ_NOMERGE | REQ_STARTED | REQ_SOFTBARRIER | REQ_FLUSH | REQ_FUA | REQ_FLUSH_SEQ)



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
#define DEFINE_SEMAPHORE(name)	\
	struct semaphore name = __SEMAPHORE_INITIALIZER(name, 1)

#define __SEMAPHORE_INITIALIZER(name, n)				\
{									\
	.lock		= __RAW_SPIN_LOCK_UNLOCKED((name).lock),	\
	.count		= n,						\
	.wait_list	= LIST_HEAD_INIT((name).wait_list),		\
}
#define INIT_RADIX_TREE(root, mask)					\
do {									\
	(root)->height = 0;						\
	(root)->gfp_mask = (mask);					\
	(root)->rnode = NULL;						\
} while (0)
#define RADIX_TREE(name, mask) \
	struct radix_tree_root name = RADIX_TREE_INIT(mask)
#define RADIX_TREE_INDEX_BITS  (8  * sizeof(unsigned long))
#define RADIX_TREE_INIT(mask)	{					\
	.height = 0,							\
	.gfp_mask = (mask),						\
	.rnode = NULL,							\
}
#define RADIX_TREE_MAX_PATH (DIV_ROUND_UP(RADIX_TREE_INDEX_BITS, \
					  RADIX_TREE_MAP_SHIFT))
#define RADIX_TREE_MAX_TAGS 3

#define radix_tree_for_each_chunk(slot, root, iter, start, flags)	\
	for (slot = radix_tree_iter_init(iter, start) ;			\
	      (slot = radix_tree_next_chunk(root, iter, flags)) ;)
#define radix_tree_for_each_chunk_slot(slot, iter, flags)		\
	for (; slot ; slot = radix_tree_next_slot(slot, iter, flags))
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
				RADIX_TREE_ITER_TAGGED))

#define list_lru_init(lru)		__list_lru_init((lru), false, NULL)
#define list_lru_init_key(lru, key)	__list_lru_init((lru), false, (key))
#define list_lru_init_memcg(lru)	__list_lru_init((lru), true, NULL)

#define DCACHE_MANAGED_DENTRY \
	(DCACHE_MOUNTED|DCACHE_NEED_AUTOMOUNT|DCACHE_MANAGE_TRANSIT)
#  define DNAME_INLINE_LEN 36 
 #define HASH_LEN_DECLARE u32 hash; u32 len;
#define IS_ROOT(x) ((x) == (x)->d_parent)
#define QSTR_INIT(n,l) { { { .len = l } }, .name = n }

 #define bytemask_from_count(cnt)	(~(~0ul << (cnt)*8))
#define hashlen_create(hash,len) (((u64)(len)<<32)|(u32)(hash))
#define hashlen_hash(hashlen) ((u32) (hashlen))
#define hashlen_len(hashlen)  ((u32)((hashlen) >> 32))
#define init_name_hash()		0
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




#define __ETH_RSS_HASH(name)	__ETH_RSS_HASH_BIT(ETH_RSS_HASH_##name##_BIT)
#define __ETH_RSS_HASH_BIT(bit)	((u32)1 << (bit))
#define ETHTOOL_F_COMPAT        (1 << ETHTOOL_F_COMPAT__BIT)
#define ETHTOOL_F_UNSUPPORTED   (1 << ETHTOOL_F_UNSUPPORTED__BIT)
#define ETHTOOL_F_WISH          (1 << ETHTOOL_F_WISH__BIT)
#define ETHTOOL_RX_FLOW_SPEC_RING_VF_OFF 32
#define ETH_FW_DUMP_DISABLE 0

#define BITS_PER_COMPAT_LONG    (8*sizeof(compat_long_t))
#define BITS_TO_COMPAT_LONGS(bits) \
	(((bits)+BITS_PER_COMPAT_LONG-1)/BITS_PER_COMPAT_LONG)
#define COMPAT_SYSCALL_DEFINE0(name) \
	asmlinkage long compat_sys_##name(void)
#define COMPAT_SYSCALL_DEFINE1(name, ...) \
        COMPAT_SYSCALL_DEFINEx(1, _##name, __VA_ARGS__)
#define COMPAT_SYSCALL_DEFINE2(name, ...) \
	COMPAT_SYSCALL_DEFINEx(2, _##name, __VA_ARGS__)
#define COMPAT_SYSCALL_DEFINE3(name, ...) \
	COMPAT_SYSCALL_DEFINEx(3, _##name, __VA_ARGS__)
#define COMPAT_SYSCALL_DEFINE4(name, ...) \
	COMPAT_SYSCALL_DEFINEx(4, _##name, __VA_ARGS__)
#define COMPAT_SYSCALL_DEFINE5(name, ...) \
	COMPAT_SYSCALL_DEFINEx(5, _##name, __VA_ARGS__)
#define COMPAT_SYSCALL_DEFINE6(name, ...) \
	COMPAT_SYSCALL_DEFINEx(6, _##name, __VA_ARGS__)
#define COMPAT_SYSCALL_DEFINEx(x, name, ...)				\
	asmlinkage long compat_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__))\
		__attribute__((alias(__stringify(compat_SyS##name))));  \
	static inline long C_SYSC##name(__MAP(x,__SC_DECL,__VA_ARGS__));\
	asmlinkage long compat_SyS##name(__MAP(x,__SC_LONG,__VA_ARGS__));\
	asmlinkage long compat_SyS##name(__MAP(x,__SC_LONG,__VA_ARGS__))\
	{								\
		return C_SYSC##name(__MAP(x,__SC_DELOUSE,__VA_ARGS__));	\
	}								\
	static inline long C_SYSC##name(__MAP(x,__SC_DECL,__VA_ARGS__))
#define COMPAT_USE_64BIT_TIME 0

#define __SC_DELOUSE(t,v) ((t)(unsigned long)(v))
#define compat_jiffies_to_clock_t(x)	\
		(((unsigned long)(x) * COMPAT_USER_HZ) / HZ)
#define compat_save_altstack_ex(uss, sp) do { \
	compat_stack_t __user *__uss = uss; \
	struct task_struct *t = current; \
	put_user_ex(ptr_to_compat((void __user *)t->sas_ss_sp), &__uss->ss_sp); \
	put_user_ex(sas_ss_flags(sp), &__uss->ss_flags); \
	put_user_ex(t->sas_ss_size, &__uss->ss_size); \
} while (0);
#define compat_user_stack_pointer() current_user_stack_pointer()
#define is_compat_task() (0)

#define MII_ADDR_C45 (1<<30)
#define PHY_ANY_ID "MATCH ANY PHY"
#define PHY_ANY_UID 0xffffffff
#define PHY_ID_FMT "%s:%02x"

#define mdiobus_register(bus) __mdiobus_register(bus, THIS_MODULE)
#define module_phy_driver(__phy_drivers)				\
	phy_module_driver(__phy_drivers, ARRAY_SIZE(__phy_drivers))
#define phy_module_driver(__phy_drivers, __count)			\
static int __init phy_module_init(void)					\
{									\
	return phy_drivers_register(__phy_drivers, __count);		\
}									\
module_init(phy_module_init);						\
static void __exit phy_module_exit(void)				\
{									\
	phy_drivers_unregister(__phy_drivers, __count);			\
}									\
module_exit(phy_module_exit)
#define to_mii_bus(d) container_of(d, struct mii_bus, dev)
#define to_phy_device(d) container_of(d, struct phy_device, dev)
#define to_phy_driver(d) container_of(d, struct phy_driver, driver)
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

#define UUID_BE(a, b, c, d0, d1, d2, d3, d4, d5, d6, d7)		\
((uuid_be)								\
{{ ((a) >> 24) & 0xff, ((a) >> 16) & 0xff, ((a) >> 8) & 0xff, (a) & 0xff, \
   ((b) >> 8) & 0xff, (b) & 0xff,					\
   ((c) >> 8) & 0xff, (c) & 0xff,					\
   (d0), (d1), (d2), (d3), (d4), (d5), (d6), (d7) }})
#define UUID_LE(a, b, c, d0, d1, d2, d3, d4, d5, d6, d7)		\
((uuid_le)								\
{{ (a) & 0xff, ((a) >> 8) & 0xff, ((a) >> 16) & 0xff, ((a) >> 24) & 0xff, \
   (b) & 0xff, ((b) >> 8) & 0xff,					\
   (c) & 0xff, ((c) >> 8) & 0xff,					\
   (d0), (d1), (d2), (d3), (d4), (d5), (d6), (d7) }})

#define MODULE_ALIAS(_alias) MODULE_INFO(alias, _alias)
#define MODULE_ARCH_INIT {}
#define MODULE_AUTHOR(_author) MODULE_INFO(author, _author)
#define MODULE_DESCRIPTION(_description) MODULE_INFO(description, _description)
#define MODULE_DEVICE_TABLE(type, name)					\
extern const typeof(name) __mod_##type##__##name##_device_table		\
  __attribute__ ((unused, alias(__stringify(name))))
#define MODULE_FIRMWARE(_firmware) MODULE_INFO(firmware, _firmware)
#define MODULE_INFO(tag, info) __MODULE_INFO(tag, tag, info)
#define MODULE_LICENSE(_license) MODULE_INFO(license, _license)
#define MODULE_NAME_LEN MAX_PARAM_PREFIX_LEN
#define MODULE_SIG_STRING "~Module signature appended~\n"
#define MODULE_SOFTDEP(_softdep) MODULE_INFO(softdep, _softdep)

#define MODULE_VERSION(_version) MODULE_INFO(version, _version)

#define __INITDATA_OR_MODULE __INITDATA
#define __INITRODATA_OR_MODULE __INITRODATA
#define __INIT_OR_MODULE __INIT
#define __MODULE_STRING(x) __stringify(x)
#define __init_or_module __init
#define __initconst_or_module __initconst
#define __initdata_or_module __initdata
#define module_exit(exitfn)					\
	static inline exitcall_t __exittest(void)		\
	{ return exitfn; }					\
	void cleanup_module(void) __attribute__((alias(#exitfn)));
#define module_init(initfn)					\
	static inline initcall_t __inittest(void)		\
	{ return initfn; }					\
	int init_module(void) __attribute__((alias(#initfn)));
#define module_name(mod)			\
({						\
	struct module *__mod = (mod);		\
	__mod ? __mod->name : "kernel";		\
})
#define module_put_and_exit(code) __module_put_and_exit(THIS_MODULE, code)
#define symbol_get(x) ((typeof(&x))(__symbol_get(VMLINUX_SYMBOL_STR(x))))
#define symbol_put(x) __symbol_put(VMLINUX_SYMBOL_STR(x))
#define symbol_put_addr(p) do { } while (0)
#define symbol_request(x) try_then_request_module(symbol_get(x), "symbol:" #x)

#define MAX_PARAM_PREFIX_LEN (64 - sizeof(unsigned long))
#define MODULE_PARAM_PREFIX 
#define MODULE_PARM_DESC(_parm, desc) \
	__MODULE_INFO(parm, _parm, #_parm ":" desc)

#define __MODULE_INFO(tag, name, info)					  \
static const char __UNIQUE_ID(name)[]					  \
  __used __attribute__((section(".modinfo"), unused, aligned(1)))	  \
  = __stringify(tag) "=" info
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
#define module_param_call(name, set, get, arg, perm)			\
	static const struct kernel_param_ops __param_ops_##name =		\
		{ .flags = 0, (void *)set, (void *)get };		\
	__module_param_call(MODULE_PARAM_PREFIX,			\
			    name, &__param_ops_##name, arg,		\
			    (perm) + sizeof(__check_old_set_param(set))*0, -1, 0)
#define module_param_cb(name, ops, arg, perm)				      \
	__module_param_call(MODULE_PARAM_PREFIX, name, ops, arg, perm, -1, 0)
#define module_param_cb_unsafe(name, ops, arg, perm)			      \
	__module_param_call(MODULE_PARAM_PREFIX, name, ops, arg, perm, -1,    \
			    KERNEL_PARAM_FL_UNSAFE)
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


#define MAX_PHANDLE_ARGS 16
#define OF_DECLARE_1(table, name, compat, fn) \
		_OF_DECLARE(table, name, compat, fn, of_init_fn_1)
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
#define of_match_node(_matches, _node)	NULL
#define of_match_ptr(_ptr)	(_ptr)
#define of_node_cmp(s1, s2)		strcasecmp((s1), (s2))
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

#define device_for_each_child_node(dev, child) \
	for (child = device_get_next_child_node(dev, NULL); child; \
	     child = device_get_next_child_node(dev, child))

#define NETDEV_HASHBITS    8
#define NETDEV_HASHENTRIES (1 << NETDEV_HASHBITS)





#define for_each_net(VAR)				\
	list_for_each_entry(VAR, &net_namespace_list, list)
#define for_each_net_rcu(VAR)				\
	list_for_each_entry_rcu(VAR, &net_namespace_list, list)


#define net_drop_ns NULL





#define DECLARE_TASKLET(name, func, data) \
struct tasklet_struct name = { NULL, 0, ATOMIC_INIT(0), func, data }
#define DECLARE_TASKLET_DISABLED(name, func, data) \
struct tasklet_struct name = { NULL, 0, ATOMIC_INIT(1), func, data }
#define SOFTIRQ_STOP_IDLE_MASK (~(1 << RCU_SOFTIRQ))

#define hard_irq_disable()	do { } while(0)
# define local_irq_enable_in_hardirq()	do { } while (0)
#define or_softirq_pending(x)  (local_softirq_pending() |= (x))
#define set_softirq_pending(x) (local_softirq_pending() = (x))
#define tasklet_trylock(t) 1
#define tasklet_unlock(t) do { } while (0)
#define tasklet_unlock_wait(t) do { } while (0)
#define IRQ_RETVAL(x)	((x) ? IRQ_HANDLED : IRQ_NONE)





#define IP_CT_EXP_CHALLENGE_ACK 		0x40

#define INIT_HLIST_NULLS_HEAD(ptr, nulls) \
	((ptr)->first = (struct hlist_nulls_node *) NULLS_MARKER(nulls))
#define NULLS_MARKER(value) (1UL | (((long)value) << 1))

#define hlist_nulls_entry(ptr, type, member) container_of(ptr,type,member)
#define hlist_nulls_for_each_entry(tpos, pos, head, member)		       \
	for (pos = (head)->first;					       \
	     (!is_a_nulls(pos)) &&					       \
		({ tpos = hlist_nulls_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = pos->next)
#define hlist_nulls_for_each_entry_from(tpos, pos, member)	\
	for (; (!is_a_nulls(pos)) && 				\
		({ tpos = hlist_nulls_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = pos->next)

#define NF_MAX_HOOKS 8

#define NFC_ALTERED 0x8000
#define NFC_UNKNOWN 0x4000
#define NF_ACCEPT 1
#define NF_DROP 0
#define NF_DROP_ERR(x) (((-x) << 16) | NF_DROP)
#define NF_MAX_VERDICT NF_STOP
#define NF_QUEUE 3
#define NF_QUEUE_NR(x) ((((x) << 16) & NF_VERDICT_QMASK) | NF_QUEUE)
#define NF_REPEAT 4
#define NF_STOLEN 2
#define NF_STOP 5
#define NF_VERDICT_BITS 16
#define NF_VERDICT_MASK 0x000000ff
#define NF_VERDICT_QBITS 16
#define NF_VERDICT_QMASK 0xffff0000


#define GROUP_FILTER_SIZE(numsrc) \
	(sizeof(struct group_filter) - sizeof(struct __kernel_sockaddr_storage) \
	+ (numsrc) * sizeof(struct __kernel_sockaddr_storage))
#define INADDR_ALLHOSTS_GROUP 	0xe0000001U	
#define INADDR_ALLRTRS_GROUP    0xe0000002U	
#define INADDR_MAX_LOCAL_GROUP  0xe00000ffU	
#define INADDR_UNSPEC_GROUP   	0xe0000000U	
#define IP_DEFAULT_MULTICAST_LOOP       1
#define IP_DEFAULT_MULTICAST_TTL        1
#define IP_MINTTL       21
#define IP_MSFILTER_SIZE(numsrc) \
	(sizeof(struct ip_msfilter) - sizeof(__u32) \
	+ (numsrc) * sizeof(__u32))
#define IP_MULTICAST_LOOP 		34
#define IP_MULTICAST_TTL 		33
#define IP_NODEFRAG     22
#define IP_ORIGDSTADDR       20
#define IP_RECVORIGDSTADDR   IP_ORIGDSTADDR











#define DECLARE_SNMP_STAT(type, name)	\
	extern __typeof__(type) __percpu *name
#define DEFINE_SNMP_STAT(type, name)	\
	__typeof__(type) __percpu *name
#define DEFINE_SNMP_STAT_ATOMIC(type, name)	\
	__typeof__(type) *name
#define ICMP6MSG_MIB_MAX  __ICMP6MSG_MIB_MAX
#define SNMP_ADD_STATS(mib, field, addend)	\
			this_cpu_add(mib->mibs[field], addend)
#define SNMP_ADD_STATS64(mib, field, addend)				\
		SNMP_ADD_STATS64_USER(mib, field, addend)
#define SNMP_ADD_STATS64_BH(mib, field, addend) 			\
	do {								\
		__typeof__(*mib) *ptr = raw_cpu_ptr(mib);		\
		u64_stats_update_begin(&ptr->syncp);			\
		ptr->mibs[field] += addend;				\
		u64_stats_update_end(&ptr->syncp);			\
	} while (0)
#define SNMP_ADD_STATS64_USER(mib, field, addend) 			\
	do {								\
		local_bh_disable();					\
		SNMP_ADD_STATS64_BH(mib, field, addend);		\
		local_bh_enable();					\
	} while (0)
#define SNMP_ADD_STATS_BH(mib, field, addend)	\
			__this_cpu_add(mib->mibs[field], addend)
#define SNMP_ADD_STATS_USER(mib, field, addend)	\
			this_cpu_add(mib->mibs[field], addend)
#define SNMP_DEC_STATS(mib, field)	\
			this_cpu_dec(mib->mibs[field])
#define SNMP_DEC_STATS64(mib, field)		SNMP_DEC_STATS(mib, field)
#define SNMP_INC_STATS(mib, field)	\
			this_cpu_inc(mib->mibs[field])
#define SNMP_INC_STATS64(mib, field) SNMP_ADD_STATS64(mib, field, 1)
#define SNMP_INC_STATS64_BH(mib, field) SNMP_ADD_STATS64_BH(mib, field, 1)
#define SNMP_INC_STATS64_USER(mib, field) SNMP_ADD_STATS64_USER(mib, field, 1)
#define SNMP_INC_STATS_ATOMIC_LONG(mib, field)	\
			atomic_long_inc(&mib->mibs[field])
#define SNMP_INC_STATS_BH(mib, field)	\
			__this_cpu_inc(mib->mibs[field])
#define SNMP_INC_STATS_USER(mib, field)	\
			this_cpu_inc(mib->mibs[field])
#define SNMP_MIB_ITEM(_name,_entry)	{	\
	.name = _name,				\
	.entry = _entry,			\
}
#define SNMP_MIB_SENTINEL {	\
	.name = NULL,		\
	.entry = 0,		\
}
#define SNMP_UPD_PO_STATS(mib, basefield, addend)	\
	do { \
		__typeof__((mib->mibs) + 0) ptr = mib->mibs;	\
		this_cpu_inc(ptr[basefield##PKTS]);		\
		this_cpu_add(ptr[basefield##OCTETS], addend);	\
	} while (0)
#define SNMP_UPD_PO_STATS64(mib, basefield, addend)			\
	do {								\
		local_bh_disable();					\
		SNMP_UPD_PO_STATS64_BH(mib, basefield, addend);		\
		local_bh_enable();					\
	} while (0)
#define SNMP_UPD_PO_STATS64_BH(mib, basefield, addend)			\
	do {								\
		__typeof__(*mib) *ptr;				\
		ptr = raw_cpu_ptr((mib));				\
		u64_stats_update_begin(&ptr->syncp);			\
		ptr->mibs[basefield##PKTS]++;				\
		ptr->mibs[basefield##OCTETS] += addend;			\
		u64_stats_update_end(&ptr->syncp);			\
	} while (0)
#define SNMP_UPD_PO_STATS_BH(mib, basefield, addend)	\
	do { \
		__typeof__((mib->mibs) + 0) ptr = mib->mibs;	\
		__this_cpu_inc(ptr[basefield##PKTS]);		\
		__this_cpu_add(ptr[basefield##OCTETS], addend);	\
	} while (0)



#define DQL_MAX_LIMIT ((UINT_MAX / 2) - DQL_MAX_OBJECT)
#define DQL_MAX_OBJECT (UINT_MAX / 16)


#define async_dma_find_channel(type) dma_find_channel(DMA_ASYNC_TX)
#define async_dmaengine_get()	dmaengine_get()
#define async_dmaengine_put()	dmaengine_put()
#define dma_cap_clear(tx, mask) __dma_cap_clear((tx), &(mask))
#define dma_cap_set(tx, mask) __dma_cap_set((tx), &(mask))
#define dma_cap_zero(mask) __dma_cap_zero(&(mask))
#define dma_has_cap(tx, mask) __dma_has_cap((tx), &(mask))
#define dma_request_channel(mask, x, y) __dma_request_channel(&(mask), x, y)
#define dma_request_slave_channel_compat(mask, x, y, dev, name) \
	__dma_request_slave_channel_compat(&(mask), x, y, dev, name)
#define for_each_dma_cap_mask(cap, mask) \
	for_each_set_bit(cap, mask.bits, DMA_TX_TYPE_END)
#define PREFETCH_STRIDE (4*L1_CACHE_BYTES)

#define prefetch(x) __builtin_prefetch(x)
#define prefetchw(x) __builtin_prefetch(x,1)
#define spin_lock_prefetch(x) prefetchw(x)

#define mdelay(n) (\
	(__builtin_constant_p(n) && (n)<=MAX_UDELAY_MS) ? udelay((n)*1000) : \
	({unsigned long __ms=(n); while (__ms--) udelay(1000);}))
#define ndelay(x) ndelay(x)
#define DEFAULT_POLLMASK (POLLIN | POLLOUT | POLLRDNORM | POLLWRNORM)
#define FDS_BYTES(nr)	(FDS_LONGS(nr)*sizeof(long))
#define FDS_LONGS(nr)	(((nr)+FDS_BITPERLONG-1)/FDS_BITPERLONG)
#define MAX_INT64_SECONDS (((s64)(~((u64)0)>>1)/HZ)-1)
#define MAX_STACK_ALLOC 832


#define hlist_nulls_first_rcu(head) \
	(*((struct hlist_nulls_node __rcu __force **)&(head)->first))
#define hlist_nulls_for_each_entry_rcu(tpos, pos, head, member)			\
	for (({barrier();}),							\
	     pos = rcu_dereference_raw(hlist_nulls_first_rcu(head));		\
		(!is_a_nulls(pos)) &&						\
		({ tpos = hlist_nulls_entry(pos, typeof(*tpos), member); 1; }); \
		pos = rcu_dereference_raw(hlist_nulls_next_rcu(pos)))
#define hlist_nulls_next_rcu(node) \
	(*((struct hlist_nulls_node __rcu __force **)&(node)->next))
#define BPF_ALU32_IMM(OP, DST, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_OP(OP) | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })
#define BPF_ALU32_REG(OP, DST, SRC)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_OP(OP) | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })
#define BPF_ALU64_IMM(OP, DST, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_OP(OP) | BPF_K,	\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })
#define BPF_ALU64_REG(OP, DST, SRC)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_OP(OP) | BPF_X,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })
#define BPF_ANCILLARY(CODE)	case SKF_AD_OFF + SKF_AD_##CODE:	\
				return BPF_ANC | SKF_AD_##CODE
#define BPF_EMIT_CALL(FUNC)					\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_CALL,			\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = ((FUNC) - __bpf_call_base) })
#define BPF_ENDIAN(TYPE, DST, LEN)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_END | BPF_SRC(TYPE),	\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = LEN })
#define BPF_EXIT_INSN()						\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_EXIT,			\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = 0 })
#define BPF_JMP_IMM(OP, DST, IMM, OFF)				\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_OP(OP) | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = OFF,					\
		.imm   = IMM })
#define BPF_JMP_REG(OP, DST, SRC, OFF)				\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_OP(OP) | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })
#define BPF_LDX_MEM(SIZE, DST, SRC, OFF)			\
	((struct bpf_insn) {					\
		.code  = BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })
#define BPF_LD_ABS(SIZE, IMM)					\
	((struct bpf_insn) {					\
		.code  = BPF_LD | BPF_SIZE(SIZE) | BPF_ABS,	\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })
#define BPF_LD_IMM64(DST, IMM)					\
	BPF_LD_IMM64_RAW(DST, 0, IMM)
#define BPF_LD_IMM64_RAW(DST, SRC, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_LD | BPF_DW | BPF_IMM,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = (__u32) (IMM) }),			\
	((struct bpf_insn) {					\
		.code  = 0, 	\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = ((__u64) (IMM)) >> 32 })
#define BPF_LD_IND(SIZE, SRC, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_LD | BPF_SIZE(SIZE) | BPF_IND,	\
		.dst_reg = 0,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = IMM })
#define BPF_LD_MAP_FD(DST, MAP_FD)				\
	BPF_LD_IMM64_RAW(DST, BPF_PSEUDO_MAP_FD, MAP_FD)
#define BPF_MOV32_IMM(DST, IMM)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_MOV | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })
#define BPF_MOV32_RAW(TYPE, DST, SRC, IMM)			\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_MOV | BPF_SRC(TYPE),	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = IMM })
#define BPF_MOV32_REG(DST, SRC)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_MOV | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })
#define BPF_MOV64_IMM(DST, IMM)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_MOV | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })
#define BPF_MOV64_RAW(TYPE, DST, SRC, IMM)			\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_MOV | BPF_SRC(TYPE),	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = IMM })
#define BPF_MOV64_REG(DST, SRC)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_MOV | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })
#define BPF_PROG_RUN(filter, ctx)  (*filter->bpf_func)(ctx, filter->insnsi)
#define BPF_RAW_INSN(CODE, DST, SRC, OFF, IMM)			\
	((struct bpf_insn) {					\
		.code  = CODE,					\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = IMM })
#define BPF_STX_MEM(SIZE, DST, SRC, OFF)			\
	((struct bpf_insn) {					\
		.code  = BPF_STX | BPF_SIZE(SIZE) | BPF_MEM,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })
#define BPF_STX_XADD(SIZE, DST, SRC, OFF)			\
	((struct bpf_insn) {					\
		.code  = BPF_STX | BPF_SIZE(SIZE) | BPF_XADD,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })
#define BPF_ST_MEM(SIZE, DST, OFF, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_ST | BPF_SIZE(SIZE) | BPF_MEM,	\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = OFF,					\
		.imm   = IMM })
#define __BPF_JUMP(CODE, K, JT, JF)				\
	((struct sock_filter) BPF_JUMP(CODE, K, JT, JF))
#define __BPF_STMT(CODE, K)					\
	((struct sock_filter) BPF_STMT(CODE, K))

#define bpf_classic_proglen(fprog) (fprog->len * sizeof(fprog->filter[0]))
#define bytes_to_bpf_size(bytes)				\
({								\
	int bpf_size = -EINVAL;					\
								\
	if (bytes == sizeof(u8))				\
		bpf_size = BPF_B;				\
	else if (bytes == sizeof(u16))				\
		bpf_size = BPF_H;				\
	else if (bytes == sizeof(u32))				\
		bpf_size = BPF_W;				\
	else if (bytes == sizeof(u64))				\
		bpf_size = BPF_DW;				\
								\
	bpf_size;						\
})

#define         BPF_A           0x10
#define BPF_JUMP(code, k, jt, jf) { (unsigned short)(code), jt, jf, k }
#define BPF_MAJOR_VERSION 1
#define BPF_MEMWORDS 16
#define BPF_MINOR_VERSION 1
#define BPF_MISCOP(code) ((code) & 0xf8)
#define BPF_RVAL(code)  ((code) & 0x18)
#define BPF_STMT(code, k) { (unsigned short)(code), 0, 0, k }
#define         BPF_TAX         0x00
#define         BPF_TXA         0x80
#define SKF_AD_IFINDEX 	8
#define SKF_AD_MARK 	20
#define SKF_AD_OFF    (-0x1000)
#define SKF_AD_PKTTYPE 	4
#define SKF_AD_PROTOCOL 0
#define SKF_AD_VLAN_TAG_PRESENT 48

#define QDISC_CB_PRIV_LEN 20

#define net_xmit_drop_count(e)	((e) & __NET_XMIT_STOLEN ? 0 : 1)
#define tcf_tree_lock(tp)	sch_tree_lock((tp)->q)
#define tcf_tree_unlock(tp)	sch_tree_unlock((tp)->q)


#define for_each_memcg_cache_index(_idx)	\
	for ((_idx) = 0; (_idx) < memcg_nr_cache_ids; (_idx)++)

#define BIOVEC_NR_POOLS 6
#define BIOVEC_PHYS_MERGEABLE(vec1, vec2)	\
	__BIOVEC_PHYS_MERGEABLE(vec1, vec2)
#define BIOVEC_SEG_BOUNDARY(q, b1, b2) \
	__BIO_SEG_BOUNDARY(bvec_to_phys((b1)), bvec_to_phys((b2)) + (b2)->bv_len, queue_segment_boundary((q)))


#define BIO_POOL_SIZE 2
#define BIO_SPLIT_ENTRIES 2
#define __BIOVEC_PHYS_MERGEABLE(vec1, vec2)	\
	((bvec_to_phys((vec1)) + (vec1)->bv_len) == bvec_to_phys((vec2)))
#define __BIO_SEG_BOUNDARY(addr1, addr2, mask) \
	(((addr1) | (mask)) == (((addr2) - 1) | (mask)))

#define __bio_for_each_segment(bvl, bio, iter, start)			\
	for (iter = (start);						\
	     (iter).bi_size &&						\
		((bvl = bio_iter_iovec((bio), (iter))), 1);		\
	     bio_advance_iter((bio), &(iter), (bvl).bv_len))
#define __bio_kmap_atomic(bio, iter)				\
	(kmap_atomic(bio_iter_iovec((bio), (iter)).bv_page) +	\
		bio_iter_iovec((bio), (iter)).bv_offset)
#define __bio_kunmap_atomic(addr)	kunmap_atomic(addr)
#define __bio_kunmap_irq(buf, flags)	bvec_kunmap_irq(buf, flags)
#define __bvec_iter_bvec(bvec, iter)	(&(bvec)[(iter).bi_idx])
#define bio_end_sector(bio)	((bio)->bi_iter.bi_sector + bio_sectors((bio)))
#define bio_for_each_integrity_vec(_bvl, _bio, _iter)			\
	for_each_bio(_bio)						\
		bip_for_each_vec(_bvl, _bio->bi_integrity, _iter)
#define bio_for_each_segment(bvl, bio, iter)				\
	__bio_for_each_segment(bvl, bio, iter, (bio)->bi_iter)
#define bio_for_each_segment_all(bvl, bio, i)				\
	for (i = 0, bvl = (bio)->bi_io_vec; i < (bio)->bi_vcnt; i++, bvl++)
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
#define bio_kmap_irq(bio, flags) \
	__bio_kmap_irq((bio), (bio)->bi_iter, (flags))
#define bio_kunmap_irq(buf,flags)	__bio_kunmap_irq(buf, flags)
#define bio_list_for_each(bio, bl) \
	for (bio = (bl)->head; bio; bio = bio->bi_next)
#define bio_multiple_segments(bio)				\
	((bio)->bi_iter.bi_size != bio_iovec(bio).bv_len)
#define bio_offset(bio)		bio_iter_offset((bio), (bio)->bi_iter)
#define bio_page(bio)		bio_iter_page((bio), (bio)->bi_iter)
#define bio_prio(bio)	((bio)->bi_rw >> BIO_PRIO_SHIFT)
#define bio_prio_valid(bio)	ioprio_valid(bio_prio(bio))
#define bio_sectors(bio)	((bio)->bi_iter.bi_size >> 9)
#define bio_set_prio(bio, prio)		do {			\
	WARN_ON(prio >= (1 << IOPRIO_BITS));			\
	(bio)->bi_rw &= ((1UL << BIO_PRIO_SHIFT) - 1);		\
	(bio)->bi_rw |= ((unsigned long) (prio) << BIO_PRIO_SHIFT);	\
} while (0)
#define bio_to_phys(bio)	(page_to_phys(bio_page((bio))) + (unsigned long) bio_offset((bio)))
#define bip_for_each_vec(bvl, bip, iter)				\
	for_each_bvec(bvl, (bip)->bip_vec, iter, (bip)->bip_iter)
#define bvec_iter_bvec(bvec, iter)				\
((struct bio_vec) {						\
	.bv_page	= bvec_iter_page((bvec), (iter)),	\
	.bv_len		= bvec_iter_len((bvec), (iter)),	\
	.bv_offset	= bvec_iter_offset((bvec), (iter)),	\
})
#define bvec_iter_len(bvec, iter)				\
	min((iter).bi_size,					\
	    __bvec_iter_bvec((bvec), (iter))->bv_len - (iter).bi_bvec_done)
#define bvec_iter_offset(bvec, iter)				\
	(__bvec_iter_bvec((bvec), (iter))->bv_offset + (iter).bi_bvec_done)
#define bvec_iter_page(bvec, iter)				\
	(__bvec_iter_bvec((bvec), (iter))->bv_page)
#define bvec_to_phys(bv)	(page_to_phys((bv)->bv_page) + (unsigned long) (bv)->bv_offset)
#define for_each_bvec(bvl, bio_vec, iter, start)			\
	for (iter = (start);						\
	     (iter).bi_size &&						\
		((bvl = bvec_iter_bvec((bio_vec), (iter))), 1);	\
	     bvec_iter_advance((bio_vec), &(iter), (bvl).bv_len))

#define IOPRIO_PRIO_CLASS(mask)	((mask) >> IOPRIO_CLASS_SHIFT)
#define IOPRIO_PRIO_DATA(mask)	((mask) & IOPRIO_PRIO_MASK)
#define IOPRIO_PRIO_VALUE(class, data)	(((class) << IOPRIO_CLASS_SHIFT) | data)
#define ioprio_valid(mask)	(IOPRIO_PRIO_CLASS((mask)) != IOPRIO_CLASS_NONE)



#define kmap_atomic_pfn(pfn)	kmap_atomic(pfn_to_page(pfn))
#define kmap_atomic_prot(page, prot)	kmap_atomic(page)
#define kmap_flush_unused()	do {} while(0)
#define kunmap_atomic(addr)                                     \
do {                                                            \
	BUILD_BUG_ON(__same_type((addr), struct page *));       \
	__kunmap_atomic(addr);                                  \
} while (0)
#define totalhigh_pages 0UL

#define faulthandler_disabled() (pagefault_disabled() || in_atomic())
#define pagefault_disabled() (current->pagefault_disabled != 0)
#define probe_kernel_address(addr, retval)		\
	probe_kernel_read(&retval, addr, sizeof(retval))
#define WB_STAT_BATCH (8*(1+ilog2(nr_cpu_ids)))

#define FPROP_FRAC_BASE (1UL << FPROP_FRAC_SHIFT)
#define FPROP_FRAC_SHIFT 10
#define INIT_FPROP_LOCAL_SINGLE(name)			\
{	.lock = __RAW_SPIN_LOCK_UNLOCKED(name.lock),	\
}

#define EFD_CLOEXEC O_CLOEXEC
#define EFD_FLAGS_SET (EFD_SHARED_FCNTL_FLAGS | EFD_SEMAPHORE)
#define EFD_NONBLOCK O_NONBLOCK
#define EFD_SEMAPHORE (1 << 0)
#define EFD_SHARED_FCNTL_FLAGS (O_CLOEXEC | O_NONBLOCK)


#define PAGE_COUNTER_MAX LONG_MAX



#define MODULE_ALIAS_XFRM_MODE(family, encap) \
	MODULE_ALIAS("xfrm-mode-" __stringify(family) "-" __stringify(encap))
#define MODULE_ALIAS_XFRM_TYPE(family, proto) \
	MODULE_ALIAS("xfrm-type-" __stringify(family) "-" __stringify(proto))
#define XFRM_ALIGN4(len)	(((len) + 3) & ~3)
#define XFRM_ALIGN8(len)	(((len) + 7) & ~7)
#define XFRM_INC_STATS(net, field)	SNMP_INC_STATS((net)->mib.xfrm_statistics, field)
#define XFRM_INC_STATS_BH(net, field)	SNMP_INC_STATS_BH((net)->mib.xfrm_statistics, field)
#define XFRM_INC_STATS_USER(net, field)	SNMP_INC_STATS_USER((net)-mib.xfrm_statistics, field)
#define XFRM_KM_TIMEOUT                30
#define XFRM_MODE_SKB_CB(__skb) ((struct xfrm_mode_skb_cb *)&((__skb)->cb[0]))
#define XFRM_SKB_CB(__skb) ((struct xfrm_skb_cb *)&((__skb)->cb[0]))
#define XFRM_SOFT_EXPIRE 2
#define XFRM_SPI_SKB_CB(__skb) ((struct xfrm_spi_skb_cb *)&((__skb)->cb[0]))
#define XFRM_TUNNEL_SKB_CB(__skb) ((struct xfrm_tunnel_skb_cb *)&((__skb)->cb[0]))

#define FIB6_SUBTREE(fn)	NULL
#define FIB6_TABLE_HASHSZ 256

#define INETPEER_MAXKEYSZ   (sizeof(struct in6_addr) / sizeof(u32))

#define ICMP6MSGIN_INC_STATS_BH(net, idev, field)	\
	_DEVINC_ATOMIC_ATOMIC(net, icmpv6msg, idev, field)
#define ICMP6MSGOUT_INC_STATS(net, idev, field)		\
	_DEVINC_ATOMIC_ATOMIC(net, icmpv6msg, idev, field +256)
#define ICMP6MSGOUT_INC_STATS_BH(net, idev, field)	\
	_DEVINC_ATOMIC_ATOMIC(net, icmpv6msg, idev, field +256)
#define ICMP6_INC_STATS(net, idev, field)	\
		_DEVINCATOMIC(net, icmpv6, , idev, field)
#define ICMP6_INC_STATS_BH(net, idev, field)	\
		_DEVINCATOMIC(net, icmpv6, _BH, idev, field)
#define IP6_ADD_STATS(net, idev,field,val)	\
		_DEVADD(net, ipv6, 64, idev, field, val)
#define IP6_ADD_STATS_BH(net, idev,field,val)	\
		_DEVADD(net, ipv6, 64_BH, idev, field, val)
#define IP6_INC_STATS(net, idev,field)		\
		_DEVINC(net, ipv6, 64, idev, field)
#define IP6_INC_STATS_BH(net, idev,field)	\
		_DEVINC(net, ipv6, 64_BH, idev, field)
#define IP6_REPLY_MARK(net, mark) \
	((net)->ipv6.sysctl.fwmark_reflect ? (mark) : 0)
#define IP6_UPD_PO_STATS(net, idev,field,val)   \
		_DEVUPD(net, ipv6, 64, idev, field, val)
#define IP6_UPD_PO_STATS_BH(net, idev,field,val)   \
		_DEVUPD(net, ipv6, 64_BH, idev, field, val)
#define IPV6_ADDR_MC_FLAG_PREFIX(a)	\
	((a)->s6_addr[1] & 0x20)
#define IPV6_ADDR_MC_FLAG_RENDEZVOUS(a)	\
	((a)->s6_addr[1] & 0x40)
#define IPV6_ADDR_MC_FLAG_TRANSIENT(a)	\
	((a)->s6_addr[1] & 0x10)
#define IPV6_ADDR_MC_SCOPE(a)	\
	((a)->s6_addr[1] & 0x0f)	
#define IPV6_ADDR_MULTICAST    	0x0002U	
#define IPV6_ADDR_UNICAST      	0x0001U	
#define IPV6_DEFAULT_HOPLIMIT   64
#define IPV6_TCLASS_MASK (IPV6_FLOWINFO_MASK & ~IPV6_FLOWLABEL_MASK)
#define _DEVADD(net, statname, modifier, idev, field, val)		\
({									\
	struct inet6_dev *_idev = (idev);				\
	if (likely(_idev != NULL))					\
		SNMP_ADD_STATS##modifier((_idev)->stats.statname, (field), (val)); \
	SNMP_ADD_STATS##modifier((net)->mib.statname##_statistics, (field), (val));\
})
#define _DEVINC(net, statname, modifier, idev, field)			\
({									\
	struct inet6_dev *_idev = (idev);				\
	if (likely(_idev != NULL))					\
		SNMP_INC_STATS##modifier((_idev)->stats.statname, (field)); \
	SNMP_INC_STATS##modifier((net)->mib.statname##_statistics, (field));\
})
#define _DEVINCATOMIC(net, statname, modifier, idev, field)		\
({									\
	struct inet6_dev *_idev = (idev);				\
	if (likely(_idev != NULL))					\
		SNMP_INC_STATS_ATOMIC_LONG((_idev)->stats.statname##dev, (field)); \
	SNMP_INC_STATS##modifier((net)->mib.statname##_statistics, (field));\
})
#define _DEVINC_ATOMIC_ATOMIC(net, statname, idev, field)		\
({									\
	struct inet6_dev *_idev = (idev);				\
	if (likely(_idev != NULL))					\
		SNMP_INC_STATS_ATOMIC_LONG((_idev)->stats.statname##dev, (field)); \
	SNMP_INC_STATS_ATOMIC_LONG((net)->mib.statname##_statistics, (field));\
})
#define _DEVUPD(net, statname, modifier, idev, field, val)		\
({									\
	struct inet6_dev *_idev = (idev);				\
	if (likely(_idev != NULL))					\
		SNMP_UPD_PO_STATS##modifier((_idev)->stats.statname, field, (val)); \
	SNMP_UPD_PO_STATS##modifier((net)->mib.statname##_statistics, field, (val));\
})

#define NDISC_OPT_SPACE(len) (((len)+2+7)&~7)

#define GOLDEN_RATIO_PRIME GOLDEN_RATIO_PRIME_32
#define GOLDEN_RATIO_PRIME_32 0x9e370001UL
#define GOLDEN_RATIO_PRIME_64 0x9e37fffffffc0001UL

#define hash_long(val, bits) hash_32(val, bits)

#define ARPHRD_BIF      775             
#define ARPHRD_DDCMP    517		
#define ARPHRD_ETHER 	1		
#define ARPHRD_IEEE80211 801		
#define ARPHRD_IEEE80211_PRISM 802	
#define ARPHRD_IEEE80211_RADIOTAP 803	
#define ARPHRD_IEEE802154_MONITOR 805	
#define ARPHRD_IEEE802_TR 800		
#define ARPHRD_INFINIBAND 32		
#define ARPHRD_IRDA 	783		
#define ARPHRD_LOCALTLK 773		
#define ARPHRD_PHONET_PIPE 821		
#define ATF_NETMASK     0x20            


#define ICMPV6_MGM_REDUCTION    	132
#define ICMPV6_MGM_REPORT       	131
#define MLD2_ALL_MCR_INIT { { { 0xff,0x02,0,0,0,0,0,0,0,0,0,0,0,0,0,0x16 } } }

#define IP6_SFLSIZE(count)	(sizeof(struct ip6_sf_socklist) + \
	(count) * sizeof(struct in6_addr))

#define IP6CB(skb)	((struct inet6_skb_parm*)((skb)->cb))
#define IP6CBMTU(skb)	((struct ip6_mtuinfo *)((skb)->cb))
#define IP6SKB_FRAGMENTED      16
#define IP6SKB_HOPBYHOP        32

#define __ipv6_only_sock(sk)	(sk->sk_ipv6only)
#define inet6_rcv_saddr(__sk)	NULL
#define inet_v6_ipv6only(__sk)		0
#define ipv6_authlen(p) (((p)->hdrlen+2) << 2)
#define ipv6_only_sock(sk)	(__ipv6_only_sock(sk))
#define ipv6_optlen(p)  (((p)->hdrlen+1) << 3)
#define ipv6_sk_rxinfo(sk)	((sk)->sk_family == PF_INET6 && \
				 inet6_sk(sk)->rxopt.bits.rxinfo)
#define tcp_twsk_ipv6only(__sk)		0




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

#define IS_UDPLITE(__sk) (udp_sk(__sk)->pcflag)
#define UDPLITE_BIT      0x1  		
#define UDPLITE_RECV_CC  0x4		
#define UDPLITE_SEND_CC  0x2  		

#define udp_portaddr_for_each_entry(__sk, node, list) \
	hlist_nulls_for_each_entry(__sk, node, list, __sk_common.skc_portaddr_node)
#define udp_portaddr_for_each_entry_rcu(__sk, node, list) \
	hlist_nulls_for_each_entry_rcu(__sk, node, list, __sk_common.skc_portaddr_node)
#define UDP_NO_CHECK6_RX 102	
#define UDP_NO_CHECK6_TX 101	

#define TCP_DSACK_SEEN    (1 << 2)   
#define TCP_FACK_ENABLED  (1 << 1)   
#define TCP_FASTOPEN_COOKIE_SIZE 8	
#define TCP_NUM_SACKS 4
#define TCP_SACK_SEEN     (1 << 0)   

#define tw_rcv_nxt tw_sk.__tw_common.skc_tw_rcv_nxt
#define tw_snd_nxt tw_sk.__tw_common.skc_tw_snd_nxt
#define TCPF_CA_Disorder (1<<TCP_CA_Disorder)
#define TCPF_CA_Recovery (1<<TCP_CA_Recovery)
#define TCP_THIN_DUPACK         17      
#define TCP_THIN_LINEAR_TIMEOUTS 16      

#define tcp_flag_word(tp) ( ((union tcp_word_hdr *)(tp))->words [3]) 

#define tw_daddr        	__tw_common.skc_daddr
#define tw_rcv_saddr    	__tw_common.skc_rcv_saddr
#define tw_tclass tw_tos
#define tw_v6_rcv_saddr    	__tw_common.skc_v6_rcv_saddr

#define ICSK_CA_PRIV_SIZE      (8 * sizeof(u64))
#define ICSK_TIME_EARLY_RETRANS 4	
#define INET_CSK_DEBUG 1


#define ipv6_destopt_hdr ipv6_opt_hdr
#define ipv6_hopopt_hdr  ipv6_opt_hdr
#define IPV6_DECODE_PREF(pref)	((pref) ^ 2)	
#define IPV6_EXTRACT_PREF(flag)	(((flag) & RTF_PREF_MASK) >> 27)

#define RTF_PREF(pref)	((pref) << 27)

#define RT_CONN_FLAGS(sk)   (RT_TOS(inet_sk(sk)->tos) | sock_flag(sk, SOCK_LOCALROUTE))
#define RT_CONN_FLAGS_TOS(sk,tos)   (RT_TOS(tos) | sock_flag(sk, SOCK_LOCALROUTE))


#define IPOPT_EOL IPOPT_END
#define IPOPT_MINOFF 4
#define IPOPT_NOP IPOPT_NOOP
#define IPOPT_OFFSET 2
#define IPOPT_OLEN   1
#define IPOPT_OPTVAL 0
#define IPOPT_TS  IPOPT_TIMESTAMP
#define IPTOS_PREC(tos)		((tos)&IPTOS_PREC_MASK)
#define IPTOS_PREC_CRITIC_ECP           0xa0
#define IPTOS_PREC_FLASH                0x60
#define IPTOS_PREC_FLASHOVERRIDE        0x80
#define IPTOS_PREC_IMMEDIATE            0x40
#define IPTOS_PREC_INTERNETCONTROL      0xc0
#define IPTOS_PREC_NETCONTROL           0xe0
#define IPTOS_PREC_PRIORITY             0x20
#define IPTOS_PREC_ROUTINE              0x00
#define IPTOS_TOS(tos)		((tos)&IPTOS_TOS_MASK)
#define IPV4_BEET_PHMAXLEN 8
#define IPV4_DEVCONF_MAX (__IPV4_DEVCONF_MAX - 1)
#define MAX_IPOPTLEN 40

#define FIB_RES_DEV(res)		(FIB_RES_NH(res).nh_dev)
#define FIB_RES_GW(res)			(FIB_RES_NH(res).nh_gw)
#define FIB_RES_NH(res)		((res).fi->fib_nh[(res).nh_sel])
#define FIB_RES_OIF(res)		(FIB_RES_NH(res).nh_oif)
#define FIB_RES_PREFSRC(net, res)	((res).fi->fib_prefsrc ? : \
					 FIB_RES_SADDR(net, res))
#define FIB_RES_SADDR(net, res)				\
	((FIB_RES_NH(res).nh_saddr_genid ==		\
	  atomic_read(&(net)->ipv4.dev_addr_genid)) ?	\
	 FIB_RES_NH(res).nh_saddr :			\
	 fib_info_update_nh_saddr((net), &FIB_RES_NH(res)))
#define FIB_TABLE_HASHSZ 256

#define fib_advmss fib_metrics[RTAX_ADVMSS-1]
#define fib_mtu fib_metrics[RTAX_MTU-1]
#define fib_rtt fib_metrics[RTAX_RTT-1]
#define fib_window fib_metrics[RTAX_WINDOW-1]
#define FRA_GENERIC_POLICY \
	[FRA_IIFNAME]	= { .type = NLA_STRING, .len = IFNAMSIZ - 1 }, \
	[FRA_OIFNAME]	= { .type = NLA_STRING, .len = IFNAMSIZ - 1 }, \
	[FRA_PRIORITY]	= { .type = NLA_U32 }, \
	[FRA_FWMARK]	= { .type = NLA_U32 }, \
	[FRA_FWMASK]	= { .type = NLA_U32 }, \
	[FRA_TABLE]     = { .type = NLA_U32 }, \
	[FRA_SUPPRESS_PREFIXLEN] = { .type = NLA_U32 }, \
	[FRA_SUPPRESS_IFGROUP] = { .type = NLA_U32 }, \
	[FRA_GOTO]	= { .type = NLA_U32 }

#define IP4_REPLY_MARK(net, mark) \
	((net)->ipv4.sysctl_fwmark_reflect ? (mark) : 0)
#define IPCB(skb) ((struct inet_skb_parm*)((skb)->cb))
#define IP_ADD_STATS(net, field, val)	SNMP_ADD_STATS64((net)->mib.ip_statistics, field, val)
#define IP_ADD_STATS_BH(net, field, val) SNMP_ADD_STATS64_BH((net)->mib.ip_statistics, field, val)
#define IP_INC_STATS(net, field)	SNMP_INC_STATS64((net)->mib.ip_statistics, field)
#define IP_INC_STATS_BH(net, field)	SNMP_INC_STATS64_BH((net)->mib.ip_statistics, field)
#define IP_REPLY_ARG_NOSRCCHECK 1
#define IP_UPD_PO_STATS(net, field, val) SNMP_UPD_PO_STATS64((net)->mib.ip_statistics, field, val)
#define IP_UPD_PO_STATS_BH(net, field, val) SNMP_UPD_PO_STATS64_BH((net)->mib.ip_statistics, field, val)
#define NET_ADD_STATS(net, field, adnd)	SNMP_ADD_STATS((net)->mib.net_statistics, field, adnd)
#define NET_ADD_STATS_BH(net, field, adnd) SNMP_ADD_STATS_BH((net)->mib.net_statistics, field, adnd)
#define NET_ADD_STATS_USER(net, field, adnd) SNMP_ADD_STATS_USER((net)->mib.net_statistics, field, adnd)
#define NET_INC_STATS(net, field)	SNMP_INC_STATS((net)->mib.net_statistics, field)
#define NET_INC_STATS_BH(net, field)	SNMP_INC_STATS_BH((net)->mib.net_statistics, field)
#define NET_INC_STATS_USER(net, field) 	SNMP_INC_STATS_USER((net)->mib.net_statistics, field)
#define PKTINFO_SKB_CB(skb) ((struct in_pktinfo *)((skb)->cb))

#define AUDIT_DEV_UNSET ((dev_t)-1)
#define AUDIT_INO_UNSET ((unsigned long)-1)

#define audit_enabled 0
#define audit_is_compat(arch)  (!((arch) & __AUDIT_ARCH_64BIT))
#define audit_n_rules 0
#define audit_signals 0
#define AUDIT_ALWAYS   2	
#define AUDIT_ANOM_ABEND            1701 
#define AUDIT_ANOM_PROMISCUOUS      1700 
#define AUDIT_ARG0      200
#define AUDIT_ARG1      (AUDIT_ARG0+1)
#define AUDIT_ARG2      (AUDIT_ARG0+2)
#define AUDIT_ARG3      (AUDIT_ARG0+3)
#define AUDIT_BIT(nr)  (1 << ((nr) - AUDIT_WORD(nr)*32))
#define AUDIT_BITMASK_SIZE 64
#define AUDIT_CLASS_CHATTR 2
#define AUDIT_CLASS_CHATTR_32 3
#define AUDIT_CLASS_DIR_WRITE 0
#define AUDIT_CLASS_DIR_WRITE_32 1
#define AUDIT_CLASS_READ 4
#define AUDIT_CLASS_READ_32 5
#define AUDIT_CLASS_SIGNAL 8
#define AUDIT_CLASS_SIGNAL_32 9
#define AUDIT_CLASS_WRITE 6
#define AUDIT_CLASS_WRITE_32 7
#define AUDIT_DAEMON_ABORT      1202    
#define AUDIT_DAEMON_CONFIG     1203    
#define AUDIT_DAEMON_END        1201    
#define AUDIT_DAEMON_START      1200    
#define AUDIT_FEATURE_BITMAP_ALL (AUDIT_FEATURE_BITMAP_BACKLOG_LIMIT | \
				  AUDIT_FEATURE_BITMAP_BACKLOG_WAIT_TIME | \
				  AUDIT_FEATURE_BITMAP_EXECUTABLE_PATH)
#define AUDIT_FEATURE_TO_MASK(x)	(1 << ((x) & 31)) 
#define AUDIT_FIRST_KERN_ANOM_MSG   1700
#define AUDIT_INTEGRITY_METADATA    1801 
#define AUDIT_LAST_KERN_ANOM_MSG    1799
#define AUDIT_MAX_FIELDS   64
#define AUDIT_MAX_KEY_LEN  256
#define AUDIT_NEVER    0	
#define AUDIT_NLGRP_MAX                (__AUDIT_NLGRP_MAX - 1)
#define AUDIT_POSSIBLE 1	
#define AUDIT_SUCCESS   104	
#define AUDIT_SYSCALL_CLASSES 16
#define AUDIT_UID_UNSET (unsigned int)-1
#define AUDIT_VERSION_LATEST 		AUDIT_FEATURE_BITMAP_ALL
#define AUDIT_WORD(nr) ((__u32)((nr)/32))

#define __AUDIT_ARCH_64BIT 0x80000000
#define __AUDIT_ARCH_CONVENTION_MASK 0x30000000
#define __AUDIT_ARCH_CONVENTION_MIPS64_N32 0x20000000
#define audit_feature_valid(x)		((x) >= 0 && (x) <= AUDIT_LAST_FEATURE)
#define PT_EVENT_FLAG(event)	(1 << (PT_OPT_FLAG_SHIFT + (event)))

#define arch_has_block_step()		(0)
#define arch_has_single_step()		(0)
#define arch_ptrace_stop(code, info)		do { } while (0)
#define arch_ptrace_stop_needed(code, info)	(0)
#define current_pt_regs() task_pt_regs(current)
#define current_user_stack_pointer() user_stack_pointer(current_pt_regs())
#define force_successful_syscall_return() do { } while (0)
#define is_syscall_success(regs) (!IS_ERR_VALUE((unsigned long)(regs_return_value(regs))))
#define ptrace_signal_deliver() ((void)0)
#define signal_pt_regs() task_pt_regs(current)

#define PIDNS_HASH_ADDING (1U << 31)

#define IP_TNL_HASH_BITS   7
#define IP_TNL_HASH_SIZE   (1 << IP_TNL_HASH_BITS)
#define MAX_IPTUN_ENCAP_OPS 8
#define TUNNEL_DONT_FRAGMENT    __cpu_to_be16(0x0100)
#define __NET_IP_TUNNELS_H 1
#define IP6_MAX_MTU (0xFFFF + sizeof(struct ipv6hdr))

#define LWTUNNEL_HASH_BITS   7
#define LWTUNNEL_HASH_SIZE   (1 << LWTUNNEL_HASH_BITS)
#define __NET_LWTUNNEL_H 1

#define IP6_ECN_flow_init(label) do {		\
      (label) &= ~htonl(INET_ECN_MASK << 20);	\
    } while (0)




#define for_each_ip_tunnel_rcu(pos, start) \
	for (pos = rcu_dereference(start); pos; pos = rcu_dereference(pos->next))
#define SIOCADD6RD      (SIOCDEVPRIVATE + 9)
#define SIOCADDPRL      (SIOCDEVPRIVATE + 5)
#define SIOCADDTUNNEL   (SIOCDEVPRIVATE + 1)
#define SIOCCHG6RD      (SIOCDEVPRIVATE + 11)
#define SIOCCHGPRL      (SIOCDEVPRIVATE + 7)
#define SIOCCHGTUNNEL   (SIOCDEVPRIVATE + 3)
#define SIOCDEL6RD      (SIOCDEVPRIVATE + 10)
#define SIOCDELPRL      (SIOCDEVPRIVATE + 6)
#define SIOCDELTUNNEL   (SIOCDEVPRIVATE + 2)
#define SIOCGET6RD      (SIOCDEVPRIVATE + 8)
#define SIOCGETPRL      (SIOCDEVPRIVATE + 4)
#define SIOCGETTUNNEL   (SIOCDEVPRIVATE + 0)
#define VTI_ISVTI ((__force __be16)0x0001)


#define ICMPMSGIN_INC_STATS_BH(net, field)	SNMP_INC_STATS_ATOMIC_LONG((net)->mib.icmpmsg_statistics, field)
#define ICMPMSGOUT_INC_STATS(net, field)	SNMP_INC_STATS_ATOMIC_LONG((net)->mib.icmpmsg_statistics, field+256)
#define ICMP_INC_STATS(net, field)	SNMP_INC_STATS((net)->mib.icmp_statistics, field)
#define ICMP_INC_STATS_BH(net, field)	SNMP_INC_STATS_BH((net)->mib.icmp_statistics, field)


#define INET_PROTOSW_ICSK      0x04  
#define INET_PROTOSW_PERMANENT 0x02  
#define INET_PROTOSW_REUSE 0x01	     

#define GID_T_MAX (((gid_t)~0U) >> 1)
#define PING_HTABLE_MASK 	(PING_HTABLE_SIZE-1)
#define PING_HTABLE_SIZE 	64

#define ping_portaddr_for_each_entry(__sk, node, list) \
	hlist_nulls_for_each_entry(__sk, node, list, sk_nulls_node)
#define UDPLITE_RECV_CSCOV   11 
#define UDPLITE_SEND_CSCOV   10 


#define UDP6_INC_STATS_BH(net, field, is_udplite) 	    do { \
	if (is_udplite) SNMP_INC_STATS_BH((net)->mib.udplite_stats_in6, field);\
	else		SNMP_INC_STATS_BH((net)->mib.udp_stats_in6, field);  \
} while(0)
#define UDP6_INC_STATS_USER(net, field, __lite)		    do { \
	if (__lite) SNMP_INC_STATS_USER((net)->mib.udplite_stats_in6, field);  \
	else	    SNMP_INC_STATS_USER((net)->mib.udp_stats_in6, field);      \
} while(0)
#define UDPX_INC_STATS_BH(sk, field)					\
do {									\
	if ((sk)->sk_family == AF_INET)					\
		UDP_INC_STATS_BH(sock_net(sk), field, 0);		\
	else								\
		UDP6_INC_STATS_BH(sock_net(sk), field, 0);		\
} while (0)
#define UDP_INC_STATS_BH(net, field, is_udplite) 	      do { \
	if (is_udplite) SNMP_INC_STATS_BH((net)->mib.udplite_statistics, field);         \
	else		SNMP_INC_STATS_BH((net)->mib.udp_statistics, field);    }  while(0)
#define UDP_INC_STATS_USER(net, field, is_udplite)	      do { \
	if (is_udplite) SNMP_INC_STATS_USER((net)->mib.udplite_statistics, field);       \
	else		SNMP_INC_STATS_USER((net)->mib.udp_statistics, field);  }  while(0)
#define UDP_SKB_CB(__skb)	((struct udp_skb_cb *)((__skb)->cb))

#define FASTRETRANS_DEBUG 1
#define MAX_TCP_OPTION_SPACE 40
#define TCPHDR_ACK 0x10
#define TCPHDR_CWR 0x80
#define TCPHDR_ECE 0x40
#define TCPHDR_FIN 0x01
#define TCPHDR_PSH 0x08
#define TCPHDR_RST 0x04
#define TCPHDR_SYN 0x02
#define TCPHDR_URG 0x20
#define TCPOLEN_EXP_FASTOPEN_BASE  4
#define TCPOLEN_FASTOPEN_BASE  2
#define TCPOLEN_MD5SIG         18
#define TCPOLEN_MSS            4
#define TCPOLEN_SACK_PERM      2
#define TCPOLEN_TIMESTAMP      10
#define TCPOLEN_WINDOW         3
#define TCPOPT_SACK             5       
#define TCPOPT_SACK_PERM        4       
#define TCP_ADD_STATS(net, field, val)	SNMP_ADD_STATS((net)->mib.tcp_statistics, field, val)
#define TCP_ADD_STATS_USER(net, field, val) SNMP_ADD_STATS_USER((net)->mib.tcp_statistics, field, val)
#define TCP_CONG_NON_RESTRICTED 0x1
#define TCP_DEC_STATS(net, field)	SNMP_DEC_STATS((net)->mib.tcp_statistics, field)
#define TCP_FASTOPEN_KEY_LENGTH 16
#define TCP_FASTRETRANS_THRESH 3
#define TCP_INC_STATS(net, field)	SNMP_INC_STATS((net)->mib.tcp_statistics, field)
#define TCP_INC_STATS_BH(net, field)	SNMP_INC_STATS_BH((net)->mib.tcp_statistics, field)
#define TCP_RACK_LOST_RETRANS  0x1
#define TCP_RESOURCE_PROBE_INTERVAL ((unsigned)(HZ/2U)) 
#define TCP_SKB_CB(__skb)	((struct tcp_skb_cb *)&((__skb)->cb[0]))
#define TCP_SYNACK_RETRIES 5	
#define TCP_THIN_LINEAR_RETRIES 6       
#define TCP_TIMEOUT_FALLBACK ((unsigned)(3*HZ))	
#define TCP_TIMEOUT_INIT ((unsigned)(1*HZ))	
#define TCP_TIMEWAIT_LEN (60*HZ) 

#define after(seq2, seq1) 	before(seq1, seq2)
#define tcp_flag_byte(th) (((u_int8_t *)th)[13])
#define tcp_for_write_queue(skb, sk)					\
	skb_queue_walk(&(sk)->sk_write_queue, skb)
#define tcp_for_write_queue_from(skb, sk)				\
	skb_queue_walk_from(&(sk)->sk_write_queue, skb)
#define tcp_for_write_queue_from_safe(skb, tmp, sk)			\
	skb_queue_walk_from_safe(&(sk)->sk_write_queue, skb, tmp)
#define tcp_twsk_md5_key(twsk)	((twsk)->tw_md5_key)
#define tcp_verify_left_out(tp)	WARN_ON(tcp_left_out(tp) > tp->packets_out)
#define INET_ADDR_COOKIE(__name, __saddr, __daddr) \
	const __addrpair __name = (__force __addrpair) ( \
				   (((__force __u64)(__be32)(__saddr)) << 32) | \
				   ((__force __u64)(__be32)(__daddr)))
#define INET_COMBINED_PORTS(__sport, __dport) \
	((__force __portpair)(((__force __u32)(__be16)(__sport) << 16) | (__u32)(__dport)))
#define INET_MATCH(__sk, __net, __cookie, __saddr, __daddr, __ports, __dif)	\
	(((__sk)->sk_portpair == (__ports))			&&	\
	 ((__sk)->sk_addrpair == (__cookie))			&&	\
	 (!(__sk)->sk_bound_dev_if	||				\
	   ((__sk)->sk_bound_dev_if == (__dif))) 		&& 	\
	 net_eq(sock_net(__sk), (__net)))
#define LISTENING_NULLS_BASE (1U << 29)

#define inet_bind_bucket_for_each(tb, head) \
	hlist_for_each_entry(tb, head, node)
#define MD5_DIGEST_WORDS 4
#define MD5_MESSAGE_BYTES 64
#define SHA_DIGEST_WORDS 5
#define SHA_MESSAGE_BYTES (512  / 8)
#define SHA_WORKSPACE_WORDS 16

#define CRYPTOA_MAX (__CRYPTOA_MAX - 1)
#define CRYPTO_MAX_ATTRS 32
#define CRYPTO_MINALIGN ARCH_KMALLOC_MINALIGN
#define CRYPTO_MINALIGN_ATTR __attribute__ ((__aligned__(CRYPTO_MINALIGN)))
#define CRYPTO_TFM_RES_BAD_BLOCK_LEN 	0x00800000
#define CRYPTO_TFM_RES_BAD_FLAGS 	0x01000000
#define CRYPTO_TFM_RES_BAD_KEY_LEN   	0x00200000
#define CRYPTO_TFM_RES_BAD_KEY_SCHED 	0x00400000
#define MODULE_ALIAS_CRYPTO(name)	\
		__MODULE_INFO(alias, alias_userspace, name);	\
		__MODULE_INFO(alias, alias_crypto, "crypto-" name)


#define IN_DEV_ACCEPT_LOCAL(in_dev)	IN_DEV_ORCONF((in_dev), ACCEPT_LOCAL)
#define IN_DEV_ANDCONF(in_dev, attr) \
	(IPV4_DEVCONF_ALL(dev_net(in_dev->dev), attr) && \
	 IN_DEV_CONF_GET((in_dev), attr))
#define IN_DEV_ARPFILTER(in_dev)	IN_DEV_ORCONF((in_dev), ARPFILTER)
#define IN_DEV_ARP_ACCEPT(in_dev)	IN_DEV_ORCONF((in_dev), ARP_ACCEPT)
#define IN_DEV_ARP_ANNOUNCE(in_dev)	IN_DEV_MAXCONF((in_dev), ARP_ANNOUNCE)
#define IN_DEV_ARP_IGNORE(in_dev)	IN_DEV_MAXCONF((in_dev), ARP_IGNORE)
#define IN_DEV_ARP_NOTIFY(in_dev)	IN_DEV_MAXCONF((in_dev), ARP_NOTIFY)
#define IN_DEV_BOOTP_RELAY(in_dev)	IN_DEV_ANDCONF((in_dev), BOOTP_RELAY)
#define IN_DEV_CONF_GET(in_dev, attr) \
	ipv4_devconf_get((in_dev), IPV4_DEVCONF_ ## attr)
#define IN_DEV_CONF_SET(in_dev, attr, val) \
	ipv4_devconf_set((in_dev), IPV4_DEVCONF_ ## attr, (val))
#define IN_DEV_FORWARD(in_dev)		IN_DEV_CONF_GET((in_dev), FORWARDING)
#define IN_DEV_IDTAG(in_dev)		IN_DEV_CONF_GET(in_dev, TAG)
#define IN_DEV_IGNORE_ROUTES_WITH_LINKDOWN(in_dev) \
	IN_DEV_CONF_GET((in_dev), IGNORE_ROUTES_WITH_LINKDOWN)
#define IN_DEV_LOG_MARTIANS(in_dev)	IN_DEV_ORCONF((in_dev), LOG_MARTIANS)
#define IN_DEV_MAXCONF(in_dev, attr) \
	(max(IPV4_DEVCONF_ALL(dev_net(in_dev->dev), attr), \
	     IN_DEV_CONF_GET((in_dev), attr)))
#define IN_DEV_MEDIUM_ID(in_dev)	IN_DEV_CONF_GET(in_dev, MEDIUM_ID)
#define IN_DEV_MFORWARD(in_dev)		IN_DEV_ANDCONF((in_dev), MC_FORWARDING)
#define IN_DEV_NET_ORCONF(in_dev, net, attr) \
	(IPV4_DEVCONF_ALL(net, attr) || \
	 IN_DEV_CONF_GET((in_dev), attr))
#define IN_DEV_NET_ROUTE_LOCALNET(in_dev, net)	\
	IN_DEV_NET_ORCONF(in_dev, net, ROUTE_LOCALNET)
#define IN_DEV_ORCONF(in_dev, attr) \
	IN_DEV_NET_ORCONF(in_dev, dev_net(in_dev->dev), attr)
#define IN_DEV_PROMOTE_SECONDARIES(in_dev) \
					IN_DEV_ORCONF((in_dev), \
						      PROMOTE_SECONDARIES)
#define IN_DEV_PROXY_ARP(in_dev)	IN_DEV_ORCONF((in_dev), PROXY_ARP)
#define IN_DEV_PROXY_ARP_PVLAN(in_dev)	IN_DEV_CONF_GET(in_dev, PROXY_ARP_PVLAN)
#define IN_DEV_ROUTE_LOCALNET(in_dev)	IN_DEV_ORCONF(in_dev, ROUTE_LOCALNET)
#define IN_DEV_RPFILTER(in_dev)		IN_DEV_MAXCONF((in_dev), RP_FILTER)
#define IN_DEV_RX_REDIRECTS(in_dev) \
	((IN_DEV_FORWARD(in_dev) && \
	  IN_DEV_ANDCONF((in_dev), ACCEPT_REDIRECTS)) \
	 || (!IN_DEV_FORWARD(in_dev) && \
	  IN_DEV_ORCONF((in_dev), ACCEPT_REDIRECTS)))
#define IN_DEV_SEC_REDIRECTS(in_dev)	IN_DEV_ORCONF((in_dev), \
						      SECURE_REDIRECTS)
#define IN_DEV_SHARED_MEDIA(in_dev)	IN_DEV_ORCONF((in_dev), SHARED_MEDIA)
#define IN_DEV_SOURCE_ROUTE(in_dev)	IN_DEV_ANDCONF((in_dev), \
						       ACCEPT_SOURCE_ROUTE)
#define IN_DEV_SRC_VMARK(in_dev)    	IN_DEV_ORCONF((in_dev), SRC_VMARK)
#define IN_DEV_TX_REDIRECTS(in_dev)	IN_DEV_ORCONF((in_dev), SEND_REDIRECTS)
#define IPV4_DEVCONF(cnf, attr) ((cnf).data[IPV4_DEVCONF_ ## attr - 1])
#define IPV4_DEVCONF_ALL(net, attr) \
	IPV4_DEVCONF((*(net)->ipv4.devconf_all), attr)
#define MC_HASH_SZ_LOG 9

#define __in_dev_put(idev)  atomic_dec(&(idev)->refcnt)
#define endfor_ifa(in_dev) }
#define for_ifa(in_dev)	{ struct in_ifaddr *ifa; \
  for (ifa = (in_dev)->ifa_list; ifa; ifa = ifa->ifa_next)
#define for_primary_ifa(in_dev)	{ struct in_ifaddr *ifa; \
  for (ifa = (in_dev)->ifa_list; ifa && !(ifa->ifa_flags&IFA_F_SECONDARY); ifa = ifa->ifa_next)
#define in_dev_hold(idev)   atomic_inc(&(idev)->refcnt)
#define IGMPV3_EXP(thresh, nbmant, nbexp, value) \
	((value) < (thresh) ? (value) : \
        ((IGMPV3_MASK(value, nbmant) | (1<<(nbmant))) << \
         (IGMPV3_MASK((value) >> (nbmant), nbexp) + (nbexp))))
#define IGMPV3_MASK(value, nb) ((nb)>=32 ? (value) : ((1<<(nb))-1) & (value))
#define IGMPV3_MRC(value) IGMPV3_EXP(0x80, 4, 3, value)
#define IGMPV3_QQIC(value) IGMPV3_EXP(0x80, 4, 3, value)
#define IP_SFLSIZE(count)	(sizeof(struct ip_sf_socklist) + \
	(count) * sizeof(__be32))

#define IGMP_ALL_ROUTER 	htonl(0xE0000002L)
#define IGMP_HOST_LEAVE_MESSAGE 	0x17



#define SO_ORIGINAL_DST 80



#define CTINFO2DIR(ctinfo) ((ctinfo) >= IP_CT_IS_REPLY ? IP_CT_DIR_REPLY : IP_CT_DIR_ORIGINAL)

