
#include<sys/queue.h>



#include<net/route.h>


#include<sys/resource.h>






#include<netinet/in.h>






#include<netinet/tcp.h>




#include<sys/socket.h>














#include<sys/select.h>



#include<sys/param.h>


#include<sys/time.h>






#include<sys/signal.h>




#include<sys/types.h>
















#include<stdint.h>


#include<sys/sysctl.h>

#include<sys/cdefs.h>


#define mac_ifnet_check_transmit_enabled() __predict_false(mac_ifnet_check_transmit_fp_flag)
#define mac_ifnet_check_transmit_fp_flag 0
#define mac_ifnet_create_mbuf_enabled() __predict_false(mac_ifnet_create_mbuf_fp_flag)
#define mac_ifnet_create_mbuf_fp_flag 0
#define mac_pipe_check_poll_enabled() __predict_false(mac_pipe_check_poll_fp_flag)
#define mac_pipe_check_poll_fp_flag 0
#define mac_pipe_check_stat_enabled() __predict_false(mac_pipe_check_stat_fp_flag)
#define mac_pipe_check_stat_fp_flag 0
#define mac_priv_check_enabled()	__predict_false(mac_priv_check_fp_flag)
#define mac_priv_check_fp_flag 0
#define mac_priv_grant_enabled()	__predict_false(mac_priv_grant_fp_flag)
#define mac_priv_grant_fp_flag 0
#define mac_vnode_assert_locked(vp, func) do { } while (0)
#define mac_vnode_check_access_enabled() __predict_false(mac_vnode_check_access_fp_flag)
#define mac_vnode_check_lookup_enabled() __predict_false(mac_vnode_check_lookup_fp_flag)
#define mac_vnode_check_lookup_fp_flag 0
#define mac_vnode_check_mmap_enabled() __predict_false(mac_vnode_check_mmap_fp_flag)
#define mac_vnode_check_mmap_fp_flag 0
#define mac_vnode_check_open_enabled() __predict_false(mac_vnode_check_open_fp_flag)
#define mac_vnode_check_open_fp_flag 0
#define mac_vnode_check_poll_enabled() __predict_false(mac_vnode_check_poll_fp_flag)
#define mac_vnode_check_read_enabled() __predict_false(mac_vnode_check_read_fp_flag)
#define mac_vnode_check_read_fp_flag 0
#define mac_vnode_check_readlink_enabled() __predict_false(mac_vnode_check_readlink_fp_flag)
#define mac_vnode_check_readlink_fp_flag 0
#define mac_vnode_check_rename_from_enabled() __predict_false(mac_vnode_check_rename_from_fp_flag)
#define mac_vnode_check_stat_enabled()	__predict_false(mac_vnode_check_stat_fp_flag)
#define mac_vnode_check_stat_fp_flag 0
#define mac_vnode_check_write_enabled() __predict_false(mac_vnode_check_write_fp_flag)
#define mac_vnode_check_write_fp_flag 0
#define offsetof(type, field) __offsetof(type, field)



#define __align_down(x, y) __builtin_align_down(x, y)
#define __align_up(x, y) __builtin_align_up(x, y)
#define __builtin_align_down(x, align)	\
	((__typeof__(x))((x)&(~((align)-1))))
#define __builtin_align_up(x, align)	\
	((__typeof__(x))(((__uintptr_t)(x)+((align)-1))&(~((align)-1))))
#define __builtin_is_aligned(x, align)	\
	(((__uintptr_t)x & ((align) - 1)) == 0)
#define __is_aligned(x, y) __builtin_is_aligned(x, y)
#define __min_size(x)	static (x)







#define SMR_ASSERT(ex, fn)						\
    KASSERT((ex), (fn ": Assertion " #ex " failed at %s:%d", "__FILE__", "__LINE__"))
#define KM_NOSLEEP M_NOWAIT
#define KM_SLEEP M_WAITOK

#define M_NOWAIT 2
#define M_WAITOK 1
#define M_ZERO 0
#define kmem_free(p, size) Free(p, "__FILE__", "__LINE__")
#define kmem_zalloc(size, flags) ({					\
	void *p = Malloc((size), "__FILE__", "__LINE__");			\
	if (p == NULL && (flags &  M_WAITOK) != 0)			\
		panic("Could not malloc %zd bytes with M_WAITOK from %s line %d", \
		    (size_t)size, "__FILE__", "__LINE__");			\
	p;								\
})


#define LIST_CONCAT(head1, head2, type, field) do {			      \
	QUEUE_TYPEOF(type) *curelm = LIST_FIRST(head1);			      \
	if (curelm == NULL) {						      \
		if ((LIST_FIRST(head1) = LIST_FIRST(head2)) != NULL) {	      \
			LIST_FIRST(head2)->field.le_prev =		      \
			    &LIST_FIRST((head1));			      \
			LIST_INIT(head2);				      \
		}							      \
	} else if (LIST_FIRST(head2) != NULL) {				      \
		while (LIST_NEXT(curelm, field) != NULL)		      \
			curelm = LIST_NEXT(curelm, field);		      \
		LIST_NEXT(curelm, field) = LIST_FIRST(head2);		      \
		LIST_FIRST(head2)->field.le_prev = &LIST_NEXT(curelm, field); \
		LIST_INIT(head2);					      \
	}								      \
} while (0)
#define LIST_SWAP(head1, head2, type, field) do {			\
	QUEUE_TYPEOF(type) *swap_tmp = LIST_FIRST(head1);		\
	LIST_FIRST((head1)) = LIST_FIRST((head2));			\
	LIST_FIRST((head2)) = swap_tmp;					\
	if ((swap_tmp = LIST_FIRST((head1))) != NULL)			\
		swap_tmp->field.le_prev = &LIST_FIRST((head1));		\
	if ((swap_tmp = LIST_FIRST((head2))) != NULL)			\
		swap_tmp->field.le_prev = &LIST_FIRST((head2));		\
} while (0)
#define SLIST_CONCAT(head1, head2, type, field) do {			\
	QUEUE_TYPEOF(type) *curelm = SLIST_FIRST(head1);		\
	if (curelm == NULL) {						\
		if ((SLIST_FIRST(head1) = SLIST_FIRST(head2)) != NULL)	\
			SLIST_INIT(head2);				\
	} else if (SLIST_FIRST(head2) != NULL) {			\
		while (SLIST_NEXT(curelm, field) != NULL)		\
			curelm = SLIST_NEXT(curelm, field);		\
		SLIST_NEXT(curelm, field) = SLIST_FIRST(head2);		\
		SLIST_INIT(head2);					\
	}								\
} while (0)
#define SLIST_REMOVE_AFTER(elm, field) do {				\
	QMD_SAVELINK(oldnext, SLIST_NEXT(elm, field)->field.sle_next);	\
	SLIST_NEXT(elm, field) =					\
	    SLIST_NEXT(SLIST_NEXT(elm, field), field);			\
	TRASHIT(*oldnext);						\
} while (0)
#define SLIST_SWAP(head1, head2, type) do {				\
	QUEUE_TYPEOF(type) *swap_first = SLIST_FIRST(head1);		\
	SLIST_FIRST(head1) = SLIST_FIRST(head2);			\
	SLIST_FIRST(head2) = swap_first;				\
} while (0)
#define STAILQ_REMOVE_AFTER(head, elm, field) do {			\
	if ((STAILQ_NEXT(elm, field) =					\
	     STAILQ_NEXT(STAILQ_NEXT(elm, field), field)) == NULL)	\
		(head)->stqh_last = &STAILQ_NEXT((elm), field);		\
} while (0)
#define STAILQ_SWAP(head1, head2, type) do {				\
	QUEUE_TYPEOF(type) *swap_first = STAILQ_FIRST(head1);		\
	QUEUE_TYPEOF(type) **swap_last = (head1)->stqh_last;		\
	STAILQ_FIRST(head1) = STAILQ_FIRST(head2);			\
	(head1)->stqh_last = (head2)->stqh_last;			\
	STAILQ_FIRST(head2) = swap_first;				\
	(head2)->stqh_last = swap_last;					\
	if (STAILQ_EMPTY(head1))					\
		(head1)->stqh_last = &STAILQ_FIRST(head1);		\
	if (STAILQ_EMPTY(head2))					\
		(head2)->stqh_last = &STAILQ_FIRST(head2);		\
} while (0)
#define TAILQ_SWAP(head1, head2, type, field) do {			\
	QUEUE_TYPEOF(type) *swap_first = (head1)->tqh_first;		\
	QUEUE_TYPEOF(type) **swap_last = (head1)->tqh_last;		\
	(head1)->tqh_first = (head2)->tqh_first;			\
	(head1)->tqh_last = (head2)->tqh_last;				\
	(head2)->tqh_first = swap_first;				\
	(head2)->tqh_last = swap_last;					\
	if ((swap_first = (head1)->tqh_first) != NULL)			\
		swap_first->field.tqe_prev = &(head1)->tqh_first;	\
	else								\
		(head1)->tqh_last = &(head1)->tqh_first;		\
	if ((swap_first = (head2)->tqh_first) != NULL)			\
		swap_first->field.tqe_prev = &(head2)->tqh_first;	\
	else								\
		(head2)->tqh_last = &(head2)->tqh_first;		\
} while (0)

#define __gone_ok(m, msg)					 \
	_Static_assert(m < P_OSREL_MAJOR(__FreeBSD_version)),	 \
	    "Obsolete code: " msg);
#define bcmp(b1, b2, len)	SAN_INTERCEPTOR(memcmp)((b1), (b2), (len))
#define bcopy(from, to, len)	SAN_INTERCEPTOR(memmove)((to), (from), (len))
#define bcopy_early(from, to, len) memmove_early((to), (from), (len))
#define bzero(buf, len)		SAN_INTERCEPTOR(memset)((buf), 0, (len))
#define bzero_early(buf, len) memset_early((buf), 0, (len))
#define critical_enter() critical_enter_KBI()
#define critical_exit() critical_exit_KBI()
#define gone_in(major, msg)		__gone_ok(major, msg) _gone_in(major, msg)
#define gone_in_dev(dev, major, msg)	__gone_ok(major, msg) _gone_in_dev(dev, major, msg)
#define memcmp(b1, b2, len)	SAN_INTERCEPTOR(memcmp)((b1), (b2), (len))
#define memcpy(to, from, len)	SAN_INTERCEPTOR(memcpy)((to), (from), (len))
#define memmove(dest, src, n)	SAN_INTERCEPTOR(memmove)((dest), (src), (n))
#define memset(buf, c, len)	SAN_INTERCEPTOR(memset)((buf), (c), (len))
#define ovbcopy(f, t, l) bcopy((f), (t), (l))
#define strcmp(s1, s2)	__builtin_strcmp((s1), (s2))
#define strcpy(d, s)	__builtin_strcpy((d), (s))
#define strlen(s)	__builtin_strlen((s))

#define ZPCPU_ASSERT_PROTECTED() MPASS(curthread->td_critnest > 0)
#define zpcpu_add_protected(base, val) ({				\
	ZPCPU_ASSERT_PROTECTED();					\
	__typeof(val) *_ptr = zpcpu_get(base);				\
									\
	*_ptr += (val);							\
})
#define zpcpu_base_to_offset(base) (base)
#define zpcpu_get(base) ({								\
	__typeof(base) _ptr = (void *)((char *)(base) + zpcpu_offset());		\
	_ptr;										\
})
#define zpcpu_get_cpu(base, cpu) ({							\
	__typeof(base) _ptr = (void *)((char *)(base) +	zpcpu_offset_cpu(cpu));		\
	_ptr;										\
})
#define zpcpu_offset()		(PCPU_GET(zpcpu_offset))
#define zpcpu_offset_cpu(cpu)	(UMA_PCPU_ALLOC_SIZE * cpu)
#define zpcpu_offset_to_base(base) (base)
#define zpcpu_replace(base, val) ({					\
	__typeof(val) *_ptr = zpcpu_get(base);				\
	__typeof(val) _old;						\
									\
	_old = *_ptr;							\
	*_ptr = val;							\
	_old;								\
})
#define zpcpu_replace_cpu(base, val, cpu) ({				\
	__typeof(val) *_ptr = zpcpu_get_cpu(base, cpu);			\
	__typeof(val) _old;						\
									\
	_old = *_ptr;							\
	*_ptr = val;							\
	_old;								\
})
#define zpcpu_set_protected(base, val) ({				\
	ZPCPU_ASSERT_PROTECTED();					\
	__typeof(val) *_ptr = zpcpu_get(base);				\
									\
	*_ptr = (val);							\
})
#define zpcpu_sub_protected(base, val) ({				\
	ZPCPU_ASSERT_PROTECTED();					\
	__typeof(val) *_ptr = zpcpu_get(base);				\
									\
	*_ptr -= (val);							\
})
#define __BITSET_DEFINE_VAR(_t)	__BITSET_DEFINE(_t, 1)
#define BLKDEV_IOSIZE  PAGE_SIZE	


#define __FreeBSD_version 1400056
#define __PAST_END(array, offset) (((__typeof__(*(array)) *)(array))[offset])
#define btoc(x)	(((vm_offset_t)(x)+PAGE_MASK)>>PAGE_SHIFT)
#define btodb(bytes)	 		 \
	(sizeof (bytes) > sizeof(long) \
	 ? (daddr_t)((unsigned long long)(bytes) >> DEV_BSHIFT) \
	 : (daddr_t)((unsigned long)(bytes) >> DEV_BSHIFT))
#define ctob(x)	((x)<<PAGE_SHIFT)
#define ctodb(db)			 \
	((db) << (PAGE_SHIFT - DEV_BSHIFT))
#define dbtob(db)			 \
	((off_t)(db) << DEV_BSHIFT)
#define dbtoc(db)			 \
	((db + (ctodb(1) - 1)) >> (PAGE_SHIFT - DEV_BSHIFT))
#define powerof2(x)	((((x)-1)&(x))==0)
#define ILL_BADSTK 	8	
#define ILL_COPROC 	7	
#define ILL_ILLADR 	3	
#define ILL_ILLOPC 	1	
#define ILL_ILLOPN 	2	
#define ILL_ILLTRP 	4	
#define ILL_PRVOPC 	5	
#define ILL_PRVREG 	6	
#define SIG_HOLD        ((__sighandler_t *)3)

#define MSEC_2_TICKS(m) max(1, (uint32_t)((hz == 1000) ? \
	  (m) : ((uint64_t)(m) * (uint64_t)hz)/(uint64_t)1000))
#define TICKS_2_MSEC(t) max(1, (uint32_t)(hz == 1000) ? \
	  (t) : (((uint64_t)(t) * (uint64_t)1000)/(uint64_t)hz))
#define TICKS_2_USEC(t) max(1, (uint32_t)(hz == 1000) ? \
	  ((t) * 1000) : (((uint64_t)(t) * (uint64_t)1000000)/(uint64_t)hz))
#define USEC_2_TICKS(u) max(1, (uint32_t)((hz == 1000) ? \
	 ((u) / 1000) : ((uint64_t)(u) * (uint64_t)hz)/(uint64_t)1000000))






#define RSIZE_MAX (SIZE_MAX >> 1)

#define MPASS(ex)		MPASS4(ex, #ex, "__FILE__", "__LINE__")
#define MPASS2(ex, what)	MPASS4(ex, what, "__FILE__", "__LINE__")
#define MPASS3(ex, file, line)	MPASS4(ex, #ex, file, line)
#define MPASS4(ex, what, file, line)					\
	KASSERT((ex), ("Assertion %s failed at %s:%d", what, file, line))
#  define kassert_panic printf

#define callout_async_drain(c, d)					\
    _callout_stop_safe(c, 0, d)
#define BANDLIM_ICMP6_UNREACH 5
#define BANDLIM_ICMP_ECHO 1
#define BANDLIM_ICMP_TSTAMP 2
#define BANDLIM_ICMP_UNREACH 0
#define BANDLIM_MAX 7
#define BANDLIM_RST_CLOSEDPORT 3 
#define BANDLIM_RST_OPENPORT 4   
#define BANDLIM_SCTP_OOTB 6
#define BANDLIM_UNLIMITED -1



#define SEGQ_EMPTY(tp) TAILQ_EMPTY(&(tp)->t_segq)
#define TCP_EI_BITS_DATA_A_CLO  0x100
#define TCP_END_BYTE_INFO 8	



#define CSUM_FLAGS_RX (CSUM_INNER_L3_CALC | CSUM_INNER_L3_VALID | \
    CSUM_INNER_L4_CALC | CSUM_INNER_L4_VALID | CSUM_L3_CALC | CSUM_L3_VALID | \
    CSUM_L4_CALC | CSUM_L4_VALID | CSUM_L5_CALC | CSUM_L5_VALID | \
    CSUM_COALESCED)
#define CSUM_FLAGS_TX (CSUM_IP | CSUM_IP_UDP | CSUM_IP_TCP | CSUM_IP_SCTP | \
    CSUM_IP_TSO | CSUM_IP_ISCSI | CSUM_INNER_IP6_UDP | CSUM_INNER_IP6_TCP | \
    CSUM_INNER_IP6_TSO | CSUM_IP6_UDP | CSUM_IP6_TCP | CSUM_IP6_SCTP | \
    CSUM_IP6_TSO | CSUM_IP6_ISCSI | CSUM_INNER_IP | CSUM_INNER_IP_UDP | \
    CSUM_INNER_IP_TCP | CSUM_INNER_IP_TSO | CSUM_ENCAP_VXLAN | \
    CSUM_ENCAP_RSVD1 | CSUM_SND_TAG)
#define MBUF_PEXT_MAX_PGS (40 / sizeof(vm_paddr_t))
#define M_ASSERTEXTPG(m)						\
	KASSERT(((m)->m_flags & (M_EXTPG|M_PKTHDR)) == M_EXTPG,		\
	    ("%s: m %p is not multipage!", __func__, m))
#define M_COPYFLAGS \
    (M_PKTHDR|M_EOR|M_RDONLY|M_BCAST|M_MCAST|M_PROMISC|M_VLANTAG|M_TSTMP| \
     M_TSTMP_HPREC|M_TSTMP_LRO|M_PROTOFLAGS)
#define M_GETFIB(_m)   rt_m_getfib(_m)
 #define M_PROFILE(m) m_profile(m)
#define M_SETFIB(_m, _fib) do {						\
        KASSERT((_m)->m_flags & M_PKTHDR, ("Attempt to set FIB on non header mbuf."));	\
	((_m)->m_pkthdr.fibnum) = (_fib);				\
} while (0)
#define DTRACE_PROBE(name)						\
	DTRACE_PROBE_IMPL_START(name, 0, 0, 0, 0, 0)			\
	DTRACE_PROBE_IMPL_END
#define DTRACE_PROBE1(name, type0, arg0)				\
	DTRACE_PROBE_IMPL_START(name, arg0, 0, 0, 0, 0) 		\
	SDT_PROBE_ARGTYPE(sdt, , , name, 0, #type0, NULL);		\
	DTRACE_PROBE_IMPL_END
#define DTRACE_PROBE2(name, type0, arg0, type1, arg1)			\
	DTRACE_PROBE_IMPL_START(name, arg0, arg1, 0, 0, 0) 		\
	SDT_PROBE_ARGTYPE(sdt, , , name, 0, #type0, NULL);		\
	SDT_PROBE_ARGTYPE(sdt, , , name, 1, #type1, NULL);		\
	DTRACE_PROBE_IMPL_END
#define DTRACE_PROBE3(name, type0, arg0, type1, arg1, type2, arg2)	\
	DTRACE_PROBE_IMPL_START(name, arg0, arg1, arg2, 0, 0)	 	\
	SDT_PROBE_ARGTYPE(sdt, , , name, 0, #type0, NULL);		\
	SDT_PROBE_ARGTYPE(sdt, , , name, 1, #type1, NULL);		\
	SDT_PROBE_ARGTYPE(sdt, , , name, 2, #type2, NULL);		\
	DTRACE_PROBE_IMPL_END
#define DTRACE_PROBE4(name, type0, arg0, type1, arg1, type2, arg2, type3, arg3)	\
	DTRACE_PROBE_IMPL_START(name, arg0, arg1, arg2, arg3, 0) 	\
	SDT_PROBE_ARGTYPE(sdt, , , name, 0, #type0, NULL);		\
	SDT_PROBE_ARGTYPE(sdt, , , name, 1, #type1, NULL);		\
	SDT_PROBE_ARGTYPE(sdt, , , name, 2, #type2, NULL);		\
	SDT_PROBE_ARGTYPE(sdt, , , name, 3, #type3, NULL);		\
	DTRACE_PROBE_IMPL_END
#define DTRACE_PROBE5(name, type0, arg0, type1, arg1, type2, arg2, type3, arg3,	\
    type4, arg4)								\
	DTRACE_PROBE_IMPL_START(name, arg0, arg1, arg2, arg3, arg4) 	\
	SDT_PROBE_ARGTYPE(sdt, , , name, 0, #type0, NULL);		\
	SDT_PROBE_ARGTYPE(sdt, , , name, 1, #type1, NULL);		\
	SDT_PROBE_ARGTYPE(sdt, , , name, 2, #type2, NULL);		\
	SDT_PROBE_ARGTYPE(sdt, , , name, 3, #type3, NULL);		\
	SDT_PROBE_ARGTYPE(sdt, , , name, 4, #type4, NULL);		\
	DTRACE_PROBE_IMPL_END
#define SDT_PROBE(prov, mod, func, name, arg0, arg1, arg2, arg3, arg4)	do {	\
	if (SDT_PROBES_ENABLED()) {						\
		if (__predict_false(sdt_##prov##_##mod##_##func##_##name->id))	\
		(*sdt_probe_func)(sdt_##prov##_##mod##_##func##_##name->id,	\
		    (uintptr_t) arg0, (uintptr_t) arg1, (uintptr_t) arg2,	\
		    (uintptr_t) arg3, (uintptr_t) arg4);			\
	} \
} while (0)
#define SDT_PROBES_ENABLED()	0
#define SDT_PROBE_ARGTYPE(prov, mod, func, name, num, type, xtype)		\
	static struct sdt_argtype sdta_##prov##_##mod##_##func##_##name##num[1]	\
	    = { { num, type, xtype, { NULL, NULL },				\
	    sdt_##prov##_##mod##_##func##_##name }				\
	};									\
	DATA_SET(sdt_argtypes_set, sdta_##prov##_##mod##_##func##_##name##num);
#define SDT_PROBE_DECLARE(prov, mod, func, name)				\
	extern struct sdt_probe sdt_##prov##_##mod##_##func##_##name[1]
#define SDT_PROBE_DEFINE(prov, mod, func, name)					\
	struct sdt_probe sdt_##prov##_##mod##_##func##_##name[1] = {		\
		{ sizeof(struct sdt_probe), sdt_provider_##prov,		\
		    { NULL, NULL }, { NULL, NULL }, #mod, #func, #name, 0, 0,	\
		    NULL }							\
	};									\
	DATA_SET(sdt_probes_set, sdt_##prov##_##mod##_##func##_##name);
#define SDT_PROBE_DEFINE4_XLATE(prov, mod, func, name, arg0, xarg0,     \
    arg1, xarg1, arg2, xarg2, arg3, xarg3)
#define SDT_PROVIDER_DECLARE(prov)						\
	extern struct sdt_provider sdt_provider_##prov[1]
#define SDT_PROVIDER_DEFINE(prov)						\
	struct sdt_provider sdt_provider_##prov[1] = {				\
		{ #prov, { NULL, NULL }, 0, 0 }					\
	};									\
	DATA_SET(sdt_providers_set, sdt_provider_##prov);
#define ABS_SET(set, sym)	__MAKE_SET(set, sym)
#define BSS_SET(set, sym)	__MAKE_SET(set, sym)
#define DATA_SET(set, sym)	__MAKE_SET(set, sym)
#define DATA_WSET(set, sym)	__MAKE_SET_QV(set, sym, )
#define SET_BEGIN(set)							\
	(&__CONCAT(__start_set_,set))
#define SET_COUNT(set)							\
	(SET_LIMIT(set) - SET_BEGIN(set))
#define SET_DECLARE(set, ptype)					\
	extern ptype __weak_symbol *__CONCAT(__start_set_,set);	\
	extern ptype __weak_symbol *__CONCAT(__stop_set_,set)
#define SET_ENTRY(set, sym)	__MAKE_SET(set, sym)
#define SET_FOREACH(pvar, set)						\
	for (pvar = SET_BEGIN(set); pvar < SET_LIMIT(set); pvar++)
#define SET_ITEM(set, i)						\
	((SET_BEGIN(set))[i])
#define SET_LIMIT(set)							\
	(&__CONCAT(__stop_set_,set))
#define TEXT_SET(set, sym)	__MAKE_SET(set, sym)

#define __MAKE_SET(set, sym)	__MAKE_SET_QV(set, sym, __MAKE_SET_CONST)
#define __MAKE_SET_QV(set, sym, qv)			\
	__WEAK(__CONCAT(__start_set_,set));		\
	__WEAK(__CONCAT(__stop_set_,set));		\
	static void const * qv				\
	__NOASAN					\
	__set_##set##_sym_##sym __section("set_" #set)	\
	__used = &(sym)
#define LO_NOPROFILE    0x10000000      
#define WITNESS_DESTROY(lock)						\
	witness_destroy(lock)

#define lock_delay_spin(n)	do {	\
	u_int _i;			\
					\
	for (_i = (n); _i > 0; _i--)	\
		cpu_spinwait();		\
} while (0)
#define KTR_COMPILE 0

#define VNET_GLOBAL_EVENTHANDLER_REGISTER(name, func, arg, priority)	\
do {									\
	if (IS_DEFAULT_VNET(curvnet)) {					\
		vimage_eventhandler_register(NULL, #name, func,		\
		    arg, priority,					\
		    vnet_global_eventhandler_iterator_func);		\
	}								\
} while(0)
#define VNET_GLOBAL_EVENTHANDLER_REGISTER_TAG(tag, name, func, arg, priority) \
do {									\
	if (IS_DEFAULT_VNET(curvnet)) {					\
		(tag) = vimage_eventhandler_register(NULL, #name, func,	\
		    arg, priority,					\
		    vnet_global_eventhandler_iterator_func);		\
	}								\
} while(0)
#define EVENTHANDLER_DEFINE(name, func, arg, priority)			\
	static eventhandler_tag name ## _tag;				\
	static void name ## _evh_init(void *ctx)			\
	{								\
		name ## _tag = EVENTHANDLER_REGISTER(name, func, ctx,	\
		    priority);						\
	}								\
	SYSINIT(name ## _evh_init, SI_SUB_CONFIGURE, SI_ORDER_ANY,	\
	    name ## _evh_init, arg);					\
	struct __hack
#define EVENTHANDLER_DEREGISTER(name, tag) 				\
do {									\
	struct eventhandler_list *_el;					\
									\
	if ((_el = eventhandler_find_list(#name)) != NULL)		\
		eventhandler_deregister(_el, tag);			\
} while (0)
#define EVENTHANDLER_DEREGISTER_NOWAIT(name, tag)			\
do {									\
	struct eventhandler_list *_el;					\
									\
	if ((_el = eventhandler_find_list(#name)) != NULL)		\
		eventhandler_deregister_nowait(_el, tag);		\
} while (0)
#define EVENTHANDLER_INVOKE(name, ...)					\
do {									\
	struct eventhandler_list *_el;					\
									\
	if ((_el = eventhandler_find_list(#name)) != NULL) 		\
		_EVENTHANDLER_INVOKE(name, _el , ## __VA_ARGS__);	\
} while (0)
#define EVENTHANDLER_REGISTER(name, func, arg, priority)		\
	eventhandler_register(NULL, #name, func, arg, priority)
#define _EVENTHANDLER_INVOKE(name, list, ...) do {			\
	struct eventhandler_entry *_ep;					\
	struct eventhandler_entry_ ## name *_t;				\
									\
	EHL_LOCK_ASSERT((list), MA_OWNED);				\
	(list)->el_runcount++;						\
	KASSERT((list)->el_runcount > 0,				\
	    ("eventhandler_invoke: runcount overflow"));		\
	CTR0(KTR_EVH, "eventhandler_invoke(\"" __STRING(name) "\")");	\
	TAILQ_FOREACH(_ep, &((list)->el_entries), ee_link) {		\
		if (_ep->ee_priority != EHE_DEAD_PRIORITY) {		\
			EHL_UNLOCK((list));				\
			_t = (struct eventhandler_entry_ ## name *)_ep;	\
			CTR1(KTR_EVH, "eventhandler_invoke: executing %p", \
 			    (void *)_t->eh_func);			\
			_t->eh_func(_ep->ee_arg , ## __VA_ARGS__);	\
			EHL_LOCK((list));				\
		}							\
	}								\
	KASSERT((list)->el_runcount > 0,				\
	    ("eventhandler_invoke: runcount underflow"));		\
	(list)->el_runcount--;						\
	if ((list)->el_runcount == 0)					\
		eventhandler_prune_list(list);				\
	EHL_UNLOCK((list));						\
} while (0)

#define DROP_GIANT()							\
do {									\
	int _giantcnt = 0;						\
	WITNESS_SAVE_DECL(Giant);					\
									\
	if (__predict_false(mtx_owned(&Giant))) {			\
		WITNESS_SAVE(&Giant.lock_object, Giant);		\
		for (_giantcnt = 0; mtx_owned(&Giant) &&		\
		    !SCHEDULER_STOPPED(); _giantcnt++)			\
			mtx_unlock(&Giant);				\
	}

#define MTX_NOPROFILE   0x00000020	
#define PARTIAL_PICKUP_GIANT()						\
	mtx_assert(&Giant, MA_NOTOWNED);				\
	if (__predict_false(_giantcnt > 0)) {				\
		while (_giantcnt--)					\
			mtx_lock(&Giant);				\
		WITNESS_RESTORE(&Giant.lock_object, Giant);		\
	}
#define PICKUP_GIANT()							\
	PARTIAL_PICKUP_GIANT();						\
} while (0)

#define __mtx_lock(mp, tid, opts, file, line) __extension__ ({		\
	uintptr_t _tid = (uintptr_t)(tid);				\
	uintptr_t _v = MTX_UNOWNED;					\
									\
	if (__predict_false(LOCKSTAT_PROFILE_ENABLED(adaptive__acquire) ||\
	    !_mtx_obtain_lock_fetch((mp), &_v, _tid)))			\
		_mtx_lock_sleep((mp), _v, (opts), (file), (line));	\
	(void)0; 			\
})
#define __mtx_lock_spin(mp, tid, opts, file, line) __extension__ ({	\
	uintptr_t _tid = (uintptr_t)(tid);				\
	uintptr_t _v = MTX_UNOWNED;					\
									\
	spinlock_enter();						\
	if (__predict_false(LOCKSTAT_PROFILE_ENABLED(spin__acquire) ||	\
	    !_mtx_obtain_lock_fetch((mp), &_v, _tid))) 			\
		_mtx_lock_spin((mp), _v, (opts), (file), (line)); 	\
	(void)0; 			\
})
#define __mtx_trylock_spin(mp, tid, opts, file, line) __extension__  ({	\
	uintptr_t _tid = (uintptr_t)(tid);				\
	int _ret;							\
									\
	spinlock_enter();						\
	if (((mp)->mtx_lock != MTX_UNOWNED || !_mtx_obtain_lock((mp), _tid))) {\
		spinlock_exit();					\
		_ret = 0;						\
	} else {							\
		LOCKSTAT_PROFILE_OBTAIN_SPIN_LOCK_SUCCESS(spin__acquire,	\
		    mp, 0, 0, file, line);				\
		_ret = 1;						\
	}								\
	_ret;								\
})
#define __mtx_unlock(mp, tid, opts, file, line) __extension__ ({	\
	uintptr_t _v = (uintptr_t)(tid);				\
									\
	if (__predict_false(LOCKSTAT_PROFILE_ENABLED(adaptive__release) ||\
	    !_mtx_release_lock_fetch((mp), &_v)))			\
		_mtx_unlock_sleep((mp), _v, (opts), (file), (line));	\
	(void)0; 			\
})
#define __mtx_unlock_spin(mp) __extension__ ({				\
	if (mtx_recursed((mp)))						\
		(mp)->mtx_recurse--;					\
	else {								\
		LOCKSTAT_PROFILE_RELEASE_SPIN_LOCK(spin__release, mp);	\
		_mtx_release_lock_quick((mp));				\
	}								\
	spinlock_exit();						\
})
#define _mtx_obtain_lock(mp, tid)					\
	atomic_cmpset_acq_ptr(&(mp)->mtx_lock, MTX_UNOWNED, (tid))
#define _mtx_obtain_lock_fetch(mp, vp, tid)				\
	atomic_fcmpset_acq_ptr(&(mp)->mtx_lock, vp, (tid))
#define _mtx_release_lock(mp, tid)					\
	atomic_cmpset_rel_ptr(&(mp)->mtx_lock, (tid), MTX_UNOWNED)
#define _mtx_release_lock_quick(mp)					\
	atomic_store_rel_ptr(&(mp)->mtx_lock, MTX_UNOWNED)
#define lv_mtx_owner(v)	((struct thread *)((v) & ~MTX_FLAGMASK))
#define mtx_assert_(m, what, file, line)	(void)0
#define mtx_lock(m)		mtx_lock_flags((m), 0)
#define mtx_lock_spin(m)	mtx_lock_spin_flags((m), 0)
#define mtx_name(m)	((m)->lock_object.lo_name)
#define mtx_owned(m)	(mtx_owner(m) == curthread)
#define mtx_owner(m)	lv_mtx_owner(MTX_READ_VALUE(m))
#define mtx_pool_lock(pool, ptr)					\
	mtx_lock(mtx_pool_find((pool), (ptr)))
#define mtx_pool_lock_spin(pool, ptr)					\
	mtx_lock_spin(mtx_pool_find((pool), (ptr)))
#define mtx_pool_unlock(pool, ptr)					\
	mtx_unlock(mtx_pool_find((pool), (ptr)))
#define mtx_pool_unlock_spin(pool, ptr)					\
	mtx_unlock_spin(mtx_pool_find((pool), (ptr)))
#define mtx_recursed(m)	((m)->mtx_recurse != 0)
#define mtx_trylock(m)		mtx_trylock_flags((m), 0)
#define mtx_trylock_flags(m, opts)					\
	mtx_trylock_flags_((m), (opts), LOCK_FILE, LOCK_LINE)
#define mtx_trylock_spin(m)	mtx_trylock_spin_flags((m), 0)
#define mtx_trylock_spin_flags(m, opts)					\
	mtx_trylock_spin_flags_((m), (opts), LOCK_FILE, LOCK_LINE)
#define mtx_unlock(m)		mtx_unlock_flags((m), 0)
#define mtx_unlock_spin(m)	mtx_unlock_spin_flags((m), 0)

#define lock_profile_obtain_lock_failed(lo, spin, contested, waittime)	(void)0
#define lock_profile_obtain_lock_success(lo, spin, contested, waittime, file, line)	(void)0
#define CTR0(m, format)			CTR6(m, format, 0, 0, 0, 0, 0, 0)
#define CTR1(m, format, p1)		CTR6(m, format, p1, 0, 0, 0, 0, 0)
#define CTR6(m, format, p1, p2, p3, p4, p5, p6) do {			\
	if (KTR_COMPILE & (m))						\
		ktr_tracepoint((m), "__FILE__", "__LINE__", format,		\
		    (u_long)(p1), (u_long)(p2), (u_long)(p3),		\
		    (u_long)(p4), (u_long)(p5), (u_long)(p6));		\
	} while (0)
#define KTR_STATE0(m, egroup, ident, state)				\
	KTR_EVENT0(m, egroup, ident, "state:\"%s\"", state)
#define KTR_STATE1(m, egroup, ident, state, a0, v0)			\
	KTR_EVENT1(m, egroup, ident, "state:\"%s\"", state, a0, (v0))
#define KTR_STATE2(m, egroup, ident, state, a0, v0, a1, v1)		\
	KTR_EVENT2(m, egroup, ident, "state:\"%s\"", state, a0, (v0), a1, (v1))
#define KTR_STATE3(m, egroup, ident, state, a0, v0, a1, v1, a2, v2)	\
	KTR_EVENT3(m, egroup, ident, "state:\"%s\"",			\
	    state, a0, (v0), a1, (v1), a2, (v2))
#define KTR_STATE4(m, egroup, ident, state, a0, v0, a1, v1, a2, v2, a3, v3)\
	KTR_EVENT4(m, egroup, ident, "state:\"%s\"",			\
	    state, a0, (v0), a1, (v1), a2, (v2), a3, (v3))

#define EVENTHANDLER_DECLARE(name, type)				\
struct eventhandler_entry_ ## name 					\
{									\
	struct eventhandler_entry	ee;				\
	type				eh_func;			\
};									\
struct __hack

#define TSENTER() TSRAW(curthread, TS_ENTER, __func__, NULL)
#define TSENTER2(x) TSRAW(curthread, TS_ENTER, __func__, x)
#define TSEVENT(x) TSRAW(curthread, TS_EVENT, x, NULL)
#define TSEVENT2(x, y) TSRAW(curthread, TS_EVENT, x, y)
#define TSEXEC(p, name) TSRAW_USER(p, (pid_t)(-1), name, NULL)
#define TSEXIT() TSRAW(curthread, TS_EXIT, __func__, NULL)
#define TSEXIT2(x) TSRAW(curthread, TS_EXIT, __func__, x)
#define TSFORK(p, pp) TSRAW_USER(p, pp, NULL, NULL)
#define TSHOLD(x) TSEVENT2("HOLD", x);
#define TSLINE() TSEVENT2("__FILE__", __XSTRING("__LINE__"))
#define TSNAMEI(p, name) TSRAW_USER(p, (pid_t)(-1), NULL, name)
#define TSPROCEXIT(p) TSRAW_USER(p, (pid_t)(-1), NULL, NULL)
#define TSRAW(a, b, c, d) tslog(a, b, c, d)
#define TSRAW_USER(a, b, c, d) tslog_user(a, b, c, d)
#define TSRELEASE(x) TSEVENT2("RELEASE", x);
#define TSTHREAD(td, x) TSRAW(td, TS_THREAD, x, NULL)
#define TSUNWAIT(x) TSEVENT2("UNWAIT", x);
#define TSWAIT(x) TSEVENT2("WAIT", x);
#define SX_DUPOK 0
#define SX_NEW 0
#define SX_NOWITNESS 0
#define sx_try_xlock(s) (1)
#define sx_xlock(s) (1)
#define sx_xunlock(s) (1)

#define TD_IS_IDLETHREAD(td)	((td)->td_flags & TDF_IDLETD)

#define RTP_PRIO_BASE(P)	PRI_BASE(P)
#define RTP_PRIO_IS_REALTIME(P) PRI_IS_REALTIME(P)
#define RTP_PRIO_NEED_RR(P)	PRI_NEED_RR(P)



#define seqc_consistent(seqcp, oldseqc)		({	\
	atomic_thread_fence_acq();			\
	seqc_consistent_no_fence(seqcp, oldseqc);	\
})
#define seqc_consistent_no_fence(seqcp, oldseqc)({	\
	const seqc_t *__seqcp = (seqcp);		\
	seqc_t __oldseqc = (oldseqc);			\
							\
	MPASS(!(seqc_in_modify(__oldseqc)));		\
	__predict_true(*__seqcp == __oldseqc);		\
})
#define seqc_in_modify(seqc)	({			\
	seqc_t __seqc = (seqc);				\
							\
	__predict_false(__seqc & SEQC_MOD);		\
})

#define EV_SET(kevp_, a, b, c, d, e, f) do {	\
	struct kevent *kevp = (kevp_);		\
	(kevp)->ident = (a);			\
	(kevp)->filter = (b);			\
	(kevp)->flags = (c);			\
	(kevp)->fflags = (d);			\
	(kevp)->data = (e);			\
	(kevp)->udata = (f);			\
	(kevp)->ext[0] = 0;			\
	(kevp)->ext[1] = 0;			\
	(kevp)->ext[2] = 0;			\
	(kevp)->ext[3] = 0;			\
} while (0)
#define KNOTE(list, hint, flags)	knote(list, hint, flags)
#define KNOTE_LOCKED(list, hint)	knote(list, hint, KNF_LISTLOCKED)
#define KNOTE_UNLOCKED(list, hint)	knote(list, hint, 0)

#define knlist_clear(knl, islocked)				\
	knlist_cleardel((knl), NULL, (islocked), 0)
#define knlist_delete(knl, td, islocked)			\
	knlist_cleardel((knl), (td), (islocked), 1)
#define cv_broadcast(cvp)	cv_broadcastpri(cvp, 0)
#define TCP_BBR_ACK_COMP_ALG   1096 	
#define TCP_BBR_ALGORITHM     1083 
#define TCP_BBR_DRAIN_INC_EXTRA 1084 
#define TCP_BBR_DRAIN_PG      1070 
#define TCP_BBR_EXTRA_GAIN     1097
#define TCP_BBR_EXTRA_STATE    1107	
#define TCP_BBR_FLOOR_MIN_TSO  1108     
#define TCP_BBR_HDWR_PACE      1105	
#define TCP_BBR_HOLD_TARGET 1078	
#define TCP_BBR_LOWGAIN_FD    1078 
#define TCP_BBR_LOWGAIN_HALF  1077 
#define TCP_BBR_LOWGAIN_THRESH 1076 
#define TCP_BBR_MIN_RTO       1080 
#define TCP_BBR_MIN_TOPACEOUT  1109	
#define TCP_BBR_ONE_RETRAN    1073 
#define TCP_BBR_PACE_CROSS     1090
#define TCP_BBR_PACE_DEL_TAR   1087
#define TCP_BBR_PACE_OH        1077 
#define TCP_BBR_PACE_PER_SEC   1086
#define TCP_BBR_PACE_SEG_MAX   1088
#define TCP_BBR_PACE_SEG_MIN   1089
#define TCP_BBR_POLICER_DETECT 1111	
#define TCP_BBR_PROBE_RTT_GAIN 1101
#define TCP_BBR_PROBE_RTT_INT 1072 
#define TCP_BBR_PROBE_RTT_LEN  1102
#define TCP_BBR_RACK_INIT_RATE 1112	
#define TCP_BBR_RACK_RTT_USE   1098	
#define TCP_BBR_RECFORCE      1068 
#define TCP_BBR_REC_OVER_HPTS 1082 
#define TCP_BBR_RETRAN_WTSO    1099
#define TCP_BBR_RWND_IS_APP   1071 
#define TCP_BBR_SEND_IWND_IN_TSO 1103	
#define TCP_BBR_STARTUP_EXIT_EPOCH 1085 
#define TCP_BBR_STARTUP_LOSS_EXIT 1074	
#define TCP_BBR_STARTUP_PG    1069 
#define TCP_BBR_TMR_PACE_OH    1096	
#define TCP_BBR_TSLIMITS 1076	   
#define TCP_BBR_TSTMP_RAISES   1110	
#define TCP_BBR_UNLIMITED     1083 
#define TCP_BBR_USEDEL_RATE   1079 
#define TCP_BBR_USE_LOWGAIN   1075 
#define TCP_BBR_USE_RACK_CHEAT TCP_BBR_USE_RACK_RR 
#define TCP_BBR_UTTER_MAX_TSO  1106	
#define TCP_DATA_AFTER_CLOSE   1100
#define TCP_DEFER_OPTIONS 1136 
#define TCP_DELACK  	72	
#define TCP_FAST_RSM_HACK 1137 
#define TCP_FIN_IS_RST 73	
#define TCP_FUNCTION_ALIAS 8193	
#define TCP_FUNCTION_BLK 8192	
#define TCP_FUNCTION_NAME_LEN_MAX 32
#define TCP_HDWR_RATE_CAP 1130 
#define TCP_HDWR_UP_ONLY 1132	
#define TCP_IDLE_REDUCE 70	
#define TCP_LOG_LIMIT  74	
#define TCP_NO_PRR         	1122 
#define TCP_PACING_RATE_CAP 1131 
#define TCP_PROC_ACCOUNTING 76	
#define TCP_RACK_ABC_VAL 1133	
#define TCP_RACK_CHEAT_NOT_CONF_RATE TCP_RACK_RR_CONF
#define TCP_RACK_DO_DETECTION  1097	
#define TCP_RACK_DSACK_OPT 1141		
#define TCP_RACK_EARLY_RECOV  1059 
#define TCP_RACK_EARLY_SEG    1060 
#define TCP_RACK_ENABLE_HYSTART 1142	
#define TCP_RACK_GP_INCREASE   1094	
#define TCP_RACK_GP_INCREASE_CA   1114	
#define TCP_RACK_GP_INCREASE_REC  1116	
#define TCP_RACK_GP_INCREASE_SS   1115	
#define TCP_RACK_IDLE_REDUCE_HIGH 1092  
#define TCP_RACK_MBUF_QUEUE   1050 
#define TCP_RACK_MEASURE_CNT 1135 
#define TCP_RACK_MIN_PACE      1093 	
#define TCP_RACK_MIN_PACE_SEG  1094	
#define TCP_RACK_MIN_TO       1058 
#define TCP_RACK_NONRXT_CFG_RATE 1123 
#define TCP_RACK_NO_PUSH_AT_MAX 1126 
#define TCP_RACK_PACE_ALWAYS  1055 
#define TCP_RACK_PACE_MAX_SEG 1054 
#define TCP_RACK_PACE_RATE_CA  1118 
#define TCP_RACK_PACE_RATE_REC  1120 
#define TCP_RACK_PACE_RATE_SS  1119 
#define TCP_RACK_PACE_REDUCE  1053 
#define TCP_RACK_PACE_TO_FILL 1127 
#define TCP_RACK_PACING_BETA 1138	
#define TCP_RACK_PACING_BETA_ECN 1139	
#define TCP_RACK_PKT_DELAY    1064 
#define TCP_RACK_PROFILE 1129	
#define TCP_RACK_PROP_RATE    1056 
#define TCP_RACK_PRR_SENDALOT 1057 
#define TCP_RACK_REORD_FADE   1062 
#define TCP_RACK_REORD_THRESH 1061 
#define TCP_RACK_TIMER_SLOP 1140	
#define TCP_RACK_TLP_INC_VAR  1065 
#define TCP_RACK_TLP_REDUCE   1052 
#define TCP_RACK_TLP_THRESH   1063 
#define TCP_RACK_TLP_USE       1095
#define TCP_REC_ABC_VAL 1134	
#define TCP_REMOTE_UDP_ENCAPS_PORT 71	
#define TCP_SHARED_CWND_ALLOWED 75 	
#define TCP_SHARED_CWND_ENABLE   1124 	
#define TCP_SHARED_CWND_TIME_LIMIT 1128 
#define TCP_TIMELY_DYN_ADJ       1125 
#define TCP_USE_CMP_ACKS 77 	

#define SCTP_ASCONF_SUPPORTED           0x00000028
#define SCTP_AUTHENTICATION     0x0f
#define SCTP_AUTH_ACTIVE_KEY 		0x00000015
#define SCTP_AUTH_CHUNK 		0x00000012
#define SCTP_AUTH_DELETE_KEY 		0x00000016
#define SCTP_AUTH_KEY 			0x00000013
#define SCTP_AUTH_SUPPORTED             0x00000027
#define SCTP_CAUSE_NAT_COLLIDING_STATE  0x00b0
#define SCTP_CAUSE_NAT_MISSING_STATE    0x00b1
#define SCTP_CC_OPT_STEADY_STEP         0x00002002
#define SCTP_CC_RTCC            0x00000003
#define SCTP_CLR_STAT_LOG               0x00001007
#define SCTP_CMT_BASE           1
#define SCTP_CMT_MAX            SCTP_CMT_MPTCP
#define SCTP_CMT_MPTCP          4
#define SCTP_CMT_OFF            0
#define SCTP_CMT_ON_OFF                 0x00001200
#define SCTP_CMT_RPV1           2
#define SCTP_CMT_RPV2           3
#define SCTP_CMT_USE_DAC                0x00001201
#define SCTP_CONNECT_X_COMPLETE         0x00008009
#define SCTP_CONTEXT                    0x0000001a	
#define SCTP_CWR_IN_SAME_WINDOW  0x02
#define SCTP_CWR_REDUCE_OVERRIDE 0x01
#define SCTP_DATA_FIRST_FRAG       0x02
#define SCTP_DATA_FRAG_MASK        0x03
#define SCTP_DATA_LAST_FRAG        0x01
#define SCTP_DATA_MIDDLE_FRAG      0x00
#define SCTP_DATA_NOT_FRAG         0x03
#define SCTP_DATA_SACK_IMMEDIATELY 0x08
#define SCTP_DATA_UNORDERED        0x04
#define SCTP_DEFAULT_PRINFO             0x00000022
#define SCTP_DEFAULT_SNDINFO            0x00000021
#define SCTP_DELAYED_SACK               0x0000000f
#define SCTP_DEL_VRF_ID                 0x00003005
#define SCTP_ECN_SUPPORTED              0x00000025
#define SCTP_ENABLE_CHANGE_ASSOC_REQ 	0x00000004
#define SCTP_ENABLE_RESET_ASSOC_REQ 	0x00000002
#define SCTP_ENABLE_RESET_STREAM_REQ 	0x00000001
#define SCTP_EVENT                      0x0000001e
#define SCTP_EXPLICIT_EOR               0x0000001b
#define SCTP_FRAGMENT_INTERLEAVE        0x00000010
#define SCTP_FRAG_LEVEL_0    0x00000000
#define SCTP_FRAG_LEVEL_1    0x00000001
#define SCTP_FRAG_LEVEL_2    0x00000002
#define SCTP_GET_ADDR_LEN               0x0000800b
#define SCTP_GET_ASOC_VRF               0x00003004
#define SCTP_GET_ASSOC_ID_LIST          0x00000105	
#define SCTP_GET_ASSOC_NUMBER           0x00000104	
#define SCTP_GET_NONCE_VALUES           0x00001105
#define SCTP_GET_PACKET_LOG             0x00004001
#define SCTP_HMAC_IDENT 		0x00000014
#define SCTP_LARGEST_PMTU  65536
#define SCTP_LOCAL_AUTH_CHUNKS 		0x00000103
#define SCTP_LOG_RWND_ENABLE    			0x00100000
#define SCTP_MAXSEG 			0x0000000e
#define SCTP_MAX_COOKIE_LIFE  3600000	
#define SCTP_MAX_CWND                   0x00000032
#define SCTP_MAX_HB_INTERVAL 14400000	
#define SCTP_MAX_SACK_DELAY 500	
#define SCTP_MIN_COOKIE_LIFE     1000	
#define SCTP_MOBILITY_BASE               0x00000001
#define SCTP_MOBILITY_FASTHANDOFF        0x00000002
#define SCTP_MOBILITY_PRIM_DELETED       0x00000004
#define SCTP_NRSACK_SUPPORTED           0x00000030
#define SCTP_PACKED __attribute__((packed))
#define SCTP_PACKET_LOG_SIZE 65536
#define SCTP_PAD_CHUNK          0x84
#define SCTP_PARTIAL_DELIVERY_POINT     0x00000011
#define SCTP_PCB_FLAGS_ADAPTATIONEVNT    0x0000000000010000
#define SCTP_PCB_FLAGS_ASSOC_RESETEVNT   0x0000000020000000
#define SCTP_PCB_FLAGS_AUTHEVNT          0x0000000000040000
#define SCTP_PCB_FLAGS_AUTOCLOSE         0x0000000000000200
#define SCTP_PCB_FLAGS_AUTO_ASCONF       0x0000000000000040
#define SCTP_PCB_FLAGS_CLOSE_IP         0x00040000
#define SCTP_PCB_FLAGS_DONOT_HEARTBEAT   0x0000000000000004
#define SCTP_PCB_FLAGS_DO_ASCONF         0x0000000000000020
#define SCTP_PCB_FLAGS_DO_NOT_PMTUD      0x0000000000000001
#define SCTP_PCB_FLAGS_DRYEVNT           0x0000000004000000
#define SCTP_PCB_FLAGS_EXPLICIT_EOR      0x0000000000400000
#define SCTP_PCB_FLAGS_EXT_RCVINFO       0x0000000000000002	
#define SCTP_PCB_FLAGS_FRAG_INTERLEAVE   0x0000000000000008
#define SCTP_PCB_FLAGS_INTERLEAVE_STRMS  0x0000000000000010
#define SCTP_PCB_FLAGS_MULTIPLE_ASCONFS  0x0000000001000000
#define SCTP_PCB_FLAGS_NEEDS_MAPPED_V4   0x0000000000800000
#define SCTP_PCB_FLAGS_NODELAY           0x0000000000000100
#define SCTP_PCB_FLAGS_NO_FRAGMENT       0x0000000000100000
#define SCTP_PCB_FLAGS_PDAPIEVNT         0x0000000000020000
#define SCTP_PCB_FLAGS_PORTREUSE         0x0000000002000000
#define SCTP_PCB_FLAGS_RECVASSOCEVNT     0x0000000000000800
#define SCTP_PCB_FLAGS_RECVDATAIOEVNT    0x0000000000000400	
#define SCTP_PCB_FLAGS_RECVNSENDFAILEVNT 0x0000000080000000
#define SCTP_PCB_FLAGS_RECVNXTINFO       0x0000000010000000
#define SCTP_PCB_FLAGS_RECVPADDREVNT     0x0000000000001000
#define SCTP_PCB_FLAGS_RECVPEERERR       0x0000000000002000
#define SCTP_PCB_FLAGS_RECVRCVINFO       0x0000000008000000
#define SCTP_PCB_FLAGS_RECVSENDFAILEVNT  0x0000000000004000	
#define SCTP_PCB_FLAGS_RECVSHUTDOWNEVNT  0x0000000000008000
#define SCTP_PCB_FLAGS_SND_ITERATOR_UP  0x00000020
#define SCTP_PCB_FLAGS_STREAM_CHANGEEVNT 0x0000000040000000
#define SCTP_PCB_FLAGS_STREAM_RESETEVNT  0x0000000000080000
#define SCTP_PCB_FLAGS_WAS_ABORTED      0x00100000
#define SCTP_PCB_FLAGS_WAS_CONNECTED    0x00080000
#define SCTP_PEELOFF                    0x0000800a
#define SCTP_PEER_ADDR_PARAMS 		0x0000000a
#define SCTP_PEER_ADDR_THLDS            0x00000023
#define SCTP_PEER_AUTH_CHUNKS 		0x00000102
#define SCTP_PKTDROP_SUPPORTED          0x00000031
#define SCTP_PLUGGABLE_CC               0x00001202
#define SCTP_PR_ASSOC_STATUS            0x00000108
#define SCTP_PR_STREAM_STATUS           0x00000107
#define SCTP_PR_SUPPORTED               0x00000026
#define SCTP_RECONFIG_SUPPORTED         0x00000029
#define SCTP_RECVNXTINFO                0x00000020
#define SCTP_RECVRCVINFO                0x0000001f
#define SCTP_REMOTE_UDP_ENCAPS_PORT     0x00000024
#define SCTP_REUSE_PORT                 0x0000001c	
#define SCTP_SACK_CMT_DAC          0x80
#define SCTP_SACK_NONCE_SUM        0x01
#define SCTP_SAT_NETWORK_BURST_INCR  2	
#define SCTP_SET_DYNAMIC_PRIMARY        0x00002001
#define SCTP_SMALLEST_PMTU 512
#define SCTP_STREAM_RESET       0x82
#define SCTP_TIMEOUTS                   0x00000106

#define INVALID_SINFO_FLAG(x) (((x) & 0xfffffff0 \
                                    & ~(SCTP_EOF | SCTP_ABORT | SCTP_UNORDERED |\
				        SCTP_ADDR_OVER | SCTP_SENDALL | SCTP_EOR |\
					SCTP_SACK_IMMEDIATELY)) != 0)
#define PR_SCTP_BUF_ENABLED(x)    (PR_SCTP_POLICY(x) == SCTP_PR_SCTP_BUF)
#define PR_SCTP_ENABLED(x)        ((PR_SCTP_POLICY(x) != SCTP_PR_SCTP_NONE) && \
                                   (PR_SCTP_POLICY(x) != SCTP_PR_SCTP_ALL))
#define PR_SCTP_INVALID_POLICY(x) (PR_SCTP_POLICY(x) > SCTP_PR_SCTP_MAX)
#define PR_SCTP_POLICY(x)         ((x) & 0x0f)
#define PR_SCTP_RTX_ENABLED(x)    (PR_SCTP_POLICY(x) == SCTP_PR_SCTP_RTX)
#define PR_SCTP_TTL_ENABLED(x)    (PR_SCTP_POLICY(x) == SCTP_PR_SCTP_TTL)
#define PR_SCTP_VALID_POLICY(x)   (PR_SCTP_POLICY(x) <= SCTP_PR_SCTP_MAX)
#define SCTP_ABORT            0x0200	
#define SCTP_ADAPTATION_INDICATION              0x0006
#define SCTP_ADAPTION_INDICATION                0x0006
#define SCTP_ADDR_OVER        0x0800	
#define SCTP_ALIGN_RESV_PAD 92
#define SCTP_ALIGN_RESV_PAD_SHORT 76
#define SCTP_ALL_ASSOC     2
#define SCTP_ASSOC_CHANGE                       0x0001
#define SCTP_ASSOC_RESET_EVENT                  0x000c
#define SCTP_AUTHENTICATION_EVENT               0x0008
#define SCTP_AUTHINFO   0x0008
#define SCTP_CANT_STR_ASSOC     0x0005
#define SCTP_COMM_LOST          0x0002
#define SCTP_COMM_UP            0x0001
#define SCTP_COMPLETE         0x0020	
#define SCTP_CURRENT_ASSOC 1
#define SCTP_DSTADDRV4  0x0009
#define SCTP_DSTADDRV6  0x000a
#define SCTP_EOF              0x0100	
#define SCTP_EOR              0x2000	
#define SCTP_FUTURE_ASSOC  0
#define SCTP_MAX_EXPLICT_STR_RESET   1000
#define SCTP_MAX_LOGGING_SIZE 30000
#define SCTP_NEXT_MSG_AVAIL        0x0001
#define SCTP_NEXT_MSG_ISCOMPLETE   0x0002
#define SCTP_NEXT_MSG_IS_NOTIFICATION 0x0008
#define SCTP_NEXT_MSG_IS_UNORDERED 0x0004
#define SCTP_NOTIFICATION     0x0010	
#define SCTP_NOTIFICATIONS_STOPPED_EVENT        0x000b	
#define SCTP_NO_NEXT_MSG           0x0000
#define SCTP_NXTINFO    0x0006
#define SCTP_PARTIAL_DELIVERY_EVENT             0x0007
#define SCTP_PEER_ADDR_CHANGE                   0x0002
#define SCTP_PRINFO     0x0007
#define SCTP_PR_SCTP_ALL  0x000f	
#define SCTP_PR_SCTP_BUF  SCTP_PR_SCTP_PRIO	
#define SCTP_PR_SCTP_MAX  SCTP_PR_SCTP_RTX
#define SCTP_PR_SCTP_NONE 0x0000	
#define SCTP_PR_SCTP_PRIO 0x0002	
#define SCTP_PR_SCTP_RTX  0x0003	
#define SCTP_PR_SCTP_TTL  0x0001	
#define SCTP_RCVINFO    0x0005
#define SCTP_RECVV_NOINFO  0
#define SCTP_RECVV_NXTINFO 2
#define SCTP_RECVV_RCVINFO 1
#define SCTP_RECVV_RN      3
#define SCTP_REMOTE_ERROR                       0x0003
#define SCTP_RESTART            0x0003
#define SCTP_SACK_IMMEDIATELY 0x4000	
#define SCTP_SENDALL          0x1000	
#define SCTP_SENDER_DRY_EVENT                   0x000a
#define SCTP_SENDV_AUTHINFO 3
#define SCTP_SENDV_NOINFO   0
#define SCTP_SENDV_PRINFO   2
#define SCTP_SENDV_SNDINFO  1
#define SCTP_SENDV_SPA      4
#define SCTP_SEND_AUTHINFO_VALID 0x00000004
#define SCTP_SEND_FAILED                        0x0004
#define SCTP_SEND_FAILED_EVENT                  0x000e
#define SCTP_SEND_PRINFO_VALID   0x00000002
#define SCTP_SEND_SNDINFO_VALID  0x00000001
#define SCTP_SHUTDOWN_COMP      0x0004
#define SCTP_SHUTDOWN_EVENT                     0x0005
#define SCTP_SNDINFO    0x0004
#define SCTP_STAT_DECR(_x) SCTP_STAT_DECR_BY(_x,1)
#define SCTP_STAT_DECR_BY(_x,_d) (SCTP_BASE_STATS[PCPU_GET(cpuid)]._x -= _d)
#define SCTP_STAT_DECR_COUNTER32(_x) SCTP_STAT_DECR(_x)
#define SCTP_STAT_DECR_COUNTER64(_x) SCTP_STAT_DECR(_x)
#define SCTP_STAT_DECR_GAUGE32(_x) SCTP_STAT_DECR(_x)
#define SCTP_STAT_INCR(_x) SCTP_STAT_INCR_BY(_x,1)
#define SCTP_STAT_INCR_BY(_x,_d) (SCTP_BASE_STATS[PCPU_GET(cpuid)]._x += _d)
#define SCTP_STAT_INCR_COUNTER32(_x) SCTP_STAT_INCR(_x)
#define SCTP_STAT_INCR_COUNTER64(_x) SCTP_STAT_INCR(_x)
#define SCTP_STAT_INCR_GAUGE32(_x) SCTP_STAT_INCR(_x)
#define SCTP_STREAM_CHANGE_EVENT                0x000d
#define SCTP_STREAM_RESET_DENIED        0x0004
#define SCTP_STREAM_RESET_EVENT                 0x0009
#define SCTP_STREAM_RESET_FAILED        0x0008
#define SCTP_STREAM_RESET_INCOMING_SSN  0x0001
#define SCTP_STREAM_RESET_OUTGOING_SSN  0x0002
#define SCTP_TRACE_PARAMS 6	
#define SCTP_UNORDERED        0x0400	
#define SPP_DSCP                0x00000200
#define SPP_HB_TIME_IS_ZERO     0x00000080
#define SPP_IPV4_TOS            SPP_DSCP
#define SPP_IPV6_FLOWLABEL      0x00000100

#define htonll(x) htobe64(x)
#define ntohll(x) be64toh(x)
#define sctp_stream_reset_events sctp_stream_reset_event
#define sinfo_pr_value sinfo_timetolive
#define spp_ipv4_tos spp_dscp
#define sreinfo_next_aid serinfo_next_aid
#define sreinfo_next_flags serinfo_next_flags
#define sreinfo_next_length serinfo_next_length
#define sreinfo_next_ppid serinfo_next_ppid
#define sreinfo_next_stream serinfo_next_stream


#define IN_LINKLOCAL(i)		(((in_addr_t)(i) & 0xffff0000) == 0xa9fe0000)
#define IN_LOOPBACK(i)		(((in_addr_t)(i) & 0xff000000) == 0x7f000000)
#define IN_ZERONET(i)		(((in_addr_t)(i) & 0xff000000) == 0)
#define IP_FW_NAT_CFG           56   
#define IP_FW_NAT_DEL           57   
#define IP_FW_NAT_GET_CONFIG    58   
#define IP_FW_NAT_GET_LOG       59   

#define IFA6_IS_DEPRECATED(a) \
	((a)->ia6_lifetime.ia6t_pltime != ND6_INFINITE_LIFETIME && \
	 (u_int32_t)((time_uptime - (a)->ia6_updatetime)) > \
	 (a)->ia6_lifetime.ia6t_pltime)
#define IFA6_IS_INVALID(a) \
	((a)->ia6_lifetime.ia6t_vltime != ND6_INFINITE_LIFETIME && \
	 (u_int32_t)((time_uptime - (a)->ia6_updatetime)) > \
	 (a)->ia6_lifetime.ia6t_vltime)
#define IN6ADDR_ANY_INIT \
	{{{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }}}
#define IN6ADDR_INTFACELOCAL_ALLNODES_INIT \
	{{{ 0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }}}
#define IN6ADDR_LINKLOCAL_ALLNODES_INIT \
	{{{ 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }}}
#define IN6ADDR_LINKLOCAL_ALLROUTERS_INIT \
	{{{ 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 }}}
#define IN6ADDR_LINKLOCAL_ALLV2ROUTERS_INIT \
	{{{ 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16 }}}
#define IN6ADDR_LOOPBACK_INIT \
	{{{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }}}
#define IN6ADDR_NODELOCAL_ALLNODES_INIT \
	{{{ 0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }}}
#define IN6_ARE_ADDR_EQUAL(a, b)			\
    (bcmp(&(a)->s6_addr[0], &(b)->s6_addr[0], sizeof(struct in6_addr)) == 0)
#define IN6_IS_ADDR_LINKLOCAL(a)	\
	(((a)->s6_addr[0] == 0xfe) && (((a)->s6_addr[1] & 0xc0) == 0x80))
#define IN6_IS_ADDR_LOOPBACK(a)		\
	((a)->__u6_addr.__u6_addr32[0] == 0 &&	\
	 (a)->__u6_addr.__u6_addr32[1] == 0 &&	\
	 (a)->__u6_addr.__u6_addr32[2] == 0 &&	\
	 (a)->__u6_addr.__u6_addr32[3] == ntohl(1))
#define IN6_IS_ADDR_MC_GLOBAL(a)	\
	(IN6_IS_ADDR_MULTICAST(a) &&	\
	 (IPV6_ADDR_MC_SCOPE(a) == IPV6_ADDR_SCOPE_GLOBAL))
#define IN6_IS_ADDR_MC_INTFACELOCAL(a)	\
	(IN6_IS_ADDR_MULTICAST(a) &&	\
	 (IPV6_ADDR_MC_SCOPE(a) == IPV6_ADDR_SCOPE_INTFACELOCAL))
#define IN6_IS_ADDR_MC_LINKLOCAL(a)	\
	(IN6_IS_ADDR_MULTICAST(a) &&	\
	 (IPV6_ADDR_MC_SCOPE(a) == IPV6_ADDR_SCOPE_LINKLOCAL))
#define IN6_IS_ADDR_MC_NODELOCAL(a)	\
	(IN6_IS_ADDR_MULTICAST(a) &&	\
	 (IPV6_ADDR_MC_SCOPE(a) == IPV6_ADDR_SCOPE_NODELOCAL))
#define IN6_IS_ADDR_MC_ORGLOCAL(a)	\
	(IN6_IS_ADDR_MULTICAST(a) &&	\
	 (IPV6_ADDR_MC_SCOPE(a) == IPV6_ADDR_SCOPE_ORGLOCAL))
#define IN6_IS_ADDR_MC_SITELOCAL(a)	\
	(IN6_IS_ADDR_MULTICAST(a) &&	\
	 (IPV6_ADDR_MC_SCOPE(a) == IPV6_ADDR_SCOPE_SITELOCAL))
#define IN6_IS_ADDR_MULTICAST(a)	((a)->s6_addr[0] == 0xff)
#define IN6_IS_ADDR_SITELOCAL(a)	\
	(((a)->s6_addr[0] == 0xfe) && (((a)->s6_addr[1] & 0xc0) == 0xc0))
#define IN6_IS_ADDR_UNSPECIFIED(a)	\
	((a)->__u6_addr.__u6_addr32[0] == 0 &&	\
	 (a)->__u6_addr.__u6_addr32[1] == 0 &&	\
	 (a)->__u6_addr.__u6_addr32[2] == 0 &&	\
	 (a)->__u6_addr.__u6_addr32[3] == 0)
#define IN6_IS_ADDR_V4COMPAT(a)		\
	((a)->__u6_addr.__u6_addr32[0] == 0 &&	\
	 (a)->__u6_addr.__u6_addr32[1] == 0 &&	\
	 (a)->__u6_addr.__u6_addr32[2] == 0 &&	\
	 (a)->__u6_addr.__u6_addr32[3] != 0 &&	\
	 (a)->__u6_addr.__u6_addr32[3] != ntohl(1))
#define IN6_IS_ADDR_V4MAPPED(a)		      \
	((a)->__u6_addr.__u6_addr32[0] == 0 &&	\
	 (a)->__u6_addr.__u6_addr32[1] == 0 &&	\
	 (a)->__u6_addr.__u6_addr32[2] == ntohl(0x0000ffff))
#define IN6_IS_SCOPE_LINKLOCAL(a)	\
	((IN6_IS_ADDR_LINKLOCAL(a)) ||	\
	 (IN6_IS_ADDR_MC_LINKLOCAL(a)))
#define IPV6CTL_SOURCECHECK_LOGINT 11	
#define IPV6_ADDR_MC_SCOPE(a)		((a)->s6_addr[1] & 0x0f)
#define IPV6_DEFAULT_MULTICAST_HOPS 1	
#define IPV6_DEFAULT_MULTICAST_LOOP 1	
#define IPV6_RTHDR_LOOSE     0 
#define IPV6_RTHDR_STRICT    1 
#define IPV6_RTHDR_TYPE_0    0 


#define __IPV6_ADDR_MC_SCOPE(a)		((a)->s6_addr[1] & 0x0f)

#define s6_addr   __u6_addr.__u6_addr8
#define s6_addr16 __u6_addr.__u6_addr16
#define s6_addr32 __u6_addr.__u6_addr32
#define s6_addr8  __u6_addr.__u6_addr8
#define ACCEPT4_COMPAT  0x2
#define ACCEPT4_INHERIT 0x1
#define AF_VENDOR00 39
#define AF_VENDOR01 41
#define AF_VENDOR03 45
#define AF_VENDOR04 47
#define AF_VENDOR05 49
#define AF_VENDOR06 51
#define AF_VENDOR07 53
#define AF_VENDOR08 55
#define AF_VENDOR09 57
#define AF_VENDOR10 59
#define AF_VENDOR11 61
#define AF_VENDOR12 63
#define AF_VENDOR13 65
#define AF_VENDOR14 67
#define AF_VENDOR15 69
#define AF_VENDOR16 71
#define AF_VENDOR17 73
#define AF_VENDOR18 75
#define AF_VENDOR19 77
#define AF_VENDOR20 79
#define AF_VENDOR21 81
#define AF_VENDOR22 83
#define AF_VENDOR23 85
#define AF_VENDOR24 87
#define AF_VENDOR25 89
#define AF_VENDOR26 91
#define AF_VENDOR27 93
#define AF_VENDOR28 95
#define AF_VENDOR29 97
#define AF_VENDOR30 99
#define AF_VENDOR31 101
#define AF_VENDOR32 103
#define AF_VENDOR33 105
#define AF_VENDOR34 107
#define AF_VENDOR35 109
#define AF_VENDOR36 111
#define AF_VENDOR37 113
#define AF_VENDOR38 115
#define AF_VENDOR39 117
#define AF_VENDOR40 119
#define AF_VENDOR41 121
#define AF_VENDOR42 123
#define AF_VENDOR43 125
#define AF_VENDOR44 127
#define AF_VENDOR45 129
#define AF_VENDOR46 131
#define AF_VENDOR47 133
#define CMGROUP_MAX 16
#define PRU_FLUSH_RD     SHUT_RD
#define PRU_FLUSH_RDWR   SHUT_RDWR
#define PRU_FLUSH_WR     SHUT_WR
#define pseudo_AF_HDRCMPLT 31		
#define IP_HDR_ALIGNED_P(ip)	1
#define EPOCH_LOCKED 0x2
#define EPOCH_PREEMPT 0x1

#define epoch_enter_preempt(epoch, et)	_epoch_enter_preempt(epoch, et)
#define		ICMP_PARAMPROB_ERRATPTR 0		
#define		ICMP_PARAMPROB_LENGTH 2			
#define		ICMP_PARAMPROB_OPTABSENT 1		
#define		ICMP_UNREACH_FILTER_PROHIB 13		
#define		ICMP_UNREACH_HOST_PRECEDENCE 14		
#define		ICMP_UNREACH_HOST_PROHIB 10		
#define		ICMP_UNREACH_HOST_UNKNOWN 7		
#define		ICMP_UNREACH_NET_UNKNOWN 6		
#define		ICMP_UNREACH_PRECEDENCE_CUTOFF 15	

#define IA_DSTSIN(ia) (&(((struct in_ifaddr *)(ia))->ia_dstaddr))
#define IA_MASKSIN(ia) (&(((struct in_ifaddr *)(ia))->ia_sockmask))
#define IA_SIN(ia)    (&(((struct in_ifaddr *)(ia))->ia_addr))
#define IFP_TO_IA(ifp, ia)						\
						\
						\
do {									\
	NET_EPOCH_ASSERT();						\
	for ((ia) = CK_STAILQ_FIRST(&V_in_ifaddrhead);			\
	    (ia) != NULL && (ia)->ia_ifp != (ifp);			\
	    (ia) = CK_STAILQ_NEXT((ia), ia_link))			\
		continue;						\
} while (0)
#define INADDR_HASH(x) \
	(&V_in_ifaddrhashtbl[INADDR_HASHVAL(x) & V_in_ifaddrhmask])
#define INADDR_HASHVAL(x)	fnv_32_buf((&(x)), sizeof(x), FNV1_32_INIT)
#define INADDR_NHASH_LOG2       9
#define INADDR_TO_IFADDR(addr, ia) \
	 \
	 \
do {									\
	NET_EPOCH_ASSERT();						\
	CK_LIST_FOREACH(ia, INADDR_HASH((addr).s_addr), ia_hash)	\
		if (IA_SIN(ia)->sin_addr.s_addr == (addr).s_addr)	\
			break;						\
} while (0)
#define INADDR_TO_IFP(addr, ifp) \
	 \
	 \
{ \
	struct in_ifaddr *ia; \
\
	INADDR_TO_IFADDR(addr, ia); \
	(ifp) = (ia == NULL) ? NULL : ia->ia_ifp; \
}
#define IN_LNAOF(in, ifa) \
	((ntohl((in).s_addr) & ~((struct in_ifaddr *)(ifa)->ia_subnetmask))
#define LLTABLE(ifp)	\
	((struct in_ifinfo *)(ifp)->if_afdata[AF_INET])->ii_llt

#define ifra_dstaddr ifra_broadaddr
#define IA6_DSTIN6(ia)	(&((ia)->ia_dstaddr.sin6_addr))
#define IA6_DSTSIN6(ia)	(&((ia)->ia_dstaddr))
#define IA6_IN6(ia)	(&((ia)->ia_addr.sin6_addr))
#define IA6_MASKIN6(ia)	(&((ia)->ia_prefixmask.sin6_addr))
#define IA6_SIN6(ia)	(&((ia)->ia_addr))
#define IFA_DSTIN6(x)	(&((struct sockaddr_in6 *)((x)->ifa_dstaddr))->sin6_addr)
#define IFA_IN6(x)	(&((struct sockaddr_in6 *)((x)->ifa_addr))->sin6_addr)
#define IFA_MASKIN6(x)	(&((struct sockaddr_in6 *)((x)->ifa_netmask))->sin6_addr)
#define IFPR_IN6(x)	(&((struct sockaddr_in6 *)((x)->ifpr_prefix))->sin6_addr)
#define IN6_ARE_MASKED_ADDR_EQUAL(d, a, m)	(	\
	(((d)->s6_addr32[0] ^ (a)->s6_addr32[0]) & (m)->s6_addr32[0]) == 0 && \
	(((d)->s6_addr32[1] ^ (a)->s6_addr32[1]) & (m)->s6_addr32[1]) == 0 && \
	(((d)->s6_addr32[2] ^ (a)->s6_addr32[2]) & (m)->s6_addr32[2]) == 0 && \
	(((d)->s6_addr32[3] ^ (a)->s6_addr32[3]) & (m)->s6_addr32[3]) == 0 )
#define IN6_ARE_SCOPE_CMP(a,b) ((a)-(b))
#define IN6_ARE_SCOPE_EQUAL(a,b) ((a)==(b))
#define IN6_IFF_NOTREADY (IN6_IFF_TENTATIVE|IN6_IFF_DUPLICATED)
#define IN6_MASK_ADDR(a, m)	do { \
	(a)->s6_addr32[0] &= (m)->s6_addr32[0]; \
	(a)->s6_addr32[1] &= (m)->s6_addr32[1]; \
	(a)->s6_addr32[2] &= (m)->s6_addr32[2]; \
	(a)->s6_addr32[3] &= (m)->s6_addr32[3]; \
} while (0)
#define SIOCSIFPHYADDR_IN6       _IOW('i', 70, struct in6_aliasreq)

#define in6_ifstat_inc(ifp, tag) \
do {								\
	if (ifp)						\
		counter_u64_add(((struct in6_ifextra *)		\
		    ((ifp)->if_afdata[AF_INET6]))->in6_ifstat[	\
		    offsetof(struct in6_ifstat, tag) / sizeof(uint64_t)], 1);\
} while ( 0)
#define FNV1_32_INIT ((Fnv32_t) 33554467UL)
#define FNV1_64_INIT ((Fnv64_t) 0xcbf29ce484222325ULL)
#define FNV_32_PRIME ((Fnv32_t) 0x01000193UL)
#define FNV_64_PRIME ((Fnv64_t) 0x100000001b3ULL)
#define RB_AUGMENT(x)	break
#define RB_BITS(elm, field)		(*(__uintptr_t *)&RB_UP(elm, field))
#define RB_COLOR(elm, field)	(RB_PARENT(elm, field) == NULL ? 0 :	\
				RB_LEFT(RB_PARENT(elm, field), field) == elm ? \
				RB_RED_LEFT(RB_PARENT(elm, field), field) : \
				RB_RED_RIGHT(RB_PARENT(elm, field), field))
#define RB_EMPTY(head)			(RB_ROOT(head) == NULL)
#define RB_ENTRY(type)							\
struct {								\
	struct type *rbe_left;				\
	struct type *rbe_right;				\
	struct type *rbe_parent;			\
}
#define RB_FIND(name, x, y)	name##_RB_FIND(x, y)
#define RB_FLIP_LEFT(elm, field)	(RB_BITS(elm, field) ^= RB_RED_L)
#define RB_FLIP_RIGHT(elm, field)	(RB_BITS(elm, field) ^= RB_RED_R)
#define RB_FOREACH(x, name, head)					\
	for ((x) = RB_MIN(name, head);					\
	     (x) != NULL;						\
	     (x) = name##_RB_NEXT(x))
#define RB_FOREACH_FROM(x, name, y)					\
	for ((x) = (y);							\
	    ((x) != NULL) && ((y) = name##_RB_NEXT(x), (x) != NULL);	\
	     (x) = (y))
#define RB_FOREACH_REVERSE(x, name, head)				\
	for ((x) = RB_MAX(name, head);					\
	     (x) != NULL;						\
	     (x) = name##_RB_PREV(x))
#define RB_FOREACH_REVERSE_FROM(x, name, y)				\
	for ((x) = (y);							\
	    ((x) != NULL) && ((y) = name##_RB_PREV(x), (x) != NULL);	\
	     (x) = (y))
#define RB_FOREACH_REVERSE_SAFE(x, name, head, y)			\
	for ((x) = RB_MAX(name, head);					\
	    ((x) != NULL) && ((y) = name##_RB_PREV(x), (x) != NULL);	\
	     (x) = (y))
#define RB_FOREACH_SAFE(x, name, head, y)				\
	for ((x) = RB_MIN(name, head);					\
	    ((x) != NULL) && ((y) = name##_RB_NEXT(x), (x) != NULL);	\
	     (x) = (y))
#define RB_GENERATE_FIND(name, type, field, cmp, attr)			\
				\
attr struct type *							\
name##_RB_FIND(struct name *head, struct type *elm)			\
{									\
	struct type *tmp = RB_ROOT(head);				\
	int comp;							\
	while (tmp) {							\
		comp = cmp(elm, tmp);					\
		if (comp < 0)						\
			tmp = RB_LEFT(tmp, field);			\
		else if (comp > 0)					\
			tmp = RB_RIGHT(tmp, field);			\
		else							\
			return (tmp);					\
	}								\
	return (NULL);							\
}
#define RB_GENERATE_INSERT(name, type, field, cmp, attr)		\
					\
attr struct type *							\
name##_RB_INSERT(struct name *head, struct type *elm)			\
{									\
	struct type *tmp;						\
	struct type *parent = NULL;					\
	int comp = 0;							\
	tmp = RB_ROOT(head);						\
	while (tmp) {							\
		parent = tmp;						\
		comp = (cmp)(elm, parent);				\
		if (comp < 0)						\
			tmp = RB_LEFT(tmp, field);			\
		else if (comp > 0)					\
			tmp = RB_RIGHT(tmp, field);			\
		else							\
			return (tmp);					\
	}								\
	RB_SET(elm, parent, field);					\
	if (parent == NULL)						\
		RB_ROOT(head) = elm;					\
	else if (comp < 0)						\
		RB_LEFT(parent, field) = elm;				\
	else								\
		RB_RIGHT(parent, field) = elm;				\
	name##_RB_INSERT_COLOR(head, elm);				\
	while (elm != NULL) {						\
		RB_AUGMENT(elm);					\
		elm = RB_PARENT(elm, field);				\
	}								\
	return (NULL);							\
}
#define RB_GENERATE_INSERT_COLOR(name, type, field, attr)		\
attr void								\
name##_RB_INSERT_COLOR(struct name *head, struct type *elm)		\
{									\
	struct type *child, *parent;					\
	while ((parent = RB_PARENT(elm, field)) != NULL) {		\
		if (RB_LEFT(parent, field) == elm) {			\
			if (RB_RED_LEFT(parent, field)) {		\
				RB_FLIP_LEFT(parent, field);		\
				return;					\
			}						\
			RB_FLIP_RIGHT(parent, field);			\
			if (RB_RED_RIGHT(parent, field)) {		\
				elm = parent;				\
				continue;				\
			}						\
			if (!RB_RED_RIGHT(elm, field)) {		\
				RB_FLIP_LEFT(elm, field);		\
				RB_ROTATE_LEFT(head, elm, child, field);\
				if (RB_RED_LEFT(child, field))		\
					RB_FLIP_RIGHT(elm, field);	\
				else if (RB_RED_RIGHT(child, field))	\
					RB_FLIP_LEFT(parent, field);	\
				elm = child;				\
			}						\
			RB_ROTATE_RIGHT(head, parent, elm, field);	\
		} else {						\
			if (RB_RED_RIGHT(parent, field)) {		\
				RB_FLIP_RIGHT(parent, field);		\
				return;					\
			}						\
			RB_FLIP_LEFT(parent, field);			\
			if (RB_RED_LEFT(parent, field)) {		\
				elm = parent;				\
				continue;				\
			}						\
			if (!RB_RED_LEFT(elm, field)) {			\
				RB_FLIP_RIGHT(elm, field);		\
				RB_ROTATE_RIGHT(head, elm, child, field);\
				if (RB_RED_RIGHT(child, field))		\
					RB_FLIP_LEFT(elm, field);	\
				else if (RB_RED_LEFT(child, field))	\
					RB_FLIP_RIGHT(parent, field);	\
				elm = child;				\
			}						\
			RB_ROTATE_LEFT(head, parent, elm, field);	\
		}							\
		RB_BITS(elm, field) &= ~RB_RED_MASK;			\
		break;							\
	}								\
}
#define RB_GENERATE_INTERNAL(name, type, field, cmp, attr)		\
	RB_GENERATE_INSERT_COLOR(name, type, field, attr)		\
	RB_GENERATE_REMOVE_COLOR(name, type, field, attr)		\
	RB_GENERATE_INSERT(name, type, field, cmp, attr)		\
	RB_GENERATE_REMOVE(name, type, field, attr)			\
	RB_GENERATE_FIND(name, type, field, cmp, attr)			\
	RB_GENERATE_NFIND(name, type, field, cmp, attr)			\
	RB_GENERATE_NEXT(name, type, field, attr)			\
	RB_GENERATE_PREV(name, type, field, attr)			\
	RB_GENERATE_MINMAX(name, type, field, attr)			\
	RB_GENERATE_REINSERT(name, type, field, cmp, attr)
#define RB_GENERATE_MINMAX(name, type, field, attr)			\
attr struct type *							\
name##_RB_MINMAX(struct name *head, int val)				\
{									\
	struct type *tmp = RB_ROOT(head);				\
	struct type *parent = NULL;					\
	while (tmp) {							\
		parent = tmp;						\
		if (val < 0)						\
			tmp = RB_LEFT(tmp, field);			\
		else							\
			tmp = RB_RIGHT(tmp, field);			\
	}								\
	return (parent);						\
}
#define RB_GENERATE_NEXT(name, type, field, attr)			\
								\
attr struct type *							\
name##_RB_NEXT(struct type *elm)					\
{									\
	if (RB_RIGHT(elm, field)) {					\
		elm = RB_RIGHT(elm, field);				\
		while (RB_LEFT(elm, field))				\
			elm = RB_LEFT(elm, field);			\
	} else {							\
		if (RB_PARENT(elm, field) &&				\
		    (elm == RB_LEFT(RB_PARENT(elm, field), field)))	\
			elm = RB_PARENT(elm, field);			\
		else {							\
			while (RB_PARENT(elm, field) &&			\
			    (elm == RB_RIGHT(RB_PARENT(elm, field), field)))\
				elm = RB_PARENT(elm, field);		\
			elm = RB_PARENT(elm, field);			\
		}							\
	}								\
	return (elm);							\
}
#define RB_GENERATE_NFIND(name, type, field, cmp, attr)			\
	\
attr struct type *							\
name##_RB_NFIND(struct name *head, struct type *elm)			\
{									\
	struct type *tmp = RB_ROOT(head);				\
	struct type *res = NULL;					\
	int comp;							\
	while (tmp) {							\
		comp = cmp(elm, tmp);					\
		if (comp < 0) {						\
			res = tmp;					\
			tmp = RB_LEFT(tmp, field);			\
		}							\
		else if (comp > 0)					\
			tmp = RB_RIGHT(tmp, field);			\
		else							\
			return (tmp);					\
	}								\
	return (res);							\
}
#define RB_GENERATE_PREV(name, type, field, attr)			\
								\
attr struct type *							\
name##_RB_PREV(struct type *elm)					\
{									\
	if (RB_LEFT(elm, field)) {					\
		elm = RB_LEFT(elm, field);				\
		while (RB_RIGHT(elm, field))				\
			elm = RB_RIGHT(elm, field);			\
	} else {							\
		if (RB_PARENT(elm, field) &&				\
		    (elm == RB_RIGHT(RB_PARENT(elm, field), field)))	\
			elm = RB_PARENT(elm, field);			\
		else {							\
			while (RB_PARENT(elm, field) &&			\
			    (elm == RB_LEFT(RB_PARENT(elm, field), field)))\
				elm = RB_PARENT(elm, field);		\
			elm = RB_PARENT(elm, field);			\
		}							\
	}								\
	return (elm);							\
}
#define RB_GENERATE_REMOVE(name, type, field, attr)			\
attr struct type *							\
name##_RB_REMOVE(struct name *head, struct type *elm)			\
{									\
	struct type *child, *old, *parent, *right;			\
									\
	old = elm;							\
	parent = RB_PARENT(elm, field);					\
	right = RB_RIGHT(elm, field);					\
	if (RB_LEFT(elm, field) == NULL)				\
		elm = child = right;					\
	else if (right == NULL)						\
		elm = child = RB_LEFT(elm, field);			\
	else {								\
		if ((child = RB_LEFT(right, field)) == NULL) {		\
			child = RB_RIGHT(right, field);			\
			RB_RIGHT(old, field) = child;			\
			parent = elm = right;				\
		} else {						\
			do						\
				elm = child;				\
			while ((child = RB_LEFT(elm, field)) != NULL);	\
			child = RB_RIGHT(elm, field);			\
			parent = RB_PARENT(elm, field);			\
			RB_LEFT(parent, field) = child;			\
			RB_SET_PARENT(RB_RIGHT(old, field), elm, field);\
		}							\
		RB_SET_PARENT(RB_LEFT(old, field), elm, field);		\
		elm->field = old->field;				\
	}								\
	RB_SWAP_CHILD(head, old, elm, field);				\
	if (child != NULL)						\
		RB_SET_PARENT(child, parent, field);			\
	if (parent != NULL)						\
		name##_RB_REMOVE_COLOR(head, parent, child);		\
	while (parent != NULL) {					\
		RB_AUGMENT(parent);					\
		parent = RB_PARENT(parent, field);			\
	}								\
	return (old);							\
}
#define RB_GENERATE_REMOVE_COLOR(name, type, field, attr)		\
attr void								\
name##_RB_REMOVE_COLOR(struct name *head,				\
    struct type *parent, struct type *elm)				\
{									\
	struct type *sib;						\
	if (RB_LEFT(parent, field) == elm &&				\
	    RB_RIGHT(parent, field) == elm) {				\
		RB_BITS(parent, field) &= ~RB_RED_MASK;			\
		elm = parent;						\
		parent = RB_PARENT(elm, field);				\
		if (parent == NULL)					\
			return;						\
	}								\
	do  {								\
		if (RB_LEFT(parent, field) == elm) {			\
			if (!RB_RED_LEFT(parent, field)) {		\
				RB_FLIP_LEFT(parent, field);		\
				return;					\
			}						\
			if (RB_RED_RIGHT(parent, field)) {		\
				RB_FLIP_RIGHT(parent, field);		\
				elm = parent;				\
				continue;				\
			}						\
			sib = RB_RIGHT(parent, field);			\
			if ((~RB_BITS(sib, field) & RB_RED_MASK) == 0) {\
				RB_BITS(sib, field) &= ~RB_RED_MASK;	\
				elm = parent;				\
				continue;				\
			}						\
			RB_FLIP_RIGHT(sib, field);			\
			if (RB_RED_LEFT(sib, field))			\
				RB_FLIP_LEFT(parent, field);		\
			else if (!RB_RED_RIGHT(sib, field)) {		\
				RB_FLIP_LEFT(parent, field);		\
				RB_ROTATE_RIGHT(head, sib, elm, field);	\
				if (RB_RED_RIGHT(elm, field))		\
					RB_FLIP_LEFT(sib, field);	\
				if (RB_RED_LEFT(elm, field))		\
					RB_FLIP_RIGHT(parent, field);	\
				RB_BITS(elm, field) |= RB_RED_MASK;	\
				sib = elm;				\
			}						\
			RB_ROTATE_LEFT(head, parent, sib, field);	\
		} else {						\
			if (!RB_RED_RIGHT(parent, field)) {		\
				RB_FLIP_RIGHT(parent, field);		\
				return;					\
			}						\
			if (RB_RED_LEFT(parent, field)) {		\
				RB_FLIP_LEFT(parent, field);		\
				elm = parent;				\
				continue;				\
			}						\
			sib = RB_LEFT(parent, field);			\
			if ((~RB_BITS(sib, field) & RB_RED_MASK) == 0) {\
				RB_BITS(sib, field) &= ~RB_RED_MASK;	\
				elm = parent;				\
				continue;				\
			}						\
			RB_FLIP_LEFT(sib, field);			\
			if (RB_RED_RIGHT(sib, field))			\
				RB_FLIP_RIGHT(parent, field);		\
			else if (!RB_RED_LEFT(sib, field)) {		\
				RB_FLIP_RIGHT(parent, field);		\
				RB_ROTATE_LEFT(head, sib, elm, field);	\
				if (RB_RED_LEFT(elm, field))		\
					RB_FLIP_RIGHT(sib, field);	\
				if (RB_RED_RIGHT(elm, field))		\
					RB_FLIP_LEFT(parent, field);	\
				RB_BITS(elm, field) |= RB_RED_MASK;	\
				sib = elm;				\
			}						\
			RB_ROTATE_RIGHT(head, parent, sib, field);	\
		}							\
		break;							\
	} while ((parent = RB_PARENT(elm, field)) != NULL);		\
}
#define RB_HEAD(name, type)						\
struct name {								\
	struct type *rbh_root; 			\
}
#define RB_INIT(root) do {						\
	(root)->rbh_root = NULL;					\
} while ( 0)
#define RB_INITIALIZER(root)						\
	{ NULL }
#define RB_INSERT(name, x, y)	name##_RB_INSERT(x, y)
#define RB_LEFT(elm, field)		(elm)->field.rbe_left
#define RB_MAX(name, x)		name##_RB_MINMAX(x, RB_INF)
#define RB_MIN(name, x)		name##_RB_MINMAX(x, RB_NEGINF)
#define RB_NEXT(name, x, y)	name##_RB_NEXT(y)
#define RB_NFIND(name, x, y)	name##_RB_NFIND(x, y)
#define RB_PARENT(elm, field)		((__typeof(RB_UP(elm, field)))	\
					 (RB_BITS(elm, field) & ~RB_RED_MASK))
#define RB_PREV(name, x, y)	name##_RB_PREV(y)
#define RB_PROTOTYPE_FIND(name, type, attr)				\
	attr struct type *name##_RB_FIND(struct name *, struct type *)
#define RB_PROTOTYPE_INSERT(name, type, attr)				\
	attr struct type *name##_RB_INSERT(struct name *, struct type *)
#define RB_PROTOTYPE_INSERT_COLOR(name, type, attr)			\
	attr void name##_RB_INSERT_COLOR(struct name *, struct type *)
#define RB_PROTOTYPE_INTERNAL(name, type, field, cmp, attr)		\
	RB_PROTOTYPE_INSERT_COLOR(name, type, attr);			\
	RB_PROTOTYPE_REMOVE_COLOR(name, type, attr);			\
	RB_PROTOTYPE_INSERT(name, type, attr);				\
	RB_PROTOTYPE_REMOVE(name, type, attr);				\
	RB_PROTOTYPE_FIND(name, type, attr);				\
	RB_PROTOTYPE_NFIND(name, type, attr);				\
	RB_PROTOTYPE_NEXT(name, type, attr);				\
	RB_PROTOTYPE_PREV(name, type, attr);				\
	RB_PROTOTYPE_MINMAX(name, type, attr);				\
	RB_PROTOTYPE_REINSERT(name, type, attr);
#define RB_PROTOTYPE_MINMAX(name, type, attr)				\
	attr struct type *name##_RB_MINMAX(struct name *, int)
#define RB_PROTOTYPE_NEXT(name, type, attr)				\
	attr struct type *name##_RB_NEXT(struct type *)
#define RB_PROTOTYPE_NFIND(name, type, attr)				\
	attr struct type *name##_RB_NFIND(struct name *, struct type *)
#define RB_PROTOTYPE_PREV(name, type, attr)				\
	attr struct type *name##_RB_PREV(struct type *)
#define RB_PROTOTYPE_REINSERT(name, type, attr)			\
	attr struct type *name##_RB_REINSERT(struct name *, struct type *)
#define RB_PROTOTYPE_REMOVE(name, type, attr)				\
	attr struct type *name##_RB_REMOVE(struct name *, struct type *)
#define RB_PROTOTYPE_REMOVE_COLOR(name, type, attr)			\
	attr void name##_RB_REMOVE_COLOR(struct name *,			\
	    struct type *, struct type *)
#define RB_RED_LEFT(elm, field)		((RB_BITS(elm, field) & RB_RED_L) != 0)
#define RB_RED_RIGHT(elm, field)	((RB_BITS(elm, field) & RB_RED_R) != 0)
#define RB_REINSERT(name, x, y)	name##_RB_REINSERT(x, y)
#define RB_REMOVE(name, x, y)	name##_RB_REMOVE(x, y)
#define RB_RIGHT(elm, field)		(elm)->field.rbe_right
#define RB_ROOT(head)			(head)->rbh_root
#define RB_ROTATE_LEFT(head, elm, tmp, field) do {			\
	(tmp) = RB_RIGHT(elm, field);					\
	if ((RB_RIGHT(elm, field) = RB_LEFT(tmp, field)) != NULL) {	\
		RB_SET_PARENT(RB_RIGHT(elm, field), elm, field);	\
	}								\
	RB_SET_PARENT(tmp, RB_PARENT(elm, field), field);		\
	RB_SWAP_CHILD(head, elm, tmp, field);				\
	RB_LEFT(tmp, field) = (elm);					\
	RB_SET_PARENT(elm, tmp, field);					\
	RB_AUGMENT(elm);						\
} while ( 0)
#define RB_ROTATE_RIGHT(head, elm, tmp, field) do {			\
	(tmp) = RB_LEFT(elm, field);					\
	if ((RB_LEFT(elm, field) = RB_RIGHT(tmp, field)) != NULL) {	\
		RB_SET_PARENT(RB_LEFT(elm, field), elm, field);		\
	}								\
	RB_SET_PARENT(tmp, RB_PARENT(elm, field), field);		\
	RB_SWAP_CHILD(head, elm, tmp, field);				\
	RB_RIGHT(tmp, field) = (elm);					\
	RB_SET_PARENT(elm, tmp, field);					\
	RB_AUGMENT(elm);						\
} while ( 0)
#define RB_SET(elm, parent, field) do {					\
	RB_UP(elm, field) = parent;					\
	RB_LEFT(elm, field) = RB_RIGHT(elm, field) = NULL;		\
} while ( 0)
#define RB_SET_PARENT(dst, src, field) do {				\
	RB_BITS(dst, field) &= RB_RED_MASK;				\
	RB_BITS(dst, field) |= (__uintptr_t)src;			\
} while ( 0)
#define RB_SWAP_CHILD(head, out, in, field) do {			\
	if (RB_PARENT(out, field) == NULL)				\
		RB_ROOT(head) = (in);					\
	else if ((out) == RB_LEFT(RB_PARENT(out, field), field))	\
		RB_LEFT(RB_PARENT(out, field), field) = (in);		\
	else								\
		RB_RIGHT(RB_PARENT(out, field), field) = (in);		\
} while ( 0)
#define RB_UP(elm, field)		(elm)->field.rbe_parent
#define SPLAY_ASSEMBLE(head, node, left, right, field) do {		\
	SPLAY_RIGHT(left, field) = SPLAY_LEFT((head)->sph_root, field);	\
	SPLAY_LEFT(right, field) = SPLAY_RIGHT((head)->sph_root, field);\
	SPLAY_LEFT((head)->sph_root, field) = SPLAY_RIGHT(node, field);	\
	SPLAY_RIGHT((head)->sph_root, field) = SPLAY_LEFT(node, field);	\
} while ( 0)
#define SPLAY_EMPTY(head)		(SPLAY_ROOT(head) == NULL)
#define SPLAY_ENTRY(type)						\
struct {								\
	struct type *spe_left; 			\
	struct type *spe_right; 			\
}
#define SPLAY_FIND(name, x, y)		name##_SPLAY_FIND(x, y)
#define SPLAY_FOREACH(x, name, head)					\
	for ((x) = SPLAY_MIN(name, head);				\
	     (x) != NULL;						\
	     (x) = SPLAY_NEXT(name, head, x))
#define SPLAY_GENERATE(name, type, field, cmp)				\
struct type *								\
name##_SPLAY_INSERT(struct name *head, struct type *elm)		\
{									\
    if (SPLAY_EMPTY(head)) {						\
	    SPLAY_LEFT(elm, field) = SPLAY_RIGHT(elm, field) = NULL;	\
    } else {								\
	    int __comp;							\
	    name##_SPLAY(head, elm);					\
	    __comp = (cmp)(elm, (head)->sph_root);			\
	    if (__comp < 0) {						\
		    SPLAY_LEFT(elm, field) = SPLAY_LEFT((head)->sph_root, field);\
		    SPLAY_RIGHT(elm, field) = (head)->sph_root;		\
		    SPLAY_LEFT((head)->sph_root, field) = NULL;		\
	    } else if (__comp > 0) {					\
		    SPLAY_RIGHT(elm, field) = SPLAY_RIGHT((head)->sph_root, field);\
		    SPLAY_LEFT(elm, field) = (head)->sph_root;		\
		    SPLAY_RIGHT((head)->sph_root, field) = NULL;	\
	    } else							\
		    return ((head)->sph_root);				\
    }									\
    (head)->sph_root = (elm);						\
    return (NULL);							\
}									\
									\
struct type *								\
name##_SPLAY_REMOVE(struct name *head, struct type *elm)		\
{									\
	struct type *__tmp;						\
	if (SPLAY_EMPTY(head))						\
		return (NULL);						\
	name##_SPLAY(head, elm);					\
	if ((cmp)(elm, (head)->sph_root) == 0) {			\
		if (SPLAY_LEFT((head)->sph_root, field) == NULL) {	\
			(head)->sph_root = SPLAY_RIGHT((head)->sph_root, field);\
		} else {						\
			__tmp = SPLAY_RIGHT((head)->sph_root, field);	\
			(head)->sph_root = SPLAY_LEFT((head)->sph_root, field);\
			name##_SPLAY(head, elm);			\
			SPLAY_RIGHT((head)->sph_root, field) = __tmp;	\
		}							\
		return (elm);						\
	}								\
	return (NULL);							\
}									\
									\
void									\
name##_SPLAY(struct name *head, struct type *elm)			\
{									\
	struct type __node, *__left, *__right, *__tmp;			\
	int __comp;							\
\
	SPLAY_LEFT(&__node, field) = SPLAY_RIGHT(&__node, field) = NULL;\
	__left = __right = &__node;					\
\
	while ((__comp = (cmp)(elm, (head)->sph_root)) != 0) {		\
		if (__comp < 0) {					\
			__tmp = SPLAY_LEFT((head)->sph_root, field);	\
			if (__tmp == NULL)				\
				break;					\
			if ((cmp)(elm, __tmp) < 0){			\
				SPLAY_ROTATE_RIGHT(head, __tmp, field);	\
				if (SPLAY_LEFT((head)->sph_root, field) == NULL)\
					break;				\
			}						\
			SPLAY_LINKLEFT(head, __right, field);		\
		} else if (__comp > 0) {				\
			__tmp = SPLAY_RIGHT((head)->sph_root, field);	\
			if (__tmp == NULL)				\
				break;					\
			if ((cmp)(elm, __tmp) > 0){			\
				SPLAY_ROTATE_LEFT(head, __tmp, field);	\
				if (SPLAY_RIGHT((head)->sph_root, field) == NULL)\
					break;				\
			}						\
			SPLAY_LINKRIGHT(head, __left, field);		\
		}							\
	}								\
	SPLAY_ASSEMBLE(head, &__node, __left, __right, field);		\
}									\
									\
									\
void name##_SPLAY_MINMAX(struct name *head, int __comp) \
{									\
	struct type __node, *__left, *__right, *__tmp;			\
\
	SPLAY_LEFT(&__node, field) = SPLAY_RIGHT(&__node, field) = NULL;\
	__left = __right = &__node;					\
\
	while (1) {							\
		if (__comp < 0) {					\
			__tmp = SPLAY_LEFT((head)->sph_root, field);	\
			if (__tmp == NULL)				\
				break;					\
			if (__comp < 0){				\
				SPLAY_ROTATE_RIGHT(head, __tmp, field);	\
				if (SPLAY_LEFT((head)->sph_root, field) == NULL)\
					break;				\
			}						\
			SPLAY_LINKLEFT(head, __right, field);		\
		} else if (__comp > 0) {				\
			__tmp = SPLAY_RIGHT((head)->sph_root, field);	\
			if (__tmp == NULL)				\
				break;					\
			if (__comp > 0) {				\
				SPLAY_ROTATE_LEFT(head, __tmp, field);	\
				if (SPLAY_RIGHT((head)->sph_root, field) == NULL)\
					break;				\
			}						\
			SPLAY_LINKRIGHT(head, __left, field);		\
		}							\
	}								\
	SPLAY_ASSEMBLE(head, &__node, __left, __right, field);		\
}
#define SPLAY_HEAD(name, type)						\
struct name {								\
	struct type *sph_root; 			\
}
#define SPLAY_INIT(root) do {						\
	(root)->sph_root = NULL;					\
} while ( 0)
#define SPLAY_INITIALIZER(root)						\
	{ NULL }
#define SPLAY_INSERT(name, x, y)	name##_SPLAY_INSERT(x, y)
#define SPLAY_LEFT(elm, field)		(elm)->field.spe_left
#define SPLAY_LINKLEFT(head, tmp, field) do {				\
	SPLAY_LEFT(tmp, field) = (head)->sph_root;			\
	tmp = (head)->sph_root;						\
	(head)->sph_root = SPLAY_LEFT((head)->sph_root, field);		\
} while ( 0)
#define SPLAY_LINKRIGHT(head, tmp, field) do {				\
	SPLAY_RIGHT(tmp, field) = (head)->sph_root;			\
	tmp = (head)->sph_root;						\
	(head)->sph_root = SPLAY_RIGHT((head)->sph_root, field);	\
} while ( 0)
#define SPLAY_MAX(name, x)		(SPLAY_EMPTY(x) ? NULL	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_INF))
#define SPLAY_MIN(name, x)		(SPLAY_EMPTY(x) ? NULL	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_NEGINF))
#define SPLAY_NEXT(name, x, y)		name##_SPLAY_NEXT(x, y)
#define SPLAY_PROTOTYPE(name, type, field, cmp)				\
void name##_SPLAY(struct name *, struct type *);			\
void name##_SPLAY_MINMAX(struct name *, int);				\
struct type *name##_SPLAY_INSERT(struct name *, struct type *);		\
struct type *name##_SPLAY_REMOVE(struct name *, struct type *);		\
									\
				\
static __unused __inline struct type *					\
name##_SPLAY_FIND(struct name *head, struct type *elm)			\
{									\
	if (SPLAY_EMPTY(head))						\
		return(NULL);						\
	name##_SPLAY(head, elm);					\
	if ((cmp)(elm, (head)->sph_root) == 0)				\
		return (head->sph_root);				\
	return (NULL);							\
}									\
									\
static __unused __inline struct type *					\
name##_SPLAY_NEXT(struct name *head, struct type *elm)			\
{									\
	name##_SPLAY(head, elm);					\
	if (SPLAY_RIGHT(elm, field) != NULL) {				\
		elm = SPLAY_RIGHT(elm, field);				\
		while (SPLAY_LEFT(elm, field) != NULL) {		\
			elm = SPLAY_LEFT(elm, field);			\
		}							\
	} else								\
		elm = NULL;						\
	return (elm);							\
}									\
									\
static __unused __inline struct type *					\
name##_SPLAY_MIN_MAX(struct name *head, int val)			\
{									\
	name##_SPLAY_MINMAX(head, val);					\
        return (SPLAY_ROOT(head));					\
}
#define SPLAY_REMOVE(name, x, y)	name##_SPLAY_REMOVE(x, y)
#define SPLAY_RIGHT(elm, field)		(elm)->field.spe_right
#define SPLAY_ROOT(head)		(head)->sph_root
#define SPLAY_ROTATE_LEFT(head, tmp, field) do {			\
	SPLAY_RIGHT((head)->sph_root, field) = SPLAY_LEFT(tmp, field);	\
	SPLAY_LEFT(tmp, field) = (head)->sph_root;			\
	(head)->sph_root = tmp;						\
} while ( 0)
#define SPLAY_ROTATE_RIGHT(head, tmp, field) do {			\
	SPLAY_LEFT((head)->sph_root, field) = SPLAY_RIGHT(tmp, field);	\
	SPLAY_RIGHT(tmp, field) = (head)->sph_root;			\
	(head)->sph_root = tmp;						\
} while ( 0)

#define INPCBSTORAGE_DEFINE(prot, lname, zname, iname, hname)		\
static int								\
prot##_inpcb_init(void *mem, int size __unused, int flags __unused)	\
{									\
	struct inpcb *inp = mem;					\
									\
	rw_init_flags(&inp->inp_lock, lname, RW_RECURSE | RW_DUPOK);	\
	return (0);							\
}									\
static struct inpcbstorage prot = {					\
	.ips_pcbinit = prot##_inpcb_init,				\
	.ips_zone_name = zname,						\
	.ips_portzone_name = zname " ports",				\
	.ips_infolock_name = iname,					\
	.ips_hashlock_name = hname,					\
};									\
SYSINIT(prot##_inpcbstorage_init, SI_SUB_PROTO_DOMAIN,			\
    SI_ORDER_SECOND, in_pcbstorage_init, &prot);			\
SYSUNINIT(prot##_inpcbstorage_uninit, SI_SUB_PROTO_DOMAIN,		\
    SI_ORDER_SECOND, in_pcbstorage_destroy, &prot)
#define INP_INFO_WLOCK(ipi)	mtx_lock(&(ipi)->ipi_lock)
#define INP_INFO_WLOCKED(ipi)	mtx_owned(&(ipi)->ipi_lock)
#define INP_INFO_WLOCK_ASSERT(ipi)	mtx_assert(&(ipi)->ipi_lock, MA_OWNED)
#define INP_INFO_WUNLOCK(ipi)	mtx_unlock(&(ipi)->ipi_lock)
#define INP_INFO_WUNLOCK_ASSERT(ipi)	\
				mtx_assert(&(ipi)->ipi_lock, MA_NOTOWNED)
#define INP_LOCK_DESTROY(inp)	rw_destroy(&(inp)->inp_lock)
#define INP_PCBHASH(faddr, lport, fport, mask)				\
	((IN_ADDR_JHASH32(faddr) ^ ntohs((lport) ^ (fport))) & (mask))
#define INP_PCBPORTHASH(lport, mask)	(ntohs((lport)) & (mask))
#define INP_RLOCK(inp)		rw_rlock(&(inp)->inp_lock)
#define INP_RUNLOCK(inp)	rw_runlock(&(inp)->inp_lock)
#define INP_TRY_RLOCK(inp)	rw_try_rlock(&(inp)->inp_lock)
#define INP_TRY_WLOCK(inp)	rw_try_wlock(&(inp)->inp_lock)
#define INP_UNLOCK(inp)		rw_unlock(&(inp)->inp_lock)
#define INP_WLOCK(inp)		rw_wlock(&(inp)->inp_lock)
#define INP_WUNLOCK(inp)	rw_wunlock(&(inp)->inp_lock)

#define CK_LIST_ENTRY LIST_ENTRY
#define CK_LIST_HEAD LIST_HEAD
#define CK_STAILQ_ENTRY STAILQ_ENTRY
#define CK_STAILQ_HEAD STAILQ_HEAD

#define NH_VALIDATE(ro, cookiep, fibnum) do {				\
	rt_gen_t cookie = RT_GEN(fibnum, (ro)->ro_dst.sa_family);	\
	if (*(cookiep) != cookie) {					\
		RO_INVALIDATE_CACHE(ro);				\
		*(cookiep) = cookie;					\
	}								\
} while (0)
#define RO_GET_FAMILY(ro, dst)	((ro) != NULL &&		\
	(ro)->ro_flags & RT_HAS_GW				\
	? (ro)->ro_dst.sa_family : (dst)->sa_family)
#define RT_GEN(fibnum, af)	rt_tables_get_gen(fibnum, af)
#define RT_LINK_IS_UP(ifp)	(!((ifp)->if_capabilities & IFCAP_LINKSTATE) \
				 || (ifp)->if_link_state == LINK_STATE_UP)
#define SA_SIZE(sa)						\
    (  (((struct sockaddr *)(sa))->sa_len == 0) ?		\
	sizeof(long)		:				\
	1 + ( (((struct sockaddr *)(sa))->sa_len - 1) | (sizeof(long) - 1) ) )


#define IF_LLADDR(ifp)							\
    LLADDR((struct sockaddr_dl *)((ifp)->if_addr->ifa_addr))
#define MCDPRINTF printf
#define RT_IS_FIXED_TABLE 0x00000004	
#define RT_IS_INDIRECT    0x00000001	
#define RT_IS_SELECTABLE  0x00000002	
#define IF_DEQUEUE(ifq, m) do { 				\
	IF_LOCK(ifq); 						\
	_IF_DEQUEUE(ifq, m); 					\
	IF_UNLOCK(ifq); 					\
} while (0)
#define IF_DRAIN(ifq) do {					\
	IF_LOCK(ifq);						\
	_IF_DRAIN(ifq);						\
	IF_UNLOCK(ifq);						\
} while(0)
#define IF_ENQUEUE(ifq, m) do {					\
	IF_LOCK(ifq); 						\
	_IF_ENQUEUE(ifq, m); 					\
	IF_UNLOCK(ifq); 					\
} while (0)
#define IF_LOCK(ifq)		mtx_lock(&(ifq)->ifq_mtx)
#define IF_PREPEND(ifq, m) do {		 			\
	IF_LOCK(ifq); 						\
	_IF_PREPEND(ifq, m); 					\
	IF_UNLOCK(ifq); 					\
} while (0)
#define IF_UNLOCK(ifq)		mtx_unlock(&(ifq)->ifq_mtx)
#define _IF_DRAIN(ifq) do { 					\
	struct mbuf *m; 					\
	for (;;) { 						\
		_IF_DEQUEUE(ifq, m); 				\
		if (m == NULL) 					\
			break; 					\
		m_freem(m); 					\
	} 							\
} while (0)


