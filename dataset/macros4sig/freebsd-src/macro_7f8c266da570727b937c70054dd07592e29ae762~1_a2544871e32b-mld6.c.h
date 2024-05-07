#include<sys/types.h>












#include<sys/resource.h>
#include<sys/queue.h>






#include<sys/select.h>


























#include<sys/param.h>

#include<sys/time.h>


#include<sys/socket.h>














#include<sys/cdefs.h>



#include<sys/signal.h>


#define offsetof(type, field) __offsetof(type, field)



#define __min_size(x)	static (x)



#define UMA_SMALLEST_UNIT       (PAGE_SIZE / 256) 



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
	SLIST_NEXT(elm, field) =					\
	    SLIST_NEXT(SLIST_NEXT(elm, field), field);			\
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
#define CALLOUT_HANDLE_INITIALIZER(handle)	\
	{ NULL }

#define __gone_ok(m, msg)					 \
	_Static_assert(m < P_OSREL_MAJOR(__FreeBSD_version)),	 \
	    "Obsolete code" msg);
#define bcmp(b1, b2, len) __builtin_memcmp((b1), (b2), (len))
#define bcopy(from, to, len) __builtin_memmove((to), (from), (len))
#define bcopy_early(from, to, len) memmove_early((to), (from), (len))
#define bzero(buf, len) __builtin_memset((buf), 0, (len))
#define bzero_early(buf, len) memset_early((buf), 0, (len))
#define critical_enter() critical_enter_KBI()
#define critical_exit() critical_exit_KBI()
#define gone_in(major, msg)		__gone_ok(major, msg) _gone_in(major, msg)
#define gone_in_dev(dev, major, msg)	__gone_ok(major, msg) _gone_in_dev(dev, major, msg)
#define memcmp(b1, b2, len) __builtin_memcmp((b1), (b2), (len))
#define memcpy(to, from, len) __builtin_memcpy((to), (from), (len))
#define memmove(dest, src, n) __builtin_memmove((dest), (src), (n))
#define memset(buf, c, len) __builtin_memset((buf), (c), (len))
#define ovbcopy(f, t, l) bcopy((f), (t), (l))

#define BITSET_DEFINE_VAR(t)	BITSET_DEFINE(t, 1)
#define BLKDEV_IOSIZE  PAGE_SIZE	


#define __FreeBSD_version 1300038	
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


#define callout_async_drain(c, d)					\
    _callout_stop_safe(c, 0, d)
#define MLD_IFINFO(ifp) \
	(((struct in6_ifextra *)(ifp)->if_afdata[AF_INET6])->mld_ifinfo)
#define MLD_RANDOM_DELAY(X)		(arc4random() % (X) + 1)

#define MLD_MRC_EXP(x)			((ntohs((x)) >> 12) & 0x0007)
#define MLD_MRC_MANT(x)			(ntohs((x)) & 0x0fff)
#define MLD_QQIC_EXP(x)			(((x) >> 4) & 0x07)
#define MLD_QQIC_MANT(x)		((x) & 0x0f)
#define MLD_QRESV(x)			(((x) >> 4) & 0x0f)
#define MLD_QRV(x)			((x) & 0x07)
#define MLD_SFLAG(x)			(((x) >> 3) & 0x01)

#define ICMP6_PARAMPROB_HEADER 	 	0	
#define ICMP6_ROUTER_RENUMBERING_COMMAND  0	
#define ICMP6_ROUTER_RENUMBERING_RESULT   1	
#define ICMP6_ROUTER_RENUMBERING_SEQNUM_RESET   255	
#define ICMP6_RR_PCOUSE_FLAGS_DECRPLTIME     0x40000000
#define ICMP6_RR_PCOUSE_FLAGS_DECRVLTIME     0x80000000
#define ICMP6_TIME_EXCEED_TRANSIT 	0	
#define MLD_LISTENER_REDUCTION MLD_LISTENER_DONE 

#define icmp6_ifoutstat_inc(ifp, type, code) \
do { \
		icmp6_ifstat_inc(ifp, ifs6_out_msg); \
 		if (type < ICMP6_INFOMSG_MASK) \
 			icmp6_ifstat_inc(ifp, ifs6_out_error); \
		switch (type) { \
		 case ICMP6_DST_UNREACH: \
			 icmp6_ifstat_inc(ifp, ifs6_out_dstunreach); \
			 if (code == ICMP6_DST_UNREACH_ADMIN) \
				 icmp6_ifstat_inc(ifp, ifs6_out_adminprohib); \
			 break; \
		 case ICMP6_PACKET_TOO_BIG: \
			 icmp6_ifstat_inc(ifp, ifs6_out_pkttoobig); \
			 break; \
		 case ICMP6_TIME_EXCEEDED: \
			 icmp6_ifstat_inc(ifp, ifs6_out_timeexceed); \
			 break; \
		 case ICMP6_PARAM_PROB: \
			 icmp6_ifstat_inc(ifp, ifs6_out_paramprob); \
			 break; \
		 case ICMP6_ECHO_REQUEST: \
			 icmp6_ifstat_inc(ifp, ifs6_out_echo); \
			 break; \
		 case ICMP6_ECHO_REPLY: \
			 icmp6_ifstat_inc(ifp, ifs6_out_echoreply); \
			 break; \
		 case MLD_LISTENER_QUERY: \
			 icmp6_ifstat_inc(ifp, ifs6_out_mldquery); \
			 break; \
		 case MLD_LISTENER_REPORT: \
			 icmp6_ifstat_inc(ifp, ifs6_out_mldreport); \
			 break; \
		 case MLD_LISTENER_DONE: \
			 icmp6_ifstat_inc(ifp, ifs6_out_mlddone); \
			 break; \
		 case ND_ROUTER_SOLICIT: \
			 icmp6_ifstat_inc(ifp, ifs6_out_routersolicit); \
			 break; \
		 case ND_ROUTER_ADVERT: \
			 icmp6_ifstat_inc(ifp, ifs6_out_routeradvert); \
			 break; \
		 case ND_NEIGHBOR_SOLICIT: \
			 icmp6_ifstat_inc(ifp, ifs6_out_neighborsolicit); \
			 break; \
		 case ND_NEIGHBOR_ADVERT: \
			 icmp6_ifstat_inc(ifp, ifs6_out_neighboradvert); \
			 break; \
		 case ND_REDIRECT: \
			 icmp6_ifstat_inc(ifp, ifs6_out_redirect); \
			 break; \
		} \
} while ( 0)
#define icmp6_ifstat_inc(ifp, tag) \
do {								\
	if (ifp)						\
		counter_u64_add(((struct in6_ifextra *)		\
		    ((ifp)->if_afdata[AF_INET6]))->icmp6_ifstat[\
		    offsetof(struct icmp6_ifstat, tag) / sizeof(uint64_t)], 1);\
} while ( 0)
#define icp6s_odst_unreach_addr icp6s_outerrhist.icp6errs_dst_unreach_addr
#define icp6s_odst_unreach_admin icp6s_outerrhist.icp6errs_dst_unreach_admin
#define icp6s_odst_unreach_beyondscope \
	icp6s_outerrhist.icp6errs_dst_unreach_beyondscope
#define icp6s_odst_unreach_noport icp6s_outerrhist.icp6errs_dst_unreach_noport
#define icp6s_odst_unreach_noroute \
	icp6s_outerrhist.icp6errs_dst_unreach_noroute
#define icp6s_opacket_too_big icp6s_outerrhist.icp6errs_packet_too_big
#define icp6s_oparamprob_header icp6s_outerrhist.icp6errs_paramprob_header
#define icp6s_oparamprob_nextheader \
	icp6s_outerrhist.icp6errs_paramprob_nextheader
#define icp6s_oparamprob_option icp6s_outerrhist.icp6errs_paramprob_option
#define icp6s_oredirect icp6s_outerrhist.icp6errs_redirect
#define icp6s_otime_exceed_reassembly \
	icp6s_outerrhist.icp6errs_time_exceed_reassembly
#define icp6s_otime_exceed_transit \
	icp6s_outerrhist.icp6errs_time_exceed_transit
#define icp6s_ounknown icp6s_outerrhist.icp6errs_unknown
#define rr_seqnum 	rr_hdr.icmp6_data32[0]

#define V_deembed_scopeid       VNET(deembed_scopeid)

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
} while(0)
#define EVENTHANDLER_DEREGISTER_NOWAIT(name, tag)			\
do {									\
	struct eventhandler_list *_el;					\
									\
	if ((_el = eventhandler_find_list(#name)) != NULL)		\
		eventhandler_deregister_nowait(_el, tag);		\
} while(0)
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

#define __mtx_lock(mp, tid, opts, file, line) do {			\
	uintptr_t _tid = (uintptr_t)(tid);				\
	uintptr_t _v = MTX_UNOWNED;					\
									\
	if (__predict_false(LOCKSTAT_PROFILE_ENABLED(adaptive__acquire) ||\
	    !_mtx_obtain_lock_fetch((mp), &_v, _tid)))			\
		_mtx_lock_sleep((mp), _v, (opts), (file), (line));	\
} while (0)
#define __mtx_lock_spin(mp, tid, opts, file, line) do {			\
	uintptr_t _tid = (uintptr_t)(tid);				\
	uintptr_t _v = MTX_UNOWNED;					\
									\
	spinlock_enter();						\
	if (__predict_false(LOCKSTAT_PROFILE_ENABLED(spin__acquire) ||	\
	    !_mtx_obtain_lock_fetch((mp), &_v, _tid))) 			\
		_mtx_lock_spin((mp), _v, (opts), (file), (line)); 	\
} while (0)
#define __mtx_trylock_spin(mp, tid, opts, file, line) __extension__  ({	\
	uintptr_t _tid = (uintptr_t)(tid);				\
	int _ret;							\
									\
	spinlock_enter();						\
	if (((mp)->mtx_lock != MTX_UNOWNED || !_mtx_obtain_lock((mp), _tid))) {\
		spinlock_exit();					\
		_ret = 0;						\
	} else {							\
		LOCKSTAT_PROFILE_OBTAIN_LOCK_SUCCESS(spin__acquire,	\
		    mp, 0, 0, file, line);				\
		_ret = 1;						\
	}								\
	_ret;								\
})
#define __mtx_unlock(mp, tid, opts, file, line) do {			\
	uintptr_t _v = (uintptr_t)(tid);				\
									\
	if (__predict_false(LOCKSTAT_PROFILE_ENABLED(adaptive__release) ||\
	    !_mtx_release_lock_fetch((mp), &_v)))			\
		_mtx_unlock_sleep((mp), _v, (opts), (file), (line));	\
} while (0)
#define __mtx_unlock_spin(mp) do {					\
	if (mtx_recursed((mp)))						\
		(mp)->mtx_recurse--;					\
	else {								\
		LOCKSTAT_PROFILE_RELEASE_LOCK(spin__release, mp);	\
		_mtx_release_lock_quick((mp));				\
	}								\
	spinlock_exit();						\
} while (0)
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
	__GLOBL(__CONCAT(__start_set_,set));		\
	__GLOBL(__CONCAT(__stop_set_,set));		\
	static void const * qv				\
	__set_##set##_sym_##sym __section("set_" #set)	\
	__used = &(sym)

#define lock_profile_obtain_lock_failed(lo, contested, waittime)	(void)0
#define lock_profile_obtain_lock_success(lo, contested, waittime, file, line)	(void)0
#define LO_NOPROFILE    0x10000000      
#define MPASS(ex)		MPASS4(ex, #ex, "__FILE__", "__LINE__")
#define MPASS2(ex, what)	MPASS4(ex, what, "__FILE__", "__LINE__")
#define MPASS3(ex, file, line)	MPASS4(ex, #ex, file, line)
#define MPASS4(ex, what, file, line)					\
	KASSERT((ex), ("Assertion %s failed at %s:%d", what, file, line))
#define WITNESS_DESTROY(lock)						\
	witness_destroy(lock)

#define lock_delay_spin(n)	do {	\
	u_int _i;			\
					\
	for (_i = (n); _i > 0; _i--)	\
		cpu_spinwait();		\
} while (0)
#define KTR_COMPILE 0

#define CTR0(m, format)			CTR6(m, format, 0, 0, 0, 0, 0, 0)
#define CTR1(m, format, p1)		CTR6(m, format, p1, 0, 0, 0, 0, 0)
#define CTR6(m, format, p1, p2, p3, p4, p5, p6) do {			\
	if (KTR_COMPILE & (m))						\
		ktr_tracepoint((m), "__FILE__", "__LINE__", format,		\
		    (u_long)(p1), (u_long)(p2), (u_long)(p3),		\
		    (u_long)(p4), (u_long)(p5), (u_long)(p6));		\
	} while(0)
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
#define TSEXIT() TSRAW(curthread, TS_EXIT, __func__, NULL)
#define TSEXIT2(x) TSRAW(curthread, TS_EXIT, __func__, x)
#define TSHOLD(x) TSEVENT2("HOLD", x);
#define TSLINE() TSEVENT2("__FILE__", __XSTRING("__LINE__"))
#define TSRAW(a, b, c, d) tslog(a, b, c, d)
#define TSRELEASE(x) TSEVENT2("RELEASE", x);
#define TSTHREAD(td, x) TSRAW(td, TS_THREAD, x, NULL)
#define TSUNWAIT(x) TSEVENT2("UNWAIT", x);
#define TSWAIT(x) TSEVENT2("WAIT", x);

#define TD_IS_IDLETHREAD(td)	((td)->td_flags & TDF_IDLETD)
#define ucontext4 ucontext

#define RTP_PRIO_BASE(P)	PRI_BASE(P)
#define RTP_PRIO_IS_REALTIME(P) PRI_IS_REALTIME(P)
#define RTP_PRIO_NEED_RR(P)	PRI_NEED_RR(P)



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
} while(0)
#define KNOTE(list, hint, flags)	knote(list, hint, flags)
#define KNOTE_LOCKED(list, hint)	knote(list, hint, KNF_LISTLOCKED)
#define KNOTE_UNLOCKED(list, hint)	knote(list, hint, 0)

#define knlist_clear(knl, islocked)				\
	knlist_cleardel((knl), NULL, (islocked), 0)
#define knlist_delete(knl, td, islocked)			\
	knlist_cleardel((knl), (td), (islocked), 1)
#define cv_broadcast(cvp)	cv_broadcastpri(cvp, 0)
#define IP6PO_TEMPADDR_NOTPREFER 0 
#define IP6_HDR_ALIGNED_P(ip)	1
#define IP6_REASS_MBUF(ip6af) (*(struct mbuf **)&((ip6af)->ip6af_m))

#define EPOCH_LOCKED 0x2
#define EPOCH_MAGIC0 0xFADECAFEF00DD00D
#define EPOCH_MAGIC1 0xBADDBABEDEEDFEED
#define EPOCH_PREEMPT 0x1

#define IP6OPT_TYPE(o)		((o) & 0xC0)
#define IP6_EXTHDR_CHECK(m, off, hlen, ret)				\
do {									\
    if ((m)->m_next != NULL) {						\
	if (((m)->m_flags & M_LOOP) &&					\
	    ((m)->m_len < (off) + (hlen)) &&				\
	    (((m) = m_pullup((m), (off) + (hlen))) == NULL)) {		\
		IP6STAT_INC(ip6s_exthdrtoolong);				\
		return ret;						\
	} else {							\
		if ((m)->m_len < (off) + (hlen)) {			\
			IP6STAT_INC(ip6s_exthdrtoolong);			\
			m_freem(m);					\
			return ret;					\
		}							\
	}								\
    } else {								\
	if ((m)->m_len < (off) + (hlen)) {				\
		IP6STAT_INC(ip6s_tooshort);				\
		in6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_truncated);	\
		m_freem(m);						\
		return ret;						\
	}								\
    }									\
} while ( 0)
#define IP6_EXTHDR_GET(val, typ, m, off, len) \
do {									\
	struct mbuf *t;							\
	int tmp;							\
	if ((m)->m_len >= (off) + (len))				\
		(val) = (typ)(mtod((m), caddr_t) + (off));		\
	else {								\
		t = m_pulldown((m), (off), (len), &tmp);		\
		if (t) {						\
			if (t->m_len < tmp + (len))			\
				panic("m_pulldown malfunction");	\
			(val) = (typ)(mtod(t, caddr_t) + tmp);		\
		} else {						\
			(val) = (typ)NULL;				\
			(m) = NULL;					\
		}							\
	}								\
} while ( 0)
#define IP6_EXTHDR_GET0(val, typ, m, off, len) \
do {									\
	struct mbuf *t;							\
	if ((off) == 0)							\
		(val) = (typ)mtod(m, caddr_t);				\
	else {								\
		t = m_pulldown((m), (off), (len), NULL);		\
		if (t) {						\
			if (t->m_len < (len))				\
				panic("m_pulldown malfunction");	\
			(val) = (typ)mtod(t, caddr_t);			\
		} else {						\
			(val) = (typ)NULL;				\
			(m) = NULL;					\
		}							\
	}								\
} while ( 0)

#define IA6_DSTIN6(ia)	(&((ia)->ia_dstaddr.sin6_addr))
#define IA6_DSTSIN6(ia)	(&((ia)->ia_dstaddr))
#define IA6_IN6(ia)	(&((ia)->ia_addr.sin6_addr))
#define IA6_MASKIN6(ia)	(&((ia)->ia_prefixmask.sin6_addr))
#define IA6_SIN6(ia)	(&((ia)->ia_addr))
#define IFA_DSTIN6(x)	(&((struct sockaddr_in6 *)((x)->ifa_dstaddr))->sin6_addr)
#define IFA_IN6(x)	(&((struct sockaddr_in6 *)((x)->ifa_addr))->sin6_addr)
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
#define RB_AUGMENT(x)	do {} while (0)
#define RB_COLOR(elm, field)		(elm)->field.rbe_color
#define RB_EMPTY(head)			(RB_ROOT(head) == NULL)
#define RB_ENTRY(type)							\
struct {								\
	struct type *rbe_left;				\
	struct type *rbe_right;				\
	struct type *rbe_parent;			\
	int rbe_color;					\
}
#define RB_FIND(name, x, y)	name##_RB_FIND(x, y)
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
	if (parent != NULL) {						\
		if (comp < 0)						\
			RB_LEFT(parent, field) = elm;			\
		else							\
			RB_RIGHT(parent, field) = elm;			\
		RB_AUGMENT(parent);					\
	} else								\
		RB_ROOT(head) = elm;					\
	name##_RB_INSERT_COLOR(head, elm);				\
	return (NULL);							\
}
#define RB_GENERATE_INSERT_COLOR(name, type, field, attr)		\
attr void								\
name##_RB_INSERT_COLOR(struct name *head, struct type *elm)		\
{									\
	struct type *parent, *gparent, *tmp;				\
	while ((parent = RB_PARENT(elm, field)) != NULL &&		\
	    RB_COLOR(parent, field) == RB_RED) {			\
		gparent = RB_PARENT(parent, field);			\
		if (parent == RB_LEFT(gparent, field)) {		\
			tmp = RB_RIGHT(gparent, field);			\
			if (tmp && RB_COLOR(tmp, field) == RB_RED) {	\
				RB_COLOR(tmp, field) = RB_BLACK;	\
				RB_SET_BLACKRED(parent, gparent, field);\
				elm = gparent;				\
				continue;				\
			}						\
			if (RB_RIGHT(parent, field) == elm) {		\
				RB_ROTATE_LEFT(head, parent, tmp, field);\
				tmp = parent;				\
				parent = elm;				\
				elm = tmp;				\
			}						\
			RB_SET_BLACKRED(parent, gparent, field);	\
			RB_ROTATE_RIGHT(head, gparent, tmp, field);	\
		} else {						\
			tmp = RB_LEFT(gparent, field);			\
			if (tmp && RB_COLOR(tmp, field) == RB_RED) {	\
				RB_COLOR(tmp, field) = RB_BLACK;	\
				RB_SET_BLACKRED(parent, gparent, field);\
				elm = gparent;				\
				continue;				\
			}						\
			if (RB_LEFT(parent, field) == elm) {		\
				RB_ROTATE_RIGHT(head, parent, tmp, field);\
				tmp = parent;				\
				parent = elm;				\
				elm = tmp;				\
			}						\
			RB_SET_BLACKRED(parent, gparent, field);	\
			RB_ROTATE_LEFT(head, gparent, tmp, field);	\
		}							\
	}								\
	RB_COLOR(head->rbh_root, field) = RB_BLACK;			\
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
	RB_GENERATE_MINMAX(name, type, field, attr)
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
	struct type *child, *parent, *old = elm;			\
	int color;							\
	if (RB_LEFT(elm, field) == NULL)				\
		child = RB_RIGHT(elm, field);				\
	else if (RB_RIGHT(elm, field) == NULL)				\
		child = RB_LEFT(elm, field);				\
	else {								\
		struct type *left;					\
		elm = RB_RIGHT(elm, field);				\
		while ((left = RB_LEFT(elm, field)) != NULL)		\
			elm = left;					\
		child = RB_RIGHT(elm, field);				\
		parent = RB_PARENT(elm, field);				\
		color = RB_COLOR(elm, field);				\
		if (child)						\
			RB_PARENT(child, field) = parent;		\
		if (parent) {						\
			if (RB_LEFT(parent, field) == elm)		\
				RB_LEFT(parent, field) = child;		\
			else						\
				RB_RIGHT(parent, field) = child;	\
			RB_AUGMENT(parent);				\
		} else							\
			RB_ROOT(head) = child;				\
		if (RB_PARENT(elm, field) == old)			\
			parent = elm;					\
		(elm)->field = (old)->field;				\
		if (RB_PARENT(old, field)) {				\
			if (RB_LEFT(RB_PARENT(old, field), field) == old)\
				RB_LEFT(RB_PARENT(old, field), field) = elm;\
			else						\
				RB_RIGHT(RB_PARENT(old, field), field) = elm;\
			RB_AUGMENT(RB_PARENT(old, field));		\
		} else							\
			RB_ROOT(head) = elm;				\
		RB_PARENT(RB_LEFT(old, field), field) = elm;		\
		if (RB_RIGHT(old, field))				\
			RB_PARENT(RB_RIGHT(old, field), field) = elm;	\
		if (parent) {						\
			left = parent;					\
			do {						\
				RB_AUGMENT(left);			\
			} while ((left = RB_PARENT(left, field)) != NULL); \
		}							\
		goto color;						\
	}								\
	parent = RB_PARENT(elm, field);					\
	color = RB_COLOR(elm, field);					\
	if (child)							\
		RB_PARENT(child, field) = parent;			\
	if (parent) {							\
		if (RB_LEFT(parent, field) == elm)			\
			RB_LEFT(parent, field) = child;			\
		else							\
			RB_RIGHT(parent, field) = child;		\
		RB_AUGMENT(parent);					\
	} else								\
		RB_ROOT(head) = child;					\
color:									\
	if (color == RB_BLACK)						\
		name##_RB_REMOVE_COLOR(head, parent, child);		\
	return (old);							\
}									\

#define RB_GENERATE_REMOVE_COLOR(name, type, field, attr)		\
attr void								\
name##_RB_REMOVE_COLOR(struct name *head, struct type *parent, struct type *elm) \
{									\
	struct type *tmp;						\
	while ((elm == NULL || RB_COLOR(elm, field) == RB_BLACK) &&	\
	    elm != RB_ROOT(head)) {					\
		if (RB_LEFT(parent, field) == elm) {			\
			tmp = RB_RIGHT(parent, field);			\
			if (RB_COLOR(tmp, field) == RB_RED) {		\
				RB_SET_BLACKRED(tmp, parent, field);	\
				RB_ROTATE_LEFT(head, parent, tmp, field);\
				tmp = RB_RIGHT(parent, field);		\
			}						\
			if ((RB_LEFT(tmp, field) == NULL ||		\
			    RB_COLOR(RB_LEFT(tmp, field), field) == RB_BLACK) &&\
			    (RB_RIGHT(tmp, field) == NULL ||		\
			    RB_COLOR(RB_RIGHT(tmp, field), field) == RB_BLACK)) {\
				RB_COLOR(tmp, field) = RB_RED;		\
				elm = parent;				\
				parent = RB_PARENT(elm, field);		\
			} else {					\
				if (RB_RIGHT(tmp, field) == NULL ||	\
				    RB_COLOR(RB_RIGHT(tmp, field), field) == RB_BLACK) {\
					struct type *oleft;		\
					if ((oleft = RB_LEFT(tmp, field)) \
					    != NULL)			\
						RB_COLOR(oleft, field) = RB_BLACK;\
					RB_COLOR(tmp, field) = RB_RED;	\
					RB_ROTATE_RIGHT(head, tmp, oleft, field);\
					tmp = RB_RIGHT(parent, field);	\
				}					\
				RB_COLOR(tmp, field) = RB_COLOR(parent, field);\
				RB_COLOR(parent, field) = RB_BLACK;	\
				if (RB_RIGHT(tmp, field))		\
					RB_COLOR(RB_RIGHT(tmp, field), field) = RB_BLACK;\
				RB_ROTATE_LEFT(head, parent, tmp, field);\
				elm = RB_ROOT(head);			\
				break;					\
			}						\
		} else {						\
			tmp = RB_LEFT(parent, field);			\
			if (RB_COLOR(tmp, field) == RB_RED) {		\
				RB_SET_BLACKRED(tmp, parent, field);	\
				RB_ROTATE_RIGHT(head, parent, tmp, field);\
				tmp = RB_LEFT(parent, field);		\
			}						\
			if ((RB_LEFT(tmp, field) == NULL ||		\
			    RB_COLOR(RB_LEFT(tmp, field), field) == RB_BLACK) &&\
			    (RB_RIGHT(tmp, field) == NULL ||		\
			    RB_COLOR(RB_RIGHT(tmp, field), field) == RB_BLACK)) {\
				RB_COLOR(tmp, field) = RB_RED;		\
				elm = parent;				\
				parent = RB_PARENT(elm, field);		\
			} else {					\
				if (RB_LEFT(tmp, field) == NULL ||	\
				    RB_COLOR(RB_LEFT(tmp, field), field) == RB_BLACK) {\
					struct type *oright;		\
					if ((oright = RB_RIGHT(tmp, field)) \
					    != NULL)			\
						RB_COLOR(oright, field) = RB_BLACK;\
					RB_COLOR(tmp, field) = RB_RED;	\
					RB_ROTATE_LEFT(head, tmp, oright, field);\
					tmp = RB_LEFT(parent, field);	\
				}					\
				RB_COLOR(tmp, field) = RB_COLOR(parent, field);\
				RB_COLOR(parent, field) = RB_BLACK;	\
				if (RB_LEFT(tmp, field))		\
					RB_COLOR(RB_LEFT(tmp, field), field) = RB_BLACK;\
				RB_ROTATE_RIGHT(head, parent, tmp, field);\
				elm = RB_ROOT(head);			\
				break;					\
			}						\
		}							\
	}								\
	if (elm)							\
		RB_COLOR(elm, field) = RB_BLACK;			\
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
#define RB_PARENT(elm, field)		(elm)->field.rbe_parent
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
	RB_PROTOTYPE_MINMAX(name, type, attr);
#define RB_PROTOTYPE_MINMAX(name, type, attr)				\
	attr struct type *name##_RB_MINMAX(struct name *, int)
#define RB_PROTOTYPE_NEXT(name, type, attr)				\
	attr struct type *name##_RB_NEXT(struct type *)
#define RB_PROTOTYPE_NFIND(name, type, attr)				\
	attr struct type *name##_RB_NFIND(struct name *, struct type *)
#define RB_PROTOTYPE_PREV(name, type, attr)				\
	attr struct type *name##_RB_PREV(struct type *)
#define RB_PROTOTYPE_REMOVE(name, type, attr)				\
	attr struct type *name##_RB_REMOVE(struct name *, struct type *)
#define RB_PROTOTYPE_REMOVE_COLOR(name, type, attr)			\
	attr void name##_RB_REMOVE_COLOR(struct name *, struct type *, struct type *)
#define RB_REMOVE(name, x, y)	name##_RB_REMOVE(x, y)
#define RB_RIGHT(elm, field)		(elm)->field.rbe_right
#define RB_ROOT(head)			(head)->rbh_root
#define RB_ROTATE_LEFT(head, elm, tmp, field) do {			\
	(tmp) = RB_RIGHT(elm, field);					\
	if ((RB_RIGHT(elm, field) = RB_LEFT(tmp, field)) != NULL) {	\
		RB_PARENT(RB_LEFT(tmp, field), field) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	if ((RB_PARENT(tmp, field) = RB_PARENT(elm, field)) != NULL) {	\
		if ((elm) == RB_LEFT(RB_PARENT(elm, field), field))	\
			RB_LEFT(RB_PARENT(elm, field), field) = (tmp);	\
		else							\
			RB_RIGHT(RB_PARENT(elm, field), field) = (tmp);	\
	} else								\
		(head)->rbh_root = (tmp);				\
	RB_LEFT(tmp, field) = (elm);					\
	RB_PARENT(elm, field) = (tmp);					\
	RB_AUGMENT(tmp);						\
	if ((RB_PARENT(tmp, field)))					\
		RB_AUGMENT(RB_PARENT(tmp, field));			\
} while ( 0)
#define RB_ROTATE_RIGHT(head, elm, tmp, field) do {			\
	(tmp) = RB_LEFT(elm, field);					\
	if ((RB_LEFT(elm, field) = RB_RIGHT(tmp, field)) != NULL) {	\
		RB_PARENT(RB_RIGHT(tmp, field), field) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	if ((RB_PARENT(tmp, field) = RB_PARENT(elm, field)) != NULL) {	\
		if ((elm) == RB_LEFT(RB_PARENT(elm, field), field))	\
			RB_LEFT(RB_PARENT(elm, field), field) = (tmp);	\
		else							\
			RB_RIGHT(RB_PARENT(elm, field), field) = (tmp);	\
	} else								\
		(head)->rbh_root = (tmp);				\
	RB_RIGHT(tmp, field) = (elm);					\
	RB_PARENT(elm, field) = (tmp);					\
	RB_AUGMENT(tmp);						\
	if ((RB_PARENT(tmp, field)))					\
		RB_AUGMENT(RB_PARENT(tmp, field));			\
} while ( 0)
#define RB_SET(elm, parent, field) do {					\
	RB_PARENT(elm, field) = parent;					\
	RB_LEFT(elm, field) = RB_RIGHT(elm, field) = NULL;		\
	RB_COLOR(elm, field) = RB_RED;					\
} while ( 0)
#define RB_SET_BLACKRED(black, red, field) do {				\
	RB_COLOR(black, field) = RB_BLACK;				\
	RB_COLOR(red, field) = RB_RED;					\
} while ( 0)
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
	    if(__comp < 0) {						\
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
#define IA_DSTSIN(ia) (&(((struct in_ifaddr *)(ia))->ia_dstaddr))
#define IA_MASKSIN(ia) (&(((struct in_ifaddr *)(ia))->ia_sockmask))
#define IA_SIN(ia)    (&(((struct in_ifaddr *)(ia))->ia_addr))
#define IFP_TO_IA(ifp, ia, t)						\
						\
						\
						\
do {									\
	IN_IFADDR_RLOCK((t));						\
	for ((ia) = CK_STAILQ_FIRST(&V_in_ifaddrhead);			\
	    (ia) != NULL && (ia)->ia_ifp != (ifp);			\
	    (ia) = CK_STAILQ_NEXT((ia), ia_link))				\
		continue;						\
	IN_IFADDR_RUNLOCK((t));						\
} while (0)
#define INADDR_HASH(x) \
	(&V_in_ifaddrhashtbl[INADDR_HASHVAL(x) & V_in_ifaddrhmask])
#define INADDR_HASHVAL(x)	fnv_32_buf((&(x)), sizeof(x), FNV1_32_INIT)
#define INADDR_NHASH_LOG2       9
#define INADDR_TO_IFADDR(addr, ia) \
	 \
	 \
do { \
\
	LIST_FOREACH(ia, INADDR_HASH((addr).s_addr), ia_hash) \
		if (IA_SIN(ia)->sin_addr.s_addr == (addr).s_addr) \
			break; \
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
#define RT_GEN(fibnum, af)	rt_tables_get_gen(fibnum, af)
#define RT_LINK_IS_UP(ifp)	(!((ifp)->if_capabilities & IFCAP_LINKSTATE) \
				 || (ifp)->if_link_state == LINK_STATE_UP)
#define RT_VALIDATE(ro, cookiep, fibnum) do {				\
	rt_gen_t cookie = RT_GEN(fibnum, (ro)->ro_dst.sa_family);	\
	if (*(cookiep) != cookie) {					\
		RO_INVALIDATE_CACHE(ro);				\
		*(cookiep) = cookie;					\
	}								\
} while (0)
#define SA_SIZE(sa)						\
    (  (((struct sockaddr *)(sa))->sa_len == 0) ?		\
	sizeof(long)		:				\
	1 + ( (((struct sockaddr *)(sa))->sa_len - 1) | (sizeof(long) - 1) ) )

#define R_Free(p) free((char *)p);
#define R_Malloc(p, t, n) (p = (t) malloc((unsigned int)(n)))
#define R_Zalloc(p, t, n) (p = (t) calloc(1,(unsigned int)(n)))
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
#define MBUF_EXT_PGS_ASSERT(m)						\
	KASSERT((((m)->m_flags & M_EXT) != 0) &&			\
	    ((m)->m_ext.ext_type == EXT_PGS),				\
	    ("%s: m %p !M_EXT or !EXT_PGS", __func__, m))
#define M_COPYFLAGS \
    (M_PKTHDR|M_EOR|M_RDONLY|M_BCAST|M_MCAST|M_PROMISC|M_VLANTAG|M_TSTMP| \
     M_TSTMP_HPREC|M_PROTOFLAGS)
#define M_GETFIB(_m)   rt_m_getfib(_m)
 #define M_PROFILE(m) m_profile(m)
#define M_SETFIB(_m, _fib) do {						\
        KASSERT((_m)->m_flags & M_PKTHDR, ("Attempt to set FIB on non header mbuf."));	\
	((_m)->m_pkthdr.fibnum) = (_fib);				\
} while (0)


#define CK_LIST_ENTRY LIST_ENTRY
#define CK_LIST_HEAD LIST_HEAD
#define CK_STAILQ_ENTRY STAILQ_ENTRY
#define CK_STAILQ_HEAD STAILQ_HEAD
#define ACCEPT4_COMPAT  0x2
#define ACCEPT4_INHERIT 0x1
#define AF_VENDOR00 39
#define AF_VENDOR01 41
#define AF_VENDOR02 43
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


