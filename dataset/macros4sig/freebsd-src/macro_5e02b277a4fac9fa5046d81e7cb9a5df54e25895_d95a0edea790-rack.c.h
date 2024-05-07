

#include<sys/select.h>




#include<sys/types.h>







#include<sys/param.h>









#include<sys/cdefs.h>



#include<netinet/tcp.h>



#include<sys/queue.h>

#include<net/route.h>











#include<sys/signal.h>

















#include<sys/socket.h>











#include<sys/resource.h>



#include<sys/time.h>







#define PACE_PKT_OUTPUT 0x01	
#define PACE_TMR_DELACK 0x40	
#define PACE_TMR_KEEP   0x20	
#define PACE_TMR_MASK   (PACE_TMR_KEEP|PACE_TMR_PERSIT|PACE_TMR_RXT|PACE_TMR_TLP|PACE_TMR_RACK|PACE_TMR_DELACK)
#define PACE_TMR_PERSIT 0x10	
#define PACE_TMR_RACK   0x02	
#define PACE_TMR_RXT    0x08	
#define PACE_TMR_TLP    0x04	
#define PROGRESS_CLEAR  3
#define PROGRESS_DROP   1
#define PROGRESS_START  4
#define PROGRESS_UPDATE 2
#define TCP_MSS_ACCT_ATIMER  60
#define TCP_MSS_ACCT_INPACE  61
#define TCP_MSS_ACCT_JUSTRET 0
#define TCP_MSS_ACCT_LATE    62
#define TCP_MSS_ACCT_PERSIST 2
#define TCP_MSS_ACCT_SIZE    70
#define TCP_MSS_ACCT_SNDACK  1
#define TCP_MSS_SMALL_MAX_SIZE_DIV (TCP_MSS_ACCT_SIZE - TCP_MSS_SMALL_SIZE_OFF)
#define TCP_MSS_SMALL_SIZE_OFF 63	
#define USE_RTT_AVG  2
#define USE_RTT_HIGH 0
#define USE_RTT_LOW  1

#define RACK_INITIAL_RTO 1000 
#define RACK_LOG_TYPE_ALLOC     0x04
#define RACK_LOG_TYPE_FREE      0x05
#define RACK_NUM_OF_RETRANS 3
#define RACK_OPTS_ADD(name, amm) counter_u64_add(rack_opts_arry[(offsetof(struct rack_opts_stats, name)/sizeof(uint64_t))], (amm))
#define RACK_OPTS_INC(name) RACK_OPTS_ADD(name, 1)
#define RACK_OPTS_SIZE (sizeof(struct rack_opts_stats)/sizeof(uint64_t))
#define RACK_RTT_EMPTY 0x00000001	
#define RACK_RTT_VALID 0x00000002	
#define RACK_SACK_PASSED  0x0010
#define RACK_TO_FRM_DELACK 6
#define RACK_TO_FRM_KEEP 4
#define RACK_TO_FRM_PERSIST 5
#define RACK_TO_FRM_RACK 3
#define RACK_TO_FRM_TLP  2
#define RACK_TO_FRM_TMR  1
#define RACK_WAS_SACKPASS 0x0020
#define TLP_USE_TWO_ONE 2	
#define TLP_USE_TWO_TWO 3	

#define SACK_FILTER_BLOCKS 7

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


#define __FreeBSD_version 1300032	
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
#define INP_INFO_LOCK_DESTROY(ipi)  mtx_destroy(&(ipi)->ipi_lock)
#define INP_INFO_LOCK_INIT(ipi, d) \
	mtx_init(&(ipi)->ipi_lock, (d), NULL, MTX_DEF| MTX_RECURSE)
#define INP_INFO_RLOCK_ASSERT(ipi)	MPASS(in_epoch(net_epoch_preempt))
#define INP_INFO_RLOCK_ET(ipi, et)	NET_EPOCH_ENTER((et))
#define INP_INFO_RUNLOCK_ET(ipi, et)	NET_EPOCH_EXIT((et))
#define INP_INFO_RUNLOCK_TP(ipi, tp)	NET_EPOCH_EXIT(*(tp)->t_inpcb->inp_et)
#define INP_INFO_TRY_WLOCK(ipi)	mtx_trylock(&(ipi)->ipi_lock)
#define INP_INFO_UNLOCK_ASSERT(ipi)	MPASS(!in_epoch(net_epoch_preempt) && !mtx_owned(&(ipi)->ipi_lock))
#define INP_INFO_WLOCK(ipi) mtx_lock(&(ipi)->ipi_lock)
#define INP_INFO_WLOCKED(ipi)	mtx_owned(&(ipi)->ipi_lock)
#define INP_INFO_WLOCK_ASSERT(ipi)	mtx_assert(&(ipi)->ipi_lock, MA_OWNED)
#define INP_INFO_WUNLOCK(ipi)	mtx_unlock(&(ipi)->ipi_lock)
#define INP_INFO_WUNLOCK_ASSERT(ipi)	\
	mtx_assert(&(ipi)->ipi_lock, MA_NOTOWNED)
#define INP_LIST_LOCK_ASSERT(ipi) \
	rw_assert(&(ipi)->ipi_list_lock, RA_LOCKED)
#define INP_LIST_LOCK_DESTROY(ipi)  rw_destroy(&(ipi)->ipi_list_lock)
#define INP_LIST_LOCK_INIT(ipi, d) \
        rw_init_flags(&(ipi)->ipi_list_lock, (d), 0)
#define INP_LIST_RLOCK(ipi)     rw_rlock(&(ipi)->ipi_list_lock)
#define INP_LIST_RLOCK_ASSERT(ipi) \
	rw_assert(&(ipi)->ipi_list_lock, RA_RLOCKED)
#define INP_LIST_RUNLOCK(ipi)   rw_runlock(&(ipi)->ipi_list_lock)
#define INP_LIST_TRY_RLOCK(ipi) rw_try_rlock(&(ipi)->ipi_list_lock)
#define INP_LIST_TRY_UPGRADE(ipi)       rw_try_upgrade(&(ipi)->ipi_list_lock)
#define INP_LIST_TRY_WLOCK(ipi) rw_try_wlock(&(ipi)->ipi_list_lock)
#define INP_LIST_UNLOCK_ASSERT(ipi) \
	rw_assert(&(ipi)->ipi_list_lock, RA_UNLOCKED)
#define INP_LIST_WLOCK(ipi)     rw_wlock(&(ipi)->ipi_list_lock)
#define INP_LIST_WLOCK_ASSERT(ipi) \
	rw_assert(&(ipi)->ipi_list_lock, RA_WLOCKED)
#define INP_LIST_WUNLOCK(ipi)   rw_wunlock(&(ipi)->ipi_list_lock)
#define INP_LOCK_DESTROY(inp)	rw_destroy(&(inp)->inp_lock)
#define INP_LOCK_INIT(inp, d, t) \
	rw_init_flags(&(inp)->inp_lock, (t), RW_RECURSE |  RW_DUPOK)
#define INP_PCBHASH(faddr, lport, fport, mask) \
	(((faddr) ^ ((faddr) >> 16) ^ ntohs((lport) ^ (fport))) & (mask))
#define INP_PCBPORTHASH(lport, mask) \
	(ntohs((lport)) & (mask))
#define INP_RLOCK(inp)		rw_rlock(&(inp)->inp_lock)
#define INP_RUNLOCK(inp)	rw_runlock(&(inp)->inp_lock)
#define INP_TRY_RLOCK(inp)	rw_try_rlock(&(inp)->inp_lock)
#define INP_TRY_WLOCK(inp)	rw_try_wlock(&(inp)->inp_lock)
#define INP_WLOCK(inp)		rw_wlock(&(inp)->inp_lock)
#define INP_WUNLOCK(inp)	rw_wunlock(&(inp)->inp_lock)

#define CK_LIST_ENTRY LIST_ENTRY
#define CK_LIST_HEAD LIST_HEAD
#define CK_STAILQ_ENTRY STAILQ_ENTRY
#define CK_STAILQ_HEAD STAILQ_HEAD
#define IF_LLADDR(ifp)							\
    LLADDR((struct sockaddr_dl *)((ifp)->if_addr->ifa_addr))
#define MCDPRINTF printf
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



#define cv_broadcast(cvp)	cv_broadcastpri(cvp, 0)
#define M_COPYFLAGS \
    (M_PKTHDR|M_EOR|M_RDONLY|M_BCAST|M_MCAST|M_PROMISC|M_VLANTAG|M_TSTMP| \
     M_TSTMP_HPREC|M_PROTOFLAGS)
#define M_GETFIB(_m)   rt_m_getfib(_m)
 #define M_PROFILE(m) m_profile(m)
#define M_SETFIB(_m, _fib) do {						\
        KASSERT((_m)->m_flags & M_PKTHDR, ("Attempt to set FIB on non header mbuf."));	\
	((_m)->m_pkthdr.fibnum) = (_fib);				\
} while (0)


#define EPOCH_LOCKED 0x2
#define EPOCH_MAGIC0 0xFADECAFEF00DD00D
#define EPOCH_MAGIC1 0xBADDBABEDEEDFEED
#define EPOCH_PREEMPT 0x1


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

#define SAV_ISCTRORGCM(_sav)	(SAV_ISCTR((_sav)) || SAV_ISGCM((_sav)))

#define _ARRAYLEN(p) (sizeof(p)/sizeof(p[0]))
#define _KEYBITS(key) ((u_int)((key)->bits))
#define _KEYBUF(key) ((caddr_t)((caddr_t)(key) + sizeof(struct sadb_key)))
#define _KEYLEN(key) ((u_int)((key)->bits >> 3))

#define PFKEYV2_REVISION        199806L
#define PFKEY_ADDR_PREFIX(ext) \
	(((struct sadb_address *)(ext))->sadb_address_prefixlen)
#define PFKEY_ADDR_PROTO(ext) \
	(((struct sadb_address *)(ext))->sadb_address_proto)
#define PFKEY_ADDR_SADDR(ext) \
	((struct sockaddr *)((caddr_t)(ext) + sizeof(struct sadb_address)))
#define PFKEY_ALIGN8(a) (1 + (((a) - 1) | (8 - 1)))
#define PF_KEY_V2 2
#define SADB_ACQUIRE     6
#define SADB_ADD         3
#define SADB_DELETE      4
#define SADB_DUMP        10
#define SADB_EXPIRE      8
#define SADB_EXT_ADDRESS_DST          6
#define SADB_EXT_ADDRESS_PROXY        7
#define SADB_EXT_ADDRESS_SRC          5
#define SADB_EXT_IDENTITY_DST         11
#define SADB_EXT_IDENTITY_SRC         10
#define SADB_EXT_KEY_AUTH             8
#define SADB_EXT_KEY_ENCRYPT          9
#define SADB_EXT_LIFETIME_CURRENT     2
#define SADB_EXT_LIFETIME_HARD        3
#define SADB_EXT_LIFETIME_SOFT        4
#define SADB_EXT_PROPOSAL             13
#define SADB_EXT_RESERVED             0
#define SADB_EXT_SA                   1
#define SADB_EXT_SENSITIVITY          12
#define SADB_EXT_SPIRANGE             16
#define SADB_EXT_SUPPORTED_AUTH       14
#define SADB_EXT_SUPPORTED_ENCRYPT    15
#define SADB_FLUSH       9
#define SADB_GET         5
#define SADB_GETSPI      1
#define SADB_IDENTTYPE_FQDN       2
#define SADB_IDENTTYPE_MAX        4
#define SADB_IDENTTYPE_PREFIX     1
#define SADB_IDENTTYPE_RESERVED   0
#define SADB_IDENTTYPE_USERFQDN   3
#define SADB_MAX          22
#define SADB_REGISTER    7
#define SADB_RESERVED    0
#define SADB_SAFLAGS_PFS      1
#define SADB_SASTATE_DEAD     3
#define SADB_SASTATE_DYING    2
#define SADB_SASTATE_LARVAL   0
#define SADB_SASTATE_MATURE   1
#define SADB_SASTATE_MAX      3
#define SADB_UPDATE      2
#define SADB_X_EXT_KMPRIVATE          17
#define SADB_X_EXT_NAT_T_DPORT        22
#define SADB_X_EXT_NAT_T_FRAG         25	
#define SADB_X_EXT_NAT_T_OA           23	
#define SADB_X_EXT_NAT_T_OAI          23	
#define SADB_X_EXT_NAT_T_OAR          24	
#define SADB_X_EXT_NAT_T_SPORT        21
#define SADB_X_EXT_NAT_T_TYPE         20
#define SADB_X_EXT_POLICY             18
#define SADB_X_EXT_SA2                19
#define SADB_X_EXT_SA_REPLAY          26	
#define SADB_X_IDENTTYPE_ADDR     4
#define SADB_X_PCHANGE   12
#define SADB_X_PROMISC   11
#define SADB_X_SPDACQUIRE 17
#define SADB_X_SPDADD     14
#define SADB_X_SPDDELETE  15	
#define SADB_X_SPDDELETE2 22	
#define SADB_X_SPDDUMP    18
#define SADB_X_SPDEXPIRE  21
#define SADB_X_SPDFLUSH   19
#define SADB_X_SPDGET     16
#define SADB_X_SPDSETIDX  20
#define SADB_X_SPDUPDATE  13

#define __PFKEY_V2_H 1
#define IPSEC_REPLAYWSIZE  32

#define ipseclog(x)	do { if (V_ipsec_debug) log x; } while (0)


#define tcp_fastopen_alloc_counter()		NULL
#define tcp_fastopen_check_cookie(i, c, l, lc)	(-1)
#define tcp_fastopen_connect(t)			((void)0)
#define tcp_fastopen_decrement_counter(c)	((void)0)
#define tcp_fastopen_destroy()			((void)0)
#define tcp_fastopen_disable_path(t)		((void)0)
#define tcp_fastopen_init()			((void)0)
#define tcp_fastopen_update_cache(t, m, l, c)	((void)0)


#define DEFAULT_HPTS_LOG 3072
#define DEFAULT_MIN_SLEEP 250	
#define HPTSLOG_RESCHEDULE     15
#define HPTS_HPTS_ACTIVE 0x01
#define HPTS_INPUT_ACTIVE 0x02
#define HPTS_MSEC_IN_SEC 1000
#define HPTS_MS_TO_SLOTS(x) (x * 100)
#define HPTS_MTX_ASSERT(hpts) mtx_assert(&(hpts)->p_mtx, MA_OWNED)
#define HPTS_REMOVE_ALL    (HPTS_REMOVE_INPUT | HPTS_REMOVE_OUTPUT)
#define HPTS_REMOVE_INPUT  0x01
#define HPTS_REMOVE_OUTPUT 0x02
#define HPTS_TICKS_PER_USEC 10
#define HPTS_USEC_IN_MSEC 1000
#define HPTS_USEC_IN_SEC 1000000
#define HPTS_USEC_TO_SLOTS(x) ((x+9) /10)
#define NUM_OF_HPTSI_SLOTS 102400

#define tcp_hpts_insert(a, b) __tcp_hpts_insert(a, b, "__LINE__")
#define tcp_hpts_remove(a, b) __tcp_hpts_remove(a, b, "__LINE__")
#define tcp_queue_to_hpts_immediate(a)__tcp_queue_to_hpts_immediate(a, "__LINE__")

#define tcp_queue_to_input_locked(a, b) __tcp_queue_to_input_locked(a, b, "__LINE__");
#define tcp_set_hpts(a) __tcp_set_hpts(a, "__LINE__")
#define tcp_set_inp_to_drop(a, b) __tcp_set_inp_to_drop(a, b, "__LINE__")
#define SEGQ_EMPTY(tp) TAILQ_EMPTY(&(tp)->t_segq)
#define TCP_FUNC_BEING_REMOVED 0x01   	
#define TF2_DROP_AF_DATA 	0x00000010 

#define TCP_BBR_ACK_COMP_ALG   1096 	
#define TCP_BBR_DRAIN_INC_EXTRA 1084 
#define TCP_BBR_DRAIN_PG      1070 
#define TCP_BBR_EXTRA_GAIN     1097
#define TCP_BBR_LOWGAIN_FD    1078 
#define TCP_BBR_LOWGAIN_HALF  1077 
#define TCP_BBR_LOWGAIN_THRESH 1076 
#define TCP_BBR_MIN_RTO       1080 
#define TCP_BBR_ONE_RETRAN    1073 
#define TCP_BBR_PACE_CROSS     1090
#define TCP_BBR_PACE_DEL_TAR   1087
#define TCP_BBR_PACE_PER_SEC   1086
#define TCP_BBR_PACE_SEG_MAX   1088
#define TCP_BBR_PACE_SEG_MIN   1089
#define TCP_BBR_PROBE_RTT_GAIN 1101
#define TCP_BBR_PROBE_RTT_INT 1072 
#define TCP_BBR_PROBE_RTT_LEN  1102
#define TCP_BBR_RACK_RTT_USE   1098	
#define TCP_BBR_RECFORCE      1068 
#define TCP_BBR_REC_OVER_HPTS 1082 
#define TCP_BBR_RETRAN_WTSO    1099
#define TCP_BBR_RWND_IS_APP   1071 
#define TCP_BBR_STARTUP_EXIT_EPOCH 1085 
#define TCP_BBR_STARTUP_LOSS_EXIT 1074	
#define TCP_BBR_STARTUP_PG    1069 
#define TCP_BBR_UNLIMITED     1083 
#define TCP_BBR_USEDEL_RATE   1079 
#define TCP_BBR_USE_LOWGAIN   1075 
#define TCP_DATA_AFTER_CLOSE   1100
#define TCP_DELACK  	72	
#define TCP_FUNCTION_BLK 8192	
#define TCP_FUNCTION_NAME_LEN_MAX 32
#define TCP_RACK_EARLY_RECOV  1059 
#define TCP_RACK_EARLY_SEG    1060 
#define TCP_RACK_IDLE_REDUCE_HIGH 1092  
#define TCP_RACK_MIN_PACE      1093 	
#define TCP_RACK_MIN_PACE_SEG  1094	
#define TCP_RACK_MIN_TO       1058 
#define TCP_RACK_PACE_ALWAYS  1055 
#define TCP_RACK_PACE_MAX_SEG 1054 
#define TCP_RACK_PACE_REDUCE  1053 
#define TCP_RACK_PKT_DELAY    1064 
#define TCP_RACK_PROP_RATE    1056 
#define TCP_RACK_PRR_SENDALOT 1057 
#define TCP_RACK_REORD_FADE   1062 
#define TCP_RACK_REORD_THRESH 1061 
#define TCP_RACK_SESS_CWV     1066 
#define TCP_RACK_TLP_INC_VAR  1065 
#define TCP_RACK_TLP_REDUCE   1052 
#define TCP_RACK_TLP_THRESH   1063 
#define TCP_RACK_TLP_USE       1095

#define TCPTV_FINWAIT2_TIMEOUT (60*hz)         
#define TCP_RTT_INVALIDATE (TCP_MAXRXTSHIFT / 4)

#define TSTMP_GEQ(a,b)	((int)((a)-(b)) >= 0)
#define TSTMP_GT(a,b)	((int)((a)-(b)) > 0)
#define TSTMP_LT(a,b)	((int)((a)-(b)) < 0)


#define IP6PO_TEMPADDR_NOTPREFER 0 
#define IP6_HDR_ALIGNED_P(ip)	1
#define IP6_REASS_MBUF(ip6af) (*(struct mbuf **)&((ip6af)->ip6af_m))

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

#define IP_HDR_ALIGNED_P(ip)	1
#define BANDLIM_ICMP6_UNREACH 5
#define BANDLIM_ICMP_ECHO 1
#define BANDLIM_ICMP_TSTAMP 2
#define BANDLIM_ICMP_UNREACH 0
#define BANDLIM_MAX 7
#define BANDLIM_RST_CLOSEDPORT 3 
#define BANDLIM_RST_OPENPORT 4   
#define BANDLIM_SCTP_OOTB 6
#define BANDLIM_UNLIMITED -1

#define		ICMP_PARAMPROB_ERRATPTR 0		
#define		ICMP_PARAMPROB_LENGTH 2			
#define		ICMP_PARAMPROB_OPTABSENT 1		
#define		ICMP_UNREACH_FILTER_PROHIB 13		
#define		ICMP_UNREACH_HOST_PRECEDENCE 14		
#define		ICMP_UNREACH_HOST_PROHIB 10		
#define		ICMP_UNREACH_HOST_UNKNOWN 7		
#define		ICMP_UNREACH_NET_UNKNOWN 6		
#define		ICMP_UNREACH_PRECEDENCE_CUTOFF 15	

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


#define CPU_SET_RDONLY  0x0002  
#define CPU_SET_ROOT    0x0001  
#define BITSET_ALLOC(_s, mt, mf)					\
	malloc(__bitset_words(_s) * sizeof(long), mt, (mf))
#define HHOOK_SOCKET_RCV 		2


#define SB_EMPTY_FIXUP(sb) do {						\
	if ((sb)->sb_mb == NULL) {					\
		(sb)->sb_mbtail = NULL;					\
		(sb)->sb_lastrecord = NULL;				\
	}								\
} while (0)




