













#include<sys/cdefs.h>


#include<sys/param.h>

#include<sys/uio.h>
#include<sys/unistd.h>





#include<sys/select.h>


#include<sys/signal.h>







#include<sys/resource.h>








#include<sys/fcntl.h>





#include<sys/errno.h>








#include<sys/time.h>









#include<sys/types.h>



#include<sys/sysctl.h>







#include<sys/queue.h>

#include<sys/file.h>












#define PMC_IS_PENDING_CALLCHAIN(p)				\
	(__predict_false((p)->td_pflags & TDP_CALLCHAIN))
#define PMC_NUM_SR (PMC_UR+1)
#define PMC_PROC_IS_USING_PMCS(p)				\
	(__predict_false(p->p_flag & P_HWPMC))
#define PMC_SOFT_CALL(pr, mo, fu, na)						\
do {										\
	if (__predict_false(pmc_##pr##_##mo##_##fu##_##na.ps_running)) {	\
		struct pmckern_soft ks;						\
		register_t intr;						\
		intr = intr_disable();						\
		PMC_FAKE_TRAPFRAME(&pmc_tf[curcpu]);				\
		ks.pm_ev = pmc_##pr##_##mo##_##fu##_##na.ps_ev.pm_ev_code;	\
		ks.pm_cpu = PCPU_GET(cpuid);					\
		ks.pm_tf = &pmc_tf[curcpu];					\
		PMC_CALL_HOOK_UNLOCKED(curthread,				\
		    PMC_FN_SOFT_SAMPLING, (void *) &ks);			\
		intr_restore(intr);						\
	}									\
} while (0)
#define PMC_SOFT_CALL_TF(pr, mo, fu, na, tf)					\
do {										\
	if (__predict_false(pmc_##pr##_##mo##_##fu##_##na.ps_running)) {	\
		struct pmckern_soft ks;						\
		register_t intr;						\
		intr = intr_disable();						\
		ks.pm_ev = pmc_##pr##_##mo##_##fu##_##na.ps_ev.pm_ev_code;	\
		ks.pm_cpu = PCPU_GET(cpuid);					\
		ks.pm_tf = tf;							\
		PMC_CALL_HOOK_UNLOCKED(curthread,				\
		    PMC_FN_SOFT_SAMPLING, (void *) &ks);			\
		intr_restore(intr);						\
	}									\
} while (0)
#define PMC_SOFT_DECLARE(prov, mod, func, name)					\
	extern struct pmc_soft pmc_##prov##_##mod##_##func##_##name
#define PMC_SOFT_DEFINE(prov, mod, func, name)					\
	PMC_SOFT_DEFINE_EX(prov, mod, func, name, NULL, NULL)
#define PMC_SOFT_DEFINE_EX(prov, mod, func, name, alloc, release)		\
	struct pmc_soft pmc_##prov##_##mod##_##func##_##name =			\
	    { 0, alloc, release, { #prov "_" #mod "_" #func "." #name, 0 } };	\
	SYSINIT(pmc_##prov##_##mod##_##func##_##name##_init, SI_SUB_KDTRACE, 	\
	    SI_ORDER_SECOND + 1, pmc_soft_ev_register, 				\
	    &pmc_##prov##_##mod##_##func##_##name );				\
	SYSUNINIT(pmc_##prov##_##mod##_##func##_##name##_uninit, 		\
	    SI_SUB_KDTRACE, SI_ORDER_SECOND + 1, pmc_soft_ev_deregister,	\
	    &pmc_##prov##_##mod##_##func##_##name )
#define PMC_THREAD_HAS_SAMPLES(td)				\
	(__predict_false((td)->td_pmcpend))

#define PMC_CPUID_LEN 64
#define PMC_SYSCTL_NAME_PREFIX "kern." PMC_MODULE_NAME "."
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

#define BITSET_DEFINE_VAR(t)	BITSET_DEFINE(t, 1)
#define BLKDEV_IOSIZE  PAGE_SIZE	


#define __FreeBSD_version 1200084	
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
#define __min_size(x)	static (x)
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





#define offsetof(type, field) __offsetof(type, field)




#define KTR_COMPILE 0

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
#define bzero(buf, len) __builtin_memset((buf), 0, (len))
#define critical_enter() critical_enter_KBI()
#define critical_exit() critical_exit_KBI()
#define gone_in(major, msg)		__gone_ok(major, msg) _gone_in(major, msg)
#define gone_in_dev(dev, major, msg)	__gone_ok(major, msg) _gone_in_dev(dev, major, msg)
#define memcmp(b1, b2, len) __builtin_memcmp((b1), (b2), (len))
#define memcpy(to, from, len) __builtin_memcpy((to), (from), (len))
#define memmove(dest, src, n) __builtin_memmove((dest), (src), (n))
#define memset(buf, c, len) __builtin_memset((buf), (c), (len))
#define ovbcopy(f, t, l) bcopy((f), (t), (l))

#define RSIZE_MAX (SIZE_MAX >> 1)


#define callout_async_drain(c, d)					\
    _callout_stop_safe(c, 0, d)
#define EPOCH_LOCKED 0x2
#define EPOCH_MAGIC0 0xFADECAFEF00DD00D
#define EPOCH_MAGIC1 0xBADDBABEDEEDFEED
#define EPOCH_PREEMPT 0x1

#define epoch_enter(e)	epoch_enter_KBI((e))
#define epoch_enter_preempt(e, t)	epoch_enter_preempt_KBI((e), (t))
#define epoch_exit(e)	epoch_exit_KBI((e))
#define epoch_exit_preempt(e, t)	epoch_exit_preempt_KBI((e), (t))
#define EPOCH_ALIGN CACHE_LINE_SIZE*2
#define INIT_CHECK(epoch)							\
	do {											\
		if (__predict_false((epoch) == NULL))		\
			return;									\
	} while (0)

#define DROP_GIANT()							\
do {									\
	int _giantcnt = 0;						\
	WITNESS_SAVE_DECL(Giant);					\
									\
	if (mtx_owned(&Giant)) {					\
		WITNESS_SAVE(&Giant.lock_object, Giant);		\
		for (_giantcnt = 0; mtx_owned(&Giant) &&		\
		    !SCHEDULER_STOPPED(); _giantcnt++)			\
			mtx_unlock(&Giant);				\
	}

#define MTX_NOPROFILE   0x00000020	
#define PARTIAL_PICKUP_GIANT()						\
	mtx_assert(&Giant, MA_NOTOWNED);				\
	if (_giantcnt > 0) {						\
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
	if (__predict_false(sdt_probes_enabled)) {				\
		if (__predict_false(sdt_##prov##_##mod##_##func##_##name->id))	\
		(*sdt_probe_func)(sdt_##prov##_##mod##_##func##_##name->id,	\
		    (uintptr_t) arg0, (uintptr_t) arg1, (uintptr_t) arg2,	\
		    (uintptr_t) arg3, (uintptr_t) arg4);			\
	} \
} while (0)
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
#define        PMC_EV_DYN_COUNT        0x1000
#define        PMC_EV_SOFT_FIRST       0x20000
#define        PMC_EV_SOFT_LAST        (PMC_EV_SOFT_FIRST + PMC_EV_DYN_COUNT - 1)
#define        PMC_EV_TSC_FIRST        PMC_EV_TSC_TSC
#define        PMC_EV_TSC_LAST         PMC_EV_TSC_TSC
#define __PMC_EV_E500() \
	__PMC_EV(E500, CYCLES) \
	__PMC_EV(E500, INSTR_COMPLETED) \
	__PMC_EV(E500, UOPS_COMPLETED) \
	__PMC_EV(E500, INSTR_FETCHED) \
	__PMC_EV(E500, UOPS_DECODED) \
	__PMC_EV(E500, PM_EVENT_TRANSITIONS) \
	__PMC_EV(E500, PM_EVENT_CYCLES) \
	__PMC_EV(E500, BRANCH_INSTRS_COMPLETED) \
	__PMC_EV(E500, LOAD_UOPS_COMPLETED) \
	__PMC_EV(E500, STORE_UOPS_COMPLETED) \
	__PMC_EV(E500, CQ_REDIRECTS) \
	__PMC_EV(E500, BRANCHES_FINISHED) \
	__PMC_EV(E500, TAKEN_BRANCHES_FINISHED) \
	__PMC_EV(E500, FINISHED_UNCOND_BRANCHES_MISS_BTB) \
	__PMC_EV(E500, BRANCH_MISPRED) \
	__PMC_EV(E500, BTB_BRANCH_MISPRED_FROM_DIRECTION) \
	__PMC_EV(E500, BTB_HITS_PSEUDO_HITS) \
	__PMC_EV(E500, CYCLES_DECODE_STALLED) \
	__PMC_EV(E500, CYCLES_ISSUE_STALLED) \
	__PMC_EV(E500, CYCLES_BRANCH_ISSUE_STALLED) \
	__PMC_EV(E500, CYCLES_SU1_SCHED_STALLED) \
	__PMC_EV(E500, CYCLES_SU2_SCHED_STALLED) \
	__PMC_EV(E500, CYCLES_MU_SCHED_STALLED) \
	__PMC_EV(E500, CYCLES_LRU_SCHED_STALLED) \
	__PMC_EV(E500, CYCLES_BU_SCHED_STALLED) \
	__PMC_EV(E500, TOTAL_TRANSLATED) \
	__PMC_EV(E500, LOADS_TRANSLATED) \
	__PMC_EV(E500, STORES_TRANSLATED) \
	__PMC_EV(E500, TOUCHES_TRANSLATED) \
	__PMC_EV(E500, CACHEOPS_TRANSLATED) \
	__PMC_EV(E500, CACHE_INHIBITED_ACCESS_TRANSLATED) \
	__PMC_EV(E500, GUARDED_LOADS_TRANSLATED) \
	__PMC_EV(E500, WRITE_THROUGH_STORES_TRANSLATED) \
	__PMC_EV(E500, MISALIGNED_LOAD_STORE_ACCESS_TRANSLATED) \
	__PMC_EV(E500, TOTAL_ALLOCATED_TO_DLFB) \
	__PMC_EV(E500, LOADS_TRANSLATED_ALLOCATED_TO_DLFB) \
	__PMC_EV(E500, STORES_COMPLETED_ALLOCATED_TO_DLFB) \
	__PMC_EV(E500, TOUCHES_TRANSLATED_ALLOCATED_TO_DLFB) \
	__PMC_EV(E500, STORES_COMPLETED) \
	__PMC_EV(E500, DATA_L1_CACHE_LOCKS) \
	__PMC_EV(E500, DATA_L1_CACHE_RELOADS) \
	__PMC_EV(E500, DATA_L1_CACHE_CASTOUTS) \
	__PMC_EV(E500, LOAD_MISS_DLFB_FULL) \
	__PMC_EV(E500, LOAD_MISS_LDQ_FULL) \
	__PMC_EV(E500, LOAD_GUARDED_MISS) \
	__PMC_EV(E500, STORE_TRANSLATE_WHEN_QUEUE_FULL) \
	__PMC_EV(E500, ADDRESS_COLLISION) \
	__PMC_EV(E500, DATA_MMU_MISS) \
	__PMC_EV(E500, DATA_MMU_BUSY) \
	__PMC_EV(E500, PART2_MISALIGNED_CACHE_ACCESS) \
	__PMC_EV(E500, LOAD_MISS_DLFB_FULL_CYCLES) \
	__PMC_EV(E500, LOAD_MISS_LDQ_FULL_CYCLES) \
	__PMC_EV(E500, LOAD_GUARDED_MISS_CYCLES) \
	__PMC_EV(E500, STORE_TRANSLATE_WHEN_QUEUE_FULL_CYCLES) \
	__PMC_EV(E500, ADDRESS_COLLISION_CYCLES) \
	__PMC_EV(E500, DATA_MMU_MISS_CYCLES) \
	__PMC_EV(E500, DATA_MMU_BUSY_CYCLES) \
	__PMC_EV(E500, PART2_MISALIGNED_CACHE_ACCESS_CYCLES) \
	__PMC_EV(E500, INSTR_L1_CACHE_LOCKS) \
	__PMC_EV(E500, INSTR_L1_CACHE_RELOADS) \
	__PMC_EV(E500, INSTR_L1_CACHE_FETCHES) \
	__PMC_EV(E500, INSTR_MMU_TLB4K_RELOADS) \
	__PMC_EV(E500, INSTR_MMU_VSP_RELOADS) \
	__PMC_EV(E500, DATA_MMU_TLB4K_RELOADS) \
	__PMC_EV(E500, DATA_MMU_VSP_RELOADS) \
	__PMC_EV(E500, L2MMU_MISSES) \
	__PMC_EV(E500, BIU_MASTER_REQUESTS) \
	__PMC_EV(E500, BIU_MASTER_INSTR_SIDE_REQUESTS) \
	__PMC_EV(E500, BIU_MASTER_DATA_SIDE_REQUESTS) \
	__PMC_EV(E500, BIU_MASTER_DATA_SIDE_CASTOUT_REQUESTS) \
	__PMC_EV(E500, BIU_MASTER_RETRIES) \
	__PMC_EV(E500, SNOOP_REQUESTS) \
	__PMC_EV(E500, SNOOP_HITS) \
	__PMC_EV(E500, SNOOP_PUSHES) \
	__PMC_EV(E500, SNOOP_RETRIES) \
	__PMC_EV(E500, DLFB_LOAD_MISS_CYCLES) \
	__PMC_EV(E500, ILFB_FETCH_MISS_CYCLES) \
	__PMC_EV(E500, EXT_INPU_INTR_LATENCY_CYCLES) \
	__PMC_EV(E500, CRIT_INPUT_INTR_LATENCY_CYCLES) \
	__PMC_EV(E500, EXT_INPUT_INTR_PENDING_LATENCY_CYCLES) \
	__PMC_EV(E500, CRIT_INPUT_INTR_PENDING_LATENCY_CYCLES) \
	__PMC_EV(E500, PMC0_OVERFLOW) \
	__PMC_EV(E500, PMC1_OVERFLOW) \
	__PMC_EV(E500, PMC2_OVERFLOW) \
	__PMC_EV(E500, PMC3_OVERFLOW) \
	__PMC_EV(E500, INTERRUPTS_TAKEN) \
	__PMC_EV(E500, EXT_INPUT_INTR_TAKEN) \
	__PMC_EV(E500, CRIT_INPUT_INTR_TAKEN) \
	__PMC_EV(E500, SYSCALL_TRAP_INTR) \
	__PMC_EV(E500, TLB_BIT_TRANSITIONS) \
	__PMC_EV(E500, L2_LINEFILL_BUFFER) \
	__PMC_EV(E500, LV2_VS) \
	__PMC_EV(E500, CASTOUTS_RELEASED) \
	__PMC_EV(E500, INTV_ALLOCATIONS) \
	__PMC_EV(E500, DLFB_RETRIES_TO_MBAR) \
	__PMC_EV(E500, STORE_RETRIES) \
	__PMC_EV(E500, STASH_L1_HITS) \
	__PMC_EV(E500, STASH_L2_HITS) \
	__PMC_EV(E500, STASH_BUSY_1) \
	__PMC_EV(E500, STASH_BUSY_2) \
	__PMC_EV(E500, STASH_BUSY_3) \
	__PMC_EV(E500, STASH_HITS) \
	__PMC_EV(E500, STASH_HIT_DLFB) \
	__PMC_EV(E500, STASH_REQUESTS) \
	__PMC_EV(E500, STASH_REQUESTS_L1) \
	__PMC_EV(E500, STASH_REQUESTS_L2) \
	__PMC_EV(E500, STALLS_NO_CAQ_OR_COB) \
	__PMC_EV(E500, L2_CACHE_ACCESSES) \
	__PMC_EV(E500, L2_HIT_CACHE_ACCESSES) \
	__PMC_EV(E500, L2_CACHE_DATA_ACCESSES) \
	__PMC_EV(E500, L2_CACHE_DATA_HITS) \
	__PMC_EV(E500, L2_CACHE_INSTR_ACCESSES) \
	__PMC_EV(E500, L2_CACHE_INSTR_HITS) \
	__PMC_EV(E500, L2_CACHE_ALLOCATIONS) \
	__PMC_EV(E500, L2_CACHE_DATA_ALLOCATIONS) \
	__PMC_EV(E500, L2_CACHE_DIRTY_DATA_ALLOCATIONS) \
	__PMC_EV(E500, L2_CACHE_INSTR_ALLOCATIONS) \
	__PMC_EV(E500, L2_CACHE_UPDATES) \
	__PMC_EV(E500, L2_CACHE_CLEAN_UPDATES) \
	__PMC_EV(E500, L2_CACHE_DIRTY_UPDATES) \
	__PMC_EV(E500, L2_CACHE_CLEAN_REDUNDANT_UPDATES) \
	__PMC_EV(E500, L2_CACHE_DIRTY_REDUNDANT_UPDATES) \
	__PMC_EV(E500, L2_CACHE_LOCKS) \
	__PMC_EV(E500, L2_CACHE_CASTOUTS) \
	__PMC_EV(E500, L2_CACHE_DATA_DIRTY_HITS) \
	__PMC_EV(E500, INSTR_LFB_WENT_HIGH_PRIORITY) \
	__PMC_EV(E500, SNOOP_THROTTLING_TURNED_ON) \
	__PMC_EV(E500, L2_CLEAN_LINE_INVALIDATIONS) \
	__PMC_EV(E500, L2_INCOHERENT_LINE_INVALIDATIONS) \
	__PMC_EV(E500, L2_COHERENT_LINE_INVALIDATIONS) \
	__PMC_EV(E500, COHERENT_LOOKUP_MISS_DUE_TO_VALID_BUT_INCOHERENT_MATCHES) \
	__PMC_EV(E500, IAC1S_DETECTED) \
	__PMC_EV(E500, IAC2S_DETECTED) \
	__PMC_EV(E500, DAC1S_DTECTED) \
	__PMC_EV(E500, DAC2S_DTECTED) \
	__PMC_EV(E500, DVT0_DETECTED) \
	__PMC_EV(E500, DVT1_DETECTED) \
	__PMC_EV(E500, DVT2_DETECTED) \
	__PMC_EV(E500, DVT3_DETECTED) \
	__PMC_EV(E500, DVT4_DETECTED) \
	__PMC_EV(E500, DVT5_DETECTED) \
	__PMC_EV(E500, DVT6_DETECTED) \
	__PMC_EV(E500, DVT7_DETECTED) \
	__PMC_EV(E500, CYCLES_COMPLETION_STALLED_NEXUS_FIFO_FULL) \
	__PMC_EV(E500, FPU_DOUBLE_PUMP) \
	__PMC_EV(E500, FPU_FINISH) \
	__PMC_EV(E500, FPU_DIVIDE_CYCLES) \
	__PMC_EV(E500, FPU_DENORM_INPUT_CYCLES) \
	__PMC_EV(E500, FPU_RESULT_STALL_CYCLES) \
	__PMC_EV(E500, FPU_FPSCR_FULL_STALL) \
	__PMC_EV(E500, FPU_PIPE_SYNC_STALLS) \
	__PMC_EV(E500, FPU_INPUT_DATA_STALLS) \
	__PMC_EV(E500, DECORATED_LOADS) \
	__PMC_EV(E500, DECORATED_STORES) \
	__PMC_EV(E500, LOAD_RETRIES) \
	__PMC_EV(E500, STWCX_SUCCESSES) \
	__PMC_EV(E500, STWCX_FAILURES) \

#define __PMC_EV_MIPS24K()                         \
	__PMC_EV(MIPS24K, CYCLE)                   \
	__PMC_EV(MIPS24K, INSTR_EXECUTED)          \
	__PMC_EV(MIPS24K, BRANCH_COMPLETED)        \
	__PMC_EV(MIPS24K, BRANCH_MISPRED)          \
	__PMC_EV(MIPS24K, RETURN)                  \
	__PMC_EV(MIPS24K, RETURN_MISPRED)          \
	__PMC_EV(MIPS24K, RETURN_NOT_31)           \
	__PMC_EV(MIPS24K, RETURN_NOTPRED)          \
	__PMC_EV(MIPS24K, ITLB_ACCESS)             \
	__PMC_EV(MIPS24K, ITLB_MISS)               \
	__PMC_EV(MIPS24K, DTLB_ACCESS)             \
	__PMC_EV(MIPS24K, DTLB_MISS)               \
	__PMC_EV(MIPS24K, JTLB_IACCESS)            \
	__PMC_EV(MIPS24K, JTLB_IMISS)              \
	__PMC_EV(MIPS24K, JTLB_DACCESS)            \
	__PMC_EV(MIPS24K, JTLB_DMISS)              \
	__PMC_EV(MIPS24K, IC_FETCH)                \
	__PMC_EV(MIPS24K, IC_MISS)                 \
	__PMC_EV(MIPS24K, DC_LOADSTORE)            \
	__PMC_EV(MIPS24K, DC_WRITEBACK)            \
	__PMC_EV(MIPS24K, DC_MISS)                 \
	__PMC_EV(MIPS24K, STORE_MISS)              \
	__PMC_EV(MIPS24K, LOAD_MISS)               \
	__PMC_EV(MIPS24K, INTEGER_COMPLETED)       \
	__PMC_EV(MIPS24K, FP_COMPLETED)            \
	__PMC_EV(MIPS24K, LOAD_COMPLETED)          \
	__PMC_EV(MIPS24K, STORE_COMPLETED)         \
	__PMC_EV(MIPS24K, BARRIER_COMPLETED)       \
	__PMC_EV(MIPS24K, MIPS16_COMPLETED)        \
	__PMC_EV(MIPS24K, NOP_COMPLETED)           \
	__PMC_EV(MIPS24K, INTEGER_MULDIV_COMPLETED)\
	__PMC_EV(MIPS24K, RF_STALL)                \
	__PMC_EV(MIPS24K, INSTR_REFETCH)           \
	__PMC_EV(MIPS24K, STORE_COND_COMPLETED)    \
	__PMC_EV(MIPS24K, STORE_COND_FAILED)       \
	__PMC_EV(MIPS24K, ICACHE_REQUESTS)         \
	__PMC_EV(MIPS24K, ICACHE_HIT)              \
	__PMC_EV(MIPS24K, L2_WRITEBACK)            \
	__PMC_EV(MIPS24K, L2_ACCESS)               \
	__PMC_EV(MIPS24K, L2_MISS)                 \
	__PMC_EV(MIPS24K, L2_ERR_CORRECTED)        \
	__PMC_EV(MIPS24K, EXCEPTIONS)              \
	__PMC_EV(MIPS24K, RF_CYCLES_STALLED)       \
	__PMC_EV(MIPS24K, IFU_CYCLES_STALLED)      \
	__PMC_EV(MIPS24K, ALU_CYCLES_STALLED)      \
	__PMC_EV(MIPS24K, UNCACHED_LOAD)           \
	__PMC_EV(MIPS24K, UNCACHED_STORE)          \
	__PMC_EV(MIPS24K, CP2_REG_TO_REG_COMPLETED)\
	__PMC_EV(MIPS24K, MFTC_COMPLETED)          \
	__PMC_EV(MIPS24K, IC_BLOCKED_CYCLES)       \
	__PMC_EV(MIPS24K, DC_BLOCKED_CYCLES)       \
	__PMC_EV(MIPS24K, L2_IMISS_STALL_CYCLES)   \
	__PMC_EV(MIPS24K, L2_DMISS_STALL_CYCLES)   \
	__PMC_EV(MIPS24K, DMISS_CYCLES)            \
	__PMC_EV(MIPS24K, L2_MISS_CYCLES)          \
	__PMC_EV(MIPS24K, UNCACHED_BLOCK_CYCLES)   \
	__PMC_EV(MIPS24K, MDU_STALL_CYCLES)        \
	__PMC_EV(MIPS24K, FPU_STALL_CYCLES)        \
	__PMC_EV(MIPS24K, CP2_STALL_CYCLES)        \
	__PMC_EV(MIPS24K, COREXTEND_STALL_CYCLES)  \
	__PMC_EV(MIPS24K, ISPRAM_STALL_CYCLES)     \
	__PMC_EV(MIPS24K, DSPRAM_STALL_CYCLES)     \
	__PMC_EV(MIPS24K, CACHE_STALL_CYCLES)      \
	__PMC_EV(MIPS24K, LOAD_TO_USE_STALLS)      \
	__PMC_EV(MIPS24K, BASE_MISPRED_STALLS)     \
	__PMC_EV(MIPS24K, CPO_READ_STALLS)         \
	__PMC_EV(MIPS24K, BRANCH_MISPRED_CYCLES)   \
	__PMC_EV(MIPS24K, IFETCH_BUFFER_FULL)      \
	__PMC_EV(MIPS24K, FETCH_BUFFER_ALLOCATED)  \
	__PMC_EV(MIPS24K, EJTAG_ITRIGGER)          \
	__PMC_EV(MIPS24K, EJTAG_DTRIGGER)          \
	__PMC_EV(MIPS24K, FSB_LT_QUARTER)          \
	__PMC_EV(MIPS24K, FSB_QUARTER_TO_HALF)     \
	__PMC_EV(MIPS24K, FSB_GT_HALF)             \
	__PMC_EV(MIPS24K, FSB_FULL_PIPELINE_STALLS)\
	__PMC_EV(MIPS24K, LDQ_LT_QUARTER)          \
	__PMC_EV(MIPS24K, LDQ_QUARTER_TO_HALF)     \
	__PMC_EV(MIPS24K, LDQ_GT_HALF)             \
	__PMC_EV(MIPS24K, LDQ_FULL_PIPELINE_STALLS)\
	__PMC_EV(MIPS24K, WBB_LT_QUARTER)          \
	__PMC_EV(MIPS24K, WBB_QUARTER_TO_HALF)     \
	__PMC_EV(MIPS24K, WBB_GT_HALF)             \
	__PMC_EV(MIPS24K, WBB_FULL_PIPELINE_STALLS) \
	__PMC_EV(MIPS24K, REQUEST_LATENCY)         \
	__PMC_EV(MIPS24K, REQUEST_COUNT)
#define __PMC_EV_MIPS74K()			\
	__PMC_EV(MIPS74K, CYCLES)		\
	__PMC_EV(MIPS74K, INSTR_EXECUTED)	\
	__PMC_EV(MIPS74K, PREDICTED_JR_31)	\
	__PMC_EV(MIPS74K, JR_31_MISPREDICTIONS)	\
	__PMC_EV(MIPS74K, REDIRECT_STALLS)	\
	__PMC_EV(MIPS74K, JR_31_NO_PREDICTIONS)	\
	__PMC_EV(MIPS74K, ITLB_ACCESSES)	\
	__PMC_EV(MIPS74K, ITLB_MISSES)		\
	__PMC_EV(MIPS74K, JTLB_INSN_MISSES)	\
	__PMC_EV(MIPS74K, ICACHE_ACCESSES)	\
	__PMC_EV(MIPS74K, ICACHE_MISSES)	\
	__PMC_EV(MIPS74K, ICACHE_MISS_STALLS)	\
	__PMC_EV(MIPS74K, UNCACHED_IFETCH_STALLS)	\
	__PMC_EV(MIPS74K, PDTRACE_BACK_STALLS)	\
	__PMC_EV(MIPS74K, IFU_REPLAYS)		\
	__PMC_EV(MIPS74K, KILLED_FETCH_SLOTS)	\
	__PMC_EV(MIPS74K, IFU_IDU_MISS_PRED_UPSTREAM_CYCLES)	\
	__PMC_EV(MIPS74K, IFU_IDU_NO_FETCH_CYCLES)	\
	__PMC_EV(MIPS74K, IFU_IDU_CLOGED_DOWNSTREAM_CYCLES)	\
	__PMC_EV(MIPS74K, DDQ0_FULL_DR_STALLS)	\
	__PMC_EV(MIPS74K, DDQ1_FULL_DR_STALLS)	\
	__PMC_EV(MIPS74K, ALCB_FULL_DR_STALLS)	\
	__PMC_EV(MIPS74K, AGCB_FULL_DR_STALLS)	\
	__PMC_EV(MIPS74K, CLDQ_FULL_DR_STALLS)	\
	__PMC_EV(MIPS74K, IODQ_FULL_DR_STALLS)	\
	__PMC_EV(MIPS74K, ALU_EMPTY_CYCLES)	\
	__PMC_EV(MIPS74K, AGEN_EMPTY_CYCLES)	\
	__PMC_EV(MIPS74K, ALU_OPERANDS_NOT_READY_CYCLES)	\
	__PMC_EV(MIPS74K, AGEN_OPERANDS_NOT_READY_CYCLES)	\
	__PMC_EV(MIPS74K, ALU_NO_ISSUES_CYCLES)	\
	__PMC_EV(MIPS74K, AGEN_NO_ISSUES_CYCLES)	\
	__PMC_EV(MIPS74K, ALU_BUBBLE_CYCLES)	\
	__PMC_EV(MIPS74K, AGEN_BUBBLE_CYCLES)	\
	__PMC_EV(MIPS74K, SINGLE_ISSUE_CYCLES)	\
	__PMC_EV(MIPS74K, DUAL_ISSUE_CYCLES)	\
	__PMC_EV(MIPS74K, OOO_ALU_ISSUE_CYCLES)	\
	__PMC_EV(MIPS74K, OOO_AGEN_ISSUE_CYCLES)	\
	__PMC_EV(MIPS74K, JALR_JALR_HB_INSNS)	\
	__PMC_EV(MIPS74K, DCACHE_LINE_REFILL_REQUESTS)	\
	__PMC_EV(MIPS74K, DCACHE_LOAD_ACCESSES)	\
	__PMC_EV(MIPS74K, DCACHE_ACCESSES)	\
	__PMC_EV(MIPS74K, DCACHE_WRITEBACKS)	\
	__PMC_EV(MIPS74K, DCACHE_MISSES)	\
	__PMC_EV(MIPS74K, JTLB_DATA_ACCESSES)	\
	__PMC_EV(MIPS74K, JTLB_DATA_MISSES)	\
	__PMC_EV(MIPS74K, LOAD_STORE_REPLAYS)	\
	__PMC_EV(MIPS74K, VA_TRANSALTION_CORNER_CASES)	\
	__PMC_EV(MIPS74K, LOAD_STORE_BLOCKED_CYCLES)	\
	__PMC_EV(MIPS74K, LOAD_STORE_NO_FILL_REQUESTS)	\
	__PMC_EV(MIPS74K, L2_CACHE_WRITEBACKS)	\
	__PMC_EV(MIPS74K, L2_CACHE_ACCESSES)	\
	__PMC_EV(MIPS74K, L2_CACHE_MISSES)	\
	__PMC_EV(MIPS74K, L2_CACHE_MISS_CYCLES)	\
	__PMC_EV(MIPS74K, FSB_FULL_STALLS)	\
	__PMC_EV(MIPS74K, FSB_OVER_50_FULL)	\
	__PMC_EV(MIPS74K, LDQ_FULL_STALLS)	\
	__PMC_EV(MIPS74K, LDQ_OVER_50_FULL)	\
	__PMC_EV(MIPS74K, WBB_FULL_STALLS)	\
	__PMC_EV(MIPS74K, WBB_OVER_50_FULL)	\
	__PMC_EV(MIPS74K, LOAD_MISS_CONSUMER_REPLAYS)	\
	__PMC_EV(MIPS74K, CP1_CP2_LOAD_INSNS)	\
	__PMC_EV(MIPS74K, JR_NON_31_INSNS)	\
	__PMC_EV(MIPS74K, MISPREDICTED_JR_31_INSNS)	\
	__PMC_EV(MIPS74K, BRANCH_INSNS)		\
	__PMC_EV(MIPS74K, CP1_CP2_COND_BRANCH_INSNS)	\
	__PMC_EV(MIPS74K, BRANCH_LIKELY_INSNS)	\
	__PMC_EV(MIPS74K, MISPREDICTED_BRANCH_LIKELY_INSNS)	\
	__PMC_EV(MIPS74K, COND_BRANCH_INSNS)	\
	__PMC_EV(MIPS74K, MISPREDICTED_BRANCH_INSNS)	\
	__PMC_EV(MIPS74K, INTEGER_INSNS)	\
	__PMC_EV(MIPS74K, FPU_INSNS)		\
	__PMC_EV(MIPS74K, LOAD_INSNS)		\
	__PMC_EV(MIPS74K, STORE_INSNS)		\
	__PMC_EV(MIPS74K, J_JAL_INSNS)		\
	__PMC_EV(MIPS74K, MIPS16_INSNS)		\
	__PMC_EV(MIPS74K, NOP_INSNS)		\
	__PMC_EV(MIPS74K, NT_MUL_DIV_INSNS)	\
	__PMC_EV(MIPS74K, DSP_INSNS)		\
	__PMC_EV(MIPS74K, ALU_DSP_SATURATION_INSNS)	\
	__PMC_EV(MIPS74K, DSP_BRANCH_INSNS)	\
	__PMC_EV(MIPS74K, MDU_DSP_SATURATION_INSNS)	\
	__PMC_EV(MIPS74K, UNCACHED_LOAD_INSNS)	\
	__PMC_EV(MIPS74K, UNCACHED_STORE_INSNS)	\
	__PMC_EV(MIPS74K, EJTAG_INSN_TRIGGERS)	\
	__PMC_EV(MIPS74K, CP1_BRANCH_MISPREDICTIONS)	\
	__PMC_EV(MIPS74K, SC_INSNS)		\
	__PMC_EV(MIPS74K, FAILED_SC_INSNS)	\
	__PMC_EV(MIPS74K, PREFETCH_INSNS)	\
	__PMC_EV(MIPS74K, CACHE_HIT_PREFETCH_INSNS)	\
	__PMC_EV(MIPS74K, NO_INSN_CYCLES)	\
	__PMC_EV(MIPS74K, LOAD_MISS_INSNS)	\
	__PMC_EV(MIPS74K, ONE_INSN_CYCLES)	\
	__PMC_EV(MIPS74K, TWO_INSNS_CYCLES)	\
	__PMC_EV(MIPS74K, GFIFO_BLOCKED_CYCLES)	\
	__PMC_EV(MIPS74K, CP1_CP2_STORE_INSNS)	\
	__PMC_EV(MIPS74K, MISPREDICTION_STALLS)	\
	__PMC_EV(MIPS74K, MISPREDICTED_BRANCH_INSNS_CYCLES)	\
	__PMC_EV(MIPS74K, EXCEPTIONS_TAKEN)	\
	__PMC_EV(MIPS74K, GRADUATION_REPLAYS)	\
	__PMC_EV(MIPS74K, COREEXTEND_EVENTS)	\
	__PMC_EV(MIPS74K, ISPRAM_EVENTS)	\
	__PMC_EV(MIPS74K, DSPRAM_EVENTS)	\
	__PMC_EV(MIPS74K, L2_CACHE_SINGLE_BIT_ERRORS)	\
	__PMC_EV(MIPS74K, SYSTEM_EVENT_0)	\
	__PMC_EV(MIPS74K, SYSTEM_EVENT_1)	\
	__PMC_EV(MIPS74K, SYSTEM_EVENT_2)	\
	__PMC_EV(MIPS74K, SYSTEM_EVENT_3)	\
	__PMC_EV(MIPS74K, SYSTEM_EVENT_4)	\
	__PMC_EV(MIPS74K, SYSTEM_EVENT_5)	\
	__PMC_EV(MIPS74K, SYSTEM_EVENT_6)	\
	__PMC_EV(MIPS74K, SYSTEM_EVENT_7)	\
	__PMC_EV(MIPS74K, OCP_ALL_REQUESTS)	\
	__PMC_EV(MIPS74K, OCP_ALL_CACHEABLE_REQUESTS)	\
	__PMC_EV(MIPS74K, OCP_READ_REQUESTS)	\
	__PMC_EV(MIPS74K, OCP_READ_CACHEABLE_REQUESTS)	\
	__PMC_EV(MIPS74K, OCP_WRITE_REQUESTS)	\
	__PMC_EV(MIPS74K, OCP_WRITE_CACHEABLE_REQUESTS)	\
	__PMC_EV(MIPS74K, FSB_LESS_25_FULL)	\
	__PMC_EV(MIPS74K, FSB_25_50_FULL)	\
	__PMC_EV(MIPS74K, LDQ_LESS_25_FULL)	\
	__PMC_EV(MIPS74K, LDQ_25_50_FULL)	\
	__PMC_EV(MIPS74K, WBB_LESS_25_FULL)	\
	__PMC_EV(MIPS74K, WBB_25_50_FULL)
#define __PMC_EV_OCTEON()                         \
    __PMC_EV(OCTEON, CLK)                         \
    __PMC_EV(OCTEON, ISSUE)                       \
    __PMC_EV(OCTEON, RET)                         \
    __PMC_EV(OCTEON, NISSUE)                      \
    __PMC_EV(OCTEON, SISSUE)                      \
    __PMC_EV(OCTEON, DISSUE)                      \
    __PMC_EV(OCTEON, IFI)                         \
    __PMC_EV(OCTEON, BR)                          \
    __PMC_EV(OCTEON, BRMIS)                       \
    __PMC_EV(OCTEON, J)                           \
    __PMC_EV(OCTEON, JMIS)                        \
    __PMC_EV(OCTEON, REPLAY)                      \
    __PMC_EV(OCTEON, IUNA)                        \
    __PMC_EV(OCTEON, TRAP)                        \
    __PMC_EV(OCTEON, UULOAD)                      \
    __PMC_EV(OCTEON, UUSTORE)                     \
    __PMC_EV(OCTEON, ULOAD)                       \
    __PMC_EV(OCTEON, USTORE)                      \
    __PMC_EV(OCTEON, EC)                          \
    __PMC_EV(OCTEON, MC)                          \
    __PMC_EV(OCTEON, CC)                          \
    __PMC_EV(OCTEON, CSRC)                        \
    __PMC_EV(OCTEON, CFETCH)                      \
    __PMC_EV(OCTEON, CPREF)                       \
    __PMC_EV(OCTEON, ICA)                         \
    __PMC_EV(OCTEON, II)                          \
    __PMC_EV(OCTEON, IP)                          \
    __PMC_EV(OCTEON, CIMISS)                      \
    __PMC_EV(OCTEON, WBUF)                        \
    __PMC_EV(OCTEON, WDAT)                        \
    __PMC_EV(OCTEON, WBUFLD)                      \
    __PMC_EV(OCTEON, WBUFFL)                      \
    __PMC_EV(OCTEON, WBUFTR)                      \
    __PMC_EV(OCTEON, BADD)                        \
    __PMC_EV(OCTEON, BADDL2)                      \
    __PMC_EV(OCTEON, BFILL)                       \
    __PMC_EV(OCTEON, DDIDS)                       \
    __PMC_EV(OCTEON, IDIDS)                       \
    __PMC_EV(OCTEON, DIDNA)                       \
    __PMC_EV(OCTEON, LDS)                         \
    __PMC_EV(OCTEON, LMLDS)                       \
    __PMC_EV(OCTEON, IOLDS)                       \
    __PMC_EV(OCTEON, DMLDS)                       \
    __PMC_EV(OCTEON, STS)                         \
    __PMC_EV(OCTEON, LMSTS)                       \
    __PMC_EV(OCTEON, IOSTS)                       \
    __PMC_EV(OCTEON, IOBDMA)                      \
    __PMC_EV(OCTEON, DTLB)                        \
    __PMC_EV(OCTEON, DTLBAD)                      \
    __PMC_EV(OCTEON, ITLB)                        \
    __PMC_EV(OCTEON, SYNC)                        \
    __PMC_EV(OCTEON, SYNCIOB)                     \
    __PMC_EV(OCTEON, SYNCW)
#define __PMC_EV_PPC7450()						\
	__PMC_EV(PPC7450, CYCLE)					\
	__PMC_EV(PPC7450, INSTR_COMPLETED)				\
	__PMC_EV(PPC7450, TLB_BIT_TRANSITIONS)				\
	__PMC_EV(PPC7450, INSTR_DISPATCHED)				\
	__PMC_EV(PPC7450, PMON_EXCEPT)					\
	__PMC_EV(PPC7450, PMON_SIG)					\
	__PMC_EV(PPC7450, VPU_INSTR_COMPLETED)				\
	__PMC_EV(PPC7450, VFPU_INSTR_COMPLETED)				\
	__PMC_EV(PPC7450, VIU1_INSTR_COMPLETED)				\
	__PMC_EV(PPC7450, VIU2_INSTR_COMPLETED)				\
	__PMC_EV(PPC7450, MTVSCR_INSTR_COMPLETED)			\
	__PMC_EV(PPC7450, MTVRSAVE_INSTR_COMPLETED)			\
	__PMC_EV(PPC7450, VPU_INSTR_WAIT_CYCLES)			\
	__PMC_EV(PPC7450, VFPU_INSTR_WAIT_CYCLES)			\
	__PMC_EV(PPC7450, VIU1_INSTR_WAIT_CYCLES)			\
	__PMC_EV(PPC7450, VIU2_INSTR_WAIT_CYCLES)			\
	__PMC_EV(PPC7450, MFVSCR_SYNC_CYCLES)				\
	__PMC_EV(PPC7450, VSCR_SAT_SET)					\
	__PMC_EV(PPC7450, STORE_INSTR_COMPLETED)			\
	__PMC_EV(PPC7450, L1_INSTR_CACHE_MISSES)			\
	__PMC_EV(PPC7450, L1_DATA_SNOOPS)				\
	__PMC_EV(PPC7450, UNRESOLVED_BRANCHES)				\
	__PMC_EV(PPC7450, SPEC_BUFFER_CYCLES)				\
	__PMC_EV(PPC7450, BRANCH_UNIT_STALL_CYCLES)			\
	__PMC_EV(PPC7450, TRUE_BRANCH_TARGET_HITS)			\
	__PMC_EV(PPC7450, BRANCH_LINK_STAC_PREDICTED)			\
	__PMC_EV(PPC7450, GPR_ISSUE_QUEUE_DISPATCHES)			\
	__PMC_EV(PPC7450, CYCLES_THREE_INSTR_DISPATCHED)		\
	__PMC_EV(PPC7450, THRESHOLD_INSTR_QUEUE_ENTRIES_CYCLES)		\
	__PMC_EV(PPC7450, THRESHOLD_VEC_INSTR_QUEUE_ENTRIES_CYCLES)	\
	__PMC_EV(PPC7450, CYCLES_NO_COMPLETED_INSTRS)			\
	__PMC_EV(PPC7450, IU2_INSTR_COMPLETED)				\
	__PMC_EV(PPC7450, BRANCHES_COMPLETED)				\
	__PMC_EV(PPC7450, EIEIO_INSTR_COMPLETED)			\
	__PMC_EV(PPC7450, MTSPR_INSTR_COMPLETED)			\
	__PMC_EV(PPC7450, SC_INSTR_COMPLETED)				\
	__PMC_EV(PPC7450, LS_LM_COMPLETED)				\
	__PMC_EV(PPC7450, ITLB_HW_TABLE_SEARCH_CYCLES)			\
	__PMC_EV(PPC7450, DTLB_HW_SEARCH_CYCLES_OVER_THRESHOLD)		\
	__PMC_EV(PPC7450, L1_INSTR_CACHE_ACCESSES)			\
	__PMC_EV(PPC7450, INSTR_BKPT_MATCHES)				\
	__PMC_EV(PPC7450, L1_DATA_CACHE_LOAD_MISS_CYCLES_OVER_THRESHOLD)\
	__PMC_EV(PPC7450, L1_DATA_SNOOP_HIT_ON_MODIFIED)		\
	__PMC_EV(PPC7450, LOAD_MISS_ALIAS)				\
	__PMC_EV(PPC7450, LOAD_MISS_ALIAS_ON_TOUCH)			\
	__PMC_EV(PPC7450, TOUCH_ALIAS)					\
	__PMC_EV(PPC7450, L1_DATA_SNOOP_HIT_CASTOUT_QUEUE)		\
	__PMC_EV(PPC7450, L1_DATA_SNOOP_HIT_CASTOUT)			\
	__PMC_EV(PPC7450, L1_DATA_SNOOP_HITS)				\
	__PMC_EV(PPC7450, WRITE_THROUGH_STORES)				\
	__PMC_EV(PPC7450, CACHE_INHIBITED_STORES)			\
	__PMC_EV(PPC7450, L1_DATA_LOAD_HIT)				\
	__PMC_EV(PPC7450, L1_DATA_TOUCH_HIT)				\
	__PMC_EV(PPC7450, L1_DATA_STORE_HIT)				\
	__PMC_EV(PPC7450, L1_DATA_TOTAL_HITS)				\
	__PMC_EV(PPC7450, DST_INSTR_DISPATCHED)				\
	__PMC_EV(PPC7450, REFRESHED_DSTS)				\
	__PMC_EV(PPC7450, SUCCESSFUL_DST_TABLE_SEARCHES)		\
	__PMC_EV(PPC7450, DSS_INSTR_COMPLETED)				\
	__PMC_EV(PPC7450, DST_STREAM_0_CACHE_LINE_FETCHES)		\
	__PMC_EV(PPC7450, VTQ_SUSPENDS_DUE_TO_CTX_CHANGE)		\
	__PMC_EV(PPC7450, VTQ_LINE_FETCH_HIT)				\
	__PMC_EV(PPC7450, VEC_LOAD_INSTR_COMPLETED)			\
	__PMC_EV(PPC7450, FP_STORE_INSTR_COMPLETED_IN_LSU)		\
	__PMC_EV(PPC7450, FPU_RENORMALIZATION)				\
	__PMC_EV(PPC7450, FPU_DENORMALIZATION)				\
	__PMC_EV(PPC7450, FP_STORE_CAUSES_STALL_IN_LSU)			\
	__PMC_EV(PPC7450, LD_ST_TRUE_ALIAS_STALL)			\
	__PMC_EV(PPC7450, LSU_INDEXED_ALIAS_STALL)			\
	__PMC_EV(PPC7450, LSU_ALIAS_VS_FSQ_WB0_WB1)			\
	__PMC_EV(PPC7450, LSU_ALIAS_VS_CSQ)				\
	__PMC_EV(PPC7450, LSU_LOAD_HIT_LINE_ALIAS_VS_CSQ0)		\
	__PMC_EV(PPC7450, LSU_LOAD_MISS_LINE_ALIAS_VS_CSQ0)		\
	__PMC_EV(PPC7450, LSU_TOUCH_LINE_ALIAS_VS_FSQ_WB0_WB1)		\
	__PMC_EV(PPC7450, LSU_TOUCH_ALIAS_VS_CSQ)			\
	__PMC_EV(PPC7450, LSU_LMQ_FULL_STALL)				\
	__PMC_EV(PPC7450, FP_LOAD_INSTR_COMPLETED_IN_LSU)		\
	__PMC_EV(PPC7450, FP_LOAD_SINGLE_INSTR_COMPLETED_IN_LSU)	\
	__PMC_EV(PPC7450, FP_LOAD_DOUBLE_COMPLETED_IN_LSU)		\
	__PMC_EV(PPC7450, LSU_RA_LATCH_STALL)				\
	__PMC_EV(PPC7450, LSU_LOAD_VS_STORE_QUEUE_ALIAS_STALL)		\
	__PMC_EV(PPC7450, LSU_LMQ_INDEX_ALIAS)				\
	__PMC_EV(PPC7450, LSU_STORE_QUEUE_INDEX_ALIAS)			\
	__PMC_EV(PPC7450, LSU_CSQ_FORWARDING)				\
	__PMC_EV(PPC7450, LSU_MISALIGNED_LOAD_FINISH)			\
	__PMC_EV(PPC7450, LSU_MISALIGN_STORE_COMPLETED)			\
	__PMC_EV(PPC7450, LSU_MISALIGN_STALL)				\
	__PMC_EV(PPC7450, FP_ONE_QUARTER_FPSCR_RENAMES_BUSY)		\
	__PMC_EV(PPC7450, FP_ONE_HALF_FPSCR_RENAMES_BUSY)		\
	__PMC_EV(PPC7450, FP_THREE_QUARTERS_FPSCR_RENAMES_BUSY)		\
	__PMC_EV(PPC7450, FP_ALL_FPSCR_RENAMES_BUSY)			\
	__PMC_EV(PPC7450, FP_DENORMALIZED_RESULT)			\
	__PMC_EV(PPC7450, L1_DATA_TOTAL_MISSES)				\
	__PMC_EV(PPC7450, DISPATCHES_TO_FPR_ISSUE_QUEUE)		\
	__PMC_EV(PPC7450, LSU_INSTR_COMPLETED)				\
	__PMC_EV(PPC7450, LOAD_INSTR_COMPLETED)				\
	__PMC_EV(PPC7450, SS_SM_INSTR_COMPLETED)			\
	__PMC_EV(PPC7450, TLBIE_INSTR_COMPLETED)			\
	__PMC_EV(PPC7450, LWARX_INSTR_COMPLETED)			\
	__PMC_EV(PPC7450, MFSPR_INSTR_COMPLETED)			\
	__PMC_EV(PPC7450, REFETCH_SERIALIZATION)			\
	__PMC_EV(PPC7450, COMPLETION_QUEUE_ENTRIES_OVER_THRESHOLD)	\
	__PMC_EV(PPC7450, CYCLES_ONE_INSTR_DISPATCHED)			\
	__PMC_EV(PPC7450, CYCLES_TWO_INSTR_COMPLETED)			\
	__PMC_EV(PPC7450, ITLB_NON_SPECULATIVE_MISSES)			\
	__PMC_EV(PPC7450, CYCLES_WAITING_FROM_L1_INSTR_CACHE_MISS)	\
	__PMC_EV(PPC7450, L1_DATA_LOAD_ACCESS_MISS)			\
	__PMC_EV(PPC7450, L1_DATA_TOUCH_MISS)				\
	__PMC_EV(PPC7450, L1_DATA_STORE_MISS)				\
	__PMC_EV(PPC7450, L1_DATA_TOUCH_MISS_CYCLES)			\
	__PMC_EV(PPC7450, L1_DATA_CYCLES_USED)				\
	__PMC_EV(PPC7450, DST_STREAM_1_CACHE_LINE_FETCHES)		\
	__PMC_EV(PPC7450, VTQ_STREAM_CANCELED_PREMATURELY)		\
	__PMC_EV(PPC7450, VTQ_RESUMES_DUE_TO_CTX_CHANGE)		\
	__PMC_EV(PPC7450, VTQ_LINE_FETCH_MISS)				\
	__PMC_EV(PPC7450, VTQ_LINE_FETCH)				\
	__PMC_EV(PPC7450, TLBIE_SNOOPS)					\
	__PMC_EV(PPC7450, L1_INSTR_CACHE_RELOADS)			\
	__PMC_EV(PPC7450, L1_DATA_CACHE_RELOADS)			\
	__PMC_EV(PPC7450, L1_DATA_CACHE_CASTOUTS_TO_L2)			\
	__PMC_EV(PPC7450, STORE_MERGE_GATHER)				\
	__PMC_EV(PPC7450, CACHEABLE_STORE_MERGE_TO_32_BYTES)		\
	__PMC_EV(PPC7450, DATA_BKPT_MATCHES)				\
	__PMC_EV(PPC7450, FALL_THROUGH_BRANCHES_PROCESSED)		\
	__PMC_EV(PPC7450,						\
	    FIRST_SPECULATIVE_BRANCH_BUFFER_RESOLVED_CORRECTLY)		\
	__PMC_EV(PPC7450, SECOND_SPECULATION_BUFFER_ACTIVE)		\
	__PMC_EV(PPC7450, BPU_STALL_ON_LR_DEPENDENCY)			\
	__PMC_EV(PPC7450, BTIC_MISS)					\
	__PMC_EV(PPC7450, BRANCH_LINK_STACK_CORRECTLY_RESOLVED)		\
	__PMC_EV(PPC7450, FPR_ISSUE_STALLED)				\
	__PMC_EV(PPC7450, SWITCHES_BETWEEN_PRIV_USER)			\
	__PMC_EV(PPC7450, LSU_COMPLETES_FP_STORE_SINGLE)		\
	__PMC_EV(PPC7450, VR_ISSUE_QUEUE_DISPATCHES)			\
	__PMC_EV(PPC7450, VR_STALLS)					\
	__PMC_EV(PPC7450, GPR_RENAME_BUFFER_ENTRIES_OVER_THRESHOLD)	\
	__PMC_EV(PPC7450, FPR_ISSUE_QUEUE_ENTRIES)			\
	__PMC_EV(PPC7450, FPU_INSTR_COMPLETED)				\
	__PMC_EV(PPC7450, STWCX_INSTR_COMPLETED)			\
	__PMC_EV(PPC7450, LS_LM_INSTR_PIECES)				\
	__PMC_EV(PPC7450, ITLB_HW_SEARCH_CYCLES_OVER_THRESHOLD)		\
	__PMC_EV(PPC7450, DTLB_MISSES)					\
	__PMC_EV(PPC7450, CANCELLED_L1_INSTR_CACHE_MISSES)		\
	__PMC_EV(PPC7450, L1_DATA_CACHE_OP_HIT)				\
	__PMC_EV(PPC7450, L1_DATA_LOAD_MISS_CYCLES)			\
	__PMC_EV(PPC7450, L1_DATA_PUSHES)				\
	__PMC_EV(PPC7450, L1_DATA_TOTAL_MISS)				\
	__PMC_EV(PPC7450, VT2_FETCHES)					\
	__PMC_EV(PPC7450, TAKEN_BRANCHES_PROCESSED)			\
	__PMC_EV(PPC7450, BRANCH_FLUSHES)				\
	__PMC_EV(PPC7450,						\
	    SECOND_SPECULATIVE_BRANCH_BUFFER_RESOLVED_CORRECTLY)	\
	__PMC_EV(PPC7450, THIRD_SPECULATION_BUFFER_ACTIVE)		\
	__PMC_EV(PPC7450, BRANCH_UNIT_STALL_ON_CTR_DEPENDENCY)		\
	__PMC_EV(PPC7450, FAST_BTIC_HIT)				\
	__PMC_EV(PPC7450, BRANCH_LINK_STACK_MISPREDICTED)		\
	__PMC_EV(PPC7450, CYCLES_THREE_INSTR_COMPLETED)			\
	__PMC_EV(PPC7450, CYCLES_NO_INSTR_DISPATCHED)			\
	__PMC_EV(PPC7450, GPR_ISSUE_QUEUE_ENTRIES_OVER_THRESHOLD)	\
	__PMC_EV(PPC7450, GPR_ISSUE_QUEUE_STALLED)			\
	__PMC_EV(PPC7450, IU1_INSTR_COMPLETED)				\
	__PMC_EV(PPC7450, DSSALL_INSTR_COMPLETED)			\
	__PMC_EV(PPC7450, TLBSYNC_INSTR_COMPLETED)			\
	__PMC_EV(PPC7450, SYNC_INSTR_COMPLETED)				\
	__PMC_EV(PPC7450, SS_SM_INSTR_PIECES)				\
	__PMC_EV(PPC7450, DTLB_HW_SEARCH_CYCLES)			\
	__PMC_EV(PPC7450, SNOOP_RETRIES)				\
	__PMC_EV(PPC7450, SUCCESSFUL_STWCX)				\
	__PMC_EV(PPC7450, DST_STREAM_3_CACHE_LINE_FETCHES)		\
	__PMC_EV(PPC7450,						\
	    THIRD_SPECULATIVE_BRANCH_BUFFER_RESOLVED_CORRECTLY)		\
	__PMC_EV(PPC7450, MISPREDICTED_BRANCHES)			\
	__PMC_EV(PPC7450, FOLDED_BRANCHES)				\
	__PMC_EV(PPC7450, FP_STORE_DOUBLE_COMPLETES_IN_LSU)		\
	__PMC_EV(PPC7450, L2_CACHE_HITS)				\
	__PMC_EV(PPC7450, L3_CACHE_HITS)				\
	__PMC_EV(PPC7450, L2_INSTR_CACHE_MISSES)			\
	__PMC_EV(PPC7450, L3_INSTR_CACHE_MISSES)			\
	__PMC_EV(PPC7450, L2_DATA_CACHE_MISSES)				\
	__PMC_EV(PPC7450, L3_DATA_CACHE_MISSES)				\
	__PMC_EV(PPC7450, L2_LOAD_HITS)					\
	__PMC_EV(PPC7450, L2_STORE_HITS)				\
	__PMC_EV(PPC7450, L3_LOAD_HITS)					\
	__PMC_EV(PPC7450, L3_STORE_HITS)				\
	__PMC_EV(PPC7450, L2_TOUCH_HITS)				\
	__PMC_EV(PPC7450, L3_TOUCH_HITS)				\
	__PMC_EV(PPC7450, SNOOP_MODIFIED)				\
	__PMC_EV(PPC7450, SNOOP_VALID)					\
	__PMC_EV(PPC7450, INTERVENTION)					\
	__PMC_EV(PPC7450, L2_CACHE_MISSES)				\
	__PMC_EV(PPC7450, L3_CACHE_MISSES)				\
	__PMC_EV(PPC7450, L2_CACHE_CASTOUTS)				\
	__PMC_EV(PPC7450, L3_CACHE_CASTOUTS)				\
	__PMC_EV(PPC7450, L2SQ_FULL_CYCLES)				\
	__PMC_EV(PPC7450, L3SQ_FULL_CYCLES)				\
	__PMC_EV(PPC7450, RAQ_FULL_CYCLES)				\
	__PMC_EV(PPC7450, WAQ_FULL_CYCLES)				\
	__PMC_EV(PPC7450, L1_EXTERNAL_INTERVENTIONS)			\
	__PMC_EV(PPC7450, L2_EXTERNAL_INTERVENTIONS)			\
	__PMC_EV(PPC7450, L3_EXTERNAL_INTERVENTIONS)			\
	__PMC_EV(PPC7450, EXTERNAL_INTERVENTIONS)			\
	__PMC_EV(PPC7450, EXTERNAL_PUSHES)				\
	__PMC_EV(PPC7450, EXTERNAL_SNOOP_RETRY)				\
	__PMC_EV(PPC7450, DTQ_FULL_CYCLES)				\
	__PMC_EV(PPC7450, BUS_RETRY)					\
	__PMC_EV(PPC7450, L2_VALID_REQUEST)				\
	__PMC_EV(PPC7450, BORDQ_FULL)					\
	__PMC_EV(PPC7450, BUS_TAS_FOR_READS)				\
	__PMC_EV(PPC7450, BUS_TAS_FOR_WRITES)				\
	__PMC_EV(PPC7450, BUS_READS_NOT_RETRIED)			\
	__PMC_EV(PPC7450, BUS_WRITES_NOT_RETRIED)			\
	__PMC_EV(PPC7450, BUS_READS_WRITES_NOT_RETRIED)			\
	__PMC_EV(PPC7450, BUS_RETRY_DUE_TO_L1_RETRY)			\
	__PMC_EV(PPC7450, BUS_RETRY_DUE_TO_PREVIOUS_ADJACENT)		\
	__PMC_EV(PPC7450, BUS_RETRY_DUE_TO_COLLISION)			\
	__PMC_EV(PPC7450, BUS_RETRY_DUE_TO_INTERVENTION_ORDERING)	\
	__PMC_EV(PPC7450, SNOOP_REQUESTS)				\
	__PMC_EV(PPC7450, PREFETCH_ENGINE_REQUEST)			\
	__PMC_EV(PPC7450, PREFETCH_ENGINE_COLLISION_VS_LOAD)		\
	__PMC_EV(PPC7450, PREFETCH_ENGINE_COLLISION_VS_STORE)		\
	__PMC_EV(PPC7450, PREFETCH_ENGINE_COLLISION_VS_INSTR_FETCH)	\
	__PMC_EV(PPC7450,						\
	    PREFETCH_ENGINE_COLLISION_VS_LOAD_STORE_INSTR_FETCH)	\
	__PMC_EV(PPC7450, PREFETCH_ENGINE_FULL)
#define __PMC_EV_PPC970() \
	__PMC_EV(PPC970, INSTR_COMPLETED) \
	__PMC_EV(PPC970, MARKED_GROUP_DISPATCH) \
	__PMC_EV(PPC970, MARKED_STORE_COMPLETED) \
	__PMC_EV(PPC970, GCT_EMPTY) \
	__PMC_EV(PPC970, RUN_CYCLES) \
	__PMC_EV(PPC970, OVERFLOW) \
	__PMC_EV(PPC970, CYCLES) \
	__PMC_EV(PPC970, THRESHOLD_TIMEOUT) \
	__PMC_EV(PPC970, GROUP_DISPATCH) \
	__PMC_EV(PPC970, BR_MARKED_INSTR_FINISH) \
	__PMC_EV(PPC970, GCT_EMPTY_BY_SRQ_FULL) \
	__PMC_EV(PPC970, STOP_COMPLETION) \
	__PMC_EV(PPC970, LSU_EMPTY) \
	__PMC_EV(PPC970, MARKED_STORE_WITH_INTR) \
	__PMC_EV(PPC970, CYCLES_IN_SUPER) \
	__PMC_EV(PPC970, VPU_MARKED_INSTR_COMPLETED) \
	__PMC_EV(PPC970, FXU0_IDLE_FXU1_BUSY) \
	__PMC_EV(PPC970, SRQ_EMPTY) \
	__PMC_EV(PPC970, MARKED_GROUP_COMPLETED) \
	__PMC_EV(PPC970, CR_MARKED_INSTR_FINISH) \
	__PMC_EV(PPC970, DISPATCH_SUCCESS) \
	__PMC_EV(PPC970, FXU0_IDLE_FXU1_IDLE) \
	__PMC_EV(PPC970, ONE_PLUS_INSTR_COMPLETED) \
	__PMC_EV(PPC970, GROUP_MARKED_IDU) \
	__PMC_EV(PPC970, MARKED_GROUP_COMPLETE_TIMEOUT) \
	__PMC_EV(PPC970, FXU0_BUSY_FXU1_BUSY) \
	__PMC_EV(PPC970, MARKED_STORE_SENT_TO_STS) \
	__PMC_EV(PPC970, FXU_MARKED_INSTR_FINISHED) \
	__PMC_EV(PPC970, MARKED_GROUP_ISSUED) \
	__PMC_EV(PPC970, FXU0_BUSY_FXU1_IDLE) \
	__PMC_EV(PPC970, GROUP_COMPLETED) \
	__PMC_EV(PPC970, FPU_MARKED_INSTR_COMPLETED) \
	__PMC_EV(PPC970, MARKED_INSTR_FINISH_ANY_UNIT) \
	__PMC_EV(PPC970, EXTERNAL_INTERRUPT) \
	__PMC_EV(PPC970, GROUP_DISPATCH_REJECT) \
	__PMC_EV(PPC970, LSU_MARKED_INSTR_FINISH) \
	__PMC_EV(PPC970, TIMEBASE_EVENT) \
	__PMC_EV(PPC970, LSU_COMPLETION_STALL) \
	__PMC_EV(PPC970, FXU_COMPLETION_STALL) \
	__PMC_EV(PPC970, DCACHE_MISS_COMPLETION_STALL) \
	__PMC_EV(PPC970, FPU_COMPLETION_STALL) \
	__PMC_EV(PPC970, FXU_LONG_INSTR_COMPLETION_STALL) \
	__PMC_EV(PPC970, REJECT_COMPLETION_STALL) \
	__PMC_EV(PPC970, FPU_LONG_INSTR_COMPLETION_STALL) \
	__PMC_EV(PPC970, GCT_EMPTY_BY_ICACHE_MISS) \
	__PMC_EV(PPC970, REJECT_COMPLETION_STALL_ERAT_MISS) \
	__PMC_EV(PPC970, GCT_EMPTY_BY_BRANCH_MISS_PREDICT) \
	__PMC_EV(PPC970, BUS_HIGH) \
	__PMC_EV(PPC970, BUS_LOW) \
	__PMC_EV(PPC970, ADDER)
#define        __PMC_EV_TSC()                                                  \
	__PMC_EV(TSC, TSC)
#define        __PMC_EV_UCP()                          \
	__PMC_EV(UCP, EVENT_0CH_04H_E)					   \
	__PMC_EV(UCP, EVENT_0CH_04H_F)					   \
	__PMC_EV(UCP, EVENT_0CH_04H_M)					   \
	__PMC_EV(UCP, EVENT_0CH_04H_S)					   \
	__PMC_EV(UCP, EVENT_0CH_08H_E)					   \
	__PMC_EV(UCP, EVENT_0CH_08H_F)					   \
	__PMC_EV(UCP, EVENT_0CH_08H_M)					   \
	__PMC_EV(UCP, EVENT_0CH_08H_S)					   \

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
#define VM_PAGE_BITS_ALL 0xffu

#define VM_PAGE_TO_PHYS(entry)	((entry)->phys_addr)



#define UMA_SMALLEST_UNIT       (PAGE_SIZE / 256) 



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
#define num_pages(x) \
	((vm_offset_t)((((vm_offset_t)(x)) + PAGE_MASK) >> PAGE_SHIFT))

#define EVENTHANDLER_DECLARE(name, type)				\
struct eventhandler_entry_ ## name 					\
{									\
	struct eventhandler_entry	ee;				\
	type				eh_func;			\
};									\
struct __hack
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

#define		UIOCCMD(n)	_IO('u', n)	

#define BUF_LOCKFREE(bp) 						\
	lockdestroy(&(bp)->b_lock)
#define BUF_LOCKINIT(bp)						\
	lockinit(&(bp)->b_lock, PRIBIO + 4, buf_wmesg, 0, 0)
#define BUF_LOCKPRINTINFO(bp) 						\
	lockmgr_printinfo(&(bp)->b_lock)
#define BUF_TRACKING_ENTRY(x)	((x) & (BUF_TRACKING_SIZE - 1))
#define BUF_WMESG "bufwait"
#define PRINT_BUF_FLAGS "\20\40remfree\37cluster\36vmio\35ram\34managed" \
	"\33paging\32infreecnt\31nocopy\30b23\27relbuf\26b21\25b20" \
	"\24b19\23b18\22clusterok\21malloc\20nocache\17b14\16inval" \
	"\15reuse\14noreuse\13eintr\12done\11b8\10delwri" \
	"\7validsuspwrt\6cache\5deferred\4direct\3async\2needcommit\1age"
#define bread(vp, blkno, size, cred, bpp) \
	    breadn_flags(vp, blkno, size, NULL, NULL, 0, cred, 0, NULL, bpp)
#define bread_gb(vp, blkno, size, cred, gbflags, bpp) \
	    breadn_flags(vp, blkno, size, NULL, NULL, 0, cred, \
		gbflags, NULL, bpp)
#define breadn(vp, blkno, size, rablkno, rabsize, cnt, cred, bpp) \
	    breadn_flags(vp, blkno, size, rablkno, rabsize, cnt, cred, \
		0, NULL, bpp)
#define BO_BDFLUSH(bo, bp)	((bo)->bo_ops->bop_bdflush((bo), (bp)))
#define BO_STRATEGY(bo, bp)	((bo)->bo_ops->bop_strategy((bo), (bp)))
#define BO_SYNC(bo, w)		((bo)->bo_ops->bop_sync((bo), (w)))
#define BO_WRITE(bo, bp)	((bo)->bo_ops->bop_write((bp)))

#define physread physio
#define physwrite physio

#define DOINGASYNC(vp)	   					\
	(((vp)->v_mount->mnt_kern_flag & MNTK_ASYNC) != 0 &&	\
	 ((curthread->td_pflags & TDP_SYNCIO) == 0))
#define VCALL(c) ((c)->a_desc->vdesc_call(c))
#define VDESC_NO_OFFSET -1
#define VN_KNOTE(vp, b, a)					\
	do {							\
		if (!VN_KNLIST_EMPTY(vp))			\
			KNOTE(&vp->v_pollinfo->vpi_selinfo.si_note, (b), \
			    (a) | KNF_NOKQLOCK);		\
	} while (0)
#define VOP_LOCK(vp, flags) VOP_LOCK1(vp, flags, "__FILE__", "__LINE__")
#define VOP_WRITE_POST(ap, ret)						\
	noffset = (ap)->a_uio->uio_offset;				\
	if (noffset > ooffset && !VN_KNLIST_EMPTY((ap)->a_vp)) {	\
		VFS_KNOTE_LOCKED((ap)->a_vp, NOTE_WRITE			\
		    | (noffset > osize ? NOTE_EXTEND : 0));		\
	}
#define vn_lock(vp, flags) _vn_lock(vp, flags, "__FILE__", "__LINE__")
#define MNT_CMDFLAGS   (MNT_UPDATE	| MNT_DELEXPORT	| MNT_RELOAD	| \
			MNT_FORCE	| MNT_SNAPSHOT	| MNT_NONBUSY	| \
			MNT_BYFSID)
#define MNT_VNODE_FOREACH_ACTIVE(vp, mp, mvp) 				\
	for (vp = __mnt_vnode_first_active(&(mvp), (mp)); 		\
		(vp) != NULL; vp = __mnt_vnode_next_active(&(mvp), (mp)))
#define MNT_VNODE_FOREACH_ACTIVE_ABORT(mp, mvp)				\
	__mnt_vnode_markerfree_active(&(mvp), (mp))
#define MNT_VNODE_FOREACH_ALL(vp, mp, mvp)				\
	for (vp = __mnt_vnode_first_all(&(mvp), (mp));			\
		(vp) != NULL; vp = __mnt_vnode_next_all(&(mvp), (mp)))
#define MNT_VNODE_FOREACH_ALL_ABORT(mp, mvp)				\
	do {								\
		MNT_ILOCK(mp);						\
		__mnt_vnode_markerfree_all(&(mvp), (mp));		\
			\
		mtx_assert(MNT_MTX(mp), MA_NOTOWNED);			\
	} while (0)
#define VCTLTOREQ(vc, req)						\
	do {								\
		(req)->newptr = (vc)->vc_ptr;				\
		(req)->newlen = (vc)->vc_len;				\
		(req)->newidx = 0;					\
	} while (0)
#define VFS_KNOTE_LOCKED(vp, hint) do					\
{									\
	if (((vp)->v_vflag & VV_NOKNOTE) == 0)				\
		VN_KNOTE((vp), (hint), KNF_LISTLOCKED);			\
} while (0)
#define VFS_KNOTE_UNLOCKED(vp, hint) do					\
{									\
	if (((vp)->v_vflag & VV_NOKNOTE) == 0)				\
		VN_KNOTE((vp), (hint), 0);				\
} while (0)
#define VFS_SET(vfsops, fsname, flags) \
	static struct vfsconf fsname ## _vfsconf = {		\
		.vfc_version = VFS_VERSION,			\
		.vfc_name = #fsname,				\
		.vfc_vfsops = &vfsops,				\
		.vfc_typenum = -1,				\
		.vfc_flags = flags,				\
	};							\
	static moduledata_t fsname ## _mod = {			\
		#fsname,					\
		vfs_modevent,					\
		& fsname ## _vfsconf				\
	};							\
	DECLARE_MODULE(fsname, fsname ## _mod, SI_SUB_VFS, SI_ORDER_MIDDLE)



#define FAIL_POINT_CV_DESC "fp cv no iterators"
#define FAIL_POINT_IS_OFF(fp) (__predict_true((fp)->fp_setting == NULL) || \
        __predict_true(fail_point_is_off(fp)))
#define FAIL_POINT_NONSLEEPABLE 0x04
#define FAIL_POINT_USE_TIMEOUT_PATH 0x02
#define KFAIL_POINT_CODE(parent, name, code...) \
	do { \
		_FAIL_POINT_INIT(parent, name, 0) \
		_FAIL_POINT_EVAL(name, true, code) \
	} while (0)
#define KFAIL_POINT_CODE_COND(parent, name, cond, flags, code...) \
	do { \
		_FAIL_POINT_INIT(parent, name, flags) \
		_FAIL_POINT_EVAL(name, cond, code) \
	} while (0)
#define KFAIL_POINT_CODE_FLAGS(parent, name, flags, code...) \
	do { \
		_FAIL_POINT_INIT(parent, name, flags) \
		_FAIL_POINT_EVAL(name, true, code) \
	} while (0)
#define KFAIL_POINT_CODE_SLEEP_CALLBACKS(parent, name, pre_func, pre_arg, \
        post_func, post_arg, code...) \
	do { \
		_FAIL_POINT_INIT(parent, name) \
		_FAIL_POINT_NAME(name).fp_pre_sleep_fn = pre_func; \
		_FAIL_POINT_NAME(name).fp_pre_sleep_arg = pre_arg; \
		_FAIL_POINT_NAME(name).fp_post_sleep_fn = post_func; \
		_FAIL_POINT_NAME(name).fp_post_sleep_arg = post_arg; \
		_FAIL_POINT_EVAL(name, true, code) \
	} while (0)
#define KFAIL_POINT_ERROR(parent, name, error_var) \
	KFAIL_POINT_CODE(parent, name, (error_var) = RETURN_VALUE)
#define KFAIL_POINT_GOTO(parent, name, error_var, label) \
	KFAIL_POINT_CODE(parent, name, (error_var) = RETURN_VALUE; goto label)
#define KFAIL_POINT_RETURN(parent, name) \
	KFAIL_POINT_CODE(parent, name, return RETURN_VALUE)
#define KFAIL_POINT_RETURN_VOID(parent, name) \
	KFAIL_POINT_CODE(parent, name, return)
#define KFAIL_POINT_SLEEP_CALLBACKS(parent, name, pre_func, pre_arg, \
        post_func, post_arg) \
	KFAIL_POINT_CODE_SLEEP_CALLBACKS(parent, name, pre_func, \
	    pre_arg, post_func, post_arg, return RETURN_VALUE)
#define _FAIL_POINT_EVAL(name, cond, code...) \
	int RETURN_VALUE; \
 \
	if (__predict_false(cond && \
	        fail_point_eval(&_FAIL_POINT_NAME(name), &RETURN_VALUE))) { \
 \
		code; \
 \
	}
#define _FAIL_POINT_INIT(parent, name, flags) \
	static struct fail_point _FAIL_POINT_NAME(name) = { \
	        .fp_name = #name, \
	        .fp_location = _FAIL_POINT_LOCATION(), \
	        .fp_ref_cnt = 0, \
	        .fp_setting = NULL, \
	        .fp_flags = (flags), \
	        .fp_pre_sleep_fn = NULL, \
	        .fp_pre_sleep_arg = NULL, \
	        .fp_post_sleep_fn = NULL, \
	        .fp_post_sleep_arg = NULL, \
	}; \
	SYSCTL_OID(parent, OID_AUTO, name, \
	        CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_MPSAFE, \
	        &_FAIL_POINT_NAME(name), 0, fail_point_sysctl, \
	        "A", ""); \
	SYSCTL_OID(parent, OID_AUTO, status_##name, \
	        CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_MPSAFE, \
	        &_FAIL_POINT_NAME(name), 0, \
	        fail_point_sysctl_status, "A", "");
#define _FAIL_POINT_LOCATION() "(" "__FILE__" ":" __XSTRING("__LINE__") ")"
#define _FAIL_POINT_NAME(name) _fail_point_##name


