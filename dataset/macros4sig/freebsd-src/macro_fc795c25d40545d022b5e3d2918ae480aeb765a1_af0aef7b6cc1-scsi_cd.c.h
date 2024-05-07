







#include<sys/resource.h>

#include<sys/cdefs.h>




#include<sys/sysctl.h>

#include<sys/queue.h>




#include<sys/select.h>


#include<sys/socket.h>









#include<stdarg.h>


#include<sys/param.h>


#include<sys/types.h>













#include<sys/signal.h>








#include<sys/time.h>









#define _SCSI_SCSI_CD_H 1
#define SMS_FLEXIBLE_GEOMETRY_PAGE 0x05
#define SMS_FLEXIBLE_GEOMETRY_PLEN 0x1E
#define SMS_RIGID_GEOMETRY_PAGE 0x04
#define SMS_RIGID_GEOMETRY_PLEN 0x16		
#define SRDD10_BLOCK_FORMAT            0x00
#define SRDD10_BYTES_FROM_INDEX_FORMAT 0x04
#define SRDD10_DLIST_FORMAT_MASK 0x07
#define SRDD10_EXT_BFI_FORMAT 	       0x01
#define SRDD10_EXT_PHYS_FORMAT 	       0x02
#define SRDD10_GLIST 0x08
#define SRDD10_LONG_BLOCK_FORMAT       0x03
#define SRDD10_PHYSICAL_SECTOR_FORMAT  0x05
#define SRDD10_PLIST 0x10
#define SRDD12_BLOCK_FORMAT            SRDD10_BLOCK_FORMAT
#define SRDD12_BYTES_FROM_INDEX_FORMAT SRDD10_BYTES_FROM_INDEX_FORMAT
#define SRDD12_DLIST_FORMAT_MASK 0x07
#define SRDD12_GLIST 0x08
#define SRDD12_PHYSICAL_SECTOR_FORMAT  SRDD10_PHYSICAL_SECTOR_FORMAT
#define SRDD12_PLIST 0x10
#define SRDDH10_BLOCK_FORMAT            0x00
#define SRDDH10_BYTES_FROM_INDEX_FORMAT 0x04
#define SRDDH10_DLIST_FORMAT_MASK 0x07
#define SRDDH10_GLIST 0x08
#define SRDDH10_PHYSICAL_SECTOR_FORMAT  0x05
#define SRDDH10_PLIST 0x10
#define SRDDH12_BLOCK_FORMAT            0x00
#define SRDDH12_BYTES_FROM_INDEX_FORMAT 0x04
#define SRDDH12_DLIST_FORMAT_MASK 0x07
#define SRDDH12_GLIST 0x08
#define SRDDH12_PHYSICAL_SECTOR_FORMAT  0x05
#define SRDDH12_PLIST 0x10
#define SRZU_LUN_MASK 0xE0
#define SRZ_SAME_TYPES_DIFFERENT 0x03 
#define SSZPL_INVERT 0x80
#define SSZPL_MAX_PATTERN_LENGTH 65535
#define SSZ_IMMED                            0x80
#define SSZ_SERVICE_ACTION_BLOCK_ERASE       0x02
#define SSZ_SERVICE_ACTION_CRYPTO_ERASE      0x03
#define SSZ_SERVICE_ACTION_EXIT_MODE_FAILURE 0x1F
#define SSZ_SERVICE_ACTION_OVERWRITE         0x01
#define SSZ_UNRESTRICTED_EXIT                0x20
#define _SCSI_SCSI_DA_H 1
#define __min_size(x)	static (x)
#define MSG_IDENTIFY(lun, disc)	(((disc) ? 0xc0 : MSG_IDENTIFYFLAG) | (lun))
#define MSG_ISIDENTIFY(m)	((m) & MSG_IDENTIFYFLAG)
#define CAM_SIM_LOCK(sim)	mtx_lock((sim)->mtx)
#define CAM_SIM_UNLOCK(sim)	mtx_unlock((sim)->mtx)
#define _CAM_CAM_SIM_H 1
#define spriv_field0 sim_priv.entries[0].field
#define spriv_field1 sim_priv.entries[1].field
#define spriv_ptr0 sim_priv.entries[0].ptr
#define spriv_ptr1 sim_priv.entries[1].ptr
#define CAMQ_GET_HEAD(camq) ((camq)->queue_array[CAMQ_HEAD])
#define CAMQ_GET_PRIO(camq) (((camq)->entries > 0) ?			\
			    ((camq)->queue_array[CAMQ_HEAD]->priority) : 0)
#define CAMQ_HEAD 1	
#define _CAM_CAM_QUEUE_H 1
#define CAM_EXTLUN_BYTE_SWIZZLE(lun) (	\
	((((u_int64_t)lun) & 0xffff000000000000L) >> 48) | \
	((((u_int64_t)lun) & 0x0000ffff00000000L) >> 16) | \
	((((u_int64_t)lun) & 0x00000000ffff0000L) << 16) | \
	((((u_int64_t)lun) & 0x000000000000ffffL) << 48))
#define CAM_MAX_CDBLEN 16
#define GENERATIONCMP(x, op, y) ((int32_t)((x) - (y)) op 0)
#define _CAM_CAM_H 1
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
#define BLKDEV_IOSIZE  PAGE_SIZE	


#define __FreeBSD_version 1300034	
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





#define offsetof(type, field) __offsetof(type, field)





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



#define BITSET_DEFINE_VAR(t)	BITSET_DEFINE(t, 1)
#define _CAM_CAM_XPT_PERIPH_H 1
#define _CAM_CAM_XPT_H 1
#define xpt_path_assert(path, what)	mtx_assert(xpt_path_mtx(path), (what))
#define xpt_path_lock(path)	mtx_lock(xpt_path_mtx(path))
#define xpt_path_owned(path)	mtx_owned(xpt_path_mtx(path))
#define xpt_path_sleep(path, chan, priority, wmesg, timo)		\
    msleep((chan), xpt_path_mtx(path), (priority), (wmesg), (timo))
#define xpt_path_unlock(path)	mtx_unlock(xpt_path_mtx(path))
#define ATA_FLAG_AUX 0x1
#define CCB_CLEAR_ALL_EXCEPT_HDR(ccbp)			\
	bzero((char *)(ccbp) + sizeof((ccbp)->ccb_h),	\
	    sizeof(*(ccbp)) - sizeof((ccbp)->ccb_h))
#define CCB_PERIPH_PRIV_SIZE 	2	
#define CCB_SIM_PRIV_SIZE 	2	
#define PROTO_VERSION_UNKNOWN (UINT_MAX - 1)
#define PROTO_VERSION_UNSPECIFIED UINT_MAX
#define XPORT_DEVSTAT_TYPE(t)	(XPORT_IS_ATA(t) ? DEVSTAT_TYPE_IF_IDE : \
				 XPORT_IS_SCSI(t) ? DEVSTAT_TYPE_IF_SCSI : \
				 DEVSTAT_TYPE_IF_OTHER)
#define XPORT_IS_ATA(t)		((t) == XPORT_ATA || (t) == XPORT_SATA)
#define XPORT_IS_NVME(t)	((t) == XPORT_NVME)
#define XPORT_IS_SCSI(t)	((t) != XPORT_UNKNOWN && \
				 (t) != XPORT_UNSPECIFIED && \
				 !XPORT_IS_ATA(t) && !XPORT_IS_NVME(t))
#define XPORT_VERSION_UNKNOWN (UINT_MAX - 1)
#define XPORT_VERSION_UNSPECIFIED UINT_MAX
#define XPT_FC_GROUP(op) ((op) & XPT_FC_GROUP_MASK)
#define XPT_FC_IS_DEV_QUEUED(ccb) 	\
    (((ccb)->ccb_h.func_code & XPT_FC_DEV_QUEUED) == XPT_FC_DEV_QUEUED)
#define XPT_FC_IS_QUEUED(ccb) 	\
    (((ccb)->ccb_h.func_code & XPT_FC_QUEUED) != 0)
#define _CAM_CAM_CCB_H 1

#define __BUS_ACCESSOR(varp, var, ivarp, ivar, type)			\
									\
static __inline type varp ## _get_ ## var(device_t dev)			\
{									\
	uintptr_t v;							\
	int e;								\
	e = BUS_READ_IVAR(device_get_parent(dev), dev,			\
	    ivarp ## _IVAR_ ## ivar, &v);				\
	KASSERT(e == 0, ("%s failed for %s on bus %s, error = %d",	\
	    __func__, device_get_nameunit(dev),				\
	    device_get_nameunit(device_get_parent(dev)), e));		\
	return ((type) v);						\
}									\
									\
static __inline void varp ## _set_ ## var(device_t dev, type t)		\
{									\
	uintptr_t v = (uintptr_t) t;					\
	int e;								\
	e = BUS_WRITE_IVAR(device_get_parent(dev), dev,			\
	    ivarp ## _IVAR_ ## ivar, v);				\
	KASSERT(e == 0, ("%s failed for %s on bus %s, error = %d",	\
	    __func__, device_get_nameunit(dev),				\
	    device_get_nameunit(device_get_parent(dev)), e));		\
}
#define bus_barrier(r, o, l, f) \
	bus_space_barrier((r)->r_bustag, (r)->r_bushandle, (o), (l), (f))
#define bus_read_1(r, o) \
	bus_space_read_1((r)->r_bustag, (r)->r_bushandle, (o))
#define bus_read_2(r, o) \
	bus_space_read_2((r)->r_bustag, (r)->r_bushandle, (o))
#define bus_read_4(r, o) \
	bus_space_read_4((r)->r_bustag, (r)->r_bushandle, (o))
#define bus_read_8(r, o) \
	bus_space_read_8((r)->r_bustag, (r)->r_bushandle, (o))
#define bus_read_multi_1(r, o, d, c) \
	bus_space_read_multi_1((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_read_multi_2(r, o, d, c) \
	bus_space_read_multi_2((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_read_multi_4(r, o, d, c) \
	bus_space_read_multi_4((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_read_multi_8(r, o, d, c) \
	bus_space_read_multi_8((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_read_multi_stream_1(r, o, d, c) \
	bus_space_read_multi_stream_1((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_read_multi_stream_2(r, o, d, c) \
	bus_space_read_multi_stream_2((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_read_multi_stream_4(r, o, d, c) \
	bus_space_read_multi_stream_4((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_read_multi_stream_8(r, o, d, c) \
	bus_space_read_multi_stream_8((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_read_region_1(r, o, d, c) \
	bus_space_read_region_1((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_read_region_2(r, o, d, c) \
	bus_space_read_region_2((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_read_region_4(r, o, d, c) \
	bus_space_read_region_4((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_read_region_8(r, o, d, c) \
	bus_space_read_region_8((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_read_region_stream_1(r, o, d, c) \
	bus_space_read_region_stream_1((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_read_region_stream_2(r, o, d, c) \
	bus_space_read_region_stream_2((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_read_region_stream_4(r, o, d, c) \
	bus_space_read_region_stream_4((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_read_region_stream_8(r, o, d, c) \
	bus_space_read_region_stream_8((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_read_stream_1(r, o) \
	bus_space_read_stream_1((r)->r_bustag, (r)->r_bushandle, (o))
#define bus_read_stream_2(r, o) \
	bus_space_read_stream_2((r)->r_bustag, (r)->r_bushandle, (o))
#define bus_read_stream_4(r, o) \
	bus_space_read_stream_4((r)->r_bustag, (r)->r_bushandle, (o))
#define bus_read_stream_8(r, o) \
	bus_space_read_stream_8((r)->r_bustag, (r)->r_bushandle, (o))
#define bus_set_multi_1(r, o, v, c) \
	bus_space_set_multi_1((r)->r_bustag, (r)->r_bushandle, (o), (v), (c))
#define bus_set_multi_2(r, o, v, c) \
	bus_space_set_multi_2((r)->r_bustag, (r)->r_bushandle, (o), (v), (c))
#define bus_set_multi_4(r, o, v, c) \
	bus_space_set_multi_4((r)->r_bustag, (r)->r_bushandle, (o), (v), (c))
#define bus_set_multi_8(r, o, v, c) \
	bus_space_set_multi_8((r)->r_bustag, (r)->r_bushandle, (o), (v), (c))
#define bus_set_multi_stream_1(r, o, v, c) \
	bus_space_set_multi_stream_1((r)->r_bustag, (r)->r_bushandle, (o), (v), (c))
#define bus_set_multi_stream_2(r, o, v, c) \
	bus_space_set_multi_stream_2((r)->r_bustag, (r)->r_bushandle, (o), (v), (c))
#define bus_set_multi_stream_4(r, o, v, c) \
	bus_space_set_multi_stream_4((r)->r_bustag, (r)->r_bushandle, (o), (v), (c))
#define bus_set_multi_stream_8(r, o, v, c) \
	bus_space_set_multi_stream_8((r)->r_bustag, (r)->r_bushandle, (o), (v), (c))
#define bus_set_region_1(r, o, v, c) \
	bus_space_set_region_1((r)->r_bustag, (r)->r_bushandle, (o), (v), (c))
#define bus_set_region_2(r, o, v, c) \
	bus_space_set_region_2((r)->r_bustag, (r)->r_bushandle, (o), (v), (c))
#define bus_set_region_4(r, o, v, c) \
	bus_space_set_region_4((r)->r_bustag, (r)->r_bushandle, (o), (v), (c))
#define bus_set_region_8(r, o, v, c) \
	bus_space_set_region_8((r)->r_bustag, (r)->r_bushandle, (o), (v), (c))
#define bus_set_region_stream_1(r, o, v, c) \
	bus_space_set_region_stream_1((r)->r_bustag, (r)->r_bushandle, (o), (v), (c))
#define bus_set_region_stream_2(r, o, v, c) \
	bus_space_set_region_stream_2((r)->r_bustag, (r)->r_bushandle, (o), (v), (c))
#define bus_set_region_stream_4(r, o, v, c) \
	bus_space_set_region_stream_4((r)->r_bustag, (r)->r_bushandle, (o), (v), (c))
#define bus_set_region_stream_8(r, o, v, c) \
	bus_space_set_region_stream_8((r)->r_bustag, (r)->r_bushandle, (o), (v), (c))
#define bus_write_1(r, o, v) \
	bus_space_write_1((r)->r_bustag, (r)->r_bushandle, (o), (v))
#define bus_write_2(r, o, v) \
	bus_space_write_2((r)->r_bustag, (r)->r_bushandle, (o), (v))
#define bus_write_4(r, o, v) \
	bus_space_write_4((r)->r_bustag, (r)->r_bushandle, (o), (v))
#define bus_write_8(r, o, v) \
	bus_space_write_8((r)->r_bustag, (r)->r_bushandle, (o), (v))
#define bus_write_multi_1(r, o, d, c) \
	bus_space_write_multi_1((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_write_multi_2(r, o, d, c) \
	bus_space_write_multi_2((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_write_multi_4(r, o, d, c) \
	bus_space_write_multi_4((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_write_multi_8(r, o, d, c) \
	bus_space_write_multi_8((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_write_multi_stream_1(r, o, d, c) \
	bus_space_write_multi_stream_1((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_write_multi_stream_2(r, o, d, c) \
	bus_space_write_multi_stream_2((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_write_multi_stream_4(r, o, d, c) \
	bus_space_write_multi_stream_4((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_write_multi_stream_8(r, o, d, c) \
	bus_space_write_multi_stream_8((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_write_region_1(r, o, d, c) \
	bus_space_write_region_1((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_write_region_2(r, o, d, c) \
	bus_space_write_region_2((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_write_region_4(r, o, d, c) \
	bus_space_write_region_4((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_write_region_8(r, o, d, c) \
	bus_space_write_region_8((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_write_region_stream_1(r, o, d, c) \
	bus_space_write_region_stream_1((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_write_region_stream_2(r, o, d, c) \
	bus_space_write_region_stream_2((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_write_region_stream_4(r, o, d, c) \
	bus_space_write_region_stream_4((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_write_region_stream_8(r, o, d, c) \
	bus_space_write_region_stream_8((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_write_stream_1(r, o, v) \
	bus_space_write_stream_1((r)->r_bustag, (r)->r_bushandle, (o), (v))
#define bus_write_stream_2(r, o, v) \
	bus_space_write_stream_2((r)->r_bustag, (r)->r_bushandle, (o), (v))
#define bus_write_stream_4(r, o, v) \
	bus_space_write_stream_4((r)->r_bustag, (r)->r_bushandle, (o), (v))
#define bus_write_stream_8(r, o, v) \
	bus_space_write_stream_8((r)->r_bustag, (r)->r_bushandle, (o), (v))
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

#define RSIZE_MAX (SIZE_MAX >> 1)


#define callout_async_drain(c, d)					\
    _callout_stop_safe(c, 0, d)
#define DECLARE_CLASS(name) extern struct kobj_class name
#define DEFINE_CLASS(name, methods, size)     		\
DEFINE_CLASS_0(name, name ## _class, methods, size)
#define DEFINE_CLASS_0(name, classvar, methods, size)	\
							\
struct kobj_class classvar = {				\
	#name, methods, size, NULL			\
}
#define DEFINE_CLASS_1(name, classvar, methods, size,	\
		       base1)				\
							\
static kobj_class_t name ## _baseclasses[] =		\
	{ &base1, NULL };				\
struct kobj_class classvar = {				\
	#name, methods, size, name ## _baseclasses	\
}
#define DEFINE_CLASS_2(name, classvar, methods, size,	\
	               base1, base2)			\
							\
static kobj_class_t name ## _baseclasses[] =		\
	{ &base1,					\
	  &base2, NULL };				\
struct kobj_class classvar = {				\
	#name, methods, size, name ## _baseclasses	\
}
#define DEFINE_CLASS_3(name, classvar, methods, size,	\
		       base1, base2, base3)		\
							\
static kobj_class_t name ## _baseclasses[] =		\
	{ &base1,					\
	  &base2,					\
	  &base3, NULL };				\
struct kobj_class classvar = {				\
	#name, methods, size, name ## _baseclasses	\
}
#define KOBJMETHOD(NAME, FUNC) \
	{ &NAME##_desc, (kobjop_t) (1 ? FUNC : (NAME##_t *)NULL) }
#define KOBJOPLOOKUP(OPS,OP) do {				\
	kobjop_desc_t _desc = &OP##_##desc;			\
	kobj_method_t **_cep =					\
	    &OPS->cache[_desc->id & (KOBJ_CACHE_SIZE-1)];	\
	kobj_method_t *_ce = *_cep;				\
	if (_ce->desc != _desc) {				\
		_ce = kobj_lookup_method(OPS->cls,		\
					 _cep, _desc);		\
		kobj_lookup_misses++;				\
	} else							\
		kobj_lookup_hits++;				\
	_m = _ce->func;						\
} while(0)

#define EVENTHANDLER_DECLARE(name, type)				\
struct eventhandler_entry_ ## name 					\
{									\
	struct eventhandler_entry	ee;				\
	type				eh_func;			\
};									\
struct __hack



#define  CCCR_CC_SMB                    (1 << 1) 
#define MMC_DATA_BLOCK_SIZE (1UL << 4)
#define SD_IO_CCCR_FN0_BLKSZ            0x10    
#define SD_IO_FBR_CIS_OFFSET            0x9  
#define SD_IO_FBR_IOBLKSZ               0x10 
#define SD_IO_FBR_START_F(n)            (SD_IO_FBR_START + (n-1) * SD_IO_FBR_F_SIZE)
#define	 SD_R5_DATA(resp)		((resp)[0] & 0xff)

#define CARD_FEATURE_18V    0x1 << 5
#define CARD_FEATURE_MEMORY 0x1
#define CARD_FEATURE_MMC    0x1 << 4
#define CARD_FEATURE_SD20   0x1 << 3
#define CARD_FEATURE_SDHC   0x1 << 1
#define CARD_FEATURE_SDIO   0x1 << 2
#define MMC_PROPOSED_RCA    2
#define CAM_NVME_NVME_ALL_H 1
#define NVME_CSTS_GET_SHST(csts)			(((csts) >> NVME_CSTS_REG_SHST_SHIFT) & NVME_CSTS_REG_SHST_MASK)
#define NVME_MAJOR(r)			(((r) >> 16) & 0xffff)
#define NVME_MINOR(r)			(((r) >> 8) & 0xff)
#define NVME_REV(x, y)			(((x) << 16) | ((y) << 8))
#define NVME_STATUS_GET_DNR(st)				(((st) >> NVME_STATUS_DNR_SHIFT) & NVME_STATUS_DNR_MASK)
#define NVME_STATUS_GET_M(st)				(((st) >> NVME_STATUS_M_SHIFT) & NVME_STATUS_M_MASK)
#define NVME_STATUS_GET_P(st)				(((st) >> NVME_STATUS_P_SHIFT) & NVME_STATUS_P_MASK)
#define NVME_STATUS_GET_SC(st)				(((st) >> NVME_STATUS_SC_SHIFT) & NVME_STATUS_SC_MASK)
#define NVME_STATUS_GET_SCT(st)				(((st) >> NVME_STATUS_SCT_SHIFT) & NVME_STATUS_SCT_MASK)

#define nvme_completion_is_error(cpl)					\
	(NVME_STATUS_GET_SC((cpl)->status) != 0 || NVME_STATUS_GET_SCT((cpl)->status) != 0)

#define CAM_ATA_ALL_H 1
#define AR_DEGRADED                     2
#define AR_JBOD                         0x0001
#define AR_RAID0                        0x0004
#define AR_RAID01                       0x0010
#define AR_RAID1                        0x0008
#define AR_RAID3                        0x0020
#define AR_RAID4                        0x0040
#define AR_RAID5                        0x0080
#define AR_READY                        1
#define AR_REBUILDING                   4
#define AR_SPAN                         0x0002
#define ATAPI_BLANK                     0xa1    
#define ATAPI_CLOSE_TRACK               0x5b    
#define ATAPI_ERASE                     0x19    
#define ATAPI_FORMAT                    0x04    
#define ATAPI_LOAD_UNLOAD               0xa6    
#define ATAPI_LOCATE                    0x2b    
#define ATAPI_MECH_STATUS               0xbd    
#define ATAPI_MODE_SELECT               0x15    
#define ATAPI_MODE_SELECT_BIG           0x55    
#define ATAPI_MODE_SENSE                0x1a    
#define ATAPI_MODE_SENSE_BIG            0x5a    
#define ATAPI_PAUSE                     0x4b    
#define ATAPI_PLAY_10                   0x45    
#define ATAPI_PLAY_12                   0xa5    
#define ATAPI_PLAY_CD                   0xb4    
#define ATAPI_PLAY_MSF                  0x47    
#define ATAPI_PLAY_TRACK                0x48    
#define ATAPI_POLL_DSC                  0xff    
#define ATAPI_PREVENT_ALLOW             0x1e    
#define ATAPI_READ                      0x08    
#define ATAPI_READ_BIG                  0x28    
#define ATAPI_READ_BUFFER               0x3c    
#define ATAPI_READ_BUFFER_CAPACITY      0x5c    
#define ATAPI_READ_CAPACITY             0x25    
#define ATAPI_READ_CD                   0xbe    
#define ATAPI_READ_DISK_INFO            0x51    
#define ATAPI_READ_FORMAT_CAPACITIES    0x23    
#define ATAPI_READ_MASTER_CUE           0x59    
#define ATAPI_READ_POSITION             0x34    
#define ATAPI_READ_STRUCTURE            0xad    
#define ATAPI_READ_SUBCHANNEL           0x42    
#define ATAPI_READ_TOC                  0x43    
#define ATAPI_READ_TRACK_INFO           0x52    
#define ATAPI_REPAIR_TRACK              0x58    
#define ATAPI_REPORT_KEY                0xa4    
#define ATAPI_REQUEST_SENSE             0x03    
#define ATAPI_RESERVE_TRACK             0x53    
#define ATAPI_REZERO                    0x01    
#define ATAPI_SEND_CUE_SHEET            0x5d    
#define ATAPI_SEND_KEY                  0xa3    
#define ATAPI_SEND_OPC_INFO             0x54    
#define ATAPI_SERVICE_ACTION_IN         0x96	
#define ATAPI_SET_SPEED                 0xbb    
#define ATAPI_SPACE                     0x11    
#define         ATAPI_SP_EOD            0x03
#define         ATAPI_SP_FM             0x01
#define         ATAPI_SS_EJECT          0x04
#define         ATAPI_SS_LOAD           0x01
#define         ATAPI_SS_RETENSION      0x02
#define ATAPI_START_STOP                0x1b    
#define ATAPI_SYNCHRONIZE_CACHE         0x35    
#define ATAPI_TEST_UNIT_READY           0x00    
#define ATAPI_WEOF                      0x10    
#define         ATAPI_WF_WRITE          0x01
#define ATAPI_WRITE                     0x0a    
#define ATAPI_WRITE_BIG                 0x2a    
#define ATAPI_WRITE_BUFFER              0x3b    
#define ATA_ACOUSTIC_CURRENT(x)         ((x) & 0x00ff)
#define ATA_ACOUSTIC_VENDOR(x)          (((x) & 0xff00) >> 8)
#define ATA_ATAPI_IDENTIFY              0xa1    
#define ATA_ATAPI_TYPE_CDROM            0x0500  
#define ATA_ATAPI_TYPE_DIRECT           0x0000  
#define ATA_ATAPI_TYPE_MASK             0x1f00
#define ATA_ATAPI_TYPE_OPTICAL          0x0700  
#define ATA_ATAPI_TYPE_TAPE             0x0100  
#define ATA_ATA_IDENTIFY                0xec    
#define ATA_CABLE_ID                    0x2000
#define ATA_CFA_ERASE                   0xc0    
#define ATA_CHECK_POWER_MODE            0xe5    
#define ATA_CMD_ATAPI                   0x08
#define ATA_CMD_CONTROL                 0x01
#define ATA_CMD_READ                    0x02
#define ATA_CMD_WRITE                   0x04
#define ATA_DEVICE_RESET                0x08    
#define ATA_DMA                 0x10
#define ATA_DMA_MASK            0xf0
#define ATA_DMA_MAX             0x4f
#define ATA_DRQ_FAST                    0x0040  
#define ATA_DRQ_INTR                    0x0020  
#define ATA_DRQ_MASK                    0x0060
#define ATA_DRQ_SLOW                    0x0000  
#define ATA_ENABLED_DAPST               0x0080
#define ATA_ENCRYPTS_ALL_USER_DATA      0x0010  
#define ATA_FLAG_54_58                  0x0001  
#define ATA_FLAG_64_70                  0x0002  
#define ATA_FLAG_88                     0x0004  
#define ATA_FLUSHCACHE                  0xe7    
#define ATA_FLUSHCACHE48                0xea    
#define ATA_IDLE_CMD                    0xe3    
#define ATA_IDLE_IMMEDIATE              0xe1    
#define ATA_MODE_MASK           0x0f
#define ATA_MULTI_VALID                 0x0100
#define         ATA_NF_AUTOPOLL         0x01    
#define         ATA_NF_FLUSHQUEUE       0x00    
#define ATA_NOP                         0x00    
#define ATA_PACKET_CMD                  0xa0    
#define ATA_PIO                 0x00
#define ATA_PIO0                0x08
#define ATA_PIO1                0x09
#define ATA_PIO2                0x0a
#define ATA_PIO3                0x0b
#define ATA_PIO4                0x0c
#define ATA_PIO_MAX             0x0f
#define ATA_PROTO_ATAPI                 0x8000
#define ATA_PROTO_ATAPI_12              0x8000
#define ATA_PROTO_ATAPI_16              0x8001
#define ATA_PROTO_CFA                   0x848a
#define ATA_PROTO_MASK                  0x8003
#define ATA_QUEUE_LEN(x)                ((x) & 0x001f)
#define ATA_READ                        0x20    
#define ATA_READ48                      0x24    
#define ATA_READ_BUFFER                 0xe4    
#define ATA_READ_DMA                    0xc8    
#define ATA_READ_DMA48                  0x25    
#define ATA_READ_DMA_QUEUED             0xc7    
#define ATA_READ_DMA_QUEUED48           0x26    
#define ATA_READ_FPDMA_QUEUED           0x60    
#define ATA_READ_LOG_DMA_EXT            0x47    
#define ATA_READ_LOG_EXT                0x2f    
#define ATA_READ_MUL                    0xc4    
#define ATA_READ_MUL48                  0x29    
#define ATA_READ_NATIVE_MAX_ADDRESS     0xf8    
#define ATA_READ_NATIVE_MAX_ADDRESS48   0x27    
#define ATA_READ_PM                     0xe4    
#define ATA_READ_STREAM48               0x2b    
#define ATA_READ_STREAM_DMA48           0x2a    
#define ATA_READ_VERIFY                 0x40
#define ATA_READ_VERIFY48               0x42
#define ATA_RECV_FPDMA_QUEUED           0x65    
#define ATA_RESP_INCOMPLETE             0x0004
#define ATA_RETIRED_DMA_MASK            0x0003
#define ATA_RETIRED_PIO_MASK            0x0300
#define ATA_SA150               0x47
#define ATA_SA300               0x48
#define ATA_SA600               0x49
#define ATA_SATA_CURR_GEN_MASK          0x0006
#define ATA_SATA_GEN1                   0x0002
#define ATA_SATA_GEN2                   0x0004
#define ATA_SATA_GEN3                   0x0008
#define ATA_SECURITY_DISABLE_PASSWORD   0xf6    
#define ATA_SECURITY_ERASE_PREPARE      0xf3    
#define ATA_SECURITY_ERASE_UNIT         0xf4    
#define ATA_SECURITY_FREEZE_LOCK        0xf5    
#define ATA_SECURITY_SET_PASSWORD       0xf1    
#define ATA_SECURITY_UNLOCK             0xf2    
#define ATA_SEEK                        0x70    
#define ATA_SEND_FPDMA_QUEUED           0x64    
#define ATA_SENSE_RECOVERED_ERROR 	0x01    
#define ATA_SEP_ATTN                    0x67    
#define ATA_SERVICE                     0xa2    
#define ATA_SETFEATURES                 0xef    
#define ATA_SET_MAX_ADDRESS             0xf9    
#define ATA_SET_MAX_ADDRESS48           0x37    
#define ATA_SET_MULTI                   0xc6    
#define         ATA_SF_DIS_PUIS         0x86    
#define         ATA_SF_DIS_RCACHE       0x55    
#define         ATA_SF_DIS_RELIRQ       0xdd    
#define         ATA_SF_DIS_SRVIRQ       0xde    
#define         ATA_SF_DIS_WCACHE       0x82    
#define         ATA_SF_ENAB_PUIS        0x06    
#define         ATA_SF_ENAB_RCACHE      0xaa    
#define         ATA_SF_ENAB_RELIRQ      0x5d    
#define         ATA_SF_ENAB_SRVIRQ      0x5e    
#define         ATA_SF_ENAB_WCACHE      0x02    
#define         ATA_SF_PUIS_SPINUP      0x07    
#define         ATA_SF_SETXFER          0x03    
#define ATA_SLEEP                       0xe6    
#define ATA_SMART_CMD                   0xb0    
#define ATA_STANDBY_CMD                 0xe2    
#define ATA_STANDBY_IMMEDIATE           0xe0    
#define ATA_SUPPORT_ADDRESS48           0x0400
#define ATA_SUPPORT_APM                 0x0008
#define ATA_SUPPORT_ASYNCNOTIF          0x0020
#define ATA_SUPPORT_AUTOACOUSTIC        0x0200
#define ATA_SUPPORT_AUTOACTIVATE        0x0004
#define ATA_SUPPORT_BLOCK_ERASE_EXT     0x8000
#define ATA_SUPPORT_CFA                 0x0004
#define ATA_SUPPORT_CRYPTO_SCRAMBLE_EXT 0x2000
#define ATA_SUPPORT_DAPST               0x4000
#define ATA_SUPPORT_DMA                 0x0100
#define ATA_SUPPORT_DRAT                0x4000
#define ATA_SUPPORT_FLUSHCACHE          0x1000
#define ATA_SUPPORT_FLUSHCACHE48        0x2000
#define ATA_SUPPORT_HAPST               0x2000
#define ATA_SUPPORT_IFPWRMNGT           0x0008
#define ATA_SUPPORT_IFPWRMNGTRCV        0x0200
#define ATA_SUPPORT_INORDERDATA         0x0010
#define ATA_SUPPORT_IORDY               0x0800
#define ATA_SUPPORT_IORDYDIS            0x0400
#define ATA_SUPPORT_LBA                 0x0200
#define ATA_SUPPORT_LOOKAHEAD           0x0040
#define ATA_SUPPORT_MAXSECURITY         0x0100
#define ATA_SUPPORT_MICROCODE           0x0001
#define ATA_SUPPORT_NCQ                 0x0100
#define ATA_SUPPORT_NCQ_PRIO            0x1000
#define ATA_SUPPORT_NCQ_QMANAGEMENT     0x0020
#define ATA_SUPPORT_NCQ_STREAM          0x0010
#define ATA_SUPPORT_NCQ_UNLOAD          0x0800
#define ATA_SUPPORT_NONZERO             0x0002
#define ATA_SUPPORT_NOP                 0x4000
#define ATA_SUPPORT_NOTIFY              0x0010
#define ATA_SUPPORT_OVERLAP             0x4000
#define ATA_SUPPORT_OVERLAY             0x0800
#define ATA_SUPPORT_OVERWRITE_EXT       0x4000
#define ATA_SUPPORT_PACKET              0x0010
#define ATA_SUPPORT_PHYEVENTCNT         0x0400
#define ATA_SUPPORT_POWERMGT            0x0008
#define ATA_SUPPORT_PROTECTED           0x0400
#define ATA_SUPPORT_QUEUED              0x0002
#define ATA_SUPPORT_RCVSND_FPDMA_QUEUED 0x0040
#define ATA_SUPPORT_READBUFFER          0x2000
#define ATA_SUPPORT_READLOGDMAEXT       0x8000
#define ATA_SUPPORT_RELEASEIRQ          0x0080
#define ATA_SUPPORT_REMOVABLE           0x0004
#define ATA_SUPPORT_RESET               0x0200
#define ATA_SUPPORT_RZAT                0x0020
#define ATA_SUPPORT_SANITIZE            0x1000
#define ATA_SUPPORT_SECURITY            0x0002
#define ATA_SUPPORT_SERVICEIRQ          0x0100
#define ATA_SUPPORT_SMART               0x0001
#define ATA_SUPPORT_SOFTSETPRESERVE     0x0040
#define ATA_SUPPORT_SPINUP              0x0040
#define ATA_SUPPORT_STANDBY             0x0020
#define ATA_SUPPORT_TCG                 0x0001
#define ATA_SUPPORT_WRITEBUFFER         0x1000
#define ATA_SUPPORT_WRITECACHE          0x0020
#define ATA_UDMA0               0x40
#define ATA_UDMA1               0x41
#define ATA_UDMA2               0x42
#define ATA_UDMA3               0x43
#define ATA_UDMA4               0x44
#define ATA_UDMA5               0x45
#define ATA_UDMA6               0x46
#define ATA_WDMA0               0x20
#define ATA_WDMA1               0x21
#define ATA_WDMA2               0x22
#define ATA_WRITE                       0x30    
#define ATA_WRITE48                     0x34    
#define ATA_WRITE_DMA                   0xca    
#define ATA_WRITE_DMA48                 0x35    
#define ATA_WRITE_DMA_FUA48             0x3d
#define ATA_WRITE_DMA_QUEUED            0xcc    
#define ATA_WRITE_DMA_QUEUED48          0x36    
#define ATA_WRITE_DMA_QUEUED_FUA48      0x3e
#define ATA_WRITE_FPDMA_QUEUED          0x61    
#define ATA_WRITE_LOG_EXT               0x3f
#define ATA_WRITE_MUL                   0xc5    
#define ATA_WRITE_MUL48                 0x39    
#define ATA_WRITE_MUL_FUA48             0xce
#define ATA_WRITE_PM                    0xe8    
#define ATA_WRITE_STREAM48              0x3b
#define ATA_WRITE_STREAM_DMA48          0x3a
#define ATA_WRITE_UNCORRECTABLE48       0x45    
#define         ATA_WU_FLAGGED          0xaa    
#define         ATA_WU_PSEUDO           0x55    
#define IOCATAATTACH            _IOW('a',  3, int)
#define IOCATADETACH            _IOW('a',  4, int)
#define IOCATADEVICES           _IOWR('a',  5, struct ata_ioc_devices)
#define IOCATAGMAXCHANNEL       _IOR('a',  1, int)
#define IOCATAGMODE             _IOR('a', 102, int)
#define IOCATAGPARM             _IOR('a', 101, struct ata_params)
#define IOCATARAIDADDSPARE      _IOW('a', 203, struct ata_ioc_raid_config)
#define IOCATARAIDCREATE        _IOWR('a', 200, struct ata_ioc_raid_config)
#define IOCATARAIDDELETE        _IOW('a', 201, int)
#define IOCATARAIDREBUILD       _IOW('a', 204, int)
#define IOCATARAIDSTATUS        _IOWR('a', 202, struct ata_ioc_raid_status)
#define IOCATAREINIT            _IOW('a',  2, int)
#define IOCATAREQUEST           _IOWR('a', 100, struct ata_ioc_request)
#define IOCATASMODE             _IOW('a', 103, int)

#define SA_RPRT_TRGT_GRP     0x0a
#define SBDC_IS_PRESENT(bdc, length, field)				   \
	((length >= offsetof(struct scsi_vpd_block_device_characteristics, \
	  field) + sizeof(bdc->field)) ? 1 : 0)
#define SERVICE_ACTION_MASK  0x1f
#define TPG_IMPLICIT     0x02
#define TPG_SET_BY_STPG  0x01
#define TPG_UNAVLBL      0
#define _CAM_CAM_DEBUG_H 1
#define CAM_PERIPH_FOREACH(periph, driver)				\
	for ((periph) = cam_periph_acquire_first(driver);		\
	    (periph) != NULL;						\
	    (periph) = cam_periph_acquire_next(periph))
#define CAM_PERIPH_PRINT(p, msg, args...)				\
    printf("%s%d:" msg, (periph)->periph_name, (periph)->unit_number, ##args)
#define PERIPHDRIVER_DECLARE(name, driver) \
	static int name ## _modevent(module_t mod, int type, void *data) \
	{ \
		switch (type) { \
		case MOD_LOAD: \
			periphdriver_register(data); \
			break; \
		case MOD_UNLOAD: \
			return (periphdriver_unregister(data)); \
		default: \
			return EOPNOTSUPP; \
		} \
		return 0; \
	} \
	static moduledata_t name ## _mod = { \
		#name, \
		name ## _modevent, \
		(void *)&driver \
	}; \
	DECLARE_MODULE(name, name ## _mod, SI_SUB_DRIVERS, SI_ORDER_ANY); \
	MODULE_DEPEND(name, cam, 1, 1, 1)
#define _CAM_CAM_PERIPH_H 1
#define cam_periph_assert(periph, what)					\
	mtx_assert(xpt_path_mtx((periph)->path), (what))
#define cam_periph_lock(periph)						\
	mtx_lock(xpt_path_mtx((periph)->path))
#define cam_periph_owned(periph)					\
	mtx_owned(xpt_path_mtx((periph)->path))
#define cam_periph_sleep(periph, chan, priority, wmesg, timo)		\
	xpt_path_sleep((periph)->path, (chan), (priority), (wmesg), (timo))
#define cam_periph_unlock(periph)					\
	mtx_unlock(xpt_path_mtx((periph)->path))
#define ppriv_field0 periph_priv.entries[0].field
#define ppriv_field1 periph_priv.entries[1].field
#define ppriv_ptr0 periph_priv.entries[0].ptr
#define ppriv_ptr1 periph_priv.entries[1].ptr

#define TASKQUEUE_DECLARE(name)			\
extern struct taskqueue *taskqueue_##name
#define TASKQUEUE_DEFINE(name, enqueue, context, init)			\
									\
struct taskqueue *taskqueue_##name;					\
									\
static void								\
taskqueue_define_##name(void *arg)					\
{									\
	taskqueue_##name =						\
	    taskqueue_create(#name, M_WAITOK, (enqueue), (context));	\
	init;								\
}									\
									\
SYSINIT(taskqueue_##name, SI_SUB_TASKQ, SI_ORDER_SECOND,		\
	taskqueue_define_##name, NULL);					\
									\
struct __hack
#define TASKQUEUE_DEFINE_THREAD(name)					\
TASKQUEUE_DEFINE(name, taskqueue_thread_enqueue, &taskqueue_##name,	\
	taskqueue_start_threads(&taskqueue_##name, 1, PWAIT,		\
	"%s taskq", #name))
#define TASKQUEUE_FAST_DEFINE(name, enqueue, context, init)		\
									\
struct taskqueue *taskqueue_##name;					\
									\
static void								\
taskqueue_define_##name(void *arg)					\
{									\
	taskqueue_##name =						\
	    taskqueue_create_fast(#name, M_WAITOK, (enqueue),		\
	    (context));							\
	init;								\
}									\
									\
SYSINIT(taskqueue_##name, SI_SUB_TASKQ, SI_ORDER_SECOND,		\
	taskqueue_define_##name, NULL);					\
									\
struct __hack
#define TASKQUEUE_FAST_DEFINE_THREAD(name)				\
TASKQUEUE_FAST_DEFINE(name, taskqueue_thread_enqueue,			\
	&taskqueue_##name, taskqueue_start_threads(&taskqueue_##name	\
	1, PWAIT, "%s taskq", #name))
#define TASK_INIT(task, priority, func, context) do {	\
	(task)->ta_pending = 0;				\
	(task)->ta_priority = (priority);		\
	(task)->ta_func = (func);			\
	(task)->ta_context = (context);			\
} while (0)
#define TASK_INITIALIZER(priority, func, context)	\
	{ .ta_pending = 0,				\
	  .ta_priority = (priority),			\
	  .ta_func = (func),				\
	  .ta_context = (context) }



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


#define INIT_SYSENTVEC(name, sv)					\
    SYSINIT(name, SI_SUB_EXEC, SI_ORDER_ANY,				\
	(sysinit_cfunc_t)exec_sysvec_init, sv);
#define SYSCALL_INIT_HELPER(syscallname)			\
    SYSCALL_INIT_HELPER_F(syscallname, 0)
#define SYSCALL_INIT_HELPER_COMPAT(syscallname)			\
    SYSCALL_INIT_HELPER_COMPAT_F(syscallname, 0)
#define SYSCALL_INIT_HELPER_COMPAT_F(syscallname, flags) {	\
    .new_sysent = {						\
	.sy_narg = (sizeof(struct syscallname ## _args )	\
	    / sizeof(register_t)),				\
	.sy_call = (sy_call_t *)& syscallname,			\
	.sy_auevent = SYS_AUE_##syscallname,			\
	.sy_flags = (flags)					\
    },								\
    .syscall_no = SYS_##syscallname				\
}
#define SYSCALL_INIT_HELPER_F(syscallname, flags) {		\
    .new_sysent = {						\
	.sy_narg = (sizeof(struct syscallname ## _args )	\
	    / sizeof(register_t)),				\
	.sy_call = (sy_call_t *)& sys_ ## syscallname,		\
	.sy_auevent = SYS_AUE_##syscallname,			\
	.sy_flags = (flags)					\
    },								\
    .syscall_no = SYS_##syscallname				\
}
#define SYSCALL_INIT_LAST {					\
    .syscall_no = NO_SYSCALL					\
}
#define SYSCALL_MODULE(name, offset, new_sysent, evh, arg)	\
static struct syscall_module_data name##_syscall_mod = {	\
	evh, arg, offset, new_sysent, { 0, NULL, AUE_NULL }	\
};								\
								\
static moduledata_t name##_mod = {				\
	"sys/" #name,						\
	syscall_module_handler,					\
	&name##_syscall_mod					\
};								\
DECLARE_MODULE(name, name##_mod, SI_SUB_SYSCALLS, SI_ORDER_MIDDLE)
#define SYSENT_INIT_VALS(_syscallname) {			\
	.sy_narg = (sizeof(struct _syscallname ## _args )	\
	    / sizeof(register_t)),				\
	.sy_call = (sy_call_t *)&sys_##_syscallname,		\
	.sy_auevent = SYS_AUE_##_syscallname,			\
	.sy_systrace_args_func = NULL,				\
	.sy_entry = 0,						\
	.sy_return = 0,						\
	.sy_flags = 0,						\
	.sy_thrcnt = 0						\
}							
#define		 sbuf_new_auto()				\
	sbuf_new(NULL, NULL, 0, SBUF_AUTOEXTEND)
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
#define DEVSTAT_DEVICE_NAME "devstat"
#define DEVSTAT_NAME_LEN  16


#define CDR_DB_RAW              0x0     
#define CDR_DB_RAW_PQ           0x1     
#define CDR_DB_RAW_PW           0x2     
#define CDR_DB_RAW_PW_R         0x3     
#define CDR_DB_RES_14           0xe     
#define CDR_DB_RES_4            0x4     
#define CDR_DB_RES_5            0x5     
#define CDR_DB_RES_6            0x6     
#define CDR_DB_ROM_MODE1        0x8     
#define CDR_DB_ROM_MODE2        0x9     
#define CDR_DB_VS_15            0xf     
#define CDR_DB_VS_7             0x7     
#define CDR_DB_XA_MODE1         0xa     
#define CDR_DB_XA_MODE2_F1      0xb     
#define CDR_DB_XA_MODE2_F2      0xc     
#define CDR_DB_XA_MODE2_MIX     0xd     
#define CDR_SESS_CDI            0x10
#define CDR_SESS_CDROM          0x00
#define CDR_SESS_CDROM_XA       0x20
#define CDR_SESS_FINAL          0x01
#define CDR_SESS_MULTI          0x03
#define CDR_SESS_NONE           0x00
#define CDR_SESS_RESERVED       0x02
#define CDIOCREADSUBCHANNEL _IOWR('c', 3 , struct ioc_read_subchannel )
#define CDIOREADTOCENTRY _IOWR('c',6,struct ioc_read_toc_single_entry)
#define CDIOREADTOCENTRYS _IOWR('c',5,struct ioc_read_toc_entry)
#define CDIOREADTOCHEADER _IOR('c',4,struct ioc_toc_header)
#define CD_AS_AUDIO_INVALID        0x00
#define CD_AS_NO_STATUS            0x15
#define CD_AS_PLAY_COMPLETED       0x13
#define CD_AS_PLAY_ERROR           0x14
#define CD_AS_PLAY_IN_PROGRESS     0x11
#define CD_AS_PLAY_PAUSED          0x12
#define physread physio
#define physwrite physio
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
