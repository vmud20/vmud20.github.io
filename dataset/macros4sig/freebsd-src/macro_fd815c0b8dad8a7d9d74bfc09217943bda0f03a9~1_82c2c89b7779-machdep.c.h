





#include<sys/uio.h>



#include<sys/select.h>


#include<sys/resource.h>




#include<sys/time.h>









































#include<sys/types.h>





#include<sys/param.h>

#include<sys/ucontext.h>

























#include<sys/signal.h>
#include<sys/queue.h>








#include<sys/cdefs.h>

#define ISA_ACCESSOR(var, ivar, type)					\
	__BUS_ACCESSOR(isa, var, ISA, ivar, type)

#define isa_dmainit(chan, size) do { \
	if (isa_dma_init(chan, size, M_NOWAIT)) \
		printf("WARNING: isa_dma_init(%d, %ju) failed\n", \
		    (int)(chan), (uintmax_t)(size)); \
	} while (0) 
#define PNP_EISAID(s)				\
	((((s[0] - '@') & 0x1f) << 2)		\
	 | (((s[1] - '@') & 0x18) >> 3)		\
	 | (((s[1] - '@') & 0x07) << 13)	\
	 | (((s[2] - '@') & 0x1f) << 8)		\
	 | (PNP_HEXTONUM(s[4]) << 16)		\
	 | (PNP_HEXTONUM(s[3]) << 20)		\
	 | (PNP_HEXTONUM(s[6]) << 24)		\
	 | (PNP_HEXTONUM(s[5]) << 28))
#define PNP_HEXTONUM(c)	((c) >= 'a'		\
			 ? (c) - 'a' + 10	\
			 : ((c) >= 'A'		\
			    ? (c) - 'A' + 10	\
			    : (c) - '0'))

#define  RTCFDT_288M_1   0x50		
#define  RTCFDT_720K     0x30           
#define  RTCSA_1024      0x06	
#define  RTCSA_128       0x09
#define  RTCSA_2048      0x05
#define  RTCSA_256       0x08
#define  RTCSA_32        0x0b	
#define  RTCSA_4096      0x04
#define  RTCSA_512       0x07
#define  RTCSA_64        0x0a
#define  RTCSA_8192      0x03	
#define  RTCSA_DIVIDER   0x20   
#define  RTCSA_PROF      RTCSA_1024
#define  RTCSB_HALT      0x80	
#define  RTC_NOPROFRATE  128
#define  RTC_PROFRATE    1024
#define _I386_ISA_RTC_H_ 1

#define LIST_SWAP(head1, head2, type, field) do {			\
	struct type *swap_tmp = LIST_FIRST((head1));			\
	LIST_FIRST((head1)) = LIST_FIRST((head2));			\
	LIST_FIRST((head2)) = swap_tmp;					\
	if ((swap_tmp = LIST_FIRST((head1))) != NULL)			\
		swap_tmp->field.le_prev = &LIST_FIRST((head1));		\
	if ((swap_tmp = LIST_FIRST((head2))) != NULL)			\
		swap_tmp->field.le_prev = &LIST_FIRST((head2));		\
} while (0)
#define SLIST_REMOVE_AFTER(elm, field) do {				\
	SLIST_NEXT(elm, field) =					\
	    SLIST_NEXT(SLIST_NEXT(elm, field), field);			\
} while (0)
#define SLIST_SWAP(head1, head2, type) do {				\
	struct type *swap_first = SLIST_FIRST(head1);			\
	SLIST_FIRST(head1) = SLIST_FIRST(head2);			\
	SLIST_FIRST(head2) = swap_first;				\
} while (0)
#define STAILQ_REMOVE_AFTER(head, elm, field) do {			\
	if ((STAILQ_NEXT(elm, field) =					\
	     STAILQ_NEXT(STAILQ_NEXT(elm, field), field)) == NULL)	\
		(head)->stqh_last = &STAILQ_NEXT((elm), field);		\
} while (0)
#define STAILQ_SWAP(head1, head2, type) do {				\
	struct type *swap_first = STAILQ_FIRST(head1);			\
	struct type **swap_last = (head1)->stqh_last;			\
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
	struct type *swap_first = (head1)->tqh_first;			\
	struct type **swap_last = (head1)->tqh_last;			\
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
#define __CC_SUPPORTS_DYNAMIC_ARRAY_INIT 1
#define __CC_SUPPORTS_INLINE 1
#define __CC_SUPPORTS_VARADIC_XXX 1 
#define __CC_SUPPORTS_WARNING 1
#define __CC_SUPPORTS___FUNC__ 1
#define __CC_SUPPORTS___INLINE 1
#define __CC_SUPPORTS___INLINE__ 1
#define __GNUCLIKE_ASM 3
#define __GNUCLIKE_BUILTIN_CONSTANT_P 1
#define __GNUCLIKE_BUILTIN_MEMCPY 1
# define __GNUCLIKE_BUILTIN_NEXT_ARG 1
# define __GNUCLIKE_BUILTIN_STDARG 1
# define __GNUCLIKE_BUILTIN_VAALIST 1
# define __GNUCLIKE_BUILTIN_VARARGS 1
# define __GNUCLIKE_CTOR_SECTION_HANDLING 1

# define __GNUCLIKE_MATH_BUILTIN_RELOPS
#define __GNUCLIKE___OFFSETOF 1
#define __GNUCLIKE___SECTION 1
#define __GNUCLIKE___TYPEOF 1
# define __GNUC_VA_LIST_COMPATIBILITY 1
#define __NO_TLS 1
#define __aligned(x)	__attribute__((__aligned__(x)))
#define __nonnull(x)	__attribute__((__nonnull__(x)))
#define __offsetof(type, field)	 __builtin_offsetof(type, field)
#define __predict_false(exp)    __builtin_expect((exp), 0)
#define __predict_true(exp)     __builtin_expect((exp), 1)
#define __section(x)	__attribute__((__section__(x)))
#define ABS_SET(set, sym)	__MAKE_SET(set, sym)
#define BSS_SET(set, sym)	__MAKE_SET(set, sym)
#define DATA_SET(set, sym)	__MAKE_SET(set, sym)
#define SET_BEGIN(set)							\
	(&__CONCAT(__start_set_,set))
#define SET_COUNT(set)							\
	(SET_LIMIT(set) - SET_BEGIN(set))
#define SET_DECLARE(set, ptype)					\
	extern ptype __weak *__CONCAT(__start_set_,set);	\
	extern ptype __weak *__CONCAT(__stop_set_,set)
#define SET_ENTRY(set, sym)	__MAKE_SET(set, sym)
#define SET_FOREACH(pvar, set)						\
	for (pvar = SET_BEGIN(set); pvar < SET_LIMIT(set); pvar++)
#define SET_ITEM(set, i)						\
	((SET_BEGIN(set))[i])
#define SET_LIMIT(set)							\
	(&__CONCAT(__stop_set_,set))
#define TEXT_SET(set, sym)	__MAKE_SET(set, sym)

#define __MAKE_SET(set, sym)				\
	__GLOBL(__CONCAT(__start_set_,set));		\
	__GLOBL(__CONCAT(__stop_set_,set));		\
	static void const * __MAKE_SET_CONST		\
	__set_##set##_sym_##sym __section("set_" #set)	\
	__used = &(sym)
#define num_pages(x) \
	((vm_offset_t)((((vm_offset_t)(x)) + PAGE_MASK) >> PAGE_SHIFT))
#define IDX_TO_OFF(idx) (((vm_ooffset_t)(idx)) << PAGE_SHIFT)
#define OBJ_MIGHTBEDIRTY 0x0100		
#define OFF_TO_IDX(off) ((vm_pindex_t)(((vm_ooffset_t)(off)) >> PAGE_SHIFT))

#define VM_FAULT_CHANGE_WIRING 1	
#define VM_FAULT_NORMAL 0		

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

#define KTR_COMPILE 0




#define VM_PAGE_BITS_ALL 0xffu
#define VM_PAGE_TO_PHYS(entry)	((entry)->phys_addr)
#define CALLOUT_HANDLE_INITIALIZER(handle)	\
	{ NULL }
#define ovbcopy(f, t, l) bcopy((f), (t), (l))
#define offsetof(type, field) __offsetof(type, field)





#define _VM_VM_KERN_H_ 1

#define ucontext4 ucontext
#define ILL_BADSTK 	8	
#define ILL_COPROC 	7	
#define ILL_ILLADR 	3	
#define ILL_ILLOPC 	1	
#define ILL_ILLOPN 	2	
#define ILL_ILLTRP 	4	
#define ILL_PRVOPC 	5	
#define ILL_PRVREG 	6	
#define SIG_HOLD        ((__sighandler_t *)3)

#define SEM_VALUE_MAX  __INT_MAX


#define CPU_SET_RDONLY  0x0002  
#define CPU_SET_ROOT    0x0001  
#define UMA_SMALLEST_UNIT       (PAGE_SIZE / 256) 

#define BLKDEV_IOSIZE  PAGE_SIZE	


#define __FreeBSD_version 1100027	
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






#define INIT_SYSENTVEC(name, sv)					\
    SYSINIT(name, SI_SUB_EXEC, SI_ORDER_ANY,				\
	(sysinit_cfunc_t)exec_sysvec_init, sv);
#define SYSCALL_INIT_HELPER(syscallname) {			\
    .new_sysent = {						\
	.sy_narg = (sizeof(struct syscallname ## _args )	\
	    / sizeof(register_t)),				\
	.sy_call = (sy_call_t *)& sys_ ## syscallname,		\
	.sy_auevent = SYS_AUE_##syscallname			\
    },								\
    .syscall_no = SYS_##syscallname				\
}
#define SYSCALL_INIT_HELPER_COMPAT(syscallname) {		\
    .new_sysent = {						\
	.sy_narg = (sizeof(struct syscallname ## _args )	\
	    / sizeof(register_t)),				\
	.sy_call = (sy_call_t *)& syscallname,			\
	.sy_auevent = SYS_AUE_##syscallname			\
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

#define MNT_CMDFLAGS   (MNT_UPDATE	| MNT_DELEXPORT	| MNT_RELOAD	| \
			MNT_FORCE	| MNT_SNAPSHOT	| MNT_BYFSID)
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

#define SCHED_FIFO      1
#define SCHED_OTHER     2
#define SCHED_RR        3
#define SCHED_STAT_INC(var)     DPCPU_GET(var)++;


#define PT_FIRSTMACH    64	
#define PT_GETDBREGS    37	
#define PT_GETFPREGS    35	
#define PT_GETREGS      33	
#define PT_SETDBREGS    38	
#define PT_SETFPREGS    36	
#define PT_SETREGS      34	
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
									\
	if (!_mtx_obtain_lock((mp), _tid))				\
		_mtx_lock_sleep((mp), _tid, (opts), (file), (line));	\
	else								\
              	LOCKSTAT_PROFILE_OBTAIN_LOCK_SUCCESS(LS_MTX_LOCK_ACQUIRE, \
		    mp, 0, 0, (file), (line));				\
} while (0)
#define __mtx_lock_spin(mp, tid, opts, file, line) do {			\
	uintptr_t _tid = (uintptr_t)(tid);				\
									\
	spinlock_enter();						\
	if (!_mtx_obtain_lock((mp), _tid)) {				\
		if ((mp)->mtx_lock == _tid)				\
			(mp)->mtx_recurse++;				\
		else							\
			_mtx_lock_spin((mp), _tid, (opts), (file), (line)); \
	} else 								\
              	LOCKSTAT_PROFILE_OBTAIN_LOCK_SUCCESS(LS_MTX_SPIN_LOCK_ACQUIRE, \
		    mp, 0, 0, (file), (line));				\
} while (0)
#define __mtx_unlock(mp, tid, opts, file, line) do {			\
	uintptr_t _tid = (uintptr_t)(tid);				\
									\
	if ((mp)->mtx_recurse == 0)					\
		 LOCKSTAT_PROFILE_RELEASE_LOCK(LS_MTX_UNLOCK_RELEASE,	\
		    (mp));						\
	if (!_mtx_release_lock((mp), _tid))				\
		_mtx_unlock_sleep((mp), (opts), (file), (line));	\
} while (0)
#define __mtx_unlock_spin(mp) do {					\
	if (mtx_recursed((mp)))						\
		(mp)->mtx_recurse--;					\
	else {								\
		LOCKSTAT_PROFILE_RELEASE_LOCK(LS_MTX_SPIN_UNLOCK_RELEASE, \
			mp);						\
		_mtx_release_lock_quick((mp));				\
	}                                                               \
	spinlock_exit();				                \
} while (0)
#define _mtx_obtain_lock(mp, tid)					\
	atomic_cmpset_acq_ptr(&(mp)->mtx_lock, MTX_UNOWNED, (tid))
#define _mtx_release_lock(mp, tid)					\
	atomic_cmpset_rel_ptr(&(mp)->mtx_lock, (tid), MTX_UNOWNED)
#define _mtx_release_lock_quick(mp)					\
	atomic_store_rel_ptr(&(mp)->mtx_lock, MTX_UNOWNED)
#define mtx_assert_(m, what, file, line)	(void)0
#define mtx_lock(m)		mtx_lock_flags((m), 0)
#define mtx_lock_spin(m)	mtx_lock_spin_flags((m), 0)
#define mtx_name(m)	((m)->lock_object.lo_name)
#define mtx_owned(m)	(((m)->mtx_lock & ~MTX_FLAGMASK) == (uintptr_t)curthread)
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
#define mtx_unlock(m)		mtx_unlock_flags((m), 0)
#define mtx_unlock_spin(m)	mtx_unlock_spin_flags((m), 0)
#define KLD_DPF(cat, args)					\
	do {							\
		if (kld_debug & KLD_DEBUG_##cat) printf args;	\
	} while (0)
#define MD_FETCH(mdp, info, type) ({ \
	type *__p; \
	__p = (type *)preload_search_info((mdp), MODINFO_METADATA | (info)); \
	__p ? *__p : 0; \
})

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
#define DEFINE_CLASS_2(name, methods, size,		\
	               base1, base2)			\
							\
static kobj_class_t name ## _baseclasses[] =		\
	{ &base1,					\
	  &base2, NULL };				\
struct kobj_class name ## _class = {			\
	#name, methods, size, name ## _baseclasses	\
}
#define DEFINE_CLASS_3(name, methods, size,		\
		       base1, base2, base3)		\
							\
static kobj_class_t name ## _baseclasses[] =		\
	{ &base1,					\
	  &base2,					\
	  &base3, NULL };				\
struct kobj_class name ## _class = {			\
	#name, methods, size, name ## _baseclasses	\
}
#define KOBJMETHOD(NAME, FUNC) \
	{ &NAME##_desc, (kobjop_t) (1 ? FUNC : (NAME##_t *)NULL) }
#define KOBJOPLOOKUP(OPS,OP) do {				\
	kobjop_desc_t _desc = &OP##_##desc;			\
	kobj_method_t **_cep =					\
	    &OPS->cache[_desc->id & (KOBJ_CACHE_SIZE-1)];	\
	kobj_method_t *_ce = *_cep;				\
	kobj_lookup_hits++; 			\
	if (_ce->desc != _desc)					\
		_ce = kobj_lookup_method(OPS->cls,		\
					 _cep, _desc);		\
	_m = _ce->func;						\
} while(0)

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

#define EXEC_SET(name, execsw_arg) \
	static int __CONCAT(name,_modevent)(module_t mod, int type, \
	    void *data) \
	{ \
		struct execsw *exec = (struct execsw *)data; \
		int error = 0; \
		switch (type) { \
		case MOD_LOAD: \
			 \
			error = exec_register(exec); \
			if (error) \
				printf(__XSTRING(name) "register failed\n"); \
			break; \
		case MOD_UNLOAD: \
			 \
			error = exec_unregister(exec); \
			if (error) \
				printf(__XSTRING(name) " unregister failed\n");\
			break; \
		default: \
			error = EOPNOTSUPP; \
			break; \
		} \
		return error; \
	} \
	static moduledata_t __CONCAT(name,_mod) = { \
		__XSTRING(name), \
		__CONCAT(name,_modevent), \
		(void *)& execsw_arg \
	}; \
	DECLARE_MODULE_TIED(name, __CONCAT(name,_mod), SI_SUB_EXEC, \
	    SI_ORDER_ANY)

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
	KASSERT((list)->el_flags & EHL_INITTED,				\
 	   ("eventhandler_invoke: running non-inited list"));		\
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


#define CPUFREQ_CMP(x, y)	(abs((x) - (y)) < 25)


#define __BUS_ACCESSOR(varp, var, ivarp, ivar, type)			\
									\
static __inline type varp ## _get_ ## var(device_t dev)			\
{									\
	uintptr_t v;							\
	BUS_READ_IVAR(device_get_parent(dev), dev,			\
	    ivarp ## _IVAR_ ## ivar, &v);				\
	return ((type) v);						\
}									\
									\
static __inline void varp ## _set_ ## var(device_t dev, type t)		\
{									\
	uintptr_t v = (uintptr_t) t;					\
	BUS_WRITE_IVAR(device_get_parent(dev), dev,			\
	    ivarp ## _IVAR_ ## ivar, v);				\
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

#define BUF_LOCKFREE(bp) 						\
	lockdestroy(&(bp)->b_lock)
#define BUF_LOCKINIT(bp)						\
	lockinit(&(bp)->b_lock, PRIBIO + 4, buf_wmesg, 0, 0)
#define BUF_LOCKPRINTINFO(bp) 						\
	lockmgr_printinfo(&(bp)->b_lock)
#define BUF_WMESG "bufwait"
#define PRINT_BUF_FLAGS "\20\40remfree\37cluster\36vmio\35ram\34managed" \
	"\33paging\32infreecnt\31nocopy\30b23\27relbuf\26dirty\25b20" \
	"\24b19\23b18\22clusterok\21malloc\20nocache\17b14\16inval" \
	"\15b12\14b11\13eintr\12done\11persist\10delwri\7validsuspwrt" \
	"\6cache\5deferred\4direct\3async\2needcommit\1age"
#define bread(vp, blkno, size, cred, bpp) \
	    breadn_flags(vp, blkno, size, NULL, NULL, 0, cred, 0, bpp)
#define bread_gb(vp, blkno, size, cred, gbflags, bpp) \
	    breadn_flags(vp, blkno, size, NULL, NULL, 0, cred, \
		gbflags, bpp)
#define breadn(vp, blkno, size, rablkno, rabsize, cnt, cred, bpp) \
	    breadn_flags(vp, blkno, size, rablkno, rabsize, cnt, cred, 0, bpp)
#define PROC_ASSERT_HELD(p) do {					\
	KASSERT((p)->p_lock > 0, ("process not held"));			\
} while (0)
#define PROC_ASSERT_NOT_HELD(p) do {					\
	KASSERT((p)->p_lock == 0, ("process held"));			\
} while (0)
#define TD_IS_IDLETHREAD(td)	((td)->td_flags & TDF_IDLETD)

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
} while(0)
#define KNOTE(list, hist, flags)	knote(list, hist, flags)
#define KNOTE_LOCKED(list, hint)	knote(list, hint, KNF_LISTLOCKED)
#define KNOTE_UNLOCKED(list, hint)	knote(list, hint, 0)

#define knlist_clear(knl, islocked)				\
		knlist_cleardel((knl), NULL, (islocked), 0)
#define knlist_delete(knl, td, islocked)			\
		knlist_cleardel((knl), (td), (islocked), 1)
#define cv_broadcast(cvp)	cv_broadcastpri(cvp, 0)
#define BO_BDFLUSH(bo, bp)	((bo)->bo_ops->bop_bdflush((bo), (bp)))
#define BO_STRATEGY(bo, bp)	((bo)->bo_ops->bop_strategy((bo), (bp)))
#define BO_SYNC(bo, w)		((bo)->bo_ops->bop_sync((bo), (w)))
#define BO_WRITE(bo, bp)	((bo)->bo_ops->bop_write((bp)))


#define physread physio
#define physwrite physio
