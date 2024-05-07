





#include<sys/sysctl.h>
#include<sys/select.h>





#include<sys/resource.h>






#include<sys/wait.h>











#include<sys/time.h>








#include<sys/ucontext.h>









#include<sys/param.h>













#include<sys/signal.h>
#include<sys/uio.h>
#include<sys/cdefs.h>


#include<sys/types.h>






#include<sys/queue.h>

#define offsetof(type, field) __offsetof(type, field)





#define DUMMY(s)							\
LIN_SDT_PROBE_DEFINE0(dummy, s, entry);					\
LIN_SDT_PROBE_DEFINE0(dummy, s, not_implemented);			\
LIN_SDT_PROBE_DEFINE1(dummy, s, return, "int");				\
int									\
linux_ ## s(struct thread *td, struct linux_ ## s ## _args *args)	\
{									\
	static pid_t pid;						\
									\
	LIN_SDT_PROBE0(dummy, s, entry);				\
									\
	if (pid != td->td_proc->p_pid) {				\
		linux_msg(td, "syscall %s not implemented", #s);	\
		LIN_SDT_PROBE0(dummy, s, not_implemented);		\
		pid = td->td_proc->p_pid;				\
	};								\
									\
	LIN_SDT_PROBE1(dummy, s, return, ENOSYS);			\
	return (ENOSYS);						\
}									\
struct __hack
#define LCONVPATH(td, upath, pathp, i) 	\
   LCONVPATH_AT(td, upath, pathp, i, AT_FDCWD)
#define LCONVPATHCREAT(td, upath, pathp) LCONVPATH(td, upath, pathp, 1)
#define LCONVPATHCREAT_AT(td, upath, pathp, dfd) LCONVPATH_AT(td, upath, pathp, 1, dfd)
#define LCONVPATHEXIST(td, upath, pathp) LCONVPATH(td, upath, pathp, 0)
#define LCONVPATHEXIST_AT(td, upath, pathp, dfd) LCONVPATH_AT(td, upath, pathp, 0, dfd)
#define LCONVPATH_AT(td, upath, pathp, i, dfd)				\
	do {								\
		int _error;						\
									\
		_error = linux_emul_convpath(td, upath, UIO_USERSPACE,	\
		    pathp, i, dfd);					\
		if (*(pathp) == NULL)					\
			return (_error);				\
	} while (0)
#define LFREEPATH(path)	free(path, M_TEMP)

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
#define BLKDEV_IOSIZE  PAGE_SIZE	


#define __FreeBSD_version 1100097	
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


#define ABS_SET(set, sym)	__MAKE_SET(set, sym)
#define BSS_SET(set, sym)	__MAKE_SET(set, sym)
#define DATA_SET(set, sym)	__MAKE_SET(set, sym)
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

#define __MAKE_SET(set, sym)				\
	__GLOBL(__CONCAT(__start_set_,set));		\
	__GLOBL(__CONCAT(__stop_set_,set));		\
	static void const * __MAKE_SET_CONST		\
	__set_##set##_sym_##sym __section("set_" #set)	\
	__used = &(sym)
#define num_pages(x) \
	((vm_offset_t)((((vm_offset_t)(x)) + PAGE_MASK) >> PAGE_SHIFT))


#define LIST_SWAP(head1, head2, type, field) do {			\
	QUEUE_TYPEOF(type) *swap_tmp = LIST_FIRST(head1);		\
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

#define LINUX_IOCTL_DISK_MAX    LINUX_BLKSSZGET
#define LINUX_IOCTL_DISK_MIN    LINUX_BLKROSET
#define FUTEX_OP_ADD            1	
#define FUTEX_OP_ANDN           3	
#define FUTEX_OP_CMP_EQ         0	
#define FUTEX_OP_CMP_GE         5	
#define FUTEX_OP_CMP_GT         4	
#define FUTEX_OP_CMP_LE         3	
#define FUTEX_OP_CMP_LT         2	
#define FUTEX_OP_CMP_NE         1	
#define FUTEX_OP_OPARG_SHIFT    8	
#define FUTEX_OP_OR             2	
#define FUTEX_OP_SET            0	
#define FUTEX_OP_XOR            4	


#define ucontext4 ucontext
#define SEM_VALUE_MAX  __INT_MAX


#define CPU_SET_RDONLY  0x0002  
#define CPU_SET_ROOT    0x0001  
#define UMA_SMALLEST_UNIT       (PAGE_SIZE / 256) 

#define LINUX_SIG_VALID(sig)	((sig) <= LINUX_SIGRTMAX && (sig) > 0)

#define VM_PAGE_BITS_ALL 0xffu
#define VM_PAGE_TO_PHYS(entry)	((entry)->phys_addr)
#define CALLOUT_HANDLE_INITIALIZER(handle)	\
	{ NULL }
#define ovbcopy(f, t, l) bcopy((f), (t), (l))


#define callout_async_drain(c, d)					\
    _callout_stop_safe(c, 0, d)
#define IDX_TO_OFF(idx) (((vm_ooffset_t)(idx)) << PAGE_SHIFT)
#define OBJ_MIGHTBEDIRTY 0x0100		
#define OFF_TO_IDX(off) ((vm_pindex_t)(((vm_ooffset_t)(off)) >> PAGE_SHIFT))

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
	if (sdt_##prov##_##mod##_##func##_##name->id)				\
		(*sdt_probe_func)(sdt_##prov##_##mod##_##func##_##name->id,	\
		    (uintptr_t) arg0, (uintptr_t) arg1, (uintptr_t) arg2,	\
		    (uintptr_t) arg3, (uintptr_t) arg4);			\
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

#define KTR_COMPILE 0


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
		LOCKSTAT_PROFILE_OBTAIN_LOCK_SUCCESS(adaptive__acquire,	\
		    mp, 0, 0, file, line);				\
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
		LOCKSTAT_PROFILE_OBTAIN_LOCK_SUCCESS(spin__acquire,	\
		    mp, 0, 0, file, line);				\
} while (0)
#define __mtx_unlock(mp, tid, opts, file, line) do {			\
	uintptr_t _tid = (uintptr_t)(tid);				\
									\
	if ((mp)->mtx_recurse == 0)					\
		LOCKSTAT_PROFILE_RELEASE_LOCK(adaptive__release, mp);	\
	if (!_mtx_release_lock((mp), _tid))				\
		_mtx_unlock_sleep((mp), (opts), (file), (line));	\
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
#define textvp_fullpath(p, rb, rfb) \
	vn_fullpath(FIRST_THREAD_IN_PROC(p), (p)->p_textvp, rb, rfb)
#define vn_lock(vp, flags) _vn_lock(vp, flags, "__FILE__", "__LINE__")
#define vprint(label, vp) vn_printf((vp), "%s\n", (label))
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
#define BO_BDFLUSH(bo, bp)	((bo)->bo_ops->bop_bdflush((bo), (bp)))
#define BO_STRATEGY(bo, bp)	((bo)->bo_ops->bop_strategy((bo), (bp)))
#define BO_SYNC(bo, w)		((bo)->bo_ops->bop_sync((bo), (w)))
#define BO_WRITE(bo, bp)	((bo)->bo_ops->bop_write((bp)))



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
#define TD_IS_IDLETHREAD(td)	((td)->td_flags & TDF_IDLETD)
#define VM_DOMAIN_POLICY_STATIC_INITIALISER(vt, vd) \
	{ .seq = 0, \
	  .p.policy = vt, \
	  .p.domain = vd }


#define RTP_PRIO_BASE(P)	PRI_BASE(P)
#define RTP_PRIO_IS_REALTIME(P) PRI_IS_REALTIME(P)
#define RTP_PRIO_NEED_RR(P)	PRI_NEED_RR(P)


#define cv_broadcast(cvp)	cv_broadcastpri(cvp, 0)
