





__FBSDID("$FreeBSD$");



































































static __inline boolean_t pmap_type_guest(pmap_t pmap)
{

	return ((pmap->pm_type == PT_EPT) || (pmap->pm_type == PT_RVI));
}

static __inline boolean_t pmap_emulate_ad_bits(pmap_t pmap)
{

	return ((pmap->pm_flags & PMAP_EMULATE_AD_BITS) != 0);
}

static __inline pt_entry_t pmap_valid_bit(pmap_t pmap)
{
	pt_entry_t mask;

	switch (pmap->pm_type) {
	case PT_X86:
	case PT_RVI:
		mask = X86_PG_V;
		break;
	case PT_EPT:
		if (pmap_emulate_ad_bits(pmap))
			mask = EPT_PG_EMUL_V;
		else mask = EPT_PG_READ;
		break;
	default:
		panic("pmap_valid_bit: invalid pm_type %d", pmap->pm_type);
	}

	return (mask);
}

static __inline pt_entry_t pmap_rw_bit(pmap_t pmap)
{
	pt_entry_t mask;

	switch (pmap->pm_type) {
	case PT_X86:
	case PT_RVI:
		mask = X86_PG_RW;
		break;
	case PT_EPT:
		if (pmap_emulate_ad_bits(pmap))
			mask = EPT_PG_EMUL_RW;
		else mask = EPT_PG_WRITE;
		break;
	default:
		panic("pmap_rw_bit: invalid pm_type %d", pmap->pm_type);
	}

	return (mask);
}

static pt_entry_t pg_g;

static __inline pt_entry_t pmap_global_bit(pmap_t pmap)
{
	pt_entry_t mask;

	switch (pmap->pm_type) {
	case PT_X86:
		mask = pg_g;
		break;
	case PT_RVI:
	case PT_EPT:
		mask = 0;
		break;
	default:
		panic("pmap_global_bit: invalid pm_type %d", pmap->pm_type);
	}

	return (mask);
}

static __inline pt_entry_t pmap_accessed_bit(pmap_t pmap)
{
	pt_entry_t mask;

	switch (pmap->pm_type) {
	case PT_X86:
	case PT_RVI:
		mask = X86_PG_A;
		break;
	case PT_EPT:
		if (pmap_emulate_ad_bits(pmap))
			mask = EPT_PG_READ;
		else mask = EPT_PG_A;
		break;
	default:
		panic("pmap_accessed_bit: invalid pm_type %d", pmap->pm_type);
	}

	return (mask);
}

static __inline pt_entry_t pmap_modified_bit(pmap_t pmap)
{
	pt_entry_t mask;

	switch (pmap->pm_type) {
	case PT_X86:
	case PT_RVI:
		mask = X86_PG_M;
		break;
	case PT_EPT:
		if (pmap_emulate_ad_bits(pmap))
			mask = EPT_PG_WRITE;
		else mask = EPT_PG_M;
		break;
	default:
		panic("pmap_modified_bit: invalid pm_type %d", pmap->pm_type);
	}

	return (mask);
}

static __inline pt_entry_t pmap_pku_mask_bit(pmap_t pmap)
{

	return (pmap->pm_type == PT_X86 ? X86_PG_PKU_MASK : 0);
}
































































struct pmap kernel_pmap_store;

vm_offset_t virtual_avail;	
vm_offset_t virtual_end;	

int nkpt;
SYSCTL_INT(_machdep, OID_AUTO, nkpt, CTLFLAG_RD, &nkpt, 0, "Number of kernel page table pages allocated on bootup");

static int ndmpdp;
vm_paddr_t dmaplimit;
vm_offset_t kernel_vm_end = VM_MIN_KERNEL_ADDRESS;
pt_entry_t pg_nx;

static SYSCTL_NODE(_vm, OID_AUTO, pmap, CTLFLAG_RD, 0, "VM/pmap parameters");

static int pg_ps_enabled = 1;
SYSCTL_INT(_vm_pmap, OID_AUTO, pg_ps_enabled, CTLFLAG_RDTUN | CTLFLAG_NOFETCH, &pg_ps_enabled, 0, "Are large page mappings enabled?");


static int pat_index[PAT_INDEX_SIZE];	

static u_int64_t	KPTphys;	
static u_int64_t	KPDphys;	
u_int64_t		KPDPphys;	
u_int64_t		KPML4phys;	

static u_int64_t	DMPDphys;	
static u_int64_t	DMPDPphys;	
static int		ndmpdpphys;	

static vm_paddr_t	KERNend;	



static struct pmap_preinit_mapping {
	vm_paddr_t	pa;
	vm_offset_t	va;
	vm_size_t	sz;
	int		mode;
} pmap_preinit_mapping[PMAP_PREINIT_MAPPING_COUNT];
static int pmap_initialized;



static __inline int pc_to_domain(struct pv_chunk *pc)
{

	return (_vm_phys_domain(DMAP_TO_PHYS((vm_offset_t)pc)));
}

static __inline int pc_to_domain(struct pv_chunk *pc __unused)
{

	return (0);
}


struct pv_chunks_list {
	struct mtx pvc_lock;
	TAILQ_HEAD(pch, pv_chunk) pvc_list;
	int active_reclaims;
} __aligned(CACHE_LINE_SIZE);

struct pv_chunks_list __exclusive_cache_line pv_chunks[PMAP_MEMDOM];


struct pmap_large_md_page {
	struct rwlock   pv_lock;
	struct md_page  pv_page;
	u_long pv_invl_gen;
};
__exclusive_cache_line static struct pmap_large_md_page pv_dummy_large;

__read_mostly static struct pmap_large_md_page *pv_table;
__read_mostly vm_paddr_t pmap_last_pa;

static struct rwlock __exclusive_cache_line pv_list_locks[NPV_LIST_LOCKS];
static u_long pv_invl_gen[NPV_LIST_LOCKS];
static struct md_page *pv_table;
static struct md_page pv_dummy;



pt_entry_t *CMAP1 = NULL;
caddr_t CADDR1 = 0;
static vm_offset_t qframe = 0;
static struct mtx qframe_mtx;

static int pmap_flags = PMAP_PDE_SUPERPAGE;	

static vmem_t *large_vmem;
static u_int lm_ents;


int pmap_pcid_enabled = 1;
SYSCTL_INT(_vm_pmap, OID_AUTO, pcid_enabled, CTLFLAG_RDTUN | CTLFLAG_NOFETCH, &pmap_pcid_enabled, 0, "Is TLB Context ID enabled ?");
int invpcid_works = 0;
SYSCTL_INT(_vm_pmap, OID_AUTO, invpcid_works, CTLFLAG_RD, &invpcid_works, 0, "Is the invpcid instruction available ?");

int __read_frequently pti = 0;
SYSCTL_INT(_vm_pmap, OID_AUTO, pti, CTLFLAG_RDTUN | CTLFLAG_NOFETCH, &pti, 0, "Page Table Isolation enabled");

static vm_object_t pti_obj;
static pml4_entry_t *pti_pml4;
static vm_pindex_t pti_pg_idx;
static bool pti_finalized;

struct pmap_pkru_range {
	struct rs_el	pkru_rs_el;
	u_int		pkru_keyidx;
	int		pkru_flags;
};

static uma_zone_t pmap_pkru_ranges_zone;
static bool pmap_pkru_same(pmap_t pmap, vm_offset_t sva, vm_offset_t eva);
static pt_entry_t pmap_pkru_get(pmap_t pmap, vm_offset_t va);
static void pmap_pkru_on_remove(pmap_t pmap, vm_offset_t sva, vm_offset_t eva);
static void *pkru_dup_range(void *ctx, void *data);
static void pkru_free_range(void *ctx, void *node);
static int pmap_pkru_copy(pmap_t dst_pmap, pmap_t src_pmap);
static int pmap_pkru_deassign(pmap_t pmap, vm_offset_t sva, vm_offset_t eva);
static void pmap_pkru_deassign_all(pmap_t pmap);

static int pmap_pcid_save_cnt_proc(SYSCTL_HANDLER_ARGS)
{
	int i;
	uint64_t res;

	res = 0;
	CPU_FOREACH(i) {
		res += cpuid_to_pcpu[i]->pc_pm_save_cnt;
	}
	return (sysctl_handle_64(oidp, &res, 0, req));
}
SYSCTL_PROC(_vm_pmap, OID_AUTO, pcid_save_cnt, CTLTYPE_U64 | CTLFLAG_RD | CTLFLAG_MPSAFE, NULL, 0, pmap_pcid_save_cnt_proc, "QU", "Count of saved TLB context on switch");


static LIST_HEAD(, pmap_invl_gen) pmap_invl_gen_tracker = LIST_HEAD_INITIALIZER(&pmap_invl_gen_tracker);
static struct mtx invl_gen_mtx;

static struct lock_object invl_gen_ts = {
	.lo_name = "invlts", };
static struct pmap_invl_gen pmap_invl_gen_head = {
	.gen = 1, .next = NULL, };

static u_long pmap_invl_gen = 1;
static int pmap_invl_waiters;
static struct callout pmap_invl_callout;
static bool pmap_invl_callout_inited;



static bool pmap_di_locked(void)
{
	int tun;

	if ((cpu_feature2 & CPUID2_CX16) == 0)
		return (true);
	tun = 0;
	TUNABLE_INT_FETCH("vm.pmap.di_locked", &tun);
	return (tun != 0);
}

static int sysctl_pmap_di_locked(SYSCTL_HANDLER_ARGS)
{
	int locked;

	locked = pmap_di_locked();
	return (sysctl_handle_int(oidp, &locked, 0, req));
}
SYSCTL_PROC(_vm_pmap, OID_AUTO, di_locked, CTLTYPE_INT | CTLFLAG_RDTUN | CTLFLAG_MPSAFE, 0, 0, sysctl_pmap_di_locked, "", "Locked delayed invalidation");


static bool pmap_not_in_di_l(void);
static bool pmap_not_in_di_u(void);
DEFINE_IFUNC(, bool, pmap_not_in_di, (void))
{

	return (pmap_di_locked() ? pmap_not_in_di_l : pmap_not_in_di_u);
}

static bool pmap_not_in_di_l(void)
{
	struct pmap_invl_gen *invl_gen;

	invl_gen = &curthread->td_md.md_invl_gen;
	return (invl_gen->gen == 0);
}

static void pmap_thread_init_invl_gen_l(struct thread *td)
{
	struct pmap_invl_gen *invl_gen;

	invl_gen = &td->td_md.md_invl_gen;
	invl_gen->gen = 0;
}

static void pmap_delayed_invl_wait_block(u_long *m_gen, u_long *invl_gen)
{
	struct turnstile *ts;

	ts = turnstile_trywait(&invl_gen_ts);
	if (*m_gen > atomic_load_long(invl_gen))
		turnstile_wait(ts, NULL, TS_SHARED_QUEUE);
	else turnstile_cancel(ts);
}

static void pmap_delayed_invl_finish_unblock(u_long new_gen)
{
	struct turnstile *ts;

	turnstile_chain_lock(&invl_gen_ts);
	ts = turnstile_lookup(&invl_gen_ts);
	if (new_gen != 0)
		pmap_invl_gen = new_gen;
	if (ts != NULL) {
		turnstile_broadcast(ts, TS_SHARED_QUEUE);
		turnstile_unpend(ts);
	}
	turnstile_chain_unlock(&invl_gen_ts);
}


static void pmap_delayed_invl_start_l(void)
{
	struct pmap_invl_gen *invl_gen;
	u_long currgen;

	invl_gen = &curthread->td_md.md_invl_gen;
	PMAP_ASSERT_NOT_IN_DI();
	mtx_lock(&invl_gen_mtx);
	if (LIST_EMPTY(&pmap_invl_gen_tracker))
		currgen = pmap_invl_gen;
	else currgen = LIST_FIRST(&pmap_invl_gen_tracker)->gen;
	invl_gen->gen = currgen + 1;
	LIST_INSERT_HEAD(&pmap_invl_gen_tracker, invl_gen, link);
	mtx_unlock(&invl_gen_mtx);
}


static void pmap_delayed_invl_finish_l(void)
{
	struct pmap_invl_gen *invl_gen, *next;

	invl_gen = &curthread->td_md.md_invl_gen;
	KASSERT(invl_gen->gen != 0, ("missed invl_start"));
	mtx_lock(&invl_gen_mtx);
	next = LIST_NEXT(invl_gen, link);
	if (next == NULL)
		pmap_delayed_invl_finish_unblock(invl_gen->gen);
	else next->gen = invl_gen->gen;
	LIST_REMOVE(invl_gen, link);
	mtx_unlock(&invl_gen_mtx);
	invl_gen->gen = 0;
}

static bool pmap_not_in_di_u(void)
{
	struct pmap_invl_gen *invl_gen;

	invl_gen = &curthread->td_md.md_invl_gen;
	return (((uintptr_t)invl_gen->next & PMAP_INVL_GEN_NEXT_INVALID) != 0);
}

static void pmap_thread_init_invl_gen_u(struct thread *td)
{
	struct pmap_invl_gen *invl_gen;

	invl_gen = &td->td_md.md_invl_gen;
	invl_gen->gen = 0;
	invl_gen->next = (void *)PMAP_INVL_GEN_NEXT_INVALID;
}

static bool pmap_di_load_invl(struct pmap_invl_gen *ptr, struct pmap_invl_gen *out)
{
	uint64_t new_high, new_low, old_high, old_low;
	char res;

	old_low = new_low = 0;
	old_high = new_high = (uintptr_t)0;

	__asm volatile("lock;cmpxchg16b\t%1;sete\t%0" : "=r" (res), "+m" (*ptr), "+a" (old_low), "+d" (old_high)
	    : "b"(new_low), "c" (new_high)
	    : "memory", "cc");
	if (res == 0) {
		if ((old_high & PMAP_INVL_GEN_NEXT_INVALID) != 0)
			return (false);
		out->gen = old_low;
		out->next = (void *)old_high;
	} else {
		out->gen = new_low;
		out->next = (void *)new_high;
	}
	return (true);
}

static bool pmap_di_store_invl(struct pmap_invl_gen *ptr, struct pmap_invl_gen *old_val, struct pmap_invl_gen *new_val)

{
	uint64_t new_high, new_low, old_high, old_low;
	char res;

	new_low = new_val->gen;
	new_high = (uintptr_t)new_val->next;
	old_low = old_val->gen;
	old_high = (uintptr_t)old_val->next;

	__asm volatile("lock;cmpxchg16b\t%1;sete\t%0" : "=r" (res), "+m" (*ptr), "+a" (old_low), "+d" (old_high)
	    : "b"(new_low), "c" (new_high)
	    : "memory", "cc");
	return (res);
}


static long invl_start_restart;
SYSCTL_LONG(_vm_pmap, OID_AUTO, invl_start_restart, CTLFLAG_RD, &invl_start_restart, 0, "");

static long invl_finish_restart;
SYSCTL_LONG(_vm_pmap, OID_AUTO, invl_finish_restart, CTLFLAG_RD, &invl_finish_restart, 0, "");

static int invl_max_qlen;
SYSCTL_INT(_vm_pmap, OID_AUTO, invl_max_qlen, CTLFLAG_RD, &invl_max_qlen, 0, "");



static struct lock_delay_config __read_frequently di_delay;
LOCK_DELAY_SYSINIT_DEFAULT(di_delay);

static void pmap_delayed_invl_start_u(void)
{
	struct pmap_invl_gen *invl_gen, *p, prev, new_prev;
	struct thread *td;
	struct lock_delay_arg lda;
	uintptr_t prevl;
	u_char pri;

	int i, ii;


	td = curthread;
	invl_gen = &td->td_md.md_invl_gen;
	PMAP_ASSERT_NOT_IN_DI();
	lock_delay_arg_init(&lda, &di_delay);
	invl_gen->saved_pri = 0;
	pri = td->td_base_pri;
	if (pri > PVM) {
		thread_lock(td);
		pri = td->td_base_pri;
		if (pri > PVM) {
			invl_gen->saved_pri = pri;
			sched_prio(td, PVM);
		}
		thread_unlock(td);
	}
again:
	PV_STAT(i = 0);
	for (p = &pmap_invl_gen_head;; p = prev.next) {
		PV_STAT(i++);
		prevl = atomic_load_ptr(&p->next);
		if ((prevl & PMAP_INVL_GEN_NEXT_INVALID) != 0) {
			PV_STAT(atomic_add_long(&invl_start_restart, 1));
			lock_delay(&lda);
			goto again;
		}
		if (prevl == 0)
			break;
		prev.next = (void *)prevl;
	}

	if ((ii = invl_max_qlen) < i)
		atomic_cmpset_int(&invl_max_qlen, ii, i);


	if (!pmap_di_load_invl(p, &prev) || prev.next != NULL) {
		PV_STAT(atomic_add_long(&invl_start_restart, 1));
		lock_delay(&lda);
		goto again;
	}

	new_prev.gen = prev.gen;
	new_prev.next = invl_gen;
	invl_gen->gen = prev.gen + 1;

	
	atomic_thread_fence_rel();

	
	critical_enter();

	
	if (!pmap_di_store_invl(p, &prev, &new_prev)) {
		critical_exit();
		PV_STAT(atomic_add_long(&invl_start_restart, 1));
		lock_delay(&lda);
		goto again;
	}

	
	invl_gen->next = NULL;
	critical_exit();
}

static bool pmap_delayed_invl_finish_u_crit(struct pmap_invl_gen *invl_gen, struct pmap_invl_gen *p)

{
	struct pmap_invl_gen prev, new_prev;
	u_long mygen;

	
	mygen = atomic_load_long(&invl_gen->gen);

	if (!pmap_di_load_invl(p, &prev) || prev.next != invl_gen)
		return (false);

	KASSERT(prev.gen < mygen, ("invalid di gen sequence %lu %lu", prev.gen, mygen));
	new_prev.gen = mygen;
	new_prev.next = (void *)((uintptr_t)invl_gen->next & ~PMAP_INVL_GEN_NEXT_INVALID);

	
	atomic_thread_fence_rel();

	return (pmap_di_store_invl(p, &prev, &new_prev));
}

static void pmap_delayed_invl_finish_u(void)
{
	struct pmap_invl_gen *invl_gen, *p;
	struct thread *td;
	struct lock_delay_arg lda;
	uintptr_t prevl;

	td = curthread;
	invl_gen = &td->td_md.md_invl_gen;
	KASSERT(invl_gen->gen != 0, ("missed invl_start: gen 0"));
	KASSERT(((uintptr_t)invl_gen->next & PMAP_INVL_GEN_NEXT_INVALID) == 0, ("missed invl_start: INVALID"));
	lock_delay_arg_init(&lda, &di_delay);

again:
	for (p = &pmap_invl_gen_head; p != NULL; p = (void *)prevl) {
		prevl = atomic_load_ptr(&p->next);
		if ((prevl & PMAP_INVL_GEN_NEXT_INVALID) != 0) {
			PV_STAT(atomic_add_long(&invl_finish_restart, 1));
			lock_delay(&lda);
			goto again;
		}
		if ((void *)prevl == invl_gen)
			break;
	}

	
	if (__predict_false(p == NULL)) {
		PV_STAT(atomic_add_long(&invl_finish_restart, 1));
		lock_delay(&lda);
		goto again;
	}

	critical_enter();
	atomic_set_ptr((uintptr_t *)&invl_gen->next, PMAP_INVL_GEN_NEXT_INVALID);
	if (!pmap_delayed_invl_finish_u_crit(invl_gen, p)) {
		atomic_clear_ptr((uintptr_t *)&invl_gen->next, PMAP_INVL_GEN_NEXT_INVALID);
		critical_exit();
		PV_STAT(atomic_add_long(&invl_finish_restart, 1));
		lock_delay(&lda);
		goto again;
	}
	critical_exit();
	if (atomic_load_int(&pmap_invl_waiters) > 0)
		pmap_delayed_invl_finish_unblock(0);
	if (invl_gen->saved_pri != 0) {
		thread_lock(td);
		sched_prio(td, invl_gen->saved_pri);
		thread_unlock(td);
	}
}


DB_SHOW_COMMAND(di_queue, pmap_di_queue)
{
	struct pmap_invl_gen *p, *pn;
	struct thread *td;
	uintptr_t nextl;
	bool first;

	for (p = &pmap_invl_gen_head, first = true; p != NULL; p = pn, first = false) {
		nextl = atomic_load_ptr(&p->next);
		pn = (void *)(nextl & ~PMAP_INVL_GEN_NEXT_INVALID);
		td = first ? NULL : __containerof(p, struct thread, td_md.md_invl_gen);
		db_printf("gen %lu inv %d td %p tid %d\n", p->gen, (nextl & PMAP_INVL_GEN_NEXT_INVALID) != 0, td, td != NULL ? td->td_tid : -1);

	}
}



static long invl_wait;
SYSCTL_LONG(_vm_pmap, OID_AUTO, invl_wait, CTLFLAG_RD, &invl_wait, 0, "Number of times DI invalidation blocked pmap_remove_all/write");
static long invl_wait_slow;
SYSCTL_LONG(_vm_pmap, OID_AUTO, invl_wait_slow, CTLFLAG_RD, &invl_wait_slow, 0, "Number of slow invalidation waits for lockless DI");



static u_long * pmap_delayed_invl_genp(vm_page_t m)
{
	vm_paddr_t pa;
	u_long *gen;

	pa = VM_PAGE_TO_PHYS(m);
	if (__predict_false((pa) > pmap_last_pa))
		gen = &pv_dummy_large.pv_invl_gen;
	else gen = &(pa_to_pmdp(pa)->pv_invl_gen);

	return (gen);
}

static u_long * pmap_delayed_invl_genp(vm_page_t m)
{

	return (&pv_invl_gen[pa_index(VM_PAGE_TO_PHYS(m)) % NPV_LIST_LOCKS]);
}


static void pmap_delayed_invl_callout_func(void *arg __unused)
{

	if (atomic_load_int(&pmap_invl_waiters) == 0)
		return;
	pmap_delayed_invl_finish_unblock(0);
}

static void pmap_delayed_invl_callout_init(void *arg __unused)
{

	if (pmap_di_locked())
		return;
	callout_init(&pmap_invl_callout, 1);
	pmap_invl_callout_inited = true;
}
SYSINIT(pmap_di_callout, SI_SUB_CPU + 1, SI_ORDER_ANY, pmap_delayed_invl_callout_init, NULL);


static void pmap_delayed_invl_wait_l(vm_page_t m)
{
	u_long *m_gen;

	bool accounted = false;


	m_gen = pmap_delayed_invl_genp(m);
	while (*m_gen > pmap_invl_gen) {

		if (!accounted) {
			atomic_add_long(&invl_wait, 1);
			accounted = true;
		}

		pmap_delayed_invl_wait_block(m_gen, &pmap_invl_gen);
	}
}

static void pmap_delayed_invl_wait_u(vm_page_t m)
{
	u_long *m_gen;
	struct lock_delay_arg lda;
	bool fast;

	fast = true;
	m_gen = pmap_delayed_invl_genp(m);
	lock_delay_arg_init(&lda, &di_delay);
	while (*m_gen > atomic_load_long(&pmap_invl_gen_head.gen)) {
		if (fast || !pmap_invl_callout_inited) {
			PV_STAT(atomic_add_long(&invl_wait, 1));
			lock_delay(&lda);
			fast = false;
		} else {
			
			atomic_add_int(&pmap_invl_waiters, 1);

			
			if (*m_gen > atomic_load_long(&pmap_invl_gen_head.gen)) {
				callout_reset(&pmap_invl_callout, 1, pmap_delayed_invl_callout_func, NULL);
				PV_STAT(atomic_add_long(&invl_wait_slow, 1));
				pmap_delayed_invl_wait_block(m_gen, &pmap_invl_gen_head.gen);
			}
			atomic_add_int(&pmap_invl_waiters, -1);
		}
	}
}

DEFINE_IFUNC(, void, pmap_thread_init_invl_gen, (struct thread *))
{

	return (pmap_di_locked() ? pmap_thread_init_invl_gen_l :
	    pmap_thread_init_invl_gen_u);
}

DEFINE_IFUNC(static, void, pmap_delayed_invl_start, (void))
{

	return (pmap_di_locked() ? pmap_delayed_invl_start_l :
	    pmap_delayed_invl_start_u);
}

DEFINE_IFUNC(static, void, pmap_delayed_invl_finish, (void))
{

	return (pmap_di_locked() ? pmap_delayed_invl_finish_l :
	    pmap_delayed_invl_finish_u);
}

DEFINE_IFUNC(static, void, pmap_delayed_invl_wait, (vm_page_t))
{

	return (pmap_di_locked() ? pmap_delayed_invl_wait_l :
	    pmap_delayed_invl_wait_u);
}


static void pmap_delayed_invl_page(vm_page_t m)
{
	u_long gen, *m_gen;

	rw_assert(VM_PAGE_TO_PV_LIST_LOCK(m), RA_WLOCKED);
	gen = curthread->td_md.md_invl_gen.gen;
	if (gen == 0)
		return;
	m_gen = pmap_delayed_invl_genp(m);
	if (*m_gen < gen)
		*m_gen = gen;
}


static caddr_t crashdumpmap;










TAILQ_HEAD(pv_chunklist, pv_chunk);

static void	free_pv_chunk(struct pv_chunk *pc);
static void	free_pv_chunk_batch(struct pv_chunklist *batch);
static void	free_pv_entry(pmap_t pmap, pv_entry_t pv);
static pv_entry_t get_pv_entry(pmap_t pmap, struct rwlock **lockp);
static int	popcnt_pc_map_pq(uint64_t *map);
static vm_page_t reclaim_pv_chunk(pmap_t locked_pmap, struct rwlock **lockp);
static void	reserve_pv_entries(pmap_t pmap, int needed, struct rwlock **lockp);
static void	pmap_pv_demote_pde(pmap_t pmap, vm_offset_t va, vm_paddr_t pa, struct rwlock **lockp);
static bool	pmap_pv_insert_pde(pmap_t pmap, vm_offset_t va, pd_entry_t pde, u_int flags, struct rwlock **lockp);

static void	pmap_pv_promote_pde(pmap_t pmap, vm_offset_t va, vm_paddr_t pa, struct rwlock **lockp);

static void	pmap_pvh_free(struct md_page *pvh, pmap_t pmap, vm_offset_t va);
static pv_entry_t pmap_pvh_remove(struct md_page *pvh, pmap_t pmap, vm_offset_t va);

static int pmap_change_props_locked(vm_offset_t va, vm_size_t size, vm_prot_t prot, int mode, int flags);
static boolean_t pmap_demote_pde(pmap_t pmap, pd_entry_t *pde, vm_offset_t va);
static boolean_t pmap_demote_pde_locked(pmap_t pmap, pd_entry_t *pde, vm_offset_t va, struct rwlock **lockp);
static boolean_t pmap_demote_pdpe(pmap_t pmap, pdp_entry_t *pdpe, vm_offset_t va);
static bool	pmap_enter_2mpage(pmap_t pmap, vm_offset_t va, vm_page_t m, vm_prot_t prot, struct rwlock **lockp);
static int	pmap_enter_pde(pmap_t pmap, vm_offset_t va, pd_entry_t newpde, u_int flags, vm_page_t m, struct rwlock **lockp);
static vm_page_t pmap_enter_quick_locked(pmap_t pmap, vm_offset_t va, vm_page_t m, vm_prot_t prot, vm_page_t mpte, struct rwlock **lockp);
static void pmap_fill_ptp(pt_entry_t *firstpte, pt_entry_t newpte);
static int pmap_insert_pt_page(pmap_t pmap, vm_page_t mpte, bool promoted);
static void pmap_invalidate_cache_range_selfsnoop(vm_offset_t sva, vm_offset_t eva);
static void pmap_invalidate_cache_range_all(vm_offset_t sva, vm_offset_t eva);
static void pmap_invalidate_pde_page(pmap_t pmap, vm_offset_t va, pd_entry_t pde);
static void pmap_kenter_attr(vm_offset_t va, vm_paddr_t pa, int mode);
static vm_page_t pmap_large_map_getptp_unlocked(void);
static vm_paddr_t pmap_large_map_kextract(vm_offset_t va);

static void pmap_promote_pde(pmap_t pmap, pd_entry_t *pde, vm_offset_t va, struct rwlock **lockp);

static boolean_t pmap_protect_pde(pmap_t pmap, pd_entry_t *pde, vm_offset_t sva, vm_prot_t prot);
static void pmap_pte_props(pt_entry_t *pte, u_long bits, u_long mask);
static void pmap_pti_add_kva_locked(vm_offset_t sva, vm_offset_t eva, bool exec);
static pdp_entry_t *pmap_pti_pdpe(vm_offset_t va);
static pd_entry_t *pmap_pti_pde(vm_offset_t va);
static void pmap_pti_wire_pte(void *pte);
static int pmap_remove_pde(pmap_t pmap, pd_entry_t *pdq, vm_offset_t sva, struct spglist *free, struct rwlock **lockp);
static int pmap_remove_pte(pmap_t pmap, pt_entry_t *ptq, vm_offset_t sva, pd_entry_t ptepde, struct spglist *free, struct rwlock **lockp);
static vm_page_t pmap_remove_pt_page(pmap_t pmap, vm_offset_t va);
static void pmap_remove_page(pmap_t pmap, vm_offset_t va, pd_entry_t *pde, struct spglist *free);
static bool	pmap_remove_ptes(pmap_t pmap, vm_offset_t sva, vm_offset_t eva, pd_entry_t *pde, struct spglist *free, struct rwlock **lockp);

static boolean_t pmap_try_insert_pv_entry(pmap_t pmap, vm_offset_t va, vm_page_t m, struct rwlock **lockp);
static void pmap_update_pde(pmap_t pmap, vm_offset_t va, pd_entry_t *pde, pd_entry_t newpde);
static void pmap_update_pde_invalidate(pmap_t, vm_offset_t va, pd_entry_t pde);

static vm_page_t _pmap_allocpte(pmap_t pmap, vm_pindex_t ptepindex, struct rwlock **lockp);
static vm_page_t pmap_allocpde(pmap_t pmap, vm_offset_t va, struct rwlock **lockp);
static vm_page_t pmap_allocpte(pmap_t pmap, vm_offset_t va, struct rwlock **lockp);

static void _pmap_unwire_ptp(pmap_t pmap, vm_offset_t va, vm_page_t m, struct spglist *free);
static int pmap_unuse_pt(pmap_t, vm_offset_t, pd_entry_t, struct spglist *);






static __inline vm_pindex_t pmap_pde_pindex(vm_offset_t va)
{
	return (va >> PDRSHIFT);
}



static __inline pml4_entry_t * pmap_pml4e(pmap_t pmap, vm_offset_t va)
{

	return (&pmap->pm_pml4[pmap_pml4e_index(va)]);
}


static __inline pdp_entry_t * pmap_pml4e_to_pdpe(pml4_entry_t *pml4e, vm_offset_t va)
{
	pdp_entry_t *pdpe;

	pdpe = (pdp_entry_t *)PHYS_TO_DMAP(*pml4e & PG_FRAME);
	return (&pdpe[pmap_pdpe_index(va)]);
}


static __inline pdp_entry_t * pmap_pdpe(pmap_t pmap, vm_offset_t va)
{
	pml4_entry_t *pml4e;
	pt_entry_t PG_V;

	PG_V = pmap_valid_bit(pmap);
	pml4e = pmap_pml4e(pmap, va);
	if ((*pml4e & PG_V) == 0)
		return (NULL);
	return (pmap_pml4e_to_pdpe(pml4e, va));
}


static __inline pd_entry_t * pmap_pdpe_to_pde(pdp_entry_t *pdpe, vm_offset_t va)
{
	pd_entry_t *pde;

	pde = (pd_entry_t *)PHYS_TO_DMAP(*pdpe & PG_FRAME);
	return (&pde[pmap_pde_index(va)]);
}


static __inline pd_entry_t * pmap_pde(pmap_t pmap, vm_offset_t va)
{
	pdp_entry_t *pdpe;
	pt_entry_t PG_V;

	PG_V = pmap_valid_bit(pmap);
	pdpe = pmap_pdpe(pmap, va);
	if (pdpe == NULL || (*pdpe & PG_V) == 0)
		return (NULL);
	return (pmap_pdpe_to_pde(pdpe, va));
}


static __inline pt_entry_t * pmap_pde_to_pte(pd_entry_t *pde, vm_offset_t va)
{
	pt_entry_t *pte;

	pte = (pt_entry_t *)PHYS_TO_DMAP(*pde & PG_FRAME);
	return (&pte[pmap_pte_index(va)]);
}


static __inline pt_entry_t * pmap_pte(pmap_t pmap, vm_offset_t va)
{
	pd_entry_t *pde;
	pt_entry_t PG_V;

	PG_V = pmap_valid_bit(pmap);
	pde = pmap_pde(pmap, va);
	if (pde == NULL || (*pde & PG_V) == 0)
		return (NULL);
	if ((*pde & PG_PS) != 0)	
		return ((pt_entry_t *)pde);
	return (pmap_pde_to_pte(pde, va));
}

static __inline void pmap_resident_count_inc(pmap_t pmap, int count)
{

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	pmap->pm_stats.resident_count += count;
}

static __inline void pmap_resident_count_dec(pmap_t pmap, int count)
{

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	KASSERT(pmap->pm_stats.resident_count >= count, ("pmap %p resident count underflow %ld %d", pmap, pmap->pm_stats.resident_count, count));

	pmap->pm_stats.resident_count -= count;
}

PMAP_INLINE pt_entry_t * vtopte(vm_offset_t va)
{
	u_int64_t mask = ((1ul << (NPTEPGSHIFT + NPDEPGSHIFT + NPDPEPGSHIFT + NPML4EPGSHIFT)) - 1);

	KASSERT(va >= VM_MAXUSER_ADDRESS, ("vtopte on a uva/gpa 0x%0lx", va));

	return (PTmap + ((va >> PAGE_SHIFT) & mask));
}

static __inline pd_entry_t * vtopde(vm_offset_t va)
{
	u_int64_t mask = ((1ul << (NPDEPGSHIFT + NPDPEPGSHIFT + NPML4EPGSHIFT)) - 1);

	KASSERT(va >= VM_MAXUSER_ADDRESS, ("vtopde on a uva/gpa 0x%0lx", va));

	return (PDmap + ((va >> PDRSHIFT) & mask));
}

static u_int64_t allocpages(vm_paddr_t *firstaddr, int n)
{
	u_int64_t ret;

	ret = *firstaddr;
	bzero((void *)ret, n * PAGE_SIZE);
	*firstaddr += n * PAGE_SIZE;
	return (ret);
}

CTASSERT(powerof2(NDMPML4E));




static void nkpt_init(vm_paddr_t addr)
{
	int pt_pages;
	

	pt_pages = NKPT;

	pt_pages = howmany(addr, 1 << PDRSHIFT);
	pt_pages += NKPDPE(pt_pages);

	
	pt_pages += 32;		

	nkpt = pt_pages;
}


static inline pt_entry_t bootaddr_rwx(vm_paddr_t pa)
{

	
	if (pa < trunc_2mpage(btext - KERNBASE) || pa >= trunc_2mpage(_end - KERNBASE))
		return (X86_PG_RW | pg_nx);

	
	if (pa >= trunc_2mpage(brwsection - KERNBASE))
		return (X86_PG_RW | pg_nx);

	
	if (pa < round_2mpage(etext - KERNBASE))
		return (0);
	return (pg_nx);
}

static void create_pagetables(vm_paddr_t *firstaddr)
{
	int i, j, ndm1g, nkpdpe, nkdmpde;
	pd_entry_t *pd_p;
	pdp_entry_t *pdp_p;
	pml4_entry_t *p4_p;
	uint64_t DMPDkernphys;

	
	ndmpdp = howmany(ptoa(Maxmem), NBPDP);
	if (ndmpdp < 4)		
		ndmpdp = 4;
	ndmpdpphys = howmany(ndmpdp, NPDPEPG);
	if (ndmpdpphys > NDMPML4E) {
		
		printf("NDMPML4E limits system to %d GB\n", NDMPML4E * 512);
		Maxmem = atop(NDMPML4E * NBPML4);
		ndmpdpphys = NDMPML4E;
		ndmpdp = NDMPML4E * NPDEPG;
	}
	DMPDPphys = allocpages(firstaddr, ndmpdpphys);
	ndm1g = 0;
	if ((amd_feature & AMDID_PAGE1GB) != 0) {
		
		ndm1g = ptoa(Maxmem) >> PDPSHIFT;

		
		nkdmpde = howmany((vm_offset_t)(brwsection - KERNBASE), NBPDP);
		DMPDkernphys = allocpages(firstaddr, nkdmpde);
	}
	if (ndm1g < ndmpdp)
		DMPDphys = allocpages(firstaddr, ndmpdp - ndm1g);
	dmaplimit = (vm_paddr_t)ndmpdp << PDPSHIFT;

	
	KPML4phys = allocpages(firstaddr, 1);
	KPDPphys = allocpages(firstaddr, NKPML4E);

	
	nkpt_init(*firstaddr);
	nkpdpe = NKPDPE(nkpt);

	KPTphys = allocpages(firstaddr, nkpt);
	KPDphys = allocpages(firstaddr, nkpdpe);

	
	pd_p = (pd_entry_t *)KPDphys;
	for (i = 0; i < nkpt; i++)
		pd_p[i] = (KPTphys + ptoa(i)) | X86_PG_RW | X86_PG_V;

	
	for (i = 0; (i << PDRSHIFT) < KERNend; i++)
		
		pd_p[i] = (i << PDRSHIFT) | X86_PG_V | PG_PS | pg_g | X86_PG_M | X86_PG_A | bootaddr_rwx(i << PDRSHIFT);

	
	if (*firstaddr < round_2mpage(KERNend))
		*firstaddr = round_2mpage(KERNend);

	
	pdp_p = (pdp_entry_t *)(KPDPphys + ptoa(KPML4I - KPML4BASE));
	for (i = 0; i < nkpdpe; i++)
		pdp_p[i + KPDPI] = (KPDphys + ptoa(i)) | X86_PG_RW | X86_PG_V;

	
	pd_p = (pd_entry_t *)DMPDphys;
	for (i = NPDEPG * ndm1g, j = 0; i < NPDEPG * ndmpdp; i++, j++) {
		pd_p[j] = (vm_paddr_t)i << PDRSHIFT;
		
		pd_p[j] |= X86_PG_RW | X86_PG_V | PG_PS | pg_g | X86_PG_M | X86_PG_A | pg_nx;
	}
	pdp_p = (pdp_entry_t *)DMPDPphys;
	for (i = 0; i < ndm1g; i++) {
		pdp_p[i] = (vm_paddr_t)i << PDPSHIFT;
		
		pdp_p[i] |= X86_PG_RW | X86_PG_V | PG_PS | pg_g | X86_PG_M | X86_PG_A | pg_nx;
	}
	for (j = 0; i < ndmpdp; i++, j++) {
		pdp_p[i] = DMPDphys + ptoa(j);
		pdp_p[i] |= X86_PG_RW | X86_PG_V | pg_nx;
	}

	
	if (ndm1g) {
		pd_p = (pd_entry_t *)DMPDkernphys;
		for (i = 0; i < (NPDEPG * nkdmpde); i++)
			pd_p[i] = (i << PDRSHIFT) | X86_PG_V | PG_PS | pg_g | X86_PG_M | X86_PG_A | pg_nx | bootaddr_rwx(i << PDRSHIFT);

		for (i = 0; i < nkdmpde; i++)
			pdp_p[i] = (DMPDkernphys + ptoa(i)) | X86_PG_RW | X86_PG_V | pg_nx;
	}

	
	p4_p = (pml4_entry_t *)KPML4phys;
	p4_p[PML4PML4I] = KPML4phys;
	p4_p[PML4PML4I] |= X86_PG_RW | X86_PG_V | pg_nx;

	
	for (i = 0; i < ndmpdpphys; i++) {
		p4_p[DMPML4I + i] = DMPDPphys + ptoa(i);
		p4_p[DMPML4I + i] |= X86_PG_RW | X86_PG_V | pg_nx;
	}

	
	for (i = 0; i < NKPML4E; i++) {
		p4_p[KPML4BASE + i] = KPDPphys + ptoa(i);
		p4_p[KPML4BASE + i] |= X86_PG_RW | X86_PG_V;
	}
}


void pmap_bootstrap(vm_paddr_t *firstaddr)
{
	vm_offset_t va;
	pt_entry_t *pte, *pcpu_pte;
	struct region_descriptor r_gdt;
	uint64_t cr4, pcpu_phys;
	u_long res;
	int i;

	KERNend = *firstaddr;
	res = atop(KERNend - (vm_paddr_t)kernphys);

	if (!pti)
		pg_g = X86_PG_G;

	
	create_pagetables(firstaddr);

	pcpu_phys = allocpages(firstaddr, MAXCPU);

	
	vm_phys_add_seg(KPTphys, KPTphys + ptoa(nkpt));

	
	virtual_avail = (vm_offset_t)KERNBASE + round_2mpage(KERNend);
	virtual_end = VM_MAX_KERNEL_ADDRESS;

	
	cr4 = rcr4();
	cr4 |= CR4_PGE;
	load_cr4(cr4);
	load_cr3(KPML4phys);
	if (cpu_stdext_feature & CPUID_STDEXT_SMEP)
		cr4 |= CR4_SMEP;
	if (cpu_stdext_feature & CPUID_STDEXT_SMAP)
		cr4 |= CR4_SMAP;
	load_cr4(cr4);

	
	PMAP_LOCK_INIT(kernel_pmap);
	kernel_pmap->pm_pml4 = (pdp_entry_t *)PHYS_TO_DMAP(KPML4phys);
	kernel_pmap->pm_cr3 = KPML4phys;
	kernel_pmap->pm_ucr3 = PMAP_NO_CR3;
	CPU_FILL(&kernel_pmap->pm_active);	
	TAILQ_INIT(&kernel_pmap->pm_pvchunk);
	kernel_pmap->pm_stats.resident_count = res;
	kernel_pmap->pm_flags = pmap_flags;

 	
	mtx_init(&invl_gen_mtx, "invlgn", NULL, MTX_DEF);

	


	va = virtual_avail;
	pte = vtopte(va);

	
	SYSMAP(caddr_t, CMAP1, crashdumpmap, MAXDUMPPGS)
	CADDR1 = crashdumpmap;

	SYSMAP(struct pcpu *, pcpu_pte, __pcpu, MAXCPU);
	virtual_avail = va;

	for (i = 0; i < MAXCPU; i++) {
		pcpu_pte[i] = (pcpu_phys + ptoa(i)) | X86_PG_V | X86_PG_RW | pg_g | pg_nx | X86_PG_M | X86_PG_A;
	}

	
	STAILQ_INIT(&cpuhead);
	wrmsr(MSR_GSBASE, (uint64_t)&__pcpu[0]);
	pcpu_init(&__pcpu[0], 0, sizeof(struct pcpu));
	amd64_bsp_pcpu_init1(&__pcpu[0]);
	amd64_bsp_ist_init(&__pcpu[0]);
	memcpy(__pcpu[0].pc_gdt, temp_bsp_pcpu.pc_gdt, NGDT * sizeof(struct user_segment_descriptor));
	gdt_segs[GPROC0_SEL].ssd_base = (uintptr_t)&__pcpu[0].pc_common_tss;
	ssdtosyssd(&gdt_segs[GPROC0_SEL], (struct system_segment_descriptor *)&__pcpu[0].pc_gdt[GPROC0_SEL]);
	r_gdt.rd_limit = NGDT * sizeof(struct user_segment_descriptor) - 1;
	r_gdt.rd_base = (long)__pcpu[0].pc_gdt;
	lgdt(&r_gdt);
	wrmsr(MSR_GSBASE, (uint64_t)&__pcpu[0]);
	ltr(GSEL(GPROC0_SEL, SEL_KPL));
	__pcpu[0].pc_dynamic = temp_bsp_pcpu.pc_dynamic;
	__pcpu[0].pc_acpi_id = temp_bsp_pcpu.pc_acpi_id;

	
	pmap_init_pat();

	
	if (pmap_pcid_enabled) {
		for (i = 0; i < MAXCPU; i++) {
			kernel_pmap->pm_pcids[i].pm_pcid = PMAP_PCID_KERN;
			kernel_pmap->pm_pcids[i].pm_gen = 1;
		}

		
		PCPU_SET(pcid_next, PMAP_PCID_KERN + 2);
		PCPU_SET(pcid_gen, 1);

		
		load_cr4(rcr4() | CR4_PCIDE);
	}
}


void pmap_init_pat(void)
{
	uint64_t pat_msr;
	u_long cr0, cr4;
	int i;

	
	if ((cpu_feature & CPUID_PAT) == 0)
		panic("no PAT??");

	
	for (i = 0; i < PAT_INDEX_SIZE; i++)
		pat_index[i] = -1;
	pat_index[PAT_WRITE_BACK] = 0;
	pat_index[PAT_WRITE_THROUGH] = 1;
	pat_index[PAT_UNCACHEABLE] = 3;
	pat_index[PAT_WRITE_COMBINING] = 6;
	pat_index[PAT_WRITE_PROTECTED] = 5;
	pat_index[PAT_UNCACHED] = 2;

	
	pat_msr = PAT_VALUE(0, PAT_WRITE_BACK) | PAT_VALUE(1, PAT_WRITE_THROUGH) | PAT_VALUE(2, PAT_UNCACHED) | PAT_VALUE(3, PAT_UNCACHEABLE) | PAT_VALUE(4, PAT_WRITE_BACK) | PAT_VALUE(5, PAT_WRITE_PROTECTED) | PAT_VALUE(6, PAT_WRITE_COMBINING) | PAT_VALUE(7, PAT_UNCACHEABLE);







	
	cr4 = rcr4();
	load_cr4(cr4 & ~CR4_PGE);

	
	cr0 = rcr0();
	load_cr0((cr0 & ~CR0_NW) | CR0_CD);

	
	wbinvd();
	invltlb();

	
	wrmsr(MSR_PAT, pat_msr);

	
	wbinvd();
	invltlb();

	
	load_cr0(cr0);
	load_cr4(cr4);
}


void pmap_page_init(vm_page_t m)
{

	TAILQ_INIT(&m->md.pv_list);
	m->md.pat_mode = PAT_WRITE_BACK;
}


static void pmap_init_pv_table(void)
{
	struct pmap_large_md_page *pvd;
	vm_size_t s;
	long start, end, highest, pv_npg;
	int domain, i, j, pages;

	
	CTASSERT((sizeof(*pvd) == 64));

	
	pmap_last_pa = vm_phys_segs[vm_phys_nsegs - 1].end;
	pv_npg = howmany(pmap_last_pa, NBPDR);
	s = (vm_size_t)pv_npg * sizeof(struct pmap_large_md_page);
	s = round_page(s);
	pv_table = (struct pmap_large_md_page *)kva_alloc(s);
	if (pv_table == NULL)
		panic("%s: kva_alloc failed\n", __func__);

	
	highest = -1;
	s = 0;
	for (i = 0; i < vm_phys_nsegs; i++) {
		end = vm_phys_segs[i].end / NBPDR;
		domain = vm_phys_segs[i].domain;

		if (highest >= end)
			continue;

		start = highest + 1;
		pvd = &pv_table[start];

		pages = end - start + 1;
		s = round_page(pages * sizeof(*pvd));
		highest = start + (s / sizeof(*pvd)) - 1;

		for (j = 0; j < s; j += PAGE_SIZE) {
			vm_page_t m = vm_page_alloc_domain(NULL, 0, domain, VM_ALLOC_NORMAL | VM_ALLOC_NOOBJ);
			if (m == NULL)
				panic("vm_page_alloc_domain failed for %lx\n", (vm_offset_t)pvd + j);
			pmap_qenter((vm_offset_t)pvd + j, &m, 1);
		}

		for (j = 0; j < s / sizeof(*pvd); j++) {
			rw_init_flags(&pvd->pv_lock, "pmap pv list", RW_NEW);
			TAILQ_INIT(&pvd->pv_page.pv_list);
			pvd->pv_page.pv_gen = 0;
			pvd->pv_page.pat_mode = 0;
			pvd->pv_invl_gen = 0;
			pvd++;
		}
	}
	pvd = &pv_dummy_large;
	rw_init_flags(&pvd->pv_lock, "pmap pv list dummy", RW_NEW);
	TAILQ_INIT(&pvd->pv_page.pv_list);
	pvd->pv_page.pv_gen = 0;
	pvd->pv_page.pat_mode = 0;
	pvd->pv_invl_gen = 0;
}

static void pmap_init_pv_table(void)
{
	vm_size_t s;
	long i, pv_npg;

	
	for (i = 0; i < NPV_LIST_LOCKS; i++)
		rw_init(&pv_list_locks[i], "pmap pv list");

	
	pv_npg = howmany(vm_phys_segs[vm_phys_nsegs - 1].end, NBPDR);

	
	s = (vm_size_t)pv_npg * sizeof(struct md_page);
	s = round_page(s);
	pv_table = (struct md_page *)kmem_malloc(s, M_WAITOK | M_ZERO);
	for (i = 0; i < pv_npg; i++)
		TAILQ_INIT(&pv_table[i].pv_list);
	TAILQ_INIT(&pv_dummy.pv_list);
}



void pmap_init(void)
{
	struct pmap_preinit_mapping *ppim;
	vm_page_t m, mpte;
	int error, i, ret, skz63;

	
	vm_page_blacklist_add(0, bootverbose);

	
	if (vm_guest == VM_GUEST_NO && cpu_vendor_id == CPU_VENDOR_INTEL && CPUID_TO_FAMILY(cpu_id) == 0x6 && CPUID_TO_MODEL(cpu_id) == 0x55) {
		
		skz63 = 1;
		TUNABLE_INT_FETCH("hw.skz63_enable", &skz63);
		if (skz63 != 0) {
			if (bootverbose)
				printf("SKZ63: skipping 4M RAM starting " "at physical 1G\n");
			for (i = 0; i < atop(0x400000); i++) {
				ret = vm_page_blacklist_add(0x40000000 + ptoa(i), FALSE);
				if (!ret && bootverbose)
					printf("page at %#lx already used\n", 0x40000000 + ptoa(i));
			}
		}
	}

	 
	PMAP_LOCK(kernel_pmap);
	for (i = 0; i < nkpt; i++) {
		mpte = PHYS_TO_VM_PAGE(KPTphys + (i << PAGE_SHIFT));
		KASSERT(mpte >= vm_page_array && mpte < &vm_page_array[vm_page_array_size], ("pmap_init: page table page is out of range"));

		mpte->pindex = pmap_pde_pindex(KERNBASE) + i;
		mpte->phys_addr = KPTphys + (i << PAGE_SHIFT);
		mpte->ref_count = 1;

		
		if (i << PDRSHIFT < KERNend && pmap_insert_pt_page(kernel_pmap, mpte, false))
			panic("pmap_init: pmap_insert_pt_page failed");
	}
	PMAP_UNLOCK(kernel_pmap);
	vm_wire_add(nkpt);

	
	if (vm_guest != VM_GUEST_NO && (cpu_feature & CPUID_SS) == 0 && (cpu_feature2 & (CPUID2_SSSE3 | CPUID2_SSE41 | CPUID2_AESNI | CPUID2_AVX | CPUID2_XSAVE)) == 0 && (amd_feature2 & (AMDID2_XOP | AMDID2_FMA4)) == 0)


		workaround_erratum383 = 1;

	
	TUNABLE_INT_FETCH("vm.pmap.pg_ps_enabled", &pg_ps_enabled);
	if (pg_ps_enabled) {
		KASSERT(MAXPAGESIZES > 1 && pagesizes[1] == 0, ("pmap_init: can't assign to pagesizes[1]"));
		pagesizes[1] = NBPDR;
	}

	
	for (i = 0; i < PMAP_MEMDOM; i++) {
		mtx_init(&pv_chunks[i].pvc_lock, "pmap pv chunk list", NULL, MTX_DEF);
		TAILQ_INIT(&pv_chunks[i].pvc_list);
	}
	pmap_init_pv_table();

	pmap_initialized = 1;
	for (i = 0; i < PMAP_PREINIT_MAPPING_COUNT; i++) {
		ppim = pmap_preinit_mapping + i;
		if (ppim->va == 0)
			continue;
		
		if (ppim->pa < dmaplimit && ppim->pa + ppim->sz <= dmaplimit) {
			(void)pmap_change_attr(PHYS_TO_DMAP(ppim->pa), ppim->sz, ppim->mode);
		}
		if (!bootverbose)
			continue;
		printf("PPIM %u: PA=%#lx, VA=%#lx, size=%#lx, mode=%#x\n", i, ppim->pa, ppim->va, ppim->sz, ppim->mode);
	}

	mtx_init(&qframe_mtx, "qfrmlk", NULL, MTX_SPIN);
	error = vmem_alloc(kernel_arena, PAGE_SIZE, M_BESTFIT | M_WAITOK, (vmem_addr_t *)&qframe);
	if (error != 0)
		panic("qframe allocation failed");

	lm_ents = 8;
	TUNABLE_INT_FETCH("vm.pmap.large_map_pml4_entries", &lm_ents);
	if (lm_ents > LMEPML4I - LMSPML4I + 1)
		lm_ents = LMEPML4I - LMSPML4I + 1;
	if (bootverbose)
		printf("pmap: large map %u PML4 slots (%lu GB)\n", lm_ents, (u_long)lm_ents * (NBPML4 / 1024 / 1024 / 1024));
	if (lm_ents != 0) {
		large_vmem = vmem_create("large", LARGEMAP_MIN_ADDRESS, (vmem_size_t)lm_ents * NBPML4, PAGE_SIZE, 0, M_WAITOK);
		if (large_vmem == NULL) {
			printf("pmap: cannot create large map\n");
			lm_ents = 0;
		}
		for (i = 0; i < lm_ents; i++) {
			m = pmap_large_map_getptp_unlocked();
			kernel_pmap->pm_pml4[LMSPML4I + i] = X86_PG_V | X86_PG_RW | X86_PG_A | X86_PG_M | pg_nx | VM_PAGE_TO_PHYS(m);

		}
	}
}

SYSCTL_UINT(_vm_pmap, OID_AUTO, large_map_pml4_entries, CTLFLAG_RDTUN | CTLFLAG_NOFETCH, &lm_ents, 0, "Maximum number of PML4 entries for use by large map (tunable).  " "Each entry corresponds to 512GB of address space.");



static SYSCTL_NODE(_vm_pmap, OID_AUTO, pde, CTLFLAG_RD, 0, "2MB page mapping counters");

static u_long pmap_pde_demotions;
SYSCTL_ULONG(_vm_pmap_pde, OID_AUTO, demotions, CTLFLAG_RD, &pmap_pde_demotions, 0, "2MB page demotions");

static u_long pmap_pde_mappings;
SYSCTL_ULONG(_vm_pmap_pde, OID_AUTO, mappings, CTLFLAG_RD, &pmap_pde_mappings, 0, "2MB page mappings");

static u_long pmap_pde_p_failures;
SYSCTL_ULONG(_vm_pmap_pde, OID_AUTO, p_failures, CTLFLAG_RD, &pmap_pde_p_failures, 0, "2MB page promotion failures");

static u_long pmap_pde_promotions;
SYSCTL_ULONG(_vm_pmap_pde, OID_AUTO, promotions, CTLFLAG_RD, &pmap_pde_promotions, 0, "2MB page promotions");

static SYSCTL_NODE(_vm_pmap, OID_AUTO, pdpe, CTLFLAG_RD, 0, "1GB page mapping counters");

static u_long pmap_pdpe_demotions;
SYSCTL_ULONG(_vm_pmap_pdpe, OID_AUTO, demotions, CTLFLAG_RD, &pmap_pdpe_demotions, 0, "1GB page demotions");



static pt_entry_t pmap_swap_pat(pmap_t pmap, pt_entry_t entry)
{
	int x86_pat_bits = X86_PG_PTE_PAT | X86_PG_PDE_PAT;

	switch (pmap->pm_type) {
	case PT_X86:
	case PT_RVI:
		
		KASSERT((entry & x86_pat_bits) != x86_pat_bits, ("Invalid PAT bits in entry %#lx", entry));

		
		if ((entry & x86_pat_bits) != 0)
			entry ^= x86_pat_bits;
		break;
	case PT_EPT:
		
		break;
	default:
		panic("pmap_switch_pat_bits: bad pm_type %d", pmap->pm_type);
	}

	return (entry);
}

boolean_t pmap_is_valid_memattr(pmap_t pmap __unused, vm_memattr_t mode)
{

	return (mode >= 0 && mode < PAT_INDEX_SIZE && pat_index[(int)mode] >= 0);
}


int pmap_cache_bits(pmap_t pmap, int mode, boolean_t is_pde)
{
	int cache_bits, pat_flag, pat_idx;

	if (!pmap_is_valid_memattr(pmap, mode))
		panic("Unknown caching mode %d\n", mode);

	switch (pmap->pm_type) {
	case PT_X86:
	case PT_RVI:
		
		pat_flag = is_pde ? X86_PG_PDE_PAT : X86_PG_PTE_PAT;

		
		pat_idx = pat_index[mode];

		
		cache_bits = 0;
		if (pat_idx & 0x4)
			cache_bits |= pat_flag;
		if (pat_idx & 0x2)
			cache_bits |= PG_NC_PCD;
		if (pat_idx & 0x1)
			cache_bits |= PG_NC_PWT;
		break;

	case PT_EPT:
		cache_bits = EPT_PG_IGNORE_PAT | EPT_PG_MEMORY_TYPE(mode);
		break;

	default:
		panic("unsupported pmap type %d", pmap->pm_type);
	}

	return (cache_bits);
}

static int pmap_cache_mask(pmap_t pmap, boolean_t is_pde)
{
	int mask;

	switch (pmap->pm_type) {
	case PT_X86:
	case PT_RVI:
		mask = is_pde ? X86_PG_PDE_CACHE : X86_PG_PTE_CACHE;
		break;
	case PT_EPT:
		mask = EPT_PG_IGNORE_PAT | EPT_PG_MEMORY_TYPE(0x7);
		break;
	default:
		panic("pmap_cache_mask: invalid pm_type %d", pmap->pm_type);
	}

	return (mask);
}

static int pmap_pat_index(pmap_t pmap, pt_entry_t pte, bool is_pde)
{
	int pat_flag, pat_idx;

	pat_idx = 0;
	switch (pmap->pm_type) {
	case PT_X86:
	case PT_RVI:
		
		pat_flag = is_pde ? X86_PG_PDE_PAT : X86_PG_PTE_PAT;

		if ((pte & pat_flag) != 0)
			pat_idx |= 0x4;
		if ((pte & PG_NC_PCD) != 0)
			pat_idx |= 0x2;
		if ((pte & PG_NC_PWT) != 0)
			pat_idx |= 0x1;
		break;
	case PT_EPT:
		if ((pte & EPT_PG_IGNORE_PAT) != 0)
			panic("EPT PTE %#lx has no PAT memory type", pte);
		pat_idx = (pte & EPT_PG_MEMORY_TYPE(0x7)) >> 3;
		break;
	}

	
	if (pat_idx == 4)
		pat_idx = 0;
	if (pat_idx == 7)
		pat_idx = 3;

	return (pat_idx);
}

bool pmap_ps_enabled(pmap_t pmap)
{

	return (pg_ps_enabled && (pmap->pm_flags & PMAP_PDE_SUPERPAGE) != 0);
}

static void pmap_update_pde_store(pmap_t pmap, pd_entry_t *pde, pd_entry_t newpde)
{

	switch (pmap->pm_type) {
	case PT_X86:
		break;
	case PT_RVI:
	case PT_EPT:
		
		atomic_add_acq_long(&pmap->pm_eptgen, 1);
		break;
	default:
		panic("pmap_update_pde_store: bad pm_type %d", pmap->pm_type);
	}
	pde_store(pde, newpde);
}


static void pmap_update_pde_invalidate(pmap_t pmap, vm_offset_t va, pd_entry_t newpde)
{
	pt_entry_t PG_G;

	if (pmap_type_guest(pmap))
		return;

	KASSERT(pmap->pm_type == PT_X86, ("pmap_update_pde_invalidate: invalid type %d", pmap->pm_type));

	PG_G = pmap_global_bit(pmap);

	if ((newpde & PG_PS) == 0)
		
		invlpg(va);
	else if ((newpde & PG_G) == 0)
		
		invltlb();
	else {
		
		invltlb_glob();
	}
}





static __inline void pmap_invalidate_ept(pmap_t pmap)
{
	int ipinum;

	sched_pin();
	KASSERT(!CPU_ISSET(curcpu, &pmap->pm_active), ("pmap_invalidate_ept: absurd pm_active"));

	
	atomic_add_acq_long(&pmap->pm_eptgen, 1);

	
	ipinum = pmap->pm_flags & PMAP_NESTED_IPIMASK;
	ipi_selected(pmap->pm_active, ipinum);
	sched_unpin();
}

static cpuset_t pmap_invalidate_cpu_mask(pmap_t pmap)
{

	return (pmap == kernel_pmap ? all_cpus : pmap->pm_active);
}

static inline void pmap_invalidate_page_pcid(pmap_t pmap, vm_offset_t va, const bool invpcid_works1)

{
	struct invpcid_descr d;
	uint64_t kcr3, ucr3;
	uint32_t pcid;
	u_int cpuid, i;

	cpuid = PCPU_GET(cpuid);
	if (pmap == PCPU_GET(curpmap)) {
		if (pmap->pm_ucr3 != PMAP_NO_CR3) {
			
			critical_enter();
			pcid = pmap->pm_pcids[cpuid].pm_pcid;
			if (invpcid_works1) {
				d.pcid = pcid | PMAP_PCID_USER_PT;
				d.pad = 0;
				d.addr = va;
				invpcid(&d, INVPCID_ADDR);
			} else {
				kcr3 = pmap->pm_cr3 | pcid | CR3_PCID_SAVE;
				ucr3 = pmap->pm_ucr3 | pcid | PMAP_PCID_USER_PT | CR3_PCID_SAVE;
				pmap_pti_pcid_invlpg(ucr3, kcr3, va);
			}
			critical_exit();
		}
	} else pmap->pm_pcids[cpuid].pm_gen = 0;

	CPU_FOREACH(i) {
		if (cpuid != i)
			pmap->pm_pcids[i].pm_gen = 0;
	}

	
	atomic_thread_fence_seq_cst();
}

static void pmap_invalidate_page_pcid_invpcid(pmap_t pmap, vm_offset_t va)
{

	pmap_invalidate_page_pcid(pmap, va, true);
}

static void pmap_invalidate_page_pcid_noinvpcid(pmap_t pmap, vm_offset_t va)
{

	pmap_invalidate_page_pcid(pmap, va, false);
}

static void pmap_invalidate_page_nopcid(pmap_t pmap, vm_offset_t va)
{
}

DEFINE_IFUNC(static, void, pmap_invalidate_page_mode, (pmap_t, vm_offset_t))
{

	if (pmap_pcid_enabled)
		return (invpcid_works ? pmap_invalidate_page_pcid_invpcid :
		    pmap_invalidate_page_pcid_noinvpcid);
	return (pmap_invalidate_page_nopcid);
}

void pmap_invalidate_page(pmap_t pmap, vm_offset_t va)
{

	if (pmap_type_guest(pmap)) {
		pmap_invalidate_ept(pmap);
		return;
	}

	KASSERT(pmap->pm_type == PT_X86, ("pmap_invalidate_page: invalid type %d", pmap->pm_type));

	sched_pin();
	if (pmap == kernel_pmap) {
		invlpg(va);
	} else {
		if (pmap == PCPU_GET(curpmap))
			invlpg(va);
		pmap_invalidate_page_mode(pmap, va);
	}
	smp_masked_invlpg(pmap_invalidate_cpu_mask(pmap), va, pmap);
	sched_unpin();
}




static void pmap_invalidate_range_pcid(pmap_t pmap, vm_offset_t sva, vm_offset_t eva, const bool invpcid_works1)

{
	struct invpcid_descr d;
	uint64_t kcr3, ucr3;
	uint32_t pcid;
	u_int cpuid, i;

	cpuid = PCPU_GET(cpuid);
	if (pmap == PCPU_GET(curpmap)) {
		if (pmap->pm_ucr3 != PMAP_NO_CR3) {
			critical_enter();
			pcid = pmap->pm_pcids[cpuid].pm_pcid;
			if (invpcid_works1) {
				d.pcid = pcid | PMAP_PCID_USER_PT;
				d.pad = 0;
				d.addr = sva;
				for (; d.addr < eva; d.addr += PAGE_SIZE)
					invpcid(&d, INVPCID_ADDR);
			} else {
				kcr3 = pmap->pm_cr3 | pcid | CR3_PCID_SAVE;
				ucr3 = pmap->pm_ucr3 | pcid | PMAP_PCID_USER_PT | CR3_PCID_SAVE;
				pmap_pti_pcid_invlrng(ucr3, kcr3, sva, eva);
			}
			critical_exit();
		}
	} else pmap->pm_pcids[cpuid].pm_gen = 0;

	CPU_FOREACH(i) {
		if (cpuid != i)
			pmap->pm_pcids[i].pm_gen = 0;
	}
	
	atomic_thread_fence_seq_cst();
}

static void pmap_invalidate_range_pcid_invpcid(pmap_t pmap, vm_offset_t sva, vm_offset_t eva)

{

	pmap_invalidate_range_pcid(pmap, sva, eva, true);
}

static void pmap_invalidate_range_pcid_noinvpcid(pmap_t pmap, vm_offset_t sva, vm_offset_t eva)

{

	pmap_invalidate_range_pcid(pmap, sva, eva, false);
}

static void pmap_invalidate_range_nopcid(pmap_t pmap, vm_offset_t sva, vm_offset_t eva)
{
}

DEFINE_IFUNC(static, void, pmap_invalidate_range_mode, (pmap_t, vm_offset_t, vm_offset_t))
{

	if (pmap_pcid_enabled)
		return (invpcid_works ? pmap_invalidate_range_pcid_invpcid :
		    pmap_invalidate_range_pcid_noinvpcid);
	return (pmap_invalidate_range_nopcid);
}

void pmap_invalidate_range(pmap_t pmap, vm_offset_t sva, vm_offset_t eva)
{
	vm_offset_t addr;

	if (eva - sva >= PMAP_INVLPG_THRESHOLD) {
		pmap_invalidate_all(pmap);
		return;
	}

	if (pmap_type_guest(pmap)) {
		pmap_invalidate_ept(pmap);
		return;
	}

	KASSERT(pmap->pm_type == PT_X86, ("pmap_invalidate_range: invalid type %d", pmap->pm_type));

	sched_pin();
	if (pmap == kernel_pmap) {
		for (addr = sva; addr < eva; addr += PAGE_SIZE)
			invlpg(addr);
	} else {
		if (pmap == PCPU_GET(curpmap)) {
			for (addr = sva; addr < eva; addr += PAGE_SIZE)
				invlpg(addr);
		}
		pmap_invalidate_range_mode(pmap, sva, eva);
	}
	smp_masked_invlpg_range(pmap_invalidate_cpu_mask(pmap), sva, eva, pmap);
	sched_unpin();
}

static inline void pmap_invalidate_all_pcid(pmap_t pmap, bool invpcid_works1)
{
	struct invpcid_descr d;
	uint64_t kcr3, ucr3;
	uint32_t pcid;
	u_int cpuid, i;

	if (pmap == kernel_pmap) {
		if (invpcid_works1) {
			bzero(&d, sizeof(d));
			invpcid(&d, INVPCID_CTXGLOB);
		} else {
			invltlb_glob();
		}
	} else {
		cpuid = PCPU_GET(cpuid);
		if (pmap == PCPU_GET(curpmap)) {
			critical_enter();
			pcid = pmap->pm_pcids[cpuid].pm_pcid;
			if (invpcid_works1) {
				d.pcid = pcid;
				d.pad = 0;
				d.addr = 0;
				invpcid(&d, INVPCID_CTX);
				if (pmap->pm_ucr3 != PMAP_NO_CR3) {
					d.pcid |= PMAP_PCID_USER_PT;
					invpcid(&d, INVPCID_CTX);
				}
			} else {
				kcr3 = pmap->pm_cr3 | pcid;
				ucr3 = pmap->pm_ucr3;
				if (ucr3 != PMAP_NO_CR3) {
					ucr3 |= pcid | PMAP_PCID_USER_PT;
					pmap_pti_pcid_invalidate(ucr3, kcr3);
				} else {
					load_cr3(kcr3);
				}
			}
			critical_exit();
		} else pmap->pm_pcids[cpuid].pm_gen = 0;
		CPU_FOREACH(i) {
			if (cpuid != i)
				pmap->pm_pcids[i].pm_gen = 0;
		}
	}
	
	atomic_thread_fence_seq_cst();
}

static void pmap_invalidate_all_pcid_invpcid(pmap_t pmap)
{

	pmap_invalidate_all_pcid(pmap, true);
}

static void pmap_invalidate_all_pcid_noinvpcid(pmap_t pmap)
{

	pmap_invalidate_all_pcid(pmap, false);
}

static void pmap_invalidate_all_nopcid(pmap_t pmap)
{

	if (pmap == kernel_pmap)
		invltlb_glob();
	else if (pmap == PCPU_GET(curpmap))
		invltlb();
}

DEFINE_IFUNC(static, void, pmap_invalidate_all_mode, (pmap_t))
{

	if (pmap_pcid_enabled)
		return (invpcid_works ? pmap_invalidate_all_pcid_invpcid :
		    pmap_invalidate_all_pcid_noinvpcid);
	return (pmap_invalidate_all_nopcid);
}

void pmap_invalidate_all(pmap_t pmap)
{

	if (pmap_type_guest(pmap)) {
		pmap_invalidate_ept(pmap);
		return;
	}

	KASSERT(pmap->pm_type == PT_X86, ("pmap_invalidate_all: invalid type %d", pmap->pm_type));

	sched_pin();
	pmap_invalidate_all_mode(pmap);
	smp_masked_invltlb(pmap_invalidate_cpu_mask(pmap), pmap);
	sched_unpin();
}

void pmap_invalidate_cache(void)
{

	sched_pin();
	wbinvd();
	smp_cache_flush();
	sched_unpin();
}

struct pde_action {
	cpuset_t invalidate;	
	pmap_t pmap;
	vm_offset_t va;
	pd_entry_t *pde;
	pd_entry_t newpde;
	u_int store;		
};

static void pmap_update_pde_action(void *arg)
{
	struct pde_action *act = arg;

	if (act->store == PCPU_GET(cpuid))
		pmap_update_pde_store(act->pmap, act->pde, act->newpde);
}

static void pmap_update_pde_teardown(void *arg)
{
	struct pde_action *act = arg;

	if (CPU_ISSET(PCPU_GET(cpuid), &act->invalidate))
		pmap_update_pde_invalidate(act->pmap, act->va, act->newpde);
}


static void pmap_update_pde(pmap_t pmap, vm_offset_t va, pd_entry_t *pde, pd_entry_t newpde)
{
	struct pde_action act;
	cpuset_t active, other_cpus;
	u_int cpuid;

	sched_pin();
	cpuid = PCPU_GET(cpuid);
	other_cpus = all_cpus;
	CPU_CLR(cpuid, &other_cpus);
	if (pmap == kernel_pmap || pmap_type_guest(pmap)) 
		active = all_cpus;
	else {
		active = pmap->pm_active;
	}
	if (CPU_OVERLAP(&active, &other_cpus)) { 
		act.store = cpuid;
		act.invalidate = active;
		act.va = va;
		act.pmap = pmap;
		act.pde = pde;
		act.newpde = newpde;
		CPU_SET(cpuid, &active);
		smp_rendezvous_cpus(active, smp_no_rendezvous_barrier, pmap_update_pde_action, pmap_update_pde_teardown, &act);

	} else {
		pmap_update_pde_store(pmap, pde, newpde);
		if (CPU_ISSET(cpuid, &active))
			pmap_update_pde_invalidate(pmap, va, newpde);
	}
	sched_unpin();
}


void pmap_invalidate_page(pmap_t pmap, vm_offset_t va)
{
	struct invpcid_descr d;
	uint64_t kcr3, ucr3;
	uint32_t pcid;

	if (pmap->pm_type == PT_RVI || pmap->pm_type == PT_EPT) {
		pmap->pm_eptgen++;
		return;
	}
	KASSERT(pmap->pm_type == PT_X86, ("pmap_invalidate_range: unknown type %d", pmap->pm_type));

	if (pmap == kernel_pmap || pmap == PCPU_GET(curpmap)) {
		invlpg(va);
		if (pmap == PCPU_GET(curpmap) && pmap_pcid_enabled && pmap->pm_ucr3 != PMAP_NO_CR3) {
			critical_enter();
			pcid = pmap->pm_pcids[0].pm_pcid;
			if (invpcid_works) {
				d.pcid = pcid | PMAP_PCID_USER_PT;
				d.pad = 0;
				d.addr = va;
				invpcid(&d, INVPCID_ADDR);
			} else {
				kcr3 = pmap->pm_cr3 | pcid | CR3_PCID_SAVE;
				ucr3 = pmap->pm_ucr3 | pcid | PMAP_PCID_USER_PT | CR3_PCID_SAVE;
				pmap_pti_pcid_invlpg(ucr3, kcr3, va);
			}
			critical_exit();
		}
	} else if (pmap_pcid_enabled)
		pmap->pm_pcids[0].pm_gen = 0;
}

void pmap_invalidate_range(pmap_t pmap, vm_offset_t sva, vm_offset_t eva)
{
	struct invpcid_descr d;
	vm_offset_t addr;
	uint64_t kcr3, ucr3;

	if (pmap->pm_type == PT_RVI || pmap->pm_type == PT_EPT) {
		pmap->pm_eptgen++;
		return;
	}
	KASSERT(pmap->pm_type == PT_X86, ("pmap_invalidate_range: unknown type %d", pmap->pm_type));

	if (pmap == kernel_pmap || pmap == PCPU_GET(curpmap)) {
		for (addr = sva; addr < eva; addr += PAGE_SIZE)
			invlpg(addr);
		if (pmap == PCPU_GET(curpmap) && pmap_pcid_enabled && pmap->pm_ucr3 != PMAP_NO_CR3) {
			critical_enter();
			if (invpcid_works) {
				d.pcid = pmap->pm_pcids[0].pm_pcid | PMAP_PCID_USER_PT;
				d.pad = 0;
				d.addr = sva;
				for (; d.addr < eva; d.addr += PAGE_SIZE)
					invpcid(&d, INVPCID_ADDR);
			} else {
				kcr3 = pmap->pm_cr3 | pmap->pm_pcids[0]. pm_pcid | CR3_PCID_SAVE;
				ucr3 = pmap->pm_ucr3 | pmap->pm_pcids[0]. pm_pcid | PMAP_PCID_USER_PT | CR3_PCID_SAVE;
				pmap_pti_pcid_invlrng(ucr3, kcr3, sva, eva);
			}
			critical_exit();
		}
	} else if (pmap_pcid_enabled) {
		pmap->pm_pcids[0].pm_gen = 0;
	}
}

void pmap_invalidate_all(pmap_t pmap)
{
	struct invpcid_descr d;
	uint64_t kcr3, ucr3;

	if (pmap->pm_type == PT_RVI || pmap->pm_type == PT_EPT) {
		pmap->pm_eptgen++;
		return;
	}
	KASSERT(pmap->pm_type == PT_X86, ("pmap_invalidate_all: unknown type %d", pmap->pm_type));

	if (pmap == kernel_pmap) {
		if (pmap_pcid_enabled && invpcid_works) {
			bzero(&d, sizeof(d));
			invpcid(&d, INVPCID_CTXGLOB);
		} else {
			invltlb_glob();
		}
	} else if (pmap == PCPU_GET(curpmap)) {
		if (pmap_pcid_enabled) {
			critical_enter();
			if (invpcid_works) {
				d.pcid = pmap->pm_pcids[0].pm_pcid;
				d.pad = 0;
				d.addr = 0;
				invpcid(&d, INVPCID_CTX);
				if (pmap->pm_ucr3 != PMAP_NO_CR3) {
					d.pcid |= PMAP_PCID_USER_PT;
					invpcid(&d, INVPCID_CTX);
				}
			} else {
				kcr3 = pmap->pm_cr3 | pmap->pm_pcids[0].pm_pcid;
				if (pmap->pm_ucr3 != PMAP_NO_CR3) {
					ucr3 = pmap->pm_ucr3 | pmap->pm_pcids[ 0].pm_pcid | PMAP_PCID_USER_PT;
					pmap_pti_pcid_invalidate(ucr3, kcr3);
				} else load_cr3(kcr3);
			}
			critical_exit();
		} else {
			invltlb();
		}
	} else if (pmap_pcid_enabled) {
		pmap->pm_pcids[0].pm_gen = 0;
	}
}

PMAP_INLINE void pmap_invalidate_cache(void)
{

	wbinvd();
}

static void pmap_update_pde(pmap_t pmap, vm_offset_t va, pd_entry_t *pde, pd_entry_t newpde)
{

	pmap_update_pde_store(pmap, pde, newpde);
	if (pmap == kernel_pmap || pmap == PCPU_GET(curpmap))
		pmap_update_pde_invalidate(pmap, va, newpde);
	else pmap->pm_pcids[0].pm_gen = 0;
}


static void pmap_invalidate_pde_page(pmap_t pmap, vm_offset_t va, pd_entry_t pde)
{

	
	if ((pde & PG_PROMOTED) != 0)
		pmap_invalidate_range(pmap, va, va + NBPDR - 1);
	else pmap_invalidate_page(pmap, va);
}

DEFINE_IFUNC(, void, pmap_invalidate_cache_range, (vm_offset_t sva, vm_offset_t eva))
{

	if ((cpu_feature & CPUID_SS) != 0)
		return (pmap_invalidate_cache_range_selfsnoop);
	if ((cpu_feature & CPUID_CLFSH) != 0)
		return (pmap_force_invalidate_cache_range);
	return (pmap_invalidate_cache_range_all);
}



static void pmap_invalidate_cache_range_check_align(vm_offset_t sva, vm_offset_t eva)
{

	KASSERT((sva & PAGE_MASK) == 0, ("pmap_invalidate_cache_range: sva not page-aligned"));
	KASSERT((eva & PAGE_MASK) == 0, ("pmap_invalidate_cache_range: eva not page-aligned"));
}

static void pmap_invalidate_cache_range_selfsnoop(vm_offset_t sva, vm_offset_t eva)
{

	pmap_invalidate_cache_range_check_align(sva, eva);
}

void pmap_force_invalidate_cache_range(vm_offset_t sva, vm_offset_t eva)
{

	sva &= ~(vm_offset_t)(cpu_clflush_line_size - 1);

	
	if (pmap_kextract(sva) == lapic_paddr)
		return;

	if ((cpu_stdext_feature & CPUID_STDEXT_CLFLUSHOPT) != 0) {
		
		atomic_thread_fence_seq_cst();
		for (; sva < eva; sva += cpu_clflush_line_size)
			clflushopt(sva);
		atomic_thread_fence_seq_cst();
	} else {
		
		if (cpu_vendor_id != CPU_VENDOR_INTEL)
			mfence();
		for (; sva < eva; sva += cpu_clflush_line_size)
			clflush(sva);
		if (cpu_vendor_id != CPU_VENDOR_INTEL)
			mfence();
	}
}

static void pmap_invalidate_cache_range_all(vm_offset_t sva, vm_offset_t eva)
{

	pmap_invalidate_cache_range_check_align(sva, eva);
	pmap_invalidate_cache();
}


void pmap_invalidate_cache_pages(vm_page_t *pages, int count)
{
	vm_offset_t daddr, eva;
	int i;
	bool useclflushopt;

	useclflushopt = (cpu_stdext_feature & CPUID_STDEXT_CLFLUSHOPT) != 0;
	if (count >= PMAP_CLFLUSH_THRESHOLD / PAGE_SIZE || ((cpu_feature & CPUID_CLFSH) == 0 && !useclflushopt))
		pmap_invalidate_cache();
	else {
		if (useclflushopt)
			atomic_thread_fence_seq_cst();
		else if (cpu_vendor_id != CPU_VENDOR_INTEL)
			mfence();
		for (i = 0; i < count; i++) {
			daddr = PHYS_TO_DMAP(VM_PAGE_TO_PHYS(pages[i]));
			eva = daddr + PAGE_SIZE;
			for (; daddr < eva; daddr += cpu_clflush_line_size) {
				if (useclflushopt)
					clflushopt(daddr);
				else clflush(daddr);
			}
		}
		if (useclflushopt)
			atomic_thread_fence_seq_cst();
		else if (cpu_vendor_id != CPU_VENDOR_INTEL)
			mfence();
	}
}

void pmap_flush_cache_range(vm_offset_t sva, vm_offset_t eva)
{

	pmap_invalidate_cache_range_check_align(sva, eva);

	if ((cpu_stdext_feature & CPUID_STDEXT_CLWB) == 0) {
		pmap_force_invalidate_cache_range(sva, eva);
		return;
	}

	
	if (pmap_kextract(sva) == lapic_paddr)
		return;

	atomic_thread_fence_seq_cst();
	for (; sva < eva; sva += cpu_clflush_line_size)
		clwb(sva);
	atomic_thread_fence_seq_cst();
}

void pmap_flush_cache_phys_range(vm_paddr_t spa, vm_paddr_t epa, vm_memattr_t mattr)
{
	pt_entry_t *pte;
	vm_offset_t vaddr;
	int error, pte_bits;

	KASSERT((spa & PAGE_MASK) == 0, ("pmap_flush_cache_phys_range: spa not page-aligned"));
	KASSERT((epa & PAGE_MASK) == 0, ("pmap_flush_cache_phys_range: epa not page-aligned"));

	if (spa < dmaplimit) {
		pmap_flush_cache_range(PHYS_TO_DMAP(spa), PHYS_TO_DMAP(MIN( dmaplimit, epa)));
		if (dmaplimit >= epa)
			return;
		spa = dmaplimit;
	}

	pte_bits = pmap_cache_bits(kernel_pmap, mattr, 0) | X86_PG_RW | X86_PG_V;
	error = vmem_alloc(kernel_arena, PAGE_SIZE, M_BESTFIT | M_WAITOK, &vaddr);
	KASSERT(error == 0, ("vmem_alloc failed: %d", error));
	pte = vtopte(vaddr);
	for (; spa < epa; spa += PAGE_SIZE) {
		sched_pin();
		pte_store(pte, spa | pte_bits);
		invlpg(vaddr);
		
		pmap_flush_cache_range(vaddr, vaddr + PAGE_SIZE);
		sched_unpin();
	}
	vmem_free(kernel_arena, vaddr, PAGE_SIZE);
}


vm_paddr_t  pmap_extract(pmap_t pmap, vm_offset_t va)
{
	pdp_entry_t *pdpe;
	pd_entry_t *pde;
	pt_entry_t *pte, PG_V;
	vm_paddr_t pa;

	pa = 0;
	PG_V = pmap_valid_bit(pmap);
	PMAP_LOCK(pmap);
	pdpe = pmap_pdpe(pmap, va);
	if (pdpe != NULL && (*pdpe & PG_V) != 0) {
		if ((*pdpe & PG_PS) != 0)
			pa = (*pdpe & PG_PS_FRAME) | (va & PDPMASK);
		else {
			pde = pmap_pdpe_to_pde(pdpe, va);
			if ((*pde & PG_V) != 0) {
				if ((*pde & PG_PS) != 0) {
					pa = (*pde & PG_PS_FRAME) | (va & PDRMASK);
				} else {
					pte = pmap_pde_to_pte(pde, va);
					pa = (*pte & PG_FRAME) | (va & PAGE_MASK);
				}
			}
		}
	}
	PMAP_UNLOCK(pmap);
	return (pa);
}


vm_page_t pmap_extract_and_hold(pmap_t pmap, vm_offset_t va, vm_prot_t prot)
{
	pd_entry_t pde, *pdep;
	pt_entry_t pte, PG_RW, PG_V;
	vm_page_t m;

	m = NULL;
	PG_RW = pmap_rw_bit(pmap);
	PG_V = pmap_valid_bit(pmap);

	PMAP_LOCK(pmap);
	pdep = pmap_pde(pmap, va);
	if (pdep != NULL && (pde = *pdep)) {
		if (pde & PG_PS) {
			if ((pde & PG_RW) != 0 || (prot & VM_PROT_WRITE) == 0)
				m = PHYS_TO_VM_PAGE((pde & PG_PS_FRAME) | (va & PDRMASK));
		} else {
			pte = *pmap_pde_to_pte(pdep, va);
			if ((pte & PG_V) != 0 && ((pte & PG_RW) != 0 || (prot & VM_PROT_WRITE) == 0))
				m = PHYS_TO_VM_PAGE(pte & PG_FRAME);
		}
		if (m != NULL && !vm_page_wire_mapped(m))
			m = NULL;
	}
	PMAP_UNLOCK(pmap);
	return (m);
}

vm_paddr_t pmap_kextract(vm_offset_t va)
{
	pd_entry_t pde;
	vm_paddr_t pa;

	if (va >= DMAP_MIN_ADDRESS && va < DMAP_MAX_ADDRESS) {
		pa = DMAP_TO_PHYS(va);
	} else if (PMAP_ADDRESS_IN_LARGEMAP(va)) {
		pa = pmap_large_map_kextract(va);
	} else {
		pde = *vtopde(va);
		if (pde & PG_PS) {
			pa = (pde & PG_PS_FRAME) | (va & PDRMASK);
		} else {
			
			pa = *pmap_pde_to_pte(&pde, va);
			pa = (pa & PG_FRAME) | (va & PAGE_MASK);
		}
	}
	return (pa);
}




PMAP_INLINE void  pmap_kenter(vm_offset_t va, vm_paddr_t pa)
{
	pt_entry_t *pte;

	pte = vtopte(va);
	pte_store(pte, pa | X86_PG_RW | X86_PG_V | pg_g | pg_nx);
}

static __inline void pmap_kenter_attr(vm_offset_t va, vm_paddr_t pa, int mode)
{
	pt_entry_t *pte;
	int cache_bits;

	pte = vtopte(va);
	cache_bits = pmap_cache_bits(kernel_pmap, mode, 0);
	pte_store(pte, pa | X86_PG_RW | X86_PG_V | pg_g | pg_nx | cache_bits);
}


PMAP_INLINE void pmap_kremove(vm_offset_t va)
{
	pt_entry_t *pte;

	pte = vtopte(va);
	pte_clear(pte);
}


vm_offset_t pmap_map(vm_offset_t *virt, vm_paddr_t start, vm_paddr_t end, int prot)
{
	return PHYS_TO_DMAP(start);
}



void pmap_qenter(vm_offset_t sva, vm_page_t *ma, int count)
{
	pt_entry_t *endpte, oldpte, pa, *pte;
	vm_page_t m;
	int cache_bits;

	oldpte = 0;
	pte = vtopte(sva);
	endpte = pte + count;
	while (pte < endpte) {
		m = *ma++;
		cache_bits = pmap_cache_bits(kernel_pmap, m->md.pat_mode, 0);
		pa = VM_PAGE_TO_PHYS(m) | cache_bits;
		if ((*pte & (PG_FRAME | X86_PG_PTE_CACHE)) != pa) {
			oldpte |= *pte;
			pte_store(pte, pa | pg_g | pg_nx | X86_PG_RW | X86_PG_V);
		}
		pte++;
	}
	if (__predict_false((oldpte & X86_PG_V) != 0))
		pmap_invalidate_range(kernel_pmap, sva, sva + count * PAGE_SIZE);
}


void pmap_qremove(vm_offset_t sva, int count)
{
	vm_offset_t va;

	va = sva;
	while (count-- > 0) {
		KASSERT(va >= VM_MIN_KERNEL_ADDRESS, ("usermode va %lx", va));
		pmap_kremove(va);
		va += PAGE_SIZE;
	}
	pmap_invalidate_range(kernel_pmap, sva, va);
}



static __inline void pmap_add_delayed_free_list(vm_page_t m, struct spglist *free, boolean_t set_PG_ZERO)

{

	if (set_PG_ZERO)
		m->flags |= PG_ZERO;
	else m->flags &= ~PG_ZERO;
	SLIST_INSERT_HEAD(free, m, plinks.s.ss);
}
	

static __inline int pmap_insert_pt_page(pmap_t pmap, vm_page_t mpte, bool promoted)
{

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	mpte->valid = promoted ? VM_PAGE_BITS_ALL : 0;
	return (vm_radix_insert(&pmap->pm_root, mpte));
}


static __inline vm_page_t pmap_remove_pt_page(pmap_t pmap, vm_offset_t va)
{

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	return (vm_radix_remove(&pmap->pm_root, pmap_pde_pindex(va)));
}


static inline boolean_t pmap_unwire_ptp(pmap_t pmap, vm_offset_t va, vm_page_t m, struct spglist *free)
{

	--m->ref_count;
	if (m->ref_count == 0) {
		_pmap_unwire_ptp(pmap, va, m, free);
		return (TRUE);
	} else return (FALSE);
}

static void _pmap_unwire_ptp(pmap_t pmap, vm_offset_t va, vm_page_t m, struct spglist *free)
{

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	
	if (m->pindex >= (NUPDE + NUPDPE)) {
		
		pml4_entry_t *pml4;
		pml4 = pmap_pml4e(pmap, va);
		*pml4 = 0;
		if (pmap->pm_pml4u != NULL && va <= VM_MAXUSER_ADDRESS) {
			pml4 = &pmap->pm_pml4u[pmap_pml4e_index(va)];
			*pml4 = 0;
		}
	} else if (m->pindex >= NUPDE) {
		
		pdp_entry_t *pdp;
		pdp = pmap_pdpe(pmap, va);
		*pdp = 0;
	} else {
		
		pd_entry_t *pd;
		pd = pmap_pde(pmap, va);
		*pd = 0;
	}
	pmap_resident_count_dec(pmap, 1);
	if (m->pindex < NUPDE) {
		
		vm_page_t pdpg;

		pdpg = PHYS_TO_VM_PAGE(*pmap_pdpe(pmap, va) & PG_FRAME);
		pmap_unwire_ptp(pmap, va, pdpg, free);
	}
	if (m->pindex >= NUPDE && m->pindex < (NUPDE + NUPDPE)) {
		
		vm_page_t pdppg;

		pdppg = PHYS_TO_VM_PAGE(*pmap_pml4e(pmap, va) & PG_FRAME);
		pmap_unwire_ptp(pmap, va, pdppg, free);
	}

	
	pmap_add_delayed_free_list(m, free, TRUE);
}


static int pmap_unuse_pt(pmap_t pmap, vm_offset_t va, pd_entry_t ptepde, struct spglist *free)

{
	vm_page_t mpte;

	if (va >= VM_MAXUSER_ADDRESS)
		return (0);
	KASSERT(ptepde != 0, ("pmap_unuse_pt: ptepde != 0"));
	mpte = PHYS_TO_VM_PAGE(ptepde & PG_FRAME);
	return (pmap_unwire_ptp(pmap, va, mpte, free));
}

void pmap_pinit0(pmap_t pmap)
{
	struct proc *p;
	struct thread *td;
	int i;

	PMAP_LOCK_INIT(pmap);
	pmap->pm_pml4 = (pml4_entry_t *)PHYS_TO_DMAP(KPML4phys);
	pmap->pm_pml4u = NULL;
	pmap->pm_cr3 = KPML4phys;
	
	pmap->pm_ucr3 = PMAP_NO_CR3;
	pmap->pm_root.rt_root = 0;
	CPU_ZERO(&pmap->pm_active);
	TAILQ_INIT(&pmap->pm_pvchunk);
	bzero(&pmap->pm_stats, sizeof pmap->pm_stats);
	pmap->pm_flags = pmap_flags;
	CPU_FOREACH(i) {
		pmap->pm_pcids[i].pm_pcid = PMAP_PCID_KERN + 1;
		pmap->pm_pcids[i].pm_gen = 1;
	}
	pmap_activate_boot(pmap);
	td = curthread;
	if (pti) {
		p = td->td_proc;
		PROC_LOCK(p);
		p->p_md.md_flags |= P_MD_KPTI;
		PROC_UNLOCK(p);
	}
	pmap_thread_init_invl_gen(td);

	if ((cpu_stdext_feature2 & CPUID_STDEXT2_PKU) != 0) {
		pmap_pkru_ranges_zone = uma_zcreate("pkru ranges", sizeof(struct pmap_pkru_range), NULL, NULL, NULL, NULL, UMA_ALIGN_PTR, 0);

	}
}

void pmap_pinit_pml4(vm_page_t pml4pg)
{
	pml4_entry_t *pm_pml4;
	int i;

	pm_pml4 = (pml4_entry_t *)PHYS_TO_DMAP(VM_PAGE_TO_PHYS(pml4pg));

	
	for (i = 0; i < NKPML4E; i++) {
		pm_pml4[KPML4BASE + i] = (KPDPphys + ptoa(i)) | X86_PG_RW | X86_PG_V;
	}
	for (i = 0; i < ndmpdpphys; i++) {
		pm_pml4[DMPML4I + i] = (DMPDPphys + ptoa(i)) | X86_PG_RW | X86_PG_V;
	}

	
	pm_pml4[PML4PML4I] = VM_PAGE_TO_PHYS(pml4pg) | X86_PG_V | X86_PG_RW | X86_PG_A | X86_PG_M;

	
	for (i = 0; i < lm_ents; i++)
		pm_pml4[LMSPML4I + i] = kernel_pmap->pm_pml4[LMSPML4I + i];
}

static void pmap_pinit_pml4_pti(vm_page_t pml4pg)
{
	pml4_entry_t *pm_pml4;
	int i;

	pm_pml4 = (pml4_entry_t *)PHYS_TO_DMAP(VM_PAGE_TO_PHYS(pml4pg));
	for (i = 0; i < NPML4EPG; i++)
		pm_pml4[i] = pti_pml4[i];
}


int pmap_pinit_type(pmap_t pmap, enum pmap_type pm_type, int flags)
{
	vm_page_t pml4pg, pml4pgu;
	vm_paddr_t pml4phys;
	int i;

	
	pml4pg = vm_page_alloc(NULL, 0, VM_ALLOC_NORMAL | VM_ALLOC_NOOBJ | VM_ALLOC_WIRED | VM_ALLOC_ZERO | VM_ALLOC_WAITOK);

	pml4phys = VM_PAGE_TO_PHYS(pml4pg);
	pmap->pm_pml4 = (pml4_entry_t *)PHYS_TO_DMAP(pml4phys);
	CPU_FOREACH(i) {
		pmap->pm_pcids[i].pm_pcid = PMAP_PCID_NONE;
		pmap->pm_pcids[i].pm_gen = 0;
	}
	pmap->pm_cr3 = PMAP_NO_CR3;	
	pmap->pm_ucr3 = PMAP_NO_CR3;
	pmap->pm_pml4u = NULL;

	pmap->pm_type = pm_type;
	if ((pml4pg->flags & PG_ZERO) == 0)
		pagezero(pmap->pm_pml4);

	
	if (pm_type == PT_X86) {
		pmap->pm_cr3 = pml4phys;
		pmap_pinit_pml4(pml4pg);
		if ((curproc->p_md.md_flags & P_MD_KPTI) != 0) {
			pml4pgu = vm_page_alloc(NULL, 0, VM_ALLOC_NORMAL | VM_ALLOC_NOOBJ | VM_ALLOC_WIRED | VM_ALLOC_WAITOK);
			pmap->pm_pml4u = (pml4_entry_t *)PHYS_TO_DMAP( VM_PAGE_TO_PHYS(pml4pgu));
			pmap_pinit_pml4_pti(pml4pgu);
			pmap->pm_ucr3 = VM_PAGE_TO_PHYS(pml4pgu);
		}
		if ((cpu_stdext_feature2 & CPUID_STDEXT2_PKU) != 0) {
			rangeset_init(&pmap->pm_pkru, pkru_dup_range, pkru_free_range, pmap, M_NOWAIT);
		}
	}

	pmap->pm_root.rt_root = 0;
	CPU_ZERO(&pmap->pm_active);
	TAILQ_INIT(&pmap->pm_pvchunk);
	bzero(&pmap->pm_stats, sizeof pmap->pm_stats);
	pmap->pm_flags = flags;
	pmap->pm_eptgen = 0;

	return (1);
}

int pmap_pinit(pmap_t pmap)
{

	return (pmap_pinit_type(pmap, PT_X86, pmap_flags));
}


static vm_page_t _pmap_allocpte(pmap_t pmap, vm_pindex_t ptepindex, struct rwlock **lockp)
{
	vm_page_t m, pdppg, pdpg;
	pt_entry_t PG_A, PG_M, PG_RW, PG_V;

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);

	PG_A = pmap_accessed_bit(pmap);
	PG_M = pmap_modified_bit(pmap);
	PG_V = pmap_valid_bit(pmap);
	PG_RW = pmap_rw_bit(pmap);

	
	if ((m = vm_page_alloc(NULL, ptepindex, VM_ALLOC_NOOBJ | VM_ALLOC_WIRED | VM_ALLOC_ZERO)) == NULL) {
		if (lockp != NULL) {
			RELEASE_PV_LIST_LOCK(lockp);
			PMAP_UNLOCK(pmap);
			PMAP_ASSERT_NOT_IN_DI();
			vm_wait(NULL);
			PMAP_LOCK(pmap);
		}

		
		return (NULL);
	}
	if ((m->flags & PG_ZERO) == 0)
		pmap_zero_page(m);

	

	if (ptepindex >= (NUPDE + NUPDPE)) {
		pml4_entry_t *pml4, *pml4u;
		vm_pindex_t pml4index;

		
		pml4index = ptepindex - (NUPDE + NUPDPE);
		pml4 = &pmap->pm_pml4[pml4index];
		*pml4 = VM_PAGE_TO_PHYS(m) | PG_U | PG_RW | PG_V | PG_A | PG_M;
		if (pmap->pm_pml4u != NULL && pml4index < NUPML4E) {
			
			if (pmap->pm_ucr3 != PMAP_NO_CR3)
				*pml4 |= pg_nx;

			pml4u = &pmap->pm_pml4u[pml4index];
			*pml4u = VM_PAGE_TO_PHYS(m) | PG_U | PG_RW | PG_V | PG_A | PG_M;
		}

	} else if (ptepindex >= NUPDE) {
		vm_pindex_t pml4index;
		vm_pindex_t pdpindex;
		pml4_entry_t *pml4;
		pdp_entry_t *pdp;

		
		pdpindex = ptepindex - NUPDE;
		pml4index = pdpindex >> NPML4EPGSHIFT;

		pml4 = &pmap->pm_pml4[pml4index];
		if ((*pml4 & PG_V) == 0) {
			
			if (_pmap_allocpte(pmap, NUPDE + NUPDPE + pml4index, lockp) == NULL) {
				vm_page_unwire_noq(m);
				vm_page_free_zero(m);
				return (NULL);
			}
		} else {
			
			pdppg = PHYS_TO_VM_PAGE(*pml4 & PG_FRAME);
			pdppg->ref_count++;
		}
		pdp = (pdp_entry_t *)PHYS_TO_DMAP(*pml4 & PG_FRAME);

		
		pdp = &pdp[pdpindex & ((1ul << NPDPEPGSHIFT) - 1)];
		*pdp = VM_PAGE_TO_PHYS(m) | PG_U | PG_RW | PG_V | PG_A | PG_M;

	} else {
		vm_pindex_t pml4index;
		vm_pindex_t pdpindex;
		pml4_entry_t *pml4;
		pdp_entry_t *pdp;
		pd_entry_t *pd;

		
		pdpindex = ptepindex >> NPDPEPGSHIFT;
		pml4index = pdpindex >> NPML4EPGSHIFT;

		
		pml4 = &pmap->pm_pml4[pml4index];
		if ((*pml4 & PG_V) == 0) {
			
			if (_pmap_allocpte(pmap, NUPDE + pdpindex, lockp) == NULL) {
				vm_page_unwire_noq(m);
				vm_page_free_zero(m);
				return (NULL);
			}
			pdp = (pdp_entry_t *)PHYS_TO_DMAP(*pml4 & PG_FRAME);
			pdp = &pdp[pdpindex & ((1ul << NPDPEPGSHIFT) - 1)];
		} else {
			pdp = (pdp_entry_t *)PHYS_TO_DMAP(*pml4 & PG_FRAME);
			pdp = &pdp[pdpindex & ((1ul << NPDPEPGSHIFT) - 1)];
			if ((*pdp & PG_V) == 0) {
				
				if (_pmap_allocpte(pmap, NUPDE + pdpindex, lockp) == NULL) {
					vm_page_unwire_noq(m);
					vm_page_free_zero(m);
					return (NULL);
				}
			} else {
				
				pdpg = PHYS_TO_VM_PAGE(*pdp & PG_FRAME);
				pdpg->ref_count++;
			}
		}
		pd = (pd_entry_t *)PHYS_TO_DMAP(*pdp & PG_FRAME);

		
		pd = &pd[ptepindex & ((1ul << NPDEPGSHIFT) - 1)];
		*pd = VM_PAGE_TO_PHYS(m) | PG_U | PG_RW | PG_V | PG_A | PG_M;
	}

	pmap_resident_count_inc(pmap, 1);

	return (m);
}

static vm_page_t pmap_allocpde(pmap_t pmap, vm_offset_t va, struct rwlock **lockp)
{
	vm_pindex_t pdpindex, ptepindex;
	pdp_entry_t *pdpe, PG_V;
	vm_page_t pdpg;

	PG_V = pmap_valid_bit(pmap);

retry:
	pdpe = pmap_pdpe(pmap, va);
	if (pdpe != NULL && (*pdpe & PG_V) != 0) {
		
		pdpg = PHYS_TO_VM_PAGE(*pdpe & PG_FRAME);
		pdpg->ref_count++;
	} else {
		
		ptepindex = pmap_pde_pindex(va);
		pdpindex = ptepindex >> NPDPEPGSHIFT;
		pdpg = _pmap_allocpte(pmap, NUPDE + pdpindex, lockp);
		if (pdpg == NULL && lockp != NULL)
			goto retry;
	}
	return (pdpg);
}

static vm_page_t pmap_allocpte(pmap_t pmap, vm_offset_t va, struct rwlock **lockp)
{
	vm_pindex_t ptepindex;
	pd_entry_t *pd, PG_V;
	vm_page_t m;

	PG_V = pmap_valid_bit(pmap);

	
	ptepindex = pmap_pde_pindex(va);
retry:
	
	pd = pmap_pde(pmap, va);

	
	if (pd != NULL && (*pd & (PG_PS | PG_V)) == (PG_PS | PG_V)) {
		if (!pmap_demote_pde_locked(pmap, pd, va, lockp)) {
			
			pd = NULL;
		}
	}

	
	if (pd != NULL && (*pd & PG_V) != 0) {
		m = PHYS_TO_VM_PAGE(*pd & PG_FRAME);
		m->ref_count++;
	} else {
		
		m = _pmap_allocpte(pmap, ptepindex, lockp);
		if (m == NULL && lockp != NULL)
			goto retry;
	}
	return (m);
}





void pmap_release(pmap_t pmap)
{
	vm_page_t m;
	int i;

	KASSERT(pmap->pm_stats.resident_count == 0, ("pmap_release: pmap resident count %ld != 0", pmap->pm_stats.resident_count));

	KASSERT(vm_radix_is_empty(&pmap->pm_root), ("pmap_release: pmap has reserved page table page(s)"));
	KASSERT(CPU_EMPTY(&pmap->pm_active), ("releasing active pmap %p", pmap));

	m = PHYS_TO_VM_PAGE(DMAP_TO_PHYS((vm_offset_t)pmap->pm_pml4));

	for (i = 0; i < NKPML4E; i++)	
		pmap->pm_pml4[KPML4BASE + i] = 0;
	for (i = 0; i < ndmpdpphys; i++)
		pmap->pm_pml4[DMPML4I + i] = 0;
	pmap->pm_pml4[PML4PML4I] = 0;	
	for (i = 0; i < lm_ents; i++)	
		pmap->pm_pml4[LMSPML4I + i] = 0;

	vm_page_unwire_noq(m);
	vm_page_free_zero(m);

	if (pmap->pm_pml4u != NULL) {
		m = PHYS_TO_VM_PAGE(DMAP_TO_PHYS((vm_offset_t)pmap->pm_pml4u));
		vm_page_unwire_noq(m);
		vm_page_free(m);
	}
	if (pmap->pm_type == PT_X86 && (cpu_stdext_feature2 & CPUID_STDEXT2_PKU) != 0)
		rangeset_fini(&pmap->pm_pkru);
}

static int kvm_size(SYSCTL_HANDLER_ARGS)
{
	unsigned long ksize = VM_MAX_KERNEL_ADDRESS - VM_MIN_KERNEL_ADDRESS;

	return sysctl_handle_long(oidp, &ksize, 0, req);
}
SYSCTL_PROC(_vm, OID_AUTO, kvm_size, CTLTYPE_LONG|CTLFLAG_RD,  0, 0, kvm_size, "LU", "Size of KVM");

static int kvm_free(SYSCTL_HANDLER_ARGS)
{
	unsigned long kfree = VM_MAX_KERNEL_ADDRESS - kernel_vm_end;

	return sysctl_handle_long(oidp, &kfree, 0, req);
}
SYSCTL_PROC(_vm, OID_AUTO, kvm_free, CTLTYPE_LONG|CTLFLAG_RD,  0, 0, kvm_free, "LU", "Amount of KVM free");


void pmap_page_array_startup(long pages)
{
	pdp_entry_t *pdpe;
	pd_entry_t *pde, newpdir;
	vm_offset_t va, start, end;
	vm_paddr_t pa;
	long pfn;
	int domain, i;

	vm_page_array_size = pages;

	start = VM_MIN_KERNEL_ADDRESS;
	end = start + pages * sizeof(struct vm_page);
	for (va = start; va < end; va += NBPDR) {
		pfn = first_page + (va - start) / sizeof(struct vm_page);
		domain = _vm_phys_domain(ptoa(pfn));
		pdpe = pmap_pdpe(kernel_pmap, va);
		if ((*pdpe & X86_PG_V) == 0) {
			pa = vm_phys_early_alloc(domain, PAGE_SIZE);
			dump_add_page(pa);
			pagezero((void *)PHYS_TO_DMAP(pa));
			*pdpe = (pdp_entry_t)(pa | X86_PG_V | X86_PG_RW | X86_PG_A | X86_PG_M);
		}
		pde = pmap_pdpe_to_pde(pdpe, va);
		if ((*pde & X86_PG_V) != 0)
			panic("Unexpected pde");
		pa = vm_phys_early_alloc(domain, NBPDR);
		for (i = 0; i < NPDEPG; i++)
			dump_add_page(pa + i * PAGE_SIZE);
		newpdir = (pd_entry_t)(pa | X86_PG_V | X86_PG_RW | X86_PG_A | X86_PG_M | PG_PS | pg_g | pg_nx);
		pde_store(pde, newpdir);
	}
	vm_page_array = (vm_page_t)start;
}


void pmap_growkernel(vm_offset_t addr)
{
	vm_paddr_t paddr;
	vm_page_t nkpg;
	pd_entry_t *pde, newpdir;
	pdp_entry_t *pdpe;

	mtx_assert(&kernel_map->system_mtx, MA_OWNED);

	
	if (KERNBASE < addr && addr <= KERNBASE + nkpt * NBPDR)
		return;

	addr = roundup2(addr, NBPDR);
	if (addr - 1 >= vm_map_max(kernel_map))
		addr = vm_map_max(kernel_map);
	while (kernel_vm_end < addr) {
		pdpe = pmap_pdpe(kernel_pmap, kernel_vm_end);
		if ((*pdpe & X86_PG_V) == 0) {
			
			nkpg = vm_page_alloc(NULL, kernel_vm_end >> PDPSHIFT, VM_ALLOC_INTERRUPT | VM_ALLOC_NOOBJ | VM_ALLOC_WIRED | VM_ALLOC_ZERO);

			if (nkpg == NULL)
				panic("pmap_growkernel: no memory to grow kernel");
			if ((nkpg->flags & PG_ZERO) == 0)
				pmap_zero_page(nkpg);
			paddr = VM_PAGE_TO_PHYS(nkpg);
			*pdpe = (pdp_entry_t)(paddr | X86_PG_V | X86_PG_RW | X86_PG_A | X86_PG_M);
			continue; 
		}
		pde = pmap_pdpe_to_pde(pdpe, kernel_vm_end);
		if ((*pde & X86_PG_V) != 0) {
			kernel_vm_end = (kernel_vm_end + NBPDR) & ~PDRMASK;
			if (kernel_vm_end - 1 >= vm_map_max(kernel_map)) {
				kernel_vm_end = vm_map_max(kernel_map);
				break;                       
			}
			continue;
		}

		nkpg = vm_page_alloc(NULL, pmap_pde_pindex(kernel_vm_end), VM_ALLOC_INTERRUPT | VM_ALLOC_NOOBJ | VM_ALLOC_WIRED | VM_ALLOC_ZERO);

		if (nkpg == NULL)
			panic("pmap_growkernel: no memory to grow kernel");
		if ((nkpg->flags & PG_ZERO) == 0)
			pmap_zero_page(nkpg);
		paddr = VM_PAGE_TO_PHYS(nkpg);
		newpdir = paddr | X86_PG_V | X86_PG_RW | X86_PG_A | X86_PG_M;
		pde_store(pde, newpdir);

		kernel_vm_end = (kernel_vm_end + NBPDR) & ~PDRMASK;
		if (kernel_vm_end - 1 >= vm_map_max(kernel_map)) {
			kernel_vm_end = vm_map_max(kernel_map);
			break;                       
		}
	}
}




CTASSERT(sizeof(struct pv_chunk) == PAGE_SIZE);
CTASSERT(_NPCM == 3);
CTASSERT(_NPCPV == 168);

static __inline struct pv_chunk * pv_to_chunk(pv_entry_t pv)
{

	return ((struct pv_chunk *)((uintptr_t)pv & ~(uintptr_t)PAGE_MASK));
}







static const uint64_t pc_freemask[_NPCM] = { PC_FREE0, PC_FREE1, PC_FREE2 };


static int pc_chunk_count, pc_chunk_allocs, pc_chunk_frees, pc_chunk_tryfail;

SYSCTL_INT(_vm_pmap, OID_AUTO, pc_chunk_count, CTLFLAG_RD, &pc_chunk_count, 0, "Current number of pv entry chunks");
SYSCTL_INT(_vm_pmap, OID_AUTO, pc_chunk_allocs, CTLFLAG_RD, &pc_chunk_allocs, 0, "Current number of pv entry chunks allocated");
SYSCTL_INT(_vm_pmap, OID_AUTO, pc_chunk_frees, CTLFLAG_RD, &pc_chunk_frees, 0, "Current number of pv entry chunks frees");
SYSCTL_INT(_vm_pmap, OID_AUTO, pc_chunk_tryfail, CTLFLAG_RD, &pc_chunk_tryfail, 0, "Number of times tried to get a chunk page but failed.");

static long pv_entry_frees, pv_entry_allocs, pv_entry_count;
static int pv_entry_spare;

SYSCTL_LONG(_vm_pmap, OID_AUTO, pv_entry_frees, CTLFLAG_RD, &pv_entry_frees, 0, "Current number of pv entry frees");
SYSCTL_LONG(_vm_pmap, OID_AUTO, pv_entry_allocs, CTLFLAG_RD, &pv_entry_allocs, 0, "Current number of pv entry allocs");
SYSCTL_LONG(_vm_pmap, OID_AUTO, pv_entry_count, CTLFLAG_RD, &pv_entry_count, 0, "Current number of pv entries");
SYSCTL_INT(_vm_pmap, OID_AUTO, pv_entry_spare, CTLFLAG_RD, &pv_entry_spare, 0, "Current number of spare pv entries");


static void reclaim_pv_chunk_leave_pmap(pmap_t pmap, pmap_t locked_pmap, bool start_di)
{

	if (pmap == NULL)
		return;
	pmap_invalidate_all(pmap);
	if (pmap != locked_pmap)
		PMAP_UNLOCK(pmap);
	if (start_di)
		pmap_delayed_invl_finish();
}


static vm_page_t reclaim_pv_chunk_domain(pmap_t locked_pmap, struct rwlock **lockp, int domain)
{
	struct pv_chunks_list *pvc;
	struct pv_chunk *pc, *pc_marker, *pc_marker_end;
	struct pv_chunk_header pc_marker_b, pc_marker_end_b;
	struct md_page *pvh;
	pd_entry_t *pde;
	pmap_t next_pmap, pmap;
	pt_entry_t *pte, tpte;
	pt_entry_t PG_G, PG_A, PG_M, PG_RW;
	pv_entry_t pv;
	vm_offset_t va;
	vm_page_t m, m_pc;
	struct spglist free;
	uint64_t inuse;
	int bit, field, freed;
	bool start_di;

	PMAP_LOCK_ASSERT(locked_pmap, MA_OWNED);
	KASSERT(lockp != NULL, ("reclaim_pv_chunk: lockp is NULL"));
	pmap = NULL;
	m_pc = NULL;
	PG_G = PG_A = PG_M = PG_RW = 0;
	SLIST_INIT(&free);
	bzero(&pc_marker_b, sizeof(pc_marker_b));
	bzero(&pc_marker_end_b, sizeof(pc_marker_end_b));
	pc_marker = (struct pv_chunk *)&pc_marker_b;
	pc_marker_end = (struct pv_chunk *)&pc_marker_end_b;

	
	start_di = pmap_not_in_di();

	pvc = &pv_chunks[domain];
	mtx_lock(&pvc->pvc_lock);
	pvc->active_reclaims++;
	TAILQ_INSERT_HEAD(&pvc->pvc_list, pc_marker, pc_lru);
	TAILQ_INSERT_TAIL(&pvc->pvc_list, pc_marker_end, pc_lru);
	while ((pc = TAILQ_NEXT(pc_marker, pc_lru)) != pc_marker_end && SLIST_EMPTY(&free)) {
		next_pmap = pc->pc_pmap;
		if (next_pmap == NULL) {
			
			goto next_chunk;
		}
		mtx_unlock(&pvc->pvc_lock);

		
		if (pmap != next_pmap) {
			reclaim_pv_chunk_leave_pmap(pmap, locked_pmap, start_di);
			pmap = next_pmap;
			
			if (pmap > locked_pmap) {
				RELEASE_PV_LIST_LOCK(lockp);
				PMAP_LOCK(pmap);
				if (start_di)
					pmap_delayed_invl_start();
				mtx_lock(&pvc->pvc_lock);
				continue;
			} else if (pmap != locked_pmap) {
				if (PMAP_TRYLOCK(pmap)) {
					if (start_di)
						pmap_delayed_invl_start();
					mtx_lock(&pvc->pvc_lock);
					continue;
				} else {
					pmap = NULL; 
					mtx_lock(&pvc->pvc_lock);
					pc = TAILQ_NEXT(pc_marker, pc_lru);
					if (pc == NULL || pc->pc_pmap != next_pmap)
						continue;
					goto next_chunk;
				}
			} else if (start_di)
				pmap_delayed_invl_start();
			PG_G = pmap_global_bit(pmap);
			PG_A = pmap_accessed_bit(pmap);
			PG_M = pmap_modified_bit(pmap);
			PG_RW = pmap_rw_bit(pmap);
		}

		
		freed = 0;
		for (field = 0; field < _NPCM; field++) {
			for (inuse = ~pc->pc_map[field] & pc_freemask[field];
			    inuse != 0; inuse &= ~(1UL << bit)) {
				bit = bsfq(inuse);
				pv = &pc->pc_pventry[field * 64 + bit];
				va = pv->pv_va;
				pde = pmap_pde(pmap, va);
				if ((*pde & PG_PS) != 0)
					continue;
				pte = pmap_pde_to_pte(pde, va);
				if ((*pte & PG_W) != 0)
					continue;
				tpte = pte_load_clear(pte);
				if ((tpte & PG_G) != 0)
					pmap_invalidate_page(pmap, va);
				m = PHYS_TO_VM_PAGE(tpte & PG_FRAME);
				if ((tpte & (PG_M | PG_RW)) == (PG_M | PG_RW))
					vm_page_dirty(m);
				if ((tpte & PG_A) != 0)
					vm_page_aflag_set(m, PGA_REFERENCED);
				CHANGE_PV_LIST_LOCK_TO_VM_PAGE(lockp, m);
				TAILQ_REMOVE(&m->md.pv_list, pv, pv_next);
				m->md.pv_gen++;
				if (TAILQ_EMPTY(&m->md.pv_list) && (m->flags & PG_FICTITIOUS) == 0) {
					pvh = pa_to_pvh(VM_PAGE_TO_PHYS(m));
					if (TAILQ_EMPTY(&pvh->pv_list)) {
						vm_page_aflag_clear(m, PGA_WRITEABLE);
					}
				}
				pmap_delayed_invl_page(m);
				pc->pc_map[field] |= 1UL << bit;
				pmap_unuse_pt(pmap, va, *pde, &free);
				freed++;
			}
		}
		if (freed == 0) {
			mtx_lock(&pvc->pvc_lock);
			goto next_chunk;
		}
		
		pmap_resident_count_dec(pmap, freed);
		PV_STAT(atomic_add_long(&pv_entry_frees, freed));
		PV_STAT(atomic_add_int(&pv_entry_spare, freed));
		PV_STAT(atomic_subtract_long(&pv_entry_count, freed));
		TAILQ_REMOVE(&pmap->pm_pvchunk, pc, pc_list);
		if (pc->pc_map[0] == PC_FREE0 && pc->pc_map[1] == PC_FREE1 && pc->pc_map[2] == PC_FREE2) {
			PV_STAT(atomic_subtract_int(&pv_entry_spare, _NPCPV));
			PV_STAT(atomic_subtract_int(&pc_chunk_count, 1));
			PV_STAT(atomic_add_int(&pc_chunk_frees, 1));
			
			m_pc = PHYS_TO_VM_PAGE(DMAP_TO_PHYS((vm_offset_t)pc));
			dump_drop_page(m_pc->phys_addr);
			mtx_lock(&pvc->pvc_lock);
			TAILQ_REMOVE(&pvc->pvc_list, pc, pc_lru);
			break;
		}
		TAILQ_INSERT_HEAD(&pmap->pm_pvchunk, pc, pc_list);
		mtx_lock(&pvc->pvc_lock);
		
		if (pmap == locked_pmap)
			break;
next_chunk:
		TAILQ_REMOVE(&pvc->pvc_list, pc_marker, pc_lru);
		TAILQ_INSERT_AFTER(&pvc->pvc_list, pc, pc_marker, pc_lru);
		if (pvc->active_reclaims == 1 && pmap != NULL) {
			
			while ((pc = TAILQ_FIRST(&pvc->pvc_list)) != pc_marker) {
				MPASS(pc->pc_pmap != NULL);
				TAILQ_REMOVE(&pvc->pvc_list, pc, pc_lru);
				TAILQ_INSERT_TAIL(&pvc->pvc_list, pc, pc_lru);
			}
		}
	}
	TAILQ_REMOVE(&pvc->pvc_list, pc_marker, pc_lru);
	TAILQ_REMOVE(&pvc->pvc_list, pc_marker_end, pc_lru);
	pvc->active_reclaims--;
	mtx_unlock(&pvc->pvc_lock);
	reclaim_pv_chunk_leave_pmap(pmap, locked_pmap, start_di);
	if (m_pc == NULL && !SLIST_EMPTY(&free)) {
		m_pc = SLIST_FIRST(&free);
		SLIST_REMOVE_HEAD(&free, plinks.s.ss);
		
		m_pc->ref_count = 1;
	}
	vm_page_free_pages_toq(&free, true);
	return (m_pc);
}

static vm_page_t reclaim_pv_chunk(pmap_t locked_pmap, struct rwlock **lockp)
{
	vm_page_t m;
	int i, domain;

	domain = PCPU_GET(domain);
	for (i = 0; i < vm_ndomains; i++) {
		m = reclaim_pv_chunk_domain(locked_pmap, lockp, domain);
		if (m != NULL)
			break;
		domain = (domain + 1) % vm_ndomains;
	}

	return (m);
}


static void free_pv_entry(pmap_t pmap, pv_entry_t pv)
{
	struct pv_chunk *pc;
	int idx, field, bit;

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	PV_STAT(atomic_add_long(&pv_entry_frees, 1));
	PV_STAT(atomic_add_int(&pv_entry_spare, 1));
	PV_STAT(atomic_subtract_long(&pv_entry_count, 1));
	pc = pv_to_chunk(pv);
	idx = pv - &pc->pc_pventry[0];
	field = idx / 64;
	bit = idx % 64;
	pc->pc_map[field] |= 1ul << bit;
	if (pc->pc_map[0] != PC_FREE0 || pc->pc_map[1] != PC_FREE1 || pc->pc_map[2] != PC_FREE2) {
		
		if (__predict_false(pc != TAILQ_FIRST(&pmap->pm_pvchunk))) {
			TAILQ_REMOVE(&pmap->pm_pvchunk, pc, pc_list);
			TAILQ_INSERT_HEAD(&pmap->pm_pvchunk, pc, pc_list);
		}
		return;
	}
	TAILQ_REMOVE(&pmap->pm_pvchunk, pc, pc_list);
	free_pv_chunk(pc);
}

static void free_pv_chunk_dequeued(struct pv_chunk *pc)
{
	vm_page_t m;

	PV_STAT(atomic_subtract_int(&pv_entry_spare, _NPCPV));
	PV_STAT(atomic_subtract_int(&pc_chunk_count, 1));
	PV_STAT(atomic_add_int(&pc_chunk_frees, 1));
	
	m = PHYS_TO_VM_PAGE(DMAP_TO_PHYS((vm_offset_t)pc));
	dump_drop_page(m->phys_addr);
	vm_page_unwire_noq(m);
	vm_page_free(m);
}

static void free_pv_chunk(struct pv_chunk *pc)
{
	struct pv_chunks_list *pvc;

	pvc = &pv_chunks[pc_to_domain(pc)];
	mtx_lock(&pvc->pvc_lock);
	TAILQ_REMOVE(&pvc->pvc_list, pc, pc_lru);
	mtx_unlock(&pvc->pvc_lock);
	free_pv_chunk_dequeued(pc);
}

static void free_pv_chunk_batch(struct pv_chunklist *batch)
{
	struct pv_chunks_list *pvc;
	struct pv_chunk *pc, *npc;
	int i;

	for (i = 0; i < vm_ndomains; i++) {
		if (TAILQ_EMPTY(&batch[i]))
			continue;
		pvc = &pv_chunks[i];
		mtx_lock(&pvc->pvc_lock);
		TAILQ_FOREACH(pc, &batch[i], pc_list) {
			TAILQ_REMOVE(&pvc->pvc_list, pc, pc_lru);
		}
		mtx_unlock(&pvc->pvc_lock);
	}

	for (i = 0; i < vm_ndomains; i++) {
		TAILQ_FOREACH_SAFE(pc, &batch[i], pc_list, npc) {
			free_pv_chunk_dequeued(pc);
		}
	}
}


static pv_entry_t get_pv_entry(pmap_t pmap, struct rwlock **lockp)
{
	struct pv_chunks_list *pvc;
	int bit, field;
	pv_entry_t pv;
	struct pv_chunk *pc;
	vm_page_t m;

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	PV_STAT(atomic_add_long(&pv_entry_allocs, 1));
retry:
	pc = TAILQ_FIRST(&pmap->pm_pvchunk);
	if (pc != NULL) {
		for (field = 0; field < _NPCM; field++) {
			if (pc->pc_map[field]) {
				bit = bsfq(pc->pc_map[field]);
				break;
			}
		}
		if (field < _NPCM) {
			pv = &pc->pc_pventry[field * 64 + bit];
			pc->pc_map[field] &= ~(1ul << bit);
			
			if (pc->pc_map[0] == 0 && pc->pc_map[1] == 0 && pc->pc_map[2] == 0) {
				TAILQ_REMOVE(&pmap->pm_pvchunk, pc, pc_list);
				TAILQ_INSERT_TAIL(&pmap->pm_pvchunk, pc, pc_list);
			}
			PV_STAT(atomic_add_long(&pv_entry_count, 1));
			PV_STAT(atomic_subtract_int(&pv_entry_spare, 1));
			return (pv);
		}
	}
	
	m = vm_page_alloc(NULL, 0, VM_ALLOC_NORMAL | VM_ALLOC_NOOBJ | VM_ALLOC_WIRED);
	if (m == NULL) {
		if (lockp == NULL) {
			PV_STAT(pc_chunk_tryfail++);
			return (NULL);
		}
		m = reclaim_pv_chunk(pmap, lockp);
		if (m == NULL)
			goto retry;
	}
	PV_STAT(atomic_add_int(&pc_chunk_count, 1));
	PV_STAT(atomic_add_int(&pc_chunk_allocs, 1));
	dump_add_page(m->phys_addr);
	pc = (void *)PHYS_TO_DMAP(m->phys_addr);
	pc->pc_pmap = pmap;
	pc->pc_map[0] = PC_FREE0 & ~1ul;	
	pc->pc_map[1] = PC_FREE1;
	pc->pc_map[2] = PC_FREE2;
	pvc = &pv_chunks[_vm_phys_domain(m->phys_addr)];
	mtx_lock(&pvc->pvc_lock);
	TAILQ_INSERT_TAIL(&pvc->pvc_list, pc, pc_lru);
	mtx_unlock(&pvc->pvc_lock);
	pv = &pc->pc_pventry[0];
	TAILQ_INSERT_HEAD(&pmap->pm_pvchunk, pc, pc_list);
	PV_STAT(atomic_add_long(&pv_entry_count, 1));
	PV_STAT(atomic_add_int(&pv_entry_spare, _NPCPV - 1));
	return (pv);
}


static int popcnt_pc_map_pq(uint64_t *map)
{
	u_long result, tmp;

	__asm __volatile("xorl %k0,%k0;popcntq %2,%0;" "xorl %k1,%k1;popcntq %3,%1;addl %k1,%k0;" "xorl %k1,%k1;popcntq %4,%1;addl %k1,%k0" : "=&r" (result), "=&r" (tmp)


	    : "m" (map[0]), "m" (map[1]), "m" (map[2]));
	return (result);
}


static void reserve_pv_entries(pmap_t pmap, int needed, struct rwlock **lockp)
{
	struct pv_chunks_list *pvc;
	struct pch new_tail[PMAP_MEMDOM];
	struct pv_chunk *pc;
	vm_page_t m;
	int avail, free, i;
	bool reclaimed;

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	KASSERT(lockp != NULL, ("reserve_pv_entries: lockp is NULL"));

	
	for (i = 0; i < PMAP_MEMDOM; i++)
		TAILQ_INIT(&new_tail[i]);
retry:
	avail = 0;
	TAILQ_FOREACH(pc, &pmap->pm_pvchunk, pc_list) {

		if ((cpu_feature2 & CPUID2_POPCNT) == 0)
			bit_count((bitstr_t *)pc->pc_map, 0, sizeof(pc->pc_map) * NBBY, &free);
		else  free = popcnt_pc_map_pq(pc->pc_map);

		if (free == 0)
			break;
		avail += free;
		if (avail >= needed)
			break;
	}
	for (reclaimed = false; avail < needed; avail += _NPCPV) {
		m = vm_page_alloc(NULL, 0, VM_ALLOC_NORMAL | VM_ALLOC_NOOBJ | VM_ALLOC_WIRED);
		if (m == NULL) {
			m = reclaim_pv_chunk(pmap, lockp);
			if (m == NULL)
				goto retry;
			reclaimed = true;
		}
		PV_STAT(atomic_add_int(&pc_chunk_count, 1));
		PV_STAT(atomic_add_int(&pc_chunk_allocs, 1));
		dump_add_page(m->phys_addr);
		pc = (void *)PHYS_TO_DMAP(m->phys_addr);
		pc->pc_pmap = pmap;
		pc->pc_map[0] = PC_FREE0;
		pc->pc_map[1] = PC_FREE1;
		pc->pc_map[2] = PC_FREE2;
		TAILQ_INSERT_HEAD(&pmap->pm_pvchunk, pc, pc_list);
		TAILQ_INSERT_TAIL(&new_tail[pc_to_domain(pc)], pc, pc_lru);
		PV_STAT(atomic_add_int(&pv_entry_spare, _NPCPV));

		
		if (reclaimed)
			goto retry;
	}
	for (i = 0; i < vm_ndomains; i++) {
		if (TAILQ_EMPTY(&new_tail[i]))
			continue;
		pvc = &pv_chunks[i];
		mtx_lock(&pvc->pvc_lock);
		TAILQ_CONCAT(&pvc->pvc_list, &new_tail[i], pc_lru);
		mtx_unlock(&pvc->pvc_lock);
	}
}


static __inline pv_entry_t pmap_pvh_remove(struct md_page *pvh, pmap_t pmap, vm_offset_t va)
{
	pv_entry_t pv;

	TAILQ_FOREACH(pv, &pvh->pv_list, pv_next) {
		if (pmap == PV_PMAP(pv) && va == pv->pv_va) {
			TAILQ_REMOVE(&pvh->pv_list, pv, pv_next);
			pvh->pv_gen++;
			break;
		}
	}
	return (pv);
}


static void pmap_pv_demote_pde(pmap_t pmap, vm_offset_t va, vm_paddr_t pa, struct rwlock **lockp)

{
	struct md_page *pvh;
	struct pv_chunk *pc;
	pv_entry_t pv;
	vm_offset_t va_last;
	vm_page_t m;
	int bit, field;

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	KASSERT((pa & PDRMASK) == 0, ("pmap_pv_demote_pde: pa is not 2mpage aligned"));
	CHANGE_PV_LIST_LOCK_TO_PHYS(lockp, pa);

	
	pvh = pa_to_pvh(pa);
	va = trunc_2mpage(va);
	pv = pmap_pvh_remove(pvh, pmap, va);
	KASSERT(pv != NULL, ("pmap_pv_demote_pde: pv not found"));
	m = PHYS_TO_VM_PAGE(pa);
	TAILQ_INSERT_TAIL(&m->md.pv_list, pv, pv_next);
	m->md.pv_gen++;
	
	PV_STAT(atomic_add_long(&pv_entry_allocs, NPTEPG - 1));
	va_last = va + NBPDR - PAGE_SIZE;
	for (;;) {
		pc = TAILQ_FIRST(&pmap->pm_pvchunk);
		KASSERT(pc->pc_map[0] != 0 || pc->pc_map[1] != 0 || pc->pc_map[2] != 0, ("pmap_pv_demote_pde: missing spare"));
		for (field = 0; field < _NPCM; field++) {
			while (pc->pc_map[field]) {
				bit = bsfq(pc->pc_map[field]);
				pc->pc_map[field] &= ~(1ul << bit);
				pv = &pc->pc_pventry[field * 64 + bit];
				va += PAGE_SIZE;
				pv->pv_va = va;
				m++;
				KASSERT((m->oflags & VPO_UNMANAGED) == 0, ("pmap_pv_demote_pde: page %p is not managed", m));
				TAILQ_INSERT_TAIL(&m->md.pv_list, pv, pv_next);
				m->md.pv_gen++;
				if (va == va_last)
					goto out;
			}
		}
		TAILQ_REMOVE(&pmap->pm_pvchunk, pc, pc_list);
		TAILQ_INSERT_TAIL(&pmap->pm_pvchunk, pc, pc_list);
	}
out:
	if (pc->pc_map[0] == 0 && pc->pc_map[1] == 0 && pc->pc_map[2] == 0) {
		TAILQ_REMOVE(&pmap->pm_pvchunk, pc, pc_list);
		TAILQ_INSERT_TAIL(&pmap->pm_pvchunk, pc, pc_list);
	}
	PV_STAT(atomic_add_long(&pv_entry_count, NPTEPG - 1));
	PV_STAT(atomic_subtract_int(&pv_entry_spare, NPTEPG - 1));
}



static void pmap_pv_promote_pde(pmap_t pmap, vm_offset_t va, vm_paddr_t pa, struct rwlock **lockp)

{
	struct md_page *pvh;
	pv_entry_t pv;
	vm_offset_t va_last;
	vm_page_t m;

	KASSERT((pa & PDRMASK) == 0, ("pmap_pv_promote_pde: pa is not 2mpage aligned"));
	CHANGE_PV_LIST_LOCK_TO_PHYS(lockp, pa);

	
	m = PHYS_TO_VM_PAGE(pa);
	va = trunc_2mpage(va);
	pv = pmap_pvh_remove(&m->md, pmap, va);
	KASSERT(pv != NULL, ("pmap_pv_promote_pde: pv not found"));
	pvh = pa_to_pvh(pa);
	TAILQ_INSERT_TAIL(&pvh->pv_list, pv, pv_next);
	pvh->pv_gen++;
	
	va_last = va + NBPDR - PAGE_SIZE;
	do {
		m++;
		va += PAGE_SIZE;
		pmap_pvh_free(&m->md, pmap, va);
	} while (va < va_last);
}



static void pmap_pvh_free(struct md_page *pvh, pmap_t pmap, vm_offset_t va)
{
	pv_entry_t pv;

	pv = pmap_pvh_remove(pvh, pmap, va);
	KASSERT(pv != NULL, ("pmap_pvh_free: pv not found"));
	free_pv_entry(pmap, pv);
}


static boolean_t pmap_try_insert_pv_entry(pmap_t pmap, vm_offset_t va, vm_page_t m, struct rwlock **lockp)

{
	pv_entry_t pv;

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	
	if ((pv = get_pv_entry(pmap, NULL)) != NULL) {
		pv->pv_va = va;
		CHANGE_PV_LIST_LOCK_TO_VM_PAGE(lockp, m);
		TAILQ_INSERT_TAIL(&m->md.pv_list, pv, pv_next);
		m->md.pv_gen++;
		return (TRUE);
	} else return (FALSE);
}


static bool pmap_pv_insert_pde(pmap_t pmap, vm_offset_t va, pd_entry_t pde, u_int flags, struct rwlock **lockp)

{
	struct md_page *pvh;
	pv_entry_t pv;
	vm_paddr_t pa;

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	
	if ((pv = get_pv_entry(pmap, (flags & PMAP_ENTER_NORECLAIM) != 0 ? NULL : lockp)) == NULL)
		return (false);
	pv->pv_va = va;
	pa = pde & PG_PS_FRAME;
	CHANGE_PV_LIST_LOCK_TO_PHYS(lockp, pa);
	pvh = pa_to_pvh(pa);
	TAILQ_INSERT_TAIL(&pvh->pv_list, pv, pv_next);
	pvh->pv_gen++;
	return (true);
}


static void pmap_fill_ptp(pt_entry_t *firstpte, pt_entry_t newpte)
{
	pt_entry_t *pte;

	for (pte = firstpte; pte < firstpte + NPTEPG; pte++) {
		*pte = newpte;
		newpte += PAGE_SIZE;
	}
}


static boolean_t pmap_demote_pde(pmap_t pmap, pd_entry_t *pde, vm_offset_t va)
{
	struct rwlock *lock;
	boolean_t rv;

	lock = NULL;
	rv = pmap_demote_pde_locked(pmap, pde, va, &lock);
	if (lock != NULL)
		rw_wunlock(lock);
	return (rv);
}

static void pmap_demote_pde_check(pt_entry_t *firstpte __unused, pt_entry_t newpte __unused)
{


	pt_entry_t *xpte, *ypte;

	for (xpte = firstpte; xpte < firstpte + NPTEPG;
	    xpte++, newpte += PAGE_SIZE) {
		if ((*xpte & PG_FRAME) != (newpte & PG_FRAME)) {
			printf("pmap_demote_pde: xpte %zd and newpte map " "different pages: found %#lx, expected %#lx\n", xpte - firstpte, *xpte, newpte);

			printf("page table dump\n");
			for (ypte = firstpte; ypte < firstpte + NPTEPG; ypte++)
				printf("%zd %#lx\n", ypte - firstpte, *ypte);
			panic("firstpte");
		}
	}

	KASSERT((*firstpte & PG_FRAME) == (newpte & PG_FRAME), ("pmap_demote_pde: firstpte and newpte map different physical" " addresses"));



}

static void pmap_demote_pde_abort(pmap_t pmap, vm_offset_t va, pd_entry_t *pde, pd_entry_t oldpde, struct rwlock **lockp)

{
	struct spglist free;
	vm_offset_t sva;

	SLIST_INIT(&free);
	sva = trunc_2mpage(va);
	pmap_remove_pde(pmap, pde, sva, &free, lockp);
	if ((oldpde & pmap_global_bit(pmap)) == 0)
		pmap_invalidate_pde_page(pmap, sva, oldpde);
	vm_page_free_pages_toq(&free, true);
	CTR2(KTR_PMAP, "pmap_demote_pde: failure for va %#lx in pmap %p", va, pmap);
}

static boolean_t pmap_demote_pde_locked(pmap_t pmap, pd_entry_t *pde, vm_offset_t va, struct rwlock **lockp)

{
	pd_entry_t newpde, oldpde;
	pt_entry_t *firstpte, newpte;
	pt_entry_t PG_A, PG_G, PG_M, PG_PKU_MASK, PG_RW, PG_V;
	vm_paddr_t mptepa;
	vm_page_t mpte;
	int PG_PTE_CACHE;
	bool in_kernel;

	PG_A = pmap_accessed_bit(pmap);
	PG_G = pmap_global_bit(pmap);
	PG_M = pmap_modified_bit(pmap);
	PG_RW = pmap_rw_bit(pmap);
	PG_V = pmap_valid_bit(pmap);
	PG_PTE_CACHE = pmap_cache_mask(pmap, 0);
	PG_PKU_MASK = pmap_pku_mask_bit(pmap);

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	in_kernel = va >= VM_MAXUSER_ADDRESS;
	oldpde = *pde;
	KASSERT((oldpde & (PG_PS | PG_V)) == (PG_PS | PG_V), ("pmap_demote_pde: oldpde is missing PG_PS and/or PG_V"));

	
	if ((oldpde & PG_A) == 0) {
		KASSERT((oldpde & PG_W) == 0, ("pmap_demote_pde: a wired mapping is missing PG_A"));
		pmap_demote_pde_abort(pmap, va, pde, oldpde, lockp);
		return (FALSE);
	}

	mpte = pmap_remove_pt_page(pmap, va);
	if (mpte == NULL) {
		KASSERT((oldpde & PG_W) == 0, ("pmap_demote_pde: page table page for a wired mapping" " is missing"));


		
		KASSERT(!in_kernel || (va >= DMAP_MIN_ADDRESS && va < DMAP_MAX_ADDRESS), ("pmap_demote_pde: No saved mpte for va %#lx", va));


		
		mpte = vm_page_alloc(NULL, pmap_pde_pindex(va), (in_kernel ? VM_ALLOC_INTERRUPT : VM_ALLOC_NORMAL) | VM_ALLOC_NOOBJ | VM_ALLOC_WIRED);


		
		if (mpte == NULL) {
			pmap_demote_pde_abort(pmap, va, pde, oldpde, lockp);
			return (FALSE);
		}

		if (!in_kernel) {
			mpte->ref_count = NPTEPG;
			pmap_resident_count_inc(pmap, 1);
		}
	}
	mptepa = VM_PAGE_TO_PHYS(mpte);
	firstpte = (pt_entry_t *)PHYS_TO_DMAP(mptepa);
	newpde = mptepa | PG_M | PG_A | (oldpde & PG_U) | PG_RW | PG_V;
	KASSERT((oldpde & (PG_M | PG_RW)) != PG_RW, ("pmap_demote_pde: oldpde is missing PG_M"));
	newpte = oldpde & ~PG_PS;
	newpte = pmap_swap_pat(pmap, newpte);

	
	if (mpte->valid == 0)
		pmap_fill_ptp(firstpte, newpte);

	pmap_demote_pde_check(firstpte, newpte);

	
	if ((*firstpte & PG_PTE_PROMOTE) != (newpte & PG_PTE_PROMOTE))
		pmap_fill_ptp(firstpte, newpte);

	
	if ((oldpde & PG_MANAGED) != 0)
		reserve_pv_entries(pmap, NPTEPG - 1, lockp);

	
	if (workaround_erratum383)
		pmap_update_pde(pmap, va, pde, newpde);
	else pde_store(pde, newpde);

	
	if (in_kernel)
		pmap_invalidate_page(pmap, (vm_offset_t)vtopte(va));

	
	if ((oldpde & PG_MANAGED) != 0)
		pmap_pv_demote_pde(pmap, va, oldpde & PG_PS_FRAME, lockp);

	atomic_add_long(&pmap_pde_demotions, 1);
	CTR2(KTR_PMAP, "pmap_demote_pde: success for va %#lx in pmap %p", va, pmap);
	return (TRUE);
}


static void pmap_remove_kernel_pde(pmap_t pmap, pd_entry_t *pde, vm_offset_t va)
{
	pd_entry_t newpde;
	vm_paddr_t mptepa;
	vm_page_t mpte;

	KASSERT(pmap == kernel_pmap, ("pmap %p is not kernel_pmap", pmap));
	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	mpte = pmap_remove_pt_page(pmap, va);
	if (mpte == NULL)
		panic("pmap_remove_kernel_pde: Missing pt page.");

	mptepa = VM_PAGE_TO_PHYS(mpte);
	newpde = mptepa | X86_PG_M | X86_PG_A | X86_PG_RW | X86_PG_V;

	
	if (mpte->valid != 0)
		pagezero((void *)PHYS_TO_DMAP(mptepa));

	
	if (workaround_erratum383)
		pmap_update_pde(pmap, va, pde, newpde);
	else pde_store(pde, newpde);

	
	pmap_invalidate_page(pmap, (vm_offset_t)vtopte(va));
}


static int pmap_remove_pde(pmap_t pmap, pd_entry_t *pdq, vm_offset_t sva, struct spglist *free, struct rwlock **lockp)

{
	struct md_page *pvh;
	pd_entry_t oldpde;
	vm_offset_t eva, va;
	vm_page_t m, mpte;
	pt_entry_t PG_G, PG_A, PG_M, PG_RW;

	PG_G = pmap_global_bit(pmap);
	PG_A = pmap_accessed_bit(pmap);
	PG_M = pmap_modified_bit(pmap);
	PG_RW = pmap_rw_bit(pmap);

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	KASSERT((sva & PDRMASK) == 0, ("pmap_remove_pde: sva is not 2mpage aligned"));
	oldpde = pte_load_clear(pdq);
	if (oldpde & PG_W)
		pmap->pm_stats.wired_count -= NBPDR / PAGE_SIZE;
	if ((oldpde & PG_G) != 0)
		pmap_invalidate_pde_page(kernel_pmap, sva, oldpde);
	pmap_resident_count_dec(pmap, NBPDR / PAGE_SIZE);
	if (oldpde & PG_MANAGED) {
		CHANGE_PV_LIST_LOCK_TO_PHYS(lockp, oldpde & PG_PS_FRAME);
		pvh = pa_to_pvh(oldpde & PG_PS_FRAME);
		pmap_pvh_free(pvh, pmap, sva);
		eva = sva + NBPDR;
		for (va = sva, m = PHYS_TO_VM_PAGE(oldpde & PG_PS_FRAME);
		    va < eva; va += PAGE_SIZE, m++) {
			if ((oldpde & (PG_M | PG_RW)) == (PG_M | PG_RW))
				vm_page_dirty(m);
			if (oldpde & PG_A)
				vm_page_aflag_set(m, PGA_REFERENCED);
			if (TAILQ_EMPTY(&m->md.pv_list) && TAILQ_EMPTY(&pvh->pv_list))
				vm_page_aflag_clear(m, PGA_WRITEABLE);
			pmap_delayed_invl_page(m);
		}
	}
	if (pmap == kernel_pmap) {
		pmap_remove_kernel_pde(pmap, pdq, sva);
	} else {
		mpte = pmap_remove_pt_page(pmap, sva);
		if (mpte != NULL) {
			KASSERT(mpte->valid == VM_PAGE_BITS_ALL, ("pmap_remove_pde: pte page not promoted"));
			pmap_resident_count_dec(pmap, 1);
			KASSERT(mpte->ref_count == NPTEPG, ("pmap_remove_pde: pte page ref count error"));
			mpte->ref_count = 0;
			pmap_add_delayed_free_list(mpte, free, FALSE);
		}
	}
	return (pmap_unuse_pt(pmap, sva, *pmap_pdpe(pmap, sva), free));
}


static int pmap_remove_pte(pmap_t pmap, pt_entry_t *ptq, vm_offset_t va, pd_entry_t ptepde, struct spglist *free, struct rwlock **lockp)

{
	struct md_page *pvh;
	pt_entry_t oldpte, PG_A, PG_M, PG_RW;
	vm_page_t m;

	PG_A = pmap_accessed_bit(pmap);
	PG_M = pmap_modified_bit(pmap);
	PG_RW = pmap_rw_bit(pmap);

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	oldpte = pte_load_clear(ptq);
	if (oldpte & PG_W)
		pmap->pm_stats.wired_count -= 1;
	pmap_resident_count_dec(pmap, 1);
	if (oldpte & PG_MANAGED) {
		m = PHYS_TO_VM_PAGE(oldpte & PG_FRAME);
		if ((oldpte & (PG_M | PG_RW)) == (PG_M | PG_RW))
			vm_page_dirty(m);
		if (oldpte & PG_A)
			vm_page_aflag_set(m, PGA_REFERENCED);
		CHANGE_PV_LIST_LOCK_TO_VM_PAGE(lockp, m);
		pmap_pvh_free(&m->md, pmap, va);
		if (TAILQ_EMPTY(&m->md.pv_list) && (m->flags & PG_FICTITIOUS) == 0) {
			pvh = pa_to_pvh(VM_PAGE_TO_PHYS(m));
			if (TAILQ_EMPTY(&pvh->pv_list))
				vm_page_aflag_clear(m, PGA_WRITEABLE);
		}
		pmap_delayed_invl_page(m);
	}
	return (pmap_unuse_pt(pmap, va, ptepde, free));
}


static void pmap_remove_page(pmap_t pmap, vm_offset_t va, pd_entry_t *pde, struct spglist *free)

{
	struct rwlock *lock;
	pt_entry_t *pte, PG_V;

	PG_V = pmap_valid_bit(pmap);
	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	if ((*pde & PG_V) == 0)
		return;
	pte = pmap_pde_to_pte(pde, va);
	if ((*pte & PG_V) == 0)
		return;
	lock = NULL;
	pmap_remove_pte(pmap, pte, va, *pde, free, &lock);
	if (lock != NULL)
		rw_wunlock(lock);
	pmap_invalidate_page(pmap, va);
}


static bool pmap_remove_ptes(pmap_t pmap, vm_offset_t sva, vm_offset_t eva, pd_entry_t *pde, struct spglist *free, struct rwlock **lockp)

{
	pt_entry_t PG_G, *pte;
	vm_offset_t va;
	bool anyvalid;

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	PG_G = pmap_global_bit(pmap);
	anyvalid = false;
	va = eva;
	for (pte = pmap_pde_to_pte(pde, sva); sva != eva; pte++, sva += PAGE_SIZE) {
		if (*pte == 0) {
			if (va != eva) {
				pmap_invalidate_range(pmap, va, sva);
				va = eva;
			}
			continue;
		}
		if ((*pte & PG_G) == 0)
			anyvalid = true;
		else if (va == eva)
			va = sva;
		if (pmap_remove_pte(pmap, pte, sva, *pde, free, lockp)) {
			sva += PAGE_SIZE;
			break;
		}
	}
	if (va != eva)
		pmap_invalidate_range(pmap, va, sva);
	return (anyvalid);
}


void pmap_remove(pmap_t pmap, vm_offset_t sva, vm_offset_t eva)
{
	struct rwlock *lock;
	vm_offset_t va_next;
	pml4_entry_t *pml4e;
	pdp_entry_t *pdpe;
	pd_entry_t ptpaddr, *pde;
	pt_entry_t PG_G, PG_V;
	struct spglist free;
	int anyvalid;

	PG_G = pmap_global_bit(pmap);
	PG_V = pmap_valid_bit(pmap);

	
	if (pmap->pm_stats.resident_count == 0)
		return;

	anyvalid = 0;
	SLIST_INIT(&free);

	pmap_delayed_invl_start();
	PMAP_LOCK(pmap);
	pmap_pkru_on_remove(pmap, sva, eva);

	
	if (sva + PAGE_SIZE == eva) {
		pde = pmap_pde(pmap, sva);
		if (pde && (*pde & PG_PS) == 0) {
			pmap_remove_page(pmap, sva, pde, &free);
			goto out;
		}
	}

	lock = NULL;
	for (; sva < eva; sva = va_next) {

		if (pmap->pm_stats.resident_count == 0)
			break;

		pml4e = pmap_pml4e(pmap, sva);
		if ((*pml4e & PG_V) == 0) {
			va_next = (sva + NBPML4) & ~PML4MASK;
			if (va_next < sva)
				va_next = eva;
			continue;
		}

		pdpe = pmap_pml4e_to_pdpe(pml4e, sva);
		if ((*pdpe & PG_V) == 0) {
			va_next = (sva + NBPDP) & ~PDPMASK;
			if (va_next < sva)
				va_next = eva;
			continue;
		}

		
		va_next = (sva + NBPDR) & ~PDRMASK;
		if (va_next < sva)
			va_next = eva;

		pde = pmap_pdpe_to_pde(pdpe, sva);
		ptpaddr = *pde;

		
		if (ptpaddr == 0)
			continue;

		
		if ((ptpaddr & PG_PS) != 0) {
			
			if (sva + NBPDR == va_next && eva >= va_next) {
				
				if ((ptpaddr & PG_G) == 0)
					anyvalid = 1;
				pmap_remove_pde(pmap, pde, sva, &free, &lock);
				continue;
			} else if (!pmap_demote_pde_locked(pmap, pde, sva, &lock)) {
				
				continue;
			} else ptpaddr = *pde;
		}

		
		if (va_next > eva)
			va_next = eva;

		if (pmap_remove_ptes(pmap, sva, va_next, pde, &free, &lock))
			anyvalid = 1;
	}
	if (lock != NULL)
		rw_wunlock(lock);
out:
	if (anyvalid)
		pmap_invalidate_all(pmap);
	PMAP_UNLOCK(pmap);
	pmap_delayed_invl_finish();
	vm_page_free_pages_toq(&free, true);
}



void pmap_remove_all(vm_page_t m)
{
	struct md_page *pvh;
	pv_entry_t pv;
	pmap_t pmap;
	struct rwlock *lock;
	pt_entry_t *pte, tpte, PG_A, PG_M, PG_RW;
	pd_entry_t *pde;
	vm_offset_t va;
	struct spglist free;
	int pvh_gen, md_gen;

	KASSERT((m->oflags & VPO_UNMANAGED) == 0, ("pmap_remove_all: page %p is not managed", m));
	SLIST_INIT(&free);
	lock = VM_PAGE_TO_PV_LIST_LOCK(m);
	pvh = (m->flags & PG_FICTITIOUS) != 0 ? &pv_dummy :
	    pa_to_pvh(VM_PAGE_TO_PHYS(m));
retry:
	rw_wlock(lock);
	while ((pv = TAILQ_FIRST(&pvh->pv_list)) != NULL) {
		pmap = PV_PMAP(pv);
		if (!PMAP_TRYLOCK(pmap)) {
			pvh_gen = pvh->pv_gen;
			rw_wunlock(lock);
			PMAP_LOCK(pmap);
			rw_wlock(lock);
			if (pvh_gen != pvh->pv_gen) {
				rw_wunlock(lock);
				PMAP_UNLOCK(pmap);
				goto retry;
			}
		}
		va = pv->pv_va;
		pde = pmap_pde(pmap, va);
		(void)pmap_demote_pde_locked(pmap, pde, va, &lock);
		PMAP_UNLOCK(pmap);
	}
	while ((pv = TAILQ_FIRST(&m->md.pv_list)) != NULL) {
		pmap = PV_PMAP(pv);
		if (!PMAP_TRYLOCK(pmap)) {
			pvh_gen = pvh->pv_gen;
			md_gen = m->md.pv_gen;
			rw_wunlock(lock);
			PMAP_LOCK(pmap);
			rw_wlock(lock);
			if (pvh_gen != pvh->pv_gen || md_gen != m->md.pv_gen) {
				rw_wunlock(lock);
				PMAP_UNLOCK(pmap);
				goto retry;
			}
		}
		PG_A = pmap_accessed_bit(pmap);
		PG_M = pmap_modified_bit(pmap);
		PG_RW = pmap_rw_bit(pmap);
		pmap_resident_count_dec(pmap, 1);
		pde = pmap_pde(pmap, pv->pv_va);
		KASSERT((*pde & PG_PS) == 0, ("pmap_remove_all: found" " a 2mpage in page %p's pv list", m));
		pte = pmap_pde_to_pte(pde, pv->pv_va);
		tpte = pte_load_clear(pte);
		if (tpte & PG_W)
			pmap->pm_stats.wired_count--;
		if (tpte & PG_A)
			vm_page_aflag_set(m, PGA_REFERENCED);

		
		if ((tpte & (PG_M | PG_RW)) == (PG_M | PG_RW))
			vm_page_dirty(m);
		pmap_unuse_pt(pmap, pv->pv_va, *pde, &free);
		pmap_invalidate_page(pmap, pv->pv_va);
		TAILQ_REMOVE(&m->md.pv_list, pv, pv_next);
		m->md.pv_gen++;
		free_pv_entry(pmap, pv);
		PMAP_UNLOCK(pmap);
	}
	vm_page_aflag_clear(m, PGA_WRITEABLE);
	rw_wunlock(lock);
	pmap_delayed_invl_wait(m);
	vm_page_free_pages_toq(&free, true);
}


static boolean_t pmap_protect_pde(pmap_t pmap, pd_entry_t *pde, vm_offset_t sva, vm_prot_t prot)
{
	pd_entry_t newpde, oldpde;
	vm_page_t m, mt;
	boolean_t anychanged;
	pt_entry_t PG_G, PG_M, PG_RW;

	PG_G = pmap_global_bit(pmap);
	PG_M = pmap_modified_bit(pmap);
	PG_RW = pmap_rw_bit(pmap);

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	KASSERT((sva & PDRMASK) == 0, ("pmap_protect_pde: sva is not 2mpage aligned"));
	anychanged = FALSE;
retry:
	oldpde = newpde = *pde;
	if ((prot & VM_PROT_WRITE) == 0) {
		if ((oldpde & (PG_MANAGED | PG_M | PG_RW)) == (PG_MANAGED | PG_M | PG_RW)) {
			m = PHYS_TO_VM_PAGE(oldpde & PG_PS_FRAME);
			for (mt = m; mt < &m[NBPDR / PAGE_SIZE]; mt++)
				vm_page_dirty(mt);
		}
		newpde &= ~(PG_RW | PG_M);
	}
	if ((prot & VM_PROT_EXECUTE) == 0)
		newpde |= pg_nx;
	if (newpde != oldpde) {
		
		if (!atomic_cmpset_long(pde, oldpde, newpde & ~PG_PROMOTED))
			goto retry;
		if ((oldpde & PG_G) != 0)
			pmap_invalidate_pde_page(kernel_pmap, sva, oldpde);
		else anychanged = TRUE;
	}
	return (anychanged);
}


void pmap_protect(pmap_t pmap, vm_offset_t sva, vm_offset_t eva, vm_prot_t prot)
{
	vm_offset_t va_next;
	pml4_entry_t *pml4e;
	pdp_entry_t *pdpe;
	pd_entry_t ptpaddr, *pde;
	pt_entry_t *pte, PG_G, PG_M, PG_RW, PG_V;
	boolean_t anychanged;

	KASSERT((prot & ~VM_PROT_ALL) == 0, ("invalid prot %x", prot));
	if (prot == VM_PROT_NONE) {
		pmap_remove(pmap, sva, eva);
		return;
	}

	if ((prot & (VM_PROT_WRITE|VM_PROT_EXECUTE)) == (VM_PROT_WRITE|VM_PROT_EXECUTE))
		return;

	PG_G = pmap_global_bit(pmap);
	PG_M = pmap_modified_bit(pmap);
	PG_V = pmap_valid_bit(pmap);
	PG_RW = pmap_rw_bit(pmap);
	anychanged = FALSE;

	
	
	PMAP_LOCK(pmap);
	for (; sva < eva; sva = va_next) {

		pml4e = pmap_pml4e(pmap, sva);
		if ((*pml4e & PG_V) == 0) {
			va_next = (sva + NBPML4) & ~PML4MASK;
			if (va_next < sva)
				va_next = eva;
			continue;
		}

		pdpe = pmap_pml4e_to_pdpe(pml4e, sva);
		if ((*pdpe & PG_V) == 0) {
			va_next = (sva + NBPDP) & ~PDPMASK;
			if (va_next < sva)
				va_next = eva;
			continue;
		}

		va_next = (sva + NBPDR) & ~PDRMASK;
		if (va_next < sva)
			va_next = eva;

		pde = pmap_pdpe_to_pde(pdpe, sva);
		ptpaddr = *pde;

		
		if (ptpaddr == 0)
			continue;

		
		if ((ptpaddr & PG_PS) != 0) {
			
			if (sva + NBPDR == va_next && eva >= va_next) {
				
				if (pmap_protect_pde(pmap, pde, sva, prot))
					anychanged = TRUE;
				continue;
			} else if (!pmap_demote_pde(pmap, pde, sva)) {
				
				continue;
			}
		}

		if (va_next > eva)
			va_next = eva;

		for (pte = pmap_pde_to_pte(pde, sva); sva != va_next; pte++, sva += PAGE_SIZE) {
			pt_entry_t obits, pbits;
			vm_page_t m;

retry:
			obits = pbits = *pte;
			if ((pbits & PG_V) == 0)
				continue;

			if ((prot & VM_PROT_WRITE) == 0) {
				if ((pbits & (PG_MANAGED | PG_M | PG_RW)) == (PG_MANAGED | PG_M | PG_RW)) {
					m = PHYS_TO_VM_PAGE(pbits & PG_FRAME);
					vm_page_dirty(m);
				}
				pbits &= ~(PG_RW | PG_M);
			}
			if ((prot & VM_PROT_EXECUTE) == 0)
				pbits |= pg_nx;

			if (pbits != obits) {
				if (!atomic_cmpset_long(pte, obits, pbits))
					goto retry;
				if (obits & PG_G)
					pmap_invalidate_page(pmap, sva);
				else anychanged = TRUE;
			}
		}
	}
	if (anychanged)
		pmap_invalidate_all(pmap);
	PMAP_UNLOCK(pmap);
}



static void pmap_promote_pde(pmap_t pmap, pd_entry_t *pde, vm_offset_t va, struct rwlock **lockp)

{
	pd_entry_t newpde;
	pt_entry_t *firstpte, oldpte, pa, *pte;
	pt_entry_t PG_G, PG_A, PG_M, PG_RW, PG_V, PG_PKU_MASK;
	vm_page_t mpte;
	int PG_PTE_CACHE;

	PG_A = pmap_accessed_bit(pmap);
	PG_G = pmap_global_bit(pmap);
	PG_M = pmap_modified_bit(pmap);
	PG_V = pmap_valid_bit(pmap);
	PG_RW = pmap_rw_bit(pmap);
	PG_PKU_MASK = pmap_pku_mask_bit(pmap);
	PG_PTE_CACHE = pmap_cache_mask(pmap, 0);

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);

	
	firstpte = (pt_entry_t *)PHYS_TO_DMAP(*pde & PG_FRAME);
setpde:
	newpde = *firstpte;
	if ((newpde & ((PG_FRAME & PDRMASK) | PG_A | PG_V)) != (PG_A | PG_V)) {
		atomic_add_long(&pmap_pde_p_failures, 1);
		CTR2(KTR_PMAP, "pmap_promote_pde: failure for va %#lx" " in pmap %p", va, pmap);
		return;
	}
	if ((newpde & (PG_M | PG_RW)) == PG_RW) {
		
		if (!atomic_cmpset_long(firstpte, newpde, newpde & ~PG_RW))
			goto setpde;
		newpde &= ~PG_RW;
	}

	
	pa = (newpde & (PG_PS_FRAME | PG_A | PG_V)) + NBPDR - PAGE_SIZE;
	for (pte = firstpte + NPTEPG - 1; pte > firstpte; pte--) {
setpte:
		oldpte = *pte;
		if ((oldpte & (PG_FRAME | PG_A | PG_V)) != pa) {
			atomic_add_long(&pmap_pde_p_failures, 1);
			CTR2(KTR_PMAP, "pmap_promote_pde: failure for va %#lx" " in pmap %p", va, pmap);
			return;
		}
		if ((oldpte & (PG_M | PG_RW)) == PG_RW) {
			
			if (!atomic_cmpset_long(pte, oldpte, oldpte & ~PG_RW))
				goto setpte;
			oldpte &= ~PG_RW;
			CTR2(KTR_PMAP, "pmap_promote_pde: protect for va %#lx" " in pmap %p", (oldpte & PG_FRAME & PDRMASK) | (va & ~PDRMASK), pmap);

		}
		if ((oldpte & PG_PTE_PROMOTE) != (newpde & PG_PTE_PROMOTE)) {
			atomic_add_long(&pmap_pde_p_failures, 1);
			CTR2(KTR_PMAP, "pmap_promote_pde: failure for va %#lx" " in pmap %p", va, pmap);
			return;
		}
		pa -= PAGE_SIZE;
	}

	
	mpte = PHYS_TO_VM_PAGE(*pde & PG_FRAME);
	KASSERT(mpte >= vm_page_array && mpte < &vm_page_array[vm_page_array_size], ("pmap_promote_pde: page table page is out of range"));

	KASSERT(mpte->pindex == pmap_pde_pindex(va), ("pmap_promote_pde: page table page's pindex is wrong"));
	if (pmap_insert_pt_page(pmap, mpte, true)) {
		atomic_add_long(&pmap_pde_p_failures, 1);
		CTR2(KTR_PMAP, "pmap_promote_pde: failure for va %#lx in pmap %p", va, pmap);

		return;
	}

	
	if ((newpde & PG_MANAGED) != 0)
		pmap_pv_promote_pde(pmap, va, newpde & PG_PS_FRAME, lockp);

	
	newpde = pmap_swap_pat(pmap, newpde);

	
	if (workaround_erratum383)
		pmap_update_pde(pmap, va, pde, PG_PS | newpde);
	else pde_store(pde, PG_PROMOTED | PG_PS | newpde);

	atomic_add_long(&pmap_pde_promotions, 1);
	CTR2(KTR_PMAP, "pmap_promote_pde: success for va %#lx" " in pmap %p", va, pmap);
}



int pmap_enter(pmap_t pmap, vm_offset_t va, vm_page_t m, vm_prot_t prot, u_int flags, int8_t psind)

{
	struct rwlock *lock;
	pd_entry_t *pde;
	pt_entry_t *pte, PG_G, PG_A, PG_M, PG_RW, PG_V;
	pt_entry_t newpte, origpte;
	pv_entry_t pv;
	vm_paddr_t opa, pa;
	vm_page_t mpte, om;
	int rv;
	boolean_t nosleep;

	PG_A = pmap_accessed_bit(pmap);
	PG_G = pmap_global_bit(pmap);
	PG_M = pmap_modified_bit(pmap);
	PG_V = pmap_valid_bit(pmap);
	PG_RW = pmap_rw_bit(pmap);

	va = trunc_page(va);
	KASSERT(va <= VM_MAX_KERNEL_ADDRESS, ("pmap_enter: toobig"));
	KASSERT(va < UPT_MIN_ADDRESS || va >= UPT_MAX_ADDRESS, ("pmap_enter: invalid to pmap_enter page table pages (va: 0x%lx)", va));

	KASSERT((m->oflags & VPO_UNMANAGED) != 0 || va < kmi.clean_sva || va >= kmi.clean_eva, ("pmap_enter: managed mapping within the clean submap"));

	if ((m->oflags & VPO_UNMANAGED) == 0)
		VM_PAGE_OBJECT_BUSY_ASSERT(m);
	KASSERT((flags & PMAP_ENTER_RESERVED) == 0, ("pmap_enter: flags %u has reserved bits set", flags));
	pa = VM_PAGE_TO_PHYS(m);
	newpte = (pt_entry_t)(pa | PG_A | PG_V);
	if ((flags & VM_PROT_WRITE) != 0)
		newpte |= PG_M;
	if ((prot & VM_PROT_WRITE) != 0)
		newpte |= PG_RW;
	KASSERT((newpte & (PG_M | PG_RW)) != PG_M, ("pmap_enter: flags includes VM_PROT_WRITE but prot doesn't"));
	if ((prot & VM_PROT_EXECUTE) == 0)
		newpte |= pg_nx;
	if ((flags & PMAP_ENTER_WIRED) != 0)
		newpte |= PG_W;
	if (va < VM_MAXUSER_ADDRESS)
		newpte |= PG_U;
	if (pmap == kernel_pmap)
		newpte |= PG_G;
	newpte |= pmap_cache_bits(pmap, m->md.pat_mode, psind > 0);

	
	if ((m->oflags & VPO_UNMANAGED) != 0) {
		if ((newpte & PG_RW) != 0)
			newpte |= PG_M;
	} else newpte |= PG_MANAGED;

	lock = NULL;
	PMAP_LOCK(pmap);
	if (psind == 1) {
		 
		KASSERT((va & PDRMASK) == 0, ("pmap_enter: va unaligned"));
		KASSERT(m->psind > 0, ("pmap_enter: m->psind < psind"));
		rv = pmap_enter_pde(pmap, va, newpte | PG_PS, flags, m, &lock);
		goto out;
	}
	mpte = NULL;

	
retry:
	pde = pmap_pde(pmap, va);
	if (pde != NULL && (*pde & PG_V) != 0 && ((*pde & PG_PS) == 0 || pmap_demote_pde_locked(pmap, pde, va, &lock))) {
		pte = pmap_pde_to_pte(pde, va);
		if (va < VM_MAXUSER_ADDRESS && mpte == NULL) {
			mpte = PHYS_TO_VM_PAGE(*pde & PG_FRAME);
			mpte->ref_count++;
		}
	} else if (va < VM_MAXUSER_ADDRESS) {
		
		nosleep = (flags & PMAP_ENTER_NOSLEEP) != 0;
		mpte = _pmap_allocpte(pmap, pmap_pde_pindex(va), nosleep ? NULL : &lock);
		if (mpte == NULL && nosleep) {
			rv = KERN_RESOURCE_SHORTAGE;
			goto out;
		}
		goto retry;
	} else panic("pmap_enter: invalid page directory va=%#lx", va);

	origpte = *pte;
	pv = NULL;
	if (va < VM_MAXUSER_ADDRESS && pmap->pm_type == PT_X86)
		newpte |= pmap_pkru_get(pmap, va);

	
	if ((origpte & PG_V) != 0) {
		
		if ((newpte & PG_W) != 0 && (origpte & PG_W) == 0)
			pmap->pm_stats.wired_count++;
		else if ((newpte & PG_W) == 0 && (origpte & PG_W) != 0)
			pmap->pm_stats.wired_count--;

		
		if (mpte != NULL) {
			mpte->ref_count--;
			KASSERT(mpte->ref_count > 0, ("pmap_enter: missing reference to page table page," " va: 0x%lx", va));

		}

		
		opa = origpte & PG_FRAME;
		if (opa == pa) {
			
			if ((origpte & PG_MANAGED) != 0 && (newpte & PG_RW) != 0)
				vm_page_aflag_set(m, PGA_WRITEABLE);
			if (((origpte ^ newpte) & ~(PG_M | PG_A)) == 0)
				goto unchanged;
			goto validate;
		}

		
		origpte = pte_load_clear(pte);
		KASSERT((origpte & PG_FRAME) == opa, ("pmap_enter: unexpected pa update for %#lx", va));
		if ((origpte & PG_MANAGED) != 0) {
			om = PHYS_TO_VM_PAGE(opa);

			
			if ((origpte & (PG_M | PG_RW)) == (PG_M | PG_RW))
				vm_page_dirty(om);
			if ((origpte & PG_A) != 0)
				vm_page_aflag_set(om, PGA_REFERENCED);
			CHANGE_PV_LIST_LOCK_TO_PHYS(&lock, opa);
			pv = pmap_pvh_remove(&om->md, pmap, va);
			KASSERT(pv != NULL, ("pmap_enter: no PV entry for %#lx", va));
			if ((newpte & PG_MANAGED) == 0)
				free_pv_entry(pmap, pv);
			if ((om->aflags & PGA_WRITEABLE) != 0 && TAILQ_EMPTY(&om->md.pv_list) && ((om->flags & PG_FICTITIOUS) != 0 || TAILQ_EMPTY(&pa_to_pvh(opa)->pv_list)))


				vm_page_aflag_clear(om, PGA_WRITEABLE);
		}
		if ((origpte & PG_A) != 0)
			pmap_invalidate_page(pmap, va);
		origpte = 0;
	} else {
		
		if ((newpte & PG_W) != 0)
			pmap->pm_stats.wired_count++;
		pmap_resident_count_inc(pmap, 1);
	}

	
	if ((newpte & PG_MANAGED) != 0) {
		if (pv == NULL) {
			pv = get_pv_entry(pmap, &lock);
			pv->pv_va = va;
		}
		CHANGE_PV_LIST_LOCK_TO_PHYS(&lock, pa);
		TAILQ_INSERT_TAIL(&m->md.pv_list, pv, pv_next);
		m->md.pv_gen++;
		if ((newpte & PG_RW) != 0)
			vm_page_aflag_set(m, PGA_WRITEABLE);
	}

	
	if ((origpte & PG_V) != 0) {
validate:
		origpte = pte_load_store(pte, newpte);
		KASSERT((origpte & PG_FRAME) == pa, ("pmap_enter: unexpected pa update for %#lx", va));
		if ((newpte & PG_M) == 0 && (origpte & (PG_M | PG_RW)) == (PG_M | PG_RW)) {
			if ((origpte & PG_MANAGED) != 0)
				vm_page_dirty(m);

			
		} else if ((origpte & PG_NX) != 0 || (newpte & PG_NX) == 0) {
			
			goto unchanged;
		}
		if ((origpte & PG_A) != 0)
			pmap_invalidate_page(pmap, va);
	} else pte_store(pte, newpte);

unchanged:


	
	if ((mpte == NULL || mpte->ref_count == NPTEPG) && pmap_ps_enabled(pmap) && (m->flags & PG_FICTITIOUS) == 0 && vm_reserv_level_iffullpop(m) == 0)


		pmap_promote_pde(pmap, pde, va, &lock);


	rv = KERN_SUCCESS;
out:
	if (lock != NULL)
		rw_wunlock(lock);
	PMAP_UNLOCK(pmap);
	return (rv);
}


static bool pmap_enter_2mpage(pmap_t pmap, vm_offset_t va, vm_page_t m, vm_prot_t prot, struct rwlock **lockp)

{
	pd_entry_t newpde;
	pt_entry_t PG_V;

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	PG_V = pmap_valid_bit(pmap);
	newpde = VM_PAGE_TO_PHYS(m) | pmap_cache_bits(pmap, m->md.pat_mode, 1) | PG_PS | PG_V;
	if ((m->oflags & VPO_UNMANAGED) == 0)
		newpde |= PG_MANAGED;
	if ((prot & VM_PROT_EXECUTE) == 0)
		newpde |= pg_nx;
	if (va < VM_MAXUSER_ADDRESS)
		newpde |= PG_U;
	return (pmap_enter_pde(pmap, va, newpde, PMAP_ENTER_NOSLEEP | PMAP_ENTER_NOREPLACE | PMAP_ENTER_NORECLAIM, NULL, lockp) == KERN_SUCCESS);

}


static int pmap_enter_pde(pmap_t pmap, vm_offset_t va, pd_entry_t newpde, u_int flags, vm_page_t m, struct rwlock **lockp)

{
	struct spglist free;
	pd_entry_t oldpde, *pde;
	pt_entry_t PG_G, PG_RW, PG_V;
	vm_page_t mt, pdpg;

	KASSERT(pmap == kernel_pmap || (newpde & PG_W) == 0, ("pmap_enter_pde: cannot create wired user mapping"));
	PG_G = pmap_global_bit(pmap);
	PG_RW = pmap_rw_bit(pmap);
	KASSERT((newpde & (pmap_modified_bit(pmap) | PG_RW)) != PG_RW, ("pmap_enter_pde: newpde is missing PG_M"));
	PG_V = pmap_valid_bit(pmap);
	PMAP_LOCK_ASSERT(pmap, MA_OWNED);

	if ((pdpg = pmap_allocpde(pmap, va, (flags & PMAP_ENTER_NOSLEEP) != 0 ? NULL : lockp)) == NULL) {
		CTR2(KTR_PMAP, "pmap_enter_pde: failure for va %#lx" " in pmap %p", va, pmap);
		return (KERN_RESOURCE_SHORTAGE);
	}

	
	if (!pmap_pkru_same(pmap, va, va + NBPDR)) {
		SLIST_INIT(&free);
		if (pmap_unwire_ptp(pmap, va, pdpg, &free)) {
			pmap_invalidate_page(pmap, va);
			vm_page_free_pages_toq(&free, true);
		}
		return (KERN_FAILURE);
	}
	if (va < VM_MAXUSER_ADDRESS && pmap->pm_type == PT_X86) {
		newpde &= ~X86_PG_PKU_MASK;
		newpde |= pmap_pkru_get(pmap, va);
	}

	pde = (pd_entry_t *)PHYS_TO_DMAP(VM_PAGE_TO_PHYS(pdpg));
	pde = &pde[pmap_pde_index(va)];
	oldpde = *pde;
	if ((oldpde & PG_V) != 0) {
		KASSERT(pdpg->ref_count > 1, ("pmap_enter_pde: pdpg's reference count is too low"));
		if ((flags & PMAP_ENTER_NOREPLACE) != 0) {
			pdpg->ref_count--;
			CTR2(KTR_PMAP, "pmap_enter_pde: failure for va %#lx" " in pmap %p", va, pmap);
			return (KERN_FAILURE);
		}
		
		SLIST_INIT(&free);
		if ((oldpde & PG_PS) != 0) {
			
			(void)pmap_remove_pde(pmap, pde, va, &free, lockp);
			if ((oldpde & PG_G) == 0)
				pmap_invalidate_pde_page(pmap, va, oldpde);
		} else {
			pmap_delayed_invl_start();
			if (pmap_remove_ptes(pmap, va, va + NBPDR, pde, &free, lockp))
		               pmap_invalidate_all(pmap);
			pmap_delayed_invl_finish();
		}
		vm_page_free_pages_toq(&free, true);
		if (va >= VM_MAXUSER_ADDRESS) {
			
			mt = PHYS_TO_VM_PAGE(*pde & PG_FRAME);
			if (pmap_insert_pt_page(pmap, mt, false))
				panic("pmap_enter_pde: trie insert failed");
		} else KASSERT(*pde == 0, ("pmap_enter_pde: non-zero pde %p", pde));

	}
	if ((newpde & PG_MANAGED) != 0) {
		
		if (!pmap_pv_insert_pde(pmap, va, newpde, flags, lockp)) {
			SLIST_INIT(&free);
			if (pmap_unwire_ptp(pmap, va, pdpg, &free)) {
				
				pmap_invalidate_page(pmap, va);
				vm_page_free_pages_toq(&free, true);
			}
			CTR2(KTR_PMAP, "pmap_enter_pde: failure for va %#lx" " in pmap %p", va, pmap);
			return (KERN_RESOURCE_SHORTAGE);
		}
		if ((newpde & PG_RW) != 0) {
			for (mt = m; mt < &m[NBPDR / PAGE_SIZE]; mt++)
				vm_page_aflag_set(mt, PGA_WRITEABLE);
		}
	}

	
	if ((newpde & PG_W) != 0)
		pmap->pm_stats.wired_count += NBPDR / PAGE_SIZE;
	pmap_resident_count_inc(pmap, NBPDR / PAGE_SIZE);

	
	pde_store(pde, newpde);

	atomic_add_long(&pmap_pde_mappings, 1);
	CTR2(KTR_PMAP, "pmap_enter_pde: success for va %#lx" " in pmap %p", va, pmap);
	return (KERN_SUCCESS);
}


void pmap_enter_object(pmap_t pmap, vm_offset_t start, vm_offset_t end, vm_page_t m_start, vm_prot_t prot)

{
	struct rwlock *lock;
	vm_offset_t va;
	vm_page_t m, mpte;
	vm_pindex_t diff, psize;

	VM_OBJECT_ASSERT_LOCKED(m_start->object);

	psize = atop(end - start);
	mpte = NULL;
	m = m_start;
	lock = NULL;
	PMAP_LOCK(pmap);
	while (m != NULL && (diff = m->pindex - m_start->pindex) < psize) {
		va = start + ptoa(diff);
		if ((va & PDRMASK) == 0 && va + NBPDR <= end && m->psind == 1 && pmap_ps_enabled(pmap) && pmap_enter_2mpage(pmap, va, m, prot, &lock))

			m = &m[NBPDR / PAGE_SIZE - 1];
		else mpte = pmap_enter_quick_locked(pmap, va, m, prot, mpte, &lock);

		m = TAILQ_NEXT(m, listq);
	}
	if (lock != NULL)
		rw_wunlock(lock);
	PMAP_UNLOCK(pmap);
}



void pmap_enter_quick(pmap_t pmap, vm_offset_t va, vm_page_t m, vm_prot_t prot)
{
	struct rwlock *lock;

	lock = NULL;
	PMAP_LOCK(pmap);
	(void)pmap_enter_quick_locked(pmap, va, m, prot, NULL, &lock);
	if (lock != NULL)
		rw_wunlock(lock);
	PMAP_UNLOCK(pmap);
}

static vm_page_t pmap_enter_quick_locked(pmap_t pmap, vm_offset_t va, vm_page_t m, vm_prot_t prot, vm_page_t mpte, struct rwlock **lockp)

{
	struct spglist free;
	pt_entry_t newpte, *pte, PG_V;

	KASSERT(va < kmi.clean_sva || va >= kmi.clean_eva || (m->oflags & VPO_UNMANAGED) != 0, ("pmap_enter_quick_locked: managed mapping within the clean submap"));

	PG_V = pmap_valid_bit(pmap);
	PMAP_LOCK_ASSERT(pmap, MA_OWNED);

	
	if (va < VM_MAXUSER_ADDRESS) {
		vm_pindex_t ptepindex;
		pd_entry_t *ptepa;

		
		ptepindex = pmap_pde_pindex(va);
		if (mpte && (mpte->pindex == ptepindex)) {
			mpte->ref_count++;
		} else {
			
			ptepa = pmap_pde(pmap, va);

			
			if (ptepa && (*ptepa & PG_V) != 0) {
				if (*ptepa & PG_PS)
					return (NULL);
				mpte = PHYS_TO_VM_PAGE(*ptepa & PG_FRAME);
				mpte->ref_count++;
			} else {
				
				mpte = _pmap_allocpte(pmap, ptepindex, NULL);
				if (mpte == NULL)
					return (mpte);
			}
		}
		pte = (pt_entry_t *)PHYS_TO_DMAP(VM_PAGE_TO_PHYS(mpte));
		pte = &pte[pmap_pte_index(va)];
	} else {
		mpte = NULL;
		pte = vtopte(va);
	}
	if (*pte) {
		if (mpte != NULL) {
			mpte->ref_count--;
			mpte = NULL;
		}
		return (mpte);
	}

	
	if ((m->oflags & VPO_UNMANAGED) == 0 && !pmap_try_insert_pv_entry(pmap, va, m, lockp)) {
		if (mpte != NULL) {
			SLIST_INIT(&free);
			if (pmap_unwire_ptp(pmap, va, mpte, &free)) {
				
				pmap_invalidate_page(pmap, va);
				vm_page_free_pages_toq(&free, true);
			}
			mpte = NULL;
		}
		return (mpte);
	}

	
	pmap_resident_count_inc(pmap, 1);

	newpte = VM_PAGE_TO_PHYS(m) | PG_V | pmap_cache_bits(pmap, m->md.pat_mode, 0);
	if ((m->oflags & VPO_UNMANAGED) == 0)
		newpte |= PG_MANAGED;
	if ((prot & VM_PROT_EXECUTE) == 0)
		newpte |= pg_nx;
	if (va < VM_MAXUSER_ADDRESS)
		newpte |= PG_U | pmap_pkru_get(pmap, va);
	pte_store(pte, newpte);
	return (mpte);
}


void * pmap_kenter_temporary(vm_paddr_t pa, int i)
{
	vm_offset_t va;

	va = (vm_offset_t)crashdumpmap + (i * PAGE_SIZE);
	pmap_kenter(va, pa);
	invlpg(va);
	return ((void *)crashdumpmap);
}


void pmap_object_init_pt(pmap_t pmap, vm_offset_t addr, vm_object_t object, vm_pindex_t pindex, vm_size_t size)

{
	pd_entry_t *pde;
	pt_entry_t PG_A, PG_M, PG_RW, PG_V;
	vm_paddr_t pa, ptepa;
	vm_page_t p, pdpg;
	int pat_mode;

	PG_A = pmap_accessed_bit(pmap);
	PG_M = pmap_modified_bit(pmap);
	PG_V = pmap_valid_bit(pmap);
	PG_RW = pmap_rw_bit(pmap);

	VM_OBJECT_ASSERT_WLOCKED(object);
	KASSERT(object->type == OBJT_DEVICE || object->type == OBJT_SG, ("pmap_object_init_pt: non-device object"));
	if ((addr & (NBPDR - 1)) == 0 && (size & (NBPDR - 1)) == 0) {
		if (!pmap_ps_enabled(pmap))
			return;
		if (!vm_object_populate(object, pindex, pindex + atop(size)))
			return;
		p = vm_page_lookup(object, pindex);
		KASSERT(p->valid == VM_PAGE_BITS_ALL, ("pmap_object_init_pt: invalid page %p", p));
		pat_mode = p->md.pat_mode;

		
		ptepa = VM_PAGE_TO_PHYS(p);
		if (ptepa & (NBPDR - 1))
			return;

		
		p = TAILQ_NEXT(p, listq);
		for (pa = ptepa + PAGE_SIZE; pa < ptepa + size;
		    pa += PAGE_SIZE) {
			KASSERT(p->valid == VM_PAGE_BITS_ALL, ("pmap_object_init_pt: invalid page %p", p));
			if (pa != VM_PAGE_TO_PHYS(p) || pat_mode != p->md.pat_mode)
				return;
			p = TAILQ_NEXT(p, listq);
		}

		 
		PMAP_LOCK(pmap);
		for (pa = ptepa | pmap_cache_bits(pmap, pat_mode, 1);
		    pa < ptepa + size; pa += NBPDR) {
			pdpg = pmap_allocpde(pmap, addr, NULL);
			if (pdpg == NULL) {
				
				addr += NBPDR;
				continue;
			}
			pde = (pd_entry_t *)PHYS_TO_DMAP(VM_PAGE_TO_PHYS(pdpg));
			pde = &pde[pmap_pde_index(addr)];
			if ((*pde & PG_V) == 0) {
				pde_store(pde, pa | PG_PS | PG_M | PG_A | PG_U | PG_RW | PG_V);
				pmap_resident_count_inc(pmap, NBPDR / PAGE_SIZE);
				atomic_add_long(&pmap_pde_mappings, 1);
			} else {
				
				pdpg->ref_count--;
				KASSERT(pdpg->ref_count > 0, ("pmap_object_init_pt: missing reference " "to page directory page, va: 0x%lx", addr));

			}
			addr += NBPDR;
		}
		PMAP_UNLOCK(pmap);
	}
}


void pmap_unwire(pmap_t pmap, vm_offset_t sva, vm_offset_t eva)
{
	vm_offset_t va_next;
	pml4_entry_t *pml4e;
	pdp_entry_t *pdpe;
	pd_entry_t *pde;
	pt_entry_t *pte, PG_V;

	PG_V = pmap_valid_bit(pmap);
	PMAP_LOCK(pmap);
	for (; sva < eva; sva = va_next) {
		pml4e = pmap_pml4e(pmap, sva);
		if ((*pml4e & PG_V) == 0) {
			va_next = (sva + NBPML4) & ~PML4MASK;
			if (va_next < sva)
				va_next = eva;
			continue;
		}
		pdpe = pmap_pml4e_to_pdpe(pml4e, sva);
		if ((*pdpe & PG_V) == 0) {
			va_next = (sva + NBPDP) & ~PDPMASK;
			if (va_next < sva)
				va_next = eva;
			continue;
		}
		va_next = (sva + NBPDR) & ~PDRMASK;
		if (va_next < sva)
			va_next = eva;
		pde = pmap_pdpe_to_pde(pdpe, sva);
		if ((*pde & PG_V) == 0)
			continue;
		if ((*pde & PG_PS) != 0) {
			if ((*pde & PG_W) == 0)
				panic("pmap_unwire: pde %#jx is missing PG_W", (uintmax_t)*pde);

			
			if (sva + NBPDR == va_next && eva >= va_next) {
				atomic_clear_long(pde, PG_W);
				pmap->pm_stats.wired_count -= NBPDR / PAGE_SIZE;
				continue;
			} else if (!pmap_demote_pde(pmap, pde, sva))
				panic("pmap_unwire: demotion failed");
		}
		if (va_next > eva)
			va_next = eva;
		for (pte = pmap_pde_to_pte(pde, sva); sva != va_next; pte++, sva += PAGE_SIZE) {
			if ((*pte & PG_V) == 0)
				continue;
			if ((*pte & PG_W) == 0)
				panic("pmap_unwire: pte %#jx is missing PG_W", (uintmax_t)*pte);

			
			atomic_clear_long(pte, PG_W);
			pmap->pm_stats.wired_count--;
		}
	}
	PMAP_UNLOCK(pmap);
}


void pmap_copy(pmap_t dst_pmap, pmap_t src_pmap, vm_offset_t dst_addr, vm_size_t len, vm_offset_t src_addr)

{
	struct rwlock *lock;
	struct spglist free;
	pml4_entry_t *pml4e;
	pdp_entry_t *pdpe;
	pd_entry_t *pde, srcptepaddr;
	pt_entry_t *dst_pte, PG_A, PG_M, PG_V, ptetemp, *src_pte;
	vm_offset_t addr, end_addr, va_next;
	vm_page_t dst_pdpg, dstmpte, srcmpte;

	if (dst_addr != src_addr)
		return;

	if (dst_pmap->pm_type != src_pmap->pm_type)
		return;

	
	if (pmap_emulate_ad_bits(dst_pmap))
		return;

	end_addr = src_addr + len;
	lock = NULL;
	if (dst_pmap < src_pmap) {
		PMAP_LOCK(dst_pmap);
		PMAP_LOCK(src_pmap);
	} else {
		PMAP_LOCK(src_pmap);
		PMAP_LOCK(dst_pmap);
	}

	PG_A = pmap_accessed_bit(dst_pmap);
	PG_M = pmap_modified_bit(dst_pmap);
	PG_V = pmap_valid_bit(dst_pmap);

	for (addr = src_addr; addr < end_addr; addr = va_next) {
		KASSERT(addr < UPT_MIN_ADDRESS, ("pmap_copy: invalid to pmap_copy page tables"));

		pml4e = pmap_pml4e(src_pmap, addr);
		if ((*pml4e & PG_V) == 0) {
			va_next = (addr + NBPML4) & ~PML4MASK;
			if (va_next < addr)
				va_next = end_addr;
			continue;
		}

		pdpe = pmap_pml4e_to_pdpe(pml4e, addr);
		if ((*pdpe & PG_V) == 0) {
			va_next = (addr + NBPDP) & ~PDPMASK;
			if (va_next < addr)
				va_next = end_addr;
			continue;
		}

		va_next = (addr + NBPDR) & ~PDRMASK;
		if (va_next < addr)
			va_next = end_addr;

		pde = pmap_pdpe_to_pde(pdpe, addr);
		srcptepaddr = *pde;
		if (srcptepaddr == 0)
			continue;
			
		if (srcptepaddr & PG_PS) {
			if ((addr & PDRMASK) != 0 || addr + NBPDR > end_addr)
				continue;
			dst_pdpg = pmap_allocpde(dst_pmap, addr, NULL);
			if (dst_pdpg == NULL)
				break;
			pde = (pd_entry_t *)
			    PHYS_TO_DMAP(VM_PAGE_TO_PHYS(dst_pdpg));
			pde = &pde[pmap_pde_index(addr)];
			if (*pde == 0 && ((srcptepaddr & PG_MANAGED) == 0 || pmap_pv_insert_pde(dst_pmap, addr, srcptepaddr, PMAP_ENTER_NORECLAIM, &lock))) {

				*pde = srcptepaddr & ~PG_W;
				pmap_resident_count_inc(dst_pmap, NBPDR / PAGE_SIZE);
				atomic_add_long(&pmap_pde_mappings, 1);
			} else dst_pdpg->ref_count--;
			continue;
		}

		srcptepaddr &= PG_FRAME;
		srcmpte = PHYS_TO_VM_PAGE(srcptepaddr);
		KASSERT(srcmpte->ref_count > 0, ("pmap_copy: source page table page is unused"));

		if (va_next > end_addr)
			va_next = end_addr;

		src_pte = (pt_entry_t *)PHYS_TO_DMAP(srcptepaddr);
		src_pte = &src_pte[pmap_pte_index(addr)];
		dstmpte = NULL;
		for (; addr < va_next; addr += PAGE_SIZE, src_pte++) {
			ptetemp = *src_pte;

			
			if ((ptetemp & PG_MANAGED) == 0)
				continue;

			if (dstmpte != NULL) {
				KASSERT(dstmpte->pindex == pmap_pde_pindex(addr), ("dstmpte pindex/addr mismatch"));

				dstmpte->ref_count++;
			} else if ((dstmpte = pmap_allocpte(dst_pmap, addr, NULL)) == NULL)
				goto out;
			dst_pte = (pt_entry_t *)
			    PHYS_TO_DMAP(VM_PAGE_TO_PHYS(dstmpte));
			dst_pte = &dst_pte[pmap_pte_index(addr)];
			if (*dst_pte == 0 && pmap_try_insert_pv_entry(dst_pmap, addr, PHYS_TO_VM_PAGE(ptetemp & PG_FRAME), &lock)) {

				
				*dst_pte = ptetemp & ~(PG_W | PG_M | PG_A);
				pmap_resident_count_inc(dst_pmap, 1);
			} else {
				SLIST_INIT(&free);
				if (pmap_unwire_ptp(dst_pmap, addr, dstmpte, &free)) {
					
					pmap_invalidate_page(dst_pmap, addr);
					vm_page_free_pages_toq(&free, true);
				}
				goto out;
			}
			 
			if (dstmpte->ref_count >= srcmpte->ref_count)
				break;
		}
	}
out:
	if (lock != NULL)
		rw_wunlock(lock);
	PMAP_UNLOCK(src_pmap);
	PMAP_UNLOCK(dst_pmap);
}

int pmap_vmspace_copy(pmap_t dst_pmap, pmap_t src_pmap)
{
	int error;

	if (dst_pmap->pm_type != src_pmap->pm_type || dst_pmap->pm_type != PT_X86 || (cpu_stdext_feature2 & CPUID_STDEXT2_PKU) == 0)

		return (0);
	for (;;) {
		if (dst_pmap < src_pmap) {
			PMAP_LOCK(dst_pmap);
			PMAP_LOCK(src_pmap);
		} else {
			PMAP_LOCK(src_pmap);
			PMAP_LOCK(dst_pmap);
		}
		error = pmap_pkru_copy(dst_pmap, src_pmap);
		
		if (error == ENOMEM)
			pmap_pkru_deassign_all(dst_pmap);
		PMAP_UNLOCK(src_pmap);
		PMAP_UNLOCK(dst_pmap);
		if (error != ENOMEM)
			break;
		vm_wait(NULL);
	}
	return (error);
}


void pmap_zero_page(vm_page_t m)
{
	vm_offset_t va = PHYS_TO_DMAP(VM_PAGE_TO_PHYS(m));

	pagezero((void *)va);
}


void pmap_zero_page_area(vm_page_t m, int off, int size)
{
	vm_offset_t va = PHYS_TO_DMAP(VM_PAGE_TO_PHYS(m));

	if (off == 0 && size == PAGE_SIZE)
		pagezero((void *)va);
	else bzero((char *)va + off, size);
}


void pmap_copy_page(vm_page_t msrc, vm_page_t mdst)
{
	vm_offset_t src = PHYS_TO_DMAP(VM_PAGE_TO_PHYS(msrc));
	vm_offset_t dst = PHYS_TO_DMAP(VM_PAGE_TO_PHYS(mdst));

	pagecopy((void *)src, (void *)dst);
}

int unmapped_buf_allowed = 1;

void pmap_copy_pages(vm_page_t ma[], vm_offset_t a_offset, vm_page_t mb[], vm_offset_t b_offset, int xfersize)

{
	void *a_cp, *b_cp;
	vm_page_t pages[2];
	vm_offset_t vaddr[2], a_pg_offset, b_pg_offset;
	int cnt;
	boolean_t mapped;

	while (xfersize > 0) {
		a_pg_offset = a_offset & PAGE_MASK;
		pages[0] = ma[a_offset >> PAGE_SHIFT];
		b_pg_offset = b_offset & PAGE_MASK;
		pages[1] = mb[b_offset >> PAGE_SHIFT];
		cnt = min(xfersize, PAGE_SIZE - a_pg_offset);
		cnt = min(cnt, PAGE_SIZE - b_pg_offset);
		mapped = pmap_map_io_transient(pages, vaddr, 2, FALSE);
		a_cp = (char *)vaddr[0] + a_pg_offset;
		b_cp = (char *)vaddr[1] + b_pg_offset;
		bcopy(a_cp, b_cp, cnt);
		if (__predict_false(mapped))
			pmap_unmap_io_transient(pages, vaddr, 2, FALSE);
		a_offset += cnt;
		b_offset += cnt;
		xfersize -= cnt;
	}
}


boolean_t pmap_page_exists_quick(pmap_t pmap, vm_page_t m)
{
	struct md_page *pvh;
	struct rwlock *lock;
	pv_entry_t pv;
	int loops = 0;
	boolean_t rv;

	KASSERT((m->oflags & VPO_UNMANAGED) == 0, ("pmap_page_exists_quick: page %p is not managed", m));
	rv = FALSE;
	lock = VM_PAGE_TO_PV_LIST_LOCK(m);
	rw_rlock(lock);
	TAILQ_FOREACH(pv, &m->md.pv_list, pv_next) {
		if (PV_PMAP(pv) == pmap) {
			rv = TRUE;
			break;
		}
		loops++;
		if (loops >= 16)
			break;
	}
	if (!rv && loops < 16 && (m->flags & PG_FICTITIOUS) == 0) {
		pvh = pa_to_pvh(VM_PAGE_TO_PHYS(m));
		TAILQ_FOREACH(pv, &pvh->pv_list, pv_next) {
			if (PV_PMAP(pv) == pmap) {
				rv = TRUE;
				break;
			}
			loops++;
			if (loops >= 16)
				break;
		}
	}
	rw_runlock(lock);
	return (rv);
}


int pmap_page_wired_mappings(vm_page_t m)
{
	struct rwlock *lock;
	struct md_page *pvh;
	pmap_t pmap;
	pt_entry_t *pte;
	pv_entry_t pv;
	int count, md_gen, pvh_gen;

	if ((m->oflags & VPO_UNMANAGED) != 0)
		return (0);
	lock = VM_PAGE_TO_PV_LIST_LOCK(m);
	rw_rlock(lock);
restart:
	count = 0;
	TAILQ_FOREACH(pv, &m->md.pv_list, pv_next) {
		pmap = PV_PMAP(pv);
		if (!PMAP_TRYLOCK(pmap)) {
			md_gen = m->md.pv_gen;
			rw_runlock(lock);
			PMAP_LOCK(pmap);
			rw_rlock(lock);
			if (md_gen != m->md.pv_gen) {
				PMAP_UNLOCK(pmap);
				goto restart;
			}
		}
		pte = pmap_pte(pmap, pv->pv_va);
		if ((*pte & PG_W) != 0)
			count++;
		PMAP_UNLOCK(pmap);
	}
	if ((m->flags & PG_FICTITIOUS) == 0) {
		pvh = pa_to_pvh(VM_PAGE_TO_PHYS(m));
		TAILQ_FOREACH(pv, &pvh->pv_list, pv_next) {
			pmap = PV_PMAP(pv);
			if (!PMAP_TRYLOCK(pmap)) {
				md_gen = m->md.pv_gen;
				pvh_gen = pvh->pv_gen;
				rw_runlock(lock);
				PMAP_LOCK(pmap);
				rw_rlock(lock);
				if (md_gen != m->md.pv_gen || pvh_gen != pvh->pv_gen) {
					PMAP_UNLOCK(pmap);
					goto restart;
				}
			}
			pte = pmap_pde(pmap, pv->pv_va);
			if ((*pte & PG_W) != 0)
				count++;
			PMAP_UNLOCK(pmap);
		}
	}
	rw_runlock(lock);
	return (count);
}


boolean_t pmap_page_is_mapped(vm_page_t m)
{
	struct rwlock *lock;
	boolean_t rv;

	if ((m->oflags & VPO_UNMANAGED) != 0)
		return (FALSE);
	lock = VM_PAGE_TO_PV_LIST_LOCK(m);
	rw_rlock(lock);
	rv = !TAILQ_EMPTY(&m->md.pv_list) || ((m->flags & PG_FICTITIOUS) == 0 && !TAILQ_EMPTY(&pa_to_pvh(VM_PAGE_TO_PHYS(m))->pv_list));

	rw_runlock(lock);
	return (rv);
}


void pmap_remove_pages(pmap_t pmap)
{
	pd_entry_t ptepde;
	pt_entry_t *pte, tpte;
	pt_entry_t PG_M, PG_RW, PG_V;
	struct spglist free;
	struct pv_chunklist free_chunks[PMAP_MEMDOM];
	vm_page_t m, mpte, mt;
	pv_entry_t pv;
	struct md_page *pvh;
	struct pv_chunk *pc, *npc;
	struct rwlock *lock;
	int64_t bit;
	uint64_t inuse, bitmask;
	int allfree, field, freed, i, idx;
	boolean_t superpage;
	vm_paddr_t pa;

	
	KASSERT(pmap == PCPU_GET(curpmap), ("non-current pmap %p", pmap));

	{
		cpuset_t other_cpus;

		other_cpus = all_cpus;
		critical_enter();
		CPU_CLR(PCPU_GET(cpuid), &other_cpus);
		CPU_AND(&other_cpus, &pmap->pm_active);
		critical_exit();
		KASSERT(CPU_EMPTY(&other_cpus), ("pmap active %p", pmap));
	}


	lock = NULL;
	PG_M = pmap_modified_bit(pmap);
	PG_V = pmap_valid_bit(pmap);
	PG_RW = pmap_rw_bit(pmap);

	for (i = 0; i < PMAP_MEMDOM; i++)
		TAILQ_INIT(&free_chunks[i]);
	SLIST_INIT(&free);
	PMAP_LOCK(pmap);
	TAILQ_FOREACH_SAFE(pc, &pmap->pm_pvchunk, pc_list, npc) {
		allfree = 1;
		freed = 0;
		for (field = 0; field < _NPCM; field++) {
			inuse = ~pc->pc_map[field] & pc_freemask[field];
			while (inuse != 0) {
				bit = bsfq(inuse);
				bitmask = 1UL << bit;
				idx = field * 64 + bit;
				pv = &pc->pc_pventry[idx];
				inuse &= ~bitmask;

				pte = pmap_pdpe(pmap, pv->pv_va);
				ptepde = *pte;
				pte = pmap_pdpe_to_pde(pte, pv->pv_va);
				tpte = *pte;
				if ((tpte & (PG_PS | PG_V)) == PG_V) {
					superpage = FALSE;
					ptepde = tpte;
					pte = (pt_entry_t *)PHYS_TO_DMAP(tpte & PG_FRAME);
					pte = &pte[pmap_pte_index(pv->pv_va)];
					tpte = *pte;
				} else {
					
					superpage = TRUE;
				}

				if ((tpte & PG_V) == 0) {
					panic("bad pte va %lx pte %lx", pv->pv_va, tpte);
				}


				if (tpte & PG_W) {
					allfree = 0;
					continue;
				}

				if (superpage)
					pa = tpte & PG_PS_FRAME;
				else pa = tpte & PG_FRAME;

				m = PHYS_TO_VM_PAGE(pa);
				KASSERT(m->phys_addr == pa, ("vm_page_t %p phys_addr mismatch %016jx %016jx", m, (uintmax_t)m->phys_addr, (uintmax_t)tpte));



				KASSERT((m->flags & PG_FICTITIOUS) != 0 || m < &vm_page_array[vm_page_array_size], ("pmap_remove_pages: bad tpte %#jx", (uintmax_t)tpte));



				pte_clear(pte);

				
				if ((tpte & (PG_M | PG_RW)) == (PG_M | PG_RW)) {
					if (superpage) {
						for (mt = m; mt < &m[NBPDR / PAGE_SIZE]; mt++)
							vm_page_dirty(mt);
					} else vm_page_dirty(m);
				}

				CHANGE_PV_LIST_LOCK_TO_VM_PAGE(&lock, m);

				
				pc->pc_map[field] |= bitmask;
				if (superpage) {
					pmap_resident_count_dec(pmap, NBPDR / PAGE_SIZE);
					pvh = pa_to_pvh(tpte & PG_PS_FRAME);
					TAILQ_REMOVE(&pvh->pv_list, pv, pv_next);
					pvh->pv_gen++;
					if (TAILQ_EMPTY(&pvh->pv_list)) {
						for (mt = m; mt < &m[NBPDR / PAGE_SIZE]; mt++)
							if ((mt->aflags & PGA_WRITEABLE) != 0 && TAILQ_EMPTY(&mt->md.pv_list))
								vm_page_aflag_clear(mt, PGA_WRITEABLE);
					}
					mpte = pmap_remove_pt_page(pmap, pv->pv_va);
					if (mpte != NULL) {
						KASSERT(mpte->valid == VM_PAGE_BITS_ALL, ("pmap_remove_pages: pte page not promoted"));
						pmap_resident_count_dec(pmap, 1);
						KASSERT(mpte->ref_count == NPTEPG, ("pmap_remove_pages: pte page reference count error"));
						mpte->ref_count = 0;
						pmap_add_delayed_free_list(mpte, &free, FALSE);
					}
				} else {
					pmap_resident_count_dec(pmap, 1);
					TAILQ_REMOVE(&m->md.pv_list, pv, pv_next);
					m->md.pv_gen++;
					if ((m->aflags & PGA_WRITEABLE) != 0 && TAILQ_EMPTY(&m->md.pv_list) && (m->flags & PG_FICTITIOUS) == 0) {

						pvh = pa_to_pvh(VM_PAGE_TO_PHYS(m));
						if (TAILQ_EMPTY(&pvh->pv_list))
							vm_page_aflag_clear(m, PGA_WRITEABLE);
					}
				}
				pmap_unuse_pt(pmap, pv->pv_va, ptepde, &free);
				freed++;
			}
		}
		PV_STAT(atomic_add_long(&pv_entry_frees, freed));
		PV_STAT(atomic_add_int(&pv_entry_spare, freed));
		PV_STAT(atomic_subtract_long(&pv_entry_count, freed));
		if (allfree) {
			TAILQ_REMOVE(&pmap->pm_pvchunk, pc, pc_list);
			TAILQ_INSERT_TAIL(&free_chunks[pc_to_domain(pc)], pc, pc_list);
		}
	}
	if (lock != NULL)
		rw_wunlock(lock);
	pmap_invalidate_all(pmap);
	pmap_pkru_deassign_all(pmap);
	free_pv_chunk_batch((struct pv_chunklist *)&free_chunks);
	PMAP_UNLOCK(pmap);
	vm_page_free_pages_toq(&free, true);
}

static boolean_t pmap_page_test_mappings(vm_page_t m, boolean_t accessed, boolean_t modified)
{
	struct rwlock *lock;
	pv_entry_t pv;
	struct md_page *pvh;
	pt_entry_t *pte, mask;
	pt_entry_t PG_A, PG_M, PG_RW, PG_V;
	pmap_t pmap;
	int md_gen, pvh_gen;
	boolean_t rv;

	rv = FALSE;
	lock = VM_PAGE_TO_PV_LIST_LOCK(m);
	rw_rlock(lock);
restart:
	TAILQ_FOREACH(pv, &m->md.pv_list, pv_next) {
		pmap = PV_PMAP(pv);
		if (!PMAP_TRYLOCK(pmap)) {
			md_gen = m->md.pv_gen;
			rw_runlock(lock);
			PMAP_LOCK(pmap);
			rw_rlock(lock);
			if (md_gen != m->md.pv_gen) {
				PMAP_UNLOCK(pmap);
				goto restart;
			}
		}
		pte = pmap_pte(pmap, pv->pv_va);
		mask = 0;
		if (modified) {
			PG_M = pmap_modified_bit(pmap);
			PG_RW = pmap_rw_bit(pmap);
			mask |= PG_RW | PG_M;
		}
		if (accessed) {
			PG_A = pmap_accessed_bit(pmap);
			PG_V = pmap_valid_bit(pmap);
			mask |= PG_V | PG_A;
		}
		rv = (*pte & mask) == mask;
		PMAP_UNLOCK(pmap);
		if (rv)
			goto out;
	}
	if ((m->flags & PG_FICTITIOUS) == 0) {
		pvh = pa_to_pvh(VM_PAGE_TO_PHYS(m));
		TAILQ_FOREACH(pv, &pvh->pv_list, pv_next) {
			pmap = PV_PMAP(pv);
			if (!PMAP_TRYLOCK(pmap)) {
				md_gen = m->md.pv_gen;
				pvh_gen = pvh->pv_gen;
				rw_runlock(lock);
				PMAP_LOCK(pmap);
				rw_rlock(lock);
				if (md_gen != m->md.pv_gen || pvh_gen != pvh->pv_gen) {
					PMAP_UNLOCK(pmap);
					goto restart;
				}
			}
			pte = pmap_pde(pmap, pv->pv_va);
			mask = 0;
			if (modified) {
				PG_M = pmap_modified_bit(pmap);
				PG_RW = pmap_rw_bit(pmap);
				mask |= PG_RW | PG_M;
			}
			if (accessed) {
				PG_A = pmap_accessed_bit(pmap);
				PG_V = pmap_valid_bit(pmap);
				mask |= PG_V | PG_A;
			}
			rv = (*pte & mask) == mask;
			PMAP_UNLOCK(pmap);
			if (rv)
				goto out;
		}
	}
out:
	rw_runlock(lock);
	return (rv);
}


boolean_t pmap_is_modified(vm_page_t m)
{

	KASSERT((m->oflags & VPO_UNMANAGED) == 0, ("pmap_is_modified: page %p is not managed", m));

	
	if (!pmap_page_is_write_mapped(m))
		return (FALSE);
	return (pmap_page_test_mappings(m, FALSE, TRUE));
}


boolean_t pmap_is_prefaultable(pmap_t pmap, vm_offset_t addr)
{
	pd_entry_t *pde;
	pt_entry_t *pte, PG_V;
	boolean_t rv;

	PG_V = pmap_valid_bit(pmap);
	rv = FALSE;
	PMAP_LOCK(pmap);
	pde = pmap_pde(pmap, addr);
	if (pde != NULL && (*pde & (PG_PS | PG_V)) == PG_V) {
		pte = pmap_pde_to_pte(pde, addr);
		rv = (*pte & PG_V) == 0;
	}
	PMAP_UNLOCK(pmap);
	return (rv);
}


boolean_t pmap_is_referenced(vm_page_t m)
{

	KASSERT((m->oflags & VPO_UNMANAGED) == 0, ("pmap_is_referenced: page %p is not managed", m));
	return (pmap_page_test_mappings(m, TRUE, FALSE));
}


void pmap_remove_write(vm_page_t m)
{
	struct md_page *pvh;
	pmap_t pmap;
	struct rwlock *lock;
	pv_entry_t next_pv, pv;
	pd_entry_t *pde;
	pt_entry_t oldpte, *pte, PG_M, PG_RW;
	vm_offset_t va;
	int pvh_gen, md_gen;

	KASSERT((m->oflags & VPO_UNMANAGED) == 0, ("pmap_remove_write: page %p is not managed", m));

	vm_page_assert_busied(m);
	if (!pmap_page_is_write_mapped(m))
		return;

	lock = VM_PAGE_TO_PV_LIST_LOCK(m);
	pvh = (m->flags & PG_FICTITIOUS) != 0 ? &pv_dummy :
	    pa_to_pvh(VM_PAGE_TO_PHYS(m));
retry_pv_loop:
	rw_wlock(lock);
	TAILQ_FOREACH_SAFE(pv, &pvh->pv_list, pv_next, next_pv) {
		pmap = PV_PMAP(pv);
		if (!PMAP_TRYLOCK(pmap)) {
			pvh_gen = pvh->pv_gen;
			rw_wunlock(lock);
			PMAP_LOCK(pmap);
			rw_wlock(lock);
			if (pvh_gen != pvh->pv_gen) {
				PMAP_UNLOCK(pmap);
				rw_wunlock(lock);
				goto retry_pv_loop;
			}
		}
		PG_RW = pmap_rw_bit(pmap);
		va = pv->pv_va;
		pde = pmap_pde(pmap, va);
		if ((*pde & PG_RW) != 0)
			(void)pmap_demote_pde_locked(pmap, pde, va, &lock);
		KASSERT(lock == VM_PAGE_TO_PV_LIST_LOCK(m), ("inconsistent pv lock %p %p for page %p", lock, VM_PAGE_TO_PV_LIST_LOCK(m), m));

		PMAP_UNLOCK(pmap);
	}
	TAILQ_FOREACH(pv, &m->md.pv_list, pv_next) {
		pmap = PV_PMAP(pv);
		if (!PMAP_TRYLOCK(pmap)) {
			pvh_gen = pvh->pv_gen;
			md_gen = m->md.pv_gen;
			rw_wunlock(lock);
			PMAP_LOCK(pmap);
			rw_wlock(lock);
			if (pvh_gen != pvh->pv_gen || md_gen != m->md.pv_gen) {
				PMAP_UNLOCK(pmap);
				rw_wunlock(lock);
				goto retry_pv_loop;
			}
		}
		PG_M = pmap_modified_bit(pmap);
		PG_RW = pmap_rw_bit(pmap);
		pde = pmap_pde(pmap, pv->pv_va);
		KASSERT((*pde & PG_PS) == 0, ("pmap_remove_write: found a 2mpage in page %p's pv list", m));

		pte = pmap_pde_to_pte(pde, pv->pv_va);
retry:
		oldpte = *pte;
		if (oldpte & PG_RW) {
			if (!atomic_cmpset_long(pte, oldpte, oldpte & ~(PG_RW | PG_M)))
				goto retry;
			if ((oldpte & PG_M) != 0)
				vm_page_dirty(m);
			pmap_invalidate_page(pmap, pv->pv_va);
		}
		PMAP_UNLOCK(pmap);
	}
	rw_wunlock(lock);
	vm_page_aflag_clear(m, PGA_WRITEABLE);
	pmap_delayed_invl_wait(m);
}

static __inline boolean_t safe_to_clear_referenced(pmap_t pmap, pt_entry_t pte)
{

	if (!pmap_emulate_ad_bits(pmap))
		return (TRUE);

	KASSERT(pmap->pm_type == PT_EPT, ("invalid pm_type %d", pmap->pm_type));

	
	if ((pte & EPT_PG_WRITE) != 0)
		return (FALSE);

	
	if ((pte & EPT_PG_EXECUTE) == 0 || ((pmap->pm_flags & PMAP_SUPPORTS_EXEC_ONLY) != 0))
		return (TRUE);
	else return (FALSE);
}


int pmap_ts_referenced(vm_page_t m)
{
	struct md_page *pvh;
	pv_entry_t pv, pvf;
	pmap_t pmap;
	struct rwlock *lock;
	pd_entry_t oldpde, *pde;
	pt_entry_t *pte, PG_A, PG_M, PG_RW;
	vm_offset_t va;
	vm_paddr_t pa;
	int cleared, md_gen, not_cleared, pvh_gen;
	struct spglist free;
	boolean_t demoted;

	KASSERT((m->oflags & VPO_UNMANAGED) == 0, ("pmap_ts_referenced: page %p is not managed", m));
	SLIST_INIT(&free);
	cleared = 0;
	pa = VM_PAGE_TO_PHYS(m);
	lock = PHYS_TO_PV_LIST_LOCK(pa);
	pvh = (m->flags & PG_FICTITIOUS) != 0 ? &pv_dummy : pa_to_pvh(pa);
	rw_wlock(lock);
retry:
	not_cleared = 0;
	if ((pvf = TAILQ_FIRST(&pvh->pv_list)) == NULL)
		goto small_mappings;
	pv = pvf;
	do {
		if (pvf == NULL)
			pvf = pv;
		pmap = PV_PMAP(pv);
		if (!PMAP_TRYLOCK(pmap)) {
			pvh_gen = pvh->pv_gen;
			rw_wunlock(lock);
			PMAP_LOCK(pmap);
			rw_wlock(lock);
			if (pvh_gen != pvh->pv_gen) {
				PMAP_UNLOCK(pmap);
				goto retry;
			}
		}
		PG_A = pmap_accessed_bit(pmap);
		PG_M = pmap_modified_bit(pmap);
		PG_RW = pmap_rw_bit(pmap);
		va = pv->pv_va;
		pde = pmap_pde(pmap, pv->pv_va);
		oldpde = *pde;
		if ((oldpde & (PG_M | PG_RW)) == (PG_M | PG_RW)) {
			
			vm_page_dirty(m);
		}
		if ((oldpde & PG_A) != 0) {
			
			if ((((pa >> PAGE_SHIFT) ^ (pv->pv_va >> PDRSHIFT) ^ (uintptr_t)pmap) & (NPTEPG - 1)) == 0 && (oldpde & PG_W) == 0) {

				if (safe_to_clear_referenced(pmap, oldpde)) {
					atomic_clear_long(pde, PG_A);
					pmap_invalidate_page(pmap, pv->pv_va);
					demoted = FALSE;
				} else if (pmap_demote_pde_locked(pmap, pde, pv->pv_va, &lock)) {
					
					demoted = TRUE;
					va += VM_PAGE_TO_PHYS(m) - (oldpde & PG_PS_FRAME);
					pte = pmap_pde_to_pte(pde, va);
					pmap_remove_pte(pmap, pte, va, *pde, NULL, &lock);
					pmap_invalidate_page(pmap, va);
				} else demoted = TRUE;

				if (demoted) {
					
					if (pvf == pv)
						pvf = NULL;
					pv = NULL;
				}
				cleared++;
				KASSERT(lock == VM_PAGE_TO_PV_LIST_LOCK(m), ("inconsistent pv lock %p %p for page %p", lock, VM_PAGE_TO_PV_LIST_LOCK(m), m));

			} else not_cleared++;
		}
		PMAP_UNLOCK(pmap);
		
		if (pv != NULL && TAILQ_NEXT(pv, pv_next) != NULL) {
			TAILQ_REMOVE(&pvh->pv_list, pv, pv_next);
			TAILQ_INSERT_TAIL(&pvh->pv_list, pv, pv_next);
			pvh->pv_gen++;
		}
		if (cleared + not_cleared >= PMAP_TS_REFERENCED_MAX)
			goto out;
	} while ((pv = TAILQ_FIRST(&pvh->pv_list)) != pvf);
small_mappings:
	if ((pvf = TAILQ_FIRST(&m->md.pv_list)) == NULL)
		goto out;
	pv = pvf;
	do {
		if (pvf == NULL)
			pvf = pv;
		pmap = PV_PMAP(pv);
		if (!PMAP_TRYLOCK(pmap)) {
			pvh_gen = pvh->pv_gen;
			md_gen = m->md.pv_gen;
			rw_wunlock(lock);
			PMAP_LOCK(pmap);
			rw_wlock(lock);
			if (pvh_gen != pvh->pv_gen || md_gen != m->md.pv_gen) {
				PMAP_UNLOCK(pmap);
				goto retry;
			}
		}
		PG_A = pmap_accessed_bit(pmap);
		PG_M = pmap_modified_bit(pmap);
		PG_RW = pmap_rw_bit(pmap);
		pde = pmap_pde(pmap, pv->pv_va);
		KASSERT((*pde & PG_PS) == 0, ("pmap_ts_referenced: found a 2mpage in page %p's pv list", m));

		pte = pmap_pde_to_pte(pde, pv->pv_va);
		if ((*pte & (PG_M | PG_RW)) == (PG_M | PG_RW))
			vm_page_dirty(m);
		if ((*pte & PG_A) != 0) {
			if (safe_to_clear_referenced(pmap, *pte)) {
				atomic_clear_long(pte, PG_A);
				pmap_invalidate_page(pmap, pv->pv_va);
				cleared++;
			} else if ((*pte & PG_W) == 0) {
				
				pmap_remove_pte(pmap, pte, pv->pv_va, *pde, &free, &lock);
				pmap_invalidate_page(pmap, pv->pv_va);
				cleared++;
				if (pvf == pv)
					pvf = NULL;
				pv = NULL;
				KASSERT(lock == VM_PAGE_TO_PV_LIST_LOCK(m), ("inconsistent pv lock %p %p for page %p", lock, VM_PAGE_TO_PV_LIST_LOCK(m), m));

			} else not_cleared++;
		}
		PMAP_UNLOCK(pmap);
		
		if (pv != NULL && TAILQ_NEXT(pv, pv_next) != NULL) {
			TAILQ_REMOVE(&m->md.pv_list, pv, pv_next);
			TAILQ_INSERT_TAIL(&m->md.pv_list, pv, pv_next);
			m->md.pv_gen++;
		}
	} while ((pv = TAILQ_FIRST(&m->md.pv_list)) != pvf && cleared + not_cleared < PMAP_TS_REFERENCED_MAX);
out:
	rw_wunlock(lock);
	vm_page_free_pages_toq(&free, true);
	return (cleared + not_cleared);
}


void pmap_advise(pmap_t pmap, vm_offset_t sva, vm_offset_t eva, int advice)
{
	struct rwlock *lock;
	pml4_entry_t *pml4e;
	pdp_entry_t *pdpe;
	pd_entry_t oldpde, *pde;
	pt_entry_t *pte, PG_A, PG_G, PG_M, PG_RW, PG_V;
	vm_offset_t va, va_next;
	vm_page_t m;
	bool anychanged;

	if (advice != MADV_DONTNEED && advice != MADV_FREE)
		return;

	
	if (pmap_emulate_ad_bits(pmap))
		return;

	PG_A = pmap_accessed_bit(pmap);
	PG_G = pmap_global_bit(pmap);
	PG_M = pmap_modified_bit(pmap);
	PG_V = pmap_valid_bit(pmap);
	PG_RW = pmap_rw_bit(pmap);
	anychanged = false;
	pmap_delayed_invl_start();
	PMAP_LOCK(pmap);
	for (; sva < eva; sva = va_next) {
		pml4e = pmap_pml4e(pmap, sva);
		if ((*pml4e & PG_V) == 0) {
			va_next = (sva + NBPML4) & ~PML4MASK;
			if (va_next < sva)
				va_next = eva;
			continue;
		}
		pdpe = pmap_pml4e_to_pdpe(pml4e, sva);
		if ((*pdpe & PG_V) == 0) {
			va_next = (sva + NBPDP) & ~PDPMASK;
			if (va_next < sva)
				va_next = eva;
			continue;
		}
		va_next = (sva + NBPDR) & ~PDRMASK;
		if (va_next < sva)
			va_next = eva;
		pde = pmap_pdpe_to_pde(pdpe, sva);
		oldpde = *pde;
		if ((oldpde & PG_V) == 0)
			continue;
		else if ((oldpde & PG_PS) != 0) {
			if ((oldpde & PG_MANAGED) == 0)
				continue;
			lock = NULL;
			if (!pmap_demote_pde_locked(pmap, pde, sva, &lock)) {
				if (lock != NULL)
					rw_wunlock(lock);

				
				continue;
			}

			
			if ((oldpde & PG_W) == 0) {
				va = eva;
				if (va > va_next)
					va = va_next;
				va -= PAGE_SIZE;
				KASSERT(va >= sva, ("pmap_advise: no address gap"));
				pte = pmap_pde_to_pte(pde, va);
				KASSERT((*pte & PG_V) != 0, ("pmap_advise: invalid PTE"));
				pmap_remove_pte(pmap, pte, va, *pde, NULL, &lock);
				anychanged = true;
			}
			if (lock != NULL)
				rw_wunlock(lock);
		}
		if (va_next > eva)
			va_next = eva;
		va = va_next;
		for (pte = pmap_pde_to_pte(pde, sva); sva != va_next; pte++, sva += PAGE_SIZE) {
			if ((*pte & (PG_MANAGED | PG_V)) != (PG_MANAGED | PG_V))
				goto maybe_invlrng;
			else if ((*pte & (PG_M | PG_RW)) == (PG_M | PG_RW)) {
				if (advice == MADV_DONTNEED) {
					
					m = PHYS_TO_VM_PAGE(*pte & PG_FRAME);
					vm_page_dirty(m);
				}
				atomic_clear_long(pte, PG_M | PG_A);
			} else if ((*pte & PG_A) != 0)
				atomic_clear_long(pte, PG_A);
			else goto maybe_invlrng;

			if ((*pte & PG_G) != 0) {
				if (va == va_next)
					va = sva;
			} else anychanged = true;
			continue;
maybe_invlrng:
			if (va != va_next) {
				pmap_invalidate_range(pmap, va, sva);
				va = va_next;
			}
		}
		if (va != va_next)
			pmap_invalidate_range(pmap, va, sva);
	}
	if (anychanged)
		pmap_invalidate_all(pmap);
	PMAP_UNLOCK(pmap);
	pmap_delayed_invl_finish();
}


void pmap_clear_modify(vm_page_t m)
{
	struct md_page *pvh;
	pmap_t pmap;
	pv_entry_t next_pv, pv;
	pd_entry_t oldpde, *pde;
	pt_entry_t *pte, PG_M, PG_RW;
	struct rwlock *lock;
	vm_offset_t va;
	int md_gen, pvh_gen;

	KASSERT((m->oflags & VPO_UNMANAGED) == 0, ("pmap_clear_modify: page %p is not managed", m));
	vm_page_assert_busied(m);

	if (!pmap_page_is_write_mapped(m))
		return;
	pvh = (m->flags & PG_FICTITIOUS) != 0 ? &pv_dummy :
	    pa_to_pvh(VM_PAGE_TO_PHYS(m));
	lock = VM_PAGE_TO_PV_LIST_LOCK(m);
	rw_wlock(lock);
restart:
	TAILQ_FOREACH_SAFE(pv, &pvh->pv_list, pv_next, next_pv) {
		pmap = PV_PMAP(pv);
		if (!PMAP_TRYLOCK(pmap)) {
			pvh_gen = pvh->pv_gen;
			rw_wunlock(lock);
			PMAP_LOCK(pmap);
			rw_wlock(lock);
			if (pvh_gen != pvh->pv_gen) {
				PMAP_UNLOCK(pmap);
				goto restart;
			}
		}
		PG_M = pmap_modified_bit(pmap);
		PG_RW = pmap_rw_bit(pmap);
		va = pv->pv_va;
		pde = pmap_pde(pmap, va);
		oldpde = *pde;
		
		if ((oldpde & PG_RW) != 0 && pmap_demote_pde_locked(pmap, pde, va, &lock) && (oldpde & PG_W) == 0) {

			
			va += VM_PAGE_TO_PHYS(m) - (oldpde & PG_PS_FRAME);
			pte = pmap_pde_to_pte(pde, va);
			atomic_clear_long(pte, PG_M | PG_RW);
			vm_page_dirty(m);
			pmap_invalidate_page(pmap, va);
		}
		PMAP_UNLOCK(pmap);
	}
	TAILQ_FOREACH(pv, &m->md.pv_list, pv_next) {
		pmap = PV_PMAP(pv);
		if (!PMAP_TRYLOCK(pmap)) {
			md_gen = m->md.pv_gen;
			pvh_gen = pvh->pv_gen;
			rw_wunlock(lock);
			PMAP_LOCK(pmap);
			rw_wlock(lock);
			if (pvh_gen != pvh->pv_gen || md_gen != m->md.pv_gen) {
				PMAP_UNLOCK(pmap);
				goto restart;
			}
		}
		PG_M = pmap_modified_bit(pmap);
		PG_RW = pmap_rw_bit(pmap);
		pde = pmap_pde(pmap, pv->pv_va);
		KASSERT((*pde & PG_PS) == 0, ("pmap_clear_modify: found" " a 2mpage in page %p's pv list", m));
		pte = pmap_pde_to_pte(pde, pv->pv_va);
		if ((*pte & (PG_M | PG_RW)) == (PG_M | PG_RW)) {
			atomic_clear_long(pte, PG_M);
			pmap_invalidate_page(pmap, pv->pv_va);
		}
		PMAP_UNLOCK(pmap);
	}
	rw_wunlock(lock);
}




static __inline void pmap_pte_props(pt_entry_t *pte, u_long bits, u_long mask)
{
	u_long opte, npte;

	opte = *(u_long *)pte;
	do {
		npte = opte & ~mask;
		npte |= bits;
	} while (npte != opte && !atomic_fcmpset_long((u_long *)pte, &opte, npte));
}


static void * pmap_mapdev_internal(vm_paddr_t pa, vm_size_t size, int mode, int flags)
{
	struct pmap_preinit_mapping *ppim;
	vm_offset_t va, offset;
	vm_size_t tmpsize;
	int i;

	offset = pa & PAGE_MASK;
	size = round_page(offset + size);
	pa = trunc_page(pa);

	if (!pmap_initialized) {
		va = 0;
		for (i = 0; i < PMAP_PREINIT_MAPPING_COUNT; i++) {
			ppim = pmap_preinit_mapping + i;
			if (ppim->va == 0) {
				ppim->pa = pa;
				ppim->sz = size;
				ppim->mode = mode;
				ppim->va = virtual_avail;
				virtual_avail += size;
				va = ppim->va;
				break;
			}
		}
		if (va == 0)
			panic("%s: too many preinit mappings", __func__);
	} else {
		
		for (i = 0; i < PMAP_PREINIT_MAPPING_COUNT; i++) {
			ppim = pmap_preinit_mapping + i;
			if (ppim->pa == pa && ppim->sz == size && (ppim->mode == mode || (flags & MAPDEV_SETATTR) == 0))

				return ((void *)(ppim->va + offset));
		}
		
		if (pa < dmaplimit && pa + size <= dmaplimit) {
			va = PHYS_TO_DMAP(pa);
			if ((flags & MAPDEV_SETATTR) != 0) {
				PMAP_LOCK(kernel_pmap);
				i = pmap_change_props_locked(va, size, PROT_NONE, mode, flags);
				PMAP_UNLOCK(kernel_pmap);
			} else i = 0;
			if (!i)
				return ((void *)(va + offset));
		}
		va = kva_alloc(size);
		if (va == 0)
			panic("%s: Couldn't allocate KVA", __func__);
	}
	for (tmpsize = 0; tmpsize < size; tmpsize += PAGE_SIZE)
		pmap_kenter_attr(va + tmpsize, pa + tmpsize, mode);
	pmap_invalidate_range(kernel_pmap, va, va + tmpsize);
	if ((flags & MAPDEV_FLUSHCACHE) != 0)
		pmap_invalidate_cache_range(va, va + tmpsize);
	return ((void *)(va + offset));
}

void * pmap_mapdev_attr(vm_paddr_t pa, vm_size_t size, int mode)
{

	return (pmap_mapdev_internal(pa, size, mode, MAPDEV_FLUSHCACHE | MAPDEV_SETATTR));
}

void * pmap_mapdev(vm_paddr_t pa, vm_size_t size)
{

	return (pmap_mapdev_attr(pa, size, PAT_UNCACHEABLE));
}

void * pmap_mapdev_pciecfg(vm_paddr_t pa, vm_size_t size)
{

	return (pmap_mapdev_internal(pa, size, PAT_UNCACHEABLE, MAPDEV_SETATTR));
}

void * pmap_mapbios(vm_paddr_t pa, vm_size_t size)
{

	return (pmap_mapdev_internal(pa, size, PAT_WRITE_BACK, MAPDEV_FLUSHCACHE));
}

void pmap_unmapdev(vm_offset_t va, vm_size_t size)
{
	struct pmap_preinit_mapping *ppim;
	vm_offset_t offset;
	int i;

	
	if (va >= DMAP_MIN_ADDRESS && va < DMAP_MAX_ADDRESS)
		return;
	offset = va & PAGE_MASK;
	size = round_page(offset + size);
	va = trunc_page(va);
	for (i = 0; i < PMAP_PREINIT_MAPPING_COUNT; i++) {
		ppim = pmap_preinit_mapping + i;
		if (ppim->va == va && ppim->sz == size) {
			if (pmap_initialized)
				return;
			ppim->pa = 0;
			ppim->va = 0;
			ppim->sz = 0;
			ppim->mode = 0;
			if (va + size == virtual_avail)
				virtual_avail = va;
			return;
		}
	}
	if (pmap_initialized)
		kva_free(va, size);
}


static boolean_t pmap_demote_pdpe(pmap_t pmap, pdp_entry_t *pdpe, vm_offset_t va)
{
	pdp_entry_t newpdpe, oldpdpe;
	pd_entry_t *firstpde, newpde, *pde;
	pt_entry_t PG_A, PG_M, PG_RW, PG_V;
	vm_paddr_t pdpgpa;
	vm_page_t pdpg;

	PG_A = pmap_accessed_bit(pmap);
	PG_M = pmap_modified_bit(pmap);
	PG_V = pmap_valid_bit(pmap);
	PG_RW = pmap_rw_bit(pmap);

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	oldpdpe = *pdpe;
	KASSERT((oldpdpe & (PG_PS | PG_V)) == (PG_PS | PG_V), ("pmap_demote_pdpe: oldpdpe is missing PG_PS and/or PG_V"));
	if ((pdpg = vm_page_alloc(NULL, va >> PDPSHIFT, VM_ALLOC_INTERRUPT | VM_ALLOC_NOOBJ | VM_ALLOC_WIRED)) == NULL) {
		CTR2(KTR_PMAP, "pmap_demote_pdpe: failure for va %#lx" " in pmap %p", va, pmap);
		return (FALSE);
	}
	pdpgpa = VM_PAGE_TO_PHYS(pdpg);
	firstpde = (pd_entry_t *)PHYS_TO_DMAP(pdpgpa);
	newpdpe = pdpgpa | PG_M | PG_A | (oldpdpe & PG_U) | PG_RW | PG_V;
	KASSERT((oldpdpe & PG_A) != 0, ("pmap_demote_pdpe: oldpdpe is missing PG_A"));
	KASSERT((oldpdpe & (PG_M | PG_RW)) != PG_RW, ("pmap_demote_pdpe: oldpdpe is missing PG_M"));
	newpde = oldpdpe;

	
	for (pde = firstpde; pde < firstpde + NPDEPG; pde++) {
		*pde = newpde;
		newpde += NBPDR;
	}

	
	*pdpe = newpdpe;

	
	pmap_invalidate_page(pmap, (vm_offset_t)vtopde(va));

	pmap_pdpe_demotions++;
	CTR2(KTR_PMAP, "pmap_demote_pdpe: success for va %#lx" " in pmap %p", va, pmap);
	return (TRUE);
}


void pmap_page_set_memattr(vm_page_t m, vm_memattr_t ma)
{

	m->md.pat_mode = ma;

	
	if ((m->flags & PG_FICTITIOUS) == 0 && pmap_change_attr(PHYS_TO_DMAP(VM_PAGE_TO_PHYS(m)), PAGE_SIZE, m->md.pat_mode))

		panic("memory attribute change on the direct map failed");
}


int pmap_change_attr(vm_offset_t va, vm_size_t size, int mode)
{
	int error;

	PMAP_LOCK(kernel_pmap);
	error = pmap_change_props_locked(va, size, PROT_NONE, mode, MAPDEV_FLUSHCACHE);
	PMAP_UNLOCK(kernel_pmap);
	return (error);
}


int pmap_change_prot(vm_offset_t va, vm_size_t size, vm_prot_t prot)
{
	int error;

	
	if (va < VM_MIN_KERNEL_ADDRESS)
		return (EINVAL);

	PMAP_LOCK(kernel_pmap);
	error = pmap_change_props_locked(va, size, prot, -1, MAPDEV_ASSERTVALID);
	PMAP_UNLOCK(kernel_pmap);
	return (error);
}

static int pmap_change_props_locked(vm_offset_t va, vm_size_t size, vm_prot_t prot, int mode, int flags)

{
	vm_offset_t base, offset, tmpva;
	vm_paddr_t pa_start, pa_end, pa_end1;
	pdp_entry_t *pdpe;
	pd_entry_t *pde, pde_bits, pde_mask;
	pt_entry_t *pte, pte_bits, pte_mask;
	int error;
	bool changed;

	PMAP_LOCK_ASSERT(kernel_pmap, MA_OWNED);
	base = trunc_page(va);
	offset = va & PAGE_MASK;
	size = round_page(offset + size);

	
	if (base < DMAP_MIN_ADDRESS)
		return (EINVAL);

	
	pde_bits = pte_bits = 0;
	pde_mask = pte_mask = 0;
	if (mode != -1) {
		pde_bits |= pmap_cache_bits(kernel_pmap, mode, true);
		pde_mask |= X86_PG_PDE_CACHE;
		pte_bits |= pmap_cache_bits(kernel_pmap, mode, false);
		pte_mask |= X86_PG_PTE_CACHE;
	}
	if (prot != VM_PROT_NONE) {
		if ((prot & VM_PROT_WRITE) != 0) {
			pde_bits |= X86_PG_RW;
			pte_bits |= X86_PG_RW;
		}
		if ((prot & VM_PROT_EXECUTE) == 0 || va < VM_MIN_KERNEL_ADDRESS) {
			pde_bits |= pg_nx;
			pte_bits |= pg_nx;
		}
		pde_mask |= X86_PG_RW | pg_nx;
		pte_mask |= X86_PG_RW | pg_nx;
	}

	
	for (tmpva = base; tmpva < base + size; ) {
		pdpe = pmap_pdpe(kernel_pmap, tmpva);
		if (pdpe == NULL || *pdpe == 0) {
			KASSERT((flags & MAPDEV_ASSERTVALID) == 0, ("%s: addr %#lx is not mapped", __func__, tmpva));
			return (EINVAL);
		}
		if (*pdpe & PG_PS) {
			
			if ((*pdpe & pde_mask) == pde_bits) {
				tmpva = trunc_1gpage(tmpva) + NBPDP;
				continue;
			}

			
			if ((tmpva & PDPMASK) == 0 && tmpva + PDPMASK < base + size) {
				tmpva += NBPDP;
				continue;
			}
			if (!pmap_demote_pdpe(kernel_pmap, pdpe, tmpva))
				return (ENOMEM);
		}
		pde = pmap_pdpe_to_pde(pdpe, tmpva);
		if (*pde == 0) {
			KASSERT((flags & MAPDEV_ASSERTVALID) == 0, ("%s: addr %#lx is not mapped", __func__, tmpva));
			return (EINVAL);
		}
		if (*pde & PG_PS) {
			
			if ((*pde & pde_mask) == pde_bits) {
				tmpva = trunc_2mpage(tmpva) + NBPDR;
				continue;
			}

			
			if ((tmpva & PDRMASK) == 0 && tmpva + PDRMASK < base + size) {
				tmpva += NBPDR;
				continue;
			}
			if (!pmap_demote_pde(kernel_pmap, pde, tmpva))
				return (ENOMEM);
		}
		pte = pmap_pde_to_pte(pde, tmpva);
		if (*pte == 0) {
			KASSERT((flags & MAPDEV_ASSERTVALID) == 0, ("%s: addr %#lx is not mapped", __func__, tmpva));
			return (EINVAL);
		}
		tmpva += PAGE_SIZE;
	}
	error = 0;

	
	changed = false;
	pa_start = pa_end = 0;
	for (tmpva = base; tmpva < base + size; ) {
		pdpe = pmap_pdpe(kernel_pmap, tmpva);
		if (*pdpe & PG_PS) {
			if ((*pdpe & pde_mask) != pde_bits) {
				pmap_pte_props(pdpe, pde_bits, pde_mask);
				changed = true;
			}
			if (tmpva >= VM_MIN_KERNEL_ADDRESS && (*pdpe & PG_PS_FRAME) < dmaplimit) {
				if (pa_start == pa_end) {
					
					pa_start = *pdpe & PG_PS_FRAME;
					pa_end = pa_start + NBPDP;
				} else if (pa_end == (*pdpe & PG_PS_FRAME))
					pa_end += NBPDP;
				else {
					
					error = pmap_change_props_locked( PHYS_TO_DMAP(pa_start), pa_end - pa_start, prot, mode, flags);


					if (error != 0)
						break;
					
					pa_start = *pdpe & PG_PS_FRAME;
					pa_end = pa_start + NBPDP;
				}
			}
			tmpva = trunc_1gpage(tmpva) + NBPDP;
			continue;
		}
		pde = pmap_pdpe_to_pde(pdpe, tmpva);
		if (*pde & PG_PS) {
			if ((*pde & pde_mask) != pde_bits) {
				pmap_pte_props(pde, pde_bits, pde_mask);
				changed = true;
			}
			if (tmpva >= VM_MIN_KERNEL_ADDRESS && (*pde & PG_PS_FRAME) < dmaplimit) {
				if (pa_start == pa_end) {
					
					pa_start = *pde & PG_PS_FRAME;
					pa_end = pa_start + NBPDR;
				} else if (pa_end == (*pde & PG_PS_FRAME))
					pa_end += NBPDR;
				else {
					
					error = pmap_change_props_locked( PHYS_TO_DMAP(pa_start), pa_end - pa_start, prot, mode, flags);


					if (error != 0)
						break;
					
					pa_start = *pde & PG_PS_FRAME;
					pa_end = pa_start + NBPDR;
				}
			}
			tmpva = trunc_2mpage(tmpva) + NBPDR;
		} else {
			pte = pmap_pde_to_pte(pde, tmpva);
			if ((*pte & pte_mask) != pte_bits) {
				pmap_pte_props(pte, pte_bits, pte_mask);
				changed = true;
			}
			if (tmpva >= VM_MIN_KERNEL_ADDRESS && (*pte & PG_FRAME) < dmaplimit) {
				if (pa_start == pa_end) {
					
					pa_start = *pte & PG_FRAME;
					pa_end = pa_start + PAGE_SIZE;
				} else if (pa_end == (*pte & PG_FRAME))
					pa_end += PAGE_SIZE;
				else {
					
					error = pmap_change_props_locked( PHYS_TO_DMAP(pa_start), pa_end - pa_start, prot, mode, flags);


					if (error != 0)
						break;
					
					pa_start = *pte & PG_FRAME;
					pa_end = pa_start + PAGE_SIZE;
				}
			}
			tmpva += PAGE_SIZE;
		}
	}
	if (error == 0 && pa_start != pa_end && pa_start < dmaplimit) {
		pa_end1 = MIN(pa_end, dmaplimit);
		if (pa_start != pa_end1)
			error = pmap_change_props_locked(PHYS_TO_DMAP(pa_start), pa_end1 - pa_start, prot, mode, flags);
	}

	
	if (changed) {
		pmap_invalidate_range(kernel_pmap, base, tmpva);
		if ((flags & MAPDEV_FLUSHCACHE) != 0)
			pmap_invalidate_cache_range(base, tmpva);
	}
	return (error);
}


void pmap_demote_DMAP(vm_paddr_t base, vm_size_t len, boolean_t invalidate)
{
	pdp_entry_t *pdpe;
	pd_entry_t *pde;
	vm_offset_t va;
	boolean_t changed;

	if (len == 0)
		return;
	KASSERT(powerof2(len), ("pmap_demote_DMAP: len is not a power of 2"));
	KASSERT((base & (len - 1)) == 0, ("pmap_demote_DMAP: base is not a multiple of len"));
	if (len < NBPDP && base < dmaplimit) {
		va = PHYS_TO_DMAP(base);
		changed = FALSE;
		PMAP_LOCK(kernel_pmap);
		pdpe = pmap_pdpe(kernel_pmap, va);
		if ((*pdpe & X86_PG_V) == 0)
			panic("pmap_demote_DMAP: invalid PDPE");
		if ((*pdpe & PG_PS) != 0) {
			if (!pmap_demote_pdpe(kernel_pmap, pdpe, va))
				panic("pmap_demote_DMAP: PDPE failed");
			changed = TRUE;
		}
		if (len < NBPDR) {
			pde = pmap_pdpe_to_pde(pdpe, va);
			if ((*pde & X86_PG_V) == 0)
				panic("pmap_demote_DMAP: invalid PDE");
			if ((*pde & PG_PS) != 0) {
				if (!pmap_demote_pde(kernel_pmap, pde, va))
					panic("pmap_demote_DMAP: PDE failed");
				changed = TRUE;
			}
		}
		if (changed && invalidate)
			pmap_invalidate_page(kernel_pmap, va);
		PMAP_UNLOCK(kernel_pmap);
	}
}


int pmap_mincore(pmap_t pmap, vm_offset_t addr, vm_paddr_t *pap)
{
	pd_entry_t *pdep;
	pt_entry_t pte, PG_A, PG_M, PG_RW, PG_V;
	vm_paddr_t pa;
	int val;

	PG_A = pmap_accessed_bit(pmap);
	PG_M = pmap_modified_bit(pmap);
	PG_V = pmap_valid_bit(pmap);
	PG_RW = pmap_rw_bit(pmap);

	PMAP_LOCK(pmap);
	pdep = pmap_pde(pmap, addr);
	if (pdep != NULL && (*pdep & PG_V)) {
		if (*pdep & PG_PS) {
			pte = *pdep;
			
			pa = ((*pdep & PG_PS_FRAME) | (addr & PDRMASK)) & PG_FRAME;
			val = MINCORE_SUPER;
		} else {
			pte = *pmap_pde_to_pte(pdep, addr);
			pa = pte & PG_FRAME;
			val = 0;
		}
	} else {
		pte = 0;
		pa = 0;
		val = 0;
	}
	if ((pte & PG_V) != 0) {
		val |= MINCORE_INCORE;
		if ((pte & (PG_M | PG_RW)) == (PG_M | PG_RW))
			val |= MINCORE_MODIFIED | MINCORE_MODIFIED_OTHER;
		if ((pte & PG_A) != 0)
			val |= MINCORE_REFERENCED | MINCORE_REFERENCED_OTHER;
	}
	if ((val & (MINCORE_MODIFIED_OTHER | MINCORE_REFERENCED_OTHER)) != (MINCORE_MODIFIED_OTHER | MINCORE_REFERENCED_OTHER) && (pte & (PG_MANAGED | PG_V)) == (PG_MANAGED | PG_V)) {

		*pap = pa;
	}
	PMAP_UNLOCK(pmap);
	return (val);
}

static uint64_t pmap_pcid_alloc(pmap_t pmap, u_int cpuid)
{
	uint32_t gen, new_gen, pcid_next;

	CRITICAL_ASSERT(curthread);
	gen = PCPU_GET(pcid_gen);
	if (pmap->pm_pcids[cpuid].pm_pcid == PMAP_PCID_KERN)
		return (pti ? 0 : CR3_PCID_SAVE);
	if (pmap->pm_pcids[cpuid].pm_gen == gen)
		return (CR3_PCID_SAVE);
	pcid_next = PCPU_GET(pcid_next);
	KASSERT((!pti && pcid_next <= PMAP_PCID_OVERMAX) || (pti && pcid_next <= PMAP_PCID_OVERMAX_KERN), ("cpu %d pcid_next %#x", cpuid, pcid_next));

	if ((!pti && pcid_next == PMAP_PCID_OVERMAX) || (pti && pcid_next == PMAP_PCID_OVERMAX_KERN)) {
		new_gen = gen + 1;
		if (new_gen == 0)
			new_gen = 1;
		PCPU_SET(pcid_gen, new_gen);
		pcid_next = PMAP_PCID_KERN + 1;
	} else {
		new_gen = gen;
	}
	pmap->pm_pcids[cpuid].pm_pcid = pcid_next;
	pmap->pm_pcids[cpuid].pm_gen = new_gen;
	PCPU_SET(pcid_next, pcid_next + 1);
	return (0);
}

static uint64_t pmap_pcid_alloc_checked(pmap_t pmap, u_int cpuid)
{
	uint64_t cached;

	cached = pmap_pcid_alloc(pmap, cpuid);
	KASSERT(pmap->pm_pcids[cpuid].pm_pcid < PMAP_PCID_OVERMAX, ("pmap %p cpu %d pcid %#x", pmap, cpuid, pmap->pm_pcids[cpuid].pm_pcid));

	KASSERT(pmap->pm_pcids[cpuid].pm_pcid != PMAP_PCID_KERN || pmap == kernel_pmap, ("non-kernel pmap pmap %p cpu %d pcid %#x", pmap, cpuid, pmap->pm_pcids[cpuid].pm_pcid));


	return (cached);
}

static void pmap_activate_sw_pti_post(struct thread *td, pmap_t pmap)
{

	PCPU_GET(tssp)->tss_rsp0 = pmap->pm_ucr3 != PMAP_NO_CR3 ? PCPU_GET(pti_rsp0) : (uintptr_t)td->td_md.md_stack_base;
}

static void inline pmap_activate_sw_pcid_pti(pmap_t pmap, u_int cpuid, const bool invpcid_works1)
{
	struct invpcid_descr d;
	uint64_t cached, cr3, kcr3, ucr3;

	cached = pmap_pcid_alloc_checked(pmap, cpuid);
	cr3 = rcr3();
	if ((cr3 & ~CR3_PCID_MASK) != pmap->pm_cr3)
		load_cr3(pmap->pm_cr3 | pmap->pm_pcids[cpuid].pm_pcid);
	PCPU_SET(curpmap, pmap);
	kcr3 = pmap->pm_cr3 | pmap->pm_pcids[cpuid].pm_pcid;
	ucr3 = pmap->pm_ucr3 | pmap->pm_pcids[cpuid].pm_pcid | PMAP_PCID_USER_PT;

	if (!cached && pmap->pm_ucr3 != PMAP_NO_CR3) {
		
		if (invpcid_works1) {
			d.pcid = PMAP_PCID_USER_PT | pmap->pm_pcids[cpuid].pm_pcid;
			d.pad = 0;
			d.addr = 0;
			invpcid(&d, INVPCID_CTX);
		} else {
			pmap_pti_pcid_invalidate(ucr3, kcr3);
		}
	}

	PCPU_SET(kcr3, kcr3 | CR3_PCID_SAVE);
	PCPU_SET(ucr3, ucr3 | CR3_PCID_SAVE);
	if (cached)
		PCPU_INC(pm_save_cnt);
}

static void pmap_activate_sw_pcid_invpcid_pti(struct thread *td, pmap_t pmap, u_int cpuid)
{

	pmap_activate_sw_pcid_pti(pmap, cpuid, true);
	pmap_activate_sw_pti_post(td, pmap);
}

static void pmap_activate_sw_pcid_noinvpcid_pti(struct thread *td, pmap_t pmap, u_int cpuid)

{
	register_t rflags;

	
	rflags = intr_disable();
	pmap_activate_sw_pcid_pti(pmap, cpuid, false);
	intr_restore(rflags);
	pmap_activate_sw_pti_post(td, pmap);
}

static void pmap_activate_sw_pcid_nopti(struct thread *td __unused, pmap_t pmap, u_int cpuid)

{
	uint64_t cached, cr3;

	cached = pmap_pcid_alloc_checked(pmap, cpuid);
	cr3 = rcr3();
	if (!cached || (cr3 & ~CR3_PCID_MASK) != pmap->pm_cr3)
		load_cr3(pmap->pm_cr3 | pmap->pm_pcids[cpuid].pm_pcid | cached);
	PCPU_SET(curpmap, pmap);
	if (cached)
		PCPU_INC(pm_save_cnt);
}

static void pmap_activate_sw_pcid_noinvpcid_nopti(struct thread *td __unused, pmap_t pmap, u_int cpuid)

{
	register_t rflags;

	rflags = intr_disable();
	pmap_activate_sw_pcid_nopti(td, pmap, cpuid);
	intr_restore(rflags);
}

static void pmap_activate_sw_nopcid_nopti(struct thread *td __unused, pmap_t pmap, u_int cpuid __unused)

{

	load_cr3(pmap->pm_cr3);
	PCPU_SET(curpmap, pmap);
}

static void pmap_activate_sw_nopcid_pti(struct thread *td, pmap_t pmap, u_int cpuid __unused)

{

	pmap_activate_sw_nopcid_nopti(td, pmap, cpuid);
	PCPU_SET(kcr3, pmap->pm_cr3);
	PCPU_SET(ucr3, pmap->pm_ucr3);
	pmap_activate_sw_pti_post(td, pmap);
}

DEFINE_IFUNC(static, void, pmap_activate_sw_mode, (struct thread *, pmap_t, u_int))
{

	if (pmap_pcid_enabled && pti && invpcid_works)
		return (pmap_activate_sw_pcid_invpcid_pti);
	else if (pmap_pcid_enabled && pti && !invpcid_works)
		return (pmap_activate_sw_pcid_noinvpcid_pti);
	else if (pmap_pcid_enabled && !pti && invpcid_works)
		return (pmap_activate_sw_pcid_nopti);
	else if (pmap_pcid_enabled && !pti && !invpcid_works)
		return (pmap_activate_sw_pcid_noinvpcid_nopti);
	else if (!pmap_pcid_enabled && pti)
		return (pmap_activate_sw_nopcid_pti);
	else  return (pmap_activate_sw_nopcid_nopti);
}

void pmap_activate_sw(struct thread *td)
{
	pmap_t oldpmap, pmap;
	u_int cpuid;

	oldpmap = PCPU_GET(curpmap);
	pmap = vmspace_pmap(td->td_proc->p_vmspace);
	if (oldpmap == pmap) {
		if (cpu_vendor_id != CPU_VENDOR_INTEL)
			mfence();
		return;
	}
	cpuid = PCPU_GET(cpuid);

	CPU_SET_ATOMIC(cpuid, &pmap->pm_active);

	CPU_SET(cpuid, &pmap->pm_active);

	pmap_activate_sw_mode(td, pmap, cpuid);

	CPU_CLR_ATOMIC(cpuid, &oldpmap->pm_active);

	CPU_CLR(cpuid, &oldpmap->pm_active);

}

void pmap_activate(struct thread *td)
{

	critical_enter();
	pmap_activate_sw(td);
	critical_exit();
}

void pmap_activate_boot(pmap_t pmap)
{
	uint64_t kcr3;
	u_int cpuid;

	
	MPASS(pmap != kernel_pmap);

	cpuid = PCPU_GET(cpuid);

	CPU_SET_ATOMIC(cpuid, &pmap->pm_active);

	CPU_SET(cpuid, &pmap->pm_active);

	PCPU_SET(curpmap, pmap);
	if (pti) {
		kcr3 = pmap->pm_cr3;
		if (pmap_pcid_enabled)
			kcr3 |= pmap->pm_pcids[cpuid].pm_pcid | CR3_PCID_SAVE;
	} else {
		kcr3 = PMAP_NO_CR3;
	}
	PCPU_SET(kcr3, kcr3);
	PCPU_SET(ucr3, PMAP_NO_CR3);
}

void pmap_sync_icache(pmap_t pm, vm_offset_t va, vm_size_t sz)
{
}


void pmap_align_superpage(vm_object_t object, vm_ooffset_t offset, vm_offset_t *addr, vm_size_t size)

{
	vm_offset_t superpage_offset;

	if (size < NBPDR)
		return;
	if (object != NULL && (object->flags & OBJ_COLORED) != 0)
		offset += ptoa(object->pg_color);
	superpage_offset = offset & PDRMASK;
	if (size - ((NBPDR - superpage_offset) & PDRMASK) < NBPDR || (*addr & PDRMASK) == superpage_offset)
		return;
	if ((*addr & PDRMASK) < superpage_offset)
		*addr = (*addr & ~PDRMASK) + superpage_offset;
	else *addr = ((*addr + PDRMASK) & ~PDRMASK) + superpage_offset;
}


static unsigned long num_dirty_emulations;
SYSCTL_ULONG(_vm_pmap, OID_AUTO, num_dirty_emulations, CTLFLAG_RW, &num_dirty_emulations, 0, NULL);

static unsigned long num_accessed_emulations;
SYSCTL_ULONG(_vm_pmap, OID_AUTO, num_accessed_emulations, CTLFLAG_RW, &num_accessed_emulations, 0, NULL);

static unsigned long num_superpage_accessed_emulations;
SYSCTL_ULONG(_vm_pmap, OID_AUTO, num_superpage_accessed_emulations, CTLFLAG_RW, &num_superpage_accessed_emulations, 0, NULL);

static unsigned long ad_emulation_superpage_promotions;
SYSCTL_ULONG(_vm_pmap, OID_AUTO, ad_emulation_superpage_promotions, CTLFLAG_RW, &ad_emulation_superpage_promotions, 0, NULL);


int pmap_emulate_accessed_dirty(pmap_t pmap, vm_offset_t va, int ftype)
{
	int rv;
	struct rwlock *lock;

	vm_page_t m, mpte;

	pd_entry_t *pde;
	pt_entry_t *pte, PG_A, PG_M, PG_RW, PG_V;

	KASSERT(ftype == VM_PROT_READ || ftype == VM_PROT_WRITE, ("pmap_emulate_accessed_dirty: invalid fault type %d", ftype));

	if (!pmap_emulate_ad_bits(pmap))
		return (-1);

	PG_A = pmap_accessed_bit(pmap);
	PG_M = pmap_modified_bit(pmap);
	PG_V = pmap_valid_bit(pmap);
	PG_RW = pmap_rw_bit(pmap);

	rv = -1;
	lock = NULL;
	PMAP_LOCK(pmap);

	pde = pmap_pde(pmap, va);
	if (pde == NULL || (*pde & PG_V) == 0)
		goto done;

	if ((*pde & PG_PS) != 0) {
		if (ftype == VM_PROT_READ) {

			atomic_add_long(&num_superpage_accessed_emulations, 1);

			*pde |= PG_A;
			rv = 0;
		}
		goto done;
	}

	pte = pmap_pde_to_pte(pde, va);
	if ((*pte & PG_V) == 0)
		goto done;

	if (ftype == VM_PROT_WRITE) {
		if ((*pte & PG_RW) == 0)
			goto done;
		
		*pte |= PG_M | PG_A;
	} else {
		*pte |= PG_A;
	}


	
	if (va < VM_MAXUSER_ADDRESS)
		mpte = PHYS_TO_VM_PAGE(*pde & PG_FRAME);
	else mpte = NULL;

	m = PHYS_TO_VM_PAGE(*pte & PG_FRAME);

	if ((mpte == NULL || mpte->ref_count == NPTEPG) && pmap_ps_enabled(pmap) && (m->flags & PG_FICTITIOUS) == 0 && vm_reserv_level_iffullpop(m) == 0) {


		pmap_promote_pde(pmap, pde, va, &lock);

		atomic_add_long(&ad_emulation_superpage_promotions, 1);

	}



	if (ftype == VM_PROT_WRITE)
		atomic_add_long(&num_dirty_emulations, 1);
	else atomic_add_long(&num_accessed_emulations, 1);

	rv = 0;		
done:
	if (lock != NULL)
		rw_wunlock(lock);
	PMAP_UNLOCK(pmap);
	return (rv);
}

void pmap_get_mapping(pmap_t pmap, vm_offset_t va, uint64_t *ptr, int *num)
{
	pml4_entry_t *pml4;
	pdp_entry_t *pdp;
	pd_entry_t *pde;
	pt_entry_t *pte, PG_V;
	int idx;

	idx = 0;
	PG_V = pmap_valid_bit(pmap);
	PMAP_LOCK(pmap);

	pml4 = pmap_pml4e(pmap, va);
	ptr[idx++] = *pml4;
	if ((*pml4 & PG_V) == 0)
		goto done;

	pdp = pmap_pml4e_to_pdpe(pml4, va);
	ptr[idx++] = *pdp;
	if ((*pdp & PG_V) == 0 || (*pdp & PG_PS) != 0)
		goto done;

	pde = pmap_pdpe_to_pde(pdp, va);
	ptr[idx++] = *pde;
	if ((*pde & PG_V) == 0 || (*pde & PG_PS) != 0)
		goto done;

	pte = pmap_pde_to_pte(pde, va);
	ptr[idx++] = *pte;

done:
	PMAP_UNLOCK(pmap);
	*num = idx;
}


boolean_t pmap_map_io_transient(vm_page_t page[], vm_offset_t vaddr[], int count, boolean_t can_fault)

{
	vm_paddr_t paddr;
	boolean_t needs_mapping;
	pt_entry_t *pte;
	int cache_bits, error __unused, i;

	
	needs_mapping = FALSE;
	for (i = 0; i < count; i++) {
		paddr = VM_PAGE_TO_PHYS(page[i]);
		if (__predict_false(paddr >= dmaplimit)) {
			error = vmem_alloc(kernel_arena, PAGE_SIZE, M_BESTFIT | M_WAITOK, &vaddr[i]);
			KASSERT(error == 0, ("vmem_alloc failed: %d", error));
			needs_mapping = TRUE;
		} else {
			vaddr[i] = PHYS_TO_DMAP(paddr);
		}
	}

	
	if (!needs_mapping)
		return (FALSE);

	
	if (!can_fault)
		sched_pin();
	for (i = 0; i < count; i++) {
		paddr = VM_PAGE_TO_PHYS(page[i]);
		if (paddr >= dmaplimit) {
			if (can_fault) {
				
				pmap_qenter(vaddr[i], &page[i], 1);
			} else {
				pte = vtopte(vaddr[i]);
				cache_bits = pmap_cache_bits(kernel_pmap, page[i]->md.pat_mode, 0);
				pte_store(pte, paddr | X86_PG_RW | X86_PG_V | cache_bits);
				invlpg(vaddr[i]);
			}
		}
	}

	return (needs_mapping);
}

void pmap_unmap_io_transient(vm_page_t page[], vm_offset_t vaddr[], int count, boolean_t can_fault)

{
	vm_paddr_t paddr;
	int i;

	if (!can_fault)
		sched_unpin();
	for (i = 0; i < count; i++) {
		paddr = VM_PAGE_TO_PHYS(page[i]);
		if (paddr >= dmaplimit) {
			if (can_fault)
				pmap_qremove(vaddr[i], 1);
			vmem_free(kernel_arena, vaddr[i], PAGE_SIZE);
		}
	}
}

vm_offset_t pmap_quick_enter_page(vm_page_t m)
{
	vm_paddr_t paddr;

	paddr = VM_PAGE_TO_PHYS(m);
	if (paddr < dmaplimit)
		return (PHYS_TO_DMAP(paddr));
	mtx_lock_spin(&qframe_mtx);
	KASSERT(*vtopte(qframe) == 0, ("qframe busy"));
	pte_store(vtopte(qframe), paddr | X86_PG_RW | X86_PG_V | X86_PG_A | X86_PG_M | pmap_cache_bits(kernel_pmap, m->md.pat_mode, 0));
	return (qframe);
}

void pmap_quick_remove_page(vm_offset_t addr)
{

	if (addr != qframe)
		return;
	pte_store(vtopte(qframe), 0);
	invlpg(qframe);
	mtx_unlock_spin(&qframe_mtx);
}


static vm_page_t pmap_large_map_getptp_unlocked(void)
{
	vm_page_t m;

	m = vm_page_alloc(NULL, 0, VM_ALLOC_NORMAL | VM_ALLOC_NOOBJ | VM_ALLOC_ZERO);
	if (m != NULL && (m->flags & PG_ZERO) == 0)
		pmap_zero_page(m);
	return (m);
}

static vm_page_t pmap_large_map_getptp(void)
{
	vm_page_t m;

	PMAP_LOCK_ASSERT(kernel_pmap, MA_OWNED);
	m = pmap_large_map_getptp_unlocked();
	if (m == NULL) {
		PMAP_UNLOCK(kernel_pmap);
		vm_wait(NULL);
		PMAP_LOCK(kernel_pmap);
		
	}
	return (m);
}

static pdp_entry_t * pmap_large_map_pdpe(vm_offset_t va)
{
	vm_pindex_t pml4_idx;
	vm_paddr_t mphys;

	pml4_idx = pmap_pml4e_index(va);
	KASSERT(LMSPML4I <= pml4_idx && pml4_idx < LMSPML4I + lm_ents, ("pmap_large_map_pdpe: va %#jx out of range idx %#jx LMSPML4I " "%#jx lm_ents %d", (uintmax_t)va, (uintmax_t)pml4_idx, LMSPML4I, lm_ents));


	KASSERT((kernel_pmap->pm_pml4[pml4_idx] & X86_PG_V) != 0, ("pmap_large_map_pdpe: invalid pml4 for va %#jx idx %#jx " "LMSPML4I %#jx lm_ents %d", (uintmax_t)va, (uintmax_t)pml4_idx, LMSPML4I, lm_ents));


	mphys = kernel_pmap->pm_pml4[pml4_idx] & PG_FRAME;
	return ((pdp_entry_t *)PHYS_TO_DMAP(mphys) + pmap_pdpe_index(va));
}

static pd_entry_t * pmap_large_map_pde(vm_offset_t va)
{
	pdp_entry_t *pdpe;
	vm_page_t m;
	vm_paddr_t mphys;

retry:
	pdpe = pmap_large_map_pdpe(va);
	if (*pdpe == 0) {
		m = pmap_large_map_getptp();
		if (m == NULL)
			goto retry;
		mphys = VM_PAGE_TO_PHYS(m);
		*pdpe = mphys | X86_PG_A | X86_PG_RW | X86_PG_V | pg_nx;
	} else {
		MPASS((*pdpe & X86_PG_PS) == 0);
		mphys = *pdpe & PG_FRAME;
	}
	return ((pd_entry_t *)PHYS_TO_DMAP(mphys) + pmap_pde_index(va));
}

static pt_entry_t * pmap_large_map_pte(vm_offset_t va)
{
	pd_entry_t *pde;
	vm_page_t m;
	vm_paddr_t mphys;

retry:
	pde = pmap_large_map_pde(va);
	if (*pde == 0) {
		m = pmap_large_map_getptp();
		if (m == NULL)
			goto retry;
		mphys = VM_PAGE_TO_PHYS(m);
		*pde = mphys | X86_PG_A | X86_PG_RW | X86_PG_V | pg_nx;
		PHYS_TO_VM_PAGE(DMAP_TO_PHYS((uintptr_t)pde))->ref_count++;
	} else {
		MPASS((*pde & X86_PG_PS) == 0);
		mphys = *pde & PG_FRAME;
	}
	return ((pt_entry_t *)PHYS_TO_DMAP(mphys) + pmap_pte_index(va));
}

static vm_paddr_t pmap_large_map_kextract(vm_offset_t va)
{
	pdp_entry_t *pdpe, pdp;
	pd_entry_t *pde, pd;
	pt_entry_t *pte, pt;

	KASSERT(PMAP_ADDRESS_IN_LARGEMAP(va), ("not largemap range %#lx", (u_long)va));
	pdpe = pmap_large_map_pdpe(va);
	pdp = *pdpe;
	KASSERT((pdp & X86_PG_V) != 0, ("invalid pdp va %#lx pdpe %#lx pdp %#lx", va, (u_long)pdpe, pdp));

	if ((pdp & X86_PG_PS) != 0) {
		KASSERT((amd_feature & AMDID_PAGE1GB) != 0, ("no 1G pages, va %#lx pdpe %#lx pdp %#lx", va, (u_long)pdpe, pdp));

		return ((pdp & PG_PS_PDP_FRAME) | (va & PDPMASK));
	}
	pde = pmap_pdpe_to_pde(pdpe, va);
	pd = *pde;
	KASSERT((pd & X86_PG_V) != 0, ("invalid pd va %#lx pde %#lx pd %#lx", va, (u_long)pde, pd));
	if ((pd & X86_PG_PS) != 0)
		return ((pd & PG_PS_FRAME) | (va & PDRMASK));
	pte = pmap_pde_to_pte(pde, va);
	pt = *pte;
	KASSERT((pt & X86_PG_V) != 0, ("invalid pte va %#lx pte %#lx pt %#lx", va, (u_long)pte, pt));
	return ((pt & PG_FRAME) | (va & PAGE_MASK));
}

static int pmap_large_map_getva(vm_size_t len, vm_offset_t align, vm_offset_t phase, vmem_addr_t *vmem_res)

{

	
	return (vmem_xalloc(large_vmem, len, align, phase, 0, VMEM_ADDR_MIN, VMEM_ADDR_MAX, M_NOWAIT | M_BESTFIT, vmem_res));
}

int pmap_large_map(vm_paddr_t spa, vm_size_t len, void **addr, vm_memattr_t mattr)

{
	pdp_entry_t *pdpe;
	pd_entry_t *pde;
	pt_entry_t *pte;
	vm_offset_t va, inc;
	vmem_addr_t vmem_res;
	vm_paddr_t pa;
	int error;

	if (len == 0 || spa + len < spa)
		return (EINVAL);

	
	if (spa + len <= dmaplimit) {
		va = PHYS_TO_DMAP(spa);
		*addr = (void *)va;
		return (pmap_change_attr(va, len, mattr));
	}

	
	error = ENOMEM;
	if ((amd_feature & AMDID_PAGE1GB) != 0 && rounddown2(spa + len, NBPDP) >= roundup2(spa, NBPDP) + NBPDP)
		error = pmap_large_map_getva(len, NBPDP, spa & PDPMASK, &vmem_res);
	if (error != 0 && rounddown2(spa + len, NBPDR) >= roundup2(spa, NBPDR) + NBPDR)
		error = pmap_large_map_getva(len, NBPDR, spa & PDRMASK, &vmem_res);
	if (error != 0)
		error = pmap_large_map_getva(len, PAGE_SIZE, 0, &vmem_res);
	if (error != 0)
		return (error);

	
	PMAP_LOCK(kernel_pmap);
	for (pa = spa, va = vmem_res; len > 0; pa += inc, va += inc, len -= inc) {
		if ((amd_feature & AMDID_PAGE1GB) != 0 && len >= NBPDP && (pa & PDPMASK) == 0 && (va & PDPMASK) == 0) {
			pdpe = pmap_large_map_pdpe(va);
			MPASS(*pdpe == 0);
			*pdpe = pa | pg_g | X86_PG_PS | X86_PG_RW | X86_PG_V | X86_PG_A | pg_nx | pmap_cache_bits(kernel_pmap, mattr, TRUE);

			inc = NBPDP;
		} else if (len >= NBPDR && (pa & PDRMASK) == 0 && (va & PDRMASK) == 0) {
			pde = pmap_large_map_pde(va);
			MPASS(*pde == 0);
			*pde = pa | pg_g | X86_PG_PS | X86_PG_RW | X86_PG_V | X86_PG_A | pg_nx | pmap_cache_bits(kernel_pmap, mattr, TRUE);

			PHYS_TO_VM_PAGE(DMAP_TO_PHYS((uintptr_t)pde))-> ref_count++;
			inc = NBPDR;
		} else {
			pte = pmap_large_map_pte(va);
			MPASS(*pte == 0);
			*pte = pa | pg_g | X86_PG_RW | X86_PG_V | X86_PG_A | pg_nx | pmap_cache_bits(kernel_pmap, mattr, FALSE);

			PHYS_TO_VM_PAGE(DMAP_TO_PHYS((uintptr_t)pte))-> ref_count++;
			inc = PAGE_SIZE;
		}
	}
	PMAP_UNLOCK(kernel_pmap);
	MPASS(len == 0);

	*addr = (void *)vmem_res;
	return (0);
}

void pmap_large_unmap(void *svaa, vm_size_t len)
{
	vm_offset_t sva, va;
	vm_size_t inc;
	pdp_entry_t *pdpe, pdp;
	pd_entry_t *pde, pd;
	pt_entry_t *pte;
	vm_page_t m;
	struct spglist spgf;

	sva = (vm_offset_t)svaa;
	if (len == 0 || sva + len < sva || (sva >= DMAP_MIN_ADDRESS && sva + len <= DMAP_MIN_ADDRESS + dmaplimit))
		return;

	SLIST_INIT(&spgf);
	KASSERT(PMAP_ADDRESS_IN_LARGEMAP(sva) && PMAP_ADDRESS_IN_LARGEMAP(sva + len - 1), ("not largemap range %#lx %#lx", (u_long)svaa, (u_long)svaa + len));

	PMAP_LOCK(kernel_pmap);
	for (va = sva; va < sva + len; va += inc) {
		pdpe = pmap_large_map_pdpe(va);
		pdp = *pdpe;
		KASSERT((pdp & X86_PG_V) != 0, ("invalid pdp va %#lx pdpe %#lx pdp %#lx", va, (u_long)pdpe, pdp));

		if ((pdp & X86_PG_PS) != 0) {
			KASSERT((amd_feature & AMDID_PAGE1GB) != 0, ("no 1G pages, va %#lx pdpe %#lx pdp %#lx", va, (u_long)pdpe, pdp));

			KASSERT((va & PDPMASK) == 0, ("PDPMASK bit set, va %#lx pdpe %#lx pdp %#lx", va, (u_long)pdpe, pdp));

			KASSERT(va + NBPDP <= sva + len, ("unmap covers partial 1GB page, sva %#lx va %#lx " "pdpe %#lx pdp %#lx len %#lx", sva, va, (u_long)pdpe, pdp, len));


			*pdpe = 0;
			inc = NBPDP;
			continue;
		}
		pde = pmap_pdpe_to_pde(pdpe, va);
		pd = *pde;
		KASSERT((pd & X86_PG_V) != 0, ("invalid pd va %#lx pde %#lx pd %#lx", va, (u_long)pde, pd));

		if ((pd & X86_PG_PS) != 0) {
			KASSERT((va & PDRMASK) == 0, ("PDRMASK bit set, va %#lx pde %#lx pd %#lx", va, (u_long)pde, pd));

			KASSERT(va + NBPDR <= sva + len, ("unmap covers partial 2MB page, sva %#lx va %#lx " "pde %#lx pd %#lx len %#lx", sva, va, (u_long)pde, pd, len));


			pde_store(pde, 0);
			inc = NBPDR;
			m = PHYS_TO_VM_PAGE(DMAP_TO_PHYS((vm_offset_t)pde));
			m->ref_count--;
			if (m->ref_count == 0) {
				*pdpe = 0;
				SLIST_INSERT_HEAD(&spgf, m, plinks.s.ss);
			}
			continue;
		}
		pte = pmap_pde_to_pte(pde, va);
		KASSERT((*pte & X86_PG_V) != 0, ("invalid pte va %#lx pte %#lx pt %#lx", va, (u_long)pte, *pte));

		pte_clear(pte);
		inc = PAGE_SIZE;
		m = PHYS_TO_VM_PAGE(DMAP_TO_PHYS((vm_offset_t)pte));
		m->ref_count--;
		if (m->ref_count == 0) {
			*pde = 0;
			SLIST_INSERT_HEAD(&spgf, m, plinks.s.ss);
			m = PHYS_TO_VM_PAGE(DMAP_TO_PHYS((vm_offset_t)pde));
			m->ref_count--;
			if (m->ref_count == 0) {
				*pdpe = 0;
				SLIST_INSERT_HEAD(&spgf, m, plinks.s.ss);
			}
		}
	}
	pmap_invalidate_range(kernel_pmap, sva, sva + len);
	PMAP_UNLOCK(kernel_pmap);
	vm_page_free_pages_toq(&spgf, false);
	vmem_free(large_vmem, sva, len);
}

static void pmap_large_map_wb_fence_mfence(void)
{

	mfence();
}

static void pmap_large_map_wb_fence_atomic(void)
{

	atomic_thread_fence_seq_cst();
}

static void pmap_large_map_wb_fence_nop(void)
{
}

DEFINE_IFUNC(static, void, pmap_large_map_wb_fence, (void))
{

	if (cpu_vendor_id != CPU_VENDOR_INTEL)
		return (pmap_large_map_wb_fence_mfence);
	else if ((cpu_stdext_feature & (CPUID_STDEXT_CLWB | CPUID_STDEXT_CLFLUSHOPT)) == 0)
		return (pmap_large_map_wb_fence_atomic);
	else  return (pmap_large_map_wb_fence_nop);

}

static void pmap_large_map_flush_range_clwb(vm_offset_t va, vm_size_t len)
{

	for (; len > 0; len -= cpu_clflush_line_size, va += cpu_clflush_line_size)
		clwb(va);
}

static void pmap_large_map_flush_range_clflushopt(vm_offset_t va, vm_size_t len)
{

	for (; len > 0; len -= cpu_clflush_line_size, va += cpu_clflush_line_size)
		clflushopt(va);
}

static void pmap_large_map_flush_range_clflush(vm_offset_t va, vm_size_t len)
{

	for (; len > 0; len -= cpu_clflush_line_size, va += cpu_clflush_line_size)
		clflush(va);
}

static void pmap_large_map_flush_range_nop(vm_offset_t sva __unused, vm_size_t len __unused)
{
}

DEFINE_IFUNC(static, void, pmap_large_map_flush_range, (vm_offset_t, vm_size_t))
{

	if ((cpu_stdext_feature & CPUID_STDEXT_CLWB) != 0)
		return (pmap_large_map_flush_range_clwb);
	else if ((cpu_stdext_feature & CPUID_STDEXT_CLFLUSHOPT) != 0)
		return (pmap_large_map_flush_range_clflushopt);
	else if ((cpu_feature & CPUID_CLFSH) != 0)
		return (pmap_large_map_flush_range_clflush);
	else return (pmap_large_map_flush_range_nop);
}

static void pmap_large_map_wb_large(vm_offset_t sva, vm_offset_t eva)
{
	volatile u_long *pe;
	u_long p;
	vm_offset_t va;
	vm_size_t inc;
	bool seen_other;

	for (va = sva; va < eva; va += inc) {
		inc = 0;
		if ((amd_feature & AMDID_PAGE1GB) != 0) {
			pe = (volatile u_long *)pmap_large_map_pdpe(va);
			p = *pe;
			if ((p & X86_PG_PS) != 0)
				inc = NBPDP;
		}
		if (inc == 0) {
			pe = (volatile u_long *)pmap_large_map_pde(va);
			p = *pe;
			if ((p & X86_PG_PS) != 0)
				inc = NBPDR;
		}
		if (inc == 0) {
			pe = (volatile u_long *)pmap_large_map_pte(va);
			p = *pe;
			inc = PAGE_SIZE;
		}
		seen_other = false;
		for (;;) {
			if ((p & X86_PG_AVAIL1) != 0) {
				
				cpu_spinwait();
				p = *pe;

				
				seen_other = true;
				continue;
			}

			if ((p & X86_PG_M) != 0 || seen_other) {
				if (!atomic_fcmpset_long(pe, &p, (p & ~X86_PG_M) | X86_PG_AVAIL1))
					
					continue;
				pmap_large_map_flush_range(va, inc);
				atomic_clear_long(pe, X86_PG_AVAIL1);
			}
			break;
		}
		maybe_yield();
	}
}


void pmap_large_map_wb(void *svap, vm_size_t len)
{
	vm_offset_t eva, sva;

	sva = (vm_offset_t)svap;
	eva = sva + len;
	pmap_large_map_wb_fence();
	if (sva >= DMAP_MIN_ADDRESS && eva <= DMAP_MIN_ADDRESS + dmaplimit) {
		pmap_large_map_flush_range(sva, len);
	} else {
		KASSERT(sva >= LARGEMAP_MIN_ADDRESS && eva <= LARGEMAP_MIN_ADDRESS + lm_ents * NBPML4, ("pmap_large_map_wb: not largemap %#lx %#lx", sva, len));

		pmap_large_map_wb_large(sva, eva);
	}
	pmap_large_map_wb_fence();
}

static vm_page_t pmap_pti_alloc_page(void)
{
	vm_page_t m;

	VM_OBJECT_ASSERT_WLOCKED(pti_obj);
	m = vm_page_grab(pti_obj, pti_pg_idx++, VM_ALLOC_NOBUSY | VM_ALLOC_WIRED | VM_ALLOC_ZERO);
	return (m);
}

static bool pmap_pti_free_page(vm_page_t m)
{

	KASSERT(m->ref_count > 0, ("page %p not referenced", m));
	if (!vm_page_unwire_noq(m))
		return (false);
	vm_page_free_zero(m);
	return (true);
}

static void pmap_pti_init(void)
{
	vm_page_t pml4_pg;
	pdp_entry_t *pdpe;
	vm_offset_t va;
	int i;

	if (!pti)
		return;
	pti_obj = vm_pager_allocate(OBJT_PHYS, NULL, 0, VM_PROT_ALL, 0, NULL);
	VM_OBJECT_WLOCK(pti_obj);
	pml4_pg = pmap_pti_alloc_page();
	pti_pml4 = (pml4_entry_t *)PHYS_TO_DMAP(VM_PAGE_TO_PHYS(pml4_pg));
	for (va = VM_MIN_KERNEL_ADDRESS; va <= VM_MAX_KERNEL_ADDRESS && va >= VM_MIN_KERNEL_ADDRESS && va > NBPML4; va += NBPML4) {
		pdpe = pmap_pti_pdpe(va);
		pmap_pti_wire_pte(pdpe);
	}
	pmap_pti_add_kva_locked((vm_offset_t)&__pcpu[0], (vm_offset_t)&__pcpu[0] + sizeof(__pcpu[0]) * MAXCPU, false);
	pmap_pti_add_kva_locked((vm_offset_t)idt, (vm_offset_t)idt + sizeof(struct gate_descriptor) * NIDT, false);
	CPU_FOREACH(i) {
		
		va = __pcpu[i].pc_common_tss.tss_ist1;
		pmap_pti_add_kva_locked(va - PAGE_SIZE, va, false);
		
		va = __pcpu[i].pc_common_tss.tss_ist2 + sizeof(struct nmi_pcpu);
		pmap_pti_add_kva_locked(va - PAGE_SIZE, va, false);
		
		va = __pcpu[i].pc_common_tss.tss_ist3 + sizeof(struct nmi_pcpu);
		pmap_pti_add_kva_locked(va - PAGE_SIZE, va, false);
		
		va = __pcpu[i].pc_common_tss.tss_ist4 + sizeof(struct nmi_pcpu);
		pmap_pti_add_kva_locked(va - PAGE_SIZE, va, false);
	}
	pmap_pti_add_kva_locked((vm_offset_t)kernphys + KERNBASE, (vm_offset_t)etext, true);
	pti_finalized = true;
	VM_OBJECT_WUNLOCK(pti_obj);
}
SYSINIT(pmap_pti, SI_SUB_CPU + 1, SI_ORDER_ANY, pmap_pti_init, NULL);

static pdp_entry_t * pmap_pti_pdpe(vm_offset_t va)
{
	pml4_entry_t *pml4e;
	pdp_entry_t *pdpe;
	vm_page_t m;
	vm_pindex_t pml4_idx;
	vm_paddr_t mphys;

	VM_OBJECT_ASSERT_WLOCKED(pti_obj);

	pml4_idx = pmap_pml4e_index(va);
	pml4e = &pti_pml4[pml4_idx];
	m = NULL;
	if (*pml4e == 0) {
		if (pti_finalized)
			panic("pml4 alloc after finalization\n");
		m = pmap_pti_alloc_page();
		if (*pml4e != 0) {
			pmap_pti_free_page(m);
			mphys = *pml4e & ~PAGE_MASK;
		} else {
			mphys = VM_PAGE_TO_PHYS(m);
			*pml4e = mphys | X86_PG_RW | X86_PG_V;
		}
	} else {
		mphys = *pml4e & ~PAGE_MASK;
	}
	pdpe = (pdp_entry_t *)PHYS_TO_DMAP(mphys) + pmap_pdpe_index(va);
	return (pdpe);
}

static void pmap_pti_wire_pte(void *pte)
{
	vm_page_t m;

	VM_OBJECT_ASSERT_WLOCKED(pti_obj);
	m = PHYS_TO_VM_PAGE(DMAP_TO_PHYS((uintptr_t)pte));
	m->ref_count++;
}

static void pmap_pti_unwire_pde(void *pde, bool only_ref)
{
	vm_page_t m;

	VM_OBJECT_ASSERT_WLOCKED(pti_obj);
	m = PHYS_TO_VM_PAGE(DMAP_TO_PHYS((uintptr_t)pde));
	MPASS(m->ref_count > 0);
	MPASS(only_ref || m->ref_count > 1);
	pmap_pti_free_page(m);
}

static void pmap_pti_unwire_pte(void *pte, vm_offset_t va)
{
	vm_page_t m;
	pd_entry_t *pde;

	VM_OBJECT_ASSERT_WLOCKED(pti_obj);
	m = PHYS_TO_VM_PAGE(DMAP_TO_PHYS((uintptr_t)pte));
	MPASS(m->ref_count > 0);
	if (pmap_pti_free_page(m)) {
		pde = pmap_pti_pde(va);
		MPASS((*pde & (X86_PG_PS | X86_PG_V)) == X86_PG_V);
		*pde = 0;
		pmap_pti_unwire_pde(pde, false);
	}
}

static pd_entry_t * pmap_pti_pde(vm_offset_t va)
{
	pdp_entry_t *pdpe;
	pd_entry_t *pde;
	vm_page_t m;
	vm_pindex_t pd_idx;
	vm_paddr_t mphys;

	VM_OBJECT_ASSERT_WLOCKED(pti_obj);

	pdpe = pmap_pti_pdpe(va);
	if (*pdpe == 0) {
		m = pmap_pti_alloc_page();
		if (*pdpe != 0) {
			pmap_pti_free_page(m);
			MPASS((*pdpe & X86_PG_PS) == 0);
			mphys = *pdpe & ~PAGE_MASK;
		} else {
			mphys =  VM_PAGE_TO_PHYS(m);
			*pdpe = mphys | X86_PG_RW | X86_PG_V;
		}
	} else {
		MPASS((*pdpe & X86_PG_PS) == 0);
		mphys = *pdpe & ~PAGE_MASK;
	}

	pde = (pd_entry_t *)PHYS_TO_DMAP(mphys);
	pd_idx = pmap_pde_index(va);
	pde += pd_idx;
	return (pde);
}

static pt_entry_t * pmap_pti_pte(vm_offset_t va, bool *unwire_pde)
{
	pd_entry_t *pde;
	pt_entry_t *pte;
	vm_page_t m;
	vm_paddr_t mphys;

	VM_OBJECT_ASSERT_WLOCKED(pti_obj);

	pde = pmap_pti_pde(va);
	if (unwire_pde != NULL) {
		*unwire_pde = true;
		pmap_pti_wire_pte(pde);
	}
	if (*pde == 0) {
		m = pmap_pti_alloc_page();
		if (*pde != 0) {
			pmap_pti_free_page(m);
			MPASS((*pde & X86_PG_PS) == 0);
			mphys = *pde & ~(PAGE_MASK | pg_nx);
		} else {
			mphys = VM_PAGE_TO_PHYS(m);
			*pde = mphys | X86_PG_RW | X86_PG_V;
			if (unwire_pde != NULL)
				*unwire_pde = false;
		}
	} else {
		MPASS((*pde & X86_PG_PS) == 0);
		mphys = *pde & ~(PAGE_MASK | pg_nx);
	}

	pte = (pt_entry_t *)PHYS_TO_DMAP(mphys);
	pte += pmap_pte_index(va);

	return (pte);
}

static void pmap_pti_add_kva_locked(vm_offset_t sva, vm_offset_t eva, bool exec)
{
	vm_paddr_t pa;
	pd_entry_t *pde;
	pt_entry_t *pte, ptev;
	bool unwire_pde;

	VM_OBJECT_ASSERT_WLOCKED(pti_obj);

	sva = trunc_page(sva);
	MPASS(sva > VM_MAXUSER_ADDRESS);
	eva = round_page(eva);
	MPASS(sva < eva);
	for (; sva < eva; sva += PAGE_SIZE) {
		pte = pmap_pti_pte(sva, &unwire_pde);
		pa = pmap_kextract(sva);
		ptev = pa | X86_PG_RW | X86_PG_V | X86_PG_A | X86_PG_G | (exec ? 0 : pg_nx) | pmap_cache_bits(kernel_pmap, VM_MEMATTR_DEFAULT, FALSE);

		if (*pte == 0) {
			pte_store(pte, ptev);
			pmap_pti_wire_pte(pte);
		} else {
			KASSERT(!pti_finalized, ("pti overlap after fin %#lx %#lx %#lx", sva, *pte, ptev));

			KASSERT(*pte == ptev, ("pti non-identical pte after fin %#lx %#lx %#lx", sva, *pte, ptev));

		}
		if (unwire_pde) {
			pde = pmap_pti_pde(sva);
			pmap_pti_unwire_pde(pde, true);
		}
	}
}

void pmap_pti_add_kva(vm_offset_t sva, vm_offset_t eva, bool exec)
{

	if (!pti)
		return;
	VM_OBJECT_WLOCK(pti_obj);
	pmap_pti_add_kva_locked(sva, eva, exec);
	VM_OBJECT_WUNLOCK(pti_obj);
}

void pmap_pti_remove_kva(vm_offset_t sva, vm_offset_t eva)
{
	pt_entry_t *pte;
	vm_offset_t va;

	if (!pti)
		return;
	sva = rounddown2(sva, PAGE_SIZE);
	MPASS(sva > VM_MAXUSER_ADDRESS);
	eva = roundup2(eva, PAGE_SIZE);
	MPASS(sva < eva);
	VM_OBJECT_WLOCK(pti_obj);
	for (va = sva; va < eva; va += PAGE_SIZE) {
		pte = pmap_pti_pte(va, NULL);
		KASSERT((*pte & X86_PG_V) != 0, ("invalid pte va %#lx pte %#lx pt %#lx", va, (u_long)pte, *pte));

		pte_clear(pte);
		pmap_pti_unwire_pte(pte, va);
	}
	pmap_invalidate_range(kernel_pmap, sva, eva);
	VM_OBJECT_WUNLOCK(pti_obj);
}

static void * pkru_dup_range(void *ctx __unused, void *data)
{
	struct pmap_pkru_range *node, *new_node;

	new_node = uma_zalloc(pmap_pkru_ranges_zone, M_NOWAIT);
	if (new_node == NULL)
		return (NULL);
	node = data;
	memcpy(new_node, node, sizeof(*node));
	return (new_node);
}

static void pkru_free_range(void *ctx __unused, void *node)
{

	uma_zfree(pmap_pkru_ranges_zone, node);
}

static int pmap_pkru_assign(pmap_t pmap, vm_offset_t sva, vm_offset_t eva, u_int keyidx, int flags)

{
	struct pmap_pkru_range *ppr;
	int error;

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	MPASS(pmap->pm_type == PT_X86);
	MPASS((cpu_stdext_feature2 & CPUID_STDEXT2_PKU) != 0);
	if ((flags & AMD64_PKRU_EXCL) != 0 && !rangeset_check_empty(&pmap->pm_pkru, sva, eva))
		return (EBUSY);
	ppr = uma_zalloc(pmap_pkru_ranges_zone, M_NOWAIT);
	if (ppr == NULL)
		return (ENOMEM);
	ppr->pkru_keyidx = keyidx;
	ppr->pkru_flags = flags & AMD64_PKRU_PERSIST;
	error = rangeset_insert(&pmap->pm_pkru, sva, eva, ppr);
	if (error != 0)
		uma_zfree(pmap_pkru_ranges_zone, ppr);
	return (error);
}

static int pmap_pkru_deassign(pmap_t pmap, vm_offset_t sva, vm_offset_t eva)
{

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	MPASS(pmap->pm_type == PT_X86);
	MPASS((cpu_stdext_feature2 & CPUID_STDEXT2_PKU) != 0);
	return (rangeset_remove(&pmap->pm_pkru, sva, eva));
}

static void pmap_pkru_deassign_all(pmap_t pmap)
{

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	if (pmap->pm_type == PT_X86 && (cpu_stdext_feature2 & CPUID_STDEXT2_PKU) != 0)
		rangeset_remove_all(&pmap->pm_pkru);
}

static bool pmap_pkru_same(pmap_t pmap, vm_offset_t sva, vm_offset_t eva)
{
	struct pmap_pkru_range *ppr, *prev_ppr;
	vm_offset_t va;

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	if (pmap->pm_type != PT_X86 || (cpu_stdext_feature2 & CPUID_STDEXT2_PKU) == 0 || sva >= VM_MAXUSER_ADDRESS)

		return (true);
	MPASS(eva <= VM_MAXUSER_ADDRESS);
	for (va = sva, prev_ppr = NULL; va < eva;) {
		ppr = rangeset_lookup(&pmap->pm_pkru, va);
		if ((ppr == NULL) ^ (prev_ppr == NULL))
			return (false);
		if (ppr == NULL) {
			va += PAGE_SIZE;
			continue;
		}
		if (prev_ppr->pkru_keyidx != ppr->pkru_keyidx)
			return (false);
		va = ppr->pkru_rs_el.re_end;
	}
	return (true);
}

static pt_entry_t pmap_pkru_get(pmap_t pmap, vm_offset_t va)
{
	struct pmap_pkru_range *ppr;

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	if (pmap->pm_type != PT_X86 || (cpu_stdext_feature2 & CPUID_STDEXT2_PKU) == 0 || va >= VM_MAXUSER_ADDRESS)

		return (0);
	ppr = rangeset_lookup(&pmap->pm_pkru, va);
	if (ppr != NULL)
		return (X86_PG_PKU(ppr->pkru_keyidx));
	return (0);
}

static bool pred_pkru_on_remove(void *ctx __unused, void *r)
{
	struct pmap_pkru_range *ppr;

	ppr = r;
	return ((ppr->pkru_flags & AMD64_PKRU_PERSIST) == 0);
}

static void pmap_pkru_on_remove(pmap_t pmap, vm_offset_t sva, vm_offset_t eva)
{

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	if (pmap->pm_type == PT_X86 && (cpu_stdext_feature2 & CPUID_STDEXT2_PKU) != 0) {
		rangeset_remove_pred(&pmap->pm_pkru, sva, eva, pred_pkru_on_remove);
	}
}

static int pmap_pkru_copy(pmap_t dst_pmap, pmap_t src_pmap)
{

	PMAP_LOCK_ASSERT(dst_pmap, MA_OWNED);
	PMAP_LOCK_ASSERT(src_pmap, MA_OWNED);
	MPASS(dst_pmap->pm_type == PT_X86);
	MPASS(src_pmap->pm_type == PT_X86);
	MPASS((cpu_stdext_feature2 & CPUID_STDEXT2_PKU) != 0);
	if (src_pmap->pm_pkru.rs_data_ctx == NULL)
		return (0);
	return (rangeset_copy(&dst_pmap->pm_pkru, &src_pmap->pm_pkru));
}

static void pmap_pkru_update_range(pmap_t pmap, vm_offset_t sva, vm_offset_t eva, u_int keyidx)

{
	pml4_entry_t *pml4e;
	pdp_entry_t *pdpe;
	pd_entry_t newpde, ptpaddr, *pde;
	pt_entry_t newpte, *ptep, pte;
	vm_offset_t va, va_next;
	bool changed;

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	MPASS(pmap->pm_type == PT_X86);
	MPASS(keyidx <= PMAP_MAX_PKRU_IDX);

	for (changed = false, va = sva; va < eva; va = va_next) {
		pml4e = pmap_pml4e(pmap, va);
		if ((*pml4e & X86_PG_V) == 0) {
			va_next = (va + NBPML4) & ~PML4MASK;
			if (va_next < va)
				va_next = eva;
			continue;
		}

		pdpe = pmap_pml4e_to_pdpe(pml4e, va);
		if ((*pdpe & X86_PG_V) == 0) {
			va_next = (va + NBPDP) & ~PDPMASK;
			if (va_next < va)
				va_next = eva;
			continue;
		}

		va_next = (va + NBPDR) & ~PDRMASK;
		if (va_next < va)
			va_next = eva;

		pde = pmap_pdpe_to_pde(pdpe, va);
		ptpaddr = *pde;
		if (ptpaddr == 0)
			continue;

		MPASS((ptpaddr & X86_PG_V) != 0);
		if ((ptpaddr & PG_PS) != 0) {
			if (va + NBPDR == va_next && eva >= va_next) {
				newpde = (ptpaddr & ~X86_PG_PKU_MASK) | X86_PG_PKU(keyidx);
				if (newpde != ptpaddr) {
					*pde = newpde;
					changed = true;
				}
				continue;
			} else if (!pmap_demote_pde(pmap, pde, va)) {
				continue;
			}
		}

		if (va_next > eva)
			va_next = eva;

		for (ptep = pmap_pde_to_pte(pde, va); va != va_next;
		    ptep++, va += PAGE_SIZE) {
			pte = *ptep;
			if ((pte & X86_PG_V) == 0)
				continue;
			newpte = (pte & ~X86_PG_PKU_MASK) | X86_PG_PKU(keyidx);
			if (newpte != pte) {
				*ptep = newpte;
				changed = true;
			}
		}
	}
	if (changed)
		pmap_invalidate_range(pmap, sva, eva);
}

static int pmap_pkru_check_uargs(pmap_t pmap, vm_offset_t sva, vm_offset_t eva, u_int keyidx, int flags)

{

	if (pmap->pm_type != PT_X86 || keyidx > PMAP_MAX_PKRU_IDX || (flags & ~(AMD64_PKRU_PERSIST | AMD64_PKRU_EXCL)) != 0)
		return (EINVAL);
	if (eva <= sva || eva > VM_MAXUSER_ADDRESS)
		return (EFAULT);
	if ((cpu_stdext_feature2 & CPUID_STDEXT2_PKU) == 0)
		return (ENOTSUP);
	return (0);
}

int pmap_pkru_set(pmap_t pmap, vm_offset_t sva, vm_offset_t eva, u_int keyidx, int flags)

{
	int error;

	sva = trunc_page(sva);
	eva = round_page(eva);
	error = pmap_pkru_check_uargs(pmap, sva, eva, keyidx, flags);
	if (error != 0)
		return (error);
	for (;;) {
		PMAP_LOCK(pmap);
		error = pmap_pkru_assign(pmap, sva, eva, keyidx, flags);
		if (error == 0)
			pmap_pkru_update_range(pmap, sva, eva, keyidx);
		PMAP_UNLOCK(pmap);
		if (error != ENOMEM)
			break;
		vm_wait(NULL);
	}
	return (error);
}

int pmap_pkru_clear(pmap_t pmap, vm_offset_t sva, vm_offset_t eva)
{
	int error;

	sva = trunc_page(sva);
	eva = round_page(eva);
	error = pmap_pkru_check_uargs(pmap, sva, eva, 0, 0);
	if (error != 0)
		return (error);
	for (;;) {
		PMAP_LOCK(pmap);
		error = pmap_pkru_deassign(pmap, sva, eva);
		if (error == 0)
			pmap_pkru_update_range(pmap, sva, eva, 0);
		PMAP_UNLOCK(pmap);
		if (error != ENOMEM)
			break;
		vm_wait(NULL);
	}
	return (error);
}


struct pmap_kernel_map_range {
	vm_offset_t sva;
	pt_entry_t attrs;
	int ptes;
	int pdes;
	int pdpes;
};

static void sysctl_kmaps_dump(struct sbuf *sb, struct pmap_kernel_map_range *range, vm_offset_t eva)

{
	const char *mode;
	int i, pat_idx;

	if (eva <= range->sva)
		return;

	pat_idx = pmap_pat_index(kernel_pmap, range->attrs, true);
	for (i = 0; i < PAT_INDEX_SIZE; i++)
		if (pat_index[i] == pat_idx)
			break;

	switch (i) {
	case PAT_WRITE_BACK:
		mode = "WB";
		break;
	case PAT_WRITE_THROUGH:
		mode = "WT";
		break;
	case PAT_UNCACHEABLE:
		mode = "UC";
		break;
	case PAT_UNCACHED:
		mode = "U-";
		break;
	case PAT_WRITE_PROTECTED:
		mode = "WP";
		break;
	case PAT_WRITE_COMBINING:
		mode = "WC";
		break;
	default:
		printf("%s: unknown PAT mode %#x for range 0x%016lx-0x%016lx\n", __func__, pat_idx, range->sva, eva);
		mode = "??";
		break;
	}

	sbuf_printf(sb, "0x%016lx-0x%016lx r%c%c%c%c %s %d %d %d\n", range->sva, eva, (range->attrs & X86_PG_RW) != 0 ? 'w' : '-', (range->attrs & pg_nx) != 0 ? '-' : 'x', (range->attrs & X86_PG_U) != 0 ? 'u' : 's', (range->attrs & X86_PG_G) != 0 ? 'g' : '-', mode, range->pdpes, range->pdes, range->ptes);






	
	range->sva = KVADDR(NPML4EPG - 1, NPDPEPG - 1, NPDEPG - 1, NPTEPG - 1);
}


static bool sysctl_kmaps_match(struct pmap_kernel_map_range *range, pt_entry_t attrs)
{
	pt_entry_t diff, mask;

	mask = X86_PG_G | X86_PG_RW | X86_PG_U | X86_PG_PDE_CACHE | pg_nx;
	diff = (range->attrs ^ attrs) & mask;
	if (diff == 0)
		return (true);
	if ((diff & ~X86_PG_PDE_PAT) == 0 && pmap_pat_index(kernel_pmap, range->attrs, true) == pmap_pat_index(kernel_pmap, attrs, true))

		return (true);
	return (false);
}

static void sysctl_kmaps_reinit(struct pmap_kernel_map_range *range, vm_offset_t va, pt_entry_t attrs)

{

	memset(range, 0, sizeof(*range));
	range->sva = va;
	range->attrs = attrs;
}


static void sysctl_kmaps_check(struct sbuf *sb, struct pmap_kernel_map_range *range, vm_offset_t va, pml4_entry_t pml4e, pdp_entry_t pdpe, pd_entry_t pde, pt_entry_t pte)


{
	pt_entry_t attrs;

	attrs = pml4e & (X86_PG_RW | X86_PG_U | pg_nx);

	attrs |= pdpe & pg_nx;
	attrs &= pg_nx | (pdpe & (X86_PG_RW | X86_PG_U));
	if ((pdpe & PG_PS) != 0) {
		attrs |= pdpe & (X86_PG_G | X86_PG_PDE_CACHE);
	} else if (pde != 0) {
		attrs |= pde & pg_nx;
		attrs &= pg_nx | (pde & (X86_PG_RW | X86_PG_U));
	}
	if ((pde & PG_PS) != 0) {
		attrs |= pde & (X86_PG_G | X86_PG_PDE_CACHE);
	} else if (pte != 0) {
		attrs |= pte & pg_nx;
		attrs &= pg_nx | (pte & (X86_PG_RW | X86_PG_U));
		attrs |= pte & (X86_PG_G | X86_PG_PTE_CACHE);

		
		if ((attrs & X86_PG_PTE_PAT) != 0)
			attrs ^= X86_PG_PDE_PAT | X86_PG_PTE_PAT;
	}

	if (range->sva > va || !sysctl_kmaps_match(range, attrs)) {
		sysctl_kmaps_dump(sb, range, va);
		sysctl_kmaps_reinit(range, va, attrs);
	}
}

static int sysctl_kmaps(SYSCTL_HANDLER_ARGS)
{
	struct pmap_kernel_map_range range;
	struct sbuf sbuf, *sb;
	pml4_entry_t pml4e;
	pdp_entry_t *pdp, pdpe;
	pd_entry_t *pd, pde;
	pt_entry_t *pt, pte;
	vm_offset_t sva;
	vm_paddr_t pa;
	int error, i, j, k, l;

	error = sysctl_wire_old_buffer(req, 0);
	if (error != 0)
		return (error);
	sb = &sbuf;
	sbuf_new_for_sysctl(sb, NULL, PAGE_SIZE, req);

	
	range.sva = KVADDR(NPML4EPG - 1, NPDPEPG - 1, NPDEPG - 1, NPTEPG - 1);

	
	for (sva = 0, i = pmap_pml4e_index(sva); i < NPML4EPG; i++) {
		switch (i) {
		case PML4PML4I:
			sbuf_printf(sb, "\nRecursive map:\n");
			break;
		case DMPML4I:
			sbuf_printf(sb, "\nDirect map:\n");
			break;
		case KPML4BASE:
			sbuf_printf(sb, "\nKernel map:\n");
			break;
		case LMSPML4I:
			sbuf_printf(sb, "\nLarge map:\n");
			break;
		}

		
		if (sva == 1ul << 47)
			sva |= -1ul << 48;

restart:
		pml4e = kernel_pmap->pm_pml4[i];
		if ((pml4e & X86_PG_V) == 0) {
			sva = rounddown2(sva, NBPML4);
			sysctl_kmaps_dump(sb, &range, sva);
			sva += NBPML4;
			continue;
		}
		pa = pml4e & PG_FRAME;
		pdp = (pdp_entry_t *)PHYS_TO_DMAP(pa);

		for (j = pmap_pdpe_index(sva); j < NPDPEPG; j++) {
			pdpe = pdp[j];
			if ((pdpe & X86_PG_V) == 0) {
				sva = rounddown2(sva, NBPDP);
				sysctl_kmaps_dump(sb, &range, sva);
				sva += NBPDP;
				continue;
			}
			pa = pdpe & PG_FRAME;
			if (PMAP_ADDRESS_IN_LARGEMAP(sva) && vm_phys_paddr_to_vm_page(pa) == NULL)
				goto restart;
			if ((pdpe & PG_PS) != 0) {
				sva = rounddown2(sva, NBPDP);
				sysctl_kmaps_check(sb, &range, sva, pml4e, pdpe, 0, 0);
				range.pdpes++;
				sva += NBPDP;
				continue;
			}
			pd = (pd_entry_t *)PHYS_TO_DMAP(pa);

			for (k = pmap_pde_index(sva); k < NPDEPG; k++) {
				pde = pd[k];
				if ((pde & X86_PG_V) == 0) {
					sva = rounddown2(sva, NBPDR);
					sysctl_kmaps_dump(sb, &range, sva);
					sva += NBPDR;
					continue;
				}
				pa = pde & PG_FRAME;
				if (PMAP_ADDRESS_IN_LARGEMAP(sva) && vm_phys_paddr_to_vm_page(pa) == NULL)
					goto restart;
				if ((pde & PG_PS) != 0) {
					sva = rounddown2(sva, NBPDR);
					sysctl_kmaps_check(sb, &range, sva, pml4e, pdpe, pde, 0);
					range.pdes++;
					sva += NBPDR;
					continue;
				}
				pt = (pt_entry_t *)PHYS_TO_DMAP(pa);

				for (l = pmap_pte_index(sva); l < NPTEPG; l++, sva += PAGE_SIZE) {
					pte = pt[l];
					if ((pte & X86_PG_V) == 0) {
						sysctl_kmaps_dump(sb, &range, sva);
						continue;
					}
					sysctl_kmaps_check(sb, &range, sva, pml4e, pdpe, pde, pte);
					range.ptes++;
				}
			}
		}
	}

	error = sbuf_finish(sb);
	sbuf_delete(sb);
	return (error);
}
SYSCTL_OID(_vm_pmap, OID_AUTO, kernel_maps, CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_MPSAFE, NULL, 0, sysctl_kmaps, "A", "Dump kernel address layout");




DB_SHOW_COMMAND(pte, pmap_print_pte)
{
	pmap_t pmap;
	pml4_entry_t *pml4;
	pdp_entry_t *pdp;
	pd_entry_t *pde;
	pt_entry_t *pte, PG_V;
	vm_offset_t va;

	if (!have_addr) {
		db_printf("show pte addr\n");
		return;
	}
	va = (vm_offset_t)addr;

	if (kdb_thread != NULL)
		pmap = vmspace_pmap(kdb_thread->td_proc->p_vmspace);
	else pmap = PCPU_GET(curpmap);

	PG_V = pmap_valid_bit(pmap);
	pml4 = pmap_pml4e(pmap, va);
	db_printf("VA 0x%016lx pml4e 0x%016lx", va, *pml4);
	if ((*pml4 & PG_V) == 0) {
		db_printf("\n");
		return;
	}
	pdp = pmap_pml4e_to_pdpe(pml4, va);
	db_printf(" pdpe 0x%016lx", *pdp);
	if ((*pdp & PG_V) == 0 || (*pdp & PG_PS) != 0) {
		db_printf("\n");
		return;
	}
	pde = pmap_pdpe_to_pde(pdp, va);
	db_printf(" pde 0x%016lx", *pde);
	if ((*pde & PG_V) == 0 || (*pde & PG_PS) != 0) {
		db_printf("\n");
		return;
	}
	pte = pmap_pde_to_pte(pde, va);
	db_printf(" pte 0x%016lx\n", *pte);
}

DB_SHOW_COMMAND(phys2dmap, pmap_phys2dmap)
{
	vm_paddr_t a;

	if (have_addr) {
		a = (vm_paddr_t)addr;
		db_printf("0x%jx\n", (uintmax_t)PHYS_TO_DMAP(a));
	} else {
		db_printf("show phys2dmap addr\n");
	}
}

