


























static inline int is_gru_paddr(unsigned long paddr)
{
	return paddr >= gru_start_paddr && paddr < gru_end_paddr;
}


struct vm_area_struct *gru_find_vma(unsigned long vaddr)
{
	struct vm_area_struct *vma;

	vma = vma_lookup(current->mm, vaddr);
	if (vma && vma->vm_ops == &gru_vm_ops)
		return vma;
	return NULL;
}



static struct gru_thread_state *gru_find_lock_gts(unsigned long vaddr)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	struct gru_thread_state *gts = NULL;

	mmap_read_lock(mm);
	vma = gru_find_vma(vaddr);
	if (vma)
		gts = gru_find_thread_state(vma, TSID(vaddr, vma));
	if (gts)
		mutex_lock(&gts->ts_ctxlock);
	else mmap_read_unlock(mm);
	return gts;
}

static struct gru_thread_state *gru_alloc_locked_gts(unsigned long vaddr)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	struct gru_thread_state *gts = ERR_PTR(-EINVAL);

	mmap_write_lock(mm);
	vma = gru_find_vma(vaddr);
	if (!vma)
		goto err;

	gts = gru_alloc_thread_state(vma, TSID(vaddr, vma));
	if (IS_ERR(gts))
		goto err;
	mutex_lock(&gts->ts_ctxlock);
	mmap_write_downgrade(mm);
	return gts;

err:
	mmap_write_unlock(mm);
	return gts;
}


static void gru_unlock_gts(struct gru_thread_state *gts)
{
	mutex_unlock(&gts->ts_ctxlock);
	mmap_read_unlock(current->mm);
}


static void gru_cb_set_istatus_active(struct gru_instruction_bits *cbk)
{
	if (cbk) {
		cbk->istatus = CBS_ACTIVE;
	}
}


static void get_clear_fault_map(struct gru_state *gru, struct gru_tlb_fault_map *imap, struct gru_tlb_fault_map *dmap)

{
	unsigned long i, k;
	struct gru_tlb_fault_map *tfm;

	tfm = get_tfm_for_cpu(gru, gru_cpu_fault_map_id());
	prefetchw(tfm);		
	for (i = 0; i < BITS_TO_LONGS(GRU_NUM_CBE); i++) {
		k = tfm->fault_bits[i];
		if (k)
			k = xchg(&tfm->fault_bits[i], 0UL);
		imap->fault_bits[i] = k;
		k = tfm->done_bits[i];
		if (k)
			k = xchg(&tfm->done_bits[i], 0UL);
		dmap->fault_bits[i] = k;
	}

	
	gru_flush_cache(tfm);
}


static int non_atomic_pte_lookup(struct vm_area_struct *vma, unsigned long vaddr, int write, unsigned long *paddr, int *pageshift)

{
	struct page *page;


	*pageshift = is_vm_hugetlb_page(vma) ? HPAGE_SHIFT : PAGE_SHIFT;

	*pageshift = PAGE_SHIFT;

	if (get_user_pages(vaddr, 1, write ? FOLL_WRITE : 0, &page, NULL) <= 0)
		return -EFAULT;
	*paddr = page_to_phys(page);
	put_page(page);
	return 0;
}


static int atomic_pte_lookup(struct vm_area_struct *vma, unsigned long vaddr, int write, unsigned long *paddr, int *pageshift)
{
	pgd_t *pgdp;
	p4d_t *p4dp;
	pud_t *pudp;
	pmd_t *pmdp;
	pte_t pte;

	pgdp = pgd_offset(vma->vm_mm, vaddr);
	if (unlikely(pgd_none(*pgdp)))
		goto err;

	p4dp = p4d_offset(pgdp, vaddr);
	if (unlikely(p4d_none(*p4dp)))
		goto err;

	pudp = pud_offset(p4dp, vaddr);
	if (unlikely(pud_none(*pudp)))
		goto err;

	pmdp = pmd_offset(pudp, vaddr);
	if (unlikely(pmd_none(*pmdp)))
		goto err;

	if (unlikely(pmd_large(*pmdp)))
		pte = *(pte_t *) pmdp;
	else  pte = *pte_offset_kernel(pmdp, vaddr);


	if (unlikely(!pte_present(pte) || (write && (!pte_write(pte) || !pte_dirty(pte)))))
		return 1;

	*paddr = pte_pfn(pte) << PAGE_SHIFT;

	*pageshift = is_vm_hugetlb_page(vma) ? HPAGE_SHIFT : PAGE_SHIFT;

	*pageshift = PAGE_SHIFT;

	return 0;

err:
	return 1;
}

static int gru_vtop(struct gru_thread_state *gts, unsigned long vaddr, int write, int atomic, unsigned long *gpa, int *pageshift)
{
	struct mm_struct *mm = gts->ts_mm;
	struct vm_area_struct *vma;
	unsigned long paddr;
	int ret, ps;

	vma = find_vma(mm, vaddr);
	if (!vma)
		goto inval;

	
	rmb();	
	ret = atomic_pte_lookup(vma, vaddr, write, &paddr, &ps);
	if (ret) {
		if (atomic)
			goto upm;
		if (non_atomic_pte_lookup(vma, vaddr, write, &paddr, &ps))
			goto inval;
	}
	if (is_gru_paddr(paddr))
		goto inval;
	paddr = paddr & ~((1UL << ps) - 1);
	*gpa = uv_soc_phys_ram_to_gpa(paddr);
	*pageshift = ps;
	return VTOP_SUCCESS;

inval:
	return VTOP_INVALID;
upm:
	return VTOP_RETRY;
}



static void gru_flush_cache_cbe(struct gru_control_block_extended *cbe)
{
	if (unlikely(cbe)) {
		cbe->cbrexecstatus = 0;         
		gru_flush_cache(cbe);
	}
}


static void gru_preload_tlb(struct gru_state *gru, struct gru_thread_state *gts, int atomic, unsigned long fault_vaddr, int asid, int write, unsigned char tlb_preload_count, struct gru_tlb_fault_handle *tfh, struct gru_control_block_extended *cbe)




{
	unsigned long vaddr = 0, gpa;
	int ret, pageshift;

	if (cbe->opccpy != OP_BCOPY)
		return;

	if (fault_vaddr == cbe->cbe_baddr0)
		vaddr = fault_vaddr + GRU_CACHE_LINE_BYTES * cbe->cbe_src_cl - 1;
	else if (fault_vaddr == cbe->cbe_baddr1)
		vaddr = fault_vaddr + (1 << cbe->xtypecpy) * cbe->cbe_nelemcur - 1;

	fault_vaddr &= PAGE_MASK;
	vaddr &= PAGE_MASK;
	vaddr = min(vaddr, fault_vaddr + tlb_preload_count * PAGE_SIZE);

	while (vaddr > fault_vaddr) {
		ret = gru_vtop(gts, vaddr, write, atomic, &gpa, &pageshift);
		if (ret || tfh_write_only(tfh, gpa, GAA_RAM, vaddr, asid, write, GRU_PAGESIZE(pageshift)))
			return;
		gru_dbg(grudev, "%s: gid %d, gts 0x%p, tfh 0x%p, vaddr 0x%lx, asid 0x%x, rw %d, ps %d, gpa 0x%lx\n", atomic ? "atomic" : "non-atomic", gru->gs_gid, gts, tfh, vaddr, asid, write, pageshift, gpa);


		vaddr -= PAGE_SIZE;
		STAT(tlb_preload_page);
	}
}


static int gru_try_dropin(struct gru_state *gru, struct gru_thread_state *gts, struct gru_tlb_fault_handle *tfh, struct gru_instruction_bits *cbk)


{
	struct gru_control_block_extended *cbe = NULL;
	unsigned char tlb_preload_count = gts->ts_tlb_preload_count;
	int pageshift = 0, asid, write, ret, atomic = !cbk, indexway;
	unsigned long gpa = 0, vaddr = 0;

	

	
	if (unlikely(tlb_preload_count)) {
		cbe = gru_tfh_to_cbe(tfh);
		prefetchw(cbe);
	}

	
	if (tfh->status != TFHSTATUS_EXCEPTION) {
		gru_flush_cache(tfh);
		sync_core();
		if (tfh->status != TFHSTATUS_EXCEPTION)
			goto failnoexception;
		STAT(tfh_stale_on_fault);
	}
	if (tfh->state == TFHSTATE_IDLE)
		goto failidle;
	if (tfh->state == TFHSTATE_MISS_FMM && cbk)
		goto failfmm;

	write = (tfh->cause & TFHCAUSE_TLB_MOD) != 0;
	vaddr = tfh->missvaddr;
	asid = tfh->missasid;
	indexway = tfh->indexway;
	if (asid == 0)
		goto failnoasid;

	rmb();	

	
	if (atomic_read(&gts->ts_gms->ms_range_active))
		goto failactive;

	ret = gru_vtop(gts, vaddr, write, atomic, &gpa, &pageshift);
	if (ret == VTOP_INVALID)
		goto failinval;
	if (ret == VTOP_RETRY)
		goto failupm;

	if (!(gts->ts_sizeavail & GRU_SIZEAVAIL(pageshift))) {
		gts->ts_sizeavail |= GRU_SIZEAVAIL(pageshift);
		if (atomic || !gru_update_cch(gts)) {
			gts->ts_force_cch_reload = 1;
			goto failupm;
		}
	}

	if (unlikely(cbe) && pageshift == PAGE_SHIFT) {
		gru_preload_tlb(gru, gts, atomic, vaddr, asid, write, tlb_preload_count, tfh, cbe);
		gru_flush_cache_cbe(cbe);
	}

	gru_cb_set_istatus_active(cbk);
	gts->ustats.tlbdropin++;
	tfh_write_restart(tfh, gpa, GAA_RAM, vaddr, asid, write, GRU_PAGESIZE(pageshift));
	gru_dbg(grudev, "%s: gid %d, gts 0x%p, tfh 0x%p, vaddr 0x%lx, asid 0x%x, indexway 0x%x," " rw %d, ps %d, gpa 0x%lx\n", atomic ? "atomic" : "non-atomic", gru->gs_gid, gts, tfh, vaddr, asid, indexway, write, pageshift, gpa);



	STAT(tlb_dropin);
	return 0;

failnoasid:
	
	STAT(tlb_dropin_fail_no_asid);
	gru_dbg(grudev, "FAILED no_asid tfh: 0x%p, vaddr 0x%lx\n", tfh, vaddr);
	if (!cbk)
		tfh_user_polling_mode(tfh);
	else gru_flush_cache(tfh);
	gru_flush_cache_cbe(cbe);
	return -EAGAIN;

failupm:
	
	tfh_user_polling_mode(tfh);
	gru_flush_cache_cbe(cbe);
	STAT(tlb_dropin_fail_upm);
	gru_dbg(grudev, "FAILED upm tfh: 0x%p, vaddr 0x%lx\n", tfh, vaddr);
	return 1;

failfmm:
	
	gru_flush_cache(tfh);
	gru_flush_cache_cbe(cbe);
	STAT(tlb_dropin_fail_fmm);
	gru_dbg(grudev, "FAILED fmm tfh: 0x%p, state %d\n", tfh, tfh->state);
	return 0;

failnoexception:
	
	gru_flush_cache(tfh);
	gru_flush_cache_cbe(cbe);
	if (cbk)
		gru_flush_cache(cbk);
	STAT(tlb_dropin_fail_no_exception);
	gru_dbg(grudev, "FAILED non-exception tfh: 0x%p, status %d, state %d\n", tfh, tfh->status, tfh->state);
	return 0;

failidle:
	
	gru_flush_cache(tfh);
	gru_flush_cache_cbe(cbe);
	if (cbk)
		gru_flush_cache(cbk);
	STAT(tlb_dropin_fail_idle);
	gru_dbg(grudev, "FAILED idle tfh: 0x%p, state %d\n", tfh, tfh->state);
	return 0;

failinval:
	
	tfh_exception(tfh);
	gru_flush_cache_cbe(cbe);
	STAT(tlb_dropin_fail_invalid);
	gru_dbg(grudev, "FAILED inval tfh: 0x%p, vaddr 0x%lx\n", tfh, vaddr);
	return -EFAULT;

failactive:
	
	if (!cbk)
		tfh_user_polling_mode(tfh);
	else gru_flush_cache(tfh);
	gru_flush_cache_cbe(cbe);
	STAT(tlb_dropin_fail_range_active);
	gru_dbg(grudev, "FAILED range active: tfh 0x%p, vaddr 0x%lx\n", tfh, vaddr);
	return 1;
}


static irqreturn_t gru_intr(int chiplet, int blade)
{
	struct gru_state *gru;
	struct gru_tlb_fault_map imap, dmap;
	struct gru_thread_state *gts;
	struct gru_tlb_fault_handle *tfh = NULL;
	struct completion *cmp;
	int cbrnum, ctxnum;

	STAT(intr);

	gru = &gru_base[blade]->bs_grus[chiplet];
	if (!gru) {
		dev_err(grudev, "GRU: invalid interrupt: cpu %d, chiplet %d\n", raw_smp_processor_id(), chiplet);
		return IRQ_NONE;
	}
	get_clear_fault_map(gru, &imap, &dmap);
	gru_dbg(grudev, "cpu %d, chiplet %d, gid %d, imap %016lx %016lx, dmap %016lx %016lx\n", smp_processor_id(), chiplet, gru->gs_gid, imap.fault_bits[0], imap.fault_bits[1], dmap.fault_bits[0], dmap.fault_bits[1]);




	for_each_cbr_in_tfm(cbrnum, dmap.fault_bits) {
		STAT(intr_cbr);
		cmp = gru->gs_blade->bs_async_wq;
		if (cmp)
			complete(cmp);
		gru_dbg(grudev, "gid %d, cbr_done %d, done %d\n", gru->gs_gid, cbrnum, cmp ? cmp->done : -1);
	}

	for_each_cbr_in_tfm(cbrnum, imap.fault_bits) {
		STAT(intr_tfh);
		tfh = get_tfh_by_index(gru, cbrnum);
		prefetchw(tfh);	

		
		ctxnum = tfh->ctxnum;
		gts = gru->gs_gts[ctxnum];

		
		if (!gts) {
			STAT(intr_spurious);
			continue;
		}

		
		gts->ustats.fmm_tlbmiss++;
		if (!gts->ts_force_cch_reload && mmap_read_trylock(gts->ts_mm)) {
			gru_try_dropin(gru, gts, tfh, NULL);
			mmap_read_unlock(gts->ts_mm);
		} else {
			tfh_user_polling_mode(tfh);
			STAT(intr_mm_lock_failed);
		}
	}
	return IRQ_HANDLED;
}

irqreturn_t gru0_intr(int irq, void *dev_id)
{
	return gru_intr(0, uv_numa_blade_id());
}

irqreturn_t gru1_intr(int irq, void *dev_id)
{
	return gru_intr(1, uv_numa_blade_id());
}

irqreturn_t gru_intr_mblade(int irq, void *dev_id)
{
	int blade;

	for_each_possible_blade(blade) {
		if (uv_blade_nr_possible_cpus(blade))
			continue;
		gru_intr(0, blade);
		gru_intr(1, blade);
	}
	return IRQ_HANDLED;
}


static int gru_user_dropin(struct gru_thread_state *gts, struct gru_tlb_fault_handle *tfh, void *cb)

{
	struct gru_mm_struct *gms = gts->ts_gms;
	int ret;

	gts->ustats.upm_tlbmiss++;
	while (1) {
		wait_event(gms->ms_wait_queue, atomic_read(&gms->ms_range_active) == 0);
		prefetchw(tfh);	
		ret = gru_try_dropin(gts->ts_gru, gts, tfh, cb);
		if (ret <= 0)
			return ret;
		STAT(call_os_wait_queue);
	}
}


int gru_handle_user_call_os(unsigned long cb)
{
	struct gru_tlb_fault_handle *tfh;
	struct gru_thread_state *gts;
	void *cbk;
	int ucbnum, cbrnum, ret = -EINVAL;

	STAT(call_os);

	
	ucbnum = get_cb_number((void *)cb);
	if ((cb & (GRU_HANDLE_STRIDE - 1)) || ucbnum >= GRU_NUM_CB)
		return -EINVAL;

	gts = gru_find_lock_gts(cb);
	if (!gts)
		return -EINVAL;
	gru_dbg(grudev, "address 0x%lx, gid %d, gts 0x%p\n", cb, gts->ts_gru ? gts->ts_gru->gs_gid : -1, gts);

	if (ucbnum >= gts->ts_cbr_au_count * GRU_CBR_AU_SIZE)
		goto exit;

	gru_check_context_placement(gts);

	
	if (gts->ts_gru && gts->ts_force_cch_reload) {
		gts->ts_force_cch_reload = 0;
		gru_update_cch(gts);
	}

	ret = -EAGAIN;
	cbrnum = thread_cbr_number(gts, ucbnum);
	if (gts->ts_gru) {
		tfh = get_tfh_by_index(gts->ts_gru, cbrnum);
		cbk = get_gseg_base_address_cb(gts->ts_gru->gs_gru_base_vaddr, gts->ts_ctxnum, ucbnum);
		ret = gru_user_dropin(gts, tfh, cbk);
	}
exit:
	gru_unlock_gts(gts);
	return ret;
}


int gru_get_exception_detail(unsigned long arg)
{
	struct control_block_extended_exc_detail excdet;
	struct gru_control_block_extended *cbe;
	struct gru_thread_state *gts;
	int ucbnum, cbrnum, ret;

	STAT(user_exception);
	if (copy_from_user(&excdet, (void __user *)arg, sizeof(excdet)))
		return -EFAULT;

	gts = gru_find_lock_gts(excdet.cb);
	if (!gts)
		return -EINVAL;

	gru_dbg(grudev, "address 0x%lx, gid %d, gts 0x%p\n", excdet.cb, gts->ts_gru ? gts->ts_gru->gs_gid : -1, gts);
	ucbnum = get_cb_number((void *)excdet.cb);
	if (ucbnum >= gts->ts_cbr_au_count * GRU_CBR_AU_SIZE) {
		ret = -EINVAL;
	} else if (gts->ts_gru) {
		cbrnum = thread_cbr_number(gts, ucbnum);
		cbe = get_cbe_by_index(gts->ts_gru, cbrnum);
		gru_flush_cache(cbe);	
		sync_core();		
		excdet.opc = cbe->opccpy;
		excdet.exopc = cbe->exopccpy;
		excdet.ecause = cbe->ecause;
		excdet.exceptdet0 = cbe->idef1upd;
		excdet.exceptdet1 = cbe->idef3upd;
		excdet.cbrstate = cbe->cbrstate;
		excdet.cbrexecstatus = cbe->cbrexecstatus;
		gru_flush_cache_cbe(cbe);
		ret = 0;
	} else {
		ret = -EAGAIN;
	}
	gru_unlock_gts(gts);

	gru_dbg(grudev, "cb 0x%lx, op %d, exopc %d, cbrstate %d, cbrexecstatus 0x%x, ecause 0x%x, " "exdet0 0x%lx, exdet1 0x%x\n", excdet.cb, excdet.opc, excdet.exopc, excdet.cbrstate, excdet.cbrexecstatus, excdet.ecause, excdet.exceptdet0, excdet.exceptdet1);



	if (!ret && copy_to_user((void __user *)arg, &excdet, sizeof(excdet)))
		ret = -EFAULT;
	return ret;
}


static int gru_unload_all_contexts(void)
{
	struct gru_thread_state *gts;
	struct gru_state *gru;
	int gid, ctxnum;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	foreach_gid(gid) {
		gru = GID_TO_GRU(gid);
		spin_lock(&gru->gs_lock);
		for (ctxnum = 0; ctxnum < GRU_NUM_CCH; ctxnum++) {
			gts = gru->gs_gts[ctxnum];
			if (gts && mutex_trylock(&gts->ts_ctxlock)) {
				spin_unlock(&gru->gs_lock);
				gru_unload_context(gts, 1);
				mutex_unlock(&gts->ts_ctxlock);
				spin_lock(&gru->gs_lock);
			}
		}
		spin_unlock(&gru->gs_lock);
	}
	return 0;
}

int gru_user_unload_context(unsigned long arg)
{
	struct gru_thread_state *gts;
	struct gru_unload_context_req req;

	STAT(user_unload_context);
	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;

	gru_dbg(grudev, "gseg 0x%lx\n", req.gseg);

	if (!req.gseg)
		return gru_unload_all_contexts();

	gts = gru_find_lock_gts(req.gseg);
	if (!gts)
		return -EINVAL;

	if (gts->ts_gru)
		gru_unload_context(gts, 1);
	gru_unlock_gts(gts);

	return 0;
}


int gru_user_flush_tlb(unsigned long arg)
{
	struct gru_thread_state *gts;
	struct gru_flush_tlb_req req;
	struct gru_mm_struct *gms;

	STAT(user_flush_tlb);
	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;

	gru_dbg(grudev, "gseg 0x%lx, vaddr 0x%lx, len 0x%lx\n", req.gseg, req.vaddr, req.len);

	gts = gru_find_lock_gts(req.gseg);
	if (!gts)
		return -EINVAL;

	gms = gts->ts_gms;
	gru_unlock_gts(gts);
	gru_flush_tlb_range(gms, req.vaddr, req.len);

	return 0;
}


long gru_get_gseg_statistics(unsigned long arg)
{
	struct gru_thread_state *gts;
	struct gru_get_gseg_statistics_req req;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;

	
	gts = gru_find_lock_gts(req.gseg);
	if (gts) {
		memcpy(&req.stats, &gts->ustats, sizeof(gts->ustats));
		gru_unlock_gts(gts);
	} else {
		memset(&req.stats, 0, sizeof(gts->ustats));
	}

	if (copy_to_user((void __user *)arg, &req, sizeof(req)))
		return -EFAULT;

	return 0;
}


int gru_set_context_option(unsigned long arg)
{
	struct gru_thread_state *gts;
	struct gru_set_context_option_req req;
	int ret = 0;

	STAT(set_context_option);
	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;
	gru_dbg(grudev, "op %d, gseg 0x%lx, value1 0x%lx\n", req.op, req.gseg, req.val1);

	gts = gru_find_lock_gts(req.gseg);
	if (!gts) {
		gts = gru_alloc_locked_gts(req.gseg);
		if (IS_ERR(gts))
			return PTR_ERR(gts);
	}

	switch (req.op) {
	case sco_blade_chiplet:
		
		if (req.val0 < -1 || req.val0 >= GRU_CHIPLETS_PER_HUB || req.val1 < -1 || req.val1 >= GRU_MAX_BLADES || (req.val1 >= 0 && !gru_base[req.val1])) {

			ret = -EINVAL;
		} else {
			gts->ts_user_blade_id = req.val1;
			gts->ts_user_chiplet_id = req.val0;
			gru_check_context_placement(gts);
		}
		break;
	case sco_gseg_owner:
 		
		gts->ts_tgid_owner = current->tgid;
		break;
	case sco_cch_req_slice:
 		
		gts->ts_cch_req_slice = req.val1 & 3;
		break;
	default:
		ret = -EINVAL;
	}
	gru_unlock_gts(gts);

	return ret;
}
