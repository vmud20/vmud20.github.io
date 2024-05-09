





















static struct page *no_page_table(struct vm_area_struct *vma, unsigned int flags)
{
	
	if ((flags & FOLL_DUMP) && (!vma->vm_ops || !vma->vm_ops->fault))
		return ERR_PTR(-EFAULT);
	return NULL;
}

static int follow_pfn_pte(struct vm_area_struct *vma, unsigned long address, pte_t *pte, unsigned int flags)
{
	
	if (flags & FOLL_GET)
		return -EFAULT;

	if (flags & FOLL_TOUCH) {
		pte_t entry = *pte;

		if (flags & FOLL_WRITE)
			entry = pte_mkdirty(entry);
		entry = pte_mkyoung(entry);

		if (!pte_same(*pte, entry)) {
			set_pte_at(vma->vm_mm, address, pte, entry);
			update_mmu_cache(vma, address, pte);
		}
	}

	
	return -EEXIST;
}


static inline bool can_follow_write_pte(pte_t pte, unsigned int flags)
{
	return pte_write(pte) || ((flags & FOLL_FORCE) && (flags & FOLL_COW) && pte_dirty(pte));
}

static struct page *follow_page_pte(struct vm_area_struct *vma, unsigned long address, pmd_t *pmd, unsigned int flags)
{
	struct mm_struct *mm = vma->vm_mm;
	struct dev_pagemap *pgmap = NULL;
	struct page *page;
	spinlock_t *ptl;
	pte_t *ptep, pte;

retry:
	if (unlikely(pmd_bad(*pmd)))
		return no_page_table(vma, flags);

	ptep = pte_offset_map_lock(mm, pmd, address, &ptl);
	pte = *ptep;
	if (!pte_present(pte)) {
		swp_entry_t entry;
		
		if (likely(!(flags & FOLL_MIGRATION)))
			goto no_page;
		if (pte_none(pte))
			goto no_page;
		entry = pte_to_swp_entry(pte);
		if (!is_migration_entry(entry))
			goto no_page;
		pte_unmap_unlock(ptep, ptl);
		migration_entry_wait(mm, pmd, address);
		goto retry;
	}
	if ((flags & FOLL_NUMA) && pte_protnone(pte))
		goto no_page;
	if ((flags & FOLL_WRITE) && !can_follow_write_pte(pte, flags)) {
		pte_unmap_unlock(ptep, ptl);
		return NULL;
	}

	page = vm_normal_page(vma, address, pte);
	if (!page && pte_devmap(pte) && (flags & FOLL_GET)) {
		
		pgmap = get_dev_pagemap(pte_pfn(pte), NULL);
		if (pgmap)
			page = pte_page(pte);
		else goto no_page;
	} else if (unlikely(!page)) {
		if (flags & FOLL_DUMP) {
			
			page = ERR_PTR(-EFAULT);
			goto out;
		}

		if (is_zero_pfn(pte_pfn(pte))) {
			page = pte_page(pte);
		} else {
			int ret;

			ret = follow_pfn_pte(vma, address, ptep, flags);
			page = ERR_PTR(ret);
			goto out;
		}
	}

	if (flags & FOLL_SPLIT && PageTransCompound(page)) {
		int ret;
		get_page(page);
		pte_unmap_unlock(ptep, ptl);
		lock_page(page);
		ret = split_huge_page(page);
		unlock_page(page);
		put_page(page);
		if (ret)
			return ERR_PTR(ret);
		goto retry;
	}

	if (flags & FOLL_GET) {
		get_page(page);

		
		if (pgmap) {
			put_dev_pagemap(pgmap);
			pgmap = NULL;
		}
	}
	if (flags & FOLL_TOUCH) {
		if ((flags & FOLL_WRITE) && !pte_dirty(pte) && !PageDirty(page))
			set_page_dirty(page);
		
		mark_page_accessed(page);
	}
	if ((flags & FOLL_MLOCK) && (vma->vm_flags & VM_LOCKED)) {
		
		if (PageTransCompound(page))
			goto out;

		
		if (page->mapping && trylock_page(page)) {
			lru_add_drain();  
			
			mlock_vma_page(page);
			unlock_page(page);
		}
	}
out:
	pte_unmap_unlock(ptep, ptl);
	return page;
no_page:
	pte_unmap_unlock(ptep, ptl);
	if (!pte_none(pte))
		return NULL;
	return no_page_table(vma, flags);
}

static struct page *follow_pmd_mask(struct vm_area_struct *vma, unsigned long address, pud_t *pudp, unsigned int flags, unsigned int *page_mask)

{
	pmd_t *pmd;
	spinlock_t *ptl;
	struct page *page;
	struct mm_struct *mm = vma->vm_mm;

	pmd = pmd_offset(pudp, address);
	if (pmd_none(*pmd))
		return no_page_table(vma, flags);
	if (pmd_huge(*pmd) && vma->vm_flags & VM_HUGETLB) {
		page = follow_huge_pmd(mm, address, pmd, flags);
		if (page)
			return page;
		return no_page_table(vma, flags);
	}
	if (is_hugepd(__hugepd(pmd_val(*pmd)))) {
		page = follow_huge_pd(vma, address, __hugepd(pmd_val(*pmd)), flags, PMD_SHIFT);

		if (page)
			return page;
		return no_page_table(vma, flags);
	}
retry:
	if (!pmd_present(*pmd)) {
		if (likely(!(flags & FOLL_MIGRATION)))
			return no_page_table(vma, flags);
		VM_BUG_ON(thp_migration_supported() && !is_pmd_migration_entry(*pmd));
		if (is_pmd_migration_entry(*pmd))
			pmd_migration_entry_wait(mm, pmd);
		goto retry;
	}
	if (pmd_devmap(*pmd)) {
		ptl = pmd_lock(mm, pmd);
		page = follow_devmap_pmd(vma, address, pmd, flags);
		spin_unlock(ptl);
		if (page)
			return page;
	}
	if (likely(!pmd_trans_huge(*pmd)))
		return follow_page_pte(vma, address, pmd, flags);

	if ((flags & FOLL_NUMA) && pmd_protnone(*pmd))
		return no_page_table(vma, flags);

retry_locked:
	ptl = pmd_lock(mm, pmd);
	if (unlikely(!pmd_present(*pmd))) {
		spin_unlock(ptl);
		if (likely(!(flags & FOLL_MIGRATION)))
			return no_page_table(vma, flags);
		pmd_migration_entry_wait(mm, pmd);
		goto retry_locked;
	}
	if (unlikely(!pmd_trans_huge(*pmd))) {
		spin_unlock(ptl);
		return follow_page_pte(vma, address, pmd, flags);
	}
	if (flags & FOLL_SPLIT) {
		int ret;
		page = pmd_page(*pmd);
		if (is_huge_zero_page(page)) {
			spin_unlock(ptl);
			ret = 0;
			split_huge_pmd(vma, pmd, address);
			if (pmd_trans_unstable(pmd))
				ret = -EBUSY;
		} else {
			get_page(page);
			spin_unlock(ptl);
			lock_page(page);
			ret = split_huge_page(page);
			unlock_page(page);
			put_page(page);
			if (pmd_none(*pmd))
				return no_page_table(vma, flags);
		}

		return ret ? ERR_PTR(ret) :
			follow_page_pte(vma, address, pmd, flags);
	}
	page = follow_trans_huge_pmd(vma, address, pmd, flags);
	spin_unlock(ptl);
	*page_mask = HPAGE_PMD_NR - 1;
	return page;
}


static struct page *follow_pud_mask(struct vm_area_struct *vma, unsigned long address, p4d_t *p4dp, unsigned int flags, unsigned int *page_mask)

{
	pud_t *pud;
	spinlock_t *ptl;
	struct page *page;
	struct mm_struct *mm = vma->vm_mm;

	pud = pud_offset(p4dp, address);
	if (pud_none(*pud))
		return no_page_table(vma, flags);
	if (pud_huge(*pud) && vma->vm_flags & VM_HUGETLB) {
		page = follow_huge_pud(mm, address, pud, flags);
		if (page)
			return page;
		return no_page_table(vma, flags);
	}
	if (is_hugepd(__hugepd(pud_val(*pud)))) {
		page = follow_huge_pd(vma, address, __hugepd(pud_val(*pud)), flags, PUD_SHIFT);

		if (page)
			return page;
		return no_page_table(vma, flags);
	}
	if (pud_devmap(*pud)) {
		ptl = pud_lock(mm, pud);
		page = follow_devmap_pud(vma, address, pud, flags);
		spin_unlock(ptl);
		if (page)
			return page;
	}
	if (unlikely(pud_bad(*pud)))
		return no_page_table(vma, flags);

	return follow_pmd_mask(vma, address, pud, flags, page_mask);
}


static struct page *follow_p4d_mask(struct vm_area_struct *vma, unsigned long address, pgd_t *pgdp, unsigned int flags, unsigned int *page_mask)

{
	p4d_t *p4d;
	struct page *page;

	p4d = p4d_offset(pgdp, address);
	if (p4d_none(*p4d))
		return no_page_table(vma, flags);
	BUILD_BUG_ON(p4d_huge(*p4d));
	if (unlikely(p4d_bad(*p4d)))
		return no_page_table(vma, flags);

	if (is_hugepd(__hugepd(p4d_val(*p4d)))) {
		page = follow_huge_pd(vma, address, __hugepd(p4d_val(*p4d)), flags, P4D_SHIFT);

		if (page)
			return page;
		return no_page_table(vma, flags);
	}
	return follow_pud_mask(vma, address, p4d, flags, page_mask);
}


struct page *follow_page_mask(struct vm_area_struct *vma, unsigned long address, unsigned int flags, unsigned int *page_mask)

{
	pgd_t *pgd;
	struct page *page;
	struct mm_struct *mm = vma->vm_mm;

	*page_mask = 0;

	
	page = follow_huge_addr(mm, address, flags & FOLL_WRITE);
	if (!IS_ERR(page)) {
		BUG_ON(flags & FOLL_GET);
		return page;
	}

	pgd = pgd_offset(mm, address);

	if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))
		return no_page_table(vma, flags);

	if (pgd_huge(*pgd)) {
		page = follow_huge_pgd(mm, address, pgd, flags);
		if (page)
			return page;
		return no_page_table(vma, flags);
	}
	if (is_hugepd(__hugepd(pgd_val(*pgd)))) {
		page = follow_huge_pd(vma, address, __hugepd(pgd_val(*pgd)), flags, PGDIR_SHIFT);

		if (page)
			return page;
		return no_page_table(vma, flags);
	}

	return follow_p4d_mask(vma, address, pgd, flags, page_mask);
}

static int get_gate_page(struct mm_struct *mm, unsigned long address, unsigned int gup_flags, struct vm_area_struct **vma, struct page **page)

{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	int ret = -EFAULT;

	
	if (gup_flags & FOLL_WRITE)
		return -EFAULT;
	if (address > TASK_SIZE)
		pgd = pgd_offset_k(address);
	else pgd = pgd_offset_gate(mm, address);
	BUG_ON(pgd_none(*pgd));
	p4d = p4d_offset(pgd, address);
	BUG_ON(p4d_none(*p4d));
	pud = pud_offset(p4d, address);
	BUG_ON(pud_none(*pud));
	pmd = pmd_offset(pud, address);
	if (!pmd_present(*pmd))
		return -EFAULT;
	VM_BUG_ON(pmd_trans_huge(*pmd));
	pte = pte_offset_map(pmd, address);
	if (pte_none(*pte))
		goto unmap;
	*vma = get_gate_vma(mm);
	if (!page)
		goto out;
	*page = vm_normal_page(*vma, address, *pte);
	if (!*page) {
		if ((gup_flags & FOLL_DUMP) || !is_zero_pfn(pte_pfn(*pte)))
			goto unmap;
		*page = pte_page(*pte);

		
		if (is_device_public_page(*page))
			goto unmap;
	}
	get_page(*page);
out:
	ret = 0;
unmap:
	pte_unmap(pte);
	return ret;
}


static int faultin_page(struct task_struct *tsk, struct vm_area_struct *vma, unsigned long address, unsigned int *flags, int *nonblocking)
{
	unsigned int fault_flags = 0;
	int ret;

	
	if ((*flags & (FOLL_POPULATE | FOLL_MLOCK)) == FOLL_MLOCK)
		return -ENOENT;
	if (*flags & FOLL_WRITE)
		fault_flags |= FAULT_FLAG_WRITE;
	if (*flags & FOLL_REMOTE)
		fault_flags |= FAULT_FLAG_REMOTE;
	if (nonblocking)
		fault_flags |= FAULT_FLAG_ALLOW_RETRY;
	if (*flags & FOLL_NOWAIT)
		fault_flags |= FAULT_FLAG_ALLOW_RETRY | FAULT_FLAG_RETRY_NOWAIT;
	if (*flags & FOLL_TRIED) {
		VM_WARN_ON_ONCE(fault_flags & FAULT_FLAG_ALLOW_RETRY);
		fault_flags |= FAULT_FLAG_TRIED;
	}

	ret = handle_mm_fault(vma, address, fault_flags);
	if (ret & VM_FAULT_ERROR) {
		int err = vm_fault_to_errno(ret, *flags);

		if (err)
			return err;
		BUG();
	}

	if (tsk) {
		if (ret & VM_FAULT_MAJOR)
			tsk->maj_flt++;
		else tsk->min_flt++;
	}

	if (ret & VM_FAULT_RETRY) {
		if (nonblocking && !(fault_flags & FAULT_FLAG_RETRY_NOWAIT))
			*nonblocking = 0;
		return -EBUSY;
	}

	
	if ((ret & VM_FAULT_WRITE) && !(vma->vm_flags & VM_WRITE))
		*flags |= FOLL_COW;
	return 0;
}

static int check_vma_flags(struct vm_area_struct *vma, unsigned long gup_flags)
{
	vm_flags_t vm_flags = vma->vm_flags;
	int write = (gup_flags & FOLL_WRITE);
	int foreign = (gup_flags & FOLL_REMOTE);

	if (vm_flags & (VM_IO | VM_PFNMAP))
		return -EFAULT;

	if (write) {
		if (!(vm_flags & VM_WRITE)) {
			if (!(gup_flags & FOLL_FORCE))
				return -EFAULT;
			
			if (!is_cow_mapping(vm_flags))
				return -EFAULT;
		}
	} else if (!(vm_flags & VM_READ)) {
		if (!(gup_flags & FOLL_FORCE))
			return -EFAULT;
		
		if (!(vm_flags & VM_MAYREAD))
			return -EFAULT;
	}
	
	if (!arch_vma_access_permitted(vma, write, false, foreign))
		return -EFAULT;
	return 0;
}


static long __get_user_pages(struct task_struct *tsk, struct mm_struct *mm, unsigned long start, unsigned long nr_pages, unsigned int gup_flags, struct page **pages, struct vm_area_struct **vmas, int *nonblocking)


{
	long i = 0;
	unsigned int page_mask;
	struct vm_area_struct *vma = NULL;

	if (!nr_pages)
		return 0;

	VM_BUG_ON(!!pages != !!(gup_flags & FOLL_GET));

	
	if (!(gup_flags & FOLL_FORCE))
		gup_flags |= FOLL_NUMA;

	do {
		struct page *page;
		unsigned int foll_flags = gup_flags;
		unsigned int page_increm;

		
		if (!vma || start >= vma->vm_end) {
			vma = find_extend_vma(mm, start);
			if (!vma && in_gate_area(mm, start)) {
				int ret;
				ret = get_gate_page(mm, start & PAGE_MASK, gup_flags, &vma, pages ? &pages[i] : NULL);

				if (ret)
					return i ? : ret;
				page_mask = 0;
				goto next_page;
			}

			if (!vma || check_vma_flags(vma, gup_flags))
				return i ? : -EFAULT;
			if (is_vm_hugetlb_page(vma)) {
				i = follow_hugetlb_page(mm, vma, pages, vmas, &start, &nr_pages, i, gup_flags, nonblocking);

				continue;
			}
		}
retry:
		
		if (unlikely(fatal_signal_pending(current)))
			return i ? i : -ERESTARTSYS;
		cond_resched();
		page = follow_page_mask(vma, start, foll_flags, &page_mask);
		if (!page) {
			int ret;
			ret = faultin_page(tsk, vma, start, &foll_flags, nonblocking);
			switch (ret) {
			case 0:
				goto retry;
			case -EFAULT:
			case -ENOMEM:
			case -EHWPOISON:
				return i ? i : ret;
			case -EBUSY:
				return i;
			case -ENOENT:
				goto next_page;
			}
			BUG();
		} else if (PTR_ERR(page) == -EEXIST) {
			
			goto next_page;
		} else if (IS_ERR(page)) {
			return i ? i : PTR_ERR(page);
		}
		if (pages) {
			pages[i] = page;
			flush_anon_page(vma, page, start);
			flush_dcache_page(page);
			page_mask = 0;
		}
next_page:
		if (vmas) {
			vmas[i] = vma;
			page_mask = 0;
		}
		page_increm = 1 + (~(start >> PAGE_SHIFT) & page_mask);
		if (page_increm > nr_pages)
			page_increm = nr_pages;
		i += page_increm;
		start += page_increm * PAGE_SIZE;
		nr_pages -= page_increm;
	} while (nr_pages);
	return i;
}

static bool vma_permits_fault(struct vm_area_struct *vma, unsigned int fault_flags)
{
	bool write   = !!(fault_flags & FAULT_FLAG_WRITE);
	bool foreign = !!(fault_flags & FAULT_FLAG_REMOTE);
	vm_flags_t vm_flags = write ? VM_WRITE : VM_READ;

	if (!(vm_flags & vma->vm_flags))
		return false;

	
	if (!arch_vma_access_permitted(vma, write, false, foreign))
		return false;

	return true;
}


int fixup_user_fault(struct task_struct *tsk, struct mm_struct *mm, unsigned long address, unsigned int fault_flags, bool *unlocked)

{
	struct vm_area_struct *vma;
	int ret, major = 0;

	if (unlocked)
		fault_flags |= FAULT_FLAG_ALLOW_RETRY;

retry:
	vma = find_extend_vma(mm, address);
	if (!vma || address < vma->vm_start)
		return -EFAULT;

	if (!vma_permits_fault(vma, fault_flags))
		return -EFAULT;

	ret = handle_mm_fault(vma, address, fault_flags);
	major |= ret & VM_FAULT_MAJOR;
	if (ret & VM_FAULT_ERROR) {
		int err = vm_fault_to_errno(ret, 0);

		if (err)
			return err;
		BUG();
	}

	if (ret & VM_FAULT_RETRY) {
		down_read(&mm->mmap_sem);
		if (!(fault_flags & FAULT_FLAG_TRIED)) {
			*unlocked = true;
			fault_flags &= ~FAULT_FLAG_ALLOW_RETRY;
			fault_flags |= FAULT_FLAG_TRIED;
			goto retry;
		}
	}

	if (tsk) {
		if (major)
			tsk->maj_flt++;
		else tsk->min_flt++;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(fixup_user_fault);

static __always_inline long __get_user_pages_locked(struct task_struct *tsk, struct mm_struct *mm, unsigned long start, unsigned long nr_pages, struct page **pages, struct vm_area_struct **vmas, int *locked, unsigned int flags)






{
	long ret, pages_done;
	bool lock_dropped;

	if (locked) {
		
		BUG_ON(vmas);
		
		BUG_ON(*locked != 1);
	}

	if (pages)
		flags |= FOLL_GET;

	pages_done = 0;
	lock_dropped = false;
	for (;;) {
		ret = __get_user_pages(tsk, mm, start, nr_pages, flags, pages, vmas, locked);
		if (!locked)
			
			return ret;

		
		if (!*locked) {
			BUG_ON(ret < 0);
			BUG_ON(ret >= nr_pages);
		}

		if (!pages)
			
			return ret;

		if (ret > 0) {
			nr_pages -= ret;
			pages_done += ret;
			if (!nr_pages)
				break;
		}
		if (*locked) {
			
			if (!pages_done)
				pages_done = ret;
			break;
		}
		
		pages += ret;
		start += ret << PAGE_SHIFT;

		
		*locked = 1;
		lock_dropped = true;
		down_read(&mm->mmap_sem);
		ret = __get_user_pages(tsk, mm, start, 1, flags | FOLL_TRIED, pages, NULL, NULL);
		if (ret != 1) {
			BUG_ON(ret > 1);
			if (!pages_done)
				pages_done = ret;
			break;
		}
		nr_pages--;
		pages_done++;
		if (!nr_pages)
			break;
		pages++;
		start += PAGE_SIZE;
	}
	if (lock_dropped && *locked) {
		
		up_read(&mm->mmap_sem);
		*locked = 0;
	}
	return pages_done;
}


long get_user_pages_locked(unsigned long start, unsigned long nr_pages, unsigned int gup_flags, struct page **pages, int *locked)

{
	return __get_user_pages_locked(current, current->mm, start, nr_pages, pages, NULL, locked, gup_flags | FOLL_TOUCH);

}
EXPORT_SYMBOL(get_user_pages_locked);


long get_user_pages_unlocked(unsigned long start, unsigned long nr_pages, struct page **pages, unsigned int gup_flags)
{
	struct mm_struct *mm = current->mm;
	int locked = 1;
	long ret;

	down_read(&mm->mmap_sem);
	ret = __get_user_pages_locked(current, mm, start, nr_pages, pages, NULL, &locked, gup_flags | FOLL_TOUCH);
	if (locked)
		up_read(&mm->mmap_sem);
	return ret;
}
EXPORT_SYMBOL(get_user_pages_unlocked);


long get_user_pages_remote(struct task_struct *tsk, struct mm_struct *mm, unsigned long start, unsigned long nr_pages, unsigned int gup_flags, struct page **pages, struct vm_area_struct **vmas, int *locked)


{
	return __get_user_pages_locked(tsk, mm, start, nr_pages, pages, vmas, locked, gup_flags | FOLL_TOUCH | FOLL_REMOTE);

}
EXPORT_SYMBOL(get_user_pages_remote);


long get_user_pages(unsigned long start, unsigned long nr_pages, unsigned int gup_flags, struct page **pages, struct vm_area_struct **vmas)

{
	return __get_user_pages_locked(current, current->mm, start, nr_pages, pages, vmas, NULL, gup_flags | FOLL_TOUCH);

}
EXPORT_SYMBOL(get_user_pages);



long get_user_pages_longterm(unsigned long start, unsigned long nr_pages, unsigned int gup_flags, struct page **pages, struct vm_area_struct **vmas_arg)

{
	struct vm_area_struct **vmas = vmas_arg;
	struct vm_area_struct *vma_prev = NULL;
	long rc, i;

	if (!pages)
		return -EINVAL;

	if (!vmas) {
		vmas = kcalloc(nr_pages, sizeof(struct vm_area_struct *), GFP_KERNEL);
		if (!vmas)
			return -ENOMEM;
	}

	rc = get_user_pages(start, nr_pages, gup_flags, pages, vmas);

	for (i = 0; i < rc; i++) {
		struct vm_area_struct *vma = vmas[i];

		if (vma == vma_prev)
			continue;

		vma_prev = vma;

		if (vma_is_fsdax(vma))
			break;
	}

	
	if (i >= rc)
		goto out;

	for (i = 0; i < rc; i++)
		put_page(pages[i]);
	rc = -EOPNOTSUPP;
out:
	if (vmas != vmas_arg)
		kfree(vmas);
	return rc;
}
EXPORT_SYMBOL(get_user_pages_longterm);



long populate_vma_page_range(struct vm_area_struct *vma, unsigned long start, unsigned long end, int *nonblocking)
{
	struct mm_struct *mm = vma->vm_mm;
	unsigned long nr_pages = (end - start) / PAGE_SIZE;
	int gup_flags;

	VM_BUG_ON(start & ~PAGE_MASK);
	VM_BUG_ON(end   & ~PAGE_MASK);
	VM_BUG_ON_VMA(start < vma->vm_start, vma);
	VM_BUG_ON_VMA(end   > vma->vm_end, vma);
	VM_BUG_ON_MM(!rwsem_is_locked(&mm->mmap_sem), mm);

	gup_flags = FOLL_TOUCH | FOLL_POPULATE | FOLL_MLOCK;
	if (vma->vm_flags & VM_LOCKONFAULT)
		gup_flags &= ~FOLL_POPULATE;
	
	if ((vma->vm_flags & (VM_WRITE | VM_SHARED)) == VM_WRITE)
		gup_flags |= FOLL_WRITE;

	
	if (vma->vm_flags & (VM_READ | VM_WRITE | VM_EXEC))
		gup_flags |= FOLL_FORCE;

	
	return __get_user_pages(current, mm, start, nr_pages, gup_flags, NULL, NULL, nonblocking);
}


int __mm_populate(unsigned long start, unsigned long len, int ignore_errors)
{
	struct mm_struct *mm = current->mm;
	unsigned long end, nstart, nend;
	struct vm_area_struct *vma = NULL;
	int locked = 0;
	long ret = 0;

	VM_BUG_ON(start & ~PAGE_MASK);
	VM_BUG_ON(len != PAGE_ALIGN(len));
	end = start + len;

	for (nstart = start; nstart < end; nstart = nend) {
		
		if (!locked) {
			locked = 1;
			down_read(&mm->mmap_sem);
			vma = find_vma(mm, nstart);
		} else if (nstart >= vma->vm_end)
			vma = vma->vm_next;
		if (!vma || vma->vm_start >= end)
			break;
		
		nend = min(end, vma->vm_end);
		if (vma->vm_flags & (VM_IO | VM_PFNMAP))
			continue;
		if (nstart < vma->vm_start)
			nstart = vma->vm_start;
		
		ret = populate_vma_page_range(vma, nstart, nend, &locked);
		if (ret < 0) {
			if (ignore_errors) {
				ret = 0;
				continue;	
			}
			break;
		}
		nend = nstart + ret * PAGE_SIZE;
		ret = 0;
	}
	if (locked)
		up_read(&mm->mmap_sem);
	return ret;	
}



struct page *get_dump_page(unsigned long addr)
{
	struct vm_area_struct *vma;
	struct page *page;

	if (__get_user_pages(current, current->mm, addr, 1, FOLL_FORCE | FOLL_DUMP | FOLL_GET, &page, &vma, NULL) < 1)

		return NULL;
	flush_cache_page(vma, addr, page_to_pfn(page));
	return page;
}







static inline pte_t gup_get_pte(pte_t *ptep)
{
	return READ_ONCE(*ptep);
}


static void undo_dev_pagemap(int *nr, int nr_start, struct page **pages)
{
	while ((*nr) - nr_start) {
		struct page *page = pages[--(*nr)];

		ClearPageReferenced(page);
		put_page(page);
	}
}


static int gup_pte_range(pmd_t pmd, unsigned long addr, unsigned long end, int write, struct page **pages, int *nr)
{
	struct dev_pagemap *pgmap = NULL;
	int nr_start = *nr, ret = 0;
	pte_t *ptep, *ptem;

	ptem = ptep = pte_offset_map(&pmd, addr);
	do {
		pte_t pte = gup_get_pte(ptep);
		struct page *head, *page;

		
		if (pte_protnone(pte))
			goto pte_unmap;

		if (!pte_access_permitted(pte, write))
			goto pte_unmap;

		if (pte_devmap(pte)) {
			pgmap = get_dev_pagemap(pte_pfn(pte), pgmap);
			if (unlikely(!pgmap)) {
				undo_dev_pagemap(nr, nr_start, pages);
				goto pte_unmap;
			}
		} else if (pte_special(pte))
			goto pte_unmap;

		VM_BUG_ON(!pfn_valid(pte_pfn(pte)));
		page = pte_page(pte);
		head = compound_head(page);

		if (!page_cache_get_speculative(head))
			goto pte_unmap;

		if (unlikely(pte_val(pte) != pte_val(*ptep))) {
			put_page(head);
			goto pte_unmap;
		}

		VM_BUG_ON_PAGE(compound_head(page) != head, page);

		SetPageReferenced(page);
		pages[*nr] = page;
		(*nr)++;

	} while (ptep++, addr += PAGE_SIZE, addr != end);

	ret = 1;

pte_unmap:
	if (pgmap)
		put_dev_pagemap(pgmap);
	pte_unmap(ptem);
	return ret;
}



static int gup_pte_range(pmd_t pmd, unsigned long addr, unsigned long end, int write, struct page **pages, int *nr)
{
	return 0;
}



static int __gup_device_huge(unsigned long pfn, unsigned long addr, unsigned long end, struct page **pages, int *nr)
{
	int nr_start = *nr;
	struct dev_pagemap *pgmap = NULL;

	do {
		struct page *page = pfn_to_page(pfn);

		pgmap = get_dev_pagemap(pfn, pgmap);
		if (unlikely(!pgmap)) {
			undo_dev_pagemap(nr, nr_start, pages);
			return 0;
		}
		SetPageReferenced(page);
		pages[*nr] = page;
		get_page(page);
		(*nr)++;
		pfn++;
	} while (addr += PAGE_SIZE, addr != end);

	if (pgmap)
		put_dev_pagemap(pgmap);
	return 1;
}

static int __gup_device_huge_pmd(pmd_t pmd, unsigned long addr, unsigned long end, struct page **pages, int *nr)
{
	unsigned long fault_pfn;

	fault_pfn = pmd_pfn(pmd) + ((addr & ~PMD_MASK) >> PAGE_SHIFT);
	return __gup_device_huge(fault_pfn, addr, end, pages, nr);
}

static int __gup_device_huge_pud(pud_t pud, unsigned long addr, unsigned long end, struct page **pages, int *nr)
{
	unsigned long fault_pfn;

	fault_pfn = pud_pfn(pud) + ((addr & ~PUD_MASK) >> PAGE_SHIFT);
	return __gup_device_huge(fault_pfn, addr, end, pages, nr);
}

static int __gup_device_huge_pmd(pmd_t pmd, unsigned long addr, unsigned long end, struct page **pages, int *nr)
{
	BUILD_BUG();
	return 0;
}

static int __gup_device_huge_pud(pud_t pud, unsigned long addr, unsigned long end, struct page **pages, int *nr)
{
	BUILD_BUG();
	return 0;
}


static int gup_huge_pmd(pmd_t orig, pmd_t *pmdp, unsigned long addr, unsigned long end, int write, struct page **pages, int *nr)
{
	struct page *head, *page;
	int refs;

	if (!pmd_access_permitted(orig, write))
		return 0;

	if (pmd_devmap(orig))
		return __gup_device_huge_pmd(orig, addr, end, pages, nr);

	refs = 0;
	page = pmd_page(orig) + ((addr & ~PMD_MASK) >> PAGE_SHIFT);
	do {
		pages[*nr] = page;
		(*nr)++;
		page++;
		refs++;
	} while (addr += PAGE_SIZE, addr != end);

	head = compound_head(pmd_page(orig));
	if (!page_cache_add_speculative(head, refs)) {
		*nr -= refs;
		return 0;
	}

	if (unlikely(pmd_val(orig) != pmd_val(*pmdp))) {
		*nr -= refs;
		while (refs--)
			put_page(head);
		return 0;
	}

	SetPageReferenced(head);
	return 1;
}

static int gup_huge_pud(pud_t orig, pud_t *pudp, unsigned long addr, unsigned long end, int write, struct page **pages, int *nr)
{
	struct page *head, *page;
	int refs;

	if (!pud_access_permitted(orig, write))
		return 0;

	if (pud_devmap(orig))
		return __gup_device_huge_pud(orig, addr, end, pages, nr);

	refs = 0;
	page = pud_page(orig) + ((addr & ~PUD_MASK) >> PAGE_SHIFT);
	do {
		pages[*nr] = page;
		(*nr)++;
		page++;
		refs++;
	} while (addr += PAGE_SIZE, addr != end);

	head = compound_head(pud_page(orig));
	if (!page_cache_add_speculative(head, refs)) {
		*nr -= refs;
		return 0;
	}

	if (unlikely(pud_val(orig) != pud_val(*pudp))) {
		*nr -= refs;
		while (refs--)
			put_page(head);
		return 0;
	}

	SetPageReferenced(head);
	return 1;
}

static int gup_huge_pgd(pgd_t orig, pgd_t *pgdp, unsigned long addr, unsigned long end, int write, struct page **pages, int *nr)

{
	int refs;
	struct page *head, *page;

	if (!pgd_access_permitted(orig, write))
		return 0;

	BUILD_BUG_ON(pgd_devmap(orig));
	refs = 0;
	page = pgd_page(orig) + ((addr & ~PGDIR_MASK) >> PAGE_SHIFT);
	do {
		pages[*nr] = page;
		(*nr)++;
		page++;
		refs++;
	} while (addr += PAGE_SIZE, addr != end);

	head = compound_head(pgd_page(orig));
	if (!page_cache_add_speculative(head, refs)) {
		*nr -= refs;
		return 0;
	}

	if (unlikely(pgd_val(orig) != pgd_val(*pgdp))) {
		*nr -= refs;
		while (refs--)
			put_page(head);
		return 0;
	}

	SetPageReferenced(head);
	return 1;
}

static int gup_pmd_range(pud_t pud, unsigned long addr, unsigned long end, int write, struct page **pages, int *nr)
{
	unsigned long next;
	pmd_t *pmdp;

	pmdp = pmd_offset(&pud, addr);
	do {
		pmd_t pmd = READ_ONCE(*pmdp);

		next = pmd_addr_end(addr, end);
		if (!pmd_present(pmd))
			return 0;

		if (unlikely(pmd_trans_huge(pmd) || pmd_huge(pmd))) {
			
			if (pmd_protnone(pmd))
				return 0;

			if (!gup_huge_pmd(pmd, pmdp, addr, next, write, pages, nr))
				return 0;

		} else if (unlikely(is_hugepd(__hugepd(pmd_val(pmd))))) {
			
			if (!gup_huge_pd(__hugepd(pmd_val(pmd)), addr, PMD_SHIFT, next, write, pages, nr))
				return 0;
		} else if (!gup_pte_range(pmd, addr, next, write, pages, nr))
			return 0;
	} while (pmdp++, addr = next, addr != end);

	return 1;
}

static int gup_pud_range(p4d_t p4d, unsigned long addr, unsigned long end, int write, struct page **pages, int *nr)
{
	unsigned long next;
	pud_t *pudp;

	pudp = pud_offset(&p4d, addr);
	do {
		pud_t pud = READ_ONCE(*pudp);

		next = pud_addr_end(addr, end);
		if (pud_none(pud))
			return 0;
		if (unlikely(pud_huge(pud))) {
			if (!gup_huge_pud(pud, pudp, addr, next, write, pages, nr))
				return 0;
		} else if (unlikely(is_hugepd(__hugepd(pud_val(pud))))) {
			if (!gup_huge_pd(__hugepd(pud_val(pud)), addr, PUD_SHIFT, next, write, pages, nr))
				return 0;
		} else if (!gup_pmd_range(pud, addr, next, write, pages, nr))
			return 0;
	} while (pudp++, addr = next, addr != end);

	return 1;
}

static int gup_p4d_range(pgd_t pgd, unsigned long addr, unsigned long end, int write, struct page **pages, int *nr)
{
	unsigned long next;
	p4d_t *p4dp;

	p4dp = p4d_offset(&pgd, addr);
	do {
		p4d_t p4d = READ_ONCE(*p4dp);

		next = p4d_addr_end(addr, end);
		if (p4d_none(p4d))
			return 0;
		BUILD_BUG_ON(p4d_huge(p4d));
		if (unlikely(is_hugepd(__hugepd(p4d_val(p4d))))) {
			if (!gup_huge_pd(__hugepd(p4d_val(p4d)), addr, P4D_SHIFT, next, write, pages, nr))
				return 0;
		} else if (!gup_pud_range(p4d, addr, next, write, pages, nr))
			return 0;
	} while (p4dp++, addr = next, addr != end);

	return 1;
}

static void gup_pgd_range(unsigned long addr, unsigned long end, int write, struct page **pages, int *nr)
{
	unsigned long next;
	pgd_t *pgdp;

	pgdp = pgd_offset(current->mm, addr);
	do {
		pgd_t pgd = READ_ONCE(*pgdp);

		next = pgd_addr_end(addr, end);
		if (pgd_none(pgd))
			return;
		if (unlikely(pgd_huge(pgd))) {
			if (!gup_huge_pgd(pgd, pgdp, addr, next, write, pages, nr))
				return;
		} else if (unlikely(is_hugepd(__hugepd(pgd_val(pgd))))) {
			if (!gup_huge_pd(__hugepd(pgd_val(pgd)), addr, PGDIR_SHIFT, next, write, pages, nr))
				return;
		} else if (!gup_p4d_range(pgd, addr, next, write, pages, nr))
			return;
	} while (pgdp++, addr = next, addr != end);
}



bool gup_fast_permitted(unsigned long start, int nr_pages, int write)
{
	unsigned long len, end;

	len = (unsigned long) nr_pages << PAGE_SHIFT;
	end = start + len;
	return end >= start;
}



int __get_user_pages_fast(unsigned long start, int nr_pages, int write, struct page **pages)
{
	unsigned long addr, len, end;
	unsigned long flags;
	int nr = 0;

	start &= PAGE_MASK;
	addr = start;
	len = (unsigned long) nr_pages << PAGE_SHIFT;
	end = start + len;

	if (unlikely(!access_ok(write ? VERIFY_WRITE : VERIFY_READ, (void __user *)start, len)))
		return 0;

	

	if (gup_fast_permitted(start, nr_pages, write)) {
		local_irq_save(flags);
		gup_pgd_range(addr, end, write, pages, &nr);
		local_irq_restore(flags);
	}

	return nr;
}


int get_user_pages_fast(unsigned long start, int nr_pages, int write, struct page **pages)
{
	unsigned long addr, len, end;
	int nr = 0, ret = 0;

	start &= PAGE_MASK;
	addr = start;
	len = (unsigned long) nr_pages << PAGE_SHIFT;
	end = start + len;

	if (nr_pages <= 0)
		return 0;

	if (unlikely(!access_ok(write ? VERIFY_WRITE : VERIFY_READ, (void __user *)start, len)))
		return -EFAULT;

	if (gup_fast_permitted(start, nr_pages, write)) {
		local_irq_disable();
		gup_pgd_range(addr, end, write, pages, &nr);
		local_irq_enable();
		ret = nr;
	}

	if (nr < nr_pages) {
		
		start += nr << PAGE_SHIFT;
		pages += nr;

		ret = get_user_pages_unlocked(start, nr_pages - nr, pages, write ? FOLL_WRITE : 0);

		
		if (nr > 0) {
			if (ret < 0)
				ret = nr;
			else ret += nr;
		}
	}

	return ret;
}


