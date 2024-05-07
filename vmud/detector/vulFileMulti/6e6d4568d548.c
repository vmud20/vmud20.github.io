






























typedef char *elf_caddr_t;













MODULE_LICENSE("GPL");

static int load_elf_fdpic_binary(struct linux_binprm *, struct pt_regs *);
static int elf_fdpic_fetch_phdrs(struct elf_fdpic_params *, struct file *);
static int elf_fdpic_map_file(struct elf_fdpic_params *, struct file *, struct mm_struct *, const char *);

static int create_elf_fdpic_tables(struct linux_binprm *, struct mm_struct *, struct elf_fdpic_params *, struct elf_fdpic_params *);



static int elf_fdpic_transfer_args_to_stack(struct linux_binprm *, unsigned long *);
static int elf_fdpic_map_file_constdisp_on_uclinux(struct elf_fdpic_params *, struct file *, struct mm_struct *);



static int elf_fdpic_map_file_by_direct_mmap(struct elf_fdpic_params *, struct file *, struct mm_struct *);


static int elf_fdpic_core_dump(long, struct pt_regs *, struct file *);


static struct linux_binfmt elf_fdpic_format = {
	.module		= THIS_MODULE, .load_binary	= load_elf_fdpic_binary,  .core_dump	= elf_fdpic_core_dump,  .min_coredump	= ELF_EXEC_PAGESIZE, };






static int __init init_elf_fdpic_binfmt(void)
{
	return register_binfmt(&elf_fdpic_format);
}

static void __exit exit_elf_fdpic_binfmt(void)
{
	unregister_binfmt(&elf_fdpic_format);
}

core_initcall(init_elf_fdpic_binfmt);
module_exit(exit_elf_fdpic_binfmt);

static int is_elf_fdpic(struct elfhdr *hdr, struct file *file)
{
	if (memcmp(hdr->e_ident, ELFMAG, SELFMAG) != 0)
		return 0;
	if (hdr->e_type != ET_EXEC && hdr->e_type != ET_DYN)
		return 0;
	if (!elf_check_arch(hdr) || !elf_check_fdpic(hdr))
		return 0;
	if (!file->f_op || !file->f_op->mmap)
		return 0;
	return 1;
}



static int elf_fdpic_fetch_phdrs(struct elf_fdpic_params *params, struct file *file)
{
	struct elf32_phdr *phdr;
	unsigned long size;
	int retval, loop;

	if (params->hdr.e_phentsize != sizeof(struct elf_phdr))
		return -ENOMEM;
	if (params->hdr.e_phnum > 65536U / sizeof(struct elf_phdr))
		return -ENOMEM;

	size = params->hdr.e_phnum * sizeof(struct elf_phdr);
	params->phdrs = kmalloc(size, GFP_KERNEL);
	if (!params->phdrs)
		return -ENOMEM;

	retval = kernel_read(file, params->hdr.e_phoff, (char *) params->phdrs, size);
	if (retval < 0)
		return retval;

	
	phdr = params->phdrs;
	for (loop = 0; loop < params->hdr.e_phnum; loop++, phdr++) {
		if (phdr->p_type != PT_GNU_STACK)
			continue;

		if (phdr->p_flags & PF_X)
			params->flags |= ELF_FDPIC_FLAG_EXEC_STACK;
		else params->flags |= ELF_FDPIC_FLAG_NOEXEC_STACK;

		params->stack_size = phdr->p_memsz;
		break;
	}

	return 0;
}



static int load_elf_fdpic_binary(struct linux_binprm *bprm, struct pt_regs *regs)
{
	struct elf_fdpic_params exec_params, interp_params;
	struct elf_phdr *phdr;
	unsigned long stack_size, entryaddr;

	unsigned long fullsize;


	unsigned long dynaddr;

	struct file *interpreter = NULL; 
	char *interpreter_name = NULL;
	int executable_stack;
	int retval, i;

	memset(&exec_params, 0, sizeof(exec_params));
	memset(&interp_params, 0, sizeof(interp_params));

	exec_params.hdr = *(struct elfhdr *) bprm->buf;
	exec_params.flags = ELF_FDPIC_FLAG_PRESENT | ELF_FDPIC_FLAG_EXECUTABLE;

	
	retval = -ENOEXEC;
	if (!is_elf_fdpic(&exec_params.hdr, bprm->file))
		goto error;

	
	retval = elf_fdpic_fetch_phdrs(&exec_params, bprm->file);
	if (retval < 0)
		goto error;

	
	phdr = exec_params.phdrs;

	for (i = 0; i < exec_params.hdr.e_phnum; i++, phdr++) {
		switch (phdr->p_type) {
		case PT_INTERP:
			retval = -ENOMEM;
			if (phdr->p_filesz > PATH_MAX)
				goto error;
			retval = -ENOENT;
			if (phdr->p_filesz < 2)
				goto error;

			
			interpreter_name = kmalloc(phdr->p_filesz, GFP_KERNEL);
			if (!interpreter_name)
				goto error;

			retval = kernel_read(bprm->file, phdr->p_offset, interpreter_name, phdr->p_filesz);


			if (retval < 0)
				goto error;

			retval = -ENOENT;
			if (interpreter_name[phdr->p_filesz - 1] != '\0')
				goto error;

			kdebug("Using ELF interpreter %s", interpreter_name);

			
			interpreter = open_exec(interpreter_name);
			retval = PTR_ERR(interpreter);
			if (IS_ERR(interpreter)) {
				interpreter = NULL;
				goto error;
			}

			retval = kernel_read(interpreter, 0, bprm->buf, BINPRM_BUF_SIZE);
			if (retval < 0)
				goto error;

			interp_params.hdr = *((struct elfhdr *) bprm->buf);
			break;

		case PT_LOAD:

			if (exec_params.load_addr == 0)
				exec_params.load_addr = phdr->p_vaddr;

			break;
		}

	}

	if (elf_check_const_displacement(&exec_params.hdr))
		exec_params.flags |= ELF_FDPIC_FLAG_CONSTDISP;

	
	if (interpreter_name) {
		retval = -ELIBBAD;
		if (!is_elf_fdpic(&interp_params.hdr, interpreter))
			goto error;

		interp_params.flags = ELF_FDPIC_FLAG_PRESENT;

		
		retval = elf_fdpic_fetch_phdrs(&interp_params, interpreter);
		if (retval < 0)
			goto error;
	}

	stack_size = exec_params.stack_size;
	if (stack_size < interp_params.stack_size)
		stack_size = interp_params.stack_size;

	if (exec_params.flags & ELF_FDPIC_FLAG_EXEC_STACK)
		executable_stack = EXSTACK_ENABLE_X;
	else if (exec_params.flags & ELF_FDPIC_FLAG_NOEXEC_STACK)
		executable_stack = EXSTACK_DISABLE_X;
	else if (interp_params.flags & ELF_FDPIC_FLAG_EXEC_STACK)
		executable_stack = EXSTACK_ENABLE_X;
	else if (interp_params.flags & ELF_FDPIC_FLAG_NOEXEC_STACK)
		executable_stack = EXSTACK_DISABLE_X;
	else executable_stack = EXSTACK_DEFAULT;

	retval = -ENOEXEC;
	if (stack_size == 0)
		goto error;

	if (elf_check_const_displacement(&interp_params.hdr))
		interp_params.flags |= ELF_FDPIC_FLAG_CONSTDISP;

	
	retval = flush_old_exec(bprm);
	if (retval)
		goto error;

	
	set_personality(PER_LINUX_FDPIC);
	set_binfmt(&elf_fdpic_format);

	current->mm->start_code = 0;
	current->mm->end_code = 0;
	current->mm->start_stack = 0;
	current->mm->start_data = 0;
	current->mm->end_data = 0;
	current->mm->context.exec_fdpic_loadmap = 0;
	current->mm->context.interp_fdpic_loadmap = 0;

	current->flags &= ~PF_FORKNOEXEC;


	elf_fdpic_arch_lay_out_mm(&exec_params, &interp_params, &current->mm->start_stack, &current->mm->start_brk);



	retval = setup_arg_pages(bprm, current->mm->start_stack, executable_stack);
	if (retval < 0) {
		send_sig(SIGKILL, current, 0);
		goto error_kill;
	}


	
	retval = elf_fdpic_map_file(&exec_params, bprm->file, current->mm, "executable");
	if (retval < 0)
		goto error_kill;

	if (interpreter_name) {
		retval = elf_fdpic_map_file(&interp_params, interpreter, current->mm, "interpreter");
		if (retval < 0) {
			printk(KERN_ERR "Unable to load interpreter\n");
			goto error_kill;
		}

		allow_write_access(interpreter);
		fput(interpreter);
		interpreter = NULL;
	}


	if (!current->mm->start_brk)
		current->mm->start_brk = current->mm->end_data;

	current->mm->brk = current->mm->start_brk = PAGE_ALIGN(current->mm->start_brk);


	
	stack_size = (stack_size + PAGE_SIZE - 1) & PAGE_MASK;
	if (stack_size < PAGE_SIZE * 2)
		stack_size = PAGE_SIZE * 2;

	down_write(&current->mm->mmap_sem);
	current->mm->start_brk = do_mmap(NULL, 0, stack_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON | MAP_GROWSDOWN, 0);



	if (IS_ERR_VALUE(current->mm->start_brk)) {
		up_write(&current->mm->mmap_sem);
		retval = current->mm->start_brk;
		current->mm->start_brk = 0;
		goto error_kill;
	}

	
	fullsize = ksize((char *) current->mm->start_brk);
	if (!IS_ERR_VALUE(do_mremap(current->mm->start_brk, stack_size, fullsize, 0, 0)))
		stack_size = fullsize;
	up_write(&current->mm->mmap_sem);

	current->mm->brk = current->mm->start_brk;
	current->mm->context.end_brk = current->mm->start_brk;
	current->mm->context.end_brk += (stack_size > PAGE_SIZE) ? (stack_size - PAGE_SIZE) : 0;
	current->mm->start_stack = current->mm->start_brk + stack_size;


	compute_creds(bprm);
	current->flags &= ~PF_FORKNOEXEC;
	if (create_elf_fdpic_tables(bprm, current->mm, &exec_params, &interp_params) < 0)
		goto error_kill;

	kdebug("- start_code  %lx", current->mm->start_code);
	kdebug("- end_code    %lx", current->mm->end_code);
	kdebug("- start_data  %lx", current->mm->start_data);
	kdebug("- end_data    %lx", current->mm->end_data);
	kdebug("- start_brk   %lx", current->mm->start_brk);
	kdebug("- brk         %lx", current->mm->brk);
	kdebug("- start_stack %lx", current->mm->start_stack);


	
	dynaddr = interp_params.dynamic_addr ?: exec_params.dynamic_addr;
	ELF_FDPIC_PLAT_INIT(regs, exec_params.map_addr, interp_params.map_addr, dynaddr);


	
	entryaddr = interp_params.entry_addr ?: exec_params.entry_addr;
	start_thread(regs, entryaddr, current->mm->start_stack);

	if (unlikely(current->ptrace & PT_PTRACED)) {
		if (current->ptrace & PT_TRACE_EXEC)
			ptrace_notify((PTRACE_EVENT_EXEC << 8) | SIGTRAP);
		else send_sig(SIGTRAP, current, 0);
	}

	retval = 0;

error:
	if (interpreter) {
		allow_write_access(interpreter);
		fput(interpreter);
	}
	kfree(interpreter_name);
	kfree(exec_params.phdrs);
	kfree(exec_params.loadmap);
	kfree(interp_params.phdrs);
	kfree(interp_params.loadmap);
	return retval;

	
error_kill:
	send_sig(SIGSEGV, current, 0);
	goto error;

}



static int create_elf_fdpic_tables(struct linux_binprm *bprm, struct mm_struct *mm, struct elf_fdpic_params *exec_params, struct elf_fdpic_params *interp_params)


{
	unsigned long sp, csp, nitems;
	elf_caddr_t __user *argv, *envp;
	size_t platform_len = 0, len;
	char *k_platform;
	char __user *u_platform, *p;
	long hwcap;
	int loop;

	

	sp = bprm->p;

	sp = mm->start_stack;

	
	if (elf_fdpic_transfer_args_to_stack(bprm, &sp) < 0)
		return -EFAULT;


	
	hwcap = ELF_HWCAP;
	k_platform = ELF_PLATFORM;
	u_platform = NULL;

	if (k_platform) {
		platform_len = strlen(k_platform) + 1;
		sp -= platform_len;
		u_platform = (char __user *) sp;
		if (__copy_to_user(u_platform, k_platform, platform_len) != 0)
			return -EFAULT;
	}


	
	if (smp_num_siblings > 1)
		sp = sp - ((current->pid % 64) << 7);


	sp &= ~7UL;

	
	len = sizeof(struct elf32_fdpic_loadmap);
	len += sizeof(struct elf32_fdpic_loadseg) * exec_params->loadmap->nsegs;
	sp = (sp - len) & ~7UL;
	exec_params->map_addr = sp;

	if (copy_to_user((void __user *) sp, exec_params->loadmap, len) != 0)
		return -EFAULT;

	current->mm->context.exec_fdpic_loadmap = (unsigned long) sp;

	if (interp_params->loadmap) {
		len = sizeof(struct elf32_fdpic_loadmap);
		len += sizeof(struct elf32_fdpic_loadseg) * interp_params->loadmap->nsegs;
		sp = (sp - len) & ~7UL;
		interp_params->map_addr = sp;

		if (copy_to_user((void __user *) sp, interp_params->loadmap, len) != 0)
			return -EFAULT;

		current->mm->context.interp_fdpic_loadmap = (unsigned long) sp;
	}

	


	nitems = 1 + DLINFO_ITEMS + (k_platform ? 1 : 0);

	nitems += DLINFO_ARCH_ITEMS;


	csp = sp;
	sp -= nitems * 2 * sizeof(unsigned long);
	sp -= (bprm->envc + 1) * sizeof(char *);	
	sp -= (bprm->argc + 1) * sizeof(char *);	
	sp -= 1 * sizeof(unsigned long);		

	csp -= sp & 15UL;
	sp -= sp & 15UL;

	








	csp -= 2 * sizeof(unsigned long);
	NEW_AUX_ENT(0, AT_NULL, 0);
	if (k_platform) {
		csp -= 2 * sizeof(unsigned long);
		NEW_AUX_ENT(0, AT_PLATFORM, (elf_addr_t) (unsigned long) u_platform);
	}

	csp -= DLINFO_ITEMS * 2 * sizeof(unsigned long);
	NEW_AUX_ENT( 0, AT_HWCAP,	hwcap);
	NEW_AUX_ENT( 1, AT_PAGESZ,	PAGE_SIZE);
	NEW_AUX_ENT( 2, AT_CLKTCK,	CLOCKS_PER_SEC);
	NEW_AUX_ENT( 3, AT_PHDR,	exec_params->ph_addr);
	NEW_AUX_ENT( 4, AT_PHENT,	sizeof(struct elf_phdr));
	NEW_AUX_ENT( 5, AT_PHNUM,	exec_params->hdr.e_phnum);
	NEW_AUX_ENT( 6,	AT_BASE,	interp_params->elfhdr_addr);
	NEW_AUX_ENT( 7, AT_FLAGS,	0);
	NEW_AUX_ENT( 8, AT_ENTRY,	exec_params->entry_addr);
	NEW_AUX_ENT( 9, AT_UID,		(elf_addr_t) current->uid);
	NEW_AUX_ENT(10, AT_EUID,	(elf_addr_t) current->euid);
	NEW_AUX_ENT(11, AT_GID,		(elf_addr_t) current->gid);
	NEW_AUX_ENT(12, AT_EGID,	(elf_addr_t) current->egid);


	
	ARCH_DLINFO;



	
	csp -= (bprm->envc + 1) * sizeof(elf_caddr_t);
	envp = (elf_caddr_t __user *) csp;
	csp -= (bprm->argc + 1) * sizeof(elf_caddr_t);
	argv = (elf_caddr_t __user *) csp;

	
	csp -= sizeof(unsigned long);
	__put_user(bprm->argc, (unsigned long __user *) csp);

	BUG_ON(csp != sp);

	

	current->mm->arg_start = bprm->p;

	current->mm->arg_start = current->mm->start_stack - (MAX_ARG_PAGES * PAGE_SIZE - bprm->p);


	p = (char __user *) current->mm->arg_start;
	for (loop = bprm->argc; loop > 0; loop--) {
		__put_user((elf_caddr_t) p, argv++);
		len = strnlen_user(p, PAGE_SIZE * MAX_ARG_PAGES);
		if (!len || len > PAGE_SIZE * MAX_ARG_PAGES)
			return -EINVAL;
		p += len;
	}
	__put_user(NULL, argv);
	current->mm->arg_end = (unsigned long) p;

	
	current->mm->env_start = (unsigned long) p;
	for (loop = bprm->envc; loop > 0; loop--) {
		__put_user((elf_caddr_t)(unsigned long) p, envp++);
		len = strnlen_user(p, PAGE_SIZE * MAX_ARG_PAGES);
		if (!len || len > PAGE_SIZE * MAX_ARG_PAGES)
			return -EINVAL;
		p += len;
	}
	__put_user(NULL, envp);
	current->mm->env_end = (unsigned long) p;

	mm->start_stack = (unsigned long) sp;
	return 0;
}




static int elf_fdpic_transfer_args_to_stack(struct linux_binprm *bprm, unsigned long *_sp)
{
	unsigned long index, stop, sp;
	char *src;
	int ret = 0;

	stop = bprm->p >> PAGE_SHIFT;
	sp = *_sp;

	for (index = MAX_ARG_PAGES - 1; index >= stop; index--) {
		src = kmap(bprm->page[index]);
		sp -= PAGE_SIZE;
		if (copy_to_user((void *) sp, src, PAGE_SIZE) != 0)
			ret = -EFAULT;
		kunmap(bprm->page[index]);
		if (ret < 0)
			goto out;
	}

	*_sp = (*_sp - (MAX_ARG_PAGES * PAGE_SIZE - bprm->p)) & ~15;

out:
	return ret;
}




static int elf_fdpic_map_file(struct elf_fdpic_params *params, struct file *file, struct mm_struct *mm, const char *what)


{
	struct elf32_fdpic_loadmap *loadmap;

	struct elf32_fdpic_loadseg *mseg;

	struct elf32_fdpic_loadseg *seg;
	struct elf32_phdr *phdr;
	unsigned long load_addr, stop;
	unsigned nloads, tmp;
	size_t size;
	int loop, ret;

	
	nloads = 0;
	for (loop = 0; loop < params->hdr.e_phnum; loop++)
		if (params->phdrs[loop].p_type == PT_LOAD)
			nloads++;

	if (nloads == 0)
		return -ELIBBAD;

	size = sizeof(*loadmap) + nloads * sizeof(*seg);
	loadmap = kzalloc(size, GFP_KERNEL);
	if (!loadmap)
		return -ENOMEM;

	params->loadmap = loadmap;

	loadmap->version = ELF32_FDPIC_LOADMAP_VERSION;
	loadmap->nsegs = nloads;

	load_addr = params->load_addr;
	seg = loadmap->segs;

	
	switch (params->flags & ELF_FDPIC_FLAG_ARRANGEMENT) {
	case ELF_FDPIC_FLAG_CONSTDISP:
	case ELF_FDPIC_FLAG_CONTIGUOUS:

		ret = elf_fdpic_map_file_constdisp_on_uclinux(params, file, mm);
		if (ret < 0)
			return ret;
		break;

	default:
		ret = elf_fdpic_map_file_by_direct_mmap(params, file, mm);
		if (ret < 0)
			return ret;
		break;
	}

	
	if (params->hdr.e_entry) {
		seg = loadmap->segs;
		for (loop = loadmap->nsegs; loop > 0; loop--, seg++) {
			if (params->hdr.e_entry >= seg->p_vaddr && params->hdr.e_entry < seg->p_vaddr + seg->p_memsz) {
				params->entry_addr = (params->hdr.e_entry - seg->p_vaddr) + seg->addr;

				break;
			}
		}
	}

	
	stop = params->hdr.e_phoff;
	stop += params->hdr.e_phnum * sizeof (struct elf_phdr);
	phdr = params->phdrs;

	for (loop = 0; loop < params->hdr.e_phnum; loop++, phdr++) {
		if (phdr->p_type != PT_LOAD)
			continue;

		if (phdr->p_offset > params->hdr.e_phoff || phdr->p_offset + phdr->p_filesz < stop)
			continue;

		seg = loadmap->segs;
		for (loop = loadmap->nsegs; loop > 0; loop--, seg++) {
			if (phdr->p_vaddr >= seg->p_vaddr && phdr->p_vaddr + phdr->p_filesz <= seg->p_vaddr + seg->p_memsz) {

				params->ph_addr = (phdr->p_vaddr - seg->p_vaddr) + seg->addr + params->hdr.e_phoff - phdr->p_offset;


				break;
			}
		}
		break;
	}

	
	phdr = params->phdrs;
	for (loop = 0; loop < params->hdr.e_phnum; loop++, phdr++) {
		if (phdr->p_type != PT_DYNAMIC)
			continue;

		seg = loadmap->segs;
		for (loop = loadmap->nsegs; loop > 0; loop--, seg++) {
			if (phdr->p_vaddr >= seg->p_vaddr && phdr->p_vaddr + phdr->p_memsz <= seg->p_vaddr + seg->p_memsz) {

				params->dynamic_addr = (phdr->p_vaddr - seg->p_vaddr) + seg->addr;


				
				if (phdr->p_memsz == 0 || phdr->p_memsz % sizeof(Elf32_Dyn) != 0)
					goto dynamic_error;

				tmp = phdr->p_memsz / sizeof(Elf32_Dyn);
				if (((Elf32_Dyn *)
				     params->dynamic_addr)[tmp - 1].d_tag != 0)
					goto dynamic_error;
				break;
			}
		}
		break;
	}

	

	nloads = loadmap->nsegs;
	mseg = loadmap->segs;
	seg = mseg + 1;
	for (loop = 1; loop < nloads; loop++) {
		
		if (seg->p_vaddr - mseg->p_vaddr == seg->addr - mseg->addr) {
			load_addr = PAGE_ALIGN(mseg->addr + mseg->p_memsz);
			if (load_addr == (seg->addr & PAGE_MASK)) {
				mseg->p_memsz += load_addr - (mseg->addr + mseg->p_memsz);

				mseg->p_memsz += seg->addr & ~PAGE_MASK;
				mseg->p_memsz += seg->p_memsz;
				loadmap->nsegs--;
				continue;
			}
		}

		mseg++;
		if (mseg != seg)
			*mseg = *seg;
	}


	kdebug("Mapped Object [%s]:", what);
	kdebug("- elfhdr   : %lx", params->elfhdr_addr);
	kdebug("- entry    : %lx", params->entry_addr);
	kdebug("- PHDR[]   : %lx", params->ph_addr);
	kdebug("- DYNAMIC[]: %lx", params->dynamic_addr);
	seg = loadmap->segs;
	for (loop = 0; loop < loadmap->nsegs; loop++, seg++)
		kdebug("- LOAD[%d] : %08x-%08x [va=%x ms=%x]", loop, seg->addr, seg->addr + seg->p_memsz - 1, seg->p_vaddr, seg->p_memsz);



	return 0;

dynamic_error:
	printk("ELF FDPIC %s with invalid DYNAMIC section (inode=%lu)\n", what, file->f_path.dentry->d_inode->i_ino);
	return -ELIBBAD;
}




static int elf_fdpic_map_file_constdisp_on_uclinux( struct elf_fdpic_params *params, struct file *file, struct mm_struct *mm)


{
	struct elf32_fdpic_loadseg *seg;
	struct elf32_phdr *phdr;
	unsigned long load_addr, base = ULONG_MAX, top = 0, maddr = 0, mflags;
	loff_t fpos;
	int loop, ret;

	load_addr = params->load_addr;
	seg = params->loadmap->segs;

	
	phdr = params->phdrs;
	for (loop = 0; loop < params->hdr.e_phnum; loop++, phdr++) {
		if (params->phdrs[loop].p_type != PT_LOAD)
			continue;

		if (base > phdr->p_vaddr)
			base = phdr->p_vaddr;
		if (top < phdr->p_vaddr + phdr->p_memsz)
			top = phdr->p_vaddr + phdr->p_memsz;
	}

	
	mflags = MAP_PRIVATE;
	if (params->flags & ELF_FDPIC_FLAG_EXECUTABLE)
		mflags |= MAP_EXECUTABLE;

	down_write(&mm->mmap_sem);
	maddr = do_mmap(NULL, load_addr, top - base, PROT_READ | PROT_WRITE | PROT_EXEC, mflags, 0);
	up_write(&mm->mmap_sem);
	if (IS_ERR_VALUE(maddr))
		return (int) maddr;

	if (load_addr != 0)
		load_addr += PAGE_ALIGN(top - base);

	
	phdr = params->phdrs;
	for (loop = 0; loop < params->hdr.e_phnum; loop++, phdr++) {
		if (params->phdrs[loop].p_type != PT_LOAD)
			continue;

		fpos = phdr->p_offset;

		seg->addr = maddr + (phdr->p_vaddr - base);
		seg->p_vaddr = phdr->p_vaddr;
		seg->p_memsz = phdr->p_memsz;

		ret = file->f_op->read(file, (void *) seg->addr, phdr->p_filesz, &fpos);
		if (ret < 0)
			return ret;

		
		if (phdr->p_offset == 0)
			params->elfhdr_addr = seg->addr;

		
		if (phdr->p_filesz < phdr->p_memsz)
			clear_user((void *) (seg->addr + phdr->p_filesz), phdr->p_memsz - phdr->p_filesz);

		if (mm) {
			if (phdr->p_flags & PF_X) {
				mm->start_code = seg->addr;
				mm->end_code = seg->addr + phdr->p_memsz;
			} else if (!mm->start_data) {
				mm->start_data = seg->addr;

				mm->end_data = seg->addr + phdr->p_memsz;

			}


			if (seg->addr + phdr->p_memsz > mm->end_data)
				mm->end_data = seg->addr + phdr->p_memsz;

		}

		seg++;
	}

	return 0;
}




static int elf_fdpic_map_file_by_direct_mmap(struct elf_fdpic_params *params, struct file *file, struct mm_struct *mm)

{
	struct elf32_fdpic_loadseg *seg;
	struct elf32_phdr *phdr;
	unsigned long load_addr, delta_vaddr;
	int loop, dvset;

	load_addr = params->load_addr;
	delta_vaddr = 0;
	dvset = 0;

	seg = params->loadmap->segs;

	
	phdr = params->phdrs;
	for (loop = 0; loop < params->hdr.e_phnum; loop++, phdr++) {
		unsigned long maddr, disp, excess, excess1;
		int prot = 0, flags;

		if (phdr->p_type != PT_LOAD)
			continue;

		kdebug("[LOAD] va=%lx of=%lx fs=%lx ms=%lx", (unsigned long) phdr->p_vaddr, (unsigned long) phdr->p_offset, (unsigned long) phdr->p_filesz, (unsigned long) phdr->p_memsz);




		
		if (phdr->p_flags & PF_R) prot |= PROT_READ;
		if (phdr->p_flags & PF_W) prot |= PROT_WRITE;
		if (phdr->p_flags & PF_X) prot |= PROT_EXEC;

		flags = MAP_PRIVATE | MAP_DENYWRITE;
		if (params->flags & ELF_FDPIC_FLAG_EXECUTABLE)
			flags |= MAP_EXECUTABLE;

		maddr = 0;

		switch (params->flags & ELF_FDPIC_FLAG_ARRANGEMENT) {
		case ELF_FDPIC_FLAG_INDEPENDENT:
			
			break;

		case ELF_FDPIC_FLAG_HONOURVADDR:
			
			maddr = phdr->p_vaddr;
			flags |= MAP_FIXED;
			break;

		case ELF_FDPIC_FLAG_CONSTDISP:
			
			if (!dvset) {
				maddr = load_addr;
				delta_vaddr = phdr->p_vaddr;
				dvset = 1;
			} else {
				maddr = load_addr + phdr->p_vaddr - delta_vaddr;
				flags |= MAP_FIXED;
			}
			break;

		case ELF_FDPIC_FLAG_CONTIGUOUS:
			
			break;

		default:
			BUG();
		}

		maddr &= PAGE_MASK;

		
		disp = phdr->p_vaddr & ~PAGE_MASK;
		down_write(&mm->mmap_sem);
		maddr = do_mmap(file, maddr, phdr->p_memsz + disp, prot, flags, phdr->p_offset - disp);
		up_write(&mm->mmap_sem);

		kdebug("mmap[%d] <file> sz=%lx pr=%x fl=%x of=%lx --> %08lx", loop, phdr->p_memsz + disp, prot, flags, phdr->p_offset - disp, maddr);


		if (IS_ERR_VALUE(maddr))
			return (int) maddr;

		if ((params->flags & ELF_FDPIC_FLAG_ARRANGEMENT) == ELF_FDPIC_FLAG_CONTIGUOUS)
			load_addr += PAGE_ALIGN(phdr->p_memsz + disp);

		seg->addr = maddr + disp;
		seg->p_vaddr = phdr->p_vaddr;
		seg->p_memsz = phdr->p_memsz;

		
		if (phdr->p_offset == 0)
			params->elfhdr_addr = seg->addr;

		
		if (prot & PROT_WRITE && disp > 0) {
			kdebug("clear[%d] ad=%lx sz=%lx", loop, maddr, disp);
			clear_user((void __user *) maddr, disp);
			maddr += disp;
		}

		
		excess = phdr->p_memsz - phdr->p_filesz;
		excess1 = PAGE_SIZE - ((maddr + phdr->p_filesz) & ~PAGE_MASK);


		if (excess > excess1) {
			unsigned long xaddr = maddr + phdr->p_filesz + excess1;
			unsigned long xmaddr;

			flags |= MAP_FIXED | MAP_ANONYMOUS;
			down_write(&mm->mmap_sem);
			xmaddr = do_mmap(NULL, xaddr, excess - excess1, prot, flags, 0);
			up_write(&mm->mmap_sem);

			kdebug("mmap[%d] <anon>" " ad=%lx sz=%lx pr=%x fl=%x of=0 --> %08lx", loop, xaddr, excess - excess1, prot, flags, xmaddr);



			if (xmaddr != xaddr)
				return -ENOMEM;
		}

		if (prot & PROT_WRITE && excess1 > 0) {
			kdebug("clear[%d] ad=%lx sz=%lx", loop, maddr + phdr->p_filesz, excess1);
			clear_user((void __user *) maddr + phdr->p_filesz, excess1);
		}


		if (excess > 0) {
			kdebug("clear[%d] ad=%lx sz=%lx", loop, maddr + phdr->p_filesz, excess);
			clear_user((void *) maddr + phdr->p_filesz, excess);
		}


		if (mm) {
			if (phdr->p_flags & PF_X) {
				mm->start_code = maddr;
				mm->end_code = maddr + phdr->p_memsz;
			} else if (!mm->start_data) {
				mm->start_data = maddr;
				mm->end_data = maddr + phdr->p_memsz;
			}
		}

		seg++;
	}

	return 0;
}






static int dump_write(struct file *file, const void *addr, int nr)
{
	return file->f_op->write(file, addr, nr, &file->f_pos) == nr;
}

static int dump_seek(struct file *file, loff_t off)
{
	if (file->f_op->llseek) {
		if (file->f_op->llseek(file, off, SEEK_SET) != off)
			return 0;
	} else {
		file->f_pos = off;
	}
	return 1;
}


static int maydump(struct vm_area_struct *vma)
{
	
	if (vma->vm_flags & (VM_IO | VM_RESERVED)) {
		kdcore("%08lx: %08lx: no (IO)", vma->vm_start, vma->vm_flags);
		return 0;
	}

	
	if (!(vma->vm_flags & VM_READ)) {
		kdcore("%08lx: %08lx: no (!read)", vma->vm_start, vma->vm_flags);
		return 0;
	}

	
	if (vma->vm_flags & VM_SHARED) {
		if (vma->vm_file->f_path.dentry->d_inode->i_nlink == 0) {
			kdcore("%08lx: %08lx: no (share)", vma->vm_start, vma->vm_flags);
			return 1;
		}

		kdcore("%08lx: %08lx: no (share)", vma->vm_start, vma->vm_flags);
		return 0;
	}


	
	if (!vma->anon_vma) {
		kdcore("%08lx: %08lx: no (!anon)", vma->vm_start, vma->vm_flags);
		return 0;
	}


	kdcore("%08lx: %08lx: yes", vma->vm_start, vma->vm_flags);
	return 1;
}


struct memelfnote {
	const char *name;
	int type;
	unsigned int datasz;
	void *data;
};

static int notesize(struct memelfnote *en)
{
	int sz;

	sz = sizeof(struct elf_note);
	sz += roundup(strlen(en->name) + 1, 4);
	sz += roundup(en->datasz, 4);

	return sz;
}






static int writenote(struct memelfnote *men, struct file *file)
{
	struct elf_note en;

	en.n_namesz = strlen(men->name) + 1;
	en.n_descsz = men->datasz;
	en.n_type = men->type;

	DUMP_WRITE(&en, sizeof(en));
	DUMP_WRITE(men->name, en.n_namesz);
	
	DUMP_SEEK(roundup((unsigned long)file->f_pos, 4));	
	DUMP_WRITE(men->data, men->datasz);
	DUMP_SEEK(roundup((unsigned long)file->f_pos, 4));	

	return 1;
}








static inline void fill_elf_fdpic_header(struct elfhdr *elf, int segs)
{
	memcpy(elf->e_ident, ELFMAG, SELFMAG);
	elf->e_ident[EI_CLASS] = ELF_CLASS;
	elf->e_ident[EI_DATA] = ELF_DATA;
	elf->e_ident[EI_VERSION] = EV_CURRENT;
	elf->e_ident[EI_OSABI] = ELF_OSABI;
	memset(elf->e_ident+EI_PAD, 0, EI_NIDENT-EI_PAD);

	elf->e_type = ET_CORE;
	elf->e_machine = ELF_ARCH;
	elf->e_version = EV_CURRENT;
	elf->e_entry = 0;
	elf->e_phoff = sizeof(struct elfhdr);
	elf->e_shoff = 0;
	elf->e_flags = ELF_FDPIC_CORE_EFLAGS;
	elf->e_ehsize = sizeof(struct elfhdr);
	elf->e_phentsize = sizeof(struct elf_phdr);
	elf->e_phnum = segs;
	elf->e_shentsize = 0;
	elf->e_shnum = 0;
	elf->e_shstrndx = 0;
	return;
}

static inline void fill_elf_note_phdr(struct elf_phdr *phdr, int sz, loff_t offset)
{
	phdr->p_type = PT_NOTE;
	phdr->p_offset = offset;
	phdr->p_vaddr = 0;
	phdr->p_paddr = 0;
	phdr->p_filesz = sz;
	phdr->p_memsz = 0;
	phdr->p_flags = 0;
	phdr->p_align = 0;
	return;
}

static inline void fill_note(struct memelfnote *note, const char *name, int type, unsigned int sz, void *data)
{
	note->name = name;
	note->type = type;
	note->datasz = sz;
	note->data = data;
	return;
}


static void fill_prstatus(struct elf_prstatus *prstatus, struct task_struct *p, long signr)
{
	prstatus->pr_info.si_signo = prstatus->pr_cursig = signr;
	prstatus->pr_sigpend = p->pending.signal.sig[0];
	prstatus->pr_sighold = p->blocked.sig[0];
	prstatus->pr_pid = p->pid;
	prstatus->pr_ppid = p->parent->pid;
	prstatus->pr_pgrp = process_group(p);
	prstatus->pr_sid = process_session(p);
	if (thread_group_leader(p)) {
		
		cputime_to_timeval(cputime_add(p->utime, p->signal->utime), &prstatus->pr_utime);
		cputime_to_timeval(cputime_add(p->stime, p->signal->stime), &prstatus->pr_stime);
	} else {
		cputime_to_timeval(p->utime, &prstatus->pr_utime);
		cputime_to_timeval(p->stime, &prstatus->pr_stime);
	}
	cputime_to_timeval(p->signal->cutime, &prstatus->pr_cutime);
	cputime_to_timeval(p->signal->cstime, &prstatus->pr_cstime);

	prstatus->pr_exec_fdpic_loadmap = p->mm->context.exec_fdpic_loadmap;
	prstatus->pr_interp_fdpic_loadmap = p->mm->context.interp_fdpic_loadmap;
}

static int fill_psinfo(struct elf_prpsinfo *psinfo, struct task_struct *p, struct mm_struct *mm)
{
	unsigned int i, len;

	
	memset(psinfo, 0, sizeof(struct elf_prpsinfo));

	len = mm->arg_end - mm->arg_start;
	if (len >= ELF_PRARGSZ)
		len = ELF_PRARGSZ - 1;
	if (copy_from_user(&psinfo->pr_psargs, (const char __user *) mm->arg_start, len))
		return -EFAULT;
	for (i = 0; i < len; i++)
		if (psinfo->pr_psargs[i] == 0)
			psinfo->pr_psargs[i] = ' ';
	psinfo->pr_psargs[len] = 0;

	psinfo->pr_pid = p->pid;
	psinfo->pr_ppid = p->parent->pid;
	psinfo->pr_pgrp = process_group(p);
	psinfo->pr_sid = process_session(p);

	i = p->state ? ffz(~p->state) + 1 : 0;
	psinfo->pr_state = i;
	psinfo->pr_sname = (i > 5) ? '.' : "RSDTZW"[i];
	psinfo->pr_zomb = psinfo->pr_sname == 'Z';
	psinfo->pr_nice = task_nice(p);
	psinfo->pr_flag = p->flags;
	SET_UID(psinfo->pr_uid, p->uid);
	SET_GID(psinfo->pr_gid, p->gid);
	strncpy(psinfo->pr_fname, p->comm, sizeof(psinfo->pr_fname));

	return 0;
}


struct elf_thread_status {
	struct list_head list;
	struct elf_prstatus prstatus;	
	elf_fpregset_t fpu;		
	struct task_struct *thread;

	elf_fpxregset_t xfpu;		

	struct memelfnote notes[3];
	int num_notes;
};


static int elf_dump_thread_status(long signr, struct elf_thread_status *t)
{
	struct task_struct *p = t->thread;
	int sz = 0;

	t->num_notes = 0;

	fill_prstatus(&t->prstatus, p, signr);
	elf_core_copy_task_regs(p, &t->prstatus.pr_reg);

	fill_note(&t->notes[0], "CORE", NT_PRSTATUS, sizeof(t->prstatus), &t->prstatus);
	t->num_notes++;
	sz += notesize(&t->notes[0]);

	t->prstatus.pr_fpvalid = elf_core_copy_task_fpregs(p, NULL, &t->fpu);
	if (t->prstatus.pr_fpvalid) {
		fill_note(&t->notes[1], "CORE", NT_PRFPREG, sizeof(t->fpu), &t->fpu);
		t->num_notes++;
		sz += notesize(&t->notes[1]);
	}


	if (elf_core_copy_task_xfpregs(p, &t->xfpu)) {
		fill_note(&t->notes[2], "LINUX", NT_PRXFPREG, sizeof(t->xfpu), &t->xfpu);
		t->num_notes++;
		sz += notesize(&t->notes[2]);
	}

	return sz;
}



static int elf_fdpic_dump_segments(struct file *file, struct mm_struct *mm, size_t *size, unsigned long *limit)
{
	struct vm_area_struct *vma;

	for (vma = current->mm->mmap; vma; vma = vma->vm_next) {
		unsigned long addr;

		if (!maydump(vma))
			continue;

		for (addr = vma->vm_start;
		     addr < vma->vm_end;
		     addr += PAGE_SIZE ) {
			struct vm_area_struct *vma;
			struct page *page;

			if (get_user_pages(current, current->mm, addr, 1, 0, 1, &page, &vma) <= 0) {
				DUMP_SEEK(file->f_pos + PAGE_SIZE);
			}
			else if (page == ZERO_PAGE(addr)) {
				DUMP_SEEK(file->f_pos + PAGE_SIZE);
				page_cache_release(page);
			}
			else {
				void *kaddr;

				flush_cache_page(vma, addr, page_to_pfn(page));
				kaddr = kmap(page);
				if ((*size += PAGE_SIZE) > *limit || !dump_write(file, kaddr, PAGE_SIZE)
				    ) {
					kunmap(page);
					page_cache_release(page);
					return -EIO;
				}
				kunmap(page);
				page_cache_release(page);
			}
		}
	}

	return 0;

end_coredump:
	return -EFBIG;
}




static int elf_fdpic_dump_segments(struct file *file, struct mm_struct *mm, size_t *size, unsigned long *limit)
{
	struct vm_list_struct *vml;

	for (vml = current->mm->context.vmlist; vml; vml = vml->next) {
	struct vm_area_struct *vma = vml->vma;

		if (!maydump(vma))
			continue;

		if ((*size += PAGE_SIZE) > *limit)
			return -EFBIG;

		if (!dump_write(file, (void *) vma->vm_start, vma->vm_end - vma->vm_start))
			return -EIO;
	}

	return 0;
}



static int elf_fdpic_core_dump(long signr, struct pt_regs *regs, struct file *file)
{

	int has_dumped = 0;
	mm_segment_t fs;
	int segs;
	size_t size = 0;
	int i;
	struct vm_area_struct *vma;
	struct elfhdr *elf = NULL;
	loff_t offset = 0, dataoff;
	unsigned long limit = current->signal->rlim[RLIMIT_CORE].rlim_cur;
	int numnote;
	struct memelfnote *notes = NULL;
	struct elf_prstatus *prstatus = NULL;	
	struct elf_prpsinfo *psinfo = NULL;	
 	struct task_struct *g, *p;
 	LIST_HEAD(thread_list);
 	struct list_head *t;
	elf_fpregset_t *fpu = NULL;

	elf_fpxregset_t *xfpu = NULL;

	int thread_status_size = 0;

	struct vm_list_struct *vml;

	elf_addr_t *auxv;

	

	
	elf = kmalloc(sizeof(*elf), GFP_KERNEL);
	if (!elf)
		goto cleanup;
	prstatus = kzalloc(sizeof(*prstatus), GFP_KERNEL);
	if (!prstatus)
		goto cleanup;
	psinfo = kmalloc(sizeof(*psinfo), GFP_KERNEL);
	if (!psinfo)
		goto cleanup;
	notes = kmalloc(NUM_NOTES * sizeof(struct memelfnote), GFP_KERNEL);
	if (!notes)
		goto cleanup;
	fpu = kmalloc(sizeof(*fpu), GFP_KERNEL);
	if (!fpu)
		goto cleanup;

	xfpu = kmalloc(sizeof(*xfpu), GFP_KERNEL);
	if (!xfpu)
		goto cleanup;


	if (signr) {
		struct elf_thread_status *tmp;
		rcu_read_lock();
		do_each_thread(g,p)
			if (current->mm == p->mm && current != p) {
				tmp = kzalloc(sizeof(*tmp), GFP_ATOMIC);
				if (!tmp) {
					rcu_read_unlock();
					goto cleanup;
				}
				tmp->thread = p;
				list_add(&tmp->list, &thread_list);
			}
		while_each_thread(g,p);
		rcu_read_unlock();
		list_for_each(t, &thread_list) {
			struct elf_thread_status *tmp;
			int sz;

			tmp = list_entry(t, struct elf_thread_status, list);
			sz = elf_dump_thread_status(signr, tmp);
			thread_status_size += sz;
		}
	}

	
	fill_prstatus(prstatus, current, signr);
	elf_core_copy_regs(&prstatus->pr_reg, regs);


	segs = current->mm->map_count;

	segs = 0;
	for (vml = current->mm->context.vmlist; vml; vml = vml->next)
	    segs++;


	segs += ELF_CORE_EXTRA_PHDRS;


	
	fill_elf_fdpic_header(elf, segs + 1);	

	has_dumped = 1;
	current->flags |= PF_DUMPCORE;

	

	fill_note(notes + 0, "CORE", NT_PRSTATUS, sizeof(*prstatus), prstatus);
	fill_psinfo(psinfo, current->group_leader, current->mm);
	fill_note(notes + 1, "CORE", NT_PRPSINFO, sizeof(*psinfo), psinfo);

	numnote = 2;

	auxv = (elf_addr_t *) current->mm->saved_auxv;

	i = 0;
	do i += 2;
	while (auxv[i - 2] != AT_NULL);
	fill_note(&notes[numnote++], "CORE", NT_AUXV, i * sizeof(elf_addr_t), auxv);

  	
	if ((prstatus->pr_fpvalid = elf_core_copy_task_fpregs(current, regs, fpu)))
		fill_note(notes + numnote++, "CORE", NT_PRFPREG, sizeof(*fpu), fpu);

	if (elf_core_copy_task_xfpregs(current, xfpu))
		fill_note(notes + numnote++, "LINUX", NT_PRXFPREG, sizeof(*xfpu), xfpu);


	fs = get_fs();
	set_fs(KERNEL_DS);

	DUMP_WRITE(elf, sizeof(*elf));
	offset += sizeof(*elf);				
	offset += (segs+1) * sizeof(struct elf_phdr);	

	
	{
		struct elf_phdr phdr;
		int sz = 0;

		for (i = 0; i < numnote; i++)
			sz += notesize(notes + i);

		sz += thread_status_size;

		fill_elf_note_phdr(&phdr, sz, offset);
		offset += sz;
		DUMP_WRITE(&phdr, sizeof(phdr));
	}

	
	dataoff = offset = roundup(offset, ELF_EXEC_PAGESIZE);

	
	for (  vma = current->mm->mmap; vma; vma = vma->vm_next  vml = current->mm->context.vmlist; vml; vml = vml->next  ) {





		struct elf_phdr phdr;
		size_t sz;


		vma = vml->vma;


		sz = vma->vm_end - vma->vm_start;

		phdr.p_type = PT_LOAD;
		phdr.p_offset = offset;
		phdr.p_vaddr = vma->vm_start;
		phdr.p_paddr = 0;
		phdr.p_filesz = maydump(vma) ? sz : 0;
		phdr.p_memsz = sz;
		offset += phdr.p_filesz;
		phdr.p_flags = vma->vm_flags & VM_READ ? PF_R : 0;
		if (vma->vm_flags & VM_WRITE)
			phdr.p_flags |= PF_W;
		if (vma->vm_flags & VM_EXEC)
			phdr.p_flags |= PF_X;
		phdr.p_align = ELF_EXEC_PAGESIZE;

		DUMP_WRITE(&phdr, sizeof(phdr));
	}


	ELF_CORE_WRITE_EXTRA_PHDRS;


 	
	for (i = 0; i < numnote; i++)
		if (!writenote(notes + i, file))
			goto end_coredump;

	
	list_for_each(t, &thread_list) {
		struct elf_thread_status *tmp = list_entry(t, struct elf_thread_status, list);

		for (i = 0; i < tmp->num_notes; i++)
			if (!writenote(&tmp->notes[i], file))
				goto end_coredump;
	}

	DUMP_SEEK(dataoff);

	if (elf_fdpic_dump_segments(file, current->mm, &size, &limit) < 0)
		goto end_coredump;


	ELF_CORE_WRITE_EXTRA_DATA;


	if (file->f_pos != offset) {
		
		printk(KERN_WARNING "elf_core_dump: file->f_pos (%lld) != offset (%lld)\n", file->f_pos, offset);

	}

end_coredump:
	set_fs(fs);

cleanup:
	while (!list_empty(&thread_list)) {
		struct list_head *tmp = thread_list.next;
		list_del(tmp);
		kfree(list_entry(tmp, struct elf_thread_status, list));
	}

	kfree(elf);
	kfree(prstatus);
	kfree(psinfo);
	kfree(notes);
	kfree(fpu);

	kfree(xfpu);

	return has_dumped;

}


