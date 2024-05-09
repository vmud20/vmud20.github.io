



































static int load_elf_binary(struct linux_binprm *bprm, struct pt_regs *regs);
static int load_elf_library(struct file *);
static unsigned long elf_map (struct file *, unsigned long, struct elf_phdr *, int, int);



static int elf_core_dump(long signr, struct pt_regs *regs, struct file *file);


















static struct linux_binfmt elf_format = {
		.module		= THIS_MODULE, .load_binary	= load_elf_binary, .load_shlib	= load_elf_library, .core_dump	= elf_core_dump, .min_coredump	= ELF_EXEC_PAGESIZE };







static int set_brk(unsigned long start, unsigned long end)
{
	start = ELF_PAGEALIGN(start);
	end = ELF_PAGEALIGN(end);
	if (end > start) {
		unsigned long addr;
		down_write(&current->mm->mmap_sem);
		addr = do_brk(start, end - start);
		up_write(&current->mm->mmap_sem);
		if (BAD_ADDR(addr))
			return addr;
	}
	current->mm->start_brk = current->mm->brk = end;
	return 0;
}


static int padzero(unsigned long elf_bss)
{
	unsigned long nbyte;

	nbyte = ELF_PAGEOFFSET(elf_bss);
	if (nbyte) {
		nbyte = ELF_MIN_ALIGN - nbyte;
		if (clear_user((void __user *) elf_bss, nbyte))
			return -EFAULT;
	}
	return 0;
}













static int create_elf_tables(struct linux_binprm *bprm, struct elfhdr *exec, int interp_aout, unsigned long load_addr, unsigned long interp_load_addr)


{
	unsigned long p = bprm->p;
	int argc = bprm->argc;
	int envc = bprm->envc;
	elf_addr_t __user *argv;
	elf_addr_t __user *envp;
	elf_addr_t __user *sp;
	elf_addr_t __user *u_platform;
	const char *k_platform = ELF_PLATFORM;
	int items;
	elf_addr_t *elf_info;
	int ei_index = 0;
	struct task_struct *tsk = current;

	
	u_platform = NULL;
	if (k_platform) {
		size_t len = strlen(k_platform) + 1;

		

		p = arch_align_stack(p);

		u_platform = (elf_addr_t __user *)STACK_ALLOC(p, len);
		if (__copy_to_user(u_platform, k_platform, len))
			return -EFAULT;
	}

	
	elf_info = (elf_addr_t *)current->mm->saved_auxv;






	
	ARCH_DLINFO;

	NEW_AUX_ENT(AT_HWCAP, ELF_HWCAP);
	NEW_AUX_ENT(AT_PAGESZ, ELF_EXEC_PAGESIZE);
	NEW_AUX_ENT(AT_CLKTCK, CLOCKS_PER_SEC);
	NEW_AUX_ENT(AT_PHDR, load_addr + exec->e_phoff);
	NEW_AUX_ENT(AT_PHENT, sizeof(struct elf_phdr));
	NEW_AUX_ENT(AT_PHNUM, exec->e_phnum);
	NEW_AUX_ENT(AT_BASE, interp_load_addr);
	NEW_AUX_ENT(AT_FLAGS, 0);
	NEW_AUX_ENT(AT_ENTRY, exec->e_entry);
	NEW_AUX_ENT(AT_UID, tsk->uid);
	NEW_AUX_ENT(AT_EUID, tsk->euid);
	NEW_AUX_ENT(AT_GID, tsk->gid);
	NEW_AUX_ENT(AT_EGID, tsk->egid);
 	NEW_AUX_ENT(AT_SECURE, security_bprm_secureexec(bprm));
	if (k_platform) {
		NEW_AUX_ENT(AT_PLATFORM, (elf_addr_t)(unsigned long)u_platform);
	}
	if (bprm->interp_flags & BINPRM_FLAGS_EXECFD) {
		NEW_AUX_ENT(AT_EXECFD, bprm->interp_data);
	}

	
	memset(&elf_info[ei_index], 0, sizeof current->mm->saved_auxv - ei_index * sizeof elf_info[0]);

	
	ei_index += 2;

	sp = STACK_ADD(p, ei_index);

	items = (argc + 1) + (envc + 1);
	if (interp_aout) {
		items += 3; 
	} else {
		items += 1; 
	}
	bprm->p = STACK_ROUND(sp, items);

	

	sp = (elf_addr_t __user *)bprm->p - items - ei_index;
	bprm->exec = (unsigned long)sp; 

	sp = (elf_addr_t __user *)bprm->p;


	
	if (__put_user(argc, sp++))
		return -EFAULT;
	if (interp_aout) {
		argv = sp + 2;
		envp = argv + argc + 1;
		if (__put_user((elf_addr_t)(unsigned long)argv, sp++) || __put_user((elf_addr_t)(unsigned long)envp, sp++))
			return -EFAULT;
	} else {
		argv = sp;
		envp = argv + argc + 1;
	}

	
	p = current->mm->arg_end = current->mm->arg_start;
	while (argc-- > 0) {
		size_t len;
		if (__put_user((elf_addr_t)p, argv++))
			return -EFAULT;
		len = strnlen_user((void __user *)p, PAGE_SIZE*MAX_ARG_PAGES);
		if (!len || len > PAGE_SIZE*MAX_ARG_PAGES)
			return 0;
		p += len;
	}
	if (__put_user(0, argv))
		return -EFAULT;
	current->mm->arg_end = current->mm->env_start = p;
	while (envc-- > 0) {
		size_t len;
		if (__put_user((elf_addr_t)p, envp++))
			return -EFAULT;
		len = strnlen_user((void __user *)p, PAGE_SIZE*MAX_ARG_PAGES);
		if (!len || len > PAGE_SIZE*MAX_ARG_PAGES)
			return 0;
		p += len;
	}
	if (__put_user(0, envp))
		return -EFAULT;
	current->mm->env_end = p;

	
	sp = (elf_addr_t __user *)envp + 1;
	if (copy_to_user(sp, elf_info, ei_index * sizeof(elf_addr_t)))
		return -EFAULT;
	return 0;
}



static unsigned long elf_map(struct file *filep, unsigned long addr, struct elf_phdr *eppnt, int prot, int type)
{
	unsigned long map_addr;
	unsigned long pageoffset = ELF_PAGEOFFSET(eppnt->p_vaddr);

	down_write(&current->mm->mmap_sem);
	
	if (eppnt->p_filesz + pageoffset)
		map_addr = do_mmap(filep, ELF_PAGESTART(addr), eppnt->p_filesz + pageoffset, prot, type, eppnt->p_offset - pageoffset);

	else map_addr = ELF_PAGESTART(addr);
	up_write(&current->mm->mmap_sem);
	return(map_addr);
}





static unsigned long load_elf_interp(struct elfhdr *interp_elf_ex, struct file *interpreter, unsigned long *interp_load_addr)
{
	struct elf_phdr *elf_phdata;
	struct elf_phdr *eppnt;
	unsigned long load_addr = 0;
	int load_addr_set = 0;
	unsigned long last_bss = 0, elf_bss = 0;
	unsigned long error = ~0UL;
	int retval, i, size;

	
	if (interp_elf_ex->e_type != ET_EXEC && interp_elf_ex->e_type != ET_DYN)
		goto out;
	if (!elf_check_arch(interp_elf_ex))
		goto out;
	if (!interpreter->f_op || !interpreter->f_op->mmap)
		goto out;

	
	if (interp_elf_ex->e_phentsize != sizeof(struct elf_phdr))
		goto out;
	if (interp_elf_ex->e_phnum < 1 || interp_elf_ex->e_phnum > 65536U / sizeof(struct elf_phdr))
		goto out;

	
	size = sizeof(struct elf_phdr) * interp_elf_ex->e_phnum;
	if (size > ELF_MIN_ALIGN)
		goto out;
	elf_phdata = kmalloc(size, GFP_KERNEL);
	if (!elf_phdata)
		goto out;

	retval = kernel_read(interpreter, interp_elf_ex->e_phoff, (char *)elf_phdata,size);
	error = -EIO;
	if (retval != size) {
		if (retval < 0)
			error = retval;	
		goto out_close;
	}

	eppnt = elf_phdata;
	for (i = 0; i < interp_elf_ex->e_phnum; i++, eppnt++) {
		if (eppnt->p_type == PT_LOAD) {
			int elf_type = MAP_PRIVATE | MAP_DENYWRITE;
			int elf_prot = 0;
			unsigned long vaddr = 0;
			unsigned long k, map_addr;

			if (eppnt->p_flags & PF_R)
		    		elf_prot = PROT_READ;
			if (eppnt->p_flags & PF_W)
				elf_prot |= PROT_WRITE;
			if (eppnt->p_flags & PF_X)
				elf_prot |= PROT_EXEC;
			vaddr = eppnt->p_vaddr;
			if (interp_elf_ex->e_type == ET_EXEC || load_addr_set)
				elf_type |= MAP_FIXED;

			map_addr = elf_map(interpreter, load_addr + vaddr, eppnt, elf_prot, elf_type);
			error = map_addr;
			if (BAD_ADDR(map_addr))
				goto out_close;

			if (!load_addr_set && interp_elf_ex->e_type == ET_DYN) {
				load_addr = map_addr - ELF_PAGESTART(vaddr);
				load_addr_set = 1;
			}

			
			k = load_addr + eppnt->p_vaddr;
			if (BAD_ADDR(k) || eppnt->p_filesz > eppnt->p_memsz || eppnt->p_memsz > TASK_SIZE || TASK_SIZE - eppnt->p_memsz < k) {


				error = -ENOMEM;
				goto out_close;
			}

			
			k = load_addr + eppnt->p_vaddr + eppnt->p_filesz;
			if (k > elf_bss)
				elf_bss = k;

			
			k = load_addr + eppnt->p_memsz + eppnt->p_vaddr;
			if (k > last_bss)
				last_bss = k;
		}
	}

	
	if (padzero(elf_bss)) {
		error = -EFAULT;
		goto out_close;
	}

	
	elf_bss = ELF_PAGESTART(elf_bss + ELF_MIN_ALIGN - 1);

	
	if (last_bss > elf_bss) {
		down_write(&current->mm->mmap_sem);
		error = do_brk(elf_bss, last_bss - elf_bss);
		up_write(&current->mm->mmap_sem);
		if (BAD_ADDR(error))
			goto out_close;
	}

	*interp_load_addr = load_addr;
	error = ((unsigned long)interp_elf_ex->e_entry) + load_addr;

out_close:
	kfree(elf_phdata);
out:
	return error;
}

static unsigned long load_aout_interp(struct exec *interp_ex, struct file *interpreter)
{
	unsigned long text_data, elf_entry = ~0UL;
	char __user * addr;
	loff_t offset;

	current->mm->end_code = interp_ex->a_text;
	text_data = interp_ex->a_text + interp_ex->a_data;
	current->mm->end_data = text_data;
	current->mm->brk = interp_ex->a_bss + text_data;

	switch (N_MAGIC(*interp_ex)) {
	case OMAGIC:
		offset = 32;
		addr = (char __user *)0;
		break;
	case ZMAGIC:
	case QMAGIC:
		offset = N_TXTOFF(*interp_ex);
		addr = (char __user *)N_TXTADDR(*interp_ex);
		break;
	default:
		goto out;
	}

	down_write(&current->mm->mmap_sem);	
	do_brk(0, text_data);
	up_write(&current->mm->mmap_sem);
	if (!interpreter->f_op || !interpreter->f_op->read)
		goto out;
	if (interpreter->f_op->read(interpreter, addr, text_data, &offset) < 0)
		goto out;
	flush_icache_range((unsigned long)addr, (unsigned long)addr + text_data);

	down_write(&current->mm->mmap_sem);	
	do_brk(ELF_PAGESTART(text_data + ELF_MIN_ALIGN - 1), interp_ex->a_bss);
	up_write(&current->mm->mmap_sem);
	elf_entry = interp_ex->a_entry;

out:
	return elf_entry;
}











static unsigned long randomize_stack_top(unsigned long stack_top)
{
	unsigned int random_variable = 0;

	if ((current->flags & PF_RANDOMIZE) && !(current->personality & ADDR_NO_RANDOMIZE)) {
		random_variable = get_random_int() & STACK_RND_MASK;
		random_variable <<= PAGE_SHIFT;
	}

	return PAGE_ALIGN(stack_top) + random_variable;

	return PAGE_ALIGN(stack_top) - random_variable;

}

static int load_elf_binary(struct linux_binprm *bprm, struct pt_regs *regs)
{
	struct file *interpreter = NULL; 
 	unsigned long load_addr = 0, load_bias = 0;
	int load_addr_set = 0;
	char * elf_interpreter = NULL;
	unsigned int interpreter_type = INTERPRETER_NONE;
	unsigned char ibcs2_interpreter = 0;
	unsigned long error;
	struct elf_phdr *elf_ppnt, *elf_phdata;
	unsigned long elf_bss, elf_brk;
	int elf_exec_fileno;
	int retval, i;
	unsigned int size;
	unsigned long elf_entry, interp_load_addr = 0;
	unsigned long start_code, end_code, start_data, end_data;
	unsigned long reloc_func_desc = 0;
	char passed_fileno[6];
	struct files_struct *files;
	int executable_stack = EXSTACK_DEFAULT;
	unsigned long def_flags = 0;
	struct {
		struct elfhdr elf_ex;
		struct elfhdr interp_elf_ex;
  		struct exec interp_ex;
	} *loc;

	loc = kmalloc(sizeof(*loc), GFP_KERNEL);
	if (!loc) {
		retval = -ENOMEM;
		goto out_ret;
	}
	
	
	loc->elf_ex = *((struct elfhdr *)bprm->buf);

	retval = -ENOEXEC;
	
	if (memcmp(loc->elf_ex.e_ident, ELFMAG, SELFMAG) != 0)
		goto out;

	if (loc->elf_ex.e_type != ET_EXEC && loc->elf_ex.e_type != ET_DYN)
		goto out;
	if (!elf_check_arch(&loc->elf_ex))
		goto out;
	if (!bprm->file->f_op||!bprm->file->f_op->mmap)
		goto out;

	
	if (loc->elf_ex.e_phentsize != sizeof(struct elf_phdr))
		goto out;
	if (loc->elf_ex.e_phnum < 1 || loc->elf_ex.e_phnum > 65536U / sizeof(struct elf_phdr))
		goto out;
	size = loc->elf_ex.e_phnum * sizeof(struct elf_phdr);
	retval = -ENOMEM;
	elf_phdata = kmalloc(size, GFP_KERNEL);
	if (!elf_phdata)
		goto out;

	retval = kernel_read(bprm->file, loc->elf_ex.e_phoff, (char *)elf_phdata, size);
	if (retval != size) {
		if (retval >= 0)
			retval = -EIO;
		goto out_free_ph;
	}

	files = current->files;	
	retval = unshare_files();
	if (retval < 0)
		goto out_free_ph;
	if (files == current->files) {
		put_files_struct(files);
		files = NULL;
	}

	
	retval = get_unused_fd();
	if (retval < 0)
		goto out_free_fh;
	get_file(bprm->file);
	fd_install(elf_exec_fileno = retval, bprm->file);

	elf_ppnt = elf_phdata;
	elf_bss = 0;
	elf_brk = 0;

	start_code = ~0UL;
	end_code = 0;
	start_data = 0;
	end_data = 0;

	for (i = 0; i < loc->elf_ex.e_phnum; i++) {
		if (elf_ppnt->p_type == PT_INTERP) {
			
			retval = -ENOEXEC;
			if (elf_ppnt->p_filesz > PATH_MAX ||  elf_ppnt->p_filesz < 2)
				goto out_free_file;

			retval = -ENOMEM;
			elf_interpreter = kmalloc(elf_ppnt->p_filesz, GFP_KERNEL);
			if (!elf_interpreter)
				goto out_free_file;

			retval = kernel_read(bprm->file, elf_ppnt->p_offset, elf_interpreter, elf_ppnt->p_filesz);

			if (retval != elf_ppnt->p_filesz) {
				if (retval >= 0)
					retval = -EIO;
				goto out_free_interp;
			}
			
			retval = -ENOEXEC;
			if (elf_interpreter[elf_ppnt->p_filesz - 1] != '\0')
				goto out_free_interp;

			
			if (strcmp(elf_interpreter,"/usr/lib/libc.so.1") == 0 || strcmp(elf_interpreter,"/usr/lib/ld.so.1") == 0)
				ibcs2_interpreter = 1;

			
			SET_PERSONALITY(loc->elf_ex, ibcs2_interpreter);

			interpreter = open_exec(elf_interpreter);
			retval = PTR_ERR(interpreter);
			if (IS_ERR(interpreter))
				goto out_free_interp;
			retval = kernel_read(interpreter, 0, bprm->buf, BINPRM_BUF_SIZE);
			if (retval != BINPRM_BUF_SIZE) {
				if (retval >= 0)
					retval = -EIO;
				goto out_free_dentry;
			}

			
			loc->interp_ex = *((struct exec *)bprm->buf);
			loc->interp_elf_ex = *((struct elfhdr *)bprm->buf);
			break;
		}
		elf_ppnt++;
	}

	elf_ppnt = elf_phdata;
	for (i = 0; i < loc->elf_ex.e_phnum; i++, elf_ppnt++)
		if (elf_ppnt->p_type == PT_GNU_STACK) {
			if (elf_ppnt->p_flags & PF_X)
				executable_stack = EXSTACK_ENABLE_X;
			else executable_stack = EXSTACK_DISABLE_X;
			break;
		}

	
	if (elf_interpreter) {
		interpreter_type = INTERPRETER_ELF | INTERPRETER_AOUT;

		
		if ((N_MAGIC(loc->interp_ex) != OMAGIC) && (N_MAGIC(loc->interp_ex) != ZMAGIC) && (N_MAGIC(loc->interp_ex) != QMAGIC))

			interpreter_type = INTERPRETER_ELF;

		if (memcmp(loc->interp_elf_ex.e_ident, ELFMAG, SELFMAG) != 0)
			interpreter_type &= ~INTERPRETER_ELF;

		retval = -ELIBBAD;
		if (!interpreter_type)
			goto out_free_dentry;

		
		if ((interpreter_type & INTERPRETER_ELF) && interpreter_type != INTERPRETER_ELF) {
	     		
			
			interpreter_type = INTERPRETER_ELF;
		}
		
		if ((interpreter_type == INTERPRETER_ELF) && !elf_check_arch(&loc->interp_elf_ex))
			goto out_free_dentry;
	} else {
		
		SET_PERSONALITY(loc->elf_ex, ibcs2_interpreter);
	}

	
	if ((!bprm->sh_bang) && (interpreter_type == INTERPRETER_AOUT)) {
		char *passed_p = passed_fileno;
		sprintf(passed_fileno, "%d", elf_exec_fileno);

		if (elf_interpreter) {
			retval = copy_strings_kernel(1, &passed_p, bprm);
			if (retval)
				goto out_free_dentry; 
			bprm->argc++;
		}
	}

	
	retval = flush_old_exec(bprm);
	if (retval)
		goto out_free_dentry;

	
	if (files) {
		put_files_struct(files);
		files = NULL;
	}

	
	current->mm->start_data = 0;
	current->mm->end_data = 0;
	current->mm->end_code = 0;
	current->mm->mmap = NULL;
	current->flags &= ~PF_FORKNOEXEC;
	current->mm->def_flags = def_flags;

	
	SET_PERSONALITY(loc->elf_ex, ibcs2_interpreter);
	if (elf_read_implies_exec(loc->elf_ex, executable_stack))
		current->personality |= READ_IMPLIES_EXEC;

	if (!(current->personality & ADDR_NO_RANDOMIZE) && randomize_va_space)
		current->flags |= PF_RANDOMIZE;
	arch_pick_mmap_layout(current->mm);

	
	current->mm->free_area_cache = current->mm->mmap_base;
	current->mm->cached_hole_size = 0;
	retval = setup_arg_pages(bprm, randomize_stack_top(STACK_TOP), executable_stack);
	if (retval < 0) {
		send_sig(SIGKILL, current, 0);
		goto out_free_dentry;
	}
	
	current->mm->start_stack = bprm->p;

	
	for(i = 0, elf_ppnt = elf_phdata;
	    i < loc->elf_ex.e_phnum; i++, elf_ppnt++) {
		int elf_prot = 0, elf_flags;
		unsigned long k, vaddr;

		if (elf_ppnt->p_type != PT_LOAD)
			continue;

		if (unlikely (elf_brk > elf_bss)) {
			unsigned long nbyte;
	            
			
			retval = set_brk (elf_bss + load_bias, elf_brk + load_bias);
			if (retval) {
				send_sig(SIGKILL, current, 0);
				goto out_free_dentry;
			}
			nbyte = ELF_PAGEOFFSET(elf_bss);
			if (nbyte) {
				nbyte = ELF_MIN_ALIGN - nbyte;
				if (nbyte > elf_brk - elf_bss)
					nbyte = elf_brk - elf_bss;
				if (clear_user((void __user *)elf_bss + load_bias, nbyte)) {
					
				}
			}
		}

		if (elf_ppnt->p_flags & PF_R)
			elf_prot |= PROT_READ;
		if (elf_ppnt->p_flags & PF_W)
			elf_prot |= PROT_WRITE;
		if (elf_ppnt->p_flags & PF_X)
			elf_prot |= PROT_EXEC;

		elf_flags = MAP_PRIVATE | MAP_DENYWRITE | MAP_EXECUTABLE;

		vaddr = elf_ppnt->p_vaddr;
		if (loc->elf_ex.e_type == ET_EXEC || load_addr_set) {
			elf_flags |= MAP_FIXED;
		} else if (loc->elf_ex.e_type == ET_DYN) {
			
			load_bias = ELF_PAGESTART(ELF_ET_DYN_BASE - vaddr);
		}

		error = elf_map(bprm->file, load_bias + vaddr, elf_ppnt, elf_prot, elf_flags);
		if (BAD_ADDR(error)) {
			send_sig(SIGKILL, current, 0);
			goto out_free_dentry;
		}

		if (!load_addr_set) {
			load_addr_set = 1;
			load_addr = (elf_ppnt->p_vaddr - elf_ppnt->p_offset);
			if (loc->elf_ex.e_type == ET_DYN) {
				load_bias += error - ELF_PAGESTART(load_bias + vaddr);
				load_addr += load_bias;
				reloc_func_desc = load_bias;
			}
		}
		k = elf_ppnt->p_vaddr;
		if (k < start_code)
			start_code = k;
		if (start_data < k)
			start_data = k;

		
		if (BAD_ADDR(k) || elf_ppnt->p_filesz > elf_ppnt->p_memsz || elf_ppnt->p_memsz > TASK_SIZE || TASK_SIZE - elf_ppnt->p_memsz < k) {

			
			send_sig(SIGKILL, current, 0);
			goto out_free_dentry;
		}

		k = elf_ppnt->p_vaddr + elf_ppnt->p_filesz;

		if (k > elf_bss)
			elf_bss = k;
		if ((elf_ppnt->p_flags & PF_X) && end_code < k)
			end_code = k;
		if (end_data < k)
			end_data = k;
		k = elf_ppnt->p_vaddr + elf_ppnt->p_memsz;
		if (k > elf_brk)
			elf_brk = k;
	}

	loc->elf_ex.e_entry += load_bias;
	elf_bss += load_bias;
	elf_brk += load_bias;
	start_code += load_bias;
	end_code += load_bias;
	start_data += load_bias;
	end_data += load_bias;

	
	retval = set_brk(elf_bss, elf_brk);
	if (retval) {
		send_sig(SIGKILL, current, 0);
		goto out_free_dentry;
	}
	if (likely(elf_bss != elf_brk) && unlikely(padzero(elf_bss))) {
		send_sig(SIGSEGV, current, 0);
		retval = -EFAULT; 
		goto out_free_dentry;
	}

	if (elf_interpreter) {
		if (interpreter_type == INTERPRETER_AOUT)
			elf_entry = load_aout_interp(&loc->interp_ex, interpreter);
		else elf_entry = load_elf_interp(&loc->interp_elf_ex, interpreter, &interp_load_addr);


		if (BAD_ADDR(elf_entry)) {
			force_sig(SIGSEGV, current);
			retval = IS_ERR((void *)elf_entry) ? (int)elf_entry : -EINVAL;
			goto out_free_dentry;
		}
		reloc_func_desc = interp_load_addr;

		allow_write_access(interpreter);
		fput(interpreter);
		kfree(elf_interpreter);
	} else {
		elf_entry = loc->elf_ex.e_entry;
		if (BAD_ADDR(elf_entry)) {
			force_sig(SIGSEGV, current);
			retval = -EINVAL;
			goto out_free_dentry;
		}
	}

	kfree(elf_phdata);

	if (interpreter_type != INTERPRETER_AOUT)
		sys_close(elf_exec_fileno);

	set_binfmt(&elf_format);


	retval = arch_setup_additional_pages(bprm, executable_stack);
	if (retval < 0) {
		send_sig(SIGKILL, current, 0);
		goto out;
	}


	compute_creds(bprm);
	current->flags &= ~PF_FORKNOEXEC;
	create_elf_tables(bprm, &loc->elf_ex, (interpreter_type == INTERPRETER_AOUT), load_addr, interp_load_addr);

	
	if (interpreter_type == INTERPRETER_AOUT)
		current->mm->arg_start += strlen(passed_fileno) + 1;
	current->mm->end_code = end_code;
	current->mm->start_code = start_code;
	current->mm->start_data = start_data;
	current->mm->end_data = end_data;
	current->mm->start_stack = bprm->p;

	if (current->personality & MMAP_PAGE_ZERO) {
		
		down_write(&current->mm->mmap_sem);
		error = do_mmap(NULL, 0, PAGE_SIZE, PROT_READ | PROT_EXEC, MAP_FIXED | MAP_PRIVATE, 0);
		up_write(&current->mm->mmap_sem);
	}


	
	ELF_PLAT_INIT(regs, reloc_func_desc);


	start_thread(regs, elf_entry, bprm->p);
	if (unlikely(current->ptrace & PT_PTRACED)) {
		if (current->ptrace & PT_TRACE_EXEC)
			ptrace_notify ((PTRACE_EVENT_EXEC << 8) | SIGTRAP);
		else send_sig(SIGTRAP, current, 0);
	}
	retval = 0;
out:
	kfree(loc);
out_ret:
	return retval;

	
out_free_dentry:
	allow_write_access(interpreter);
	if (interpreter)
		fput(interpreter);
out_free_interp:
	kfree(elf_interpreter);
out_free_file:
	sys_close(elf_exec_fileno);
out_free_fh:
	if (files)
		reset_files_struct(current, files);
out_free_ph:
	kfree(elf_phdata);
	goto out;
}


static int load_elf_library(struct file *file)
{
	struct elf_phdr *elf_phdata;
	struct elf_phdr *eppnt;
	unsigned long elf_bss, bss, len;
	int retval, error, i, j;
	struct elfhdr elf_ex;

	error = -ENOEXEC;
	retval = kernel_read(file, 0, (char *)&elf_ex, sizeof(elf_ex));
	if (retval != sizeof(elf_ex))
		goto out;

	if (memcmp(elf_ex.e_ident, ELFMAG, SELFMAG) != 0)
		goto out;

	
	if (elf_ex.e_type != ET_EXEC || elf_ex.e_phnum > 2 || !elf_check_arch(&elf_ex) || !file->f_op || !file->f_op->mmap)
		goto out;

	

	j = sizeof(struct elf_phdr) * elf_ex.e_phnum;
	

	error = -ENOMEM;
	elf_phdata = kmalloc(j, GFP_KERNEL);
	if (!elf_phdata)
		goto out;

	eppnt = elf_phdata;
	error = -ENOEXEC;
	retval = kernel_read(file, elf_ex.e_phoff, (char *)eppnt, j);
	if (retval != j)
		goto out_free_ph;

	for (j = 0, i = 0; i<elf_ex.e_phnum; i++)
		if ((eppnt + i)->p_type == PT_LOAD)
			j++;
	if (j != 1)
		goto out_free_ph;

	while (eppnt->p_type != PT_LOAD)
		eppnt++;

	
	down_write(&current->mm->mmap_sem);
	error = do_mmap(file, ELF_PAGESTART(eppnt->p_vaddr), (eppnt->p_filesz + ELF_PAGEOFFSET(eppnt->p_vaddr)), PROT_READ | PROT_WRITE | PROT_EXEC, MAP_FIXED | MAP_PRIVATE | MAP_DENYWRITE, (eppnt->p_offset - ELF_PAGEOFFSET(eppnt->p_vaddr)));






	up_write(&current->mm->mmap_sem);
	if (error != ELF_PAGESTART(eppnt->p_vaddr))
		goto out_free_ph;

	elf_bss = eppnt->p_vaddr + eppnt->p_filesz;
	if (padzero(elf_bss)) {
		error = -EFAULT;
		goto out_free_ph;
	}

	len = ELF_PAGESTART(eppnt->p_filesz + eppnt->p_vaddr + ELF_MIN_ALIGN - 1);
	bss = eppnt->p_memsz + eppnt->p_vaddr;
	if (bss > len) {
		down_write(&current->mm->mmap_sem);
		do_brk(len, bss - len);
		up_write(&current->mm->mmap_sem);
	}
	error = 0;

out_free_ph:
	kfree(elf_phdata);
out:
	return error;
}






static int dump_write(struct file *file, const void *addr, int nr)
{
	return file->f_op->write(file, addr, nr, &file->f_pos) == nr;
}

static int dump_seek(struct file *file, loff_t off)
{
	if (file->f_op->llseek && file->f_op->llseek != no_llseek) {
		if (file->f_op->llseek(file, off, SEEK_CUR) < 0)
			return 0;
	} else {
		char *buf = (char *)get_zeroed_page(GFP_KERNEL);
		if (!buf)
			return 0;
		while (off > 0) {
			unsigned long n = off;
			if (n > PAGE_SIZE)
				n = PAGE_SIZE;
			if (!dump_write(file, buf, n))
				return 0;
			off -= n;
		}
		free_page((unsigned long)buf);
	}
	return 1;
}


static int maydump(struct vm_area_struct *vma)
{
	
	if (vma->vm_flags & VM_ALWAYSDUMP)
		return 1;

	
	if (vma->vm_flags & (VM_IO | VM_RESERVED))
		return 0;

	
	if (vma->vm_flags & VM_SHARED)
		return vma->vm_file->f_path.dentry->d_inode->i_nlink == 0;

	
	if (!vma->anon_vma)
		return 0;

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



static int alignfile(struct file *file, loff_t *foffset)
{
	static const char buf[4] = { 0, };
	DUMP_WRITE(buf, roundup(*foffset, 4) - *foffset, foffset);
	return 1;
}

static int writenote(struct memelfnote *men, struct file *file, loff_t *foffset)
{
	struct elf_note en;
	en.n_namesz = strlen(men->name) + 1;
	en.n_descsz = men->datasz;
	en.n_type = men->type;

	DUMP_WRITE(&en, sizeof(en), foffset);
	DUMP_WRITE(men->name, en.n_namesz, foffset);
	if (!alignfile(file, foffset))
		return 0;
	DUMP_WRITE(men->data, men->datasz, foffset);
	if (!alignfile(file, foffset))
		return 0;

	return 1;
}







static void fill_elf_header(struct elfhdr *elf, int segs)
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
	elf->e_flags = ELF_CORE_EFLAGS;
	elf->e_ehsize = sizeof(struct elfhdr);
	elf->e_phentsize = sizeof(struct elf_phdr);
	elf->e_phnum = segs;
	elf->e_shentsize = 0;
	elf->e_shnum = 0;
	elf->e_shstrndx = 0;
	return;
}

static void fill_elf_note_phdr(struct elf_phdr *phdr, int sz, loff_t offset)
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

static void fill_note(struct memelfnote *note, const char *name, int type,  unsigned int sz, void *data)
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
}

static int fill_psinfo(struct elf_prpsinfo *psinfo, struct task_struct *p, struct mm_struct *mm)
{
	unsigned int i, len;
	
	
	memset(psinfo, 0, sizeof(struct elf_prpsinfo));

	len = mm->arg_end - mm->arg_start;
	if (len >= ELF_PRARGSZ)
		len = ELF_PRARGSZ-1;
	if (copy_from_user(&psinfo->pr_psargs, (const char __user *)mm->arg_start, len))
		return -EFAULT;
	for(i = 0; i < len; i++)
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
	int sz = 0;
	struct task_struct *p = t->thread;
	t->num_notes = 0;

	fill_prstatus(&t->prstatus, p, signr);
	elf_core_copy_task_regs(p, &t->prstatus.pr_reg);	
	
	fill_note(&t->notes[0], "CORE", NT_PRSTATUS, sizeof(t->prstatus), &(t->prstatus));
	t->num_notes++;
	sz += notesize(&t->notes[0]);

	if ((t->prstatus.pr_fpvalid = elf_core_copy_task_fpregs(p, NULL, &t->fpu))) {
		fill_note(&t->notes[1], "CORE", NT_PRFPREG, sizeof(t->fpu), &(t->fpu));
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

static struct vm_area_struct *first_vma(struct task_struct *tsk, struct vm_area_struct *gate_vma)
{
	struct vm_area_struct *ret = tsk->mm->mmap;

	if (ret)
		return ret;
	return gate_vma;
}

static struct vm_area_struct *next_vma(struct vm_area_struct *this_vma, struct vm_area_struct *gate_vma)
{
	struct vm_area_struct *ret;

	ret = this_vma->vm_next;
	if (ret)
		return ret;
	if (this_vma == gate_vma)
		return NULL;
	return gate_vma;
}


static int elf_core_dump(long signr, struct pt_regs *regs, struct file *file)
{

	int has_dumped = 0;
	mm_segment_t fs;
	int segs;
	size_t size = 0;
	int i;
	struct vm_area_struct *vma, *gate_vma;
	struct elfhdr *elf = NULL;
	loff_t offset = 0, dataoff, foffset;
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
	elf_addr_t *auxv;

	
  
	
	elf = kmalloc(sizeof(*elf), GFP_KERNEL);
	if (!elf)
		goto cleanup;
	prstatus = kmalloc(sizeof(*prstatus), GFP_KERNEL);
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
	
	memset(prstatus, 0, sizeof(*prstatus));
	fill_prstatus(prstatus, current, signr);
	elf_core_copy_regs(&prstatus->pr_reg, regs);
	
	segs = current->mm->map_count;

	segs += ELF_CORE_EXTRA_PHDRS;


	gate_vma = get_gate_vma(current);
	if (gate_vma != NULL)
		segs++;

	
	fill_elf_header(elf, segs + 1);	

	has_dumped = 1;
	current->flags |= PF_DUMPCORE;

	

	fill_note(notes + 0, "CORE", NT_PRSTATUS, sizeof(*prstatus), prstatus);
	fill_psinfo(psinfo, current->group_leader, current->mm);
	fill_note(notes + 1, "CORE", NT_PRPSINFO, sizeof(*psinfo), psinfo);
	
	numnote = 2;

	auxv = (elf_addr_t *)current->mm->saved_auxv;

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
	offset += (segs + 1) * sizeof(struct elf_phdr); 
	foffset = offset;

	
	{
		struct elf_phdr phdr;
		int sz = 0;

		for (i = 0; i < numnote; i++)
			sz += notesize(notes + i);
		
		sz += thread_status_size;


		sz += ELF_CORE_EXTRA_NOTES_SIZE;


		fill_elf_note_phdr(&phdr, sz, offset);
		offset += sz;
		DUMP_WRITE(&phdr, sizeof(phdr));
	}

	dataoff = offset = roundup(offset, ELF_EXEC_PAGESIZE);

	
	for (vma = first_vma(current, gate_vma); vma != NULL;
			vma = next_vma(vma, gate_vma)) {
		struct elf_phdr phdr;
		size_t sz;

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
		if (!writenote(notes + i, file, &foffset))
			goto end_coredump;


	ELF_CORE_WRITE_EXTRA_NOTES;


	
	list_for_each(t, &thread_list) {
		struct elf_thread_status *tmp = list_entry(t, struct elf_thread_status, list);

		for (i = 0; i < tmp->num_notes; i++)
			if (!writenote(&tmp->notes[i], file, &foffset))
				goto end_coredump;
	}

	
	DUMP_SEEK(dataoff - foffset);

	for (vma = first_vma(current, gate_vma); vma != NULL;
			vma = next_vma(vma, gate_vma)) {
		unsigned long addr;

		if (!maydump(vma))
			continue;

		for (addr = vma->vm_start;
		     addr < vma->vm_end;
		     addr += PAGE_SIZE) {
			struct page *page;
			struct vm_area_struct *vma;

			if (get_user_pages(current, current->mm, addr, 1, 0, 1, &page, &vma) <= 0) {
				DUMP_SEEK(PAGE_SIZE);
			} else {
				if (page == ZERO_PAGE(addr)) {
					DUMP_SEEK(PAGE_SIZE);
				} else {
					void *kaddr;
					flush_cache_page(vma, addr, page_to_pfn(page));
					kaddr = kmap(page);
					if ((size += PAGE_SIZE) > limit || !dump_write(file, kaddr, PAGE_SIZE)) {

						kunmap(page);
						page_cache_release(page);
						goto end_coredump;
					}
					kunmap(page);
				}
				page_cache_release(page);
			}
		}
	}


	ELF_CORE_WRITE_EXTRA_DATA;


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



static int __init init_elf_binfmt(void)
{
	return register_binfmt(&elf_format);
}

static void __exit exit_elf_binfmt(void)
{
	
	unregister_binfmt(&elf_format);
}

core_initcall(init_elf_binfmt);
module_exit(exit_elf_binfmt);
MODULE_LICENSE("GPL");
