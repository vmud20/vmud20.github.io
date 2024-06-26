


__FBSDID("$FreeBSD$");




















































MODULE_VERSION(linux64, 1);








SYSCTL_PROC(_compat_linux, OID_AUTO, debug, CTLTYPE_STRING | CTLFLAG_RW, 0, 0, linux_sysctl_debug, "A", "Linux 64 debugging control");







const char *linux_kplatform;
static int linux_szsigcode;
static vm_object_t linux_shared_page_obj;
static char *linux_shared_page_mapping;
extern char _binary_linux_locore_o_start;
extern char _binary_linux_locore_o_end;

extern struct sysent linux_sysent[LINUX_SYS_MAXSYSCALL];

SET_DECLARE(linux_ioctl_handler_set, struct linux_ioctl_handler);

static register_t * linux_copyout_strings(struct image_params *imgp);
static int	elf_linux_fixup(register_t **stack_base, struct image_params *iparams);
static boolean_t linux_trans_osrel(const Elf_Note *note, int32_t *osrel);
static void	linux_vdso_install(void *param);
static void	linux_vdso_deinstall(void *param);
static void	linux_set_syscall_retval(struct thread *td, int error);
static int	linux_fetch_syscall_args(struct thread *td, struct syscall_args *sa);
static void	linux_exec_setregs(struct thread *td, struct image_params *imgp, u_long stack);
static int	linux_vsyscall(struct thread *td);


static int bsd_to_linux_errno[ELAST + 1] = {
	-0,  -1,  -2,  -3,  -4,  -5,  -6,  -7,  -8,  -9, -10, -35, -12, -13, -14, -15, -16, -17, -18, -19, -20, -21, -22, -23, -24, -25, -26, -27, -28, -29, -30, -31, -32, -33, -34, -11,-115,-114, -88, -89, -90, -91, -92, -93, -94, -95, -96, -97, -98, -99, -100,-101,-102,-103,-104,-105,-106,-107,-108,-109, -110,-111, -40, -36,-112,-113, -39, -11, -87,-122, -116, -66,  -6,  -6,  -6,  -6,  -6, -37, -38,  -9, -6,  -6, -43, -42, -75,-125, -84, -95, -16, -74, -72, -67, -71 };











static int _bsd_to_linux_trapcode[] = {
	LINUX_T_UNKNOWN,	 6, LINUX_T_UNKNOWN, 3, LINUX_T_UNKNOWN, LINUX_T_UNKNOWN, 16, 254, LINUX_T_UNKNOWN, 13, 1, LINUX_T_UNKNOWN, 14, LINUX_T_UNKNOWN, 17, LINUX_T_UNKNOWN, LINUX_T_UNKNOWN, LINUX_T_UNKNOWN, 0, 2, 4, 5, 7, 8, 9, 10, 11, 12, 18, 19, 15 };


































LINUX_VDSO_SYM_INTPTR(linux_rt_sigcode);
LINUX_VDSO_SYM_CHAR(linux_platform);


static int translate_traps(int signal, int trap_code)
{

	if (signal != SIGBUS)
		return signal;
	switch (trap_code) {
	case T_PROTFLT:
	case T_TSSFLT:
	case T_DOUBLEFLT:
	case T_PAGEFLT:
		return SIGSEGV;
	default:
		return signal;
	}
}

static int linux_fetch_syscall_args(struct thread *td, struct syscall_args *sa)
{
	struct proc *p;
	struct trapframe *frame;

	p = td->td_proc;
	frame = td->td_frame;

	sa->args[0] = frame->tf_rdi;
	sa->args[1] = frame->tf_rsi;
	sa->args[2] = frame->tf_rdx;
	sa->args[3] = frame->tf_rcx;
	sa->args[4] = frame->tf_r8;
	sa->args[5] = frame->tf_r9;
	sa->code = frame->tf_rax;

	if (sa->code >= p->p_sysent->sv_size)
		
		sa->callp = &p->p_sysent->sv_table[p->p_sysent->sv_size - 1];
	else sa->callp = &p->p_sysent->sv_table[sa->code];
	sa->narg = sa->callp->sy_narg;

	td->td_retval[0] = 0;
	return (0);
}

static void linux_set_syscall_retval(struct thread *td, int error)
{
	struct trapframe *frame = td->td_frame;

	
	td->td_retval[1] = frame->tf_rdx;
	frame->tf_r10 = frame->tf_rcx;

	cpu_set_syscall_retval(td, error);

	 
	set_pcb_flags(td->td_pcb, PCB_FULL_IRET);
}

static int elf_linux_fixup(register_t **stack_base, struct image_params *imgp)
{
	Elf_Auxargs *args;
	Elf_Addr *base;
	Elf_Addr *pos;
	struct ps_strings *arginfo;
	struct proc *p;

	p = imgp->proc;
	arginfo = (struct ps_strings *)p->p_sysent->sv_psstrings;

	KASSERT(curthread->td_proc == imgp->proc, ("unsafe elf_linux_fixup(), should be curproc"));
	base = (Elf64_Addr *)*stack_base;
	args = (Elf64_Auxargs *)imgp->auxargs;
	pos = base + (imgp->args->argc + imgp->args->envc + 2);

	AUXARGS_ENTRY(pos, LINUX_AT_SYSINFO_EHDR, imgp->proc->p_sysent->sv_shared_page_base);
	AUXARGS_ENTRY(pos, LINUX_AT_HWCAP, cpu_feature);
	AUXARGS_ENTRY(pos, LINUX_AT_CLKTCK, stclohz);
	AUXARGS_ENTRY(pos, AT_PHDR, args->phdr);
	AUXARGS_ENTRY(pos, AT_PHENT, args->phent);
	AUXARGS_ENTRY(pos, AT_PHNUM, args->phnum);
	AUXARGS_ENTRY(pos, AT_PAGESZ, args->pagesz);
	AUXARGS_ENTRY(pos, AT_BASE, args->base);
	AUXARGS_ENTRY(pos, AT_FLAGS, args->flags);
	AUXARGS_ENTRY(pos, AT_ENTRY, args->entry);
	AUXARGS_ENTRY(pos, AT_UID, imgp->proc->p_ucred->cr_ruid);
	AUXARGS_ENTRY(pos, AT_EUID, imgp->proc->p_ucred->cr_svuid);
	AUXARGS_ENTRY(pos, AT_GID, imgp->proc->p_ucred->cr_rgid);
	AUXARGS_ENTRY(pos, AT_EGID, imgp->proc->p_ucred->cr_svgid);
	AUXARGS_ENTRY(pos, LINUX_AT_SECURE, 0);
	AUXARGS_ENTRY(pos, LINUX_AT_PLATFORM, PTROUT(linux_platform));
	AUXARGS_ENTRY(pos, LINUX_AT_RANDOM, imgp->canary);
	if (imgp->execpathp != 0)
		AUXARGS_ENTRY(pos, LINUX_AT_EXECFN, imgp->execpathp);
	if (args->execfd != -1)
		AUXARGS_ENTRY(pos, AT_EXECFD, args->execfd);
	AUXARGS_ENTRY(pos, AT_NULL, 0);
	free(imgp->auxargs, M_TEMP);
	imgp->auxargs = NULL;

	base--;
	suword(base, (uint64_t)imgp->args->argc);

	*stack_base = (register_t *)base;
	return (0);
}


static register_t * linux_copyout_strings(struct image_params *imgp)
{
	int argc, envc;
	char **vectp;
	char *stringp, *destp;
	register_t *stack_base;
	struct ps_strings *arginfo;
	char canary[LINUX_AT_RANDOM_LEN];
	size_t execpath_len;
	struct proc *p;

	
	if (imgp->execpath != NULL && imgp->auxargs != NULL)
		execpath_len = strlen(imgp->execpath) + 1;
	else execpath_len = 0;

	p = imgp->proc;
	arginfo = (struct ps_strings *)p->p_sysent->sv_psstrings;
	destp =	(caddr_t)arginfo - SPARE_USRSPACE - roundup(sizeof(canary), sizeof(char *)) - roundup(execpath_len, sizeof(char *)) - roundup((ARG_MAX - imgp->args->stringspace), sizeof(char *));



	if (execpath_len != 0) {
		imgp->execpathp = (uintptr_t)arginfo - execpath_len;
		copyout(imgp->execpath, (void *)imgp->execpathp, execpath_len);
	}

	
	arc4rand(canary, sizeof(canary), 0);
	imgp->canary = (uintptr_t)arginfo - roundup(execpath_len, sizeof(char *)) - roundup(sizeof(canary), sizeof(char *));

	copyout(canary, (void *)imgp->canary, sizeof(canary));

	
	if (imgp->auxargs) {
		
		imgp->auxarg_size = (imgp->auxarg_size) ? imgp->auxarg_size :
		    (LINUX_AT_COUNT * 2);

		
		vectp = (char **)(destp - (imgp->args->argc + imgp->args->envc + 2 + imgp->auxarg_size) * sizeof(char *));

	} else {
		
		vectp = (char **)(destp - (imgp->args->argc + imgp->args->envc + 2) * sizeof(char *));
	}

	
	stack_base = (register_t *)vectp;

	stringp = imgp->args->begin_argv;
	argc = imgp->args->argc;
	envc = imgp->args->envc;

	
	copyout(stringp, destp, ARG_MAX - imgp->args->stringspace);

	
	suword(&arginfo->ps_argvstr, (long)(intptr_t)vectp);
	suword(&arginfo->ps_nargvstr, argc);

	
	for (; argc > 0; --argc) {
		suword(vectp++, (long)(intptr_t)destp);
		while (*stringp++ != 0)
			destp++;
		destp++;
	}

	
	suword(vectp++, 0);

	suword(&arginfo->ps_envstr, (long)(intptr_t)vectp);
	suword(&arginfo->ps_nenvstr, envc);

	
	for (; envc > 0; --envc) {
		suword(vectp++, (long)(intptr_t)destp);
		while (*stringp++ != 0)
			destp++;
		destp++;
	}

	
	suword(vectp, 0);
	return (stack_base);
}


static void linux_exec_setregs(struct thread *td, struct image_params *imgp, u_long stack)
{
	struct trapframe *regs = td->td_frame;
	struct pcb *pcb = td->td_pcb;

	mtx_lock(&dt_lock);
	if (td->td_proc->p_md.md_ldt != NULL)
		user_ldt_free(td);
	else mtx_unlock(&dt_lock);

	pcb->pcb_fsbase = 0;
	pcb->pcb_gsbase = 0;
	clear_pcb_flags(pcb, PCB_32BIT);
	pcb->pcb_initial_fpucw = __LINUX_NPXCW__;
	set_pcb_flags(pcb, PCB_FULL_IRET);

	bzero((char *)regs, sizeof(struct trapframe));
	regs->tf_rip = imgp->entry_addr;
	regs->tf_rsp = stack;
	regs->tf_rflags = PSL_USER | (regs->tf_rflags & PSL_T);
	regs->tf_ss = _udatasel;
	regs->tf_cs = _ucodesel;
	regs->tf_ds = _udatasel;
	regs->tf_es = _udatasel;
	regs->tf_fs = _ufssel;
	regs->tf_gs = _ugssel;
	regs->tf_flags = TF_HASSEGS;

	
	if (pcb->pcb_flags & PCB_DBREGS) {
		pcb->pcb_dr0 = 0;
		pcb->pcb_dr1 = 0;
		pcb->pcb_dr2 = 0;
		pcb->pcb_dr3 = 0;
		pcb->pcb_dr6 = 0;
		pcb->pcb_dr7 = 0;
		if (pcb == curpcb) {
			
			reset_dbregs();
		}
		clear_pcb_flags(pcb, PCB_DBREGS);
	}

	
	fpstate_drop(td);
}


int linux_rt_sigreturn(struct thread *td, struct linux_rt_sigreturn_args *args)
{
	struct proc *p;
	struct l_ucontext uc;
	struct l_sigcontext *context;
	struct trapframe *regs;
	unsigned long rflags;
	int error;
	ksiginfo_t ksi;

	regs = td->td_frame;
	error = copyin((void *)regs->tf_rbx, &uc, sizeof(uc));
	if (error != 0)
		return (error);

	p = td->td_proc;
	context = &uc.uc_mcontext;
	rflags = context->sc_rflags;

	
	


	if (!RFLAG_SECURE(rflags & ~PSL_RF, regs->tf_rflags & ~PSL_RF)) {
		printf("linux_rt_sigreturn: rflags = 0x%lx\n", rflags);
		return (EINVAL);
	}

	

	if (!CS_SECURE(context->sc_cs)) {
		printf("linux_rt_sigreturn: cs = 0x%x\n", context->sc_cs);
		ksiginfo_init_trap(&ksi);
		ksi.ksi_signo = SIGBUS;
		ksi.ksi_code = BUS_OBJERR;
		ksi.ksi_trapno = T_PROTFLT;
		ksi.ksi_addr = (void *)regs->tf_rip;
		trapsignal(td, &ksi);
		return (EINVAL);
	}

	PROC_LOCK(p);
	linux_to_bsd_sigset(&uc.uc_sigmask, &td->td_sigmask);
	SIG_CANTMASK(td->td_sigmask);
	signotify(td);
	PROC_UNLOCK(p);

	regs->tf_rdi    = context->sc_rdi;
	regs->tf_rsi    = context->sc_rsi;
	regs->tf_rdx    = context->sc_rdx;
	regs->tf_rbp    = context->sc_rbp;
	regs->tf_rbx    = context->sc_rbx;
	regs->tf_rcx    = context->sc_rcx;
	regs->tf_rax    = context->sc_rax;
	regs->tf_rip    = context->sc_rip;
	regs->tf_rsp    = context->sc_rsp;
	regs->tf_r8     = context->sc_r8;
	regs->tf_r9     = context->sc_r9;
	regs->tf_r10    = context->sc_r10;
	regs->tf_r11    = context->sc_r11;
	regs->tf_r12    = context->sc_r12;
	regs->tf_r13    = context->sc_r13;
	regs->tf_r14    = context->sc_r14;
	regs->tf_r15    = context->sc_r15;
	regs->tf_cs     = context->sc_cs;
	regs->tf_err    = context->sc_err;
	regs->tf_rflags = rflags;

	set_pcb_flags(td->td_pcb, PCB_FULL_IRET);
	return (EJUSTRETURN);
}


static void linux_rt_sendsig(sig_t catcher, ksiginfo_t *ksi, sigset_t *mask)
{
	struct l_rt_sigframe sf, *sfp;
	struct proc *p;
	struct thread *td;
	struct sigacts *psp;
	caddr_t sp;
	struct trapframe *regs;
	int sig, code;
	int oonstack;

	td = curthread;
	p = td->td_proc;
	PROC_LOCK_ASSERT(p, MA_OWNED);
	sig = ksi->ksi_signo;
	psp = p->p_sigacts;
	code = ksi->ksi_code;
	mtx_assert(&psp->ps_mtx, MA_OWNED);
	regs = td->td_frame;
	oonstack = sigonstack(regs->tf_rsp);

	LINUX_CTR4(rt_sendsig, "%p, %d, %p, %u", catcher, sig, mask, code);

	
	if ((td->td_pflags & TDP_ALTSTACK) != 0 && !oonstack && SIGISMEMBER(psp->ps_sigonstack, sig)) {
		sp = td->td_sigstk.ss_sp + td->td_sigstk.ss_size - sizeof(struct l_rt_sigframe);
	} else sp = (caddr_t)regs->tf_rsp - sizeof(struct l_rt_sigframe) - 128;
	
	sfp = (struct l_rt_sigframe *)((unsigned long)sp & ~0xFul);
	mtx_unlock(&psp->ps_mtx);

	
	sig = bsd_to_linux_signal(sig);

	
	bzero(&sf, sizeof(sf));
	bsd_to_linux_sigset(mask, &sf.sf_sc.uc_sigmask);
	bsd_to_linux_sigset(mask, &sf.sf_sc.uc_mcontext.sc_mask);

	sf.sf_sc.uc_stack.ss_sp = PTROUT(td->td_sigstk.ss_sp);
	sf.sf_sc.uc_stack.ss_size = td->td_sigstk.ss_size;
	sf.sf_sc.uc_stack.ss_flags = (td->td_pflags & TDP_ALTSTACK)
	    ? ((oonstack) ? LINUX_SS_ONSTACK : 0) : LINUX_SS_DISABLE;
	PROC_UNLOCK(p);

	sf.sf_sc.uc_mcontext.sc_rdi    = regs->tf_rdi;
	sf.sf_sc.uc_mcontext.sc_rsi    = regs->tf_rsi;
	sf.sf_sc.uc_mcontext.sc_rdx    = regs->tf_rdx;
	sf.sf_sc.uc_mcontext.sc_rbp    = regs->tf_rbp;
	sf.sf_sc.uc_mcontext.sc_rbx    = regs->tf_rbx;
	sf.sf_sc.uc_mcontext.sc_rcx    = regs->tf_rcx;
	sf.sf_sc.uc_mcontext.sc_rax    = regs->tf_rax;
	sf.sf_sc.uc_mcontext.sc_rip    = regs->tf_rip;
	sf.sf_sc.uc_mcontext.sc_rsp    = regs->tf_rsp;
	sf.sf_sc.uc_mcontext.sc_r8     = regs->tf_r8;
	sf.sf_sc.uc_mcontext.sc_r9     = regs->tf_r9;
	sf.sf_sc.uc_mcontext.sc_r10    = regs->tf_r10;
	sf.sf_sc.uc_mcontext.sc_r11    = regs->tf_r11;
	sf.sf_sc.uc_mcontext.sc_r12    = regs->tf_r12;
	sf.sf_sc.uc_mcontext.sc_r13    = regs->tf_r13;
	sf.sf_sc.uc_mcontext.sc_r14    = regs->tf_r14;
	sf.sf_sc.uc_mcontext.sc_r15    = regs->tf_r15;
	sf.sf_sc.uc_mcontext.sc_cs     = regs->tf_cs;
	sf.sf_sc.uc_mcontext.sc_rflags = regs->tf_rflags;
	sf.sf_sc.uc_mcontext.sc_err    = regs->tf_err;
	sf.sf_sc.uc_mcontext.sc_trapno = bsd_to_linux_trapcode(code);
	sf.sf_sc.uc_mcontext.sc_cr2    = (register_t)ksi->ksi_addr;

	
	regs->tf_rdi = sig;			
	regs->tf_rax = 0;
	regs->tf_rsi = (register_t)&sfp->sf_si;	
	regs->tf_rdx = (register_t)&sfp->sf_sc;	

	sf.sf_handler = catcher;
	
	ksiginfo_to_lsiginfo(ksi, &sf.sf_si, sig);

	
	if (copyout(&sf, sfp, sizeof(*sfp)) != 0) {

		printf("process %ld has trashed its stack\n", (long)p->p_pid);

		PROC_LOCK(p);
		sigexit(td, SIGILL);
	}

	regs->tf_rsp = (long)sfp;
	regs->tf_rip = linux_rt_sigcode;
	regs->tf_rflags &= ~(PSL_T | PSL_D);
	regs->tf_cs = _ucodesel;
	set_pcb_flags(td->td_pcb, PCB_FULL_IRET);
	PROC_LOCK(p);
	mtx_lock(&psp->ps_mtx);
}


static int exec_linux_imgact_try(struct image_params *iparams);

static int exec_linux_imgact_try(struct image_params *imgp)
{
	const char *head = (const char *)imgp->image_header;
	char *rpath;
	int error = -1, len;

	
	if (((const short *)head)[0] == SHELLMAGIC) {
		
		if ((error = exec_shell_imgact(imgp)) == 0) {
			linux_emul_convpath(FIRST_THREAD_IN_PROC(imgp->proc), imgp->interpreter_name, UIO_SYSSPACE, &rpath, 0, AT_FDCWD);

			if (rpath != NULL) {
				len = strlen(rpath) + 1;

				if (len <= MAXSHELLCMDLEN)
					memcpy(imgp->interpreter_name, rpath, len);
				free(rpath, M_TEMP);
			}
		}
	}
	return(error);
}




const unsigned long linux_vsyscall_vector[] = {
	LINUX_SYS_gettimeofday, LINUX_SYS_linux_time,  };



static int linux_vsyscall(struct thread *td)
{
	struct trapframe *frame;
	uint64_t retqaddr;
	int code, traced;
	int error; 

	frame = td->td_frame;

	
	if (__predict_true(frame->tf_rip < LINUX_VSYSCALL_START))
		return (EINVAL);
	if ((frame->tf_rip & (LINUX_VSYSCALL_SZ - 1)) != 0)
		return (EINVAL);
	code = (frame->tf_rip - LINUX_VSYSCALL_START) / LINUX_VSYSCALL_SZ;
	if (code >= nitems(linux_vsyscall_vector))
		return (EINVAL);

	
	error = copyin((void *)frame->tf_rsp, &retqaddr, sizeof(retqaddr));
	if (error)
		return (error);

	frame->tf_rip = retqaddr;
	frame->tf_rax = linux_vsyscall_vector[code];
	frame->tf_rsp += 8;

	traced = (frame->tf_flags & PSL_T);

	amd64_syscall(td, traced);

	return (0);
}

struct sysentvec elf_linux_sysvec = {
	.sv_size	= LINUX_SYS_MAXSYSCALL, .sv_table	= linux_sysent, .sv_mask	= 0, .sv_errsize	= ELAST + 1, .sv_errtbl	= bsd_to_linux_errno, .sv_transtrap	= translate_traps, .sv_fixup	= elf_linux_fixup, .sv_sendsig	= linux_rt_sendsig, .sv_sigcode	= &_binary_linux_locore_o_start, .sv_szsigcode	= &linux_szsigcode, .sv_name	= "Linux ELF64", .sv_coredump	= elf64_coredump, .sv_imgact_try	= exec_linux_imgact_try, .sv_minsigstksz	= LINUX_MINSIGSTKSZ, .sv_pagesize	= PAGE_SIZE, .sv_minuser	= VM_MIN_ADDRESS, .sv_maxuser	= VM_MAXUSER_ADDRESS, .sv_usrstack	= USRSTACK, .sv_psstrings	= PS_STRINGS, .sv_stackprot	= VM_PROT_ALL, .sv_copyout_strings = linux_copyout_strings, .sv_setregs	= linux_exec_setregs, .sv_fixlimit	= NULL, .sv_maxssiz	= NULL, .sv_flags	= SV_ABI_LINUX | SV_LP64 | SV_SHP, .sv_set_syscall_retval = linux_set_syscall_retval, .sv_fetch_syscall_args = linux_fetch_syscall_args, .sv_syscallnames = NULL, .sv_shared_page_base = SHAREDPAGE, .sv_shared_page_len = PAGE_SIZE, .sv_schedtail	= linux_schedtail, .sv_thread_detach = linux_thread_detach, .sv_trap	= linux_vsyscall, };

































static void linux_vdso_install(void *param)
{

	linux_szsigcode = (&_binary_linux_locore_o_end -  &_binary_linux_locore_o_start);

	if (linux_szsigcode > elf_linux_sysvec.sv_shared_page_len)
		panic("Linux invalid vdso size\n");

	__elfN(linux_vdso_fixup)(&elf_linux_sysvec);

	linux_shared_page_obj = __elfN(linux_shared_page_init)
	    (&linux_shared_page_mapping);

	__elfN(linux_vdso_reloc)(&elf_linux_sysvec, SHAREDPAGE);

	bcopy(elf_linux_sysvec.sv_sigcode, linux_shared_page_mapping, linux_szsigcode);
	elf_linux_sysvec.sv_shared_page_obj = linux_shared_page_obj;

	linux_kplatform = linux_shared_page_mapping + (linux_platform - (caddr_t)SHAREDPAGE);
}
SYSINIT(elf_linux_vdso_init, SI_SUB_EXEC, SI_ORDER_ANY, (sysinit_cfunc_t)linux_vdso_install, NULL);

static void linux_vdso_deinstall(void *param)
{

	__elfN(linux_shared_page_fini)(linux_shared_page_obj);
};
SYSUNINIT(elf_linux_vdso_uninit, SI_SUB_EXEC, SI_ORDER_FIRST, (sysinit_cfunc_t)linux_vdso_deinstall, NULL);

static char GNULINUX_ABI_VENDOR[] = "GNU";
static int GNULINUX_ABI_DESC = 0;

static boolean_t linux_trans_osrel(const Elf_Note *note, int32_t *osrel)
{
	const Elf32_Word *desc;
	uintptr_t p;

	p = (uintptr_t)(note + 1);
	p += roundup2(note->n_namesz, sizeof(Elf32_Addr));

	desc = (const Elf32_Word *)p;
	if (desc[0] != GNULINUX_ABI_DESC)
		return (FALSE);

	
	*osrel = desc[1] * 1000000 + desc[2] * 1000 + desc[3];

	return (TRUE);
}

static Elf_Brandnote linux64_brandnote = {
	.hdr.n_namesz	= sizeof(GNULINUX_ABI_VENDOR), .hdr.n_descsz	= 16, .hdr.n_type	= 1, .vendor		= GNULINUX_ABI_VENDOR, .flags		= BN_TRANSLATE_OSREL, .trans_osrel	= linux_trans_osrel };






static Elf64_Brandinfo linux_glibc2brand = {
	.brand		= ELFOSABI_LINUX, .machine	= EM_X86_64, .compat_3_brand	= "Linux", .emul_path	= "/compat/linux", .interp_path	= "/lib64/ld-linux-x86-64.so.2", .sysvec		= &elf_linux_sysvec, .interp_newpath	= NULL, .brand_note	= &linux64_brandnote, .flags		= BI_CAN_EXEC_DYN | BI_BRAND_NOTE };









static Elf64_Brandinfo linux_glibc2brandshort = {
	.brand		= ELFOSABI_LINUX, .machine	= EM_X86_64, .compat_3_brand	= "Linux", .emul_path	= "/compat/linux", .interp_path	= "/lib64/ld-linux.so.2", .sysvec		= &elf_linux_sysvec, .interp_newpath	= NULL, .brand_note	= &linux64_brandnote, .flags		= BI_CAN_EXEC_DYN | BI_BRAND_NOTE };









Elf64_Brandinfo *linux_brandlist[] = {
	&linux_glibc2brand, &linux_glibc2brandshort, NULL };



static int linux64_elf_modevent(module_t mod, int type, void *data)
{
	Elf64_Brandinfo **brandinfo;
	int error;
	struct linux_ioctl_handler **lihp;

	error = 0;

	switch(type) {
	case MOD_LOAD:
		for (brandinfo = &linux_brandlist[0]; *brandinfo != NULL;
		     ++brandinfo)
			if (elf64_insert_brand_entry(*brandinfo) < 0)
				error = EINVAL;
		if (error == 0) {
			SET_FOREACH(lihp, linux_ioctl_handler_set)
				linux_ioctl_register_handler(*lihp);
			LIST_INIT(&futex_list);
			mtx_init(&futex_mtx, "ftllk64", NULL, MTX_DEF);
			stclohz = (stathz ? stathz : hz);
			if (bootverbose)
				printf("Linux x86-64 ELF exec handler installed\n");
		} else printf("cannot insert Linux x86-64 ELF brand handler\n");
		break;
	case MOD_UNLOAD:
		for (brandinfo = &linux_brandlist[0]; *brandinfo != NULL;
		     ++brandinfo)
			if (elf64_brand_inuse(*brandinfo))
				error = EBUSY;
		if (error == 0) {
			for (brandinfo = &linux_brandlist[0];
			     *brandinfo != NULL; ++brandinfo)
				if (elf64_remove_brand_entry(*brandinfo) < 0)
					error = EINVAL;
		}
		if (error == 0) {
			SET_FOREACH(lihp, linux_ioctl_handler_set)
				linux_ioctl_unregister_handler(*lihp);
			mtx_destroy(&futex_mtx);
			if (bootverbose)
				printf("Linux ELF exec handler removed\n");
		} else printf("Could not deinstall ELF interpreter entry\n");
		break;
	default:
		return (EOPNOTSUPP);
	}
	return (error);
}

static moduledata_t linux64_elf_mod = {
	"linux64elf", linux64_elf_modevent, 0 };



DECLARE_MODULE_TIED(linux64elf, linux64_elf_mod, SI_SUB_EXEC, SI_ORDER_ANY);
MODULE_DEPEND(linux64elf, linux_common, 1, 1, 1);
