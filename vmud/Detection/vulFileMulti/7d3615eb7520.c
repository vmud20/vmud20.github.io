


__FBSDID("$FreeBSD$");





















































MODULE_VERSION(linux, 1);
















const char *linux_kplatform;
static int linux_szsigcode;
static vm_object_t linux_shared_page_obj;
static char *linux_shared_page_mapping;
extern char _binary_linux32_locore_o_start;
extern char _binary_linux32_locore_o_end;

extern struct sysent linux32_sysent[LINUX32_SYS_MAXSYSCALL];

SET_DECLARE(linux_ioctl_handler_set, struct linux_ioctl_handler);

static int	elf_linux_fixup(register_t **stack_base, struct image_params *iparams);
static register_t *linux_copyout_strings(struct image_params *imgp);
static void     linux_sendsig(sig_t catcher, ksiginfo_t *ksi, sigset_t *mask);
static void	exec_linux_setregs(struct thread *td,  struct image_params *imgp, u_long stack);
static void	linux32_fixlimit(struct rlimit *rl, int which);
static boolean_t linux32_trans_osrel(const Elf_Note *note, int32_t *osrel);
static void	linux_vdso_install(void *param);
static void	linux_vdso_deinstall(void *param);


static int bsd_to_linux_errno[ELAST + 1] = {
	-0,  -1,  -2,  -3,  -4,  -5,  -6,  -7,  -8,  -9, -10, -35, -12, -13, -14, -15, -16, -17, -18, -19, -20, -21, -22, -23, -24, -25, -26, -27, -28, -29, -30, -31, -32, -33, -34, -11,-115,-114, -88, -89, -90, -91, -92, -93, -94, -95, -96, -97, -98, -99, -100,-101,-102,-103,-104,-105,-106,-107,-108,-109, -110,-111, -40, -36,-112,-113, -39, -11, -87,-122, -116, -66,  -6,  -6,  -6,  -6,  -6, -37, -38,  -9, -6,  -6, -43, -42, -75,-125, -84, -95, -16, -74, -72, -67, -71 };











static int _bsd_to_linux_trapcode[] = {
	LINUX_T_UNKNOWN,	 6, LINUX_T_UNKNOWN, 3, LINUX_T_UNKNOWN, LINUX_T_UNKNOWN, 16, 254, LINUX_T_UNKNOWN, 13, 1, LINUX_T_UNKNOWN, 14, LINUX_T_UNKNOWN, 17, LINUX_T_UNKNOWN, LINUX_T_UNKNOWN, LINUX_T_UNKNOWN, 0, 2, 4, 5, 7, 8, 9, 10, 11, 12, 18, 19, 15 };


































struct linux32_ps_strings {
	u_int32_t ps_argvstr;	
	u_int ps_nargvstr;	
	u_int32_t ps_envstr;	
	u_int ps_nenvstr;	
};

LINUX_VDSO_SYM_INTPTR(linux32_sigcode);
LINUX_VDSO_SYM_INTPTR(linux32_rt_sigcode);
LINUX_VDSO_SYM_INTPTR(linux32_vsyscall);
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

static int elf_linux_fixup(register_t **stack_base, struct image_params *imgp)
{
	Elf32_Auxargs *args;
	Elf32_Addr *base;
	Elf32_Addr *pos;
	struct linux32_ps_strings *arginfo;

	arginfo = (struct linux32_ps_strings *)LINUX32_PS_STRINGS;

	KASSERT(curthread->td_proc == imgp->proc, ("unsafe elf_linux_fixup(), should be curproc"));
	base = (Elf32_Addr *)*stack_base;
	args = (Elf32_Auxargs *)imgp->auxargs;
	pos = base + (imgp->args->argc + imgp->args->envc + 2);

	AUXARGS_ENTRY_32(pos, LINUX_AT_SYSINFO_EHDR, imgp->proc->p_sysent->sv_shared_page_base);
	AUXARGS_ENTRY_32(pos, LINUX_AT_SYSINFO, linux32_vsyscall);
	AUXARGS_ENTRY_32(pos, LINUX_AT_HWCAP, cpu_feature);

	
	if (linux_kernver(curthread) >= LINUX_KERNVER_2004000)
		AUXARGS_ENTRY_32(pos, LINUX_AT_CLKTCK, stclohz);
	AUXARGS_ENTRY_32(pos, AT_PHDR, args->phdr);
	AUXARGS_ENTRY_32(pos, AT_PHENT, args->phent);
	AUXARGS_ENTRY_32(pos, AT_PHNUM, args->phnum);
	AUXARGS_ENTRY_32(pos, AT_PAGESZ, args->pagesz);
	AUXARGS_ENTRY_32(pos, AT_FLAGS, args->flags);
	AUXARGS_ENTRY_32(pos, AT_ENTRY, args->entry);
	AUXARGS_ENTRY_32(pos, AT_BASE, args->base);
	AUXARGS_ENTRY_32(pos, LINUX_AT_SECURE, 0);
	AUXARGS_ENTRY_32(pos, AT_UID, imgp->proc->p_ucred->cr_ruid);
	AUXARGS_ENTRY_32(pos, AT_EUID, imgp->proc->p_ucred->cr_svuid);
	AUXARGS_ENTRY_32(pos, AT_GID, imgp->proc->p_ucred->cr_rgid);
	AUXARGS_ENTRY_32(pos, AT_EGID, imgp->proc->p_ucred->cr_svgid);
	AUXARGS_ENTRY_32(pos, LINUX_AT_PLATFORM, PTROUT(linux_platform));
	AUXARGS_ENTRY(pos, LINUX_AT_RANDOM, PTROUT(imgp->canary));
	if (imgp->execpathp != 0)
		AUXARGS_ENTRY(pos, LINUX_AT_EXECFN, PTROUT(imgp->execpathp));
	if (args->execfd != -1)
		AUXARGS_ENTRY_32(pos, AT_EXECFD, args->execfd);
	AUXARGS_ENTRY_32(pos, AT_NULL, 0);

	free(imgp->auxargs, M_TEMP);
	imgp->auxargs = NULL;

	base--;
	suword32(base, (uint32_t)imgp->args->argc);
	*stack_base = (register_t *)base;
	return (0);
}

static void linux_rt_sendsig(sig_t catcher, ksiginfo_t *ksi, sigset_t *mask)
{
	struct thread *td = curthread;
	struct proc *p = td->td_proc;
	struct sigacts *psp;
	struct trapframe *regs;
	struct l_rt_sigframe *fp, frame;
	int oonstack;
	int sig;
	int code;
	
	sig = ksi->ksi_signo;
	code = ksi->ksi_code;
	PROC_LOCK_ASSERT(p, MA_OWNED);
	psp = p->p_sigacts;
	mtx_assert(&psp->ps_mtx, MA_OWNED);
	regs = td->td_frame;
	oonstack = sigonstack(regs->tf_rsp);


	if (ldebug(rt_sendsig))
		printf(ARGS(rt_sendsig, "%p, %d, %p, %u"), catcher, sig, (void*)mask, code);

	
	if ((td->td_pflags & TDP_ALTSTACK) && !oonstack && SIGISMEMBER(psp->ps_sigonstack, sig)) {
		fp = (struct l_rt_sigframe *)(td->td_sigstk.ss_sp + td->td_sigstk.ss_size - sizeof(struct l_rt_sigframe));
	} else fp = (struct l_rt_sigframe *)regs->tf_rsp - 1;
	mtx_unlock(&psp->ps_mtx);

	
	sig = bsd_to_linux_signal(sig);

	bzero(&frame, sizeof(frame));

	frame.sf_handler = PTROUT(catcher);
	frame.sf_sig = sig;
	frame.sf_siginfo = PTROUT(&fp->sf_si);
	frame.sf_ucontext = PTROUT(&fp->sf_sc);

	
	ksiginfo_to_lsiginfo(ksi, &frame.sf_si, sig);

	
	frame.sf_sc.uc_flags = 0;		
	frame.sf_sc.uc_link = 0;		

	frame.sf_sc.uc_stack.ss_sp = PTROUT(td->td_sigstk.ss_sp);
	frame.sf_sc.uc_stack.ss_size = td->td_sigstk.ss_size;
	frame.sf_sc.uc_stack.ss_flags = (td->td_pflags & TDP_ALTSTACK)
	    ? ((oonstack) ? LINUX_SS_ONSTACK : 0) : LINUX_SS_DISABLE;
	PROC_UNLOCK(p);

	bsd_to_linux_sigset(mask, &frame.sf_sc.uc_sigmask);

	frame.sf_sc.uc_mcontext.sc_mask   = frame.sf_sc.uc_sigmask.__mask;
	frame.sf_sc.uc_mcontext.sc_edi    = regs->tf_rdi;
	frame.sf_sc.uc_mcontext.sc_esi    = regs->tf_rsi;
	frame.sf_sc.uc_mcontext.sc_ebp    = regs->tf_rbp;
	frame.sf_sc.uc_mcontext.sc_ebx    = regs->tf_rbx;
	frame.sf_sc.uc_mcontext.sc_esp    = regs->tf_rsp;
	frame.sf_sc.uc_mcontext.sc_edx    = regs->tf_rdx;
	frame.sf_sc.uc_mcontext.sc_ecx    = regs->tf_rcx;
	frame.sf_sc.uc_mcontext.sc_eax    = regs->tf_rax;
	frame.sf_sc.uc_mcontext.sc_eip    = regs->tf_rip;
	frame.sf_sc.uc_mcontext.sc_cs     = regs->tf_cs;
	frame.sf_sc.uc_mcontext.sc_gs     = regs->tf_gs;
	frame.sf_sc.uc_mcontext.sc_fs     = regs->tf_fs;
	frame.sf_sc.uc_mcontext.sc_es     = regs->tf_es;
	frame.sf_sc.uc_mcontext.sc_ds     = regs->tf_ds;
	frame.sf_sc.uc_mcontext.sc_eflags = regs->tf_rflags;
	frame.sf_sc.uc_mcontext.sc_esp_at_signal = regs->tf_rsp;
	frame.sf_sc.uc_mcontext.sc_ss     = regs->tf_ss;
	frame.sf_sc.uc_mcontext.sc_err    = regs->tf_err;
	frame.sf_sc.uc_mcontext.sc_cr2    = (u_int32_t)(uintptr_t)ksi->ksi_addr;
	frame.sf_sc.uc_mcontext.sc_trapno = bsd_to_linux_trapcode(code);


	if (ldebug(rt_sendsig))
		printf(LMSG("rt_sendsig flags: 0x%x, sp: %p, ss: 0x%lx, mask: 0x%x"), frame.sf_sc.uc_stack.ss_flags, td->td_sigstk.ss_sp, td->td_sigstk.ss_size, frame.sf_sc.uc_mcontext.sc_mask);



	if (copyout(&frame, fp, sizeof(frame)) != 0) {
		

		if (ldebug(rt_sendsig))
			printf(LMSG("rt_sendsig: bad stack %p, oonstack=%x"), fp, oonstack);

		PROC_LOCK(p);
		sigexit(td, SIGILL);
	}

	
	regs->tf_rsp = PTROUT(fp);
	regs->tf_rip = linux32_rt_sigcode;
	regs->tf_rflags &= ~(PSL_T | PSL_D);
	regs->tf_cs = _ucode32sel;
	regs->tf_ss = _udatasel;
	regs->tf_ds = _udatasel;
	regs->tf_es = _udatasel;
	regs->tf_fs = _ufssel;
	regs->tf_gs = _ugssel;
	regs->tf_flags = TF_HASSEGS;
	set_pcb_flags(td->td_pcb, PCB_FULL_IRET);
	PROC_LOCK(p);
	mtx_lock(&psp->ps_mtx);
}



static void linux_sendsig(sig_t catcher, ksiginfo_t *ksi, sigset_t *mask)
{
	struct thread *td = curthread;
	struct proc *p = td->td_proc;
	struct sigacts *psp;
	struct trapframe *regs;
	struct l_sigframe *fp, frame;
	l_sigset_t lmask;
	int oonstack;
	int sig, code;

	sig = ksi->ksi_signo;
	code = ksi->ksi_code;
	PROC_LOCK_ASSERT(p, MA_OWNED);
	psp = p->p_sigacts;
	mtx_assert(&psp->ps_mtx, MA_OWNED);
	if (SIGISMEMBER(psp->ps_siginfo, sig)) {
		
		linux_rt_sendsig(catcher, ksi, mask);
		return;
	}

	regs = td->td_frame;
	oonstack = sigonstack(regs->tf_rsp);


	if (ldebug(sendsig))
		printf(ARGS(sendsig, "%p, %d, %p, %u"), catcher, sig, (void*)mask, code);


	
	if ((td->td_pflags & TDP_ALTSTACK) && !oonstack && SIGISMEMBER(psp->ps_sigonstack, sig)) {
		fp = (struct l_sigframe *)(td->td_sigstk.ss_sp + td->td_sigstk.ss_size - sizeof(struct l_sigframe));
	} else fp = (struct l_sigframe *)regs->tf_rsp - 1;
	mtx_unlock(&psp->ps_mtx);
	PROC_UNLOCK(p);

	
	sig = bsd_to_linux_signal(sig);

	bzero(&frame, sizeof(frame));

	frame.sf_handler = PTROUT(catcher);
	frame.sf_sig = sig;

	bsd_to_linux_sigset(mask, &lmask);

	
	frame.sf_sc.sc_mask   = lmask.__mask;
	frame.sf_sc.sc_gs     = regs->tf_gs;
	frame.sf_sc.sc_fs     = regs->tf_fs;
	frame.sf_sc.sc_es     = regs->tf_es;
	frame.sf_sc.sc_ds     = regs->tf_ds;
	frame.sf_sc.sc_edi    = regs->tf_rdi;
	frame.sf_sc.sc_esi    = regs->tf_rsi;
	frame.sf_sc.sc_ebp    = regs->tf_rbp;
	frame.sf_sc.sc_ebx    = regs->tf_rbx;
	frame.sf_sc.sc_esp    = regs->tf_rsp;
	frame.sf_sc.sc_edx    = regs->tf_rdx;
	frame.sf_sc.sc_ecx    = regs->tf_rcx;
	frame.sf_sc.sc_eax    = regs->tf_rax;
	frame.sf_sc.sc_eip    = regs->tf_rip;
	frame.sf_sc.sc_cs     = regs->tf_cs;
	frame.sf_sc.sc_eflags = regs->tf_rflags;
	frame.sf_sc.sc_esp_at_signal = regs->tf_rsp;
	frame.sf_sc.sc_ss     = regs->tf_ss;
	frame.sf_sc.sc_err    = regs->tf_err;
	frame.sf_sc.sc_cr2    = (u_int32_t)(uintptr_t)ksi->ksi_addr;
	frame.sf_sc.sc_trapno = bsd_to_linux_trapcode(code);

	frame.sf_extramask[0] = lmask.__mask;

	if (copyout(&frame, fp, sizeof(frame)) != 0) {
		
		PROC_LOCK(p);
		sigexit(td, SIGILL);
	}

	
	regs->tf_rsp = PTROUT(fp);
	regs->tf_rip = linux32_sigcode;
	regs->tf_rflags &= ~(PSL_T | PSL_D);
	regs->tf_cs = _ucode32sel;
	regs->tf_ss = _udatasel;
	regs->tf_ds = _udatasel;
	regs->tf_es = _udatasel;
	regs->tf_fs = _ufssel;
	regs->tf_gs = _ugssel;
	regs->tf_flags = TF_HASSEGS;
	set_pcb_flags(td->td_pcb, PCB_FULL_IRET);
	PROC_LOCK(p);
	mtx_lock(&psp->ps_mtx);
}


int linux_sigreturn(struct thread *td, struct linux_sigreturn_args *args)
{
	struct l_sigframe frame;
	struct trapframe *regs;
	sigset_t bmask;
	l_sigset_t lmask;
	int eflags;
	ksiginfo_t ksi;

	regs = td->td_frame;


	if (ldebug(sigreturn))
		printf(ARGS(sigreturn, "%p"), (void *)args->sfp);

	
	if (copyin(args->sfp, &frame, sizeof(frame)) != 0)
		return (EFAULT);

	

	eflags = frame.sf_sc.sc_eflags;
	if (!EFLAGS_SECURE(eflags, regs->tf_rflags))
		return(EINVAL);

	

	if (!CS_SECURE(frame.sf_sc.sc_cs)) {
		ksiginfo_init_trap(&ksi);
		ksi.ksi_signo = SIGBUS;
		ksi.ksi_code = BUS_OBJERR;
		ksi.ksi_trapno = T_PROTFLT;
		ksi.ksi_addr = (void *)regs->tf_rip;
		trapsignal(td, &ksi);
		return(EINVAL);
	}

	lmask.__mask = frame.sf_sc.sc_mask;
	lmask.__mask = frame.sf_extramask[0];
	linux_to_bsd_sigset(&lmask, &bmask);
	kern_sigprocmask(td, SIG_SETMASK, &bmask, NULL, 0);

	
	regs->tf_rdi    = frame.sf_sc.sc_edi;
	regs->tf_rsi    = frame.sf_sc.sc_esi;
	regs->tf_rbp    = frame.sf_sc.sc_ebp;
	regs->tf_rbx    = frame.sf_sc.sc_ebx;
	regs->tf_rdx    = frame.sf_sc.sc_edx;
	regs->tf_rcx    = frame.sf_sc.sc_ecx;
	regs->tf_rax    = frame.sf_sc.sc_eax;
	regs->tf_rip    = frame.sf_sc.sc_eip;
	regs->tf_cs     = frame.sf_sc.sc_cs;
	regs->tf_ds     = frame.sf_sc.sc_ds;
	regs->tf_es     = frame.sf_sc.sc_es;
	regs->tf_fs     = frame.sf_sc.sc_fs;
	regs->tf_gs     = frame.sf_sc.sc_gs;
	regs->tf_rflags = eflags;
	regs->tf_rsp    = frame.sf_sc.sc_esp_at_signal;
	regs->tf_ss     = frame.sf_sc.sc_ss;
	set_pcb_flags(td->td_pcb, PCB_FULL_IRET);

	return (EJUSTRETURN);
}


int linux_rt_sigreturn(struct thread *td, struct linux_rt_sigreturn_args *args)
{
	struct l_ucontext uc;
	struct l_sigcontext *context;
	sigset_t bmask;
	l_stack_t *lss;
	stack_t ss;
	struct trapframe *regs;
	int eflags;
	ksiginfo_t ksi;

	regs = td->td_frame;


	if (ldebug(rt_sigreturn))
		printf(ARGS(rt_sigreturn, "%p"), (void *)args->ucp);

	
	if (copyin(args->ucp, &uc, sizeof(uc)) != 0)
		return (EFAULT);

	context = &uc.uc_mcontext;

	

	eflags = context->sc_eflags;
	if (!EFLAGS_SECURE(eflags, regs->tf_rflags))
		return(EINVAL);

	

	if (!CS_SECURE(context->sc_cs)) {
		ksiginfo_init_trap(&ksi);
		ksi.ksi_signo = SIGBUS;
		ksi.ksi_code = BUS_OBJERR;
		ksi.ksi_trapno = T_PROTFLT;
		ksi.ksi_addr = (void *)regs->tf_rip;
		trapsignal(td, &ksi);
		return(EINVAL);
	}

	linux_to_bsd_sigset(&uc.uc_sigmask, &bmask);
	kern_sigprocmask(td, SIG_SETMASK, &bmask, NULL, 0);

	
	regs->tf_gs	= context->sc_gs;
	regs->tf_fs	= context->sc_fs;
	regs->tf_es	= context->sc_es;
	regs->tf_ds	= context->sc_ds;
	regs->tf_rdi    = context->sc_edi;
	regs->tf_rsi    = context->sc_esi;
	regs->tf_rbp    = context->sc_ebp;
	regs->tf_rbx    = context->sc_ebx;
	regs->tf_rdx    = context->sc_edx;
	regs->tf_rcx    = context->sc_ecx;
	regs->tf_rax    = context->sc_eax;
	regs->tf_rip    = context->sc_eip;
	regs->tf_cs     = context->sc_cs;
	regs->tf_rflags = eflags;
	regs->tf_rsp    = context->sc_esp_at_signal;
	regs->tf_ss     = context->sc_ss;
	set_pcb_flags(td->td_pcb, PCB_FULL_IRET);

	
	lss = &uc.uc_stack;
	ss.ss_sp = PTRIN(lss->ss_sp);
	ss.ss_size = lss->ss_size;
	ss.ss_flags = linux_to_bsd_sigaltstack(lss->ss_flags);


	if (ldebug(rt_sigreturn))
		printf(LMSG("rt_sigret flags: 0x%x, sp: %p, ss: 0x%lx, mask: 0x%x"), ss.ss_flags, ss.ss_sp, ss.ss_size, context->sc_mask);

	(void)kern_sigaltstack(td, &ss, NULL);

	return (EJUSTRETURN);
}

static int linux32_fetch_syscall_args(struct thread *td, struct syscall_args *sa)
{
	struct proc *p;
	struct trapframe *frame;

	p = td->td_proc;
	frame = td->td_frame;

	sa->args[0] = frame->tf_rbx;
	sa->args[1] = frame->tf_rcx;
	sa->args[2] = frame->tf_rdx;
	sa->args[3] = frame->tf_rsi;
	sa->args[4] = frame->tf_rdi;
	sa->args[5] = frame->tf_rbp;	
	sa->code = frame->tf_rax;

	if (sa->code >= p->p_sysent->sv_size)
		
		sa->callp = &p->p_sysent->sv_table[p->p_sysent->sv_size - 1];
	else sa->callp = &p->p_sysent->sv_table[sa->code];
	sa->narg = sa->callp->sy_narg;

	td->td_retval[0] = 0;
	td->td_retval[1] = frame->tf_rdx;

	return (0);
}


static int	exec_linux_imgact_try(struct image_params *iparams);

static int exec_linux_imgact_try(struct image_params *imgp)
{
	const char *head = (const char *)imgp->image_header;
	char *rpath;
	int error = -1;

	
	if (((const short *)head)[0] == SHELLMAGIC) {
		
		if ((error = exec_shell_imgact(imgp)) == 0) {
			linux_emul_convpath(FIRST_THREAD_IN_PROC(imgp->proc), imgp->interpreter_name, UIO_SYSSPACE, &rpath, 0, AT_FDCWD);

			if (rpath != NULL)
				imgp->args->fname_buf = imgp->interpreter_name = rpath;
		}
	}
	return (error);
}


static void exec_linux_setregs(struct thread *td, struct image_params *imgp, u_long stack)
{
	struct trapframe *regs = td->td_frame;
	struct pcb *pcb = td->td_pcb;

	mtx_lock(&dt_lock);
	if (td->td_proc->p_md.md_ldt != NULL)
		user_ldt_free(td);
	else mtx_unlock(&dt_lock);

	critical_enter();
	wrmsr(MSR_FSBASE, 0);
	wrmsr(MSR_KGSBASE, 0);	
	pcb->pcb_fsbase = 0;
	pcb->pcb_gsbase = 0;
	critical_exit();
	pcb->pcb_initial_fpucw = __LINUX_NPXCW__;

	bzero((char *)regs, sizeof(struct trapframe));
	regs->tf_rip = imgp->entry_addr;
	regs->tf_rsp = stack;
	regs->tf_rflags = PSL_USER | (regs->tf_rflags & PSL_T);
	regs->tf_gs = _ugssel;
	regs->tf_fs = _ufssel;
	regs->tf_es = _udatasel;
	regs->tf_ds = _udatasel;
	regs->tf_ss = _udatasel;
	regs->tf_flags = TF_HASSEGS;
	regs->tf_cs = _ucode32sel;
	regs->tf_rbx = imgp->ps_strings;

	fpstate_drop(td);

	
	set_pcb_flags(pcb, PCB_32BIT | PCB_FULL_IRET);
	td->td_retval[1] = 0;
}


static register_t * linux_copyout_strings(struct image_params *imgp)
{
	int argc, envc;
	u_int32_t *vectp;
	char *stringp, *destp;
	u_int32_t *stack_base;
	struct linux32_ps_strings *arginfo;
	char canary[LINUX_AT_RANDOM_LEN];
	size_t execpath_len;

	
	if (imgp->execpath != NULL && imgp->auxargs != NULL)
		execpath_len = strlen(imgp->execpath) + 1;
	else execpath_len = 0;

	arginfo = (struct linux32_ps_strings *)LINUX32_PS_STRINGS;
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
		
		vectp = (u_int32_t *) (destp - (imgp->args->argc + imgp->args->envc + 2 + imgp->auxarg_size) * sizeof(u_int32_t));


	} else  vectp = (u_int32_t *)(destp - (imgp->args->argc + imgp->args->envc + 2) * sizeof(u_int32_t));



	
	stack_base = vectp;

	stringp = imgp->args->begin_argv;
	argc = imgp->args->argc;
	envc = imgp->args->envc;
	
	copyout(stringp, destp, ARG_MAX - imgp->args->stringspace);

	
	suword32(&arginfo->ps_argvstr, (uint32_t)(intptr_t)vectp);
	suword32(&arginfo->ps_nargvstr, argc);

	
	for (; argc > 0; --argc) {
		suword32(vectp++, (uint32_t)(intptr_t)destp);
		while (*stringp++ != 0)
			destp++;
		destp++;
	}

	
	suword32(vectp++, 0);

	suword32(&arginfo->ps_envstr, (uint32_t)(intptr_t)vectp);
	suword32(&arginfo->ps_nenvstr, envc);

	
	for (; envc > 0; --envc) {
		suword32(vectp++, (uint32_t)(intptr_t)destp);
		while (*stringp++ != 0)
			destp++;
		destp++;
	}

	
	suword32(vectp, 0);

	return ((register_t *)stack_base);
}

static SYSCTL_NODE(_compat, OID_AUTO, linux32, CTLFLAG_RW, 0, "32-bit Linux emulation");

static u_long	linux32_maxdsiz = LINUX32_MAXDSIZ;
SYSCTL_ULONG(_compat_linux32, OID_AUTO, maxdsiz, CTLFLAG_RW, &linux32_maxdsiz, 0, "");
static u_long	linux32_maxssiz = LINUX32_MAXSSIZ;
SYSCTL_ULONG(_compat_linux32, OID_AUTO, maxssiz, CTLFLAG_RW, &linux32_maxssiz, 0, "");
static u_long	linux32_maxvmem = LINUX32_MAXVMEM;
SYSCTL_ULONG(_compat_linux32, OID_AUTO, maxvmem, CTLFLAG_RW, &linux32_maxvmem, 0, "");


SYSCTL_PROC(_compat_linux32, OID_AUTO, debug, CTLTYPE_STRING | CTLFLAG_RW, 0, 0, linux_sysctl_debug, "A", "Linux debugging control");




static void linux32_fixlimit(struct rlimit *rl, int which)
{

	switch (which) {
	case RLIMIT_DATA:
		if (linux32_maxdsiz != 0) {
			if (rl->rlim_cur > linux32_maxdsiz)
				rl->rlim_cur = linux32_maxdsiz;
			if (rl->rlim_max > linux32_maxdsiz)
				rl->rlim_max = linux32_maxdsiz;
		}
		break;
	case RLIMIT_STACK:
		if (linux32_maxssiz != 0) {
			if (rl->rlim_cur > linux32_maxssiz)
				rl->rlim_cur = linux32_maxssiz;
			if (rl->rlim_max > linux32_maxssiz)
				rl->rlim_max = linux32_maxssiz;
		}
		break;
	case RLIMIT_VMEM:
		if (linux32_maxvmem != 0) {
			if (rl->rlim_cur > linux32_maxvmem)
				rl->rlim_cur = linux32_maxvmem;
			if (rl->rlim_max > linux32_maxvmem)
				rl->rlim_max = linux32_maxvmem;
		}
		break;
	}
}

struct sysentvec elf_linux_sysvec = {
	.sv_size	= LINUX32_SYS_MAXSYSCALL, .sv_table	= linux32_sysent, .sv_mask	= 0, .sv_errsize	= ELAST + 1, .sv_errtbl	= bsd_to_linux_errno, .sv_transtrap	= translate_traps, .sv_fixup	= elf_linux_fixup, .sv_sendsig	= linux_sendsig, .sv_sigcode	= &_binary_linux32_locore_o_start, .sv_szsigcode	= &linux_szsigcode, .sv_name	= "Linux ELF32", .sv_coredump	= elf32_coredump, .sv_imgact_try	= exec_linux_imgact_try, .sv_minsigstksz	= LINUX_MINSIGSTKSZ, .sv_pagesize	= PAGE_SIZE, .sv_minuser	= VM_MIN_ADDRESS, .sv_maxuser	= LINUX32_MAXUSER, .sv_usrstack	= LINUX32_USRSTACK, .sv_psstrings	= LINUX32_PS_STRINGS, .sv_stackprot	= VM_PROT_ALL, .sv_copyout_strings = linux_copyout_strings, .sv_setregs	= exec_linux_setregs, .sv_fixlimit	= linux32_fixlimit, .sv_maxssiz	= &linux32_maxssiz, .sv_flags	= SV_ABI_LINUX | SV_ILP32 | SV_IA32 | SV_SHP, .sv_set_syscall_retval = cpu_set_syscall_retval, .sv_fetch_syscall_args = linux32_fetch_syscall_args, .sv_syscallnames = NULL, .sv_shared_page_base = LINUX32_SHAREDPAGE, .sv_shared_page_len = PAGE_SIZE, .sv_schedtail	= linux_schedtail, .sv_thread_detach = linux_thread_detach, .sv_trap	= NULL, };

































static void linux_vdso_install(void *param)
{

	linux_szsigcode = (&_binary_linux32_locore_o_end -  &_binary_linux32_locore_o_start);

	if (linux_szsigcode > elf_linux_sysvec.sv_shared_page_len)
		panic("Linux invalid vdso size\n");

	__elfN(linux_vdso_fixup)(&elf_linux_sysvec);

	linux_shared_page_obj = __elfN(linux_shared_page_init)
	    (&linux_shared_page_mapping);

	__elfN(linux_vdso_reloc)(&elf_linux_sysvec, LINUX32_SHAREDPAGE);

	bcopy(elf_linux_sysvec.sv_sigcode, linux_shared_page_mapping, linux_szsigcode);
	elf_linux_sysvec.sv_shared_page_obj = linux_shared_page_obj;

	linux_kplatform = linux_shared_page_mapping + (linux_platform - (caddr_t)LINUX32_SHAREDPAGE);
}
SYSINIT(elf_linux_vdso_init, SI_SUB_EXEC, SI_ORDER_ANY, (sysinit_cfunc_t)linux_vdso_install, NULL);

static void linux_vdso_deinstall(void *param)
{

	__elfN(linux_shared_page_fini)(linux_shared_page_obj);
};
SYSUNINIT(elf_linux_vdso_uninit, SI_SUB_EXEC, SI_ORDER_FIRST, (sysinit_cfunc_t)linux_vdso_deinstall, NULL);

static char GNU_ABI_VENDOR[] = "GNU";
static int GNULINUX_ABI_DESC = 0;

static boolean_t linux32_trans_osrel(const Elf_Note *note, int32_t *osrel)
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

static Elf_Brandnote linux32_brandnote = {
	.hdr.n_namesz	= sizeof(GNU_ABI_VENDOR), .hdr.n_descsz	= 16, .hdr.n_type	= 1, .vendor		= GNU_ABI_VENDOR, .flags		= BN_TRANSLATE_OSREL, .trans_osrel	= linux32_trans_osrel };






static Elf32_Brandinfo linux_brand = {
	.brand		= ELFOSABI_LINUX, .machine	= EM_386, .compat_3_brand	= "Linux", .emul_path	= "/compat/linux", .interp_path	= "/lib/ld-linux.so.1", .sysvec		= &elf_linux_sysvec, .interp_newpath	= NULL, .brand_note	= &linux32_brandnote, .flags		= BI_CAN_EXEC_DYN | BI_BRAND_NOTE };









static Elf32_Brandinfo linux_glibc2brand = {
	.brand		= ELFOSABI_LINUX, .machine	= EM_386, .compat_3_brand	= "Linux", .emul_path	= "/compat/linux", .interp_path	= "/lib/ld-linux.so.2", .sysvec		= &elf_linux_sysvec, .interp_newpath	= NULL, .brand_note	= &linux32_brandnote, .flags		= BI_CAN_EXEC_DYN | BI_BRAND_NOTE };









Elf32_Brandinfo *linux_brandlist[] = {
	&linux_brand, &linux_glibc2brand, NULL };



static int linux_elf_modevent(module_t mod, int type, void *data)
{
	Elf32_Brandinfo **brandinfo;
	int error;
	struct linux_ioctl_handler **lihp;

	error = 0;

	switch(type) {
	case MOD_LOAD:
		for (brandinfo = &linux_brandlist[0]; *brandinfo != NULL;
		     ++brandinfo)
			if (elf32_insert_brand_entry(*brandinfo) < 0)
				error = EINVAL;
		if (error == 0) {
			SET_FOREACH(lihp, linux_ioctl_handler_set)
				linux_ioctl_register_handler(*lihp);
			LIST_INIT(&futex_list);
			mtx_init(&futex_mtx, "ftllk", NULL, MTX_DEF);
			stclohz = (stathz ? stathz : hz);
			if (bootverbose)
				printf("Linux ELF exec handler installed\n");
		} else printf("cannot insert Linux ELF brand handler\n");
		break;
	case MOD_UNLOAD:
		for (brandinfo = &linux_brandlist[0]; *brandinfo != NULL;
		     ++brandinfo)
			if (elf32_brand_inuse(*brandinfo))
				error = EBUSY;
		if (error == 0) {
			for (brandinfo = &linux_brandlist[0];
			     *brandinfo != NULL; ++brandinfo)
				if (elf32_remove_brand_entry(*brandinfo) < 0)
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

static moduledata_t linux_elf_mod = {
	"linuxelf", linux_elf_modevent, 0 };



DECLARE_MODULE_TIED(linuxelf, linux_elf_mod, SI_SUB_EXEC, SI_ORDER_ANY);
MODULE_DEPEND(linuxelf, linux_common, 1, 1, 1);
