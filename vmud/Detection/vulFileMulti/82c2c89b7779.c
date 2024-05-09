


__FBSDID("$FreeBSD$");











































































































CTASSERT(offsetof(struct pcpu, pc_curthread) == 0);

extern u_int64_t hammer_time(u_int64_t, u_int64_t);

extern void printcpuinfo(void);	
extern void identify_cpu(void);
extern void panicifcpuunsupported(void);




static void cpu_startup(void *);
static void get_fpcontext(struct thread *td, mcontext_t *mcp, char *xfpusave, size_t xfpusave_len);
static int  set_fpcontext(struct thread *td, const mcontext_t *mcp, char *xfpustate, size_t xfpustate_len);
SYSINIT(cpu, SI_SUB_CPU, SI_ORDER_FIRST, cpu_startup, NULL);


static caddr_t native_parse_preload_data(u_int64_t);


static void native_parse_memmap(caddr_t, vm_paddr_t *, int *);


struct init_ops init_ops = {
	.parse_preload_data =	native_parse_preload_data, .early_clock_source_init =	i8254_init, .early_delay =			i8254_delay, .parse_memmap =			native_parse_memmap,  .mp_bootaddress =		mp_bootaddress, .start_all_aps =		native_start_all_aps,  };









extern char kernphys[];

extern vm_offset_t ksym_start, ksym_end;


struct msgbuf *msgbufp;





int	_udatasel, _ucodesel, _ucode32sel, _ufssel, _ugssel;

int cold = 1;

long Maxmem = 0;
long realmem = 0;




vm_paddr_t phys_avail[PHYSMAP_SIZE + 2];
vm_paddr_t dump_avail[PHYSMAP_SIZE + 2];





struct kva_md_info kmi;

static struct trapframe proc0_tf;
struct region_descriptor r_gdt, r_idt;

struct pcpu __pcpu[MAXCPU];

struct mtx icu_lock;

struct mem_range_softc mem_range_softc;

struct mtx dt_lock;	

void (*vmm_resume_p)(void);

static void cpu_startup(dummy)
	void *dummy;
{
	uintmax_t memsize;
	char *sysenv;

	
	sysenv = getenv("smbios.system.product");
	if (sysenv != NULL) {
		if (strncmp(sysenv, "MacBook1,1", 10) == 0 || strncmp(sysenv, "MacBook3,1", 10) == 0 || strncmp(sysenv, "MacBookPro1,1", 13) == 0 || strncmp(sysenv, "MacBookPro1,2", 13) == 0 || strncmp(sysenv, "MacBookPro3,1", 13) == 0 || strncmp(sysenv, "Macmini1,1", 10) == 0) {




			if (bootverbose)
				printf("Disabling LEGACY_USB_EN bit on " "Intel ICH.\n");
			outl(ICH_SMI_EN, inl(ICH_SMI_EN) & ~0x8);
		}
		freeenv(sysenv);
	}

	
	startrtclock();
	printcpuinfo();
	panicifcpuunsupported();

	perfmon_init();


	
	memsize = 0;
	sysenv = getenv("smbios.memory.enabled");
	if (sysenv != NULL) {
		memsize = (uintmax_t)strtoul(sysenv, (char **)NULL, 10) << 10;
		freeenv(sysenv);
	}
	if (memsize < ptoa((uintmax_t)vm_cnt.v_free_count))
		memsize = ptoa((uintmax_t)Maxmem);
	printf("real memory  = %ju (%ju MB)\n", memsize, memsize >> 20);
	realmem = atop(memsize);

	
	if (bootverbose) {
		int indx;

		printf("Physical memory chunk(s):\n");
		for (indx = 0; phys_avail[indx + 1] != 0; indx += 2) {
			vm_paddr_t size;

			size = phys_avail[indx + 1] - phys_avail[indx];
			printf( "0x%016jx - 0x%016jx, %ju bytes (%ju pages)\n", (uintmax_t)phys_avail[indx], (uintmax_t)phys_avail[indx + 1] - 1, (uintmax_t)size, (uintmax_t)size / PAGE_SIZE);



		}
	}

	vm_ksubmap_init(&kmi);

	printf("avail memory = %ju (%ju MB)\n", ptoa((uintmax_t)vm_cnt.v_free_count), ptoa((uintmax_t)vm_cnt.v_free_count) / 1048576);


	
	bufinit();
	vm_pager_bufferinit();

	cpu_setregs();
}


void sendsig(sig_t catcher, ksiginfo_t *ksi, sigset_t *mask)
{
	struct sigframe sf, *sfp;
	struct pcb *pcb;
	struct proc *p;
	struct thread *td;
	struct sigacts *psp;
	char *sp;
	struct trapframe *regs;
	char *xfpusave;
	size_t xfpusave_len;
	int sig;
	int oonstack;

	td = curthread;
	pcb = td->td_pcb;
	p = td->td_proc;
	PROC_LOCK_ASSERT(p, MA_OWNED);
	sig = ksi->ksi_signo;
	psp = p->p_sigacts;
	mtx_assert(&psp->ps_mtx, MA_OWNED);
	regs = td->td_frame;
	oonstack = sigonstack(regs->tf_rsp);

	if (cpu_max_ext_state_size > sizeof(struct savefpu) && use_xsave) {
		xfpusave_len = cpu_max_ext_state_size - sizeof(struct savefpu);
		xfpusave = __builtin_alloca(xfpusave_len);
	} else {
		xfpusave_len = 0;
		xfpusave = NULL;
	}

	
	bzero(&sf, sizeof(sf));
	sf.sf_uc.uc_sigmask = *mask;
	sf.sf_uc.uc_stack = td->td_sigstk;
	sf.sf_uc.uc_stack.ss_flags = (td->td_pflags & TDP_ALTSTACK)
	    ? ((oonstack) ? SS_ONSTACK : 0) : SS_DISABLE;
	sf.sf_uc.uc_mcontext.mc_onstack = (oonstack) ? 1 : 0;
	bcopy(regs, &sf.sf_uc.uc_mcontext.mc_rdi, sizeof(*regs));
	sf.sf_uc.uc_mcontext.mc_len = sizeof(sf.sf_uc.uc_mcontext); 
	get_fpcontext(td, &sf.sf_uc.uc_mcontext, xfpusave, xfpusave_len);
	fpstate_drop(td);
	sf.sf_uc.uc_mcontext.mc_fsbase = pcb->pcb_fsbase;
	sf.sf_uc.uc_mcontext.mc_gsbase = pcb->pcb_gsbase;
	bzero(sf.sf_uc.uc_mcontext.mc_spare, sizeof(sf.sf_uc.uc_mcontext.mc_spare));
	bzero(sf.sf_uc.__spare__, sizeof(sf.sf_uc.__spare__));

	
	if ((td->td_pflags & TDP_ALTSTACK) != 0 && !oonstack && SIGISMEMBER(psp->ps_sigonstack, sig)) {
		sp = td->td_sigstk.ss_sp + td->td_sigstk.ss_size;

		td->td_sigstk.ss_flags |= SS_ONSTACK;

	} else sp = (char *)regs->tf_rsp - 128;
	if (xfpusave != NULL) {
		sp -= xfpusave_len;
		sp = (char *)((unsigned long)sp & ~0x3Ful);
		sf.sf_uc.uc_mcontext.mc_xfpustate = (register_t)sp;
	}
	sp -= sizeof(struct sigframe);
	
	sfp = (struct sigframe *)((unsigned long)sp & ~0xFul);

	
	if (p->p_sysent->sv_sigtbl && sig <= p->p_sysent->sv_sigsize)
		sig = p->p_sysent->sv_sigtbl[_SIG_IDX(sig)];

	
	regs->tf_rdi = sig;			
	regs->tf_rdx = (register_t)&sfp->sf_uc;	
	bzero(&sf.sf_si, sizeof(sf.sf_si));
	if (SIGISMEMBER(psp->ps_siginfo, sig)) {
		
		regs->tf_rsi = (register_t)&sfp->sf_si;	
		sf.sf_ahu.sf_action = (__siginfohandler_t *)catcher;

		
		sf.sf_si = ksi->ksi_info;
		sf.sf_si.si_signo = sig; 
		regs->tf_rcx = (register_t)ksi->ksi_addr; 
	} else {
		
		regs->tf_rsi = ksi->ksi_code;	
		regs->tf_rcx = (register_t)ksi->ksi_addr; 
		sf.sf_ahu.sf_handler = catcher;
	}
	mtx_unlock(&psp->ps_mtx);
	PROC_UNLOCK(p);

	
	if (copyout(&sf, sfp, sizeof(*sfp)) != 0 || (xfpusave != NULL && copyout(xfpusave, (void *)sf.sf_uc.uc_mcontext.mc_xfpustate, xfpusave_len)

	    != 0)) {

		printf("process %ld has trashed its stack\n", (long)p->p_pid);

		PROC_LOCK(p);
		sigexit(td, SIGILL);
	}

	regs->tf_rsp = (long)sfp;
	regs->tf_rip = p->p_sysent->sv_sigcode_base;
	regs->tf_rflags &= ~(PSL_T | PSL_D);
	regs->tf_cs = _ucodesel;
	regs->tf_ds = _udatasel;
	regs->tf_es = _udatasel;
	regs->tf_fs = _ufssel;
	regs->tf_gs = _ugssel;
	regs->tf_flags = TF_HASSEGS;
	set_pcb_flags(pcb, PCB_FULL_IRET);
	PROC_LOCK(p);
	mtx_lock(&psp->ps_mtx);
}


int sys_sigreturn(td, uap)
	struct thread *td;
	struct sigreturn_args  *uap;
{
	ucontext_t uc;
	struct pcb *pcb;
	struct proc *p;
	struct trapframe *regs;
	ucontext_t *ucp;
	char *xfpustate;
	size_t xfpustate_len;
	long rflags;
	int cs, error, ret;
	ksiginfo_t ksi;

	pcb = td->td_pcb;
	p = td->td_proc;

	error = copyin(uap->sigcntxp, &uc, sizeof(uc));
	if (error != 0) {
		uprintf("pid %d (%s): sigreturn copyin failed\n", p->p_pid, td->td_name);
		return (error);
	}
	ucp = &uc;
	if ((ucp->uc_mcontext.mc_flags & ~_MC_FLAG_MASK) != 0) {
		uprintf("pid %d (%s): sigreturn mc_flags %x\n", p->p_pid, td->td_name, ucp->uc_mcontext.mc_flags);
		return (EINVAL);
	}
	regs = td->td_frame;
	rflags = ucp->uc_mcontext.mc_rflags;
	
	if (!EFL_SECURE(rflags, regs->tf_rflags)) {
		uprintf("pid %d (%s): sigreturn rflags = 0x%lx\n", p->p_pid, td->td_name, rflags);
		return (EINVAL);
	}

	
	cs = ucp->uc_mcontext.mc_cs;
	if (!CS_SECURE(cs)) {
		uprintf("pid %d (%s): sigreturn cs = 0x%x\n", p->p_pid, td->td_name, cs);
		ksiginfo_init_trap(&ksi);
		ksi.ksi_signo = SIGBUS;
		ksi.ksi_code = BUS_OBJERR;
		ksi.ksi_trapno = T_PROTFLT;
		ksi.ksi_addr = (void *)regs->tf_rip;
		trapsignal(td, &ksi);
		return (EINVAL);
	}

	if ((uc.uc_mcontext.mc_flags & _MC_HASFPXSTATE) != 0) {
		xfpustate_len = uc.uc_mcontext.mc_xfpustate_len;
		if (xfpustate_len > cpu_max_ext_state_size - sizeof(struct savefpu)) {
			uprintf("pid %d (%s): sigreturn xfpusave_len = 0x%zx\n", p->p_pid, td->td_name, xfpustate_len);
			return (EINVAL);
		}
		xfpustate = __builtin_alloca(xfpustate_len);
		error = copyin((const void *)uc.uc_mcontext.mc_xfpustate, xfpustate, xfpustate_len);
		if (error != 0) {
			uprintf( "pid %d (%s): sigreturn copying xfpustate failed\n", p->p_pid, td->td_name);

			return (error);
		}
	} else {
		xfpustate = NULL;
		xfpustate_len = 0;
	}
	ret = set_fpcontext(td, &ucp->uc_mcontext, xfpustate, xfpustate_len);
	if (ret != 0) {
		uprintf("pid %d (%s): sigreturn set_fpcontext err %d\n", p->p_pid, td->td_name, ret);
		return (ret);
	}
	bcopy(&ucp->uc_mcontext.mc_rdi, regs, sizeof(*regs));
	pcb->pcb_fsbase = ucp->uc_mcontext.mc_fsbase;
	pcb->pcb_gsbase = ucp->uc_mcontext.mc_gsbase;


	if (ucp->uc_mcontext.mc_onstack & 1)
		td->td_sigstk.ss_flags |= SS_ONSTACK;
	else td->td_sigstk.ss_flags &= ~SS_ONSTACK;


	kern_sigprocmask(td, SIG_SETMASK, &ucp->uc_sigmask, NULL, 0);
	set_pcb_flags(pcb, PCB_FULL_IRET);
	return (EJUSTRETURN);
}


int freebsd4_sigreturn(struct thread *td, struct freebsd4_sigreturn_args *uap)
{
 
	return sys_sigreturn(td, (struct sigreturn_args *)uap);
}




void cpu_boot(int howto)
{
}


void cpu_flush_dcache(void *ptr, size_t len)
{
	
}


int cpu_est_clockrate(int cpu_id, uint64_t *rate)
{
	uint64_t tsc1, tsc2;
	uint64_t acnt, mcnt, perf;
	register_t reg;

	if (pcpu_find(cpu_id) == NULL || rate == NULL)
		return (EINVAL);

	
	if (tsc_is_invariant && !tsc_perf_stat)
		return (EOPNOTSUPP);


	if (smp_cpus > 1) {
		
		thread_lock(curthread);
		sched_bind(curthread, cpu_id);
		thread_unlock(curthread);
	}


	
	reg = intr_disable();
	if (tsc_is_invariant) {
		wrmsr(MSR_MPERF, 0);
		wrmsr(MSR_APERF, 0);
		tsc1 = rdtsc();
		DELAY(1000);
		mcnt = rdmsr(MSR_MPERF);
		acnt = rdmsr(MSR_APERF);
		tsc2 = rdtsc();
		intr_restore(reg);
		perf = 1000 * acnt / mcnt;
		*rate = (tsc2 - tsc1) * perf;
	} else {
		tsc1 = rdtsc();
		DELAY(1000);
		tsc2 = rdtsc();
		intr_restore(reg);
		*rate = (tsc2 - tsc1) * 1000;
	}


	if (smp_cpus > 1) {
		thread_lock(curthread);
		sched_unbind(curthread);
		thread_unlock(curthread);
	}


	return (0);
}


void cpu_halt(void)
{
	for (;;)
		halt();
}

void (*cpu_idle_hook)(sbintime_t) = NULL;	
static int	cpu_ident_amdc1e = 0;	
static int	idle_mwait = 1;		
SYSCTL_INT(_machdep, OID_AUTO, idle_mwait, CTLFLAG_RWTUN, &idle_mwait, 0, "Use MONITOR/MWAIT for short idle");





static void cpu_idle_acpi(sbintime_t sbt)
{
	int *state;

	state = (int *)PCPU_PTR(monitorbuf);
	*state = STATE_SLEEPING;

	
	disable_intr();
	if (sched_runnable())
		enable_intr();
	else if (cpu_idle_hook)
		cpu_idle_hook(sbt);
	else __asm __volatile("sti; hlt");
	*state = STATE_RUNNING;
}

static void cpu_idle_hlt(sbintime_t sbt)
{
	int *state;

	state = (int *)PCPU_PTR(monitorbuf);
	*state = STATE_SLEEPING;

	
	disable_intr();
	if (sched_runnable())
		enable_intr();
	else __asm __volatile("sti; hlt");
	*state = STATE_RUNNING;
}








static void cpu_idle_mwait(sbintime_t sbt)
{
	int *state;

	state = (int *)PCPU_PTR(monitorbuf);
	*state = STATE_MWAIT;

	
	disable_intr();
	if (sched_runnable()) {
		enable_intr();
		*state = STATE_RUNNING;
		return;
	}
	cpu_monitor(state, 0, 0);
	if (*state == STATE_MWAIT)
		__asm __volatile("sti; mwait" : : "a" (MWAIT_C1), "c" (0));
	else enable_intr();
	*state = STATE_RUNNING;
}

static void cpu_idle_spin(sbintime_t sbt)
{
	int *state;
	int i;

	state = (int *)PCPU_PTR(monitorbuf);
	*state = STATE_RUNNING;

	
	for (i = 0; i < 1000; i++) {
		if (sched_runnable())
			return;
		cpu_spinwait();
	}
}







static void cpu_probe_amdc1e(void)
{

	
	if (cpu_vendor_id == CPU_VENDOR_AMD && (cpu_id & 0x00000f00) == 0x00000f00 && (cpu_id & 0x0fff0000) >=  0x00040000) {

		cpu_ident_amdc1e = 1;
	}
}

void (*cpu_idle_fn)(sbintime_t) = cpu_idle_acpi;

void cpu_idle(int busy)
{
	uint64_t msr;
	sbintime_t sbt = -1;

	CTR2(KTR_SPARE2, "cpu_idle(%d) at %d", busy, curcpu);

	ap_watchdog(PCPU_GET(cpuid));

	
	if (busy) {
		if ((cpu_feature2 & CPUID2_MON) && idle_mwait) {
			cpu_idle_mwait(busy);
			goto out;
		}
	}

	
	if (!busy) {
		critical_enter();
		sbt = cpu_idleclock();
	}

	
	if (cpu_ident_amdc1e && cpu_disable_deep_sleep) {
		msr = rdmsr(MSR_AMDK8_IPM);
		if (msr & AMDK8_CMPHALT)
			wrmsr(MSR_AMDK8_IPM, msr & ~AMDK8_CMPHALT);
	}

	
	cpu_idle_fn(sbt);

	
	if (!busy) {
		cpu_activeclock();
		critical_exit();
	}
out:
	CTR2(KTR_SPARE2, "cpu_idle(%d) at %d done", busy, curcpu);
}

int cpu_idle_wakeup(int cpu)
{
	struct pcpu *pcpu;
	int *state;

	pcpu = pcpu_find(cpu);
	state = (int *)pcpu->pc_monitorbuf;
	
	if (*state == STATE_SLEEPING)
		return (0);
	if (*state == STATE_MWAIT)
		*state = STATE_RUNNING;
	return (1);
}


struct {
	void	*id_fn;
	char	*id_name;
} idle_tbl[] = {
	{ cpu_idle_spin, "spin" }, { cpu_idle_mwait, "mwait" }, { cpu_idle_hlt, "hlt" }, { cpu_idle_acpi, "acpi" }, { NULL, NULL }



};

static int idle_sysctl_available(SYSCTL_HANDLER_ARGS)
{
	char *avail, *p;
	int error;
	int i;

	avail = malloc(256, M_TEMP, M_WAITOK);
	p = avail;
	for (i = 0; idle_tbl[i].id_name != NULL; i++) {
		if (strstr(idle_tbl[i].id_name, "mwait") && (cpu_feature2 & CPUID2_MON) == 0)
			continue;
		if (strcmp(idle_tbl[i].id_name, "acpi") == 0 && cpu_idle_hook == NULL)
			continue;
		p += sprintf(p, "%s%s", p != avail ? ", " : "", idle_tbl[i].id_name);
	}
	error = sysctl_handle_string(oidp, avail, 0, req);
	free(avail, M_TEMP);
	return (error);
}

SYSCTL_PROC(_machdep, OID_AUTO, idle_available, CTLTYPE_STRING | CTLFLAG_RD, 0, 0, idle_sysctl_available, "A", "list of available idle functions");

static int idle_sysctl(SYSCTL_HANDLER_ARGS)
{
	char buf[16];
	int error;
	char *p;
	int i;

	p = "unknown";
	for (i = 0; idle_tbl[i].id_name != NULL; i++) {
		if (idle_tbl[i].id_fn == cpu_idle_fn) {
			p = idle_tbl[i].id_name;
			break;
		}
	}
	strncpy(buf, p, sizeof(buf));
	error = sysctl_handle_string(oidp, buf, sizeof(buf), req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	for (i = 0; idle_tbl[i].id_name != NULL; i++) {
		if (strstr(idle_tbl[i].id_name, "mwait") && (cpu_feature2 & CPUID2_MON) == 0)
			continue;
		if (strcmp(idle_tbl[i].id_name, "acpi") == 0 && cpu_idle_hook == NULL)
			continue;
		if (strcmp(idle_tbl[i].id_name, buf))
			continue;
		cpu_idle_fn = idle_tbl[i].id_fn;
		return (0);
	}
	return (EINVAL);
}

SYSCTL_PROC(_machdep, OID_AUTO, idle, CTLTYPE_STRING | CTLFLAG_RW, 0, 0, idle_sysctl, "A", "currently selected idle function");


void exec_setregs(struct thread *td, struct image_params *imgp, u_long stack)
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
	pcb->pcb_initial_fpucw = __INITIAL_FPUCW__;
	set_pcb_flags(pcb, PCB_FULL_IRET);

	bzero((char *)regs, sizeof(struct trapframe));
	regs->tf_rip = imgp->entry_addr;
	regs->tf_rsp = ((stack - 8) & ~0xFul) + 8;
	regs->tf_rdi = stack;		
	regs->tf_rflags = PSL_USER | (regs->tf_rflags & PSL_T);
	regs->tf_ss = _udatasel;
	regs->tf_cs = _ucodesel;
	regs->tf_ds = _udatasel;
	regs->tf_es = _udatasel;
	regs->tf_fs = _ufssel;
	regs->tf_gs = _ugssel;
	regs->tf_flags = TF_HASSEGS;
	td->td_retval[1] = 0;

	
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

void cpu_setregs(void)
{
	register_t cr0;

	cr0 = rcr0();
	
	cr0 |= CR0_MP | CR0_NE | CR0_TS | CR0_WP | CR0_AM;
	load_cr0(cr0);
}





struct user_segment_descriptor gdt[NGDT * MAXCPU];
static struct gate_descriptor idt0[NIDT];
struct gate_descriptor *idt = &idt0[0];	

static char dblfault_stack[PAGE_SIZE] __aligned(16);

static char nmi0_stack[PAGE_SIZE] __aligned(16);
CTASSERT(sizeof(struct nmi_pcpu) == 16);

struct amd64tss common_tss[MAXCPU];


struct soft_segment_descriptor gdt_segs[] = {

{	.ssd_base = 0x0, .ssd_limit = 0x0, .ssd_type = 0, .ssd_dpl = 0, .ssd_p = 0, .ssd_long = 0, .ssd_def32 = 0, .ssd_gran = 0		},  {	.ssd_base = 0x0, .ssd_limit = 0x0, .ssd_type = 0, .ssd_dpl = 0, .ssd_p = 0, .ssd_long = 0, .ssd_def32 = 0, .ssd_gran = 0		},  {	.ssd_base = 0x0, .ssd_limit = 0xfffff, .ssd_type = SDT_MEMRWA, .ssd_dpl = SEL_UPL, .ssd_p = 1, .ssd_long = 0, .ssd_def32 = 1, .ssd_gran = 1		},  {	.ssd_base = 0x0, .ssd_limit = 0xfffff, .ssd_type = SDT_MEMRWA, .ssd_dpl = SEL_UPL, .ssd_p = 1, .ssd_long = 0, .ssd_def32 = 1, .ssd_gran = 1		},  {	.ssd_base = 0x0, .ssd_limit = 0xfffff, .ssd_type = SDT_MEMERA, .ssd_dpl = SEL_KPL, .ssd_p = 1, .ssd_long = 1, .ssd_def32 = 0, .ssd_gran = 1		},  {	.ssd_base = 0x0, .ssd_limit = 0xfffff, .ssd_type = SDT_MEMRWA, .ssd_dpl = SEL_KPL, .ssd_p = 1, .ssd_long = 1, .ssd_def32 = 0, .ssd_gran = 1		},  {	.ssd_base = 0x0, .ssd_limit = 0xfffff, .ssd_type = SDT_MEMERA, .ssd_dpl = SEL_UPL, .ssd_p = 1, .ssd_long = 0, .ssd_def32 = 1, .ssd_gran = 1		},  {	.ssd_base = 0x0, .ssd_limit = 0xfffff, .ssd_type = SDT_MEMRWA, .ssd_dpl = SEL_UPL, .ssd_p = 1, .ssd_long = 0, .ssd_def32 = 1, .ssd_gran = 1		},  {	.ssd_base = 0x0, .ssd_limit = 0xfffff, .ssd_type = SDT_MEMERA, .ssd_dpl = SEL_UPL, .ssd_p = 1, .ssd_long = 1, .ssd_def32 = 0, .ssd_gran = 1		},  {	.ssd_base = 0x0, .ssd_limit = sizeof(struct amd64tss) + IOPERM_BITMAP_SIZE - 1, .ssd_type = SDT_SYSTSS, .ssd_dpl = SEL_KPL, .ssd_p = 1, .ssd_long = 0, .ssd_def32 = 0, .ssd_gran = 0		},  {	.ssd_base = 0x0, .ssd_limit = 0x0, .ssd_type = 0, .ssd_dpl = 0, .ssd_p = 0, .ssd_long = 0, .ssd_def32 = 0, .ssd_gran = 0		},  {	.ssd_base = 0x0, .ssd_limit = 0x0, .ssd_type = 0, .ssd_dpl = 0, .ssd_p = 0, .ssd_long = 0, .ssd_def32 = 0, .ssd_gran = 0		},  {	.ssd_base = 0x0, .ssd_limit = 0x0, .ssd_type = 0, .ssd_dpl = 0, .ssd_p = 0, .ssd_long = 0, .ssd_def32 = 0, .ssd_gran = 0		}, };




















































































































void setidt(idx, func, typ, dpl, ist)
	int idx;
	inthand_t *func;
	int typ;
	int dpl;
	int ist;
{
	struct gate_descriptor *ip;

	ip = idt + idx;
	ip->gd_looffset = (uintptr_t)func;
	ip->gd_selector = GSEL(GCODE_SEL, SEL_KPL);
	ip->gd_ist = ist;
	ip->gd_xx = 0;
	ip->gd_type = typ;
	ip->gd_dpl = dpl;
	ip->gd_p = 1;
	ip->gd_hioffset = ((uintptr_t)func)>>16 ;
}

extern inthand_t IDTVEC(div), IDTVEC(dbg), IDTVEC(nmi), IDTVEC(bpt), IDTVEC(ofl), IDTVEC(bnd), IDTVEC(ill), IDTVEC(dna), IDTVEC(fpusegm), IDTVEC(tss), IDTVEC(missing), IDTVEC(stk), IDTVEC(prot), IDTVEC(page), IDTVEC(mchk), IDTVEC(rsvd), IDTVEC(fpu), IDTVEC(align), IDTVEC(xmm), IDTVEC(dblfault),  IDTVEC(dtrace_ret),   IDTVEC(xen_intr_upcall),  IDTVEC(fast_syscall), IDTVEC(fast_syscall32);














DB_SHOW_COMMAND(idt, db_show_idt)
{
	struct gate_descriptor *ip;
	int idx;
	uintptr_t func;

	ip = idt;
	for (idx = 0; idx < NIDT && !db_pager_quit; idx++) {
		func = ((long)ip->gd_hioffset << 16 | ip->gd_looffset);
		if (func != (uintptr_t)&IDTVEC(rsvd)) {
			db_printf("%3d\t", idx);
			db_printsym(func, DB_STGY_PROC);
			db_printf("\n");
		}
		ip++;
	}
}


DB_SHOW_COMMAND(sysregs, db_show_sysregs)
{
	struct {
		uint16_t limit;
		uint64_t base;
	} __packed idtr, gdtr;
	uint16_t ldt, tr;

	__asm __volatile("sidt %0" : "=m" (idtr));
	db_printf("idtr\t0x%016lx/%04x\n", (u_long)idtr.base, (u_int)idtr.limit);
	__asm __volatile("sgdt %0" : "=m" (gdtr));
	db_printf("gdtr\t0x%016lx/%04x\n", (u_long)gdtr.base, (u_int)gdtr.limit);
	__asm __volatile("sldt %0" : "=r" (ldt));
	db_printf("ldtr\t0x%04x\n", ldt);
	__asm __volatile("str %0" : "=r" (tr));
	db_printf("tr\t0x%04x\n", tr);
	db_printf("cr0\t0x%016lx\n", rcr0());
	db_printf("cr2\t0x%016lx\n", rcr2());
	db_printf("cr3\t0x%016lx\n", rcr3());
	db_printf("cr4\t0x%016lx\n", rcr4());
	db_printf("EFER\t%016lx\n", rdmsr(MSR_EFER));
	db_printf("FEATURES_CTL\t%016lx\n", rdmsr(MSR_IA32_FEATURE_CONTROL));
	db_printf("DEBUG_CTL\t%016lx\n", rdmsr(MSR_DEBUGCTLMSR));
	db_printf("PAT\t%016lx\n", rdmsr(MSR_PAT));
	db_printf("GSBASE\t%016lx\n", rdmsr(MSR_GSBASE));
}


void sdtossd(sd, ssd)
	struct user_segment_descriptor *sd;
	struct soft_segment_descriptor *ssd;
{

	ssd->ssd_base  = (sd->sd_hibase << 24) | sd->sd_lobase;
	ssd->ssd_limit = (sd->sd_hilimit << 16) | sd->sd_lolimit;
	ssd->ssd_type  = sd->sd_type;
	ssd->ssd_dpl   = sd->sd_dpl;
	ssd->ssd_p     = sd->sd_p;
	ssd->ssd_long  = sd->sd_long;
	ssd->ssd_def32 = sd->sd_def32;
	ssd->ssd_gran  = sd->sd_gran;
}

void ssdtosd(ssd, sd)
	struct soft_segment_descriptor *ssd;
	struct user_segment_descriptor *sd;
{

	sd->sd_lobase = (ssd->ssd_base) & 0xffffff;
	sd->sd_hibase = (ssd->ssd_base >> 24) & 0xff;
	sd->sd_lolimit = (ssd->ssd_limit) & 0xffff;
	sd->sd_hilimit = (ssd->ssd_limit >> 16) & 0xf;
	sd->sd_type  = ssd->ssd_type;
	sd->sd_dpl   = ssd->ssd_dpl;
	sd->sd_p     = ssd->ssd_p;
	sd->sd_long  = ssd->ssd_long;
	sd->sd_def32 = ssd->ssd_def32;
	sd->sd_gran  = ssd->ssd_gran;
}

void ssdtosyssd(ssd, sd)
	struct soft_segment_descriptor *ssd;
	struct system_segment_descriptor *sd;
{

	sd->sd_lobase = (ssd->ssd_base) & 0xffffff;
	sd->sd_hibase = (ssd->ssd_base >> 24) & 0xfffffffffful;
	sd->sd_lolimit = (ssd->ssd_limit) & 0xffff;
	sd->sd_hilimit = (ssd->ssd_limit >> 16) & 0xf;
	sd->sd_type  = ssd->ssd_type;
	sd->sd_dpl   = ssd->ssd_dpl;
	sd->sd_p     = ssd->ssd_p;
	sd->sd_gran  = ssd->ssd_gran;
}





intrmask_t isa_irq_pending(void)
{
	u_char irr1;
	u_char irr2;

	irr1 = inb(IO_ICU1);
	irr2 = inb(IO_ICU2);
	return ((irr2 << 8) | irr1);
}


u_int basemem;

static int add_physmap_entry(uint64_t base, uint64_t length, vm_paddr_t *physmap, int *physmap_idxp)

{
	int i, insert_idx, physmap_idx;

	physmap_idx = *physmap_idxp;

	if (length == 0)
		return (1);

	
	insert_idx = physmap_idx + 2;
	for (i = 0; i <= physmap_idx; i += 2) {
		if (base < physmap[i + 1]) {
			if (base + length <= physmap[i]) {
				insert_idx = i;
				break;
			}
			if (boothowto & RB_VERBOSE)
				printf( "Overlapping memory regions, ignoring second region\n");
			return (1);
		}
	}

	
	if (insert_idx <= physmap_idx && base + length == physmap[insert_idx]) {
		physmap[insert_idx] = base;
		return (1);
	}

	
	if (insert_idx > 0 && base == physmap[insert_idx - 1]) {
		physmap[insert_idx - 1] += length;
		return (1);
	}

	physmap_idx += 2;
	*physmap_idxp = physmap_idx;
	if (physmap_idx == PHYSMAP_SIZE) {
		printf( "Too many segments in the physical address map, giving up\n");
		return (0);
	}

	
	for (i = physmap_idx; i > insert_idx; i -= 2) {
		physmap[i] = physmap[i - 2];
		physmap[i + 1] = physmap[i - 1];
	}

	
	physmap[insert_idx] = base;
	physmap[insert_idx + 1] = base + length;
	return (1);
}

void bios_add_smap_entries(struct bios_smap *smapbase, u_int32_t smapsize, vm_paddr_t *physmap, int *physmap_idx)

{
	struct bios_smap *smap, *smapend;

	smapend = (struct bios_smap *)((uintptr_t)smapbase + smapsize);

	for (smap = smapbase; smap < smapend; smap++) {
		if (boothowto & RB_VERBOSE)
			printf("SMAP type=%02x base=%016lx len=%016lx\n", smap->type, smap->base, smap->length);

		if (smap->type != SMAP_TYPE_MEMORY)
			continue;

		if (!add_physmap_entry(smap->base, smap->length, physmap, physmap_idx))
			break;
	}
}



static void add_efi_map_entries(struct efi_map_header *efihdr, vm_paddr_t *physmap, int *physmap_idx)

{
	struct efi_md *map, *p;
	const char *type;
	size_t efisz;
	int ndesc, i;

	static const char *types[] = {
		"Reserved", "LoaderCode", "LoaderData", "BootServicesCode", "BootServicesData", "RuntimeServicesCode", "RuntimeServicesData", "ConventionalMemory", "UnusableMemory", "ACPIReclaimMemory", "ACPIMemoryNVS", "MemoryMappedIO", "MemoryMappedIOPortSpace", "PalCode" };














	
	efisz = (sizeof(struct efi_map_header) + 0xf) & ~0xf;
	map = (struct efi_md *)((uint8_t *)efihdr + efisz); 

	if (efihdr->descriptor_size == 0)
		return;
	ndesc = efihdr->memory_size / efihdr->descriptor_size;

	if (boothowto & RB_VERBOSE)
		printf("%23s %12s %12s %8s %4s\n", "Type", "Physical", "Virtual", "#Pages", "Attr");

	for (i = 0, p = map; i < ndesc; i++, p = efi_next_descriptor(p, efihdr->descriptor_size)) {
		if (boothowto & RB_VERBOSE) {
			if (p->md_type <= EFI_MD_TYPE_PALCODE)
				type = types[p->md_type];
			else type = "<INVALID>";
			printf("%23s %012lx %12p %08lx ", type, p->md_phys, p->md_virt, p->md_pages);
			if (p->md_attr & EFI_MD_ATTR_UC)
				printf("UC ");
			if (p->md_attr & EFI_MD_ATTR_WC)
				printf("WC ");
			if (p->md_attr & EFI_MD_ATTR_WT)
				printf("WT ");
			if (p->md_attr & EFI_MD_ATTR_WB)
				printf("WB ");
			if (p->md_attr & EFI_MD_ATTR_UCE)
				printf("UCE ");
			if (p->md_attr & EFI_MD_ATTR_WP)
				printf("WP ");
			if (p->md_attr & EFI_MD_ATTR_RP)
				printf("RP ");
			if (p->md_attr & EFI_MD_ATTR_XP)
				printf("XP ");
			if (p->md_attr & EFI_MD_ATTR_RT)
				printf("RUNTIME");
			printf("\n");
		}

		switch (p->md_type) {
		case EFI_MD_TYPE_CODE:
		case EFI_MD_TYPE_DATA:
		case EFI_MD_TYPE_BS_CODE:
		case EFI_MD_TYPE_BS_DATA:
		case EFI_MD_TYPE_FREE:
			
			break;
		default:
			continue;
		}

		if (!add_physmap_entry(p->md_phys, (p->md_pages * PAGE_SIZE), physmap, physmap_idx))
			break;
	}
}

static char bootmethod[16] = "";
SYSCTL_STRING(_machdep, OID_AUTO, bootmethod, CTLFLAG_RD, bootmethod, 0, "System firmware boot method");

static void native_parse_memmap(caddr_t kmdp, vm_paddr_t *physmap, int *physmap_idx)
{
	struct bios_smap *smap;
	struct efi_map_header *efihdr;
	u_int32_t size;

	

	efihdr = (struct efi_map_header *)preload_search_info(kmdp, MODINFO_METADATA | MODINFOMD_EFI_MAP);
	smap = (struct bios_smap *)preload_search_info(kmdp, MODINFO_METADATA | MODINFOMD_SMAP);
	if (efihdr == NULL && smap == NULL)
		panic("No BIOS smap or EFI map info from loader!");

	if (efihdr != NULL) {
		add_efi_map_entries(efihdr, physmap, physmap_idx);
		strlcpy(bootmethod, "UEFI", sizeof(bootmethod));
	} else {
		size = *((u_int32_t *)smap - 1);
		bios_add_smap_entries(smap, size, physmap, physmap_idx);
		strlcpy(bootmethod, "BIOS", sizeof(bootmethod));
	}
}


static void getmemsize(caddr_t kmdp, u_int64_t first)
{
	int i, physmap_idx, pa_indx, da_indx;
	vm_paddr_t pa, physmap[PHYSMAP_SIZE];
	u_long physmem_start, physmem_tunable, memtest;
	pt_entry_t *pte;
	quad_t dcons_addr, dcons_size;

	bzero(physmap, sizeof(physmap));
	basemem = 0;
	physmap_idx = 0;

	init_ops.parse_memmap(kmdp, physmap, &physmap_idx);

	
	basemem = 0;
	for (i = 0; i <= physmap_idx; i += 2) {
		if (physmap[i] == 0x00000000) {
			basemem = physmap[i + 1] / 1024;
			break;
		}
	}
	if (basemem == 0)
		panic("BIOS smap did not include a basemem segment!");

	
	if (init_ops.mp_bootaddress)
		physmap[1] = init_ops.mp_bootaddress(physmap[1] / 1024);

	
	Maxmem = atop(physmap[physmap_idx + 1]);


	Maxmem = MAXMEM / 4;


	if (TUNABLE_ULONG_FETCH("hw.physmem", &physmem_tunable))
		Maxmem = atop(physmem_tunable);

	
	memtest = 0;
	TUNABLE_ULONG_FETCH("hw.memtest.tests", &memtest);

	
	if (Maxmem > atop(physmap[physmap_idx + 1]))
		Maxmem = atop(physmap[physmap_idx + 1]);

	if (atop(physmap[physmap_idx + 1]) != Maxmem && (boothowto & RB_VERBOSE))
		printf("Physical memory use set to %ldK\n", Maxmem * 4);

	
	pmap_bootstrap(&first);

	
	physmem_start = (vm_guest > VM_GUEST_NO ? 1 : 16) << PAGE_SHIFT;
	TUNABLE_ULONG_FETCH("hw.physmem.start", &physmem_start);
	if (physmem_start < PAGE_SIZE)
		physmap[0] = PAGE_SIZE;
	else if (physmem_start >= physmap[1])
		physmap[0] = round_page(physmap[1] - PAGE_SIZE);
	else physmap[0] = round_page(physmem_start);
	pa_indx = 0;
	da_indx = 1;
	phys_avail[pa_indx++] = physmap[0];
	phys_avail[pa_indx] = physmap[0];
	dump_avail[da_indx] = physmap[0];
	pte = CMAP1;

	
	if (getenv_quad("dcons.addr", &dcons_addr) == 0 || getenv_quad("dcons.size", &dcons_size) == 0)
		dcons_addr = 0;

	
	for (i = 0; i <= physmap_idx; i += 2) {
		vm_paddr_t end;

		end = ptoa((vm_paddr_t)Maxmem);
		if (physmap[i + 1] < end)
			end = trunc_page(physmap[i + 1]);
		for (pa = round_page(physmap[i]); pa < end; pa += PAGE_SIZE) {
			int tmp, page_bad, full;
			int *ptr = (int *)CADDR1;

			full = FALSE;
			
			if (pa >= (vm_paddr_t)kernphys && pa < first)
				goto do_dump_avail;

			
			if (dcons_addr > 0 && pa >= trunc_page(dcons_addr)
			    && pa < dcons_addr + dcons_size)
				goto do_dump_avail;

			page_bad = FALSE;
			if (memtest == 0)
				goto skip_memtest;

			
			*pte = pa | PG_V | PG_RW | PG_NC_PWT | PG_NC_PCD;
			invltlb();

			tmp = *(int *)ptr;
			
			*(volatile int *)ptr = 0xaaaaaaaa;
			if (*(volatile int *)ptr != 0xaaaaaaaa)
				page_bad = TRUE;
			
			*(volatile int *)ptr = 0x55555555;
			if (*(volatile int *)ptr != 0x55555555)
				page_bad = TRUE;
			
			*(volatile int *)ptr = 0xffffffff;
			if (*(volatile int *)ptr != 0xffffffff)
				page_bad = TRUE;
			
			*(volatile int *)ptr = 0x0;
			if (*(volatile int *)ptr != 0x0)
				page_bad = TRUE;
			
			*(int *)ptr = tmp;

skip_memtest:
			
			if (page_bad == TRUE)
				continue;
			
			if (phys_avail[pa_indx] == pa) {
				phys_avail[pa_indx] += PAGE_SIZE;
			} else {
				pa_indx++;
				if (pa_indx == PHYS_AVAIL_ARRAY_END) {
					printf( "Too many holes in the physical address space, giving up\n");
					pa_indx--;
					full = TRUE;
					goto do_dump_avail;
				}
				phys_avail[pa_indx++] = pa;	
				phys_avail[pa_indx] = pa + PAGE_SIZE; 
			}
			physmem++;
do_dump_avail:
			if (dump_avail[da_indx] == pa) {
				dump_avail[da_indx] += PAGE_SIZE;
			} else {
				da_indx++;
				if (da_indx == DUMP_AVAIL_ARRAY_END) {
					da_indx--;
					goto do_next;
				}
				dump_avail[da_indx++] = pa; 
				dump_avail[da_indx] = pa + PAGE_SIZE; 
			}
do_next:
			if (full)
				break;
		}
	}
	*pte = 0;
	invltlb();

	
	while (phys_avail[pa_indx - 1] + PAGE_SIZE + round_page(msgbufsize) >= phys_avail[pa_indx]) {
		physmem -= atop(phys_avail[pa_indx] - phys_avail[pa_indx - 1]);
		phys_avail[pa_indx--] = 0;
		phys_avail[pa_indx--] = 0;
	}

	Maxmem = atop(phys_avail[pa_indx]);

	
	phys_avail[pa_indx] -= round_page(msgbufsize);

	
	msgbufp = (struct msgbuf *)PHYS_TO_DMAP(phys_avail[pa_indx]);
}

static caddr_t native_parse_preload_data(u_int64_t modulep)
{
	caddr_t kmdp;

	preload_metadata = (caddr_t)(uintptr_t)(modulep + KERNBASE);
	preload_bootstrap_relocate(KERNBASE);
	kmdp = preload_search_by_type("elf kernel");
	if (kmdp == NULL)
		kmdp = preload_search_by_type("elf64 kernel");
	boothowto = MD_FETCH(kmdp, MODINFOMD_HOWTO, int);
	kern_envp = MD_FETCH(kmdp, MODINFOMD_ENVP, char *) + KERNBASE;

	ksym_start = MD_FETCH(kmdp, MODINFOMD_SSYM, uintptr_t);
	ksym_end = MD_FETCH(kmdp, MODINFOMD_ESYM, uintptr_t);


	return (kmdp);
}

u_int64_t hammer_time(u_int64_t modulep, u_int64_t physfree)
{
	caddr_t kmdp;
	int gsel_tss, x;
	struct pcpu *pc;
	struct nmi_pcpu *np;
	struct xstate_hdr *xhdr;
	u_int64_t msr;
	char *env;
	size_t kstack0_sz;

	thread0.td_kstack = physfree + KERNBASE;
	thread0.td_kstack_pages = KSTACK_PAGES;
	kstack0_sz = thread0.td_kstack_pages * PAGE_SIZE;
	bzero((void *)thread0.td_kstack, kstack0_sz);
	physfree += kstack0_sz;

	
	proc_linkup0(&proc0, &thread0);

	kmdp = init_ops.parse_preload_data(modulep);

	
	init_param1();

	
	for (x = 0; x < NGDT; x++) {
		if (x != GPROC0_SEL && x != (GPROC0_SEL + 1) && x != GUSERLDT_SEL && x != (GUSERLDT_SEL) + 1)
			ssdtosd(&gdt_segs[x], &gdt[x]);
	}
	gdt_segs[GPROC0_SEL].ssd_base = (uintptr_t)&common_tss[0];
	ssdtosyssd(&gdt_segs[GPROC0_SEL], (struct system_segment_descriptor *)&gdt[GPROC0_SEL]);

	r_gdt.rd_limit = NGDT * sizeof(gdt[0]) - 1;
	r_gdt.rd_base =  (long) gdt;
	lgdt(&r_gdt);
	pc = &__pcpu[0];

	wrmsr(MSR_FSBASE, 0);		
	wrmsr(MSR_GSBASE, (u_int64_t)pc);
	wrmsr(MSR_KGSBASE, 0);		

	pcpu_init(pc, 0, sizeof(struct pcpu));
	dpcpu_init((void *)(physfree + KERNBASE), 0);
	physfree += DPCPU_SIZE;
	PCPU_SET(prvspace, pc);
	PCPU_SET(curthread, &thread0);
	PCPU_SET(tssp, &common_tss[0]);
	PCPU_SET(commontssp, &common_tss[0]);
	PCPU_SET(tss, (struct system_segment_descriptor *)&gdt[GPROC0_SEL]);
	PCPU_SET(ldt, (struct system_segment_descriptor *)&gdt[GUSERLDT_SEL]);
	PCPU_SET(fs32p, &gdt[GUFS32_SEL]);
	PCPU_SET(gs32p, &gdt[GUGS32_SEL]);

	
	mutex_init();
	mtx_init(&icu_lock, "icu", NULL, MTX_SPIN | MTX_NOWITNESS);
	mtx_init(&dt_lock, "descriptor tables", NULL, MTX_DEF);

	
	for (x = 0; x < NIDT; x++)
		setidt(x, &IDTVEC(rsvd), SDT_SYSIGT, SEL_KPL, 0);
	setidt(IDT_DE, &IDTVEC(div),  SDT_SYSIGT, SEL_KPL, 0);
	setidt(IDT_DB, &IDTVEC(dbg),  SDT_SYSIGT, SEL_KPL, 0);
	setidt(IDT_NMI, &IDTVEC(nmi),  SDT_SYSIGT, SEL_KPL, 2);
 	setidt(IDT_BP, &IDTVEC(bpt),  SDT_SYSIGT, SEL_UPL, 0);
	setidt(IDT_OF, &IDTVEC(ofl),  SDT_SYSIGT, SEL_KPL, 0);
	setidt(IDT_BR, &IDTVEC(bnd),  SDT_SYSIGT, SEL_KPL, 0);
	setidt(IDT_UD, &IDTVEC(ill),  SDT_SYSIGT, SEL_KPL, 0);
	setidt(IDT_NM, &IDTVEC(dna),  SDT_SYSIGT, SEL_KPL, 0);
	setidt(IDT_DF, &IDTVEC(dblfault), SDT_SYSIGT, SEL_KPL, 1);
	setidt(IDT_FPUGP, &IDTVEC(fpusegm),  SDT_SYSIGT, SEL_KPL, 0);
	setidt(IDT_TS, &IDTVEC(tss),  SDT_SYSIGT, SEL_KPL, 0);
	setidt(IDT_NP, &IDTVEC(missing),  SDT_SYSIGT, SEL_KPL, 0);
	setidt(IDT_SS, &IDTVEC(stk),  SDT_SYSIGT, SEL_KPL, 0);
	setidt(IDT_GP, &IDTVEC(prot),  SDT_SYSIGT, SEL_KPL, 0);
	setidt(IDT_PF, &IDTVEC(page),  SDT_SYSIGT, SEL_KPL, 0);
	setidt(IDT_MF, &IDTVEC(fpu),  SDT_SYSIGT, SEL_KPL, 0);
	setidt(IDT_AC, &IDTVEC(align), SDT_SYSIGT, SEL_KPL, 0);
	setidt(IDT_MC, &IDTVEC(mchk),  SDT_SYSIGT, SEL_KPL, 0);
	setidt(IDT_XF, &IDTVEC(xmm), SDT_SYSIGT, SEL_KPL, 0);

	setidt(IDT_DTRACE_RET, &IDTVEC(dtrace_ret), SDT_SYSIGT, SEL_UPL, 0);


	setidt(IDT_EVTCHN, &IDTVEC(xen_intr_upcall), SDT_SYSIGT, SEL_UPL, 0);


	r_idt.rd_limit = sizeof(idt0) - 1;
	r_idt.rd_base = (long) idt;
	lidt(&r_idt);

	
	clock_init();

	
	if (preload_search_info(kmdp, MODINFO_METADATA | MODINFOMD_EFI_MAP) != NULL)
		vty_set_preferred(VTY_VT);

	
	cninit();



	elcr_probe();
	atpic_startup();

	
	atpic_reset();

	
	setidt(IDT_IO_INTS + 7, IDTVEC(spuriousint), SDT_SYSIGT, SEL_KPL, 0);
	setidt(IDT_IO_INTS + 15, IDTVEC(spuriousint), SDT_SYSIGT, SEL_KPL, 0);





	kdb_init();


	if (boothowto & RB_KDB)
		kdb_enter(KDB_WHY_BOOTFLAGS, "Boot flags requested debugger");


	identify_cpu();		
	initializecpu();	
	initializecpucache();

	
	common_tss[0].tss_ist1 = (long)&dblfault_stack[sizeof(dblfault_stack)];

	
	np = ((struct nmi_pcpu *) &nmi0_stack[sizeof(nmi0_stack)]) - 1;
	np->np_pcpu = (register_t) pc;
	common_tss[0].tss_ist2 = (long) np;

	
	common_tss[0].tss_iobase = sizeof(struct amd64tss) + IOPERM_BITMAP_SIZE;

	gsel_tss = GSEL(GPROC0_SEL, SEL_KPL);
	ltr(gsel_tss);

	
	msr = rdmsr(MSR_EFER) | EFER_SCE;
	wrmsr(MSR_EFER, msr);
	wrmsr(MSR_LSTAR, (u_int64_t)IDTVEC(fast_syscall));
	wrmsr(MSR_CSTAR, (u_int64_t)IDTVEC(fast_syscall32));
	msr = ((u_int64_t)GSEL(GCODE_SEL, SEL_KPL) << 32) | ((u_int64_t)GSEL(GUCODE32_SEL, SEL_UPL) << 48);
	wrmsr(MSR_STAR, msr);
	wrmsr(MSR_SF_MASK, PSL_NT|PSL_T|PSL_I|PSL_C|PSL_D);

	getmemsize(kmdp, physfree);
	init_param2(physmem);

	

	msgbufinit(msgbufp, msgbufsize);
	fpuinit();

	
	thread0.td_pcb = get_pcb_td(&thread0);
	bzero(get_pcb_user_save_td(&thread0), cpu_max_ext_state_size);
	if (use_xsave) {
		xhdr = (struct xstate_hdr *)(get_pcb_user_save_td(&thread0) + 1);
		xhdr->xstate_bv = xsave_mask;
	}
	
	common_tss[0].tss_rsp0 = (vm_offset_t)thread0.td_pcb;
	
	common_tss[0].tss_rsp0 &= ~0xFul;
	PCPU_SET(rsp0, common_tss[0].tss_rsp0);
	PCPU_SET(curpcb, thread0.td_pcb);

	

	_ucodesel = GSEL(GUCODE_SEL, SEL_UPL);
	_udatasel = GSEL(GUDATA_SEL, SEL_UPL);
	_ucode32sel = GSEL(GUCODE32_SEL, SEL_UPL);
	_ufssel = GSEL(GUFS32_SEL, SEL_UPL);
	_ugssel = GSEL(GUGS32_SEL, SEL_UPL);

	load_ds(_udatasel);
	load_es(_udatasel);
	load_fs(_ufssel);

	
	thread0.td_pcb->pcb_flags = 0;
	thread0.td_pcb->pcb_cr3 = KPML4phys; 
	thread0.td_frame = &proc0_tf;

        env = getenv("kernelname");
	if (env != NULL)
		strlcpy(kernelname, env, sizeof(kernelname));

	cpu_probe_amdc1e();


	x86_init_fdt();


	
	return ((u_int64_t)thread0.td_pcb);
}

void cpu_pcpu_init(struct pcpu *pcpu, int cpuid, size_t size)
{

	pcpu->pc_acpi_id = 0xffffffff;
}

void spinlock_enter(void)
{
	struct thread *td;
	register_t flags;

	td = curthread;
	if (td->td_md.md_spinlock_count == 0) {
		flags = intr_disable();
		td->td_md.md_spinlock_count = 1;
		td->td_md.md_saved_flags = flags;
	} else td->td_md.md_spinlock_count++;
	critical_enter();
}

void spinlock_exit(void)
{
	struct thread *td;
	register_t flags;

	td = curthread;
	critical_exit();
	flags = td->td_md.md_saved_flags;
	td->td_md.md_spinlock_count--;
	if (td->td_md.md_spinlock_count == 0)
		intr_restore(flags);
}


void makectx(struct trapframe *tf, struct pcb *pcb)
{

	pcb->pcb_r12 = tf->tf_r12;
	pcb->pcb_r13 = tf->tf_r13;
	pcb->pcb_r14 = tf->tf_r14;
	pcb->pcb_r15 = tf->tf_r15;
	pcb->pcb_rbp = tf->tf_rbp;
	pcb->pcb_rbx = tf->tf_rbx;
	pcb->pcb_rip = tf->tf_rip;
	pcb->pcb_rsp = tf->tf_rsp;
}

int ptrace_set_pc(struct thread *td, unsigned long addr)
{
	td->td_frame->tf_rip = addr;
	return (0);
}

int ptrace_single_step(struct thread *td)
{
	td->td_frame->tf_rflags |= PSL_T;
	return (0);
}

int ptrace_clear_single_step(struct thread *td)
{
	td->td_frame->tf_rflags &= ~PSL_T;
	return (0);
}

int fill_regs(struct thread *td, struct reg *regs)
{
	struct trapframe *tp;

	tp = td->td_frame;
	return (fill_frame_regs(tp, regs));
}

int fill_frame_regs(struct trapframe *tp, struct reg *regs)
{
	regs->r_r15 = tp->tf_r15;
	regs->r_r14 = tp->tf_r14;
	regs->r_r13 = tp->tf_r13;
	regs->r_r12 = tp->tf_r12;
	regs->r_r11 = tp->tf_r11;
	regs->r_r10 = tp->tf_r10;
	regs->r_r9  = tp->tf_r9;
	regs->r_r8  = tp->tf_r8;
	regs->r_rdi = tp->tf_rdi;
	regs->r_rsi = tp->tf_rsi;
	regs->r_rbp = tp->tf_rbp;
	regs->r_rbx = tp->tf_rbx;
	regs->r_rdx = tp->tf_rdx;
	regs->r_rcx = tp->tf_rcx;
	regs->r_rax = tp->tf_rax;
	regs->r_rip = tp->tf_rip;
	regs->r_cs = tp->tf_cs;
	regs->r_rflags = tp->tf_rflags;
	regs->r_rsp = tp->tf_rsp;
	regs->r_ss = tp->tf_ss;
	if (tp->tf_flags & TF_HASSEGS) {
		regs->r_ds = tp->tf_ds;
		regs->r_es = tp->tf_es;
		regs->r_fs = tp->tf_fs;
		regs->r_gs = tp->tf_gs;
	} else {
		regs->r_ds = 0;
		regs->r_es = 0;
		regs->r_fs = 0;
		regs->r_gs = 0;
	}
	return (0);
}

int set_regs(struct thread *td, struct reg *regs)
{
	struct trapframe *tp;
	register_t rflags;

	tp = td->td_frame;
	rflags = regs->r_rflags & 0xffffffff;
	if (!EFL_SECURE(rflags, tp->tf_rflags) || !CS_SECURE(regs->r_cs))
		return (EINVAL);
	tp->tf_r15 = regs->r_r15;
	tp->tf_r14 = regs->r_r14;
	tp->tf_r13 = regs->r_r13;
	tp->tf_r12 = regs->r_r12;
	tp->tf_r11 = regs->r_r11;
	tp->tf_r10 = regs->r_r10;
	tp->tf_r9  = regs->r_r9;
	tp->tf_r8  = regs->r_r8;
	tp->tf_rdi = regs->r_rdi;
	tp->tf_rsi = regs->r_rsi;
	tp->tf_rbp = regs->r_rbp;
	tp->tf_rbx = regs->r_rbx;
	tp->tf_rdx = regs->r_rdx;
	tp->tf_rcx = regs->r_rcx;
	tp->tf_rax = regs->r_rax;
	tp->tf_rip = regs->r_rip;
	tp->tf_cs = regs->r_cs;
	tp->tf_rflags = rflags;
	tp->tf_rsp = regs->r_rsp;
	tp->tf_ss = regs->r_ss;
	if (0) {	
		tp->tf_ds = regs->r_ds;
		tp->tf_es = regs->r_es;
		tp->tf_fs = regs->r_fs;
		tp->tf_gs = regs->r_gs;
		tp->tf_flags = TF_HASSEGS;
		set_pcb_flags(td->td_pcb, PCB_FULL_IRET);
	}
	return (0);
}



static void fill_fpregs_xmm(struct savefpu *sv_xmm, struct fpreg *fpregs)
{
	struct envxmm *penv_fpreg = (struct envxmm *)&fpregs->fpr_env;
	struct envxmm *penv_xmm = &sv_xmm->sv_env;
	int i;

	
	bzero(fpregs, sizeof(*fpregs));

	
	penv_fpreg->en_cw = penv_xmm->en_cw;
	penv_fpreg->en_sw = penv_xmm->en_sw;
	penv_fpreg->en_tw = penv_xmm->en_tw;
	penv_fpreg->en_opcode = penv_xmm->en_opcode;
	penv_fpreg->en_rip = penv_xmm->en_rip;
	penv_fpreg->en_rdp = penv_xmm->en_rdp;
	penv_fpreg->en_mxcsr = penv_xmm->en_mxcsr;
	penv_fpreg->en_mxcsr_mask = penv_xmm->en_mxcsr_mask;

	
	for (i = 0; i < 8; ++i)
		bcopy(sv_xmm->sv_fp[i].fp_acc.fp_bytes, fpregs->fpr_acc[i], 10);

	
	for (i = 0; i < 16; ++i)
		bcopy(sv_xmm->sv_xmm[i].xmm_bytes, fpregs->fpr_xacc[i], 16);
}


static void set_fpregs_xmm(struct fpreg *fpregs, struct savefpu *sv_xmm)
{
	struct envxmm *penv_xmm = &sv_xmm->sv_env;
	struct envxmm *penv_fpreg = (struct envxmm *)&fpregs->fpr_env;
	int i;

	
	
	penv_xmm->en_cw = penv_fpreg->en_cw;
	penv_xmm->en_sw = penv_fpreg->en_sw;
	penv_xmm->en_tw = penv_fpreg->en_tw;
	penv_xmm->en_opcode = penv_fpreg->en_opcode;
	penv_xmm->en_rip = penv_fpreg->en_rip;
	penv_xmm->en_rdp = penv_fpreg->en_rdp;
	penv_xmm->en_mxcsr = penv_fpreg->en_mxcsr;
	penv_xmm->en_mxcsr_mask = penv_fpreg->en_mxcsr_mask & cpu_mxcsr_mask;

	
	for (i = 0; i < 8; ++i)
		bcopy(fpregs->fpr_acc[i], sv_xmm->sv_fp[i].fp_acc.fp_bytes, 10);

	
	for (i = 0; i < 16; ++i)
		bcopy(fpregs->fpr_xacc[i], sv_xmm->sv_xmm[i].xmm_bytes, 16);
}


int fill_fpregs(struct thread *td, struct fpreg *fpregs)
{

	KASSERT(td == curthread || TD_IS_SUSPENDED(td) || P_SHOULDSTOP(td->td_proc), ("not suspended thread %p", td));

	fpugetregs(td);
	fill_fpregs_xmm(get_pcb_user_save_td(td), fpregs);
	return (0);
}


int set_fpregs(struct thread *td, struct fpreg *fpregs)
{

	set_fpregs_xmm(fpregs, get_pcb_user_save_td(td));
	fpuuserinited(td);
	return (0);
}


int get_mcontext(struct thread *td, mcontext_t *mcp, int flags)
{
	struct pcb *pcb;
	struct trapframe *tp;

	pcb = td->td_pcb;
	tp = td->td_frame;
	PROC_LOCK(curthread->td_proc);
	mcp->mc_onstack = sigonstack(tp->tf_rsp);
	PROC_UNLOCK(curthread->td_proc);
	mcp->mc_r15 = tp->tf_r15;
	mcp->mc_r14 = tp->tf_r14;
	mcp->mc_r13 = tp->tf_r13;
	mcp->mc_r12 = tp->tf_r12;
	mcp->mc_r11 = tp->tf_r11;
	mcp->mc_r10 = tp->tf_r10;
	mcp->mc_r9  = tp->tf_r9;
	mcp->mc_r8  = tp->tf_r8;
	mcp->mc_rdi = tp->tf_rdi;
	mcp->mc_rsi = tp->tf_rsi;
	mcp->mc_rbp = tp->tf_rbp;
	mcp->mc_rbx = tp->tf_rbx;
	mcp->mc_rcx = tp->tf_rcx;
	mcp->mc_rflags = tp->tf_rflags;
	if (flags & GET_MC_CLEAR_RET) {
		mcp->mc_rax = 0;
		mcp->mc_rdx = 0;
		mcp->mc_rflags &= ~PSL_C;
	} else {
		mcp->mc_rax = tp->tf_rax;
		mcp->mc_rdx = tp->tf_rdx;
	}
	mcp->mc_rip = tp->tf_rip;
	mcp->mc_cs = tp->tf_cs;
	mcp->mc_rsp = tp->tf_rsp;
	mcp->mc_ss = tp->tf_ss;
	mcp->mc_ds = tp->tf_ds;
	mcp->mc_es = tp->tf_es;
	mcp->mc_fs = tp->tf_fs;
	mcp->mc_gs = tp->tf_gs;
	mcp->mc_flags = tp->tf_flags;
	mcp->mc_len = sizeof(*mcp);
	get_fpcontext(td, mcp, NULL, 0);
	mcp->mc_fsbase = pcb->pcb_fsbase;
	mcp->mc_gsbase = pcb->pcb_gsbase;
	mcp->mc_xfpustate = 0;
	mcp->mc_xfpustate_len = 0;
	bzero(mcp->mc_spare, sizeof(mcp->mc_spare));
	return (0);
}


int set_mcontext(struct thread *td, const mcontext_t *mcp)
{
	struct pcb *pcb;
	struct trapframe *tp;
	char *xfpustate;
	long rflags;
	int ret;

	pcb = td->td_pcb;
	tp = td->td_frame;
	if (mcp->mc_len != sizeof(*mcp) || (mcp->mc_flags & ~_MC_FLAG_MASK) != 0)
		return (EINVAL);
	rflags = (mcp->mc_rflags & PSL_USERCHANGE) | (tp->tf_rflags & ~PSL_USERCHANGE);
	if (mcp->mc_flags & _MC_HASFPXSTATE) {
		if (mcp->mc_xfpustate_len > cpu_max_ext_state_size - sizeof(struct savefpu))
			return (EINVAL);
		xfpustate = __builtin_alloca(mcp->mc_xfpustate_len);
		ret = copyin((void *)mcp->mc_xfpustate, xfpustate, mcp->mc_xfpustate_len);
		if (ret != 0)
			return (ret);
	} else xfpustate = NULL;
	ret = set_fpcontext(td, mcp, xfpustate, mcp->mc_xfpustate_len);
	if (ret != 0)
		return (ret);
	tp->tf_r15 = mcp->mc_r15;
	tp->tf_r14 = mcp->mc_r14;
	tp->tf_r13 = mcp->mc_r13;
	tp->tf_r12 = mcp->mc_r12;
	tp->tf_r11 = mcp->mc_r11;
	tp->tf_r10 = mcp->mc_r10;
	tp->tf_r9  = mcp->mc_r9;
	tp->tf_r8  = mcp->mc_r8;
	tp->tf_rdi = mcp->mc_rdi;
	tp->tf_rsi = mcp->mc_rsi;
	tp->tf_rbp = mcp->mc_rbp;
	tp->tf_rbx = mcp->mc_rbx;
	tp->tf_rdx = mcp->mc_rdx;
	tp->tf_rcx = mcp->mc_rcx;
	tp->tf_rax = mcp->mc_rax;
	tp->tf_rip = mcp->mc_rip;
	tp->tf_rflags = rflags;
	tp->tf_rsp = mcp->mc_rsp;
	tp->tf_ss = mcp->mc_ss;
	tp->tf_flags = mcp->mc_flags;
	if (tp->tf_flags & TF_HASSEGS) {
		tp->tf_ds = mcp->mc_ds;
		tp->tf_es = mcp->mc_es;
		tp->tf_fs = mcp->mc_fs;
		tp->tf_gs = mcp->mc_gs;
	}
	if (mcp->mc_flags & _MC_HASBASES) {
		pcb->pcb_fsbase = mcp->mc_fsbase;
		pcb->pcb_gsbase = mcp->mc_gsbase;
	}
	set_pcb_flags(pcb, PCB_FULL_IRET);
	return (0);
}

static void get_fpcontext(struct thread *td, mcontext_t *mcp, char *xfpusave, size_t xfpusave_len)

{
	size_t max_len, len;

	mcp->mc_ownedfp = fpugetregs(td);
	bcopy(get_pcb_user_save_td(td), &mcp->mc_fpstate[0], sizeof(mcp->mc_fpstate));
	mcp->mc_fpformat = fpuformat();
	if (!use_xsave || xfpusave_len == 0)
		return;
	max_len = cpu_max_ext_state_size - sizeof(struct savefpu);
	len = xfpusave_len;
	if (len > max_len) {
		len = max_len;
		bzero(xfpusave + max_len, len - max_len);
	}
	mcp->mc_flags |= _MC_HASFPXSTATE;
	mcp->mc_xfpustate_len = len;
	bcopy(get_pcb_user_save_td(td) + 1, xfpusave, len);
}

static int set_fpcontext(struct thread *td, const mcontext_t *mcp, char *xfpustate, size_t xfpustate_len)

{
	struct savefpu *fpstate;
	int error;

	if (mcp->mc_fpformat == _MC_FPFMT_NODEV)
		return (0);
	else if (mcp->mc_fpformat != _MC_FPFMT_XMM)
		return (EINVAL);
	else if (mcp->mc_ownedfp == _MC_FPOWNED_NONE) {
		
		fpstate_drop(td);
		error = 0;
	} else if (mcp->mc_ownedfp == _MC_FPOWNED_FPU || mcp->mc_ownedfp == _MC_FPOWNED_PCB) {
		fpstate = (struct savefpu *)&mcp->mc_fpstate;
		fpstate->sv_env.en_mxcsr &= cpu_mxcsr_mask;
		error = fpusetregs(td, fpstate, xfpustate, xfpustate_len);
	} else return (EINVAL);
	return (error);
}

void fpstate_drop(struct thread *td)
{

	KASSERT(PCB_USER_FPU(td->td_pcb), ("fpstate_drop: kernel-owned fpu"));
	critical_enter();
	if (PCPU_GET(fpcurthread) == td)
		fpudrop();
	
	clear_pcb_flags(curthread->td_pcb, PCB_FPUINITDONE | PCB_USERFPUINITDONE);
	critical_exit();
}

int fill_dbregs(struct thread *td, struct dbreg *dbregs)
{
	struct pcb *pcb;

	if (td == NULL) {
		dbregs->dr[0] = rdr0();
		dbregs->dr[1] = rdr1();
		dbregs->dr[2] = rdr2();
		dbregs->dr[3] = rdr3();
		dbregs->dr[6] = rdr6();
		dbregs->dr[7] = rdr7();
	} else {
		pcb = td->td_pcb;
		dbregs->dr[0] = pcb->pcb_dr0;
		dbregs->dr[1] = pcb->pcb_dr1;
		dbregs->dr[2] = pcb->pcb_dr2;
		dbregs->dr[3] = pcb->pcb_dr3;
		dbregs->dr[6] = pcb->pcb_dr6;
		dbregs->dr[7] = pcb->pcb_dr7;
	}
	dbregs->dr[4] = 0;
	dbregs->dr[5] = 0;
	dbregs->dr[8] = 0;
	dbregs->dr[9] = 0;
	dbregs->dr[10] = 0;
	dbregs->dr[11] = 0;
	dbregs->dr[12] = 0;
	dbregs->dr[13] = 0;
	dbregs->dr[14] = 0;
	dbregs->dr[15] = 0;
	return (0);
}

int set_dbregs(struct thread *td, struct dbreg *dbregs)
{
	struct pcb *pcb;
	int i;

	if (td == NULL) {
		load_dr0(dbregs->dr[0]);
		load_dr1(dbregs->dr[1]);
		load_dr2(dbregs->dr[2]);
		load_dr3(dbregs->dr[3]);
		load_dr6(dbregs->dr[6]);
		load_dr7(dbregs->dr[7]);
	} else {
		
		for (i = 0; i < 4; i++) {
			if (DBREG_DR7_ACCESS(dbregs->dr[7], i) == 0x02)
				return (EINVAL);
			if (td->td_frame->tf_cs == _ucode32sel && DBREG_DR7_LEN(dbregs->dr[7], i) == DBREG_DR7_LEN_8)
				return (EINVAL);
		}
		if ((dbregs->dr[6] & 0xffffffff00000000ul) != 0 || (dbregs->dr[7] & 0xffffffff00000000ul) != 0)
			return (EINVAL);

		pcb = td->td_pcb;

		

		if (DBREG_DR7_ENABLED(dbregs->dr[7], 0)) {
			
			if (dbregs->dr[0] >= VM_MAXUSER_ADDRESS)
				return (EINVAL);
		}
		if (DBREG_DR7_ENABLED(dbregs->dr[7], 1)) {
			
			if (dbregs->dr[1] >= VM_MAXUSER_ADDRESS)
				return (EINVAL);
		}
		if (DBREG_DR7_ENABLED(dbregs->dr[7], 2)) {
			
			if (dbregs->dr[2] >= VM_MAXUSER_ADDRESS)
				return (EINVAL);
		}
		if (DBREG_DR7_ENABLED(dbregs->dr[7], 3)) {
			
			if (dbregs->dr[3] >= VM_MAXUSER_ADDRESS)
				return (EINVAL);
		}

		pcb->pcb_dr0 = dbregs->dr[0];
		pcb->pcb_dr1 = dbregs->dr[1];
		pcb->pcb_dr2 = dbregs->dr[2];
		pcb->pcb_dr3 = dbregs->dr[3];
		pcb->pcb_dr6 = dbregs->dr[6];
		pcb->pcb_dr7 = dbregs->dr[7];

		set_pcb_flags(pcb, PCB_DBREGS);
	}

	return (0);
}

void reset_dbregs(void)
{

	load_dr7(0);	
	load_dr0(0);
	load_dr1(0);
	load_dr2(0);
	load_dr3(0);
	load_dr6(0);
}


int user_dbreg_trap(void)
{
        u_int64_t dr7, dr6; 
        u_int64_t bp;       
        int nbp;            
        caddr_t addr[4];    
        int i;
        
        dr7 = rdr7();
        if ((dr7 & 0x000000ff) == 0) {
                
                return 0;
        }

        nbp = 0;
        dr6 = rdr6();
        bp = dr6 & 0x0000000f;

        if (!bp) {
                
                return 0;
        }

        

        if (bp & 0x01) {
                addr[nbp++] = (caddr_t)rdr0();
        }
        if (bp & 0x02) {
                addr[nbp++] = (caddr_t)rdr1();
        }
        if (bp & 0x04) {
                addr[nbp++] = (caddr_t)rdr2();
        }
        if (bp & 0x08) {
                addr[nbp++] = (caddr_t)rdr3();
        }

        for (i = 0; i < nbp; i++) {
                if (addr[i] < (caddr_t)VM_MAXUSER_ADDRESS) {
                        
                        return nbp;
                }
        }

        
        return 0;
}






u_char inb_(u_short);
void outb_(u_short, u_char);

u_char inb_(u_short port)
{
	return inb(port);
}

void outb_(u_short port, u_char data)
{
	outb(port, data);
}


