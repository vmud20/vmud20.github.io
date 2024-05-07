


__FBSDID("$FreeBSD$");



























































static __inline void xrstor(char *addr, uint64_t mask)
{
	uint32_t low, hi;

	low = mask;
	hi = mask >> 32;
	__asm __volatile("xrstor %0" : : "m" (*addr), "a" (low), "d" (hi));
}

static __inline void xsave(char *addr, uint64_t mask)
{
	uint32_t low, hi;

	low = mask;
	hi = mask >> 32;
	__asm __volatile("xsave %0" : "=m" (*addr) : "a" (low), "d" (hi) :
	    "memory");
}

static __inline void xsaveopt(char *addr, uint64_t mask)
{
	uint32_t low, hi;

	low = mask;
	hi = mask >> 32;
	__asm __volatile("xsaveopt %0" : "=m" (*addr) : "a" (low), "d" (hi) :
	    "memory");
}


void	fldcw(u_short cw);
void	fnclex(void);
void	fninit(void);
void	fnsave(caddr_t addr);
void	fnstcw(caddr_t addr);
void	fnstsw(caddr_t addr);
void	fp_divide_by_0(void);
void	frstor(caddr_t addr);
void	fxsave(caddr_t addr);
void	fxrstor(caddr_t addr);
void	ldmxcsr(u_int csr);
void	stmxcsr(u_int *csr);
void	xrstor(char *addr, uint64_t mask);
void	xsave(char *addr, uint64_t mask);
void	xsaveopt(char *addr, uint64_t mask);


















CTASSERT(sizeof(union savefpu) == 512);
CTASSERT(sizeof(struct xstate_hdr) == 64);
CTASSERT(sizeof(struct savefpu_ymm) == 832);


CTASSERT(sizeof(struct pcb) % XSAVE_AREA_ALIGN == 0);


CTASSERT(X86_XSTATE_XCR0_OFFSET >= offsetof(struct savexmm, sv_pad) && X86_XSTATE_XCR0_OFFSET + sizeof(uint64_t) <= sizeof(struct savexmm));

static	void	fpu_clean_state(void);

static	void	fpusave(union savefpu *);
static	void	fpurstor(union savefpu *);

int	hw_float;

SYSCTL_INT(_hw, HW_FLOATINGPT, floatingpoint, CTLFLAG_RD, &hw_float, 0, "Floating point instructions executed in hardware");

int use_xsave;
uint64_t xsave_mask;
static	uma_zone_t fpu_save_area_zone;
static	union savefpu *npx_initialstate;

struct xsave_area_elm_descr {
	u_int	offset;
	u_int	size;
} *xsave_area_desc;

static int use_xsaveopt;

static	volatile u_int		npx_traps_while_probing;

alias_for_inthand_t probetrap;
__asm("								\n .text							\n .p2align 2,0x90						\n .type	" __XSTRING(CNAME(probetrap)) ",@function	\n " __XSTRING(CNAME(probetrap)) ":				\n ss							\n incl	" __XSTRING(CNAME(npx_traps_while_probing)) "	\n fnclex							\n iret							\n ")










static int npx_probe(void)
{
	struct gate_descriptor save_idt_npxtrap;
	u_short control, status;

	
	if (cpu_feature & CPUID_FPU) {
		hw_float = 1;
		return (1);
	}

	save_idt_npxtrap = idt[IDT_MF];
	setidt(IDT_MF, probetrap, SDT_SYS386TGT, SEL_KPL, GSEL(GCODE_SEL, SEL_KPL));

	
	stop_emulating();

	
	fninit();

	
	DELAY(1000);		

	if (npx_traps_while_probing != 0)
		printf("fninit caused %u bogus npx trap(s)\n", npx_traps_while_probing);

	
	status = 0x5a5a;
	fnstsw(&status);
	if ((status & 0xb8ff) == 0) {
		
		control = 0x5a5a;
		fnstcw(&control);
		if ((control & 0x1f3f) == 0x033f) {
			
			control &= ~(1 << 2);	
			fldcw(control);
			npx_traps_while_probing = 0;
			fp_divide_by_0();
			if (npx_traps_while_probing != 0) {
				
				hw_float = 1;
				goto cleanup;
			}
			printf( "FPU does not use exception 16 for error reporting\n");
			goto cleanup;
		}
	}

	
	printf("WARNING: no FPU!\n");
	__asm __volatile("smsw %%ax; orb %0,%%al; lmsw %%ax" : :
	    "n" (CR0_EM | CR0_MP) : "ax");

cleanup:
	idt[IDT_MF] = save_idt_npxtrap;
	return (hw_float);
}


static void npxinit_bsp1(void)
{
	u_int cp[4];
	uint64_t xsave_mask_user;

	if (cpu_fxsr && (cpu_feature2 & CPUID2_XSAVE) != 0) {
		use_xsave = 1;
		TUNABLE_INT_FETCH("hw.use_xsave", &use_xsave);
	}
	if (!use_xsave)
		return;

	cpuid_count(0xd, 0x0, cp);
	xsave_mask = XFEATURE_ENABLED_X87 | XFEATURE_ENABLED_SSE;
	if ((cp[0] & xsave_mask) != xsave_mask)
		panic("CPU0 does not support X87 or SSE: %x", cp[0]);
	xsave_mask = ((uint64_t)cp[3] << 32) | cp[0];
	xsave_mask_user = xsave_mask;
	TUNABLE_QUAD_FETCH("hw.xsave_mask", &xsave_mask_user);
	xsave_mask_user |= XFEATURE_ENABLED_X87 | XFEATURE_ENABLED_SSE;
	xsave_mask &= xsave_mask_user;
	if ((xsave_mask & XFEATURE_AVX512) != XFEATURE_AVX512)
		xsave_mask &= ~XFEATURE_AVX512;
	if ((xsave_mask & XFEATURE_MPX) != XFEATURE_MPX)
		xsave_mask &= ~XFEATURE_MPX;

	cpuid_count(0xd, 0x1, cp);
	if ((cp[0] & CPUID_EXTSTATE_XSAVEOPT) != 0)
		use_xsaveopt = 1;
}


static void npxinit_bsp2(void)
{
	u_int cp[4];

	if (use_xsave) {
		cpuid_count(0xd, 0x0, cp);
		cpu_max_ext_state_size = cp[1];

		
		do_cpuid(1, cp);
		cpu_feature2 = cp[2];
	} else cpu_max_ext_state_size = sizeof(union savefpu);
}


void npxinit(bool bsp)
{
	static union savefpu dummy;
	register_t saveintr;
	u_int mxcsr;
	u_short control;

	if (bsp) {
		if (!npx_probe())
			return;
		npxinit_bsp1();
	}

	if (use_xsave) {
		load_cr4(rcr4() | CR4_XSAVE);
		load_xcr(XCR0, xsave_mask);
	}

	
	if (bsp)
		npxinit_bsp2();
	
	
	saveintr = intr_disable();
	stop_emulating();
	if (cpu_fxsr)
		fninit();
	else fnsave(&dummy);
	control = __INITIAL_NPXCW__;
	fldcw(control);
	if (cpu_fxsr) {
		mxcsr = __INITIAL_MXCSR__;
		ldmxcsr(mxcsr);
	}
	start_emulating();
	intr_restore(saveintr);
}


static void npxinitstate(void *arg __unused)
{
	register_t saveintr;
	int cp[4], i, max_ext_n;

	if (!hw_float)
		return;

	npx_initialstate = malloc(cpu_max_ext_state_size, M_DEVBUF, M_WAITOK | M_ZERO);
	saveintr = intr_disable();
	stop_emulating();

	fpusave(npx_initialstate);
	if (cpu_fxsr) {
		if (npx_initialstate->sv_xmm.sv_env.en_mxcsr_mask)
			cpu_mxcsr_mask =  npx_initialstate->sv_xmm.sv_env.en_mxcsr_mask;
		else cpu_mxcsr_mask = 0xFFBF;

		
		bzero(npx_initialstate->sv_xmm.sv_fp, sizeof(npx_initialstate->sv_xmm.sv_fp));
		bzero(npx_initialstate->sv_xmm.sv_xmm, sizeof(npx_initialstate->sv_xmm.sv_xmm));
	} else bzero(npx_initialstate->sv_87.sv_ac, sizeof(npx_initialstate->sv_87.sv_ac));


	
	if (use_xsave) {
		if (xsave_mask >> 32 != 0)
			max_ext_n = fls(xsave_mask >> 32) + 32;
		else max_ext_n = fls(xsave_mask);
		xsave_area_desc = malloc(max_ext_n * sizeof(struct xsave_area_elm_descr), M_DEVBUF, M_WAITOK | M_ZERO);
		
		xsave_area_desc[0].offset = 0;
		xsave_area_desc[0].size = 160;
		
		xsave_area_desc[1].offset = 160;
		xsave_area_desc[1].size = 288 - 160;

		for (i = 2; i < max_ext_n; i++) {
			cpuid_count(0xd, i, cp);
			xsave_area_desc[i].offset = cp[1];
			xsave_area_desc[i].size = cp[0];
		}
	}

	fpu_save_area_zone = uma_zcreate("FPU_save_area", cpu_max_ext_state_size, NULL, NULL, NULL, NULL, XSAVE_AREA_ALIGN - 1, 0);


	start_emulating();
	intr_restore(saveintr);
}
SYSINIT(npxinitstate, SI_SUB_DRIVERS, SI_ORDER_ANY, npxinitstate, NULL);


void npxexit(struct thread *td)
{

	critical_enter();
	if (curthread == PCPU_GET(fpcurthread)) {
		stop_emulating();
		fpusave(curpcb->pcb_save);
		start_emulating();
		PCPU_SET(fpcurthread, NULL);
	}
	critical_exit();

	if (hw_float) {
		u_int	masked_exceptions;

		masked_exceptions = GET_FPU_CW(td) & GET_FPU_SW(td) & 0x7f;
		
		if (masked_exceptions & 0x0d)
			log(LOG_ERR, "pid %d (%s) exited with masked floating point exceptions 0x%02x\n", td->td_proc->p_pid, td->td_proc->p_comm, masked_exceptions);


	}

}

int npxformat(void)
{

	if (!hw_float)
		return (_MC_FPFMT_NODEV);
	if (cpu_fxsr)
		return (_MC_FPFMT_XMM);
	return (_MC_FPFMT_387);
}


static char fpetable[128] = {
	0, FPE_FLTINV, FPE_FLTUND, FPE_FLTINV, FPE_FLTDIV, FPE_FLTINV, FPE_FLTDIV, FPE_FLTINV, FPE_FLTOVF, FPE_FLTINV, FPE_FLTUND, FPE_FLTINV, FPE_FLTDIV, FPE_FLTINV, FPE_FLTDIV, FPE_FLTINV, FPE_FLTUND, FPE_FLTINV, FPE_FLTUND, FPE_FLTINV, FPE_FLTDIV, FPE_FLTINV, FPE_FLTDIV, FPE_FLTINV, FPE_FLTOVF, FPE_FLTINV, FPE_FLTUND, FPE_FLTINV, FPE_FLTDIV, FPE_FLTINV, FPE_FLTDIV, FPE_FLTINV, FPE_FLTRES, FPE_FLTINV, FPE_FLTUND, FPE_FLTINV, FPE_FLTDIV, FPE_FLTINV, FPE_FLTDIV, FPE_FLTINV, FPE_FLTOVF, FPE_FLTINV, FPE_FLTUND, FPE_FLTINV, FPE_FLTDIV, FPE_FLTINV, FPE_FLTDIV, FPE_FLTINV, FPE_FLTUND, FPE_FLTINV, FPE_FLTUND, FPE_FLTINV, FPE_FLTDIV, FPE_FLTINV, FPE_FLTDIV, FPE_FLTINV, FPE_FLTOVF, FPE_FLTINV, FPE_FLTUND, FPE_FLTINV, FPE_FLTDIV, FPE_FLTINV, FPE_FLTDIV, FPE_FLTINV, FPE_FLTSUB, FPE_FLTSUB, FPE_FLTUND, FPE_FLTSUB, FPE_FLTDIV, FPE_FLTSUB, FPE_FLTDIV, FPE_FLTSUB, FPE_FLTOVF, FPE_FLTSUB, FPE_FLTUND, FPE_FLTSUB, FPE_FLTDIV, FPE_FLTSUB, FPE_FLTDIV, FPE_FLTSUB, FPE_FLTUND, FPE_FLTSUB, FPE_FLTUND, FPE_FLTSUB, FPE_FLTDIV, FPE_FLTSUB, FPE_FLTDIV, FPE_FLTSUB, FPE_FLTOVF, FPE_FLTSUB, FPE_FLTUND, FPE_FLTSUB, FPE_FLTDIV, FPE_FLTSUB, FPE_FLTDIV, FPE_FLTSUB, FPE_FLTRES, FPE_FLTSUB, FPE_FLTUND, FPE_FLTSUB, FPE_FLTDIV, FPE_FLTSUB, FPE_FLTDIV, FPE_FLTSUB, FPE_FLTOVF, FPE_FLTSUB, FPE_FLTUND, FPE_FLTSUB, FPE_FLTDIV, FPE_FLTSUB, FPE_FLTDIV, FPE_FLTSUB, FPE_FLTUND, FPE_FLTSUB, FPE_FLTUND, FPE_FLTSUB, FPE_FLTDIV, FPE_FLTSUB, FPE_FLTDIV, FPE_FLTSUB, FPE_FLTOVF, FPE_FLTSUB, FPE_FLTUND, FPE_FLTSUB, FPE_FLTDIV, FPE_FLTSUB, FPE_FLTDIV, FPE_FLTSUB, };

































































































































int npxtrap_x87(void)
{
	u_short control, status;

	if (!hw_float) {
		printf( "npxtrap_x87: fpcurthread = %p, curthread = %p, hw_float = %d\n", PCPU_GET(fpcurthread), curthread, hw_float);

		panic("npxtrap from nowhere");
	}
	critical_enter();

	
	if (PCPU_GET(fpcurthread) != curthread) {
		control = GET_FPU_CW(curthread);
		status = GET_FPU_SW(curthread);
	} else {
		fnstcw(&control);
		fnstsw(&status);
	}
	critical_exit();
	return (fpetable[status & ((~control & 0x3f) | 0x40)]);
}

int npxtrap_sse(void)
{
	u_int mxcsr;

	if (!hw_float) {
		printf( "npxtrap_sse: fpcurthread = %p, curthread = %p, hw_float = %d\n", PCPU_GET(fpcurthread), curthread, hw_float);

		panic("npxtrap from nowhere");
	}
	critical_enter();
	if (PCPU_GET(fpcurthread) != curthread)
		mxcsr = curthread->td_pcb->pcb_save->sv_xmm.sv_env.en_mxcsr;
	else stmxcsr(&mxcsr);
	critical_exit();
	return (fpetable[(mxcsr & (~mxcsr >> 7)) & 0x3f]);
}



static int err_count = 0;

int npxdna(void)
{

	if (!hw_float)
		return (0);
	critical_enter();
	if (PCPU_GET(fpcurthread) == curthread) {
		printf("npxdna: fpcurthread == curthread %d times\n", ++err_count);
		stop_emulating();
		critical_exit();
		return (1);
	}
	if (PCPU_GET(fpcurthread) != NULL) {
		printf("npxdna: fpcurthread = %p (%d), curthread = %p (%d)\n", PCPU_GET(fpcurthread), PCPU_GET(fpcurthread)->td_proc->p_pid, curthread, curthread->td_proc->p_pid);


		panic("npxdna");
	}
	stop_emulating();
	
	PCPU_SET(fpcurthread, curthread);

	if (cpu_fxsr)
		fpu_clean_state();

	if ((curpcb->pcb_flags & PCB_NPXINITDONE) == 0) {
		
		bcopy(npx_initialstate, curpcb->pcb_save, cpu_max_ext_state_size);
		fpurstor(curpcb->pcb_save);
		if (curpcb->pcb_initial_npxcw != __INITIAL_NPXCW__)
			fldcw(curpcb->pcb_initial_npxcw);
		curpcb->pcb_flags |= PCB_NPXINITDONE;
		if (PCB_USER_FPU(curpcb))
			curpcb->pcb_flags |= PCB_NPXUSERINITDONE;
	} else {
		fpurstor(curpcb->pcb_save);
	}
	critical_exit();

	return (1);
}


void npxsave(addr)
	union savefpu *addr;
{

	stop_emulating();
	if (use_xsaveopt)
		xsaveopt((char *)addr, xsave_mask);
	else fpusave(addr);
	start_emulating();
	PCPU_SET(fpcurthread, NULL);
}


void npxsuspend(union savefpu *addr)
{
	register_t cr0;

	if (!hw_float)
		return;
	if (PCPU_GET(fpcurthread) == NULL) {
		bcopy(npx_initialstate, addr, cpu_max_ext_state_size);
		return;
	}
	cr0 = rcr0();
	stop_emulating();
	fpusave(addr);
	load_cr0(cr0);
}

void npxresume(union savefpu *addr)
{
	register_t cr0;

	if (!hw_float)
		return;

	cr0 = rcr0();
	npxinit(false);
	stop_emulating();
	fpurstor(addr);
	load_cr0(cr0);
}

void npxdrop(void)
{
	struct thread *td;

	
	if (!cpu_fxsr)
		fnclex();

	td = PCPU_GET(fpcurthread);
	KASSERT(td == curthread, ("fpudrop: fpcurthread != curthread"));
	CRITICAL_ASSERT(td);
	PCPU_SET(fpcurthread, NULL);
	td->td_pcb->pcb_flags &= ~PCB_NPXINITDONE;
	start_emulating();
}


int npxgetregs(struct thread *td)
{
	struct pcb *pcb;
	uint64_t *xstate_bv, bit;
	char *sa;
	int max_ext_n, i;
	int owned;

	if (!hw_float)
		return (_MC_FPOWNED_NONE);

	pcb = td->td_pcb;
	if ((pcb->pcb_flags & PCB_NPXINITDONE) == 0) {
		bcopy(npx_initialstate, get_pcb_user_save_pcb(pcb), cpu_max_ext_state_size);
		SET_FPU_CW(get_pcb_user_save_pcb(pcb), pcb->pcb_initial_npxcw);
		npxuserinited(td);
		return (_MC_FPOWNED_PCB);
	}
	critical_enter();
	if (td == PCPU_GET(fpcurthread)) {
		fpusave(get_pcb_user_save_pcb(pcb));
		if (!cpu_fxsr)
			
			npxdrop();
		owned = _MC_FPOWNED_FPU;
	} else {
		owned = _MC_FPOWNED_PCB;
	}
	critical_exit();
	if (use_xsave) {
		
		sa = (char *)get_pcb_user_save_pcb(pcb);
		xstate_bv = (uint64_t *)(sa + sizeof(union savefpu) + offsetof(struct xstate_hdr, xstate_bv));
		if (xsave_mask >> 32 != 0)
			max_ext_n = fls(xsave_mask >> 32) + 32;
		else max_ext_n = fls(xsave_mask);
		for (i = 0; i < max_ext_n; i++) {
			bit = 1ULL << i;
			if ((xsave_mask & bit) == 0 || (*xstate_bv & bit) != 0)
				continue;
			bcopy((char *)npx_initialstate + xsave_area_desc[i].offset, sa + xsave_area_desc[i].offset, xsave_area_desc[i].size);


			*xstate_bv |= bit;
		}
	}
	return (owned);
}

void npxuserinited(struct thread *td)
{
	struct pcb *pcb;

	pcb = td->td_pcb;
	if (PCB_USER_FPU(pcb))
		pcb->pcb_flags |= PCB_NPXINITDONE;
	pcb->pcb_flags |= PCB_NPXUSERINITDONE;
}

int npxsetxstate(struct thread *td, char *xfpustate, size_t xfpustate_size)
{
	struct xstate_hdr *hdr, *ehdr;
	size_t len, max_len;
	uint64_t bv;

	
	if (xfpustate == NULL)
		return (0);
	if (!use_xsave)
		return (EOPNOTSUPP);

	len = xfpustate_size;
	if (len < sizeof(struct xstate_hdr))
		return (EINVAL);
	max_len = cpu_max_ext_state_size - sizeof(union savefpu);
	if (len > max_len)
		return (EINVAL);

	ehdr = (struct xstate_hdr *)xfpustate;
	bv = ehdr->xstate_bv;

	
	if (bv & ~xsave_mask)
		return (EINVAL);

	hdr = (struct xstate_hdr *)(get_pcb_user_save_td(td) + 1);

	hdr->xstate_bv = bv;
	bcopy(xfpustate + sizeof(struct xstate_hdr), (char *)(hdr + 1), len - sizeof(struct xstate_hdr));

	return (0);
}

int npxsetregs(struct thread *td, union savefpu *addr, char *xfpustate, size_t xfpustate_size)

{
	struct pcb *pcb;
	int error;

	if (!hw_float)
		return (ENXIO);

	if (cpu_fxsr)
		addr->sv_xmm.sv_env.en_mxcsr &= cpu_mxcsr_mask;
	pcb = td->td_pcb;
	critical_enter();
	if (td == PCPU_GET(fpcurthread) && PCB_USER_FPU(pcb)) {
		error = npxsetxstate(td, xfpustate, xfpustate_size);
		if (error != 0) {
			critical_exit();
			return (error);
		}
		if (!cpu_fxsr)
			fnclex();	
		bcopy(addr, get_pcb_user_save_td(td), sizeof(*addr));
		fpurstor(get_pcb_user_save_td(td));
		critical_exit();
		pcb->pcb_flags |= PCB_NPXUSERINITDONE | PCB_NPXINITDONE;
	} else {
		critical_exit();
		error = npxsetxstate(td, xfpustate, xfpustate_size);
		if (error != 0)
			return (error);
		bcopy(addr, get_pcb_user_save_td(td), sizeof(*addr));
		npxuserinited(td);
	}
	return (0);
}

static void fpusave(addr)
	union savefpu *addr;
{
	
	if (use_xsave)
		xsave((char *)addr, xsave_mask);
	else if (cpu_fxsr)
		fxsave(addr);
	else fnsave(addr);
}

static void npx_fill_fpregs_xmm1(struct savexmm *sv_xmm, struct save87 *sv_87)
{
	struct env87 *penv_87;
	struct envxmm *penv_xmm;
	int i;

	penv_87 = &sv_87->sv_env;
	penv_xmm = &sv_xmm->sv_env;

	
	penv_87->en_cw = penv_xmm->en_cw;
	penv_87->en_sw = penv_xmm->en_sw;
	penv_87->en_fip = penv_xmm->en_fip;
	penv_87->en_fcs = penv_xmm->en_fcs;
	penv_87->en_opcode = penv_xmm->en_opcode;
	penv_87->en_foo = penv_xmm->en_foo;
	penv_87->en_fos = penv_xmm->en_fos;

	
	penv_87->en_tw = 0xffff;
	for (i = 0; i < 8; ++i) {
		sv_87->sv_ac[i] = sv_xmm->sv_fp[i].fp_acc;
		if ((penv_xmm->en_tw & (1 << i)) != 0)
			
			penv_87->en_tw &= ~(3 << i * 2);
	}
}

void npx_fill_fpregs_xmm(struct savexmm *sv_xmm, struct save87 *sv_87)
{

	bzero(sv_87, sizeof(*sv_87));
	npx_fill_fpregs_xmm1(sv_xmm, sv_87);
}

void npx_set_fpregs_xmm(struct save87 *sv_87, struct savexmm *sv_xmm)
{
	struct env87 *penv_87;
	struct envxmm *penv_xmm;
	int i;

	penv_87 = &sv_87->sv_env;
	penv_xmm = &sv_xmm->sv_env;

	
	penv_xmm->en_cw = penv_87->en_cw;
	penv_xmm->en_sw = penv_87->en_sw;
	penv_xmm->en_fip = penv_87->en_fip;
	penv_xmm->en_fcs = penv_87->en_fcs;
	penv_xmm->en_opcode = penv_87->en_opcode;
	penv_xmm->en_foo = penv_87->en_foo;
	penv_xmm->en_fos = penv_87->en_fos;

	
	penv_xmm->en_tw = 0;
	for (i = 0; i < 8; ++i) {
		sv_xmm->sv_fp[i].fp_acc = sv_87->sv_ac[i];
		if ((penv_87->en_tw & (3 << i * 2)) != (3 << i * 2))
			penv_xmm->en_tw |= 1 << i;
	}
}

void npx_get_fsave(void *addr)
{
	struct thread *td;
	union savefpu *sv;

	td = curthread;
	npxgetregs(td);
	sv = get_pcb_user_save_td(td);
	if (cpu_fxsr)
		npx_fill_fpregs_xmm1(&sv->sv_xmm, addr);
	else bcopy(sv, addr, sizeof(struct env87) + sizeof(struct fpacc87[8]));

}

int npx_set_fsave(void *addr)
{
	union savefpu sv;
	int error;

	bzero(&sv, sizeof(sv));
	if (cpu_fxsr)
		npx_set_fpregs_xmm(addr, &sv.sv_xmm);
	else bcopy(addr, &sv, sizeof(struct env87) + sizeof(struct fpacc87[8]));

	error = npxsetregs(curthread, &sv, NULL, 0);
	return (error);
}


static void fpu_clean_state(void)
{
	static float dummy_variable = 0.0;
	u_short status;

	
	fnstsw(&status);
	if (status & 0x80)
		fnclex();

	
	__asm __volatile("ffree %%st(7); flds %0" : : "m" (dummy_variable));
}

static void fpurstor(union savefpu *addr)
{

	if (use_xsave)
		xrstor((char *)addr, xsave_mask);
	else if (cpu_fxsr)
		fxrstor(addr);
	else frstor(addr);
}



static struct isa_pnp_id npxisa_ids[] = {
	{ 0x040cd041, "Legacy ISA coprocessor support" },  { 0 }
};

static int npxisa_probe(device_t dev)
{
	int result;
	if ((result = ISA_PNP_PROBE(device_get_parent(dev), dev, npxisa_ids)) <= 0) {
		device_quiet(dev);
	}
	return(result);
}

static int npxisa_attach(device_t dev)
{
	return (0);
}

static device_method_t npxisa_methods[] = {
	
	DEVMETHOD(device_probe,		npxisa_probe), DEVMETHOD(device_attach,	npxisa_attach), DEVMETHOD(device_detach,	bus_generic_detach), DEVMETHOD(device_shutdown,	bus_generic_shutdown), DEVMETHOD(device_suspend,	bus_generic_suspend), DEVMETHOD(device_resume,	bus_generic_resume),  { 0, 0 }






};

static driver_t npxisa_driver = {
	"npxisa", npxisa_methods, 1, };



static devclass_t npxisa_devclass;

DRIVER_MODULE(npxisa, isa, npxisa_driver, npxisa_devclass, 0, 0);
DRIVER_MODULE(npxisa, acpi, npxisa_driver, npxisa_devclass, 0, 0);
ISA_PNP_INFO(npxisa_ids);


static MALLOC_DEFINE(M_FPUKERN_CTX, "fpukern_ctx", "Kernel contexts for FPU state");





struct fpu_kern_ctx {
	union savefpu *prev;
	uint32_t flags;
	char hwstate1[];
};

struct fpu_kern_ctx * fpu_kern_alloc_ctx(u_int flags)
{
	struct fpu_kern_ctx *res;
	size_t sz;

	sz = sizeof(struct fpu_kern_ctx) + XSAVE_AREA_ALIGN + cpu_max_ext_state_size;
	res = malloc(sz, M_FPUKERN_CTX, ((flags & FPU_KERN_NOWAIT) ? M_NOWAIT : M_WAITOK) | M_ZERO);
	return (res);
}

void fpu_kern_free_ctx(struct fpu_kern_ctx *ctx)
{

	KASSERT((ctx->flags & FPU_KERN_CTX_INUSE) == 0, ("free'ing inuse ctx"));
	
	free(ctx, M_FPUKERN_CTX);
}

static union savefpu * fpu_kern_ctx_savefpu(struct fpu_kern_ctx *ctx)
{
	vm_offset_t p;

	p = (vm_offset_t)&ctx->hwstate1;
	p = roundup2(p, XSAVE_AREA_ALIGN);
	return ((union savefpu *)p);
}

void fpu_kern_enter(struct thread *td, struct fpu_kern_ctx *ctx, u_int flags)
{
	struct pcb *pcb;

	KASSERT((ctx->flags & FPU_KERN_CTX_INUSE) == 0, ("using inuse ctx"));

	if ((flags & FPU_KERN_KTHR) != 0 && is_fpu_kern_thread(0)) {
		ctx->flags = FPU_KERN_CTX_DUMMY | FPU_KERN_CTX_INUSE;
		return;
	}
	pcb = td->td_pcb;
	KASSERT(!PCB_USER_FPU(pcb) || pcb->pcb_save == get_pcb_user_save_pcb(pcb), ("mangled pcb_save"));
	ctx->flags = FPU_KERN_CTX_INUSE;
	if ((pcb->pcb_flags & PCB_NPXINITDONE) != 0)
		ctx->flags |= FPU_KERN_CTX_NPXINITDONE;
	npxexit(td);
	ctx->prev = pcb->pcb_save;
	pcb->pcb_save = fpu_kern_ctx_savefpu(ctx);
	pcb->pcb_flags |= PCB_KERNNPX;
	pcb->pcb_flags &= ~PCB_NPXINITDONE;
	return;
}

int fpu_kern_leave(struct thread *td, struct fpu_kern_ctx *ctx)
{
	struct pcb *pcb;

	KASSERT((ctx->flags & FPU_KERN_CTX_INUSE) != 0, ("leaving not inuse ctx"));
	ctx->flags &= ~FPU_KERN_CTX_INUSE;

	if (is_fpu_kern_thread(0) && (ctx->flags & FPU_KERN_CTX_DUMMY) != 0)
		return (0);
	pcb = td->td_pcb;
	critical_enter();
	if (curthread == PCPU_GET(fpcurthread))
		npxdrop();
	critical_exit();
	pcb->pcb_save = ctx->prev;
	if (pcb->pcb_save == get_pcb_user_save_pcb(pcb)) {
		if ((pcb->pcb_flags & PCB_NPXUSERINITDONE) != 0)
			pcb->pcb_flags |= PCB_NPXINITDONE;
		else pcb->pcb_flags &= ~PCB_NPXINITDONE;
		pcb->pcb_flags &= ~PCB_KERNNPX;
	} else {
		if ((ctx->flags & FPU_KERN_CTX_NPXINITDONE) != 0)
			pcb->pcb_flags |= PCB_NPXINITDONE;
		else pcb->pcb_flags &= ~PCB_NPXINITDONE;
		KASSERT(!PCB_USER_FPU(pcb), ("unpaired fpu_kern_leave"));
	}
	return (0);
}

int fpu_kern_thread(u_int flags)
{

	KASSERT((curthread->td_pflags & TDP_KTHREAD) != 0, ("Only kthread may use fpu_kern_thread"));
	KASSERT(curpcb->pcb_save == get_pcb_user_save_pcb(curpcb), ("mangled pcb_save"));
	KASSERT(PCB_USER_FPU(curpcb), ("recursive call"));

	curpcb->pcb_flags |= PCB_KERNNPX;
	return (0);
}

int is_fpu_kern_thread(u_int flags)
{

	if ((curthread->td_pflags & TDP_KTHREAD) == 0)
		return (0);
	return ((curpcb->pcb_flags & PCB_KERNNPX) != 0);
}


union savefpu * fpu_save_area_alloc(void)
{

	return (uma_zalloc(fpu_save_area_zone, 0));
}

void fpu_save_area_free(union savefpu *fsa)
{

	uma_zfree(fpu_save_area_zone, fsa);
}

void fpu_save_area_reset(union savefpu *fsa)
{

	bcopy(npx_initialstate, fsa, cpu_max_ext_state_size);
}
