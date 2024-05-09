



































































extern unsigned long _get_SP(void);



bool tm_suspend_disabled __ro_after_init = false;

static void check_if_tm_restore_required(struct task_struct *tsk)
{
	
	if (tsk == current && tsk->thread.regs && MSR_TM_ACTIVE(tsk->thread.regs->msr) && !test_thread_flag(TIF_RESTORE_TM)) {

		tsk->thread.ckpt_regs.msr = tsk->thread.regs->msr;
		set_thread_flag(TIF_RESTORE_TM);
	}
}

static bool tm_active_with_fp(struct task_struct *tsk)
{
	return MSR_TM_ACTIVE(tsk->thread.regs->msr) && (tsk->thread.ckpt_regs.msr & MSR_FP);
}

static bool tm_active_with_altivec(struct task_struct *tsk)
{
	return MSR_TM_ACTIVE(tsk->thread.regs->msr) && (tsk->thread.ckpt_regs.msr & MSR_VEC);
}

static inline void check_if_tm_restore_required(struct task_struct *tsk) { }
static inline bool tm_active_with_fp(struct task_struct *tsk) { return false; }
static inline bool tm_active_with_altivec(struct task_struct *tsk) { return false; }


bool strict_msr_control;
EXPORT_SYMBOL(strict_msr_control);

static int __init enable_strict_msr_control(char *str)
{
	strict_msr_control = true;
	pr_info("Enabling strict facility control\n");

	return 0;
}
early_param("ppc_strict_facility_enable", enable_strict_msr_control);


unsigned long notrace msr_check_and_set(unsigned long bits)
{
	unsigned long oldmsr = mfmsr();
	unsigned long newmsr;

	newmsr = oldmsr | bits;


	if (cpu_has_feature(CPU_FTR_VSX) && (bits & MSR_FP))
		newmsr |= MSR_VSX;


	if (oldmsr != newmsr)
		mtmsr_isync(newmsr);

	return newmsr;
}
EXPORT_SYMBOL_GPL(msr_check_and_set);


void notrace __msr_check_and_clear(unsigned long bits)
{
	unsigned long oldmsr = mfmsr();
	unsigned long newmsr;

	newmsr = oldmsr & ~bits;


	if (cpu_has_feature(CPU_FTR_VSX) && (bits & MSR_FP))
		newmsr &= ~MSR_VSX;


	if (oldmsr != newmsr)
		mtmsr_isync(newmsr);
}
EXPORT_SYMBOL(__msr_check_and_clear);


static void __giveup_fpu(struct task_struct *tsk)
{
	unsigned long msr;

	save_fpu(tsk);
	msr = tsk->thread.regs->msr;
	msr &= ~(MSR_FP|MSR_FE0|MSR_FE1);

	if (cpu_has_feature(CPU_FTR_VSX))
		msr &= ~MSR_VSX;

	tsk->thread.regs->msr = msr;
}

void giveup_fpu(struct task_struct *tsk)
{
	check_if_tm_restore_required(tsk);

	msr_check_and_set(MSR_FP);
	__giveup_fpu(tsk);
	msr_check_and_clear(MSR_FP);
}
EXPORT_SYMBOL(giveup_fpu);


void flush_fp_to_thread(struct task_struct *tsk)
{
	if (tsk->thread.regs) {
		
		preempt_disable();
		if (tsk->thread.regs->msr & MSR_FP) {
			
			BUG_ON(tsk != current);
			giveup_fpu(tsk);
		}
		preempt_enable();
	}
}
EXPORT_SYMBOL_GPL(flush_fp_to_thread);

void enable_kernel_fp(void)
{
	unsigned long cpumsr;

	WARN_ON(preemptible());

	cpumsr = msr_check_and_set(MSR_FP);

	if (current->thread.regs && (current->thread.regs->msr & MSR_FP)) {
		check_if_tm_restore_required(current);
		
		if (!MSR_TM_ACTIVE(cpumsr) && MSR_TM_ACTIVE(current->thread.regs->msr))
			return;
		__giveup_fpu(current);
	}
}
EXPORT_SYMBOL(enable_kernel_fp);

static int restore_fp(struct task_struct *tsk)
{
	if (tsk->thread.load_fp || tm_active_with_fp(tsk)) {
		load_fp_state(&current->thread.fp_state);
		current->thread.load_fp++;
		return 1;
	}
	return 0;
}

static int restore_fp(struct task_struct *tsk) { return 0; }





static void __giveup_altivec(struct task_struct *tsk)
{
	unsigned long msr;

	save_altivec(tsk);
	msr = tsk->thread.regs->msr;
	msr &= ~MSR_VEC;

	if (cpu_has_feature(CPU_FTR_VSX))
		msr &= ~MSR_VSX;

	tsk->thread.regs->msr = msr;
}

void giveup_altivec(struct task_struct *tsk)
{
	check_if_tm_restore_required(tsk);

	msr_check_and_set(MSR_VEC);
	__giveup_altivec(tsk);
	msr_check_and_clear(MSR_VEC);
}
EXPORT_SYMBOL(giveup_altivec);

void enable_kernel_altivec(void)
{
	unsigned long cpumsr;

	WARN_ON(preemptible());

	cpumsr = msr_check_and_set(MSR_VEC);

	if (current->thread.regs && (current->thread.regs->msr & MSR_VEC)) {
		check_if_tm_restore_required(current);
		
		if (!MSR_TM_ACTIVE(cpumsr) && MSR_TM_ACTIVE(current->thread.regs->msr))
			return;
		__giveup_altivec(current);
	}
}
EXPORT_SYMBOL(enable_kernel_altivec);


void flush_altivec_to_thread(struct task_struct *tsk)
{
	if (tsk->thread.regs) {
		preempt_disable();
		if (tsk->thread.regs->msr & MSR_VEC) {
			BUG_ON(tsk != current);
			giveup_altivec(tsk);
		}
		preempt_enable();
	}
}
EXPORT_SYMBOL_GPL(flush_altivec_to_thread);

static int restore_altivec(struct task_struct *tsk)
{
	if (cpu_has_feature(CPU_FTR_ALTIVEC) && (tsk->thread.load_vec || tm_active_with_altivec(tsk))) {
		load_vr_state(&tsk->thread.vr_state);
		tsk->thread.used_vr = 1;
		tsk->thread.load_vec++;

		return 1;
	}
	return 0;
}


static inline int restore_altivec(struct task_struct *tsk) { return 0; }



static void __giveup_vsx(struct task_struct *tsk)
{
	unsigned long msr = tsk->thread.regs->msr;

	
	WARN_ON((msr & MSR_VSX) && !((msr & MSR_FP) && (msr & MSR_VEC)));

	
	if (msr & MSR_FP)
		__giveup_fpu(tsk);
	if (msr & MSR_VEC)
		__giveup_altivec(tsk);
}

static void giveup_vsx(struct task_struct *tsk)
{
	check_if_tm_restore_required(tsk);

	msr_check_and_set(MSR_FP|MSR_VEC|MSR_VSX);
	__giveup_vsx(tsk);
	msr_check_and_clear(MSR_FP|MSR_VEC|MSR_VSX);
}

void enable_kernel_vsx(void)
{
	unsigned long cpumsr;

	WARN_ON(preemptible());

	cpumsr = msr_check_and_set(MSR_FP|MSR_VEC|MSR_VSX);

	if (current->thread.regs && (current->thread.regs->msr & (MSR_VSX|MSR_VEC|MSR_FP))) {
		check_if_tm_restore_required(current);
		
		if (!MSR_TM_ACTIVE(cpumsr) && MSR_TM_ACTIVE(current->thread.regs->msr))
			return;
		__giveup_vsx(current);
	}
}
EXPORT_SYMBOL(enable_kernel_vsx);

void flush_vsx_to_thread(struct task_struct *tsk)
{
	if (tsk->thread.regs) {
		preempt_disable();
		if (tsk->thread.regs->msr & (MSR_VSX|MSR_VEC|MSR_FP)) {
			BUG_ON(tsk != current);
			giveup_vsx(tsk);
		}
		preempt_enable();
	}
}
EXPORT_SYMBOL_GPL(flush_vsx_to_thread);

static int restore_vsx(struct task_struct *tsk)
{
	if (cpu_has_feature(CPU_FTR_VSX)) {
		tsk->thread.used_vsr = 1;
		return 1;
	}

	return 0;
}

static inline int restore_vsx(struct task_struct *tsk) { return 0; }



void giveup_spe(struct task_struct *tsk)
{
	check_if_tm_restore_required(tsk);

	msr_check_and_set(MSR_SPE);
	__giveup_spe(tsk);
	msr_check_and_clear(MSR_SPE);
}
EXPORT_SYMBOL(giveup_spe);

void enable_kernel_spe(void)
{
	WARN_ON(preemptible());

	msr_check_and_set(MSR_SPE);

	if (current->thread.regs && (current->thread.regs->msr & MSR_SPE)) {
		check_if_tm_restore_required(current);
		__giveup_spe(current);
	}
}
EXPORT_SYMBOL(enable_kernel_spe);

void flush_spe_to_thread(struct task_struct *tsk)
{
	if (tsk->thread.regs) {
		preempt_disable();
		if (tsk->thread.regs->msr & MSR_SPE) {
			BUG_ON(tsk != current);
			tsk->thread.spefscr = mfspr(SPRN_SPEFSCR);
			giveup_spe(tsk);
		}
		preempt_enable();
	}
}


static unsigned long msr_all_available;

static int __init init_msr_all_available(void)
{

	msr_all_available |= MSR_FP;


	if (cpu_has_feature(CPU_FTR_ALTIVEC))
		msr_all_available |= MSR_VEC;


	if (cpu_has_feature(CPU_FTR_VSX))
		msr_all_available |= MSR_VSX;


	if (cpu_has_feature(CPU_FTR_SPE))
		msr_all_available |= MSR_SPE;


	return 0;
}
early_initcall(init_msr_all_available);

void giveup_all(struct task_struct *tsk)
{
	unsigned long usermsr;

	if (!tsk->thread.regs)
		return;

	check_if_tm_restore_required(tsk);

	usermsr = tsk->thread.regs->msr;

	if ((usermsr & msr_all_available) == 0)
		return;

	msr_check_and_set(msr_all_available);

	WARN_ON((usermsr & MSR_VSX) && !((usermsr & MSR_FP) && (usermsr & MSR_VEC)));


	if (usermsr & MSR_FP)
		__giveup_fpu(tsk);


	if (usermsr & MSR_VEC)
		__giveup_altivec(tsk);


	if (usermsr & MSR_SPE)
		__giveup_spe(tsk);


	msr_check_and_clear(msr_all_available);
}
EXPORT_SYMBOL(giveup_all);


void notrace restore_math(struct pt_regs *regs)
{
	unsigned long msr;

	if (!MSR_TM_ACTIVE(regs->msr) && !current->thread.load_fp && !loadvec(current->thread))
		return;

	msr = regs->msr;
	msr_check_and_set(msr_all_available);

	
	if ((!(msr & MSR_FP)) && restore_fp(current))
		msr |= MSR_FP | current->thread.fpexc_mode;

	if ((!(msr & MSR_VEC)) && restore_altivec(current))
		msr |= MSR_VEC;

	if ((msr & (MSR_FP | MSR_VEC)) == (MSR_FP | MSR_VEC) && restore_vsx(current)) {
		msr |= MSR_VSX;
	}

	msr_check_and_clear(msr_all_available);

	regs->msr = msr;
}

static void save_all(struct task_struct *tsk)
{
	unsigned long usermsr;

	if (!tsk->thread.regs)
		return;

	usermsr = tsk->thread.regs->msr;

	if ((usermsr & msr_all_available) == 0)
		return;

	msr_check_and_set(msr_all_available);

	WARN_ON((usermsr & MSR_VSX) && !((usermsr & MSR_FP) && (usermsr & MSR_VEC)));

	if (usermsr & MSR_FP)
		save_fpu(tsk);

	if (usermsr & MSR_VEC)
		save_altivec(tsk);

	if (usermsr & MSR_SPE)
		__giveup_spe(tsk);

	msr_check_and_clear(msr_all_available);
	thread_pkey_regs_save(&tsk->thread);
}

void flush_all_to_thread(struct task_struct *tsk)
{
	if (tsk->thread.regs) {
		preempt_disable();
		BUG_ON(tsk != current);

		if (tsk->thread.regs->msr & MSR_SPE)
			tsk->thread.spefscr = mfspr(SPRN_SPEFSCR);

		save_all(tsk);

		preempt_enable();
	}
}
EXPORT_SYMBOL(flush_all_to_thread);


void do_send_trap(struct pt_regs *regs, unsigned long address, unsigned long error_code, int breakpt)
{
	current->thread.trap_nr = TRAP_HWBKPT;
	if (notify_die(DIE_DABR_MATCH, "dabr_match", regs, error_code, 11, SIGSEGV) == NOTIFY_STOP)
		return;

	
	force_sig_ptrace_errno_trap(breakpt,  (void __user *)address);
}

void do_break (struct pt_regs *regs, unsigned long address, unsigned long error_code)
{
	current->thread.trap_nr = TRAP_HWBKPT;
	if (notify_die(DIE_DABR_MATCH, "dabr_match", regs, error_code, 11, SIGSEGV) == NOTIFY_STOP)
		return;

	if (debugger_break_match(regs))
		return;

	
	hw_breakpoint_disable();

	
	force_sig_fault(SIGTRAP, TRAP_HWBKPT, (void __user *)address);
}


static DEFINE_PER_CPU(struct arch_hw_breakpoint, current_brk);



static void set_debug_reg_defaults(struct thread_struct *thread)
{
	thread->debug.iac1 = thread->debug.iac2 = 0;

	thread->debug.iac3 = thread->debug.iac4 = 0;

	thread->debug.dac1 = thread->debug.dac2 = 0;

	thread->debug.dvc1 = thread->debug.dvc2 = 0;

	thread->debug.dbcr0 = 0;

	
	thread->debug.dbcr1 = DBCR1_IAC1US | DBCR1_IAC2US | DBCR1_IAC3US | DBCR1_IAC4US;
	
	thread->debug.dbcr2 = DBCR2_DAC1US | DBCR2_DAC2US;

	thread->debug.dbcr1 = 0;

}

static void prime_debug_regs(struct debug_reg *debug)
{
	
	mtmsr(mfmsr() & ~MSR_DE);

	mtspr(SPRN_IAC1, debug->iac1);
	mtspr(SPRN_IAC2, debug->iac2);

	mtspr(SPRN_IAC3, debug->iac3);
	mtspr(SPRN_IAC4, debug->iac4);

	mtspr(SPRN_DAC1, debug->dac1);
	mtspr(SPRN_DAC2, debug->dac2);

	mtspr(SPRN_DVC1, debug->dvc1);
	mtspr(SPRN_DVC2, debug->dvc2);

	mtspr(SPRN_DBCR0, debug->dbcr0);
	mtspr(SPRN_DBCR1, debug->dbcr1);

	mtspr(SPRN_DBCR2, debug->dbcr2);

}

void switch_booke_debug_regs(struct debug_reg *new_debug)
{
	if ((current->thread.debug.dbcr0 & DBCR0_IDM)
		|| (new_debug->dbcr0 & DBCR0_IDM))
			prime_debug_regs(new_debug);
}
EXPORT_SYMBOL_GPL(switch_booke_debug_regs);


static void set_breakpoint(struct arch_hw_breakpoint *brk)
{
	preempt_disable();
	__set_breakpoint(brk);
	preempt_enable();
}

static void set_debug_reg_defaults(struct thread_struct *thread)
{
	thread->hw_brk.address = 0;
	thread->hw_brk.type = 0;
	if (ppc_breakpoint_available())
		set_breakpoint(&thread->hw_brk);
}




static inline int __set_dabr(unsigned long dabr, unsigned long dabrx)
{
	mtspr(SPRN_DAC1, dabr);

	isync();

	return 0;
}

static inline int __set_dabr(unsigned long dabr, unsigned long dabrx)
{
	mtspr(SPRN_DABR, dabr);
	if (cpu_has_feature(CPU_FTR_DABRX))
		mtspr(SPRN_DABRX, dabrx);
	return 0;
}

static inline int __set_dabr(unsigned long dabr, unsigned long dabrx)
{
	unsigned long addr = dabr & ~HW_BRK_TYPE_DABR;
	unsigned long lctrl1 = 0x90000000; 
	unsigned long lctrl2 = 0x8e000002; 

	if ((dabr & HW_BRK_TYPE_RDWR) == HW_BRK_TYPE_READ)
		lctrl1 |= 0xa0000;
	else if ((dabr & HW_BRK_TYPE_RDWR) == HW_BRK_TYPE_WRITE)
		lctrl1 |= 0xf0000;
	else if ((dabr & HW_BRK_TYPE_RDWR) == 0)
		lctrl2 = 0;

	mtspr(SPRN_LCTRL2, 0);
	mtspr(SPRN_CMPE, addr);
	mtspr(SPRN_CMPF, addr + 4);
	mtspr(SPRN_LCTRL1, lctrl1);
	mtspr(SPRN_LCTRL2, lctrl2);

	return 0;
}

static inline int __set_dabr(unsigned long dabr, unsigned long dabrx)
{
	return -EINVAL;
}


static inline int set_dabr(struct arch_hw_breakpoint *brk)
{
	unsigned long dabr, dabrx;

	dabr = brk->address | (brk->type & HW_BRK_TYPE_DABR);
	dabrx = ((brk->type >> 3) & 0x7);

	if (ppc_md.set_dabr)
		return ppc_md.set_dabr(dabr, dabrx);

	return __set_dabr(dabr, dabrx);
}

void __set_breakpoint(struct arch_hw_breakpoint *brk)
{
	memcpy(this_cpu_ptr(&current_brk), brk, sizeof(*brk));

	if (dawr_enabled())
		
		set_dawr(brk);
	else if (!cpu_has_feature(CPU_FTR_ARCH_207S))
		
		set_dabr(brk);
	else  WARN_ON_ONCE(1);

}


bool ppc_breakpoint_available(void)
{
	if (dawr_enabled())
		return true; 
	if (cpu_has_feature(CPU_FTR_ARCH_207S))
		return false; 
	
	return true;
}
EXPORT_SYMBOL_GPL(ppc_breakpoint_available);

static inline bool hw_brk_match(struct arch_hw_breakpoint *a, struct arch_hw_breakpoint *b)
{
	if (a->address != b->address)
		return false;
	if (a->type != b->type)
		return false;
	if (a->len != b->len)
		return false;
	return true;
}



static inline bool tm_enabled(struct task_struct *tsk)
{
	return tsk && tsk->thread.regs && (tsk->thread.regs->msr & MSR_TM);
}

static void tm_reclaim_thread(struct thread_struct *thr, uint8_t cause)
{
	
	if (!MSR_TM_SUSPENDED(mfmsr()))
		return;

	giveup_all(container_of(thr, struct task_struct, thread));

	tm_reclaim(thr, cause);

	
	if ((thr->ckpt_regs.msr & MSR_FP) == 0)
		memcpy(&thr->ckfp_state, &thr->fp_state, sizeof(struct thread_fp_state));
	if ((thr->ckpt_regs.msr & MSR_VEC) == 0)
		memcpy(&thr->ckvr_state, &thr->vr_state, sizeof(struct thread_vr_state));
}

void tm_reclaim_current(uint8_t cause)
{
	tm_enable();
	tm_reclaim_thread(&current->thread, cause);
}

static inline void tm_reclaim_task(struct task_struct *tsk)
{
	
	struct thread_struct *thr = &tsk->thread;

	if (!thr->regs)
		return;

	if (!MSR_TM_ACTIVE(thr->regs->msr))
		goto out_and_saveregs;

	WARN_ON(tm_suspend_disabled);

	TM_DEBUG("--- tm_reclaim on pid %d (NIP=%lx, " "ccr=%lx, msr=%lx, trap=%lx)\n", tsk->pid, thr->regs->nip, thr->regs->ccr, thr->regs->msr, thr->regs->trap);




	tm_reclaim_thread(thr, TM_CAUSE_RESCHED);

	TM_DEBUG("--- tm_reclaim on pid %d complete\n", tsk->pid);

out_and_saveregs:
	
	tm_save_sprs(thr);
}

extern void __tm_recheckpoint(struct thread_struct *thread);

void tm_recheckpoint(struct thread_struct *thread)
{
	unsigned long flags;

	if (!(thread->regs->msr & MSR_TM))
		return;

	
	local_irq_save(flags);
	hard_irq_disable();

	
	tm_restore_sprs(thread);

	__tm_recheckpoint(thread);

	local_irq_restore(flags);
}

static inline void tm_recheckpoint_new_task(struct task_struct *new)
{
	if (!cpu_has_feature(CPU_FTR_TM))
		return;

	
	if (!tm_enabled(new))
		return;

	if (!MSR_TM_ACTIVE(new->thread.regs->msr)){
		tm_restore_sprs(&new->thread);
		return;
	}
	
	TM_DEBUG("*** tm_recheckpoint of pid %d (new->msr 0x%lx)\n", new->pid, new->thread.regs->msr);

	tm_recheckpoint(&new->thread);

	
	new->thread.regs->msr &= ~(MSR_FP | MSR_VEC | MSR_VSX);

	TM_DEBUG("*** tm_recheckpoint of pid %d complete " "(kernel msr 0x%lx)\n", new->pid, mfmsr());

}

static inline void __switch_to_tm(struct task_struct *prev, struct task_struct *new)
{
	if (cpu_has_feature(CPU_FTR_TM)) {
		if (tm_enabled(prev) || tm_enabled(new))
			tm_enable();

		if (tm_enabled(prev)) {
			prev->thread.load_tm++;
			tm_reclaim_task(prev);
			if (!MSR_TM_ACTIVE(prev->thread.regs->msr) && prev->thread.load_tm == 0)
				prev->thread.regs->msr &= ~MSR_TM;
		}

		tm_recheckpoint_new_task(new);
	}
}


void restore_tm_state(struct pt_regs *regs)
{
	unsigned long msr_diff;

	
	clear_thread_flag(TIF_RESTORE_TM);
	if (!MSR_TM_ACTIVE(regs->msr))
		return;

	msr_diff = current->thread.ckpt_regs.msr & ~regs->msr;
	msr_diff &= MSR_FP | MSR_VEC | MSR_VSX;

	
	if (msr_diff & MSR_FP)
		current->thread.load_fp = 1;

	if (cpu_has_feature(CPU_FTR_ALTIVEC) && msr_diff & MSR_VEC)
		current->thread.load_vec = 1;

	restore_math(regs);

	regs->msr |= msr_diff;
}






static inline void save_sprs(struct thread_struct *t)
{

	if (cpu_has_feature(CPU_FTR_ALTIVEC))
		t->vrsave = mfspr(SPRN_VRSAVE);


	if (cpu_has_feature(CPU_FTR_DSCR))
		t->dscr = mfspr(SPRN_DSCR);

	if (cpu_has_feature(CPU_FTR_ARCH_207S)) {
		t->bescr = mfspr(SPRN_BESCR);
		t->ebbhr = mfspr(SPRN_EBBHR);
		t->ebbrr = mfspr(SPRN_EBBRR);

		t->fscr = mfspr(SPRN_FSCR);

		
		t->tar = mfspr(SPRN_TAR);
	}


	thread_pkey_regs_save(t);
}

static inline void restore_sprs(struct thread_struct *old_thread, struct thread_struct *new_thread)
{

	if (cpu_has_feature(CPU_FTR_ALTIVEC) && old_thread->vrsave != new_thread->vrsave)
		mtspr(SPRN_VRSAVE, new_thread->vrsave);


	if (cpu_has_feature(CPU_FTR_DSCR)) {
		u64 dscr = get_paca()->dscr_default;
		if (new_thread->dscr_inherit)
			dscr = new_thread->dscr;

		if (old_thread->dscr != dscr)
			mtspr(SPRN_DSCR, dscr);
	}

	if (cpu_has_feature(CPU_FTR_ARCH_207S)) {
		if (old_thread->bescr != new_thread->bescr)
			mtspr(SPRN_BESCR, new_thread->bescr);
		if (old_thread->ebbhr != new_thread->ebbhr)
			mtspr(SPRN_EBBHR, new_thread->ebbhr);
		if (old_thread->ebbrr != new_thread->ebbrr)
			mtspr(SPRN_EBBRR, new_thread->ebbrr);

		if (old_thread->fscr != new_thread->fscr)
			mtspr(SPRN_FSCR, new_thread->fscr);

		if (old_thread->tar != new_thread->tar)
			mtspr(SPRN_TAR, new_thread->tar);
	}

	if (cpu_has_feature(CPU_FTR_P9_TIDR) && old_thread->tidr != new_thread->tidr)
		mtspr(SPRN_TIDR, new_thread->tidr);


	thread_pkey_regs_restore(new_thread, old_thread);
}

struct task_struct *__switch_to(struct task_struct *prev, struct task_struct *new)
{
	struct thread_struct *new_thread, *old_thread;
	struct task_struct *last;

	struct ppc64_tlb_batch *batch;


	new_thread = &new->thread;
	old_thread = &current->thread;

	WARN_ON(!irqs_disabled());


	batch = this_cpu_ptr(&ppc64_tlb_batch);
	if (batch->active) {
		current_thread_info()->local_flags |= _TLF_LAZY_MMU;
		if (batch->index)
			__flush_tlb_pending(batch);
		batch->active = 0;
	}



	switch_booke_debug_regs(&new->thread.debug);



	if (unlikely(!hw_brk_match(this_cpu_ptr(&current_brk), &new->thread.hw_brk)))
		__set_breakpoint(&new->thread.hw_brk);



	
	save_sprs(&prev->thread);

	
	giveup_all(prev);

	__switch_to_tm(prev, new);

	if (!radix_enabled()) {
		
		hard_irq_disable();
	}

	
	restore_sprs(old_thread, new_thread);

	last = _switch(old_thread, new_thread);


	if (current_thread_info()->local_flags & _TLF_LAZY_MMU) {
		current_thread_info()->local_flags &= ~_TLF_LAZY_MMU;
		batch = this_cpu_ptr(&ppc64_tlb_batch);
		batch->active = 1;
	}

	if (current->thread.regs) {
		restore_math(current->thread.regs);

		
		if (current->thread.used_vas)
			asm volatile(PPC_CP_ABORT);
	}


	return last;
}



static void show_instructions(struct pt_regs *regs)
{
	int i;
	unsigned long pc = regs->nip - (NR_INSN_TO_PRINT * 3 / 4 * sizeof(int));

	printk("Instruction dump:");

	for (i = 0; i < NR_INSN_TO_PRINT; i++) {
		int instr;

		if (!(i % 8))
			pr_cont("\n");


		
		if (!(regs->msr & MSR_IR))
			pc = (unsigned long)phys_to_virt(pc);


		if (!__kernel_text_address(pc) || probe_kernel_address((const void *)pc, instr)) {
			pr_cont("XXXXXXXX ");
		} else {
			if (regs->nip == pc)
				pr_cont("<%08x> ", instr);
			else pr_cont("%08x ", instr);
		}

		pc += sizeof(int);
	}

	pr_cont("\n");
}

void show_user_instructions(struct pt_regs *regs)
{
	unsigned long pc;
	int n = NR_INSN_TO_PRINT;
	struct seq_buf s;
	char buf[96]; 

	pc = regs->nip - (NR_INSN_TO_PRINT * 3 / 4 * sizeof(int));

	
	if (!__access_ok(pc, NR_INSN_TO_PRINT * sizeof(int), USER_DS)) {
		pr_info("%s[%d]: Bad NIP, not dumping instructions.\n", current->comm, current->pid);
		return;
	}

	seq_buf_init(&s, buf, sizeof(buf));

	while (n) {
		int i;

		seq_buf_clear(&s);

		for (i = 0; i < 8 && n; i++, n--, pc += sizeof(int)) {
			int instr;

			if (probe_kernel_address((const void *)pc, instr)) {
				seq_buf_printf(&s, "XXXXXXXX ");
				continue;
			}
			seq_buf_printf(&s, regs->nip == pc ? "<%08x> " : "%08x ", instr);
		}

		if (!seq_buf_has_overflowed(&s))
			pr_info("%s[%d]: code: %s\n", current->comm, current->pid, s.buffer);
	}
}

struct regbit {
	unsigned long bit;
	const char *name;
};

static struct regbit msr_bits[] = {

	{MSR_SF,	"SF", {MSR_HV,	"HV",  {MSR_VEC,	"VEC", {MSR_VSX,	"VSX",  {MSR_CE,	"CE",  {MSR_EE,	"EE", {MSR_PR,	"PR", {MSR_FP,	"FP", {MSR_ME,	"ME",  {MSR_DE,	"DE",  {MSR_SE,	"SE", {MSR_BE,	"BE",  {MSR_IR,	"IR", {MSR_DR,	"DR", {MSR_PMM,	"PMM",  {MSR_RI,	"RI", {MSR_LE,	"LE",  {0,		NULL}
























};

static void print_bits(unsigned long val, struct regbit *bits, const char *sep)
{
	const char *s = "";

	for (; bits->bit; ++bits)
		if (val & bits->bit) {
			pr_cont("%s%s", s, bits->name);
			s = sep;
		}
}


static struct regbit msr_tm_bits[] = {
	{MSR_TS_T,	"T", {MSR_TS_S,	"S", {MSR_TM,	"E", {0,		NULL}


};

static void print_tm_bits(unsigned long val)
{

	if (val & (MSR_TM | MSR_TS_S | MSR_TS_T)) {
		pr_cont(",TM[");
		print_bits(val, msr_tm_bits, "");
		pr_cont("]");
	}
}

static void print_tm_bits(unsigned long val) {}


static void print_msr_bits(unsigned long val)
{
	pr_cont("<");
	print_bits(val, msr_bits, ",");
	print_tm_bits(val);
	pr_cont(">");
}











void show_regs(struct pt_regs * regs)
{
	int i, trap;

	show_regs_print_info(KERN_DEFAULT);

	printk("NIP:  "REG" LR: "REG" CTR: "REG"\n", regs->nip, regs->link, regs->ctr);
	printk("REGS: %px TRAP: %04lx   %s  (%s)\n", regs, regs->trap, print_tainted(), init_utsname()->release);
	printk("MSR:  "REG" ", regs->msr);
	print_msr_bits(regs->msr);
	pr_cont("  CR: %08lx  XER: %08lx\n", regs->ccr, regs->xer);
	trap = TRAP(regs);
	if ((TRAP(regs) != 0xc00) && cpu_has_feature(CPU_FTR_CFAR))
		pr_cont("CFAR: "REG" ", regs->orig_gpr3);
	if (trap == 0x200 || trap == 0x300 || trap == 0x600)

		pr_cont("DEAR: "REG" ESR: "REG" ", regs->dar, regs->dsisr);

		pr_cont("DAR: "REG" DSISR: %08lx ", regs->dar, regs->dsisr);


	pr_cont("IRQMASK: %lx ", regs->softe);


	if (MSR_TM_ACTIVE(regs->msr))
		pr_cont("\nPACATMSCRATCH: %016llx ", get_paca()->tm_scratch);


	for (i = 0;  i < 32;  i++) {
		if ((i % REGS_PER_LINE) == 0)
			pr_cont("\nGPR%02d: ", i);
		pr_cont(REG " ", regs->gpr[i]);
		if (i == LAST_VOLATILE && !FULL_REGS(regs))
			break;
	}
	pr_cont("\n");

	
	printk("NIP ["REG"] %pS\n", regs->nip, (void *)regs->nip);
	printk("LR ["REG"] %pS\n", regs->link, (void *)regs->link);

	show_stack(current, (unsigned long *) regs->gpr[1]);
	if (!user_mode(regs))
		show_instructions(regs);
}

void flush_thread(void)
{

	flush_ptrace_hw_breakpoint(current);

	set_debug_reg_defaults(&current->thread);

}


void arch_setup_new_exec(void)
{
	if (radix_enabled())
		return;
	hash__setup_new_exec();
}


int set_thread_uses_vas(void)
{

	if (!cpu_has_feature(CPU_FTR_ARCH_300))
		return -EINVAL;

	current->thread.used_vas = 1;

	
	asm volatile(PPC_CP_ABORT);


	return 0;
}



int set_thread_tidr(struct task_struct *t)
{
	if (!cpu_has_feature(CPU_FTR_P9_TIDR))
		return -EINVAL;

	if (t != current)
		return -EINVAL;

	if (t->thread.tidr)
		return 0;

	t->thread.tidr = (u16)task_pid_nr(t);
	mtspr(SPRN_TIDR, t->thread.tidr);

	return 0;
}
EXPORT_SYMBOL_GPL(set_thread_tidr);



void release_thread(struct task_struct *t)
{
}


int arch_dup_task_struct(struct task_struct *dst, struct task_struct *src)
{
	flush_all_to_thread(src);
	
	__switch_to_tm(src, src);

	*dst = *src;

	clear_task_ebb(dst);

	return 0;
}

static void setup_ksp_vsid(struct task_struct *p, unsigned long sp)
{

	unsigned long sp_vsid;
	unsigned long llp = mmu_psize_defs[mmu_linear_psize].sllp;

	if (radix_enabled())
		return;

	if (mmu_has_feature(MMU_FTR_1T_SEGMENT))
		sp_vsid = get_kernel_vsid(sp, MMU_SEGSIZE_1T)
			<< SLB_VSID_SHIFT_1T;
	else sp_vsid = get_kernel_vsid(sp, MMU_SEGSIZE_256M)
			<< SLB_VSID_SHIFT;
	sp_vsid |= SLB_VSID_KERNEL | llp;
	p->thread.ksp_vsid = sp_vsid;

}




int copy_thread(unsigned long clone_flags, unsigned long usp, unsigned long kthread_arg, struct task_struct *p)
{
	struct pt_regs *childregs, *kregs;
	extern void ret_from_fork(void);
	extern void ret_from_kernel_thread(void);
	void (*f)(void);
	unsigned long sp = (unsigned long)task_stack_page(p) + THREAD_SIZE;
	struct thread_info *ti = task_thread_info(p);

	klp_init_thread_info(p);

	
	sp -= sizeof(struct pt_regs);
	childregs = (struct pt_regs *) sp;
	if (unlikely(p->flags & PF_KTHREAD)) {
		
		memset(childregs, 0, sizeof(struct pt_regs));
		childregs->gpr[1] = sp + sizeof(struct pt_regs);
		
		if (usp)
			childregs->gpr[14] = ppc_function_entry((void *)usp);

		clear_tsk_thread_flag(p, TIF_32BIT);
		childregs->softe = IRQS_ENABLED;

		childregs->gpr[15] = kthread_arg;
		p->thread.regs = NULL;	
		ti->flags |= _TIF_RESTOREALL;
		f = ret_from_kernel_thread;
	} else {
		
		struct pt_regs *regs = current_pt_regs();
		CHECK_FULL_REGS(regs);
		*childregs = *regs;
		if (usp)
			childregs->gpr[1] = usp;
		p->thread.regs = childregs;
		childregs->gpr[3] = 0;  
		if (clone_flags & CLONE_SETTLS) {

			if (!is_32bit_task())
				childregs->gpr[13] = childregs->gpr[6];
			else  childregs->gpr[2] = childregs->gpr[6];

		}

		f = ret_from_fork;
	}
	childregs->msr &= ~(MSR_FP|MSR_VEC|MSR_VSX);
	sp -= STACK_FRAME_OVERHEAD;

	
	((unsigned long *)sp)[0] = 0;
	sp -= sizeof(struct pt_regs);
	kregs = (struct pt_regs *) sp;
	sp -= STACK_FRAME_OVERHEAD;
	p->thread.ksp = sp;

	p->thread.ksp_limit = (unsigned long)end_of_stack(p);


	p->thread.ptrace_bps[0] = NULL;


	p->thread.fp_save_area = NULL;

	p->thread.vr_save_area = NULL;


	setup_ksp_vsid(p, sp);


	if (cpu_has_feature(CPU_FTR_DSCR)) {
		p->thread.dscr_inherit = current->thread.dscr_inherit;
		p->thread.dscr = mfspr(SPRN_DSCR);
	}
	if (cpu_has_feature(CPU_FTR_HAS_PPR))
		childregs->ppr = DEFAULT_PPR;

	p->thread.tidr = 0;

	kregs->nip = ppc_function_entry(f);
	return 0;
}

void preload_new_slb_context(unsigned long start, unsigned long sp);


void start_thread(struct pt_regs *regs, unsigned long start, unsigned long sp)
{

	unsigned long load_addr = regs->gpr[2];	


	if (!radix_enabled())
		preload_new_slb_context(start, sp);



	
	if (!current->thread.regs) {
		struct pt_regs *regs = task_stack_page(current) + THREAD_SIZE;
		current->thread.regs = regs - 1;
	}


	
	if (MSR_TM_SUSPENDED(mfmsr()))
		tm_reclaim_current(0);


	memset(regs->gpr, 0, sizeof(regs->gpr));
	regs->ctr = 0;
	regs->link = 0;
	regs->xer = 0;
	regs->ccr = 0;
	regs->gpr[1] = sp;

	
	regs->trap &= ~1UL;


	regs->mq = 0;
	regs->nip = start;
	regs->msr = MSR_USER;

	if (!is_32bit_task()) {
		unsigned long entry;

		if (is_elf2_task()) {
			
			entry = start;

			
			regs->gpr[12] = start;
			
			set_thread_flag(TIF_RESTOREALL);
		} else {
			unsigned long toc;

			
			__get_user(entry, (unsigned long __user *)start);
			__get_user(toc, (unsigned long __user *)start+1);

			
			if (load_addr != 0) {
				entry += load_addr;
				toc   += load_addr;
			}
			regs->gpr[2] = toc;
		}
		regs->nip = entry;
		regs->msr = MSR_USER64;
	} else {
		regs->nip = start;
		regs->gpr[2] = 0;
		regs->msr = MSR_USER32;
	}


	current->thread.used_vsr = 0;

	current->thread.load_slb = 0;
	current->thread.load_fp = 0;
	memset(&current->thread.fp_state, 0, sizeof(current->thread.fp_state));
	current->thread.fp_save_area = NULL;

	memset(&current->thread.vr_state, 0, sizeof(current->thread.vr_state));
	current->thread.vr_state.vscr.u[3] = 0x00010000; 
	current->thread.vr_save_area = NULL;
	current->thread.vrsave = 0;
	current->thread.used_vr = 0;
	current->thread.load_vec = 0;


	memset(current->thread.evr, 0, sizeof(current->thread.evr));
	current->thread.acc = 0;
	current->thread.spefscr = 0;
	current->thread.used_spe = 0;


	current->thread.tm_tfhar = 0;
	current->thread.tm_texasr = 0;
	current->thread.tm_tfiar = 0;
	current->thread.load_tm = 0;


	thread_pkey_regs_init(&current->thread);
}
EXPORT_SYMBOL(start_thread);



int set_fpexc_mode(struct task_struct *tsk, unsigned int val)
{
	struct pt_regs *regs = tsk->thread.regs;

	
	if (val & PR_FP_EXC_SW_ENABLE) {

		if (cpu_has_feature(CPU_FTR_SPE)) {
			
			tsk->thread.spefscr_last = mfspr(SPRN_SPEFSCR);
			tsk->thread.fpexc_mode = val & (PR_FP_EXC_SW_ENABLE | PR_FP_ALL_EXCEPT);
			return 0;
		} else {
			return -EINVAL;
		}

		return -EINVAL;

	}

	
	if (val > PR_FP_EXC_PRECISE)
		return -EINVAL;
	tsk->thread.fpexc_mode = __pack_fe01(val);
	if (regs != NULL && (regs->msr & MSR_FP) != 0)
		regs->msr = (regs->msr & ~(MSR_FE0|MSR_FE1))
			| tsk->thread.fpexc_mode;
	return 0;
}

int get_fpexc_mode(struct task_struct *tsk, unsigned long adr)
{
	unsigned int val;

	if (tsk->thread.fpexc_mode & PR_FP_EXC_SW_ENABLE)

		if (cpu_has_feature(CPU_FTR_SPE)) {
			
			tsk->thread.spefscr_last = mfspr(SPRN_SPEFSCR);
			val = tsk->thread.fpexc_mode;
		} else return -EINVAL;

		return -EINVAL;

	else val = __unpack_fe01(tsk->thread.fpexc_mode);
	return put_user(val, (unsigned int __user *) adr);
}

int set_endian(struct task_struct *tsk, unsigned int val)
{
	struct pt_regs *regs = tsk->thread.regs;

	if ((val == PR_ENDIAN_LITTLE && !cpu_has_feature(CPU_FTR_REAL_LE)) || (val == PR_ENDIAN_PPC_LITTLE && !cpu_has_feature(CPU_FTR_PPC_LE)))
		return -EINVAL;

	if (regs == NULL)
		return -EINVAL;

	if (val == PR_ENDIAN_BIG)
		regs->msr &= ~MSR_LE;
	else if (val == PR_ENDIAN_LITTLE || val == PR_ENDIAN_PPC_LITTLE)
		regs->msr |= MSR_LE;
	else return -EINVAL;

	return 0;
}

int get_endian(struct task_struct *tsk, unsigned long adr)
{
	struct pt_regs *regs = tsk->thread.regs;
	unsigned int val;

	if (!cpu_has_feature(CPU_FTR_PPC_LE) && !cpu_has_feature(CPU_FTR_REAL_LE))
		return -EINVAL;

	if (regs == NULL)
		return -EINVAL;

	if (regs->msr & MSR_LE) {
		if (cpu_has_feature(CPU_FTR_REAL_LE))
			val = PR_ENDIAN_LITTLE;
		else val = PR_ENDIAN_PPC_LITTLE;
	} else val = PR_ENDIAN_BIG;

	return put_user(val, (unsigned int __user *)adr);
}

int set_unalign_ctl(struct task_struct *tsk, unsigned int val)
{
	tsk->thread.align_ctl = val;
	return 0;
}

int get_unalign_ctl(struct task_struct *tsk, unsigned long adr)
{
	return put_user(tsk->thread.align_ctl, (unsigned int __user *)adr);
}

static inline int valid_irq_stack(unsigned long sp, struct task_struct *p, unsigned long nbytes)
{
	unsigned long stack_page;
	unsigned long cpu = task_cpu(p);

	stack_page = (unsigned long)hardirq_ctx[cpu];
	if (sp >= stack_page && sp <= stack_page + THREAD_SIZE - nbytes)
		return 1;

	stack_page = (unsigned long)softirq_ctx[cpu];
	if (sp >= stack_page && sp <= stack_page + THREAD_SIZE - nbytes)
		return 1;

	return 0;
}

int validate_sp(unsigned long sp, struct task_struct *p, unsigned long nbytes)
{
	unsigned long stack_page = (unsigned long)task_stack_page(p);

	if (sp < THREAD_SIZE)
		return 0;

	if (sp >= stack_page && sp <= stack_page + THREAD_SIZE - nbytes)
		return 1;

	return valid_irq_stack(sp, p, nbytes);
}

EXPORT_SYMBOL(validate_sp);

static unsigned long __get_wchan(struct task_struct *p)
{
	unsigned long ip, sp;
	int count = 0;

	if (!p || p == current || p->state == TASK_RUNNING)
		return 0;

	sp = p->thread.ksp;
	if (!validate_sp(sp, p, STACK_FRAME_OVERHEAD))
		return 0;

	do {
		sp = *(unsigned long *)sp;
		if (!validate_sp(sp, p, STACK_FRAME_OVERHEAD) || p->state == TASK_RUNNING)
			return 0;
		if (count > 0) {
			ip = ((unsigned long *)sp)[STACK_FRAME_LR_SAVE];
			if (!in_sched_functions(ip))
				return ip;
		}
	} while (count++ < 16);
	return 0;
}

unsigned long get_wchan(struct task_struct *p)
{
	unsigned long ret;

	if (!try_get_task_stack(p))
		return 0;

	ret = __get_wchan(p);

	put_task_stack(p);

	return ret;
}

static int kstack_depth_to_print = CONFIG_PRINT_STACK_DEPTH;

void show_stack(struct task_struct *tsk, unsigned long *stack)
{
	unsigned long sp, ip, lr, newsp;
	int count = 0;
	int firstframe = 1;

	struct ftrace_ret_stack *ret_stack;
	extern void return_to_handler(void);
	unsigned long rth = (unsigned long)return_to_handler;
	int curr_frame = 0;


	if (tsk == NULL)
		tsk = current;

	if (!try_get_task_stack(tsk))
		return;

	sp = (unsigned long) stack;
	if (sp == 0) {
		if (tsk == current)
			sp = current_stack_pointer();
		else sp = tsk->thread.ksp;
	}

	lr = 0;
	printk("Call Trace:\n");
	do {
		if (!validate_sp(sp, tsk, STACK_FRAME_OVERHEAD))
			break;

		stack = (unsigned long *) sp;
		newsp = stack[0];
		ip = stack[STACK_FRAME_LR_SAVE];
		if (!firstframe || ip != lr) {
			printk("["REG"] ["REG"] %pS", sp, ip, (void *)ip);

			if ((ip == rth) && curr_frame >= 0) {
				ret_stack = ftrace_graph_get_ret_stack(current, curr_frame++);
				if (ret_stack)
					pr_cont(" (%pS)", (void *)ret_stack->ret);
				else curr_frame = -1;
			}

			if (firstframe)
				pr_cont(" (unreliable)");
			pr_cont("\n");
		}
		firstframe = 0;

		
		if (validate_sp(sp, tsk, STACK_INT_FRAME_SIZE)
		    && stack[STACK_FRAME_MARKER] == STACK_FRAME_REGS_MARKER) {
			struct pt_regs *regs = (struct pt_regs *)
				(sp + STACK_FRAME_OVERHEAD);
			lr = regs->link;
			printk("--- interrupt: %lx at %pS\n    LR = %pS\n", regs->trap, (void *)regs->nip, (void *)lr);
			firstframe = 1;
		}

		sp = newsp;
	} while (count++ < kstack_depth_to_print);

	put_task_stack(tsk);
}



void notrace __ppc64_runlatch_on(void)
{
	struct thread_info *ti = current_thread_info();

	if (cpu_has_feature(CPU_FTR_ARCH_206)) {
		
		mtspr(SPRN_CTRLT, CTRL_RUNLATCH);
	} else {
		unsigned long ctrl;

		
		ctrl = mfspr(SPRN_CTRLF);
		ctrl |= CTRL_RUNLATCH;
		mtspr(SPRN_CTRLT, ctrl);
	}

	ti->local_flags |= _TLF_RUNLATCH;
}


void notrace __ppc64_runlatch_off(void)
{
	struct thread_info *ti = current_thread_info();

	ti->local_flags &= ~_TLF_RUNLATCH;

	if (cpu_has_feature(CPU_FTR_ARCH_206)) {
		mtspr(SPRN_CTRLT, 0);
	} else {
		unsigned long ctrl;

		ctrl = mfspr(SPRN_CTRLF);
		ctrl &= ~CTRL_RUNLATCH;
		mtspr(SPRN_CTRLT, ctrl);
	}
}


unsigned long arch_align_stack(unsigned long sp)
{
	if (!(current->personality & ADDR_NO_RANDOMIZE) && randomize_va_space)
		sp -= get_random_int() & ~PAGE_MASK;
	return sp & ~0xf;
}

static inline unsigned long brk_rnd(void)
{
        unsigned long rnd = 0;

	
	if (is_32bit_task())
		rnd = (get_random_long() % (1UL<<(23-PAGE_SHIFT)));
	else rnd = (get_random_long() % (1UL<<(30-PAGE_SHIFT)));

	return rnd << PAGE_SHIFT;
}

unsigned long arch_randomize_brk(struct mm_struct *mm)
{
	unsigned long base = mm->brk;
	unsigned long ret;


	
	if (!is_32bit_task() && (mmu_highuser_ssize == MMU_SEGSIZE_1T))
		base = max_t(unsigned long, mm->brk, 1UL << SID_SHIFT_1T);


	ret = PAGE_ALIGN(base + brk_rnd());

	if (ret < mm->brk)
		return mm->brk;

	return ret;
}

