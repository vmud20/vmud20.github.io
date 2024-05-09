


__FBSDID("$FreeBSD$");



































































static u_int	cpu_reset_proxyid;
static volatile u_int	cpu_reset_proxy_active;



bool mwait_cpustop_broken = false;
SYSCTL_BOOL(_machdep, OID_AUTO, mwait_cpustop_broken, CTLFLAG_RDTUN, &mwait_cpustop_broken, 0, "Can not reliably wake MONITOR/MWAIT cpus without interrupts");



void cpu_boot(int howto)
{
}


void cpu_flush_dcache(void *ptr, size_t len)
{
	
}

void acpi_cpu_c1(void)
{

	__asm __volatile("sti; hlt");
}


void acpi_cpu_idle_mwait(uint32_t mwait_hint)
{
	int *state;
	uint64_t v;

	

	state = &PCPU_PTR(monitorbuf)->idle_state;
	KASSERT(atomic_load_int(state) == STATE_SLEEPING, ("cpu_mwait_cx: wrong monitorbuf state"));
	atomic_store_int(state, STATE_MWAIT);
	if (PCPU_GET(ibpb_set) || hw_ssb_active) {
		v = rdmsr(MSR_IA32_SPEC_CTRL);
		wrmsr(MSR_IA32_SPEC_CTRL, v & ~(IA32_SPEC_CTRL_IBRS | IA32_SPEC_CTRL_STIBP | IA32_SPEC_CTRL_SSBD));
	} else {
		v = 0;
	}
	cpu_monitor(state, 0, 0);
	if (atomic_load_int(state) == STATE_MWAIT)
		cpu_mwait(MWAIT_INTRBREAK, mwait_hint);

	
	if (v != 0)
		wrmsr(MSR_IA32_SPEC_CTRL, v);

	
	atomic_store_int(state, STATE_RUNNING);
}


int cpu_est_clockrate(int cpu_id, uint64_t *rate)
{
	uint64_t tsc1, tsc2;
	uint64_t acnt, mcnt, perf;
	register_t reg;

	if (pcpu_find(cpu_id) == NULL || rate == NULL)
		return (EINVAL);

	if ((cpu_feature & CPUID_TSC) == 0)
		return (EOPNOTSUPP);


	
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

static void cpu_reset_real(void)
{
	struct region_descriptor null_idt;
	int b;

	disable_intr();

	if (elan_mmcr != NULL)
		elan_mmcr->RESCFG = 1;


	if (cpu == CPU_GEODE1100) {
		
		outl(0xcf8, 0x80009044ul);
		outl(0xcfc, 0xf);
	}


	
	outb(IO_KBD + 4, 0xFE);
	DELAY(500000);	


	
	outb(0xcf9, 0x2);
	outb(0xcf9, 0x6);
	DELAY(500000);  

	
	b = inb(0x92);
	if (b != 0xff) {
		if ((b & 0x1) != 0)
			outb(0x92, b & 0xfe);
		outb(0x92, b | 0x1);
		DELAY(500000);  
	}

	printf("No known reset method worked, attempting CPU shutdown\n");
	DELAY(1000000); 

	
	null_idt.rd_limit = 0;
	null_idt.rd_base = 0;
	lidt(&null_idt);

	
	breakpoint();

	
	while(1);
}


static void cpu_reset_proxy(void)
{

	cpu_reset_proxy_active = 1;
	while (cpu_reset_proxy_active == 1)
		ia32_pause(); 

	printf("cpu_reset_proxy: Stopped CPU %d\n", cpu_reset_proxyid);
	DELAY(1000000);
	cpu_reset_real();
}


void cpu_reset(void)
{

	struct monitorbuf *mb;
	cpuset_t map;
	u_int cnt;

	if (smp_started) {
		map = all_cpus;
		CPU_CLR(PCPU_GET(cpuid), &map);
		CPU_NAND(&map, &stopped_cpus);
		if (!CPU_EMPTY(&map)) {
			printf("cpu_reset: Stopping other CPUs\n");
			stop_cpus(map);
		}

		if (PCPU_GET(cpuid) != 0) {
			cpu_reset_proxyid = PCPU_GET(cpuid);
			cpustop_restartfunc = cpu_reset_proxy;
			cpu_reset_proxy_active = 0;
			printf("cpu_reset: Restarting BSP\n");

			
			CPU_SETOF(0, &started_cpus);
			mb = &pcpu_find(0)->pc_monitorbuf;
			atomic_store_int(&mb->stop_state, MONITOR_STOPSTATE_RUNNING);

			cnt = 0;
			while (cpu_reset_proxy_active == 0 && cnt < 10000000) {
				ia32_pause();
				cnt++;	
			}
			if (cpu_reset_proxy_active == 0) {
				printf("cpu_reset: Failed to restart BSP\n");
			} else {
				cpu_reset_proxy_active = 2;
				while (1)
					ia32_pause();
				
			}
		}

		DELAY(1000000);
	}

	cpu_reset_real();
	
}

bool cpu_mwait_usable(void)
{

	return ((cpu_feature2 & CPUID2_MON) != 0 && ((cpu_mon_mwait_flags & (CPUID5_MON_MWAIT_EXT | CPUID5_MWAIT_INTRBREAK)) == (CPUID5_MON_MWAIT_EXT | CPUID5_MWAIT_INTRBREAK)));

}

void (*cpu_idle_hook)(sbintime_t) = NULL;	
static int	cpu_ident_amdc1e = 0;	
static int	idle_mwait = 1;		
SYSCTL_INT(_machdep, OID_AUTO, idle_mwait, CTLFLAG_RWTUN, &idle_mwait, 0, "Use MONITOR/MWAIT for short idle");

static void cpu_idle_acpi(sbintime_t sbt)
{
	int *state;

	state = &PCPU_PTR(monitorbuf)->idle_state;
	atomic_store_int(state, STATE_SLEEPING);

	
	disable_intr();
	if (sched_runnable())
		enable_intr();
	else if (cpu_idle_hook)
		cpu_idle_hook(sbt);
	else acpi_cpu_c1();
	atomic_store_int(state, STATE_RUNNING);
}

static void cpu_idle_hlt(sbintime_t sbt)
{
	int *state;

	state = &PCPU_PTR(monitorbuf)->idle_state;
	atomic_store_int(state, STATE_SLEEPING);

	
	disable_intr();
	if (sched_runnable())
		enable_intr();
	else acpi_cpu_c1();
	atomic_store_int(state, STATE_RUNNING);
}

static void cpu_idle_mwait(sbintime_t sbt)
{
	int *state;

	state = &PCPU_PTR(monitorbuf)->idle_state;
	atomic_store_int(state, STATE_MWAIT);

	
	disable_intr();
	if (sched_runnable()) {
		atomic_store_int(state, STATE_RUNNING);
		enable_intr();
		return;
	}

	cpu_monitor(state, 0, 0);
	if (atomic_load_int(state) == STATE_MWAIT)
		__asm __volatile("sti; mwait" : : "a" (MWAIT_C1), "c" (0));
	else enable_intr();
	atomic_store_int(state, STATE_RUNNING);
}

static void cpu_idle_spin(sbintime_t sbt)
{
	int *state;
	int i;

	state = &PCPU_PTR(monitorbuf)->idle_state;
	atomic_store_int(state, STATE_RUNNING);

	
	for (i = 0; i < 1000; i++) {
		if (sched_runnable())
			return;
		cpu_spinwait();
	}
}







void cpu_probe_amdc1e(void)
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

	
	if (cpu_ident_amdc1e && cpu_disable_c3_sleep) {
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

static int cpu_idle_apl31_workaround;
SYSCTL_INT(_machdep, OID_AUTO, idle_apl31, CTLFLAG_RW, &cpu_idle_apl31_workaround, 0, "Apollo Lake APL31 MWAIT bug workaround");


int cpu_idle_wakeup(int cpu)
{
	struct monitorbuf *mb;
	int *state;

	mb = &pcpu_find(cpu)->pc_monitorbuf;
	state = &mb->idle_state;
	switch (atomic_load_int(state)) {
	case STATE_SLEEPING:
		return (0);
	case STATE_MWAIT:
		atomic_store_int(state, STATE_RUNNING);
		return (cpu_idle_apl31_workaround ? 0 : 1);
	case STATE_RUNNING:
		return (1);
	default:
		panic("bad monitor state");
		return (1);
	}
}


static struct {
	void	*id_fn;
	char	*id_name;
	int	id_cpuid2_flag;
} idle_tbl[] = {
	{ .id_fn = cpu_idle_spin, .id_name = "spin" }, { .id_fn = cpu_idle_mwait, .id_name = "mwait", .id_cpuid2_flag = CPUID2_MON }, { .id_fn = cpu_idle_hlt, .id_name = "hlt" }, { .id_fn = cpu_idle_acpi, .id_name = "acpi" }, };





static int idle_sysctl_available(SYSCTL_HANDLER_ARGS)
{
	char *avail, *p;
	int error;
	int i;

	avail = malloc(256, M_TEMP, M_WAITOK);
	p = avail;
	for (i = 0; i < nitems(idle_tbl); i++) {
		if (idle_tbl[i].id_cpuid2_flag != 0 && (cpu_feature2 & idle_tbl[i].id_cpuid2_flag) == 0)
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

static bool cpu_idle_selector(const char *new_idle_name)
{
	int i;

	for (i = 0; i < nitems(idle_tbl); i++) {
		if (idle_tbl[i].id_cpuid2_flag != 0 && (cpu_feature2 & idle_tbl[i].id_cpuid2_flag) == 0)
			continue;
		if (strcmp(idle_tbl[i].id_name, "acpi") == 0 && cpu_idle_hook == NULL)
			continue;
		if (strcmp(idle_tbl[i].id_name, new_idle_name))
			continue;
		cpu_idle_fn = idle_tbl[i].id_fn;
		if (bootverbose)
			printf("CPU idle set to %s\n", idle_tbl[i].id_name);
		return (true);
	}
	return (false);
}

static int cpu_idle_sysctl(SYSCTL_HANDLER_ARGS)
{
	char buf[16], *p;
	int error, i;

	p = "unknown";
	for (i = 0; i < nitems(idle_tbl); i++) {
		if (idle_tbl[i].id_fn == cpu_idle_fn) {
			p = idle_tbl[i].id_name;
			break;
		}
	}
	strncpy(buf, p, sizeof(buf));
	error = sysctl_handle_string(oidp, buf, sizeof(buf), req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	return (cpu_idle_selector(buf) ? 0 : EINVAL);
}

SYSCTL_PROC(_machdep, OID_AUTO, idle, CTLTYPE_STRING | CTLFLAG_RW, 0, 0, cpu_idle_sysctl, "A", "currently selected idle function");

static void cpu_idle_tun(void *unused __unused)
{
	char tunvar[16];

	if (TUNABLE_STR_FETCH("machdep.idle", tunvar, sizeof(tunvar)))
		cpu_idle_selector(tunvar);
	else if (cpu_vendor_id == CPU_VENDOR_AMD && CPUID_TO_FAMILY(cpu_id) == 0x17 && CPUID_TO_MODEL(cpu_id) == 0x1) {
		
		cpu_idle_selector("hlt");
		idle_mwait = 0;
		mwait_cpustop_broken = true;
	}

	if (cpu_vendor_id == CPU_VENDOR_INTEL && cpu_id == 0x506c9) {
		
		cpu_idle_apl31_workaround = 1;
		mwait_cpustop_broken = true;
	}
	TUNABLE_INT_FETCH("machdep.idle_apl31", &cpu_idle_apl31_workaround);
}
SYSINIT(cpu_idle_tun, SI_SUB_CPU, SI_ORDER_MIDDLE, cpu_idle_tun, NULL);

static int panic_on_nmi = 1;
SYSCTL_INT(_machdep, OID_AUTO, panic_on_nmi, CTLFLAG_RWTUN, &panic_on_nmi, 0, "Panic on NMI raised by hardware failure");

int nmi_is_broadcast = 1;
SYSCTL_INT(_machdep, OID_AUTO, nmi_is_broadcast, CTLFLAG_RWTUN, &nmi_is_broadcast, 0, "Chipset NMI is broadcast");


int kdb_on_nmi = 1;
SYSCTL_INT(_machdep, OID_AUTO, kdb_on_nmi, CTLFLAG_RWTUN, &kdb_on_nmi, 0, "Go to KDB on NMI with unknown source");



void nmi_call_kdb(u_int cpu, u_int type, struct trapframe *frame)
{
	bool claimed = false;


	
	if (isa_nmi(frame->tf_err)) {
		claimed = true;
		if (panic_on_nmi)
			panic("NMI indicates hardware failure");
	}


	if (!claimed && kdb_on_nmi) {
		
		printf("NMI/cpu%d ... going to debugger\n", cpu);
		kdb_trap(type, 0, frame);
	}

}

void nmi_handle_intr(u_int type, struct trapframe *frame)
{


	if (nmi_is_broadcast) {
		nmi_call_kdb_smp(type, frame);
		return;
	}

	nmi_call_kdb(PCPU_GET(cpuid), type, frame);
}

int hw_ibrs_active;
int hw_ibrs_disable = 1;

SYSCTL_INT(_hw, OID_AUTO, ibrs_active, CTLFLAG_RD, &hw_ibrs_active, 0, "Indirect Branch Restricted Speculation active");

void hw_ibrs_recalculate(void)
{
	uint64_t v;

	if ((cpu_ia32_arch_caps & IA32_ARCH_CAP_IBRS_ALL) != 0) {
		if (hw_ibrs_disable) {
			v = rdmsr(MSR_IA32_SPEC_CTRL);
			v &= ~(uint64_t)IA32_SPEC_CTRL_IBRS;
			wrmsr(MSR_IA32_SPEC_CTRL, v);
		} else {
			v = rdmsr(MSR_IA32_SPEC_CTRL);
			v |= IA32_SPEC_CTRL_IBRS;
			wrmsr(MSR_IA32_SPEC_CTRL, v);
		}
		return;
	}
	hw_ibrs_active = (cpu_stdext_feature3 & CPUID_STDEXT3_IBPB) != 0 && !hw_ibrs_disable;
}

static int hw_ibrs_disable_handler(SYSCTL_HANDLER_ARGS)
{
	int error, val;

	val = hw_ibrs_disable;
	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	hw_ibrs_disable = val != 0;
	hw_ibrs_recalculate();
	return (0);
}
SYSCTL_PROC(_hw, OID_AUTO, ibrs_disable, CTLTYPE_INT | CTLFLAG_RWTUN | CTLFLAG_NOFETCH | CTLFLAG_MPSAFE, NULL, 0, hw_ibrs_disable_handler, "I", "Disable Indirect Branch Restricted Speculation");


int hw_ssb_active;
int hw_ssb_disable;

SYSCTL_INT(_hw, OID_AUTO, spec_store_bypass_disable_active, CTLFLAG_RD, &hw_ssb_active, 0, "Speculative Store Bypass Disable active");


static void hw_ssb_set_one(bool enable)
{
	uint64_t v;

	v = rdmsr(MSR_IA32_SPEC_CTRL);
	if (enable)
		v |= (uint64_t)IA32_SPEC_CTRL_SSBD;
	else v &= ~(uint64_t)IA32_SPEC_CTRL_SSBD;
	wrmsr(MSR_IA32_SPEC_CTRL, v);
}

static void hw_ssb_set(bool enable, bool for_all_cpus)
{
	struct thread *td;
	int bound_cpu, i, is_bound;

	if ((cpu_stdext_feature3 & CPUID_STDEXT3_SSBD) == 0) {
		hw_ssb_active = 0;
		return;
	}
	hw_ssb_active = enable;
	if (for_all_cpus) {
		td = curthread;
		thread_lock(td);
		is_bound = sched_is_bound(td);
		bound_cpu = td->td_oncpu;
		CPU_FOREACH(i) {
			sched_bind(td, i);
			hw_ssb_set_one(enable);
		}
		if (is_bound)
			sched_bind(td, bound_cpu);
		else sched_unbind(td);
		thread_unlock(td);
	} else {
		hw_ssb_set_one(enable);
	}
}

void hw_ssb_recalculate(bool all_cpus)
{

	switch (hw_ssb_disable) {
	default:
		hw_ssb_disable = 0;
		
	case 0: 
		hw_ssb_set(false, all_cpus);
		break;
	case 1: 
		hw_ssb_set(true, all_cpus);
		break;
	case 2: 
		hw_ssb_set((cpu_ia32_arch_caps & IA32_ARCH_CAP_SSB_NO) != 0 ? false : true, all_cpus);
		break;
	}
}

static int hw_ssb_disable_handler(SYSCTL_HANDLER_ARGS)
{
	int error, val;

	val = hw_ssb_disable;
	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	hw_ssb_disable = val;
	hw_ssb_recalculate(true);
	return (0);
}
SYSCTL_PROC(_hw, OID_AUTO, spec_store_bypass_disable, CTLTYPE_INT | CTLFLAG_RWTUN | CTLFLAG_NOFETCH | CTLFLAG_MPSAFE, NULL, 0, hw_ssb_disable_handler, "I", "Speculative Store Bypass Disable (0 - off, 1 - on, 2 - auto");



int hw_mds_disable;


void mds_handler_void(void);
void mds_handler_verw(void);
void mds_handler_ivb(void);
void mds_handler_bdw(void);
void mds_handler_skl_sse(void);
void mds_handler_skl_avx(void);
void mds_handler_skl_avx512(void);
void mds_handler_silvermont(void);
void (*mds_handler)(void) = mds_handler_void;

static int sysctl_hw_mds_disable_state_handler(SYSCTL_HANDLER_ARGS)
{
	const char *state;

	if (mds_handler == mds_handler_void)
		state = "inactive";
	else if (mds_handler == mds_handler_verw)
		state = "VERW";
	else if (mds_handler == mds_handler_ivb)
		state = "software IvyBridge";
	else if (mds_handler == mds_handler_bdw)
		state = "software Broadwell";
	else if (mds_handler == mds_handler_skl_sse)
		state = "software Skylake SSE";
	else if (mds_handler == mds_handler_skl_avx)
		state = "software Skylake AVX";
	else if (mds_handler == mds_handler_skl_avx512)
		state = "software Skylake AVX512";
	else if (mds_handler == mds_handler_silvermont)
		state = "software Silvermont";
	else state = "unknown";
	return (SYSCTL_OUT(req, state, strlen(state)));
}

SYSCTL_PROC(_hw, OID_AUTO, mds_disable_state, CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_MPSAFE, NULL, 0, sysctl_hw_mds_disable_state_handler, "A", "Microarchitectural Data Sampling Mitigation state");



_Static_assert(__offsetof(struct pcpu, pc_mds_tmp) % 64 == 0, "MDS AVX512");

void hw_mds_recalculate(void)
{
	struct pcpu *pc;
	vm_offset_t b64;
	u_long xcr0;
	int i;

	
	if (cpu_vendor_id != CPU_VENDOR_INTEL || hw_mds_disable == 0 || ((cpu_ia32_arch_caps & (IA32_ARCH_CAP_RDCL_NO | IA32_ARCH_CAP_MDS_NO)) != 0 && hw_mds_disable == 3)) {

		mds_handler = mds_handler_void;
	} else if (((cpu_stdext_feature3 & CPUID_STDEXT3_MD_CLEAR) != 0 && hw_mds_disable == 3) || hw_mds_disable == 1) {
		mds_handler = mds_handler_verw;
	} else if (CPUID_TO_FAMILY(cpu_id) == 0x6 && (CPUID_TO_MODEL(cpu_id) == 0x2e || CPUID_TO_MODEL(cpu_id) == 0x1e || CPUID_TO_MODEL(cpu_id) == 0x1f || CPUID_TO_MODEL(cpu_id) == 0x1a || CPUID_TO_MODEL(cpu_id) == 0x2f || CPUID_TO_MODEL(cpu_id) == 0x25 || CPUID_TO_MODEL(cpu_id) == 0x2c || CPUID_TO_MODEL(cpu_id) == 0x2d || CPUID_TO_MODEL(cpu_id) == 0x2a || CPUID_TO_MODEL(cpu_id) == 0x3e || CPUID_TO_MODEL(cpu_id) == 0x3a) && (hw_mds_disable == 2 || hw_mds_disable == 3)) {






		
		CPU_FOREACH(i) {
			pc = pcpu_find(i);
			if (pc->pc_mds_buf == NULL) {
				pc->pc_mds_buf = malloc_domainset(672, M_TEMP, DOMAINSET_PREF(pc->pc_domain), M_WAITOK);
				bzero(pc->pc_mds_buf, 16);
			}
		}
		mds_handler = mds_handler_ivb;
	} else if (CPUID_TO_FAMILY(cpu_id) == 0x6 && (CPUID_TO_MODEL(cpu_id) == 0x3f || CPUID_TO_MODEL(cpu_id) == 0x3c || CPUID_TO_MODEL(cpu_id) == 0x45 || CPUID_TO_MODEL(cpu_id) == 0x46 || CPUID_TO_MODEL(cpu_id) == 0x56 || CPUID_TO_MODEL(cpu_id) == 0x4f || CPUID_TO_MODEL(cpu_id) == 0x47 || CPUID_TO_MODEL(cpu_id) == 0x3d) && (hw_mds_disable == 2 || hw_mds_disable == 3)) {




		
		CPU_FOREACH(i) {
			pc = pcpu_find(i);
			if (pc->pc_mds_buf == NULL) {
				pc->pc_mds_buf = malloc_domainset(1536, M_TEMP, DOMAINSET_PREF(pc->pc_domain), M_WAITOK);
				bzero(pc->pc_mds_buf, 16);
			}
		}
		mds_handler = mds_handler_bdw;
	} else if (CPUID_TO_FAMILY(cpu_id) == 0x6 && ((CPUID_TO_MODEL(cpu_id) == 0x55 && (cpu_id & CPUID_STEPPING) <= 5) || CPUID_TO_MODEL(cpu_id) == 0x4e || CPUID_TO_MODEL(cpu_id) == 0x5e || (CPUID_TO_MODEL(cpu_id) == 0x8e && (cpu_id & CPUID_STEPPING) <= 0xb) || (CPUID_TO_MODEL(cpu_id) == 0x9e && (cpu_id & CPUID_STEPPING) <= 0xc)) && (hw_mds_disable == 2 || hw_mds_disable == 3)) {







		
		CPU_FOREACH(i) {
			pc = pcpu_find(i);
			if (pc->pc_mds_buf == NULL) {
				pc->pc_mds_buf = malloc_domainset(6 * 1024, M_TEMP, DOMAINSET_PREF(pc->pc_domain), M_WAITOK);

				b64 = (vm_offset_t)malloc_domainset(64 + 63, M_TEMP, DOMAINSET_PREF(pc->pc_domain), M_WAITOK);

				pc->pc_mds_buf64 = (void *)roundup2(b64, 64);
				bzero(pc->pc_mds_buf64, 64);
			}
		}
		xcr0 = rxcr(0);
		if ((xcr0 & XFEATURE_ENABLED_ZMM_HI256) != 0 && (cpu_stdext_feature & CPUID_STDEXT_AVX512DQ) != 0)
			mds_handler = mds_handler_skl_avx512;
		else if ((xcr0 & XFEATURE_ENABLED_AVX) != 0 && (cpu_feature2 & CPUID2_AVX) != 0)
			mds_handler = mds_handler_skl_avx;
		else mds_handler = mds_handler_skl_sse;
	} else if (CPUID_TO_FAMILY(cpu_id) == 0x6 && ((CPUID_TO_MODEL(cpu_id) == 0x37 || CPUID_TO_MODEL(cpu_id) == 0x4a || CPUID_TO_MODEL(cpu_id) == 0x4c || CPUID_TO_MODEL(cpu_id) == 0x4d || CPUID_TO_MODEL(cpu_id) == 0x5a || CPUID_TO_MODEL(cpu_id) == 0x5d || CPUID_TO_MODEL(cpu_id) == 0x6e || CPUID_TO_MODEL(cpu_id) == 0x65 || CPUID_TO_MODEL(cpu_id) == 0x75 || CPUID_TO_MODEL(cpu_id) == 0x1c || CPUID_TO_MODEL(cpu_id) == 0x26 || CPUID_TO_MODEL(cpu_id) == 0x27 || CPUID_TO_MODEL(cpu_id) == 0x35 || CPUID_TO_MODEL(cpu_id) == 0x36 || CPUID_TO_MODEL(cpu_id) == 0x7a))) {














		
		CPU_FOREACH(i) {
			pc = pcpu_find(i);
			if (pc->pc_mds_buf == NULL)
				pc->pc_mds_buf = malloc(256, M_TEMP, M_WAITOK);
		}
		mds_handler = mds_handler_silvermont;
	} else {
		hw_mds_disable = 0;
		mds_handler = mds_handler_void;
	}
}

static void hw_mds_recalculate_boot(void *arg __unused)
{

	hw_mds_recalculate();
}
SYSINIT(mds_recalc, SI_SUB_SMP, SI_ORDER_ANY, hw_mds_recalculate_boot, NULL);

static int sysctl_mds_disable_handler(SYSCTL_HANDLER_ARGS)
{
	int error, val;

	val = hw_mds_disable;
	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (val < 0 || val > 3)
		return (EINVAL);
	hw_mds_disable = val;
	hw_mds_recalculate();
	return (0);
}

SYSCTL_PROC(_hw, OID_AUTO, mds_disable, CTLTYPE_INT | CTLFLAG_RWTUN | CTLFLAG_NOFETCH | CTLFLAG_MPSAFE, NULL, 0, sysctl_mds_disable_handler, "I", "Microarchitectural Data Sampling Mitigation " "(0 - off, 1 - on VERW, 2 - on SW, 3 - on AUTO");





bool disable_wp(void)
{
	u_int cr0;

	cr0 = rcr0();
	if ((cr0 & CR0_WP) == 0)
		return (false);
	load_cr0(cr0 & ~CR0_WP);
	return (true);
}

void restore_wp(bool old_wp)
{

	if (old_wp)
		load_cr0(rcr0() | CR0_WP);
}

bool acpi_get_fadt_bootflags(uint16_t *flagsp)
{

	ACPI_TABLE_FADT *fadt;
	vm_paddr_t physaddr;

	physaddr = acpi_find_table(ACPI_SIG_FADT);
	if (physaddr == 0)
		return (false);
	fadt = acpi_map_table(physaddr, ACPI_SIG_FADT);
	if (fadt == NULL)
		return (false);
	*flagsp = fadt->BootFlags;
	acpi_unmap_table(fadt);
	return (true);

	return (false);

}
