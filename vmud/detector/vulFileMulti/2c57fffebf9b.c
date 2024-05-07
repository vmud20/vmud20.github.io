





























































u32 elf_hwcap2 __read_mostly;


cpumask_var_t cpu_initialized_mask;
cpumask_var_t cpu_callout_mask;
cpumask_var_t cpu_callin_mask;


cpumask_var_t cpu_sibling_setup_mask;


int smp_num_siblings = 1;
EXPORT_SYMBOL(smp_num_siblings);


DEFINE_PER_CPU_READ_MOSTLY(u16, cpu_llc_id) = BAD_APICID;


void __init setup_cpu_local_masks(void)
{
	alloc_bootmem_cpumask_var(&cpu_initialized_mask);
	alloc_bootmem_cpumask_var(&cpu_callin_mask);
	alloc_bootmem_cpumask_var(&cpu_callout_mask);
	alloc_bootmem_cpumask_var(&cpu_sibling_setup_mask);
}

static void default_init(struct cpuinfo_x86 *c)
{

	cpu_detect_cache_sizes(c);

	
	
	if (c->cpuid_level == -1) {
		
		if (c->x86 == 4)
			strcpy(c->x86_model_id, "486");
		else if (c->x86 == 3)
			strcpy(c->x86_model_id, "386");
	}

}

static const struct cpu_dev default_cpu = {
	.c_init		= default_init, .c_vendor	= "Unknown", .c_x86_vendor	= X86_VENDOR_UNKNOWN, };



static const struct cpu_dev *this_cpu = &default_cpu;

DEFINE_PER_CPU_PAGE_ALIGNED(struct gdt_page, gdt_page) = { .gdt = {

	
	[GDT_ENTRY_KERNEL32_CS]		= GDT_ENTRY_INIT(0xc09b, 0, 0xfffff), [GDT_ENTRY_KERNEL_CS]		= GDT_ENTRY_INIT(0xa09b, 0, 0xfffff), [GDT_ENTRY_KERNEL_DS]		= GDT_ENTRY_INIT(0xc093, 0, 0xfffff), [GDT_ENTRY_DEFAULT_USER32_CS]	= GDT_ENTRY_INIT(0xc0fb, 0, 0xfffff), [GDT_ENTRY_DEFAULT_USER_DS]	= GDT_ENTRY_INIT(0xc0f3, 0, 0xfffff), [GDT_ENTRY_DEFAULT_USER_CS]	= GDT_ENTRY_INIT(0xa0fb, 0, 0xfffff),  [GDT_ENTRY_KERNEL_CS]		= GDT_ENTRY_INIT(0xc09a, 0, 0xfffff), [GDT_ENTRY_KERNEL_DS]		= GDT_ENTRY_INIT(0xc092, 0, 0xfffff), [GDT_ENTRY_DEFAULT_USER_CS]	= GDT_ENTRY_INIT(0xc0fa, 0, 0xfffff), [GDT_ENTRY_DEFAULT_USER_DS]	= GDT_ENTRY_INIT(0xc0f2, 0, 0xfffff),   [GDT_ENTRY_PNPBIOS_CS32]	= GDT_ENTRY_INIT(0x409a, 0, 0xffff),  [GDT_ENTRY_PNPBIOS_CS16]	= GDT_ENTRY_INIT(0x009a, 0, 0xffff),  [GDT_ENTRY_PNPBIOS_DS]		= GDT_ENTRY_INIT(0x0092, 0, 0xffff),  [GDT_ENTRY_PNPBIOS_TS1]		= GDT_ENTRY_INIT(0x0092, 0, 0),  [GDT_ENTRY_PNPBIOS_TS2]		= GDT_ENTRY_INIT(0x0092, 0, 0),   [GDT_ENTRY_APMBIOS_BASE]	= GDT_ENTRY_INIT(0x409a, 0, 0xffff),  [GDT_ENTRY_APMBIOS_BASE+1]	= GDT_ENTRY_INIT(0x009a, 0, 0xffff),  [GDT_ENTRY_APMBIOS_BASE+2]	= GDT_ENTRY_INIT(0x4092, 0, 0xffff),  [GDT_ENTRY_ESPFIX_SS]		= GDT_ENTRY_INIT(0xc092, 0, 0xfffff), [GDT_ENTRY_PERCPU]		= GDT_ENTRY_INIT(0xc092, 0, 0xfffff), GDT_STACK_CANARY_INIT  } };

































EXPORT_PER_CPU_SYMBOL_GPL(gdt_page);

static int __init x86_mpx_setup(char *s)
{
	
	if (strlen(s))
		return 0;

	
	if (!boot_cpu_has(X86_FEATURE_MPX))
		return 1;

	setup_clear_cpu_cap(X86_FEATURE_MPX);
	pr_info("nompx: Intel Memory Protection Extensions (MPX) disabled\n");
	return 1;
}
__setup("nompx", x86_mpx_setup);


static int __init x86_nopcid_setup(char *s)
{
	
	if (s)
		return -EINVAL;

	
	if (!boot_cpu_has(X86_FEATURE_PCID))
		return 0;

	setup_clear_cpu_cap(X86_FEATURE_PCID);
	pr_info("nopcid: PCID feature disabled\n");
	return 0;
}
early_param("nopcid", x86_nopcid_setup);


static int __init x86_noinvpcid_setup(char *s)
{
	
	if (s)
		return -EINVAL;

	
	if (!boot_cpu_has(X86_FEATURE_INVPCID))
		return 0;

	setup_clear_cpu_cap(X86_FEATURE_INVPCID);
	pr_info("noinvpcid: INVPCID feature disabled\n");
	return 0;
}
early_param("noinvpcid", x86_noinvpcid_setup);


static int cachesize_override = -1;
static int disable_x86_serial_nr = 1;

static int __init cachesize_setup(char *str)
{
	get_option(&str, &cachesize_override);
	return 1;
}
__setup("cachesize=", cachesize_setup);

static int __init x86_sep_setup(char *s)
{
	setup_clear_cpu_cap(X86_FEATURE_SEP);
	return 1;
}
__setup("nosep", x86_sep_setup);


static inline int flag_is_changeable_p(u32 flag)
{
	u32 f1, f2;

	
	asm volatile ("pushfl		\n\t" "pushfl		\n\t" "popl %0		\n\t" "movl %0, %1	\n\t" "xorl %2, %0	\n\t" "pushl %0		\n\t" "popfl		\n\t" "pushfl		\n\t" "popl %0		\n\t" "popfl		\n\t"  : "=&r" (f1), "=&r" (f2)










		      : "ir" (flag));

	return ((f1^f2) & flag) != 0;
}


int have_cpuid_p(void)
{
	return flag_is_changeable_p(X86_EFLAGS_ID);
}

static void squash_the_stupid_serial_number(struct cpuinfo_x86 *c)
{
	unsigned long lo, hi;

	if (!cpu_has(c, X86_FEATURE_PN) || !disable_x86_serial_nr)
		return;

	

	rdmsr(MSR_IA32_BBL_CR_CTL, lo, hi);
	lo |= 0x200000;
	wrmsr(MSR_IA32_BBL_CR_CTL, lo, hi);

	pr_notice("CPU serial number disabled.\n");
	clear_cpu_cap(c, X86_FEATURE_PN);

	
	c->cpuid_level = cpuid_eax(0);
}

static int __init x86_serial_nr_setup(char *s)
{
	disable_x86_serial_nr = 0;
	return 1;
}
__setup("serialnumber", x86_serial_nr_setup);

static inline int flag_is_changeable_p(u32 flag)
{
	return 1;
}
static inline void squash_the_stupid_serial_number(struct cpuinfo_x86 *c)
{
}


static __init int setup_disable_smep(char *arg)
{
	setup_clear_cpu_cap(X86_FEATURE_SMEP);
	
	check_mpx_erratum(&boot_cpu_data);
	return 1;
}
__setup("nosmep", setup_disable_smep);

static __always_inline void setup_smep(struct cpuinfo_x86 *c)
{
	if (cpu_has(c, X86_FEATURE_SMEP))
		cr4_set_bits(X86_CR4_SMEP);
}

static __init int setup_disable_smap(char *arg)
{
	setup_clear_cpu_cap(X86_FEATURE_SMAP);
	return 1;
}
__setup("nosmap", setup_disable_smap);

static __always_inline void setup_smap(struct cpuinfo_x86 *c)
{
	unsigned long eflags = native_save_fl();

	
	BUG_ON(eflags & X86_EFLAGS_AC);

	if (cpu_has(c, X86_FEATURE_SMAP)) {

		cr4_set_bits(X86_CR4_SMAP);

		cr4_clear_bits(X86_CR4_SMAP);

	}
}

static __always_inline void setup_umip(struct cpuinfo_x86 *c)
{
	
	if (!cpu_feature_enabled(X86_FEATURE_UMIP))
		goto out;

	
	if (!cpu_has(c, X86_FEATURE_UMIP))
		goto out;

	cr4_set_bits(X86_CR4_UMIP);

	pr_info_once("x86/cpu: User Mode Instruction Prevention (UMIP) activated\n");

	return;

out:
	
	cr4_clear_bits(X86_CR4_UMIP);
}


static bool pku_disabled;

static __always_inline void setup_pku(struct cpuinfo_x86 *c)
{
	struct pkru_state *pk;

	
	if (!cpu_feature_enabled(X86_FEATURE_PKU))
		return;
	
	if (!cpu_has(c, X86_FEATURE_PKU))
		return;
	if (pku_disabled)
		return;

	cr4_set_bits(X86_CR4_PKE);
	pk = get_xsave_addr(&init_fpstate.xsave, XFEATURE_PKRU);
	if (pk)
		pk->pkru = init_pkru_value;
	
	get_cpu_cap(c);
}


static __init int setup_disable_pku(char *arg)
{
	
	pr_info("x86: 'nopku' specified, disabling Memory Protection Keys\n");
	pku_disabled = true;
	return 1;
}
__setup("nopku", setup_disable_pku);



struct cpuid_dependent_feature {
	u32 feature;
	u32 level;
};

static const struct cpuid_dependent_feature cpuid_dependent_features[] = {
	{ X86_FEATURE_MWAIT,		0x00000005 }, { X86_FEATURE_DCA,		0x00000009 }, { X86_FEATURE_XSAVE,		0x0000000d }, { 0, 0 }


};

static void filter_cpuid_features(struct cpuinfo_x86 *c, bool warn)
{
	const struct cpuid_dependent_feature *df;

	for (df = cpuid_dependent_features; df->feature; df++) {

		if (!cpu_has(c, df->feature))
			continue;
		
		if (!((s32)df->level < 0 ? (u32)df->level > (u32)c->extended_cpuid_level :
		     (s32)df->level > (s32)c->cpuid_level))
			continue;

		clear_cpu_cap(c, df->feature);
		if (!warn)
			continue;

		pr_warn("CPU: CPU feature " X86_CAP_FMT " disabled, no CPUID level 0x%x\n", x86_cap_flag(df->feature), df->level);
	}
}




static const char *table_lookup_model(struct cpuinfo_x86 *c)
{

	const struct legacy_cpu_model_info *info;

	if (c->x86_model >= 16)
		return NULL;	

	if (!this_cpu)
		return NULL;

	info = this_cpu->legacy_models;

	while (info->family) {
		if (info->family == c->x86)
			return info->model_names[c->x86_model];
		info++;
	}

	return NULL;		
}

__u32 cpu_caps_cleared[NCAPINTS + NBUGINTS];
__u32 cpu_caps_set[NCAPINTS + NBUGINTS];

void load_percpu_segment(int cpu)
{

	loadsegment(fs, __KERNEL_PERCPU);

	__loadsegment_simple(gs, 0);
	wrmsrl(MSR_GS_BASE, cpu_kernelmode_gs_base(cpu));

	load_stack_canary_segment();
}



DEFINE_PER_CPU(struct cpu_entry_area *, cpu_entry_area);



void load_direct_gdt(int cpu)
{
	struct desc_ptr gdt_descr;

	gdt_descr.address = (long)get_cpu_gdt_rw(cpu);
	gdt_descr.size = GDT_SIZE - 1;
	load_gdt(&gdt_descr);
}
EXPORT_SYMBOL_GPL(load_direct_gdt);


void load_fixmap_gdt(int cpu)
{
	struct desc_ptr gdt_descr;

	gdt_descr.address = (long)get_cpu_gdt_ro(cpu);
	gdt_descr.size = GDT_SIZE - 1;
	load_gdt(&gdt_descr);
}
EXPORT_SYMBOL_GPL(load_fixmap_gdt);


void switch_to_new_gdt(int cpu)
{
	
	load_direct_gdt(cpu);
	
	load_percpu_segment(cpu);
}

static const struct cpu_dev *cpu_devs[X86_VENDOR_NUM] = {};

static void get_model_name(struct cpuinfo_x86 *c)
{
	unsigned int *v;
	char *p, *q, *s;

	if (c->extended_cpuid_level < 0x80000004)
		return;

	v = (unsigned int *)c->x86_model_id;
	cpuid(0x80000002, &v[0], &v[1], &v[2], &v[3]);
	cpuid(0x80000003, &v[4], &v[5], &v[6], &v[7]);
	cpuid(0x80000004, &v[8], &v[9], &v[10], &v[11]);
	c->x86_model_id[48] = 0;

	
	p = q = s = &c->x86_model_id[0];

	while (*p == ' ')
		p++;

	while (*p) {
		
		if (!isspace(*p))
			s = q;

		*q++ = *p++;
	}

	*(s + 1) = '\0';
}

void detect_num_cpu_cores(struct cpuinfo_x86 *c)
{
	unsigned int eax, ebx, ecx, edx;

	c->x86_max_cores = 1;
	if (!IS_ENABLED(CONFIG_SMP) || c->cpuid_level < 4)
		return;

	cpuid_count(4, 0, &eax, &ebx, &ecx, &edx);
	if (eax & 0x1f)
		c->x86_max_cores = (eax >> 26) + 1;
}

void cpu_detect_cache_sizes(struct cpuinfo_x86 *c)
{
	unsigned int n, dummy, ebx, ecx, edx, l2size;

	n = c->extended_cpuid_level;

	if (n >= 0x80000005) {
		cpuid(0x80000005, &dummy, &ebx, &ecx, &edx);
		c->x86_cache_size = (ecx>>24) + (edx>>24);

		
		c->x86_tlbsize = 0;

	}

	if (n < 0x80000006)	
		return;

	cpuid(0x80000006, &dummy, &ebx, &ecx, &edx);
	l2size = ecx >> 16;


	c->x86_tlbsize += ((ebx >> 16) & 0xfff) + (ebx & 0xfff);

	
	if (this_cpu->legacy_cache_size)
		l2size = this_cpu->legacy_cache_size(c, l2size);

	
	if (cachesize_override != -1)
		l2size = cachesize_override;

	if (l2size == 0)
		return;		


	c->x86_cache_size = l2size;
}

u16 __read_mostly tlb_lli_4k[NR_INFO];
u16 __read_mostly tlb_lli_2m[NR_INFO];
u16 __read_mostly tlb_lli_4m[NR_INFO];
u16 __read_mostly tlb_lld_4k[NR_INFO];
u16 __read_mostly tlb_lld_2m[NR_INFO];
u16 __read_mostly tlb_lld_4m[NR_INFO];
u16 __read_mostly tlb_lld_1g[NR_INFO];

static void cpu_detect_tlb(struct cpuinfo_x86 *c)
{
	if (this_cpu->c_detect_tlb)
		this_cpu->c_detect_tlb(c);

	pr_info("Last level iTLB entries: 4KB %d, 2MB %d, 4MB %d\n", tlb_lli_4k[ENTRIES], tlb_lli_2m[ENTRIES], tlb_lli_4m[ENTRIES]);


	pr_info("Last level dTLB entries: 4KB %d, 2MB %d, 4MB %d, 1GB %d\n", tlb_lld_4k[ENTRIES], tlb_lld_2m[ENTRIES], tlb_lld_4m[ENTRIES], tlb_lld_1g[ENTRIES]);

}

int detect_ht_early(struct cpuinfo_x86 *c)
{

	u32 eax, ebx, ecx, edx;

	if (!cpu_has(c, X86_FEATURE_HT))
		return -1;

	if (cpu_has(c, X86_FEATURE_CMP_LEGACY))
		return -1;

	if (cpu_has(c, X86_FEATURE_XTOPOLOGY))
		return -1;

	cpuid(1, &eax, &ebx, &ecx, &edx);

	smp_num_siblings = (ebx & 0xff0000) >> 16;
	if (smp_num_siblings == 1)
		pr_info_once("CPU0: Hyper-Threading is disabled\n");

	return 0;
}

void detect_ht(struct cpuinfo_x86 *c)
{

	int index_msb, core_bits;

	if (detect_ht_early(c) < 0)
		return;

	index_msb = get_count_order(smp_num_siblings);
	c->phys_proc_id = apic->phys_pkg_id(c->initial_apicid, index_msb);

	smp_num_siblings = smp_num_siblings / c->x86_max_cores;

	index_msb = get_count_order(smp_num_siblings);

	core_bits = get_count_order(c->x86_max_cores);

	c->cpu_core_id = apic->phys_pkg_id(c->initial_apicid, index_msb) & ((1 << core_bits) - 1);

}

static void get_cpu_vendor(struct cpuinfo_x86 *c)
{
	char *v = c->x86_vendor_id;
	int i;

	for (i = 0; i < X86_VENDOR_NUM; i++) {
		if (!cpu_devs[i])
			break;

		if (!strcmp(v, cpu_devs[i]->c_ident[0]) || (cpu_devs[i]->c_ident[1] && !strcmp(v, cpu_devs[i]->c_ident[1]))) {


			this_cpu = cpu_devs[i];
			c->x86_vendor = this_cpu->c_x86_vendor;
			return;
		}
	}

	pr_err_once("CPU: vendor_id '%s' unknown, using generic init.\n"  "CPU: Your system may be unstable.\n", v)

	c->x86_vendor = X86_VENDOR_UNKNOWN;
	this_cpu = &default_cpu;
}

void cpu_detect(struct cpuinfo_x86 *c)
{
	
	cpuid(0x00000000, (unsigned int *)&c->cpuid_level, (unsigned int *)&c->x86_vendor_id[0], (unsigned int *)&c->x86_vendor_id[8], (unsigned int *)&c->x86_vendor_id[4]);



	c->x86 = 4;
	
	if (c->cpuid_level >= 0x00000001) {
		u32 junk, tfms, cap0, misc;

		cpuid(0x00000001, &tfms, &misc, &junk, &cap0);
		c->x86		= x86_family(tfms);
		c->x86_model	= x86_model(tfms);
		c->x86_stepping	= x86_stepping(tfms);

		if (cap0 & (1<<19)) {
			c->x86_clflush_size = ((misc >> 8) & 0xff) * 8;
			c->x86_cache_alignment = c->x86_clflush_size;
		}
	}
}

static void apply_forced_caps(struct cpuinfo_x86 *c)
{
	int i;

	for (i = 0; i < NCAPINTS + NBUGINTS; i++) {
		c->x86_capability[i] &= ~cpu_caps_cleared[i];
		c->x86_capability[i] |= cpu_caps_set[i];
	}
}

static void init_speculation_control(struct cpuinfo_x86 *c)
{
	
	if (cpu_has(c, X86_FEATURE_SPEC_CTRL)) {
		set_cpu_cap(c, X86_FEATURE_IBRS);
		set_cpu_cap(c, X86_FEATURE_IBPB);
		set_cpu_cap(c, X86_FEATURE_MSR_SPEC_CTRL);
	}

	if (cpu_has(c, X86_FEATURE_INTEL_STIBP))
		set_cpu_cap(c, X86_FEATURE_STIBP);

	if (cpu_has(c, X86_FEATURE_SPEC_CTRL_SSBD) || cpu_has(c, X86_FEATURE_VIRT_SSBD))
		set_cpu_cap(c, X86_FEATURE_SSBD);

	if (cpu_has(c, X86_FEATURE_AMD_IBRS)) {
		set_cpu_cap(c, X86_FEATURE_IBRS);
		set_cpu_cap(c, X86_FEATURE_MSR_SPEC_CTRL);
	}

	if (cpu_has(c, X86_FEATURE_AMD_IBPB))
		set_cpu_cap(c, X86_FEATURE_IBPB);

	if (cpu_has(c, X86_FEATURE_AMD_STIBP)) {
		set_cpu_cap(c, X86_FEATURE_STIBP);
		set_cpu_cap(c, X86_FEATURE_MSR_SPEC_CTRL);
	}

	if (cpu_has(c, X86_FEATURE_AMD_SSBD)) {
		set_cpu_cap(c, X86_FEATURE_SSBD);
		set_cpu_cap(c, X86_FEATURE_MSR_SPEC_CTRL);
		clear_cpu_cap(c, X86_FEATURE_VIRT_SSBD);
	}
}

void get_cpu_cap(struct cpuinfo_x86 *c)
{
	u32 eax, ebx, ecx, edx;

	
	if (c->cpuid_level >= 0x00000001) {
		cpuid(0x00000001, &eax, &ebx, &ecx, &edx);

		c->x86_capability[CPUID_1_ECX] = ecx;
		c->x86_capability[CPUID_1_EDX] = edx;
	}

	
	if (c->cpuid_level >= 0x00000006)
		c->x86_capability[CPUID_6_EAX] = cpuid_eax(0x00000006);

	
	if (c->cpuid_level >= 0x00000007) {
		cpuid_count(0x00000007, 0, &eax, &ebx, &ecx, &edx);
		c->x86_capability[CPUID_7_0_EBX] = ebx;
		c->x86_capability[CPUID_7_ECX] = ecx;
		c->x86_capability[CPUID_7_EDX] = edx;
	}

	
	if (c->cpuid_level >= 0x0000000d) {
		cpuid_count(0x0000000d, 1, &eax, &ebx, &ecx, &edx);

		c->x86_capability[CPUID_D_1_EAX] = eax;
	}

	
	if (c->cpuid_level >= 0x0000000F) {

		
		cpuid_count(0x0000000F, 0, &eax, &ebx, &ecx, &edx);
		c->x86_capability[CPUID_F_0_EDX] = edx;

		if (cpu_has(c, X86_FEATURE_CQM_LLC)) {
			
			c->x86_cache_max_rmid = ebx;

			
			cpuid_count(0x0000000F, 1, &eax, &ebx, &ecx, &edx);
			c->x86_capability[CPUID_F_1_EDX] = edx;

			if ((cpu_has(c, X86_FEATURE_CQM_OCCUP_LLC)) || ((cpu_has(c, X86_FEATURE_CQM_MBM_TOTAL)) || (cpu_has(c, X86_FEATURE_CQM_MBM_LOCAL)))) {

				c->x86_cache_max_rmid = ecx;
				c->x86_cache_occ_scale = ebx;
			}
		} else {
			c->x86_cache_max_rmid = -1;
			c->x86_cache_occ_scale = -1;
		}
	}

	
	eax = cpuid_eax(0x80000000);
	c->extended_cpuid_level = eax;

	if ((eax & 0xffff0000) == 0x80000000) {
		if (eax >= 0x80000001) {
			cpuid(0x80000001, &eax, &ebx, &ecx, &edx);

			c->x86_capability[CPUID_8000_0001_ECX] = ecx;
			c->x86_capability[CPUID_8000_0001_EDX] = edx;
		}
	}

	if (c->extended_cpuid_level >= 0x80000007) {
		cpuid(0x80000007, &eax, &ebx, &ecx, &edx);

		c->x86_capability[CPUID_8000_0007_EBX] = ebx;
		c->x86_power = edx;
	}

	if (c->extended_cpuid_level >= 0x80000008) {
		cpuid(0x80000008, &eax, &ebx, &ecx, &edx);
		c->x86_capability[CPUID_8000_0008_EBX] = ebx;
	}

	if (c->extended_cpuid_level >= 0x8000000a)
		c->x86_capability[CPUID_8000_000A_EDX] = cpuid_edx(0x8000000a);

	init_scattered_cpuid_features(c);
	init_speculation_control(c);

	
	apply_forced_caps(c);
}

void get_cpu_address_sizes(struct cpuinfo_x86 *c)
{
	u32 eax, ebx, ecx, edx;

	if (c->extended_cpuid_level >= 0x80000008) {
		cpuid(0x80000008, &eax, &ebx, &ecx, &edx);

		c->x86_virt_bits = (eax >> 8) & 0xff;
		c->x86_phys_bits = eax & 0xff;
	}

	else if (cpu_has(c, X86_FEATURE_PAE) || cpu_has(c, X86_FEATURE_PSE36))
		c->x86_phys_bits = 36;

	c->x86_cache_bits = c->x86_phys_bits;
}

static void identify_cpu_without_cpuid(struct cpuinfo_x86 *c)
{

	int i;

	
	if (flag_is_changeable_p(X86_EFLAGS_AC))
		c->x86 = 4;
	else c->x86 = 3;

	for (i = 0; i < X86_VENDOR_NUM; i++)
		if (cpu_devs[i] && cpu_devs[i]->c_identify) {
			c->x86_vendor_id[0] = 0;
			cpu_devs[i]->c_identify(c);
			if (c->x86_vendor_id[0]) {
				get_cpu_vendor(c);
				break;
			}
		}

}
















static const __initconst struct x86_cpu_id cpu_vuln_whitelist[] = {
	VULNWL(ANY,	4, X86_MODEL_ANY,	NO_SPECULATION), VULNWL(CENTAUR,	5, X86_MODEL_ANY,	NO_SPECULATION), VULNWL(INTEL,	5, X86_MODEL_ANY,	NO_SPECULATION), VULNWL(NSC,	5, X86_MODEL_ANY,	NO_SPECULATION),   VULNWL_INTEL(ATOM_SALTWELL,		NO_SPECULATION), VULNWL_INTEL(ATOM_SALTWELL_TABLET,	NO_SPECULATION), VULNWL_INTEL(ATOM_SALTWELL_MID,		NO_SPECULATION), VULNWL_INTEL(ATOM_BONNELL,		NO_SPECULATION), VULNWL_INTEL(ATOM_BONNELL_MID,		NO_SPECULATION),  VULNWL_INTEL(ATOM_SILVERMONT,		NO_SSB | NO_L1TF | MSBDS_ONLY), VULNWL_INTEL(ATOM_SILVERMONT_X,		NO_SSB | NO_L1TF | MSBDS_ONLY), VULNWL_INTEL(ATOM_SILVERMONT_MID,	NO_SSB | NO_L1TF | MSBDS_ONLY), VULNWL_INTEL(ATOM_AIRMONT,		NO_SSB | NO_L1TF | MSBDS_ONLY), VULNWL_INTEL(XEON_PHI_KNL,		NO_SSB | NO_L1TF | MSBDS_ONLY), VULNWL_INTEL(XEON_PHI_KNM,		NO_SSB | NO_L1TF | MSBDS_ONLY),  VULNWL_INTEL(CORE_YONAH,		NO_SSB),  VULNWL_INTEL(ATOM_AIRMONT_MID,		NO_L1TF | MSBDS_ONLY),  VULNWL_INTEL(ATOM_GOLDMONT,		NO_MDS | NO_L1TF), VULNWL_INTEL(ATOM_GOLDMONT_X,		NO_MDS | NO_L1TF), VULNWL_INTEL(ATOM_GOLDMONT_PLUS,	NO_MDS | NO_L1TF),   VULNWL_AMD(0x0f,	NO_MELTDOWN | NO_SSB | NO_L1TF | NO_MDS), VULNWL_AMD(0x10,	NO_MELTDOWN | NO_SSB | NO_L1TF | NO_MDS), VULNWL_AMD(0x11,	NO_MELTDOWN | NO_SSB | NO_L1TF | NO_MDS), VULNWL_AMD(0x12,	NO_MELTDOWN | NO_SSB | NO_L1TF | NO_MDS),   VULNWL_AMD(X86_FAMILY_ANY,	NO_MELTDOWN | NO_L1TF | NO_MDS), VULNWL_HYGON(X86_FAMILY_ANY,	NO_MELTDOWN | NO_L1TF | NO_MDS), {}



































};

static bool __init cpu_matches(unsigned long which)
{
	const struct x86_cpu_id *m = x86_match_cpu(cpu_vuln_whitelist);

	return m && !!(m->driver_data & which);
}

static void __init cpu_set_bug_bits(struct cpuinfo_x86 *c)
{
	u64 ia32_cap = 0;

	if (cpu_matches(NO_SPECULATION))
		return;

	setup_force_cpu_bug(X86_BUG_SPECTRE_V1);
	setup_force_cpu_bug(X86_BUG_SPECTRE_V2);

	if (cpu_has(c, X86_FEATURE_ARCH_CAPABILITIES))
		rdmsrl(MSR_IA32_ARCH_CAPABILITIES, ia32_cap);

	if (!cpu_matches(NO_SSB) && !(ia32_cap & ARCH_CAP_SSB_NO) && !cpu_has(c, X86_FEATURE_AMD_SSB_NO))
		setup_force_cpu_bug(X86_BUG_SPEC_STORE_BYPASS);

	if (ia32_cap & ARCH_CAP_IBRS_ALL)
		setup_force_cpu_cap(X86_FEATURE_IBRS_ENHANCED);

	if (!cpu_matches(NO_MDS) && !(ia32_cap & ARCH_CAP_MDS_NO)) {
		setup_force_cpu_bug(X86_BUG_MDS);
		if (cpu_matches(MSBDS_ONLY))
			setup_force_cpu_bug(X86_BUG_MSBDS_ONLY);
	}

	if (cpu_matches(NO_MELTDOWN))
		return;

	
	if (ia32_cap & ARCH_CAP_RDCL_NO)
		return;

	setup_force_cpu_bug(X86_BUG_CPU_MELTDOWN);

	if (cpu_matches(NO_L1TF))
		return;

	setup_force_cpu_bug(X86_BUG_L1TF);
}


static void detect_nopl(void)
{

	setup_clear_cpu_cap(X86_FEATURE_NOPL);

	setup_force_cpu_cap(X86_FEATURE_NOPL);

}


static void __init early_identify_cpu(struct cpuinfo_x86 *c)
{

	c->x86_clflush_size = 64;
	c->x86_phys_bits = 36;
	c->x86_virt_bits = 48;

	c->x86_clflush_size = 32;
	c->x86_phys_bits = 32;
	c->x86_virt_bits = 32;

	c->x86_cache_alignment = c->x86_clflush_size;

	memset(&c->x86_capability, 0, sizeof(c->x86_capability));
	c->extended_cpuid_level = 0;

	if (!have_cpuid_p())
		identify_cpu_without_cpuid(c);

	
	if (have_cpuid_p()) {
		cpu_detect(c);
		get_cpu_vendor(c);
		get_cpu_cap(c);
		get_cpu_address_sizes(c);
		setup_force_cpu_cap(X86_FEATURE_CPUID);

		if (this_cpu->c_early_init)
			this_cpu->c_early_init(c);

		c->cpu_index = 0;
		filter_cpuid_features(c, false);

		if (this_cpu->c_bsp_init)
			this_cpu->c_bsp_init(c);
	} else {
		setup_clear_cpu_cap(X86_FEATURE_CPUID);
	}

	setup_force_cpu_cap(X86_FEATURE_ALWAYS);

	cpu_set_bug_bits(c);

	fpu__init_system(c);


	
	setup_clear_cpu_cap(X86_FEATURE_PCID);


	
	if (!pgtable_l5_enabled())
		setup_clear_cpu_cap(X86_FEATURE_LA57);

	detect_nopl();
}

void __init early_cpu_init(void)
{
	const struct cpu_dev *const *cdev;
	int count = 0;


	pr_info("KERNEL supported cpus:\n");


	for (cdev = __x86_cpu_dev_start; cdev < __x86_cpu_dev_end; cdev++) {
		const struct cpu_dev *cpudev = *cdev;

		if (count >= X86_VENDOR_NUM)
			break;
		cpu_devs[count] = cpudev;
		count++;


		{
			unsigned int j;

			for (j = 0; j < 2; j++) {
				if (!cpudev->c_ident[j])
					continue;
				pr_info("  %s %s\n", cpudev->c_vendor, cpudev->c_ident[j]);
			}
		}

	}
	early_identify_cpu(&boot_cpu_data);
}

static void detect_null_seg_behavior(struct cpuinfo_x86 *c)
{

	

	unsigned long old_base, tmp;
	rdmsrl(MSR_FS_BASE, old_base);
	wrmsrl(MSR_FS_BASE, 1);
	loadsegment(fs, 0);
	rdmsrl(MSR_FS_BASE, tmp);
	if (tmp != 0)
		set_cpu_bug(c, X86_BUG_NULL_SEG);
	wrmsrl(MSR_FS_BASE, old_base);

}

static void generic_identify(struct cpuinfo_x86 *c)
{
	c->extended_cpuid_level = 0;

	if (!have_cpuid_p())
		identify_cpu_without_cpuid(c);

	
	if (!have_cpuid_p())
		return;

	cpu_detect(c);

	get_cpu_vendor(c);

	get_cpu_cap(c);

	get_cpu_address_sizes(c);

	if (c->cpuid_level >= 0x00000001) {
		c->initial_apicid = (cpuid_ebx(1) >> 24) & 0xFF;


		c->apicid = apic->phys_pkg_id(c->initial_apicid, 0);

		c->apicid = c->initial_apicid;


		c->phys_proc_id = c->initial_apicid;
	}

	get_model_name(c); 

	detect_null_seg_behavior(c);

	


	do {
		extern void native_iret(void);
		if (pv_ops.cpu.iret == native_iret)
			set_cpu_bug(c, X86_BUG_ESPFIX);
	} while (0);

	set_cpu_bug(c, X86_BUG_ESPFIX);


}

static void x86_init_cache_qos(struct cpuinfo_x86 *c)
{
	
	if (c != &boot_cpu_data) {
		boot_cpu_data.x86_cache_max_rmid = min(boot_cpu_data.x86_cache_max_rmid, c->x86_cache_max_rmid);

	}
}


static void validate_apic_and_package_id(struct cpuinfo_x86 *c)
{

	unsigned int apicid, cpu = smp_processor_id();

	apicid = apic->cpu_present_to_apicid(cpu);

	if (apicid != c->apicid) {
		pr_err(FW_BUG "CPU%u: APIC id mismatch. Firmware: %x APIC: %x\n", cpu, apicid, c->initial_apicid);
	}
	BUG_ON(topology_update_package_map(c->phys_proc_id, cpu));

	c->logical_proc_id = 0;

}


static void identify_cpu(struct cpuinfo_x86 *c)
{
	int i;

	c->loops_per_jiffy = loops_per_jiffy;
	c->x86_cache_size = 0;
	c->x86_vendor = X86_VENDOR_UNKNOWN;
	c->x86_model = c->x86_stepping = 0;	
	c->x86_vendor_id[0] = '\0'; 
	c->x86_model_id[0] = '\0';  
	c->x86_max_cores = 1;
	c->x86_coreid_bits = 0;
	c->cu_id = 0xff;

	c->x86_clflush_size = 64;
	c->x86_phys_bits = 36;
	c->x86_virt_bits = 48;

	c->cpuid_level = -1;	
	c->x86_clflush_size = 32;
	c->x86_phys_bits = 32;
	c->x86_virt_bits = 32;

	c->x86_cache_alignment = c->x86_clflush_size;
	memset(&c->x86_capability, 0, sizeof(c->x86_capability));

	generic_identify(c);

	if (this_cpu->c_identify)
		this_cpu->c_identify(c);

	
	apply_forced_caps(c);


	c->apicid = apic->phys_pkg_id(c->initial_apicid, 0);


	
	if (this_cpu->c_init)
		this_cpu->c_init(c);

	
	squash_the_stupid_serial_number(c);

	
	setup_smep(c);
	setup_smap(c);
	setup_umip(c);

	

	
	filter_cpuid_features(c, true);

	
	if (!c->x86_model_id[0]) {
		const char *p;
		p = table_lookup_model(c);
		if (p)
			strcpy(c->x86_model_id, p);
		else  sprintf(c->x86_model_id, "%02x/%02x", c->x86, c->x86_model);


	}


	detect_ht(c);


	x86_init_rdrand(c);
	x86_init_cache_qos(c);
	setup_pku(c);

	
	apply_forced_caps(c);

	
	if (c != &boot_cpu_data) {
		
		for (i = 0; i < NCAPINTS; i++)
			boot_cpu_data.x86_capability[i] &= c->x86_capability[i];

		
		for (i = NCAPINTS; i < NCAPINTS + NBUGINTS; i++)
			c->x86_capability[i] |= boot_cpu_data.x86_capability[i];
	}

	
	mcheck_cpu_init(c);

	select_idle_routine(c);


	numa_add_cpu(smp_processor_id());

}



void enable_sep_cpu(void)
{
	struct tss_struct *tss;
	int cpu;

	if (!boot_cpu_has(X86_FEATURE_SEP))
		return;

	cpu = get_cpu();
	tss = &per_cpu(cpu_tss_rw, cpu);

	

	tss->x86_tss.ss1 = __KERNEL_CS;
	wrmsr(MSR_IA32_SYSENTER_CS, tss->x86_tss.ss1, 0);
	wrmsr(MSR_IA32_SYSENTER_ESP, (unsigned long)(cpu_entry_stack(cpu) + 1), 0);
	wrmsr(MSR_IA32_SYSENTER_EIP, (unsigned long)entry_SYSENTER_32, 0);

	put_cpu();
}


void __init identify_boot_cpu(void)
{
	identify_cpu(&boot_cpu_data);

	sysenter_setup();
	enable_sep_cpu();

	cpu_detect_tlb(&boot_cpu_data);
}

void identify_secondary_cpu(struct cpuinfo_x86 *c)
{
	BUG_ON(c == &boot_cpu_data);
	identify_cpu(c);

	enable_sep_cpu();

	mtrr_ap_init();
	validate_apic_and_package_id(c);
	x86_spec_ctrl_setup_ap();
}

static __init int setup_noclflush(char *arg)
{
	setup_clear_cpu_cap(X86_FEATURE_CLFLUSH);
	setup_clear_cpu_cap(X86_FEATURE_CLFLUSHOPT);
	return 1;
}
__setup("noclflush", setup_noclflush);

void print_cpu_info(struct cpuinfo_x86 *c)
{
	const char *vendor = NULL;

	if (c->x86_vendor < X86_VENDOR_NUM) {
		vendor = this_cpu->c_vendor;
	} else {
		if (c->cpuid_level >= 0)
			vendor = c->x86_vendor_id;
	}

	if (vendor && !strstr(c->x86_model_id, vendor))
		pr_cont("%s ", vendor);

	if (c->x86_model_id[0])
		pr_cont("%s", c->x86_model_id);
	else pr_cont("%d86", c->x86);

	pr_cont(" (family: 0x%x, model: 0x%x", c->x86, c->x86_model);

	if (c->x86_stepping || c->cpuid_level >= 0)
		pr_cont(", stepping: 0x%x)\n", c->x86_stepping);
	else pr_cont(")\n");
}


static __init int setup_clearcpuid(char *arg)
{
	return 1;
}
__setup("clearcpuid=", setup_clearcpuid);


DEFINE_PER_CPU_FIRST(struct fixed_percpu_data, fixed_percpu_data) __aligned(PAGE_SIZE) __visible;
EXPORT_PER_CPU_SYMBOL_GPL(fixed_percpu_data);


DEFINE_PER_CPU(struct task_struct *, current_task) ____cacheline_aligned = &init_task;
EXPORT_PER_CPU_SYMBOL(current_task);

DEFINE_PER_CPU(struct irq_stack *, hardirq_stack_ptr);
DEFINE_PER_CPU(unsigned int, irq_count) __visible = -1;

DEFINE_PER_CPU(int, __preempt_count) = INIT_PREEMPT_COUNT;
EXPORT_PER_CPU_SYMBOL(__preempt_count);


void syscall_init(void)
{
	wrmsr(MSR_STAR, 0, (__USER32_CS << 16) | __KERNEL_CS);
	wrmsrl(MSR_LSTAR, (unsigned long)entry_SYSCALL_64);


	wrmsrl(MSR_CSTAR, (unsigned long)entry_SYSCALL_compat);
	
	wrmsrl_safe(MSR_IA32_SYSENTER_CS, (u64)__KERNEL_CS);
	wrmsrl_safe(MSR_IA32_SYSENTER_ESP, (unsigned long)(cpu_entry_stack(smp_processor_id()) + 1));
	wrmsrl_safe(MSR_IA32_SYSENTER_EIP, (u64)entry_SYSENTER_compat);

	wrmsrl(MSR_CSTAR, (unsigned long)ignore_sysret);
	wrmsrl_safe(MSR_IA32_SYSENTER_CS, (u64)GDT_ENTRY_INVALID_SEG);
	wrmsrl_safe(MSR_IA32_SYSENTER_ESP, 0ULL);
	wrmsrl_safe(MSR_IA32_SYSENTER_EIP, 0ULL);


	
	wrmsrl(MSR_SYSCALL_MASK, X86_EFLAGS_TF|X86_EFLAGS_DF|X86_EFLAGS_IF| X86_EFLAGS_IOPL|X86_EFLAGS_AC|X86_EFLAGS_NT);

}

DEFINE_PER_CPU(int, debug_stack_usage);
DEFINE_PER_CPU(u32, debug_idt_ctr);

void debug_stack_set_zero(void)
{
	this_cpu_inc(debug_idt_ctr);
	load_current_idt();
}
NOKPROBE_SYMBOL(debug_stack_set_zero);

void debug_stack_reset(void)
{
	if (WARN_ON(!this_cpu_read(debug_idt_ctr)))
		return;
	if (this_cpu_dec_return(debug_idt_ctr) == 0)
		load_current_idt();
}
NOKPROBE_SYMBOL(debug_stack_reset);



DEFINE_PER_CPU(struct task_struct *, current_task) = &init_task;
EXPORT_PER_CPU_SYMBOL(current_task);
DEFINE_PER_CPU(int, __preempt_count) = INIT_PREEMPT_COUNT;
EXPORT_PER_CPU_SYMBOL(__preempt_count);


DEFINE_PER_CPU(unsigned long, cpu_current_top_of_stack) = (unsigned long)&init_thread_union + THREAD_SIZE;
EXPORT_PER_CPU_SYMBOL(cpu_current_top_of_stack);


DEFINE_PER_CPU_ALIGNED(struct stack_canary, stack_canary);





static void clear_all_debug_regs(void)
{
	int i;

	for (i = 0; i < 8; i++) {
		
		if ((i == 4) || (i == 5))
			continue;

		set_debugreg(0, i);
	}
}



static void dbg_restore_debug_regs(void)
{
	if (unlikely(kgdb_connected && arch_kgdb_ops.correct_hw_break))
		arch_kgdb_ops.correct_hw_break();
}




static void wait_for_master_cpu(int cpu)
{

	
	WARN_ON(cpumask_test_and_set_cpu(cpu, cpu_initialized_mask));
	while (!cpumask_test_cpu(cpu, cpu_callout_mask))
		cpu_relax();

}


static void setup_getcpu(int cpu)
{
	unsigned long cpudata = vdso_encode_cpunode(cpu, early_cpu_to_node(cpu));
	struct desc_struct d = { };

	if (boot_cpu_has(X86_FEATURE_RDTSCP))
		write_rdtscp_aux(cpudata);

	
	d.limit0 = cpudata;
	d.limit1 = cpudata >> 16;

	d.type = 5;		
	d.dpl = 3;		
	d.s = 1;		
	d.p = 1;		
	d.d = 1;		

	write_gdt_entry(get_cpu_gdt_rw(cpu), GDT_ENTRY_CPUNODE, &d, DESCTYPE_S);
}





void cpu_init(void)
{
	int cpu = raw_smp_processor_id();
	struct task_struct *me;
	struct tss_struct *t;
	int i;

	wait_for_master_cpu(cpu);

	
	cr4_init_shadow();

	if (cpu)
		load_ucode_ap();

	t = &per_cpu(cpu_tss_rw, cpu);


	if (this_cpu_read(numa_node) == 0 && early_cpu_to_node(cpu) != NUMA_NO_NODE)
		set_numa_node(early_cpu_to_node(cpu));

	setup_getcpu(cpu);

	me = current;

	pr_debug("Initializing CPU#%d\n", cpu);

	cr4_clear_bits(X86_CR4_VME|X86_CR4_PVI|X86_CR4_TSD|X86_CR4_DE);

	

	switch_to_new_gdt(cpu);
	loadsegment(fs, 0);

	load_current_idt();

	memset(me->thread.tls_array, 0, GDT_ENTRY_TLS_ENTRIES * 8);
	syscall_init();

	wrmsrl(MSR_FS_BASE, 0);
	wrmsrl(MSR_KERNEL_GS_BASE, 0);
	barrier();

	x86_configure_nx();
	x2apic_setup();

	
	if (!t->x86_tss.ist[0]) {
		t->x86_tss.ist[IST_INDEX_DF] = __this_cpu_ist_top_va(DF);
		t->x86_tss.ist[IST_INDEX_NMI] = __this_cpu_ist_top_va(NMI);
		t->x86_tss.ist[IST_INDEX_DB] = __this_cpu_ist_top_va(DB);
		t->x86_tss.ist[IST_INDEX_MCE] = __this_cpu_ist_top_va(MCE);
	}

	t->x86_tss.io_bitmap_base = IO_BITMAP_OFFSET;

	
	for (i = 0; i <= IO_BITMAP_LONGS; i++)
		t->io_bitmap[i] = ~0UL;

	mmgrab(&init_mm);
	me->active_mm = &init_mm;
	BUG_ON(me->mm);
	initialize_tlbstate_and_flush();
	enter_lazy_tlb(&init_mm, me);

	
	set_tss_desc(cpu, &get_cpu_entry_area(cpu)->tss.x86_tss);
	load_TR_desc();
	load_sp0((unsigned long)(cpu_entry_stack(cpu) + 1));

	load_mm_ldt(&init_mm);

	clear_all_debug_regs();
	dbg_restore_debug_regs();

	fpu__init_cpu();

	if (is_uv_system())
		uv_cpu_init();

	load_fixmap_gdt(cpu);
}



void cpu_init(void)
{
	int cpu = smp_processor_id();
	struct task_struct *curr = current;
	struct tss_struct *t = &per_cpu(cpu_tss_rw, cpu);

	wait_for_master_cpu(cpu);

	
	cr4_init_shadow();

	show_ucode_info_early();

	pr_info("Initializing CPU#%d\n", cpu);

	if (cpu_feature_enabled(X86_FEATURE_VME) || boot_cpu_has(X86_FEATURE_TSC) || boot_cpu_has(X86_FEATURE_DE))

		cr4_clear_bits(X86_CR4_VME|X86_CR4_PVI|X86_CR4_TSD|X86_CR4_DE);

	load_current_idt();
	switch_to_new_gdt(cpu);

	
	mmgrab(&init_mm);
	curr->active_mm = &init_mm;
	BUG_ON(curr->mm);
	initialize_tlbstate_and_flush();
	enter_lazy_tlb(&init_mm, curr);

	
	set_tss_desc(cpu, &get_cpu_entry_area(cpu)->tss.x86_tss);
	load_TR_desc();
	load_sp0((unsigned long)(cpu_entry_stack(cpu) + 1));

	load_mm_ldt(&init_mm);

	t->x86_tss.io_bitmap_base = IO_BITMAP_OFFSET;


	
	__set_tss_desc(cpu, GDT_ENTRY_DOUBLEFAULT_TSS, &doublefault_tss);


	clear_all_debug_regs();
	dbg_restore_debug_regs();

	fpu__init_cpu();

	load_fixmap_gdt(cpu);
}



void microcode_check(void)
{
	struct cpuinfo_x86 info;

	perf_check_microcode();

	
	info.cpuid_level = cpuid_eax(0);

	
	memcpy(&info.x86_capability, &boot_cpu_data.x86_capability, sizeof(info.x86_capability));

	get_cpu_cap(&info);

	if (!memcmp(&info.x86_capability, &boot_cpu_data.x86_capability, sizeof(info.x86_capability)))
		return;

	pr_warn("x86/CPU: CPU features have changed after loading microcode, but might not take effect.\n");
	pr_warn("x86/CPU: Please consider either early loading through initrd/built-in or a potential BIOS update.\n");
}
