



















































cpumask_var_t cpu_initialized_mask;
cpumask_var_t cpu_callout_mask;
cpumask_var_t cpu_callin_mask;


cpumask_var_t cpu_sibling_setup_mask;


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

	printk(KERN_NOTICE "CPU serial number disabled.\n");
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
	unsigned long eflags;

	
	raw_local_save_flags(eflags);
	BUG_ON(eflags & X86_EFLAGS_AC);

	if (cpu_has(c, X86_FEATURE_SMAP)) {

		cr4_set_bits(X86_CR4_SMAP);

		cr4_clear_bits(X86_CR4_SMAP);

	}
}


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

		printk(KERN_WARNING "CPU: CPU feature " X86_CAP_FMT " disabled, no CPUID level 0x%x\n", x86_cap_flag(df->feature), df->level);

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

__u32 cpu_caps_cleared[NCAPINTS];
__u32 cpu_caps_set[NCAPINTS];

void load_percpu_segment(int cpu)
{

	loadsegment(fs, __KERNEL_PERCPU);

	loadsegment(gs, 0);
	wrmsrl(MSR_GS_BASE, (unsigned long)per_cpu(irq_stack_union.gs_base, cpu));

	load_stack_canary_segment();
}


void switch_to_new_gdt(int cpu)
{
	struct desc_ptr gdt_descr;

	gdt_descr.address = (long)get_cpu_gdt_table(cpu);
	gdt_descr.size = GDT_SIZE - 1;
	load_gdt(&gdt_descr);
	

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

void detect_ht(struct cpuinfo_x86 *c)
{

	u32 eax, ebx, ecx, edx;
	int index_msb, core_bits;
	static bool printed;

	if (!cpu_has(c, X86_FEATURE_HT))
		return;

	if (cpu_has(c, X86_FEATURE_CMP_LEGACY))
		goto out;

	if (cpu_has(c, X86_FEATURE_XTOPOLOGY))
		return;

	cpuid(1, &eax, &ebx, &ecx, &edx);

	smp_num_siblings = (ebx & 0xff0000) >> 16;

	if (smp_num_siblings == 1) {
		printk_once(KERN_INFO "CPU0: Hyper-Threading is disabled\n");
		goto out;
	}

	if (smp_num_siblings <= 1)
		goto out;

	index_msb = get_count_order(smp_num_siblings);
	c->phys_proc_id = apic->phys_pkg_id(c->initial_apicid, index_msb);

	smp_num_siblings = smp_num_siblings / c->x86_max_cores;

	index_msb = get_count_order(smp_num_siblings);

	core_bits = get_count_order(c->x86_max_cores);

	c->cpu_core_id = apic->phys_pkg_id(c->initial_apicid, index_msb) & ((1 << core_bits) - 1);

out:
	if (!printed && (c->x86_max_cores * smp_num_siblings) > 1) {
		printk(KERN_INFO  "CPU: Physical Processor ID: %d\n", c->phys_proc_id);
		printk(KERN_INFO  "CPU: Processor Core ID: %d\n", c->cpu_core_id);
		printed = 1;
	}

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

	printk_once(KERN_ERR "CPU: vendor_id '%s' unknown, using generic init.\n"  "CPU: Your system may be unstable.\n", v)

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
		c->x86 = (tfms >> 8) & 0xf;
		c->x86_model = (tfms >> 4) & 0xf;
		c->x86_mask = tfms & 0xf;

		if (c->x86 == 0xf)
			c->x86 += (tfms >> 20) & 0xff;
		if (c->x86 >= 0x6)
			c->x86_model += ((tfms >> 16) & 0xf) << 4;

		if (cap0 & (1<<19)) {
			c->x86_clflush_size = ((misc >> 8) & 0xff) * 8;
			c->x86_cache_alignment = c->x86_clflush_size;
		}
	}
}

void get_cpu_cap(struct cpuinfo_x86 *c)
{
	u32 tfms, xlvl;
	u32 ebx;

	
	if (c->cpuid_level >= 0x00000001) {
		u32 capability, excap;

		cpuid(0x00000001, &tfms, &ebx, &excap, &capability);
		c->x86_capability[0] = capability;
		c->x86_capability[4] = excap;
	}

	
	if (c->cpuid_level >= 0x00000007) {
		u32 eax, ebx, ecx, edx;

		cpuid_count(0x00000007, 0, &eax, &ebx, &ecx, &edx);

		c->x86_capability[9] = ebx;
	}

	
	if (c->cpuid_level >= 0x0000000d) {
		u32 eax, ebx, ecx, edx;

		cpuid_count(0x0000000d, 1, &eax, &ebx, &ecx, &edx);

		c->x86_capability[10] = eax;
	}

	
	if (c->cpuid_level >= 0x0000000F) {
		u32 eax, ebx, ecx, edx;

		
		cpuid_count(0x0000000F, 0, &eax, &ebx, &ecx, &edx);
		c->x86_capability[11] = edx;
		if (cpu_has(c, X86_FEATURE_CQM_LLC)) {
			
			c->x86_cache_max_rmid = ebx;

			
			cpuid_count(0x0000000F, 1, &eax, &ebx, &ecx, &edx);
			c->x86_capability[12] = edx;
			if (cpu_has(c, X86_FEATURE_CQM_OCCUP_LLC)) {
				c->x86_cache_max_rmid = ecx;
				c->x86_cache_occ_scale = ebx;
			}
		} else {
			c->x86_cache_max_rmid = -1;
			c->x86_cache_occ_scale = -1;
		}
	}

	
	xlvl = cpuid_eax(0x80000000);
	c->extended_cpuid_level = xlvl;

	if ((xlvl & 0xffff0000) == 0x80000000) {
		if (xlvl >= 0x80000001) {
			c->x86_capability[1] = cpuid_edx(0x80000001);
			c->x86_capability[6] = cpuid_ecx(0x80000001);
		}
	}

	if (c->extended_cpuid_level >= 0x80000008) {
		u32 eax = cpuid_eax(0x80000008);

		c->x86_virt_bits = (eax >> 8) & 0xff;
		c->x86_phys_bits = eax & 0xff;
	}

	else if (cpu_has(c, X86_FEATURE_PAE) || cpu_has(c, X86_FEATURE_PSE36))
		c->x86_phys_bits = 36;


	if (c->extended_cpuid_level >= 0x80000007)
		c->x86_power = cpuid_edx(0x80000007);

	init_scattered_cpuid_features(c);
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


static void __init early_identify_cpu(struct cpuinfo_x86 *c)
{

	c->x86_clflush_size = 64;
	c->x86_phys_bits = 36;
	c->x86_virt_bits = 48;

	c->x86_clflush_size = 32;
	c->x86_phys_bits = 32;
	c->x86_virt_bits = 32;

	c->x86_cache_alignment = c->x86_clflush_size;

	memset(&c->x86_capability, 0, sizeof c->x86_capability);
	c->extended_cpuid_level = 0;

	if (!have_cpuid_p())
		identify_cpu_without_cpuid(c);

	
	if (!have_cpuid_p())
		return;

	cpu_detect(c);
	get_cpu_vendor(c);
	get_cpu_cap(c);

	if (this_cpu->c_early_init)
		this_cpu->c_early_init(c);

	c->cpu_index = 0;
	filter_cpuid_features(c, false);

	if (this_cpu->c_bsp_init)
		this_cpu->c_bsp_init(c);

	setup_force_cpu_cap(X86_FEATURE_ALWAYS);
	fpu__init_system(c);
}

void __init early_cpu_init(void)
{
	const struct cpu_dev *const *cdev;
	int count = 0;


	printk(KERN_INFO "KERNEL supported cpus:\n");


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
				printk(KERN_INFO "  %s %s\n", cpudev->c_vendor, cpudev->c_ident[j]);
			}
		}

	}
	early_identify_cpu(&boot_cpu_data);
}


static void detect_nopl(struct cpuinfo_x86 *c)
{

	clear_cpu_cap(c, X86_FEATURE_NOPL);

	set_cpu_cap(c, X86_FEATURE_NOPL);

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

	if (c->cpuid_level >= 0x00000001) {
		c->initial_apicid = (cpuid_ebx(1) >> 24) & 0xFF;


		c->apicid = apic->phys_pkg_id(c->initial_apicid, 0);

		c->apicid = c->initial_apicid;


		c->phys_proc_id = c->initial_apicid;
	}

	get_model_name(c); 

	detect_nopl(c);
}

static void x86_init_cache_qos(struct cpuinfo_x86 *c)
{
	
	if (c != &boot_cpu_data) {
		boot_cpu_data.x86_cache_max_rmid = min(boot_cpu_data.x86_cache_max_rmid, c->x86_cache_max_rmid);

	}
}


static void identify_cpu(struct cpuinfo_x86 *c)
{
	int i;

	c->loops_per_jiffy = loops_per_jiffy;
	c->x86_cache_size = -1;
	c->x86_vendor = X86_VENDOR_UNKNOWN;
	c->x86_model = c->x86_mask = 0;	
	c->x86_vendor_id[0] = '\0'; 
	c->x86_model_id[0] = '\0';  
	c->x86_max_cores = 1;
	c->x86_coreid_bits = 0;

	c->x86_clflush_size = 64;
	c->x86_phys_bits = 36;
	c->x86_virt_bits = 48;

	c->cpuid_level = -1;	
	c->x86_clflush_size = 32;
	c->x86_phys_bits = 32;
	c->x86_virt_bits = 32;

	c->x86_cache_alignment = c->x86_clflush_size;
	memset(&c->x86_capability, 0, sizeof c->x86_capability);

	generic_identify(c);

	if (this_cpu->c_identify)
		this_cpu->c_identify(c);

	
	for (i = 0; i < NCAPINTS; i++) {
		c->x86_capability[i] &= ~cpu_caps_cleared[i];
		c->x86_capability[i] |= cpu_caps_set[i];
	}


	c->apicid = apic->phys_pkg_id(c->initial_apicid, 0);


	
	if (this_cpu->c_init)
		this_cpu->c_init(c);

	
	squash_the_stupid_serial_number(c);

	
	setup_smep(c);
	setup_smap(c);

	

	
	filter_cpuid_features(c, true);

	
	if (!c->x86_model_id[0]) {
		const char *p;
		p = table_lookup_model(c);
		if (p)
			strcpy(c->x86_model_id, p);
		else  sprintf(c->x86_model_id, "%02x/%02x", c->x86, c->x86_model);


	}


	detect_ht(c);


	init_hypervisor(c);
	x86_init_rdrand(c);
	x86_init_cache_qos(c);

	
	for (i = 0; i < NCAPINTS; i++) {
		c->x86_capability[i] &= ~cpu_caps_cleared[i];
		c->x86_capability[i] |= cpu_caps_set[i];
	}

	
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

	cpu = get_cpu();
	tss = &per_cpu(cpu_tss, cpu);

	if (!boot_cpu_has(X86_FEATURE_SEP))
		goto out;

	

	tss->x86_tss.ss1 = __KERNEL_CS;
	wrmsr(MSR_IA32_SYSENTER_CS, tss->x86_tss.ss1, 0);

	wrmsr(MSR_IA32_SYSENTER_ESP, (unsigned long)tss + offsetofend(struct tss_struct, SYSENTER_stack), 0);


	wrmsr(MSR_IA32_SYSENTER_EIP, (unsigned long)entry_SYSENTER_32, 0);

out:
	put_cpu();
}


void __init identify_boot_cpu(void)
{
	identify_cpu(&boot_cpu_data);
	init_amd_e400_c1e_mask();

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
}

struct msr_range {
	unsigned	min;
	unsigned	max;
};

static const struct msr_range msr_range_array[] = {
	{ 0x00000000, 0x00000418}, { 0xc0000000, 0xc000040b}, { 0xc0010000, 0xc0010142}, { 0xc0011000, 0xc001103b}, };




static void __print_cpu_msr(void)
{
	unsigned index_min, index_max;
	unsigned index;
	u64 val;
	int i;

	for (i = 0; i < ARRAY_SIZE(msr_range_array); i++) {
		index_min = msr_range_array[i].min;
		index_max = msr_range_array[i].max;

		for (index = index_min; index < index_max; index++) {
			if (rdmsrl_safe(index, &val))
				continue;
			printk(KERN_INFO " MSR%08x: %016llx\n", index, val);
		}
	}
}

static int show_msr;

static __init int setup_show_msr(char *arg)
{
	int num;

	get_option(&arg, &num);

	if (num > 0)
		show_msr = num;
	return 1;
}
__setup("show_msr=", setup_show_msr);

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
		printk(KERN_CONT "%s ", vendor);

	if (c->x86_model_id[0])
		printk(KERN_CONT "%s", c->x86_model_id);
	else printk(KERN_CONT "%d86", c->x86);

	printk(KERN_CONT " (fam: %02x, model: %02x", c->x86, c->x86_model);

	if (c->x86_mask || c->cpuid_level >= 0)
		printk(KERN_CONT ", stepping: %02x)\n", c->x86_mask);
	else printk(KERN_CONT ")\n");

	print_cpu_msr(c);
}

void print_cpu_msr(struct cpuinfo_x86 *c)
{
	if (c->cpu_index < show_msr)
		__print_cpu_msr();
}

static __init int setup_disablecpuid(char *arg)
{
	int bit;

	if (get_option(&arg, &bit) && bit < NCAPINTS*32)
		setup_clear_cpu_cap(bit);
	else return 0;

	return 1;
}
__setup("clearcpuid=", setup_disablecpuid);


struct desc_ptr idt_descr = { NR_VECTORS * 16 - 1, (unsigned long) idt_table };
struct desc_ptr debug_idt_descr = { NR_VECTORS * 16 - 1, (unsigned long) debug_idt_table };

DEFINE_PER_CPU_FIRST(union irq_stack_union, irq_stack_union) __aligned(PAGE_SIZE) __visible;


DEFINE_PER_CPU(struct task_struct *, current_task) ____cacheline_aligned = &init_task;
EXPORT_PER_CPU_SYMBOL(current_task);

DEFINE_PER_CPU(char *, irq_stack_ptr) = init_per_cpu_var(irq_stack_union.irq_stack) + IRQ_STACK_SIZE - 64;

DEFINE_PER_CPU(unsigned int, irq_count) __visible = -1;

DEFINE_PER_CPU(int, __preempt_count) = INIT_PREEMPT_COUNT;
EXPORT_PER_CPU_SYMBOL(__preempt_count);


static const unsigned int exception_stack_sizes[N_EXCEPTION_STACKS] = {
	  [0 ... N_EXCEPTION_STACKS - 1]	= EXCEPTION_STKSZ, [DEBUG_STACK - 1]			= DEBUG_STKSZ };


static DEFINE_PER_CPU_PAGE_ALIGNED(char, exception_stacks [(N_EXCEPTION_STACKS - 1) * EXCEPTION_STKSZ + DEBUG_STKSZ]);


void syscall_init(void)
{
	
	wrmsrl(MSR_STAR,  ((u64)__USER32_CS)<<48  | ((u64)__KERNEL_CS)<<32);
	wrmsrl(MSR_LSTAR, entry_SYSCALL_64);


	wrmsrl(MSR_CSTAR, entry_SYSCALL_compat);
	
	wrmsrl_safe(MSR_IA32_SYSENTER_CS, (u64)__KERNEL_CS);
	wrmsrl_safe(MSR_IA32_SYSENTER_ESP, 0ULL);
	wrmsrl_safe(MSR_IA32_SYSENTER_EIP, (u64)entry_SYSENTER_compat);

	wrmsrl(MSR_CSTAR, ignore_sysret);
	wrmsrl_safe(MSR_IA32_SYSENTER_CS, (u64)GDT_ENTRY_INVALID_SEG);
	wrmsrl_safe(MSR_IA32_SYSENTER_ESP, 0ULL);
	wrmsrl_safe(MSR_IA32_SYSENTER_EIP, 0ULL);


	
	wrmsrl(MSR_SYSCALL_MASK, X86_EFLAGS_TF|X86_EFLAGS_DF|X86_EFLAGS_IF| X86_EFLAGS_IOPL|X86_EFLAGS_AC|X86_EFLAGS_NT);

}


DEFINE_PER_CPU(struct orig_ist, orig_ist);

static DEFINE_PER_CPU(unsigned long, debug_stack_addr);
DEFINE_PER_CPU(int, debug_stack_usage);

int is_debug_stack(unsigned long addr)
{
	return __this_cpu_read(debug_stack_usage) || (addr <= __this_cpu_read(debug_stack_addr) && addr > (__this_cpu_read(debug_stack_addr) - DEBUG_STKSZ));

}
NOKPROBE_SYMBOL(is_debug_stack);

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




void cpu_init(void)
{
	struct orig_ist *oist;
	struct task_struct *me;
	struct tss_struct *t;
	unsigned long v;
	int cpu = stack_smp_processor_id();
	int i;

	wait_for_master_cpu(cpu);

	
	cr4_init_shadow();

	
	load_ucode_ap();

	t = &per_cpu(cpu_tss, cpu);
	oist = &per_cpu(orig_ist, cpu);


	if (this_cpu_read(numa_node) == 0 && early_cpu_to_node(cpu) != NUMA_NO_NODE)
		set_numa_node(early_cpu_to_node(cpu));


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

	
	if (!oist->ist[0]) {
		char *estacks = per_cpu(exception_stacks, cpu);

		for (v = 0; v < N_EXCEPTION_STACKS; v++) {
			estacks += exception_stack_sizes[v];
			oist->ist[v] = t->x86_tss.ist[v] = (unsigned long)estacks;
			if (v == DEBUG_STACK-1)
				per_cpu(debug_stack_addr, cpu) = (unsigned long)estacks;
		}
	}

	t->x86_tss.io_bitmap_base = offsetof(struct tss_struct, io_bitmap);

	
	for (i = 0; i <= IO_BITMAP_LONGS; i++)
		t->io_bitmap[i] = ~0UL;

	atomic_inc(&init_mm.mm_count);
	me->active_mm = &init_mm;
	BUG_ON(me->mm);
	enter_lazy_tlb(&init_mm, me);

	load_sp0(t, &current->thread);
	set_tss_desc(cpu, t);
	load_TR_desc();
	load_LDT(&init_mm.context);

	clear_all_debug_regs();
	dbg_restore_debug_regs();

	fpu__init_cpu();

	if (is_uv_system())
		uv_cpu_init();
}



void cpu_init(void)
{
	int cpu = smp_processor_id();
	struct task_struct *curr = current;
	struct tss_struct *t = &per_cpu(cpu_tss, cpu);
	struct thread_struct *thread = &curr->thread;

	wait_for_master_cpu(cpu);

	
	cr4_init_shadow();

	show_ucode_info_early();

	printk(KERN_INFO "Initializing CPU#%d\n", cpu);

	if (cpu_feature_enabled(X86_FEATURE_VME) || cpu_has_tsc || cpu_has_de)
		cr4_clear_bits(X86_CR4_VME|X86_CR4_PVI|X86_CR4_TSD|X86_CR4_DE);

	load_current_idt();
	switch_to_new_gdt(cpu);

	
	atomic_inc(&init_mm.mm_count);
	curr->active_mm = &init_mm;
	BUG_ON(curr->mm);
	enter_lazy_tlb(&init_mm, curr);

	load_sp0(t, thread);
	set_tss_desc(cpu, t);
	load_TR_desc();
	load_LDT(&init_mm.context);

	t->x86_tss.io_bitmap_base = offsetof(struct tss_struct, io_bitmap);


	
	__set_tss_desc(cpu, GDT_ENTRY_DOUBLEFAULT_TSS, &doublefault_tss);


	clear_all_debug_regs();
	dbg_restore_debug_regs();

	fpu__init_cpu();
}



void warn_pre_alternatives(void)
{
	WARN(1, "You're using static_cpu_has before alternatives have run!\n");
}
EXPORT_SYMBOL_GPL(warn_pre_alternatives);


inline bool __static_cpu_has_safe(u16 bit)
{
	return boot_cpu_has(bit);
}
EXPORT_SYMBOL_GPL(__static_cpu_has_safe);
