






























































struct cpuinfo_x86 boot_cpu_data __read_mostly;

unsigned long mmu_cr4_features;

int acpi_disabled;
EXPORT_SYMBOL(acpi_disabled);

extern int __initdata acpi_ht;
extern acpi_interrupt_flags	acpi_sci_flags;
int __initdata acpi_force = 0;


int acpi_numa __initdata;


int bootloader_type;

unsigned long saved_video_mode;


int dmi_alloc_index;
char dmi_alloc_data[DMI_MAX_DATA];


struct screen_info screen_info;
struct sys_desc_table_struct {
	unsigned short length;
	unsigned char table[0];
};

struct edid_info edid_info;
struct e820map e820;

extern int root_mountflags;

char command_line[COMMAND_LINE_SIZE];

struct resource standard_io_resources[] = {
	{ .name = "dma1", .start = 0x00, .end = 0x1f, .flags = IORESOURCE_BUSY | IORESOURCE_IO }, { .name = "pic1", .start = 0x20, .end = 0x21, .flags = IORESOURCE_BUSY | IORESOURCE_IO }, { .name = "timer0", .start = 0x40, .end = 0x43, .flags = IORESOURCE_BUSY | IORESOURCE_IO }, { .name = "timer1", .start = 0x50, .end = 0x53, .flags = IORESOURCE_BUSY | IORESOURCE_IO }, { .name = "keyboard", .start = 0x60, .end = 0x6f, .flags = IORESOURCE_BUSY | IORESOURCE_IO }, { .name = "dma page reg", .start = 0x80, .end = 0x8f, .flags = IORESOURCE_BUSY | IORESOURCE_IO }, { .name = "pic2", .start = 0xa0, .end = 0xa1, .flags = IORESOURCE_BUSY | IORESOURCE_IO }, { .name = "dma2", .start = 0xc0, .end = 0xdf, .flags = IORESOURCE_BUSY | IORESOURCE_IO }, { .name = "fpu", .start = 0xf0, .end = 0xff, .flags = IORESOURCE_BUSY | IORESOURCE_IO }
















};





struct resource data_resource = {
	.name = "Kernel data", .start = 0, .end = 0, .flags = IORESOURCE_RAM, };



struct resource code_resource = {
	.name = "Kernel code", .start = 0, .end = 0, .flags = IORESOURCE_RAM, };






static struct resource system_rom_resource = {
	.name = "System ROM", .start = 0xf0000, .end = 0xfffff, .flags = IORESOURCE_ROM, };




static struct resource extension_rom_resource = {
	.name = "Extension ROM", .start = 0xe0000, .end = 0xeffff, .flags = IORESOURCE_ROM, };




static struct resource adapter_rom_resources[] = {
	{ .name = "Adapter ROM", .start = 0xc8000, .end = 0, .flags = IORESOURCE_ROM }, { .name = "Adapter ROM", .start = 0, .end = 0, .flags = IORESOURCE_ROM }, { .name = "Adapter ROM", .start = 0, .end = 0, .flags = IORESOURCE_ROM }, { .name = "Adapter ROM", .start = 0, .end = 0, .flags = IORESOURCE_ROM }, { .name = "Adapter ROM", .start = 0, .end = 0, .flags = IORESOURCE_ROM }, { .name = "Adapter ROM", .start = 0, .end = 0, .flags = IORESOURCE_ROM }










};



static struct resource video_rom_resource = {
	.name = "Video ROM", .start = 0xc0000, .end = 0xc7fff, .flags = IORESOURCE_ROM, };




static struct resource video_ram_resource = {
	.name = "Video RAM area", .start = 0xa0000, .end = 0xbffff, .flags = IORESOURCE_RAM, };






static int __init romchecksum(unsigned char *rom, unsigned long length)
{
	unsigned char *p, sum = 0;

	for (p = rom; p < rom + length; p++)
		sum += *p;
	return sum == 0;
}

static void __init probe_roms(void)
{
	unsigned long start, length, upper;
	unsigned char *rom;
	int	      i;

	
	upper = adapter_rom_resources[0].start;
	for (start = video_rom_resource.start; start < upper; start += 2048) {
		rom = isa_bus_to_virt(start);
		if (!romsignature(rom))
			continue;

		video_rom_resource.start = start;

		
		length = rom[2] * 512;

		
		if (length && romchecksum(rom, length))
			video_rom_resource.end = start + length - 1;

		request_resource(&iomem_resource, &video_rom_resource);
		break;
			}

	start = (video_rom_resource.end + 1 + 2047) & ~2047UL;
	if (start < upper)
		start = upper;

	
	request_resource(&iomem_resource, &system_rom_resource);
	upper = system_rom_resource.start;

	
	rom = isa_bus_to_virt(extension_rom_resource.start);
	if (romsignature(rom)) {
		length = extension_rom_resource.end - extension_rom_resource.start + 1;
		if (romchecksum(rom, length)) {
			request_resource(&iomem_resource, &extension_rom_resource);
			upper = extension_rom_resource.start;
		}
	}

	
	for (i = 0; i < ADAPTER_ROM_RESOURCES && start < upper; start += 2048) {
		rom = isa_bus_to_virt(start);
		if (!romsignature(rom))
			continue;

		
		length = rom[2] * 512;

		
		if (!length || start + length > upper || !romchecksum(rom, length))
			continue;

		adapter_rom_resources[i].start = start;
		adapter_rom_resources[i].end = start + length - 1;
		request_resource(&iomem_resource, &adapter_rom_resources[i]);

		start = adapter_rom_resources[i++].end & ~2047UL;
	}
}


static int fullarg(char *p, char *arg)
{
	int l = strlen(arg);
	return !memcmp(p, arg, l) && (p[l] == 0 || isspace(p[l]));
}

static __init void parse_cmdline_early (char ** cmdline_p)
{
	char c = ' ', *to = command_line, *from = COMMAND_LINE;
	int len = 0;
	int userdef = 0;

	for (;;) {
		if (c != ' ') 
			goto next_char; 


		
		else if (!memcmp(from, "maxcpus=", 8)) {
			extern unsigned int maxcpus;

			maxcpus = simple_strtoul(from + 8, NULL, 0);
		}


		
		if (fullarg(from,"acpi=off"))
			disable_acpi();

		if (fullarg(from, "acpi=force")) { 
			
			acpi_force = 1;
			acpi_disabled = 0;
		}

		
		if (fullarg(from, "acpi=ht")) { 
			if (!acpi_force)
				disable_acpi();
			acpi_ht = 1; 
		}
                else if (fullarg(from, "pci=noacpi")) 
			acpi_disable_pci();
		else if (fullarg(from, "acpi=noirq"))
			acpi_noirq_set();

		else if (fullarg(from, "acpi_sci=edge"))
			acpi_sci_flags.trigger =  1;
		else if (fullarg(from, "acpi_sci=level"))
			acpi_sci_flags.trigger = 3;
		else if (fullarg(from, "acpi_sci=high"))
			acpi_sci_flags.polarity = 1;
		else if (fullarg(from, "acpi_sci=low"))
			acpi_sci_flags.polarity = 3;

		
		else if (fullarg(from, "acpi=strict")) {
			acpi_strict = 1;
		}

		else if (fullarg(from, "acpi_skip_timer_override"))
			acpi_skip_timer_override = 1;



		if (fullarg(from, "disable_timer_pin_1"))
			disable_timer_pin_1 = 1;
		if (fullarg(from, "enable_timer_pin_1"))
			disable_timer_pin_1 = -1;

		if (fullarg(from, "nolapic") || fullarg(from, "disableapic")) {
			clear_bit(X86_FEATURE_APIC, boot_cpu_data.x86_capability);
			disable_apic = 1;
		}

		if (fullarg(from, "noapic"))
			skip_ioapic_setup = 1;

		if (fullarg(from,"apic")) {
			skip_ioapic_setup = 0;
			ioapic_force = 1;
		}
			
		if (!memcmp(from, "mem=", 4))
			parse_memopt(from+4, &from); 

		if (!memcmp(from, "memmap=", 7)) {
			
			if (!memcmp(from+7, "exactmap", 8)) {

				
				saved_max_pfn = e820_end_of_ram();

				from += 8+7;
				end_pfn_map = 0;
				e820.nr_map = 0;
				userdef = 1;
			}
			else {
				parse_memmapopt(from+7, &from);
				userdef = 1;
			}
		}


		if (!memcmp(from, "numa=", 5))
			numa_setup(from+5); 


		if (!memcmp(from,"iommu=",6)) { 
			iommu_setup(from+6); 
		}

		if (fullarg(from,"oops=panic"))
			panic_on_oops = 1;

		if (!memcmp(from, "noexec=", 7))
			nonx_setup(from + 7);


		
		else if (!memcmp(from, "crashkernel=", 12)) {
			unsigned long size, base;
			size = memparse(from+12, &from);
			if (*from == '@') {
				base = memparse(from+1, &from);
				
				crashk_res.start = base;
				crashk_res.end   = base + size - 1;
			}
		}



		
		else if(!memcmp(from, "elfcorehdr=", 11))
			elfcorehdr_addr = memparse(from+11, &from);



		else if (!memcmp(from, "additional_cpus=", 16))
			setup_additional_cpus(from+16);


	next_char:
		c = *(from++);
		if (!c)
			break;
		if (COMMAND_LINE_SIZE <= ++len)
			break;
		*(to++) = c;
	}
	if (userdef) {
		printk(KERN_INFO "user-defined physical RAM map:\n");
		e820_print_map("user");
	}
	*to = '\0';
	*cmdline_p = command_line;
}


static void __init contig_initmem_init(unsigned long start_pfn, unsigned long end_pfn)
{
	unsigned long bootmap_size, bootmap;

	bootmap_size = bootmem_bootmap_pages(end_pfn)<<PAGE_SHIFT;
	bootmap = find_e820_area(0, end_pfn<<PAGE_SHIFT, bootmap_size);
	if (bootmap == -1L)
		panic("Cannot find bootmem map of size %ld\n",bootmap_size);
	bootmap_size = init_bootmem(bootmap >> PAGE_SHIFT, end_pfn);
	e820_bootmem_free(NODE_DATA(0), 0, end_pfn << PAGE_SHIFT);
	reserve_bootmem(bootmap, bootmap_size);
} 



asm("\t.data\nk8nops: "  K8_NOP1 K8_NOP2 K8_NOP3 K8_NOP4 K8_NOP5 K8_NOP6 K8_NOP7 K8_NOP8);

    
extern unsigned char k8nops[];
static unsigned char *k8_nops[ASM_NOP_MAX+1] = { 
     NULL, k8nops, k8nops + 1, k8nops + 1 + 2, k8nops + 1 + 2 + 3, k8nops + 1 + 2 + 3 + 4, k8nops + 1 + 2 + 3 + 4 + 5, k8nops + 1 + 2 + 3 + 4 + 5 + 6, k8nops + 1 + 2 + 3 + 4 + 5 + 6 + 7, };









extern char __vsyscall_0;

 
void apply_alternatives(void *start, void *end) 
{ 
	struct alt_instr *a; 
	int diff, i, k;
	for (a = start; (void *)a < end; a++) { 
		u8 *instr;

		if (!boot_cpu_has(a->cpuid))
			continue;

		BUG_ON(a->replacementlen > a->instrlen); 
		instr = a->instr;
		
		if (instr >= (u8 *)VSYSCALL_START && instr < (u8*)VSYSCALL_END)
			instr = __va(instr - (u8*)VSYSCALL_START + (u8*)__pa_symbol(&__vsyscall_0));
		__inline_memcpy(instr, a->replacement, a->replacementlen);
		diff = a->instrlen - a->replacementlen; 

		
		for (i = a->replacementlen; diff > 0; diff -= k, i += k) {
			k = diff;
			if (k > ASM_NOP_MAX)
				k = ASM_NOP_MAX;
			__inline_memcpy(instr + i, k8_nops[k], k);
		} 
	}
} 

static int no_replacement __initdata = 0; 
 
void __init alternative_instructions(void)
{
	extern struct alt_instr __alt_instructions[], __alt_instructions_end[];
	if (no_replacement) 
		return;
	apply_alternatives(__alt_instructions, __alt_instructions_end);
}

static int __init noreplacement_setup(char *s)
{ 
     no_replacement = 1; 
     return 1;
} 

__setup("noreplacement", noreplacement_setup); 


struct edd edd;

EXPORT_SYMBOL(edd);


static inline void copy_edd(void)
{
     memcpy(edd.mbr_signature, EDD_MBR_SIGNATURE, sizeof(edd.mbr_signature));
     memcpy(edd.edd_info, EDD_BUF, sizeof(edd.edd_info));
     edd.mbr_signature_nr = EDD_MBR_SIG_NR;
     edd.edd_info_nr = EDD_NR;
}

static inline void copy_edd(void)
{
}



static void __init reserve_ebda_region(void)
{
	unsigned int addr;
	
	addr = *(unsigned short *)phys_to_virt(EBDA_ADDR_POINTER);
	addr <<= 4;
	if (addr)
		reserve_bootmem_generic(addr, PAGE_SIZE);
}

void __init setup_arch(char **cmdline_p)
{
	unsigned long kernel_end;

 	ROOT_DEV = old_decode_dev(ORIG_ROOT_DEV);
 	screen_info = SCREEN_INFO;
	edid_info = EDID_INFO;
	saved_video_mode = SAVED_VIDEO_MODE;
	bootloader_type = LOADER_TYPE;


	rd_image_start = RAMDISK_FLAGS & RAMDISK_IMAGE_START_MASK;
	rd_prompt = ((RAMDISK_FLAGS & RAMDISK_PROMPT_FLAG) != 0);
	rd_doload = ((RAMDISK_FLAGS & RAMDISK_LOAD_FLAG) != 0);

	setup_memory_region();
	copy_edd();

	if (!MOUNT_ROOT_RDONLY)
		root_mountflags &= ~MS_RDONLY;
	init_mm.start_code = (unsigned long) &_text;
	init_mm.end_code = (unsigned long) &_etext;
	init_mm.end_data = (unsigned long) &_edata;
	init_mm.brk = (unsigned long) &_end;

	code_resource.start = virt_to_phys(&_text);
	code_resource.end = virt_to_phys(&_etext)-1;
	data_resource.start = virt_to_phys(&_etext);
	data_resource.end = virt_to_phys(&_edata)-1;

	parse_cmdline_early(cmdline_p);

	early_identify_cpu(&boot_cpu_data);

	
	end_pfn = e820_end_of_ram();
	num_physpages = end_pfn;		

	check_efer();

	init_memory_mapping(0, (end_pfn_map << PAGE_SHIFT));

	dmi_scan_machine();

	zap_low_mappings(0);


	
	acpi_boot_table_init();



	
	acpi_numa_init();



	numa_initmem_init(0, end_pfn); 

	contig_initmem_init(0, end_pfn);


	
	reserve_bootmem_generic(table_start << PAGE_SHIFT,  (table_end - table_start) << PAGE_SHIFT);

	
	kernel_end = round_up(__pa_symbol(&_end),PAGE_SIZE);
	reserve_bootmem_generic(HIGH_MEMORY, kernel_end - HIGH_MEMORY);

	
	reserve_bootmem_generic(0, PAGE_SIZE);

	
	reserve_ebda_region();


	
	reserve_bootmem_generic(PAGE_SIZE, PAGE_SIZE);

	
	reserve_bootmem_generic(SMP_TRAMPOLINE_BASE, PAGE_SIZE);



       
       acpi_reserve_bootmem();


	
	find_smp_config();


	if (LOADER_TYPE && INITRD_START) {
		if (INITRD_START + INITRD_SIZE <= (end_pfn << PAGE_SHIFT)) {
			reserve_bootmem_generic(INITRD_START, INITRD_SIZE);
			initrd_start = INITRD_START ? INITRD_START + PAGE_OFFSET : 0;
			initrd_end = initrd_start+INITRD_SIZE;
		}
		else {
			printk(KERN_ERR "initrd extends beyond end of memory " "(0x%08lx > 0x%08lx)\ndisabling initrd\n", (unsigned long)(INITRD_START + INITRD_SIZE), (unsigned long)(end_pfn << PAGE_SHIFT));


			initrd_start = 0;
		}
	}


	if (crashk_res.start != crashk_res.end) {
		reserve_bootmem(crashk_res.start, crashk_res.end - crashk_res.start + 1);
	}


	paging_init();

	check_ioapic();

	
	cpu_set(0, cpu_present_map);

	
	acpi_boot_init();


	init_cpu_to_node();


	
	if (smp_found_config)
		get_smp_config();
	init_apic_mappings();


	
	probe_roms();
	e820_reserve_resources(); 

	request_resource(&iomem_resource, &video_ram_resource);

	{
	unsigned i;
	
	for (i = 0; i < STANDARD_IO_RESOURCES; i++)
		request_resource(&ioport_resource, &standard_io_resources[i]);
	}

	e820_setup_gap();


	iommu_hole_init();




	conswitchp = &vga_con;

	conswitchp = &dummy_con;


}

static int __cpuinit get_model_name(struct cpuinfo_x86 *c)
{
	unsigned int *v;

	if (c->extended_cpuid_level < 0x80000004)
		return 0;

	v = (unsigned int *) c->x86_model_id;
	cpuid(0x80000002, &v[0], &v[1], &v[2], &v[3]);
	cpuid(0x80000003, &v[4], &v[5], &v[6], &v[7]);
	cpuid(0x80000004, &v[8], &v[9], &v[10], &v[11]);
	c->x86_model_id[48] = 0;
	return 1;
}


static void __cpuinit display_cacheinfo(struct cpuinfo_x86 *c)
{
	unsigned int n, dummy, eax, ebx, ecx, edx;

	n = c->extended_cpuid_level;

	if (n >= 0x80000005) {
		cpuid(0x80000005, &dummy, &ebx, &ecx, &edx);
		printk(KERN_INFO "CPU: L1 I Cache: %dK (%d bytes/line), D cache %dK (%d bytes/line)\n", edx>>24, edx&0xFF, ecx>>24, ecx&0xFF);
		c->x86_cache_size=(ecx>>24)+(edx>>24);
		
		c->x86_tlbsize = 0;
	}

	if (n >= 0x80000006) {
		cpuid(0x80000006, &dummy, &ebx, &ecx, &edx);
		ecx = cpuid_ecx(0x80000006);
		c->x86_cache_size = ecx >> 16;
		c->x86_tlbsize += ((ebx >> 16) & 0xfff) + (ebx & 0xfff);

		printk(KERN_INFO "CPU: L2 Cache: %dK (%d bytes/line)\n", c->x86_cache_size, ecx & 0xFF);
	}

	if (n >= 0x80000007)
		cpuid(0x80000007, &dummy, &dummy, &dummy, &c->x86_power); 
	if (n >= 0x80000008) {
		cpuid(0x80000008, &eax, &dummy, &dummy, &dummy); 
		c->x86_virt_bits = (eax >> 8) & 0xff;
		c->x86_phys_bits = eax & 0xff;
	}
}


static int nearby_node(int apicid)
{
	int i;
	for (i = apicid - 1; i >= 0; i--) {
		int node = apicid_to_node[i];
		if (node != NUMA_NO_NODE && node_online(node))
			return node;
	}
	for (i = apicid + 1; i < MAX_LOCAL_APIC; i++) {
		int node = apicid_to_node[i];
		if (node != NUMA_NO_NODE && node_online(node))
			return node;
	}
	return first_node(node_online_map); 
}



static void __init amd_detect_cmp(struct cpuinfo_x86 *c)
{

	int cpu = smp_processor_id();
	unsigned bits;

	int node = 0;
	unsigned apicid = hard_smp_processor_id();


	bits = 0;
	while ((1 << bits) < c->x86_max_cores)
		bits++;

	
	cpu_core_id[cpu] = phys_proc_id[cpu] & ((1 << bits)-1);
	
	phys_proc_id[cpu] = phys_pkg_id(bits);


  	node = phys_proc_id[cpu];
 	if (apicid_to_node[apicid] != NUMA_NO_NODE)
 		node = apicid_to_node[apicid];
 	if (!node_online(node)) {
 		
 		int ht_nodeid = apicid - (phys_proc_id[0] << bits);
 		if (ht_nodeid >= 0 && apicid_to_node[ht_nodeid] != NUMA_NO_NODE)
 			node = apicid_to_node[ht_nodeid];
 		
 		if (!node_online(node))
 			node = nearby_node(apicid);
 	}
	numa_set_node(cpu, node);

  	printk(KERN_INFO "CPU %d/%x(%d) -> Node %d -> Core %d\n", cpu, apicid, c->x86_max_cores, node, cpu_core_id[cpu]);


}

static int __init init_amd(struct cpuinfo_x86 *c)
{
	int r;
	unsigned level;


	unsigned long value;

	
	if (c->x86 == 15) {
		rdmsrl(MSR_K8_HWCR, value);
		value |= 1 << 6;
		wrmsrl(MSR_K8_HWCR, value);
	}


	
	clear_bit(0*32+31, &c->x86_capability);
	
	
	level = cpuid_eax(1);
	if (c->x86 == 15 && ((level >= 0x0f48 && level < 0x0f50) || level >= 0x0f58))
		set_bit(X86_FEATURE_REP_GOOD, &c->x86_capability);

	r = get_model_name(c);
	if (!r) { 
		switch (c->x86) { 
		case 15:
			
			strcpy(c->x86_model_id, "Hammer");
			break; 
		} 
	} 
	display_cacheinfo(c);

	
	if (c->x86_power & (1<<8))
		set_bit(X86_FEATURE_CONSTANT_TSC, &c->x86_capability);

	if (c->extended_cpuid_level >= 0x80000008) {
		c->x86_max_cores = (cpuid_ecx(0x80000008) & 0xff) + 1;

		amd_detect_cmp(c);
	}

	return r;
}

static void __cpuinit detect_ht(struct cpuinfo_x86 *c)
{

	u32 	eax, ebx, ecx, edx;
	int 	index_msb, core_bits;
	int 	cpu = smp_processor_id();

	cpuid(1, &eax, &ebx, &ecx, &edx);


	if (!cpu_has(c, X86_FEATURE_HT) || cpu_has(c, X86_FEATURE_CMP_LEGACY))
		return;

	smp_num_siblings = (ebx & 0xff0000) >> 16;

	if (smp_num_siblings == 1) {
		printk(KERN_INFO  "CPU: Hyper-Threading is disabled\n");
	} else if (smp_num_siblings > 1 ) {

		if (smp_num_siblings > NR_CPUS) {
			printk(KERN_WARNING "CPU: Unsupported number of the siblings %d", smp_num_siblings);
			smp_num_siblings = 1;
			return;
		}

		index_msb = get_count_order(smp_num_siblings);
		phys_proc_id[cpu] = phys_pkg_id(index_msb);

		printk(KERN_INFO  "CPU: Physical Processor ID: %d\n", phys_proc_id[cpu]);

		smp_num_siblings = smp_num_siblings / c->x86_max_cores;

		index_msb = get_count_order(smp_num_siblings) ;

		core_bits = get_count_order(c->x86_max_cores);

		cpu_core_id[cpu] = phys_pkg_id(index_msb) & ((1 << core_bits) - 1);

		if (c->x86_max_cores > 1)
			printk(KERN_INFO  "CPU: Processor Core ID: %d\n", cpu_core_id[cpu]);
	}

}


static int __cpuinit intel_num_cpu_cores(struct cpuinfo_x86 *c)
{
	unsigned int eax;

	if (c->cpuid_level < 4)
		return 1;

	__asm__("cpuid" : "=a" (eax)
		: "0" (4), "c" (0)
		: "bx", "dx");

	if (eax & 0x1f)
		return ((eax >> 26) + 1);
	else return 1;
}

static void srat_detect_node(void)
{

	unsigned node;
	int cpu = smp_processor_id();

	
	node = apicid_to_node[hard_smp_processor_id()];
	if (node == NUMA_NO_NODE)
		node = 0;
	numa_set_node(cpu, node);

	if (acpi_numa > 0)
		printk(KERN_INFO "CPU %d -> Node %d\n", cpu, node);

}

static void __cpuinit init_intel(struct cpuinfo_x86 *c)
{
	
	unsigned n;

	init_intel_cacheinfo(c);
	n = c->extended_cpuid_level;
	if (n >= 0x80000008) {
		unsigned eax = cpuid_eax(0x80000008);
		c->x86_virt_bits = (eax >> 8) & 0xff;
		c->x86_phys_bits = eax & 0xff;
		
		if (c->x86_vendor == X86_VENDOR_INTEL && c->x86 == 0xF && c->x86_model == 0x3 && c->x86_mask == 0x4)

			c->x86_phys_bits = 36;
	}

	if (c->x86 == 15)
		c->x86_cache_alignment = c->x86_clflush_size * 2;
	if ((c->x86 == 0xf && c->x86_model >= 0x03) || (c->x86 == 0x6 && c->x86_model >= 0x0e))
		set_bit(X86_FEATURE_CONSTANT_TSC, &c->x86_capability);
	set_bit(X86_FEATURE_SYNC_RDTSC, &c->x86_capability);
 	c->x86_max_cores = intel_num_cpu_cores(c);

	srat_detect_node();
}

static void __cpuinit get_cpu_vendor(struct cpuinfo_x86 *c)
{
	char *v = c->x86_vendor_id;

	if (!strcmp(v, "AuthenticAMD"))
		c->x86_vendor = X86_VENDOR_AMD;
	else if (!strcmp(v, "GenuineIntel"))
		c->x86_vendor = X86_VENDOR_INTEL;
	else c->x86_vendor = X86_VENDOR_UNKNOWN;
}

struct cpu_model_info {
	int vendor;
	int family;
	char *model_names[16];
};


void __cpuinit early_identify_cpu(struct cpuinfo_x86 *c)
{
	u32 tfms;

	c->loops_per_jiffy = loops_per_jiffy;
	c->x86_cache_size = -1;
	c->x86_vendor = X86_VENDOR_UNKNOWN;
	c->x86_model = c->x86_mask = 0;	
	c->x86_vendor_id[0] = '\0'; 
	c->x86_model_id[0] = '\0';  
	c->x86_clflush_size = 64;
	c->x86_cache_alignment = c->x86_clflush_size;
	c->x86_max_cores = 1;
	c->extended_cpuid_level = 0;
	memset(&c->x86_capability, 0, sizeof c->x86_capability);

	
	cpuid(0x00000000, (unsigned int *)&c->cpuid_level, (unsigned int *)&c->x86_vendor_id[0], (unsigned int *)&c->x86_vendor_id[8], (unsigned int *)&c->x86_vendor_id[4]);


		
	get_cpu_vendor(c);

	
	

	
	if (c->cpuid_level >= 0x00000001) {
		__u32 misc;
		cpuid(0x00000001, &tfms, &misc, &c->x86_capability[4], &c->x86_capability[0]);
		c->x86 = (tfms >> 8) & 0xf;
		c->x86_model = (tfms >> 4) & 0xf;
		c->x86_mask = tfms & 0xf;
		if (c->x86 == 0xf)
			c->x86 += (tfms >> 20) & 0xff;
		if (c->x86 >= 0x6)
			c->x86_model += ((tfms >> 16) & 0xF) << 4;
		if (c->x86_capability[0] & (1<<19)) 
			c->x86_clflush_size = ((misc >> 8) & 0xff) * 8;
	} else {
		
		c->x86 = 4;
	}


	phys_proc_id[smp_processor_id()] = (cpuid_ebx(1) >> 24) & 0xff;

}


void __cpuinit identify_cpu(struct cpuinfo_x86 *c)
{
	int i;
	u32 xlvl;

	early_identify_cpu(c);

	
	xlvl = cpuid_eax(0x80000000);
	c->extended_cpuid_level = xlvl;
	if ((xlvl & 0xffff0000) == 0x80000000) {
		if (xlvl >= 0x80000001) {
			c->x86_capability[1] = cpuid_edx(0x80000001);
			c->x86_capability[6] = cpuid_ecx(0x80000001);
		}
		if (xlvl >= 0x80000004)
			get_model_name(c); 
	}

	
	xlvl = cpuid_eax(0x80860000);
	if ((xlvl & 0xffff0000) == 0x80860000) {
		
		if (xlvl >= 0x80860001)
			c->x86_capability[2] = cpuid_edx(0x80860001);
	}

	c->apicid = phys_pkg_id(0);

	
	switch (c->x86_vendor) {
	case X86_VENDOR_AMD:
		init_amd(c);
		break;

	case X86_VENDOR_INTEL:
		init_intel(c);
		break;

	case X86_VENDOR_UNKNOWN:
	default:
		display_cacheinfo(c);
		break;
	}

	select_idle_routine(c);
	detect_ht(c); 

	
	if (c != &boot_cpu_data) {
		
		for (i = 0 ; i < NCAPINTS ; i++)
			boot_cpu_data.x86_capability[i] &= c->x86_capability[i];
	}


	mcheck_init(c);

	if (c == &boot_cpu_data)
		mtrr_bp_init();
	else mtrr_ap_init();

	numa_add_cpu(smp_processor_id());

}
 

void __cpuinit print_cpu_info(struct cpuinfo_x86 *c)
{
	if (c->x86_model_id[0])
		printk("%s", c->x86_model_id);

	if (c->x86_mask || c->cpuid_level >= 0) 
		printk(" stepping %02x\n", c->x86_mask);
	else printk("\n");
}



static int show_cpuinfo(struct seq_file *m, void *v)
{
	struct cpuinfo_x86 *c = v;

	
	static char *x86_cap_flags[] = {
		
	        "fpu", "vme", "de", "pse", "tsc", "msr", "pae", "mce", "cx8", "apic", NULL, "sep", "mtrr", "pge", "mca", "cmov", "pat", "pse36", "pn", "clflush", NULL, "dts", "acpi", "mmx", "fxsr", "sse", "sse2", "ss", "ht", "tm", "ia64", NULL,   NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "syscall", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "nx", NULL, "mmxext", NULL, NULL, "fxsr_opt", "rdtscp", NULL, NULL, "lm", "3dnowext", "3dnow",   "recovery", "longrun", NULL, "lrti", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,   "cxmmx", NULL, "cyrix_arr", "centaur_mcr", NULL, "constant_tsc", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,   "pni", NULL, NULL, "monitor", "ds_cpl", "vmx", "smx", "est", "tm2", NULL, "cid", NULL, NULL, "cx16", "xtpr", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,   NULL, NULL, "rng", "rng_en", NULL, NULL, "ace", "ace_en", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,   "lahf_lm", "cmp_legacy", "svm", NULL, "cr8_legacy", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, };








































	static char *x86_power_flags[] = { 
		"ts",	 "fid", "vid", "ttp", "tm", "stc", NULL,  };










	if (!cpu_online(c-cpu_data))
		return 0;


	seq_printf(m,"processor\t: %u\n" "vendor_id\t: %s\n" "cpu family\t: %d\n" "model\t\t: %d\n" "model name\t: %s\n", (unsigned)(c-cpu_data), c->x86_vendor_id[0] ? c->x86_vendor_id : "unknown", c->x86, (int)c->x86_model, c->x86_model_id[0] ? c->x86_model_id : "unknown");








	
	if (c->x86_mask || c->cpuid_level >= 0)
		seq_printf(m, "stepping\t: %d\n", c->x86_mask);
	else seq_printf(m, "stepping\t: unknown\n");
	
	if (cpu_has(c,X86_FEATURE_TSC)) {
		unsigned int freq = cpufreq_quick_get((unsigned)(c-cpu_data));
		if (!freq)
			freq = cpu_khz;
		seq_printf(m, "cpu MHz\t\t: %u.%03u\n", freq / 1000, (freq % 1000));
	}

	
	if (c->x86_cache_size >= 0) 
		seq_printf(m, "cache size\t: %d KB\n", c->x86_cache_size);
	

	if (smp_num_siblings * c->x86_max_cores > 1) {
		int cpu = c - cpu_data;
		seq_printf(m, "physical id\t: %d\n", phys_proc_id[cpu]);
		seq_printf(m, "siblings\t: %d\n", cpus_weight(cpu_core_map[cpu]));
		seq_printf(m, "core id\t\t: %d\n", cpu_core_id[cpu]);
		seq_printf(m, "cpu cores\t: %d\n", c->booted_cores);
	}


	seq_printf(m, "fpu\t\t: yes\n" "fpu_exception\t: yes\n" "cpuid level\t: %d\n" "wp\t\t: yes\n" "flags\t\t:", c->cpuid_level);






	{ 
		int i; 
		for ( i = 0 ; i < 32*NCAPINTS ; i++ )
			if (cpu_has(c, i) && x86_cap_flags[i] != NULL)
				seq_printf(m, " %s", x86_cap_flags[i]);
	}
		
	seq_printf(m, "\nbogomips\t: %lu.%02lu\n", c->loops_per_jiffy/(500000/HZ), (c->loops_per_jiffy/(5000/HZ)) % 100);


	if (c->x86_tlbsize > 0) 
		seq_printf(m, "TLB size\t: %d 4K pages\n", c->x86_tlbsize);
	seq_printf(m, "clflush size\t: %d\n", c->x86_clflush_size);
	seq_printf(m, "cache_alignment\t: %d\n", c->x86_cache_alignment);

	seq_printf(m, "address sizes\t: %u bits physical, %u bits virtual\n",  c->x86_phys_bits, c->x86_virt_bits);

	seq_printf(m, "power management:");
	{
		unsigned i;
		for (i = 0; i < 32; i++) 
			if (c->x86_power & (1 << i)) {
				if (i < ARRAY_SIZE(x86_power_flags) && x86_power_flags[i])
					seq_printf(m, "%s%s", x86_power_flags[i][0]?" ":"", x86_power_flags[i]);

				else seq_printf(m, " [%d]", i);
			}
	}

	seq_printf(m, "\n\n");

	return 0;
}

static void *c_start(struct seq_file *m, loff_t *pos)
{
	return *pos < NR_CPUS ? cpu_data + *pos : NULL;
}

static void *c_next(struct seq_file *m, void *v, loff_t *pos)
{
	++*pos;
	return c_start(m, pos);
}

static void c_stop(struct seq_file *m, void *v)
{
}

struct seq_operations cpuinfo_op = {
	.start =c_start, .next =	c_next, .stop =	c_stop, .show =	show_cpuinfo, };




