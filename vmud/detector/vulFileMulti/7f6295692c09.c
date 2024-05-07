


__FBSDID("$FreeBSD$");


























static d_open_t cpuctl_open;
static d_ioctl_t cpuctl_ioctl;











static int cpuctl_do_msr(int cpu, cpuctl_msr_args_t *data, u_long cmd, struct thread *td);
static int cpuctl_do_cpuid(int cpu, cpuctl_cpuid_args_t *data, struct thread *td);
static int cpuctl_do_cpuid_count(int cpu, cpuctl_cpuid_count_args_t *data, struct thread *td);
static int cpuctl_do_eval_cpu_features(int cpu, struct thread *td);
static int cpuctl_do_update(int cpu, cpuctl_update_args_t *data, struct thread *td);
static int update_intel(int cpu, cpuctl_update_args_t *args, struct thread *td);
static int update_amd(int cpu, cpuctl_update_args_t *args, struct thread *td);
static int update_via(int cpu, cpuctl_update_args_t *args, struct thread *td);

static struct cdev **cpuctl_devs;
static MALLOC_DEFINE(M_CPUCTL, "cpuctl", "CPUCTL buffer");

static struct cdevsw cpuctl_cdevsw = {
        .d_version =    D_VERSION, .d_open =       cpuctl_open, .d_ioctl =      cpuctl_ioctl, .d_name =       "cpuctl", };





static int cpu_enabled(int cpu)
{

	return (pmc_cpu_is_disabled(cpu) == 0);
}


static int cpu_sched_is_bound(struct thread *td)
{
	int ret;

	thread_lock(td);
	ret = sched_is_bound(td);
	thread_unlock(td);
	return (ret);
}


static void set_cpu(int cpu, struct thread *td)
{

	KASSERT(cpu >= 0 && cpu <= mp_maxid && cpu_enabled(cpu), ("[cpuctl,%d]: bad cpu number %d", __LINE__, cpu));
	thread_lock(td);
	sched_bind(td, cpu);
	thread_unlock(td);
	KASSERT(td->td_oncpu == cpu, ("[cpuctl,%d]: cannot bind to target cpu %d on cpu %d", __LINE__, cpu, td->td_oncpu));

}

static void restore_cpu(int oldcpu, int is_bound, struct thread *td)
{

	KASSERT(oldcpu >= 0 && oldcpu <= mp_maxid && cpu_enabled(oldcpu), ("[cpuctl,%d]: bad cpu number %d", __LINE__, oldcpu));
	thread_lock(td);
	if (is_bound == 0)
		sched_unbind(td);
	else sched_bind(td, oldcpu);
	thread_unlock(td);
}

int cpuctl_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int flags, struct thread *td)

{
	int cpu, ret;

	cpu = dev2unit(dev);
	if (cpu > mp_maxid || !cpu_enabled(cpu)) {
		DPRINTF("[cpuctl,%d]: bad cpu number %d\n", __LINE__, cpu);
		return (ENXIO);
	}
	
	if ((cmd == CPUCTL_MSRCBIT || cmd == CPUCTL_MSRSBIT || cmd == CPUCTL_UPDATE || cmd == CPUCTL_WRMSR || cmd == CPUCTL_EVAL_CPU_FEATURES) && (flags & FWRITE) == 0)


		return (EPERM);
	switch (cmd) {
	case CPUCTL_RDMSR:
		ret = cpuctl_do_msr(cpu, (cpuctl_msr_args_t *)data, cmd, td);
		break;
	case CPUCTL_MSRSBIT:
	case CPUCTL_MSRCBIT:
	case CPUCTL_WRMSR:
		ret = priv_check(td, PRIV_CPUCTL_WRMSR);
		if (ret != 0)
			goto fail;
		ret = cpuctl_do_msr(cpu, (cpuctl_msr_args_t *)data, cmd, td);
		break;
	case CPUCTL_CPUID:
		ret = cpuctl_do_cpuid(cpu, (cpuctl_cpuid_args_t *)data, td);
		break;
	case CPUCTL_UPDATE:
		ret = priv_check(td, PRIV_CPUCTL_UPDATE);
		if (ret != 0)
			goto fail;
		ret = cpuctl_do_update(cpu, (cpuctl_update_args_t *)data, td);
		break;
	case CPUCTL_CPUID_COUNT:
		ret = cpuctl_do_cpuid_count(cpu, (cpuctl_cpuid_count_args_t *)data, td);
		break;
	case CPUCTL_EVAL_CPU_FEATURES:
		ret = cpuctl_do_eval_cpu_features(cpu, td);
		break;
	default:
		ret = EINVAL;
		break;
	}
fail:
	return (ret);
}


static int cpuctl_do_cpuid_count(int cpu, cpuctl_cpuid_count_args_t *data, struct thread *td)

{
	int is_bound = 0;
	int oldcpu;

	KASSERT(cpu >= 0 && cpu <= mp_maxid, ("[cpuctl,%d]: bad cpu number %d", __LINE__, cpu));

	
	bzero(data->data, sizeof(data->data));
	DPRINTF("[cpuctl,%d]: retrieving cpuid lev %#0x type %#0x for %d cpu\n", __LINE__, data->level, data->level_type, cpu);

	if (cpu_id == 0)
		return (ENODEV);

	oldcpu = td->td_oncpu;
	is_bound = cpu_sched_is_bound(td);
	set_cpu(cpu, td);
	cpuid_count(data->level, data->level_type, data->data);
	restore_cpu(oldcpu, is_bound, td);
	return (0);
}

static int cpuctl_do_cpuid(int cpu, cpuctl_cpuid_args_t *data, struct thread *td)
{
	cpuctl_cpuid_count_args_t cdata;
	int error;

	cdata.level = data->level;
	
	cdata.level_type = 0;
	error = cpuctl_do_cpuid_count(cpu, &cdata, td);
	bcopy(cdata.data, data->data, sizeof(data->data)); 
	return (error);
}


static int cpuctl_do_msr(int cpu, cpuctl_msr_args_t *data, u_long cmd, struct thread *td)
{
	uint64_t reg;
	int is_bound = 0;
	int oldcpu;
	int ret;

	KASSERT(cpu >= 0 && cpu <= mp_maxid, ("[cpuctl,%d]: bad cpu number %d", __LINE__, cpu));

	
	DPRINTF("[cpuctl,%d]: operating on MSR %#0x for %d cpu\n", __LINE__, data->msr, cpu);

	if ((cpu_feature & CPUID_MSR) == 0)
		return (ENODEV);

	oldcpu = td->td_oncpu;
	is_bound = cpu_sched_is_bound(td);
	set_cpu(cpu, td);
	if (cmd == CPUCTL_RDMSR) {
		data->data = 0;
		ret = rdmsr_safe(data->msr, &data->data);
	} else if (cmd == CPUCTL_WRMSR) {
		ret = wrmsr_safe(data->msr, data->data);
	} else if (cmd == CPUCTL_MSRSBIT) {
		critical_enter();
		ret = rdmsr_safe(data->msr, &reg);
		if (ret == 0)
			ret = wrmsr_safe(data->msr, reg | data->data);
		critical_exit();
	} else if (cmd == CPUCTL_MSRCBIT) {
		critical_enter();
		ret = rdmsr_safe(data->msr, &reg);
		if (ret == 0)
			ret = wrmsr_safe(data->msr, reg & ~data->data);
		critical_exit();
	} else panic("[cpuctl,%d]: unknown operation requested: %lu", __LINE__, cmd);

	restore_cpu(oldcpu, is_bound, td);
	return (ret);
}


static int cpuctl_do_update(int cpu, cpuctl_update_args_t *data, struct thread *td)
{
	cpuctl_cpuid_args_t args = {
		.level = 0, };
	char vendor[13];
	int ret;

	KASSERT(cpu >= 0 && cpu <= mp_maxid, ("[cpuctl,%d]: bad cpu number %d", __LINE__, cpu));
	DPRINTF("[cpuctl,%d]: XXX %d", __LINE__, cpu);

	ret = cpuctl_do_cpuid(cpu, &args, td);
	if (ret != 0)
		return (ret);
	((uint32_t *)vendor)[0] = args.data[1];
	((uint32_t *)vendor)[1] = args.data[3];
	((uint32_t *)vendor)[2] = args.data[2];
	vendor[12] = '\0';
	if (strncmp(vendor, INTEL_VENDOR_ID, sizeof(INTEL_VENDOR_ID)) == 0)
		ret = update_intel(cpu, data, td);
	else if(strncmp(vendor, AMD_VENDOR_ID, sizeof(AMD_VENDOR_ID)) == 0)
		ret = update_amd(cpu, data, td);
	else if(strncmp(vendor, CENTAUR_VENDOR_ID, sizeof(CENTAUR_VENDOR_ID))
	    == 0)
		ret = update_via(cpu, data, td);
	else ret = ENXIO;
	return (ret);
}

struct ucode_update_data {
	void *ptr;
	int cpu;
	int ret;
};

static void ucode_intel_load_rv(void *arg)
{
	struct ucode_update_data *d;

	d = arg;
	if (PCPU_GET(cpuid) == d->cpu)
		d->ret = ucode_intel_load(d->ptr, true, NULL, NULL);
}

static int update_intel(int cpu, cpuctl_update_args_t *args, struct thread *td)
{
	struct ucode_update_data d;
	void *ptr;
	int is_bound, oldcpu, ret;

	if (args->size == 0 || args->data == NULL) {
		DPRINTF("[cpuctl,%d]: zero-sized firmware image", __LINE__);
		return (EINVAL);
	}
	if (args->size > UCODE_SIZE_MAX) {
		DPRINTF("[cpuctl,%d]: firmware image too large", __LINE__);
		return (EINVAL);
	}

	
	ptr = malloc(args->size + 16, M_CPUCTL, M_WAITOK);
	if (copyin(args->data, ptr, args->size) != 0) {
		DPRINTF("[cpuctl,%d]: copyin %p->%p of %zd bytes failed", __LINE__, args->data, ptr, args->size);
		ret = EFAULT;
		goto out;
	}
	oldcpu = td->td_oncpu;
	is_bound = cpu_sched_is_bound(td);
	set_cpu(cpu, td);
	d.ptr = ptr;
	d.cpu = cpu;
	smp_rendezvous(NULL, ucode_intel_load_rv, NULL, &d);
	restore_cpu(oldcpu, is_bound, td);
	ret = d.ret;

	
	if (ret == 0)
		ptr = ucode_update(ptr);

out:
	free(ptr, M_CPUCTL);
	return (ret);
}


static void amd_ucode_wrmsr(void *ucode_ptr)
{
	uint32_t tmp[4];

	wrmsr_safe(MSR_K8_UCODE_UPDATE, (uintptr_t)ucode_ptr);
	do_cpuid(0, tmp);
}

static int update_amd(int cpu, cpuctl_update_args_t *args, struct thread *td)
{
	void *ptr;
	int ret;

	if (args->size == 0 || args->data == NULL) {
		DPRINTF("[cpuctl,%d]: zero-sized firmware image", __LINE__);
		return (EINVAL);
	}
	if (args->size > UCODE_SIZE_MAX) {
		DPRINTF("[cpuctl,%d]: firmware image too large", __LINE__);
		return (EINVAL);
	}

	
	ptr = malloc(args->size + 16, M_CPUCTL, M_ZERO | M_WAITOK);
	if (copyin(args->data, ptr, args->size) != 0) {
		DPRINTF("[cpuctl,%d]: copyin %p->%p of %zd bytes failed", __LINE__, args->data, ptr, args->size);
		ret = EFAULT;
		goto fail;
	}
	smp_rendezvous(NULL, amd_ucode_wrmsr, NULL, ptr);
	ret = 0;
fail:
	free(ptr, M_CPUCTL);
	return (ret);
}

static int update_via(int cpu, cpuctl_update_args_t *args, struct thread *td)
{
	void *ptr;
	uint64_t rev0, rev1, res;
	uint32_t tmp[4];
	int is_bound;
	int oldcpu;
	int ret;

	if (args->size == 0 || args->data == NULL) {
		DPRINTF("[cpuctl,%d]: zero-sized firmware image", __LINE__);
		return (EINVAL);
	}
	if (args->size > UCODE_SIZE_MAX) {
		DPRINTF("[cpuctl,%d]: firmware image too large", __LINE__);
		return (EINVAL);
	}

	
	ptr = malloc(args->size, M_CPUCTL, M_WAITOK);
	if (copyin(args->data, ptr, args->size) != 0) {
		DPRINTF("[cpuctl,%d]: copyin %p->%p of %zd bytes failed", __LINE__, args->data, ptr, args->size);
		ret = EFAULT;
		goto fail;
	}
	oldcpu = td->td_oncpu;
	is_bound = cpu_sched_is_bound(td);
	set_cpu(cpu, td);
	critical_enter();
	rdmsr_safe(MSR_BIOS_SIGN, &rev0); 

	
	wrmsr_safe(MSR_BIOS_UPDT_TRIG, (uintptr_t)(ptr));
	do_cpuid(1, tmp);

	
	rdmsr_safe(0x1205, &res);
	res &= 0xff;
	critical_exit();
	rdmsr_safe(MSR_BIOS_SIGN, &rev1); 
	restore_cpu(oldcpu, is_bound, td);

	DPRINTF("[cpu,%d]: rev0=%x rev1=%x res=%x\n", __LINE__, (unsigned)(rev0 >> 32), (unsigned)(rev1 >> 32), (unsigned)res);

	if (res != 0x01)
		ret = EINVAL;
	else ret = 0;
fail:
	free(ptr, M_CPUCTL);
	return (ret);
}

static int cpuctl_do_eval_cpu_features(int cpu, struct thread *td)
{
	int is_bound = 0;
	int oldcpu;

	KASSERT(cpu >= 0 && cpu <= mp_maxid, ("[cpuctl,%d]: bad cpu number %d", __LINE__, cpu));


	if (cpu_id == 0)
		return (ENODEV);

	oldcpu = td->td_oncpu;
	is_bound = cpu_sched_is_bound(td);
	set_cpu(cpu, td);
	identify_cpu1();
	identify_cpu2();
	hw_ibrs_recalculate();
	restore_cpu(oldcpu, is_bound, td);
	hw_ssb_recalculate(true);

	amd64_syscall_ret_flush_l1d_recalc();

	hw_mds_recalculate();
	printcpuinfo();
	return (0);
}


int cpuctl_open(struct cdev *dev, int flags, int fmt __unused, struct thread *td)
{
	int ret = 0;
	int cpu;

	cpu = dev2unit(dev);
	if (cpu > mp_maxid || !cpu_enabled(cpu)) {
		DPRINTF("[cpuctl,%d]: incorrect cpu number %d\n", __LINE__, cpu);
		return (ENXIO);
	}
	if (flags & FWRITE)
		ret = securelevel_gt(td->td_ucred, 0);
	return (ret);
}

static int cpuctl_modevent(module_t mod __unused, int type, void *data __unused)
{
	int cpu;

	switch(type) {
	case MOD_LOAD:
		if (bootverbose)
			printf("cpuctl: access to MSR registers/cpuid info.\n");
		cpuctl_devs = malloc(sizeof(*cpuctl_devs) * (mp_maxid + 1), M_CPUCTL, M_WAITOK | M_ZERO);
		CPU_FOREACH(cpu)
			if (cpu_enabled(cpu))
				cpuctl_devs[cpu] = make_dev(&cpuctl_cdevsw, cpu, UID_ROOT, GID_KMEM, 0640, "cpuctl%d", cpu);
		break;
	case MOD_UNLOAD:
		CPU_FOREACH(cpu) {
			if (cpuctl_devs[cpu] != NULL)
				destroy_dev(cpuctl_devs[cpu]);
		}
		free(cpuctl_devs, M_CPUCTL);
		break;
	case MOD_SHUTDOWN:
		break;
	default:
		return (EOPNOTSUPP);
        }
	return (0);
}

DEV_MODULE(cpuctl, cpuctl_modevent, NULL);
MODULE_VERSION(cpuctl, CPUCTL_VERSION);
