















































struct appldata_parameter_list {
	u16 diag;		
	u8  function;		
	u8  parlist_length;	
	u32 product_id_addr;	
	u16 reserved;
	u16 buffer_length;	
	u32 buffer_addr;	
};

struct appldata_parameter_list {
	u16 diag;
	u8  function;
	u8  parlist_length;
	u32 unused01;
	u16 reserved;
	u16 buffer_length;
	u32 unused02;
	u64 product_id_addr;
	u64 buffer_addr;
};



static const char appldata_proc_name[APPLDATA_PROC_NAME_LENGTH] = "appldata";
static int appldata_timer_handler(ctl_table *ctl, int write, struct file *filp, void __user *buffer, size_t *lenp, loff_t *ppos);
static int appldata_interval_handler(ctl_table *ctl, int write, struct file *filp, void __user *buffer, size_t *lenp, loff_t *ppos);



static struct ctl_table_header *appldata_sysctl_header;
static struct ctl_table appldata_table[] = {
	{
		.ctl_name	= CTL_APPLDATA_TIMER, .procname	= "timer", .mode		= S_IRUGO | S_IWUSR, .proc_handler	= &appldata_timer_handler, }, {




		.ctl_name	= CTL_APPLDATA_INTERVAL, .procname	= "interval", .mode		= S_IRUGO | S_IWUSR, .proc_handler	= &appldata_interval_handler, }, { .ctl_name = 0 }




};

static struct ctl_table appldata_dir_table[] = {
	{
		.ctl_name	= CTL_APPLDATA, .procname	= appldata_proc_name, .maxlen		= 0, .mode		= S_IRUGO | S_IXUGO, .child		= appldata_table, }, { .ctl_name = 0 }





};


DEFINE_PER_CPU(struct vtimer_list, appldata_timer);
static atomic_t appldata_expire_count = ATOMIC_INIT(0);

static DEFINE_SPINLOCK(appldata_timer_lock);
static int appldata_interval = APPLDATA_CPU_INTERVAL;
static int appldata_timer_active;


static struct workqueue_struct *appldata_wq;
static void appldata_work_fn(void *data);
static DECLARE_WORK(appldata_work, appldata_work_fn, NULL);



static DEFINE_SPINLOCK(appldata_ops_lock);
static LIST_HEAD(appldata_ops_list);




static void appldata_timer_function(unsigned long data, struct pt_regs *regs)
{
	P_DEBUG("   -= Timer =-\n");
	P_DEBUG("CPU: %i, expire_count: %i\n", smp_processor_id(), atomic_read(&appldata_expire_count));
	if (atomic_dec_and_test(&appldata_expire_count)) {
		atomic_set(&appldata_expire_count, num_online_cpus());
		queue_work(appldata_wq, (struct work_struct *) data);
	}
}


static void appldata_work_fn(void *data)
{
	struct list_head *lh;
	struct appldata_ops *ops;
	int i;

	P_DEBUG("  -= Work Queue =-\n");
	i = 0;
	spin_lock(&appldata_ops_lock);
	list_for_each(lh, &appldata_ops_list) {
		ops = list_entry(lh, struct appldata_ops, list);
		P_DEBUG("list_for_each loop: %i) active = %u, name = %s\n", ++i, ops->active, ops->name);
		if (ops->active == 1) {
			ops->callback(ops->data);
		}
	}
	spin_unlock(&appldata_ops_lock);
}


static int appldata_diag(char record_nr, u16 function, unsigned long buffer, u16 length)
{
	unsigned long ry;
	struct appldata_product_id {
		char prod_nr[7];			
		char prod_fn[2];			
		char record_nr;				
		char version_nr[2];			
		char release_nr[2];			
		char mod_lvl[2];			
	} appldata_product_id = {
	
		.prod_nr    = {0xD3, 0xC9, 0xD5, 0xE4, 0xE7, 0xD2, 0xD9}, .prod_fn    = {0xD5, 0xD3}, .record_nr  = record_nr, .version_nr = {0xF2, 0xF6}, .release_nr = {0xF0, 0xF1}, .mod_lvl    = {0xF0, 0xF0}, };






	struct appldata_parameter_list appldata_parameter_list = {
				.diag = 0xDC, .function = function, .parlist_length = sizeof(appldata_parameter_list), .buffer_length = length, .product_id_addr = (unsigned long) &appldata_product_id, .buffer_addr = virt_to_phys((void *) buffer)






	};

	if (!MACHINE_IS_VM)
		return -ENOSYS;
	ry = -1;
	asm volatile( "diag %1,%0,0xDC\n\t" : "=d" (ry)

			: "d" (&appldata_parameter_list), "m" (appldata_parameter_list), "m" (appldata_product_id)

			: "cc");
	return (int) ry;
}






static void __appldata_mod_vtimer_wrap(void *p) {
	struct {
		struct vtimer_list *timer;
		u64    expires;
	} *args = p;
	mod_virt_timer(args->timer, args->expires);
}






static void __appldata_vtimer_setup(int cmd)
{
	u64 per_cpu_interval;
	int i;

	switch (cmd) {
	case APPLDATA_ADD_TIMER:
		if (appldata_timer_active)
			break;
		per_cpu_interval = (u64) (appldata_interval*1000 / num_online_cpus()) * TOD_MICRO;
		for_each_online_cpu(i) {
			per_cpu(appldata_timer, i).expires = per_cpu_interval;
			smp_call_function_on(add_virt_timer_periodic, &per_cpu(appldata_timer, i), 0, 1, i);

		}
		appldata_timer_active = 1;
		P_INFO("Monitoring timer started.\n");
		break;
	case APPLDATA_DEL_TIMER:
		for_each_online_cpu(i)
			del_virt_timer(&per_cpu(appldata_timer, i));
		if (!appldata_timer_active)
			break;
		appldata_timer_active = 0;
		atomic_set(&appldata_expire_count, num_online_cpus());
		P_INFO("Monitoring timer stopped.\n");
		break;
	case APPLDATA_MOD_TIMER:
		per_cpu_interval = (u64) (appldata_interval*1000 / num_online_cpus()) * TOD_MICRO;
		if (!appldata_timer_active)
			break;
		for_each_online_cpu(i) {
			struct {
				struct vtimer_list *timer;
				u64    expires;
			} args;
			args.timer = &per_cpu(appldata_timer, i);
			args.expires = per_cpu_interval;
			smp_call_function_on(__appldata_mod_vtimer_wrap, &args, 0, 1, i);
		}
	}
}


static int appldata_timer_handler(ctl_table *ctl, int write, struct file *filp, void __user *buffer, size_t *lenp, loff_t *ppos)

{
	int len;
	char buf[2];

	if (!*lenp || *ppos) {
		*lenp = 0;
		return 0;
	}
	if (!write) {
		len = sprintf(buf, appldata_timer_active ? "1\n" : "0\n");
		if (len > *lenp)
			len = *lenp;
		if (copy_to_user(buffer, buf, len))
			return -EFAULT;
		goto out;
	}
	len = *lenp;
	if (copy_from_user(buf, buffer, len > sizeof(buf) ? sizeof(buf) : len))
		return -EFAULT;
	spin_lock(&appldata_timer_lock);
	if (buf[0] == '1')
		__appldata_vtimer_setup(APPLDATA_ADD_TIMER);
	else if (buf[0] == '0')
		__appldata_vtimer_setup(APPLDATA_DEL_TIMER);
	spin_unlock(&appldata_timer_lock);
out:
	*lenp = len;
	*ppos += len;
	return 0;
}


static int appldata_interval_handler(ctl_table *ctl, int write, struct file *filp, void __user *buffer, size_t *lenp, loff_t *ppos)

{
	int len, interval;
	char buf[16];

	if (!*lenp || *ppos) {
		*lenp = 0;
		return 0;
	}
	if (!write) {
		len = sprintf(buf, "%i\n", appldata_interval);
		if (len > *lenp)
			len = *lenp;
		if (copy_to_user(buffer, buf, len))
			return -EFAULT;
		goto out;
	}
	len = *lenp;
	if (copy_from_user(buf, buffer, len > sizeof(buf) ? sizeof(buf) : len)) {
		return -EFAULT;
	}
	sscanf(buf, "%i", &interval);
	if (interval <= 0) {
		P_ERROR("Timer CPU interval has to be > 0!\n");
		return -EINVAL;
	}

	spin_lock(&appldata_timer_lock);
	appldata_interval = interval;
	__appldata_vtimer_setup(APPLDATA_MOD_TIMER);
	spin_unlock(&appldata_timer_lock);

	P_INFO("Monitoring CPU interval set to %u milliseconds.\n", interval);
out:
	*lenp = len;
	*ppos += len;
	return 0;
}


static int appldata_generic_handler(ctl_table *ctl, int write, struct file *filp, void __user *buffer, size_t *lenp, loff_t *ppos)

{
	struct appldata_ops *ops = NULL, *tmp_ops;
	int rc, len, found;
	char buf[2];
	struct list_head *lh;

	found = 0;
	spin_lock(&appldata_ops_lock);
	list_for_each(lh, &appldata_ops_list) {
		tmp_ops = list_entry(lh, struct appldata_ops, list);
		if (&tmp_ops->ctl_table[2] == ctl) {
			found = 1;
		}
	}
	if (!found) {
		spin_unlock(&appldata_ops_lock);
		return -ENODEV;
	}
	ops = ctl->data;
	if (!try_module_get(ops->owner)) {	
		spin_unlock(&appldata_ops_lock);
		return -ENODEV;
	}
	spin_unlock(&appldata_ops_lock);

	if (!*lenp || *ppos) {
		*lenp = 0;
		module_put(ops->owner);
		return 0;
	}
	if (!write) {
		len = sprintf(buf, ops->active ? "1\n" : "0\n");
		if (len > *lenp)
			len = *lenp;
		if (copy_to_user(buffer, buf, len)) {
			module_put(ops->owner);
			return -EFAULT;
		}
		goto out;
	}
	len = *lenp;
	if (copy_from_user(buf, buffer, len > sizeof(buf) ? sizeof(buf) : len)) {
		module_put(ops->owner);
		return -EFAULT;
	}

	spin_lock(&appldata_ops_lock);
	if ((buf[0] == '1') && (ops->active == 0)) {
		
		if (!try_module_get(ops->owner)) {
			spin_unlock(&appldata_ops_lock);
			module_put(ops->owner);
			return -ENODEV;
		}
		ops->active = 1;
		ops->callback(ops->data);	
		rc = appldata_diag(ops->record_nr, APPLDATA_START_INTERVAL_REC, (unsigned long) ops->data, ops->size);

		if (rc != 0) {
			P_ERROR("START DIAG 0xDC for %s failed, " "return code: %d\n", ops->name, rc);
			module_put(ops->owner);
			ops->active = 0;
		} else {
			P_INFO("Monitoring %s data enabled, " "DIAG 0xDC started.\n", ops->name);
		}
	} else if ((buf[0] == '0') && (ops->active == 1)) {
		ops->active = 0;
		rc = appldata_diag(ops->record_nr, APPLDATA_STOP_REC, (unsigned long) ops->data, ops->size);
		if (rc != 0) {
			P_ERROR("STOP DIAG 0xDC for %s failed, " "return code: %d\n", ops->name, rc);
		} else {
			P_INFO("Monitoring %s data disabled, " "DIAG 0xDC stopped.\n", ops->name);
		}
		module_put(ops->owner);
	}
	spin_unlock(&appldata_ops_lock);
out:
	*lenp = len;
	*ppos += len;
	module_put(ops->owner);
	return 0;
}






int appldata_register_ops(struct appldata_ops *ops)
{
	struct list_head *lh;
	struct appldata_ops *tmp_ops;
	int i;

	i = 0;

	if ((ops->size > APPLDATA_MAX_REC_SIZE) || (ops->size < 0)){
		P_ERROR("Invalid size of %s record = %i, maximum = %i!\n", ops->name, ops->size, APPLDATA_MAX_REC_SIZE);
		return -ENOMEM;
	}
	if ((ops->ctl_nr == CTL_APPLDATA) || (ops->ctl_nr == CTL_APPLDATA_TIMER) || (ops->ctl_nr == CTL_APPLDATA_INTERVAL)) {

		P_ERROR("ctl_nr %i already in use!\n", ops->ctl_nr);
		return -EBUSY;
	}
	ops->ctl_table = kmalloc(4*sizeof(struct ctl_table), GFP_KERNEL);
	if (ops->ctl_table == NULL) {
		P_ERROR("Not enough memory for %s ctl_table!\n", ops->name);
		return -ENOMEM;
	}
	memset(ops->ctl_table, 0, 4*sizeof(struct ctl_table));

	spin_lock(&appldata_ops_lock);
	list_for_each(lh, &appldata_ops_list) {
		tmp_ops = list_entry(lh, struct appldata_ops, list);
		P_DEBUG("register_ops loop: %i) name = %s, ctl = %i\n", ++i, tmp_ops->name, tmp_ops->ctl_nr);
		P_DEBUG("Comparing %s (ctl %i) with %s (ctl %i)\n", tmp_ops->name, tmp_ops->ctl_nr, ops->name, ops->ctl_nr);

		if (strncmp(tmp_ops->name, ops->name, APPLDATA_PROC_NAME_LENGTH) == 0) {
			P_ERROR("Name \"%s\" already registered!\n", ops->name);
			kfree(ops->ctl_table);
			spin_unlock(&appldata_ops_lock);
			return -EBUSY;
		}
		if (tmp_ops->ctl_nr == ops->ctl_nr) {
			P_ERROR("ctl_nr %i already registered!\n", ops->ctl_nr);
			kfree(ops->ctl_table);
			spin_unlock(&appldata_ops_lock);
			return -EBUSY;
		}
	}
	list_add(&ops->list, &appldata_ops_list);
	spin_unlock(&appldata_ops_lock);

	ops->ctl_table[0].ctl_name = CTL_APPLDATA;
	ops->ctl_table[0].procname = appldata_proc_name;
	ops->ctl_table[0].maxlen   = 0;
	ops->ctl_table[0].mode     = S_IRUGO | S_IXUGO;
	ops->ctl_table[0].child    = &ops->ctl_table[2];

	ops->ctl_table[1].ctl_name = 0;

	ops->ctl_table[2].ctl_name = ops->ctl_nr;
	ops->ctl_table[2].procname = ops->name;
	ops->ctl_table[2].mode     = S_IRUGO | S_IWUSR;
	ops->ctl_table[2].proc_handler = appldata_generic_handler;
	ops->ctl_table[2].data = ops;

	ops->ctl_table[3].ctl_name = 0;

	ops->sysctl_header = register_sysctl_table(ops->ctl_table,1);

	P_INFO("%s-ops registered!\n", ops->name);
	return 0;
}


void appldata_unregister_ops(struct appldata_ops *ops)
{
	spin_lock(&appldata_ops_lock);
	unregister_sysctl_table(ops->sysctl_header);
	list_del(&ops->list);
	kfree(ops->ctl_table);
	ops->ctl_table = NULL;
	spin_unlock(&appldata_ops_lock);
	P_INFO("%s-ops unregistered!\n", ops->name);
}





static void appldata_online_cpu(int cpu)
{
	init_virt_timer(&per_cpu(appldata_timer, cpu));
	per_cpu(appldata_timer, cpu).function = appldata_timer_function;
	per_cpu(appldata_timer, cpu).data = (unsigned long)
		&appldata_work;
	atomic_inc(&appldata_expire_count);
	spin_lock(&appldata_timer_lock);
	__appldata_vtimer_setup(APPLDATA_MOD_TIMER);
	spin_unlock(&appldata_timer_lock);
}

static void appldata_offline_cpu(int cpu)
{
	del_virt_timer(&per_cpu(appldata_timer, cpu));
	if (atomic_dec_and_test(&appldata_expire_count)) {
		atomic_set(&appldata_expire_count, num_online_cpus());
		queue_work(appldata_wq, &appldata_work);
	}
	spin_lock(&appldata_timer_lock);
	__appldata_vtimer_setup(APPLDATA_MOD_TIMER);
	spin_unlock(&appldata_timer_lock);
}

static int appldata_cpu_notify(struct notifier_block *self, unsigned long action, void *hcpu)

{
	switch (action) {
	case CPU_ONLINE:
		appldata_online_cpu((long) hcpu);
		break;

	case CPU_DEAD:
		appldata_offline_cpu((long) hcpu);
		break;

	default:
		break;
	}
	return NOTIFY_OK;
}

static struct notifier_block __devinitdata appldata_nb = {
	.notifier_call = appldata_cpu_notify, };


static int __init appldata_init(void)
{
	int i;

	P_DEBUG("sizeof(parameter_list) = %lu\n", sizeof(struct appldata_parameter_list));

	appldata_wq = create_singlethread_workqueue("appldata");
	if (!appldata_wq) {
		P_ERROR("Could not create work queue\n");
		return -ENOMEM;
	}

	for_each_online_cpu(i)
		appldata_online_cpu(i);

	
	register_cpu_notifier(&appldata_nb);

	appldata_sysctl_header = register_sysctl_table(appldata_dir_table, 1);

	appldata_dir_table[0].de->owner = THIS_MODULE;
	appldata_table[0].de->owner = THIS_MODULE;
	appldata_table[1].de->owner = THIS_MODULE;


	P_DEBUG("Base interface initialized.\n");
	return 0;
}


static void __exit appldata_exit(void)
{
	struct list_head *lh;
	struct appldata_ops *ops;
	int rc, i;

	P_DEBUG("Unloading module ...\n");
	
	spin_lock(&appldata_ops_lock);
	list_for_each(lh, &appldata_ops_list) {
		ops = list_entry(lh, struct appldata_ops, list);
		rc = appldata_diag(ops->record_nr, APPLDATA_STOP_REC, (unsigned long) ops->data, ops->size);
		if (rc != 0) {
			P_ERROR("STOP DIAG 0xDC for %s failed, " "return code: %d\n", ops->name, rc);
		}
	}
	spin_unlock(&appldata_ops_lock);

	for_each_online_cpu(i)
		appldata_offline_cpu(i);

	appldata_timer_active = 0;

	unregister_sysctl_table(appldata_sysctl_header);

	destroy_workqueue(appldata_wq);
	P_DEBUG("... module unloaded!\n");
}



module_init(appldata_init);
module_exit(appldata_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Gerald Schaefer");
MODULE_DESCRIPTION("Linux-VM Monitor Stream, base infrastructure");

EXPORT_SYMBOL_GPL(appldata_register_ops);
EXPORT_SYMBOL_GPL(appldata_unregister_ops);



void si_swapinfo(struct sysinfo *val)
{
	val->freeswap = -1ul;
	val->totalswap = -1ul;
}

unsigned long avenrun[3] = {-1 - FIXED_1/200, -1 - FIXED_1/200, -1 - FIXED_1/200};
int nr_threads = -1;

void get_full_page_state(struct page_state *ps)
{
	memset(ps, -1, sizeof(struct page_state));
}

unsigned long nr_running(void)
{
	return -1;
}

unsigned long nr_iowait(void)
{
	return -1;
}



EXPORT_SYMBOL_GPL(si_swapinfo);
EXPORT_SYMBOL_GPL(nr_threads);
EXPORT_SYMBOL_GPL(avenrun);
EXPORT_SYMBOL_GPL(get_full_page_state);
EXPORT_SYMBOL_GPL(nr_running);
EXPORT_SYMBOL_GPL(nr_iowait);

