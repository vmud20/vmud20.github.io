


























static void warn_setuid_and_fcaps_mixed(const char *fname)
{
	static int warned;
	if (!warned) {
		printk(KERN_INFO "warning: `%s' has both setuid-root and" " effective capabilities. Therefore not raising all" " capabilities.\n", fname);

		warned = 1;
	}
}


int cap_capable(const struct cred *cred, struct user_namespace *targ_ns, int cap, int audit)
{
	struct user_namespace *ns = targ_ns;

	
	for (;;) {
		
		if (ns == cred->user_ns)
			return cap_raised(cred->cap_effective, cap) ? 0 : -EPERM;

		
		if (ns == &init_user_ns)
			return -EPERM;

		
		if ((ns->parent == cred->user_ns) && uid_eq(ns->owner, cred->euid))
			return 0;

		
		ns = ns->parent;
	}

	
}


int cap_settime(const struct timespec64 *ts, const struct timezone *tz)
{
	if (!capable(CAP_SYS_TIME))
		return -EPERM;
	return 0;
}


int cap_ptrace_access_check(struct task_struct *child, unsigned int mode)
{
	int ret = 0;
	const struct cred *cred, *child_cred;
	const kernel_cap_t *caller_caps;

	rcu_read_lock();
	cred = current_cred();
	child_cred = __task_cred(child);
	if (mode & PTRACE_MODE_FSCREDS)
		caller_caps = &cred->cap_effective;
	else caller_caps = &cred->cap_permitted;
	if (cred->user_ns == child_cred->user_ns && cap_issubset(child_cred->cap_permitted, *caller_caps))
		goto out;
	if (ns_capable(child_cred->user_ns, CAP_SYS_PTRACE))
		goto out;
	ret = -EPERM;
out:
	rcu_read_unlock();
	return ret;
}


int cap_ptrace_traceme(struct task_struct *parent)
{
	int ret = 0;
	const struct cred *cred, *child_cred;

	rcu_read_lock();
	cred = __task_cred(parent);
	child_cred = current_cred();
	if (cred->user_ns == child_cred->user_ns && cap_issubset(child_cred->cap_permitted, cred->cap_permitted))
		goto out;
	if (has_ns_capability(parent, child_cred->user_ns, CAP_SYS_PTRACE))
		goto out;
	ret = -EPERM;
out:
	rcu_read_unlock();
	return ret;
}


int cap_capget(struct task_struct *target, kernel_cap_t *effective, kernel_cap_t *inheritable, kernel_cap_t *permitted)
{
	const struct cred *cred;

	
	rcu_read_lock();
	cred = __task_cred(target);
	*effective   = cred->cap_effective;
	*inheritable = cred->cap_inheritable;
	*permitted   = cred->cap_permitted;
	rcu_read_unlock();
	return 0;
}


static inline int cap_inh_is_capped(void)
{

	
	if (cap_capable(current_cred(), current_cred()->user_ns, CAP_SETPCAP, SECURITY_CAP_AUDIT) == 0)
		return 0;
	return 1;
}


int cap_capset(struct cred *new, const struct cred *old, const kernel_cap_t *effective, const kernel_cap_t *inheritable, const kernel_cap_t *permitted)



{
	if (cap_inh_is_capped() && !cap_issubset(*inheritable, cap_combine(old->cap_inheritable, old->cap_permitted)))


		
		return -EPERM;

	if (!cap_issubset(*inheritable, cap_combine(old->cap_inheritable, old->cap_bset)))

		
		return -EPERM;

	
	if (!cap_issubset(*permitted, old->cap_permitted))
		return -EPERM;

	
	if (!cap_issubset(*effective, *permitted))
		return -EPERM;

	new->cap_effective   = *effective;
	new->cap_inheritable = *inheritable;
	new->cap_permitted   = *permitted;

	
	new->cap_ambient = cap_intersect(new->cap_ambient, cap_intersect(*permitted, *inheritable));

	if (WARN_ON(!cap_ambient_invariant_ok(new)))
		return -EINVAL;
	return 0;
}


static inline void bprm_clear_caps(struct linux_binprm *bprm)
{
	cap_clear(bprm->cred->cap_permitted);
	bprm->cap_effective = false;
}


int cap_inode_need_killpriv(struct dentry *dentry)
{
	struct inode *inode = d_backing_inode(dentry);
	int error;

	if (!inode->i_op->getxattr)
	       return 0;

	error = inode->i_op->getxattr(dentry, inode, XATTR_NAME_CAPS, NULL, 0);
	if (error <= 0)
		return 0;
	return 1;
}


int cap_inode_killpriv(struct dentry *dentry)
{
	struct inode *inode = d_backing_inode(dentry);

	if (!inode->i_op->removexattr)
	       return 0;

	return inode->i_op->removexattr(dentry, XATTR_NAME_CAPS);
}


static inline int bprm_caps_from_vfs_caps(struct cpu_vfs_cap_data *caps, struct linux_binprm *bprm, bool *effective, bool *has_cap)


{
	struct cred *new = bprm->cred;
	unsigned i;
	int ret = 0;

	if (caps->magic_etc & VFS_CAP_FLAGS_EFFECTIVE)
		*effective = true;

	if (caps->magic_etc & VFS_CAP_REVISION_MASK)
		*has_cap = true;

	CAP_FOR_EACH_U32(i) {
		__u32 permitted = caps->permitted.cap[i];
		__u32 inheritable = caps->inheritable.cap[i];

		
		new->cap_permitted.cap[i] = (new->cap_bset.cap[i] & permitted) | (new->cap_inheritable.cap[i] & inheritable);


		if (permitted & ~new->cap_permitted.cap[i])
			
			ret = -EPERM;
	}

	
	return *effective ? ret : 0;
}


int get_vfs_caps_from_disk(const struct dentry *dentry, struct cpu_vfs_cap_data *cpu_caps)
{
	struct inode *inode = d_backing_inode(dentry);
	__u32 magic_etc;
	unsigned tocopy, i;
	int size;
	struct vfs_cap_data caps;

	memset(cpu_caps, 0, sizeof(struct cpu_vfs_cap_data));

	if (!inode || !inode->i_op->getxattr)
		return -ENODATA;

	size = inode->i_op->getxattr((struct dentry *)dentry, inode, XATTR_NAME_CAPS, &caps, XATTR_CAPS_SZ);
	if (size == -ENODATA || size == -EOPNOTSUPP)
		
		return -ENODATA;
	if (size < 0)
		return size;

	if (size < sizeof(magic_etc))
		return -EINVAL;

	cpu_caps->magic_etc = magic_etc = le32_to_cpu(caps.magic_etc);

	switch (magic_etc & VFS_CAP_REVISION_MASK) {
	case VFS_CAP_REVISION_1:
		if (size != XATTR_CAPS_SZ_1)
			return -EINVAL;
		tocopy = VFS_CAP_U32_1;
		break;
	case VFS_CAP_REVISION_2:
		if (size != XATTR_CAPS_SZ_2)
			return -EINVAL;
		tocopy = VFS_CAP_U32_2;
		break;
	default:
		return -EINVAL;
	}

	CAP_FOR_EACH_U32(i) {
		if (i >= tocopy)
			break;
		cpu_caps->permitted.cap[i] = le32_to_cpu(caps.data[i].permitted);
		cpu_caps->inheritable.cap[i] = le32_to_cpu(caps.data[i].inheritable);
	}

	cpu_caps->permitted.cap[CAP_LAST_U32] &= CAP_LAST_U32_VALID_MASK;
	cpu_caps->inheritable.cap[CAP_LAST_U32] &= CAP_LAST_U32_VALID_MASK;

	return 0;
}


static int get_file_caps(struct linux_binprm *bprm, bool *effective, bool *has_cap)
{
	int rc = 0;
	struct cpu_vfs_cap_data vcaps;

	bprm_clear_caps(bprm);

	if (!file_caps_enabled)
		return 0;

	if (bprm->file->f_path.mnt->mnt_flags & MNT_NOSUID)
		return 0;
	if (!current_in_userns(bprm->file->f_path.mnt->mnt_sb->s_user_ns))
		return 0;

	rc = get_vfs_caps_from_disk(bprm->file->f_path.dentry, &vcaps);
	if (rc < 0) {
		if (rc == -EINVAL)
			printk(KERN_NOTICE "%s: get_vfs_caps_from_disk returned %d for %s\n", __func__, rc, bprm->filename);
		else if (rc == -ENODATA)
			rc = 0;
		goto out;
	}

	rc = bprm_caps_from_vfs_caps(&vcaps, bprm, effective, has_cap);
	if (rc == -EINVAL)
		printk(KERN_NOTICE "%s: cap_from_disk returned %d for %s\n", __func__, rc, bprm->filename);

out:
	if (rc)
		bprm_clear_caps(bprm);

	return rc;
}


int cap_bprm_set_creds(struct linux_binprm *bprm)
{
	const struct cred *old = current_cred();
	struct cred *new = bprm->cred;
	bool effective, has_cap = false, is_setid;
	int ret;
	kuid_t root_uid;

	if (WARN_ON(!cap_ambient_invariant_ok(old)))
		return -EPERM;

	effective = false;
	ret = get_file_caps(bprm, &effective, &has_cap);
	if (ret < 0)
		return ret;

	root_uid = make_kuid(new->user_ns, 0);

	if (!issecure(SECURE_NOROOT)) {
		
		if (has_cap && !uid_eq(new->uid, root_uid) && uid_eq(new->euid, root_uid)) {
			warn_setuid_and_fcaps_mixed(bprm->filename);
			goto skip;
		}
		
		if (uid_eq(new->euid, root_uid) || uid_eq(new->uid, root_uid)) {
			
			new->cap_permitted = cap_combine(old->cap_bset, old->cap_inheritable);
		}
		if (uid_eq(new->euid, root_uid))
			effective = true;
	}
skip:

	
	if (!cap_issubset(new->cap_permitted, old->cap_permitted))
		bprm->per_clear |= PER_CLEAR_ON_SETID;


	
	is_setid = !uid_eq(new->euid, old->uid) || !gid_eq(new->egid, old->gid);

	if ((is_setid || !cap_issubset(new->cap_permitted, old->cap_permitted)) && bprm->unsafe & ~LSM_UNSAFE_PTRACE_CAP) {

		
		if (!capable(CAP_SETUID) || (bprm->unsafe & LSM_UNSAFE_NO_NEW_PRIVS)) {
			new->euid = new->uid;
			new->egid = new->gid;
		}
		new->cap_permitted = cap_intersect(new->cap_permitted, old->cap_permitted);
	}

	new->suid = new->fsuid = new->euid;
	new->sgid = new->fsgid = new->egid;

	
	if (has_cap || is_setid)
		cap_clear(new->cap_ambient);

	
	new->cap_permitted = cap_combine(new->cap_permitted, new->cap_ambient);

	
	if (effective)
		new->cap_effective = new->cap_permitted;
	else new->cap_effective = new->cap_ambient;

	if (WARN_ON(!cap_ambient_invariant_ok(new)))
		return -EPERM;

	bprm->cap_effective = effective;

	
	if (!cap_issubset(new->cap_effective, new->cap_ambient)) {
		if (!cap_issubset(CAP_FULL_SET, new->cap_effective) || !uid_eq(new->euid, root_uid) || !uid_eq(new->uid, root_uid) || issecure(SECURE_NOROOT)) {

			ret = audit_log_bprm_fcaps(bprm, new, old);
			if (ret < 0)
				return ret;
		}
	}

	new->securebits &= ~issecure_mask(SECURE_KEEP_CAPS);

	if (WARN_ON(!cap_ambient_invariant_ok(new)))
		return -EPERM;

	return 0;
}


int cap_bprm_secureexec(struct linux_binprm *bprm)
{
	const struct cred *cred = current_cred();
	kuid_t root_uid = make_kuid(cred->user_ns, 0);

	if (!uid_eq(cred->uid, root_uid)) {
		if (bprm->cap_effective)
			return 1;
		if (!cap_issubset(cred->cap_permitted, cred->cap_ambient))
			return 1;
	}

	return (!uid_eq(cred->euid, cred->uid) || !gid_eq(cred->egid, cred->gid));
}


int cap_inode_setxattr(struct dentry *dentry, const char *name, const void *value, size_t size, int flags)
{
	if (!strcmp(name, XATTR_NAME_CAPS)) {
		if (!capable(CAP_SETFCAP))
			return -EPERM;
		return 0;
	}

	if (!strncmp(name, XATTR_SECURITY_PREFIX, sizeof(XATTR_SECURITY_PREFIX) - 1) && !capable(CAP_SYS_ADMIN))

		return -EPERM;
	return 0;
}


int cap_inode_removexattr(struct dentry *dentry, const char *name)
{
	if (!strcmp(name, XATTR_NAME_CAPS)) {
		if (!capable(CAP_SETFCAP))
			return -EPERM;
		return 0;
	}

	if (!strncmp(name, XATTR_SECURITY_PREFIX, sizeof(XATTR_SECURITY_PREFIX) - 1) && !capable(CAP_SYS_ADMIN))

		return -EPERM;
	return 0;
}


static inline void cap_emulate_setxuid(struct cred *new, const struct cred *old)
{
	kuid_t root_uid = make_kuid(old->user_ns, 0);

	if ((uid_eq(old->uid, root_uid) || uid_eq(old->euid, root_uid) || uid_eq(old->suid, root_uid)) && (!uid_eq(new->uid, root_uid) && !uid_eq(new->euid, root_uid) && !uid_eq(new->suid, root_uid))) {




		if (!issecure(SECURE_KEEP_CAPS)) {
			cap_clear(new->cap_permitted);
			cap_clear(new->cap_effective);
		}

		
		cap_clear(new->cap_ambient);
	}
	if (uid_eq(old->euid, root_uid) && !uid_eq(new->euid, root_uid))
		cap_clear(new->cap_effective);
	if (!uid_eq(old->euid, root_uid) && uid_eq(new->euid, root_uid))
		new->cap_effective = new->cap_permitted;
}


int cap_task_fix_setuid(struct cred *new, const struct cred *old, int flags)
{
	switch (flags) {
	case LSM_SETID_RE:
	case LSM_SETID_ID:
	case LSM_SETID_RES:
		
		if (!issecure(SECURE_NO_SETUID_FIXUP))
			cap_emulate_setxuid(new, old);
		break;

	case LSM_SETID_FS:
		
		if (!issecure(SECURE_NO_SETUID_FIXUP)) {
			kuid_t root_uid = make_kuid(old->user_ns, 0);
			if (uid_eq(old->fsuid, root_uid) && !uid_eq(new->fsuid, root_uid))
				new->cap_effective = cap_drop_fs_set(new->cap_effective);

			if (!uid_eq(old->fsuid, root_uid) && uid_eq(new->fsuid, root_uid))
				new->cap_effective = cap_raise_fs_set(new->cap_effective, new->cap_permitted);

		}
		break;

	default:
		return -EINVAL;
	}

	return 0;
}


static int cap_safe_nice(struct task_struct *p)
{
	int is_subset, ret = 0;

	rcu_read_lock();
	is_subset = cap_issubset(__task_cred(p)->cap_permitted, current_cred()->cap_permitted);
	if (!is_subset && !ns_capable(__task_cred(p)->user_ns, CAP_SYS_NICE))
		ret = -EPERM;
	rcu_read_unlock();

	return ret;
}


int cap_task_setscheduler(struct task_struct *p)
{
	return cap_safe_nice(p);
}


int cap_task_setioprio(struct task_struct *p, int ioprio)
{
	return cap_safe_nice(p);
}


int cap_task_setnice(struct task_struct *p, int nice)
{
	return cap_safe_nice(p);
}


static int cap_prctl_drop(unsigned long cap)
{
	struct cred *new;

	if (!ns_capable(current_user_ns(), CAP_SETPCAP))
		return -EPERM;
	if (!cap_valid(cap))
		return -EINVAL;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;
	cap_lower(new->cap_bset, cap);
	return commit_creds(new);
}


int cap_task_prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
	const struct cred *old = current_cred();
	struct cred *new;

	switch (option) {
	case PR_CAPBSET_READ:
		if (!cap_valid(arg2))
			return -EINVAL;
		return !!cap_raised(old->cap_bset, arg2);

	case PR_CAPBSET_DROP:
		return cap_prctl_drop(arg2);

	
	case PR_SET_SECUREBITS:
		if ((((old->securebits & SECURE_ALL_LOCKS) >> 1)
		     & (old->securebits ^ arg2))			
		    || ((old->securebits & SECURE_ALL_LOCKS & ~arg2))	
		    || (arg2 & ~(SECURE_ALL_LOCKS | SECURE_ALL_BITS))	
		    || (cap_capable(current_cred(), current_cred()->user_ns, CAP_SETPCAP, SECURITY_CAP_AUDIT) != 0)

			
		    )
			
			return -EPERM;

		new = prepare_creds();
		if (!new)
			return -ENOMEM;
		new->securebits = arg2;
		return commit_creds(new);

	case PR_GET_SECUREBITS:
		return old->securebits;

	case PR_GET_KEEPCAPS:
		return !!issecure(SECURE_KEEP_CAPS);

	case PR_SET_KEEPCAPS:
		if (arg2 > 1) 
			return -EINVAL;
		if (issecure(SECURE_KEEP_CAPS_LOCKED))
			return -EPERM;

		new = prepare_creds();
		if (!new)
			return -ENOMEM;
		if (arg2)
			new->securebits |= issecure_mask(SECURE_KEEP_CAPS);
		else new->securebits &= ~issecure_mask(SECURE_KEEP_CAPS);
		return commit_creds(new);

	case PR_CAP_AMBIENT:
		if (arg2 == PR_CAP_AMBIENT_CLEAR_ALL) {
			if (arg3 | arg4 | arg5)
				return -EINVAL;

			new = prepare_creds();
			if (!new)
				return -ENOMEM;
			cap_clear(new->cap_ambient);
			return commit_creds(new);
		}

		if (((!cap_valid(arg3)) | arg4 | arg5))
			return -EINVAL;

		if (arg2 == PR_CAP_AMBIENT_IS_SET) {
			return !!cap_raised(current_cred()->cap_ambient, arg3);
		} else if (arg2 != PR_CAP_AMBIENT_RAISE && arg2 != PR_CAP_AMBIENT_LOWER) {
			return -EINVAL;
		} else {
			if (arg2 == PR_CAP_AMBIENT_RAISE && (!cap_raised(current_cred()->cap_permitted, arg3) || !cap_raised(current_cred()->cap_inheritable, arg3) || issecure(SECURE_NO_CAP_AMBIENT_RAISE)))



				return -EPERM;

			new = prepare_creds();
			if (!new)
				return -ENOMEM;
			if (arg2 == PR_CAP_AMBIENT_RAISE)
				cap_raise(new->cap_ambient, arg3);
			else cap_lower(new->cap_ambient, arg3);
			return commit_creds(new);
		}

	default:
		
		return -ENOSYS;
	}
}


int cap_vm_enough_memory(struct mm_struct *mm, long pages)
{
	int cap_sys_admin = 0;

	if (cap_capable(current_cred(), &init_user_ns, CAP_SYS_ADMIN, SECURITY_CAP_NOAUDIT) == 0)
		cap_sys_admin = 1;
	return cap_sys_admin;
}


int cap_mmap_addr(unsigned long addr)
{
	int ret = 0;

	if (addr < dac_mmap_min_addr) {
		ret = cap_capable(current_cred(), &init_user_ns, CAP_SYS_RAWIO, SECURITY_CAP_AUDIT);
		
		if (ret == 0)
			current->flags |= PF_SUPERPRIV;
	}
	return ret;
}

int cap_mmap_file(struct file *file, unsigned long reqprot, unsigned long prot, unsigned long flags)
{
	return 0;
}



struct security_hook_list capability_hooks[] = {
	LSM_HOOK_INIT(capable, cap_capable), LSM_HOOK_INIT(settime, cap_settime), LSM_HOOK_INIT(ptrace_access_check, cap_ptrace_access_check), LSM_HOOK_INIT(ptrace_traceme, cap_ptrace_traceme), LSM_HOOK_INIT(capget, cap_capget), LSM_HOOK_INIT(capset, cap_capset), LSM_HOOK_INIT(bprm_set_creds, cap_bprm_set_creds), LSM_HOOK_INIT(bprm_secureexec, cap_bprm_secureexec), LSM_HOOK_INIT(inode_need_killpriv, cap_inode_need_killpriv), LSM_HOOK_INIT(inode_killpriv, cap_inode_killpriv), LSM_HOOK_INIT(mmap_addr, cap_mmap_addr), LSM_HOOK_INIT(mmap_file, cap_mmap_file), LSM_HOOK_INIT(task_fix_setuid, cap_task_fix_setuid), LSM_HOOK_INIT(task_prctl, cap_task_prctl), LSM_HOOK_INIT(task_setscheduler, cap_task_setscheduler), LSM_HOOK_INIT(task_setioprio, cap_task_setioprio), LSM_HOOK_INIT(task_setnice, cap_task_setnice), LSM_HOOK_INIT(vm_enough_memory, cap_vm_enough_memory), };


















void __init capability_add_hooks(void)
{
	security_add_hooks(capability_hooks, ARRAY_SIZE(capability_hooks));
}


