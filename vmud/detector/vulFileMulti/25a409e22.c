






























static int __mtab_find_umount_fs(struct libmnt_context *cxt, const char *tgt, struct libmnt_fs **pfs)

{
	int rc;
	struct libmnt_ns *ns_old;
	struct libmnt_table *mtab = NULL;
	struct libmnt_fs *fs;
	char *loopdev = NULL;

	assert(cxt);
	assert(tgt);
	assert(pfs);

	*pfs = NULL;
	DBG(CXT, ul_debugobj(cxt, " search %s in mountinfo", tgt));

	
	if (mnt_context_is_nocanonicalize(cxt) && !mnt_context_mtab_writable(cxt) && *tgt == '/')
		rc = mnt_context_get_mtab_for_target(cxt, &mtab, tgt);
	else rc = mnt_context_get_mtab(cxt, &mtab);

	if (rc) {
		DBG(CXT, ul_debugobj(cxt, "umount: failed to read mtab"));
		return rc;
	}

	if (mnt_table_get_nents(mtab) == 0) {
		DBG(CXT, ul_debugobj(cxt, "umount: mtab empty"));
		return 1;
	}

	ns_old = mnt_context_switch_target_ns(cxt);
	if (!ns_old)
		return -MNT_ERR_NAMESPACE;

try_loopdev:
	fs = mnt_table_find_target(mtab, tgt, MNT_ITER_BACKWARD);
	if (!fs && mnt_context_is_swapmatch(cxt)) {
		
		fs = mnt_table_find_source(mtab, tgt, MNT_ITER_BACKWARD);

		if (fs) {
			struct libmnt_fs *fs1 = mnt_table_find_target(mtab, mnt_fs_get_target(fs), MNT_ITER_BACKWARD);

			if (!fs1) {
				DBG(CXT, ul_debugobj(cxt, "mtab is broken?!?!"));
				rc = -EINVAL;
				goto err;
			}
			if (fs != fs1) {
				
				DBG(CXT, ul_debugobj(cxt, "umount: %s: %s is mounted " "over it on the same point", tgt, mnt_fs_get_source(fs1)));


				rc = -EINVAL;
				goto err;
			}
		}
	}

	if (!fs && !loopdev && mnt_context_is_swapmatch(cxt)) {
		
		struct stat st;

		if (mnt_stat_mountpoint(tgt, &st) == 0 && S_ISREG(st.st_mode)) {
			int count;
			struct libmnt_cache *cache = mnt_context_get_cache(cxt);
			const char *bf = cache ? mnt_resolve_path(tgt, cache) : tgt;

			count = loopdev_count_by_backing_file(bf, &loopdev);
			if (count == 1) {
				DBG(CXT, ul_debugobj(cxt, "umount: %s --> %s (retry)", tgt, loopdev));
				tgt = loopdev;
				goto try_loopdev;

			} else if (count > 1)
				DBG(CXT, ul_debugobj(cxt, "umount: warning: %s is associated " "with more than one loopdev", tgt));

		}
	}

	*pfs = fs;
	free(loopdev);
	if (!mnt_context_switch_ns(cxt, ns_old))
		return -MNT_ERR_NAMESPACE;

	DBG(CXT, ul_debugobj(cxt, "umount fs: %s", fs ? mnt_fs_get_target(fs) :
							"<not found>"));
	return fs ? 0 : 1;
err:
	free(loopdev);
	if (!mnt_context_switch_ns(cxt, ns_old))
		return -MNT_ERR_NAMESPACE;
	return rc;
}


int mnt_context_find_umount_fs(struct libmnt_context *cxt, const char *tgt, struct libmnt_fs **pfs)

{
	if (pfs)
		*pfs = NULL;

	if (!cxt || !tgt || !pfs)
		return -EINVAL;

	DBG(CXT, ul_debugobj(cxt, "umount: lookup FS for '%s'", tgt));

	if (!*tgt)
		return 1; 

	
	return __mtab_find_umount_fs(cxt, tgt, pfs);
}


static int has_utab_entry(struct libmnt_context *cxt, const char *target)
{
	struct libmnt_cache *cache = NULL;
	struct libmnt_fs *fs;
	struct libmnt_iter itr;
	char *cn = NULL;
	int rc = 0;

	assert(cxt);

	if (!cxt->utab) {
		const char *path = mnt_get_utab_path();

		if (!path || is_file_empty(path))
			return 0;
		cxt->utab = mnt_new_table();
		if (!cxt->utab)
			return 0;
		cxt->utab->fmt = MNT_FMT_UTAB;
		if (mnt_table_parse_file(cxt->utab, path))
			return 0;
	}

	
	cache = mnt_context_get_cache(cxt);
	cn = mnt_resolve_path(target, cache);
	mnt_reset_iter(&itr, MNT_ITER_BACKWARD);

	while (mnt_table_next_fs(cxt->utab, &itr, &fs) == 0) {
		if (mnt_fs_streq_target(fs, cn)) {
			rc = 1;
			break;
		}
	}

	if (!cache)
		free(cn);
	return rc;
}


static int lookup_umount_fs_by_statfs(struct libmnt_context *cxt, const char *tgt)
{
	struct stat st;
	const char *type;

	assert(cxt);
	assert(cxt->fs);

	DBG(CXT, ul_debugobj(cxt, " lookup by statfs"));

	
	if (mnt_context_is_restricted(cxt)
	    || *tgt != '/' || (cxt->flags & MNT_FL_HELPER)
	    || mnt_context_mtab_writable(cxt)
	    || mnt_context_is_force(cxt)
	    || mnt_context_is_lazy(cxt)
	    || mnt_context_is_nocanonicalize(cxt)
	    || mnt_context_is_loopdel(cxt)
	    || mnt_stat_mountpoint(tgt, &st) != 0 || !S_ISDIR(st.st_mode)
	    || has_utab_entry(cxt, tgt))
		return 1; 

	type = mnt_fs_get_fstype(cxt->fs);
	if (!type) {
		struct statfs vfs;
		int fd;

		DBG(CXT, ul_debugobj(cxt, "  trying fstatfs()"));

		
		fd = open(tgt, O_PATH);
		if (fd >= 0) {
			if (fstatfs(fd, &vfs) == 0)
				type = mnt_statfs_get_fstype(&vfs);
			close(fd);
		}
		if (type) {
			int rc = mnt_fs_set_fstype(cxt->fs, type);
			if (rc)
				return rc;
		}
	}
	if (type) {
		DBG(CXT, ul_debugobj(cxt, "  umount: disabling mtab"));
		mnt_context_disable_mtab(cxt, TRUE);

		DBG(CXT, ul_debugobj(cxt, "  mountinfo unnecessary [type=%s]", type));
		return 0;
	}

	return 1; 
}


static int lookup_umount_fs_by_mountinfo(struct libmnt_context *cxt, const char *tgt)
{
	struct libmnt_fs *fs = NULL;
	int rc;

	assert(cxt);
	assert(cxt->fs);

	DBG(CXT, ul_debugobj(cxt, " lookup by mountinfo"));

	
	rc = __mtab_find_umount_fs(cxt, tgt, &fs);
	if (rc != 0)
		return rc;

	
	if (fs != cxt->fs) {
		mnt_fs_set_source(cxt->fs, NULL);
		mnt_fs_set_target(cxt->fs, NULL);

		if (!mnt_copy_fs(cxt->fs, fs)) {
			DBG(CXT, ul_debugobj(cxt, "  failed to copy FS"));
			return -errno;
		}
		DBG(CXT, ul_debugobj(cxt, "  mtab applied"));
	}

	cxt->flags |= MNT_FL_TAB_APPLIED;
	return 0;
}


static int lookup_umount_fs(struct libmnt_context *cxt)
{
	const char *tgt;
	int rc = 0;

	assert(cxt);
	assert(cxt->fs);

	DBG(CXT, ul_debugobj(cxt, "umount: lookup FS"));

	tgt = mnt_fs_get_target(cxt->fs);
	if (!tgt) {
		DBG(CXT, ul_debugobj(cxt, " undefined target"));
		return -EINVAL;
	}

	
	rc = lookup_umount_fs_by_statfs(cxt, tgt);
	if (rc <= 0)
		return rc;

	
	rc = lookup_umount_fs_by_mountinfo(cxt, tgt);
	if (rc <= 0)
		return rc;

	DBG(CXT, ul_debugobj(cxt, " cannot find '%s'", tgt));
	return 0;	
}


static int is_associated_fs(const char *devname, struct libmnt_fs *fs)
{
	uintmax_t offset = 0;
	const char *src, *optstr;
	char *val;
	size_t valsz;
	int flags = 0;

	
	if (strncmp(devname, _PATH_DEV_LOOP, sizeof(_PATH_DEV_LOOP) - 1) != 0)
		return 0;

	src = mnt_fs_get_srcpath(fs);
	if (!src)
		return 0;

	
	optstr = mnt_fs_get_user_options(fs);

	if (optstr && mnt_optstr_get_option(optstr, "offset", &val, &valsz) == 0) {
		flags |= LOOPDEV_FL_OFFSET;

		if (mnt_parse_offset(val, valsz, &offset) != 0)
			return 0;
	}

	return loopdev_is_used(devname, src, offset, 0, flags);
}

static int prepare_helper_from_options(struct libmnt_context *cxt, const char *name)
{
	char *suffix = NULL;
	const char *opts;
	size_t valsz;
	int rc;

	if (mnt_context_is_nohelpers(cxt))
		return 0;

	opts = mnt_fs_get_user_options(cxt->fs);
	if (!opts)
		return 0;

	if (mnt_optstr_get_option(opts, name, &suffix, &valsz))
		return 0;

	suffix = strndup(suffix, valsz);
	if (!suffix)
		return -ENOMEM;

	DBG(CXT, ul_debugobj(cxt, "umount: umount.%s %s requested", suffix, name));

	rc = mnt_context_prepare_helper(cxt, "umount", suffix);
	free(suffix);

	return rc;
}

static int is_fuse_usermount(struct libmnt_context *cxt, int *errsv)
{
	struct libmnt_ns *ns_old;
	const char *type = mnt_fs_get_fstype(cxt->fs);
	const char *optstr;
	char *user_id = NULL;
	size_t sz;
	uid_t uid;
	char uidstr[sizeof(stringify_value(ULONG_MAX))];

	*errsv = 0;

	if (!type)
		return 0;

	if (strcmp(type, "fuse") != 0 && strcmp(type, "fuseblk") != 0 && strncmp(type, "fuse.", 5) != 0 && strncmp(type, "fuseblk.", 8) != 0)


		return 0;

	
	optstr = mnt_fs_get_fs_options(cxt->fs);
	if (!optstr)
		return 0;

	if (mnt_optstr_get_option(optstr, "user_id", &user_id, &sz) != 0)
		return 0;

	if (sz == 0 || user_id == NULL)
		return 0;

	
	ns_old = mnt_context_switch_origin_ns(cxt);
	if (!ns_old) {
		*errsv = -MNT_ERR_NAMESPACE;
		return 0;
	}

	uid = getuid();

	if (!mnt_context_switch_ns(cxt, ns_old)) {
		*errsv = -MNT_ERR_NAMESPACE;
		return 0;
	}

	snprintf(uidstr, sizeof(uidstr), "%lu", (unsigned long) uid);
	return strncmp(user_id, uidstr, sz) == 0;
}


static int evaluate_permissions(struct libmnt_context *cxt)
{
	struct libmnt_table *fstab;
	unsigned long u_flags = 0;
	const char *tgt, *src, *optstr;
	int rc = 0, ok = 0;
	struct libmnt_fs *fs;

	assert(cxt);
	assert(cxt->fs);
	assert((cxt->flags & MNT_FL_MOUNTFLAGS_MERGED));

	if (!mnt_context_is_restricted(cxt))
		 return 0;		

	DBG(CXT, ul_debugobj(cxt, "umount: evaluating permissions"));

	if (!mnt_context_tab_applied(cxt)) {
		DBG(CXT, ul_debugobj(cxt, "cannot find %s in mtab and you are not root", mnt_fs_get_target(cxt->fs)));

		goto eperm;
	}

	if (cxt->user_mountflags & MNT_MS_UHELPER) {
		
		rc = prepare_helper_from_options(cxt, "uhelper");
		if (rc)
			return rc;
		if (cxt->helper)
			return 0;	
	}

	
	if (is_fuse_usermount(cxt, &rc)) {
		DBG(CXT, ul_debugobj(cxt, "fuse user mount, umount is allowed"));
		return 0;
	}
	if (rc)
		return rc;

	
	rc = mnt_context_get_fstab(cxt, &fstab);
	if (rc)
		return rc;

	tgt = mnt_fs_get_target(cxt->fs);
	src = mnt_fs_get_source(cxt->fs);

	if (mnt_fs_get_bindsrc(cxt->fs)) {
		src = mnt_fs_get_bindsrc(cxt->fs);
		DBG(CXT, ul_debugobj(cxt, "umount: using bind source: %s", src));
	}

	
	fs = mnt_table_find_pair(fstab, src, tgt, MNT_ITER_FORWARD);
	if (!fs) {
		
		fs = mnt_table_find_target(fstab, tgt, MNT_ITER_FORWARD);
		if (fs) {
			struct libmnt_cache *cache = mnt_context_get_cache(cxt);
			const char *sp = mnt_fs_get_srcpath(cxt->fs);		
			const char *dev = sp && cache ? mnt_resolve_path(sp, cache) : sp;

			if (!dev || !is_associated_fs(dev, fs))
				fs = NULL;
		}
		if (!fs) {
			DBG(CXT, ul_debugobj(cxt, "umount %s: mtab disagrees with fstab", tgt));

			goto eperm;
		}
	}

	
	optstr = mnt_fs_get_user_options(fs);	
	if (!optstr)
		goto eperm;

	if (mnt_optstr_get_flags(optstr, &u_flags, mnt_get_builtin_optmap(MNT_USERSPACE_MAP)))
		goto eperm;

	if (u_flags & MNT_MS_USERS) {
		DBG(CXT, ul_debugobj(cxt, "umount: promiscuous setting ('users') in fstab"));
		return 0;
	}
	
	if (u_flags & (MNT_MS_USER | MNT_MS_OWNER | MNT_MS_GROUP)) {

		char *curr_user;
		char *mtab_user = NULL;
		size_t sz;
		struct libmnt_ns *ns_old;

		DBG(CXT, ul_debugobj(cxt, "umount: checking user=<username> from mtab"));

		ns_old = mnt_context_switch_origin_ns(cxt);
		if (!ns_old)
			return -MNT_ERR_NAMESPACE;

		curr_user = mnt_get_username(getuid());

		if (!mnt_context_switch_ns(cxt, ns_old)) {
			free(curr_user);
			return -MNT_ERR_NAMESPACE;
		}
		if (!curr_user) {
			DBG(CXT, ul_debugobj(cxt, "umount %s: cannot " "convert %d to username", tgt, getuid()));
			goto eperm;
		}

		
		optstr = mnt_fs_get_user_options(cxt->fs);
		if (optstr && !mnt_optstr_get_option(optstr, "user", &mtab_user, &sz) && sz)
			ok = !strncmp(curr_user, mtab_user, sz);

		free(curr_user);
	}

	if (ok) {
		DBG(CXT, ul_debugobj(cxt, "umount %s is allowed", tgt));
		return 0;
	}
eperm:
	DBG(CXT, ul_debugobj(cxt, "umount is not allowed for you"));
	return -EPERM;
}

static int exec_helper(struct libmnt_context *cxt)
{
	char *namespace = NULL;
	struct libmnt_ns *ns_tgt = mnt_context_get_target_ns(cxt);
	int rc;
	pid_t pid;

	assert(cxt);
	assert(cxt->fs);
	assert(cxt->helper);
	assert((cxt->flags & MNT_FL_MOUNTFLAGS_MERGED));
	assert(cxt->helper_exec_status == 1);

	if (mnt_context_is_fake(cxt)) {
		DBG(CXT, ul_debugobj(cxt, "fake mode: does not execute helper"));
		cxt->helper_exec_status = rc = 0;
		return rc;
	}

	if (ns_tgt->fd != -1 && asprintf(&namespace, "/proc/%i/fd/%i", getpid(), ns_tgt->fd) == -1) {

		return -ENOMEM;
	}

	DBG_FLUSH;

	pid = fork();
	switch (pid) {
	case 0:
	{
		const char *args[12], *type;
		int i = 0;

		if (drop_permissions() != 0)
			_exit(EXIT_FAILURE);

		if (!mnt_context_switch_origin_ns(cxt))
			_exit(EXIT_FAILURE);

		type = mnt_fs_get_fstype(cxt->fs);

		args[i++] = cxt->helper;			
		args[i++] = mnt_fs_get_target(cxt->fs);		

		if (mnt_context_is_nomtab(cxt))
			args[i++] = "-n";			
		if (mnt_context_is_lazy(cxt))
			args[i++] = "-l";			
		if (mnt_context_is_force(cxt))
			args[i++] = "-f";			
		if (mnt_context_is_verbose(cxt))
			args[i++] = "-v";			
		if (mnt_context_is_rdonly_umount(cxt))
			args[i++] = "-r";			
		if (type && strchr(type, '.')
		    && !endswith(cxt->helper, type)) {
			args[i++] = "-t";			
			args[i++] = type;			
		}
		if (namespace) {
			args[i++] = "-N";			
			args[i++] = namespace;			
		}

		args[i] = NULL;					
		for (i = 0; args[i]; i++)
			DBG(CXT, ul_debugobj(cxt, "argv[%d] = \"%s\"", i, args[i]));
		DBG_FLUSH;
		execv(cxt->helper, (char * const *) args);
		_exit(EXIT_FAILURE);
	}
	default:
	{
		int st;

		if (waitpid(pid, &st, 0) == (pid_t) -1) {
			cxt->helper_status = -1;
			rc = -errno;
		} else {
			cxt->helper_status = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
			cxt->helper_exec_status = rc = 0;
		}
		DBG(CXT, ul_debugobj(cxt, "%s executed [status=%d, rc=%d%s]", cxt->helper, cxt->helper_status, rc, rc ? " waitpid failed" : ""));


		break;
	}

	case -1:
		cxt->helper_exec_status = rc = -errno;
		DBG(CXT, ul_debugobj(cxt, "fork() failed"));
		break;
	}

	free(namespace);
	return rc;
}


int mnt_context_umount_setopt(struct libmnt_context *cxt, int c, char *arg)
{
	int rc = -EINVAL;

	assert(cxt);
	assert(cxt->action == MNT_ACT_UMOUNT);

	switch(c) {
	case 'n':
		rc = mnt_context_disable_mtab(cxt, TRUE);
		break;
	case 'l':
		rc = mnt_context_enable_lazy(cxt, TRUE);
		break;
	case 'f':
		rc = mnt_context_enable_force(cxt, TRUE);
		break;
	case 'v':
		rc = mnt_context_enable_verbose(cxt, TRUE);
		break;
	case 'r':
		rc = mnt_context_enable_rdonly_umount(cxt, TRUE);
		break;
	case 't':
		if (arg)
			rc = mnt_context_set_fstype(cxt, arg);
		break;
	case 'N':
		if (arg)
			rc = mnt_context_set_target_ns(cxt, arg);
		break;
	default:
		return 1;
	}

	return rc;
}


static int umount_nofollow_support(void)
{
	int res = umount2("", UMOUNT_UNUSED);
	if (res != -1 || errno != EINVAL)
		return 0;

	res = umount2("", UMOUNT_NOFOLLOW);
	if (res != -1 || errno != ENOENT)
		return 0;

	return 1;
}

static int do_umount(struct libmnt_context *cxt)
{
	int rc = 0, flags = 0;
	const char *src, *target;
	char *tgtbuf = NULL;

	assert(cxt);
	assert(cxt->fs);
	assert((cxt->flags & MNT_FL_MOUNTFLAGS_MERGED));
	assert(cxt->syscall_status == 1);

	if (cxt->helper)
		return exec_helper(cxt);

	src = mnt_fs_get_srcpath(cxt->fs);
	target = mnt_fs_get_target(cxt->fs);

	if (!target)
		return -EINVAL;

	DBG(CXT, ul_debugobj(cxt, "do umount"));

	if (mnt_context_is_restricted(cxt) && !mnt_context_is_fake(cxt)) {
		
		if (umount_nofollow_support())
			flags |= UMOUNT_NOFOLLOW;

		rc = mnt_chdir_to_parent(target, &tgtbuf);
		if (rc)
			return rc;
		target = tgtbuf;
	}

	if (mnt_context_is_lazy(cxt))
		flags |= MNT_DETACH;

	if (mnt_context_is_force(cxt))
		flags |= MNT_FORCE;

	DBG(CXT, ul_debugobj(cxt, "umount(2) [target='%s', flags=0x%08x]%s", target, flags, mnt_context_is_fake(cxt) ? " (FAKE)" : ""));


	if (mnt_context_is_fake(cxt))
		rc = 0;
	else {
		rc = flags ? umount2(target, flags) : umount(target);
		if (rc < 0)
			cxt->syscall_status = -errno;
		free(tgtbuf);
	}

	
	if (rc < 0 && cxt->syscall_status == -EBUSY && mnt_context_is_rdonly_umount(cxt)

	    && src) {

		mnt_context_set_mflags(cxt, (cxt->mountflags | MS_REMOUNT | MS_RDONLY));
		mnt_context_enable_loopdel(cxt, FALSE);

		DBG(CXT, ul_debugobj(cxt, "umount(2) failed [errno=%d] -- trying to remount read-only", -cxt->syscall_status));


		rc = mount(src, mnt_fs_get_target(cxt->fs), NULL, MS_REMOUNT | MS_RDONLY, NULL);
		if (rc < 0) {
			cxt->syscall_status = -errno;
			DBG(CXT, ul_debugobj(cxt, "read-only re-mount(2) failed [errno=%d]", -cxt->syscall_status));


			return -cxt->syscall_status;
		}
		cxt->syscall_status = 0;
		DBG(CXT, ul_debugobj(cxt, "read-only re-mount(2) success"));
		return 0;
	}

	if (rc < 0) {
		DBG(CXT, ul_debugobj(cxt, "umount(2) failed [errno=%d]", -cxt->syscall_status));
		return -cxt->syscall_status;
	}

	cxt->syscall_status = 0;
	DBG(CXT, ul_debugobj(cxt, "umount(2) success"));
	return 0;
}


int mnt_context_prepare_umount(struct libmnt_context *cxt)
{
	int rc;
	struct libmnt_ns *ns_old;

	if (!cxt || !cxt->fs || mnt_fs_is_swaparea(cxt->fs))
		return -EINVAL;
	if (!mnt_context_get_source(cxt) && !mnt_context_get_target(cxt))
		return -EINVAL;
	if (cxt->flags & MNT_FL_PREPARED)
		return 0;

	assert(cxt->helper_exec_status == 1);
	assert(cxt->syscall_status == 1);

	free(cxt->helper);	
	cxt->helper = NULL;
	cxt->action = MNT_ACT_UMOUNT;

	ns_old = mnt_context_switch_target_ns(cxt);
	if (!ns_old)
		return -MNT_ERR_NAMESPACE;

	rc = lookup_umount_fs(cxt);
	if (!rc)
		rc = mnt_context_merge_mflags(cxt);
	if (!rc)
		rc = evaluate_permissions(cxt);

	if (!rc && !cxt->helper) {

		if (cxt->user_mountflags & MNT_MS_HELPER)
			
			rc = prepare_helper_from_options(cxt, "helper");

		if (!rc && !cxt->helper)
			
			rc = mnt_context_prepare_helper(cxt, "umount", NULL);
	}

	if (!rc && (cxt->user_mountflags & MNT_MS_LOOP))
		
		mnt_context_enable_loopdel(cxt, TRUE);

	if (!rc && mnt_context_is_loopdel(cxt) && cxt->fs) {
		const char *src = mnt_fs_get_srcpath(cxt->fs);

		if (src && (!is_loopdev(src) || loopdev_is_autoclear(src)))
			mnt_context_enable_loopdel(cxt, FALSE);
	}

	if (rc) {
		DBG(CXT, ul_debugobj(cxt, "umount: preparing failed"));
		return rc;
	}
	cxt->flags |= MNT_FL_PREPARED;

	if (!mnt_context_switch_ns(cxt, ns_old))
		return -MNT_ERR_NAMESPACE;

	return rc;
}


int mnt_context_do_umount(struct libmnt_context *cxt)
{
	int rc;
	struct libmnt_ns *ns_old;

	assert(cxt);
	assert(cxt->fs);
	assert(cxt->helper_exec_status == 1);
	assert(cxt->syscall_status == 1);
	assert((cxt->flags & MNT_FL_PREPARED));
	assert((cxt->action == MNT_ACT_UMOUNT));
	assert((cxt->flags & MNT_FL_MOUNTFLAGS_MERGED));

	ns_old = mnt_context_switch_target_ns(cxt);
	if (!ns_old)
		return -MNT_ERR_NAMESPACE;

	rc = do_umount(cxt);
	if (rc)
		goto end;

	if (mnt_context_get_status(cxt) && !mnt_context_is_fake(cxt)) {
		
		if (mnt_context_is_loopdel(cxt)
		    && !(cxt->mountflags & MS_REMOUNT))
			rc = mnt_context_delete_loopdev(cxt);

		if (!mnt_context_is_nomtab(cxt)
		    && mnt_context_get_status(cxt)
		    && !cxt->helper && mnt_context_is_rdonly_umount(cxt)
		    && (cxt->mountflags & MS_REMOUNT)) {

			
			if (!rc && cxt->update && mnt_context_mtab_writable(cxt))
				rc = mnt_update_set_fs(cxt->update, cxt->mountflags, NULL, cxt->fs);
		}
	}
end:
	if (!mnt_context_switch_ns(cxt, ns_old))
		return -MNT_ERR_NAMESPACE;

	return rc;
}


int mnt_context_finalize_umount(struct libmnt_context *cxt)
{
	int rc;

	assert(cxt);
	assert(cxt->fs);
	assert((cxt->flags & MNT_FL_PREPARED));
	assert((cxt->flags & MNT_FL_MOUNTFLAGS_MERGED));

	rc = mnt_context_prepare_update(cxt);
	if (!rc)
		rc = mnt_context_update_tabs(cxt);
	return rc;
}



int mnt_context_umount(struct libmnt_context *cxt)
{
	int rc;
	struct libmnt_ns *ns_old;

	assert(cxt);
	assert(cxt->fs);
	assert(cxt->helper_exec_status == 1);
	assert(cxt->syscall_status == 1);

	DBG(CXT, ul_debugobj(cxt, "umount: %s", mnt_context_get_target(cxt)));

	ns_old = mnt_context_switch_target_ns(cxt);
	if (!ns_old)
		return -MNT_ERR_NAMESPACE;

	rc = mnt_context_prepare_umount(cxt);
	if (!rc)
		rc = mnt_context_prepare_update(cxt);
	if (!rc)
		rc = mnt_context_do_umount(cxt);
	if (!rc)
		rc = mnt_context_update_tabs(cxt);

	if (!mnt_context_switch_ns(cxt, ns_old))
		return -MNT_ERR_NAMESPACE;

	return rc;
}



int mnt_context_next_umount(struct libmnt_context *cxt, struct libmnt_iter *itr, struct libmnt_fs **fs, int *mntrc, int *ignored)



{
	struct libmnt_table *mtab;
	const char *tgt;
	int rc;

	if (ignored)
		*ignored = 0;
	if (mntrc)
		*mntrc = 0;

	if (!cxt || !fs || !itr)
		return -EINVAL;

	rc = mnt_context_get_mtab(cxt, &mtab);
	cxt->mtab = NULL;		
	mnt_reset_context(cxt);

	if (rc)
		return rc;

	cxt->mtab = mtab;

	do {
		rc = mnt_table_next_fs(mtab, itr, fs);
		if (rc != 0)
			return rc;	

		tgt = mnt_fs_get_target(*fs);
	} while (!tgt);

	DBG(CXT, ul_debugobj(cxt, "next-umount: trying %s [fstype: %s, t-pattern: %s, options: %s, O-pattern: %s]", tgt, mnt_fs_get_fstype(*fs), cxt->fstype_pattern, mnt_fs_get_options(*fs), cxt->optstr_pattern));

	
	if ((cxt->fstype_pattern && !mnt_fs_match_fstype(*fs, cxt->fstype_pattern)) ||   (cxt->optstr_pattern && !mnt_fs_match_options(*fs, cxt->optstr_pattern))) {




		if (ignored)
			*ignored = 1;

		DBG(CXT, ul_debugobj(cxt, "next-umount: not-match"));
		return 0;
	}

	rc = mnt_context_set_fs(cxt, *fs);
	if (rc)
		return rc;
	rc = mnt_context_umount(cxt);
	if (mntrc)
		*mntrc = rc;
	return 0;
}


int mnt_context_get_umount_excode( struct libmnt_context *cxt, int rc, char *buf, size_t bufsz)



{
	if (mnt_context_helper_executed(cxt))
		
		return mnt_context_get_helper_status(cxt);

	if (rc == 0 && mnt_context_get_status(cxt) == 1)
		
		return MNT_EX_SUCCESS;

	if (!mnt_context_syscall_called(cxt)) {
		
		if (rc == -EPERM && !mnt_context_tab_applied(cxt)) {
			
			if (buf)
				snprintf(buf, bufsz, _("not mounted"));
			return MNT_EX_USAGE;
		}

		if (rc == -MNT_ERR_LOCK) {
			if (buf)
				snprintf(buf, bufsz, _("locking failed"));
			return MNT_EX_FILEIO;
		}

		if (rc == -MNT_ERR_NAMESPACE) {
			if (buf)
				snprintf(buf, bufsz, _("failed to switch namespace"));
			return MNT_EX_SYSERR;
		}
		return mnt_context_get_generic_excode(rc, buf, bufsz, _("umount failed: %m"));

	} if (mnt_context_get_syscall_errno(cxt) == 0) {
		
		if (rc == -MNT_ERR_LOCK) {
			if (buf)
				snprintf(buf, bufsz, _("filesystem was unmounted, but failed to update userspace mount table"));
			return MNT_EX_FILEIO;
		}

		if (rc == -MNT_ERR_NAMESPACE) {
			if (buf)
				snprintf(buf, bufsz, _("filesystem was unmounted, but failed to switch namespace back"));
			return MNT_EX_SYSERR;

		}

		if (rc < 0)
			return mnt_context_get_generic_excode(rc, buf, bufsz, _("filesystem was unmounted, but any subsequent operation failed: %m"));

		return MNT_EX_SOFTWARE;	
	}

	
	if (buf) {
		int syserr = mnt_context_get_syscall_errno(cxt);

		switch (syserr) {
		case ENXIO:
			snprintf(buf, bufsz, _("invalid block device"));	
			break;
		case EINVAL:
			snprintf(buf, bufsz, _("not mounted"));
			break;
		case EIO:
			snprintf(buf, bufsz, _("can't write superblock"));
			break;
		case EBUSY:
			snprintf(buf, bufsz, _("target is busy"));
			break;
		case ENOENT:
			snprintf(buf, bufsz, _("no mount point specified"));
			break;
		case EPERM:
			snprintf(buf, bufsz, _("must be superuser to unmount"));
			break;
		case EACCES:
			snprintf(buf, bufsz, _("block devices are not permitted on filesystem"));
			break;
		default:
			return mnt_context_get_generic_excode(syserr, buf, bufsz,_("umount(2) system call failed: %m"));
		}
	}
	return MNT_EX_FAIL;
}
