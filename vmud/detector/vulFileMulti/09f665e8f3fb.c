


__FBSDID("$FreeBSD$");
















































static fo_rdwr_t	vn_read;
static fo_rdwr_t	vn_write;
static fo_rdwr_t	vn_io_fault;
static fo_truncate_t	vn_truncate;
static fo_ioctl_t	vn_ioctl;
static fo_poll_t	vn_poll;
static fo_kqfilter_t	vn_kqfilter;
static fo_stat_t	vn_statfile;
static fo_close_t	vn_closefile;
static fo_mmap_t	vn_mmap;

struct 	fileops vnops = {
	.fo_read = vn_io_fault, .fo_write = vn_io_fault, .fo_truncate = vn_truncate, .fo_ioctl = vn_ioctl, .fo_poll = vn_poll, .fo_kqfilter = vn_kqfilter, .fo_stat = vn_statfile, .fo_close = vn_closefile, .fo_chmod = vn_chmod, .fo_chown = vn_chown, .fo_sendfile = vn_sendfile, .fo_seek = vn_seek, .fo_fill_kinfo = vn_fill_kinfo, .fo_mmap = vn_mmap, .fo_flags = DFLAG_PASSABLE | DFLAG_SEEKABLE };















static const int io_hold_cnt = 16;
static int vn_io_fault_enable = 1;
SYSCTL_INT(_debug, OID_AUTO, vn_io_fault_enable, CTLFLAG_RW, &vn_io_fault_enable, 0, "Enable vn_io_fault lock avoidance");
static int vn_io_fault_prefault = 0;
SYSCTL_INT(_debug, OID_AUTO, vn_io_fault_prefault, CTLFLAG_RW, &vn_io_fault_prefault, 0, "Enable vn_io_fault prefaulting");
static u_long vn_io_faults_cnt;
SYSCTL_ULONG(_debug, OID_AUTO, vn_io_faults, CTLFLAG_RD, &vn_io_faults_cnt, 0, "Count of vn_io_fault lock avoidance triggers");


static bool do_vn_io_fault(struct vnode *vp, struct uio *uio)
{
	struct mount *mp;

	return (uio->uio_segflg == UIO_USERSPACE && vp->v_type == VREG && (mp = vp->v_mount) != NULL && (mp->mnt_kern_flag & MNTK_NO_IOPF) != 0 && vn_io_fault_enable);

}


struct vn_io_fault_args {
	enum {
		VN_IO_FAULT_FOP, VN_IO_FAULT_VOP } kind;

	struct ucred *cred;
	int flags;
	union {
		struct fop_args_tag {
			struct file *fp;
			fo_rdwr_t *doio;
		} fop_args;
		struct vop_args_tag {
			struct vnode *vp;
		} vop_args;
	} args;
};

static int vn_io_fault1(struct vnode *vp, struct uio *uio, struct vn_io_fault_args *args, struct thread *td);

int vn_open(struct nameidata *ndp, int *flagp, int cmode, struct file *fp)
{
	struct thread *td = ndp->ni_cnd.cn_thread;

	return (vn_open_cred(ndp, flagp, cmode, 0, td->td_ucred, fp));
}


int vn_open_cred(struct nameidata *ndp, int *flagp, int cmode, u_int vn_open_flags, struct ucred *cred, struct file *fp)

{
	struct vnode *vp;
	struct mount *mp;
	struct thread *td = ndp->ni_cnd.cn_thread;
	struct vattr vat;
	struct vattr *vap = &vat;
	int fmode, error;

restart:
	fmode = *flagp;
	if ((fmode & (O_CREAT | O_EXCL | O_DIRECTORY)) == (O_CREAT | O_EXCL | O_DIRECTORY))
		return (EINVAL);
	else if ((fmode & (O_CREAT | O_DIRECTORY)) == O_CREAT) {
		ndp->ni_cnd.cn_nameiop = CREATE;
		
		ndp->ni_cnd.cn_flags = ISOPEN | LOCKPARENT | LOCKLEAF | NOCACHE;
		if ((fmode & O_EXCL) == 0 && (fmode & O_NOFOLLOW) == 0)
			ndp->ni_cnd.cn_flags |= FOLLOW;
		if (!(vn_open_flags & VN_OPEN_NOAUDIT))
			ndp->ni_cnd.cn_flags |= AUDITVNODE1;
		if (vn_open_flags & VN_OPEN_NOCAPCHECK)
			ndp->ni_cnd.cn_flags |= NOCAPCHECK;
		bwillwrite();
		if ((error = namei(ndp)) != 0)
			return (error);
		if (ndp->ni_vp == NULL) {
			VATTR_NULL(vap);
			vap->va_type = VREG;
			vap->va_mode = cmode;
			if (fmode & O_EXCL)
				vap->va_vaflags |= VA_EXCLUSIVE;
			if (vn_start_write(ndp->ni_dvp, &mp, V_NOWAIT) != 0) {
				NDFREE(ndp, NDF_ONLY_PNBUF);
				vput(ndp->ni_dvp);
				if ((error = vn_start_write(NULL, &mp, V_XSLEEP | PCATCH)) != 0)
					return (error);
				goto restart;
			}
			if ((vn_open_flags & VN_OPEN_NAMECACHE) != 0)
				ndp->ni_cnd.cn_flags |= MAKEENTRY;

			error = mac_vnode_check_create(cred, ndp->ni_dvp, &ndp->ni_cnd, vap);
			if (error == 0)

				error = VOP_CREATE(ndp->ni_dvp, &ndp->ni_vp, &ndp->ni_cnd, vap);
			vput(ndp->ni_dvp);
			vn_finished_write(mp);
			if (error) {
				NDFREE(ndp, NDF_ONLY_PNBUF);
				return (error);
			}
			fmode &= ~O_TRUNC;
			vp = ndp->ni_vp;
		} else {
			if (ndp->ni_dvp == ndp->ni_vp)
				vrele(ndp->ni_dvp);
			else vput(ndp->ni_dvp);
			ndp->ni_dvp = NULL;
			vp = ndp->ni_vp;
			if (fmode & O_EXCL) {
				error = EEXIST;
				goto bad;
			}
			fmode &= ~O_CREAT;
		}
	} else {
		ndp->ni_cnd.cn_nameiop = LOOKUP;
		ndp->ni_cnd.cn_flags = ISOPEN | ((fmode & O_NOFOLLOW) ? NOFOLLOW : FOLLOW) | LOCKLEAF;
		if (!(fmode & FWRITE))
			ndp->ni_cnd.cn_flags |= LOCKSHARED;
		if (!(vn_open_flags & VN_OPEN_NOAUDIT))
			ndp->ni_cnd.cn_flags |= AUDITVNODE1;
		if (vn_open_flags & VN_OPEN_NOCAPCHECK)
			ndp->ni_cnd.cn_flags |= NOCAPCHECK;
		if ((error = namei(ndp)) != 0)
			return (error);
		vp = ndp->ni_vp;
	}
	error = vn_open_vnode(vp, fmode, cred, td, fp);
	if (error)
		goto bad;
	*flagp = fmode;
	return (0);
bad:
	NDFREE(ndp, NDF_ONLY_PNBUF);
	vput(vp);
	*flagp = fmode;
	ndp->ni_vp = NULL;
	return (error);
}


int vn_open_vnode(struct vnode *vp, int fmode, struct ucred *cred, struct thread *td, struct file *fp)

{
	accmode_t accmode;
	struct flock lf;
	int error, lock_flags, type;

	if (vp->v_type == VLNK)
		return (EMLINK);
	if (vp->v_type == VSOCK)
		return (EOPNOTSUPP);
	if (vp->v_type != VDIR && fmode & O_DIRECTORY)
		return (ENOTDIR);
	accmode = 0;
	if (fmode & (FWRITE | O_TRUNC)) {
		if (vp->v_type == VDIR)
			return (EISDIR);
		accmode |= VWRITE;
	}
	if (fmode & FREAD)
		accmode |= VREAD;
	if (fmode & FEXEC)
		accmode |= VEXEC;
	if ((fmode & O_APPEND) && (fmode & FWRITE))
		accmode |= VAPPEND;

	if (fmode & O_CREAT)
		accmode |= VCREAT;
	if (fmode & O_VERIFY)
		accmode |= VVERIFY;
	error = mac_vnode_check_open(cred, vp, accmode);
	if (error)
		return (error);

	accmode &= ~(VCREAT | VVERIFY);

	if ((fmode & O_CREAT) == 0) {
		if (accmode & VWRITE) {
			error = vn_writechk(vp);
			if (error)
				return (error);
		}
		if (accmode) {
		        error = VOP_ACCESS(vp, accmode, cred, td);
			if (error)
				return (error);
		}
	}
	if (vp->v_type == VFIFO && VOP_ISLOCKED(vp) != LK_EXCLUSIVE)
		vn_lock(vp, LK_UPGRADE | LK_RETRY);
	if ((error = VOP_OPEN(vp, fmode, cred, td, fp)) != 0)
		return (error);

	while ((fmode & (O_EXLOCK | O_SHLOCK)) != 0) {
		KASSERT(fp != NULL, ("open with flock requires fp"));
		if (fp->f_type != DTYPE_NONE && fp->f_type != DTYPE_VNODE) {
			error = EOPNOTSUPP;
			break;
		}
		lock_flags = VOP_ISLOCKED(vp);
		VOP_UNLOCK(vp, 0);
		lf.l_whence = SEEK_SET;
		lf.l_start = 0;
		lf.l_len = 0;
		if (fmode & O_EXLOCK)
			lf.l_type = F_WRLCK;
		else lf.l_type = F_RDLCK;
		type = F_FLOCK;
		if ((fmode & FNONBLOCK) == 0)
			type |= F_WAIT;
		error = VOP_ADVLOCK(vp, (caddr_t)fp, F_SETLK, &lf, type);
		if (error == 0)
			fp->f_flag |= FHASLOCK;
		vn_lock(vp, lock_flags | LK_RETRY);
		if (error != 0)
			break;
		if ((vp->v_iflag & VI_DOOMED) != 0) {
			error = ENOENT;
			break;
		}

		
		if ((accmode & VWRITE) != 0)
			error = vn_writechk(vp);
		break;
	}

	if (error != 0) {
		fp->f_flag |= FOPENFAILED;
		fp->f_vnode = vp;
		if (fp->f_ops == &badfileops) {
			fp->f_type = DTYPE_VNODE;
			fp->f_ops = &vnops;
		}
		vref(vp);
	} else if  ((fmode & FWRITE) != 0) {
		VOP_ADD_WRITECOUNT(vp, 1);
		CTR3(KTR_VFS, "%s: vp %p v_writecount increased to %d", __func__, vp, vp->v_writecount);
	}
	ASSERT_VOP_LOCKED(vp, "vn_open_vnode");
	return (error);
}


int vn_writechk(struct vnode *vp)
{

	ASSERT_VOP_LOCKED(vp, "vn_writechk");
	
	if (VOP_IS_TEXT(vp))
		return (ETXTBSY);

	return (0);
}


static int vn_close1(struct vnode *vp, int flags, struct ucred *file_cred, struct thread *td, bool keep_ref)

{
	struct mount *mp;
	int error, lock_flags;

	if (vp->v_type != VFIFO && (flags & FWRITE) == 0 && MNT_EXTENDED_SHARED(vp->v_mount))
		lock_flags = LK_SHARED;
	else lock_flags = LK_EXCLUSIVE;

	vn_start_write(vp, &mp, V_WAIT);
	vn_lock(vp, lock_flags | LK_RETRY);
	AUDIT_ARG_VNODE1(vp);
	if ((flags & (FWRITE | FOPENFAILED)) == FWRITE) {
		VNASSERT(vp->v_writecount > 0, vp,  ("vn_close: negative writecount"));
		VOP_ADD_WRITECOUNT(vp, -1);
		CTR3(KTR_VFS, "%s: vp %p v_writecount decreased to %d", __func__, vp, vp->v_writecount);
	}
	error = VOP_CLOSE(vp, flags, file_cred, td);
	if (keep_ref)
		VOP_UNLOCK(vp, 0);
	else vput(vp);
	vn_finished_write(mp);
	return (error);
}

int vn_close(struct vnode *vp, int flags, struct ucred *file_cred, struct thread *td)

{

	return (vn_close1(vp, flags, file_cred, td, false));
}


static int sequential_heuristic(struct uio *uio, struct file *fp)
{

	ASSERT_VOP_LOCKED(fp->f_vnode, __func__);
	if (fp->f_flag & FRDAHEAD)
		return (fp->f_seqcount << IO_SEQSHIFT);

	
	if ((uio->uio_offset == 0 && fp->f_seqcount > 0) || uio->uio_offset == fp->f_nextoff) {
		
		fp->f_seqcount += howmany(uio->uio_resid, 16384);
		if (fp->f_seqcount > IO_SEQMAX)
			fp->f_seqcount = IO_SEQMAX;
		return (fp->f_seqcount << IO_SEQSHIFT);
	}

	
	if (fp->f_seqcount > 1)
		fp->f_seqcount = 1;
	else fp->f_seqcount = 0;
	return (0);
}


int vn_rdwr(enum uio_rw rw, struct vnode *vp, void *base, int len, off_t offset, enum uio_seg segflg, int ioflg, struct ucred *active_cred, struct ucred *file_cred, ssize_t *aresid, struct thread *td)


{
	struct uio auio;
	struct iovec aiov;
	struct mount *mp;
	struct ucred *cred;
	void *rl_cookie;
	struct vn_io_fault_args args;
	int error, lock_flags;

	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	aiov.iov_base = base;
	aiov.iov_len = len;
	auio.uio_resid = len;
	auio.uio_offset = offset;
	auio.uio_segflg = segflg;
	auio.uio_rw = rw;
	auio.uio_td = td;
	error = 0;

	if ((ioflg & IO_NODELOCKED) == 0) {
		if ((ioflg & IO_RANGELOCKED) == 0) {
			if (rw == UIO_READ) {
				rl_cookie = vn_rangelock_rlock(vp, offset, offset + len);
			} else {
				rl_cookie = vn_rangelock_wlock(vp, offset, offset + len);
			}
		} else rl_cookie = NULL;
		mp = NULL;
		if (rw == UIO_WRITE) { 
			if (vp->v_type != VCHR && (error = vn_start_write(vp, &mp, V_WAIT | PCATCH))
			    != 0)
				goto out;
			if (MNT_SHARED_WRITES(mp) || ((mp == NULL) && MNT_SHARED_WRITES(vp->v_mount)))
				lock_flags = LK_SHARED;
			else lock_flags = LK_EXCLUSIVE;
		} else lock_flags = LK_SHARED;
		vn_lock(vp, lock_flags | LK_RETRY);
	} else rl_cookie = NULL;

	ASSERT_VOP_LOCKED(vp, "IO_NODELOCKED with no vp lock held");

	if ((ioflg & IO_NOMACCHECK) == 0) {
		if (rw == UIO_READ)
			error = mac_vnode_check_read(active_cred, file_cred, vp);
		else error = mac_vnode_check_write(active_cred, file_cred, vp);

	}

	if (error == 0) {
		if (file_cred != NULL)
			cred = file_cred;
		else cred = active_cred;
		if (do_vn_io_fault(vp, &auio)) {
			args.kind = VN_IO_FAULT_VOP;
			args.cred = cred;
			args.flags = ioflg;
			args.args.vop_args.vp = vp;
			error = vn_io_fault1(vp, &auio, &args, td);
		} else if (rw == UIO_READ) {
			error = VOP_READ(vp, &auio, ioflg, cred);
		} else  {
			error = VOP_WRITE(vp, &auio, ioflg, cred);
		}
	}
	if (aresid)
		*aresid = auio.uio_resid;
	else if (auio.uio_resid && error == 0)
			error = EIO;
	if ((ioflg & IO_NODELOCKED) == 0) {
		VOP_UNLOCK(vp, 0);
		if (mp != NULL)
			vn_finished_write(mp);
	}
 out:
	if (rl_cookie != NULL)
		vn_rangelock_unlock(vp, rl_cookie);
	return (error);
}


int vn_rdwr_inchunks(enum uio_rw rw, struct vnode *vp, void *base, size_t len, off_t offset, enum uio_seg segflg, int ioflg, struct ucred *active_cred, struct ucred *file_cred, size_t *aresid, struct thread *td)


{
	int error = 0;
	ssize_t iaresid;

	do {
		int chunk;

		
		chunk = MAXBSIZE - (uoff_t)offset % MAXBSIZE;

		if (chunk > len)
			chunk = len;
		if (rw != UIO_READ && vp->v_type == VREG)
			bwillwrite();
		iaresid = 0;
		error = vn_rdwr(rw, vp, base, chunk, offset, segflg, ioflg, active_cred, file_cred, &iaresid, td);
		len -= chunk;	
		if (error)
			break;
		offset += chunk;
		base = (char *)base + chunk;
		kern_yield(PRI_USER);
	} while (len);
	if (aresid)
		*aresid = len + iaresid;
	return (error);
}

off_t foffset_lock(struct file *fp, int flags)
{
	struct mtx *mtxp;
	off_t res;

	KASSERT((flags & FOF_OFFSET) == 0, ("FOF_OFFSET passed"));


	
	if ((flags & FOF_NOLOCK) != 0)
		return (fp->f_offset);


	
	mtxp = mtx_pool_find(mtxpool_sleep, fp);
	mtx_lock(mtxp);
	if ((flags & FOF_NOLOCK) == 0) {
		while (fp->f_vnread_flags & FOFFSET_LOCKED) {
			fp->f_vnread_flags |= FOFFSET_LOCK_WAITING;
			msleep(&fp->f_vnread_flags, mtxp, PUSER -1, "vofflock", 0);
		}
		fp->f_vnread_flags |= FOFFSET_LOCKED;
	}
	res = fp->f_offset;
	mtx_unlock(mtxp);
	return (res);
}

void foffset_unlock(struct file *fp, off_t val, int flags)
{
	struct mtx *mtxp;

	KASSERT((flags & FOF_OFFSET) == 0, ("FOF_OFFSET passed"));


	if ((flags & FOF_NOLOCK) != 0) {
		if ((flags & FOF_NOUPDATE) == 0)
			fp->f_offset = val;
		if ((flags & FOF_NEXTOFF) != 0)
			fp->f_nextoff = val;
		return;
	}


	mtxp = mtx_pool_find(mtxpool_sleep, fp);
	mtx_lock(mtxp);
	if ((flags & FOF_NOUPDATE) == 0)
		fp->f_offset = val;
	if ((flags & FOF_NEXTOFF) != 0)
		fp->f_nextoff = val;
	if ((flags & FOF_NOLOCK) == 0) {
		KASSERT((fp->f_vnread_flags & FOFFSET_LOCKED) != 0, ("Lost FOFFSET_LOCKED"));
		if (fp->f_vnread_flags & FOFFSET_LOCK_WAITING)
			wakeup(&fp->f_vnread_flags);
		fp->f_vnread_flags = 0;
	}
	mtx_unlock(mtxp);
}

void foffset_lock_uio(struct file *fp, struct uio *uio, int flags)
{

	if ((flags & FOF_OFFSET) == 0)
		uio->uio_offset = foffset_lock(fp, flags);
}

void foffset_unlock_uio(struct file *fp, struct uio *uio, int flags)
{

	if ((flags & FOF_OFFSET) == 0)
		foffset_unlock(fp, uio->uio_offset, flags);
}

static int get_advice(struct file *fp, struct uio *uio)
{
	struct mtx *mtxp;
	int ret;

	ret = POSIX_FADV_NORMAL;
	if (fp->f_advice == NULL || fp->f_vnode->v_type != VREG)
		return (ret);

	mtxp = mtx_pool_find(mtxpool_sleep, fp);
	mtx_lock(mtxp);
	if (fp->f_advice != NULL && uio->uio_offset >= fp->f_advice->fa_start && uio->uio_offset + uio->uio_resid <= fp->f_advice->fa_end)

		ret = fp->f_advice->fa_advice;
	mtx_unlock(mtxp);
	return (ret);
}


static int vn_read(struct file *fp, struct uio *uio, struct ucred *active_cred, int flags, struct thread *td)

{
	struct vnode *vp;
	off_t orig_offset;
	int error, ioflag;
	int advice;

	KASSERT(uio->uio_td == td, ("uio_td %p is not td %p", uio->uio_td, td));
	KASSERT(flags & FOF_OFFSET, ("No FOF_OFFSET"));
	vp = fp->f_vnode;
	ioflag = 0;
	if (fp->f_flag & FNONBLOCK)
		ioflag |= IO_NDELAY;
	if (fp->f_flag & O_DIRECT)
		ioflag |= IO_DIRECT;
	advice = get_advice(fp, uio);
	vn_lock(vp, LK_SHARED | LK_RETRY);

	switch (advice) {
	case POSIX_FADV_NORMAL:
	case POSIX_FADV_SEQUENTIAL:
	case POSIX_FADV_NOREUSE:
		ioflag |= sequential_heuristic(uio, fp);
		break;
	case POSIX_FADV_RANDOM:
		
		break;
	}
	orig_offset = uio->uio_offset;


	error = mac_vnode_check_read(active_cred, fp->f_cred, vp);
	if (error == 0)

		error = VOP_READ(vp, uio, ioflag, fp->f_cred);
	fp->f_nextoff = uio->uio_offset;
	VOP_UNLOCK(vp, 0);
	if (error == 0 && advice == POSIX_FADV_NOREUSE && orig_offset != uio->uio_offset)
		
		error = VOP_ADVISE(vp, orig_offset, uio->uio_offset - 1, POSIX_FADV_DONTNEED);
	return (error);
}


static int vn_write(struct file *fp, struct uio *uio, struct ucred *active_cred, int flags, struct thread *td)

{
	struct vnode *vp;
	struct mount *mp;
	off_t orig_offset;
	int error, ioflag, lock_flags;
	int advice;

	KASSERT(uio->uio_td == td, ("uio_td %p is not td %p", uio->uio_td, td));
	KASSERT(flags & FOF_OFFSET, ("No FOF_OFFSET"));
	vp = fp->f_vnode;
	if (vp->v_type == VREG)
		bwillwrite();
	ioflag = IO_UNIT;
	if (vp->v_type == VREG && (fp->f_flag & O_APPEND))
		ioflag |= IO_APPEND;
	if (fp->f_flag & FNONBLOCK)
		ioflag |= IO_NDELAY;
	if (fp->f_flag & O_DIRECT)
		ioflag |= IO_DIRECT;
	if ((fp->f_flag & O_FSYNC) || (vp->v_mount && (vp->v_mount->mnt_flag & MNT_SYNCHRONOUS)))
		ioflag |= IO_SYNC;
	mp = NULL;
	if (vp->v_type != VCHR && (error = vn_start_write(vp, &mp, V_WAIT | PCATCH)) != 0)
		goto unlock;

	advice = get_advice(fp, uio);

	if (MNT_SHARED_WRITES(mp) || (mp == NULL && MNT_SHARED_WRITES(vp->v_mount))) {
		lock_flags = LK_SHARED;
	} else {
		lock_flags = LK_EXCLUSIVE;
	}

	vn_lock(vp, lock_flags | LK_RETRY);
	switch (advice) {
	case POSIX_FADV_NORMAL:
	case POSIX_FADV_SEQUENTIAL:
	case POSIX_FADV_NOREUSE:
		ioflag |= sequential_heuristic(uio, fp);
		break;
	case POSIX_FADV_RANDOM:
		
		break;
	}
	orig_offset = uio->uio_offset;


	error = mac_vnode_check_write(active_cred, fp->f_cred, vp);
	if (error == 0)

		error = VOP_WRITE(vp, uio, ioflag, fp->f_cred);
	fp->f_nextoff = uio->uio_offset;
	VOP_UNLOCK(vp, 0);
	if (vp->v_type != VCHR)
		vn_finished_write(mp);
	if (error == 0 && advice == POSIX_FADV_NOREUSE && orig_offset != uio->uio_offset)
		
		error = VOP_ADVISE(vp, orig_offset, uio->uio_offset - 1, POSIX_FADV_DONTNEED);
unlock:
	return (error);
}




static int vn_io_fault_doio(struct vn_io_fault_args *args, struct uio *uio, struct thread *td)

{
	int error, save;

	error = 0;
	save = vm_fault_disable_pagefaults();
	switch (args->kind) {
	case VN_IO_FAULT_FOP:
		error = (args->args.fop_args.doio)(args->args.fop_args.fp, uio, args->cred, args->flags, td);
		break;
	case VN_IO_FAULT_VOP:
		if (uio->uio_rw == UIO_READ) {
			error = VOP_READ(args->args.vop_args.vp, uio, args->flags, args->cred);
		} else if (uio->uio_rw == UIO_WRITE) {
			error = VOP_WRITE(args->args.vop_args.vp, uio, args->flags, args->cred);
		}
		break;
	default:
		panic("vn_io_fault_doio: unknown kind of io %d %d", args->kind, uio->uio_rw);
	}
	vm_fault_enable_pagefaults(save);
	return (error);
}

static int vn_io_fault_touch(char *base, const struct uio *uio)
{
	int r;

	r = fubyte(base);
	if (r == -1 || (uio->uio_rw == UIO_READ && subyte(base, r) == -1))
		return (EFAULT);
	return (0);
}

static int vn_io_fault_prefault_user(const struct uio *uio)
{
	char *base;
	const struct iovec *iov;
	size_t len;
	ssize_t resid;
	int error, i;

	KASSERT(uio->uio_segflg == UIO_USERSPACE, ("vn_io_fault_prefault userspace"));

	error = i = 0;
	iov = uio->uio_iov;
	resid = uio->uio_resid;
	base = iov->iov_base;
	len = iov->iov_len;
	while (resid > 0) {
		error = vn_io_fault_touch(base, uio);
		if (error != 0)
			break;
		if (len < PAGE_SIZE) {
			if (len != 0) {
				error = vn_io_fault_touch(base + len - 1, uio);
				if (error != 0)
					break;
				resid -= len;
			}
			if (++i >= uio->uio_iovcnt)
				break;
			iov = uio->uio_iov + i;
			base = iov->iov_base;
			len = iov->iov_len;
		} else {
			len -= PAGE_SIZE;
			base += PAGE_SIZE;
			resid -= PAGE_SIZE;
		}
	}
	return (error);
}


static int vn_io_fault1(struct vnode *vp, struct uio *uio, struct vn_io_fault_args *args, struct thread *td)

{
	vm_page_t ma[io_hold_cnt + 2];
	struct uio *uio_clone, short_uio;
	struct iovec short_iovec[1];
	vm_page_t *prev_td_ma;
	vm_prot_t prot;
	vm_offset_t addr, end;
	size_t len, resid;
	ssize_t adv;
	int error, cnt, saveheld, prev_td_ma_cnt;

	if (vn_io_fault_prefault) {
		error = vn_io_fault_prefault_user(uio);
		if (error != 0)
			return (error); 
	}

	prot = uio->uio_rw == UIO_READ ? VM_PROT_WRITE : VM_PROT_READ;

	
	uio_clone = cloneuio(uio);
	resid = uio->uio_resid;

	short_uio.uio_segflg = UIO_USERSPACE;
	short_uio.uio_rw = uio->uio_rw;
	short_uio.uio_td = uio->uio_td;

	error = vn_io_fault_doio(args, uio, td);
	if (error != EFAULT)
		goto out;

	atomic_add_long(&vn_io_faults_cnt, 1);
	uio_clone->uio_segflg = UIO_NOCOPY;
	uiomove(NULL, resid - uio->uio_resid, uio_clone);
	uio_clone->uio_segflg = uio->uio_segflg;

	saveheld = curthread_pflags_set(TDP_UIOHELD);
	prev_td_ma = td->td_ma;
	prev_td_ma_cnt = td->td_ma_cnt;

	while (uio_clone->uio_resid != 0) {
		len = uio_clone->uio_iov->iov_len;
		if (len == 0) {
			KASSERT(uio_clone->uio_iovcnt >= 1, ("iovcnt underflow"));
			uio_clone->uio_iov++;
			uio_clone->uio_iovcnt--;
			continue;
		}
		if (len > io_hold_cnt * PAGE_SIZE)
			len = io_hold_cnt * PAGE_SIZE;
		addr = (uintptr_t)uio_clone->uio_iov->iov_base;
		end = round_page(addr + len);
		if (end < addr) {
			error = EFAULT;
			break;
		}
		cnt = atop(end - trunc_page(addr));
		
		cnt = vm_fault_quick_hold_pages(&td->td_proc->p_vmspace->vm_map, addr, len, prot, ma, io_hold_cnt + 2);
		if (cnt == -1) {
			error = EFAULT;
			break;
		}
		short_uio.uio_iov = &short_iovec[0];
		short_iovec[0].iov_base = (void *)addr;
		short_uio.uio_iovcnt = 1;
		short_uio.uio_resid = short_iovec[0].iov_len = len;
		short_uio.uio_offset = uio_clone->uio_offset;
		td->td_ma = ma;
		td->td_ma_cnt = cnt;

		error = vn_io_fault_doio(args, &short_uio, td);
		vm_page_unhold_pages(ma, cnt);
		adv = len - short_uio.uio_resid;

		uio_clone->uio_iov->iov_base = (char *)uio_clone->uio_iov->iov_base + adv;
		uio_clone->uio_iov->iov_len -= adv;
		uio_clone->uio_resid -= adv;
		uio_clone->uio_offset += adv;

		uio->uio_resid -= adv;
		uio->uio_offset += adv;

		if (error != 0 || adv == 0)
			break;
	}
	td->td_ma = prev_td_ma;
	td->td_ma_cnt = prev_td_ma_cnt;
	curthread_pflags_restore(saveheld);
out:
	free(uio_clone, M_IOV);
	return (error);
}

static int vn_io_fault(struct file *fp, struct uio *uio, struct ucred *active_cred, int flags, struct thread *td)

{
	fo_rdwr_t *doio;
	struct vnode *vp;
	void *rl_cookie;
	struct vn_io_fault_args args;
	int error;

	doio = uio->uio_rw == UIO_READ ? vn_read : vn_write;
	vp = fp->f_vnode;
	foffset_lock_uio(fp, uio, flags);
	if (do_vn_io_fault(vp, uio)) {
		args.kind = VN_IO_FAULT_FOP;
		args.args.fop_args.fp = fp;
		args.args.fop_args.doio = doio;
		args.cred = active_cred;
		args.flags = flags | FOF_OFFSET;
		if (uio->uio_rw == UIO_READ) {
			rl_cookie = vn_rangelock_rlock(vp, uio->uio_offset, uio->uio_offset + uio->uio_resid);
		} else if ((fp->f_flag & O_APPEND) != 0 || (flags & FOF_OFFSET) == 0) {
			
			rl_cookie = vn_rangelock_wlock(vp, 0, OFF_MAX);
		} else {
			rl_cookie = vn_rangelock_wlock(vp, uio->uio_offset, uio->uio_offset + uio->uio_resid);
		}
		error = vn_io_fault1(vp, uio, &args, td);
		vn_rangelock_unlock(vp, rl_cookie);
	} else {
		error = doio(fp, uio, active_cred, flags | FOF_OFFSET, td);
	}
	foffset_unlock_uio(fp, uio, flags);
	return (error);
}


int vn_io_fault_uiomove(char *data, int xfersize, struct uio *uio)
{
	struct uio transp_uio;
	struct iovec transp_iov[1];
	struct thread *td;
	size_t adv;
	int error, pgadv;

	td = curthread;
	if ((td->td_pflags & TDP_UIOHELD) == 0 || uio->uio_segflg != UIO_USERSPACE)
		return (uiomove(data, xfersize, uio));

	KASSERT(uio->uio_iovcnt == 1, ("uio_iovcnt %d", uio->uio_iovcnt));
	transp_iov[0].iov_base = data;
	transp_uio.uio_iov = &transp_iov[0];
	transp_uio.uio_iovcnt = 1;
	if (xfersize > uio->uio_resid)
		xfersize = uio->uio_resid;
	transp_uio.uio_resid = transp_iov[0].iov_len = xfersize;
	transp_uio.uio_offset = 0;
	transp_uio.uio_segflg = UIO_SYSSPACE;
	
	switch (uio->uio_rw) {
	case UIO_WRITE:
		transp_uio.uio_rw = UIO_READ;
		break;
	case UIO_READ:
		transp_uio.uio_rw = UIO_WRITE;
		break;
	}
	transp_uio.uio_td = uio->uio_td;
	error = uiomove_fromphys(td->td_ma, ((vm_offset_t)uio->uio_iov->iov_base) & PAGE_MASK, xfersize, &transp_uio);

	adv = xfersize - transp_uio.uio_resid;
	pgadv = (((vm_offset_t)uio->uio_iov->iov_base + adv) >> PAGE_SHIFT) - (((vm_offset_t)uio->uio_iov->iov_base) >> PAGE_SHIFT);

	td->td_ma += pgadv;
	KASSERT(td->td_ma_cnt >= pgadv, ("consumed pages %d %d", td->td_ma_cnt, pgadv));
	td->td_ma_cnt -= pgadv;
	uio->uio_iov->iov_base = (char *)uio->uio_iov->iov_base + adv;
	uio->uio_iov->iov_len -= adv;
	uio->uio_resid -= adv;
	uio->uio_offset += adv;
	return (error);
}

int vn_io_fault_pgmove(vm_page_t ma[], vm_offset_t offset, int xfersize, struct uio *uio)

{
	struct thread *td;
	vm_offset_t iov_base;
	int cnt, pgadv;

	td = curthread;
	if ((td->td_pflags & TDP_UIOHELD) == 0 || uio->uio_segflg != UIO_USERSPACE)
		return (uiomove_fromphys(ma, offset, xfersize, uio));

	KASSERT(uio->uio_iovcnt == 1, ("uio_iovcnt %d", uio->uio_iovcnt));
	cnt = xfersize > uio->uio_resid ? uio->uio_resid : xfersize;
	iov_base = (vm_offset_t)uio->uio_iov->iov_base;
	switch (uio->uio_rw) {
	case UIO_WRITE:
		pmap_copy_pages(td->td_ma, iov_base & PAGE_MASK, ma, offset, cnt);
		break;
	case UIO_READ:
		pmap_copy_pages(ma, offset, td->td_ma, iov_base & PAGE_MASK, cnt);
		break;
	}
	pgadv = ((iov_base + cnt) >> PAGE_SHIFT) - (iov_base >> PAGE_SHIFT);
	td->td_ma += pgadv;
	KASSERT(td->td_ma_cnt >= pgadv, ("consumed pages %d %d", td->td_ma_cnt, pgadv));
	td->td_ma_cnt -= pgadv;
	uio->uio_iov->iov_base = (char *)(iov_base + cnt);
	uio->uio_iov->iov_len -= cnt;
	uio->uio_resid -= cnt;
	uio->uio_offset += cnt;
	return (0);
}



static int vn_truncate(struct file *fp, off_t length, struct ucred *active_cred, struct thread *td)

{
	struct vattr vattr;
	struct mount *mp;
	struct vnode *vp;
	void *rl_cookie;
	int error;

	vp = fp->f_vnode;

	
	rl_cookie = vn_rangelock_wlock(vp, 0, OFF_MAX);
	error = vn_start_write(vp, &mp, V_WAIT | PCATCH);
	if (error)
		goto out1;
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	AUDIT_ARG_VNODE1(vp);
	if (vp->v_type == VDIR) {
		error = EISDIR;
		goto out;
	}

	error = mac_vnode_check_write(active_cred, fp->f_cred, vp);
	if (error)
		goto out;

	error = vn_writechk(vp);
	if (error == 0) {
		VATTR_NULL(&vattr);
		vattr.va_size = length;
		if ((fp->f_flag & O_FSYNC) != 0)
			vattr.va_vaflags |= VA_SYNC;
		error = VOP_SETATTR(vp, &vattr, fp->f_cred);
	}
out:
	VOP_UNLOCK(vp, 0);
	vn_finished_write(mp);
out1:
	vn_rangelock_unlock(vp, rl_cookie);
	return (error);
}


static int vn_statfile(struct file *fp, struct stat *sb, struct ucred *active_cred, struct thread *td)

{
	struct vnode *vp = fp->f_vnode;
	int error;

	vn_lock(vp, LK_SHARED | LK_RETRY);
	error = vn_stat(vp, sb, active_cred, fp->f_cred, td);
	VOP_UNLOCK(vp, 0);

	return (error);
}


int vn_stat(struct vnode *vp, struct stat *sb, struct ucred *active_cred, struct ucred *file_cred, struct thread *td)

{
	struct vattr vattr;
	struct vattr *vap;
	int error;
	u_short mode;

	AUDIT_ARG_VNODE1(vp);

	error = mac_vnode_check_stat(active_cred, file_cred, vp);
	if (error)
		return (error);


	vap = &vattr;

	
	vap->va_birthtime.tv_sec = -1;
	vap->va_birthtime.tv_nsec = 0;
	vap->va_fsid = VNOVAL;
	vap->va_rdev = NODEV;

	error = VOP_GETATTR(vp, vap, active_cred);
	if (error)
		return (error);

	
	bzero(sb, sizeof *sb);

	
	if (vap->va_fsid != VNOVAL)
		sb->st_dev = vap->va_fsid;
	else sb->st_dev = vp->v_mount->mnt_stat.f_fsid.val[0];
	sb->st_ino = vap->va_fileid;
	mode = vap->va_mode;
	switch (vap->va_type) {
	case VREG:
		mode |= S_IFREG;
		break;
	case VDIR:
		mode |= S_IFDIR;
		break;
	case VBLK:
		mode |= S_IFBLK;
		break;
	case VCHR:
		mode |= S_IFCHR;
		break;
	case VLNK:
		mode |= S_IFLNK;
		break;
	case VSOCK:
		mode |= S_IFSOCK;
		break;
	case VFIFO:
		mode |= S_IFIFO;
		break;
	default:
		return (EBADF);
	}
	sb->st_mode = mode;
	sb->st_nlink = vap->va_nlink;
	sb->st_uid = vap->va_uid;
	sb->st_gid = vap->va_gid;
	sb->st_rdev = vap->va_rdev;
	if (vap->va_size > OFF_MAX)
		return (EOVERFLOW);
	sb->st_size = vap->va_size;
	sb->st_atim = vap->va_atime;
	sb->st_mtim = vap->va_mtime;
	sb->st_ctim = vap->va_ctime;
	sb->st_birthtim = vap->va_birthtime;

        

	sb->st_blksize = max(PAGE_SIZE, vap->va_blocksize);
	
	sb->st_flags = vap->va_flags;
	if (priv_check(td, PRIV_VFS_GENERATION))
		sb->st_gen = 0;
	else sb->st_gen = vap->va_gen;

	sb->st_blocks = vap->va_bytes / S_BLKSIZE;
	return (0);
}


static int vn_ioctl(struct file *fp, u_long com, void *data, struct ucred *active_cred, struct thread *td)

{
	struct vattr vattr;
	struct vnode *vp;
	int error;

	vp = fp->f_vnode;
	switch (vp->v_type) {
	case VDIR:
	case VREG:
		switch (com) {
		case FIONREAD:
			vn_lock(vp, LK_SHARED | LK_RETRY);
			error = VOP_GETATTR(vp, &vattr, active_cred);
			VOP_UNLOCK(vp, 0);
			if (error == 0)
				*(int *)data = vattr.va_size - fp->f_offset;
			return (error);
		case FIONBIO:
		case FIOASYNC:
			return (0);
		default:
			return (VOP_IOCTL(vp, com, data, fp->f_flag, active_cred, td));
		}
		break;
	case VCHR:
		return (VOP_IOCTL(vp, com, data, fp->f_flag, active_cred, td));
	default:
		return (ENOTTY);
	}
}


static int vn_poll(struct file *fp, int events, struct ucred *active_cred, struct thread *td)

{
	struct vnode *vp;
	int error;

	vp = fp->f_vnode;

	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	AUDIT_ARG_VNODE1(vp);
	error = mac_vnode_check_poll(active_cred, fp->f_cred, vp);
	VOP_UNLOCK(vp, 0);
	if (!error)


	error = VOP_POLL(vp, events, fp->f_cred, td);
	return (error);
}


int _vn_lock(struct vnode *vp, int flags, char *file, int line)
{
	int error;

	VNASSERT((flags & LK_TYPE_MASK) != 0, vp, ("vn_lock: no locktype"));
	VNASSERT(vp->v_holdcnt != 0, vp, ("vn_lock: zero hold count"));
retry:
	error = VOP_LOCK1(vp, flags, file, line);
	flags &= ~LK_INTERLOCK;	
	KASSERT((flags & LK_RETRY) == 0 || error == 0, ("vn_lock: error %d incompatible with flags %#x", error, flags));

	if ((flags & LK_RETRY) == 0) {
		if (error == 0 && (vp->v_iflag & VI_DOOMED) != 0) {
			VOP_UNLOCK(vp, 0);
			error = ENOENT;
		}
	} else if (error != 0)
		goto retry;
	return (error);
}


static int vn_closefile(struct file *fp, struct thread *td)
{
	struct vnode *vp;
	struct flock lf;
	int error;
	bool ref;

	vp = fp->f_vnode;
	fp->f_ops = &badfileops;
	ref= (fp->f_flag & FHASLOCK) != 0 && fp->f_type == DTYPE_VNODE;

	error = vn_close1(vp, fp->f_flag, fp->f_cred, td, ref);

	if (__predict_false(ref)) {
		lf.l_whence = SEEK_SET;
		lf.l_start = 0;
		lf.l_len = 0;
		lf.l_type = F_UNLCK;
		(void) VOP_ADVLOCK(vp, fp, F_UNLCK, &lf, F_FLOCK);
		vrele(vp);
	}
	return (error);
}

static bool vn_suspendable(struct mount *mp)
{

	return (mp->mnt_op->vfs_susp_clean != NULL);
}


static int vn_start_write_locked(struct mount *mp, int flags)
{
	int error, mflags;

	mtx_assert(MNT_MTX(mp), MA_OWNED);
	error = 0;

	
	if ((curthread->td_pflags & TDP_IGNSUSP) == 0 || mp->mnt_susp_owner != curthread) {
		mflags = ((mp->mnt_vfc->vfc_flags & VFCF_SBDRY) != 0 ? (flags & PCATCH) : 0) | (PUSER - 1);
		while ((mp->mnt_kern_flag & MNTK_SUSPEND) != 0) {
			if (flags & V_NOWAIT) {
				error = EWOULDBLOCK;
				goto unlock;
			}
			error = msleep(&mp->mnt_flag, MNT_MTX(mp), mflags, "suspfs", 0);
			if (error)
				goto unlock;
		}
	}
	if (flags & V_XSLEEP)
		goto unlock;
	mp->mnt_writeopcount++;
unlock:
	if (error != 0 || (flags & V_XSLEEP) != 0)
		MNT_REL(mp);
	MNT_IUNLOCK(mp);
	return (error);
}

int vn_start_write(struct vnode *vp, struct mount **mpp, int flags)
{
	struct mount *mp;
	int error;

	KASSERT((flags & V_MNTREF) == 0 || (*mpp != NULL && vp == NULL), ("V_MNTREF requires mp"));

	error = 0;
	
	if (vp != NULL) {
		if ((error = VOP_GETWRITEMOUNT(vp, mpp)) != 0) {
			*mpp = NULL;
			if (error != EOPNOTSUPP)
				return (error);
			return (0);
		}
	}
	if ((mp = *mpp) == NULL)
		return (0);

	if (!vn_suspendable(mp)) {
		if (vp != NULL || (flags & V_MNTREF) != 0)
			vfs_rel(mp);
		return (0);
	}

	
	MNT_ILOCK(mp);
	if (vp == NULL && (flags & V_MNTREF) == 0)
		MNT_REF(mp);

	return (vn_start_write_locked(mp, flags));
}


int vn_start_secondary_write(struct vnode *vp, struct mount **mpp, int flags)
{
	struct mount *mp;
	int error;

	KASSERT((flags & V_MNTREF) == 0 || (*mpp != NULL && vp == NULL), ("V_MNTREF requires mp"));

 retry:
	if (vp != NULL) {
		if ((error = VOP_GETWRITEMOUNT(vp, mpp)) != 0) {
			*mpp = NULL;
			if (error != EOPNOTSUPP)
				return (error);
			return (0);
		}
	}
	
	if ((mp = *mpp) == NULL)
		return (0);

	if (!vn_suspendable(mp)) {
		if (vp != NULL || (flags & V_MNTREF) != 0)
			vfs_rel(mp);
		return (0);
	}

	
	MNT_ILOCK(mp);
	if (vp == NULL && (flags & V_MNTREF) == 0)
		MNT_REF(mp);
	if ((mp->mnt_kern_flag & (MNTK_SUSPENDED | MNTK_SUSPEND2)) == 0) {
		mp->mnt_secondary_writes++;
		mp->mnt_secondary_accwrites++;
		MNT_IUNLOCK(mp);
		return (0);
	}
	if (flags & V_NOWAIT) {
		MNT_REL(mp);
		MNT_IUNLOCK(mp);
		return (EWOULDBLOCK);
	}
	
	error = msleep(&mp->mnt_flag, MNT_MTX(mp), (PUSER - 1) | PDROP | ((mp->mnt_vfc->vfc_flags & VFCF_SBDRY) != 0 ? (flags & PCATCH) : 0), "suspfs", 0);

	vfs_rel(mp);
	if (error == 0)
		goto retry;
	return (error);
}


void vn_finished_write(struct mount *mp)
{
	if (mp == NULL || !vn_suspendable(mp))
		return;
	MNT_ILOCK(mp);
	MNT_REL(mp);
	mp->mnt_writeopcount--;
	if (mp->mnt_writeopcount < 0)
		panic("vn_finished_write: neg cnt");
	if ((mp->mnt_kern_flag & MNTK_SUSPEND) != 0 && mp->mnt_writeopcount <= 0)
		wakeup(&mp->mnt_writeopcount);
	MNT_IUNLOCK(mp);
}



void vn_finished_secondary_write(struct mount *mp)
{
	if (mp == NULL || !vn_suspendable(mp))
		return;
	MNT_ILOCK(mp);
	MNT_REL(mp);
	mp->mnt_secondary_writes--;
	if (mp->mnt_secondary_writes < 0)
		panic("vn_finished_secondary_write: neg cnt");
	if ((mp->mnt_kern_flag & MNTK_SUSPEND) != 0 && mp->mnt_secondary_writes <= 0)
		wakeup(&mp->mnt_secondary_writes);
	MNT_IUNLOCK(mp);
}




int vfs_write_suspend(struct mount *mp, int flags)
{
	int error;

	MPASS(vn_suspendable(mp));

	MNT_ILOCK(mp);
	if (mp->mnt_susp_owner == curthread) {
		MNT_IUNLOCK(mp);
		return (EALREADY);
	}
	while (mp->mnt_kern_flag & MNTK_SUSPEND)
		msleep(&mp->mnt_flag, MNT_MTX(mp), PUSER - 1, "wsuspfs", 0);

	
	if ((flags & VS_SKIP_UNMOUNT) != 0 && (mp->mnt_kern_flag & MNTK_UNMOUNT) != 0) {
		MNT_IUNLOCK(mp);
		return (EBUSY);
	}

	mp->mnt_kern_flag |= MNTK_SUSPEND;
	mp->mnt_susp_owner = curthread;
	if (mp->mnt_writeopcount > 0)
		(void) msleep(&mp->mnt_writeopcount,  MNT_MTX(mp), (PUSER - 1)|PDROP, "suspwt", 0);
	else MNT_IUNLOCK(mp);
	if ((error = VFS_SYNC(mp, MNT_SUSPEND)) != 0)
		vfs_write_resume(mp, 0);
	return (error);
}


void vfs_write_resume(struct mount *mp, int flags)
{

	MPASS(vn_suspendable(mp));

	MNT_ILOCK(mp);
	if ((mp->mnt_kern_flag & MNTK_SUSPEND) != 0) {
		KASSERT(mp->mnt_susp_owner == curthread, ("mnt_susp_owner"));
		mp->mnt_kern_flag &= ~(MNTK_SUSPEND | MNTK_SUSPEND2 | MNTK_SUSPENDED);
		mp->mnt_susp_owner = NULL;
		wakeup(&mp->mnt_writeopcount);
		wakeup(&mp->mnt_flag);
		curthread->td_pflags &= ~TDP_IGNSUSP;
		if ((flags & VR_START_WRITE) != 0) {
			MNT_REF(mp);
			mp->mnt_writeopcount++;
		}
		MNT_IUNLOCK(mp);
		if ((flags & VR_NO_SUSPCLR) == 0)
			VFS_SUSP_CLEAN(mp);
	} else if ((flags & VR_START_WRITE) != 0) {
		MNT_REF(mp);
		vn_start_write_locked(mp, 0);
	} else {
		MNT_IUNLOCK(mp);
	}
}


int vfs_write_suspend_umnt(struct mount *mp)
{
	int error;

	MPASS(vn_suspendable(mp));
	KASSERT((curthread->td_pflags & TDP_IGNSUSP) == 0, ("vfs_write_suspend_umnt: recursed"));

	
	for (;;) {
		vn_finished_write(mp);
		error = vfs_write_suspend(mp, 0);
		if (error != 0) {
			vn_start_write(NULL, &mp, V_WAIT);
			return (error);
		}
		MNT_ILOCK(mp);
		if ((mp->mnt_kern_flag & MNTK_SUSPENDED) != 0)
			break;
		MNT_IUNLOCK(mp);
		vn_start_write(NULL, &mp, V_WAIT);
	}
	mp->mnt_kern_flag &= ~(MNTK_SUSPENDED | MNTK_SUSPEND2);
	wakeup(&mp->mnt_flag);
	MNT_IUNLOCK(mp);
	curthread->td_pflags |= TDP_IGNSUSP;
	return (0);
}


static int vn_kqfilter(struct file *fp, struct knote *kn)
{

	return (VOP_KQFILTER(fp->f_vnode, kn));
}


int vn_extattr_get(struct vnode *vp, int ioflg, int attrnamespace, const char *attrname, int *buflen, char *buf, struct thread *td)

{
	struct uio	auio;
	struct iovec	iov;
	int	error;

	iov.iov_len = *buflen;
	iov.iov_base = buf;

	auio.uio_iov = &iov;
	auio.uio_iovcnt = 1;
	auio.uio_rw = UIO_READ;
	auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_td = td;
	auio.uio_offset = 0;
	auio.uio_resid = *buflen;

	if ((ioflg & IO_NODELOCKED) == 0)
		vn_lock(vp, LK_SHARED | LK_RETRY);

	ASSERT_VOP_LOCKED(vp, "IO_NODELOCKED with no vp lock held");

	
	error = VOP_GETEXTATTR(vp, attrnamespace, attrname, &auio, NULL, NULL, td);

	if ((ioflg & IO_NODELOCKED) == 0)
		VOP_UNLOCK(vp, 0);

	if (error == 0) {
		*buflen = *buflen - auio.uio_resid;
	}

	return (error);
}


int vn_extattr_set(struct vnode *vp, int ioflg, int attrnamespace, const char *attrname, int buflen, char *buf, struct thread *td)

{
	struct uio	auio;
	struct iovec	iov;
	struct mount	*mp;
	int	error;

	iov.iov_len = buflen;
	iov.iov_base = buf;

	auio.uio_iov = &iov;
	auio.uio_iovcnt = 1;
	auio.uio_rw = UIO_WRITE;
	auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_td = td;
	auio.uio_offset = 0;
	auio.uio_resid = buflen;

	if ((ioflg & IO_NODELOCKED) == 0) {
		if ((error = vn_start_write(vp, &mp, V_WAIT)) != 0)
			return (error);
		vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	}

	ASSERT_VOP_LOCKED(vp, "IO_NODELOCKED with no vp lock held");

	
	error = VOP_SETEXTATTR(vp, attrnamespace, attrname, &auio, NULL, td);

	if ((ioflg & IO_NODELOCKED) == 0) {
		vn_finished_write(mp);
		VOP_UNLOCK(vp, 0);
	}

	return (error);
}

int vn_extattr_rm(struct vnode *vp, int ioflg, int attrnamespace, const char *attrname, struct thread *td)

{
	struct mount	*mp;
	int	error;

	if ((ioflg & IO_NODELOCKED) == 0) {
		if ((error = vn_start_write(vp, &mp, V_WAIT)) != 0)
			return (error);
		vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	}

	ASSERT_VOP_LOCKED(vp, "IO_NODELOCKED with no vp lock held");

	
	error = VOP_DELETEEXTATTR(vp, attrnamespace, attrname, NULL, td);
	if (error == EOPNOTSUPP)
		error = VOP_SETEXTATTR(vp, attrnamespace, attrname, NULL, NULL, td);

	if ((ioflg & IO_NODELOCKED) == 0) {
		vn_finished_write(mp);
		VOP_UNLOCK(vp, 0);
	}

	return (error);
}

static int vn_get_ino_alloc_vget(struct mount *mp, void *arg, int lkflags, struct vnode **rvp)

{

	return (VFS_VGET(mp, *(ino_t *)arg, lkflags, rvp));
}

int vn_vget_ino(struct vnode *vp, ino_t ino, int lkflags, struct vnode **rvp)
{

	return (vn_vget_ino_gen(vp, vn_get_ino_alloc_vget, &ino, lkflags, rvp));
}

int vn_vget_ino_gen(struct vnode *vp, vn_get_ino_t alloc, void *alloc_arg, int lkflags, struct vnode **rvp)

{
	struct mount *mp;
	int ltype, error;

	ASSERT_VOP_LOCKED(vp, "vn_vget_ino_get");
	mp = vp->v_mount;
	ltype = VOP_ISLOCKED(vp);
	KASSERT(ltype == LK_EXCLUSIVE || ltype == LK_SHARED, ("vn_vget_ino: vp not locked"));
	error = vfs_busy(mp, MBF_NOWAIT);
	if (error != 0) {
		vfs_ref(mp);
		VOP_UNLOCK(vp, 0);
		error = vfs_busy(mp, 0);
		vn_lock(vp, ltype | LK_RETRY);
		vfs_rel(mp);
		if (error != 0)
			return (ENOENT);
		if (vp->v_iflag & VI_DOOMED) {
			vfs_unbusy(mp);
			return (ENOENT);
		}
	}
	VOP_UNLOCK(vp, 0);
	error = alloc(mp, alloc_arg, lkflags, rvp);
	vfs_unbusy(mp);
	if (*rvp != vp)
		vn_lock(vp, ltype | LK_RETRY);
	if (vp->v_iflag & VI_DOOMED) {
		if (error == 0) {
			if (*rvp == vp)
				vunref(vp);
			else vput(*rvp);
		}
		error = ENOENT;
	}
	return (error);
}

int vn_rlimit_fsize(const struct vnode *vp, const struct uio *uio, struct thread *td)

{

	if (vp->v_type != VREG || td == NULL)
		return (0);
	if ((uoff_t)uio->uio_offset + uio->uio_resid > lim_cur(td, RLIMIT_FSIZE)) {
		PROC_LOCK(td->td_proc);
		kern_psignal(td->td_proc, SIGXFSZ);
		PROC_UNLOCK(td->td_proc);
		return (EFBIG);
	}
	return (0);
}

int vn_chmod(struct file *fp, mode_t mode, struct ucred *active_cred, struct thread *td)

{
	struct vnode *vp;

	vp = fp->f_vnode;

	vn_lock(vp, LK_SHARED | LK_RETRY);
	AUDIT_ARG_VNODE1(vp);
	VOP_UNLOCK(vp, 0);

	return (setfmode(td, active_cred, vp, mode));
}

int vn_chown(struct file *fp, uid_t uid, gid_t gid, struct ucred *active_cred, struct thread *td)

{
	struct vnode *vp;

	vp = fp->f_vnode;

	vn_lock(vp, LK_SHARED | LK_RETRY);
	AUDIT_ARG_VNODE1(vp);
	VOP_UNLOCK(vp, 0);

	return (setfown(td, active_cred, vp, uid, gid));
}

void vn_pages_remove(struct vnode *vp, vm_pindex_t start, vm_pindex_t end)
{
	vm_object_t object;

	if ((object = vp->v_object) == NULL)
		return;
	VM_OBJECT_WLOCK(object);
	vm_object_page_remove(object, start, end, 0);
	VM_OBJECT_WUNLOCK(object);
}

int vn_bmap_seekhole(struct vnode *vp, u_long cmd, off_t *off, struct ucred *cred)
{
	struct vattr va;
	daddr_t bn, bnp;
	uint64_t bsize;
	off_t noff;
	int error;

	KASSERT(cmd == FIOSEEKHOLE || cmd == FIOSEEKDATA, ("Wrong command %lu", cmd));

	if (vn_lock(vp, LK_SHARED) != 0)
		return (EBADF);
	if (vp->v_type != VREG) {
		error = ENOTTY;
		goto unlock;
	}
	error = VOP_GETATTR(vp, &va, cred);
	if (error != 0)
		goto unlock;
	noff = *off;
	if (noff >= va.va_size) {
		error = ENXIO;
		goto unlock;
	}
	bsize = vp->v_mount->mnt_stat.f_iosize;
	for (bn = noff / bsize; noff < va.va_size; bn++, noff += bsize) {
		error = VOP_BMAP(vp, bn, NULL, &bnp, NULL, NULL);
		if (error == EOPNOTSUPP) {
			error = ENOTTY;
			goto unlock;
		}
		if ((bnp == -1 && cmd == FIOSEEKHOLE) || (bnp != -1 && cmd == FIOSEEKDATA)) {
			noff = bn * bsize;
			if (noff < *off)
				noff = *off;
			goto unlock;
		}
	}
	if (noff > va.va_size)
		noff = va.va_size;
	
	if (cmd == FIOSEEKDATA)
		error = ENXIO;
unlock:
	VOP_UNLOCK(vp, 0);
	if (error == 0)
		*off = noff;
	return (error);
}

int vn_seek(struct file *fp, off_t offset, int whence, struct thread *td)
{
	struct ucred *cred;
	struct vnode *vp;
	struct vattr vattr;
	off_t foffset, size;
	int error, noneg;

	cred = td->td_ucred;
	vp = fp->f_vnode;
	foffset = foffset_lock(fp, 0);
	noneg = (vp->v_type != VCHR);
	error = 0;
	switch (whence) {
	case L_INCR:
		if (noneg && (foffset < 0 || (offset > 0 && foffset > OFF_MAX - offset))) {

			error = EOVERFLOW;
			break;
		}
		offset += foffset;
		break;
	case L_XTND:
		vn_lock(vp, LK_SHARED | LK_RETRY);
		error = VOP_GETATTR(vp, &vattr, cred);
		VOP_UNLOCK(vp, 0);
		if (error)
			break;

		
		if (vattr.va_size == 0 && vp->v_type == VCHR && fo_ioctl(fp, DIOCGMEDIASIZE, &size, cred, td) == 0)
			vattr.va_size = size;
		if (noneg && (vattr.va_size > OFF_MAX || (offset > 0 && vattr.va_size > OFF_MAX - offset))) {

			error = EOVERFLOW;
			break;
		}
		offset += vattr.va_size;
		break;
	case L_SET:
		break;
	case SEEK_DATA:
		error = fo_ioctl(fp, FIOSEEKDATA, &offset, cred, td);
		break;
	case SEEK_HOLE:
		error = fo_ioctl(fp, FIOSEEKHOLE, &offset, cred, td);
		break;
	default:
		error = EINVAL;
	}
	if (error == 0 && noneg && offset < 0)
		error = EINVAL;
	if (error != 0)
		goto drop;
	VFS_KNOTE_UNLOCKED(vp, 0);
	td->td_uretoff.tdu_off = offset;
drop:
	foffset_unlock(fp, offset, error != 0 ? FOF_NOUPDATE : 0);
	return (error);
}

int vn_utimes_perm(struct vnode *vp, struct vattr *vap, struct ucred *cred, struct thread *td)

{
	int error;

	
	error = VOP_ACCESSX(vp, VWRITE_ATTRIBUTES, cred, td);
	if (error != 0 && (vap->va_vaflags & VA_UTIMES_NULL) != 0)
		error = VOP_ACCESS(vp, VWRITE, cred, td);
	return (error);
}

int vn_fill_kinfo(struct file *fp, struct kinfo_file *kif, struct filedesc *fdp)
{
	struct vnode *vp;
	int error;

	if (fp->f_type == DTYPE_FIFO)
		kif->kf_type = KF_TYPE_FIFO;
	else kif->kf_type = KF_TYPE_VNODE;
	vp = fp->f_vnode;
	vref(vp);
	FILEDESC_SUNLOCK(fdp);
	error = vn_fill_kinfo_vnode(vp, kif);
	vrele(vp);
	FILEDESC_SLOCK(fdp);
	return (error);
}

static inline void vn_fill_junk(struct kinfo_file *kif)
{
	size_t len, olen;

	
	len = (arc4random() % (sizeof(kif->kf_path) - 2)) + 1;
	olen = strlen(kif->kf_path);
	if (len < olen)
		strcpy(&kif->kf_path[len - 1], "$");
	else for (; olen < len; olen++)
			strcpy(&kif->kf_path[olen], "A");
}

int vn_fill_kinfo_vnode(struct vnode *vp, struct kinfo_file *kif)
{
	struct vattr va;
	char *fullpath, *freepath;
	int error;

	kif->kf_un.kf_file.kf_file_type = vntype_to_kinfo(vp->v_type);
	freepath = NULL;
	fullpath = "-";
	error = vn_fullpath(curthread, vp, &fullpath, &freepath);
	if (error == 0) {
		strlcpy(kif->kf_path, fullpath, sizeof(kif->kf_path));
	}
	if (freepath != NULL)
		free(freepath, M_TEMP);

	KFAIL_POINT_CODE(DEBUG_FP, fill_kinfo_vnode__random_path, vn_fill_junk(kif);
	);

	
	va.va_fsid = VNOVAL;
	va.va_rdev = NODEV;
	vn_lock(vp, LK_SHARED | LK_RETRY);
	error = VOP_GETATTR(vp, &va, curthread->td_ucred);
	VOP_UNLOCK(vp, 0);
	if (error != 0)
		return (error);
	if (va.va_fsid != VNOVAL)
		kif->kf_un.kf_file.kf_file_fsid = va.va_fsid;
	else kif->kf_un.kf_file.kf_file_fsid = vp->v_mount->mnt_stat.f_fsid.val[0];

	kif->kf_un.kf_file.kf_file_fsid_freebsd11 = kif->kf_un.kf_file.kf_file_fsid;
	kif->kf_un.kf_file.kf_file_fileid = va.va_fileid;
	kif->kf_un.kf_file.kf_file_mode = MAKEIMODE(va.va_type, va.va_mode);
	kif->kf_un.kf_file.kf_file_size = va.va_size;
	kif->kf_un.kf_file.kf_file_rdev = va.va_rdev;
	kif->kf_un.kf_file.kf_file_rdev_freebsd11 = kif->kf_un.kf_file.kf_file_rdev;
	return (0);
}

int vn_mmap(struct file *fp, vm_map_t map, vm_offset_t *addr, vm_size_t size, vm_prot_t prot, vm_prot_t cap_maxprot, int flags, vm_ooffset_t foff, struct thread *td)


{

	struct pmckern_map_in pkm;

	struct mount *mp;
	struct vnode *vp;
	vm_object_t object;
	vm_prot_t maxprot;
	boolean_t writecounted;
	int error;


	
	if ((fp->f_flag & FPOSIXSHM) != 0)
		flags |= MAP_NOSYNC;

	vp = fp->f_vnode;

	
	mp = vp->v_mount;
	if (mp != NULL && (mp->mnt_flag & MNT_NOEXEC) != 0) {
		maxprot = VM_PROT_NONE;
		if ((prot & VM_PROT_EXECUTE) != 0)
			return (EACCES);
	} else maxprot = VM_PROT_EXECUTE;
	if ((fp->f_flag & FREAD) != 0)
		maxprot |= VM_PROT_READ;
	else if ((prot & VM_PROT_READ) != 0)
		return (EACCES);

	
	if ((flags & MAP_SHARED) != 0) {
		if ((fp->f_flag & FWRITE) != 0)
			maxprot |= VM_PROT_WRITE;
		else if ((prot & VM_PROT_WRITE) != 0)
			return (EACCES);
	} else {
		maxprot |= VM_PROT_WRITE;
		cap_maxprot |= VM_PROT_WRITE;
	}
	maxprot &= cap_maxprot;

	
	if (  size > OFF_MAX ||  foff < 0 || foff > OFF_MAX - size)



		return (EINVAL);

	writecounted = FALSE;
	error = vm_mmap_vnode(td, size, prot, &maxprot, &flags, vp, &foff, &object, &writecounted);
	if (error != 0)
		return (error);
	error = vm_mmap_object(map, addr, size, prot, maxprot, flags, object, foff, writecounted, td);
	if (error != 0) {
		
		if (writecounted)
			vnode_pager_release_writecount(object, 0, size);
		vm_object_deallocate(object);
	}

	
	if (PMC_HOOK_INSTALLED(PMC_FN_MMAP)) {
		if ((prot & VM_PROT_EXECUTE) != 0 && error == 0) {
			pkm.pm_file = vp;
			pkm.pm_address = (uintptr_t) *addr;
			PMC_CALL_HOOK_UNLOCKED(td, PMC_FN_MMAP, (void *) &pkm);
		}
	}

	return (error);
}

void vn_fsid(struct vnode *vp, struct vattr *va)
{
	fsid_t *f;

	f = &vp->v_mount->mnt_stat.f_fsid;
	va->va_fsid = (uint32_t)f->val[1];
	va->va_fsid <<= sizeof(f->val[1]) * NBBY;
	va->va_fsid += (uint32_t)f->val[0];
}
