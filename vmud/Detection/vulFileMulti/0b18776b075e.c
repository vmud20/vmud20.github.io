





































int xfs_find_handle( unsigned int		cmd, xfs_fsop_handlereq_t	*hreq)


{
	int			hsize;
	xfs_handle_t		handle;
	struct inode		*inode;
	struct fd		f = {NULL};
	struct path		path;
	int			error;
	struct xfs_inode	*ip;

	if (cmd == XFS_IOC_FD_TO_HANDLE) {
		f = fdget(hreq->fd);
		if (!f.file)
			return -EBADF;
		inode = file_inode(f.file);
	} else {
		error = user_lpath((const char __user *)hreq->path, &path);
		if (error)
			return error;
		inode = path.dentry->d_inode;
	}
	ip = XFS_I(inode);

	
	error = -EINVAL;
	if (inode->i_sb->s_magic != XFS_SB_MAGIC)
		goto out_put;

	error = -EBADF;
	if (!S_ISREG(inode->i_mode) && !S_ISDIR(inode->i_mode) && !S_ISLNK(inode->i_mode))

		goto out_put;


	memcpy(&handle.ha_fsid, ip->i_mount->m_fixedfsid, sizeof(xfs_fsid_t));

	if (cmd == XFS_IOC_PATH_TO_FSHANDLE) {
		
		memset(&handle.ha_fid, 0, sizeof(handle.ha_fid));
		hsize = sizeof(xfs_fsid_t);
	} else {
		handle.ha_fid.fid_len = sizeof(xfs_fid_t) - sizeof(handle.ha_fid.fid_len);
		handle.ha_fid.fid_pad = 0;
		handle.ha_fid.fid_gen = ip->i_d.di_gen;
		handle.ha_fid.fid_ino = ip->i_ino;

		hsize = XFS_HSIZE(handle);
	}

	error = -EFAULT;
	if (copy_to_user(hreq->ohandle, &handle, hsize) || copy_to_user(hreq->ohandlen, &hsize, sizeof(__s32)))
		goto out_put;

	error = 0;

 out_put:
	if (cmd == XFS_IOC_FD_TO_HANDLE)
		fdput(f);
	else path_put(&path);
	return error;
}


STATIC int xfs_handle_acceptable( void			*context, struct dentry		*dentry)


{
	return 1;
}


struct dentry * xfs_handle_to_dentry( struct file		*parfilp, void __user		*uhandle, u32			hlen)



{
	xfs_handle_t		handle;
	struct xfs_fid64	fid;

	
	if (!S_ISDIR(file_inode(parfilp)->i_mode))
		return ERR_PTR(-ENOTDIR);

	if (hlen != sizeof(xfs_handle_t))
		return ERR_PTR(-EINVAL);
	if (copy_from_user(&handle, uhandle, hlen))
		return ERR_PTR(-EFAULT);
	if (handle.ha_fid.fid_len != sizeof(handle.ha_fid) - sizeof(handle.ha_fid.fid_len))
		return ERR_PTR(-EINVAL);

	memset(&fid, 0, sizeof(struct fid));
	fid.ino = handle.ha_fid.fid_ino;
	fid.gen = handle.ha_fid.fid_gen;

	return exportfs_decode_fh(parfilp->f_path.mnt, (struct fid *)&fid, 3, FILEID_INO32_GEN | XFS_FILEID_TYPE_64FLAG, xfs_handle_acceptable, NULL);

}

STATIC struct dentry * xfs_handlereq_to_dentry( struct file		*parfilp, xfs_fsop_handlereq_t	*hreq)


{
	return xfs_handle_to_dentry(parfilp, hreq->ihandle, hreq->ihandlen);
}

int xfs_open_by_handle( struct file		*parfilp, xfs_fsop_handlereq_t	*hreq)


{
	const struct cred	*cred = current_cred();
	int			error;
	int			fd;
	int			permflag;
	struct file		*filp;
	struct inode		*inode;
	struct dentry		*dentry;
	fmode_t			fmode;
	struct path		path;

	if (!capable(CAP_SYS_ADMIN))
		return -XFS_ERROR(EPERM);

	dentry = xfs_handlereq_to_dentry(parfilp, hreq);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);
	inode = dentry->d_inode;

	
	if (!(S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode))) {
		error = -XFS_ERROR(EPERM);
		goto out_dput;
	}


	hreq->oflags |= O_LARGEFILE;


	permflag = hreq->oflags;
	fmode = OPEN_FMODE(permflag);
	if ((!(permflag & O_APPEND) || (permflag & O_TRUNC)) && (fmode & FMODE_WRITE) && IS_APPEND(inode)) {
		error = -XFS_ERROR(EPERM);
		goto out_dput;
	}

	if ((fmode & FMODE_WRITE) && IS_IMMUTABLE(inode)) {
		error = -XFS_ERROR(EACCES);
		goto out_dput;
	}

	
	if (S_ISDIR(inode->i_mode) && (fmode & FMODE_WRITE)) {
		error = -XFS_ERROR(EISDIR);
		goto out_dput;
	}

	fd = get_unused_fd_flags(0);
	if (fd < 0) {
		error = fd;
		goto out_dput;
	}

	path.mnt = parfilp->f_path.mnt;
	path.dentry = dentry;
	filp = dentry_open(&path, hreq->oflags, cred);
	dput(dentry);
	if (IS_ERR(filp)) {
		put_unused_fd(fd);
		return PTR_ERR(filp);
	}

	if (S_ISREG(inode->i_mode)) {
		filp->f_flags |= O_NOATIME;
		filp->f_mode |= FMODE_NOCMTIME;
	}

	fd_install(fd, filp);
	return fd;

 out_dput:
	dput(dentry);
	return error;
}

int xfs_readlink_by_handle( struct file		*parfilp, xfs_fsop_handlereq_t	*hreq)


{
	struct dentry		*dentry;
	__u32			olen;
	void			*link;
	int			error;

	if (!capable(CAP_SYS_ADMIN))
		return -XFS_ERROR(EPERM);

	dentry = xfs_handlereq_to_dentry(parfilp, hreq);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);

	
	if (!S_ISLNK(dentry->d_inode->i_mode)) {
		error = -XFS_ERROR(EINVAL);
		goto out_dput;
	}

	if (copy_from_user(&olen, hreq->ohandlen, sizeof(__u32))) {
		error = -XFS_ERROR(EFAULT);
		goto out_dput;
	}

	link = kmalloc(MAXPATHLEN+1, GFP_KERNEL);
	if (!link) {
		error = -XFS_ERROR(ENOMEM);
		goto out_dput;
	}

	error = -xfs_readlink(XFS_I(dentry->d_inode), link);
	if (error)
		goto out_kfree;
	error = readlink_copy(hreq->ohandle, olen, link);
	if (error)
		goto out_kfree;

 out_kfree:
	kfree(link);
 out_dput:
	dput(dentry);
	return error;
}

int xfs_set_dmattrs( xfs_inode_t     *ip, u_int		evmask, u_int16_t	state)



{
	xfs_mount_t	*mp = ip->i_mount;
	xfs_trans_t	*tp;
	int		error;

	if (!capable(CAP_SYS_ADMIN))
		return XFS_ERROR(EPERM);

	if (XFS_FORCED_SHUTDOWN(mp))
		return XFS_ERROR(EIO);

	tp = xfs_trans_alloc(mp, XFS_TRANS_SET_DMATTRS);
	error = xfs_trans_reserve(tp, &M_RES(mp)->tr_ichange, 0, 0);
	if (error) {
		xfs_trans_cancel(tp, 0);
		return error;
	}
	xfs_ilock(ip, XFS_ILOCK_EXCL);
	xfs_trans_ijoin(tp, ip, XFS_ILOCK_EXCL);

	ip->i_d.di_dmevmask = evmask;
	ip->i_d.di_dmstate  = state;

	xfs_trans_log_inode(tp, ip, XFS_ILOG_CORE);
	error = xfs_trans_commit(tp, 0);

	return error;
}

STATIC int xfs_fssetdm_by_handle( struct file		*parfilp, void			__user *arg)


{
	int			error;
	struct fsdmidata	fsd;
	xfs_fsop_setdm_handlereq_t dmhreq;
	struct dentry		*dentry;

	if (!capable(CAP_MKNOD))
		return -XFS_ERROR(EPERM);
	if (copy_from_user(&dmhreq, arg, sizeof(xfs_fsop_setdm_handlereq_t)))
		return -XFS_ERROR(EFAULT);

	error = mnt_want_write_file(parfilp);
	if (error)
		return error;

	dentry = xfs_handlereq_to_dentry(parfilp, &dmhreq.hreq);
	if (IS_ERR(dentry)) {
		mnt_drop_write_file(parfilp);
		return PTR_ERR(dentry);
	}

	if (IS_IMMUTABLE(dentry->d_inode) || IS_APPEND(dentry->d_inode)) {
		error = -XFS_ERROR(EPERM);
		goto out;
	}

	if (copy_from_user(&fsd, dmhreq.data, sizeof(fsd))) {
		error = -XFS_ERROR(EFAULT);
		goto out;
	}

	error = -xfs_set_dmattrs(XFS_I(dentry->d_inode), fsd.fsd_dmevmask, fsd.fsd_dmstate);

 out:
	mnt_drop_write_file(parfilp);
	dput(dentry);
	return error;
}

STATIC int xfs_attrlist_by_handle( struct file		*parfilp, void			__user *arg)


{
	int			error = -ENOMEM;
	attrlist_cursor_kern_t	*cursor;
	xfs_fsop_attrlist_handlereq_t al_hreq;
	struct dentry		*dentry;
	char			*kbuf;

	if (!capable(CAP_SYS_ADMIN))
		return -XFS_ERROR(EPERM);
	if (copy_from_user(&al_hreq, arg, sizeof(xfs_fsop_attrlist_handlereq_t)))
		return -XFS_ERROR(EFAULT);
	if (al_hreq.buflen < sizeof(struct attrlist) || al_hreq.buflen > XATTR_LIST_MAX)
		return -XFS_ERROR(EINVAL);

	
	if (al_hreq.flags & ~(ATTR_ROOT | ATTR_SECURE))
		return -XFS_ERROR(EINVAL);

	dentry = xfs_handlereq_to_dentry(parfilp, &al_hreq.hreq);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);

	kbuf = kmem_zalloc_large(al_hreq.buflen, KM_SLEEP);
	if (!kbuf)
		goto out_dput;

	cursor = (attrlist_cursor_kern_t *)&al_hreq.pos;
	error = -xfs_attr_list(XFS_I(dentry->d_inode), kbuf, al_hreq.buflen, al_hreq.flags, cursor);
	if (error)
		goto out_kfree;

	if (copy_to_user(al_hreq.buffer, kbuf, al_hreq.buflen))
		error = -EFAULT;

out_kfree:
	kmem_free(kbuf);
out_dput:
	dput(dentry);
	return error;
}

int xfs_attrmulti_attr_get( struct inode		*inode, unsigned char		*name, unsigned char		__user *ubuf, __uint32_t		*len, __uint32_t		flags)





{
	unsigned char		*kbuf;
	int			error = EFAULT;

	if (*len > XATTR_SIZE_MAX)
		return EINVAL;
	kbuf = kmem_zalloc_large(*len, KM_SLEEP);
	if (!kbuf)
		return ENOMEM;

	error = xfs_attr_get(XFS_I(inode), name, kbuf, (int *)len, flags);
	if (error)
		goto out_kfree;

	if (copy_to_user(ubuf, kbuf, *len))
		error = EFAULT;

out_kfree:
	kmem_free(kbuf);
	return error;
}

int xfs_attrmulti_attr_set( struct inode		*inode, unsigned char		*name, const unsigned char	__user *ubuf, __uint32_t		len, __uint32_t		flags)





{
	unsigned char		*kbuf;
	int			error = EFAULT;

	if (IS_IMMUTABLE(inode) || IS_APPEND(inode))
		return EPERM;
	if (len > XATTR_SIZE_MAX)
		return EINVAL;

	kbuf = memdup_user(ubuf, len);
	if (IS_ERR(kbuf))
		return PTR_ERR(kbuf);

	error = xfs_attr_set(XFS_I(inode), name, kbuf, len, flags);

	return error;
}

int xfs_attrmulti_attr_remove( struct inode		*inode, unsigned char		*name, __uint32_t		flags)



{
	if (IS_IMMUTABLE(inode) || IS_APPEND(inode))
		return EPERM;
	return xfs_attr_remove(XFS_I(inode), name, flags);
}

STATIC int xfs_attrmulti_by_handle( struct file		*parfilp, void			__user *arg)


{
	int			error;
	xfs_attr_multiop_t	*ops;
	xfs_fsop_attrmulti_handlereq_t am_hreq;
	struct dentry		*dentry;
	unsigned int		i, size;
	unsigned char		*attr_name;

	if (!capable(CAP_SYS_ADMIN))
		return -XFS_ERROR(EPERM);
	if (copy_from_user(&am_hreq, arg, sizeof(xfs_fsop_attrmulti_handlereq_t)))
		return -XFS_ERROR(EFAULT);

	
	if (am_hreq.opcount >= INT_MAX / sizeof(xfs_attr_multiop_t))
		return -E2BIG;

	dentry = xfs_handlereq_to_dentry(parfilp, &am_hreq.hreq);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);

	error = E2BIG;
	size = am_hreq.opcount * sizeof(xfs_attr_multiop_t);
	if (!size || size > 16 * PAGE_SIZE)
		goto out_dput;

	ops = memdup_user(am_hreq.ops, size);
	if (IS_ERR(ops)) {
		error = PTR_ERR(ops);
		goto out_dput;
	}

	attr_name = kmalloc(MAXNAMELEN, GFP_KERNEL);
	if (!attr_name)
		goto out_kfree_ops;

	error = 0;
	for (i = 0; i < am_hreq.opcount; i++) {
		ops[i].am_error = strncpy_from_user((char *)attr_name, ops[i].am_attrname, MAXNAMELEN);
		if (ops[i].am_error == 0 || ops[i].am_error == MAXNAMELEN)
			error = -ERANGE;
		if (ops[i].am_error < 0)
			break;

		switch (ops[i].am_opcode) {
		case ATTR_OP_GET:
			ops[i].am_error = xfs_attrmulti_attr_get( dentry->d_inode, attr_name, ops[i].am_attrvalue, &ops[i].am_length, ops[i].am_flags);


			break;
		case ATTR_OP_SET:
			ops[i].am_error = mnt_want_write_file(parfilp);
			if (ops[i].am_error)
				break;
			ops[i].am_error = xfs_attrmulti_attr_set( dentry->d_inode, attr_name, ops[i].am_attrvalue, ops[i].am_length, ops[i].am_flags);


			mnt_drop_write_file(parfilp);
			break;
		case ATTR_OP_REMOVE:
			ops[i].am_error = mnt_want_write_file(parfilp);
			if (ops[i].am_error)
				break;
			ops[i].am_error = xfs_attrmulti_attr_remove( dentry->d_inode, attr_name, ops[i].am_flags);

			mnt_drop_write_file(parfilp);
			break;
		default:
			ops[i].am_error = EINVAL;
		}
	}

	if (copy_to_user(am_hreq.ops, ops, size))
		error = XFS_ERROR(EFAULT);

	kfree(attr_name);
 out_kfree_ops:
	kfree(ops);
 out_dput:
	dput(dentry);
	return -error;
}

int xfs_ioc_space( struct xfs_inode	*ip, struct inode		*inode, struct file		*filp, int			ioflags, unsigned int		cmd, xfs_flock64_t		*bf)






{
	struct xfs_mount	*mp = ip->i_mount;
	struct xfs_trans	*tp;
	struct iattr		iattr;
	bool			setprealloc = false;
	bool			clrprealloc = false;
	int			error;

	
	if (!xfs_sb_version_hasextflgbit(&ip->i_mount->m_sb) && !capable(CAP_SYS_ADMIN))
		return -XFS_ERROR(EPERM);

	if (inode->i_flags & (S_IMMUTABLE|S_APPEND))
		return -XFS_ERROR(EPERM);

	if (!(filp->f_mode & FMODE_WRITE))
		return -XFS_ERROR(EBADF);

	if (!S_ISREG(inode->i_mode))
		return -XFS_ERROR(EINVAL);

	error = mnt_want_write_file(filp);
	if (error)
		return error;

	xfs_ilock(ip, XFS_IOLOCK_EXCL);

	switch (bf->l_whence) {
	case 0: 
		break;
	case 1: 
		bf->l_start += filp->f_pos;
		break;
	case 2: 
		bf->l_start += XFS_ISIZE(ip);
		break;
	default:
		error = XFS_ERROR(EINVAL);
		goto out_unlock;
	}

	
	switch (cmd) {
	case XFS_IOC_ZERO_RANGE:
	case XFS_IOC_RESVSP:
	case XFS_IOC_RESVSP64:
	case XFS_IOC_UNRESVSP:
	case XFS_IOC_UNRESVSP64:
		if (bf->l_len <= 0) {
			error = XFS_ERROR(EINVAL);
			goto out_unlock;
		}
		break;
	default:
		bf->l_len = 0;
		break;
	}

	if (bf->l_start < 0 || bf->l_start > mp->m_super->s_maxbytes || bf->l_start + bf->l_len < 0 || bf->l_start + bf->l_len >= mp->m_super->s_maxbytes) {


		error = XFS_ERROR(EINVAL);
		goto out_unlock;
	}

	switch (cmd) {
	case XFS_IOC_ZERO_RANGE:
		error = xfs_zero_file_space(ip, bf->l_start, bf->l_len);
		if (!error)
			setprealloc = true;
		break;
	case XFS_IOC_RESVSP:
	case XFS_IOC_RESVSP64:
		error = xfs_alloc_file_space(ip, bf->l_start, bf->l_len, XFS_BMAPI_PREALLOC);
		if (!error)
			setprealloc = true;
		break;
	case XFS_IOC_UNRESVSP:
	case XFS_IOC_UNRESVSP64:
		error = xfs_free_file_space(ip, bf->l_start, bf->l_len);
		break;
	case XFS_IOC_ALLOCSP:
	case XFS_IOC_ALLOCSP64:
	case XFS_IOC_FREESP:
	case XFS_IOC_FREESP64:
		if (bf->l_start > XFS_ISIZE(ip)) {
			error = xfs_alloc_file_space(ip, XFS_ISIZE(ip), bf->l_start - XFS_ISIZE(ip), 0);
			if (error)
				goto out_unlock;
		}

		iattr.ia_valid = ATTR_SIZE;
		iattr.ia_size = bf->l_start;

		error = xfs_setattr_size(ip, &iattr);
		if (!error)
			clrprealloc = true;
		break;
	default:
		ASSERT(0);
		error = XFS_ERROR(EINVAL);
	}

	if (error)
		goto out_unlock;

	tp = xfs_trans_alloc(mp, XFS_TRANS_WRITEID);
	error = xfs_trans_reserve(tp, &M_RES(mp)->tr_writeid, 0, 0);
	if (error) {
		xfs_trans_cancel(tp, 0);
		goto out_unlock;
	}

	xfs_ilock(ip, XFS_ILOCK_EXCL);
	xfs_trans_ijoin(tp, ip, XFS_ILOCK_EXCL);

	if (!(ioflags & IO_INVIS)) {
		ip->i_d.di_mode &= ~S_ISUID;
		if (ip->i_d.di_mode & S_IXGRP)
			ip->i_d.di_mode &= ~S_ISGID;
		xfs_trans_ichgtime(tp, ip, XFS_ICHGTIME_MOD | XFS_ICHGTIME_CHG);
	}

	if (setprealloc)
		ip->i_d.di_flags |= XFS_DIFLAG_PREALLOC;
	else if (clrprealloc)
		ip->i_d.di_flags &= ~XFS_DIFLAG_PREALLOC;

	xfs_trans_log_inode(tp, ip, XFS_ILOG_CORE);
	if (filp->f_flags & O_DSYNC)
		xfs_trans_set_sync(tp);
	error = xfs_trans_commit(tp, 0);

out_unlock:
	xfs_iunlock(ip, XFS_IOLOCK_EXCL);
	mnt_drop_write_file(filp);
	return -error;
}

STATIC int xfs_ioc_bulkstat( xfs_mount_t		*mp, unsigned int		cmd, void			__user *arg)



{
	xfs_fsop_bulkreq_t	bulkreq;
	int			count;	
	xfs_ino_t		inlast;	
	int			done;
	int			error;

	
	

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (XFS_FORCED_SHUTDOWN(mp))
		return -XFS_ERROR(EIO);

	if (copy_from_user(&bulkreq, arg, sizeof(xfs_fsop_bulkreq_t)))
		return -XFS_ERROR(EFAULT);

	if (copy_from_user(&inlast, bulkreq.lastip, sizeof(__s64)))
		return -XFS_ERROR(EFAULT);

	if ((count = bulkreq.icount) <= 0)
		return -XFS_ERROR(EINVAL);

	if (bulkreq.ubuffer == NULL)
		return -XFS_ERROR(EINVAL);

	if (cmd == XFS_IOC_FSINUMBERS)
		error = xfs_inumbers(mp, &inlast, &count, bulkreq.ubuffer, xfs_inumbers_fmt);
	else if (cmd == XFS_IOC_FSBULKSTAT_SINGLE)
		error = xfs_bulkstat_single(mp, &inlast, bulkreq.ubuffer, &done);
	else	 error = xfs_bulkstat(mp, &inlast, &count, xfs_bulkstat_one, sizeof(xfs_bstat_t), bulkreq.ubuffer, &done);



	if (error)
		return -error;

	if (bulkreq.ocount != NULL) {
		if (copy_to_user(bulkreq.lastip, &inlast, sizeof(xfs_ino_t)))
			return -XFS_ERROR(EFAULT);

		if (copy_to_user(bulkreq.ocount, &count, sizeof(count)))
			return -XFS_ERROR(EFAULT);
	}

	return 0;
}

STATIC int xfs_ioc_fsgeometry_v1( xfs_mount_t		*mp, void			__user *arg)


{
	xfs_fsop_geom_t         fsgeo;
	int			error;

	error = xfs_fs_geometry(mp, &fsgeo, 3);
	if (error)
		return -error;

	
	if (copy_to_user(arg, &fsgeo, sizeof(xfs_fsop_geom_v1_t)))
		return -XFS_ERROR(EFAULT);
	return 0;
}

STATIC int xfs_ioc_fsgeometry( xfs_mount_t		*mp, void			__user *arg)


{
	xfs_fsop_geom_t		fsgeo;
	int			error;

	error = xfs_fs_geometry(mp, &fsgeo, 4);
	if (error)
		return -error;

	if (copy_to_user(arg, &fsgeo, sizeof(fsgeo)))
		return -XFS_ERROR(EFAULT);
	return 0;
}



STATIC unsigned int xfs_merge_ioc_xflags( unsigned int	flags, unsigned int	start)


{
	unsigned int	xflags = start;

	if (flags & FS_IMMUTABLE_FL)
		xflags |= XFS_XFLAG_IMMUTABLE;
	else xflags &= ~XFS_XFLAG_IMMUTABLE;
	if (flags & FS_APPEND_FL)
		xflags |= XFS_XFLAG_APPEND;
	else xflags &= ~XFS_XFLAG_APPEND;
	if (flags & FS_SYNC_FL)
		xflags |= XFS_XFLAG_SYNC;
	else xflags &= ~XFS_XFLAG_SYNC;
	if (flags & FS_NOATIME_FL)
		xflags |= XFS_XFLAG_NOATIME;
	else xflags &= ~XFS_XFLAG_NOATIME;
	if (flags & FS_NODUMP_FL)
		xflags |= XFS_XFLAG_NODUMP;
	else xflags &= ~XFS_XFLAG_NODUMP;

	return xflags;
}

STATIC unsigned int xfs_di2lxflags( __uint16_t	di_flags)

{
	unsigned int	flags = 0;

	if (di_flags & XFS_DIFLAG_IMMUTABLE)
		flags |= FS_IMMUTABLE_FL;
	if (di_flags & XFS_DIFLAG_APPEND)
		flags |= FS_APPEND_FL;
	if (di_flags & XFS_DIFLAG_SYNC)
		flags |= FS_SYNC_FL;
	if (di_flags & XFS_DIFLAG_NOATIME)
		flags |= FS_NOATIME_FL;
	if (di_flags & XFS_DIFLAG_NODUMP)
		flags |= FS_NODUMP_FL;
	return flags;
}

STATIC int xfs_ioc_fsgetxattr( xfs_inode_t		*ip, int			attr, void			__user *arg)



{
	struct fsxattr		fa;

	memset(&fa, 0, sizeof(struct fsxattr));

	xfs_ilock(ip, XFS_ILOCK_SHARED);
	fa.fsx_xflags = xfs_ip2xflags(ip);
	fa.fsx_extsize = ip->i_d.di_extsize << ip->i_mount->m_sb.sb_blocklog;
	fa.fsx_projid = xfs_get_projid(ip);

	if (attr) {
		if (ip->i_afp) {
			if (ip->i_afp->if_flags & XFS_IFEXTENTS)
				fa.fsx_nextents = ip->i_afp->if_bytes / sizeof(xfs_bmbt_rec_t);
			else fa.fsx_nextents = ip->i_d.di_anextents;
		} else fa.fsx_nextents = 0;
	} else {
		if (ip->i_df.if_flags & XFS_IFEXTENTS)
			fa.fsx_nextents = ip->i_df.if_bytes / sizeof(xfs_bmbt_rec_t);
		else fa.fsx_nextents = ip->i_d.di_nextents;
	}
	xfs_iunlock(ip, XFS_ILOCK_SHARED);

	if (copy_to_user(arg, &fa, sizeof(fa)))
		return -EFAULT;
	return 0;
}

STATIC void xfs_set_diflags( struct xfs_inode	*ip, unsigned int		xflags)


{
	unsigned int		di_flags;

	
	di_flags = (ip->i_d.di_flags & XFS_DIFLAG_PREALLOC);
	if (xflags & XFS_XFLAG_IMMUTABLE)
		di_flags |= XFS_DIFLAG_IMMUTABLE;
	if (xflags & XFS_XFLAG_APPEND)
		di_flags |= XFS_DIFLAG_APPEND;
	if (xflags & XFS_XFLAG_SYNC)
		di_flags |= XFS_DIFLAG_SYNC;
	if (xflags & XFS_XFLAG_NOATIME)
		di_flags |= XFS_DIFLAG_NOATIME;
	if (xflags & XFS_XFLAG_NODUMP)
		di_flags |= XFS_DIFLAG_NODUMP;
	if (xflags & XFS_XFLAG_PROJINHERIT)
		di_flags |= XFS_DIFLAG_PROJINHERIT;
	if (xflags & XFS_XFLAG_NODEFRAG)
		di_flags |= XFS_DIFLAG_NODEFRAG;
	if (xflags & XFS_XFLAG_FILESTREAM)
		di_flags |= XFS_DIFLAG_FILESTREAM;
	if (S_ISDIR(ip->i_d.di_mode)) {
		if (xflags & XFS_XFLAG_RTINHERIT)
			di_flags |= XFS_DIFLAG_RTINHERIT;
		if (xflags & XFS_XFLAG_NOSYMLINKS)
			di_flags |= XFS_DIFLAG_NOSYMLINKS;
		if (xflags & XFS_XFLAG_EXTSZINHERIT)
			di_flags |= XFS_DIFLAG_EXTSZINHERIT;
	} else if (S_ISREG(ip->i_d.di_mode)) {
		if (xflags & XFS_XFLAG_REALTIME)
			di_flags |= XFS_DIFLAG_REALTIME;
		if (xflags & XFS_XFLAG_EXTSIZE)
			di_flags |= XFS_DIFLAG_EXTSIZE;
	}

	ip->i_d.di_flags = di_flags;
}

STATIC void xfs_diflags_to_linux( struct xfs_inode	*ip)

{
	struct inode		*inode = VFS_I(ip);
	unsigned int		xflags = xfs_ip2xflags(ip);

	if (xflags & XFS_XFLAG_IMMUTABLE)
		inode->i_flags |= S_IMMUTABLE;
	else inode->i_flags &= ~S_IMMUTABLE;
	if (xflags & XFS_XFLAG_APPEND)
		inode->i_flags |= S_APPEND;
	else inode->i_flags &= ~S_APPEND;
	if (xflags & XFS_XFLAG_SYNC)
		inode->i_flags |= S_SYNC;
	else inode->i_flags &= ~S_SYNC;
	if (xflags & XFS_XFLAG_NOATIME)
		inode->i_flags |= S_NOATIME;
	else inode->i_flags &= ~S_NOATIME;
}






STATIC int xfs_ioctl_setattr( xfs_inode_t		*ip, struct fsxattr		*fa, int			mask)



{
	struct xfs_mount	*mp = ip->i_mount;
	struct xfs_trans	*tp;
	unsigned int		lock_flags = 0;
	struct xfs_dquot	*udqp = NULL;
	struct xfs_dquot	*pdqp = NULL;
	struct xfs_dquot	*olddquot = NULL;
	int			code;

	trace_xfs_ioctl_setattr(ip);

	if (mp->m_flags & XFS_MOUNT_RDONLY)
		return XFS_ERROR(EROFS);
	if (XFS_FORCED_SHUTDOWN(mp))
		return XFS_ERROR(EIO);

	
	if ((mask & FSX_PROJID) && (fa->fsx_projid > (__uint16_t)-1) && !xfs_sb_version_hasprojid32bit(&ip->i_mount->m_sb))
		return XFS_ERROR(EINVAL);

	
	if (XFS_IS_QUOTA_ON(mp) && (mask & FSX_PROJID)) {
		code = xfs_qm_vop_dqalloc(ip, ip->i_d.di_uid, ip->i_d.di_gid, fa->fsx_projid, XFS_QMOPT_PQUOTA, &udqp, NULL, &pdqp);

		if (code)
			return code;
	}

	
	tp = xfs_trans_alloc(mp, XFS_TRANS_SETATTR_NOT_SIZE);
	code = xfs_trans_reserve(tp, &M_RES(mp)->tr_ichange, 0, 0);
	if (code)
		goto error_return;

	lock_flags = XFS_ILOCK_EXCL;
	xfs_ilock(ip, lock_flags);

	
	if (!inode_owner_or_capable(VFS_I(ip))) {
		code = XFS_ERROR(EPERM);
		goto error_return;
	}

	
	if (mask & FSX_PROJID) {
		if (current_user_ns() != &init_user_ns) {
			code = XFS_ERROR(EINVAL);
			goto error_return;
		}

		if (XFS_IS_QUOTA_RUNNING(mp) && XFS_IS_PQUOTA_ON(mp) && xfs_get_projid(ip) != fa->fsx_projid) {

			ASSERT(tp);
			code = xfs_qm_vop_chown_reserve(tp, ip, udqp, NULL, pdqp, capable(CAP_FOWNER) ? XFS_QMOPT_FORCE_RES : 0);

			if (code)	
				goto error_return;
		}
	}

	if (mask & FSX_EXTSIZE) {
		
		if (ip->i_d.di_nextents && ((ip->i_d.di_extsize << mp->m_sb.sb_blocklog) != fa->fsx_extsize)) {

			code = XFS_ERROR(EINVAL);	
			goto error_return;
		}

		
		if (fa->fsx_extsize != 0) {
			xfs_extlen_t    size;
			xfs_fsblock_t   extsize_fsb;

			extsize_fsb = XFS_B_TO_FSB(mp, fa->fsx_extsize);
			if (extsize_fsb > MAXEXTLEN) {
				code = XFS_ERROR(EINVAL);
				goto error_return;
			}

			if (XFS_IS_REALTIME_INODE(ip) || ((mask & FSX_XFLAGS) && (fa->fsx_xflags & XFS_XFLAG_REALTIME))) {

				size = mp->m_sb.sb_rextsize << mp->m_sb.sb_blocklog;
			} else {
				size = mp->m_sb.sb_blocksize;
				if (extsize_fsb > mp->m_sb.sb_agblocks / 2) {
					code = XFS_ERROR(EINVAL);
					goto error_return;
				}
			}

			if (fa->fsx_extsize % size) {
				code = XFS_ERROR(EINVAL);
				goto error_return;
			}
		}
	}


	if (mask & FSX_XFLAGS) {
		
		if ((ip->i_d.di_nextents || ip->i_delayed_blks) && (XFS_IS_REALTIME_INODE(ip)) != (fa->fsx_xflags & XFS_XFLAG_REALTIME)) {

			code = XFS_ERROR(EINVAL);	
			goto error_return;
		}

		
		if ((fa->fsx_xflags & XFS_XFLAG_REALTIME)) {
			if ((mp->m_sb.sb_rblocks == 0) || (mp->m_sb.sb_rextsize == 0) || (ip->i_d.di_extsize % mp->m_sb.sb_rextsize)) {

				code = XFS_ERROR(EINVAL);
				goto error_return;
			}
		}

		
		if ((ip->i_d.di_flags & (XFS_DIFLAG_IMMUTABLE|XFS_DIFLAG_APPEND) || (fa->fsx_xflags & (XFS_XFLAG_IMMUTABLE | XFS_XFLAG_APPEND))) && !capable(CAP_LINUX_IMMUTABLE)) {



			code = XFS_ERROR(EPERM);
			goto error_return;
		}
	}

	xfs_trans_ijoin(tp, ip, 0);

	
	if (mask & FSX_PROJID) {
		
		if ((ip->i_d.di_mode & (S_ISUID|S_ISGID)) && !inode_capable(VFS_I(ip), CAP_FSETID))
			ip->i_d.di_mode &= ~(S_ISUID|S_ISGID);

		
		if (xfs_get_projid(ip) != fa->fsx_projid) {
			if (XFS_IS_QUOTA_RUNNING(mp) && XFS_IS_PQUOTA_ON(mp)) {
				olddquot = xfs_qm_vop_chown(tp, ip, &ip->i_pdquot, pdqp);
			}
			xfs_set_projid(ip, fa->fsx_projid);

			
			if (ip->i_d.di_version == 1)
				xfs_bump_ino_vers2(tp, ip);
		}

	}

	if (mask & FSX_EXTSIZE)
		ip->i_d.di_extsize = fa->fsx_extsize >> mp->m_sb.sb_blocklog;
	if (mask & FSX_XFLAGS) {
		xfs_set_diflags(ip, fa->fsx_xflags);
		xfs_diflags_to_linux(ip);
	}

	xfs_trans_ichgtime(tp, ip, XFS_ICHGTIME_CHG);
	xfs_trans_log_inode(tp, ip, XFS_ILOG_CORE);

	XFS_STATS_INC(xs_ig_attrchg);

	
	if (mp->m_flags & XFS_MOUNT_WSYNC)
		xfs_trans_set_sync(tp);
	code = xfs_trans_commit(tp, 0);
	xfs_iunlock(ip, lock_flags);

	
	xfs_qm_dqrele(olddquot);
	xfs_qm_dqrele(udqp);
	xfs_qm_dqrele(pdqp);

	return code;

 error_return:
	xfs_qm_dqrele(udqp);
	xfs_qm_dqrele(pdqp);
	xfs_trans_cancel(tp, 0);
	if (lock_flags)
		xfs_iunlock(ip, lock_flags);
	return code;
}

STATIC int xfs_ioc_fssetxattr( xfs_inode_t		*ip, struct file		*filp, void			__user *arg)



{
	struct fsxattr		fa;
	unsigned int		mask;
	int error;

	if (copy_from_user(&fa, arg, sizeof(fa)))
		return -EFAULT;

	mask = FSX_XFLAGS | FSX_EXTSIZE | FSX_PROJID;
	if (filp->f_flags & (O_NDELAY|O_NONBLOCK))
		mask |= FSX_NONBLOCK;

	error = mnt_want_write_file(filp);
	if (error)
		return error;
	error = xfs_ioctl_setattr(ip, &fa, mask);
	mnt_drop_write_file(filp);
	return -error;
}

STATIC int xfs_ioc_getxflags( xfs_inode_t		*ip, void			__user *arg)


{
	unsigned int		flags;

	flags = xfs_di2lxflags(ip->i_d.di_flags);
	if (copy_to_user(arg, &flags, sizeof(flags)))
		return -EFAULT;
	return 0;
}

STATIC int xfs_ioc_setxflags( xfs_inode_t		*ip, struct file		*filp, void			__user *arg)



{
	struct fsxattr		fa;
	unsigned int		flags;
	unsigned int		mask;
	int error;

	if (copy_from_user(&flags, arg, sizeof(flags)))
		return -EFAULT;

	if (flags & ~(FS_IMMUTABLE_FL | FS_APPEND_FL |  FS_NOATIME_FL | FS_NODUMP_FL | FS_SYNC_FL)

		return -EOPNOTSUPP;

	mask = FSX_XFLAGS;
	if (filp->f_flags & (O_NDELAY|O_NONBLOCK))
		mask |= FSX_NONBLOCK;
	fa.fsx_xflags = xfs_merge_ioc_xflags(flags, xfs_ip2xflags(ip));

	error = mnt_want_write_file(filp);
	if (error)
		return error;
	error = xfs_ioctl_setattr(ip, &fa, mask);
	mnt_drop_write_file(filp);
	return -error;
}

STATIC int xfs_getbmap_format(void **ap, struct getbmapx *bmv, int *full)
{
	struct getbmap __user	*base = *ap;

	
	if (copy_to_user(base, bmv, sizeof(struct getbmap)))
		return XFS_ERROR(EFAULT);

	*ap += sizeof(struct getbmap);
	return 0;
}

STATIC int xfs_ioc_getbmap( struct xfs_inode	*ip, int			ioflags, unsigned int		cmd, void			__user *arg)




{
	struct getbmapx		bmx;
	int			error;

	if (copy_from_user(&bmx, arg, sizeof(struct getbmapx)))
		return -XFS_ERROR(EFAULT);

	if (bmx.bmv_count < 2)
		return -XFS_ERROR(EINVAL);

	bmx.bmv_iflags = (cmd == XFS_IOC_GETBMAPA ? BMV_IF_ATTRFORK : 0);
	if (ioflags & IO_INVIS)
		bmx.bmv_iflags |= BMV_IF_NO_DMAPI_READ;

	error = xfs_getbmap(ip, &bmx, xfs_getbmap_format, (struct getbmap *)arg+1);
	if (error)
		return -error;

	
	if (copy_to_user(arg, &bmx, sizeof(struct getbmap)))
		return -XFS_ERROR(EFAULT);
	return 0;
}

STATIC int xfs_getbmapx_format(void **ap, struct getbmapx *bmv, int *full)
{
	struct getbmapx __user	*base = *ap;

	if (copy_to_user(base, bmv, sizeof(struct getbmapx)))
		return XFS_ERROR(EFAULT);

	*ap += sizeof(struct getbmapx);
	return 0;
}

STATIC int xfs_ioc_getbmapx( struct xfs_inode	*ip, void			__user *arg)


{
	struct getbmapx		bmx;
	int			error;

	if (copy_from_user(&bmx, arg, sizeof(bmx)))
		return -XFS_ERROR(EFAULT);

	if (bmx.bmv_count < 2)
		return -XFS_ERROR(EINVAL);

	if (bmx.bmv_iflags & (~BMV_IF_VALID))
		return -XFS_ERROR(EINVAL);

	error = xfs_getbmap(ip, &bmx, xfs_getbmapx_format, (struct getbmapx *)arg+1);
	if (error)
		return -error;

	
	if (copy_to_user(arg, &bmx, sizeof(struct getbmapx)))
		return -XFS_ERROR(EFAULT);

	return 0;
}

int xfs_ioc_swapext( xfs_swapext_t	*sxp)

{
	xfs_inode_t     *ip, *tip;
	struct fd	f, tmp;
	int		error = 0;

	
	f = fdget((int)sxp->sx_fdtarget);
	if (!f.file) {
		error = XFS_ERROR(EINVAL);
		goto out;
	}

	if (!(f.file->f_mode & FMODE_WRITE) || !(f.file->f_mode & FMODE_READ) || (f.file->f_flags & O_APPEND)) {

		error = XFS_ERROR(EBADF);
		goto out_put_file;
	}

	tmp = fdget((int)sxp->sx_fdtmp);
	if (!tmp.file) {
		error = XFS_ERROR(EINVAL);
		goto out_put_file;
	}

	if (!(tmp.file->f_mode & FMODE_WRITE) || !(tmp.file->f_mode & FMODE_READ) || (tmp.file->f_flags & O_APPEND)) {

		error = XFS_ERROR(EBADF);
		goto out_put_tmp_file;
	}

	if (IS_SWAPFILE(file_inode(f.file)) || IS_SWAPFILE(file_inode(tmp.file))) {
		error = XFS_ERROR(EINVAL);
		goto out_put_tmp_file;
	}

	ip = XFS_I(file_inode(f.file));
	tip = XFS_I(file_inode(tmp.file));

	if (ip->i_mount != tip->i_mount) {
		error = XFS_ERROR(EINVAL);
		goto out_put_tmp_file;
	}

	if (ip->i_ino == tip->i_ino) {
		error = XFS_ERROR(EINVAL);
		goto out_put_tmp_file;
	}

	if (XFS_FORCED_SHUTDOWN(ip->i_mount)) {
		error = XFS_ERROR(EIO);
		goto out_put_tmp_file;
	}

	error = xfs_swap_extents(ip, tip, sxp);

 out_put_tmp_file:
	fdput(tmp);
 out_put_file:
	fdput(f);
 out:
	return error;
}


long xfs_file_ioctl( struct file		*filp, unsigned int		cmd, unsigned long		p)



{
	struct inode		*inode = file_inode(filp);
	struct xfs_inode	*ip = XFS_I(inode);
	struct xfs_mount	*mp = ip->i_mount;
	void			__user *arg = (void __user *)p;
	int			ioflags = 0;
	int			error;

	if (filp->f_mode & FMODE_NOCMTIME)
		ioflags |= IO_INVIS;

	trace_xfs_file_ioctl(ip);

	switch (cmd) {
	case FITRIM:
		return xfs_ioc_trim(mp, arg);
	case XFS_IOC_ALLOCSP:
	case XFS_IOC_FREESP:
	case XFS_IOC_RESVSP:
	case XFS_IOC_UNRESVSP:
	case XFS_IOC_ALLOCSP64:
	case XFS_IOC_FREESP64:
	case XFS_IOC_RESVSP64:
	case XFS_IOC_UNRESVSP64:
	case XFS_IOC_ZERO_RANGE: {
		xfs_flock64_t		bf;

		if (copy_from_user(&bf, arg, sizeof(bf)))
			return -XFS_ERROR(EFAULT);
		return xfs_ioc_space(ip, inode, filp, ioflags, cmd, &bf);
	}
	case XFS_IOC_DIOINFO: {
		struct dioattr	da;
		xfs_buftarg_t	*target = XFS_IS_REALTIME_INODE(ip) ? mp->m_rtdev_targp : mp->m_ddev_targp;


		da.d_mem =  da.d_miniosz = target->bt_logical_sectorsize;
		da.d_maxiosz = INT_MAX & ~(da.d_miniosz - 1);

		if (copy_to_user(arg, &da, sizeof(da)))
			return -XFS_ERROR(EFAULT);
		return 0;
	}

	case XFS_IOC_FSBULKSTAT_SINGLE:
	case XFS_IOC_FSBULKSTAT:
	case XFS_IOC_FSINUMBERS:
		return xfs_ioc_bulkstat(mp, cmd, arg);

	case XFS_IOC_FSGEOMETRY_V1:
		return xfs_ioc_fsgeometry_v1(mp, arg);

	case XFS_IOC_FSGEOMETRY:
		return xfs_ioc_fsgeometry(mp, arg);

	case XFS_IOC_GETVERSION:
		return put_user(inode->i_generation, (int __user *)arg);

	case XFS_IOC_FSGETXATTR:
		return xfs_ioc_fsgetxattr(ip, 0, arg);
	case XFS_IOC_FSGETXATTRA:
		return xfs_ioc_fsgetxattr(ip, 1, arg);
	case XFS_IOC_FSSETXATTR:
		return xfs_ioc_fssetxattr(ip, filp, arg);
	case XFS_IOC_GETXFLAGS:
		return xfs_ioc_getxflags(ip, arg);
	case XFS_IOC_SETXFLAGS:
		return xfs_ioc_setxflags(ip, filp, arg);

	case XFS_IOC_FSSETDM: {
		struct fsdmidata	dmi;

		if (copy_from_user(&dmi, arg, sizeof(dmi)))
			return -XFS_ERROR(EFAULT);

		error = mnt_want_write_file(filp);
		if (error)
			return error;

		error = xfs_set_dmattrs(ip, dmi.fsd_dmevmask, dmi.fsd_dmstate);
		mnt_drop_write_file(filp);
		return -error;
	}

	case XFS_IOC_GETBMAP:
	case XFS_IOC_GETBMAPA:
		return xfs_ioc_getbmap(ip, ioflags, cmd, arg);

	case XFS_IOC_GETBMAPX:
		return xfs_ioc_getbmapx(ip, arg);

	case XFS_IOC_FD_TO_HANDLE:
	case XFS_IOC_PATH_TO_HANDLE:
	case XFS_IOC_PATH_TO_FSHANDLE: {
		xfs_fsop_handlereq_t	hreq;

		if (copy_from_user(&hreq, arg, sizeof(hreq)))
			return -XFS_ERROR(EFAULT);
		return xfs_find_handle(cmd, &hreq);
	}
	case XFS_IOC_OPEN_BY_HANDLE: {
		xfs_fsop_handlereq_t	hreq;

		if (copy_from_user(&hreq, arg, sizeof(xfs_fsop_handlereq_t)))
			return -XFS_ERROR(EFAULT);
		return xfs_open_by_handle(filp, &hreq);
	}
	case XFS_IOC_FSSETDM_BY_HANDLE:
		return xfs_fssetdm_by_handle(filp, arg);

	case XFS_IOC_READLINK_BY_HANDLE: {
		xfs_fsop_handlereq_t	hreq;

		if (copy_from_user(&hreq, arg, sizeof(xfs_fsop_handlereq_t)))
			return -XFS_ERROR(EFAULT);
		return xfs_readlink_by_handle(filp, &hreq);
	}
	case XFS_IOC_ATTRLIST_BY_HANDLE:
		return xfs_attrlist_by_handle(filp, arg);

	case XFS_IOC_ATTRMULTI_BY_HANDLE:
		return xfs_attrmulti_by_handle(filp, arg);

	case XFS_IOC_SWAPEXT: {
		struct xfs_swapext	sxp;

		if (copy_from_user(&sxp, arg, sizeof(xfs_swapext_t)))
			return -XFS_ERROR(EFAULT);
		error = mnt_want_write_file(filp);
		if (error)
			return error;
		error = xfs_ioc_swapext(&sxp);
		mnt_drop_write_file(filp);
		return -error;
	}

	case XFS_IOC_FSCOUNTS: {
		xfs_fsop_counts_t out;

		error = xfs_fs_counts(mp, &out);
		if (error)
			return -error;

		if (copy_to_user(arg, &out, sizeof(out)))
			return -XFS_ERROR(EFAULT);
		return 0;
	}

	case XFS_IOC_SET_RESBLKS: {
		xfs_fsop_resblks_t inout;
		__uint64_t	   in;

		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;

		if (mp->m_flags & XFS_MOUNT_RDONLY)
			return -XFS_ERROR(EROFS);

		if (copy_from_user(&inout, arg, sizeof(inout)))
			return -XFS_ERROR(EFAULT);

		error = mnt_want_write_file(filp);
		if (error)
			return error;

		
		in = inout.resblks;
		error = xfs_reserve_blocks(mp, &in, &inout);
		mnt_drop_write_file(filp);
		if (error)
			return -error;

		if (copy_to_user(arg, &inout, sizeof(inout)))
			return -XFS_ERROR(EFAULT);
		return 0;
	}

	case XFS_IOC_GET_RESBLKS: {
		xfs_fsop_resblks_t out;

		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;

		error = xfs_reserve_blocks(mp, NULL, &out);
		if (error)
			return -error;

		if (copy_to_user(arg, &out, sizeof(out)))
			return -XFS_ERROR(EFAULT);

		return 0;
	}

	case XFS_IOC_FSGROWFSDATA: {
		xfs_growfs_data_t in;

		if (copy_from_user(&in, arg, sizeof(in)))
			return -XFS_ERROR(EFAULT);

		error = mnt_want_write_file(filp);
		if (error)
			return error;
		error = xfs_growfs_data(mp, &in);
		mnt_drop_write_file(filp);
		return -error;
	}

	case XFS_IOC_FSGROWFSLOG: {
		xfs_growfs_log_t in;

		if (copy_from_user(&in, arg, sizeof(in)))
			return -XFS_ERROR(EFAULT);

		error = mnt_want_write_file(filp);
		if (error)
			return error;
		error = xfs_growfs_log(mp, &in);
		mnt_drop_write_file(filp);
		return -error;
	}

	case XFS_IOC_FSGROWFSRT: {
		xfs_growfs_rt_t in;

		if (copy_from_user(&in, arg, sizeof(in)))
			return -XFS_ERROR(EFAULT);

		error = mnt_want_write_file(filp);
		if (error)
			return error;
		error = xfs_growfs_rt(mp, &in);
		mnt_drop_write_file(filp);
		return -error;
	}

	case XFS_IOC_GOINGDOWN: {
		__uint32_t in;

		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;

		if (get_user(in, (__uint32_t __user *)arg))
			return -XFS_ERROR(EFAULT);

		error = xfs_fs_goingdown(mp, in);
		return -error;
	}

	case XFS_IOC_ERROR_INJECTION: {
		xfs_error_injection_t in;

		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;

		if (copy_from_user(&in, arg, sizeof(in)))
			return -XFS_ERROR(EFAULT);

		error = xfs_errortag_add(in.errtag, mp);
		return -error;
	}

	case XFS_IOC_ERROR_CLEARALL:
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;

		error = xfs_errortag_clearall(mp, 1);
		return -error;

	case XFS_IOC_FREE_EOFBLOCKS: {
		struct xfs_fs_eofblocks eofb;
		struct xfs_eofblocks keofb;

		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;

		if (mp->m_flags & XFS_MOUNT_RDONLY)
			return -XFS_ERROR(EROFS);

		if (copy_from_user(&eofb, arg, sizeof(eofb)))
			return -XFS_ERROR(EFAULT);

		error = xfs_fs_eofblocks_from_user(&eofb, &keofb);
		if (error)
			return -error;

		return -xfs_icache_free_eofblocks(mp, &keofb);
	}

	default:
		return -ENOTTY;
	}
}
