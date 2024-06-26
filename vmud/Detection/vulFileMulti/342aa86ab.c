






















unsigned int pipe_max_size = 1048576;


unsigned int pipe_min_size = PAGE_SIZE;



static void pipe_lock_nested(struct pipe_inode_info *pipe, int subclass)
{
	if (pipe->inode)
		mutex_lock_nested(&pipe->inode->i_mutex, subclass);
}

void pipe_lock(struct pipe_inode_info *pipe)
{
	
	pipe_lock_nested(pipe, I_MUTEX_PARENT);
}
EXPORT_SYMBOL(pipe_lock);

void pipe_unlock(struct pipe_inode_info *pipe)
{
	if (pipe->inode)
		mutex_unlock(&pipe->inode->i_mutex);
}
EXPORT_SYMBOL(pipe_unlock);

void pipe_double_lock(struct pipe_inode_info *pipe1, struct pipe_inode_info *pipe2)
{
	BUG_ON(pipe1 == pipe2);

	if (pipe1 < pipe2) {
		pipe_lock_nested(pipe1, I_MUTEX_PARENT);
		pipe_lock_nested(pipe2, I_MUTEX_CHILD);
	} else {
		pipe_lock_nested(pipe2, I_MUTEX_PARENT);
		pipe_lock_nested(pipe1, I_MUTEX_CHILD);
	}
}


void pipe_wait(struct pipe_inode_info *pipe)
{
	DEFINE_WAIT(wait);

	
	prepare_to_wait(&pipe->wait, &wait, TASK_INTERRUPTIBLE);
	pipe_unlock(pipe);
	schedule();
	finish_wait(&pipe->wait, &wait);
	pipe_lock(pipe);
}

static int pipe_iov_copy_from_user(void *to, struct iovec *iov, unsigned long len, int atomic)

{
	unsigned long copy;

	while (len > 0) {
		while (!iov->iov_len)
			iov++;
		copy = min_t(unsigned long, len, iov->iov_len);

		if (atomic) {
			if (__copy_from_user_inatomic(to, iov->iov_base, copy))
				return -EFAULT;
		} else {
			if (copy_from_user(to, iov->iov_base, copy))
				return -EFAULT;
		}
		to += copy;
		len -= copy;
		iov->iov_base += copy;
		iov->iov_len -= copy;
	}
	return 0;
}

static int pipe_iov_copy_to_user(struct iovec *iov, const void *from, unsigned long len, int atomic)

{
	unsigned long copy;

	while (len > 0) {
		while (!iov->iov_len)
			iov++;
		copy = min_t(unsigned long, len, iov->iov_len);

		if (atomic) {
			if (__copy_to_user_inatomic(iov->iov_base, from, copy))
				return -EFAULT;
		} else {
			if (copy_to_user(iov->iov_base, from, copy))
				return -EFAULT;
		}
		from += copy;
		len -= copy;
		iov->iov_base += copy;
		iov->iov_len -= copy;
	}
	return 0;
}


static int iov_fault_in_pages_write(struct iovec *iov, unsigned long len)
{
	while (!iov->iov_len)
		iov++;

	while (len > 0) {
		unsigned long this_len;

		this_len = min_t(unsigned long, len, iov->iov_len);
		if (fault_in_pages_writeable(iov->iov_base, this_len))
			break;

		len -= this_len;
		iov++;
	}

	return len;
}


static void iov_fault_in_pages_read(struct iovec *iov, unsigned long len)
{
	while (!iov->iov_len)
		iov++;

	while (len > 0) {
		unsigned long this_len;

		this_len = min_t(unsigned long, len, iov->iov_len);
		fault_in_pages_readable(iov->iov_base, this_len);
		len -= this_len;
		iov++;
	}
}

static void anon_pipe_buf_release(struct pipe_inode_info *pipe, struct pipe_buffer *buf)
{
	struct page *page = buf->page;

	
	if (page_count(page) == 1 && !pipe->tmp_page)
		pipe->tmp_page = page;
	else page_cache_release(page);
}


void *generic_pipe_buf_map(struct pipe_inode_info *pipe, struct pipe_buffer *buf, int atomic)
{
	if (atomic) {
		buf->flags |= PIPE_BUF_FLAG_ATOMIC;
		return kmap_atomic(buf->page, KM_USER0);
	}

	return kmap(buf->page);
}
EXPORT_SYMBOL(generic_pipe_buf_map);


void generic_pipe_buf_unmap(struct pipe_inode_info *pipe, struct pipe_buffer *buf, void *map_data)
{
	if (buf->flags & PIPE_BUF_FLAG_ATOMIC) {
		buf->flags &= ~PIPE_BUF_FLAG_ATOMIC;
		kunmap_atomic(map_data, KM_USER0);
	} else kunmap(buf->page);
}
EXPORT_SYMBOL(generic_pipe_buf_unmap);


int generic_pipe_buf_steal(struct pipe_inode_info *pipe, struct pipe_buffer *buf)
{
	struct page *page = buf->page;

	
	if (page_count(page) == 1) {
		lock_page(page);
		return 0;
	}

	return 1;
}
EXPORT_SYMBOL(generic_pipe_buf_steal);


void generic_pipe_buf_get(struct pipe_inode_info *pipe, struct pipe_buffer *buf)
{
	page_cache_get(buf->page);
}
EXPORT_SYMBOL(generic_pipe_buf_get);


int generic_pipe_buf_confirm(struct pipe_inode_info *info, struct pipe_buffer *buf)
{
	return 0;
}
EXPORT_SYMBOL(generic_pipe_buf_confirm);


void generic_pipe_buf_release(struct pipe_inode_info *pipe, struct pipe_buffer *buf)
{
	page_cache_release(buf->page);
}
EXPORT_SYMBOL(generic_pipe_buf_release);

static const struct pipe_buf_operations anon_pipe_buf_ops = {
	.can_merge = 1, .map = generic_pipe_buf_map, .unmap = generic_pipe_buf_unmap, .confirm = generic_pipe_buf_confirm, .release = anon_pipe_buf_release, .steal = generic_pipe_buf_steal, .get = generic_pipe_buf_get, };







static const struct pipe_buf_operations packet_pipe_buf_ops = {
	.can_merge = 0, .map = generic_pipe_buf_map, .unmap = generic_pipe_buf_unmap, .confirm = generic_pipe_buf_confirm, .release = anon_pipe_buf_release, .steal = generic_pipe_buf_steal, .get = generic_pipe_buf_get, };







static ssize_t pipe_read(struct kiocb *iocb, const struct iovec *_iov, unsigned long nr_segs, loff_t pos)

{
	struct file *filp = iocb->ki_filp;
	struct inode *inode = filp->f_path.dentry->d_inode;
	struct pipe_inode_info *pipe;
	int do_wakeup;
	ssize_t ret;
	struct iovec *iov = (struct iovec *)_iov;
	size_t total_len;

	total_len = iov_length(iov, nr_segs);
	
	if (unlikely(total_len == 0))
		return 0;

	do_wakeup = 0;
	ret = 0;
	mutex_lock(&inode->i_mutex);
	pipe = inode->i_pipe;
	for (;;) {
		int bufs = pipe->nrbufs;
		if (bufs) {
			int curbuf = pipe->curbuf;
			struct pipe_buffer *buf = pipe->bufs + curbuf;
			const struct pipe_buf_operations *ops = buf->ops;
			void *addr;
			size_t chars = buf->len;
			int error, atomic;

			if (chars > total_len)
				chars = total_len;

			error = ops->confirm(pipe, buf);
			if (error) {
				if (!ret)
					ret = error;
				break;
			}

			atomic = !iov_fault_in_pages_write(iov, chars);
redo:
			addr = ops->map(pipe, buf, atomic);
			error = pipe_iov_copy_to_user(iov, addr + buf->offset, chars, atomic);
			ops->unmap(pipe, buf, addr);
			if (unlikely(error)) {
				
				if (atomic) {
					atomic = 0;
					goto redo;
				}
				if (!ret)
					ret = error;
				break;
			}
			ret += chars;
			buf->offset += chars;
			buf->len -= chars;

			
			if (buf->flags & PIPE_BUF_FLAG_PACKET) {
				total_len = chars;
				buf->len = 0;
			}

			if (!buf->len) {
				buf->ops = NULL;
				ops->release(pipe, buf);
				curbuf = (curbuf + 1) & (pipe->buffers - 1);
				pipe->curbuf = curbuf;
				pipe->nrbufs = --bufs;
				do_wakeup = 1;
			}
			total_len -= chars;
			if (!total_len)
				break;	
		}
		if (bufs)	
			continue;
		if (!pipe->writers)
			break;
		if (!pipe->waiting_writers) {
			
			if (ret)
				break;
			if (filp->f_flags & O_NONBLOCK) {
				ret = -EAGAIN;
				break;
			}
		}
		if (signal_pending(current)) {
			if (!ret)
				ret = -ERESTARTSYS;
			break;
		}
		if (do_wakeup) {
			wake_up_interruptible_sync_poll(&pipe->wait, POLLOUT | POLLWRNORM);
 			kill_fasync(&pipe->fasync_writers, SIGIO, POLL_OUT);
		}
		pipe_wait(pipe);
	}
	mutex_unlock(&inode->i_mutex);

	
	if (do_wakeup) {
		wake_up_interruptible_sync_poll(&pipe->wait, POLLOUT | POLLWRNORM);
		kill_fasync(&pipe->fasync_writers, SIGIO, POLL_OUT);
	}
	if (ret > 0)
		file_accessed(filp);
	return ret;
}

static inline int is_packetized(struct file *file)
{
	return (file->f_flags & O_DIRECT) != 0;
}

static ssize_t pipe_write(struct kiocb *iocb, const struct iovec *_iov, unsigned long nr_segs, loff_t ppos)

{
	struct file *filp = iocb->ki_filp;
	struct inode *inode = filp->f_path.dentry->d_inode;
	struct pipe_inode_info *pipe;
	ssize_t ret;
	int do_wakeup;
	struct iovec *iov = (struct iovec *)_iov;
	size_t total_len;
	ssize_t chars;

	total_len = iov_length(iov, nr_segs);
	
	if (unlikely(total_len == 0))
		return 0;

	do_wakeup = 0;
	ret = 0;
	mutex_lock(&inode->i_mutex);
	pipe = inode->i_pipe;

	if (!pipe->readers) {
		send_sig(SIGPIPE, current, 0);
		ret = -EPIPE;
		goto out;
	}

	
	chars = total_len & (PAGE_SIZE-1); 
	if (pipe->nrbufs && chars != 0) {
		int lastbuf = (pipe->curbuf + pipe->nrbufs - 1) & (pipe->buffers - 1);
		struct pipe_buffer *buf = pipe->bufs + lastbuf;
		const struct pipe_buf_operations *ops = buf->ops;
		int offset = buf->offset + buf->len;

		if (ops->can_merge && offset + chars <= PAGE_SIZE) {
			int error, atomic = 1;
			void *addr;

			error = ops->confirm(pipe, buf);
			if (error)
				goto out;

			iov_fault_in_pages_read(iov, chars);
redo1:
			addr = ops->map(pipe, buf, atomic);
			error = pipe_iov_copy_from_user(offset + addr, iov, chars, atomic);
			ops->unmap(pipe, buf, addr);
			ret = error;
			do_wakeup = 1;
			if (error) {
				if (atomic) {
					atomic = 0;
					goto redo1;
				}
				goto out;
			}
			buf->len += chars;
			total_len -= chars;
			ret = chars;
			if (!total_len)
				goto out;
		}
	}

	for (;;) {
		int bufs;

		if (!pipe->readers) {
			send_sig(SIGPIPE, current, 0);
			if (!ret)
				ret = -EPIPE;
			break;
		}
		bufs = pipe->nrbufs;
		if (bufs < pipe->buffers) {
			int newbuf = (pipe->curbuf + bufs) & (pipe->buffers-1);
			struct pipe_buffer *buf = pipe->bufs + newbuf;
			struct page *page = pipe->tmp_page;
			char *src;
			int error, atomic = 1;

			if (!page) {
				page = alloc_page(GFP_HIGHUSER);
				if (unlikely(!page)) {
					ret = ret ? : -ENOMEM;
					break;
				}
				pipe->tmp_page = page;
			}
			
			do_wakeup = 1;
			chars = PAGE_SIZE;
			if (chars > total_len)
				chars = total_len;

			iov_fault_in_pages_read(iov, chars);
redo2:
			if (atomic)
				src = kmap_atomic(page, KM_USER0);
			else src = kmap(page);

			error = pipe_iov_copy_from_user(src, iov, chars, atomic);
			if (atomic)
				kunmap_atomic(src, KM_USER0);
			else kunmap(page);

			if (unlikely(error)) {
				if (atomic) {
					atomic = 0;
					goto redo2;
				}
				if (!ret)
					ret = error;
				break;
			}
			ret += chars;

			
			buf->page = page;
			buf->ops = &anon_pipe_buf_ops;
			buf->offset = 0;
			buf->len = chars;
			buf->flags = 0;
			if (is_packetized(filp)) {
				buf->ops = &packet_pipe_buf_ops;
				buf->flags = PIPE_BUF_FLAG_PACKET;
			}
			pipe->nrbufs = ++bufs;
			pipe->tmp_page = NULL;

			total_len -= chars;
			if (!total_len)
				break;
		}
		if (bufs < pipe->buffers)
			continue;
		if (filp->f_flags & O_NONBLOCK) {
			if (!ret)
				ret = -EAGAIN;
			break;
		}
		if (signal_pending(current)) {
			if (!ret)
				ret = -ERESTARTSYS;
			break;
		}
		if (do_wakeup) {
			wake_up_interruptible_sync_poll(&pipe->wait, POLLIN | POLLRDNORM);
			kill_fasync(&pipe->fasync_readers, SIGIO, POLL_IN);
			do_wakeup = 0;
		}
		pipe->waiting_writers++;
		pipe_wait(pipe);
		pipe->waiting_writers--;
	}
out:
	mutex_unlock(&inode->i_mutex);
	if (do_wakeup) {
		wake_up_interruptible_sync_poll(&pipe->wait, POLLIN | POLLRDNORM);
		kill_fasync(&pipe->fasync_readers, SIGIO, POLL_IN);
	}
	if (ret > 0)
		file_update_time(filp);
	return ret;
}

static ssize_t bad_pipe_r(struct file *filp, char __user *buf, size_t count, loff_t *ppos)
{
	return -EBADF;
}

static ssize_t bad_pipe_w(struct file *filp, const char __user *buf, size_t count, loff_t *ppos)

{
	return -EBADF;
}

static long pipe_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct inode *inode = filp->f_path.dentry->d_inode;
	struct pipe_inode_info *pipe;
	int count, buf, nrbufs;

	switch (cmd) {
		case FIONREAD:
			mutex_lock(&inode->i_mutex);
			pipe = inode->i_pipe;
			count = 0;
			buf = pipe->curbuf;
			nrbufs = pipe->nrbufs;
			while (--nrbufs >= 0) {
				count += pipe->bufs[buf].len;
				buf = (buf+1) & (pipe->buffers - 1);
			}
			mutex_unlock(&inode->i_mutex);

			return put_user(count, (int __user *)arg);
		default:
			return -EINVAL;
	}
}


static unsigned int pipe_poll(struct file *filp, poll_table *wait)
{
	unsigned int mask;
	struct inode *inode = filp->f_path.dentry->d_inode;
	struct pipe_inode_info *pipe = inode->i_pipe;
	int nrbufs;

	poll_wait(filp, &pipe->wait, wait);

	
	nrbufs = pipe->nrbufs;
	mask = 0;
	if (filp->f_mode & FMODE_READ) {
		mask = (nrbufs > 0) ? POLLIN | POLLRDNORM : 0;
		if (!pipe->writers && filp->f_version != pipe->w_counter)
			mask |= POLLHUP;
	}

	if (filp->f_mode & FMODE_WRITE) {
		mask |= (nrbufs < pipe->buffers) ? POLLOUT | POLLWRNORM : 0;
		
		if (!pipe->readers)
			mask |= POLLERR;
	}

	return mask;
}

static int pipe_release(struct inode *inode, int decr, int decw)
{
	struct pipe_inode_info *pipe;

	mutex_lock(&inode->i_mutex);
	pipe = inode->i_pipe;
	pipe->readers -= decr;
	pipe->writers -= decw;

	if (!pipe->readers && !pipe->writers) {
		free_pipe_info(inode);
	} else {
		wake_up_interruptible_sync_poll(&pipe->wait, POLLIN | POLLOUT | POLLRDNORM | POLLWRNORM | POLLERR | POLLHUP);
		kill_fasync(&pipe->fasync_readers, SIGIO, POLL_IN);
		kill_fasync(&pipe->fasync_writers, SIGIO, POLL_OUT);
	}
	mutex_unlock(&inode->i_mutex);

	return 0;
}

static int pipe_read_fasync(int fd, struct file *filp, int on)
{
	struct inode *inode = filp->f_path.dentry->d_inode;
	int retval;

	mutex_lock(&inode->i_mutex);
	retval = fasync_helper(fd, filp, on, &inode->i_pipe->fasync_readers);
	mutex_unlock(&inode->i_mutex);

	return retval;
}


static int pipe_write_fasync(int fd, struct file *filp, int on)
{
	struct inode *inode = filp->f_path.dentry->d_inode;
	int retval;

	mutex_lock(&inode->i_mutex);
	retval = fasync_helper(fd, filp, on, &inode->i_pipe->fasync_writers);
	mutex_unlock(&inode->i_mutex);

	return retval;
}


static int pipe_rdwr_fasync(int fd, struct file *filp, int on)
{
	struct inode *inode = filp->f_path.dentry->d_inode;
	struct pipe_inode_info *pipe = inode->i_pipe;
	int retval;

	mutex_lock(&inode->i_mutex);
	retval = fasync_helper(fd, filp, on, &pipe->fasync_readers);
	if (retval >= 0) {
		retval = fasync_helper(fd, filp, on, &pipe->fasync_writers);
		if (retval < 0) 
			fasync_helper(-1, filp, 0, &pipe->fasync_readers);
	}
	mutex_unlock(&inode->i_mutex);
	return retval;
}


static int pipe_read_release(struct inode *inode, struct file *filp)
{
	return pipe_release(inode, 1, 0);
}

static int pipe_write_release(struct inode *inode, struct file *filp)
{
	return pipe_release(inode, 0, 1);
}

static int pipe_rdwr_release(struct inode *inode, struct file *filp)
{
	int decr, decw;

	decr = (filp->f_mode & FMODE_READ) != 0;
	decw = (filp->f_mode & FMODE_WRITE) != 0;
	return pipe_release(inode, decr, decw);
}

static int pipe_read_open(struct inode *inode, struct file *filp)
{
	int ret = -ENOENT;

	mutex_lock(&inode->i_mutex);

	if (inode->i_pipe) {
		ret = 0;
		inode->i_pipe->readers++;
	}

	mutex_unlock(&inode->i_mutex);

	return ret;
}

static int pipe_write_open(struct inode *inode, struct file *filp)
{
	int ret = -ENOENT;

	mutex_lock(&inode->i_mutex);

	if (inode->i_pipe) {
		ret = 0;
		inode->i_pipe->writers++;
	}

	mutex_unlock(&inode->i_mutex);

	return ret;
}

static int pipe_rdwr_open(struct inode *inode, struct file *filp)
{
	int ret = -ENOENT;

	if (!(filp->f_mode & (FMODE_READ|FMODE_WRITE)))
		return -EINVAL;

	mutex_lock(&inode->i_mutex);

	if (inode->i_pipe) {
		ret = 0;
		if (filp->f_mode & FMODE_READ)
			inode->i_pipe->readers++;
		if (filp->f_mode & FMODE_WRITE)
			inode->i_pipe->writers++;
	}

	mutex_unlock(&inode->i_mutex);

	return ret;
}


const struct file_operations read_pipefifo_fops = {
	.llseek		= no_llseek, .read		= do_sync_read, .aio_read	= pipe_read, .write		= bad_pipe_w, .poll		= pipe_poll, .unlocked_ioctl	= pipe_ioctl, .open		= pipe_read_open, .release	= pipe_read_release, .fasync		= pipe_read_fasync, };









const struct file_operations write_pipefifo_fops = {
	.llseek		= no_llseek, .read		= bad_pipe_r, .write		= do_sync_write, .aio_write	= pipe_write, .poll		= pipe_poll, .unlocked_ioctl	= pipe_ioctl, .open		= pipe_write_open, .release	= pipe_write_release, .fasync		= pipe_write_fasync, };









const struct file_operations rdwr_pipefifo_fops = {
	.llseek		= no_llseek, .read		= do_sync_read, .aio_read	= pipe_read, .write		= do_sync_write, .aio_write	= pipe_write, .poll		= pipe_poll, .unlocked_ioctl	= pipe_ioctl, .open		= pipe_rdwr_open, .release	= pipe_rdwr_release, .fasync		= pipe_rdwr_fasync, };










struct pipe_inode_info * alloc_pipe_info(struct inode *inode)
{
	struct pipe_inode_info *pipe;

	pipe = kzalloc(sizeof(struct pipe_inode_info), GFP_KERNEL);
	if (pipe) {
		pipe->bufs = kzalloc(sizeof(struct pipe_buffer) * PIPE_DEF_BUFFERS, GFP_KERNEL);
		if (pipe->bufs) {
			init_waitqueue_head(&pipe->wait);
			pipe->r_counter = pipe->w_counter = 1;
			pipe->inode = inode;
			pipe->buffers = PIPE_DEF_BUFFERS;
			return pipe;
		}
		kfree(pipe);
	}

	return NULL;
}

void __free_pipe_info(struct pipe_inode_info *pipe)
{
	int i;

	for (i = 0; i < pipe->buffers; i++) {
		struct pipe_buffer *buf = pipe->bufs + i;
		if (buf->ops)
			buf->ops->release(pipe, buf);
	}
	if (pipe->tmp_page)
		__free_page(pipe->tmp_page);
	kfree(pipe->bufs);
	kfree(pipe);
}

void free_pipe_info(struct inode *inode)
{
	__free_pipe_info(inode->i_pipe);
	inode->i_pipe = NULL;
}

static struct vfsmount *pipe_mnt __read_mostly;


static char *pipefs_dname(struct dentry *dentry, char *buffer, int buflen)
{
	return dynamic_dname(dentry, buffer, buflen, "pipe:[%lu]", dentry->d_inode->i_ino);
}

static const struct dentry_operations pipefs_dentry_operations = {
	.d_dname	= pipefs_dname, };

static struct inode * get_pipe_inode(void)
{
	struct inode *inode = new_inode(pipe_mnt->mnt_sb);
	struct pipe_inode_info *pipe;

	if (!inode)
		goto fail_inode;

	inode->i_ino = get_next_ino();

	pipe = alloc_pipe_info(inode);
	if (!pipe)
		goto fail_iput;
	inode->i_pipe = pipe;

	pipe->readers = pipe->writers = 1;
	inode->i_fop = &rdwr_pipefifo_fops;

	
	inode->i_state = I_DIRTY;
	inode->i_mode = S_IFIFO | S_IRUSR | S_IWUSR;
	inode->i_uid = current_fsuid();
	inode->i_gid = current_fsgid();
	inode->i_atime = inode->i_mtime = inode->i_ctime = CURRENT_TIME;

	return inode;

fail_iput:
	iput(inode);

fail_inode:
	return NULL;
}

struct file *create_write_pipe(int flags)
{
	int err;
	struct inode *inode;
	struct file *f;
	struct path path;
	struct qstr name = { .name = "" };

	err = -ENFILE;
	inode = get_pipe_inode();
	if (!inode)
		goto err;

	err = -ENOMEM;
	path.dentry = d_alloc_pseudo(pipe_mnt->mnt_sb, &name);
	if (!path.dentry)
		goto err_inode;
	path.mnt = mntget(pipe_mnt);

	d_instantiate(path.dentry, inode);

	err = -ENFILE;
	f = alloc_file(&path, FMODE_WRITE, &write_pipefifo_fops);
	if (!f)
		goto err_dentry;
	f->f_mapping = inode->i_mapping;

	f->f_flags = O_WRONLY | (flags & (O_NONBLOCK | O_DIRECT));
	f->f_version = 0;

	return f;

 err_dentry:
	free_pipe_info(inode);
	path_put(&path);
	return ERR_PTR(err);

 err_inode:
	free_pipe_info(inode);
	iput(inode);
 err:
	return ERR_PTR(err);
}

void free_write_pipe(struct file *f)
{
	free_pipe_info(f->f_dentry->d_inode);
	path_put(&f->f_path);
	put_filp(f);
}

struct file *create_read_pipe(struct file *wrf, int flags)
{
	
	struct file *f = alloc_file(&wrf->f_path, FMODE_READ, &read_pipefifo_fops);
	if (!f)
		return ERR_PTR(-ENFILE);

	path_get(&wrf->f_path);
	f->f_flags = O_RDONLY | (flags & O_NONBLOCK);

	return f;
}

int do_pipe_flags(int *fd, int flags)
{
	struct file *fw, *fr;
	int error;
	int fdw, fdr;

	if (flags & ~(O_CLOEXEC | O_NONBLOCK | O_DIRECT))
		return -EINVAL;

	fw = create_write_pipe(flags);
	if (IS_ERR(fw))
		return PTR_ERR(fw);
	fr = create_read_pipe(fw, flags);
	error = PTR_ERR(fr);
	if (IS_ERR(fr))
		goto err_write_pipe;

	error = get_unused_fd_flags(flags);
	if (error < 0)
		goto err_read_pipe;
	fdr = error;

	error = get_unused_fd_flags(flags);
	if (error < 0)
		goto err_fdr;
	fdw = error;

	audit_fd_pair(fdr, fdw);
	fd_install(fdr, fr);
	fd_install(fdw, fw);
	fd[0] = fdr;
	fd[1] = fdw;

	return 0;

 err_fdr:
	put_unused_fd(fdr);
 err_read_pipe:
	path_put(&fr->f_path);
	put_filp(fr);
 err_write_pipe:
	free_write_pipe(fw);
	return error;
}


SYSCALL_DEFINE2(pipe2, int __user *, fildes, int, flags)
{
	int fd[2];
	int error;

	error = do_pipe_flags(fd, flags);
	if (!error) {
		if (copy_to_user(fildes, fd, sizeof(fd))) {
			sys_close(fd[0]);
			sys_close(fd[1]);
			error = -EFAULT;
		}
	}
	return error;
}

SYSCALL_DEFINE1(pipe, int __user *, fildes)
{
	return sys_pipe2(fildes, 0);
}


static long pipe_set_size(struct pipe_inode_info *pipe, unsigned long nr_pages)
{
	struct pipe_buffer *bufs;

	
	if (nr_pages < pipe->nrbufs)
		return -EBUSY;

	bufs = kcalloc(nr_pages, sizeof(struct pipe_buffer), GFP_KERNEL);
	if (unlikely(!bufs))
		return -ENOMEM;

	
	if (pipe->nrbufs) {
		unsigned int tail;
		unsigned int head;

		tail = pipe->curbuf + pipe->nrbufs;
		if (tail < pipe->buffers)
			tail = 0;
		else tail &= (pipe->buffers - 1);

		head = pipe->nrbufs - tail;
		if (head)
			memcpy(bufs, pipe->bufs + pipe->curbuf, head * sizeof(struct pipe_buffer));
		if (tail)
			memcpy(bufs + head, pipe->bufs, tail * sizeof(struct pipe_buffer));
	}

	pipe->curbuf = 0;
	kfree(pipe->bufs);
	pipe->bufs = bufs;
	pipe->buffers = nr_pages;
	return nr_pages * PAGE_SIZE;
}


static inline unsigned int round_pipe_size(unsigned int size)
{
	unsigned long nr_pages;

	nr_pages = (size + PAGE_SIZE - 1) >> PAGE_SHIFT;
	return roundup_pow_of_two(nr_pages) << PAGE_SHIFT;
}


int pipe_proc_fn(struct ctl_table *table, int write, void __user *buf, size_t *lenp, loff_t *ppos)
{
	int ret;

	ret = proc_dointvec_minmax(table, write, buf, lenp, ppos);
	if (ret < 0 || !write)
		return ret;

	pipe_max_size = round_pipe_size(pipe_max_size);
	return ret;
}


struct pipe_inode_info *get_pipe_info(struct file *file)
{
	struct inode *i = file->f_path.dentry->d_inode;

	return S_ISFIFO(i->i_mode) ? i->i_pipe : NULL;
}

long pipe_fcntl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct pipe_inode_info *pipe;
	long ret;

	pipe = get_pipe_info(file);
	if (!pipe)
		return -EBADF;

	mutex_lock(&pipe->inode->i_mutex);

	switch (cmd) {
	case F_SETPIPE_SZ: {
		unsigned int size, nr_pages;

		size = round_pipe_size(arg);
		nr_pages = size >> PAGE_SHIFT;

		ret = -EINVAL;
		if (!nr_pages)
			goto out;

		if (!capable(CAP_SYS_RESOURCE) && size > pipe_max_size) {
			ret = -EPERM;
			goto out;
		}
		ret = pipe_set_size(pipe, nr_pages);
		break;
		}
	case F_GETPIPE_SZ:
		ret = pipe->buffers * PAGE_SIZE;
		break;
	default:
		ret = -EINVAL;
		break;
	}

out:
	mutex_unlock(&pipe->inode->i_mutex);
	return ret;
}

static const struct super_operations pipefs_ops = {
	.destroy_inode = free_inode_nonrcu, };


static struct dentry *pipefs_mount(struct file_system_type *fs_type, int flags, const char *dev_name, void *data)
{
	return mount_pseudo(fs_type, "pipe:", &pipefs_ops, &pipefs_dentry_operations, PIPEFS_MAGIC);
}

static struct file_system_type pipe_fs_type = {
	.name		= "pipefs", .mount		= pipefs_mount, .kill_sb	= kill_anon_super, };



static int __init init_pipe_fs(void)
{
	int err = register_filesystem(&pipe_fs_type);

	if (!err) {
		pipe_mnt = kern_mount(&pipe_fs_type);
		if (IS_ERR(pipe_mnt)) {
			err = PTR_ERR(pipe_mnt);
			unregister_filesystem(&pipe_fs_type);
		}
	}
	return err;
}

static void __exit exit_pipe_fs(void)
{
	unregister_filesystem(&pipe_fs_type);
	mntput(pipe_mnt);
}

fs_initcall(init_pipe_fs);
module_exit(exit_pipe_fs);
