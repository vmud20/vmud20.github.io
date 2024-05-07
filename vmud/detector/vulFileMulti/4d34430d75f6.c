










































static struct ext4_lazy_init *ext4_li_info;
static struct mutex ext4_li_mtx;
static struct ratelimit_state ext4_mount_msg_ratelimit;

static int ext4_load_journal(struct super_block *, struct ext4_super_block *, unsigned long journal_devnum);
static int ext4_show_options(struct seq_file *seq, struct dentry *root);
static int ext4_commit_super(struct super_block *sb, int sync);
static void ext4_mark_recovery_complete(struct super_block *sb, struct ext4_super_block *es);
static void ext4_clear_journal_err(struct super_block *sb, struct ext4_super_block *es);
static int ext4_sync_fs(struct super_block *sb, int wait);
static int ext4_remount(struct super_block *sb, int *flags, char *data);
static int ext4_statfs(struct dentry *dentry, struct kstatfs *buf);
static int ext4_unfreeze(struct super_block *sb);
static int ext4_freeze(struct super_block *sb);
static struct dentry *ext4_mount(struct file_system_type *fs_type, int flags, const char *dev_name, void *data);
static inline int ext2_feature_set_ok(struct super_block *sb);
static inline int ext3_feature_set_ok(struct super_block *sb);
static int ext4_feature_set_ok(struct super_block *sb, int readonly);
static void ext4_destroy_lazyinit_thread(void);
static void ext4_unregister_li_request(struct super_block *sb);
static void ext4_clear_request_list(void);
static struct inode *ext4_get_journal_inode(struct super_block *sb, unsigned int journal_inum);




static struct file_system_type ext2_fs_type = {
	.owner		= THIS_MODULE, .name		= "ext2", .mount		= ext4_mount, .kill_sb	= kill_block_super, .fs_flags	= FS_REQUIRES_DEV, };




MODULE_ALIAS_FS("ext2");
MODULE_ALIAS("ext2");






static struct file_system_type ext3_fs_type = {
	.owner		= THIS_MODULE, .name		= "ext3", .mount		= ext4_mount, .kill_sb	= kill_block_super, .fs_flags	= FS_REQUIRES_DEV, };




MODULE_ALIAS_FS("ext3");
MODULE_ALIAS("ext3");


static int ext4_verify_csum_type(struct super_block *sb, struct ext4_super_block *es)
{
	if (!ext4_has_feature_metadata_csum(sb))
		return 1;

	return es->s_checksum_type == EXT4_CRC32C_CHKSUM;
}

static __le32 ext4_superblock_csum(struct super_block *sb, struct ext4_super_block *es)
{
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	int offset = offsetof(struct ext4_super_block, s_checksum);
	__u32 csum;

	csum = ext4_chksum(sbi, ~0, (char *)es, offset);

	return cpu_to_le32(csum);
}

static int ext4_superblock_csum_verify(struct super_block *sb, struct ext4_super_block *es)
{
	if (!ext4_has_metadata_csum(sb))
		return 1;

	return es->s_checksum == ext4_superblock_csum(sb, es);
}

void ext4_superblock_csum_set(struct super_block *sb)
{
	struct ext4_super_block *es = EXT4_SB(sb)->s_es;

	if (!ext4_has_metadata_csum(sb))
		return;

	es->s_checksum = ext4_superblock_csum(sb, es);
}

void *ext4_kvmalloc(size_t size, gfp_t flags)
{
	void *ret;

	ret = kmalloc(size, flags | __GFP_NOWARN);
	if (!ret)
		ret = __vmalloc(size, flags, PAGE_KERNEL);
	return ret;
}

void *ext4_kvzalloc(size_t size, gfp_t flags)
{
	void *ret;

	ret = kzalloc(size, flags | __GFP_NOWARN);
	if (!ret)
		ret = __vmalloc(size, flags | __GFP_ZERO, PAGE_KERNEL);
	return ret;
}

ext4_fsblk_t ext4_block_bitmap(struct super_block *sb, struct ext4_group_desc *bg)
{
	return le32_to_cpu(bg->bg_block_bitmap_lo) | (EXT4_DESC_SIZE(sb) >= EXT4_MIN_DESC_SIZE_64BIT ? (ext4_fsblk_t)le32_to_cpu(bg->bg_block_bitmap_hi) << 32 : 0);

}

ext4_fsblk_t ext4_inode_bitmap(struct super_block *sb, struct ext4_group_desc *bg)
{
	return le32_to_cpu(bg->bg_inode_bitmap_lo) | (EXT4_DESC_SIZE(sb) >= EXT4_MIN_DESC_SIZE_64BIT ? (ext4_fsblk_t)le32_to_cpu(bg->bg_inode_bitmap_hi) << 32 : 0);

}

ext4_fsblk_t ext4_inode_table(struct super_block *sb, struct ext4_group_desc *bg)
{
	return le32_to_cpu(bg->bg_inode_table_lo) | (EXT4_DESC_SIZE(sb) >= EXT4_MIN_DESC_SIZE_64BIT ? (ext4_fsblk_t)le32_to_cpu(bg->bg_inode_table_hi) << 32 : 0);

}

__u32 ext4_free_group_clusters(struct super_block *sb, struct ext4_group_desc *bg)
{
	return le16_to_cpu(bg->bg_free_blocks_count_lo) | (EXT4_DESC_SIZE(sb) >= EXT4_MIN_DESC_SIZE_64BIT ? (__u32)le16_to_cpu(bg->bg_free_blocks_count_hi) << 16 : 0);

}

__u32 ext4_free_inodes_count(struct super_block *sb, struct ext4_group_desc *bg)
{
	return le16_to_cpu(bg->bg_free_inodes_count_lo) | (EXT4_DESC_SIZE(sb) >= EXT4_MIN_DESC_SIZE_64BIT ? (__u32)le16_to_cpu(bg->bg_free_inodes_count_hi) << 16 : 0);

}

__u32 ext4_used_dirs_count(struct super_block *sb, struct ext4_group_desc *bg)
{
	return le16_to_cpu(bg->bg_used_dirs_count_lo) | (EXT4_DESC_SIZE(sb) >= EXT4_MIN_DESC_SIZE_64BIT ? (__u32)le16_to_cpu(bg->bg_used_dirs_count_hi) << 16 : 0);

}

__u32 ext4_itable_unused_count(struct super_block *sb, struct ext4_group_desc *bg)
{
	return le16_to_cpu(bg->bg_itable_unused_lo) | (EXT4_DESC_SIZE(sb) >= EXT4_MIN_DESC_SIZE_64BIT ? (__u32)le16_to_cpu(bg->bg_itable_unused_hi) << 16 : 0);

}

void ext4_block_bitmap_set(struct super_block *sb, struct ext4_group_desc *bg, ext4_fsblk_t blk)
{
	bg->bg_block_bitmap_lo = cpu_to_le32((u32)blk);
	if (EXT4_DESC_SIZE(sb) >= EXT4_MIN_DESC_SIZE_64BIT)
		bg->bg_block_bitmap_hi = cpu_to_le32(blk >> 32);
}

void ext4_inode_bitmap_set(struct super_block *sb, struct ext4_group_desc *bg, ext4_fsblk_t blk)
{
	bg->bg_inode_bitmap_lo  = cpu_to_le32((u32)blk);
	if (EXT4_DESC_SIZE(sb) >= EXT4_MIN_DESC_SIZE_64BIT)
		bg->bg_inode_bitmap_hi = cpu_to_le32(blk >> 32);
}

void ext4_inode_table_set(struct super_block *sb, struct ext4_group_desc *bg, ext4_fsblk_t blk)
{
	bg->bg_inode_table_lo = cpu_to_le32((u32)blk);
	if (EXT4_DESC_SIZE(sb) >= EXT4_MIN_DESC_SIZE_64BIT)
		bg->bg_inode_table_hi = cpu_to_le32(blk >> 32);
}

void ext4_free_group_clusters_set(struct super_block *sb, struct ext4_group_desc *bg, __u32 count)
{
	bg->bg_free_blocks_count_lo = cpu_to_le16((__u16)count);
	if (EXT4_DESC_SIZE(sb) >= EXT4_MIN_DESC_SIZE_64BIT)
		bg->bg_free_blocks_count_hi = cpu_to_le16(count >> 16);
}

void ext4_free_inodes_set(struct super_block *sb, struct ext4_group_desc *bg, __u32 count)
{
	bg->bg_free_inodes_count_lo = cpu_to_le16((__u16)count);
	if (EXT4_DESC_SIZE(sb) >= EXT4_MIN_DESC_SIZE_64BIT)
		bg->bg_free_inodes_count_hi = cpu_to_le16(count >> 16);
}

void ext4_used_dirs_set(struct super_block *sb, struct ext4_group_desc *bg, __u32 count)
{
	bg->bg_used_dirs_count_lo = cpu_to_le16((__u16)count);
	if (EXT4_DESC_SIZE(sb) >= EXT4_MIN_DESC_SIZE_64BIT)
		bg->bg_used_dirs_count_hi = cpu_to_le16(count >> 16);
}

void ext4_itable_unused_set(struct super_block *sb, struct ext4_group_desc *bg, __u32 count)
{
	bg->bg_itable_unused_lo = cpu_to_le16((__u16)count);
	if (EXT4_DESC_SIZE(sb) >= EXT4_MIN_DESC_SIZE_64BIT)
		bg->bg_itable_unused_hi = cpu_to_le16(count >> 16);
}


static void __save_error_info(struct super_block *sb, const char *func, unsigned int line)
{
	struct ext4_super_block *es = EXT4_SB(sb)->s_es;

	EXT4_SB(sb)->s_mount_state |= EXT4_ERROR_FS;
	if (bdev_read_only(sb->s_bdev))
		return;
	es->s_state |= cpu_to_le16(EXT4_ERROR_FS);
	es->s_last_error_time = cpu_to_le32(get_seconds());
	strncpy(es->s_last_error_func, func, sizeof(es->s_last_error_func));
	es->s_last_error_line = cpu_to_le32(line);
	if (!es->s_first_error_time) {
		es->s_first_error_time = es->s_last_error_time;
		strncpy(es->s_first_error_func, func, sizeof(es->s_first_error_func));
		es->s_first_error_line = cpu_to_le32(line);
		es->s_first_error_ino = es->s_last_error_ino;
		es->s_first_error_block = es->s_last_error_block;
	}
	
	if (!es->s_error_count)
		mod_timer(&EXT4_SB(sb)->s_err_report, jiffies + 24*60*60*HZ);
	le32_add_cpu(&es->s_error_count, 1);
}

static void save_error_info(struct super_block *sb, const char *func, unsigned int line)
{
	__save_error_info(sb, func, line);
	ext4_commit_super(sb, 1);
}


static int block_device_ejected(struct super_block *sb)
{
	struct inode *bd_inode = sb->s_bdev->bd_inode;
	struct backing_dev_info *bdi = inode_to_bdi(bd_inode);

	return bdi->dev == NULL;
}

static void ext4_journal_commit_callback(journal_t *journal, transaction_t *txn)
{
	struct super_block		*sb = journal->j_private;
	struct ext4_sb_info		*sbi = EXT4_SB(sb);
	int				error = is_journal_aborted(journal);
	struct ext4_journal_cb_entry	*jce;

	BUG_ON(txn->t_state == T_FINISHED);

	ext4_process_freed_data(sb, txn->t_tid);

	spin_lock(&sbi->s_md_lock);
	while (!list_empty(&txn->t_private_list)) {
		jce = list_entry(txn->t_private_list.next, struct ext4_journal_cb_entry, jce_list);
		list_del_init(&jce->jce_list);
		spin_unlock(&sbi->s_md_lock);
		jce->jce_func(sb, jce, error);
		spin_lock(&sbi->s_md_lock);
	}
	spin_unlock(&sbi->s_md_lock);
}



static void ext4_handle_error(struct super_block *sb)
{
	if (test_opt(sb, WARN_ON_ERROR))
		WARN_ON_ONCE(1);

	if (sb_rdonly(sb))
		return;

	if (!test_opt(sb, ERRORS_CONT)) {
		journal_t *journal = EXT4_SB(sb)->s_journal;

		EXT4_SB(sb)->s_mount_flags |= EXT4_MF_FS_ABORTED;
		if (journal)
			jbd2_journal_abort(journal, -EIO);
	}
	if (test_opt(sb, ERRORS_RO)) {
		ext4_msg(sb, KERN_CRIT, "Remounting filesystem read-only");
		
		smp_wmb();
		sb->s_flags |= SB_RDONLY;
	}
	if (test_opt(sb, ERRORS_PANIC)) {
		if (EXT4_SB(sb)->s_journal && !(EXT4_SB(sb)->s_journal->j_flags & JBD2_REC_ERR))
			return;
		panic("EXT4-fs (device %s): panic forced after error\n", sb->s_id);
	}
}




void __ext4_error(struct super_block *sb, const char *function, unsigned int line, const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	if (unlikely(ext4_forced_shutdown(EXT4_SB(sb))))
		return;

	trace_ext4_error(sb, function, line);
	if (ext4_error_ratelimit(sb)) {
		va_start(args, fmt);
		vaf.fmt = fmt;
		vaf.va = &args;
		printk(KERN_CRIT "EXT4-fs error (device %s): %s:%d: comm %s: %pV\n", sb->s_id, function, line, current->comm, &vaf);

		va_end(args);
	}
	save_error_info(sb, function, line);
	ext4_handle_error(sb);
}

void __ext4_error_inode(struct inode *inode, const char *function, unsigned int line, ext4_fsblk_t block, const char *fmt, ...)

{
	va_list args;
	struct va_format vaf;
	struct ext4_super_block *es = EXT4_SB(inode->i_sb)->s_es;

	if (unlikely(ext4_forced_shutdown(EXT4_SB(inode->i_sb))))
		return;

	trace_ext4_error(inode->i_sb, function, line);
	es->s_last_error_ino = cpu_to_le32(inode->i_ino);
	es->s_last_error_block = cpu_to_le64(block);
	if (ext4_error_ratelimit(inode->i_sb)) {
		va_start(args, fmt);
		vaf.fmt = fmt;
		vaf.va = &args;
		if (block)
			printk(KERN_CRIT "EXT4-fs error (device %s): %s:%d: " "inode #%lu: block %llu: comm %s: %pV\n", inode->i_sb->s_id, function, line, inode->i_ino, block, current->comm, &vaf);


		else printk(KERN_CRIT "EXT4-fs error (device %s): %s:%d: " "inode #%lu: comm %s: %pV\n", inode->i_sb->s_id, function, line, inode->i_ino, current->comm, &vaf);



		va_end(args);
	}
	save_error_info(inode->i_sb, function, line);
	ext4_handle_error(inode->i_sb);
}

void __ext4_error_file(struct file *file, const char *function, unsigned int line, ext4_fsblk_t block, const char *fmt, ...)

{
	va_list args;
	struct va_format vaf;
	struct ext4_super_block *es;
	struct inode *inode = file_inode(file);
	char pathname[80], *path;

	if (unlikely(ext4_forced_shutdown(EXT4_SB(inode->i_sb))))
		return;

	trace_ext4_error(inode->i_sb, function, line);
	es = EXT4_SB(inode->i_sb)->s_es;
	es->s_last_error_ino = cpu_to_le32(inode->i_ino);
	if (ext4_error_ratelimit(inode->i_sb)) {
		path = file_path(file, pathname, sizeof(pathname));
		if (IS_ERR(path))
			path = "(unknown)";
		va_start(args, fmt);
		vaf.fmt = fmt;
		vaf.va = &args;
		if (block)
			printk(KERN_CRIT "EXT4-fs error (device %s): %s:%d: inode #%lu: " "block %llu: comm %s: path %s: %pV\n", inode->i_sb->s_id, function, line, inode->i_ino, block, current->comm, path, &vaf);



		else printk(KERN_CRIT "EXT4-fs error (device %s): %s:%d: inode #%lu: " "comm %s: path %s: %pV\n", inode->i_sb->s_id, function, line, inode->i_ino, current->comm, path, &vaf);




		va_end(args);
	}
	save_error_info(inode->i_sb, function, line);
	ext4_handle_error(inode->i_sb);
}

const char *ext4_decode_error(struct super_block *sb, int errno, char nbuf[16])
{
	char *errstr = NULL;

	switch (errno) {
	case -EFSCORRUPTED:
		errstr = "Corrupt filesystem";
		break;
	case -EFSBADCRC:
		errstr = "Filesystem failed CRC";
		break;
	case -EIO:
		errstr = "IO failure";
		break;
	case -ENOMEM:
		errstr = "Out of memory";
		break;
	case -EROFS:
		if (!sb || (EXT4_SB(sb)->s_journal && EXT4_SB(sb)->s_journal->j_flags & JBD2_ABORT))
			errstr = "Journal has aborted";
		else errstr = "Readonly filesystem";
		break;
	default:
		
		if (nbuf) {
			
			if (snprintf(nbuf, 16, "error %d", -errno) >= 0)
				errstr = nbuf;
		}
		break;
	}

	return errstr;
}



void __ext4_std_error(struct super_block *sb, const char *function, unsigned int line, int errno)
{
	char nbuf[16];
	const char *errstr;

	if (unlikely(ext4_forced_shutdown(EXT4_SB(sb))))
		return;

	
	if (errno == -EROFS && journal_current_handle() == NULL && sb_rdonly(sb))
		return;

	if (ext4_error_ratelimit(sb)) {
		errstr = ext4_decode_error(sb, errno, nbuf);
		printk(KERN_CRIT "EXT4-fs error (device %s) in %s:%d: %s\n", sb->s_id, function, line, errstr);
	}

	save_error_info(sb, function, line);
	ext4_handle_error(sb);
}



void __ext4_abort(struct super_block *sb, const char *function, unsigned int line, const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	if (unlikely(ext4_forced_shutdown(EXT4_SB(sb))))
		return;

	save_error_info(sb, function, line);
	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;
	printk(KERN_CRIT "EXT4-fs error (device %s): %s:%d: %pV\n", sb->s_id, function, line, &vaf);
	va_end(args);

	if (sb_rdonly(sb) == 0) {
		ext4_msg(sb, KERN_CRIT, "Remounting filesystem read-only");
		EXT4_SB(sb)->s_mount_flags |= EXT4_MF_FS_ABORTED;
		
		smp_wmb();
		sb->s_flags |= SB_RDONLY;
		if (EXT4_SB(sb)->s_journal)
			jbd2_journal_abort(EXT4_SB(sb)->s_journal, -EIO);
		save_error_info(sb, function, line);
	}
	if (test_opt(sb, ERRORS_PANIC)) {
		if (EXT4_SB(sb)->s_journal && !(EXT4_SB(sb)->s_journal->j_flags & JBD2_REC_ERR))
			return;
		panic("EXT4-fs panic from previous error\n");
	}
}

void __ext4_msg(struct super_block *sb, const char *prefix, const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	if (!___ratelimit(&(EXT4_SB(sb)->s_msg_ratelimit_state), "EXT4-fs"))
		return;

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;
	printk("%sEXT4-fs (%s): %pV\n", prefix, sb->s_id, &vaf);
	va_end(args);
}




void __ext4_warning(struct super_block *sb, const char *function, unsigned int line, const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	if (!ext4_warning_ratelimit(sb))
		return;

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;
	printk(KERN_WARNING "EXT4-fs warning (device %s): %s:%d: %pV\n", sb->s_id, function, line, &vaf);
	va_end(args);
}

void __ext4_warning_inode(const struct inode *inode, const char *function, unsigned int line, const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	if (!ext4_warning_ratelimit(inode->i_sb))
		return;

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;
	printk(KERN_WARNING "EXT4-fs warning (device %s): %s:%d: " "inode #%lu: comm %s: %pV\n", inode->i_sb->s_id, function, line, inode->i_ino, current->comm, &vaf);

	va_end(args);
}

void __ext4_grp_locked_error(const char *function, unsigned int line, struct super_block *sb, ext4_group_t grp, unsigned long ino, ext4_fsblk_t block, const char *fmt, ...)


__releases(bitlock)
__acquires(bitlock)
{
	struct va_format vaf;
	va_list args;
	struct ext4_super_block *es = EXT4_SB(sb)->s_es;

	if (unlikely(ext4_forced_shutdown(EXT4_SB(sb))))
		return;

	trace_ext4_error(sb, function, line);
	es->s_last_error_ino = cpu_to_le32(ino);
	es->s_last_error_block = cpu_to_le64(block);
	__save_error_info(sb, function, line);

	if (ext4_error_ratelimit(sb)) {
		va_start(args, fmt);
		vaf.fmt = fmt;
		vaf.va = &args;
		printk(KERN_CRIT "EXT4-fs error (device %s): %s:%d: group %u, ", sb->s_id, function, line, grp);
		if (ino)
			printk(KERN_CONT "inode %lu: ", ino);
		if (block)
			printk(KERN_CONT "block %llu:", (unsigned long long) block);
		printk(KERN_CONT "%pV\n", &vaf);
		va_end(args);
	}

	if (test_opt(sb, WARN_ON_ERROR))
		WARN_ON_ONCE(1);

	if (test_opt(sb, ERRORS_CONT)) {
		ext4_commit_super(sb, 0);
		return;
	}

	ext4_unlock_group(sb, grp);
	ext4_commit_super(sb, 1);
	ext4_handle_error(sb);
	
	ext4_lock_group(sb, grp);
	return;
}

void ext4_mark_group_bitmap_corrupted(struct super_block *sb, ext4_group_t group, unsigned int flags)

{
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	struct ext4_group_info *grp = ext4_get_group_info(sb, group);
	struct ext4_group_desc *gdp = ext4_get_group_desc(sb, group, NULL);

	if ((flags & EXT4_GROUP_INFO_BBITMAP_CORRUPT) && !EXT4_MB_GRP_BBITMAP_CORRUPT(grp)) {
		percpu_counter_sub(&sbi->s_freeclusters_counter, grp->bb_free);
		set_bit(EXT4_GROUP_INFO_BBITMAP_CORRUPT_BIT, &grp->bb_state);
	}

	if ((flags & EXT4_GROUP_INFO_IBITMAP_CORRUPT) && !EXT4_MB_GRP_IBITMAP_CORRUPT(grp)) {
		if (gdp) {
			int count;

			count = ext4_free_inodes_count(sb, gdp);
			percpu_counter_sub(&sbi->s_freeinodes_counter, count);
		}
		set_bit(EXT4_GROUP_INFO_IBITMAP_CORRUPT_BIT, &grp->bb_state);
	}
}

void ext4_update_dynamic_rev(struct super_block *sb)
{
	struct ext4_super_block *es = EXT4_SB(sb)->s_es;

	if (le32_to_cpu(es->s_rev_level) > EXT4_GOOD_OLD_REV)
		return;

	ext4_warning(sb, "updating to rev %d because of new feature flag, " "running e2fsck is recommended", EXT4_DYNAMIC_REV);



	es->s_first_ino = cpu_to_le32(EXT4_GOOD_OLD_FIRST_INO);
	es->s_inode_size = cpu_to_le16(EXT4_GOOD_OLD_INODE_SIZE);
	es->s_rev_level = cpu_to_le32(EXT4_DYNAMIC_REV);
	
	

	
}


static struct block_device *ext4_blkdev_get(dev_t dev, struct super_block *sb)
{
	struct block_device *bdev;
	char b[BDEVNAME_SIZE];

	bdev = blkdev_get_by_dev(dev, FMODE_READ|FMODE_WRITE|FMODE_EXCL, sb);
	if (IS_ERR(bdev))
		goto fail;
	return bdev;

fail:
	ext4_msg(sb, KERN_ERR, "failed to open journal device %s: %ld", __bdevname(dev, b), PTR_ERR(bdev));
	return NULL;
}


static void ext4_blkdev_put(struct block_device *bdev)
{
	blkdev_put(bdev, FMODE_READ|FMODE_WRITE|FMODE_EXCL);
}

static void ext4_blkdev_remove(struct ext4_sb_info *sbi)
{
	struct block_device *bdev;
	bdev = sbi->journal_bdev;
	if (bdev) {
		ext4_blkdev_put(bdev);
		sbi->journal_bdev = NULL;
	}
}

static inline struct inode *orphan_list_entry(struct list_head *l)
{
	return &list_entry(l, struct ext4_inode_info, i_orphan)->vfs_inode;
}

static void dump_orphan_list(struct super_block *sb, struct ext4_sb_info *sbi)
{
	struct list_head *l;

	ext4_msg(sb, KERN_ERR, "sb orphan head is %d", le32_to_cpu(sbi->s_es->s_last_orphan));

	printk(KERN_ERR "sb_info orphan list:\n");
	list_for_each(l, &sbi->s_orphan) {
		struct inode *inode = orphan_list_entry(l);
		printk(KERN_ERR "  " "inode %s:%lu at %p: mode %o, nlink %d, next %d\n", inode->i_sb->s_id, inode->i_ino, inode, inode->i_mode, inode->i_nlink, NEXT_ORPHAN(inode));



	}
}


static int ext4_quota_off(struct super_block *sb, int type);

static inline void ext4_quota_off_umount(struct super_block *sb)
{
	int type;

	
	for (type = 0; type < EXT4_MAXQUOTAS; type++)
		ext4_quota_off(sb, type);
}

static inline void ext4_quota_off_umount(struct super_block *sb)
{
}


static void ext4_put_super(struct super_block *sb)
{
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	struct ext4_super_block *es = sbi->s_es;
	int aborted = 0;
	int i, err;

	ext4_unregister_li_request(sb);
	ext4_quota_off_umount(sb);

	destroy_workqueue(sbi->rsv_conversion_wq);

	if (sbi->s_journal) {
		aborted = is_journal_aborted(sbi->s_journal);
		err = jbd2_journal_destroy(sbi->s_journal);
		sbi->s_journal = NULL;
		if ((err < 0) && !aborted)
			ext4_abort(sb, "Couldn't clean up the journal");
	}

	ext4_unregister_sysfs(sb);
	ext4_es_unregister_shrinker(sbi);
	del_timer_sync(&sbi->s_err_report);
	ext4_release_system_zone(sb);
	ext4_mb_release(sb);
	ext4_ext_release(sb);

	if (!sb_rdonly(sb) && !aborted) {
		ext4_clear_feature_journal_needs_recovery(sb);
		es->s_state = cpu_to_le16(sbi->s_mount_state);
	}
	if (!sb_rdonly(sb))
		ext4_commit_super(sb, 1);

	for (i = 0; i < sbi->s_gdb_count; i++)
		brelse(sbi->s_group_desc[i]);
	kvfree(sbi->s_group_desc);
	kvfree(sbi->s_flex_groups);
	percpu_counter_destroy(&sbi->s_freeclusters_counter);
	percpu_counter_destroy(&sbi->s_freeinodes_counter);
	percpu_counter_destroy(&sbi->s_dirs_counter);
	percpu_counter_destroy(&sbi->s_dirtyclusters_counter);
	percpu_free_rwsem(&sbi->s_journal_flag_rwsem);

	for (i = 0; i < EXT4_MAXQUOTAS; i++)
		kfree(sbi->s_qf_names[i]);


	
	if (!list_empty(&sbi->s_orphan))
		dump_orphan_list(sb, sbi);
	J_ASSERT(list_empty(&sbi->s_orphan));

	sync_blockdev(sb->s_bdev);
	invalidate_bdev(sb->s_bdev);
	if (sbi->journal_bdev && sbi->journal_bdev != sb->s_bdev) {
		
		sync_blockdev(sbi->journal_bdev);
		invalidate_bdev(sbi->journal_bdev);
		ext4_blkdev_remove(sbi);
	}
	if (sbi->s_ea_inode_cache) {
		ext4_xattr_destroy_cache(sbi->s_ea_inode_cache);
		sbi->s_ea_inode_cache = NULL;
	}
	if (sbi->s_ea_block_cache) {
		ext4_xattr_destroy_cache(sbi->s_ea_block_cache);
		sbi->s_ea_block_cache = NULL;
	}
	if (sbi->s_mmp_tsk)
		kthread_stop(sbi->s_mmp_tsk);
	brelse(sbi->s_sbh);
	sb->s_fs_info = NULL;
	
	kobject_put(&sbi->s_kobj);
	wait_for_completion(&sbi->s_kobj_unregister);
	if (sbi->s_chksum_driver)
		crypto_free_shash(sbi->s_chksum_driver);
	kfree(sbi->s_blockgroup_lock);
	fs_put_dax(sbi->s_daxdev);
	kfree(sbi);
}

static struct kmem_cache *ext4_inode_cachep;


static struct inode *ext4_alloc_inode(struct super_block *sb)
{
	struct ext4_inode_info *ei;

	ei = kmem_cache_alloc(ext4_inode_cachep, GFP_NOFS);
	if (!ei)
		return NULL;

	inode_set_iversion(&ei->vfs_inode, 1);
	spin_lock_init(&ei->i_raw_lock);
	INIT_LIST_HEAD(&ei->i_prealloc_list);
	spin_lock_init(&ei->i_prealloc_lock);
	ext4_es_init_tree(&ei->i_es_tree);
	rwlock_init(&ei->i_es_lock);
	INIT_LIST_HEAD(&ei->i_es_list);
	ei->i_es_all_nr = 0;
	ei->i_es_shk_nr = 0;
	ei->i_es_shrink_lblk = 0;
	ei->i_reserved_data_blocks = 0;
	ei->i_da_metadata_calc_len = 0;
	ei->i_da_metadata_calc_last_lblock = 0;
	spin_lock_init(&(ei->i_block_reservation_lock));

	ei->i_reserved_quota = 0;
	memset(&ei->i_dquot, 0, sizeof(ei->i_dquot));

	ei->jinode = NULL;
	INIT_LIST_HEAD(&ei->i_rsv_conversion_list);
	spin_lock_init(&ei->i_completed_io_lock);
	ei->i_sync_tid = 0;
	ei->i_datasync_tid = 0;
	atomic_set(&ei->i_unwritten, 0);
	INIT_WORK(&ei->i_rsv_conversion_work, ext4_end_io_rsv_work);
	return &ei->vfs_inode;
}

static int ext4_drop_inode(struct inode *inode)
{
	int drop = generic_drop_inode(inode);

	trace_ext4_drop_inode(inode, drop);
	return drop;
}

static void ext4_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	kmem_cache_free(ext4_inode_cachep, EXT4_I(inode));
}

static void ext4_destroy_inode(struct inode *inode)
{
	if (!list_empty(&(EXT4_I(inode)->i_orphan))) {
		ext4_msg(inode->i_sb, KERN_ERR, "Inode %lu (%p): orphan list check failed!", inode->i_ino, EXT4_I(inode));

		print_hex_dump(KERN_INFO, "", DUMP_PREFIX_ADDRESS, 16, 4, EXT4_I(inode), sizeof(struct ext4_inode_info), true);

		dump_stack();
	}
	call_rcu(&inode->i_rcu, ext4_i_callback);
}

static void init_once(void *foo)
{
	struct ext4_inode_info *ei = (struct ext4_inode_info *) foo;

	INIT_LIST_HEAD(&ei->i_orphan);
	init_rwsem(&ei->xattr_sem);
	init_rwsem(&ei->i_data_sem);
	init_rwsem(&ei->i_mmap_sem);
	inode_init_once(&ei->vfs_inode);
}

static int __init init_inodecache(void)
{
	ext4_inode_cachep = kmem_cache_create_usercopy("ext4_inode_cache", sizeof(struct ext4_inode_info), 0, (SLAB_RECLAIM_ACCOUNT|SLAB_MEM_SPREAD| SLAB_ACCOUNT), offsetof(struct ext4_inode_info, i_data), sizeof_field(struct ext4_inode_info, i_data), init_once);





	if (ext4_inode_cachep == NULL)
		return -ENOMEM;
	return 0;
}

static void destroy_inodecache(void)
{
	
	rcu_barrier();
	kmem_cache_destroy(ext4_inode_cachep);
}

void ext4_clear_inode(struct inode *inode)
{
	invalidate_inode_buffers(inode);
	clear_inode(inode);
	dquot_drop(inode);
	ext4_discard_preallocations(inode);
	ext4_es_remove_extent(inode, 0, EXT_MAX_BLOCKS);
	if (EXT4_I(inode)->jinode) {
		jbd2_journal_release_jbd_inode(EXT4_JOURNAL(inode), EXT4_I(inode)->jinode);
		jbd2_free_inode(EXT4_I(inode)->jinode);
		EXT4_I(inode)->jinode = NULL;
	}
	fscrypt_put_encryption_info(inode);
}

static struct inode *ext4_nfs_get_inode(struct super_block *sb, u64 ino, u32 generation)
{
	struct inode *inode;

	if (ino < EXT4_FIRST_INO(sb) && ino != EXT4_ROOT_INO)
		return ERR_PTR(-ESTALE);
	if (ino > le32_to_cpu(EXT4_SB(sb)->s_es->s_inodes_count))
		return ERR_PTR(-ESTALE);

	
	inode = ext4_iget_normal(sb, ino);
	if (IS_ERR(inode))
		return ERR_CAST(inode);
	if (generation && inode->i_generation != generation) {
		iput(inode);
		return ERR_PTR(-ESTALE);
	}

	return inode;
}

static struct dentry *ext4_fh_to_dentry(struct super_block *sb, struct fid *fid, int fh_len, int fh_type)
{
	return generic_fh_to_dentry(sb, fid, fh_len, fh_type, ext4_nfs_get_inode);
}

static struct dentry *ext4_fh_to_parent(struct super_block *sb, struct fid *fid, int fh_len, int fh_type)
{
	return generic_fh_to_parent(sb, fid, fh_len, fh_type, ext4_nfs_get_inode);
}


static int bdev_try_to_free_page(struct super_block *sb, struct page *page, gfp_t wait)
{
	journal_t *journal = EXT4_SB(sb)->s_journal;

	WARN_ON(PageChecked(page));
	if (!page_has_buffers(page))
		return 0;
	if (journal)
		return jbd2_journal_try_to_free_buffers(journal, page, wait & ~__GFP_DIRECT_RECLAIM);
	return try_to_free_buffers(page);
}


static int ext4_get_context(struct inode *inode, void *ctx, size_t len)
{
	return ext4_xattr_get(inode, EXT4_XATTR_INDEX_ENCRYPTION, EXT4_XATTR_NAME_ENCRYPTION_CONTEXT, ctx, len);
}

static int ext4_set_context(struct inode *inode, const void *ctx, size_t len, void *fs_data)
{
	handle_t *handle = fs_data;
	int res, res2, credits, retries = 0;

	
	if (inode->i_ino == EXT4_ROOT_INO)
		return -EPERM;

	if (WARN_ON_ONCE(IS_DAX(inode) && i_size_read(inode)))
		return -EINVAL;

	res = ext4_convert_inline_data(inode);
	if (res)
		return res;

	

	if (handle) {
		res = ext4_xattr_set_handle(handle, inode, EXT4_XATTR_INDEX_ENCRYPTION, EXT4_XATTR_NAME_ENCRYPTION_CONTEXT, ctx, len, 0);


		if (!res) {
			ext4_set_inode_flag(inode, EXT4_INODE_ENCRYPT);
			ext4_clear_inode_state(inode, EXT4_STATE_MAY_INLINE_DATA);
			
			ext4_set_inode_flags(inode);
		}
		return res;
	}

	res = dquot_initialize(inode);
	if (res)
		return res;
retry:
	res = ext4_xattr_set_credits(inode, len, false , &credits);
	if (res)
		return res;

	handle = ext4_journal_start(inode, EXT4_HT_MISC, credits);
	if (IS_ERR(handle))
		return PTR_ERR(handle);

	res = ext4_xattr_set_handle(handle, inode, EXT4_XATTR_INDEX_ENCRYPTION, EXT4_XATTR_NAME_ENCRYPTION_CONTEXT, ctx, len, 0);

	if (!res) {
		ext4_set_inode_flag(inode, EXT4_INODE_ENCRYPT);
		
		ext4_set_inode_flags(inode);
		res = ext4_mark_inode_dirty(handle, inode);
		if (res)
			EXT4_ERROR_INODE(inode, "Failed to mark inode dirty");
	}
	res2 = ext4_journal_stop(handle);

	if (res == -ENOSPC && ext4_should_retry_alloc(inode->i_sb, &retries))
		goto retry;
	if (!res)
		res = res2;
	return res;
}

static bool ext4_dummy_context(struct inode *inode)
{
	return DUMMY_ENCRYPTION_ENABLED(EXT4_SB(inode->i_sb));
}

static unsigned ext4_max_namelen(struct inode *inode)
{
	return S_ISLNK(inode->i_mode) ? inode->i_sb->s_blocksize :
		EXT4_NAME_LEN;
}

static const struct fscrypt_operations ext4_cryptops = {
	.key_prefix		= "ext4:", .get_context		= ext4_get_context, .set_context		= ext4_set_context, .dummy_context		= ext4_dummy_context, .empty_dir		= ext4_empty_dir, .max_namelen		= ext4_max_namelen, };








static const char * const quotatypes[] = INITQFNAMES;


static int ext4_write_dquot(struct dquot *dquot);
static int ext4_acquire_dquot(struct dquot *dquot);
static int ext4_release_dquot(struct dquot *dquot);
static int ext4_mark_dquot_dirty(struct dquot *dquot);
static int ext4_write_info(struct super_block *sb, int type);
static int ext4_quota_on(struct super_block *sb, int type, int format_id, const struct path *path);
static int ext4_quota_on_mount(struct super_block *sb, int type);
static ssize_t ext4_quota_read(struct super_block *sb, int type, char *data, size_t len, loff_t off);
static ssize_t ext4_quota_write(struct super_block *sb, int type, const char *data, size_t len, loff_t off);
static int ext4_quota_enable(struct super_block *sb, int type, int format_id, unsigned int flags);
static int ext4_enable_quotas(struct super_block *sb);
static int ext4_get_next_id(struct super_block *sb, struct kqid *qid);

static struct dquot **ext4_get_dquots(struct inode *inode)
{
	return EXT4_I(inode)->i_dquot;
}

static const struct dquot_operations ext4_quota_operations = {
	.get_reserved_space	= ext4_get_reserved_space, .write_dquot		= ext4_write_dquot, .acquire_dquot		= ext4_acquire_dquot, .release_dquot		= ext4_release_dquot, .mark_dirty		= ext4_mark_dquot_dirty, .write_info		= ext4_write_info, .alloc_dquot		= dquot_alloc, .destroy_dquot		= dquot_destroy, .get_projid		= ext4_get_projid, .get_inode_usage	= ext4_get_inode_usage, .get_next_id		= ext4_get_next_id, };











static const struct quotactl_ops ext4_qctl_operations = {
	.quota_on	= ext4_quota_on, .quota_off	= ext4_quota_off, .quota_sync	= dquot_quota_sync, .get_state	= dquot_get_state, .set_info	= dquot_set_dqinfo, .get_dqblk	= dquot_get_dqblk, .set_dqblk	= dquot_set_dqblk, .get_nextdqblk	= dquot_get_next_dqblk, };









static const struct super_operations ext4_sops = {
	.alloc_inode	= ext4_alloc_inode, .destroy_inode	= ext4_destroy_inode, .write_inode	= ext4_write_inode, .dirty_inode	= ext4_dirty_inode, .drop_inode	= ext4_drop_inode, .evict_inode	= ext4_evict_inode, .put_super	= ext4_put_super, .sync_fs	= ext4_sync_fs, .freeze_fs	= ext4_freeze, .unfreeze_fs	= ext4_unfreeze, .statfs		= ext4_statfs, .remount_fs	= ext4_remount, .show_options	= ext4_show_options,  .quota_read	= ext4_quota_read, .quota_write	= ext4_quota_write, .get_dquots	= ext4_get_dquots,  .bdev_try_to_free_page = bdev_try_to_free_page, };



















static const struct export_operations ext4_export_ops = {
	.fh_to_dentry = ext4_fh_to_dentry, .fh_to_parent = ext4_fh_to_parent, .get_parent = ext4_get_parent, };



enum {
	Opt_bsd_df, Opt_minix_df, Opt_grpid, Opt_nogrpid, Opt_resgid, Opt_resuid, Opt_sb, Opt_err_cont, Opt_err_panic, Opt_err_ro, Opt_nouid32, Opt_debug, Opt_removed, Opt_user_xattr, Opt_nouser_xattr, Opt_acl, Opt_noacl, Opt_auto_da_alloc, Opt_noauto_da_alloc, Opt_noload, Opt_commit, Opt_min_batch_time, Opt_max_batch_time, Opt_journal_dev, Opt_journal_path, Opt_journal_checksum, Opt_journal_async_commit, Opt_abort, Opt_data_journal, Opt_data_ordered, Opt_data_writeback, Opt_data_err_abort, Opt_data_err_ignore, Opt_test_dummy_encryption, Opt_usrjquota, Opt_grpjquota, Opt_offusrjquota, Opt_offgrpjquota, Opt_jqfmt_vfsold, Opt_jqfmt_vfsv0, Opt_jqfmt_vfsv1, Opt_quota, Opt_noquota, Opt_barrier, Opt_nobarrier, Opt_err, Opt_usrquota, Opt_grpquota, Opt_prjquota, Opt_i_version, Opt_dax, Opt_stripe, Opt_delalloc, Opt_nodelalloc, Opt_warn_on_error, Opt_nowarn_on_error, Opt_mblk_io_submit, Opt_lazytime, Opt_nolazytime, Opt_debug_want_extra_isize, Opt_nomblk_io_submit, Opt_block_validity, Opt_noblock_validity, Opt_inode_readahead_blks, Opt_journal_ioprio, Opt_dioread_nolock, Opt_dioread_lock, Opt_discard, Opt_nodiscard, Opt_init_itable, Opt_noinit_itable, Opt_max_dir_size_kb, Opt_nojournal_checksum, Opt_nombcache, };





















static const match_table_t tokens = {
	{Opt_bsd_df, "bsddf", {Opt_minix_df, "minixdf", {Opt_grpid, "grpid", {Opt_grpid, "bsdgroups", {Opt_nogrpid, "nogrpid", {Opt_nogrpid, "sysvgroups", {Opt_resgid, "resgid=%u", {Opt_resuid, "resuid=%u", {Opt_sb, "sb=%u", {Opt_err_cont, "errors=continue", {Opt_err_panic, "errors=panic", {Opt_err_ro, "errors=remount-ro", {Opt_nouid32, "nouid32", {Opt_debug, "debug", {Opt_removed, "oldalloc", {Opt_removed, "orlov", {Opt_user_xattr, "user_xattr", {Opt_nouser_xattr, "nouser_xattr", {Opt_acl, "acl", {Opt_noacl, "noacl", {Opt_noload, "norecovery", {Opt_noload, "noload", {Opt_removed, "nobh", {Opt_removed, "bh", {Opt_commit, "commit=%u", {Opt_min_batch_time, "min_batch_time=%u", {Opt_max_batch_time, "max_batch_time=%u", {Opt_journal_dev, "journal_dev=%u", {Opt_journal_path, "journal_path=%s", {Opt_journal_checksum, "journal_checksum", {Opt_nojournal_checksum, "nojournal_checksum", {Opt_journal_async_commit, "journal_async_commit", {Opt_abort, "abort", {Opt_data_journal, "data=journal", {Opt_data_ordered, "data=ordered", {Opt_data_writeback, "data=writeback", {Opt_data_err_abort, "data_err=abort", {Opt_data_err_ignore, "data_err=ignore", {Opt_offusrjquota, "usrjquota=", {Opt_usrjquota, "usrjquota=%s", {Opt_offgrpjquota, "grpjquota=", {Opt_grpjquota, "grpjquota=%s", {Opt_jqfmt_vfsold, "jqfmt=vfsold", {Opt_jqfmt_vfsv0, "jqfmt=vfsv0", {Opt_jqfmt_vfsv1, "jqfmt=vfsv1", {Opt_grpquota, "grpquota", {Opt_noquota, "noquota", {Opt_quota, "quota", {Opt_usrquota, "usrquota", {Opt_prjquota, "prjquota", {Opt_barrier, "barrier=%u", {Opt_barrier, "barrier", {Opt_nobarrier, "nobarrier", {Opt_i_version, "i_version", {Opt_dax, "dax", {Opt_stripe, "stripe=%u", {Opt_delalloc, "delalloc", {Opt_warn_on_error, "warn_on_error", {Opt_nowarn_on_error, "nowarn_on_error", {Opt_lazytime, "lazytime", {Opt_nolazytime, "nolazytime", {Opt_debug_want_extra_isize, "debug_want_extra_isize=%u", {Opt_nodelalloc, "nodelalloc", {Opt_removed, "mblk_io_submit", {Opt_removed, "nomblk_io_submit", {Opt_block_validity, "block_validity", {Opt_noblock_validity, "noblock_validity", {Opt_inode_readahead_blks, "inode_readahead_blks=%u", {Opt_journal_ioprio, "journal_ioprio=%u", {Opt_auto_da_alloc, "auto_da_alloc=%u", {Opt_auto_da_alloc, "auto_da_alloc", {Opt_noauto_da_alloc, "noauto_da_alloc", {Opt_dioread_nolock, "dioread_nolock", {Opt_dioread_lock, "dioread_lock", {Opt_discard, "discard", {Opt_nodiscard, "nodiscard", {Opt_init_itable, "init_itable=%u", {Opt_init_itable, "init_itable", {Opt_noinit_itable, "noinit_itable", {Opt_max_dir_size_kb, "max_dir_size_kb=%u", {Opt_test_dummy_encryption, "test_dummy_encryption", {Opt_nombcache, "nombcache", {Opt_nombcache, "no_mbcache", {Opt_removed, "check=none", {Opt_removed, "nocheck", {Opt_removed, "reservation", {Opt_removed, "noreservation", {Opt_removed, "journal=%u", {Opt_err, NULL}, };

























































































static ext4_fsblk_t get_sb_block(void **data)
{
	ext4_fsblk_t	sb_block;
	char		*options = (char *) *data;

	if (!options || strncmp(options, "sb=", 3) != 0)
		return 1;	

	options += 3;
	
	sb_block = simple_strtoul(options, &options, 0);
	if (*options && *options != ',') {
		printk(KERN_ERR "EXT4-fs: Invalid sb specification: %s\n", (char *) *data);
		return 1;
	}
	if (*options == ',')
		options++;
	*data = (void *) options;

	return sb_block;
}


static const char deprecated_msg[] = "Mount option \"%s\" will be removed by %s\n" "Contact linux-ext4@vger.kernel.org if you think we should keep it.\n";



static int set_qf_name(struct super_block *sb, int qtype, substring_t *args)
{
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	char *qname;
	int ret = -1;

	if (sb_any_quota_loaded(sb) && !sbi->s_qf_names[qtype]) {
		ext4_msg(sb, KERN_ERR, "Cannot change journaled " "quota options when quota turned on");

		return -1;
	}
	if (ext4_has_feature_quota(sb)) {
		ext4_msg(sb, KERN_INFO, "Journaled quota options " "ignored when QUOTA feature is enabled");
		return 1;
	}
	qname = match_strdup(args);
	if (!qname) {
		ext4_msg(sb, KERN_ERR, "Not enough memory for storing quotafile name");
		return -1;
	}
	if (sbi->s_qf_names[qtype]) {
		if (strcmp(sbi->s_qf_names[qtype], qname) == 0)
			ret = 1;
		else ext4_msg(sb, KERN_ERR, "%s quota file already specified", QTYPE2NAME(qtype));


		goto errout;
	}
	if (strchr(qname, '/')) {
		ext4_msg(sb, KERN_ERR, "quotafile must be on filesystem root");
		goto errout;
	}
	sbi->s_qf_names[qtype] = qname;
	set_opt(sb, QUOTA);
	return 1;
errout:
	kfree(qname);
	return ret;
}

static int clear_qf_name(struct super_block *sb, int qtype)
{

	struct ext4_sb_info *sbi = EXT4_SB(sb);

	if (sb_any_quota_loaded(sb) && sbi->s_qf_names[qtype]) {
		ext4_msg(sb, KERN_ERR, "Cannot change journaled quota options" " when quota turned on");
		return -1;
	}
	kfree(sbi->s_qf_names[qtype]);
	sbi->s_qf_names[qtype] = NULL;
	return 1;
}





















static const struct mount_opts {
	int	token;
	int	mount_opt;
	int	flags;
} ext4_mount_opts[] = {
	{Opt_minix_df, EXT4_MOUNT_MINIX_DF, MOPT_SET}, {Opt_bsd_df, EXT4_MOUNT_MINIX_DF, MOPT_CLEAR}, {Opt_grpid, EXT4_MOUNT_GRPID, MOPT_SET}, {Opt_nogrpid, EXT4_MOUNT_GRPID, MOPT_CLEAR}, {Opt_block_validity, EXT4_MOUNT_BLOCK_VALIDITY, MOPT_SET}, {Opt_noblock_validity, EXT4_MOUNT_BLOCK_VALIDITY, MOPT_CLEAR}, {Opt_dioread_nolock, EXT4_MOUNT_DIOREAD_NOLOCK, MOPT_EXT4_ONLY | MOPT_SET}, {Opt_dioread_lock, EXT4_MOUNT_DIOREAD_NOLOCK, MOPT_EXT4_ONLY | MOPT_CLEAR}, {Opt_discard, EXT4_MOUNT_DISCARD, MOPT_SET}, {Opt_nodiscard, EXT4_MOUNT_DISCARD, MOPT_CLEAR}, {Opt_delalloc, EXT4_MOUNT_DELALLOC, MOPT_EXT4_ONLY | MOPT_SET | MOPT_EXPLICIT}, {Opt_nodelalloc, EXT4_MOUNT_DELALLOC, MOPT_EXT4_ONLY | MOPT_CLEAR}, {Opt_warn_on_error, EXT4_MOUNT_WARN_ON_ERROR, MOPT_SET}, {Opt_nowarn_on_error, EXT4_MOUNT_WARN_ON_ERROR, MOPT_CLEAR}, {Opt_nojournal_checksum, EXT4_MOUNT_JOURNAL_CHECKSUM, MOPT_EXT4_ONLY | MOPT_CLEAR}, {Opt_journal_checksum, EXT4_MOUNT_JOURNAL_CHECKSUM, MOPT_EXT4_ONLY | MOPT_SET | MOPT_EXPLICIT}, {Opt_journal_async_commit, (EXT4_MOUNT_JOURNAL_ASYNC_COMMIT | EXT4_MOUNT_JOURNAL_CHECKSUM), MOPT_EXT4_ONLY | MOPT_SET | MOPT_EXPLICIT}, {Opt_noload, EXT4_MOUNT_NOLOAD, MOPT_NO_EXT2 | MOPT_SET}, {Opt_err_panic, EXT4_MOUNT_ERRORS_PANIC, MOPT_SET | MOPT_CLEAR_ERR}, {Opt_err_ro, EXT4_MOUNT_ERRORS_RO, MOPT_SET | MOPT_CLEAR_ERR}, {Opt_err_cont, EXT4_MOUNT_ERRORS_CONT, MOPT_SET | MOPT_CLEAR_ERR}, {Opt_data_err_abort, EXT4_MOUNT_DATA_ERR_ABORT, MOPT_NO_EXT2}, {Opt_data_err_ignore, EXT4_MOUNT_DATA_ERR_ABORT, MOPT_NO_EXT2}, {Opt_barrier, EXT4_MOUNT_BARRIER, MOPT_SET}, {Opt_nobarrier, EXT4_MOUNT_BARRIER, MOPT_CLEAR}, {Opt_noauto_da_alloc, EXT4_MOUNT_NO_AUTO_DA_ALLOC, MOPT_SET}, {Opt_auto_da_alloc, EXT4_MOUNT_NO_AUTO_DA_ALLOC, MOPT_CLEAR}, {Opt_noinit_itable, EXT4_MOUNT_INIT_INODE_TABLE, MOPT_CLEAR}, {Opt_commit, 0, MOPT_GTE0}, {Opt_max_batch_time, 0, MOPT_GTE0}, {Opt_min_batch_time, 0, MOPT_GTE0}, {Opt_inode_readahead_blks, 0, MOPT_GTE0}, {Opt_init_itable, 0, MOPT_GTE0}, {Opt_dax, EXT4_MOUNT_DAX, MOPT_SET}, {Opt_stripe, 0, MOPT_GTE0}, {Opt_resuid, 0, MOPT_GTE0}, {Opt_resgid, 0, MOPT_GTE0}, {Opt_journal_dev, 0, MOPT_NO_EXT2 | MOPT_GTE0}, {Opt_journal_path, 0, MOPT_NO_EXT2 | MOPT_STRING}, {Opt_journal_ioprio, 0, MOPT_NO_EXT2 | MOPT_GTE0}, {Opt_data_journal, EXT4_MOUNT_JOURNAL_DATA, MOPT_NO_EXT2 | MOPT_DATAJ}, {Opt_data_ordered, EXT4_MOUNT_ORDERED_DATA, MOPT_NO_EXT2 | MOPT_DATAJ}, {Opt_data_writeback, EXT4_MOUNT_WRITEBACK_DATA, MOPT_NO_EXT2 | MOPT_DATAJ}, {Opt_user_xattr, EXT4_MOUNT_XATTR_USER, MOPT_SET}, {Opt_nouser_xattr, EXT4_MOUNT_XATTR_USER, MOPT_CLEAR},  {Opt_acl, EXT4_MOUNT_POSIX_ACL, MOPT_SET}, {Opt_noacl, EXT4_MOUNT_POSIX_ACL, MOPT_CLEAR},  {Opt_acl, 0, MOPT_NOSUPPORT}, {Opt_noacl, 0, MOPT_NOSUPPORT},  {Opt_nouid32, EXT4_MOUNT_NO_UID32, MOPT_SET}, {Opt_debug, EXT4_MOUNT_DEBUG, MOPT_SET}, {Opt_debug_want_extra_isize, 0, MOPT_GTE0}, {Opt_quota, EXT4_MOUNT_QUOTA | EXT4_MOUNT_USRQUOTA, MOPT_SET | MOPT_Q}, {Opt_usrquota, EXT4_MOUNT_QUOTA | EXT4_MOUNT_USRQUOTA, MOPT_SET | MOPT_Q}, {Opt_grpquota, EXT4_MOUNT_QUOTA | EXT4_MOUNT_GRPQUOTA, MOPT_SET | MOPT_Q}, {Opt_prjquota, EXT4_MOUNT_QUOTA | EXT4_MOUNT_PRJQUOTA, MOPT_SET | MOPT_Q}, {Opt_noquota, (EXT4_MOUNT_QUOTA | EXT4_MOUNT_USRQUOTA | EXT4_MOUNT_GRPQUOTA | EXT4_MOUNT_PRJQUOTA), MOPT_CLEAR | MOPT_Q}, {Opt_usrjquota, 0, MOPT_Q}, {Opt_grpjquota, 0, MOPT_Q}, {Opt_offusrjquota, 0, MOPT_Q}, {Opt_offgrpjquota, 0, MOPT_Q}, {Opt_jqfmt_vfsold, QFMT_VFS_OLD, MOPT_QFMT}, {Opt_jqfmt_vfsv0, QFMT_VFS_V0, MOPT_QFMT}, {Opt_jqfmt_vfsv1, QFMT_VFS_V1, MOPT_QFMT}, {Opt_max_dir_size_kb, 0, MOPT_GTE0}, {Opt_test_dummy_encryption, 0, MOPT_GTE0}, {Opt_nombcache, EXT4_MOUNT_NO_MBCACHE, MOPT_SET}, {Opt_err, 0, 0}





















































































};

static int handle_mount_opt(struct super_block *sb, char *opt, int token, substring_t *args, unsigned long *journal_devnum, unsigned int *journal_ioprio, int is_remount)

{
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	const struct mount_opts *m;
	kuid_t uid;
	kgid_t gid;
	int arg = 0;


	if (token == Opt_usrjquota)
		return set_qf_name(sb, USRQUOTA, &args[0]);
	else if (token == Opt_grpjquota)
		return set_qf_name(sb, GRPQUOTA, &args[0]);
	else if (token == Opt_offusrjquota)
		return clear_qf_name(sb, USRQUOTA);
	else if (token == Opt_offgrpjquota)
		return clear_qf_name(sb, GRPQUOTA);

	switch (token) {
	case Opt_noacl:
	case Opt_nouser_xattr:
		ext4_msg(sb, KERN_WARNING, deprecated_msg, opt, "3.5");
		break;
	case Opt_sb:
		return 1;	
	case Opt_removed:
		ext4_msg(sb, KERN_WARNING, "Ignoring removed %s option", opt);
		return 1;
	case Opt_abort:
		sbi->s_mount_flags |= EXT4_MF_FS_ABORTED;
		return 1;
	case Opt_i_version:
		sb->s_flags |= SB_I_VERSION;
		return 1;
	case Opt_lazytime:
		sb->s_flags |= SB_LAZYTIME;
		return 1;
	case Opt_nolazytime:
		sb->s_flags &= ~SB_LAZYTIME;
		return 1;
	}

	for (m = ext4_mount_opts; m->token != Opt_err; m++)
		if (token == m->token)
			break;

	if (m->token == Opt_err) {
		ext4_msg(sb, KERN_ERR, "Unrecognized mount option \"%s\" " "or missing value", opt);
		return -1;
	}

	if ((m->flags & MOPT_NO_EXT2) && IS_EXT2_SB(sb)) {
		ext4_msg(sb, KERN_ERR, "Mount option \"%s\" incompatible with ext2", opt);
		return -1;
	}
	if ((m->flags & MOPT_NO_EXT3) && IS_EXT3_SB(sb)) {
		ext4_msg(sb, KERN_ERR, "Mount option \"%s\" incompatible with ext3", opt);
		return -1;
	}

	if (args->from && !(m->flags & MOPT_STRING) && match_int(args, &arg))
		return -1;
	if (args->from && (m->flags & MOPT_GTE0) && (arg < 0))
		return -1;
	if (m->flags & MOPT_EXPLICIT) {
		if (m->mount_opt & EXT4_MOUNT_DELALLOC) {
			set_opt2(sb, EXPLICIT_DELALLOC);
		} else if (m->mount_opt & EXT4_MOUNT_JOURNAL_CHECKSUM) {
			set_opt2(sb, EXPLICIT_JOURNAL_CHECKSUM);
		} else return -1;
	}
	if (m->flags & MOPT_CLEAR_ERR)
		clear_opt(sb, ERRORS_MASK);
	if (token == Opt_noquota && sb_any_quota_loaded(sb)) {
		ext4_msg(sb, KERN_ERR, "Cannot change quota " "options when quota turned on");
		return -1;
	}

	if (m->flags & MOPT_NOSUPPORT) {
		ext4_msg(sb, KERN_ERR, "%s option not supported", opt);
	} else if (token == Opt_commit) {
		if (arg == 0)
			arg = JBD2_DEFAULT_MAX_COMMIT_AGE;
		sbi->s_commit_interval = HZ * arg;
	} else if (token == Opt_debug_want_extra_isize) {
		sbi->s_want_extra_isize = arg;
	} else if (token == Opt_max_batch_time) {
		sbi->s_max_batch_time = arg;
	} else if (token == Opt_min_batch_time) {
		sbi->s_min_batch_time = arg;
	} else if (token == Opt_inode_readahead_blks) {
		if (arg && (arg > (1 << 30) || !is_power_of_2(arg))) {
			ext4_msg(sb, KERN_ERR, "EXT4-fs: inode_readahead_blks must be " "0 or a power of 2 smaller than 2^31");

			return -1;
		}
		sbi->s_inode_readahead_blks = arg;
	} else if (token == Opt_init_itable) {
		set_opt(sb, INIT_INODE_TABLE);
		if (!args->from)
			arg = EXT4_DEF_LI_WAIT_MULT;
		sbi->s_li_wait_mult = arg;
	} else if (token == Opt_max_dir_size_kb) {
		sbi->s_max_dir_size_kb = arg;
	} else if (token == Opt_stripe) {
		sbi->s_stripe = arg;
	} else if (token == Opt_resuid) {
		uid = make_kuid(current_user_ns(), arg);
		if (!uid_valid(uid)) {
			ext4_msg(sb, KERN_ERR, "Invalid uid value %d", arg);
			return -1;
		}
		sbi->s_resuid = uid;
	} else if (token == Opt_resgid) {
		gid = make_kgid(current_user_ns(), arg);
		if (!gid_valid(gid)) {
			ext4_msg(sb, KERN_ERR, "Invalid gid value %d", arg);
			return -1;
		}
		sbi->s_resgid = gid;
	} else if (token == Opt_journal_dev) {
		if (is_remount) {
			ext4_msg(sb, KERN_ERR, "Cannot specify journal on remount");
			return -1;
		}
		*journal_devnum = arg;
	} else if (token == Opt_journal_path) {
		char *journal_path;
		struct inode *journal_inode;
		struct path path;
		int error;

		if (is_remount) {
			ext4_msg(sb, KERN_ERR, "Cannot specify journal on remount");
			return -1;
		}
		journal_path = match_strdup(&args[0]);
		if (!journal_path) {
			ext4_msg(sb, KERN_ERR, "error: could not dup " "journal device string");
			return -1;
		}

		error = kern_path(journal_path, LOOKUP_FOLLOW, &path);
		if (error) {
			ext4_msg(sb, KERN_ERR, "error: could not find " "journal device path: error %d", error);
			kfree(journal_path);
			return -1;
		}

		journal_inode = d_inode(path.dentry);
		if (!S_ISBLK(journal_inode->i_mode)) {
			ext4_msg(sb, KERN_ERR, "error: journal path %s " "is not a block device", journal_path);
			path_put(&path);
			kfree(journal_path);
			return -1;
		}

		*journal_devnum = new_encode_dev(journal_inode->i_rdev);
		path_put(&path);
		kfree(journal_path);
	} else if (token == Opt_journal_ioprio) {
		if (arg > 7) {
			ext4_msg(sb, KERN_ERR, "Invalid journal IO priority" " (must be 0-7)");
			return -1;
		}
		*journal_ioprio = IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, arg);
	} else if (token == Opt_test_dummy_encryption) {

		sbi->s_mount_flags |= EXT4_MF_TEST_DUMMY_ENCRYPTION;
		ext4_msg(sb, KERN_WARNING, "Test dummy encryption mode enabled");

		ext4_msg(sb, KERN_WARNING, "Test dummy encryption mount option ignored");

	} else if (m->flags & MOPT_DATAJ) {
		if (is_remount) {
			if (!sbi->s_journal)
				ext4_msg(sb, KERN_WARNING, "Remounting file system with no journal so ignoring journalled data option");
			else if (test_opt(sb, DATA_FLAGS) != m->mount_opt) {
				ext4_msg(sb, KERN_ERR, "Cannot change data mode on remount");
				return -1;
			}
		} else {
			clear_opt(sb, DATA_FLAGS);
			sbi->s_mount_opt |= m->mount_opt;
		}

	} else if (m->flags & MOPT_QFMT) {
		if (sb_any_quota_loaded(sb) && sbi->s_jquota_fmt != m->mount_opt) {
			ext4_msg(sb, KERN_ERR, "Cannot change journaled " "quota options when quota turned on");
			return -1;
		}
		if (ext4_has_feature_quota(sb)) {
			ext4_msg(sb, KERN_INFO, "Quota format mount options ignored " "when QUOTA feature is enabled");

			return 1;
		}
		sbi->s_jquota_fmt = m->mount_opt;

	} else if (token == Opt_dax) {

		ext4_msg(sb, KERN_WARNING, "DAX enabled. Warning: EXPERIMENTAL, use at your own risk");
			sbi->s_mount_opt |= m->mount_opt;

		ext4_msg(sb, KERN_INFO, "dax option not supported");
		return -1;

	} else if (token == Opt_data_err_abort) {
		sbi->s_mount_opt |= m->mount_opt;
	} else if (token == Opt_data_err_ignore) {
		sbi->s_mount_opt &= ~m->mount_opt;
	} else {
		if (!args->from)
			arg = 1;
		if (m->flags & MOPT_CLEAR)
			arg = !arg;
		else if (unlikely(!(m->flags & MOPT_SET))) {
			ext4_msg(sb, KERN_WARNING, "buggy handling of option %s", opt);
			WARN_ON(1);
			return -1;
		}
		if (arg != 0)
			sbi->s_mount_opt |= m->mount_opt;
		else sbi->s_mount_opt &= ~m->mount_opt;
	}
	return 1;
}

static int parse_options(char *options, struct super_block *sb, unsigned long *journal_devnum, unsigned int *journal_ioprio, int is_remount)


{
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	char *p;
	substring_t args[MAX_OPT_ARGS];
	int token;

	if (!options)
		return 1;

	while ((p = strsep(&options, ",")) != NULL) {
		if (!*p)
			continue;
		
		args[0].to = args[0].from = NULL;
		token = match_token(p, tokens, args);
		if (handle_mount_opt(sb, p, token, args, journal_devnum, journal_ioprio, is_remount) < 0)
			return 0;
	}

	
	if (test_opt(sb, PRJQUOTA) && !ext4_has_feature_project(sb)) {
		ext4_msg(sb, KERN_ERR, "Project quota feature not enabled. " "Cannot enable project quota enforcement.");
		return 0;
	}
	if (sbi->s_qf_names[USRQUOTA] || sbi->s_qf_names[GRPQUOTA]) {
		if (test_opt(sb, USRQUOTA) && sbi->s_qf_names[USRQUOTA])
			clear_opt(sb, USRQUOTA);

		if (test_opt(sb, GRPQUOTA) && sbi->s_qf_names[GRPQUOTA])
			clear_opt(sb, GRPQUOTA);

		if (test_opt(sb, GRPQUOTA) || test_opt(sb, USRQUOTA)) {
			ext4_msg(sb, KERN_ERR, "old and new quota " "format mixing");
			return 0;
		}

		if (!sbi->s_jquota_fmt) {
			ext4_msg(sb, KERN_ERR, "journaled quota format " "not specified");
			return 0;
		}
	}

	if (test_opt(sb, DIOREAD_NOLOCK)) {
		int blocksize = BLOCK_SIZE << le32_to_cpu(sbi->s_es->s_log_block_size);

		if (blocksize < PAGE_SIZE) {
			ext4_msg(sb, KERN_ERR, "can't mount with " "dioread_nolock if block size != PAGE_SIZE");
			return 0;
		}
	}
	return 1;
}

static inline void ext4_show_quota_options(struct seq_file *seq, struct super_block *sb)
{

	struct ext4_sb_info *sbi = EXT4_SB(sb);

	if (sbi->s_jquota_fmt) {
		char *fmtname = "";

		switch (sbi->s_jquota_fmt) {
		case QFMT_VFS_OLD:
			fmtname = "vfsold";
			break;
		case QFMT_VFS_V0:
			fmtname = "vfsv0";
			break;
		case QFMT_VFS_V1:
			fmtname = "vfsv1";
			break;
		}
		seq_printf(seq, ",jqfmt=%s", fmtname);
	}

	if (sbi->s_qf_names[USRQUOTA])
		seq_show_option(seq, "usrjquota", sbi->s_qf_names[USRQUOTA]);

	if (sbi->s_qf_names[GRPQUOTA])
		seq_show_option(seq, "grpjquota", sbi->s_qf_names[GRPQUOTA]);

}

static const char *token2str(int token)
{
	const struct match_token *t;

	for (t = tokens; t->token != Opt_err; t++)
		if (t->token == token && !strchr(t->pattern, '='))
			break;
	return t->pattern;
}


static int _ext4_show_options(struct seq_file *seq, struct super_block *sb, int nodefs)
{
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	struct ext4_super_block *es = sbi->s_es;
	int def_errors, def_mount_opt = sbi->s_def_mount_opt;
	const struct mount_opts *m;
	char sep = nodefs ? '\n' : ',';




	if (sbi->s_sb_block != 1)
		SEQ_OPTS_PRINT("sb=%llu", sbi->s_sb_block);

	for (m = ext4_mount_opts; m->token != Opt_err; m++) {
		int want_set = m->flags & MOPT_SET;
		if (((m->flags & (MOPT_SET|MOPT_CLEAR)) == 0) || (m->flags & MOPT_CLEAR_ERR))
			continue;
		if (!nodefs && !(m->mount_opt & (sbi->s_mount_opt ^ def_mount_opt)))
			continue; 
		if ((want_set && (sbi->s_mount_opt & m->mount_opt) != m->mount_opt) || (!want_set && (sbi->s_mount_opt & m->mount_opt)))

			continue; 
		SEQ_OPTS_PRINT("%s", token2str(m->token));
	}

	if (nodefs || !uid_eq(sbi->s_resuid, make_kuid(&init_user_ns, EXT4_DEF_RESUID)) || le16_to_cpu(es->s_def_resuid) != EXT4_DEF_RESUID)
		SEQ_OPTS_PRINT("resuid=%u", from_kuid_munged(&init_user_ns, sbi->s_resuid));
	if (nodefs || !gid_eq(sbi->s_resgid, make_kgid(&init_user_ns, EXT4_DEF_RESGID)) || le16_to_cpu(es->s_def_resgid) != EXT4_DEF_RESGID)
		SEQ_OPTS_PRINT("resgid=%u", from_kgid_munged(&init_user_ns, sbi->s_resgid));
	def_errors = nodefs ? -1 : le16_to_cpu(es->s_errors);
	if (test_opt(sb, ERRORS_RO) && def_errors != EXT4_ERRORS_RO)
		SEQ_OPTS_PUTS("errors=remount-ro");
	if (test_opt(sb, ERRORS_CONT) && def_errors != EXT4_ERRORS_CONTINUE)
		SEQ_OPTS_PUTS("errors=continue");
	if (test_opt(sb, ERRORS_PANIC) && def_errors != EXT4_ERRORS_PANIC)
		SEQ_OPTS_PUTS("errors=panic");
	if (nodefs || sbi->s_commit_interval != JBD2_DEFAULT_MAX_COMMIT_AGE*HZ)
		SEQ_OPTS_PRINT("commit=%lu", sbi->s_commit_interval / HZ);
	if (nodefs || sbi->s_min_batch_time != EXT4_DEF_MIN_BATCH_TIME)
		SEQ_OPTS_PRINT("min_batch_time=%u", sbi->s_min_batch_time);
	if (nodefs || sbi->s_max_batch_time != EXT4_DEF_MAX_BATCH_TIME)
		SEQ_OPTS_PRINT("max_batch_time=%u", sbi->s_max_batch_time);
	if (sb->s_flags & SB_I_VERSION)
		SEQ_OPTS_PUTS("i_version");
	if (nodefs || sbi->s_stripe)
		SEQ_OPTS_PRINT("stripe=%lu", sbi->s_stripe);
	if (nodefs || EXT4_MOUNT_DATA_FLAGS & (sbi->s_mount_opt ^ def_mount_opt)) {
		if (test_opt(sb, DATA_FLAGS) == EXT4_MOUNT_JOURNAL_DATA)
			SEQ_OPTS_PUTS("data=journal");
		else if (test_opt(sb, DATA_FLAGS) == EXT4_MOUNT_ORDERED_DATA)
			SEQ_OPTS_PUTS("data=ordered");
		else if (test_opt(sb, DATA_FLAGS) == EXT4_MOUNT_WRITEBACK_DATA)
			SEQ_OPTS_PUTS("data=writeback");
	}
	if (nodefs || sbi->s_inode_readahead_blks != EXT4_DEF_INODE_READAHEAD_BLKS)
		SEQ_OPTS_PRINT("inode_readahead_blks=%u", sbi->s_inode_readahead_blks);

	if (test_opt(sb, INIT_INODE_TABLE) && (nodefs || (sbi->s_li_wait_mult != EXT4_DEF_LI_WAIT_MULT)))
		SEQ_OPTS_PRINT("init_itable=%u", sbi->s_li_wait_mult);
	if (nodefs || sbi->s_max_dir_size_kb)
		SEQ_OPTS_PRINT("max_dir_size_kb=%u", sbi->s_max_dir_size_kb);
	if (test_opt(sb, DATA_ERR_ABORT))
		SEQ_OPTS_PUTS("data_err=abort");

	ext4_show_quota_options(seq, sb);
	return 0;
}

static int ext4_show_options(struct seq_file *seq, struct dentry *root)
{
	return _ext4_show_options(seq, root->d_sb, 0);
}

int ext4_seq_options_show(struct seq_file *seq, void *offset)
{
	struct super_block *sb = seq->private;
	int rc;

	seq_puts(seq, sb_rdonly(sb) ? "ro" : "rw");
	rc = _ext4_show_options(seq, sb, 1);
	seq_puts(seq, "\n");
	return rc;
}

static int ext4_setup_super(struct super_block *sb, struct ext4_super_block *es, int read_only)
{
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	int err = 0;

	if (le32_to_cpu(es->s_rev_level) > EXT4_MAX_SUPP_REV) {
		ext4_msg(sb, KERN_ERR, "revision level too high, " "forcing read-only mode");
		err = -EROFS;
	}
	if (read_only)
		goto done;
	if (!(sbi->s_mount_state & EXT4_VALID_FS))
		ext4_msg(sb, KERN_WARNING, "warning: mounting unchecked fs, " "running e2fsck is recommended");
	else if (sbi->s_mount_state & EXT4_ERROR_FS)
		ext4_msg(sb, KERN_WARNING, "warning: mounting fs with errors, " "running e2fsck is recommended");

	else if ((__s16) le16_to_cpu(es->s_max_mnt_count) > 0 && le16_to_cpu(es->s_mnt_count) >= (unsigned short) (__s16) le16_to_cpu(es->s_max_mnt_count))

		ext4_msg(sb, KERN_WARNING, "warning: maximal mount count reached, " "running e2fsck is recommended");

	else if (le32_to_cpu(es->s_checkinterval) && (le32_to_cpu(es->s_lastcheck) + le32_to_cpu(es->s_checkinterval) <= get_seconds()))

		ext4_msg(sb, KERN_WARNING, "warning: checktime reached, " "running e2fsck is recommended");

	if (!sbi->s_journal)
		es->s_state &= cpu_to_le16(~EXT4_VALID_FS);
	if (!(__s16) le16_to_cpu(es->s_max_mnt_count))
		es->s_max_mnt_count = cpu_to_le16(EXT4_DFL_MAX_MNT_COUNT);
	le16_add_cpu(&es->s_mnt_count, 1);
	es->s_mtime = cpu_to_le32(get_seconds());
	ext4_update_dynamic_rev(sb);
	if (sbi->s_journal)
		ext4_set_feature_journal_needs_recovery(sb);

	err = ext4_commit_super(sb, 1);
done:
	if (test_opt(sb, DEBUG))
		printk(KERN_INFO "[EXT4 FS bs=%lu, gc=%u, " "bpg=%lu, ipg=%lu, mo=%04x, mo2=%04x]\n", sb->s_blocksize, sbi->s_groups_count, EXT4_BLOCKS_PER_GROUP(sb), EXT4_INODES_PER_GROUP(sb), sbi->s_mount_opt, sbi->s_mount_opt2);






	cleancache_init_fs(sb);
	return err;
}

int ext4_alloc_flex_bg_array(struct super_block *sb, ext4_group_t ngroup)
{
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	struct flex_groups *new_groups;
	int size;

	if (!sbi->s_log_groups_per_flex)
		return 0;

	size = ext4_flex_group(sbi, ngroup - 1) + 1;
	if (size <= sbi->s_flex_groups_allocated)
		return 0;

	size = roundup_pow_of_two(size * sizeof(struct flex_groups));
	new_groups = kvzalloc(size, GFP_KERNEL);
	if (!new_groups) {
		ext4_msg(sb, KERN_ERR, "not enough memory for %d flex groups", size / (int) sizeof(struct flex_groups));
		return -ENOMEM;
	}

	if (sbi->s_flex_groups) {
		memcpy(new_groups, sbi->s_flex_groups, (sbi->s_flex_groups_allocated * sizeof(struct flex_groups)));

		kvfree(sbi->s_flex_groups);
	}
	sbi->s_flex_groups = new_groups;
	sbi->s_flex_groups_allocated = size / sizeof(struct flex_groups);
	return 0;
}

static int ext4_fill_flex_info(struct super_block *sb)
{
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	struct ext4_group_desc *gdp = NULL;
	ext4_group_t flex_group;
	int i, err;

	sbi->s_log_groups_per_flex = sbi->s_es->s_log_groups_per_flex;
	if (sbi->s_log_groups_per_flex < 1 || sbi->s_log_groups_per_flex > 31) {
		sbi->s_log_groups_per_flex = 0;
		return 1;
	}

	err = ext4_alloc_flex_bg_array(sb, sbi->s_groups_count);
	if (err)
		goto failed;

	for (i = 0; i < sbi->s_groups_count; i++) {
		gdp = ext4_get_group_desc(sb, i, NULL);

		flex_group = ext4_flex_group(sbi, i);
		atomic_add(ext4_free_inodes_count(sb, gdp), &sbi->s_flex_groups[flex_group].free_inodes);
		atomic64_add(ext4_free_group_clusters(sb, gdp), &sbi->s_flex_groups[flex_group].free_clusters);
		atomic_add(ext4_used_dirs_count(sb, gdp), &sbi->s_flex_groups[flex_group].used_dirs);
	}

	return 1;
failed:
	return 0;
}

static __le16 ext4_group_desc_csum(struct super_block *sb, __u32 block_group, struct ext4_group_desc *gdp)
{
	int offset = offsetof(struct ext4_group_desc, bg_checksum);
	__u16 crc = 0;
	__le32 le_group = cpu_to_le32(block_group);
	struct ext4_sb_info *sbi = EXT4_SB(sb);

	if (ext4_has_metadata_csum(sbi->s_sb)) {
		
		__u32 csum32;
		__u16 dummy_csum = 0;

		csum32 = ext4_chksum(sbi, sbi->s_csum_seed, (__u8 *)&le_group, sizeof(le_group));
		csum32 = ext4_chksum(sbi, csum32, (__u8 *)gdp, offset);
		csum32 = ext4_chksum(sbi, csum32, (__u8 *)&dummy_csum, sizeof(dummy_csum));
		offset += sizeof(dummy_csum);
		if (offset < sbi->s_desc_size)
			csum32 = ext4_chksum(sbi, csum32, (__u8 *)gdp + offset, sbi->s_desc_size - offset);

		crc = csum32 & 0xFFFF;
		goto out;
	}

	
	if (!ext4_has_feature_gdt_csum(sb))
		return 0;

	crc = crc16(~0, sbi->s_es->s_uuid, sizeof(sbi->s_es->s_uuid));
	crc = crc16(crc, (__u8 *)&le_group, sizeof(le_group));
	crc = crc16(crc, (__u8 *)gdp, offset);
	offset += sizeof(gdp->bg_checksum); 
	
	if (ext4_has_feature_64bit(sb) && offset < le16_to_cpu(sbi->s_es->s_desc_size))
		crc = crc16(crc, (__u8 *)gdp + offset, le16_to_cpu(sbi->s_es->s_desc_size) - offset);


out:
	return cpu_to_le16(crc);
}

int ext4_group_desc_csum_verify(struct super_block *sb, __u32 block_group, struct ext4_group_desc *gdp)
{
	if (ext4_has_group_desc_csum(sb) && (gdp->bg_checksum != ext4_group_desc_csum(sb, block_group, gdp)))
		return 0;

	return 1;
}

void ext4_group_desc_csum_set(struct super_block *sb, __u32 block_group, struct ext4_group_desc *gdp)
{
	if (!ext4_has_group_desc_csum(sb))
		return;
	gdp->bg_checksum = ext4_group_desc_csum(sb, block_group, gdp);
}


static int ext4_check_descriptors(struct super_block *sb, ext4_fsblk_t sb_block, ext4_group_t *first_not_zeroed)

{
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	ext4_fsblk_t first_block = le32_to_cpu(sbi->s_es->s_first_data_block);
	ext4_fsblk_t last_block;
	ext4_fsblk_t last_bg_block = sb_block + ext4_bg_num_gdb(sb, 0) + 1;
	ext4_fsblk_t block_bitmap;
	ext4_fsblk_t inode_bitmap;
	ext4_fsblk_t inode_table;
	int flexbg_flag = 0;
	ext4_group_t i, grp = sbi->s_groups_count;

	if (ext4_has_feature_flex_bg(sb))
		flexbg_flag = 1;

	ext4_debug("Checking group descriptors");

	for (i = 0; i < sbi->s_groups_count; i++) {
		struct ext4_group_desc *gdp = ext4_get_group_desc(sb, i, NULL);

		if (i == sbi->s_groups_count - 1 || flexbg_flag)
			last_block = ext4_blocks_count(sbi->s_es) - 1;
		else last_block = first_block + (EXT4_BLOCKS_PER_GROUP(sb) - 1);


		if ((grp == sbi->s_groups_count) && !(gdp->bg_flags & cpu_to_le16(EXT4_BG_INODE_ZEROED)))
			grp = i;

		block_bitmap = ext4_block_bitmap(sb, gdp);
		if (block_bitmap == sb_block) {
			ext4_msg(sb, KERN_ERR, "ext4_check_descriptors: " "Block bitmap for group %u overlaps " "superblock", i);

			if (!sb_rdonly(sb))
				return 0;
		}
		if (block_bitmap >= sb_block + 1 && block_bitmap <= last_bg_block) {
			ext4_msg(sb, KERN_ERR, "ext4_check_descriptors: " "Block bitmap for group %u overlaps " "block group descriptors", i);

			if (!sb_rdonly(sb))
				return 0;
		}
		if (block_bitmap < first_block || block_bitmap > last_block) {
			ext4_msg(sb, KERN_ERR, "ext4_check_descriptors: " "Block bitmap for group %u not in group " "(block %llu)!", i, block_bitmap);

			return 0;
		}
		inode_bitmap = ext4_inode_bitmap(sb, gdp);
		if (inode_bitmap == sb_block) {
			ext4_msg(sb, KERN_ERR, "ext4_check_descriptors: " "Inode bitmap for group %u overlaps " "superblock", i);

			if (!sb_rdonly(sb))
				return 0;
		}
		if (inode_bitmap >= sb_block + 1 && inode_bitmap <= last_bg_block) {
			ext4_msg(sb, KERN_ERR, "ext4_check_descriptors: " "Inode bitmap for group %u overlaps " "block group descriptors", i);

			if (!sb_rdonly(sb))
				return 0;
		}
		if (inode_bitmap < first_block || inode_bitmap > last_block) {
			ext4_msg(sb, KERN_ERR, "ext4_check_descriptors: " "Inode bitmap for group %u not in group " "(block %llu)!", i, inode_bitmap);

			return 0;
		}
		inode_table = ext4_inode_table(sb, gdp);
		if (inode_table == sb_block) {
			ext4_msg(sb, KERN_ERR, "ext4_check_descriptors: " "Inode table for group %u overlaps " "superblock", i);

			if (!sb_rdonly(sb))
				return 0;
		}
		if (inode_table >= sb_block + 1 && inode_table <= last_bg_block) {
			ext4_msg(sb, KERN_ERR, "ext4_check_descriptors: " "Inode table for group %u overlaps " "block group descriptors", i);

			if (!sb_rdonly(sb))
				return 0;
		}
		if (inode_table < first_block || inode_table + sbi->s_itb_per_group - 1 > last_block) {
			ext4_msg(sb, KERN_ERR, "ext4_check_descriptors: " "Inode table for group %u not in group " "(block %llu)!", i, inode_table);

			return 0;
		}
		ext4_lock_group(sb, i);
		if (!ext4_group_desc_csum_verify(sb, i, gdp)) {
			ext4_msg(sb, KERN_ERR, "ext4_check_descriptors: " "Checksum for group %u failed (%u!=%u)", i, le16_to_cpu(ext4_group_desc_csum(sb, i, gdp)), le16_to_cpu(gdp->bg_checksum));


			if (!sb_rdonly(sb)) {
				ext4_unlock_group(sb, i);
				return 0;
			}
		}
		ext4_unlock_group(sb, i);
		if (!flexbg_flag)
			first_block += EXT4_BLOCKS_PER_GROUP(sb);
	}
	if (NULL != first_not_zeroed)
		*first_not_zeroed = grp;
	return 1;
}


static void ext4_orphan_cleanup(struct super_block *sb, struct ext4_super_block *es)
{
	unsigned int s_flags = sb->s_flags;
	int ret, nr_orphans = 0, nr_truncates = 0;

	int quota_update = 0;
	int i;

	if (!es->s_last_orphan) {
		jbd_debug(4, "no orphan inodes to clean up\n");
		return;
	}

	if (bdev_read_only(sb->s_bdev)) {
		ext4_msg(sb, KERN_ERR, "write access " "unavailable, skipping orphan cleanup");
		return;
	}

	
	if (!ext4_feature_set_ok(sb, 0)) {
		ext4_msg(sb, KERN_INFO, "Skipping orphan cleanup due to " "unknown ROCOMPAT features");
		return;
	}

	if (EXT4_SB(sb)->s_mount_state & EXT4_ERROR_FS) {
		
		if (es->s_last_orphan && !(s_flags & SB_RDONLY)) {
			ext4_msg(sb, KERN_INFO, "Errors on filesystem, " "clearing orphan list.\n");
			es->s_last_orphan = 0;
		}
		jbd_debug(1, "Skipping orphan recovery on fs with errors.\n");
		return;
	}

	if (s_flags & SB_RDONLY) {
		ext4_msg(sb, KERN_INFO, "orphan cleanup on readonly fs");
		sb->s_flags &= ~SB_RDONLY;
	}

	
	sb->s_flags |= SB_ACTIVE;

	
	if (ext4_has_feature_quota(sb) && (s_flags & SB_RDONLY)) {
		int ret = ext4_enable_quotas(sb);

		if (!ret)
			quota_update = 1;
		else ext4_msg(sb, KERN_ERR, "Cannot turn on quotas: error %d", ret);

	}

	
	for (i = 0; i < EXT4_MAXQUOTAS; i++) {
		if (EXT4_SB(sb)->s_qf_names[i]) {
			int ret = ext4_quota_on_mount(sb, i);

			if (!ret)
				quota_update = 1;
			else ext4_msg(sb, KERN_ERR, "Cannot turn on journaled " "quota: type %d: error %d", i, ret);


		}
	}


	while (es->s_last_orphan) {
		struct inode *inode;

		
		if (EXT4_SB(sb)->s_mount_state & EXT4_ERROR_FS) {
			jbd_debug(1, "Skipping orphan recovery on fs with errors.\n");
			es->s_last_orphan = 0;
			break;
		}

		inode = ext4_orphan_get(sb, le32_to_cpu(es->s_last_orphan));
		if (IS_ERR(inode)) {
			es->s_last_orphan = 0;
			break;
		}

		list_add(&EXT4_I(inode)->i_orphan, &EXT4_SB(sb)->s_orphan);
		dquot_initialize(inode);
		if (inode->i_nlink) {
			if (test_opt(sb, DEBUG))
				ext4_msg(sb, KERN_DEBUG, "%s: truncating inode %lu to %lld bytes", __func__, inode->i_ino, inode->i_size);

			jbd_debug(2, "truncating inode %lu to %lld bytes\n", inode->i_ino, inode->i_size);
			inode_lock(inode);
			truncate_inode_pages(inode->i_mapping, inode->i_size);
			ret = ext4_truncate(inode);
			if (ret)
				ext4_std_error(inode->i_sb, ret);
			inode_unlock(inode);
			nr_truncates++;
		} else {
			if (test_opt(sb, DEBUG))
				ext4_msg(sb, KERN_DEBUG, "%s: deleting unreferenced inode %lu", __func__, inode->i_ino);

			jbd_debug(2, "deleting unreferenced inode %lu\n", inode->i_ino);
			nr_orphans++;
		}
		iput(inode);  
	}



	if (nr_orphans)
		ext4_msg(sb, KERN_INFO, "%d orphan inode%s deleted", PLURAL(nr_orphans));
	if (nr_truncates)
		ext4_msg(sb, KERN_INFO, "%d truncate%s cleaned up", PLURAL(nr_truncates));

	
	if (quota_update) {
		for (i = 0; i < EXT4_MAXQUOTAS; i++) {
			if (sb_dqopt(sb)->files[i])
				dquot_quota_off(sb, i);
		}
	}

	sb->s_flags = s_flags; 
}


static loff_t ext4_max_size(int blkbits, int has_huge_files)
{
	loff_t res;
	loff_t upper_limit = MAX_LFS_FILESIZE;

	
	if (!has_huge_files || sizeof(blkcnt_t) < sizeof(u64)) {
		
		upper_limit = (1LL << 32) - 1;

		
		upper_limit >>= (blkbits - 9);
		upper_limit <<= blkbits;
	}

	
	res = (1LL << 32) - 1;
	res <<= blkbits;

	
	if (res > upper_limit)
		res = upper_limit;

	return res;
}


static loff_t ext4_max_bitmap_size(int bits, int has_huge_files)
{
	loff_t res = EXT4_NDIR_BLOCKS;
	int meta_blocks;
	loff_t upper_limit;
	

	if (!has_huge_files || sizeof(blkcnt_t) < sizeof(u64)) {
		
		upper_limit = (1LL << 32) - 1;

		
		upper_limit >>= (bits - 9);

	} else {
		
		upper_limit = (1LL << 48) - 1;

	}

	
	meta_blocks = 1;
	
	meta_blocks += 1 + (1LL << (bits-2));
	
	meta_blocks += 1 + (1LL << (bits-2)) + (1LL << (2*(bits-2)));

	upper_limit -= meta_blocks;
	upper_limit <<= bits;

	res += 1LL << (bits-2);
	res += 1LL << (2*(bits-2));
	res += 1LL << (3*(bits-2));
	res <<= bits;
	if (res > upper_limit)
		res = upper_limit;

	if (res > MAX_LFS_FILESIZE)
		res = MAX_LFS_FILESIZE;

	return res;
}

static ext4_fsblk_t descriptor_loc(struct super_block *sb, ext4_fsblk_t logical_sb_block, int nr)
{
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	ext4_group_t bg, first_meta_bg;
	int has_super = 0;

	first_meta_bg = le32_to_cpu(sbi->s_es->s_first_meta_bg);

	if (!ext4_has_feature_meta_bg(sb) || nr < first_meta_bg)
		return logical_sb_block + nr + 1;
	bg = sbi->s_desc_per_block * nr;
	if (ext4_bg_has_super(sb, bg))
		has_super = 1;

	
	if (sb->s_blocksize == 1024 && nr == 0 && le32_to_cpu(sbi->s_es->s_first_data_block) == 0)
		has_super++;

	return (has_super + ext4_group_first_block_no(sb, bg));
}


static unsigned long ext4_get_stripe_size(struct ext4_sb_info *sbi)
{
	unsigned long stride = le16_to_cpu(sbi->s_es->s_raid_stride);
	unsigned long stripe_width = le32_to_cpu(sbi->s_es->s_raid_stripe_width);
	int ret;

	if (sbi->s_stripe && sbi->s_stripe <= sbi->s_blocks_per_group)
		ret = sbi->s_stripe;
	else if (stripe_width && stripe_width <= sbi->s_blocks_per_group)
		ret = stripe_width;
	else if (stride && stride <= sbi->s_blocks_per_group)
		ret = stride;
	else ret = 0;

	
	if (ret <= 1)
		ret = 0;

	return ret;
}


static int ext4_feature_set_ok(struct super_block *sb, int readonly)
{
	if (ext4_has_unknown_ext4_incompat_features(sb)) {
		ext4_msg(sb, KERN_ERR, "Couldn't mount because of " "unsupported optional features (%x)", (le32_to_cpu(EXT4_SB(sb)->s_es->s_feature_incompat) & ~EXT4_FEATURE_INCOMPAT_SUPP));



		return 0;
	}

	if (readonly)
		return 1;

	if (ext4_has_feature_readonly(sb)) {
		ext4_msg(sb, KERN_INFO, "filesystem is read-only");
		sb->s_flags |= SB_RDONLY;
		return 1;
	}

	
	if (ext4_has_unknown_ext4_ro_compat_features(sb)) {
		ext4_msg(sb, KERN_ERR, "couldn't mount RDWR because of " "unsupported optional features (%x)", (le32_to_cpu(EXT4_SB(sb)->s_es->s_feature_ro_compat) & ~EXT4_FEATURE_RO_COMPAT_SUPP));


		return 0;
	}
	
	if (ext4_has_feature_huge_file(sb)) {
		if (sizeof(blkcnt_t) < sizeof(u64)) {
			ext4_msg(sb, KERN_ERR, "Filesystem with huge files " "cannot be mounted RDWR without " "CONFIG_LBDAF");

			return 0;
		}
	}
	if (ext4_has_feature_bigalloc(sb) && !ext4_has_feature_extents(sb)) {
		ext4_msg(sb, KERN_ERR, "Can't support bigalloc feature without " "extents feature\n");

		return 0;
	}


	if (ext4_has_feature_quota(sb) && !readonly) {
		ext4_msg(sb, KERN_ERR, "Filesystem with quota feature cannot be mounted RDWR " "without CONFIG_QUOTA");

		return 0;
	}
	if (ext4_has_feature_project(sb) && !readonly) {
		ext4_msg(sb, KERN_ERR, "Filesystem with project quota feature cannot be mounted RDWR " "without CONFIG_QUOTA");

		return 0;
	}

	return 1;
}


static void print_daily_error_info(struct timer_list *t)
{
	struct ext4_sb_info *sbi = from_timer(sbi, t, s_err_report);
	struct super_block *sb = sbi->s_sb;
	struct ext4_super_block *es = sbi->s_es;

	if (es->s_error_count)
		
		ext4_msg(sb, KERN_NOTICE, "error count since last fsck: %u", le32_to_cpu(es->s_error_count));
	if (es->s_first_error_time) {
		printk(KERN_NOTICE "EXT4-fs (%s): initial error at time %u: %.*s:%d", sb->s_id, le32_to_cpu(es->s_first_error_time), (int) sizeof(es->s_first_error_func), es->s_first_error_func, le32_to_cpu(es->s_first_error_line));



		if (es->s_first_error_ino)
			printk(KERN_CONT ": inode %u", le32_to_cpu(es->s_first_error_ino));
		if (es->s_first_error_block)
			printk(KERN_CONT ": block %llu", (unsigned long long)
			       le64_to_cpu(es->s_first_error_block));
		printk(KERN_CONT "\n");
	}
	if (es->s_last_error_time) {
		printk(KERN_NOTICE "EXT4-fs (%s): last error at time %u: %.*s:%d", sb->s_id, le32_to_cpu(es->s_last_error_time), (int) sizeof(es->s_last_error_func), es->s_last_error_func, le32_to_cpu(es->s_last_error_line));



		if (es->s_last_error_ino)
			printk(KERN_CONT ": inode %u", le32_to_cpu(es->s_last_error_ino));
		if (es->s_last_error_block)
			printk(KERN_CONT ": block %llu", (unsigned long long)
			       le64_to_cpu(es->s_last_error_block));
		printk(KERN_CONT "\n");
	}
	mod_timer(&sbi->s_err_report, jiffies + 24*60*60*HZ);  
}


static int ext4_run_li_request(struct ext4_li_request *elr)
{
	struct ext4_group_desc *gdp = NULL;
	ext4_group_t group, ngroups;
	struct super_block *sb;
	unsigned long timeout = 0;
	int ret = 0;

	sb = elr->lr_super;
	ngroups = EXT4_SB(sb)->s_groups_count;

	for (group = elr->lr_next_group; group < ngroups; group++) {
		gdp = ext4_get_group_desc(sb, group, NULL);
		if (!gdp) {
			ret = 1;
			break;
		}

		if (!(gdp->bg_flags & cpu_to_le16(EXT4_BG_INODE_ZEROED)))
			break;
	}

	if (group >= ngroups)
		ret = 1;

	if (!ret) {
		timeout = jiffies;
		ret = ext4_init_inode_table(sb, group, elr->lr_timeout ? 0 : 1);
		if (elr->lr_timeout == 0) {
			timeout = (jiffies - timeout) * elr->lr_sbi->s_li_wait_mult;
			elr->lr_timeout = timeout;
		}
		elr->lr_next_sched = jiffies + elr->lr_timeout;
		elr->lr_next_group = group + 1;
	}
	return ret;
}


static void ext4_remove_li_request(struct ext4_li_request *elr)
{
	struct ext4_sb_info *sbi;

	if (!elr)
		return;

	sbi = elr->lr_sbi;

	list_del(&elr->lr_request);
	sbi->s_li_request = NULL;
	kfree(elr);
}

static void ext4_unregister_li_request(struct super_block *sb)
{
	mutex_lock(&ext4_li_mtx);
	if (!ext4_li_info) {
		mutex_unlock(&ext4_li_mtx);
		return;
	}

	mutex_lock(&ext4_li_info->li_list_mtx);
	ext4_remove_li_request(EXT4_SB(sb)->s_li_request);
	mutex_unlock(&ext4_li_info->li_list_mtx);
	mutex_unlock(&ext4_li_mtx);
}

static struct task_struct *ext4_lazyinit_task;


static int ext4_lazyinit_thread(void *arg)
{
	struct ext4_lazy_init *eli = (struct ext4_lazy_init *)arg;
	struct list_head *pos, *n;
	struct ext4_li_request *elr;
	unsigned long next_wakeup, cur;

	BUG_ON(NULL == eli);

cont_thread:
	while (true) {
		next_wakeup = MAX_JIFFY_OFFSET;

		mutex_lock(&eli->li_list_mtx);
		if (list_empty(&eli->li_request_list)) {
			mutex_unlock(&eli->li_list_mtx);
			goto exit_thread;
		}
		list_for_each_safe(pos, n, &eli->li_request_list) {
			int err = 0;
			int progress = 0;
			elr = list_entry(pos, struct ext4_li_request, lr_request);

			if (time_before(jiffies, elr->lr_next_sched)) {
				if (time_before(elr->lr_next_sched, next_wakeup))
					next_wakeup = elr->lr_next_sched;
				continue;
			}
			if (down_read_trylock(&elr->lr_super->s_umount)) {
				if (sb_start_write_trylock(elr->lr_super)) {
					progress = 1;
					
					mutex_unlock(&eli->li_list_mtx);
					err = ext4_run_li_request(elr);
					sb_end_write(elr->lr_super);
					mutex_lock(&eli->li_list_mtx);
					n = pos->next;
				}
				up_read((&elr->lr_super->s_umount));
			}
			
			if (err) {
				ext4_remove_li_request(elr);
				continue;
			}
			if (!progress) {
				elr->lr_next_sched = jiffies + (prandom_u32()
					 % (EXT4_DEF_LI_MAX_START_DELAY * HZ));
			}
			if (time_before(elr->lr_next_sched, next_wakeup))
				next_wakeup = elr->lr_next_sched;
		}
		mutex_unlock(&eli->li_list_mtx);

		try_to_freeze();

		cur = jiffies;
		if ((time_after_eq(cur, next_wakeup)) || (MAX_JIFFY_OFFSET == next_wakeup)) {
			cond_resched();
			continue;
		}

		schedule_timeout_interruptible(next_wakeup - cur);

		if (kthread_should_stop()) {
			ext4_clear_request_list();
			goto exit_thread;
		}
	}

exit_thread:
	
	mutex_lock(&ext4_li_mtx);
	mutex_lock(&eli->li_list_mtx);
	if (!list_empty(&eli->li_request_list)) {
		mutex_unlock(&eli->li_list_mtx);
		mutex_unlock(&ext4_li_mtx);
		goto cont_thread;
	}
	mutex_unlock(&eli->li_list_mtx);
	kfree(ext4_li_info);
	ext4_li_info = NULL;
	mutex_unlock(&ext4_li_mtx);

	return 0;
}

static void ext4_clear_request_list(void)
{
	struct list_head *pos, *n;
	struct ext4_li_request *elr;

	mutex_lock(&ext4_li_info->li_list_mtx);
	list_for_each_safe(pos, n, &ext4_li_info->li_request_list) {
		elr = list_entry(pos, struct ext4_li_request, lr_request);
		ext4_remove_li_request(elr);
	}
	mutex_unlock(&ext4_li_info->li_list_mtx);
}

static int ext4_run_lazyinit_thread(void)
{
	ext4_lazyinit_task = kthread_run(ext4_lazyinit_thread, ext4_li_info, "ext4lazyinit");
	if (IS_ERR(ext4_lazyinit_task)) {
		int err = PTR_ERR(ext4_lazyinit_task);
		ext4_clear_request_list();
		kfree(ext4_li_info);
		ext4_li_info = NULL;
		printk(KERN_CRIT "EXT4-fs: error %d creating inode table " "initialization thread\n", err);

		return err;
	}
	ext4_li_info->li_state |= EXT4_LAZYINIT_RUNNING;
	return 0;
}


static ext4_group_t ext4_has_uninit_itable(struct super_block *sb)
{
	ext4_group_t group, ngroups = EXT4_SB(sb)->s_groups_count;
	struct ext4_group_desc *gdp = NULL;

	if (!ext4_has_group_desc_csum(sb))
		return ngroups;

	for (group = 0; group < ngroups; group++) {
		gdp = ext4_get_group_desc(sb, group, NULL);
		if (!gdp)
			continue;

		if (gdp->bg_flags & cpu_to_le16(EXT4_BG_INODE_ZEROED))
			continue;
		if (group != 0)
			break;
		ext4_error(sb, "Inode table for bg 0 marked as " "needing zeroing");
		if (sb_rdonly(sb))
			return ngroups;
	}

	return group;
}

static int ext4_li_info_new(void)
{
	struct ext4_lazy_init *eli = NULL;

	eli = kzalloc(sizeof(*eli), GFP_KERNEL);
	if (!eli)
		return -ENOMEM;

	INIT_LIST_HEAD(&eli->li_request_list);
	mutex_init(&eli->li_list_mtx);

	eli->li_state |= EXT4_LAZYINIT_QUIT;

	ext4_li_info = eli;

	return 0;
}

static struct ext4_li_request *ext4_li_request_new(struct super_block *sb, ext4_group_t start)
{
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	struct ext4_li_request *elr;

	elr = kzalloc(sizeof(*elr), GFP_KERNEL);
	if (!elr)
		return NULL;

	elr->lr_super = sb;
	elr->lr_sbi = sbi;
	elr->lr_next_group = start;

	
	elr->lr_next_sched = jiffies + (prandom_u32() % (EXT4_DEF_LI_MAX_START_DELAY * HZ));
	return elr;
}

int ext4_register_li_request(struct super_block *sb, ext4_group_t first_not_zeroed)
{
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	struct ext4_li_request *elr = NULL;
	ext4_group_t ngroups = sbi->s_groups_count;
	int ret = 0;

	mutex_lock(&ext4_li_mtx);
	if (sbi->s_li_request != NULL) {
		
		sbi->s_li_request->lr_timeout = 0;
		goto out;
	}

	if (first_not_zeroed == ngroups || sb_rdonly(sb) || !test_opt(sb, INIT_INODE_TABLE))
		goto out;

	elr = ext4_li_request_new(sb, first_not_zeroed);
	if (!elr) {
		ret = -ENOMEM;
		goto out;
	}

	if (NULL == ext4_li_info) {
		ret = ext4_li_info_new();
		if (ret)
			goto out;
	}

	mutex_lock(&ext4_li_info->li_list_mtx);
	list_add(&elr->lr_request, &ext4_li_info->li_request_list);
	mutex_unlock(&ext4_li_info->li_list_mtx);

	sbi->s_li_request = elr;
	
	elr = NULL;

	if (!(ext4_li_info->li_state & EXT4_LAZYINIT_RUNNING)) {
		ret = ext4_run_lazyinit_thread();
		if (ret)
			goto out;
	}
out:
	mutex_unlock(&ext4_li_mtx);
	if (ret)
		kfree(elr);
	return ret;
}


static void ext4_destroy_lazyinit_thread(void)
{
	
	if (!ext4_li_info || !ext4_lazyinit_task)
		return;

	kthread_stop(ext4_lazyinit_task);
}

static int set_journal_csum_feature_set(struct super_block *sb)
{
	int ret = 1;
	int compat, incompat;
	struct ext4_sb_info *sbi = EXT4_SB(sb);

	if (ext4_has_metadata_csum(sb)) {
		
		compat = 0;
		incompat = JBD2_FEATURE_INCOMPAT_CSUM_V3;
	} else {
		
		compat = JBD2_FEATURE_COMPAT_CHECKSUM;
		incompat = 0;
	}

	jbd2_journal_clear_features(sbi->s_journal, JBD2_FEATURE_COMPAT_CHECKSUM, 0, JBD2_FEATURE_INCOMPAT_CSUM_V3 | JBD2_FEATURE_INCOMPAT_CSUM_V2);


	if (test_opt(sb, JOURNAL_ASYNC_COMMIT)) {
		ret = jbd2_journal_set_features(sbi->s_journal, compat, 0, JBD2_FEATURE_INCOMPAT_ASYNC_COMMIT | incompat);


	} else if (test_opt(sb, JOURNAL_CHECKSUM)) {
		ret = jbd2_journal_set_features(sbi->s_journal, compat, 0, incompat);

		jbd2_journal_clear_features(sbi->s_journal, 0, 0, JBD2_FEATURE_INCOMPAT_ASYNC_COMMIT);
	} else {
		jbd2_journal_clear_features(sbi->s_journal, 0, 0, JBD2_FEATURE_INCOMPAT_ASYNC_COMMIT);
	}

	return ret;
}


static int count_overhead(struct super_block *sb, ext4_group_t grp, char *buf)
{
	struct ext4_sb_info	*sbi = EXT4_SB(sb);
	struct ext4_group_desc	*gdp;
	ext4_fsblk_t		first_block, last_block, b;
	ext4_group_t		i, ngroups = ext4_get_groups_count(sb);
	int			s, j, count = 0;

	if (!ext4_has_feature_bigalloc(sb))
		return (ext4_bg_has_super(sb, grp) + ext4_bg_num_gdb(sb, grp) + sbi->s_itb_per_group + 2);

	first_block = le32_to_cpu(sbi->s_es->s_first_data_block) + (grp * EXT4_BLOCKS_PER_GROUP(sb));
	last_block = first_block + EXT4_BLOCKS_PER_GROUP(sb) - 1;
	for (i = 0; i < ngroups; i++) {
		gdp = ext4_get_group_desc(sb, i, NULL);
		b = ext4_block_bitmap(sb, gdp);
		if (b >= first_block && b <= last_block) {
			ext4_set_bit(EXT4_B2C(sbi, b - first_block), buf);
			count++;
		}
		b = ext4_inode_bitmap(sb, gdp);
		if (b >= first_block && b <= last_block) {
			ext4_set_bit(EXT4_B2C(sbi, b - first_block), buf);
			count++;
		}
		b = ext4_inode_table(sb, gdp);
		if (b >= first_block && b + sbi->s_itb_per_group <= last_block)
			for (j = 0; j < sbi->s_itb_per_group; j++, b++) {
				int c = EXT4_B2C(sbi, b - first_block);
				ext4_set_bit(c, buf);
				count++;
			}
		if (i != grp)
			continue;
		s = 0;
		if (ext4_bg_has_super(sb, grp)) {
			ext4_set_bit(s++, buf);
			count++;
		}
		j = ext4_bg_num_gdb(sb, grp);
		if (s + j > EXT4_BLOCKS_PER_GROUP(sb)) {
			ext4_error(sb, "Invalid number of block group " "descriptor blocks: %d", j);
			j = EXT4_BLOCKS_PER_GROUP(sb) - s;
		}
		count += j;
		for (; j > 0; j--)
			ext4_set_bit(EXT4_B2C(sbi, s++), buf);
	}
	if (!count)
		return 0;
	return EXT4_CLUSTERS_PER_GROUP(sb) - ext4_count_free(buf, EXT4_CLUSTERS_PER_GROUP(sb) / 8);
}


int ext4_calculate_overhead(struct super_block *sb)
{
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	struct ext4_super_block *es = sbi->s_es;
	struct inode *j_inode;
	unsigned int j_blocks, j_inum = le32_to_cpu(es->s_journal_inum);
	ext4_group_t i, ngroups = ext4_get_groups_count(sb);
	ext4_fsblk_t overhead = 0;
	char *buf = (char *) get_zeroed_page(GFP_NOFS);

	if (!buf)
		return -ENOMEM;

	

	
	overhead = EXT4_B2C(sbi, le32_to_cpu(es->s_first_data_block));

	
	for (i = 0; i < ngroups; i++) {
		int blks;

		blks = count_overhead(sb, i, buf);
		overhead += blks;
		if (blks)
			memset(buf, 0, PAGE_SIZE);
		cond_resched();
	}

	
	if (sbi->s_journal && !sbi->journal_bdev)
		overhead += EXT4_NUM_B2C(sbi, sbi->s_journal->j_maxlen);
	else if (ext4_has_feature_journal(sb) && !sbi->s_journal) {
		j_inode = ext4_get_journal_inode(sb, j_inum);
		if (j_inode) {
			j_blocks = j_inode->i_size >> sb->s_blocksize_bits;
			overhead += EXT4_NUM_B2C(sbi, j_blocks);
			iput(j_inode);
		} else {
			ext4_msg(sb, KERN_ERR, "can't get journal size");
		}
	}
	sbi->s_overhead = overhead;
	smp_wmb();
	free_page((unsigned long) buf);
	return 0;
}

static void ext4_set_resv_clusters(struct super_block *sb)
{
	ext4_fsblk_t resv_clusters;
	struct ext4_sb_info *sbi = EXT4_SB(sb);

	
	if (!ext4_has_feature_extents(sb))
		return;
	
	resv_clusters = (ext4_blocks_count(sbi->s_es) >> sbi->s_cluster_bits);

	do_div(resv_clusters, 50);
	resv_clusters = min_t(ext4_fsblk_t, resv_clusters, 4096);

	atomic64_set(&sbi->s_resv_clusters, resv_clusters);
}

static int ext4_fill_super(struct super_block *sb, void *data, int silent)
{
	struct dax_device *dax_dev = fs_dax_get_by_bdev(sb->s_bdev);
	char *orig_data = kstrdup(data, GFP_KERNEL);
	struct buffer_head *bh;
	struct ext4_super_block *es = NULL;
	struct ext4_sb_info *sbi = kzalloc(sizeof(*sbi), GFP_KERNEL);
	ext4_fsblk_t block;
	ext4_fsblk_t sb_block = get_sb_block(&data);
	ext4_fsblk_t logical_sb_block;
	unsigned long offset = 0;
	unsigned long journal_devnum = 0;
	unsigned long def_mount_opts;
	struct inode *root;
	const char *descr;
	int ret = -ENOMEM;
	int blocksize, clustersize;
	unsigned int db_count;
	unsigned int i;
	int needs_recovery, has_huge_files, has_bigalloc;
	__u64 blocks_count;
	int err = 0;
	unsigned int journal_ioprio = DEFAULT_JOURNAL_IOPRIO;
	ext4_group_t first_not_zeroed;

	if ((data && !orig_data) || !sbi)
		goto out_free_base;

	sbi->s_daxdev = dax_dev;
	sbi->s_blockgroup_lock = kzalloc(sizeof(struct blockgroup_lock), GFP_KERNEL);
	if (!sbi->s_blockgroup_lock)
		goto out_free_base;

	sb->s_fs_info = sbi;
	sbi->s_sb = sb;
	sbi->s_inode_readahead_blks = EXT4_DEF_INODE_READAHEAD_BLKS;
	sbi->s_sb_block = sb_block;
	if (sb->s_bdev->bd_part)
		sbi->s_sectors_written_start = part_stat_read(sb->s_bdev->bd_part, sectors[1]);

	
	strreplace(sb->s_id, '/', '!');

	
	ret = -EINVAL;
	blocksize = sb_min_blocksize(sb, EXT4_MIN_BLOCK_SIZE);
	if (!blocksize) {
		ext4_msg(sb, KERN_ERR, "unable to set blocksize");
		goto out_fail;
	}

	
	if (blocksize != EXT4_MIN_BLOCK_SIZE) {
		logical_sb_block = sb_block * EXT4_MIN_BLOCK_SIZE;
		offset = do_div(logical_sb_block, blocksize);
	} else {
		logical_sb_block = sb_block;
	}

	if (!(bh = sb_bread_unmovable(sb, logical_sb_block))) {
		ext4_msg(sb, KERN_ERR, "unable to read superblock");
		goto out_fail;
	}
	
	es = (struct ext4_super_block *) (bh->b_data + offset);
	sbi->s_es = es;
	sb->s_magic = le16_to_cpu(es->s_magic);
	if (sb->s_magic != EXT4_SUPER_MAGIC)
		goto cantfind_ext4;
	sbi->s_kbytes_written = le64_to_cpu(es->s_kbytes_written);

	
	if (ext4_has_feature_metadata_csum(sb) && ext4_has_feature_gdt_csum(sb))
		ext4_warning(sb, "metadata_csum and uninit_bg are " "redundant flags; please run fsck.");

	
	if (!ext4_verify_csum_type(sb, es)) {
		ext4_msg(sb, KERN_ERR, "VFS: Found ext4 filesystem with " "unknown checksum algorithm.");
		silent = 1;
		goto cantfind_ext4;
	}

	
	sbi->s_chksum_driver = crypto_alloc_shash("crc32c", 0, 0);
	if (IS_ERR(sbi->s_chksum_driver)) {
		ext4_msg(sb, KERN_ERR, "Cannot load crc32c driver.");
		ret = PTR_ERR(sbi->s_chksum_driver);
		sbi->s_chksum_driver = NULL;
		goto failed_mount;
	}

	
	if (!ext4_superblock_csum_verify(sb, es)) {
		ext4_msg(sb, KERN_ERR, "VFS: Found ext4 filesystem with " "invalid superblock checksum.  Run e2fsck?");
		silent = 1;
		ret = -EFSBADCRC;
		goto cantfind_ext4;
	}

	
	if (ext4_has_feature_csum_seed(sb))
		sbi->s_csum_seed = le32_to_cpu(es->s_checksum_seed);
	else if (ext4_has_metadata_csum(sb) || ext4_has_feature_ea_inode(sb))
		sbi->s_csum_seed = ext4_chksum(sbi, ~0, es->s_uuid, sizeof(es->s_uuid));

	
	def_mount_opts = le32_to_cpu(es->s_default_mount_opts);
	set_opt(sb, INIT_INODE_TABLE);
	if (def_mount_opts & EXT4_DEFM_DEBUG)
		set_opt(sb, DEBUG);
	if (def_mount_opts & EXT4_DEFM_BSDGROUPS)
		set_opt(sb, GRPID);
	if (def_mount_opts & EXT4_DEFM_UID16)
		set_opt(sb, NO_UID32);
	
	set_opt(sb, XATTR_USER);

	set_opt(sb, POSIX_ACL);

	
	if (ext4_has_metadata_csum(sb))
		set_opt(sb, JOURNAL_CHECKSUM);

	if ((def_mount_opts & EXT4_DEFM_JMODE) == EXT4_DEFM_JMODE_DATA)
		set_opt(sb, JOURNAL_DATA);
	else if ((def_mount_opts & EXT4_DEFM_JMODE) == EXT4_DEFM_JMODE_ORDERED)
		set_opt(sb, ORDERED_DATA);
	else if ((def_mount_opts & EXT4_DEFM_JMODE) == EXT4_DEFM_JMODE_WBACK)
		set_opt(sb, WRITEBACK_DATA);

	if (le16_to_cpu(sbi->s_es->s_errors) == EXT4_ERRORS_PANIC)
		set_opt(sb, ERRORS_PANIC);
	else if (le16_to_cpu(sbi->s_es->s_errors) == EXT4_ERRORS_CONTINUE)
		set_opt(sb, ERRORS_CONT);
	else set_opt(sb, ERRORS_RO);
	
	set_opt(sb, BLOCK_VALIDITY);
	if (def_mount_opts & EXT4_DEFM_DISCARD)
		set_opt(sb, DISCARD);

	sbi->s_resuid = make_kuid(&init_user_ns, le16_to_cpu(es->s_def_resuid));
	sbi->s_resgid = make_kgid(&init_user_ns, le16_to_cpu(es->s_def_resgid));
	sbi->s_commit_interval = JBD2_DEFAULT_MAX_COMMIT_AGE * HZ;
	sbi->s_min_batch_time = EXT4_DEF_MIN_BATCH_TIME;
	sbi->s_max_batch_time = EXT4_DEF_MAX_BATCH_TIME;

	if ((def_mount_opts & EXT4_DEFM_NOBARRIER) == 0)
		set_opt(sb, BARRIER);

	
	if (!IS_EXT3_SB(sb) && !IS_EXT2_SB(sb) && ((def_mount_opts & EXT4_DEFM_NODELALLOC) == 0))
		set_opt(sb, DELALLOC);

	
	sbi->s_li_wait_mult = EXT4_DEF_LI_WAIT_MULT;

	if (sbi->s_es->s_mount_opts[0]) {
		char *s_mount_opts = kstrndup(sbi->s_es->s_mount_opts, sizeof(sbi->s_es->s_mount_opts), GFP_KERNEL);

		if (!s_mount_opts)
			goto failed_mount;
		if (!parse_options(s_mount_opts, sb, &journal_devnum, &journal_ioprio, 0)) {
			ext4_msg(sb, KERN_WARNING, "failed to parse options in superblock: %s", s_mount_opts);

		}
		kfree(s_mount_opts);
	}
	sbi->s_def_mount_opt = sbi->s_mount_opt;
	if (!parse_options((char *) data, sb, &journal_devnum, &journal_ioprio, 0))
		goto failed_mount;

	if (test_opt(sb, DATA_FLAGS) == EXT4_MOUNT_JOURNAL_DATA) {
		printk_once(KERN_WARNING "EXT4-fs: Warning: mounting " "with data=journal disables delayed " "allocation and O_DIRECT support!\n");

		if (test_opt2(sb, EXPLICIT_DELALLOC)) {
			ext4_msg(sb, KERN_ERR, "can't mount with " "both data=journal and delalloc");
			goto failed_mount;
		}
		if (test_opt(sb, DIOREAD_NOLOCK)) {
			ext4_msg(sb, KERN_ERR, "can't mount with " "both data=journal and dioread_nolock");
			goto failed_mount;
		}
		if (test_opt(sb, DAX)) {
			ext4_msg(sb, KERN_ERR, "can't mount with " "both data=journal and dax");
			goto failed_mount;
		}
		if (ext4_has_feature_encrypt(sb)) {
			ext4_msg(sb, KERN_WARNING, "encrypted files will use data=ordered " "instead of data journaling mode");

		}
		if (test_opt(sb, DELALLOC))
			clear_opt(sb, DELALLOC);
	} else {
		sb->s_iflags |= SB_I_CGROUPWB;
	}

	sb->s_flags = (sb->s_flags & ~SB_POSIXACL) | (test_opt(sb, POSIX_ACL) ? SB_POSIXACL : 0);

	if (le32_to_cpu(es->s_rev_level) == EXT4_GOOD_OLD_REV && (ext4_has_compat_features(sb) || ext4_has_ro_compat_features(sb) || ext4_has_incompat_features(sb)))


		ext4_msg(sb, KERN_WARNING, "feature flags set on rev 0 fs, " "running e2fsck is recommended");


	if (es->s_creator_os == cpu_to_le32(EXT4_OS_HURD)) {
		set_opt2(sb, HURD_COMPAT);
		if (ext4_has_feature_64bit(sb)) {
			ext4_msg(sb, KERN_ERR, "The Hurd can't support 64-bit file systems");
			goto failed_mount;
		}

		
		if (ext4_has_feature_ea_inode(sb)) {
			ext4_msg(sb, KERN_ERR, "ea_inode feature is not supported for Hurd");
			goto failed_mount;
		}
	}

	if (IS_EXT2_SB(sb)) {
		if (ext2_feature_set_ok(sb))
			ext4_msg(sb, KERN_INFO, "mounting ext2 file system " "using the ext4 subsystem");
		else {
			
			if (silent && ext4_feature_set_ok(sb, sb_rdonly(sb)))
				goto failed_mount;
			ext4_msg(sb, KERN_ERR, "couldn't mount as ext2 due " "to feature incompatibilities");
			goto failed_mount;
		}
	}

	if (IS_EXT3_SB(sb)) {
		if (ext3_feature_set_ok(sb))
			ext4_msg(sb, KERN_INFO, "mounting ext3 file system " "using the ext4 subsystem");
		else {
			
			if (silent && ext4_feature_set_ok(sb, sb_rdonly(sb)))
				goto failed_mount;
			ext4_msg(sb, KERN_ERR, "couldn't mount as ext3 due " "to feature incompatibilities");
			goto failed_mount;
		}
	}

	
	if (!ext4_feature_set_ok(sb, (sb_rdonly(sb))))
		goto failed_mount;

	blocksize = BLOCK_SIZE << le32_to_cpu(es->s_log_block_size);
	if (blocksize < EXT4_MIN_BLOCK_SIZE || blocksize > EXT4_MAX_BLOCK_SIZE) {
		ext4_msg(sb, KERN_ERR, "Unsupported filesystem blocksize %d (%d log_block_size)", blocksize, le32_to_cpu(es->s_log_block_size));

		goto failed_mount;
	}
	if (le32_to_cpu(es->s_log_block_size) > (EXT4_MAX_BLOCK_LOG_SIZE - EXT4_MIN_BLOCK_LOG_SIZE)) {
		ext4_msg(sb, KERN_ERR, "Invalid log block size: %u", le32_to_cpu(es->s_log_block_size));

		goto failed_mount;
	}

	if (le16_to_cpu(sbi->s_es->s_reserved_gdt_blocks) > (blocksize / 4)) {
		ext4_msg(sb, KERN_ERR, "Number of reserved GDT blocks insanely large: %d", le16_to_cpu(sbi->s_es->s_reserved_gdt_blocks));

		goto failed_mount;
	}

	if (sbi->s_mount_opt & EXT4_MOUNT_DAX) {
		if (ext4_has_feature_inline_data(sb)) {
			ext4_msg(sb, KERN_ERR, "Cannot use DAX on a filesystem" " that may contain inline data");
			sbi->s_mount_opt &= ~EXT4_MOUNT_DAX;
		}
		err = bdev_dax_supported(sb, blocksize);
		if (err) {
			ext4_msg(sb, KERN_ERR, "DAX unsupported by block device. Turning off DAX.");
			sbi->s_mount_opt &= ~EXT4_MOUNT_DAX;
		}
	}

	if (ext4_has_feature_encrypt(sb) && es->s_encryption_level) {
		ext4_msg(sb, KERN_ERR, "Unsupported encryption level %d", es->s_encryption_level);
		goto failed_mount;
	}

	if (sb->s_blocksize != blocksize) {
		
		if (!sb_set_blocksize(sb, blocksize)) {
			ext4_msg(sb, KERN_ERR, "bad block size %d", blocksize);
			goto failed_mount;
		}

		brelse(bh);
		logical_sb_block = sb_block * EXT4_MIN_BLOCK_SIZE;
		offset = do_div(logical_sb_block, blocksize);
		bh = sb_bread_unmovable(sb, logical_sb_block);
		if (!bh) {
			ext4_msg(sb, KERN_ERR, "Can't read superblock on 2nd try");
			goto failed_mount;
		}
		es = (struct ext4_super_block *)(bh->b_data + offset);
		sbi->s_es = es;
		if (es->s_magic != cpu_to_le16(EXT4_SUPER_MAGIC)) {
			ext4_msg(sb, KERN_ERR, "Magic mismatch, very weird!");
			goto failed_mount;
		}
	}

	has_huge_files = ext4_has_feature_huge_file(sb);
	sbi->s_bitmap_maxbytes = ext4_max_bitmap_size(sb->s_blocksize_bits, has_huge_files);
	sb->s_maxbytes = ext4_max_size(sb->s_blocksize_bits, has_huge_files);

	if (le32_to_cpu(es->s_rev_level) == EXT4_GOOD_OLD_REV) {
		sbi->s_inode_size = EXT4_GOOD_OLD_INODE_SIZE;
		sbi->s_first_ino = EXT4_GOOD_OLD_FIRST_INO;
	} else {
		sbi->s_inode_size = le16_to_cpu(es->s_inode_size);
		sbi->s_first_ino = le32_to_cpu(es->s_first_ino);
		if ((sbi->s_inode_size < EXT4_GOOD_OLD_INODE_SIZE) || (!is_power_of_2(sbi->s_inode_size)) || (sbi->s_inode_size > blocksize)) {

			ext4_msg(sb, KERN_ERR, "unsupported inode size: %d", sbi->s_inode_size);

			goto failed_mount;
		}
		if (sbi->s_inode_size > EXT4_GOOD_OLD_INODE_SIZE)
			sb->s_time_gran = 1 << (EXT4_EPOCH_BITS - 2);
	}

	sbi->s_desc_size = le16_to_cpu(es->s_desc_size);
	if (ext4_has_feature_64bit(sb)) {
		if (sbi->s_desc_size < EXT4_MIN_DESC_SIZE_64BIT || sbi->s_desc_size > EXT4_MAX_DESC_SIZE || !is_power_of_2(sbi->s_desc_size)) {

			ext4_msg(sb, KERN_ERR, "unsupported descriptor size %lu", sbi->s_desc_size);

			goto failed_mount;
		}
	} else sbi->s_desc_size = EXT4_MIN_DESC_SIZE;

	sbi->s_blocks_per_group = le32_to_cpu(es->s_blocks_per_group);
	sbi->s_inodes_per_group = le32_to_cpu(es->s_inodes_per_group);

	sbi->s_inodes_per_block = blocksize / EXT4_INODE_SIZE(sb);
	if (sbi->s_inodes_per_block == 0)
		goto cantfind_ext4;
	if (sbi->s_inodes_per_group < sbi->s_inodes_per_block || sbi->s_inodes_per_group > blocksize * 8) {
		ext4_msg(sb, KERN_ERR, "invalid inodes per group: %lu\n", sbi->s_blocks_per_group);
		goto failed_mount;
	}
	sbi->s_itb_per_group = sbi->s_inodes_per_group / sbi->s_inodes_per_block;
	sbi->s_desc_per_block = blocksize / EXT4_DESC_SIZE(sb);
	sbi->s_sbh = bh;
	sbi->s_mount_state = le16_to_cpu(es->s_state);
	sbi->s_addr_per_block_bits = ilog2(EXT4_ADDR_PER_BLOCK(sb));
	sbi->s_desc_per_block_bits = ilog2(EXT4_DESC_PER_BLOCK(sb));

	for (i = 0; i < 4; i++)
		sbi->s_hash_seed[i] = le32_to_cpu(es->s_hash_seed[i]);
	sbi->s_def_hash_version = es->s_def_hash_version;
	if (ext4_has_feature_dir_index(sb)) {
		i = le32_to_cpu(es->s_flags);
		if (i & EXT2_FLAGS_UNSIGNED_HASH)
			sbi->s_hash_unsigned = 3;
		else if ((i & EXT2_FLAGS_SIGNED_HASH) == 0) {

			if (!sb_rdonly(sb))
				es->s_flags |= cpu_to_le32(EXT2_FLAGS_UNSIGNED_HASH);
			sbi->s_hash_unsigned = 3;

			if (!sb_rdonly(sb))
				es->s_flags |= cpu_to_le32(EXT2_FLAGS_SIGNED_HASH);

		}
	}

	
	clustersize = BLOCK_SIZE << le32_to_cpu(es->s_log_cluster_size);
	has_bigalloc = ext4_has_feature_bigalloc(sb);
	if (has_bigalloc) {
		if (clustersize < blocksize) {
			ext4_msg(sb, KERN_ERR, "cluster size (%d) smaller than " "block size (%d)", clustersize, blocksize);

			goto failed_mount;
		}
		if (le32_to_cpu(es->s_log_cluster_size) > (EXT4_MAX_CLUSTER_LOG_SIZE - EXT4_MIN_BLOCK_LOG_SIZE)) {
			ext4_msg(sb, KERN_ERR, "Invalid log cluster size: %u", le32_to_cpu(es->s_log_cluster_size));

			goto failed_mount;
		}
		sbi->s_cluster_bits = le32_to_cpu(es->s_log_cluster_size) - le32_to_cpu(es->s_log_block_size);
		sbi->s_clusters_per_group = le32_to_cpu(es->s_clusters_per_group);
		if (sbi->s_clusters_per_group > blocksize * 8) {
			ext4_msg(sb, KERN_ERR, "#clusters per group too big: %lu", sbi->s_clusters_per_group);

			goto failed_mount;
		}
		if (sbi->s_blocks_per_group != (sbi->s_clusters_per_group * (clustersize / blocksize))) {
			ext4_msg(sb, KERN_ERR, "blocks per group (%lu) and " "clusters per group (%lu) inconsistent", sbi->s_blocks_per_group, sbi->s_clusters_per_group);


			goto failed_mount;
		}
	} else {
		if (clustersize != blocksize) {
			ext4_warning(sb, "fragment/cluster size (%d) != " "block size (%d)", clustersize, blocksize);

			clustersize = blocksize;
		}
		if (sbi->s_blocks_per_group > blocksize * 8) {
			ext4_msg(sb, KERN_ERR, "#blocks per group too big: %lu", sbi->s_blocks_per_group);

			goto failed_mount;
		}
		sbi->s_clusters_per_group = sbi->s_blocks_per_group;
		sbi->s_cluster_bits = 0;
	}
	sbi->s_cluster_ratio = clustersize / blocksize;

	
	if (sbi->s_blocks_per_group == clustersize << 3)
		set_opt2(sb, STD_GROUP_SIZE);

	
	err = generic_check_addressable(sb->s_blocksize_bits, ext4_blocks_count(es));
	if (err) {
		ext4_msg(sb, KERN_ERR, "filesystem" " too large to mount safely on this system");
		if (sizeof(sector_t) < 8)
			ext4_msg(sb, KERN_WARNING, "CONFIG_LBDAF not enabled");
		goto failed_mount;
	}

	if (EXT4_BLOCKS_PER_GROUP(sb) == 0)
		goto cantfind_ext4;

	
	blocks_count = sb->s_bdev->bd_inode->i_size >> sb->s_blocksize_bits;
	if (blocks_count && ext4_blocks_count(es) > blocks_count) {
		ext4_msg(sb, KERN_WARNING, "bad geometry: block count %llu " "exceeds size of device (%llu blocks)", ext4_blocks_count(es), blocks_count);

		goto failed_mount;
	}

	
	if (le32_to_cpu(es->s_first_data_block) >= ext4_blocks_count(es)) {
		ext4_msg(sb, KERN_WARNING, "bad geometry: first data " "block %u is beyond end of filesystem (%llu)", le32_to_cpu(es->s_first_data_block), ext4_blocks_count(es));


		goto failed_mount;
	}
	blocks_count = (ext4_blocks_count(es) - le32_to_cpu(es->s_first_data_block) + EXT4_BLOCKS_PER_GROUP(sb) - 1);

	do_div(blocks_count, EXT4_BLOCKS_PER_GROUP(sb));
	if (blocks_count > ((uint64_t)1<<32) - EXT4_DESC_PER_BLOCK(sb)) {
		ext4_msg(sb, KERN_WARNING, "groups count too large: %u " "(block count %llu, first data block %u, " "blocks per group %lu)", sbi->s_groups_count, ext4_blocks_count(es), le32_to_cpu(es->s_first_data_block), EXT4_BLOCKS_PER_GROUP(sb));




		goto failed_mount;
	}
	sbi->s_groups_count = blocks_count;
	sbi->s_blockfile_groups = min_t(ext4_group_t, sbi->s_groups_count, (EXT4_MAX_BLOCK_FILE_PHYS / EXT4_BLOCKS_PER_GROUP(sb)));
	db_count = (sbi->s_groups_count + EXT4_DESC_PER_BLOCK(sb) - 1) / EXT4_DESC_PER_BLOCK(sb);
	if (ext4_has_feature_meta_bg(sb)) {
		if (le32_to_cpu(es->s_first_meta_bg) > db_count) {
			ext4_msg(sb, KERN_WARNING, "first meta block group too large: %u " "(group descriptor block count %u)", le32_to_cpu(es->s_first_meta_bg), db_count);


			goto failed_mount;
		}
	}
	sbi->s_group_desc = kvmalloc(db_count * sizeof(struct buffer_head *), GFP_KERNEL);

	if (sbi->s_group_desc == NULL) {
		ext4_msg(sb, KERN_ERR, "not enough memory");
		ret = -ENOMEM;
		goto failed_mount;
	}

	bgl_lock_init(sbi->s_blockgroup_lock);

	
	for (i = 0; i < db_count; i++) {
		block = descriptor_loc(sb, logical_sb_block, i);
		sb_breadahead(sb, block);
	}

	for (i = 0; i < db_count; i++) {
		block = descriptor_loc(sb, logical_sb_block, i);
		sbi->s_group_desc[i] = sb_bread_unmovable(sb, block);
		if (!sbi->s_group_desc[i]) {
			ext4_msg(sb, KERN_ERR, "can't read group descriptor %d", i);
			db_count = i;
			goto failed_mount2;
		}
	}
	if (!ext4_check_descriptors(sb, logical_sb_block, &first_not_zeroed)) {
		ext4_msg(sb, KERN_ERR, "group descriptors corrupted!");
		ret = -EFSCORRUPTED;
		goto failed_mount2;
	}

	sbi->s_gdb_count = db_count;

	timer_setup(&sbi->s_err_report, print_daily_error_info, 0);

	
	if (ext4_es_register_shrinker(sbi))
		goto failed_mount3;

	sbi->s_stripe = ext4_get_stripe_size(sbi);
	sbi->s_extent_max_zeroout_kb = 32;

	
	sb->s_op = &ext4_sops;
	sb->s_export_op = &ext4_export_ops;
	sb->s_xattr = ext4_xattr_handlers;

	sb->s_cop = &ext4_cryptops;


	sb->dq_op = &ext4_quota_operations;
	if (ext4_has_feature_quota(sb))
		sb->s_qcop = &dquot_quotactl_sysfile_ops;
	else sb->s_qcop = &ext4_qctl_operations;
	sb->s_quota_types = QTYPE_MASK_USR | QTYPE_MASK_GRP | QTYPE_MASK_PRJ;

	memcpy(&sb->s_uuid, es->s_uuid, sizeof(es->s_uuid));

	INIT_LIST_HEAD(&sbi->s_orphan); 
	mutex_init(&sbi->s_orphan_lock);

	sb->s_root = NULL;

	needs_recovery = (es->s_last_orphan != 0 || ext4_has_feature_journal_needs_recovery(sb));

	if (ext4_has_feature_mmp(sb) && !sb_rdonly(sb))
		if (ext4_multi_mount_protect(sb, le64_to_cpu(es->s_mmp_block)))
			goto failed_mount3a;

	
	if (!test_opt(sb, NOLOAD) && ext4_has_feature_journal(sb)) {
		err = ext4_load_journal(sb, es, journal_devnum);
		if (err)
			goto failed_mount3a;
	} else if (test_opt(sb, NOLOAD) && !sb_rdonly(sb) && ext4_has_feature_journal_needs_recovery(sb)) {
		ext4_msg(sb, KERN_ERR, "required journal recovery " "suppressed and not mounted read-only");
		goto failed_mount_wq;
	} else {
		
		if (test_opt2(sb, EXPLICIT_JOURNAL_CHECKSUM)) {
			ext4_msg(sb, KERN_ERR, "can't mount with " "journal_checksum, fs mounted w/o journal");
			goto failed_mount_wq;
		}
		if (test_opt(sb, JOURNAL_ASYNC_COMMIT)) {
			ext4_msg(sb, KERN_ERR, "can't mount with " "journal_async_commit, fs mounted w/o journal");
			goto failed_mount_wq;
		}
		if (sbi->s_commit_interval != JBD2_DEFAULT_MAX_COMMIT_AGE*HZ) {
			ext4_msg(sb, KERN_ERR, "can't mount with " "commit=%lu, fs mounted w/o journal", sbi->s_commit_interval / HZ);

			goto failed_mount_wq;
		}
		if (EXT4_MOUNT_DATA_FLAGS & (sbi->s_mount_opt ^ sbi->s_def_mount_opt)) {
			ext4_msg(sb, KERN_ERR, "can't mount with " "data=, fs mounted w/o journal");
			goto failed_mount_wq;
		}
		sbi->s_def_mount_opt &= EXT4_MOUNT_JOURNAL_CHECKSUM;
		clear_opt(sb, JOURNAL_CHECKSUM);
		clear_opt(sb, DATA_FLAGS);
		sbi->s_journal = NULL;
		needs_recovery = 0;
		goto no_journal;
	}

	if (ext4_has_feature_64bit(sb) && !jbd2_journal_set_features(EXT4_SB(sb)->s_journal, 0, 0, JBD2_FEATURE_INCOMPAT_64BIT)) {

		ext4_msg(sb, KERN_ERR, "Failed to set 64-bit journal feature");
		goto failed_mount_wq;
	}

	if (!set_journal_csum_feature_set(sb)) {
		ext4_msg(sb, KERN_ERR, "Failed to set journal checksum " "feature set");
		goto failed_mount_wq;
	}

	
	switch (test_opt(sb, DATA_FLAGS)) {
	case 0:
		
		if (jbd2_journal_check_available_features (sbi->s_journal, 0, 0, JBD2_FEATURE_INCOMPAT_REVOKE)) {
			set_opt(sb, ORDERED_DATA);
			sbi->s_def_mount_opt |= EXT4_MOUNT_ORDERED_DATA;
		} else {
			set_opt(sb, JOURNAL_DATA);
			sbi->s_def_mount_opt |= EXT4_MOUNT_JOURNAL_DATA;
		}
		break;

	case EXT4_MOUNT_ORDERED_DATA:
	case EXT4_MOUNT_WRITEBACK_DATA:
		if (!jbd2_journal_check_available_features (sbi->s_journal, 0, 0, JBD2_FEATURE_INCOMPAT_REVOKE)) {
			ext4_msg(sb, KERN_ERR, "Journal does not support " "requested data journaling mode");
			goto failed_mount_wq;
		}
	default:
		break;
	}

	if (test_opt(sb, DATA_FLAGS) == EXT4_MOUNT_ORDERED_DATA && test_opt(sb, JOURNAL_ASYNC_COMMIT)) {
		ext4_msg(sb, KERN_ERR, "can't mount with " "journal_async_commit in data=ordered mode");
		goto failed_mount_wq;
	}

	set_task_ioprio(sbi->s_journal->j_task, journal_ioprio);

	sbi->s_journal->j_commit_callback = ext4_journal_commit_callback;

no_journal:
	if (!test_opt(sb, NO_MBCACHE)) {
		sbi->s_ea_block_cache = ext4_xattr_create_cache();
		if (!sbi->s_ea_block_cache) {
			ext4_msg(sb, KERN_ERR, "Failed to create ea_block_cache");
			goto failed_mount_wq;
		}

		if (ext4_has_feature_ea_inode(sb)) {
			sbi->s_ea_inode_cache = ext4_xattr_create_cache();
			if (!sbi->s_ea_inode_cache) {
				ext4_msg(sb, KERN_ERR, "Failed to create ea_inode_cache");
				goto failed_mount_wq;
			}
		}
	}

	if ((DUMMY_ENCRYPTION_ENABLED(sbi) || ext4_has_feature_encrypt(sb)) && (blocksize != PAGE_SIZE)) {
		ext4_msg(sb, KERN_ERR, "Unsupported blocksize for fs encryption");
		goto failed_mount_wq;
	}

	if (DUMMY_ENCRYPTION_ENABLED(sbi) && !sb_rdonly(sb) && !ext4_has_feature_encrypt(sb)) {
		ext4_set_feature_encrypt(sb);
		ext4_commit_super(sb, 1);
	}

	
	if (es->s_overhead_clusters)
		sbi->s_overhead = le32_to_cpu(es->s_overhead_clusters);
	else {
		err = ext4_calculate_overhead(sb);
		if (err)
			goto failed_mount_wq;
	}

	
	EXT4_SB(sb)->rsv_conversion_wq = alloc_workqueue("ext4-rsv-conversion", WQ_MEM_RECLAIM | WQ_UNBOUND, 1);
	if (!EXT4_SB(sb)->rsv_conversion_wq) {
		printk(KERN_ERR "EXT4-fs: failed to create workqueue\n");
		ret = -ENOMEM;
		goto failed_mount4;
	}

	

	root = ext4_iget(sb, EXT4_ROOT_INO);
	if (IS_ERR(root)) {
		ext4_msg(sb, KERN_ERR, "get root inode failed");
		ret = PTR_ERR(root);
		root = NULL;
		goto failed_mount4;
	}
	if (!S_ISDIR(root->i_mode) || !root->i_blocks || !root->i_size) {
		ext4_msg(sb, KERN_ERR, "corrupt root inode, run e2fsck");
		iput(root);
		goto failed_mount4;
	}
	sb->s_root = d_make_root(root);
	if (!sb->s_root) {
		ext4_msg(sb, KERN_ERR, "get root dentry failed");
		ret = -ENOMEM;
		goto failed_mount4;
	}

	ret = ext4_setup_super(sb, es, sb_rdonly(sb));
	if (ret == -EROFS) {
		sb->s_flags |= SB_RDONLY;
		ret = 0;
	} else if (ret)
		goto failed_mount4a;

	
	if (sbi->s_inode_size > EXT4_GOOD_OLD_INODE_SIZE && sbi->s_want_extra_isize == 0) {
		sbi->s_want_extra_isize = sizeof(struct ext4_inode) - EXT4_GOOD_OLD_INODE_SIZE;
		if (ext4_has_feature_extra_isize(sb)) {
			if (sbi->s_want_extra_isize < le16_to_cpu(es->s_want_extra_isize))
				sbi->s_want_extra_isize = le16_to_cpu(es->s_want_extra_isize);
			if (sbi->s_want_extra_isize < le16_to_cpu(es->s_min_extra_isize))
				sbi->s_want_extra_isize = le16_to_cpu(es->s_min_extra_isize);
		}
	}
	
	if (EXT4_GOOD_OLD_INODE_SIZE + sbi->s_want_extra_isize > sbi->s_inode_size) {
		sbi->s_want_extra_isize = sizeof(struct ext4_inode) - EXT4_GOOD_OLD_INODE_SIZE;
		ext4_msg(sb, KERN_INFO, "required extra inode space not" "available");
	}

	ext4_set_resv_clusters(sb);

	err = ext4_setup_system_zone(sb);
	if (err) {
		ext4_msg(sb, KERN_ERR, "failed to initialize system " "zone (%d)", err);
		goto failed_mount4a;
	}

	ext4_ext_init(sb);
	err = ext4_mb_init(sb);
	if (err) {
		ext4_msg(sb, KERN_ERR, "failed to initialize mballoc (%d)", err);
		goto failed_mount5;
	}

	block = ext4_count_free_clusters(sb);
	ext4_free_blocks_count_set(sbi->s_es,  EXT4_C2B(sbi, block));
	err = percpu_counter_init(&sbi->s_freeclusters_counter, block, GFP_KERNEL);
	if (!err) {
		unsigned long freei = ext4_count_free_inodes(sb);
		sbi->s_es->s_free_inodes_count = cpu_to_le32(freei);
		err = percpu_counter_init(&sbi->s_freeinodes_counter, freei, GFP_KERNEL);
	}
	if (!err)
		err = percpu_counter_init(&sbi->s_dirs_counter, ext4_count_dirs(sb), GFP_KERNEL);
	if (!err)
		err = percpu_counter_init(&sbi->s_dirtyclusters_counter, 0, GFP_KERNEL);
	if (!err)
		err = percpu_init_rwsem(&sbi->s_journal_flag_rwsem);

	if (err) {
		ext4_msg(sb, KERN_ERR, "insufficient memory");
		goto failed_mount6;
	}

	if (ext4_has_feature_flex_bg(sb))
		if (!ext4_fill_flex_info(sb)) {
			ext4_msg(sb, KERN_ERR, "unable to initialize " "flex_bg meta info!");

			goto failed_mount6;
		}

	err = ext4_register_li_request(sb, first_not_zeroed);
	if (err)
		goto failed_mount6;

	err = ext4_register_sysfs(sb);
	if (err)
		goto failed_mount7;


	
	if (ext4_has_feature_quota(sb) && !sb_rdonly(sb)) {
		err = ext4_enable_quotas(sb);
		if (err)
			goto failed_mount8;
	}


	EXT4_SB(sb)->s_mount_state |= EXT4_ORPHAN_FS;
	ext4_orphan_cleanup(sb, es);
	EXT4_SB(sb)->s_mount_state &= ~EXT4_ORPHAN_FS;
	if (needs_recovery) {
		ext4_msg(sb, KERN_INFO, "recovery complete");
		ext4_mark_recovery_complete(sb, es);
	}
	if (EXT4_SB(sb)->s_journal) {
		if (test_opt(sb, DATA_FLAGS) == EXT4_MOUNT_JOURNAL_DATA)
			descr = " journalled data mode";
		else if (test_opt(sb, DATA_FLAGS) == EXT4_MOUNT_ORDERED_DATA)
			descr = " ordered data mode";
		else descr = " writeback data mode";
	} else descr = "out journal";

	if (test_opt(sb, DISCARD)) {
		struct request_queue *q = bdev_get_queue(sb->s_bdev);
		if (!blk_queue_discard(q))
			ext4_msg(sb, KERN_WARNING, "mounting with \"discard\" option, but " "the device does not support discard");

	}

	if (___ratelimit(&ext4_mount_msg_ratelimit, "EXT4-fs mount"))
		ext4_msg(sb, KERN_INFO, "mounted filesystem with%s. " "Opts: %.*s%s%s", descr, (int) sizeof(sbi->s_es->s_mount_opts), sbi->s_es->s_mount_opts, *sbi->s_es->s_mount_opts ? "; " : "", orig_data);




	if (es->s_error_count)
		mod_timer(&sbi->s_err_report, jiffies + 300*HZ); 

	
	ratelimit_state_init(&sbi->s_err_ratelimit_state, 5 * HZ, 10);
	ratelimit_state_init(&sbi->s_warning_ratelimit_state, 5 * HZ, 10);
	ratelimit_state_init(&sbi->s_msg_ratelimit_state, 5 * HZ, 10);

	kfree(orig_data);
	return 0;

cantfind_ext4:
	if (!silent)
		ext4_msg(sb, KERN_ERR, "VFS: Can't find ext4 filesystem");
	goto failed_mount;


failed_mount8:
	ext4_unregister_sysfs(sb);

failed_mount7:
	ext4_unregister_li_request(sb);
failed_mount6:
	ext4_mb_release(sb);
	if (sbi->s_flex_groups)
		kvfree(sbi->s_flex_groups);
	percpu_counter_destroy(&sbi->s_freeclusters_counter);
	percpu_counter_destroy(&sbi->s_freeinodes_counter);
	percpu_counter_destroy(&sbi->s_dirs_counter);
	percpu_counter_destroy(&sbi->s_dirtyclusters_counter);
failed_mount5:
	ext4_ext_release(sb);
	ext4_release_system_zone(sb);
failed_mount4a:
	dput(sb->s_root);
	sb->s_root = NULL;
failed_mount4:
	ext4_msg(sb, KERN_ERR, "mount failed");
	if (EXT4_SB(sb)->rsv_conversion_wq)
		destroy_workqueue(EXT4_SB(sb)->rsv_conversion_wq);
failed_mount_wq:
	if (sbi->s_ea_inode_cache) {
		ext4_xattr_destroy_cache(sbi->s_ea_inode_cache);
		sbi->s_ea_inode_cache = NULL;
	}
	if (sbi->s_ea_block_cache) {
		ext4_xattr_destroy_cache(sbi->s_ea_block_cache);
		sbi->s_ea_block_cache = NULL;
	}
	if (sbi->s_journal) {
		jbd2_journal_destroy(sbi->s_journal);
		sbi->s_journal = NULL;
	}
failed_mount3a:
	ext4_es_unregister_shrinker(sbi);
failed_mount3:
	del_timer_sync(&sbi->s_err_report);
	if (sbi->s_mmp_tsk)
		kthread_stop(sbi->s_mmp_tsk);
failed_mount2:
	for (i = 0; i < db_count; i++)
		brelse(sbi->s_group_desc[i]);
	kvfree(sbi->s_group_desc);
failed_mount:
	if (sbi->s_chksum_driver)
		crypto_free_shash(sbi->s_chksum_driver);

	for (i = 0; i < EXT4_MAXQUOTAS; i++)
		kfree(sbi->s_qf_names[i]);

	ext4_blkdev_remove(sbi);
	brelse(bh);
out_fail:
	sb->s_fs_info = NULL;
	kfree(sbi->s_blockgroup_lock);
out_free_base:
	kfree(sbi);
	kfree(orig_data);
	fs_put_dax(dax_dev);
	return err ? err : ret;
}


static void ext4_init_journal_params(struct super_block *sb, journal_t *journal)
{
	struct ext4_sb_info *sbi = EXT4_SB(sb);

	journal->j_commit_interval = sbi->s_commit_interval;
	journal->j_min_batch_time = sbi->s_min_batch_time;
	journal->j_max_batch_time = sbi->s_max_batch_time;

	write_lock(&journal->j_state_lock);
	if (test_opt(sb, BARRIER))
		journal->j_flags |= JBD2_BARRIER;
	else journal->j_flags &= ~JBD2_BARRIER;
	if (test_opt(sb, DATA_ERR_ABORT))
		journal->j_flags |= JBD2_ABORT_ON_SYNCDATA_ERR;
	else journal->j_flags &= ~JBD2_ABORT_ON_SYNCDATA_ERR;
	write_unlock(&journal->j_state_lock);
}

static struct inode *ext4_get_journal_inode(struct super_block *sb, unsigned int journal_inum)
{
	struct inode *journal_inode;

	
	journal_inode = ext4_iget(sb, journal_inum);
	if (IS_ERR(journal_inode)) {
		ext4_msg(sb, KERN_ERR, "no journal found");
		return NULL;
	}
	if (!journal_inode->i_nlink) {
		make_bad_inode(journal_inode);
		iput(journal_inode);
		ext4_msg(sb, KERN_ERR, "journal inode is deleted");
		return NULL;
	}

	jbd_debug(2, "Journal inode found at %p: %lld bytes\n", journal_inode, journal_inode->i_size);
	if (!S_ISREG(journal_inode->i_mode)) {
		ext4_msg(sb, KERN_ERR, "invalid journal inode");
		iput(journal_inode);
		return NULL;
	}
	return journal_inode;
}

static journal_t *ext4_get_journal(struct super_block *sb, unsigned int journal_inum)
{
	struct inode *journal_inode;
	journal_t *journal;

	BUG_ON(!ext4_has_feature_journal(sb));

	journal_inode = ext4_get_journal_inode(sb, journal_inum);
	if (!journal_inode)
		return NULL;

	journal = jbd2_journal_init_inode(journal_inode);
	if (!journal) {
		ext4_msg(sb, KERN_ERR, "Could not load journal inode");
		iput(journal_inode);
		return NULL;
	}
	journal->j_private = sb;
	ext4_init_journal_params(sb, journal);
	return journal;
}

static journal_t *ext4_get_dev_journal(struct super_block *sb, dev_t j_dev)
{
	struct buffer_head *bh;
	journal_t *journal;
	ext4_fsblk_t start;
	ext4_fsblk_t len;
	int hblock, blocksize;
	ext4_fsblk_t sb_block;
	unsigned long offset;
	struct ext4_super_block *es;
	struct block_device *bdev;

	BUG_ON(!ext4_has_feature_journal(sb));

	bdev = ext4_blkdev_get(j_dev, sb);
	if (bdev == NULL)
		return NULL;

	blocksize = sb->s_blocksize;
	hblock = bdev_logical_block_size(bdev);
	if (blocksize < hblock) {
		ext4_msg(sb, KERN_ERR, "blocksize too small for journal device");
		goto out_bdev;
	}

	sb_block = EXT4_MIN_BLOCK_SIZE / blocksize;
	offset = EXT4_MIN_BLOCK_SIZE % blocksize;
	set_blocksize(bdev, blocksize);
	if (!(bh = __bread(bdev, sb_block, blocksize))) {
		ext4_msg(sb, KERN_ERR, "couldn't read superblock of " "external journal");
		goto out_bdev;
	}

	es = (struct ext4_super_block *) (bh->b_data + offset);
	if ((le16_to_cpu(es->s_magic) != EXT4_SUPER_MAGIC) || !(le32_to_cpu(es->s_feature_incompat) & EXT4_FEATURE_INCOMPAT_JOURNAL_DEV)) {

		ext4_msg(sb, KERN_ERR, "external journal has " "bad superblock");
		brelse(bh);
		goto out_bdev;
	}

	if ((le32_to_cpu(es->s_feature_ro_compat) & EXT4_FEATURE_RO_COMPAT_METADATA_CSUM) && es->s_checksum != ext4_superblock_csum(sb, es)) {

		ext4_msg(sb, KERN_ERR, "external journal has " "corrupt superblock");
		brelse(bh);
		goto out_bdev;
	}

	if (memcmp(EXT4_SB(sb)->s_es->s_journal_uuid, es->s_uuid, 16)) {
		ext4_msg(sb, KERN_ERR, "journal UUID does not match");
		brelse(bh);
		goto out_bdev;
	}

	len = ext4_blocks_count(es);
	start = sb_block + 1;
	brelse(bh);	

	journal = jbd2_journal_init_dev(bdev, sb->s_bdev, start, len, blocksize);
	if (!journal) {
		ext4_msg(sb, KERN_ERR, "failed to create device journal");
		goto out_bdev;
	}
	journal->j_private = sb;
	ll_rw_block(REQ_OP_READ, REQ_META | REQ_PRIO, 1, &journal->j_sb_buffer);
	wait_on_buffer(journal->j_sb_buffer);
	if (!buffer_uptodate(journal->j_sb_buffer)) {
		ext4_msg(sb, KERN_ERR, "I/O error on journal device");
		goto out_journal;
	}
	if (be32_to_cpu(journal->j_superblock->s_nr_users) != 1) {
		ext4_msg(sb, KERN_ERR, "External journal has more than one " "user (unsupported) - %d", be32_to_cpu(journal->j_superblock->s_nr_users));

		goto out_journal;
	}
	EXT4_SB(sb)->journal_bdev = bdev;
	ext4_init_journal_params(sb, journal);
	return journal;

out_journal:
	jbd2_journal_destroy(journal);
out_bdev:
	ext4_blkdev_put(bdev);
	return NULL;
}

static int ext4_load_journal(struct super_block *sb, struct ext4_super_block *es, unsigned long journal_devnum)

{
	journal_t *journal;
	unsigned int journal_inum = le32_to_cpu(es->s_journal_inum);
	dev_t journal_dev;
	int err = 0;
	int really_read_only;

	BUG_ON(!ext4_has_feature_journal(sb));

	if (journal_devnum && journal_devnum != le32_to_cpu(es->s_journal_dev)) {
		ext4_msg(sb, KERN_INFO, "external journal device major/minor " "numbers have changed");
		journal_dev = new_decode_dev(journal_devnum);
	} else journal_dev = new_decode_dev(le32_to_cpu(es->s_journal_dev));

	really_read_only = bdev_read_only(sb->s_bdev);

	
	if (ext4_has_feature_journal_needs_recovery(sb)) {
		if (sb_rdonly(sb)) {
			ext4_msg(sb, KERN_INFO, "INFO: recovery " "required on readonly filesystem");
			if (really_read_only) {
				ext4_msg(sb, KERN_ERR, "write access " "unavailable, cannot proceed " "(try mounting with noload)");

				return -EROFS;
			}
			ext4_msg(sb, KERN_INFO, "write access will " "be enabled during recovery");
		}
	}

	if (journal_inum && journal_dev) {
		ext4_msg(sb, KERN_ERR, "filesystem has both journal " "and inode journals!");
		return -EINVAL;
	}

	if (journal_inum) {
		if (!(journal = ext4_get_journal(sb, journal_inum)))
			return -EINVAL;
	} else {
		if (!(journal = ext4_get_dev_journal(sb, journal_dev)))
			return -EINVAL;
	}

	if (!(journal->j_flags & JBD2_BARRIER))
		ext4_msg(sb, KERN_INFO, "barriers disabled");

	if (!ext4_has_feature_journal_needs_recovery(sb))
		err = jbd2_journal_wipe(journal, !really_read_only);
	if (!err) {
		char *save = kmalloc(EXT4_S_ERR_LEN, GFP_KERNEL);
		if (save)
			memcpy(save, ((char *) es) + EXT4_S_ERR_START, EXT4_S_ERR_LEN);
		err = jbd2_journal_load(journal);
		if (save)
			memcpy(((char *) es) + EXT4_S_ERR_START, save, EXT4_S_ERR_LEN);
		kfree(save);
	}

	if (err) {
		ext4_msg(sb, KERN_ERR, "error loading journal");
		jbd2_journal_destroy(journal);
		return err;
	}

	EXT4_SB(sb)->s_journal = journal;
	ext4_clear_journal_err(sb, es);

	if (!really_read_only && journal_devnum && journal_devnum != le32_to_cpu(es->s_journal_dev)) {
		es->s_journal_dev = cpu_to_le32(journal_devnum);

		
		ext4_commit_super(sb, 1);
	}

	return 0;
}

static int ext4_commit_super(struct super_block *sb, int sync)
{
	struct ext4_super_block *es = EXT4_SB(sb)->s_es;
	struct buffer_head *sbh = EXT4_SB(sb)->s_sbh;
	int error = 0;

	if (!sbh || block_device_ejected(sb))
		return error;
	
	if (!(sb->s_flags & SB_RDONLY))
		es->s_wtime = cpu_to_le32(get_seconds());
	if (sb->s_bdev->bd_part)
		es->s_kbytes_written = cpu_to_le64(EXT4_SB(sb)->s_kbytes_written + ((part_stat_read(sb->s_bdev->bd_part, sectors[1]) - EXT4_SB(sb)->s_sectors_written_start) >> 1));


	else es->s_kbytes_written = cpu_to_le64(EXT4_SB(sb)->s_kbytes_written);

	if (percpu_counter_initialized(&EXT4_SB(sb)->s_freeclusters_counter))
		ext4_free_blocks_count_set(es, EXT4_C2B(EXT4_SB(sb), percpu_counter_sum_positive( &EXT4_SB(sb)->s_freeclusters_counter)));

	if (percpu_counter_initialized(&EXT4_SB(sb)->s_freeinodes_counter))
		es->s_free_inodes_count = cpu_to_le32(percpu_counter_sum_positive( &EXT4_SB(sb)->s_freeinodes_counter));

	BUFFER_TRACE(sbh, "marking dirty");
	ext4_superblock_csum_set(sb);
	if (sync)
		lock_buffer(sbh);
	if (buffer_write_io_error(sbh)) {
		
		ext4_msg(sb, KERN_ERR, "previous I/O error to " "superblock detected");
		clear_buffer_write_io_error(sbh);
		set_buffer_uptodate(sbh);
	}
	mark_buffer_dirty(sbh);
	if (sync) {
		unlock_buffer(sbh);
		error = __sync_dirty_buffer(sbh, REQ_SYNC | (test_opt(sb, BARRIER) ? REQ_FUA : 0));
		if (buffer_write_io_error(sbh)) {
			ext4_msg(sb, KERN_ERR, "I/O error while writing " "superblock");
			clear_buffer_write_io_error(sbh);
			set_buffer_uptodate(sbh);
		}
	}
	return error;
}


static void ext4_mark_recovery_complete(struct super_block *sb, struct ext4_super_block *es)
{
	journal_t *journal = EXT4_SB(sb)->s_journal;

	if (!ext4_has_feature_journal(sb)) {
		BUG_ON(journal != NULL);
		return;
	}
	jbd2_journal_lock_updates(journal);
	if (jbd2_journal_flush(journal) < 0)
		goto out;

	if (ext4_has_feature_journal_needs_recovery(sb) && sb_rdonly(sb)) {
		ext4_clear_feature_journal_needs_recovery(sb);
		ext4_commit_super(sb, 1);
	}

out:
	jbd2_journal_unlock_updates(journal);
}


static void ext4_clear_journal_err(struct super_block *sb, struct ext4_super_block *es)
{
	journal_t *journal;
	int j_errno;
	const char *errstr;

	BUG_ON(!ext4_has_feature_journal(sb));

	journal = EXT4_SB(sb)->s_journal;

	

	j_errno = jbd2_journal_errno(journal);
	if (j_errno) {
		char nbuf[16];

		errstr = ext4_decode_error(sb, j_errno, nbuf);
		ext4_warning(sb, "Filesystem error recorded " "from previous mount: %s", errstr);
		ext4_warning(sb, "Marking fs in need of filesystem check.");

		EXT4_SB(sb)->s_mount_state |= EXT4_ERROR_FS;
		es->s_state |= cpu_to_le16(EXT4_ERROR_FS);
		ext4_commit_super(sb, 1);

		jbd2_journal_clear_err(journal);
		jbd2_journal_update_sb_errno(journal);
	}
}


int ext4_force_commit(struct super_block *sb)
{
	journal_t *journal;

	if (sb_rdonly(sb))
		return 0;

	journal = EXT4_SB(sb)->s_journal;
	return ext4_journal_force_commit(journal);
}

static int ext4_sync_fs(struct super_block *sb, int wait)
{
	int ret = 0;
	tid_t target;
	bool needs_barrier = false;
	struct ext4_sb_info *sbi = EXT4_SB(sb);

	if (unlikely(ext4_forced_shutdown(sbi)))
		return 0;

	trace_ext4_sync_fs(sb, wait);
	flush_workqueue(sbi->rsv_conversion_wq);
	
	dquot_writeback_dquots(sb, -1);
	
	if (sbi->s_journal) {
		target = jbd2_get_latest_transaction(sbi->s_journal);
		if (wait && sbi->s_journal->j_flags & JBD2_BARRIER && !jbd2_trans_will_send_data_barrier(sbi->s_journal, target))
			needs_barrier = true;

		if (jbd2_journal_start_commit(sbi->s_journal, &target)) {
			if (wait)
				ret = jbd2_log_wait_commit(sbi->s_journal, target);
		}
	} else if (wait && test_opt(sb, BARRIER))
		needs_barrier = true;
	if (needs_barrier) {
		int err;
		err = blkdev_issue_flush(sb->s_bdev, GFP_KERNEL, NULL);
		if (!ret)
			ret = err;
	}

	return ret;
}


static int ext4_freeze(struct super_block *sb)
{
	int error = 0;
	journal_t *journal;

	if (sb_rdonly(sb))
		return 0;

	journal = EXT4_SB(sb)->s_journal;

	if (journal) {
		
		jbd2_journal_lock_updates(journal);

		
		error = jbd2_journal_flush(journal);
		if (error < 0)
			goto out;

		
		ext4_clear_feature_journal_needs_recovery(sb);
	}

	error = ext4_commit_super(sb, 1);
out:
	if (journal)
		
		jbd2_journal_unlock_updates(journal);
	return error;
}


static int ext4_unfreeze(struct super_block *sb)
{
	if (sb_rdonly(sb) || ext4_forced_shutdown(EXT4_SB(sb)))
		return 0;

	if (EXT4_SB(sb)->s_journal) {
		
		ext4_set_feature_journal_needs_recovery(sb);
	}

	ext4_commit_super(sb, 1);
	return 0;
}


struct ext4_mount_options {
	unsigned long s_mount_opt;
	unsigned long s_mount_opt2;
	kuid_t s_resuid;
	kgid_t s_resgid;
	unsigned long s_commit_interval;
	u32 s_min_batch_time, s_max_batch_time;

	int s_jquota_fmt;
	char *s_qf_names[EXT4_MAXQUOTAS];

};

static int ext4_remount(struct super_block *sb, int *flags, char *data)
{
	struct ext4_super_block *es;
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	unsigned long old_sb_flags;
	struct ext4_mount_options old_opts;
	int enable_quota = 0;
	ext4_group_t g;
	unsigned int journal_ioprio = DEFAULT_JOURNAL_IOPRIO;
	int err = 0;

	int i, j;

	char *orig_data = kstrdup(data, GFP_KERNEL);

	
	old_sb_flags = sb->s_flags;
	old_opts.s_mount_opt = sbi->s_mount_opt;
	old_opts.s_mount_opt2 = sbi->s_mount_opt2;
	old_opts.s_resuid = sbi->s_resuid;
	old_opts.s_resgid = sbi->s_resgid;
	old_opts.s_commit_interval = sbi->s_commit_interval;
	old_opts.s_min_batch_time = sbi->s_min_batch_time;
	old_opts.s_max_batch_time = sbi->s_max_batch_time;

	old_opts.s_jquota_fmt = sbi->s_jquota_fmt;
	for (i = 0; i < EXT4_MAXQUOTAS; i++)
		if (sbi->s_qf_names[i]) {
			old_opts.s_qf_names[i] = kstrdup(sbi->s_qf_names[i], GFP_KERNEL);
			if (!old_opts.s_qf_names[i]) {
				for (j = 0; j < i; j++)
					kfree(old_opts.s_qf_names[j]);
				kfree(orig_data);
				return -ENOMEM;
			}
		} else old_opts.s_qf_names[i] = NULL;

	if (sbi->s_journal && sbi->s_journal->j_task->io_context)
		journal_ioprio = sbi->s_journal->j_task->io_context->ioprio;

	if (!parse_options(data, sb, NULL, &journal_ioprio, 1)) {
		err = -EINVAL;
		goto restore_opts;
	}

	if ((old_opts.s_mount_opt & EXT4_MOUNT_JOURNAL_CHECKSUM) ^ test_opt(sb, JOURNAL_CHECKSUM)) {
		ext4_msg(sb, KERN_ERR, "changing journal_checksum " "during remount not supported; ignoring");
		sbi->s_mount_opt ^= EXT4_MOUNT_JOURNAL_CHECKSUM;
	}

	if (test_opt(sb, DATA_FLAGS) == EXT4_MOUNT_JOURNAL_DATA) {
		if (test_opt2(sb, EXPLICIT_DELALLOC)) {
			ext4_msg(sb, KERN_ERR, "can't mount with " "both data=journal and delalloc");
			err = -EINVAL;
			goto restore_opts;
		}
		if (test_opt(sb, DIOREAD_NOLOCK)) {
			ext4_msg(sb, KERN_ERR, "can't mount with " "both data=journal and dioread_nolock");
			err = -EINVAL;
			goto restore_opts;
		}
		if (test_opt(sb, DAX)) {
			ext4_msg(sb, KERN_ERR, "can't mount with " "both data=journal and dax");
			err = -EINVAL;
			goto restore_opts;
		}
	} else if (test_opt(sb, DATA_FLAGS) == EXT4_MOUNT_ORDERED_DATA) {
		if (test_opt(sb, JOURNAL_ASYNC_COMMIT)) {
			ext4_msg(sb, KERN_ERR, "can't mount with " "journal_async_commit in data=ordered mode");
			err = -EINVAL;
			goto restore_opts;
		}
	}

	if ((sbi->s_mount_opt ^ old_opts.s_mount_opt) & EXT4_MOUNT_NO_MBCACHE) {
		ext4_msg(sb, KERN_ERR, "can't enable nombcache during remount");
		err = -EINVAL;
		goto restore_opts;
	}

	if ((sbi->s_mount_opt ^ old_opts.s_mount_opt) & EXT4_MOUNT_DAX) {
		ext4_msg(sb, KERN_WARNING, "warning: refusing change of " "dax flag with busy inodes while remounting");
		sbi->s_mount_opt ^= EXT4_MOUNT_DAX;
	}

	if (sbi->s_mount_flags & EXT4_MF_FS_ABORTED)
		ext4_abort(sb, "Abort forced by user");

	sb->s_flags = (sb->s_flags & ~SB_POSIXACL) | (test_opt(sb, POSIX_ACL) ? SB_POSIXACL : 0);

	es = sbi->s_es;

	if (sbi->s_journal) {
		ext4_init_journal_params(sb, sbi->s_journal);
		set_task_ioprio(sbi->s_journal->j_task, journal_ioprio);
	}

	if (*flags & SB_LAZYTIME)
		sb->s_flags |= SB_LAZYTIME;

	if ((bool)(*flags & SB_RDONLY) != sb_rdonly(sb)) {
		if (sbi->s_mount_flags & EXT4_MF_FS_ABORTED) {
			err = -EROFS;
			goto restore_opts;
		}

		if (*flags & SB_RDONLY) {
			err = sync_filesystem(sb);
			if (err < 0)
				goto restore_opts;
			err = dquot_suspend(sb, -1);
			if (err < 0)
				goto restore_opts;

			
			sb->s_flags |= SB_RDONLY;

			
			if (!(es->s_state & cpu_to_le16(EXT4_VALID_FS)) && (sbi->s_mount_state & EXT4_VALID_FS))
				es->s_state = cpu_to_le16(sbi->s_mount_state);

			if (sbi->s_journal)
				ext4_mark_recovery_complete(sb, es);
		} else {
			
			if (ext4_has_feature_readonly(sb) || !ext4_feature_set_ok(sb, 0)) {
				err = -EROFS;
				goto restore_opts;
			}
			
			for (g = 0; g < sbi->s_groups_count; g++) {
				struct ext4_group_desc *gdp = ext4_get_group_desc(sb, g, NULL);

				if (!ext4_group_desc_csum_verify(sb, g, gdp)) {
					ext4_msg(sb, KERN_ERR, "ext4_remount: Checksum for group %u failed (%u!=%u)", g, le16_to_cpu(ext4_group_desc_csum(sb, g, gdp)), le16_to_cpu(gdp->bg_checksum));


					err = -EFSBADCRC;
					goto restore_opts;
				}
			}

			
			if (es->s_last_orphan) {
				ext4_msg(sb, KERN_WARNING, "Couldn't " "remount RDWR because of unprocessed " "orphan inode list.  Please " "umount/remount instead");


				err = -EINVAL;
				goto restore_opts;
			}

			
			if (sbi->s_journal)
				ext4_clear_journal_err(sb, es);
			sbi->s_mount_state = le16_to_cpu(es->s_state);

			err = ext4_setup_super(sb, es, 0);
			if (err)
				goto restore_opts;

			sb->s_flags &= ~SB_RDONLY;
			if (ext4_has_feature_mmp(sb))
				if (ext4_multi_mount_protect(sb, le64_to_cpu(es->s_mmp_block))) {
					err = -EROFS;
					goto restore_opts;
				}
			enable_quota = 1;
		}
	}

	
	if (sb_rdonly(sb) || !test_opt(sb, INIT_INODE_TABLE))
		ext4_unregister_li_request(sb);
	else {
		ext4_group_t first_not_zeroed;
		first_not_zeroed = ext4_has_uninit_itable(sb);
		ext4_register_li_request(sb, first_not_zeroed);
	}

	ext4_setup_system_zone(sb);
	if (sbi->s_journal == NULL && !(old_sb_flags & SB_RDONLY)) {
		err = ext4_commit_super(sb, 1);
		if (err)
			goto restore_opts;
	}


	
	for (i = 0; i < EXT4_MAXQUOTAS; i++)
		kfree(old_opts.s_qf_names[i]);
	if (enable_quota) {
		if (sb_any_quota_suspended(sb))
			dquot_resume(sb, -1);
		else if (ext4_has_feature_quota(sb)) {
			err = ext4_enable_quotas(sb);
			if (err)
				goto restore_opts;
		}
	}


	*flags = (*flags & ~SB_LAZYTIME) | (sb->s_flags & SB_LAZYTIME);
	ext4_msg(sb, KERN_INFO, "re-mounted. Opts: %s", orig_data);
	kfree(orig_data);
	return 0;

restore_opts:
	sb->s_flags = old_sb_flags;
	sbi->s_mount_opt = old_opts.s_mount_opt;
	sbi->s_mount_opt2 = old_opts.s_mount_opt2;
	sbi->s_resuid = old_opts.s_resuid;
	sbi->s_resgid = old_opts.s_resgid;
	sbi->s_commit_interval = old_opts.s_commit_interval;
	sbi->s_min_batch_time = old_opts.s_min_batch_time;
	sbi->s_max_batch_time = old_opts.s_max_batch_time;

	sbi->s_jquota_fmt = old_opts.s_jquota_fmt;
	for (i = 0; i < EXT4_MAXQUOTAS; i++) {
		kfree(sbi->s_qf_names[i]);
		sbi->s_qf_names[i] = old_opts.s_qf_names[i];
	}

	kfree(orig_data);
	return err;
}


static int ext4_statfs_project(struct super_block *sb, kprojid_t projid, struct kstatfs *buf)
{
	struct kqid qid;
	struct dquot *dquot;
	u64 limit;
	u64 curblock;

	qid = make_kqid_projid(projid);
	dquot = dqget(sb, qid);
	if (IS_ERR(dquot))
		return PTR_ERR(dquot);
	spin_lock(&dquot->dq_dqb_lock);

	limit = (dquot->dq_dqb.dqb_bsoftlimit ? dquot->dq_dqb.dqb_bsoftlimit :
		 dquot->dq_dqb.dqb_bhardlimit) >> sb->s_blocksize_bits;
	if (limit && buf->f_blocks > limit) {
		curblock = (dquot->dq_dqb.dqb_curspace + dquot->dq_dqb.dqb_rsvspace) >> sb->s_blocksize_bits;
		buf->f_blocks = limit;
		buf->f_bfree = buf->f_bavail = (buf->f_blocks > curblock) ? (buf->f_blocks - curblock) : 0;

	}

	limit = dquot->dq_dqb.dqb_isoftlimit ? dquot->dq_dqb.dqb_isoftlimit :
		dquot->dq_dqb.dqb_ihardlimit;
	if (limit && buf->f_files > limit) {
		buf->f_files = limit;
		buf->f_ffree = (buf->f_files > dquot->dq_dqb.dqb_curinodes) ? (buf->f_files - dquot->dq_dqb.dqb_curinodes) : 0;

	}

	spin_unlock(&dquot->dq_dqb_lock);
	dqput(dquot);
	return 0;
}


static int ext4_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	struct ext4_super_block *es = sbi->s_es;
	ext4_fsblk_t overhead = 0, resv_blocks;
	u64 fsid;
	s64 bfree;
	resv_blocks = EXT4_C2B(sbi, atomic64_read(&sbi->s_resv_clusters));

	if (!test_opt(sb, MINIX_DF))
		overhead = sbi->s_overhead;

	buf->f_type = EXT4_SUPER_MAGIC;
	buf->f_bsize = sb->s_blocksize;
	buf->f_blocks = ext4_blocks_count(es) - EXT4_C2B(sbi, overhead);
	bfree = percpu_counter_sum_positive(&sbi->s_freeclusters_counter) - percpu_counter_sum_positive(&sbi->s_dirtyclusters_counter);
	
	buf->f_bfree = EXT4_C2B(sbi, max_t(s64, bfree, 0));
	buf->f_bavail = buf->f_bfree - (ext4_r_blocks_count(es) + resv_blocks);
	if (buf->f_bfree < (ext4_r_blocks_count(es) + resv_blocks))
		buf->f_bavail = 0;
	buf->f_files = le32_to_cpu(es->s_inodes_count);
	buf->f_ffree = percpu_counter_sum_positive(&sbi->s_freeinodes_counter);
	buf->f_namelen = EXT4_NAME_LEN;
	fsid = le64_to_cpup((void *)es->s_uuid) ^ le64_to_cpup((void *)es->s_uuid + sizeof(u64));
	buf->f_fsid.val[0] = fsid & 0xFFFFFFFFUL;
	buf->f_fsid.val[1] = (fsid >> 32) & 0xFFFFFFFFUL;


	if (ext4_test_inode_flag(dentry->d_inode, EXT4_INODE_PROJINHERIT) && sb_has_quota_limits_enabled(sb, PRJQUOTA))
		ext4_statfs_project(sb, EXT4_I(dentry->d_inode)->i_projid, buf);

	return 0;
}





static inline struct inode *dquot_to_inode(struct dquot *dquot)
{
	return sb_dqopt(dquot->dq_sb)->files[dquot->dq_id.type];
}

static int ext4_write_dquot(struct dquot *dquot)
{
	int ret, err;
	handle_t *handle;
	struct inode *inode;

	inode = dquot_to_inode(dquot);
	handle = ext4_journal_start(inode, EXT4_HT_QUOTA, EXT4_QUOTA_TRANS_BLOCKS(dquot->dq_sb));
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	ret = dquot_commit(dquot);
	err = ext4_journal_stop(handle);
	if (!ret)
		ret = err;
	return ret;
}

static int ext4_acquire_dquot(struct dquot *dquot)
{
	int ret, err;
	handle_t *handle;

	handle = ext4_journal_start(dquot_to_inode(dquot), EXT4_HT_QUOTA, EXT4_QUOTA_INIT_BLOCKS(dquot->dq_sb));
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	ret = dquot_acquire(dquot);
	err = ext4_journal_stop(handle);
	if (!ret)
		ret = err;
	return ret;
}

static int ext4_release_dquot(struct dquot *dquot)
{
	int ret, err;
	handle_t *handle;

	handle = ext4_journal_start(dquot_to_inode(dquot), EXT4_HT_QUOTA, EXT4_QUOTA_DEL_BLOCKS(dquot->dq_sb));
	if (IS_ERR(handle)) {
		
		dquot_release(dquot);
		return PTR_ERR(handle);
	}
	ret = dquot_release(dquot);
	err = ext4_journal_stop(handle);
	if (!ret)
		ret = err;
	return ret;
}

static int ext4_mark_dquot_dirty(struct dquot *dquot)
{
	struct super_block *sb = dquot->dq_sb;
	struct ext4_sb_info *sbi = EXT4_SB(sb);

	
	if (ext4_has_feature_quota(sb) || sbi->s_qf_names[USRQUOTA] || sbi->s_qf_names[GRPQUOTA]) {
		dquot_mark_dquot_dirty(dquot);
		return ext4_write_dquot(dquot);
	} else {
		return dquot_mark_dquot_dirty(dquot);
	}
}

static int ext4_write_info(struct super_block *sb, int type)
{
	int ret, err;
	handle_t *handle;

	
	handle = ext4_journal_start(d_inode(sb->s_root), EXT4_HT_QUOTA, 2);
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	ret = dquot_commit_info(sb, type);
	err = ext4_journal_stop(handle);
	if (!ret)
		ret = err;
	return ret;
}


static int ext4_quota_on_mount(struct super_block *sb, int type)
{
	return dquot_quota_on_mount(sb, EXT4_SB(sb)->s_qf_names[type], EXT4_SB(sb)->s_jquota_fmt, type);
}

static void lockdep_set_quota_inode(struct inode *inode, int subclass)
{
	struct ext4_inode_info *ei = EXT4_I(inode);

	
	(void) ei;	
	lockdep_set_subclass(&ei->i_data_sem, subclass);
}


static int ext4_quota_on(struct super_block *sb, int type, int format_id, const struct path *path)
{
	int err;

	if (!test_opt(sb, QUOTA))
		return -EINVAL;

	
	if (path->dentry->d_sb != sb)
		return -EXDEV;
	
	if (EXT4_SB(sb)->s_qf_names[type]) {
		
		if (path->dentry->d_parent != sb->s_root)
			ext4_msg(sb, KERN_WARNING, "Quota file not on filesystem root. " "Journaled quota will not work");

		sb_dqopt(sb)->flags |= DQUOT_NOLIST_DIRTY;
	} else {
		
		sb_dqopt(sb)->flags &= ~DQUOT_NOLIST_DIRTY;
	}

	
	if (EXT4_SB(sb)->s_journal && ext4_should_journal_data(d_inode(path->dentry))) {
		
		jbd2_journal_lock_updates(EXT4_SB(sb)->s_journal);
		err = jbd2_journal_flush(EXT4_SB(sb)->s_journal);
		jbd2_journal_unlock_updates(EXT4_SB(sb)->s_journal);
		if (err)
			return err;
	}

	lockdep_set_quota_inode(path->dentry->d_inode, I_DATA_SEM_QUOTA);
	err = dquot_quota_on(sb, type, format_id, path);
	if (err) {
		lockdep_set_quota_inode(path->dentry->d_inode, I_DATA_SEM_NORMAL);
	} else {
		struct inode *inode = d_inode(path->dentry);
		handle_t *handle;

		
		inode_lock(inode);
		handle = ext4_journal_start(inode, EXT4_HT_QUOTA, 1);
		if (IS_ERR(handle))
			goto unlock_inode;
		EXT4_I(inode)->i_flags |= EXT4_NOATIME_FL | EXT4_IMMUTABLE_FL;
		inode_set_flags(inode, S_NOATIME | S_IMMUTABLE, S_NOATIME | S_IMMUTABLE);
		ext4_mark_inode_dirty(handle, inode);
		ext4_journal_stop(handle);
	unlock_inode:
		inode_unlock(inode);
	}
	return err;
}

static int ext4_quota_enable(struct super_block *sb, int type, int format_id, unsigned int flags)
{
	int err;
	struct inode *qf_inode;
	unsigned long qf_inums[EXT4_MAXQUOTAS] = {
		le32_to_cpu(EXT4_SB(sb)->s_es->s_usr_quota_inum), le32_to_cpu(EXT4_SB(sb)->s_es->s_grp_quota_inum), le32_to_cpu(EXT4_SB(sb)->s_es->s_prj_quota_inum)

	};

	BUG_ON(!ext4_has_feature_quota(sb));

	if (!qf_inums[type])
		return -EPERM;

	qf_inode = ext4_iget(sb, qf_inums[type]);
	if (IS_ERR(qf_inode)) {
		ext4_error(sb, "Bad quota inode # %lu", qf_inums[type]);
		return PTR_ERR(qf_inode);
	}

	
	qf_inode->i_flags |= S_NOQUOTA;
	lockdep_set_quota_inode(qf_inode, I_DATA_SEM_QUOTA);
	err = dquot_enable(qf_inode, type, format_id, flags);
	iput(qf_inode);
	if (err)
		lockdep_set_quota_inode(qf_inode, I_DATA_SEM_NORMAL);

	return err;
}


static int ext4_enable_quotas(struct super_block *sb)
{
	int type, err = 0;
	unsigned long qf_inums[EXT4_MAXQUOTAS] = {
		le32_to_cpu(EXT4_SB(sb)->s_es->s_usr_quota_inum), le32_to_cpu(EXT4_SB(sb)->s_es->s_grp_quota_inum), le32_to_cpu(EXT4_SB(sb)->s_es->s_prj_quota_inum)

	};
	bool quota_mopt[EXT4_MAXQUOTAS] = {
		test_opt(sb, USRQUOTA), test_opt(sb, GRPQUOTA), test_opt(sb, PRJQUOTA), };



	sb_dqopt(sb)->flags |= DQUOT_QUOTA_SYS_FILE | DQUOT_NOLIST_DIRTY;
	for (type = 0; type < EXT4_MAXQUOTAS; type++) {
		if (qf_inums[type]) {
			err = ext4_quota_enable(sb, type, QFMT_VFS_V1, DQUOT_USAGE_ENABLED | (quota_mopt[type] ? DQUOT_LIMITS_ENABLED : 0));

			if (err) {
				for (type--; type >= 0; type--)
					dquot_quota_off(sb, type);

				ext4_warning(sb, "Failed to enable quota tracking " "(type=%d, err=%d). Please run " "e2fsck to fix.", type, err);


				return err;
			}
		}
	}
	return 0;
}

static int ext4_quota_off(struct super_block *sb, int type)
{
	struct inode *inode = sb_dqopt(sb)->files[type];
	handle_t *handle;
	int err;

	
	if (test_opt(sb, DELALLOC))
		sync_filesystem(sb);

	if (!inode || !igrab(inode))
		goto out;

	err = dquot_quota_off(sb, type);
	if (err || ext4_has_feature_quota(sb))
		goto out_put;

	inode_lock(inode);
	
	handle = ext4_journal_start(inode, EXT4_HT_QUOTA, 1);
	if (IS_ERR(handle))
		goto out_unlock;
	EXT4_I(inode)->i_flags &= ~(EXT4_NOATIME_FL | EXT4_IMMUTABLE_FL);
	inode_set_flags(inode, 0, S_NOATIME | S_IMMUTABLE);
	inode->i_mtime = inode->i_ctime = current_time(inode);
	ext4_mark_inode_dirty(handle, inode);
	ext4_journal_stop(handle);
out_unlock:
	inode_unlock(inode);
out_put:
	lockdep_set_quota_inode(inode, I_DATA_SEM_NORMAL);
	iput(inode);
	return err;
out:
	return dquot_quota_off(sb, type);
}


static ssize_t ext4_quota_read(struct super_block *sb, int type, char *data, size_t len, loff_t off)
{
	struct inode *inode = sb_dqopt(sb)->files[type];
	ext4_lblk_t blk = off >> EXT4_BLOCK_SIZE_BITS(sb);
	int offset = off & (sb->s_blocksize - 1);
	int tocopy;
	size_t toread;
	struct buffer_head *bh;
	loff_t i_size = i_size_read(inode);

	if (off > i_size)
		return 0;
	if (off+len > i_size)
		len = i_size-off;
	toread = len;
	while (toread > 0) {
		tocopy = sb->s_blocksize - offset < toread ? sb->s_blocksize - offset : toread;
		bh = ext4_bread(NULL, inode, blk, 0);
		if (IS_ERR(bh))
			return PTR_ERR(bh);
		if (!bh)	
			memset(data, 0, tocopy);
		else memcpy(data, bh->b_data+offset, tocopy);
		brelse(bh);
		offset = 0;
		toread -= tocopy;
		data += tocopy;
		blk++;
	}
	return len;
}


static ssize_t ext4_quota_write(struct super_block *sb, int type, const char *data, size_t len, loff_t off)
{
	struct inode *inode = sb_dqopt(sb)->files[type];
	ext4_lblk_t blk = off >> EXT4_BLOCK_SIZE_BITS(sb);
	int err, offset = off & (sb->s_blocksize - 1);
	int retries = 0;
	struct buffer_head *bh;
	handle_t *handle = journal_current_handle();

	if (EXT4_SB(sb)->s_journal && !handle) {
		ext4_msg(sb, KERN_WARNING, "Quota write (off=%llu, len=%llu)" " cancelled because transaction is not started", (unsigned long long)off, (unsigned long long)len);

		return -EIO;
	}
	
	if (sb->s_blocksize - offset < len) {
		ext4_msg(sb, KERN_WARNING, "Quota write (off=%llu, len=%llu)" " cancelled because not block aligned", (unsigned long long)off, (unsigned long long)len);

		return -EIO;
	}

	do {
		bh = ext4_bread(handle, inode, blk, EXT4_GET_BLOCKS_CREATE | EXT4_GET_BLOCKS_METADATA_NOFAIL);

	} while (IS_ERR(bh) && (PTR_ERR(bh) == -ENOSPC) && ext4_should_retry_alloc(inode->i_sb, &retries));
	if (IS_ERR(bh))
		return PTR_ERR(bh);
	if (!bh)
		goto out;
	BUFFER_TRACE(bh, "get write access");
	err = ext4_journal_get_write_access(handle, bh);
	if (err) {
		brelse(bh);
		return err;
	}
	lock_buffer(bh);
	memcpy(bh->b_data+offset, data, len);
	flush_dcache_page(bh->b_page);
	unlock_buffer(bh);
	err = ext4_handle_dirty_metadata(handle, NULL, bh);
	brelse(bh);
out:
	if (inode->i_size < off + len) {
		i_size_write(inode, off + len);
		EXT4_I(inode)->i_disksize = inode->i_size;
		ext4_mark_inode_dirty(handle, inode);
	}
	return len;
}

static int ext4_get_next_id(struct super_block *sb, struct kqid *qid)
{
	const struct quota_format_ops	*ops;

	if (!sb_has_quota_loaded(sb, qid->type))
		return -ESRCH;
	ops = sb_dqopt(sb)->ops[qid->type];
	if (!ops || !ops->get_next_id)
		return -ENOSYS;
	return dquot_get_next_id(sb, qid);
}


static struct dentry *ext4_mount(struct file_system_type *fs_type, int flags, const char *dev_name, void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, ext4_fill_super);
}


static inline void register_as_ext2(void)
{
	int err = register_filesystem(&ext2_fs_type);
	if (err)
		printk(KERN_WARNING "EXT4-fs: Unable to register as ext2 (%d)\n", err);
}

static inline void unregister_as_ext2(void)
{
	unregister_filesystem(&ext2_fs_type);
}

static inline int ext2_feature_set_ok(struct super_block *sb)
{
	if (ext4_has_unknown_ext2_incompat_features(sb))
		return 0;
	if (sb_rdonly(sb))
		return 1;
	if (ext4_has_unknown_ext2_ro_compat_features(sb))
		return 0;
	return 1;
}

static inline void register_as_ext2(void) { }
static inline void unregister_as_ext2(void) { }
static inline int ext2_feature_set_ok(struct super_block *sb) { return 0; }


static inline void register_as_ext3(void)
{
	int err = register_filesystem(&ext3_fs_type);
	if (err)
		printk(KERN_WARNING "EXT4-fs: Unable to register as ext3 (%d)\n", err);
}

static inline void unregister_as_ext3(void)
{
	unregister_filesystem(&ext3_fs_type);
}

static inline int ext3_feature_set_ok(struct super_block *sb)
{
	if (ext4_has_unknown_ext3_incompat_features(sb))
		return 0;
	if (!ext4_has_feature_journal(sb))
		return 0;
	if (sb_rdonly(sb))
		return 1;
	if (ext4_has_unknown_ext3_ro_compat_features(sb))
		return 0;
	return 1;
}

static struct file_system_type ext4_fs_type = {
	.owner		= THIS_MODULE, .name		= "ext4", .mount		= ext4_mount, .kill_sb	= kill_block_super, .fs_flags	= FS_REQUIRES_DEV, };




MODULE_ALIAS_FS("ext4");


wait_queue_head_t ext4__ioend_wq[EXT4_WQ_HASH_SZ];

static int __init ext4_init_fs(void)
{
	int i, err;

	ratelimit_state_init(&ext4_mount_msg_ratelimit, 30 * HZ, 64);
	ext4_li_info = NULL;
	mutex_init(&ext4_li_mtx);

	
	ext4_check_flag_values();

	for (i = 0; i < EXT4_WQ_HASH_SZ; i++)
		init_waitqueue_head(&ext4__ioend_wq[i]);

	err = ext4_init_es();
	if (err)
		return err;

	err = ext4_init_pageio();
	if (err)
		goto out5;

	err = ext4_init_system_zone();
	if (err)
		goto out4;

	err = ext4_init_sysfs();
	if (err)
		goto out3;

	err = ext4_init_mballoc();
	if (err)
		goto out2;
	err = init_inodecache();
	if (err)
		goto out1;
	register_as_ext3();
	register_as_ext2();
	err = register_filesystem(&ext4_fs_type);
	if (err)
		goto out;

	return 0;
out:
	unregister_as_ext2();
	unregister_as_ext3();
	destroy_inodecache();
out1:
	ext4_exit_mballoc();
out2:
	ext4_exit_sysfs();
out3:
	ext4_exit_system_zone();
out4:
	ext4_exit_pageio();
out5:
	ext4_exit_es();

	return err;
}

static void __exit ext4_exit_fs(void)
{
	ext4_destroy_lazyinit_thread();
	unregister_as_ext2();
	unregister_as_ext3();
	unregister_filesystem(&ext4_fs_type);
	destroy_inodecache();
	ext4_exit_mballoc();
	ext4_exit_sysfs();
	ext4_exit_system_zone();
	ext4_exit_pageio();
	ext4_exit_es();
}

MODULE_AUTHOR("Remy Card, Stephen Tweedie, Andrew Morton, Andreas Dilger, Theodore Ts'o and others");
MODULE_DESCRIPTION("Fourth Extended Filesystem");
MODULE_LICENSE("GPL");
MODULE_SOFTDEP("pre: crc32c");
module_init(ext4_init_fs)
module_exit(ext4_exit_fs)