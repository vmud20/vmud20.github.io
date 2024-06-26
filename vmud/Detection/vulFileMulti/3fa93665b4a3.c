



























void ext4_mark_bitmap_end(int start_bit, int end_bit, char *bitmap)
{
	int i;

	if (start_bit >= end_bit)
		return;

	ext4_debug("mark end bits +%d through +%d used\n", start_bit, end_bit);
	for (i = start_bit; i < ((start_bit + 7) & ~7UL); i++)
		ext4_set_bit(i, bitmap);
	if (i < end_bit)
		memset(bitmap + (i >> 3), 0xff, (end_bit - i) >> 3);
}

void ext4_end_bitmap_read(struct buffer_head *bh, int uptodate)
{
	if (uptodate) {
		set_buffer_uptodate(bh);
		set_bitmap_uptodate(bh);
	}
	unlock_buffer(bh);
	put_bh(bh);
}

static int ext4_validate_inode_bitmap(struct super_block *sb, struct ext4_group_desc *desc, ext4_group_t block_group, struct buffer_head *bh)


{
	ext4_fsblk_t	blk;
	struct ext4_group_info *grp = ext4_get_group_info(sb, block_group);
	struct ext4_sb_info *sbi = EXT4_SB(sb);

	if (buffer_verified(bh))
		return 0;
	if (EXT4_MB_GRP_IBITMAP_CORRUPT(grp))
		return -EFSCORRUPTED;

	ext4_lock_group(sb, block_group);
	blk = ext4_inode_bitmap(sb, desc);
	if (!ext4_inode_bitmap_csum_verify(sb, block_group, desc, bh, EXT4_INODES_PER_GROUP(sb) / 8)) {
		ext4_unlock_group(sb, block_group);
		ext4_error(sb, "Corrupt inode bitmap - block_group = %u, " "inode_bitmap = %llu", block_group, blk);
		grp = ext4_get_group_info(sb, block_group);
		if (!EXT4_MB_GRP_IBITMAP_CORRUPT(grp)) {
			int count;
			count = ext4_free_inodes_count(sb, desc);
			percpu_counter_sub(&sbi->s_freeinodes_counter, count);
		}
		set_bit(EXT4_GROUP_INFO_IBITMAP_CORRUPT_BIT, &grp->bb_state);
		return -EFSBADCRC;
	}
	set_buffer_verified(bh);
	ext4_unlock_group(sb, block_group);
	return 0;
}


static struct buffer_head * ext4_read_inode_bitmap(struct super_block *sb, ext4_group_t block_group)
{
	struct ext4_group_desc *desc;
	struct buffer_head *bh = NULL;
	ext4_fsblk_t bitmap_blk;
	int err;

	desc = ext4_get_group_desc(sb, block_group, NULL);
	if (!desc)
		return ERR_PTR(-EFSCORRUPTED);

	bitmap_blk = ext4_inode_bitmap(sb, desc);
	bh = sb_getblk(sb, bitmap_blk);
	if (unlikely(!bh)) {
		ext4_error(sb, "Cannot read inode bitmap - " "block_group = %u, inode_bitmap = %llu", block_group, bitmap_blk);

		return ERR_PTR(-EIO);
	}
	if (bitmap_uptodate(bh))
		goto verify;

	lock_buffer(bh);
	if (bitmap_uptodate(bh)) {
		unlock_buffer(bh);
		goto verify;
	}

	ext4_lock_group(sb, block_group);
	if (desc->bg_flags & cpu_to_le16(EXT4_BG_INODE_UNINIT)) {
		memset(bh->b_data, 0, (EXT4_INODES_PER_GROUP(sb) + 7) / 8);
		ext4_mark_bitmap_end(EXT4_INODES_PER_GROUP(sb), sb->s_blocksize * 8, bh->b_data);
		set_bitmap_uptodate(bh);
		set_buffer_uptodate(bh);
		set_buffer_verified(bh);
		ext4_unlock_group(sb, block_group);
		unlock_buffer(bh);
		return bh;
	}
	ext4_unlock_group(sb, block_group);

	if (buffer_uptodate(bh)) {
		
		set_bitmap_uptodate(bh);
		unlock_buffer(bh);
		goto verify;
	}
	
	trace_ext4_load_inode_bitmap(sb, block_group);
	bh->b_end_io = ext4_end_bitmap_read;
	get_bh(bh);
	submit_bh(REQ_OP_READ, REQ_META | REQ_PRIO, bh);
	wait_on_buffer(bh);
	if (!buffer_uptodate(bh)) {
		put_bh(bh);
		ext4_error(sb, "Cannot read inode bitmap - " "block_group = %u, inode_bitmap = %llu", block_group, bitmap_blk);

		return ERR_PTR(-EIO);
	}

verify:
	err = ext4_validate_inode_bitmap(sb, desc, block_group, bh);
	if (err)
		goto out;
	return bh;
out:
	put_bh(bh);
	return ERR_PTR(err);
}


void ext4_free_inode(handle_t *handle, struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	int is_directory;
	unsigned long ino;
	struct buffer_head *bitmap_bh = NULL;
	struct buffer_head *bh2;
	ext4_group_t block_group;
	unsigned long bit;
	struct ext4_group_desc *gdp;
	struct ext4_super_block *es;
	struct ext4_sb_info *sbi;
	int fatal = 0, err, count, cleared;
	struct ext4_group_info *grp;

	if (!sb) {
		printk(KERN_ERR "EXT4-fs: %s:%d: inode on " "nonexistent device\n", __func__, __LINE__);
		return;
	}
	if (atomic_read(&inode->i_count) > 1) {
		ext4_msg(sb, KERN_ERR, "%s:%d: inode #%lu: count=%d", __func__, __LINE__, inode->i_ino, atomic_read(&inode->i_count));

		return;
	}
	if (inode->i_nlink) {
		ext4_msg(sb, KERN_ERR, "%s:%d: inode #%lu: nlink=%d\n", __func__, __LINE__, inode->i_ino, inode->i_nlink);
		return;
	}
	sbi = EXT4_SB(sb);

	ino = inode->i_ino;
	ext4_debug("freeing inode %lu\n", ino);
	trace_ext4_free_inode(inode);

	
	dquot_initialize(inode);
	dquot_free_inode(inode);
	dquot_drop(inode);

	is_directory = S_ISDIR(inode->i_mode);

	
	ext4_clear_inode(inode);

	es = sbi->s_es;
	if (ino < EXT4_FIRST_INO(sb) || ino > le32_to_cpu(es->s_inodes_count)) {
		ext4_error(sb, "reserved or nonexistent inode %lu", ino);
		goto error_return;
	}
	block_group = (ino - 1) / EXT4_INODES_PER_GROUP(sb);
	bit = (ino - 1) % EXT4_INODES_PER_GROUP(sb);
	bitmap_bh = ext4_read_inode_bitmap(sb, block_group);
	
	grp = ext4_get_group_info(sb, block_group);
	if (IS_ERR(bitmap_bh)) {
		fatal = PTR_ERR(bitmap_bh);
		bitmap_bh = NULL;
		goto error_return;
	}
	if (unlikely(EXT4_MB_GRP_IBITMAP_CORRUPT(grp))) {
		fatal = -EFSCORRUPTED;
		goto error_return;
	}

	BUFFER_TRACE(bitmap_bh, "get_write_access");
	fatal = ext4_journal_get_write_access(handle, bitmap_bh);
	if (fatal)
		goto error_return;

	fatal = -ESRCH;
	gdp = ext4_get_group_desc(sb, block_group, &bh2);
	if (gdp) {
		BUFFER_TRACE(bh2, "get_write_access");
		fatal = ext4_journal_get_write_access(handle, bh2);
	}
	ext4_lock_group(sb, block_group);
	cleared = ext4_test_and_clear_bit(bit, bitmap_bh->b_data);
	if (fatal || !cleared) {
		ext4_unlock_group(sb, block_group);
		goto out;
	}

	count = ext4_free_inodes_count(sb, gdp) + 1;
	ext4_free_inodes_set(sb, gdp, count);
	if (is_directory) {
		count = ext4_used_dirs_count(sb, gdp) - 1;
		ext4_used_dirs_set(sb, gdp, count);
		percpu_counter_dec(&sbi->s_dirs_counter);
	}
	ext4_inode_bitmap_csum_set(sb, block_group, gdp, bitmap_bh, EXT4_INODES_PER_GROUP(sb) / 8);
	ext4_group_desc_csum_set(sb, block_group, gdp);
	ext4_unlock_group(sb, block_group);

	percpu_counter_inc(&sbi->s_freeinodes_counter);
	if (sbi->s_log_groups_per_flex) {
		ext4_group_t f = ext4_flex_group(sbi, block_group);

		atomic_inc(&sbi->s_flex_groups[f].free_inodes);
		if (is_directory)
			atomic_dec(&sbi->s_flex_groups[f].used_dirs);
	}
	BUFFER_TRACE(bh2, "call ext4_handle_dirty_metadata");
	fatal = ext4_handle_dirty_metadata(handle, NULL, bh2);
out:
	if (cleared) {
		BUFFER_TRACE(bitmap_bh, "call ext4_handle_dirty_metadata");
		err = ext4_handle_dirty_metadata(handle, NULL, bitmap_bh);
		if (!fatal)
			fatal = err;
	} else {
		ext4_error(sb, "bit already cleared for inode %lu", ino);
		if (gdp && !EXT4_MB_GRP_IBITMAP_CORRUPT(grp)) {
			int count;
			count = ext4_free_inodes_count(sb, gdp);
			percpu_counter_sub(&sbi->s_freeinodes_counter, count);
		}
		set_bit(EXT4_GROUP_INFO_IBITMAP_CORRUPT_BIT, &grp->bb_state);
	}

error_return:
	brelse(bitmap_bh);
	ext4_std_error(sb, fatal);
}

struct orlov_stats {
	__u64 free_clusters;
	__u32 free_inodes;
	__u32 used_dirs;
};


static void get_orlov_stats(struct super_block *sb, ext4_group_t g, int flex_size, struct orlov_stats *stats)
{
	struct ext4_group_desc *desc;
	struct flex_groups *flex_group = EXT4_SB(sb)->s_flex_groups;

	if (flex_size > 1) {
		stats->free_inodes = atomic_read(&flex_group[g].free_inodes);
		stats->free_clusters = atomic64_read(&flex_group[g].free_clusters);
		stats->used_dirs = atomic_read(&flex_group[g].used_dirs);
		return;
	}

	desc = ext4_get_group_desc(sb, g, NULL);
	if (desc) {
		stats->free_inodes = ext4_free_inodes_count(sb, desc);
		stats->free_clusters = ext4_free_group_clusters(sb, desc);
		stats->used_dirs = ext4_used_dirs_count(sb, desc);
	} else {
		stats->free_inodes = 0;
		stats->free_clusters = 0;
		stats->used_dirs = 0;
	}
}



static int find_group_orlov(struct super_block *sb, struct inode *parent, ext4_group_t *group, umode_t mode, const struct qstr *qstr)

{
	ext4_group_t parent_group = EXT4_I(parent)->i_block_group;
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	ext4_group_t real_ngroups = ext4_get_groups_count(sb);
	int inodes_per_group = EXT4_INODES_PER_GROUP(sb);
	unsigned int freei, avefreei, grp_free;
	ext4_fsblk_t freeb, avefreec;
	unsigned int ndirs;
	int max_dirs, min_inodes;
	ext4_grpblk_t min_clusters;
	ext4_group_t i, grp, g, ngroups;
	struct ext4_group_desc *desc;
	struct orlov_stats stats;
	int flex_size = ext4_flex_bg_size(sbi);
	struct dx_hash_info hinfo;

	ngroups = real_ngroups;
	if (flex_size > 1) {
		ngroups = (real_ngroups + flex_size - 1) >> sbi->s_log_groups_per_flex;
		parent_group >>= sbi->s_log_groups_per_flex;
	}

	freei = percpu_counter_read_positive(&sbi->s_freeinodes_counter);
	avefreei = freei / ngroups;
	freeb = EXT4_C2B(sbi, percpu_counter_read_positive(&sbi->s_freeclusters_counter));
	avefreec = freeb;
	do_div(avefreec, ngroups);
	ndirs = percpu_counter_read_positive(&sbi->s_dirs_counter);

	if (S_ISDIR(mode) && ((parent == d_inode(sb->s_root)) || (ext4_test_inode_flag(parent, EXT4_INODE_TOPDIR)))) {

		int best_ndir = inodes_per_group;
		int ret = -1;

		if (qstr) {
			hinfo.hash_version = DX_HASH_HALF_MD4;
			hinfo.seed = sbi->s_hash_seed;
			ext4fs_dirhash(qstr->name, qstr->len, &hinfo);
			grp = hinfo.hash;
		} else grp = prandom_u32();
		parent_group = (unsigned)grp % ngroups;
		for (i = 0; i < ngroups; i++) {
			g = (parent_group + i) % ngroups;
			get_orlov_stats(sb, g, flex_size, &stats);
			if (!stats.free_inodes)
				continue;
			if (stats.used_dirs >= best_ndir)
				continue;
			if (stats.free_inodes < avefreei)
				continue;
			if (stats.free_clusters < avefreec)
				continue;
			grp = g;
			ret = 0;
			best_ndir = stats.used_dirs;
		}
		if (ret)
			goto fallback;
	found_flex_bg:
		if (flex_size == 1) {
			*group = grp;
			return 0;
		}

		
		grp *= flex_size;
		for (i = 0; i < flex_size; i++) {
			if (grp+i >= real_ngroups)
				break;
			desc = ext4_get_group_desc(sb, grp+i, NULL);
			if (desc && ext4_free_inodes_count(sb, desc)) {
				*group = grp+i;
				return 0;
			}
		}
		goto fallback;
	}

	max_dirs = ndirs / ngroups + inodes_per_group / 16;
	min_inodes = avefreei - inodes_per_group*flex_size / 4;
	if (min_inodes < 1)
		min_inodes = 1;
	min_clusters = avefreec - EXT4_CLUSTERS_PER_GROUP(sb)*flex_size / 4;

	
	if (EXT4_I(parent)->i_last_alloc_group != ~0) {
		parent_group = EXT4_I(parent)->i_last_alloc_group;
		if (flex_size > 1)
			parent_group >>= sbi->s_log_groups_per_flex;
	}

	for (i = 0; i < ngroups; i++) {
		grp = (parent_group + i) % ngroups;
		get_orlov_stats(sb, grp, flex_size, &stats);
		if (stats.used_dirs >= max_dirs)
			continue;
		if (stats.free_inodes < min_inodes)
			continue;
		if (stats.free_clusters < min_clusters)
			continue;
		goto found_flex_bg;
	}

fallback:
	ngroups = real_ngroups;
	avefreei = freei / ngroups;
fallback_retry:
	parent_group = EXT4_I(parent)->i_block_group;
	for (i = 0; i < ngroups; i++) {
		grp = (parent_group + i) % ngroups;
		desc = ext4_get_group_desc(sb, grp, NULL);
		if (desc) {
			grp_free = ext4_free_inodes_count(sb, desc);
			if (grp_free && grp_free >= avefreei) {
				*group = grp;
				return 0;
			}
		}
	}

	if (avefreei) {
		
		avefreei = 0;
		goto fallback_retry;
	}

	return -1;
}

static int find_group_other(struct super_block *sb, struct inode *parent, ext4_group_t *group, umode_t mode)
{
	ext4_group_t parent_group = EXT4_I(parent)->i_block_group;
	ext4_group_t i, last, ngroups = ext4_get_groups_count(sb);
	struct ext4_group_desc *desc;
	int flex_size = ext4_flex_bg_size(EXT4_SB(sb));

	
	if (flex_size > 1) {
		int retry = 0;

	try_again:
		parent_group &= ~(flex_size-1);
		last = parent_group + flex_size;
		if (last > ngroups)
			last = ngroups;
		for  (i = parent_group; i < last; i++) {
			desc = ext4_get_group_desc(sb, i, NULL);
			if (desc && ext4_free_inodes_count(sb, desc)) {
				*group = i;
				return 0;
			}
		}
		if (!retry && EXT4_I(parent)->i_last_alloc_group != ~0) {
			retry = 1;
			parent_group = EXT4_I(parent)->i_last_alloc_group;
			goto try_again;
		}
		
		*group = parent_group + flex_size;
		if (*group > ngroups)
			*group = 0;
		return find_group_orlov(sb, parent, group, mode, NULL);
	}

	
	*group = parent_group;
	desc = ext4_get_group_desc(sb, *group, NULL);
	if (desc && ext4_free_inodes_count(sb, desc) && ext4_free_group_clusters(sb, desc))
		return 0;

	
	*group = (*group + parent->i_ino) % ngroups;

	
	for (i = 1; i < ngroups; i <<= 1) {
		*group += i;
		if (*group >= ngroups)
			*group -= ngroups;
		desc = ext4_get_group_desc(sb, *group, NULL);
		if (desc && ext4_free_inodes_count(sb, desc) && ext4_free_group_clusters(sb, desc))
			return 0;
	}

	
	*group = parent_group;
	for (i = 0; i < ngroups; i++) {
		if (++*group >= ngroups)
			*group = 0;
		desc = ext4_get_group_desc(sb, *group, NULL);
		if (desc && ext4_free_inodes_count(sb, desc))
			return 0;
	}

	return -1;
}





static int recently_deleted(struct super_block *sb, ext4_group_t group, int ino)
{
	struct ext4_group_desc	*gdp;
	struct ext4_inode	*raw_inode;
	struct buffer_head	*bh;
	int inodes_per_block = EXT4_SB(sb)->s_inodes_per_block;
	int offset, ret = 0;
	int recentcy = RECENTCY_MIN;
	u32 dtime, now;

	gdp = ext4_get_group_desc(sb, group, NULL);
	if (unlikely(!gdp))
		return 0;

	bh = sb_find_get_block(sb, ext4_inode_table(sb, gdp) + (ino / inodes_per_block));
	if (!bh || !buffer_uptodate(bh))
		
		goto out;

	offset = (ino % inodes_per_block) * EXT4_INODE_SIZE(sb);
	raw_inode = (struct ext4_inode *) (bh->b_data + offset);

	
	dtime = le32_to_cpu(raw_inode->i_dtime);
	now = ktime_get_real_seconds();
	if (buffer_dirty(bh))
		recentcy += RECENTCY_DIRTY;

	if (dtime && time_before32(dtime, now) && time_before32(now, dtime + recentcy))
		ret = 1;
out:
	brelse(bh);
	return ret;
}

static int find_inode_bit(struct super_block *sb, ext4_group_t group, struct buffer_head *bitmap, unsigned long *ino)
{
next:
	*ino = ext4_find_next_zero_bit((unsigned long *)
				       bitmap->b_data, EXT4_INODES_PER_GROUP(sb), *ino);
	if (*ino >= EXT4_INODES_PER_GROUP(sb))
		return 0;

	if ((EXT4_SB(sb)->s_journal == NULL) && recently_deleted(sb, group, *ino)) {
		*ino = *ino + 1;
		if (*ino < EXT4_INODES_PER_GROUP(sb))
			goto next;
		return 0;
	}

	return 1;
}


struct inode *__ext4_new_inode(handle_t *handle, struct inode *dir, umode_t mode, const struct qstr *qstr, __u32 goal, uid_t *owner, __u32 i_flags, int handle_type, unsigned int line_no, int nblocks)



{
	struct super_block *sb;
	struct buffer_head *inode_bitmap_bh = NULL;
	struct buffer_head *group_desc_bh;
	ext4_group_t ngroups, group = 0;
	unsigned long ino = 0;
	struct inode *inode;
	struct ext4_group_desc *gdp = NULL;
	struct ext4_inode_info *ei;
	struct ext4_sb_info *sbi;
	int ret2, err;
	struct inode *ret;
	ext4_group_t i;
	ext4_group_t flex_group;
	struct ext4_group_info *grp;
	int encrypt = 0;

	
	if (!dir || !dir->i_nlink)
		return ERR_PTR(-EPERM);

	sb = dir->i_sb;
	sbi = EXT4_SB(sb);

	if (unlikely(ext4_forced_shutdown(sbi)))
		return ERR_PTR(-EIO);

	if ((ext4_encrypted_inode(dir) || DUMMY_ENCRYPTION_ENABLED(sbi)) && (S_ISREG(mode) || S_ISDIR(mode) || S_ISLNK(mode)) && !(i_flags & EXT4_EA_INODE_FL)) {

		err = fscrypt_get_encryption_info(dir);
		if (err)
			return ERR_PTR(err);
		if (!fscrypt_has_encryption_key(dir))
			return ERR_PTR(-ENOKEY);
		encrypt = 1;
	}

	if (!handle && sbi->s_journal && !(i_flags & EXT4_EA_INODE_FL)) {

		struct posix_acl *p = get_acl(dir, ACL_TYPE_DEFAULT);

		if (IS_ERR(p))
			return ERR_CAST(p);
		if (p) {
			int acl_size = p->a_count * sizeof(ext4_acl_entry);

			nblocks += (S_ISDIR(mode) ? 2 : 1) * __ext4_xattr_set_credits(sb, NULL , NULL , acl_size, true );


			posix_acl_release(p);
		}



		{
			int num_security_xattrs = 1;


			num_security_xattrs++;

			
			nblocks += num_security_xattrs * __ext4_xattr_set_credits(sb, NULL , NULL , 1024, true );


		}

		if (encrypt)
			nblocks += __ext4_xattr_set_credits(sb, NULL , NULL , FSCRYPT_SET_CONTEXT_MAX_SIZE, true );


	}

	ngroups = ext4_get_groups_count(sb);
	trace_ext4_request_inode(dir, mode);
	inode = new_inode(sb);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	ei = EXT4_I(inode);

	
	if (owner) {
		inode->i_mode = mode;
		i_uid_write(inode, owner[0]);
		i_gid_write(inode, owner[1]);
	} else if (test_opt(sb, GRPID)) {
		inode->i_mode = mode;
		inode->i_uid = current_fsuid();
		inode->i_gid = dir->i_gid;
	} else inode_init_owner(inode, dir, mode);

	if (ext4_has_feature_project(sb) && ext4_test_inode_flag(dir, EXT4_INODE_PROJINHERIT))
		ei->i_projid = EXT4_I(dir)->i_projid;
	else ei->i_projid = make_kprojid(&init_user_ns, EXT4_DEF_PROJID);

	err = dquot_initialize(inode);
	if (err)
		goto out;

	if (!goal)
		goal = sbi->s_inode_goal;

	if (goal && goal <= le32_to_cpu(sbi->s_es->s_inodes_count)) {
		group = (goal - 1) / EXT4_INODES_PER_GROUP(sb);
		ino = (goal - 1) % EXT4_INODES_PER_GROUP(sb);
		ret2 = 0;
		goto got_group;
	}

	if (S_ISDIR(mode))
		ret2 = find_group_orlov(sb, dir, &group, mode, qstr);
	else ret2 = find_group_other(sb, dir, &group, mode);

got_group:
	EXT4_I(dir)->i_last_alloc_group = group;
	err = -ENOSPC;
	if (ret2 == -1)
		goto out;

	
	for (i = 0; i < ngroups; i++, ino = 0) {
		err = -EIO;

		gdp = ext4_get_group_desc(sb, group, &group_desc_bh);
		if (!gdp)
			goto out;

		
		if (ext4_free_inodes_count(sb, gdp) == 0)
			goto next_group;

		grp = ext4_get_group_info(sb, group);
		
		if (EXT4_MB_GRP_IBITMAP_CORRUPT(grp))
			goto next_group;

		brelse(inode_bitmap_bh);
		inode_bitmap_bh = ext4_read_inode_bitmap(sb, group);
		
		if (EXT4_MB_GRP_IBITMAP_CORRUPT(grp) || IS_ERR(inode_bitmap_bh)) {
			inode_bitmap_bh = NULL;
			goto next_group;
		}

repeat_in_this_group:
		ret2 = find_inode_bit(sb, group, inode_bitmap_bh, &ino);
		if (!ret2)
			goto next_group;

		if (group == 0 && (ino + 1) < EXT4_FIRST_INO(sb)) {
			ext4_error(sb, "reserved inode found cleared - " "inode=%lu", ino + 1);
			goto next_group;
		}

		if (!handle) {
			BUG_ON(nblocks <= 0);
			handle = __ext4_journal_start_sb(dir->i_sb, line_no, handle_type, nblocks, 0);

			if (IS_ERR(handle)) {
				err = PTR_ERR(handle);
				ext4_std_error(sb, err);
				goto out;
			}
		}
		BUFFER_TRACE(inode_bitmap_bh, "get_write_access");
		err = ext4_journal_get_write_access(handle, inode_bitmap_bh);
		if (err) {
			ext4_std_error(sb, err);
			goto out;
		}
		ext4_lock_group(sb, group);
		ret2 = ext4_test_and_set_bit(ino, inode_bitmap_bh->b_data);
		if (ret2) {
			
			ret2 = find_inode_bit(sb, group, inode_bitmap_bh, &ino);
			if (ret2) {
				ext4_set_bit(ino, inode_bitmap_bh->b_data);
				ret2 = 0;
			} else {
				ret2 = 1; 
			}
		}
		ext4_unlock_group(sb, group);
		ino++;		
		if (!ret2)
			goto got; 

		if (ino < EXT4_INODES_PER_GROUP(sb))
			goto repeat_in_this_group;
next_group:
		if (++group == ngroups)
			group = 0;
	}
	err = -ENOSPC;
	goto out;

got:
	BUFFER_TRACE(inode_bitmap_bh, "call ext4_handle_dirty_metadata");
	err = ext4_handle_dirty_metadata(handle, NULL, inode_bitmap_bh);
	if (err) {
		ext4_std_error(sb, err);
		goto out;
	}

	BUFFER_TRACE(group_desc_bh, "get_write_access");
	err = ext4_journal_get_write_access(handle, group_desc_bh);
	if (err) {
		ext4_std_error(sb, err);
		goto out;
	}

	
	if (ext4_has_group_desc_csum(sb) && gdp->bg_flags & cpu_to_le16(EXT4_BG_BLOCK_UNINIT)) {
		struct buffer_head *block_bitmap_bh;

		block_bitmap_bh = ext4_read_block_bitmap(sb, group);
		if (IS_ERR(block_bitmap_bh)) {
			err = PTR_ERR(block_bitmap_bh);
			goto out;
		}
		BUFFER_TRACE(block_bitmap_bh, "get block bitmap access");
		err = ext4_journal_get_write_access(handle, block_bitmap_bh);
		if (err) {
			brelse(block_bitmap_bh);
			ext4_std_error(sb, err);
			goto out;
		}

		BUFFER_TRACE(block_bitmap_bh, "dirty block bitmap");
		err = ext4_handle_dirty_metadata(handle, NULL, block_bitmap_bh);

		
		ext4_lock_group(sb, group);
		if (gdp->bg_flags & cpu_to_le16(EXT4_BG_BLOCK_UNINIT)) {
			gdp->bg_flags &= cpu_to_le16(~EXT4_BG_BLOCK_UNINIT);
			ext4_free_group_clusters_set(sb, gdp, ext4_free_clusters_after_init(sb, group, gdp));
			ext4_block_bitmap_csum_set(sb, group, gdp, block_bitmap_bh);
			ext4_group_desc_csum_set(sb, group, gdp);
		}
		ext4_unlock_group(sb, group);
		brelse(block_bitmap_bh);

		if (err) {
			ext4_std_error(sb, err);
			goto out;
		}
	}

	
	if (ext4_has_group_desc_csum(sb)) {
		int free;
		struct ext4_group_info *grp = ext4_get_group_info(sb, group);

		down_read(&grp->alloc_sem); 
		ext4_lock_group(sb, group); 
		free = EXT4_INODES_PER_GROUP(sb) - ext4_itable_unused_count(sb, gdp);
		if (gdp->bg_flags & cpu_to_le16(EXT4_BG_INODE_UNINIT)) {
			gdp->bg_flags &= cpu_to_le16(~EXT4_BG_INODE_UNINIT);
			free = 0;
		}
		
		if (ino > free)
			ext4_itable_unused_set(sb, gdp, (EXT4_INODES_PER_GROUP(sb) - ino));
		up_read(&grp->alloc_sem);
	} else {
		ext4_lock_group(sb, group);
	}

	ext4_free_inodes_set(sb, gdp, ext4_free_inodes_count(sb, gdp) - 1);
	if (S_ISDIR(mode)) {
		ext4_used_dirs_set(sb, gdp, ext4_used_dirs_count(sb, gdp) + 1);
		if (sbi->s_log_groups_per_flex) {
			ext4_group_t f = ext4_flex_group(sbi, group);

			atomic_inc(&sbi->s_flex_groups[f].used_dirs);
		}
	}
	if (ext4_has_group_desc_csum(sb)) {
		ext4_inode_bitmap_csum_set(sb, group, gdp, inode_bitmap_bh, EXT4_INODES_PER_GROUP(sb) / 8);
		ext4_group_desc_csum_set(sb, group, gdp);
	}
	ext4_unlock_group(sb, group);

	BUFFER_TRACE(group_desc_bh, "call ext4_handle_dirty_metadata");
	err = ext4_handle_dirty_metadata(handle, NULL, group_desc_bh);
	if (err) {
		ext4_std_error(sb, err);
		goto out;
	}

	percpu_counter_dec(&sbi->s_freeinodes_counter);
	if (S_ISDIR(mode))
		percpu_counter_inc(&sbi->s_dirs_counter);

	if (sbi->s_log_groups_per_flex) {
		flex_group = ext4_flex_group(sbi, group);
		atomic_dec(&sbi->s_flex_groups[flex_group].free_inodes);
	}

	inode->i_ino = ino + group * EXT4_INODES_PER_GROUP(sb);
	
	inode->i_blocks = 0;
	inode->i_mtime = inode->i_atime = inode->i_ctime = ei->i_crtime = current_time(inode);

	memset(ei->i_data, 0, sizeof(ei->i_data));
	ei->i_dir_start_lookup = 0;
	ei->i_disksize = 0;

	
	ei->i_flags = ext4_mask_flags(mode, EXT4_I(dir)->i_flags & EXT4_FL_INHERITED);
	ei->i_flags |= i_flags;
	ei->i_file_acl = 0;
	ei->i_dtime = 0;
	ei->i_block_group = group;
	ei->i_last_alloc_group = ~0;

	ext4_set_inode_flags(inode);
	if (IS_DIRSYNC(inode))
		ext4_handle_sync(handle);
	if (insert_inode_locked(inode) < 0) {
		
		err = -EIO;
		ext4_error(sb, "failed to insert inode %lu: doubly allocated?", inode->i_ino);
		goto out;
	}
	inode->i_generation = prandom_u32();

	
	if (ext4_has_metadata_csum(sb)) {
		__u32 csum;
		__le32 inum = cpu_to_le32(inode->i_ino);
		__le32 gen = cpu_to_le32(inode->i_generation);
		csum = ext4_chksum(sbi, sbi->s_csum_seed, (__u8 *)&inum, sizeof(inum));
		ei->i_csum_seed = ext4_chksum(sbi, csum, (__u8 *)&gen, sizeof(gen));
	}

	ext4_clear_state_flags(ei); 
	ext4_set_inode_state(inode, EXT4_STATE_NEW);

	ei->i_extra_isize = sbi->s_want_extra_isize;
	ei->i_inline_off = 0;
	if (ext4_has_feature_inline_data(sb))
		ext4_set_inode_state(inode, EXT4_STATE_MAY_INLINE_DATA);
	ret = inode;
	err = dquot_alloc_inode(inode);
	if (err)
		goto fail_drop;

	
	if (encrypt) {
		err = fscrypt_inherit_context(dir, inode, handle, true);
		if (err)
			goto fail_free_drop;
	}

	if (!(ei->i_flags & EXT4_EA_INODE_FL)) {
		err = ext4_init_acl(handle, inode, dir);
		if (err)
			goto fail_free_drop;

		err = ext4_init_security(handle, inode, dir, qstr);
		if (err)
			goto fail_free_drop;
	}

	if (ext4_has_feature_extents(sb)) {
		
		if (S_ISDIR(mode) || S_ISREG(mode) || S_ISLNK(mode)) {
			ext4_set_inode_flag(inode, EXT4_INODE_EXTENTS);
			ext4_ext_tree_init(handle, inode);
		}
	}

	if (ext4_handle_valid(handle)) {
		ei->i_sync_tid = handle->h_transaction->t_tid;
		ei->i_datasync_tid = handle->h_transaction->t_tid;
	}

	err = ext4_mark_inode_dirty(handle, inode);
	if (err) {
		ext4_std_error(sb, err);
		goto fail_free_drop;
	}

	ext4_debug("allocating inode %lu\n", inode->i_ino);
	trace_ext4_allocate_inode(inode, dir, mode);
	brelse(inode_bitmap_bh);
	return ret;

fail_free_drop:
	dquot_free_inode(inode);
fail_drop:
	clear_nlink(inode);
	unlock_new_inode(inode);
out:
	dquot_drop(inode);
	inode->i_flags |= S_NOQUOTA;
	iput(inode);
	brelse(inode_bitmap_bh);
	return ERR_PTR(err);
}


struct inode *ext4_orphan_get(struct super_block *sb, unsigned long ino)
{
	unsigned long max_ino = le32_to_cpu(EXT4_SB(sb)->s_es->s_inodes_count);
	ext4_group_t block_group;
	int bit;
	struct buffer_head *bitmap_bh = NULL;
	struct inode *inode = NULL;
	int err = -EFSCORRUPTED;

	if (ino < EXT4_FIRST_INO(sb) || ino > max_ino)
		goto bad_orphan;

	block_group = (ino - 1) / EXT4_INODES_PER_GROUP(sb);
	bit = (ino - 1) % EXT4_INODES_PER_GROUP(sb);
	bitmap_bh = ext4_read_inode_bitmap(sb, block_group);
	if (IS_ERR(bitmap_bh)) {
		ext4_error(sb, "inode bitmap error %ld for orphan %lu", ino, PTR_ERR(bitmap_bh));
		return (struct inode *) bitmap_bh;
	}

	
	if (!ext4_test_bit(bit, bitmap_bh->b_data))
		goto bad_orphan;

	inode = ext4_iget(sb, ino);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		ext4_error(sb, "couldn't read orphan inode %lu (err %d)", ino, err);
		return inode;
	}

	
	if ((inode->i_nlink && !ext4_can_truncate(inode)) || is_bad_inode(inode))
		goto bad_orphan;

	if (NEXT_ORPHAN(inode) > max_ino)
		goto bad_orphan;
	brelse(bitmap_bh);
	return inode;

bad_orphan:
	ext4_error(sb, "bad orphan inode %lu", ino);
	if (bitmap_bh)
		printk(KERN_ERR "ext4_test_bit(bit=%d, block=%llu) = %d\n", bit, (unsigned long long)bitmap_bh->b_blocknr, ext4_test_bit(bit, bitmap_bh->b_data));

	if (inode) {
		printk(KERN_ERR "is_bad_inode(inode)=%d\n", is_bad_inode(inode));
		printk(KERN_ERR "NEXT_ORPHAN(inode)=%u\n", NEXT_ORPHAN(inode));
		printk(KERN_ERR "max_ino=%lu\n", max_ino);
		printk(KERN_ERR "i_nlink=%u\n", inode->i_nlink);
		
		if (inode->i_nlink == 0)
			inode->i_blocks = 0;
		iput(inode);
	}
	brelse(bitmap_bh);
	return ERR_PTR(err);
}

unsigned long ext4_count_free_inodes(struct super_block *sb)
{
	unsigned long desc_count;
	struct ext4_group_desc *gdp;
	ext4_group_t i, ngroups = ext4_get_groups_count(sb);

	struct ext4_super_block *es;
	unsigned long bitmap_count, x;
	struct buffer_head *bitmap_bh = NULL;

	es = EXT4_SB(sb)->s_es;
	desc_count = 0;
	bitmap_count = 0;
	gdp = NULL;
	for (i = 0; i < ngroups; i++) {
		gdp = ext4_get_group_desc(sb, i, NULL);
		if (!gdp)
			continue;
		desc_count += ext4_free_inodes_count(sb, gdp);
		brelse(bitmap_bh);
		bitmap_bh = ext4_read_inode_bitmap(sb, i);
		if (IS_ERR(bitmap_bh)) {
			bitmap_bh = NULL;
			continue;
		}

		x = ext4_count_free(bitmap_bh->b_data, EXT4_INODES_PER_GROUP(sb) / 8);
		printk(KERN_DEBUG "group %lu: stored = %d, counted = %lu\n", (unsigned long) i, ext4_free_inodes_count(sb, gdp), x);
		bitmap_count += x;
	}
	brelse(bitmap_bh);
	printk(KERN_DEBUG "ext4_count_free_inodes: " "stored = %u, computed = %lu, %lu\n", le32_to_cpu(es->s_free_inodes_count), desc_count, bitmap_count);

	return desc_count;

	desc_count = 0;
	for (i = 0; i < ngroups; i++) {
		gdp = ext4_get_group_desc(sb, i, NULL);
		if (!gdp)
			continue;
		desc_count += ext4_free_inodes_count(sb, gdp);
		cond_resched();
	}
	return desc_count;

}


unsigned long ext4_count_dirs(struct super_block * sb)
{
	unsigned long count = 0;
	ext4_group_t i, ngroups = ext4_get_groups_count(sb);

	for (i = 0; i < ngroups; i++) {
		struct ext4_group_desc *gdp = ext4_get_group_desc(sb, i, NULL);
		if (!gdp)
			continue;
		count += ext4_used_dirs_count(sb, gdp);
	}
	return count;
}


int ext4_init_inode_table(struct super_block *sb, ext4_group_t group, int barrier)
{
	struct ext4_group_info *grp = ext4_get_group_info(sb, group);
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	struct ext4_group_desc *gdp = NULL;
	struct buffer_head *group_desc_bh;
	handle_t *handle;
	ext4_fsblk_t blk;
	int num, ret = 0, used_blks = 0;

	
	if (sb_rdonly(sb)) {
		ret = 1;
		goto out;
	}

	gdp = ext4_get_group_desc(sb, group, &group_desc_bh);
	if (!gdp)
		goto out;

	
	if (gdp->bg_flags & cpu_to_le16(EXT4_BG_INODE_ZEROED))
		goto out;

	handle = ext4_journal_start_sb(sb, EXT4_HT_MISC, 1);
	if (IS_ERR(handle)) {
		ret = PTR_ERR(handle);
		goto out;
	}

	down_write(&grp->alloc_sem);
	
	if (!(gdp->bg_flags & cpu_to_le16(EXT4_BG_INODE_UNINIT)))
		used_blks = DIV_ROUND_UP((EXT4_INODES_PER_GROUP(sb) - ext4_itable_unused_count(sb, gdp)), sbi->s_inodes_per_block);


	if ((used_blks < 0) || (used_blks > sbi->s_itb_per_group)) {
		ext4_error(sb, "Something is wrong with group %u: " "used itable blocks: %d; " "itable unused count: %u", group, used_blks, ext4_itable_unused_count(sb, gdp));



		ret = 1;
		goto err_out;
	}

	blk = ext4_inode_table(sb, gdp) + used_blks;
	num = sbi->s_itb_per_group - used_blks;

	BUFFER_TRACE(group_desc_bh, "get_write_access");
	ret = ext4_journal_get_write_access(handle, group_desc_bh);
	if (ret)
		goto err_out;

	
	if (unlikely(num == 0))
		goto skip_zeroout;

	ext4_debug("going to zero out inode table in group %d\n", group);
	ret = sb_issue_zeroout(sb, blk, num, GFP_NOFS);
	if (ret < 0)
		goto err_out;
	if (barrier)
		blkdev_issue_flush(sb->s_bdev, GFP_NOFS, NULL);

skip_zeroout:
	ext4_lock_group(sb, group);
	gdp->bg_flags |= cpu_to_le16(EXT4_BG_INODE_ZEROED);
	ext4_group_desc_csum_set(sb, group, gdp);
	ext4_unlock_group(sb, group);

	BUFFER_TRACE(group_desc_bh, "call ext4_handle_dirty_metadata");
	ret = ext4_handle_dirty_metadata(handle, NULL, group_desc_bh);

err_out:
	up_write(&grp->alloc_sem);
	ext4_journal_stop(handle);
out:
	return ret;
}
