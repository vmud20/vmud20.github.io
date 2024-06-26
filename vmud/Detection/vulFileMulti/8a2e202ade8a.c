













static unsigned ext4_num_base_meta_clusters(struct super_block *sb, ext4_group_t block_group);



ext4_group_t ext4_get_group_number(struct super_block *sb, ext4_fsblk_t block)
{
	ext4_group_t group;

	if (test_opt2(sb, STD_GROUP_SIZE))
		group = (block - le32_to_cpu(EXT4_SB(sb)->s_es->s_first_data_block)) >> (EXT4_BLOCK_SIZE_BITS(sb) + EXT4_CLUSTER_BITS(sb) + 3);

	else ext4_get_group_no_and_offset(sb, block, &group, NULL);
	return group;
}


void ext4_get_group_no_and_offset(struct super_block *sb, ext4_fsblk_t blocknr, ext4_group_t *blockgrpp, ext4_grpblk_t *offsetp)
{
	struct ext4_super_block *es = EXT4_SB(sb)->s_es;
	ext4_grpblk_t offset;

	blocknr = blocknr - le32_to_cpu(es->s_first_data_block);
	offset = do_div(blocknr, EXT4_BLOCKS_PER_GROUP(sb)) >> EXT4_SB(sb)->s_cluster_bits;
	if (offsetp)
		*offsetp = offset;
	if (blockgrpp)
		*blockgrpp = blocknr;

}


static inline int ext4_block_in_group(struct super_block *sb, ext4_fsblk_t block, ext4_group_t block_group)

{
	ext4_group_t actual_group;

	actual_group = ext4_get_group_number(sb, block);
	return (actual_group == block_group) ? 1 : 0;
}


static unsigned ext4_num_overhead_clusters(struct super_block *sb, ext4_group_t block_group, struct ext4_group_desc *gdp)

{
	unsigned num_clusters;
	int block_cluster = -1, inode_cluster = -1, itbl_cluster = -1, i, c;
	ext4_fsblk_t start = ext4_group_first_block_no(sb, block_group);
	ext4_fsblk_t itbl_blk;
	struct ext4_sb_info *sbi = EXT4_SB(sb);

	
	num_clusters = ext4_num_base_meta_clusters(sb, block_group);

	
	if (ext4_block_in_group(sb, ext4_block_bitmap(sb, gdp), block_group)) {
		block_cluster = EXT4_B2C(sbi, ext4_block_bitmap(sb, gdp) - start);
		if (block_cluster < num_clusters)
			block_cluster = -1;
		else if (block_cluster == num_clusters) {
			num_clusters++;
			block_cluster = -1;
		}
	}

	if (ext4_block_in_group(sb, ext4_inode_bitmap(sb, gdp), block_group)) {
		inode_cluster = EXT4_B2C(sbi, ext4_inode_bitmap(sb, gdp) - start);
		if (inode_cluster < num_clusters)
			inode_cluster = -1;
		else if (inode_cluster == num_clusters) {
			num_clusters++;
			inode_cluster = -1;
		}
	}

	itbl_blk = ext4_inode_table(sb, gdp);
	for (i = 0; i < sbi->s_itb_per_group; i++) {
		if (ext4_block_in_group(sb, itbl_blk + i, block_group)) {
			c = EXT4_B2C(sbi, itbl_blk + i - start);
			if ((c < num_clusters) || (c == inode_cluster) || (c == block_cluster) || (c == itbl_cluster))
				continue;
			if (c == num_clusters) {
				num_clusters++;
				continue;
			}
			num_clusters++;
			itbl_cluster = c;
		}
	}

	if (block_cluster != -1)
		num_clusters++;
	if (inode_cluster != -1)
		num_clusters++;

	return num_clusters;
}

static unsigned int num_clusters_in_group(struct super_block *sb, ext4_group_t block_group)
{
	unsigned int blocks;

	if (block_group == ext4_get_groups_count(sb) - 1) {
		
		blocks = ext4_blocks_count(EXT4_SB(sb)->s_es) - ext4_group_first_block_no(sb, block_group);
	} else blocks = EXT4_BLOCKS_PER_GROUP(sb);
	return EXT4_NUM_B2C(EXT4_SB(sb), blocks);
}


static int ext4_init_block_bitmap(struct super_block *sb, struct buffer_head *bh, ext4_group_t block_group, struct ext4_group_desc *gdp)


{
	unsigned int bit, bit_max;
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	ext4_fsblk_t start, tmp;

	J_ASSERT_BH(bh, buffer_locked(bh));

	
	if (!ext4_group_desc_csum_verify(sb, block_group, gdp)) {
		ext4_mark_group_bitmap_corrupted(sb, block_group, EXT4_GROUP_INFO_BBITMAP_CORRUPT | EXT4_GROUP_INFO_IBITMAP_CORRUPT);

		return -EFSBADCRC;
	}
	memset(bh->b_data, 0, sb->s_blocksize);

	bit_max = ext4_num_base_meta_clusters(sb, block_group);
	if ((bit_max >> 3) >= bh->b_size)
		return -EFSCORRUPTED;

	for (bit = 0; bit < bit_max; bit++)
		ext4_set_bit(bit, bh->b_data);

	start = ext4_group_first_block_no(sb, block_group);

	
	tmp = ext4_block_bitmap(sb, gdp);
	if (ext4_block_in_group(sb, tmp, block_group))
		ext4_set_bit(EXT4_B2C(sbi, tmp - start), bh->b_data);

	tmp = ext4_inode_bitmap(sb, gdp);
	if (ext4_block_in_group(sb, tmp, block_group))
		ext4_set_bit(EXT4_B2C(sbi, tmp - start), bh->b_data);

	tmp = ext4_inode_table(sb, gdp);
	for (; tmp < ext4_inode_table(sb, gdp) + sbi->s_itb_per_group; tmp++) {
		if (ext4_block_in_group(sb, tmp, block_group))
			ext4_set_bit(EXT4_B2C(sbi, tmp - start), bh->b_data);
	}

	
	ext4_mark_bitmap_end(num_clusters_in_group(sb, block_group), sb->s_blocksize * 8, bh->b_data);
	return 0;
}


unsigned ext4_free_clusters_after_init(struct super_block *sb, ext4_group_t block_group, struct ext4_group_desc *gdp)

{
	return num_clusters_in_group(sb, block_group) -  ext4_num_overhead_clusters(sb, block_group, gdp);
}




struct ext4_group_desc * ext4_get_group_desc(struct super_block *sb, ext4_group_t block_group, struct buffer_head **bh)

{
	unsigned int group_desc;
	unsigned int offset;
	ext4_group_t ngroups = ext4_get_groups_count(sb);
	struct ext4_group_desc *desc;
	struct ext4_sb_info *sbi = EXT4_SB(sb);

	if (block_group >= ngroups) {
		ext4_error(sb, "block_group >= groups_count - block_group = %u," " groups_count = %u", block_group, ngroups);

		return NULL;
	}

	group_desc = block_group >> EXT4_DESC_PER_BLOCK_BITS(sb);
	offset = block_group & (EXT4_DESC_PER_BLOCK(sb) - 1);
	if (!sbi->s_group_desc[group_desc]) {
		ext4_error(sb, "Group descriptor not loaded - " "block_group = %u, group_desc = %u, desc = %u", block_group, group_desc, offset);

		return NULL;
	}

	desc = (struct ext4_group_desc *)( (__u8 *)sbi->s_group_desc[group_desc]->b_data + offset * EXT4_DESC_SIZE(sb));

	if (bh)
		*bh = sbi->s_group_desc[group_desc];
	return desc;
}


static ext4_fsblk_t ext4_valid_block_bitmap(struct super_block *sb, struct ext4_group_desc *desc, ext4_group_t block_group, struct buffer_head *bh)


{
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	ext4_grpblk_t offset;
	ext4_grpblk_t next_zero_bit;
	ext4_grpblk_t max_bit = EXT4_CLUSTERS_PER_GROUP(sb);
	ext4_fsblk_t blk;
	ext4_fsblk_t group_first_block;

	if (ext4_has_feature_flex_bg(sb)) {
		
		return 0;
	}
	group_first_block = ext4_group_first_block_no(sb, block_group);

	
	blk = ext4_block_bitmap(sb, desc);
	offset = blk - group_first_block;
	if (offset < 0 || EXT4_B2C(sbi, offset) >= max_bit || !ext4_test_bit(EXT4_B2C(sbi, offset), bh->b_data))
		
		return blk;

	
	blk = ext4_inode_bitmap(sb, desc);
	offset = blk - group_first_block;
	if (offset < 0 || EXT4_B2C(sbi, offset) >= max_bit || !ext4_test_bit(EXT4_B2C(sbi, offset), bh->b_data))
		
		return blk;

	
	blk = ext4_inode_table(sb, desc);
	offset = blk - group_first_block;
	if (offset < 0 || EXT4_B2C(sbi, offset) >= max_bit || EXT4_B2C(sbi, offset + sbi->s_itb_per_group) >= max_bit)
		return blk;
	next_zero_bit = ext4_find_next_zero_bit(bh->b_data, EXT4_B2C(sbi, offset + sbi->s_itb_per_group), EXT4_B2C(sbi, offset));

	if (next_zero_bit < EXT4_B2C(sbi, offset + sbi->s_itb_per_group))
		
		return blk;
	return 0;
}

static int ext4_validate_block_bitmap(struct super_block *sb, struct ext4_group_desc *desc, ext4_group_t block_group, struct buffer_head *bh)


{
	ext4_fsblk_t	blk;
	struct ext4_group_info *grp = ext4_get_group_info(sb, block_group);

	if (buffer_verified(bh))
		return 0;
	if (EXT4_MB_GRP_BBITMAP_CORRUPT(grp))
		return -EFSCORRUPTED;

	ext4_lock_group(sb, block_group);
	if (unlikely(!ext4_block_bitmap_csum_verify(sb, block_group, desc, bh))) {
		ext4_unlock_group(sb, block_group);
		ext4_error(sb, "bg %u: bad block bitmap checksum", block_group);
		ext4_mark_group_bitmap_corrupted(sb, block_group, EXT4_GROUP_INFO_BBITMAP_CORRUPT);
		return -EFSBADCRC;
	}
	blk = ext4_valid_block_bitmap(sb, desc, block_group, bh);
	if (unlikely(blk != 0)) {
		ext4_unlock_group(sb, block_group);
		ext4_error(sb, "bg %u: block %llu: invalid block bitmap", block_group, blk);
		ext4_mark_group_bitmap_corrupted(sb, block_group, EXT4_GROUP_INFO_BBITMAP_CORRUPT);
		return -EFSCORRUPTED;
	}
	set_buffer_verified(bh);
	ext4_unlock_group(sb, block_group);
	return 0;
}


struct buffer_head * ext4_read_block_bitmap_nowait(struct super_block *sb, ext4_group_t block_group)
{
	struct ext4_group_desc *desc;
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	struct buffer_head *bh;
	ext4_fsblk_t bitmap_blk;
	int err;

	desc = ext4_get_group_desc(sb, block_group, NULL);
	if (!desc)
		return ERR_PTR(-EFSCORRUPTED);
	bitmap_blk = ext4_block_bitmap(sb, desc);
	if ((bitmap_blk <= le32_to_cpu(sbi->s_es->s_first_data_block)) || (bitmap_blk >= ext4_blocks_count(sbi->s_es))) {
		ext4_error(sb, "Invalid block bitmap block %llu in " "block_group %u", bitmap_blk, block_group);
		ext4_mark_group_bitmap_corrupted(sb, block_group, EXT4_GROUP_INFO_BBITMAP_CORRUPT);
		return ERR_PTR(-EFSCORRUPTED);
	}
	bh = sb_getblk(sb, bitmap_blk);
	if (unlikely(!bh)) {
		ext4_error(sb, "Cannot get buffer for block bitmap - " "block_group = %u, block_bitmap = %llu", block_group, bitmap_blk);

		return ERR_PTR(-ENOMEM);
	}

	if (bitmap_uptodate(bh))
		goto verify;

	lock_buffer(bh);
	if (bitmap_uptodate(bh)) {
		unlock_buffer(bh);
		goto verify;
	}
	ext4_lock_group(sb, block_group);
	if (desc->bg_flags & cpu_to_le16(EXT4_BG_BLOCK_UNINIT)) {
		err = ext4_init_block_bitmap(sb, bh, block_group, desc);
		set_bitmap_uptodate(bh);
		set_buffer_uptodate(bh);
		set_buffer_verified(bh);
		ext4_unlock_group(sb, block_group);
		unlock_buffer(bh);
		if (err) {
			ext4_error(sb, "Failed to init block bitmap for group " "%u: %d", block_group, err);
			goto out;
		}
		goto verify;
	}
	ext4_unlock_group(sb, block_group);
	if (buffer_uptodate(bh)) {
		
		set_bitmap_uptodate(bh);
		unlock_buffer(bh);
		goto verify;
	}
	
	set_buffer_new(bh);
	trace_ext4_read_block_bitmap_load(sb, block_group);
	bh->b_end_io = ext4_end_bitmap_read;
	get_bh(bh);
	submit_bh(REQ_OP_READ, REQ_META | REQ_PRIO, bh);
	return bh;
verify:
	err = ext4_validate_block_bitmap(sb, desc, block_group, bh);
	if (err)
		goto out;
	return bh;
out:
	put_bh(bh);
	return ERR_PTR(err);
}


int ext4_wait_block_bitmap(struct super_block *sb, ext4_group_t block_group, struct buffer_head *bh)
{
	struct ext4_group_desc *desc;

	if (!buffer_new(bh))
		return 0;
	desc = ext4_get_group_desc(sb, block_group, NULL);
	if (!desc)
		return -EFSCORRUPTED;
	wait_on_buffer(bh);
	if (!buffer_uptodate(bh)) {
		ext4_error(sb, "Cannot read block bitmap - " "block_group = %u, block_bitmap = %llu", block_group, (unsigned long long) bh->b_blocknr);

		ext4_mark_group_bitmap_corrupted(sb, block_group, EXT4_GROUP_INFO_BBITMAP_CORRUPT);
		return -EIO;
	}
	clear_buffer_new(bh);
	
	return ext4_validate_block_bitmap(sb, desc, block_group, bh);
}

struct buffer_head * ext4_read_block_bitmap(struct super_block *sb, ext4_group_t block_group)
{
	struct buffer_head *bh;
	int err;

	bh = ext4_read_block_bitmap_nowait(sb, block_group);
	if (IS_ERR(bh))
		return bh;
	err = ext4_wait_block_bitmap(sb, block_group, bh);
	if (err) {
		put_bh(bh);
		return ERR_PTR(err);
	}
	return bh;
}


static int ext4_has_free_clusters(struct ext4_sb_info *sbi, s64 nclusters, unsigned int flags)
{
	s64 free_clusters, dirty_clusters, rsv, resv_clusters;
	struct percpu_counter *fcc = &sbi->s_freeclusters_counter;
	struct percpu_counter *dcc = &sbi->s_dirtyclusters_counter;

	free_clusters  = percpu_counter_read_positive(fcc);
	dirty_clusters = percpu_counter_read_positive(dcc);
	resv_clusters = atomic64_read(&sbi->s_resv_clusters);

	
	rsv = (ext4_r_blocks_count(sbi->s_es) >> sbi->s_cluster_bits) + resv_clusters;

	if (free_clusters - (nclusters + rsv + dirty_clusters) < EXT4_FREECLUSTERS_WATERMARK) {
		free_clusters  = percpu_counter_sum_positive(fcc);
		dirty_clusters = percpu_counter_sum_positive(dcc);
	}
	
	if (free_clusters >= (rsv + nclusters + dirty_clusters))
		return 1;

	
	if (uid_eq(sbi->s_resuid, current_fsuid()) || (!gid_eq(sbi->s_resgid, GLOBAL_ROOT_GID) && in_group_p(sbi->s_resgid)) || capable(CAP_SYS_RESOURCE) || (flags & EXT4_MB_USE_ROOT_BLOCKS)) {



		if (free_clusters >= (nclusters + dirty_clusters + resv_clusters))
			return 1;
	}
	
	if (flags & EXT4_MB_USE_RESERVED) {
		if (free_clusters >= (nclusters + dirty_clusters))
			return 1;
	}

	return 0;
}

int ext4_claim_free_clusters(struct ext4_sb_info *sbi, s64 nclusters, unsigned int flags)
{
	if (ext4_has_free_clusters(sbi, nclusters, flags)) {
		percpu_counter_add(&sbi->s_dirtyclusters_counter, nclusters);
		return 0;
	} else return -ENOSPC;
}


int ext4_should_retry_alloc(struct super_block *sb, int *retries)
{
	if (!ext4_has_free_clusters(EXT4_SB(sb), 1, 0) || (*retries)++ > 1 || !EXT4_SB(sb)->s_journal)

		return 0;

	smp_mb();
	if (EXT4_SB(sb)->s_mb_free_pending == 0)
		return 0;

	jbd_debug(1, "%s: retrying operation after ENOSPC\n", sb->s_id);
	jbd2_journal_force_commit_nested(EXT4_SB(sb)->s_journal);
	return 1;
}


ext4_fsblk_t ext4_new_meta_blocks(handle_t *handle, struct inode *inode, ext4_fsblk_t goal, unsigned int flags, unsigned long *count, int *errp)

{
	struct ext4_allocation_request ar;
	ext4_fsblk_t ret;

	memset(&ar, 0, sizeof(ar));
	
	ar.inode = inode;
	ar.goal = goal;
	ar.len = count ? *count : 1;
	ar.flags = flags;

	ret = ext4_mb_new_blocks(handle, &ar, errp);
	if (count)
		*count = ar.len;
	
	if (!(*errp) && (flags & EXT4_MB_DELALLOC_RESERVED)) {
		dquot_alloc_block_nofail(inode, EXT4_C2B(EXT4_SB(inode->i_sb), ar.len));
	}
	return ret;
}


ext4_fsblk_t ext4_count_free_clusters(struct super_block *sb)
{
	ext4_fsblk_t desc_count;
	struct ext4_group_desc *gdp;
	ext4_group_t i;
	ext4_group_t ngroups = ext4_get_groups_count(sb);
	struct ext4_group_info *grp;

	struct ext4_super_block *es;
	ext4_fsblk_t bitmap_count;
	unsigned int x;
	struct buffer_head *bitmap_bh = NULL;

	es = EXT4_SB(sb)->s_es;
	desc_count = 0;
	bitmap_count = 0;
	gdp = NULL;

	for (i = 0; i < ngroups; i++) {
		gdp = ext4_get_group_desc(sb, i, NULL);
		if (!gdp)
			continue;
		grp = NULL;
		if (EXT4_SB(sb)->s_group_info)
			grp = ext4_get_group_info(sb, i);
		if (!grp || !EXT4_MB_GRP_BBITMAP_CORRUPT(grp))
			desc_count += ext4_free_group_clusters(sb, gdp);
		brelse(bitmap_bh);
		bitmap_bh = ext4_read_block_bitmap(sb, i);
		if (IS_ERR(bitmap_bh)) {
			bitmap_bh = NULL;
			continue;
		}

		x = ext4_count_free(bitmap_bh->b_data, EXT4_CLUSTERS_PER_GROUP(sb) / 8);
		printk(KERN_DEBUG "group %u: stored = %d, counted = %u\n", i, ext4_free_group_clusters(sb, gdp), x);
		bitmap_count += x;
	}
	brelse(bitmap_bh);
	printk(KERN_DEBUG "ext4_count_free_clusters: stored = %llu" ", computed = %llu, %llu\n", EXT4_NUM_B2C(EXT4_SB(sb), ext4_free_blocks_count(es)), desc_count, bitmap_count);


	return bitmap_count;

	desc_count = 0;
	for (i = 0; i < ngroups; i++) {
		gdp = ext4_get_group_desc(sb, i, NULL);
		if (!gdp)
			continue;
		grp = NULL;
		if (EXT4_SB(sb)->s_group_info)
			grp = ext4_get_group_info(sb, i);
		if (!grp || !EXT4_MB_GRP_BBITMAP_CORRUPT(grp))
			desc_count += ext4_free_group_clusters(sb, gdp);
	}

	return desc_count;

}

static inline int test_root(ext4_group_t a, int b)
{
	while (1) {
		if (a < b)
			return 0;
		if (a == b)
			return 1;
		if ((a % b) != 0)
			return 0;
		a = a / b;
	}
}


int ext4_bg_has_super(struct super_block *sb, ext4_group_t group)
{
	struct ext4_super_block *es = EXT4_SB(sb)->s_es;

	if (group == 0)
		return 1;
	if (ext4_has_feature_sparse_super2(sb)) {
		if (group == le32_to_cpu(es->s_backup_bgs[0]) || group == le32_to_cpu(es->s_backup_bgs[1]))
			return 1;
		return 0;
	}
	if ((group <= 1) || !ext4_has_feature_sparse_super(sb))
		return 1;
	if (!(group & 1))
		return 0;
	if (test_root(group, 3) || (test_root(group, 5)) || test_root(group, 7))
		return 1;

	return 0;
}

static unsigned long ext4_bg_num_gdb_meta(struct super_block *sb, ext4_group_t group)
{
	unsigned long metagroup = group / EXT4_DESC_PER_BLOCK(sb);
	ext4_group_t first = metagroup * EXT4_DESC_PER_BLOCK(sb);
	ext4_group_t last = first + EXT4_DESC_PER_BLOCK(sb) - 1;

	if (group == first || group == first + 1 || group == last)
		return 1;
	return 0;
}

static unsigned long ext4_bg_num_gdb_nometa(struct super_block *sb, ext4_group_t group)
{
	if (!ext4_bg_has_super(sb, group))
		return 0;

	if (ext4_has_feature_meta_bg(sb))
		return le32_to_cpu(EXT4_SB(sb)->s_es->s_first_meta_bg);
	else return EXT4_SB(sb)->s_gdb_count;
}


unsigned long ext4_bg_num_gdb(struct super_block *sb, ext4_group_t group)
{
	unsigned long first_meta_bg = le32_to_cpu(EXT4_SB(sb)->s_es->s_first_meta_bg);
	unsigned long metagroup = group / EXT4_DESC_PER_BLOCK(sb);

	if (!ext4_has_feature_meta_bg(sb) || metagroup < first_meta_bg)
		return ext4_bg_num_gdb_nometa(sb, group);

	return ext4_bg_num_gdb_meta(sb,group);

}


static unsigned ext4_num_base_meta_clusters(struct super_block *sb, ext4_group_t block_group)
{
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	unsigned num;

	
	num = ext4_bg_has_super(sb, block_group);

	if (!ext4_has_feature_meta_bg(sb) || block_group < le32_to_cpu(sbi->s_es->s_first_meta_bg) * sbi->s_desc_per_block) {

		if (num) {
			num += ext4_bg_num_gdb(sb, block_group);
			num += le16_to_cpu(sbi->s_es->s_reserved_gdt_blocks);
		}
	} else { 
		num += ext4_bg_num_gdb(sb, block_group);
	}
	return EXT4_NUM_B2C(sbi, num);
}

ext4_fsblk_t ext4_inode_to_goal_block(struct inode *inode)
{
	struct ext4_inode_info *ei = EXT4_I(inode);
	ext4_group_t block_group;
	ext4_grpblk_t colour;
	int flex_size = ext4_flex_bg_size(EXT4_SB(inode->i_sb));
	ext4_fsblk_t bg_start;
	ext4_fsblk_t last_block;

	block_group = ei->i_block_group;
	if (flex_size >= EXT4_FLEX_SIZE_DIR_ALLOC_SCHEME) {
		
		block_group &= ~(flex_size-1);
		if (S_ISREG(inode->i_mode))
			block_group++;
	}
	bg_start = ext4_group_first_block_no(inode->i_sb, block_group);
	last_block = ext4_blocks_count(EXT4_SB(inode->i_sb)->s_es) - 1;

	
	if (test_opt(inode->i_sb, DELALLOC))
		return bg_start;

	if (bg_start + EXT4_BLOCKS_PER_GROUP(inode->i_sb) <= last_block)
		colour = (current->pid % 16) * (EXT4_BLOCKS_PER_GROUP(inode->i_sb) / 16);
	else colour = (current->pid % 16) * ((last_block - bg_start) / 16);
	return bg_start + colour;
}

