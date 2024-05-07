





























static __le32 ext4_extent_block_csum(struct inode *inode, struct ext4_extent_header *eh)
{
	struct ext4_inode_info *ei = EXT4_I(inode);
	struct ext4_sb_info *sbi = EXT4_SB(inode->i_sb);
	__u32 csum;

	csum = ext4_chksum(sbi, ei->i_csum_seed, (__u8 *)eh, EXT4_EXTENT_TAIL_OFFSET(eh));
	return cpu_to_le32(csum);
}

static int ext4_extent_block_csum_verify(struct inode *inode, struct ext4_extent_header *eh)
{
	struct ext4_extent_tail *et;

	if (!ext4_has_metadata_csum(inode->i_sb))
		return 1;

	et = find_ext4_extent_tail(eh);
	if (et->et_checksum != ext4_extent_block_csum(inode, eh))
		return 0;
	return 1;
}

static void ext4_extent_block_csum_set(struct inode *inode, struct ext4_extent_header *eh)
{
	struct ext4_extent_tail *et;

	if (!ext4_has_metadata_csum(inode->i_sb))
		return;

	et = find_ext4_extent_tail(eh);
	et->et_checksum = ext4_extent_block_csum(inode, eh);
}

static int ext4_split_extent(handle_t *handle, struct inode *inode, struct ext4_ext_path **ppath, struct ext4_map_blocks *map, int split_flag, int flags);





static int ext4_split_extent_at(handle_t *handle, struct inode *inode, struct ext4_ext_path **ppath, ext4_lblk_t split, int split_flag, int flags);





static int ext4_find_delayed_extent(struct inode *inode, struct extent_status *newes);

static int ext4_ext_truncate_extend_restart(handle_t *handle, struct inode *inode, int needed)

{
	int err;

	if (!ext4_handle_valid(handle))
		return 0;
	if (handle->h_buffer_credits >= needed)
		return 0;
	
	needed += 3;
	err = ext4_journal_extend(handle, needed - handle->h_buffer_credits);
	if (err <= 0)
		return err;
	err = ext4_truncate_restart_trans(handle, inode, needed);
	if (err == 0)
		err = -EAGAIN;

	return err;
}


static int ext4_ext_get_access(handle_t *handle, struct inode *inode, struct ext4_ext_path *path)
{
	if (path->p_bh) {
		
		BUFFER_TRACE(path->p_bh, "get_write_access");
		return ext4_journal_get_write_access(handle, path->p_bh);
	}
	
	
	return 0;
}


int __ext4_ext_dirty(const char *where, unsigned int line, handle_t *handle, struct inode *inode, struct ext4_ext_path *path)
{
	int err;

	WARN_ON(!rwsem_is_locked(&EXT4_I(inode)->i_data_sem));
	if (path->p_bh) {
		ext4_extent_block_csum_set(inode, ext_block_hdr(path->p_bh));
		
		err = __ext4_handle_dirty_metadata(where, line, handle, inode, path->p_bh);
	} else {
		
		err = ext4_mark_inode_dirty(handle, inode);
	}
	return err;
}

static ext4_fsblk_t ext4_ext_find_goal(struct inode *inode, struct ext4_ext_path *path, ext4_lblk_t block)

{
	if (path) {
		int depth = path->p_depth;
		struct ext4_extent *ex;

		
		ex = path[depth].p_ext;
		if (ex) {
			ext4_fsblk_t ext_pblk = ext4_ext_pblock(ex);
			ext4_lblk_t ext_block = le32_to_cpu(ex->ee_block);

			if (block > ext_block)
				return ext_pblk + (block - ext_block);
			else return ext_pblk - (ext_block - block);
		}

		
		if (path[depth].p_bh)
			return path[depth].p_bh->b_blocknr;
	}

	
	return ext4_inode_to_goal_block(inode);
}


static ext4_fsblk_t ext4_ext_new_meta_block(handle_t *handle, struct inode *inode, struct ext4_ext_path *path, struct ext4_extent *ex, int *err, unsigned int flags)


{
	ext4_fsblk_t goal, newblock;

	goal = ext4_ext_find_goal(inode, path, le32_to_cpu(ex->ee_block));
	newblock = ext4_new_meta_blocks(handle, inode, goal, flags, NULL, err);
	return newblock;
}

static inline int ext4_ext_space_block(struct inode *inode, int check)
{
	int size;

	size = (inode->i_sb->s_blocksize - sizeof(struct ext4_extent_header))
			/ sizeof(struct ext4_extent);

	if (!check && size > 6)
		size = 6;

	return size;
}

static inline int ext4_ext_space_block_idx(struct inode *inode, int check)
{
	int size;

	size = (inode->i_sb->s_blocksize - sizeof(struct ext4_extent_header))
			/ sizeof(struct ext4_extent_idx);

	if (!check && size > 5)
		size = 5;

	return size;
}

static inline int ext4_ext_space_root(struct inode *inode, int check)
{
	int size;

	size = sizeof(EXT4_I(inode)->i_data);
	size -= sizeof(struct ext4_extent_header);
	size /= sizeof(struct ext4_extent);

	if (!check && size > 3)
		size = 3;

	return size;
}

static inline int ext4_ext_space_root_idx(struct inode *inode, int check)
{
	int size;

	size = sizeof(EXT4_I(inode)->i_data);
	size -= sizeof(struct ext4_extent_header);
	size /= sizeof(struct ext4_extent_idx);

	if (!check && size > 4)
		size = 4;

	return size;
}

static inline int ext4_force_split_extent_at(handle_t *handle, struct inode *inode, struct ext4_ext_path **ppath, ext4_lblk_t lblk, int nofail)


{
	struct ext4_ext_path *path = *ppath;
	int unwritten = ext4_ext_is_unwritten(path[path->p_depth].p_ext);

	return ext4_split_extent_at(handle, inode, ppath, lblk, unwritten ? EXT4_EXT_MARK_UNWRIT1|EXT4_EXT_MARK_UNWRIT2 : 0, EXT4_EX_NOCACHE | EXT4_GET_BLOCKS_PRE_IO | (nofail ? EXT4_GET_BLOCKS_METADATA_NOFAIL:0));


}


int ext4_ext_calc_metadata_amount(struct inode *inode, ext4_lblk_t lblock)
{
	struct ext4_inode_info *ei = EXT4_I(inode);
	int idxs;

	idxs = ((inode->i_sb->s_blocksize - sizeof(struct ext4_extent_header))
		/ sizeof(struct ext4_extent_idx));

	
	if (ei->i_da_metadata_calc_len && ei->i_da_metadata_calc_last_lblock+1 == lblock) {
		int num = 0;

		if ((ei->i_da_metadata_calc_len % idxs) == 0)
			num++;
		if ((ei->i_da_metadata_calc_len % (idxs*idxs)) == 0)
			num++;
		if ((ei->i_da_metadata_calc_len % (idxs*idxs*idxs)) == 0) {
			num++;
			ei->i_da_metadata_calc_len = 0;
		} else ei->i_da_metadata_calc_len++;
		ei->i_da_metadata_calc_last_lblock++;
		return num;
	}

	
	ei->i_da_metadata_calc_len = 1;
	ei->i_da_metadata_calc_last_lblock = lblock;
	return ext_depth(inode) + 1;
}

static int ext4_ext_max_entries(struct inode *inode, int depth)
{
	int max;

	if (depth == ext_depth(inode)) {
		if (depth == 0)
			max = ext4_ext_space_root(inode, 1);
		else max = ext4_ext_space_root_idx(inode, 1);
	} else {
		if (depth == 0)
			max = ext4_ext_space_block(inode, 1);
		else max = ext4_ext_space_block_idx(inode, 1);
	}

	return max;
}

static int ext4_valid_extent(struct inode *inode, struct ext4_extent *ext)
{
	ext4_fsblk_t block = ext4_ext_pblock(ext);
	int len = ext4_ext_get_actual_len(ext);
	ext4_lblk_t lblock = le32_to_cpu(ext->ee_block);

	
	if (lblock + len <= lblock)
		return 0;
	return ext4_data_block_valid(EXT4_SB(inode->i_sb), block, len);
}

static int ext4_valid_extent_idx(struct inode *inode, struct ext4_extent_idx *ext_idx)
{
	ext4_fsblk_t block = ext4_idx_pblock(ext_idx);

	return ext4_data_block_valid(EXT4_SB(inode->i_sb), block, 1);
}

static int ext4_valid_extent_entries(struct inode *inode, struct ext4_extent_header *eh, int depth)

{
	unsigned short entries;
	if (eh->eh_entries == 0)
		return 1;

	entries = le16_to_cpu(eh->eh_entries);

	if (depth == 0) {
		
		struct ext4_extent *ext = EXT_FIRST_EXTENT(eh);
		struct ext4_super_block *es = EXT4_SB(inode->i_sb)->s_es;
		ext4_fsblk_t pblock = 0;
		ext4_lblk_t lblock = 0;
		ext4_lblk_t prev = 0;
		int len = 0;
		while (entries) {
			if (!ext4_valid_extent(inode, ext))
				return 0;

			
			lblock = le32_to_cpu(ext->ee_block);
			len = ext4_ext_get_actual_len(ext);
			if ((lblock <= prev) && prev) {
				pblock = ext4_ext_pblock(ext);
				es->s_last_error_block = cpu_to_le64(pblock);
				return 0;
			}
			ext++;
			entries--;
			prev = lblock + len - 1;
		}
	} else {
		struct ext4_extent_idx *ext_idx = EXT_FIRST_INDEX(eh);
		while (entries) {
			if (!ext4_valid_extent_idx(inode, ext_idx))
				return 0;
			ext_idx++;
			entries--;
		}
	}
	return 1;
}

static int __ext4_ext_check(const char *function, unsigned int line, struct inode *inode, struct ext4_extent_header *eh, int depth, ext4_fsblk_t pblk)

{
	const char *error_msg;
	int max = 0, err = -EFSCORRUPTED;

	if (unlikely(eh->eh_magic != EXT4_EXT_MAGIC)) {
		error_msg = "invalid magic";
		goto corrupted;
	}
	if (unlikely(le16_to_cpu(eh->eh_depth) != depth)) {
		error_msg = "unexpected eh_depth";
		goto corrupted;
	}
	if (unlikely(eh->eh_max == 0)) {
		error_msg = "invalid eh_max";
		goto corrupted;
	}
	max = ext4_ext_max_entries(inode, depth);
	if (unlikely(le16_to_cpu(eh->eh_max) > max)) {
		error_msg = "too large eh_max";
		goto corrupted;
	}
	if (unlikely(le16_to_cpu(eh->eh_entries) > le16_to_cpu(eh->eh_max))) {
		error_msg = "invalid eh_entries";
		goto corrupted;
	}
	if (!ext4_valid_extent_entries(inode, eh, depth)) {
		error_msg = "invalid extent entries";
		goto corrupted;
	}
	if (unlikely(depth > 32)) {
		error_msg = "too large eh_depth";
		goto corrupted;
	}
	
	if (ext_depth(inode) != depth && !ext4_extent_block_csum_verify(inode, eh)) {
		error_msg = "extent tree corrupted";
		err = -EFSBADCRC;
		goto corrupted;
	}
	return 0;

corrupted:
	ext4_error_inode(inode, function, line, 0, "pblk %llu bad header/extent: %s - magic %x, " "entries %u, max %u(%u), depth %u(%u)", (unsigned long long) pblk, error_msg, le16_to_cpu(eh->eh_magic), le16_to_cpu(eh->eh_entries), le16_to_cpu(eh->eh_max), max, le16_to_cpu(eh->eh_depth), depth);





	return err;
}



int ext4_ext_check_inode(struct inode *inode)
{
	return ext4_ext_check(inode, ext_inode_hdr(inode), ext_depth(inode), 0);
}

static struct buffer_head * __read_extent_tree_block(const char *function, unsigned int line, struct inode *inode, ext4_fsblk_t pblk, int depth, int flags)


{
	struct buffer_head		*bh;
	int				err;

	bh = sb_getblk_gfp(inode->i_sb, pblk, __GFP_MOVABLE | GFP_NOFS);
	if (unlikely(!bh))
		return ERR_PTR(-ENOMEM);

	if (!bh_uptodate_or_lock(bh)) {
		trace_ext4_ext_load_extent(inode, pblk, _RET_IP_);
		err = bh_submit_read(bh);
		if (err < 0)
			goto errout;
	}
	if (buffer_verified(bh) && !(flags & EXT4_EX_FORCE_CACHE))
		return bh;
	err = __ext4_ext_check(function, line, inode, ext_block_hdr(bh), depth, pblk);
	if (err)
		goto errout;
	set_buffer_verified(bh);
	
	if (!(flags & EXT4_EX_NOCACHE) && depth == 0) {
		struct ext4_extent_header *eh = ext_block_hdr(bh);
		struct ext4_extent *ex = EXT_FIRST_EXTENT(eh);
		ext4_lblk_t prev = 0;
		int i;

		for (i = le16_to_cpu(eh->eh_entries); i > 0; i--, ex++) {
			unsigned int status = EXTENT_STATUS_WRITTEN;
			ext4_lblk_t lblk = le32_to_cpu(ex->ee_block);
			int len = ext4_ext_get_actual_len(ex);

			if (prev && (prev != lblk))
				ext4_es_cache_extent(inode, prev, lblk - prev, ~0, EXTENT_STATUS_HOLE);


			if (ext4_ext_is_unwritten(ex))
				status = EXTENT_STATUS_UNWRITTEN;
			ext4_es_cache_extent(inode, lblk, len, ext4_ext_pblock(ex), status);
			prev = lblk + len;
		}
	}
	return bh;
errout:
	put_bh(bh);
	return ERR_PTR(err);

}





int ext4_ext_precache(struct inode *inode)
{
	struct ext4_inode_info *ei = EXT4_I(inode);
	struct ext4_ext_path *path = NULL;
	struct buffer_head *bh;
	int i = 0, depth, ret = 0;

	if (!ext4_test_inode_flag(inode, EXT4_INODE_EXTENTS))
		return 0;	

	down_read(&ei->i_data_sem);
	depth = ext_depth(inode);

	path = kcalloc(depth + 1, sizeof(struct ext4_ext_path), GFP_NOFS);
	if (path == NULL) {
		up_read(&ei->i_data_sem);
		return -ENOMEM;
	}

	
	if (depth == 0)
		goto out;
	path[0].p_hdr = ext_inode_hdr(inode);
	ret = ext4_ext_check(inode, path[0].p_hdr, depth, 0);
	if (ret)
		goto out;
	path[0].p_idx = EXT_FIRST_INDEX(path[0].p_hdr);
	while (i >= 0) {
		
		if ((i == depth) || path[i].p_idx > EXT_LAST_INDEX(path[i].p_hdr)) {
			brelse(path[i].p_bh);
			path[i].p_bh = NULL;
			i--;
			continue;
		}
		bh = read_extent_tree_block(inode, ext4_idx_pblock(path[i].p_idx++), depth - i - 1, EXT4_EX_FORCE_CACHE);


		if (IS_ERR(bh)) {
			ret = PTR_ERR(bh);
			break;
		}
		i++;
		path[i].p_bh = bh;
		path[i].p_hdr = ext_block_hdr(bh);
		path[i].p_idx = EXT_FIRST_INDEX(path[i].p_hdr);
	}
	ext4_set_inode_state(inode, EXT4_STATE_EXT_PRECACHED);
out:
	up_read(&ei->i_data_sem);
	ext4_ext_drop_refs(path);
	kfree(path);
	return ret;
}


static void ext4_ext_show_path(struct inode *inode, struct ext4_ext_path *path)
{
	int k, l = path->p_depth;

	ext_debug("path:");
	for (k = 0; k <= l; k++, path++) {
		if (path->p_idx) {
		  ext_debug("  %d->%llu", le32_to_cpu(path->p_idx->ei_block), ext4_idx_pblock(path->p_idx));
		} else if (path->p_ext) {
			ext_debug("  %d:[%d]%d:%llu ", le32_to_cpu(path->p_ext->ee_block), ext4_ext_is_unwritten(path->p_ext), ext4_ext_get_actual_len(path->p_ext), ext4_ext_pblock(path->p_ext));



		} else ext_debug("  []");
	}
	ext_debug("\n");
}

static void ext4_ext_show_leaf(struct inode *inode, struct ext4_ext_path *path)
{
	int depth = ext_depth(inode);
	struct ext4_extent_header *eh;
	struct ext4_extent *ex;
	int i;

	if (!path)
		return;

	eh = path[depth].p_hdr;
	ex = EXT_FIRST_EXTENT(eh);

	ext_debug("Displaying leaf extents for inode %lu\n", inode->i_ino);

	for (i = 0; i < le16_to_cpu(eh->eh_entries); i++, ex++) {
		ext_debug("%d:[%d]%d:%llu ", le32_to_cpu(ex->ee_block), ext4_ext_is_unwritten(ex), ext4_ext_get_actual_len(ex), ext4_ext_pblock(ex));

	}
	ext_debug("\n");
}

static void ext4_ext_show_move(struct inode *inode, struct ext4_ext_path *path, ext4_fsblk_t newblock, int level)
{
	int depth = ext_depth(inode);
	struct ext4_extent *ex;

	if (depth != level) {
		struct ext4_extent_idx *idx;
		idx = path[level].p_idx;
		while (idx <= EXT_MAX_INDEX(path[level].p_hdr)) {
			ext_debug("%d: move %d:%llu in new index %llu\n", level, le32_to_cpu(idx->ei_block), ext4_idx_pblock(idx), newblock);


			idx++;
		}

		return;
	}

	ex = path[depth].p_ext;
	while (ex <= EXT_MAX_EXTENT(path[depth].p_hdr)) {
		ext_debug("move %d:%llu:[%d]%d in new leaf %llu\n", le32_to_cpu(ex->ee_block), ext4_ext_pblock(ex), ext4_ext_is_unwritten(ex), ext4_ext_get_actual_len(ex), newblock);




		ex++;
	}
}







void ext4_ext_drop_refs(struct ext4_ext_path *path)
{
	int depth, i;

	if (!path)
		return;
	depth = path->p_depth;
	for (i = 0; i <= depth; i++, path++)
		if (path->p_bh) {
			brelse(path->p_bh);
			path->p_bh = NULL;
		}
}


static void ext4_ext_binsearch_idx(struct inode *inode, struct ext4_ext_path *path, ext4_lblk_t block)

{
	struct ext4_extent_header *eh = path->p_hdr;
	struct ext4_extent_idx *r, *l, *m;


	ext_debug("binsearch for %u(idx):  ", block);

	l = EXT_FIRST_INDEX(eh) + 1;
	r = EXT_LAST_INDEX(eh);
	while (l <= r) {
		m = l + (r - l) / 2;
		if (block < le32_to_cpu(m->ei_block))
			r = m - 1;
		else l = m + 1;
		ext_debug("%p(%u):%p(%u):%p(%u) ", l, le32_to_cpu(l->ei_block), m, le32_to_cpu(m->ei_block), r, le32_to_cpu(r->ei_block));

	}

	path->p_idx = l - 1;
	ext_debug("  -> %u->%lld ", le32_to_cpu(path->p_idx->ei_block), ext4_idx_pblock(path->p_idx));


	{
		struct ext4_extent_idx *chix, *ix;
		int k;

		chix = ix = EXT_FIRST_INDEX(eh);
		for (k = 0; k < le16_to_cpu(eh->eh_entries); k++, ix++) {
		  if (k != 0 && le32_to_cpu(ix->ei_block) <= le32_to_cpu(ix[-1].ei_block)) {
				printk(KERN_DEBUG "k=%d, ix=0x%p, " "first=0x%p\n", k, ix, EXT_FIRST_INDEX(eh));

				printk(KERN_DEBUG "%u <= %u\n", le32_to_cpu(ix->ei_block), le32_to_cpu(ix[-1].ei_block));

			}
			BUG_ON(k && le32_to_cpu(ix->ei_block)
					   <= le32_to_cpu(ix[-1].ei_block));
			if (block < le32_to_cpu(ix->ei_block))
				break;
			chix = ix;
		}
		BUG_ON(chix != path->p_idx);
	}


}


static void ext4_ext_binsearch(struct inode *inode, struct ext4_ext_path *path, ext4_lblk_t block)

{
	struct ext4_extent_header *eh = path->p_hdr;
	struct ext4_extent *r, *l, *m;

	if (eh->eh_entries == 0) {
		
		return;
	}

	ext_debug("binsearch for %u:  ", block);

	l = EXT_FIRST_EXTENT(eh) + 1;
	r = EXT_LAST_EXTENT(eh);

	while (l <= r) {
		m = l + (r - l) / 2;
		if (block < le32_to_cpu(m->ee_block))
			r = m - 1;
		else l = m + 1;
		ext_debug("%p(%u):%p(%u):%p(%u) ", l, le32_to_cpu(l->ee_block), m, le32_to_cpu(m->ee_block), r, le32_to_cpu(r->ee_block));

	}

	path->p_ext = l - 1;
	ext_debug("  -> %d:%llu:[%d]%d ", le32_to_cpu(path->p_ext->ee_block), ext4_ext_pblock(path->p_ext), ext4_ext_is_unwritten(path->p_ext), ext4_ext_get_actual_len(path->p_ext));





	{
		struct ext4_extent *chex, *ex;
		int k;

		chex = ex = EXT_FIRST_EXTENT(eh);
		for (k = 0; k < le16_to_cpu(eh->eh_entries); k++, ex++) {
			BUG_ON(k && le32_to_cpu(ex->ee_block)
					  <= le32_to_cpu(ex[-1].ee_block));
			if (block < le32_to_cpu(ex->ee_block))
				break;
			chex = ex;
		}
		BUG_ON(chex != path->p_ext);
	}


}

int ext4_ext_tree_init(handle_t *handle, struct inode *inode)
{
	struct ext4_extent_header *eh;

	eh = ext_inode_hdr(inode);
	eh->eh_depth = 0;
	eh->eh_entries = 0;
	eh->eh_magic = EXT4_EXT_MAGIC;
	eh->eh_max = cpu_to_le16(ext4_ext_space_root(inode, 0));
	ext4_mark_inode_dirty(handle, inode);
	return 0;
}

struct ext4_ext_path * ext4_find_extent(struct inode *inode, ext4_lblk_t block, struct ext4_ext_path **orig_path, int flags)

{
	struct ext4_extent_header *eh;
	struct buffer_head *bh;
	struct ext4_ext_path *path = orig_path ? *orig_path : NULL;
	short int depth, i, ppos = 0;
	int ret;

	eh = ext_inode_hdr(inode);
	depth = ext_depth(inode);
	if (depth < 0 || depth > EXT4_MAX_EXTENT_DEPTH) {
		EXT4_ERROR_INODE(inode, "inode has invalid extent depth: %d", depth);
		ret = -EFSCORRUPTED;
		goto err;
	}

	if (path) {
		ext4_ext_drop_refs(path);
		if (depth > path[0].p_maxdepth) {
			kfree(path);
			*orig_path = path = NULL;
		}
	}
	if (!path) {
		
		path = kcalloc(depth + 2, sizeof(struct ext4_ext_path), GFP_NOFS);
		if (unlikely(!path))
			return ERR_PTR(-ENOMEM);
		path[0].p_maxdepth = depth + 1;
	}
	path[0].p_hdr = eh;
	path[0].p_bh = NULL;

	i = depth;
	
	while (i) {
		ext_debug("depth %d: num %d, max %d\n", ppos, le16_to_cpu(eh->eh_entries), le16_to_cpu(eh->eh_max));

		ext4_ext_binsearch_idx(inode, path + ppos, block);
		path[ppos].p_block = ext4_idx_pblock(path[ppos].p_idx);
		path[ppos].p_depth = i;
		path[ppos].p_ext = NULL;

		bh = read_extent_tree_block(inode, path[ppos].p_block, --i, flags);
		if (IS_ERR(bh)) {
			ret = PTR_ERR(bh);
			goto err;
		}

		eh = ext_block_hdr(bh);
		ppos++;
		path[ppos].p_bh = bh;
		path[ppos].p_hdr = eh;
	}

	path[ppos].p_depth = i;
	path[ppos].p_ext = NULL;
	path[ppos].p_idx = NULL;

	
	ext4_ext_binsearch(inode, path + ppos, block);
	
	if (path[ppos].p_ext)
		path[ppos].p_block = ext4_ext_pblock(path[ppos].p_ext);

	ext4_ext_show_path(inode, path);

	return path;

err:
	ext4_ext_drop_refs(path);
	kfree(path);
	if (orig_path)
		*orig_path = NULL;
	return ERR_PTR(ret);
}


static int ext4_ext_insert_index(handle_t *handle, struct inode *inode, struct ext4_ext_path *curp, int logical, ext4_fsblk_t ptr)

{
	struct ext4_extent_idx *ix;
	int len, err;

	err = ext4_ext_get_access(handle, inode, curp);
	if (err)
		return err;

	if (unlikely(logical == le32_to_cpu(curp->p_idx->ei_block))) {
		EXT4_ERROR_INODE(inode, "logical %d == ei_block %d!", logical, le32_to_cpu(curp->p_idx->ei_block));

		return -EFSCORRUPTED;
	}

	if (unlikely(le16_to_cpu(curp->p_hdr->eh_entries)
			     >= le16_to_cpu(curp->p_hdr->eh_max))) {
		EXT4_ERROR_INODE(inode, "eh_entries %d >= eh_max %d!", le16_to_cpu(curp->p_hdr->eh_entries), le16_to_cpu(curp->p_hdr->eh_max));


		return -EFSCORRUPTED;
	}

	if (logical > le32_to_cpu(curp->p_idx->ei_block)) {
		
		ext_debug("insert new index %d after: %llu\n", logical, ptr);
		ix = curp->p_idx + 1;
	} else {
		
		ext_debug("insert new index %d before: %llu\n", logical, ptr);
		ix = curp->p_idx;
	}

	len = EXT_LAST_INDEX(curp->p_hdr) - ix + 1;
	BUG_ON(len < 0);
	if (len > 0) {
		ext_debug("insert new index %d: " "move %d indices from 0x%p to 0x%p\n", logical, len, ix, ix + 1);

		memmove(ix + 1, ix, len * sizeof(struct ext4_extent_idx));
	}

	if (unlikely(ix > EXT_MAX_INDEX(curp->p_hdr))) {
		EXT4_ERROR_INODE(inode, "ix > EXT_MAX_INDEX!");
		return -EFSCORRUPTED;
	}

	ix->ei_block = cpu_to_le32(logical);
	ext4_idx_store_pblock(ix, ptr);
	le16_add_cpu(&curp->p_hdr->eh_entries, 1);

	if (unlikely(ix > EXT_LAST_INDEX(curp->p_hdr))) {
		EXT4_ERROR_INODE(inode, "ix > EXT_LAST_INDEX!");
		return -EFSCORRUPTED;
	}

	err = ext4_ext_dirty(handle, inode, curp);
	ext4_std_error(inode->i_sb, err);

	return err;
}


static int ext4_ext_split(handle_t *handle, struct inode *inode, unsigned int flags, struct ext4_ext_path *path, struct ext4_extent *newext, int at)


{
	struct buffer_head *bh = NULL;
	int depth = ext_depth(inode);
	struct ext4_extent_header *neh;
	struct ext4_extent_idx *fidx;
	int i = at, k, m, a;
	ext4_fsblk_t newblock, oldblock;
	__le32 border;
	ext4_fsblk_t *ablocks = NULL; 
	int err = 0;

	
	

	
	if (unlikely(path[depth].p_ext > EXT_MAX_EXTENT(path[depth].p_hdr))) {
		EXT4_ERROR_INODE(inode, "p_ext > EXT_MAX_EXTENT!");
		return -EFSCORRUPTED;
	}
	if (path[depth].p_ext != EXT_MAX_EXTENT(path[depth].p_hdr)) {
		border = path[depth].p_ext[1].ee_block;
		ext_debug("leaf will be split." " next leaf starts at %d\n", le32_to_cpu(border));

	} else {
		border = newext->ee_block;
		ext_debug("leaf will be added." " next leaf starts at %d\n", le32_to_cpu(border));

	}

	

	
	ablocks = kcalloc(depth, sizeof(ext4_fsblk_t), GFP_NOFS);
	if (!ablocks)
		return -ENOMEM;

	
	ext_debug("allocate %d blocks for indexes/leaf\n", depth - at);
	for (a = 0; a < depth - at; a++) {
		newblock = ext4_ext_new_meta_block(handle, inode, path, newext, &err, flags);
		if (newblock == 0)
			goto cleanup;
		ablocks[a] = newblock;
	}

	
	newblock = ablocks[--a];
	if (unlikely(newblock == 0)) {
		EXT4_ERROR_INODE(inode, "newblock == 0!");
		err = -EFSCORRUPTED;
		goto cleanup;
	}
	bh = sb_getblk_gfp(inode->i_sb, newblock, __GFP_MOVABLE | GFP_NOFS);
	if (unlikely(!bh)) {
		err = -ENOMEM;
		goto cleanup;
	}
	lock_buffer(bh);

	err = ext4_journal_get_create_access(handle, bh);
	if (err)
		goto cleanup;

	neh = ext_block_hdr(bh);
	neh->eh_entries = 0;
	neh->eh_max = cpu_to_le16(ext4_ext_space_block(inode, 0));
	neh->eh_magic = EXT4_EXT_MAGIC;
	neh->eh_depth = 0;

	
	if (unlikely(path[depth].p_hdr->eh_entries != path[depth].p_hdr->eh_max)) {
		EXT4_ERROR_INODE(inode, "eh_entries %d != eh_max %d!", path[depth].p_hdr->eh_entries, path[depth].p_hdr->eh_max);

		err = -EFSCORRUPTED;
		goto cleanup;
	}
	
	m = EXT_MAX_EXTENT(path[depth].p_hdr) - path[depth].p_ext++;
	ext4_ext_show_move(inode, path, newblock, depth);
	if (m) {
		struct ext4_extent *ex;
		ex = EXT_FIRST_EXTENT(neh);
		memmove(ex, path[depth].p_ext, sizeof(struct ext4_extent) * m);
		le16_add_cpu(&neh->eh_entries, m);
	}

	ext4_extent_block_csum_set(inode, neh);
	set_buffer_uptodate(bh);
	unlock_buffer(bh);

	err = ext4_handle_dirty_metadata(handle, inode, bh);
	if (err)
		goto cleanup;
	brelse(bh);
	bh = NULL;

	
	if (m) {
		err = ext4_ext_get_access(handle, inode, path + depth);
		if (err)
			goto cleanup;
		le16_add_cpu(&path[depth].p_hdr->eh_entries, -m);
		err = ext4_ext_dirty(handle, inode, path + depth);
		if (err)
			goto cleanup;

	}

	
	k = depth - at - 1;
	if (unlikely(k < 0)) {
		EXT4_ERROR_INODE(inode, "k %d < 0!", k);
		err = -EFSCORRUPTED;
		goto cleanup;
	}
	if (k)
		ext_debug("create %d intermediate indices\n", k);
	
	
	i = depth - 1;
	while (k--) {
		oldblock = newblock;
		newblock = ablocks[--a];
		bh = sb_getblk(inode->i_sb, newblock);
		if (unlikely(!bh)) {
			err = -ENOMEM;
			goto cleanup;
		}
		lock_buffer(bh);

		err = ext4_journal_get_create_access(handle, bh);
		if (err)
			goto cleanup;

		neh = ext_block_hdr(bh);
		neh->eh_entries = cpu_to_le16(1);
		neh->eh_magic = EXT4_EXT_MAGIC;
		neh->eh_max = cpu_to_le16(ext4_ext_space_block_idx(inode, 0));
		neh->eh_depth = cpu_to_le16(depth - i);
		fidx = EXT_FIRST_INDEX(neh);
		fidx->ei_block = border;
		ext4_idx_store_pblock(fidx, oldblock);

		ext_debug("int.index at %d (block %llu): %u -> %llu\n", i, newblock, le32_to_cpu(border), oldblock);

		
		if (unlikely(EXT_MAX_INDEX(path[i].p_hdr) != EXT_LAST_INDEX(path[i].p_hdr))) {
			EXT4_ERROR_INODE(inode, "EXT_MAX_INDEX != EXT_LAST_INDEX ee_block %d!", le32_to_cpu(path[i].p_ext->ee_block));

			err = -EFSCORRUPTED;
			goto cleanup;
		}
		
		m = EXT_MAX_INDEX(path[i].p_hdr) - path[i].p_idx++;
		ext_debug("cur 0x%p, last 0x%p\n", path[i].p_idx, EXT_MAX_INDEX(path[i].p_hdr));
		ext4_ext_show_move(inode, path, newblock, i);
		if (m) {
			memmove(++fidx, path[i].p_idx, sizeof(struct ext4_extent_idx) * m);
			le16_add_cpu(&neh->eh_entries, m);
		}
		ext4_extent_block_csum_set(inode, neh);
		set_buffer_uptodate(bh);
		unlock_buffer(bh);

		err = ext4_handle_dirty_metadata(handle, inode, bh);
		if (err)
			goto cleanup;
		brelse(bh);
		bh = NULL;

		
		if (m) {
			err = ext4_ext_get_access(handle, inode, path + i);
			if (err)
				goto cleanup;
			le16_add_cpu(&path[i].p_hdr->eh_entries, -m);
			err = ext4_ext_dirty(handle, inode, path + i);
			if (err)
				goto cleanup;
		}

		i--;
	}

	
	err = ext4_ext_insert_index(handle, inode, path + at, le32_to_cpu(border), newblock);

cleanup:
	if (bh) {
		if (buffer_locked(bh))
			unlock_buffer(bh);
		brelse(bh);
	}

	if (err) {
		
		for (i = 0; i < depth; i++) {
			if (!ablocks[i])
				continue;
			ext4_free_blocks(handle, inode, NULL, ablocks[i], 1, EXT4_FREE_BLOCKS_METADATA);
		}
	}
	kfree(ablocks);

	return err;
}


static int ext4_ext_grow_indepth(handle_t *handle, struct inode *inode, unsigned int flags)
{
	struct ext4_extent_header *neh;
	struct buffer_head *bh;
	ext4_fsblk_t newblock, goal = 0;
	struct ext4_super_block *es = EXT4_SB(inode->i_sb)->s_es;
	int err = 0;

	
	if (ext_depth(inode))
		goal = ext4_idx_pblock(EXT_FIRST_INDEX(ext_inode_hdr(inode)));
	if (goal > le32_to_cpu(es->s_first_data_block)) {
		flags |= EXT4_MB_HINT_TRY_GOAL;
		goal--;
	} else goal = ext4_inode_to_goal_block(inode);
	newblock = ext4_new_meta_blocks(handle, inode, goal, flags, NULL, &err);
	if (newblock == 0)
		return err;

	bh = sb_getblk_gfp(inode->i_sb, newblock, __GFP_MOVABLE | GFP_NOFS);
	if (unlikely(!bh))
		return -ENOMEM;
	lock_buffer(bh);

	err = ext4_journal_get_create_access(handle, bh);
	if (err) {
		unlock_buffer(bh);
		goto out;
	}

	
	memmove(bh->b_data, EXT4_I(inode)->i_data, sizeof(EXT4_I(inode)->i_data));

	
	neh = ext_block_hdr(bh);
	
	if (ext_depth(inode))
		neh->eh_max = cpu_to_le16(ext4_ext_space_block_idx(inode, 0));
	else neh->eh_max = cpu_to_le16(ext4_ext_space_block(inode, 0));
	neh->eh_magic = EXT4_EXT_MAGIC;
	ext4_extent_block_csum_set(inode, neh);
	set_buffer_uptodate(bh);
	unlock_buffer(bh);

	err = ext4_handle_dirty_metadata(handle, inode, bh);
	if (err)
		goto out;

	
	neh = ext_inode_hdr(inode);
	neh->eh_entries = cpu_to_le16(1);
	ext4_idx_store_pblock(EXT_FIRST_INDEX(neh), newblock);
	if (neh->eh_depth == 0) {
		
		neh->eh_max = cpu_to_le16(ext4_ext_space_root_idx(inode, 0));
		EXT_FIRST_INDEX(neh)->ei_block = EXT_FIRST_EXTENT(neh)->ee_block;
	}
	ext_debug("new root: num %d(%d), lblock %d, ptr %llu\n", le16_to_cpu(neh->eh_entries), le16_to_cpu(neh->eh_max), le32_to_cpu(EXT_FIRST_INDEX(neh)->ei_block), ext4_idx_pblock(EXT_FIRST_INDEX(neh)));



	le16_add_cpu(&neh->eh_depth, 1);
	ext4_mark_inode_dirty(handle, inode);
out:
	brelse(bh);

	return err;
}


static int ext4_ext_create_new_leaf(handle_t *handle, struct inode *inode, unsigned int mb_flags, unsigned int gb_flags, struct ext4_ext_path **ppath, struct ext4_extent *newext)



{
	struct ext4_ext_path *path = *ppath;
	struct ext4_ext_path *curp;
	int depth, i, err = 0;

repeat:
	i = depth = ext_depth(inode);

	
	curp = path + depth;
	while (i > 0 && !EXT_HAS_FREE_INDEX(curp)) {
		i--;
		curp--;
	}

	
	if (EXT_HAS_FREE_INDEX(curp)) {
		
		err = ext4_ext_split(handle, inode, mb_flags, path, newext, i);
		if (err)
			goto out;

		
		path = ext4_find_extent(inode, (ext4_lblk_t)le32_to_cpu(newext->ee_block), ppath, gb_flags);

		if (IS_ERR(path))
			err = PTR_ERR(path);
	} else {
		
		err = ext4_ext_grow_indepth(handle, inode, mb_flags);
		if (err)
			goto out;

		
		path = ext4_find_extent(inode, (ext4_lblk_t)le32_to_cpu(newext->ee_block), ppath, gb_flags);

		if (IS_ERR(path)) {
			err = PTR_ERR(path);
			goto out;
		}

		
		depth = ext_depth(inode);
		if (path[depth].p_hdr->eh_entries == path[depth].p_hdr->eh_max) {
			
			goto repeat;
		}
	}

out:
	return err;
}


static int ext4_ext_search_left(struct inode *inode, struct ext4_ext_path *path, ext4_lblk_t *logical, ext4_fsblk_t *phys)

{
	struct ext4_extent_idx *ix;
	struct ext4_extent *ex;
	int depth, ee_len;

	if (unlikely(path == NULL)) {
		EXT4_ERROR_INODE(inode, "path == NULL *logical %d!", *logical);
		return -EFSCORRUPTED;
	}
	depth = path->p_depth;
	*phys = 0;

	if (depth == 0 && path->p_ext == NULL)
		return 0;

	

	ex = path[depth].p_ext;
	ee_len = ext4_ext_get_actual_len(ex);
	if (*logical < le32_to_cpu(ex->ee_block)) {
		if (unlikely(EXT_FIRST_EXTENT(path[depth].p_hdr) != ex)) {
			EXT4_ERROR_INODE(inode, "EXT_FIRST_EXTENT != ex *logical %d ee_block %d!", *logical, le32_to_cpu(ex->ee_block));

			return -EFSCORRUPTED;
		}
		while (--depth >= 0) {
			ix = path[depth].p_idx;
			if (unlikely(ix != EXT_FIRST_INDEX(path[depth].p_hdr))) {
				EXT4_ERROR_INODE(inode, "ix (%d) != EXT_FIRST_INDEX (%d) (depth %d)!", ix != NULL ? le32_to_cpu(ix->ei_block) : 0, EXT_FIRST_INDEX(path[depth].p_hdr) != NULL ? le32_to_cpu(EXT_FIRST_INDEX(path[depth].p_hdr)->ei_block) : 0, depth);




				return -EFSCORRUPTED;
			}
		}
		return 0;
	}

	if (unlikely(*logical < (le32_to_cpu(ex->ee_block) + ee_len))) {
		EXT4_ERROR_INODE(inode, "logical %d < ee_block %d + ee_len %d!", *logical, le32_to_cpu(ex->ee_block), ee_len);

		return -EFSCORRUPTED;
	}

	*logical = le32_to_cpu(ex->ee_block) + ee_len - 1;
	*phys = ext4_ext_pblock(ex) + ee_len - 1;
	return 0;
}


static int ext4_ext_search_right(struct inode *inode, struct ext4_ext_path *path, ext4_lblk_t *logical, ext4_fsblk_t *phys, struct ext4_extent **ret_ex)


{
	struct buffer_head *bh = NULL;
	struct ext4_extent_header *eh;
	struct ext4_extent_idx *ix;
	struct ext4_extent *ex;
	ext4_fsblk_t block;
	int depth;	
	int ee_len;

	if (unlikely(path == NULL)) {
		EXT4_ERROR_INODE(inode, "path == NULL *logical %d!", *logical);
		return -EFSCORRUPTED;
	}
	depth = path->p_depth;
	*phys = 0;

	if (depth == 0 && path->p_ext == NULL)
		return 0;

	

	ex = path[depth].p_ext;
	ee_len = ext4_ext_get_actual_len(ex);
	if (*logical < le32_to_cpu(ex->ee_block)) {
		if (unlikely(EXT_FIRST_EXTENT(path[depth].p_hdr) != ex)) {
			EXT4_ERROR_INODE(inode, "first_extent(path[%d].p_hdr) != ex", depth);

			return -EFSCORRUPTED;
		}
		while (--depth >= 0) {
			ix = path[depth].p_idx;
			if (unlikely(ix != EXT_FIRST_INDEX(path[depth].p_hdr))) {
				EXT4_ERROR_INODE(inode, "ix != EXT_FIRST_INDEX *logical %d!", *logical);

				return -EFSCORRUPTED;
			}
		}
		goto found_extent;
	}

	if (unlikely(*logical < (le32_to_cpu(ex->ee_block) + ee_len))) {
		EXT4_ERROR_INODE(inode, "logical %d < ee_block %d + ee_len %d!", *logical, le32_to_cpu(ex->ee_block), ee_len);

		return -EFSCORRUPTED;
	}

	if (ex != EXT_LAST_EXTENT(path[depth].p_hdr)) {
		
		ex++;
		goto found_extent;
	}

	
	while (--depth >= 0) {
		ix = path[depth].p_idx;
		if (ix != EXT_LAST_INDEX(path[depth].p_hdr))
			goto got_index;
	}

	
	return 0;

got_index:
	
	ix++;
	block = ext4_idx_pblock(ix);
	while (++depth < path->p_depth) {
		
		bh = read_extent_tree_block(inode, block, path->p_depth - depth, 0);
		if (IS_ERR(bh))
			return PTR_ERR(bh);
		eh = ext_block_hdr(bh);
		ix = EXT_FIRST_INDEX(eh);
		block = ext4_idx_pblock(ix);
		put_bh(bh);
	}

	bh = read_extent_tree_block(inode, block, path->p_depth - depth, 0);
	if (IS_ERR(bh))
		return PTR_ERR(bh);
	eh = ext_block_hdr(bh);
	ex = EXT_FIRST_EXTENT(eh);
found_extent:
	*logical = le32_to_cpu(ex->ee_block);
	*phys = ext4_ext_pblock(ex);
	*ret_ex = ex;
	if (bh)
		put_bh(bh);
	return 0;
}


ext4_lblk_t ext4_ext_next_allocated_block(struct ext4_ext_path *path)
{
	int depth;

	BUG_ON(path == NULL);
	depth = path->p_depth;

	if (depth == 0 && path->p_ext == NULL)
		return EXT_MAX_BLOCKS;

	while (depth >= 0) {
		if (depth == path->p_depth) {
			
			if (path[depth].p_ext && path[depth].p_ext != EXT_LAST_EXTENT(path[depth].p_hdr))

			  return le32_to_cpu(path[depth].p_ext[1].ee_block);
		} else {
			
			if (path[depth].p_idx != EXT_LAST_INDEX(path[depth].p_hdr))
			  return le32_to_cpu(path[depth].p_idx[1].ei_block);
		}
		depth--;
	}

	return EXT_MAX_BLOCKS;
}


static ext4_lblk_t ext4_ext_next_leaf_block(struct ext4_ext_path *path)
{
	int depth;

	BUG_ON(path == NULL);
	depth = path->p_depth;

	
	if (depth == 0)
		return EXT_MAX_BLOCKS;

	
	depth--;

	while (depth >= 0) {
		if (path[depth].p_idx != EXT_LAST_INDEX(path[depth].p_hdr))
			return (ext4_lblk_t)
				le32_to_cpu(path[depth].p_idx[1].ei_block);
		depth--;
	}

	return EXT_MAX_BLOCKS;
}


static int ext4_ext_correct_indexes(handle_t *handle, struct inode *inode, struct ext4_ext_path *path)
{
	struct ext4_extent_header *eh;
	int depth = ext_depth(inode);
	struct ext4_extent *ex;
	__le32 border;
	int k, err = 0;

	eh = path[depth].p_hdr;
	ex = path[depth].p_ext;

	if (unlikely(ex == NULL || eh == NULL)) {
		EXT4_ERROR_INODE(inode, "ex %p == NULL or eh %p == NULL", ex, eh);
		return -EFSCORRUPTED;
	}

	if (depth == 0) {
		
		return 0;
	}

	if (ex != EXT_FIRST_EXTENT(eh)) {
		
		return 0;
	}

	
	k = depth - 1;
	border = path[depth].p_ext->ee_block;
	err = ext4_ext_get_access(handle, inode, path + k);
	if (err)
		return err;
	path[k].p_idx->ei_block = border;
	err = ext4_ext_dirty(handle, inode, path + k);
	if (err)
		return err;

	while (k--) {
		
		if (path[k+1].p_idx != EXT_FIRST_INDEX(path[k+1].p_hdr))
			break;
		err = ext4_ext_get_access(handle, inode, path + k);
		if (err)
			break;
		path[k].p_idx->ei_block = border;
		err = ext4_ext_dirty(handle, inode, path + k);
		if (err)
			break;
	}

	return err;
}

int ext4_can_extents_be_merged(struct inode *inode, struct ext4_extent *ex1, struct ext4_extent *ex2)

{
	unsigned short ext1_ee_len, ext2_ee_len;

	if (ext4_ext_is_unwritten(ex1) != ext4_ext_is_unwritten(ex2))
		return 0;

	ext1_ee_len = ext4_ext_get_actual_len(ex1);
	ext2_ee_len = ext4_ext_get_actual_len(ex2);

	if (le32_to_cpu(ex1->ee_block) + ext1_ee_len != le32_to_cpu(ex2->ee_block))
		return 0;

	
	if (ext1_ee_len + ext2_ee_len > EXT_INIT_MAX_LEN)
		return 0;
	
	if (ext4_ext_is_unwritten(ex1) && (ext4_test_inode_state(inode, EXT4_STATE_DIO_UNWRITTEN) || atomic_read(&EXT4_I(inode)->i_unwritten) || (ext1_ee_len + ext2_ee_len > EXT_UNWRITTEN_MAX_LEN)))


		return 0;

	if (ext1_ee_len >= 4)
		return 0;


	if (ext4_ext_pblock(ex1) + ext1_ee_len == ext4_ext_pblock(ex2))
		return 1;
	return 0;
}


static int ext4_ext_try_to_merge_right(struct inode *inode, struct ext4_ext_path *path, struct ext4_extent *ex)

{
	struct ext4_extent_header *eh;
	unsigned int depth, len;
	int merge_done = 0, unwritten;

	depth = ext_depth(inode);
	BUG_ON(path[depth].p_hdr == NULL);
	eh = path[depth].p_hdr;

	while (ex < EXT_LAST_EXTENT(eh)) {
		if (!ext4_can_extents_be_merged(inode, ex, ex + 1))
			break;
		
		unwritten = ext4_ext_is_unwritten(ex);
		ex->ee_len = cpu_to_le16(ext4_ext_get_actual_len(ex)
				+ ext4_ext_get_actual_len(ex + 1));
		if (unwritten)
			ext4_ext_mark_unwritten(ex);

		if (ex + 1 < EXT_LAST_EXTENT(eh)) {
			len = (EXT_LAST_EXTENT(eh) - ex - 1)
				* sizeof(struct ext4_extent);
			memmove(ex + 1, ex + 2, len);
		}
		le16_add_cpu(&eh->eh_entries, -1);
		merge_done = 1;
		WARN_ON(eh->eh_entries == 0);
		if (!eh->eh_entries)
			EXT4_ERROR_INODE(inode, "eh->eh_entries = 0!");
	}

	return merge_done;
}


static void ext4_ext_try_to_merge_up(handle_t *handle, struct inode *inode, struct ext4_ext_path *path)

{
	size_t s;
	unsigned max_root = ext4_ext_space_root(inode, 0);
	ext4_fsblk_t blk;

	if ((path[0].p_depth != 1) || (le16_to_cpu(path[0].p_hdr->eh_entries) != 1) || (le16_to_cpu(path[1].p_hdr->eh_entries) > max_root))

		return;

	
	if (ext4_journal_extend(handle, 2))
		return;

	
	blk = ext4_idx_pblock(path[0].p_idx);
	s = le16_to_cpu(path[1].p_hdr->eh_entries) * sizeof(struct ext4_extent_idx);
	s += sizeof(struct ext4_extent_header);

	path[1].p_maxdepth = path[0].p_maxdepth;
	memcpy(path[0].p_hdr, path[1].p_hdr, s);
	path[0].p_depth = 0;
	path[0].p_ext = EXT_FIRST_EXTENT(path[0].p_hdr) + (path[1].p_ext - EXT_FIRST_EXTENT(path[1].p_hdr));
	path[0].p_hdr->eh_max = cpu_to_le16(max_root);

	brelse(path[1].p_bh);
	ext4_free_blocks(handle, inode, NULL, blk, 1, EXT4_FREE_BLOCKS_METADATA | EXT4_FREE_BLOCKS_FORGET);
}


static void ext4_ext_try_to_merge(handle_t *handle, struct inode *inode, struct ext4_ext_path *path, struct ext4_extent *ex) {


	struct ext4_extent_header *eh;
	unsigned int depth;
	int merge_done = 0;

	depth = ext_depth(inode);
	BUG_ON(path[depth].p_hdr == NULL);
	eh = path[depth].p_hdr;

	if (ex > EXT_FIRST_EXTENT(eh))
		merge_done = ext4_ext_try_to_merge_right(inode, path, ex - 1);

	if (!merge_done)
		(void) ext4_ext_try_to_merge_right(inode, path, ex);

	ext4_ext_try_to_merge_up(handle, inode, path);
}


static unsigned int ext4_ext_check_overlap(struct ext4_sb_info *sbi, struct inode *inode, struct ext4_extent *newext, struct ext4_ext_path *path)


{
	ext4_lblk_t b1, b2;
	unsigned int depth, len1;
	unsigned int ret = 0;

	b1 = le32_to_cpu(newext->ee_block);
	len1 = ext4_ext_get_actual_len(newext);
	depth = ext_depth(inode);
	if (!path[depth].p_ext)
		goto out;
	b2 = EXT4_LBLK_CMASK(sbi, le32_to_cpu(path[depth].p_ext->ee_block));

	
	if (b2 < b1) {
		b2 = ext4_ext_next_allocated_block(path);
		if (b2 == EXT_MAX_BLOCKS)
			goto out;
		b2 = EXT4_LBLK_CMASK(sbi, b2);
	}

	
	if (b1 + len1 < b1) {
		len1 = EXT_MAX_BLOCKS - b1;
		newext->ee_len = cpu_to_le16(len1);
		ret = 1;
	}

	
	if (b1 + len1 > b2) {
		newext->ee_len = cpu_to_le16(b2 - b1);
		ret = 1;
	}
out:
	return ret;
}


int ext4_ext_insert_extent(handle_t *handle, struct inode *inode, struct ext4_ext_path **ppath, struct ext4_extent *newext, int gb_flags)

{
	struct ext4_ext_path *path = *ppath;
	struct ext4_extent_header *eh;
	struct ext4_extent *ex, *fex;
	struct ext4_extent *nearex; 
	struct ext4_ext_path *npath = NULL;
	int depth, len, err;
	ext4_lblk_t next;
	int mb_flags = 0, unwritten;

	if (gb_flags & EXT4_GET_BLOCKS_DELALLOC_RESERVE)
		mb_flags |= EXT4_MB_DELALLOC_RESERVED;
	if (unlikely(ext4_ext_get_actual_len(newext) == 0)) {
		EXT4_ERROR_INODE(inode, "ext4_ext_get_actual_len(newext) == 0");
		return -EFSCORRUPTED;
	}
	depth = ext_depth(inode);
	ex = path[depth].p_ext;
	eh = path[depth].p_hdr;
	if (unlikely(path[depth].p_hdr == NULL)) {
		EXT4_ERROR_INODE(inode, "path[%d].p_hdr == NULL", depth);
		return -EFSCORRUPTED;
	}

	
	if (ex && !(gb_flags & EXT4_GET_BLOCKS_PRE_IO)) {

		
		if (ex < EXT_LAST_EXTENT(eh) && (le32_to_cpu(ex->ee_block) + ext4_ext_get_actual_len(ex) < le32_to_cpu(newext->ee_block))) {


			ex += 1;
			goto prepend;
		} else if ((ex > EXT_FIRST_EXTENT(eh)) && (le32_to_cpu(newext->ee_block) + ext4_ext_get_actual_len(newext) < le32_to_cpu(ex->ee_block)))


			ex -= 1;

		
		if (ext4_can_extents_be_merged(inode, ex, newext)) {
			ext_debug("append [%d]%d block to %u:[%d]%d" "(from %llu)\n", ext4_ext_is_unwritten(newext), ext4_ext_get_actual_len(newext), le32_to_cpu(ex->ee_block), ext4_ext_is_unwritten(ex), ext4_ext_get_actual_len(ex), ext4_ext_pblock(ex));






			err = ext4_ext_get_access(handle, inode, path + depth);
			if (err)
				return err;
			unwritten = ext4_ext_is_unwritten(ex);
			ex->ee_len = cpu_to_le16(ext4_ext_get_actual_len(ex)
					+ ext4_ext_get_actual_len(newext));
			if (unwritten)
				ext4_ext_mark_unwritten(ex);
			eh = path[depth].p_hdr;
			nearex = ex;
			goto merge;
		}

prepend:
		
		if (ext4_can_extents_be_merged(inode, newext, ex)) {
			ext_debug("prepend %u[%d]%d block to %u:[%d]%d" "(from %llu)\n", le32_to_cpu(newext->ee_block), ext4_ext_is_unwritten(newext), ext4_ext_get_actual_len(newext), le32_to_cpu(ex->ee_block), ext4_ext_is_unwritten(ex), ext4_ext_get_actual_len(ex), ext4_ext_pblock(ex));







			err = ext4_ext_get_access(handle, inode, path + depth);
			if (err)
				return err;

			unwritten = ext4_ext_is_unwritten(ex);
			ex->ee_block = newext->ee_block;
			ext4_ext_store_pblock(ex, ext4_ext_pblock(newext));
			ex->ee_len = cpu_to_le16(ext4_ext_get_actual_len(ex)
					+ ext4_ext_get_actual_len(newext));
			if (unwritten)
				ext4_ext_mark_unwritten(ex);
			eh = path[depth].p_hdr;
			nearex = ex;
			goto merge;
		}
	}

	depth = ext_depth(inode);
	eh = path[depth].p_hdr;
	if (le16_to_cpu(eh->eh_entries) < le16_to_cpu(eh->eh_max))
		goto has_space;

	
	fex = EXT_LAST_EXTENT(eh);
	next = EXT_MAX_BLOCKS;
	if (le32_to_cpu(newext->ee_block) > le32_to_cpu(fex->ee_block))
		next = ext4_ext_next_leaf_block(path);
	if (next != EXT_MAX_BLOCKS) {
		ext_debug("next leaf block - %u\n", next);
		BUG_ON(npath != NULL);
		npath = ext4_find_extent(inode, next, NULL, 0);
		if (IS_ERR(npath))
			return PTR_ERR(npath);
		BUG_ON(npath->p_depth != path->p_depth);
		eh = npath[depth].p_hdr;
		if (le16_to_cpu(eh->eh_entries) < le16_to_cpu(eh->eh_max)) {
			ext_debug("next leaf isn't full(%d)\n", le16_to_cpu(eh->eh_entries));
			path = npath;
			goto has_space;
		}
		ext_debug("next leaf has no free space(%d,%d)\n", le16_to_cpu(eh->eh_entries), le16_to_cpu(eh->eh_max));
	}

	
	if (gb_flags & EXT4_GET_BLOCKS_METADATA_NOFAIL)
		mb_flags |= EXT4_MB_USE_RESERVED;
	err = ext4_ext_create_new_leaf(handle, inode, mb_flags, gb_flags, ppath, newext);
	if (err)
		goto cleanup;
	depth = ext_depth(inode);
	eh = path[depth].p_hdr;

has_space:
	nearex = path[depth].p_ext;

	err = ext4_ext_get_access(handle, inode, path + depth);
	if (err)
		goto cleanup;

	if (!nearex) {
		
		ext_debug("first extent in the leaf: %u:%llu:[%d]%d\n", le32_to_cpu(newext->ee_block), ext4_ext_pblock(newext), ext4_ext_is_unwritten(newext), ext4_ext_get_actual_len(newext));



		nearex = EXT_FIRST_EXTENT(eh);
	} else {
		if (le32_to_cpu(newext->ee_block)
			   > le32_to_cpu(nearex->ee_block)) {
			
			ext_debug("insert %u:%llu:[%d]%d before: " "nearest %p\n", le32_to_cpu(newext->ee_block), ext4_ext_pblock(newext), ext4_ext_is_unwritten(newext), ext4_ext_get_actual_len(newext), nearex);





			nearex++;
		} else {
			
			BUG_ON(newext->ee_block == nearex->ee_block);
			ext_debug("insert %u:%llu:[%d]%d after: " "nearest %p\n", le32_to_cpu(newext->ee_block), ext4_ext_pblock(newext), ext4_ext_is_unwritten(newext), ext4_ext_get_actual_len(newext), nearex);





		}
		len = EXT_LAST_EXTENT(eh) - nearex + 1;
		if (len > 0) {
			ext_debug("insert %u:%llu:[%d]%d: " "move %d extents from 0x%p to 0x%p\n", le32_to_cpu(newext->ee_block), ext4_ext_pblock(newext), ext4_ext_is_unwritten(newext), ext4_ext_get_actual_len(newext), len, nearex, nearex + 1);





			memmove(nearex + 1, nearex, len * sizeof(struct ext4_extent));
		}
	}

	le16_add_cpu(&eh->eh_entries, 1);
	path[depth].p_ext = nearex;
	nearex->ee_block = newext->ee_block;
	ext4_ext_store_pblock(nearex, ext4_ext_pblock(newext));
	nearex->ee_len = newext->ee_len;

merge:
	
	if (!(gb_flags & EXT4_GET_BLOCKS_PRE_IO))
		ext4_ext_try_to_merge(handle, inode, path, nearex);


	
	err = ext4_ext_correct_indexes(handle, inode, path);
	if (err)
		goto cleanup;

	err = ext4_ext_dirty(handle, inode, path + path->p_depth);

cleanup:
	ext4_ext_drop_refs(npath);
	kfree(npath);
	return err;
}

static int ext4_fill_fiemap_extents(struct inode *inode, ext4_lblk_t block, ext4_lblk_t num, struct fiemap_extent_info *fieinfo)

{
	struct ext4_ext_path *path = NULL;
	struct ext4_extent *ex;
	struct extent_status es;
	ext4_lblk_t next, next_del, start = 0, end = 0;
	ext4_lblk_t last = block + num;
	int exists, depth = 0, err = 0;
	unsigned int flags = 0;
	unsigned char blksize_bits = inode->i_sb->s_blocksize_bits;

	while (block < last && block != EXT_MAX_BLOCKS) {
		num = last - block;
		
		down_read(&EXT4_I(inode)->i_data_sem);

		path = ext4_find_extent(inode, block, &path, 0);
		if (IS_ERR(path)) {
			up_read(&EXT4_I(inode)->i_data_sem);
			err = PTR_ERR(path);
			path = NULL;
			break;
		}

		depth = ext_depth(inode);
		if (unlikely(path[depth].p_hdr == NULL)) {
			up_read(&EXT4_I(inode)->i_data_sem);
			EXT4_ERROR_INODE(inode, "path[%d].p_hdr == NULL", depth);
			err = -EFSCORRUPTED;
			break;
		}
		ex = path[depth].p_ext;
		next = ext4_ext_next_allocated_block(path);

		flags = 0;
		exists = 0;
		if (!ex) {
			
			start = block;
			end = block + num;
		} else if (le32_to_cpu(ex->ee_block) > block) {
			
			start = block;
			end = le32_to_cpu(ex->ee_block);
			if (block + num < end)
				end = block + num;
		} else if (block >= le32_to_cpu(ex->ee_block)
					+ ext4_ext_get_actual_len(ex)) {
			
			start = block;
			end = block + num;
			if (end >= next)
				end = next;
		} else if (block >= le32_to_cpu(ex->ee_block)) {
			
			start = block;
			end = le32_to_cpu(ex->ee_block)
				+ ext4_ext_get_actual_len(ex);
			if (block + num < end)
				end = block + num;
			exists = 1;
		} else {
			BUG();
		}
		BUG_ON(end <= start);

		if (!exists) {
			es.es_lblk = start;
			es.es_len = end - start;
			es.es_pblk = 0;
		} else {
			es.es_lblk = le32_to_cpu(ex->ee_block);
			es.es_len = ext4_ext_get_actual_len(ex);
			es.es_pblk = ext4_ext_pblock(ex);
			if (ext4_ext_is_unwritten(ex))
				flags |= FIEMAP_EXTENT_UNWRITTEN;
		}

		
		next_del = ext4_find_delayed_extent(inode, &es);
		if (!exists && next_del) {
			exists = 1;
			flags |= (FIEMAP_EXTENT_DELALLOC | FIEMAP_EXTENT_UNKNOWN);
		}
		up_read(&EXT4_I(inode)->i_data_sem);

		if (unlikely(es.es_len == 0)) {
			EXT4_ERROR_INODE(inode, "es.es_len == 0");
			err = -EFSCORRUPTED;
			break;
		}

		
		if (next == next_del && next == EXT_MAX_BLOCKS) {
			flags |= FIEMAP_EXTENT_LAST;
			if (unlikely(next_del != EXT_MAX_BLOCKS || next != EXT_MAX_BLOCKS)) {
				EXT4_ERROR_INODE(inode, "next extent == %u, next " "delalloc extent = %u", next, next_del);


				err = -EFSCORRUPTED;
				break;
			}
		}

		if (exists) {
			err = fiemap_fill_next_extent(fieinfo, (__u64)es.es_lblk << blksize_bits, (__u64)es.es_pblk << blksize_bits, (__u64)es.es_len << blksize_bits, flags);



			if (err < 0)
				break;
			if (err == 1) {
				err = 0;
				break;
			}
		}

		block = es.es_lblk + es.es_len;
	}

	ext4_ext_drop_refs(path);
	kfree(path);
	return err;
}


static ext4_lblk_t ext4_ext_determine_hole(struct inode *inode, struct ext4_ext_path *path, ext4_lblk_t *lblk)

{
	int depth = ext_depth(inode);
	struct ext4_extent *ex;
	ext4_lblk_t len;

	ex = path[depth].p_ext;
	if (ex == NULL) {
		
		*lblk = 0;
		len = EXT_MAX_BLOCKS;
	} else if (*lblk < le32_to_cpu(ex->ee_block)) {
		len = le32_to_cpu(ex->ee_block) - *lblk;
	} else if (*lblk >= le32_to_cpu(ex->ee_block)
			+ ext4_ext_get_actual_len(ex)) {
		ext4_lblk_t next;

		*lblk = le32_to_cpu(ex->ee_block) + ext4_ext_get_actual_len(ex);
		next = ext4_ext_next_allocated_block(path);
		BUG_ON(next == *lblk);
		len = next - *lblk;
	} else {
		BUG();
	}
	return len;
}


static void ext4_ext_put_gap_in_cache(struct inode *inode, ext4_lblk_t hole_start, ext4_lblk_t hole_len)

{
	struct extent_status es;

	ext4_es_find_extent_range(inode, &ext4_es_is_delayed, hole_start, hole_start + hole_len - 1, &es);
	if (es.es_len) {
		
		if (es.es_lblk <= hole_start)
			return;
		hole_len = min(es.es_lblk - hole_start, hole_len);
	}
	ext_debug(" -> %u:%u\n", hole_start, hole_len);
	ext4_es_insert_extent(inode, hole_start, hole_len, ~0, EXTENT_STATUS_HOLE);
}


static int ext4_ext_rm_idx(handle_t *handle, struct inode *inode, struct ext4_ext_path *path, int depth)
{
	int err;
	ext4_fsblk_t leaf;

	
	depth--;
	path = path + depth;
	leaf = ext4_idx_pblock(path->p_idx);
	if (unlikely(path->p_hdr->eh_entries == 0)) {
		EXT4_ERROR_INODE(inode, "path->p_hdr->eh_entries == 0");
		return -EFSCORRUPTED;
	}
	err = ext4_ext_get_access(handle, inode, path);
	if (err)
		return err;

	if (path->p_idx != EXT_LAST_INDEX(path->p_hdr)) {
		int len = EXT_LAST_INDEX(path->p_hdr) - path->p_idx;
		len *= sizeof(struct ext4_extent_idx);
		memmove(path->p_idx, path->p_idx + 1, len);
	}

	le16_add_cpu(&path->p_hdr->eh_entries, -1);
	err = ext4_ext_dirty(handle, inode, path);
	if (err)
		return err;
	ext_debug("index is empty, remove it, free block %llu\n", leaf);
	trace_ext4_ext_rm_idx(inode, leaf);

	ext4_free_blocks(handle, inode, NULL, leaf, 1, EXT4_FREE_BLOCKS_METADATA | EXT4_FREE_BLOCKS_FORGET);

	while (--depth >= 0) {
		if (path->p_idx != EXT_FIRST_INDEX(path->p_hdr))
			break;
		path--;
		err = ext4_ext_get_access(handle, inode, path);
		if (err)
			break;
		path->p_idx->ei_block = (path+1)->p_idx->ei_block;
		err = ext4_ext_dirty(handle, inode, path);
		if (err)
			break;
	}
	return err;
}


int ext4_ext_calc_credits_for_single_extent(struct inode *inode, int nrblocks, struct ext4_ext_path *path)
{
	if (path) {
		int depth = ext_depth(inode);
		int ret = 0;

		
		if (le16_to_cpu(path[depth].p_hdr->eh_entries)
				< le16_to_cpu(path[depth].p_hdr->eh_max)) {

			
			
			ret = 2 + EXT4_META_TRANS_BLOCKS(inode->i_sb);
			return ret;
		}
	}

	return ext4_chunk_trans_blocks(inode, nrblocks);
}


int ext4_ext_index_trans_blocks(struct inode *inode, int extents)
{
	int index;
	int depth;

	
	if (ext4_has_inline_data(inode))
		return 1;

	depth = ext_depth(inode);

	if (extents <= 1)
		index = depth * 2;
	else index = depth * 3;

	return index;
}

static inline int get_default_free_blocks_flags(struct inode *inode)
{
	if (S_ISDIR(inode->i_mode) || S_ISLNK(inode->i_mode) || ext4_test_inode_flag(inode, EXT4_INODE_EA_INODE))
		return EXT4_FREE_BLOCKS_METADATA | EXT4_FREE_BLOCKS_FORGET;
	else if (ext4_should_journal_data(inode))
		return EXT4_FREE_BLOCKS_FORGET;
	return 0;
}


static void ext4_rereserve_cluster(struct inode *inode, ext4_lblk_t lblk)
{
	struct ext4_sb_info *sbi = EXT4_SB(inode->i_sb);
	struct ext4_inode_info *ei = EXT4_I(inode);

	dquot_reclaim_block(inode, EXT4_C2B(sbi, 1));

	spin_lock(&ei->i_block_reservation_lock);
	ei->i_reserved_data_blocks++;
	percpu_counter_add(&sbi->s_dirtyclusters_counter, 1);
	spin_unlock(&ei->i_block_reservation_lock);

	percpu_counter_add(&sbi->s_freeclusters_counter, 1);
	ext4_remove_pending(inode, lblk);
}

static int ext4_remove_blocks(handle_t *handle, struct inode *inode, struct ext4_extent *ex, struct partial_cluster *partial, ext4_lblk_t from, ext4_lblk_t to)


{
	struct ext4_sb_info *sbi = EXT4_SB(inode->i_sb);
	unsigned short ee_len = ext4_ext_get_actual_len(ex);
	ext4_fsblk_t last_pblk, pblk;
	ext4_lblk_t num;
	int flags;

	
	if (from < le32_to_cpu(ex->ee_block) || to != le32_to_cpu(ex->ee_block) + ee_len - 1) {
		ext4_error(sbi->s_sb, "strange request: removal(2) %u-%u from %u:%u", from, to, le32_to_cpu(ex->ee_block), ee_len);

		return 0;
	}


	spin_lock(&sbi->s_ext_stats_lock);
	sbi->s_ext_blocks += ee_len;
	sbi->s_ext_extents++;
	if (ee_len < sbi->s_ext_min)
		sbi->s_ext_min = ee_len;
	if (ee_len > sbi->s_ext_max)
		sbi->s_ext_max = ee_len;
	if (ext_depth(inode) > sbi->s_depth_max)
		sbi->s_depth_max = ext_depth(inode);
	spin_unlock(&sbi->s_ext_stats_lock);


	trace_ext4_remove_blocks(inode, ex, from, to, partial);

	
	last_pblk = ext4_ext_pblock(ex) + ee_len - 1;

	if (partial->state != initial && partial->pclu != EXT4_B2C(sbi, last_pblk)) {
		if (partial->state == tofree) {
			flags = get_default_free_blocks_flags(inode);
			if (ext4_is_pending(inode, partial->lblk))
				flags |= EXT4_FREE_BLOCKS_RERESERVE_CLUSTER;
			ext4_free_blocks(handle, inode, NULL, EXT4_C2B(sbi, partial->pclu), sbi->s_cluster_ratio, flags);

			if (flags & EXT4_FREE_BLOCKS_RERESERVE_CLUSTER)
				ext4_rereserve_cluster(inode, partial->lblk);
		}
		partial->state = initial;
	}

	num = le32_to_cpu(ex->ee_block) + ee_len - from;
	pblk = ext4_ext_pblock(ex) + ee_len - num;

	
	flags = get_default_free_blocks_flags(inode);

	
	if ((EXT4_LBLK_COFF(sbi, to) != sbi->s_cluster_ratio - 1) && (EXT4_LBLK_CMASK(sbi, to) >= from) && (partial->state != nofree)) {

		if (ext4_is_pending(inode, to))
			flags |= EXT4_FREE_BLOCKS_RERESERVE_CLUSTER;
		ext4_free_blocks(handle, inode, NULL, EXT4_PBLK_CMASK(sbi, last_pblk), sbi->s_cluster_ratio, flags);

		if (flags & EXT4_FREE_BLOCKS_RERESERVE_CLUSTER)
			ext4_rereserve_cluster(inode, to);
		partial->state = initial;
		flags = get_default_free_blocks_flags(inode);
	}

	flags |= EXT4_FREE_BLOCKS_NOFREE_LAST_CLUSTER;

	
	flags |= EXT4_FREE_BLOCKS_NOFREE_FIRST_CLUSTER;
	ext4_free_blocks(handle, inode, NULL, pblk, num, flags);

	
	if (partial->state != initial && partial->pclu != EXT4_B2C(sbi, pblk))
		partial->state = initial;

	
	if (EXT4_LBLK_COFF(sbi, from) && num == ee_len) {
		if (partial->state == initial) {
			partial->pclu = EXT4_B2C(sbi, pblk);
			partial->lblk = from;
			partial->state = tofree;
		}
	} else {
		partial->state = initial;
	}

	return 0;
}


static int ext4_ext_rm_leaf(handle_t *handle, struct inode *inode, struct ext4_ext_path *path, struct partial_cluster *partial, ext4_lblk_t start, ext4_lblk_t end)



{
	struct ext4_sb_info *sbi = EXT4_SB(inode->i_sb);
	int err = 0, correct_index = 0;
	int depth = ext_depth(inode), credits;
	struct ext4_extent_header *eh;
	ext4_lblk_t a, b;
	unsigned num;
	ext4_lblk_t ex_ee_block;
	unsigned short ex_ee_len;
	unsigned unwritten = 0;
	struct ext4_extent *ex;
	ext4_fsblk_t pblk;

	
	ext_debug("truncate since %u in leaf to %u\n", start, end);
	if (!path[depth].p_hdr)
		path[depth].p_hdr = ext_block_hdr(path[depth].p_bh);
	eh = path[depth].p_hdr;
	if (unlikely(path[depth].p_hdr == NULL)) {
		EXT4_ERROR_INODE(inode, "path[%d].p_hdr == NULL", depth);
		return -EFSCORRUPTED;
	}
	
	ex = path[depth].p_ext;
	if (!ex)
		ex = EXT_LAST_EXTENT(eh);

	ex_ee_block = le32_to_cpu(ex->ee_block);
	ex_ee_len = ext4_ext_get_actual_len(ex);

	trace_ext4_ext_rm_leaf(inode, start, ex, partial);

	while (ex >= EXT_FIRST_EXTENT(eh) && ex_ee_block + ex_ee_len > start) {

		if (ext4_ext_is_unwritten(ex))
			unwritten = 1;
		else unwritten = 0;

		ext_debug("remove ext %u:[%d]%d\n", ex_ee_block, unwritten, ex_ee_len);
		path[depth].p_ext = ex;

		a = ex_ee_block > start ? ex_ee_block : start;
		b = ex_ee_block+ex_ee_len - 1 < end ? ex_ee_block+ex_ee_len - 1 : end;

		ext_debug("  border %u:%u\n", a, b);

		
		if (end < ex_ee_block) {
			
			if (sbi->s_cluster_ratio > 1) {
				pblk = ext4_ext_pblock(ex);
				partial->pclu = EXT4_B2C(sbi, pblk);
				partial->state = nofree;
			}
			ex--;
			ex_ee_block = le32_to_cpu(ex->ee_block);
			ex_ee_len = ext4_ext_get_actual_len(ex);
			continue;
		} else if (b != ex_ee_block + ex_ee_len - 1) {
			EXT4_ERROR_INODE(inode, "can not handle truncate %u:%u " "on extent %u:%u", start, end, ex_ee_block, ex_ee_block + ex_ee_len - 1);



			err = -EFSCORRUPTED;
			goto out;
		} else if (a != ex_ee_block) {
			
			num = a - ex_ee_block;
		} else {
			
			num = 0;
		}
		
		credits = 7 + 2*(ex_ee_len/EXT4_BLOCKS_PER_GROUP(inode->i_sb));
		if (ex == EXT_FIRST_EXTENT(eh)) {
			correct_index = 1;
			credits += (ext_depth(inode)) + 1;
		}
		credits += EXT4_MAXQUOTAS_TRANS_BLOCKS(inode->i_sb);

		err = ext4_ext_truncate_extend_restart(handle, inode, credits);
		if (err)
			goto out;

		err = ext4_ext_get_access(handle, inode, path + depth);
		if (err)
			goto out;

		err = ext4_remove_blocks(handle, inode, ex, partial, a, b);
		if (err)
			goto out;

		if (num == 0)
			
			ext4_ext_store_pblock(ex, 0);

		ex->ee_len = cpu_to_le16(num);
		
		if (unwritten && num)
			ext4_ext_mark_unwritten(ex);
		
		if (num == 0) {
			if (end != EXT_MAX_BLOCKS - 1) {
				
				memmove(ex, ex+1, (EXT_LAST_EXTENT(eh) - ex) * sizeof(struct ext4_extent));

				
				memset(EXT_LAST_EXTENT(eh), 0, sizeof(struct ext4_extent));
			}
			le16_add_cpu(&eh->eh_entries, -1);
		}

		err = ext4_ext_dirty(handle, inode, path + depth);
		if (err)
			goto out;

		ext_debug("new extent: %u:%u:%llu\n", ex_ee_block, num, ext4_ext_pblock(ex));
		ex--;
		ex_ee_block = le32_to_cpu(ex->ee_block);
		ex_ee_len = ext4_ext_get_actual_len(ex);
	}

	if (correct_index && eh->eh_entries)
		err = ext4_ext_correct_indexes(handle, inode, path);

	
	if (partial->state == tofree && ex >= EXT_FIRST_EXTENT(eh)) {
		pblk = ext4_ext_pblock(ex) + ex_ee_len - 1;
		if (partial->pclu != EXT4_B2C(sbi, pblk)) {
			int flags = get_default_free_blocks_flags(inode);

			if (ext4_is_pending(inode, partial->lblk))
				flags |= EXT4_FREE_BLOCKS_RERESERVE_CLUSTER;
			ext4_free_blocks(handle, inode, NULL, EXT4_C2B(sbi, partial->pclu), sbi->s_cluster_ratio, flags);

			if (flags & EXT4_FREE_BLOCKS_RERESERVE_CLUSTER)
				ext4_rereserve_cluster(inode, partial->lblk);
		}
		partial->state = initial;
	}

	
	if (err == 0 && eh->eh_entries == 0 && path[depth].p_bh != NULL)
		err = ext4_ext_rm_idx(handle, inode, path, depth);

out:
	return err;
}


static int ext4_ext_more_to_rm(struct ext4_ext_path *path)
{
	BUG_ON(path->p_idx == NULL);

	if (path->p_idx < EXT_FIRST_INDEX(path->p_hdr))
		return 0;

	
	if (le16_to_cpu(path->p_hdr->eh_entries) == path->p_block)
		return 0;
	return 1;
}

int ext4_ext_remove_space(struct inode *inode, ext4_lblk_t start, ext4_lblk_t end)
{
	struct ext4_sb_info *sbi = EXT4_SB(inode->i_sb);
	int depth = ext_depth(inode);
	struct ext4_ext_path *path = NULL;
	struct partial_cluster partial;
	handle_t *handle;
	int i = 0, err = 0;

	partial.pclu = 0;
	partial.lblk = 0;
	partial.state = initial;

	ext_debug("truncate since %u to %u\n", start, end);

	
	handle = ext4_journal_start(inode, EXT4_HT_TRUNCATE, depth + 1);
	if (IS_ERR(handle))
		return PTR_ERR(handle);

again:
	trace_ext4_ext_remove_space(inode, start, end, depth);

	
	if (end < EXT_MAX_BLOCKS - 1) {
		struct ext4_extent *ex;
		ext4_lblk_t ee_block, ex_end, lblk;
		ext4_fsblk_t pblk;

		
		path = ext4_find_extent(inode, end, NULL, EXT4_EX_NOCACHE);
		if (IS_ERR(path)) {
			ext4_journal_stop(handle);
			return PTR_ERR(path);
		}
		depth = ext_depth(inode);
		
		ex = path[depth].p_ext;
		if (!ex) {
			if (depth) {
				EXT4_ERROR_INODE(inode, "path[%d].p_hdr == NULL", depth);

				err = -EFSCORRUPTED;
			}
			goto out;
		}

		ee_block = le32_to_cpu(ex->ee_block);
		ex_end = ee_block + ext4_ext_get_actual_len(ex) - 1;

		
		if (end >= ee_block && end < ex_end) {

			
			if (sbi->s_cluster_ratio > 1) {
				pblk = ext4_ext_pblock(ex) + end - ee_block + 2;
				partial.pclu = EXT4_B2C(sbi, pblk);
				partial.state = nofree;
			}

			
			err = ext4_force_split_extent_at(handle, inode, &path, end + 1, 1);
			if (err < 0)
				goto out;

		} else if (sbi->s_cluster_ratio > 1 && end >= ex_end && partial.state == initial) {
			
			lblk = ex_end + 1;
			err = ext4_ext_search_right(inode, path, &lblk, &pblk, &ex);
			if (err)
				goto out;
			if (pblk) {
				partial.pclu = EXT4_B2C(sbi, pblk);
				partial.state = nofree;
			}
		}
	}
	
	depth = ext_depth(inode);
	if (path) {
		int k = i = depth;
		while (--k > 0)
			path[k].p_block = le16_to_cpu(path[k].p_hdr->eh_entries)+1;
	} else {
		path = kcalloc(depth + 1, sizeof(struct ext4_ext_path), GFP_NOFS);
		if (path == NULL) {
			ext4_journal_stop(handle);
			return -ENOMEM;
		}
		path[0].p_maxdepth = path[0].p_depth = depth;
		path[0].p_hdr = ext_inode_hdr(inode);
		i = 0;

		if (ext4_ext_check(inode, path[0].p_hdr, depth, 0)) {
			err = -EFSCORRUPTED;
			goto out;
		}
	}
	err = 0;

	while (i >= 0 && err == 0) {
		if (i == depth) {
			
			err = ext4_ext_rm_leaf(handle, inode, path, &partial, start, end);
			
			brelse(path[i].p_bh);
			path[i].p_bh = NULL;
			i--;
			continue;
		}

		
		if (!path[i].p_hdr) {
			ext_debug("initialize header\n");
			path[i].p_hdr = ext_block_hdr(path[i].p_bh);
		}

		if (!path[i].p_idx) {
			
			path[i].p_idx = EXT_LAST_INDEX(path[i].p_hdr);
			path[i].p_block = le16_to_cpu(path[i].p_hdr->eh_entries)+1;
			ext_debug("init index ptr: hdr 0x%p, num %d\n", path[i].p_hdr, le16_to_cpu(path[i].p_hdr->eh_entries));

		} else {
			
			path[i].p_idx--;
		}

		ext_debug("level %d - index, first 0x%p, cur 0x%p\n", i, EXT_FIRST_INDEX(path[i].p_hdr), path[i].p_idx);

		if (ext4_ext_more_to_rm(path + i)) {
			struct buffer_head *bh;
			
			ext_debug("move to level %d (block %llu)\n", i + 1, ext4_idx_pblock(path[i].p_idx));
			memset(path + i + 1, 0, sizeof(*path));
			bh = read_extent_tree_block(inode, ext4_idx_pblock(path[i].p_idx), depth - i - 1, EXT4_EX_NOCACHE);

			if (IS_ERR(bh)) {
				
				err = PTR_ERR(bh);
				break;
			}
			
			cond_resched();
			if (WARN_ON(i + 1 > depth)) {
				err = -EFSCORRUPTED;
				break;
			}
			path[i + 1].p_bh = bh;

			
			path[i].p_block = le16_to_cpu(path[i].p_hdr->eh_entries);
			i++;
		} else {
			
			if (path[i].p_hdr->eh_entries == 0 && i > 0) {
				
				err = ext4_ext_rm_idx(handle, inode, path, i);
			}
			
			brelse(path[i].p_bh);
			path[i].p_bh = NULL;
			i--;
			ext_debug("return to level %d\n", i);
		}
	}

	trace_ext4_ext_remove_space_done(inode, start, end, depth, &partial, path->p_hdr->eh_entries);

	
	if (partial.state == tofree && err == 0) {
		int flags = get_default_free_blocks_flags(inode);

		if (ext4_is_pending(inode, partial.lblk))
			flags |= EXT4_FREE_BLOCKS_RERESERVE_CLUSTER;
		ext4_free_blocks(handle, inode, NULL, EXT4_C2B(sbi, partial.pclu), sbi->s_cluster_ratio, flags);

		if (flags & EXT4_FREE_BLOCKS_RERESERVE_CLUSTER)
			ext4_rereserve_cluster(inode, partial.lblk);
		partial.state = initial;
	}

	
	if (path->p_hdr->eh_entries == 0) {
		
		err = ext4_ext_get_access(handle, inode, path);
		if (err == 0) {
			ext_inode_hdr(inode)->eh_depth = 0;
			ext_inode_hdr(inode)->eh_max = cpu_to_le16(ext4_ext_space_root(inode, 0));
			err = ext4_ext_dirty(handle, inode, path);
		}
	}
out:
	ext4_ext_drop_refs(path);
	kfree(path);
	path = NULL;
	if (err == -EAGAIN)
		goto again;
	ext4_journal_stop(handle);

	return err;
}


void ext4_ext_init(struct super_block *sb)
{
	

	if (ext4_has_feature_extents(sb)) {

		printk(KERN_INFO "EXT4-fs: file extents enabled"  ", aggressive tests"   ", check binsearch"   ", stats"  "\n");











		spin_lock_init(&EXT4_SB(sb)->s_ext_stats_lock);
		EXT4_SB(sb)->s_ext_min = 1 << 30;
		EXT4_SB(sb)->s_ext_max = 0;

	}
}


void ext4_ext_release(struct super_block *sb)
{
	if (!ext4_has_feature_extents(sb))
		return;


	if (EXT4_SB(sb)->s_ext_blocks && EXT4_SB(sb)->s_ext_extents) {
		struct ext4_sb_info *sbi = EXT4_SB(sb);
		printk(KERN_ERR "EXT4-fs: %lu blocks in %lu extents (%lu ave)\n", sbi->s_ext_blocks, sbi->s_ext_extents, sbi->s_ext_blocks / sbi->s_ext_extents);

		printk(KERN_ERR "EXT4-fs: extents: %lu min, %lu max, max depth %lu\n", sbi->s_ext_min, sbi->s_ext_max, sbi->s_depth_max);
	}

}

static int ext4_zeroout_es(struct inode *inode, struct ext4_extent *ex)
{
	ext4_lblk_t  ee_block;
	ext4_fsblk_t ee_pblock;
	unsigned int ee_len;

	ee_block  = le32_to_cpu(ex->ee_block);
	ee_len    = ext4_ext_get_actual_len(ex);
	ee_pblock = ext4_ext_pblock(ex);

	if (ee_len == 0)
		return 0;

	return ext4_es_insert_extent(inode, ee_block, ee_len, ee_pblock, EXTENT_STATUS_WRITTEN);
}


static int ext4_ext_zeroout(struct inode *inode, struct ext4_extent *ex)
{
	ext4_fsblk_t ee_pblock;
	unsigned int ee_len;

	ee_len    = ext4_ext_get_actual_len(ex);
	ee_pblock = ext4_ext_pblock(ex);
	return ext4_issue_zeroout(inode, le32_to_cpu(ex->ee_block), ee_pblock, ee_len);
}


static int ext4_split_extent_at(handle_t *handle, struct inode *inode, struct ext4_ext_path **ppath, ext4_lblk_t split, int split_flag, int flags)




{
	struct ext4_ext_path *path = *ppath;
	ext4_fsblk_t newblock;
	ext4_lblk_t ee_block;
	struct ext4_extent *ex, newex, orig_ex, zero_ex;
	struct ext4_extent *ex2 = NULL;
	unsigned int ee_len, depth;
	int err = 0;

	BUG_ON((split_flag & (EXT4_EXT_DATA_VALID1 | EXT4_EXT_DATA_VALID2)) == (EXT4_EXT_DATA_VALID1 | EXT4_EXT_DATA_VALID2));

	ext_debug("ext4_split_extents_at: inode %lu, logical" "block %llu\n", inode->i_ino, (unsigned long long)split);

	ext4_ext_show_leaf(inode, path);

	depth = ext_depth(inode);
	ex = path[depth].p_ext;
	ee_block = le32_to_cpu(ex->ee_block);
	ee_len = ext4_ext_get_actual_len(ex);
	newblock = split - ee_block + ext4_ext_pblock(ex);

	BUG_ON(split < ee_block || split >= (ee_block + ee_len));
	BUG_ON(!ext4_ext_is_unwritten(ex) && split_flag & (EXT4_EXT_MAY_ZEROOUT | EXT4_EXT_MARK_UNWRIT1 | EXT4_EXT_MARK_UNWRIT2));



	err = ext4_ext_get_access(handle, inode, path + depth);
	if (err)
		goto out;

	if (split == ee_block) {
		
		if (split_flag & EXT4_EXT_MARK_UNWRIT2)
			ext4_ext_mark_unwritten(ex);
		else ext4_ext_mark_initialized(ex);

		if (!(flags & EXT4_GET_BLOCKS_PRE_IO))
			ext4_ext_try_to_merge(handle, inode, path, ex);

		err = ext4_ext_dirty(handle, inode, path + path->p_depth);
		goto out;
	}

	
	memcpy(&orig_ex, ex, sizeof(orig_ex));
	ex->ee_len = cpu_to_le16(split - ee_block);
	if (split_flag & EXT4_EXT_MARK_UNWRIT1)
		ext4_ext_mark_unwritten(ex);

	
	err = ext4_ext_dirty(handle, inode, path + depth);
	if (err)
		goto fix_extent_len;

	ex2 = &newex;
	ex2->ee_block = cpu_to_le32(split);
	ex2->ee_len   = cpu_to_le16(ee_len - (split - ee_block));
	ext4_ext_store_pblock(ex2, newblock);
	if (split_flag & EXT4_EXT_MARK_UNWRIT2)
		ext4_ext_mark_unwritten(ex2);

	err = ext4_ext_insert_extent(handle, inode, ppath, &newex, flags);
	if (err == -ENOSPC && (EXT4_EXT_MAY_ZEROOUT & split_flag)) {
		if (split_flag & (EXT4_EXT_DATA_VALID1|EXT4_EXT_DATA_VALID2)) {
			if (split_flag & EXT4_EXT_DATA_VALID1) {
				err = ext4_ext_zeroout(inode, ex2);
				zero_ex.ee_block = ex2->ee_block;
				zero_ex.ee_len = cpu_to_le16( ext4_ext_get_actual_len(ex2));
				ext4_ext_store_pblock(&zero_ex, ext4_ext_pblock(ex2));
			} else {
				err = ext4_ext_zeroout(inode, ex);
				zero_ex.ee_block = ex->ee_block;
				zero_ex.ee_len = cpu_to_le16( ext4_ext_get_actual_len(ex));
				ext4_ext_store_pblock(&zero_ex, ext4_ext_pblock(ex));
			}
		} else {
			err = ext4_ext_zeroout(inode, &orig_ex);
			zero_ex.ee_block = orig_ex.ee_block;
			zero_ex.ee_len = cpu_to_le16( ext4_ext_get_actual_len(&orig_ex));
			ext4_ext_store_pblock(&zero_ex, ext4_ext_pblock(&orig_ex));
		}

		if (err)
			goto fix_extent_len;
		
		ex->ee_len = cpu_to_le16(ee_len);
		ext4_ext_try_to_merge(handle, inode, path, ex);
		err = ext4_ext_dirty(handle, inode, path + path->p_depth);
		if (err)
			goto fix_extent_len;

		
		err = ext4_zeroout_es(inode, &zero_ex);

		goto out;
	} else if (err)
		goto fix_extent_len;

out:
	ext4_ext_show_leaf(inode, path);
	return err;

fix_extent_len:
	ex->ee_len = orig_ex.ee_len;
	ext4_ext_dirty(handle, inode, path + path->p_depth);
	return err;
}


static int ext4_split_extent(handle_t *handle, struct inode *inode, struct ext4_ext_path **ppath, struct ext4_map_blocks *map, int split_flag, int flags)




{
	struct ext4_ext_path *path = *ppath;
	ext4_lblk_t ee_block;
	struct ext4_extent *ex;
	unsigned int ee_len, depth;
	int err = 0;
	int unwritten;
	int split_flag1, flags1;
	int allocated = map->m_len;

	depth = ext_depth(inode);
	ex = path[depth].p_ext;
	ee_block = le32_to_cpu(ex->ee_block);
	ee_len = ext4_ext_get_actual_len(ex);
	unwritten = ext4_ext_is_unwritten(ex);

	if (map->m_lblk + map->m_len < ee_block + ee_len) {
		split_flag1 = split_flag & EXT4_EXT_MAY_ZEROOUT;
		flags1 = flags | EXT4_GET_BLOCKS_PRE_IO;
		if (unwritten)
			split_flag1 |= EXT4_EXT_MARK_UNWRIT1 | EXT4_EXT_MARK_UNWRIT2;
		if (split_flag & EXT4_EXT_DATA_VALID2)
			split_flag1 |= EXT4_EXT_DATA_VALID1;
		err = ext4_split_extent_at(handle, inode, ppath, map->m_lblk + map->m_len, split_flag1, flags1);
		if (err)
			goto out;
	} else {
		allocated = ee_len - (map->m_lblk - ee_block);
	}
	
	path = ext4_find_extent(inode, map->m_lblk, ppath, 0);
	if (IS_ERR(path))
		return PTR_ERR(path);
	depth = ext_depth(inode);
	ex = path[depth].p_ext;
	if (!ex) {
		EXT4_ERROR_INODE(inode, "unexpected hole at %lu", (unsigned long) map->m_lblk);
		return -EFSCORRUPTED;
	}
	unwritten = ext4_ext_is_unwritten(ex);
	split_flag1 = 0;

	if (map->m_lblk >= ee_block) {
		split_flag1 = split_flag & EXT4_EXT_DATA_VALID2;
		if (unwritten) {
			split_flag1 |= EXT4_EXT_MARK_UNWRIT1;
			split_flag1 |= split_flag & (EXT4_EXT_MAY_ZEROOUT | EXT4_EXT_MARK_UNWRIT2);
		}
		err = ext4_split_extent_at(handle, inode, ppath, map->m_lblk, split_flag1, flags);
		if (err)
			goto out;
	}

	ext4_ext_show_leaf(inode, path);
out:
	return err ? err : allocated;
}


static int ext4_ext_convert_to_initialized(handle_t *handle, struct inode *inode, struct ext4_map_blocks *map, struct ext4_ext_path **ppath, int flags)



{
	struct ext4_ext_path *path = *ppath;
	struct ext4_sb_info *sbi;
	struct ext4_extent_header *eh;
	struct ext4_map_blocks split_map;
	struct ext4_extent zero_ex1, zero_ex2;
	struct ext4_extent *ex, *abut_ex;
	ext4_lblk_t ee_block, eof_block;
	unsigned int ee_len, depth, map_len = map->m_len;
	int allocated = 0, max_zeroout = 0;
	int err = 0;
	int split_flag = EXT4_EXT_DATA_VALID2;

	ext_debug("ext4_ext_convert_to_initialized: inode %lu, logical" "block %llu, max_blocks %u\n", inode->i_ino, (unsigned long long)map->m_lblk, map_len);


	sbi = EXT4_SB(inode->i_sb);
	eof_block = (inode->i_size + inode->i_sb->s_blocksize - 1) >> inode->i_sb->s_blocksize_bits;
	if (eof_block < map->m_lblk + map_len)
		eof_block = map->m_lblk + map_len;

	depth = ext_depth(inode);
	eh = path[depth].p_hdr;
	ex = path[depth].p_ext;
	ee_block = le32_to_cpu(ex->ee_block);
	ee_len = ext4_ext_get_actual_len(ex);
	zero_ex1.ee_len = 0;
	zero_ex2.ee_len = 0;

	trace_ext4_ext_convert_to_initialized_enter(inode, map, ex);

	
	BUG_ON(!ext4_ext_is_unwritten(ex));
	BUG_ON(!in_range(map->m_lblk, ee_block, ee_len));

	
	if ((map->m_lblk == ee_block) &&  (map_len < ee_len) && (ex > EXT_FIRST_EXTENT(eh))) {


		ext4_lblk_t prev_lblk;
		ext4_fsblk_t prev_pblk, ee_pblk;
		unsigned int prev_len;

		abut_ex = ex - 1;
		prev_lblk = le32_to_cpu(abut_ex->ee_block);
		prev_len = ext4_ext_get_actual_len(abut_ex);
		prev_pblk = ext4_ext_pblock(abut_ex);
		ee_pblk = ext4_ext_pblock(ex);

		
		if ((!ext4_ext_is_unwritten(abut_ex)) &&		 ((prev_lblk + prev_len) == ee_block) && ((prev_pblk + prev_len) == ee_pblk) && (prev_len < (EXT_INIT_MAX_LEN - map_len))) {


			err = ext4_ext_get_access(handle, inode, path + depth);
			if (err)
				goto out;

			trace_ext4_ext_convert_to_initialized_fastpath(inode, map, ex, abut_ex);

			
			ex->ee_block = cpu_to_le32(ee_block + map_len);
			ext4_ext_store_pblock(ex, ee_pblk + map_len);
			ex->ee_len = cpu_to_le16(ee_len - map_len);
			ext4_ext_mark_unwritten(ex); 

			
			abut_ex->ee_len = cpu_to_le16(prev_len + map_len);

			
			allocated = map_len;
		}
	} else if (((map->m_lblk + map_len) == (ee_block + ee_len)) && (map_len < ee_len) && ex < EXT_LAST_EXTENT(eh)) {

		
		ext4_lblk_t next_lblk;
		ext4_fsblk_t next_pblk, ee_pblk;
		unsigned int next_len;

		abut_ex = ex + 1;
		next_lblk = le32_to_cpu(abut_ex->ee_block);
		next_len = ext4_ext_get_actual_len(abut_ex);
		next_pblk = ext4_ext_pblock(abut_ex);
		ee_pblk = ext4_ext_pblock(ex);

		
		if ((!ext4_ext_is_unwritten(abut_ex)) &&		 ((map->m_lblk + map_len) == next_lblk) && ((ee_pblk + ee_len) == next_pblk) && (next_len < (EXT_INIT_MAX_LEN - map_len))) {


			err = ext4_ext_get_access(handle, inode, path + depth);
			if (err)
				goto out;

			trace_ext4_ext_convert_to_initialized_fastpath(inode, map, ex, abut_ex);

			
			abut_ex->ee_block = cpu_to_le32(next_lblk - map_len);
			ext4_ext_store_pblock(abut_ex, next_pblk - map_len);
			ex->ee_len = cpu_to_le16(ee_len - map_len);
			ext4_ext_mark_unwritten(ex); 

			
			abut_ex->ee_len = cpu_to_le16(next_len + map_len);

			
			allocated = map_len;
		}
	}
	if (allocated) {
		
		ext4_ext_dirty(handle, inode, path + depth);

		
		path[depth].p_ext = abut_ex;
		goto out;
	} else allocated = ee_len - (map->m_lblk - ee_block);

	WARN_ON(map->m_lblk < ee_block);
	
	split_flag |= ee_block + ee_len <= eof_block ? EXT4_EXT_MAY_ZEROOUT : 0;

	if (EXT4_EXT_MAY_ZEROOUT & split_flag)
		max_zeroout = sbi->s_extent_max_zeroout_kb >> (inode->i_sb->s_blocksize_bits - 10);

	if (IS_ENCRYPTED(inode))
		max_zeroout = 0;

	
	split_map.m_lblk = map->m_lblk;
	split_map.m_len = map->m_len;

	if (max_zeroout && (allocated > split_map.m_len)) {
		if (allocated <= max_zeroout) {
			
			zero_ex1.ee_block = cpu_to_le32(split_map.m_lblk + split_map.m_len);

			zero_ex1.ee_len = cpu_to_le16(allocated - split_map.m_len);
			ext4_ext_store_pblock(&zero_ex1, ext4_ext_pblock(ex) + split_map.m_lblk + split_map.m_len - ee_block);

			err = ext4_ext_zeroout(inode, &zero_ex1);
			if (err)
				goto out;
			split_map.m_len = allocated;
		}
		if (split_map.m_lblk - ee_block + split_map.m_len < max_zeroout) {
			
			if (split_map.m_lblk != ee_block) {
				zero_ex2.ee_block = ex->ee_block;
				zero_ex2.ee_len = cpu_to_le16(split_map.m_lblk - ee_block);
				ext4_ext_store_pblock(&zero_ex2, ext4_ext_pblock(ex));
				err = ext4_ext_zeroout(inode, &zero_ex2);
				if (err)
					goto out;
			}

			split_map.m_len += split_map.m_lblk - ee_block;
			split_map.m_lblk = ee_block;
			allocated = map->m_len;
		}
	}

	err = ext4_split_extent(handle, inode, ppath, &split_map, split_flag, flags);
	if (err > 0)
		err = 0;
out:
	
	if (!err) {
		err = ext4_zeroout_es(inode, &zero_ex1);
		if (!err)
			err = ext4_zeroout_es(inode, &zero_ex2);
	}
	return err ? err : allocated;
}


static int ext4_split_convert_extents(handle_t *handle, struct inode *inode, struct ext4_map_blocks *map, struct ext4_ext_path **ppath, int flags)



{
	struct ext4_ext_path *path = *ppath;
	ext4_lblk_t eof_block;
	ext4_lblk_t ee_block;
	struct ext4_extent *ex;
	unsigned int ee_len;
	int split_flag = 0, depth;

	ext_debug("%s: inode %lu, logical block %llu, max_blocks %u\n", __func__, inode->i_ino, (unsigned long long)map->m_lblk, map->m_len);


	eof_block = (inode->i_size + inode->i_sb->s_blocksize - 1) >> inode->i_sb->s_blocksize_bits;
	if (eof_block < map->m_lblk + map->m_len)
		eof_block = map->m_lblk + map->m_len;
	
	depth = ext_depth(inode);
	ex = path[depth].p_ext;
	ee_block = le32_to_cpu(ex->ee_block);
	ee_len = ext4_ext_get_actual_len(ex);

	
	if (flags & EXT4_GET_BLOCKS_CONVERT_UNWRITTEN) {
		split_flag |= EXT4_EXT_DATA_VALID1;
	
	} else if (flags & EXT4_GET_BLOCKS_CONVERT) {
		split_flag |= ee_block + ee_len <= eof_block ? EXT4_EXT_MAY_ZEROOUT : 0;
		split_flag |= (EXT4_EXT_MARK_UNWRIT2 | EXT4_EXT_DATA_VALID2);
	}
	flags |= EXT4_GET_BLOCKS_PRE_IO;
	return ext4_split_extent(handle, inode, ppath, map, split_flag, flags);
}

static int ext4_convert_unwritten_extents_endio(handle_t *handle, struct inode *inode, struct ext4_map_blocks *map, struct ext4_ext_path **ppath)


{
	struct ext4_ext_path *path = *ppath;
	struct ext4_extent *ex;
	ext4_lblk_t ee_block;
	unsigned int ee_len;
	int depth;
	int err = 0;

	depth = ext_depth(inode);
	ex = path[depth].p_ext;
	ee_block = le32_to_cpu(ex->ee_block);
	ee_len = ext4_ext_get_actual_len(ex);

	ext_debug("ext4_convert_unwritten_extents_endio: inode %lu, logical" "block %llu, max_blocks %u\n", inode->i_ino, (unsigned long long)ee_block, ee_len);


	
	if (ee_block != map->m_lblk || ee_len > map->m_len) {

		ext4_warning("Inode (%ld) finished: extent logical block %llu," " len %u; IO logical block %llu, len %u", inode->i_ino, (unsigned long long)ee_block, ee_len, (unsigned long long)map->m_lblk, map->m_len);



		err = ext4_split_convert_extents(handle, inode, map, ppath, EXT4_GET_BLOCKS_CONVERT);
		if (err < 0)
			return err;
		path = ext4_find_extent(inode, map->m_lblk, ppath, 0);
		if (IS_ERR(path))
			return PTR_ERR(path);
		depth = ext_depth(inode);
		ex = path[depth].p_ext;
	}

	err = ext4_ext_get_access(handle, inode, path + depth);
	if (err)
		goto out;
	
	ext4_ext_mark_initialized(ex);

	
	ext4_ext_try_to_merge(handle, inode, path, ex);

	
	err = ext4_ext_dirty(handle, inode, path + path->p_depth);
out:
	ext4_ext_show_leaf(inode, path);
	return err;
}


static int check_eofblocks_fl(handle_t *handle, struct inode *inode, ext4_lblk_t lblk, struct ext4_ext_path *path, unsigned int len)


{
	int i, depth;
	struct ext4_extent_header *eh;
	struct ext4_extent *last_ex;

	if (!ext4_test_inode_flag(inode, EXT4_INODE_EOFBLOCKS))
		return 0;

	depth = ext_depth(inode);
	eh = path[depth].p_hdr;

	
	if (unlikely(!eh->eh_entries))
		goto out;
	last_ex = EXT_LAST_EXTENT(eh);
	
	if (lblk + len < le32_to_cpu(last_ex->ee_block) + ext4_ext_get_actual_len(last_ex))
		return 0;
	
	for (i = depth-1; i >= 0; i--)
		if (path[i].p_idx != EXT_LAST_INDEX(path[i].p_hdr))
			return 0;
out:
	ext4_clear_inode_flag(inode, EXT4_INODE_EOFBLOCKS);
	return ext4_mark_inode_dirty(handle, inode);
}

static int convert_initialized_extent(handle_t *handle, struct inode *inode, struct ext4_map_blocks *map, struct ext4_ext_path **ppath, unsigned int allocated)



{
	struct ext4_ext_path *path = *ppath;
	struct ext4_extent *ex;
	ext4_lblk_t ee_block;
	unsigned int ee_len;
	int depth;
	int err = 0;

	
	if (map->m_len > EXT_UNWRITTEN_MAX_LEN)
		map->m_len = EXT_UNWRITTEN_MAX_LEN / 2;

	depth = ext_depth(inode);
	ex = path[depth].p_ext;
	ee_block = le32_to_cpu(ex->ee_block);
	ee_len = ext4_ext_get_actual_len(ex);

	ext_debug("%s: inode %lu, logical" "block %llu, max_blocks %u\n", __func__, inode->i_ino, (unsigned long long)ee_block, ee_len);


	if (ee_block != map->m_lblk || ee_len > map->m_len) {
		err = ext4_split_convert_extents(handle, inode, map, ppath, EXT4_GET_BLOCKS_CONVERT_UNWRITTEN);
		if (err < 0)
			return err;
		path = ext4_find_extent(inode, map->m_lblk, ppath, 0);
		if (IS_ERR(path))
			return PTR_ERR(path);
		depth = ext_depth(inode);
		ex = path[depth].p_ext;
		if (!ex) {
			EXT4_ERROR_INODE(inode, "unexpected hole at %lu", (unsigned long) map->m_lblk);
			return -EFSCORRUPTED;
		}
	}

	err = ext4_ext_get_access(handle, inode, path + depth);
	if (err)
		return err;
	
	ext4_ext_mark_unwritten(ex);

	
	ext4_ext_try_to_merge(handle, inode, path, ex);

	
	err = ext4_ext_dirty(handle, inode, path + path->p_depth);
	if (err)
		return err;
	ext4_ext_show_leaf(inode, path);

	ext4_update_inode_fsync_trans(handle, inode, 1);
	err = check_eofblocks_fl(handle, inode, map->m_lblk, path, map->m_len);
	if (err)
		return err;
	map->m_flags |= EXT4_MAP_UNWRITTEN;
	if (allocated > map->m_len)
		allocated = map->m_len;
	map->m_len = allocated;
	return allocated;
}

static int ext4_ext_handle_unwritten_extents(handle_t *handle, struct inode *inode, struct ext4_map_blocks *map, struct ext4_ext_path **ppath, int flags, unsigned int allocated, ext4_fsblk_t newblock)



{
	struct ext4_ext_path *path = *ppath;
	int ret = 0;
	int err = 0;

	ext_debug("ext4_ext_handle_unwritten_extents: inode %lu, logical " "block %llu, max_blocks %u, flags %x, allocated %u\n", inode->i_ino, (unsigned long long)map->m_lblk, map->m_len, flags, allocated);


	ext4_ext_show_leaf(inode, path);

	
	flags |= EXT4_GET_BLOCKS_METADATA_NOFAIL;

	trace_ext4_ext_handle_unwritten_extents(inode, map, flags, allocated, newblock);

	
	if (flags & EXT4_GET_BLOCKS_PRE_IO) {
		ret = ext4_split_convert_extents(handle, inode, map, ppath, flags | EXT4_GET_BLOCKS_CONVERT);
		if (ret <= 0)
			goto out;
		map->m_flags |= EXT4_MAP_UNWRITTEN;
		goto out;
	}
	
	if (flags & EXT4_GET_BLOCKS_CONVERT) {
		if (flags & EXT4_GET_BLOCKS_ZERO) {
			if (allocated > map->m_len)
				allocated = map->m_len;
			err = ext4_issue_zeroout(inode, map->m_lblk, newblock, allocated);
			if (err < 0)
				goto out2;
		}
		ret = ext4_convert_unwritten_extents_endio(handle, inode, map, ppath);
		if (ret >= 0) {
			ext4_update_inode_fsync_trans(handle, inode, 1);
			err = check_eofblocks_fl(handle, inode, map->m_lblk, path, map->m_len);
		} else err = ret;
		map->m_flags |= EXT4_MAP_MAPPED;
		map->m_pblk = newblock;
		if (allocated > map->m_len)
			allocated = map->m_len;
		map->m_len = allocated;
		goto out2;
	}
	
	
	if (flags & EXT4_GET_BLOCKS_UNWRIT_EXT) {
		map->m_flags |= EXT4_MAP_UNWRITTEN;
		goto map_out;
	}

	
	if ((flags & EXT4_GET_BLOCKS_CREATE) == 0) {
		
		map->m_flags |= EXT4_MAP_UNWRITTEN;
		goto out1;
	}

	
	ret = ext4_ext_convert_to_initialized(handle, inode, map, ppath, flags);
	if (ret >= 0)
		ext4_update_inode_fsync_trans(handle, inode, 1);
out:
	if (ret <= 0) {
		err = ret;
		goto out2;
	} else allocated = ret;
	map->m_flags |= EXT4_MAP_NEW;
	if (allocated > map->m_len)
		allocated = map->m_len;
	map->m_len = allocated;

map_out:
	map->m_flags |= EXT4_MAP_MAPPED;
	if ((flags & EXT4_GET_BLOCKS_KEEP_SIZE) == 0) {
		err = check_eofblocks_fl(handle, inode, map->m_lblk, path, map->m_len);
		if (err < 0)
			goto out2;
	}
out1:
	if (allocated > map->m_len)
		allocated = map->m_len;
	ext4_ext_show_leaf(inode, path);
	map->m_pblk = newblock;
	map->m_len = allocated;
out2:
	return err ? err : allocated;
}


static int get_implied_cluster_alloc(struct super_block *sb, struct ext4_map_blocks *map, struct ext4_extent *ex, struct ext4_ext_path *path)


{
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	ext4_lblk_t c_offset = EXT4_LBLK_COFF(sbi, map->m_lblk);
	ext4_lblk_t ex_cluster_start, ex_cluster_end;
	ext4_lblk_t rr_cluster_start;
	ext4_lblk_t ee_block = le32_to_cpu(ex->ee_block);
	ext4_fsblk_t ee_start = ext4_ext_pblock(ex);
	unsigned short ee_len = ext4_ext_get_actual_len(ex);

	
	ex_cluster_start = EXT4_B2C(sbi, ee_block);
	ex_cluster_end = EXT4_B2C(sbi, ee_block + ee_len - 1);

	
	rr_cluster_start = EXT4_B2C(sbi, map->m_lblk);

	if ((rr_cluster_start == ex_cluster_end) || (rr_cluster_start == ex_cluster_start)) {
		if (rr_cluster_start == ex_cluster_end)
			ee_start += ee_len - 1;
		map->m_pblk = EXT4_PBLK_CMASK(sbi, ee_start) + c_offset;
		map->m_len = min(map->m_len, (unsigned) sbi->s_cluster_ratio - c_offset);
		

		if (map->m_lblk < ee_block)
			map->m_len = min(map->m_len, ee_block - map->m_lblk);

		
		if (map->m_lblk > ee_block) {
			ext4_lblk_t next = ext4_ext_next_allocated_block(path);
			map->m_len = min(map->m_len, next - map->m_lblk);
		}

		trace_ext4_get_implied_cluster_alloc_exit(sb, map, 1);
		return 1;
	}

	trace_ext4_get_implied_cluster_alloc_exit(sb, map, 0);
	return 0;
}



int ext4_ext_map_blocks(handle_t *handle, struct inode *inode, struct ext4_map_blocks *map, int flags)
{
	struct ext4_ext_path *path = NULL;
	struct ext4_extent newex, *ex, *ex2;
	struct ext4_sb_info *sbi = EXT4_SB(inode->i_sb);
	ext4_fsblk_t newblock = 0;
	int free_on_err = 0, err = 0, depth, ret;
	unsigned int allocated = 0, offset = 0;
	unsigned int allocated_clusters = 0;
	struct ext4_allocation_request ar;
	ext4_lblk_t cluster_offset;
	bool map_from_cluster = false;

	ext_debug("blocks %u/%u requested for inode %lu\n", map->m_lblk, map->m_len, inode->i_ino);
	trace_ext4_ext_map_blocks_enter(inode, map->m_lblk, map->m_len, flags);

	
	path = ext4_find_extent(inode, map->m_lblk, NULL, 0);
	if (IS_ERR(path)) {
		err = PTR_ERR(path);
		path = NULL;
		goto out2;
	}

	depth = ext_depth(inode);

	
	if (unlikely(path[depth].p_ext == NULL && depth != 0)) {
		EXT4_ERROR_INODE(inode, "bad extent address " "lblock: %lu, depth: %d pblock %lld", (unsigned long) map->m_lblk, depth, path[depth].p_block);


		err = -EFSCORRUPTED;
		goto out2;
	}

	ex = path[depth].p_ext;
	if (ex) {
		ext4_lblk_t ee_block = le32_to_cpu(ex->ee_block);
		ext4_fsblk_t ee_start = ext4_ext_pblock(ex);
		unsigned short ee_len;


		
		ee_len = ext4_ext_get_actual_len(ex);

		trace_ext4_ext_show_extent(inode, ee_block, ee_start, ee_len);

		
		if (in_range(map->m_lblk, ee_block, ee_len)) {
			newblock = map->m_lblk - ee_block + ee_start;
			
			allocated = ee_len - (map->m_lblk - ee_block);
			ext_debug("%u fit into %u:%d -> %llu\n", map->m_lblk, ee_block, ee_len, newblock);

			
			if ((!ext4_ext_is_unwritten(ex)) && (flags & EXT4_GET_BLOCKS_CONVERT_UNWRITTEN)) {
				allocated = convert_initialized_extent( handle, inode, map, &path, allocated);

				goto out2;
			} else if (!ext4_ext_is_unwritten(ex))
				goto out;

			ret = ext4_ext_handle_unwritten_extents( handle, inode, map, &path, flags, allocated, newblock);

			if (ret < 0)
				err = ret;
			else allocated = ret;
			goto out2;
		}
	}

	
	if ((flags & EXT4_GET_BLOCKS_CREATE) == 0) {
		ext4_lblk_t hole_start, hole_len;

		hole_start = map->m_lblk;
		hole_len = ext4_ext_determine_hole(inode, path, &hole_start);
		
		ext4_ext_put_gap_in_cache(inode, hole_start, hole_len);

		
		if (hole_start != map->m_lblk)
			hole_len -= map->m_lblk - hole_start;
		map->m_pblk = 0;
		map->m_len = min_t(unsigned int, map->m_len, hole_len);

		goto out2;
	}

	
	newex.ee_block = cpu_to_le32(map->m_lblk);
	cluster_offset = EXT4_LBLK_COFF(sbi, map->m_lblk);

	
	if (cluster_offset && ex && get_implied_cluster_alloc(inode->i_sb, map, ex, path)) {
		ar.len = allocated = map->m_len;
		newblock = map->m_pblk;
		map_from_cluster = true;
		goto got_allocated_blocks;
	}

	
	ar.lleft = map->m_lblk;
	err = ext4_ext_search_left(inode, path, &ar.lleft, &ar.pleft);
	if (err)
		goto out2;
	ar.lright = map->m_lblk;
	ex2 = NULL;
	err = ext4_ext_search_right(inode, path, &ar.lright, &ar.pright, &ex2);
	if (err)
		goto out2;

	
	if ((sbi->s_cluster_ratio > 1) && ex2 && get_implied_cluster_alloc(inode->i_sb, map, ex2, path)) {
		ar.len = allocated = map->m_len;
		newblock = map->m_pblk;
		map_from_cluster = true;
		goto got_allocated_blocks;
	}

	
	if (map->m_len > EXT_INIT_MAX_LEN && !(flags & EXT4_GET_BLOCKS_UNWRIT_EXT))
		map->m_len = EXT_INIT_MAX_LEN;
	else if (map->m_len > EXT_UNWRITTEN_MAX_LEN && (flags & EXT4_GET_BLOCKS_UNWRIT_EXT))
		map->m_len = EXT_UNWRITTEN_MAX_LEN;

	
	newex.ee_len = cpu_to_le16(map->m_len);
	err = ext4_ext_check_overlap(sbi, inode, &newex, path);
	if (err)
		allocated = ext4_ext_get_actual_len(&newex);
	else allocated = map->m_len;

	
	ar.inode = inode;
	ar.goal = ext4_ext_find_goal(inode, path, map->m_lblk);
	ar.logical = map->m_lblk;
	
	offset = EXT4_LBLK_COFF(sbi, map->m_lblk);
	ar.len = EXT4_NUM_B2C(sbi, offset+allocated);
	ar.goal -= offset;
	ar.logical -= offset;
	if (S_ISREG(inode->i_mode))
		ar.flags = EXT4_MB_HINT_DATA;
	else  ar.flags = 0;

	if (flags & EXT4_GET_BLOCKS_NO_NORMALIZE)
		ar.flags |= EXT4_MB_HINT_NOPREALLOC;
	if (flags & EXT4_GET_BLOCKS_DELALLOC_RESERVE)
		ar.flags |= EXT4_MB_DELALLOC_RESERVED;
	if (flags & EXT4_GET_BLOCKS_METADATA_NOFAIL)
		ar.flags |= EXT4_MB_USE_RESERVED;
	newblock = ext4_mb_new_blocks(handle, &ar, &err);
	if (!newblock)
		goto out2;
	ext_debug("allocate new block: goal %llu, found %llu/%u\n", ar.goal, newblock, allocated);
	free_on_err = 1;
	allocated_clusters = ar.len;
	ar.len = EXT4_C2B(sbi, ar.len) - offset;
	if (ar.len > allocated)
		ar.len = allocated;

got_allocated_blocks:
	
	ext4_ext_store_pblock(&newex, newblock + offset);
	newex.ee_len = cpu_to_le16(ar.len);
	
	if (flags & EXT4_GET_BLOCKS_UNWRIT_EXT){
		ext4_ext_mark_unwritten(&newex);
		map->m_flags |= EXT4_MAP_UNWRITTEN;
	}

	err = 0;
	if ((flags & EXT4_GET_BLOCKS_KEEP_SIZE) == 0)
		err = check_eofblocks_fl(handle, inode, map->m_lblk, path, ar.len);
	if (!err)
		err = ext4_ext_insert_extent(handle, inode, &path, &newex, flags);

	if (err && free_on_err) {
		int fb_flags = flags & EXT4_GET_BLOCKS_DELALLOC_RESERVE ? EXT4_FREE_BLOCKS_NO_QUOT_UPDATE : 0;
		
		
		ext4_discard_preallocations(inode);
		ext4_free_blocks(handle, inode, NULL, newblock, EXT4_C2B(sbi, allocated_clusters), fb_flags);
		goto out2;
	}

	
	newblock = ext4_ext_pblock(&newex);
	allocated = ext4_ext_get_actual_len(&newex);
	if (allocated > map->m_len)
		allocated = map->m_len;
	map->m_flags |= EXT4_MAP_NEW;

	
	if (test_opt(inode->i_sb, DELALLOC) && !map_from_cluster) {
		if (flags & EXT4_GET_BLOCKS_DELALLOC_RESERVE) {
			
			ext4_da_update_reserve_space(inode, allocated_clusters, 1);
		} else {
			ext4_lblk_t lblk, len;
			unsigned int n;

			
			lblk = EXT4_LBLK_CMASK(sbi, map->m_lblk);
			len = allocated_clusters << sbi->s_cluster_bits;
			n = ext4_es_delayed_clu(inode, lblk, len);
			if (n > 0)
				ext4_da_update_reserve_space(inode, (int) n, 0);
		}
	}

	
	if ((flags & EXT4_GET_BLOCKS_UNWRIT_EXT) == 0)
		ext4_update_inode_fsync_trans(handle, inode, 1);
	else ext4_update_inode_fsync_trans(handle, inode, 0);
out:
	if (allocated > map->m_len)
		allocated = map->m_len;
	ext4_ext_show_leaf(inode, path);
	map->m_flags |= EXT4_MAP_MAPPED;
	map->m_pblk = newblock;
	map->m_len = allocated;
out2:
	ext4_ext_drop_refs(path);
	kfree(path);

	trace_ext4_ext_map_blocks_exit(inode, flags, map, err ? err : allocated);
	return err ? err : allocated;
}

int ext4_ext_truncate(handle_t *handle, struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	ext4_lblk_t last_block;
	int err = 0;

	

	
	EXT4_I(inode)->i_disksize = inode->i_size;
	err = ext4_mark_inode_dirty(handle, inode);
	if (err)
		return err;

	last_block = (inode->i_size + sb->s_blocksize - 1)
			>> EXT4_BLOCK_SIZE_BITS(sb);
retry:
	err = ext4_es_remove_extent(inode, last_block, EXT_MAX_BLOCKS - last_block);
	if (err == -ENOMEM) {
		cond_resched();
		congestion_wait(BLK_RW_ASYNC, HZ/50);
		goto retry;
	}
	if (err)
		return err;
	return ext4_ext_remove_space(inode, last_block, EXT_MAX_BLOCKS - 1);
}

static int ext4_alloc_file_blocks(struct file *file, ext4_lblk_t offset, ext4_lblk_t len, loff_t new_size, int flags)

{
	struct inode *inode = file_inode(file);
	handle_t *handle;
	int ret = 0;
	int ret2 = 0;
	int retries = 0;
	int depth = 0;
	struct ext4_map_blocks map;
	unsigned int credits;
	loff_t epos;

	BUG_ON(!ext4_test_inode_flag(inode, EXT4_INODE_EXTENTS));
	map.m_lblk = offset;
	map.m_len = len;
	
	if (len <= EXT_UNWRITTEN_MAX_LEN)
		flags |= EXT4_GET_BLOCKS_NO_NORMALIZE;

	
	credits = ext4_chunk_trans_blocks(inode, len);
	depth = ext_depth(inode);

retry:
	while (ret >= 0 && len) {
		
		if (depth != ext_depth(inode)) {
			credits = ext4_chunk_trans_blocks(inode, len);
			depth = ext_depth(inode);
		}

		handle = ext4_journal_start(inode, EXT4_HT_MAP_BLOCKS, credits);
		if (IS_ERR(handle)) {
			ret = PTR_ERR(handle);
			break;
		}
		ret = ext4_map_blocks(handle, inode, &map, flags);
		if (ret <= 0) {
			ext4_debug("inode #%lu: block %u: len %u: " "ext4_ext_map_blocks returned %d", inode->i_ino, map.m_lblk, map.m_len, ret);


			ext4_mark_inode_dirty(handle, inode);
			ret2 = ext4_journal_stop(handle);
			break;
		}
		map.m_lblk += ret;
		map.m_len = len = len - ret;
		epos = (loff_t)map.m_lblk << inode->i_blkbits;
		inode->i_ctime = current_time(inode);
		if (new_size) {
			if (epos > new_size)
				epos = new_size;
			if (ext4_update_inode_size(inode, epos) & 0x1)
				inode->i_mtime = inode->i_ctime;
		} else {
			if (epos > inode->i_size)
				ext4_set_inode_flag(inode, EXT4_INODE_EOFBLOCKS);
		}
		ext4_mark_inode_dirty(handle, inode);
		ext4_update_inode_fsync_trans(handle, inode, 1);
		ret2 = ext4_journal_stop(handle);
		if (ret2)
			break;
	}
	if (ret == -ENOSPC && ext4_should_retry_alloc(inode->i_sb, &retries)) {
		ret = 0;
		goto retry;
	}

	return ret > 0 ? ret2 : ret;
}

static long ext4_zero_range(struct file *file, loff_t offset, loff_t len, int mode)
{
	struct inode *inode = file_inode(file);
	handle_t *handle = NULL;
	unsigned int max_blocks;
	loff_t new_size = 0;
	int ret = 0;
	int flags;
	int credits;
	int partial_begin, partial_end;
	loff_t start, end;
	ext4_lblk_t lblk;
	unsigned int blkbits = inode->i_blkbits;

	trace_ext4_zero_range(inode, offset, len, mode);

	if (!S_ISREG(inode->i_mode))
		return -EINVAL;

	
	if (ext4_should_journal_data(inode)) {
		ret = ext4_force_commit(inode->i_sb);
		if (ret)
			return ret;
	}

	
	start = round_up(offset, 1 << blkbits);
	end = round_down((offset + len), 1 << blkbits);

	if (start < offset || end > offset + len)
		return -EINVAL;
	partial_begin = offset & ((1 << blkbits) - 1);
	partial_end = (offset + len) & ((1 << blkbits) - 1);

	lblk = start >> blkbits;
	max_blocks = (end >> blkbits);
	if (max_blocks < lblk)
		max_blocks = 0;
	else max_blocks -= lblk;

	inode_lock(inode);

	
	if (!(ext4_test_inode_flag(inode, EXT4_INODE_EXTENTS))) {
		ret = -EOPNOTSUPP;
		goto out_mutex;
	}

	if (!(mode & FALLOC_FL_KEEP_SIZE) && (offset + len > i_size_read(inode) || offset + len > EXT4_I(inode)->i_disksize)) {

		new_size = offset + len;
		ret = inode_newsize_ok(inode, new_size);
		if (ret)
			goto out_mutex;
	}

	flags = EXT4_GET_BLOCKS_CREATE_UNWRIT_EXT;
	if (mode & FALLOC_FL_KEEP_SIZE)
		flags |= EXT4_GET_BLOCKS_KEEP_SIZE;

	
	inode_dio_wait(inode);

	
	if (partial_begin || partial_end) {
		ret = ext4_alloc_file_blocks(file, round_down(offset, 1 << blkbits) >> blkbits, (round_up((offset + len), 1 << blkbits) - round_down(offset, 1 << blkbits)) >> blkbits, new_size, flags);



		if (ret)
			goto out_mutex;

	}

	
	if (max_blocks > 0) {
		flags |= (EXT4_GET_BLOCKS_CONVERT_UNWRITTEN | EXT4_EX_NOCACHE);

		
		down_write(&EXT4_I(inode)->i_mmap_sem);

		ret = ext4_break_layouts(inode);
		if (ret) {
			up_write(&EXT4_I(inode)->i_mmap_sem);
			goto out_mutex;
		}

		ret = ext4_update_disksize_before_punch(inode, offset, len);
		if (ret) {
			up_write(&EXT4_I(inode)->i_mmap_sem);
			goto out_mutex;
		}
		
		truncate_pagecache_range(inode, start, end - 1);
		inode->i_mtime = inode->i_ctime = current_time(inode);

		ret = ext4_alloc_file_blocks(file, lblk, max_blocks, new_size, flags);
		up_write(&EXT4_I(inode)->i_mmap_sem);
		if (ret)
			goto out_mutex;
	}
	if (!partial_begin && !partial_end)
		goto out_mutex;

	
	credits = (2 * ext4_ext_index_trans_blocks(inode, 2)) + 1;
	if (ext4_should_journal_data(inode))
		credits += 2;
	handle = ext4_journal_start(inode, EXT4_HT_MISC, credits);
	if (IS_ERR(handle)) {
		ret = PTR_ERR(handle);
		ext4_std_error(inode->i_sb, ret);
		goto out_mutex;
	}

	inode->i_mtime = inode->i_ctime = current_time(inode);
	if (new_size) {
		ext4_update_inode_size(inode, new_size);
	} else {
		
		if ((offset + len) > i_size_read(inode))
			ext4_set_inode_flag(inode, EXT4_INODE_EOFBLOCKS);
	}
	ext4_mark_inode_dirty(handle, inode);

	
	ret = ext4_zero_partial_blocks(handle, inode, offset, len);
	if (ret >= 0)
		ext4_update_inode_fsync_trans(handle, inode, 1);

	if (file->f_flags & O_SYNC)
		ext4_handle_sync(handle);

	ext4_journal_stop(handle);
out_mutex:
	inode_unlock(inode);
	return ret;
}


long ext4_fallocate(struct file *file, int mode, loff_t offset, loff_t len)
{
	struct inode *inode = file_inode(file);
	loff_t new_size = 0;
	unsigned int max_blocks;
	int ret = 0;
	int flags;
	ext4_lblk_t lblk;
	unsigned int blkbits = inode->i_blkbits;

	
	if (IS_ENCRYPTED(inode) && (mode & (FALLOC_FL_COLLAPSE_RANGE | FALLOC_FL_INSERT_RANGE | FALLOC_FL_ZERO_RANGE)))

		return -EOPNOTSUPP;

	
	if (mode & ~(FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE | FALLOC_FL_COLLAPSE_RANGE | FALLOC_FL_ZERO_RANGE | FALLOC_FL_INSERT_RANGE))

		return -EOPNOTSUPP;

	if (mode & FALLOC_FL_PUNCH_HOLE)
		return ext4_punch_hole(inode, offset, len);

	ret = ext4_convert_inline_data(inode);
	if (ret)
		return ret;

	if (mode & FALLOC_FL_COLLAPSE_RANGE)
		return ext4_collapse_range(inode, offset, len);

	if (mode & FALLOC_FL_INSERT_RANGE)
		return ext4_insert_range(inode, offset, len);

	if (mode & FALLOC_FL_ZERO_RANGE)
		return ext4_zero_range(file, offset, len, mode);

	trace_ext4_fallocate_enter(inode, offset, len, mode);
	lblk = offset >> blkbits;

	max_blocks = EXT4_MAX_BLOCKS(len, offset, blkbits);
	flags = EXT4_GET_BLOCKS_CREATE_UNWRIT_EXT;
	if (mode & FALLOC_FL_KEEP_SIZE)
		flags |= EXT4_GET_BLOCKS_KEEP_SIZE;

	inode_lock(inode);

	
	if (!(ext4_test_inode_flag(inode, EXT4_INODE_EXTENTS))) {
		ret = -EOPNOTSUPP;
		goto out;
	}

	if (!(mode & FALLOC_FL_KEEP_SIZE) && (offset + len > i_size_read(inode) || offset + len > EXT4_I(inode)->i_disksize)) {

		new_size = offset + len;
		ret = inode_newsize_ok(inode, new_size);
		if (ret)
			goto out;
	}

	
	inode_dio_wait(inode);

	ret = ext4_alloc_file_blocks(file, lblk, max_blocks, new_size, flags);
	if (ret)
		goto out;

	if (file->f_flags & O_SYNC && EXT4_SB(inode->i_sb)->s_journal) {
		ret = jbd2_complete_transaction(EXT4_SB(inode->i_sb)->s_journal, EXT4_I(inode)->i_sync_tid);
	}
out:
	inode_unlock(inode);
	trace_ext4_fallocate_exit(inode, offset, max_blocks, ret);
	return ret;
}


int ext4_convert_unwritten_extents(handle_t *handle, struct inode *inode, loff_t offset, ssize_t len)
{
	unsigned int max_blocks;
	int ret = 0;
	int ret2 = 0;
	struct ext4_map_blocks map;
	unsigned int credits, blkbits = inode->i_blkbits;

	map.m_lblk = offset >> blkbits;
	max_blocks = EXT4_MAX_BLOCKS(len, offset, blkbits);

	
	if (handle) {
		handle = ext4_journal_start_reserved(handle, EXT4_HT_EXT_CONVERT);
		if (IS_ERR(handle))
			return PTR_ERR(handle);
		credits = 0;
	} else {
		
		credits = ext4_chunk_trans_blocks(inode, max_blocks);
	}
	while (ret >= 0 && ret < max_blocks) {
		map.m_lblk += ret;
		map.m_len = (max_blocks -= ret);
		if (credits) {
			handle = ext4_journal_start(inode, EXT4_HT_MAP_BLOCKS, credits);
			if (IS_ERR(handle)) {
				ret = PTR_ERR(handle);
				break;
			}
		}
		ret = ext4_map_blocks(handle, inode, &map, EXT4_GET_BLOCKS_IO_CONVERT_EXT);
		if (ret <= 0)
			ext4_warning(inode->i_sb, "inode #%lu: block %u: len %u: " "ext4_ext_map_blocks returned %d", inode->i_ino, map.m_lblk, map.m_len, ret);



		ext4_mark_inode_dirty(handle, inode);
		if (credits)
			ret2 = ext4_journal_stop(handle);
		if (ret <= 0 || ret2)
			break;
	}
	if (!credits)
		ret2 = ext4_journal_stop(handle);
	return ret > 0 ? ret2 : ret;
}


static int ext4_find_delayed_extent(struct inode *inode, struct extent_status *newes)
{
	struct extent_status es;
	ext4_lblk_t block, next_del;

	if (newes->es_pblk == 0) {
		ext4_es_find_extent_range(inode, &ext4_es_is_delayed, newes->es_lblk, newes->es_lblk + newes->es_len - 1, &es);



		
		if (es.es_len == 0)
			
			return 0;

		if (es.es_lblk > newes->es_lblk) {
			
			newes->es_len = min(es.es_lblk - newes->es_lblk, newes->es_len);
			return 0;
		}

		newes->es_len = es.es_lblk + es.es_len - newes->es_lblk;
	}

	block = newes->es_lblk + newes->es_len;
	ext4_es_find_extent_range(inode, &ext4_es_is_delayed, block, EXT_MAX_BLOCKS, &es);
	if (es.es_len == 0)
		next_del = EXT_MAX_BLOCKS;
	else next_del = es.es_lblk;

	return next_del;
}



static int ext4_xattr_fiemap(struct inode *inode, struct fiemap_extent_info *fieinfo)
{
	__u64 physical = 0;
	__u64 length;
	__u32 flags = FIEMAP_EXTENT_LAST;
	int blockbits = inode->i_sb->s_blocksize_bits;
	int error = 0;

	
	if (ext4_test_inode_state(inode, EXT4_STATE_XATTR)) {
		struct ext4_iloc iloc;
		int offset;	

		error = ext4_get_inode_loc(inode, &iloc);
		if (error)
			return error;
		physical = (__u64)iloc.bh->b_blocknr << blockbits;
		offset = EXT4_GOOD_OLD_INODE_SIZE + EXT4_I(inode)->i_extra_isize;
		physical += offset;
		length = EXT4_SB(inode->i_sb)->s_inode_size - offset;
		flags |= FIEMAP_EXTENT_DATA_INLINE;
		brelse(iloc.bh);
	} else { 
		physical = (__u64)EXT4_I(inode)->i_file_acl << blockbits;
		length = inode->i_sb->s_blocksize;
	}

	if (physical)
		error = fiemap_fill_next_extent(fieinfo, 0, physical, length, flags);
	return (error < 0 ? error : 0);
}

int ext4_fiemap(struct inode *inode, struct fiemap_extent_info *fieinfo, __u64 start, __u64 len)
{
	ext4_lblk_t start_blk;
	int error = 0;

	if (ext4_has_inline_data(inode)) {
		int has_inline = 1;

		error = ext4_inline_data_fiemap(inode, fieinfo, &has_inline, start, len);

		if (has_inline)
			return error;
	}

	if (fieinfo->fi_flags & FIEMAP_FLAG_CACHE) {
		error = ext4_ext_precache(inode);
		if (error)
			return error;
	}

	
	if (!(ext4_test_inode_flag(inode, EXT4_INODE_EXTENTS)))
		return generic_block_fiemap(inode, fieinfo, start, len, ext4_get_block);

	if (fiemap_check_flags(fieinfo, EXT4_FIEMAP_FLAGS))
		return -EBADR;

	if (fieinfo->fi_flags & FIEMAP_FLAG_XATTR) {
		error = ext4_xattr_fiemap(inode, fieinfo);
	} else {
		ext4_lblk_t len_blks;
		__u64 last_blk;

		start_blk = start >> inode->i_sb->s_blocksize_bits;
		last_blk = (start + len - 1) >> inode->i_sb->s_blocksize_bits;
		if (last_blk >= EXT_MAX_BLOCKS)
			last_blk = EXT_MAX_BLOCKS-1;
		len_blks = ((ext4_lblk_t) last_blk) - start_blk + 1;

		
		error = ext4_fill_fiemap_extents(inode, start_blk, len_blks, fieinfo);
	}
	return error;
}


static int ext4_access_path(handle_t *handle, struct inode *inode, struct ext4_ext_path *path)

{
	int credits, err;

	if (!ext4_handle_valid(handle))
		return 0;

	
	if (handle->h_buffer_credits < 7) {
		credits = ext4_writepage_trans_blocks(inode);
		err = ext4_ext_truncate_extend_restart(handle, inode, credits);
		
		if (err && err != -EAGAIN)
			return err;
	}

	err = ext4_ext_get_access(handle, inode, path);
	return err;
}


static int ext4_ext_shift_path_extents(struct ext4_ext_path *path, ext4_lblk_t shift, struct inode *inode, handle_t *handle, enum SHIFT_DIRECTION SHIFT)


{
	int depth, err = 0;
	struct ext4_extent *ex_start, *ex_last;
	bool update = 0;
	depth = path->p_depth;

	while (depth >= 0) {
		if (depth == path->p_depth) {
			ex_start = path[depth].p_ext;
			if (!ex_start)
				return -EFSCORRUPTED;

			ex_last = EXT_LAST_EXTENT(path[depth].p_hdr);

			err = ext4_access_path(handle, inode, path + depth);
			if (err)
				goto out;

			if (ex_start == EXT_FIRST_EXTENT(path[depth].p_hdr))
				update = 1;

			while (ex_start <= ex_last) {
				if (SHIFT == SHIFT_LEFT) {
					le32_add_cpu(&ex_start->ee_block, -shift);
					
					if ((ex_start > EXT_FIRST_EXTENT(path[depth].p_hdr))
					    && ext4_ext_try_to_merge_right(inode, path, ex_start - 1))

						ex_last--;
					else ex_start++;
				} else {
					le32_add_cpu(&ex_last->ee_block, shift);
					ext4_ext_try_to_merge_right(inode, path, ex_last);
					ex_last--;
				}
			}
			err = ext4_ext_dirty(handle, inode, path + depth);
			if (err)
				goto out;

			if (--depth < 0 || !update)
				break;
		}

		
		err = ext4_access_path(handle, inode, path + depth);
		if (err)
			goto out;

		if (SHIFT == SHIFT_LEFT)
			le32_add_cpu(&path[depth].p_idx->ei_block, -shift);
		else le32_add_cpu(&path[depth].p_idx->ei_block, shift);
		err = ext4_ext_dirty(handle, inode, path + depth);
		if (err)
			goto out;

		
		if (path[depth].p_idx != EXT_FIRST_INDEX(path[depth].p_hdr))
			break;

		depth--;
	}

out:
	return err;
}


static int ext4_ext_shift_extents(struct inode *inode, handle_t *handle, ext4_lblk_t start, ext4_lblk_t shift, enum SHIFT_DIRECTION SHIFT)


{
	struct ext4_ext_path *path;
	int ret = 0, depth;
	struct ext4_extent *extent;
	ext4_lblk_t stop, *iterator, ex_start, ex_end;

	
	path = ext4_find_extent(inode, EXT_MAX_BLOCKS - 1, NULL, EXT4_EX_NOCACHE);
	if (IS_ERR(path))
		return PTR_ERR(path);

	depth = path->p_depth;
	extent = path[depth].p_ext;
	if (!extent)
		goto out;

	stop = le32_to_cpu(extent->ee_block);

       
	if (SHIFT == SHIFT_LEFT) {
		path = ext4_find_extent(inode, start - 1, &path, EXT4_EX_NOCACHE);
		if (IS_ERR(path))
			return PTR_ERR(path);
		depth = path->p_depth;
		extent =  path[depth].p_ext;
		if (extent) {
			ex_start = le32_to_cpu(extent->ee_block);
			ex_end = le32_to_cpu(extent->ee_block) + ext4_ext_get_actual_len(extent);
		} else {
			ex_start = 0;
			ex_end = 0;
		}

		if ((start == ex_start && shift > ex_start) || (shift > start - ex_end)) {
			ret = -EINVAL;
			goto out;
		}
	} else {
		if (shift > EXT_MAX_BLOCKS - (stop + ext4_ext_get_actual_len(extent))) {
			ret = -EINVAL;
			goto out;
		}
	}

	
	if (SHIFT == SHIFT_LEFT)
		iterator = &start;
	else iterator = &stop;

	
	while (iterator && start <= stop) {
		path = ext4_find_extent(inode, *iterator, &path, EXT4_EX_NOCACHE);
		if (IS_ERR(path))
			return PTR_ERR(path);
		depth = path->p_depth;
		extent = path[depth].p_ext;
		if (!extent) {
			EXT4_ERROR_INODE(inode, "unexpected hole at %lu", (unsigned long) *iterator);
			return -EFSCORRUPTED;
		}
		if (SHIFT == SHIFT_LEFT && *iterator > le32_to_cpu(extent->ee_block)) {
			
			if (extent < EXT_LAST_EXTENT(path[depth].p_hdr)) {
				path[depth].p_ext++;
			} else {
				*iterator = ext4_ext_next_allocated_block(path);
				continue;
			}
		}

		if (SHIFT == SHIFT_LEFT) {
			extent = EXT_LAST_EXTENT(path[depth].p_hdr);
			*iterator = le32_to_cpu(extent->ee_block) + ext4_ext_get_actual_len(extent);
		} else {
			extent = EXT_FIRST_EXTENT(path[depth].p_hdr);
			if (le32_to_cpu(extent->ee_block) > 0)
				*iterator = le32_to_cpu(extent->ee_block) - 1;
			else  iterator = NULL;

			
			while (le32_to_cpu(extent->ee_block) < start)
				extent++;
			path[depth].p_ext = extent;
		}
		ret = ext4_ext_shift_path_extents(path, shift, inode, handle, SHIFT);
		if (ret)
			break;
	}
out:
	ext4_ext_drop_refs(path);
	kfree(path);
	return ret;
}


int ext4_collapse_range(struct inode *inode, loff_t offset, loff_t len)
{
	struct super_block *sb = inode->i_sb;
	ext4_lblk_t punch_start, punch_stop;
	handle_t *handle;
	unsigned int credits;
	loff_t new_size, ioffset;
	int ret;

	
	if (!ext4_test_inode_flag(inode, EXT4_INODE_EXTENTS))
		return -EOPNOTSUPP;

	
	if (offset & (EXT4_CLUSTER_SIZE(sb) - 1) || len & (EXT4_CLUSTER_SIZE(sb) - 1))
		return -EINVAL;

	if (!S_ISREG(inode->i_mode))
		return -EINVAL;

	trace_ext4_collapse_range(inode, offset, len);

	punch_start = offset >> EXT4_BLOCK_SIZE_BITS(sb);
	punch_stop = (offset + len) >> EXT4_BLOCK_SIZE_BITS(sb);

	
	if (ext4_should_journal_data(inode)) {
		ret = ext4_force_commit(inode->i_sb);
		if (ret)
			return ret;
	}

	inode_lock(inode);
	
	if (offset + len >= i_size_read(inode)) {
		ret = -EINVAL;
		goto out_mutex;
	}

	
	if (!ext4_test_inode_flag(inode, EXT4_INODE_EXTENTS)) {
		ret = -EOPNOTSUPP;
		goto out_mutex;
	}

	
	inode_dio_wait(inode);

	
	down_write(&EXT4_I(inode)->i_mmap_sem);

	ret = ext4_break_layouts(inode);
	if (ret)
		goto out_mmap;

	
	ioffset = round_down(offset, PAGE_SIZE);
	
	ret = filemap_write_and_wait_range(inode->i_mapping, ioffset, offset);
	if (ret)
		goto out_mmap;
	
	ret = filemap_write_and_wait_range(inode->i_mapping, offset + len, LLONG_MAX);
	if (ret)
		goto out_mmap;
	truncate_pagecache(inode, ioffset);

	credits = ext4_writepage_trans_blocks(inode);
	handle = ext4_journal_start(inode, EXT4_HT_TRUNCATE, credits);
	if (IS_ERR(handle)) {
		ret = PTR_ERR(handle);
		goto out_mmap;
	}

	down_write(&EXT4_I(inode)->i_data_sem);
	ext4_discard_preallocations(inode);

	ret = ext4_es_remove_extent(inode, punch_start, EXT_MAX_BLOCKS - punch_start);
	if (ret) {
		up_write(&EXT4_I(inode)->i_data_sem);
		goto out_stop;
	}

	ret = ext4_ext_remove_space(inode, punch_start, punch_stop - 1);
	if (ret) {
		up_write(&EXT4_I(inode)->i_data_sem);
		goto out_stop;
	}
	ext4_discard_preallocations(inode);

	ret = ext4_ext_shift_extents(inode, handle, punch_stop, punch_stop - punch_start, SHIFT_LEFT);
	if (ret) {
		up_write(&EXT4_I(inode)->i_data_sem);
		goto out_stop;
	}

	new_size = i_size_read(inode) - len;
	i_size_write(inode, new_size);
	EXT4_I(inode)->i_disksize = new_size;

	up_write(&EXT4_I(inode)->i_data_sem);
	if (IS_SYNC(inode))
		ext4_handle_sync(handle);
	inode->i_mtime = inode->i_ctime = current_time(inode);
	ext4_mark_inode_dirty(handle, inode);
	ext4_update_inode_fsync_trans(handle, inode, 1);

out_stop:
	ext4_journal_stop(handle);
out_mmap:
	up_write(&EXT4_I(inode)->i_mmap_sem);
out_mutex:
	inode_unlock(inode);
	return ret;
}


int ext4_insert_range(struct inode *inode, loff_t offset, loff_t len)
{
	struct super_block *sb = inode->i_sb;
	handle_t *handle;
	struct ext4_ext_path *path;
	struct ext4_extent *extent;
	ext4_lblk_t offset_lblk, len_lblk, ee_start_lblk = 0;
	unsigned int credits, ee_len;
	int ret = 0, depth, split_flag = 0;
	loff_t ioffset;

	
	if (!ext4_test_inode_flag(inode, EXT4_INODE_EXTENTS))
		return -EOPNOTSUPP;

	
	if (offset & (EXT4_CLUSTER_SIZE(sb) - 1) || len & (EXT4_CLUSTER_SIZE(sb) - 1))
		return -EINVAL;

	if (!S_ISREG(inode->i_mode))
		return -EOPNOTSUPP;

	trace_ext4_insert_range(inode, offset, len);

	offset_lblk = offset >> EXT4_BLOCK_SIZE_BITS(sb);
	len_lblk = len >> EXT4_BLOCK_SIZE_BITS(sb);

	
	if (ext4_should_journal_data(inode)) {
		ret = ext4_force_commit(inode->i_sb);
		if (ret)
			return ret;
	}

	inode_lock(inode);
	
	if (!ext4_test_inode_flag(inode, EXT4_INODE_EXTENTS)) {
		ret = -EOPNOTSUPP;
		goto out_mutex;
	}

	
	if (inode->i_size + len > inode->i_sb->s_maxbytes) {
		ret = -EFBIG;
		goto out_mutex;
	}

	
	if (offset >= i_size_read(inode)) {
		ret = -EINVAL;
		goto out_mutex;
	}

	
	inode_dio_wait(inode);

	
	down_write(&EXT4_I(inode)->i_mmap_sem);

	ret = ext4_break_layouts(inode);
	if (ret)
		goto out_mmap;

	
	ioffset = round_down(offset, PAGE_SIZE);
	
	ret = filemap_write_and_wait_range(inode->i_mapping, ioffset, LLONG_MAX);
	if (ret)
		goto out_mmap;
	truncate_pagecache(inode, ioffset);

	credits = ext4_writepage_trans_blocks(inode);
	handle = ext4_journal_start(inode, EXT4_HT_TRUNCATE, credits);
	if (IS_ERR(handle)) {
		ret = PTR_ERR(handle);
		goto out_mmap;
	}

	
	inode->i_size += len;
	EXT4_I(inode)->i_disksize += len;
	inode->i_mtime = inode->i_ctime = current_time(inode);
	ret = ext4_mark_inode_dirty(handle, inode);
	if (ret)
		goto out_stop;

	down_write(&EXT4_I(inode)->i_data_sem);
	ext4_discard_preallocations(inode);

	path = ext4_find_extent(inode, offset_lblk, NULL, 0);
	if (IS_ERR(path)) {
		up_write(&EXT4_I(inode)->i_data_sem);
		goto out_stop;
	}

	depth = ext_depth(inode);
	extent = path[depth].p_ext;
	if (extent) {
		ee_start_lblk = le32_to_cpu(extent->ee_block);
		ee_len = ext4_ext_get_actual_len(extent);

		
		if ((offset_lblk > ee_start_lblk) && (offset_lblk < (ee_start_lblk + ee_len))) {
			if (ext4_ext_is_unwritten(extent))
				split_flag = EXT4_EXT_MARK_UNWRIT1 | EXT4_EXT_MARK_UNWRIT2;
			ret = ext4_split_extent_at(handle, inode, &path, offset_lblk, split_flag, EXT4_EX_NOCACHE | EXT4_GET_BLOCKS_PRE_IO | EXT4_GET_BLOCKS_METADATA_NOFAIL);



		}

		ext4_ext_drop_refs(path);
		kfree(path);
		if (ret < 0) {
			up_write(&EXT4_I(inode)->i_data_sem);
			goto out_stop;
		}
	} else {
		ext4_ext_drop_refs(path);
		kfree(path);
	}

	ret = ext4_es_remove_extent(inode, offset_lblk, EXT_MAX_BLOCKS - offset_lblk);
	if (ret) {
		up_write(&EXT4_I(inode)->i_data_sem);
		goto out_stop;
	}

	
	ret = ext4_ext_shift_extents(inode, handle, ee_start_lblk > offset_lblk ? ee_start_lblk : offset_lblk, len_lblk, SHIFT_RIGHT);


	up_write(&EXT4_I(inode)->i_data_sem);
	if (IS_SYNC(inode))
		ext4_handle_sync(handle);
	if (ret >= 0)
		ext4_update_inode_fsync_trans(handle, inode, 1);

out_stop:
	ext4_journal_stop(handle);
out_mmap:
	up_write(&EXT4_I(inode)->i_mmap_sem);
out_mutex:
	inode_unlock(inode);
	return ret;
}


int ext4_swap_extents(handle_t *handle, struct inode *inode1, struct inode *inode2, ext4_lblk_t lblk1, ext4_lblk_t lblk2, ext4_lblk_t count, int unwritten, int *erp)


{
	struct ext4_ext_path *path1 = NULL;
	struct ext4_ext_path *path2 = NULL;
	int replaced_count = 0;

	BUG_ON(!rwsem_is_locked(&EXT4_I(inode1)->i_data_sem));
	BUG_ON(!rwsem_is_locked(&EXT4_I(inode2)->i_data_sem));
	BUG_ON(!inode_is_locked(inode1));
	BUG_ON(!inode_is_locked(inode2));

	*erp = ext4_es_remove_extent(inode1, lblk1, count);
	if (unlikely(*erp))
		return 0;
	*erp = ext4_es_remove_extent(inode2, lblk2, count);
	if (unlikely(*erp))
		return 0;

	while (count) {
		struct ext4_extent *ex1, *ex2, tmp_ex;
		ext4_lblk_t e1_blk, e2_blk;
		int e1_len, e2_len, len;
		int split = 0;

		path1 = ext4_find_extent(inode1, lblk1, NULL, EXT4_EX_NOCACHE);
		if (IS_ERR(path1)) {
			*erp = PTR_ERR(path1);
			path1 = NULL;
		finish:
			count = 0;
			goto repeat;
		}
		path2 = ext4_find_extent(inode2, lblk2, NULL, EXT4_EX_NOCACHE);
		if (IS_ERR(path2)) {
			*erp = PTR_ERR(path2);
			path2 = NULL;
			goto finish;
		}
		ex1 = path1[path1->p_depth].p_ext;
		ex2 = path2[path2->p_depth].p_ext;
		
		if (unlikely(!ex2 || !ex1))
			goto finish;

		e1_blk = le32_to_cpu(ex1->ee_block);
		e2_blk = le32_to_cpu(ex2->ee_block);
		e1_len = ext4_ext_get_actual_len(ex1);
		e2_len = ext4_ext_get_actual_len(ex2);

		
		if (!in_range(lblk1, e1_blk, e1_len) || !in_range(lblk2, e2_blk, e2_len)) {
			ext4_lblk_t next1, next2;

			
			next1 = ext4_ext_next_allocated_block(path1);
			next2 = ext4_ext_next_allocated_block(path2);
			
			if (e1_blk > lblk1)
				next1 = e1_blk;
			if (e2_blk > lblk2)
				next2 = e2_blk;
			
			if (next1 == EXT_MAX_BLOCKS || next2 == EXT_MAX_BLOCKS)
				goto finish;
			
			len = next1 - lblk1;
			if (len < next2 - lblk2)
				len = next2 - lblk2;
			if (len > count)
				len = count;
			lblk1 += len;
			lblk2 += len;
			count -= len;
			goto repeat;
		}

		
		if (e1_blk < lblk1) {
			split = 1;
			*erp = ext4_force_split_extent_at(handle, inode1, &path1, lblk1, 0);
			if (unlikely(*erp))
				goto finish;
		}
		if (e2_blk < lblk2) {
			split = 1;
			*erp = ext4_force_split_extent_at(handle, inode2, &path2,  lblk2, 0);
			if (unlikely(*erp))
				goto finish;
		}
		
		if (split)
			goto repeat;

		
		len = count;
		if (len > e1_blk + e1_len - lblk1)
			len = e1_blk + e1_len - lblk1;
		if (len > e2_blk + e2_len - lblk2)
			len = e2_blk + e2_len - lblk2;

		if (len != e1_len) {
			split = 1;
			*erp = ext4_force_split_extent_at(handle, inode1, &path1, lblk1 + len, 0);
			if (unlikely(*erp))
				goto finish;
		}
		if (len != e2_len) {
			split = 1;
			*erp = ext4_force_split_extent_at(handle, inode2, &path2, lblk2 + len, 0);
			if (*erp)
				goto finish;
		}
		
		if (split)
			goto repeat;

		BUG_ON(e2_len != e1_len);
		*erp = ext4_ext_get_access(handle, inode1, path1 + path1->p_depth);
		if (unlikely(*erp))
			goto finish;
		*erp = ext4_ext_get_access(handle, inode2, path2 + path2->p_depth);
		if (unlikely(*erp))
			goto finish;

		
		tmp_ex = *ex1;
		ext4_ext_store_pblock(ex1, ext4_ext_pblock(ex2));
		ext4_ext_store_pblock(ex2, ext4_ext_pblock(&tmp_ex));
		ex1->ee_len = cpu_to_le16(e2_len);
		ex2->ee_len = cpu_to_le16(e1_len);
		if (unwritten)
			ext4_ext_mark_unwritten(ex2);
		if (ext4_ext_is_unwritten(&tmp_ex))
			ext4_ext_mark_unwritten(ex1);

		ext4_ext_try_to_merge(handle, inode2, path2, ex2);
		ext4_ext_try_to_merge(handle, inode1, path1, ex1);
		*erp = ext4_ext_dirty(handle, inode2, path2 + path2->p_depth);
		if (unlikely(*erp))
			goto finish;
		*erp = ext4_ext_dirty(handle, inode1, path1 + path1->p_depth);
		
		if (unlikely(*erp))
			goto finish;
		lblk1 += len;
		lblk2 += len;
		replaced_count += len;
		count -= len;

	repeat:
		ext4_ext_drop_refs(path1);
		kfree(path1);
		ext4_ext_drop_refs(path2);
		kfree(path2);
		path1 = path2 = NULL;
	}
	return replaced_count;
}


int ext4_clu_mapped(struct inode *inode, ext4_lblk_t lclu)
{
	struct ext4_sb_info *sbi = EXT4_SB(inode->i_sb);
	struct ext4_ext_path *path;
	int depth, mapped = 0, err = 0;
	struct ext4_extent *extent;
	ext4_lblk_t first_lblk, first_lclu, last_lclu;

	
	path = ext4_find_extent(inode, EXT4_C2B(sbi, lclu), NULL, 0);
	if (IS_ERR(path)) {
		err = PTR_ERR(path);
		path = NULL;
		goto out;
	}

	depth = ext_depth(inode);

	
	if (unlikely(path[depth].p_ext == NULL && depth != 0)) {
		EXT4_ERROR_INODE(inode, "bad extent address - lblock: %lu, depth: %d, pblock: %lld", (unsigned long) EXT4_C2B(sbi, lclu), depth, path[depth].p_block);


		err = -EFSCORRUPTED;
		goto out;
	}

	extent = path[depth].p_ext;

	
	if (extent == NULL)
		goto out;

	first_lblk = le32_to_cpu(extent->ee_block);
	first_lclu = EXT4_B2C(sbi, first_lblk);

	
	if (lclu >= first_lclu) {
		last_lclu = EXT4_B2C(sbi, first_lblk + ext4_ext_get_actual_len(extent) - 1);
		if (lclu <= last_lclu) {
			mapped = 1;
		} else {
			first_lblk = ext4_ext_next_allocated_block(path);
			first_lclu = EXT4_B2C(sbi, first_lblk);
			if (lclu == first_lclu)
				mapped = 1;
		}
	}

out:
	ext4_ext_drop_refs(path);
	kfree(path);

	return err ? err : mapped;
}
