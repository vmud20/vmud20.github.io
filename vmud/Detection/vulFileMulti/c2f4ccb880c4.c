

































static __u32 ext4_inode_csum(struct inode *inode, struct ext4_inode *raw, struct ext4_inode_info *ei)
{
	struct ext4_sb_info *sbi = EXT4_SB(inode->i_sb);
	__u32 csum;
	__u16 dummy_csum = 0;
	int offset = offsetof(struct ext4_inode, i_checksum_lo);
	unsigned int csum_size = sizeof(dummy_csum);

	csum = ext4_chksum(sbi, ei->i_csum_seed, (__u8 *)raw, offset);
	csum = ext4_chksum(sbi, csum, (__u8 *)&dummy_csum, csum_size);
	offset += csum_size;
	csum = ext4_chksum(sbi, csum, (__u8 *)raw + offset, EXT4_GOOD_OLD_INODE_SIZE - offset);

	if (EXT4_INODE_SIZE(inode->i_sb) > EXT4_GOOD_OLD_INODE_SIZE) {
		offset = offsetof(struct ext4_inode, i_checksum_hi);
		csum = ext4_chksum(sbi, csum, (__u8 *)raw + EXT4_GOOD_OLD_INODE_SIZE, offset - EXT4_GOOD_OLD_INODE_SIZE);

		if (EXT4_FITS_IN_INODE(raw, ei, i_checksum_hi)) {
			csum = ext4_chksum(sbi, csum, (__u8 *)&dummy_csum, csum_size);
			offset += csum_size;
		}
		csum = ext4_chksum(sbi, csum, (__u8 *)raw + offset, EXT4_INODE_SIZE(inode->i_sb) - offset);
	}

	return csum;
}

static int ext4_inode_csum_verify(struct inode *inode, struct ext4_inode *raw, struct ext4_inode_info *ei)
{
	__u32 provided, calculated;

	if (EXT4_SB(inode->i_sb)->s_es->s_creator_os != cpu_to_le32(EXT4_OS_LINUX) || !ext4_has_metadata_csum(inode->i_sb))

		return 1;

	provided = le16_to_cpu(raw->i_checksum_lo);
	calculated = ext4_inode_csum(inode, raw, ei);
	if (EXT4_INODE_SIZE(inode->i_sb) > EXT4_GOOD_OLD_INODE_SIZE && EXT4_FITS_IN_INODE(raw, ei, i_checksum_hi))
		provided |= ((__u32)le16_to_cpu(raw->i_checksum_hi)) << 16;
	else calculated &= 0xFFFF;

	return provided == calculated;
}

static void ext4_inode_csum_set(struct inode *inode, struct ext4_inode *raw, struct ext4_inode_info *ei)
{
	__u32 csum;

	if (EXT4_SB(inode->i_sb)->s_es->s_creator_os != cpu_to_le32(EXT4_OS_LINUX) || !ext4_has_metadata_csum(inode->i_sb))

		return;

	csum = ext4_inode_csum(inode, raw, ei);
	raw->i_checksum_lo = cpu_to_le16(csum & 0xFFFF);
	if (EXT4_INODE_SIZE(inode->i_sb) > EXT4_GOOD_OLD_INODE_SIZE && EXT4_FITS_IN_INODE(raw, ei, i_checksum_hi))
		raw->i_checksum_hi = cpu_to_le16(csum >> 16);
}

static inline int ext4_begin_ordered_truncate(struct inode *inode, loff_t new_size)
{
	trace_ext4_begin_ordered_truncate(inode, new_size);
	
	if (!EXT4_I(inode)->jinode)
		return 0;
	return jbd2_journal_begin_ordered_truncate(EXT4_JOURNAL(inode), EXT4_I(inode)->jinode, new_size);

}

static void ext4_invalidatepage(struct page *page, unsigned int offset, unsigned int length);
static int __ext4_journalled_writepage(struct page *page, unsigned int len);
static int ext4_bh_delay_or_unwritten(handle_t *handle, struct buffer_head *bh);
static int ext4_meta_trans_blocks(struct inode *inode, int lblocks, int pextents);


int ext4_inode_is_fast_symlink(struct inode *inode)
{
	if (!(EXT4_I(inode)->i_flags & EXT4_EA_INODE_FL)) {
		int ea_blocks = EXT4_I(inode)->i_file_acl ? EXT4_CLUSTER_SIZE(inode->i_sb) >> 9 : 0;

		if (ext4_has_inline_data(inode))
			return 0;

		return (S_ISLNK(inode->i_mode) && inode->i_blocks - ea_blocks == 0);
	}
	return S_ISLNK(inode->i_mode) && inode->i_size && (inode->i_size < EXT4_N_BLOCKS * 4);
}


int ext4_truncate_restart_trans(handle_t *handle, struct inode *inode, int nblocks)
{
	int ret;

	
	BUG_ON(EXT4_JOURNAL(inode) == NULL);
	jbd_debug(2, "restarting handle %p\n", handle);
	up_write(&EXT4_I(inode)->i_data_sem);
	ret = ext4_journal_restart(handle, nblocks);
	down_write(&EXT4_I(inode)->i_data_sem);
	ext4_discard_preallocations(inode);

	return ret;
}


void ext4_evict_inode(struct inode *inode)
{
	handle_t *handle;
	int err;
	int extra_credits = 3;
	struct ext4_xattr_inode_array *ea_inode_array = NULL;

	trace_ext4_evict_inode(inode);

	if (inode->i_nlink) {
		
		if (inode->i_ino != EXT4_JOURNAL_INO && ext4_should_journal_data(inode) && (S_ISLNK(inode->i_mode) || S_ISREG(inode->i_mode)) && inode->i_data.nrpages) {


			journal_t *journal = EXT4_SB(inode->i_sb)->s_journal;
			tid_t commit_tid = EXT4_I(inode)->i_datasync_tid;

			jbd2_complete_transaction(journal, commit_tid);
			filemap_write_and_wait(&inode->i_data);
		}
		truncate_inode_pages_final(&inode->i_data);

		goto no_delete;
	}

	if (is_bad_inode(inode))
		goto no_delete;
	dquot_initialize(inode);

	if (ext4_should_order_data(inode))
		ext4_begin_ordered_truncate(inode, 0);
	truncate_inode_pages_final(&inode->i_data);

	
	sb_start_intwrite(inode->i_sb);

	if (!IS_NOQUOTA(inode))
		extra_credits += EXT4_MAXQUOTAS_DEL_BLOCKS(inode->i_sb);

	handle = ext4_journal_start(inode, EXT4_HT_TRUNCATE, ext4_blocks_for_truncate(inode)+extra_credits);
	if (IS_ERR(handle)) {
		ext4_std_error(inode->i_sb, PTR_ERR(handle));
		
		ext4_orphan_del(NULL, inode);
		sb_end_intwrite(inode->i_sb);
		goto no_delete;
	}

	if (IS_SYNC(inode))
		ext4_handle_sync(handle);

	
	if (ext4_inode_is_fast_symlink(inode))
		memset(EXT4_I(inode)->i_data, 0, sizeof(EXT4_I(inode)->i_data));
	inode->i_size = 0;
	err = ext4_mark_inode_dirty(handle, inode);
	if (err) {
		ext4_warning(inode->i_sb, "couldn't mark inode dirty (err %d)", err);
		goto stop_handle;
	}
	if (inode->i_blocks) {
		err = ext4_truncate(inode);
		if (err) {
			ext4_error(inode->i_sb, "couldn't truncate inode %lu (err %d)", inode->i_ino, err);

			goto stop_handle;
		}
	}

	
	err = ext4_xattr_delete_inode(handle, inode, &ea_inode_array, extra_credits);
	if (err) {
		ext4_warning(inode->i_sb, "xattr delete (err %d)", err);
stop_handle:
		ext4_journal_stop(handle);
		ext4_orphan_del(NULL, inode);
		sb_end_intwrite(inode->i_sb);
		ext4_xattr_inode_array_free(ea_inode_array);
		goto no_delete;
	}

	
	ext4_orphan_del(handle, inode);
	EXT4_I(inode)->i_dtime	= get_seconds();

	
	if (ext4_mark_inode_dirty(handle, inode))
		
		ext4_clear_inode(inode);
	else ext4_free_inode(handle, inode);
	ext4_journal_stop(handle);
	sb_end_intwrite(inode->i_sb);
	ext4_xattr_inode_array_free(ea_inode_array);
	return;
no_delete:
	ext4_clear_inode(inode);	
}


qsize_t *ext4_get_reserved_space(struct inode *inode)
{
	return &EXT4_I(inode)->i_reserved_quota;
}



void ext4_da_update_reserve_space(struct inode *inode, int used, int quota_claim)
{
	struct ext4_sb_info *sbi = EXT4_SB(inode->i_sb);
	struct ext4_inode_info *ei = EXT4_I(inode);

	spin_lock(&ei->i_block_reservation_lock);
	trace_ext4_da_update_reserve_space(inode, used, quota_claim);
	if (unlikely(used > ei->i_reserved_data_blocks)) {
		ext4_warning(inode->i_sb, "%s: ino %lu, used %d " "with only %d reserved data blocks", __func__, inode->i_ino, used, ei->i_reserved_data_blocks);


		WARN_ON(1);
		used = ei->i_reserved_data_blocks;
	}

	
	ei->i_reserved_data_blocks -= used;
	percpu_counter_sub(&sbi->s_dirtyclusters_counter, used);

	spin_unlock(&EXT4_I(inode)->i_block_reservation_lock);

	
	if (quota_claim)
		dquot_claim_block(inode, EXT4_C2B(sbi, used));
	else {
		
		dquot_release_reservation_block(inode, EXT4_C2B(sbi, used));
	}

	
	if ((ei->i_reserved_data_blocks == 0) && (atomic_read(&inode->i_writecount) == 0))
		ext4_discard_preallocations(inode);
}

static int __check_block_validity(struct inode *inode, const char *func, unsigned int line, struct ext4_map_blocks *map)

{
	if (!ext4_data_block_valid(EXT4_SB(inode->i_sb), map->m_pblk, map->m_len)) {
		ext4_error_inode(inode, func, line, map->m_pblk, "lblock %lu mapped to illegal pblock %llu " "(length %d)", (unsigned long) map->m_lblk, map->m_pblk, map->m_len);


		return -EFSCORRUPTED;
	}
	return 0;
}

int ext4_issue_zeroout(struct inode *inode, ext4_lblk_t lblk, ext4_fsblk_t pblk, ext4_lblk_t len)
{
	int ret;

	if (ext4_encrypted_inode(inode))
		return fscrypt_zeroout_range(inode, lblk, pblk, len);

	ret = sb_issue_zeroout(inode->i_sb, pblk, len, GFP_NOFS);
	if (ret > 0)
		ret = 0;

	return ret;
}




static void ext4_map_blocks_es_recheck(handle_t *handle, struct inode *inode, struct ext4_map_blocks *es_map, struct ext4_map_blocks *map, int flags)



{
	int retval;

	map->m_flags = 0;
	
	down_read(&EXT4_I(inode)->i_data_sem);
	if (ext4_test_inode_flag(inode, EXT4_INODE_EXTENTS)) {
		retval = ext4_ext_map_blocks(handle, inode, map, flags & EXT4_GET_BLOCKS_KEEP_SIZE);
	} else {
		retval = ext4_ind_map_blocks(handle, inode, map, flags & EXT4_GET_BLOCKS_KEEP_SIZE);
	}
	up_read((&EXT4_I(inode)->i_data_sem));

	
	if (es_map->m_lblk != map->m_lblk || es_map->m_flags != map->m_flags || es_map->m_pblk != map->m_pblk) {

		printk("ES cache assertion failed for inode: %lu " "es_cached ex [%d/%d/%llu/%x] != " "found ex [%d/%d/%llu/%x] retval %d flags %x\n", inode->i_ino, es_map->m_lblk, es_map->m_len, es_map->m_pblk, es_map->m_flags, map->m_lblk, map->m_len, map->m_pblk, map->m_flags, retval, flags);





	}
}



int ext4_map_blocks(handle_t *handle, struct inode *inode, struct ext4_map_blocks *map, int flags)
{
	struct extent_status es;
	int retval;
	int ret = 0;

	struct ext4_map_blocks orig_map;

	memcpy(&orig_map, map, sizeof(*map));


	map->m_flags = 0;
	ext_debug("ext4_map_blocks(): inode %lu, flag %d, max_blocks %u," "logical block %lu\n", inode->i_ino, flags, map->m_len, (unsigned long) map->m_lblk);


	
	if (unlikely(map->m_len > INT_MAX))
		map->m_len = INT_MAX;

	
	if (unlikely(map->m_lblk >= EXT_MAX_BLOCKS))
		return -EFSCORRUPTED;

	
	if (ext4_es_lookup_extent(inode, map->m_lblk, &es)) {
		if (ext4_es_is_written(&es) || ext4_es_is_unwritten(&es)) {
			map->m_pblk = ext4_es_pblock(&es) + map->m_lblk - es.es_lblk;
			map->m_flags |= ext4_es_is_written(&es) ? EXT4_MAP_MAPPED : EXT4_MAP_UNWRITTEN;
			retval = es.es_len - (map->m_lblk - es.es_lblk);
			if (retval > map->m_len)
				retval = map->m_len;
			map->m_len = retval;
		} else if (ext4_es_is_delayed(&es) || ext4_es_is_hole(&es)) {
			map->m_pblk = 0;
			retval = es.es_len - (map->m_lblk - es.es_lblk);
			if (retval > map->m_len)
				retval = map->m_len;
			map->m_len = retval;
			retval = 0;
		} else {
			BUG_ON(1);
		}

		ext4_map_blocks_es_recheck(handle, inode, map, &orig_map, flags);

		goto found;
	}

	
	down_read(&EXT4_I(inode)->i_data_sem);
	if (ext4_test_inode_flag(inode, EXT4_INODE_EXTENTS)) {
		retval = ext4_ext_map_blocks(handle, inode, map, flags & EXT4_GET_BLOCKS_KEEP_SIZE);
	} else {
		retval = ext4_ind_map_blocks(handle, inode, map, flags & EXT4_GET_BLOCKS_KEEP_SIZE);
	}
	if (retval > 0) {
		unsigned int status;

		if (unlikely(retval != map->m_len)) {
			ext4_warning(inode->i_sb, "ES len assertion failed for inode " "%lu: retval %d != map->m_len %d", inode->i_ino, retval, map->m_len);


			WARN_ON(1);
		}

		status = map->m_flags & EXT4_MAP_UNWRITTEN ? EXTENT_STATUS_UNWRITTEN : EXTENT_STATUS_WRITTEN;
		if (!(flags & EXT4_GET_BLOCKS_DELALLOC_RESERVE) && !(status & EXTENT_STATUS_WRITTEN) && ext4_find_delalloc_range(inode, map->m_lblk, map->m_lblk + map->m_len - 1))


			status |= EXTENT_STATUS_DELAYED;
		ret = ext4_es_insert_extent(inode, map->m_lblk, map->m_len, map->m_pblk, status);
		if (ret < 0)
			retval = ret;
	}
	up_read((&EXT4_I(inode)->i_data_sem));

found:
	if (retval > 0 && map->m_flags & EXT4_MAP_MAPPED) {
		ret = check_block_validity(inode, map);
		if (ret != 0)
			return ret;
	}

	
	if ((flags & EXT4_GET_BLOCKS_CREATE) == 0)
		return retval;

	
	if (retval > 0 && map->m_flags & EXT4_MAP_MAPPED)
		
		if (!(flags & EXT4_GET_BLOCKS_CONVERT_UNWRITTEN))
			return retval;

	
	map->m_flags &= ~EXT4_MAP_FLAGS;

	
	down_write(&EXT4_I(inode)->i_data_sem);

	
	if (ext4_test_inode_flag(inode, EXT4_INODE_EXTENTS)) {
		retval = ext4_ext_map_blocks(handle, inode, map, flags);
	} else {
		retval = ext4_ind_map_blocks(handle, inode, map, flags);

		if (retval > 0 && map->m_flags & EXT4_MAP_NEW) {
			
			ext4_clear_inode_state(inode, EXT4_STATE_EXT_MIGRATE);
		}

		
		if ((retval > 0) && (flags & EXT4_GET_BLOCKS_DELALLOC_RESERVE))
			ext4_da_update_reserve_space(inode, retval, 1);
	}

	if (retval > 0) {
		unsigned int status;

		if (unlikely(retval != map->m_len)) {
			ext4_warning(inode->i_sb, "ES len assertion failed for inode " "%lu: retval %d != map->m_len %d", inode->i_ino, retval, map->m_len);


			WARN_ON(1);
		}

		
		if (flags & EXT4_GET_BLOCKS_ZERO && map->m_flags & EXT4_MAP_MAPPED && map->m_flags & EXT4_MAP_NEW) {

			clean_bdev_aliases(inode->i_sb->s_bdev, map->m_pblk, map->m_len);
			ret = ext4_issue_zeroout(inode, map->m_lblk, map->m_pblk, map->m_len);
			if (ret) {
				retval = ret;
				goto out_sem;
			}
		}

		
		if ((flags & EXT4_GET_BLOCKS_PRE_IO) && ext4_es_lookup_extent(inode, map->m_lblk, &es)) {
			if (ext4_es_is_written(&es))
				goto out_sem;
		}
		status = map->m_flags & EXT4_MAP_UNWRITTEN ? EXTENT_STATUS_UNWRITTEN : EXTENT_STATUS_WRITTEN;
		if (!(flags & EXT4_GET_BLOCKS_DELALLOC_RESERVE) && !(status & EXTENT_STATUS_WRITTEN) && ext4_find_delalloc_range(inode, map->m_lblk, map->m_lblk + map->m_len - 1))


			status |= EXTENT_STATUS_DELAYED;
		ret = ext4_es_insert_extent(inode, map->m_lblk, map->m_len, map->m_pblk, status);
		if (ret < 0) {
			retval = ret;
			goto out_sem;
		}
	}

out_sem:
	up_write((&EXT4_I(inode)->i_data_sem));
	if (retval > 0 && map->m_flags & EXT4_MAP_MAPPED) {
		ret = check_block_validity(inode, map);
		if (ret != 0)
			return ret;

		
		if (map->m_flags & EXT4_MAP_NEW && !(map->m_flags & EXT4_MAP_UNWRITTEN) && !(flags & EXT4_GET_BLOCKS_ZERO) && !ext4_is_quota_file(inode) && ext4_should_order_data(inode)) {



			if (flags & EXT4_GET_BLOCKS_IO_SUBMIT)
				ret = ext4_jbd2_inode_add_wait(handle, inode);
			else ret = ext4_jbd2_inode_add_write(handle, inode);
			if (ret)
				return ret;
		}
	}
	return retval;
}


static void ext4_update_bh_state(struct buffer_head *bh, unsigned long flags)
{
	unsigned long old_state;
	unsigned long new_state;

	flags &= EXT4_MAP_FLAGS;

	
	if (!bh->b_page) {
		bh->b_state = (bh->b_state & ~EXT4_MAP_FLAGS) | flags;
		return;
	}
	
	do {
		old_state = READ_ONCE(bh->b_state);
		new_state = (old_state & ~EXT4_MAP_FLAGS) | flags;
	} while (unlikely( cmpxchg(&bh->b_state, old_state, new_state) != old_state));
}

static int _ext4_get_block(struct inode *inode, sector_t iblock, struct buffer_head *bh, int flags)
{
	struct ext4_map_blocks map;
	int ret = 0;

	if (ext4_has_inline_data(inode))
		return -ERANGE;

	map.m_lblk = iblock;
	map.m_len = bh->b_size >> inode->i_blkbits;

	ret = ext4_map_blocks(ext4_journal_current_handle(), inode, &map, flags);
	if (ret > 0) {
		map_bh(bh, inode->i_sb, map.m_pblk);
		ext4_update_bh_state(bh, map.m_flags);
		bh->b_size = inode->i_sb->s_blocksize * map.m_len;
		ret = 0;
	} else if (ret == 0) {
		
		bh->b_size = inode->i_sb->s_blocksize * map.m_len;
	}
	return ret;
}

int ext4_get_block(struct inode *inode, sector_t iblock, struct buffer_head *bh, int create)
{
	return _ext4_get_block(inode, iblock, bh, create ? EXT4_GET_BLOCKS_CREATE : 0);
}


int ext4_get_block_unwritten(struct inode *inode, sector_t iblock, struct buffer_head *bh_result, int create)
{
	ext4_debug("ext4_get_block_unwritten: inode %lu, create flag %d\n", inode->i_ino, create);
	return _ext4_get_block(inode, iblock, bh_result, EXT4_GET_BLOCKS_IO_CREATE_EXT);
}





static int ext4_get_block_trans(struct inode *inode, sector_t iblock, struct buffer_head *bh_result, int flags)
{
	int dio_credits;
	handle_t *handle;
	int retries = 0;
	int ret;

	
	if (bh_result->b_size >> inode->i_blkbits > DIO_MAX_BLOCKS)
		bh_result->b_size = DIO_MAX_BLOCKS << inode->i_blkbits;
	dio_credits = ext4_chunk_trans_blocks(inode, bh_result->b_size >> inode->i_blkbits);
retry:
	handle = ext4_journal_start(inode, EXT4_HT_MAP_BLOCKS, dio_credits);
	if (IS_ERR(handle))
		return PTR_ERR(handle);

	ret = _ext4_get_block(inode, iblock, bh_result, flags);
	ext4_journal_stop(handle);

	if (ret == -ENOSPC && ext4_should_retry_alloc(inode->i_sb, &retries))
		goto retry;
	return ret;
}


int ext4_dio_get_block(struct inode *inode, sector_t iblock, struct buffer_head *bh, int create)
{
	
	WARN_ON_ONCE(ext4_journal_current_handle());

	if (!create)
		return _ext4_get_block(inode, iblock, bh, 0);
	return ext4_get_block_trans(inode, iblock, bh, EXT4_GET_BLOCKS_CREATE);
}


static int ext4_dio_get_block_unwritten_async(struct inode *inode, sector_t iblock, struct buffer_head *bh_result,	int create)
{
	int ret;

	
	WARN_ON_ONCE(ext4_journal_current_handle());

	ret = ext4_get_block_trans(inode, iblock, bh_result, EXT4_GET_BLOCKS_IO_CREATE_EXT);

	
	if (!ret && buffer_unwritten(bh_result)) {
		if (!bh_result->b_private) {
			ext4_io_end_t *io_end;

			io_end = ext4_init_io_end(inode, GFP_KERNEL);
			if (!io_end)
				return -ENOMEM;
			bh_result->b_private = io_end;
			ext4_set_io_unwritten_flag(inode, io_end);
		}
		set_buffer_defer_completion(bh_result);
	}

	return ret;
}


static int ext4_dio_get_block_unwritten_sync(struct inode *inode, sector_t iblock, struct buffer_head *bh_result,	int create)
{
	int ret;

	
	WARN_ON_ONCE(ext4_journal_current_handle());

	ret = ext4_get_block_trans(inode, iblock, bh_result, EXT4_GET_BLOCKS_IO_CREATE_EXT);

	
	if (!ret && buffer_unwritten(bh_result))
		ext4_set_inode_state(inode, EXT4_STATE_DIO_UNWRITTEN);

	return ret;
}

static int ext4_dio_get_block_overwrite(struct inode *inode, sector_t iblock, struct buffer_head *bh_result, int create)
{
	int ret;

	ext4_debug("ext4_dio_get_block_overwrite: inode %lu, create flag %d\n", inode->i_ino, create);
	
	WARN_ON_ONCE(ext4_journal_current_handle());

	ret = _ext4_get_block(inode, iblock, bh_result, 0);
	
	WARN_ON_ONCE(!buffer_mapped(bh_result) || buffer_unwritten(bh_result));

	return ret;
}



struct buffer_head *ext4_getblk(handle_t *handle, struct inode *inode, ext4_lblk_t block, int map_flags)
{
	struct ext4_map_blocks map;
	struct buffer_head *bh;
	int create = map_flags & EXT4_GET_BLOCKS_CREATE;
	int err;

	J_ASSERT(handle != NULL || create == 0);

	map.m_lblk = block;
	map.m_len = 1;
	err = ext4_map_blocks(handle, inode, &map, map_flags);

	if (err == 0)
		return create ? ERR_PTR(-ENOSPC) : NULL;
	if (err < 0)
		return ERR_PTR(err);

	bh = sb_getblk(inode->i_sb, map.m_pblk);
	if (unlikely(!bh))
		return ERR_PTR(-ENOMEM);
	if (map.m_flags & EXT4_MAP_NEW) {
		J_ASSERT(create != 0);
		J_ASSERT(handle != NULL);

		
		lock_buffer(bh);
		BUFFER_TRACE(bh, "call get_create_access");
		err = ext4_journal_get_create_access(handle, bh);
		if (unlikely(err)) {
			unlock_buffer(bh);
			goto errout;
		}
		if (!buffer_uptodate(bh)) {
			memset(bh->b_data, 0, inode->i_sb->s_blocksize);
			set_buffer_uptodate(bh);
		}
		unlock_buffer(bh);
		BUFFER_TRACE(bh, "call ext4_handle_dirty_metadata");
		err = ext4_handle_dirty_metadata(handle, inode, bh);
		if (unlikely(err))
			goto errout;
	} else BUFFER_TRACE(bh, "not a new buffer");
	return bh;
errout:
	brelse(bh);
	return ERR_PTR(err);
}

struct buffer_head *ext4_bread(handle_t *handle, struct inode *inode, ext4_lblk_t block, int map_flags)
{
	struct buffer_head *bh;

	bh = ext4_getblk(handle, inode, block, map_flags);
	if (IS_ERR(bh))
		return bh;
	if (!bh || buffer_uptodate(bh))
		return bh;
	ll_rw_block(REQ_OP_READ, REQ_META | REQ_PRIO, 1, &bh);
	wait_on_buffer(bh);
	if (buffer_uptodate(bh))
		return bh;
	put_bh(bh);
	return ERR_PTR(-EIO);
}


int ext4_bread_batch(struct inode *inode, ext4_lblk_t block, int bh_count, bool wait, struct buffer_head **bhs)
{
	int i, err;

	for (i = 0; i < bh_count; i++) {
		bhs[i] = ext4_getblk(NULL, inode, block + i, 0 );
		if (IS_ERR(bhs[i])) {
			err = PTR_ERR(bhs[i]);
			bh_count = i;
			goto out_brelse;
		}
	}

	for (i = 0; i < bh_count; i++)
		
		if (bhs[i] && !buffer_uptodate(bhs[i]))
			ll_rw_block(REQ_OP_READ, REQ_META | REQ_PRIO, 1, &bhs[i]);

	if (!wait)
		return 0;

	for (i = 0; i < bh_count; i++)
		if (bhs[i])
			wait_on_buffer(bhs[i]);

	for (i = 0; i < bh_count; i++) {
		if (bhs[i] && !buffer_uptodate(bhs[i])) {
			err = -EIO;
			goto out_brelse;
		}
	}
	return 0;

out_brelse:
	for (i = 0; i < bh_count; i++) {
		brelse(bhs[i]);
		bhs[i] = NULL;
	}
	return err;
}

int ext4_walk_page_buffers(handle_t *handle, struct buffer_head *head, unsigned from, unsigned to, int *partial, int (*fn)(handle_t *handle, struct buffer_head *bh))





{
	struct buffer_head *bh;
	unsigned block_start, block_end;
	unsigned blocksize = head->b_size;
	int err, ret = 0;
	struct buffer_head *next;

	for (bh = head, block_start = 0;
	     ret == 0 && (bh != head || !block_start);
	     block_start = block_end, bh = next) {
		next = bh->b_this_page;
		block_end = block_start + blocksize;
		if (block_end <= from || block_start >= to) {
			if (partial && !buffer_uptodate(bh))
				*partial = 1;
			continue;
		}
		err = (*fn)(handle, bh);
		if (!ret)
			ret = err;
	}
	return ret;
}


int do_journal_get_write_access(handle_t *handle, struct buffer_head *bh)
{
	int dirty = buffer_dirty(bh);
	int ret;

	if (!buffer_mapped(bh) || buffer_freed(bh))
		return 0;
	
	if (dirty)
		clear_buffer_dirty(bh);
	BUFFER_TRACE(bh, "get write access");
	ret = ext4_journal_get_write_access(handle, bh);
	if (!ret && dirty)
		ret = ext4_handle_dirty_metadata(handle, NULL, bh);
	return ret;
}


static int ext4_block_write_begin(struct page *page, loff_t pos, unsigned len, get_block_t *get_block)
{
	unsigned from = pos & (PAGE_SIZE - 1);
	unsigned to = from + len;
	struct inode *inode = page->mapping->host;
	unsigned block_start, block_end;
	sector_t block;
	int err = 0;
	unsigned blocksize = inode->i_sb->s_blocksize;
	unsigned bbits;
	struct buffer_head *bh, *head, *wait[2], **wait_bh = wait;
	bool decrypt = false;

	BUG_ON(!PageLocked(page));
	BUG_ON(from > PAGE_SIZE);
	BUG_ON(to > PAGE_SIZE);
	BUG_ON(from > to);

	if (!page_has_buffers(page))
		create_empty_buffers(page, blocksize, 0);
	head = page_buffers(page);
	bbits = ilog2(blocksize);
	block = (sector_t)page->index << (PAGE_SHIFT - bbits);

	for (bh = head, block_start = 0; bh != head || !block_start;
	    block++, block_start = block_end, bh = bh->b_this_page) {
		block_end = block_start + blocksize;
		if (block_end <= from || block_start >= to) {
			if (PageUptodate(page)) {
				if (!buffer_uptodate(bh))
					set_buffer_uptodate(bh);
			}
			continue;
		}
		if (buffer_new(bh))
			clear_buffer_new(bh);
		if (!buffer_mapped(bh)) {
			WARN_ON(bh->b_size != blocksize);
			err = get_block(inode, block, bh, 1);
			if (err)
				break;
			if (buffer_new(bh)) {
				clean_bdev_bh_alias(bh);
				if (PageUptodate(page)) {
					clear_buffer_new(bh);
					set_buffer_uptodate(bh);
					mark_buffer_dirty(bh);
					continue;
				}
				if (block_end > to || block_start < from)
					zero_user_segments(page, to, block_end, block_start, from);
				continue;
			}
		}
		if (PageUptodate(page)) {
			if (!buffer_uptodate(bh))
				set_buffer_uptodate(bh);
			continue;
		}
		if (!buffer_uptodate(bh) && !buffer_delay(bh) && !buffer_unwritten(bh) && (block_start < from || block_end > to)) {

			ll_rw_block(REQ_OP_READ, 0, 1, &bh);
			*wait_bh++ = bh;
			decrypt = ext4_encrypted_inode(inode) && S_ISREG(inode->i_mode);
		}
	}
	
	while (wait_bh > wait) {
		wait_on_buffer(*--wait_bh);
		if (!buffer_uptodate(*wait_bh))
			err = -EIO;
	}
	if (unlikely(err))
		page_zero_new_buffers(page, from, to);
	else if (decrypt)
		err = fscrypt_decrypt_page(page->mapping->host, page, PAGE_SIZE, 0, page->index);
	return err;
}


static int ext4_write_begin(struct file *file, struct address_space *mapping, loff_t pos, unsigned len, unsigned flags, struct page **pagep, void **fsdata)

{
	struct inode *inode = mapping->host;
	int ret, needed_blocks;
	handle_t *handle;
	int retries = 0;
	struct page *page;
	pgoff_t index;
	unsigned from, to;

	if (unlikely(ext4_forced_shutdown(EXT4_SB(inode->i_sb))))
		return -EIO;

	trace_ext4_write_begin(inode, pos, len, flags);
	
	needed_blocks = ext4_writepage_trans_blocks(inode) + 1;
	index = pos >> PAGE_SHIFT;
	from = pos & (PAGE_SIZE - 1);
	to = from + len;

	if (ext4_test_inode_state(inode, EXT4_STATE_MAY_INLINE_DATA)) {
		ret = ext4_try_to_write_inline_data(mapping, inode, pos, len, flags, pagep);
		if (ret < 0)
			return ret;
		if (ret == 1)
			return 0;
	}

	
retry_grab:
	page = grab_cache_page_write_begin(mapping, index, flags);
	if (!page)
		return -ENOMEM;
	unlock_page(page);

retry_journal:
	handle = ext4_journal_start(inode, EXT4_HT_WRITE_PAGE, needed_blocks);
	if (IS_ERR(handle)) {
		put_page(page);
		return PTR_ERR(handle);
	}

	lock_page(page);
	if (page->mapping != mapping) {
		
		unlock_page(page);
		put_page(page);
		ext4_journal_stop(handle);
		goto retry_grab;
	}
	
	wait_for_stable_page(page);


	if (ext4_should_dioread_nolock(inode))
		ret = ext4_block_write_begin(page, pos, len, ext4_get_block_unwritten);
	else ret = ext4_block_write_begin(page, pos, len, ext4_get_block);


	if (ext4_should_dioread_nolock(inode))
		ret = __block_write_begin(page, pos, len, ext4_get_block_unwritten);
	else ret = __block_write_begin(page, pos, len, ext4_get_block);

	if (!ret && ext4_should_journal_data(inode)) {
		ret = ext4_walk_page_buffers(handle, page_buffers(page), from, to, NULL, do_journal_get_write_access);

	}

	if (ret) {
		unlock_page(page);
		
		if (pos + len > inode->i_size && ext4_can_truncate(inode))
			ext4_orphan_add(handle, inode);

		ext4_journal_stop(handle);
		if (pos + len > inode->i_size) {
			ext4_truncate_failed_write(inode);
			
			if (inode->i_nlink)
				ext4_orphan_del(NULL, inode);
		}

		if (ret == -ENOSPC && ext4_should_retry_alloc(inode->i_sb, &retries))
			goto retry_journal;
		put_page(page);
		return ret;
	}
	*pagep = page;
	return ret;
}


static int write_end_fn(handle_t *handle, struct buffer_head *bh)
{
	int ret;
	if (!buffer_mapped(bh) || buffer_freed(bh))
		return 0;
	set_buffer_uptodate(bh);
	ret = ext4_handle_dirty_metadata(handle, NULL, bh);
	clear_buffer_meta(bh);
	clear_buffer_prio(bh);
	return ret;
}


static int ext4_write_end(struct file *file, struct address_space *mapping, loff_t pos, unsigned len, unsigned copied, struct page *page, void *fsdata)


{
	handle_t *handle = ext4_journal_current_handle();
	struct inode *inode = mapping->host;
	loff_t old_size = inode->i_size;
	int ret = 0, ret2;
	int i_size_changed = 0;

	trace_ext4_write_end(inode, pos, len, copied);
	if (ext4_has_inline_data(inode)) {
		ret = ext4_write_inline_data_end(inode, pos, len, copied, page);
		if (ret < 0) {
			unlock_page(page);
			put_page(page);
			goto errout;
		}
		copied = ret;
	} else copied = block_write_end(file, mapping, pos, len, copied, page, fsdata);

	
	i_size_changed = ext4_update_inode_size(inode, pos + copied);
	unlock_page(page);
	put_page(page);

	if (old_size < pos)
		pagecache_isize_extended(inode, old_size, pos);
	
	if (i_size_changed)
		ext4_mark_inode_dirty(handle, inode);

	if (pos + len > inode->i_size && ext4_can_truncate(inode))
		
		ext4_orphan_add(handle, inode);
errout:
	ret2 = ext4_journal_stop(handle);
	if (!ret)
		ret = ret2;

	if (pos + len > inode->i_size) {
		ext4_truncate_failed_write(inode);
		
		if (inode->i_nlink)
			ext4_orphan_del(NULL, inode);
	}

	return ret ? ret : copied;
}


static void ext4_journalled_zero_new_buffers(handle_t *handle, struct page *page, unsigned from, unsigned to)

{
	unsigned int block_start = 0, block_end;
	struct buffer_head *head, *bh;

	bh = head = page_buffers(page);
	do {
		block_end = block_start + bh->b_size;
		if (buffer_new(bh)) {
			if (block_end > from && block_start < to) {
				if (!PageUptodate(page)) {
					unsigned start, size;

					start = max(from, block_start);
					size = min(to, block_end) - start;

					zero_user(page, start, size);
					write_end_fn(handle, bh);
				}
				clear_buffer_new(bh);
			}
		}
		block_start = block_end;
		bh = bh->b_this_page;
	} while (bh != head);
}

static int ext4_journalled_write_end(struct file *file, struct address_space *mapping, loff_t pos, unsigned len, unsigned copied, struct page *page, void *fsdata)


{
	handle_t *handle = ext4_journal_current_handle();
	struct inode *inode = mapping->host;
	loff_t old_size = inode->i_size;
	int ret = 0, ret2;
	int partial = 0;
	unsigned from, to;
	int size_changed = 0;

	trace_ext4_journalled_write_end(inode, pos, len, copied);
	from = pos & (PAGE_SIZE - 1);
	to = from + len;

	BUG_ON(!ext4_handle_valid(handle));

	if (ext4_has_inline_data(inode)) {
		ret = ext4_write_inline_data_end(inode, pos, len, copied, page);
		if (ret < 0) {
			unlock_page(page);
			put_page(page);
			goto errout;
		}
		copied = ret;
	} else if (unlikely(copied < len) && !PageUptodate(page)) {
		copied = 0;
		ext4_journalled_zero_new_buffers(handle, page, from, to);
	} else {
		if (unlikely(copied < len))
			ext4_journalled_zero_new_buffers(handle, page, from + copied, to);
		ret = ext4_walk_page_buffers(handle, page_buffers(page), from, from + copied, &partial, write_end_fn);

		if (!partial)
			SetPageUptodate(page);
	}
	size_changed = ext4_update_inode_size(inode, pos + copied);
	ext4_set_inode_state(inode, EXT4_STATE_JDATA);
	EXT4_I(inode)->i_datasync_tid = handle->h_transaction->t_tid;
	unlock_page(page);
	put_page(page);

	if (old_size < pos)
		pagecache_isize_extended(inode, old_size, pos);

	if (size_changed) {
		ret2 = ext4_mark_inode_dirty(handle, inode);
		if (!ret)
			ret = ret2;
	}

	if (pos + len > inode->i_size && ext4_can_truncate(inode))
		
		ext4_orphan_add(handle, inode);

errout:
	ret2 = ext4_journal_stop(handle);
	if (!ret)
		ret = ret2;
	if (pos + len > inode->i_size) {
		ext4_truncate_failed_write(inode);
		
		if (inode->i_nlink)
			ext4_orphan_del(NULL, inode);
	}

	return ret ? ret : copied;
}


static int ext4_da_reserve_space(struct inode *inode)
{
	struct ext4_sb_info *sbi = EXT4_SB(inode->i_sb);
	struct ext4_inode_info *ei = EXT4_I(inode);
	int ret;

	
	ret = dquot_reserve_block(inode, EXT4_C2B(sbi, 1));
	if (ret)
		return ret;

	spin_lock(&ei->i_block_reservation_lock);
	if (ext4_claim_free_clusters(sbi, 1, 0)) {
		spin_unlock(&ei->i_block_reservation_lock);
		dquot_release_reservation_block(inode, EXT4_C2B(sbi, 1));
		return -ENOSPC;
	}
	ei->i_reserved_data_blocks++;
	trace_ext4_da_reserve_space(inode);
	spin_unlock(&ei->i_block_reservation_lock);

	return 0;       
}

static void ext4_da_release_space(struct inode *inode, int to_free)
{
	struct ext4_sb_info *sbi = EXT4_SB(inode->i_sb);
	struct ext4_inode_info *ei = EXT4_I(inode);

	if (!to_free)
		return;		

	spin_lock(&EXT4_I(inode)->i_block_reservation_lock);

	trace_ext4_da_release_space(inode, to_free);
	if (unlikely(to_free > ei->i_reserved_data_blocks)) {
		
		ext4_warning(inode->i_sb, "ext4_da_release_space: " "ino %lu, to_free %d with only %d reserved " "data blocks", inode->i_ino, to_free, ei->i_reserved_data_blocks);


		WARN_ON(1);
		to_free = ei->i_reserved_data_blocks;
	}
	ei->i_reserved_data_blocks -= to_free;

	
	percpu_counter_sub(&sbi->s_dirtyclusters_counter, to_free);

	spin_unlock(&EXT4_I(inode)->i_block_reservation_lock);

	dquot_release_reservation_block(inode, EXT4_C2B(sbi, to_free));
}

static void ext4_da_page_release_reservation(struct page *page, unsigned int offset, unsigned int length)

{
	int to_release = 0, contiguous_blks = 0;
	struct buffer_head *head, *bh;
	unsigned int curr_off = 0;
	struct inode *inode = page->mapping->host;
	struct ext4_sb_info *sbi = EXT4_SB(inode->i_sb);
	unsigned int stop = offset + length;
	int num_clusters;
	ext4_fsblk_t lblk;

	BUG_ON(stop > PAGE_SIZE || stop < length);

	head = page_buffers(page);
	bh = head;
	do {
		unsigned int next_off = curr_off + bh->b_size;

		if (next_off > stop)
			break;

		if ((offset <= curr_off) && (buffer_delay(bh))) {
			to_release++;
			contiguous_blks++;
			clear_buffer_delay(bh);
		} else if (contiguous_blks) {
			lblk = page->index << (PAGE_SHIFT - inode->i_blkbits);
			lblk += (curr_off >> inode->i_blkbits) - contiguous_blks;
			ext4_es_remove_extent(inode, lblk, contiguous_blks);
			contiguous_blks = 0;
		}
		curr_off = next_off;
	} while ((bh = bh->b_this_page) != head);

	if (contiguous_blks) {
		lblk = page->index << (PAGE_SHIFT - inode->i_blkbits);
		lblk += (curr_off >> inode->i_blkbits) - contiguous_blks;
		ext4_es_remove_extent(inode, lblk, contiguous_blks);
	}

	
	num_clusters = EXT4_NUM_B2C(sbi, to_release);
	while (num_clusters > 0) {
		lblk = (page->index << (PAGE_SHIFT - inode->i_blkbits)) + ((num_clusters - 1) << sbi->s_cluster_bits);
		if (sbi->s_cluster_ratio == 1 || !ext4_find_delalloc_cluster(inode, lblk))
			ext4_da_release_space(inode, 1);

		num_clusters--;
	}
}



struct mpage_da_data {
	struct inode *inode;
	struct writeback_control *wbc;

	pgoff_t first_page;	
	pgoff_t next_page;	
	pgoff_t last_page;	
	
	struct ext4_map_blocks map;
	struct ext4_io_submit io_submit;	
	unsigned int do_map:1;
};

static void mpage_release_unused_pages(struct mpage_da_data *mpd, bool invalidate)
{
	int nr_pages, i;
	pgoff_t index, end;
	struct pagevec pvec;
	struct inode *inode = mpd->inode;
	struct address_space *mapping = inode->i_mapping;

	
	if (mpd->first_page >= mpd->next_page)
		return;

	index = mpd->first_page;
	end   = mpd->next_page - 1;
	if (invalidate) {
		ext4_lblk_t start, last;
		start = index << (PAGE_SHIFT - inode->i_blkbits);
		last = end << (PAGE_SHIFT - inode->i_blkbits);
		ext4_es_remove_extent(inode, start, last - start + 1);
	}

	pagevec_init(&pvec);
	while (index <= end) {
		nr_pages = pagevec_lookup_range(&pvec, mapping, &index, end);
		if (nr_pages == 0)
			break;
		for (i = 0; i < nr_pages; i++) {
			struct page *page = pvec.pages[i];

			BUG_ON(!PageLocked(page));
			BUG_ON(PageWriteback(page));
			if (invalidate) {
				if (page_mapped(page))
					clear_page_dirty_for_io(page);
				block_invalidatepage(page, 0, PAGE_SIZE);
				ClearPageUptodate(page);
			}
			unlock_page(page);
		}
		pagevec_release(&pvec);
	}
}

static void ext4_print_free_blocks(struct inode *inode)
{
	struct ext4_sb_info *sbi = EXT4_SB(inode->i_sb);
	struct super_block *sb = inode->i_sb;
	struct ext4_inode_info *ei = EXT4_I(inode);

	ext4_msg(sb, KERN_CRIT, "Total free blocks count %lld", EXT4_C2B(EXT4_SB(inode->i_sb), ext4_count_free_clusters(sb)));

	ext4_msg(sb, KERN_CRIT, "Free/Dirty block details");
	ext4_msg(sb, KERN_CRIT, "free_blocks=%lld", (long long) EXT4_C2B(EXT4_SB(sb), percpu_counter_sum(&sbi->s_freeclusters_counter)));

	ext4_msg(sb, KERN_CRIT, "dirty_blocks=%lld", (long long) EXT4_C2B(EXT4_SB(sb), percpu_counter_sum(&sbi->s_dirtyclusters_counter)));

	ext4_msg(sb, KERN_CRIT, "Block reservation details");
	ext4_msg(sb, KERN_CRIT, "i_reserved_data_blocks=%u", ei->i_reserved_data_blocks);
	return;
}

static int ext4_bh_delay_or_unwritten(handle_t *handle, struct buffer_head *bh)
{
	return (buffer_delay(bh) || buffer_unwritten(bh)) && buffer_dirty(bh);
}


static int ext4_da_map_blocks(struct inode *inode, sector_t iblock, struct ext4_map_blocks *map, struct buffer_head *bh)

{
	struct extent_status es;
	int retval;
	sector_t invalid_block = ~((sector_t) 0xffff);

	struct ext4_map_blocks orig_map;

	memcpy(&orig_map, map, sizeof(*map));


	if (invalid_block < ext4_blocks_count(EXT4_SB(inode->i_sb)->s_es))
		invalid_block = ~0;

	map->m_flags = 0;
	ext_debug("ext4_da_map_blocks(): inode %lu, max_blocks %u," "logical block %lu\n", inode->i_ino, map->m_len, (unsigned long) map->m_lblk);


	
	if (ext4_es_lookup_extent(inode, iblock, &es)) {
		if (ext4_es_is_hole(&es)) {
			retval = 0;
			down_read(&EXT4_I(inode)->i_data_sem);
			goto add_delayed;
		}

		
		if (ext4_es_is_delayed(&es) && !ext4_es_is_unwritten(&es)) {
			map_bh(bh, inode->i_sb, invalid_block);
			set_buffer_new(bh);
			set_buffer_delay(bh);
			return 0;
		}

		map->m_pblk = ext4_es_pblock(&es) + iblock - es.es_lblk;
		retval = es.es_len - (iblock - es.es_lblk);
		if (retval > map->m_len)
			retval = map->m_len;
		map->m_len = retval;
		if (ext4_es_is_written(&es))
			map->m_flags |= EXT4_MAP_MAPPED;
		else if (ext4_es_is_unwritten(&es))
			map->m_flags |= EXT4_MAP_UNWRITTEN;
		else BUG_ON(1);


		ext4_map_blocks_es_recheck(NULL, inode, map, &orig_map, 0);

		return retval;
	}

	
	down_read(&EXT4_I(inode)->i_data_sem);
	if (ext4_has_inline_data(inode))
		retval = 0;
	else if (ext4_test_inode_flag(inode, EXT4_INODE_EXTENTS))
		retval = ext4_ext_map_blocks(NULL, inode, map, 0);
	else retval = ext4_ind_map_blocks(NULL, inode, map, 0);

add_delayed:
	if (retval == 0) {
		int ret;
		
		
		if (EXT4_SB(inode->i_sb)->s_cluster_ratio == 1 || !ext4_find_delalloc_cluster(inode, map->m_lblk)) {
			ret = ext4_da_reserve_space(inode);
			if (ret) {
				
				retval = ret;
				goto out_unlock;
			}
		}

		ret = ext4_es_insert_extent(inode, map->m_lblk, map->m_len, ~0, EXTENT_STATUS_DELAYED);
		if (ret) {
			retval = ret;
			goto out_unlock;
		}

		map_bh(bh, inode->i_sb, invalid_block);
		set_buffer_new(bh);
		set_buffer_delay(bh);
	} else if (retval > 0) {
		int ret;
		unsigned int status;

		if (unlikely(retval != map->m_len)) {
			ext4_warning(inode->i_sb, "ES len assertion failed for inode " "%lu: retval %d != map->m_len %d", inode->i_ino, retval, map->m_len);


			WARN_ON(1);
		}

		status = map->m_flags & EXT4_MAP_UNWRITTEN ? EXTENT_STATUS_UNWRITTEN : EXTENT_STATUS_WRITTEN;
		ret = ext4_es_insert_extent(inode, map->m_lblk, map->m_len, map->m_pblk, status);
		if (ret != 0)
			retval = ret;
	}

out_unlock:
	up_read((&EXT4_I(inode)->i_data_sem));

	return retval;
}


int ext4_da_get_block_prep(struct inode *inode, sector_t iblock, struct buffer_head *bh, int create)
{
	struct ext4_map_blocks map;
	int ret = 0;

	BUG_ON(create == 0);
	BUG_ON(bh->b_size != inode->i_sb->s_blocksize);

	map.m_lblk = iblock;
	map.m_len = 1;

	
	ret = ext4_da_map_blocks(inode, iblock, &map, bh);
	if (ret <= 0)
		return ret;

	map_bh(bh, inode->i_sb, map.m_pblk);
	ext4_update_bh_state(bh, map.m_flags);

	if (buffer_unwritten(bh)) {
		
		set_buffer_new(bh);
		set_buffer_mapped(bh);
	}
	return 0;
}

static int bget_one(handle_t *handle, struct buffer_head *bh)
{
	get_bh(bh);
	return 0;
}

static int bput_one(handle_t *handle, struct buffer_head *bh)
{
	put_bh(bh);
	return 0;
}

static int __ext4_journalled_writepage(struct page *page, unsigned int len)
{
	struct address_space *mapping = page->mapping;
	struct inode *inode = mapping->host;
	struct buffer_head *page_bufs = NULL;
	handle_t *handle = NULL;
	int ret = 0, err = 0;
	int inline_data = ext4_has_inline_data(inode);
	struct buffer_head *inode_bh = NULL;

	ClearPageChecked(page);

	if (inline_data) {
		BUG_ON(page->index != 0);
		BUG_ON(len > ext4_get_max_inline_size(inode));
		inode_bh = ext4_journalled_write_inline_data(inode, len, page);
		if (inode_bh == NULL)
			goto out;
	} else {
		page_bufs = page_buffers(page);
		if (!page_bufs) {
			BUG();
			goto out;
		}
		ext4_walk_page_buffers(handle, page_bufs, 0, len, NULL, bget_one);
	}
	
	get_page(page);
	unlock_page(page);

	handle = ext4_journal_start(inode, EXT4_HT_WRITE_PAGE, ext4_writepage_trans_blocks(inode));
	if (IS_ERR(handle)) {
		ret = PTR_ERR(handle);
		put_page(page);
		goto out_no_pagelock;
	}
	BUG_ON(!ext4_handle_valid(handle));

	lock_page(page);
	put_page(page);
	if (page->mapping != mapping) {
		
		ext4_journal_stop(handle);
		ret = 0;
		goto out;
	}

	if (inline_data) {
		BUFFER_TRACE(inode_bh, "get write access");
		ret = ext4_journal_get_write_access(handle, inode_bh);

		err = ext4_handle_dirty_metadata(handle, inode, inode_bh);

	} else {
		ret = ext4_walk_page_buffers(handle, page_bufs, 0, len, NULL, do_journal_get_write_access);

		err = ext4_walk_page_buffers(handle, page_bufs, 0, len, NULL, write_end_fn);
	}
	if (ret == 0)
		ret = err;
	EXT4_I(inode)->i_datasync_tid = handle->h_transaction->t_tid;
	err = ext4_journal_stop(handle);
	if (!ret)
		ret = err;

	if (!ext4_has_inline_data(inode))
		ext4_walk_page_buffers(NULL, page_bufs, 0, len, NULL, bput_one);
	ext4_set_inode_state(inode, EXT4_STATE_JDATA);
out:
	unlock_page(page);
out_no_pagelock:
	brelse(inode_bh);
	return ret;
}


static int ext4_writepage(struct page *page, struct writeback_control *wbc)
{
	int ret = 0;
	loff_t size;
	unsigned int len;
	struct buffer_head *page_bufs = NULL;
	struct inode *inode = page->mapping->host;
	struct ext4_io_submit io_submit;
	bool keep_towrite = false;

	if (unlikely(ext4_forced_shutdown(EXT4_SB(inode->i_sb)))) {
		ext4_invalidatepage(page, 0, PAGE_SIZE);
		unlock_page(page);
		return -EIO;
	}

	trace_ext4_writepage(page);
	size = i_size_read(inode);
	if (page->index == size >> PAGE_SHIFT)
		len = size & ~PAGE_MASK;
	else len = PAGE_SIZE;

	page_bufs = page_buffers(page);
	
	if (ext4_walk_page_buffers(NULL, page_bufs, 0, len, NULL, ext4_bh_delay_or_unwritten)) {
		redirty_page_for_writepage(wbc, page);
		if ((current->flags & PF_MEMALLOC) || (inode->i_sb->s_blocksize == PAGE_SIZE)) {
			
			WARN_ON_ONCE((current->flags & (PF_MEMALLOC|PF_KSWAPD))
							== PF_MEMALLOC);
			unlock_page(page);
			return 0;
		}
		keep_towrite = true;
	}

	if (PageChecked(page) && ext4_should_journal_data(inode))
		
		return __ext4_journalled_writepage(page, len);

	ext4_io_submit_init(&io_submit, wbc);
	io_submit.io_end = ext4_init_io_end(inode, GFP_NOFS);
	if (!io_submit.io_end) {
		redirty_page_for_writepage(wbc, page);
		unlock_page(page);
		return -ENOMEM;
	}
	ret = ext4_bio_write_page(&io_submit, page, len, wbc, keep_towrite);
	ext4_io_submit(&io_submit);
	
	ext4_put_io_end_defer(io_submit.io_end);
	return ret;
}

static int mpage_submit_page(struct mpage_da_data *mpd, struct page *page)
{
	int len;
	loff_t size;
	int err;

	BUG_ON(page->index != mpd->first_page);
	clear_page_dirty_for_io(page);
	
	size = i_size_read(mpd->inode);
	if (page->index == size >> PAGE_SHIFT)
		len = size & ~PAGE_MASK;
	else len = PAGE_SIZE;
	err = ext4_bio_write_page(&mpd->io_submit, page, len, mpd->wbc, false);
	if (!err)
		mpd->wbc->nr_to_write--;
	mpd->first_page++;

	return err;
}







static bool mpage_add_bh_to_extent(struct mpage_da_data *mpd, ext4_lblk_t lblk, struct buffer_head *bh)
{
	struct ext4_map_blocks *map = &mpd->map;

	
	if (!buffer_dirty(bh) || !buffer_mapped(bh) || (!buffer_delay(bh) && !buffer_unwritten(bh))) {
		
		if (map->m_len == 0)
			return true;
		return false;
	}

	
	if (map->m_len == 0) {
		
		if (!mpd->do_map)
			return false;
		map->m_lblk = lblk;
		map->m_len = 1;
		map->m_flags = bh->b_state & BH_FLAGS;
		return true;
	}

	
	if (map->m_len >= MAX_WRITEPAGES_EXTENT_LEN)
		return false;

	
	if (lblk == map->m_lblk + map->m_len && (bh->b_state & BH_FLAGS) == map->m_flags) {
		map->m_len++;
		return true;
	}
	return false;
}


static int mpage_process_page_bufs(struct mpage_da_data *mpd, struct buffer_head *head, struct buffer_head *bh, ext4_lblk_t lblk)


{
	struct inode *inode = mpd->inode;
	int err;
	ext4_lblk_t blocks = (i_size_read(inode) + i_blocksize(inode) - 1)
							>> inode->i_blkbits;

	do {
		BUG_ON(buffer_locked(bh));

		if (lblk >= blocks || !mpage_add_bh_to_extent(mpd, lblk, bh)) {
			
			if (mpd->map.m_len)
				return 0;
			
			if (!mpd->do_map)
				return 0;
			
			break;
		}
	} while (lblk++, (bh = bh->b_this_page) != head);
	
	if (mpd->map.m_len == 0) {
		err = mpage_submit_page(mpd, head->b_page);
		if (err < 0)
			return err;
	}
	return lblk < blocks;
}


static int mpage_map_and_submit_buffers(struct mpage_da_data *mpd)
{
	struct pagevec pvec;
	int nr_pages, i;
	struct inode *inode = mpd->inode;
	struct buffer_head *head, *bh;
	int bpp_bits = PAGE_SHIFT - inode->i_blkbits;
	pgoff_t start, end;
	ext4_lblk_t lblk;
	sector_t pblock;
	int err;

	start = mpd->map.m_lblk >> bpp_bits;
	end = (mpd->map.m_lblk + mpd->map.m_len - 1) >> bpp_bits;
	lblk = start << bpp_bits;
	pblock = mpd->map.m_pblk;

	pagevec_init(&pvec);
	while (start <= end) {
		nr_pages = pagevec_lookup_range(&pvec, inode->i_mapping, &start, end);
		if (nr_pages == 0)
			break;
		for (i = 0; i < nr_pages; i++) {
			struct page *page = pvec.pages[i];

			bh = head = page_buffers(page);
			do {
				if (lblk < mpd->map.m_lblk)
					continue;
				if (lblk >= mpd->map.m_lblk + mpd->map.m_len) {
					
					mpd->map.m_len = 0;
					mpd->map.m_flags = 0;
					
					err = mpage_process_page_bufs(mpd, head, bh, lblk);
					pagevec_release(&pvec);
					if (err > 0)
						err = 0;
					return err;
				}
				if (buffer_delay(bh)) {
					clear_buffer_delay(bh);
					bh->b_blocknr = pblock++;
				}
				clear_buffer_unwritten(bh);
			} while (lblk++, (bh = bh->b_this_page) != head);

			
			mpd->io_submit.io_end->size += PAGE_SIZE;
			
			err = mpage_submit_page(mpd, page);
			if (err < 0) {
				pagevec_release(&pvec);
				return err;
			}
		}
		pagevec_release(&pvec);
	}
	
	mpd->map.m_len = 0;
	mpd->map.m_flags = 0;
	return 0;
}

static int mpage_map_one_extent(handle_t *handle, struct mpage_da_data *mpd)
{
	struct inode *inode = mpd->inode;
	struct ext4_map_blocks *map = &mpd->map;
	int get_blocks_flags;
	int err, dioread_nolock;

	trace_ext4_da_write_pages_extent(inode, map);
	
	get_blocks_flags = EXT4_GET_BLOCKS_CREATE | EXT4_GET_BLOCKS_METADATA_NOFAIL | EXT4_GET_BLOCKS_IO_SUBMIT;

	dioread_nolock = ext4_should_dioread_nolock(inode);
	if (dioread_nolock)
		get_blocks_flags |= EXT4_GET_BLOCKS_IO_CREATE_EXT;
	if (map->m_flags & (1 << BH_Delay))
		get_blocks_flags |= EXT4_GET_BLOCKS_DELALLOC_RESERVE;

	err = ext4_map_blocks(handle, inode, map, get_blocks_flags);
	if (err < 0)
		return err;
	if (dioread_nolock && (map->m_flags & EXT4_MAP_UNWRITTEN)) {
		if (!mpd->io_submit.io_end->handle && ext4_handle_valid(handle)) {
			mpd->io_submit.io_end->handle = handle->h_rsv_handle;
			handle->h_rsv_handle = NULL;
		}
		ext4_set_io_unwritten_flag(inode, mpd->io_submit.io_end);
	}

	BUG_ON(map->m_len == 0);
	if (map->m_flags & EXT4_MAP_NEW) {
		clean_bdev_aliases(inode->i_sb->s_bdev, map->m_pblk, map->m_len);
	}
	return 0;
}


static int mpage_map_and_submit_extent(handle_t *handle, struct mpage_da_data *mpd, bool *give_up_on_write)

{
	struct inode *inode = mpd->inode;
	struct ext4_map_blocks *map = &mpd->map;
	int err;
	loff_t disksize;
	int progress = 0;

	mpd->io_submit.io_end->offset = ((loff_t)map->m_lblk) << inode->i_blkbits;
	do {
		err = mpage_map_one_extent(handle, mpd);
		if (err < 0) {
			struct super_block *sb = inode->i_sb;

			if (ext4_forced_shutdown(EXT4_SB(sb)) || EXT4_SB(sb)->s_mount_flags & EXT4_MF_FS_ABORTED)
				goto invalidate_dirty_pages;
			
			if ((err == -ENOMEM) || (err == -ENOSPC && ext4_count_free_clusters(sb))) {
				if (progress)
					goto update_disksize;
				return err;
			}
			ext4_msg(sb, KERN_CRIT, "Delayed block allocation failed for " "inode %lu at logical offset %llu with" " max blocks %u with error %d", inode->i_ino, (unsigned long long)map->m_lblk, (unsigned)map->m_len, -err);





			ext4_msg(sb, KERN_CRIT, "This should not happen!! Data will " "be lost\n");

			if (err == -ENOSPC)
				ext4_print_free_blocks(inode);
		invalidate_dirty_pages:
			*give_up_on_write = true;
			return err;
		}
		progress = 1;
		
		err = mpage_map_and_submit_buffers(mpd);
		if (err < 0)
			goto update_disksize;
	} while (map->m_len);

update_disksize:
	
	disksize = ((loff_t)mpd->first_page) << PAGE_SHIFT;
	if (disksize > EXT4_I(inode)->i_disksize) {
		int err2;
		loff_t i_size;

		down_write(&EXT4_I(inode)->i_data_sem);
		i_size = i_size_read(inode);
		if (disksize > i_size)
			disksize = i_size;
		if (disksize > EXT4_I(inode)->i_disksize)
			EXT4_I(inode)->i_disksize = disksize;
		up_write(&EXT4_I(inode)->i_data_sem);
		err2 = ext4_mark_inode_dirty(handle, inode);
		if (err2)
			ext4_error(inode->i_sb, "Failed to mark inode %lu dirty", inode->i_ino);

		if (!err)
			err = err2;
	}
	return err;
}


static int ext4_da_writepages_trans_blocks(struct inode *inode)
{
	int bpp = ext4_journal_blocks_per_page(inode);

	return ext4_meta_trans_blocks(inode, MAX_WRITEPAGES_EXTENT_LEN + bpp - 1, bpp);
}


static int mpage_prepare_extent_to_map(struct mpage_da_data *mpd)
{
	struct address_space *mapping = mpd->inode->i_mapping;
	struct pagevec pvec;
	unsigned int nr_pages;
	long left = mpd->wbc->nr_to_write;
	pgoff_t index = mpd->first_page;
	pgoff_t end = mpd->last_page;
	int tag;
	int i, err = 0;
	int blkbits = mpd->inode->i_blkbits;
	ext4_lblk_t lblk;
	struct buffer_head *head;

	if (mpd->wbc->sync_mode == WB_SYNC_ALL || mpd->wbc->tagged_writepages)
		tag = PAGECACHE_TAG_TOWRITE;
	else tag = PAGECACHE_TAG_DIRTY;

	pagevec_init(&pvec);
	mpd->map.m_len = 0;
	mpd->next_page = index;
	while (index <= end) {
		nr_pages = pagevec_lookup_range_tag(&pvec, mapping, &index, end, tag);
		if (nr_pages == 0)
			goto out;

		for (i = 0; i < nr_pages; i++) {
			struct page *page = pvec.pages[i];

			
			if (mpd->wbc->sync_mode == WB_SYNC_NONE && left <= 0)
				goto out;

			
			if (mpd->map.m_len > 0 && mpd->next_page != page->index)
				goto out;

			lock_page(page);
			
			if (!PageDirty(page) || (PageWriteback(page) && (mpd->wbc->sync_mode == WB_SYNC_NONE)) || unlikely(page->mapping != mapping)) {


				unlock_page(page);
				continue;
			}

			wait_on_page_writeback(page);
			BUG_ON(PageWriteback(page));

			if (mpd->map.m_len == 0)
				mpd->first_page = page->index;
			mpd->next_page = page->index + 1;
			
			lblk = ((ext4_lblk_t)page->index) << (PAGE_SHIFT - blkbits);
			head = page_buffers(page);
			err = mpage_process_page_bufs(mpd, head, head, lblk);
			if (err <= 0)
				goto out;
			err = 0;
			left--;
		}
		pagevec_release(&pvec);
		cond_resched();
	}
	return 0;
out:
	pagevec_release(&pvec);
	return err;
}

static int ext4_writepages(struct address_space *mapping, struct writeback_control *wbc)
{
	pgoff_t	writeback_index = 0;
	long nr_to_write = wbc->nr_to_write;
	int range_whole = 0;
	int cycled = 1;
	handle_t *handle = NULL;
	struct mpage_da_data mpd;
	struct inode *inode = mapping->host;
	int needed_blocks, rsv_blocks = 0, ret = 0;
	struct ext4_sb_info *sbi = EXT4_SB(mapping->host->i_sb);
	bool done;
	struct blk_plug plug;
	bool give_up_on_write = false;

	if (unlikely(ext4_forced_shutdown(EXT4_SB(inode->i_sb))))
		return -EIO;

	percpu_down_read(&sbi->s_journal_flag_rwsem);
	trace_ext4_writepages(inode, wbc);

	
	if (!mapping->nrpages || !mapping_tagged(mapping, PAGECACHE_TAG_DIRTY))
		goto out_writepages;

	if (ext4_should_journal_data(inode)) {
		ret = generic_writepages(mapping, wbc);
		goto out_writepages;
	}

	
	if (unlikely(ext4_forced_shutdown(EXT4_SB(mapping->host->i_sb)) || sbi->s_mount_flags & EXT4_MF_FS_ABORTED)) {
		ret = -EROFS;
		goto out_writepages;
	}

	if (ext4_should_dioread_nolock(inode)) {
		
		rsv_blocks = 1 + (PAGE_SIZE >> inode->i_blkbits);
	}

	
	if (ext4_has_inline_data(inode)) {
		
		handle = ext4_journal_start(inode, EXT4_HT_INODE, 1);
		if (IS_ERR(handle)) {
			ret = PTR_ERR(handle);
			goto out_writepages;
		}
		BUG_ON(ext4_test_inode_state(inode, EXT4_STATE_MAY_INLINE_DATA));
		ext4_destroy_inline_data(handle, inode);
		ext4_journal_stop(handle);
	}

	if (wbc->range_start == 0 && wbc->range_end == LLONG_MAX)
		range_whole = 1;

	if (wbc->range_cyclic) {
		writeback_index = mapping->writeback_index;
		if (writeback_index)
			cycled = 0;
		mpd.first_page = writeback_index;
		mpd.last_page = -1;
	} else {
		mpd.first_page = wbc->range_start >> PAGE_SHIFT;
		mpd.last_page = wbc->range_end >> PAGE_SHIFT;
	}

	mpd.inode = inode;
	mpd.wbc = wbc;
	ext4_io_submit_init(&mpd.io_submit, wbc);
retry:
	if (wbc->sync_mode == WB_SYNC_ALL || wbc->tagged_writepages)
		tag_pages_for_writeback(mapping, mpd.first_page, mpd.last_page);
	done = false;
	blk_start_plug(&plug);

	
	mpd.do_map = 0;
	mpd.io_submit.io_end = ext4_init_io_end(inode, GFP_KERNEL);
	if (!mpd.io_submit.io_end) {
		ret = -ENOMEM;
		goto unplug;
	}
	ret = mpage_prepare_extent_to_map(&mpd);
	
	ext4_io_submit(&mpd.io_submit);
	ext4_put_io_end_defer(mpd.io_submit.io_end);
	mpd.io_submit.io_end = NULL;
	
	mpage_release_unused_pages(&mpd, false);
	if (ret < 0)
		goto unplug;

	while (!done && mpd.first_page <= mpd.last_page) {
		
		mpd.io_submit.io_end = ext4_init_io_end(inode, GFP_KERNEL);
		if (!mpd.io_submit.io_end) {
			ret = -ENOMEM;
			break;
		}

		
		BUG_ON(ext4_should_journal_data(inode));
		needed_blocks = ext4_da_writepages_trans_blocks(inode);

		
		handle = ext4_journal_start_with_reserve(inode, EXT4_HT_WRITE_PAGE, needed_blocks, rsv_blocks);
		if (IS_ERR(handle)) {
			ret = PTR_ERR(handle);
			ext4_msg(inode->i_sb, KERN_CRIT, "%s: jbd2_start: " "%ld pages, ino %lu; err %d", __func__, wbc->nr_to_write, inode->i_ino, ret);

			
			ext4_put_io_end(mpd.io_submit.io_end);
			mpd.io_submit.io_end = NULL;
			break;
		}
		mpd.do_map = 1;

		trace_ext4_da_write_pages(inode, mpd.first_page, mpd.wbc);
		ret = mpage_prepare_extent_to_map(&mpd);
		if (!ret) {
			if (mpd.map.m_len)
				ret = mpage_map_and_submit_extent(handle, &mpd, &give_up_on_write);
			else {
				
				done = true;
			}
		}
		
		if (!ext4_handle_valid(handle) || handle->h_sync == 0) {
			ext4_journal_stop(handle);
			handle = NULL;
			mpd.do_map = 0;
		}
		
		ext4_io_submit(&mpd.io_submit);
		
		mpage_release_unused_pages(&mpd, give_up_on_write);
		
		if (handle) {
			ext4_put_io_end_defer(mpd.io_submit.io_end);
			ext4_journal_stop(handle);
		} else ext4_put_io_end(mpd.io_submit.io_end);
		mpd.io_submit.io_end = NULL;

		if (ret == -ENOSPC && sbi->s_journal) {
			
			jbd2_journal_force_commit_nested(sbi->s_journal);
			ret = 0;
			continue;
		}
		
		if (ret)
			break;
	}
unplug:
	blk_finish_plug(&plug);
	if (!ret && !cycled && wbc->nr_to_write > 0) {
		cycled = 1;
		mpd.last_page = writeback_index - 1;
		mpd.first_page = 0;
		goto retry;
	}

	
	if (wbc->range_cyclic || (range_whole && wbc->nr_to_write > 0))
		
		mapping->writeback_index = mpd.first_page;

out_writepages:
	trace_ext4_writepages_result(inode, wbc, ret, nr_to_write - wbc->nr_to_write);
	percpu_up_read(&sbi->s_journal_flag_rwsem);
	return ret;
}

static int ext4_dax_writepages(struct address_space *mapping, struct writeback_control *wbc)
{
	int ret;
	long nr_to_write = wbc->nr_to_write;
	struct inode *inode = mapping->host;
	struct ext4_sb_info *sbi = EXT4_SB(mapping->host->i_sb);

	if (unlikely(ext4_forced_shutdown(EXT4_SB(inode->i_sb))))
		return -EIO;

	percpu_down_read(&sbi->s_journal_flag_rwsem);
	trace_ext4_writepages(inode, wbc);

	ret = dax_writeback_mapping_range(mapping, inode->i_sb->s_bdev, wbc);
	trace_ext4_writepages_result(inode, wbc, ret, nr_to_write - wbc->nr_to_write);
	percpu_up_read(&sbi->s_journal_flag_rwsem);
	return ret;
}

static int ext4_nonda_switch(struct super_block *sb)
{
	s64 free_clusters, dirty_clusters;
	struct ext4_sb_info *sbi = EXT4_SB(sb);

	
	free_clusters = percpu_counter_read_positive(&sbi->s_freeclusters_counter);
	dirty_clusters = percpu_counter_read_positive(&sbi->s_dirtyclusters_counter);
	
	if (dirty_clusters && (free_clusters < 2 * dirty_clusters))
		try_to_writeback_inodes_sb(sb, WB_REASON_FS_FREE_SPACE);

	if (2 * free_clusters < 3 * dirty_clusters || free_clusters < (dirty_clusters + EXT4_FREECLUSTERS_WATERMARK)) {
		
		return 1;
	}
	return 0;
}


static int ext4_da_write_credits(struct inode *inode, loff_t pos, unsigned len)
{
	if (likely(ext4_has_feature_large_file(inode->i_sb)))
		return 1;

	if (pos + len <= 0x7fffffffULL)
		return 1;

	
	return 2;
}

static int ext4_da_write_begin(struct file *file, struct address_space *mapping, loff_t pos, unsigned len, unsigned flags, struct page **pagep, void **fsdata)

{
	int ret, retries = 0;
	struct page *page;
	pgoff_t index;
	struct inode *inode = mapping->host;
	handle_t *handle;

	if (unlikely(ext4_forced_shutdown(EXT4_SB(inode->i_sb))))
		return -EIO;

	index = pos >> PAGE_SHIFT;

	if (ext4_nonda_switch(inode->i_sb) || S_ISLNK(inode->i_mode)) {
		*fsdata = (void *)FALL_BACK_TO_NONDELALLOC;
		return ext4_write_begin(file, mapping, pos, len, flags, pagep, fsdata);
	}
	*fsdata = (void *)0;
	trace_ext4_da_write_begin(inode, pos, len, flags);

	if (ext4_test_inode_state(inode, EXT4_STATE_MAY_INLINE_DATA)) {
		ret = ext4_da_write_inline_data_begin(mapping, inode, pos, len, flags, pagep, fsdata);

		if (ret < 0)
			return ret;
		if (ret == 1)
			return 0;
	}

	
retry_grab:
	page = grab_cache_page_write_begin(mapping, index, flags);
	if (!page)
		return -ENOMEM;
	unlock_page(page);

	
retry_journal:
	handle = ext4_journal_start(inode, EXT4_HT_WRITE_PAGE, ext4_da_write_credits(inode, pos, len));
	if (IS_ERR(handle)) {
		put_page(page);
		return PTR_ERR(handle);
	}

	lock_page(page);
	if (page->mapping != mapping) {
		
		unlock_page(page);
		put_page(page);
		ext4_journal_stop(handle);
		goto retry_grab;
	}
	
	wait_for_stable_page(page);


	ret = ext4_block_write_begin(page, pos, len, ext4_da_get_block_prep);

	ret = __block_write_begin(page, pos, len, ext4_da_get_block_prep);

	if (ret < 0) {
		unlock_page(page);
		ext4_journal_stop(handle);
		
		if (pos + len > inode->i_size)
			ext4_truncate_failed_write(inode);

		if (ret == -ENOSPC && ext4_should_retry_alloc(inode->i_sb, &retries))
			goto retry_journal;

		put_page(page);
		return ret;
	}

	*pagep = page;
	return ret;
}


static int ext4_da_should_update_i_disksize(struct page *page, unsigned long offset)
{
	struct buffer_head *bh;
	struct inode *inode = page->mapping->host;
	unsigned int idx;
	int i;

	bh = page_buffers(page);
	idx = offset >> inode->i_blkbits;

	for (i = 0; i < idx; i++)
		bh = bh->b_this_page;

	if (!buffer_mapped(bh) || (buffer_delay(bh)) || buffer_unwritten(bh))
		return 0;
	return 1;
}

static int ext4_da_write_end(struct file *file, struct address_space *mapping, loff_t pos, unsigned len, unsigned copied, struct page *page, void *fsdata)


{
	struct inode *inode = mapping->host;
	int ret = 0, ret2;
	handle_t *handle = ext4_journal_current_handle();
	loff_t new_i_size;
	unsigned long start, end;
	int write_mode = (int)(unsigned long)fsdata;

	if (write_mode == FALL_BACK_TO_NONDELALLOC)
		return ext4_write_end(file, mapping, pos, len, copied, page, fsdata);

	trace_ext4_da_write_end(inode, pos, len, copied);
	start = pos & (PAGE_SIZE - 1);
	end = start + copied - 1;

	
	new_i_size = pos + copied;
	if (copied && new_i_size > EXT4_I(inode)->i_disksize) {
		if (ext4_has_inline_data(inode) || ext4_da_should_update_i_disksize(page, end)) {
			ext4_update_i_disksize(inode, new_i_size);
			
			ext4_mark_inode_dirty(handle, inode);
		}
	}

	if (write_mode != CONVERT_INLINE_DATA && ext4_test_inode_state(inode, EXT4_STATE_MAY_INLINE_DATA) && ext4_has_inline_data(inode))

		ret2 = ext4_da_write_inline_data_end(inode, pos, len, copied, page);
	else ret2 = generic_write_end(file, mapping, pos, len, copied, page, fsdata);


	copied = ret2;
	if (ret2 < 0)
		ret = ret2;
	ret2 = ext4_journal_stop(handle);
	if (!ret)
		ret = ret2;

	return ret ? ret : copied;
}

static void ext4_da_invalidatepage(struct page *page, unsigned int offset, unsigned int length)
{
	
	BUG_ON(!PageLocked(page));
	if (!page_has_buffers(page))
		goto out;

	ext4_da_page_release_reservation(page, offset, length);

out:
	ext4_invalidatepage(page, offset, length);

	return;
}


int ext4_alloc_da_blocks(struct inode *inode)
{
	trace_ext4_alloc_da_blocks(inode);

	if (!EXT4_I(inode)->i_reserved_data_blocks)
		return 0;

	
	return filemap_flush(inode->i_mapping);
}


static sector_t ext4_bmap(struct address_space *mapping, sector_t block)
{
	struct inode *inode = mapping->host;
	journal_t *journal;
	int err;

	
	if (ext4_has_inline_data(inode))
		return 0;

	if (mapping_tagged(mapping, PAGECACHE_TAG_DIRTY) && test_opt(inode->i_sb, DELALLOC)) {
		
		filemap_write_and_wait(mapping);
	}

	if (EXT4_JOURNAL(inode) && ext4_test_inode_state(inode, EXT4_STATE_JDATA)) {
		

		ext4_clear_inode_state(inode, EXT4_STATE_JDATA);
		journal = EXT4_JOURNAL(inode);
		jbd2_journal_lock_updates(journal);
		err = jbd2_journal_flush(journal);
		jbd2_journal_unlock_updates(journal);

		if (err)
			return 0;
	}

	return generic_block_bmap(mapping, block, ext4_get_block);
}

static int ext4_readpage(struct file *file, struct page *page)
{
	int ret = -EAGAIN;
	struct inode *inode = page->mapping->host;

	trace_ext4_readpage(page);

	if (ext4_has_inline_data(inode))
		ret = ext4_readpage_inline(inode, page);

	if (ret == -EAGAIN)
		return ext4_mpage_readpages(page->mapping, NULL, page, 1);

	return ret;
}

static int ext4_readpages(struct file *file, struct address_space *mapping, struct list_head *pages, unsigned nr_pages)

{
	struct inode *inode = mapping->host;

	
	if (ext4_has_inline_data(inode))
		return 0;

	return ext4_mpage_readpages(mapping, pages, NULL, nr_pages);
}

static void ext4_invalidatepage(struct page *page, unsigned int offset, unsigned int length)
{
	trace_ext4_invalidatepage(page, offset, length);

	
	WARN_ON(page_has_buffers(page) && buffer_jbd(page_buffers(page)));

	block_invalidatepage(page, offset, length);
}

static int __ext4_journalled_invalidatepage(struct page *page, unsigned int offset, unsigned int length)

{
	journal_t *journal = EXT4_JOURNAL(page->mapping->host);

	trace_ext4_journalled_invalidatepage(page, offset, length);

	
	if (offset == 0 && length == PAGE_SIZE)
		ClearPageChecked(page);

	return jbd2_journal_invalidatepage(journal, page, offset, length);
}


static void ext4_journalled_invalidatepage(struct page *page, unsigned int offset, unsigned int length)

{
	WARN_ON(__ext4_journalled_invalidatepage(page, offset, length) < 0);
}

static int ext4_releasepage(struct page *page, gfp_t wait)
{
	journal_t *journal = EXT4_JOURNAL(page->mapping->host);

	trace_ext4_releasepage(page);

	
	if (PageChecked(page))
		return 0;
	if (journal)
		return jbd2_journal_try_to_free_buffers(journal, page, wait);
	else return try_to_free_buffers(page);
}

static bool ext4_inode_datasync_dirty(struct inode *inode)
{
	journal_t *journal = EXT4_SB(inode->i_sb)->s_journal;

	if (journal)
		return !jbd2_transaction_committed(journal, EXT4_I(inode)->i_datasync_tid);
	
	if (!list_empty(&inode->i_mapping->private_list))
		return true;
	return inode->i_state & I_DIRTY_DATASYNC;
}

static int ext4_iomap_begin(struct inode *inode, loff_t offset, loff_t length, unsigned flags, struct iomap *iomap)
{
	struct ext4_sb_info *sbi = EXT4_SB(inode->i_sb);
	unsigned int blkbits = inode->i_blkbits;
	unsigned long first_block = offset >> blkbits;
	unsigned long last_block = (offset + length - 1) >> blkbits;
	struct ext4_map_blocks map;
	bool delalloc = false;
	int ret;


	if (flags & IOMAP_REPORT) {
		if (ext4_has_inline_data(inode)) {
			ret = ext4_inline_data_iomap(inode, iomap);
			if (ret != -EAGAIN) {
				if (ret == 0 && offset >= iomap->length)
					ret = -ENOENT;
				return ret;
			}
		}
	} else {
		if (WARN_ON_ONCE(ext4_has_inline_data(inode)))
			return -ERANGE;
	}

	map.m_lblk = first_block;
	map.m_len = last_block - first_block + 1;

	if (flags & IOMAP_REPORT) {
		ret = ext4_map_blocks(NULL, inode, &map, 0);
		if (ret < 0)
			return ret;

		if (ret == 0) {
			ext4_lblk_t end = map.m_lblk + map.m_len - 1;
			struct extent_status es;

			ext4_es_find_delayed_extent_range(inode, map.m_lblk, end, &es);

			if (!es.es_len || es.es_lblk > end) {
				
			} else if (es.es_lblk > map.m_lblk) {
				
				map.m_len = es.es_lblk - map.m_lblk;
			} else {
				ext4_lblk_t offs = 0;

				if (es.es_lblk < map.m_lblk)
					offs = map.m_lblk - es.es_lblk;
				map.m_lblk = es.es_lblk + offs;
				map.m_len = es.es_len - offs;
				delalloc = true;
			}
		}
	} else if (flags & IOMAP_WRITE) {
		int dio_credits;
		handle_t *handle;
		int retries = 0;

		
		if (map.m_len > DIO_MAX_BLOCKS)
			map.m_len = DIO_MAX_BLOCKS;
		dio_credits = ext4_chunk_trans_blocks(inode, map.m_len);
retry:
		
		handle = ext4_journal_start(inode, EXT4_HT_MAP_BLOCKS, dio_credits);
		if (IS_ERR(handle))
			return PTR_ERR(handle);

		ret = ext4_map_blocks(handle, inode, &map, EXT4_GET_BLOCKS_CREATE_ZERO);
		if (ret < 0) {
			ext4_journal_stop(handle);
			if (ret == -ENOSPC && ext4_should_retry_alloc(inode->i_sb, &retries))
				goto retry;
			return ret;
		}

		
		if (!(flags & IOMAP_FAULT) && first_block + map.m_len > (i_size_read(inode) + (1 << blkbits) - 1) >> blkbits) {
			int err;

			err = ext4_orphan_add(handle, inode);
			if (err < 0) {
				ext4_journal_stop(handle);
				return err;
			}
		}
		ext4_journal_stop(handle);
	} else {
		ret = ext4_map_blocks(NULL, inode, &map, 0);
		if (ret < 0)
			return ret;
	}

	iomap->flags = 0;
	if (ext4_inode_datasync_dirty(inode))
		iomap->flags |= IOMAP_F_DIRTY;
	iomap->bdev = inode->i_sb->s_bdev;
	iomap->dax_dev = sbi->s_daxdev;
	iomap->offset = (u64)first_block << blkbits;
	iomap->length = (u64)map.m_len << blkbits;

	if (ret == 0) {
		iomap->type = delalloc ? IOMAP_DELALLOC : IOMAP_HOLE;
		iomap->addr = IOMAP_NULL_ADDR;
	} else {
		if (map.m_flags & EXT4_MAP_MAPPED) {
			iomap->type = IOMAP_MAPPED;
		} else if (map.m_flags & EXT4_MAP_UNWRITTEN) {
			iomap->type = IOMAP_UNWRITTEN;
		} else {
			WARN_ON_ONCE(1);
			return -EIO;
		}
		iomap->addr = (u64)map.m_pblk << blkbits;
	}

	if (map.m_flags & EXT4_MAP_NEW)
		iomap->flags |= IOMAP_F_NEW;

	return 0;
}

static int ext4_iomap_end(struct inode *inode, loff_t offset, loff_t length, ssize_t written, unsigned flags, struct iomap *iomap)
{
	int ret = 0;
	handle_t *handle;
	int blkbits = inode->i_blkbits;
	bool truncate = false;

	if (!(flags & IOMAP_WRITE) || (flags & IOMAP_FAULT))
		return 0;

	handle = ext4_journal_start(inode, EXT4_HT_INODE, 2);
	if (IS_ERR(handle)) {
		ret = PTR_ERR(handle);
		goto orphan_del;
	}
	if (ext4_update_inode_size(inode, offset + written))
		ext4_mark_inode_dirty(handle, inode);
	
	if (iomap->offset + iomap->length >  ALIGN(inode->i_size, 1 << blkbits)) {
		ext4_lblk_t written_blk, end_blk;

		written_blk = (offset + written) >> blkbits;
		end_blk = (offset + length) >> blkbits;
		if (written_blk < end_blk && ext4_can_truncate(inode))
			truncate = true;
	}
	
	if (!truncate && inode->i_nlink && !list_empty(&EXT4_I(inode)->i_orphan))
		ext4_orphan_del(handle, inode);
	ext4_journal_stop(handle);
	if (truncate) {
		ext4_truncate_failed_write(inode);
orphan_del:
		
		if (inode->i_nlink)
			ext4_orphan_del(NULL, inode);
	}
	return ret;
}

const struct iomap_ops ext4_iomap_ops = {
	.iomap_begin		= ext4_iomap_begin, .iomap_end		= ext4_iomap_end, };


static int ext4_end_io_dio(struct kiocb *iocb, loff_t offset, ssize_t size, void *private)
{
        ext4_io_end_t *io_end = private;

	
	if (!io_end)
		return 0;

	ext_debug("ext4_end_io_dio(): io_end 0x%p " "for inode %lu, iocb 0x%p, offset %llu, size %zd\n", io_end, io_end->inode->i_ino, iocb, offset, size);


	
	if (size <= 0) {
		ext4_clear_io_unwritten_flag(io_end);
		size = 0;
	}
	io_end->offset = offset;
	io_end->size = size;
	ext4_put_io_end(io_end);

	return 0;
}


static ssize_t ext4_direct_IO_write(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	struct ext4_inode_info *ei = EXT4_I(inode);
	ssize_t ret;
	loff_t offset = iocb->ki_pos;
	size_t count = iov_iter_count(iter);
	int overwrite = 0;
	get_block_t *get_block_func = NULL;
	int dio_flags = 0;
	loff_t final_size = offset + count;
	int orphan = 0;
	handle_t *handle;

	if (final_size > inode->i_size || final_size > ei->i_disksize) {
		
		handle = ext4_journal_start(inode, EXT4_HT_INODE, 2);
		if (IS_ERR(handle)) {
			ret = PTR_ERR(handle);
			goto out;
		}
		ret = ext4_orphan_add(handle, inode);
		if (ret) {
			ext4_journal_stop(handle);
			goto out;
		}
		orphan = 1;
		ext4_update_i_disksize(inode, inode->i_size);
		ext4_journal_stop(handle);
	}

	BUG_ON(iocb->private == NULL);

	
	inode_dio_begin(inode);

	
	overwrite = *((int *)iocb->private);

	if (overwrite)
		inode_unlock(inode);

	
	iocb->private = NULL;
	if (overwrite)
		get_block_func = ext4_dio_get_block_overwrite;
	else if (!ext4_test_inode_flag(inode, EXT4_INODE_EXTENTS) || round_down(offset, i_blocksize(inode)) >= inode->i_size) {
		get_block_func = ext4_dio_get_block;
		dio_flags = DIO_LOCKING | DIO_SKIP_HOLES;
	} else if (is_sync_kiocb(iocb)) {
		get_block_func = ext4_dio_get_block_unwritten_sync;
		dio_flags = DIO_LOCKING;
	} else {
		get_block_func = ext4_dio_get_block_unwritten_async;
		dio_flags = DIO_LOCKING;
	}
	ret = __blockdev_direct_IO(iocb, inode, inode->i_sb->s_bdev, iter, get_block_func, ext4_end_io_dio, NULL, dio_flags);


	if (ret > 0 && !overwrite && ext4_test_inode_state(inode, EXT4_STATE_DIO_UNWRITTEN)) {
		int err;
		
		err = ext4_convert_unwritten_extents(NULL, inode, offset, ret);
		if (err < 0)
			ret = err;
		ext4_clear_inode_state(inode, EXT4_STATE_DIO_UNWRITTEN);
	}

	inode_dio_end(inode);
	
	if (overwrite)
		inode_lock(inode);

	if (ret < 0 && final_size > inode->i_size)
		ext4_truncate_failed_write(inode);

	
	if (orphan) {
		int err;

		
		handle = ext4_journal_start(inode, EXT4_HT_INODE, 2);
		if (IS_ERR(handle)) {
			
			if (!ret)
				ret = PTR_ERR(handle);
			if (inode->i_nlink)
				ext4_orphan_del(NULL, inode);

			goto out;
		}
		if (inode->i_nlink)
			ext4_orphan_del(handle, inode);
		if (ret > 0) {
			loff_t end = offset + ret;
			if (end > inode->i_size || end > ei->i_disksize) {
				ext4_update_i_disksize(inode, end);
				if (end > inode->i_size)
					i_size_write(inode, end);
				
				ext4_mark_inode_dirty(handle, inode);
			}
		}
		err = ext4_journal_stop(handle);
		if (ret == 0)
			ret = err;
	}
out:
	return ret;
}

static ssize_t ext4_direct_IO_read(struct kiocb *iocb, struct iov_iter *iter)
{
	struct address_space *mapping = iocb->ki_filp->f_mapping;
	struct inode *inode = mapping->host;
	size_t count = iov_iter_count(iter);
	ssize_t ret;

	
	inode_lock_shared(inode);
	ret = filemap_write_and_wait_range(mapping, iocb->ki_pos, iocb->ki_pos + count - 1);
	if (ret)
		goto out_unlock;
	ret = __blockdev_direct_IO(iocb, inode, inode->i_sb->s_bdev, iter, ext4_dio_get_block, NULL, NULL, 0);
out_unlock:
	inode_unlock_shared(inode);
	return ret;
}

static ssize_t ext4_direct_IO(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	size_t count = iov_iter_count(iter);
	loff_t offset = iocb->ki_pos;
	ssize_t ret;


	if (ext4_encrypted_inode(inode) && S_ISREG(inode->i_mode))
		return 0;


	
	if (ext4_should_journal_data(inode))
		return 0;

	
	if (ext4_has_inline_data(inode))
		return 0;

	trace_ext4_direct_IO_enter(inode, offset, count, iov_iter_rw(iter));
	if (iov_iter_rw(iter) == READ)
		ret = ext4_direct_IO_read(iocb, iter);
	else ret = ext4_direct_IO_write(iocb, iter);
	trace_ext4_direct_IO_exit(inode, offset, count, iov_iter_rw(iter), ret);
	return ret;
}


static int ext4_journalled_set_page_dirty(struct page *page)
{
	SetPageChecked(page);
	return __set_page_dirty_nobuffers(page);
}

static int ext4_set_page_dirty(struct page *page)
{
	WARN_ON_ONCE(!PageLocked(page) && !PageDirty(page));
	WARN_ON_ONCE(!page_has_buffers(page));
	return __set_page_dirty_buffers(page);
}

static const struct address_space_operations ext4_aops = {
	.readpage		= ext4_readpage, .readpages		= ext4_readpages, .writepage		= ext4_writepage, .writepages		= ext4_writepages, .write_begin		= ext4_write_begin, .write_end		= ext4_write_end, .set_page_dirty		= ext4_set_page_dirty, .bmap			= ext4_bmap, .invalidatepage		= ext4_invalidatepage, .releasepage		= ext4_releasepage, .direct_IO		= ext4_direct_IO, .migratepage		= buffer_migrate_page, .is_partially_uptodate  = block_is_partially_uptodate, .error_remove_page	= generic_error_remove_page, };














static const struct address_space_operations ext4_journalled_aops = {
	.readpage		= ext4_readpage, .readpages		= ext4_readpages, .writepage		= ext4_writepage, .writepages		= ext4_writepages, .write_begin		= ext4_write_begin, .write_end		= ext4_journalled_write_end, .set_page_dirty		= ext4_journalled_set_page_dirty, .bmap			= ext4_bmap, .invalidatepage		= ext4_journalled_invalidatepage, .releasepage		= ext4_releasepage, .direct_IO		= ext4_direct_IO, .is_partially_uptodate  = block_is_partially_uptodate, .error_remove_page	= generic_error_remove_page, };













static const struct address_space_operations ext4_da_aops = {
	.readpage		= ext4_readpage, .readpages		= ext4_readpages, .writepage		= ext4_writepage, .writepages		= ext4_writepages, .write_begin		= ext4_da_write_begin, .write_end		= ext4_da_write_end, .set_page_dirty		= ext4_set_page_dirty, .bmap			= ext4_bmap, .invalidatepage		= ext4_da_invalidatepage, .releasepage		= ext4_releasepage, .direct_IO		= ext4_direct_IO, .migratepage		= buffer_migrate_page, .is_partially_uptodate  = block_is_partially_uptodate, .error_remove_page	= generic_error_remove_page, };














static const struct address_space_operations ext4_dax_aops = {
	.writepages		= ext4_dax_writepages, .direct_IO		= noop_direct_IO, .set_page_dirty		= noop_set_page_dirty, .invalidatepage		= noop_invalidatepage, };




void ext4_set_aops(struct inode *inode)
{
	switch (ext4_inode_journal_mode(inode)) {
	case EXT4_INODE_ORDERED_DATA_MODE:
	case EXT4_INODE_WRITEBACK_DATA_MODE:
		break;
	case EXT4_INODE_JOURNAL_DATA_MODE:
		inode->i_mapping->a_ops = &ext4_journalled_aops;
		return;
	default:
		BUG();
	}
	if (IS_DAX(inode))
		inode->i_mapping->a_ops = &ext4_dax_aops;
	else if (test_opt(inode->i_sb, DELALLOC))
		inode->i_mapping->a_ops = &ext4_da_aops;
	else inode->i_mapping->a_ops = &ext4_aops;
}

static int __ext4_block_zero_page_range(handle_t *handle, struct address_space *mapping, loff_t from, loff_t length)
{
	ext4_fsblk_t index = from >> PAGE_SHIFT;
	unsigned offset = from & (PAGE_SIZE-1);
	unsigned blocksize, pos;
	ext4_lblk_t iblock;
	struct inode *inode = mapping->host;
	struct buffer_head *bh;
	struct page *page;
	int err = 0;

	page = find_or_create_page(mapping, from >> PAGE_SHIFT, mapping_gfp_constraint(mapping, ~__GFP_FS));
	if (!page)
		return -ENOMEM;

	blocksize = inode->i_sb->s_blocksize;

	iblock = index << (PAGE_SHIFT - inode->i_sb->s_blocksize_bits);

	if (!page_has_buffers(page))
		create_empty_buffers(page, blocksize, 0);

	
	bh = page_buffers(page);
	pos = blocksize;
	while (offset >= pos) {
		bh = bh->b_this_page;
		iblock++;
		pos += blocksize;
	}
	if (buffer_freed(bh)) {
		BUFFER_TRACE(bh, "freed: skip");
		goto unlock;
	}
	if (!buffer_mapped(bh)) {
		BUFFER_TRACE(bh, "unmapped");
		ext4_get_block(inode, iblock, bh, 0);
		
		if (!buffer_mapped(bh)) {
			BUFFER_TRACE(bh, "still unmapped");
			goto unlock;
		}
	}

	
	if (PageUptodate(page))
		set_buffer_uptodate(bh);

	if (!buffer_uptodate(bh)) {
		err = -EIO;
		ll_rw_block(REQ_OP_READ, 0, 1, &bh);
		wait_on_buffer(bh);
		
		if (!buffer_uptodate(bh))
			goto unlock;
		if (S_ISREG(inode->i_mode) && ext4_encrypted_inode(inode)) {
			
			BUG_ON(!fscrypt_has_encryption_key(inode));
			BUG_ON(blocksize != PAGE_SIZE);
			WARN_ON_ONCE(fscrypt_decrypt_page(page->mapping->host, page, PAGE_SIZE, 0, page->index));
		}
	}
	if (ext4_should_journal_data(inode)) {
		BUFFER_TRACE(bh, "get write access");
		err = ext4_journal_get_write_access(handle, bh);
		if (err)
			goto unlock;
	}
	zero_user(page, offset, length);
	BUFFER_TRACE(bh, "zeroed end of block");

	if (ext4_should_journal_data(inode)) {
		err = ext4_handle_dirty_metadata(handle, inode, bh);
	} else {
		err = 0;
		mark_buffer_dirty(bh);
		if (ext4_should_order_data(inode))
			err = ext4_jbd2_inode_add_write(handle, inode);
	}

unlock:
	unlock_page(page);
	put_page(page);
	return err;
}


static int ext4_block_zero_page_range(handle_t *handle, struct address_space *mapping, loff_t from, loff_t length)
{
	struct inode *inode = mapping->host;
	unsigned offset = from & (PAGE_SIZE-1);
	unsigned blocksize = inode->i_sb->s_blocksize;
	unsigned max = blocksize - (offset & (blocksize - 1));

	
	if (length > max || length < 0)
		length = max;

	if (IS_DAX(inode)) {
		return iomap_zero_range(inode, from, length, NULL, &ext4_iomap_ops);
	}
	return __ext4_block_zero_page_range(handle, mapping, from, length);
}


static int ext4_block_truncate_page(handle_t *handle, struct address_space *mapping, loff_t from)
{
	unsigned offset = from & (PAGE_SIZE-1);
	unsigned length;
	unsigned blocksize;
	struct inode *inode = mapping->host;

	
	if (ext4_encrypted_inode(inode) && !fscrypt_has_encryption_key(inode))
		return 0;

	blocksize = inode->i_sb->s_blocksize;
	length = blocksize - (offset & (blocksize - 1));

	return ext4_block_zero_page_range(handle, mapping, from, length);
}

int ext4_zero_partial_blocks(handle_t *handle, struct inode *inode, loff_t lstart, loff_t length)
{
	struct super_block *sb = inode->i_sb;
	struct address_space *mapping = inode->i_mapping;
	unsigned partial_start, partial_end;
	ext4_fsblk_t start, end;
	loff_t byte_end = (lstart + length - 1);
	int err = 0;

	partial_start = lstart & (sb->s_blocksize - 1);
	partial_end = byte_end & (sb->s_blocksize - 1);

	start = lstart >> sb->s_blocksize_bits;
	end = byte_end >> sb->s_blocksize_bits;

	
	if (start == end && (partial_start || (partial_end != sb->s_blocksize - 1))) {
		err = ext4_block_zero_page_range(handle, mapping, lstart, length);
		return err;
	}
	
	if (partial_start) {
		err = ext4_block_zero_page_range(handle, mapping, lstart, sb->s_blocksize);
		if (err)
			return err;
	}
	
	if (partial_end != sb->s_blocksize - 1)
		err = ext4_block_zero_page_range(handle, mapping, byte_end - partial_end, partial_end + 1);

	return err;
}

int ext4_can_truncate(struct inode *inode)
{
	if (S_ISREG(inode->i_mode))
		return 1;
	if (S_ISDIR(inode->i_mode))
		return 1;
	if (S_ISLNK(inode->i_mode))
		return !ext4_inode_is_fast_symlink(inode);
	return 0;
}


int ext4_update_disksize_before_punch(struct inode *inode, loff_t offset, loff_t len)
{
	handle_t *handle;
	loff_t size = i_size_read(inode);

	WARN_ON(!inode_is_locked(inode));
	if (offset > size || offset + len < size)
		return 0;

	if (EXT4_I(inode)->i_disksize >= size)
		return 0;

	handle = ext4_journal_start(inode, EXT4_HT_MISC, 1);
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	ext4_update_i_disksize(inode, size);
	ext4_mark_inode_dirty(handle, inode);
	ext4_journal_stop(handle);

	return 0;
}



int ext4_punch_hole(struct inode *inode, loff_t offset, loff_t length)
{
	struct super_block *sb = inode->i_sb;
	ext4_lblk_t first_block, stop_block;
	struct address_space *mapping = inode->i_mapping;
	loff_t first_block_offset, last_block_offset;
	handle_t *handle;
	unsigned int credits;
	int ret = 0;

	if (!S_ISREG(inode->i_mode))
		return -EOPNOTSUPP;

	trace_ext4_punch_hole(inode, offset, length, 0);

	
	if (mapping_tagged(mapping, PAGECACHE_TAG_DIRTY)) {
		ret = filemap_write_and_wait_range(mapping, offset, offset + length - 1);
		if (ret)
			return ret;
	}

	inode_lock(inode);

	
	if (offset >= inode->i_size)
		goto out_mutex;

	
	if (offset + length > inode->i_size) {
		length = inode->i_size + PAGE_SIZE - (inode->i_size & (PAGE_SIZE - 1)) - offset;

	}

	if (offset & (sb->s_blocksize - 1) || (offset + length) & (sb->s_blocksize - 1)) {
		
		ret = ext4_inode_attach_jinode(inode);
		if (ret < 0)
			goto out_mutex;

	}

	
	inode_dio_wait(inode);

	
	down_write(&EXT4_I(inode)->i_mmap_sem);
	first_block_offset = round_up(offset, sb->s_blocksize);
	last_block_offset = round_down((offset + length), sb->s_blocksize) - 1;

	
	if (last_block_offset > first_block_offset) {
		ret = ext4_update_disksize_before_punch(inode, offset, length);
		if (ret)
			goto out_dio;
		truncate_pagecache_range(inode, first_block_offset, last_block_offset);
	}

	if (ext4_test_inode_flag(inode, EXT4_INODE_EXTENTS))
		credits = ext4_writepage_trans_blocks(inode);
	else credits = ext4_blocks_for_truncate(inode);
	handle = ext4_journal_start(inode, EXT4_HT_TRUNCATE, credits);
	if (IS_ERR(handle)) {
		ret = PTR_ERR(handle);
		ext4_std_error(sb, ret);
		goto out_dio;
	}

	ret = ext4_zero_partial_blocks(handle, inode, offset, length);
	if (ret)
		goto out_stop;

	first_block = (offset + sb->s_blocksize - 1) >> EXT4_BLOCK_SIZE_BITS(sb);
	stop_block = (offset + length) >> EXT4_BLOCK_SIZE_BITS(sb);

	
	if (stop_block > first_block) {

		down_write(&EXT4_I(inode)->i_data_sem);
		ext4_discard_preallocations(inode);

		ret = ext4_es_remove_extent(inode, first_block, stop_block - first_block);
		if (ret) {
			up_write(&EXT4_I(inode)->i_data_sem);
			goto out_stop;
		}

		if (ext4_test_inode_flag(inode, EXT4_INODE_EXTENTS))
			ret = ext4_ext_remove_space(inode, first_block, stop_block - 1);
		else ret = ext4_ind_remove_space(handle, inode, first_block, stop_block);


		up_write(&EXT4_I(inode)->i_data_sem);
	}
	if (IS_SYNC(inode))
		ext4_handle_sync(handle);

	inode->i_mtime = inode->i_ctime = current_time(inode);
	ext4_mark_inode_dirty(handle, inode);
	if (ret >= 0)
		ext4_update_inode_fsync_trans(handle, inode, 1);
out_stop:
	ext4_journal_stop(handle);
out_dio:
	up_write(&EXT4_I(inode)->i_mmap_sem);
out_mutex:
	inode_unlock(inode);
	return ret;
}

int ext4_inode_attach_jinode(struct inode *inode)
{
	struct ext4_inode_info *ei = EXT4_I(inode);
	struct jbd2_inode *jinode;

	if (ei->jinode || !EXT4_SB(inode->i_sb)->s_journal)
		return 0;

	jinode = jbd2_alloc_inode(GFP_KERNEL);
	spin_lock(&inode->i_lock);
	if (!ei->jinode) {
		if (!jinode) {
			spin_unlock(&inode->i_lock);
			return -ENOMEM;
		}
		ei->jinode = jinode;
		jbd2_journal_init_jbd_inode(ei->jinode, inode);
		jinode = NULL;
	}
	spin_unlock(&inode->i_lock);
	if (unlikely(jinode != NULL))
		jbd2_free_inode(jinode);
	return 0;
}


int ext4_truncate(struct inode *inode)
{
	struct ext4_inode_info *ei = EXT4_I(inode);
	unsigned int credits;
	int err = 0;
	handle_t *handle;
	struct address_space *mapping = inode->i_mapping;

	
	if (!(inode->i_state & (I_NEW|I_FREEING)))
		WARN_ON(!inode_is_locked(inode));
	trace_ext4_truncate_enter(inode);

	if (!ext4_can_truncate(inode))
		return 0;

	ext4_clear_inode_flag(inode, EXT4_INODE_EOFBLOCKS);

	if (inode->i_size == 0 && !test_opt(inode->i_sb, NO_AUTO_DA_ALLOC))
		ext4_set_inode_state(inode, EXT4_STATE_DA_ALLOC_CLOSE);

	if (ext4_has_inline_data(inode)) {
		int has_inline = 1;

		err = ext4_inline_data_truncate(inode, &has_inline);
		if (err)
			return err;
		if (has_inline)
			return 0;
	}

	
	if (inode->i_size & (inode->i_sb->s_blocksize - 1)) {
		if (ext4_inode_attach_jinode(inode) < 0)
			return 0;
	}

	if (ext4_test_inode_flag(inode, EXT4_INODE_EXTENTS))
		credits = ext4_writepage_trans_blocks(inode);
	else credits = ext4_blocks_for_truncate(inode);

	handle = ext4_journal_start(inode, EXT4_HT_TRUNCATE, credits);
	if (IS_ERR(handle))
		return PTR_ERR(handle);

	if (inode->i_size & (inode->i_sb->s_blocksize - 1))
		ext4_block_truncate_page(handle, mapping, inode->i_size);

	
	err = ext4_orphan_add(handle, inode);
	if (err)
		goto out_stop;

	down_write(&EXT4_I(inode)->i_data_sem);

	ext4_discard_preallocations(inode);

	if (ext4_test_inode_flag(inode, EXT4_INODE_EXTENTS))
		err = ext4_ext_truncate(handle, inode);
	else ext4_ind_truncate(handle, inode);

	up_write(&ei->i_data_sem);
	if (err)
		goto out_stop;

	if (IS_SYNC(inode))
		ext4_handle_sync(handle);

out_stop:
	
	if (inode->i_nlink)
		ext4_orphan_del(handle, inode);

	inode->i_mtime = inode->i_ctime = current_time(inode);
	ext4_mark_inode_dirty(handle, inode);
	ext4_journal_stop(handle);

	trace_ext4_truncate_exit(inode);
	return err;
}


static int __ext4_get_inode_loc(struct inode *inode, struct ext4_iloc *iloc, int in_mem)
{
	struct ext4_group_desc	*gdp;
	struct buffer_head	*bh;
	struct super_block	*sb = inode->i_sb;
	ext4_fsblk_t		block;
	int			inodes_per_block, inode_offset;

	iloc->bh = NULL;
	if (!ext4_valid_inum(sb, inode->i_ino))
		return -EFSCORRUPTED;

	iloc->block_group = (inode->i_ino - 1) / EXT4_INODES_PER_GROUP(sb);
	gdp = ext4_get_group_desc(sb, iloc->block_group, NULL);
	if (!gdp)
		return -EIO;

	
	inodes_per_block = EXT4_SB(sb)->s_inodes_per_block;
	inode_offset = ((inode->i_ino - 1) % EXT4_INODES_PER_GROUP(sb));
	block = ext4_inode_table(sb, gdp) + (inode_offset / inodes_per_block);
	iloc->offset = (inode_offset % inodes_per_block) * EXT4_INODE_SIZE(sb);

	bh = sb_getblk(sb, block);
	if (unlikely(!bh))
		return -ENOMEM;
	if (!buffer_uptodate(bh)) {
		lock_buffer(bh);

		
		if (buffer_write_io_error(bh) && !buffer_uptodate(bh))
			set_buffer_uptodate(bh);

		if (buffer_uptodate(bh)) {
			
			unlock_buffer(bh);
			goto has_buffer;
		}

		
		if (in_mem) {
			struct buffer_head *bitmap_bh;
			int i, start;

			start = inode_offset & ~(inodes_per_block - 1);

			
			bitmap_bh = sb_getblk(sb, ext4_inode_bitmap(sb, gdp));
			if (unlikely(!bitmap_bh))
				goto make_io;

			
			if (!buffer_uptodate(bitmap_bh)) {
				brelse(bitmap_bh);
				goto make_io;
			}
			for (i = start; i < start + inodes_per_block; i++) {
				if (i == inode_offset)
					continue;
				if (ext4_test_bit(i, bitmap_bh->b_data))
					break;
			}
			brelse(bitmap_bh);
			if (i == start + inodes_per_block) {
				
				memset(bh->b_data, 0, bh->b_size);
				set_buffer_uptodate(bh);
				unlock_buffer(bh);
				goto has_buffer;
			}
		}

make_io:
		
		if (EXT4_SB(sb)->s_inode_readahead_blks) {
			ext4_fsblk_t b, end, table;
			unsigned num;
			__u32 ra_blks = EXT4_SB(sb)->s_inode_readahead_blks;

			table = ext4_inode_table(sb, gdp);
			
			b = block & ~((ext4_fsblk_t) ra_blks - 1);
			if (table > b)
				b = table;
			end = b + ra_blks;
			num = EXT4_INODES_PER_GROUP(sb);
			if (ext4_has_group_desc_csum(sb))
				num -= ext4_itable_unused_count(sb, gdp);
			table += num / inodes_per_block;
			if (end > table)
				end = table;
			while (b <= end)
				sb_breadahead(sb, b++);
		}

		
		trace_ext4_load_inode(inode);
		get_bh(bh);
		bh->b_end_io = end_buffer_read_sync;
		submit_bh(REQ_OP_READ, REQ_META | REQ_PRIO, bh);
		wait_on_buffer(bh);
		if (!buffer_uptodate(bh)) {
			EXT4_ERROR_INODE_BLOCK(inode, block, "unable to read itable block");
			brelse(bh);
			return -EIO;
		}
	}
has_buffer:
	iloc->bh = bh;
	return 0;
}

int ext4_get_inode_loc(struct inode *inode, struct ext4_iloc *iloc)
{
	
	return __ext4_get_inode_loc(inode, iloc, !ext4_test_inode_state(inode, EXT4_STATE_XATTR));
}

static bool ext4_should_use_dax(struct inode *inode)
{
	if (!test_opt(inode->i_sb, DAX))
		return false;
	if (!S_ISREG(inode->i_mode))
		return false;
	if (ext4_should_journal_data(inode))
		return false;
	if (ext4_has_inline_data(inode))
		return false;
	if (ext4_encrypted_inode(inode))
		return false;
	return true;
}

void ext4_set_inode_flags(struct inode *inode)
{
	unsigned int flags = EXT4_I(inode)->i_flags;
	unsigned int new_fl = 0;

	if (flags & EXT4_SYNC_FL)
		new_fl |= S_SYNC;
	if (flags & EXT4_APPEND_FL)
		new_fl |= S_APPEND;
	if (flags & EXT4_IMMUTABLE_FL)
		new_fl |= S_IMMUTABLE;
	if (flags & EXT4_NOATIME_FL)
		new_fl |= S_NOATIME;
	if (flags & EXT4_DIRSYNC_FL)
		new_fl |= S_DIRSYNC;
	if (ext4_should_use_dax(inode))
		new_fl |= S_DAX;
	if (flags & EXT4_ENCRYPT_FL)
		new_fl |= S_ENCRYPTED;
	inode_set_flags(inode, new_fl, S_SYNC|S_APPEND|S_IMMUTABLE|S_NOATIME|S_DIRSYNC|S_DAX| S_ENCRYPTED);

}

static blkcnt_t ext4_inode_blocks(struct ext4_inode *raw_inode, struct ext4_inode_info *ei)
{
	blkcnt_t i_blocks ;
	struct inode *inode = &(ei->vfs_inode);
	struct super_block *sb = inode->i_sb;

	if (ext4_has_feature_huge_file(sb)) {
		
		i_blocks = ((u64)le16_to_cpu(raw_inode->i_blocks_high)) << 32 | le32_to_cpu(raw_inode->i_blocks_lo);
		if (ext4_test_inode_flag(inode, EXT4_INODE_HUGE_FILE)) {
			
			return i_blocks  << (inode->i_blkbits - 9);
		} else {
			return i_blocks;
		}
	} else {
		return le32_to_cpu(raw_inode->i_blocks_lo);
	}
}

static inline int ext4_iget_extra_inode(struct inode *inode, struct ext4_inode *raw_inode, struct ext4_inode_info *ei)

{
	__le32 *magic = (void *)raw_inode + EXT4_GOOD_OLD_INODE_SIZE + ei->i_extra_isize;

	if (EXT4_GOOD_OLD_INODE_SIZE + ei->i_extra_isize + sizeof(__le32) <= EXT4_INODE_SIZE(inode->i_sb) && *magic == cpu_to_le32(EXT4_XATTR_MAGIC)) {

		ext4_set_inode_state(inode, EXT4_STATE_XATTR);
		return ext4_find_inline_data_nolock(inode);
	} else EXT4_I(inode)->i_inline_off = 0;
	return 0;
}

int ext4_get_projid(struct inode *inode, kprojid_t *projid)
{
	if (!ext4_has_feature_project(inode->i_sb))
		return -EOPNOTSUPP;
	*projid = EXT4_I(inode)->i_projid;
	return 0;
}


static inline void ext4_inode_set_iversion_queried(struct inode *inode, u64 val)
{
	if (unlikely(EXT4_I(inode)->i_flags & EXT4_EA_INODE_FL))
		inode_set_iversion_raw(inode, val);
	else inode_set_iversion_queried(inode, val);
}
static inline u64 ext4_inode_peek_iversion(const struct inode *inode)
{
	if (unlikely(EXT4_I(inode)->i_flags & EXT4_EA_INODE_FL))
		return inode_peek_iversion_raw(inode);
	else return inode_peek_iversion(inode);
}

struct inode *ext4_iget(struct super_block *sb, unsigned long ino)
{
	struct ext4_iloc iloc;
	struct ext4_inode *raw_inode;
	struct ext4_inode_info *ei;
	struct inode *inode;
	journal_t *journal = EXT4_SB(sb)->s_journal;
	long ret;
	loff_t size;
	int block;
	uid_t i_uid;
	gid_t i_gid;
	projid_t i_projid;

	inode = iget_locked(sb, ino);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;

	ei = EXT4_I(inode);
	iloc.bh = NULL;

	ret = __ext4_get_inode_loc(inode, &iloc, 0);
	if (ret < 0)
		goto bad_inode;
	raw_inode = ext4_raw_inode(&iloc);

	if ((ino == EXT4_ROOT_INO) && (raw_inode->i_links_count == 0)) {
		EXT4_ERROR_INODE(inode, "root inode unallocated");
		ret = -EFSCORRUPTED;
		goto bad_inode;
	}

	if (EXT4_INODE_SIZE(inode->i_sb) > EXT4_GOOD_OLD_INODE_SIZE) {
		ei->i_extra_isize = le16_to_cpu(raw_inode->i_extra_isize);
		if (EXT4_GOOD_OLD_INODE_SIZE + ei->i_extra_isize > EXT4_INODE_SIZE(inode->i_sb) || (ei->i_extra_isize & 3)) {

			EXT4_ERROR_INODE(inode, "bad extra_isize %u (inode size %u)", ei->i_extra_isize, EXT4_INODE_SIZE(inode->i_sb));


			ret = -EFSCORRUPTED;
			goto bad_inode;
		}
	} else ei->i_extra_isize = 0;

	
	if (ext4_has_metadata_csum(sb)) {
		struct ext4_sb_info *sbi = EXT4_SB(inode->i_sb);
		__u32 csum;
		__le32 inum = cpu_to_le32(inode->i_ino);
		__le32 gen = raw_inode->i_generation;
		csum = ext4_chksum(sbi, sbi->s_csum_seed, (__u8 *)&inum, sizeof(inum));
		ei->i_csum_seed = ext4_chksum(sbi, csum, (__u8 *)&gen, sizeof(gen));
	}

	if (!ext4_inode_csum_verify(inode, raw_inode, ei)) {
		EXT4_ERROR_INODE(inode, "checksum invalid");
		ret = -EFSBADCRC;
		goto bad_inode;
	}

	inode->i_mode = le16_to_cpu(raw_inode->i_mode);
	i_uid = (uid_t)le16_to_cpu(raw_inode->i_uid_low);
	i_gid = (gid_t)le16_to_cpu(raw_inode->i_gid_low);
	if (ext4_has_feature_project(sb) && EXT4_INODE_SIZE(sb) > EXT4_GOOD_OLD_INODE_SIZE && EXT4_FITS_IN_INODE(raw_inode, ei, i_projid))

		i_projid = (projid_t)le32_to_cpu(raw_inode->i_projid);
	else i_projid = EXT4_DEF_PROJID;

	if (!(test_opt(inode->i_sb, NO_UID32))) {
		i_uid |= le16_to_cpu(raw_inode->i_uid_high) << 16;
		i_gid |= le16_to_cpu(raw_inode->i_gid_high) << 16;
	}
	i_uid_write(inode, i_uid);
	i_gid_write(inode, i_gid);
	ei->i_projid = make_kprojid(&init_user_ns, i_projid);
	set_nlink(inode, le16_to_cpu(raw_inode->i_links_count));

	ext4_clear_state_flags(ei);	
	ei->i_inline_off = 0;
	ei->i_dir_start_lookup = 0;
	ei->i_dtime = le32_to_cpu(raw_inode->i_dtime);
	
	if (inode->i_nlink == 0) {
		if ((inode->i_mode == 0 || !(EXT4_SB(inode->i_sb)->s_mount_state & EXT4_ORPHAN_FS)) && ino != EXT4_BOOT_LOADER_INO) {

			
			ret = -ESTALE;
			goto bad_inode;
		}
		
	}
	ei->i_flags = le32_to_cpu(raw_inode->i_flags);
	inode->i_blocks = ext4_inode_blocks(raw_inode, ei);
	ei->i_file_acl = le32_to_cpu(raw_inode->i_file_acl_lo);
	if (ext4_has_feature_64bit(sb))
		ei->i_file_acl |= ((__u64)le16_to_cpu(raw_inode->i_file_acl_high)) << 32;
	inode->i_size = ext4_isize(sb, raw_inode);
	if ((size = i_size_read(inode)) < 0) {
		EXT4_ERROR_INODE(inode, "bad i_size value: %lld", size);
		ret = -EFSCORRUPTED;
		goto bad_inode;
	}
	ei->i_disksize = inode->i_size;

	ei->i_reserved_quota = 0;

	inode->i_generation = le32_to_cpu(raw_inode->i_generation);
	ei->i_block_group = iloc.block_group;
	ei->i_last_alloc_group = ~0;
	
	for (block = 0; block < EXT4_N_BLOCKS; block++)
		ei->i_data[block] = raw_inode->i_block[block];
	INIT_LIST_HEAD(&ei->i_orphan);

	
	if (journal) {
		transaction_t *transaction;
		tid_t tid;

		read_lock(&journal->j_state_lock);
		if (journal->j_running_transaction)
			transaction = journal->j_running_transaction;
		else transaction = journal->j_committing_transaction;
		if (transaction)
			tid = transaction->t_tid;
		else tid = journal->j_commit_sequence;
		read_unlock(&journal->j_state_lock);
		ei->i_sync_tid = tid;
		ei->i_datasync_tid = tid;
	}

	if (EXT4_INODE_SIZE(inode->i_sb) > EXT4_GOOD_OLD_INODE_SIZE) {
		if (ei->i_extra_isize == 0) {
			
			BUILD_BUG_ON(sizeof(struct ext4_inode) & 3);
			ei->i_extra_isize = sizeof(struct ext4_inode) - EXT4_GOOD_OLD_INODE_SIZE;
		} else {
			ret = ext4_iget_extra_inode(inode, raw_inode, ei);
			if (ret)
				goto bad_inode;
		}
	}

	EXT4_INODE_GET_XTIME(i_ctime, inode, raw_inode);
	EXT4_INODE_GET_XTIME(i_mtime, inode, raw_inode);
	EXT4_INODE_GET_XTIME(i_atime, inode, raw_inode);
	EXT4_EINODE_GET_XTIME(i_crtime, ei, raw_inode);

	if (likely(!test_opt2(inode->i_sb, HURD_COMPAT))) {
		u64 ivers = le32_to_cpu(raw_inode->i_disk_version);

		if (EXT4_INODE_SIZE(inode->i_sb) > EXT4_GOOD_OLD_INODE_SIZE) {
			if (EXT4_FITS_IN_INODE(raw_inode, ei, i_version_hi))
				ivers |= (__u64)(le32_to_cpu(raw_inode->i_version_hi)) << 32;
		}
		ext4_inode_set_iversion_queried(inode, ivers);
	}

	ret = 0;
	if (ei->i_file_acl && !ext4_data_block_valid(EXT4_SB(sb), ei->i_file_acl, 1)) {
		EXT4_ERROR_INODE(inode, "bad extended attribute block %llu", ei->i_file_acl);
		ret = -EFSCORRUPTED;
		goto bad_inode;
	} else if (!ext4_has_inline_data(inode)) {
		if (ext4_test_inode_flag(inode, EXT4_INODE_EXTENTS)) {
			if ((S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode) || (S_ISLNK(inode->i_mode) && !ext4_inode_is_fast_symlink(inode))))

				
				ret = ext4_ext_check_inode(inode);
		} else if (S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode) || (S_ISLNK(inode->i_mode) && !ext4_inode_is_fast_symlink(inode))) {

			
			ret = ext4_ind_check_inode(inode);
		}
	}
	if (ret)
		goto bad_inode;

	if (S_ISREG(inode->i_mode)) {
		inode->i_op = &ext4_file_inode_operations;
		inode->i_fop = &ext4_file_operations;
		ext4_set_aops(inode);
	} else if (S_ISDIR(inode->i_mode)) {
		inode->i_op = &ext4_dir_inode_operations;
		inode->i_fop = &ext4_dir_operations;
	} else if (S_ISLNK(inode->i_mode)) {
		
		if (IS_APPEND(inode) || IS_IMMUTABLE(inode)) {
			EXT4_ERROR_INODE(inode, "immutable or append flags not allowed on symlinks");
			ret = -EFSCORRUPTED;
			goto bad_inode;
		}
		if (ext4_encrypted_inode(inode)) {
			inode->i_op = &ext4_encrypted_symlink_inode_operations;
			ext4_set_aops(inode);
		} else if (ext4_inode_is_fast_symlink(inode)) {
			inode->i_link = (char *)ei->i_data;
			inode->i_op = &ext4_fast_symlink_inode_operations;
			nd_terminate_link(ei->i_data, inode->i_size, sizeof(ei->i_data) - 1);
		} else {
			inode->i_op = &ext4_symlink_inode_operations;
			ext4_set_aops(inode);
		}
		inode_nohighmem(inode);
	} else if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode) || S_ISFIFO(inode->i_mode) || S_ISSOCK(inode->i_mode)) {
		inode->i_op = &ext4_special_inode_operations;
		if (raw_inode->i_block[0])
			init_special_inode(inode, inode->i_mode, old_decode_dev(le32_to_cpu(raw_inode->i_block[0])));
		else init_special_inode(inode, inode->i_mode, new_decode_dev(le32_to_cpu(raw_inode->i_block[1])));

	} else if (ino == EXT4_BOOT_LOADER_INO) {
		make_bad_inode(inode);
	} else {
		ret = -EFSCORRUPTED;
		EXT4_ERROR_INODE(inode, "bogus i_mode (%o)", inode->i_mode);
		goto bad_inode;
	}
	brelse(iloc.bh);
	ext4_set_inode_flags(inode);

	unlock_new_inode(inode);
	return inode;

bad_inode:
	brelse(iloc.bh);
	iget_failed(inode);
	return ERR_PTR(ret);
}

struct inode *ext4_iget_normal(struct super_block *sb, unsigned long ino)
{
	if (ino < EXT4_FIRST_INO(sb) && ino != EXT4_ROOT_INO)
		return ERR_PTR(-EFSCORRUPTED);
	return ext4_iget(sb, ino);
}

static int ext4_inode_blocks_set(handle_t *handle, struct ext4_inode *raw_inode, struct ext4_inode_info *ei)

{
	struct inode *inode = &(ei->vfs_inode);
	u64 i_blocks = inode->i_blocks;
	struct super_block *sb = inode->i_sb;

	if (i_blocks <= ~0U) {
		
		raw_inode->i_blocks_lo   = cpu_to_le32(i_blocks);
		raw_inode->i_blocks_high = 0;
		ext4_clear_inode_flag(inode, EXT4_INODE_HUGE_FILE);
		return 0;
	}
	if (!ext4_has_feature_huge_file(sb))
		return -EFBIG;

	if (i_blocks <= 0xffffffffffffULL) {
		
		raw_inode->i_blocks_lo   = cpu_to_le32(i_blocks);
		raw_inode->i_blocks_high = cpu_to_le16(i_blocks >> 32);
		ext4_clear_inode_flag(inode, EXT4_INODE_HUGE_FILE);
	} else {
		ext4_set_inode_flag(inode, EXT4_INODE_HUGE_FILE);
		
		i_blocks = i_blocks >> (inode->i_blkbits - 9);
		raw_inode->i_blocks_lo   = cpu_to_le32(i_blocks);
		raw_inode->i_blocks_high = cpu_to_le16(i_blocks >> 32);
	}
	return 0;
}

struct other_inode {
	unsigned long		orig_ino;
	struct ext4_inode	*raw_inode;
};

static int other_inode_match(struct inode * inode, unsigned long ino, void *data)
{
	struct other_inode *oi = (struct other_inode *) data;

	if ((inode->i_ino != ino) || (inode->i_state & (I_FREEING | I_WILL_FREE | I_NEW | I_DIRTY_INODE)) || ((inode->i_state & I_DIRTY_TIME) == 0))


		return 0;
	spin_lock(&inode->i_lock);
	if (((inode->i_state & (I_FREEING | I_WILL_FREE | I_NEW | I_DIRTY_INODE)) == 0) && (inode->i_state & I_DIRTY_TIME)) {

		struct ext4_inode_info	*ei = EXT4_I(inode);

		inode->i_state &= ~(I_DIRTY_TIME | I_DIRTY_TIME_EXPIRED);
		spin_unlock(&inode->i_lock);

		spin_lock(&ei->i_raw_lock);
		EXT4_INODE_SET_XTIME(i_ctime, inode, oi->raw_inode);
		EXT4_INODE_SET_XTIME(i_mtime, inode, oi->raw_inode);
		EXT4_INODE_SET_XTIME(i_atime, inode, oi->raw_inode);
		ext4_inode_csum_set(inode, oi->raw_inode, ei);
		spin_unlock(&ei->i_raw_lock);
		trace_ext4_other_inode_update_time(inode, oi->orig_ino);
		return -1;
	}
	spin_unlock(&inode->i_lock);
	return -1;
}


static void ext4_update_other_inodes_time(struct super_block *sb, unsigned long orig_ino, char *buf)
{
	struct other_inode oi;
	unsigned long ino;
	int i, inodes_per_block = EXT4_SB(sb)->s_inodes_per_block;
	int inode_size = EXT4_INODE_SIZE(sb);

	oi.orig_ino = orig_ino;
	
	ino = ((orig_ino - 1) & ~(inodes_per_block - 1)) + 1;
	for (i = 0; i < inodes_per_block; i++, ino++, buf += inode_size) {
		if (ino == orig_ino)
			continue;
		oi.raw_inode = (struct ext4_inode *) buf;
		(void) find_inode_nowait(sb, ino, other_inode_match, &oi);
	}
}


static int ext4_do_update_inode(handle_t *handle, struct inode *inode, struct ext4_iloc *iloc)

{
	struct ext4_inode *raw_inode = ext4_raw_inode(iloc);
	struct ext4_inode_info *ei = EXT4_I(inode);
	struct buffer_head *bh = iloc->bh;
	struct super_block *sb = inode->i_sb;
	int err = 0, rc, block;
	int need_datasync = 0, set_large_file = 0;
	uid_t i_uid;
	gid_t i_gid;
	projid_t i_projid;

	spin_lock(&ei->i_raw_lock);

	
	if (ext4_test_inode_state(inode, EXT4_STATE_NEW))
		memset(raw_inode, 0, EXT4_SB(inode->i_sb)->s_inode_size);

	raw_inode->i_mode = cpu_to_le16(inode->i_mode);
	i_uid = i_uid_read(inode);
	i_gid = i_gid_read(inode);
	i_projid = from_kprojid(&init_user_ns, ei->i_projid);
	if (!(test_opt(inode->i_sb, NO_UID32))) {
		raw_inode->i_uid_low = cpu_to_le16(low_16_bits(i_uid));
		raw_inode->i_gid_low = cpu_to_le16(low_16_bits(i_gid));

		if (ei->i_dtime && list_empty(&ei->i_orphan)) {
			raw_inode->i_uid_high = 0;
			raw_inode->i_gid_high = 0;
		} else {
			raw_inode->i_uid_high = cpu_to_le16(high_16_bits(i_uid));
			raw_inode->i_gid_high = cpu_to_le16(high_16_bits(i_gid));
		}
	} else {
		raw_inode->i_uid_low = cpu_to_le16(fs_high2lowuid(i_uid));
		raw_inode->i_gid_low = cpu_to_le16(fs_high2lowgid(i_gid));
		raw_inode->i_uid_high = 0;
		raw_inode->i_gid_high = 0;
	}
	raw_inode->i_links_count = cpu_to_le16(inode->i_nlink);

	EXT4_INODE_SET_XTIME(i_ctime, inode, raw_inode);
	EXT4_INODE_SET_XTIME(i_mtime, inode, raw_inode);
	EXT4_INODE_SET_XTIME(i_atime, inode, raw_inode);
	EXT4_EINODE_SET_XTIME(i_crtime, ei, raw_inode);

	err = ext4_inode_blocks_set(handle, raw_inode, ei);
	if (err) {
		spin_unlock(&ei->i_raw_lock);
		goto out_brelse;
	}
	raw_inode->i_dtime = cpu_to_le32(ei->i_dtime);
	raw_inode->i_flags = cpu_to_le32(ei->i_flags & 0xFFFFFFFF);
	if (likely(!test_opt2(inode->i_sb, HURD_COMPAT)))
		raw_inode->i_file_acl_high = cpu_to_le16(ei->i_file_acl >> 32);
	raw_inode->i_file_acl_lo = cpu_to_le32(ei->i_file_acl);
	if (ei->i_disksize != ext4_isize(inode->i_sb, raw_inode)) {
		ext4_isize_set(raw_inode, ei->i_disksize);
		need_datasync = 1;
	}
	if (ei->i_disksize > 0x7fffffffULL) {
		if (!ext4_has_feature_large_file(sb) || EXT4_SB(sb)->s_es->s_rev_level == cpu_to_le32(EXT4_GOOD_OLD_REV))

			set_large_file = 1;
	}
	raw_inode->i_generation = cpu_to_le32(inode->i_generation);
	if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode)) {
		if (old_valid_dev(inode->i_rdev)) {
			raw_inode->i_block[0] = cpu_to_le32(old_encode_dev(inode->i_rdev));
			raw_inode->i_block[1] = 0;
		} else {
			raw_inode->i_block[0] = 0;
			raw_inode->i_block[1] = cpu_to_le32(new_encode_dev(inode->i_rdev));
			raw_inode->i_block[2] = 0;
		}
	} else if (!ext4_has_inline_data(inode)) {
		for (block = 0; block < EXT4_N_BLOCKS; block++)
			raw_inode->i_block[block] = ei->i_data[block];
	}

	if (likely(!test_opt2(inode->i_sb, HURD_COMPAT))) {
		u64 ivers = ext4_inode_peek_iversion(inode);

		raw_inode->i_disk_version = cpu_to_le32(ivers);
		if (ei->i_extra_isize) {
			if (EXT4_FITS_IN_INODE(raw_inode, ei, i_version_hi))
				raw_inode->i_version_hi = cpu_to_le32(ivers >> 32);
			raw_inode->i_extra_isize = cpu_to_le16(ei->i_extra_isize);
		}
	}

	BUG_ON(!ext4_has_feature_project(inode->i_sb) && i_projid != EXT4_DEF_PROJID);

	if (EXT4_INODE_SIZE(inode->i_sb) > EXT4_GOOD_OLD_INODE_SIZE && EXT4_FITS_IN_INODE(raw_inode, ei, i_projid))
		raw_inode->i_projid = cpu_to_le32(i_projid);

	ext4_inode_csum_set(inode, raw_inode, ei);
	spin_unlock(&ei->i_raw_lock);
	if (inode->i_sb->s_flags & SB_LAZYTIME)
		ext4_update_other_inodes_time(inode->i_sb, inode->i_ino, bh->b_data);

	BUFFER_TRACE(bh, "call ext4_handle_dirty_metadata");
	rc = ext4_handle_dirty_metadata(handle, NULL, bh);
	if (!err)
		err = rc;
	ext4_clear_inode_state(inode, EXT4_STATE_NEW);
	if (set_large_file) {
		BUFFER_TRACE(EXT4_SB(sb)->s_sbh, "get write access");
		err = ext4_journal_get_write_access(handle, EXT4_SB(sb)->s_sbh);
		if (err)
			goto out_brelse;
		ext4_update_dynamic_rev(sb);
		ext4_set_feature_large_file(sb);
		ext4_handle_sync(handle);
		err = ext4_handle_dirty_super(handle, sb);
	}
	ext4_update_inode_fsync_trans(handle, inode, need_datasync);
out_brelse:
	brelse(bh);
	ext4_std_error(inode->i_sb, err);
	return err;
}


int ext4_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	int err;

	if (WARN_ON_ONCE(current->flags & PF_MEMALLOC))
		return 0;

	if (EXT4_SB(inode->i_sb)->s_journal) {
		if (ext4_journal_current_handle()) {
			jbd_debug(1, "called recursively, non-PF_MEMALLOC!\n");
			dump_stack();
			return -EIO;
		}

		
		if (wbc->sync_mode != WB_SYNC_ALL || wbc->for_sync)
			return 0;

		err = ext4_force_commit(inode->i_sb);
	} else {
		struct ext4_iloc iloc;

		err = __ext4_get_inode_loc(inode, &iloc, 0);
		if (err)
			return err;
		
		if (wbc->sync_mode == WB_SYNC_ALL && !wbc->for_sync)
			sync_dirty_buffer(iloc.bh);
		if (buffer_req(iloc.bh) && !buffer_uptodate(iloc.bh)) {
			EXT4_ERROR_INODE_BLOCK(inode, iloc.bh->b_blocknr, "IO error syncing inode");
			err = -EIO;
		}
		brelse(iloc.bh);
	}
	return err;
}


static void ext4_wait_for_tail_page_commit(struct inode *inode)
{
	struct page *page;
	unsigned offset;
	journal_t *journal = EXT4_SB(inode->i_sb)->s_journal;
	tid_t commit_tid = 0;
	int ret;

	offset = inode->i_size & (PAGE_SIZE - 1);
	
	if (offset > PAGE_SIZE - i_blocksize(inode))
		return;
	while (1) {
		page = find_lock_page(inode->i_mapping, inode->i_size >> PAGE_SHIFT);
		if (!page)
			return;
		ret = __ext4_journalled_invalidatepage(page, offset, PAGE_SIZE - offset);
		unlock_page(page);
		put_page(page);
		if (ret != -EBUSY)
			return;
		commit_tid = 0;
		read_lock(&journal->j_state_lock);
		if (journal->j_committing_transaction)
			commit_tid = journal->j_committing_transaction->t_tid;
		read_unlock(&journal->j_state_lock);
		if (commit_tid)
			jbd2_log_wait_commit(journal, commit_tid);
	}
}


int ext4_setattr(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = d_inode(dentry);
	int error, rc = 0;
	int orphan = 0;
	const unsigned int ia_valid = attr->ia_valid;

	if (unlikely(ext4_forced_shutdown(EXT4_SB(inode->i_sb))))
		return -EIO;

	error = setattr_prepare(dentry, attr);
	if (error)
		return error;

	error = fscrypt_prepare_setattr(dentry, attr);
	if (error)
		return error;

	if (is_quota_modification(inode, attr)) {
		error = dquot_initialize(inode);
		if (error)
			return error;
	}
	if ((ia_valid & ATTR_UID && !uid_eq(attr->ia_uid, inode->i_uid)) || (ia_valid & ATTR_GID && !gid_eq(attr->ia_gid, inode->i_gid))) {
		handle_t *handle;

		
		handle = ext4_journal_start(inode, EXT4_HT_QUOTA, (EXT4_MAXQUOTAS_INIT_BLOCKS(inode->i_sb) + EXT4_MAXQUOTAS_DEL_BLOCKS(inode->i_sb)) + 3);

		if (IS_ERR(handle)) {
			error = PTR_ERR(handle);
			goto err_out;
		}

		
		down_read(&EXT4_I(inode)->xattr_sem);
		error = dquot_transfer(inode, attr);
		up_read(&EXT4_I(inode)->xattr_sem);

		if (error) {
			ext4_journal_stop(handle);
			return error;
		}
		
		if (attr->ia_valid & ATTR_UID)
			inode->i_uid = attr->ia_uid;
		if (attr->ia_valid & ATTR_GID)
			inode->i_gid = attr->ia_gid;
		error = ext4_mark_inode_dirty(handle, inode);
		ext4_journal_stop(handle);
	}

	if (attr->ia_valid & ATTR_SIZE) {
		handle_t *handle;
		loff_t oldsize = inode->i_size;
		int shrink = (attr->ia_size <= inode->i_size);

		if (!(ext4_test_inode_flag(inode, EXT4_INODE_EXTENTS))) {
			struct ext4_sb_info *sbi = EXT4_SB(inode->i_sb);

			if (attr->ia_size > sbi->s_bitmap_maxbytes)
				return -EFBIG;
		}
		if (!S_ISREG(inode->i_mode))
			return -EINVAL;

		if (IS_I_VERSION(inode) && attr->ia_size != inode->i_size)
			inode_inc_iversion(inode);

		if (ext4_should_order_data(inode) && (attr->ia_size < inode->i_size)) {
			error = ext4_begin_ordered_truncate(inode, attr->ia_size);
			if (error)
				goto err_out;
		}
		if (attr->ia_size != inode->i_size) {
			handle = ext4_journal_start(inode, EXT4_HT_INODE, 3);
			if (IS_ERR(handle)) {
				error = PTR_ERR(handle);
				goto err_out;
			}
			if (ext4_handle_valid(handle) && shrink) {
				error = ext4_orphan_add(handle, inode);
				orphan = 1;
			}
			
			if (!shrink) {
				inode->i_mtime = current_time(inode);
				inode->i_ctime = inode->i_mtime;
			}
			down_write(&EXT4_I(inode)->i_data_sem);
			EXT4_I(inode)->i_disksize = attr->ia_size;
			rc = ext4_mark_inode_dirty(handle, inode);
			if (!error)
				error = rc;
			
			if (!error)
				i_size_write(inode, attr->ia_size);
			up_write(&EXT4_I(inode)->i_data_sem);
			ext4_journal_stop(handle);
			if (error) {
				if (orphan)
					ext4_orphan_del(NULL, inode);
				goto err_out;
			}
		}
		if (!shrink)
			pagecache_isize_extended(inode, oldsize, inode->i_size);

		
		if (orphan) {
			if (!ext4_should_journal_data(inode)) {
				inode_dio_wait(inode);
			} else ext4_wait_for_tail_page_commit(inode);
		}
		down_write(&EXT4_I(inode)->i_mmap_sem);
		
		truncate_pagecache(inode, inode->i_size);
		if (shrink) {
			rc = ext4_truncate(inode);
			if (rc)
				error = rc;
		}
		up_write(&EXT4_I(inode)->i_mmap_sem);
	}

	if (!error) {
		setattr_copy(inode, attr);
		mark_inode_dirty(inode);
	}

	
	if (orphan && inode->i_nlink)
		ext4_orphan_del(NULL, inode);

	if (!error && (ia_valid & ATTR_MODE))
		rc = posix_acl_chmod(inode, inode->i_mode);

err_out:
	ext4_std_error(inode->i_sb, error);
	if (!error)
		error = rc;
	return error;
}

int ext4_getattr(const struct path *path, struct kstat *stat, u32 request_mask, unsigned int query_flags)
{
	struct inode *inode = d_inode(path->dentry);
	struct ext4_inode *raw_inode;
	struct ext4_inode_info *ei = EXT4_I(inode);
	unsigned int flags;

	if (EXT4_FITS_IN_INODE(raw_inode, ei, i_crtime)) {
		stat->result_mask |= STATX_BTIME;
		stat->btime.tv_sec = ei->i_crtime.tv_sec;
		stat->btime.tv_nsec = ei->i_crtime.tv_nsec;
	}

	flags = ei->i_flags & EXT4_FL_USER_VISIBLE;
	if (flags & EXT4_APPEND_FL)
		stat->attributes |= STATX_ATTR_APPEND;
	if (flags & EXT4_COMPR_FL)
		stat->attributes |= STATX_ATTR_COMPRESSED;
	if (flags & EXT4_ENCRYPT_FL)
		stat->attributes |= STATX_ATTR_ENCRYPTED;
	if (flags & EXT4_IMMUTABLE_FL)
		stat->attributes |= STATX_ATTR_IMMUTABLE;
	if (flags & EXT4_NODUMP_FL)
		stat->attributes |= STATX_ATTR_NODUMP;

	stat->attributes_mask |= (STATX_ATTR_APPEND | STATX_ATTR_COMPRESSED | STATX_ATTR_ENCRYPTED | STATX_ATTR_IMMUTABLE | STATX_ATTR_NODUMP);




	generic_fillattr(inode, stat);
	return 0;
}

int ext4_file_getattr(const struct path *path, struct kstat *stat, u32 request_mask, unsigned int query_flags)
{
	struct inode *inode = d_inode(path->dentry);
	u64 delalloc_blocks;

	ext4_getattr(path, stat, request_mask, query_flags);

	
	if (unlikely(ext4_has_inline_data(inode)))
		stat->blocks += (stat->size + 511) >> 9;

	
	delalloc_blocks = EXT4_C2B(EXT4_SB(inode->i_sb), EXT4_I(inode)->i_reserved_data_blocks);
	stat->blocks += delalloc_blocks << (inode->i_sb->s_blocksize_bits - 9);
	return 0;
}

static int ext4_index_trans_blocks(struct inode *inode, int lblocks, int pextents)
{
	if (!(ext4_test_inode_flag(inode, EXT4_INODE_EXTENTS)))
		return ext4_ind_trans_blocks(inode, lblocks);
	return ext4_ext_index_trans_blocks(inode, pextents);
}


static int ext4_meta_trans_blocks(struct inode *inode, int lblocks, int pextents)
{
	ext4_group_t groups, ngroups = ext4_get_groups_count(inode->i_sb);
	int gdpblocks;
	int idxblocks;
	int ret = 0;

	
	idxblocks = ext4_index_trans_blocks(inode, lblocks, pextents);

	ret = idxblocks;

	
	groups = idxblocks + pextents;
	gdpblocks = groups;
	if (groups > ngroups)
		groups = ngroups;
	if (groups > EXT4_SB(inode->i_sb)->s_gdb_count)
		gdpblocks = EXT4_SB(inode->i_sb)->s_gdb_count;

	
	ret += groups + gdpblocks;

	
	ret += EXT4_META_TRANS_BLOCKS(inode->i_sb);

	return ret;
}


int ext4_writepage_trans_blocks(struct inode *inode)
{
	int bpp = ext4_journal_blocks_per_page(inode);
	int ret;

	ret = ext4_meta_trans_blocks(inode, bpp, bpp);

	
	if (ext4_should_journal_data(inode))
		ret += bpp;
	return ret;
}


int ext4_chunk_trans_blocks(struct inode *inode, int nrblocks)
{
	return ext4_meta_trans_blocks(inode, nrblocks, 1);
}


int ext4_mark_iloc_dirty(handle_t *handle, struct inode *inode, struct ext4_iloc *iloc)
{
	int err = 0;

	if (unlikely(ext4_forced_shutdown(EXT4_SB(inode->i_sb))))
		return -EIO;

	if (IS_I_VERSION(inode))
		inode_inc_iversion(inode);

	
	get_bh(iloc->bh);

	
	err = ext4_do_update_inode(handle, inode, iloc);
	put_bh(iloc->bh);
	return err;
}



int ext4_reserve_inode_write(handle_t *handle, struct inode *inode, struct ext4_iloc *iloc)

{
	int err;

	if (unlikely(ext4_forced_shutdown(EXT4_SB(inode->i_sb))))
		return -EIO;

	err = ext4_get_inode_loc(inode, iloc);
	if (!err) {
		BUFFER_TRACE(iloc->bh, "get_write_access");
		err = ext4_journal_get_write_access(handle, iloc->bh);
		if (err) {
			brelse(iloc->bh);
			iloc->bh = NULL;
		}
	}
	ext4_std_error(inode->i_sb, err);
	return err;
}

static int __ext4_expand_extra_isize(struct inode *inode, unsigned int new_extra_isize, struct ext4_iloc *iloc, handle_t *handle, int *no_expand)


{
	struct ext4_inode *raw_inode;
	struct ext4_xattr_ibody_header *header;
	int error;

	raw_inode = ext4_raw_inode(iloc);

	header = IHDR(inode, raw_inode);

	
	if (!ext4_test_inode_state(inode, EXT4_STATE_XATTR) || header->h_magic != cpu_to_le32(EXT4_XATTR_MAGIC)) {
		memset((void *)raw_inode + EXT4_GOOD_OLD_INODE_SIZE + EXT4_I(inode)->i_extra_isize, 0, new_extra_isize - EXT4_I(inode)->i_extra_isize);

		EXT4_I(inode)->i_extra_isize = new_extra_isize;
		return 0;
	}

	
	error = ext4_expand_extra_isize_ea(inode, new_extra_isize, raw_inode, handle);
	if (error) {
		
		*no_expand = 1;
	}

	return error;
}


static int ext4_try_to_expand_extra_isize(struct inode *inode, unsigned int new_extra_isize, struct ext4_iloc iloc, handle_t *handle)


{
	int no_expand;
	int error;

	if (ext4_test_inode_state(inode, EXT4_STATE_NO_EXPAND))
		return -EOVERFLOW;

	
	if (ext4_handle_valid(handle) && jbd2_journal_extend(handle, EXT4_DATA_TRANS_BLOCKS(inode->i_sb)) != 0)

		return -ENOSPC;

	if (ext4_write_trylock_xattr(inode, &no_expand) == 0)
		return -EBUSY;

	error = __ext4_expand_extra_isize(inode, new_extra_isize, &iloc, handle, &no_expand);
	ext4_write_unlock_xattr(inode, &no_expand);

	return error;
}

int ext4_expand_extra_isize(struct inode *inode, unsigned int new_extra_isize, struct ext4_iloc *iloc)

{
	handle_t *handle;
	int no_expand;
	int error, rc;

	if (ext4_test_inode_state(inode, EXT4_STATE_NO_EXPAND)) {
		brelse(iloc->bh);
		return -EOVERFLOW;
	}

	handle = ext4_journal_start(inode, EXT4_HT_INODE, EXT4_DATA_TRANS_BLOCKS(inode->i_sb));
	if (IS_ERR(handle)) {
		error = PTR_ERR(handle);
		brelse(iloc->bh);
		return error;
	}

	ext4_write_lock_xattr(inode, &no_expand);

	BUFFER_TRACE(iloc.bh, "get_write_access");
	error = ext4_journal_get_write_access(handle, iloc->bh);
	if (error) {
		brelse(iloc->bh);
		goto out_stop;
	}

	error = __ext4_expand_extra_isize(inode, new_extra_isize, iloc, handle, &no_expand);

	rc = ext4_mark_iloc_dirty(handle, inode, iloc);
	if (!error)
		error = rc;

	ext4_write_unlock_xattr(inode, &no_expand);
out_stop:
	ext4_journal_stop(handle);
	return error;
}


int ext4_mark_inode_dirty(handle_t *handle, struct inode *inode)
{
	struct ext4_iloc iloc;
	struct ext4_sb_info *sbi = EXT4_SB(inode->i_sb);
	int err;

	might_sleep();
	trace_ext4_mark_inode_dirty(inode, _RET_IP_);
	err = ext4_reserve_inode_write(handle, inode, &iloc);
	if (err)
		return err;

	if (EXT4_I(inode)->i_extra_isize < sbi->s_want_extra_isize)
		ext4_try_to_expand_extra_isize(inode, sbi->s_want_extra_isize, iloc, handle);

	return ext4_mark_iloc_dirty(handle, inode, &iloc);
}


void ext4_dirty_inode(struct inode *inode, int flags)
{
	handle_t *handle;

	if (flags == I_DIRTY_TIME)
		return;
	handle = ext4_journal_start(inode, EXT4_HT_INODE, 2);
	if (IS_ERR(handle))
		goto out;

	ext4_mark_inode_dirty(handle, inode);

	ext4_journal_stop(handle);
out:
	return;
}



static int ext4_pin_inode(handle_t *handle, struct inode *inode)
{
	struct ext4_iloc iloc;

	int err = 0;
	if (handle) {
		err = ext4_get_inode_loc(inode, &iloc);
		if (!err) {
			BUFFER_TRACE(iloc.bh, "get_write_access");
			err = jbd2_journal_get_write_access(handle, iloc.bh);
			if (!err)
				err = ext4_handle_dirty_metadata(handle, NULL, iloc.bh);

			brelse(iloc.bh);
		}
	}
	ext4_std_error(inode->i_sb, err);
	return err;
}


int ext4_change_inode_journal_flag(struct inode *inode, int val)
{
	journal_t *journal;
	handle_t *handle;
	int err;
	struct ext4_sb_info *sbi = EXT4_SB(inode->i_sb);

	

	journal = EXT4_JOURNAL(inode);
	if (!journal)
		return 0;
	if (is_journal_aborted(journal))
		return -EROFS;

	
	inode_dio_wait(inode);

	
	if (val) {
		down_write(&EXT4_I(inode)->i_mmap_sem);
		err = filemap_write_and_wait(inode->i_mapping);
		if (err < 0) {
			up_write(&EXT4_I(inode)->i_mmap_sem);
			return err;
		}
	}

	percpu_down_write(&sbi->s_journal_flag_rwsem);
	jbd2_journal_lock_updates(journal);

	

	if (val)
		ext4_set_inode_flag(inode, EXT4_INODE_JOURNAL_DATA);
	else {
		err = jbd2_journal_flush(journal);
		if (err < 0) {
			jbd2_journal_unlock_updates(journal);
			percpu_up_write(&sbi->s_journal_flag_rwsem);
			return err;
		}
		ext4_clear_inode_flag(inode, EXT4_INODE_JOURNAL_DATA);
	}
	ext4_set_aops(inode);

	jbd2_journal_unlock_updates(journal);
	percpu_up_write(&sbi->s_journal_flag_rwsem);

	if (val)
		up_write(&EXT4_I(inode)->i_mmap_sem);

	

	handle = ext4_journal_start(inode, EXT4_HT_INODE, 1);
	if (IS_ERR(handle))
		return PTR_ERR(handle);

	err = ext4_mark_inode_dirty(handle, inode);
	ext4_handle_sync(handle);
	ext4_journal_stop(handle);
	ext4_std_error(inode->i_sb, err);

	return err;
}

static int ext4_bh_unmapped(handle_t *handle, struct buffer_head *bh)
{
	return !buffer_mapped(bh);
}

int ext4_page_mkwrite(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct page *page = vmf->page;
	loff_t size;
	unsigned long len;
	int ret;
	struct file *file = vma->vm_file;
	struct inode *inode = file_inode(file);
	struct address_space *mapping = inode->i_mapping;
	handle_t *handle;
	get_block_t *get_block;
	int retries = 0;

	sb_start_pagefault(inode->i_sb);
	file_update_time(vma->vm_file);

	down_read(&EXT4_I(inode)->i_mmap_sem);

	ret = ext4_convert_inline_data(inode);
	if (ret)
		goto out_ret;

	
	if (test_opt(inode->i_sb, DELALLOC) && !ext4_should_journal_data(inode) && !ext4_nonda_switch(inode->i_sb)) {

		do {
			ret = block_page_mkwrite(vma, vmf, ext4_da_get_block_prep);
		} while (ret == -ENOSPC && ext4_should_retry_alloc(inode->i_sb, &retries));
		goto out_ret;
	}

	lock_page(page);
	size = i_size_read(inode);
	
	if (page->mapping != mapping || page_offset(page) > size) {
		unlock_page(page);
		ret = VM_FAULT_NOPAGE;
		goto out;
	}

	if (page->index == size >> PAGE_SHIFT)
		len = size & ~PAGE_MASK;
	else len = PAGE_SIZE;
	
	if (page_has_buffers(page)) {
		if (!ext4_walk_page_buffers(NULL, page_buffers(page), 0, len, NULL, ext4_bh_unmapped)) {

			
			wait_for_stable_page(page);
			ret = VM_FAULT_LOCKED;
			goto out;
		}
	}
	unlock_page(page);
	
	if (ext4_should_dioread_nolock(inode))
		get_block = ext4_get_block_unwritten;
	else get_block = ext4_get_block;
retry_alloc:
	handle = ext4_journal_start(inode, EXT4_HT_WRITE_PAGE, ext4_writepage_trans_blocks(inode));
	if (IS_ERR(handle)) {
		ret = VM_FAULT_SIGBUS;
		goto out;
	}
	ret = block_page_mkwrite(vma, vmf, get_block);
	if (!ret && ext4_should_journal_data(inode)) {
		if (ext4_walk_page_buffers(handle, page_buffers(page), 0, PAGE_SIZE, NULL, do_journal_get_write_access)) {
			unlock_page(page);
			ret = VM_FAULT_SIGBUS;
			ext4_journal_stop(handle);
			goto out;
		}
		ext4_set_inode_state(inode, EXT4_STATE_JDATA);
	}
	ext4_journal_stop(handle);
	if (ret == -ENOSPC && ext4_should_retry_alloc(inode->i_sb, &retries))
		goto retry_alloc;
out_ret:
	ret = block_page_mkwrite_return(ret);
out:
	up_read(&EXT4_I(inode)->i_mmap_sem);
	sb_end_pagefault(inode->i_sb);
	return ret;
}

int ext4_filemap_fault(struct vm_fault *vmf)
{
	struct inode *inode = file_inode(vmf->vma->vm_file);
	int err;

	down_read(&EXT4_I(inode)->i_mmap_sem);
	err = filemap_fault(vmf);
	up_read(&EXT4_I(inode)->i_mmap_sem);

	return err;
}
