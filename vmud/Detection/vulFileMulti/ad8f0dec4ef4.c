


enum {DIRECT = 7, DEPTH = 4};	

typedef u32 block_t;	

static inline unsigned long block_to_cpu(block_t n)
{
	return n;
}

static inline block_t cpu_to_block(unsigned long n)
{
	return n;
}

static inline block_t *i_data(struct inode *inode)
{
	return (block_t *)minix_i(inode)->u.i2_data;
}

static int block_to_path(struct inode * inode, long block, int offsets[DEPTH])
{
	int n = 0;
	struct super_block *sb = inode->i_sb;

	if (block < 0) {
		printk("minix_bmap: block<0\n");
	} else if (block >= (minix_sb(inode->i_sb)->s_max_size/sb->s_blocksize)) {
		printk("minix_bmap: block>big\n");
	} else if (block < 7) {
		offsets[n++] = block;
	} else if ((block -= 7) < 256) {
		offsets[n++] = 7;
		offsets[n++] = block;
	} else if ((block -= 256) < 256*256) {
		offsets[n++] = 8;
		offsets[n++] = block>>8;
		offsets[n++] = block & 255;
	} else {
		block -= 256*256;
		offsets[n++] = 9;
		offsets[n++] = block>>16;
		offsets[n++] = (block>>8) & 255;
		offsets[n++] = block & 255;
	}
	return n;
}



int V2_minix_get_block(struct inode * inode, long block, struct buffer_head *bh_result, int create)
{
	return get_block(inode, block, bh_result, create);
}

void V2_minix_truncate(struct inode * inode)
{
	truncate(inode);
}

unsigned V2_minix_blocks(loff_t size, struct super_block *sb)
{
	return nblocks(size, sb);
}
