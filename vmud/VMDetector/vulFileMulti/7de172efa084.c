

































static char error_buf[1024];


static int udf_fill_super(struct super_block *, void *, int);
static void udf_put_super(struct super_block *);
static void udf_write_super(struct super_block *);
static int udf_remount_fs(struct super_block *, int *, char *);
static int udf_check_valid(struct super_block *, int, int);
static int udf_vrs(struct super_block *sb, int silent);
static int udf_load_partition(struct super_block *, kernel_lb_addr *);
static int udf_load_logicalvol(struct super_block *, struct buffer_head *, kernel_lb_addr *);
static void udf_load_logicalvolint(struct super_block *, kernel_extent_ad);
static void udf_find_anchor(struct super_block *);
static int udf_find_fileset(struct super_block *, kernel_lb_addr *, kernel_lb_addr *);
static void udf_load_pvoldesc(struct super_block *, struct buffer_head *);
static void udf_load_fileset(struct super_block *, struct buffer_head *, kernel_lb_addr *);
static void udf_load_partdesc(struct super_block *, struct buffer_head *);
static void udf_open_lvid(struct super_block *);
static void udf_close_lvid(struct super_block *);
static unsigned int udf_count_free(struct super_block *);
static int udf_statfs(struct dentry *, struct kstatfs *);


static int udf_get_sb(struct file_system_type *fs_type, int flags, const char *dev_name, void *data, struct vfsmount *mnt)
{
	return get_sb_bdev(fs_type, flags, dev_name, data, udf_fill_super, mnt);
}

static struct file_system_type udf_fstype = {
	.owner		= THIS_MODULE, .name		= "udf", .get_sb		= udf_get_sb, .kill_sb	= kill_block_super, .fs_flags	= FS_REQUIRES_DEV, };





static kmem_cache_t * udf_inode_cachep;

static struct inode *udf_alloc_inode(struct super_block *sb)
{
	struct udf_inode_info *ei;
	ei = (struct udf_inode_info *)kmem_cache_alloc(udf_inode_cachep, SLAB_KERNEL);
	if (!ei)
		return NULL;

	ei->i_unique = 0;
	ei->i_lenExtents = 0;
	ei->i_next_alloc_block = 0;
	ei->i_next_alloc_goal = 0;
	ei->i_strat4096 = 0;

	return &ei->vfs_inode;
}

static void udf_destroy_inode(struct inode *inode)
{
	kmem_cache_free(udf_inode_cachep, UDF_I(inode));
}

static void init_once(void * foo, kmem_cache_t * cachep, unsigned long flags)
{
	struct udf_inode_info *ei = (struct udf_inode_info *) foo;

	if ((flags & (SLAB_CTOR_VERIFY|SLAB_CTOR_CONSTRUCTOR)) == SLAB_CTOR_CONSTRUCTOR)
	{
		ei->i_ext.i_data = NULL;
		inode_init_once(&ei->vfs_inode);
	}
}

static int init_inodecache(void)
{
	udf_inode_cachep = kmem_cache_create("udf_inode_cache", sizeof(struct udf_inode_info), 0, (SLAB_RECLAIM_ACCOUNT| SLAB_MEM_SPREAD), init_once, NULL);



	if (udf_inode_cachep == NULL)
		return -ENOMEM;
	return 0;
}

static void destroy_inodecache(void)
{
	if (kmem_cache_destroy(udf_inode_cachep))
		printk(KERN_INFO "udf_inode_cache: not all structures were freed\n");
}


static struct super_operations udf_sb_ops = {
	.alloc_inode		= udf_alloc_inode, .destroy_inode		= udf_destroy_inode, .write_inode		= udf_write_inode, .delete_inode		= udf_delete_inode, .clear_inode		= udf_clear_inode, .put_super		= udf_put_super, .write_super		= udf_write_super, .statfs			= udf_statfs, .remount_fs		= udf_remount_fs, };









struct udf_options {
	unsigned char novrs;
	unsigned int blocksize;
	unsigned int session;
	unsigned int lastblock;
	unsigned int anchor;
	unsigned int volume;
	unsigned short partition;
	unsigned int fileset;
	unsigned int rootdir;
	unsigned int flags;
	mode_t umask;
	gid_t gid;
	uid_t uid;
	struct nls_table *nls_map;
};

static int __init init_udf_fs(void)
{
	int err;
	err = init_inodecache();
	if (err)
		goto out1;
	err = register_filesystem(&udf_fstype);
	if (err)
		goto out;
	return 0;
out:
	destroy_inodecache();
out1:
	return err;
}

static void __exit exit_udf_fs(void)
{
	unregister_filesystem(&udf_fstype);
	destroy_inodecache();
}

module_init(init_udf_fs)
module_exit(exit_udf_fs)



enum {
	Opt_novrs, Opt_nostrict, Opt_bs, Opt_unhide, Opt_undelete, Opt_noadinicb, Opt_adinicb, Opt_shortad, Opt_longad, Opt_gid, Opt_uid, Opt_umask, Opt_session, Opt_lastblock, Opt_anchor, Opt_volume, Opt_partition, Opt_fileset, Opt_rootdir, Opt_utf8, Opt_iocharset, Opt_err, Opt_uforget, Opt_uignore, Opt_gforget, Opt_gignore };






static match_table_t tokens = {
	{Opt_novrs, "novrs", {Opt_nostrict, "nostrict", {Opt_bs, "bs=%u", {Opt_unhide, "unhide", {Opt_undelete, "undelete", {Opt_noadinicb, "noadinicb", {Opt_adinicb, "adinicb", {Opt_shortad, "shortad", {Opt_longad, "longad", {Opt_uforget, "uid=forget", {Opt_uignore, "uid=ignore", {Opt_gforget, "gid=forget", {Opt_gignore, "gid=ignore", {Opt_gid, "gid=%u", {Opt_uid, "uid=%u", {Opt_umask, "umask=%o", {Opt_session, "session=%u", {Opt_lastblock, "lastblock=%u", {Opt_anchor, "anchor=%u", {Opt_volume, "volume=%u", {Opt_partition, "partition=%u", {Opt_fileset, "fileset=%u", {Opt_rootdir, "rootdir=%u", {Opt_utf8, "utf8", {Opt_iocharset, "iocharset=%s", {Opt_err, NULL}
























};

static int udf_parse_options(char *options, struct udf_options *uopt)
{
	char *p;
	int option;

	uopt->novrs = 0;
	uopt->blocksize = 2048;
	uopt->partition = 0xFFFF;
	uopt->session = 0xFFFFFFFF;
	uopt->lastblock = 0;
	uopt->anchor = 0;
	uopt->volume = 0xFFFFFFFF;
	uopt->rootdir = 0xFFFFFFFF;
	uopt->fileset = 0xFFFFFFFF;
	uopt->nls_map = NULL;

	if (!options)
		return 1;

	while ((p = strsep(&options, ",")) != NULL)
	{
		substring_t args[MAX_OPT_ARGS];
		int token;
		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token)
		{
			case Opt_novrs:
				uopt->novrs = 1;
			case Opt_bs:
				if (match_int(&args[0], &option))
					return 0;
				uopt->blocksize = option;
				break;
			case Opt_unhide:
				uopt->flags |= (1 << UDF_FLAG_UNHIDE);
				break;
			case Opt_undelete:
				uopt->flags |= (1 << UDF_FLAG_UNDELETE);
				break;
			case Opt_noadinicb:
				uopt->flags &= ~(1 << UDF_FLAG_USE_AD_IN_ICB);
				break;
			case Opt_adinicb:
				uopt->flags |= (1 << UDF_FLAG_USE_AD_IN_ICB);
				break;
			case Opt_shortad:
				uopt->flags |= (1 << UDF_FLAG_USE_SHORT_AD);
				break;
			case Opt_longad:
				uopt->flags &= ~(1 << UDF_FLAG_USE_SHORT_AD);
				break;
			case Opt_gid:
				if (match_int(args, &option))
					return 0;
				uopt->gid = option;
				break;
			case Opt_uid:
				if (match_int(args, &option))
					return 0;
				uopt->uid = option;
				break;
			case Opt_umask:
				if (match_octal(args, &option))
					return 0;
				uopt->umask = option;
				break;
			case Opt_nostrict:
				uopt->flags &= ~(1 << UDF_FLAG_STRICT);
				break;
			case Opt_session:
				if (match_int(args, &option))
					return 0;
				uopt->session = option;
				break;
			case Opt_lastblock:
				if (match_int(args, &option))
					return 0;
				uopt->lastblock = option;
				break;
			case Opt_anchor:
				if (match_int(args, &option))
					return 0;
				uopt->anchor = option;
				break;
			case Opt_volume:
				if (match_int(args, &option))
					return 0;
				uopt->volume = option;
				break;
			case Opt_partition:
				if (match_int(args, &option))
					return 0;
				uopt->partition = option;
				break;
			case Opt_fileset:
				if (match_int(args, &option))
					return 0;
				uopt->fileset = option;
				break;
			case Opt_rootdir:
				if (match_int(args, &option))
					return 0;
				uopt->rootdir = option;
				break;
			case Opt_utf8:
				uopt->flags |= (1 << UDF_FLAG_UTF8);
				break;

			case Opt_iocharset:
				uopt->nls_map = load_nls(args[0].from);
				uopt->flags |= (1 << UDF_FLAG_NLS_MAP);
				break;

			case Opt_uignore:
				uopt->flags |= (1 << UDF_FLAG_UID_IGNORE);
				break;
			case Opt_uforget:
				uopt->flags |= (1 << UDF_FLAG_UID_FORGET);
				break;
			case Opt_gignore:
			    uopt->flags |= (1 << UDF_FLAG_GID_IGNORE);
				break;
			case Opt_gforget:
			    uopt->flags |= (1 << UDF_FLAG_GID_FORGET);
				break;
			default:
				printk(KERN_ERR "udf: bad mount option \"%s\" " "or missing value\n", p);
			return 0;
		}
	}
	return 1;
}

void udf_write_super(struct super_block *sb)
{
	lock_kernel();
	if (!(sb->s_flags & MS_RDONLY))
		udf_open_lvid(sb);
	sb->s_dirt = 0;
	unlock_kernel();
}

static int udf_remount_fs(struct super_block *sb, int *flags, char *options)
{
	struct udf_options uopt;

	uopt.flags = UDF_SB(sb)->s_flags ;
	uopt.uid   = UDF_SB(sb)->s_uid ;
	uopt.gid   = UDF_SB(sb)->s_gid ;
	uopt.umask = UDF_SB(sb)->s_umask ;

	if ( !udf_parse_options(options, &uopt) )
		return -EINVAL;

	UDF_SB(sb)->s_flags = uopt.flags;
	UDF_SB(sb)->s_uid   = uopt.uid;
	UDF_SB(sb)->s_gid   = uopt.gid;
	UDF_SB(sb)->s_umask = uopt.umask;

	if (UDF_SB_LVIDBH(sb)) {
		int write_rev = le16_to_cpu(UDF_SB_LVIDIU(sb)->minUDFWriteRev);
		if (write_rev > UDF_MAX_WRITE_VERSION)
			*flags |= MS_RDONLY;
	}

	if ((*flags & MS_RDONLY) == (sb->s_flags & MS_RDONLY))
		return 0;
	if (*flags & MS_RDONLY)
		udf_close_lvid(sb);
	else udf_open_lvid(sb);

	return 0;
}


static  int udf_set_blocksize(struct super_block *sb, int bsize)
{
	if (!sb_min_blocksize(sb, bsize)) {
		udf_debug("Bad block size (%d)\n", bsize);
		printk(KERN_ERR "udf: bad block size (%d)\n", bsize);
		return 0;
	}
	return sb->s_blocksize;
}

static int udf_vrs(struct super_block *sb, int silent)
{
	struct volStructDesc *vsd = NULL;
	int sector = 32768;
	int sectorsize;
	struct buffer_head *bh = NULL;
	int iso9660=0;
	int nsr02=0;
	int nsr03=0;

	
	if (sb->s_blocksize & 511)
		return 0;

	if (sb->s_blocksize < sizeof(struct volStructDesc))
		sectorsize = sizeof(struct volStructDesc);
	else sectorsize = sb->s_blocksize;

	sector += (UDF_SB_SESSION(sb) << sb->s_blocksize_bits);

	udf_debug("Starting at sector %u (%ld byte sectors)\n", (sector >> sb->s_blocksize_bits), sb->s_blocksize);
	
	for (;!nsr02 && !nsr03; sector += sectorsize)
	{
		
		bh = udf_tread(sb, sector >> sb->s_blocksize_bits);
		if (!bh)
			break;

		
		vsd = (struct volStructDesc *)(bh->b_data + (sector & (sb->s_blocksize - 1)));

		if (vsd->stdIdent[0] == 0)
		{
			udf_release_data(bh);
			break;
		}
		else if (!strncmp(vsd->stdIdent, VSD_STD_ID_CD001, VSD_STD_ID_LEN))
		{
			iso9660 = sector;
			switch (vsd->structType)
			{
				case 0: 
					udf_debug("ISO9660 Boot Record found\n");
					break;
				case 1: 
					udf_debug("ISO9660 Primary Volume Descriptor found\n");
					break;
				case 2: 
					udf_debug("ISO9660 Supplementary Volume Descriptor found\n");
					break;
				case 3: 
					udf_debug("ISO9660 Volume Partition Descriptor found\n");
					break;
				case 255: 
					udf_debug("ISO9660 Volume Descriptor Set Terminator found\n");
					break;
				default: 
					udf_debug("ISO9660 VRS (%u) found\n", vsd->structType);
					break;
			}
		}
		else if (!strncmp(vsd->stdIdent, VSD_STD_ID_BEA01, VSD_STD_ID_LEN))
		{
		}
		else if (!strncmp(vsd->stdIdent, VSD_STD_ID_TEA01, VSD_STD_ID_LEN))
		{
			udf_release_data(bh);
			break;
		}
		else if (!strncmp(vsd->stdIdent, VSD_STD_ID_NSR02, VSD_STD_ID_LEN))
		{
			nsr02 = sector;
		}
		else if (!strncmp(vsd->stdIdent, VSD_STD_ID_NSR03, VSD_STD_ID_LEN))
		{
			nsr03 = sector;
		}
		udf_release_data(bh);
	}

	if (nsr03)
		return nsr03;
	else if (nsr02)
		return nsr02;
	else if (sector - (UDF_SB_SESSION(sb) << sb->s_blocksize_bits) == 32768)
		return -1;
	else return 0;
}


static void udf_find_anchor(struct super_block *sb)
{
	int lastblock = UDF_SB_LASTBLOCK(sb);
	struct buffer_head *bh = NULL;
	uint16_t ident;
	uint32_t location;
	int i;

	if (lastblock)
	{
		int varlastblock = udf_variable_to_fixed(lastblock);
		int last[] =  { lastblock, lastblock - 2, lastblock - 150, lastblock - 152, varlastblock, varlastblock - 2, varlastblock - 150, varlastblock - 152 };



		lastblock = 0;

		

		

		for (i = 0; !lastblock && i < ARRAY_SIZE(last); i++) {
			if (last[i] < 0 || !(bh = sb_bread(sb, last[i])))
			{
				ident = location = 0;
			}
			else {
				ident = le16_to_cpu(((tag *)bh->b_data)->tagIdent);
				location = le32_to_cpu(((tag *)bh->b_data)->tagLocation);
				udf_release_data(bh);
			}

			if (ident == TAG_IDENT_AVDP)
			{
				if (location == last[i] - UDF_SB_SESSION(sb))
				{
					lastblock = UDF_SB_ANCHOR(sb)[0] = last[i] - UDF_SB_SESSION(sb);
					UDF_SB_ANCHOR(sb)[1] = last[i] - 256 - UDF_SB_SESSION(sb);
				}
				else if (location == udf_variable_to_fixed(last[i]) - UDF_SB_SESSION(sb))
				{
					UDF_SET_FLAG(sb, UDF_FLAG_VARCONV);
					lastblock = UDF_SB_ANCHOR(sb)[0] = udf_variable_to_fixed(last[i]) - UDF_SB_SESSION(sb);
					UDF_SB_ANCHOR(sb)[1] = lastblock - 256 - UDF_SB_SESSION(sb);
				}
				else udf_debug("Anchor found at block %d, location mismatch %d.\n", last[i], location);

			}
			else if (ident == TAG_IDENT_FE || ident == TAG_IDENT_EFE)
			{
				lastblock = last[i];
				UDF_SB_ANCHOR(sb)[3] = 512;
			}
			else {
				if (last[i] < 256 || !(bh = sb_bread(sb, last[i] - 256)))
				{
					ident = location = 0;
				}
				else {
					ident = le16_to_cpu(((tag *)bh->b_data)->tagIdent);
					location = le32_to_cpu(((tag *)bh->b_data)->tagLocation);
					udf_release_data(bh);
				}
	
				if (ident == TAG_IDENT_AVDP && location == last[i] - 256 - UDF_SB_SESSION(sb))
				{
					lastblock = last[i];
					UDF_SB_ANCHOR(sb)[1] = last[i] - 256;
				}
				else {
					if (last[i] < 312 + UDF_SB_SESSION(sb) || !(bh = sb_bread(sb, last[i] - 312 - UDF_SB_SESSION(sb))))
					{
						ident = location = 0;
					}
					else {
						ident = le16_to_cpu(((tag *)bh->b_data)->tagIdent);
						location = le32_to_cpu(((tag *)bh->b_data)->tagLocation);
						udf_release_data(bh);
					}
	
					if (ident == TAG_IDENT_AVDP && location == udf_variable_to_fixed(last[i]) - 256)
					{
						UDF_SET_FLAG(sb, UDF_FLAG_VARCONV);
						lastblock = udf_variable_to_fixed(last[i]);
						UDF_SB_ANCHOR(sb)[1] = lastblock - 256;
					}
				}
			}
		}
	}

	if (!lastblock)
	{
		
		if ((bh = sb_bread(sb, 312 + UDF_SB_SESSION(sb))))
		{
			ident = le16_to_cpu(((tag *)bh->b_data)->tagIdent);
			location = le32_to_cpu(((tag *)bh->b_data)->tagLocation);
			udf_release_data(bh);

			if (ident == TAG_IDENT_AVDP && location == 256)
				UDF_SET_FLAG(sb, UDF_FLAG_VARCONV);
		}
	}

	for (i = 0; i < ARRAY_SIZE(UDF_SB_ANCHOR(sb)); i++) {
		if (UDF_SB_ANCHOR(sb)[i])
		{
			if (!(bh = udf_read_tagged(sb, UDF_SB_ANCHOR(sb)[i], UDF_SB_ANCHOR(sb)[i], &ident)))
			{
				UDF_SB_ANCHOR(sb)[i] = 0;
			}
			else {
				udf_release_data(bh);
				if ((ident != TAG_IDENT_AVDP) && (i || (ident != TAG_IDENT_FE && ident != TAG_IDENT_EFE)))
				{
					UDF_SB_ANCHOR(sb)[i] = 0;
				}
			}
		}
	}

	UDF_SB_LASTBLOCK(sb) = lastblock;
}

static int  udf_find_fileset(struct super_block *sb, kernel_lb_addr *fileset, kernel_lb_addr *root)
{
	struct buffer_head *bh = NULL;
	long lastblock;
	uint16_t ident;

	if (fileset->logicalBlockNum != 0xFFFFFFFF || fileset->partitionReferenceNum != 0xFFFF)
	{
		bh = udf_read_ptagged(sb, *fileset, 0, &ident);

		if (!bh)
			return 1;
		else if (ident != TAG_IDENT_FSD)
		{
			udf_release_data(bh);
			return 1;
		}
			
	}

	if (!bh) 
	{
		kernel_lb_addr newfileset;

		return 1;
		
		for (newfileset.partitionReferenceNum=UDF_SB_NUMPARTS(sb)-1;
			(newfileset.partitionReferenceNum != 0xFFFF && fileset->logicalBlockNum == 0xFFFFFFFF && fileset->partitionReferenceNum == 0xFFFF);

			newfileset.partitionReferenceNum--)
		{
			lastblock = UDF_SB_PARTLEN(sb, newfileset.partitionReferenceNum);
			newfileset.logicalBlockNum = 0;

			do {
				bh = udf_read_ptagged(sb, newfileset, 0, &ident);
				if (!bh)
				{
					newfileset.logicalBlockNum ++;
					continue;
				}

				switch (ident)
				{
					case TAG_IDENT_SBD:
					{
						struct spaceBitmapDesc *sp;
						sp = (struct spaceBitmapDesc *)bh->b_data;
						newfileset.logicalBlockNum += 1 + ((le32_to_cpu(sp->numOfBytes) + sizeof(struct spaceBitmapDesc) - 1)
								>> sb->s_blocksize_bits);
						udf_release_data(bh);
						break;
					}
					case TAG_IDENT_FSD:
					{
						*fileset = newfileset;
						break;
					}
					default:
					{
						newfileset.logicalBlockNum ++;
						udf_release_data(bh);
						bh = NULL;
						break;
					}
				}
			}
			while (newfileset.logicalBlockNum < lastblock && fileset->logicalBlockNum == 0xFFFFFFFF && fileset->partitionReferenceNum == 0xFFFF);

		}
	}

	if ((fileset->logicalBlockNum != 0xFFFFFFFF || fileset->partitionReferenceNum != 0xFFFF) && bh)
	{
		udf_debug("Fileset at block=%d, partition=%d\n", fileset->logicalBlockNum, fileset->partitionReferenceNum);

		UDF_SB_PARTITION(sb) = fileset->partitionReferenceNum;
		udf_load_fileset(sb, bh, root);
		udf_release_data(bh);
		return 0;
	}
	return 1;
}

static void  udf_load_pvoldesc(struct super_block *sb, struct buffer_head *bh)
{
	struct primaryVolDesc *pvoldesc;
	time_t recording;
	long recording_usec;
	struct ustr instr;
	struct ustr outstr;

	pvoldesc = (struct primaryVolDesc *)bh->b_data;

	if ( udf_stamp_to_time(&recording, &recording_usec, lets_to_cpu(pvoldesc->recordingDateAndTime)) )
	{
		kernel_timestamp ts;
		ts = lets_to_cpu(pvoldesc->recordingDateAndTime);
		udf_debug("recording time %ld/%ld, %04u/%02u/%02u %02u:%02u (%x)\n", recording, recording_usec, ts.year, ts.month, ts.day, ts.hour, ts.minute, ts.typeAndTimezone);

		UDF_SB_RECORDTIME(sb).tv_sec = recording;
		UDF_SB_RECORDTIME(sb).tv_nsec = recording_usec * 1000;
	}

	if ( !udf_build_ustr(&instr, pvoldesc->volIdent, 32) )
	{
		if (udf_CS0toUTF8(&outstr, &instr))
		{
			strncpy( UDF_SB_VOLIDENT(sb), outstr.u_name, outstr.u_len > 31 ? 31 : outstr.u_len);
			udf_debug("volIdent[] = '%s'\n", UDF_SB_VOLIDENT(sb));
		}
	}

	if ( !udf_build_ustr(&instr, pvoldesc->volSetIdent, 128) )
	{
		if (udf_CS0toUTF8(&outstr, &instr))
			udf_debug("volSetIdent[] = '%s'\n", outstr.u_name);
	}
}

static void  udf_load_fileset(struct super_block *sb, struct buffer_head *bh, kernel_lb_addr *root)
{
	struct fileSetDesc *fset;

	fset = (struct fileSetDesc *)bh->b_data;

	*root = lelb_to_cpu(fset->rootDirectoryICB.extLocation);

	UDF_SB_SERIALNUM(sb) = le16_to_cpu(fset->descTag.tagSerialNum);

	udf_debug("Rootdir at block=%d, partition=%d\n",  root->logicalBlockNum, root->partitionReferenceNum);
}

static void  udf_load_partdesc(struct super_block *sb, struct buffer_head *bh)
{
	struct partitionDesc *p;
	int i;

	p = (struct partitionDesc *)bh->b_data;

	for (i=0; i<UDF_SB_NUMPARTS(sb); i++)
	{
		udf_debug("Searching map: (%d == %d)\n",  UDF_SB_PARTMAPS(sb)[i].s_partition_num, le16_to_cpu(p->partitionNumber));
		if (UDF_SB_PARTMAPS(sb)[i].s_partition_num == le16_to_cpu(p->partitionNumber))
		{
			UDF_SB_PARTLEN(sb,i) = le32_to_cpu(p->partitionLength); 
			UDF_SB_PARTROOT(sb,i) = le32_to_cpu(p->partitionStartingLocation);
			if (le32_to_cpu(p->accessType) == PD_ACCESS_TYPE_READ_ONLY)
				UDF_SB_PARTFLAGS(sb,i) |= UDF_PART_FLAG_READ_ONLY;
			if (le32_to_cpu(p->accessType) == PD_ACCESS_TYPE_WRITE_ONCE)
				UDF_SB_PARTFLAGS(sb,i) |= UDF_PART_FLAG_WRITE_ONCE;
			if (le32_to_cpu(p->accessType) == PD_ACCESS_TYPE_REWRITABLE)
				UDF_SB_PARTFLAGS(sb,i) |= UDF_PART_FLAG_REWRITABLE;
			if (le32_to_cpu(p->accessType) == PD_ACCESS_TYPE_OVERWRITABLE)
				UDF_SB_PARTFLAGS(sb,i) |= UDF_PART_FLAG_OVERWRITABLE;

			if (!strcmp(p->partitionContents.ident, PD_PARTITION_CONTENTS_NSR02) || !strcmp(p->partitionContents.ident, PD_PARTITION_CONTENTS_NSR03))
			{
				struct partitionHeaderDesc *phd;

				phd = (struct partitionHeaderDesc *)(p->partitionContentsUse);
				if (phd->unallocSpaceTable.extLength)
				{
					kernel_lb_addr loc = { le32_to_cpu(phd->unallocSpaceTable.extPosition), i };

					UDF_SB_PARTMAPS(sb)[i].s_uspace.s_table = udf_iget(sb, loc);
					UDF_SB_PARTFLAGS(sb,i) |= UDF_PART_FLAG_UNALLOC_TABLE;
					udf_debug("unallocSpaceTable (part %d) @ %ld\n", i, UDF_SB_PARTMAPS(sb)[i].s_uspace.s_table->i_ino);
				}
				if (phd->unallocSpaceBitmap.extLength)
				{
					UDF_SB_ALLOC_BITMAP(sb, i, s_uspace);
					if (UDF_SB_PARTMAPS(sb)[i].s_uspace.s_bitmap != NULL)
					{
						UDF_SB_PARTMAPS(sb)[i].s_uspace.s_bitmap->s_extLength = le32_to_cpu(phd->unallocSpaceBitmap.extLength);
						UDF_SB_PARTMAPS(sb)[i].s_uspace.s_bitmap->s_extPosition = le32_to_cpu(phd->unallocSpaceBitmap.extPosition);
						UDF_SB_PARTFLAGS(sb,i) |= UDF_PART_FLAG_UNALLOC_BITMAP;
						udf_debug("unallocSpaceBitmap (part %d) @ %d\n", i, UDF_SB_PARTMAPS(sb)[i].s_uspace.s_bitmap->s_extPosition);
					}
				}
				if (phd->partitionIntegrityTable.extLength)
					udf_debug("partitionIntegrityTable (part %d)\n", i);
				if (phd->freedSpaceTable.extLength)
				{
					kernel_lb_addr loc = { le32_to_cpu(phd->freedSpaceTable.extPosition), i };

					UDF_SB_PARTMAPS(sb)[i].s_fspace.s_table = udf_iget(sb, loc);
					UDF_SB_PARTFLAGS(sb,i) |= UDF_PART_FLAG_FREED_TABLE;
					udf_debug("freedSpaceTable (part %d) @ %ld\n", i, UDF_SB_PARTMAPS(sb)[i].s_fspace.s_table->i_ino);
				}
				if (phd->freedSpaceBitmap.extLength)
				{
					UDF_SB_ALLOC_BITMAP(sb, i, s_fspace);
					if (UDF_SB_PARTMAPS(sb)[i].s_fspace.s_bitmap != NULL)
					{
						UDF_SB_PARTMAPS(sb)[i].s_fspace.s_bitmap->s_extLength = le32_to_cpu(phd->freedSpaceBitmap.extLength);
						UDF_SB_PARTMAPS(sb)[i].s_fspace.s_bitmap->s_extPosition = le32_to_cpu(phd->freedSpaceBitmap.extPosition);
						UDF_SB_PARTFLAGS(sb,i) |= UDF_PART_FLAG_FREED_BITMAP;
						udf_debug("freedSpaceBitmap (part %d) @ %d\n", i, UDF_SB_PARTMAPS(sb)[i].s_fspace.s_bitmap->s_extPosition);
					}
				}
			}
			break;
		}
	}
	if (i == UDF_SB_NUMPARTS(sb))
	{
		udf_debug("Partition (%d) not found in partition map\n", le16_to_cpu(p->partitionNumber));
	}
	else {
		udf_debug("Partition (%d:%d type %x) starts at physical %d, block length %d\n", le16_to_cpu(p->partitionNumber), i, UDF_SB_PARTTYPE(sb,i), UDF_SB_PARTROOT(sb,i), UDF_SB_PARTLEN(sb,i));

	}
}

static int  udf_load_logicalvol(struct super_block *sb, struct buffer_head * bh, kernel_lb_addr *fileset)
{
	struct logicalVolDesc *lvd;
	int i, j, offset;
	uint8_t type;

	lvd = (struct logicalVolDesc *)bh->b_data;

	UDF_SB_ALLOC_PARTMAPS(sb, le32_to_cpu(lvd->numPartitionMaps));

	for (i=0,offset=0;
		 i<UDF_SB_NUMPARTS(sb) && offset<le32_to_cpu(lvd->mapTableLength);
		 i++,offset+=((struct genericPartitionMap *)&(lvd->partitionMaps[offset]))->partitionMapLength)
	{
		type = ((struct genericPartitionMap *)&(lvd->partitionMaps[offset]))->partitionMapType;
		if (type == 1)
		{
			struct genericPartitionMap1 *gpm1 = (struct genericPartitionMap1 *)&(lvd->partitionMaps[offset]);
			UDF_SB_PARTTYPE(sb,i) = UDF_TYPE1_MAP15;
			UDF_SB_PARTVSN(sb,i) = le16_to_cpu(gpm1->volSeqNum);
			UDF_SB_PARTNUM(sb,i) = le16_to_cpu(gpm1->partitionNum);
			UDF_SB_PARTFUNC(sb,i) = NULL;
		}
		else if (type == 2)
		{
			struct udfPartitionMap2 *upm2 = (struct udfPartitionMap2 *)&(lvd->partitionMaps[offset]);
			if (!strncmp(upm2->partIdent.ident, UDF_ID_VIRTUAL, strlen(UDF_ID_VIRTUAL)))
			{
				if (le16_to_cpu(((__le16 *)upm2->partIdent.identSuffix)[0]) == 0x0150)
				{
					UDF_SB_PARTTYPE(sb,i) = UDF_VIRTUAL_MAP15;
					UDF_SB_PARTFUNC(sb,i) = udf_get_pblock_virt15;
				}
				else if (le16_to_cpu(((__le16 *)upm2->partIdent.identSuffix)[0]) == 0x0200)
				{
					UDF_SB_PARTTYPE(sb,i) = UDF_VIRTUAL_MAP20;
					UDF_SB_PARTFUNC(sb,i) = udf_get_pblock_virt20;
				}
			}
			else if (!strncmp(upm2->partIdent.ident, UDF_ID_SPARABLE, strlen(UDF_ID_SPARABLE)))
			{
				uint32_t loc;
				uint16_t ident;
				struct sparingTable *st;
				struct sparablePartitionMap *spm = (struct sparablePartitionMap *)&(lvd->partitionMaps[offset]);

				UDF_SB_PARTTYPE(sb,i) = UDF_SPARABLE_MAP15;
				UDF_SB_TYPESPAR(sb,i).s_packet_len = le16_to_cpu(spm->packetLength);
				for (j=0; j<spm->numSparingTables; j++)
				{
					loc = le32_to_cpu(spm->locSparingTable[j]);
					UDF_SB_TYPESPAR(sb,i).s_spar_map[j] = udf_read_tagged(sb, loc, loc, &ident);
					if (UDF_SB_TYPESPAR(sb,i).s_spar_map[j] != NULL)
					{
						st = (struct sparingTable *)UDF_SB_TYPESPAR(sb,i).s_spar_map[j]->b_data;
						if (ident != 0 || strncmp(st->sparingIdent.ident, UDF_ID_SPARING, strlen(UDF_ID_SPARING)))
						{
							udf_release_data(UDF_SB_TYPESPAR(sb,i).s_spar_map[j]);
							UDF_SB_TYPESPAR(sb,i).s_spar_map[j] = NULL;
						}
					}
				}
				UDF_SB_PARTFUNC(sb,i) = udf_get_pblock_spar15;
			}
			else {
				udf_debug("Unknown ident: %s\n", upm2->partIdent.ident);
				continue;
			}
			UDF_SB_PARTVSN(sb,i) = le16_to_cpu(upm2->volSeqNum);
			UDF_SB_PARTNUM(sb,i) = le16_to_cpu(upm2->partitionNum);
		}
		udf_debug("Partition (%d:%d) type %d on volume %d\n", i, UDF_SB_PARTNUM(sb,i), type, UDF_SB_PARTVSN(sb,i));
	}

	if (fileset)
	{
		long_ad *la = (long_ad *)&(lvd->logicalVolContentsUse[0]);

		*fileset = lelb_to_cpu(la->extLocation);
		udf_debug("FileSet found in LogicalVolDesc at block=%d, partition=%d\n", fileset->logicalBlockNum, fileset->partitionReferenceNum);

	}
	if (lvd->integritySeqExt.extLength)
		udf_load_logicalvolint(sb, leea_to_cpu(lvd->integritySeqExt));
	return 0;
}


static void udf_load_logicalvolint(struct super_block *sb, kernel_extent_ad loc)
{
	struct buffer_head *bh = NULL;
	uint16_t ident;

	while (loc.extLength > 0 && (bh = udf_read_tagged(sb, loc.extLocation, loc.extLocation, &ident)) && ident == TAG_IDENT_LVID)


	{
		UDF_SB_LVIDBH(sb) = bh;
		
		if (UDF_SB_LVID(sb)->nextIntegrityExt.extLength)
			udf_load_logicalvolint(sb, leea_to_cpu(UDF_SB_LVID(sb)->nextIntegrityExt));
		
		if (UDF_SB_LVIDBH(sb) != bh)
			udf_release_data(bh);
		loc.extLength -= sb->s_blocksize;
		loc.extLocation ++;
	}
	if (UDF_SB_LVIDBH(sb) != bh)
		udf_release_data(bh);
}


static  int udf_process_sequence(struct super_block *sb, long block, long lastblock, kernel_lb_addr *fileset)
{
	struct buffer_head *bh = NULL;
	struct udf_vds_record vds[VDS_POS_LENGTH];
	struct generic_desc *gd;
	struct volDescPtr *vdp;
	int done=0;
	int i,j;
	uint32_t vdsn;
	uint16_t ident;
	long next_s = 0, next_e = 0;

	memset(vds, 0, sizeof(struct udf_vds_record) * VDS_POS_LENGTH);

	
	for (;(!done && block <= lastblock); block++)
	{

		bh = udf_read_tagged(sb, block, block, &ident);
		if (!bh) 
			break;

		
		gd = (struct generic_desc *)bh->b_data;
		vdsn = le32_to_cpu(gd->volDescSeqNum);
		switch (ident)
		{
			case TAG_IDENT_PVD: 
				if (vdsn >= vds[VDS_POS_PRIMARY_VOL_DESC].volDescSeqNum)
				{
					vds[VDS_POS_PRIMARY_VOL_DESC].volDescSeqNum = vdsn;
					vds[VDS_POS_PRIMARY_VOL_DESC].block = block;
				}
				break;
			case TAG_IDENT_VDP: 
				if (vdsn >= vds[VDS_POS_VOL_DESC_PTR].volDescSeqNum)
				{
					vds[VDS_POS_VOL_DESC_PTR].volDescSeqNum = vdsn;
					vds[VDS_POS_VOL_DESC_PTR].block = block;

					vdp = (struct volDescPtr *)bh->b_data;
					next_s = le32_to_cpu(vdp->nextVolDescSeqExt.extLocation);
					next_e = le32_to_cpu(vdp->nextVolDescSeqExt.extLength);
					next_e = next_e >> sb->s_blocksize_bits;
					next_e += next_s;
				}
				break;
			case TAG_IDENT_IUVD: 
				if (vdsn >= vds[VDS_POS_IMP_USE_VOL_DESC].volDescSeqNum)
				{
					vds[VDS_POS_IMP_USE_VOL_DESC].volDescSeqNum = vdsn;
					vds[VDS_POS_IMP_USE_VOL_DESC].block = block;
				}
				break;
			case TAG_IDENT_PD: 
				if (!vds[VDS_POS_PARTITION_DESC].block)
					vds[VDS_POS_PARTITION_DESC].block = block;
				break;
			case TAG_IDENT_LVD: 
				if (vdsn >= vds[VDS_POS_LOGICAL_VOL_DESC].volDescSeqNum)
				{
					vds[VDS_POS_LOGICAL_VOL_DESC].volDescSeqNum = vdsn;
					vds[VDS_POS_LOGICAL_VOL_DESC].block = block;
				}
				break;
			case TAG_IDENT_USD: 
				if (vdsn >= vds[VDS_POS_UNALLOC_SPACE_DESC].volDescSeqNum)
				{
					vds[VDS_POS_UNALLOC_SPACE_DESC].volDescSeqNum = vdsn;
					vds[VDS_POS_UNALLOC_SPACE_DESC].block = block;
				}
				break;
			case TAG_IDENT_TD: 
				vds[VDS_POS_TERMINATING_DESC].block = block;
				if (next_e)
				{
					block = next_s;
					lastblock = next_e;
					next_s = next_e = 0;
				}
				else done = 1;
				break;
		}
		udf_release_data(bh);
	}
	for (i=0; i<VDS_POS_LENGTH; i++)
	{
		if (vds[i].block)
		{
			bh = udf_read_tagged(sb, vds[i].block, vds[i].block, &ident);

			if (i == VDS_POS_PRIMARY_VOL_DESC)
				udf_load_pvoldesc(sb, bh);
			else if (i == VDS_POS_LOGICAL_VOL_DESC)
				udf_load_logicalvol(sb, bh, fileset);
			else if (i == VDS_POS_PARTITION_DESC)
			{
				struct buffer_head *bh2 = NULL;
				udf_load_partdesc(sb, bh);
				for (j=vds[i].block+1; j<vds[VDS_POS_TERMINATING_DESC].block; j++)
				{
					bh2 = udf_read_tagged(sb, j, j, &ident);
					gd = (struct generic_desc *)bh2->b_data;
					if (ident == TAG_IDENT_PD)
						udf_load_partdesc(sb, bh2);
					udf_release_data(bh2);
				}
			}
			udf_release_data(bh);
		}
	}

	return 0;
}


static int udf_check_valid(struct super_block *sb, int novrs, int silent)
{
	long block;

	if (novrs)
	{
		udf_debug("Validity check skipped because of novrs option\n");
		return 0;
	}
	
	
	else if ((block = udf_vrs(sb, silent)) == -1)
	{
		udf_debug("Failed to read byte 32768. Assuming open disc. Skipping validity check\n");
		if (!UDF_SB_LASTBLOCK(sb))
			UDF_SB_LASTBLOCK(sb) = udf_get_last_block(sb);
		return 0;
	}
	else  return !block;
}

static int udf_load_partition(struct super_block *sb, kernel_lb_addr *fileset)
{
	struct anchorVolDescPtr *anchor;
	uint16_t ident;
	struct buffer_head *bh;
	long main_s, main_e, reserve_s, reserve_e;
	int i, j;

	if (!sb)
		return 1;

	for (i = 0; i < ARRAY_SIZE(UDF_SB_ANCHOR(sb)); i++) {
		if (UDF_SB_ANCHOR(sb)[i] && (bh = udf_read_tagged(sb, UDF_SB_ANCHOR(sb)[i], UDF_SB_ANCHOR(sb)[i], &ident)))
		{
			anchor = (struct anchorVolDescPtr *)bh->b_data;

			
			main_s = le32_to_cpu( anchor->mainVolDescSeqExt.extLocation );
			main_e = le32_to_cpu( anchor->mainVolDescSeqExt.extLength );
			main_e = main_e >> sb->s_blocksize_bits;
			main_e += main_s;

			
			reserve_s = le32_to_cpu(anchor->reserveVolDescSeqExt.extLocation);
			reserve_e = le32_to_cpu(anchor->reserveVolDescSeqExt.extLength);
			reserve_e = reserve_e >> sb->s_blocksize_bits;
			reserve_e += reserve_s;

			udf_release_data(bh);

			
			
			if (!(udf_process_sequence(sb, main_s, main_e, fileset) && udf_process_sequence(sb, reserve_s, reserve_e, fileset)))
			{
				break;
			}
		}
	}

	if (i == ARRAY_SIZE(UDF_SB_ANCHOR(sb))) {
		udf_debug("No Anchor block found\n");
		return 1;
	} else udf_debug("Using anchor in block %d\n", UDF_SB_ANCHOR(sb)[i]);

	for (i=0; i<UDF_SB_NUMPARTS(sb); i++)
	{
		switch UDF_SB_PARTTYPE(sb, i)
		{
			case UDF_VIRTUAL_MAP15:
			case UDF_VIRTUAL_MAP20:
			{
				kernel_lb_addr ino;

				if (!UDF_SB_LASTBLOCK(sb))
				{
					UDF_SB_LASTBLOCK(sb) = udf_get_last_block(sb);
					udf_find_anchor(sb);
				}

				if (!UDF_SB_LASTBLOCK(sb))
				{
					udf_debug("Unable to determine Lastblock (For Virtual Partition)\n");
					return 1;
				}

				for (j=0; j<UDF_SB_NUMPARTS(sb); j++)
				{
					if (j != i && UDF_SB_PARTVSN(sb,i) == UDF_SB_PARTVSN(sb,j) && UDF_SB_PARTNUM(sb,i) == UDF_SB_PARTNUM(sb,j))

					{
						ino.partitionReferenceNum = j;
						ino.logicalBlockNum = UDF_SB_LASTBLOCK(sb) - UDF_SB_PARTROOT(sb,j);
						break;
					}
				}

				if (j == UDF_SB_NUMPARTS(sb))
					return 1;

				if (!(UDF_SB_VAT(sb) = udf_iget(sb, ino)))
					return 1;

				if (UDF_SB_PARTTYPE(sb,i) == UDF_VIRTUAL_MAP15)
				{
					UDF_SB_TYPEVIRT(sb,i).s_start_offset = udf_ext0_offset(UDF_SB_VAT(sb));
					UDF_SB_TYPEVIRT(sb,i).s_num_entries = (UDF_SB_VAT(sb)->i_size - 36) >> 2;
				}
				else if (UDF_SB_PARTTYPE(sb,i) == UDF_VIRTUAL_MAP20)
				{
					struct buffer_head *bh = NULL;
					uint32_t pos;

					pos = udf_block_map(UDF_SB_VAT(sb), 0);
					bh = sb_bread(sb, pos);
					UDF_SB_TYPEVIRT(sb,i).s_start_offset = le16_to_cpu(((struct virtualAllocationTable20 *)bh->b_data + udf_ext0_offset(UDF_SB_VAT(sb)))->lengthHeader) + udf_ext0_offset(UDF_SB_VAT(sb));

					UDF_SB_TYPEVIRT(sb,i).s_num_entries = (UDF_SB_VAT(sb)->i_size - UDF_SB_TYPEVIRT(sb,i).s_start_offset) >> 2;
					udf_release_data(bh);
				}
				UDF_SB_PARTROOT(sb,i) = udf_get_pblock(sb, 0, i, 0);
				UDF_SB_PARTLEN(sb,i) = UDF_SB_PARTLEN(sb,ino.partitionReferenceNum);
			}
		}
	}
	return 0;
}

static void udf_open_lvid(struct super_block *sb)
{
	if (UDF_SB_LVIDBH(sb))
	{
		int i;
		kernel_timestamp cpu_time;

		UDF_SB_LVIDIU(sb)->impIdent.identSuffix[0] = UDF_OS_CLASS_UNIX;
		UDF_SB_LVIDIU(sb)->impIdent.identSuffix[1] = UDF_OS_ID_LINUX;
		if (udf_time_to_stamp(&cpu_time, CURRENT_TIME))
			UDF_SB_LVID(sb)->recordingDateAndTime = cpu_to_lets(cpu_time);
		UDF_SB_LVID(sb)->integrityType = LVID_INTEGRITY_TYPE_OPEN;

		UDF_SB_LVID(sb)->descTag.descCRC = cpu_to_le16(udf_crc((char *)UDF_SB_LVID(sb) + sizeof(tag), le16_to_cpu(UDF_SB_LVID(sb)->descTag.descCRCLength), 0));


		UDF_SB_LVID(sb)->descTag.tagChecksum = 0;
		for (i=0; i<16; i++)
			if (i != 4)
				UDF_SB_LVID(sb)->descTag.tagChecksum += ((uint8_t *)&(UDF_SB_LVID(sb)->descTag))[i];

		mark_buffer_dirty(UDF_SB_LVIDBH(sb));
	}
}

static void udf_close_lvid(struct super_block *sb)
{
	if (UDF_SB_LVIDBH(sb) && UDF_SB_LVID(sb)->integrityType == LVID_INTEGRITY_TYPE_OPEN)
	{
		int i;
		kernel_timestamp cpu_time;

		UDF_SB_LVIDIU(sb)->impIdent.identSuffix[0] = UDF_OS_CLASS_UNIX;
		UDF_SB_LVIDIU(sb)->impIdent.identSuffix[1] = UDF_OS_ID_LINUX;
		if (udf_time_to_stamp(&cpu_time, CURRENT_TIME))
			UDF_SB_LVID(sb)->recordingDateAndTime = cpu_to_lets(cpu_time);
		if (UDF_MAX_WRITE_VERSION > le16_to_cpu(UDF_SB_LVIDIU(sb)->maxUDFWriteRev))
			UDF_SB_LVIDIU(sb)->maxUDFWriteRev = cpu_to_le16(UDF_MAX_WRITE_VERSION);
		if (UDF_SB_UDFREV(sb) > le16_to_cpu(UDF_SB_LVIDIU(sb)->minUDFReadRev))
			UDF_SB_LVIDIU(sb)->minUDFReadRev = cpu_to_le16(UDF_SB_UDFREV(sb));
		if (UDF_SB_UDFREV(sb) > le16_to_cpu(UDF_SB_LVIDIU(sb)->minUDFWriteRev))
			UDF_SB_LVIDIU(sb)->minUDFWriteRev = cpu_to_le16(UDF_SB_UDFREV(sb));
		UDF_SB_LVID(sb)->integrityType = cpu_to_le32(LVID_INTEGRITY_TYPE_CLOSE);

		UDF_SB_LVID(sb)->descTag.descCRC = cpu_to_le16(udf_crc((char *)UDF_SB_LVID(sb) + sizeof(tag), le16_to_cpu(UDF_SB_LVID(sb)->descTag.descCRCLength), 0));


		UDF_SB_LVID(sb)->descTag.tagChecksum = 0;
		for (i=0; i<16; i++)
			if (i != 4)
				UDF_SB_LVID(sb)->descTag.tagChecksum += ((uint8_t *)&(UDF_SB_LVID(sb)->descTag))[i];

		mark_buffer_dirty(UDF_SB_LVIDBH(sb));
	}
}


static int udf_fill_super(struct super_block *sb, void *options, int silent)
{
	int i;
	struct inode *inode=NULL;
	struct udf_options uopt;
	kernel_lb_addr rootdir, fileset;
	struct udf_sb_info *sbi;

	uopt.flags = (1 << UDF_FLAG_USE_AD_IN_ICB) | (1 << UDF_FLAG_STRICT);
	uopt.uid = -1;
	uopt.gid = -1;
	uopt.umask = 0;

	sbi = kmalloc(sizeof(struct udf_sb_info), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;
	sb->s_fs_info = sbi;
	memset(UDF_SB(sb), 0x00, sizeof(struct udf_sb_info));

	mutex_init(&sbi->s_alloc_mutex);

	if (!udf_parse_options((char *)options, &uopt))
		goto error_out;

	if (uopt.flags & (1 << UDF_FLAG_UTF8) && uopt.flags & (1 << UDF_FLAG_NLS_MAP))
	{
		udf_error(sb, "udf_read_super", "utf8 cannot be combined with iocharset\n");
		goto error_out;
	}

	if ((uopt.flags & (1 << UDF_FLAG_NLS_MAP)) && !uopt.nls_map)
	{
		uopt.nls_map = load_nls_default();
		if (!uopt.nls_map)
			uopt.flags &= ~(1 << UDF_FLAG_NLS_MAP);
		else udf_debug("Using default NLS map\n");
	}

	if (!(uopt.flags & (1 << UDF_FLAG_NLS_MAP)))
		uopt.flags |= (1 << UDF_FLAG_UTF8);

	fileset.logicalBlockNum = 0xFFFFFFFF;
	fileset.partitionReferenceNum = 0xFFFF;

	UDF_SB(sb)->s_flags = uopt.flags;
	UDF_SB(sb)->s_uid = uopt.uid;
	UDF_SB(sb)->s_gid = uopt.gid;
	UDF_SB(sb)->s_umask = uopt.umask;
	UDF_SB(sb)->s_nls_map = uopt.nls_map;

	
	if (!udf_set_blocksize(sb, uopt.blocksize))
		goto error_out;

	if ( uopt.session == 0xFFFFFFFF )
		UDF_SB_SESSION(sb) = udf_get_last_session(sb);
	else UDF_SB_SESSION(sb) = uopt.session;

	udf_debug("Multi-session=%d\n", UDF_SB_SESSION(sb));

	UDF_SB_LASTBLOCK(sb) = uopt.lastblock;
	UDF_SB_ANCHOR(sb)[0] = UDF_SB_ANCHOR(sb)[1] = 0;
	UDF_SB_ANCHOR(sb)[2] = uopt.anchor;
	UDF_SB_ANCHOR(sb)[3] = 256;

	if (udf_check_valid(sb, uopt.novrs, silent)) 
	{
		printk("UDF-fs: No VRS found\n");
 		goto error_out;
	}

	udf_find_anchor(sb);

	
	sb->s_op = &udf_sb_ops;
	sb->dq_op = NULL;
	sb->s_dirt = 0;
	sb->s_magic = UDF_SUPER_MAGIC;
	sb->s_time_gran = 1000;

	if (udf_load_partition(sb, &fileset))
	{
		printk("UDF-fs: No partition found (1)\n");
		goto error_out;
	}

	udf_debug("Lastblock=%d\n", UDF_SB_LASTBLOCK(sb));

	if ( UDF_SB_LVIDBH(sb) )
	{
		uint16_t minUDFReadRev = le16_to_cpu(UDF_SB_LVIDIU(sb)->minUDFReadRev);
		uint16_t minUDFWriteRev = le16_to_cpu(UDF_SB_LVIDIU(sb)->minUDFWriteRev);
		

		if (minUDFReadRev > UDF_MAX_READ_VERSION)
		{
			printk("UDF-fs: minUDFReadRev=%x (max is %x)\n", le16_to_cpu(UDF_SB_LVIDIU(sb)->minUDFReadRev), UDF_MAX_READ_VERSION);

			goto error_out;
		}
		else if (minUDFWriteRev > UDF_MAX_WRITE_VERSION)
		{
			sb->s_flags |= MS_RDONLY;
		}

		UDF_SB_UDFREV(sb) = minUDFWriteRev;

		if (minUDFReadRev >= UDF_VERS_USE_EXTENDED_FE)
			UDF_SET_FLAG(sb, UDF_FLAG_USE_EXTENDED_FE);
		if (minUDFReadRev >= UDF_VERS_USE_STREAMS)
			UDF_SET_FLAG(sb, UDF_FLAG_USE_STREAMS);
	}

	if ( !UDF_SB_NUMPARTS(sb) )
	{
		printk("UDF-fs: No partition found (2)\n");
		goto error_out;
	}

	if ( udf_find_fileset(sb, &fileset, &rootdir) )
	{
		printk("UDF-fs: No fileset found\n");
		goto error_out;
	}

	if (!silent)
	{
		kernel_timestamp ts;
		udf_time_to_stamp(&ts, UDF_SB_RECORDTIME(sb));
		udf_info("UDF %s (%s) Mounting volume '%s', timestamp %04u/%02u/%02u %02u:%02u (%x)\n", UDFFS_VERSION, UDFFS_DATE, UDF_SB_VOLIDENT(sb), ts.year, ts.month, ts.day, ts.hour, ts.minute, ts.typeAndTimezone);


	}
	if (!(sb->s_flags & MS_RDONLY))
		udf_open_lvid(sb);

	
	
	
	inode = udf_iget(sb, rootdir); 
	if (!inode)
	{
		printk("UDF-fs: Error in udf_iget, block=%d, partition=%d\n", rootdir.logicalBlockNum, rootdir.partitionReferenceNum);
		goto error_out;
	}

	
	sb->s_root = d_alloc_root(inode);
	if (!sb->s_root)
	{
		printk("UDF-fs: Couldn't allocate root dentry\n");
		iput(inode);
		goto error_out;
	}
	sb->s_maxbytes = MAX_LFS_FILESIZE;
	return 0;

error_out:
	if (UDF_SB_VAT(sb))
		iput(UDF_SB_VAT(sb));
	if (UDF_SB_NUMPARTS(sb))
	{
		if (UDF_SB_PARTFLAGS(sb, UDF_SB_PARTITION(sb)) & UDF_PART_FLAG_UNALLOC_TABLE)
			iput(UDF_SB_PARTMAPS(sb)[UDF_SB_PARTITION(sb)].s_uspace.s_table);
		if (UDF_SB_PARTFLAGS(sb, UDF_SB_PARTITION(sb)) & UDF_PART_FLAG_FREED_TABLE)
			iput(UDF_SB_PARTMAPS(sb)[UDF_SB_PARTITION(sb)].s_fspace.s_table);
		if (UDF_SB_PARTFLAGS(sb, UDF_SB_PARTITION(sb)) & UDF_PART_FLAG_UNALLOC_BITMAP)
			UDF_SB_FREE_BITMAP(sb,UDF_SB_PARTITION(sb),s_uspace);
		if (UDF_SB_PARTFLAGS(sb, UDF_SB_PARTITION(sb)) & UDF_PART_FLAG_FREED_BITMAP)
			UDF_SB_FREE_BITMAP(sb,UDF_SB_PARTITION(sb),s_fspace);
		if (UDF_SB_PARTTYPE(sb, UDF_SB_PARTITION(sb)) == UDF_SPARABLE_MAP15)
		{
			for (i=0; i<4; i++)
				udf_release_data(UDF_SB_TYPESPAR(sb, UDF_SB_PARTITION(sb)).s_spar_map[i]);
		}
	}

	if (UDF_QUERY_FLAG(sb, UDF_FLAG_NLS_MAP))
		unload_nls(UDF_SB(sb)->s_nls_map);

	if (!(sb->s_flags & MS_RDONLY))
		udf_close_lvid(sb);
	udf_release_data(UDF_SB_LVIDBH(sb));
	UDF_SB_FREE(sb);
	kfree(sbi);
	sb->s_fs_info = NULL;
	return -EINVAL;
}

void udf_error(struct super_block *sb, const char *function, const char *fmt, ...)
{
	va_list args;

	if (!(sb->s_flags & MS_RDONLY))
	{
		
		sb->s_dirt = 1;
	}
	va_start(args, fmt);
	vsprintf(error_buf, fmt, args);
	va_end(args);
	printk (KERN_CRIT "UDF-fs error (device %s): %s: %s\n", sb->s_id, function, error_buf);
}

void udf_warning(struct super_block *sb, const char *function, const char *fmt, ...)
{
	va_list args;

	va_start (args, fmt);
	vsprintf(error_buf, fmt, args);
	va_end(args);
	printk(KERN_WARNING "UDF-fs warning (device %s): %s: %s\n", sb->s_id, function, error_buf);
}


static void udf_put_super(struct super_block *sb)
{
	int i;

	if (UDF_SB_VAT(sb))
		iput(UDF_SB_VAT(sb));
	if (UDF_SB_NUMPARTS(sb))
	{
		if (UDF_SB_PARTFLAGS(sb, UDF_SB_PARTITION(sb)) & UDF_PART_FLAG_UNALLOC_TABLE)
			iput(UDF_SB_PARTMAPS(sb)[UDF_SB_PARTITION(sb)].s_uspace.s_table);
		if (UDF_SB_PARTFLAGS(sb, UDF_SB_PARTITION(sb)) & UDF_PART_FLAG_FREED_TABLE)
			iput(UDF_SB_PARTMAPS(sb)[UDF_SB_PARTITION(sb)].s_fspace.s_table);
		if (UDF_SB_PARTFLAGS(sb, UDF_SB_PARTITION(sb)) & UDF_PART_FLAG_UNALLOC_BITMAP)
			UDF_SB_FREE_BITMAP(sb,UDF_SB_PARTITION(sb),s_uspace);
		if (UDF_SB_PARTFLAGS(sb, UDF_SB_PARTITION(sb)) & UDF_PART_FLAG_FREED_BITMAP)
			UDF_SB_FREE_BITMAP(sb,UDF_SB_PARTITION(sb),s_fspace);
		if (UDF_SB_PARTTYPE(sb, UDF_SB_PARTITION(sb)) == UDF_SPARABLE_MAP15)
		{
			for (i=0; i<4; i++)
				udf_release_data(UDF_SB_TYPESPAR(sb, UDF_SB_PARTITION(sb)).s_spar_map[i]);
		}
	}

	if (UDF_QUERY_FLAG(sb, UDF_FLAG_NLS_MAP))
		unload_nls(UDF_SB(sb)->s_nls_map);

	if (!(sb->s_flags & MS_RDONLY))
		udf_close_lvid(sb);
	udf_release_data(UDF_SB_LVIDBH(sb));
	UDF_SB_FREE(sb);
	kfree(sb->s_fs_info);
	sb->s_fs_info = NULL;
}


static int udf_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;

	buf->f_type = UDF_SUPER_MAGIC;
	buf->f_bsize = sb->s_blocksize;
	buf->f_blocks = UDF_SB_PARTLEN(sb, UDF_SB_PARTITION(sb));
	buf->f_bfree = udf_count_free(sb);
	buf->f_bavail = buf->f_bfree;
	buf->f_files = (UDF_SB_LVIDBH(sb) ? (le32_to_cpu(UDF_SB_LVIDIU(sb)->numFiles) + le32_to_cpu(UDF_SB_LVIDIU(sb)->numDirs)) : 0) + buf->f_bfree;

	buf->f_ffree = buf->f_bfree;
	
	buf->f_namelen = UDF_NAME_LEN-2;

	return 0;
}

static unsigned char udf_bitmap_lookup[16] = {
	0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4 };

static unsigned int udf_count_free_bitmap(struct super_block *sb, struct udf_bitmap *bitmap)
{
	struct buffer_head *bh = NULL;
	unsigned int accum = 0;
	int index;
	int block = 0, newblock;
	kernel_lb_addr loc;
	uint32_t bytes;
	uint8_t value;
	uint8_t *ptr;
	uint16_t ident;
	struct spaceBitmapDesc *bm;

	lock_kernel();

	loc.logicalBlockNum = bitmap->s_extPosition;
	loc.partitionReferenceNum = UDF_SB_PARTITION(sb);
	bh = udf_read_ptagged(sb, loc, 0, &ident);

	if (!bh)
	{
		printk(KERN_ERR "udf: udf_count_free failed\n");
		goto out;
	}
	else if (ident != TAG_IDENT_SBD)
	{
		udf_release_data(bh);
		printk(KERN_ERR "udf: udf_count_free failed\n");
		goto out;
	}

	bm = (struct spaceBitmapDesc *)bh->b_data;
	bytes = le32_to_cpu(bm->numOfBytes);
	index = sizeof(struct spaceBitmapDesc); 
	ptr = (uint8_t *)bh->b_data;

	while ( bytes > 0 )
	{
		while ((bytes > 0) && (index < sb->s_blocksize))
		{
			value = ptr[index];
			accum += udf_bitmap_lookup[ value & 0x0f ];
			accum += udf_bitmap_lookup[ value >> 4 ];
			index++;
			bytes--;
		}
		if ( bytes )
		{
			udf_release_data(bh);
			newblock = udf_get_lb_pblock(sb, loc, ++block);
			bh = udf_tread(sb, newblock);
			if (!bh)
			{
				udf_debug("read failed\n");
				goto out;
			}
			index = 0;
			ptr = (uint8_t *)bh->b_data;
		}
	}
	udf_release_data(bh);

out:
	unlock_kernel();

	return accum;
}

static unsigned int udf_count_free_table(struct super_block *sb, struct inode * table)
{
	unsigned int accum = 0;
	uint32_t extoffset, elen;
	kernel_lb_addr bloc, eloc;
	int8_t etype;
	struct buffer_head *bh = NULL;

	lock_kernel();

	bloc = UDF_I_LOCATION(table);
	extoffset = sizeof(struct unallocSpaceEntry);

	while ((etype = udf_next_aext(table, &bloc, &extoffset, &eloc, &elen, &bh, 1)) != -1)
	{
		accum += (elen >> table->i_sb->s_blocksize_bits);
	}
	udf_release_data(bh);

	unlock_kernel();

	return accum;
}
	
static unsigned int udf_count_free(struct super_block *sb)
{
	unsigned int accum = 0;

	if (UDF_SB_LVIDBH(sb))
	{
		if (le32_to_cpu(UDF_SB_LVID(sb)->numOfPartitions) > UDF_SB_PARTITION(sb))
		{
			accum = le32_to_cpu(UDF_SB_LVID(sb)->freeSpaceTable[UDF_SB_PARTITION(sb)]);

			if (accum == 0xFFFFFFFF)
				accum = 0;
		}
	}

	if (accum)
		return accum;

	if (UDF_SB_PARTFLAGS(sb,UDF_SB_PARTITION(sb)) & UDF_PART_FLAG_UNALLOC_BITMAP)
	{
		accum += udf_count_free_bitmap(sb, UDF_SB_PARTMAPS(sb)[UDF_SB_PARTITION(sb)].s_uspace.s_bitmap);
	}
	if (UDF_SB_PARTFLAGS(sb,UDF_SB_PARTITION(sb)) & UDF_PART_FLAG_FREED_BITMAP)
	{
		accum += udf_count_free_bitmap(sb, UDF_SB_PARTMAPS(sb)[UDF_SB_PARTITION(sb)].s_fspace.s_bitmap);
	}
	if (accum)
		return accum;

	if (UDF_SB_PARTFLAGS(sb,UDF_SB_PARTITION(sb)) & UDF_PART_FLAG_UNALLOC_TABLE)
	{
		accum += udf_count_free_table(sb, UDF_SB_PARTMAPS(sb)[UDF_SB_PARTITION(sb)].s_uspace.s_table);
	}
	if (UDF_SB_PARTFLAGS(sb,UDF_SB_PARTITION(sb)) & UDF_PART_FLAG_FREED_TABLE)
	{
		accum += udf_count_free_table(sb, UDF_SB_PARTMAPS(sb)[UDF_SB_PARTITION(sb)].s_fspace.s_table);
	}

	return accum;
}
