





static int	zread(void *, char *, int);












             









typedef long	code_int;
typedef long	count_int;
typedef u_char	char_type;

static char_type magic_header[] = {'\037', '\235';

static char_type rmask[9] = {0x00, 0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7f, 0xff};


off_t total_compressed_bytes;
size_t compressed_prelen;
char *compressed_pre;

struct s_zstate {
	FILE *zs_fp;			
	char zs_mode;			
	enum {
		S_START, S_MIDDLE, S_EOF } zs_state;
	int zs_n_bits;			
	int zs_maxbits;			
	code_int zs_maxcode;		
	code_int zs_maxmaxcode;		
	count_int zs_htab [HSIZE];
	u_short zs_codetab [HSIZE];
	code_int zs_hsize;		
	code_int zs_free_ent;		
	
	int zs_block_compress;
	int zs_clear_flg;
	long zs_ratio;
	count_int zs_checkpoint;
	int zs_offset;
	long zs_in_count;		
	long zs_bytes_out;		
	long zs_out_count;		
	char_type zs_buf[BITS];
	union {
		struct {
			long zs_fcode;
			code_int zs_ent;
			code_int zs_hsize_reg;
			int zs_hshift;
		} w;			
		struct {
			char_type *zs_stackp;
			int zs_finchar;
			code_int zs_code, zs_oldcode, zs_incode;
			int zs_roffset, zs_size;
			char_type zs_gbuf[BITS];
		} r;			
	} u;
};

static code_int	getcode(struct s_zstate *zs);

static off_t zuncompress(FILE *in, FILE *out, char *pre, size_t prelen, off_t *compressed_bytes)

{
	off_t bin, bout = 0;
	char *buf;

	buf = malloc(BUFSIZE);
	if (buf == NULL)
		return -1;

	
	compressed_prelen = prelen;
	if (prelen != 0)
		compressed_pre = pre;
	else compressed_pre = NULL;

	while ((bin = fread(buf, 1, sizeof(buf), in)) != 0) {
		if (tflag == 0 && (off_t)fwrite(buf, 1, bin, out) != bin) {
			free(buf);
			return -1;
		}
		bout += bin;
	}

	if (compressed_bytes)
		*compressed_bytes = total_compressed_bytes;

	free(buf);
	return bout;
}

static int zclose(void *zs)
{
	free(zs);
	
	return 0;
}

FILE * zdopen(int fd)
{
	struct s_zstate *zs;

	if ((zs = calloc(1, sizeof(struct s_zstate))) == NULL)
		return (NULL);

	zs->zs_state = S_START;

	
	zs->zs_hsize = HSIZE;			
	zs->zs_free_ent = 0;			
	zs->zs_block_compress = BLOCK_MASK;
	zs->zs_clear_flg = 0;			
	zs->zs_ratio = 0;
	zs->zs_checkpoint = CHECK_GAP;
	zs->zs_in_count = 1;			
	zs->zs_out_count = 0;			
	zs->u.r.zs_roffset = 0;
	zs->u.r.zs_size = 0;

	
	if ((zs->zs_fp = fdopen(fd, "r")) == NULL) {
		free(zs);
		return NULL;
	}

	return funopen(zs, zread, NULL, NULL, zclose);
}


static int zread(void *cookie, char *rbp, int num)
{
	u_int count, i;
	struct s_zstate *zs;
	u_char *bp, header[3];

	if (num == 0)
		return (0);

	zs = cookie;
	count = num;
	bp = (u_char *)rbp;
	switch (zs->zs_state) {
	case S_START:
		zs->zs_state = S_MIDDLE;
		break;
	case S_MIDDLE:
		goto middle;
	case S_EOF:
		goto eof;
	}

	
	for (i = 0; i < 3 && compressed_prelen; i++, compressed_prelen--)  
		header[i] = *compressed_pre++;

	if (fread(header + i, 1, sizeof(header) - i, zs->zs_fp) != sizeof(header) - i || memcmp(header, magic_header, sizeof(magic_header)) != 0) {

		errno = EFTYPE;
		return (-1);
	}
	total_compressed_bytes = 0;
	zs->zs_maxbits = header[2];	
	zs->zs_block_compress = zs->zs_maxbits & BLOCK_MASK;
	zs->zs_maxbits &= BIT_MASK;
	zs->zs_maxmaxcode = 1L << zs->zs_maxbits;
	if (zs->zs_maxbits > BITS) {
		errno = EFTYPE;
		return (-1);
	}
	
	zs->zs_maxcode = MAXCODE(zs->zs_n_bits = INIT_BITS);
	for (zs->u.r.zs_code = 255; zs->u.r.zs_code >= 0; zs->u.r.zs_code--) {
		tab_prefixof(zs->u.r.zs_code) = 0;
		tab_suffixof(zs->u.r.zs_code) = (char_type) zs->u.r.zs_code;
	}
	zs->zs_free_ent = zs->zs_block_compress ? FIRST : 256;

	zs->u.r.zs_finchar = zs->u.r.zs_oldcode = getcode(zs);
	if (zs->u.r.zs_oldcode == -1)	
		return (0);	

	
	*bp++ = (u_char)zs->u.r.zs_finchar;
	count--;
	zs->u.r.zs_stackp = de_stack;

	while ((zs->u.r.zs_code = getcode(zs)) > -1) {

		if ((zs->u.r.zs_code == CLEAR) && zs->zs_block_compress) {
			for (zs->u.r.zs_code = 255; zs->u.r.zs_code >= 0;
			    zs->u.r.zs_code--)
				tab_prefixof(zs->u.r.zs_code) = 0;
			zs->zs_clear_flg = 1;
			zs->zs_free_ent = FIRST - 1;
			if ((zs->u.r.zs_code = getcode(zs)) == -1)	
				break;
		}
		zs->u.r.zs_incode = zs->u.r.zs_code;

		
		if (zs->u.r.zs_code >= zs->zs_free_ent) {
			*zs->u.r.zs_stackp++ = zs->u.r.zs_finchar;
			zs->u.r.zs_code = zs->u.r.zs_oldcode;
		}

		
		while (zs->u.r.zs_code >= 256) {
			*zs->u.r.zs_stackp++ = tab_suffixof(zs->u.r.zs_code);
			zs->u.r.zs_code = tab_prefixof(zs->u.r.zs_code);
		}
		*zs->u.r.zs_stackp++ = zs->u.r.zs_finchar = tab_suffixof(zs->u.r.zs_code);

		
middle:		do {
			if (count-- == 0)
				return (num);
			*bp++ = *--zs->u.r.zs_stackp;
		} while (zs->u.r.zs_stackp > de_stack);

		
		if ((zs->u.r.zs_code = zs->zs_free_ent) < zs->zs_maxmaxcode) {
			tab_prefixof(zs->u.r.zs_code) = (u_short) zs->u.r.zs_oldcode;
			tab_suffixof(zs->u.r.zs_code) = zs->u.r.zs_finchar;
			zs->zs_free_ent = zs->u.r.zs_code + 1;
		}

		
		zs->u.r.zs_oldcode = zs->u.r.zs_incode;
	}
	zs->zs_state = S_EOF;
eof:	return (num - count);
}


static code_int getcode(struct s_zstate *zs)
{
	code_int gcode;
	int r_off, bits, i;
	char_type *bp;

	bp = zs->u.r.zs_gbuf;
	if (zs->zs_clear_flg > 0 || zs->u.r.zs_roffset >= zs->u.r.zs_size || zs->zs_free_ent > zs->zs_maxcode) {
		
		if (zs->zs_free_ent > zs->zs_maxcode) {
			zs->zs_n_bits++;
			if (zs->zs_n_bits == zs->zs_maxbits)	
				zs->zs_maxcode = zs->zs_maxmaxcode;
			else zs->zs_maxcode = MAXCODE(zs->zs_n_bits);
		}
		if (zs->zs_clear_flg > 0) {
			zs->zs_maxcode = MAXCODE(zs->zs_n_bits = INIT_BITS);
			zs->zs_clear_flg = 0;
		}
		
		for (i = 0; i < zs->zs_n_bits && compressed_prelen; i++, compressed_prelen--)  
			zs->u.r.zs_gbuf[i] = *compressed_pre++;
		zs->u.r.zs_size = fread(zs->u.r.zs_gbuf + i, 1, zs->zs_n_bits - i, zs->zs_fp);
		zs->u.r.zs_size += i;
		if (zs->u.r.zs_size <= 0)			
			return (-1);
		zs->u.r.zs_roffset = 0;

		total_compressed_bytes += zs->u.r.zs_size;

		
		zs->u.r.zs_size = (zs->u.r.zs_size << 3) - (zs->zs_n_bits - 1);
	}
	r_off = zs->u.r.zs_roffset;
	bits = zs->zs_n_bits;

	
	bp += (r_off >> 3);
	r_off &= 7;

	
	gcode = (*bp++ >> r_off);
	bits -= (8 - r_off);
	r_off = 8 - r_off;	

	
	if (bits >= 8) {
		gcode |= *bp++ << r_off;
		r_off += 8;
		bits -= 8;
	}

	
	gcode |= (*bp & rmask[bits]) << r_off;
	zs->u.r.zs_roffset += zs->zs_n_bits;

	return (gcode);
}

