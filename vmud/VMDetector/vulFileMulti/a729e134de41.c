


static char sccsid[] = "@(#)zopen.c	8.1 (Berkeley) 6/27/93";



__FBSDID("$FreeBSD$");



















typedef long code_int;
typedef long count_int;

typedef u_char char_type;
static char_type magic_header[] = {'\037', '\235';









struct s_zstate {
	FILE *zs_fp;			
	char zs_mode;			
	enum {
		S_START, S_MIDDLE, S_EOF } zs_state;
	u_int zs_n_bits;		
	u_int zs_maxbits;		
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
	u_int zs_offset;
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


















































static int	cl_block(struct s_zstate *);
static void	cl_hash(struct s_zstate *, count_int);
static code_int	getcode(struct s_zstate *);
static int	output(struct s_zstate *, code_int);
static int	zclose(void *);
static int	zread(void *, char *, int);
static int	zwrite(void *, const char *, int);




static int zwrite(void *cookie, const char *wbp, int num)
{
	code_int i;
	int c, disp;
	struct s_zstate *zs;
	const u_char *bp;
	u_char tmp;
	int count;

	if (num == 0)
		return (0);

	zs = cookie;
	count = num;
	bp = (const u_char *)wbp;
	if (state == S_MIDDLE)
		goto middle;
	state = S_MIDDLE;

	maxmaxcode = 1L << maxbits;
	if (fwrite(magic_header, sizeof(char), sizeof(magic_header), fp) != sizeof(magic_header))
		return (-1);
	tmp = (u_char)((maxbits) | block_compress);
	if (fwrite(&tmp, sizeof(char), sizeof(tmp), fp) != sizeof(tmp))
		return (-1);

	offset = 0;
	bytes_out = 3;		
	out_count = 0;
	clear_flg = 0;
	ratio = 0;
	in_count = 1;
	checkpoint = CHECK_GAP;
	maxcode = MAXCODE(n_bits = INIT_BITS);
	free_ent = ((block_compress) ? FIRST : 256);

	ent = *bp++;
	--count;

	hshift = 0;
	for (fcode = (long)hsize; fcode < 65536L; fcode *= 2L)
		hshift++;
	hshift = 8 - hshift;	

	hsize_reg = hsize;
	cl_hash(zs, (count_int)hsize_reg);	

middle:	for (i = 0; count--;) {
		c = *bp++;
		in_count++;
		fcode = (long)(((long)c << maxbits) + ent);
		i = ((c << hshift) ^ ent);	

		if (htabof(i) == fcode) {
			ent = codetabof(i);
			continue;
		} else if ((long)htabof(i) < 0)	
			goto nomatch;
		disp = hsize_reg - i;	
		if (i == 0)
			disp = 1;
probe:		if ((i -= disp) < 0)
			i += hsize_reg;

		if (htabof(i) == fcode) {
			ent = codetabof(i);
			continue;
		}
		if ((long)htabof(i) >= 0)
			goto probe;
nomatch:	if (output(zs, (code_int) ent) == -1)
			return (-1);
		out_count++;
		ent = c;
		if (free_ent < maxmaxcode) {
			codetabof(i) = free_ent++;	
			htabof(i) = fcode;
		} else if ((count_int)in_count >= checkpoint && block_compress) {
			if (cl_block(zs) == -1)
				return (-1);
		}
	}
	return (num);
}

static int zclose(void *cookie)
{
	struct s_zstate *zs;
	int rval;

	zs = cookie;
	if (zmode == 'w') {		
		if (output(zs, (code_int) ent) == -1) {
			(void)fclose(fp);
			free(zs);
			return (-1);
		}
		out_count++;
		if (output(zs, (code_int) - 1) == -1) {
			(void)fclose(fp);
			free(zs);
			return (-1);
		}
	}
	rval = fclose(fp) == EOF ? -1 : 0;
	free(zs);
	return (rval);
}



static char_type lmask[9] = {0xff, 0xfe, 0xfc, 0xf8, 0xf0, 0xe0, 0xc0, 0x80, 0x00};
static char_type rmask[9] = {0x00, 0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7f, 0xff};

static int output(struct s_zstate *zs, code_int ocode)
{
	int r_off;
	u_int bits;
	char_type *bp;

	r_off = offset;
	bits = n_bits;
	bp = buf;
	if (ocode >= 0) {
		
		bp += (r_off >> 3);
		r_off &= 7;
		
		*bp = (*bp & rmask[r_off]) | ((ocode << r_off) & lmask[r_off]);
		bp++;
		bits -= (8 - r_off);
		ocode >>= 8 - r_off;
		
		if (bits >= 8) {
			*bp++ = ocode;
			ocode >>= 8;
			bits -= 8;
		}
		
		if (bits)
			*bp = ocode;
		offset += n_bits;
		if (offset == (n_bits << 3)) {
			bp = buf;
			bits = n_bits;
			bytes_out += bits;
			if (fwrite(bp, sizeof(char), bits, fp) != bits)
				return (-1);
			bp += bits;
			bits = 0;
			offset = 0;
		}
		
		if (free_ent > maxcode || (clear_flg > 0)) {
		       
			if (offset > 0) {
				if (fwrite(buf, 1, n_bits, fp) != n_bits)
					return (-1);
				bytes_out += n_bits;
			}
			offset = 0;

			if (clear_flg) {
				maxcode = MAXCODE(n_bits = INIT_BITS);
				clear_flg = 0;
			} else {
				n_bits++;
				if (n_bits == maxbits)
					maxcode = maxmaxcode;
				else maxcode = MAXCODE(n_bits);
			}
		}
	} else {
		
		if (offset > 0) {
			offset = (offset + 7) / 8;
			if (fwrite(buf, 1, offset, fp) != offset)
				return (-1);
			bytes_out += offset;
		}
		offset = 0;
	}
	return (0);
}


static int zread(void *cookie, char *rbp, int num)
{
	u_int count;
	struct s_zstate *zs;
	u_char *bp, header[3];

	if (num == 0)
		return (0);

	zs = cookie;
	count = num;
	bp = (u_char *)rbp;
	switch (state) {
	case S_START:
		state = S_MIDDLE;
		break;
	case S_MIDDLE:
		goto middle;
	case S_EOF:
		goto eof;
	}

	
	if (fread(header, sizeof(char), sizeof(header), fp) != sizeof(header) || memcmp(header, magic_header, sizeof(magic_header)) != 0) {

		errno = EFTYPE;
		return (-1);
	}
	maxbits = header[2];	
	block_compress = maxbits & BLOCK_MASK;
	maxbits &= BIT_MASK;
	maxmaxcode = 1L << maxbits;
	if (maxbits > BITS) {
		errno = EFTYPE;
		return (-1);
	}
	
	maxcode = MAXCODE(n_bits = INIT_BITS);
	for (code = 255; code >= 0; code--) {
		tab_prefixof(code) = 0;
		tab_suffixof(code) = (char_type) code;
	}
	free_ent = block_compress ? FIRST : 256;

	finchar = oldcode = getcode(zs);
	if (oldcode == -1)	
		return (0);	

	
	*bp++ = (u_char)finchar;
	count--;
	stackp = de_stack;

	while ((code = getcode(zs)) > -1) {

		if ((code == CLEAR) && block_compress) {
			for (code = 255; code >= 0; code--)
				tab_prefixof(code) = 0;
			clear_flg = 1;
			free_ent = FIRST - 1;
			if ((code = getcode(zs)) == -1)	
				break;
		}
		incode = code;

		
		if (code >= free_ent) {
			*stackp++ = finchar;
			code = oldcode;
		}

		
		while (code >= 256) {
			*stackp++ = tab_suffixof(code);
			code = tab_prefixof(code);
		}
		*stackp++ = finchar = tab_suffixof(code);

		
middle:		do {
			if (count-- == 0)
				return (num);
			*bp++ = *--stackp;
		} while (stackp > de_stack);

		
		if ((code = free_ent) < maxmaxcode) {
			tab_prefixof(code) = (u_short) oldcode;
			tab_suffixof(code) = finchar;
			free_ent = code + 1;
		}

		
		oldcode = incode;
	}
	state = S_EOF;
eof:	return (num - count);
}


static code_int getcode(struct s_zstate *zs)
{
	code_int gcode;
	int r_off, bits;
	char_type *bp;

	bp = gbuf;
	if (clear_flg > 0 || roffset >= size || free_ent > maxcode) {
		
		if (free_ent > maxcode) {
			n_bits++;
			if (n_bits == maxbits)	
				maxcode = maxmaxcode;
			else maxcode = MAXCODE(n_bits);
		}
		if (clear_flg > 0) {
			maxcode = MAXCODE(n_bits = INIT_BITS);
			clear_flg = 0;
		}
		size = fread(gbuf, 1, n_bits, fp);
		if (size <= 0)			
			return (-1);
		roffset = 0;
		
		size = (size << 3) - (n_bits - 1);
	}
	r_off = roffset;
	bits = n_bits;

	
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
	roffset += n_bits;

	return (gcode);
}

static int cl_block(struct s_zstate *zs)
{
	long rat;

	checkpoint = in_count + CHECK_GAP;

	if (in_count > 0x007fffff) {	
		rat = bytes_out >> 8;
		if (rat == 0)		
			rat = 0x7fffffff;
		else rat = in_count / rat;
	} else rat = (in_count << 8) / bytes_out;
	if (rat > ratio)
		ratio = rat;
	else {
		ratio = 0;
		cl_hash(zs, (count_int) hsize);
		free_ent = FIRST;
		clear_flg = 1;
		if (output(zs, (code_int) CLEAR) == -1)
			return (-1);
	}
	return (0);
}

static void cl_hash(struct s_zstate *zs, count_int cl_hsize)
{
	count_int *htab_p;
	long i, m1;

	m1 = -1;
	htab_p = htab + cl_hsize;
	i = cl_hsize - 16;
	do {			
		*(htab_p - 16) = m1;
		*(htab_p - 15) = m1;
		*(htab_p - 14) = m1;
		*(htab_p - 13) = m1;
		*(htab_p - 12) = m1;
		*(htab_p - 11) = m1;
		*(htab_p - 10) = m1;
		*(htab_p - 9) = m1;
		*(htab_p - 8) = m1;
		*(htab_p - 7) = m1;
		*(htab_p - 6) = m1;
		*(htab_p - 5) = m1;
		*(htab_p - 4) = m1;
		*(htab_p - 3) = m1;
		*(htab_p - 2) = m1;
		*(htab_p - 1) = m1;
		htab_p -= 16;
	} while ((i -= 16) >= 0);
	for (i += 16; i > 0; i--)
		*--htab_p = m1;
}

FILE * zopen(const char *fname, const char *mode, int bits)
{
	struct s_zstate *zs;

	if ((mode[0] != 'r' && mode[0] != 'w') || mode[1] != '\0' || bits < 0 || bits > BITS) {
		errno = EINVAL;
		return (NULL);
	}

	if ((zs = calloc(1, sizeof(struct s_zstate))) == NULL)
		return (NULL);

	maxbits = bits ? bits : BITS;	
	maxmaxcode = 1L << maxbits;	
	hsize = HSIZE;			
	free_ent = 0;			
	block_compress = BLOCK_MASK;
	clear_flg = 0;
	ratio = 0;
	checkpoint = CHECK_GAP;
	in_count = 1;			
	out_count = 0;			
	state = S_START;
	roffset = 0;
	size = 0;

	
	if ((fp = fopen(fname, mode)) == NULL) {
		free(zs);
		return (NULL);
	}
	switch (*mode) {
	case 'r':
		zmode = 'r';
		return (funopen(zs, zread, NULL, NULL, zclose));
	case 'w':
		zmode = 'w';
		return (funopen(zs, NULL, zwrite, NULL, zclose));
	}
	
	return (NULL);
}
