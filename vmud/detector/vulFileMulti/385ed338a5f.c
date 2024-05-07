





















typedef struct {
	ushort  imagic;      
	ushort  type;
	ushort  dim;
	ushort  xsize;
	ushort  ysize;
	ushort  zsize;
	uint    min;
	uint    max;
	uint    wastebytes;
	char    name[80];
	uint    colormap;

	int     file;       
	ushort  flags;
	short   dorev;
	short   x;
	short   y;
	short   z;
	short   cnt;
	ushort *ptr;
	ushort *base;
	ushort *tmpbuf;
	uint    offset;
	uint    rleend;         
	uint      *rowstart;    
	const int *rowsize;     
} IMAGE;





























typedef struct MFileOffset {
	const uchar *_file_data;
	uint _file_offset;
} MFileOffset;






static void readheader(MFileOffset *inf, IMAGE *image);
static int writeheader(FILE *outf, IMAGE *image);

static ushort getshort(MFileOffset *inf);
static uint getlong(MFileOffset *inf);
static void putshort(FILE *outf, ushort val);
static int putlong(FILE *outf, uint val);
static int writetab(FILE *outf, uint *tab, int len);
static void readtab(MFileOffset *inf, uint *tab, int len);

static void expandrow(uchar *optr, const uchar *iptr, int z);
static void expandrow2(float *optr, const uchar *iptr, int z);
static void interleaverow(uchar *lptr, const uchar *cptr, int z, int n);
static void interleaverow2(float *lptr, const uchar *cptr, int z, int n);
static int compressrow(uchar *lbuf, uchar *rlebuf, int z, int cnt);
static void lumrow(uchar *rgbptr, uchar *lumptr, int n);



static ushort getshort(MFileOffset *inf)
{
	const uchar *buf;

	buf = MFILE_DATA(inf);
	MFILE_STEP(inf, 2);

	return ((ushort)buf[0] << 8) + ((ushort)buf[1] << 0);
}

static uint getlong(MFileOffset *mofs)
{
	const uchar *buf;
	
	buf = MFILE_DATA(mofs);
	MFILE_STEP(mofs, 4);

	return ((uint)buf[0] << 24) + ((uint)buf[1] << 16) + ((uint)buf[2] << 8) + ((uint)buf[3] << 0);
}

static void putshort(FILE *outf, ushort val)
{
	uchar buf[2];

	buf[0] = (val >> 8);
	buf[1] = (val >> 0);
	fwrite(buf, 2, 1, outf);
}

static int putlong(FILE *outf, uint val)
{
	uchar buf[4];

	buf[0] = (val >> 24);
	buf[1] = (val >> 16);
	buf[2] = (val >> 8);
	buf[3] = (val >> 0);
	return fwrite(buf, 4, 1, outf);
}

static void readheader(MFileOffset *inf, IMAGE *image)
{
	memset(image, 0, sizeof(IMAGE));
	image->imagic = getshort(inf);
	image->type = getshort(inf);
	image->dim = getshort(inf);
	image->xsize = getshort(inf);
	image->ysize = getshort(inf);
	image->zsize = getshort(inf);
}

static int writeheader(FILE *outf, IMAGE *image)
{
	IMAGE t = {0};

	fwrite(&t, sizeof(IMAGE), 1, outf);
	fseek(outf, 0, SEEK_SET);
	putshort(outf, image->imagic);
	putshort(outf, image->type);
	putshort(outf, image->dim);
	putshort(outf, image->xsize);
	putshort(outf, image->ysize);
	putshort(outf, image->zsize);
	putlong(outf, image->min);
	putlong(outf, image->max);
	putlong(outf, 0);
	return fwrite("no name", 8, 1, outf);
}

static int writetab(FILE *outf, uint *tab, int len)
{
	int r = 0;

	while (len) {
		r = putlong(outf, *tab++);
		len -= 4;
	}
	return r;
}

static void readtab(MFileOffset *inf, uint *tab, int len)
{
	while (len) {
		*tab++ = getlong(inf);
		len -= 4;
	}
}

static void test_endian_zbuf(struct ImBuf *ibuf)
{
	int len;
	int *zval;
	
	if (BIG_LONG(1) == 1) return;
	if (ibuf->zbuf == NULL) return;
	
	len = ibuf->x * ibuf->y;
	zval = ibuf->zbuf;
	
	while (len--) {
		zval[0] = BIG_LONG(zval[0]);
		zval++;
	}
}







int imb_is_a_iris(const uchar *mem)
{
	return ((GS(mem) == IMAGIC) || (GSS(mem) == IMAGIC));
}



struct ImBuf *imb_loadiris(const uchar *mem, size_t size, int flags, char colorspace[IM_MAX_SPACE])
{
	uint *base, *lptr = NULL;
	float *fbase, *fptr = NULL;
	uint *zbase, *zptr;
	const uchar *rledat;
	uint *starttab, *lengthtab;
	MFileOffset _inf_data = {mem, 0}, *inf = &_inf_data;
	IMAGE image;
	int x, y, z, tablen;
	int xsize, ysize, zsize;
	int bpp, rle, cur, badorder;
	ImBuf *ibuf;

	(void)size; 
	
	if (!imb_is_a_iris(mem)) return NULL;

	
	colorspace_set_default_role(colorspace, IM_MAX_SPACE, COLOR_ROLE_DEFAULT_BYTE);

	
	
	readheader(inf, &image);
	if (image.imagic != IMAGIC) {
		fprintf(stderr, "longimagedata: bad magic number in image file\n");
		return(NULL);
	}
	
	rle = ISRLE(image.type);
	bpp = BPP(image.type);
	if (bpp != 1 && bpp != 2) {
		fprintf(stderr, "longimagedata: image must have 1 or 2 byte per pix chan\n");
		return(NULL);
	}
	
	xsize = image.xsize;
	ysize = image.ysize;
	zsize = image.zsize;
	
	if (flags & IB_test) {
		ibuf = IMB_allocImBuf(image.xsize, image.ysize, 8 * image.zsize, 0);
		if (ibuf) ibuf->ftype = IMB_FTYPE_IMAGIC;
		return(ibuf);
	}
	
	if (rle) {
		
		tablen = ysize * zsize * sizeof(int);
		starttab = (uint *)MEM_mallocN(tablen, "iris starttab");
		lengthtab = (uint *)MEM_mallocN(tablen, "iris endtab");
		MFILE_SEEK(inf, HEADER_SIZE);
		
		readtab(inf, starttab, tablen);
		readtab(inf, lengthtab, tablen);
	
		
		cur = 0;
		badorder = 0;
		for (y = 0; y < ysize; y++) {
			for (z = 0; z < zsize; z++) {
				if (starttab[y + z * ysize] < cur) {
					badorder = 1;
					break;
				}
				cur = starttab[y + z * ysize];
			}
			if (badorder)
				break;
		}
	
		if (bpp == 1) {
			
			ibuf = IMB_allocImBuf(xsize, ysize, 8 * zsize, IB_rect);
			if (ibuf->planes > 32) ibuf->planes = 32;
			base = ibuf->rect;
			zbase = (uint *)ibuf->zbuf;
			
			if (badorder) {
				for (z = 0; z < zsize; z++) {
					lptr = base;
					for (y = 0; y < ysize; y++) {
						MFILE_SEEK(inf, starttab[y + z * ysize]);
						rledat = MFILE_DATA(inf);
						MFILE_STEP(inf, lengthtab[y + z * ysize]);
						
						expandrow((uchar *)lptr, rledat, 3 - z);
						lptr += xsize;
					}
				}
			}
			else {
				lptr = base;
				zptr = zbase;
				for (y = 0; y < ysize; y++) {
				
					for (z = 0; z < zsize; z++) {
						MFILE_SEEK(inf, starttab[y + z * ysize]);
						rledat = MFILE_DATA(inf);
						MFILE_STEP(inf, lengthtab[y + z * ysize]);
						
						if (z < 4) expandrow((uchar *)lptr, rledat, 3 - z);
						else if (z < 8) expandrow((uchar *)zptr, rledat, 7 - z);
					}
					lptr += xsize;
					zptr += xsize;
				}
			}
			

		}
		else {  
			
			ibuf = IMB_allocImBuf(xsize, ysize, 32, (flags & IB_rect) | IB_rectfloat);
			
			fbase = ibuf->rect_float;
			
			if (badorder) {
				for (z = 0; z < zsize; z++) {
					fptr = fbase;
					for (y = 0; y < ysize; y++) {
						MFILE_SEEK(inf, starttab[y + z * ysize]);
						rledat = MFILE_DATA(inf);
						MFILE_STEP(inf, lengthtab[y + z * ysize]);
						
						expandrow2(fptr, rledat, 3 - z);
						fptr += xsize * 4;
					}
				}
			}
			else {
				fptr = fbase;

				for (y = 0; y < ysize; y++) {
				
					for (z = 0; z < zsize; z++) {
						MFILE_SEEK(inf, starttab[y + z * ysize]);
						rledat = MFILE_DATA(inf);
						MFILE_STEP(inf, lengthtab[y + z * ysize]);
						
						expandrow2(fptr, rledat, 3 - z);
						
					}
					fptr += xsize * 4;
				}
			}
		}
		
		MEM_freeN(starttab);
		MEM_freeN(lengthtab);

	}
	else {
		if (bpp == 1) {
			
			ibuf = IMB_allocImBuf(xsize, ysize, 8 * zsize, IB_rect);
			if (ibuf->planes > 32) ibuf->planes = 32;

			base = ibuf->rect;
			zbase = (uint *)ibuf->zbuf;
			
			MFILE_SEEK(inf, HEADER_SIZE);
			rledat = MFILE_DATA(inf);
			
			for (z = 0; z < zsize; z++) {
				
				if (z < 4) lptr = base;
				else if (z < 8) lptr = zbase;
				
				for (y = 0; y < ysize; y++) {

					interleaverow((uchar *)lptr, rledat, 3 - z, xsize);
					rledat += xsize;
					
					lptr += xsize;
				}
			}
			
		}
		else {  
			
			ibuf = IMB_allocImBuf(xsize, ysize, 32, (flags & IB_rect) | IB_rectfloat);

			fbase = ibuf->rect_float;

			MFILE_SEEK(inf, HEADER_SIZE);
			rledat = MFILE_DATA(inf);
			
			for (z = 0; z < zsize; z++) {
				
				fptr = fbase;
				
				for (y = 0; y < ysize; y++) {

					interleaverow2(fptr, rledat, 3 - z, xsize);
					rledat += xsize * 2;
					
					fptr += xsize * 4;
				}
			}
			
		}
	}
	
	
	if (bpp == 1) {
		uchar *rect;
		
		if (image.zsize == 1) {
			rect = (uchar *) ibuf->rect;
			for (x = ibuf->x * ibuf->y; x > 0; x--) {
				rect[0] = 255;
				rect[1] = rect[2] = rect[3];
				rect += 4;
			}
		}
		else if (image.zsize == 2) {
			
			rect = (uchar *) ibuf->rect;
			for (x = ibuf->x * ibuf->y; x > 0; x--) {
				rect[0] = rect[2];
				rect[1] = rect[2] = rect[3];
				rect += 4;
			}
		}
		else if (image.zsize == 3) {
			
			rect = (uchar *) ibuf->rect;
			for (x = ibuf->x * ibuf->y; x > 0; x--) {
				rect[0] = 255;
				rect += 4;
			}
		}
		
	}
	else {  
		
		if (image.zsize == 1) {
			fbase = ibuf->rect_float;
			for (x = ibuf->x * ibuf->y; x > 0; x--) {
				fbase[0] = 1;
				fbase[1] = fbase[2] = fbase[3];
				fbase += 4;
			}
		}
		else if (image.zsize == 2) {
			
			fbase = ibuf->rect_float;
			for (x = ibuf->x * ibuf->y; x > 0; x--) {
				fbase[0] = fbase[2];
				fbase[1] = fbase[2] = fbase[3];
				fbase += 4;
			}
		}
		else if (image.zsize == 3) {
			
			fbase = ibuf->rect_float;
			for (x = ibuf->x * ibuf->y; x > 0; x--) {
				fbase[0] = 1;
				fbase += 4;
			}
		}
		
		if (flags & IB_rect) {
			IMB_rect_from_float(ibuf);
		}
		
	}

	ibuf->ftype = IMB_FTYPE_IMAGIC;

	test_endian_zbuf(ibuf);

	if (ibuf->rect) {
		IMB_convert_rgba_to_abgr(ibuf);
	}

	return(ibuf);
}



static void interleaverow(uchar *lptr, const uchar *cptr, int z, int n)
{
	lptr += z;
	while (n--) {
		*lptr = *cptr++;
		lptr += 4;
	}
}

static void interleaverow2(float *lptr, const uchar *cptr, int z, int n)
{
	lptr += z;
	while (n--) {
		*lptr = ((cptr[0] << 8) | (cptr[1] << 0)) / (float)0xFFFF;
		cptr += 2;
		lptr += 4;
	}
}

static void expandrow2(float *optr, const uchar *iptr, int z)
{
	ushort pixel, count;
	float pixel_f;

	optr += z;
	while (1) {
		pixel = (iptr[0] << 8) | (iptr[1] << 0);
		iptr += 2;
		
		if (!(count = (pixel & 0x7f)) )
			return;
		if (pixel & 0x80) {
			while (count >= 8) {
				optr[0 * 4] = ((iptr[0] << 8) | (iptr[1] << 0)) / (float)0xFFFF;
				optr[1 * 4] = ((iptr[2] << 8) | (iptr[3] << 0)) / (float)0xFFFF;
				optr[2 * 4] = ((iptr[4] << 8) | (iptr[5] << 0)) / (float)0xFFFF;
				optr[3 * 4] = ((iptr[6] << 8) | (iptr[7] << 0)) / (float)0xFFFF;
				optr[4 * 4] = ((iptr[8] << 8) | (iptr[9] << 0)) / (float)0xFFFF;
				optr[5 * 4] = ((iptr[10] << 8) | (iptr[11] << 0)) / (float)0xFFFF;
				optr[6 * 4] = ((iptr[12] << 8) | (iptr[13] << 0)) / (float)0xFFFF;
				optr[7 * 4] = ((iptr[14] << 8) | (iptr[15] << 0)) / (float)0xFFFF;
				optr += 8 * 4;
				iptr += 8 * 2;
				count -= 8;
			}
			while (count--) {
				*optr = ((iptr[0] << 8) | (iptr[1] << 0)) / (float)0xFFFF;
				iptr += 2;
				optr += 4;
			}
		}
		else {
			pixel_f = ((iptr[0] << 8) | (iptr[1] << 0)) / (float)0xFFFF;
			iptr += 2;

			while (count >= 8) {
				optr[0 * 4] = pixel_f;
				optr[1 * 4] = pixel_f;
				optr[2 * 4] = pixel_f;
				optr[3 * 4] = pixel_f;
				optr[4 * 4] = pixel_f;
				optr[5 * 4] = pixel_f;
				optr[6 * 4] = pixel_f;
				optr[7 * 4] = pixel_f;
				optr += 8 * 4;
				count -= 8;
			}
			while (count--) {
				*optr = pixel_f;
				optr += 4;
			}
		}
	}
}

static void expandrow(uchar *optr, const uchar *iptr, int z)
{
	uchar pixel, count;

	optr += z;
	while (1) {
		pixel = *iptr++;
		if (!(count = (pixel & 0x7f)) )
			return;
		if (pixel & 0x80) {
			while (count >= 8) {
				optr[0 * 4] = iptr[0];
				optr[1 * 4] = iptr[1];
				optr[2 * 4] = iptr[2];
				optr[3 * 4] = iptr[3];
				optr[4 * 4] = iptr[4];
				optr[5 * 4] = iptr[5];
				optr[6 * 4] = iptr[6];
				optr[7 * 4] = iptr[7];
				optr += 8 * 4;
				iptr += 8;
				count -= 8;
			}
			while (count--) {
				*optr = *iptr++;
				optr += 4;
			}
		}
		else {
			pixel = *iptr++;
			while (count >= 8) {
				optr[0 * 4] = pixel;
				optr[1 * 4] = pixel;
				optr[2 * 4] = pixel;
				optr[3 * 4] = pixel;
				optr[4 * 4] = pixel;
				optr[5 * 4] = pixel;
				optr[6 * 4] = pixel;
				optr[7 * 4] = pixel;
				optr += 8 * 4;
				count -= 8;
			}
			while (count--) {
				*optr = pixel;
				optr += 4;
			}
		}
	}
}



static int output_iris(uint *lptr, int xsize, int ysize, int zsize, const char *name, int *zptr)
{
	FILE *outf;
	IMAGE *image;
	int tablen, y, z, pos, len = 0;
	uint *starttab, *lengthtab;
	uchar *rlebuf;
	uint *lumbuf;
	int rlebuflen, goodwrite;

	goodwrite = 1;
	outf = BLI_fopen(name, "wb");
	if (!outf) return 0;

	tablen = ysize * zsize * sizeof(int);

	image = (IMAGE *)MEM_mallocN(sizeof(IMAGE), "iris image");
	starttab = (uint *)MEM_mallocN(tablen, "iris starttab");
	lengthtab = (uint *)MEM_mallocN(tablen, "iris lengthtab");
	rlebuflen = 1.05 * xsize + 10;
	rlebuf = (uchar *)MEM_mallocN(rlebuflen, "iris rlebuf");
	lumbuf = (uint *)MEM_mallocN(xsize * sizeof(int), "iris lumbuf");

	memset(image, 0, sizeof(IMAGE));
	image->imagic = IMAGIC;
	image->type = RLE(1);
	if (zsize > 1)
		image->dim = 3;
	else image->dim = 2;
	image->xsize = xsize;
	image->ysize = ysize;
	image->zsize = zsize;
	image->min = 0;
	image->max = 255;
	goodwrite *= writeheader(outf, image);
	fseek(outf, HEADER_SIZE + (2 * tablen), SEEK_SET);
	pos = HEADER_SIZE + (2 * tablen);
	
	for (y = 0; y < ysize; y++) {
		for (z = 0; z < zsize; z++) {
			
			if (zsize == 1) {
				lumrow((uchar *)lptr, (uchar *)lumbuf, xsize);
				len = compressrow((uchar *)lumbuf, rlebuf, CHANOFFSET(z), xsize);
			}
			else {
				if (z < 4) {
					len = compressrow((uchar *)lptr, rlebuf, CHANOFFSET(z), xsize);
				}
				else if (z < 8 && zptr) {
					len = compressrow((uchar *)zptr, rlebuf, CHANOFFSET(z - 4), xsize);
				}
			}
			if (len > rlebuflen) {
				fprintf(stderr, "output_iris: rlebuf is too small - bad poop\n");
				exit(1);
			}
			goodwrite *= fwrite(rlebuf, len, 1, outf);
			starttab[y + z * ysize] = pos;
			lengthtab[y + z * ysize] = len;
			pos += len;
		}
		lptr += xsize;
		if (zptr) zptr += xsize;
	}

	fseek(outf, HEADER_SIZE, SEEK_SET);
	goodwrite *= writetab(outf, starttab, tablen);
	goodwrite *= writetab(outf, lengthtab, tablen);
	MEM_freeN(image);
	MEM_freeN(starttab);
	MEM_freeN(lengthtab);
	MEM_freeN(rlebuf);
	MEM_freeN(lumbuf);
	fclose(outf);
	if (goodwrite)
		return 1;
	else {
		fprintf(stderr, "output_iris: not enough space for image!!\n");
		return 0;
	}
}



static void lumrow(uchar *rgbptr, uchar *lumptr, int n)
{
	lumptr += CHANOFFSET(0);
	while (n--) {
		*lumptr = ILUM(rgbptr[OFFSET_R], rgbptr[OFFSET_G], rgbptr[OFFSET_B]);
		lumptr += 4;
		rgbptr += 4;
	}
}

static int compressrow(uchar *lbuf, uchar *rlebuf, int z, int cnt)
{
	uchar *iptr, *ibufend, *sptr, *optr;
	short todo, cc;
	int count;

	lbuf += z;
	iptr = lbuf;
	ibufend = iptr + cnt * 4;
	optr = rlebuf;

	while (iptr < ibufend) {
		sptr = iptr;
		iptr += 8;
		while ((iptr < ibufend) && ((iptr[-8] != iptr[-4]) || (iptr[-4] != iptr[0])))
			iptr += 4;
		iptr -= 8;
		count = (iptr - sptr) / 4;
		while (count) {
			todo = count > 126 ? 126 : count;
			count -= todo;
			*optr++ = 0x80 | todo;
			while (todo > 8) {
				optr[0] = sptr[0 * 4];
				optr[1] = sptr[1 * 4];
				optr[2] = sptr[2 * 4];
				optr[3] = sptr[3 * 4];
				optr[4] = sptr[4 * 4];
				optr[5] = sptr[5 * 4];
				optr[6] = sptr[6 * 4];
				optr[7] = sptr[7 * 4];

				optr += 8;
				sptr += 8 * 4;
				todo -= 8;
			}
			while (todo--) {
				*optr++ = *sptr;
				sptr += 4;
			}
		}
		sptr = iptr;
		cc = *iptr;
		iptr += 4;
		while ( (iptr < ibufend) && (*iptr == cc) )
			iptr += 4;
		count = (iptr - sptr) / 4;
		while (count) {
			todo = count > 126 ? 126 : count;
			count -= todo;
			*optr++ = todo;
			*optr++ = cc;
		}
	}
	*optr++ = 0;
	return optr - (uchar *)rlebuf;
}

int imb_saveiris(struct ImBuf *ibuf, const char *name, int flags)
{
	short zsize;
	int ret;

	zsize = (ibuf->planes + 7) >> 3;
	if (flags & IB_zbuf &&  ibuf->zbuf != NULL) zsize = 8;
	
	IMB_convert_rgba_to_abgr(ibuf);
	test_endian_zbuf(ibuf);

	ret = output_iris(ibuf->rect, ibuf->x, ibuf->y, zsize, name, ibuf->zbuf);

	
	IMB_convert_rgba_to_abgr(ibuf);
	test_endian_zbuf(ibuf);

	return(ret);
}

