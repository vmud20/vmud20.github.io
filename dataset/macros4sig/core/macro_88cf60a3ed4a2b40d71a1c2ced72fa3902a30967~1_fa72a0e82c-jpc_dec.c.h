#include<stdbool.h>
#include<stddef.h>


#include<assert.h>
#include<unistd.h>
#include<stdio.h>


#include<limits.h>
#include<stdlib.h>









#include<math.h>


#include<sys/types.h>

#include<string.h>
#include<fcntl.h>
#include<stdint.h>







#define jas_matrix_bindcol(mat0, mat1, c) \
  (jas_matrix_bindsub((mat0), (mat1), 0, (c), (mat1)->numrows_ - 1, (c)))
#define jas_matrix_bindrow(mat0, mat1, r) \
  (jas_matrix_bindsub((mat0), (mat1), (r), 0, (r), (mat1)->numcols_ - 1))
#define jas_matrix_get(matrix, i, j) \
	((matrix)->rows_[i][j])
#define jas_matrix_getv(matrix, i) \
	(((matrix)->numrows_ == 1) ? ((matrix)->rows_[0][i]) : \
	  ((matrix)->rows_[i][0]))
#define jas_matrix_length(matrix) \
	(max((matrix)->numrows_, (matrix)->numcols_))
#define jas_matrix_numcols(matrix) \
	((matrix)->numcols_)
#define jas_matrix_numrows(matrix) \
	((matrix)->numrows_)
#define jas_matrix_set(matrix, i, j, v) \
	((matrix)->rows_[i][j] = (v))
#define jas_matrix_setv(matrix, i, v) \
	(((matrix)->numrows_ == 1) ? ((matrix)->rows_[0][i] = (v)) : \
	  ((matrix)->rows_[i][0] = (v)))
#define jas_seq_set(seq, i, v) \
	((seq)->rows_[0][(i) - (seq)->xstart_] = (v))

#define longlong long long
#define uchar unsigned char
#define uint unsigned int
#define ulong unsigned long
#define ulonglong unsigned long long
#define ushort unsigned short
#define HAVE_DLFCN_H 1
#define HAVE_FCNTL_H 1
#define HAVE_GETRUSAGE 1
#define HAVE_GETTIMEOFDAY 1
#define HAVE_INTTYPES_H 1
#define HAVE_LIBM 1
#define HAVE_LIMITS_H 1
#define HAVE_MEMORY_H 1
#define HAVE_STDBOOL_H 1
#define HAVE_STDDEF_H 1
#define HAVE_STDINT_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STRINGS_H 1
#define HAVE_STRING_H 1
#define HAVE_SYS_STAT_H 1
#define HAVE_SYS_TIME_H 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_UNISTD_H 1
#define HAVE_VLA 1
#define HAVE_VPRINTF 1
#define JAS_CONFIGURE 1

#define JAS_VERSION "1.900.1"
#define PACKAGE "jasper"
#define PACKAGE_BUGREPORT ""
#define PACKAGE_NAME "jasper"
#define PACKAGE_STRING "jasper 1.900.1"
#define PACKAGE_TARNAME "jasper"
#define PACKAGE_VERSION "1.900.1"
#define STDC_HEADERS 1
#define VERSION "1.900.1"
#define JAS_STREAM_ERRMASK \
	(JAS_STREAM_EOF | JAS_STREAM_ERR | JAS_STREAM_RWLIMIT)

#define jas_stream_clearerr(stream) \
	((stream)->flags_ &= ~(JAS_STREAM_ERR | JAS_STREAM_EOF))
#define jas_stream_eof(stream) \
	(((stream)->flags_ & JAS_STREAM_EOF) != 0)
#define jas_stream_error(stream) \
	(((stream)->flags_ & JAS_STREAM_ERR) != 0)
#define jas_stream_getc2(stream) \
	((--(stream)->cnt_ < 0) ? jas_stream_fillbuf(stream, 1) : \
	  (++(stream)->rwcnt_, (int)(*(stream)->ptr_++)))
#define jas_stream_getc_macro(stream) \
	((!((stream)->flags_ & (JAS_STREAM_ERR | JAS_STREAM_EOF | \
	  JAS_STREAM_RWLIMIT))) ? \
	  (((stream)->rwlimit_ >= 0 && (stream)->rwcnt_ >= (stream)->rwlimit_) ? \
	  (stream->flags_ |= JAS_STREAM_RWLIMIT, EOF) : \
	  jas_stream_getc2(stream)) : EOF)
#define jas_stream_putc2(stream, c) \
	(((stream)->bufmode_ |= JAS_STREAM_WRBUF, --(stream)->cnt_ < 0) ? \
	  jas_stream_flushbuf((stream), (uchar)(c)) : \
	  (++(stream)->rwcnt_, (int)(*(stream)->ptr_++ = (c))))
#define jas_stream_putc_macro(stream, c) \
	((!((stream)->flags_ & (JAS_STREAM_ERR | JAS_STREAM_EOF | \
	  JAS_STREAM_RWLIMIT))) ? \
	  (((stream)->rwlimit_ >= 0 && (stream)->rwcnt_ >= (stream)->rwlimit_) ? \
	  (stream->flags_ |= JAS_STREAM_RWLIMIT, EOF) : \
	  jas_stream_putc2(stream, c)) : EOF)

#define jpc_dbltofix(x)	JAS_DBLTOFIX(jpc_fix_t, JPC_FIX_FRACBITS, x)
#define jpc_fix_add3(x, y, z)	jpc_fix_add(jpc_fix_add(x, y), z)
#define jpc_fix_minuseq(x, y)	JAS_FIX_MINUSEQ(jpc_fix_t, JPC_FIX_FRACBITS, x, y)
#define jpc_fix_pluseq(x, y)	JAS_FIX_PLUSEQ(jpc_fix_t, JPC_FIX_FRACBITS, x, y)
#define jpc_fix_sgn(x)		JAS_FIX_SGN(jpc_fix_t, JPC_FIX_FRACBITS, x)
#define jpc_fix_trunc(x)	JAS_FIX_TRUNC(jpc_fix_t, JPC_FIX_FRACBITS, x)
#define jpc_fixtodbl(x)	JAS_FIXTODBL(jpc_fix_t, JPC_FIX_FRACBITS, x)
#define jpc_fixtoint(x)	JAS_FIXTOINT(jpc_fix_t, JPC_FIX_FRACBITS, x)
#define jpc_inttofix(x)	JAS_INTTOFIX(jpc_fix_t, JPC_FIX_FRACBITS, x)
#define JAS_DBLTOFIX(fix_t, fracbits, x) \
	JAS_CAST(fix_t, ((x) * JAS_CAST(double, JAS_CAST(fix_t, 1) << (fracbits))))
#define JAS_FIXTODBL(fix_t, fracbits, x) \
	(JAS_CAST(double, x) / (JAS_CAST(fix_t, 1) << (fracbits)))
#define JAS_FIXTOINT(fix_t, fracbits, x) \
	JAS_CAST(int, (x) >> (fracbits))
#define JAS_FIX_ADD			JAS_FIX_ADD_FAST
#define JAS_FIX_CMP(fix_t, fracbits, x, y) \
	((x) > (y) ? 1 : (((x) == (y)) ? 0 : (-1)))
#define JAS_FIX_DIV			JAS_FIX_DIV_FAST
#define JAS_FIX_DIV_UFLOW(fix_t, fracbits, bigfix_t, x, y) \
	JAS_FIX_DIV_FAST(fix_t, fracbits, bigfix_t, x, y)

#define JAS_FIX_MINUSEQ(fix_t, fracbits, x, y) \
	((x) = JAS_FIX_SUB(fix_t, fracbits, x, y))
#define JAS_FIX_MUL			JAS_FIX_MUL_FAST
#define JAS_FIX_MUL_OFLOW(fix_t, fracbits, bigfix_t, x, y) \
	((JAS_CAST(bigfix_t, x) * JAS_CAST(bigfix_t, y) >> (fracbits)) == \
	  JAS_CAST(fix_t, (JAS_CAST(bigfix_t, x) * JAS_CAST(bigfix_t, y) >> \
	  (fracbits))) ? \
	  JAS_CAST(fix_t, (JAS_CAST(bigfix_t, x) * JAS_CAST(bigfix_t, y) >> \
	  (fracbits))) : JAS_FIX_OFLOW())
#define JAS_FIX_PLUSEQ(fix_t, fracbits, x, y) \
	((x) = JAS_FIX_ADD(fix_t, fracbits, x, y))
#define JAS_FIX_SGN(fix_t, fracbits, x) \
	((x) >= 0 ? 1 : (-1))
#define JAS_FIX_SUB(fix_t, fracbits, x, y) \
	JAS_FIX_ADD(fix_t, fracbits, x, JAS_FIX_NEG(fix_t, fracbits, y))
#define JAS_FIX_TRUNC(fix_t, fracbits, x) \
	(((x) >= 0) ? JAS_FIX_FLOOR(fix_t, fracbits, x) : \
	  JAS_FIX_CEIL(fix_t, fracbits, x))
#define JAS_INTTOFIX(fix_t, fracbits, x) \
	JAS_CAST(fix_t, (x) << (fracbits))



#define jpc_pi_cmptno(pi)	(assert(pi->valid), (pi)->compno)
#define jpc_pi_lyrno(pi)	(assert(pi->valid), (pi)->lyrno)
#define jpc_pi_prcno(pi)	(assert(pi->valid), (pi)->prcno)
#define jpc_pi_prg(pi)	(assert(pi->valid), (pi)->pchg->prgord)
#define jpc_pi_rlvlno(pi)	(assert(pi->valid), (pi)->rlvlno)



#define jas_image_brx(image) \
	((image)->brx_)
#define jas_image_bry(image) \
	((image)->bry_)
#define jas_image_cmpttype(image, cmptno) \
	((image)->cmpts_[(cmptno)]->type_)
#define jas_image_setclrspc(image, clrspc) \
	((image)->clrspc_ = (clrspc))
#define jas_image_setcmpttype(image, cmptno, type) \
	((image)->cmpts_[(cmptno)]->type_ = (type))
#define jas_image_tlx(image) \
	((image)->tlx_)
#define jas_image_tly(image) \
	((image)->tly_)
#define jas_image_width(image) \
	((image)->brx_ - (image)->tlx_)



#define jpc_bitstream_eof(bitstream) \
	((bitstream)->flags_ & JPC_BITSTREAM_EOF)
#define jpc_bitstream_getbit(bitstream) \
	jpc_bitstream_getbit_macro(bitstream)
#define jpc_bitstream_putbit_macro(bitstream, bit) \
	(assert((bitstream)->openmode_ & JPC_BITSTREAM_WRITE), \
	  (--(bitstream)->cnt_ < 0) ? \
	  ((bitstream)->buf_ = ((bitstream)->buf_ << 8) & 0xffff, \
	  (bitstream)->cnt_ = ((bitstream)->buf_ == 0xff00) ? 6 : 7, \
	  (bitstream)->buf_ |= ((bit) & 1) << (bitstream)->cnt_, \
	  (jas_stream_putc((bitstream)->stream_, (bitstream)->buf_ >> 8) == EOF) \
	  ? (EOF) : ((bit) & 1)) : \
	  ((bitstream)->buf_ |= ((bit) & 1) << (bitstream)->cnt_, \
	  (bit) & 1))





