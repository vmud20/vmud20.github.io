

#include<time.h>
#include<utime.h>

#include<errno.h>
#include<libintl.h>
#include<unistd.h>

#include<stdio.h>

#include<limits.h>
#include<stdlib.h>
#include<netinet/in.h>

#include<setjmp.h>

#include<math.h>



#include<sys/types.h>
#include<float.h>
#include<string.h>

#include<fcntl.h>
#include<ctype.h>
#define C_MAX_BLOCKS_IN_MCU   10 
#define D_MAX_BLOCKS_IN_MCU   10 
#define JDCT_DEFAULT  JDCT_ISLOW
#define JDCT_FASTEST  JDCT_IFAST
#define JMSG_LENGTH_MAX  200	
#define JMSG_STR_PARM_MAX  80

#define JPEG_LIB_VERSION        80	
#define JPEG_LIB_VERSION_MAJOR  8
#define JPEG_LIB_VERSION_MINOR  3
#define JPP(arglist)	arglist
#define MAX_COMPS_IN_SCAN   4	
#define MAX_SAMP_FACTOR     4	
#define NUM_ARITH_TBLS      16	
#define NUM_HUFF_TBLS       4	
#define NUM_QUANT_TBLS      4	
#define jpeg_common_fields \
  struct jpeg_error_mgr * err;	\
  struct jpeg_memory_mgr * mem;	\
  struct jpeg_progress_mgr * progress; \
  void * client_data;		\
  boolean is_decompressor;	\
  int global_state		
#define jpeg_create_compress(cinfo) \
    jpeg_CreateCompress((cinfo), JPEG_LIB_VERSION, \
			(size_t) sizeof(struct jpeg_compress_struct))
#define jpeg_create_decompress(cinfo) \
    jpeg_CreateDecompress((cinfo), JPEG_LIB_VERSION, \
			  (size_t) sizeof(struct jpeg_decompress_struct))
#define ABS(x) (((int)(x) ^ ((int)(x) >> 31)) - ((int)(x) >> 31))
#define CLIP(x) LIM(x,0,65535)

#define DCR_VERSION "8.93"
#define FORC(cnt) for (c=0; c < cnt; c++)
#define FORC3     FORC(3)
#define FORC4     FORC(4)
#define FORCC(p)  FORC(p->colors)
#define LIM(x,min,max) MAX(min,MIN(x,max))
  #define LONG_BIT (8 * sizeof (long))
#define MAX(a,b) ((a) > (b) ? (a) : (b))
#define MIN(a,b) ((a) < (b) ? (a) : (b))
  #define M_PI 3.14159265358979323846


#define RESTRICTED 0
#define SQR(x) ((x)*(x))
#define SWAP(a,b) { a ^= b; a ^= (b ^= a); }
#define ULIM(x,y,z) ((y) < (z) ? LIM(x,y,z) : LIM(x,z,y))

 #define _getcwd getcwd
#define _swab   swab
#define dcr_fclose (*p->ops_->close_)
#define dcr_feof   (*p->ops_->eof_)
#define dcr_fgetc  (*p->ops_->getc_)
#define dcr_fgets  (*p->ops_->gets_)
#define dcr_fread  (*p->ops_->read_)
#define dcr_fscanf (*p->ops_->scanf_)
#define dcr_fseek  (*p->ops_->seek_)
#define dcr_ftell  (*p->ops_->tell_)
#define dcr_fwrite (*p->ops_->write_)
  #define fseeko fseek
  #define ftello ftell
