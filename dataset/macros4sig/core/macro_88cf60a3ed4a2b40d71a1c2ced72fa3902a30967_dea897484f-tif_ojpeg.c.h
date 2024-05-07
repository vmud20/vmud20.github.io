#include<stdio.h>
#include<setjmp.h>
#include<stdarg.h>



#include<inttypes.h>

#define ERREXIT(cinfo,code)  \
  ((cinfo)->err->msg_code = (code), \
   (*(cinfo)->err->error_exit) ((j_common_ptr) (cinfo)))
#define ERREXIT1(cinfo,code,p1)  \
  ((cinfo)->err->msg_code = (code), \
   (cinfo)->err->msg_parm.i[0] = (p1), \
   (*(cinfo)->err->error_exit) ((j_common_ptr) (cinfo)))
#define ERREXIT2(cinfo,code,p1,p2)  \
  ((cinfo)->err->msg_code = (code), \
   (cinfo)->err->msg_parm.i[0] = (p1), \
   (cinfo)->err->msg_parm.i[1] = (p2), \
   (*(cinfo)->err->error_exit) ((j_common_ptr) (cinfo)))
#define ERREXIT3(cinfo,code,p1,p2,p3)  \
  ((cinfo)->err->msg_code = (code), \
   (cinfo)->err->msg_parm.i[0] = (p1), \
   (cinfo)->err->msg_parm.i[1] = (p2), \
   (cinfo)->err->msg_parm.i[2] = (p3), \
   (*(cinfo)->err->error_exit) ((j_common_ptr) (cinfo)))
#define ERREXIT4(cinfo,code,p1,p2,p3,p4)  \
  ((cinfo)->err->msg_code = (code), \
   (cinfo)->err->msg_parm.i[0] = (p1), \
   (cinfo)->err->msg_parm.i[1] = (p2), \
   (cinfo)->err->msg_parm.i[2] = (p3), \
   (cinfo)->err->msg_parm.i[3] = (p4), \
   (*(cinfo)->err->error_exit) ((j_common_ptr) (cinfo)))
#define ERREXIT6(cinfo,code,p1,p2,p3,p4,p5,p6)  \
  ((cinfo)->err->msg_code = (code), \
   (cinfo)->err->msg_parm.i[0] = (p1), \
   (cinfo)->err->msg_parm.i[1] = (p2), \
   (cinfo)->err->msg_parm.i[2] = (p3), \
   (cinfo)->err->msg_parm.i[3] = (p4), \
   (cinfo)->err->msg_parm.i[4] = (p5), \
   (cinfo)->err->msg_parm.i[5] = (p6), \
   (*(cinfo)->err->error_exit) ((j_common_ptr) (cinfo)))
#define ERREXITS(cinfo,code,str)  \
  ((cinfo)->err->msg_code = (code), \
   strncpy((cinfo)->err->msg_parm.s, (str), JMSG_STR_PARM_MAX), \
   (*(cinfo)->err->error_exit) ((j_common_ptr) (cinfo)))



#define MAKESTMT(stuff)		do { stuff } while (0)
#define TRACEMS(cinfo,lvl,code)  \
  ((cinfo)->err->msg_code = (code), \
   (*(cinfo)->err->emit_message) ((j_common_ptr) (cinfo), (lvl)))
#define TRACEMS1(cinfo,lvl,code,p1)  \
  ((cinfo)->err->msg_code = (code), \
   (cinfo)->err->msg_parm.i[0] = (p1), \
   (*(cinfo)->err->emit_message) ((j_common_ptr) (cinfo), (lvl)))
#define TRACEMS2(cinfo,lvl,code,p1,p2)  \
  ((cinfo)->err->msg_code = (code), \
   (cinfo)->err->msg_parm.i[0] = (p1), \
   (cinfo)->err->msg_parm.i[1] = (p2), \
   (*(cinfo)->err->emit_message) ((j_common_ptr) (cinfo), (lvl)))
#define TRACEMS3(cinfo,lvl,code,p1,p2,p3)  \
  MAKESTMT(int * _mp = (cinfo)->err->msg_parm.i; \
	   _mp[0] = (p1); _mp[1] = (p2); _mp[2] = (p3); \
	   (cinfo)->err->msg_code = (code); \
	   (*(cinfo)->err->emit_message) ((j_common_ptr) (cinfo), (lvl)); )
#define TRACEMS4(cinfo,lvl,code,p1,p2,p3,p4)  \
  MAKESTMT(int * _mp = (cinfo)->err->msg_parm.i; \
	   _mp[0] = (p1); _mp[1] = (p2); _mp[2] = (p3); _mp[3] = (p4); \
	   (cinfo)->err->msg_code = (code); \
	   (*(cinfo)->err->emit_message) ((j_common_ptr) (cinfo), (lvl)); )
#define TRACEMS5(cinfo,lvl,code,p1,p2,p3,p4,p5)  \
  MAKESTMT(int * _mp = (cinfo)->err->msg_parm.i; \
	   _mp[0] = (p1); _mp[1] = (p2); _mp[2] = (p3); _mp[3] = (p4); \
	   _mp[4] = (p5); \
	   (cinfo)->err->msg_code = (code); \
	   (*(cinfo)->err->emit_message) ((j_common_ptr) (cinfo), (lvl)); )
#define TRACEMS8(cinfo,lvl,code,p1,p2,p3,p4,p5,p6,p7,p8)  \
  MAKESTMT(int * _mp = (cinfo)->err->msg_parm.i; \
	   _mp[0] = (p1); _mp[1] = (p2); _mp[2] = (p3); _mp[3] = (p4); \
	   _mp[4] = (p5); _mp[5] = (p6); _mp[6] = (p7); _mp[7] = (p8); \
	   (cinfo)->err->msg_code = (code); \
	   (*(cinfo)->err->emit_message) ((j_common_ptr) (cinfo), (lvl)); )
#define TRACEMSS(cinfo,lvl,code,str)  \
  ((cinfo)->err->msg_code = (code), \
   strncpy((cinfo)->err->msg_parm.s, (str), JMSG_STR_PARM_MAX), \
   (*(cinfo)->err->emit_message) ((j_common_ptr) (cinfo), (lvl)))
#define WARNMS(cinfo,code)  \
  ((cinfo)->err->msg_code = (code), \
   (*(cinfo)->err->emit_message) ((j_common_ptr) (cinfo), -1))
#define WARNMS1(cinfo,code,p1)  \
  ((cinfo)->err->msg_code = (code), \
   (cinfo)->err->msg_parm.i[0] = (p1), \
   (*(cinfo)->err->emit_message) ((j_common_ptr) (cinfo), -1))
#define WARNMS2(cinfo,code,p1,p2)  \
  ((cinfo)->err->msg_code = (code), \
   (cinfo)->err->msg_parm.i[0] = (p1), \
   (cinfo)->err->msg_parm.i[1] = (p2), \
   (*(cinfo)->err->emit_message) ((j_common_ptr) (cinfo), -1))
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
# define STRIP_SIZE_DEFAULT 8192
#define TIFFArrayCount(a) (sizeof (a) / sizeof ((a)[0]))
#define TIFFSafeMultiply(t,v,m) ((((t)m != (t)0) && (((t)((v*m)/m)) == (t)v)) ? (t)(v*m) : (t)0)
#define TIFFhowmany(x, y) (((uint32)x < (0xffffffff - (uint32)(y-1))) ?	\
			   ((((uint32)(x))+(((uint32)(y))-1))/((uint32)(y))) : \
			   0U)
#define TIFFhowmany8(x) (((x)&0x07)?((uint32)(x)>>3)+1:(uint32)(x)>>3)
#define TIFFmax(A,B) ((A)>(B)?(A):(B))
#define TIFFmin(A,B) ((A)<(B)?(A):(B))
# define assert(x) 
#define    streq(a,b)      (strcmp(a,b) == 0)
#define BITFIELDn(tif, n)		((tif)->tif_dir.td_fieldsset[(n)/32]) 
#define BITn(n)				(((unsigned long)1L)<<((n)&0x1f)) 
#define TIFFClrFieldBit(tif, field)	(BITFIELDn(tif, field) &= ~BITn(field))
#define TIFFFieldSet(tif, field)	(BITFIELDn(tif, field) & BITn(field)) 
#define TIFFSetFieldBit(tif, field)	(BITFIELDn(tif, field) |= BITn(field))
#define _TIFFFindFieldInfoByName    TIFFFindFieldInfoByName
#    define AVOID_WIN32_FILEIO
#define CIELABTORGB_TABLE_RANGE 1500
#define D50_X0 (96.4250F)
#define D50_Y0 (100.0F)
#define D50_Z0 (82.4680F)
#define D65_X0 (95.0470F)
#define D65_Y0 (100.0F)
#define D65_Z0 (108.8827F)
#define FIELD_CUSTOM    65    
# define VC_EXTRALEAN

#  define __attribute__(x) 
#define TIFFLIB_VERSION 20100615
﻿#define TIFFLIB_VERSION_STR "LIBTIFF, Version 3.9.4\nCopyright (c) 1988-1996 Sam Leffler\nCopyright (c) 1991-1996 Silicon Graphics, Inc."
#define     COMPRESSION_ADOBE_DEFLATE   8       
#define     COMPRESSION_CCITT_T4        3       
#define     COMPRESSION_CCITT_T6        4       
#define     COMPRESSION_DCS             32947   
#define     COMPRESSION_JP2000          34712   
#define     DCSIMAGERFILTER_CFA         2       
#define     DCSIMAGERFILTER_IR          0       
#define     DCSIMAGERFILTER_MONO        1       
#define     DCSIMAGERFILTER_OTHER       3       
#define     DCSIMAGERMODEL_M3           0       
#define     DCSIMAGERMODEL_M5           1       
#define     DCSIMAGERMODEL_M6           2       
#define     DCSINTERPMODE_NORMAL        0x0     
#define     DCSINTERPMODE_PREVIEW       0x1     
#define EXIFTAG_DEVICESETTINGDESCRIPTION 41995	
#define EXIFTAG_FOCALPLANERESOLUTIONUNIT 41488	
#define EXIFTAG_SPATIALFREQUENCYRESPONSE 41484	
#define	    JPEGTABLESMODE_QUANT 0x0001		
#define TIFFTAG_DCSBALANCEARRAY         65552   
#define TIFFTAG_DCSCALIBRATIONFD        65556   
#define TIFFTAG_DCSCORRECTMATRIX        65553   
#define TIFFTAG_DCSGAMMA                65554   
#define TIFFTAG_DCSHUESHIFTVALUES       65535   
#define TIFFTAG_DCSIMAGERTYPE           65550   
#define TIFFTAG_DCSINTERPMODE           65551   
#define TIFFTAG_DCSTOESHOULDERPTS       65555   
#define TIFFTAG_FRAMECOUNT              34232   
#define TIFFTAG_IT8BITSPEREXTENDEDRUNLENGTH 34021
#define TIFFTAG_IT8COLORCHARACTERIZATION 34029	
#define TIFFTAG_IT8TRANSPARENCYINDICATOR 34028	
#define TIFFTAG_PIXAR_IMAGEFULLLENGTH   33301   
#define TIFFTAG_PIXAR_IMAGEFULLWIDTH    33300   
#define TIFFTAG_PIXAR_MATRIX_WORLDTOCAMERA 33306
#define TIFFTAG_PIXAR_MATRIX_WORLDTOSCREEN 33305
#define TIFFTAG_T6OPTIONS               293     
#define TIFFTAG_WRITERSERIALNUMBER      33405   
#define TIFF_BIGTIFF_VERSION    43
#define CCITT_SUPPORT 1
#define CHECK_JPEG_YCBCR_SUBSAMPLING 1


#define DEFAULT_EXTRASAMPLE_AS_ALPHA 1
#define HAVE_IEEEFP 1
#define HOST_BIGENDIAN 0
#define HOST_FILLORDER FILLORDER_LSB2MSB


#define JPEG_SUPPORT 1
#define LOGLUV_SUPPORT 1
#define LZW_SUPPORT 1
#define NEXT_SUPPORT 1
#define OJPEG_SUPPORT 1
#define PACKBITS_SUPPORT 1

#define SIZEOF_INT 4
#define SIZEOF_LONG 4
#define STRIPCHOP_DEFAULT TIFF_STRIPCHOP
#define SUBIFD_SUPPORT 1
#define THUNDER_SUPPORT 1
#define TIFF_INT64_FORMAT "%lld"
#define TIFF_INT64_T signed __int64
#define TIFF_UINT64_FORMAT "%I64u"
#define TIFF_UINT64_T unsigned __int64

#define ZIP_SUPPORT 1

#define HAVE_ASSERT_H 1
#define HAVE_FCNTL_H 1
#define HAVE_IEEEFP 1
#define HAVE_IO_H 1
#define HAVE_JBG_NEWLEN 1
#define HAVE_SEARCH_H 1
#define HAVE_SETMODE 1
#define HAVE_STRING_H 1
#define HAVE_SYS_TYPES_H 1
#define HOST_FILLORDER FILLORDER_LSB2MSB
#define SIZEOF_INT 4
#define SIZEOF_LONG 4
#define TIFF_INT64_T signed __int64
#define TIFF_UINT64_T unsigned __int64
#define lfind _lfind
