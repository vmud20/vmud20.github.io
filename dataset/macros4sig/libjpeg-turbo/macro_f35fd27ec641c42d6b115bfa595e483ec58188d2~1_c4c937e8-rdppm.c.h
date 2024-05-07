

#include<stddef.h>
#include<stdio.h>
#include<string.h>


#include<sys/types.h>
#include<strings.h>

#include<stdlib.h>
#define EXIT_FAILURE  1
#define EXIT_SUCCESS  0
#define EXIT_WARNING  2
#define IsExtRGB(cs) \
  (cs == JCS_RGB || (cs >= JCS_EXT_RGB && cs <= JCS_EXT_ARGB))
#define JPEG_CJPEG_DJPEG        
#define JPEG_INTERNAL_OPTIONS   
#define READ_BINARY     "r"
#define WRITE_BINARY    "w"


#define JMESSAGE(code, string)
#define ERREXIT(cinfo, code) \
  ((cinfo)->err->msg_code = (code), \
   (*(cinfo)->err->error_exit) ((j_common_ptr)(cinfo)))
#define ERREXIT1(cinfo, code, p1) \
  ((cinfo)->err->msg_code = (code), \
   (cinfo)->err->msg_parm.i[0] = (p1), \
   (*(cinfo)->err->error_exit) ((j_common_ptr)(cinfo)))
#define ERREXIT2(cinfo, code, p1, p2) \
  ((cinfo)->err->msg_code = (code), \
   (cinfo)->err->msg_parm.i[0] = (p1), \
   (cinfo)->err->msg_parm.i[1] = (p2), \
   (*(cinfo)->err->error_exit) ((j_common_ptr)(cinfo)))
#define ERREXIT3(cinfo, code, p1, p2, p3) \
  ((cinfo)->err->msg_code = (code), \
   (cinfo)->err->msg_parm.i[0] = (p1), \
   (cinfo)->err->msg_parm.i[1] = (p2), \
   (cinfo)->err->msg_parm.i[2] = (p3), \
   (*(cinfo)->err->error_exit) ((j_common_ptr)(cinfo)))
#define ERREXIT4(cinfo, code, p1, p2, p3, p4) \
  ((cinfo)->err->msg_code = (code), \
   (cinfo)->err->msg_parm.i[0] = (p1), \
   (cinfo)->err->msg_parm.i[1] = (p2), \
   (cinfo)->err->msg_parm.i[2] = (p3), \
   (cinfo)->err->msg_parm.i[3] = (p4), \
   (*(cinfo)->err->error_exit) ((j_common_ptr)(cinfo)))
#define ERREXIT6(cinfo, code, p1, p2, p3, p4, p5, p6) \
  ((cinfo)->err->msg_code = (code), \
   (cinfo)->err->msg_parm.i[0] = (p1), \
   (cinfo)->err->msg_parm.i[1] = (p2), \
   (cinfo)->err->msg_parm.i[2] = (p3), \
   (cinfo)->err->msg_parm.i[3] = (p4), \
   (cinfo)->err->msg_parm.i[4] = (p5), \
   (cinfo)->err->msg_parm.i[5] = (p6), \
   (*(cinfo)->err->error_exit) ((j_common_ptr)(cinfo)))
#define ERREXITS(cinfo, code, str) \
  ((cinfo)->err->msg_code = (code), \
   strncpy((cinfo)->err->msg_parm.s, (str), JMSG_STR_PARM_MAX), \
   (*(cinfo)->err->error_exit) ((j_common_ptr)(cinfo)))

#define MAKESTMT(stuff)         do { stuff } while (0)
#define TRACEMS(cinfo, lvl, code) \
  ((cinfo)->err->msg_code = (code), \
   (*(cinfo)->err->emit_message) ((j_common_ptr)(cinfo), (lvl)))
#define TRACEMS1(cinfo, lvl, code, p1) \
  ((cinfo)->err->msg_code = (code), \
   (cinfo)->err->msg_parm.i[0] = (p1), \
   (*(cinfo)->err->emit_message) ((j_common_ptr)(cinfo), (lvl)))
#define TRACEMS2(cinfo, lvl, code, p1, p2) \
  ((cinfo)->err->msg_code = (code), \
   (cinfo)->err->msg_parm.i[0] = (p1), \
   (cinfo)->err->msg_parm.i[1] = (p2), \
   (*(cinfo)->err->emit_message) ((j_common_ptr)(cinfo), (lvl)))
#define TRACEMS3(cinfo, lvl, code, p1, p2, p3) \
  MAKESTMT(int *_mp = (cinfo)->err->msg_parm.i; \
           _mp[0] = (p1);  _mp[1] = (p2);  _mp[2] = (p3); \
           (cinfo)->err->msg_code = (code); \
           (*(cinfo)->err->emit_message) ((j_common_ptr)(cinfo), (lvl)); )
#define TRACEMS4(cinfo, lvl, code, p1, p2, p3, p4) \
  MAKESTMT(int *_mp = (cinfo)->err->msg_parm.i; \
           _mp[0] = (p1);  _mp[1] = (p2);  _mp[2] = (p3);  _mp[3] = (p4); \
           (cinfo)->err->msg_code = (code); \
           (*(cinfo)->err->emit_message) ((j_common_ptr)(cinfo), (lvl)); )
#define TRACEMS5(cinfo, lvl, code, p1, p2, p3, p4, p5) \
  MAKESTMT(int *_mp = (cinfo)->err->msg_parm.i; \
           _mp[0] = (p1);  _mp[1] = (p2);  _mp[2] = (p3);  _mp[3] = (p4); \
           _mp[4] = (p5); \
           (cinfo)->err->msg_code = (code); \
           (*(cinfo)->err->emit_message) ((j_common_ptr)(cinfo), (lvl)); )
#define TRACEMS8(cinfo, lvl, code, p1, p2, p3, p4, p5, p6, p7, p8) \
  MAKESTMT(int *_mp = (cinfo)->err->msg_parm.i; \
           _mp[0] = (p1);  _mp[1] = (p2);  _mp[2] = (p3);  _mp[3] = (p4); \
           _mp[4] = (p5);  _mp[5] = (p6);  _mp[6] = (p7);  _mp[7] = (p8); \
           (cinfo)->err->msg_code = (code); \
           (*(cinfo)->err->emit_message) ((j_common_ptr)(cinfo), (lvl)); )
#define TRACEMSS(cinfo, lvl, code, str) \
  ((cinfo)->err->msg_code = (code), \
   strncpy((cinfo)->err->msg_parm.s, (str), JMSG_STR_PARM_MAX), \
   (*(cinfo)->err->emit_message) ((j_common_ptr)(cinfo), (lvl)))
#define WARNMS(cinfo, code) \
  ((cinfo)->err->msg_code = (code), \
   (*(cinfo)->err->emit_message) ((j_common_ptr)(cinfo), -1))
#define WARNMS1(cinfo, code, p1) \
  ((cinfo)->err->msg_code = (code), \
   (cinfo)->err->msg_parm.i[0] = (p1), \
   (*(cinfo)->err->emit_message) ((j_common_ptr)(cinfo), -1))
#define WARNMS2(cinfo, code, p1, p2) \
  ((cinfo)->err->msg_code = (code), \
   (cinfo)->err->msg_parm.i[0] = (p1), \
   (cinfo)->err->msg_parm.i[1] = (p2), \
   (*(cinfo)->err->emit_message) ((j_common_ptr)(cinfo), -1))
#define C_MAX_BLOCKS_IN_MCU   10 
#define DCTSIZE             8   
#define DCTSIZE2            64  
#define D_MAX_BLOCKS_IN_MCU   10 
#define JCS_ALPHA_EXTENSIONS  1
#define JCS_EXTENSIONS  1
#define JDCT_DEFAULT  JDCT_ISLOW
#define JDCT_FASTEST  JDCT_IFAST
#define JMSG_LENGTH_MAX  200    
#define JMSG_STR_PARM_MAX  80

#define JPEG_APP0       0xE0    
#define JPEG_COM        0xFE    
#define JPEG_EOI        0xD9    
#define JPEG_HEADER_OK           1 
#define JPEG_HEADER_TABLES_ONLY  2 
#define JPEG_REACHED_EOI        2 
#define JPEG_REACHED_SOS        1 
#define JPEG_ROW_COMPLETED      3 
#define JPEG_RST0       0xD0    
#define JPEG_SCAN_COMPLETED     4 
#define JPEG_SUSPENDED           0 
#define JPOOL_IMAGE      1      
#define JPOOL_NUMPOOLS   2
#define JPOOL_PERMANENT  0      
#define JPP(arglist)    arglist
#define MAX_COMPS_IN_SCAN   4   
#define MAX_SAMP_FACTOR     4   
#define NUM_ARITH_TBLS      16  
#define NUM_HUFF_TBLS       4   
#define NUM_QUANT_TBLS      4   
#define jpeg_common_fields \
  struct jpeg_error_mgr *err;    \
  struct jpeg_memory_mgr *mem;   \
  struct jpeg_progress_mgr *progress;  \
  void *client_data;             \
  boolean is_decompressor;       \
  int global_state              
#define jpeg_create_compress(cinfo) \
  jpeg_CreateCompress((cinfo), JPEG_LIB_VERSION, \
                      (size_t)sizeof(struct jpeg_compress_struct))
#define jpeg_create_decompress(cinfo) \
  jpeg_CreateDecompress((cinfo), JPEG_LIB_VERSION, \
                        (size_t)sizeof(struct jpeg_decompress_struct))
#define CSTATE_RAW_OK    102    
#define CSTATE_SCANNING  101    
#define CSTATE_START     100    
#define CSTATE_WRCOEFS   103    
#define DSTATE_BUFIMAGE  207    
#define DSTATE_BUFPOST   208    
#define DSTATE_INHEADER  201    
#define DSTATE_PRELOAD   203    
#define DSTATE_PRESCAN   204    
#define DSTATE_RAW_OK    206    
#define DSTATE_RDCOEFS   209    
#define DSTATE_READY     202    
#define DSTATE_SCANNING  205    
#define DSTATE_START     200    
#define DSTATE_STOPPING  210    
#define LEFT_SHIFT(a, b)  ((JLONG)((unsigned long)(a) << (b)))
#define MAX(a, b)       ((a) > (b) ? (a) : (b))
#define MIN(a, b)       ((a) < (b) ? (a) : (b))
#define RIGHT_SHIFT(x, shft) \
  ((shift_temp = (x)) < 0 ? \
   (shift_temp >> (shft)) | ((~((JLONG)0)) << (32 - (shft))) : \
   (shift_temp >> (shft)))
#define SHIFT_TEMPS     JLONG shift_temp;
#define BLOCK_SMOOTHING_SUPPORTED   
#define CENTERJSAMPLE   128
#define C_MULTISCAN_FILES_SUPPORTED 
#define C_PROGRESSIVE_SUPPORTED     
#define DCT_FLOAT_SUPPORTED     
#define DCT_IFAST_SUPPORTED     
#define DCT_ISLOW_SUPPORTED     
#define D_MULTISCAN_FILES_SUPPORTED 
#define D_PROGRESSIVE_SUPPORTED     
#define ENTROPY_OPT_SUPPORTED       
#define EXTERN(type)            extern type
#define EXT_BGRX_BLUE       0
#define EXT_BGRX_GREEN      1
#define EXT_BGRX_PIXELSIZE  4
#define EXT_BGRX_RED        2
#define EXT_BGR_BLUE        0
#define EXT_BGR_GREEN       1
#define EXT_BGR_PIXELSIZE   3
#define EXT_BGR_RED         2
#define EXT_RGBX_BLUE       2
#define EXT_RGBX_GREEN      1
#define EXT_RGBX_PIXELSIZE  4
#define EXT_RGBX_RED        0
#define EXT_RGB_BLUE        2
#define EXT_RGB_GREEN       1
#define EXT_RGB_PIXELSIZE   3
#define EXT_RGB_RED         0
#define EXT_XBGR_BLUE       1
#define EXT_XBGR_GREEN      2
#define EXT_XBGR_PIXELSIZE  4
#define EXT_XBGR_RED        3
#define EXT_XRGB_BLUE       3
#define EXT_XRGB_GREEN      2
#define EXT_XRGB_PIXELSIZE  4
#define EXT_XRGB_RED        1
#define FALSE   0               

#define FAST_FLOAT  float
#define GETJOCTET(value)  (value)
#define GETJSAMPLE(value)  ((int)(value))
#define GLOBAL(type)            type
#define IDCT_SCALING_SUPPORTED      
#define INPUT_SMOOTHING_SUPPORTED   
#define JMETHOD(type, methodname, arglist)  type (*methodname) arglist
#define JPEG_MAX_DIMENSION  65500L  
#define JPEG_NUMCS  17
#define LOCAL(type)             static type
#define MAXJSAMPLE      255
#define MAX_COMPONENTS  10      
#define METHODDEF(type)         static type
#define MULTIPLIER  int         
#define QUANT_1PASS_SUPPORTED       
#define QUANT_2PASS_SUPPORTED       
#define RGB_BLUE        2       
#define RGB_GREEN       1       
#define RGB_PIXELSIZE   3       
#define RGB_RED         0       
#define SAVE_MARKERS_SUPPORTED      
#define TRUE    1
#define UPSAMPLE_MERGING_SUPPORTED  
#define JCONFIG_INCLUDED        
#define JFREAD(file, buf, sizeofbuf) \
  ((size_t)fread((void *)(buf), (size_t)1, (size_t)(sizeofbuf), (file)))
#define JFWRITE(file, buf, sizeofbuf) \
  ((size_t)fwrite((const void *)(buf), (size_t)1, (size_t)(sizeofbuf), (file)))
#define MEMCOPY(dest, src, size) \
  bcopy((const void *)(src), (void *)(dest), (size_t)(size))
#define MEMZERO(target, size) \
  bzero((void *)(target), (size_t)(size))


