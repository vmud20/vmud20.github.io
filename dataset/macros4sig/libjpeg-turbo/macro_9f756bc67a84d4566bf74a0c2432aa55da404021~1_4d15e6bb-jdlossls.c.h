
#include<errno.h>
#include<stdlib.h>
#include<stddef.h>


#include<string.h>
#include<stdio.h>
#define ALLOC_DARRAY(pool_id, diffsperrow, numrows) \
  (JDIFFARRAY)(*cinfo->mem->alloc_sarray) \
    ((j_common_ptr)cinfo, pool_id, \
     (diffsperrow) * sizeof(JDIFF) / sizeof(_JSAMPLE), numrows)


#define PREDICTOR1  Ra
#define PREDICTOR2  Rb
#define PREDICTOR3  Rc
#define PREDICTOR4  (int)((JLONG)Ra + (JLONG)Rb - (JLONG)Rc)
#define PREDICTOR5  (int)((JLONG)Ra + RIGHT_SHIFT((JLONG)Rb - (JLONG)Rc, 1))
#define PREDICTOR6  (int)((JLONG)Rb + RIGHT_SHIFT((JLONG)Ra - (JLONG)Rc, 1))
#define PREDICTOR7  (int)RIGHT_SHIFT((JLONG)Ra + (JLONG)Rb, 1)

#define _CENTERJSAMPLE   CENTERJ12SAMPLE
#define _JSAMPARRAY  J12SAMPARRAY
#define _JSAMPIMAGE  J12SAMPIMAGE
#define _JSAMPLE  J12SAMPLE
#define _JSAMPROW  J12SAMPROW
#define _MAXJSAMPLE  MAXJ12SAMPLE
#define _buffer  buffer12
#define _color_convert  color_convert_12
#define _color_quantize  color_quantize_12
#define _compress_data  compress_data_12
#define _decompress_data  decompress_data_12
#define _downsample  downsample_12
#define _forward_DCT  forward_DCT_12
#define _inverse_DCT  inverse_DCT_12
#define _inverse_DCT_method_ptr  inverse_DCT_12_method_ptr
#define _jcopy_sample_rows  j12copy_sample_rows
#define _jinit_1pass_quantizer  j12init_1pass_quantizer
#define _jinit_2pass_quantizer  j12init_2pass_quantizer
#define _jinit_c_coef_controller  j12init_c_coef_controller
#define _jinit_c_diff_controller  j12init_c_diff_controller
#define _jinit_c_main_controller  j12init_c_main_controller
#define _jinit_c_prep_controller  j12init_c_prep_controller
#define _jinit_color_converter  j12init_color_converter
#define _jinit_color_deconverter  j12init_color_deconverter
#define _jinit_d_coef_controller  j12init_d_coef_controller
#define _jinit_d_diff_controller  j12init_d_diff_controller
#define _jinit_d_main_controller  j12init_d_main_controller
#define _jinit_d_post_controller  j12init_d_post_controller
#define _jinit_downsampler  j12init_downsampler
#define _jinit_forward_dct  j12init_forward_dct
#define _jinit_inverse_dct  j12init_inverse_dct
#define _jinit_lossless_compressor  j12init_lossless_compressor
#define _jinit_lossless_decompressor  j12init_lossless_decompressor
#define _jinit_merged_upsampler  j12init_merged_upsampler
#define _jinit_read_gif  j16init_read_gif
#define _jinit_read_ppm  j16init_read_ppm
#define _jinit_upsampler  j12init_upsampler
#define _jinit_write_gif  j16init_write_gif
#define _jinit_write_ppm  j16init_write_ppm
#define _jpeg_crop_scanline  jpeg12_crop_scanline
#define _jpeg_fdct_ifast  jpeg12_fdct_ifast
#define _jpeg_fdct_islow  jpeg12_fdct_islow
#define _jpeg_idct_10x10  jpeg12_idct_10x10
#define _jpeg_idct_11x11  jpeg12_idct_11x11
#define _jpeg_idct_12x12  jpeg12_idct_12x12
#define _jpeg_idct_13x13  jpeg12_idct_13x13
#define _jpeg_idct_14x14  jpeg12_idct_14x14
#define _jpeg_idct_15x15  jpeg12_idct_15x15
#define _jpeg_idct_16x16  jpeg12_idct_16x16
#define _jpeg_idct_1x1  jpeg12_idct_1x1
#define _jpeg_idct_2x2  jpeg12_idct_2x2
#define _jpeg_idct_3x3  jpeg12_idct_3x3
#define _jpeg_idct_4x4  jpeg12_idct_4x4
#define _jpeg_idct_5x5  jpeg12_idct_5x5
#define _jpeg_idct_6x6  jpeg12_idct_6x6
#define _jpeg_idct_7x7  jpeg12_idct_7x7
#define _jpeg_idct_9x9  jpeg12_idct_9x9
#define _jpeg_idct_float  jpeg12_idct_float
#define _jpeg_idct_ifast  jpeg12_idct_ifast
#define _jpeg_idct_islow  jpeg12_idct_islow
#define _jpeg_read_raw_data  jpeg12_read_raw_data
#define _jpeg_read_scanlines  jpeg12_read_scanlines
#define _jpeg_skip_scanlines  jpeg12_skip_scanlines
#define _jpeg_write_raw_data  jpeg12_write_raw_data
#define _jpeg_write_scanlines  jpeg12_write_scanlines
#define _post_process_data  post_process_data_12
#define _pre_process_data  pre_process_data_12
#define _process_data  process_data_12
#define _read_color_map  read_color_map_16
#define _upsample  upsample_12
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
   (cinfo)->err->msg_parm.s[JMSG_STR_PARM_MAX - 1] = '\0', \
   (*(cinfo)->err->error_exit) ((j_common_ptr)(cinfo)))


#define JMESSAGE(code, string)
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
   (cinfo)->err->msg_parm.s[JMSG_STR_PARM_MAX - 1] = '\0', \
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
#define IsExtRGB(cs) \
  (cs == JCS_RGB || (cs >= JCS_EXT_RGB && cs <= JCS_EXT_ARGB))
#define LEFT_SHIFT(a, b)  ((JLONG)((unsigned long)(a) << (b)))
#define MAX(a, b)       ((a) > (b) ? (a) : (b))
#define MIN(a, b)       ((a) < (b) ? (a) : (b))
#define RIGHT_SHIFT(x, shft) \
  ((shift_temp = (x)) < 0 ? \
   (shift_temp >> (shft)) | ((~((JLONG)0)) << (32 - (shft))) : \
   (shift_temp >> (shft)))
#define SHIFT_TEMPS     JLONG shift_temp;
#define BLOCK_SMOOTHING_SUPPORTED   
#define CENTERJ12SAMPLE  2048
#define CENTERJ16SAMPLE  32768
#define CENTERJSAMPLE    128
#define C_LOSSLESS_SUPPORTED        
#define C_MULTISCAN_FILES_SUPPORTED 
#define C_PROGRESSIVE_SUPPORTED     
#define DCT_FLOAT_SUPPORTED     
#define DCT_IFAST_SUPPORTED     
#define DCT_ISLOW_SUPPORTED     
#define D_LOSSLESS_SUPPORTED        
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
#define MAXJ12SAMPLE     4095
#define MAXJ16SAMPLE     65535
#define MAXJSAMPLE       255
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
#define PUTENV_S(name, value)  _putenv_s(name, value)
#define SNPRINTF  snprintf

