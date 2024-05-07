#include<stdarg.h>

#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>

#define  LEPTONICA_ALLHEADERS_H
#define LIBLEPT_MAJOR_VERSION   1
#define LIBLEPT_MINOR_VERSION   80
#define LIBLEPT_PATCH_VERSION   0
#define  LEPTONICA_ALLTYPES_H
#define  LEPTONICA_WATERSHED_H

#define  LEPTONICA_STRINGCODE_H
#define  LEPTONICA_REGUTILS_H
#define  LEPTONICA_RECOG_H
#define  RECOG_VERSION_NUMBER      2
#define  BOXAA_VERSION_NUMBER      3  
#define  BOXA_VERSION_NUMBER       2  
#define  DPIX_VERSION_NUMBER      2 
#define  FPIX_VERSION_NUMBER      2 
#define  LEPTONICA_PIX_H
#define  PIXAA_VERSION_NUMBER      2  
#define  PIXACOMP_VERSION_NUMBER 2  
#define  PIXA_VERSION_NUMBER       2  
#define   PIX_CLR      (0x0)                      
#define   PIX_DST      (0xa)                      
#define   PIX_MASK     (PIX_SRC & PIX_DST)        
#define   PIX_NOT(op)  ((op) ^ 0x0f)              
#define   PIX_PAINT    (PIX_SRC | PIX_DST)        
#define   PIX_SET      (0xf)                      
#define   PIX_SRC      (0xc)                      
#define   PIX_SUBTRACT (PIX_DST & PIX_NOT(PIX_SRC)) 
#define   PIX_XOR      (PIX_SRC ^ PIX_DST)        
#define  PTA_VERSION_NUMBER      1  
#define  KERNEL_VERSION_NUMBER    2
#define  LEPTONICA_MORPH_H
#define  SEL_VERSION_NUMBER    1
#define   JB_DATA_EXT          ".data"
#define   JB_TEMPLATE_EXT      ".templates.png"
#define  LEPTONICA_JBCLASS_H
#define  LEPTONICA_IMAGEIO_H
#define  L_FORMAT_IS_TIFF(f)  ((f) == IFF_TIFF || (f) == IFF_TIFF_PACKBITS || \
                               (f) == IFF_TIFF_RLE || (f) == IFF_TIFF_G3 || \
                               (f) == IFF_TIFF_G4 || (f) == IFF_TIFF_LZW || \
                               (f) == IFF_TIFF_ZIP || (f) == IFF_TIFF_JPEG)
#define  GPLOT_VERSION_NUMBER    1
#define  LEPTONICA_GPLOT_H
#define  NUM_GPLOT_OUTPUTS  6
#define  NUM_GPLOT_STYLES  5
#define  DEWARP_VERSION_NUMBER      4
#define  LEPTONICA_DEWARP_H
#define  LEPTONICA_COLORFILL_H
#define  LEPTONICA_CCBORD_H
#define  LEPTONICA_BMF_H
#define  CLEAR_DATA_BIT(pdata, n) \
    *((l_uint32 *)(pdata) + ((n) >> 5)) &= ~(0x80000000 >> ((n) & 31))
#define  CLEAR_DATA_DIBIT(pdata, n) \
    *((l_uint32 *)(pdata) + ((n) >> 4)) &= ~(0xc0000000 >> (2 * ((n) & 15)))
#define  CLEAR_DATA_QBIT(pdata, n) \
    *((l_uint32 *)(pdata) + ((n) >> 3)) &= ~(0xf0000000 >> (4 * ((n) & 7)))
#define  GET_DATA_BIT(pdata, n) \
    ((*((const l_uint32 *)(pdata) + ((n) >> 5)) >> (31 - ((n) & 31))) & 1)
#define  GET_DATA_BYTE(pdata, n) \
             (*((const l_uint8 *)(pdata) + (n)))
#define  GET_DATA_DIBIT(pdata, n) \
    ((*((const l_uint32 *)(pdata) + ((n) >> 4)) >> (2 * (15 - ((n) & 15)))) & 3)
#define  GET_DATA_FOUR_BYTES(pdata, n) \
             (*((const l_uint32 *)(pdata) + (n)))
#define  GET_DATA_QBIT(pdata, n) \
     ((*((const l_uint32 *)(pdata) + ((n) >> 3)) >> (4 * (7 - ((n) & 7)))) & 0xf)
#define  GET_DATA_TWO_BYTES(pdata, n) \
             (*((const l_uint16 *)(pdata) + (n)))
#define  LEPTONICA_ARRAY_ACCESS_H
#define  SET_DATA_BIT(pdata, n) \
    *((l_uint32 *)(pdata) + ((n) >> 5)) |= (0x80000000 >> ((n) & 31))
#define  SET_DATA_BIT_VAL(pdata, n, val) \
     *((l_uint32 *)(pdata) + ((n) >> 5)) = \
        ((*((l_uint32 *)(pdata) + ((n) >> 5)) \
        & (~(0x80000000 >> ((n) & 31)))) \
        | ((l_uint32)(val) << (31 - ((n) & 31))))
#define  SET_DATA_BYTE(pdata, n, val) \
             *((l_uint8 *)(pdata) + (n)) = (val)
#define  SET_DATA_DIBIT(pdata, n, val) \
     *((l_uint32 *)(pdata) + ((n) >> 4)) = \
        ((*((l_uint32 *)(pdata) + ((n) >> 4)) \
        & (~(0xc0000000 >> (2 * ((n) & 15))))) \
        | ((l_uint32)((val) & 3) << (30 - 2 * ((n) & 15))))
#define  SET_DATA_FOUR_BYTES(pdata, n, val) \
             *((l_uint32 *)(pdata) + (n)) = (val)
#define  SET_DATA_QBIT(pdata, n, val) \
     *((l_uint32 *)(pdata) + ((n) >> 3)) = \
        ((*((l_uint32 *)(pdata) + ((n) >> 3)) \
        & (~(0xf0000000 >> (4 * ((n) & 7))))) \
        | ((l_uint32)((val) & 15) << (28 - 4 * ((n) & 7))))
#define  SET_DATA_TWO_BYTES(pdata, n, val) \
             *((l_uint16 *)(pdata) + (n)) = (val)
#define  USE_INLINE_ACCESSORS    1
#define  LEPTONICA_STACK_H
#define  LEPTONICA_RBTREE_H
#define  LEPTONICA_QUEUE_H
#define  LEPTONICA_PTRA_H
#define  LEPTONICA_LIST_H
#define L_BEGIN_LIST_FORWARD(head, element) \
        { \
        DLLIST   *_leptvar_nextelem_; \
        for ((element) = (head); (element); (element) = _leptvar_nextelem_) { \
            _leptvar_nextelem_ = (element)->next;
#define L_BEGIN_LIST_REVERSE(tail, element) \
        { \
        DLLIST   *_leptvar_prevelem_; \
        for ((element) = (tail); (element); (element) = _leptvar_prevelem_) { \
            _leptvar_prevelem_ = (element)->prev;
#define L_END_LIST    }}
#define  LEPTONICA_HEAP_H
#define  LEPTONICA_BBUFFER_H
#define  DNA_VERSION_NUMBER     1
#define  LEPTONICA_ARRAY_H
#define  NUMA_VERSION_NUMBER     1
#define  SARRAY_VERSION_NUMBER     1
    #define DEFAULT_SEVERITY    MINIMUM_SEVERITY   
  #define ERROR_FLOAT(a, b, c)          ((l_float32)(c))
  #define ERROR_INT(a, b, c)            ((l_int32)(c))
  #define ERROR_PTR(a, b, c)            ((void *)(c))
#define FALSE         0
#define  HAVE_FMEMOPEN    1
#define  HAVE_FSTATAT     0
  #define  HAVE_LIBGIF        0
  #define  HAVE_LIBJP2K       0
  #define  HAVE_LIBJPEG       1
  #define  HAVE_LIBPNG        1
  #define  HAVE_LIBTIFF       1
  #define  HAVE_LIBUNGIF      0
  #define  HAVE_LIBWEBP       0
  #define  HAVE_LIBWEBP_ANIM  0
  #define  HAVE_LIBZ          1
  #define IF_SEV(l, t, f) \
      ((l) >= MINIMUM_SEVERITY && (l) >= LeptMsgSeverity ? (t) : (f))
#define  LEPTONICA_ENVIRON_H
  #define LEPT_CALLOC(numelem, elemsize)   leptonica_calloc(numelem, elemsize)
      #define LEPT_DLL __declspec(dllexport)
  #define LEPT_FREE(ptr)                   leptonica_free(ptr)
  #define LEPT_MALLOC(blocksize)           leptonica_malloc(blocksize)
  #define LEPT_REALLOC(ptr, blocksize)     leptonica_realloc(ptr, blocksize)
  #define  LIBJP2K_HEADER   <openjpeg-2.3/openjpeg.h>
#define L_ABS(x)     (((x) < 0) ? (-1 * (x)) : (x))
  #define L_ERROR(a, ...)
  #define L_INFO(a, ...)
#define L_MAX(x, y)   (((x) > (y)) ? (x) : (y))
#define L_MIN(x, y)   (((x) < (y)) ? (x) : (y))
#define L_SIGN(x)    (((x) < 0) ? -1 : 1)
  #define L_WARNING(a, ...)
    #define MINIMUM_SEVERITY    L_SEVERITY_INFO    
#define NULL          0

#define TRUE          1
#define UNDEF        -1
#define  USE_BMPIO        1
#define  USE_JP2KHEADER   1
#define  USE_PDFIO        1
#define  USE_PNMIO        1
#define  USE_PSIO         1
#define expf(x) (float)exp((double)(x))
#define powf(x, y) (float)pow((double)(x), (double)(y))
#define snprintf(buf, size, ...)  _snprintf_s(buf, size, _TRUNCATE, __VA_ARGS__)
