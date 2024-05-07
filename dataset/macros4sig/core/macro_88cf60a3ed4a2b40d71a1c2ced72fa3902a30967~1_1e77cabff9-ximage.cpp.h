
#include<stdio.h>
#include<unistd.h>



#include<arpa/inet.h>
#include<string.h>
#include<math.h>
#include<limits.h>
#include<stdlib.h>
#include<stdint.h>
#include<ctype.h>
#define MAX_COMMENT 255
#define MAX_SECTIONS 20




#define BI_BITFIELDS  3L
#define BI_RGB        0L
#define BI_RLE4       2L
#define BI_RLE8       1L
 #define CXIMAGE_SUPPORT_BASICTRANSFORMATIONS 1
 #define CXIMAGE_SUPPORT_EXIF 0
 #define CXIMAGE_SUPPORT_INTERPOLATION 1
 #define CXIMAGE_SUPPORT_JASPER 1
 #define CXIMAGE_SUPPORT_TRANSFORMATION 1
 #define CXIMAGE_SUPPORT_WINDOWS 0
 #define CXIMAGE_SUPPORT_WMF 0
 #define DLL_EXP __declspec(dllexport)
#define FALSE               0
#define GetBValue(rgb)      ((uint8_t)((rgb)>>16))
#define GetGValue(rgb)      ((uint8_t)(((uint16_t)(rgb)) >> 8))
#define GetRValue(rgb)      ((uint8_t)(rgb))
 #define PI 3.141592653589793f
#define RGB(r,g,b)          ((COLORREF)(((uint8_t)(r)|((uint16_t)((uint8_t)(g))<<8))|(((uint32_t)(uint8_t)(b))<<16)))
#define TCHAR char
#define TRUE                1


#define _cabs(c) sqrt(c.x*c.x+c.y*c.y)
  #define cx_catch catch (const char *message)
  #define cx_throw(message) throw(message)
  #define cx_try try
    #define max(a,b) (((a)>(b))?(a):(b))
    #define min(a,b) (((a)<(b))?(a):(b))
#define INT16_C(val) val##i16
#define INT16_MAX    _I16_MAX
#define INT16_MIN    ((int16_t)_I16_MIN)
#define INT32_C(val) val##i32
#define INT32_MAX    _I32_MAX
#define INT32_MIN    ((int32_t)_I32_MIN)
#define INT64_C(val) val##i64
#define INT64_MAX    _I64_MAX
#define INT64_MIN    ((int64_t)_I64_MIN)
#define INT8_C(val)  val##i8
#define INT8_MAX     _I8_MAX
#define INT8_MIN     ((int8_t)_I8_MIN)
#define INTMAX_C   INT64_C
#define INTMAX_MAX   INT64_MAX
#define INTMAX_MIN   INT64_MIN
#  define INTPTR_MAX   INT64_MAX
#  define INTPTR_MIN   INT64_MIN
#define INT_FAST16_MAX   INT16_MAX
#define INT_FAST16_MIN   INT16_MIN
#define INT_FAST32_MAX   INT32_MAX
#define INT_FAST32_MIN   INT32_MIN
#define INT_FAST64_MAX   INT64_MAX
#define INT_FAST64_MIN   INT64_MIN
#define INT_FAST8_MAX    INT8_MAX
#define INT_FAST8_MIN    INT8_MIN
#define INT_LEAST16_MAX   INT16_MAX
#define INT_LEAST16_MIN   INT16_MIN
#define INT_LEAST32_MAX   INT32_MAX
#define INT_LEAST32_MIN   INT32_MIN
#define INT_LEAST64_MAX   INT64_MAX
#define INT_LEAST64_MIN   INT64_MIN
#define INT_LEAST8_MAX    INT8_MAX
#define INT_LEAST8_MIN    INT8_MIN
#  define PTRDIFF_MAX  _I64_MAX
#  define PTRDIFF_MIN  _I64_MIN
#define SIG_ATOMIC_MAX  INT_MAX
#define SIG_ATOMIC_MIN  INT_MIN
#     define SIZE_MAX  _UI64_MAX
#define UINT16_C(val) val##ui16
#define UINT16_MAX   _UI16_MAX
#define UINT32_C(val) val##ui32
#define UINT32_MAX   _UI32_MAX
#define UINT64_C(val) val##ui64
#define UINT64_MAX   _UI64_MAX
#define UINT8_C(val)  val##ui8
#define UINT8_MAX    _UI8_MAX
#define UINTMAX_C  UINT64_C
#define UINTMAX_MAX  UINT64_MAX
#  define UINTPTR_MAX  UINT64_MAX
#define UINT_FAST16_MAX  UINT16_MAX
#define UINT_FAST32_MAX  UINT32_MAX
#define UINT_FAST64_MAX  UINT64_MAX
#define UINT_FAST8_MAX   UINT8_MAX
#define UINT_LEAST16_MAX  UINT16_MAX
#define UINT_LEAST32_MAX  UINT32_MAX
#define UINT_LEAST64_MAX  UINT64_MAX
#define UINT_LEAST8_MAX   UINT8_MAX
#  define WCHAR_MAX  _UI16_MAX
#  define WCHAR_MIN  0
#define WINT_MAX  _UI16_MAX
#define WINT_MIN  0

#     define _W64 __w64
#define CXIMAGE_DEFAULT_DPI 96
#define CXIMAGE_ERR_NOFILE "null file handler"
#define CXIMAGE_ERR_NOIMAGE "null image!!!"
#define CXIMAGE_SUPPORT_ALPHA          1
#define CXIMAGE_SUPPORT_BMP 1
#define CXIMAGE_SUPPORT_DSP            1
#define CXIMAGE_SUPPORT_EXCEPTION_HANDLING 1
#define CXIMAGE_SUPPORT_GIF 1
#define CXIMAGE_SUPPORT_ICO 1
#define CXIMAGE_SUPPORT_JBG 0		
#define CXIMAGE_SUPPORT_JP2 1
#define CXIMAGE_SUPPORT_JPC 1
#define CXIMAGE_SUPPORT_JPG 1
#define CXIMAGE_SUPPORT_MNG 1
#define CXIMAGE_SUPPORT_PCX 1
#define CXIMAGE_SUPPORT_PGX 1
#define CXIMAGE_SUPPORT_PNG 1
#define CXIMAGE_SUPPORT_PNM 1
#define CXIMAGE_SUPPORT_PSD 1
#define CXIMAGE_SUPPORT_RAS 1
#define CXIMAGE_SUPPORT_RAW 1
#define CXIMAGE_SUPPORT_SELECTION      1
#define CXIMAGE_SUPPORT_SKA 1
#define CXIMAGE_SUPPORT_TGA 1
#define CXIMAGE_SUPPORT_TIF 1
#define CXIMAGE_SUPPORT_WBMP 1
#define RGB2GRAY(r,g,b) (((b)*117 + (g)*601 + (r)*306) >> 10)


