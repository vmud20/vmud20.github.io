




#include<stdint.h>



#include<stdio.h>



#include<stdarg.h>









#include<stddef.h>


# define APTR JPG_APTR
# define CPTR JPG_CPTR
#define FALSE JPG_FALSE
#     define HAVE_QUAD
#   define IS_64BIT_CODE
#define MAX_BYTE 0x7f
#define MAX_DOUBLE HUGE_VAL
# define MAX_LONG JPG_MAX_LONG
#define MAX_QUAD  ((QUAD)((MAX_UQUAD)>>1))
#define MAX_UBYTE 0xff
# define MAX_ULONG JPG_MAX_ULONG
#define MAX_UQUAD ((UQUAD)((QUAD)(-1L)))
#define MAX_UWORD 0xffff
#define MAX_WORD 0x7fff
#define MIN_BYTE -0x80
# define MIN_LONG JPG_MIN_LONG
#define MIN_QUAD  (-MAX_QUAD-1)
#define MIN_UBYTE 0x00
# define MIN_ULONG JPG_MIN_ULONG
#define MIN_UQUAD 0x0
#define MIN_UWORD 0x0000
#define MIN_WORD -0x8000
#  define NULL (__null)
#define TRUE JPG_TRUE

#define ACCUSOFT_CODE 1
#  define ALWAYS_INLINE __attribute__ ((always_inline))
#define AMBIGIOUS_NEW_BUG 1

#   define FORCEINLINE __forceinline
#  define FORCE_ALIGNED __attribute__ ((aligned))
#define HAS_CONST_CAST 1
#define HAS_PTRDIFF_T 1
#define HAS_REINTERPRET_CAST 1
#define HAS_STDERR_FILENO 1
#define HAS_STDIN_FILENO 1
#define HAS_STDOUT_FILENO 1
# define HAS__NULL_TYPE 1
#     define HAVE_ASM_BLOCKDEC
#     define HAVE_ASM_COLORTRAFO
#     define HAVE_ASM_QUANTIZER
#     define HAVE_ASM_TRANSFORMER
#define HAVE_ASSERT_H 1
#define HAVE_CLOCK 1
#define HAVE_CLOSE 1
#     define HAVE_CPU_ID
#define HAVE_CTYPE_H 1
#define HAVE_CYTPE_H 1
#define HAVE_ERRNO_H 1
#define HAVE_FCNTL_H 1
#define HAVE_FREE 1
#define HAVE_GETTICKCOUNT 1
#define HAVE_GETTIMEOFDAY 1
#define HAVE_HTONL 1
#define HAVE_HTONS 1
#define HAVE_IO_H 1
#define HAVE_ISSPACE 1
#define HAVE_LONGJMP 1
#define HAVE_MALLOC 1
#define HAVE_MATH_H 1
#define HAVE_MEMCHR 1
#define HAVE_MEMMOVE 1
#define HAVE_MEMSET 1
#define HAVE_NETINET_IN_H 1
#define HAVE_NORETURN 1
#define HAVE_NTOHL 1
#define HAVE_NTOHS 1
#define HAVE_OPEN 1
#define HAVE_READ 1
#define HAVE_RENAME 1
#define HAVE_SETJMP 1
#define HAVE_SETJMP_H 1
# define HAVE_SIGNAL 1
# define HAVE_SIGNAL_H 1
# define HAVE_SIGSEGV 1
#define HAVE_SLEEP 1
# define HAVE_SNPRINTF 1
#define HAVE_STDARG_H 1
#define HAVE_STDDEF_H 1
#define HAVE_STDIO_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STRCHR 1
#define HAVE_STRERROR 1
#define HAVE_STRING_H 1
#define HAVE_STRRCHR 1
#define HAVE_STRTOD 1
#define HAVE_STRTOL 1
#define HAVE_SYSTEM 1
#define HAVE_TIME_H 1
#define HAVE_UNISTD_H 1
# define HAVE_VSNPRINTF 1
#define HAVE_WINDOWS_H 1
#define HAVE_WRITE 1
#define HAVE__LSEEKI64 1
#define ISO_CODE 1
#   define JPG_EXPORT __attribute__ ((visibility ("default")))
#  define JPG_HIDDEN
#define JPG_LIL_ENDIAN 1
# define NATURAL_ALIGNMENT 4
# define NONALIASED __restrict__
#  define NORETURN       __attribute__ ((noreturn))
#define PCYCLES_AVAILABLE 1
#define SIZEOF_CHAR 1
#define SIZEOF_INT 4
# define SIZEOF_LONG 4
# define SIZEOF_LONG_LONG 8
#define SIZEOF_SHORT 2
#   define SIZEOF___INT64 8
#define STD_HEADERS 1
#define TIME_WITH_SYS_TIME 1
#   define TYPE_CDECL __cdecl
# define USE_I386_XADD
# define USE_INTERLOCKED
#define USE_NT_MUTEXES 1
#define USE_NT_SEMAPHORES 1
#define USE_NT_THREADS 1
# define USE_PENTIUM_TSC 1

#define BORROW_NEW(base) \
public:  \
void *operator new(size_t size,class Environ *env) { return base::operator new(size,env); } \
void operator delete(void *obj) { base::operator delete(obj); } \
private:

#define JPG_CATCH else {
#define JPG_ENDTRY } __exc__.Unlink();}
#define JPG_FREE(x)    m_pEnviron->FreeVec(x)
#define JPG_MALLOC(x)  m_pEnviron->AllocVec(x)
#define JPG_RETHROW m_pEnviron->ReThrow()
#define JPG_RETURN __exc__.Unlink();return;
#define JPG_THROW(err,obj,des) m_pEnviron->Throw(JPGERR_ ## err,obj,"__LINE__","__FILE__",des)
#define JPG_THROW_INT(err,obj,des) m_pEnviron->Throw(err, obj, "__LINE__", "__FILE__", des)
#define JPG_TRY                                \
{ class ExceptionStack __exc__(m_pEnviron);    \
  __exc__.m_pFile = "__FILE__";                  \
  __exc__.m_iLine = "__LINE__";                  \
  m_pEnviron->TestCaller();                    \
  if (likely(setjmp(__exc__.m_JumpDestination) == 0))
#define JPG_WARN(err,obj,des) m_pEnviron->Warn(JPGERR_ ## err,obj,"__LINE__","__FILE__",des)
#define NOREF(x) do {const void *y = &x;y=y;} while(0)
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)


#define JPGERR_BAD_STREAM          -1033
#define JPGERR_DOUBLE_MARKER       -1037
#define JPGERR_INVALID_HUFFMAN     -1042
#define JPGERR_INVALID_PARAMETER   -1024
#define JPGERR_MALFORMED_STREAM    -1038
#define JPGERR_MISSING_PARAMETER   -1032
#define JPGERR_NOT_AVAILABLE       -1029
#define JPGERR_NOT_IMPLEMENTED     -1034
#define JPGERR_NOT_IN_PROFILE      -1040
#define JPGERR_NO_JPG              -1036
#define JPGERR_OBJECT_DOESNT_EXIST -1031
#define JPGERR_OBJECT_EXISTS       -1030
#define JPGERR_OPERATION_UNIMPLEMENTED -1034
#define JPGERR_OUT_OF_MEMORY       -2048
#define JPGERR_OVERFLOW_PARAMETER  -1028
#define JPGERR_PHASE_ERROR         -1035
#define JPGERR_STREAM_EMPTY        -1027
#define JPGERR_THREAD_ABORTED      -1041
#define JPGERR_UNEXPECTED_EOB      -1026
#define JPGERR_UNEXPECTED_EOF      -1025
#define JPGERR_USER_ERROR         -8192
#define JPGFLAG_ACTION_QUERY 'Q'  
#define JPGFLAG_ACTION_READ  'R'  
#define JPGFLAG_ACTION_SEEK  'S'  
#define JPGFLAG_ACTION_WRITE 'W'  
#define JPGFLAG_ALPHA_MATTEREMOVAL 3
#define JPGFLAG_ALPHA_OPAQUE 0
#define JPGFLAG_ALPHA_PREMULTIPLIED 2
#define JPGFLAG_ALPHA_REGULAR 1
#define JPGFLAG_ARITHMETIC 8
#define JPGFLAG_BASELINE 0
#define JPGFLAG_BIO_RELEASE 'r'
#define JPGFLAG_BIO_REQUEST 'R'
#define JPGFLAG_DECODER_STOP_FRAME  0x08
#define JPGFLAG_DECODER_STOP_IMAGE  0x10
#define JPGFLAG_DECODER_STOP_MCU    0x01
#define JPGFLAG_DECODER_STOP_ROW    0x02
#define JPGFLAG_DECODER_STOP_SCAN   0x04
#define JPGFLAG_ENCODER_STOP_FRAME JPGFLAG_DECODER_STOP_FRAME
#define JPGFLAG_ENCODER_STOP_IMAGE JPGFLAG_DECODER_STOP_IMAGE
#define JPGFLAG_ENCODER_STOP_MCU   JPGFLAG_DECODER_STOP_MCU
#define JPGFLAG_ENCODER_STOP_ROW   JPGFLAG_DECODER_STOP_ROW
#define JPGFLAG_ENCODER_STOP_SCAN  JPGFLAG_DECODER_STOP_SCAN
#define JPGFLAG_FIXPOINT_PRESHIFT 13
#define JPGFLAG_JPEG_LS 4
#define JPGFLAG_LOSSLESS 3
#define JPGFLAG_MATRIX_COLORTRANSFORMATION_FREEFORM 3
#define JPGFLAG_MATRIX_COLORTRANSFORMATION_LSRCT 2
#define JPGFLAG_MATRIX_COLORTRANSFORMATION_NONE 0
#define JPGFLAG_MATRIX_COLORTRANSFORMATION_RCT 2
#define JPGFLAG_MATRIX_COLORTRANSFORMATION_YCBCR 1
#define JPGFLAG_OFFSET_BEGINNING -1  
#define JPGFLAG_OFFSET_CURRENT    0  
#define JPGFLAG_OFFSET_END        1  
#define JPGFLAG_OPTIMIZE_HUFFMAN 128
#define JPGFLAG_PROFILE_HDR_ADDITIVE   0x78726164
#define JPGFLAG_PROFILE_HDR_REFINEMENT 0x78727266
#define JPGFLAG_PROFILE_IDR            0x69726670
#define JPGFLAG_PROFILE_LOSSLESS       0x6c736670
#define JPGFLAG_PROGRESSIVE 2
#define JPGFLAG_PYRAMIDAL 16
#define JPGFLAG_QUANTIZATION_AHUMADA1         7
#define JPGFLAG_QUANTIZATION_AHUMADA2         8
#define JPGFLAG_QUANTIZATION_ANNEX_K          0
#define JPGFLAG_QUANTIZATION_CUSTOM           -1
#define JPGFLAG_QUANTIZATION_DCTUNE           6
#define JPGFLAG_QUANTIZATION_FLAT             1
#define JPGFLAG_QUANTIZATION_HVS              4
#define JPGFLAG_QUANTIZATION_KLEIN            5
#define JPGFLAG_QUANTIZATION_SSIM             2
#define JPGFLAG_QUANTZATION_IMAGEMAGICK       3
#define JPGFLAG_RESIDUAL 5
#define JPGFLAG_RESIDUALDCT 7
#define JPGFLAG_RESIDUALPROGRESSIVE 6
#define JPGFLAG_RESIDUAL_CODING 64
#define JPGFLAG_SCAN_LS_INTERLEAVING_LINE 1
#define JPGFLAG_SCAN_LS_INTERLEAVING_NONE 0
#define JPGFLAG_SCAN_LS_INTERLEAVING_SAMPLE 2
#define JPGFLAG_SEQUENTIAL 1
#define JPGFLAG_TONEMAPPING_CONSTANT 1
#define JPGFLAG_TONEMAPPING_EXPONENTIAL 6
#define JPGFLAG_TONEMAPPING_GAMMA 4
#define JPGFLAG_TONEMAPPING_IDENTITY 2
#define JPGFLAG_TONEMAPPING_LINEAR 5
#define JPGFLAG_TONEMAPPING_LOGARITHMIC 7
#define JPGFLAG_TONEMAPPING_LUT 0x10
#define JPGFLAG_TONEMAPPING_POWER 8
#define JPGFLAG_TONEMAPPING_ZERO 0
#define JPGTAG_ALPHA_BASE   (JPGTAG_TAG_USER + 0x4000)
#define JPGTAG_ALPHA_MATTE(n) (JPGTAG_ALPHA_BASE + 0x03 + n)
#define JPGTAG_ALPHA_MODE   (JPGTAG_ALPHA_BASE + 0x02)
#define JPGTAG_ALPHA_TAGLIST (JPGTAG_ALPHA_BASE + 0x01)
#define JPGTAG_APP_BASE (JPGTAG_TAG_USER + 0x10000)
#define JPGTAG_BIH_ALPHAHOOK (JPGTAG_BIH_BASE + 0x03)
#define JPGTAG_BIH_BASE      (JPGTAG_TAG_USER + 0x500)
#define JPGTAG_BIH_HOOK      (JPGTAG_BIH_BASE + 0x01)
#define JPGTAG_BIH_LDRHOOK   (JPGTAG_BIH_BASE + 0x02)
#define JPGTAG_BIO_ACTION (JPGTAG_BIO_BASE + 65)
#define JPGTAG_BIO_ALPHA     (JPGTAG_BIO_BASE + 30)
#define JPGTAG_BIO_BASE    (JPGTAG_TAG_USER + 0x400)
#define JPGTAG_BIO_BYTESPERPIXEL (JPGTAG_BIO_BASE + 5)
#define JPGTAG_BIO_BYTESPERROW (JPGTAG_BIO_BASE + 4)
#define JPGTAG_BIO_COMPONENT (JPGTAG_BIO_BASE + 32)
#define JPGTAG_BIO_HEIGHT  (JPGTAG_BIO_BASE + 3)
#define JPGTAG_BIO_MAXX   (JPGTAG_BIO_BASE + 18)
#define JPGTAG_BIO_MAXY   (JPGTAG_BIO_BASE + 19)
#define JPGTAG_BIO_MEMORY  (JPGTAG_BIO_BASE + 1)
#define JPGTAG_BIO_MINX   (JPGTAG_BIO_BASE + 16)
#define JPGTAG_BIO_MINY   (JPGTAG_BIO_BASE + 17)
#define JPGTAG_BIO_PIXELTYPE (JPGTAG_BIO_BASE + 6)
#define JPGTAG_BIO_PIXEL_MAXX (JPGTAG_BIO_BASE + 26)
#define JPGTAG_BIO_PIXEL_MAXY (JPGTAG_BIO_BASE + 27)
#define JPGTAG_BIO_PIXEL_MINX (JPGTAG_BIO_BASE + 24)
#define JPGTAG_BIO_PIXEL_MINY (JPGTAG_BIO_BASE + 25)
#define JPGTAG_BIO_PIXEL_XORG (JPGTAG_BIO_BASE + 28)
#define JPGTAG_BIO_PIXEL_YORG (JPGTAG_BIO_BASE + 29)
#define JPGTAG_BIO_RANGE (JPGTAG_BIO_BASE + 36) 
#define JPGTAG_BIO_ROI       (JPGTAG_BIO_BASE + 33)
#define JPGTAG_BIO_USERDATA (JPGTAG_BIO_BASE + 64)
#define JPGTAG_BIO_WIDTH   (JPGTAG_BIO_BASE + 2)
#define JPGTAG_DEADZONE_QUANTIZER        (JPGTAG_IMAGE_BASE + 0x19)
#define JPGTAG_DECODER_BASE            (JPGTAG_TAG_USER + 0xf00)
#define JPGTAG_DECODER_INCLUDE_ALPHA   (JPGTAG_DECODER_BASE + 0x16)
#define JPGTAG_DECODER_MAXCOMPONENT    (JPGTAG_DECODER_BASE + 0x06)
#define JPGTAG_DECODER_MAXX            (JPGTAG_DECODER_BASE + 0x03)
#define JPGTAG_DECODER_MAXY            (JPGTAG_DECODER_BASE + 0x04)
#define JPGTAG_DECODER_MINCOMPONENT    (JPGTAG_DECODER_BASE + 0x05)
#define JPGTAG_DECODER_MINX            (JPGTAG_DECODER_BASE + 0x01)
#define JPGTAG_DECODER_MINY            (JPGTAG_DECODER_BASE + 0x02)
#define JPGTAG_DECODER_STOP             (JPGTAG_DECODER_BASE + 0x20)
#define JPGTAG_DECODER_UPSAMPLE        (JPGTAG_DECODER_BASE + 0x08)
#define JPGTAG_ENCODER_BASE            (JPGTAG_TAG_USER + 0xf80)
#define JPGTAG_ENCODER_IMAGE_COMPLETE (JPGTAG_ENCODER_BASE + 0x01)
#define JPGTAG_ENCODER_LOOP_ON_INCOMPLETE (JPGTAG_ENCODER_BASE + 0x02)
#define JPGTAG_ENCODER_STOP JPGTAG_DECODER_STOP
#define JPGTAG_EXCEPTION_BASE  (JPGTAG_TAG_USER + 0x2100)
#define JPGTAG_EXC_CLASS       (JPGTAG_EXCEPTION_BASE + 0x02)
#define JPGTAG_EXC_DESCRIPTION (JPGTAG_EXCEPTION_BASE + 0x05)
#define JPGTAG_EXC_ERROR       (JPGTAG_EXCEPTION_BASE + 0x01)
#define JPGTAG_EXC_EXCEPTION_HOOK (JPGTAG_EXCEPTION_BASE + 0x10)
#define JPGTAG_EXC_EXCEPTION_USERDATA (JPGTAG_EXCEPTION_BASE + 0x20)
#define JPGTAG_EXC_LINE        (JPGTAG_EXCEPTION_BASE + 0x03)
#define JPGTAG_EXC_SOURCE      (JPGTAG_EXCEPTION_BASE + 0x04)
#define JPGTAG_EXC_SUPPRESS_IDENTICAL (JPGTAG_EXCEPTION_BASE + 0x30)
#define JPGTAG_EXC_WARNING_HOOK   (JPGTAG_EXCEPTION_BASE + 0x11)
#define JPGTAG_EXC_WARNING_USERDATA (JPGTAG_EXCEPTION_BASE + 0x21)
#define JPGTAG_FIO_ACTION  (JPGTAG_FIO_BASE + 4)
#define JPGTAG_FIO_BASE    (JPGTAG_TAG_USER + 0x100)
#define JPGTAG_FIO_BUFFER  (JPGTAG_FIO_BASE + 2)
#define JPGTAG_FIO_HANDLE  (JPGTAG_FIO_BASE + 1)
#define JPGTAG_FIO_OFFSET   (JPGTAG_FIO_BASE + 6)
#define JPGTAG_FIO_SEEKMODE (JPGTAG_FIO_BASE + 5)
#define JPGTAG_FIO_SIZE    (JPGTAG_FIO_BASE + 3)
#define JPGTAG_FIO_USERDATA (JPGTAG_FIO_BASE + 7)
#define JPGTAG_HOOK_BASE       (JPGTAG_TAG_USER + 0xb00)
#define JPGTAG_HOOK_BUFFER    (JPGTAG_HOOK_BASE + 0x04)
#define JPGTAG_HOOK_BUFFERSIZE (JPGTAG_HOOK_BASE + 0x03)
#define JPGTAG_HOOK_IOHOOK     (JPGTAG_HOOK_BASE + 0x01)
#define JPGTAG_HOOK_IOSTREAM   (JPGTAG_HOOK_BASE + 0x02)
#define JPGTAG_HOOK_REMAININGBYTES (JPGTAG_HOOK_BASE + 0x08)
#define JPGTAG_IMAGE_BASE     (JPGTAG_TAG_USER + 0x200)
#define JPGTAG_IMAGE_DEPTH    (JPGTAG_IMAGE_BASE + 0x03)
#define JPGTAG_IMAGE_DERINGING           (JPGTAG_IMAGE_BASE + 0x30)   
#define JPGTAG_IMAGE_ENABLE_NOISESHAPING (JPGTAG_IMAGE_BASE + 0x11)
#define JPGTAG_IMAGE_ERRORBOUND (JPGTAG_IMAGE_BASE + 0x07)
#define JPGTAG_IMAGE_FRAMETYPE (JPGTAG_IMAGE_BASE + 0x05)
#define JPGTAG_IMAGE_HEIGHT   (JPGTAG_IMAGE_BASE + 0x02)
#define JPGTAG_IMAGE_HIDDEN_DCTBITS      (JPGTAG_IMAGE_BASE + 0x12)
#define JPGTAG_IMAGE_IS_FLOAT            (JPGTAG_IMAGE_BASE + 0x13)
#define JPGTAG_IMAGE_LOSSLESSDCT         (JPGTAG_IMAGE_BASE + 0x2f)
#define JPGTAG_IMAGE_OUTPUT_CONVERSION   (JPGTAG_IMAGE_BASE + 0x17)
#define JPGTAG_IMAGE_PRECISION (JPGTAG_IMAGE_BASE + 0x04)
#define JPGTAG_IMAGE_QUALITY (JPGTAG_IMAGE_BASE + 0x06)
#define JPGTAG_IMAGE_RESOLUTIONLEVELS (JPGTAG_IMAGE_BASE + 0x08)
#define JPGTAG_IMAGE_RESTART_INTERVAL (JPGTAG_IMAGE_BASE + 0x0b)
#define JPGTAG_IMAGE_SCAN (JPGTAG_IMAGE_BASE + 0x0e)
#define JPGTAG_IMAGE_SUBLENGTH           (JPGTAG_IMAGE_BASE + 0x0f)
#define JPGTAG_IMAGE_SUBX (JPGTAG_IMAGE_BASE + 0x0c)
#define JPGTAG_IMAGE_SUBY (JPGTAG_IMAGE_BASE + 0x0d)
#define JPGTAG_IMAGE_WIDTH    (JPGTAG_IMAGE_BASE + 0x01)
#define JPGTAG_IMAGE_WRITE_DNL (JPGTAG_IMAGE_BASE + 0x0a)
#define JPGTAG_MATRIX_BASE      (JPGTAG_TAG_USER + 0x600)
#define JPGTAG_MATRIX_CFMATRIX(x,y)       (JPGTAG_MATRIX_BASE + 0x80 + (x) + (y) * 3)
#define JPGTAG_MATRIX_CMATRIX(x,y)        (JPGTAG_MATRIX_BASE + 0x70 + (x) + (y) * 3)
#define JPGTAG_MATRIX_DFMATRIX(x,y)       (JPGTAG_MATRIX_BASE + 0xb0 + (x) + (y) * 3)
#define JPGTAG_MATRIX_LFMATRIX(x,y)       (JPGTAG_MATRIX_BASE + 0x20 + (x) + (y) * 3)
#define JPGTAG_MATRIX_LMATRIX(x,y)        (JPGTAG_MATRIX_BASE + 0x10 + (x) + (y) * 3)
#define JPGTAG_MATRIX_LTRAFO    (JPGTAG_MATRIX_BASE + 0x0)
#define JPGTAG_MATRIX_PFMATRIX(x,y)       (JPGTAG_MATRIX_BASE + 0xd0 + (x) + (y) * 3)
#define JPGTAG_MATRIX_PTRAFO              (JPGTAG_MATRIX_BASE + 0xc0)
#define JPGTAG_MATRIX_RFMATRIX(x,y)       (JPGTAG_MATRIX_BASE + 0x50 + (x) + (y) * 3)
#define JPGTAG_MATRIX_RMATRIX(x,y)        (JPGTAG_MATRIX_BASE + 0x40 + (x) + (y) * 3)
#define JPGTAG_MATRIX_RTRAFO              (JPGTAG_MATRIX_BASE + 0x30)
#define JPGTAG_MEMORY_BASE (JPGTAG_TAG_USER + 0x2000)
#define JPGTAG_MIO_ALLOC_HOOK   (JPGTAG_MEMORY_BASE + 0x20)
#define JPGTAG_MIO_ALLOC_USERDATA (JPGTAG_MEMORY_BASE + 0x10)
#define JPGTAG_MIO_KEEPSIZE     (JPGTAG_MEMORY_BASE + 0x30)
#define JPGTAG_MIO_MEMORY (JPGTAG_MEMORY_BASE + 0x03)
#define JPGTAG_MIO_RELEASE_HOOK (JPGTAG_MEMORY_BASE + 0x21)
#define JPGTAG_MIO_RELEASE_USERDATA (JPGTAG_MEMORY_BASE + 0x11)
#define JPGTAG_MIO_SIZE (JPGTAG_MEMORY_BASE + 0x01)
#define JPGTAG_MIO_TYPE (JPGTAG_MEMORY_BASE + 0x02)
#define JPGTAG_OPENLOOP_ENCODER          (JPGTAG_IMAGE_BASE + 0x16)
#define JPGTAG_OPTIMIZE_QUANTIZER        (JPGTAG_IMAGE_BASE + 0x1a)
#define JPGTAG_PROFILE       (JPGTAG_PROFILE_BASE + 0x01)
#define JPGTAG_PROFILE_BASE  (JPGTAG_IMAGE_BASE + 0x50)
#define JPGTAG_QUANTIZATION_BASE      (JPGTAG_TAG_USER + 0x700)
#define JPGTAG_QUANTIZATION_CHROMATABLE      (JPGTAG_TAG_USER + 0x703)
#define JPGTAG_QUANTIZATION_LUMATABLE        (JPGTAG_TAG_USER + 0x702)
#define JPGTAG_QUANTIZATION_MATRIX    (JPGTAG_TAG_USER + 0x701)
#define JPGTAG_RESIDUALQUANT_CHROMATABLE     (JPGTAG_TAG_USER + 0x713)
#define JPGTAG_RESIDUALQUANT_LUMATABLE       (JPGTAG_TAG_USER + 0x712)
#define JPGTAG_RESIDUALQUANT_MATRIX          (JPGTAG_TAG_USER + 0x711)
#define JPGTAG_RESIDUAL_DCT              (JPGTAG_IMAGE_BASE + 0x2e)
#define JPGTAG_RESIDUAL_FRAMETYPE (JPGTAG_IMAGE_BASE + 0x45)
#define JPGTAG_RESIDUAL_HIDDEN_DCTBITS   (JPGTAG_IMAGE_BASE + 0x18)
#define JPGTAG_RESIDUAL_PRECISION (JPGTAG_IMAGE_BASE + 0x44)
#define JPGTAG_RESIDUAL_QUALITY (JPGTAG_IMAGE_BASE + 0x4f)
#define JPGTAG_RESIDUAL_SCAN (JPGTAG_IMAGE_BASE + 0x4e)
#define JPGTAG_RESIDUAL_SUBX (JPGTAG_IMAGE_BASE + 0x4c)
#define JPGTAG_RESIDUAL_SUBY (JPGTAG_IMAGE_BASE + 0x4d)
#define JPGTAG_RESIDUAL_TAGOFFSET        0x40
#define JPGTAG_SCAN_APPROXIMATION_HI (JPGTAG_SCAN_BASE + 0x09)
#define JPGTAG_SCAN_APPROXIMATION_LO (JPGTAG_SCAN_BASE + 0x08)
#define JPGTAG_SCAN_BASE (JPGTAG_TAG_USER + 0x300)
#define JPGTAG_SCAN_COMPONENT0 (JPGTAG_SCAN_BASE + 0x01)
#define JPGTAG_SCAN_COMPONENT1 (JPGTAG_SCAN_BASE + 0x02)
#define JPGTAG_SCAN_COMPONENT2 (JPGTAG_SCAN_BASE + 0x03)
#define JPGTAG_SCAN_COMPONENT3 (JPGTAG_SCAN_BASE + 0x04)
#define JPGTAG_SCAN_COMPONENTS_CHROMA (JPGTAG_SCAN_BASE + 0x05)
#define JPGTAG_SCAN_LS_INTERLEAVING  (JPGTAG_SCAN_BASE + 0x0b)
#define JPGTAG_SCAN_POINTTRANSFORM   (JPGTAG_SCAN_BASE + 0x0a)
#define JPGTAG_SCAN_SPECTRUM_START (JPGTAG_SCAN_BASE + 0x06)
#define JPGTAG_SCAN_SPECTRUM_STOP  (JPGTAG_SCAN_BASE + 0x07)
#define JPGTAG_TONEMAPPING_BASE (JPGTAG_TAG_USER + 0x1000)
#define JPGTAG_TONEMAPPING_L2_P(n,m) (JPGTAG_TONEMAPPING_BASE + 0x200 + (n<<4) + m + 1)
#define JPGTAG_TONEMAPPING_L2_TYPE(n) (JPGTAG_TONEMAPPING_BASE + 0x200 + (n<<4))
#define JPGTAG_TONEMAPPING_L_FLUT(n) (JPGTAG_TONEMAPPING_BASE + 0x100 + (n<<4) + 9)
#define JPGTAG_TONEMAPPING_L_LUT(n) (JPGTAG_TONEMAPPING_BASE + 0x100 + (n<<4) + 8)
#define JPGTAG_TONEMAPPING_L_P(n,m) (JPGTAG_TONEMAPPING_BASE + 0x100 + (n<<4) + m + 1)
#define JPGTAG_TONEMAPPING_L_ROUNDING(n) (JPGTAG_TONEMAPPING_BASE + 0x100 + (n<<4) + 10)
#define JPGTAG_TONEMAPPING_L_TYPE(n) (JPGTAG_TONEMAPPING_BASE + 0x100 + (n<<4))
#define JPGTAG_TONEMAPPING_O_P(n,m) (JPGTAG_TONEMAPPING_BASE + 0xF00 + (n<<4) + m + 1)
#define JPGTAG_TONEMAPPING_O_TYPE(n) (JPGTAG_TONEMAPPING_BASE + 0xF00 + (n<<4))
#define JPGTAG_TONEMAPPING_P_P(m) (JPGTAG_TONEMAPPING_BASE + 0x900 + m + 1)
#define JPGTAG_TONEMAPPING_P_TYPE (JPGTAG_TONEMAPPING_BASE + 0x900)
#define JPGTAG_TONEMAPPING_Q_P(n,m) (JPGTAG_TONEMAPPING_BASE + 0x400 + (n<<4) + m + 1)
#define JPGTAG_TONEMAPPING_Q_ROUNDING(n) (JPGTAG_TONEMAPPING_BASE + 0x400 + (n<<4) + 10)
#define JPGTAG_TONEMAPPING_Q_TYPE(n) (JPGTAG_TONEMAPPING_BASE + 0x400 + (n<<4))
#define JPGTAG_TONEMAPPING_R2_P(n,m) (JPGTAG_TONEMAPPING_BASE + 0x600 + (n<<4) + m + 1)
#define JPGTAG_TONEMAPPING_R2_TYPE(n) (JPGTAG_TONEMAPPING_BASE + 0x600 + (n<<4))
#define JPGTAG_TONEMAPPING_R_P(n,m) (JPGTAG_TONEMAPPING_BASE + 0x500 + (n<<4) + m + 1)
#define JPGTAG_TONEMAPPING_R_TYPE(n) (JPGTAG_TONEMAPPING_BASE + 0x500 + (n<<4))
#define JPGTAG_TONEMAPPING_S_FLUT  (JPGTAG_TONEMAPPING_BASE + 0x800 + 9)
#define JPGTAG_TONEMAPPING_S_P(m) (JPGTAG_TONEMAPPING_BASE + 0x800 + m + 1)
#define JPGTAG_TONEMAPPING_S_TYPE (JPGTAG_TONEMAPPING_BASE + 0x800)
#define JPG_MAKEID(a,b,c,d) (((JPG_ULONG(a))<<24) | ((JPG_ULONG(b))<<16) | ((JPG_ULONG(c))<<8) | ((JPG_ULONG(d))))



#define JPGTAG_SET (((JPG_ULONG)1)<<30)
#define JPGTAG_TAG_DONE   (0L)
#define JPGTAG_TAG_END    (0L)
#define JPGTAG_TAG_IGNORE (1L)
#define JPGTAG_TAG_MORE   (2L)
#define JPGTAG_TAG_SKIP   (3L)
#define JPGTAG_TAG_USER   (((JPG_ULONG)1)<<31)
#define JPG_Continue(tag)       JPG_TagItem(JPGTAG_TAG_MORE,const_cast<struct JPG_TagItem *>(tag))
#define JPG_EndTag              JPG_TagItem(JPGTAG_TAG_DONE)
#define JPG_FloatTag(id,f)      JPG_TagItem(id,(JPG_FLOAT)(f))
#define JPG_PointerTag(id,ptr)  JPG_TagItem(id,(JPG_APTR)(ptr))
#define JPG_ValueTag(id,v)      JPG_TagItem(id,(JPG_LONG)(v))




#define MAKE_ID(a,b,c,d) (((a) << 24) | ((b) << 16) | ((c) << 8) | ((d) << 0))





#  define memcpy __builtin_memcpy
#  define memmove __builtin_memmove
#  define memset __builtin_memset
#define strerror(c) "unknown error"










#   define assert(x)





# define fopen fopen64


