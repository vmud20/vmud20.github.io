

#include<limits.h>
#include<math.h>

#include<fcntl.h>







#include<stdarg.h>

#include<float.h>
#include<signal.h>




#include<stdio.h>



#include<errno.h>


#include<ctype.h>
#include<locale.h>

#include<assert.h>

#include<time.h>


#define MagickImageCoderSignature  ((size_t) \
  (((MagickLibInterface) << 8) | MAGICKCORE_QUANTUM_DEPTH))
#define MagickImageFilterSignature  ((size_t) \
  (((MagickLibInterface) << 8) | MAGICKCORE_QUANTUM_DEPTH))




#define ExponentBias  (127-15)
#define ExponentMask  0x7c00
#define ExponentShift  23

#define SignBitShift  31
#define SignificandMask  0x00000400
#define SignificandShift  13



#define OpaqueAlpha  ((Quantum) QuantumRange)
#define TransparentAlpha  ((Quantum) 0)



#define MaxPixelChannels  64


#define BesselFilter  JincFilter
#define HanningFilter HannFilter

#define WelshFilter   WelchFilter














#define MagickMaxBufferExtent  81920
#define MagickMinBufferExtent  16384






#define BackgroundColor  "#ffffff"  
#define BackgroundColorRGBA  QuantumRange,QuantumRange,QuantumRange,OpaqueAlpha
#define BorderColor  "#dfdfdf"  
#define BorderColorRGBA  ScaleShortToQuantum(0xdfdf),\
  ScaleShortToQuantum(0xdfdf),ScaleShortToQuantum(0xdfdf),OpaqueAlpha
#define DefaultResolution  72.0
#define DefaultTileFrame  "15x15+3+3"
#define DefaultTileGeometry  "120x120+4+3>"
#define DefaultTileLabel  "%f\n%G\n%b"
#define ForegroundColor  "#000"  
#define ForegroundColorRGBA  0,0,0,OpaqueAlpha
#define LoadImageTag  "Load/Image"
#define LoadImagesTag  "Load/Images"

#define MAGICK_SIZE_MAX  (SIZE_MAX)
#define MAGICK_SSIZE_MAX  (SSIZE_MAX)
#define MAGICK_SSIZE_MIN  (-(SSIZE_MAX)-1)
#define Magick2PI    6.28318530717958647692528676655900576839433879875020
#define MagickAbsoluteValue(x)  ((x) < 0 ? -(x) : (x))
#define MagickMax(x,y)  (((x) > (y)) ? (x) : (y))
#define MagickMin(x,y)  (((x) < (y)) ? (x) : (y))
#define MagickPHI    1.61803398874989484820458683436563811772030917980576
#define MagickPI  3.14159265358979323846264338327950288419716939937510
#define MagickPI2    1.57079632679489661923132169163975144209858469968755
#define MagickSQ1_2  0.70710678118654752440084436210484903928483593768847
#define MagickSQ2    1.41421356237309504880168872420969807856967187537695
#define MagickSQ2PI  2.50662827463100024161235523934010416269302368164062
#define MatteColor  "#bdbdbd"  
#define MatteColorRGBA  ScaleShortToQuantum(0xbdbd),\
  ScaleShortToQuantum(0xbdbd),ScaleShortToQuantum(0xbdbd),OpaqueAlpha
#define PSDensityGeometry  "72.0x72.0"
#define PSPageGeometry  "612x792"
#define SaveImageTag  "Save/Image"
#define SaveImagesTag  "Save/Images"
#define TransparentColor  "#00000000"  
#define TransparentColorRGBA  0,0,0,TransparentAlpha
#define UndefinedCompressionQuality  0UL
#define UndefinedTicksPerSecond  100L


# define magick_module  _module   


#define ThrowBinaryException(severity,tag,context) \
{ \
  (void) ThrowMagickException(exception,GetMagickModule(),severity,tag, \
    "`%s'",context); \
  return(MagickFalse); \
}
#define ThrowFatalException(severity,tag) \
{ \
  char \
    *fatal_message; \
 \
  ExceptionInfo \
    *fatal_exception; \
 \
  fatal_exception=AcquireExceptionInfo(); \
  fatal_message=GetExceptionMessage(errno); \
  (void) ThrowMagickException(fatal_exception,GetMagickModule(),severity,tag, \
    "`%s'",fatal_message); \
  fatal_message=DestroyString(fatal_message); \
  CatchException(fatal_exception); \
  (void) DestroyExceptionInfo(fatal_exception); \
  MagickCoreTerminus(); \
  _exit((int) (severity-FatalErrorException)+1); \
}
#define ThrowFileException(exception,severity,tag,context) \
{ \
  char \
    *file_message; \
 \
  file_message=GetExceptionMessage(errno); \
  (void) ThrowMagickException(exception,GetMagickModule(),severity,tag, \
    "'%s': %s",context,file_message); \
  file_message=DestroyString(file_message); \
}
#define ThrowImageException(severity,tag) \
{ \
  (void) ThrowMagickException(exception,GetMagickModule(),severity,tag, \
    "`%s'",image->filename); \
  return((Image *) NULL); \
}
#define ThrowReaderException(severity,tag) \
{ \
  (void) ThrowMagickException(exception,GetMagickModule(),severity,tag, \
    "`%s'",image_info->filename); \
  if ((image) != (Image *) NULL) \
    { \
      (void) CloseBlob(image); \
      image=DestroyImageList(image); \
    } \
  return((Image *) NULL); \
}
#define ThrowWriterException(severity,tag) \
{ \
  (void) ThrowMagickException(exception,GetMagickModule(),severity,tag, \
    "`%s'",image->filename); \
  if (image_info->adjoin != MagickFalse) \
    while (image->previous != (Image *) NULL) \
      image=image->previous; \
  (void) CloseBlob(image); \
  return(MagickFalse); \
}
# define GetMagickModule()  "__FILE__",__func__,(unsigned long) "__LINE__"

#define MagickLogFilename  "log.xml"



#define MagickMinBlobExtent  32767L
# define fseek  fseeko
# define ftell  ftello



#    define MagickDLLCall __stdcall
# define gs_main_instance_DEFINED

#   define DirectoryListSeparator  ';'
#   define DirectorySeparator  "\\"
# define DisableMSCWarning(nr) __pragma(warning(push)) \
  __pragma(warning(disable:nr))
#  define EditorOptions  ""
#  define Exit  exit
#  define HAVE_STRERROR
#  define IsBasenameSeparator(c) \
  (((c) == ']') || ((c) == ':') || ((c) == '/') ? MagickTrue : MagickFalse)
# define MAGICKCORE_BUILD_MODULES
# define MAGICKCORE_CONFIG_H
#define MAGICKCORE_IMPLEMENTATION  1
#  define MAGICKCORE_LIBRARY_PATH  "sys$login:"
#  define MAGICKCORE_MODULES_SUPPORT
#  define MAGICKCORE_OPENCL_SUPPORT  1
#  define MAGICKCORE_OPENMP_SUPPORT  1
#  define MAGICKCORE_SHARE_PATH  "sys$login:"

#  define MAGICKCORE_WINDOWS_SUPPORT
#define MagickMaxRecursionDepth  600
#   define NAMLEN(dirent) (dirent)->d_namlen
#define NDEBUG 1
#define O_BINARY  0x00
#define PATH_MAX  4096
# define PreferencesDefaults  "~\."
#  define ProcessPendingEvents(text)
#  define ReadCommandlLine(argc,argv)
# define RestoreMSCWarning __pragma(warning(pop))
#  define STDC
#define STDIN_FILENO  0x00
#  define S_ISDIR(mode) (((mode) & S_IFMT) == S_IFDIR)
#  define S_ISREG(mode) (((mode) & S_IFMT) == S_IFREG)
# define S_MODE (S_IRUSR | S_IWUSR)
#  define SetNotifyHandlers \
    SetErrorHandler(NTErrorHandler); \
    SetWarningHandler(NTWarningHandler)
#define Swap(x,y) ((x)^=(y), (y)^=(x), (x)^=(y))
#  define X11_APPLICATION_PATH  "decw$system_defaults:"
#    define X11_PREFERENCES_PATH  "~\\."

# define _FILE_OFFSET_BITS MAGICKCORE__FILE_OFFSET_BITS
# define const  _magickcore_const
#   define dirent direct
# define inline  _magickcore_inline
#  define magick_restrict restrict

#define MagickCoreSignature  0xabacadabUL
#        define MagickExport __attribute__ ((dllimport))
#  define MagickPathExtent  4096  
#  define MagickPrivate
#define MagickTimeExtent  26
#define MaxTextExtent  MagickPathExtent
#      define ModuleExport __attribute__ ((dllexport))
#    define _MAGICKDLL_
#  define _MAGICKLIB_
#  define magick_aligned(x,y)  x __attribute__((aligned(y)))
#  define magick_alloc_size(x)  __attribute__((__alloc_size__(x)))
#  define magick_alloc_sizes(x,y)  __attribute__((__alloc_size__(x,y)))
#  define magick_attribute  __attribute__
#  define magick_cold_spot  __attribute__((__cold__))
#  define magick_fallthrough  __attribute__((fallthrough))
#  define magick_hot_spot  __attribute__((__hot__))
#  define magick_unused(x)  magick_unused_ ## x __attribute__((unused))
#define MAGICKCORE_ABI_SUFFIX  "Q" MAGICKCORE_STRING_XQUOTE(MAGICKCORE_QUANTUM_DEPTH)
#define MAGICKCORE_ALIGN_DOWN(n, power_of_2) \
  ((n) & ~MAGICKCORE_BITS_BELOW(power_of_2))
#define MAGICKCORE_ALIGN_UP(n, power_of_2) \
  MAGICKCORE_ALIGN_DOWN((n) + MAGICKCORE_MAX_ALIGNMENT_PADDING(power_of_2),power_of_2)
#define MAGICKCORE_BITS_BELOW(power_of_2) \
  ((power_of_2)-1)
#  define MAGICKCORE_CODER_PATH "sys$login:"
# define MAGICKCORE_CODER_RELATIVE_PATH MAGICKCORE_MODULES_RELATIVE_PATH MAGICKCORE_DIR_SEPARATOR MAGICKCORE_CODER_DIRNAME
# define MAGICKCORE_DIAGNOSTIC_IGNORE_MAYBE_UNINITIALIZED() \
   _Pragma("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
# define MAGICKCORE_DIAGNOSTIC_POP() \
   _Pragma("GCC diagnostic pop")
# define MAGICKCORE_DIAGNOSTIC_PUSH() \
   _Pragma("GCC diagnostic push")
#  define MAGICKCORE_FILTER_PATH  "sys$login:"
# define MAGICKCORE_FILTER_RELATIVE_PATH MAGICKCORE_MODULES_RELATIVE_PATH MAGICKCORE_DIR_SEPARATOR MAGICKCORE_FILTER_DIRNAME
# define MAGICKCORE_HDRI_ENABLE MAGICKCORE_HDRI_ENABLE_OBSOLETE_IN_H
# define MAGICKCORE_HDRI_SUPPORT 1
#define MAGICKCORE_IS_NOT_ALIGNED(n, power_of_2) \
  ((n) & MAGICKCORE_BITS_BELOW(power_of_2))
#define MAGICKCORE_IS_NOT_POWER_OF_2(n) \
  MAGICKCORE_IS_NOT_ALIGNED((n), (n))

#define MAGICKCORE_MAX_ALIGNMENT_PADDING(power_of_2) \
  MAGICKCORE_BITS_BELOW(power_of_2)
# define MAGICKCORE_MODULES_DIRNAME MAGICKCORE_MODULES_BASEDIRNAME "-" MAGICKCORE_ABI_SUFFIX
#  define MAGICKCORE_MODULES_PATH MAGICKCORE_LIBRARY_PATH MAGICKCORE_DIR_SEPARATOR MAGICKCORE_MODULES_DIRNAME
#define MAGICKCORE_MODULES_RELATIVE_PATH MAGICKCORE_LIBRARY_RELATIVE_PATH MAGICKCORE_DIR_SEPARATOR MAGICKCORE_MODULES_DIRNAME
# define MAGICKCORE_QUANTUM_DEPTH MAGICKCORE_QUANTUM_DEPTH_OBSOLETE_IN_H
# define MAGICKCORE_SHAREARCH_DIRNAME MAGICKCORE_SHAREARCH_BASEDIRNAME "-" MAGICKCORE_ABI_SUFFIX
#  define MAGICKCORE_SHAREARCH_PATH MAGICKCORE_LIBRARY_PATH MAGICKCORE_DIR_SEPARATOR MAGICKCORE_SHAREARCH_DIRNAME MAGICKCORE_DIR_SEPARATOR
#define MAGICKCORE_SHAREARCH_RELATIVE_PATH MAGICKCORE_LIBRARY_RELATIVE_PATH MAGICKCORE_DIR_SEPARATOR MAGICKCORE_SHAREARCH_DIRNAME
#define MAGICKCORE_STRING_QUOTE(str) #str
#define MAGICKCORE_STRING_XQUOTE(str) MAGICKCORE_STRING_QUOTE(str)
#  define MAGICK_COMPILER_WARNING(w) _Pragma(MAGICKCORE_STRING_QUOTE(GCC warning w))
#  define __CYGWIN__  __CYGWIN32__
#  define __has_builtin(x) 0
