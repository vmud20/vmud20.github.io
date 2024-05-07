


#include<stdarg.h>
#include<fcntl.h>

#include<assert.h>
#include<float.h>
#include<stdio.h>

#include<limits.h>
#include<X11/Xutil.h>
#include<X11/keysym.h>
#include<X11/Xlib.h>


#include<X11/Xatom.h>

#include<X11/Xresource.h>
#include<X11/cursorfont.h>

#include<math.h>

#include<locale.h>

#include<errno.h>


#include<signal.h>




#include<ctype.h>




#include<time.h>
#include<X11/Xos.h>


#define MaxIconSize  96
#define MaxNumberFonts  11
#define MaxNumberPens  11
#define MaxXWindows  12
#define ThrowXWindowException(severity,tag,context) \
{ \
  ExceptionInfo \
    *exception; \
 \
  exception=AcquireExceptionInfo(); \
  (void) ThrowMagickException(exception,GetMagickModule(),severity, \
    tag == (const char *) NULL ? "unknown" : tag,"`%s': %s",context, \
    strerror(errno)); \
  CatchException(exception); \
  (void) DestroyExceptionInfo(exception); \
}
#define ThrowXWindowFatalException(severity,tag,context) \
{ \
   ThrowXWindowException(severity,tag,context); \
  _exit(1); \
}
# define klass  c_class


#    define BZ_IMPORT 1





#    define MagickDLLCall __stdcall
# define gs_main_instance_DEFINED






#define MAGICK_PIXEL_RGBA  1



#define OpaqueOpacity  ((Quantum) 0UL)
#define TransparentOpacity  (QuantumRange)



#define BesselFilter JincFilter



#define RoundToQuantum(quantum)  ClampToQuantum(quantum)



#define HugeHashmapSize  131071
#define LargeHashmapSize  8191

#define MediumHashmapSize  509
#define SmallHashmapSize  17




#define AddCompositeOp       ModulusAddCompositeOp
#define DivideCompositeOp    DivideDstCompositeOp

#define MinusCompositeOp     MinusDstCompositeOp
#define SubtractCompositeOp  ModulusSubtractCompositeOp

#define MagickMaxBufferExtent  81920
#define MagickMinBufferExtent  16384





# define magick_module  _module   

#define ThrowBinaryException(severity,tag,context) \
{ \
  (void) ThrowMagickException(exception,GetMagickModule(),severity, \
    tag == (const char *) NULL ? "unknown" : tag,"`%s'",context); \
  return(MagickFalse); \
}
#define ThrowBinaryImageException(severity,tag,context) \
{ \
  if (image != (Image *) NULL) \
    (void) ThrowMagickException(&image->exception,GetMagickModule(),severity, \
       tag == (const char *) NULL ? "unknown" : tag,"`%s'",context); \
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
  (void) ThrowMagickException(fatal_exception,GetMagickModule(),severity, \
    tag == (const char *) NULL ? "unknown" : tag,"`%s'",fatal_message); \
  fatal_message=DestroyString(fatal_message); \
  CatchException(fatal_exception); \
  (void) DestroyExceptionInfo(fatal_exception); \
  MagickCoreTerminus(); \
  _exit((int) (severity-FatalErrorException)+1); \
}
#define ThrowFileException(exception,severity,tag,context) \
{ \
  char \
    *message; \
 \
  message=GetExceptionMessage(errno); \
  (void) ThrowMagickException(exception,GetMagickModule(),severity, \
    tag == (const char *) NULL ? "unknown" : tag,"`%s': %s",context,message); \
  message=DestroyString(message); \
}
#define ThrowImageException(severity,tag) \
{ \
  (void) ThrowMagickException(exception,GetMagickModule(),severity, \
    tag == (const char *) NULL ? "unknown" : tag,"`%s'",image->filename); \
  return((Image *) NULL); \
}
#define ThrowReaderException(severity,tag) \
{ \
  (void) ThrowMagickException(exception,GetMagickModule(),severity, \
    tag == (const char *) NULL ? "unknown" : tag,"`%s'",image_info->filename); \
  if ((image) != (Image *) NULL) \
    { \
      (void) CloseBlob(image); \
      image=DestroyImageList(image); \
    } \
  return((Image *) NULL); \
}
#define ThrowWriterException(severity,tag) \
{ \
  (void) ThrowMagickException(&image->exception,GetMagickModule(),severity, \
    tag == (const char *) NULL ? "unknown" : tag,"`%s'",image->filename); \
  if (image_info->adjoin != MagickFalse) \
    while (image->previous != (Image *) NULL) \
      image=image->previous; \
  (void) CloseBlob(image); \
  return(MagickFalse); \
}
# define GetMagickModule()  "__FILE__",__func__,(unsigned long) "__LINE__"

#define MagickLogFilename  "log.xml"

#define ClampPixelBlue(pixel) ClampToQuantum((pixel)->blue)
#define ClampPixelGreen(pixel) ClampToQuantum((pixel)->green)
#define ClampPixelIndex(indexes) ClampToQuantum(*(indexes))
#define ClampPixelOpacity(pixel) ClampToQuantum((pixel)->opacity)
#define ClampPixelRed(pixel) ClampToQuantum((pixel)->red)
#define GetPixelAlpha(pixel) (QuantumRange-(pixel)->opacity)
#define GetPixelBlack(indexes) (*(indexes))
#define GetPixelBlue(pixel) ((pixel)->blue)
#define GetPixelCb(pixel) ((pixel)->green)
#define GetPixelCr(pixel) ((pixel)->blue)
#define GetPixelCyan(pixel) ((pixel)->red)
#define GetPixelGray(pixel) ((pixel)->red)
#define GetPixelGreen(pixel) ((pixel)->green)
#define GetPixelIndex(indexes)  (*(indexes))
#define GetPixelL(pixel) ((pixel)->red)
#define GetPixelLabel(pixel) ((ssize_t) (pixel)->red)
#define GetPixelMagenta(pixel) ((pixel)->green)
#define GetPixelNext(pixel)  ((pixel)+1)
#define GetPixelOpacity(pixel) ((pixel)->opacity)
#define GetPixelRGB(pixel,packet) \
{ \
  (packet)->red=GetPixelRed((pixel)); \
  (packet)->green=GetPixelGreen((pixel)); \
  (packet)->blue=GetPixelBlue((pixel)); \
}
#define GetPixelRGBO(pixel,packet) \
{ \
  (packet)->red=GetPixelRed((pixel)); \
  (packet)->green=GetPixelGreen((pixel)); \
  (packet)->blue=GetPixelBlue((pixel)); \
  (packet)->opacity=GetPixelOpacity((pixel)); \
}
#define GetPixelRed(pixel) ((pixel)->red)
#define GetPixelY(pixel) ((pixel)->red)
#define GetPixelYellow(pixel) ((pixel)->blue)
#define GetPixela(pixel) ((pixel)->green)
#define GetPixelb(pixel) ((pixel)->blue)

#define SetPixelAlpha(pixel,value) \
  ((pixel)->opacity=(Quantum) (QuantumRange-(value)))
#define SetPixelBlack(indexes,value) (*(indexes)=(Quantum) (value))
#define SetPixelBlue(pixel,value) ((pixel)->blue=(Quantum) (value))
#define SetPixelCb(pixel,value) ((pixel)->green=(Quantum) (value))
#define SetPixelCr(pixel,value) ((pixel)->blue=(Quantum) (value))
#define SetPixelCyan(pixel,value) ((pixel)->red=(Quantum) (value))
#define SetPixelGray(pixel,value) \
  ((pixel)->red=(pixel)->green=(pixel)->blue=(Quantum) (value))
#define SetPixelGreen(pixel,value) ((pixel)->green=(Quantum) (value))
#define SetPixelIndex(indexes,value) (*(indexes)=(IndexPacket) (value))
#define SetPixelL(pixel,value) ((pixel)->red=(Quantum) (value))
#define SetPixelMagenta(pixel,value) ((pixel)->green=(Quantum) (value))
#define SetPixelOpacity(pixel,value) ((pixel)->opacity=(Quantum) (value))
#define SetPixelRGBA(pixel,packet) \
{ \
  SetPixelRed(pixel,(packet)->red); \
  SetPixelGreen(pixel,(packet)->green); \
  SetPixelBlue(pixel,(packet)->blue); \
  SetPixelAlpha(pixel,(QuantumRange-(packet)->opacity)); \
}
#define SetPixelRGBO(pixel,packet) \
{ \
  SetPixelRed(pixel,(packet)->red); \
  SetPixelGreen(pixel,(packet)->green); \
  SetPixelBlue(pixel,(packet)->blue); \
  SetPixelOpacity(pixel,(packet)->opacity); \
}
#define SetPixelRed(pixel,value) ((pixel)->red=(Quantum) (value))
#define SetPixelRgb(pixel,packet) \
{ \
  SetPixelRed(pixel,(packet)->red); \
  SetPixelGreen(pixel,(packet)->green); \
  SetPixelBlue(pixel,(packet)->blue); \
}
#define SetPixelY(pixel,value) ((pixel)->red=(Quantum) (value))
#define SetPixelYellow(pixel,value) ((pixel)->blue=(Quantum) (value))
#define SetPixela(pixel,value) ((pixel)->green=(Quantum) (value))
#define SetPixelb(pixel,value) ((pixel)->blue=(Quantum) (value))




#define BackgroundColor  "#ffffff"  
#define BorderColor  "#dfdfdf"  
#define DefaultResolution  72.0
#define DefaultTileFrame  "15x15+3+3"
#define DefaultTileGeometry  "120x120+4+3>"
#define DefaultTileLabel  "%f\n%G\n%b"
#define ForegroundColor  "#000"  
#define LoadImageTag  "Load/Image"
#define LoadImagesTag  "Load/Images"

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
#define PSDensityGeometry  "72.0x72.0"
#define PSPageGeometry  "612x792"
#define SaveImageTag  "Save/Image"
#define SaveImagesTag  "Save/Images"
#define TransparentColor  "#00000000"  
#define UndefinedCompressionQuality  0UL
#define UndefinedTicksPerSecond  100L
#   define DirectoryListSeparator  ';'
#   define DirectorySeparator  "\\"
# define DisableMSCWarning(nr) __pragma(warning(push)) \
  __pragma(warning(disable:nr))
#  define EditorOptions  ""
#  define Exit  exit
#  define HAVE_STRERROR
#    define HAVE_TIFFCONF_H
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
#define MAGICK_SSIZE_MAX  (SSIZE_MAX)
#define MAGICK_SSIZE_MIN  (-(SSIZE_MAX)-1)
#define MagickMaxRecursionDepth  600
#   define NAMLEN(dirent) (dirent)->d_namlen
#define O_BINARY  0x00
#define PATH_MAX  4096
# define PreferencesDefaults  "~\."
#  define ProcessPendingEvents(text)
#   define ReadCommandlLine(argc,argv)
# define RestoreMSCWarning __pragma(warning(pop))
#  define STDC
#define STDIN_FILENO  0x00
#  define S_ISDIR(mode) (((mode) & S_IFMT) == S_IFDIR)
#  define S_ISREG(mode) (((mode) & S_IFMT) == S_IFREG)
# define S_MODE (S_IRUSR | S_IWUSR)
#   define SetNotifyHandlers \
     SetFatalErrorHandler(MacFatalErrorHandler); \
     SetErrorHandler(MACErrorHandler); \
     SetWarningHandler(MACWarningHandler)
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
#  define MagickPrivate
#define MagickSignature  MagickCoreSignature
#  define MaxTextExtent  4096  
#      define ModuleExport __attribute__ ((dllexport))
#    define _MAGICKDLL_
#  define _MAGICKLIB_
#  define magick_aligned(x,y)  x __attribute__((aligned(y)))
#  define magick_alloc_size(x)  __attribute__((__alloc_size__(x)))
#  define magick_alloc_sizes(x,y)  __attribute__((__alloc_size__(x,y)))
#  define magick_attribute  __attribute__
#  define magick_cold_spot  __attribute__((__cold__))
#  define magick_hot_spot  __attribute__((__hot__))
#  define magick_unused(x)  magick_unused_ ## x __attribute__((unused))
