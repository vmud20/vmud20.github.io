




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
#include<sys/types.h>
#include<stdlib.h>







#include<signal.h>

#include<string.h>
#include<ctype.h>





#include<stdint.h>

#include<time.h>
#include<X11/Xos.h>



#define HugeHashmapSize  131071
#define LargeHashmapSize  8191

#define MediumHashmapSize  509
#define SmallHashmapSize  17


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






#define AddCompositeOp       ModulusAddCompositeOp
#define DivideCompositeOp    DivideDstCompositeOp

#define MinusCompositeOp     MinusDstCompositeOp
#define SubtractCompositeOp  ModulusSubtractCompositeOp

#define MagickMaxBufferExtent  81920
#define MagickMinBufferExtent  16384
#define AppendImageStack(images) \
{ \
  (void) SyncImagesSettings(image_info,images); \
  AppendImageToList(&image_stack[k].image,images); \
  image=image_stack[k].image; \
}
#define DestroyImageStack() \
{ \
  while (k > 0) \
    PopImageStack(); \
  image_stack[k].image=DestroyImageList(image_stack[k].image); \
  image_stack[k].image_info=DestroyImageInfo(image_stack[k].image_info); \
  image_info=image_stack[MaxImageStackDepth].image_info; \
}
#define FinalizeImageSettings(image_info,image,advance) \
{ \
  FireImageStack(MagickTrue,advance,MagickTrue); \
  if (image != (Image *) NULL) \
    { \
      InheritException(exception,&(image)->exception); \
      (void) SyncImagesSettings(image_info,image); \
    } \
}
#define FireImageStack(postfix,advance,fire) \
  if ((j <= i) && (i < (ssize_t) argc)) \
    { \
DisableMSCWarning(4127) \
      if (image_stack[k].image == (Image *) NULL) \
        status&=MogrifyImageInfo(image_stack[k].image_info,(int) (i-j+1), \
          (const char **) (argv+j),exception); \
      else \
        if ((fire) != MagickFalse) \
          { \
            status&=MogrifyImages(image_stack[k].image_info,postfix,(int) \
              (i-j+1),(const char **) (argv+j),&image_stack[k].image, \
              exception); \
            image=image_stack[k].image; \
            if ((advance) != MagickFalse) \
              j=i+1; \
            pend=MagickFalse; \
          } \
RestoreMSCWarning \
    }

#define MaxImageStackDepth  128
#define NewImageStack() \
{ \
  image_stack[MaxImageStackDepth].image_info=image_info; \
  image_stack[0].image_info=CloneImageInfo(image_info); \
  image_stack[0].image=NewImageList(); \
  image_info=image_stack[0].image_info; \
  image=image_stack[0].image; \
}
#define PopImageStack() \
{ \
  if (respect_parenthesis == MagickFalse) \
    { \
      image_stack[k-1].image_info=DestroyImageInfo(image_stack[k-1].image_info); \
      image_stack[k-1].image_info=CloneImageInfo(image_stack[k].image_info); \
    } \
  image_stack[k].image_info=DestroyImageInfo(image_stack[k].image_info); \
  AppendImageToList(&image_stack[k-1].image,image_stack[k].image); \
  k--; \
  image_info=image_stack[k].image_info; \
  image=image_stack[k].image; \
}
#define PushImageStack() \
{ \
  k++; \
  image_stack[k].image_info=CloneImageInfo(image_stack[k-1].image_info); \
  image_stack[k].image=NewImageList(); \
  image_info=image_stack[k].image_info; \
  image=image_stack[k].image; \
}
#define QuantumTick(i,span) ((MagickBooleanType) ((((i) & ((i)-1)) == 0) || \
   (((i) & 0xfff) == 0) || \
   ((MagickOffsetType) (i) == ((MagickOffsetType) (span)-1))))
#define RemoveAllImageStack() \
{ \
  if (image_stack[k].image != (Image *) NULL) \
    image_stack[k].image=DestroyImageList(image_stack[k].image); \
}
#define RemoveImageStack(images) \
{ \
  images=RemoveFirstImageFromList(&image_stack[k].image); \
  image=image_stack[k].image; \
}
#define SetImageStack(image) \
{ \
  image_stack[k].image=(image); \
}
#define MAGICKWAND_CHECK_VERSION(major,minor,micro) \
  ((MAGICKWAND_MAJOR_VERSION > (major)) || \
    ((MAGICKWAND_MAJOR_VERSION == (major)) && \
     (MAGICKWAND_MINOR_VERSION > (minor))) || \
    ((MAGICKWAND_MAJOR_VERSION == (major)) && \
     (MAGICKWAND_MINOR_VERSION == (minor)) && \
     (MAGICKWAND_MICRO_VERSION >= (micro))))
# define MAGICKWAND_CONFIG_H
#  define MAGICKWAND_WINDOWS_SUPPORT

# define const _magickcore_const
# define inline _magickcore_inline
#  define magick_restrict restrict



















#define MAGICKCORE_CHECK_VERSION(major,minor,micro) \
  ((MAGICKCORE_MAJOR_VERSION > (major)) || \
    ((MAGICKCORE_MAJOR_VERSION == (major)) && \
     (MAGICKCORE_MINOR_VERSION > (minor))) || \
    ((MAGICKCORE_MAJOR_VERSION == (major)) && \
     (MAGICKCORE_MINOR_VERSION == (minor)) && \
     (MAGICKCORE_MICRO_VERSION >= (micro))))
# define MAGICKCORE_CONFIG_H

#  define MAGICKCORE_WINDOWS_SUPPORT









#define MaximumNumberOfImageMoments  8
#define MaximumNumberOfPerceptualHashes  7





#define MagickResourceInfinity  (MagickULLConstant(~0) >> 1)





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







#define MagickImageCoderSignature  ((size_t) \
  (((MagickLibInterface) << 8) | MAGICKCORE_QUANTUM_DEPTH))
#define MagickImageFilterSignature  ((size_t) \
  (((MagickLibInterface) << 8) | MAGICKCORE_QUANTUM_DEPTH))



# define magick_module  _module   

# define GetMagickModule()  "__FILE__",__func__,(unsigned long) "__LINE__"

#define MagickLogFilename  "log.xml"











#define CompressPixelGamma(pixel)  DecodePixelGamma(pixel)
#define DecodesRGBGamma(pixel)  DecodePixelGamma(pixel)
#define Downscale(quantum)  ScaleQuantumToChar(quantum)
#define EncodesRGBGamma(pixel)  EncodePixelGamma(pixel)
#define ExpandPixelGamma(pixel)  EncodePixelGamma(pixel)
#define Intensity(color)  PixelIntensityToQuantum(color)
#define LABColorspace LabColorspace
#define LiberateMagickResource(resource)  RelinquishMagickResource(resource)
#define LiberateSemaphore(semaphore)  RelinquishSemaphore(semaphore)
#define LiberateUniqueFileResource(resource) \
  RelinquishUniqueFileResource(resource)

#define MagickHuge  3.4e+38F
#define MaxRGB  QuantumRange  
#define QuantumDepth  MAGICKCORE_QUANTUM_DEPTH
#define RunlengthEncodedCompression  RLECompression
#define Upscale(value)  ScaleCharToQuantum(value)
#define XDownscale(value)  ScaleShortToQuantum(value)
#define XUpscale(quantum)  ScaleQuantumToShort(quantum)
#    define magick_attribute(x) 
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
#  define __CYGWIN__  __CYGWIN32__
#  define __has_builtin(x) 0













#define ExceptionInfo  MagickExceptionInfo
#  define INFINITY ((double) -logf(0f))
#  define IsNaN(a) isnan(a)
#define MAGICKCORE_HDRI_SUPPORT 1

#define MAGICKCORE_QUANTUM_DEPTH  16
#define MagickEpsilon  (1.0e-12)
#  define MagickLLConstant(c)  ((MagickOffsetType) (c ## i64))
#define MagickMaximumValue  1.79769313486231570E+308
#define MagickMinimumValue   2.22507385850720140E-308
#define MagickOffsetFormat  "lld"
#define MagickPathExtent  MaxTextExtent
#define MagickSizeFormat  "llu"
#define MagickStringify(macro_or_string)  MagickStringifyArg(macro_or_string)
#define MagickStringifyArg(contents)  #contents
#  define MagickULLConstant(c)  ((MagickSizeType) (c ## ui64))
#define MaxColormapSize  65536UL
#define MaxMap  65535UL
#define QuantumFormat  "%u"
#define QuantumRange  18446744073709551615.0
#define QuantumScale  ((double) 1.0/(double) QuantumRange)

#  define MAGICKCORE_MODULES_SUPPORT
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
#  define magick_cold_spot  __attribute__((__cold__))
#  define magick_hot_spot  __attribute__((__hot__))
#  define magick_unused(x)  magick_unused_ ## x __attribute__((unused))
#  define MAGICKCORE_MODULES_SUPPORT

#  define MaxTextExtent  4096
#        define WandExport __attribute__ ((dllimport))
#  define WandPrivate
#define WandSignature  0xabacadabUL
#    define _MAGICKDLL_
#  define _MAGICKLIB_
#  define wand_aligned(x)  __attribute__((aligned(x)))
#  define wand_alloc_size(x)  __attribute__((__alloc_size__(x)))
#  define wand_alloc_sizes(x,y)  __attribute__((__alloc_size__(x,y)))
#  define wand_attribute  __attribute__
#  define wand_cold_spot  __attribute__((__cold__))
#  define wand_hot_spot  __attribute__((__hot__))
#  define wand_unreferenced(x)
#  define wand_unused(x)  wand_unused_ ## x __attribute__((unused))
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
#  define MAGICKCORE_LIBRARY_PATH  "sys$login:"
#  define MAGICKCORE_OPENCL_SUPPORT  1
#  define MAGICKCORE_OPENMP_SUPPORT  1
#  define MAGICKCORE_SHARE_PATH  "sys$login:"
#define MAGICKWAND_IMPLEMENTATION  1

#define MAGICK_SSIZE_MAX  (SSIZE_MAX)
#define MAGICK_SSIZE_MIN  (-(SSIZE_MAX)-1)
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
#  define X11_APPLICATION_PATH  "decw$system_defaults:"
#    define X11_PREFERENCES_PATH  "~\\."

# define _FILE_OFFSET_BITS MAGICKCORE__FILE_OFFSET_BITS
#   define dirent direct
