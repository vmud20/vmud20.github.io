
#include<time.h>

#include<stdlib.h>
#include<inttypes.h>

#include<limits.h>


#include<errno.h>




#include<string.h>
#include<error.h>


#include<stdarg.h>





#include<sys/socket.h>

#include<math.h>

#include<stdint.h>
















#include<sys/stat.h>

#include<stddef.h>


#include<stdio.h>










#define FF_AMBISONIC_BASE_GUID \
    0x21, 0x07, 0xD3, 0x11, 0x86, 0x44, 0xC8, 0xC1, 0xCA, 0x00, 0x00, 0x00
#define FF_ARG_GUID(g) \
    g[0], g[1], g[2],  g[3],  g[4],  g[5],  g[6],  g[7], \
    g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15],\
    g[3], g[2], g[1],  g[0],  g[5],  g[4],  g[7],  g[6], \
    g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]
#define FF_BROKEN_BASE_GUID \
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0xAA
#define FF_MEDIASUBTYPE_BASE_GUID \
    0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71
#define FF_PRI_GUID \
    "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x " \
    "{%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x}"
#define FF_PUT_WAV_HEADER_FORCE_WAVEFORMATEX    0x00000001
#define FF_PUT_WAV_HEADER_SKIP_CHANNELMASK      0x00000002


#define AV_DICT_APPEND         32   
#define AV_DICT_DONT_OVERWRITE 16   
#define AV_DICT_DONT_STRDUP_KEY 4   
#define AV_DICT_DONT_STRDUP_VAL 8   
#define AV_DICT_IGNORE_SUFFIX   2   
#define AV_DICT_MATCH_CASE      1   
#define AV_DICT_MULTIKEY       64   
#define AVFMTCTX_NOHEADER      0x0001 
#define AVFMTCTX_UNSEEKABLE    0x0002 
#define AVFMT_ALLOW_FLUSH  0x10000 
#define AVFMT_AVOID_NEG_TS_AUTO             -1 
#define AVFMT_AVOID_NEG_TS_DISABLED          0 
#define AVFMT_AVOID_NEG_TS_MAKE_NON_NEGATIVE 1 
#define AVFMT_AVOID_NEG_TS_MAKE_ZERO         2 
#define AVFMT_EVENT_FLAG_METADATA_UPDATED 0x0001
#define AVFMT_EXPERIMENTAL  0x0004
#define AVFMT_FLAG_AUTO_BSF   0x200000 
#define AVFMT_FLAG_BITEXACT         0x0400
#define AVFMT_FLAG_CUSTOM_IO    0x0080 
#define AVFMT_FLAG_DISCARD_CORRUPT  0x0100 
#define AVFMT_FLAG_FAST_SEEK   0x80000 
#define AVFMT_FLAG_FLUSH_PACKETS    0x0200 
#define AVFMT_FLAG_GENPTS       0x0001 
#define AVFMT_FLAG_IGNDTS       0x0008 
#define AVFMT_FLAG_IGNIDX       0x0002 
#define AVFMT_FLAG_NOBUFFER     0x0040 
#define AVFMT_FLAG_NOFILLIN     0x0010 
#define AVFMT_FLAG_NONBLOCK     0x0004 
#define AVFMT_FLAG_NOPARSE      0x0020 
#define AVFMT_FLAG_PRIV_OPT    0x20000 
#define AVFMT_FLAG_SHORTEST   0x100000 
#define AVFMT_FLAG_SORT_DTS    0x10000 
#define AVFMT_GENERIC_INDEX 0x0100 
#define AVFMT_GLOBALHEADER  0x0040 
#define AVFMT_NEEDNUMBER    0x0002 
#define AVFMT_NOBINSEARCH   0x2000 
#define AVFMT_NODIMENSIONS  0x0800 
#define AVFMT_NOFILE        0x0001
#define AVFMT_NOGENSEARCH   0x4000 
#define AVFMT_NOSTREAMS     0x1000 
#define AVFMT_NOTIMESTAMPS  0x0080 
#define AVFMT_NO_BYTE_SEEK  0x8000 
#define AVFMT_SEEK_TO_PTS   0x4000000 
#define AVFMT_SHOW_IDS      0x0008 
#define AVFMT_TS_DISCONT    0x0200 
#define AVFMT_TS_NEGATIVE  0x40000 
#define AVFMT_TS_NONSTRICT 0x20000 
#define AVFMT_VARIABLE_FPS  0x0400 

#define AVINDEX_DISCARD_FRAME  0x0002    
#define AVINDEX_KEYFRAME 0x0001
#define AVPROBE_PADDING_SIZE 32             
#define AVPROBE_SCORE_EXTENSION  50 
#define AVPROBE_SCORE_MAX       100 
#define AVPROBE_SCORE_MIME       75 
#define AVPROBE_SCORE_RETRY (AVPROBE_SCORE_MAX/4)
#define AVPROBE_SCORE_STREAM_RETRY (AVPROBE_SCORE_MAX/4-1)
#define AVSEEK_FLAG_ANY      4 
#define AVSEEK_FLAG_BACKWARD 1 
#define AVSEEK_FLAG_BYTE     2 
#define AVSEEK_FLAG_FRAME    8 
#define AVSTREAM_EVENT_FLAG_METADATA_UPDATED 0x0001
#define AVSTREAM_EVENT_FLAG_NEW_PACKETS (1 << 1)
#define AVSTREAM_INIT_IN_INIT_OUTPUT  1 
#define AVSTREAM_INIT_IN_WRITE_HEADER 0 
#define AV_DISPOSITION_ATTACHED_PIC         (1 << 10)
#define AV_DISPOSITION_CAPTIONS             (1 << 16)
#define AV_DISPOSITION_CLEAN_EFFECTS        (1 << 9)
#define AV_DISPOSITION_COMMENT              (1 << 3)
#define AV_DISPOSITION_DEFAULT              (1 << 0)
#define AV_DISPOSITION_DEPENDENT            (1 << 19)
#define AV_DISPOSITION_DESCRIPTIONS         (1 << 17)
#define AV_DISPOSITION_DUB                  (1 << 1)
#define AV_DISPOSITION_FORCED               (1 << 6)
#define AV_DISPOSITION_HEARING_IMPAIRED     (1 << 7)
#define AV_DISPOSITION_KARAOKE              (1 << 5)
#define AV_DISPOSITION_LYRICS               (1 << 4)
#define AV_DISPOSITION_METADATA             (1 << 18)
#define AV_DISPOSITION_ORIGINAL             (1 << 2)
#define AV_DISPOSITION_STILL_IMAGE          (1 << 20)
#define AV_DISPOSITION_TIMED_THUMBNAILS     (1 << 11)
#define AV_DISPOSITION_VISUAL_IMPAIRED      (1 << 8)
#define AV_FRAME_FILENAME_FLAGS_MULTIPLE 1 
#define AV_PROGRAM_RUNNING 1
#define AV_PTS_WRAP_ADD_OFFSET  1   
#define AV_PTS_WRAP_IGNORE      0   
#define AV_PTS_WRAP_SUB_OFFSET  -1  
#define FF_FDEBUG_TS        0x0001

#define FF_API_AVIOCONTEXT_WRITTEN      (LIBAVFORMAT_VERSION_MAJOR < 60)
#define FF_API_AVSTREAM_CLASS           (LIBAVFORMAT_VERSION_MAJOR > 59)
#define FF_API_COMPUTE_PKT_FIELDS2      (LIBAVFORMAT_VERSION_MAJOR < 60)
#define FF_API_LAVF_PRIV_OPT            (LIBAVFORMAT_VERSION_MAJOR < 60)
#define FF_API_R_FRAME_RATE            1
#define FF_HLS_TS_OPTIONS               (LIBAVFORMAT_VERSION_MAJOR < 60)
#define LIBAVFORMAT_BUILD       LIBAVFORMAT_VERSION_INT
#define LIBAVFORMAT_IDENT       "Lavf" AV_STRINGIFY(LIBAVFORMAT_VERSION)
#define LIBAVFORMAT_VERSION     AV_VERSION(LIBAVFORMAT_VERSION_MAJOR,   \
                                           LIBAVFORMAT_VERSION_MINOR,   \
                                           LIBAVFORMAT_VERSION_MICRO)
#define LIBAVFORMAT_VERSION_INT AV_VERSION_INT(LIBAVFORMAT_VERSION_MAJOR, \
                                               LIBAVFORMAT_VERSION_MINOR, \
                                               LIBAVFORMAT_VERSION_MICRO)
#define LIBAVFORMAT_VERSION_MAJOR  59
#define LIBAVFORMAT_VERSION_MICRO 102
#define LIBAVFORMAT_VERSION_MINOR  17

#define AV_VERSION(a, b, c) AV_VERSION_DOT(a, b, c)
#define AV_VERSION_DOT(a, b, c) a ##.## b ##.## c
#define AV_VERSION_INT(a, b, c) ((a)<<16 | (b)<<8 | (c))
#define AV_VERSION_MAJOR(a) ((a) >> 16)
#define AV_VERSION_MICRO(a) ((a) & 0xFF)
#define AV_VERSION_MINOR(a) (((a) & 0x00FF00) >> 8)
#define FF_API_AV_MALLOCZ_ARRAY         (LIBAVUTIL_VERSION_MAJOR < 58)
#define FF_API_COLORSPACE_NAME          (LIBAVUTIL_VERSION_MAJOR < 58)
#define FF_API_D2STR                    (LIBAVUTIL_VERSION_MAJOR < 58)
#define FF_API_DECLARE_ALIGNED          (LIBAVUTIL_VERSION_MAJOR < 58)
#define FF_API_FIFO_OLD_API             (LIBAVUTIL_VERSION_MAJOR < 58)
#define FF_API_FIFO_PEEK2               (LIBAVUTIL_VERSION_MAJOR < 58)
#define FF_API_XVMC                     (LIBAVUTIL_VERSION_MAJOR < 58)
#define LIBAVUTIL_BUILD         LIBAVUTIL_VERSION_INT
#define LIBAVUTIL_IDENT         "Lavu" AV_STRINGIFY(LIBAVUTIL_VERSION)
#define LIBAVUTIL_VERSION       AV_VERSION(LIBAVUTIL_VERSION_MAJOR,     \
                                           LIBAVUTIL_VERSION_MINOR,     \
                                           LIBAVUTIL_VERSION_MICRO)
#define LIBAVUTIL_VERSION_INT   AV_VERSION_INT(LIBAVUTIL_VERSION_MAJOR, \
                                               LIBAVUTIL_VERSION_MINOR, \
                                               LIBAVUTIL_VERSION_MICRO)
#define LIBAVUTIL_VERSION_MAJOR  57
#define LIBAVUTIL_VERSION_MICRO 100
#define LIBAVUTIL_VERSION_MINOR  21

#define AVIO_FLAG_DIRECT 0x8000
#define AVIO_FLAG_NONBLOCK 8
#define AVIO_FLAG_READ  1                                      
#define AVIO_FLAG_READ_WRITE (AVIO_FLAG_READ|AVIO_FLAG_WRITE)  
#define AVIO_FLAG_WRITE 2                                      
#define AVIO_SEEKABLE_NORMAL (1 << 0)
#define AVIO_SEEKABLE_TIME   (1 << 1)
#define AVSEEK_FORCE 0x20000
#define AVSEEK_SIZE 0x10000
#define avio_print(s, ...) \
    avio_print_string_array(s, (const char*[]){__VA_ARGS__, NULL})

#define AV_IS_INPUT_DEVICE(category) \
    (((category) == AV_CLASS_CATEGORY_DEVICE_VIDEO_INPUT) || \
     ((category) == AV_CLASS_CATEGORY_DEVICE_AUDIO_INPUT) || \
     ((category) == AV_CLASS_CATEGORY_DEVICE_INPUT))
#define AV_IS_OUTPUT_DEVICE(category) \
    (((category) == AV_CLASS_CATEGORY_DEVICE_VIDEO_OUTPUT) || \
     ((category) == AV_CLASS_CATEGORY_DEVICE_AUDIO_OUTPUT) || \
     ((category) == AV_CLASS_CATEGORY_DEVICE_OUTPUT))
#define AV_LOG_C(x) ((x) << 8)
#define AV_LOG_DEBUG    48
#define AV_LOG_ERROR    16
#define AV_LOG_FATAL     8
#define AV_LOG_INFO     32
#define AV_LOG_MAX_OFFSET (AV_LOG_TRACE - AV_LOG_QUIET)
#define AV_LOG_PANIC     0
#define AV_LOG_PRINT_LEVEL 2
#define AV_LOG_QUIET    -8
#define AV_LOG_SKIP_REPEATED 1
#define AV_LOG_TRACE    56
#define AV_LOG_VERBOSE  40
#define AV_LOG_WARNING  24

#define AV_CEIL_RSHIFT(a,b) (!av_builtin_constant_p(b) ? -((-(a)) >> (b)) \
                                                       : ((a) + (1<<(b)) - 1) >> (b))
#define FFABS(a) ((a) >= 0 ? (a) : (-(a)))
#define FFABS64U(a) ((a) <= 0 ? -(uint64_t)(a) : (uint64_t)(a))
#define FFABSU(a) ((a) <= 0 ? -(unsigned)(a) : (unsigned)(a))
#define FFNABS(a) ((a) <= 0 ? (a) : (-(a)))
#define FFSIGN(a) ((a) > 0 ? 1 : -1)
#define FFUDIV(a,b) (((a)>0 ?(a):(a)-(b)+1) / (b))
#define FFUMOD(a,b) ((a)-(b)*FFUDIV(a,b))
#define FF_CEIL_RSHIFT AV_CEIL_RSHIFT
#define GET_UTF16(val, GET_16BIT, ERROR)\
    val = (GET_16BIT);\
    {\
        unsigned int hi = val - 0xD800;\
        if (hi < 0x800) {\
            val = (GET_16BIT) - 0xDC00;\
            if (val > 0x3FFU || hi > 0x3FFU)\
                {ERROR}\
            val += (hi<<10) + 0x10000;\
        }\
    }\

#define GET_UTF8(val, GET_BYTE, ERROR)\
    val= (GET_BYTE);\
    {\
        uint32_t top = (val & 128) >> 1;\
        if ((val & 0xc0) == 0x80 || val >= 0xFE)\
            {ERROR}\
        while (val & top) {\
            unsigned int tmp = (GET_BYTE) - 128;\
            if(tmp>>6)\
                {ERROR}\
            val= (val<<6) + tmp;\
            top <<= 5;\
        }\
        val &= (top << 1) - 1;\
    }
#define PUT_UTF16(val, tmp, PUT_16BIT)\
    {\
        uint32_t in = val;\
        if (in < 0x10000) {\
            tmp = in;\
            PUT_16BIT\
        } else {\
            tmp = 0xD800 | ((in - 0x10000) >> 10);\
            PUT_16BIT\
            tmp = 0xDC00 | ((in - 0x10000) & 0x3FF);\
            PUT_16BIT\
        }\
    }\

#define PUT_UTF8(val, tmp, PUT_BYTE)\
    {\
        int bytes, shift;\
        uint32_t in = val;\
        if (in < 0x80) {\
            tmp = in;\
            PUT_BYTE\
        } else {\
            bytes = (av_log2(in) + 4) / 5;\
            shift = (bytes - 1) * 6;\
            tmp = (256 - (256 >> bytes)) | (in >> shift);\
            PUT_BYTE\
            while (shift >= 6) {\
                shift -= 6;\
                tmp = 0x80 | ((in >> shift) & 0x3f);\
                PUT_BYTE\
            }\
        }\
    }
#define ROUNDED_DIV(a,b) (((a)>=0 ? (a) + ((b)>>1) : (a) - ((b)>>1))/(b))
#define RSHIFT(a,b) ((a) > 0 ? ((a) + ((1<<(b))>>1))>>(b) : ((a) + ((1<<(b))>>1)-1)>>(b))
#   define av_ceil_log2     av_ceil_log2_c
#   define av_clip          av_clip_c
#   define av_clip64        av_clip64_c
#   define av_clip_int16    av_clip_int16_c
#   define av_clip_int8     av_clip_int8_c
#   define av_clip_intp2    av_clip_intp2_c
#   define av_clip_uint16   av_clip_uint16_c
#   define av_clip_uint8    av_clip_uint8_c
#   define av_clip_uintp2   av_clip_uintp2_c
#   define av_clipd         av_clipd_c
#   define av_clipf         av_clipf_c
#   define av_clipl_int32   av_clipl_int32_c
#   define av_mod_uintp2    av_mod_uintp2_c
#   define av_parity        av_parity_c
#   define av_popcount      av_popcount_c
#   define av_popcount64    av_popcount64_c
#   define av_sat_add32     av_sat_add32_c
#   define av_sat_add64     av_sat_add64_c
#   define av_sat_dadd32    av_sat_dadd32_c
#   define av_sat_dsub32    av_sat_dsub32_c
#   define av_sat_sub32     av_sat_sub32_c
#   define av_sat_sub64     av_sat_sub64_c

#define AV_PKT_DATA_QUALITY_FACTOR AV_PKT_DATA_QUALITY_STATS 
#define AV_PKT_FLAG_CORRUPT 0x0002 
#define AV_PKT_FLAG_DISCARD   0x0004
#define AV_PKT_FLAG_DISPOSABLE 0x0010
#define AV_PKT_FLAG_KEY     0x0001 
#define AV_PKT_FLAG_TRUSTED   0x0008

#define FF_API_AUTO_THREADS        (LIBAVCODEC_VERSION_MAJOR < 60)
#define FF_API_AVCTX_TIMEBASE    (LIBAVCODEC_VERSION_MAJOR < 60)
#define FF_API_DEBUG_MV          (LIBAVCODEC_VERSION_MAJOR < 60)
#define FF_API_FLAG_TRUNCATED      (LIBAVCODEC_VERSION_MAJOR < 60)
#define FF_API_GET_FRAME_CLASS     (LIBAVCODEC_VERSION_MAJOR < 60)
#define FF_API_IDCT_NONE           (LIBAVCODEC_VERSION_MAJOR < 60)
#define FF_API_INIT_PACKET         (LIBAVCODEC_VERSION_MAJOR < 60)
#define FF_API_MJPEG_PRED          (LIBAVCODEC_VERSION_MAJOR < 60)
#define FF_API_MPEGVIDEO_OPTS      (LIBAVCODEC_VERSION_MAJOR < 60)
#define FF_API_OPENH264_CABAC      (LIBAVCODEC_VERSION_MAJOR < 60)
#define FF_API_OPENH264_SLICE_MODE (LIBAVCODEC_VERSION_MAJOR < 60)
#define FF_API_SUB_TEXT_FORMAT     (LIBAVCODEC_VERSION_MAJOR < 60)
#define FF_API_THREAD_SAFE_CALLBACKS (LIBAVCODEC_VERSION_MAJOR < 60)
#define FF_API_UNUSED_CODEC_CAPS   (LIBAVCODEC_VERSION_MAJOR < 60)
#define LIBAVCODEC_BUILD        LIBAVCODEC_VERSION_INT
#define LIBAVCODEC_IDENT        "Lavc" AV_STRINGIFY(LIBAVCODEC_VERSION)
#define LIBAVCODEC_VERSION      AV_VERSION(LIBAVCODEC_VERSION_MAJOR,    \
                                           LIBAVCODEC_VERSION_MINOR,    \
                                           LIBAVCODEC_VERSION_MICRO)
#define LIBAVCODEC_VERSION_INT  AV_VERSION_INT(LIBAVCODEC_VERSION_MAJOR, \
                                               LIBAVCODEC_VERSION_MINOR, \
                                               LIBAVCODEC_VERSION_MICRO)
#define LIBAVCODEC_VERSION_MAJOR  59
#define LIBAVCODEC_VERSION_MICRO 100
#define LIBAVCODEC_VERSION_MINOR  21


#define AV_BUFFER_FLAG_READONLY (1 << 0)

#    define AV_GCC_VERSION_AT_LEAST(x,y) ("__GNUC__" > (x) || "__GNUC__" == (x) && "__GNUC_MINOR__" >= (y))
#    define AV_GCC_VERSION_AT_MOST(x,y)  ("__GNUC__" < (x) || "__GNUC__" == (x) && "__GNUC_MINOR__" <= (y))
#    define AV_HAS_BUILTIN(x) __has_builtin(x)
#    define AV_NOWARN_DEPRECATED(code) \
        _Pragma("GCC diagnostic push") \
        _Pragma("GCC diagnostic ignored \"-Wdeprecated-declarations\"") \
        code \
        _Pragma("GCC diagnostic pop")
#    define attribute_deprecated __attribute__((deprecated))
#   define av_alias __attribute__((may_alias))
#    define av_always_inline __attribute__((always_inline)) inline
#    define av_builtin_constant_p __builtin_constant_p
#    define av_cold __attribute__((cold))
#    define av_const __attribute__((const))
#    define av_extern_inline extern inline
#    define av_flatten __attribute__((flatten))
#    define av_noinline __attribute__((noinline))
#    define av_noreturn __attribute__((noreturn))
#    define av_printf_format(fmtpos, attrpos) __attribute__((__format__(__printf__, fmtpos, attrpos)))
#    define av_pure __attribute__((pure))
#    define av_uninit(x) x=x
#    define av_unused __attribute__((unused))
#    define av_used __attribute__((used))
#    define av_warn_unused_result __attribute__((warn_unused_result))

#define AV_INPUT_BUFFER_PADDING_SIZE 64

#define AVPALETTE_COUNT 256
#define AVPALETTE_SIZE 1024

#define AV_PIX_FMT_0BGR32  AV_PIX_FMT_NE(0BGR, RGB0)
#define AV_PIX_FMT_0RGB32  AV_PIX_FMT_NE(0RGB, BGR0)
#define AV_PIX_FMT_AYUV64     AV_PIX_FMT_NE(AYUV64BE, AYUV64LE)
#define AV_PIX_FMT_BAYER_BGGR16 AV_PIX_FMT_NE(BAYER_BGGR16BE,    BAYER_BGGR16LE)
#define AV_PIX_FMT_BAYER_GBRG16 AV_PIX_FMT_NE(BAYER_GBRG16BE,    BAYER_GBRG16LE)
#define AV_PIX_FMT_BAYER_GRBG16 AV_PIX_FMT_NE(BAYER_GRBG16BE,    BAYER_GRBG16LE)
#define AV_PIX_FMT_BAYER_RGGB16 AV_PIX_FMT_NE(BAYER_RGGB16BE,    BAYER_RGGB16LE)
#define AV_PIX_FMT_BGR32   AV_PIX_FMT_NE(ABGR, RGBA)
#define AV_PIX_FMT_BGR32_1 AV_PIX_FMT_NE(BGRA, ARGB)
#define AV_PIX_FMT_BGR444 AV_PIX_FMT_NE(BGR444BE, BGR444LE)
#define AV_PIX_FMT_BGR48  AV_PIX_FMT_NE(BGR48BE,  BGR48LE)
#define AV_PIX_FMT_BGR555 AV_PIX_FMT_NE(BGR555BE, BGR555LE)
#define AV_PIX_FMT_BGR565 AV_PIX_FMT_NE(BGR565BE, BGR565LE)
#define AV_PIX_FMT_BGRA64 AV_PIX_FMT_NE(BGRA64BE, BGRA64LE)
#define AV_PIX_FMT_GBRAP10   AV_PIX_FMT_NE(GBRAP10BE,   GBRAP10LE)
#define AV_PIX_FMT_GBRAP12   AV_PIX_FMT_NE(GBRAP12BE,   GBRAP12LE)
#define AV_PIX_FMT_GBRAP16   AV_PIX_FMT_NE(GBRAP16BE,   GBRAP16LE)
#define AV_PIX_FMT_GBRAPF32   AV_PIX_FMT_NE(GBRAPF32BE, GBRAPF32LE)
#define AV_PIX_FMT_GBRP10    AV_PIX_FMT_NE(GBRP10BE,    GBRP10LE)
#define AV_PIX_FMT_GBRP12    AV_PIX_FMT_NE(GBRP12BE,    GBRP12LE)
#define AV_PIX_FMT_GBRP14    AV_PIX_FMT_NE(GBRP14BE,    GBRP14LE)
#define AV_PIX_FMT_GBRP16    AV_PIX_FMT_NE(GBRP16BE,    GBRP16LE)
#define AV_PIX_FMT_GBRP9     AV_PIX_FMT_NE(GBRP9BE ,    GBRP9LE)
#define AV_PIX_FMT_GBRPF32    AV_PIX_FMT_NE(GBRPF32BE,  GBRPF32LE)
#define AV_PIX_FMT_GRAY10 AV_PIX_FMT_NE(GRAY10BE, GRAY10LE)
#define AV_PIX_FMT_GRAY12 AV_PIX_FMT_NE(GRAY12BE, GRAY12LE)
#define AV_PIX_FMT_GRAY14 AV_PIX_FMT_NE(GRAY14BE, GRAY14LE)
#define AV_PIX_FMT_GRAY16 AV_PIX_FMT_NE(GRAY16BE, GRAY16LE)
#define AV_PIX_FMT_GRAY9  AV_PIX_FMT_NE(GRAY9BE,  GRAY9LE)
#define AV_PIX_FMT_GRAYF32    AV_PIX_FMT_NE(GRAYF32BE, GRAYF32LE)
#   define AV_PIX_FMT_NE(be, le) AV_PIX_FMT_##be
#define AV_PIX_FMT_NV20       AV_PIX_FMT_NE(NV20BE,  NV20LE)
#define AV_PIX_FMT_P010       AV_PIX_FMT_NE(P010BE,  P010LE)
#define AV_PIX_FMT_P016       AV_PIX_FMT_NE(P016BE,  P016LE)
#define AV_PIX_FMT_P210       AV_PIX_FMT_NE(P210BE, P210LE)
#define AV_PIX_FMT_P216       AV_PIX_FMT_NE(P216BE, P216LE)
#define AV_PIX_FMT_P410       AV_PIX_FMT_NE(P410BE, P410LE)
#define AV_PIX_FMT_P416       AV_PIX_FMT_NE(P416BE, P416LE)
#define AV_PIX_FMT_RGB32   AV_PIX_FMT_NE(ARGB, BGRA)
#define AV_PIX_FMT_RGB32_1 AV_PIX_FMT_NE(RGBA, ABGR)
#define AV_PIX_FMT_RGB444 AV_PIX_FMT_NE(RGB444BE, RGB444LE)
#define AV_PIX_FMT_RGB48  AV_PIX_FMT_NE(RGB48BE,  RGB48LE)
#define AV_PIX_FMT_RGB555 AV_PIX_FMT_NE(RGB555BE, RGB555LE)
#define AV_PIX_FMT_RGB565 AV_PIX_FMT_NE(RGB565BE, RGB565LE)
#define AV_PIX_FMT_RGBA64 AV_PIX_FMT_NE(RGBA64BE, RGBA64LE)
#define AV_PIX_FMT_X2BGR10    AV_PIX_FMT_NE(X2BGR10BE, X2BGR10LE)
#define AV_PIX_FMT_X2RGB10    AV_PIX_FMT_NE(X2RGB10BE, X2RGB10LE)
#define AV_PIX_FMT_XYZ12      AV_PIX_FMT_NE(XYZ12BE, XYZ12LE)
#define AV_PIX_FMT_Y210       AV_PIX_FMT_NE(Y210BE,  Y210LE)
#define AV_PIX_FMT_YA16   AV_PIX_FMT_NE(YA16BE,   YA16LE)
#define AV_PIX_FMT_YUV420P10 AV_PIX_FMT_NE(YUV420P10BE, YUV420P10LE)
#define AV_PIX_FMT_YUV420P12 AV_PIX_FMT_NE(YUV420P12BE, YUV420P12LE)
#define AV_PIX_FMT_YUV420P14 AV_PIX_FMT_NE(YUV420P14BE, YUV420P14LE)
#define AV_PIX_FMT_YUV420P16 AV_PIX_FMT_NE(YUV420P16BE, YUV420P16LE)
#define AV_PIX_FMT_YUV420P9  AV_PIX_FMT_NE(YUV420P9BE , YUV420P9LE)
#define AV_PIX_FMT_YUV422P10 AV_PIX_FMT_NE(YUV422P10BE, YUV422P10LE)
#define AV_PIX_FMT_YUV422P12 AV_PIX_FMT_NE(YUV422P12BE, YUV422P12LE)
#define AV_PIX_FMT_YUV422P14 AV_PIX_FMT_NE(YUV422P14BE, YUV422P14LE)
#define AV_PIX_FMT_YUV422P16 AV_PIX_FMT_NE(YUV422P16BE, YUV422P16LE)
#define AV_PIX_FMT_YUV422P9  AV_PIX_FMT_NE(YUV422P9BE , YUV422P9LE)
#define AV_PIX_FMT_YUV440P10 AV_PIX_FMT_NE(YUV440P10BE, YUV440P10LE)
#define AV_PIX_FMT_YUV440P12 AV_PIX_FMT_NE(YUV440P12BE, YUV440P12LE)
#define AV_PIX_FMT_YUV444P10 AV_PIX_FMT_NE(YUV444P10BE, YUV444P10LE)
#define AV_PIX_FMT_YUV444P12 AV_PIX_FMT_NE(YUV444P12BE, YUV444P12LE)
#define AV_PIX_FMT_YUV444P14 AV_PIX_FMT_NE(YUV444P14BE, YUV444P14LE)
#define AV_PIX_FMT_YUV444P16 AV_PIX_FMT_NE(YUV444P16BE, YUV444P16LE)
#define AV_PIX_FMT_YUV444P9  AV_PIX_FMT_NE(YUV444P9BE , YUV444P9LE)
#define AV_PIX_FMT_YUVA420P10 AV_PIX_FMT_NE(YUVA420P10BE, YUVA420P10LE)
#define AV_PIX_FMT_YUVA420P16 AV_PIX_FMT_NE(YUVA420P16BE, YUVA420P16LE)
#define AV_PIX_FMT_YUVA420P9  AV_PIX_FMT_NE(YUVA420P9BE , YUVA420P9LE)
#define AV_PIX_FMT_YUVA422P10 AV_PIX_FMT_NE(YUVA422P10BE, YUVA422P10LE)
#define AV_PIX_FMT_YUVA422P12 AV_PIX_FMT_NE(YUVA422P12BE, YUVA422P12LE)
#define AV_PIX_FMT_YUVA422P16 AV_PIX_FMT_NE(YUVA422P16BE, YUVA422P16LE)
#define AV_PIX_FMT_YUVA422P9  AV_PIX_FMT_NE(YUVA422P9BE , YUVA422P9LE)
#define AV_PIX_FMT_YUVA444P10 AV_PIX_FMT_NE(YUVA444P10BE, YUVA444P10LE)
#define AV_PIX_FMT_YUVA444P12 AV_PIX_FMT_NE(YUVA444P12BE, YUVA444P12LE)
#define AV_PIX_FMT_YUVA444P16 AV_PIX_FMT_NE(YUVA444P16BE, YUVA444P16LE)
#define AV_PIX_FMT_YUVA444P9  AV_PIX_FMT_NE(YUVA444P9BE , YUVA444P9LE)

#define AV_FOURCC_MAX_STRING_SIZE 32
#define AV_NOPTS_VALUE          ((int64_t)UINT64_C(0x8000000000000000))
#define AV_TIME_BASE            1000000
#define AV_TIME_BASE_Q          (AVRational){1, AV_TIME_BASE}
#define FF_LAMBDA_MAX (256*128-1)
#define FF_LAMBDA_SCALE (1<<FF_LAMBDA_SHIFT)
#define FF_LAMBDA_SHIFT 7
#define FF_QP2LAMBDA 118 
#define FF_QUALITY_SCALE FF_LAMBDA_SCALE 
#define av_fourcc2str(fourcc) av_fourcc_make_string((char[AV_FOURCC_MAX_STRING_SIZE]){0}, fourcc)
#define av_int_list_length(list, term) \
    av_int_list_length_for_size(sizeof(*(list)), list, term)

#define AV_CODEC_CAP_AUTO_THREADS        AV_CODEC_CAP_OTHER_THREADS
#define AV_CODEC_CAP_AVOID_PROBING       (1 << 17)
#define AV_CODEC_CAP_CHANNEL_CONF        (1 << 10)
#define AV_CODEC_CAP_DELAY               (1 <<  5)
#define AV_CODEC_CAP_DR1                 (1 <<  1)
#define AV_CODEC_CAP_DRAW_HORIZ_BAND     (1 <<  0)
#define AV_CODEC_CAP_ENCODER_FLUSH   (1 << 21)
#define AV_CODEC_CAP_ENCODER_REORDERED_OPAQUE (1 << 20)
#define AV_CODEC_CAP_EXPERIMENTAL        (1 <<  9)
#define AV_CODEC_CAP_FRAME_THREADS       (1 << 12)
#define AV_CODEC_CAP_HARDWARE            (1 << 18)
#define AV_CODEC_CAP_HYBRID              (1 << 19)
#define AV_CODEC_CAP_INTRA_ONLY       0x40000000
#define AV_CODEC_CAP_LOSSLESS         0x80000000
#define AV_CODEC_CAP_OTHER_THREADS       (1 << 15)
#define AV_CODEC_CAP_PARAM_CHANGE        (1 << 14)
#define AV_CODEC_CAP_SLICE_THREADS       (1 << 13)
#define AV_CODEC_CAP_SMALL_LAST_FRAME    (1 <<  6)
#define AV_CODEC_CAP_SUBFRAMES           (1 <<  8)
#define AV_CODEC_CAP_TRUNCATED           (1 <<  3)
#define AV_CODEC_CAP_VARIABLE_FRAME_SIZE (1 << 16)

#define AV_CODEC_ID_H265 AV_CODEC_ID_HEVC
#define AV_CODEC_ID_H266 AV_CODEC_ID_VVC
#define AV_CODEC_ID_IFF_BYTERUN1 AV_CODEC_ID_IFF_ILBM



#define AVOID_NEGATIVE_TS_ENABLED(status) ((status) >= 0)
#define CONTAINS_PAL 2
#define FFERROR_REDO FFERRTAG('R','E','D','O')
#define FF_FMT_INIT_CLEANUP                             (1 << 0)
#define MAX_REORDER_DELAY 16
#define MAX_STD_TIMEBASES (30*12+30+3+6)
#define MAX_URL_SIZE 4096
#define NTP_OFFSET 2208988800ULL
#define NTP_OFFSET_US (NTP_OFFSET * 1000000ULL)
#define PROBE_BUF_MAX (1 << 20)
#define PROBE_BUF_MIN 2048
#define RELATIVE_TS_BASE (INT64_MAX - (1LL << 48))
#define SPACE_CHARS " \t\r\n"
#define dynarray_add(tab, nb_ptr, elem)\
do {\
    __typeof__(tab) _tab = (tab);\
    __typeof__(elem) _elem = (elem);\
    (void)sizeof(**_tab == _elem); \
    av_dynarray_add(_tab, nb_ptr, _elem);\
} while(0)
#    define hex_dump_debug(class, buf, size) av_hex_dump_log(class, AV_LOG_DEBUG, buf, size)

#define DEF_FS_FUNCTION(name, wfunc, afunc)               \
static inline int win32_##name(const char *filename_utf8) \
{                                                         \
    wchar_t *filename_w;                                  \
    int ret;                                              \
                                                          \
    if (utf8towchar(filename_utf8, &filename_w))          \
        return -1;                                        \
    if (!filename_w)                                      \
        goto fallback;                                    \
                                                          \
    ret = wfunc(filename_w);                              \
    av_free(filename_w);                                  \
    return ret;                                           \
                                                          \
fallback:                                                 \
                        \
    return afunc(filename_utf8);                          \
}
#define DEF_FS_FUNCTION2(name, wfunc, afunc, partype)     \
static inline int win32_##name(const char *filename_utf8, partype par) \
{                                                         \
    wchar_t *filename_w;                                  \
    int ret;                                              \
                                                          \
    if (utf8towchar(filename_utf8, &filename_w))          \
        return -1;                                        \
    if (!filename_w)                                      \
        goto fallback;                                    \
                                                          \
    ret = wfunc(filename_w, par);                         \
    av_free(filename_w);                                  \
    return ret;                                           \
                                                          \
fallback:                                                 \
                        \
    return afunc(filename_utf8, par);                     \
}
#define POLLERR    0x0004  
#define POLLHUP    0x0080  
#define POLLIN     0x0001  
#define POLLNVAL   0x1000  
#define POLLOUT    0x0002  
#define POLLPRI    0x0020  
#define POLLRDBAND 0x0008  
#define POLLRDNORM POLLIN
#define POLLWRBAND 0x0010  
#define POLLWRNORM POLLOUT
#define SHUT_RD SD_RECEIVE
#define SHUT_RDWR SD_BOTH
#define SHUT_WR SD_SEND
#define S_IRUSR S_IREAD
#define S_IWUSR S_IWRITE
#define access      win32_access
#define closesocket close
#  define fstat(f,s) _fstati64((f), (s))
#  define lseek(f,p,w) _lseeki64((f), (p), (w))
#define mkdir(a, b) win32_mkdir(a)
#define poll ff_poll
#define rename      win32_rename
#define rmdir       win32_rmdir
#  define stat _stati64
#define unlink      win32_unlink




#define AV_CODEC_EXPORT_DATA_FILM_GRAIN (1 << 3)
#define AV_CODEC_EXPORT_DATA_MVS         (1 << 0)
#define AV_CODEC_EXPORT_DATA_PRFT        (1 << 1)
#define AV_CODEC_EXPORT_DATA_VIDEO_ENC_PARAMS (1 << 2)
#define AV_CODEC_FLAG2_CHUNKS         (1 << 15)
#define AV_CODEC_FLAG2_DROP_FRAME_TIMECODE (1 << 13)
#define AV_CODEC_FLAG2_EXPORT_MVS     (1 << 28)
#define AV_CODEC_FLAG2_FAST           (1 <<  0)
#define AV_CODEC_FLAG2_IGNORE_CROP    (1 << 16)
#define AV_CODEC_FLAG2_LOCAL_HEADER   (1 <<  3)
#define AV_CODEC_FLAG2_NO_OUTPUT      (1 <<  2)
#define AV_CODEC_FLAG2_RO_FLUSH_NOOP  (1 << 30)
#define AV_CODEC_FLAG2_SHOW_ALL       (1 << 22)
#define AV_CODEC_FLAG2_SKIP_MANUAL    (1 << 29)
#define AV_CODEC_FLAG_4MV             (1 <<  2)
#define AV_CODEC_FLAG_AC_PRED         (1 << 24)
#define AV_CODEC_FLAG_BITEXACT        (1 << 23)
#define AV_CODEC_FLAG_CLOSED_GOP      (1U << 31)
#define AV_CODEC_FLAG_DROPCHANGED     (1 <<  5)
#define AV_CODEC_FLAG_GLOBAL_HEADER   (1 << 22)
#define AV_CODEC_FLAG_GRAY            (1 << 13)
#define AV_CODEC_FLAG_INTERLACED_DCT  (1 << 18)
#define AV_CODEC_FLAG_INTERLACED_ME   (1 << 29)
#define AV_CODEC_FLAG_LOOP_FILTER     (1 << 11)
#define AV_CODEC_FLAG_LOW_DELAY       (1 << 19)
#define AV_CODEC_FLAG_OUTPUT_CORRUPT  (1 <<  3)
#define AV_CODEC_FLAG_PASS1           (1 <<  9)
#define AV_CODEC_FLAG_PASS2           (1 << 10)
#define AV_CODEC_FLAG_PSNR            (1 << 15)
#define AV_CODEC_FLAG_QPEL            (1 <<  4)
#define AV_CODEC_FLAG_QSCALE          (1 <<  1)
#define AV_CODEC_FLAG_TRUNCATED       (1 << 16)
#define AV_CODEC_FLAG_UNALIGNED       (1 <<  0)
#define AV_EF_AGGRESSIVE (1<<18)        
#define AV_EF_BITSTREAM (1<<1)          
#define AV_EF_BUFFER    (1<<2)          
#define AV_EF_CAREFUL    (1<<16)        
#define AV_EF_COMPLIANT  (1<<17)        
#define AV_EF_CRCCHECK  (1<<0)
#define AV_EF_EXPLODE   (1<<3)          
#define AV_EF_IGNORE_ERR (1<<15)        
#define AV_GET_BUFFER_FLAG_REF (1 << 0)
#define AV_GET_ENCODE_BUFFER_FLAG_REF (1 << 0)
#define AV_HWACCEL_CODEC_CAP_EXPERIMENTAL 0x0200
#define AV_HWACCEL_FLAG_ALLOW_HIGH_DEPTH (1 << 1)
#define AV_HWACCEL_FLAG_ALLOW_PROFILE_MISMATCH (1 << 2)
#define AV_HWACCEL_FLAG_IGNORE_LEVEL (1 << 0)
#define AV_INPUT_BUFFER_MIN_SIZE 16384
#define AV_PARSER_PTS_NB 4
#define AV_SUBTITLE_FLAG_FORCED 0x00000001
#define FF_BUG_AMV              32
#define FF_BUG_AUTODETECT       1  
#define FF_BUG_DC_CLIP          4096
#define FF_BUG_DIRECT_BLOCKSIZE 512
#define FF_BUG_EDGE             1024
#define FF_BUG_HPEL_CHROMA      2048
#define FF_BUG_IEDGE           32768
#define FF_BUG_MS               8192 
#define FF_BUG_NO_PADDING       16
#define FF_BUG_QPEL_CHROMA      64
#define FF_BUG_QPEL_CHROMA2     256
#define FF_BUG_STD_QPEL         128
#define FF_BUG_TRUNCATED       16384
#define FF_BUG_UMP4             8
#define FF_BUG_XVID_ILACE       4
#define FF_CMP_BIT          5
#define FF_CMP_CHROMA       256
#define FF_CMP_DCT          3
#define FF_CMP_DCT264       14
#define FF_CMP_DCTMAX       13
#define FF_CMP_MEDIAN_SAD   15
#define FF_CMP_NSSE         10
#define FF_CMP_PSNR         4
#define FF_CMP_RD           6
#define FF_CMP_SAD          0
#define FF_CMP_SATD         2
#define FF_CMP_SSE          1
#define FF_CMP_VSAD         8
#define FF_CMP_VSSE         9
#define FF_CMP_W53          11
#define FF_CMP_W97          12
#define FF_CMP_ZERO         7
#define FF_CODEC_PROPERTY_CLOSED_CAPTIONS 0x00000002
#define FF_CODEC_PROPERTY_FILM_GRAIN      0x00000004
#define FF_CODEC_PROPERTY_LOSSLESS        0x00000001
#define FF_COMPLIANCE_EXPERIMENTAL -2 
#define FF_COMPLIANCE_NORMAL        0
#define FF_COMPLIANCE_STRICT        1 
#define FF_COMPLIANCE_UNOFFICIAL   -1 
#define FF_COMPLIANCE_VERY_STRICT   2 
#define FF_COMPRESSION_DEFAULT -1
#define FF_DCT_ALTIVEC 5
#define FF_DCT_AUTO    0
#define FF_DCT_FAAN    6
#define FF_DCT_FASTINT 1
#define FF_DCT_INT     2
#define FF_DCT_MMX     3
#define FF_DEBUG_BITSTREAM   4
#define FF_DEBUG_BUFFERS     0x00008000
#define FF_DEBUG_BUGS        0x00001000
#define FF_DEBUG_DCT_COEFF   0x00000040
#define FF_DEBUG_ER          0x00000400
#define FF_DEBUG_GREEN_MD    0x00800000
#define FF_DEBUG_MB_TYPE     8
#define FF_DEBUG_MMCO        0x00000800
#define FF_DEBUG_NOMC        0x01000000
#define FF_DEBUG_PICT_INFO   1
#define FF_DEBUG_QP          16
#define FF_DEBUG_RC          2
#define FF_DEBUG_SKIP        0x00000080
#define FF_DEBUG_STARTCODE   0x00000100
#define FF_DEBUG_THREADS     0x00010000
#define FF_DEBUG_VIS_MV_B_BACK 0x00000004 
#define FF_DEBUG_VIS_MV_B_FOR  0x00000002 
#define FF_DEBUG_VIS_MV_P_FOR  0x00000001 
#define FF_EC_DEBLOCK     2
#define FF_EC_FAVOR_INTER 256
#define FF_EC_GUESS_MVS   1
#define FF_IDCT_ALTIVEC       8
#define FF_IDCT_ARM           7
#define FF_IDCT_AUTO          0
#define FF_IDCT_FAAN          20
#define FF_IDCT_INT           1
#define FF_IDCT_NONE          24
#define FF_IDCT_SIMPLE        2
#define FF_IDCT_SIMPLEARM     10
#define FF_IDCT_SIMPLEARMV5TE 16
#define FF_IDCT_SIMPLEARMV6   17
#define FF_IDCT_SIMPLEAUTO    128
#define FF_IDCT_SIMPLEMMX     3
#define FF_IDCT_SIMPLENEON    22
#define FF_IDCT_XVID          14
#define FF_LEVEL_UNKNOWN -99
#define FF_MB_DECISION_BITS   1        
#define FF_MB_DECISION_RD     2        
#define FF_MB_DECISION_SIMPLE 0        
#define FF_PROFILE_AAC_ELD  38
#define FF_PROFILE_AAC_HE   4
#define FF_PROFILE_AAC_HE_V2 28
#define FF_PROFILE_AAC_LD   22
#define FF_PROFILE_AAC_LOW  1
#define FF_PROFILE_AAC_LTP  3
#define FF_PROFILE_AAC_MAIN 0
#define FF_PROFILE_AAC_SSR  2
#define FF_PROFILE_ARIB_PROFILE_A 0
#define FF_PROFILE_ARIB_PROFILE_C 1
#define FF_PROFILE_AV1_HIGH                         1
#define FF_PROFILE_AV1_MAIN                         0
#define FF_PROFILE_AV1_PROFESSIONAL                 2
#define FF_PROFILE_DNXHD         0
#define FF_PROFILE_DNXHR_444     5
#define FF_PROFILE_DNXHR_HQ      3
#define FF_PROFILE_DNXHR_HQX     4
#define FF_PROFILE_DNXHR_LB      1
#define FF_PROFILE_DNXHR_SQ      2
#define FF_PROFILE_DTS         20
#define FF_PROFILE_DTS_96_24   40
#define FF_PROFILE_DTS_ES      30
#define FF_PROFILE_DTS_EXPRESS 70
#define FF_PROFILE_DTS_HD_HRA  50
#define FF_PROFILE_DTS_HD_MA   60
#define FF_PROFILE_H264_BASELINE             66
#define FF_PROFILE_H264_CAVLC_444            44
#define FF_PROFILE_H264_CONSTRAINED  (1<<9)  
#define FF_PROFILE_H264_CONSTRAINED_BASELINE (66|FF_PROFILE_H264_CONSTRAINED)
#define FF_PROFILE_H264_EXTENDED             88
#define FF_PROFILE_H264_HIGH                 100
#define FF_PROFILE_H264_HIGH_10              110
#define FF_PROFILE_H264_HIGH_10_INTRA        (110|FF_PROFILE_H264_INTRA)
#define FF_PROFILE_H264_HIGH_422             122
#define FF_PROFILE_H264_HIGH_422_INTRA       (122|FF_PROFILE_H264_INTRA)
#define FF_PROFILE_H264_HIGH_444             144
#define FF_PROFILE_H264_HIGH_444_INTRA       (244|FF_PROFILE_H264_INTRA)
#define FF_PROFILE_H264_HIGH_444_PREDICTIVE  244
#define FF_PROFILE_H264_INTRA        (1<<11) 
#define FF_PROFILE_H264_MAIN                 77
#define FF_PROFILE_H264_MULTIVIEW_HIGH       118
#define FF_PROFILE_H264_STEREO_HIGH          128
#define FF_PROFILE_HEVC_MAIN                        1
#define FF_PROFILE_HEVC_MAIN_10                     2
#define FF_PROFILE_HEVC_MAIN_STILL_PICTURE          3
#define FF_PROFILE_HEVC_REXT                        4
#define FF_PROFILE_JPEG2000_CSTREAM_NO_RESTRICTION  32768
#define FF_PROFILE_JPEG2000_CSTREAM_RESTRICTION_0   1
#define FF_PROFILE_JPEG2000_CSTREAM_RESTRICTION_1   2
#define FF_PROFILE_JPEG2000_DCINEMA_2K              3
#define FF_PROFILE_JPEG2000_DCINEMA_4K              4
#define FF_PROFILE_KLVA_ASYNC 1
#define FF_PROFILE_KLVA_SYNC 0
#define FF_PROFILE_MJPEG_HUFFMAN_BASELINE_DCT            0xc0
#define FF_PROFILE_MJPEG_HUFFMAN_EXTENDED_SEQUENTIAL_DCT 0xc1
#define FF_PROFILE_MJPEG_HUFFMAN_LOSSLESS                0xc3
#define FF_PROFILE_MJPEG_HUFFMAN_PROGRESSIVE_DCT         0xc2
#define FF_PROFILE_MJPEG_JPEG_LS                         0xf7
#define FF_PROFILE_MPEG2_422    0
#define FF_PROFILE_MPEG2_AAC_HE  131
#define FF_PROFILE_MPEG2_AAC_LOW 128
#define FF_PROFILE_MPEG2_HIGH   1
#define FF_PROFILE_MPEG2_MAIN   4
#define FF_PROFILE_MPEG2_SIMPLE 5
#define FF_PROFILE_MPEG2_SNR_SCALABLE  3
#define FF_PROFILE_MPEG2_SS     2
#define FF_PROFILE_MPEG4_ADVANCED_CODING           11
#define FF_PROFILE_MPEG4_ADVANCED_CORE             12
#define FF_PROFILE_MPEG4_ADVANCED_REAL_TIME         9
#define FF_PROFILE_MPEG4_ADVANCED_SCALABLE_TEXTURE 13
#define FF_PROFILE_MPEG4_ADVANCED_SIMPLE           15
#define FF_PROFILE_MPEG4_BASIC_ANIMATED_TEXTURE     7
#define FF_PROFILE_MPEG4_CORE                       2
#define FF_PROFILE_MPEG4_CORE_SCALABLE             10
#define FF_PROFILE_MPEG4_HYBRID                     8
#define FF_PROFILE_MPEG4_MAIN                       3
#define FF_PROFILE_MPEG4_N_BIT                      4
#define FF_PROFILE_MPEG4_SCALABLE_TEXTURE           5
#define FF_PROFILE_MPEG4_SIMPLE                     0
#define FF_PROFILE_MPEG4_SIMPLE_FACE_ANIMATION      6
#define FF_PROFILE_MPEG4_SIMPLE_SCALABLE            1
#define FF_PROFILE_MPEG4_SIMPLE_STUDIO             14
#define FF_PROFILE_PRORES_4444      4
#define FF_PROFILE_PRORES_HQ        3
#define FF_PROFILE_PRORES_LT        1
#define FF_PROFILE_PRORES_PROXY     0
#define FF_PROFILE_PRORES_STANDARD  2
#define FF_PROFILE_PRORES_XQ        5
#define FF_PROFILE_RESERVED -100
#define FF_PROFILE_SBC_MSBC                         1
#define FF_PROFILE_UNKNOWN -99
#define FF_PROFILE_VC1_ADVANCED 3
#define FF_PROFILE_VC1_COMPLEX  2
#define FF_PROFILE_VC1_MAIN     1
#define FF_PROFILE_VC1_SIMPLE   0
#define FF_PROFILE_VP9_0                            0
#define FF_PROFILE_VP9_1                            1
#define FF_PROFILE_VP9_2                            2
#define FF_PROFILE_VP9_3                            3
#define FF_PROFILE_VVC_MAIN_10                      1
#define FF_PROFILE_VVC_MAIN_10_444                 33
#define FF_SUB_CHARENC_MODE_AUTOMATIC    0  
#define FF_SUB_CHARENC_MODE_DO_NOTHING  -1  
#define FF_SUB_CHARENC_MODE_IGNORE       2  
#define FF_SUB_CHARENC_MODE_PRE_DECODER  1  
#define FF_SUB_TEXT_FMT_ASS              0
#define FF_THREAD_FRAME   1 
#define FF_THREAD_SLICE   2 
#define PARSER_FLAG_COMPLETE_FRAMES           0x0001
#define PARSER_FLAG_FETCHED_OFFSET            0x0004
#define PARSER_FLAG_ONCE                      0x0002
#define PARSER_FLAG_USE_CODEC_TS              0x1000
#define SLICE_FLAG_ALLOW_FIELD    0x0002 
#define SLICE_FLAG_ALLOW_PLANE    0x0004 
#define SLICE_FLAG_CODED_ORDER    0x0001 

#define AV_FRAME_FLAG_CORRUPT       (1 << 0)
#define AV_FRAME_FLAG_DISCARD   (1 << 2)
#define AV_NUM_DATA_POINTERS 8
#define FF_DECODE_ERROR_CONCEALMENT_ACTIVE  4
#define FF_DECODE_ERROR_DECODE_SLICES       8
#define FF_DECODE_ERROR_INVALID_BITSTREAM   1
#define FF_DECODE_ERROR_MISSING_REFERENCE   2

#define ID_STRING "nut/multimedia container\0"
#define     INDEX_STARTCODE (0xDD672F23E64EULL + (((uint64_t)('N'<<8) + 'X')<<48))
#define      INFO_STARTCODE (0xAB68B596BA78ULL + (((uint64_t)('N'<<8) + 'I')<<48))
#define      MAIN_STARTCODE (0x7A561F5F04ADULL + (((uint64_t)('N'<<8) + 'M')<<48))
#define MAX_DISTANCE (1024*32-1)
#define NUT_BROADCAST 1 
#define NUT_MAX_VERSION 4
#define NUT_MIN_VERSION 2
#define NUT_PIPE 2      
#define NUT_STABLE_VERSION 3
#define    STREAM_STARTCODE (0x11405BF2F9DBULL + (((uint64_t)('N'<<8) + 'S')<<48))
#define SYNCPOINT_STARTCODE (0xE4ADEECA4569ULL + (((uint64_t)('N'<<8) + 'K')<<48))

#define FF_MOV_FLAG_MFRA_AUTO -1
#define FF_MOV_FLAG_MFRA_DTS 1
#define FF_MOV_FLAG_MFRA_PTS 2
#define MOV_FRAG_SAMPLE_FLAG_DEGRADATION_PRIORITY_MASK 0x0000ffff
#define MOV_FRAG_SAMPLE_FLAG_DEPENDED_MASK             0x00c00000
#define MOV_FRAG_SAMPLE_FLAG_DEPENDS_MASK              0x03000000
#define MOV_FRAG_SAMPLE_FLAG_DEPENDS_NO                0x02000000
#define MOV_FRAG_SAMPLE_FLAG_DEPENDS_YES               0x01000000
#define MOV_FRAG_SAMPLE_FLAG_IS_NON_SYNC               0x00010000
#define MOV_FRAG_SAMPLE_FLAG_PADDING_MASK              0x000e0000
#define MOV_FRAG_SAMPLE_FLAG_REDUNDANCY_MASK           0x00300000
#define MOV_ISMV_TTML_TAG MKTAG('d', 'f', 'x', 'p')
#define MOV_MP4_TTML_TAG  MKTAG('s', 't', 'p', 'p')
#define MOV_SAMPLE_DEPENDENCY_NO      0x2
#define MOV_SAMPLE_DEPENDENCY_UNKNOWN 0x0
#define MOV_SAMPLE_DEPENDENCY_YES     0x1
#define MOV_TFHD_BASE_DATA_OFFSET       0x01
#define MOV_TFHD_DEFAULT_BASE_IS_MOOF 0x020000
#define MOV_TFHD_DEFAULT_DURATION       0x08
#define MOV_TFHD_DEFAULT_FLAGS          0x20
#define MOV_TFHD_DEFAULT_SIZE           0x10
#define MOV_TFHD_DURATION_IS_EMPTY  0x010000
#define MOV_TFHD_STSD_ID                0x02
#define MOV_TKHD_FLAG_ENABLED       0x0001
#define MOV_TKHD_FLAG_IN_MOVIE      0x0002
#define MOV_TKHD_FLAG_IN_POSTER     0x0008
#define MOV_TKHD_FLAG_IN_PREVIEW    0x0004
#define MOV_TRUN_DATA_OFFSET            0x01
#define MOV_TRUN_FIRST_SAMPLE_FLAGS     0x04
#define MOV_TRUN_SAMPLE_CTS            0x800
#define MOV_TRUN_SAMPLE_DURATION       0x100
#define MOV_TRUN_SAMPLE_FLAGS          0x400
#define MOV_TRUN_SAMPLE_SIZE           0x200
#define MP4DecConfigDescrTag            0x04
#define MP4DecSpecificDescrTag          0x05
#define MP4ESDescrTag                   0x03
#define MP4IODescrTag                   0x02
#define MP4ODescrTag                    0x01
#define MP4SLDescrTag                   0x06
#define TAG_IS_AVCI(tag)                    \
    ((tag) == MKTAG('a', 'i', '5', 'p') ||  \
     (tag) == MKTAG('a', 'i', '5', 'q') ||  \
     (tag) == MKTAG('a', 'i', '5', '2') ||  \
     (tag) == MKTAG('a', 'i', '5', '3') ||  \
     (tag) == MKTAG('a', 'i', '5', '5') ||  \
     (tag) == MKTAG('a', 'i', '5', '6') ||  \
     (tag) == MKTAG('a', 'i', '1', 'p') ||  \
     (tag) == MKTAG('a', 'i', '1', 'q') ||  \
     (tag) == MKTAG('a', 'i', '1', '2') ||  \
     (tag) == MKTAG('a', 'i', '1', '3') ||  \
     (tag) == MKTAG('a', 'i', '1', '5') ||  \
     (tag) == MKTAG('a', 'i', '1', '6') ||  \
     (tag) == MKTAG('a', 'i', 'v', 'x') ||  \
     (tag) == MKTAG('A', 'V', 'i', 'n'))


#define AV_STEREO3D_FLAG_INVERT     (1 << 0)





#define URL_COMPONENT_HAVE(uc, component) \
    ((uc).url_component_end_##component > (uc).component)
#define URL_PROTOCOL_FLAG_NESTED_SCHEME 1 
#define URL_PROTOCOL_FLAG_NETWORK       2 
#define url_component_end_authority   userinfo
#define url_component_end_authority_full path
#define url_component_end_fragment    end
#define url_component_end_host        port
#define url_component_end_path        query
#define url_component_end_port        path
#define url_component_end_query       fragment
#define url_component_end_scheme      authority
#define url_component_end_userinfo    host

#define DEF(type, name, bytes, read, write)                                  \
static av_always_inline type bytestream_get_ ## name(const uint8_t **b)        \
{                                                                              \
    (*b) += bytes;                                                             \
    return read(*b - bytes);                                                   \
}                                                                              \
static av_always_inline void bytestream_put_ ## name(uint8_t **b,              \
                                                     const type value)         \
{                                                                              \
    write(*b, value);                                                          \
    (*b) += bytes;                                                             \
}                                                                              \
static av_always_inline void bytestream2_put_ ## name ## u(PutByteContext *p,  \
                                                           const type value)   \
{                                                                              \
    bytestream_put_ ## name(&p->buffer, value);                                \
}                                                                              \
static av_always_inline void bytestream2_put_ ## name(PutByteContext *p,       \
                                                      const type value)        \
{                                                                              \
    if (!p->eof && (p->buffer_end - p->buffer >= bytes)) {                     \
        write(p->buffer, value);                                               \
        p->buffer += bytes;                                                    \
    } else                                                                     \
        p->eof = 1;                                                            \
}                                                                              \
static av_always_inline type bytestream2_get_ ## name ## u(GetByteContext *g)  \
{                                                                              \
    return bytestream_get_ ## name(&g->buffer);                                \
}                                                                              \
static av_always_inline type bytestream2_get_ ## name(GetByteContext *g)       \
{                                                                              \
    if (g->buffer_end - g->buffer < bytes) {                                   \
        g->buffer = g->buffer_end;                                             \
        return 0;                                                              \
    }                                                                          \
    return bytestream2_get_ ## name ## u(g);                                   \
}                                                                              \
static av_always_inline type bytestream2_peek_ ## name ## u(GetByteContext *g) \
{                                                                              \
    return read(g->buffer);                                                    \
}                                                                              \
static av_always_inline type bytestream2_peek_ ## name(GetByteContext *g)      \
{                                                                              \
    if (g->buffer_end - g->buffer < bytes)                                     \
        return 0;                                                              \
    return bytestream2_peek_ ## name ## u(g);                                  \
}
#   define bytestream2_get_ne16  bytestream2_get_be16
#   define bytestream2_get_ne16u bytestream2_get_be16u
#   define bytestream2_get_ne24  bytestream2_get_be24
#   define bytestream2_get_ne24u bytestream2_get_be24u
#   define bytestream2_get_ne32  bytestream2_get_be32
#   define bytestream2_get_ne32u bytestream2_get_be32u
#   define bytestream2_get_ne64  bytestream2_get_be64
#   define bytestream2_get_ne64u bytestream2_get_be64u
#   define bytestream2_peek_ne16 bytestream2_peek_be16
#   define bytestream2_peek_ne24 bytestream2_peek_be24
#   define bytestream2_peek_ne32 bytestream2_peek_be32
#   define bytestream2_peek_ne64 bytestream2_peek_be64
#   define bytestream2_put_ne16  bytestream2_put_be16
#   define bytestream2_put_ne24  bytestream2_put_be24
#   define bytestream2_put_ne32  bytestream2_put_be32
#   define bytestream2_put_ne64  bytestream2_put_be64

#define AV_COPY(n, d, s) \
    (((av_alias##n*)(d))->u##n = ((const av_alias##n*)(s))->u##n)
#   define AV_COPY128(d, s)                    \
    do {                                       \
        AV_COPY64(d, s);                       \
        AV_COPY64((char*)(d)+8, (char*)(s)+8); \
    } while(0)
#   define AV_COPY128U(d, s)                                    \
    do {                                                        \
        AV_COPY64U(d, s);                                       \
        AV_COPY64U((char *)(d) + 8, (const char *)(s) + 8);     \
    } while(0)
#   define AV_COPY16(d, s) AV_COPY(16, d, s)
#   define AV_COPY16U(d, s) AV_COPYU(16, d, s)
#   define AV_COPY32(d, s) AV_COPY(32, d, s)
#   define AV_COPY32U(d, s) AV_COPYU(32, d, s)
#   define AV_COPY64(d, s) AV_COPY(64, d, s)
#   define AV_COPY64U(d, s) AV_COPYU(64, d, s)
#define AV_COPYU(n, d, s) AV_WN##n(d, AV_RN##n(s));
#   define AV_RB(s, p)    AV_RN##s(p)
#       define AV_RB16(p) AV_RN16(p)
#       define AV_RB24(p) AV_RN24(p)
#       define AV_RB32(p) AV_RN32(p)
#       define AV_RB48(p) AV_RN48(p)
#       define AV_RB64(p) AV_RN64(p)
#define AV_RB8(x)     (((const uint8_t*)(x))[0])
#   define AV_RL(s, p)    av_bswap##s(AV_RN##s(p))
#       define AV_RL16(p) AV_RN16(p)
#       define AV_RL24(p) AV_RN24(p)
#       define AV_RL32(p) AV_RN32(p)
#       define AV_RL48(p) AV_RN48(p)
#       define AV_RL64(p) AV_RN64(p)
#   define AV_RL64A(p) AV_RLA(64, p)
#define AV_RL8(x)     AV_RB8(x)
#   define AV_RLA(s, p)    av_bswap##s(AV_RN##s##A(p))
#   define AV_RN(s, p) (((const union unaligned_##s *) (p))->l)
#       define AV_RN16(p) AV_RL16(p)
#   define AV_RN16A(p) AV_RNA(16, p)
#       define AV_RN24(p) AV_RB24(p)
#       define AV_RN32(p) AV_RB32(p)
#   define AV_RN32A(p) AV_RNA(32, p)
#       define AV_RN48(p) AV_RB48(p)
#       define AV_RN64(p) AV_RB64(p)
#   define AV_RN64A(p) AV_RNA(64, p)
#define AV_RNA(s, p)    (((const av_alias##s*)(p))->u##s)
#define AV_SWAP(n, a, b) FFSWAP(av_alias##n, *(av_alias##n*)(a), *(av_alias##n*)(b))
#   define AV_SWAP64(a, b) AV_SWAP(64, a, b)
#   define AV_WB(s, p, v) AV_WN##s(p, v)
#       define AV_WB16(p, v) AV_WN16(p, v)
#       define AV_WB24(p, v) AV_WN24(p, v)
#       define AV_WB32(p, v) AV_WN32(p, v)
#       define AV_WB48(p, v) AV_WN48(p, v)
#       define AV_WB64(p, v) AV_WN64(p, v)
#define AV_WB8(p, d)  do { ((uint8_t*)(p))[0] = (d); } while(0)
#   define AV_WL(s, p, v) AV_WN##s(p, av_bswap##s(v))
#       define AV_WL16(p, v) AV_WN16(p, v)
#       define AV_WL24(p, v) AV_WN24(p, v)
#       define AV_WL32(p, v) AV_WN32(p, v)
#       define AV_WL48(p, v) AV_WN48(p, v)
#       define AV_WL64(p, v) AV_WN64(p, v)
#   define AV_WL64A(p, v) AV_WLA(64, p, v)
#define AV_WL8(p, d)  AV_WB8(p, d)
#   define AV_WLA(s, p, v) AV_WN##s##A(p, av_bswap##s(v))
#   define AV_WN(s, p, v) ((((union unaligned_##s *) (p))->l) = (v))
#       define AV_WN16(p, v) AV_WL16(p, v)
#   define AV_WN16A(p, v) AV_WNA(16, p, v)
#       define AV_WN24(p, v) AV_WB24(p, v)
#       define AV_WN32(p, v) AV_WB32(p, v)
#   define AV_WN32A(p, v) AV_WNA(32, p, v)
#       define AV_WN48(p, v) AV_WB48(p, v)
#       define AV_WN64(p, v) AV_WB64(p, v)
#   define AV_WN64A(p, v) AV_WNA(64, p, v)
#define AV_WNA(s, p, v) (((av_alias##s*)(p))->u##s = (v))
#define AV_ZERO(n, d) (((av_alias##n*)(d))->u##n = 0)
#   define AV_ZERO128(d)         \
    do {                         \
        AV_ZERO64(d);            \
        AV_ZERO64((char*)(d)+8); \
    } while(0)
#   define AV_ZERO16(d) AV_ZERO(16, d)
#   define AV_ZERO32(d) AV_ZERO(32, d)
#   define AV_ZERO64(d) AV_ZERO(64, d)

#define av_assert0(cond) do {                                           \
    if (!(cond)) {                                                      \
        av_log(NULL, AV_LOG_PANIC, "Assertion %s failed at %s:%d\n",    \
               AV_STRINGIFY(cond), "__FILE__", "__LINE__");                 \
        abort();                                                        \
    }                                                                   \
} while (0)
#define av_assert1(cond) av_assert0(cond)
#define av_assert2(cond) av_assert0(cond)
#define av_assert2_fpu() av_assert0_fpu()


#define INFINITY       av_int2float(0x7f800000)
#define M_E            2.7182818284590452354   
#define M_LN10         2.30258509299404568402  
#define M_LN2          0.69314718055994530942  
#define M_LOG2_10      3.32192809488736234787  
#define M_PHI          1.61803398874989484820   
#define M_PI           3.14159265358979323846  
#define M_PI_2         1.57079632679489661923  
#define M_SQRT1_2      0.70710678118654752440  
#define M_SQRT2        1.41421356237309504880  
#define NAN            av_int2float(0x7fc00000)

#define AV_BE2NE16C(x) AV_BE2NEC(16, x)
#define AV_BE2NE32C(x) AV_BE2NEC(32, x)
#define AV_BE2NE64C(x) AV_BE2NEC(64, x)
#define AV_BE2NEC(s, x) (x)
#define AV_BSWAP16C(x) (((x) << 8 & 0xff00)  | ((x) >> 8 & 0x00ff))
#define AV_BSWAP32C(x) (AV_BSWAP16C(x) << 16 | AV_BSWAP16C((x) >> 16))
#define AV_BSWAP64C(x) (AV_BSWAP32C(x) << 32 | AV_BSWAP32C((x) >> 32))
#define AV_BSWAPC(s, x) AV_BSWAP##s##C(x)
#define AV_LE2NE16C(x) AV_LE2NEC(16, x)
#define AV_LE2NE32C(x) AV_LE2NEC(32, x)
#define AV_LE2NE64C(x) AV_LE2NEC(64, x)
#define AV_LE2NEC(s, x) AV_BSWAPC(s, x)
#define av_be2ne16(x) (x)
#define av_be2ne32(x) (x)
#define av_be2ne64(x) (x)
#define av_le2ne16(x) av_bswap16(x)
#define av_le2ne32(x) av_bswap32(x)
#define av_le2ne64(x) av_bswap64(x)

#define AV_ESCAPE_FLAG_STRICT (1 << 1)
#define AV_ESCAPE_FLAG_WHITESPACE (1 << 0)
#define AV_ESCAPE_FLAG_XML_DOUBLE_QUOTES (1 << 3)
#define AV_ESCAPE_FLAG_XML_SINGLE_QUOTES (1 << 2)
#define AV_UTF8_FLAG_ACCEPT_ALL \
    AV_UTF8_FLAG_ACCEPT_INVALID_BIG_CODES|AV_UTF8_FLAG_ACCEPT_NON_CHARACTERS|AV_UTF8_FLAG_ACCEPT_SURROGATES
#define AV_UTF8_FLAG_ACCEPT_INVALID_BIG_CODES          1 
#define AV_UTF8_FLAG_ACCEPT_NON_CHARACTERS             2 
#define AV_UTF8_FLAG_ACCEPT_SURROGATES                 4 
#define AV_UTF8_FLAG_EXCLUDE_XML_INVALID_CONTROL_CODES 8 
