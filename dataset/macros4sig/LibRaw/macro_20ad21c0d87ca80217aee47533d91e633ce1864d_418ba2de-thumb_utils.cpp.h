
#include<stdlib.h>
#include<memory.h>

#include<float.h>
#include<utime.h>




#include<fcntl.h>
#include<new>


#include<math.h>


#include<sys/stat.h>
#include<limits.h>
#include<string.h>

#include<time.h>
#include<sys/types.h>
#include<exception>


#include<zlib.h>
#include<errno.h>


#include<netinet/in.h>
#include<libintl.h>


#include<stdio.h>
#include<setjmp.h>

#include<ctype.h>
#include<unistd.h>




#define C  imgdata.color
#define CLIP(x) LIM(x, 0, 65535)
#define EXCEPTION_HANDLER(e)                                                   \
  do                                                                           \
  {                                                                            \
    switch (e)                                                                 \
    {                                                                          \
    case LIBRAW_EXCEPTION_MEMPOOL:                                             \
      recycle();                                                               \
      return LIBRAW_MEMPOOL_OVERFLOW;                                          \
    case LIBRAW_EXCEPTION_ALLOC:                                               \
      recycle();                                                               \
      return LIBRAW_UNSUFFICIENT_MEMORY;                                       \
    case LIBRAW_EXCEPTION_TOOBIG:                                              \
      recycle();                                                               \
      return LIBRAW_TOO_BIG;                                                   \
    case LIBRAW_EXCEPTION_DECODE_RAW:                                          \
    case LIBRAW_EXCEPTION_DECODE_JPEG:                                         \
      recycle();                                                               \
      return LIBRAW_DATA_ERROR;                                                \
    case LIBRAW_EXCEPTION_DECODE_JPEG2000:                                     \
      recycle();                                                               \
      return LIBRAW_DATA_ERROR;                                                \
    case LIBRAW_EXCEPTION_IO_EOF:                                              \
    case LIBRAW_EXCEPTION_IO_CORRUPT:                                          \
      recycle();                                                               \
      return LIBRAW_IO_ERROR;                                                  \
    case LIBRAW_EXCEPTION_CANCELLED_BY_CALLBACK:                               \
      recycle();                                                               \
      return LIBRAW_CANCELLED_BY_CALLBACK;                                     \
    case LIBRAW_EXCEPTION_BAD_CROP:                                            \
      recycle();                                                               \
      return LIBRAW_BAD_CROP;                                                  \
    default:                                                                   \
      return LIBRAW_UNSPECIFIED_ERROR;                                         \
    }                                                                          \
  } while (0)
#define ID libraw_internal_data.internal_data
#define IO libraw_internal_data.internal_output_params

#define LIM(x, min, max) MAX(min, MIN(x, max))
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MN imgdata.makernotes
#define O  imgdata.params
#define P1 imgdata.idata
#define S  imgdata.sizes
#define T  imgdata.thumbnail
#define THUMB_READ_BEYOND 16384
#define ZERO(a) memset(&a, 0, sizeof(a))

#define makeIs(idx) (imgdata.idata.maker_index == idx)
#define mnCamID imgdata.lens.makernotes.CamID
#define ABS(x) (((int)(x) ^ ((int)(x) >> 31)) - ((int)(x) >> 31))
#define BAYER(row, col)                                                        \
  image[((row) >> shrink) * iwidth + ((col) >> shrink)][FC(row, col)]
#define BAYER2(row, col)                                                       \
  image[((row) >> shrink) * iwidth + ((col) >> shrink)][fcol(row, col)]
#define BAYERC(row, col, c)                                                    \
  imgdata.image[((row) >> IO.shrink) * S.iwidth + ((col) >> IO.shrink)][c]
#define BG2RG1_2_RGBG(q)  (q ^ 2)
#define CLIP15(x) LIM((int)(x), 0, 32767)
#define DCRAW_VERSION "9.26"
#define FORC(cnt) for (c = 0; c < cnt; c++)
#define FORC3 FORC(3)
#define FORC4 FORC(4)
#define FORCC for (c = 0; c < colors && c < 4; c++)
#define GRBG_2_RGBG(q)    (q ^ (q >> 1) ^ 1)
#define GRGB_2_RGBG(q)    (q ^ 1)

#define LONG_BIT (8 * sizeof(long))



#define RAW(row, col) raw_image[(row)*raw_width + (col)]
#define RAWINDEX(row, col) ((row)*raw_width + (col))
#define RBGG_2_RGBG(q)    ((q >> 1) | ((q & 1) << 1))
#define RGGB_2_RGBG(q)    (q ^ (q >> 1))
#define SQR(x) ((x) * (x))
#define SWAP(a, b)                                                             \
  {                                                                            \
    a = a + b;                                                                 \
    b = a - b;                                                                 \
    a = a - b;                                                                 \
  }
#define ULIM(x, y, z) ((y) < (z) ? LIM(x, y, z) : LIM(x, z, y))
#define _(String) gettext(String)


#define my_swap(type, i, j)                                                    \
  {                                                                            \
    type t = i;                                                                \
    i = j;                                                                     \
    j = t;                                                                     \
  }
#define snprintf _snprintf
#define strcasecmp stricmp
#define strncasecmp strnicmp
#define LIBRAW_USE_STREAMS_DATASTREAM_MAXSIZE (250 * 1024L * 1024L)
#   define LIBRAW_WIN32_CALLS
#  define LIBRAW_WIN32_DLLDEFS
#    define LIBRAW_WIN32_UNICODEPATHS
#define RUN_CALLBACK(stage, iter, expect)                                      \
  if (callbacks.progress_cb)                                                   \
  {                                                                            \
    int rr = (*callbacks.progress_cb)(callbacks.progresscb_data, stage, iter,  \
                                      expect);                                 \
    if (rr != 0)                                                               \
      throw LIBRAW_EXCEPTION_CANCELLED_BY_CALLBACK;                            \
  }
#define _FILE_OFFSET_BITS 64


