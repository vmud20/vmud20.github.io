#include<string.h>
#include<stdlib.h>
#include<math.h>

#include<limits.h>
#include<errno.h>
#include<stdio.h>
#define OPUS_CHANNEL_COUNT_MAX (255)
#define OP_ABSOLUTE_GAIN (3009)
#define OP_ALBUM_GAIN    (3007)
#  define OP_ARG_NONNULL(_x) __attribute__((__nonnull__(_x)))
#define OP_CHECK_CONST_CHAR_PTR(_x) ((_x)+((_x)-(const char *)(_x)))
#define OP_CHECK_INT(_x) ((void)((_x)==(opus_int32)0),(opus_int32)(_x))
#define OP_CHECK_SERVER_INFO_PTR(_x) ((_x)+((_x)-(OpusServerInfo *)(_x)))
#define OP_DEC_FORMAT_FLOAT (7040)
#define OP_DEC_FORMAT_SHORT (7008)
#define OP_DEC_USE_DEFAULT  (6720)
#define OP_EBADHEADER    (-133)
#define OP_EBADLINK      (-137)
#define OP_EBADPACKET    (-136)
#define OP_EBADTIMESTAMP (-139)
#define OP_EFAULT        (-129)
#define OP_EIMPL         (-130)
#define OP_EINVAL        (-131)
#define OP_ENOSEEK       (-138)
#define OP_ENOTAUDIO     (-135)
#define OP_ENOTFORMAT    (-132)
#define OP_EOF           (-2)
#define OP_EREAD         (-128)
#define OP_EVERSION      (-134)
#define OP_FALSE         (-1)
#define OP_GET_SERVER_INFO(_info) \
 OP_URL_OPT(OP_GET_SERVER_INFO_REQUEST),OP_CHECK_SERVER_INFO_PTR(_info)
#define OP_GET_SERVER_INFO_REQUEST            (6784)
#   define OP_GNUC_PREREQ(_maj,_min) \
 (("__GNUC__"<<16)+"__GNUC_MINOR__">=((_maj)<<16)+(_min))
#define OP_HEADER_GAIN   (0)
#define OP_HOLE          (-3)
#define OP_HTTP_PROXY_HOST(_host) \
 OP_URL_OPT(OP_HTTP_PROXY_HOST_REQUEST),OP_CHECK_CONST_CHAR_PTR(_host)
#define OP_HTTP_PROXY_HOST_REQUEST            (6528)
#define OP_HTTP_PROXY_PASS(_pass) \
 OP_URL_OPT(OP_HTTP_PROXY_PASS_REQUEST),OP_CHECK_CONST_CHAR_PTR(_pass)
#define OP_HTTP_PROXY_PASS_REQUEST            (6720)
#define OP_HTTP_PROXY_PORT(_port) \
 OP_URL_OPT(OP_HTTP_PROXY_PORT_REQUEST),OP_CHECK_INT(_port)
#define OP_HTTP_PROXY_PORT_REQUEST            (6592)
#define OP_HTTP_PROXY_USER(_user) \
 OP_URL_OPT(OP_HTTP_PROXY_USER_REQUEST),OP_CHECK_CONST_CHAR_PTR(_user)
#define OP_HTTP_PROXY_USER_REQUEST            (6656)
#define OP_PIC_FORMAT_GIF     (3)
#define OP_PIC_FORMAT_JPEG    (1)
#define OP_PIC_FORMAT_PNG     (2)
#define OP_PIC_FORMAT_UNKNOWN (-1)
#define OP_PIC_FORMAT_URL     (0)
#define OP_SSL_SKIP_CERTIFICATE_CHECK(_b) \
 OP_URL_OPT(OP_SSL_SKIP_CERTIFICATE_CHECK_REQUEST),OP_CHECK_INT(_b)
#define OP_SSL_SKIP_CERTIFICATE_CHECK_REQUEST (6464)
#define OP_TRACK_GAIN    (3008)
#define OP_URL_OPT(_request) ((char *)(_request))
#  define OP_WARN_UNUSED_RESULT __attribute__((__warn_unused_result__))
# define _opusfile_h (1)
#define OP_ADV_OFFSET(_offset,_amount) \
 (OP_MIN(_offset,OP_INT64_MAX-(_amount))+(_amount))
#  define OP_ALWAYS_TRUE(_cond) OP_ASSERT(_cond)
#  define OP_ASSERT(_cond) \
  do{ \
    if(OP_UNLIKELY(!(_cond)))OP_FATAL("assertion failed: " #_cond); \
  } \
  while(0)
# define OP_CLAMP(_lo,_x,_hi) (OP_MAX(_lo,OP_MIN(_x,_hi)))
#  define OP_FATAL(_str) (op_fatal_impl(_str,"__FILE__","__LINE__"))
# define  OP_INITSET   (4)
# define OP_INT32_MAX (2*(((ogg_int32_t)1<<30)-1)|1)
# define OP_INT32_MIN (-OP_INT32_MAX-1)
# define OP_INT64_MAX (2*(((ogg_int64_t)1<<62)-1)|1)
# define OP_INT64_MIN (-OP_INT64_MAX-1)
#  define OP_LIKELY(_x) (__builtin_expect(!!(_x),1))
#  define OP_LIKELY(_x)   (!!(_x))
# define OP_MAX(_a,_b)        ((_a)>(_b)?(_a):(_b))
# define OP_MIN(_a,_b)        ((_a)<(_b)?(_a):(_b))
# define OP_NCHANNELS_MAX (8)
# define  OP_NOTOPEN   (0)
# define  OP_OPENED    (2)
# define  OP_PARTOPEN  (1)
#   define OP_SOFT_CLIP (1)
# define  OP_STREAMSET (3)
#  define OP_UNLIKELY(_x) (__builtin_expect(!!(_x),0))
#  define OP_UNLIKELY(_x) (!!(_x))
#  define _FILE_OFFSET_BITS 64
#  define _GNU_SOURCE
#  define _LARGEFILE64_SOURCE
#  define _LARGEFILE_SOURCE
#  define _REENTRANT
# define _opusfile_internal_h (1)
