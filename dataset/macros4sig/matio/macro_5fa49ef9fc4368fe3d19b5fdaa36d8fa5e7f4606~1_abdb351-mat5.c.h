#include<stdio.h>


#include<time.h>
#include<stddef.h>
#include<stdlib.h>
#include<string.h>
#include<math.h>
#include<stdarg.h>
#   define EXTERN extern "C"

#define CAT(X, Y) _CAT(X, Y)

#define READ_BLOCK_SIZE (8192)
#   define ZLIB_BYTE_PTR(a) ((Bytef *)(a))
#define _CAT(X, Y) X ## Y
#define mat_asprintf rpl_asprintf
#define mat_snprintf rpl_snprintf
#define mat_vasprintf rpl_vasprintf
#define mat_vsnprintf rpl_vsnprintf

#define MATIO_LOG_LEVEL_CRITICAL 1 << 1
#define MATIO_LOG_LEVEL_DEBUG    1 << 4
#define MATIO_LOG_LEVEL_ERROR    1
#define MATIO_LOG_LEVEL_MESSAGE  1 << 3
#define MATIO_LOG_LEVEL_WARNING  1 << 2
#define            Mat_Create(a,b) Mat_CreateVer(a,b,MAT_FT_DEFAULT)
