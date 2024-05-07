#include<string.h>
#include<sys/types.h>
#include<math.h>



#include<stdint.h>


#include<stdbool.h>


#include<inttypes.h>
#include<stddef.h>
#include<sys/stat.h>


#include<stdlib.h>
#include<fcntl.h>
#include<stdio.h>
#define MAX_COLORSPACE_DESCRIPTION  512
#define MAX_COLORSPACE_NAME          64

#define BCM_CONFIG_FILE "config.ocio"



#define IM_MAX_SPACE 64

# define UINT64_MAX     18446744073709551615

#define DDS_MAKEFOURCC(ch0, ch1, ch2, ch3)\
	((unsigned long)(unsigned char)(ch0) | \
	((unsigned long)(unsigned char)(ch1) << 8) | \
	((unsigned long)(unsigned char)(ch2) << 16) | \
	((unsigned long)(unsigned char)(ch3) << 24))
#define FOURCC_DDS   (DDS_MAKEFOURCC('D','D','S',' '))
#define FOURCC_DXT1  (DDS_MAKEFOURCC('D','X','T','1'))
#define FOURCC_DXT2  (DDS_MAKEFOURCC('D','X','T','2'))
#define FOURCC_DXT3  (DDS_MAKEFOURCC('D','X','T','3'))
#define FOURCC_DXT4  (DDS_MAKEFOURCC('D','X','T','4'))
#define FOURCC_DXT5  (DDS_MAKEFOURCC('D','X','T','5'))
#define OPENEXR_COMPRESS (15)

#  define BIG_LONG ENDIAN_NOP
#  define BIG_SHORT ENDIAN_NOP
#define ENDIAN_NOP(x) (x)
#define IMB_DPI_DEFAULT 72.0f
#  define LITTLE_LONG SWAP_LONG
#  define LITTLE_SHORT SWAP_SHORT
#  define O_BINARY 0
#define SWAP_LONG(x) (((x) << 24) | (((x) & 0xff00) << 8) | (((x) >> 8) & 0xff00) | (((x) >> 24) & 0xff))
#define SWAP_SHORT(x) (((x & 0xff) << 8) | ((x >> 8) & 0xff))

