





#include<stdarg.h>




#include<stddef.h>















#include<errno.h>

#include<stdio.h>

#include<fcntl.h>





























#include<stdlib.h>
#include<limits.h>





#include<string.h>
#include<ctype.h>



#include<time.h>



#include<zlib.h>









#include<math.h>



















#define SIZEOFBLENDERHEADER 12

#  define BLEND_MAKE_ID(a, b, c, d) ( (int)(a) << 24 | (int)(b) << 16 | (c) << 8 | (d) )
#define BLEN_THUMB_MEMSIZE_FILE(_x, _y) (sizeof(int) * (size_t)(2 + (_x) * (_y)))


#define BLO_GROUP_MAX 32
#define BLO_READ_SKIP_ALL \
	(BLO_READ_SKIP_USERDEF | BLO_READ_SKIP_DATA)

