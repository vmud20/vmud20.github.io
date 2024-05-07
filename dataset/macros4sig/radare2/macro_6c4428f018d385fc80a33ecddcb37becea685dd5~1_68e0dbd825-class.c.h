
#include<stdlib.h>
#include<stdio.h>
#include<math.h>
#include<string.h>





#include<stdarg.h>


#define R_BIN_JAVA_DOUBLE(x,y) rbin_java_raw_to_double(x, y)
#define R_BIN_JAVA_FLOAT(x,y) ((float)R_BIN_JAVA_UINT(x,y))
#define R_BIN_JAVA_LONG(x,y) ( ((ut64) R_BIN_JAVA_UINT (x, y) << 32) | ((ut64)R_BIN_JAVA_UINT (x, y+4) & 0xffffffff))
#define R_BIN_JAVA_MAXSTR 256
#define R_BIN_JAVA_UINT(x,y) ((ut32)(((x[y]&0xff)<<24)|((x[y+1]&0xff)<<16)|((x[y+2]&0xff)<<8)|(x[y+3]&0xff)))
#define R_BIN_JAVA_USHORT(x,y) ((ut16)(((0xff&x[y+1])|((x[y]&0xff)<<8)) & 0xffff))
#define U(x) x
#define UINT(x,y) (ut32)(((x[y]&0xff)<<24) \
|  ((x[y+1]&0xff)<<16)  \
|  ((x[y+2]&0xff)<<8)   \
|  (x[y+3]&0xff))
#define USHORT(x,y) ((ut16)(x[y+1]|(x[y]<<8)))

