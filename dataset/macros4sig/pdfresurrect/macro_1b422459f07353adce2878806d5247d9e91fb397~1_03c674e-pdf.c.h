#include<stdio.h>
#include<stdlib.h>
#include<ctype.h>
#include<string.h>
#define ERR(...) {fprintf(stderr, TAG" -- Error -- " __VA_ARGS__);}
#define EXEC_NAME "pdfresurrect"

#define TAG "[pdfresurrect]"
#define VER       VER_MAJOR"."VER_MINOR 
#define VER_MAJOR "0"
#define VER_MINOR "21b"
#define KV_MAX_KEY_LENGTH   32
#define KV_MAX_VALUE_LENGTH 128
#define PDF_FLAG_DISP_CREATOR 2
#define PDF_FLAG_NONE         0
#define PDF_FLAG_QUIET        1

