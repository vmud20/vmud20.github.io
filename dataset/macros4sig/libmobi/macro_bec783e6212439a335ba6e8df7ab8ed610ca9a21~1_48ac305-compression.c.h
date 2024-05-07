#include<stdbool.h>

#include<string.h>
#include<time.h>
#include<stdio.h>


#include<stdint.h>
#define MOBI_DEBUG 0 
#define calloc(x, y) debug_calloc(x, y, "__FILE__", "__LINE__")
#define debug_print(fmt, ...) { \
    fprintf(stderr, "%s:%d:%s(): " fmt, "__FILE__", \
    "__LINE__", __func__, __VA_ARGS__); \
}
#define free(x) debug_free(x, "__FILE__", "__LINE__")

#define malloc(x) debug_malloc(x, "__FILE__", "__LINE__")
#define realloc(x, y) debug_realloc(x, y, "__FILE__", "__LINE__")
#define MOBI_EXPORT __attribute__((visibility("default"))) __declspec(dllexport) extern
#define MOBI_NOTSET UINT32_MAX



#define MOBI_HUFFMAN_MAXDEPTH 20 
#define MOBI_INLINE 

