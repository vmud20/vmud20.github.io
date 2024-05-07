#include<assert.h>
#include<stdlib.h>
#include<stdint.h>
#include<math.h>
#include<float.h>
#include<string.h>
#include<stdio.h>
#include<wchar.h>
#include<stddef.h>
#define DCONV_DECIMAL_IN_SHORTEST_HIGH 16
#define DCONV_DECIMAL_IN_SHORTEST_LOW -4
    #define EXPORTFUNCTION __declspec(dllexport)
        #define FASTCALL_ATTR __attribute__((fastcall))
    #define FASTCALL_MSVC __fastcall
    #define INLINE_PREFIX inline
    #define JSON_DOUBLE_MAX_DECIMALS 15
    #define JSON_MAX_OBJECT_DEPTH 1024
    #define JSON_MAX_RECURSION_DEPTH 1024
    #define JSON_MAX_STACK_BUFFER_SIZE 1024

    #define LIKELY(x)       __builtin_expect(!!(x), 1)
    #define UNLIKELY(x)     __builtin_expect(!!(x), 0)



