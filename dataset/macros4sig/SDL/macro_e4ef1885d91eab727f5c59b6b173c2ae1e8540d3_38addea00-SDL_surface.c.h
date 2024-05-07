

#include<stdint.h>




#include<mm3dnow.h>


#include<sys/types.h>
#include<stdarg.h>


#include<stdlib.h>





#include<xmmintrin.h>















#include<pmmintrin.h>







#include<emmintrin.h>

#include<stdio.h>
#include<endian.h>
#include<X11/Xlib.h>

#include<mmintrin.h>
#include<xcb/xcb.h>
#define ABGR8888_FROM_RGBA(Pixel, r, g, b, a)                           \
{                                                                       \
    Pixel = (a<<24)|(b<<16)|(g<<8)|r;                                   \
}
#define ALPHA_BLEND_RGB(sR, sG, sB, A, dR, dG, dB)                      \
do {                                                                    \
    dR = (Uint8)((((int)(sR-dR)*(int)A)/255)+dR);                       \
    dG = (Uint8)((((int)(sG-dG)*(int)A)/255)+dG);                       \
    dB = (Uint8)((((int)(sB-dB)*(int)A)/255)+dB);                       \
} while(0)
#define ALPHA_BLEND_RGBA(sR, sG, sB, sA, dR, dG, dB, dA)                \
do {                                                                    \
    dR = (Uint8)((((int)(sR-dR)*(int)sA)/255)+dR);                      \
    dG = (Uint8)((((int)(sG-dG)*(int)sA)/255)+dG);                      \
    dB = (Uint8)((((int)(sB-dB)*(int)sA)/255)+dB);                      \
    dA = (Uint8)((int)sA+dA-((int)sA*dA)/255);                          \
} while(0)
#define ARGB2101010_FROM_RGBA(Pixel, r, g, b, a)                        \
{                                                                       \
    r = r ? ((r << 2) | 0x3) : 0;                                       \
    g = g ? ((g << 2) | 0x3) : 0;                                       \
    b = b ? ((b << 2) | 0x3) : 0;                                       \
    a = (a * 3) / 255;                                                  \
    Pixel = (a<<30)|(r<<20)|(g<<10)|b;                                  \
}
#define ARGB8888_FROM_RGBA(Pixel, r, g, b, a)                           \
{                                                                       \
    Pixel = (a<<24)|(r<<16)|(g<<8)|b;                                   \
}
#define ASSEMBLE_RGB(buf, bpp, fmt, r, g, b)                            \
{                                                                       \
    switch (bpp) {                                                      \
        case 1: {                                                       \
            Uint8 Pixel;                                                \
                                                                        \
            PIXEL_FROM_RGB(Pixel, fmt, r, g, b);                        \
            *((Uint8 *)(buf)) = Pixel;                                  \
        }                                                               \
        break;                                                          \
                                                                        \
        case 2: {                                                       \
            Uint16 Pixel;                                               \
                                                                        \
            PIXEL_FROM_RGB(Pixel, fmt, r, g, b);                        \
            *((Uint16 *)(buf)) = Pixel;                                 \
        }                                                               \
        break;                                                          \
                                                                        \
        case 3: {                                                       \
            if (SDL_BYTEORDER == SDL_LIL_ENDIAN) {                      \
                *((buf)+fmt->Rshift/8) = r;                             \
                *((buf)+fmt->Gshift/8) = g;                             \
                *((buf)+fmt->Bshift/8) = b;                             \
            } else {                                                    \
                *((buf)+2-fmt->Rshift/8) = r;                           \
                *((buf)+2-fmt->Gshift/8) = g;                           \
                *((buf)+2-fmt->Bshift/8) = b;                           \
            }                                                           \
        }                                                               \
        break;                                                          \
                                                                        \
        case 4: {                                                       \
            Uint32 Pixel;                                               \
                                                                        \
            PIXEL_FROM_RGB(Pixel, fmt, r, g, b);                        \
            *((Uint32 *)(buf)) = Pixel;                                 \
        }                                                               \
        break;                                                          \
    }                                                                   \
}
#define ASSEMBLE_RGBA(buf, bpp, fmt, r, g, b, a)                        \
{                                                                       \
    switch (bpp) {                                                      \
        case 1: {                                                       \
            Uint8 _pixel;                                               \
                                                                        \
            PIXEL_FROM_RGBA(_pixel, fmt, r, g, b, a);                   \
            *((Uint8 *)(buf)) = _pixel;                                 \
        }                                                               \
        break;                                                          \
                                                                        \
        case 2: {                                                       \
            Uint16 _pixel;                                              \
                                                                        \
            PIXEL_FROM_RGBA(_pixel, fmt, r, g, b, a);                   \
            *((Uint16 *)(buf)) = _pixel;                                \
        }                                                               \
        break;                                                          \
                                                                        \
        case 3: {                                                       \
            if (SDL_BYTEORDER == SDL_LIL_ENDIAN) {                      \
                *((buf)+fmt->Rshift/8) = r;                             \
                *((buf)+fmt->Gshift/8) = g;                             \
                *((buf)+fmt->Bshift/8) = b;                             \
            } else {                                                    \
                *((buf)+2-fmt->Rshift/8) = r;                           \
                *((buf)+2-fmt->Gshift/8) = g;                           \
                *((buf)+2-fmt->Bshift/8) = b;                           \
            }                                                           \
        }                                                               \
        break;                                                          \
                                                                        \
        case 4: {                                                       \
            Uint32 _pixel;                                              \
                                                                        \
            PIXEL_FROM_RGBA(_pixel, fmt, r, g, b, a);                   \
            *((Uint32 *)(buf)) = _pixel;                                \
        }                                                               \
        break;                                                          \
    }                                                                   \
}
#define BGRA8888_FROM_RGBA(Pixel, r, g, b, a)                           \
{                                                                       \
    Pixel = (b<<24)|(g<<16)|(r<<8)|a;                                   \
}
#define DECLARE_ALIGNED(t,v,a)  t __attribute__((aligned(a))) v
#define DISEMBLE_RGB(buf, bpp, fmt, Pixel, r, g, b)                     \
do {                                                                    \
    switch (bpp) {                                                      \
        case 1:                                                         \
            Pixel = *((Uint8 *)(buf));                                  \
            RGB_FROM_PIXEL(Pixel, fmt, r, g, b);                        \
        break;                                                          \
                                                                        \
        case 2:                                                         \
            Pixel = *((Uint16 *)(buf));                                 \
            RGB_FROM_PIXEL(Pixel, fmt, r, g, b);                        \
        break;                                                          \
                                                                        \
        case 3: {                                                       \
            Pixel = 0;                                                  \
            if (SDL_BYTEORDER == SDL_LIL_ENDIAN) {                      \
                r = *((buf)+fmt->Rshift/8);                             \
                g = *((buf)+fmt->Gshift/8);                             \
                b = *((buf)+fmt->Bshift/8);                             \
            } else {                                                    \
                r = *((buf)+2-fmt->Rshift/8);                           \
                g = *((buf)+2-fmt->Gshift/8);                           \
                b = *((buf)+2-fmt->Bshift/8);                           \
            }                                                           \
        }                                                               \
        break;                                                          \
                                                                        \
        case 4:                                                         \
            Pixel = *((Uint32 *)(buf));                                 \
            RGB_FROM_PIXEL(Pixel, fmt, r, g, b);                        \
        break;                                                          \
                                                                        \
        default:                                                        \
                                               \
                Pixel = 0;                                              \
                r = g = b = 0;                                          \
        break;                                                          \
    }                                                                   \
} while (0)
#define DISEMBLE_RGBA(buf, bpp, fmt, Pixel, r, g, b, a)                 \
do {                                                                    \
    switch (bpp) {                                                      \
        case 1:                                                         \
            Pixel = *((Uint8 *)(buf));                                  \
            RGBA_FROM_PIXEL(Pixel, fmt, r, g, b, a);                    \
        break;                                                          \
                                                                        \
        case 2:                                                         \
            Pixel = *((Uint16 *)(buf));                                 \
            RGBA_FROM_PIXEL(Pixel, fmt, r, g, b, a);                    \
        break;                                                          \
                                                                        \
        case 3: {                                                       \
            Pixel = 0;                                                  \
            if (SDL_BYTEORDER == SDL_LIL_ENDIAN) {                      \
                r = *((buf)+fmt->Rshift/8);                             \
                g = *((buf)+fmt->Gshift/8);                             \
                b = *((buf)+fmt->Bshift/8);                             \
            } else {                                                    \
                r = *((buf)+2-fmt->Rshift/8);                           \
                g = *((buf)+2-fmt->Gshift/8);                           \
                b = *((buf)+2-fmt->Bshift/8);                           \
            }                                                           \
            a = 0xFF;                                                   \
        }                                                               \
        break;                                                          \
                                                                        \
        case 4:                                                         \
            Pixel = *((Uint32 *)(buf));                                 \
            RGBA_FROM_PIXEL(Pixel, fmt, r, g, b, a);                    \
        break;                                                          \
                                                                        \
        default:                                                        \
                                               \
            Pixel = 0;                                                  \
            r = g = b = a = 0;                                          \
        break;                                                          \
    }                                                                   \
} while (0)
#define DUFFS_LOOP(pixel_copy_increment, width)                         \
    DUFFS_LOOP8(pixel_copy_increment, width)
#define DUFFS_LOOP4(pixel_copy_increment, width)                        \
{ int n = (width+3)/4;                                                  \
    switch (width & 3) {                                                \
    case 0: do {    pixel_copy_increment;              \
    case 3:     pixel_copy_increment;                  \
    case 2:     pixel_copy_increment;                  \
    case 1:     pixel_copy_increment;                  \
        } while (--n > 0);                                              \
    }                                                                   \
}
#define DUFFS_LOOP8(pixel_copy_increment, width)                        \
{ int n = (width+7)/8;                                                  \
    switch (width & 7) {                                                \
    case 0: do {    pixel_copy_increment;              \
    case 7:     pixel_copy_increment;                  \
    case 6:     pixel_copy_increment;                  \
    case 5:     pixel_copy_increment;                  \
    case 4:     pixel_copy_increment;                  \
    case 3:     pixel_copy_increment;                  \
    case 2:     pixel_copy_increment;                  \
    case 1:     pixel_copy_increment;                  \
        } while ( --n > 0 );                                            \
    }                                                                   \
}
#define DUFFS_LOOP_124(pixel_copy_increment1,                           \
                       pixel_copy_increment2,                           \
                       pixel_copy_increment4, width)                    \
{ int n = width;                                                        \
    if (n & 1) {                                                        \
        pixel_copy_increment1; n -= 1;                                  \
    }                                                                   \
    if (n & 2) {                                                        \
        pixel_copy_increment2; n -= 2;                                  \
    }                                                                   \
    if (n & 4) {                                                        \
        pixel_copy_increment4; n -= 4;                                  \
    }                                                                   \
    if (n) {                                                            \
        n /= 8;                                                         \
        do {                                                            \
            pixel_copy_increment4;                                      \
            pixel_copy_increment4;                                      \
        } while (--n > 0);                                              \
    }                                                                   \
}
#define PIXEL_FROM_RGB(Pixel, fmt, r, g, b)                             \
{                                                                       \
    Pixel = ((r>>fmt->Rloss)<<fmt->Rshift)|                             \
        ((g>>fmt->Gloss)<<fmt->Gshift)|                                 \
        ((b>>fmt->Bloss)<<fmt->Bshift)|                                 \
        fmt->Amask;                                                     \
}
#define PIXEL_FROM_RGBA(Pixel, fmt, r, g, b, a)                         \
{                                                                       \
    Pixel = ((r>>fmt->Rloss)<<fmt->Rshift)|                             \
        ((g>>fmt->Gloss)<<fmt->Gshift)|                                 \
        ((b>>fmt->Bloss)<<fmt->Bshift)|                                 \
        ((a>>fmt->Aloss)<<fmt->Ashift);                                 \
}
#define RETRIEVE_RGB_PIXEL(buf, bpp, Pixel)                             \
do {                                                                    \
    switch (bpp) {                                                      \
        case 1:                                                         \
            Pixel = *((Uint8 *)(buf));                                  \
        break;                                                          \
                                                                        \
        case 2:                                                         \
            Pixel = *((Uint16 *)(buf));                                 \
        break;                                                          \
                                                                        \
        case 3: {                                                       \
            Uint8 *B = (Uint8 *)(buf);                                  \
            if (SDL_BYTEORDER == SDL_LIL_ENDIAN) {                      \
                Pixel = B[0] + (B[1] << 8) + (B[2] << 16);              \
            } else {                                                    \
                Pixel = (B[0] << 16) + (B[1] << 8) + B[2];              \
            }                                                           \
        }                                                               \
        break;                                                          \
                                                                        \
        case 4:                                                         \
            Pixel = *((Uint32 *)(buf));                                 \
        break;                                                          \
                                                                        \
        default:                                                        \
                Pixel = 0;                     \
        break;                                                          \
    }                                                                   \
} while (0)
#define RGB555_FROM_RGB(Pixel, r, g, b)                                 \
{                                                                       \
    Pixel = ((r>>3)<<10)|((g>>3)<<5)|(b>>3);                            \
}
#define RGB565_FROM_RGB(Pixel, r, g, b)                                 \
{                                                                       \
    Pixel = ((r>>3)<<11)|((g>>2)<<5)|(b>>3);                            \
}
#define RGB888_FROM_RGB(Pixel, r, g, b)                                 \
{                                                                       \
    Pixel = (r<<16)|(g<<8)|b;                                           \
}
#define RGBA8888_FROM_RGBA(Pixel, r, g, b, a)                           \
{                                                                       \
    Pixel = (r<<24)|(g<<16)|(b<<8)|a;                                   \
}
#define RGBA_FROM_8888(Pixel, fmt, r, g, b, a)                          \
{                                                                       \
    r = (Pixel&fmt->Rmask)>>fmt->Rshift;                                \
    g = (Pixel&fmt->Gmask)>>fmt->Gshift;                                \
    b = (Pixel&fmt->Bmask)>>fmt->Bshift;                                \
    a = (Pixel&fmt->Amask)>>fmt->Ashift;                                \
}
#define RGBA_FROM_ABGR8888(Pixel, r, g, b, a)                           \
{                                                                       \
    r = (Pixel&0xFF);                                                   \
    g = ((Pixel>>8)&0xFF);                                              \
    b = ((Pixel>>16)&0xFF);                                             \
    a = (Pixel>>24);                                                    \
}
#define RGBA_FROM_ARGB2101010(Pixel, r, g, b, a)                        \
{                                                                       \
    r = ((Pixel>>22)&0xFF);                                             \
    g = ((Pixel>>12)&0xFF);                                             \
    b = ((Pixel>>2)&0xFF);                                              \
    a = SDL_expand_byte[6][(Pixel>>30)];                                \
}
#define RGBA_FROM_ARGB8888(Pixel, r, g, b, a)                           \
{                                                                       \
    r = ((Pixel>>16)&0xFF);                                             \
    g = ((Pixel>>8)&0xFF);                                              \
    b = (Pixel&0xFF);                                                   \
    a = (Pixel>>24);                                                    \
}
#define RGBA_FROM_BGRA8888(Pixel, r, g, b, a)                           \
{                                                                       \
    r = ((Pixel>>8)&0xFF);                                              \
    g = ((Pixel>>16)&0xFF);                                             \
    b = (Pixel>>24);                                                    \
    a = (Pixel&0xFF);                                                   \
}
#define RGBA_FROM_PIXEL(Pixel, fmt, r, g, b, a)                         \
{                                                                       \
    r = SDL_expand_byte[fmt->Rloss][((Pixel&fmt->Rmask)>>fmt->Rshift)]; \
    g = SDL_expand_byte[fmt->Gloss][((Pixel&fmt->Gmask)>>fmt->Gshift)]; \
    b = SDL_expand_byte[fmt->Bloss][((Pixel&fmt->Bmask)>>fmt->Bshift)]; \
    a = SDL_expand_byte[fmt->Aloss][((Pixel&fmt->Amask)>>fmt->Ashift)]; \
}
#define RGBA_FROM_RGBA8888(Pixel, r, g, b, a)                           \
{                                                                       \
    r = (Pixel>>24);                                                    \
    g = ((Pixel>>16)&0xFF);                                             \
    b = ((Pixel>>8)&0xFF);                                              \
    a = (Pixel&0xFF);                                                   \
}
#define RGB_FROM_PIXEL(Pixel, fmt, r, g, b)                             \
{                                                                       \
    r = SDL_expand_byte[fmt->Rloss][((Pixel&fmt->Rmask)>>fmt->Rshift)]; \
    g = SDL_expand_byte[fmt->Gloss][((Pixel&fmt->Gmask)>>fmt->Gshift)]; \
    b = SDL_expand_byte[fmt->Bloss][((Pixel&fmt->Bmask)>>fmt->Bshift)]; \
}
#define RGB_FROM_RGB555(Pixel, r, g, b)                                 \
{                                                                       \
    r = SDL_expand_byte[3][((Pixel&0x7C00)>>10)];                       \
    g = SDL_expand_byte[3][((Pixel&0x03E0)>>5)];                        \
    b = SDL_expand_byte[3][(Pixel&0x001F)];                             \
}
#define RGB_FROM_RGB565(Pixel, r, g, b)                                 \
    {                                                                   \
    r = SDL_expand_byte[3][((Pixel&0xF800)>>11)];                       \
    g = SDL_expand_byte[2][((Pixel&0x07E0)>>5)];                        \
    b = SDL_expand_byte[3][(Pixel&0x001F)];                             \
}
#define RGB_FROM_RGB888(Pixel, r, g, b)                                 \
{                                                                       \
    r = ((Pixel&0xFF0000)>>16);                                         \
    g = ((Pixel&0xFF00)>>8);                                            \
    b = (Pixel&0xFF);                                                   \
}
#define SDL_COPY_ADD                0x00000020
#define SDL_COPY_BLEND              0x00000010
#define SDL_COPY_COLORKEY           0x00000100
#define SDL_COPY_MOD                0x00000040
#define SDL_COPY_MODULATE_ALPHA     0x00000002
#define SDL_COPY_MODULATE_COLOR     0x00000001
#define SDL_COPY_NEAREST            0x00000200
#define SDL_COPY_RLE_ALPHAKEY       0x00004000
#define SDL_COPY_RLE_COLORKEY       0x00002000
#define SDL_COPY_RLE_DESIRED        0x00001000
#define SDL_COPY_RLE_MASK           (SDL_COPY_RLE_DESIRED|SDL_COPY_RLE_COLORKEY|SDL_COPY_RLE_ALPHAKEY)
#define SDL_CPU_3DNOW               0x00000002
#define SDL_CPU_ALTIVEC_NOPREFETCH  0x00000020
#define SDL_CPU_ALTIVEC_PREFETCH    0x00000010
#define SDL_CPU_ANY                 0x00000000
#define SDL_CPU_MMX                 0x00000001
#define SDL_CPU_SSE                 0x00000004
#define SDL_CPU_SSE2                0x00000008


#define SDL_BlitScaled SDL_UpperBlitScaled
#define SDL_BlitSurface SDL_UpperBlit
#define SDL_DONTFREE        0x00000004  
#define SDL_LoadBMP(file)   SDL_LoadBMP_RW(SDL_RWFromFile(file, "rb"), 1)
#define SDL_MUSTLOCK(S) (((S)->flags & SDL_RLEACCEL) != 0)
#define SDL_PREALLOC        0x00000001  
#define SDL_RLEACCEL        0x00000002  
#define SDL_SWSURFACE       0           
#define SDL_SaveBMP(surface, file) \
        SDL_SaveBMP_RW(surface, SDL_RWFromFile(file, "wb"), 1)

#    define DECLSPEC    __declspec(dllimport)
#define NULL 0
#define SDLCALL __cdecl
#    define SDL_DEPRECATED __attribute__((deprecated))
#define SDL_FORCE_INLINE __forceinline
#define SDL_INLINE __inline__
#define SDL_NORETURN __attribute__((noreturn))
#    define SDL_UNUSED __attribute__((unused))
#  define _System 
#define __inline__ __inline

#define RW_SEEK_CUR 1       
#define RW_SEEK_END 2       
#define RW_SEEK_SET 0       
#define SDL_LoadFile(file, datasize)   SDL_LoadFile_RW(SDL_RWFromFile(file, "rb"), datasize, 1)
#define SDL_RWOPS_JNIFILE   3U  
#define SDL_RWOPS_MEMORY    4U  
#define SDL_RWOPS_MEMORY_RO 5U  
#define SDL_RWOPS_STDFILE   2U  
#define SDL_RWOPS_UNKNOWN   0U  
#define SDL_RWOPS_WINFILE   1U  
#define SDL_RWclose(ctx)        (ctx)->close(ctx)
#define SDL_RWread(ctx, ptr, size, n)   (ctx)->read(ctx, ptr, size, n)
#define SDL_RWseek(ctx, offset, whence) (ctx)->seek(ctx, offset, whence)
#define SDL_RWsize(ctx)         (ctx)->size(ctx)
#define SDL_RWtell(ctx)         (ctx)->seek(ctx, 0, RW_SEEK_CUR)
#define SDL_RWwrite(ctx, ptr, size, n)  (ctx)->write(ctx, ptr, size, n)

#define SDL_InvalidParamError(param)    SDL_SetError("Parameter '%s' is invalid", (param))
#define SDL_OutOfMemory()   SDL_Error(SDL_ENOMEM)
#define SDL_Unsupported()   SDL_Error(SDL_UNSUPPORTED)

#define M_PI    3.14159265358979323846264338327950288   
#define SDL_COMPILE_TIME_ASSERT(name, x)               \
       typedef int SDL_compile_time_assert_ ## name[(x) * 2 - 1]
#define SDL_FALSE 0
#define SDL_FOURCC(A, B, C, D) \
    ((SDL_static_cast(Uint32, SDL_static_cast(Uint8, (A))) << 0) | \
     (SDL_static_cast(Uint32, SDL_static_cast(Uint8, (B))) << 8) | \
     (SDL_static_cast(Uint32, SDL_static_cast(Uint8, (C))) << 16) | \
     (SDL_static_cast(Uint32, SDL_static_cast(Uint8, (D))) << 24))
#define SDL_ICONV_E2BIG     (size_t)-2
#define SDL_ICONV_EILSEQ    (size_t)-3
#define SDL_ICONV_EINVAL    (size_t)-4
#define SDL_ICONV_ERROR     (size_t)-1


#define SDL_MAX_SINT16  ((Sint16)0x7FFF)        
#define SDL_MAX_SINT32  ((Sint32)0x7FFFFFFF)    
#define SDL_MAX_SINT64  ((Sint64)0x7FFFFFFFFFFFFFFFll)      
#define SDL_MAX_SINT8   ((Sint8)0x7F)           
#define SDL_MAX_UINT16  ((Uint16)0xFFFF)        
#define SDL_MAX_UINT32  ((Uint32)0xFFFFFFFFu)   
#define SDL_MAX_UINT64  ((Uint64)0xFFFFFFFFFFFFFFFFull)     
#define SDL_MAX_UINT8   ((Uint8)0xFF)           
#define SDL_MIN_SINT16  ((Sint16)(~0x7FFF))     
#define SDL_MIN_SINT32  ((Sint32)(~0x7FFFFFFF)) 
#define SDL_MIN_SINT64  ((Sint64)(~0x7FFFFFFFFFFFFFFFll))   
#define SDL_MIN_SINT8   ((Sint8)(~0x7F))        
#define SDL_MIN_UINT16  ((Uint16)0x0000)        
#define SDL_MIN_UINT32  ((Uint32)0x00000000)    
#define SDL_MIN_UINT64  ((Uint64)(0x0000000000000000ull))   
#define SDL_MIN_UINT8   ((Uint8)0x00)           




#define SDL_PRINTF_FORMAT_STRING _Printf_format_string_
#define SDL_PRINTF_VARARG_FUNC( fmtargnumber )
#define SDL_PRIX64 PRIX64
#define SDL_PRIs64 PRIs64
#define SDL_PRIu64 PRIu64
#define SDL_PRIx64 PRIx64
#define SDL_SCANF_FORMAT_STRING _Scanf_format_string_impl_
#define SDL_SCANF_VARARG_FUNC( fmtargnumber )
#define SDL_STRINGIFY_ARG(arg)  #arg
#define SDL_TABLESIZE(table)    SDL_arraysize(table)
#define SDL_TRUE 1
#define SDL_arraysize(array)    (sizeof(array)/sizeof(array[0]))
#define SDL_calloc calloc
#define SDL_const_cast(type, expression) const_cast<type>(expression)
#define SDL_free free
#define SDL_iconv_utf8_locale(S)    SDL_iconv_string("", "UTF-8", S, SDL_strlen(S)+1)
#define SDL_iconv_utf8_ucs2(S)      (Uint16 *)SDL_iconv_string("UCS-2-INTERNAL", "UTF-8", S, SDL_strlen(S)+1)
#define SDL_iconv_utf8_ucs4(S)      (Uint32 *)SDL_iconv_string("UCS-4-INTERNAL", "UTF-8", S, SDL_strlen(S)+1)
#define SDL_malloc malloc
#define SDL_max(x, y) (((x) > (y)) ? (x) : (y))
#define SDL_memcmp memcmp
#define SDL_memcpy memcpy
#define SDL_memmove memmove
#define SDL_memset memset
#define SDL_min(x, y) (((x) < (y)) ? (x) : (y))
#define SDL_realloc realloc
#define SDL_reinterpret_cast(type, expression) reinterpret_cast<type>(expression)
#define SDL_snprintf snprintf
#define SDL_sscanf sscanf
#define SDL_stack_alloc(type, count)    (type*)alloca(sizeof(type)*(count))

#define SDL_static_cast(type, expression) static_cast<type>(expression)

#define SDL_strcasecmp strcasecmp
#define SDL_strchr strchr
#define SDL_strcmp strcmp
#define SDL_strdup strdup
#define SDL_strlcat strlcat
#define SDL_strlcpy strlcpy
#define SDL_strlen strlen
#define SDL_strncasecmp strncasecmp
#define SDL_strncmp strncmp
#define SDL_strrchr strrchr
#define SDL_strstr strstr
#define SDL_vsnprintf vsnprintf
#define SDL_vsscanf vsscanf
#define SDL_zero(x) SDL_memset(&(x), 0, sizeof((x)))
#define SDL_zerop(x) SDL_memset((x), 0, sizeof(*(x)))
#  define _USE_MATH_DEFINES

#define HAVE_GCC_SYNC_LOCK_TEST_AND_SET 1
#define HAVE_STDARG_H   1
#define HAVE_STDDEF_H   1
#define HAVE_STDINT_H 1
#define SDL_AUDIO_DRIVER_DUMMY  1
#define SDL_FILESYSTEM_DUMMY  1
#define SDL_HAPTIC_DISABLED 1
#define SDL_JOYSTICK_DISABLED   1
#define SDL_LOADSO_DISABLED 1
#define SDL_THREADS_DISABLED    1
#define SDL_TIMERS_DISABLED 1
#define SDL_VIDEO_DRIVER_DUMMY  1

#define HAVE_WINAPIFAMILY_H __has_include(<winapifamily.h>)

#define WINAPI_FAMILY_WINRT (!WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP) && WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_APP))
#define __AIX__     1
#define __ANDROID__ 1
#define __BSDI__    1
#define __DREAMCAST__   1
#define __FREEBSD__ 1
#define __HAIKU__   1
#define __HPUX__    1
#define __IPHONEOS__ 1
#define __IRIX__    1
#define __LINUX__   1
#define __MACOSX__  1
#define __NACL__ 1
#define __NETBSD__  1
#define __OPENBSD__ 1
#define __OS2__     1
#define __OSF__     1
#define __PNACL__ 1
#define __PSP__ 1
#define __QNXNTO__  1
#define __RISCOS__  1

#define __SOLARIS__ 1
#define __TVOS__ 1
#define __WIN32__ 1
#define __WINDOWS__ 1
#define __WINRT__ 1
#define HAVE_ABS    1
#define HAVE_ACOS  1
#define HAVE_ALLOCA 1
#define HAVE_ALLOCA_H       1
#define HAVE_ASIN  1
#define HAVE_ATAN   1
#define HAVE_ATAN2  1
#define HAVE_ATOF   1
#define HAVE_ATOI   1
#define HAVE_BCOPY  1
#define HAVE_CALLOC 1
#define HAVE_CEIL   1
#define HAVE_COPYSIGN   1
#define HAVE_COS    1
#define HAVE_COSF   1
#define HAVE_CTYPE_H    1
#define HAVE_FABS   1
#define HAVE_FLOOR  1
#define HAVE_FREE   1
#define HAVE_GCC_ATOMICS    1
#define HAVE_GETENV 1
#define HAVE_INTTYPES_H 1
#define HAVE_LIMITS_H   1
#define HAVE_LOG    1
#define HAVE_MALLOC 1
#define HAVE_MATH_H 1
#define HAVE_MEMCMP 1
#define HAVE_MEMCPY 1
#define HAVE_MEMMOVE    1
#define HAVE_MEMSET 1
#define HAVE_M_PI   1
#define HAVE_NANOSLEEP  1
#define HAVE_POW    1
#define HAVE_PUTENV 1
#define HAVE_QSORT  1
#define HAVE_REALLOC    1
#define HAVE_SCALBN 1
#define HAVE_SETENV 1
#define HAVE_SETJMP 1
#define HAVE_SIGNAL_H   1
#define HAVE_SIN    1
#define HAVE_SINF   1
#define HAVE_SQRT   1
#define HAVE_SQRTF  1
#define HAVE_STDIO_H    1
#define HAVE_STRCASECMP 1
#define HAVE_STRCHR 1
#define HAVE_STRCMP 1
#define HAVE_STRING_H   1
#define HAVE_STRLCAT    1
#define HAVE_STRLCPY    1
#define HAVE_STRLEN 1
#define HAVE_STRNCASECMP 1
#define HAVE_STRNCMP    1
#define HAVE_STRRCHR    1
#define HAVE_STRSTR 1
#define HAVE_STRTOD 1
#define HAVE_STRTOL 1
#define HAVE_STRTOLL    1
#define HAVE_STRTOUL    1
#define HAVE_STRTOULL   1
#define HAVE_SYS_TYPES_H    1
#define HAVE_TAN    1
#define HAVE_TANF   1
#define HAVE_UNSETENV   1
#define HAVE_VSNPRINTF  1
#define HAVE_VSSCANF 1
#define LACKS_SYS_MMAN_H 1
#define SDL_AUDIO_DRIVER_PSP    1
#define SDL_JOYSTICK_PSP        1
#define SDL_POWER_PSP          1
#define SDL_THREAD_PSP  1
#define SDL_TIMERS_PSP  1
#define SDL_VIDEO_DRIVER_PSP   1
#define SDL_VIDEO_RENDER_PSP   1

#define STDC_HEADERS    1
#define HAVE_SIGACTION 1
#define HAVE_SYSCONF    1
#define SDL_AUDIO_DRIVER_ANDROID    1
#define SDL_FILESYSTEM_ANDROID   1
#define SDL_HAPTIC_ANDROID    1
#define SDL_JOYSTICK_ANDROID    1
#define SDL_LOADSO_DLOPEN   1
#define SDL_POWER_ANDROID 1
#define SDL_THREAD_PTHREAD  1
#define SDL_THREAD_PTHREAD_RECURSIVE_MUTEX  1
#define SDL_TIMER_UNIX  1
#define SDL_VIDEO_DRIVER_ANDROID 1
#define SDL_VIDEO_OPENGL_EGL 1
#define SDL_VIDEO_OPENGL_ES 1
#define SDL_VIDEO_OPENGL_ES2 1
#define SDL_VIDEO_RENDER_OGL_ES 1
#define SDL_VIDEO_RENDER_OGL_ES2    1
#define SDL_VIDEO_VULKAN 0

#define SIZEOF_VOIDP 4
#define HAVE_LIBUNWIND_H    1
#define HAVE_SYSCTLBYNAME 1
#define SDL_AUDIO_DRIVER_COREAUDIO 1
#define SDL_FILESYSTEM_COCOA   1
#define SDL_HAPTIC_DUMMY 1
#define SDL_IPHONE_KEYBOARD 1
#define SDL_IPHONE_LAUNCHSCREEN 1
#define SDL_IPHONE_MAX_GFORCE 5.0
#define SDL_JOYSTICK_MFI 1
#define SDL_POWER_UIKIT 1
#define SDL_VIDEO_DRIVER_UIKIT  1

#define HAVE_FLOAT_H    1
#define SDL_ALTIVEC_BLITTERS    1
#define SDL_ASSEMBLY_ROUTINES   1
#define SDL_AUDIO_DRIVER_DISK   1
#define SDL_HAPTIC_IOKIT    1
#define SDL_JOYSTICK_IOKIT  1
#define SDL_POWER_MACOSX 1
#define SDL_VIDEO_DRIVER_COCOA  1
#define SDL_VIDEO_DRIVER_X11_CONST_PARAM_XEXTADDDISPLAY 1
#define SDL_VIDEO_DRIVER_X11_DYNAMIC "/usr/X11R6/lib/libX11.6.dylib"
#define SDL_VIDEO_DRIVER_X11_DYNAMIC_XEXT "/usr/X11R6/lib/libXext.6.dylib"
#define SDL_VIDEO_DRIVER_X11_DYNAMIC_XINERAMA "/usr/X11R6/lib/libXinerama.1.dylib"
#define SDL_VIDEO_DRIVER_X11_DYNAMIC_XINPUT2 "/usr/X11R6/lib/libXi.6.dylib"
#define SDL_VIDEO_DRIVER_X11_DYNAMIC_XRANDR "/usr/X11R6/lib/libXrandr.2.dylib"
#define SDL_VIDEO_DRIVER_X11_DYNAMIC_XSS "/usr/X11R6/lib/libXss.1.dylib"
#define SDL_VIDEO_DRIVER_X11_DYNAMIC_XVIDMODE "/usr/X11R6/lib/libXxf86vm.1.dylib"
#define SDL_VIDEO_DRIVER_X11_HAS_XKBKEYCODETOKEYSYM 1
#define SDL_VIDEO_DRIVER_X11_SUPPORTS_GENERIC_EVENTS 1
#define SDL_VIDEO_DRIVER_X11_XDBE 1
#define SDL_VIDEO_DRIVER_X11_XINERAMA 1
#define SDL_VIDEO_DRIVER_X11_XINPUT2 1
#define SDL_VIDEO_DRIVER_X11_XRANDR 1
#define SDL_VIDEO_DRIVER_X11_XSCRNSAVER 1
#define SDL_VIDEO_DRIVER_X11_XSHAPE 1
#define SDL_VIDEO_DRIVER_X11_XVIDMODE 1
#define SDL_VIDEO_OPENGL    1
#define SDL_VIDEO_OPENGL_CGL    1
#define SDL_VIDEO_OPENGL_GLX    1
#define SDL_VIDEO_RENDER_OGL    1

#define DWORD_PTR DWORD
#define HAVE_DXGI_H 1
#define HAVE_LIBC 1
#define HAVE_XINPUT_H 1
#define HAVE__COPYSIGN 1
#define HAVE__FSEEKI64 1
#define HAVE__SCALB 1
#define HAVE__STRICMP 1
#define HAVE__STRNICMP 1
#define HAVE__STRREV 1
#define HAVE__STRUPR 1
#define LONG_PTR LONG
#define NTDDI_WIN10 0x0A000000
#define NTDDI_WINBLUE 0x06030000
#define SDL_HAPTIC_XINPUT   1
#define SDL_JOYSTICK_XINPUT 1
#define SDL_POWER_WINRT 1
#define SDL_THREAD_STDCPP   1
#define SDL_THREAD_WINDOWS  1
#define SDL_VIDEO_RENDER_D3D11  1



#define HAVE_DDRAW_H 1
#define HAVE_DINPUT_H 1
#define HAVE_DSOUND_H 1
#define HAVE__LTOA 1
#define HAVE__STRLWR 1
#define HAVE__ULTOA 1
#define SDL_AUDIO_DRIVER_DSOUND 1
#define SDL_AUDIO_DRIVER_WASAPI 1
#define SDL_AUDIO_DRIVER_WINMM  1
#define SDL_AUDIO_DRIVER_XAUDIO2    0
#define SDL_FILESYSTEM_WINDOWS  1
#define SDL_HAPTIC_DINPUT   1
#define SDL_JOYSTICK_DINPUT 1
#define SDL_LOADSO_WINDOWS  1
#define SDL_POWER_WINDOWS 1
#define SDL_TIMER_WINDOWS   1
#define SDL_VIDEO_DRIVER_WINDOWS    1
#define SDL_VIDEO_OPENGL_WGL    1
#define SDL_VIDEO_RENDER_D3D    1



#define SDL_ALPHA_OPAQUE 255
#define SDL_ALPHA_TRANSPARENT 0
#define SDL_BITSPERPIXEL(X) (((X) >> 8) & 0xFF)
#define SDL_BYTESPERPIXEL(X) \
    (SDL_ISPIXELFORMAT_FOURCC(X) ? \
        ((((X) == SDL_PIXELFORMAT_YUY2) || \
          ((X) == SDL_PIXELFORMAT_UYVY) || \
          ((X) == SDL_PIXELFORMAT_YVYU)) ? 2 : 1) : (((X) >> 0) & 0xFF))
#define SDL_Colour SDL_Color
#define SDL_DEFINE_PIXELFORMAT(type, order, layout, bits, bytes) \
    ((1 << 28) | ((type) << 24) | ((order) << 20) | ((layout) << 16) | \
     ((bits) << 8) | ((bytes) << 0))
#define SDL_DEFINE_PIXELFOURCC(A, B, C, D) SDL_FOURCC(A, B, C, D)
#define SDL_ISPIXELFORMAT_ALPHA(format)   \
    ((SDL_ISPIXELFORMAT_PACKED(format) && \
     ((SDL_PIXELORDER(format) == SDL_PACKEDORDER_ARGB) || \
      (SDL_PIXELORDER(format) == SDL_PACKEDORDER_RGBA) || \
      (SDL_PIXELORDER(format) == SDL_PACKEDORDER_ABGR) || \
      (SDL_PIXELORDER(format) == SDL_PACKEDORDER_BGRA))) || \
    (SDL_ISPIXELFORMAT_ARRAY(format) && \
     ((SDL_PIXELORDER(format) == SDL_ARRAYORDER_ARGB) || \
      (SDL_PIXELORDER(format) == SDL_ARRAYORDER_RGBA) || \
      (SDL_PIXELORDER(format) == SDL_ARRAYORDER_ABGR) || \
      (SDL_PIXELORDER(format) == SDL_ARRAYORDER_BGRA))))
#define SDL_ISPIXELFORMAT_ARRAY(format) \
    (!SDL_ISPIXELFORMAT_FOURCC(format) && \
     ((SDL_PIXELTYPE(format) == SDL_PIXELTYPE_ARRAYU8) || \
      (SDL_PIXELTYPE(format) == SDL_PIXELTYPE_ARRAYU16) || \
      (SDL_PIXELTYPE(format) == SDL_PIXELTYPE_ARRAYU32) || \
      (SDL_PIXELTYPE(format) == SDL_PIXELTYPE_ARRAYF16) || \
      (SDL_PIXELTYPE(format) == SDL_PIXELTYPE_ARRAYF32)))
#define SDL_ISPIXELFORMAT_FOURCC(format)    \
    ((format) && (SDL_PIXELFLAG(format) != 1))
#define SDL_ISPIXELFORMAT_INDEXED(format)   \
    (!SDL_ISPIXELFORMAT_FOURCC(format) && \
     ((SDL_PIXELTYPE(format) == SDL_PIXELTYPE_INDEX1) || \
      (SDL_PIXELTYPE(format) == SDL_PIXELTYPE_INDEX4) || \
      (SDL_PIXELTYPE(format) == SDL_PIXELTYPE_INDEX8)))
#define SDL_ISPIXELFORMAT_PACKED(format) \
    (!SDL_ISPIXELFORMAT_FOURCC(format) && \
     ((SDL_PIXELTYPE(format) == SDL_PIXELTYPE_PACKED8) || \
      (SDL_PIXELTYPE(format) == SDL_PIXELTYPE_PACKED16) || \
      (SDL_PIXELTYPE(format) == SDL_PIXELTYPE_PACKED32)))
#define SDL_PIXELFLAG(X)    (((X) >> 28) & 0x0F)
#define SDL_PIXELLAYOUT(X)  (((X) >> 16) & 0x0F)
#define SDL_PIXELORDER(X)   (((X) >> 20) & 0x0F)
#define SDL_PIXELTYPE(X)    (((X) >> 24) & 0x0F)

#define SDL_BIG_ENDIAN  4321
#define SDL_BYTEORDER  __BYTE_ORDER
#define SDL_LIL_ENDIAN  1234
#define SDL_SwapBE16(X) SDL_Swap16(X)
#define SDL_SwapBE32(X) SDL_Swap32(X)
#define SDL_SwapBE64(X) SDL_Swap64(X)
#define SDL_SwapFloatBE(X)  SDL_SwapFloat(X)
#define SDL_SwapFloatLE(X)  (X)
#define SDL_SwapLE16(X) (X)
#define SDL_SwapLE32(X) (X)
#define SDL_SwapLE64(X) (X)

#define SDL_CACHELINE_SIZE  128







#define SDL_VARIABLE_LENGTH_ARRAY 1


#define SDL_AddEventWatch SDL_AddEventWatch_REAL
#define SDL_AddHintCallback SDL_AddHintCallback_REAL
#define SDL_AddTimer SDL_AddTimer_REAL
#define SDL_AllocFormat SDL_AllocFormat_REAL
#define SDL_AllocPalette SDL_AllocPalette_REAL
#define SDL_AllocRW SDL_AllocRW_REAL
#define SDL_AndroidGetActivity SDL_AndroidGetActivity_REAL
#define SDL_AndroidGetExternalStoragePath SDL_AndroidGetExternalStoragePath_REAL
#define SDL_AndroidGetExternalStorageState SDL_AndroidGetExternalStorageState_REAL
#define SDL_AndroidGetInternalStoragePath SDL_AndroidGetInternalStoragePath_REAL
#define SDL_AndroidGetJNIEnv SDL_AndroidGetJNIEnv_REAL
#define SDL_AtomicAdd SDL_AtomicAdd_REAL
#define SDL_AtomicCAS SDL_AtomicCAS_REAL
#define SDL_AtomicCASPtr SDL_AtomicCASPtr_REAL
#define SDL_AtomicGet SDL_AtomicGet_REAL
#define SDL_AtomicGetPtr SDL_AtomicGetPtr_REAL
#define SDL_AtomicLock SDL_AtomicLock_REAL
#define SDL_AtomicSet SDL_AtomicSet_REAL
#define SDL_AtomicSetPtr SDL_AtomicSetPtr_REAL
#define SDL_AtomicTryLock SDL_AtomicTryLock_REAL
#define SDL_AtomicUnlock SDL_AtomicUnlock_REAL
#define SDL_AudioInit SDL_AudioInit_REAL
#define SDL_AudioQuit SDL_AudioQuit_REAL
#define SDL_BuildAudioCVT SDL_BuildAudioCVT_REAL
#define SDL_CalculateGammaRamp SDL_CalculateGammaRamp_REAL
#define SDL_CaptureMouse SDL_CaptureMouse_REAL
#define SDL_ClearError SDL_ClearError_REAL
#define SDL_ClearHints SDL_ClearHints_REAL
#define SDL_ClearQueuedAudio SDL_ClearQueuedAudio_REAL
#define SDL_CloseAudio SDL_CloseAudio_REAL
#define SDL_CloseAudioDevice SDL_CloseAudioDevice_REAL
#define SDL_ComposeCustomBlendMode SDL_ComposeCustomBlendMode_REAL
#define SDL_CondBroadcast SDL_CondBroadcast_REAL
#define SDL_CondSignal SDL_CondSignal_REAL
#define SDL_CondWait SDL_CondWait_REAL
#define SDL_CondWaitTimeout SDL_CondWaitTimeout_REAL
#define SDL_ConvertAudio SDL_ConvertAudio_REAL
#define SDL_ConvertPixels SDL_ConvertPixels_REAL
#define SDL_ConvertSurface SDL_ConvertSurface_REAL
#define SDL_ConvertSurfaceFormat SDL_ConvertSurfaceFormat_REAL
#define SDL_CreateColorCursor SDL_CreateColorCursor_REAL
#define SDL_CreateCond SDL_CreateCond_REAL
#define SDL_CreateCursor SDL_CreateCursor_REAL
#define SDL_CreateMutex SDL_CreateMutex_REAL
#define SDL_CreateRGBSurface SDL_CreateRGBSurface_REAL
#define SDL_CreateRGBSurfaceFrom SDL_CreateRGBSurfaceFrom_REAL
#define SDL_CreateRGBSurfaceWithFormat SDL_CreateRGBSurfaceWithFormat_REAL
#define SDL_CreateRGBSurfaceWithFormatFrom SDL_CreateRGBSurfaceWithFormatFrom_REAL
#define SDL_CreateRenderer SDL_CreateRenderer_REAL
#define SDL_CreateSemaphore SDL_CreateSemaphore_REAL
#define SDL_CreateShapedWindow SDL_CreateShapedWindow_REAL
#define SDL_CreateSoftwareRenderer SDL_CreateSoftwareRenderer_REAL
#define SDL_CreateSystemCursor SDL_CreateSystemCursor_REAL
#define SDL_CreateTexture SDL_CreateTexture_REAL
#define SDL_CreateTextureFromSurface SDL_CreateTextureFromSurface_REAL
#define SDL_CreateThread SDL_CreateThread_REAL
#define SDL_CreateWindow SDL_CreateWindow_REAL
#define SDL_CreateWindowAndRenderer SDL_CreateWindowAndRenderer_REAL
#define SDL_CreateWindowFrom SDL_CreateWindowFrom_REAL
#define SDL_DXGIGetOutputInfo SDL_DXGIGetOutputInfo_REAL
#define SDL_DelEventWatch SDL_DelEventWatch_REAL
#define SDL_DelHintCallback SDL_DelHintCallback_REAL
#define SDL_Delay SDL_Delay_REAL
#define SDL_DequeueAudio SDL_DequeueAudio_REAL
#define SDL_DestroyCond SDL_DestroyCond_REAL
#define SDL_DestroyMutex SDL_DestroyMutex_REAL
#define SDL_DestroyRenderer SDL_DestroyRenderer_REAL
#define SDL_DestroySemaphore SDL_DestroySemaphore_REAL
#define SDL_DestroyTexture SDL_DestroyTexture_REAL
#define SDL_DestroyWindow SDL_DestroyWindow_REAL
#define SDL_DetachThread SDL_DetachThread_REAL
#define SDL_Direct3D9GetAdapterIndex SDL_Direct3D9GetAdapterIndex_REAL
#define SDL_DisableScreenSaver SDL_DisableScreenSaver_REAL
#define SDL_DuplicateSurface SDL_DuplicateSurface_REAL
#define SDL_EnableScreenSaver SDL_EnableScreenSaver_REAL
#define SDL_EnclosePoints SDL_EnclosePoints_REAL
#define SDL_Error SDL_Error_REAL
#define SDL_EventState SDL_EventState_REAL
#define SDL_FillRect SDL_FillRect_REAL
#define SDL_FillRects SDL_FillRects_REAL
#define SDL_FilterEvents SDL_FilterEvents_REAL
#define SDL_FlushEvent SDL_FlushEvent_REAL
#define SDL_FlushEvents SDL_FlushEvents_REAL
#define SDL_FreeCursor SDL_FreeCursor_REAL
#define SDL_FreeFormat SDL_FreeFormat_REAL
#define SDL_FreePalette SDL_FreePalette_REAL
#define SDL_FreeRW SDL_FreeRW_REAL
#define SDL_FreeSurface SDL_FreeSurface_REAL
#define SDL_FreeWAV SDL_FreeWAV_REAL
#define SDL_GL_BindTexture SDL_GL_BindTexture_REAL
#define SDL_GL_CreateContext SDL_GL_CreateContext_REAL
#define SDL_GL_DeleteContext SDL_GL_DeleteContext_REAL
#define SDL_GL_ExtensionSupported SDL_GL_ExtensionSupported_REAL
#define SDL_GL_GetAttribute SDL_GL_GetAttribute_REAL
#define SDL_GL_GetCurrentContext SDL_GL_GetCurrentContext_REAL
#define SDL_GL_GetCurrentWindow SDL_GL_GetCurrentWindow_REAL
#define SDL_GL_GetDrawableSize SDL_GL_GetDrawableSize_REAL
#define SDL_GL_GetProcAddress SDL_GL_GetProcAddress_REAL
#define SDL_GL_GetSwapInterval SDL_GL_GetSwapInterval_REAL
#define SDL_GL_LoadLibrary SDL_GL_LoadLibrary_REAL
#define SDL_GL_MakeCurrent SDL_GL_MakeCurrent_REAL
#define SDL_GL_ResetAttributes SDL_GL_ResetAttributes_REAL
#define SDL_GL_SetAttribute SDL_GL_SetAttribute_REAL
#define SDL_GL_SetSwapInterval SDL_GL_SetSwapInterval_REAL
#define SDL_GL_SwapWindow SDL_GL_SwapWindow_REAL
#define SDL_GL_UnbindTexture SDL_GL_UnbindTexture_REAL
#define SDL_GL_UnloadLibrary SDL_GL_UnloadLibrary_REAL
#define SDL_GameControllerAddMapping SDL_GameControllerAddMapping_REAL
#define SDL_GameControllerAddMappingsFromRW SDL_GameControllerAddMappingsFromRW_REAL
#define SDL_GameControllerClose SDL_GameControllerClose_REAL
#define SDL_GameControllerEventState SDL_GameControllerEventState_REAL
#define SDL_GameControllerFromInstanceID SDL_GameControllerFromInstanceID_REAL
#define SDL_GameControllerGetAttached SDL_GameControllerGetAttached_REAL
#define SDL_GameControllerGetAxis SDL_GameControllerGetAxis_REAL
#define SDL_GameControllerGetAxisFromString SDL_GameControllerGetAxisFromString_REAL
#define SDL_GameControllerGetBindForAxis SDL_GameControllerGetBindForAxis_REAL
#define SDL_GameControllerGetBindForButton SDL_GameControllerGetBindForButton_REAL
#define SDL_GameControllerGetButton SDL_GameControllerGetButton_REAL
#define SDL_GameControllerGetButtonFromString SDL_GameControllerGetButtonFromString_REAL
#define SDL_GameControllerGetJoystick SDL_GameControllerGetJoystick_REAL
#define SDL_GameControllerGetProduct SDL_GameControllerGetProduct_REAL
#define SDL_GameControllerGetProductVersion SDL_GameControllerGetProductVersion_REAL
#define SDL_GameControllerGetStringForAxis SDL_GameControllerGetStringForAxis_REAL
#define SDL_GameControllerGetStringForButton SDL_GameControllerGetStringForButton_REAL
#define SDL_GameControllerGetVendor SDL_GameControllerGetVendor_REAL
#define SDL_GameControllerMapping SDL_GameControllerMapping_REAL
#define SDL_GameControllerMappingForGUID SDL_GameControllerMappingForGUID_REAL
#define SDL_GameControllerMappingForIndex SDL_GameControllerMappingForIndex_REAL
#define SDL_GameControllerName SDL_GameControllerName_REAL
#define SDL_GameControllerNameForIndex SDL_GameControllerNameForIndex_REAL
#define SDL_GameControllerNumMappings SDL_GameControllerNumMappings_REAL
#define SDL_GameControllerOpen SDL_GameControllerOpen_REAL
#define SDL_GameControllerUpdate SDL_GameControllerUpdate_REAL
#define SDL_GetAssertionHandler SDL_GetAssertionHandler_REAL
#define SDL_GetAssertionReport SDL_GetAssertionReport_REAL
#define SDL_GetAudioDeviceName SDL_GetAudioDeviceName_REAL
#define SDL_GetAudioDeviceStatus SDL_GetAudioDeviceStatus_REAL
#define SDL_GetAudioDriver SDL_GetAudioDriver_REAL
#define SDL_GetAudioStatus SDL_GetAudioStatus_REAL
#define SDL_GetBasePath SDL_GetBasePath_REAL
#define SDL_GetCPUCacheLineSize SDL_GetCPUCacheLineSize_REAL
#define SDL_GetCPUCount SDL_GetCPUCount_REAL
#define SDL_GetClipRect SDL_GetClipRect_REAL
#define SDL_GetClipboardText SDL_GetClipboardText_REAL
#define SDL_GetClosestDisplayMode SDL_GetClosestDisplayMode_REAL
#define SDL_GetColorKey SDL_GetColorKey_REAL
#define SDL_GetCurrentAudioDriver SDL_GetCurrentAudioDriver_REAL
#define SDL_GetCurrentDisplayMode SDL_GetCurrentDisplayMode_REAL
#define SDL_GetCurrentVideoDriver SDL_GetCurrentVideoDriver_REAL
#define SDL_GetCursor SDL_GetCursor_REAL
#define SDL_GetDefaultAssertionHandler SDL_GetDefaultAssertionHandler_REAL
#define SDL_GetDefaultCursor SDL_GetDefaultCursor_REAL
#define SDL_GetDesktopDisplayMode SDL_GetDesktopDisplayMode_REAL
#define SDL_GetDisplayBounds SDL_GetDisplayBounds_REAL
#define SDL_GetDisplayDPI SDL_GetDisplayDPI_REAL
#define SDL_GetDisplayMode SDL_GetDisplayMode_REAL
#define SDL_GetDisplayName SDL_GetDisplayName_REAL
#define SDL_GetDisplayUsableBounds SDL_GetDisplayUsableBounds_REAL
#define SDL_GetError SDL_GetError_REAL
#define SDL_GetEventFilter SDL_GetEventFilter_REAL
#define SDL_GetGlobalMouseState SDL_GetGlobalMouseState_REAL
#define SDL_GetGrabbedWindow SDL_GetGrabbedWindow_REAL
#define SDL_GetHint SDL_GetHint_REAL
#define SDL_GetHintBoolean SDL_GetHintBoolean_REAL
#define SDL_GetKeyFromName SDL_GetKeyFromName_REAL
#define SDL_GetKeyFromScancode SDL_GetKeyFromScancode_REAL
#define SDL_GetKeyName SDL_GetKeyName_REAL
#define SDL_GetKeyboardFocus SDL_GetKeyboardFocus_REAL
#define SDL_GetKeyboardState SDL_GetKeyboardState_REAL
#define SDL_GetMemoryFunctions SDL_GetMemoryFunctions_REAL
#define SDL_GetModState SDL_GetModState_REAL
#define SDL_GetMouseFocus SDL_GetMouseFocus_REAL
#define SDL_GetMouseState SDL_GetMouseState_REAL
#define SDL_GetNumAllocations SDL_GetNumAllocations_REAL
#define SDL_GetNumAudioDevices SDL_GetNumAudioDevices_REAL
#define SDL_GetNumAudioDrivers SDL_GetNumAudioDrivers_REAL
#define SDL_GetNumDisplayModes SDL_GetNumDisplayModes_REAL
#define SDL_GetNumRenderDrivers SDL_GetNumRenderDrivers_REAL
#define SDL_GetNumTouchDevices SDL_GetNumTouchDevices_REAL
#define SDL_GetNumTouchFingers SDL_GetNumTouchFingers_REAL
#define SDL_GetNumVideoDisplays SDL_GetNumVideoDisplays_REAL
#define SDL_GetNumVideoDrivers SDL_GetNumVideoDrivers_REAL
#define SDL_GetPerformanceCounter SDL_GetPerformanceCounter_REAL
#define SDL_GetPerformanceFrequency SDL_GetPerformanceFrequency_REAL
#define SDL_GetPixelFormatName SDL_GetPixelFormatName_REAL
#define SDL_GetPlatform SDL_GetPlatform_REAL
#define SDL_GetPowerInfo SDL_GetPowerInfo_REAL
#define SDL_GetPrefPath SDL_GetPrefPath_REAL
#define SDL_GetQueuedAudioSize SDL_GetQueuedAudioSize_REAL
#define SDL_GetRGB SDL_GetRGB_REAL
#define SDL_GetRGBA SDL_GetRGBA_REAL
#define SDL_GetRelativeMouseMode SDL_GetRelativeMouseMode_REAL
#define SDL_GetRelativeMouseState SDL_GetRelativeMouseState_REAL
#define SDL_GetRenderDrawBlendMode SDL_GetRenderDrawBlendMode_REAL
#define SDL_GetRenderDrawColor SDL_GetRenderDrawColor_REAL
#define SDL_GetRenderDriverInfo SDL_GetRenderDriverInfo_REAL
#define SDL_GetRenderTarget SDL_GetRenderTarget_REAL
#define SDL_GetRenderer SDL_GetRenderer_REAL
#define SDL_GetRendererInfo SDL_GetRendererInfo_REAL
#define SDL_GetRendererOutputSize SDL_GetRendererOutputSize_REAL
#define SDL_GetRevision SDL_GetRevision_REAL
#define SDL_GetRevisionNumber SDL_GetRevisionNumber_REAL
#define SDL_GetScancodeFromKey SDL_GetScancodeFromKey_REAL
#define SDL_GetScancodeFromName SDL_GetScancodeFromName_REAL
#define SDL_GetScancodeName SDL_GetScancodeName_REAL
#define SDL_GetShapedWindowMode SDL_GetShapedWindowMode_REAL
#define SDL_GetSurfaceAlphaMod SDL_GetSurfaceAlphaMod_REAL
#define SDL_GetSurfaceBlendMode SDL_GetSurfaceBlendMode_REAL
#define SDL_GetSurfaceColorMod SDL_GetSurfaceColorMod_REAL
#define SDL_GetSystemRAM SDL_GetSystemRAM_REAL
#define SDL_GetTextureAlphaMod SDL_GetTextureAlphaMod_REAL
#define SDL_GetTextureBlendMode SDL_GetTextureBlendMode_REAL
#define SDL_GetTextureColorMod SDL_GetTextureColorMod_REAL
#define SDL_GetThreadID SDL_GetThreadID_REAL
#define SDL_GetThreadName SDL_GetThreadName_REAL
#define SDL_GetTicks SDL_GetTicks_REAL
#define SDL_GetTouchDevice SDL_GetTouchDevice_REAL
#define SDL_GetTouchFinger SDL_GetTouchFinger_REAL
#define SDL_GetVersion SDL_GetVersion_REAL
#define SDL_GetVideoDriver SDL_GetVideoDriver_REAL
#define SDL_GetWindowBordersSize SDL_GetWindowBordersSize_REAL
#define SDL_GetWindowBrightness SDL_GetWindowBrightness_REAL
#define SDL_GetWindowData SDL_GetWindowData_REAL
#define SDL_GetWindowDisplayIndex SDL_GetWindowDisplayIndex_REAL
#define SDL_GetWindowDisplayMode SDL_GetWindowDisplayMode_REAL
#define SDL_GetWindowFlags SDL_GetWindowFlags_REAL
#define SDL_GetWindowFromID SDL_GetWindowFromID_REAL
#define SDL_GetWindowGammaRamp SDL_GetWindowGammaRamp_REAL
#define SDL_GetWindowGrab SDL_GetWindowGrab_REAL
#define SDL_GetWindowID SDL_GetWindowID_REAL
#define SDL_GetWindowMaximumSize SDL_GetWindowMaximumSize_REAL
#define SDL_GetWindowMinimumSize SDL_GetWindowMinimumSize_REAL
#define SDL_GetWindowOpacity SDL_GetWindowOpacity_REAL
#define SDL_GetWindowPixelFormat SDL_GetWindowPixelFormat_REAL
#define SDL_GetWindowPosition SDL_GetWindowPosition_REAL
#define SDL_GetWindowSize SDL_GetWindowSize_REAL
#define SDL_GetWindowSurface SDL_GetWindowSurface_REAL
#define SDL_GetWindowTitle SDL_GetWindowTitle_REAL
#define SDL_GetWindowWMInfo SDL_GetWindowWMInfo_REAL
#define SDL_HapticClose SDL_HapticClose_REAL
#define SDL_HapticDestroyEffect SDL_HapticDestroyEffect_REAL
#define SDL_HapticEffectSupported SDL_HapticEffectSupported_REAL
#define SDL_HapticGetEffectStatus SDL_HapticGetEffectStatus_REAL
#define SDL_HapticIndex SDL_HapticIndex_REAL
#define SDL_HapticName SDL_HapticName_REAL
#define SDL_HapticNewEffect SDL_HapticNewEffect_REAL
#define SDL_HapticNumAxes SDL_HapticNumAxes_REAL
#define SDL_HapticNumEffects SDL_HapticNumEffects_REAL
#define SDL_HapticNumEffectsPlaying SDL_HapticNumEffectsPlaying_REAL
#define SDL_HapticOpen SDL_HapticOpen_REAL
#define SDL_HapticOpenFromJoystick SDL_HapticOpenFromJoystick_REAL
#define SDL_HapticOpenFromMouse SDL_HapticOpenFromMouse_REAL
#define SDL_HapticOpened SDL_HapticOpened_REAL
#define SDL_HapticPause SDL_HapticPause_REAL
#define SDL_HapticQuery SDL_HapticQuery_REAL
#define SDL_HapticRumbleInit SDL_HapticRumbleInit_REAL
#define SDL_HapticRumblePlay SDL_HapticRumblePlay_REAL
#define SDL_HapticRumbleStop SDL_HapticRumbleStop_REAL
#define SDL_HapticRumbleSupported SDL_HapticRumbleSupported_REAL
#define SDL_HapticRunEffect SDL_HapticRunEffect_REAL
#define SDL_HapticSetAutocenter SDL_HapticSetAutocenter_REAL
#define SDL_HapticSetGain SDL_HapticSetGain_REAL
#define SDL_HapticStopAll SDL_HapticStopAll_REAL
#define SDL_HapticStopEffect SDL_HapticStopEffect_REAL
#define SDL_HapticUnpause SDL_HapticUnpause_REAL
#define SDL_HapticUpdateEffect SDL_HapticUpdateEffect_REAL
#define SDL_Has3DNow SDL_Has3DNow_REAL
#define SDL_HasAVX SDL_HasAVX_REAL
#define SDL_HasAVX2 SDL_HasAVX2_REAL
#define SDL_HasAltiVec SDL_HasAltiVec_REAL
#define SDL_HasClipboardText SDL_HasClipboardText_REAL
#define SDL_HasEvent SDL_HasEvent_REAL
#define SDL_HasEvents SDL_HasEvents_REAL
#define SDL_HasIntersection SDL_HasIntersection_REAL
#define SDL_HasMMX SDL_HasMMX_REAL
#define SDL_HasNEON SDL_HasNEON_REAL
#define SDL_HasRDTSC SDL_HasRDTSC_REAL
#define SDL_HasSSE SDL_HasSSE_REAL
#define SDL_HasSSE2 SDL_HasSSE2_REAL
#define SDL_HasSSE3 SDL_HasSSE3_REAL
#define SDL_HasSSE41 SDL_HasSSE41_REAL
#define SDL_HasSSE42 SDL_HasSSE42_REAL
#define SDL_HasScreenKeyboardSupport SDL_HasScreenKeyboardSupport_REAL
#define SDL_HideWindow SDL_HideWindow_REAL
#define SDL_Init SDL_Init_REAL
#define SDL_InitSubSystem SDL_InitSubSystem_REAL
#define SDL_IntersectRect SDL_IntersectRect_REAL
#define SDL_IntersectRectAndLine SDL_IntersectRectAndLine_REAL
#define SDL_IsGameController SDL_IsGameController_REAL
#define SDL_IsScreenKeyboardShown SDL_IsScreenKeyboardShown_REAL
#define SDL_IsScreenSaverEnabled SDL_IsScreenSaverEnabled_REAL
#define SDL_IsShapedWindow SDL_IsShapedWindow_REAL
#define SDL_IsTextInputActive SDL_IsTextInputActive_REAL
#define SDL_JoystickClose SDL_JoystickClose_REAL
#define SDL_JoystickCurrentPowerLevel SDL_JoystickCurrentPowerLevel_REAL
#define SDL_JoystickEventState SDL_JoystickEventState_REAL
#define SDL_JoystickFromInstanceID SDL_JoystickFromInstanceID_REAL
#define SDL_JoystickGetAttached SDL_JoystickGetAttached_REAL
#define SDL_JoystickGetAxis SDL_JoystickGetAxis_REAL
#define SDL_JoystickGetAxisInitialState SDL_JoystickGetAxisInitialState_REAL
#define SDL_JoystickGetBall SDL_JoystickGetBall_REAL
#define SDL_JoystickGetButton SDL_JoystickGetButton_REAL
#define SDL_JoystickGetDeviceGUID SDL_JoystickGetDeviceGUID_REAL
#define SDL_JoystickGetDeviceInstanceID SDL_JoystickGetDeviceInstanceID_REAL
#define SDL_JoystickGetDeviceProduct SDL_JoystickGetDeviceProduct_REAL
#define SDL_JoystickGetDeviceProductVersion SDL_JoystickGetDeviceProductVersion_REAL
#define SDL_JoystickGetDeviceType SDL_JoystickGetDeviceType_REAL
#define SDL_JoystickGetDeviceVendor SDL_JoystickGetDeviceVendor_REAL
#define SDL_JoystickGetGUID SDL_JoystickGetGUID_REAL
#define SDL_JoystickGetGUIDFromString SDL_JoystickGetGUIDFromString_REAL
#define SDL_JoystickGetGUIDString SDL_JoystickGetGUIDString_REAL
#define SDL_JoystickGetHat SDL_JoystickGetHat_REAL
#define SDL_JoystickGetProduct SDL_JoystickGetProduct_REAL
#define SDL_JoystickGetProductVersion SDL_JoystickGetProductVersion_REAL
#define SDL_JoystickGetType SDL_JoystickGetType_REAL
#define SDL_JoystickGetVendor SDL_JoystickGetVendor_REAL
#define SDL_JoystickInstanceID SDL_JoystickInstanceID_REAL
#define SDL_JoystickIsHaptic SDL_JoystickIsHaptic_REAL
#define SDL_JoystickName SDL_JoystickName_REAL
#define SDL_JoystickNameForIndex SDL_JoystickNameForIndex_REAL
#define SDL_JoystickNumAxes SDL_JoystickNumAxes_REAL
#define SDL_JoystickNumBalls SDL_JoystickNumBalls_REAL
#define SDL_JoystickNumButtons SDL_JoystickNumButtons_REAL
#define SDL_JoystickNumHats SDL_JoystickNumHats_REAL
#define SDL_JoystickOpen SDL_JoystickOpen_REAL
#define SDL_JoystickUpdate SDL_JoystickUpdate_REAL
#define SDL_LoadBMP_RW SDL_LoadBMP_RW_REAL
#define SDL_LoadDollarTemplates SDL_LoadDollarTemplates_REAL
#define SDL_LoadFile_RW SDL_LoadFile_RW_REAL
#define SDL_LoadFunction SDL_LoadFunction_REAL
#define SDL_LoadObject SDL_LoadObject_REAL
#define SDL_LoadWAV_RW SDL_LoadWAV_RW_REAL
#define SDL_LockAudio SDL_LockAudio_REAL
#define SDL_LockAudioDevice SDL_LockAudioDevice_REAL
#define SDL_LockJoysticks SDL_LockJoysticks_REAL
#define SDL_LockMutex SDL_LockMutex_REAL
#define SDL_LockSurface SDL_LockSurface_REAL
#define SDL_LockTexture SDL_LockTexture_REAL
#define SDL_Log SDL_Log_REAL
#define SDL_LogCritical SDL_LogCritical_REAL
#define SDL_LogDebug SDL_LogDebug_REAL
#define SDL_LogError SDL_LogError_REAL
#define SDL_LogGetOutputFunction SDL_LogGetOutputFunction_REAL
#define SDL_LogGetPriority SDL_LogGetPriority_REAL
#define SDL_LogInfo SDL_LogInfo_REAL
#define SDL_LogMessage SDL_LogMessage_REAL
#define SDL_LogMessageV SDL_LogMessageV_REAL
#define SDL_LogResetPriorities SDL_LogResetPriorities_REAL
#define SDL_LogSetAllPriority SDL_LogSetAllPriority_REAL
#define SDL_LogSetOutputFunction SDL_LogSetOutputFunction_REAL
#define SDL_LogSetPriority SDL_LogSetPriority_REAL
#define SDL_LogVerbose SDL_LogVerbose_REAL
#define SDL_LogWarn SDL_LogWarn_REAL
#define SDL_LowerBlit SDL_LowerBlit_REAL
#define SDL_LowerBlitScaled SDL_LowerBlitScaled_REAL
#define SDL_MapRGB SDL_MapRGB_REAL
#define SDL_MapRGBA SDL_MapRGBA_REAL
#define SDL_MasksToPixelFormatEnum SDL_MasksToPixelFormatEnum_REAL
#define SDL_MaximizeWindow SDL_MaximizeWindow_REAL
#define SDL_MemoryBarrierAcquireFunction SDL_MemoryBarrierAcquireFunction_REAL
#define SDL_MemoryBarrierReleaseFunction SDL_MemoryBarrierReleaseFunction_REAL
#define SDL_MinimizeWindow SDL_MinimizeWindow_REAL
#define SDL_MixAudio SDL_MixAudio_REAL
#define SDL_MixAudioFormat SDL_MixAudioFormat_REAL
#define SDL_MouseIsHaptic SDL_MouseIsHaptic_REAL
#define SDL_NumHaptics SDL_NumHaptics_REAL
#define SDL_NumJoysticks SDL_NumJoysticks_REAL
#define SDL_OpenAudio SDL_OpenAudio_REAL
#define SDL_OpenAudioDevice SDL_OpenAudioDevice_REAL
#define SDL_PauseAudio SDL_PauseAudio_REAL
#define SDL_PauseAudioDevice SDL_PauseAudioDevice_REAL
#define SDL_PeepEvents SDL_PeepEvents_REAL
#define SDL_PixelFormatEnumToMasks SDL_PixelFormatEnumToMasks_REAL
#define SDL_PollEvent SDL_PollEvent_REAL
#define SDL_PumpEvents SDL_PumpEvents_REAL
#define SDL_PushEvent SDL_PushEvent_REAL
#define SDL_QueryTexture SDL_QueryTexture_REAL
#define SDL_QueueAudio SDL_QueueAudio_REAL
#define SDL_Quit SDL_Quit_REAL
#define SDL_QuitSubSystem SDL_QuitSubSystem_REAL
#define SDL_RWFromConstMem SDL_RWFromConstMem_REAL
#define SDL_RWFromFP SDL_RWFromFP_REAL
#define SDL_RWFromFile SDL_RWFromFile_REAL
#define SDL_RWFromMem SDL_RWFromMem_REAL
#define SDL_RaiseWindow SDL_RaiseWindow_REAL
#define SDL_ReadBE16 SDL_ReadBE16_REAL
#define SDL_ReadBE32 SDL_ReadBE32_REAL
#define SDL_ReadBE64 SDL_ReadBE64_REAL
#define SDL_ReadLE16 SDL_ReadLE16_REAL
#define SDL_ReadLE32 SDL_ReadLE32_REAL
#define SDL_ReadLE64 SDL_ReadLE64_REAL
#define SDL_ReadU8 SDL_ReadU8_REAL
#define SDL_RecordGesture SDL_RecordGesture_REAL
#define SDL_RegisterApp SDL_RegisterApp_REAL
#define SDL_RegisterEvents SDL_RegisterEvents_REAL
#define SDL_RemoveTimer SDL_RemoveTimer_REAL
#define SDL_RenderClear SDL_RenderClear_REAL
#define SDL_RenderCopy SDL_RenderCopy_REAL
#define SDL_RenderCopyEx SDL_RenderCopyEx_REAL
#define SDL_RenderDrawLine SDL_RenderDrawLine_REAL
#define SDL_RenderDrawLines SDL_RenderDrawLines_REAL
#define SDL_RenderDrawPoint SDL_RenderDrawPoint_REAL
#define SDL_RenderDrawPoints SDL_RenderDrawPoints_REAL
#define SDL_RenderDrawRect SDL_RenderDrawRect_REAL
#define SDL_RenderDrawRects SDL_RenderDrawRects_REAL
#define SDL_RenderFillRect SDL_RenderFillRect_REAL
#define SDL_RenderFillRects SDL_RenderFillRects_REAL
#define SDL_RenderGetClipRect SDL_RenderGetClipRect_REAL
#define SDL_RenderGetD3D9Device SDL_RenderGetD3D9Device_REAL
#define SDL_RenderGetIntegerScale SDL_RenderGetIntegerScale_REAL
#define SDL_RenderGetLogicalSize SDL_RenderGetLogicalSize_REAL
#define SDL_RenderGetScale SDL_RenderGetScale_REAL
#define SDL_RenderGetViewport SDL_RenderGetViewport_REAL
#define SDL_RenderIsClipEnabled SDL_RenderIsClipEnabled_REAL
#define SDL_RenderPresent SDL_RenderPresent_REAL
#define SDL_RenderReadPixels SDL_RenderReadPixels_REAL
#define SDL_RenderSetClipRect SDL_RenderSetClipRect_REAL
#define SDL_RenderSetIntegerScale SDL_RenderSetIntegerScale_REAL
#define SDL_RenderSetLogicalSize SDL_RenderSetLogicalSize_REAL
#define SDL_RenderSetScale SDL_RenderSetScale_REAL
#define SDL_RenderSetViewport SDL_RenderSetViewport_REAL
#define SDL_RenderTargetSupported SDL_RenderTargetSupported_REAL
#define SDL_ReportAssertion SDL_ReportAssertion_REAL
#define SDL_ResetAssertionReport SDL_ResetAssertionReport_REAL
#define SDL_RestoreWindow SDL_RestoreWindow_REAL
#define SDL_SaveAllDollarTemplates SDL_SaveAllDollarTemplates_REAL
#define SDL_SaveBMP_RW SDL_SaveBMP_RW_REAL
#define SDL_SaveDollarTemplate SDL_SaveDollarTemplate_REAL
#define SDL_SemPost SDL_SemPost_REAL
#define SDL_SemTryWait SDL_SemTryWait_REAL
#define SDL_SemValue SDL_SemValue_REAL
#define SDL_SemWait SDL_SemWait_REAL
#define SDL_SemWaitTimeout SDL_SemWaitTimeout_REAL
#define SDL_SetAssertionHandler SDL_SetAssertionHandler_REAL
#define SDL_SetClipRect SDL_SetClipRect_REAL
#define SDL_SetClipboardText SDL_SetClipboardText_REAL
#define SDL_SetColorKey SDL_SetColorKey_REAL
#define SDL_SetCursor SDL_SetCursor_REAL
#define SDL_SetError SDL_SetError_REAL
#define SDL_SetEventFilter SDL_SetEventFilter_REAL
#define SDL_SetHint SDL_SetHint_REAL
#define SDL_SetHintWithPriority SDL_SetHintWithPriority_REAL
#define SDL_SetMainReady SDL_SetMainReady_REAL
#define SDL_SetMemoryFunctions SDL_SetMemoryFunctions_REAL
#define SDL_SetModState SDL_SetModState_REAL
#define SDL_SetPaletteColors SDL_SetPaletteColors_REAL
#define SDL_SetPixelFormatPalette SDL_SetPixelFormatPalette_REAL
#define SDL_SetRelativeMouseMode SDL_SetRelativeMouseMode_REAL
#define SDL_SetRenderDrawBlendMode SDL_SetRenderDrawBlendMode_REAL
#define SDL_SetRenderDrawColor SDL_SetRenderDrawColor_REAL
#define SDL_SetRenderTarget SDL_SetRenderTarget_REAL
#define SDL_SetSurfaceAlphaMod SDL_SetSurfaceAlphaMod_REAL
#define SDL_SetSurfaceBlendMode SDL_SetSurfaceBlendMode_REAL
#define SDL_SetSurfaceColorMod SDL_SetSurfaceColorMod_REAL
#define SDL_SetSurfacePalette SDL_SetSurfacePalette_REAL
#define SDL_SetSurfaceRLE SDL_SetSurfaceRLE_REAL
#define SDL_SetTextInputRect SDL_SetTextInputRect_REAL
#define SDL_SetTextureAlphaMod SDL_SetTextureAlphaMod_REAL
#define SDL_SetTextureBlendMode SDL_SetTextureBlendMode_REAL
#define SDL_SetTextureColorMod SDL_SetTextureColorMod_REAL
#define SDL_SetThreadPriority SDL_SetThreadPriority_REAL
#define SDL_SetWindowBordered SDL_SetWindowBordered_REAL
#define SDL_SetWindowBrightness SDL_SetWindowBrightness_REAL
#define SDL_SetWindowData SDL_SetWindowData_REAL
#define SDL_SetWindowDisplayMode SDL_SetWindowDisplayMode_REAL
#define SDL_SetWindowFullscreen SDL_SetWindowFullscreen_REAL
#define SDL_SetWindowGammaRamp SDL_SetWindowGammaRamp_REAL
#define SDL_SetWindowGrab SDL_SetWindowGrab_REAL
#define SDL_SetWindowHitTest SDL_SetWindowHitTest_REAL
#define SDL_SetWindowIcon SDL_SetWindowIcon_REAL
#define SDL_SetWindowInputFocus SDL_SetWindowInputFocus_REAL
#define SDL_SetWindowMaximumSize SDL_SetWindowMaximumSize_REAL
#define SDL_SetWindowMinimumSize SDL_SetWindowMinimumSize_REAL
#define SDL_SetWindowModalFor SDL_SetWindowModalFor_REAL
#define SDL_SetWindowOpacity SDL_SetWindowOpacity_REAL
#define SDL_SetWindowPosition SDL_SetWindowPosition_REAL
#define SDL_SetWindowResizable SDL_SetWindowResizable_REAL
#define SDL_SetWindowShape SDL_SetWindowShape_REAL
#define SDL_SetWindowSize SDL_SetWindowSize_REAL
#define SDL_SetWindowTitle SDL_SetWindowTitle_REAL
#define SDL_SetWindowsMessageHook SDL_SetWindowsMessageHook_REAL
#define SDL_ShowCursor SDL_ShowCursor_REAL
#define SDL_ShowMessageBox SDL_ShowMessageBox_REAL
#define SDL_ShowSimpleMessageBox SDL_ShowSimpleMessageBox_REAL
#define SDL_ShowWindow SDL_ShowWindow_REAL
#define SDL_SoftStretch SDL_SoftStretch_REAL
#define SDL_StartTextInput SDL_StartTextInput_REAL
#define SDL_StopTextInput SDL_StopTextInput_REAL
#define SDL_TLSCreate SDL_TLSCreate_REAL
#define SDL_TLSGet SDL_TLSGet_REAL
#define SDL_TLSSet SDL_TLSSet_REAL
#define SDL_ThreadID SDL_ThreadID_REAL
#define SDL_TryLockMutex SDL_TryLockMutex_REAL
#define SDL_UnionRect SDL_UnionRect_REAL
#define SDL_UnloadObject SDL_UnloadObject_REAL
#define SDL_UnlockAudio SDL_UnlockAudio_REAL
#define SDL_UnlockAudioDevice SDL_UnlockAudioDevice_REAL
#define SDL_UnlockJoysticks SDL_UnlockJoysticks_REAL
#define SDL_UnlockMutex SDL_UnlockMutex_REAL
#define SDL_UnlockSurface SDL_UnlockSurface_REAL
#define SDL_UnlockTexture SDL_UnlockTexture_REAL
#define SDL_UnregisterApp SDL_UnregisterApp_REAL
#define SDL_UpdateTexture SDL_UpdateTexture_REAL
#define SDL_UpdateWindowSurface SDL_UpdateWindowSurface_REAL
#define SDL_UpdateWindowSurfaceRects SDL_UpdateWindowSurfaceRects_REAL
#define SDL_UpdateYUVTexture SDL_UpdateYUVTexture_REAL
#define SDL_UpperBlit SDL_UpperBlit_REAL
#define SDL_UpperBlitScaled SDL_UpperBlitScaled_REAL
#define SDL_VideoInit SDL_VideoInit_REAL
#define SDL_VideoQuit SDL_VideoQuit_REAL
#define SDL_Vulkan_CreateSurface SDL_Vulkan_CreateSurface_REAL
#define SDL_Vulkan_GetDrawableSize SDL_Vulkan_GetDrawableSize_REAL
#define SDL_Vulkan_GetInstanceExtensions SDL_Vulkan_GetInstanceExtensions_REAL
#define SDL_Vulkan_GetVkGetInstanceProcAddr SDL_Vulkan_GetVkGetInstanceProcAddr_REAL
#define SDL_Vulkan_LoadLibrary SDL_Vulkan_LoadLibrary_REAL
#define SDL_Vulkan_UnloadLibrary SDL_Vulkan_UnloadLibrary_REAL
#define SDL_WaitEvent SDL_WaitEvent_REAL
#define SDL_WaitEventTimeout SDL_WaitEventTimeout_REAL
#define SDL_WaitThread SDL_WaitThread_REAL
#define SDL_WarpMouseGlobal SDL_WarpMouseGlobal_REAL
#define SDL_WarpMouseInWindow SDL_WarpMouseInWindow_REAL
#define SDL_WasInit SDL_WasInit_REAL
#define SDL_WinRTGetFSPathUNICODE SDL_WinRTGetFSPathUNICODE_REAL
#define SDL_WinRTGetFSPathUTF8 SDL_WinRTGetFSPathUTF8_REAL
#define SDL_WinRTRunApp SDL_WinRTRunApp_REAL
#define SDL_WriteBE16 SDL_WriteBE16_REAL
#define SDL_WriteBE32 SDL_WriteBE32_REAL
#define SDL_WriteBE64 SDL_WriteBE64_REAL
#define SDL_WriteLE16 SDL_WriteLE16_REAL
#define SDL_WriteLE32 SDL_WriteLE32_REAL
#define SDL_WriteLE64 SDL_WriteLE64_REAL
#define SDL_WriteU8 SDL_WriteU8_REAL
#define SDL_abs SDL_abs_REAL
#define SDL_acos SDL_acos_REAL
#define SDL_asin SDL_asin_REAL
#define SDL_atan SDL_atan_REAL
#define SDL_atan2 SDL_atan2_REAL
#define SDL_atof SDL_atof_REAL
#define SDL_atoi SDL_atoi_REAL
#define SDL_calloc SDL_calloc_REAL
#define SDL_ceil SDL_ceil_REAL
#define SDL_copysign SDL_copysign_REAL
#define SDL_cos SDL_cos_REAL
#define SDL_cosf SDL_cosf_REAL
#define SDL_fabs SDL_fabs_REAL
#define SDL_floor SDL_floor_REAL
#define SDL_free SDL_free_REAL
#define SDL_getenv SDL_getenv_REAL
#define SDL_iPhoneSetAnimationCallback SDL_iPhoneSetAnimationCallback_REAL
#define SDL_iPhoneSetEventPump SDL_iPhoneSetEventPump_REAL
#define SDL_iconv SDL_iconv_REAL
#define SDL_iconv_close SDL_iconv_close_REAL
#define SDL_iconv_open SDL_iconv_open_REAL
#define SDL_iconv_string SDL_iconv_string_REAL
#define SDL_isdigit SDL_isdigit_REAL
#define SDL_isspace SDL_isspace_REAL
#define SDL_itoa SDL_itoa_REAL
#define SDL_lltoa SDL_lltoa_REAL
#define SDL_log SDL_log_REAL
#define SDL_ltoa SDL_ltoa_REAL
#define SDL_malloc SDL_malloc_REAL
#define SDL_memcmp SDL_memcmp_REAL
#define SDL_memcpy SDL_memcpy_REAL
#define SDL_memmove SDL_memmove_REAL
#define SDL_memset SDL_memset_REAL
#define SDL_pow SDL_pow_REAL
#define SDL_qsort SDL_qsort_REAL
#define SDL_realloc SDL_realloc_REAL
#define SDL_scalbn SDL_scalbn_REAL
#define SDL_setenv SDL_setenv_REAL
#define SDL_sin SDL_sin_REAL
#define SDL_sinf SDL_sinf_REAL
#define SDL_snprintf SDL_snprintf_REAL
#define SDL_sqrt SDL_sqrt_REAL
#define SDL_sqrtf SDL_sqrtf_REAL
#define SDL_sscanf SDL_sscanf_REAL
#define SDL_strcasecmp SDL_strcasecmp_REAL
#define SDL_strchr SDL_strchr_REAL
#define SDL_strcmp SDL_strcmp_REAL
#define SDL_strdup SDL_strdup_REAL
#define SDL_strlcat SDL_strlcat_REAL
#define SDL_strlcpy SDL_strlcpy_REAL
#define SDL_strlen SDL_strlen_REAL
#define SDL_strlwr SDL_strlwr_REAL
#define SDL_strncasecmp SDL_strncasecmp_REAL
#define SDL_strncmp SDL_strncmp_REAL
#define SDL_strrchr SDL_strrchr_REAL
#define SDL_strrev SDL_strrev_REAL
#define SDL_strstr SDL_strstr_REAL
#define SDL_strtod SDL_strtod_REAL
#define SDL_strtol SDL_strtol_REAL
#define SDL_strtoll SDL_strtoll_REAL
#define SDL_strtoul SDL_strtoul_REAL
#define SDL_strtoull SDL_strtoull_REAL
#define SDL_strupr SDL_strupr_REAL
#define SDL_tan SDL_tan_REAL
#define SDL_tanf SDL_tanf_REAL
#define SDL_tolower SDL_tolower_REAL
#define SDL_toupper SDL_toupper_REAL
#define SDL_uitoa SDL_uitoa_REAL
#define SDL_ulltoa SDL_ulltoa_REAL
#define SDL_ultoa SDL_ultoa_REAL
#define SDL_utf8strlcpy SDL_utf8strlcpy_REAL
#define SDL_utf8strlen SDL_utf8strlen_REAL
#define SDL_vsnprintf SDL_vsnprintf_REAL
#define SDL_vsscanf SDL_vsscanf_REAL
#define SDL_wcscmp SDL_wcscmp_REAL
#define SDL_wcslcat SDL_wcslcat_REAL
#define SDL_wcslcpy SDL_wcslcpy_REAL
#define SDL_wcslen SDL_wcslen_REAL
#define SDL_DYNAMIC_API 0

#define FULLSCREEN_VISIBLE(W) \
    (((W)->flags & SDL_WINDOW_FULLSCREEN) && \
     ((W)->flags & SDL_WINDOW_SHOWN) && \
     !((W)->flags & SDL_WINDOW_MINIMIZED))

#define _THIS   SDL_VideoDevice *_this
#define SDL_VIDEO_VULKAN 0












#define VK_DEFINE_HANDLE(object) typedef struct object##_T* object;
#define VK_DEFINE_NON_DISPATCHABLE_HANDLE(object) typedef struct object##_T *object;
#define SDL_WINDOWPOS_CENTERED         SDL_WINDOWPOS_CENTERED_DISPLAY(0)
#define SDL_WINDOWPOS_CENTERED_DISPLAY(X)  (SDL_WINDOWPOS_CENTERED_MASK|(X))
#define SDL_WINDOWPOS_CENTERED_MASK    0x2FFF0000u
#define SDL_WINDOWPOS_ISCENTERED(X)    \
            (((X)&0xFFFF0000) == SDL_WINDOWPOS_CENTERED_MASK)
#define SDL_WINDOWPOS_ISUNDEFINED(X)    \
            (((X)&0xFFFF0000) == SDL_WINDOWPOS_UNDEFINED_MASK)
#define SDL_WINDOWPOS_UNDEFINED         SDL_WINDOWPOS_UNDEFINED_DISPLAY(0)
#define SDL_WINDOWPOS_UNDEFINED_DISPLAY(X)  (SDL_WINDOWPOS_UNDEFINED_MASK|(X))
#define SDL_WINDOWPOS_UNDEFINED_MASK    0x1FFF0000u

#define VK_AMD_DRAW_INDIRECT_COUNT_EXTENSION_NAME "VK_AMD_draw_indirect_count"
#define VK_AMD_DRAW_INDIRECT_COUNT_SPEC_VERSION 1
#define VK_AMD_GCN_SHADER_EXTENSION_NAME  "VK_AMD_gcn_shader"
#define VK_AMD_GCN_SHADER_SPEC_VERSION    1
#define VK_AMD_GPU_SHADER_HALF_FLOAT_EXTENSION_NAME "VK_AMD_gpu_shader_half_float"
#define VK_AMD_GPU_SHADER_HALF_FLOAT_SPEC_VERSION 1
#define VK_AMD_GPU_SHADER_INT16_EXTENSION_NAME "VK_AMD_gpu_shader_int16"
#define VK_AMD_GPU_SHADER_INT16_SPEC_VERSION 1
#define VK_AMD_MIXED_ATTACHMENT_SAMPLES_EXTENSION_NAME "VK_AMD_mixed_attachment_samples"
#define VK_AMD_MIXED_ATTACHMENT_SAMPLES_SPEC_VERSION 1
#define VK_AMD_NEGATIVE_VIEWPORT_HEIGHT_EXTENSION_NAME "VK_AMD_negative_viewport_height"
#define VK_AMD_NEGATIVE_VIEWPORT_HEIGHT_SPEC_VERSION 1
#define VK_AMD_RASTERIZATION_ORDER_EXTENSION_NAME "VK_AMD_rasterization_order"
#define VK_AMD_RASTERIZATION_ORDER_SPEC_VERSION 1
#define VK_AMD_SHADER_BALLOT_EXTENSION_NAME "VK_AMD_shader_ballot"
#define VK_AMD_SHADER_BALLOT_SPEC_VERSION 1
#define VK_AMD_SHADER_EXPLICIT_VERTEX_PARAMETER_EXTENSION_NAME "VK_AMD_shader_explicit_vertex_parameter"
#define VK_AMD_SHADER_EXPLICIT_VERTEX_PARAMETER_SPEC_VERSION 1
#define VK_AMD_SHADER_TRINARY_MINMAX_EXTENSION_NAME "VK_AMD_shader_trinary_minmax"
#define VK_AMD_SHADER_TRINARY_MINMAX_SPEC_VERSION 1
#define VK_AMD_TEXTURE_GATHER_BIAS_LOD_EXTENSION_NAME "VK_AMD_texture_gather_bias_lod"
#define VK_AMD_TEXTURE_GATHER_BIAS_LOD_SPEC_VERSION 1
#define VK_AMD_draw_indirect_count 1
#define VK_AMD_gcn_shader 1
#define VK_AMD_gpu_shader_half_float 1
#define VK_AMD_gpu_shader_int16 1
#define VK_AMD_mixed_attachment_samples 1
#define VK_AMD_negative_viewport_height 1
#define VK_AMD_rasterization_order 1
#define VK_AMD_shader_ballot 1
#define VK_AMD_shader_explicit_vertex_parameter 1
#define VK_AMD_shader_trinary_minmax 1
#define VK_AMD_texture_gather_bias_lod 1
#define VK_API_VERSION_1_0 VK_MAKE_VERSION(1, 0, 0)
#define VK_ATTACHMENT_UNUSED              (~0U)
#define VK_COLORSPACE_SRGB_NONLINEAR_KHR  VK_COLOR_SPACE_SRGB_NONLINEAR_KHR
#define VK_DEBUG_REPORT_OBJECT_TYPE_DEBUG_REPORT_EXT VK_DEBUG_REPORT_OBJECT_TYPE_DEBUG_REPORT_CALLBACK_EXT_EXT
#define VK_EXT_ACQUIRE_XLIB_DISPLAY_EXTENSION_NAME "VK_EXT_acquire_xlib_display"
#define VK_EXT_ACQUIRE_XLIB_DISPLAY_SPEC_VERSION 1
#define VK_EXT_BLEND_OPERATION_ADVANCED_EXTENSION_NAME "VK_EXT_blend_operation_advanced"
#define VK_EXT_BLEND_OPERATION_ADVANCED_SPEC_VERSION 2
#define VK_EXT_DEBUG_MARKER_EXTENSION_NAME "VK_EXT_debug_marker"
#define VK_EXT_DEBUG_MARKER_SPEC_VERSION  4
#define VK_EXT_DEBUG_REPORT_EXTENSION_NAME "VK_EXT_debug_report"
#define VK_EXT_DEBUG_REPORT_SPEC_VERSION  8
#define VK_EXT_DEPTH_RANGE_UNRESTRICTED_EXTENSION_NAME "VK_EXT_depth_range_unrestricted"
#define VK_EXT_DEPTH_RANGE_UNRESTRICTED_SPEC_VERSION 1
#define VK_EXT_DIRECT_MODE_DISPLAY_EXTENSION_NAME "VK_EXT_direct_mode_display"
#define VK_EXT_DIRECT_MODE_DISPLAY_SPEC_VERSION 1
#define VK_EXT_DISCARD_RECTANGLES_EXTENSION_NAME "VK_EXT_discard_rectangles"
#define VK_EXT_DISCARD_RECTANGLES_SPEC_VERSION 1
#define VK_EXT_DISPLAY_CONTROL_EXTENSION_NAME "VK_EXT_display_control"
#define VK_EXT_DISPLAY_CONTROL_SPEC_VERSION 1
#define VK_EXT_DISPLAY_SURFACE_COUNTER_EXTENSION_NAME "VK_EXT_display_surface_counter"
#define VK_EXT_DISPLAY_SURFACE_COUNTER_SPEC_VERSION 1
#define VK_EXT_HDR_METADATA_EXTENSION_NAME "VK_EXT_hdr_metadata"
#define VK_EXT_HDR_METADATA_SPEC_VERSION  1
#define VK_EXT_POST_DEPTH_COVERAGE_EXTENSION_NAME "VK_EXT_post_depth_coverage"
#define VK_EXT_POST_DEPTH_COVERAGE_SPEC_VERSION 1
#define VK_EXT_SAMPLER_FILTER_MINMAX_EXTENSION_NAME "VK_EXT_sampler_filter_minmax"
#define VK_EXT_SAMPLER_FILTER_MINMAX_SPEC_VERSION 1
#define VK_EXT_SHADER_STENCIL_EXPORT_EXTENSION_NAME "VK_EXT_shader_stencil_export"
#define VK_EXT_SHADER_STENCIL_EXPORT_SPEC_VERSION 1
#define VK_EXT_SHADER_SUBGROUP_BALLOT_EXTENSION_NAME "VK_EXT_shader_subgroup_ballot"
#define VK_EXT_SHADER_SUBGROUP_BALLOT_SPEC_VERSION 1
#define VK_EXT_SHADER_SUBGROUP_VOTE_EXTENSION_NAME "VK_EXT_shader_subgroup_vote"
#define VK_EXT_SHADER_SUBGROUP_VOTE_SPEC_VERSION 1
#define VK_EXT_SHADER_VIEWPORT_INDEX_LAYER_EXTENSION_NAME "VK_EXT_shader_viewport_index_layer"
#define VK_EXT_SHADER_VIEWPORT_INDEX_LAYER_SPEC_VERSION 1
#define VK_EXT_SWAPCHAIN_COLOR_SPACE_EXTENSION_NAME "VK_EXT_swapchain_colorspace"
#define VK_EXT_SWAPCHAIN_COLOR_SPACE_SPEC_VERSION 3
#define VK_EXT_VALIDATION_FLAGS_EXTENSION_NAME "VK_EXT_validation_flags"
#define VK_EXT_VALIDATION_FLAGS_SPEC_VERSION 1
#define VK_EXT_acquire_xlib_display 1
#define VK_EXT_blend_operation_advanced 1
#define VK_EXT_debug_marker 1
#define VK_EXT_debug_report 1
#define VK_EXT_depth_range_unrestricted 1
#define VK_EXT_direct_mode_display 1
#define VK_EXT_discard_rectangles 1
#define VK_EXT_display_control 1
#define VK_EXT_display_surface_counter 1
#define VK_EXT_hdr_metadata 1
#define VK_EXT_post_depth_coverage 1
#define VK_EXT_sampler_filter_minmax 1
#define VK_EXT_shader_stencil_export 1
#define VK_EXT_shader_subgroup_ballot 1
#define VK_EXT_shader_subgroup_vote 1
#define VK_EXT_shader_viewport_index_layer 1
#define VK_EXT_swapchain_colorspace 1
#define VK_EXT_validation_flags 1
#define VK_FALSE                          0
#define VK_GOOGLE_DISPLAY_TIMING_EXTENSION_NAME "VK_GOOGLE_display_timing"
#define VK_GOOGLE_DISPLAY_TIMING_SPEC_VERSION 1
#define VK_GOOGLE_display_timing 1
#define VK_HEADER_VERSION 59
#define VK_IMG_FILTER_CUBIC_EXTENSION_NAME "VK_IMG_filter_cubic"
#define VK_IMG_FILTER_CUBIC_SPEC_VERSION  1
#define VK_IMG_FORMAT_PVRTC_EXTENSION_NAME "VK_IMG_format_pvrtc"
#define VK_IMG_FORMAT_PVRTC_SPEC_VERSION  1
#define VK_IMG_filter_cubic 1
#define VK_IMG_format_pvrtc 1
#define VK_KHR_16BIT_STORAGE_EXTENSION_NAME "VK_KHR_16bit_storage"
#define VK_KHR_16BIT_STORAGE_SPEC_VERSION 1
#define VK_KHR_16bit_storage 1
#define VK_KHR_ANDROID_SURFACE_EXTENSION_NAME "VK_KHR_android_surface"
#define VK_KHR_ANDROID_SURFACE_SPEC_VERSION 6
#define VK_KHR_DEDICATED_ALLOCATION_EXTENSION_NAME "VK_KHR_dedicated_allocation"
#define VK_KHR_DEDICATED_ALLOCATION_SPEC_VERSION 3
#define VK_KHR_DESCRIPTOR_UPDATE_TEMPLATE_EXTENSION_NAME "VK_KHR_descriptor_update_template"
#define VK_KHR_DESCRIPTOR_UPDATE_TEMPLATE_SPEC_VERSION 1
#define VK_KHR_DISPLAY_EXTENSION_NAME     "VK_KHR_display"
#define VK_KHR_DISPLAY_SPEC_VERSION       21
#define VK_KHR_DISPLAY_SWAPCHAIN_EXTENSION_NAME "VK_KHR_display_swapchain"
#define VK_KHR_DISPLAY_SWAPCHAIN_SPEC_VERSION 9
#define VK_KHR_EXTERNAL_FENCE_CAPABILITIES_EXTENSION_NAME "VK_KHR_external_fence_capabilities"
#define VK_KHR_EXTERNAL_FENCE_CAPABILITIES_SPEC_VERSION 1
#define VK_KHR_EXTERNAL_FENCE_EXTENSION_NAME "VK_KHR_external_fence"
#define VK_KHR_EXTERNAL_FENCE_FD_EXTENSION_NAME "VK_KHR_external_fence_fd"
#define VK_KHR_EXTERNAL_FENCE_FD_SPEC_VERSION 1
#define VK_KHR_EXTERNAL_FENCE_SPEC_VERSION 1
#define VK_KHR_EXTERNAL_FENCE_WIN32_EXTENSION_NAME "VK_KHR_external_fence_win32"
#define VK_KHR_EXTERNAL_FENCE_WIN32_SPEC_VERSION 1
#define VK_KHR_EXTERNAL_MEMORY_CAPABILITIES_EXTENSION_NAME "VK_KHR_external_memory_capabilities"
#define VK_KHR_EXTERNAL_MEMORY_CAPABILITIES_SPEC_VERSION 1
#define VK_KHR_EXTERNAL_MEMORY_EXTENSION_NAME "VK_KHR_external_memory"
#define VK_KHR_EXTERNAL_MEMORY_FD_EXTENSION_NAME "VK_KHR_external_memory_fd"
#define VK_KHR_EXTERNAL_MEMORY_FD_SPEC_VERSION 1
#define VK_KHR_EXTERNAL_MEMORY_SPEC_VERSION 1
#define VK_KHR_EXTERNAL_MEMORY_WIN32_EXTENSION_NAME "VK_KHR_external_memory_win32"
#define VK_KHR_EXTERNAL_MEMORY_WIN32_SPEC_VERSION 1
#define VK_KHR_EXTERNAL_SEMAPHORE_CAPABILITIES_EXTENSION_NAME "VK_KHR_external_semaphore_capabilities"
#define VK_KHR_EXTERNAL_SEMAPHORE_CAPABILITIES_SPEC_VERSION 1
#define VK_KHR_EXTERNAL_SEMAPHORE_EXTENSION_NAME "VK_KHR_external_semaphore"
#define VK_KHR_EXTERNAL_SEMAPHORE_FD_EXTENSION_NAME "VK_KHR_external_semaphore_fd"
#define VK_KHR_EXTERNAL_SEMAPHORE_FD_SPEC_VERSION 1
#define VK_KHR_EXTERNAL_SEMAPHORE_SPEC_VERSION 1
#define VK_KHR_EXTERNAL_SEMAPHORE_WIN32_EXTENSION_NAME "VK_KHR_external_semaphore_win32"
#define VK_KHR_EXTERNAL_SEMAPHORE_WIN32_SPEC_VERSION 1
#define VK_KHR_GET_MEMORY_REQUIREMENTS_2_EXTENSION_NAME "VK_KHR_get_memory_requirements2"
#define VK_KHR_GET_MEMORY_REQUIREMENTS_2_SPEC_VERSION 1
#define VK_KHR_GET_PHYSICAL_DEVICE_PROPERTIES_2_EXTENSION_NAME "VK_KHR_get_physical_device_properties2"
#define VK_KHR_GET_PHYSICAL_DEVICE_PROPERTIES_2_SPEC_VERSION 1
#define VK_KHR_GET_SURFACE_CAPABILITIES_2_EXTENSION_NAME "VK_KHR_get_surface_capabilities2"
#define VK_KHR_GET_SURFACE_CAPABILITIES_2_SPEC_VERSION 1
#define VK_KHR_INCREMENTAL_PRESENT_EXTENSION_NAME "VK_KHR_incremental_present"
#define VK_KHR_INCREMENTAL_PRESENT_SPEC_VERSION 1
#define VK_KHR_MAINTENANCE1_EXTENSION_NAME "VK_KHR_maintenance1"
#define VK_KHR_MAINTENANCE1_SPEC_VERSION  1
#define VK_KHR_MIR_SURFACE_EXTENSION_NAME "VK_KHR_mir_surface"
#define VK_KHR_MIR_SURFACE_SPEC_VERSION   4
#define VK_KHR_PUSH_DESCRIPTOR_EXTENSION_NAME "VK_KHR_push_descriptor"
#define VK_KHR_PUSH_DESCRIPTOR_SPEC_VERSION 1
#define VK_KHR_RELAXED_BLOCK_LAYOUT_EXTENSION_NAME "VK_KHR_relaxed_block_layout"
#define VK_KHR_RELAXED_BLOCK_LAYOUT_SPEC_VERSION 1
#define VK_KHR_SAMPLER_MIRROR_CLAMP_TO_EDGE_EXTENSION_NAME "VK_KHR_sampler_mirror_clamp_to_edge"
#define VK_KHR_SAMPLER_MIRROR_CLAMP_TO_EDGE_SPEC_VERSION 1
#define VK_KHR_SHADER_DRAW_PARAMETERS_EXTENSION_NAME "VK_KHR_shader_draw_parameters"
#define VK_KHR_SHADER_DRAW_PARAMETERS_SPEC_VERSION 1
#define VK_KHR_SHARED_PRESENTABLE_IMAGE_EXTENSION_NAME "VK_KHR_shared_presentable_image"
#define VK_KHR_SHARED_PRESENTABLE_IMAGE_SPEC_VERSION 1
#define VK_KHR_STORAGE_BUFFER_STORAGE_CLASS_EXTENSION_NAME "VK_KHR_storage_buffer_storage_class"
#define VK_KHR_STORAGE_BUFFER_STORAGE_CLASS_SPEC_VERSION 1
#define VK_KHR_SURFACE_EXTENSION_NAME     "VK_KHR_surface"
#define VK_KHR_SURFACE_SPEC_VERSION       25
#define VK_KHR_SWAPCHAIN_EXTENSION_NAME   "VK_KHR_swapchain"
#define VK_KHR_SWAPCHAIN_SPEC_VERSION     68
#define VK_KHR_VARIABLE_POINTERS_EXTENSION_NAME "VK_KHR_variable_pointers"
#define VK_KHR_VARIABLE_POINTERS_SPEC_VERSION 1
#define VK_KHR_WAYLAND_SURFACE_EXTENSION_NAME "VK_KHR_wayland_surface"
#define VK_KHR_WAYLAND_SURFACE_SPEC_VERSION 6
#define VK_KHR_WIN32_KEYED_MUTEX_EXTENSION_NAME "VK_KHR_win32_keyed_mutex"
#define VK_KHR_WIN32_KEYED_MUTEX_SPEC_VERSION 1
#define VK_KHR_WIN32_SURFACE_EXTENSION_NAME "VK_KHR_win32_surface"
#define VK_KHR_WIN32_SURFACE_SPEC_VERSION 6
#define VK_KHR_XCB_SURFACE_EXTENSION_NAME "VK_KHR_xcb_surface"
#define VK_KHR_XCB_SURFACE_SPEC_VERSION   6
#define VK_KHR_XLIB_SURFACE_EXTENSION_NAME "VK_KHR_xlib_surface"
#define VK_KHR_XLIB_SURFACE_SPEC_VERSION  6
#define VK_KHR_android_surface 1
#define VK_KHR_dedicated_allocation 1
#define VK_KHR_descriptor_update_template 1
#define VK_KHR_display 1
#define VK_KHR_display_swapchain 1
#define VK_KHR_external_fence 1
#define VK_KHR_external_fence_capabilities 1
#define VK_KHR_external_fence_fd 1
#define VK_KHR_external_fence_win32 1
#define VK_KHR_external_memory 1
#define VK_KHR_external_memory_capabilities 1
#define VK_KHR_external_memory_fd 1
#define VK_KHR_external_memory_win32 1
#define VK_KHR_external_semaphore 1
#define VK_KHR_external_semaphore_capabilities 1
#define VK_KHR_external_semaphore_fd 1
#define VK_KHR_external_semaphore_win32 1
#define VK_KHR_get_memory_requirements2 1
#define VK_KHR_get_physical_device_properties2 1
#define VK_KHR_get_surface_capabilities2 1
#define VK_KHR_incremental_present 1
#define VK_KHR_maintenance1 1
#define VK_KHR_mir_surface 1
#define VK_KHR_push_descriptor 1
#define VK_KHR_relaxed_block_layout 1
#define VK_KHR_sampler_mirror_clamp_to_edge 1
#define VK_KHR_shader_draw_parameters 1
#define VK_KHR_shared_presentable_image 1
#define VK_KHR_storage_buffer_storage_class 1
#define VK_KHR_surface 1
#define VK_KHR_swapchain 1
#define VK_KHR_variable_pointers 1
#define VK_KHR_wayland_surface 1
#define VK_KHR_win32_keyed_mutex 1
#define VK_KHR_win32_surface 1
#define VK_KHR_xcb_surface 1
#define VK_KHR_xlib_surface 1
#define VK_KHX_DEVICE_GROUP_CREATION_EXTENSION_NAME "VK_KHX_device_group_creation"
#define VK_KHX_DEVICE_GROUP_CREATION_SPEC_VERSION 1
#define VK_KHX_DEVICE_GROUP_EXTENSION_NAME "VK_KHX_device_group"
#define VK_KHX_DEVICE_GROUP_SPEC_VERSION  1
#define VK_KHX_MULTIVIEW_EXTENSION_NAME   "VK_KHX_multiview"
#define VK_KHX_MULTIVIEW_SPEC_VERSION     1
#define VK_KHX_device_group 1
#define VK_KHX_device_group_creation 1
#define VK_KHX_multiview 1
#define VK_LOD_CLAMP_NONE                 1000.0f
#define VK_LUID_SIZE_KHR                  8
#define VK_MAKE_VERSION(major, minor, patch) \
    (((major) << 22) | ((minor) << 12) | (patch))
#define VK_MAX_DESCRIPTION_SIZE           256
#define VK_MAX_DEVICE_GROUP_SIZE_KHX      32
#define VK_MAX_EXTENSION_NAME_SIZE        256
#define VK_MAX_MEMORY_HEAPS               16
#define VK_MAX_MEMORY_TYPES               32
#define VK_MAX_PHYSICAL_DEVICE_NAME_SIZE  256
#define VK_MVK_IOS_SURFACE_EXTENSION_NAME "VK_MVK_ios_surface"
#define VK_MVK_IOS_SURFACE_SPEC_VERSION   2
#define VK_MVK_MACOS_SURFACE_EXTENSION_NAME "VK_MVK_macos_surface"
#define VK_MVK_MACOS_SURFACE_SPEC_VERSION 2
#define VK_MVK_ios_surface 1
#define VK_MVK_macos_surface 1
#define VK_NN_VI_SURFACE_EXTENSION_NAME   "VK_NN_vi_surface"
#define VK_NN_VI_SURFACE_SPEC_VERSION     1
#define VK_NN_vi_surface 1
#define VK_NULL_HANDLE 0
#define VK_NVX_DEVICE_GENERATED_COMMANDS_EXTENSION_NAME "VK_NVX_device_generated_commands"
#define VK_NVX_DEVICE_GENERATED_COMMANDS_SPEC_VERSION 3
#define VK_NVX_MULTIVIEW_PER_VIEW_ATTRIBUTES_EXTENSION_NAME "VK_NVX_multiview_per_view_attributes"
#define VK_NVX_MULTIVIEW_PER_VIEW_ATTRIBUTES_SPEC_VERSION 1
#define VK_NVX_device_generated_commands 1
#define VK_NVX_multiview_per_view_attributes 1
#define VK_NV_CLIP_SPACE_W_SCALING_EXTENSION_NAME "VK_NV_clip_space_w_scaling"
#define VK_NV_CLIP_SPACE_W_SCALING_SPEC_VERSION 1
#define VK_NV_DEDICATED_ALLOCATION_EXTENSION_NAME "VK_NV_dedicated_allocation"
#define VK_NV_DEDICATED_ALLOCATION_SPEC_VERSION 1
#define VK_NV_EXTERNAL_MEMORY_CAPABILITIES_EXTENSION_NAME "VK_NV_external_memory_capabilities"
#define VK_NV_EXTERNAL_MEMORY_CAPABILITIES_SPEC_VERSION 1
#define VK_NV_EXTERNAL_MEMORY_EXTENSION_NAME "VK_NV_external_memory"
#define VK_NV_EXTERNAL_MEMORY_SPEC_VERSION 1
#define VK_NV_EXTERNAL_MEMORY_WIN32_EXTENSION_NAME "VK_NV_external_memory_win32"
#define VK_NV_EXTERNAL_MEMORY_WIN32_SPEC_VERSION 1
#define VK_NV_FILL_RECTANGLE_EXTENSION_NAME "VK_NV_fill_rectangle"
#define VK_NV_FILL_RECTANGLE_SPEC_VERSION 1
#define VK_NV_FRAGMENT_COVERAGE_TO_COLOR_EXTENSION_NAME "VK_NV_fragment_coverage_to_color"
#define VK_NV_FRAGMENT_COVERAGE_TO_COLOR_SPEC_VERSION 1
#define VK_NV_FRAMEBUFFER_MIXED_SAMPLES_EXTENSION_NAME "VK_NV_framebuffer_mixed_samples"
#define VK_NV_FRAMEBUFFER_MIXED_SAMPLES_SPEC_VERSION 1
#define VK_NV_GEOMETRY_SHADER_PASSTHROUGH_EXTENSION_NAME "VK_NV_geometry_shader_passthrough"
#define VK_NV_GEOMETRY_SHADER_PASSTHROUGH_SPEC_VERSION 1
#define VK_NV_GLSL_SHADER_EXTENSION_NAME  "VK_NV_glsl_shader"
#define VK_NV_GLSL_SHADER_SPEC_VERSION    1
#define VK_NV_SAMPLE_MASK_OVERRIDE_COVERAGE_EXTENSION_NAME "VK_NV_sample_mask_override_coverage"
#define VK_NV_SAMPLE_MASK_OVERRIDE_COVERAGE_SPEC_VERSION 1
#define VK_NV_VIEWPORT_ARRAY2_EXTENSION_NAME "VK_NV_viewport_array2"
#define VK_NV_VIEWPORT_ARRAY2_SPEC_VERSION 1
#define VK_NV_VIEWPORT_SWIZZLE_EXTENSION_NAME "VK_NV_viewport_swizzle"
#define VK_NV_VIEWPORT_SWIZZLE_SPEC_VERSION 1
#define VK_NV_WIN32_KEYED_MUTEX_EXTENSION_NAME "VK_NV_win32_keyed_mutex"
#define VK_NV_WIN32_KEYED_MUTEX_SPEC_VERSION 1
#define VK_NV_clip_space_w_scaling 1
#define VK_NV_dedicated_allocation 1
#define VK_NV_external_memory 1
#define VK_NV_external_memory_capabilities 1
#define VK_NV_external_memory_win32 1
#define VK_NV_fill_rectangle 1
#define VK_NV_fragment_coverage_to_color 1
#define VK_NV_framebuffer_mixed_samples 1
#define VK_NV_geometry_shader_passthrough 1
#define VK_NV_glsl_shader 1
#define VK_NV_sample_mask_override_coverage 1
#define VK_NV_viewport_array2 1
#define VK_NV_viewport_swizzle 1
#define VK_NV_win32_keyed_mutex 1
#define VK_QUEUE_FAMILY_EXTERNAL_KHR      (~0U-1)
#define VK_QUEUE_FAMILY_IGNORED           (~0U)
#define VK_REMAINING_ARRAY_LAYERS         (~0U)
#define VK_REMAINING_MIP_LEVELS           (~0U)
#define VK_STRUCTURE_TYPE_DEBUG_REPORT_CREATE_INFO_EXT VK_STRUCTURE_TYPE_DEBUG_REPORT_CALLBACK_CREATE_INFO_EXT
#define VK_STRUCTURE_TYPE_SURFACE_CAPABILITIES2_EXT VK_STRUCTURE_TYPE_SURFACE_CAPABILITIES_2_EXT
#define VK_SUBPASS_EXTERNAL               (~0U)
#define VK_TRUE                           1
#define VK_UUID_SIZE                      16
#define VK_VERSION_1_0 1
#define VK_VERSION_MAJOR(version) ((uint32_t)(version) >> 22)
#define VK_VERSION_MINOR(version) (((uint32_t)(version) >> 12) & 0x3ff)
#define VK_VERSION_PATCH(version) ((uint32_t)(version) & 0xfff)
#define VK_WHOLE_SIZE                     (~0ULL)
#define VULKAN_H_ 1

#define UNICODE 1

#define WIN_StringToUTF8(S) SDL_iconv_string("UTF-8", "UTF-16LE", (char *)(S), (SDL_wcslen(S)+1)*sizeof(WCHAR))
#define WIN_UTF8ToString(S) (WCHAR *)SDL_iconv_string("UTF-16LE", "UTF-8", (char *)(S), SDL_strlen(S)+1)

#define _WIN32_WINNT  0x501   
#define SDL_WAYLAND_INTERFACE(iface) extern const struct wl_interface *WAYLAND_##iface;
#define SDL_WAYLAND_MODULE(modname) extern int SDL_WAYLAND_HAVE_##modname;
#define SDL_WAYLAND_SYM(rc,fn,params) \
    typedef rc (*SDL_DYNWAYLANDFN_##fn) params; \
    extern SDL_DYNWAYLANDFN_##fn WAYLAND_##fn;

#define wl_buffer_interface (*WAYLAND_wl_buffer_interface)
#define wl_compositor_interface (*WAYLAND_wl_compositor_interface)
#define wl_data_device_interface (*WAYLAND_wl_data_device_interface)
#define wl_data_device_manager_interface (*WAYLAND_wl_data_device_manager_interface)
#define wl_data_offer_interface (*WAYLAND_wl_data_offer_interface)
#define wl_data_source_interface (*WAYLAND_wl_data_source_interface)
#define wl_keyboard_interface (*WAYLAND_wl_keyboard_interface)
#define wl_output_interface (*WAYLAND_wl_output_interface)
#define wl_pointer_interface (*WAYLAND_wl_pointer_interface)
#define wl_proxy_add_listener (*WAYLAND_wl_proxy_add_listener)
#define wl_proxy_create (*WAYLAND_wl_proxy_create)
#define wl_proxy_destroy (*WAYLAND_wl_proxy_destroy)
#define wl_proxy_get_user_data (*WAYLAND_wl_proxy_get_user_data)
#define wl_proxy_marshal (*WAYLAND_wl_proxy_marshal)
#define wl_proxy_marshal_constructor (*WAYLAND_wl_proxy_marshal_constructor)
#define wl_proxy_marshal_constructor_versioned (*WAYLAND_wl_proxy_marshal_constructor_versioned)
#define wl_proxy_set_user_data (*WAYLAND_wl_proxy_set_user_data)
#define wl_region_interface (*WAYLAND_wl_region_interface)
#define wl_registry_interface (*WAYLAND_wl_registry_interface)
#define wl_seat_interface (*WAYLAND_wl_seat_interface)
#define wl_shell_interface (*WAYLAND_wl_shell_interface)
#define wl_shell_surface_interface (*WAYLAND_wl_shell_surface_interface)
#define wl_shm_interface (*WAYLAND_wl_shm_interface)
#define wl_shm_pool_interface (*WAYLAND_wl_shm_pool_interface)
#define wl_surface_interface (*WAYLAND_wl_surface_interface)
#define SDL_CreateThread(fn, name, data) SDL_CreateThread_REAL(fn, name, data, (pfnSDL_CurrentBeginThread)_beginthreadex, (pfnSDL_CurrentEndThread)_endthreadex)


#define SDL_MUTEX_MAXWAIT   (~(Uint32)0)
#define SDL_MUTEX_TIMEDOUT  1
#define SDL_mutexP(m)   SDL_LockMutex(m)
#define SDL_mutexV(m)   SDL_UnlockMutex(m)

#define SDL_AtomicDecRef(a)    (SDL_AtomicAdd(a, -1) == 1)
#define SDL_AtomicIncRef(a)    SDL_AtomicAdd(a, 1)
#define SDL_CompilerBarrier()   _ReadWriteBarrier()
#define SDL_MemoryBarrierAcquire()   __asm__ __volatile__ ("lwsync" : : : "memory")
#define SDL_MemoryBarrierRelease()   __asm__ __volatile__ ("lwsync" : : : "memory")

#define SDL_INVALID_SHAPE_ARGUMENT -2
#define SDL_NONSHAPEABLE_WINDOW -1
#define SDL_SHAPEMODEALPHA(mode) (mode == ShapeModeDefault || mode == ShapeModeBinarizeAlpha || mode == ShapeModeReverseBinarizeAlpha)
#define SDL_WINDOW_LACKS_SHAPE -3


