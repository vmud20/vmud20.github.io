

#define IMAGING_CODEC_BROKEN    -2
#define IMAGING_CODEC_CONFIG    -8
#define IMAGING_CODEC_END        1
#define IMAGING_CODEC_MEMORY    -9
#define IMAGING_CODEC_OVERRUN   -1
#define IMAGING_CODEC_UNKNOWN   -3
#define IMAGING_MAGIC "PIL Imaging"
#define IMAGING_MODE_LENGTH 6+1 
#define IMAGING_PIXEL_1(im,x,y) ((im)->image8[(y)][(x)])
#define IMAGING_PIXEL_CMYK(im,x,y) ((im)->image[(y)][(x)*4])
#define IMAGING_PIXEL_F(im,x,y) (((FLOAT32*)(im)->image32[y])[x])
#define IMAGING_PIXEL_FLOAT32(im,x,y) (((FLOAT32*)(im)->image32[y])[x])
#define IMAGING_PIXEL_I(im,x,y) ((im)->image32[(y)][(x)])
#define IMAGING_PIXEL_INT32(im,x,y) ((im)->image32[(y)][(x)])
#define IMAGING_PIXEL_L(im,x,y) ((im)->image8[(y)][(x)])
#define IMAGING_PIXEL_LA(im,x,y) ((im)->image[(y)][(x)*4])
#define IMAGING_PIXEL_P(im,x,y) ((im)->image8[(y)][(x)])
#define IMAGING_PIXEL_PA(im,x,y) ((im)->image[(y)][(x)*4])
#define IMAGING_PIXEL_RGB(im,x,y) ((im)->image[(y)][(x)*4])
#define IMAGING_PIXEL_RGBA(im,x,y) ((im)->image[(y)][(x)*4])
#define IMAGING_PIXEL_UINT8(im,x,y) ((im)->image8[(y)][(x)])
#define IMAGING_PIXEL_YCbCr(im,x,y) ((im)->image[(y)][(x)*4])
#define IMAGING_TRANSFORM_AFFINE 0
#define IMAGING_TRANSFORM_BICUBIC 3
#define IMAGING_TRANSFORM_BILINEAR 2
#define IMAGING_TRANSFORM_BOX 4
#define IMAGING_TRANSFORM_HAMMING 5
#define IMAGING_TRANSFORM_LANCZOS 1
#define IMAGING_TRANSFORM_NEAREST 0
#define IMAGING_TRANSFORM_PERSPECTIVE 2
#define IMAGING_TRANSFORM_QUAD 3
#define IMAGING_TYPE_FLOAT32 2
#define IMAGING_TYPE_INT32 1
#define IMAGING_TYPE_SPECIAL 3 
#define IMAGING_TYPE_UINT8 0
#define ImagingAccessDelete(im, access) 
#define ImagingPaletteCache(p, r, g, b)\
    p->cache[(r>>2) + (g>>2)*64 + (b>>2)*64*64]
#define M_PI    3.1415926535897932384626433832795
#define BLEND(mask, in1, in2, tmp1)\
    DIV255(in1 * (255 - mask) + in2 * mask, tmp1)
#define CLIP8(v) ((v) <= 0 ? 0 : (v) < 256 ? (v) : 255)
#define DIV255(a, tmp)\
    (tmp = (a) + 128, SHIFTFORDIV255(tmp))
    #define MAKE_UINT32(u0, u1, u2, u3) (u3 | (u2<<8) | (u1<<16) | (u0<<24))
    #define MASK_UINT32_CHANNEL_0 0xff000000
    #define MASK_UINT32_CHANNEL_1 0x0000ff00
    #define MASK_UINT32_CHANNEL_2 0x00ff0000
    #define MASK_UINT32_CHANNEL_3 0xff000000
#define MULDIV255(a, b, tmp)\
    (tmp = (a) * (b) + 128, SHIFTFORDIV255(tmp))
#define PREBLEND(mask, in1, in2, tmp1)\
    (MULDIV255(in1, (255 - mask), tmp1) + in2)
#define SHIFTFORDIV255(a)\
    ((((a) >> 8) + a) >> 8)
    #define GCC_VERSION ("__GNUC__" * 10000 \
                       + "__GNUC_MINOR__" * 100 \
                       + "__GNUC_PATCHLEVEL__")

#define inline __inline
