




#include<inttypes.h>


#include<error.h>
#include<ctype.h>
#include<stdint.h>
#include<errno.h>
#include<string.h>










#include<assert.h>








#include<limits.h>
#include<math.h>



#include<stdarg.h>



#include<stdlib.h>
#include<stdio.h>

#define CHROMA_IDC 3
#   define FUNC(n) AV_JOIN(n ## _simple_, BITS)
#   define PIXEL_SHIFT (BITS >> 4)
#   define MCFUNC(n) FUNC(n ## _420)
#define mc_part MCFUNC(mc_part)

#define av_assert0(cond) do {                                           \
    if (!(cond)) {                                                      \
        av_log(NULL, AV_LOG_FATAL, "Assertion %s failed at %s:%d\n",    \
               AV_STRINGIFY(cond), "__FILE__", "__LINE__");                 \
        abort();                                                        \
    }                                                                   \
} while (0)
#define av_assert1(cond) av_assert0(cond)
#define av_assert2(cond) av_assert0(cond)


#define CANDIDATE_MB_TYPE_BACKWARD 0x40
#define CANDIDATE_MB_TYPE_BACKWARD_I 0x400
#define CANDIDATE_MB_TYPE_BIDIR    0x80
#define CANDIDATE_MB_TYPE_BIDIR_I    0x800
#define CANDIDATE_MB_TYPE_DIRECT   0x10
#define CANDIDATE_MB_TYPE_DIRECT0    0x1000
#define CANDIDATE_MB_TYPE_FORWARD  0x20
#define CANDIDATE_MB_TYPE_FORWARD_I  0x200
#define CANDIDATE_MB_TYPE_INTER    0x02
#define CANDIDATE_MB_TYPE_INTER4V  0x04
#define CANDIDATE_MB_TYPE_INTER_I    0x100
#define CANDIDATE_MB_TYPE_INTRA    0x01
#define CANDIDATE_MB_TYPE_SKIPPED   0x08
#define CHROMA_420 1
#define CHROMA_422 2
#define CHROMA_444 3
#define DELAYED_PIC_REF 4
#define ER_AC_END              16
#define ER_AC_ERROR            2
#define ER_DC_END              32
#define ER_DC_ERROR            4
#define ER_MB_END   (ER_AC_END|ER_DC_END|ER_MV_END)
#define ER_MB_ERROR (ER_AC_ERROR|ER_DC_ERROR|ER_MV_ERROR)
#define ER_MV_END              64
#define ER_MV_ERROR            8
#define EXT_START_CODE          0x000001b5
#define FF_MPV_COMMON_OPTS \
{ "mpv_flags",      "Flags common for all mpegvideo-based encoders.", FF_MPV_OFFSET(mpv_flags), AV_OPT_TYPE_FLAGS, { .i64 = 0 }, INT_MIN, INT_MAX, FF_MPV_OPT_FLAGS, "mpv_flags" },\
{ "skip_rd",        "RD optimal MB level residual skipping", 0, AV_OPT_TYPE_CONST, { .i64 = FF_MPV_FLAG_SKIP_RD },    0, 0, FF_MPV_OPT_FLAGS, "mpv_flags" },\
{ "strict_gop",     "Strictly enforce gop size",             0, AV_OPT_TYPE_CONST, { .i64 = FF_MPV_FLAG_STRICT_GOP }, 0, 0, FF_MPV_OPT_FLAGS, "mpv_flags" },\
{ "qp_rd",          "Use rate distortion optimization for qp selection", 0, AV_OPT_TYPE_CONST, { .i64 = FF_MPV_FLAG_QP_RD },  0, 0, FF_MPV_OPT_FLAGS, "mpv_flags" },\
{ "cbp_rd",         "use rate distortion optimization for CBP",          0, AV_OPT_TYPE_CONST, { .i64 = FF_MPV_FLAG_CBP_RD }, 0, 0, FF_MPV_OPT_FLAGS, "mpv_flags" },\
{ "luma_elim_threshold",   "single coefficient elimination threshold for luminance (negative values also consider dc coefficient)",\
                                                                      FF_MPV_OFFSET(luma_elim_threshold), AV_OPT_TYPE_INT, { .i64 = 0 }, INT_MIN, INT_MAX, FF_MPV_OPT_FLAGS },\
{ "chroma_elim_threshold", "single coefficient elimination threshold for chrominance (negative values also consider dc coefficient)",\
                                                                      FF_MPV_OFFSET(chroma_elim_threshold), AV_OPT_TYPE_INT, { .i64 = 0 }, INT_MIN, INT_MAX, FF_MPV_OPT_FLAGS },\
{ "quantizer_noise_shaping", NULL,                                  FF_MPV_OFFSET(quantizer_noise_shaping), AV_OPT_TYPE_INT, { .i64 = 0 },       0, INT_MAX, FF_MPV_OPT_FLAGS },
#define FF_MPV_FLAG_CBP_RD       0x0008
#define FF_MPV_FLAG_QP_RD        0x0004
#define FF_MPV_FLAG_SKIP_RD      0x0001
#define FF_MPV_FLAG_STRICT_GOP   0x0002
#define FF_MPV_GENERIC_CLASS(name) \
static const AVClass name ## _class = {\
    .class_name = #name " encoder",\
    .item_name  = av_default_item_name,\
    .option     = ff_mpv_generic_options,\
    .version    = LIBAVUTIL_VERSION_INT,\
};
#define FF_MPV_OFFSET(x) offsetof(MpegEncContext, x)
#define FF_MPV_OPT_FLAGS (AV_OPT_FLAG_VIDEO_PARAM | AV_OPT_FLAG_ENCODING_PARAM)
#define FRAME_SKIPPED 100 
#define GOP_START_CODE          0x000001b8
#define HAS_CBP(a)        ((a)&MB_TYPE_CBP)
#define INPLACE_OFFSET 16
#define IS_16X16(a)      ((a)&MB_TYPE_16x16)
#define IS_16X8(a)       ((a)&MB_TYPE_16x8)
#define IS_8X16(a)       ((a)&MB_TYPE_8x16)
#define IS_8X8(a)        ((a)&MB_TYPE_8x8)
#define IS_ACPRED(a)     ((a)&MB_TYPE_ACPRED)
#define IS_DIR(a, part, list) ((a) & (MB_TYPE_P0L0<<((part)+2*(list))))
#define IS_DIRECT(a)     ((a)&MB_TYPE_DIRECT2)
#define IS_GMC(a)        ((a)&MB_TYPE_GMC)
#define IS_INTER(a)      ((a)&(MB_TYPE_16x16|MB_TYPE_16x8|MB_TYPE_8x16|MB_TYPE_8x8))
#define IS_INTERLACED(a) ((a)&MB_TYPE_INTERLACED)
#define IS_INTRA(a)      ((a)&7)
#define IS_INTRA16x16(a) ((a)&MB_TYPE_INTRA16x16)
#define IS_INTRA4x4(a)   ((a)&MB_TYPE_INTRA4x4)
#define IS_INTRA_PCM(a)  ((a)&MB_TYPE_INTRA_PCM)
#define IS_PCM(a)        ((a)&MB_TYPE_INTRA_PCM)
#define IS_QUANT(a)      ((a)&MB_TYPE_QUANT)
#define IS_SKIP(a)       ((a)&MB_TYPE_SKIP)
#define IS_SUB_4X4(a)    ((a)&MB_TYPE_8x8)   
#define IS_SUB_4X8(a)    ((a)&MB_TYPE_8x16)  
#define IS_SUB_8X4(a)    ((a)&MB_TYPE_16x8)  
#define IS_SUB_8X8(a)    ((a)&MB_TYPE_16x16) 
#define MAX_FCODE 7
#define MAX_MB_BYTES (30*16*16*3/8 + 120)
#define MAX_MV 2048
#define MAX_PICTURE_COUNT 32
#define MAX_THREADS 16
#define MB_TYPE_INTRA MB_TYPE_INTRA4x4 
#define ME_MAP_MV_BITS 11
#define ME_MAP_SHIFT 3
#define ME_MAP_SIZE 64
#define MPEG_BUF_SIZE (16 * 1024)
#define MV_DIRECT        4 
#define MV_DIR_BACKWARD  2
#define MV_DIR_FORWARD   1
#define MV_TYPE_16X16       0   
#define MV_TYPE_16X8        2   
#define MV_TYPE_8X8         1   
#define MV_TYPE_DMV         4   
#define MV_TYPE_FIELD       3   
#define PICTURE_START_CODE      0x00000100
#define PICT_BOTTOM_FIELD  2
#define PICT_FRAME         3
#define PICT_TOP_FIELD     1
#define QMAT_SHIFT 22
#define QMAT_SHIFT_MMX 16
#define QUANT_BIAS_SHIFT 8
#define REBASE_PICTURE(pic, new_ctx, old_ctx) (pic ? \
    (pic >= old_ctx->picture && pic < old_ctx->picture+old_ctx->picture_count ?\
        &new_ctx->picture[pic - old_ctx->picture] : pic - (Picture*)old_ctx + (Picture*)new_ctx)\
    : NULL)
#define SEQ_END_CODE            0x000001b7
#define SEQ_START_CODE          0x000001b3
#define SLICE_END       -2 
#define SLICE_ERROR     -1
#define SLICE_MAX_START_CODE    0x000001af
#define SLICE_MIN_START_CODE    0x00000101
#define SLICE_NOEND     -3 
#define SLICE_OK         0
#define UNI_AC_ENC_INDEX(run,level) ((run)*128 + (level))
#define USER_START_CODE         0x000001b2
#define USES_LIST(a, list) ((a) & ((MB_TYPE_P0L0|MB_TYPE_P1L0)<<(2*(list)))) 
#define VP_START            1          

#define AV_OPT_FLAG_AUDIO_PARAM     8
#define AV_OPT_FLAG_DECODING_PARAM  2   
#define AV_OPT_FLAG_ENCODING_PARAM  1   
#define AV_OPT_FLAG_METADATA        4   
#define AV_OPT_FLAG_SUBTITLE_PARAM  32
#define AV_OPT_FLAG_VIDEO_PARAM     16
#define AV_OPT_SEARCH_CHILDREN   0x0001 
#define AV_OPT_SEARCH_FAKE_OBJ   0x0002

#define INIT_VLC_RL(rl, static_size)\
{\
    int q;\
    static RL_VLC_ELEM rl_vlc_table[32][static_size];\
    INIT_VLC_STATIC(&rl.vlc, 9, rl.n + 1,\
             &rl.table_vlc[0][1], 4, 2,\
             &rl.table_vlc[0][0], 4, 2, static_size);\
\
    if(!rl.rl_vlc[0]){\
        for(q=0; q<32; q++)\
            rl.rl_vlc[q]= rl_vlc_table[q];\
\
        ff_init_vlc_rl(&rl);\
    }\
}
#define MAX_LEVEL  64
#define MAX_RUN    64

#define CLOSE_READER(name, gb) (gb)->index = name##_index
#define GET_CACHE(name, gb) ((uint32_t)name##_cache)
#define GET_RL_VLC(level, run, name, gb, table, bits, max_depth, need_update) \
    do {                                                                \
        int n, nb_bits;                                                 \
        unsigned int index;                                             \
                                                                        \
        index = SHOW_UBITS(name, gb, bits);                             \
        level = table[index].level;                                     \
        n     = table[index].len;                                       \
                                                                        \
        if (max_depth > 1 && n < 0) {                                   \
            SKIP_BITS(name, gb, bits);                                  \
            if (need_update) {                                          \
                UPDATE_CACHE(name, gb);                                 \
            }                                                           \
                                                                        \
            nb_bits = -n;                                               \
                                                                        \
            index = SHOW_UBITS(name, gb, nb_bits) + level;              \
            level = table[index].level;                                 \
            n     = table[index].len;                                   \
        }                                                               \
        run = table[index].run;                                         \
        SKIP_BITS(name, gb, n);                                         \
    } while (0)
#define GET_VLC(code, name, gb, table, bits, max_depth)         \
    do {                                                        \
        int n, nb_bits;                                         \
        unsigned int index;                                     \
                                                                \
        index = SHOW_UBITS(name, gb, bits);                     \
        code  = table[index][0];                                \
        n     = table[index][1];                                \
                                                                \
        if (max_depth > 1 && n < 0) {                           \
            LAST_SKIP_BITS(name, gb, bits);                     \
            UPDATE_CACHE(name, gb);                             \
                                                                \
            nb_bits = -n;                                       \
                                                                \
            index = SHOW_UBITS(name, gb, nb_bits) + code;       \
            code  = table[index][0];                            \
            n     = table[index][1];                            \
            if (max_depth > 2 && n < 0) {                       \
                LAST_SKIP_BITS(name, gb, nb_bits);              \
                UPDATE_CACHE(name, gb);                         \
                                                                \
                nb_bits = -n;                                   \
                                                                \
                index = SHOW_UBITS(name, gb, nb_bits) + code;   \
                code  = table[index][0];                        \
                n     = table[index][1];                        \
            }                                                   \
        }                                                       \
        SKIP_BITS(name, gb, n);                                 \
    } while (0)
#define HAVE_BITS_REMAINING(name, gb) 1
#define INIT_VLC_LE         2
#define INIT_VLC_STATIC(vlc, bits, a,b,c,d,e,f,g, static_size) do {     \
        static VLC_TYPE table[static_size][2];                          \
        (vlc)->table = table;                                           \
        (vlc)->table_allocated = static_size;                           \
        init_vlc(vlc, bits, a,b,c,d,e,f,g, INIT_VLC_USE_NEW_STATIC);    \
    } while (0)
#define INIT_VLC_USE_NEW_STATIC 4
#define LAST_SKIP_BITS(name, gb, num) SKIP_COUNTER(name, gb, num)
#   define MIN_CACHE_BITS 32
#define OPEN_READER(name, gb)                   \
    unsigned int name##_index = (gb)->index;    \
    unsigned int av_unused name##_cache = 0
#   define SHOW_SBITS(name, gb, num) sign_extend(name##_cache, num)
#   define SHOW_UBITS(name, gb, num) zero_extend(name##_cache, num)
#define SKIP_BITS(name, gb, num) do {           \
        SKIP_CACHE(name, gb, num);              \
        SKIP_COUNTER(name, gb, num);            \
    } while (0)
# define SKIP_CACHE(name, gb, num) name##_cache >>= (num)
#   define SKIP_COUNTER(name, gb, num) name##_index += (num)
#define UNCHECKED_BITSTREAM_READER !CONFIG_SAFE_BITSTREAM_READER
#   define UPDATE_CACHE(name, gb) name##_cache = \
        AV_RL64((gb)->buffer + (name##_index >> 3)) >> (name##_index & 7)
#define VLC_TYPE int16_t
#define get_bits(s, n)  get_bits_trace(s, n, "__FILE__", __PRETTY_FUNCTION__, "__LINE__")
#define get_bits1(s)    get_bits_trace(s, 1, "__FILE__", __PRETTY_FUNCTION__, "__LINE__")
#define get_vlc(s, vlc)            get_vlc_trace(s, (vlc)->table, (vlc)->bits, 3, "__FILE__", __PRETTY_FUNCTION__, "__LINE__")
#define get_vlc2(s, tab, bits, max) get_vlc_trace(s, tab, bits, max, "__FILE__", __PRETTY_FUNCTION__, "__LINE__")
#define get_xbits(s, n) get_xbits_trace(s, n, "__FILE__", __PRETTY_FUNCTION__, "__LINE__")
#define init_vlc(vlc, nb_bits, nb_codes,                \
                 bits, bits_wrap, bits_size,            \
                 codes, codes_wrap, codes_size,         \
                 flags)                                 \
        ff_init_vlc_sparse(vlc, nb_bits, nb_codes,         \
                           bits, bits_wrap, bits_size,     \
                           codes, codes_wrap, codes_size,  \
                           NULL, 0, 0, flags)
#define tprintf(p, ...) av_log(p, AV_LOG_DEBUG, __VA_ARGS__)

#define COPY3_IF_LT(x, y, a, b, c, d)\
if ((y) < (x)) {\
    (x) = (y);\
    (a) = (b);\
    (c) = (d);\
}
#   define FASTDIV(a,b) ((uint32_t)((((uint64_t)a) * ff_inverse[b]) >> 32))
#   define MAC16(rt, ra, rb) rt += (ra) * (rb)
#   define MAC64(d, a, b) ((d) += MUL64(a, b))
#define MASK_ABS(mask, level) do {              \
        mask  = level >> 31;                    \
        level = (level ^ mask) - mask;          \
    } while (0)
#   define MLS16(rt, ra, rb) ((rt) -= (ra) * (rb))
#   define MLS64(d, a, b) ((d) -= MUL64(a, b))
#   define MUL16(ra, rb) ((ra) * (rb))
#   define MUL64(a,b) ((int64_t)(a) * (int64_t)(b))
#   define MULL(a,b,s) (MUL64(a, b) >> (s))
#   define NEG_SSR32(a,s) ((( int32_t)(a))>>(32-(s)))
#   define NEG_USR32(a,s) (((uint32_t)(a))>>(32-(s)))
#   define PACK_2S16(a,b)    PACK_2U16((a)&0xffff, (b)&0xffff)
#   define PACK_2S8(a,b)     PACK_2U8((a)&255, (b)&255)
#   define PACK_2U16(a,b)    (((a) << 16) | (b))
#   define PACK_2U8(a,b)     (((a) <<  8) | (b))
#   define PACK_4S8(a,b,c,d) PACK_4U8((a)&255, (b)&255, (c)&255, (d)&255)
#   define PACK_4U8(a,b,c,d) (((a) << 24) | ((b) << 16) | ((c) << 8) | (d))
#define mid_pred mid_pred
#define ARCH_AARCH64 0
#define ARCH_ALPHA 0
#define ARCH_ARM 0
#define ARCH_AVR32 0
#define ARCH_AVR32_AP 0
#define ARCH_AVR32_UC 0
#define ARCH_BFIN 0
#define ARCH_IA64 0
#define ARCH_M68K 0
#define ARCH_MIPS 0
#define ARCH_MIPS64 0
#define ARCH_PARISC 0
#define ARCH_PPC 0
#define ARCH_PPC64 0
#define ARCH_S390 0
#define ARCH_SH4 0
#define ARCH_SPARC 0
#define ARCH_SPARC64 0
#define ARCH_TILEGX 0
#define ARCH_TILEPRO 0
#define ARCH_TOMI 0
#define ARCH_X86 1
#define ARCH_X86_32 0
#define ARCH_X86_64 1
#define AVCONV_DATADIR "/usr/local/share/ffmpeg"
#define BUILDSUF ""
#define CC_IDENT "gcc 9 (Ubuntu 9.4.0-1ubuntu1~20.04.2)"
#define CONFIG_A64MULTI5_ENCODER 1
#define CONFIG_A64MULTI_ENCODER 1
#define CONFIG_A64_MUXER 1
#define CONFIG_AAC_ADTSTOASC_BSF 1
#define CONFIG_AAC_AT_DECODER 0
#define CONFIG_AAC_AT_ENCODER 0
#define CONFIG_AAC_DECODER 1
#define CONFIG_AAC_DEMUXER 1
#define CONFIG_AAC_ENCODER 1
#define CONFIG_AAC_FIXED_DECODER 1
#define CONFIG_AAC_LATM_DECODER 1
#define CONFIG_AAC_LATM_PARSER 1
#define CONFIG_AAC_MF_ENCODER 0
#define CONFIG_AAC_PARSER 1
#define CONFIG_AANDCTTABLES 1
#define CONFIG_AASC_DECODER 1
#define CONFIG_AAX_DEMUXER 1
#define CONFIG_AA_DEMUXER 1
#define CONFIG_ABENCH_FILTER 1
#define CONFIG_ABITSCOPE_FILTER 1
#define CONFIG_AC3DSP 1
#define CONFIG_AC3_AT_DECODER 0
#define CONFIG_AC3_DECODER 1
#define CONFIG_AC3_DEMUXER 1
#define CONFIG_AC3_ENCODER 1
#define CONFIG_AC3_FIXED_DECODER 1
#define CONFIG_AC3_FIXED_ENCODER 1
#define CONFIG_AC3_MF_ENCODER 0
#define CONFIG_AC3_MUXER 1
#define CONFIG_AC3_PARSER 1
#define CONFIG_ACELP_KELVIN_DECODER 1
#define CONFIG_ACE_DEMUXER 1
#define CONFIG_ACM_DEMUXER 1
#define CONFIG_ACOMPRESSOR_FILTER 1
#define CONFIG_ACONTRAST_FILTER 1
#define CONFIG_ACOPY_FILTER 1
#define CONFIG_ACROSSFADE_FILTER 1
#define CONFIG_ACROSSOVER_FILTER 1
#define CONFIG_ACRUSHER_FILTER 1
#define CONFIG_ACT_DEMUXER 1
#define CONFIG_ACUE_FILTER 1
#define CONFIG_ADDROI_FILTER 1
#define CONFIG_ADECLICK_FILTER 1
#define CONFIG_ADECLIP_FILTER 1
#define CONFIG_ADELAY_FILTER 1
#define CONFIG_ADENORM_FILTER 1
#define CONFIG_ADERIVATIVE_FILTER 1
#define CONFIG_ADF_DEMUXER 1
#define CONFIG_ADPCM_4XM_DECODER 1
#define CONFIG_ADPCM_ADX_DECODER 1
#define CONFIG_ADPCM_ADX_ENCODER 1
#define CONFIG_ADPCM_AFC_DECODER 1
#define CONFIG_ADPCM_AGM_DECODER 1
#define CONFIG_ADPCM_AICA_DECODER 1
#define CONFIG_ADPCM_ARGO_DECODER 1
#define CONFIG_ADPCM_ARGO_ENCODER 1
#define CONFIG_ADPCM_CT_DECODER 1
#define CONFIG_ADPCM_DTK_DECODER 1
#define CONFIG_ADPCM_EA_DECODER 1
#define CONFIG_ADPCM_EA_MAXIS_XA_DECODER 1
#define CONFIG_ADPCM_EA_R1_DECODER 1
#define CONFIG_ADPCM_EA_R2_DECODER 1
#define CONFIG_ADPCM_EA_R3_DECODER 1
#define CONFIG_ADPCM_EA_XAS_DECODER 1
#define CONFIG_ADPCM_G722_DECODER 1
#define CONFIG_ADPCM_G722_ENCODER 1
#define CONFIG_ADPCM_G726LE_DECODER 1
#define CONFIG_ADPCM_G726LE_ENCODER 1
#define CONFIG_ADPCM_G726_DECODER 1
#define CONFIG_ADPCM_G726_ENCODER 1
#define CONFIG_ADPCM_IMA_ACORN_DECODER 1
#define CONFIG_ADPCM_IMA_ALP_DECODER 1
#define CONFIG_ADPCM_IMA_ALP_ENCODER 1
#define CONFIG_ADPCM_IMA_AMV_DECODER 1
#define CONFIG_ADPCM_IMA_AMV_ENCODER 1
#define CONFIG_ADPCM_IMA_APC_DECODER 1
#define CONFIG_ADPCM_IMA_APM_DECODER 1
#define CONFIG_ADPCM_IMA_APM_ENCODER 1
#define CONFIG_ADPCM_IMA_CUNNING_DECODER 1
#define CONFIG_ADPCM_IMA_DAT4_DECODER 1
#define CONFIG_ADPCM_IMA_DK3_DECODER 1
#define CONFIG_ADPCM_IMA_DK4_DECODER 1
#define CONFIG_ADPCM_IMA_EA_EACS_DECODER 1
#define CONFIG_ADPCM_IMA_EA_SEAD_DECODER 1
#define CONFIG_ADPCM_IMA_ISS_DECODER 1
#define CONFIG_ADPCM_IMA_MOFLEX_DECODER 1
#define CONFIG_ADPCM_IMA_MTF_DECODER 1
#define CONFIG_ADPCM_IMA_OKI_DECODER 1
#define CONFIG_ADPCM_IMA_QT_AT_DECODER 0
#define CONFIG_ADPCM_IMA_QT_DECODER 1
#define CONFIG_ADPCM_IMA_QT_ENCODER 1
#define CONFIG_ADPCM_IMA_RAD_DECODER 1
#define CONFIG_ADPCM_IMA_SMJPEG_DECODER 1
#define CONFIG_ADPCM_IMA_SSI_DECODER 1
#define CONFIG_ADPCM_IMA_SSI_ENCODER 1
#define CONFIG_ADPCM_IMA_WAV_DECODER 1
#define CONFIG_ADPCM_IMA_WAV_ENCODER 1
#define CONFIG_ADPCM_IMA_WS_DECODER 1
#define CONFIG_ADPCM_IMA_WS_ENCODER 1
#define CONFIG_ADPCM_MS_DECODER 1
#define CONFIG_ADPCM_MS_ENCODER 1
#define CONFIG_ADPCM_MTAF_DECODER 1
#define CONFIG_ADPCM_PSX_DECODER 1
#define CONFIG_ADPCM_SBPRO_2_DECODER 1
#define CONFIG_ADPCM_SBPRO_3_DECODER 1
#define CONFIG_ADPCM_SBPRO_4_DECODER 1
#define CONFIG_ADPCM_SWF_DECODER 1
#define CONFIG_ADPCM_SWF_ENCODER 1
#define CONFIG_ADPCM_THP_DECODER 1
#define CONFIG_ADPCM_THP_LE_DECODER 1
#define CONFIG_ADPCM_VIMA_DECODER 1
#define CONFIG_ADPCM_XA_DECODER 1
#define CONFIG_ADPCM_YAMAHA_DECODER 1
#define CONFIG_ADPCM_YAMAHA_ENCODER 1
#define CONFIG_ADPCM_ZORK_DECODER 1
#define CONFIG_ADP_DEMUXER 1
#define CONFIG_ADRAWGRAPH_FILTER 1
#define CONFIG_ADS_DEMUXER 1
#define CONFIG_ADTS_HEADER 1
#define CONFIG_ADTS_MUXER 1
#define CONFIG_ADX_DEMUXER 1
#define CONFIG_ADX_MUXER 1
#define CONFIG_ADX_PARSER 1
#define CONFIG_AEA_DEMUXER 1
#define CONFIG_AECHO_FILTER 1
#define CONFIG_AEMPHASIS_FILTER 1
#define CONFIG_AEVALSRC_FILTER 1
#define CONFIG_AEVAL_FILTER 1
#define CONFIG_AEXCITER_FILTER 1
#define CONFIG_AFADE_FILTER 1
#define CONFIG_AFC_DEMUXER 1
#define CONFIG_AFFTDN_FILTER 1
#define CONFIG_AFFTFILT_FILTER 1
#define CONFIG_AFIFO_FILTER 1
#define CONFIG_AFIRSRC_FILTER 1
#define CONFIG_AFIR_FILTER 1
#define CONFIG_AFORMAT_FILTER 1
#define CONFIG_AFREQSHIFT_FILTER 1
#define CONFIG_AGATE_FILTER 1
#define CONFIG_AGM_DECODER 1
#define CONFIG_AGRAPHMONITOR_FILTER 1
#define CONFIG_AHISTOGRAM_FILTER 1
#define CONFIG_AIC_DECODER 1
#define CONFIG_AIFF_DEMUXER 1
#define CONFIG_AIFF_MUXER 1
#define CONFIG_AIIR_FILTER 1
#define CONFIG_AINTEGRAL_FILTER 1
#define CONFIG_AINTERLEAVE_FILTER 1
#define CONFIG_AIX_DEMUXER 1
#define CONFIG_ALAC_AT_DECODER 0
#define CONFIG_ALAC_AT_ENCODER 0
#define CONFIG_ALAC_DECODER 1
#define CONFIG_ALAC_ENCODER 1
#define CONFIG_ALIAS_PIX_DECODER 1
#define CONFIG_ALIAS_PIX_ENCODER 1
#define CONFIG_ALIMITER_FILTER 1
#define CONFIG_ALLPASS_FILTER 1
#define CONFIG_ALLRGB_FILTER 1
#define CONFIG_ALLYUV_FILTER 1
#define CONFIG_ALOOP_FILTER 1
#define CONFIG_ALPHAEXTRACT_FILTER 1
#define CONFIG_ALPHAMERGE_FILTER 1
#define CONFIG_ALP_DEMUXER 1
#define CONFIG_ALP_MUXER 1
#define CONFIG_ALSA 0
#define CONFIG_ALSA_INDEV 0
#define CONFIG_ALSA_OUTDEV 0
#define CONFIG_ALS_DECODER 1
#define CONFIG_AMERGE_FILTER 1
#define CONFIG_AMETADATA_FILTER 1
#define CONFIG_AMF 0
#define CONFIG_AMIX_FILTER 1
#define CONFIG_AMOVIE_FILTER 1
#define CONFIG_AMPLIFY_FILTER 1
#define CONFIG_AMRNB_DECODER 1
#define CONFIG_AMRNB_DEMUXER 1
#define CONFIG_AMRWB_DECODER 1
#define CONFIG_AMRWB_DEMUXER 1
#define CONFIG_AMR_DEMUXER 1
#define CONFIG_AMR_MUXER 1
#define CONFIG_AMR_NB_AT_DECODER 0
#define CONFIG_AMULTIPLY_FILTER 1
#define CONFIG_AMV_DECODER 1
#define CONFIG_AMV_ENCODER 1
#define CONFIG_AMV_MUXER 1
#define CONFIG_ANDROID_CAMERA_INDEV 0
#define CONFIG_ANEQUALIZER_FILTER 1
#define CONFIG_ANLMDN_FILTER 1
#define CONFIG_ANLMS_FILTER 1
#define CONFIG_ANM_DECODER 1
#define CONFIG_ANM_DEMUXER 1
#define CONFIG_ANOISESRC_FILTER 1
#define CONFIG_ANSI_DECODER 1
#define CONFIG_ANULLSINK_FILTER 1
#define CONFIG_ANULLSRC_FILTER 1
#define CONFIG_ANULL_FILTER 1
#define CONFIG_APAD_FILTER 1
#define CONFIG_APC_DEMUXER 1
#define CONFIG_APERMS_FILTER 1
#define CONFIG_APE_DECODER 1
#define CONFIG_APE_DEMUXER 1
#define CONFIG_APHASEMETER_FILTER 1
#define CONFIG_APHASER_FILTER 1
#define CONFIG_APHASESHIFT_FILTER 1
#define CONFIG_APM_DEMUXER 1
#define CONFIG_APM_MUXER 1
#define CONFIG_APNG_DECODER 1
#define CONFIG_APNG_DEMUXER 1
#define CONFIG_APNG_ENCODER 1
#define CONFIG_APNG_MUXER 1
#define CONFIG_APPKIT 0
#define CONFIG_APTX_DECODER 1
#define CONFIG_APTX_DEMUXER 1
#define CONFIG_APTX_ENCODER 1
#define CONFIG_APTX_HD_DECODER 1
#define CONFIG_APTX_HD_DEMUXER 1
#define CONFIG_APTX_HD_ENCODER 1
#define CONFIG_APTX_HD_MUXER 1
#define CONFIG_APTX_MUXER 1
#define CONFIG_APULSATOR_FILTER 1
#define CONFIG_AQTITLE_DEMUXER 1
#define CONFIG_ARBC_DECODER 1
#define CONFIG_AREALTIME_FILTER 1
#define CONFIG_ARESAMPLE_FILTER 1
#define CONFIG_AREVERSE_FILTER 1
#define CONFIG_ARGO_ASF_DEMUXER 1
#define CONFIG_ARGO_ASF_MUXER 1
#define CONFIG_ARGO_BRP_DEMUXER 1
#define CONFIG_ARGO_CVG_DEMUXER 1
#define CONFIG_ARGO_CVG_MUXER 1
#define CONFIG_ARGO_DECODER 1
#define CONFIG_ARNNDN_FILTER 1
#define CONFIG_ASELECT_FILTER 1
#define CONFIG_ASENDCMD_FILTER 1
#define CONFIG_ASETNSAMPLES_FILTER 1
#define CONFIG_ASETPTS_FILTER 1
#define CONFIG_ASETRATE_FILTER 1
#define CONFIG_ASETTB_FILTER 1
#define CONFIG_ASF_DEMUXER 1
#define CONFIG_ASF_MUXER 1
#define CONFIG_ASF_O_DEMUXER 1
#define CONFIG_ASF_STREAM_MUXER 1
#define CONFIG_ASHOWINFO_FILTER 1
#define CONFIG_ASIDEDATA_FILTER 1
#define CONFIG_ASOFTCLIP_FILTER 1
#define CONFIG_ASPLIT_FILTER 1
#define CONFIG_ASR_FILTER 0
#define CONFIG_ASS_DECODER 1
#define CONFIG_ASS_DEMUXER 1
#define CONFIG_ASS_ENCODER 1
#define CONFIG_ASS_FILTER 0
#define CONFIG_ASS_MUXER 1
#define CONFIG_ASTATS_FILTER 1
#define CONFIG_ASTREAMSELECT_FILTER 1
#define CONFIG_AST_DEMUXER 1
#define CONFIG_AST_MUXER 1
#define CONFIG_ASUBBOOST_FILTER 1
#define CONFIG_ASUBCUT_FILTER 1
#define CONFIG_ASUPERCUT_FILTER 1
#define CONFIG_ASUPERPASS_FILTER 1
#define CONFIG_ASUPERSTOP_FILTER 1
#define CONFIG_ASV1_DECODER 1
#define CONFIG_ASV1_ENCODER 1
#define CONFIG_ASV2_DECODER 1
#define CONFIG_ASV2_ENCODER 1
#define CONFIG_ASYNC_PROTOCOL 1
#define CONFIG_ATADENOISE_FILTER 1
#define CONFIG_ATEMPO_FILTER 1
#define CONFIG_ATRAC1_DECODER 1
#define CONFIG_ATRAC3AL_DECODER 1
#define CONFIG_ATRAC3PAL_DECODER 1
#define CONFIG_ATRAC3P_DECODER 1
#define CONFIG_ATRAC3_DECODER 1
#define CONFIG_ATRAC9_DECODER 1
#define CONFIG_ATRIM_FILTER 1
#define CONFIG_ATSC_A53 1
#define CONFIG_AUDIODSP 1
#define CONFIG_AUDIOTOOLBOX 0
#define CONFIG_AUDIOTOOLBOX_OUTDEV 0
#define CONFIG_AUDIO_FRAME_QUEUE 1
#define CONFIG_AURA2_DECODER 1
#define CONFIG_AURA_DECODER 1
#define CONFIG_AUTODETECT 0
#define CONFIG_AU_DEMUXER 1
#define CONFIG_AU_MUXER 1
#define CONFIG_AV1_CUVID_DECODER 0
#define CONFIG_AV1_D3D11VA2_HWACCEL 0
#define CONFIG_AV1_D3D11VA_HWACCEL 0
#define CONFIG_AV1_DECODER 1
#define CONFIG_AV1_DEMUXER 1
#define CONFIG_AV1_DXVA2_HWACCEL 0
#define CONFIG_AV1_FRAME_MERGE_BSF 1
#define CONFIG_AV1_FRAME_SPLIT_BSF 1
#define CONFIG_AV1_METADATA_BSF 1
#define CONFIG_AV1_NVDEC_HWACCEL 0
#define CONFIG_AV1_PARSER 1
#define CONFIG_AV1_QSV_DECODER 0
#define CONFIG_AV1_VAAPI_HWACCEL 0
#define CONFIG_AVCODEC 1
#define CONFIG_AVDEVICE 1
#define CONFIG_AVECTORSCOPE_FILTER 1
#define CONFIG_AVFILTER 1
#define CONFIG_AVFORMAT 1
#define CONFIG_AVFOUNDATION 0
#define CONFIG_AVFOUNDATION_INDEV 0
#define CONFIG_AVGBLUR_FILTER 1
#define CONFIG_AVGBLUR_OPENCL_FILTER 0
#define CONFIG_AVGBLUR_VULKAN_FILTER 0
#define CONFIG_AVIO_LIST_DIR_EXAMPLE 1
#define CONFIG_AVIO_READING_EXAMPLE 1
#define CONFIG_AVISYNTH 0
#define CONFIG_AVISYNTH_DEMUXER 0
#define CONFIG_AVI_DEMUXER 1
#define CONFIG_AVI_MUXER 1
#define CONFIG_AVM2_MUXER 1
#define CONFIG_AVRN_DECODER 1
#define CONFIG_AVRP_DECODER 1
#define CONFIG_AVRP_ENCODER 1
#define CONFIG_AVR_DEMUXER 1
#define CONFIG_AVS2_DEMUXER 1
#define CONFIG_AVS2_MUXER 1
#define CONFIG_AVS2_PARSER 1
#define CONFIG_AVS3_DEMUXER 1
#define CONFIG_AVS3_PARSER 1
#define CONFIG_AVS_DECODER 1
#define CONFIG_AVS_DEMUXER 1
#define CONFIG_AVUI_DECODER 1
#define CONFIG_AVUI_ENCODER 1
#define CONFIG_AVUTIL 1
#define CONFIG_AXCORRELATE_FILTER 1
#define CONFIG_AYUV_DECODER 1
#define CONFIG_AYUV_ENCODER 1
#define CONFIG_AZMQ_FILTER 0
#define CONFIG_BANDPASS_FILTER 1
#define CONFIG_BANDREJECT_FILTER 1
#define CONFIG_BASS_FILTER 1
#define CONFIG_BBOX_FILTER 1
#define CONFIG_BENCH_FILTER 1
#define CONFIG_BETHSOFTVID_DECODER 1
#define CONFIG_BETHSOFTVID_DEMUXER 1
#define CONFIG_BFI_DECODER 1
#define CONFIG_BFI_DEMUXER 1
#define CONFIG_BFSTM_DEMUXER 1
#define CONFIG_BILATERAL_FILTER 1
#define CONFIG_BINKAUDIO_DCT_DECODER 1
#define CONFIG_BINKAUDIO_RDFT_DECODER 1
#define CONFIG_BINKA_DEMUXER 1
#define CONFIG_BINK_DECODER 1
#define CONFIG_BINK_DEMUXER 1
#define CONFIG_BINTEXT_DECODER 1
#define CONFIG_BINTEXT_DEMUXER 1
#define CONFIG_BIQUAD_FILTER 1
#define CONFIG_BITPACKED_DECODER 1
#define CONFIG_BITPLANENOISE_FILTER 1
#define CONFIG_BIT_DEMUXER 1
#define CONFIG_BIT_MUXER 1
#define CONFIG_BKTR_INDEV 0
#define CONFIG_BLACKDETECT_FILTER 1
#define CONFIG_BLACKFRAME_FILTER 0
#define CONFIG_BLEND_FILTER 1
#define CONFIG_BLOCKDSP 1
#define CONFIG_BLURAY_PROTOCOL 0
#define CONFIG_BM3D_FILTER 1
#define CONFIG_BMP_DECODER 1
#define CONFIG_BMP_ENCODER 1
#define CONFIG_BMP_PARSER 1
#define CONFIG_BMV_AUDIO_DECODER 1
#define CONFIG_BMV_DEMUXER 1
#define CONFIG_BMV_VIDEO_DECODER 1
#define CONFIG_BOA_DEMUXER 1
#define CONFIG_BOXBLUR_FILTER 0
#define CONFIG_BOXBLUR_OPENCL_FILTER 0
#define CONFIG_BRENDER_PIX_DECODER 1
#define CONFIG_BRSTM_DEMUXER 1
#define CONFIG_BS2B_FILTER 0
#define CONFIG_BSFS 1
#define CONFIG_BSWAPDSP 1
#define CONFIG_BWDIF_FILTER 1
#define CONFIG_BZLIB 0
#define CONFIG_C93_DECODER 1
#define CONFIG_C93_DEMUXER 1
#define CONFIG_CABAC 1
#define CONFIG_CACA_OUTDEV 0
#define CONFIG_CACHE_PROTOCOL 1
#define CONFIG_CAF_DEMUXER 1
#define CONFIG_CAF_MUXER 1
#define CONFIG_CAS_FILTER 1
#define CONFIG_CAVSVIDEO_DEMUXER 1
#define CONFIG_CAVSVIDEO_MUXER 1
#define CONFIG_CAVSVIDEO_PARSER 1
#define CONFIG_CAVS_DECODER 1
#define CONFIG_CBS 1
#define CONFIG_CBS_AV1 1
#define CONFIG_CBS_H264 1
#define CONFIG_CBS_H265 1
#define CONFIG_CBS_JPEG 0
#define CONFIG_CBS_MPEG2 1
#define CONFIG_CBS_VP9 1
#define CONFIG_CCAPTION_DECODER 1
#define CONFIG_CDGRAPHICS_DECODER 1
#define CONFIG_CDG_DEMUXER 1
#define CONFIG_CDTOONS_DECODER 1
#define CONFIG_CDXL_DECODER 1
#define CONFIG_CDXL_DEMUXER 1
#define CONFIG_CELLAUTO_FILTER 1
#define CONFIG_CFHD_DECODER 1
#define CONFIG_CFHD_ENCODER 1
#define CONFIG_CHANNELMAP_FILTER 1
#define CONFIG_CHANNELSPLIT_FILTER 1
#define CONFIG_CHOMP_BSF 1
#define CONFIG_CHORUS_FILTER 1
#define CONFIG_CHROMABER_VULKAN_FILTER 0
#define CONFIG_CHROMAHOLD_FILTER 1
#define CONFIG_CHROMAKEY_FILTER 1
#define CONFIG_CHROMANR_FILTER 1
#define CONFIG_CHROMAPRINT 0
#define CONFIG_CHROMAPRINT_MUXER 0
#define CONFIG_CHROMASHIFT_FILTER 1
#define CONFIG_CIESCOPE_FILTER 1
#define CONFIG_CINEPAK_DECODER 1
#define CONFIG_CINEPAK_ENCODER 1
#define CONFIG_CINE_DEMUXER 1
#define CONFIG_CLEARVIDEO_DECODER 1
#define CONFIG_CLJR_DECODER 1
#define CONFIG_CLJR_ENCODER 1
#define CONFIG_CLLC_DECODER 1
#define CONFIG_CODEC2RAW_DEMUXER 1
#define CONFIG_CODEC2RAW_MUXER 1
#define CONFIG_CODEC2_DEMUXER 1
#define CONFIG_CODEC2_MUXER 1
#define CONFIG_CODECVIEW_FILTER 1
#define CONFIG_COLORBALANCE_FILTER 1
#define CONFIG_COLORCHANNELMIXER_FILTER 1
#define CONFIG_COLORCONTRAST_FILTER 1
#define CONFIG_COLORCORRECT_FILTER 1
#define CONFIG_COLORHOLD_FILTER 1
#define CONFIG_COLORIZE_FILTER 1
#define CONFIG_COLORKEY_FILTER 1
#define CONFIG_COLORKEY_OPENCL_FILTER 0
#define CONFIG_COLORLEVELS_FILTER 1
#define CONFIG_COLORMATRIX_FILTER 0
#define CONFIG_COLORSPACE_FILTER 1
#define CONFIG_COLORTEMPERATURE_FILTER 1
#define CONFIG_COLOR_FILTER 1
#define CONFIG_COMFORTNOISE_DECODER 1
#define CONFIG_COMFORTNOISE_ENCODER 1
#define CONFIG_COMPAND_FILTER 1
#define CONFIG_COMPENSATIONDELAY_FILTER 1
#define CONFIG_CONCAT_DEMUXER 1
#define CONFIG_CONCAT_FILTER 1
#define CONFIG_CONCAT_PROTOCOL 1
#define CONFIG_CONVOLUTION_FILTER 1
#define CONFIG_CONVOLUTION_OPENCL_FILTER 0
#define CONFIG_CONVOLVE_FILTER 1
#define CONFIG_COOK_DECODER 1
#define CONFIG_COOK_PARSER 1
#define CONFIG_COPY_FILTER 1
#define CONFIG_COREIMAGE 0
#define CONFIG_COREIMAGESRC_FILTER 0
#define CONFIG_COREIMAGE_FILTER 0
#define CONFIG_COVER_RECT_FILTER 0
#define CONFIG_CPIA_DECODER 1
#define CONFIG_CRC_MUXER 1
#define CONFIG_CRI_DECODER 1
#define CONFIG_CRI_PARSER 1
#define CONFIG_CROPDETECT_FILTER 0
#define CONFIG_CROP_FILTER 1
#define CONFIG_CROSSFEED_FILTER 1
#define CONFIG_CRYPTO_PROTOCOL 1
#define CONFIG_CRYSTALHD 0
#define CONFIG_CRYSTALIZER_FILTER 1
#define CONFIG_CSCD_DECODER 1
#define CONFIG_CUDA 0
#define CONFIG_CUDA_LLVM 1
#define CONFIG_CUDA_NVCC 0
#define CONFIG_CUDA_SDK 0
#define CONFIG_CUE_FILTER 1
#define CONFIG_CURVES_FILTER 1
#define CONFIG_CUVID 0
#define CONFIG_CYUV_DECODER 1
#define CONFIG_D3D11VA 0
#define CONFIG_DASH_DEMUXER 0
#define CONFIG_DASH_MUXER 1
#define CONFIG_DATASCOPE_FILTER 1
#define CONFIG_DATA_DEMUXER 1
#define CONFIG_DATA_MUXER 1
#define CONFIG_DATA_PROTOCOL 1
#define CONFIG_DAUD_DEMUXER 1
#define CONFIG_DAUD_MUXER 1
#define CONFIG_DBLUR_FILTER 1
#define CONFIG_DCA_CORE_BSF 1
#define CONFIG_DCA_DECODER 1
#define CONFIG_DCA_ENCODER 1
#define CONFIG_DCA_PARSER 1
#define CONFIG_DCSHIFT_FILTER 1
#define CONFIG_DCSTR_DEMUXER 1
#define CONFIG_DCT 1
#define CONFIG_DCTDNOIZ_FILTER 1
#define CONFIG_DDS_DECODER 1
#define CONFIG_DEBAND_FILTER 1
#define CONFIG_DEBLOCK_FILTER 1
#define CONFIG_DECIMATE_FILTER 1
#define CONFIG_DECKLINK 0
#define CONFIG_DECKLINK_INDEV 0
#define CONFIG_DECKLINK_OUTDEV 0
#define CONFIG_DECODERS 1
#define CONFIG_DECODE_AUDIO_EXAMPLE 1
#define CONFIG_DECODE_VIDEO_EXAMPLE 1
#define CONFIG_DECONVOLVE_FILTER 1
#define CONFIG_DEDOT_FILTER 1
#define CONFIG_DEESSER_FILTER 1
#define CONFIG_DEFLATE_FILTER 1
#define CONFIG_DEFLICKER_FILTER 1
#define CONFIG_DEINTERLACE_QSV_FILTER 0
#define CONFIG_DEINTERLACE_VAAPI_FILTER 0
#define CONFIG_DEJUDDER_FILTER 1
#define CONFIG_DELOGO_FILTER 0
#define CONFIG_DEMUXERS 1
#define CONFIG_DEMUXING_DECODING_EXAMPLE 1
#define CONFIG_DENOISE_VAAPI_FILTER 0
#define CONFIG_DERAIN_FILTER 1
#define CONFIG_DERF_DEMUXER 1
#define CONFIG_DERF_DPCM_DECODER 1
#define CONFIG_DESHAKE_FILTER 1
#define CONFIG_DESHAKE_OPENCL_FILTER 0
#define CONFIG_DESPILL_FILTER 1
#define CONFIG_DETELECINE_FILTER 1
#define CONFIG_DFA_DECODER 1
#define CONFIG_DFA_DEMUXER 1
#define CONFIG_DHAV_DEMUXER 1
#define CONFIG_DILATION_FILTER 1
#define CONFIG_DILATION_OPENCL_FILTER 0
#define CONFIG_DIRAC_DECODER 1
#define CONFIG_DIRAC_DEMUXER 1
#define CONFIG_DIRAC_MUXER 1
#define CONFIG_DIRAC_PARSE 1
#define CONFIG_DIRAC_PARSER 1
#define CONFIG_DISPLACE_FILTER 1
#define CONFIG_DNN 1
#define CONFIG_DNN_CLASSIFY_FILTER 1
#define CONFIG_DNN_DETECT_FILTER 1
#define CONFIG_DNN_PROCESSING_FILTER 1
#define CONFIG_DNXHD_DECODER 1
#define CONFIG_DNXHD_DEMUXER 1
#define CONFIG_DNXHD_ENCODER 1
#define CONFIG_DNXHD_MUXER 1
#define CONFIG_DNXHD_PARSER 1
#define CONFIG_DOC 1
#define CONFIG_DOLBY_E_DECODER 1
#define CONFIG_DOLBY_E_PARSER 1
#define CONFIG_DOUBLEWEAVE_FILTER 1
#define CONFIG_DPX_DECODER 1
#define CONFIG_DPX_ENCODER 1
#define CONFIG_DPX_PARSER 1
#define CONFIG_DRAWBOX_FILTER 1
#define CONFIG_DRAWGRAPH_FILTER 1
#define CONFIG_DRAWGRID_FILTER 1
#define CONFIG_DRAWTEXT_FILTER 0
#define CONFIG_DRMETER_FILTER 1
#define CONFIG_DSD_LSBF_DECODER 1
#define CONFIG_DSD_LSBF_PLANAR_DECODER 1
#define CONFIG_DSD_MSBF_DECODER 1
#define CONFIG_DSD_MSBF_PLANAR_DECODER 1
#define CONFIG_DSF_DEMUXER 1
#define CONFIG_DSHOW_INDEV 0
#define CONFIG_DSICINAUDIO_DECODER 1
#define CONFIG_DSICINVIDEO_DECODER 1
#define CONFIG_DSICIN_DEMUXER 1
#define CONFIG_DSS_DEMUXER 1
#define CONFIG_DSS_SP_DECODER 1
#define CONFIG_DST_DECODER 1
#define CONFIG_DTSHD_DEMUXER 1
#define CONFIG_DTS_DEMUXER 1
#define CONFIG_DTS_MUXER 1
#define CONFIG_DUMP_EXTRADATA_BSF 1
#define CONFIG_DVAUDIO_DECODER 1
#define CONFIG_DVAUDIO_PARSER 1
#define CONFIG_DVBSUB_DECODER 1
#define CONFIG_DVBSUB_DEMUXER 1
#define CONFIG_DVBSUB_ENCODER 1
#define CONFIG_DVBSUB_PARSER 1
#define CONFIG_DVBTXT_DEMUXER 1
#define CONFIG_DVDSUB_DECODER 1
#define CONFIG_DVDSUB_ENCODER 1
#define CONFIG_DVDSUB_PARSER 1
#define CONFIG_DVD_NAV_PARSER 1
#define CONFIG_DVPROFILE 1
#define CONFIG_DVVIDEO_DECODER 1
#define CONFIG_DVVIDEO_ENCODER 1
#define CONFIG_DV_DEMUXER 1
#define CONFIG_DV_MUXER 1
#define CONFIG_DWT 1
#define CONFIG_DXA_DECODER 1
#define CONFIG_DXA_DEMUXER 1
#define CONFIG_DXTORY_DECODER 1
#define CONFIG_DXVA2 0
#define CONFIG_DXV_DECODER 1
#define CONFIG_DYNAUDNORM_FILTER 1
#define CONFIG_EAC3_AT_DECODER 0
#define CONFIG_EAC3_CORE_BSF 1
#define CONFIG_EAC3_DECODER 1
#define CONFIG_EAC3_DEMUXER 1
#define CONFIG_EAC3_ENCODER 1
#define CONFIG_EAC3_MUXER 1
#define CONFIG_EACMV_DECODER 1
#define CONFIG_EAMAD_DECODER 1
#define CONFIG_EARWAX_FILTER 1
#define CONFIG_EATGQ_DECODER 1
#define CONFIG_EATGV_DECODER 1
#define CONFIG_EATQI_DECODER 1
#define CONFIG_EA_CDATA_DEMUXER 1
#define CONFIG_EA_DEMUXER 1
#define CONFIG_EBUR128_FILTER 1
#define CONFIG_EDGEDETECT_FILTER 1
#define CONFIG_EIGHTBPS_DECODER 1
#define CONFIG_EIGHTSVX_EXP_DECODER 1
#define CONFIG_EIGHTSVX_FIB_DECODER 1
#define CONFIG_ELBG_FILTER 1
#define CONFIG_ENCODERS 1
#define CONFIG_ENCODE_AUDIO_EXAMPLE 1
#define CONFIG_ENCODE_VIDEO_EXAMPLE 1
#define CONFIG_ENTROPY_FILTER 1
#define CONFIG_EPAF_DEMUXER 1
#define CONFIG_EPX_FILTER 1
#define CONFIG_EQUALIZER_FILTER 1
#define CONFIG_EQ_FILTER 0
#define CONFIG_EROSION_FILTER 1
#define CONFIG_EROSION_OPENCL_FILTER 0
#define CONFIG_ERROR_RESILIENCE 1
#define CONFIG_ESCAPE124_DECODER 1
#define CONFIG_ESCAPE130_DECODER 1
#define CONFIG_ESTDIF_FILTER 1
#define CONFIG_EVRC_DECODER 1
#define CONFIG_EXIF 1
#define CONFIG_EXPOSURE_FILTER 1
#define CONFIG_EXR_DECODER 1
#define CONFIG_EXR_ENCODER 1
#define CONFIG_EXTRACTPLANES_FILTER 1
#define CONFIG_EXTRACT_EXTRADATA_BSF 1
#define CONFIG_EXTRACT_MVS_EXAMPLE 1
#define CONFIG_EXTRASTEREO_FILTER 1
#define CONFIG_F4V_MUXER 1
#define CONFIG_FAAN 1
#define CONFIG_FAANDCT 1
#define CONFIG_FAANIDCT 1
#define CONFIG_FADE_FILTER 1
#define CONFIG_FASTAUDIO_DECODER 1
#define CONFIG_FAST_UNALIGNED 1
#define CONFIG_FBDEV_INDEV 1
#define CONFIG_FBDEV_OUTDEV 1
#define CONFIG_FDCTDSP 1
#define CONFIG_FFMETADATA_DEMUXER 1
#define CONFIG_FFMETADATA_MUXER 1
#define CONFIG_FFMPEG 1
#define CONFIG_FFNVCODEC 0
#define CONFIG_FFPLAY 0
#define CONFIG_FFPROBE 1
#define CONFIG_FFRTMPCRYPT_PROTOCOL 0
#define CONFIG_FFRTMPHTTP_PROTOCOL 1
#define CONFIG_FFT 1
#define CONFIG_FFTDNOIZ_FILTER 1
#define CONFIG_FFTFILT_FILTER 1
#define CONFIG_FFV1_DECODER 1
#define CONFIG_FFV1_ENCODER 1
#define CONFIG_FFVHUFF_DECODER 1
#define CONFIG_FFVHUFF_ENCODER 1
#define CONFIG_FFWAVESYNTH_DECODER 1
#define CONFIG_FIC_DECODER 1
#define CONFIG_FIELDHINT_FILTER 1
#define CONFIG_FIELDMATCH_FILTER 1
#define CONFIG_FIELDORDER_FILTER 1
#define CONFIG_FIELD_FILTER 1
#define CONFIG_FIFO_FILTER 1
#define CONFIG_FIFO_MUXER 1
#define CONFIG_FIFO_TEST_MUXER 1
#define CONFIG_FILE_PROTOCOL 1
#define CONFIG_FILLBORDERS_FILTER 1
#define CONFIG_FILMSTRIP_DEMUXER 1
#define CONFIG_FILMSTRIP_MUXER 1
#define CONFIG_FILTERING_AUDIO_EXAMPLE 1
#define CONFIG_FILTERING_VIDEO_EXAMPLE 1
#define CONFIG_FILTERS 1
#define CONFIG_FILTER_AUDIO_EXAMPLE 1
#define CONFIG_FILTER_UNITS_BSF 1
#define CONFIG_FIND_RECT_FILTER 0
#define CONFIG_FIREQUALIZER_FILTER 1
#define CONFIG_FITS_DECODER 1
#define CONFIG_FITS_DEMUXER 1
#define CONFIG_FITS_ENCODER 1
#define CONFIG_FITS_MUXER 1
#define CONFIG_FLACDSP 1
#define CONFIG_FLAC_DECODER 1
#define CONFIG_FLAC_DEMUXER 1
#define CONFIG_FLAC_ENCODER 1
#define CONFIG_FLAC_MUXER 1
#define CONFIG_FLAC_PARSER 1
#define CONFIG_FLANGER_FILTER 1
#define CONFIG_FLASHSV2_DECODER 1
#define CONFIG_FLASHSV2_ENCODER 1
#define CONFIG_FLASHSV_DECODER 1
#define CONFIG_FLASHSV_ENCODER 1
#define CONFIG_FLIC_DECODER 1
#define CONFIG_FLIC_DEMUXER 1
#define CONFIG_FLITE_FILTER 0
#define CONFIG_FLOODFILL_FILTER 1
#define CONFIG_FLV_DECODER 1
#define CONFIG_FLV_DEMUXER 1
#define CONFIG_FLV_ENCODER 1
#define CONFIG_FLV_MUXER 1
#define CONFIG_FMTCONVERT 1
#define CONFIG_FMVC_DECODER 1
#define CONFIG_FONTCONFIG 0
#define CONFIG_FORMAT_FILTER 1
#define CONFIG_FOURXM_DECODER 1
#define CONFIG_FOURXM_DEMUXER 1
#define CONFIG_FPS_FILTER 1
#define CONFIG_FRAMECRC_MUXER 1
#define CONFIG_FRAMEHASH_MUXER 1
#define CONFIG_FRAMEMD5_MUXER 1
#define CONFIG_FRAMEPACK_FILTER 1
#define CONFIG_FRAMERATE_FILTER 1
#define CONFIG_FRAMESTEP_FILTER 1
#define CONFIG_FRAME_THREAD_ENCODER 1
#define CONFIG_FRAPS_DECODER 1
#define CONFIG_FREEZEDETECT_FILTER 1
#define CONFIG_FREEZEFRAMES_FILTER 1
#define CONFIG_FREI0R 0
#define CONFIG_FREI0R_FILTER 0
#define CONFIG_FREI0R_SRC_FILTER 0
#define CONFIG_FRM_DEMUXER 1
#define CONFIG_FRWU_DECODER 1
#define CONFIG_FSB_DEMUXER 1
#define CONFIG_FSPP_FILTER 0
#define CONFIG_FTP_PROTOCOL 1
#define CONFIG_FTRAPV 0
#define CONFIG_FWSE_DEMUXER 1
#define CONFIG_G2M_DECODER 1
#define CONFIG_G722DSP 1
#define CONFIG_G722_DEMUXER 1
#define CONFIG_G722_MUXER 1
#define CONFIG_G723_1_DECODER 1
#define CONFIG_G723_1_DEMUXER 1
#define CONFIG_G723_1_ENCODER 1
#define CONFIG_G723_1_MUXER 1
#define CONFIG_G723_1_PARSER 1
#define CONFIG_G726LE_DEMUXER 1
#define CONFIG_G726LE_MUXER 1
#define CONFIG_G726_DEMUXER 1
#define CONFIG_G726_MUXER 1
#define CONFIG_G729_DECODER 1
#define CONFIG_G729_DEMUXER 1
#define CONFIG_G729_PARSER 1
#define CONFIG_GBLUR_FILTER 1
#define CONFIG_GCRYPT 0
#define CONFIG_GDIGRAB_INDEV 0
#define CONFIG_GDV_DECODER 1
#define CONFIG_GDV_DEMUXER 1
#define CONFIG_GENH_DEMUXER 1
#define CONFIG_GEQ_FILTER 1
#define CONFIG_GIF_DECODER 1
#define CONFIG_GIF_DEMUXER 1
#define CONFIG_GIF_ENCODER 1
#define CONFIG_GIF_MUXER 1
#define CONFIG_GIF_PARSER 1
#define CONFIG_GMP 0
#define CONFIG_GNUTLS 0
#define CONFIG_GOLOMB 1
#define CONFIG_GOPHERS_PROTOCOL 0
#define CONFIG_GOPHER_PROTOCOL 1
#define CONFIG_GPL 0
#define CONFIG_GPLV3 0
#define CONFIG_GRADFUN_FILTER 1
#define CONFIG_GRADIENTS_FILTER 1
#define CONFIG_GRAPHMONITOR_FILTER 1
#define CONFIG_GRAY 0
#define CONFIG_GREMLIN_DPCM_DECODER 1
#define CONFIG_GREYEDGE_FILTER 1
#define CONFIG_GSM_DECODER 1
#define CONFIG_GSM_DEMUXER 1
#define CONFIG_GSM_MS_AT_DECODER 0
#define CONFIG_GSM_MS_DECODER 1
#define CONFIG_GSM_MUXER 1
#define CONFIG_GSM_PARSER 1
#define CONFIG_GUIDED_FILTER 1
#define CONFIG_GXF_DEMUXER 1
#define CONFIG_GXF_MUXER 1
#define CONFIG_H261_DECODER 1
#define CONFIG_H261_DEMUXER 1
#define CONFIG_H261_ENCODER 1
#define CONFIG_H261_MUXER 1
#define CONFIG_H261_PARSER 1
#define CONFIG_H263DSP 1
#define CONFIG_H263I_DECODER 1
#define CONFIG_H263P_DECODER 1
#define CONFIG_H263P_ENCODER 1
#define CONFIG_H263_DECODER 1
#define CONFIG_H263_DEMUXER 1
#define CONFIG_H263_ENCODER 1
#define CONFIG_H263_MUXER 1
#define CONFIG_H263_PARSER 1
#define CONFIG_H263_V4L2M2M_DECODER 1
#define CONFIG_H263_V4L2M2M_ENCODER 1
#define CONFIG_H263_VAAPI_HWACCEL 0
#define CONFIG_H263_VIDEOTOOLBOX_HWACCEL 0
#define CONFIG_H264CHROMA 1
#define CONFIG_H264DSP 1
#define CONFIG_H264PARSE 1
#define CONFIG_H264PRED 1
#define CONFIG_H264QPEL 1
#define CONFIG_H264_AMF_ENCODER 0
#define CONFIG_H264_CRYSTALHD_DECODER 0
#define CONFIG_H264_CUVID_DECODER 0
#define CONFIG_H264_D3D11VA2_HWACCEL 0
#define CONFIG_H264_D3D11VA_HWACCEL 0
#define CONFIG_H264_DECODER 1
#define CONFIG_H264_DEMUXER 1
#define CONFIG_H264_DXVA2_HWACCEL 0
#define CONFIG_H264_MEDIACODEC_DECODER 0
#define CONFIG_H264_METADATA_BSF 1
#define CONFIG_H264_MF_ENCODER 0
#define CONFIG_H264_MMAL_DECODER 0
#define CONFIG_H264_MP4TOANNEXB_BSF 1
#define CONFIG_H264_MUXER 1
#define CONFIG_H264_NVDEC_HWACCEL 0
#define CONFIG_H264_NVENC_ENCODER 0
#define CONFIG_H264_OMX_ENCODER 0
#define CONFIG_H264_PARSER 1
#define CONFIG_H264_QSV_DECODER 0
#define CONFIG_H264_QSV_ENCODER 0
#define CONFIG_H264_REDUNDANT_PPS_BSF 1
#define CONFIG_H264_RKMPP_DECODER 0
#define CONFIG_H264_V4L2M2M_DECODER 1
#define CONFIG_H264_V4L2M2M_ENCODER 1
#define CONFIG_H264_VAAPI_ENCODER 0
#define CONFIG_H264_VAAPI_HWACCEL 0
#define CONFIG_H264_VDPAU_HWACCEL 1
#define CONFIG_H264_VIDEOTOOLBOX_ENCODER 0
#define CONFIG_H264_VIDEOTOOLBOX_HWACCEL 0
#define CONFIG_HAAS_FILTER 1
#define CONFIG_HALDCLUTSRC_FILTER 1
#define CONFIG_HALDCLUT_FILTER 1
#define CONFIG_HAPQA_EXTRACT_BSF 1
#define CONFIG_HAP_DECODER 1
#define CONFIG_HAP_ENCODER 0
#define CONFIG_HARDCODED_TABLES 0
#define CONFIG_HASH_MUXER 1
#define CONFIG_HCA_DECODER 1
#define CONFIG_HCA_DEMUXER 1
#define CONFIG_HCOM_DECODER 1
#define CONFIG_HCOM_DEMUXER 1
#define CONFIG_HDCD_FILTER 1
#define CONFIG_HDS_MUXER 1
#define CONFIG_HEADPHONE_FILTER 1
#define CONFIG_HEVCPARSE 1
#define CONFIG_HEVC_AMF_ENCODER 0
#define CONFIG_HEVC_CUVID_DECODER 0
#define CONFIG_HEVC_D3D11VA2_HWACCEL 0
#define CONFIG_HEVC_D3D11VA_HWACCEL 0
#define CONFIG_HEVC_DECODER 1
#define CONFIG_HEVC_DEMUXER 1
#define CONFIG_HEVC_DXVA2_HWACCEL 0
#define CONFIG_HEVC_MEDIACODEC_DECODER 0
#define CONFIG_HEVC_METADATA_BSF 1
#define CONFIG_HEVC_MF_ENCODER 0
#define CONFIG_HEVC_MP4TOANNEXB_BSF 1
#define CONFIG_HEVC_MUXER 1
#define CONFIG_HEVC_NVDEC_HWACCEL 0
#define CONFIG_HEVC_NVENC_ENCODER 0
#define CONFIG_HEVC_PARSER 1
#define CONFIG_HEVC_QSV_DECODER 0
#define CONFIG_HEVC_QSV_ENCODER 0
#define CONFIG_HEVC_RKMPP_DECODER 0
#define CONFIG_HEVC_V4L2M2M_DECODER 1
#define CONFIG_HEVC_V4L2M2M_ENCODER 1
#define CONFIG_HEVC_VAAPI_ENCODER 0
#define CONFIG_HEVC_VAAPI_HWACCEL 0
#define CONFIG_HEVC_VDPAU_HWACCEL 1
#define CONFIG_HEVC_VIDEOTOOLBOX_ENCODER 0
#define CONFIG_HEVC_VIDEOTOOLBOX_HWACCEL 0
#define CONFIG_HFLIP_FILTER 1
#define CONFIG_HIGHPASS_FILTER 1
#define CONFIG_HIGHSHELF_FILTER 1
#define CONFIG_HILBERT_FILTER 1
#define CONFIG_HISTEQ_FILTER 0
#define CONFIG_HISTOGRAM_FILTER 1
#define CONFIG_HLS_DEMUXER 1
#define CONFIG_HLS_MUXER 1
#define CONFIG_HLS_PROTOCOL 1
#define CONFIG_HNM4_VIDEO_DECODER 1
#define CONFIG_HNM_DEMUXER 1
#define CONFIG_HPELDSP 1
#define CONFIG_HQDN3D_FILTER 0
#define CONFIG_HQX_DECODER 1
#define CONFIG_HQX_FILTER 1
#define CONFIG_HQ_HQA_DECODER 1
#define CONFIG_HSTACK_FILTER 1
#define CONFIG_HTMLPAGES 0
#define CONFIG_HTTPPROXY_PROTOCOL 1
#define CONFIG_HTTPS_PROTOCOL 0
#define CONFIG_HTTP_MULTICLIENT_EXAMPLE 1
#define CONFIG_HTTP_PROTOCOL 1
#define CONFIG_HUE_FILTER 1
#define CONFIG_HUFFMAN 1
#define CONFIG_HUFFYUVDSP 1
#define CONFIG_HUFFYUVENCDSP 1
#define CONFIG_HUFFYUV_DECODER 1
#define CONFIG_HUFFYUV_ENCODER 1
#define CONFIG_HWACCELS 1
#define CONFIG_HWDOWNLOAD_FILTER 1
#define CONFIG_HWMAP_FILTER 1
#define CONFIG_HWUPLOAD_CUDA_FILTER 0
#define CONFIG_HWUPLOAD_FILTER 1
#define CONFIG_HW_DECODE_EXAMPLE 1
#define CONFIG_HYMT_DECODER 1
#define CONFIG_HYSTERESIS_FILTER 1
#define CONFIG_IAC_DECODER 1
#define CONFIG_ICECAST_PROTOCOL 1
#define CONFIG_ICONV 1
#define CONFIG_ICO_DEMUXER 1
#define CONFIG_ICO_MUXER 1
#define CONFIG_IDCIN_DECODER 1
#define CONFIG_IDCIN_DEMUXER 1
#define CONFIG_IDCTDSP 1
#define CONFIG_IDENTITY_FILTER 1
#define CONFIG_IDET_FILTER 1
#define CONFIG_IDF_DECODER 1
#define CONFIG_IDF_DEMUXER 1
#define CONFIG_IEC61883_INDEV 0
#define CONFIG_IFF_DEMUXER 1
#define CONFIG_IFF_ILBM_DECODER 1
#define CONFIG_IFV_DEMUXER 1
#define CONFIG_IIRFILTER 1
#define CONFIG_ILBC_AT_DECODER 0
#define CONFIG_ILBC_AT_ENCODER 0
#define CONFIG_ILBC_DECODER 1
#define CONFIG_ILBC_DEMUXER 1
#define CONFIG_ILBC_MUXER 1
#define CONFIG_IL_FILTER 1
#define CONFIG_IMAGE2PIPE_DEMUXER 1
#define CONFIG_IMAGE2PIPE_MUXER 1
#define CONFIG_IMAGE2_ALIAS_PIX_DEMUXER 1
#define CONFIG_IMAGE2_BRENDER_PIX_DEMUXER 1
#define CONFIG_IMAGE2_DEMUXER 1
#define CONFIG_IMAGE2_MUXER 1
#define CONFIG_IMAGE_BMP_PIPE_DEMUXER 1
#define CONFIG_IMAGE_CRI_PIPE_DEMUXER 1
#define CONFIG_IMAGE_DDS_PIPE_DEMUXER 1
#define CONFIG_IMAGE_DPX_PIPE_DEMUXER 1
#define CONFIG_IMAGE_EXR_PIPE_DEMUXER 1
#define CONFIG_IMAGE_GIF_PIPE_DEMUXER 1
#define CONFIG_IMAGE_J2K_PIPE_DEMUXER 1
#define CONFIG_IMAGE_JPEGLS_PIPE_DEMUXER 1
#define CONFIG_IMAGE_JPEG_PIPE_DEMUXER 1
#define CONFIG_IMAGE_PAM_PIPE_DEMUXER 1
#define CONFIG_IMAGE_PBM_PIPE_DEMUXER 1
#define CONFIG_IMAGE_PCX_PIPE_DEMUXER 1
#define CONFIG_IMAGE_PGMYUV_PIPE_DEMUXER 1
#define CONFIG_IMAGE_PGM_PIPE_DEMUXER 1
#define CONFIG_IMAGE_PGX_PIPE_DEMUXER 1
#define CONFIG_IMAGE_PHOTOCD_PIPE_DEMUXER 1
#define CONFIG_IMAGE_PICTOR_PIPE_DEMUXER 1
#define CONFIG_IMAGE_PNG_PIPE_DEMUXER 1
#define CONFIG_IMAGE_PPM_PIPE_DEMUXER 1
#define CONFIG_IMAGE_PSD_PIPE_DEMUXER 1
#define CONFIG_IMAGE_QDRAW_PIPE_DEMUXER 1
#define CONFIG_IMAGE_SGI_PIPE_DEMUXER 1
#define CONFIG_IMAGE_SUNRAST_PIPE_DEMUXER 1
#define CONFIG_IMAGE_SVG_PIPE_DEMUXER 1
#define CONFIG_IMAGE_TIFF_PIPE_DEMUXER 1
#define CONFIG_IMAGE_WEBP_PIPE_DEMUXER 1
#define CONFIG_IMAGE_XBM_PIPE_DEMUXER 1
#define CONFIG_IMAGE_XPM_PIPE_DEMUXER 1
#define CONFIG_IMAGE_XWD_PIPE_DEMUXER 1
#define CONFIG_IMC_DECODER 1
#define CONFIG_IMM4_DECODER 1
#define CONFIG_IMM5_DECODER 1
#define CONFIG_IMX_DUMP_HEADER_BSF 1
#define CONFIG_INDEO2_DECODER 1
#define CONFIG_INDEO3_DECODER 1
#define CONFIG_INDEO4_DECODER 1
#define CONFIG_INDEO5_DECODER 1
#define CONFIG_INDEVS 1
#define CONFIG_INFLATE_FILTER 1
#define CONFIG_INGENIENT_DEMUXER 1
#define CONFIG_INTERLACE_FILTER 0
#define CONFIG_INTERLEAVE_FILTER 1
#define CONFIG_INTERPLAY_ACM_DECODER 1
#define CONFIG_INTERPLAY_DPCM_DECODER 1
#define CONFIG_INTERPLAY_VIDEO_DECODER 1
#define CONFIG_INTRAX8 1
#define CONFIG_IPMOVIE_DEMUXER 1
#define CONFIG_IPOD_MUXER 1
#define CONFIG_IPU_DECODER 1
#define CONFIG_IPU_DEMUXER 1
#define CONFIG_IPU_PARSER 1
#define CONFIG_IRCAM_DEMUXER 1
#define CONFIG_IRCAM_MUXER 1
#define CONFIG_ISMV_MUXER 1
#define CONFIG_ISO_MEDIA 1
#define CONFIG_ISS_DEMUXER 1
#define CONFIG_IV8_DEMUXER 1
#define CONFIG_IVF_DEMUXER 1
#define CONFIG_IVF_MUXER 1
#define CONFIG_IVIDSP 1
#define CONFIG_IVR_DEMUXER 1
#define CONFIG_JACK_INDEV 0
#define CONFIG_JACOSUB_DECODER 1
#define CONFIG_JACOSUB_DEMUXER 1
#define CONFIG_JACOSUB_MUXER 1
#define CONFIG_JNI 0
#define CONFIG_JOIN_FILTER 1
#define CONFIG_JPEG2000_DECODER 1
#define CONFIG_JPEG2000_ENCODER 1
#define CONFIG_JPEG2000_PARSER 1
#define CONFIG_JPEGLS_DECODER 1
#define CONFIG_JPEGLS_ENCODER 1
#define CONFIG_JPEGTABLES 1
#define CONFIG_JV_DECODER 1
#define CONFIG_JV_DEMUXER 1
#define CONFIG_KERNDEINT_FILTER 0
#define CONFIG_KGV1_DECODER 1
#define CONFIG_KIRSCH_FILTER 1
#define CONFIG_KMSGRAB_INDEV 0
#define CONFIG_KMVC_DECODER 1
#define CONFIG_KUX_DEMUXER 1
#define CONFIG_KVAG_DEMUXER 1
#define CONFIG_KVAG_MUXER 1
#define CONFIG_LADSPA 0
#define CONFIG_LADSPA_FILTER 0
#define CONFIG_LAGARITH_DECODER 1
#define CONFIG_LAGFUN_FILTER 1
#define CONFIG_LARGE_TESTS 1
#define CONFIG_LATM_MUXER 1
#define CONFIG_LAVFI_INDEV 1
#define CONFIG_LENSCORRECTION_FILTER 1
#define CONFIG_LENSFUN_FILTER 0
#define CONFIG_LGPLV3 0
#define CONFIG_LIBAMQP_PROTOCOL 0
#define CONFIG_LIBAOM 0
#define CONFIG_LIBAOM_AV1_DECODER 0
#define CONFIG_LIBAOM_AV1_ENCODER 0
#define CONFIG_LIBARIBB24 0
#define CONFIG_LIBARIBB24_DECODER 0
#define CONFIG_LIBASS 0
#define CONFIG_LIBBLURAY 0
#define CONFIG_LIBBS2B 0
#define CONFIG_LIBCACA 0
#define CONFIG_LIBCDIO 0
#define CONFIG_LIBCDIO_INDEV 0
#define CONFIG_LIBCELT 0
#define CONFIG_LIBCELT_DECODER 0
#define CONFIG_LIBCODEC2 0
#define CONFIG_LIBCODEC2_DECODER 0
#define CONFIG_LIBCODEC2_ENCODER 0
#define CONFIG_LIBDAV1D 0
#define CONFIG_LIBDAV1D_DECODER 0
#define CONFIG_LIBDAVS2 0
#define CONFIG_LIBDAVS2_DECODER 0
#define CONFIG_LIBDC1394 0
#define CONFIG_LIBDC1394_INDEV 0
#define CONFIG_LIBDRM 0
#define CONFIG_LIBFDK_AAC 0
#define CONFIG_LIBFDK_AAC_DECODER 0
#define CONFIG_LIBFDK_AAC_ENCODER 0
#define CONFIG_LIBFLITE 0
#define CONFIG_LIBFONTCONFIG 0
#define CONFIG_LIBFREETYPE 0
#define CONFIG_LIBFRIBIDI 0
#define CONFIG_LIBGLSLANG 0
#define CONFIG_LIBGME 0
#define CONFIG_LIBGME_DEMUXER 0
#define CONFIG_LIBGSM 0
#define CONFIG_LIBGSM_DECODER 0
#define CONFIG_LIBGSM_ENCODER 0
#define CONFIG_LIBGSM_MS_DECODER 0
#define CONFIG_LIBGSM_MS_ENCODER 0
#define CONFIG_LIBIEC61883 0
#define CONFIG_LIBILBC 0
#define CONFIG_LIBILBC_DECODER 0
#define CONFIG_LIBILBC_ENCODER 0
#define CONFIG_LIBJACK 0
#define CONFIG_LIBKLVANC 0
#define CONFIG_LIBKVAZAAR 0
#define CONFIG_LIBKVAZAAR_ENCODER 0
#define CONFIG_LIBLENSFUN 0
#define CONFIG_LIBMFX 0
#define CONFIG_LIBMODPLUG 0
#define CONFIG_LIBMODPLUG_DEMUXER 0
#define CONFIG_LIBMP3LAME 0
#define CONFIG_LIBMP3LAME_ENCODER 0
#define CONFIG_LIBMYSOFA 0
#define CONFIG_LIBNPP 0
#define CONFIG_LIBOPENCORE_AMRNB 0
#define CONFIG_LIBOPENCORE_AMRNB_DECODER 0
#define CONFIG_LIBOPENCORE_AMRNB_ENCODER 0
#define CONFIG_LIBOPENCORE_AMRWB 0
#define CONFIG_LIBOPENCORE_AMRWB_DECODER 0
#define CONFIG_LIBOPENCV 0
#define CONFIG_LIBOPENH264 0
#define CONFIG_LIBOPENH264_DECODER 0
#define CONFIG_LIBOPENH264_ENCODER 0
#define CONFIG_LIBOPENJPEG 0
#define CONFIG_LIBOPENJPEG_DECODER 0
#define CONFIG_LIBOPENJPEG_ENCODER 0
#define CONFIG_LIBOPENMPT 0
#define CONFIG_LIBOPENMPT_DEMUXER 0
#define CONFIG_LIBOPENVINO 0
#define CONFIG_LIBOPUS 0
#define CONFIG_LIBOPUS_DECODER 0
#define CONFIG_LIBOPUS_ENCODER 0
#define CONFIG_LIBPULSE 0
#define CONFIG_LIBRABBITMQ 0
#define CONFIG_LIBRAV1E 0
#define CONFIG_LIBRAV1E_ENCODER 0
#define CONFIG_LIBRIST 0
#define CONFIG_LIBRIST_PROTOCOL 0
#define CONFIG_LIBRSVG 0
#define CONFIG_LIBRSVG_DECODER 0
#define CONFIG_LIBRTMP 0
#define CONFIG_LIBRTMPE_PROTOCOL 0
#define CONFIG_LIBRTMPS_PROTOCOL 0
#define CONFIG_LIBRTMPTE_PROTOCOL 0
#define CONFIG_LIBRTMPT_PROTOCOL 0
#define CONFIG_LIBRTMP_PROTOCOL 0
#define CONFIG_LIBRUBBERBAND 0
#define CONFIG_LIBSHINE 0
#define CONFIG_LIBSHINE_ENCODER 0
#define CONFIG_LIBSMBCLIENT 0
#define CONFIG_LIBSMBCLIENT_PROTOCOL 0
#define CONFIG_LIBSNAPPY 0
#define CONFIG_LIBSOXR 0
#define CONFIG_LIBSPEEX 0
#define CONFIG_LIBSPEEX_DECODER 0
#define CONFIG_LIBSPEEX_ENCODER 0
#define CONFIG_LIBSRT 0
#define CONFIG_LIBSRT_PROTOCOL 0
#define CONFIG_LIBSSH 0
#define CONFIG_LIBSSH_PROTOCOL 0
#define CONFIG_LIBSVTAV1 0
#define CONFIG_LIBSVTAV1_ENCODER 0
#define CONFIG_LIBTENSORFLOW 0
#define CONFIG_LIBTESSERACT 0
#define CONFIG_LIBTHEORA 0
#define CONFIG_LIBTHEORA_ENCODER 0
#define CONFIG_LIBTLS 0
#define CONFIG_LIBTWOLAME 0
#define CONFIG_LIBTWOLAME_ENCODER 0
#define CONFIG_LIBUAVS3D 0
#define CONFIG_LIBUAVS3D_DECODER 0
#define CONFIG_LIBV4L2 0
#define CONFIG_LIBVIDSTAB 0
#define CONFIG_LIBVMAF 0
#define CONFIG_LIBVMAF_FILTER 0
#define CONFIG_LIBVORBIS 0
#define CONFIG_LIBVORBIS_DECODER 0
#define CONFIG_LIBVORBIS_ENCODER 0
#define CONFIG_LIBVO_AMRWBENC 0
#define CONFIG_LIBVO_AMRWBENC_ENCODER 0
#define CONFIG_LIBVPX 0
#define CONFIG_LIBVPX_VP8_DECODER 0
#define CONFIG_LIBVPX_VP8_ENCODER 0
#define CONFIG_LIBVPX_VP9_DECODER 0
#define CONFIG_LIBVPX_VP9_ENCODER 0
#define CONFIG_LIBWEBP 0
#define CONFIG_LIBWEBP_ANIM_ENCODER 0
#define CONFIG_LIBWEBP_ENCODER 0
#define CONFIG_LIBX262 0
#define CONFIG_LIBX262_ENCODER 0
#define CONFIG_LIBX264 0
#define CONFIG_LIBX264RGB_ENCODER 0
#define CONFIG_LIBX264_ENCODER 0
#define CONFIG_LIBX265 0
#define CONFIG_LIBX265_ENCODER 0
#define CONFIG_LIBXAVS 0
#define CONFIG_LIBXAVS2 0
#define CONFIG_LIBXAVS2_ENCODER 0
#define CONFIG_LIBXAVS_ENCODER 0
#define CONFIG_LIBXCB 1
#define CONFIG_LIBXCB_SHAPE 0
#define CONFIG_LIBXCB_SHM 0
#define CONFIG_LIBXCB_XFIXES 0
#define CONFIG_LIBXML2 0
#define CONFIG_LIBXVID 0
#define CONFIG_LIBXVID_ENCODER 0
#define CONFIG_LIBZIMG 0
#define CONFIG_LIBZMQ 0
#define CONFIG_LIBZMQ_PROTOCOL 0
#define CONFIG_LIBZVBI 0
#define CONFIG_LIBZVBI_TELETEXT_DECODER 0
#define CONFIG_LIFE_FILTER 1
#define CONFIG_LIMITER_FILTER 1
#define CONFIG_LINUX_PERF 0
#define CONFIG_LIVE_FLV_DEMUXER 1
#define CONFIG_LJPEG_ENCODER 1
#define CONFIG_LLAUDDSP 1
#define CONFIG_LLVIDDSP 1
#define CONFIG_LLVIDENCDSP 1
#define CONFIG_LMLM4_DEMUXER 1
#define CONFIG_LOAS_DEMUXER 1
#define CONFIG_LOCO_DECODER 1
#define CONFIG_LOOP_FILTER 1
#define CONFIG_LOUDNORM_FILTER 1
#define CONFIG_LOWPASS_FILTER 1
#define CONFIG_LOWSHELF_FILTER 1
#define CONFIG_LPC 1
#define CONFIG_LRC_DEMUXER 1
#define CONFIG_LRC_MUXER 1
#define CONFIG_LSCR_DECODER 1
#define CONFIG_LSP 1
#define CONFIG_LUMAKEY_FILTER 1
#define CONFIG_LUODAT_DEMUXER 1
#define CONFIG_LUT1D_FILTER 1
#define CONFIG_LUT2_FILTER 1
#define CONFIG_LUT3D_FILTER 1
#define CONFIG_LUTRGB_FILTER 1
#define CONFIG_LUTYUV_FILTER 1
#define CONFIG_LUT_FILTER 1
#define CONFIG_LV2 0
#define CONFIG_LV2_FILTER 0
#define CONFIG_LVF_DEMUXER 1
#define CONFIG_LXF_DEMUXER 1
#define CONFIG_LZF 1
#define CONFIG_LZMA 0
#define CONFIG_LZO 1
#define CONFIG_M101_DECODER 1
#define CONFIG_M4V_DEMUXER 1
#define CONFIG_M4V_MUXER 1
#define CONFIG_MACE3_DECODER 1
#define CONFIG_MACE6_DECODER 1
#define CONFIG_MAGICYUV_DECODER 1
#define CONFIG_MAGICYUV_ENCODER 1
#define CONFIG_MANDELBROT_FILTER 1
#define CONFIG_MANPAGES 1
#define CONFIG_MASKEDCLAMP_FILTER 1
#define CONFIG_MASKEDMAX_FILTER 1
#define CONFIG_MASKEDMERGE_FILTER 1
#define CONFIG_MASKEDMIN_FILTER 1
#define CONFIG_MASKEDTHRESHOLD_FILTER 1
#define CONFIG_MASKFUN_FILTER 1
#define CONFIG_MATROSKA_AUDIO_MUXER 1
#define CONFIG_MATROSKA_DEMUXER 1
#define CONFIG_MATROSKA_MUXER 1
#define CONFIG_MBEDTLS 0
#define CONFIG_MCA_DEMUXER 1
#define CONFIG_MCC_DEMUXER 1
#define CONFIG_MCDEINT_FILTER 0
#define CONFIG_MCOMPAND_FILTER 1
#define CONFIG_MD5_MUXER 1
#define CONFIG_MD5_PROTOCOL 1
#define CONFIG_MDCT 1
#define CONFIG_MDCT15 1
#define CONFIG_MDEC_DECODER 1
#define CONFIG_MEDIACODEC 0
#define CONFIG_MEDIAFOUNDATION 0
#define CONFIG_MEDIAN_FILTER 1
#define CONFIG_MEMORY_POISONING 0
#define CONFIG_MERGEPLANES_FILTER 1
#define CONFIG_MESTIMATE_FILTER 1
#define CONFIG_METADATA_EXAMPLE 1
#define CONFIG_METADATA_FILTER 1
#define CONFIG_METASOUND_DECODER 1
#define CONFIG_ME_CMP 1
#define CONFIG_MGSTS_DEMUXER 1
#define CONFIG_MICRODVD_DECODER 1
#define CONFIG_MICRODVD_DEMUXER 1
#define CONFIG_MICRODVD_MUXER 1
#define CONFIG_MIDEQUALIZER_FILTER 1
#define CONFIG_MIMIC_DECODER 1
#define CONFIG_MINTERPOLATE_FILTER 1
#define CONFIG_MIX_FILTER 1
#define CONFIG_MJPEG2JPEG_BSF 1
#define CONFIG_MJPEGA_DUMP_HEADER_BSF 1
#define CONFIG_MJPEGB_DECODER 1
#define CONFIG_MJPEG_2000_DEMUXER 1
#define CONFIG_MJPEG_CUVID_DECODER 0
#define CONFIG_MJPEG_DECODER 1
#define CONFIG_MJPEG_DEMUXER 1
#define CONFIG_MJPEG_ENCODER 1
#define CONFIG_MJPEG_MUXER 1
#define CONFIG_MJPEG_NVDEC_HWACCEL 0
#define CONFIG_MJPEG_PARSER 1
#define CONFIG_MJPEG_QSV_DECODER 0
#define CONFIG_MJPEG_QSV_ENCODER 0
#define CONFIG_MJPEG_VAAPI_ENCODER 0
#define CONFIG_MJPEG_VAAPI_HWACCEL 0
#define CONFIG_MKVTIMESTAMP_V2_MUXER 1
#define CONFIG_MLP_DECODER 1
#define CONFIG_MLP_DEMUXER 1
#define CONFIG_MLP_ENCODER 1
#define CONFIG_MLP_MUXER 1
#define CONFIG_MLP_PARSER 1
#define CONFIG_MLV_DEMUXER 1
#define CONFIG_MMAL 0
#define CONFIG_MMF_DEMUXER 1
#define CONFIG_MMF_MUXER 1
#define CONFIG_MMSH_PROTOCOL 1
#define CONFIG_MMST_PROTOCOL 1
#define CONFIG_MMVIDEO_DECODER 1
#define CONFIG_MM_DEMUXER 1
#define CONFIG_MOBICLIP_DECODER 1
#define CONFIG_MODS_DEMUXER 1
#define CONFIG_MOFLEX_DEMUXER 1
#define CONFIG_MONOCHROME_FILTER 1
#define CONFIG_MOTIONPIXELS_DECODER 1
#define CONFIG_MOV2TEXTSUB_BSF 1
#define CONFIG_MOVIE_FILTER 1
#define CONFIG_MOVTEXT_DECODER 1
#define CONFIG_MOVTEXT_ENCODER 1
#define CONFIG_MOV_DEMUXER 1
#define CONFIG_MOV_MUXER 1
#define CONFIG_MP1FLOAT_DECODER 1
#define CONFIG_MP1_AT_DECODER 0
#define CONFIG_MP1_DECODER 1
#define CONFIG_MP2FIXED_ENCODER 1
#define CONFIG_MP2FLOAT_DECODER 1
#define CONFIG_MP2_AT_DECODER 0
#define CONFIG_MP2_DECODER 1
#define CONFIG_MP2_ENCODER 1
#define CONFIG_MP2_MUXER 1
#define CONFIG_MP3ADUFLOAT_DECODER 1
#define CONFIG_MP3ADU_DECODER 1
#define CONFIG_MP3FLOAT_DECODER 1
#define CONFIG_MP3ON4FLOAT_DECODER 1
#define CONFIG_MP3ON4_DECODER 1
#define CONFIG_MP3_AT_DECODER 0
#define CONFIG_MP3_DECODER 1
#define CONFIG_MP3_DEMUXER 1
#define CONFIG_MP3_HEADER_DECOMPRESS_BSF 1
#define CONFIG_MP3_MF_ENCODER 0
#define CONFIG_MP3_MUXER 1
#define CONFIG_MP4_MUXER 1
#define CONFIG_MPC7_DECODER 1
#define CONFIG_MPC8_DECODER 1
#define CONFIG_MPC8_DEMUXER 1
#define CONFIG_MPC_DEMUXER 1
#define CONFIG_MPDECIMATE_FILTER 0
#define CONFIG_MPEG1SYSTEM_MUXER 1
#define CONFIG_MPEG1VCD_MUXER 1
#define CONFIG_MPEG1VIDEO_DECODER 1
#define CONFIG_MPEG1VIDEO_ENCODER 1
#define CONFIG_MPEG1VIDEO_MUXER 1
#define CONFIG_MPEG1_CUVID_DECODER 0
#define CONFIG_MPEG1_NVDEC_HWACCEL 0
#define CONFIG_MPEG1_V4L2M2M_DECODER 1
#define CONFIG_MPEG1_VDPAU_HWACCEL 1
#define CONFIG_MPEG1_VIDEOTOOLBOX_HWACCEL 0
#define CONFIG_MPEG1_XVMC_HWACCEL 0
#define CONFIG_MPEG2DVD_MUXER 1
#define CONFIG_MPEG2SVCD_MUXER 1
#define CONFIG_MPEG2VIDEO_DECODER 1
#define CONFIG_MPEG2VIDEO_ENCODER 1
#define CONFIG_MPEG2VIDEO_MUXER 1
#define CONFIG_MPEG2VOB_MUXER 1
#define CONFIG_MPEG2_CRYSTALHD_DECODER 0
#define CONFIG_MPEG2_CUVID_DECODER 0
#define CONFIG_MPEG2_D3D11VA2_HWACCEL 0
#define CONFIG_MPEG2_D3D11VA_HWACCEL 0
#define CONFIG_MPEG2_DXVA2_HWACCEL 0
#define CONFIG_MPEG2_MEDIACODEC_DECODER 0
#define CONFIG_MPEG2_METADATA_BSF 1
#define CONFIG_MPEG2_MMAL_DECODER 0
#define CONFIG_MPEG2_NVDEC_HWACCEL 0
#define CONFIG_MPEG2_QSV_DECODER 0
#define CONFIG_MPEG2_QSV_ENCODER 0
#define CONFIG_MPEG2_V4L2M2M_DECODER 1
#define CONFIG_MPEG2_VAAPI_ENCODER 0
#define CONFIG_MPEG2_VAAPI_HWACCEL 0
#define CONFIG_MPEG2_VDPAU_HWACCEL 1
#define CONFIG_MPEG2_VIDEOTOOLBOX_HWACCEL 0
#define CONFIG_MPEG2_XVMC_HWACCEL 0
#define CONFIG_MPEG4VIDEO_PARSER 1
#define CONFIG_MPEG4_CRYSTALHD_DECODER 0
#define CONFIG_MPEG4_CUVID_DECODER 0
#define CONFIG_MPEG4_DECODER 1
#define CONFIG_MPEG4_ENCODER 1
#define CONFIG_MPEG4_MEDIACODEC_DECODER 0
#define CONFIG_MPEG4_MMAL_DECODER 0
#define CONFIG_MPEG4_NVDEC_HWACCEL 0
#define CONFIG_MPEG4_OMX_ENCODER 0
#define CONFIG_MPEG4_UNPACK_BFRAMES_BSF 1
#define CONFIG_MPEG4_V4L2M2M_DECODER 1
#define CONFIG_MPEG4_V4L2M2M_ENCODER 1
#define CONFIG_MPEG4_VAAPI_HWACCEL 0
#define CONFIG_MPEG4_VDPAU_HWACCEL 1
#define CONFIG_MPEG4_VIDEOTOOLBOX_HWACCEL 0
#define CONFIG_MPEGAUDIO 1
#define CONFIG_MPEGAUDIODSP 1
#define CONFIG_MPEGAUDIOHEADER 1
#define CONFIG_MPEGAUDIO_PARSER 1
#define CONFIG_MPEGPS_DEMUXER 1
#define CONFIG_MPEGTSRAW_DEMUXER 1
#define CONFIG_MPEGTS_DEMUXER 1
#define CONFIG_MPEGTS_MUXER 1
#define CONFIG_MPEGVIDEO 1
#define CONFIG_MPEGVIDEOENC 1
#define CONFIG_MPEGVIDEO_DECODER 1
#define CONFIG_MPEGVIDEO_DEMUXER 1
#define CONFIG_MPEGVIDEO_PARSER 1
#define CONFIG_MPEG_ER 1
#define CONFIG_MPJPEG_DEMUXER 1
#define CONFIG_MPJPEG_MUXER 1
#define CONFIG_MPL2_DECODER 1
#define CONFIG_MPL2_DEMUXER 1
#define CONFIG_MPSUB_DEMUXER 1
#define CONFIG_MPTESTSRC_FILTER 0
#define CONFIG_MSA1_DECODER 1
#define CONFIG_MSAD_FILTER 1
#define CONFIG_MSCC_DECODER 1
#define CONFIG_MSF_DEMUXER 1
#define CONFIG_MSMPEG4V1_DECODER 1
#define CONFIG_MSMPEG4V2_DECODER 1
#define CONFIG_MSMPEG4V2_ENCODER 1
#define CONFIG_MSMPEG4V3_DECODER 1
#define CONFIG_MSMPEG4V3_ENCODER 1
#define CONFIG_MSMPEG4_CRYSTALHD_DECODER 0
#define CONFIG_MSNWC_TCP_DEMUXER 1
#define CONFIG_MSP2_DECODER 1
#define CONFIG_MSP_DEMUXER 1
#define CONFIG_MSRLE_DECODER 1
#define CONFIG_MSS1_DECODER 1
#define CONFIG_MSS2_DECODER 1
#define CONFIG_MSS34DSP 1
#define CONFIG_MSVIDEO1_DECODER 1
#define CONFIG_MSVIDEO1_ENCODER 1
#define CONFIG_MSZH_DECODER 1
#define CONFIG_MTAF_DEMUXER 1
#define CONFIG_MTS2_DECODER 1
#define CONFIG_MTV_DEMUXER 1
#define CONFIG_MUSX_DEMUXER 1
#define CONFIG_MUXERS 1
#define CONFIG_MUXING_EXAMPLE 1
#define CONFIG_MV30_DECODER 1
#define CONFIG_MVC1_DECODER 1
#define CONFIG_MVC2_DECODER 1
#define CONFIG_MVDV_DECODER 1
#define CONFIG_MVHA_DECODER 1
#define CONFIG_MVI_DEMUXER 1
#define CONFIG_MV_DEMUXER 1
#define CONFIG_MWSC_DECODER 1
#define CONFIG_MXF_D10_MUXER 1
#define CONFIG_MXF_DEMUXER 1
#define CONFIG_MXF_MUXER 1
#define CONFIG_MXF_OPATOM_MUXER 1
#define CONFIG_MXG_DEMUXER 1
#define CONFIG_MXPEG_DECODER 1
#define CONFIG_NC_DEMUXER 1
#define CONFIG_NEGATE_FILTER 1
#define CONFIG_NELLYMOSER_DECODER 1
#define CONFIG_NELLYMOSER_ENCODER 1
#define CONFIG_NEON_CLOBBER_TEST 0
#define CONFIG_NETWORK 1
#define CONFIG_NISTSPHERE_DEMUXER 1
#define CONFIG_NLMEANS_FILTER 1
#define CONFIG_NLMEANS_OPENCL_FILTER 0
#define CONFIG_NNEDI_FILTER 0
#define CONFIG_NOFORMAT_FILTER 1
#define CONFIG_NOISE_BSF 1
#define CONFIG_NOISE_FILTER 1
#define CONFIG_NONFREE 0
#define CONFIG_NORMALIZE_FILTER 1
#define CONFIG_NOTCHLC_DECODER 1
#define CONFIG_NSP_DEMUXER 1
#define CONFIG_NSV_DEMUXER 1
#define CONFIG_NULLSINK_FILTER 1
#define CONFIG_NULLSRC_FILTER 1
#define CONFIG_NULL_BSF 1
#define CONFIG_NULL_FILTER 1
#define CONFIG_NULL_MUXER 1
#define CONFIG_NUT_DEMUXER 1
#define CONFIG_NUT_MUXER 1
#define CONFIG_NUV_DECODER 1
#define CONFIG_NUV_DEMUXER 1
#define CONFIG_NVDEC 0
#define CONFIG_NVENC 0
#define CONFIG_OBU_DEMUXER 1
#define CONFIG_OCR_FILTER 0
#define CONFIG_OCV_FILTER 0
#define CONFIG_OGA_MUXER 1
#define CONFIG_OGG_DEMUXER 1
#define CONFIG_OGG_MUXER 1
#define CONFIG_OGV_MUXER 1
#define CONFIG_OMA_DEMUXER 1
#define CONFIG_OMA_MUXER 1
#define CONFIG_OMX 0
#define CONFIG_OMX_RPI 0
#define CONFIG_ON2AVC_DECODER 1
#define CONFIG_OPENAL 0
#define CONFIG_OPENAL_INDEV 0
#define CONFIG_OPENCL 0
#define CONFIG_OPENCLSRC_FILTER 0
#define CONFIG_OPENGL 0
#define CONFIG_OPENGL_OUTDEV 0
#define CONFIG_OPENSSL 0
#define CONFIG_OPUS_DECODER 1
#define CONFIG_OPUS_ENCODER 1
#define CONFIG_OPUS_METADATA_BSF 1
#define CONFIG_OPUS_MUXER 1
#define CONFIG_OPUS_PARSER 1
#define CONFIG_OSCILLOSCOPE_FILTER 1
#define CONFIG_OSSFUZZ 0
#define CONFIG_OSS_INDEV 1
#define CONFIG_OSS_OUTDEV 1
#define CONFIG_OUTDEVS 1
#define CONFIG_OVERLAY_CUDA_FILTER 0
#define CONFIG_OVERLAY_FILTER 1
#define CONFIG_OVERLAY_OPENCL_FILTER 0
#define CONFIG_OVERLAY_QSV_FILTER 0
#define CONFIG_OVERLAY_VULKAN_FILTER 0
#define CONFIG_OWDENOISE_FILTER 0
#define CONFIG_PAD_FILTER 1
#define CONFIG_PAD_OPENCL_FILTER 0
#define CONFIG_PAF_AUDIO_DECODER 1
#define CONFIG_PAF_DEMUXER 1
#define CONFIG_PAF_VIDEO_DECODER 1
#define CONFIG_PAL100BARS_FILTER 1
#define CONFIG_PAL75BARS_FILTER 1
#define CONFIG_PALETTEGEN_FILTER 1
#define CONFIG_PALETTEUSE_FILTER 1
#define CONFIG_PAM_DECODER 1
#define CONFIG_PAM_ENCODER 1
#define CONFIG_PAN_FILTER 1
#define CONFIG_PARSERS 1
#define CONFIG_PBM_DECODER 1
#define CONFIG_PBM_ENCODER 1
#define CONFIG_PCM_ALAW_AT_DECODER 0
#define CONFIG_PCM_ALAW_AT_ENCODER 0
#define CONFIG_PCM_ALAW_DECODER 1
#define CONFIG_PCM_ALAW_DEMUXER 1
#define CONFIG_PCM_ALAW_ENCODER 1
#define CONFIG_PCM_ALAW_MUXER 1
#define CONFIG_PCM_BLURAY_DECODER 1
#define CONFIG_PCM_DVD_DECODER 1
#define CONFIG_PCM_DVD_ENCODER 1
#define CONFIG_PCM_F16LE_DECODER 1
#define CONFIG_PCM_F24LE_DECODER 1
#define CONFIG_PCM_F32BE_DECODER 1
#define CONFIG_PCM_F32BE_DEMUXER 1
#define CONFIG_PCM_F32BE_ENCODER 1
#define CONFIG_PCM_F32BE_MUXER 1
#define CONFIG_PCM_F32LE_DECODER 1
#define CONFIG_PCM_F32LE_DEMUXER 1
#define CONFIG_PCM_F32LE_ENCODER 1
#define CONFIG_PCM_F32LE_MUXER 1
#define CONFIG_PCM_F64BE_DECODER 1
#define CONFIG_PCM_F64BE_DEMUXER 1
#define CONFIG_PCM_F64BE_ENCODER 1
#define CONFIG_PCM_F64BE_MUXER 1
#define CONFIG_PCM_F64LE_DECODER 1
#define CONFIG_PCM_F64LE_DEMUXER 1
#define CONFIG_PCM_F64LE_ENCODER 1
#define CONFIG_PCM_F64LE_MUXER 1
#define CONFIG_PCM_LXF_DECODER 1
#define CONFIG_PCM_MULAW_AT_DECODER 0
#define CONFIG_PCM_MULAW_AT_ENCODER 0
#define CONFIG_PCM_MULAW_DECODER 1
#define CONFIG_PCM_MULAW_DEMUXER 1
#define CONFIG_PCM_MULAW_ENCODER 1
#define CONFIG_PCM_MULAW_MUXER 1
#define CONFIG_PCM_RECHUNK_BSF 1
#define CONFIG_PCM_S16BE_DECODER 1
#define CONFIG_PCM_S16BE_DEMUXER 1
#define CONFIG_PCM_S16BE_ENCODER 1
#define CONFIG_PCM_S16BE_MUXER 1
#define CONFIG_PCM_S16BE_PLANAR_DECODER 1
#define CONFIG_PCM_S16BE_PLANAR_ENCODER 1
#define CONFIG_PCM_S16LE_DECODER 1
#define CONFIG_PCM_S16LE_DEMUXER 1
#define CONFIG_PCM_S16LE_ENCODER 1
#define CONFIG_PCM_S16LE_MUXER 1
#define CONFIG_PCM_S16LE_PLANAR_DECODER 1
#define CONFIG_PCM_S16LE_PLANAR_ENCODER 1
#define CONFIG_PCM_S24BE_DECODER 1
#define CONFIG_PCM_S24BE_DEMUXER 1
#define CONFIG_PCM_S24BE_ENCODER 1
#define CONFIG_PCM_S24BE_MUXER 1
#define CONFIG_PCM_S24DAUD_DECODER 1
#define CONFIG_PCM_S24DAUD_ENCODER 1
#define CONFIG_PCM_S24LE_DECODER 1
#define CONFIG_PCM_S24LE_DEMUXER 1
#define CONFIG_PCM_S24LE_ENCODER 1
#define CONFIG_PCM_S24LE_MUXER 1
#define CONFIG_PCM_S24LE_PLANAR_DECODER 1
#define CONFIG_PCM_S24LE_PLANAR_ENCODER 1
#define CONFIG_PCM_S32BE_DECODER 1
#define CONFIG_PCM_S32BE_DEMUXER 1
#define CONFIG_PCM_S32BE_ENCODER 1
#define CONFIG_PCM_S32BE_MUXER 1
#define CONFIG_PCM_S32LE_DECODER 1
#define CONFIG_PCM_S32LE_DEMUXER 1
#define CONFIG_PCM_S32LE_ENCODER 1
#define CONFIG_PCM_S32LE_MUXER 1
#define CONFIG_PCM_S32LE_PLANAR_DECODER 1
#define CONFIG_PCM_S32LE_PLANAR_ENCODER 1
#define CONFIG_PCM_S64BE_DECODER 1
#define CONFIG_PCM_S64BE_ENCODER 1
#define CONFIG_PCM_S64LE_DECODER 1
#define CONFIG_PCM_S64LE_ENCODER 1
#define CONFIG_PCM_S8_DECODER 1
#define CONFIG_PCM_S8_DEMUXER 1
#define CONFIG_PCM_S8_ENCODER 1
#define CONFIG_PCM_S8_MUXER 1
#define CONFIG_PCM_S8_PLANAR_DECODER 1
#define CONFIG_PCM_S8_PLANAR_ENCODER 1
#define CONFIG_PCM_SGA_DECODER 1
#define CONFIG_PCM_U16BE_DECODER 1
#define CONFIG_PCM_U16BE_DEMUXER 1
#define CONFIG_PCM_U16BE_ENCODER 1
#define CONFIG_PCM_U16BE_MUXER 1
#define CONFIG_PCM_U16LE_DECODER 1
#define CONFIG_PCM_U16LE_DEMUXER 1
#define CONFIG_PCM_U16LE_ENCODER 1
#define CONFIG_PCM_U16LE_MUXER 1
#define CONFIG_PCM_U24BE_DECODER 1
#define CONFIG_PCM_U24BE_DEMUXER 1
#define CONFIG_PCM_U24BE_ENCODER 1
#define CONFIG_PCM_U24BE_MUXER 1
#define CONFIG_PCM_U24LE_DECODER 1
#define CONFIG_PCM_U24LE_DEMUXER 1
#define CONFIG_PCM_U24LE_ENCODER 1
#define CONFIG_PCM_U24LE_MUXER 1
#define CONFIG_PCM_U32BE_DECODER 1
#define CONFIG_PCM_U32BE_DEMUXER 1
#define CONFIG_PCM_U32BE_ENCODER 1
#define CONFIG_PCM_U32BE_MUXER 1
#define CONFIG_PCM_U32LE_DECODER 1
#define CONFIG_PCM_U32LE_DEMUXER 1
#define CONFIG_PCM_U32LE_ENCODER 1
#define CONFIG_PCM_U32LE_MUXER 1
#define CONFIG_PCM_U8_DECODER 1
#define CONFIG_PCM_U8_DEMUXER 1
#define CONFIG_PCM_U8_ENCODER 1
#define CONFIG_PCM_U8_MUXER 1
#define CONFIG_PCM_VIDC_DECODER 1
#define CONFIG_PCM_VIDC_DEMUXER 1
#define CONFIG_PCM_VIDC_ENCODER 1
#define CONFIG_PCM_VIDC_MUXER 1
#define CONFIG_PCX_DECODER 1
#define CONFIG_PCX_ENCODER 1
#define CONFIG_PERMS_FILTER 1
#define CONFIG_PERSPECTIVE_FILTER 0
#define CONFIG_PFM_DECODER 1
#define CONFIG_PFM_ENCODER 1
#define CONFIG_PGMYUV_DECODER 1
#define CONFIG_PGMYUV_ENCODER 1
#define CONFIG_PGM_DECODER 1
#define CONFIG_PGM_ENCODER 1
#define CONFIG_PGSSUB_DECODER 1
#define CONFIG_PGX_DECODER 1
#define CONFIG_PHASE_FILTER 0
#define CONFIG_PHOTOCD_DECODER 1
#define CONFIG_PHOTOSENSITIVITY_FILTER 1
#define CONFIG_PIC 1
#define CONFIG_PICTOR_DECODER 1
#define CONFIG_PIPE_PROTOCOL 1
#define CONFIG_PIXBLOCKDSP 1
#define CONFIG_PIXDESCTEST_FILTER 1
#define CONFIG_PIXELUTILS 1
#define CONFIG_PIXLET_DECODER 1
#define CONFIG_PIXSCOPE_FILTER 1
#define CONFIG_PJS_DECODER 1
#define CONFIG_PJS_DEMUXER 1
#define CONFIG_PMP_DEMUXER 1
#define CONFIG_PNG_DECODER 1
#define CONFIG_PNG_ENCODER 1
#define CONFIG_PNG_PARSER 1
#define CONFIG_PNM_PARSER 1
#define CONFIG_POCKETSPHINX 0
#define CONFIG_PODPAGES 1
#define CONFIG_POSTPROC 0
#define CONFIG_PP7_FILTER 0
#define CONFIG_PPM_DECODER 1
#define CONFIG_PPM_ENCODER 1
#define CONFIG_PP_BNK_DEMUXER 1
#define CONFIG_PP_FILTER 0
#define CONFIG_PREMULTIPLY_FILTER 1
#define CONFIG_PREWITT_FILTER 1
#define CONFIG_PREWITT_OPENCL_FILTER 0
#define CONFIG_PROCAMP_VAAPI_FILTER 0
#define CONFIG_PROGRAM_OPENCL_FILTER 0
#define CONFIG_PROMPEG_PROTOCOL 1
#define CONFIG_PRORES_AW_ENCODER 1
#define CONFIG_PRORES_DECODER 1
#define CONFIG_PRORES_ENCODER 1
#define CONFIG_PRORES_KS_ENCODER 1
#define CONFIG_PRORES_METADATA_BSF 1
#define CONFIG_PROSUMER_DECODER 1
#define CONFIG_PROTOCOLS 1
#define CONFIG_PSD_DECODER 1
#define CONFIG_PSEUDOCOLOR_FILTER 1
#define CONFIG_PSNR_FILTER 1
#define CONFIG_PSP_MUXER 1
#define CONFIG_PTX_DECODER 1
#define CONFIG_PULLUP_FILTER 0
#define CONFIG_PULSE_INDEV 0
#define CONFIG_PULSE_OUTDEV 0
#define CONFIG_PVA_DEMUXER 1
#define CONFIG_PVF_DEMUXER 1
#define CONFIG_QCELP_DECODER 1
#define CONFIG_QCP_DEMUXER 1
#define CONFIG_QDM2_AT_DECODER 0
#define CONFIG_QDM2_DECODER 1
#define CONFIG_QDMC_AT_DECODER 0
#define CONFIG_QDMC_DECODER 1
#define CONFIG_QDRAW_DECODER 1
#define CONFIG_QPEG_DECODER 1
#define CONFIG_QPELDSP 1
#define CONFIG_QP_FILTER 1
#define CONFIG_QSV 0
#define CONFIG_QSVDEC 0
#define CONFIG_QSVDEC_EXAMPLE 0
#define CONFIG_QSVENC 0
#define CONFIG_QSVVPP 0
#define CONFIG_QTRLE_DECODER 1
#define CONFIG_QTRLE_ENCODER 1
#define CONFIG_R10K_DECODER 1
#define CONFIG_R10K_ENCODER 1
#define CONFIG_R210_DECODER 1
#define CONFIG_R210_ENCODER 1
#define CONFIG_R3D_DEMUXER 1
#define CONFIG_RALF_DECODER 1
#define CONFIG_RANDOM_FILTER 1
#define CONFIG_RANGECODER 1
#define CONFIG_RASC_DECODER 1
#define CONFIG_RAWVIDEO_DECODER 1
#define CONFIG_RAWVIDEO_DEMUXER 1
#define CONFIG_RAWVIDEO_ENCODER 1
#define CONFIG_RAWVIDEO_MUXER 1
#define CONFIG_RA_144_DECODER 1
#define CONFIG_RA_144_ENCODER 1
#define CONFIG_RA_288_DECODER 1
#define CONFIG_RDFT 1
#define CONFIG_READEIA608_FILTER 1
#define CONFIG_READVITC_FILTER 1
#define CONFIG_REALTEXT_DECODER 1
#define CONFIG_REALTEXT_DEMUXER 1
#define CONFIG_REALTIME_FILTER 1
#define CONFIG_REDSPARK_DEMUXER 1
#define CONFIG_REMAP_FILTER 1
#define CONFIG_REMOVEGRAIN_FILTER 1
#define CONFIG_REMOVELOGO_FILTER 1
#define CONFIG_REMOVE_EXTRADATA_BSF 1
#define CONFIG_REMUXING_EXAMPLE 1
#define CONFIG_REPEATFIELDS_FILTER 0
#define CONFIG_REPLAYGAIN_FILTER 1
#define CONFIG_RESAMPLING_AUDIO_EXAMPLE 1
#define CONFIG_REVERSE_FILTER 1
#define CONFIG_RGBASHIFT_FILTER 1
#define CONFIG_RGBTESTSRC_FILTER 1
#define CONFIG_RIFFDEC 1
#define CONFIG_RIFFENC 1
#define CONFIG_RKMPP 0
#define CONFIG_RL2_DECODER 1
#define CONFIG_RL2_DEMUXER 1
#define CONFIG_RM_DEMUXER 1
#define CONFIG_RM_MUXER 1
#define CONFIG_ROBERTS_FILTER 1
#define CONFIG_ROBERTS_OPENCL_FILTER 0
#define CONFIG_ROQ_DECODER 1
#define CONFIG_ROQ_DEMUXER 1
#define CONFIG_ROQ_DPCM_DECODER 1
#define CONFIG_ROQ_DPCM_ENCODER 1
#define CONFIG_ROQ_ENCODER 1
#define CONFIG_ROQ_MUXER 1
#define CONFIG_ROTATE_FILTER 1
#define CONFIG_RPL_DEMUXER 1
#define CONFIG_RPZA_DECODER 1
#define CONFIG_RPZA_ENCODER 1
#define CONFIG_RSCC_DECODER 1
#define CONFIG_RSD_DEMUXER 1
#define CONFIG_RSO_DEMUXER 1
#define CONFIG_RSO_MUXER 1
#define CONFIG_RTMPE_PROTOCOL 0
#define CONFIG_RTMPS_PROTOCOL 0
#define CONFIG_RTMPTE_PROTOCOL 0
#define CONFIG_RTMPTS_PROTOCOL 0
#define CONFIG_RTMPT_PROTOCOL 1
#define CONFIG_RTMP_PROTOCOL 1
#define CONFIG_RTPDEC 1
#define CONFIG_RTPENC_CHAIN 1
#define CONFIG_RTP_DEMUXER 1
#define CONFIG_RTP_MPEGTS_MUXER 1
#define CONFIG_RTP_MUXER 1
#define CONFIG_RTP_PROTOCOL 1
#define CONFIG_RTSP_DEMUXER 1
#define CONFIG_RTSP_MUXER 1
#define CONFIG_RUBBERBAND_FILTER 0
#define CONFIG_RUNTIME_CPUDETECT 1
#define CONFIG_RV10_DECODER 1
#define CONFIG_RV10_ENCODER 1
#define CONFIG_RV20_DECODER 1
#define CONFIG_RV20_ENCODER 1
#define CONFIG_RV30_DECODER 1
#define CONFIG_RV30_PARSER 1
#define CONFIG_RV34DSP 1
#define CONFIG_RV40_DECODER 1
#define CONFIG_RV40_PARSER 1
#define CONFIG_S302M_DECODER 1
#define CONFIG_S302M_ENCODER 1
#define CONFIG_S337M_DEMUXER 1
#define CONFIG_SAB_FILTER 0
#define CONFIG_SAFE_BITSTREAM_READER 1
#define CONFIG_SAMI_DECODER 1
#define CONFIG_SAMI_DEMUXER 1
#define CONFIG_SANM_DECODER 1
#define CONFIG_SAP_DEMUXER 1
#define CONFIG_SAP_MUXER 1
#define CONFIG_SBC_DECODER 1
#define CONFIG_SBC_DEMUXER 1
#define CONFIG_SBC_ENCODER 1
#define CONFIG_SBC_MUXER 1
#define CONFIG_SBC_PARSER 1
#define CONFIG_SBG_DEMUXER 1
#define CONFIG_SCALE2REF_FILTER 1
#define CONFIG_SCALE_CUDA_FILTER 0
#define CONFIG_SCALE_FILTER 1
#define CONFIG_SCALE_NPP_FILTER 0
#define CONFIG_SCALE_QSV_FILTER 0
#define CONFIG_SCALE_VAAPI_FILTER 0
#define CONFIG_SCALE_VULKAN_FILTER 0
#define CONFIG_SCALING_VIDEO_EXAMPLE 1
#define CONFIG_SCC_DEMUXER 1
#define CONFIG_SCC_MUXER 1
#define CONFIG_SCDET_FILTER 1
#define CONFIG_SCENE_SAD 1
#define CONFIG_SCHANNEL 0
#define CONFIG_SCPR_DECODER 1
#define CONFIG_SCREENPRESSO_DECODER 1
#define CONFIG_SCROLL_FILTER 1
#define CONFIG_SCTP_PROTOCOL 1
#define CONFIG_SDL2 0
#define CONFIG_SDL2_OUTDEV 0
#define CONFIG_SDP_DEMUXER 1
#define CONFIG_SDR2_DEMUXER 1
#define CONFIG_SDS_DEMUXER 1
#define CONFIG_SDX2_DPCM_DECODER 1
#define CONFIG_SDX_DEMUXER 1
#define CONFIG_SECURETRANSPORT 0
#define CONFIG_SEGAFILM_DEMUXER 1
#define CONFIG_SEGAFILM_MUXER 1
#define CONFIG_SEGMENT_MUXER 1
#define CONFIG_SELECTIVECOLOR_FILTER 1
#define CONFIG_SELECT_FILTER 1
#define CONFIG_SENDCMD_FILTER 1
#define CONFIG_SEPARATEFIELDS_FILTER 1
#define CONFIG_SER_DEMUXER 1
#define CONFIG_SETDAR_FILTER 1
#define CONFIG_SETFIELD_FILTER 1
#define CONFIG_SETPARAMS_FILTER 1
#define CONFIG_SETPTS_FILTER 1
#define CONFIG_SETRANGE_FILTER 1
#define CONFIG_SETSAR_FILTER 1
#define CONFIG_SETTB_FILTER 1
#define CONFIG_SETTS_BSF 1
#define CONFIG_SGA_DECODER 1
#define CONFIG_SGA_DEMUXER 1
#define CONFIG_SGIRLE_DECODER 1
#define CONFIG_SGI_DECODER 1
#define CONFIG_SGI_ENCODER 1
#define CONFIG_SHARED 0
#define CONFIG_SHARPNESS_VAAPI_FILTER 0
#define CONFIG_SHEAR_FILTER 1
#define CONFIG_SHEERVIDEO_DECODER 1
#define CONFIG_SHORTEN_DECODER 1
#define CONFIG_SHORTEN_DEMUXER 1
#define CONFIG_SHOWCQT_FILTER 1
#define CONFIG_SHOWFREQS_FILTER 1
#define CONFIG_SHOWINFO_FILTER 1
#define CONFIG_SHOWPALETTE_FILTER 1
#define CONFIG_SHOWSPATIAL_FILTER 1
#define CONFIG_SHOWSPECTRUMPIC_FILTER 1
#define CONFIG_SHOWSPECTRUM_FILTER 1
#define CONFIG_SHOWVOLUME_FILTER 1
#define CONFIG_SHOWWAVESPIC_FILTER 1
#define CONFIG_SHOWWAVES_FILTER 1
#define CONFIG_SHUFFLEFRAMES_FILTER 1
#define CONFIG_SHUFFLEPIXELS_FILTER 1
#define CONFIG_SHUFFLEPLANES_FILTER 1
#define CONFIG_SIDECHAINCOMPRESS_FILTER 1
#define CONFIG_SIDECHAINGATE_FILTER 1
#define CONFIG_SIDEDATA_FILTER 1
#define CONFIG_SIERPINSKI_FILTER 1
#define CONFIG_SIFF_DEMUXER 1
#define CONFIG_SIGNALSTATS_FILTER 1
#define CONFIG_SIGNATURE_FILTER 0
#define CONFIG_SILENCEDETECT_FILTER 1
#define CONFIG_SILENCEREMOVE_FILTER 1
#define CONFIG_SIMBIOSIS_IMX_DECODER 1
#define CONFIG_SIMBIOSIS_IMX_DEMUXER 1
#define CONFIG_SINC_FILTER 1
#define CONFIG_SINEWIN 1
#define CONFIG_SINE_FILTER 1
#define CONFIG_SIPR_DECODER 1
#define CONFIG_SIPR_PARSER 1
#define CONFIG_SIREN_DECODER 1
#define CONFIG_SLN_DEMUXER 1
#define CONFIG_SMACKAUD_DECODER 1
#define CONFIG_SMACKER_DECODER 1
#define CONFIG_SMACKER_DEMUXER 1
#define CONFIG_SMALL 0
#define CONFIG_SMARTBLUR_FILTER 0
#define CONFIG_SMC_DECODER 1
#define CONFIG_SMJPEG_DEMUXER 1
#define CONFIG_SMJPEG_MUXER 1
#define CONFIG_SMOOTHSTREAMING_MUXER 1
#define CONFIG_SMPTEBARS_FILTER 1
#define CONFIG_SMPTEHDBARS_FILTER 1
#define CONFIG_SMUSH_DEMUXER 1
#define CONFIG_SMVJPEG_DECODER 1
#define CONFIG_SNAPPY 1
#define CONFIG_SNDIO 0
#define CONFIG_SNDIO_INDEV 0
#define CONFIG_SNDIO_OUTDEV 0
#define CONFIG_SNOW_DECODER 1
#define CONFIG_SNOW_ENCODER 1
#define CONFIG_SOBEL_FILTER 1
#define CONFIG_SOBEL_OPENCL_FILTER 0
#define CONFIG_SOFALIZER_FILTER 0
#define CONFIG_SOL_DEMUXER 1
#define CONFIG_SOL_DPCM_DECODER 1
#define CONFIG_SONIC_DECODER 1
#define CONFIG_SONIC_ENCODER 1
#define CONFIG_SONIC_LS_ENCODER 1
#define CONFIG_SOX_DEMUXER 1
#define CONFIG_SOX_MUXER 1
#define CONFIG_SP5X_DECODER 1
#define CONFIG_SPDIF_DEMUXER 1
#define CONFIG_SPDIF_MUXER 1
#define CONFIG_SPECTRUMSYNTH_FILTER 1
#define CONFIG_SPEECHNORM_FILTER 1
#define CONFIG_SPEEDHQ_DECODER 1
#define CONFIG_SPEEDHQ_ENCODER 1
#define CONFIG_SPLIT_FILTER 1
#define CONFIG_SPP_FILTER 0
#define CONFIG_SPX_MUXER 1
#define CONFIG_SRGC_DECODER 1
#define CONFIG_SRTP 1
#define CONFIG_SRTP_PROTOCOL 1
#define CONFIG_SRT_DECODER 1
#define CONFIG_SRT_DEMUXER 1
#define CONFIG_SRT_ENCODER 1
#define CONFIG_SRT_MUXER 1
#define CONFIG_SR_FILTER 1
#define CONFIG_SSA_DECODER 1
#define CONFIG_SSA_ENCODER 1
#define CONFIG_SSIM_FILTER 1
#define CONFIG_STARTCODE 1
#define CONFIG_STATIC 1
#define CONFIG_STEREO3D_FILTER 0
#define CONFIG_STEREOTOOLS_FILTER 1
#define CONFIG_STEREOWIDEN_FILTER 1
#define CONFIG_STL_DECODER 1
#define CONFIG_STL_DEMUXER 1
#define CONFIG_STREAMHASH_MUXER 1
#define CONFIG_STREAMSELECT_FILTER 1
#define CONFIG_STREAM_SEGMENT_MUXER 1
#define CONFIG_STR_DEMUXER 1
#define CONFIG_SUBFILE_PROTOCOL 1
#define CONFIG_SUBRIP_DECODER 1
#define CONFIG_SUBRIP_ENCODER 1
#define CONFIG_SUBTITLES_FILTER 0
#define CONFIG_SUBVIEWER1_DECODER 1
#define CONFIG_SUBVIEWER1_DEMUXER 1
#define CONFIG_SUBVIEWER_DECODER 1
#define CONFIG_SUBVIEWER_DEMUXER 1
#define CONFIG_SUNRAST_DECODER 1
#define CONFIG_SUNRAST_ENCODER 1
#define CONFIG_SUPER2XSAI_FILTER 0
#define CONFIG_SUPEREQUALIZER_FILTER 1
#define CONFIG_SUP_DEMUXER 1
#define CONFIG_SUP_MUXER 1
#define CONFIG_SURROUND_FILTER 1
#define CONFIG_SVAG_DEMUXER 1
#define CONFIG_SVQ1_DECODER 1
#define CONFIG_SVQ1_ENCODER 1
#define CONFIG_SVQ3_DECODER 1
#define CONFIG_SVS_DEMUXER 1
#define CONFIG_SWAPRECT_FILTER 1
#define CONFIG_SWAPUV_FILTER 1
#define CONFIG_SWF_DEMUXER 1
#define CONFIG_SWF_MUXER 1
#define CONFIG_SWRESAMPLE 1
#define CONFIG_SWSCALE 1
#define CONFIG_SWSCALE_ALPHA 1
#define CONFIG_TAK_DECODER 1
#define CONFIG_TAK_DEMUXER 1
#define CONFIG_TAK_PARSER 1
#define CONFIG_TARGA_DECODER 1
#define CONFIG_TARGA_ENCODER 1
#define CONFIG_TARGA_Y216_DECODER 1
#define CONFIG_TBLEND_FILTER 1
#define CONFIG_TCP_PROTOCOL 1
#define CONFIG_TDSC_DECODER 1
#define CONFIG_TEDCAPTIONS_DEMUXER 1
#define CONFIG_TEE_MUXER 1
#define CONFIG_TEE_PROTOCOL 1
#define CONFIG_TELECINE_FILTER 1
#define CONFIG_TESTSRC2_FILTER 1
#define CONFIG_TESTSRC_FILTER 1
#define CONFIG_TEXT2MOVSUB_BSF 1
#define CONFIG_TEXTUREDSP 1
#define CONFIG_TEXTUREDSPENC 0
#define CONFIG_TEXT_DECODER 1
#define CONFIG_TEXT_ENCODER 1
#define CONFIG_TG2_MUXER 1
#define CONFIG_TGP_MUXER 1
#define CONFIG_THEORA_DECODER 1
#define CONFIG_THISTOGRAM_FILTER 1
#define CONFIG_THIS_YEAR 2021
#define CONFIG_THP_DECODER 1
#define CONFIG_THP_DEMUXER 1
#define CONFIG_THREEDOSTR_DEMUXER 1
#define CONFIG_THRESHOLD_FILTER 1
#define CONFIG_THUMB 0
#define CONFIG_THUMBNAIL_CUDA_FILTER 0
#define CONFIG_THUMBNAIL_FILTER 1
#define CONFIG_TIERTEXSEQVIDEO_DECODER 1
#define CONFIG_TIERTEXSEQ_DEMUXER 1
#define CONFIG_TIFF_DECODER 1
#define CONFIG_TIFF_ENCODER 1
#define CONFIG_TILE_FILTER 1
#define CONFIG_TINTERLACE_FILTER 0
#define CONFIG_TLS_PROTOCOL 0
#define CONFIG_TLUT2_FILTER 1
#define CONFIG_TMEDIAN_FILTER 1
#define CONFIG_TMIDEQUALIZER_FILTER 1
#define CONFIG_TMIX_FILTER 1
#define CONFIG_TMV_DECODER 1
#define CONFIG_TMV_DEMUXER 1
#define CONFIG_TONEMAP_FILTER 1
#define CONFIG_TONEMAP_OPENCL_FILTER 0
#define CONFIG_TONEMAP_VAAPI_FILTER 0
#define CONFIG_TPAD_FILTER 1
#define CONFIG_TPELDSP 1
#define CONFIG_TRACE_HEADERS_BSF 1
#define CONFIG_TRANSCODE_AAC_EXAMPLE 1
#define CONFIG_TRANSCODING_EXAMPLE 1
#define CONFIG_TRANSPOSE_FILTER 1
#define CONFIG_TRANSPOSE_NPP_FILTER 0
#define CONFIG_TRANSPOSE_OPENCL_FILTER 0
#define CONFIG_TRANSPOSE_VAAPI_FILTER 0
#define CONFIG_TREBLE_FILTER 1
#define CONFIG_TREMOLO_FILTER 1
#define CONFIG_TRIM_FILTER 1
#define CONFIG_TRUEHD_CORE_BSF 1
#define CONFIG_TRUEHD_DECODER 1
#define CONFIG_TRUEHD_DEMUXER 1
#define CONFIG_TRUEHD_ENCODER 1
#define CONFIG_TRUEHD_MUXER 1
#define CONFIG_TRUEMOTION1_DECODER 1
#define CONFIG_TRUEMOTION2RT_DECODER 1
#define CONFIG_TRUEMOTION2_DECODER 1
#define CONFIG_TRUESPEECH_DECODER 1
#define CONFIG_TSCC2_DECODER 1
#define CONFIG_TSCC_DECODER 1
#define CONFIG_TTA_DECODER 1
#define CONFIG_TTA_DEMUXER 1
#define CONFIG_TTA_ENCODER 1
#define CONFIG_TTA_MUXER 1
#define CONFIG_TTML_ENCODER 1
#define CONFIG_TTML_MUXER 1
#define CONFIG_TTY_DEMUXER 1
#define CONFIG_TWINVQ_DECODER 1
#define CONFIG_TXD_DECODER 1
#define CONFIG_TXD_DEMUXER 1
#define CONFIG_TXTPAGES 0
#define CONFIG_TY_DEMUXER 1
#define CONFIG_UDPLITE_PROTOCOL 1
#define CONFIG_UDP_PROTOCOL 1
#define CONFIG_ULTI_DECODER 1
#define CONFIG_UNCODEDFRAMECRC_MUXER 1
#define CONFIG_UNIX_PROTOCOL 1
#define CONFIG_UNPREMULTIPLY_FILTER 1
#define CONFIG_UNSHARP_FILTER 1
#define CONFIG_UNSHARP_OPENCL_FILTER 0
#define CONFIG_UNTILE_FILTER 1
#define CONFIG_USPP_FILTER 0
#define CONFIG_UTVIDEO_DECODER 1
#define CONFIG_UTVIDEO_ENCODER 1
#define CONFIG_V210X_DECODER 1
#define CONFIG_V210X_DEMUXER 1
#define CONFIG_V210_DECODER 1
#define CONFIG_V210_DEMUXER 1
#define CONFIG_V210_ENCODER 1
#define CONFIG_V308_DECODER 1
#define CONFIG_V308_ENCODER 1
#define CONFIG_V360_FILTER 1
#define CONFIG_V408_DECODER 1
#define CONFIG_V408_ENCODER 1
#define CONFIG_V410_DECODER 1
#define CONFIG_V410_ENCODER 1
#define CONFIG_V4L2_INDEV 1
#define CONFIG_V4L2_M2M 1
#define CONFIG_V4L2_OUTDEV 1
#define CONFIG_VAAPI 0
#define CONFIG_VAAPI_1 0
#define CONFIG_VAAPI_ENCODE 0
#define CONFIG_VAAPI_ENCODE_EXAMPLE 0
#define CONFIG_VAAPI_TRANSCODE_EXAMPLE 0
#define CONFIG_VAGUEDENOISER_FILTER 0
#define CONFIG_VAG_DEMUXER 1
#define CONFIG_VALGRIND_BACKTRACE 0
#define CONFIG_VAPOURSYNTH 0
#define CONFIG_VAPOURSYNTH_DEMUXER 0
#define CONFIG_VBLE_DECODER 1
#define CONFIG_VB_DECODER 1
#define CONFIG_VC1DSP 1
#define CONFIG_VC1IMAGE_DECODER 1
#define CONFIG_VC1T_DEMUXER 1
#define CONFIG_VC1T_MUXER 1
#define CONFIG_VC1_CRYSTALHD_DECODER 0
#define CONFIG_VC1_CUVID_DECODER 0
#define CONFIG_VC1_D3D11VA2_HWACCEL 0
#define CONFIG_VC1_D3D11VA_HWACCEL 0
#define CONFIG_VC1_DECODER 1
#define CONFIG_VC1_DEMUXER 1
#define CONFIG_VC1_DXVA2_HWACCEL 0
#define CONFIG_VC1_MMAL_DECODER 0
#define CONFIG_VC1_MUXER 1
#define CONFIG_VC1_NVDEC_HWACCEL 0
#define CONFIG_VC1_PARSER 1
#define CONFIG_VC1_QSV_DECODER 0
#define CONFIG_VC1_V4L2M2M_DECODER 1
#define CONFIG_VC1_VAAPI_HWACCEL 0
#define CONFIG_VC1_VDPAU_HWACCEL 1
#define CONFIG_VC2_ENCODER 1
#define CONFIG_VCR1_DECODER 1
#define CONFIG_VDPAU 1
#define CONFIG_VECTORSCOPE_FILTER 1
#define CONFIG_VERSION3 0
#define CONFIG_VFLIP_FILTER 1
#define CONFIG_VFRDET_FILTER 1
#define CONFIG_VFWCAP_INDEV 0
#define CONFIG_VIBRANCE_FILTER 1
#define CONFIG_VIBRATO_FILTER 1
#define CONFIG_VIDEODSP 1
#define CONFIG_VIDEOTOOLBOX 0
#define CONFIG_VIDSTABDETECT_FILTER 0
#define CONFIG_VIDSTABTRANSFORM_FILTER 0
#define CONFIG_VIF_FILTER 1
#define CONFIG_VIGNETTE_FILTER 1
#define CONFIG_VIVIDAS_DEMUXER 1
#define CONFIG_VIVO_DEMUXER 1
#define CONFIG_VMAFMOTION_FILTER 1
#define CONFIG_VMDAUDIO_DECODER 1
#define CONFIG_VMDVIDEO_DECODER 1
#define CONFIG_VMD_DEMUXER 1
#define CONFIG_VMNC_DECODER 1
#define CONFIG_VOBSUB_DEMUXER 1
#define CONFIG_VOC_DEMUXER 1
#define CONFIG_VOC_MUXER 1
#define CONFIG_VOLUMEDETECT_FILTER 1
#define CONFIG_VOLUME_FILTER 1
#define CONFIG_VORBIS_DECODER 1
#define CONFIG_VORBIS_ENCODER 1
#define CONFIG_VORBIS_PARSER 1
#define CONFIG_VP3DSP 1
#define CONFIG_VP3_DECODER 1
#define CONFIG_VP3_PARSER 1
#define CONFIG_VP4_DECODER 1
#define CONFIG_VP56DSP 1
#define CONFIG_VP5_DECODER 1
#define CONFIG_VP6A_DECODER 1
#define CONFIG_VP6F_DECODER 1
#define CONFIG_VP6_DECODER 1
#define CONFIG_VP7_DECODER 1
#define CONFIG_VP8DSP 1
#define CONFIG_VP8_CUVID_DECODER 0
#define CONFIG_VP8_DECODER 1
#define CONFIG_VP8_MEDIACODEC_DECODER 0
#define CONFIG_VP8_NVDEC_HWACCEL 0
#define CONFIG_VP8_PARSER 1
#define CONFIG_VP8_QSV_DECODER 0
#define CONFIG_VP8_RKMPP_DECODER 0
#define CONFIG_VP8_V4L2M2M_DECODER 1
#define CONFIG_VP8_V4L2M2M_ENCODER 1
#define CONFIG_VP8_VAAPI_ENCODER 0
#define CONFIG_VP8_VAAPI_HWACCEL 0
#define CONFIG_VP9_CUVID_DECODER 0
#define CONFIG_VP9_D3D11VA2_HWACCEL 0
#define CONFIG_VP9_D3D11VA_HWACCEL 0
#define CONFIG_VP9_DECODER 1
#define CONFIG_VP9_DXVA2_HWACCEL 0
#define CONFIG_VP9_MEDIACODEC_DECODER 0
#define CONFIG_VP9_METADATA_BSF 1
#define CONFIG_VP9_NVDEC_HWACCEL 0
#define CONFIG_VP9_PARSER 1
#define CONFIG_VP9_QSV_DECODER 0
#define CONFIG_VP9_QSV_ENCODER 0
#define CONFIG_VP9_RAW_REORDER_BSF 1
#define CONFIG_VP9_RKMPP_DECODER 0
#define CONFIG_VP9_SUPERFRAME_BSF 1
#define CONFIG_VP9_SUPERFRAME_SPLIT_BSF 1
#define CONFIG_VP9_V4L2M2M_DECODER 1
#define CONFIG_VP9_VAAPI_ENCODER 0
#define CONFIG_VP9_VAAPI_HWACCEL 0
#define CONFIG_VP9_VDPAU_HWACCEL 1
#define CONFIG_VPK_DEMUXER 1
#define CONFIG_VPLAYER_DECODER 1
#define CONFIG_VPLAYER_DEMUXER 1
#define CONFIG_VPP_QSV_FILTER 0
#define CONFIG_VQA_DECODER 1
#define CONFIG_VQF_DEMUXER 1
#define CONFIG_VSTACK_FILTER 1
#define CONFIG_VULKAN 0
#define CONFIG_W3FDIF_FILTER 1
#define CONFIG_W64_DEMUXER 1
#define CONFIG_W64_MUXER 1
#define CONFIG_WAVEFORM_FILTER 1
#define CONFIG_WAVPACK_DECODER 1
#define CONFIG_WAVPACK_ENCODER 1
#define CONFIG_WAV_DEMUXER 1
#define CONFIG_WAV_MUXER 1
#define CONFIG_WC3_DEMUXER 1
#define CONFIG_WCMV_DECODER 1
#define CONFIG_WEAVE_FILTER 1
#define CONFIG_WEBM_CHUNK_MUXER 1
#define CONFIG_WEBM_DASH_MANIFEST_DEMUXER 1
#define CONFIG_WEBM_DASH_MANIFEST_MUXER 1
#define CONFIG_WEBM_MUXER 1
#define CONFIG_WEBP_DECODER 1
#define CONFIG_WEBP_MUXER 1
#define CONFIG_WEBP_PARSER 1
#define CONFIG_WEBVTT_DECODER 1
#define CONFIG_WEBVTT_DEMUXER 1
#define CONFIG_WEBVTT_ENCODER 1
#define CONFIG_WEBVTT_MUXER 1
#define CONFIG_WMALOSSLESS_DECODER 1
#define CONFIG_WMAPRO_DECODER 1
#define CONFIG_WMAV1_DECODER 1
#define CONFIG_WMAV1_ENCODER 1
#define CONFIG_WMAV2_DECODER 1
#define CONFIG_WMAV2_ENCODER 1
#define CONFIG_WMAVOICE_DECODER 1
#define CONFIG_WMA_FREQS 1
#define CONFIG_WMV1_DECODER 1
#define CONFIG_WMV1_ENCODER 1
#define CONFIG_WMV2DSP 1
#define CONFIG_WMV2_DECODER 1
#define CONFIG_WMV2_ENCODER 1
#define CONFIG_WMV3IMAGE_DECODER 1
#define CONFIG_WMV3_CRYSTALHD_DECODER 0
#define CONFIG_WMV3_D3D11VA2_HWACCEL 0
#define CONFIG_WMV3_D3D11VA_HWACCEL 0
#define CONFIG_WMV3_DECODER 1
#define CONFIG_WMV3_DXVA2_HWACCEL 0
#define CONFIG_WMV3_NVDEC_HWACCEL 0
#define CONFIG_WMV3_VAAPI_HWACCEL 0
#define CONFIG_WMV3_VDPAU_HWACCEL 1
#define CONFIG_WNV1_DECODER 1
#define CONFIG_WRAPPED_AVFRAME_DECODER 1
#define CONFIG_WRAPPED_AVFRAME_ENCODER 1
#define CONFIG_WSAUD_DEMUXER 1
#define CONFIG_WSAUD_MUXER 1
#define CONFIG_WSD_DEMUXER 1
#define CONFIG_WSVQA_DEMUXER 1
#define CONFIG_WS_SND1_DECODER 1
#define CONFIG_WTV_DEMUXER 1
#define CONFIG_WTV_MUXER 1
#define CONFIG_WVE_DEMUXER 1
#define CONFIG_WV_DEMUXER 1
#define CONFIG_WV_MUXER 1
#define CONFIG_XAN_DPCM_DECODER 1
#define CONFIG_XAN_WC3_DECODER 1
#define CONFIG_XAN_WC4_DECODER 1
#define CONFIG_XA_DEMUXER 1
#define CONFIG_XBIN_DECODER 1
#define CONFIG_XBIN_DEMUXER 1
#define CONFIG_XBM_DECODER 1
#define CONFIG_XBM_ENCODER 1
#define CONFIG_XBM_PARSER 1
#define CONFIG_XBR_FILTER 1
#define CONFIG_XCBGRAB_INDEV 1
#define CONFIG_XFACE_DECODER 1
#define CONFIG_XFACE_ENCODER 1
#define CONFIG_XFADE_FILTER 1
#define CONFIG_XFADE_OPENCL_FILTER 0
#define CONFIG_XLIB 0
#define CONFIG_XL_DECODER 1
#define CONFIG_XMA1_DECODER 1
#define CONFIG_XMA2_DECODER 1
#define CONFIG_XMA_PARSER 1
#define CONFIG_XMEDIAN_FILTER 1
#define CONFIG_XMM_CLOBBER_TEST 0
#define CONFIG_XMV_DEMUXER 1
#define CONFIG_XPM_DECODER 1
#define CONFIG_XSTACK_FILTER 1
#define CONFIG_XSUB_DECODER 1
#define CONFIG_XSUB_ENCODER 1
#define CONFIG_XVAG_DEMUXER 1
#define CONFIG_XVMC 0
#define CONFIG_XV_OUTDEV 0
#define CONFIG_XWD_DECODER 1
#define CONFIG_XWD_ENCODER 1
#define CONFIG_XWMA_DEMUXER 1
#define CONFIG_Y41P_DECODER 1
#define CONFIG_Y41P_ENCODER 1
#define CONFIG_YADIF_CUDA_FILTER 0
#define CONFIG_YADIF_FILTER 1
#define CONFIG_YAEPBLUR_FILTER 1
#define CONFIG_YLC_DECODER 1
#define CONFIG_YOP_DECODER 1
#define CONFIG_YOP_DEMUXER 1
#define CONFIG_YUV4MPEGPIPE_DEMUXER 1
#define CONFIG_YUV4MPEGPIPE_MUXER 1
#define CONFIG_YUV4_DECODER 1
#define CONFIG_YUV4_ENCODER 1
#define CONFIG_YUVTESTSRC_FILTER 1
#define CONFIG_ZERO12V_DECODER 1
#define CONFIG_ZEROCODEC_DECODER 1
#define CONFIG_ZLIB 1
#define CONFIG_ZLIB_DECODER 1
#define CONFIG_ZLIB_ENCODER 1
#define CONFIG_ZMBV_DECODER 1
#define CONFIG_ZMBV_ENCODER 1
#define CONFIG_ZMQ_FILTER 0
#define CONFIG_ZOOMPAN_FILTER 1
#define CONFIG_ZSCALE_FILTER 0
#define EXTERN_ASM 
#define EXTERN_PREFIX ""
#define FFMPEG_CONFIGURATION "--disable-x86asm"

#define FFMPEG_DATADIR "/usr/local/share/ffmpeg"
#define FFMPEG_LICENSE "LGPL version 2.1 or later"
#define HAVE_ACCESS 1
#define HAVE_AESNI 1
#define HAVE_AESNI_EXTERNAL 0
#define HAVE_AESNI_INLINE 1
#define HAVE_ALIGNED_MALLOC 0
#define HAVE_ALIGNED_STACK 1
#define HAVE_ALTIVEC 0
#define HAVE_ALTIVEC_EXTERNAL 0
#define HAVE_ALTIVEC_INLINE 0
#define HAVE_AMD3DNOW 1
#define HAVE_AMD3DNOWEXT 1
#define HAVE_AMD3DNOWEXT_EXTERNAL 0
#define HAVE_AMD3DNOWEXT_INLINE 1
#define HAVE_AMD3DNOW_EXTERNAL 0
#define HAVE_AMD3DNOW_INLINE 1
#define HAVE_ARC4RANDOM 0
#define HAVE_ARMV5TE 0
#define HAVE_ARMV5TE_EXTERNAL 0
#define HAVE_ARMV5TE_INLINE 0
#define HAVE_ARMV6 0
#define HAVE_ARMV6T2 0
#define HAVE_ARMV6T2_EXTERNAL 0
#define HAVE_ARMV6T2_INLINE 0
#define HAVE_ARMV6_EXTERNAL 0
#define HAVE_ARMV6_INLINE 0
#define HAVE_ARMV8 0
#define HAVE_ARMV8_EXTERNAL 0
#define HAVE_ARMV8_INLINE 0
#define HAVE_ARPA_INET_H 1
#define HAVE_ASM_MOD_Q 0
#define HAVE_ASM_TYPES_H 1
#define HAVE_AS_ARCH_DIRECTIVE 0
#define HAVE_AS_DN_DIRECTIVE 0
#define HAVE_AS_FPU_DIRECTIVE 0
#define HAVE_AS_FUNC 0
#define HAVE_AS_OBJECT_ARCH 0
#define HAVE_ATAN2F 1
#define HAVE_ATANF 1
#define HAVE_ATOMIC_CAS_PTR 0
#define HAVE_AVX 1
#define HAVE_AVX2 1
#define HAVE_AVX2_EXTERNAL 0
#define HAVE_AVX2_INLINE 1
#define HAVE_AVX512 1
#define HAVE_AVX512_EXTERNAL 0
#define HAVE_AVX512_INLINE 1
#define HAVE_AVX_EXTERNAL 0
#define HAVE_AVX_INLINE 1
#define HAVE_BCRYPT 0
#define HAVE_BIGENDIAN 0
#define HAVE_BLOCKS_EXTENSION 0
#define HAVE_CABS 0
#define HAVE_CBRT 1
#define HAVE_CBRTF 1
#define HAVE_CDIO_PARANOIA_H 0
#define HAVE_CDIO_PARANOIA_PARANOIA_H 0
#define HAVE_CEXP 0
#define HAVE_CLOCK_GETTIME 1
#define HAVE_CLOSESOCKET 0
#define HAVE_COMMANDLINETOARGVW 0
#define HAVE_COPYSIGN 1
#define HAVE_COSF 1
#define HAVE_CPUNOP 1
#define HAVE_CPUNOP_EXTERNAL 0
#define HAVE_CPUNOP_INLINE 0
#define HAVE_CUDA_H 0
#define HAVE_DCBZL 0
#define HAVE_DCBZL_EXTERNAL 0
#define HAVE_DCBZL_INLINE 0
#define HAVE_DEV_BKTR_IOCTL_BT848_H 0
#define HAVE_DEV_BKTR_IOCTL_METEOR_H 0
#define HAVE_DEV_IC_BT8XX_H 0
#define HAVE_DEV_VIDEO_BKTR_IOCTL_BT848_H 0
#define HAVE_DEV_VIDEO_METEOR_IOCTL_METEOR_H 0
#define HAVE_DIRECT_H 0
#define HAVE_DIRENT_H 1
#define HAVE_DISPATCH_DISPATCH_H 0
#define HAVE_DOS_PATHS 0
#define HAVE_DXGIDEBUG_H 0
#define HAVE_DXVA_H 0
#define HAVE_EBP_AVAILABLE 1
#define HAVE_EBX_AVAILABLE 1
#define HAVE_ERF 1
#define HAVE_ES2_GL_H 0
#define HAVE_EXP2 1
#define HAVE_EXP2F 1
#define HAVE_EXPF 1
#define HAVE_FAST_64BIT 1
#define HAVE_FAST_CLZ 1
#define HAVE_FAST_CMOV 1
#define HAVE_FAST_UNALIGNED 1
#define HAVE_FCNTL 1
#define HAVE_FMA3 1
#define HAVE_FMA3_EXTERNAL 0
#define HAVE_FMA3_INLINE 1
#define HAVE_FMA4 1
#define HAVE_FMA4_EXTERNAL 0
#define HAVE_FMA4_INLINE 1
#define HAVE_GETADDRINFO 1
#define HAVE_GETHRTIME 0
#define HAVE_GETMODULEHANDLE 0
#define HAVE_GETOPT 1
#define HAVE_GETPROCESSAFFINITYMASK 0
#define HAVE_GETPROCESSMEMORYINFO 0
#define HAVE_GETPROCESSTIMES 0
#define HAVE_GETRUSAGE 1
#define HAVE_GETSTDHANDLE 0
#define HAVE_GETSYSTEMTIMEASFILETIME 0
#define HAVE_GETTIMEOFDAY 1
#define HAVE_GLOB 1
#define HAVE_GLXGETPROCADDRESS 0
#define HAVE_GMTIME_R 1
#define HAVE_GNU_AS 0
#define HAVE_GNU_WINDRES 0
#define HAVE_GSM_H 0
#define HAVE_HYPOT 1
#define HAVE_I686 1
#define HAVE_I686_EXTERNAL 0
#define HAVE_I686_INLINE 0
#define HAVE_IBM_ASM 0
#define HAVE_INET_ATON 1
#define HAVE_INLINE_ASM 1
#define HAVE_INLINE_ASM_DIRECT_SYMBOL_REFS 1
#define HAVE_INLINE_ASM_LABELS 1
#define HAVE_INLINE_ASM_NONLOCAL_LABELS 1
#define HAVE_INTRINSICS_NEON 0
#define HAVE_IO_H 0
#define HAVE_ISATTY 1
#define HAVE_ISFINITE 1
#define HAVE_ISINF 1
#define HAVE_ISNAN 1
#define HAVE_KBHIT 0
#define HAVE_KCMVIDEOCODECTYPE_HEVC 0
#define HAVE_KCMVIDEOCODECTYPE_HEVCWITHALPHA 0
#define HAVE_KCVIMAGEBUFFERTRANSFERFUNCTION_ITU_R_2100_HLG 0
#define HAVE_KCVIMAGEBUFFERTRANSFERFUNCTION_LINEAR 0
#define HAVE_KCVIMAGEBUFFERTRANSFERFUNCTION_SMPTE_ST_2084_PQ 0
#define HAVE_KCVPIXELFORMATTYPE_420YPCBCR10BIPLANARVIDEORANGE 0
#define HAVE_LDBRX 0
#define HAVE_LDBRX_EXTERNAL 0
#define HAVE_LDBRX_INLINE 0
#define HAVE_LDEXPF 1
#define HAVE_LIBC_MSVCRT 0
#define HAVE_LIBDRM_GETFB2 0
#define HAVE_LINUX_DMA_BUF_H 0
#define HAVE_LINUX_PERF_EVENT_H 1
#define HAVE_LLRINT 1
#define HAVE_LLRINTF 1
#define HAVE_LOCALTIME_R 1
#define HAVE_LOCAL_ALIGNED 1
#define HAVE_LOG10F 1
#define HAVE_LOG2 1
#define HAVE_LOG2F 1
#define HAVE_LOONGSON2 0
#define HAVE_LOONGSON2_EXTERNAL 0
#define HAVE_LOONGSON2_INLINE 0
#define HAVE_LOONGSON3 0
#define HAVE_LOONGSON3_EXTERNAL 0
#define HAVE_LOONGSON3_INLINE 0
#define HAVE_LRINT 1
#define HAVE_LRINTF 1
#define HAVE_LSTAT 1
#define HAVE_LZO1X_999_COMPRESS 0
#define HAVE_MACHINE_IOCTL_BT848_H 0
#define HAVE_MACHINE_IOCTL_METEOR_H 0
#define HAVE_MACHINE_RW_BARRIER 0
#define HAVE_MACH_ABSOLUTE_TIME 0
#define HAVE_MAKEINFO 0
#define HAVE_MAKEINFO_HTML 0
#define HAVE_MALLOC_H 1
#define HAVE_MAPVIEWOFFILE 0
#define HAVE_MEMALIGN 1
#define HAVE_MEMORYBARRIER 0
#define HAVE_MIPS32R2 0
#define HAVE_MIPS32R2_EXTERNAL 0
#define HAVE_MIPS32R2_INLINE 0
#define HAVE_MIPS32R5 0
#define HAVE_MIPS32R5_EXTERNAL 0
#define HAVE_MIPS32R5_INLINE 0
#define HAVE_MIPS32R6 0
#define HAVE_MIPS32R6_EXTERNAL 0
#define HAVE_MIPS32R6_INLINE 0
#define HAVE_MIPS64R2 0
#define HAVE_MIPS64R2_EXTERNAL 0
#define HAVE_MIPS64R2_INLINE 0
#define HAVE_MIPS64R6 0
#define HAVE_MIPS64R6_EXTERNAL 0
#define HAVE_MIPS64R6_INLINE 0
#define HAVE_MIPSDSP 0
#define HAVE_MIPSDSPR2 0
#define HAVE_MIPSDSPR2_EXTERNAL 0
#define HAVE_MIPSDSPR2_INLINE 0
#define HAVE_MIPSDSP_EXTERNAL 0
#define HAVE_MIPSDSP_INLINE 0
#define HAVE_MIPSFPU 0
#define HAVE_MIPSFPU_EXTERNAL 0
#define HAVE_MIPSFPU_INLINE 0
#define HAVE_MKSTEMP 1
#define HAVE_MMAL_PARAMETER_VIDEO_MAX_NUM_CALLBACKS 0
#define HAVE_MMAP 1
#define HAVE_MMI 0
#define HAVE_MMI_EXTERNAL 0
#define HAVE_MMI_INLINE 0
#define HAVE_MMX 1
#define HAVE_MMX2 HAVE_MMXEXT
#define HAVE_MMXEXT 1
#define HAVE_MMXEXT_EXTERNAL 0
#define HAVE_MMXEXT_INLINE 1
#define HAVE_MMX_EXTERNAL 0
#define HAVE_MMX_INLINE 1
#define HAVE_MM_EMPTY 1
#define HAVE_MPROTECT 1
#define HAVE_MSA 0
#define HAVE_MSA_EXTERNAL 0
#define HAVE_MSA_INLINE 0
#define HAVE_NANOSLEEP 1
#define HAVE_NEON 0
#define HAVE_NEON_EXTERNAL 0
#define HAVE_NEON_INLINE 0
#define HAVE_OPENCL_D3D11 0
#define HAVE_OPENCL_DRM_ARM 0
#define HAVE_OPENCL_DRM_BEIGNET 0
#define HAVE_OPENCL_DXVA2 0
#define HAVE_OPENCL_VAAPI_BEIGNET 0
#define HAVE_OPENCL_VAAPI_INTEL_MEDIA 0
#define HAVE_OPENCV2_CORE_CORE_C_H 0
#define HAVE_OPENGL_GL3_H 0
#define HAVE_OS2THREADS 0
#define HAVE_PEEKNAMEDPIPE 0
#define HAVE_PERL 1
#define HAVE_POD2MAN 1
#define HAVE_POLL_H 1
#define HAVE_POSIX_MEMALIGN 1
#define HAVE_POWER8 0
#define HAVE_POWER8_EXTERNAL 0
#define HAVE_POWER8_INLINE 0
#define HAVE_POWF 1
#define HAVE_PPC4XX 0
#define HAVE_PPC4XX_EXTERNAL 0
#define HAVE_PPC4XX_INLINE 0
#define HAVE_PRAGMA_DEPRECATED 1
#define HAVE_PTHREADS 1
#define HAVE_PTHREAD_CANCEL 1
#define HAVE_RDTSC 0
#define HAVE_RINT 1
#define HAVE_ROUND 1
#define HAVE_ROUNDF 1
#define HAVE_RSYNC_CONTIMEOUT 1
#define HAVE_SCHED_GETAFFINITY 1
#define HAVE_SECITEMIMPORT 0
#define HAVE_SECTION_DATA_REL_RO 1
#define HAVE_SEM_TIMEDWAIT 1
#define HAVE_SETCONSOLECTRLHANDLER 0
#define HAVE_SETCONSOLETEXTATTRIBUTE 0
#define HAVE_SETDLLDIRECTORY 0
#define HAVE_SETEND 0
#define HAVE_SETEND_EXTERNAL 0
#define HAVE_SETEND_INLINE 0
#define HAVE_SETMODE 0
#define HAVE_SETRLIMIT 1
#define HAVE_SIMD_ALIGN_16 1
#define HAVE_SIMD_ALIGN_32 1
#define HAVE_SIMD_ALIGN_64 1
#define HAVE_SINF 1
#define HAVE_SLEEP 0
#define HAVE_SOCKLEN_T 1
#define HAVE_SSE 1
#define HAVE_SSE2 1
#define HAVE_SSE2_EXTERNAL 0
#define HAVE_SSE2_INLINE 1
#define HAVE_SSE3 1
#define HAVE_SSE3_EXTERNAL 0
#define HAVE_SSE3_INLINE 1
#define HAVE_SSE4 1
#define HAVE_SSE42 1
#define HAVE_SSE42_EXTERNAL 0
#define HAVE_SSE42_INLINE 1
#define HAVE_SSE4_EXTERNAL 0
#define HAVE_SSE4_INLINE 1
#define HAVE_SSE_EXTERNAL 0
#define HAVE_SSE_INLINE 1
#define HAVE_SSSE3 1
#define HAVE_SSSE3_EXTERNAL 0
#define HAVE_SSSE3_INLINE 1
#define HAVE_STRERROR_R 1
#define HAVE_STRUCT_ADDRINFO 1
#define HAVE_STRUCT_GROUP_SOURCE_REQ 1
#define HAVE_STRUCT_IPV6_MREQ 1
#define HAVE_STRUCT_IP_MREQ_SOURCE 1
#define HAVE_STRUCT_MSGHDR_MSG_FLAGS 1
#define HAVE_STRUCT_POLLFD 1
#define HAVE_STRUCT_RUSAGE_RU_MAXRSS 1
#define HAVE_STRUCT_SCTP_EVENT_SUBSCRIBE 1
#define HAVE_STRUCT_SOCKADDR_IN6 1
#define HAVE_STRUCT_SOCKADDR_SA_LEN 0
#define HAVE_STRUCT_SOCKADDR_STORAGE 1
#define HAVE_STRUCT_STAT_ST_MTIM_TV_NSEC 1
#define HAVE_STRUCT_V4L2_FRMIVALENUM_DISCRETE 1
#define HAVE_SYMVER 1
#define HAVE_SYMVER_ASM_LABEL 0
#define HAVE_SYMVER_GNU_ASM 1
#define HAVE_SYNC_VAL_COMPARE_AND_SWAP 1
#define HAVE_SYSCONF 1
#define HAVE_SYSCTL 1
#define HAVE_SYS_PARAM_H 1
#define HAVE_SYS_RESOURCE_H 1
#define HAVE_SYS_SELECT_H 1
#define HAVE_SYS_SOUNDCARD_H 1
#define HAVE_SYS_TIME_H 1
#define HAVE_SYS_UN_H 1
#define HAVE_SYS_VIDEOIO_H 0
#define HAVE_TERMIOS_H 1
#define HAVE_TEXI2HTML 0
#define HAVE_THREADS 1
#define HAVE_TRUNC 1
#define HAVE_TRUNCF 1
#define HAVE_UDPLITE_H 0
#define HAVE_UNISTD_H 1
#define HAVE_USLEEP 1
#define HAVE_UTGETOSTYPEFROMSTRING 0
#define HAVE_UWP 0
#define HAVE_VAAPI_DRM 0
#define HAVE_VAAPI_X11 0
#define HAVE_VALGRIND_VALGRIND_H 0
#define HAVE_VDPAU_X11 1
#define HAVE_VFP 0
#define HAVE_VFPV3 0
#define HAVE_VFPV3_EXTERNAL 0
#define HAVE_VFPV3_INLINE 0
#define HAVE_VFP_ARGS 0
#define HAVE_VFP_EXTERNAL 0
#define HAVE_VFP_INLINE 0
#define HAVE_VIRTUALALLOC 0
#define HAVE_VSX 0
#define HAVE_VSX_EXTERNAL 0
#define HAVE_VSX_INLINE 0
#define HAVE_W32THREADS 0
#define HAVE_WGLGETPROCADDRESS 0
#define HAVE_WINDOWS_H 0
#define HAVE_WINRT 0
#define HAVE_WINSOCK2_H 0
#define HAVE_X86ASM 0
#define HAVE_XFORM_ASM 0
#define HAVE_XMM_CLOBBERS 1
#define HAVE_XOP 1
#define HAVE_XOP_EXTERNAL 0
#define HAVE_XOP_INLINE 1
#define OS_NAME linux
#define SLIBSUF ".so"
#define SWS_MAX_FILTER_SIZE 256
#define av_restrict restrict

#   define AV_NE(be, le) (be)
#define FFABS(a) ((a) >= 0 ? (a) : (-(a)))
#define FFALIGN(x, a) (((x)+(a)-1)&~((a)-1))
#define FFMAX(a,b) ((a) > (b) ? (a) : (b))
#define FFMAX3(a,b,c) FFMAX(FFMAX(a,b),c)
#define FFMIN(a,b) ((a) > (b) ? (b) : (a))
#define FFMIN3(a,b,c) FFMIN(FFMIN(a,b),c)
#define FFSIGN(a) ((a) > 0 ? 1 : -1)
#define FFSWAP(type,a,b) do{type SWAP_tmp= b; b= a; a= SWAP_tmp;}while(0)
#define FF_ARRAY_ELEMS(a) (sizeof(a) / sizeof((a)[0]))
#define GET_UTF16(val, GET_16BIT, ERROR)\
    val = GET_16BIT;\
    {\
        unsigned int hi = val - 0xD800;\
        if (hi < 0x800) {\
            val = GET_16BIT - 0xDC00;\
            if (val > 0x3FFU || hi > 0x3FFU)\
                ERROR\
            val += (hi<<10) + 0x10000;\
        }\
    }\

#define GET_UTF8(val, GET_BYTE, ERROR)\
    val= GET_BYTE;\
    {\
        uint32_t top = (val & 128) >> 1;\
        if ((val & 0xc0) == 0x80)\
            ERROR\
        while (val & top) {\
            int tmp= GET_BYTE - 128;\
            if(tmp>>6)\
                ERROR\
            val= (val<<6) + tmp;\
            top <<= 5;\
        }\
        val &= (top << 1) - 1;\
    }
#define MKBETAG(a,b,c,d) ((d) | ((c) << 8) | ((b) << 16) | ((unsigned)(a) << 24))
#define MKTAG(a,b,c,d) ((a) | ((b) << 8) | ((c) << 16) | ((unsigned)(d) << 24))
#define PUT_UTF16(val, tmp, PUT_16BIT)\
    {\
        uint32_t in = val;\
        if (in < 0x10000) {\
            tmp = in;\
            PUT_16BIT\
        } else {\
            tmp = 0xD800 | ((in - 0x10000) >> 10);\
            PUT_16BIT\
            tmp = 0xDC00 | ((in - 0x10000) & 0x3FF);\
            PUT_16BIT\
        }\
    }\

#define PUT_UTF8(val, tmp, PUT_BYTE)\
    {\
        int bytes, shift;\
        uint32_t in = val;\
        if (in < 0x80) {\
            tmp = in;\
            PUT_BYTE\
        } else {\
            bytes = (av_log2(in) + 4) / 5;\
            shift = (bytes - 1) * 6;\
            tmp = (256 - (256 >> bytes)) | (in >> shift);\
            PUT_BYTE\
            while (shift >= 6) {\
                shift -= 6;\
                tmp = 0x80 | ((in >> shift) & 0x3f);\
                PUT_BYTE\
            }\
        }\
    }
#define ROUNDED_DIV(a,b) (((a)>0 ? (a) + ((b)>>1) : (a) - ((b)>>1))/(b))
#define RSHIFT(a,b) ((a) > 0 ? ((a) + ((1<<(b))>>1))>>(b) : ((a) + ((1<<(b))>>1)-1)>>(b))
#   define av_ceil_log2     av_ceil_log2_c
#   define av_clip          av_clip_c
#   define av_clip_int16    av_clip_int16_c
#   define av_clip_int8     av_clip_int8_c
#   define av_clip_uint16   av_clip_uint16_c
#   define av_clip_uint8    av_clip_uint8_c
#   define av_clip_uintp2   av_clip_uintp2_c
#   define av_clipf         av_clipf_c
#   define av_clipl_int32   av_clipl_int32_c
#   define av_popcount      av_popcount_c
#   define av_popcount64    av_popcount64_c
#   define av_sat_add32     av_sat_add32_c
#   define av_sat_dadd32    av_sat_dadd32_c

#define AV_HAVE_BIGENDIAN 0
#define AV_HAVE_FAST_UNALIGNED 1

#define AV_LOG_DEBUG    48
#define AV_LOG_ERROR    16
#define AV_LOG_FATAL     8
#define AV_LOG_INFO     32
#define AV_LOG_PANIC     0
#define AV_LOG_QUIET    -8
#define AV_LOG_SKIP_REPEATED 1
#define AV_LOG_VERBOSE  40
#define AV_LOG_WARNING  24
#    define av_dlog(pctx, ...) av_log(pctx, AV_LOG_DEBUG, __VA_ARGS__)

#define AV_COPY(n, d, s) \
    (((av_alias##n*)(d))->u##n = ((const av_alias##n*)(s))->u##n)
#   define AV_COPY128(d, s)                    \
    do {                                       \
        AV_COPY64(d, s);                       \
        AV_COPY64((char*)(d)+8, (char*)(s)+8); \
    } while(0)
#   define AV_COPY128U(d, s)                                    \
    do {                                                        \
        AV_COPY64U(d, s);                                       \
        AV_COPY64U((char *)(d) + 8, (const char *)(s) + 8);     \
    } while(0)
#   define AV_COPY16(d, s) AV_COPY(16, d, s)
#   define AV_COPY16U(d, s) AV_COPYU(16, d, s)
#   define AV_COPY32(d, s) AV_COPY(32, d, s)
#   define AV_COPY32U(d, s) AV_COPYU(32, d, s)
#   define AV_COPY64(d, s) AV_COPY(64, d, s)
#   define AV_COPY64U(d, s) AV_COPYU(64, d, s)
#define AV_COPYU(n, d, s) AV_WN##n(d, AV_RN##n(s));
#   define AV_RB(s, p)    AV_RN##s(p)
#       define AV_RB16(p) AV_RN16(p)
#       define AV_RB24(p) AV_RN24(p)
#       define AV_RB32(p) AV_RN32(p)
#       define AV_RB64(p) AV_RN64(p)
#define AV_RB8(x)     (((const uint8_t*)(x))[0])
#   define AV_RL(s, p)    av_bswap##s(AV_RN##s(p))
#       define AV_RL16(p) AV_RN16(p)
#       define AV_RL24(p) AV_RN24(p)
#       define AV_RL32(p) AV_RN32(p)
#       define AV_RL64(p) AV_RN64(p)
#define AV_RL8(x)     AV_RB8(x)
#   define AV_RN(s, p) (((const union unaligned_##s *) (p))->l)
#       define AV_RN16(p) AV_RL16(p)
#   define AV_RN16A(p) AV_RNA(16, p)
#       define AV_RN24(p) AV_RL24(p)
#       define AV_RN32(p) AV_RB32(p)
#   define AV_RN32A(p) AV_RNA(32, p)
#       define AV_RN64(p) AV_RB64(p)
#   define AV_RN64A(p) AV_RNA(64, p)
#define AV_RNA(s, p)    (((const av_alias##s*)(p))->u##s)
#define AV_SWAP(n, a, b) FFSWAP(av_alias##n, *(av_alias##n*)(a), *(av_alias##n*)(b))
#   define AV_SWAP64(a, b) AV_SWAP(64, a, b)
#   define AV_WB(s, p, v) AV_WN##s(p, v)
#       define AV_WB16(p, v) AV_WN16(p, v)
#       define AV_WB24(p, v) AV_WN24(p, v)
#       define AV_WB32(p, v) AV_WN32(p, v)
#       define AV_WB64(p, v) AV_WN64(p, v)
#define AV_WB8(p, d)  do { ((uint8_t*)(p))[0] = (d); } while(0)
#   define AV_WL(s, p, v) AV_WN##s(p, av_bswap##s(v))
#       define AV_WL16(p, v) AV_WN16(p, v)
#       define AV_WL24(p, v) AV_WN24(p, v)
#       define AV_WL32(p, v) AV_WN32(p, v)
#       define AV_WL64(p, v) AV_WN64(p, v)
#define AV_WL8(p, d)  AV_WB8(p, d)
#   define AV_WN(s, p, v) ((((union unaligned_##s *) (p))->l) = (v))
#       define AV_WN16(p, v) AV_WL16(p, v)
#   define AV_WN16A(p, v) AV_WNA(16, p, v)
#       define AV_WN24(p, v) AV_WB24(p, v)
#       define AV_WN32(p, v) AV_WB32(p, v)
#   define AV_WN32A(p, v) AV_WNA(32, p, v)
#       define AV_WN64(p, v) AV_WB64(p, v)
#   define AV_WN64A(p, v) AV_WNA(64, p, v)
#define AV_WNA(s, p, v) (((av_alias##s*)(p))->u##s = (v))
#define AV_ZERO(n, d) (((av_alias##n*)(d))->u##n = 0)
#   define AV_ZERO128(d)         \
    do {                         \
        AV_ZERO64(d);            \
        AV_ZERO64((char*)(d)+8); \
    } while(0)
#   define AV_ZERO16(d) AV_ZERO(16, d)
#   define AV_ZERO32(d) AV_ZERO(32, d)
#   define AV_ZERO64(d) AV_ZERO(64, d)



#define END_NOT_FOUND (-100)

#define AVCODEC_MAX_AUDIO_FRAME_SIZE 192000 
#define AVPALETTE_COUNT 256
#define AVPALETTE_SIZE 1024
#define AV_CODEC_PROP_INTRA_ONLY    (1 << 0)
#define AV_CODEC_PROP_LOSSLESS      (1 << 2)
#define AV_CODEC_PROP_LOSSY         (1 << 1)
#define AV_EF_BITSTREAM (1<<1)
#define AV_EF_BUFFER    (1<<2)
#define AV_EF_CRCCHECK  (1<<0)
#define AV_EF_EXPLODE   (1<<3)
#define AV_NUM_DATA_POINTERS 8
#define AV_PARSER_PTS_NB 4
#define AV_PKT_FLAG_CORRUPT 0x0002 
#define AV_PKT_FLAG_KEY     0x0001 
#define AV_SUBTITLE_FLAG_FORCED 0x00000001
#define CODEC_CAP_AUTO_THREADS     0x8000
#define CODEC_CAP_CHANNEL_CONF     0x0400
#define CODEC_CAP_DELAY           0x0020
#define CODEC_CAP_DR1             0x0002
#define CODEC_CAP_DRAW_HORIZ_BAND 0x0001 
#define CODEC_CAP_EXPERIMENTAL     0x0200
#define CODEC_CAP_FRAME_THREADS    0x1000
#define CODEC_CAP_HWACCEL         0x0010
#define CODEC_CAP_HWACCEL_VDPAU    0x0080
#define CODEC_CAP_NEG_LINESIZES    0x0800
#define CODEC_CAP_PARAM_CHANGE     0x4000
#define CODEC_CAP_SLICE_THREADS    0x2000
#define CODEC_CAP_SMALL_LAST_FRAME 0x0040
#define CODEC_CAP_SUBFRAMES        0x0100
#define CODEC_CAP_TRUNCATED       0x0008
#define CODEC_CAP_VARIABLE_FRAME_SIZE 0x10000
#define CODEC_FLAG2_CHUNKS        0x00008000 
#define CODEC_FLAG2_FAST          0x00000001 
#define CODEC_FLAG2_LOCAL_HEADER  0x00000008 
#define CODEC_FLAG2_NO_OUTPUT     0x00000004 
#define CODEC_FLAG2_SKIP_RD       0x00004000 
#define CODEC_FLAG2_STRICT_GOP    0x00000002 
#define CODEC_FLAG_4MV    0x0004  
#define CODEC_FLAG_AC_PRED        0x01000000 
#define CODEC_FLAG_BITEXACT       0x00800000 
#define CODEC_FLAG_CBP_RD         0x04000000 
#define CODEC_FLAG_CLOSED_GOP     0x80000000
#define CODEC_FLAG_EMU_EDGE        0x4000   
#define CODEC_FLAG_GLOBAL_HEADER  0x00400000 
#define CODEC_FLAG_GMC    0x0020  
#define CODEC_FLAG_GRAY            0x2000   
#define CODEC_FLAG_INPUT_PRESERVED 0x0100
#define CODEC_FLAG_INTERLACED_DCT 0x00040000 
#define CODEC_FLAG_INTERLACED_ME  0x20000000 
#define CODEC_FLAG_LOOP_FILTER    0x00000800 
#define CODEC_FLAG_LOW_DELAY      0x00080000 
#define CODEC_FLAG_MV0    0x0040  
#define CODEC_FLAG_NORMALIZE_AQP  0x00020000 
#define CODEC_FLAG_PASS1           0x0200   
#define CODEC_FLAG_PASS2           0x0400   
#define CODEC_FLAG_PSNR            0x8000   
#define CODEC_FLAG_QPEL   0x0010  
#define CODEC_FLAG_QP_RD          0x08000000 
#define CODEC_FLAG_QSCALE 0x0002  
#define CODEC_FLAG_TRUNCATED       0x00010000 
#define CodecID AVCodecID
#define FF_ASPECT_EXTENDED 15
#define FF_BUFFER_HINTS_PRESERVE 0x04 
#define FF_BUFFER_HINTS_READABLE 0x02 
#define FF_BUFFER_HINTS_REUSABLE 0x08 
#define FF_BUFFER_HINTS_VALID    0x01 
#define FF_BUFFER_TYPE_COPY     8 
#define FF_BUFFER_TYPE_INTERNAL 1
#define FF_BUFFER_TYPE_SHARED   4 
#define FF_BUFFER_TYPE_USER     2 
#define FF_BUG_AC_VLC           0  
#define FF_BUG_AMV              32
#define FF_BUG_AUTODETECT       1  
#define FF_BUG_DC_CLIP          4096
#define FF_BUG_DIRECT_BLOCKSIZE 512
#define FF_BUG_EDGE             1024
#define FF_BUG_HPEL_CHROMA      2048
#define FF_BUG_MS               8192 
#define FF_BUG_NO_PADDING       16
#define FF_BUG_OLD_MSMPEG4      2
#define FF_BUG_QPEL_CHROMA      64
#define FF_BUG_QPEL_CHROMA2     256
#define FF_BUG_STD_QPEL         128
#define FF_BUG_TRUNCATED       16384
#define FF_BUG_UMP4             8
#define FF_BUG_XVID_ILACE       4
#define FF_CMP_BIT    5
#define FF_CMP_CHROMA 256
#define FF_CMP_DCT    3
#define FF_CMP_DCT264 14
#define FF_CMP_DCTMAX 13
#define FF_CMP_NSSE   10
#define FF_CMP_PSNR   4
#define FF_CMP_RD     6
#define FF_CMP_SAD    0
#define FF_CMP_SATD   2
#define FF_CMP_SSE    1
#define FF_CMP_VSAD   8
#define FF_CMP_VSSE   9
#define FF_CMP_W53    11
#define FF_CMP_W97    12
#define FF_CMP_ZERO   7
#define FF_CODER_TYPE_AC        1
#define FF_CODER_TYPE_DEFLATE   4
#define FF_CODER_TYPE_RAW       2
#define FF_CODER_TYPE_RLE       3
#define FF_CODER_TYPE_VLC       0
#define FF_COMPLIANCE_EXPERIMENTAL -2 
#define FF_COMPLIANCE_NORMAL        0
#define FF_COMPLIANCE_STRICT        1 
#define FF_COMPLIANCE_UNOFFICIAL   -1 
#define FF_COMPLIANCE_VERY_STRICT   2 
#define FF_COMPRESSION_DEFAULT -1
#define FF_DCT_ALTIVEC 5
#define FF_DCT_AUTO    0
#define FF_DCT_FAAN    6
#define FF_DCT_FASTINT 1
#define FF_DCT_INT     2
#define FF_DCT_MMX     3
#define FF_DEBUG_BITSTREAM   4
#define FF_DEBUG_BUFFERS     0x00008000
#define FF_DEBUG_BUGS        0x00001000
#define FF_DEBUG_DCT_COEFF   0x00000040
#define FF_DEBUG_ER          0x00000400
#define FF_DEBUG_MB_TYPE     8
#define FF_DEBUG_MMCO        0x00000800
#define FF_DEBUG_MV          32
#define FF_DEBUG_PICT_INFO   1
#define FF_DEBUG_PTS         0x00000200
#define FF_DEBUG_QP          16
#define FF_DEBUG_RC          2
#define FF_DEBUG_SKIP        0x00000080
#define FF_DEBUG_STARTCODE   0x00000100
#define FF_DEBUG_THREADS     0x00010000
#define FF_DEBUG_VIS_MB_TYPE 0x00004000
#define FF_DEBUG_VIS_MV_B_BACK 0x00000004 
#define FF_DEBUG_VIS_MV_B_FOR  0x00000002 
#define FF_DEBUG_VIS_MV_P_FOR  0x00000001 
#define FF_DEBUG_VIS_QP      0x00002000
#define FF_DEFAULT_QUANT_BIAS 999999
#define FF_DTG_AFD_14_9         11
#define FF_DTG_AFD_16_9         10
#define FF_DTG_AFD_16_9_SP_14_9 14
#define FF_DTG_AFD_4_3          9
#define FF_DTG_AFD_4_3_SP_14_9  13
#define FF_DTG_AFD_SAME         8
#define FF_DTG_AFD_SP_4_3       15
#define FF_EC_DEBLOCK     2
#define FF_EC_GUESS_MVS   1
#define FF_IDCT_ALTIVEC       8
#define FF_IDCT_ARM           7
#define FF_IDCT_AUTO          0
#define FF_IDCT_BINK          24
#define FF_IDCT_CAVS          15
#define FF_IDCT_EA            21
#define FF_IDCT_FAAN          20
#define FF_IDCT_H264          11
#define FF_IDCT_INT           1
#define FF_IDCT_IPP           13
#define FF_IDCT_LIBMPEG2MMX   4
#define FF_IDCT_MMI           5
#define FF_IDCT_SH4           9
#define FF_IDCT_SIMPLE        2
#define FF_IDCT_SIMPLEALPHA   23
#define FF_IDCT_SIMPLEARM     10
#define FF_IDCT_SIMPLEARMV5TE 16
#define FF_IDCT_SIMPLEARMV6   17
#define FF_IDCT_SIMPLEMMX     3
#define FF_IDCT_SIMPLENEON    22
#define FF_IDCT_SIMPLEVIS     18
#define FF_IDCT_VP3           12
#define FF_IDCT_WMV2          19
#define FF_IDCT_XVIDMMX       14
#define FF_INPUT_BUFFER_PADDING_SIZE 8
#define FF_LEVEL_UNKNOWN -99
#define FF_LOSS_ALPHA       0x0008 
#define FF_LOSS_CHROMA      0x0020 
#define FF_LOSS_COLORQUANT  0x0010 
#define FF_LOSS_COLORSPACE  0x0004 
#define FF_LOSS_DEPTH       0x0002 
#define FF_LOSS_RESOLUTION  0x0001 
#define FF_MAX_B_FRAMES 16
#define FF_MB_DECISION_BITS   1        
#define FF_MB_DECISION_RD     2        
#define FF_MB_DECISION_SIMPLE 0        
#define FF_MIN_BUFFER_SIZE 16384
#define FF_PRED_LEFT   0
#define FF_PRED_MEDIAN 2
#define FF_PRED_PLANE  1
#define FF_PROFILE_AAC_ELD  38
#define FF_PROFILE_AAC_HE   4
#define FF_PROFILE_AAC_HE_V2 28
#define FF_PROFILE_AAC_LD   22
#define FF_PROFILE_AAC_LOW  1
#define FF_PROFILE_AAC_LTP  3
#define FF_PROFILE_AAC_MAIN 0
#define FF_PROFILE_AAC_SSR  2
#define FF_PROFILE_DTS         20
#define FF_PROFILE_DTS_96_24   40
#define FF_PROFILE_DTS_ES      30
#define FF_PROFILE_DTS_HD_HRA  50
#define FF_PROFILE_DTS_HD_MA   60
#define FF_PROFILE_H264_BASELINE             66
#define FF_PROFILE_H264_CAVLC_444            44
#define FF_PROFILE_H264_CONSTRAINED  (1<<9)  
#define FF_PROFILE_H264_CONSTRAINED_BASELINE (66|FF_PROFILE_H264_CONSTRAINED)
#define FF_PROFILE_H264_EXTENDED             88
#define FF_PROFILE_H264_HIGH                 100
#define FF_PROFILE_H264_HIGH_10              110
#define FF_PROFILE_H264_HIGH_10_INTRA        (110|FF_PROFILE_H264_INTRA)
#define FF_PROFILE_H264_HIGH_422             122
#define FF_PROFILE_H264_HIGH_422_INTRA       (122|FF_PROFILE_H264_INTRA)
#define FF_PROFILE_H264_HIGH_444             144
#define FF_PROFILE_H264_HIGH_444_INTRA       (244|FF_PROFILE_H264_INTRA)
#define FF_PROFILE_H264_HIGH_444_PREDICTIVE  244
#define FF_PROFILE_H264_INTRA        (1<<11) 
#define FF_PROFILE_H264_MAIN                 77
#define FF_PROFILE_MPEG2_422    0
#define FF_PROFILE_MPEG2_HIGH   1
#define FF_PROFILE_MPEG2_MAIN   4
#define FF_PROFILE_MPEG2_SIMPLE 5
#define FF_PROFILE_MPEG2_SNR_SCALABLE  3
#define FF_PROFILE_MPEG2_SS     2
#define FF_PROFILE_MPEG4_ADVANCED_CODING           11
#define FF_PROFILE_MPEG4_ADVANCED_CORE             12
#define FF_PROFILE_MPEG4_ADVANCED_REAL_TIME         9
#define FF_PROFILE_MPEG4_ADVANCED_SCALABLE_TEXTURE 13
#define FF_PROFILE_MPEG4_ADVANCED_SIMPLE           15
#define FF_PROFILE_MPEG4_BASIC_ANIMATED_TEXTURE     7
#define FF_PROFILE_MPEG4_CORE                       2
#define FF_PROFILE_MPEG4_CORE_SCALABLE             10
#define FF_PROFILE_MPEG4_HYBRID                     8
#define FF_PROFILE_MPEG4_MAIN                       3
#define FF_PROFILE_MPEG4_N_BIT                      4
#define FF_PROFILE_MPEG4_SCALABLE_TEXTURE           5
#define FF_PROFILE_MPEG4_SIMPLE                     0
#define FF_PROFILE_MPEG4_SIMPLE_FACE_ANIMATION      6
#define FF_PROFILE_MPEG4_SIMPLE_SCALABLE            1
#define FF_PROFILE_MPEG4_SIMPLE_STUDIO             14
#define FF_PROFILE_RESERVED -100
#define FF_PROFILE_UNKNOWN -99
#define FF_PROFILE_VC1_ADVANCED 3
#define FF_PROFILE_VC1_COMPLEX  2
#define FF_PROFILE_VC1_MAIN     1
#define FF_PROFILE_VC1_SIMPLE   0
#define FF_QSCALE_TYPE_H264  2
#define FF_QSCALE_TYPE_MPEG1 0
#define FF_QSCALE_TYPE_MPEG2 1
#define FF_QSCALE_TYPE_VP56  3
#define FF_RC_STRATEGY_XVID 1
#define FF_THREAD_FRAME   1 
#define FF_THREAD_SLICE   2 
#define MB_TYPE_16x16      0x0008
#define MB_TYPE_16x8       0x0010
#define MB_TYPE_8x16       0x0020
#define MB_TYPE_8x8        0x0040
#define MB_TYPE_ACPRED     0x0200
#define MB_TYPE_CBP        0x00020000
#define MB_TYPE_DIRECT2    0x0100 
#define MB_TYPE_GMC        0x0400
#define MB_TYPE_INTERLACED 0x0080
#define MB_TYPE_INTRA16x16 0x0002 
#define MB_TYPE_INTRA4x4   0x0001
#define MB_TYPE_INTRA_PCM  0x0004 
#define MB_TYPE_L0         (MB_TYPE_P0L0 | MB_TYPE_P1L0)
#define MB_TYPE_L0L1       (MB_TYPE_L0   | MB_TYPE_L1)
#define MB_TYPE_L1         (MB_TYPE_P0L1 | MB_TYPE_P1L1)
#define MB_TYPE_P0L0       0x1000
#define MB_TYPE_P0L1       0x4000
#define MB_TYPE_P1L0       0x2000
#define MB_TYPE_P1L1       0x8000
#define MB_TYPE_QUANT      0x00010000
#define MB_TYPE_SKIP       0x0800
#define PARSER_FLAG_COMPLETE_FRAMES           0x0001
#define PARSER_FLAG_FETCHED_OFFSET            0x0004
#define PARSER_FLAG_ONCE                      0x0002
#define SLICE_FLAG_ALLOW_FIELD    0x0002 
#define SLICE_FLAG_ALLOW_PLANE    0x0004 
#define SLICE_FLAG_CODED_ORDER    0x0001 


#define FF_API_AVCODEC_RESAMPLE  (LIBAVCODEC_VERSION_MAJOR < 55)
#define FF_API_CODEC_ID          (LIBAVCODEC_VERSION_MAJOR < 55)
#define FF_API_COLOR_TABLE_ID   (LIBAVCODEC_VERSION_MAJOR < 55)
#define FF_API_DSP_MASK         (LIBAVCODEC_VERSION_MAJOR < 55)
#define FF_API_FIND_BEST_PIX_FMT (LIBAVCODEC_VERSION_MAJOR < 55)
#define FF_API_INTER_THRESHOLD  (LIBAVCODEC_VERSION_MAJOR < 55)
#define FF_API_LIBMPEG2          (LIBAVCODEC_VERSION_MAJOR < 55)
#define FF_API_MMI               (LIBAVCODEC_VERSION_MAJOR < 55)
#define FF_API_MPV_GLOBAL_OPTS  (LIBAVCODEC_VERSION_MAJOR < 55)
#define FF_API_OLD_DECODE_AUDIO (LIBAVCODEC_VERSION_MAJOR < 55)
#define FF_API_OLD_ENCODE_AUDIO (LIBAVCODEC_VERSION_MAJOR < 55)
#define FF_API_OLD_ENCODE_VIDEO (LIBAVCODEC_VERSION_MAJOR < 55)
#define FF_API_REQUEST_CHANNELS (LIBAVCODEC_VERSION_MAJOR < 55)
#define FF_API_SUB_ID           (LIBAVCODEC_VERSION_MAJOR < 55)
#define FF_API_VDA_ASYNC         (LIBAVCODEC_VERSION_MAJOR < 55)
#define LIBAVCODEC_BUILD        LIBAVCODEC_VERSION_INT
#define LIBAVCODEC_IDENT        "Lavc" AV_STRINGIFY(LIBAVCODEC_VERSION)
#define LIBAVCODEC_VERSION      AV_VERSION(LIBAVCODEC_VERSION_MAJOR,    \
                                           LIBAVCODEC_VERSION_MINOR,    \
                                           LIBAVCODEC_VERSION_MICRO)
#define LIBAVCODEC_VERSION_INT  AV_VERSION_INT(LIBAVCODEC_VERSION_MAJOR, \
                                               LIBAVCODEC_VERSION_MINOR, \
                                               LIBAVCODEC_VERSION_MICRO)
#define LIBAVCODEC_VERSION_MAJOR 54
#define LIBAVCODEC_VERSION_MICRO  1
#define LIBAVCODEC_VERSION_MINOR 34

#define AV_PIX_FMT_BGR32   AV_PIX_FMT_NE(ABGR, RGBA)
#define AV_PIX_FMT_BGR32_1 AV_PIX_FMT_NE(BGRA, ARGB)
#define AV_PIX_FMT_BGR444 AV_PIX_FMT_NE(BGR444BE, BGR444LE)
#define AV_PIX_FMT_BGR48  AV_PIX_FMT_NE(BGR48BE,  BGR48LE)
#define AV_PIX_FMT_BGR555 AV_PIX_FMT_NE(BGR555BE, BGR555LE)
#define AV_PIX_FMT_BGR565 AV_PIX_FMT_NE(BGR565BE, BGR565LE)
#define AV_PIX_FMT_GBRP10    AV_PIX_FMT_NE(GBRP10BE,    GBRP10LE)
#define AV_PIX_FMT_GBRP16    AV_PIX_FMT_NE(GBRP16BE,    GBRP16LE)
#define AV_PIX_FMT_GBRP9     AV_PIX_FMT_NE(GBRP9BE ,    GBRP9LE)
#define AV_PIX_FMT_GRAY16 AV_PIX_FMT_NE(GRAY16BE, GRAY16LE)
#   define AV_PIX_FMT_NE(be, le) AV_PIX_FMT_##be
#define AV_PIX_FMT_RGB32   AV_PIX_FMT_NE(ARGB, BGRA)
#define AV_PIX_FMT_RGB32_1 AV_PIX_FMT_NE(RGBA, ABGR)
#define AV_PIX_FMT_RGB444 AV_PIX_FMT_NE(RGB444BE, RGB444LE)
#define AV_PIX_FMT_RGB48  AV_PIX_FMT_NE(RGB48BE,  RGB48LE)
#define AV_PIX_FMT_RGB555 AV_PIX_FMT_NE(RGB555BE, RGB555LE)
#define AV_PIX_FMT_RGB565 AV_PIX_FMT_NE(RGB565BE, RGB565LE)
#define AV_PIX_FMT_YUV420P10 AV_PIX_FMT_NE(YUV420P10BE, YUV420P10LE)
#define AV_PIX_FMT_YUV420P16 AV_PIX_FMT_NE(YUV420P16BE, YUV420P16LE)
#define AV_PIX_FMT_YUV420P9  AV_PIX_FMT_NE(YUV420P9BE , YUV420P9LE)
#define AV_PIX_FMT_YUV422P10 AV_PIX_FMT_NE(YUV422P10BE, YUV422P10LE)
#define AV_PIX_FMT_YUV422P16 AV_PIX_FMT_NE(YUV422P16BE, YUV422P16LE)
#define AV_PIX_FMT_YUV422P9  AV_PIX_FMT_NE(YUV422P9BE , YUV422P9LE)
#define AV_PIX_FMT_YUV444P10 AV_PIX_FMT_NE(YUV444P10BE, YUV444P10LE)
#define AV_PIX_FMT_YUV444P16 AV_PIX_FMT_NE(YUV444P16BE, YUV444P16LE)
#define AV_PIX_FMT_YUV444P9  AV_PIX_FMT_NE(YUV444P9BE , YUV444P9LE)
#define AV_PIX_FMT_YUVA420P10 AV_PIX_FMT_NE(YUVA420P10BE, YUVA420P10LE)
#define AV_PIX_FMT_YUVA420P16 AV_PIX_FMT_NE(YUVA420P16BE, YUVA420P16LE)
#define AV_PIX_FMT_YUVA420P9  AV_PIX_FMT_NE(YUVA420P9BE , YUVA420P9LE)
#define AV_PIX_FMT_YUVA422P10 AV_PIX_FMT_NE(YUVA422P10BE, YUVA422P10LE)
#define AV_PIX_FMT_YUVA422P16 AV_PIX_FMT_NE(YUVA422P16BE, YUVA422P16LE)
#define AV_PIX_FMT_YUVA422P9  AV_PIX_FMT_NE(YUVA422P9BE , YUVA422P9LE)
#define AV_PIX_FMT_YUVA444P10 AV_PIX_FMT_NE(YUVA444P10BE, YUVA444P10LE)
#define AV_PIX_FMT_YUVA444P16 AV_PIX_FMT_NE(YUVA444P16BE, YUVA444P16LE)
#define AV_PIX_FMT_YUVA444P9  AV_PIX_FMT_NE(YUVA444P9BE , YUVA444P9LE)
#define PIX_FMT_BGR32   AV_PIX_FMT_BGR32
#define PIX_FMT_BGR32_1 AV_PIX_FMT_BGR32_1
#define PIX_FMT_BGR444 AV_PIX_FMT_BGR444
#define PIX_FMT_BGR48  AV_PIX_FMT_BGR48
#define PIX_FMT_BGR555 AV_PIX_FMT_BGR555
#define PIX_FMT_BGR565 AV_PIX_FMT_BGR565
#define PIX_FMT_GBRP10 AV_PIX_FMT_GBRP10
#define PIX_FMT_GBRP16 AV_PIX_FMT_GBRP16
#define PIX_FMT_GBRP9  AV_PIX_FMT_GBRP9
#define PIX_FMT_GRAY16 AV_PIX_FMT_GRAY16
#define PIX_FMT_NE(be, le) AV_PIX_FMT_NE(be, le)
#define PIX_FMT_RGB32   AV_PIX_FMT_RGB32
#define PIX_FMT_RGB32_1 AV_PIX_FMT_RGB32_1
#define PIX_FMT_RGB444 AV_PIX_FMT_RGB444
#define PIX_FMT_RGB48  AV_PIX_FMT_RGB48
#define PIX_FMT_RGB555 AV_PIX_FMT_RGB555
#define PIX_FMT_RGB565 AV_PIX_FMT_RGB565
#define PIX_FMT_YUV420P10 AV_PIX_FMT_YUV420P10
#define PIX_FMT_YUV420P16 AV_PIX_FMT_YUV420P16
#define PIX_FMT_YUV420P9  AV_PIX_FMT_YUV420P9
#define PIX_FMT_YUV422P10 AV_PIX_FMT_YUV422P10
#define PIX_FMT_YUV422P16 AV_PIX_FMT_YUV422P16
#define PIX_FMT_YUV422P9  AV_PIX_FMT_YUV422P9
#define PIX_FMT_YUV444P10 AV_PIX_FMT_YUV444P10
#define PIX_FMT_YUV444P16 AV_PIX_FMT_YUV444P16
#define PIX_FMT_YUV444P9  AV_PIX_FMT_YUV444P9
#define PixelFormat AVPixelFormat

#define FF_API_AUDIOCONVERT             (LIBAVUTIL_VERSION_MAJOR < 53)
#define FF_API_AV_REVERSE               (LIBAVUTIL_VERSION_MAJOR < 53)
#define FF_API_CONTEXT_SIZE             (LIBAVUTIL_VERSION_MAJOR < 53)
#define FF_API_CPU_FLAG_MMX2            (LIBAVUTIL_VERSION_MAJOR < 53)
#define FF_API_PIX_FMT                  (LIBAVUTIL_VERSION_MAJOR < 53)
#define FF_API_PIX_FMT_DESC             (LIBAVUTIL_VERSION_MAJOR < 53)
#define LIBAVUTIL_BUILD         LIBAVUTIL_VERSION_INT
#define LIBAVUTIL_IDENT         "Lavu" AV_STRINGIFY(LIBAVUTIL_VERSION)
#define LIBAVUTIL_VERSION       AV_VERSION(LIBAVUTIL_VERSION_MAJOR,     \
                                           LIBAVUTIL_VERSION_MINOR,     \
                                           LIBAVUTIL_VERSION_MICRO)
#define LIBAVUTIL_VERSION_INT   AV_VERSION_INT(LIBAVUTIL_VERSION_MAJOR, \
                                               LIBAVUTIL_VERSION_MINOR, \
                                               LIBAVUTIL_VERSION_MICRO)
#define LIBAVUTIL_VERSION_MAJOR 52
#define LIBAVUTIL_VERSION_MICRO  0
#define LIBAVUTIL_VERSION_MINOR  2

#define AV_DICT_APPEND         32   
#define AV_DICT_DONT_OVERWRITE 16   
#define AV_DICT_DONT_STRDUP_KEY 4   
#define AV_DICT_DONT_STRDUP_VAL 8   
#define AV_DICT_IGNORE_SUFFIX   2
#define AV_DICT_MATCH_CASE      1

#define AV_CPU_FLAG_3DNOW        0x0004 
#define AV_CPU_FLAG_3DNOWEXT     0x0020 
#define AV_CPU_FLAG_ALTIVEC      0x0001 
#define AV_CPU_FLAG_ARMV5TE      (1 << 0)
#define AV_CPU_FLAG_ARMV6        (1 << 1)
#define AV_CPU_FLAG_ARMV6T2      (1 << 2)
#define AV_CPU_FLAG_ATOM     0x10000000 
#define AV_CPU_FLAG_AVX          0x4000 
#define AV_CPU_FLAG_CMOV         0x1000 
#define AV_CPU_FLAG_FMA4         0x0800 
#define AV_CPU_FLAG_FORCE    0x80000000 
#define AV_CPU_FLAG_MMX          0x0001 
#define AV_CPU_FLAG_MMX2         0x0002 
#define AV_CPU_FLAG_MMXEXT       0x0002 
#define AV_CPU_FLAG_NEON         (1 << 5)
#define AV_CPU_FLAG_SSE          0x0008 
#define AV_CPU_FLAG_SSE2         0x0010 
#define AV_CPU_FLAG_SSE2SLOW 0x40000000 
#define AV_CPU_FLAG_SSE3         0x0040 
#define AV_CPU_FLAG_SSE3SLOW 0x20000000 
#define AV_CPU_FLAG_SSE4         0x0100 
#define AV_CPU_FLAG_SSE42        0x0200 
#define AV_CPU_FLAG_SSSE3        0x0080 
#define AV_CPU_FLAG_VFP          (1 << 3)
#define AV_CPU_FLAG_VFPV3        (1 << 4)
#define AV_CPU_FLAG_XOP          0x0400 

#define AV_GLUE(a, b) a ## b
#define AV_JOIN(a, b) AV_GLUE(a, b)
#define AV_NOPTS_VALUE          INT64_C(0x8000000000000000)
#define AV_PRAGMA(s) _Pragma(#s)
#define AV_STRINGIFY(s)         AV_TOSTRING(s)
#define AV_TIME_BASE            1000000
#define AV_TIME_BASE_Q          (AVRational){1, AV_TIME_BASE}
#define AV_TOSTRING(s) #s
#define AV_VERSION(a, b, c) AV_VERSION_DOT(a, b, c)
#define AV_VERSION_DOT(a, b, c) a ##.## b ##.## c
#define AV_VERSION_INT(a, b, c) (a<<16 | b<<8 | c)
#define FF_LAMBDA_MAX (256*128-1)
#define FF_LAMBDA_SCALE (1<<FF_LAMBDA_SHIFT)
#define FF_LAMBDA_SHIFT 7
#define FF_QP2LAMBDA 118 
#define FF_QUALITY_SCALE FF_LAMBDA_SCALE 




#define avpriv_align_put_bits align_put_bits_unsupported_here
#define avpriv_copy_bits avpriv_copy_bits_unsupported_here
#define avpriv_put_string ff_put_string_unsupported_here

#define AV_BE2NE16C(x) AV_BE2NEC(16, x)
#define AV_BE2NE32C(x) AV_BE2NEC(32, x)
#define AV_BE2NE64C(x) AV_BE2NEC(64, x)
#define AV_BE2NEC(s, x) (x)
#define AV_BSWAP16C(x) (((x) << 8 & 0xff00)  | ((x) >> 8 & 0x00ff))
#define AV_BSWAP32C(x) (AV_BSWAP16C(x) << 16 | AV_BSWAP16C((x) >> 16))
#define AV_BSWAP64C(x) (AV_BSWAP32C(x) << 32 | AV_BSWAP32C((x) >> 32))
#define AV_BSWAPC(s, x) AV_BSWAP##s##C(x)
#define AV_LE2NE16C(x) AV_LE2NEC(16, x)
#define AV_LE2NE32C(x) AV_LE2NEC(32, x)
#define AV_LE2NE64C(x) AV_LE2NEC(64, x)
#define AV_LE2NEC(s, x) AV_BSWAPC(s, x)
#define av_be2ne16(x) (x)
#define av_be2ne32(x) (x)
#define av_be2ne64(x) (x)
#define av_le2ne16(x) av_bswap16(x)
#define av_le2ne32(x) av_bswap32(x)
#define av_le2ne64(x) av_bswap64(x)

#define BASIS_SHIFT 16
#define         BYTE_VEC32(c)   ((c)*0x01010101UL)
#define         BYTE_VEC64(c)   ((c)*0x0001000100010001UL)
#define CALL_2X_PIXELS(a, b, n)\
static void a(uint8_t *block, const uint8_t *pixels, int line_size, int h){\
    b(block  , pixels  , line_size, h);\
    b(block+n, pixels+n, line_size, h);\
}
#define DEF_OLD_QPEL(name)\
void ff_put_        ## name (uint8_t *dst, uint8_t *src, int stride);\
void ff_put_no_rnd_ ## name (uint8_t *dst, uint8_t *src, int stride);\
void ff_avg_        ## name (uint8_t *dst, uint8_t *src, int stride);
#define E(x) x
#define EDGE_BOTTOM 2
#define EDGE_TOP    1
#define EDGE_WIDTH 16
#define EMULATED_EDGE(depth) \
void ff_emulated_edge_mc_ ## depth (uint8_t *buf, const uint8_t *src, int linesize,\
                         int block_w, int block_h,\
                         int src_x, int src_y, int w, int h);
#define FF_LIBMPEG2_IDCT_PERM 2
#define FF_NO_IDCT_PERM 1
#define FF_PARTTRANS_IDCT_PERM 5
#define FF_SIMPLE_IDCT_PERM 3
#define FF_SSE2_IDCT_PERM 6
#define FF_TRANSPOSE_IDCT_PERM 4
#define H264_IDCT(depth) \
void ff_h264_idct8_add_ ## depth ## _c(uint8_t *dst, DCTELEM *block, int stride);\
void ff_h264_idct_add_ ## depth ## _c(uint8_t *dst, DCTELEM *block, int stride);\
void ff_h264_idct8_dc_add_ ## depth ## _c(uint8_t *dst, DCTELEM *block, int stride);\
void ff_h264_idct_dc_add_ ## depth ## _c(uint8_t *dst, DCTELEM *block, int stride);\
void ff_h264_idct_add16_ ## depth ## _c(uint8_t *dst, const int *blockoffset, DCTELEM *block, int stride, const uint8_t nnzc[6*8]);\
void ff_h264_idct_add16intra_ ## depth ## _c(uint8_t *dst, const int *blockoffset, DCTELEM *block, int stride, const uint8_t nnzc[6*8]);\
void ff_h264_idct8_add4_ ## depth ## _c(uint8_t *dst, const int *blockoffset, DCTELEM *block, int stride, const uint8_t nnzc[6*8]);\
void ff_h264_idct_add8_422_ ## depth ## _c(uint8_t **dest, const int *blockoffset, DCTELEM *block, int stride, const uint8_t nnzc[6*8]);\
void ff_h264_idct_add8_ ## depth ## _c(uint8_t **dest, const int *blockoffset, DCTELEM *block, int stride, const uint8_t nnzc[6*8]);\
void ff_h264_luma_dc_dequant_idct_ ## depth ## _c(DCTELEM *output, DCTELEM *input, int qmul);\
void ff_h264_chroma422_dc_dequant_idct_ ## depth ## _c(DCTELEM *block, int qmul);\
void ff_h264_chroma_dc_dequant_idct_ ## depth ## _c(DCTELEM *block, int qmul);
#define LOCAL_ALIGNED(a, t, v, ...) E(LOCAL_ALIGNED_A(a, t, v, __VA_ARGS__,,))
#   define LOCAL_ALIGNED_16(t, v, ...) E(LOCAL_ALIGNED_D(16, t, v, __VA_ARGS__,,))
#   define LOCAL_ALIGNED_8(t, v, ...) E(LOCAL_ALIGNED_D(8, t, v, __VA_ARGS__,,))
#define LOCAL_ALIGNED_A(a, t, v, s, o, ...)             \
    uint8_t la_##v[sizeof(t s o) + (a)];                \
    t (*v) o = (void *)FFALIGN((uintptr_t)la_##v, a)
#define LOCAL_ALIGNED_D(a, t, v, s, o, ...)             \
    DECLARE_ALIGNED(a, t, la_##v) s o;                  \
    t (*v) o = la_##v
#define MAX_NEG_CROP 1024
#define PUTAVG_PIXELS(depth)\
void ff_put_pixels8x8_ ## depth ## _c(uint8_t *dst, uint8_t *src, int stride);\
void ff_avg_pixels8x8_ ## depth ## _c(uint8_t *dst, uint8_t *src, int stride);\
void ff_put_pixels16x16_ ## depth ## _c(uint8_t *dst, uint8_t *src, int stride);\
void ff_avg_pixels16x16_ ## depth ## _c(uint8_t *dst, uint8_t *src, int stride);
#define RECON_SHIFT 6
#   define STRIDE_ALIGN 16
#define WRAPPER8_16_SQ(name8, name16)\
static int name16(void  *s, uint8_t *dst, uint8_t *src, int stride, int h){\
    int score=0;\
    score +=name8(s, dst           , src           , stride, 8);\
    score +=name8(s, dst+8         , src+8         , stride, 8);\
    if(h==16){\
        dst += 8*stride;\
        src += 8*stride;\
        score +=name8(s, dst           , src           , stride, 8);\
        score +=name8(s, dst+8         , src+8         , stride, 8);\
    }\
    return score;\
}
#define ff_avg_pixels16x16_c ff_avg_pixels16x16_8_c
#define ff_avg_pixels8x8_c ff_avg_pixels8x8_8_c
#define ff_put_pixels16x16_c ff_put_pixels16x16_8_c
#define ff_put_pixels8x8_c ff_put_pixels8x8_8_c



#define INVALID_VLC           0x80000000
#define get_se_golomb(a) get_se(a, "__FILE__", __PRETTY_FUNCTION__, "__LINE__")
#define get_te0_golomb(a, r) get_te(a, r, "__FILE__", __PRETTY_FUNCTION__, "__LINE__")
#define get_te_golomb(a, r) get_te(a, r, "__FILE__", __PRETTY_FUNCTION__, "__LINE__")
#define get_ue_golomb(a) get_ue(a, "__FILE__", __PRETTY_FUNCTION__, "__LINE__")

#define FIX_MV_MBAFF(type, refn, mvn, idx)      \
    if (FRAME_MBAFF) {                          \
        if (MB_FIELD) {                         \
            if (!IS_INTERLACED(type)) {         \
                refn <<= 1;                     \
                AV_COPY32(mvbuf[idx], mvn);     \
                mvbuf[idx][1] /= 2;             \
                mvn = mvbuf[idx];               \
            }                                   \
        } else {                                \
            if (IS_INTERLACED(type)) {          \
                refn >>= 1;                     \
                AV_COPY32(mvbuf[idx], mvn);     \
                mvbuf[idx][1] <<= 1;            \
                mvn = mvbuf[idx];               \
            }                                   \
        }                                       \
    }
#define MAP_F2F(idx, mb_type)                                           \
    if (!IS_INTERLACED(mb_type) && h->ref_cache[list][idx] >= 0) {      \
        h->ref_cache[list][idx]    <<= 1;                               \
        h->mv_cache[list][idx][1]   /= 2;                               \
        h->mvd_cache[list][idx][1] >>= 1;                               \
    }
#define MAP_MVS                                                         \
    MAP_F2F(scan8[0] - 1 - 1 * 8, topleft_type)                         \
    MAP_F2F(scan8[0] + 0 - 1 * 8, top_type)                             \
    MAP_F2F(scan8[0] + 1 - 1 * 8, top_type)                             \
    MAP_F2F(scan8[0] + 2 - 1 * 8, top_type)                             \
    MAP_F2F(scan8[0] + 3 - 1 * 8, top_type)                             \
    MAP_F2F(scan8[0] + 4 - 1 * 8, topright_type)                        \
    MAP_F2F(scan8[0] - 1 + 0 * 8, left_type[LTOP])                      \
    MAP_F2F(scan8[0] - 1 + 1 * 8, left_type[LTOP])                      \
    MAP_F2F(scan8[0] - 1 + 2 * 8, left_type[LBOT])                      \
    MAP_F2F(scan8[0] - 1 + 3 * 8, left_type[LBOT])
#define SET_DIAG_MV(MV_OP, REF_OP, XY, Y4)                              \
        const int xy = XY, y4 = Y4;                                     \
        const int mb_type = mb_types[xy + (y4 >> 2) * s->mb_stride];    \
        if (!USES_LIST(mb_type, list))                                  \
            return LIST_NOT_USED;                                       \
        mv = s->current_picture_ptr->f.motion_val[list][h->mb2b_xy[xy] + 3 + y4 * h->b_stride]; \
        h->mv_cache[list][scan8[0] - 2][0] = mv[0];                     \
        h->mv_cache[list][scan8[0] - 2][1] = mv[1] MV_OP;               \
        return s->current_picture_ptr->f.ref_index[list][4 * xy + 1 + (y4 & ~1)] REF_OP;


#define CABAC h->pps.cabac
#define CHROMA422 (h->sps.chroma_format_idc == 2)
#define CHROMA444 (h->sps.chroma_format_idc == 3)
#define CHROMA_DC_BLOCK_INDEX 49
#define EXTENDED_SAR       255
#define FIELD_OR_MBAFF_PICTURE (FRAME_MBAFF || FIELD_PICTURE)
#define FIELD_PICTURE (s->picture_structure != PICT_FRAME)
#define FMO 0
#define FRAME_MBAFF h->mb_aff_frame
#define IS_8x8DCT(a)       ((a) & MB_TYPE_8x8DCT)
#define IS_REF0(a)         ((a) & MB_TYPE_REF0)
#define LBOT     1
#define LEFT(i)  (i)
#define LEFT_MBS 2
#define LIST_NOT_USED -1 
#define LTOP     0
#define LUMA_DC_BLOCK_INDEX   48
#define MAX_DELAYED_PIC_COUNT  16
#define MAX_MMCO_COUNT         66
#define MAX_PPS_COUNT         256
#define MAX_SLICES 16
#define MAX_SPS_COUNT          32
#define MB_FIELD    h->mb_field_decoding_flag
#define MB_MBAFF    h->mb_mbaff
#define MB_TYPE_8x8DCT     0x01000000
#define MB_TYPE_REF0       MB_TYPE_ACPRED 
#define PART_NOT_AVAILABLE -2
#define QP_MAX_NUM (51 + 2 * 6)           
#define interlaced_dct interlaced_dct_is_a_bad_name
#define mb_intra       mb_intra_is_not_initialized_see_mb_type
#define ALZHEIMER_DC_0L0_PRED8x8 10
#define ALZHEIMER_DC_0LT_PRED8x8  8
#define ALZHEIMER_DC_L00_PRED8x8  9
#define ALZHEIMER_DC_L0T_PRED8x8  7

#define DC_127_PRED           12
#define DC_127_PRED8x8         7
#define DC_128_PRED           11
#define DC_128_PRED8x8         6
#define DC_129_PRED           13
#define DC_129_PRED8x8         8
#define DC_PRED                2
#define DC_PRED8x8             0
#define DIAG_DOWN_LEFT_PRED    3
#define DIAG_DOWN_LEFT_PRED_RV40_NODOWN   12
#define DIAG_DOWN_RIGHT_PRED   4
#define HOR_DOWN_PRED          6
#define HOR_PRED               1
#define HOR_PRED8x8            1
#define HOR_UP_PRED            8
#define HOR_UP_PRED_RV40_NODOWN           13
#define HOR_VP8_PRED          11    
#define LEFT_DC_PRED           9
#define LEFT_DC_PRED8x8        4
#define PLANE_PRED8x8          3
#define TM_VP8_PRED            9    
#define TOP_DC_PRED           10
#define TOP_DC_PRED8x8         5
#define VERT_LEFT_PRED         7
#define VERT_LEFT_PRED_RV40_NODOWN        14
#define VERT_PRED              0
#define VERT_PRED8x8           2
#define VERT_RIGHT_PRED        5
#define VERT_VP8_PRED         10    


#define CABAC_BITS 16
#define CABAC_MASK ((1<<CABAC_BITS)-1)
#define H264_LAST_COEFF_FLAG_OFFSET_8x8_OFFSET 1280
#define H264_LPS_RANGE_OFFSET 512
#define H264_MLPS_STATE_OFFSET 1024
#define H264_NORM_SHIFT_OFFSET 0

#define FF_MAX_EXTRADATA_SIZE ((1 << 28) - FF_INPUT_BUFFER_PADDING_SIZE)
#define FF_SANE_NB_CHANNELS 128U

#define INFINITY       av_int2float(0x7f800000)
#define M_LOG2_10      3.32192809488736234787  
#define M_PHI          1.61803398874989484820   
#define NAN            av_int2float(0x7fc00000)



