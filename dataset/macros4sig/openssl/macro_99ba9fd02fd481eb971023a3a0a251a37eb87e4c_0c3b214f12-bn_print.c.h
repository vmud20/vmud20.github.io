#include<limits.h>
#include<ctype.h>
#include<stdio.h>
#  define BN_BITS4        32
#    define BN_DEBUG_TRIX
#  define BN_DEC_CONV     (10000000000000000000UL)
#  define BN_DEC_FMT1     "%lu"
#  define BN_DEC_FMT2     "%019lu"
#  define BN_DEC_NUM      19
#  define BN_DIV2W
#  define BN_MASK2        (0xffffffffffffffffL)
#  define BN_MASK2h       (0xffffffff00000000L)
#  define BN_MASK2h1      (0xffffffff80000000L)
#  define BN_MASK2l       (0xffffffffL)
#  define BN_MAX_WINDOW_BITS_FOR_CTIME_EXPONENT_SIZE    (6)
# define BN_MONT_CTX_SET_SIZE_WORD               (64)
# define BN_MULL_SIZE_NORMAL                     (16)
#  define BN_MUL_COMBA
# define BN_MUL_LOW_RECURSIVE_SIZE_NORMAL        (32)
# define BN_MUL_RECURSIVE_SIZE_NORMAL            (16)
#  define BN_RECURSION
#  define BN_SQR_COMBA
# define BN_SQR_RECURSIVE_SIZE_NORMAL            (16)
#    define BN_ULLONG     unsigned __int64
#     define BN_UMULT_HIGH(a,b)          (((__uint128_t)(a)*(b))>>64)
#     define BN_UMULT_LOHI(low,high,a,b) ({     \
        __uint128_t ret=(__uint128_t)(a)*(b);   \
        (high)=ret>>64; (low)=ret;       })
#  define BN_window_bits_for_ctime_exponent_size(b) \
                ((b) > 937 ? 6 : \
                 (b) > 306 ? 5 : \
                 (b) >  89 ? 4 : \
                 (b) >  22 ? 3 : 1)
# define BN_window_bits_for_exponent_size(b) \
                ((b) > 671 ? 6 : \
                 (b) > 239 ? 5 : \
                 (b) >  79 ? 4 : \
                 (b) >  23 ? 3 : 1)
#  define HBITS(a)        (((a)>>BN_BITS4)&BN_MASK2l)
# define HEADER_BN_LCL_H
# define Hw(t)    (((BN_ULONG)((t)>>BN_BITS2))&BN_MASK2)
#  define L2HBITS(a)      (((a)<<BN_BITS4)&BN_MASK2)
#  define LBITS(a)        ((a)&BN_MASK2l)
#  define LHBITS(a)       (((a)>>BN_BITS2)&BN_MASKl)
#  define LL2HBITS(a)     ((BN_ULLONG)((a)&BN_MASKl)<<BN_BITS2)
#  define LLBITS(a)       ((a)&BN_MASKl)
# define Lw(t)    (((BN_ULONG)(t))&BN_MASK2)
# define MOD_EXP_CTIME_MIN_CACHE_LINE_MASK       (MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH - 1)
# define MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH      ( 64 )
#   define PTR_SIZE_INT long long
#  define bn_check_size(bn, bits) bn_wcheck_size(bn, ((bits+BN_BITS2-1))/BN_BITS2)
#  define bn_check_top(a) \
        do { \
                const BIGNUM *_bnum2 = (a); \
                if (_bnum2 != NULL) { \
                        assert((_bnum2->top == 0) || \
                                (_bnum2->d[_bnum2->top - 1] != 0)); \
                        bn_pollute(_bnum2); \
                } \
        } while(0)
#  define bn_clear_top2max(a) \
        { \
        int      ind = (a)->dmax - (a)->top; \
        BN_ULONG *ftl = &(a)->d[(a)->top-1]; \
        for (; ind != 0; ind--) \
                *(++ftl) = 0x0; \
        }
#  define bn_fix_top(a)           bn_check_top(a)
#   define bn_pollute(a) \
        do { \
                const BIGNUM *_bnum1 = (a); \
                if(_bnum1->top < _bnum1->dmax) { \
                        unsigned char _tmp_char; \
                         \
                        BN_ULONG *_not_const; \
                        memcpy(&_not_const, &_bnum1->d, sizeof(_not_const)); \
                        RAND_bytes(&_tmp_char, 1); \
                        memset(_not_const + _bnum1->top, _tmp_char, \
                                sizeof(*_not_const) * (_bnum1->dmax - _bnum1->top)); \
                } \
        } while(0)
#  define bn_wcheck_size(bn, words) \
        do { \
                const BIGNUM *_bnum2 = (bn); \
                assert((words) <= (_bnum2)->dmax && (words) >= (_bnum2)->top); \
                 \
                (void)(_bnum2); \
        } while(0)
#  define mul(r,a,w,c) { \
        BN_ULLONG t; \
        t=(BN_ULLONG)w * (a) + (c); \
        (r)= Lw(t); \
        (c)= Hw(t); \
        }
#  define mul64(l,h,bl,bh) \
        { \
        BN_ULONG m,m1,lt,ht; \
 \
        lt=l; \
        ht=h; \
        m =(bh)*(lt); \
        lt=(bl)*(lt); \
        m1=(bl)*(ht); \
        ht =(bh)*(ht); \
        m=(m+m1)&BN_MASK2; if (m < m1) ht+=L2HBITS((BN_ULONG)1); \
        ht+=HBITS(m); \
        m1=L2HBITS(m); \
        lt=(lt+m1)&BN_MASK2; if (lt < m1) ht++; \
        (l)=lt; \
        (h)=ht; \
        }
#  define mul_add(r,a,w,c) { \
        BN_ULLONG t; \
        t=(BN_ULLONG)w * (a) + (r) + (c); \
        (r)= Lw(t); \
        (c)= Hw(t); \
        }
#  define sqr(r0,r1,a) { \
        BN_ULLONG t; \
        t=(BN_ULLONG)(a)*(a); \
        (r0)=Lw(t); \
        (r1)=Hw(t); \
        }
#  define sqr64(lo,ho,in) \
        { \
        BN_ULONG l,h,m; \
 \
        h=(in); \
        l=LBITS(h); \
        h=HBITS(h); \
        m =(l)*(h); \
        l*=l; \
        h*=h; \
        h+=(m&BN_MASK2h1)>>(BN_BITS4-1); \
        m =(m&BN_MASK2l)<<(BN_BITS4+1); \
        l=(l+m)&BN_MASK2; if (l < m) h++; \
        (lo)=l; \
        (ho)=h; \
        }
# define BUF_F_BUF_MEM_GROW                               100
# define BUF_F_BUF_MEM_GROW_CLEAN                         105
# define BUF_F_BUF_MEM_NEW                                101
# define BUF_MEM_FLAG_SECURE  0x01
# define BUF_memdup(data, size) OPENSSL_memdup(data, size)
# define BUF_strdup(s) OPENSSL_strdup(s)
# define BUF_strlcat(dst, src, size) OPENSSL_strlcat(dst, src, size)
# define BUF_strlcpy(dst, src, size)  OPENSSL_strlcpy(dst, src, size)
# define BUF_strndup(s, size) OPENSSL_strndup(s, size)
# define BUF_strnlen(str, maxlen) OPENSSL_strnlen(str, maxlen)
# define HEADER_BUFFER_H
#  define BIO_FLAGS_UPLINK 0x8000
# define DECIMAL_SIZE(type)      ((sizeof(type)*8+2)/3+1)
# define HEADER_CRYPTLIB_H
# define HEX_SIZE(type)          (sizeof(type)*2)
#  define X509_CERT_AREA          OPENSSLDIR
#  define X509_CERT_DIR           OPENSSLDIR "/certs"
# define X509_CERT_DIR_EVP        "SSL_CERT_DIR"
#  define X509_CERT_FILE          "SSLCERTS:cert.pem"
# define X509_CERT_FILE_EVP       "SSL_CERT_FILE"
#  define X509_PRIVATE_DIR        "SSLPRIVATE:"
