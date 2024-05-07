#include<assert.h>

#include<stdio.h>
#include<typeinfo>
#include<stddef.h>
#include<type_traits>




#include<new>
#include<exception>

#define STUB_I386_DOS32_TMT_ADLER32 0x692aaf56
#define STUB_I386_DOS32_TMT_CRC32   0xf741d739
#define STUB_I386_DOS32_TMT_SIZE    27077
#define __UPX_LINKER_H 1
#define __UPX_P_TMT_H 1
#define C const char *
#define UPX_PACKER_H__ 1
#define __UPX_FILTER_H 1
#define UPX_FILE_H__ 1
#define ACC_CFG_PREFER_TYPEOF_ACC_INT32E_T ACC_TYPEOF_INT
#define ACC_CFG_PREFER_TYPEOF_ACC_INT64E_T ACC_TYPEOF_LONG_LONG
#define ACC_CFG_USE_NEW_STYLE_CASTS 1
#define ACC_WANT_ACC_CXX_H 1
#define ACC_WANT_ACC_INCD_H 1
#define ACC_WANT_ACC_INCE_H 1
#define ACC_WANT_ACC_LIB_H 1
#define Array(type, var, size) \
    MemBuffer var ## _membuf(mem_size(sizeof(type), size)); \
    type * const var = ACC_STATIC_CAST(type *, var ## _membuf.getVoidPtr())
#define ByteArray(var, size)    Array(unsigned char, var, size)
#define CLANG_FORMAT_DUMMY_STATEMENT 
#define COMPILE_TIME_ASSERT(e)  ACC_COMPILE_TIME_ASSERT(e)
#define COMPILE_TIME_ASSERT_ALIGNED1(a)     COMPILE_TIME_ASSERT_ALIGNOF__(a,char)
#define COMPILE_TIME_ASSERT_ALIGNOF_USING_SIZEOF__(a,b) { \
     typedef a acc_tmp_a_t; typedef b acc_tmp_b_t; \
     struct alignas(1) acc_tmp_t { acc_tmp_b_t x; acc_tmp_a_t y; acc_tmp_b_t z; }; \
     COMPILE_TIME_ASSERT(sizeof(struct acc_tmp_t) == 2*sizeof(b)+sizeof(a)) \
     COMPILE_TIME_ASSERT(sizeof(((acc_tmp_t*)nullptr)->x)+sizeof(((acc_tmp_t*)nullptr)->y)+sizeof(((acc_tmp_t*)nullptr)->z) == 2*sizeof(b)+sizeof(a)) \
   }
#define COMPILE_TIME_ASSERT_ALIGNOF__(a,b) \
   COMPILE_TIME_ASSERT_ALIGNOF_USING_SIZEOF__(a,b) \
   COMPILE_TIME_ASSERT(__acc_alignof(a) == sizeof(b)) \
   COMPILE_TIME_ASSERT(alignof(a) == sizeof(b))
#define EXIT_CHECKSUM   1
#define EXIT_ERROR      1
#define EXIT_FILE_READ  1
#define EXIT_FILE_WRITE 1
#define EXIT_INIT       1
#define EXIT_INTERNAL   1
#define EXIT_MEMORY     1
#define EXIT_OK         0
#define EXIT_USAGE      1
#define EXIT_WARN       2
#define FT_END          (-1)
#define FT_NONE         (-2)
#define FT_SKIP         (-3)
#define FT_ULTRA_BRUTE  (-4)
#define HAVE_STDINT_H 1
#define M_ALL           (-1)
#define M_DEFLATE       15      
#define M_END           (-2)
#define M_IS_DEFLATE(x) ((x) == M_DEFLATE)
#define M_IS_LZMA(x)    (((x) & 255) == M_LZMA)
#define M_IS_NRV2B(x)   ((x) >= M_NRV2B_LE32 && (x) <= M_NRV2B_LE16)
#define M_IS_NRV2D(x)   ((x) >= M_NRV2D_LE32 && (x) <= M_NRV2D_LE16)
#define M_IS_NRV2E(x)   ((x) >= M_NRV2E_LE32 && (x) <= M_NRV2E_LE16)
#define M_LZMA          14
#define M_NONE          (-3)
#define M_NRV2B_8       3
#define M_NRV2B_LE16    4
#define M_NRV2B_LE32    2
#define M_NRV2D_8       6
#define M_NRV2D_LE16    7
#define M_NRV2D_LE32    5
#define M_NRV2E_8       9
#define M_NRV2E_LE16    10
#define M_NRV2E_LE32    8
#define M_SKIP          (-4)
#define M_ULTRA_BRUTE   (-5)
#define NULL_cconf  ((upx_compress_config_t *) nullptr)
#  define OPTIONS_VAR   "UPX"
#  define O_BINARY  0
#  define STDERR_FILENO     (fileno(stderr))
#  define STDIN_FILENO      (fileno(stdin))
#  define STDOUT_FILENO     (fileno(stdout))
#  define S_IFCHR           _S_IFCHR
#  define S_IFDIR           _S_IFDIR
#  define S_IFMT            _S_IFMT
#  define S_IFREG           _S_IFREG
#    define S_ISCHR(m)      (((m) & S_IFMT) == S_IFCHR)
#    define S_ISDIR(m)      (((m) & S_IFMT) == S_IFDIR)
#    define S_ISREG(m)      (((m) & S_IFMT) == S_IFREG)
#  define S_IWUSR           _S_IWUSR
#define TABLESIZE(table)    ((sizeof(table)/sizeof((table)[0])))
#define UNUSED(var)             ACC_UNUSED(var)
#define UPX_CONF_H__ 1
#define UPX_E_EOF_NOT_FOUND         (-7)
#define UPX_E_ERROR                 (-1)
#define UPX_E_INPUT_NOT_CONSUMED    (-8)
#define UPX_E_INPUT_OVERRUN         (-4)
#define UPX_E_INVALID_ARGUMENT      (-10)
#define UPX_E_LOOKBEHIND_OVERRUN    (-6)
#define UPX_E_NOT_COMPRESSIBLE      (-3)
#define UPX_E_NOT_YET_IMPLEMENTED   (-9)
#define UPX_E_OK                    (0)
#define UPX_E_OUTPUT_OVERRUN        (-5)
#define UPX_E_OUT_OF_MEMORY         (-2)
#define UPX_F_ATARI_TOS         129
#define UPX_F_BSD_ELF_i386      25
#define UPX_F_BSD_SH_i386       26
#define UPX_F_BSD_i386          24
#define UPX_F_BVMLINUZ_i386     16
#define UPX_F_DJGPP2_COFF       4
#define UPX_F_DOS_COM           1
#define UPX_F_DOS_EXE           3
#define UPX_F_DOS_EXEH          7               
#define UPX_F_DOS_SYS           2
#define UPX_F_DYLIB_AMD64       35
#define UPX_F_DYLIB_PPC32       138
#define UPX_F_DYLIB_PPC64       142
#define UPX_F_DYLIB_i386        33
#define UPX_F_ELKS_8086         17              
#define UPX_F_LINUX_ELF32_ARMEB 133
#define UPX_F_LINUX_ELF32_ARMEL 23
#define UPX_F_LINUX_ELF32_MIPSEB 137
#define UPX_F_LINUX_ELF32_MIPSEL 30
#define UPX_F_LINUX_ELF64_AMD   22
#define UPX_F_LINUX_ELF64_ARM   42
#define UPX_F_LINUX_ELFI_i386   20
#define UPX_F_LINUX_ELFPPC32    132
#define UPX_F_LINUX_ELFPPC64    140
#define UPX_F_LINUX_ELFPPC64LE  39
#define UPX_F_LINUX_ELF_i386    12
#define UPX_F_LINUX_SEP_i386    13              
#define UPX_F_LINUX_SH_i386     14
#define UPX_F_LINUX_i386        10
#define UPX_F_MACH_AMD64        34
#define UPX_F_MACH_ARM64EL      37
#define UPX_F_MACH_ARMEL        32
#define UPX_F_MACH_FAT          134
#define UPX_F_MACH_PPC32        131
#define UPX_F_MACH_PPC64        139
#define UPX_F_MACH_i386         29
#define UPX_F_PS1_EXE           18
#define UPX_F_SOLARIS_SPARC     130             
#define UPX_F_TMT_ADAM          8
#define UPX_F_VMLINUX_AMD64     27
#define UPX_F_VMLINUX_ARMEB     135
#define UPX_F_VMLINUX_ARMEL     28
#define UPX_F_VMLINUX_PPC32     136
#define UPX_F_VMLINUX_PPC64     141
#define UPX_F_VMLINUX_PPC64LE   40
#define UPX_F_VMLINUX_i386      19
#define UPX_F_VMLINUZ_ARMEL     31
#define UPX_F_VMLINUZ_i386      15
#define UPX_F_VXD_LE            6               
#define UPX_F_WATCOM_LE         5
#define UPX_F_WIN16_NE          11              
#define UPX_F_WIN32_PE          9
#define UPX_F_WIN64_PEP         36
#define UPX_F_WINCE_ARM_PE      21
#define UPX_MAGIC2_LE32         0xD5D0D8A1
#define UPX_MAGIC_LE32          0x21585055      
#define UPX_RSIZE_MAX       UPX_RSIZE_MAX_MEM
#define UPX_RSIZE_MAX_MEM   (768 * 1024 * 1024)   
#define UPX_RSIZE_MAX_STR   (1024 * 1024)
#  define VALGRIND_MAKE_MEM_DEFINED(addr,len)   0
#  define VALGRIND_MAKE_MEM_NOACCESS(addr,len)  0
#  define VALGRIND_MAKE_MEM_UNDEFINED(addr,len) 0
#define WITH_LZMA 0x443
#define WITH_UCL 1
#define WITH_ZLIB 1
#  define _FILE_OFFSET_BITS 64
#    define _USE_MINGW_ANSI_STDIO 1
#  define __has_builtin(x)      0
#define __packed_struct(s)      struct alignas(1) s {
#define __packed_struct_end()   };
#  define __unix__ 1
#  define attribute_format(a,b) __attribute__((__format__(__gnu_printf__,a,b)))
#define basename            upx_basename
#define index               upx_index
#define off_t upx_off_t
#define outp                upx_outp
#  define strcasecmp        stricmp
#  define strncasecmp       strnicmp
#  define ucl_compress_config_t REAL_ucl_compress_config_t
#define upx_bytep       upx_byte *
#  define upx_memcpy_inline     __builtin_memcpy_inline
#define SPAN_0(type) Ptr<type>
#define SPAN_0_MAKE(type, first, ...) (SPAN_0(type)(first))
#define SPAN_0_VAR(type, var, first, ...) SPAN_0(type) var(first)
#define SPAN_CONFIG_ENABLE_IMPLICIT_CONVERSION 0
#define SPAN_CONFIG_ENABLE_SPAN_CONVERSION 1
#define SPAN_P(type) Ptr<type>
#define SPAN_P_MAKE(type, first, ...) (SPAN_P(type)(first))
#define SPAN_P_VAR(type, var, first, ...) SPAN_P(type) var(first)
#define SPAN_S(type) Ptr<type>
#define SPAN_S_MAKE(type, first, ...) (SPAN_S(type)(first))
#define SPAN_S_VAR(type, var, first, ...) SPAN_S(type) var(first)
#define WITH_SPAN 2
#define New(type, n) new type[mem_size_get_n(sizeof(type), n)]
#define UPX_UTIL_H__ 1
#define BG_BLACK     0x00
#define BG_BLUE      0x10
#define BG_CYAN      0x30
#define BG_GREEN     0x20
#define BG_ORANGE    0x60
#define BG_RED       0x40
#define BG_VIOLET    0x50
#define BG_WHITE     0x70
#define FG_BLACK     0x00
#define FG_BLUE      0x01
#define FG_BRTBLUE   0x09
#define FG_BRTCYAN   0x0b
#define FG_BRTGREEN  0x0a
#define FG_BRTRED    0x0c
#define FG_BRTVIOLET 0x0d
#define FG_CYAN      0x03
#define FG_DKGRAY    0x08
#define FG_GREEN     0x02
#define FG_LTGRAY    0x07
#define FG_ORANGE    0x06
#define FG_RED       0x04
#define FG_VIOLET    0x05
#define FG_WHITE     0x0f
#define FG_YELLOW    0x0e
#  define NO_CONSOLE 1
#  define USE_SCREEN 1
#  define USE_SCREEN_VCSA 1
#  define USE_SCREEN_WIN32 1
#define con_fg(f,x)     con->set_fg(f,x)
#define con_fprintf     fprintf
#define BELE_CTP 1
#define BELE_RTP 1
#define UPX_BELE_H__ 1
#define ne16_to_be16(v) no_bswap16(v)
#define ne16_to_le16(v) bswap16(v)
#define ne32_to_be32(v) no_bswap32(v)
#define ne32_to_le32(v) bswap32(v)
#define ne64_to_be64(v) no_bswap64(v)
#define ne64_to_le64(v) bswap64(v)
#define S static int __acc_cdecl_qsort
#define V static inline
#define NORET __acc_noinline __attribute__((__noreturn__))
#define UPX_EXCEPT_H__ 1
#define UPX_OPTIONS_H__ 1
#define UPX_SNPRINTF_H__ 1
#define snprintf upx_safe_snprintf
#define sprintf ERROR_sprintf_IS_DANGEROUS_USE_snprintf
#define strlen upx_safe_strlen
#define vsnprintf upx_safe_vsnprintf
#  define ACCCHK_ASSERT(expr)   ACC_COMPILE_TIME_ASSERT_HEADER(expr)
#  define ACCCHK_ASSERT_IS_SIGNED_T(type)       ACCCHK_ASSERT_SIGN_T(type,<)
#    define ACCCHK_ASSERT_IS_UNSIGNED_T(type) \
        ACCCHK_ASSERT( ACC_STATIC_CAST(type, -1) > ACC_STATIC_CAST(type, 0) )
#  define ACCCHK_ASSERT_SIGN_T(type,relop) \
        ACCCHK_ASSERT( ACC_STATIC_CAST(type, -1)  relop  ACC_STATIC_CAST(type, 0)) \
        ACCCHK_ASSERT( ACC_STATIC_CAST(type, ~ACC_STATIC_CAST(type, 0)) relop  ACC_STATIC_CAST(type, 0)) \
        ACCCHK_ASSERT( ACC_STATIC_CAST(type, ~ACC_STATIC_CAST(type, 0)) ==     ACC_STATIC_CAST(type, -1))
#define ACCCHK_TMP1 ACCCHK_VAL
#define ACCCHK_TMP2 ACCCHK_VAL
#define ACCCHK_VAL  1
#  define ACCLIB_EXTERN(r,f)                extern r __ACCLIB_FUNCNAME(f)
#    define ACCLIB_EXTERN_NOINLINE(r,f)     extern __acc_noinline r __ACCLIB_FUNCNAME(f)
#  define ACCLIB_PUBLIC(r,f)    r __ACCLIB_FUNCNAME(f)
#    define ACCLIB_PUBLIC_NOINLINE(r,f)     r __ACCLIB_FUNCNAME(f)
#define ACC_0xffffL             ACC_0xffffUL
#define ACC_0xffffUL            65535ul
#define ACC_0xffffffffL         ACC_0xffffffffUL
#define ACC_0xffffffffUL        4294967295ul
#  define ACC_ABI_I8LP16         1
#  define ACC_ABI_IP32W64       1
#  define ACC_ARCH_AARCH64          1
#  define ACC_ARCH_ALPHA            1
#  define ACC_ARCH_AMD64            1
#  define ACC_ARCH_ARM              1
#  define ACC_ARCH_ARM64            1
#      define ACC_ARCH_ARM_THUMB2   1
#  define ACC_ARCH_AVR              1
#  define ACC_ARCH_AVR32            1
#  define ACC_ARCH_BLACKFIN         1
#  define ACC_ARCH_C166             1
#      define ACC_ARCH_CRAY_MPP     1
#      define ACC_ARCH_CRAY_PVP     1
#    define ACC_ARCH_CRAY_SV1       1
#    define ACC_ARCH_CRAY_T90       1
#    define ACC_ARCH_CRAY_XMP       1
#    define ACC_ARCH_CRAY_YMP       1
#  define ACC_ARCH_CRIS             1
#  define ACC_ARCH_EZ80             1
#  define ACC_ARCH_H8300            1
#  define ACC_ARCH_HPPA             1
#  define ACC_ARCH_I086             1
#  define ACC_ARCH_I086PM           1
#  define ACC_ARCH_I386            1
#  define ACC_ARCH_IA32             1
#  define ACC_ARCH_IA64             1
#  define ACC_ARCH_M16C             1
#  define ACC_ARCH_M32R             1
#  define ACC_ARCH_M68K             1
#  define ACC_ARCH_MCS251           1
#  define ACC_ARCH_MCS51            1
#  define ACC_ARCH_MICROBLAZE       1
#  define ACC_ARCH_MIPS             1
#  define ACC_ARCH_MSP430           1
#  define ACC_ARCH_POWERPC          1
#  define ACC_ARCH_RISCV            1
#  define ACC_ARCH_S390             1
#  define ACC_ARCH_SH               1
#  define ACC_ARCH_SPARC            1
#  define ACC_ARCH_SPU              1
#  define ACC_ARCH_UNKNOWN          1
#  define ACC_ARCH_X64              1
#  define ACC_ARCH_X86              1
#  define ACC_ARCH_Z80              1
#  define ACC_ASM_SYNTAX_MSC 1
#  define ACC_BLOCK_BEGIN           do {
#  define ACC_BLOCK_END             } while __acc_cte(0)
#    define ACC_BROKEN_CDECL_ALT_SYNTAX 1
#    define ACC_BROKEN_INTEGRAL_CONSTANTS 1
#    define ACC_BROKEN_INTEGRAL_PROMOTION 1
#  define ACC_BROKEN_SIGNED_RIGHT_SHIFT 1
#    define ACC_BROKEN_SIZEOF 1
#    define ACC_CCAST(t,e)                  ((t) (e))
#  define ACC_CC_ACK            1
#  define ACC_CC_ARMCC          __ARMCC_VERSION
#  define ACC_CC_ARMCC_ARMCC    __ARMCC_VERSION
#    define ACC_CC_ARMCC_GNUC   ("__GNUC__" * 0x10000L + ("__GNUC_MINOR__"-0) * 0x100 + ("__GNUC_PATCHLEVEL__"-0))
#  define ACC_CC_AZTECC         1
#  define ACC_CC_BORLANDC       1
#  define ACC_CC_CILLY          1
#    define ACC_CC_CLANG        (__clang_major__ * 0x10000L + (__clang_minor__-0) * 0x100 + (__clang_patchlevel__-0))
#  define ACC_CC_CLANG_C2       _MSC_VER
#    define ACC_CC_CLANG_GNUC   ("__GNUC__" * 0x10000L + ("__GNUC_MINOR__"-0) * 0x100 + ("__GNUC_PATCHLEVEL__"-0))
#    define ACC_CC_CLANG_MSC    _MSC_VER
#    define ACC_CC_CLANG_VENDOR_APPLE 1
#    define ACC_CC_CLANG_VENDOR_LLVM 1
#  define ACC_CC_CLANG_VENDOR_MICROSOFT 1
#  define ACC_CC_CODEGEARC      1
#  define ACC_CC_CRAYC          1
#  define ACC_CC_DECC           1
#  define ACC_CC_DMC            1
#  define ACC_CC_GHS            1
#    define ACC_CC_GHS_GNUC     ("__GNUC__" * 0x10000L + ("__GNUC_MINOR__"-0) * 0x100 + ("__GNUC_PATCHLEVEL__"-0))
#    define ACC_CC_GHS_MSC      _MSC_VER
#    define ACC_CC_GNUC         ("__GNUC__" * 0x10000L + ("__GNUC_MINOR__"-0) * 0x100 + ("__GNUC_PATCHLEVEL__"-0))
#  define ACC_CC_HIGHC          1
#  define ACC_CC_HPACC          __HP_aCC
#  define ACC_CC_IARC           1
#  define ACC_CC_IBMC           __IBMC__
#  define ACC_CC_INTELC         __INTEL_COMPILER
#    define ACC_CC_INTELC_GNUC   ("__GNUC__" * 0x10000L + ("__GNUC_MINOR__"-0) * 0x100 + ("__GNUC_PATCHLEVEL__"-0))
#    define ACC_CC_INTELC_MSC   _MSC_VER
#  define ACC_CC_KEILC          1
#  define ACC_CC_LCC            1
#  define ACC_CC_LCCWIN32       1
#  define ACC_CC_LLVM           ACC_CC_LLVM_GNUC
#    define ACC_CC_LLVM_GNUC    ("__GNUC__" * 0x10000L + ("__GNUC_MINOR__"-0) * 0x100 + ("__GNUC_PATCHLEVEL__"-0))
#  define ACC_CC_MSC            _MSC_VER
#  define ACC_CC_MWERKS         __MWERKS__
#  define ACC_CC_NDPC           1
#    define ACC_CC_OPEN64       (__OPENCC__ * 0x10000L + (__OPENCC_MINOR__-0) * 0x100 + (__OPENCC_PATCHLEVEL__-0))
#    define ACC_CC_OPEN64_GNUC  ACC_CC_GNUC
#  define ACC_CC_PACIFICC       1
#  define ACC_CC_PATHSCALE      (__PATHCC__ * 0x10000L + (__PATHCC_MINOR__-0) * 0x100 + (__PATHCC_PATCHLEVEL__-0))
#    define ACC_CC_PATHSCALE_GNUC ("__GNUC__" * 0x10000L + ("__GNUC_MINOR__"-0) * 0x100 + ("__GNUC_PATCHLEVEL__"-0))
#    define ACC_CC_PCC          (__PCC__ * 0x10000L + (__PCC_MINOR__-0) * 0x100 + (__PCC_MINORMINOR__-0))
#    define ACC_CC_PCC_GNUC     ACC_CC_GNUC
#  define ACC_CC_PELLESC        1
#    define ACC_CC_PGI          (__PGIC__ * 0x10000L + (__PGIC_MINOR__-0) * 0x100 + (__PGIC_PATCHLEVEL__-0))
#  define ACC_CC_PUREC          1
#  define ACC_CC_SDCC           1
#    define ACC_CC_SUNPROC      __SUNPRO_C
#  define ACC_CC_SYMANTECC      1
#  define ACC_CC_TINYC          1
#  define ACC_CC_TOPSPEEDC      1
#  define ACC_CC_TURBOC         1
#  define ACC_CC_UNKNOWN        1
#  define ACC_CC_WATCOMC        1
#  define ACC_CC_ZORTECHC       1
#  define ACC_CFG_NO_INLINE_ASM 1
#  define ACC_CFG_NO_UNALIGNED 1
#  define ACC_CFG_USE_COUNTER 1
#    define ACC_COMPILE_TIME_ASSERT(e)  {static_assert(e, #e);}
#    define ACC_COMPILE_TIME_ASSERT_HEADER(e)  static_assert(e, #e);
#define ACC_CPP_CONCAT2(a,b)            a ## b
#define ACC_CPP_CONCAT3(a,b,c)          a ## b ## c
#define ACC_CPP_CONCAT4(a,b,c,d)        a ## b ## c ## d
#define ACC_CPP_CONCAT5(a,b,c,d,e)      a ## b ## c ## d ## e
#define ACC_CPP_CONCAT6(a,b,c,d,e,f)    a ## b ## c ## d ## e ## f
#define ACC_CPP_CONCAT7(a,b,c,d,e,f,g)  a ## b ## c ## d ## e ## f ## g
#define ACC_CPP_ECONCAT2(a,b)           ACC_CPP_CONCAT2(a,b)
#define ACC_CPP_ECONCAT3(a,b,c)         ACC_CPP_CONCAT3(a,b,c)
#define ACC_CPP_ECONCAT4(a,b,c,d)       ACC_CPP_CONCAT4(a,b,c,d)
#define ACC_CPP_ECONCAT5(a,b,c,d,e)     ACC_CPP_CONCAT5(a,b,c,d,e)
#define ACC_CPP_ECONCAT6(a,b,c,d,e,f)   ACC_CPP_CONCAT6(a,b,c,d,e,f)
#define ACC_CPP_ECONCAT7(a,b,c,d,e,f,g) ACC_CPP_CONCAT7(a,b,c,d,e,f,g)
#define ACC_CPP_MACRO_EXPAND(x)         ACC_CPP_STRINGIZE(x)
#define ACC_CPP_STRINGIZE(x)            #x
#  define ACC_CXX_DISABLE_NEW_DELETE private:
#  define ACC_CXX_NOTHROW           throw()
#  define ACC_CXX_TRIGGER_FUNCTION \
        protected: virtual const void* acc_cxx_trigger_function() const; \
        private:
#  define ACC_CXX_TRIGGER_FUNCTION_IMPL(klass) \
        const void* klass::acc_cxx_trigger_function() const { return ACC_STATIC_CAST(const void *, ACC_nullptr); }
#    define ACC_DEFINE_UNINITIALIZED_VAR(type,var,init)  type var = var
#  define ACC_EXTERN_C          extern "C"
#  define ACC_EXTERN_C_BEGIN    extern "C" {
#  define ACC_EXTERN_C_END      }
#define ACC_FNMATCH_ASCII_CASEFOLD  16
#define ACC_FNMATCH_NOESCAPE        1
#define ACC_FNMATCH_PATHNAME        2
#define ACC_FNMATCH_PATHSTAR        4
#define ACC_FNMATCH_PERIOD          8
#  define ACC_FN_NAME_MAX   12
#  define ACC_FN_PATH_MAX   143
#define ACC_HAVE_MM_HUGE_ARRAY      1
#define ACC_HAVE_MM_HUGE_PTR        1
#  define ACC_ICAST(t,e)                    ACC_STATIC_CAST(t, e)
#  define ACC_ICONV(t,e)                    ACC_STATIC_CAST(t, e)
#  define ACC_INFO_ABI_ENDIAN       "be"
#  define ACC_INFO_ABI_PM       "i8lp16"
#    define ACC_INFO_ARCH           "cray_sv1"
#    define ACC_INFO_CC         "clang/apple"
#    define ACC_INFO_CCVER      ACC_PP_MACRO_EXPAND(__CILLY__)
#  define ACC_INFO_LIBC         "naked"
#  define ACC_INFO_MM           "compact"
#    define ACC_INFO_OS         "os216"
#  define ACC_INFO_OS_CONSOLE   "ps2"
#      define ACC_INFO_OS_POSIX       "darwin_iphone"
#define ACC_INFO_STRING \
    ACC_INFO_ARCH __ACC_INFOSTR_MM __ACC_INFOSTR_PM __ACC_INFOSTR_ENDIAN \
    " " __ACC_INFOSTR_OSNAME __ACC_INFOSTR_LIBC " " ACC_INFO_CC __ACC_INFOSTR_CCVER
#    define ACC_INT16_C(c)          ((c) + 0)
#    define ACC_INT32_C(c)          ((c) + 0)
#    define ACC_INT64_C(c)          ((c) + 0)
#  define ACC_ITRUNC(t,e)                   ACC_STATIC_CAST(t, e)
#    define ACC_LANG_ASSEMBLER  1
#    define ACC_LANG_C          "__STDC_VERSION__"
#  define ACC_LANG_CPLUSPLUS    ACC_LANG_CXX
#    define ACC_LANG_CXX        1
#  define ACC_MM_AHSHIFT      ((unsigned) _AHSHIFT)
#    define ACC_MM_COMPACT      1
#  define ACC_MM_FLAT           1
#  define ACC_MM_HUGE           1
#    define ACC_MM_LARGE        1
#    define ACC_MM_MEDIUM       1
#  define ACC_MM_PVP            1
#    define ACC_MM_SMALL        1
#  define ACC_MM_TINY           1
#  define ACC_MM_XSMALL         1
#  define ACC_MM_XTINY          1
#  define ACC_OPT_AVOID_UINT_INDEX          1
#  define ACC_OS_BEOS           1
#  define ACC_OS_CONSOLE        1
#  define ACC_OS_CONSOLE_PS2    1
#  define ACC_OS_CONSOLE_PSP    1
#  define ACC_OS_CYGWIN         1
#    define ACC_OS_DOS16        1
#    define ACC_OS_DOS32        1
#  define ACC_OS_EMBEDDED       1
#  define ACC_OS_EMX            1
#  define ACC_OS_LYNXOS         1
#  define ACC_OS_MACCLASSIC     1
#    define ACC_OS_OS2          1
#    define ACC_OS_OS216        1
#  define ACC_OS_OS400          1
#  define ACC_OS_PALMOS         1
#    define ACC_OS_POSIX        1
#    define ACC_OS_POSIX_AIX        1
#      define ACC_OS_POSIX_DARWIN     1040
#    define ACC_OS_POSIX_DRAGONFLY  1
#    define ACC_OS_POSIX_FREEBSD    1
#    define ACC_OS_POSIX_HPUX       1
#    define ACC_OS_POSIX_INTERIX    1
#    define ACC_OS_POSIX_IRIX       1
#    define ACC_OS_POSIX_LINUX      1
#    define ACC_OS_POSIX_MACOSX     ACC_OS_POSIX_DARWIN
#    define ACC_OS_POSIX_MINIX      1
#    define ACC_OS_POSIX_NETBSD     1
#    define ACC_OS_POSIX_OPENBSD    1
#    define ACC_OS_POSIX_OSF        1
#      define ACC_OS_POSIX_SOLARIS  1
#      define ACC_OS_POSIX_SUNOS    1
#    define ACC_OS_POSIX_ULTRIX     1
#    define ACC_OS_POSIX_UNICOS     1
#    define ACC_OS_POSIX_UNKNOWN    1
#  define ACC_OS_QNX            1
#  define ACC_OS_TOS            1
#  define ACC_OS_VMS            1
#    define ACC_OS_WIN16        1
#    define ACC_OS_WIN32        1
#  define ACC_OS_WIN64          1
#    define ACC_PCAST(t,e)                  ((t) (e))
#define ACC_PCLOCK_MONOTONIC            1
#define ACC_PCLOCK_PROCESS_CPUTIME_ID   2
#define ACC_PCLOCK_REALTIME             0
#define ACC_PCLOCK_THREAD_CPUTIME_ID    3
#define ACC_PP_CONCAT0()                
#define ACC_PP_CONCAT1(a)               a
#define ACC_PP_CONCAT2(a,b)             a ## b
#define ACC_PP_CONCAT3(a,b,c)           a ## b ## c
#define ACC_PP_CONCAT4(a,b,c,d)         a ## b ## c ## d
#define ACC_PP_CONCAT5(a,b,c,d,e)       a ## b ## c ## d ## e
#define ACC_PP_CONCAT6(a,b,c,d,e,f)     a ## b ## c ## d ## e ## f
#define ACC_PP_CONCAT7(a,b,c,d,e,f,g)   a ## b ## c ## d ## e ## f ## g
#define ACC_PP_ECONCAT0()               ACC_PP_CONCAT0()
#define ACC_PP_ECONCAT1(a)              ACC_PP_CONCAT1(a)
#define ACC_PP_ECONCAT2(a,b)            ACC_PP_CONCAT2(a,b)
#define ACC_PP_ECONCAT3(a,b,c)          ACC_PP_CONCAT3(a,b,c)
#define ACC_PP_ECONCAT4(a,b,c,d)        ACC_PP_CONCAT4(a,b,c,d)
#define ACC_PP_ECONCAT5(a,b,c,d,e)      ACC_PP_CONCAT5(a,b,c,d,e)
#define ACC_PP_ECONCAT6(a,b,c,d,e,f)    ACC_PP_CONCAT6(a,b,c,d,e,f)
#define ACC_PP_ECONCAT7(a,b,c,d,e,f,g)  ACC_PP_CONCAT7(a,b,c,d,e,f,g)
#define ACC_PP_EMPTY                    
#define ACC_PP_EMPTY0()                 
#define ACC_PP_EMPTY1(a)                
#define ACC_PP_EMPTY2(a,b)              
#define ACC_PP_EMPTY3(a,b,c)            
#define ACC_PP_EMPTY4(a,b,c,d)          
#define ACC_PP_EMPTY5(a,b,c,d,e)        
#define ACC_PP_EMPTY6(a,b,c,d,e,f)      
#define ACC_PP_EMPTY7(a,b,c,d,e,f,g)    
#define ACC_PP_MACRO_EXPAND(x)          ACC_PP_STRINGIZE(x)
#define ACC_PP_STRINGIZE(x)             #x
#    define ACC_PTR_FP_OFF(x)   FP_OFF(x)
#    define ACC_PTR_FP_SEG(x)   FP_SEG(x)
#    define ACC_PTR_MK_FP(s,o)  MK_FP(s,o)
#    define ACC_REINTERPRET_CAST(t,e)       (reinterpret_cast<t> (e))
#  define ACC_SIZEOF_ACC_INT16E_T   2
#define ACC_SIZEOF_ACC_INT16_T      ACC_SIZEOF_ACC_INT16E_T
#  define ACC_SIZEOF_ACC_INT32E_T   4
#  define ACC_SIZEOF_ACC_INT32F_T   ACC_SIZEOF_ACC_INT64L_T
#  define ACC_SIZEOF_ACC_INT32L_T   ACC_SIZEOF_ACC_INT32E_T
#define ACC_SIZEOF_ACC_INT32_T      ACC_SIZEOF_ACC_INT32E_T
#  define ACC_SIZEOF_ACC_INT64E_T   8
#  define ACC_SIZEOF_ACC_INT64F_T   ACC_SIZEOF_ACC_INT64L_T
#  define ACC_SIZEOF_ACC_INT64L_T   ACC_SIZEOF_ACC_INT64E_T
#define ACC_SIZEOF_ACC_INT64_T      ACC_SIZEOF_ACC_INT64E_T
#define ACC_SIZEOF_ACC_INT8_T       1
#  define ACC_SIZEOF_ACC_INTPTR_T   ACC_SIZEOF_VOID_P
#define ACC_SIZEOF_ACC_INT_FAST32_T ACC_SIZEOF_ACC_INT32F_T
#define ACC_SIZEOF_ACC_INT_FAST64_T ACC_SIZEOF_ACC_INT64F_T
#define ACC_SIZEOF_ACC_INT_LEAST32_T ACC_SIZEOF_ACC_INT32L_T
#define ACC_SIZEOF_ACC_INT_LEAST64_T ACC_SIZEOF_ACC_INT64L_T
#  define ACC_SIZEOF_ACC_WORD_T     ACC_SIZEOF_ACC_INTPTR_T
#define ACC_SIZEOF_CHAR             1
#    define ACC_SIZEOF_INT          8
#    define ACC_SIZEOF_LONG         4
#        define ACC_SIZEOF_LONG_LONG      ACC_SIZEOF_LONG
#    define ACC_SIZEOF_PTRDIFF_T    ACC_SIZEOF_VOID_P
#    define ACC_SIZEOF_SHORT        8
#  define ACC_SIZEOF_SIZE_T         (SIZEOF_SIZE_T)
#  define ACC_SIZEOF_VOID_P         (SIZEOF_VOID_P)
#  define ACC_SIZEOF___INT16        (SIZEOF___INT16)
#  define ACC_SIZEOF___INT32        (SIZEOF___INT32)
#  define ACC_SIZEOF___INT64        (SIZEOF___INT64)
#define ACC_SPAWN_P_NOWAIT  1
#define ACC_SPAWN_P_WAIT    0
#    define ACC_STATIC_CAST(t,e)            (static_cast<t> (e))
#  define ACC_STATIC_CAST2(t1,t2,e)         ACC_STATIC_CAST(t1, ACC_STATIC_CAST(t2, e))
#      define ACC_TARGET_FEATURE_AVX        1
#      define ACC_TARGET_FEATURE_AVX2       1
#      define ACC_TARGET_FEATURE_NEON       1
#      define ACC_TARGET_FEATURE_SSE2       1
#      define ACC_TARGET_FEATURE_SSE4_2     1
#      define ACC_TARGET_FEATURE_SSSE3      1
#  define ACC_TYPEOF_ACC_INT16E_T   ACC_TYPEOF_LONG
#define ACC_TYPEOF_ACC_INT16_T      ACC_TYPEOF_ACC_INT16E_T
#  define ACC_TYPEOF_ACC_INT32E_T   ACC_TYPEOF_LONG
#  define ACC_TYPEOF_ACC_INT32F_T   ACC_TYPEOF_ACC_INT64L_T
#  define ACC_TYPEOF_ACC_INT32L_T   ACC_TYPEOF_ACC_INT32E_T
#define ACC_TYPEOF_ACC_INT32_T      ACC_TYPEOF_ACC_INT32E_T
#  define ACC_TYPEOF_ACC_INT64E_T   ACC_TYPEOF_INT
#  define ACC_TYPEOF_ACC_INT64F_T   ACC_TYPEOF_ACC_INT64L_T
#  define ACC_TYPEOF_ACC_INT64L_T   ACC_TYPEOF_ACC_INT64E_T
#define ACC_TYPEOF_ACC_INT64_T      ACC_TYPEOF_ACC_INT64E_T
#define ACC_TYPEOF_ACC_INT8_T       ACC_TYPEOF_CHAR
#  define ACC_TYPEOF_ACC_INTPTR_T   ACC_TYPEOF_CHAR_P
#define ACC_TYPEOF_ACC_INT_FAST32_T ACC_TYPEOF_ACC_INT32F_T
#define ACC_TYPEOF_ACC_INT_FAST64_T ACC_TYPEOF_ACC_INT64F_T
#define ACC_TYPEOF_ACC_INT_LEAST32_T ACC_TYPEOF_ACC_INT32L_T
#define ACC_TYPEOF_ACC_INT_LEAST64_T ACC_TYPEOF_ACC_INT64L_T
#  define ACC_TYPEOF_ACC_WORD_T     ACC_TYPEOF_ACC_INTPTR_T
#define ACC_TYPEOF_CHAR             1u
#define ACC_TYPEOF_CHAR_P           129u
#define ACC_TYPEOF_INT              3u
#define ACC_TYPEOF_LONG             4u
#define ACC_TYPEOF_LONG_LONG        5u
#define ACC_TYPEOF_SHORT            2u
#define ACC_TYPEOF___INT128         21u
#define ACC_TYPEOF___INT16          18u
#define ACC_TYPEOF___INT256         22u
#define ACC_TYPEOF___INT32          19u
#define ACC_TYPEOF___INT64          20u
#define ACC_TYPEOF___INT8           17u
#define ACC_TYPEOF___MODE_DI        36u
#define ACC_TYPEOF___MODE_HI        34u
#define ACC_TYPEOF___MODE_QI        33u
#define ACC_TYPEOF___MODE_SI        35u
#define ACC_TYPEOF___MODE_TI        37u
#  define ACC_UA_COPY16(d,s)    ACC_UA_SET16(d, ACC_UA_GET16(s))
#  define ACC_UA_COPY32(d,s)    ACC_UA_SET32(d, ACC_UA_GET32(s))
#  define ACC_UA_COPY64(d,s)    ACC_UA_SET64(d, ACC_UA_GET64(s))
#define ACC_UA_GET16(p)         (* ACC_STATIC_CAST2(__acc_ua_volatile const acc_uint16e_t*, __acc_ua_volatile const void*, p))
#define ACC_UA_GET32(p)         (* ACC_STATIC_CAST2(__acc_ua_volatile const acc_uint32e_t*, __acc_ua_volatile const void*, p))
#define ACC_UA_GET64(p)         (* ACC_STATIC_CAST2(__acc_ua_volatile const acc_uint64l_t*, __acc_ua_volatile const void*, p))
#  define ACC_UA_GET_BE16(p)    ACC_UA_GET16(p)
#  define ACC_UA_GET_BE32(p)    ACC_UA_GET32(p)
#  define ACC_UA_GET_BE64(p)    ACC_UA_GET64(p)
#  define ACC_UA_GET_LE16(p)    ACC_UA_GET16(p)
#  define ACC_UA_GET_LE32(p)    ACC_UA_GET32(p)
#  define ACC_UA_GET_LE64(p)    ACC_UA_GET64(p)
#define ACC_UA_SET16(p,v)       (* ACC_STATIC_CAST2(__acc_ua_volatile acc_uint16e_t*, __acc_ua_volatile void*, p) = ACC_ITRUNC(acc_uint16e_t, v))
#define ACC_UA_SET32(p,v)       (* ACC_STATIC_CAST2(__acc_ua_volatile acc_uint32e_t*, __acc_ua_volatile void*, p) = ACC_ITRUNC(acc_uint32e_t, v))
#define ACC_UA_SET64(p,v)       (* ACC_STATIC_CAST2(__acc_ua_volatile acc_uint64l_t*, __acc_ua_volatile void*, p) = ACC_ITRUNC(acc_uint64l_t, v))
#  define ACC_UA_SET_BE16(p,v)  ACC_UA_SET16(p,v)
#  define ACC_UA_SET_BE32(p,v)  ACC_UA_SET32(p,v)
#  define ACC_UA_SET_BE64(p,v)  ACC_UA_SET64(p,v)
#  define ACC_UA_SET_LE16(p,v)  ACC_UA_SET16(p,v)
#  define ACC_UA_SET_LE32(p,v)  ACC_UA_SET32(p,v)
#  define ACC_UA_SET_LE64(p,v)  ACC_UA_SET64(p,v)
#    define ACC_UINT16_C(c)         ((c) + 0U)
#    define ACC_UINT32_C(c)         ((c) + 0U)
#    define ACC_UINT64_C(c)         ((c) + 0U)
#    define ACC_UNCONST_CAST(t,e)           (const_cast<t> (e))
#    define ACC_UNCONST_VOLATILE_CAST(t,e)  (const_cast<t> (e))
#    define ACC_UNUSED(var)         ((void) &var)
#    define ACC_UNUSED_FUNC(func)   ((void) func)
#    define ACC_UNUSED_LABEL(l)     (__acc_gnuc_extension__ ((void) ACC_STATIC_CAST(const void *, &&l)))
#  define ACC_UNUSED_RESULT(var)    ACC_UNUSED(var)
#    define ACC_UNVOLATILE_CAST(t,e)        (const_cast<t> (e))
#    define ACC_UNVOLATILE_CONST_CAST(t,e)  (const_cast<t> (e))
#define ACC_VERSION     20220904L
#  define ACC_WORDSIZE              8
#  define ACC_nullptr           nullptr
#define CHAR_BIT        8
#define CHAR_MAX        SCHAR_MAX
#define CHAR_MIN        SCHAR_MIN
#define INT_MAX         (__INT_MAX__)
#define INT_MIN         (-1 - INT_MAX)
#define LONG_MAX        ((__LONG_MAX__) + 0L)
#define LONG_MIN        (-1L - LONG_MAX)
#define MB_LEN_MAX      1
#    define MSDOS 1
#define NULL    nullptr
#define SCHAR_MAX       (__SCHAR_MAX__)
#define SCHAR_MIN       (-1 - SCHAR_MAX)
#define SHRT_MAX        (__SHRT_MAX__)
#define SHRT_MIN        (-1 - SHRT_MAX)
#define UCHAR_MAX       (SCHAR_MAX * 2 + 1)
#define UINT_MAX        (INT_MAX * 2U + 1U)
#define ULONG_MAX       (LONG_MAX * 2UL + 1UL)
#define USHRT_MAX       (SHRT_MAX * 2U + 1U)
#    define WIN32_LEAN_AND_MEAN 1
#  define _ALL_SOURCE 1
#define _CRT_NONSTDC_NO_DEPRECATE 1
#define _CRT_NONSTDC_NO_WARNINGS 1
#define _CRT_SECURE_NO_DEPRECATE 1
#define _CRT_SECURE_NO_WARNINGS 1
#    define _MSDOS 1
#  define _PTRDIFF_T_DEFINED 1
#define _SIZE_T_DEFINED 1
#define _WCHAR_T_DEFINED 1
#    define _WIN32_WINNT 0x0400
#define __ACCLIB_DOSALLOC_CH_INCLUDED 1
#  define __ACCLIB_FUNCNAME(f)  f
#define __ACCLIB_GETOPT_CH_INCLUDED 1
#define __ACCLIB_HALLOC_CH_INCLUDED 1
#  define __ACCLIB_HALLOC_USE_DAH 1
#  define __ACCLIB_HALLOC_USE_GA 1
#define __ACCLIB_HAVE_ACC_WILDARGV 1
#define __ACCLIB_HFREAD_CH_INCLUDED 1
#define __ACCLIB_HMEMCPY_CH_INCLUDED 1
#define __ACCLIB_HSREAD_CH_INCLUDED 1
#define __ACCLIB_MISC_CH_INCLUDED 1
#define __ACCLIB_PCLOCK_CH_INCLUDED 1
#define __ACCLIB_RAND_CH_INCLUDED 1
#define __ACCLIB_RDTSC_CH_INCLUDED 1
#  define __ACCLIB_RDTSC_REGS   : : "c" (t) : "memory", "rax", "rdx"
#define __ACCLIB_REQUIRE_HMEMCPY_CH 1
#  define __ACCLIB_REQUIRE_HREAD_CH 1
#define __ACCLIB_UA_CH_INCLUDED 1
#  define __ACCLIB_USE_OPENDIR 1
#define __ACCLIB_VGET_BODY(T) \
    if __acc_very_unlikely(acc_vget_ptr__) { \
        typedef T __acc_may_alias TT; \
        unsigned char e; expr &= 255; e = ACC_STATIC_CAST(unsigned char, expr); \
        * ACC_STATIC_CAST(TT *, acc_vget_ptr__) = v; \
        * ACC_STATIC_CAST(unsigned char *, acc_vget_ptr__) = e; \
        v = * ACC_STATIC_CAST(TT *, acc_vget_ptr__); \
    } \
    return v;
#define __ACCLIB_VGET_CH_INCLUDED 1
#define __ACCLIB_WILDARGV_CH_INCLUDED 1
#  define __ACC_ASM_CLOBBER                     "ax"
#  define __ACC_ASM_CLOBBER_LIST_CC             
#  define __ACC_ASM_CLOBBER_LIST_CC_MEMORY      
#  define __ACC_ASM_CLOBBER_LIST_EMPTY          
#  define __ACC_CTA_NAME(a)         ACC_PP_ECONCAT2(a,__COUNTER__)
#  define __ACC_CXX_DO_DELETE       { }
#  define __ACC_CXX_DO_NEW          { return 0; }
#  define __ACC_CXX_HAVE_ARRAY_NEW 1
#    define __ACC_CXX_HAVE_PLACEMENT_DELETE 1
#  define __ACC_CXX_HAVE_PLACEMENT_NEW 1
#define __ACC_CXX_H_INCLUDED 1
#define __ACC_FALLBACK_LIMITS_H_INCLUDED 1
#define __ACC_FALLBACK_STDDEF_H_INCLUDED 1
#define __ACC_H_INCLUDED 1
#define __ACC_INCD_H_INCLUDED 1
#define __ACC_INCE_H_INCLUDED 1
#define __ACC_INCI_H_INCLUDED 1
#  define __ACC_INTPTR_T_IS_POINTER 1
#define __ACC_LIB_H_INCLUDED 1
#define __ACC_LSR(x,b)    (((x)+0ul) >> (b))
#define __ACC_MASK_GEN(o,b)     (((((o) << ((b)-((b)!=0))) - (o)) << 1) + (o)*((b)!=0))
#      define __ACC_RENAME_A 1
#      define __ACC_RENAME_B 1
#      define __AZTEC_C__ __VERSION
#  define __CYGWIN__ __CYGWIN32__
#      define __DOS__ 1
#define __INT_MAX__     2147483647
#    define __LONG_MAX__ 9223372036854775807L
#define __SCHAR_MAX__   127
#define __SHRT_MAX__    32767
#    define __STDC_CONSTANT_MACROS 1
#    define __STDC_LIMIT_MACROS 1
#  define __acc_HAVE_alignof 1
#  define __acc_HAVE_c99_extern_inline 1
#  define __acc_HAVE_constructor 1
#  define __acc_HAVE_destructor 1
#  define __acc_HAVE_forceinline 1
#  define __acc_HAVE_inline 1
#  define __acc_HAVE_likely 1
#  define __acc_HAVE_may_alias 1
#  define __acc_HAVE_noinline 1
#  define __acc_HAVE_noreturn 1
#  define __acc_HAVE_nothrow 1
#  define __acc_HAVE_restrict 1
#  define __acc_HAVE_unlikely 1
#  define __acc_HAVE_unreachable 1
#  define __acc_HAVE_very_likely 1
#  define __acc_HAVE_very_unlikely 1
#  define __acc_alignof(e)      __alignof__(e)
#  define __acc_byte_struct(s,n)        __acc_struct_packed(s) unsigned char a[n]; __acc_struct_packed_end()
#  define __acc_byte_struct_ma(s,n)     __acc_struct_packed_ma(s) unsigned char a[n]; __acc_struct_packed_ma_end()
#  define __acc_c99_extern_inline   __acc_inline
#  define __acc_cdecl                   
#  define __acc_cdecl_atexit            
#  define __acc_cdecl_main              
#  define __acc_cdecl_qsort             
#  define __acc_cdecl_sighandler        
#  define __acc_cdecl_va                __acc_cdecl
#  define __acc_constructor     __attribute__((__constructor__,__used__))
#    define __acc_cte(e)            ((void)0,(e))
#  define __acc_destructor      __attribute__((__destructor__,__used__))
#  define __acc_forceinline     __inline__ __attribute__((__always_inline__))
#  define __acc_gnuc_extension__    __extension__
#  define __acc_inline          inline
#  define __acc_likely(e)       (__builtin_expect(!!(e),1))
#    define __acc_loop_forever()    ACC_BLOCK_BEGIN for (;;) { ; } ACC_BLOCK_END
#  define __acc_may_alias       __attribute__((__may_alias__))
#    define __acc_noinline      __declspec(noinline)
#  define __acc_noreturn        __attribute__((__noreturn__))
#  define __acc_nothrow         __attribute__((__nothrow__))
#  define __acc_restrict        __restrict__
#  define __acc_static_forceinline  __acc_gnuc_extension__ static __acc_forceinline
#  define __acc_static_inline       __acc_gnuc_extension__ static __acc_inline
#  define __acc_static_noinline     __acc_gnuc_extension__ static __acc_noinline
#  define __acc_struct_align16(s)       struct __declspec(align(16)) s {
#  define __acc_struct_align16_end()    };
#  define __acc_struct_align32(s)       struct __declspec(align(32)) s {
#  define __acc_struct_align32_end()    };
#  define __acc_struct_align64(s)       struct __declspec(align(64)) s {
#  define __acc_struct_align64_end()    };
#  define __acc_struct_packed(s)        struct s {
#  define __acc_struct_packed_end()     } __attribute__((__gcc_struct__,__packed__));
#  define __acc_struct_packed_ma(s)     __acc_struct_packed(s)
#  define __acc_struct_packed_ma_end()  } __acc_may_alias __attribute__((__gcc_struct__,__packed__));
#  define __acc_ua16_t __acc_ua16_t
#  define __acc_ua32_t __acc_ua32_t
#  define __acc_ua64_t __acc_ua64_t
#  define __acc_ua_volatile     volatile
#  define __acc_union_am(s)             union s {
#  define __acc_union_am_end()          } __acc_may_alias;
#  define __acc_union_um(s)             union s {
#  define __acc_union_um_end()          } __acc_may_alias __attribute__((__packed__));
#  define __acc_unlikely(e)     (__builtin_expect(!!(e),0))
#  define __acc_unreachable()       __builtin_unreachable();
#  define __acc_very_likely(e)      __acc_likely(e)
#  define __acc_very_unlikely(e)    __acc_unlikely(e)
#      define __cdecl cdecl
#      define __far far
#      define __huge huge
#      define __near near
#      define __pascal pascal
#  define acc_alloca(x)     __builtin_alloca((x))
#define acc_ascii_isdigit(c)    ((ACC_ICAST(unsigned, c) - 48) < 10)
#define acc_ascii_islower(c)    ((ACC_ICAST(unsigned, c) - 97) < 26)
#define acc_ascii_isupper(c)    ((ACC_ICAST(unsigned, c) - 65) < 26)
#define acc_ascii_tolower(c)    (ACC_ICAST(int, c) + (acc_ascii_isupper(c) << 5))
#define acc_ascii_toupper(c)    (ACC_ICAST(int, c) - (acc_ascii_islower(c) << 5))
#define acc_ascii_utolower(c)   acc_ascii_tolower(ACC_ITRUNC(unsigned char, c))
#define acc_ascii_utoupper(c)   acc_ascii_toupper(ACC_ITRUNC(unsigned char, c))
#define acc_dir_p acc_dir_t *
#define acc_getopt_longopt_p acc_getopt_longopt_t *
#define acc_getopt_p acc_getopt_t *
#  define acc_has_attribute         __has_attribute
#  define acc_has_builtin           __has_builtin
#  define acc_has_declspec_attribute        __has_declspec_attribute
#  define acc_has_extension         __has_extension
#  define acc_has_feature         __has_feature
#  define acc_hbyte_p   unsigned char __huge *
#  define acc_hchar_p   char __huge *
#  define acc_hchar_pp  char __huge * __huge *
#  define acc_hsize_t   unsigned long
#  define acc_hvoid_p   void __huge *
#define acc_int16_t                 acc_int16e_t
#  define acc_int16e_t              long
#define acc_int32_t                 acc_int32e_t
#  define acc_int32e_t              long int
#  define acc_int32f_t              acc_int64l_t
#  define acc_int32l_t              acc_int32e_t
#define acc_int64_t                 acc_int64e_t
#  define acc_int64e_t              int
#  define acc_int64f_t              acc_int64l_t
#  define acc_int64l_t              acc_int64e_t
#define acc_int8_t                  signed char
#define acc_int_fast32_t           acc_int32f_t
#define acc_int_fast64_t           acc_int64f_t
#define acc_int_least32_t           acc_int32l_t
#define acc_int_least64_t           acc_int64l_t
#  define acc_intptr_t              acc_intptr_t
#  define acc_llong_t               acc_llong_t__
#define acc_pclock_handle_p acc_pclock_handle_t *
#define acc_pclock_p acc_pclock_t *
#define acc_pclock_read_clock acc_pclock_read_clock
#define acc_pclock_read_clock_gettime_m_syscall acc_pclock_read_clock_gettime_m_syscall
#define acc_pclock_read_clock_gettime_p_libc acc_pclock_read_clock_gettime_p_libc
#define acc_pclock_read_clock_gettime_p_syscall acc_pclock_read_clock_gettime_p_syscall
#define acc_pclock_read_clock_gettime_t_libc acc_pclock_read_clock_gettime_t_libc
#define acc_pclock_read_clock_gettime_t_syscall acc_pclock_read_clock_gettime_t_syscall
#define acc_pclock_read_getprocesstimes acc_pclock_read_getprocesstimes
#define acc_pclock_read_getrusage acc_pclock_read_getrusage
#define acc_pclock_read_getthreadtimes acc_pclock_read_getthreadtimes
#define acc_pclock_read_gettimeofday acc_pclock_read_gettimeofday
#define acc_pclock_read_uclock acc_pclock_read_uclock
#define acc_pclock_syscall_clock_gettime acc_pclock_syscall_clock_gettime
#define acc_rand31_p acc_rand31_t *
#define acc_rand48_p acc_rand48_t *
#define acc_rand64_p acc_rand64_t *
#define acc_randmt64_p acc_randmt64_t *
#define acc_randmt_p acc_randmt_t *
#  define acc_signo_t               acc_int32e_t
#    define acc_stackavail()  stackavail()
#  define acc_sword_t               acc_intptr_t
#define acc_uint16_t                acc_uint16e_t
#  define acc_uint16e_t             unsigned long
#define acc_uint32_t                acc_uint32e_t
#  define acc_uint32e_t             unsigned long int
#  define acc_uint32f_t             acc_uint64l_t
#  define acc_uint32l_t             acc_uint32e_t
#define acc_uint64_t                acc_uint64e_t
#  define acc_uint64e_t             unsigned int
#  define acc_uint64f_t             acc_uint64l_t
#  define acc_uint64l_t             acc_uint64e_t
#define acc_uint8_t                 unsigned char
#define acc_uint_fast32_t          acc_uint32f_t
#define acc_uint_fast64_t          acc_uint64f_t
#define acc_uint_least32_t          acc_uint32l_t
#define acc_uint_least64_t          acc_uint64l_t
#  define acc_uintptr_t             acc_uintptr_t
#  define acc_ullong_t              acc_ullong_t__
#    define acc_unused_funcs_impl(r,f)  static r __attribute__((__unused__)) f
#  define acc_word_t                acc_uintptr_t
#  define acclib_handle_t       long
#define offsetof(s,m)   ((size_t)((ptrdiff_t)&(((s*)NULL)->m)))
#define pe  __ACCLIB_FUNCNAME(acc_getopt_perror)
#  define ptrdiff_t long
#define UPX_VERSION_DATE        "Nov 22nd 2022"
#define UPX_VERSION_DATE_ISO    "2022-11-22"
#define UPX_VERSION_HEX         0x040002        
#define UPX_VERSION_STRING      "4.0.2"
#define UPX_VERSION_STRING4     "4.02"
#define UPX_VERSION_YEAR        "2022"
