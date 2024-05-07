

#include<float.h>
#include<sys/types.h>
#include<time.h>
#include<setjmp.h>

#include<errno.h>
#include<math.h>
#include<stdio.h>


#include<assert.h>

#include<stdlib.h>


#include<ctype.h>
#include<limits.h>
#include<stdint.h>
#define MPH_BUCKETS 7016
#define MPH_RSHIFT 8
#define MPH_VALt I16
#define PL_E_FORMAT_PRECISION 2
#   define BOM_UTF8  "\xDD\x73\x66\x73"    
#   define BOM_UTF8_FIRST_BYTE  0xDD    
#   define BOM_UTF8_TAIL  "\x73\x66\x73"    
#   define COMBINING_DOT_ABOVE_UTF8  "\xAF\x48"    
#   define COMBINING_GRAVE_ACCENT_UTF8  "\xAD\x41"    
#   define CR_NATIVE  0x0D    
#   define DEL_NATIVE  0x07    
#   define ESC_NATIVE  0x27    
#define HIGHEST_CASE_CHANGING_CP_FOR_USE_ONLY_BY_UTF8_DOT_C  0x1E943
#   define HYPHEN_UTF8  "\xCA\x41\x57"    
#   define LATIN_CAPITAL_LETTER_A_WITH_RING_ABOVE_NATIVE  0x67    
#   define LATIN_CAPITAL_LETTER_I_WITH_DOT_ABOVE_UTF8  "\x8D\x57"    
#   define LATIN_CAPITAL_LETTER_SHARP_S_UTF8  "\xBF\x63\x72"    
#   define LATIN_SMALL_LETTER_A_WITH_RING_ABOVE_NATIVE  0x47    
#   define LATIN_SMALL_LETTER_DOTLESS_I_UTF8  "\x8D\x58"    
#   define LATIN_SMALL_LETTER_LONG_S_UTF8  "\x8E\x72"    
#   define LATIN_SMALL_LETTER_SHARP_S_NATIVE  0x59    
#   define LATIN_SMALL_LETTER_Y_WITH_DIAERESIS_NATIVE  0xDF    
#   define LATIN_SMALL_LIGATURE_LONG_S_T_UTF8  "\xDD\x72\x67\x46"    
#   define LATIN_SMALL_LIGATURE_ST_UTF8  "\xDD\x72\x67\x47"    
#   define LF_NATIVE  0x15    
#   define MAX_PRINT_A_FOR_USE_ONLY_BY_REGCOMP_DOT_C   0xF9   
#   define MAX_UNICODE_UTF8  "\xEE\x42\x73\x73\x73"    
#   define MICRO_SIGN_NATIVE  0xA0    
#   define NBSP_NATIVE  0x41    
#   define NBSP_UTF8  "\x80\x41"    
#define NON_OTHER_COUNT_FOR_USE_ONLY_BY_REGCOMP_DOT_C  137768
#define PERL_UNICODE_CONSTANTS_H_   1
#   define REPLACEMENT_CHARACTER_UTF8  "\xDD\x73\x73\x71"    
#define UNICODE_DOT_DOT_VERSION 0
#define UNICODE_DOT_VERSION     1
#define UNICODE_MAJOR_VERSION   12
#   define VT_NATIVE  0x0B    
#define ELEMENT_RANGE_MATCHES_INVLIST(i) (! ((i) & 1))
#define FROM_INTERNAL_SIZE(x) ((x)/ sizeof(UV))

#define PREV_RANGE_MATCHES_INVLIST(i) (! ELEMENT_RANGE_MATCHES_INVLIST(i))
#define TO_INTERNAL_SIZE(x) ((x) * sizeof(UV))

#define AMT_AMAGIC(amt)		((amt)->flags & AMTf_AMAGIC)
#define AMT_AMAGIC_off(amt)	((amt)->flags &= ~AMTf_AMAGIC)
#define AMT_AMAGIC_on(amt)	((amt)->flags |= AMTf_AMAGIC)

#    define ASSUME(x) ((x) ? (void) 0 : __builtin_unreachable())
#   define Atoul(s)	Strtoul(s, NULL, 10)
#  define BSD_GETPGRP(pid)		getpgid((pid))
#  define BSD_SETPGRP(pid, pgrp)	setpgid((pid), (pgrp))
#       define BSDish
#   define BYTEORDER 0x1234
#define CALLREGCOMP(sv, flags) Perl_pregcomp(aTHX_ (sv),(flags))
#define CALLREGCOMP_ENG(prog, sv, flags) (prog)->comp(aTHX_ sv, flags)
#define CALLREGDUPE(prog,param) \
    Perl_re_dup(aTHX_ (prog),(param))
#define CALLREGDUPE_PVT(prog,param) \
    (prog ? RX_ENGINE(prog)->dupe(aTHX_ (prog),(param)) \
          : (REGEXP *)NULL)
#define CALLREGEXEC(prog,stringarg,strend,strbeg,minend,sv,data,flags) \
    RX_ENGINE(prog)->exec(aTHX_ (prog),(stringarg),(strend), \
        (strbeg),(minend),(sv),(data),(flags))
#define CALLREGFREE(prog) \
    Perl_pregfree(aTHX_ (prog))
#define CALLREGFREE_PVT(prog) \
    if(prog && RX_ENGINE(prog)) RX_ENGINE(prog)->rxfree(aTHX_ (prog))
#define CALLREG_INTUIT_START(prog,sv,strbeg,strpos,strend,flags,data) \
    RX_ENGINE(prog)->intuit(aTHX_ (prog), (sv), (strbeg), (strpos), \
        (strend),(flags),(data))
#define CALLREG_INTUIT_STRING(prog) \
    RX_ENGINE(prog)->checkstr(aTHX_ (prog))
#define CALLREG_NAMED_BUFF_ALL(rx, flags) \
    RX_ENGINE(rx)->named_buff(aTHX_ (rx), NULL, NULL, flags)
#define CALLREG_NAMED_BUFF_CLEAR(rx, flags) \
    RX_ENGINE(rx)->named_buff(aTHX_ (rx), NULL, NULL, ((flags) | RXapif_CLEAR))
#define CALLREG_NAMED_BUFF_COUNT(rx) \
    RX_ENGINE(rx)->named_buff(aTHX_ (rx), NULL, NULL, RXapif_REGNAMES_COUNT)
#define CALLREG_NAMED_BUFF_DELETE(rx, key, flags) \
    RX_ENGINE(rx)->named_buff(aTHX_ (rx),(key), NULL, ((flags) | RXapif_DELETE))
#define CALLREG_NAMED_BUFF_EXISTS(rx, key, flags) \
    RX_ENGINE(rx)->named_buff(aTHX_ (rx), (key), NULL, ((flags) | RXapif_EXISTS))
#define CALLREG_NAMED_BUFF_FETCH(rx, key, flags) \
    RX_ENGINE(rx)->named_buff(aTHX_ (rx), (key), NULL, ((flags) | RXapif_FETCH))
#define CALLREG_NAMED_BUFF_FIRSTKEY(rx, flags) \
    RX_ENGINE(rx)->named_buff_iter(aTHX_ (rx), NULL, ((flags) | RXapif_FIRSTKEY))
#define CALLREG_NAMED_BUFF_NEXTKEY(rx, lastkey, flags) \
    RX_ENGINE(rx)->named_buff_iter(aTHX_ (rx), (lastkey), ((flags) | RXapif_NEXTKEY))
#define CALLREG_NAMED_BUFF_SCALAR(rx, flags) \
    RX_ENGINE(rx)->named_buff(aTHX_ (rx), NULL, NULL, ((flags) | RXapif_SCALAR))
#define CALLREG_NAMED_BUFF_STORE(rx, key, value, flags) \
    RX_ENGINE(rx)->named_buff(aTHX_ (rx), (key), (value), ((flags) | RXapif_STORE))
#define CALLREG_NUMBUF_FETCH(rx,paren,usesv)                                \
    RX_ENGINE(rx)->numbered_buff_FETCH(aTHX_ (rx),(paren),(usesv))
#define CALLREG_NUMBUF_LENGTH(rx,sv,paren)                              \
    RX_ENGINE(rx)->numbered_buff_LENGTH(aTHX_ (rx),(sv),(paren))
#define CALLREG_NUMBUF_STORE(rx,paren,value) \
    RX_ENGINE(rx)->numbered_buff_STORE(aTHX_ (rx),(paren),(value))
#define CALLREG_PACKAGE(rx) \
    RX_ENGINE(rx)->qr_package(aTHX_ (rx))
#define CALLRUNOPS  PL_runops
#define CALL_FPTR(fptr) (*fptr)

#  define CHECK_MALLOC_TAINT(newval)				\
	CHECK_MALLOC_TOO_LATE_FOR_(				\
		if (newval) {					\
		  PERL_UNUSED_RESULT(panic_write2("panic: tainting with $ENV{PERL_MALLOC_OPT}\n"));\
		  exit(1); })
#  define CHECK_MALLOC_TOO_LATE_FOR(ch)				\
	CHECK_MALLOC_TOO_LATE_FOR_(MALLOC_TOO_LATE_FOR(ch))
#  define CHECK_MALLOC_TOO_LATE_FOR_(code)	STMT_START {		\
	if (!TAINTING_get && MallocCfg_ptr[MallocCfg_cfg_env_read])	\
		code;							\
    } STMT_END
#  define CLANG_DIAG_IGNORE(x) _Pragma("clang diagnostic push") \
                               CLANG_DIAG_PRAGMA(clang diagnostic ignored #x)
#define CLANG_DIAG_IGNORE_DECL(x) CLANG_DIAG_IGNORE(x) dNOOP
#define CLANG_DIAG_IGNORE_STMT(x) CLANG_DIAG_IGNORE(x) NOOP
#  define CLANG_DIAG_PRAGMA(x) _Pragma (#x)
#  define CLANG_DIAG_RESTORE   _Pragma("clang diagnostic pop")
#define CLANG_DIAG_RESTORE_DECL CLANG_DIAG_RESTORE dNOOP
#define CLANG_DIAG_RESTORE_STMT CLANG_DIAG_RESTORE NOOP
#define CLEAR_ERRSV() STMT_START {					\
    SV ** const svp = &GvSV(PL_errgv);					\
    if (!*svp) {							\
        *svp = newSVpvs("");                                            \
    } else if (SvREADONLY(*svp)) {					\
	SvREFCNT_dec_NN(*svp);						\
	*svp = newSVpvs("");						\
    } else {								\
	SV *const errsv = *svp;						\
        SvPVCLEAR(errsv);                                               \
	SvPOK_only(errsv);						\
	if (SvMAGICAL(errsv)) {						\
	    mg_free(errsv);						\
	}								\
    }									\
    } STMT_END
#define CLUMP_2IV(uv)	((uv) > (UV)IV_MAX ? IV_MAX : (IV)(uv))
#define CLUMP_2UV(iv)	((iv) < 0 ? 0 : (UV)(iv))
#define CPERLarg void

#define CPERLscope(x) x
#  define C_FAC_POSIX 0x35A000
#define DBVARMG_COUNT   3
#define DBVARMG_SIGNAL  2
#define DBVARMG_SINGLE  0
#define DBVARMG_TRACE   1
#  define DEBUG_A(a)
#  define DEBUG_A_TEST (0)
#  define DEBUG_A_TEST_ UNLIKELY(PL_debug & DEBUG_A_FLAG)
#  define DEBUG_B(a)
#  define DEBUG_B_TEST (0)
#  define DEBUG_B_TEST_ UNLIKELY(PL_debug & DEBUG_B_FLAG)
#  define DEBUG_C(a)
#  define DEBUG_C_TEST (0)
#  define DEBUG_C_TEST_ UNLIKELY(PL_debug & DEBUG_C_FLAG)
#  define DEBUG_D(a)
#  define DEBUG_D_TEST (0)
#  define DEBUG_D_TEST_ UNLIKELY(PL_debug & DEBUG_D_FLAG)
#  define DEBUG_J_TEST (0)
#  define DEBUG_J_TEST_ UNLIKELY(PL_debug & DEBUG_J_FLAG)
#  define DEBUG_L(a)
#  define DEBUG_L_TEST (0)
#  define DEBUG_L_TEST_ UNLIKELY(PL_debug & DEBUG_L_FLAG)
#  define DEBUG_Lv(a)
#  define DEBUG_Lv_TEST (0)
#  define DEBUG_Lv_TEST_ (DEBUG_L_TEST_ && DEBUG_v_TEST_)
#  define DEBUG_M(a)
#  define DEBUG_M_TEST (0)
#  define DEBUG_M_TEST_ UNLIKELY(PL_debug & DEBUG_M_FLAG)
#  define DEBUG_P(a)
#  define DEBUG_P_TEST (0)
#  define DEBUG_P_TEST_ UNLIKELY(PL_debug & DEBUG_P_FLAG)
#  define DEBUG_Pv(a)
#  define DEBUG_Pv_TEST (0)
#  define DEBUG_Pv_TEST_ (DEBUG_P_TEST_ && DEBUG_v_TEST_)
#  define DEBUG_R(a)
#  define DEBUG_R_TEST (0)
#  define DEBUG_R_TEST_ UNLIKELY(PL_debug & DEBUG_R_FLAG)
#  define DEBUG_S(a)
#define DEBUG_SCOPE(where) \
    DEBUG_l( \
    Perl_deb(aTHX_ "%s scope %ld (savestack=%ld) at %s:%d\n",	\
		    where, (long)PL_scopestack_ix, (long)PL_savestack_ix, \
		    "__FILE__", "__LINE__"));
#  define DEBUG_S_TEST (0)
#  define DEBUG_S_TEST_ UNLIKELY(PL_debug & DEBUG_S_FLAG)
#  define DEBUG_T(a)
#  define DEBUG_T_TEST (0)
#  define DEBUG_T_TEST_ UNLIKELY(PL_debug & DEBUG_T_FLAG)
#  define DEBUG_U(a)
#  define DEBUG_U_TEST (0)
#  define DEBUG_U_TEST_ UNLIKELY(PL_debug & DEBUG_U_FLAG)
#  define DEBUG_Uv(a)
#  define DEBUG_Uv_TEST (0)
#  define DEBUG_Uv_TEST_ (DEBUG_U_TEST_ && DEBUG_v_TEST_)
#  define DEBUG_X(a)
#  define DEBUG_X_TEST (0)
#  define DEBUG_X_TEST_ UNLIKELY(PL_debug & DEBUG_X_FLAG)
#  define DEBUG_Xv(a)
#  define DEBUG_Xv_TEST (0)
#  define DEBUG_Xv_TEST_ (DEBUG_X_TEST_ && DEBUG_v_TEST_)
#  define DEBUG__(t, a)                                                 \
        STMT_START {                                                    \
                if (t) STMT_START {a;} STMT_END;                        \
        } STMT_END
#  define DEBUG_c(a)
#  define DEBUG_c_TEST (0)
#  define DEBUG_c_TEST_ UNLIKELY(PL_debug & DEBUG_c_FLAG)
#  define DEBUG_f(a)
#  define DEBUG_f_TEST (0)
#  define DEBUG_f_TEST_ UNLIKELY(PL_debug & DEBUG_f_FLAG)
#  define DEBUG_i(a)
#  define DEBUG_i_TEST (0)
#  define DEBUG_i_TEST_ UNLIKELY(PL_debug & DEBUG_i_FLAG)
#  define DEBUG_l(a)
#  define DEBUG_l_TEST (0)
#  define DEBUG_l_TEST_ UNLIKELY(PL_debug & DEBUG_l_FLAG)
#  define DEBUG_m(a)  \
    STMT_START {					                \
        if (PERL_GET_INTERP) {                                          \
                                dTHX;                                   \
                                if (DEBUG_m_TEST) {                     \
                                    PL_debug &= ~DEBUG_m_FLAG;          \
                                    a;                                  \
                                    PL_debug |= DEBUG_m_FLAG;           \
                                }                                       \
                              }                                         \
    } STMT_END
#  define DEBUG_m_TEST (0)
#  define DEBUG_m_TEST_ UNLIKELY(PL_debug & DEBUG_m_FLAG)
#  define DEBUG_o(a)
#  define DEBUG_o_TEST (0)
#  define DEBUG_o_TEST_ UNLIKELY(PL_debug & DEBUG_o_FLAG)
#  define DEBUG_p(a)
#  define DEBUG_p_TEST (0)
#  define DEBUG_p_TEST_ UNLIKELY(PL_debug & DEBUG_p_FLAG)
#  define DEBUG_q(a)
#  define DEBUG_q_TEST (0)
#  define DEBUG_q_TEST_ UNLIKELY(PL_debug & DEBUG_q_FLAG)
#    define DEBUG_r(a) STMT_START {a;} STMT_END
#  define DEBUG_r_TEST (0)
#  define DEBUG_r_TEST_ UNLIKELY(PL_debug & DEBUG_r_FLAG)
#  define DEBUG_s(a)
#  define DEBUG_s_TEST (0)
#  define DEBUG_s_TEST_ UNLIKELY(PL_debug & DEBUG_s_FLAG)
#  define DEBUG_t(a)
#  define DEBUG_t_TEST (0)
#  define DEBUG_t_TEST_ UNLIKELY(PL_debug & DEBUG_t_FLAG)
#  define DEBUG_u(a)
#  define DEBUG_u_TEST (0)
#  define DEBUG_u_TEST_ UNLIKELY(PL_debug & DEBUG_u_FLAG)
#  define DEBUG_v(a)
#  define DEBUG_v_TEST (0)
#  define DEBUG_v_TEST_ UNLIKELY(PL_debug & DEBUG_v_FLAG)
#  define DEBUG_x(a)
#  define DEBUG_x_TEST (0)
#  define DEBUG_x_TEST_ UNLIKELY(PL_debug & DEBUG_x_FLAG)
#  define DECLARATION_FOR_LC_NUMERIC_MANIPULATION                           \
    void (*_restore_LC_NUMERIC_function)(pTHX) = NULL
# define DEFSV (0 + GvSVn(PL_defgv))
# define DEFSV_set(sv) \
    (SvREFCNT_dec(GvSV(PL_defgv)), GvSV(PL_defgv) = SvREFCNT_inc(sv))
#define DOSISH 1
#  define DOUBLE_BIG_ENDIAN
#  define DOUBLE_HAS_INF
#  define DOUBLE_HAS_NAN
#  define DOUBLE_IS_IEEE_FORMAT
#  define DOUBLE_IS_VAX_FLOAT
#  define DOUBLE_LITTLE_ENDIAN
#  define DOUBLE_MIX_ENDIAN
#  define DOUBLE_VAX_ENDIAN
#define DPTR2FPTR(t,p) ((t)PTR2nat(p))	
#  define END_EXTERN_C }
#define ERRSV GvSVn(PL_errgv)
#define EXEC_ARGV_CAST(x) (char **)x
#  define EXPECT(expr,val)                  __builtin_expect(expr,val)
#  define EXTERN_C extern "C"
#define EXT_MGVTBL EXTCONST MGVTBL

#  define  FAKE_DEFAULT_SIGNAL_HANDLERS
#  define  FAKE_PERSISTENT_SIGNAL_HANDLERS
#define FILTER_DATA(idx) \
	    (PL_parser ? AvARRAY(PL_parser->rsfp_filters)[idx] : NULL)
#define FILTER_ISREADER(idx) \
	    (PL_parser && PL_parser->rsfp_filters \
		&& idx >= AvFILLp(PL_parser->rsfp_filters))
#define FILTER_READ(idx, sv, len)  filter_read(idx, sv, len)
#define FPTR2DPTR(t,p) ((t)PTR2nat(p))	
#     define FP_PINF FP_PINF
#     define FP_QNAN FP_QNAN
#       define FSEEKSIZE LSEEKSIZE
#       define F_atan2_amg  atan2_amg
#       define F_cos_amg    cos_amg
#       define F_exp_amg    exp_amg
#       define F_log_amg    log_amg
#       define F_pow_amg    pow_amg
#       define F_sin_amg    sin_amg
#       define F_sqrt_amg   sqrt_amg
#       define Fpos_t fpos64_t
#  define GCC_DIAG_IGNORE(x) _Pragma("GCC diagnostic push") \
                             GCC_DIAG_PRAGMA(GCC diagnostic ignored #x)
#define GCC_DIAG_IGNORE_DECL(x) GCC_DIAG_IGNORE(x) dNOOP
#define GCC_DIAG_IGNORE_STMT(x) GCC_DIAG_IGNORE(x) NOOP
#  define GCC_DIAG_PRAGMA(x) _Pragma (#x)
#  define GCC_DIAG_RESTORE   _Pragma("GCC diagnostic pop")
#define GCC_DIAG_RESTORE_DECL GCC_DIAG_RESTORE dNOOP
#define GCC_DIAG_RESTORE_STMT GCC_DIAG_RESTORE NOOP
#define GROK_NUMERIC_RADIX(sp, send) grok_numeric_radix(sp, send)
#    define HASATTRIBUTE_DEPRECATED
#    define HASATTRIBUTE_FORMAT
#    define HASATTRIBUTE_MALLOC
#    define HASATTRIBUTE_NONNULL
#    define HASATTRIBUTE_NORETURN
#    define HASATTRIBUTE_PURE
#    define HASATTRIBUTE_UNUSED 
#    define HASATTRIBUTE_WARN_UNUSED_RESULT
#  define HAS_C99 1
#  define HAS_GETPGRP  




#    define HAS_POSIX_2008_LOCALE
#      define HAS_QUAD
#  define HAS_SETPGRP  
#    define HAS_SETREGID
#    define HAS_SETREUID
#   define HAS_SKIP_LOCALE_INIT 
#  define HEKf "2p"
#  define HEKf256 "3p"
#define HEKfARG(p) ((void*)(p))
#define H_PERL 1
#define I32_MAX_P1 (2.0 * (1 + (((U32)I32_MAX) >> 1)))
#       define INCLUDE_PROTOTYPES 
#define INFNAN_NV_U8_DECL EXTCONST union { NV nv; U8 u8[NVSIZE]; }
#define INFNAN_U8_NV_DECL EXTCONST union { U8 u8[NVSIZE]; NV nv; }
#  define INIT_TRACK_MEMPOOL(header, interp)			\
	STMT_START {						\
		(header).interpreter = (interp);		\
		(header).prev = (header).next = &(header);	\
		(header).readonly = 0;				\
	} STMT_END
#  define INT2PTR(any,d)	(any)(d)
#    define INT64_C(c) PeRl_INT64_C(c)
#    define INTMAX_C(c) INT64_C(c)
#  define IN_LC(category)  \
                    (IN_LC_COMPILETIME(category) || IN_LC_RUNTIME(category))
#  define IN_LC_ALL_COMPILETIME   IN_LOCALE_COMPILETIME
#  define IN_LC_ALL_RUNTIME       IN_LOCALE_RUNTIME
#  define IN_LC_COMPILETIME(category)                                       \
       (       IN_LC_ALL_COMPILETIME                                        \
        || (   IN_LC_PARTIAL_COMPILETIME                                    \
            && Perl__is_in_locale_category(aTHX_ TRUE, (category))))
#  define IN_LC_PARTIAL_COMPILETIME   cBOOL(PL_hints & HINT_LOCALE_PARTIAL)
#  define IN_LC_PARTIAL_RUNTIME                                             \
              (PL_curcop && CopHINTS_get(PL_curcop) & HINT_LOCALE_PARTIAL)
#  define IN_LC_RUNTIME(category)                                           \
      (IN_LC_ALL_RUNTIME || (IN_LC_PARTIAL_RUNTIME                          \
                 && Perl__is_in_locale_category(aTHX_ FALSE, (category))))
#  define IN_LOCALE                                                         \
        (IN_PERL_COMPILETIME ? IN_LOCALE_COMPILETIME : IN_LOCALE_RUNTIME)
#  define IN_LOCALE_COMPILETIME            0
#  define IN_LOCALE_RUNTIME                0
#  define IN_SOME_LOCALE_FORM                                               \
                    (IN_PERL_COMPILETIME ? IN_SOME_LOCALE_FORM_COMPILETIME  \
                                         : IN_SOME_LOCALE_FORM_RUNTIME)
#  define IN_SOME_LOCALE_FORM_COMPILETIME                                   \
                        cBOOL(PL_hints & (HINT_LOCALE|HINT_LOCALE_PARTIAL))
#  define IN_SOME_LOCALE_FORM_RUNTIME                                       \
        cBOOL(CopHINTS_get(PL_curcop) & (HINT_LOCALE|HINT_LOCALE_PARTIAL))
#define IS_NUMBER_GREATER_THAN_UV_MAX 0x02 
#define IS_NUMBER_NAN                 0x20 
#define IS_NUMBER_TRAILING            0x40 
#  define IS_NUMERIC_RADIX(a, b)		(0)
#define IS_SAFE_PATHNAME(p, len, op_name) IS_SAFE_SYSCALL((p), (len), "pathname", (op_name))
#define IS_SAFE_SYSCALL(p, len, what, op_name) (S_is_safe_syscall(aTHX_ (p), (len), (what), (op_name)))
#define IV_DIG (BIT_DIGITS(IVSIZE * 8))
#    define IV_IS_QUAD
#    define IV_MAX INT64_MAX
#define IV_MAX_P1 (2.0 * (1 + (((UV)IV_MAX) >> 1)))
#    define IV_MIN INT64_MIN
#define I_32(what) (cast_i32((NV)(what)))


#define I_V(what) (cast_iv((NV)(what)))
#define KEYWORD_PLUGIN_DECLINE 0
#define KEYWORD_PLUGIN_EXPR    2
#  define KEYWORD_PLUGIN_MUTEX_INIT    MUTEX_INIT(&PL_keyword_plugin_mutex)
#  define KEYWORD_PLUGIN_MUTEX_LOCK    MUTEX_LOCK(&PL_keyword_plugin_mutex)
#  define KEYWORD_PLUGIN_MUTEX_TERM    MUTEX_DESTROY(&PL_keyword_plugin_mutex)
#  define KEYWORD_PLUGIN_MUTEX_UNLOCK  MUTEX_UNLOCK(&PL_keyword_plugin_mutex)
#define KEYWORD_PLUGIN_STMT    1
#define KEY_sigvar 0xFFFF 
#    define LC_NUMERIC_LOCK(cond)
#    define LC_NUMERIC_UNLOCK                                               \
        STMT_START {                                                        \
            if (PL_lc_numeric_mutex_depth <= 1) {                           \
                MUTEX_UNLOCK(&PL_lc_numeric_mutex);                         \
                PL_lc_numeric_mutex_depth = 0;                              \
                DEBUG_Lv(PerlIO_printf(Perl_debug_log,                      \
                         "%s: %d: unlocking lc_numeric; depth=0\n",         \
                         "__FILE__", "__LINE__"));                              \
            }                                                               \
            else {                                                          \
                PL_lc_numeric_mutex_depth--;                                \
                DEBUG_Lv(PerlIO_printf(Perl_debug_log,                      \
                        "%s: %d: avoided lc_numeric_unlock; depth=%d\n",    \
                        "__FILE__", "__LINE__", PL_lc_numeric_mutex_depth));    \
            }                                                               \
        } STMT_END                                                          \
        CLANG_DIAG_RESTORE
#    define LDBL_DIG 18 
#   define LIBERAL 1
#   define LIB_INVARG 		LIB$_INVARG
#define LIKELY(cond)                        EXPECT(cBOOL(cond),TRUE)
#    define LOCALE_INIT     MUTEX_INIT(&PL_locale_mutex);
#    define LOCALE_LOCK     LOCALE_LOCK_V
#  define LOCALE_LOCK_V                                                     \
        STMT_START {                                                        \
            DEBUG_Lv(PerlIO_printf(Perl_debug_log,                          \
                    "%s: %d: locking locale\n", "__FILE__", "__LINE__"));       \
            MUTEX_LOCK(&PL_locale_mutex);                                   \
        } STMT_END
#    define LOCALE_TERM     MUTEX_DESTROY(&PL_locale_mutex)
#    define LOCALE_UNLOCK   LOCALE_UNLOCK_V
#  define LOCALE_UNLOCK_V                                                   \
        STMT_START {                                                        \
            DEBUG_Lv(PerlIO_printf(Perl_debug_log,                          \
                   "%s: %d: unlocking locale\n", "__FILE__", "__LINE__"));      \
            MUTEX_UNLOCK(&PL_locale_mutex);                                 \
        } STMT_END
#  define LOCK_LC_NUMERIC_STANDARD()                                        \
        STMT_START {                                                        \
            DEBUG_Lv(PerlIO_printf(Perl_debug_log,                          \
                      "%s: %d: lock lc_numeric_standard: new depth=%d\n",   \
                      "__FILE__", "__LINE__", PL_numeric_standard + 1));        \
            __ASSERT_(PL_numeric_standard)                                  \
            PL_numeric_standard++;                                          \
        } STMT_END
#    define LONGDOUBLE_BIG_ENDIAN
#    define LONGDOUBLE_DOUBLEDOUBLE
#    define LONGDOUBLE_LITTLE_ENDIAN
#    define LONGDOUBLE_MIX_ENDIAN
#    define LONGDOUBLE_VAX_ENDIAN
#    define LONGDOUBLE_X86_80_BIT
#    define LONG_DOUBLE_EQUALS_DOUBLE
#       define LSEEKSIZE 8
#  define MALLOC_CHECK_TAINT(argc,argv,env)	STMT_START {	\
	if (doing_taint(argc,argv,env)) {			\
		MallocCfg_ptr[MallocCfg_skip_cfg_env] = 1;	\
    }} STMT_END;
#define MALLOC_CHECK_TAINT2(argc,argv)	MALLOC_CHECK_TAINT(argc,argv,NULL)
#    define MALLOC_INIT MUTEX_INIT(&PL_malloc_mutex)
#    define MALLOC_TERM MUTEX_DESTROY(&PL_malloc_mutex)
#define MALLOC_TOO_LATE_FOR(ch)	TOO_LATE_FOR_(ch, " with $ENV{PERL_MALLOC_OPT}")
#         define MAXPATHLEN PATH_MAX
#   define MAXSYSFD 2
#  define MB_CUR_MAX 1uL
#define MEMBER_TO_FPTR(name) name
#define MEM_SIZE Size_t
#  define MSVC_DIAG_IGNORE(x) __pragma(warning(push)) \
                              __pragma(warning(disable : x))
#define MSVC_DIAG_IGNORE_DECL(x) MSVC_DIAG_IGNORE(x) dNOOP
#define MSVC_DIAG_IGNORE_STMT(x) MSVC_DIAG_IGNORE(x) NOOP
#  define MSVC_DIAG_RESTORE   __pragma(warning(pop))
#define MSVC_DIAG_RESTORE_DECL MSVC_DIAG_RESTORE dNOOP
#define MSVC_DIAG_RESTORE_STMT MSVC_DIAG_RESTORE NOOP
#    define MULTIPLICITY
#  define MY_CXT_CLONE \
	my_cxt_t *my_cxtp = (my_cxt_t*)SvPVX(newSV(sizeof(my_cxt_t)-1));\
	void * old_my_cxtp = PL_my_cxt_list[MY_CXT_INDEX];		\
	PL_my_cxt_list[MY_CXT_INDEX] = my_cxtp;				\
	Copy(old_my_cxtp, my_cxtp, 1, my_cxt_t);
#    define MY_CXT_INDEX Perl_my_cxt_index(aTHX_ MY_CXT_KEY)
#  define MY_CXT_INIT \
	my_cxt_t *my_cxtp = \
	    (my_cxt_t*)Perl_my_cxt_init(aTHX_ MY_CXT_INIT_ARG, sizeof(my_cxt_t)); \
	PERL_UNUSED_VAR(my_cxtp)
#    define MY_CXT_INIT_ARG MY_CXT_KEY
#  define MY_CXT_INIT_INTERP(my_perl) \
	my_cxt_t *my_cxtp = \
	    (my_cxt_t*)Perl_my_cxt_init(my_perl, MY_CXT_INIT_ARG, sizeof(my_cxt_t)); \
	PERL_UNUSED_VAR(my_cxtp)
#    define N0 0
#    define N1 ((N0)   + NUM_CLASSES)
#    define N10 ((N9)  + NUM_CLASSES)
#    define N11 ((N10) + NUM_CLASSES)
#    define N2 ((N1)   + NUM_CLASSES)
#    define N3 ((N2)   + NUM_CLASSES)
#    define N4 ((N3)   + NUM_CLASSES)
#    define N5 ((N4)   + NUM_CLASSES)
#    define N6 ((N5)   + NUM_CLASSES)
#    define N7 ((N6)   + NUM_CLASSES)
#    define N8 ((N7)   + NUM_CLASSES)
#    define N9 ((N8)   + NUM_CLASSES)
#  define NAN_COMPARE_BROKEN
#  define NDEBUG 1
#define NOOP (void)0
#  define NORETURN_FUNCTION_END NOT_REACHED;
#  define NOT_REACHED STMT_START { ASSUME(0); __builtin_unreachable(); } STMT_END

#   define NO_LOCALE
#  define NO_TAINT_SUPPORT 1
#    define NSIG (_NSIG)
#define NUM2PTR(any,d)	(any)(PTRV)(d)
#    define NUM_CLASSES 18
#    define NV_BIG_ENDIAN
#       define NV_DIG LDBL_DIG
#           define NV_EPSILON LDBL_EPSILON
#  define NV_IMPLICIT_BIT
#  define NV_INF PL_inf.nv
#    define NV_LITTLE_ENDIAN
#           define NV_MANT_DIG LDBL_MANT_DIG
#           define NV_MAX LDBL_MAX
#           define NV_MAX_10_EXP LDBL_MAX_10_EXP
#           define NV_MAX_EXP LDBL_MAX_EXP
#           define NV_MIN LDBL_MIN
#           define NV_MIN_10_EXP LDBL_MIN_10_EXP
#           define NV_MIN_EXP LDBL_MIN_EXP
#    define NV_MIX_ENDIAN
#  define NV_NAN PL_nan.nv
#define NV_NAN_BITS (NVMANTBITS - 1)
#define NV_NAN_IS_QUIET(nvp) \
    (NV_NAN_QS_TEST(nvp) == (NV_NAN_QS_QUIET ? NV_NAN_QS_BIT : 0))
#define NV_NAN_IS_SIGNALING(nvp) \
    (NV_NAN_QS_TEST(nvp) == (NV_NAN_QS_QUIET ? 0 : NV_NAN_QS_BIT))
#    define NV_NAN_PAYLOAD_MASK NV_NAN_PAYLOAD_MASK_IEEE_754_128_LE
#define NV_NAN_PAYLOAD_MASK_IEEE_754_128_BE \
  0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, \
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
#define NV_NAN_PAYLOAD_MASK_IEEE_754_128_LE \
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, \
  0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0x00, 0x00
#define NV_NAN_PAYLOAD_MASK_IEEE_754_64_BE \
  0x00, 0x07, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
#define NV_NAN_PAYLOAD_MASK_IEEE_754_64_LE \
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x07, 0x00
#define NV_NAN_PAYLOAD_MASK_SKIP_EIGHT \
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
#    define NV_NAN_PAYLOAD_PERM NV_NAN_PAYLOAD_PERM_IEEE_754_128_LE
#define NV_NAN_PAYLOAD_PERM_0_TO_7 \
  0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7
#define NV_NAN_PAYLOAD_PERM_7_TO_0 \
  0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0
#define NV_NAN_PAYLOAD_PERM_IEEE_754_128_BE \
  0xFF, 0xFF, 0xd, 0xc, 0xb, 0xa, 0x9, 0x8, \
  NV_NAN_PAYLOAD_PERM_7_TO_0
#define NV_NAN_PAYLOAD_PERM_IEEE_754_128_LE \
  NV_NAN_PAYLOAD_PERM_0_TO_7, \
  0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xFF, 0xFF
#define NV_NAN_PAYLOAD_PERM_IEEE_754_64_BE \
  0xFF, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0
#define NV_NAN_PAYLOAD_PERM_IEEE_754_64_LE \
  0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0xFF
#define NV_NAN_PAYLOAD_PERM_SKIP_EIGHT \
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
#define NV_NAN_QS_BIT (1 << (NV_NAN_QS_BIT_SHIFT))
#define NV_NAN_QS_BIT_OFFSET \
    (8 * (NV_NAN_QS_BYTE_OFFSET) + (NV_NAN_QS_BIT_SHIFT))
#  define NV_NAN_QS_BIT_SHIFT 6 
#define NV_NAN_QS_BYTE(nvp) (((U8*)(nvp))[NV_NAN_QS_BYTE_OFFSET])
#    define NV_NAN_QS_BYTE_OFFSET 13
#define NV_NAN_QS_QUIET \
    ((NV_NAN_QS_BYTE(PL_nan.u8) & NV_NAN_QS_BIT) == NV_NAN_QS_BIT)
#define NV_NAN_QS_SIGNALING (!(NV_NAN_QS_QUIET))
#define NV_NAN_QS_TEST(nvp) (NV_NAN_QS_BYTE(nvp) & NV_NAN_QS_BIT)
#define NV_NAN_QS_XOR(nvp) (NV_NAN_QS_BYTE(nvp) ^= NV_NAN_QS_BIT)
#define NV_NAN_SET_QUIET(nvp) \
    (NV_NAN_QS_QUIET ? \
     (NV_NAN_QS_BYTE(nvp) |= NV_NAN_QS_BIT) : \
     (NV_NAN_QS_BYTE(nvp) &= ~NV_NAN_QS_BIT))
#define NV_NAN_SET_SIGNALING(nvp) \
    (NV_NAN_QS_QUIET ? \
     (NV_NAN_QS_BYTE(nvp) &= ~NV_NAN_QS_BIT) : \
     (NV_NAN_QS_BYTE(nvp) |= NV_NAN_QS_BIT))
#    define NV_VAX_ENDIAN
#define NV_WITHIN_IV(nv) (I_V(nv) >= IV_MIN && I_V(nv) <= IV_MAX)
#define NV_WITHIN_UV(nv) ((nv)>=0.0 && U_V(nv) >= UV_MIN && U_V(nv) <= UV_MAX)
#      define NV_X86_80_BIT
#  define O_BINARY 0
#  define O_TEXT 0
#       define Off_t off64_t
#define PERLDB_LINE_OR_SAVESRC (PL_perldb & (PERLDBf_LINE | PERLDBf_SAVESRC))
#define PERLDB_NAMEANON 	(PL_perldb & PERLDBf_NAMEANON)
#define PERLDB_NAMEEVAL 	(PL_perldb & PERLDBf_NAMEEVAL)
#define PERLDB_SAVESRC  	(PL_perldb & PERLDBf_SAVESRC)
#define PERLDBf_SAVESRC  	0x400	

#  define PERLIO_INIT MUTEX_INIT(&PL_perlio_mutex)
#  define PERLIO_TERM 				\
	STMT_START {				\
		PerlIO_teardown();		\
		MUTEX_DESTROY(&PL_perlio_mutex);\
	} STMT_END
#      define PERLIO_USING_CRLF 1
#  define PERLVAR(prefix,var,type) type prefix##var;
#  define PERLVARA(prefix,var,n,type) type prefix##var[n];
#  define PERLVARI(prefix,var,type,init) type prefix##var;
#  define PERLVARIC(prefix,var,type,init) type prefix##var;
#define PERL_ABS(x) ((x) < 0 ? -(x) : (x))
#define PERL_ALLOC_CHECK(p)  NOOP
#  define PERL_ANY_COW
#define PERL_ARENA_SIZE 4080
#		define PERL_ASYNC_CHECK() if (UNLIKELY(PL_sig_pending)) PL_signalhook(aTHX)
#  define PERL_BITFIELD16 unsigned
#  define PERL_BITFIELD32 unsigned
#  define PERL_BITFIELD8 unsigned
#    define PERL_CALLCONV extern "C"
#    define PERL_CALLCONV_NO_RET PERL_CALLCONV
#define PERL_CKDEF(s)	PERL_CALLCONV OP *s (pTHX_ OP *o);
#  define PERL_COPY_ON_WRITE
#  define PERL_DEB(a)                  a
#  define PERL_DEB2(a,b)               a
#  define PERL_DEBUG(a) if (PL_debug)  a
#define PERL_DEBUG_PAD(i)	&(PL_debug_pad.pad[i])
#define PERL_DEBUG_PAD_ZERO(i)	(SvPVX(PERL_DEBUG_PAD(i))[0] = 0, \
	(((XPV*) SvANY(PERL_DEBUG_PAD(i)))->xpv_cur = 0), \
	PERL_DEBUG_PAD(i))

#    define PERL_DONT_CREATE_GVSV
#define PERL_EXIT_DESTRUCT_END  0x02  
#define PERL_FILTER_EXISTS(i) \
	    (PL_parser && PL_parser->rsfp_filters \
		&& (i) <= av_tindex(PL_parser->rsfp_filters))
#    define PERL_FPU_INIT (void)fpsetmask(0)
#    define PERL_FPU_POST_EXEC    rsignal_restore(SIGFPE, &xfpe); }
#    define PERL_FPU_PRE_EXEC   { Sigsave_t xfpe; rsignal_save(SIGFPE, PL_sigfpe_saved, &xfpe);
#    define PERL_GCC_BRACE_GROUPS_FORBIDDEN
#        define PERL_GET_VARS() PL_VarsPtr
#    define PERL_GLOBAL_STRUCT
#define PERL_GPROF_MONCONTROL(x) moncontrol(x)
#    define PERL_IMPLICIT_CONTEXT
#  define PERL_INTERPRETER_SIZE_UPTO_MEMBER(member)			\
    STRUCT_OFFSET(struct interpreter, member) +				\
    sizeof(((struct interpreter*)0)->member)
#define PERL_INT_MAX ((int)INT_MAX)
#define PERL_INT_MIN ((int)INT_MIN)
#define PERL_LONG_MAX ((long)LONG_MAX)
#define PERL_LONG_MIN ((long)LONG_MIN)
#define PERL_MAGIC_READONLY_ACCEPTABLE 0x40
#define PERL_MAGIC_TYPE_IS_VALUE_MAGIC(t) \
    (PL_magic_data[(U8)(t)] & PERL_MAGIC_VALUE_MAGIC)
#define PERL_MAGIC_TYPE_READONLY_ACCEPTABLE(t) \
    (PL_magic_data[(U8)(t)] & PERL_MAGIC_READONLY_ACCEPTABLE)
#define PERL_MAGIC_VALUE_MAGIC 0x80
#define PERL_MAGIC_VTABLE_MASK 0x3F
#  define PERL_MEMORY_DEBUG_HEADER_SIZE \
        (sizeof(struct perl_memory_debug_header) + \
	(MEM_ALIGNBYTES - sizeof(struct perl_memory_debug_header) \
	 %MEM_ALIGNBYTES) % MEM_ALIGNBYTES)
#define PERL_MG_UFUNC(name,ix,sv) I32 name(pTHX_ IV ix, SV *sv)
#define PERL_MULTICONCAT_HEADER_SIZE 5 
#define PERL_MULTICONCAT_IX_LENGTHS   5 
#define PERL_MULTICONCAT_IX_NARGS     0 
#define PERL_MULTICONCAT_IX_PLAIN_LEN 2 
#define PERL_MULTICONCAT_IX_PLAIN_PV  1 
#define PERL_MULTICONCAT_IX_UTF8_LEN  4 
#define PERL_MULTICONCAT_IX_UTF8_PV   3 
#define PERL_MULTICONCAT_MAXARG 64
#      define PERL_MY_SNPRINTF_GUARDED
#  define PERL_MY_SNPRINTF_POST_GUARD(len, max) PERL_SNPRINTF_CHECK(len, max, snprintf)
#      define PERL_MY_VSNPRINTF_GUARDED
#  define PERL_MY_VSNPRINTF_POST_GUARD(len, max) PERL_SNPRINTF_CHECK(len, max, vsnprintf)


#  define PERL_OP_PARENT

#define PERL_PPDEF(s)	PERL_CALLCONV OP *s (pTHX);
#define PERL_PV_ESCAPE_ALL            0x001000
#define PERL_PV_ESCAPE_DWIM         0x010000
#define PERL_PV_ESCAPE_FIRSTCHAR    0x000800
#define PERL_PV_ESCAPE_NOBACKSLASH  0x002000
#define PERL_PV_ESCAPE_NOCLEAR      0x004000
#define PERL_PV_ESCAPE_NONASCII     0x000400
#define PERL_PV_ESCAPE_QUOTE        0x000001
#define PERL_PV_ESCAPE_RE           0x008000
#define PERL_PV_ESCAPE_UNI          0x000100
#define PERL_PV_ESCAPE_UNI_DETECT   0x000200
#define PERL_PV_PRETTY_DUMP  PERL_PV_PRETTY_ELLIPSES|PERL_PV_PRETTY_QUOTE
#define PERL_PV_PRETTY_ELLIPSES     0x000002
#define PERL_PV_PRETTY_EXACTSIZE    0x000008
#define PERL_PV_PRETTY_LTGT         0x000004
#define PERL_PV_PRETTY_NOCLEAR      PERL_PV_ESCAPE_NOCLEAR
#define PERL_PV_PRETTY_QUOTE        PERL_PV_ESCAPE_QUOTE
#define PERL_PV_PRETTY_REGPROP PERL_PV_PRETTY_ELLIPSES|PERL_PV_PRETTY_LTGT|PERL_PV_ESCAPE_RE|PERL_PV_ESCAPE_NONASCII
#    define PERL_QUAD_MAX 	((IV) (PERL_UQUAD_MAX >> 1))
#    define PERL_QUAD_MIN 	(-PERL_QUAD_MAX - ((3 & -1) == 3))
# define PERL_SAWAMPERSAND
#define PERL_SCAN_ALLOW_UNDERSCORES   0x01 
#define PERL_SCAN_DISALLOW_PREFIX     0x02 
#define PERL_SCAN_GREATER_THAN_UV_MAX 0x02 
#define PERL_SCAN_SILENT_ILLDIGIT     0x04 
#define PERL_SCAN_SILENT_NON_PORTABLE 0x08 
#define PERL_SCAN_TRAILING            0x10 
#define PERL_SCRIPT_MODE "r"
#  define PERL_SET_CONTEXT(i)		PERL_SET_INTERP(i)
#  define PERL_SET_INTERP(i)		(PL_curinterp = (PerlInterpreter*)(i))
#  define PERL_SET_PHASE(new_phase) \
    PERL_DTRACE_PROBE_PHASE(new_phase); \
    PL_phase = new_phase;
#  define PERL_SET_THX(t)		PERL_SET_CONTEXT(t)
#define PERL_SHORT_MAX ((short)SHRT_MAX)
#define PERL_SHORT_MIN ((short)SHRT_MIN)
#define PERL_SNPRINTF_CHECK(len, max, api) STMT_START { if ((max) > 0 && (Size_t)len > (max)) Perl_croak_nocontext("panic: %s buffer overflow", STRINGIFY(api)); } STMT_END
#       define PERL_SOCKS_NEED_PROTOTYPES
#define PERL_STACK_OVERFLOW_CHECK()  NOOP
#    define PERL_STATIC_INLINE static inline
#  define PERL_STATIC_INLINE_NO_RET PERL_STATIC_INLINE
#  define PERL_STATIC_NO_RET STATIC
#  define PERL_STRLEN_EXPAND_SHIFT 2
#define PERL_STRLEN_ROUNDUP_QUANTUM Size_t_size
#define PERL_SUB_DEPTH_WARN 100
#  define PERL_SYS_FPU_INIT \
     STMT_START { \
         ieee_set_fp_control(IEEE_TRAP_ENABLE_INV); \
         signal(SIGFPE, SIG_IGN); \
     } STMT_END
#define PERL_SYS_INIT(argc, argv)	Perl_sys_init(argc, argv)
#define PERL_SYS_INIT3(argc, argv, env)	Perl_sys_init3(argc, argv, env)
#  define PERL_SYS_INIT3_BODY(argvp,argcp,envp) PERL_SYS_INIT_BODY(argvp,argcp)
#define PERL_SYS_TERM()			Perl_sys_term()
#    define PERL_TRACK_MEMPOOL
#define PERL_TSA_ACQUIRE(x) \
    PERL_TSA__(acquire_capability(x))
#  define PERL_TSA_ACTIVE
#define PERL_TSA_CAPABILITY(x) \
    PERL_TSA__(capability(x))
#define PERL_TSA_EXCLUDES(x) \
    PERL_TSA__(locks_excluded(x))
#define PERL_TSA_GUARDED_BY(x) \
    PERL_TSA__(guarded_by(x))
#define PERL_TSA_NO_TSA \
    PERL_TSA__(no_thread_safety_analysis)
#define PERL_TSA_PT_GUARDED_BY(x) \
    PERL_TSA__(pt_guarded_by(x))
#define PERL_TSA_RELEASE(x) \
    PERL_TSA__(release_capability(x))
#define PERL_TSA_REQUIRES(x) \
    PERL_TSA__(requires_capability(x))
#  define PERL_TSA__(x)   __attribute__((x))
#define PERL_UCHAR_MAX ((unsigned char)UCHAR_MAX)
#define PERL_UCHAR_MIN ((unsigned char)0)
#define PERL_UINT_MAX ((unsigned int)UINT_MAX)
#define PERL_UINT_MIN ((unsigned int)0)
#define PERL_ULONG_MAX ((unsigned long)ULONG_MAX)
#define PERL_ULONG_MIN ((unsigned long)0L)
#  define PERL_UNUSED_ARG(x) ((void)sizeof(x))
#  define PERL_UNUSED_CONTEXT PERL_UNUSED_ARG(my_perl)
#    define PERL_UNUSED_DECL __attribute__((unused))
#    define PERL_UNUSED_RESULT(v) STMT_START { __typeof__(v) z = (v); (void)sizeof(z); } STMT_END
#  define PERL_UNUSED_VAR(x) ((void)sizeof(x))

#    define PERL_USE_GCC_BRACE_GROUPS
#define PERL_USHORT_MAX ((unsigned short)USHRT_MAX)
#define PERL_USHORT_MIN ((unsigned short)0)
#  define PERL_WRITE_MSG_TO_CONSOLE(io, msg, len) PerlIO_write(io, msg, len)
#  define PIPESOCK_MODE
#define PL_DBsignal_iv  (PL_DBcontrol[DBVARMG_SIGNAL])
#define PL_DBsingle_iv  (PL_DBcontrol[DBVARMG_SINGLE])
#define PL_DBtrace_iv   (PL_DBcontrol[DBVARMG_TRACE])
#      define PL_Vars (*((PL_VarsPtr) \
		       ? PL_VarsPtr : (PL_VarsPtr = Perl_GetVars(aTHX))))
#  define PL_amagic_generation PL_na
#  define PL_dirty cBOOL(PL_phase == PERL_PHASE_DESTRUCT)
#  define PL_encoding ((SV *)NULL)
#define PL_hints PL_compiling.cop_hints
#define PL_maxo  MAXO
# define PL_sawampersand \
	(SAWAMPERSAND_LEFT|SAWAMPERSAND_MIDDLE|SAWAMPERSAND_RIGHT)
#  define PL_sv_no    (PL_sv_immortals[2])
#  define PL_sv_undef (PL_sv_immortals[1])
#  define PL_sv_yes   (PL_sv_immortals[0])
#  define PL_sv_zero  (PL_sv_immortals[3])
#define PNf UTF8f
#define PNfARG(pn) (int)1, (UV)PadnameLEN(pn), (void *)PadnamePV(pn)
#      define PRINTF_FORMAT_NULL_OK
#define PTR2IV(p)	INT2PTR(IV,p)
#define PTR2NV(p)	NUM2PTR(NV,p)
#define PTR2UV(p)	INT2PTR(UV,p)
#define PTR2nat(p)	(PTRV)(p)	
#  define PTR2ul(p)		(unsigned long)(p)
#define Pause() sleep((32767<<16)+32767)
#    define PeRl_INT64_C(c)	(c)
#    define PeRl_UINT64_C(c)	CAT2(c,U)
#       define Perl_acos acosl
#       define Perl_asin asinl
#define Perl_assert(what)	PERL_DEB2( 				\
	((what) ? ((void) 0) :						\
	    (Perl_croak_nocontext("Assertion %s failed: file \"" "__FILE__" \
			"\", line %d", STRINGIFY(what), "__LINE__"),	\
             (void) 0)), ((void)0))
#       define Perl_atan atanl
#       define Perl_atan2 atan2l
#   define Perl_atof(s) Perl_my_atof(s)
#   define Perl_atof2(s, n) Perl_my_atof3(aTHX_ (s), &(n), 0)
#       define Perl_ceil ceill
#       define Perl_cos cosl
#       define Perl_cosh coshl
#       define Perl_exp expl
#       define Perl_floor floorl
#       define Perl_fmod fmodl
#                define Perl_fp_class(x)	fp_class_l(x)
#        define Perl_fp_class_denorm(x)	(Perl_fp_class(x)==FP_SUBNORMAL)
#        define Perl_fp_class_inf(x)	(Perl_fp_class(x)==FP_INFINITE)
#        define Perl_fp_class_nan(x)	(Perl_fp_class(x)==FP_NAN)
#            define Perl_fp_class_ndenorm(x)	(Perl_fp_class(x)==FP_NEG_DENORM)
#            define Perl_fp_class_ninf(x)	(Perl_fp_class(x)==FP_NEG_INF)
#            define Perl_fp_class_nnorm(x)	(Perl_fp_class(x)==FP_NEG_NORM)
#        define Perl_fp_class_norm(x)	(Perl_fp_class(x)==FP_NORMAL)
#            define Perl_fp_class_nzero(x)	(Perl_fp_class(x)==FP_NEG_ZERO)
#            define Perl_fp_class_pdenorm(x)	(Perl_fp_class(x)==FP_POS_DENORM)
#            define Perl_fp_class_pinf(x)	(Perl_fp_class(x)==FP_POS_INF)
#            define Perl_fp_class_pnorm(x)	(Perl_fp_class(x)==FP_POS_NORM)
#            define Perl_fp_class_pzero(x)	(Perl_fp_class(x)==FP_POS_ZERO)
#            define Perl_fp_class_qnan(x)	(Perl_fp_class(x)==FP_QNAN)
#            define Perl_fp_class_snan(x)	(Perl_fp_class(x)==FP_SNAN)
#        define Perl_fp_class_zero(x)	(Perl_fp_class(x)==FP_ZERO)
#           define Perl_frexp(x,y) frexpl(x,y)
#       define Perl_isfinite(x) isfinite(x)
#        define Perl_isfinitel(x) isfinite(x)
#           define Perl_isinf(x) isinfl(x)
#           define Perl_isnan(x) isnanl(x)
#           define Perl_ldexp(x, y) ldexpl(x,y)
#       define Perl_log logl
#       define Perl_log10 log10l
#           define Perl_modf(x,y) modfl(x,y)
#       define Perl_pow powl
#  define Perl_safesysmalloc_size(where)	Perl_malloced_size(where)
#    define Perl_signbit signbit
#       define Perl_sin sinl
#       define Perl_sinh sinhl
#       define Perl_sqrt sqrtl
#  define Perl_strtod   Strtod
#       define Perl_tan tanl
#       define Perl_tanh tanhl
#  define Ptrdiff_t ptrdiff_t
#   define RESTORE_ERRNO  SETERRNO(saved_errno, saved_vms_errno)
#  define RESTORE_LC_NUMERIC()                                              \
        STMT_START {                                                        \
            if (_restore_LC_NUMERIC_function) {                             \
                _restore_LC_NUMERIC_function(aTHX);                         \
            }                                                               \
            LC_NUMERIC_UNLOCK;                                              \
        } STMT_END
#   define RMS_DIR    		RMS$_DIR
#   define RMS_FAC    		RMS$_FAC
#   define RMS_FEX    		RMS$_FEX
#   define RMS_FNF    		RMS$_FNF
#   define RMS_IFI    		RMS$_IFI
#   define RMS_ISI    		RMS$_ISI
#   define RMS_PRV    		RMS$_PRV
# define RUNOPS_DEFAULT Perl_runops_debug
#define RsPARA(sv)    (SvPOK(sv) && ! SvCUR(sv))
#define RsRECORD(sv)  (SvROK(sv) && (SvIV(SvRV(sv)) > 0))
#define RsSIMPLE(sv)  (SvOK(sv) && (! SvPOK(sv) || SvCUR(sv)))
#define RsSNARF(sv)   (! SvOK(sv))
# define SAVE_DEFSV                \
    (                               \
	save_gp(PL_defgv, 0),        \
	GvINTRO_off(PL_defgv),        \
	SAVEGENERICSV(GvSV(PL_defgv)), \
	GvSV(PL_defgv) = NULL           \
    )
#   define SAVE_ERRNO     ( saved_errno = errno, saved_vms_errno = vaxc$errno )
#define SAWAMPERSAND_LEFT       1   
#define SAWAMPERSAND_MIDDLE     2   
#define SAWAMPERSAND_RIGHT      4   
#define SCAN_DEF 0
#define SCAN_REPL 2
#define SCAN_TR 1
#   define SETERRNO(errcode,vmserrcode) \
	STMT_START {			\
	    set_errno(errcode);		\
	    set_vaxc_errno(vmserrcode);	\
	} STMT_END
#  define SET_NUMERIC_STANDARD()                                            \
	STMT_START {                                                        \
            DEBUG_Lv(PerlIO_printf(Perl_debug_log,                          \
                               "%s: %d: lc_numeric standard=%d\n",          \
                                "__FILE__", "__LINE__", PL_numeric_standard));  \
            Perl_set_numeric_standard(aTHX);                                \
            DEBUG_Lv(PerlIO_printf(Perl_debug_log,                          \
                                 "%s: %d: lc_numeric standard=%d\n",        \
                                 "__FILE__", "__LINE__", PL_numeric_standard)); \
        } STMT_END
#  define SET_NUMERIC_UNDERLYING()                                          \
	STMT_START {                                                        \
            if (_NOT_IN_NUMERIC_UNDERLYING) {                               \
                Perl_set_numeric_underlying(aTHX);                          \
            }                                                               \
        } STMT_END
#   define SLOPPYDIVIDE
#   define SS_ACCVIO      	SS$_ACCVIO
#   define SS_IVCHAN  		SS$_IVCHAN
#   define SS_NOPRIV  		SS$_NOPRIV
#   define SS_NORMAL  		SS$_NORMAL
#define SSize_t_MAX (SSize_t)(~(Size_t)0 >> 1)

#  define START_EXTERN_C extern "C" {
#    define START_MY_CXT static int my_cxt_index = -1;
#define STATIC static
#  define STATIC_ASSERT_1(COND, SUFFIX) STATIC_ASSERT_2(COND, SUFFIX)
#  define STATIC_ASSERT_2(COND, SUFFIX) \
    typedef struct { \
        unsigned int _static_assertion_failed_##SUFFIX : (COND) ? 1 : -1; \
    } _static_assertion_failed_##SUFFIX PERL_UNUSED_DECL
#  define STATIC_ASSERT_DECL(COND) static_assert(COND, #COND)
#define STATIC_ASSERT_STMT(COND)      STMT_START { STATIC_ASSERT_DECL(COND); } STMT_END
#   define STATUS_CURRENT STATUS_UNIX
#   define STATUS_EXIT \
	(((I32)PL_statusvalue_vms == -1 ? SS$_ABORT : PL_statusvalue_vms) | \
	   (VMSISH_HUSHED ? STS$M_INHIB_MSG : 0))
#   define STATUS_EXIT_SET(n)				\
	STMT_START {					\
	    I32 evalue = (I32)n;			\
	    PL_statusvalue = evalue;			\
	    if (MY_POSIX_EXIT)				\
		if (evalue > 255) PL_statusvalue_vms = evalue; else {	\
		  PL_statusvalue_vms = \
		    (C_FAC_POSIX | (evalue << 3 ) |	\
		     ((evalue == 1) ? (STS$K_ERROR | STS$M_INHIB_MSG) : 1));} \
	    else					\
		PL_statusvalue_vms = evalue ? evalue : SS$_NORMAL; \
	    set_vaxc_errno(PL_statusvalue_vms);		\
	} STMT_END
#       define STATUS_NATIVE_CHILD_SET(n)                  \
            STMT_START {                                   \
                PL_statusvalue_posix = (n);                \
                if (PL_statusvalue_posix == -1)            \
                    PL_statusvalue = -1;                   \
                else {                                     \
                    PL_statusvalue =                       \
                        (WIFEXITED(PL_statusvalue_posix) ? (WEXITSTATUS(PL_statusvalue_posix) << 8) : 0) |  \
                        (WIFSIGNALED(PL_statusvalue_posix) ? (WTERMSIG(PL_statusvalue_posix) & 0x7F) : 0) | \
                        (WIFSIGNALED(PL_statusvalue_posix) && WCOREDUMP(PL_statusvalue_posix) ? 0x80 : 0);  \
                }                                          \
            } STMT_END
#   define STATUS_UNIX_EXIT_SET(n)			\
	STMT_START {					\
	    I32 evalue = (I32)n;			\
	    PL_statusvalue = evalue;			\
	    if (MY_POSIX_EXIT) { \
	      if (evalue <= 0xFF00) {		\
		  if (evalue > 0xFF)			\
		    evalue = (evalue >> child_offset_bits) & 0xFF; \
		  PL_statusvalue_vms =		\
		    (C_FAC_POSIX | (evalue << 3 ) |	\
		    ((evalue == 1) ? (STS$K_ERROR | STS$M_INHIB_MSG) : 1)); \
	      } else  \
		PL_statusvalue_vms = evalue; \
	    } else { \
	      if (evalue == 0)			\
		PL_statusvalue_vms = SS$_NORMAL;	\
	      else if (evalue <= 0xFF00) \
		PL_statusvalue_vms = SS$_ABORT; \
	      else {  \
		  if (evalue != EVMSERR) PL_statusvalue_vms = evalue; \
		  else PL_statusvalue_vms = vaxc$errno;	\
		   \
		  PL_statusvalue = EVMSERR;		\
	      } \
	      set_vaxc_errno(PL_statusvalue_vms);	\
	    }						\
	} STMT_END
#   define STATUS_UNIX_SET(n)				\
	STMT_START {					\
	    I32 evalue = (I32)n;			\
	    PL_statusvalue = evalue;			\
	    if (PL_statusvalue != -1) {			\
		if (PL_statusvalue != EVMSERR) {	\
		  PL_statusvalue &= 0xFFFF;		\
		  if (MY_POSIX_EXIT)			\
		    PL_statusvalue_vms=PL_statusvalue ? SS$_ABORT : SS$_NORMAL;\
		  else PL_statusvalue_vms = Perl_unix_status_to_vms(evalue); \
		}					\
		else {					\
		  PL_statusvalue_vms = vaxc$errno;	\
		}					\
	    }						\
	    else PL_statusvalue_vms = SS$_ABORT;	\
	    set_vaxc_errno(PL_statusvalue_vms);		\
	} STMT_END
#  define STORE_LC_NUMERIC_FORCE_TO_UNDERLYING()                            \
	STMT_START {                                                        \
            LC_NUMERIC_LOCK(_NOT_IN_NUMERIC_UNDERLYING);                    \
            if (_NOT_IN_NUMERIC_UNDERLYING) {                               \
                Perl_set_numeric_underlying(aTHX);                          \
                _restore_LC_NUMERIC_function = &Perl_set_numeric_standard;  \
            }                                                               \
        } STMT_END
#  define STORE_LC_NUMERIC_SET_STANDARD()                                   \
        STMT_START {                                                        \
            LC_NUMERIC_LOCK(_NOT_IN_NUMERIC_STANDARD);                      \
            if (_NOT_IN_NUMERIC_STANDARD) {                                 \
                _restore_LC_NUMERIC_function = &Perl_set_numeric_underlying;\
                Perl_set_numeric_standard(aTHX);                            \
            }                                                               \
        } STMT_END
#  define STORE_LC_NUMERIC_SET_TO_NEEDED()                                  \
        STMT_START {                                                        \
            LC_NUMERIC_LOCK(                                                \
                    (   (  IN_LC(LC_NUMERIC) && _NOT_IN_NUMERIC_UNDERLYING) \
                     || (! IN_LC(LC_NUMERIC) && _NOT_IN_NUMERIC_STANDARD)));\
            if (IN_LC(LC_NUMERIC)) {                                        \
                if (_NOT_IN_NUMERIC_UNDERLYING) {                           \
                    Perl_set_numeric_underlying(aTHX);                      \
                    _restore_LC_NUMERIC_function                            \
                                            = &Perl_set_numeric_standard;   \
                }                                                           \
            }                                                               \
            else {                                                          \
                if (_NOT_IN_NUMERIC_STANDARD) {                             \
                    Perl_set_numeric_standard(aTHX);                        \
                    _restore_LC_NUMERIC_function                            \
                                            = &Perl_set_numeric_underlying; \
                }                                                           \
            }                                                               \
        } STMT_END
#  define STRUCT_OFFSET(s,m)  (Size_t)(&(((s *)0)->m))
#   define STRUCT_SV perl_sv
#  define SUBST_TAINT_BOOLRET 16	
#  define SUBST_TAINT_PAT      2	
#  define SUBST_TAINT_REPL     4	
#  define SUBST_TAINT_RETAINT  8	
#  define SUBST_TAINT_STR      1	
#  define SVf "-p"
#  define SVf256 SVf_(256)
#  define SVf32 SVf_(32)
#define SVfARG(p) ((void*)(p))
#  define SVf_(n) "-" STRINGIFY(n) "p"
#       define SYMBIAN
#   define S_IEXEC S_IXUSR
#   define S_IFIFO _S_IFIFO
#   define S_IREAD S_IRUSR
#       define S_IRGRP (S_IRUSR>>3)
#       define S_IROTH (S_IRUSR>>6)
#   define S_IRWXG (S_IRGRP|S_IWGRP|S_IXGRP)
#   define S_IRWXO (S_IROTH|S_IWOTH|S_IXOTH)
#   define S_IRWXU (S_IRUSR|S_IWUSR|S_IXUSR)
#   define S_ISCHR(m) ((m & S_IFMT) == S_IFCHR)
#   define S_ISDIR(m) ((m & S_IFMT) == S_IFDIR)
#   define S_ISGID 02000
#    define S_ISLNK(m) ((m & S_IFMT) == _S_IFLNK)
#   define S_ISREG(m) ((m & S_IFMT) == S_IFREG)
#    define S_ISSOCK(m) ((m & S_IFMT) == _S_IFSOCK)
#   define S_ISUID 04000
#       define S_IWGRP (S_IWUSR>>3)
#       define S_IWOTH (S_IWUSR>>6)
#   define S_IWRITE S_IWUSR
#       define S_IXGRP (S_IXUSR>>3)
#       define S_IXOTH (S_IXUSR>>6)
#               define Semctl(id, num, cmd, semun) semctl(id, num, cmd, semun.buff)
#define Size_t_MAX (~(Size_t)0)
#define StashHANDLER(stash,meth)	gv_handler((stash),CAT2(meth,_amg))
#define Strerror(e) strerror((e), vaxc$errno)
#define Strtod                          my_strtod
#   define Strtoul(s, e, b)	strchr((s), '-') ? ULONG_MAX : (unsigned long)strtol((s), (e), (b))
#   define TAINTING_set(s)	NOOP
#   define TAINT_ENV()		NOOP
#   define TAINT_IF(c)		NOOP
#   define TAINT_PROPER(s)	NOOP
#   define TAINT_WARN_get       0
#   define TAINT_WARN_set(s)    NOOP
#   define TAINT_set(s)		NOOP
#define TOO_LATE_FOR_(ch,what)	Perl_croak(aTHX_ "\"-%c\" is on the #! line, it must also be used on the command line%s", (char)(ch), what)
#  define TS_W32_BROKEN_LOCALECONV
#define U32_MAX_P1 (4.0 * (1 + ((U32_MAX) >> 2)))
#define U32_MAX_P1_HALF (2.0 * (1 + ((U32_MAX) >> 2)))
#    define UINT16_C(x) ((U16_TYPE)x##U)
#    define UINT32_C(x) ((U32_TYPE)x##U)
#      define UINT32_MIN 0
#    define UINT64_C(c) PeRl_UINT64_C(c)
#      define UINT64_MIN 0
#    define UINTMAX_C(c) UINT64_C(c)
#define UNKNOWN_ERRNO_MSG "(unknown)"
#define UNLIKELY(cond)                      EXPECT(cBOOL(cond),FALSE)
#define UNLINK unlnk
#  define UNLOCK_LC_NUMERIC_STANDARD()                                      \
        STMT_START {                                                        \
            if (PL_numeric_standard > 1) {                                  \
                PL_numeric_standard--;                                      \
            }                                                               \
            else {                                                          \
                assert(0);                                                  \
            }                                                               \
            DEBUG_Lv(PerlIO_printf(Perl_debug_log,                          \
            "%s: %d: lc_numeric_standard decrement lock, new depth=%d\n",   \
            "__FILE__", "__LINE__", PL_numeric_standard));                      \
        } STMT_END
#  define USEMYBINMODE 
#  define USER_PROP_MUTEX_INIT    MUTEX_INIT(&PL_user_prop_mutex)
#  define USER_PROP_MUTEX_LOCK    MUTEX_LOCK(&PL_user_prop_mutex)
#  define USER_PROP_MUTEX_TERM    MUTEX_DESTROY(&PL_user_prop_mutex)
#  define USER_PROP_MUTEX_UNLOCK  MUTEX_UNLOCK(&PL_user_prop_mutex)
#       define USE_64_BIT_STDIO 
#    define USE_BSDPGRP
#  define USE_ENVIRON_ARRAY
#  define USE_HASH_SEED
#   define USE_HEAP_INSTEAD_OF_STACK
#    define USE_LOCALE
#       define USE_PERL_ATOF
#      define USE_POSIX_2008_LOCALE
#   define USE_REENTRANT_API

#        define USE_THREAD_SAFE_LOCALE
#  define USING_MSVC6
#  define UTF8f "d%" UVuf "%4p"
#define UTF8fARG(u,l,p) (int)cBOOL(u), (UV)(l), (void*)(p)
#define UV_DIG (BIT_DIGITS(UVSIZE * 8))
#    define UV_IS_QUAD
#        define UV_MAX UINT32_MAX
#define UV_MAX_P1 (4.0 * (1 + ((UV_MAX) >> 2)))
#define UV_MAX_P1_HALF (2.0 * (1 + ((UV_MAX) >> 2)))
#    define UV_MIN UINT64_MIN
#  define UVf UVuf
#define U_32(what) (cast_ulong((NV)(what)))
#define U_I(what) ((unsigned int)U_32(what))
#define U_L(what) U_32(what)
#define U_S(what) ((U16)U_32(what))
#define U_V(what) (cast_uv((NV)(what)))
#define VOL volatile
#define _(args) args
#    define _CHECK_AND_OUTPUT_WIDE_LOCALE_CP_MSG(cp)                        \
	STMT_START {                                                        \
            if (! PL_in_utf8_CTYPE_locale && ckWARN(WARN_LOCALE)) {         \
                Perl_warner(aTHX_ packWARN(WARN_LOCALE),                    \
                                       "Wide character (U+%" UVXf ") in %s",\
                                       (UV) cp, OP_DESC(PL_op));            \
            }                                                               \
        }  STMT_END
#    define _CHECK_AND_OUTPUT_WIDE_LOCALE_UTF8_MSG(s, send)                 \
	STMT_START { \
            if (! PL_in_utf8_CTYPE_locale && ckWARN(WARN_LOCALE)) {         \
                UV cp = utf8_to_uvchr_buf((U8 *) (s), (U8 *) (send), NULL); \
                Perl_warner(aTHX_ packWARN(WARN_LOCALE),                    \
                    "Wide character (U+%" UVXf ") in %s",                   \
                    (cp == 0)                                               \
                     ? UNICODE_REPLACEMENT                                  \
                     : (UV) cp,                                             \
                    OP_DESC(PL_op));                                        \
            }                                                               \
        }  STMT_END
#      define _CHECK_AND_WARN_PROBLEMATIC_LOCALE                              \
                STMT_START {                                                  \
                    if (UNLIKELY(PL_warn_locale)) {                           \
                        Perl__warn_problematic_locale();                      \
                    }                                                         \
                }  STMT_END

#    define _LOCALE_TERM_POSIX_2008  NOOP
#  define _NOT_IN_NUMERIC_STANDARD (! PL_numeric_standard)
#  define _NOT_IN_NUMERIC_UNDERLYING                                        \
                    (! PL_numeric_underlying && PL_numeric_standard < 2)

#  define __attribute__deprecated__         __attribute__((deprecated))
#  define __attribute__format__(x,y,z)      __attribute__((format(x,y,z)))
#  define __attribute__format__null_ok__(x,y,z)  __attribute__format__(x,y,z)
#  define __attribute__malloc__             __attribute__((__malloc__))
#  define __attribute__nonnull__(a)         __attribute__((nonnull(a)))
#  define __attribute__noreturn__           __attribute__((noreturn))
#  define __attribute__pure__               __attribute__((pure))
#  define __attribute__unused__             __attribute__((unused))
#  define __attribute__warn_unused_result__ __attribute__((warn_unused_result))
#  define __has_builtin(x) 0 
#define _aDEPTH ,depth
#  define _aMY_CXT
#define _pDEPTH ,U32 depth
#  define _pMY_CXT
# define _swab_16_(x) ((U16)( \
         (((U16)(x) & UINT16_C(0x00ff)) << 8) | \
         (((U16)(x) & UINT16_C(0xff00)) >> 8) ))
# define _swab_32_(x) ((U32)( \
         (((U32)(x) & UINT32_C(0x000000ff)) << 24) | \
         (((U32)(x) & UINT32_C(0x0000ff00)) <<  8) | \
         (((U32)(x) & UINT32_C(0x00ff0000)) >>  8) | \
         (((U32)(x) & UINT32_C(0xff000000)) >> 24) ))
#  define _swab_64_(x) ((U64)( \
          (((U64)(x) & UINT64_C(0x00000000000000ff)) << 56) | \
          (((U64)(x) & UINT64_C(0x000000000000ff00)) << 40) | \
          (((U64)(x) & UINT64_C(0x0000000000ff0000)) << 24) | \
          (((U64)(x) & UINT64_C(0x00000000ff000000)) <<  8) | \
          (((U64)(x) & UINT64_C(0x000000ff00000000)) >>  8) | \
          (((U64)(x) & UINT64_C(0x0000ff0000000000)) >> 24) | \
          (((U64)(x) & UINT64_C(0x00ff000000000000)) >> 40) | \
          (((U64)(x) & UINT64_C(0xff00000000000000)) >> 56) ))
#  define aMY_CXT
#  define aMY_CXT_
#  define aTHX
#  define aTHX_
#  define aTHXa(a) aTHX = (tTHX)a
#  define assert_(what)	assert(what),
#       define atoll    _atoi64		
#  define child_offset_bits (8)
#  define dMY_CXT_INTERP(my_perl)	\
	my_cxt_t *my_cxtp = (my_cxt_t *)(my_perl)->Imy_cxt_list[MY_CXT_INDEX]
#define dNOOP struct Perl___notused_struct
#   define dSAVEDERRNO    int saved_errno; unsigned saved_vms_errno
#   define dSAVE_ERRNO    int saved_errno = errno; unsigned saved_vms_errno = vaxc$errno
#  define dTHX_DEBUGGING dTHX
#    define dTHXa(a)	dVAR; pTHX = (tTHX)a
#  define dTHXoa(x)	dTHXa(x)
#  define do_aexec			Perl_do_aexec
#  define do_exec(cmd)			do_exec3(cmd,0,0)
#define do_open(g, n, l, a, rm, rp, sf) \
	do_openn(g, n, l, a, rm, rp, sf, (SV **) NULL, 0)
#       define environ myenviron
#       define fcntl fcntl64
#       define fgetpos fgetpos64
#       define flock flock64
#       define fopen fopen64
#       define freopen freopen64
#       define fseek fseek64 
#       define fsetpos fsetpos64
#       define fstat fstat64
#       define ftell ftell64 
#       define ftruncate ftruncate64
#   define htoni htons
#    define htonl(x)    ntohl(x)
#    define htons(x)    ntohs(x)
#  define htovl(x)      vtohl(x)
#  define htovs(x)      vtohs(x)
#    define isnormal(x) Perl_fp_class_norm(x)
#       define lockf lockf64
#           define lseek llseek
#       define lstat lstat64
#   define memzero(d,l) memset(d,0,l)
#define my_atof2(a,b) my_atof3(a,b,0)
#  define my_binmode(fp, iotype, mode) \
            cBOOL(PerlLIO_setmode(fileno(fp), mode) != -1)
#define my_lstat() my_lstat_flags(SV_GMAGIC)
#      define my_snprintf(buffer, max, ...) ({ int len = snprintf(buffer, max, __VA_ARGS__); PERL_SNPRINTF_CHECK(len, max, snprintf); len; })
#define my_sprintf sprintf
#define my_stat()  my_stat_flags(SV_GMAGIC)
#  define my_strlcat    Perl_my_strlcat
#      define my_vsnprintf(buffer, max, ...) ({ int len = vsnprintf(buffer, max, __VA_ARGS__); PERL_SNPRINTF_CHECK(len, max, vsnprintf); len; })
#   define ntohi ntohs
#    define ntohl(x)    ((x)&0xFFFFFFFF)
#    define ntohs(x)    ((x)&0xFFFF)
#       define open open64
#  define pMY_CXT_
#  define pTHX  tTHX my_perl PERL_UNUSED_DECL
#  define pTHX_
#define pVAR    struct perl_vars* my_vars PERL_UNUSED_DECL
#  define panic_write2(s)		write(2, s, strlen(s))
#  define register
#  define safecalloc  Perl_calloc
#  define safefree    Perl_mfree
#  define safemalloc  Perl_malloc
#  define saferealloc Perl_realloc
#           define semun gccbug_semun
#    define setregid(r,e) setresgid(r,e,(Gid_t)-1)
#    define setreuid(r,e) setresuid(r,e,(Uid_t)-1)
#       define stat stat64
#        define strtoll _strtoi64	
#        define strtoull _strtoui64	
#       define tmpfile tmpfile64
#       define truncate truncate64
#  define vtohl(x)      ((x)&0xFFFFFFFF)
#  define vtohs(x)      ((x)&0xFFFF)
#define NofAMmeth max_amg_code
#define PERL_MAGIC_arylen         '#' 
#define PERL_MAGIC_arylen_p       '@' 
#define PERL_MAGIC_backref        '<' 
#define PERL_MAGIC_bm             'B' 
#define PERL_MAGIC_checkcall      ']' 
#define PERL_MAGIC_collxfrm       'o' 
#define PERL_MAGIC_dbfile         'L' 
#define PERL_MAGIC_dbline         'l' 
#define PERL_MAGIC_debugvar       '*' 
#define PERL_MAGIC_defelem        'y' 
#define PERL_MAGIC_env            'E' 
#define PERL_MAGIC_envelem        'e' 
#define PERL_MAGIC_ext            '~' 
#define PERL_MAGIC_fm             'f' 
#define PERL_MAGIC_hints          'H' 
#define PERL_MAGIC_hintselem      'h' 
#define PERL_MAGIC_isa            'I' 
#define PERL_MAGIC_isaelem        'i' 
#define PERL_MAGIC_lvref          '\\' 
#define PERL_MAGIC_nkeys          'k' 
#define PERL_MAGIC_nonelem        'Y' 
#define PERL_MAGIC_overload_table 'c' 
#define PERL_MAGIC_pos            '.' 
#define PERL_MAGIC_qr             'r' 
#define PERL_MAGIC_regdata        'D' 
#define PERL_MAGIC_regdatum       'd' 
#define PERL_MAGIC_regex_global   'g' 
#define PERL_MAGIC_rhash          '%' 
#define PERL_MAGIC_shared         'N' 
#define PERL_MAGIC_shared_scalar  'n' 
#define PERL_MAGIC_sig            'S' 
#define PERL_MAGIC_sigelem        's' 
#define PERL_MAGIC_substr         'x' 
#define PERL_MAGIC_sv             '\0' 
#define PERL_MAGIC_symtab         ':' 
#define PERL_MAGIC_taint          't' 
#define PERL_MAGIC_tied           'P' 
#define PERL_MAGIC_tiedelem       'p' 
#define PERL_MAGIC_tiedscalar     'q' 
#define PERL_MAGIC_utf8           'w' 
#define PERL_MAGIC_uvar           'U' 
#define PERL_MAGIC_uvar_elem      'u' 
#define PERL_MAGIC_vec            'v' 
#define PERL_MAGIC_vstring        'V' 
#define PL_vtbl_arylen PL_magic_vtables[want_vtbl_arylen]
#define PL_vtbl_arylen_p PL_magic_vtables[want_vtbl_arylen_p]
#define PL_vtbl_backref PL_magic_vtables[want_vtbl_backref]
#define PL_vtbl_bm PL_magic_vtables[want_vtbl_bm]
#define PL_vtbl_checkcall PL_magic_vtables[want_vtbl_checkcall]
#define PL_vtbl_collxfrm PL_magic_vtables[want_vtbl_collxfrm]
#define PL_vtbl_dbline PL_magic_vtables[want_vtbl_dbline]
#define PL_vtbl_debugvar PL_magic_vtables[want_vtbl_debugvar]
#define PL_vtbl_defelem PL_magic_vtables[want_vtbl_defelem]
#define PL_vtbl_env PL_magic_vtables[want_vtbl_env]
#define PL_vtbl_envelem PL_magic_vtables[want_vtbl_envelem]
#define PL_vtbl_fm PL_magic_vtables[want_vtbl_fm]
#define PL_vtbl_hints PL_magic_vtables[want_vtbl_hints]
#define PL_vtbl_hintselem PL_magic_vtables[want_vtbl_hintselem]
#define PL_vtbl_isa PL_magic_vtables[want_vtbl_isa]
#define PL_vtbl_isaelem PL_magic_vtables[want_vtbl_isaelem]
#define PL_vtbl_lvref PL_magic_vtables[want_vtbl_lvref]
#define PL_vtbl_mglob PL_magic_vtables[want_vtbl_mglob]
#define PL_vtbl_nkeys PL_magic_vtables[want_vtbl_nkeys]
#define PL_vtbl_nonelem PL_magic_vtables[want_vtbl_nonelem]
#define PL_vtbl_ovrld PL_magic_vtables[want_vtbl_ovrld]
#define PL_vtbl_pack PL_magic_vtables[want_vtbl_pack]
#define PL_vtbl_packelem PL_magic_vtables[want_vtbl_packelem]
#define PL_vtbl_pos PL_magic_vtables[want_vtbl_pos]
#define PL_vtbl_regdata PL_magic_vtables[want_vtbl_regdata]
#define PL_vtbl_regdatum PL_magic_vtables[want_vtbl_regdatum]
#define PL_vtbl_regexp PL_magic_vtables[want_vtbl_regexp]
#define PL_vtbl_sigelem PL_magic_vtables[want_vtbl_sigelem]
#define PL_vtbl_substr PL_magic_vtables[want_vtbl_substr]
#define PL_vtbl_sv PL_magic_vtables[want_vtbl_sv]
#define PL_vtbl_taint PL_magic_vtables[want_vtbl_taint]
#define PL_vtbl_utf8 PL_magic_vtables[want_vtbl_utf8]
#define PL_vtbl_uvar PL_magic_vtables[want_vtbl_uvar]
#define PL_vtbl_vec PL_magic_vtables[want_vtbl_vec]
#define want_vtbl_bm want_vtbl_regexp
#define want_vtbl_fm want_vtbl_regexp
#define F0convert		S_F0convert
#define GetVars()		Perl_GetVars(aTHX)
#define PerlIO_close(a)		Perl_PerlIO_close(aTHX_ a)
#define PerlIO_eof(a)		Perl_PerlIO_eof(aTHX_ a)
#define PerlIO_error(a)		Perl_PerlIO_error(aTHX_ a)
#define PerlIO_fill(a)		Perl_PerlIO_fill(aTHX_ a)
#define PerlIO_flush(a)		Perl_PerlIO_flush(aTHX_ a)
#define PerlIO_stderr()		Perl_PerlIO_stderr(aTHX)
#define PerlIO_stdin()		Perl_PerlIO_stdin(aTHX)
#define PerlIO_stdout()		Perl_PerlIO_stdout(aTHX)
#define PerlIO_tell(a)		Perl_PerlIO_tell(aTHX_ a)
#define Slab_Alloc(a)		Perl_Slab_Alloc(aTHX_ a)
#define Slab_Free(a)		Perl_Slab_Free(aTHX_ a)
#define Slab_to_ro(a)		Perl_Slab_to_ro(aTHX_ a)
#define Slab_to_rw(a)		Perl_Slab_to_rw(aTHX_ a)
#define _invlist_len		S__invlist_len
#define _invlist_search		Perl__invlist_search
#define _new_invlist(a)		Perl__new_invlist(aTHX_ a)
#define _to_fold_latin1		Perl__to_fold_latin1
#define add_data		S_add_data
#define allocmy(a,b,c)		Perl_allocmy(aTHX_ a,b,c)
#define amagic_cmp(a,b)		S_amagic_cmp(aTHX_ a,b)
#define any_dup(a,b)		Perl_any_dup(aTHX_ a,b)
#define ao(a)			S_ao(aTHX_ a)
#define apply(a,b,c)		Perl_apply(aTHX_ a,b,c)
#define atfork_lock		Perl_atfork_lock
#define atfork_unlock		Perl_atfork_unlock
#define av_clear(a)		Perl_av_clear(aTHX_ a)
#define av_exists(a,b)		Perl_av_exists(aTHX_ a,b)
#define av_extend(a,b)		Perl_av_extend(aTHX_ a,b)
#define av_fetch(a,b,c)		Perl_av_fetch(aTHX_ a,b,c)
#define av_fill(a,b)		Perl_av_fill(aTHX_ a,b)
#define av_len(a)		Perl_av_len(aTHX_ a)
#define av_make(a,b)		Perl_av_make(aTHX_ a,b)
#define av_nonelem(a,b)		Perl_av_nonelem(aTHX_ a,b)
#define av_pop(a)		Perl_av_pop(aTHX_ a)
#define av_push(a,b)		Perl_av_push(aTHX_ a,b)
#define av_reify(a)		Perl_av_reify(aTHX_ a)
#define av_shift(a)		Perl_av_shift(aTHX_ a)
#define av_store(a,b,c)		Perl_av_store(aTHX_ a,b,c)
#define av_top_index(a)		S_av_top_index(aTHX_ a)
#define av_undef(a)		Perl_av_undef(aTHX_ a)
#define av_unshift(a,b)		Perl_av_unshift(aTHX_ a,b)
#define block_end(a,b)		Perl_block_end(aTHX_ a,b)
#define block_gimme()		Perl_block_gimme(aTHX)
#define block_start(a)		Perl_block_start(aTHX_ a)
#define boot_core_mro()		Perl_boot_core_mro(aTHX)
#define call_list(a,b)		Perl_call_list(aTHX_ a,b)
#define call_pv(a,b)		Perl_call_pv(aTHX_ a,b)
#define call_sv(a,b)		Perl_call_sv(aTHX_ a,b)
#define caller_cx(a,b)		Perl_caller_cx(aTHX_ a,b)
#define cando(a,b,c)		Perl_cando(aTHX_ a,b,c)
#define cast_i32		Perl_cast_i32
#define cast_iv			Perl_cast_iv
#define cast_ulong		Perl_cast_ulong
#define cast_uv			Perl_cast_uv
#define category_name		S_category_name
#define check_uni()		S_check_uni(aTHX)
#define ck_anoncode(a)		Perl_ck_anoncode(aTHX_ a)
#define ck_backtick(a)		Perl_ck_backtick(aTHX_ a)
#define ck_bitop(a)		Perl_ck_bitop(aTHX_ a)
#define ck_cmp(a)		Perl_ck_cmp(aTHX_ a)
#define ck_concat(a)		Perl_ck_concat(aTHX_ a)
#define ck_defined(a)		Perl_ck_defined(aTHX_ a)
#define ck_delete(a)		Perl_ck_delete(aTHX_ a)
#define ck_each(a)		Perl_ck_each(aTHX_ a)
#define ck_eof(a)		Perl_ck_eof(aTHX_ a)
#define ck_eval(a)		Perl_ck_eval(aTHX_ a)
#define ck_exec(a)		Perl_ck_exec(aTHX_ a)
#define ck_exists(a)		Perl_ck_exists(aTHX_ a)
#define ck_ftst(a)		Perl_ck_ftst(aTHX_ a)
#define ck_fun(a)		Perl_ck_fun(aTHX_ a)
#define ck_glob(a)		Perl_ck_glob(aTHX_ a)
#define ck_grep(a)		Perl_ck_grep(aTHX_ a)
#define ck_index(a)		Perl_ck_index(aTHX_ a)
#define ck_join(a)		Perl_ck_join(aTHX_ a)
#define ck_length(a)		Perl_ck_length(aTHX_ a)
#define ck_lfun(a)		Perl_ck_lfun(aTHX_ a)
#define ck_listiob(a)		Perl_ck_listiob(aTHX_ a)
#define ck_match(a)		Perl_ck_match(aTHX_ a)
#define ck_method(a)		Perl_ck_method(aTHX_ a)
#define ck_null(a)		Perl_ck_null(aTHX_ a)
#define ck_open(a)		Perl_ck_open(aTHX_ a)
#define ck_prototype(a)		Perl_ck_prototype(aTHX_ a)
#define ck_readline(a)		Perl_ck_readline(aTHX_ a)
#define ck_refassign(a)		Perl_ck_refassign(aTHX_ a)
#define ck_repeat(a)		Perl_ck_repeat(aTHX_ a)
#define ck_require(a)		Perl_ck_require(aTHX_ a)
#define ck_return(a)		Perl_ck_return(aTHX_ a)
#define ck_rfun(a)		Perl_ck_rfun(aTHX_ a)
#define ck_rvconst(a)		Perl_ck_rvconst(aTHX_ a)
#define ck_sassign(a)		Perl_ck_sassign(aTHX_ a)
#define ck_select(a)		Perl_ck_select(aTHX_ a)
#define ck_shift(a)		Perl_ck_shift(aTHX_ a)
#define ck_sort(a)		Perl_ck_sort(aTHX_ a)
#define ck_spair(a)		Perl_ck_spair(aTHX_ a)
#define ck_split(a)		Perl_ck_split(aTHX_ a)
#define ck_stringify(a)		Perl_ck_stringify(aTHX_ a)
#define ck_subr(a)		Perl_ck_subr(aTHX_ a)
#define ck_substr(a)		Perl_ck_substr(aTHX_ a)
#define ck_svconst(a)		Perl_ck_svconst(aTHX_ a)
#define ck_tell(a)		Perl_ck_tell(aTHX_ a)
#define ck_trunc(a)		Perl_ck_trunc(aTHX_ a)
#define ck_warner		Perl_ck_warner
#define ck_warner_d		Perl_ck_warner_d
#define cop_free(a)		S_cop_free(aTHX_ a)
#  define croak			Perl_croak_nocontext
#define croak_caller		Perl_croak_caller
#define croak_no_mem		Perl_croak_no_mem
#define croak_no_modify		Perl_croak_no_modify
#define croak_nocontext		Perl_croak_nocontext
#define croak_popstack		Perl_croak_popstack
#define croak_sv(a)		Perl_croak_sv(aTHX_ a)
#define croak_xs_usage		Perl_croak_xs_usage
#define csighandler		Perl_csighandler
#define curse(a,b)		S_curse(aTHX_ a,b)
#define cv_clone(a)		Perl_cv_clone(aTHX_ a)
#define cv_const_sv		Perl_cv_const_sv
#define cv_dump(a,b)		S_cv_dump(aTHX_ a,b)
#define cv_name(a,b,c)		Perl_cv_name(aTHX_ a,b,c)
#define cv_undef(a)		Perl_cv_undef(aTHX_ a)
#define cvgv_set(a,b)		Perl_cvgv_set(aTHX_ a,b)
#define cx_dump(a)		Perl_cx_dump(aTHX_ a)
#define cx_dup(a,b,c,d)		Perl_cx_dup(aTHX_ a,b,c,d)
#define cx_popblock(a)		S_cx_popblock(aTHX_ a)
#define cx_popeval(a)		S_cx_popeval(aTHX_ a)
#define cx_popformat(a)		S_cx_popformat(aTHX_ a)
#define cx_popgiven(a)		S_cx_popgiven(aTHX_ a)
#define cx_poploop(a)		S_cx_poploop(aTHX_ a)
#define cx_popsub(a)		S_cx_popsub(aTHX_ a)
#define cx_popwhen(a)		S_cx_popwhen(aTHX_ a)
#define cx_pushwhen(a)		S_cx_pushwhen(aTHX_ a)
#define cx_topblock(a)		S_cx_topblock(aTHX_ a)
#define cxinc()			Perl_cxinc(aTHX)
#  define deb			Perl_deb_nocontext
#define deb_curcv(a)		S_deb_curcv(aTHX_ a)
#define deb_nocontext		Perl_deb_nocontext
#define deb_stack_all()		Perl_deb_stack_all(aTHX)
#define debop(a)		Perl_debop(aTHX_ a)
#define debprof(a)		S_debprof(aTHX_ a)
#define debprofdump()		Perl_debprofdump(aTHX)
#define debstack()		Perl_debstack(aTHX)
#define debstackptrs()		Perl_debstackptrs(aTHX)
#define del_sv(a)		S_del_sv(aTHX_ a)
#define delimcpy		Perl_delimcpy
#  define die			Perl_die_nocontext
#define die_nocontext		Perl_die_nocontext
#define die_sv(a)		Perl_die_sv(aTHX_ a)
#define die_unwind(a)		Perl_die_unwind(aTHX_ a)
#define dirp_dup(a,b)		Perl_dirp_dup(aTHX_ a,b)
#define div128(a,b)		S_div128(aTHX_ a,b)
#define do_chomp(a,b,c)		S_do_chomp(aTHX_ a,b,c)
#define do_close(a,b)		Perl_do_close(aTHX_ a,b)
#define do_eof(a)		Perl_do_eof(aTHX_ a)
#define do_exec3(a,b,c)		Perl_do_exec3(aTHX_ a,b,c)
#define do_msgrcv(a,b)		Perl_do_msgrcv(aTHX_ a,b)
#define do_msgsnd(a,b)		Perl_do_msgsnd(aTHX_ a,b)
#define do_ncmp(a,b)		Perl_do_ncmp(aTHX_ a,b)
#define do_oddball(a,b)		S_do_oddball(aTHX_ a,b)
#define do_print(a,b)		Perl_do_print(aTHX_ a,b)
#define do_readline()		Perl_do_readline(aTHX)
#define do_seek(a,b,c)		Perl_do_seek(aTHX_ a,b,c)
#define do_semop(a,b)		Perl_do_semop(aTHX_ a,b)
#define do_shmio(a,b,c)		Perl_do_shmio(aTHX_ a,b,c)
#define do_spawn(a)		Perl_do_spawn(aTHX_ a)
#define do_tell(a)		Perl_do_tell(aTHX_ a)
#define do_trans(a)		Perl_do_trans(aTHX_ a)
#define do_vecset(a)		Perl_do_vecset(aTHX_ a)
#define do_vop(a,b,c,d)		Perl_do_vop(aTHX_ a,b,c,d)
#define docatch(a)		S_docatch(aTHX_ a)
#define dofile(a,b)		Perl_dofile(aTHX_ a,b)
#define doform(a,b,c)		S_doform(aTHX_ a,b,c)
#define doing_taint		Perl_doing_taint
#define dooneliner(a,b)		S_dooneliner(aTHX_ a,b)
#define doopen_pm(a)		S_doopen_pm(aTHX_ a)
#define doparseform(a)		S_doparseform(aTHX_ a)
#define dopoptoeval(a)		S_dopoptoeval(aTHX_ a)
#define dopoptoloop(a)		S_dopoptoloop(aTHX_ a)
#define dopoptowhen(a)		S_dopoptowhen(aTHX_ a)
#define doref(a,b,c)		Perl_doref(aTHX_ a,b,c)
#define dounwind(a)		Perl_dounwind(aTHX_ a)
#define dowantarray()		Perl_dowantarray(aTHX)
#define dump_all()		Perl_dump_all(aTHX)
#define dump_eval()		Perl_dump_eval(aTHX)
#define dump_form(a)		Perl_dump_form(aTHX_ a)
#define dump_indent		Perl_dump_indent
#define dump_mstats(a)		Perl_dump_mstats(aTHX_ a)
#define dump_sub(a)		Perl_dump_sub(aTHX_ a)
#define dup_attrlist(a)		S_dup_attrlist(aTHX_ a)
#define edit_distance		S_edit_distance
#define eval_pv(a,b)		Perl_eval_pv(aTHX_ a,b)
#define eval_sv(a,b)		Perl_eval_sv(aTHX_ a,b)
#define filter_add(a,b)		Perl_filter_add(aTHX_ a,b)
#define filter_del(a)		Perl_filter_del(aTHX_ a)
#define finalize_op(a)		S_finalize_op(aTHX_ a)
#define find_runcv(a)		Perl_find_runcv(aTHX_ a)
#define find_rundefsv()		Perl_find_rundefsv(aTHX)
#define find_span_end		S_find_span_end
#define first_symbol		S_first_symbol
#define foldEQ			Perl_foldEQ
#define foldEQ_latin1		Perl_foldEQ_latin1
#define foldEQ_locale		Perl_foldEQ_locale
#define force_list(a,b)		S_force_list(aTHX_ a,b)
#define force_next(a)		S_force_next(aTHX_ a)
#define forget_pmop(a)		S_forget_pmop(aTHX_ a)
#  define form			Perl_form_nocontext
#define form_nocontext		Perl_form_nocontext
#define fp_dup(a,b,c)		Perl_fp_dup(aTHX_ a,b,c)
#define free_tmps()		Perl_free_tmps(aTHX)
#define get_aux_mg(a)		S_get_aux_mg(aTHX_ a)
#define get_av(a,b)		Perl_get_av(aTHX_ a,b)
#define get_context		Perl_get_context
#define get_cv(a,b)		Perl_get_cv(aTHX_ a,b)
#define get_hv(a,b)		Perl_get_hv(aTHX_ a,b)
#define get_no_modify()		Perl_get_no_modify(aTHX)
#define get_num(a,b)		S_get_num(aTHX_ a,b)
#define get_op_descs()		Perl_get_op_descs(aTHX)
#define get_op_names()		Perl_get_op_names(aTHX)
#define get_opargs()		Perl_get_opargs(aTHX)
#define get_ppaddr()		Perl_get_ppaddr(aTHX)
#define get_sv(a,b)		Perl_get_sv(aTHX_ a,b)
#define get_vtbl(a)		Perl_get_vtbl(aTHX_ a)
#define getcwd_sv(a)		Perl_getcwd_sv(aTHX_ a)
#define getenv_len(a,b)		Perl_getenv_len(aTHX_ a,b)
#define glob_2number(a)		S_glob_2number(aTHX_ a)
#define gp_dup(a,b)		Perl_gp_dup(aTHX_ a,b)
#define gp_free(a)		Perl_gp_free(aTHX_ a)
#define gp_ref(a)		Perl_gp_ref(aTHX_ a)
#define grok_atoUV		Perl_grok_atoUV
#define gv_check(a)		Perl_gv_check(aTHX_ a)
#define gv_const_sv(a)		Perl_gv_const_sv(aTHX_ a)
#define gv_dump(a)		Perl_gv_dump(aTHX_ a)
#define gv_fetchfile(a)		Perl_gv_fetchfile(aTHX_ a)
#define gv_handler(a,b)		Perl_gv_handler(aTHX_ a,b)
#define gv_setref(a,b)		Perl_gv_setref(aTHX_ a,b)
#define gv_stashpv(a,b)		Perl_gv_stashpv(aTHX_ a,b)
#define gv_stashsv(a,b)		Perl_gv_stashsv(aTHX_ a,b)
#define he_dup(a,b,c)		Perl_he_dup(aTHX_ a,b,c)
#define hek_dup(a,b)		Perl_hek_dup(aTHX_ a,b)
#define hsplit(a,b,c)		S_hsplit(aTHX_ a,b,c)
#define hv_auxinit(a)		S_hv_auxinit(aTHX_ a)
#define hv_clear(a)		Perl_hv_clear(aTHX_ a)
#define hv_iterinit(a)		Perl_hv_iterinit(aTHX_ a)
#define hv_iterkey(a,b)		Perl_hv_iterkey(aTHX_ a,b)
#define hv_iterkeysv(a)		Perl_hv_iterkeysv(aTHX_ a)
#define hv_iterval(a,b)		Perl_hv_iterval(aTHX_ a,b)
#define hv_ksplit(a,b)		Perl_hv_ksplit(aTHX_ a,b)
#define hv_magic_check		S_hv_magic_check
#define hv_pushkv(a,b)		Perl_hv_pushkv(aTHX_ a,b)
#define hv_scalar(a)		Perl_hv_scalar(aTHX_ a)
#define incline(a,b)		S_incline(aTHX_ a,b)
#define incpush(a,b,c)		S_incpush(aTHX_ a,b,c)
#define ingroup(a,b)		S_ingroup(aTHX_ a,b)
#define init_debugger()		Perl_init_debugger(aTHX)
#define init_ids()		S_init_ids(aTHX)
#define init_interp()		S_init_interp(aTHX)
#define init_perllib()		S_init_perllib(aTHX)
#define init_stacks()		Perl_init_stacks(aTHX)
#define init_tm(a)		Perl_init_tm(aTHX_ a)
#define init_uniprops()		Perl_init_uniprops(aTHX)
#define intro_my()		Perl_intro_my(aTHX)
#define invert(a)		Perl_invert(aTHX_ a)
#define invlist_array		S_invlist_array
#define invlist_highest		S_invlist_highest
#define invlist_max		S_invlist_max
#define invlist_trim		S_invlist_trim
#define isALNUM_lazy(a)		Perl_isALNUM_lazy(aTHX_ a)
#define isFF_OVERLONG		S_isFF_OVERLONG
#define isFOO_lc(a,b)		Perl_isFOO_lc(aTHX_ a,b)
#define isUTF8_CHAR		S_isUTF8_CHAR
#define is_an_int(a,b)		S_is_an_int(aTHX_ a,b)
#define is_invlist		S_is_invlist
#define is_lvalue_sub()		Perl_is_lvalue_sub(aTHX)
#define is_ssc_worth_it		S_is_ssc_worth_it
#define is_uni_alnum(a)		Perl_is_uni_alnum(aTHX_ a)
#define is_uni_alpha(a)		Perl_is_uni_alpha(aTHX_ a)
#define is_uni_ascii(a)		Perl_is_uni_ascii(aTHX_ a)
#define is_uni_blank(a)		Perl_is_uni_blank(aTHX_ a)
#define is_uni_cntrl(a)		Perl_is_uni_cntrl(aTHX_ a)
#define is_uni_digit(a)		Perl_is_uni_digit(aTHX_ a)
#define is_uni_graph(a)		Perl_is_uni_graph(aTHX_ a)
#define is_uni_lower(a)		Perl_is_uni_lower(aTHX_ a)
#define is_uni_print(a)		Perl_is_uni_print(aTHX_ a)
#define is_uni_punct(a)		Perl_is_uni_punct(aTHX_ a)
#define is_uni_space(a)		Perl_is_uni_space(aTHX_ a)
#define is_uni_upper(a)		Perl_is_uni_upper(aTHX_ a)
#define is_utf8_char		Perl_is_utf8_char
#define is_utf8_mark(a)		Perl_is_utf8_mark(aTHX_ a)
#define isinfnan		Perl_isinfnan
#define isinfnansv(a)		Perl_isinfnansv(aTHX_ a)
#define jmaybe(a)		Perl_jmaybe(aTHX_ a)
#define keyword(a,b,c)		Perl_keyword(aTHX_ a,b,c)
#define leave_scope(a)		Perl_leave_scope(aTHX_ a)
#define lex_bufutf8()		Perl_lex_bufutf8(aTHX)
#define lex_read_to(a)		Perl_lex_read_to(aTHX_ a)
#define lex_unstuff(a)		Perl_lex_unstuff(aTHX_ a)
#define list(a)			Perl_list(aTHX_ a)
#define listkids(a)		S_listkids(aTHX_ a)
#  define load_module		Perl_load_module_nocontext
#define localize(a,b)		Perl_localize(aTHX_ a,b)
#define lop(a,b,c)		S_lop(aTHX_ a,b,c)
#define magic_dump(a)		Perl_magic_dump(aTHX_ a)
#define magic_get(a,b)		Perl_magic_get(aTHX_ a,b)
#define magic_set(a,b)		Perl_magic_set(aTHX_ a,b)
#define make_matcher(a)		S_make_matcher(aTHX_ a)
#define malloced_size		Perl_malloced_size
#define mem_log_alloc		Perl_mem_log_alloc
#define mem_log_common		S_mem_log_common
#define mem_log_free		Perl_mem_log_free
#define mem_log_realloc		Perl_mem_log_realloc
#  define mess			Perl_mess_nocontext
#define mess_alloc()		S_mess_alloc(aTHX)
#define mess_nocontext		Perl_mess_nocontext
#define mess_sv(a,b)		Perl_mess_sv(aTHX_ a,b)
#define mg_clear(a)		Perl_mg_clear(aTHX_ a)
#define mg_dup(a,b)		Perl_mg_dup(aTHX_ a,b)
#define mg_find			Perl_mg_find
#define mg_findext		Perl_mg_findext
#define mg_free(a)		Perl_mg_free(aTHX_ a)
#define mg_get(a)		Perl_mg_get(aTHX_ a)
#define mg_length(a)		Perl_mg_length(aTHX_ a)
#define mg_magical		Perl_mg_magical
#define mg_set(a)		Perl_mg_set(aTHX_ a)
#define mg_size(a)		Perl_mg_size(aTHX_ a)
#define mini_mktime		Perl_mini_mktime
#define minus_v()		S_minus_v(aTHX)
#define modkids(a,b)		S_modkids(aTHX_ a,b)
#define more_sv()		S_more_sv(aTHX)
#define moreswitches(a)		Perl_moreswitches(aTHX_ a)
#define mul128(a,b)		S_mul128(aTHX_ a,b)
#define my_atof(a)		Perl_my_atof(aTHX_ a)
#define my_atof3(a,b,c)		Perl_my_atof3(aTHX_ a,b,c)
#define my_attrs(a,b)		Perl_my_attrs(aTHX_ a,b)
#define my_chsize(a,b)		Perl_my_chsize(aTHX_ a,b)
#define my_clearenv()		Perl_my_clearenv(aTHX)
#define my_dirfd		Perl_my_dirfd
#define my_exit(a)		Perl_my_exit(aTHX_ a)
#define my_exit_jump()		S_my_exit_jump(aTHX)
#define my_fflush_all()		Perl_my_fflush_all(aTHX)
#define my_fork			Perl_my_fork
#define my_kid(a,b,c)		S_my_kid(aTHX_ a,b,c)
#define my_memrchr		S_my_memrchr
#define my_nl_langinfo		S_my_nl_langinfo
#define my_pclose(a)		Perl_my_pclose(aTHX_ a)
#define my_popen(a,b)		Perl_my_popen(aTHX_ a,b)
#define my_setenv(a,b)		Perl_my_setenv(aTHX_ a,b)
#define my_socketpair		Perl_my_socketpair
#define my_strerror(a)		Perl_my_strerror(aTHX_ a)
#define my_strtod		Perl_my_strtod
#define my_unexec()		Perl_my_unexec(aTHX)
#define need_utf8		S_need_utf8
#define newANONHASH(a)		Perl_newANONHASH(aTHX_ a)
#define newANONLIST(a)		Perl_newANONLIST(aTHX_ a)
#define newAVREF(a)		Perl_newAVREF(aTHX_ a)
#define newCVREF(a,b)		Perl_newCVREF(aTHX_ a,b)
#define newDEFSVOP()		Perl_newDEFSVOP(aTHX)
#define newFORM(a,b,c)		Perl_newFORM(aTHX_ a,b,c)
#define newGVOP(a,b,c)		Perl_newGVOP(aTHX_ a,b,c)
#define newGVREF(a,b)		Perl_newGVREF(aTHX_ a,b)
#define newHVREF(a)		Perl_newHVREF(aTHX_ a)
#define newHVhv(a)		Perl_newHVhv(aTHX_ a)
#define newLOOPEX(a,b)		Perl_newLOOPEX(aTHX_ a,b)
#define newNULLLIST()		Perl_newNULLLIST(aTHX)
#define newOP(a,b)		Perl_newOP(aTHX_ a,b)
#define newPADNAMELIST		Perl_newPADNAMELIST
#define newPADNAMEouter		Perl_newPADNAMEouter
#define newPADNAMEpvn		Perl_newPADNAMEpvn
#define newPADOP(a,b,c)		Perl_newPADOP(aTHX_ a,b,c)
#define newPMOP(a,b)		Perl_newPMOP(aTHX_ a,b)
#define newPROG(a)		Perl_newPROG(aTHX_ a)
#define newPVOP(a,b,c)		Perl_newPVOP(aTHX_ a,b,c)
#define newRANGE(a,b,c)		Perl_newRANGE(aTHX_ a,b,c)
#define newRV(a)		Perl_newRV(aTHX_ a)
#define newRV_noinc(a)		Perl_newRV_noinc(aTHX_ a)
#define newSTUB(a,b)		Perl_newSTUB(aTHX_ a,b)
#define newSV(a)		Perl_newSV(aTHX_ a)
#define newSVOP(a,b,c)		Perl_newSVOP(aTHX_ a,b,c)
#define newSVREF(a)		Perl_newSVREF(aTHX_ a)
#define newSV_type(a)		Perl_newSV_type(aTHX_ a)
#define newSVhek(a)		Perl_newSVhek(aTHX_ a)
#define newSViv(a)		Perl_newSViv(aTHX_ a)
#define newSVnv(a)		Perl_newSVnv(aTHX_ a)
#define newSVpv(a,b)		Perl_newSVpv(aTHX_ a,b)
#  define newSVpvf		Perl_newSVpvf_nocontext
#define newSVpvn(a,b)		Perl_newSVpvn(aTHX_ a,b)
#define newSVrv(a,b)		Perl_newSVrv(aTHX_ a,b)
#define newSVuv(a)		Perl_newSVuv(aTHX_ a)
#define newUNOP(a,b,c)		Perl_newUNOP(aTHX_ a,b,c)
#define newWHENOP(a,b)		Perl_newWHENOP(aTHX_ a,b)
#define newXS(a,b,c)		Perl_newXS(aTHX_ a,b,c)
#define new_collate(a)		S_new_collate(aTHX_ a)
#define new_ctype(a)		S_new_ctype(aTHX_ a)
#define new_he()		S_new_he(aTHX)
#define new_numeric(a)		S_new_numeric(aTHX_ a)
#define new_regcurly		S_new_regcurly
#define new_version(a)		Perl_new_version(aTHX_ a)
#define next_symbol(a)		S_next_symbol(aTHX_ a)
#define nextargv(a,b)		Perl_nextargv(aTHX_ a,b)
#define nextchar(a)		S_nextchar(aTHX_ a)
#define ninstr			Perl_ninstr
#define no_op(a,b)		S_no_op(aTHX_ a,b)
#define noperl_die		Perl_noperl_die
#define not_a_number(a)		S_not_a_number(aTHX_ a)
#define nothreadhook()		Perl_nothreadhook(aTHX)
#define nuke_stacks()		S_nuke_stacks(aTHX)
#define num_overflow		S_num_overflow
#define oopsAV(a)		Perl_oopsAV(aTHX_ a)
#define oopsHV(a)		Perl_oopsHV(aTHX_ a)
#define op_class(a)		Perl_op_class(aTHX_ a)
#define op_clear(a)		Perl_op_clear(aTHX_ a)
#define op_dump(a)		Perl_op_dump(aTHX_ a)
#define op_free(a)		Perl_op_free(aTHX_ a)
#define op_linklist(a)		Perl_op_linklist(aTHX_ a)
#define op_null(a)		Perl_op_null(aTHX_ a)
#define op_parent		Perl_op_parent
#define op_scope(a)		Perl_op_scope(aTHX_ a)
#define op_std_init(a)		S_op_std_init(aTHX_ a)
#define op_unscope(a)		Perl_op_unscope(aTHX_ a)
#define opslab_free(a)		Perl_opslab_free(aTHX_ a)
#define optimize_op(a)		S_optimize_op(aTHX_ a)
#define package(a)		Perl_package(aTHX_ a)
#define pad_alloc(a,b)		Perl_pad_alloc(aTHX_ a,b)
#define pad_free(a)		Perl_pad_free(aTHX_ a)
#define pad_leavemy()		Perl_pad_leavemy(aTHX)
#define pad_new(a)		Perl_pad_new(aTHX_ a)
#define pad_push(a,b)		Perl_pad_push(aTHX_ a,b)
#define pad_reset()		S_pad_reset(aTHX)
#define pad_setsv(a,b)		Perl_pad_setsv(aTHX_ a,b)
#define pad_sv(a)		Perl_pad_sv(aTHX_ a)
#define pad_swipe(a,b)		Perl_pad_swipe(aTHX_ a,b)
#define pad_tidy(a)		Perl_pad_tidy(aTHX_ a)
#define parse_block(a)		Perl_parse_block(aTHX_ a)
#define parse_body(a,b)		S_parse_body(aTHX_ a,b)
#define parse_label(a)		Perl_parse_label(aTHX_ a)
#define parser_dup(a,b)		Perl_parser_dup(aTHX_ a,b)
#define parser_free(a)		Perl_parser_free(aTHX_ a)
#define peep(a)			Perl_peep(aTHX_ a)
#define pending_ident()		S_pending_ident(aTHX)
#  define perl_atexit(a,b)		call_atexit(a,b)
#  define perl_call_argv(a,b,c)		call_argv(a,b,c)
#  define perl_call_method(a,b)		call_method(a,b)
#  define perl_call_pv(a,b)		call_pv(a,b)
#  define perl_call_sv(a,b)		call_sv(a,b)
#  define perl_eval_pv(a,b)		eval_pv(a,b)
#  define perl_eval_sv(a,b)		eval_sv(a,b)
#  define perl_get_av(a,b)		get_av(a,b)
#  define perl_get_cv(a,b)		get_cv(a,b)
#  define perl_get_hv(a,b)		get_hv(a,b)
#  define perl_get_sv(a,b)		get_sv(a,b)
#  define perl_init_i18nl10n(a)		init_i18nl10n(a)
#  define perl_init_i18nl14n(a)		init_i18nl14n(a)
#  define perl_require_pv(a)		require_pv(a)
#define pidgone(a,b)		S_pidgone(aTHX_ a,b)
#define pmop_dump(a)		Perl_pmop_dump(aTHX_ a)
#define pmtrans(a,b,c)		S_pmtrans(aTHX_ a,b,c)
#define pop_scope()		Perl_pop_scope(aTHX)
#define pregcomp(a,b)		Perl_pregcomp(aTHX_ a,b)
#define pregfree(a)		Perl_pregfree(aTHX_ a)
#define pregfree2(a)		Perl_pregfree2(aTHX_ a)
#define printbuf(a,b)		S_printbuf(aTHX_ a,b)
#define ptr_hash		S_ptr_hash
#define ptr_table_find		S_ptr_table_find
#define ptr_table_new()		Perl_ptr_table_new(aTHX)
#define push_scope()		Perl_push_scope(aTHX)
#define qerror(a)		Perl_qerror(aTHX_ a)
#define re_compile(a,b)		Perl_re_compile(aTHX_ a,b)
#define re_exec_indentf		Perl_re_exec_indentf
#define re_indentf		Perl_re_indentf
#define re_printf		Perl_re_printf
#define reentrant_retry		Perl_reentrant_retry
#define refkids(a,b)		S_refkids(aTHX_ a,b)
#define refto(a)		S_refto(aTHX_ a)
#define reg(a,b,c,d)		S_reg(aTHX_ a,b,c,d)
#define reg_node(a,b)		S_reg_node(aTHX_ a,b)
#define reg_skipcomment		S_reg_skipcomment
#define reganode(a,b,c)		S_reganode(aTHX_ a,b,c)
#define regatom(a,b,c)		S_regatom(aTHX_ a,b,c)
#define regcppop(a,b)		S_regcppop(aTHX_ a,b _aDEPTH)
#define regcurly		S_regcurly
#define regdump(a)		Perl_regdump(aTHX_ a)
#define reghop3			S_reghop3
#define reghop4			S_reghop4
#define reghopmaybe3		S_reghopmaybe3
#define reginitcolors()		Perl_reginitcolors(aTHX)
#define regmatch(a,b,c)		S_regmatch(aTHX_ a,b,c)
#define regnext(a)		Perl_regnext(aTHX_ a)
#define regpiece(a,b,c)		S_regpiece(aTHX_ a,b,c)
#define regtry(a,b)		S_regtry(aTHX_ a,b)
#define repeatcpy		Perl_repeatcpy
#define require_pv(a)		Perl_require_pv(aTHX_ a)
#define rninstr			Perl_rninstr
#define rpeep(a)		Perl_rpeep(aTHX_ a)
#define rsignal(a,b)		Perl_rsignal(aTHX_ a,b)
#define run_body(a)		S_run_body(aTHX_ a)
#define runops_debug()		Perl_runops_debug(aTHX)
#define rvpv_dup(a,b,c)		Perl_rvpv_dup(aTHX_ a,b,c)
#define rxres_free(a)		S_rxres_free(aTHX_ a)
#define rxres_save(a,b)		Perl_rxres_save(aTHX_ a,b)
#define safesyscalloc		Perl_safesyscalloc
#define safesysfree		Perl_safesysfree
#define safesysmalloc		Perl_safesysmalloc
#define safesysrealloc		Perl_safesysrealloc
#define save_I16(a)		Perl_save_I16(aTHX_ a)
#define save_I32(a)		Perl_save_I32(aTHX_ a)
#define save_I8(a)		Perl_save_I8(aTHX_ a)
#define save_alloc(a,b)		Perl_save_alloc(aTHX_ a,b)
#define save_aptr(a)		Perl_save_aptr(aTHX_ a)
#define save_ary(a)		Perl_save_ary(aTHX_ a)
#define save_bool(a)		Perl_save_bool(aTHX_ a)
#define save_clearsv(a)		Perl_save_clearsv(aTHX_ a)
#define save_gp(a,b)		Perl_save_gp(aTHX_ a,b)
#define save_hash(a)		Perl_save_hash(aTHX_ a)
#define save_hek_flags		S_save_hek_flags
#define save_hints()		Perl_save_hints(aTHX)
#define save_hptr(a)		Perl_save_hptr(aTHX_ a)
#define save_int(a)		Perl_save_int(aTHX_ a)
#define save_item(a)		Perl_save_item(aTHX_ a)
#define save_iv(a)		Perl_save_iv(aTHX_ a)
#define save_lines(a,b)		S_save_lines(aTHX_ a,b)
#define save_list(a,b)		Perl_save_list(aTHX_ a,b)
#define save_long(a)		Perl_save_long(aTHX_ a)
#define save_nogv(a)		Perl_save_nogv(aTHX_ a)
#define save_pptr(a)		Perl_save_pptr(aTHX_ a)
#define save_scalar(a)		Perl_save_scalar(aTHX_ a)
#define save_sptr(a)		Perl_save_sptr(aTHX_ a)
#define save_strlen(a)		Perl_save_strlen(aTHX_ a)
#define save_svref(a)		Perl_save_svref(aTHX_ a)
#define save_to_buffer		S_save_to_buffer
#define save_vptr(a)		Perl_save_vptr(aTHX_ a)
#define savepv(a)		Perl_savepv(aTHX_ a)
#define savepvn(a,b)		Perl_savepvn(aTHX_ a,b)
#define savesharedpv(a)		Perl_savesharedpv(aTHX_ a)
#define savesvpv(a)		Perl_savesvpv(aTHX_ a)
#define sawparens(a)		Perl_sawparens(aTHX_ a)
#define scalar(a)		Perl_scalar(aTHX_ a)
#define scalar_mod_type		S_scalar_mod_type
#define scalarkids(a)		S_scalarkids(aTHX_ a)
#define scalarseq(a)		S_scalarseq(aTHX_ a)
#define scalarvoid(a)		Perl_scalarvoid(aTHX_ a)
#define scan_bin(a,b,c)		Perl_scan_bin(aTHX_ a,b,c)
#define scan_const(a)		S_scan_const(aTHX_ a)
#define scan_heredoc(a)		S_scan_heredoc(aTHX_ a)
#define scan_hex(a,b,c)		Perl_scan_hex(aTHX_ a,b,c)
#define scan_num(a,b)		Perl_scan_num(aTHX_ a,b)
#define scan_oct(a,b,c)		Perl_scan_oct(aTHX_ a,b,c)
#define scan_pat(a,b)		S_scan_pat(aTHX_ a,b)
#define scan_subst(a)		S_scan_subst(aTHX_ a)
#define scan_trans(a)		S_scan_trans(aTHX_ a)
#define search_const(a)		S_search_const(aTHX_ a)
#define seed()			Perl_seed(aTHX)
#define sequence_num(a)		S_sequence_num(aTHX_ a)
#define set_caret_X()		Perl_set_caret_X(aTHX)
#define set_context		Perl_set_context
#define set_padlist		Perl_set_padlist
#define setdefout(a)		Perl_setdefout(aTHX_ a)
#define setfd_cloexec		Perl_setfd_cloexec
#define setfd_inhexec		Perl_setfd_inhexec
#define should_warn_nl		S_should_warn_nl
#define si_dup(a,b)		Perl_si_dup(aTHX_ a,b)
#define sighandler		Perl_sighandler
#define sortcv(a,b)		S_sortcv(aTHX_ a,b)
#define sortsv(a,b,c)		Perl_sortsv(aTHX_ a,b,c)
#define ss_dup(a,b)		Perl_ss_dup(aTHX_ a,b)
#define ssc_and(a,b,c)		S_ssc_and(aTHX_ a,b,c)
#define ssc_anything(a)		S_ssc_anything(aTHX_ a)
#define ssc_cp_and(a,b)		S_ssc_cp_and(aTHX_ a,b)
#define ssc_init(a,b)		S_ssc_init(aTHX_ a,b)
#define ssc_is_anything		S_ssc_is_anything
#define ssc_or(a,b,c)		S_ssc_or(aTHX_ a,b,c)
#define strip_return(a)		S_strip_return(aTHX_ a)
#define sublex_done()		S_sublex_done(aTHX)
#define sublex_push()		S_sublex_push(aTHX)
#define sublex_start()		S_sublex_start(aTHX)
#define sv_2cv(a,b,c,d)		Perl_sv_2cv(aTHX_ a,b,c,d)
#define sv_2io(a)		Perl_sv_2io(aTHX_ a)
#define sv_2mortal(a)		Perl_sv_2mortal(aTHX_ a)
#define sv_2num(a)		Perl_sv_2num(aTHX_ a)
#define sv_2pvbyte(a,b)		Perl_sv_2pvbyte(aTHX_ a,b)
#define sv_2pvutf8(a,b)		Perl_sv_2pvutf8(aTHX_ a,b)
#define sv_backoff		Perl_sv_backoff
#define sv_bless(a,b)		Perl_sv_bless(aTHX_ a,b)
#define sv_buf_to_ro(a)		Perl_sv_buf_to_ro(aTHX_ a)
#define sv_buf_to_rw(a)		S_sv_buf_to_rw(aTHX_ a)
#define sv_catpv(a,b)		Perl_sv_catpv(aTHX_ a,b)
#  define sv_catpvf		Perl_sv_catpvf_nocontext
#  define sv_catpvf_mg		Perl_sv_catpvf_mg_nocontext
#define sv_chop(a,b)		Perl_sv_chop(aTHX_ a,b)
#define sv_clean_all()		Perl_sv_clean_all(aTHX)
#define sv_clean_objs()		Perl_sv_clean_objs(aTHX)
#define sv_clear(a)		Perl_sv_clear(aTHX_ a)
#define sv_dec(a)		Perl_sv_dec(aTHX_ a)
#define sv_dec_nomg(a)		Perl_sv_dec_nomg(aTHX_ a)
#define sv_does(a,b)		Perl_sv_does(aTHX_ a,b)
#define sv_dump(a)		Perl_sv_dump(aTHX_ a)
#define sv_dup(a,b)		Perl_sv_dup(aTHX_ a,b)
#define sv_dup_inc(a,b)		Perl_sv_dup_inc(aTHX_ a,b)
#define sv_free(a)		Perl_sv_free(aTHX_ a)
#define sv_get_backrefs		Perl_sv_get_backrefs
#define sv_gets(a,b,c)		Perl_sv_gets(aTHX_ a,b,c)
#define sv_grow(a,b)		Perl_sv_grow(aTHX_ a,b)
#define sv_i_ncmp(a,b)		S_sv_i_ncmp(aTHX_ a,b)
#define sv_inc(a)		Perl_sv_inc(aTHX_ a)
#define sv_inc_nomg(a)		Perl_sv_inc_nomg(aTHX_ a)
#define sv_isa(a,b)		Perl_sv_isa(aTHX_ a,b)
#define sv_isobject(a)		Perl_sv_isobject(aTHX_ a)
#define sv_iv(a)		Perl_sv_iv(aTHX_ a)
#define sv_len(a)		Perl_sv_len(aTHX_ a)
#define sv_len_utf8(a)		Perl_sv_len_utf8(aTHX_ a)
#define sv_ncmp(a,b)		S_sv_ncmp(aTHX_ a,b)
#define sv_newmortal()		Perl_sv_newmortal(aTHX)
#define sv_newref(a)		Perl_sv_newref(aTHX_ a)
#define sv_nosharing(a)		Perl_sv_nosharing(aTHX_ a)
#define sv_nv(a)		Perl_sv_nv(aTHX_ a)
#define sv_peek(a)		Perl_sv_peek(aTHX_ a)
#define sv_pos_b2u(a,b)		Perl_sv_pos_b2u(aTHX_ a,b)
#define sv_pvbyten(a,b)		Perl_sv_pvbyten(aTHX_ a,b)
#define sv_pvn(a,b)		Perl_sv_pvn(aTHX_ a,b)
#define sv_pvutf8n(a,b)		Perl_sv_pvutf8n(aTHX_ a,b)
#define sv_ref(a,b,c)		Perl_sv_ref(aTHX_ a,b,c)
#define sv_reftype(a,b)		Perl_sv_reftype(aTHX_ a,b)
#define sv_replace(a,b)		Perl_sv_replace(aTHX_ a,b)
#define sv_reset(a,b)		Perl_sv_reset(aTHX_ a,b)
#define sv_rvweaken(a)		Perl_sv_rvweaken(aTHX_ a)
#define sv_set_undef(a)		Perl_sv_set_undef(aTHX_ a)
#define sv_sethek(a,b)		Perl_sv_sethek(aTHX_ a,b)
#define sv_setiv(a,b)		Perl_sv_setiv(aTHX_ a,b)
#define sv_setnv(a,b)		Perl_sv_setnv(aTHX_ a,b)
#  define sv_setptrobj(rv,ptr,name)	sv_setref_iv(rv,name,PTR2IV(ptr))
#  define sv_setptrref(rv,ptr)		sv_setref_iv(rv,NULL,PTR2IV(ptr))
#define sv_setpv(a,b)		Perl_sv_setpv(aTHX_ a,b)
#  define sv_setpvf		Perl_sv_setpvf_nocontext
#  define sv_setpvf_mg		Perl_sv_setpvf_mg_nocontext
#define sv_setpviv(a,b)		Perl_sv_setpviv(aTHX_ a,b)
#define sv_setuv(a,b)		Perl_sv_setuv(aTHX_ a,b)
#define sv_tainted(a)		Perl_sv_tainted(aTHX_ a)
#define sv_true(a)		Perl_sv_true(aTHX_ a)
#define sv_unglob(a,b)		S_sv_unglob(aTHX_ a,b)
#define sv_unmagic(a,b)		Perl_sv_unmagic(aTHX_ a,b)
#define sv_untaint(a)		Perl_sv_untaint(aTHX_ a)
#define sv_upgrade(a,b)		Perl_sv_upgrade(aTHX_ a,b)
#define sv_uv(a)		Perl_sv_uv(aTHX_ a)
#define swallow_bom(a)		S_swallow_bom(aTHX_ a)
#define sync_locale		Perl_sync_locale
#define taint_env()		Perl_taint_env(aTHX)
#define tied_method		Perl_tied_method
#define tmps_grow_p(a)		Perl_tmps_grow_p(aTHX_ a)
#define to_lower_latin1		S_to_lower_latin1
#define tokeq(a)		S_tokeq(aTHX_ a)
#define tokereport(a,b)		S_tokereport(aTHX_ a,b)
#define uiv_2buf		S_uiv_2buf
#define unlnk(a)		Perl_unlnk(aTHX_ a)
#define unshare_hek(a)		Perl_unshare_hek(aTHX_ a)
#define usage()			S_usage(aTHX)
#define utf8_hop		Perl_utf8_hop
#define utf8_hop_back		Perl_utf8_hop_back
#define utf8_hop_safe		Perl_utf8_hop_safe
#define vcmp(a,b)		Perl_vcmp(aTHX_ a,b)
#define vcroak(a,b)		Perl_vcroak(aTHX_ a,b)
#define vdeb(a,b)		Perl_vdeb(aTHX_ a,b)
#define vform(a,b)		Perl_vform(aTHX_ a,b)
#define visit(a,b,c)		S_visit(aTHX_ a,b,c)
#define vivify_ref(a,b)		Perl_vivify_ref(aTHX_ a,b)
#define vmess(a,b)		Perl_vmess(aTHX_ a,b)
#define vnewSVpvf(a,b)		Perl_vnewSVpvf(aTHX_ a,b)
#define vnormal(a)		Perl_vnormal(aTHX_ a)
#define vnumify(a)		Perl_vnumify(aTHX_ a)
#define vstringify(a)		Perl_vstringify(aTHX_ a)
#define vverify(a)		Perl_vverify(aTHX_ a)
#define vwarn(a,b)		Perl_vwarn(aTHX_ a,b)
#define vwarner(a,b,c)		Perl_vwarner(aTHX_ a,b,c)
#define wait4pid(a,b,c)		Perl_wait4pid(aTHX_ a,b,c)
#  define warn			Perl_warn_nocontext
#define warn_nocontext		Perl_warn_nocontext
#define warn_sv(a)		Perl_warn_sv(aTHX_ a)
#  define warner		Perl_warner_nocontext
#define watch(a)		Perl_watch(aTHX_ a)
#define whichsig_pv(a)		Perl_whichsig_pv(aTHX_ a)
#define whichsig_sv(a)		Perl_whichsig_sv(aTHX_ a)
#define yyerror(a)		Perl_yyerror(aTHX_ a)
#define yyerror_pv(a,b)		Perl_yyerror_pv(aTHX_ a,b)
#define yylex()			Perl_yylex(aTHX)
#define yyparse(a)		Perl_yyparse(aTHX_ a)
#define yyquit()		Perl_yyquit(aTHX)
#define yyunlex()		Perl_yyunlex(aTHX)
#define yywarn(a,b)		S_yywarn(aTHX_ a,b)
#define OPpALLOW_FAKE           0x40
#define OPpARG1_MASK            0x01
#define OPpARG2_MASK            0x03
#define OPpARG3_MASK            0x07
#define OPpARG4_MASK            0x0f
#define OPpARGELEM_AV           0x02
#define OPpARGELEM_HV           0x04
#define OPpARGELEM_MASK         0x06
#define OPpARGELEM_SV           0x00
#define OPpASSIGN_BACKWARDS     0x40
#define OPpASSIGN_COMMON_AGG    0x10
#define OPpASSIGN_COMMON_RC1    0x20
#define OPpASSIGN_COMMON_SCALAR 0x40
#define OPpASSIGN_CV_TO_GV      0x80
#define OPpASSIGN_TRUEBOOL      0x04
#define OPpAVHVSWITCH_MASK      0x03
#define OPpCONCAT_NESTED        0x40
#define OPpCONST_BARE           0x40
#define OPpCONST_ENTERED        0x10
#define OPpCONST_NOVER          0x02
#define OPpCONST_SHORTCIRCUIT   0x04
#define OPpCONST_STRICT         0x08
#define OPpCOREARGS_DEREF1      0x01
#define OPpCOREARGS_DEREF2      0x02
#define OPpCOREARGS_PUSHMARK    0x80
#define OPpCOREARGS_SCALARMOD   0x40
#define OPpDEREF                0x30
#define OPpDEREF_AV             0x10
#define OPpDEREF_HV             0x20
#define OPpDEREF_SV             0x30
#define OPpDONT_INIT_GV         0x04
#define OPpEARLY_CV             0x20
#define OPpENTERSUB_AMPER       0x08
#define OPpENTERSUB_DB          0x40
#define OPpENTERSUB_HASTARG     0x04
#define OPpENTERSUB_INARGS      0x01
#define OPpENTERSUB_NOPAREN     0x80
#define OPpEVAL_BYTES           0x08
#define OPpEVAL_COPHH           0x10
#define OPpEVAL_HAS_HH          0x02
#define OPpEVAL_RE_REPARSING    0x20
#define OPpEVAL_UNICODE         0x04
#define OPpEXISTS_SUB           0x40
#define OPpFLIP_LINENUM         0x40
#define OPpFT_ACCESS            0x02
#define OPpFT_AFTER_t           0x10
#define OPpFT_STACKED           0x04
#define OPpFT_STACKING          0x08
#define OPpHINT_STRICT_REFS     0x02
#define OPpHUSH_VMSISH          0x20
#define OPpINDEX_BOOLNEG        0x40
#define OPpITER_DEF             0x08
#define OPpITER_REVERSED        0x02
#define OPpKVSLICE              0x20
#define OPpLIST_GUESSED         0x40
#define OPpLVALUE               0x80
#define OPpLVAL_DEFER           0x40
#define OPpLVAL_INTRO           0x80
#define OPpLVREF_AV             0x10
#define OPpLVREF_CV             0x30
#define OPpLVREF_ELEM           0x04
#define OPpLVREF_HV             0x20
#define OPpLVREF_ITER           0x08
#define OPpLVREF_SV             0x00
#define OPpLVREF_TYPE           0x30
#define OPpMAYBE_LVSUB          0x08
#define OPpMAYBE_TRUEBOOL       0x10
#define OPpMAY_RETURN_CONSTANT  0x20
#define OPpMULTICONCAT_APPEND   0x40
#define OPpMULTICONCAT_FAKE     0x20
#define OPpMULTICONCAT_STRINGIFY 0x08
#define OPpMULTIDEREF_DELETE    0x20
#define OPpMULTIDEREF_EXISTS    0x10
#define OPpOFFBYONE             0x80
#define OPpOPEN_IN_CRLF         0x20
#define OPpOPEN_IN_RAW          0x10
#define OPpOPEN_OUT_CRLF        0x80
#define OPpOPEN_OUT_RAW         0x40
#define OPpOUR_INTRO            0x40
#define OPpPADHV_ISKEYS         0x01
#define OPpPADRANGE_COUNTMASK   0x7f
#define OPpPADRANGE_COUNTSHIFT  0x07
#define OPpPAD_STATE            0x40
#define OPpPV_IS_UTF8           0x80
#define OPpREFCOUNTED           0x40
#define OPpREPEAT_DOLIST        0x40
#define OPpREVERSE_INPLACE      0x08
#define OPpRV2HV_ISKEYS         0x01
#define OPpSLICE                0x40
#define OPpSLICEWARNING         0x04
#define OPpSORT_DESCEND         0x10
#define OPpSORT_INPLACE         0x08
#define OPpSORT_INTEGER         0x02
#define OPpSORT_NUMERIC         0x01
#define OPpSORT_REVERSE         0x04
#define OPpSORT_STABLE          0x40
#define OPpSORT_UNSTABLE        0x80
#define OPpSPLIT_ASSIGN         0x10
#define OPpSPLIT_IMPLIM         0x04
#define OPpSPLIT_LEX            0x08
#define OPpSUBSTR_REPL_FIRST    0x10
#define OPpTARGET_MY            0x10
#define OPpTRANS_COMPLEMENT     0x20
#define OPpTRANS_DELETE         0x80
#define OPpTRANS_FROM_UTF       0x01
#define OPpTRANS_GROWS          0x40
#define OPpTRANS_IDENTICAL      0x04
#define OPpTRANS_SQUASH         0x08
#define OPpTRANS_TO_UTF         0x02
#define OPpTRUEBOOL             0x20
#  define PERL_CHECK_INITED
#  define PERL_PPADDR_INITED
#define Perl_pp_accept Perl_unimplemented_op
#define Perl_pp_aelemfast_lex Perl_pp_aelemfast
#define Perl_pp_andassign Perl_pp_and
#define Perl_pp_avalues Perl_pp_akeys
#define Perl_pp_bind Perl_unimplemented_op
#define Perl_pp_bit_xor Perl_pp_bit_or
#define Perl_pp_chmod Perl_pp_chown
#define Perl_pp_chomp Perl_pp_chop
#define Perl_pp_connect Perl_pp_bind
#define Perl_pp_cos Perl_pp_sin
#define Perl_pp_custom Perl_unimplemented_op
#define Perl_pp_dbmclose Perl_pp_untie
#define Perl_pp_dofile Perl_pp_require
#define Perl_pp_dor Perl_pp_defined
#define Perl_pp_dorassign Perl_pp_defined
#define Perl_pp_dump Perl_pp_goto
#define Perl_pp_egrent Perl_pp_ehostent
#define Perl_pp_enetent Perl_pp_ehostent
#define Perl_pp_eprotoent Perl_pp_ehostent
#define Perl_pp_epwent Perl_pp_ehostent
#define Perl_pp_eservent Perl_pp_ehostent
#define Perl_pp_exp Perl_pp_sin
#define Perl_pp_fcntl Perl_pp_ioctl
#define Perl_pp_ftatime Perl_pp_ftis
#define Perl_pp_ftbinary Perl_pp_fttext
#define Perl_pp_ftblk Perl_pp_ftrowned
#define Perl_pp_ftchr Perl_pp_ftrowned
#define Perl_pp_ftctime Perl_pp_ftis
#define Perl_pp_ftdir Perl_pp_ftrowned
#define Perl_pp_fteexec Perl_pp_ftrread
#define Perl_pp_fteowned Perl_pp_ftrowned
#define Perl_pp_fteread Perl_pp_ftrread
#define Perl_pp_ftewrite Perl_pp_ftrread
#define Perl_pp_ftfile Perl_pp_ftrowned
#define Perl_pp_ftmtime Perl_pp_ftis
#define Perl_pp_ftpipe Perl_pp_ftrowned
#define Perl_pp_ftrexec Perl_pp_ftrread
#define Perl_pp_ftrwrite Perl_pp_ftrread
#define Perl_pp_ftsgid Perl_pp_ftrowned
#define Perl_pp_ftsize Perl_pp_ftis
#define Perl_pp_ftsock Perl_pp_ftrowned
#define Perl_pp_ftsuid Perl_pp_ftrowned
#define Perl_pp_ftsvtx Perl_pp_ftrowned
#define Perl_pp_ftzero Perl_pp_ftrowned
#define Perl_pp_getpeername Perl_unimplemented_op
#define Perl_pp_getsockname Perl_pp_getpeername
#define Perl_pp_ggrgid Perl_pp_ggrent
#define Perl_pp_ggrnam Perl_pp_ggrent
#define Perl_pp_ghbyaddr Perl_pp_ghostent
#define Perl_pp_ghbyname Perl_pp_ghostent
#define Perl_pp_gnbyaddr Perl_pp_gnetent
#define Perl_pp_gnbyname Perl_pp_gnetent
#define Perl_pp_gpbyname Perl_pp_gprotoent
#define Perl_pp_gpbynumber Perl_pp_gprotoent
#define Perl_pp_gpwnam Perl_pp_gpwent
#define Perl_pp_gpwuid Perl_pp_gpwent
#define Perl_pp_gsbyname Perl_pp_gservent
#define Perl_pp_gsbyport Perl_pp_gservent
#define Perl_pp_gsockopt Perl_pp_ssockopt
#define Perl_pp_hex Perl_pp_oct
#define Perl_pp_i_postdec Perl_pp_postdec
#define Perl_pp_i_postinc Perl_pp_postinc
#define Perl_pp_i_predec Perl_pp_predec
#define Perl_pp_i_preinc Perl_pp_preinc
#define Perl_pp_keys Perl_do_kv
#define Perl_pp_kill Perl_pp_chown
#define Perl_pp_lcfirst Perl_pp_ucfirst
#define Perl_pp_lineseq Perl_pp_null
#define Perl_pp_listen Perl_unimplemented_op
#define Perl_pp_localtime Perl_pp_gmtime
#define Perl_pp_log Perl_pp_sin
#define Perl_pp_lstat Perl_pp_stat
#define Perl_pp_mapstart Perl_pp_grepstart
#define Perl_pp_msgctl Perl_pp_semctl
#define Perl_pp_msgget Perl_pp_semget
#define Perl_pp_msgrcv Perl_pp_shmwrite
#define Perl_pp_msgsnd Perl_pp_shmwrite
#define Perl_pp_nbit_xor Perl_pp_nbit_or
#define Perl_pp_orassign Perl_pp_or
#define Perl_pp_padany Perl_unimplemented_op
#define Perl_pp_pop Perl_pp_shift
#define Perl_pp_read Perl_pp_sysread
#define Perl_pp_recv Perl_pp_sysread
#define Perl_pp_regcmaybe Perl_pp_null
#define Perl_pp_rindex Perl_pp_index
#define Perl_pp_rv2hv Perl_pp_rv2av
#define Perl_pp_say Perl_pp_print
#define Perl_pp_sbit_xor Perl_pp_sbit_or
#define Perl_pp_scalar Perl_pp_null
#define Perl_pp_schomp Perl_pp_schop
#define Perl_pp_scope Perl_pp_null
#define Perl_pp_seek Perl_pp_sysseek
#define Perl_pp_semop Perl_pp_shmwrite
#define Perl_pp_send Perl_pp_syswrite
#define Perl_pp_sge Perl_pp_sle
#define Perl_pp_sgrent Perl_pp_ehostent
#define Perl_pp_sgt Perl_pp_sle
#define Perl_pp_shmctl Perl_pp_semctl
#define Perl_pp_shmget Perl_pp_semget
#define Perl_pp_shmread Perl_pp_shmwrite
#define Perl_pp_shutdown Perl_unimplemented_op
#define Perl_pp_slt Perl_pp_sle
#define Perl_pp_snetent Perl_pp_shostent
#define Perl_pp_socket Perl_unimplemented_op
#define Perl_pp_sprotoent Perl_pp_shostent
#define Perl_pp_spwent Perl_pp_ehostent
#define Perl_pp_sqrt Perl_pp_sin
#define Perl_pp_sservent Perl_pp_shostent
#define Perl_pp_ssockopt Perl_unimplemented_op
#define Perl_pp_symlink Perl_pp_link
#define Perl_pp_transr Perl_pp_trans
#define Perl_pp_unlink Perl_pp_chown
#define Perl_pp_utime Perl_pp_chown
#define Perl_pp_values Perl_do_kv
#define AMG_CALLun(sv,meth) AMG_CALLunary(sv, CAT2(meth,_amg))
#define AMG_CALLunary(sv,meth) \
    amagic_call(sv,&PL_sv_undef, meth, AMGf_noright | AMGf_unary)
#define DIE return Perl_die
#  define EXTEND(p,n)   STMT_START {                                    \
                         EXTEND_HWM_SET(p, n);                          \
                         if (UNLIKELY(_EXTEND_NEEDS_GROW(p,n))) {       \
                           sp = stack_grow(sp,p,_EXTEND_SAFE_N(n));     \
                           PERL_UNUSED_VAR(sp);                         \
                         } } STMT_END
#  define EXTEND_HWM_SET(p, n)                      \
        STMT_START {                                \
            SSize_t ix = (p) - PL_stack_base + (n); \
            if (ix > PL_curstackinfo->si_stack_hwm) \
                PL_curstackinfo->si_stack_hwm = ix; \
        } STMT_END
#define EXTEND_MORTAL(n) \
    STMT_START {						\
	SSize_t eMiX = PL_tmps_ix + (n);			\
	if (UNLIKELY(eMiX >= PL_tmps_max))			\
	    (void)Perl_tmps_grow_p(aTHX_ eMiX);			\
    } STMT_END
#  define EXTEND_SKIP(p, n) STMT_START {                                \
                                EXTEND_HWM_SET(p, n);                   \
                                assert(!_EXTEND_NEEDS_GROW(p,n));       \
                          } STMT_END
#define GETATARGET targ = (PL_op->op_flags & OPf_STACKED ? sp[-1] : PAD_SV(PL_op->op_targ))
#define GETTARGET targ = PAD_SV(PL_op->op_targ)
#define GETTARGETSTACKED targ = (PL_op->op_flags & OPf_STACKED ? POPs : PAD_SV(PL_op->op_targ))
#define INCMARK \
    STMT_START {                                                      \
        DEBUG_s(DEBUG_v(PerlIO_printf(Perl_debug_log,                 \
                "MARK inc  %p %" IVdf "\n",                           \
                (PL_markstack_ptr+1), (IV)*(PL_markstack_ptr+1))));   \
        PL_markstack_ptr++;                                           \
    } STMT_END
#define LVRET ((PL_op->op_private & OPpMAYBE_LVSUB) && is_lvalue_sub())
#define MARK mark
#  define MAYBE_DEREF_GV(sv)      MAYBE_DEREF_GV_flags(sv,SV_GMAGIC)
#  define MAYBE_DEREF_GV_flags(sv,phlags)                          \
    (                                                               \
	(void)(phlags & SV_GMAGIC && (SvGETMAGIC(sv),0)),            \
	isGV_with_GP(sv)                                              \
	  ? (GV *)(sv)                                                \
	  : SvROK(sv) && SvTYPE(SvRV(sv)) <= SVt_PVLV &&               \
	    (SvGETMAGIC(SvRV(sv)), isGV_with_GP(SvRV(sv)))              \
	     ? (GV *)SvRV(sv)                                            \
	     : NULL                                                       \
    )
#  define MAYBE_DEREF_GV_nomg(sv) MAYBE_DEREF_GV_flags(sv,0)
#  define MEXTEND(p,n)  STMT_START {                                    \
                         EXTEND_HWM_SET(p, n);                          \
                         if (UNLIKELY(_EXTEND_NEEDS_GROW(p,n))) {       \
                           const SSize_t markoff = mark - PL_stack_base;\
                           sp = stack_grow(sp,p,_EXTEND_SAFE_N(n));     \
                           mark = PL_stack_base + markoff;              \
                           PERL_UNUSED_VAR(sp);                         \
                         } } STMT_END
#define NORMAL PL_op->op_next
#define POPMARK S_POPMARK(aTHX)
#define POPp		POPpx
#define PP(s) OP * Perl_##s(pTHX)
#define PUSHMARK(p) \
    STMT_START {                                                      \
        I32 * mark_stack_entry;                                       \
        if (UNLIKELY((mark_stack_entry = ++PL_markstack_ptr)          \
                                           == PL_markstack_max))      \
	    mark_stack_entry = markstack_grow();                      \
        *mark_stack_entry  = (I32)((p) - PL_stack_base);              \
        DEBUG_s(DEBUG_v(PerlIO_printf(Perl_debug_log,                 \
                "MARK push %p %" IVdf "\n",                           \
                PL_markstack_ptr, (IV)*mark_stack_entry)));           \
    } STMT_END
#define PUSHi(i)	STMT_START { TARGi(i,1); PUSHs(TARG); } STMT_END
#define PUSHn(n)	STMT_START { TARGn(n,1); PUSHs(TARG); } STMT_END
#define PUSHp(p,l)	STMT_START { sv_setpvn(TARG, (p), (l)); PUSHTARG; } STMT_END
#define PUSHs(s)	(*++sp = (s))
#define PUSHu(u)	STMT_START { TARGu(u,1); PUSHs(TARG); } STMT_END
#define RETURNOP(o)	return (PUTBACK, o)
#define RETURNX(x)	return (x, PUTBACK, NORMAL)
#define SETi(i)		STMT_START { TARGi(i,1); SETs(TARG); } STMT_END
#define SETn(n)		STMT_START { TARGn(n,1); SETs(TARG); } STMT_END
#define SETp(p,l)	STMT_START { sv_setpvn(TARG, (p), (l)); SETTARG; } STMT_END
#define SETs(s)		(*sp = s)
#define SETu(u)		STMT_START { TARGu(u,1); SETs(TARG); } STMT_END
#define SP sp
#define SWITCHSTACK(f,t) \
    STMT_START {							\
	AvFILLp(f) = sp - PL_stack_base;				\
	PL_stack_base = AvARRAY(t);					\
	PL_stack_max = PL_stack_base + AvMAX(t);			\
	sp = PL_stack_sp = PL_stack_base + AvFILLp(t);			\
	PL_curstack = t;						\
    } STMT_END
#define SvCANEXISTDELETE(sv) \
 (!SvRMAGICAL(sv)            \
  || !(mg = mg_find((const SV *) sv, PERL_MAGIC_tied))           \
  || (   (stash = SvSTASH(SvRV(SvTIED_obj(MUTABLE_SV(sv), mg)))) \
      && gv_fetchmethod_autoload(stash, "EXISTS", TRUE)          \
      && gv_fetchmethod_autoload(stash, "DELETE", TRUE)          \
     )                       \
  )
#define TARG targ
#define TARGi(i, do_taint) \
    STMT_START {                                                        \
        IV TARGi_iv = i;                                                \
        if (LIKELY(                                                     \
              ((SvFLAGS(TARG) & (SVTYPEMASK|SVf_THINKFIRST|SVf_IVisUV)) == SVt_IV) \
            & (do_taint ? !TAINT_get : 1)))                             \
        {                                                               \
                          \
            assert(!(SvFLAGS(TARG) &                                    \
                (SVf_OOK|SVf_UTF8|(SVf_OK & ~(SVf_IOK|SVp_IOK)))));     \
            SvFLAGS(TARG) |= (SVf_IOK|SVp_IOK);                         \
                            \
            TARG->sv_u.svu_iv = TARGi_iv;                               \
        }                                                               \
        else                                                            \
            sv_setiv_mg(targ, TARGi_iv);                                \
    } STMT_END
#define TARGn(n, do_taint) \
    STMT_START {                                                        \
        NV TARGn_nv = n;                                                \
        if (LIKELY(                                                     \
              ((SvFLAGS(TARG) & (SVTYPEMASK|SVf_THINKFIRST)) == SVt_NV) \
            & (do_taint ? !TAINT_get : 1)))                             \
        {                                                               \
                          \
            assert(!(SvFLAGS(TARG) &                                    \
                (SVf_OOK|SVf_UTF8|(SVf_OK & ~(SVf_NOK|SVp_NOK)))));     \
            SvFLAGS(TARG) |= (SVf_NOK|SVp_NOK);                         \
            SvNV_set(TARG, TARGn_nv);                                   \
        }                                                               \
        else                                                            \
            sv_setnv_mg(targ, TARGn_nv);                                \
    } STMT_END
#define TARGu(u, do_taint) \
    STMT_START {                                                        \
        UV TARGu_uv = u;                                                \
        if (LIKELY(                                                     \
              ((SvFLAGS(TARG) & (SVTYPEMASK|SVf_THINKFIRST|SVf_IVisUV)) == SVt_IV) \
            & (do_taint ? !TAINT_get : 1)                               \
            & (TARGu_uv <= (UV)IV_MAX)))                                \
        {                                                               \
                          \
            assert(!(SvFLAGS(TARG) &                                    \
                (SVf_OOK|SVf_UTF8|(SVf_OK & ~(SVf_IOK|SVp_IOK)))));     \
            SvFLAGS(TARG) |= (SVf_IOK|SVp_IOK);                         \
                            \
            TARG->sv_u.svu_iv = TARGu_uv;                               \
        }                                                               \
        else                                                            \
            sv_setuv_mg(targ, TARGu_uv);                                \
    } STMT_END
#define TOPMARK S_TOPMARK(aTHX)
#define TOPp		TOPpx
#define USE_LEFT(sv) \
	(SvOK(sv) || !(PL_op->op_flags & OPf_STACKED))
#define XPUSHi(i)	STMT_START { TARGi(i,1); XPUSHs(TARG); } STMT_END
#define XPUSHn(n)	STMT_START { TARGn(n,1); XPUSHs(TARG); } STMT_END
#define XPUSHp(p,l)	STMT_START { sv_setpvn(TARG, (p), (l)); XPUSHTARG; } STMT_END
#define XPUSHs(s)	STMT_START { EXTEND(sp,1); *++sp = (s); } STMT_END
#define XPUSHu(u)	STMT_START { TARGu(u,1); XPUSHs(TARG); } STMT_END
#  define _EXTEND_NEEDS_GROW(p,n) ((n) < 0 || PL_stack_max - (p) < (n))
#define _EXTEND_SAFE_N(n) \
        (sizeof(n) > sizeof(SSize_t) && ((SSize_t)(n) != (n)) ? -1 : (n))
#define dATARGET SV * GETATARGET
#define dPOPTOPiirl_nomg \
    IV right = SvIV_nomg(TOPs); IV left = (sp--, SvIV_nomg(TOPs))
#define dPOPTOPiirl_ul_nomg dPOPXiirl_ul_nomg(TOP)
#define dPOPTOPnnrl_nomg \
    NV right = SvNV_nomg(TOPs); NV left = (sp--, SvNV_nomg(TOPs))
#define dPOPXiirl(X)	IV right = POPi; IV left = CAT2(X,i)
#define dPOPXiirl_ul_nomg(X) \
    IV right = (sp--, SvIV_nomg(TOPp1s));		\
    SV *leftsv = CAT2(X,s);				\
    IV left = USE_LEFT(leftsv) ? SvIV_nomg(leftsv) : 0
#define dPOPXnnrl(X)	NV right = POPn; NV left = CAT2(X,n)
#define dPOPXssrl(X)	SV *right = POPs; SV *left = CAT2(X,s)
#define dTARG SV *targ
#define dTARGET SV * GETTARGET
#define dTARGETSTACKED SV * GETTARGETSTACKED
#define mPUSHi(i)	sv_setiv(PUSHmortal, (IV)(i))
#define mPUSHn(n)	sv_setnv(PUSHmortal, (NV)(n))
#define mPUSHp(p,l)	PUSHs(newSVpvn_flags((p), (l), SVs_TEMP))
#define mPUSHs(s)	PUSHs(sv_2mortal(s))
#define mPUSHu(u)	sv_setuv(PUSHmortal, (UV)(u))
#define mXPUSHi(i)	STMT_START { EXTEND(sp,1); mPUSHi(i); } STMT_END
#define mXPUSHn(n)	STMT_START { EXTEND(sp,1); mPUSHn(n); } STMT_END
#define mXPUSHp(p,l)	STMT_START { EXTEND(sp,1); mPUSHp((p), (l)); } STMT_END
#define mXPUSHs(s)	XPUSHs(sv_2mortal(s))
#define mXPUSHu(u)	STMT_START { EXTEND(sp,1); mPUSHu(u); } STMT_END
#define opASSIGN (PL_op->op_flags & OPf_STACKED)
#define tryAMAGICbin_MG(method, flags) STMT_START { \
	if ( UNLIKELY(((SvFLAGS(TOPm1s)|SvFLAGS(TOPs)) & (SVf_ROK|SVs_GMG))) \
		&& Perl_try_amagic_bin(aTHX_ method, flags)) \
	    return NORMAL; \
    } STMT_END
#define tryAMAGICunDEREF(meth)						\
    STMT_START {							\
	sv = amagic_deref_call(*sp, CAT2(meth,_amg));			\
	SPAGAIN;							\
    } STMT_END
#define tryAMAGICunTARGETlist(meth, jump)			\
    STMT_START {						\
	dSP;							\
	SV *tmpsv;						\
	SV *arg= *sp;						\
        U8 gimme = GIMME_V;                                    \
	if (UNLIKELY(SvAMAGIC(arg) &&				\
	    (tmpsv = amagic_call(arg, &PL_sv_undef, meth,	\
				 AMGf_want_list | AMGf_noright	\
				|AMGf_unary))))                 \
        {                                       		\
	    SPAGAIN;						\
            if (gimme == G_VOID) {                              \
                NOOP;                                           \
            }                                                   \
            else if (gimme == G_ARRAY) {			\
                SSize_t i;                                      \
                SSize_t len;                                    \
                assert(SvTYPE(tmpsv) == SVt_PVAV);              \
                len = av_tindex((AV *)tmpsv) + 1;               \
                (void)POPs;             \
                EXTEND(sp, len);                                \
                for (i = 0; i < len; ++i)                       \
                    PUSHs(av_shift((AV *)tmpsv));               \
            }                                                   \
            else {                        \
                dATARGET;      \
                sv_setsv(TARG, tmpsv);                          \
                if (PL_op->op_flags & OPf_STACKED)              \
                    sp--;                                       \
                SETTARG;                                        \
            }                                                   \
	    PUTBACK;						\
	    if (jump) {						\
	        OP *jump_o = NORMAL->op_next;                   \
		while (jump_o->op_type == OP_NULL)		\
		    jump_o = jump_o->op_next;			\
		assert(jump_o->op_type == OP_ENTERSUB);		\
		(void)POPMARK;                                        \
		return jump_o->op_next;				\
	    }							\
	    return NORMAL;					\
	}							\
    } STMT_END
#define tryAMAGICun_MG(method, flags) STMT_START { \
	if ( UNLIKELY((SvFLAGS(TOPs) & (SVf_ROK|SVs_GMG))) \
		&& Perl_try_amagic_un(aTHX_ method, flags)) \
	    return NORMAL; \
    } STMT_END
#  define ALLOC_THREAD_KEY \
    STMT_START {						\
	if (pthread_key_create(&PL_thr_key, 0)) {		\
            PERL_UNUSED_RESULT(write(2, STR_WITH_LEN("panic: pthread_key_create failed\n"))); \
	    exit(1);						\
	}							\
    } STMT_END
#  define COND_BROADCAST(c) \
    STMT_START {						\
	int _eC_;						\
	if ((_eC_ = pthread_cond_broadcast((c))))		\
	    Perl_croak_nocontext("panic: COND_BROADCAST (%d) [%s:%d]",	\
				 _eC_, "__FILE__", "__LINE__");	\
    } STMT_END
#  define COND_DESTROY(c) \
    STMT_START {						\
	int _eC_;						\
	if ((_eC_ = pthread_cond_destroy((c))))			\
	    Perl_croak_nocontext("panic: COND_DESTROY (%d) [%s:%d]",	\
				 _eC_, "__FILE__", "__LINE__");	\
    } STMT_END
#  define COND_INIT(c) \
    STMT_START {						\
	int _eC_;						\
	if ((_eC_ = pthread_cond_init((c), pthread_condattr_default)))	\
	    Perl_croak_nocontext("panic: COND_INIT (%d) [%s:%d]",	\
				 _eC_, "__FILE__", "__LINE__");	\
    } STMT_END
#  define COND_SIGNAL(c) \
    STMT_START {						\
	int _eC_;						\
	if ((_eC_ = pthread_cond_signal((c))))			\
	    Perl_croak_nocontext("panic: COND_SIGNAL (%d) [%s:%d]",	\
				 _eC_, "__FILE__", "__LINE__");	\
    } STMT_END
#  define COND_WAIT(c, m) \
    STMT_START {						\
	int _eC_;						\
	if ((_eC_ = pthread_cond_wait((c), (m))))		\
	    Perl_croak_nocontext("panic: COND_WAIT (%d) [%s:%d]",	\
				 _eC_, "__FILE__", "__LINE__");	\
    } STMT_END
#    define DETACH(t) \
    STMT_START {						\
	int _eC_;						\
	if ((_eC_ = pthread_detach(&(t)->self))) {		\
	    MUTEX_UNLOCK(&(t)->mutex);				\
	    Perl_croak_nocontext("panic: DETACH (%d) [%s:%d]",	\
				 _eC_, "__FILE__", "__LINE__");	\
	}							\
    } STMT_END
#  define FREE_THREAD_KEY \
    STMT_START {						\
	pthread_key_delete(PL_thr_key);				\
    } STMT_END
#  define HAS_PTHREAD_UNCHECKED_GETSPECIFIC_NP 
#    define INIT_THREADS pthread_init()
#  define JOIN(t, avp) \
    STMT_START {						\
	int _eC_;						\
	if ((_eC_ = pthread_join((t)->self, (void**)(avp))))	\
	    Perl_croak_nocontext("panic: pthread_join (%d) [%s:%d]",	\
				 _eC_, "__FILE__", "__LINE__");	\
    } STMT_END
#  define LOCK_DOLLARZERO_MUTEX   NOOP
#  define MUTEX_DESTROY(m) \
    STMT_START {						\
	int _eC_;						\
	if ((_eC_ = pthread_mutex_destroy((m))))		\
	    Perl_croak_nocontext("panic: MUTEX_DESTROY (%d) [%s:%d]",	\
				 _eC_, "__FILE__", "__LINE__");	\
    } STMT_END
#    define MUTEX_INIT(m) \
    STMT_START {						\
	int _eC_;						\
	Zero((m), 1, perl_mutex);                               \
 	if ((_eC_ = pthread_mutex_init((m), pthread_mutexattr_default)))	\
	    Perl_croak_nocontext("panic: MUTEX_INIT (%d) [%s:%d]",	\
				 _eC_, "__FILE__", "__LINE__");	\
    } STMT_END
#  define MUTEX_INIT_NEEDS_MUTEX_ZEROED
#  define MUTEX_LOCK(m) \
    STMT_START {						\
	int _eC_;						\
	if ((_eC_ = perl_pthread_mutex_lock((m))))			\
	    Perl_croak_nocontext("panic: MUTEX_LOCK (%d) [%s:%d]",	\
				 _eC_, "__FILE__", "__LINE__");	\
    } STMT_END
#  define MUTEX_UNLOCK(m) \
    STMT_START {						\
	int _eC_;						\
	if ((_eC_ = perl_pthread_mutex_unlock((m))))			\
	    Perl_croak_nocontext("panic: MUTEX_UNLOCK (%d) [%s:%d]",	\
				 _eC_, "__FILE__", "__LINE__");	\
    } STMT_END
#      define NEED_PTHREAD_INIT
#    define PTHREAD_ATFORK(prepare,parent,child)		\
	pthread_atfork(prepare,parent,child)
#      define PTHREAD_ATTR_SETDETACHSTATE(a,s) pthread_setdetach_np(a,s)
#      define PTHREAD_CREATE(t,a,s,d) pthread_create(t,a,s,d)
#      define PTHREAD_CREATE_JOINABLE (1)
#    define PTHREAD_GETSPECIFIC(key) pthread_getspecific(key)
#    define PTHREAD_GETSPECIFIC_INT
#  define SET_THR(t)	PERL_SET_THX(t)
#define SET_THREAD_SELF(thr)	(thr->self = cthread_self())
#define THREAD_CREATE(thr, f)	(thr->self = cthread_fork(f, thr), 0)
#    define THREAD_CREATE_NEEDS_STACK (48*1024)
#define THREAD_POST_CREATE(thr)	NOOP
#  define THREAD_RET_CAST(p)	((void *)(p))
#  define UNLOCK_DOLLARZERO_MUTEX NOOP
#      define YIELD pthread_yield(NULL)
#  define dTHR dNOOP
#    define perl_pthread_mutex_lock(m) perl_tsa_mutex_lock(m)
#    define perl_pthread_mutex_unlock(m) perl_tsa_mutex_unlock(m)
#      define pthread_addr_t any_t
#      define pthread_attr_init(a) pthread_attr_create(a)
#    define pthread_condattr_default  NULL
#      define pthread_create(t,a,s,d)        pthread_create(t,&(a),s,d)
#      define pthread_key_create(k,d) pthread_keycreate(k,(pthread_destructor_t)(d))
#      define pthread_keycreate              pthread_key_create
#    define pthread_mutexattr_default NULL
#      define pthread_mutexattr_init(a) pthread_mutexattr_create(a)
#      define pthread_mutexattr_settype(a,t) pthread_mutexattr_setkind_np(a,t)
#    define PERL_GIT_UNPUSHED_COMMITS 
#    define PERL_PATCHNUM "UNKNOWN-miniperl"
#define SUBVERSION		PERL_SUBVERSION

# define LEX_START_FLAGS \
	(LEX_START_SAME_FILTER|LEX_START_COPIED \
	|LEX_IGNORE_UTF8_HINTS|LEX_EVALBYTES|LEX_DONT_CLOSE_RSFP)
#define PARSE_OPTIONAL          0x00000001
#define ANGSTROM_SIGN                           0x212B
#define ANYOF_FOLD_SHARP_S(node, input, end)	\
	(ANYOF_BITMAP_TEST(node, LATIN_SMALL_LETTER_SHARP_S) && \
	 (ANYOF_NONBITMAP(node)) && \
	 (ANYOF_FLAGS(node) & ANYOF_LOC_NONBITMAP_FOLD) && \
	 ((end) > (input) + 1) && \
	 isALPHA_FOLD_EQ((input)[0], 's'))
#define ASCII_TO_NATIVE(ch)      LATIN1_TO_NATIVE(ch)
#define DO_UTF8(sv) (SvUTF8(sv) && !IN_BYTES)
#define EIGHT_BIT_UTF8_TO_NATIVE(HI, LO)                                        \
    ( __ASSERT_(UTF8_IS_DOWNGRADEABLE_START(HI))                                \
      __ASSERT_(UTF8_IS_CONTINUATION(LO))                                       \
     LATIN1_TO_NATIVE(UTF8_ACCUMULATE((                                         \
                            NATIVE_UTF8_TO_I8(HI) & UTF_START_MASK(2)), (LO))))
#define FOLDEQ_LOCALE             (1 << 1)
#define FOLDEQ_S1_ALREADY_FOLDED  (1 << 2)
#define FOLDEQ_S1_FOLDS_SANE      (1 << 4)
#define FOLDEQ_S2_ALREADY_FOLDED  (1 << 3)
#define FOLDEQ_S2_FOLDS_SANE      (1 << 5)
#define FOLDEQ_UTF8_NOMIX_ASCII   (1 << 0)
#define FOLD_FLAGS_FULL         0x2
#define FOLD_FLAGS_LOCALE       0x1
#define FOLD_FLAGS_NOMIX_ASCII  0x4
#define GREEK_CAPITAL_LETTER_MU                 0x039C	
#define GREEK_SMALL_LETTER_MU                   0x03BC
#define I8_TO_NATIVE(ch)         I8_TO_NATIVE_UTF8(ch)
#define I8_TO_NATIVE_UTF8(ch) ((U8) (ch))
#define ILLEGAL_UTF8_BYTE   I8_TO_NATIVE_UTF8(0xC1)
#define IN_BYTES UNLIKELY(CopHINTS_get(PL_curcop) & HINT_BYTES)
#define IN_UNI_8_BIT                                                    \
	    ((    (      (CopHINTS_get(PL_curcop) & HINT_UNI_8_BIT))    \
                   || (   CopHINTS_get(PL_curcop) & HINT_LOCALE_PARTIAL \
                                   \
                       && _is_in_locale_category(FALSE, -1)))           \
              && (! IN_BYTES))
#define IS_UTF8_CHAR(p, n)      (isUTF8_CHAR(p, (p) + (n)) == n)
#define KELVIN_SIGN                             0x212A
#define LATIN1_TO_NATIVE(ch)     ((U8)(ch))
#define LATIN_CAPITAL_LETTER_A_WITH_RING_ABOVE                               \
                            LATIN_CAPITAL_LETTER_A_WITH_RING_ABOVE_NATIVE
#define LATIN_CAPITAL_LETTER_I_WITH_DOT_ABOVE   0x130
#define LATIN_CAPITAL_LETTER_Y_WITH_DIAERESIS   0x0178	
#define LATIN_SMALL_LETTER_A_WITH_RING_ABOVE                                 \
                                LATIN_SMALL_LETTER_A_WITH_RING_ABOVE_NATIVE
#define LATIN_SMALL_LETTER_DOTLESS_I            0x131
#define LATIN_SMALL_LETTER_LONG_S               0x017F
#define LATIN_SMALL_LETTER_SHARP_S      LATIN_SMALL_LETTER_SHARP_S_NATIVE
#define LATIN_SMALL_LETTER_Y_WITH_DIAERESIS                                  \
                                LATIN_SMALL_LETTER_Y_WITH_DIAERESIS_NATIVE
#define LATIN_SMALL_LIGATURE_LONG_S_T           0xFB05
#define LATIN_SMALL_LIGATURE_ST                 0xFB06
#define MAX_LEGAL_CP  ((UV)IV_MAX)
#define MAX_PORTABLE_UTF8_TWO_BYTE (32 * (1U << 5) - 1)
#define MAX_UTF8_TWO_BYTE (32 * (1U << UTF_ACCUMULATION_SHIFT) - 1)
#define MICRO_SIGN      MICRO_SIGN_NATIVE
#define NATIVE8_TO_UNI(ch)       NATIVE_TO_LATIN1(ch)
#define NATIVE_BYTE_IS_INVARIANT(c)	UVCHR_IS_INVARIANT(c)
#define NATIVE_SKIP(uv) UVCHR_SKIP(uv)
#define NATIVE_TO_ASCII(ch)      NATIVE_TO_LATIN1(ch)
#define NATIVE_TO_I8(ch)         NATIVE_UTF8_TO_I8(ch)
#define NATIVE_TO_LATIN1(ch)     ((U8)(ch))
#define NATIVE_TO_UNI(ch)        ((UV) (ch))
#define NATIVE_TO_UTF(ch)        NATIVE_UTF8_TO_I8(ch)
#define NATIVE_UTF8_TO_I8(ch) ((U8) (ch))
#define OFFUNISKIP(uv) (OFFUNI_IS_INVARIANT(uv) ? 1 : __BASE_UNI_SKIP(uv))
#define OFFUNI_IS_INVARIANT(cp)     isASCII(cp)

#define PERL_UTF8_H_ 1
#define QUESTION_MARK_CTRL  DEL_NATIVE
#define SHARP_S_SKIP 2
#define TWO_BYTE_UTF8_TO_NATIVE(HI, LO) \
    (__ASSERT_(FITS_IN_8_BITS(HI))                                              \
     __ASSERT_(FITS_IN_8_BITS(LO))                                              \
     __ASSERT_(PL_utf8skip[HI] == 2)                                            \
     __ASSERT_(UTF8_IS_CONTINUATION(LO))                                        \
     UNI_TO_NATIVE(UTF8_ACCUMULATE((NATIVE_UTF8_TO_I8(HI) & UTF_START_MASK(2)), \
                                   (LO))))
#define TWO_BYTE_UTF8_TO_UNI(HI, LO) NATIVE_TO_UNI(TWO_BYTE_UTF8_TO_NATIVE(HI, LO))
#define UNICODE_ALLOW_SURROGATE 0
#define UNICODE_DISALLOW_ABOVE_31_BIT  UNICODE_DISALLOW_PERL_EXTENDED
#define UNICODE_DISALLOW_ILLEGAL_C9_INTERCHANGE                               \
                          (UNICODE_DISALLOW_SURROGATE|UNICODE_DISALLOW_SUPER)
#define UNICODE_DISALLOW_ILLEGAL_INTERCHANGE                                  \
           (UNICODE_DISALLOW_ILLEGAL_C9_INTERCHANGE|UNICODE_DISALLOW_NONCHAR)
#define UNICODE_DISALLOW_NONCHAR       0x0020
#define UNICODE_DISALLOW_PERL_EXTENDED 0x0080
#define UNICODE_DISALLOW_SUPER         0x0040
#define UNICODE_DISALLOW_SURROGATE     0x0010
#define UNICODE_GOT_NONCHAR         UNICODE_DISALLOW_NONCHAR
#define UNICODE_GOT_PERL_EXTENDED   UNICODE_DISALLOW_PERL_EXTENDED
#define UNICODE_GOT_SUPER           UNICODE_DISALLOW_SUPER
#define UNICODE_GOT_SURROGATE       UNICODE_DISALLOW_SURROGATE
#define UNICODE_IS_32_CONTIGUOUS_NONCHARS(uv)      ((UV) (uv) >= 0xFDD0         \
                                                 && (UV) (uv) <= 0xFDEF)
#define UNICODE_IS_BYTE_ORDER_MARK(uv)	((UV) (uv) == UNICODE_BYTE_ORDER_MARK)
#define UNICODE_IS_END_PLANE_NONCHAR_GIVEN_NOT_SUPER(uv)                        \
                                              (((UV) (uv) & 0xFFFE) == 0xFFFE)
#define UNICODE_IS_NONCHAR(uv)                                                  \
    (   UNICODE_IS_32_CONTIGUOUS_NONCHARS(uv)                                   \
     || (   LIKELY( ! UNICODE_IS_SUPER(uv))                                     \
         && UNICODE_IS_END_PLANE_NONCHAR_GIVEN_NOT_SUPER(uv)))
#define UNICODE_IS_PERL_EXTENDED(uv)    UNLIKELY((UV) (uv) > 0x7FFFFFFF)
#define UNICODE_IS_REPLACEMENT(uv)	((UV) (uv) == UNICODE_REPLACEMENT)
#define UNICODE_IS_SUPER(uv)    ((UV) (uv) > PERL_UNICODE_MAX)
#define UNICODE_IS_SURROGATE(uv)        (((UV) (uv) & (~0xFFFF | 0xF800))       \
                                                                    == 0xD800)
#define UNICODE_WARN_ABOVE_31_BIT      UNICODE_WARN_PERL_EXTENDED
#define UNICODE_WARN_ILLEGAL_C9_INTERCHANGE                                   \
                                  (UNICODE_WARN_SURROGATE|UNICODE_WARN_SUPER)
#define UNICODE_WARN_ILLEGAL_INTERCHANGE                                      \
                   (UNICODE_WARN_ILLEGAL_C9_INTERCHANGE|UNICODE_WARN_NONCHAR)
#define UNICODE_WARN_NONCHAR           0x0002	
#define UNICODE_WARN_PERL_EXTENDED     0x0008	
#define UNICODE_WARN_SUPER             0x0004	
#define UNICODE_WARN_SURROGATE         0x0001	
#define UNISKIP(uv)   UVCHR_SKIP(uv)
#define UNI_IS_INVARIANT(cp)   UVCHR_IS_INVARIANT(cp)
#define UNI_TO_NATIVE(ch)        ((UV) (ch))
#    define USE_UTF8_IN_NAMES (!IN_BYTES)
#define UTF8SKIP(s)  PL_utf8skip[*(const U8*)(s)]
#define UTF8_ACCUMULATE(old, new) (__ASSERT_(FITS_IN_8_BITS(new))              \
                                   ((old) << UTF_ACCUMULATION_SHIFT)           \
                                   | ((NATIVE_UTF8_TO_I8((U8)new))             \
                                       & UTF_CONTINUATION_MASK))
#define UTF8_ALLOW_ANY ( UTF8_ALLOW_CONTINUATION                                \
                        |UTF8_ALLOW_NON_CONTINUATION                            \
                        |UTF8_ALLOW_SHORT                                       \
                        |UTF8_ALLOW_LONG                                        \
                        |UTF8_ALLOW_OVERFLOW)
#define UTF8_ALLOW_ANYUV   0
#define UTF8_ALLOW_DEFAULT UTF8_ALLOW_ANYUV
#define UTF8_ALLOW_FE_FF 0
#define UTF8_ALLOW_FFFF 0
#define UTF8_ALLOW_LONG                 0x0010
#define UTF8_ALLOW_LONG_AND_ITS_VALUE   (UTF8_ALLOW_LONG|0x0020)
#define UTF8_ALLOW_OVERFLOW             0x0080
#define UTF8_ALLOW_SURROGATE 0
#define UTF8_DISALLOW_ABOVE_31_BIT      UTF8_DISALLOW_PERL_EXTENDED
#define UTF8_DISALLOW_FE_FF             UTF8_DISALLOW_PERL_EXTENDED
#define UTF8_DISALLOW_ILLEGAL_C9_INTERCHANGE                                    \
                                 (UTF8_DISALLOW_SUPER|UTF8_DISALLOW_SURROGATE)
#define UTF8_DISALLOW_ILLEGAL_INTERCHANGE                                       \
                  (UTF8_DISALLOW_ILLEGAL_C9_INTERCHANGE|UTF8_DISALLOW_NONCHAR)
#define UTF8_DISALLOW_NONCHAR           0x0400
#define UTF8_DISALLOW_PERL_EXTENDED     0x4000
#define UTF8_EIGHT_BIT_HI(c) (__ASSERT_(FITS_IN_8_BITS(c))                    \
                             ( __BASE_TWO_BYTE_HI(c, NATIVE_TO_LATIN1)))
#define UTF8_EIGHT_BIT_LO(c) (__ASSERT_(FITS_IN_8_BITS(c))                    \
                             (__BASE_TWO_BYTE_LO(c, NATIVE_TO_LATIN1)))
#define UTF8_GOT_ABOVE_31_BIT           UTF8_GOT_PERL_EXTENDED
#define UTF8_GOT_EMPTY                  UTF8_ALLOW_EMPTY
#define UTF8_GOT_LONG                   UTF8_ALLOW_LONG
#define UTF8_GOT_NONCHAR                UTF8_DISALLOW_NONCHAR
#define UTF8_GOT_OVERFLOW               UTF8_ALLOW_OVERFLOW
#define UTF8_GOT_PERL_EXTENDED          UTF8_DISALLOW_PERL_EXTENDED
#define UTF8_IS_ABOVE_LATIN1(c)     (__ASSERT_(FITS_IN_8_BITS(c))           \
                                     ((U8)((c) | 0)) >= 0xc4)
#define UTF8_IS_ABOVE_LATIN1_START(c)     UTF8_IS_ABOVE_LATIN1(c)
#define UTF8_IS_CONTINUATION(c)     (__ASSERT_(FITS_IN_8_BITS(c))           \
     (((U8)((c) | 0)) & UTF_IS_CONTINUATION_MASK) == UTF_CONTINUATION_MARK)
#define UTF8_IS_CONTINUED(c)  (__ASSERT_(FITS_IN_8_BITS(c))                 \
                               ((U8)((c) | 0)) &  UTF_CONTINUATION_MARK)
#define UTF8_IS_DOWNGRADEABLE_START(c)	(__ASSERT_(FITS_IN_8_BITS(c))       \
                                         (((U8)((c) | 0)) & 0xfe) == 0xc2)
#define UTF8_IS_INVARIANT(c)	UVCHR_IS_INVARIANT((c) | 0)
#define UTF8_IS_NEXT_CHAR_DOWNGRADEABLE(s, e)                                 \
                                       (   UTF8_IS_DOWNGRADEABLE_START(*(s))  \
                                        && ( (e) - (s) > 1)                   \
                                        && UTF8_IS_CONTINUATION(*((s)+1)))
#define UTF8_IS_NONCHAR(s, e)                                                  \
                UTF8_IS_NONCHAR_GIVEN_THAT_NON_SUPER_AND_GE_PROBLEMATIC(s, e)
#define UTF8_IS_NONCHAR_GIVEN_THAT_NON_SUPER_AND_GE_PROBLEMATIC(s, e)          \
                                            cBOOL(is_NONCHAR_utf8_safe(s,e))
#define UTF8_IS_REPLACEMENT(s, send) is_REPLACEMENT_utf8_safe(s,send)
#define UTF8_IS_START(c)      (__ASSERT_(FITS_IN_8_BITS(c))                 \
                               ((U8)((c) | 0)) >= 0xc2)
#   define UTF8_IS_SUPER(s, e)                                              \
                  ((    LIKELY((e) > (s) + 4)                               \
                    &&      NATIVE_UTF8_TO_I8(*(s)) >= 0xF9                 \
                    && (    NATIVE_UTF8_TO_I8(*(s)) >  0xF9                 \
                        || (NATIVE_UTF8_TO_I8(*((s) + 1)) >= 0xA2))         \
                    &&  LIKELY((s) + UTF8SKIP(s) <= (e)))                   \
                    ? _is_utf8_char_helper(s, s + UTF8SKIP(s), 0) : 0)
#define UTF8_IS_SURROGATE(s, e)      is_SURROGATE_utf8_safe(s, e)
#define UTF8_MAXBYTES 13
#define UTF8_MAXLEN UTF8_MAXBYTES
#define UTF8_MAX_FOLD_CHAR_EXPAND 3
#define UTF8_SAFE_SKIP(s, e)  (__ASSERT_((e) >= (s))                \
                              ((e) - (s)) <= 0                      \
                               ? 0                                  \
                               : MIN(((e) - (s)), UTF8_SKIP(s)))
#define UTF8_SKIP(s) UTF8SKIP(s)
#define UTF8_TWO_BYTE_HI(c)                                                    \
       (__ASSERT_((sizeof(c) ==  1)                                            \
                  || !(((WIDEST_UTYPE)(c)) & ~MAX_UTF8_TWO_BYTE))              \
        (__BASE_TWO_BYTE_HI(c, NATIVE_TO_UNI)))
#define UTF8_TWO_BYTE_HI_nocast(c)  __BASE_TWO_BYTE_HI(c, NATIVE_TO_UNI)
#define UTF8_TWO_BYTE_LO(c)                                                    \
       (__ASSERT_((sizeof(c) ==  1)                                            \
                  || !(((WIDEST_UTYPE)(c)) & ~MAX_UTF8_TWO_BYTE))              \
        (__BASE_TWO_BYTE_LO(c, NATIVE_TO_UNI)))
#define UTF8_TWO_BYTE_LO_nocast(c)  __BASE_TWO_BYTE_LO(c, NATIVE_TO_UNI)
#define UTF8_WARN_ABOVE_31_BIT          UTF8_WARN_PERL_EXTENDED
#define UTF8_WARN_FE_FF                 UTF8_WARN_PERL_EXTENDED
#define UTF8_WARN_ILLEGAL_C9_INTERCHANGE (UTF8_WARN_SUPER|UTF8_WARN_SURROGATE)
#define UTF8_WARN_ILLEGAL_INTERCHANGE \
                          (UTF8_WARN_ILLEGAL_C9_INTERCHANGE|UTF8_WARN_NONCHAR)
#define UTF8_WARN_NONCHAR               0x0800
#define UTF8_WARN_PERL_EXTENDED         0x8000
#define UTF_CONTINUATION_MASK  ((U8) ((1U << UTF_ACCUMULATION_SHIFT) - 1))
#define UTF_IS_CONTINUATION_MASK    0xC0
#define UTF_START_MARK(len) (((len) >  7) ? 0xFF : (0xFF & (0xFE << (7-(len)))))
#define UTF_START_MASK(len) (((len) >= 7) ? 0x00 : (0x1F >> ((len)-2)))
#define UTF_TO_NATIVE(ch)        I8_TO_NATIVE_UTF8(ch)
#define UVCHR_IS_INVARIANT(cp)      OFFUNI_IS_INVARIANT(cp)
#define UVCHR_SKIP(uv) ( UVCHR_IS_INVARIANT(uv) ? 1 : __BASE_UNI_SKIP(uv))
#define _UTF8_NO_CONFIDENCE_IN_CURLEN   0x20000  
#define __BASE_TWO_BYTE_HI(c, translate_function)                               \
           (__ASSERT_(! UVCHR_IS_INVARIANT(c))                                  \
            I8_TO_NATIVE_UTF8((translate_function(c) >> UTF_ACCUMULATION_SHIFT) \
                              | UTF_START_MARK(2)))
#define __BASE_TWO_BYTE_LO(c, translate_function)                               \
             (__ASSERT_(! UVCHR_IS_INVARIANT(c))                                \
              I8_TO_NATIVE_UTF8((translate_function(c) & UTF_CONTINUATION_MASK) \
                                 | UTF_CONTINUATION_MARK))
#   define __BASE_UNI_SKIP(uv) (__COMMON_UNI_SKIP(uv)                       \
     (UV) (uv) < ((UV) 1U << (6 * UTF_ACCUMULATION_SHIFT)) ? 7 : UTF8_MAXBYTES)
#define __COMMON_UNI_SKIP(uv)                                               \
          (UV) (uv) < (32 * (1U << (    UTF_ACCUMULATION_SHIFT))) ? 2 :     \
          (UV) (uv) < (16 * (1U << (2 * UTF_ACCUMULATION_SHIFT))) ? 3 :     \
          (UV) (uv) < ( 8 * (1U << (3 * UTF_ACCUMULATION_SHIFT))) ? 4 :     \
          (UV) (uv) < ( 4 * (1U << (4 * UTF_ACCUMULATION_SHIFT))) ? 5 :     \
          (UV) (uv) < ( 2 * (1U << (5 * UTF_ACCUMULATION_SHIFT))) ? 6 :
#define bytes_from_utf8(s, lenp, is_utf8p)                                  \
                            bytes_from_utf8_loc(s, lenp, is_utf8p, 0)
#define foldEQ_utf8(s1, pe1, l1, u1, s2, pe2, l2, u2) \
		    foldEQ_utf8_flags(s1, pe1, l1, u1, s2, pe2, l2, u2, 0)
#define ibcmp_utf8(s1, pe1, l1, u1, s2, pe2, l2, u2) \
		    cBOOL(! foldEQ_utf8(s1, pe1, l1, u1, s2, pe2, l2, u2))
#define isALNUM_lazy_if(p,UTF)                                              \
            _is_utf8_FOO(_CC_IDFIRST, (const U8 *) p, "isALNUM_lazy_if",    \
                         "isWORDCHAR_lazy_if_safe",                         \
                         cBOOL(UTF && ! IN_BYTES), 0, "__FILE__","__LINE__")
#define isIDFIRST_lazy_if(p,UTF)                                            \
            _is_utf8_FOO(_CC_IDFIRST, (const U8 *) p, "isIDFIRST_lazy_if",  \
                         "isIDFIRST_lazy_if_safe",                          \
                         cBOOL(UTF && ! IN_BYTES), 0, "__FILE__","__LINE__")
#define isIDFIRST_lazy_if_safe(p, e, UTF)                                   \
                   ((IN_BYTES || !UTF)                                      \
                     ? isIDFIRST(*(p))                                      \
                     : isIDFIRST_utf8_safe(p, e))
#define isUTF8_CHAR_flags(s, e, flags)                                      \
    (UNLIKELY((e) <= (s))                                                   \
    ? 0                                                                     \
    : (UTF8_IS_INVARIANT(*s))                                               \
      ? 1                                                                   \
      : UNLIKELY(((e) - (s)) < UTF8SKIP(s))                                 \
        ? 0                                                                 \
        : _is_utf8_char_helper(s, e, flags))
#define isUTF8_POSSIBLY_PROBLEMATIC(c) (__ASSERT_(FITS_IN_8_BITS(c))        \
                                        (U8) c >= 0xED)
#define isWORDCHAR_lazy_if(p,UTF)                                           \
            _is_utf8_FOO(_CC_IDFIRST, (const U8 *) p, "isWORDCHAR_lazy_if", \
                         "isWORDCHAR_lazy_if_safe",                         \
                         cBOOL(UTF && ! IN_BYTES), 0, "__FILE__","__LINE__")
#define isWORDCHAR_lazy_if_safe(p, e, UTF)                                  \
                   ((IN_BYTES || !UTF)                                      \
                     ? isWORDCHAR(*(p))                                     \
                     : isWORDCHAR_utf8_safe((U8 *) p, (U8 *) e))
#define is_ascii_string(s, len)     is_utf8_invariant_string(s, len)
#define is_invariant_string(s, len) is_utf8_invariant_string(s, len)
#define is_utf8_char_buf(buf, buf_end) isUTF8_CHAR(buf, buf_end)
#define to_uni_fold(c, p, lenp) _to_uni_fold_flags(c, p, lenp, FOLD_FLAGS_FULL)
#define to_utf8_fold(s, r, lenr)                                                \
    _to_utf8_fold_flags (s, NULL, r, lenr, FOLD_FLAGS_FULL, "__FILE__", "__LINE__")
#define to_utf8_lower(s, r, lenr)                                               \
                  _to_utf8_lower_flags(s, NULL, r ,lenr, 0, "__FILE__", "__LINE__")
#define to_utf8_title(s, r, lenr)                                               \
                  _to_utf8_title_flags(s, NULL, r, lenr ,0, "__FILE__", "__LINE__")
#define to_utf8_upper(s, r, lenr)                                               \
                  _to_utf8_upper_flags(s, NULL, r, lenr, 0, "__FILE__", "__LINE__")
#define utf8_to_uvchr_buf(s, e, lenp)                                          \
                                (__ASSERT_((U8*) (e) > (U8*) (s))              \
                                 utf8n_to_uvchr(s, (U8*)(e) - (U8*)(s), lenp,  \
                                    ckWARN_d(WARN_UTF8) ? 0 : UTF8_ALLOW_ANY))
#define utf8n_to_uvchr(s, len, lenp, flags)                                    \
                                utf8n_to_uvchr_error(s, len, lenp, flags, 0)
#define utf8n_to_uvchr_error(s, len, lenp, flags, errors)                      \
                        utf8n_to_uvchr_msgs(s, len, lenp, flags, errors, 0)
#define uvchr_to_utf8(a,b)          uvchr_to_utf8_flags(a,b,0)
#define uvchr_to_utf8_flags(d,uv,flags)                                        \
                                    uvchr_to_utf8_flags_msgs(d,uv,flags, 0)
#define uvchr_to_utf8_flags_msgs(d,uv,flags,msgs)                              \
                uvoffuni_to_utf8_flags_msgs(d,NATIVE_TO_UNI(uv),flags, msgs)
#define uvoffuni_to_utf8_flags(d,uv,flags)                                     \
                               uvoffuni_to_utf8_flags_msgs(d, uv, flags, 0)
#define _IS_UTF8_CHAR_HIGHEST_START_BYTE 0xF9
#define is_C9_STRICT_UTF8_CHAR_utf8_no_length_checks(s)             \
( ( 0x80 == ((const U8*)s)[0] || ( 0x8A <= ((const U8*)s)[0] && ((const U8*)s)[0] <= 0x90 ) || ( 0x9A <= ((const U8*)s)[0] && ((const U8*)s)[0] <= 0xA0 ) || ( 0xAA <= ((const U8*)s)[0] && ((const U8*)s)[0] <= 0xAC ) || ( 0xAE <= ((const U8*)s)[0] && ((const U8*)s)[0] <= 0xB6 ) ) ?\
    ( LIKELY( ( 0x41 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x6A ) || ( ((const U8*)s)[1] & 0xFC ) == 0x70 ) ? 2 : 0 )\
: ( ( ( ((const U8*)s)[0] & 0xFC ) == 0xB8 ) || ((const U8*)s)[0] == 0xBC || ( ( ((const U8*)s)[0] & 0xFE ) == 0xBE ) || ( ( ((const U8*)s)[0] & 0xEE ) == 0xCA ) || ( ( ((const U8*)s)[0] & 0xFC ) == 0xCC ) ) ?\
    ( LIKELY( ( ( 0x41 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x6A ) || ( ((const U8*)s)[1] & 0xFC ) == 0x70 ) && ( ( 0x41 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x6A ) || ( ((const U8*)s)[2] & 0xFC ) == 0x70 ) ) ? 3 : 0 )\
: ( 0xDC == ((const U8*)s)[0] ) ?                                                 \
    ( LIKELY( ( ( ( 0x57 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x6A ) || ( ((const U8*)s)[1] & 0xFC ) == 0x70 ) && ( ( 0x41 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x6A ) || ( ((const U8*)s)[2] & 0xFC ) == 0x70 ) ) && ( ( 0x41 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x6A ) || ( ((const U8*)s)[3] & 0xFC ) == 0x70 ) ) ? 4 : 0 )\
: ( 0xDD == ((const U8*)s)[0] ) ?                                                 \
    ( LIKELY( ( ( ( 0x41 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x64 ) || ( 0x67 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x6A ) || ( ((const U8*)s)[1] & 0xFC ) == 0x70 ) && ( ( 0x41 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x6A ) || ( ((const U8*)s)[2] & 0xFC ) == 0x70 ) ) && ( ( 0x41 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x6A ) || ( ((const U8*)s)[3] & 0xFC ) == 0x70 ) ) ? 4 : 0 )\
: ( ( ((const U8*)s)[0] & 0xFE ) == 0xDE || 0xE1 == ((const U8*)s)[0] || ( 0xEA <= ((const U8*)s)[0] && ((const U8*)s)[0] <= 0xEC ) ) ?\
    ( LIKELY( ( ( ( 0x41 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x6A ) || ( ((const U8*)s)[1] & 0xFC ) == 0x70 ) && ( ( 0x41 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x6A ) || ( ((const U8*)s)[2] & 0xFC ) == 0x70 ) ) && ( ( 0x41 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x6A ) || ( ((const U8*)s)[3] & 0xFC ) == 0x70 ) ) ? 4 : 0 )\
: ( 0xED == ((const U8*)s)[0] ) ?                                                 \
    ( LIKELY( ( ( ( ( 0x49 == ((const U8*)s)[1] || 0x4A == ((const U8*)s)[1] ) || ( 0x51 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x6A ) || ( ((const U8*)s)[1] & 0xFC ) == 0x70 ) && ( ( 0x41 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x6A ) || ( ((const U8*)s)[2] & 0xFC ) == 0x70 ) ) && ( ( 0x41 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x6A ) || ( ((const U8*)s)[3] & 0xFC ) == 0x70 ) ) && ( ( 0x41 <= ((const U8*)s)[4] && ((const U8*)s)[4] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[4] && ((const U8*)s)[4] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[4] && ((const U8*)s)[4] <= 0x6A ) || ( ((const U8*)s)[4] & 0xFC ) == 0x70 ) ) ? 5 : 0 )\
: LIKELY( ( ( ( ( 0xEE == ((const U8*)s)[0] ) && ( 0x41 == ((const U8*)s)[1] || 0x42 == ((const U8*)s)[1] ) ) && ( ( 0x41 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x6A ) || ( ((const U8*)s)[2] & 0xFC ) == 0x70 ) ) && ( ( 0x41 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x6A ) || ( ((const U8*)s)[3] & 0xFC ) == 0x70 ) ) && ( ( 0x41 <= ((const U8*)s)[4] && ((const U8*)s)[4] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[4] && ((const U8*)s)[4] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[4] && ((const U8*)s)[4] <= 0x6A ) || ( ((const U8*)s)[4] & 0xFC ) == 0x70 ) ) ? 5 : 0 )
#define is_C9_STRICT_UTF8_CHAR_utf8_no_length_checks_part0(s)               \
( ( ( 0x41 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x59 ) || 0x5F == ((const U8*)s)[1] || ( 0x62 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x6A ) || ( 0x70 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x72 ) ) ? 2 : 0 )
#define is_C9_STRICT_UTF8_CHAR_utf8_no_length_checks_part1(s)               \
( ( ((const U8*)s)[0] == 0xB7 || ( ( ((const U8*)s)[0] & 0xFE ) == 0xB8 ) || ( ( ((const U8*)s)[0] & 0xFC ) == 0xBC ) || ( ( ((const U8*)s)[0] & 0xEE ) == 0xCA ) || ( ( ((const U8*)s)[0] & 0xFC ) == 0xCC ) ) ?\
    ( ( ( ( 0x41 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x59 ) || 0x5F == ((const U8*)s)[1] || ( 0x62 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x6A ) || ( 0x70 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x72 ) ) && ( ( 0x41 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x59 ) || 0x5F == ((const U8*)s)[2] || ( 0x62 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x6A ) || ( 0x70 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x72 ) ) ) ? 3 : 0 )\
: ( 0xDC == ((const U8*)s)[0] ) ?                                           \
    ( ( ( ( ( 0x57 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x59 ) || 0x5F == ((const U8*)s)[1] || ( 0x62 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x6A ) || ( 0x70 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x72 ) ) && ( ( 0x41 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x59 ) || 0x5F == ((const U8*)s)[2] || ( 0x62 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x6A ) || ( 0x70 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x72 ) ) ) && ( ( 0x41 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x59 ) || 0x5F == ((const U8*)s)[3] || ( 0x62 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x6A ) || ( 0x70 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x72 ) ) ) ? 4 : 0 )\
: ( 0xDD == ((const U8*)s)[0] ) ?                                           \
    ( ( ( ( ( 0x41 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x59 ) || 0x5F == ((const U8*)s)[1] || ( ((const U8*)s)[1] & 0xFE ) == 0x62 || ( 0x66 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x6A ) || ( 0x70 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x72 ) ) && ( ( 0x41 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x59 ) || 0x5F == ((const U8*)s)[2] || ( 0x62 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x6A ) || ( 0x70 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x72 ) ) ) && ( ( 0x41 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x59 ) || 0x5F == ((const U8*)s)[3] || ( 0x62 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x6A ) || ( 0x70 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x72 ) ) ) ? 4 : 0 )\
: ( ( ((const U8*)s)[0] & 0xFE ) == 0xDE || 0xE1 == ((const U8*)s)[0] || ( 0xEA <= ((const U8*)s)[0] && ((const U8*)s)[0] <= 0xEC ) ) ?\
    ( ( ( ( ( 0x41 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x59 ) || 0x5F == ((const U8*)s)[1] || ( 0x62 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x6A ) || ( 0x70 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x72 ) ) && ( ( 0x41 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x59 ) || 0x5F == ((const U8*)s)[2] || ( 0x62 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x6A ) || ( 0x70 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x72 ) ) ) && ( ( 0x41 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x59 ) || 0x5F == ((const U8*)s)[3] || ( 0x62 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x6A ) || ( 0x70 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x72 ) ) ) ? 4 : 0 )\
: ( 0xED == ((const U8*)s)[0] ) ?                                           \
    ( ( ( ( ( ( 0x49 == ((const U8*)s)[1] || 0x4A == ((const U8*)s)[1] ) || ( 0x51 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x59 ) || 0x5F == ((const U8*)s)[1] || ( 0x62 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x6A ) || ( 0x70 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x72 ) ) && ( ( 0x41 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x59 ) || 0x5F == ((const U8*)s)[2] || ( 0x62 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x6A ) || ( 0x70 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x72 ) ) ) && ( ( 0x41 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x59 ) || 0x5F == ((const U8*)s)[3] || ( 0x62 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x6A ) || ( 0x70 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x72 ) ) ) && ( ( 0x41 <= ((const U8*)s)[4] && ((const U8*)s)[4] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[4] && ((const U8*)s)[4] <= 0x59 ) || 0x5F == ((const U8*)s)[4] || ( 0x62 <= ((const U8*)s)[4] && ((const U8*)s)[4] <= 0x6A ) || ( 0x70 <= ((const U8*)s)[4] && ((const U8*)s)[4] <= 0x72 ) ) ) ? 5 : 0 )\
: ( ( ( ( ( 0xEE == ((const U8*)s)[0] ) && ( 0x41 == ((const U8*)s)[1] || 0x42 == ((const U8*)s)[1] ) ) && ( ( 0x41 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x59 ) || 0x5F == ((const U8*)s)[2] || ( 0x62 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x6A ) || ( 0x70 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x72 ) ) ) && ( ( 0x41 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x59 ) || 0x5F == ((const U8*)s)[3] || ( 0x62 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x6A ) || ( 0x70 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x72 ) ) ) && ( ( 0x41 <= ((const U8*)s)[4] && ((const U8*)s)[4] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[4] && ((const U8*)s)[4] <= 0x59 ) || 0x5F == ((const U8*)s)[4] || ( 0x62 <= ((const U8*)s)[4] && ((const U8*)s)[4] <= 0x6A ) || ( 0x70 <= ((const U8*)s)[4] && ((const U8*)s)[4] <= 0x72 ) ) ) ? 5 : 0 )
#define is_STRICT_UTF8_CHAR_utf8_no_length_checks(s)                        \
( ( 0x80 == ((const U8*)s)[0] || ( 0x8A <= ((const U8*)s)[0] && ((const U8*)s)[0] <= 0x90 ) || ( 0x9A <= ((const U8*)s)[0] && ((const U8*)s)[0] <= 0xA0 ) || ( 0xAA <= ((const U8*)s)[0] && ((const U8*)s)[0] <= 0xAC ) || ( 0xAE <= ((const U8*)s)[0] && ((const U8*)s)[0] <= 0xB6 ) ) ?\
    ( LIKELY( ( 0x41 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x6A ) || ( ((const U8*)s)[1] & 0xFC ) == 0x70 ) ? 2 : 0 )\
: ( ( ( ((const U8*)s)[0] & 0xFC ) == 0xB8 ) || ((const U8*)s)[0] == 0xBC || ( ( ((const U8*)s)[0] & 0xFE ) == 0xBE ) || ( ( ((const U8*)s)[0] & 0xEE ) == 0xCA ) || ( ( ((const U8*)s)[0] & 0xFC ) == 0xCC ) ) ?\
    ( LIKELY( ( ( 0x41 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x6A ) || ( ((const U8*)s)[1] & 0xFC ) == 0x70 ) && ( ( 0x41 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x6A ) || ( ((const U8*)s)[2] & 0xFC ) == 0x70 ) ) ? 3 : 0 )\
: ( 0xDC == ((const U8*)s)[0] ) ?                                                 \
    ( LIKELY( ( ( ( 0x57 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x6A ) || ( ((const U8*)s)[1] & 0xFC ) == 0x70 ) && ( ( 0x41 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x6A ) || ( ((const U8*)s)[2] & 0xFC ) == 0x70 ) ) && ( ( 0x41 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x6A ) || ( ((const U8*)s)[3] & 0xFC ) == 0x70 ) ) ? 4 : 0 )\
: ( 0xDD == ((const U8*)s)[0] ) ?                                                 \
    ( ( ( 0x41 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x64 ) || ( 0x67 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x6A ) || ( 0x70 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x72 ) ) ?\
	( LIKELY( ( ( 0x41 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x6A ) || ( ((const U8*)s)[2] & 0xFC ) == 0x70 ) && ( ( 0x41 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x6A ) || ( ((const U8*)s)[3] & 0xFC ) == 0x70 ) ) ? 4 : 0 )\
    : ( 0x73 == ((const U8*)s)[1] ) ?                                             \
	( ( ( 0x41 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x54 ) || ( 0x57 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x6A ) || ( 0x70 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x72 ) ) ?\
	    ( LIKELY( ( 0x41 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x6A ) || ( ((const U8*)s)[3] & 0xFC ) == 0x70 ) ? 4 : 0 )\
	: ( 0x55 == ((const U8*)s)[2] ) ?                                         \
	    ( LIKELY( ( 0x41 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x56 ) ) ? 4 : 0 )\
	: ( 0x56 == ((const U8*)s)[2] ) ?                                         \
	    ( LIKELY( ( 0x57 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x6A ) || ( ((const U8*)s)[3] & 0xFC ) == 0x70 ) ? 4 : 0 )\
	: LIKELY( ( 0x73 == ((const U8*)s)[2] ) && ( ( 0x41 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x6A ) || ( ((const U8*)s)[3] & 0xFE ) == 0x70 ) ) ? 4 : 0 )\
    : 0 )                                                                   \
: ( 0xDE == ((const U8*)s)[0] || 0xE1 == ((const U8*)s)[0] || 0xEB == ((const U8*)s)[0] ) ?   \
    ( LIKELY( ( ( ( 0x41 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x6A ) || ( ((const U8*)s)[1] & 0xFC ) == 0x70 ) && ( ( 0x41 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x6A ) || ( ((const U8*)s)[2] & 0xFC ) == 0x70 ) ) && ( ( 0x41 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x6A ) || ( ((const U8*)s)[3] & 0xFC ) == 0x70 ) ) ? 4 : 0 )\
: ( 0xDF == ((const U8*)s)[0] || 0xEA == ((const U8*)s)[0] || 0xEC == ((const U8*)s)[0] ) ? is_STRICT_UTF8_CHAR_utf8_no_length_checks_part0(s) : is_STRICT_UTF8_CHAR_utf8_no_length_checks_part1(s) )
#define is_STRICT_UTF8_CHAR_utf8_no_length_checks_part0(s)                  \
( ( ( 0x41 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x6A ) || ( 0x70 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x72 ) ) ?\
	( LIKELY( ( ( 0x41 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x6A ) || ( ((const U8*)s)[2] & 0xFC ) == 0x70 ) && ( ( 0x41 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x6A ) || ( ((const U8*)s)[3] & 0xFC ) == 0x70 ) ) ? 4 : 0 )\
    : ( 0x73 == ((const U8*)s)[1] ) ?                                             \
	( ( ( 0x41 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x6A ) || ( 0x70 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x72 ) ) ?\
	    ( LIKELY( ( 0x41 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x6A ) || ( ((const U8*)s)[3] & 0xFC ) == 0x70 ) ? 4 : 0 )\
	: LIKELY( ( 0x73 == ((const U8*)s)[2] ) && ( ( 0x41 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x6A ) || ( ((const U8*)s)[3] & 0xFE ) == 0x70 ) ) ? 4 : 0 )\
    : 0 )
#define is_STRICT_UTF8_CHAR_utf8_no_length_checks_part1(s)                  \
( ( 0xED == ((const U8*)s)[0] ) ?                                                 \
    ( ( ( ( ((const U8*)s)[1] & 0xEF ) == 0x49 ) || ( ( ((const U8*)s)[1] & 0xF9 ) == 0x51 ) || ((const U8*)s)[1] == 0x63 || ( ( ((const U8*)s)[1] & 0xFD ) == 0x65 ) || ((const U8*)s)[1] == 0x69 || ( ( ((const U8*)s)[1] & 0xFD ) == 0x70 ) ) ?\
	( LIKELY( ( ( ( 0x41 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x6A ) || ( ((const U8*)s)[2] & 0xFC ) == 0x70 ) && ( ( 0x41 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x6A ) || ( ((const U8*)s)[3] & 0xFC ) == 0x70 ) ) && ( ( 0x41 <= ((const U8*)s)[4] && ((const U8*)s)[4] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[4] && ((const U8*)s)[4] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[4] && ((const U8*)s)[4] <= 0x6A ) || ( ((const U8*)s)[4] & 0xFC ) == 0x70 ) ) ? 5 : 0 )\
    : ( ((const U8*)s)[1] == 0x4A || ((const U8*)s)[1] == 0x52 || ( ( ((const U8*)s)[1] & 0xFD ) == 0x54 ) || ((const U8*)s)[1] == 0x58 || ((const U8*)s)[1] == 0x62 || ( ( ((const U8*)s)[1] & 0xFD ) == 0x64 ) || ( ( ((const U8*)s)[1] & 0xFD ) == 0x68 ) || ( ( ((const U8*)s)[1] & 0xFD ) == 0x71 ) ) ?\
	( ( ( 0x41 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x6A ) || ( 0x70 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x72 ) ) ?\
	    ( LIKELY( ( ( 0x41 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x6A ) || ( ((const U8*)s)[3] & 0xFC ) == 0x70 ) && ( ( 0x41 <= ((const U8*)s)[4] && ((const U8*)s)[4] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[4] && ((const U8*)s)[4] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[4] && ((const U8*)s)[4] <= 0x6A ) || ( ((const U8*)s)[4] & 0xFC ) == 0x70 ) ) ? 5 : 0 )\
	: ( 0x73 == ((const U8*)s)[2] ) ?                                         \
	    ( ( ( 0x41 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x6A ) || ( 0x70 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x72 ) ) ?\
		( LIKELY( ( 0x41 <= ((const U8*)s)[4] && ((const U8*)s)[4] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[4] && ((const U8*)s)[4] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[4] && ((const U8*)s)[4] <= 0x6A ) || ( ((const U8*)s)[4] & 0xFC ) == 0x70 ) ? 5 : 0 )\
	    : LIKELY( ( 0x73 == ((const U8*)s)[3] ) && ( ( 0x41 <= ((const U8*)s)[4] && ((const U8*)s)[4] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[4] && ((const U8*)s)[4] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[4] && ((const U8*)s)[4] <= 0x6A ) || ( ((const U8*)s)[4] & 0xFE ) == 0x70 ) ) ? 5 : 0 )\
	: 0 )                                                               \
    : 0 )                                                                   \
: ( 0xEE == ((const U8*)s)[0] ) ?                                                 \
    ( ( 0x41 == ((const U8*)s)[1] ) ?                                             \
	( LIKELY( ( ( ( 0x41 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x6A ) || ( ((const U8*)s)[2] & 0xFC ) == 0x70 ) && ( ( 0x41 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x6A ) || ( ((const U8*)s)[3] & 0xFC ) == 0x70 ) ) && ( ( 0x41 <= ((const U8*)s)[4] && ((const U8*)s)[4] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[4] && ((const U8*)s)[4] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[4] && ((const U8*)s)[4] <= 0x6A ) || ( ((const U8*)s)[4] & 0xFC ) == 0x70 ) ) ? 5 : 0 )\
    : ( 0x42 == ((const U8*)s)[1] ) ?                                             \
	( ( ( 0x41 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x6A ) || ( 0x70 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x72 ) ) ?\
	    ( LIKELY( ( ( 0x41 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x6A ) || ( ((const U8*)s)[3] & 0xFC ) == 0x70 ) && ( ( 0x41 <= ((const U8*)s)[4] && ((const U8*)s)[4] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[4] && ((const U8*)s)[4] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[4] && ((const U8*)s)[4] <= 0x6A ) || ( ((const U8*)s)[4] & 0xFC ) == 0x70 ) ) ? 5 : 0 )\
	: ( 0x73 == ((const U8*)s)[2] ) ?                                         \
	    ( ( ( 0x41 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x6A ) || ( 0x70 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x72 ) ) ?\
		( LIKELY( ( 0x41 <= ((const U8*)s)[4] && ((const U8*)s)[4] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[4] && ((const U8*)s)[4] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[4] && ((const U8*)s)[4] <= 0x6A ) || ( ((const U8*)s)[4] & 0xFC ) == 0x70 ) ? 5 : 0 )\
	    : LIKELY( ( 0x73 == ((const U8*)s)[3] ) && ( ( 0x41 <= ((const U8*)s)[4] && ((const U8*)s)[4] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[4] && ((const U8*)s)[4] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[4] && ((const U8*)s)[4] <= 0x6A ) || ( ((const U8*)s)[4] & 0xFE ) == 0x70 ) ) ? 5 : 0 )\
	: 0 )                                                               \
    : 0 )                                                                   \
: 0 )
#define is_STRICT_UTF8_CHAR_utf8_no_length_checks_part2(s)                  \
( ( ( ( ( 0x57 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x59 ) || 0x5F == ((const U8*)s)[1] || ( 0x62 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x6A ) || ( 0x70 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x72 ) ) && ( ( 0x41 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x59 ) || 0x5F == ((const U8*)s)[2] || ( 0x62 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x6A ) || ( 0x70 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x72 ) ) ) && ( ( 0x41 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x59 ) || 0x5F == ((const U8*)s)[3] || ( 0x62 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x6A ) || ( 0x70 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x72 ) ) ) ? 4 : 0 )
#define is_STRICT_UTF8_CHAR_utf8_no_length_checks_part3(s)                  \
( ( 0xDD == ((const U8*)s)[0] ) ?                                           \
    ( ( ( 0x41 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x59 ) || 0x5F == ((const U8*)s)[1] || ( ((const U8*)s)[1] & 0xFE ) == 0x62 || ( 0x66 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x6A ) || ( ((const U8*)s)[1] & 0xFE ) == 0x70 ) ?\
	( ( ( ( 0x41 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x59 ) || 0x5F == ((const U8*)s)[2] || ( 0x62 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x6A ) || ( 0x70 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x72 ) ) && ( ( 0x41 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x59 ) || 0x5F == ((const U8*)s)[3] || ( 0x62 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x6A ) || ( 0x70 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x72 ) ) ) ? 4 : 0 )\
    : ( 0x72 == ((const U8*)s)[1] ) ?                                       \
	( ( ( 0x41 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x54 ) || ( 0x57 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x59 ) || 0x5F == ((const U8*)s)[2] || ( 0x62 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x6A ) || ( ((const U8*)s)[2] & 0xFE ) == 0x70 ) ?\
	    ( ( ( 0x41 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x59 ) || 0x5F == ((const U8*)s)[3] || ( 0x62 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x6A ) || ( 0x70 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x72 ) ) ? 4 : 0 )\
	: ( 0x55 == ((const U8*)s)[2] ) ?                                   \
	    ( ( ( 0x41 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x56 ) ) ? 4 : 0 )\
	: ( 0x56 == ((const U8*)s)[2] ) ?                                   \
	    ( ( ( 0x57 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x59 ) || 0x5F == ((const U8*)s)[3] || ( 0x62 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x6A ) || ( 0x70 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x72 ) ) ? 4 : 0 )\
	: ( ( 0x72 == ((const U8*)s)[2] ) && ( ( 0x41 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x59 ) || 0x5F == ((const U8*)s)[3] || ( 0x62 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x6A ) || 0x70 == ((const U8*)s)[3] ) ) ? 4 : 0 )\
    : 0 )                                                                   \
: ( 0xDE == ((const U8*)s)[0] || 0xE1 == ((const U8*)s)[0] || 0xEB == ((const U8*)s)[0] ) ?\
    ( ( ( ( ( 0x41 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x59 ) || 0x5F == ((const U8*)s)[1] || ( 0x62 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x6A ) || ( 0x70 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x72 ) ) && ( ( 0x41 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x59 ) || 0x5F == ((const U8*)s)[2] || ( 0x62 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x6A ) || ( 0x70 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x72 ) ) ) && ( ( 0x41 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x59 ) || 0x5F == ((const U8*)s)[3] || ( 0x62 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x6A ) || ( 0x70 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x72 ) ) ) ? 4 : 0 )\
: ( 0xDF == ((const U8*)s)[0] || 0xEA == ((const U8*)s)[0] || 0xEC == ((const U8*)s)[0] ) ?\
    ( ( ( 0x41 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x59 ) || 0x5F == ((const U8*)s)[1] || ( 0x62 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x6A ) || ( ((const U8*)s)[1] & 0xFE ) == 0x70 ) ?\
	( ( ( ( 0x41 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x59 ) || 0x5F == ((const U8*)s)[2] || ( 0x62 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x6A ) || ( 0x70 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x72 ) ) && ( ( 0x41 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x59 ) || 0x5F == ((const U8*)s)[3] || ( 0x62 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x6A ) || ( 0x70 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x72 ) ) ) ? 4 : 0 )\
    : ( 0x72 == ((const U8*)s)[1] ) ?                                       \
	( ( ( 0x41 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x59 ) || 0x5F == ((const U8*)s)[2] || ( 0x62 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x6A ) || ( ((const U8*)s)[2] & 0xFE ) == 0x70 ) ?\
	    ( ( ( 0x41 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x59 ) || 0x5F == ((const U8*)s)[3] || ( 0x62 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x6A ) || ( 0x70 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x72 ) ) ? 4 : 0 )\
	: ( ( 0x72 == ((const U8*)s)[2] ) && ( ( 0x41 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x59 ) || 0x5F == ((const U8*)s)[3] || ( 0x62 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x6A ) || 0x70 == ((const U8*)s)[3] ) ) ? 4 : 0 )\
    : 0 )                                                                   \
: ( 0xED == ((const U8*)s)[0] ) ? is_STRICT_UTF8_CHAR_utf8_no_length_checks_part0(s) : is_STRICT_UTF8_CHAR_utf8_no_length_checks_part1(s) )
#define is_UTF8_CHAR_utf8_no_length_checks(s)                               \
( ( 0x80 == ((const U8*)s)[0] || ( 0x8A <= ((const U8*)s)[0] && ((const U8*)s)[0] <= 0x90 ) || ( 0x9A <= ((const U8*)s)[0] && ((const U8*)s)[0] <= 0xA0 ) || ( 0xAA <= ((const U8*)s)[0] && ((const U8*)s)[0] <= 0xAC ) || ( 0xAE <= ((const U8*)s)[0] && ((const U8*)s)[0] <= 0xB6 ) ) ?\
    ( LIKELY( ( 0x41 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x6A ) || ( ((const U8*)s)[1] & 0xFC ) == 0x70 ) ? 2 : 0 )\
: ( ( ( ((const U8*)s)[0] & 0xFC ) == 0xB8 ) || ((const U8*)s)[0] == 0xBC || ( ( ((const U8*)s)[0] & 0xFE ) == 0xBE ) || ( ( ((const U8*)s)[0] & 0xEE ) == 0xCA ) || ( ( ((const U8*)s)[0] & 0xFC ) == 0xCC ) ) ?\
    ( LIKELY( ( ( 0x41 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x6A ) || ( ((const U8*)s)[1] & 0xFC ) == 0x70 ) && ( ( 0x41 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x6A ) || ( ((const U8*)s)[2] & 0xFC ) == 0x70 ) ) ? 3 : 0 )\
: ( 0xDC == ((const U8*)s)[0] ) ?                                                 \
    ( LIKELY( ( ( ( 0x57 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x6A ) || ( ((const U8*)s)[1] & 0xFC ) == 0x70 ) && ( ( 0x41 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x6A ) || ( ((const U8*)s)[2] & 0xFC ) == 0x70 ) ) && ( ( 0x41 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x6A ) || ( ((const U8*)s)[3] & 0xFC ) == 0x70 ) ) ? 4 : 0 )\
: ( ( 0xDD <= ((const U8*)s)[0] && ((const U8*)s)[0] <= 0xDF ) || 0xE1 == ((const U8*)s)[0] || ( 0xEA <= ((const U8*)s)[0] && ((const U8*)s)[0] <= 0xEC ) ) ?\
    ( LIKELY( ( ( ( 0x41 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x6A ) || ( ((const U8*)s)[1] & 0xFC ) == 0x70 ) && ( ( 0x41 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x6A ) || ( ((const U8*)s)[2] & 0xFC ) == 0x70 ) ) && ( ( 0x41 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x6A ) || ( ((const U8*)s)[3] & 0xFC ) == 0x70 ) ) ? 4 : 0 )\
: ( 0xED == ((const U8*)s)[0] ) ?                                                 \
    ( LIKELY( ( ( ( ( 0x49 == ((const U8*)s)[1] || 0x4A == ((const U8*)s)[1] ) || ( 0x51 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x6A ) || ( ((const U8*)s)[1] & 0xFC ) == 0x70 ) && ( ( 0x41 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x6A ) || ( ((const U8*)s)[2] & 0xFC ) == 0x70 ) ) && ( ( 0x41 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x6A ) || ( ((const U8*)s)[3] & 0xFC ) == 0x70 ) ) && ( ( 0x41 <= ((const U8*)s)[4] && ((const U8*)s)[4] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[4] && ((const U8*)s)[4] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[4] && ((const U8*)s)[4] <= 0x6A ) || ( ((const U8*)s)[4] & 0xFC ) == 0x70 ) ) ? 5 : 0 )\
: ( ( ( ( ( 0xEE == ((const U8*)s)[0] ) && LIKELY( ( 0x41 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[1] && ((const U8*)s)[1] <= 0x6A ) || ( ((const U8*)s)[1] & 0xFC ) == 0x70 ) ) && LIKELY( ( 0x41 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[2] && ((const U8*)s)[2] <= 0x6A ) || ( ((const U8*)s)[2] & 0xFC ) == 0x70 ) ) && LIKELY( ( 0x41 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[3] && ((const U8*)s)[3] <= 0x6A ) || ( ((const U8*)s)[3] & 0xFC ) == 0x70 ) ) && LIKELY( ( 0x41 <= ((const U8*)s)[4] && ((const U8*)s)[4] <= 0x4A ) || ( 0x51 <= ((const U8*)s)[4] && ((const U8*)s)[4] <= 0x59 ) || ( 0x62 <= ((const U8*)s)[4] && ((const U8*)s)[4] <= 0x6A ) || ( ((const U8*)s)[4] & 0xFC ) == 0x70 ) ) ? 5 : 0 )
#define PERL_EBCDIC_TABLES_H_   1

#define is_FOLDS_TO_MULTI_utf8(s)                                           \
( ( 0x8A == ((const U8*)s)[0] ) ?                                           \
    ( ( 0x73 == ((const U8*)s)[1] ) ? 2 : 0 )                               \
: ( 0x8D == ((const U8*)s)[0] || 0x9C == ((const U8*)s)[0] || inRANGE(((const U8*)s)[0], 0xB3, 0xB4 ) ) ?\
    ( ( 0x57 == ((const U8*)s)[1] ) ? 2 : 0 )                               \
: ( 0x8E == ((const U8*)s)[0] ) ?                                           \
    ( ( 0x4A == ((const U8*)s)[1] ) ? 2 : 0 )                               \
: ( 0xB8 == ((const U8*)s)[0] ) ?                                           \
    ( ( ( 0x53 == ((const U8*)s)[1] ) && ( 0x48 == ((const U8*)s)[2] ) ) ? 3 : 0 )\
: ( 0xBF == ((const U8*)s)[0] ) ?                                           \
    ( ( 0x63 == ((const U8*)s)[1] ) ?                                       \
	( ( inRANGE(((const U8*)s)[2], 0x65, 0x69 ) || 0x72 == ((const U8*)s)[2] ) ? 3 : 0 )\
    : ( 0x69 == ((const U8*)s)[1] ) ?                                       \
	( ( 0x57 == ((const U8*)s)[2] || 0x59 == ((const U8*)s)[2] || 0x63 == ((const U8*)s)[2] || 0x65 == ((const U8*)s)[2] ) ? 3 : 0 )\
    : ( 0x70 == ((const U8*)s)[1] ) ?                                       \
	( ( inRANGE(((const U8*)s)[2], 0x41, 0x4A ) || inRANGE(((const U8*)s)[2], 0x51, 0x59 ) || inRANGE(((const U8*)s)[2], 0x62, 0x6A ) || inRANGE(((const U8*)s)[2], 0x70, 0x73 ) ) ? 3 : 0 )\
    : ( 0x71 == ((const U8*)s)[1] ) ?                                       \
	( ( inRANGE(((const U8*)s)[2], 0x41, 0x4A ) || inRANGE(((const U8*)s)[2], 0x51, 0x56 ) || 0x59 == ((const U8*)s)[2] || inRANGE(((const U8*)s)[2], 0x62, 0x63 ) || inRANGE(((const U8*)s)[2], 0x65, 0x66 ) || 0x70 == ((const U8*)s)[2] ) ? 3 : 0 )\
    : ( 0x72 == ((const U8*)s)[1] ) ?                                       \
	( ( inRANGE(((const U8*)s)[2], 0x43, 0x45 ) || inRANGE(((const U8*)s)[2], 0x47, 0x48 ) || 0x53 == ((const U8*)s)[2] || 0x59 == ((const U8*)s)[2] || 0x62 == ((const U8*)s)[2] || inRANGE(((const U8*)s)[2], 0x65, 0x66 ) ) ? 3 : 0 )\
    : ( ( 0x73 == ((const U8*)s)[1] ) && ( inRANGE(((const U8*)s)[2], 0x43, 0x45 ) || inRANGE(((const U8*)s)[2], 0x47, 0x48 ) || 0x59 == ((const U8*)s)[2] || inRANGE(((const U8*)s)[2], 0x62, 0x63 ) || inRANGE(((const U8*)s)[2], 0x65, 0x66 ) || 0x70 == ((const U8*)s)[2] ) ) ? 3 : 0 )\
: ( ( ( ( 0xDD == ((const U8*)s)[0] ) && ( 0x72 == ((const U8*)s)[1] ) ) && ( 0x67 == ((const U8*)s)[2] ) ) && ( inRANGE(((const U8*)s)[3], 0x41, 0x47 ) || inRANGE(((const U8*)s)[3], 0x62, 0x66 ) ) ) ? 4 : 0 )
#define is_HANGUL_ED_utf8_safe(s,e)                                         \
( ( ( ( ( ((e) - (s)) >= 3 ) && ( 0xED == ((const U8*)s)[0] ) ) && ( inRANGE(((const U8*)s)[1], 0x80, 0x9F ) ) ) && ( inRANGE(((const U8*)s)[2], 0x80, 0xBF ) ) ) ? 3 : 0 )
#define is_HORIZWS_cp_high(cp)                                              \
( 0x1680 == cp || ( 0x1680 < cp &&                                          \
( inRANGE(cp, 0x2000, 0x200A) || ( 0x200A < cp &&                           \
( 0x202F == cp || ( 0x202F < cp &&                                          \
( 0x205F == cp || 0x3000 == cp ) ) ) ) ) ) )
#define is_HORIZWS_high(s)                                                  \
( ( 0xBD == ((const U8*)s)[0] ) ?                                           \
    ( ( ( 0x62 == ((const U8*)s)[1] ) && ( 0x41 == ((const U8*)s)[2] ) ) ? 3 : 0 )\
: ( 0xCA == ((const U8*)s)[0] ) ?                                           \
    ( ( 0x41 == ((const U8*)s)[1] ) ?                                       \
	( ( inRANGE(((const U8*)s)[2], 0x41, 0x4A ) || 0x51 == ((const U8*)s)[2] ) ? 3 : 0 )\
    : ( 0x42 == ((const U8*)s)[1] ) ?                                       \
	( ( 0x56 == ((const U8*)s)[2] ) ? 3 : 0 )                           \
    : ( ( 0x43 == ((const U8*)s)[1] ) && ( 0x72 == ((const U8*)s)[2] ) ) ? 3 : 0 )\
: ( ( ( 0xCE == ((const U8*)s)[0] ) && ( 0x41 == ((const U8*)s)[1] ) ) && ( 0x41 == ((const U8*)s)[2] ) ) ? 3 : 0 )
#define is_LNBREAK_latin1_safe(s,e)                                         \
( ((e)-(s) > 1) ?                                                           \
    ( ( inRANGE(((const U8*)s)[0], 0x0B, 0x0C ) || 0x15 == ((const U8*)s)[0] || 0x25 == ((const U8*)s)[0] ) ? 1\
    : ( 0x0D == ((const U8*)s)[0] ) ?                                       \
	( ( 0x25 == ((const U8*)s)[1] ) ? 2 : 1 )                           \
    : 0 )                                                                   \
: ((e)-(s) > 0) ?                                                           \
    ( inRANGE(((const U8*)s)[0], 0x0B, 0x0D ) || 0x15 == ((const U8*)s)[0] || 0x25 == ((const U8*)s)[0] )\
: 0 )
#define is_LNBREAK_safe(s,e,is_utf8)                                        \
( ((e)-(s) > 2) ?                                                           \
    ( ( inRANGE(((const U8*)s)[0], 0x0B, 0x0C ) || 0x15 == ((const U8*)s)[0] || 0x25 == ((const U8*)s)[0] ) ? 1\
    : ( 0x0D == ((const U8*)s)[0] ) ?                                       \
	( ( 0x25 == ((const U8*)s)[1] ) ? 2 : 1 )                           \
    : ( ( ( ( is_utf8 ) && ( 0xCA == ((const U8*)s)[0] ) ) && ( 0x42 == ((const U8*)s)[1] ) ) && ( inRANGE(((const U8*)s)[2], 0x49, 0x4A ) ) ) ? 3 : 0 )\
: ((e)-(s) > 1) ?                                                           \
    ( ( inRANGE(((const U8*)s)[0], 0x0B, 0x0C ) || 0x15 == ((const U8*)s)[0] || 0x25 == ((const U8*)s)[0] ) ? 1\
    : ( 0x0D == ((const U8*)s)[0] ) ?                                       \
	( ( 0x25 == ((const U8*)s)[1] ) ? 2 : 1 )                           \
    : 0 )                                                                   \
: ((e)-(s) > 0) ?                                                           \
    ( inRANGE(((const U8*)s)[0], 0x0B, 0x0D ) || 0x15 == ((const U8*)s)[0] || 0x25 == ((const U8*)s)[0] )\
: 0 )
#define is_LNBREAK_utf8_safe(s,e)                                           \
( ((e)-(s) > 2) ?                                                           \
    ( ( inRANGE(((const U8*)s)[0], 0x0B, 0x0C ) || 0x15 == ((const U8*)s)[0] || 0x25 == ((const U8*)s)[0] ) ? 1\
    : ( 0x0D == ((const U8*)s)[0] ) ?                                       \
	( ( 0x25 == ((const U8*)s)[1] ) ? 2 : 1 )                           \
    : ( ( ( 0xCA == ((const U8*)s)[0] ) && ( 0x42 == ((const U8*)s)[1] ) ) && ( inRANGE(((const U8*)s)[2], 0x49, 0x4A ) ) ) ? 3 : 0 )\
: ((e)-(s) > 1) ?                                                           \
    ( ( inRANGE(((const U8*)s)[0], 0x0B, 0x0C ) || 0x15 == ((const U8*)s)[0] || 0x25 == ((const U8*)s)[0] ) ? 1\
    : ( 0x0D == ((const U8*)s)[0] ) ?                                       \
	( ( 0x25 == ((const U8*)s)[1] ) ? 2 : 1 )                           \
    : 0 )                                                                   \
: ((e)-(s) > 0) ?                                                           \
    ( inRANGE(((const U8*)s)[0], 0x0B, 0x0D ) || 0x15 == ((const U8*)s)[0] || 0x25 == ((const U8*)s)[0] )\
: 0 )
#define is_MULTI_CHAR_FOLD_latin1_safe(s,e)                                 \
( ((e)-(s) > 2) ?                                                           \
    ( ( ( ((const U8*)s)[0] & 0xBF ) == 0x86 ) ?                            \
	( ( ( ((const U8*)s)[1] & 0xBF ) == 0x86 ) ?                        \
	    ( ( ( ( ((const U8*)s)[2] & 0xBF ) == 0x89 ) || ( ( ((const U8*)s)[2] & 0xBF ) == 0x93 ) ) ? 3 : 2 )\
	: ( ( ( ((const U8*)s)[1] & 0xBF ) == 0x89 ) || ( ( ((const U8*)s)[1] & 0xBF ) == 0x93 ) ) ? 2 : 0 )\
    : ( ( ( ((const U8*)s)[0] & 0xBF ) == 0xA2 ) && ( ( ((const U8*)s)[1] & 0xBE ) == 0xA2 ) ) ? 2 : 0 )\
: ((e)-(s) > 1) ?                                                           \
    ( ( ( ((const U8*)s)[0] & 0xBF ) == 0x86 ) ?                            \
	( ( ( ( ((const U8*)s)[1] & 0xBF ) == 0x86 ) || ( ( ((const U8*)s)[1] & 0xBF ) == 0x89 ) || ( ( ((const U8*)s)[1] & 0xBF ) == 0x93 ) ) ? 2 : 0 )\
    : ( ( ( ((const U8*)s)[0] & 0xBF ) == 0xA2 ) && ( ( ((const U8*)s)[1] & 0xBE ) == 0xA2 ) ) ? 2 : 0 )\
: 0 )
#define is_MULTI_CHAR_FOLD_utf8_safe(s,e)                                   \
( ((e)-(s) > 5) ?                                                           \
    ( ( 0x81 == ((const U8*)s)[0] ) ?                                       \
	( ( ( 0xAB == ((const U8*)s)[1] ) && ( 0x72 == ((const U8*)s)[2] ) ) ? 3 : 0 )\
    : ( 0x86 == ((const U8*)s)[0] ) ? is_MULTI_CHAR_FOLD_utf8_safe_part0(s,e) : is_MULTI_CHAR_FOLD_utf8_safe_part1(s,e) )\
: ((e)-(s) > 4) ? is_MULTI_CHAR_FOLD_utf8_safe_part2(s,e) : is_MULTI_CHAR_FOLD_utf8_safe_part3(s,e) )
#define is_MULTI_CHAR_FOLD_utf8_safe_part0(s,e)                             \
( ( 0x86 == ((const U8*)s)[1] ) ?                                           \
	    ( ( 0x89 == ((const U8*)s)[2] || 0x93 == ((const U8*)s)[2] ) ? 3 : 2 )\
	: ( 0x89 == ((const U8*)s)[1] || 0x93 == ((const U8*)s)[1] ) ? 2 : 0 )
#define is_MULTI_CHAR_FOLD_utf8_safe_part1(s,e)                             \
( ( 0x88 == ((const U8*)s)[0] ) ?                                           \
	( ( ( 0xAE == ((const U8*)s)[1] ) && ( 0x58 == ((const U8*)s)[2] ) ) ? 3 : 0 )\
    : ( 0x89 == ((const U8*)s)[0] ) ?                                       \
	( ( ( 0xAD == ((const U8*)s)[1] ) && ( 0x48 == ((const U8*)s)[2] ) ) ? 3 : 0 )\
    : ( 0x8E == ((const U8*)s)[0] ) ?                                       \
	( ( ( ( 0x72 == ((const U8*)s)[1] ) && ( 0x8E == ((const U8*)s)[2] ) ) && ( 0x72 == ((const U8*)s)[3] ) ) ? 4 : 0 )\
    : ( 0x91 == ((const U8*)s)[0] ) ?                                       \
	( ( ( 0xAD == ((const U8*)s)[1] ) && ( 0x53 == ((const U8*)s)[2] ) ) ? 3 : 0 )\
    : ( 0xA2 == ((const U8*)s)[0] ) ?                                       \
	( ( inRANGE(((const U8*)s)[1], 0xA2, 0xA3 ) ) ? 2 : 0 )             \
    : ( 0xA3 == ((const U8*)s)[0] ) ?                                       \
	( ( ( 0xAD == ((const U8*)s)[1] ) && ( 0x49 == ((const U8*)s)[2] ) ) ? 3 : 0 )\
    : ( 0xA6 == ((const U8*)s)[0] || 0xA8 == ((const U8*)s)[0] ) ?          \
	( ( ( 0xAD == ((const U8*)s)[1] ) && ( 0x51 == ((const U8*)s)[2] ) ) ? 3 : 0 )\
    : ( 0xAA == ((const U8*)s)[0] ) ?                                       \
	( ( ( 0x6A == ((const U8*)s)[1] ) && ( 0x95 == ((const U8*)s)[2] ) ) ? 3 : 0 )\
    : ( 0xB3 == ((const U8*)s)[0] ) ?                                       \
	( ( 0x53 == ((const U8*)s)[1] || 0x55 == ((const U8*)s)[1] ) ?      \
	    ( ( ( 0xB3 == ((const U8*)s)[2] ) && ( 0x67 == ((const U8*)s)[3] ) ) ? 4 : 0 )\
	: ( 0x58 == ((const U8*)s)[1] || 0x65 == ((const U8*)s)[1] ) ?      \
	    ( ( 0xAF == ((const U8*)s)[2] ) ?                               \
		( ( 0x43 == ((const U8*)s)[3] ) ?                           \
		    ( ( ( 0xB3 == ((const U8*)s)[4] ) && ( 0x67 == ((const U8*)s)[5] ) ) ? 6 : 4 )\
		: 0 )                                                       \
	    : ( ( 0xB3 == ((const U8*)s)[2] ) && ( 0x67 == ((const U8*)s)[3] ) ) ? 4 : 0 )\
	: ( 0x67 == ((const U8*)s)[1] ) ?                                   \
	    ( ( 0xAD == ((const U8*)s)[2] ) ?                               \
		( ( 0x49 == ((const U8*)s)[3] ) ?                           \
		    ( ( 0xAD == ((const U8*)s)[4] ) ?                       \
			( ( inRANGE(((const U8*)s)[5], 0x41, 0x42 ) ) ? 6 : 0 )\
		    : ( ( 0xAF == ((const U8*)s)[4] ) && ( 0x43 == ((const U8*)s)[5] ) ) ? 6 : 0 )\
		: 0 )                                                       \
	    : ( ( 0xAF == ((const U8*)s)[2] ) && ( 0x43 == ((const U8*)s)[3] ) ) ? 4 : 0 )\
	: 0 )                                                               \
    : ( 0xB4 == ((const U8*)s)[0] ) ?                                       \
	( ( 0x42 == ((const U8*)s)[1] ) ?                                   \
	    ( ( ( 0xAD == ((const U8*)s)[2] ) && ( 0x5F == ((const U8*)s)[3] ) ) ? 4 : 0 )\
	: ( 0x46 == ((const U8*)s)[1] ) ?                                   \
	    ( ( 0xAD == ((const U8*)s)[2] ) ?                               \
		( ( 0x49 == ((const U8*)s)[3] ) ?                           \
		    ( ( 0xAD == ((const U8*)s)[4] ) ?                       \
			( ( inRANGE(((const U8*)s)[5], 0x41, 0x42 ) ) ? 6 : 0 )\
		    : ( ( 0xAF == ((const U8*)s)[4] ) && ( 0x43 == ((const U8*)s)[5] ) ) ? 6 : 0 )\
		: ( 0x5F == ((const U8*)s)[3] ) ?                           \
		    ( ( 0xAD == ((const U8*)s)[4] ) ?                       \
			( ( inRANGE(((const U8*)s)[5], 0x41, 0x42 ) ) ? 6 : 4 )\
		    : ( ( 0xAF == ((const U8*)s)[4] ) && ( 0x43 == ((const U8*)s)[5] ) ) ? 6 : 4 )\
		: 0 )                                                       \
	    : ( ( 0xAF == ((const U8*)s)[2] ) && ( 0x43 == ((const U8*)s)[3] ) ) ? 4 : 0 )\
	: ( 0x4A == ((const U8*)s)[1] ) ?                                   \
	    ( ( 0xAF == ((const U8*)s)[2] ) ?                               \
		( ( 0x43 == ((const U8*)s)[3] ) ?                           \
		    ( ( ( 0xB3 == ((const U8*)s)[4] ) && ( 0x67 == ((const U8*)s)[5] ) ) ? 6 : 4 )\
		: 0 )                                                       \
	    : ( ( 0xB3 == ((const U8*)s)[2] ) && ( 0x67 == ((const U8*)s)[3] ) ) ? 4 : 0 )\
	: ( ( ( 0x55 == ((const U8*)s)[1] ) && ( 0xB3 == ((const U8*)s)[2] ) ) && ( 0x67 == ((const U8*)s)[3] ) ) ? 4 : 0 )\
    : ( 0xB7 == ((const U8*)s)[0] ) ?                                       \
	( ( 0x52 == ((const U8*)s)[1] ) ?                                   \
	    ( ( 0x46 == ((const U8*)s)[2] ) ?                               \
		( ( ( ( 0xB7 == ((const U8*)s)[3] ) && ( 0x53 == ((const U8*)s)[4] ) ) && ( 0x43 == ((const U8*)s)[5] ) ) ? 6 : 0 )\
	    : ( 0x62 == ((const U8*)s)[2] ) ?                               \
		( ( ( ( 0xB7 == ((const U8*)s)[3] ) && ( 0x52 == ((const U8*)s)[4] ) ) && ( 0x46 == ((const U8*)s)[5] || 0x52 == ((const U8*)s)[5] || 0x54 == ((const U8*)s)[5] || 0x64 == ((const U8*)s)[5] ) ) ? 6 : 0 )\
	    : ( ( ( ( 0x71 == ((const U8*)s)[2] ) && ( 0xB7 == ((const U8*)s)[3] ) ) && ( 0x52 == ((const U8*)s)[4] ) ) && ( 0x64 == ((const U8*)s)[5] ) ) ? 6 : 0 )\
	: 0 )                                                               \
    : ( 0xBF == ((const U8*)s)[0] ) ?                                       \
	( ( inRANGE(((const U8*)s)[1], 0x66, 0x67 ) ) ?                     \
	    ( ( ( ( inRANGE(((const U8*)s)[2], 0x41, 0x48 ) ) && ( 0xB3 == ((const U8*)s)[3] ) ) && ( 0x67 == ((const U8*)s)[4] ) ) ? 5 : 0 )\
	: ( ( ( ( 0x69 == ((const U8*)s)[1] ) && ( inRANGE(((const U8*)s)[2], 0x41, 0x48 ) || 0x57 == ((const U8*)s)[2] || 0x62 == ((const U8*)s)[2] || 0x6A == ((const U8*)s)[2] ) ) && ( 0xB3 == ((const U8*)s)[3] ) ) && ( 0x67 == ((const U8*)s)[4] ) ) ? 5 : 0 )\
    : 0 )
#define is_MULTI_CHAR_FOLD_utf8_safe_part2(s,e)                             \
( ( 0x81 == ((const U8*)s)[0] ) ?                                           \
	( ( ( 0xAA == ((const U8*)s)[1] ) && ( 0x71 == ((const U8*)s)[2] ) ) ? 3 : 0 )\
    : ( 0x86 == ((const U8*)s)[0] ) ?                                       \
	( ( 0x86 == ((const U8*)s)[1] ) ?                                   \
	    ( ( 0x89 == ((const U8*)s)[2] || 0x93 == ((const U8*)s)[2] ) ? 3 : 2 )\
	: ( 0x89 == ((const U8*)s)[1] || 0x93 == ((const U8*)s)[1] ) ? 2 : 0 )\
    : ( 0x88 == ((const U8*)s)[0] ) ?                                       \
	( ( ( 0xAE == ((const U8*)s)[1] ) && ( 0x58 == ((const U8*)s)[2] ) ) ? 3 : 0 )\
    : ( 0x89 == ((const U8*)s)[0] ) ?                                       \
	( ( ( 0xAD == ((const U8*)s)[1] ) && ( 0x48 == ((const U8*)s)[2] ) ) ? 3 : 0 )\
    : ( 0x8E == ((const U8*)s)[0] ) ?                                       \
	( ( ( ( 0x72 == ((const U8*)s)[1] ) && ( 0x8E == ((const U8*)s)[2] ) ) && ( 0x72 == ((const U8*)s)[3] ) ) ? 4 : 0 )\
    : ( 0x91 == ((const U8*)s)[0] ) ?                                       \
	( ( ( 0xAD == ((const U8*)s)[1] ) && ( 0x53 == ((const U8*)s)[2] ) ) ? 3 : 0 )\
    : ( 0xA2 == ((const U8*)s)[0] ) ?                                       \
	( ( inRANGE(((const U8*)s)[1], 0xA2, 0xA3 ) ) ? 2 : 0 )             \
    : ( 0xA3 == ((const U8*)s)[0] ) ?                                       \
	( ( ( 0xAD == ((const U8*)s)[1] ) && ( 0x49 == ((const U8*)s)[2] ) ) ? 3 : 0 )\
    : ( 0xA6 == ((const U8*)s)[0] || 0xA8 == ((const U8*)s)[0] ) ?          \
	( ( ( 0xAD == ((const U8*)s)[1] ) && ( 0x51 == ((const U8*)s)[2] ) ) ? 3 : 0 )\
    : ( 0xAA == ((const U8*)s)[0] ) ?                                       \
	( ( ( 0x6A == ((const U8*)s)[1] ) && ( 0x95 == ((const U8*)s)[2] ) ) ? 3 : 0 )\
    : ( 0xB3 == ((const U8*)s)[0] ) ?                                       \
	( ( 0x53 == ((const U8*)s)[1] || 0x55 == ((const U8*)s)[1] ) ?      \
	    ( ( ( 0xB3 == ((const U8*)s)[2] ) && ( 0x67 == ((const U8*)s)[3] ) ) ? 4 : 0 )\
	: ( 0x58 == ((const U8*)s)[1] || 0x65 == ((const U8*)s)[1] ) ?      \
	    ( ( 0xAF == ((const U8*)s)[2] ) ?                               \
		( ( 0x43 == ((const U8*)s)[3] ) ? 4 : 0 )                   \
	    : ( ( 0xB3 == ((const U8*)s)[2] ) && ( 0x67 == ((const U8*)s)[3] ) ) ? 4 : 0 )\
	: ( ( ( 0x67 == ((const U8*)s)[1] ) && ( 0xAF == ((const U8*)s)[2] ) ) && ( 0x43 == ((const U8*)s)[3] ) ) ? 4 : 0 )\
    : ( 0xB4 == ((const U8*)s)[0] ) ?                                       \
	( ( 0x42 == ((const U8*)s)[1] ) ?                                   \
	    ( ( ( 0xAD == ((const U8*)s)[2] ) && ( 0x5F == ((const U8*)s)[3] ) ) ? 4 : 0 )\
	: ( 0x46 == ((const U8*)s)[1] ) ?                                   \
	    ( ( 0xAD == ((const U8*)s)[2] ) ?                               \
		( ( 0x5F == ((const U8*)s)[3] ) ? 4 : 0 )                   \
	    : ( ( 0xAF == ((const U8*)s)[2] ) && ( 0x43 == ((const U8*)s)[3] ) ) ? 4 : 0 )\
	: ( 0x4A == ((const U8*)s)[1] ) ?                                   \
	    ( ( 0xAF == ((const U8*)s)[2] ) ?                               \
		( ( 0x43 == ((const U8*)s)[3] ) ? 4 : 0 )                   \
	    : ( ( 0xB3 == ((const U8*)s)[2] ) && ( 0x67 == ((const U8*)s)[3] ) ) ? 4 : 0 )\
	: ( ( ( 0x55 == ((const U8*)s)[1] ) && ( 0xB3 == ((const U8*)s)[2] ) ) && ( 0x67 == ((const U8*)s)[3] ) ) ? 4 : 0 )\
    : ( 0xBF == ((const U8*)s)[0] ) ?                                       \
	( ( inRANGE(((const U8*)s)[1], 0x66, 0x67 ) ) ?                     \
	    ( ( ( ( inRANGE(((const U8*)s)[2], 0x41, 0x48 ) ) && ( 0xB3 == ((const U8*)s)[3] ) ) && ( 0x67 == ((const U8*)s)[4] ) ) ? 5 : 0 )\
	: ( ( ( ( 0x69 == ((const U8*)s)[1] ) && ( inRANGE(((const U8*)s)[2], 0x41, 0x48 ) || 0x57 == ((const U8*)s)[2] || 0x62 == ((const U8*)s)[2] || 0x6A == ((const U8*)s)[2] ) ) && ( 0xB3 == ((const U8*)s)[3] ) ) && ( 0x67 == ((const U8*)s)[4] ) ) ? 5 : 0 )\
    : 0 )
#define is_MULTI_CHAR_FOLD_utf8_safe_part3(s,e)                             \
( ((e)-(s) > 3) ?                                                           \
    ( ( 0x81 == ((const U8*)s)[0] ) ?                                       \
	( ( ( 0xAA == ((const U8*)s)[1] ) && ( 0x71 == ((const U8*)s)[2] ) ) ? 3 : 0 )\
    : ( 0x86 == ((const U8*)s)[0] ) ?                                       \
	( ( 0x86 == ((const U8*)s)[1] ) ?                                   \
	    ( ( 0x89 == ((const U8*)s)[2] || 0x93 == ((const U8*)s)[2] ) ? 3 : 2 )\
	: ( 0x89 == ((const U8*)s)[1] || 0x93 == ((const U8*)s)[1] ) ? 2 : 0 )\
    : ( 0x88 == ((const U8*)s)[0] ) ?                                       \
	( ( ( 0xAE == ((const U8*)s)[1] ) && ( 0x58 == ((const U8*)s)[2] ) ) ? 3 : 0 )\
    : ( 0x89 == ((const U8*)s)[0] ) ?                                       \
	( ( ( 0xAD == ((const U8*)s)[1] ) && ( 0x48 == ((const U8*)s)[2] ) ) ? 3 : 0 )\
    : ( 0x8E == ((const U8*)s)[0] ) ?                                       \
	( ( ( ( 0x72 == ((const U8*)s)[1] ) && ( 0x8E == ((const U8*)s)[2] ) ) && ( 0x72 == ((const U8*)s)[3] ) ) ? 4 : 0 )\
    : ( 0x91 == ((const U8*)s)[0] ) ?                                       \
	( ( ( 0xAD == ((const U8*)s)[1] ) && ( 0x53 == ((const U8*)s)[2] ) ) ? 3 : 0 )\
    : ( 0xA2 == ((const U8*)s)[0] ) ?                                       \
	( ( inRANGE(((const U8*)s)[1], 0xA2, 0xA3 ) ) ? 2 : 0 )             \
    : ( 0xA3 == ((const U8*)s)[0] ) ?                                       \
	( ( ( 0xAD == ((const U8*)s)[1] ) && ( 0x49 == ((const U8*)s)[2] ) ) ? 3 : 0 )\
    : ( 0xA6 == ((const U8*)s)[0] || 0xA8 == ((const U8*)s)[0] ) ?          \
	( ( ( 0xAD == ((const U8*)s)[1] ) && ( 0x51 == ((const U8*)s)[2] ) ) ? 3 : 0 )\
    : ( 0xAA == ((const U8*)s)[0] ) ?                                       \
	( ( ( 0x6A == ((const U8*)s)[1] ) && ( 0x95 == ((const U8*)s)[2] ) ) ? 3 : 0 )\
    : ( 0xB3 == ((const U8*)s)[0] ) ?                                       \
	( ( 0x53 == ((const U8*)s)[1] || 0x55 == ((const U8*)s)[1] ) ?      \
	    ( ( ( 0xB3 == ((const U8*)s)[2] ) && ( 0x67 == ((const U8*)s)[3] ) ) ? 4 : 0 )\
	: ( 0x58 == ((const U8*)s)[1] || 0x65 == ((const U8*)s)[1] ) ?      \
	    ( ( 0xAF == ((const U8*)s)[2] ) ?                               \
		( ( 0x43 == ((const U8*)s)[3] ) ? 4 : 0 )                   \
	    : ( ( 0xB3 == ((const U8*)s)[2] ) && ( 0x67 == ((const U8*)s)[3] ) ) ? 4 : 0 )\
	: ( ( ( 0x67 == ((const U8*)s)[1] ) && ( 0xAF == ((const U8*)s)[2] ) ) && ( 0x43 == ((const U8*)s)[3] ) ) ? 4 : 0 )\
    : ( 0xB4 == ((const U8*)s)[0] ) ?                                       \
	( ( 0x42 == ((const U8*)s)[1] ) ?                                   \
	    ( ( ( 0xAD == ((const U8*)s)[2] ) && ( 0x5F == ((const U8*)s)[3] ) ) ? 4 : 0 )\
	: ( 0x46 == ((const U8*)s)[1] ) ?                                   \
	    ( ( 0xAD == ((const U8*)s)[2] ) ?                               \
		( ( 0x5F == ((const U8*)s)[3] ) ? 4 : 0 )                   \
	    : ( ( 0xAF == ((const U8*)s)[2] ) && ( 0x43 == ((const U8*)s)[3] ) ) ? 4 : 0 )\
	: ( 0x4A == ((const U8*)s)[1] ) ?                                   \
	    ( ( 0xAF == ((const U8*)s)[2] ) ?                               \
		( ( 0x43 == ((const U8*)s)[3] ) ? 4 : 0 )                   \
	    : ( ( 0xB3 == ((const U8*)s)[2] ) && ( 0x67 == ((const U8*)s)[3] ) ) ? 4 : 0 )\
	: ( ( ( 0x55 == ((const U8*)s)[1] ) && ( 0xB3 == ((const U8*)s)[2] ) ) && ( 0x67 == ((const U8*)s)[3] ) ) ? 4 : 0 )\
    : 0 )                                                                   \
: ((e)-(s) > 2) ?                                                           \
    ( ( 0x81 == ((const U8*)s)[0] ) ?                                       \
	( ( ( 0xAA == ((const U8*)s)[1] ) && ( 0x71 == ((const U8*)s)[2] ) ) ? 3 : 0 )\
    : ( 0x86 == ((const U8*)s)[0] ) ?                                       \
	( ( 0x86 == ((const U8*)s)[1] ) ?                                   \
	    ( ( 0x89 == ((const U8*)s)[2] || 0x93 == ((const U8*)s)[2] ) ? 3 : 2 )\
	: ( 0x89 == ((const U8*)s)[1] || 0x93 == ((const U8*)s)[1] ) ? 2 : 0 )\
    : ( 0x88 == ((const U8*)s)[0] ) ?                                       \
	( ( ( 0xAE == ((const U8*)s)[1] ) && ( 0x58 == ((const U8*)s)[2] ) ) ? 3 : 0 )\
    : ( 0x89 == ((const U8*)s)[0] ) ?                                       \
	( ( ( 0xAD == ((const U8*)s)[1] ) && ( 0x48 == ((const U8*)s)[2] ) ) ? 3 : 0 )\
    : ( 0x91 == ((const U8*)s)[0] ) ?                                       \
	( ( ( 0xAD == ((const U8*)s)[1] ) && ( 0x53 == ((const U8*)s)[2] ) ) ? 3 : 0 )\
    : ( 0xA2 == ((const U8*)s)[0] ) ?                                       \
	( ( inRANGE(((const U8*)s)[1], 0xA2, 0xA3 ) ) ? 2 : 0 )             \
    : ( 0xA3 == ((const U8*)s)[0] ) ?                                       \
	( ( ( 0xAD == ((const U8*)s)[1] ) && ( 0x49 == ((const U8*)s)[2] ) ) ? 3 : 0 )\
    : ( 0xA6 == ((const U8*)s)[0] || 0xA8 == ((const U8*)s)[0] ) ?          \
	( ( ( 0xAD == ((const U8*)s)[1] ) && ( 0x51 == ((const U8*)s)[2] ) ) ? 3 : 0 )\
    : ( ( ( 0xAA == ((const U8*)s)[0] ) && ( 0x6A == ((const U8*)s)[1] ) ) && ( 0x95 == ((const U8*)s)[2] ) ) ? 3 : 0 )\
: ((e)-(s) > 1) ?                                                           \
    ( ( 0x86 == ((const U8*)s)[0] ) ?                                       \
	( ( 0x86 == ((const U8*)s)[1] || 0x89 == ((const U8*)s)[1] || 0x93 == ((const U8*)s)[1] ) ? 2 : 0 )\
    : ( ( 0xA2 == ((const U8*)s)[0] ) && ( inRANGE(((const U8*)s)[1], 0xA2, 0xA3 ) ) ) ? 2 : 0 )\
: 0 )
#define is_NONCHAR_utf8_safe(s,e)                                           \
( ( ( LIKELY((e) > (s)) ) && ( LIKELY(((e) - (s)) >= UTF8SKIP(s)) ) ) ? ( ( 0xDD == ((const U8*)s)[0] ) ?\
	    ( ( 0x72 == ((const U8*)s)[1] ) ?                               \
		( ( 0x55 == ((const U8*)s)[2] ) ?                           \
		    ( ( inRANGE(((const U8*)s)[3], 0x57, 0x59 ) || 0x5F == ((const U8*)s)[3] || inRANGE(((const U8*)s)[3], 0x62, 0x6A ) || inRANGE(((const U8*)s)[3], 0x70, 0x72 ) ) ? 4 : 0 )\
		: ( 0x56 == ((const U8*)s)[2] ) ?                           \
		    ( ( inRANGE(((const U8*)s)[3], 0x41, 0x4A ) || inRANGE(((const U8*)s)[3], 0x51, 0x56 ) ) ? 4 : 0 )\
		: ( ( 0x72 == ((const U8*)s)[2] ) && ( inRANGE(((const U8*)s)[3], 0x71, 0x72 ) ) ) ? 4 : 0 )\
	    : 0 )                                                           \
	: ( 0xDF == ((const U8*)s)[0] || 0xEA == ((const U8*)s)[0] || 0xEC == ((const U8*)s)[0] ) ?\
	    ( ( ( ( 0x72 == ((const U8*)s)[1] ) && ( 0x72 == ((const U8*)s)[2] ) ) && ( inRANGE(((const U8*)s)[3], 0x71, 0x72 ) ) ) ? 4 : 0 )\
	: ( 0xED == ((const U8*)s)[0] ) ?                                   \
	    ( ( ( ( ( ((const U8*)s)[1] == 0x4A || ((const U8*)s)[1] == 0x52 || ( ( ((const U8*)s)[1] & 0xFD ) == 0x54 ) || ((const U8*)s)[1] == 0x58 || ((const U8*)s)[1] == 0x5F || ((const U8*)s)[1] == 0x63 || ( ( ((const U8*)s)[1] & 0xFD ) == 0x65 ) || ((const U8*)s)[1] == 0x69 || ( ( ((const U8*)s)[1] & 0xFD ) == 0x70 ) ) && ( 0x72 == ((const U8*)s)[2] ) ) && ( 0x72 == ((const U8*)s)[3] ) ) && ( inRANGE(((const U8*)s)[4], 0x71, 0x72 ) ) ) ? 5 : 0 )\
	: ( ( ( ( ( 0xEE == ((const U8*)s)[0] ) && ( 0x42 == ((const U8*)s)[1] ) ) && ( 0x72 == ((const U8*)s)[2] ) ) && ( 0x72 == ((const U8*)s)[3] ) ) && ( inRANGE(((const U8*)s)[4], 0x71, 0x72 ) ) ) ? 5 : 0 ) : 0 )
#define is_PATWS_cp(cp)                                                     \
( 0x05 == cp || ( 0x05 < cp &&                                              \
( inRANGE(cp, 0x0B, 0x0D) || ( 0x0D < cp &&                                 \
( 0x15 == cp || ( 0x15 < cp &&                                              \
( 0x25 == cp || ( 0x25 < cp &&                                              \
( 0x40 == cp || ( 0x40 < cp &&                                              \
( 0x200E == cp || ( 0x200E < cp &&                                          \
( 0x200F == cp || ( 0x200F < cp &&                                          \
( 0x2028 == cp || 0x2029 == cp ) ) ) ) ) ) ) ) ) ) ) ) ) ) )
#define is_PATWS_safe(s,e,is_utf8)                                          \
( ( LIKELY((e) > (s)) ) ?                                                   \
    ( ( 0x05 == ((const U8*)s)[0] || inRANGE(((const U8*)s)[0], 0x0B, 0x0D ) || 0x15 == ((const U8*)s)[0] || 0x25 == ((const U8*)s)[0] || 0x40 == ((const U8*)s)[0] ) ? 1\
    : ( ( is_utf8 && LIKELY(((e) - (s)) >= UTF8SKIP(s)) ) && ( 0xCA == ((const U8*)s)[0] ) ) ? ( ( 0x41 == ((const U8*)s)[1] ) ?\
		    ( ( inRANGE(((const U8*)s)[2], 0x55, 0x56 ) ) ? 3 : 0 ) \
		: ( ( 0x42 == ((const U8*)s)[1] ) && ( inRANGE(((const U8*)s)[2], 0x49, 0x4A ) ) ) ? 3 : 0 ) : 0 )\
: 0 )
#define is_PROBLEMATIC_LOCALE_FOLDEDS_START_cp(cp)                          \
( cp <= 0xFF || ( 0xFF < cp &&                                              \
( 0x130 == cp || ( 0x130 < cp &&                                            \
( 0x131 == cp || ( 0x131 < cp &&                                            \
( 0x149 == cp || ( 0x149 < cp &&                                            \
( 0x178 == cp || ( 0x178 < cp &&                                            \
( 0x17F == cp || ( 0x17F < cp &&                                            \
( 0x1F0 == cp || ( 0x1F0 < cp &&                                            \
( 0x2BC == cp || ( 0x2BC < cp &&                                            \
( 0x39C == cp || ( 0x39C < cp &&                                            \
( 0x3BC == cp || ( 0x3BC < cp &&                                            \
( inRANGE(cp, 0x1E96, 0x1E9A) || ( 0x1E9A < cp &&                           \
( 0x1E9E == cp || ( 0x1E9E < cp &&                                          \
( 0x212A == cp || ( 0x212A < cp &&                                          \
( 0x212B == cp || inRANGE(cp, 0xFB00, 0xFB06) ) ) ) ) ) ) ) ) ) ) ) ) ) ) ) ) ) ) ) ) ) ) ) ) ) ) )
#define is_PROBLEMATIC_LOCALE_FOLDEDS_START_utf8(s)                         \
( ( ( ((const U8*)s)[0] <= 0x40 ) || inRANGE(((const U8*)s)[0], 0x4B, 0x50 ) || inRANGE(((const U8*)s)[0], 0x5A, 0x61 ) || inRANGE(((const U8*)s)[0], 0x6B, 0x6F ) || inRANGE(((const U8*)s)[0], 0x79, 0x7F ) || inRANGE(((const U8*)s)[0], 0x81, 0x89 ) || inRANGE(((const U8*)s)[0], 0x91, 0x99 ) || inRANGE(((const U8*)s)[0], 0xA1, 0xA9 ) || 0xAD == ((const U8*)s)[0] || 0xBD == ((const U8*)s)[0] || inRANGE(((const U8*)s)[0], 0xC0, 0xC9 ) || inRANGE(((const U8*)s)[0], 0xD0, 0xD9 ) || 0xE0 == ((const U8*)s)[0] || inRANGE(((const U8*)s)[0], 0xE2, 0xE9 ) || inRANGE(((const U8*)s)[0], 0xF0, 0xF9 ) || 0xFF == ((const U8*)s)[0] ) ? 1\
: ( 0x80 == ((const U8*)s)[0] || inRANGE(((const U8*)s)[0], 0x8A, 0x8B ) ) ?\
    ( ( inRANGE(((const U8*)s)[1], 0x41, 0x4A ) || inRANGE(((const U8*)s)[1], 0x51, 0x59 ) || inRANGE(((const U8*)s)[1], 0x62, 0x6A ) || inRANGE(((const U8*)s)[1], 0x70, 0x73 ) ) ? 2 : 0 )\
: ( 0x8D == ((const U8*)s)[0] ) ?                                           \
    ( ( inRANGE(((const U8*)s)[1], 0x57, 0x58 ) ) ? 2 : 0 )                 \
: ( 0x8E == ((const U8*)s)[0] ) ?                                           \
    ( ( 0x4A == ((const U8*)s)[1] ) ? 2 : 0 )                               \
: ( 0x8F == ((const U8*)s)[0] ) ?                                           \
    ( ( 0x67 == ((const U8*)s)[1] || 0x73 == ((const U8*)s)[1] ) ? 2 : 0 )  \
: ( 0x9C == ((const U8*)s)[0] ) ?                                           \
    ( ( 0x57 == ((const U8*)s)[1] ) ? 2 : 0 )                               \
: ( 0xAB == ((const U8*)s)[0] || inRANGE(((const U8*)s)[0], 0xB3, 0xB4 ) ) ?\
    ( ( 0x70 == ((const U8*)s)[1] ) ? 2 : 0 )                               \
: ( 0xBF == ((const U8*)s)[0] ) ?                                           \
    ( ( ( 0x63 == ((const U8*)s)[1] ) && ( inRANGE(((const U8*)s)[2], 0x65, 0x69 ) || 0x72 == ((const U8*)s)[2] ) ) ? 3 : 0 )\
: ( 0xCA == ((const U8*)s)[0] ) ?                                           \
    ( ( ( 0x4A == ((const U8*)s)[1] ) && ( inRANGE(((const U8*)s)[2], 0x51, 0x52 ) ) ) ? 3 : 0 )\
: ( ( ( ( 0xDD == ((const U8*)s)[0] ) && ( 0x72 == ((const U8*)s)[1] ) ) && ( 0x67 == ((const U8*)s)[2] ) ) && ( inRANGE(((const U8*)s)[3], 0x41, 0x47 ) ) ) ? 4 : 0 )
#define is_PROBLEMATIC_LOCALE_FOLD_cp(cp)                                   \
( cp <= 0xFF || ( 0xFF < cp &&                                              \
( 0x130 == cp || ( 0x130 < cp &&                                            \
( 0x131 == cp || ( 0x131 < cp &&                                            \
( 0x149 == cp || ( 0x149 < cp &&                                            \
( 0x178 == cp || ( 0x178 < cp &&                                            \
( 0x17F == cp || ( 0x17F < cp &&                                            \
( 0x1F0 == cp || ( 0x1F0 < cp &&                                            \
( 0x307 == cp || ( 0x307 < cp &&                                            \
( 0x39C == cp || ( 0x39C < cp &&                                            \
( 0x3BC == cp || ( 0x3BC < cp &&                                            \
( inRANGE(cp, 0x1E96, 0x1E9A) || ( 0x1E9A < cp &&                           \
( 0x1E9E == cp || ( 0x1E9E < cp &&                                          \
( 0x212A == cp || ( 0x212A < cp &&                                          \
( 0x212B == cp || inRANGE(cp, 0xFB00, 0xFB06) ) ) ) ) ) ) ) ) ) ) ) ) ) ) ) ) ) ) ) ) ) ) ) ) ) ) )
#define is_PROBLEMATIC_LOCALE_FOLD_utf8(s)                                  \
( ( ( ((const U8*)s)[0] <= 0x40 ) || inRANGE(((const U8*)s)[0], 0x4B, 0x50 ) || inRANGE(((const U8*)s)[0], 0x5A, 0x61 ) || inRANGE(((const U8*)s)[0], 0x6B, 0x6F ) || inRANGE(((const U8*)s)[0], 0x79, 0x7F ) || inRANGE(((const U8*)s)[0], 0x81, 0x89 ) || inRANGE(((const U8*)s)[0], 0x91, 0x99 ) || inRANGE(((const U8*)s)[0], 0xA1, 0xA9 ) || 0xAD == ((const U8*)s)[0] || 0xBD == ((const U8*)s)[0] || inRANGE(((const U8*)s)[0], 0xC0, 0xC9 ) || inRANGE(((const U8*)s)[0], 0xD0, 0xD9 ) || 0xE0 == ((const U8*)s)[0] || inRANGE(((const U8*)s)[0], 0xE2, 0xE9 ) || inRANGE(((const U8*)s)[0], 0xF0, 0xF9 ) || 0xFF == ((const U8*)s)[0] ) ? 1\
: ( 0x80 == ((const U8*)s)[0] || inRANGE(((const U8*)s)[0], 0x8A, 0x8B ) ) ?\
    ( ( inRANGE(((const U8*)s)[1], 0x41, 0x4A ) || inRANGE(((const U8*)s)[1], 0x51, 0x59 ) || inRANGE(((const U8*)s)[1], 0x62, 0x6A ) || inRANGE(((const U8*)s)[1], 0x70, 0x73 ) ) ? 2 : 0 )\
: ( 0x8D == ((const U8*)s)[0] ) ?                                           \
    ( ( inRANGE(((const U8*)s)[1], 0x57, 0x58 ) ) ? 2 : 0 )                 \
: ( 0x8E == ((const U8*)s)[0] ) ?                                           \
    ( ( 0x4A == ((const U8*)s)[1] ) ? 2 : 0 )                               \
: ( 0x8F == ((const U8*)s)[0] ) ?                                           \
    ( ( 0x67 == ((const U8*)s)[1] || 0x73 == ((const U8*)s)[1] ) ? 2 : 0 )  \
: ( 0x9C == ((const U8*)s)[0] ) ?                                           \
    ( ( 0x57 == ((const U8*)s)[1] ) ? 2 : 0 )                               \
: ( 0xAF == ((const U8*)s)[0] ) ?                                           \
    ( ( 0x48 == ((const U8*)s)[1] ) ? 2 : 0 )                               \
: ( inRANGE(((const U8*)s)[0], 0xB3, 0xB4 ) ) ?                             \
    ( ( 0x70 == ((const U8*)s)[1] ) ? 2 : 0 )                               \
: ( 0xBF == ((const U8*)s)[0] ) ?                                           \
    ( ( ( 0x63 == ((const U8*)s)[1] ) && ( inRANGE(((const U8*)s)[2], 0x65, 0x69 ) || 0x72 == ((const U8*)s)[2] ) ) ? 3 : 0 )\
: ( 0xCA == ((const U8*)s)[0] ) ?                                           \
    ( ( ( 0x4A == ((const U8*)s)[1] ) && ( inRANGE(((const U8*)s)[2], 0x51, 0x52 ) ) ) ? 3 : 0 )\
: ( ( ( ( 0xDD == ((const U8*)s)[0] ) && ( 0x72 == ((const U8*)s)[1] ) ) && ( 0x67 == ((const U8*)s)[2] ) ) && ( inRANGE(((const U8*)s)[3], 0x41, 0x47 ) ) ) ? 4 : 0 )
#define is_QUOTEMETA_high(s)                                                \
( ( 0xAF == ((const U8*)s)[0] ) ?                                           \
    ( ( 0x56 == ((const U8*)s)[1] ) ? 2 : 0 )                               \
: ( 0xB7 == ((const U8*)s)[0] ) ?                                           \
    ( ( ( 0x57 == ((const U8*)s)[1] ) && ( 0x6A == ((const U8*)s)[2] ) ) ? 3 : 0 )\
: ( 0xBC == ((const U8*)s)[0] ) ? is_QUOTEMETA_high_part0(s) : is_QUOTEMETA_high_part1(s) )
#define is_QUOTEMETA_high_part0(s)                                          \
( ( 0x51 == ((const U8*)s)[1] ) ?                                           \
	( ( 0x72 == ((const U8*)s)[2] ) ? 3 : 0 )                           \
    : ( ( 0x52 == ((const U8*)s)[1] ) && ( 0x41 == ((const U8*)s)[2] ) ) ? 3 : 0 )
#define is_QUOTEMETA_high_part1(s)                                          \
( ( 0xBD == ((const U8*)s)[0] ) ?                                           \
    ( ( 0x62 == ((const U8*)s)[1] ) ?                                       \
	( ( 0x41 == ((const U8*)s)[2] ) ? 3 : 0 )                           \
    : ( ( 0x70 == ((const U8*)s)[1] ) && ( inRANGE(((const U8*)s)[2], 0x62, 0x63 ) ) ) ? 3 : 0 )\
: ( 0xBE == ((const U8*)s)[0] ) ?                                           \
    ( ( ( 0x41 == ((const U8*)s)[1] ) && ( inRANGE(((const U8*)s)[2], 0x52, 0x55 ) ) ) ? 3 : 0 )\
: ( 0xCA == ((const U8*)s)[0] ) ?                                           \
    ( ( 0x41 == ((const U8*)s)[1] || inRANGE(((const U8*)s)[1], 0x54, 0x59 ) || 0x5F == ((const U8*)s)[1] || inRANGE(((const U8*)s)[1], 0x62, 0x6A ) || inRANGE(((const U8*)s)[1], 0x70, 0x72 ) ) ?\
	( ( inRANGE(((const U8*)s)[2], 0x41, 0x4A ) || inRANGE(((const U8*)s)[2], 0x51, 0x59 ) || 0x5F == ((const U8*)s)[2] || inRANGE(((const U8*)s)[2], 0x62, 0x6A ) || inRANGE(((const U8*)s)[2], 0x70, 0x72 ) ) ? 3 : 0 )\
    : ( 0x42 == ((const U8*)s)[1] ) ?                                       \
	( ( inRANGE(((const U8*)s)[2], 0x41, 0x4A ) || inRANGE(((const U8*)s)[2], 0x51, 0x59 ) || 0x5F == ((const U8*)s)[2] || inRANGE(((const U8*)s)[2], 0x62, 0x6A ) || inRANGE(((const U8*)s)[2], 0x70, 0x71 ) ) ? 3 : 0 )\
    : ( 0x43 == ((const U8*)s)[1] ) ?                                       \
	( ( inRANGE(((const U8*)s)[2], 0x42, 0x4A ) || inRANGE(((const U8*)s)[2], 0x51, 0x59 ) || 0x5F == ((const U8*)s)[2] || inRANGE(((const U8*)s)[2], 0x63, 0x6A ) || inRANGE(((const U8*)s)[2], 0x70, 0x72 ) ) ? 3 : 0 )\
    : ( 0x44 == ((const U8*)s)[1] ) ?                                       \
	( ( inRANGE(((const U8*)s)[2], 0x41, 0x4A ) || inRANGE(((const U8*)s)[2], 0x51, 0x56 ) ) ? 3 : 0 )\
    : ( ( 0x53 == ((const U8*)s)[1] ) && ( inRANGE(((const U8*)s)[2], 0x57, 0x59 ) || 0x5F == ((const U8*)s)[2] || inRANGE(((const U8*)s)[2], 0x62, 0x6A ) || inRANGE(((const U8*)s)[2], 0x70, 0x72 ) ) ) ? 3 : 0 )\
: ( 0xCB == ((const U8*)s)[0] ) ?                                           \
    ( ( inRANGE(((const U8*)s)[1], 0x41, 0x43 ) || inRANGE(((const U8*)s)[1], 0x49, 0x4A ) || inRANGE(((const U8*)s)[1], 0x51, 0x59 ) || 0x5F == ((const U8*)s)[1] || inRANGE(((const U8*)s)[1], 0x62, 0x68 ) || inRANGE(((const U8*)s)[1], 0x70, 0x72 ) ) ?\
	( ( inRANGE(((const U8*)s)[2], 0x41, 0x4A ) || inRANGE(((const U8*)s)[2], 0x51, 0x59 ) || 0x5F == ((const U8*)s)[2] || inRANGE(((const U8*)s)[2], 0x62, 0x6A ) || inRANGE(((const U8*)s)[2], 0x70, 0x72 ) ) ? 3 : 0 )\
    : ( 0x69 == ((const U8*)s)[1] ) ?                                       \
	( ( inRANGE(((const U8*)s)[2], 0x41, 0x4A ) || inRANGE(((const U8*)s)[2], 0x51, 0x59 ) || 0x5F == ((const U8*)s)[2] || inRANGE(((const U8*)s)[2], 0x62, 0x63 ) ) ? 3 : 0 )\
    : ( ( 0x6A == ((const U8*)s)[1] ) && ( inRANGE(((const U8*)s)[2], 0x62, 0x6A ) || inRANGE(((const U8*)s)[2], 0x70, 0x72 ) ) ) ? 3 : 0 )\
: ( 0xCC == ((const U8*)s)[0] ) ?                                           \
    ( ( ( inRANGE(((const U8*)s)[1], 0x41, 0x4A ) || inRANGE(((const U8*)s)[1], 0x51, 0x59 ) || 0x5F == ((const U8*)s)[1] || inRANGE(((const U8*)s)[1], 0x62, 0x6A ) || inRANGE(((const U8*)s)[1], 0x70, 0x72 ) ) && ( inRANGE(((const U8*)s)[2], 0x41, 0x4A ) || inRANGE(((const U8*)s)[2], 0x51, 0x59 ) || 0x5F == ((const U8*)s)[2] || inRANGE(((const U8*)s)[2], 0x62, 0x6A ) || inRANGE(((const U8*)s)[2], 0x70, 0x72 ) ) ) ? 3 : 0 )\
: ( 0xCD == ((const U8*)s)[0] ) ?                                           \
    ( ( ( inRANGE(((const U8*)s)[1], 0x57, 0x59 ) || 0x5F == ((const U8*)s)[1] ) && ( inRANGE(((const U8*)s)[2], 0x41, 0x4A ) || inRANGE(((const U8*)s)[2], 0x51, 0x59 ) || 0x5F == ((const U8*)s)[2] || inRANGE(((const U8*)s)[2], 0x62, 0x6A ) || inRANGE(((const U8*)s)[2], 0x70, 0x72 ) ) ) ? 3 : 0 )\
: ( 0xCE == ((const U8*)s)[0] ) ?                                           \
    ( ( 0x41 == ((const U8*)s)[1] ) ?                                       \
	( ( inRANGE(((const U8*)s)[2], 0x41, 0x44 ) || inRANGE(((const U8*)s)[2], 0x49, 0x4A ) || inRANGE(((const U8*)s)[2], 0x51, 0x59 ) || 0x5F == ((const U8*)s)[2] || inRANGE(((const U8*)s)[2], 0x62, 0x6A ) || inRANGE(((const U8*)s)[2], 0x70, 0x72 ) ) ? 3 : 0 )\
    : ( 0x42 == ((const U8*)s)[1] ) ?                                       \
	( ( 0x41 == ((const U8*)s)[2] || 0x57 == ((const U8*)s)[2] ) ? 3 : 0 )\
    : ( ( 0x52 == ((const U8*)s)[1] ) && ( 0x45 == ((const U8*)s)[2] ) ) ? 3 : 0 )\
: ( 0xDD == ((const U8*)s)[0] ) ?                                           \
    ( ( 0x72 == ((const U8*)s)[1] ) ?                                       \
	( ( 0x4A == ((const U8*)s)[2] ) ?                                   \
	    ( ( inRANGE(((const U8*)s)[3], 0x71, 0x72 ) ) ? 4 : 0 )         \
	: ( 0x57 == ((const U8*)s)[2] ) ?                                   \
	    ( ( inRANGE(((const U8*)s)[3], 0x41, 0x4A ) || inRANGE(((const U8*)s)[3], 0x51, 0x56 ) ) ? 4 : 0 )\
	: ( 0x59 == ((const U8*)s)[2] ) ?                                   \
	    ( ( inRANGE(((const U8*)s)[3], 0x46, 0x47 ) ) ? 4 : 0 )         \
	: ( 0x65 == ((const U8*)s)[2] ) ?                                   \
	    ( ( 0x72 == ((const U8*)s)[3] ) ? 4 : 0 )                       \
	: ( 0x70 == ((const U8*)s)[2] ) ?                                   \
	    ( ( 0x41 == ((const U8*)s)[3] ) ? 4 : 0 )                       \
	: ( ( 0x72 == ((const U8*)s)[2] ) && ( inRANGE(((const U8*)s)[3], 0x57, 0x59 ) || 0x5F == ((const U8*)s)[3] || inRANGE(((const U8*)s)[3], 0x62, 0x66 ) ) ) ? 4 : 0 )\
    : 0 )                                                                   \
: ( 0xDF == ((const U8*)s)[0] ) ?                                           \
    ( ( 0x56 == ((const U8*)s)[1] ) ?                                       \
	( ( ( 0x46 == ((const U8*)s)[2] ) && ( inRANGE(((const U8*)s)[3], 0x41, 0x44 ) ) ) ? 4 : 0 )\
    : ( ( ( 0x62 == ((const U8*)s)[1] ) && ( 0x52 == ((const U8*)s)[2] ) ) && ( 0x5F == ((const U8*)s)[3] || inRANGE(((const U8*)s)[3], 0x62, 0x68 ) ) ) ? 4 : 0 )\
: ( ( ( ( ( 0xED == ((const U8*)s)[0] ) && ( 0x6A == ((const U8*)s)[1] ) ) && ( inRANGE(((const U8*)s)[2], 0x41, 0x44 ) ) ) && ( inRANGE(((const U8*)s)[3], 0x41, 0x4A ) || inRANGE(((const U8*)s)[3], 0x51, 0x59 ) || 0x5F == ((const U8*)s)[3] || inRANGE(((const U8*)s)[3], 0x62, 0x6A ) || inRANGE(((const U8*)s)[3], 0x70, 0x72 ) ) ) && ( inRANGE(((const U8*)s)[4], 0x41, 0x4A ) || inRANGE(((const U8*)s)[4], 0x51, 0x59 ) || 0x5F == ((const U8*)s)[4] || inRANGE(((const U8*)s)[4], 0x62, 0x6A ) || inRANGE(((const U8*)s)[4], 0x70, 0x72 ) ) ) ? 5 : 0 )
#define is_SURROGATE_utf8_safe(s,e)                                         \
( ( ( ( ( ( ((e) - (s)) >= 4 ) && ( 0xDD == ((const U8*)s)[0] ) ) && ( inRANGE(((const U8*)s)[1], 0x64, 0x65 ) ) ) && ( inRANGE(((const U8*)s)[2], 0x41, 0x4A ) || inRANGE(((const U8*)s)[2], 0x51, 0x59 ) || 0x5F == ((const U8*)s)[2] || inRANGE(((const U8*)s)[2], 0x62, 0x6A ) || inRANGE(((const U8*)s)[2], 0x70, 0x72 ) ) ) && ( inRANGE(((const U8*)s)[3], 0x41, 0x4A ) || inRANGE(((const U8*)s)[3], 0x51, 0x59 ) || 0x5F == ((const U8*)s)[3] || inRANGE(((const U8*)s)[3], 0x62, 0x6A ) || inRANGE(((const U8*)s)[3], 0x70, 0x72 ) ) ) ? 4 : 0 )
#define is_VERTWS_cp_high(cp)                                               \
( 0x2028 == cp || 0x2029 == cp )
#define is_VERTWS_high(s)                                                   \
( ( ( ( 0xE2 == ((const U8*)s)[0] ) && ( 0x80 == ((const U8*)s)[1] ) ) && ( inRANGE(((const U8*)s)[2], 0xA8, 0xA9 ) ) ) ? 3 : 0 )
#define is_XDIGIT_cp_high(cp)                                               \
( inRANGE(cp, 0xFF10, 0xFF19) || ( 0xFF19 < cp &&                           \
( inRANGE(cp, 0xFF21, 0xFF26) || inRANGE(cp, 0xFF41, 0xFF46) ) ) )
#define is_XDIGIT_high(s)                                                   \
( ( 0xEF == ((const U8*)s)[0] ) ?                                           \
    ( ( 0xBC == ((const U8*)s)[1] ) ?                                       \
	( ( inRANGE(((const U8*)s)[2], 0x90, 0x99 ) || inRANGE(((const U8*)s)[2], 0xA1, 0xA6 ) ) ? 3 : 0 )\
    : ( ( 0xBD == ((const U8*)s)[1] ) && ( inRANGE(((const U8*)s)[2], 0x81, 0x86 ) ) ) ? 3 : 0 )\
: 0 )
#define is_XPERLSPACE_cp_high(cp)                                           \
( 0x1680 == cp || ( 0x1680 < cp &&                                          \
( inRANGE(cp, 0x2000, 0x200A) || ( 0x200A < cp &&                           \
( 0x2028 == cp || ( 0x2028 < cp &&                                          \
( 0x2029 == cp || ( 0x2029 < cp &&                                          \
( 0x202F == cp || ( 0x202F < cp &&                                          \
( 0x205F == cp || 0x3000 == cp ) ) ) ) ) ) ) ) ) ) )
#define is_XPERLSPACE_high(s)                                               \
( ( 0xBD == ((const U8*)s)[0] ) ?                                           \
    ( ( ( 0x62 == ((const U8*)s)[1] ) && ( 0x41 == ((const U8*)s)[2] ) ) ? 3 : 0 )\
: ( 0xCA == ((const U8*)s)[0] ) ?                                           \
    ( ( 0x41 == ((const U8*)s)[1] ) ?                                       \
	( ( inRANGE(((const U8*)s)[2], 0x41, 0x4A ) || 0x51 == ((const U8*)s)[2] ) ? 3 : 0 )\
    : ( 0x42 == ((const U8*)s)[1] ) ?                                       \
	( ( inRANGE(((const U8*)s)[2], 0x49, 0x4A ) || 0x56 == ((const U8*)s)[2] ) ? 3 : 0 )\
    : ( ( 0x43 == ((const U8*)s)[1] ) && ( 0x72 == ((const U8*)s)[2] ) ) ? 3 : 0 )\
: ( ( ( 0xCE == ((const U8*)s)[0] ) && ( 0x41 == ((const U8*)s)[1] ) ) && ( 0x41 == ((const U8*)s)[2] ) ) ? 3 : 0 )
#define Bit(x)			(1 << ((x) % 8))
#define DUP_WARNINGS(p) Perl_dup_warnings(aTHX_ p)
#define IsSet(a, x)		((a)[Off(x)] & Bit(x))
#define Off(x)			((x) / 8)
#define WARN_EXPERIMENTAL__ALPHA_ASSERTIONS 67
#define WARN_EXPERIMENTAL__DECLARED_REFS 66
#define WARN_EXPERIMENTAL__UNIPROP_WILDCARDS 71
#define ckDEAD(x)							\
   (PL_curcop &&                                                        \
    !specialWARN(PL_curcop->cop_warnings) &&			        \
    (isWARNf_on(PL_curcop->cop_warnings, unpackWARN1(x)) ||	        \
      (unpackWARN2(x) &&                                                \
	(isWARNf_on(PL_curcop->cop_warnings, unpackWARN2(x)) ||	        \
	  (unpackWARN3(x) &&                                            \
	    (isWARNf_on(PL_curcop->cop_warnings, unpackWARN3(x)) ||	\
	      (unpackWARN4(x) &&                                        \
		isWARNf_on(PL_curcop->cop_warnings, unpackWARN4(x)))))))))
#define ckWARN(w)		Perl_ckwarn(aTHX_ packWARN(w))
#define ckWARN2(w1,w2)		Perl_ckwarn(aTHX_ packWARN2(w1,w2))
#define ckWARN2_d(w1,w2)	Perl_ckwarn_d(aTHX_ packWARN2(w1,w2))
#define ckWARN3_d(w1,w2,w3)	Perl_ckwarn_d(aTHX_ packWARN3(w1,w2,w3))
#define ckWARN4_d(w1,w2,w3,w4)	Perl_ckwarn_d(aTHX_ packWARN4(w1,w2,w3,w4))
#define ckWARN_d(w)		Perl_ckwarn_d(aTHX_ packWARN(w))
#define isLEXWARN_off \
	cBOOL(!PL_curcop || PL_curcop->cop_warnings == pWARN_STD)
#define isLEXWARN_on \
	cBOOL(PL_curcop && PL_curcop->cop_warnings != pWARN_STD)
#define isWARN_on(c,x)	(IsSet((U8 *)(c + 1), 2*(x)))
#define isWARNf_on(c,x)	(IsSet((U8 *)(c + 1), 2*(x)+1))
#define packWARN(a)		(a                                      )
#define packWARN2(a,b)		((a) | ((b)<<8)                         )
#define packWARN3(a,b,c)	((a) | ((b)<<8) | ((c)<<16)             )
#define packWARN4(a,b,c,d)	((a) | ((b)<<8) | ((c)<<16) | ((d) <<24))
#define specialWARN(x)		((x) == pWARN_STD || (x) == pWARN_ALL ||	\
				 (x) == pWARN_NONE)
#define unpackWARN1(x)		((x)        & 0xFF)
#define unpackWARN2(x)		(((x) >>8)  & 0xFF)
#define unpackWARN3(x)		(((x) >>16) & 0xFF)
#define unpackWARN4(x)		(((x) >>24) & 0xFF)
#define ENTER push_scope()
#define ENTER_with_name(name)						\
    STMT_START {							\
	push_scope();							\
	if (PL_scopestack_name)						\
	    PL_scopestack_name[PL_scopestack_ix-1] = name;		\
	DEBUG_SCOPE("ENTER \"" name "\"")				\
    } STMT_END
#define FREETMPS if (PL_tmps_ix > PL_tmps_floor) free_tmps()
#define LEAVE pop_scope()
#define LEAVE_SCOPE(old) STMT_START { \
	if (PL_savestack_ix > old) leave_scope(old); \
    } STMT_END
#define LEAVE_with_name(name)						\
    STMT_START {							\
	DEBUG_SCOPE("LEAVE \"" name "\"")				\
	if (PL_scopestack_name)	{					\
	    assert(((char*)PL_scopestack_name[PL_scopestack_ix-1]	\
			== (char*)name)					\
		    || strEQ(PL_scopestack_name[PL_scopestack_ix-1], name));        \
	}								\
	pop_scope();							\
    } STMT_END
#define SAVEADELETE(a,k) \
	  save_adelete(MUTABLE_AV(a), (SSize_t)(k))
#define SAVEBOOL(b)	save_bool(&(b))
#define SAVECLEARSV(sv)	save_clearsv((SV**)&(sv))
#define SAVECOMPILEWARNINGS() save_pushptr(PL_compiling.cop_warnings, SAVEt_COMPILE_WARNINGS)
#define SAVECOMPPAD() save_pushptr(MUTABLE_SV(PL_comppad), SAVEt_COMPPAD)
#  define SAVECOPFILE(c)	SAVEPPTR(CopFILE(c))
#  define SAVECOPFILE_FREE(c)	SAVESHAREDPV(CopFILE(c))
#define SAVECOPLINE(c)		SAVEI32(CopLINE(c))
#  define SAVECOPSTASH_FREE(c)	SAVEIV((c)->cop_stashoff)
#define SAVEDELETE(h,k,l) \
	  save_delete(MUTABLE_HV(h), (char*)(k), (I32)(l))
#define SAVEDESTRUCTOR(f,p) \
	  save_destructor((DESTRUCTORFUNC_NOCONTEXT_t)(f), (void*)(p))
#define SAVEDESTRUCTOR_X(f,p) \
	  save_destructor_x((DESTRUCTORFUNC_t)(f), (void*)(p))
#define SAVEFREECOPHH(h)	save_pushptr((void *)(h), SAVEt_FREECOPHH)
#define SAVEFREEOP(o)	save_freeop((OP*)(o))
#define SAVEFREEPADNAME(s) save_pushptr((void *)(s), SAVEt_FREEPADNAME)
#define SAVEFREEPV(p)	save_freepv((char*)(p))
#define SAVEFREESV(s)	save_freesv(MUTABLE_SV(s))
#define SAVEGENERICPV(s)	save_generic_pvref((char**)&(s))
#define SAVEGENERICSV(s)	save_generic_svref((SV**)&(s))
#define SAVEHDELETE(h,s) \
	  save_hdelete(MUTABLE_HV(h), (s))
#define SAVEHINTS()	save_hints()
#define SAVEI16(i)	save_I16((I16*)&(i))
#define SAVEI32(i)	save_I32((I32*)&(i))
#define SAVEI8(i)	save_I8((I8*)&(i))
#define SAVEINT(i)	save_int((int*)&(i))
#define SAVEIV(i)	save_iv((IV*)&(i))
#define SAVELONG(l)	save_long((long*)&(l))
#define SAVEMORTALIZESV(s)	save_mortalizesv(MUTABLE_SV(s))
#define SAVEOP()	save_op()
#define SAVEPADSVANDMORTALIZE(s)	save_padsv_and_mortalize(s)
#define SAVEPARSER(p) save_pushptr((p), SAVEt_PARSER)
#define SAVEPPTR(s)	save_pptr((char**)&(s))
#define SAVESETSVFLAGS(sv,mask,val)	save_set_svflags(sv,mask,val)
#define SAVESHAREDPV(s)		save_shared_pvref((char**)&(s))
#define SAVESPTR(s)	save_sptr((SV**)&(s))
#define SAVESTACK_POS() \
    STMT_START {				   \
        dSS_ADD;                                   \
        SS_ADD_INT(PL_stack_sp - PL_stack_base);   \
        SS_ADD_UV(SAVEt_STACK_POS);                \
        SS_ADD_END(2);                             \
    } STMT_END
#define SAVESWITCHSTACK(f,t) \
    STMT_START {					\
	save_pushptrptr(MUTABLE_SV(f), MUTABLE_SV(t), SAVEt_SAVESWITCHSTACK); \
	SWITCHSTACK((f),(t));				\
	PL_curstackinfo->si_stack = (t);		\
    } STMT_END
#define SAVETMPS Perl_savetmps(aTHX)
#define SAVEVPTR(s)	save_vptr((void*)&(s))
#define SAVEt_PADSV_AND_MORTALIZE 49
#define SCOPE_SAVES_SIGNAL_MASK 0
#define SSCHECK(need) if (UNLIKELY(PL_savestack_ix + (I32)(need) > PL_savestack_max)) savestack_grow()
#define SSGROW(need) if (UNLIKELY(PL_savestack_ix + (I32)(need) > PL_savestack_max)) savestack_grow_cnt(need)
#define SSNEW(size)             Perl_save_alloc(aTHX_ (size), 0)
#define SSNEWa(size,align)	Perl_save_alloc(aTHX_ (size), \
    (I32)(align - ((size_t)((caddr_t)&PL_savestack[PL_savestack_ix]) % align)) % align)
#define SSNEWat(n,t,align)	SSNEWa((n)*sizeof(t), align)
#define SSNEWt(n,t)             SSNEW((n)*sizeof(t))
#define SSPOPBOOL (PL_savestack[--PL_savestack_ix].any_bool)
#define SSPOPDPTR (PL_savestack[--PL_savestack_ix].any_dptr)
#define SSPOPDXPTR (PL_savestack[--PL_savestack_ix].any_dxptr)
#define SSPOPINT (PL_savestack[--PL_savestack_ix].any_i32)
#define SSPOPIV (PL_savestack[--PL_savestack_ix].any_iv)
#define SSPOPLONG (PL_savestack[--PL_savestack_ix].any_long)
#define SSPOPPTR (PL_savestack[--PL_savestack_ix].any_ptr)
#define SSPOPUV (PL_savestack[--PL_savestack_ix].any_uv)
#define SSPTR(off,type)         ((type)  ((char*)PL_savestack + off))
#define SSPTRt(off,type)        ((type*) ((char*)PL_savestack + off))
#define SSPUSHBOOL(p) (PL_savestack[PL_savestack_ix++].any_bool = (p))
#define SSPUSHDPTR(p) (PL_savestack[PL_savestack_ix++].any_dptr = (p))
#define SSPUSHDXPTR(p) (PL_savestack[PL_savestack_ix++].any_dxptr = (p))
#define SSPUSHINT(i) (PL_savestack[PL_savestack_ix++].any_i32 = (I32)(i))
#define SSPUSHIV(i) (PL_savestack[PL_savestack_ix++].any_iv = (IV)(i))
#define SSPUSHLONG(i) (PL_savestack[PL_savestack_ix++].any_long = (long)(i))
#define SSPUSHPTR(p) (PL_savestack[PL_savestack_ix++].any_ptr = (void*)(p))
#define SSPUSHUV(u) (PL_savestack[PL_savestack_ix++].any_uv = (UV)(u))
#define SS_ADD_BOOL(p)  ((ssp++)->any_bool = (p))
#define SS_ADD_DPTR(p)  ((ssp++)->any_dptr = (p))
#define SS_ADD_DXPTR(p) ((ssp++)->any_dxptr = (p))
#define SS_ADD_END(need) \
    assert((need) <= SS_MAXPUSH);                               \
    ix += (need);                                               \
    PL_savestack_ix = ix;                                       \
    assert(ix <= PL_savestack_max + SS_MAXPUSH);                \
    if (UNLIKELY(ix > PL_savestack_max)) savestack_grow();      \
    assert(PL_savestack_ix <= PL_savestack_max);
#define SS_ADD_INT(i)   ((ssp++)->any_i32 = (I32)(i))
#define SS_ADD_IV(i)    ((ssp++)->any_iv = (IV)(i))
#define SS_ADD_LONG(i)  ((ssp++)->any_long = (long)(i))
#define SS_ADD_PTR(p)   ((ssp++)->any_ptr = (void*)(p))
#define SS_ADD_UV(u)    ((ssp++)->any_uv = (UV)(u))
#define SS_MAXPUSH 4
#define dSS_ADD \
    I32 ix = PL_savestack_ix;     \
    ANY *ssp = &PL_savestack[ix]
# define save_freeop(op)                    \
STMT_START {                                 \
      OP * const _o = (OP *)(op);             \
      assert(!_o->op_savefree);               \
      _o->op_savefree = 1;                     \
      save_pushptr((void *)(_o), SAVEt_FREEOP); \
    } STMT_END
#define save_freepv(pv)		save_pushptr((void *)(pv), SAVEt_FREEPV)
#define save_freesv(op)		save_pushptr((void *)(op), SAVEt_FREESV)
#define save_mortalizesv(op)	save_pushptr((void *)(op), SAVEt_MORTALIZESV)
#define save_op()		save_pushptr((void *)(PL_op), SAVEt_OP)
#define MGf_BYTES   0x40        
#define MGf_COPY       8	
#define MGf_DUP     0x10 	
#define MGf_GSKIP      4	
#define MGf_LOCAL   0x20	
#define MGf_MINMATCH   1        
#define MGf_PERSIST    0x80     
#define MGf_REFCOUNTED 2
#define MGf_REQUIRE_GV 1        
#define MGf_TAINTEDDIR 1        
# define MgBYTEPOS(mg,sv,pv,len) S_MgBYTEPOS(aTHX_ mg,sv,pv,len)
# define MgBYTEPOS_set(mg,sv,pv,off) (			 \
    assert_((mg)->mg_type == PERL_MAGIC_regex_global)	  \
    SvPOK(sv) && (!SvGMAGICAL(sv) || sv_only_taint_gmagic(sv))  \
	? (mg)->mg_len = (off), (mg)->mg_flags |= MGf_BYTES \
	: ((mg)->mg_len = DO_UTF8(sv)			     \
	    ? (SSize_t)utf8_length((U8 *)(pv), (U8 *)(pv)+(off)) \
	    : (SSize_t)(off),					  \
	   (mg)->mg_flags &= ~MGf_BYTES))
#define MgPV(mg,lp)		((((int)(lp = (mg)->mg_len)) == HEf_SVKEY) ?   \
				 SvPV(MUTABLE_SV((mg)->mg_ptr),lp) :	\
				 (mg)->mg_ptr)
#define MgPV_const(mg,lp)	((((int)(lp = (mg)->mg_len)) == HEf_SVKEY) ? \
				 SvPV_const(MUTABLE_SV((mg)->mg_ptr),lp) :   \
				 (const char*)(mg)->mg_ptr)
#define MgPV_nolen_const(mg)	(((((int)(mg)->mg_len)) == HEf_SVKEY) ?	\
				 SvPV_nolen_const(MUTABLE_SV((mg)->mg_ptr)) : \
				 (const char*)(mg)->mg_ptr)
#define MgTAINTEDDIR(mg)	(mg->mg_flags & MGf_TAINTEDDIR)
#define MgTAINTEDDIR_off(mg)	(mg->mg_flags &= ~MGf_TAINTEDDIR)
#define MgTAINTEDDIR_on(mg)	(mg->mg_flags |= MGf_TAINTEDDIR)
#define SvTIED_mg(sv,how) (SvRMAGICAL(sv) ? mg_find((sv),(how)) : NULL)
#define SvTIED_obj(sv,mg) \
    ((mg)->mg_obj ? (mg)->mg_obj : sv_2mortal(newRV(sv)))
#define whichsig(pv) whichsig_pv(pv)
#define AvALLOC(av)	((XPVAV*)  SvANY(av))->xav_alloc
#define AvARRAY(av)	((av)->sv_u.svu_array)
#define AvARYLEN(av)	(*Perl_av_arylen_p(aTHX_ MUTABLE_AV(av)))
#define AvFILL(av)	((SvRMAGICAL((const SV *) (av))) \
			 ? mg_size(MUTABLE_SV(av)) : AvFILLp(av))
#define AvFILLp(av)	((XPVAV*)  SvANY(av))->xav_fill
#define AvMAX(av)	((XPVAV*)  SvANY(av))->xav_max
#define AvREAL(av)	(SvFLAGS(av) & SVpav_REAL)
#define AvREALISH(av)	(SvFLAGS(av) & (SVpav_REAL|SVpav_REIFY))
#define AvREAL_off(av)	(SvFLAGS(av) &= ~SVpav_REAL)
#define AvREAL_on(av)	(SvFLAGS(av) |= SVpav_REAL)
#define AvREAL_only(av)	(AvREIFY_off(av), SvFLAGS(av) |= SVpav_REAL)
#define AvREIFY(av)	(SvFLAGS(av) & SVpav_REIFY)
#define AvREIFY_off(av)	(SvFLAGS(av) &= ~SVpav_REIFY)
#define AvREIFY_on(av)	(SvFLAGS(av) |= SVpav_REIFY)
#define AvREIFY_only(av)	(AvREAL_off(av), SvFLAGS(av) |= SVpav_REIFY)
#define NEGATIVE_INDICES_VAR "NEGATIVE_INDICES"
#  define Nullav Null(AV*)
#define av_tindex(av)   av_top_index(av)
#   define av_tindex_skip_len_mg(av)  av_top_index_skip_len_mg(av)
#   define av_top_index_skip_len_mg(av)                                     \
                            (__ASSERT_(SvTYPE(av) == SVt_PVAV) AvFILLp(av))
#define newAV()	MUTABLE_AV(newSV_type(SVt_PVAV))
#define CATCH_SET(v) \
    STMT_START {							\
	DEBUG_l(							\
	    Perl_deb(aTHX_						\
		"JUMPLEVEL set catch %d => %d (for %p) at %s:%d\n",	\
		 PL_top_env->je_mustcatch, v, (void*)PL_top_env,	\
		 "__FILE__", "__LINE__");)					\
	PL_top_env->je_mustcatch = (v);					\
    } STMT_END
#define CHANGE_MULTICALL_FLAGS(the_cv, flags) \
    STMT_START {							\
	CV * const _nOnclAshIngNamE_ = the_cv;				\
	CV * const cv = _nOnclAshIngNamE_;				\
	PADLIST * const padlist = CvPADLIST(cv);			\
        PERL_CONTEXT *cx = CX_CUR();					\
	assert(CxMULTICALL(cx));                                        \
        cx_popsub_common(cx);                                           \
	cx->cx_type = (CXt_SUB|CXp_MULTICALL|flags);                    \
        cx_pushsub(cx, cv, NULL, 0);			                \
        if (!(flags & CXp_SUB_RE_FAKE))                                 \
            CvDEPTH(cv)++;						\
	if (CvDEPTH(cv) >= 2)  						\
	    Perl_pad_push(aTHX_ padlist, CvDEPTH(cv));			\
	PAD_SET_CUR_NOSAVE(padlist, CvDEPTH(cv));			\
	multicall_cop = CvSTART(cv);					\
    } STMT_END
#define CLEAR_ARGARRAY(ary) \
    STMT_START {							\
	AvMAX(ary) += AvARRAY(ary) - AvALLOC(ary);			\
	AvARRAY(ary) = AvALLOC(ary);					\
	AvFILLp(ary) = -1;						\
    } STMT_END
#define COPHH_KEY_UTF8 REFCOUNTED_HE_KEY_UTF8
#define CXINC (cxstack_ix < cxstack_max ? ++cxstack_ix : (cxstack_ix = cxinc()))
#define CX_CUR() (&cxstack[cxstack_ix])
#define CX_DEBUG(cx, action)						\
    DEBUG_l(								\
	Perl_deb(aTHX_ "CX %ld %s %s (scope %ld,%ld) (save %ld,%ld) at %s:%d\n",\
		    (long)cxstack_ix,					\
		    action,						\
		    PL_block_type[CxTYPE(cx)],	                        \
		    (long)PL_scopestack_ix,				\
		    (long)(cx->blk_oldscopesp),		                \
		    (long)PL_savestack_ix,				\
		    (long)(cx->blk_oldsaveix),                          \
		    "__FILE__", "__LINE__"));
#define CX_LEAVE_SCOPE(cx) LEAVE_SCOPE(cx->blk_oldsaveix)
#  define CX_POP(cx)                                                   \
        assert(CX_CUR() == cx);                                        \
        cxstack_ix--;                                                  \
        cx = NULL;
#  define CX_POPSUBST(cx) \
    STMT_START {							\
        REGEXP *re;                                                     \
        assert(CxTYPE(cx) == CXt_SUBST);                                \
	rxres_free(&cx->sb_rxres);					\
	re = cx->sb_rx;                                                 \
	cx->sb_rx = NULL;                                               \
	ReREFCNT_dec(re);                                               \
        SvREFCNT_dec_NN(cx->sb_targ);                                   \
    } STMT_END
#define CX_POP_SAVEARRAY(cx)						\
    STMT_START {							\
        AV *cx_pop_savearray_av = GvAV(PL_defgv);                       \
	GvAV(PL_defgv) = cx->blk_sub.savearray;				\
        cx->blk_sub.savearray = NULL;                                   \
        SvREFCNT_dec(cx_pop_savearray_av);	 			\
    } STMT_END
#  define CX_PUSHSUBST(cx) CXINC, cx = CX_CUR(),		        \
	cx->blk_oldsaveix = oldsave,				        \
	cx->sb_iters		= iters,				\
	cx->sb_maxiters		= maxiters,				\
	cx->sb_rflags		= r_flags,				\
	cx->sb_rxtainted	= rxtainted,				\
	cx->sb_orig		= orig,					\
	cx->sb_dstr		= dstr,					\
	cx->sb_targ		= targ,					\
	cx->sb_s		= s,					\
	cx->sb_m		= m,					\
	cx->sb_strend		= strend,				\
	cx->sb_rxres		= NULL,					\
	cx->sb_rx		= rx,					\
	cx->cx_type		= CXt_SUBST | (once ? CXp_ONCE : 0);	\
	rxres_save(&cx->sb_rxres, rx);					\
	(void)ReREFCNT_inc(rx);						\
        SvREFCNT_inc_void_NN(targ)
#define CX_PUSHSUB_GET_LVALUE_MASK(func) \
		\
		\
	(								\
	   (PL_op->op_flags & OPf_WANT)					\
	       ? OPpENTERSUB_LVAL_MASK					\
	       : !(PL_op->op_private & OPpENTERSUB_LVAL_MASK)		\
	           ? 0 : (U8)func(aTHX)					\
	)
#define CXt_EVAL       11
#define CXt_FORMAT     10
#define CXt_SUBST      12
#  define CopFILE(c)		((c)->cop_file)
#  define CopFILEAV(c)		(CopFILE(c) \
				 ? GvAV(gv_fetchfile(CopFILE(c))) : NULL)
#    define CopFILEAVx(c)	(assert(CopFILEGV(c)), GvAV(CopFILEGV(c)))
#  define CopFILEGV(c)		(CopFILE(c) \
				 ? gv_fetchfile(CopFILE(c)) : NULL)
#  define CopFILEGV_set(c,gv)	((c)->cop_filegv = (GV*)SvREFCNT_inc(gv))
#  define CopFILESV(c)		(CopFILE(c) \
				 ? GvSV(gv_fetchfile(CopFILE(c))) : NULL)
#    define CopFILE_free(c) SAVECOPFILE_FREE(c)
#    define CopFILE_set(c,pv)	((c)->cop_file = savepv(pv))
#    define CopFILE_setn(c,pv,l)  ((c)->cop_file = savepvn((pv),(l)))
#define CopHINTHASH_get(c)	((COPHH*)((c)->cop_hints_hash))
#define CopHINTHASH_set(c,h)	((c)->cop_hints_hash = (h))
#define CopHINTS_get(c)		((c)->cop_hints + 0)
#define CopHINTS_set(c, h)	STMT_START {				\
				    (c)->cop_hints = (h);		\
				} STMT_END
#define CopLABEL(c)  Perl_cop_fetch_label(aTHX_ (c), NULL, NULL)
#define CopLABEL_alloc(pv)	((pv)?savepv(pv):NULL)
#define CopLABEL_len(c,len)  Perl_cop_fetch_label(aTHX_ (c), len, NULL)
#define CopLABEL_len_flags(c,len,flags)  Perl_cop_fetch_label(aTHX_ (c), len, flags)
#define CopLINE(c)		((c)->cop_line)
#define CopLINE_dec(c)		(--CopLINE(c))
#define CopLINE_inc(c)		(++CopLINE(c))
#define CopLINE_set(c,l)	(CopLINE(c) = (l))
#  define CopSTASH(c)           PL_stashpad[(c)->cop_stashoff]
#define CopSTASHPV(c)		(CopSTASH(c) ? HvNAME_get(CopSTASH(c)) : NULL)
#define CopSTASHPV_set(c,pv)	CopSTASH_set((c), gv_stashpv(pv,GV_ADD))
#define CopSTASH_eq(c,hv)	(CopSTASH(c) == (hv))
#define CopSTASH_ne(c,hv)	(!CopSTASH_eq(c,hv))
#  define CopSTASH_set(c,hv)	((c)->cop_stashoff = (hv)		\
				    ? alloccopstash(hv)			\
				    : 0)
#define CxEVAL_TXT_REFCNTED(cx)	(((cx)->blk_u16) & 0x40) 
#define CxFOREACH(c)	(   CxTYPE(cx) >= CXt_LOOP_ARY                  \
                         && CxTYPE(cx) <= CXt_LOOP_LIST)
#define CxHASARGS(c)	(((c)->cx_type & CXp_HASARGS) == CXp_HASARGS)
#define CxITERVAR(c)                                    \
        (CxPADLOOP(c)                                   \
            ? (c)->blk_loop.itervar_u.svp               \
            : ((c)->cx_type & CXp_FOR_GV)               \
                ? &GvSV((c)->blk_loop.itervar_u.gv)     \
                : (SV **)&(c)->blk_loop.itervar_u.gv)
#define CxLABEL(c)	(0 + CopLABEL((c)->blk_oldcop))
#define CxLABEL_len(c,len)	(0 + CopLABEL_len((c)->blk_oldcop, len))
#define CxLABEL_len_flags(c,len,flags)	(0 + CopLABEL_len_flags((c)->blk_oldcop, len, flags))
#define CxLVAL(c)	(0 + ((c)->blk_u16 & 0xff))
#define CxMULTICALL(c)	((c)->cx_type & CXp_MULTICALL)
#define CxOLD_IN_EVAL(cx)	(((cx)->blk_u16) & 0x3F) 
#define CxOLD_OP_TYPE(cx)	(((cx)->blk_u16) >> 7)   
#define CxONCE(cx)		((cx)->cx_type & CXp_ONCE)
#define CxPADLOOP(c)	((c)->cx_type & CXp_FOR_PAD)
#define CxREALEVAL(c)	(((c)->cx_type & (CXTYPEMASK|CXp_REAL))		\
			 == (CXt_EVAL|CXp_REAL))
#define CxTRYBLOCK(c)	(((c)->cx_type & (CXTYPEMASK|CXp_TRYBLOCK))	\
			 == (CXt_EVAL|CXp_TRYBLOCK))
#define CxTYPE(c)	((c)->cx_type & CXTYPEMASK)
#define CxTYPE_is_LOOP(c) (   CxTYPE(cx) >= CXt_LOOP_ARY                \
                           && CxTYPE(cx) <= CXt_LOOP_PLAIN)
#define EVAL_RE_REPARSING 0x10	
#define G_FAKINGEVAL  256	
#define G_KEEPERR      32	
#define G_METHOD      128       
#define G_METHOD_NAMED 4096	
#define G_NOARGS       16	
#define G_NODEBUG      64	
#define G_RE_REPARSING 0x800     
#define G_UNDEF_FILL  512	
#define G_WRITING_TO_STDERR 1024 
#  define JE_OLD_STACK_HWM_restore(je)  \
        if (PL_curstackinfo->si_stack_hwm < (je).je_old_stack_hwm) \
            PL_curstackinfo->si_stack_hwm = (je).je_old_stack_hwm
#  define JE_OLD_STACK_HWM_save(je)  \
        (je).je_old_stack_hwm = PL_curstackinfo->si_stack_hwm
#  define JE_OLD_STACK_HWM_zero      PL_start_env.je_old_stack_hwm = 0
#define JMPENV_BOOTSTRAP \
    STMT_START {				\
	PERL_POISON_EXPR(PoisonNew(&PL_start_env, 1, JMPENV));\
	PL_top_env = &PL_start_env;		\
	PL_start_env.je_prev = NULL;		\
	PL_start_env.je_ret = -1;		\
	PL_start_env.je_mustcatch = TRUE;	\
	PL_start_env.je_old_delaymagic = 0;	\
        JE_OLD_STACK_HWM_zero;                  \
    } STMT_END
#define JMPENV_JUMP(v) \
    STMT_START {						\
	DEBUG_l({						\
	    int i = -1; JMPENV *p = PL_top_env;			\
	    while (p) { i++; p = p->je_prev; }			\
	    Perl_deb(aTHX_ "JUMPENV_JUMP(%d) level=%d at %s:%d\n", \
		         (int)v, i, "__FILE__", "__LINE__");})	\
	if (PL_top_env->je_prev)				\
	    PerlProc_longjmp(PL_top_env->je_buf, (v));		\
	if ((v) == 2)						\
	    PerlProc_exit(STATUS_EXIT);		                \
	PerlIO_printf(PerlIO_stderr(), "panic: top_env, v=%d\n", (int)v); \
	PerlProc_exit(1);					\
    } STMT_END
#define JMPENV_POP \
    STMT_START {							\
	DEBUG_l({							\
	    int i = -1; JMPENV *p = PL_top_env;				\
	    while (p) { i++; p = p->je_prev; }				\
	    Perl_deb(aTHX_ "JUMPENV_POP level=%d at %s:%d\n",		\
		         i, "__FILE__", "__LINE__");})			\
	assert(PL_top_env == &cur_env);					\
	PL_delaymagic = cur_env.je_old_delaymagic;			\
	PL_top_env = cur_env.je_prev;					\
    } STMT_END
#define JMPENV_PUSH(v) \
    STMT_START {							\
	DEBUG_l({							\
	    int i = 0; JMPENV *p = PL_top_env;				\
	    while (p) { i++; p = p->je_prev; }				\
	    Perl_deb(aTHX_ "JUMPENV_PUSH level=%d at %s:%d\n",		\
		         i,  "__FILE__", "__LINE__");})			\
	cur_env.je_prev = PL_top_env;					\
        JE_OLD_STACK_HWM_save(cur_env);                                 \
	cur_env.je_ret = PerlProc_setjmp(cur_env.je_buf, SCOPE_SAVES_SIGNAL_MASK);		\
        JE_OLD_STACK_HWM_restore(cur_env);                              \
	PL_top_env = &cur_env;						\
	cur_env.je_mustcatch = FALSE;					\
	cur_env.je_old_delaymagic = PL_delaymagic;			\
	(v) = cur_env.je_ret;						\
    } STMT_END
#define MULTICALL \
    STMT_START {							\
	PL_op = multicall_cop;						\
	CALLRUNOPS(aTHX);						\
    } STMT_END
#define OutCopFILE(c) CopFILE(c)
#define PERLSI_MULTICALL       10
#define POPSTACK \
    STMT_START {							\
	dSP;								\
	PERL_SI * const prev = PL_curstackinfo->si_prev;		\
	DEBUG_l({							\
	    int i = -1; PERL_SI *p = PL_curstackinfo;			\
	    while (p) { i++; p = p->si_prev; }				\
	    Perl_deb(aTHX_ "pop  STACKINFO %d at %s:%d\n",		\
		         i, "__FILE__", "__LINE__");})			\
	if (!prev) {							\
	    Perl_croak_popstack();					\
	}								\
	SWITCHSTACK(PL_curstack,prev->si_stack);			\
			\
	PL_curstackinfo = prev;						\
    } STMT_END
#define POPSTACK_TO(s) \
    STMT_START {							\
	while (PL_curstack != s) {					\
	    dounwind(-1);						\
	    POPSTACK;							\
	}								\
    } STMT_END
#define POP_MULTICALL \
    STMT_START {							\
        PERL_CONTEXT *cx;						\
	cx = CX_CUR();					                \
	CX_LEAVE_SCOPE(cx);                                             \
        cx_popsub_common(cx);                                           \
        gimme = cx->blk_gimme;                                          \
        PERL_UNUSED_VAR(gimme);                            \
	cx_popblock(cx);				   		\
	CX_POP(cx);                                                     \
	POPSTACK;							\
	CATCH_SET(multicall_oldcatch);					\
	SPAGAIN;							\
    } STMT_END
#define PUSHSTACK PUSHSTACKi(PERLSI_UNKNOWN)
#  define PUSHSTACK_INIT_HWM(si) ((si)->si_stack_hwm = 0)
#define PUSHSTACKi(type) \
    STMT_START {							\
	PERL_SI *next = PL_curstackinfo->si_next;			\
	DEBUG_l({							\
	    int i = 0; PERL_SI *p = PL_curstackinfo;			\
	    while (p) { i++; p = p->si_prev; }				\
	    Perl_deb(aTHX_ "push STACKINFO %d at %s:%d\n",		\
		         i, "__FILE__", "__LINE__");})			\
	if (!next) {							\
	    next = new_stackinfo(32, 2048/sizeof(PERL_CONTEXT) - 1);	\
	    next->si_prev = PL_curstackinfo;				\
	    PL_curstackinfo->si_next = next;				\
	}								\
	next->si_type = type;						\
	next->si_cxix = -1;						\
        PUSHSTACK_INIT_HWM(next);                                       \
	AvFILLp(next->si_stack) = 0;					\
	SWITCHSTACK(PL_curstack,next->si_stack);			\
	PL_curstackinfo = next;						\
	SET_MARK_OFFSET;						\
    } STMT_END
#define PUSH_MULTICALL(the_cv) \
    PUSH_MULTICALL_FLAGS(the_cv, 0)
#define PUSH_MULTICALL_FLAGS(the_cv, flags) \
    STMT_START {							\
        PERL_CONTEXT *cx;						\
	CV * const _nOnclAshIngNamE_ = the_cv;				\
	CV * const cv = _nOnclAshIngNamE_;				\
	PADLIST * const padlist = CvPADLIST(cv);			\
 	multicall_oldcatch = CATCH_GET;					\
	CATCH_SET(TRUE);						\
	PUSHSTACKi(PERLSI_MULTICALL);					\
	cx = cx_pushblock((CXt_SUB|CXp_MULTICALL|flags), (U8)gimme,     \
                  PL_stack_sp, PL_savestack_ix);	                \
        cx_pushsub(cx, cv, NULL, 0);                                    \
	SAVEOP();					                \
        if (!(flags & CXp_SUB_RE_FAKE))                                 \
            CvDEPTH(cv)++;						\
	if (CvDEPTH(cv) >= 2)  						\
	    Perl_pad_push(aTHX_ padlist, CvDEPTH(cv));			\
	PAD_SET_CUR_NOSAVE(padlist, CvDEPTH(cv));			\
	multicall_cop = CvSTART(cv);					\
    } STMT_END
#define blk_old_tmpsfloor cx_u.cx_blk.blku_old_tmpsfloor
#define blk_oldsaveix   cx_u.cx_blk.blku_oldsaveix
#define cop_hints_2hv(cop, flags) \
    cophh_2hv(CopHINTHASH_get(cop), flags)
#define cop_hints_fetch_pv(cop, key, hash, flags) \
    cophh_fetch_pv(CopHINTHASH_get(cop), key, hash, flags)
#define cop_hints_fetch_pvn(cop, keypv, keylen, hash, flags) \
    cophh_fetch_pvn(CopHINTHASH_get(cop), keypv, keylen, hash, flags)
#define cop_hints_fetch_pvs(cop, key, flags) \
    cophh_fetch_pvs(CopHINTHASH_get(cop), key, flags)
#define cop_hints_fetch_sv(cop, key, hash, flags) \
    cophh_fetch_sv(CopHINTHASH_get(cop), key, hash, flags)
#define cophh_2hv(cophh, flags) \
    Perl_refcounted_he_chain_2hv(aTHX_ cophh, flags)
#define cophh_copy(cophh) Perl_refcounted_he_inc(aTHX_ cophh)
#define cophh_delete_pv(cophh, key, hash, flags) \
    Perl_refcounted_he_new_pv(aTHX_ cophh, key, hash, (SV *)NULL, flags)
#define cophh_delete_pvn(cophh, keypv, keylen, hash, flags) \
    Perl_refcounted_he_new_pvn(aTHX_ cophh, keypv, keylen, hash, \
	(SV *)NULL, flags)
#define cophh_delete_pvs(cophh, key, flags) \
    Perl_refcounted_he_new_pvn(aTHX_ cophh, STR_WITH_LEN(key), 0, \
	(SV *)NULL, flags)
#define cophh_delete_sv(cophh, key, hash, flags) \
    Perl_refcounted_he_new_sv(aTHX_ cophh, key, hash, (SV *)NULL, flags)
#define cophh_fetch_pv(cophh, key, hash, flags) \
    Perl_refcounted_he_fetch_pv(aTHX_ cophh, key, hash, flags)
#define cophh_fetch_pvn(cophh, keypv, keylen, hash, flags) \
    Perl_refcounted_he_fetch_pvn(aTHX_ cophh, keypv, keylen, hash, flags)
#define cophh_fetch_pvs(cophh, key, flags) \
    Perl_refcounted_he_fetch_pvn(aTHX_ cophh, STR_WITH_LEN(key), 0, flags)
#define cophh_fetch_sv(cophh, key, hash, flags) \
    Perl_refcounted_he_fetch_sv(aTHX_ cophh, key, hash, flags)
#define cophh_free(cophh) Perl_refcounted_he_free(aTHX_ cophh)
#define cophh_new_empty() ((COPHH *)NULL)
#define cophh_store_pv(cophh, key, hash, value, flags) \
    Perl_refcounted_he_new_pv(aTHX_ cophh, key, hash, value, flags)
#define cophh_store_pvn(cophh, keypv, keylen, hash, value, flags) \
    Perl_refcounted_he_new_pvn(aTHX_ cophh, keypv, keylen, hash, value, flags)
#define cophh_store_pvs(cophh, key, value, flags) \
    Perl_refcounted_he_new_pvn(aTHX_ cophh, STR_WITH_LEN(key), 0, value, flags)
#define cophh_store_sv(cophh, key, hash, value, flags) \
    Perl_refcounted_he_new_sv(aTHX_ cophh, key, hash, value, flags)
#define cx_type cx_u.cx_subst.sbu_type
#define cxstack		(PL_curstackinfo->si_cxstack)
#define dMULTICALL \
    OP  *multicall_cop;							\
    bool multicall_oldcatch
#  define PERL_DTRACE_PROBE_ENTRY(cv)               \
    if (PERL_SUB_ENTRY_ENABLED())                   \
        Perl_dtrace_probe_call(aTHX_ cv, TRUE);
#  define PERL_DTRACE_PROBE_FILE_LOADED(name)       \
    if (PERL_SUB_ENTRY_ENABLED())                   \
        Perl_dtrace_probe_load(aTHX_ name, FALSE);
#  define PERL_DTRACE_PROBE_FILE_LOADING(name)      \
    if (PERL_SUB_ENTRY_ENABLED())                   \
        Perl_dtrace_probe_load(aTHX_ name, TRUE);
#  define PERL_DTRACE_PROBE_OP(op)                  \
    if (PERL_OP_ENTRY_ENABLED())                    \
        Perl_dtrace_probe_op(aTHX_ op);
#  define PERL_DTRACE_PROBE_PHASE(phase)            \
    if (PERL_OP_ENTRY_ENABLED())                    \
        Perl_dtrace_probe_phase(aTHX_ phase);
#  define PERL_DTRACE_PROBE_RETURN(cv)              \
    if (PERL_SUB_ENTRY_ENABLED())                   \
        Perl_dtrace_probe_call(aTHX_ cv, FALSE);
#define HEK_FLAGS(hek)	(*((unsigned char *)(HEK_KEY(hek))+HEK_LEN(hek)+1))
#define HEK_HASH(hek)		(hek)->hek_hash
#define HEK_KEY(hek)		(hek)->hek_key
#define HEK_LEN(hek)		(hek)->hek_len
#define HEK_UTF8(hek)		(HEK_FLAGS(hek) & HVhek_UTF8)
#define HEK_UTF8_off(hek)	(HEK_FLAGS(hek) &= ~HVhek_UTF8)
#define HEK_UTF8_on(hek)	(HEK_FLAGS(hek) |= HVhek_UTF8)
#define HEK_WASUTF8(hek)	(HEK_FLAGS(hek) & HVhek_WASUTF8)
#define HEK_WASUTF8_off(hek)	(HEK_FLAGS(hek) &= ~HVhek_WASUTF8)
#define HEK_WASUTF8_on(hek)	(HEK_FLAGS(hek) |= HVhek_WASUTF8)
#define HVhek_ENABLEHVKFLAGS        (HVhek_MASK & ~(HVhek_UNSHARED))
#define HVhek_KEYCANONICAL 0x400 
#define HVrhek_typemask 0x70
#define HeHASH(he)		HEK_HASH(HeKEY_hek(he))
#define HeKEY(he)		HEK_KEY(HeKEY_hek(he))
#define HeKEY_hek(he)		(he)->hent_hek
#define HeKEY_sv(he)		(*(SV**)HeKEY(he))
#define HeKFLAGS(he)  HEK_FLAGS(HeKEY_hek(he))
#define HeKLEN(he)		HEK_LEN(HeKEY_hek(he))
#define HeKLEN_UTF8(he)  (HeKUTF8(he) ? -HeKLEN(he) : HeKLEN(he))
#define HeKUTF8(he)  HEK_UTF8(HeKEY_hek(he))
#define HeKWASUTF8(he)  HEK_WASUTF8(HeKEY_hek(he))
#define HeNEXT(he)		(he)->hent_next
#define HePV(he,lp)		((HeKLEN(he) == HEf_SVKEY) ?		\
				 SvPV(HeKEY_sv(he),lp) :		\
				 ((lp = HeKLEN(he)), HeKEY(he)))
#define HeSVKEY(he)		((HeKEY(he) && 				\
				  HeKLEN(he) == HEf_SVKEY) ?		\
				 HeKEY_sv(he) : NULL)
#define HeSVKEY_force(he)	(HeKEY(he) ?				\
				 ((HeKLEN(he) == HEf_SVKEY) ?		\
				  HeKEY_sv(he) :			\
				  newSVpvn_flags(HeKEY(he),		\
                                                 HeKLEN(he),            \
                                                 SVs_TEMP |             \
                                      ( HeKUTF8(he) ? SVf_UTF8 : 0 ))) : \
				 &PL_sv_undef)
#define HeSVKEY_set(he,sv)	((HeKLEN(he) = HEf_SVKEY), (HeKEY_sv(he) = sv))
#define HeUTF8(he)		((HeKLEN(he) == HEf_SVKEY) ?		\
				 SvUTF8(HeKEY_sv(he)) :			\
				 (U32)HeKUTF8(he))
#define HeVAL(he)		(he)->he_valu.hent_val
#define HvARRAY(hv)	((hv)->sv_u.svu_hash)
#define HvAUX(hv)	((struct xpvhv_aux*)&(HvARRAY(hv)[HvMAX(hv)+1]))
#define HvAUXf_NO_DEREF     0x2   
#define HvAUXf_SCAN_STASH   0x1   
#define HvEITER(hv)	(*Perl_hv_eiter_p(aTHX_ MUTABLE_HV(hv)))
#define HvEITER_get(hv)	(SvOOK(hv) ? HvAUX(hv)->xhv_eiter : NULL)
#define HvEITER_set(hv,e)	Perl_hv_eiter_set(aTHX_ MUTABLE_HV(hv), e)
#define HvENAMELEN(hv)  HvENAMELEN_get(hv)
#define HvENAMELEN_get(hv) \
   ((SvOOK(hv) && HvAUX(hv)->xhv_name_u.xhvnameu_name && HvAUX(hv)->xhv_name_count != -1) \
				 ? HEK_LEN(HvENAME_HEK_NN(hv)) : 0)
#define HvENAMEUTF8(hv) \
   ((SvOOK(hv) && HvAUX(hv)->xhv_name_u.xhvnameu_name && HvAUX(hv)->xhv_name_count != -1) \
				 ? HEK_UTF8(HvENAME_HEK_NN(hv)) : 0)
#define HvENAME_HEK(hv) \
	(SvOOK(hv) && HvAUX(hv)->xhv_name_u.xhvnameu_name ? HvENAME_HEK_NN(hv) : NULL)
#define HvENAME_HEK_NN(hv)                                             \
 (                                                                      \
  HvAUX(hv)->xhv_name_count > 0   ? HvAUX(hv)->xhv_name_u.xhvnameu_names[0] : \
  HvAUX(hv)->xhv_name_count < -1  ? HvAUX(hv)->xhv_name_u.xhvnameu_names[1] : \
  HvAUX(hv)->xhv_name_count == -1 ? NULL                              : \
                                    HvAUX(hv)->xhv_name_u.xhvnameu_name \
 )
#define HvENAME_get(hv) \
   ((SvOOK(hv) && HvAUX(hv)->xhv_name_u.xhvnameu_name && HvAUX(hv)->xhv_name_count != -1) \
			 ? HEK_KEY(HvENAME_HEK_NN(hv)) : NULL)
#define HvFILL(hv)	Perl_hv_fill(aTHX_ MUTABLE_HV(hv))
#define HvHASKFLAGS(hv)		(SvFLAGS(hv) & SVphv_HASKFLAGS)
#define HvHASKFLAGS_off(hv)	(SvFLAGS(hv) &= ~SVphv_HASKFLAGS)
#define HvHASKFLAGS_on(hv)	(SvFLAGS(hv) |= SVphv_HASKFLAGS)
#define HvKEYS(hv)		HvUSEDKEYS(hv)
#define HvLASTRAND_get(hv)	(SvOOK(hv) ? HvAUX(hv)->xhv_last_rand : 0)
#define HvLAZYDEL(hv)		(SvFLAGS(hv) & SVphv_LAZYDEL)
#define HvLAZYDEL_off(hv)	(SvFLAGS(hv) &= ~SVphv_LAZYDEL)
#define HvLAZYDEL_on(hv)	(SvFLAGS(hv) |= SVphv_LAZYDEL)
#define HvMAX(hv)	((XPVHV*)  SvANY(hv))->xhv_max
#define HvMROMETA(hv) (HvAUX(hv)->xhv_mro_meta \
                       ? HvAUX(hv)->xhv_mro_meta \
                       : Perl_mro_meta_init(aTHX_ hv))
#define HvNAMELEN(hv)   HvNAMELEN_get(hv)
#define HvNAMELEN_get(hv) \
	((SvOOK(hv) && HvAUX(hv)->xhv_name_u.xhvnameu_name && HvNAME_HEK_NN(hv)) \
				 ? HEK_LEN(HvNAME_HEK_NN(hv)) : 0)
#define HvNAMEUTF8(hv) \
	((SvOOK(hv) && HvAUX(hv)->xhv_name_u.xhvnameu_name && HvNAME_HEK_NN(hv)) \
				 ? HEK_UTF8(HvNAME_HEK_NN(hv)) : 0)
#define HvNAME_HEK(hv) \
	(SvOOK(hv) && HvAUX(hv)->xhv_name_u.xhvnameu_name ? HvNAME_HEK_NN(hv) : NULL)
#define HvNAME_HEK_NN(hv)			  \
 (						  \
  HvAUX(hv)->xhv_name_count			  \
  ? *HvAUX(hv)->xhv_name_u.xhvnameu_names	  \
  : HvAUX(hv)->xhv_name_u.xhvnameu_name		  \
 )
#define HvNAME_get(hv) \
	((SvOOK(hv) && HvAUX(hv)->xhv_name_u.xhvnameu_name && HvNAME_HEK_NN(hv)) \
			 ? HEK_KEY(HvNAME_HEK_NN(hv)) : NULL)
#define HvPLACEHOLDERS(hv)	(*Perl_hv_placeholders_p(aTHX_ MUTABLE_HV(hv)))
#define HvPLACEHOLDERS_get(hv)	(SvMAGIC(hv) ? Perl_hv_placeholders_get(aTHX_ (const HV *)hv) : 0)
#define HvPLACEHOLDERS_set(hv,p)	Perl_hv_placeholders_set(aTHX_ MUTABLE_HV(hv), p)
#define HvRAND_get(hv)	(SvOOK(hv) ? HvAUX(hv)->xhv_rand : 0)
#define HvRITER(hv)	(*Perl_hv_riter_p(aTHX_ MUTABLE_HV(hv)))
#define HvRITER_get(hv)	(SvOOK(hv) ? HvAUX(hv)->xhv_riter : -1)
#define HvRITER_set(hv,r)	Perl_hv_riter_set(aTHX_ MUTABLE_HV(hv), r)
#define HvSHAREKEYS(hv)		(SvFLAGS(hv) & SVphv_SHAREKEYS)
#define HvSHAREKEYS_off(hv)	(SvFLAGS(hv) &= ~SVphv_SHAREKEYS)
#define HvSHAREKEYS_on(hv)	(SvFLAGS(hv) |= SVphv_SHAREKEYS)
#define HvTOTALKEYS(hv)		XHvTOTALKEYS((XPVHV*)  SvANY(hv))
#define HvUSEDKEYS(hv)		(HvTOTALKEYS(hv) - HvPLACEHOLDERS_get(hv))
#  define MALLOC_OVERHEAD 16
#define MRO_GET_PRIVATE_DATA(smeta, which)		   \
    (((smeta)->mro_which && (which) == (smeta)->mro_which) \
     ? (smeta)->mro_linear_current			   \
     : Perl_mro_get_private_data(aTHX_ (smeta), (which)))
#  define Nullhe Null(HE*)
#  define Nullhek Null(HEK*)
#  define Nullhv Null(HV*)
#define PERL_HASH_DEFAULT_HvMAX 7
#   define PERL_HASH_ITER_BUCKET(iter)      ((iter)->xhv_riter)
#   define PERL_HASH_RANDOMIZE_KEYS         1
#define PERL_HV_ALLOC_AUX_SIZE (1 << 9)
#  define PERL_HV_ARRAY_ALLOC_BYTES(size) ((size) * sizeof(HE*))
#       define PL_HASH_RAND_BITS_ENABLED    1
#define Perl_sharepvn(pv, len, hash) HEK_KEY(share_hek(pv, len, hash))
#define REF_HE_KEY(chain)						\
	((((chain->refcounted_he_data[0] & 0x60) == 0x40)		\
	    ? chain->refcounted_he_val.refcounted_he_u_len + 1 : 0)	\
	 + 1 + chain->refcounted_he_data)
#       define USE_PERL_PERTURB_KEYS        1
#define XHvTOTALKEYS(xhv)	((xhv)->xhv_keys)
#define hv_delete(hv, key, klen, flags)					\
    (MUTABLE_SV(hv_common_key_len((hv), (key), (klen),			\
				  (flags) | HV_DELETE, NULL, 0)))
#define hv_delete_ent(hv, key, flags, hash)				\
    (MUTABLE_SV(hv_common((hv), (key), NULL, 0, 0, (flags) | HV_DELETE,	\
			  NULL, (hash))))
# define hv_deletehek(hv, hek, flags) \
    hv_common((hv), NULL, HEK_KEY(hek), HEK_LEN(hek), HEK_UTF8(hek), \
	      (flags)|HV_DELETE, NULL, HEK_HASH(hek))
#define hv_deletes(hv, key, flags) \
    hv_delete((hv), ("" key ""), (sizeof(key)-1), (flags))
#define hv_exists(hv, key, klen)					\
    cBOOL(hv_common_key_len((hv), (key), (klen), HV_FETCH_ISEXISTS, NULL, 0))
#define hv_exists_ent(hv, keysv, hash)					\
    cBOOL(hv_common((hv), (keysv), NULL, 0, 0, HV_FETCH_ISEXISTS, 0, (hash)))
#define hv_existss(hv, key) \
    hv_exists((hv), ("" key ""), (sizeof(key)-1))
#define hv_fetch(hv, key, klen, lval)					\
    ((SV**) hv_common_key_len((hv), (key), (klen), (lval)		\
			      ? (HV_FETCH_JUST_SV | HV_FETCH_LVALUE)	\
			      : HV_FETCH_JUST_SV, NULL, 0))
#define hv_fetch_ent(hv, keysv, lval, hash)				\
    ((HE *) hv_common((hv), (keysv), NULL, 0, 0,			\
		      ((lval) ? HV_FETCH_LVALUE : 0), NULL, (hash)))
# define hv_fetchhek(hv, hek, lval) \
    ((SV **)								\
     hv_common((hv), NULL, HEK_KEY(hek), HEK_LEN(hek), HEK_UTF8(hek),	\
	       (lval)							\
		? (HV_FETCH_JUST_SV | HV_FETCH_LVALUE)			\
		: HV_FETCH_JUST_SV,					\
	       NULL, HEK_HASH(hek)))
#define hv_fetchs(hv, key, lval) \
    hv_fetch((hv), ("" key ""), (sizeof(key)-1), (lval))
#define hv_magic(hv, gv, how) sv_magic(MUTABLE_SV(hv), MUTABLE_SV(gv), how, NULL, 0)
#define hv_name_sets(hv, name, flags) \
    hv_name_set((hv),("" name ""),(sizeof(name)-1), flags)
#define hv_store(hv, key, klen, val, hash)				\
    ((SV**) hv_common_key_len((hv), (key), (klen),			\
			      (HV_FETCH_ISSTORE|HV_FETCH_JUST_SV),	\
			      (val), (hash)))
#define hv_store_ent(hv, keysv, val, hash)				\
    ((HE *) hv_common((hv), (keysv), NULL, 0, 0, HV_FETCH_ISSTORE,	\
		      (val), (hash)))
#define hv_store_flags(hv, key, klen, val, hash, flags)			\
    ((SV**) hv_common((hv), NULL, (key), (klen), (flags),		\
		      (HV_FETCH_ISSTORE|HV_FETCH_JUST_SV), (val),	\
		      (hash)))
# define hv_storehek(hv, hek, val) \
    hv_common((hv), NULL, HEK_KEY(hek), HEK_LEN(hek), HEK_UTF8(hek),	\
	      HV_FETCH_ISSTORE|HV_FETCH_JUST_SV, (val), HEK_HASH(hek))
#define hv_stores(hv, key, val) \
    hv_store((hv), ("" key ""), (sizeof(key)-1), (val), 0)
#define hv_undef(hv) Perl_hv_undef_flags(aTHX_ hv, 0)
#define newHV()	MUTABLE_HV(newSV_type(SVt_PVHV))
#define refcounted_he_fetch_pvs(chain, key, flags) \
    Perl_refcounted_he_fetch_pvn(aTHX_ chain, STR_WITH_LEN(key), 0, flags)
#define refcounted_he_new_pvs(parent, key, value, flags) \
    Perl_refcounted_he_new_pvn(aTHX_ parent, STR_WITH_LEN(key), 0, value, flags)
#define share_hek_hek(hek)						\
    (++(((struct shared_he *)(((char *)hek)				\
			      - STRUCT_OFFSET(struct shared_he,		\
					      shared_he_hek)))		\
	->shared_he_he.he_valu.hent_refcount),				\
     hek)
#define sharepvn(pv, len, hash)	     Perl_sharepvn(pv, len, hash)
#define PERL_HASH(state,str,len) \
    (hash) = ((len) < 2 ? ( (len) == 0 ? PL_hash_chars[256] : PL_hash_chars[(U8)(str)[0]] ) \
                       : _PERL_HASH_WITH_STATE(PL_hash_state,(U8*)(str),(len)))
#define PERL_HASH_FUNC        _PERL_HASH_FUNC
#       define PERL_HASH_FUNC_STADTX
#       define PERL_HASH_FUNC_ZAPHOD32
#define PERL_HASH_INTERNAL(hash,str,len) PERL_HASH(hash,str,len)
#       define PERL_HASH_SEED PL_hash_seed
#define PERL_HASH_SEED_BYTES _PERL_HASH_SEED_BYTES
#define PERL_HASH_SEED_STATE(seed,state) _PERL_HASH_SEED_STATE(seed,state)
#define PERL_HASH_STATE_BYTES _PERL_HASH_STATE_BYTES
#define PERL_HASH_USE_SBOX32_ALSO 1
#define PERL_HASH_WITH_SEED(seed,hash,str,len) \
    (hash) = S_perl_hash_with_seed((const U8 *) seed, (const U8 *) str,len)
#define PERL_HASH_WITH_STATE(state,hash,str,len) \
    (hash) = _PERL_HASH_WITH_STATE((state),(U8*)(str),(len))

#define PERL_SIPHASH_FNC(FNC,SIP_ROUNDS,SIP_FINAL_ROUNDS) \
PERL_STATIC_INLINE U32 \
FNC ## _with_state \
  (const unsigned char * const state, const unsigned char *in, const STRLEN inlen) \
{                                           \
  const int left = inlen & 7;               \
  const U8 *end = in + inlen - left;        \
                                            \
  U64 b = ( ( U64 )(inlen) ) << 56;         \
  U64 m;                                    \
  U64 v0 = U8TO64_LE(state);                \
  U64 v1 = U8TO64_LE(state+8);              \
  U64 v2 = U8TO64_LE(state+16);             \
  U64 v3 = U8TO64_LE(state+24);             \
                                            \
  for ( ; in != end; in += 8 )              \
  {                                         \
    m = U8TO64_LE( in );                    \
    v3 ^= m;                                \
                                            \
    SIP_ROUNDS;                             \
                                            \
    v0 ^= m;                                \
  }                                         \
                                            \
  switch( left )                            \
  {                                         \
  case 7: b |= ( ( U64 )in[ 6] )  << 48;    \
  case 6: b |= ( ( U64 )in[ 5] )  << 40;    \
  case 5: b |= ( ( U64 )in[ 4] )  << 32;    \
  case 4: b |= ( ( U64 )in[ 3] )  << 24;    \
  case 3: b |= ( ( U64 )in[ 2] )  << 16;    \
  case 2: b |= ( ( U64 )in[ 1] )  <<  8;    \
  case 1: b |= ( ( U64 )in[ 0] ); break;    \
  case 0: break;                            \
  }                                         \
                                            \
  v3 ^= b;                                  \
                                            \
  SIP_ROUNDS;                               \
                                            \
  v0 ^= b;                                  \
                                            \
  v2 ^= 0xff;                               \
                                            \
  SIP_FINAL_ROUNDS                          \
                                            \
  b = v0 ^ v1 ^ v2  ^ v3;                   \
  return (U32)(b & U32_MAX);                \
}                                           \
                                            \
PERL_STATIC_INLINE U32                      \
FNC (const unsigned char * const seed, const unsigned char *in, const STRLEN inlen) \
{                                                                   \
    U64 state[4];                                                   \
    SIPHASH_SEED_STATE(seed,state[0],state[1],state[2],state[3]);   \
    return FNC ## _with_state((U8*)state,in,inlen);                 \
}
#define SBOX32_MAX_LEN 24
#define SIPHASH_SEED_STATE(key,v0,v1,v2,v3) \
do {                                    \
    v0 = v2 = U8TO64_LE(key + 0);       \
    v1 = v3 = U8TO64_LE(key + 8);       \
    \
    v0 ^= UINT64_C(0x736f6d6570736575);  \
    v1 ^= UINT64_C(0x646f72616e646f6d);      \
    v2 ^= UINT64_C(0x6c7967656e657261);      \
    v3 ^= UINT64_C(0x7465646279746573);      \
} while (0)
#define SIPROUND            \
  STMT_START {              \
    v0 += v1; v1=ROTL64(v1,13); v1 ^= v0; v0=ROTL64(v0,32); \
    v2 += v3; v3=ROTL64(v3,16); v3 ^= v2;     \
    v0 += v3; v3=ROTL64(v3,21); v3 ^= v0;     \
    v2 += v1; v1=ROTL64(v1,17); v1 ^= v2; v2=ROTL64(v2,32); \
  } STMT_END
# define _PERL_HASH_FUNC                        __PERL_HASH_FUNC
# define _PERL_HASH_SEED_BYTES                  __PERL_HASH_SEED_BYTES
# define _PERL_HASH_SEED_STATE(seed,state)      __PERL_HASH_SEED_STATE(seed,state)
# define _PERL_HASH_STATE_BYTES                 __PERL_HASH_STATE_BYTES
# define _PERL_HASH_WITH_STATE(state,str,len)   __PERL_HASH_WITH_STATE(state,str,len)
# define __PERL_HASH_FUNC "SIPHASH_2_4"
# define __PERL_HASH_SEED_BYTES 16
# define __PERL_HASH_SEED_STATE(seed,state) S_perl_siphash_seed_state(seed,state)
# define __PERL_HASH_STATE_BYTES 32
# define __PERL_HASH_WITH_STATE(state,str,len) S_perl_hash_siphash_2_4_with_state((state),(U8*)(str),(len))
#define DEBUG_SBOX32_HASH 0
#define NOTE3(pat,v0,v1,v2)             printf(pat, v0, v1, v2)
#define ROTL32(x,r)  _rotl(x,r)
#define ROTR32(x,r)  _rotr(x,r)
#define SBOX32_CHURN_ROUNDS 5
#define SBOX32_MIX3(v0,v1,v2,text) STMT_START {                               \
    SBOX32_WARN4("v0=%08x v1=%08x v2=%08x - SBOX32_MIX3 %s\n",              \
            (unsigned int)v0,(unsigned int)v1,(unsigned int)v2, text );     \
    v0 = ROTL32(v0,16) - v2;   \
    v1 = ROTR32(v1,13) ^ v2;   \
    v2 = ROTL32(v2,17) + v1;   \
    v0 = ROTR32(v0, 2) + v1;   \
    v1 = ROTR32(v1,17) - v0;   \
    v2 = ROTR32(v2, 7) ^ v0;   \
} STMT_END
#define SBOX32_MIX4(v0,v1,v2,v3,text) STMT_START { \
        SBOX32_WARN5("v0=%08x v1=%08x v2=%08x v3=%08x - SBOX32_MIX4 %s\n", \
                            (unsigned int)v0, (unsigned int)v1,    \
                            (unsigned int)v2, (unsigned int)v3, text);   \
        v0 = ROTL32(v0,13) - v3;    \
        v1 ^= v2;                   \
        v3 = ROTL32(v3, 9) + v1;    \
        v2 ^= v0;                   \
        v0 = ROTL32(v0,14) ^ v3;    \
        v1 = ROTL32(v1,25) - v2;    \
        v3 ^= v1;                   \
        v2 = ROTL32(v2, 4) - v0;    \
} STMT_END
#define SBOX32_SCRAMBLE32(v,prime) STMT_START {  \
    v ^= (v>>9);                        \
    v ^= (v<<21);                       \
    v ^= (v>>16);                       \
    v *= prime;                         \
    v ^= (v>>17);                       \
    v ^= (v<<15);                       \
    v ^= (v>>23);                       \
} STMT_END
#define SBOX32_SKIP_MASK 0x3
#define SBOX32_STATE_BITS (SBOX32_STATE_BYTES * 8)
#define SBOX32_STATE_BYTES (SBOX32_STATE_WORDS * sizeof(U32))
#define SBOX32_STATE_WORDS (1 + (SBOX32_MAX_LEN * 256))
#define SBOX32_STATIC_INLINE PERL_STATIC_INLINE
#define SBOX32_WARN2(pat,v0,v1)                printf(pat, v0, v1)
#define SBOX32_WARN3(pat,v0,v1,v2)             printf(pat, v0, v1, v2)
#define SBOX32_WARN4(pat,v0,v1,v2,v3)          printf(pat, v0, v1, v2, v3)


#define STMT_END while(0)
#define STMT_START do
#define STRLEN int
#define U16 uint16_t
#define U32 uint32_t
#define U8 unsigned char
#define XORSHIFT128_set(r,x,y,z,w,t) STMT_START {       \
    t = ( x ^ ( x << 5 ) );                             \
    x = y; y = z; z = w;                                \
    r = w = ( w ^ ( w >> 29 ) ) ^ ( t ^ ( t >> 12 ) );  \
} STMT_END
#define XORSHIFT96_set(r,x,y,z,t) STMT_START {          \
    t = (x ^ ( x << 10 ) );                             \
    x = y; y = z;                                       \
    r = z = (z ^ ( z >> 26 ) ) ^ ( t ^ ( t >> 5 ) );    \
} STMT_END
#define _SBOX32_CASE(len,hash,state,key) \
     \
    case len: hash ^= state[ 1 + ( 256 * ( len - 1 ) ) + key[ len - 1 ] ];
#define case_100_SBOX32(hash,state,key) _SBOX32_CASE(100,hash,state,key)
#define case_101_SBOX32(hash,state,key) _SBOX32_CASE(101,hash,state,key)
#define case_102_SBOX32(hash,state,key) _SBOX32_CASE(102,hash,state,key)
#define case_103_SBOX32(hash,state,key) _SBOX32_CASE(103,hash,state,key)
#define case_104_SBOX32(hash,state,key) _SBOX32_CASE(104,hash,state,key)
#define case_105_SBOX32(hash,state,key) _SBOX32_CASE(105,hash,state,key)
#define case_106_SBOX32(hash,state,key) _SBOX32_CASE(106,hash,state,key)
#define case_107_SBOX32(hash,state,key) _SBOX32_CASE(107,hash,state,key)
#define case_108_SBOX32(hash,state,key) _SBOX32_CASE(108,hash,state,key)
#define case_109_SBOX32(hash,state,key) _SBOX32_CASE(109,hash,state,key)
#define case_10_SBOX32(hash,state,key) _SBOX32_CASE(10,hash,state,key)
#define case_110_SBOX32(hash,state,key) _SBOX32_CASE(110,hash,state,key)
#define case_111_SBOX32(hash,state,key) _SBOX32_CASE(111,hash,state,key)
#define case_112_SBOX32(hash,state,key) _SBOX32_CASE(112,hash,state,key)
#define case_113_SBOX32(hash,state,key) _SBOX32_CASE(113,hash,state,key)
#define case_114_SBOX32(hash,state,key) _SBOX32_CASE(114,hash,state,key)
#define case_115_SBOX32(hash,state,key) _SBOX32_CASE(115,hash,state,key)
#define case_116_SBOX32(hash,state,key) _SBOX32_CASE(116,hash,state,key)
#define case_117_SBOX32(hash,state,key) _SBOX32_CASE(117,hash,state,key)
#define case_118_SBOX32(hash,state,key) _SBOX32_CASE(118,hash,state,key)
#define case_119_SBOX32(hash,state,key) _SBOX32_CASE(119,hash,state,key)
#define case_11_SBOX32(hash,state,key) _SBOX32_CASE(11,hash,state,key)
#define case_120_SBOX32(hash,state,key) _SBOX32_CASE(120,hash,state,key)
#define case_121_SBOX32(hash,state,key) _SBOX32_CASE(121,hash,state,key)
#define case_122_SBOX32(hash,state,key) _SBOX32_CASE(122,hash,state,key)
#define case_123_SBOX32(hash,state,key) _SBOX32_CASE(123,hash,state,key)
#define case_124_SBOX32(hash,state,key) _SBOX32_CASE(124,hash,state,key)
#define case_125_SBOX32(hash,state,key) _SBOX32_CASE(125,hash,state,key)
#define case_126_SBOX32(hash,state,key) _SBOX32_CASE(126,hash,state,key)
#define case_127_SBOX32(hash,state,key) _SBOX32_CASE(127,hash,state,key)
#define case_128_SBOX32(hash,state,key) _SBOX32_CASE(128,hash,state,key)
#define case_129_SBOX32(hash,state,key) _SBOX32_CASE(129,hash,state,key)
#define case_12_SBOX32(hash,state,key) _SBOX32_CASE(12,hash,state,key)
#define case_130_SBOX32(hash,state,key) _SBOX32_CASE(130,hash,state,key)
#define case_131_SBOX32(hash,state,key) _SBOX32_CASE(131,hash,state,key)
#define case_132_SBOX32(hash,state,key) _SBOX32_CASE(132,hash,state,key)
#define case_133_SBOX32(hash,state,key) _SBOX32_CASE(133,hash,state,key)
#define case_134_SBOX32(hash,state,key) _SBOX32_CASE(134,hash,state,key)
#define case_135_SBOX32(hash,state,key) _SBOX32_CASE(135,hash,state,key)
#define case_136_SBOX32(hash,state,key) _SBOX32_CASE(136,hash,state,key)
#define case_137_SBOX32(hash,state,key) _SBOX32_CASE(137,hash,state,key)
#define case_138_SBOX32(hash,state,key) _SBOX32_CASE(138,hash,state,key)
#define case_139_SBOX32(hash,state,key) _SBOX32_CASE(139,hash,state,key)
#define case_13_SBOX32(hash,state,key) _SBOX32_CASE(13,hash,state,key)
#define case_140_SBOX32(hash,state,key) _SBOX32_CASE(140,hash,state,key)
#define case_141_SBOX32(hash,state,key) _SBOX32_CASE(141,hash,state,key)
#define case_142_SBOX32(hash,state,key) _SBOX32_CASE(142,hash,state,key)
#define case_143_SBOX32(hash,state,key) _SBOX32_CASE(143,hash,state,key)
#define case_144_SBOX32(hash,state,key) _SBOX32_CASE(144,hash,state,key)
#define case_145_SBOX32(hash,state,key) _SBOX32_CASE(145,hash,state,key)
#define case_146_SBOX32(hash,state,key) _SBOX32_CASE(146,hash,state,key)
#define case_147_SBOX32(hash,state,key) _SBOX32_CASE(147,hash,state,key)
#define case_148_SBOX32(hash,state,key) _SBOX32_CASE(148,hash,state,key)
#define case_149_SBOX32(hash,state,key) _SBOX32_CASE(149,hash,state,key)
#define case_14_SBOX32(hash,state,key) _SBOX32_CASE(14,hash,state,key)
#define case_150_SBOX32(hash,state,key) _SBOX32_CASE(150,hash,state,key)
#define case_151_SBOX32(hash,state,key) _SBOX32_CASE(151,hash,state,key)
#define case_152_SBOX32(hash,state,key) _SBOX32_CASE(152,hash,state,key)
#define case_153_SBOX32(hash,state,key) _SBOX32_CASE(153,hash,state,key)
#define case_154_SBOX32(hash,state,key) _SBOX32_CASE(154,hash,state,key)
#define case_155_SBOX32(hash,state,key) _SBOX32_CASE(155,hash,state,key)
#define case_156_SBOX32(hash,state,key) _SBOX32_CASE(156,hash,state,key)
#define case_157_SBOX32(hash,state,key) _SBOX32_CASE(157,hash,state,key)
#define case_158_SBOX32(hash,state,key) _SBOX32_CASE(158,hash,state,key)
#define case_159_SBOX32(hash,state,key) _SBOX32_CASE(159,hash,state,key)
#define case_15_SBOX32(hash,state,key) _SBOX32_CASE(15,hash,state,key)
#define case_160_SBOX32(hash,state,key) _SBOX32_CASE(160,hash,state,key)
#define case_161_SBOX32(hash,state,key) _SBOX32_CASE(161,hash,state,key)
#define case_162_SBOX32(hash,state,key) _SBOX32_CASE(162,hash,state,key)
#define case_163_SBOX32(hash,state,key) _SBOX32_CASE(163,hash,state,key)
#define case_164_SBOX32(hash,state,key) _SBOX32_CASE(164,hash,state,key)
#define case_165_SBOX32(hash,state,key) _SBOX32_CASE(165,hash,state,key)
#define case_166_SBOX32(hash,state,key) _SBOX32_CASE(166,hash,state,key)
#define case_167_SBOX32(hash,state,key) _SBOX32_CASE(167,hash,state,key)
#define case_168_SBOX32(hash,state,key) _SBOX32_CASE(168,hash,state,key)
#define case_169_SBOX32(hash,state,key) _SBOX32_CASE(169,hash,state,key)
#define case_16_SBOX32(hash,state,key) _SBOX32_CASE(16,hash,state,key)
#define case_170_SBOX32(hash,state,key) _SBOX32_CASE(170,hash,state,key)
#define case_171_SBOX32(hash,state,key) _SBOX32_CASE(171,hash,state,key)
#define case_172_SBOX32(hash,state,key) _SBOX32_CASE(172,hash,state,key)
#define case_173_SBOX32(hash,state,key) _SBOX32_CASE(173,hash,state,key)
#define case_174_SBOX32(hash,state,key) _SBOX32_CASE(174,hash,state,key)
#define case_175_SBOX32(hash,state,key) _SBOX32_CASE(175,hash,state,key)
#define case_176_SBOX32(hash,state,key) _SBOX32_CASE(176,hash,state,key)
#define case_177_SBOX32(hash,state,key) _SBOX32_CASE(177,hash,state,key)
#define case_178_SBOX32(hash,state,key) _SBOX32_CASE(178,hash,state,key)
#define case_179_SBOX32(hash,state,key) _SBOX32_CASE(179,hash,state,key)
#define case_17_SBOX32(hash,state,key) _SBOX32_CASE(17,hash,state,key)
#define case_180_SBOX32(hash,state,key) _SBOX32_CASE(180,hash,state,key)
#define case_181_SBOX32(hash,state,key) _SBOX32_CASE(181,hash,state,key)
#define case_182_SBOX32(hash,state,key) _SBOX32_CASE(182,hash,state,key)
#define case_183_SBOX32(hash,state,key) _SBOX32_CASE(183,hash,state,key)
#define case_184_SBOX32(hash,state,key) _SBOX32_CASE(184,hash,state,key)
#define case_185_SBOX32(hash,state,key) _SBOX32_CASE(185,hash,state,key)
#define case_186_SBOX32(hash,state,key) _SBOX32_CASE(186,hash,state,key)
#define case_187_SBOX32(hash,state,key) _SBOX32_CASE(187,hash,state,key)
#define case_188_SBOX32(hash,state,key) _SBOX32_CASE(188,hash,state,key)
#define case_189_SBOX32(hash,state,key) _SBOX32_CASE(189,hash,state,key)
#define case_18_SBOX32(hash,state,key) _SBOX32_CASE(18,hash,state,key)
#define case_190_SBOX32(hash,state,key) _SBOX32_CASE(190,hash,state,key)
#define case_191_SBOX32(hash,state,key) _SBOX32_CASE(191,hash,state,key)
#define case_192_SBOX32(hash,state,key) _SBOX32_CASE(192,hash,state,key)
#define case_193_SBOX32(hash,state,key) _SBOX32_CASE(193,hash,state,key)
#define case_194_SBOX32(hash,state,key) _SBOX32_CASE(194,hash,state,key)
#define case_195_SBOX32(hash,state,key) _SBOX32_CASE(195,hash,state,key)
#define case_196_SBOX32(hash,state,key) _SBOX32_CASE(196,hash,state,key)
#define case_197_SBOX32(hash,state,key) _SBOX32_CASE(197,hash,state,key)
#define case_198_SBOX32(hash,state,key) _SBOX32_CASE(198,hash,state,key)
#define case_199_SBOX32(hash,state,key) _SBOX32_CASE(199,hash,state,key)
#define case_19_SBOX32(hash,state,key) _SBOX32_CASE(19,hash,state,key)
#define case_1_SBOX32(hash,state,key) _SBOX32_CASE(1,hash,state,key)
#define case_200_SBOX32(hash,state,key) _SBOX32_CASE(200,hash,state,key)
#define case_201_SBOX32(hash,state,key) _SBOX32_CASE(201,hash,state,key)
#define case_202_SBOX32(hash,state,key) _SBOX32_CASE(202,hash,state,key)
#define case_203_SBOX32(hash,state,key) _SBOX32_CASE(203,hash,state,key)
#define case_204_SBOX32(hash,state,key) _SBOX32_CASE(204,hash,state,key)
#define case_205_SBOX32(hash,state,key) _SBOX32_CASE(205,hash,state,key)
#define case_206_SBOX32(hash,state,key) _SBOX32_CASE(206,hash,state,key)
#define case_207_SBOX32(hash,state,key) _SBOX32_CASE(207,hash,state,key)
#define case_208_SBOX32(hash,state,key) _SBOX32_CASE(208,hash,state,key)
#define case_209_SBOX32(hash,state,key) _SBOX32_CASE(209,hash,state,key)
#define case_20_SBOX32(hash,state,key) _SBOX32_CASE(20,hash,state,key)
#define case_210_SBOX32(hash,state,key) _SBOX32_CASE(210,hash,state,key)
#define case_211_SBOX32(hash,state,key) _SBOX32_CASE(211,hash,state,key)
#define case_212_SBOX32(hash,state,key) _SBOX32_CASE(212,hash,state,key)
#define case_213_SBOX32(hash,state,key) _SBOX32_CASE(213,hash,state,key)
#define case_214_SBOX32(hash,state,key) _SBOX32_CASE(214,hash,state,key)
#define case_215_SBOX32(hash,state,key) _SBOX32_CASE(215,hash,state,key)
#define case_216_SBOX32(hash,state,key) _SBOX32_CASE(216,hash,state,key)
#define case_217_SBOX32(hash,state,key) _SBOX32_CASE(217,hash,state,key)
#define case_218_SBOX32(hash,state,key) _SBOX32_CASE(218,hash,state,key)
#define case_219_SBOX32(hash,state,key) _SBOX32_CASE(219,hash,state,key)
#define case_21_SBOX32(hash,state,key) _SBOX32_CASE(21,hash,state,key)
#define case_220_SBOX32(hash,state,key) _SBOX32_CASE(220,hash,state,key)
#define case_221_SBOX32(hash,state,key) _SBOX32_CASE(221,hash,state,key)
#define case_222_SBOX32(hash,state,key) _SBOX32_CASE(222,hash,state,key)
#define case_223_SBOX32(hash,state,key) _SBOX32_CASE(223,hash,state,key)
#define case_224_SBOX32(hash,state,key) _SBOX32_CASE(224,hash,state,key)
#define case_225_SBOX32(hash,state,key) _SBOX32_CASE(225,hash,state,key)
#define case_226_SBOX32(hash,state,key) _SBOX32_CASE(226,hash,state,key)
#define case_227_SBOX32(hash,state,key) _SBOX32_CASE(227,hash,state,key)
#define case_228_SBOX32(hash,state,key) _SBOX32_CASE(228,hash,state,key)
#define case_229_SBOX32(hash,state,key) _SBOX32_CASE(229,hash,state,key)
#define case_22_SBOX32(hash,state,key) _SBOX32_CASE(22,hash,state,key)
#define case_230_SBOX32(hash,state,key) _SBOX32_CASE(230,hash,state,key)
#define case_231_SBOX32(hash,state,key) _SBOX32_CASE(231,hash,state,key)
#define case_232_SBOX32(hash,state,key) _SBOX32_CASE(232,hash,state,key)
#define case_233_SBOX32(hash,state,key) _SBOX32_CASE(233,hash,state,key)
#define case_234_SBOX32(hash,state,key) _SBOX32_CASE(234,hash,state,key)
#define case_235_SBOX32(hash,state,key) _SBOX32_CASE(235,hash,state,key)
#define case_236_SBOX32(hash,state,key) _SBOX32_CASE(236,hash,state,key)
#define case_237_SBOX32(hash,state,key) _SBOX32_CASE(237,hash,state,key)
#define case_238_SBOX32(hash,state,key) _SBOX32_CASE(238,hash,state,key)
#define case_239_SBOX32(hash,state,key) _SBOX32_CASE(239,hash,state,key)
#define case_23_SBOX32(hash,state,key) _SBOX32_CASE(23,hash,state,key)
#define case_240_SBOX32(hash,state,key) _SBOX32_CASE(240,hash,state,key)
#define case_241_SBOX32(hash,state,key) _SBOX32_CASE(241,hash,state,key)
#define case_242_SBOX32(hash,state,key) _SBOX32_CASE(242,hash,state,key)
#define case_243_SBOX32(hash,state,key) _SBOX32_CASE(243,hash,state,key)
#define case_244_SBOX32(hash,state,key) _SBOX32_CASE(244,hash,state,key)
#define case_245_SBOX32(hash,state,key) _SBOX32_CASE(245,hash,state,key)
#define case_246_SBOX32(hash,state,key) _SBOX32_CASE(246,hash,state,key)
#define case_247_SBOX32(hash,state,key) _SBOX32_CASE(247,hash,state,key)
#define case_248_SBOX32(hash,state,key) _SBOX32_CASE(248,hash,state,key)
#define case_249_SBOX32(hash,state,key) _SBOX32_CASE(249,hash,state,key)
#define case_24_SBOX32(hash,state,key) _SBOX32_CASE(24,hash,state,key)
#define case_250_SBOX32(hash,state,key) _SBOX32_CASE(250,hash,state,key)
#define case_251_SBOX32(hash,state,key) _SBOX32_CASE(251,hash,state,key)
#define case_252_SBOX32(hash,state,key) _SBOX32_CASE(252,hash,state,key)
#define case_253_SBOX32(hash,state,key) _SBOX32_CASE(253,hash,state,key)
#define case_254_SBOX32(hash,state,key) _SBOX32_CASE(254,hash,state,key)
#define case_255_SBOX32(hash,state,key) _SBOX32_CASE(255,hash,state,key)
#define case_256_SBOX32(hash,state,key) _SBOX32_CASE(256,hash,state,key)
#define case_25_SBOX32(hash,state,key) _SBOX32_CASE(25,hash,state,key)
#define case_26_SBOX32(hash,state,key) _SBOX32_CASE(26,hash,state,key)
#define case_27_SBOX32(hash,state,key) _SBOX32_CASE(27,hash,state,key)
#define case_28_SBOX32(hash,state,key) _SBOX32_CASE(28,hash,state,key)
#define case_29_SBOX32(hash,state,key) _SBOX32_CASE(29,hash,state,key)
#define case_2_SBOX32(hash,state,key) _SBOX32_CASE(2,hash,state,key)
#define case_30_SBOX32(hash,state,key) _SBOX32_CASE(30,hash,state,key)
#define case_31_SBOX32(hash,state,key) _SBOX32_CASE(31,hash,state,key)
#define case_32_SBOX32(hash,state,key) _SBOX32_CASE(32,hash,state,key)
#define case_33_SBOX32(hash,state,key) _SBOX32_CASE(33,hash,state,key)
#define case_34_SBOX32(hash,state,key) _SBOX32_CASE(34,hash,state,key)
#define case_35_SBOX32(hash,state,key) _SBOX32_CASE(35,hash,state,key)
#define case_36_SBOX32(hash,state,key) _SBOX32_CASE(36,hash,state,key)
#define case_37_SBOX32(hash,state,key) _SBOX32_CASE(37,hash,state,key)
#define case_38_SBOX32(hash,state,key) _SBOX32_CASE(38,hash,state,key)
#define case_39_SBOX32(hash,state,key) _SBOX32_CASE(39,hash,state,key)
#define case_3_SBOX32(hash,state,key) _SBOX32_CASE(3,hash,state,key)
#define case_40_SBOX32(hash,state,key) _SBOX32_CASE(40,hash,state,key)
#define case_41_SBOX32(hash,state,key) _SBOX32_CASE(41,hash,state,key)
#define case_42_SBOX32(hash,state,key) _SBOX32_CASE(42,hash,state,key)
#define case_43_SBOX32(hash,state,key) _SBOX32_CASE(43,hash,state,key)
#define case_44_SBOX32(hash,state,key) _SBOX32_CASE(44,hash,state,key)
#define case_45_SBOX32(hash,state,key) _SBOX32_CASE(45,hash,state,key)
#define case_46_SBOX32(hash,state,key) _SBOX32_CASE(46,hash,state,key)
#define case_47_SBOX32(hash,state,key) _SBOX32_CASE(47,hash,state,key)
#define case_48_SBOX32(hash,state,key) _SBOX32_CASE(48,hash,state,key)
#define case_49_SBOX32(hash,state,key) _SBOX32_CASE(49,hash,state,key)
#define case_4_SBOX32(hash,state,key) _SBOX32_CASE(4,hash,state,key)
#define case_50_SBOX32(hash,state,key) _SBOX32_CASE(50,hash,state,key)
#define case_51_SBOX32(hash,state,key) _SBOX32_CASE(51,hash,state,key)
#define case_52_SBOX32(hash,state,key) _SBOX32_CASE(52,hash,state,key)
#define case_53_SBOX32(hash,state,key) _SBOX32_CASE(53,hash,state,key)
#define case_54_SBOX32(hash,state,key) _SBOX32_CASE(54,hash,state,key)
#define case_55_SBOX32(hash,state,key) _SBOX32_CASE(55,hash,state,key)
#define case_56_SBOX32(hash,state,key) _SBOX32_CASE(56,hash,state,key)
#define case_57_SBOX32(hash,state,key) _SBOX32_CASE(57,hash,state,key)
#define case_58_SBOX32(hash,state,key) _SBOX32_CASE(58,hash,state,key)
#define case_59_SBOX32(hash,state,key) _SBOX32_CASE(59,hash,state,key)
#define case_5_SBOX32(hash,state,key) _SBOX32_CASE(5,hash,state,key)
#define case_60_SBOX32(hash,state,key) _SBOX32_CASE(60,hash,state,key)
#define case_61_SBOX32(hash,state,key) _SBOX32_CASE(61,hash,state,key)
#define case_62_SBOX32(hash,state,key) _SBOX32_CASE(62,hash,state,key)
#define case_63_SBOX32(hash,state,key) _SBOX32_CASE(63,hash,state,key)
#define case_64_SBOX32(hash,state,key) _SBOX32_CASE(64,hash,state,key)
#define case_65_SBOX32(hash,state,key) _SBOX32_CASE(65,hash,state,key)
#define case_66_SBOX32(hash,state,key) _SBOX32_CASE(66,hash,state,key)
#define case_67_SBOX32(hash,state,key) _SBOX32_CASE(67,hash,state,key)
#define case_68_SBOX32(hash,state,key) _SBOX32_CASE(68,hash,state,key)
#define case_69_SBOX32(hash,state,key) _SBOX32_CASE(69,hash,state,key)
#define case_6_SBOX32(hash,state,key) _SBOX32_CASE(6,hash,state,key)
#define case_70_SBOX32(hash,state,key) _SBOX32_CASE(70,hash,state,key)
#define case_71_SBOX32(hash,state,key) _SBOX32_CASE(71,hash,state,key)
#define case_72_SBOX32(hash,state,key) _SBOX32_CASE(72,hash,state,key)
#define case_73_SBOX32(hash,state,key) _SBOX32_CASE(73,hash,state,key)
#define case_74_SBOX32(hash,state,key) _SBOX32_CASE(74,hash,state,key)
#define case_75_SBOX32(hash,state,key) _SBOX32_CASE(75,hash,state,key)
#define case_76_SBOX32(hash,state,key) _SBOX32_CASE(76,hash,state,key)
#define case_77_SBOX32(hash,state,key) _SBOX32_CASE(77,hash,state,key)
#define case_78_SBOX32(hash,state,key) _SBOX32_CASE(78,hash,state,key)
#define case_79_SBOX32(hash,state,key) 
#define case_7_SBOX32(hash,state,key) _SBOX32_CASE(7,hash,state,key)
#define case_80_SBOX32(hash,state,key) _SBOX32_CASE(80,hash,state,key)
#define case_81_SBOX32(hash,state,key) _SBOX32_CASE(81,hash,state,key)
#define case_82_SBOX32(hash,state,key) _SBOX32_CASE(82,hash,state,key)
#define case_83_SBOX32(hash,state,key) _SBOX32_CASE(83,hash,state,key)
#define case_84_SBOX32(hash,state,key) _SBOX32_CASE(84,hash,state,key)
#define case_85_SBOX32(hash,state,key) _SBOX32_CASE(85,hash,state,key)
#define case_86_SBOX32(hash,state,key) _SBOX32_CASE(86,hash,state,key)
#define case_87_SBOX32(hash,state,key) _SBOX32_CASE(87,hash,state,key)
#define case_88_SBOX32(hash,state,key) _SBOX32_CASE(88,hash,state,key)
#define case_89_SBOX32(hash,state,key) _SBOX32_CASE(89,hash,state,key)
#define case_8_SBOX32(hash,state,key) _SBOX32_CASE(8,hash,state,key)
#define case_90_SBOX32(hash,state,key) _SBOX32_CASE(90,hash,state,key)
#define case_91_SBOX32(hash,state,key) _SBOX32_CASE(91,hash,state,key)
#define case_92_SBOX32(hash,state,key) _SBOX32_CASE(92,hash,state,key)
#define case_93_SBOX32(hash,state,key) _SBOX32_CASE(93,hash,state,key)
#define case_94_SBOX32(hash,state,key) _SBOX32_CASE(94,hash,state,key)
#define case_95_SBOX32(hash,state,key) _SBOX32_CASE(95,hash,state,key)
#define case_96_SBOX32(hash,state,key) _SBOX32_CASE(96,hash,state,key)
#define case_97_SBOX32(hash,state,key) _SBOX32_CASE(97,hash,state,key)
#define case_98_SBOX32(hash,state,key) _SBOX32_CASE(98,hash,state,key)
#define case_99_SBOX32(hash,state,key) _SBOX32_CASE(99,hash,state,key)
#define case_9_SBOX32(hash,state,key) _SBOX32_CASE(9,hash,state,key)
#define DEBUG_ZAPHOD32_HASH 0
#define U64 uint64_t
#define U8TO16_LE(ptr)  (*((const U16 *)(ptr)))
#define U8TO32_LE(ptr)  (*((const U32 *)(ptr)))
#define ZAPHOD32_ALLOW_UNALIGNED_AND_LITTLE_ENDIAN 0
#define ZAPHOD32_FINALIZE(v0,v1,v2) STMT_START {          \
    ZAPHOD32_WARN3("v0=%08x v1=%08x v2=%08x - ZAPHOD32 FINALIZE\n", \
            (unsigned int)v0, (unsigned int)v1, (unsigned int)v2);  \
    v2 += v0;                       \
    v1 -= v2;                       \
    v1 = ROTL32(v1,  6);           \
    v2 ^= v1;                       \
    v2 = ROTL32(v2, 28);           \
    v1 ^= v2;                       \
    v0 += v1;                       \
    v1 = ROTL32(v1, 24);           \
    v2 += v1;                       \
    v2 = ROTL32(v2, 18) + v1;      \
    v0 ^= v2;                       \
    v0 = ROTL32(v0, 20);           \
    v2 += v0;                       \
    v1 ^= v2;                       \
    v0 += v1;                       \
    v0 = ROTL32(v0,  5);           \
    v2 += v0;                       \
    v2 = ROTL32(v2, 22);           \
    v0 -= v1;                       \
    v1 -= v2;                       \
    v1 = ROTL32(v1, 17);           \
} STMT_END
#define ZAPHOD32_MIX(v0,v1,v2,text) STMT_START {                              \
    ZAPHOD32_WARN4("v0=%08x v1=%08x v2=%08x - ZAPHOD32 %s MIX\n",                   \
            (unsigned int)v0,(unsigned int)v1,(unsigned int)v2, text );  \
    v0 = ROTL32(v0,16) - v2;   \
    v1 = ROTR32(v1,13) ^ v2;   \
    v2 = ROTL32(v2,17) + v1;   \
    v0 = ROTR32(v0, 2) + v1;   \
    v1 = ROTR32(v1,17) - v0;   \
    v2 = ROTR32(v2, 7) ^ v0;   \
} STMT_END
#define ZAPHOD32_SCRAMBLE32(v,prime) STMT_START {  \
    v ^= (v>>9);                        \
    v ^= (v<<21);                       \
    v ^= (v>>16);                       \
    v *= prime;                         \
    v ^= (v>>17);                       \
    v ^= (v<<15);                       \
    v ^= (v>>23);                       \
} STMT_END
#define ZAPHOD32_STATIC_INLINE PERL_STATIC_INLINE
#define ZAPHOD32_WARN2(pat,v0,v1)                printf(pat, v0, v1)






  #define ROTL64(x,r)  _rotl64(x,r)
#define ROTL_UV(x,r) ROTL64(x,r)
  #define ROTR64(x,r)  _rotr64(x,r)
#define ROTR_UV(x,r) ROTL64(x,r)
  #define U64 uint64_t
      #define U8TO16_LE(ptr)   (__builtin_bswap16(*((U16*)(ptr))))
      #define U8TO32_LE(ptr)   (__builtin_bswap32(*((U32*)(ptr))))
      #define U8TO64_LE(ptr)   (__builtin_bswap64(*((U64*)(ptr))))
#define BASEOP BASEOP_DEFINITION
#define BHKf_bhk_post_end   0x04
#define BHKf_bhk_pre_end    0x02
#define BhkDISABLE(hk, which) \
    STMT_START { \
	BhkFLAGS(hk) &= ~(BHKf_ ## which); \
    } STMT_END
#define BhkENABLE(hk, which) \
    STMT_START { \
	BhkFLAGS(hk) |= BHKf_ ## which; \
	assert(BhkENTRY(hk, which)); \
    } STMT_END
#define BhkENTRY(hk, which) \
    ((BhkFLAGS(hk) & BHKf_ ## which) ? ((hk)->which) : NULL)
#define BhkENTRY_set(hk, which, ptr) \
    STMT_START { \
	(hk)->which = ptr; \
	BhkENABLE(hk, which); \
    } STMT_END
#define BhkFLAGS(hk)		((hk)->bhk_flags)
#define CALL_BLOCK_HOOKS(which, arg) \
    STMT_START { \
	if (PL_blockhooks) { \
	    SSize_t i; \
	    for (i = av_tindex(PL_blockhooks); i >= 0; i--) { \
		SV *sv = AvARRAY(PL_blockhooks)[i]; \
		BHK *hk; \
		\
		assert(SvIOK(sv)); \
		if (SvUOK(sv)) \
		    hk = INT2PTR(BHK *, SvUVX(sv)); \
		else \
		    hk = INT2PTR(BHK *, SvIVX(sv)); \
		\
		if (BhkENTRY(hk, which)) \
		    BhkENTRY(hk, which)(aTHX_ arg); \
	    } \
	} \
    } STMT_END
#  define DEPRECATED_ABOVE_FF_MSG                                   \
      "Use of strings with code points over 0xFF as arguments to "  \
      "%s operator is deprecated. This will be a fatal error in "   \
      "Perl 5.32"
#   define FATAL_ABOVE_FF_MSG                                       \
      "Use of strings with code points over 0xFF as arguments to "  \
      "%s operator is not allowed"
#define FreeOp(p) Perl_Slab_Free(aTHX_ p)
#  define GIMME \
	  (PL_op->op_flags & OPf_WANT					\
	   ? ((PL_op->op_flags & OPf_WANT) == OPf_WANT_LIST		\
	      ? G_ARRAY							\
	      : G_SCALAR)						\
	   : dowantarray())
#define LINKLIST(o) ((o)->op_next ? (o)->op_next : op_linklist((OP*)o))
#define MDEREF_ACTION_MASK                0xf
#define MDEREF_AV_gvav_aelem                6
#define MDEREF_AV_gvsv_vivify_rv2av_aelem   2
#define MDEREF_AV_padav_aelem               5
#define MDEREF_AV_padsv_vivify_rv2av_aelem  3
#define MDEREF_AV_pop_rv2av_aelem           1
#define MDEREF_AV_vivify_rv2av_aelem        4
#define MDEREF_FLAG_last    0x40 
#define MDEREF_HV_gvhv_helem               13
#define MDEREF_HV_gvsv_vivify_rv2hv_helem   9
#define MDEREF_HV_padhv_helem              12
#define MDEREF_HV_padsv_vivify_rv2hv_helem 10
#define MDEREF_HV_pop_rv2hv_helem           8
#define MDEREF_HV_vivify_rv2hv_helem       11
#define MDEREF_INDEX_MASK   0x30
#define MDEREF_INDEX_const  0x10 
#define MDEREF_INDEX_gvsv   0x30 
#define MDEREF_INDEX_none   0x00 
#define MDEREF_INDEX_padsv  0x20 
#define MDEREF_MASK         0x7F
#define MDEREF_SHIFT           7
#define MDEREF_reload                       0
#define NewOp(m,var,c,type)	\
	(var = (type *) Perl_Slab_Alloc(aTHX_ c*sizeof(type)))
#define NewOpSz(m,var,size)	\
	(var = (OP *) Perl_Slab_Alloc(aTHX_ size))
#  define Nullop ((OP*)NULL)
#define OASHIFT 12
#define OA_AVREF 3
#define OA_BASEOP (0 << OCSHIFT)
#define OA_BASEOP_OR_UNOP (11 << OCSHIFT)
#define OA_BINOP (2 << OCSHIFT)
#define OA_CLASS_MASK (15 << OCSHIFT)
#define OA_COP (10 << OCSHIFT)
#define OA_CVREF 5
#define OA_DANGEROUS 64
#define OA_DEFGV 128
#define OA_FILEREF 6
#define OA_FILESTATOP (12 << OCSHIFT)
#define OA_FOLDCONST 2
#define OA_HVREF 4
#define OA_LIST 2
#define OA_LISTOP (4 << OCSHIFT)
#define OA_LOGOP (3 << OCSHIFT)
#define OA_LOOP (9 << OCSHIFT)
#define OA_LOOPEXOP (13 << OCSHIFT)
#define OA_MARK 1
#define OA_METHOP (14 << OCSHIFT)
#define OA_OPTIONAL 8
#define OA_OTHERINT 32
#define OA_PADOP (7 << OCSHIFT)
#define OA_PMOP (5 << OCSHIFT)
#define OA_PVOP_OR_SVOP (8 << OCSHIFT)
#define OA_RETSCALAR 4
#define OA_SCALAR 1
#define OA_SCALARREF 7
#define OA_SVOP (6 << OCSHIFT)
#define OA_TARGET 8
#define OA_TARGLEX 16
#define OA_UNOP (1 << OCSHIFT)
#define OA_UNOP_AUX (15 << OCSHIFT)
#define OCSHIFT 8
#define OPCODE U16
#define OP_CLASS(o) ((o)->op_type == OP_CUSTOM \
		     ? XopENTRYCUSTOM(o, xop_class) \
		     : (PL_opargs[(o)->op_type] & OA_CLASS_MASK))
#define OP_DESC(o) ((o)->op_type == OP_CUSTOM \
                    ? XopENTRYCUSTOM(o, xop_desc) \
		    : PL_op_desc[(o)->op_type])
#define OP_GIMME(op,dfl) \
	(((op)->op_flags & OPf_WANT) ? ((op)->op_flags & OPf_WANT) : dfl)
#define OP_GIMME_REVERSE(flags)	((flags) & G_WANT)
#define OP_LVALUE_NO_CROAK 1
#define OP_NAME(o) ((o)->op_type == OP_CUSTOM \
                    ? XopENTRYCUSTOM(o, xop_name) \
		    : PL_op_name[(o)->op_type])
#  define OP_SIBLING(o)		OpSIBLING(o)
#define OP_TYPE_IS(o, type) ((o) && (o)->op_type == (type))
#define OP_TYPE_ISNT(o, type) ((o) && (o)->op_type != (type))
#define OP_TYPE_ISNT_AND_WASNT(o, type) \
    ( (o) && OP_TYPE_ISNT_AND_WASNT_NN(o, type) )
#define OP_TYPE_ISNT_AND_WASNT_NN(o, type) \
    ( ((o)->op_type == OP_NULL \
       ? (o)->op_targ \
       : (o)->op_type) \
      != (type) )
#define OP_TYPE_ISNT_NN(o, type) ((o)->op_type != (type))
#define OP_TYPE_IS_NN(o, type) ((o)->op_type == (type))
#define OP_TYPE_IS_OR_WAS(o, type) \
    ( (o) && OP_TYPE_IS_OR_WAS_NN(o, type) )
#define OP_TYPE_IS_OR_WAS_NN(o, type) \
    ( ((o)->op_type == OP_NULL \
       ? (o)->op_targ \
       : (o)->op_type) \
      == (type) )
#define OPf_FOLDED      (1<<16)
#define  OPf_WANT_SCALAR 2	
#define OPpENTERSUB_LVAL_MASK (OPpLVAL_INTRO|OPpENTERSUB_INARGS)
#  define OpHAS_SIBLING(o)	(cBOOL((o)->op_moresib))
#  define OpLASTSIB_set(o, parent) \
       ((o)->op_moresib = 0, (o)->op_sibparent = (parent))
#  define OpMAYBESIB_set(o, sib, parent) \
       ((o)->op_sibparent = ((o)->op_moresib = cBOOL(sib)) ? (sib) : (parent))
#  define OpMORESIB_set(o, sib) ((o)->op_moresib = 1, (o)->op_sibparent = (sib))
#  define OpREFCNT_dec(o)		Perl_op_refcnt_dec(aTHX_ o)
#  define OpREFCNT_inc(o)		Perl_op_refcnt_inc(aTHX_ o)
#define OpREFCNT_set(o,n)		((o)->op_targ = (n))
#  define OpSIBLING(o)		(0 + (o)->op_moresib ? (o)->op_sibparent : NULL)
# define OpSLAB(o)		OpSLOT(o)->opslot_slab
# define OpSLOT(o)		(assert_(o->op_slabbed) \
				 (OPSLOT *)(((char *)o)-OPSLOT_HEADER))
# define OpslabREFCNT_dec(slab)      \
	(((slab)->opslab_refcnt == 1) \
	 ? opslab_free_nopad(slab)     \
	 : (void)--(slab)->opslab_refcnt)
# define OpslabREFCNT_dec_padok(slab) \
	(((slab)->opslab_refcnt == 1)  \
	 ? opslab_free(slab)		\
	 : (void)--(slab)->opslab_refcnt)
#define PM_GETRE(o)	(SvTYPE(PL_regex_pad[(o)->op_pmoffset]) == SVt_REGEXP \
		 	 ? (REGEXP*)(PL_regex_pad[(o)->op_pmoffset]) : NULL)
#define PM_SETRE(o,r)	STMT_START {					\
                            REGEXP *const _pm_setre = (r);		\
                            assert(_pm_setre);				\
			    PL_regex_pad[(o)->op_pmoffset] = MUTABLE_SV(_pm_setre); \
                        } STMT_END
#define PMf_BASE_SHIFT (_RXf_PMf_SHIFT_NEXT+2)
#define PMf_USED        (1U<<(PMf_BASE_SHIFT+7))
#define Perl_custom_op_xop(x) \
    (Perl_custom_op_get_field(x, XOPe_xop_ptr).xop_ptr)
#  define PmopSTASH(o)         ((o)->op_pmflags & PMf_ONCE                         \
                                ? PL_stashpad[(o)->op_pmstashstartu.op_pmstashoff]   \
                                : NULL)
#define PmopSTASHPV(o)	(PmopSTASH(o) ? HvNAME_get(PmopSTASH(o)) : NULL)
#define PmopSTASHPV_set(o,pv)	PmopSTASH_set((o), gv_stashpv(pv,GV_ADD))
#    define PmopSTASH_set(o,hv)		({				\
	assert((o)->op_pmflags & PMf_ONCE);				\
	((o)->op_pmstashstartu.op_pmstash = (hv));			\
    })
#define RV2CVOPCV_FLAG_MASK      0x0000000f 
#define RV2CVOPCV_MARK_EARLY     0x00000001
# define RV2CVOPCV_MAYBE_NAME_GV  0x00000008
#define RV2CVOPCV_RETURN_NAME_GV 0x00000002
#define RV2CVOPCV_RETURN_STUB    0x00000004
#  define UNOP_AUX_item_sv(item) PAD_SVl((item)->pad_offset);
#define XopDISABLE(xop, which) ((xop)->xop_flags &= ~XOPf_ ## which)
#define XopENABLE(xop, which) \
    STMT_START { \
	(xop)->xop_flags |= XOPf_ ## which; \
	assert(XopENTRY(xop, which)); \
    } STMT_END
#define XopENTRY(xop, which) \
    ((XopFLAGS(xop) & XOPf_ ## which) ? (xop)->which : XOPd_ ## which)
#define XopENTRYCUSTOM(o, which) \
    (Perl_custom_op_get_field(aTHX_ o, XOPe_ ## which).which)
#define XopENTRY_set(xop, which, to) \
    STMT_START { \
	(xop)->which = (to); \
	(xop)->xop_flags |= XOPf_ ## which; \
    } STMT_END
#define XopFLAGS(xop) ((xop)->xop_flags)
#define cBINOP		cBINOPx(PL_op)
#define cBINOPx(o)	((BINOP*)(o))
#define cCOP		cCOPx(PL_op)
#define cCOPx(o)	((COP*)(o))
#define cLISTOP		cLISTOPx(PL_op)
#define cLISTOPx(o)	((LISTOP*)(o))
#define cLOGOP		cLOGOPx(PL_op)
#define cLOGOPx(o)	((LOGOP*)(o))
#define cLOOP		cLOOPx(PL_op)
#define cLOOPx(o)	((LOOP*)(o))
#define cMETHOPx(o)	((METHOP*)(o))
#define cPADOP		cPADOPx(PL_op)
#define cPADOPx(o)	((PADOP*)(o))
#define cPMOP		cPMOPx(PL_op)
#define cPMOPx(o)	((PMOP*)(o))
#define cPVOP		cPVOPx(PL_op)
#define cPVOPx(o)	((PVOP*)(o))
#define cSVOP		cSVOPx(PL_op)
#define cSVOPx(o)	((SVOP*)(o))
#define cUNOP		cUNOPx(PL_op)
#define cUNOP_AUXx(o)	((UNOP_AUX*)(o))
#define cUNOPx(o)	((UNOP*)(o))
#define cv_ckproto(cv, gv, p) \
   cv_ckproto_len_flags((cv), (gv), (p), (p) ? strlen(p) : 0, 0)
#define newATTRSUB(f, o, p, a, b) Perl_newATTRSUB_x(aTHX_  f, o, p, a, b, FALSE)
#define newSUB(f, o, p, b)	newATTRSUB((f), (o), (p), NULL, (b))
#define op_lvalue(op,t) Perl_op_lvalue_flags(aTHX_ op,t,0)
#define ref(o, type) doref(o, type, TRUE)
#   define ENDGRENT_R_HAS_FPTR
#   define ENDPWENT_R_HAS_FPTR
#   define GETGRENT_R_HAS_BUFFER
#   define GETGRENT_R_HAS_FPTR
#   define GETGRENT_R_HAS_PTR
#   define GETGRGID_R_HAS_BUFFER
#   define GETGRGID_R_HAS_PTR
#   define GETGRNAM_R_HAS_BUFFER
#   define GETGRNAM_R_HAS_PTR
#   define GETHOSTBYADDR_R_HAS_BUFFER
#   define GETHOSTBYADDR_R_HAS_ERRNO
#   define GETHOSTBYADDR_R_HAS_PTR
#   define GETHOSTBYNAME_R_HAS_BUFFER
#   define GETHOSTBYNAME_R_HAS_ERRNO
#   define GETHOSTBYNAME_R_HAS_PTR
#   define GETHOSTENT_R_HAS_BUFFER
#   define GETHOSTENT_R_HAS_ERRNO
#   define GETHOSTENT_R_HAS_PTR
#   define GETNETBYADDR_R_HAS_BUFFER
#   define GETNETBYADDR_R_HAS_ERRNO
#   define GETNETBYADDR_R_HAS_PTR
#   define GETNETBYNAME_R_HAS_BUFFER
#   define GETNETBYNAME_R_HAS_ERRNO
#   define GETNETBYNAME_R_HAS_PTR
#   define GETNETENT_R_HAS_BUFFER
#   define GETNETENT_R_HAS_ERRNO
#   define GETNETENT_R_HAS_PTR
#   define GETPROTOBYNAME_R_HAS_BUFFER
#   define GETPROTOBYNAME_R_HAS_PTR
#   define GETPROTOBYNUMBER_R_HAS_BUFFER
#   define GETPROTOBYNUMBER_R_HAS_PTR
#   define GETPROTOENT_R_HAS_BUFFER
#   define GETPROTOENT_R_HAS_PTR
#   define GETPWENT_R_HAS_BUFFER
#   define GETPWENT_R_HAS_FPTR
#   define GETPWENT_R_HAS_PTR
#   define GETPWNAM_R_HAS_BUFFER
#   define GETPWNAM_R_HAS_PTR
#   define GETPWUID_R_HAS_PTR
#   define GETSERVBYNAME_R_HAS_BUFFER
#   define GETSERVBYNAME_R_HAS_PTR
#   define GETSERVBYPORT_R_HAS_BUFFER
#   define GETSERVBYPORT_R_HAS_PTR
#   define GETSERVENT_R_HAS_BUFFER
#   define GETSERVENT_R_HAS_PTR
#   define GETSPNAM_R_HAS_PTR
#   define NETDB_R_OBSOLETE
#  define PERL_REENTR_API 1

#    define REENTR_MEMZERO(a,b) memzero(a,b)
#   define SETGRENT_R_HAS_FPTR
#   define SETPWENT_R_HAS_FPTR
#   define USE_GRENT_BUFFER
#   define USE_GRENT_FPTR
#   define USE_GRENT_PTR
#   define USE_HOSTENT_BUFFER
#   define USE_HOSTENT_ERRNO
#   define USE_HOSTENT_PTR
#   define USE_NETENT_BUFFER
#   define USE_NETENT_ERRNO
#   define USE_NETENT_PTR
#   define USE_PROTOENT_BUFFER
#   define USE_PROTOENT_PTR
#   define USE_PWENT_BUFFER
#   define USE_PWENT_FPTR
#   define USE_PWENT_PTR
#   define USE_SERVENT_BUFFER
#   define USE_SERVENT_PTR
#   define USE_SPENT_PTR
#       define asctime(a) (asctime_r(a, PL_reentrant_buffer->_asctime_buffer) == 0 ? PL_reentrant_buffer->_asctime_buffer : 0)
#       define crypt(a, b) crypt_r(a, b, &PL_reentrant_buffer->_crypt_data)
#       define ctermid(a) ctermid_r(a)
#       define ctime(a) (ctime_r(a, PL_reentrant_buffer->_ctime_buffer) == 0 ? PL_reentrant_buffer->_ctime_buffer : 0)
#       define endgrent() (endgrent_r(&PL_reentrant_buffer->_grent_fptr) == 0 ? 1 : 0)
#       define endhostent() (endhostent_r(&PL_reentrant_buffer->_hostent_data) == 0 ? 1 : 0)
#       define endnetent() (endnetent_r(&PL_reentrant_buffer->_netent_data) == 0 ? 1 : 0)
#       define endprotoent() (endprotoent_r(&PL_reentrant_buffer->_protoent_data) == 0 ? 1 : 0)
#       define endpwent() (endpwent_r(&PL_reentrant_buffer->_pwent_fptr) == 0 ? 1 : 0)
#       define endservent() (endservent_r(&PL_reentrant_buffer->_servent_data) == 0 ? 1 : 0)
#       define getgrent() ((PL_reentrant_retint = getgrent_r(&PL_reentrant_buffer->_grent_struct, PL_reentrant_buffer->_grent_buffer, PL_reentrant_buffer->_grent_size, &PL_reentrant_buffer->_grent_ptr)) == 0 ? PL_reentrant_buffer->_grent_ptr : ((PL_reentrant_retint == ERANGE) ? (struct group *) Perl_reentrant_retry("getgrent") : 0))
#       define getgrgid(a) ((PL_reentrant_retint = getgrgid_r(a, &PL_reentrant_buffer->_grent_struct, PL_reentrant_buffer->_grent_buffer, PL_reentrant_buffer->_grent_size, &PL_reentrant_buffer->_grent_ptr)) == 0 ? PL_reentrant_buffer->_grent_ptr : ((PL_reentrant_retint == ERANGE) ? (struct group *) Perl_reentrant_retry("getgrgid", a) : 0))
#       define getgrnam(a) ((PL_reentrant_retint = getgrnam_r(a, &PL_reentrant_buffer->_grent_struct, PL_reentrant_buffer->_grent_buffer, PL_reentrant_buffer->_grent_size, &PL_reentrant_buffer->_grent_ptr)) == 0 ? PL_reentrant_buffer->_grent_ptr : ((PL_reentrant_retint == ERANGE) ? (struct group *) Perl_reentrant_retry("getgrnam", a) : 0))
#       define gethostbyaddr(a, b, c) ((PL_reentrant_retint = gethostbyaddr_r(a, b, c)) == 0 ? 1 : ((PL_reentrant_retint == ERANGE) ? (struct hostent *) Perl_reentrant_retry("gethostbyaddr", a, b, c) : 0))
#       define gethostbyname(a) ((PL_reentrant_retint = gethostbyname_r(a, &PL_reentrant_buffer->_hostent_struct, PL_reentrant_buffer->_hostent_buffer, PL_reentrant_buffer->_hostent_size, &PL_reentrant_buffer->_hostent_ptr, &PL_reentrant_buffer->_hostent_errno)) == 0 ? PL_reentrant_buffer->_hostent_ptr : ((PL_reentrant_retint == ERANGE) ? (struct hostent *) Perl_reentrant_retry("gethostbyname", a) : 0))
#       define gethostent() ((PL_reentrant_retint = gethostent_r(&PL_reentrant_buffer->_hostent_struct, PL_reentrant_buffer->_hostent_buffer, PL_reentrant_buffer->_hostent_size, &PL_reentrant_buffer->_hostent_ptr, &PL_reentrant_buffer->_hostent_errno)) == 0 ? PL_reentrant_buffer->_hostent_ptr : ((PL_reentrant_retint == ERANGE) ? (struct hostent *) Perl_reentrant_retry("gethostent") : 0))
#       define getlogin() ((PL_reentrant_retint = getlogin_r(PL_reentrant_buffer->_getlogin_buffer, PL_reentrant_buffer->_getlogin_size)) == 0 ? PL_reentrant_buffer->_getlogin_buffer : ((PL_reentrant_retint == ERANGE) ? (char *) Perl_reentrant_retry("getlogin") : 0))
#       define getnetbyaddr(a, b) ((PL_reentrant_retint = getnetbyaddr_r(a, b, &PL_reentrant_buffer->_netent_struct, PL_reentrant_buffer->_netent_buffer, PL_reentrant_buffer->_netent_size, &PL_reentrant_buffer->_netent_ptr, &PL_reentrant_buffer->_netent_errno)) == 0 ? PL_reentrant_buffer->_netent_ptr : ((PL_reentrant_retint == ERANGE) ? (struct netent *) Perl_reentrant_retry("getnetbyaddr", a, b) : 0))
#       define getnetbyname(a) ((PL_reentrant_retint = getnetbyname_r(a, &PL_reentrant_buffer->_netent_struct, PL_reentrant_buffer->_netent_buffer, PL_reentrant_buffer->_netent_size, &PL_reentrant_buffer->_netent_ptr, &PL_reentrant_buffer->_netent_errno)) == 0 ? PL_reentrant_buffer->_netent_ptr : ((PL_reentrant_retint == ERANGE) ? (struct netent *) Perl_reentrant_retry("getnetbyname", a) : 0))
#       define getnetent() ((PL_reentrant_retint = getnetent_r(&PL_reentrant_buffer->_netent_struct, PL_reentrant_buffer->_netent_buffer, PL_reentrant_buffer->_netent_size, &PL_reentrant_buffer->_netent_ptr, &PL_reentrant_buffer->_netent_errno)) == 0 ? PL_reentrant_buffer->_netent_ptr : ((PL_reentrant_retint == ERANGE) ? (struct netent *) Perl_reentrant_retry("getnetent") : 0))
#       define getprotobyname(a) ((PL_reentrant_retint = getprotobyname_r(a, &PL_reentrant_buffer->_protoent_struct, PL_reentrant_buffer->_protoent_buffer, PL_reentrant_buffer->_protoent_size, &PL_reentrant_buffer->_protoent_ptr)) == 0 ? PL_reentrant_buffer->_protoent_ptr : ((PL_reentrant_retint == ERANGE) ? (struct protoent *) Perl_reentrant_retry("getprotobyname", a) : 0))
#       define getprotobynumber(a) ((PL_reentrant_retint = getprotobynumber_r(a, &PL_reentrant_buffer->_protoent_struct, PL_reentrant_buffer->_protoent_buffer, PL_reentrant_buffer->_protoent_size, &PL_reentrant_buffer->_protoent_ptr)) == 0 ? PL_reentrant_buffer->_protoent_ptr : ((PL_reentrant_retint == ERANGE) ? (struct protoent *) Perl_reentrant_retry("getprotobynumber", a) : 0))
#       define getprotoent() ((PL_reentrant_retint = getprotoent_r(&PL_reentrant_buffer->_protoent_struct, PL_reentrant_buffer->_protoent_buffer, PL_reentrant_buffer->_protoent_size, &PL_reentrant_buffer->_protoent_ptr)) == 0 ? PL_reentrant_buffer->_protoent_ptr : ((PL_reentrant_retint == ERANGE) ? (struct protoent *) Perl_reentrant_retry("getprotoent") : 0))
#       define getpwent() ((PL_reentrant_retint = getpwent_r(&PL_reentrant_buffer->_pwent_struct, PL_reentrant_buffer->_pwent_buffer, PL_reentrant_buffer->_pwent_size, &PL_reentrant_buffer->_pwent_ptr)) == 0 ? PL_reentrant_buffer->_pwent_ptr : ((PL_reentrant_retint == ERANGE) ? (struct passwd *) Perl_reentrant_retry("getpwent") : 0))
#       define getpwnam(a) ((PL_reentrant_retint = getpwnam_r(a, &PL_reentrant_buffer->_pwent_struct, PL_reentrant_buffer->_pwent_buffer, PL_reentrant_buffer->_pwent_size, &PL_reentrant_buffer->_pwent_ptr)) == 0 ? PL_reentrant_buffer->_pwent_ptr : ((PL_reentrant_retint == ERANGE) ? (struct passwd *) Perl_reentrant_retry("getpwnam", a) : 0))
#       define getpwuid(a) ((PL_reentrant_retint = getpwuid_r(a, &PL_reentrant_buffer->_pwent_struct, PL_reentrant_buffer->_pwent_buffer, PL_reentrant_buffer->_pwent_size, &PL_reentrant_buffer->_pwent_ptr)) == 0 ? PL_reentrant_buffer->_pwent_ptr : ((PL_reentrant_retint == ERANGE) ? (struct passwd *) Perl_reentrant_retry("getpwuid", a) : 0))
#       define getservbyname(a, b) ((PL_reentrant_retint = getservbyname_r(a, b, &PL_reentrant_buffer->_servent_struct, PL_reentrant_buffer->_servent_buffer, PL_reentrant_buffer->_servent_size, &PL_reentrant_buffer->_servent_ptr)) == 0 ? PL_reentrant_buffer->_servent_ptr : ((PL_reentrant_retint == ERANGE) ? (struct servent *) Perl_reentrant_retry("getservbyname", a, b) : 0))
#       define getservbyport(a, b) ((PL_reentrant_retint = getservbyport_r(a, b, &PL_reentrant_buffer->_servent_struct, PL_reentrant_buffer->_servent_buffer, PL_reentrant_buffer->_servent_size, &PL_reentrant_buffer->_servent_ptr)) == 0 ? PL_reentrant_buffer->_servent_ptr : ((PL_reentrant_retint == ERANGE) ? (struct servent *) Perl_reentrant_retry("getservbyport", a, b) : 0))
#       define getservent() ((PL_reentrant_retint = getservent_r(&PL_reentrant_buffer->_servent_struct, PL_reentrant_buffer->_servent_buffer, PL_reentrant_buffer->_servent_size, &PL_reentrant_buffer->_servent_ptr)) == 0 ? PL_reentrant_buffer->_servent_ptr : ((PL_reentrant_retint == ERANGE) ? (struct servent *) Perl_reentrant_retry("getservent") : 0))
#       define getspnam(a) ((PL_reentrant_retint = getspnam_r(a, &PL_reentrant_buffer->_spent_struct, PL_reentrant_buffer->_spent_buffer, PL_reentrant_buffer->_spent_size, &PL_reentrant_buffer->_spent_ptr)) == 0 ? PL_reentrant_buffer->_spent_ptr : ((PL_reentrant_retint == ERANGE) ? (struct spwd *) Perl_reentrant_retry("getspnam", a) : 0))
#       define readdir(a) (readdir_r(a, PL_reentrant_buffer->_readdir_struct) == 0 ? PL_reentrant_buffer->_readdir_struct : 0)
#       define readdir64(a) (readdir64_r(a, PL_reentrant_buffer->_readdir64_struct) == 0 ? PL_reentrant_buffer->_readdir64_struct : 0)
#       define setgrent() (setgrent_r(&PL_reentrant_buffer->_grent_fptr) == 0 ? 1 : 0)
#       define sethostent(a) (sethostent_r(a, &PL_reentrant_buffer->_hostent_data) == 0 ? 1 : 0)
#       define setlocale(a, b) (setlocale_r(a, b, PL_reentrant_buffer->_setlocale_buffer, PL_reentrant_buffer->_setlocale_size) == 0 ? PL_reentrant_buffer->_setlocale_buffer : 0)
#       define setnetent(a) (setnetent_r(a, &PL_reentrant_buffer->_netent_data) == 0 ? 1 : 0)
#       define setprotoent(a) (setprotoent_r(a, &PL_reentrant_buffer->_protoent_data) == 0 ? 1 : 0)
#       define setpwent() (setpwent_r(&PL_reentrant_buffer->_pwent_fptr) == 0 ? 1 : 0)
#       define setservent(a) (setservent_r(a, &PL_reentrant_buffer->_servent_data) == 0 ? 1 : 0)
#       define strerror(a) (strerror_r(a, PL_reentrant_buffer->_strerror_buffer, PL_reentrant_buffer->_strerror_size) == 0 ? PL_reentrant_buffer->_strerror_buffer : 0)
#       define tmpnam(a) tmpnam_r(a)
#       define ttyname(a) (ttyname_r(a, PL_reentrant_buffer->_ttyname_buffer, PL_reentrant_buffer->_ttyname_size) == 0 ? PL_reentrant_buffer->_ttyname_buffer : 0)
#define PMf_CHARSET       (7U<<7)
#define PMf_EXTENDED      (1U<<3)
#define PMf_EXTENDED_MORE (1U<<4)
#define PMf_FOLD          (1U<<2)
#define PMf_KEEPCOPY      (1U<<6)
#define PMf_MULTILINE     (1U<<0)
#define PMf_NOCAPTURE     (1U<<5)
#define PMf_SINGLELINE    (1U<<1)
#define PMf_SPLIT         (1U<<11)
#define PMf_STRICT        (1U<<10)
#define RXf_PMf_CHARSET (7U << (_RXf_PMf_CHARSET_SHIFT)) 
#define RXf_PMf_COMPILETIME    (RXf_PMf_MULTILINE|RXf_PMf_SINGLELINE|RXf_PMf_FOLD|RXf_PMf_EXTENDED|RXf_PMf_EXTENDED_MORE|RXf_PMf_KEEPCOPY|RXf_PMf_NOCAPTURE|RXf_PMf_CHARSET|RXf_PMf_STRICT)
#define RXf_PMf_EXTENDED       (1U << (RXf_PMf_STD_PMMOD_SHIFT+3))    
#define RXf_PMf_EXTENDED_MORE  (1U << (RXf_PMf_STD_PMMOD_SHIFT+4))    
#define RXf_PMf_FLAGCOPYMASK   (RXf_PMf_COMPILETIME|RXf_PMf_SPLIT)
#define RXf_PMf_FOLD           (1U << (RXf_PMf_STD_PMMOD_SHIFT+2))    
#define RXf_PMf_KEEPCOPY       (1U << (RXf_PMf_STD_PMMOD_SHIFT+6))    
#define RXf_PMf_MULTILINE      (1U << (RXf_PMf_STD_PMMOD_SHIFT+0))    
#define RXf_PMf_NOCAPTURE      (1U << (RXf_PMf_STD_PMMOD_SHIFT+5))    
#define RXf_PMf_SINGLELINE     (1U << (RXf_PMf_STD_PMMOD_SHIFT+1))    
#define RXf_PMf_SPLIT (1U<<(RXf_PMf_STD_PMMOD_SHIFT+11))
#define RXf_PMf_STD_PMMOD_SHIFT 0
#define RXf_PMf_STRICT (1U<<(RXf_PMf_STD_PMMOD_SHIFT+10))
#define _RXf_PMf_CHARSET_SHIFT ((RXf_PMf_STD_PMMOD_SHIFT)+7)
#define _RXf_PMf_SHIFT_COMPILETIME (RXf_PMf_STD_PMMOD_SHIFT+11)
#define _RXf_PMf_SHIFT_NEXT (RXf_PMf_STD_PMMOD_SHIFT+12)
#define MAXO 397
#define OP_FREED MAXO
#define OP_IS_DIRHOP(op)	\
	((op) >= OP_READDIR && (op) <= OP_CLOSEDIR)
#define OP_IS_FILETEST(op)	\
	((op) >= OP_FTRREAD && (op) <= OP_FTBINARY)
#define OP_IS_FILETEST_ACCESS(op)	\
	((op) >= OP_FTRREAD && (op) <= OP_FTEEXEC)
#define OP_IS_INFIX_BIT(op)	\
	((op) >= OP_BIT_AND && (op) <= OP_SBIT_OR)
#define OP_IS_NUMCOMPARE(op)	\
	((op) >= OP_LT && (op) <= OP_I_NCMP)
#define OP_IS_SOCKET(op)	\
	((op) >= OP_SEND && (op) <= OP_GETPEERNAME)
#define CvANON(cv)		(CvFLAGS(cv) & CVf_ANON)
#define CvANONCONST(cv)		(CvFLAGS(cv) & CVf_ANONCONST)
#define CvANONCONST_off(cv)	(CvFLAGS(cv) &= ~CVf_ANONCONST)
#define CvANONCONST_on(cv)	(CvFLAGS(cv) |= CVf_ANONCONST)
#define CvANON_off(cv)		(CvFLAGS(cv) &= ~CVf_ANON)
#define CvANON_on(cv)		(CvFLAGS(cv) |= CVf_ANON)
#define CvAUTOLOAD(cv)		(CvFLAGS(cv) & CVf_AUTOLOAD)
#define CvAUTOLOAD_off(cv)	(CvFLAGS(cv) &= ~CVf_AUTOLOAD)
#define CvAUTOLOAD_on(cv)	(CvFLAGS(cv) |= CVf_AUTOLOAD)
#define CvCLONE(cv)		(CvFLAGS(cv) & CVf_CLONE)
#define CvCLONED(cv)		(CvFLAGS(cv) & CVf_CLONED)
#define CvCLONED_off(cv)	(CvFLAGS(cv) &= ~CVf_CLONED)
#define CvCLONED_on(cv)		(CvFLAGS(cv) |= CVf_CLONED)
#define CvCLONE_off(cv)		(CvFLAGS(cv) &= ~CVf_CLONE)
#define CvCLONE_on(cv)		(CvFLAGS(cv) |= CVf_CLONE)
#define CvCONST(cv)		(CvFLAGS(cv) & CVf_CONST)
#define CvCONST_off(cv)		(CvFLAGS(cv) &= ~CVf_CONST)
#define CvCONST_on(cv)		(CvFLAGS(cv) |= CVf_CONST)
#define CvCVGV_RC(cv)		(CvFLAGS(cv) & CVf_CVGV_RC)
#define CvCVGV_RC_off(cv)	(CvFLAGS(cv) &= ~CVf_CVGV_RC)
#define CvCVGV_RC_on(cv)	(CvFLAGS(cv) |= CVf_CVGV_RC)
#define CvDEPTHunsafe(sv) ((XPVCV*)MUTABLE_PTR(SvANY(sv)))->xcv_depth
#define CvDYNFILE(cv)		(CvFLAGS(cv) & CVf_DYNFILE)
#define CvDYNFILE_off(cv)	(CvFLAGS(cv) &= ~CVf_DYNFILE)
#define CvDYNFILE_on(cv)	(CvFLAGS(cv) |= CVf_DYNFILE)
#define CvEVAL(cv)		(CvUNIQUE(cv) && !SvFAKE(cv))
#define CvEVAL_off(cv)		CvUNIQUE_off(cv)
#define CvEVAL_on(cv)		(CvUNIQUE_on(cv),SvFAKE_off(cv))
#define CvFILE(sv)	((XPVCV*)MUTABLE_PTR(SvANY(sv)))->xcv_file
#define CvFILEGV(sv)	(gv_fetchfile(CvFILE(sv)))
#  define CvFILE_set_from_cop(sv, cop)	\
    (CvFILE(sv) = savepv(CopFILE(cop)), CvDYNFILE_on(sv))
#define CvFLAGS(sv)	  ((XPVCV*)MUTABLE_PTR(SvANY(sv)))->xcv_flags
#define CvGV_set(cv,gv)	Perl_cvgv_set(aTHX_ cv, gv)
#define CvGvNAME_HEK(sv) ( \
        CvNAMED((CV*)sv) ? \
            ((XPVCV*)MUTABLE_PTR(SvANY((SV*)sv)))->xcv_gv_u.xcv_hek\
            : GvNAME_HEK(CvGV( (SV*) sv)) \
        )
#define CvHASEVAL(cv)		(CvFLAGS(cv) & CVf_HASEVAL)
#define CvHASEVAL_off(cv)	(CvFLAGS(cv) &= ~CVf_HASEVAL)
#define CvHASEVAL_on(cv)	(CvFLAGS(cv) |= CVf_HASEVAL)
#define CvHASGV(cv)	cBOOL(SvANY(cv)->xcv_gv_u.xcv_gv)
#define CvHSCXT(sv)	  *(assert_(CvISXSUB((CV*)(sv))) \
	&(((XPVCV*)MUTABLE_PTR(SvANY(sv)))->xcv_padlist_u.xcv_hscxt))
#define CvISXSUB(cv)		(CvFLAGS(cv) & CVf_ISXSUB)
#define CvISXSUB_off(cv)	(CvFLAGS(cv) &= ~CVf_ISXSUB)
#define CvISXSUB_on(cv)		(CvFLAGS(cv) |= CVf_ISXSUB)
#define CvLEXICAL(cv)		(CvFLAGS(cv) & CVf_LEXICAL)
#define CvLEXICAL_off(cv)	(CvFLAGS(cv) &= ~CVf_LEXICAL)
#define CvLEXICAL_on(cv)	(CvFLAGS(cv) |= CVf_LEXICAL)
#define CvLVALUE(cv)		(CvFLAGS(cv) & CVf_LVALUE)
#define CvLVALUE_off(cv)	(CvFLAGS(cv) &= ~CVf_LVALUE)
#define CvLVALUE_on(cv)		(CvFLAGS(cv) |= CVf_LVALUE)
#define CvMETHOD(cv)		(CvFLAGS(cv) & CVf_METHOD)
#define CvMETHOD_off(cv)	(CvFLAGS(cv) &= ~CVf_METHOD)
#define CvMETHOD_on(cv)		(CvFLAGS(cv) |= CVf_METHOD)
#define CvNAMED(cv)		(CvFLAGS(cv) & CVf_NAMED)
#define CvNAMED_off(cv)		(CvFLAGS(cv) &= ~CVf_NAMED)
#define CvNAMED_on(cv)		(CvFLAGS(cv) |= CVf_NAMED)
#define CvNAME_HEK_set(cv, hek) ( \
	CvNAME_HEK((CV *)(cv))						 \
	    ? unshare_hek(SvANY((CV *)(cv))->xcv_gv_u.xcv_hek)	  \
	    : (void)0,						   \
	((XPVCV*)MUTABLE_PTR(SvANY(cv)))->xcv_gv_u.xcv_hek = (hek), \
	CvNAMED_on(cv)						     \
    )
#define CvNODEBUG(cv)		(CvFLAGS(cv) & CVf_NODEBUG)
#define CvNODEBUG_off(cv)	(CvFLAGS(cv) &= ~CVf_NODEBUG)
#define CvNODEBUG_on(cv)	(CvFLAGS(cv) |= CVf_NODEBUG)
#define CvOUTSIDE(sv)	  ((XPVCV*)MUTABLE_PTR(SvANY(sv)))->xcv_outside
#define CvOUTSIDE_SEQ(sv) ((XPVCV*)MUTABLE_PTR(SvANY(sv)))->xcv_outside_seq
#define CvPADLIST(sv)	  (*(assert_(!CvISXSUB((CV*)(sv))) \
	&(((XPVCV*)MUTABLE_PTR(SvANY(sv)))->xcv_padlist_u.xcv_padlist)))
#  define CvPADLIST_set(sv, padlist) Perl_set_padlist((CV*)sv, padlist)
#define CvPROTO(sv)                               \
	(                                          \
	 SvPOK(sv)                                  \
	  ? SvTYPE(sv) == SVt_PVCV && CvAUTOLOAD(sv) \
	     ? SvEND(sv)+1 : SvPVX_const(sv)          \
	  : NULL                                       \
	)
#define CvPROTOLEN(sv)	                          \
	(                                          \
	 SvPOK(sv)                                  \
	  ? SvTYPE(sv) == SVt_PVCV && CvAUTOLOAD(sv) \
	     ? SvLEN(sv)-SvCUR(sv)-2                  \
	     : SvCUR(sv)                               \
	  : 0                                           \
	)
#define CvROOT(sv)	((XPVCV*)MUTABLE_PTR(SvANY(sv)))->xcv_root_u.xcv_root
# define CvSLABBED(cv)		(CvFLAGS(cv) & CVf_SLABBED)
# define CvSLABBED_off(cv)	(CvFLAGS(cv) &= ~CVf_SLABBED)
# define CvSLABBED_on(cv)	(CvFLAGS(cv) |= CVf_SLABBED)
#define CvSPECIAL(cv)		(CvUNIQUE(cv) && SvFAKE(cv))
#define CvSPECIAL_off(cv)	(CvUNIQUE_off(cv),SvFAKE_off(cv))
#define CvSPECIAL_on(cv)	(CvUNIQUE_on(cv),SvFAKE_on(cv))
#define CvSTART(sv)	((XPVCV*)MUTABLE_PTR(SvANY(sv)))->xcv_start_u.xcv_start
#define CvSTASH(sv)	(0+((XPVCV*)MUTABLE_PTR(SvANY(sv)))->xcv_stash)
#define CvSTASH_set(cv,st) Perl_cvstash_set(aTHX_ cv, st)
#define CvUNIQUE(cv)		(CvFLAGS(cv) & CVf_UNIQUE)
#define CvUNIQUE_off(cv)	(CvFLAGS(cv) &= ~CVf_UNIQUE)
#define CvUNIQUE_on(cv)		(CvFLAGS(cv) |= CVf_UNIQUE)
#define CvWEAKOUTSIDE(cv)	(CvFLAGS(cv) & CVf_WEAKOUTSIDE)
#define CvWEAKOUTSIDE_off(cv)	(CvFLAGS(cv) &= ~CVf_WEAKOUTSIDE)
#define CvWEAKOUTSIDE_on(cv)	(CvFLAGS(cv) |= CVf_WEAKOUTSIDE)
#define CvXSUB(sv)	((XPVCV*)MUTABLE_PTR(SvANY(sv)))->xcv_root_u.xcv_xsub
#define CvXSUBANY(sv)	((XPVCV*)MUTABLE_PTR(SvANY(sv)))->xcv_start_u.xcv_xsubany
#  define Nullcv Null(CV*)
#    define PoisonPADLIST(sv) \
        (((XPVCV*)MUTABLE_PTR(SvANY(sv)))->xcv_padlist_u.xcv_padlist = (PADLIST *)UINT64_C(0xEFEFEFEFEFEFEFEF))
#  define ASSERT_CURPAD_ACTIVE(label) \
    pad_peg(label); \
    if (!PL_comppad || (AvARRAY(PL_comppad) != PL_curpad))		  \
	Perl_croak(aTHX_ "panic: invalid pad in %s: 0x%" UVxf "[0x%" UVxf "]",\
	    label, PTR2UV(PL_comppad), PTR2UV(PL_curpad));
#  define ASSERT_CURPAD_LEGAL(label) \
    pad_peg(label); \
    if (PL_comppad ? (AvARRAY(PL_comppad) != PL_curpad) : (PL_curpad != 0))  \
	Perl_croak(aTHX_ "panic: illegal pad in %s: 0x%" UVxf "[0x%" UVxf "]",\
	    label, PTR2UV(PL_comppad), PTR2UV(PL_curpad));
#define COP_SEQMAX_INC \
	(PL_cop_seqmax++, \
	 (void)(PL_cop_seqmax == PERL_PADSEQ_INTRO && PL_cop_seqmax++))
#define COP_SEQ_RANGE_HIGH(pn)		(pn)->xpadn_high
#define COP_SEQ_RANGE_LOW(pn)		(pn)->xpadn_low
#define CX_CURPAD_SAVE(block)  (block).oldcomppad = PL_comppad
#define CX_CURPAD_SV(block,po) (AvARRAY(MUTABLE_AV(((block).oldcomppad)))[po])
#define NOT_IN_PAD ((PADOFFSET) -1)
#define PADNAME_FROM_PV(s) \
    ((PADNAME *)((s) - STRUCT_OFFSET(struct padname_with_str, xpadn_str)))
#define PAD_BASE_SV(padlist, po) \
	(PadlistARRAY(padlist)[1])					\
	    ? AvARRAY(MUTABLE_AV((PadlistARRAY(padlist)[1])))[po] \
	    : NULL;
#define PAD_CLONE_VARS(proto_perl, param)				\
    PL_comppad			= av_dup(proto_perl->Icomppad, param);	\
    PL_curpad = PL_comppad ?  AvARRAY(PL_comppad) : NULL;		\
    PL_comppad_name		=					\
		  padnamelist_dup(proto_perl->Icomppad_name, param);	\
    PL_comppad_name_fill	= proto_perl->Icomppad_name_fill;	\
    PL_comppad_name_floor	= proto_perl->Icomppad_name_floor;	\
    PL_min_intro_pending	= proto_perl->Imin_intro_pending;	\
    PL_max_intro_pending	= proto_perl->Imax_intro_pending;	\
    PL_padix			= proto_perl->Ipadix;			\
    PL_padix_floor		= proto_perl->Ipadix_floor;		\
    PL_pad_reset_pending	= proto_perl->Ipad_reset_pending;	\
    PL_cop_seqmax		= proto_perl->Icop_seqmax;
#define PAD_COMPNAME_FLAGS(po)	PadnameFLAGS(PAD_COMPNAME(po))
#define PAD_COMPNAME_FLAGS_isOUR(po) SvPAD_OUR(PAD_COMPNAME_SV(po))
#define PAD_COMPNAME_GEN(po) \
    ((STRLEN)PadnamelistARRAY(PL_comppad_name)[po]->xpadn_gen)
#define PAD_COMPNAME_GEN_set(po, gen) \
    (PadnamelistARRAY(PL_comppad_name)[po]->xpadn_gen = (gen))
#define PAD_COMPNAME_OURSTASH(po) \
    (SvOURSTASH(PAD_COMPNAME_SV(po)))
#define PAD_COMPNAME_PV(po)	PadnamePV(PAD_COMPNAME(po))
#define PAD_COMPNAME_SV(po)	(PadnamelistARRAY(PL_comppad_name)[(po)])
#define PAD_COMPNAME_TYPE(po)	PadnameTYPE(PAD_COMPNAME(po))
#define PAD_FAKELEX_ANON   1 
#define PAD_FAKELEX_MULTI  2 
#define PAD_RESTORE_LOCAL(opad) \
        assert(!opad || !SvIS_FREED(opad));					\
	PL_comppad = opad;						\
	PL_curpad =  PL_comppad ? AvARRAY(PL_comppad) : NULL;	\
	DEBUG_Xv(PerlIO_printf(Perl_debug_log,			\
	      "Pad 0x%" UVxf "[0x%" UVxf "] restore_local\n",	\
	      PTR2UV(PL_comppad), PTR2UV(PL_curpad)));
#define PAD_SAVE_LOCAL(opad,npad) \
	opad = PL_comppad;					\
	PL_comppad = (npad);					\
	PL_curpad =  PL_comppad ? AvARRAY(PL_comppad) : NULL;	\
	DEBUG_Xv(PerlIO_printf(Perl_debug_log,			\
	      "Pad 0x%" UVxf "[0x%" UVxf "] save_local\n",		\
	      PTR2UV(PL_comppad), PTR2UV(PL_curpad)));
#define PAD_SAVE_SETNULLPAD()	SAVECOMPPAD(); \
	PL_comppad = NULL; PL_curpad = NULL;	\
	DEBUG_Xv(PerlIO_printf(Perl_debug_log, "Pad set_null\n"));
#  define PAD_SETSV(po,sv) pad_setsv(po,sv)
#define PAD_SET_CUR(padlist,nth) \
	SAVECOMPPAD();						\
	PAD_SET_CUR_NOSAVE(padlist,nth);
#define PAD_SET_CUR_NOSAVE(padlist,nth) \
	PL_comppad = (PAD*) (PadlistARRAY(padlist)[nth]);	\
	PL_curpad = AvARRAY(PL_comppad);			\
	DEBUG_Xv(PerlIO_printf(Perl_debug_log,			\
	      "Pad 0x%" UVxf "[0x%" UVxf "] set_cur    depth=%d\n",	\
	      PTR2UV(PL_comppad), PTR2UV(PL_curpad), (int)(nth)));
#  define PAD_SV(po)	   pad_sv(po)
#define PAD_SVl(po)       (PL_curpad[po])
#define PARENT_FAKELEX_FLAGS(pn)	(pn)->xpadn_high
#define PARENT_PAD_INDEX(pn)		(pn)->xpadn_low
#  define PERL_PADNAME_MINIMAL
#define PERL_PADSEQ_INTRO  U32_MAX
#define PadARRAY(pad)		AvARRAY(pad)
#define PadMAX(pad)		AvFILLp(pad)
#define PadlistARRAY(pl)	(pl)->xpadl_arr.xpadlarr_alloc
#define PadlistMAX(pl)		(pl)->xpadl_max
#define PadlistNAMES(pl)	*((PADNAMELIST **)PadlistARRAY(pl))
#define PadlistNAMESARRAY(pl)	PadnamelistARRAY(PadlistNAMES(pl))
#define PadlistNAMESMAX(pl)	PadnamelistMAX(PadlistNAMES(pl))
#define PadlistREFCNT(pl)	1	
#define PadnameFLAGS(pn)	(pn)->xpadn_flags
#define PadnameIsOUR(pn)	(!!(pn)->xpadn_ourstash)
#define PadnameIsSTATE(pn)	(PadnameFLAGS(pn) & PADNAMEt_STATE)
#define PadnameIsSTATE_on(pn)	(PadnameFLAGS(pn) |= PADNAMEt_STATE)
#define PadnameLEN(pn)		(pn)->xpadn_len
#define PadnameLVALUE(pn)	(PadnameFLAGS(pn) & PADNAMEt_LVALUE)
#define PadnameLVALUE_on(pn)	(PadnameFLAGS(pn) |= PADNAMEt_LVALUE)
#define PadnameOURSTASH(pn)	(pn)->xpadn_ourstash
#define PadnameOURSTASH_set(pn,s) (PadnameOURSTASH(pn) = (s))
#define PadnameOUTER(pn)	(PadnameFLAGS(pn) & PADNAMEt_OUTER)
#define PadnamePROTOCV(pn)	(pn)->xpadn_type_u.xpadn_protocv
#define PadnamePV(pn)		(pn)->xpadn_pv
#define PadnameREFCNT(pn)	(pn)->xpadn_refcnt
#define PadnameREFCNT_dec(pn)	Perl_padname_free(aTHX_ pn)
#define PadnameSV(pn) \
	newSVpvn_flags(PadnamePV(pn), PadnameLEN(pn), SVs_TEMP|SVf_UTF8)
#define PadnameTYPE(pn)		(pn)->xpadn_type_u.xpadn_typestash
#define PadnameTYPE_set(pn,s)	  (PadnameTYPE(pn) = (s))
#define PadnameUTF8(pn)		1
#define PadnamelistARRAY(pnl)		(pnl)->xpadnl_alloc
#define PadnamelistMAX(pnl)		(pnl)->xpadnl_fill
#define PadnamelistMAXNAMED(pnl)	(pnl)->xpadnl_max_named
#define PadnamelistREFCNT(pnl)		(pnl)->xpadnl_refcnt
#define PadnamelistREFCNT_dec(pnl)	Perl_padnamelist_free(aTHX_ pnl)
#define SvPAD_OUR(pn)		(!!PadnameOURSTASH(pn))
#define SvPAD_OUR_on(pn)	(PadnameFLAGS(pn) |= PADNAMEt_OUR)
#define SvPAD_TYPED(pn)		(!!PadnameTYPE(pn))
#define SvPAD_TYPED_on(pn)	(PadnameFLAGS(pn) |= PADNAMEt_TYPED)
#define _PADNAME_BASE \
    char *	xpadn_pv;		\
    HV *	xpadn_ourstash;		\
    union {				\
	HV *	xpadn_typestash;	\
	CV *	xpadn_protocv;		\
    } xpadn_type_u;			\
    U32		xpadn_low;		\
    U32		xpadn_high;		\
    U32		xpadn_refcnt;		\
    int		xpadn_gen;		\
    U8		xpadn_len;		\
    U8		xpadn_flags
#define pad_add_name_pvs(name,flags,typestash,ourstash) \
    Perl_pad_add_name_pvn(aTHX_ STR_WITH_LEN(name), flags, typestash, ourstash)
#define pad_findmy_pvs(name,flags) \
    Perl_pad_findmy_pvn(aTHX_ STR_WITH_LEN(name), flags)
#  define pad_peg(label)
#define DM_ARRAY_ISA 0x004
#define DM_DELAY     0x100
#define DM_EGID      0x020
#define DM_EUID      0x002
#define DM_GID       (DM_RGID|DM_EGID)
#define DM_RGID      0x010
#define DM_RUID      0x001
#define DM_UID       (DM_RUID|DM_EUID)
#define GV_AUTOLOAD_ISMETHOD 1	
#define GV_NOADD_MASK \
  (SVf_UTF8|GV_NOADD_NOINIT|GV_NOEXPAND|GV_NOTQUAL|GV_ADDMG|GV_NO_SVGMAGIC)
#define GvASSUMECV(gv)		(GvFLAGS(gv) & GVf_ASSUMECV)
#define GvASSUMECV_off(gv)	(GvFLAGS(gv) &= ~GVf_ASSUMECV)
#define GvASSUMECV_on(gv)	(GvFLAGS(gv) |= GVf_ASSUMECV)
#define GvAV(gv)	(GvGP(gv)->gp_av)
#define GvAVn(gv)	(GvGP(gv)->gp_av ? \
			 GvGP(gv)->gp_av : \
			 GvGP(gv_AVadd(gv))->gp_av)
#define GvCV(gv)	(0+GvGP(gv)->gp_cv)
#define GvCVGEN(gv)	(GvGP(gv)->gp_cvgen)
#define GvCV_set(gv,cv)	(GvGP(gv)->gp_cv = (cv))
#define GvCVu(gv)	(GvGP(gv)->gp_cvgen ? NULL : GvGP(gv)->gp_cv)
#define GvEGV(gv)	(GvGP(gv)->gp_egv)
#define GvEGVx(gv)	(isGV_with_GP(gv) ? GvEGV(gv) : NULL)
#define GvENAME(gv)	GvNAME(GvEGV(gv) ? GvEGV(gv) : gv)
#define GvENAMELEN(gv)  GvNAMELEN(GvEGV(gv) ? GvEGV(gv) : gv)
#define GvENAMEUTF8(gv) GvNAMEUTF8(GvEGV(gv) ? GvEGV(gv) : gv)
#define GvENAME_HEK(gv) GvNAME_HEK(GvEGV(gv) ? GvEGV(gv) : gv)
#define GvESTASH(gv)	GvSTASH(GvEGV(gv) ? GvEGV(gv) : gv)
#define GvFILEGV(gv)	(GvFILE_HEK(gv) ? gv_fetchfile(GvFILEx(gv)) : NULL)
#define GvFILE_HEK(gv)	(GvGP(gv)->gp_file_hek)
#define GvFILEx(gv)	HEK_KEY(GvFILE_HEK(gv))
#  define GvFLAGS(gv)							\
	(*({GV *const _gvflags = (GV *) (gv);				\
	    assert(SvTYPE(_gvflags) == SVt_PVGV || SvTYPE(_gvflags) == SVt_PVLV); \
	    assert(isGV_with_GP(_gvflags));				\
	    &(GvXPVGV(_gvflags)->xpv_cur);}))
#define GvFORM(gv)	(GvGP(gv)->gp_form)
#  define GvGP(gv)							\
	(0+(*({GV *const _gvgp = (GV *) (gv);				\
	    assert(SvTYPE(_gvgp) == SVt_PVGV || SvTYPE(_gvgp) == SVt_PVLV); \
	    assert(isGV_with_GP(_gvgp));				\
	    &((_gvgp)->sv_u.svu_gp);})))
#define GvGPFLAGS(gv)	(GvGP(gv)->gp_flags)
#  define GvGP_set(gv,gp)						\
	{GV *const _gvgp = (GV *) (gv);				\
	    assert(SvTYPE(_gvgp) == SVt_PVGV || SvTYPE(_gvgp) == SVt_PVLV); \
	    assert(isGV_with_GP(_gvgp));				\
	    (_gvgp)->sv_u.svu_gp = (gp); }
#define GvHV(gv)	((GvGP(gv))->gp_hv)
#define GvHVn(gv)	(GvGP(gv)->gp_hv ? \
			 GvGP(gv)->gp_hv : \
			 GvGP(gv_HVadd(gv))->gp_hv)
#define GvIMPORTED(gv)		(GvFLAGS(gv) & GVf_IMPORTED)
#define GvIMPORTED_AV(gv)	(GvFLAGS(gv) & GVf_IMPORTED_AV)
#define GvIMPORTED_AV_off(gv)	(GvFLAGS(gv) &= ~GVf_IMPORTED_AV)
#define GvIMPORTED_AV_on(gv)	(GvFLAGS(gv) |= GVf_IMPORTED_AV)
#define GvIMPORTED_CV(gv)	(GvFLAGS(gv) & GVf_IMPORTED_CV)
#define GvIMPORTED_CV_off(gv)	(GvFLAGS(gv) &= ~GVf_IMPORTED_CV)
#define GvIMPORTED_CV_on(gv)	(GvFLAGS(gv) |= GVf_IMPORTED_CV)
#define GvIMPORTED_HV(gv)	(GvFLAGS(gv) & GVf_IMPORTED_HV)
#define GvIMPORTED_HV_off(gv)	(GvFLAGS(gv) &= ~GVf_IMPORTED_HV)
#define GvIMPORTED_HV_on(gv)	(GvFLAGS(gv) |= GVf_IMPORTED_HV)
#define GvIMPORTED_SV(gv)	(GvFLAGS(gv) & GVf_IMPORTED_SV)
#define GvIMPORTED_SV_off(gv)	(GvFLAGS(gv) &= ~GVf_IMPORTED_SV)
#define GvIMPORTED_SV_on(gv)	(GvFLAGS(gv) |= GVf_IMPORTED_SV)
#define GvIMPORTED_off(gv)	(GvFLAGS(gv) &= ~GVf_IMPORTED)
#define GvIMPORTED_on(gv)	(GvFLAGS(gv) |= GVf_IMPORTED)
#define GvINTRO(gv)		(GvFLAGS(gv) & GVf_INTRO)
#define GvINTRO_off(gv)		(GvFLAGS(gv) &= ~GVf_INTRO)
#define GvINTRO_on(gv)		(GvFLAGS(gv) |= GVf_INTRO)
#  define GvIN_PAD(gv)		0
#  define GvIN_PAD_off(gv)	NOOP
#  define GvIN_PAD_on(gv)	NOOP
#define GvIO(gv)                         \
 (                                        \
     (gv)                                  \
  && (                                      \
         SvTYPE((const SV*)(gv)) == SVt_PVGV \
      || SvTYPE((const SV*)(gv)) == SVt_PVLV  \
     )                                         \
  && GvGP(gv)                                   \
   ? GvIOp(gv)                                   \
   : NULL                                         \
 )
#define GvIOn(gv)	(GvIO(gv) ? GvIOp(gv) : GvIOp(gv_IOadd(gv)))
#define GvIOp(gv)	(GvGP(gv)->gp_io)
#define GvLINE(gv)	(GvGP(gv)->gp_line)
#define GvMULTI(gv)		(GvFLAGS(gv) & GVf_MULTI)
#define GvMULTI_off(gv)		(GvFLAGS(gv) &= ~GVf_MULTI)
#define GvMULTI_on(gv)		(GvFLAGS(gv) |= GVf_MULTI)
#  define GvNAMELEN_get(gv)	({ assert(GvNAME_HEK(gv)); HEK_LEN(GvNAME_HEK(gv)); })
#  define GvNAMEUTF8(gv)	({ assert(GvNAME_HEK(gv)); HEK_UTF8(GvNAME_HEK(gv)); })
#  define GvNAME_HEK(gv)						\
    (*({ GV * const _gvname_hek = (GV *) (gv);				\
	   assert(isGV_with_GP(_gvname_hek));				\
	   assert(SvTYPE(_gvname_hek) == SVt_PVGV || SvTYPE(_gvname_hek) >= SVt_PVLV); \
	   &(GvXPVGV(_gvname_hek)->xiv_u.xivu_namehek);			\
	 }))
#  define GvNAME_get(gv)	({ assert(GvNAME_HEK(gv)); (char *)HEK_KEY(GvNAME_HEK(gv)); })
#define GvREFCNT(gv)	(GvGP(gv)->gp_refcnt)
#  define GvSTASH(gv)							\
	(*({ GV * const _gvstash = (GV *) (gv);				\
	    assert(isGV_with_GP(_gvstash));				\
	    assert(SvTYPE(_gvstash) == SVt_PVGV || SvTYPE(_gvstash) >= SVt_PVLV); \
	    &(GvXPVGV(_gvstash)->xnv_u.xgv_stash);			\
	 }))
#define GvSV(gv)	(GvGP(gv)->gp_sv)
#define GvSVn(gv)	GvSV(gv)
#define GvXPVGV(gv)	((XPVGV*)SvANY(gv))
#  define Nullgv Null(GV*)
#define gv_AVadd(gv) gv_add_by_type((gv), SVt_PVAV)
#define gv_HVadd(gv) gv_add_by_type((gv), SVt_PVHV)
#define gv_IOadd(gv) gv_add_by_type((gv), SVt_PVIO)
#define gv_SVadd(gv) gv_add_by_type((gv), SVt_NULL)
#define gv_autoload4(stash, name, len, method) \
	gv_autoload_pvn(stash, name, len, !!(method))
#define gv_efullname3(sv,gv,prefix) gv_efullname4(sv,gv,prefix,TRUE)
#define gv_fetchmeth(stash,name,len,level) gv_fetchmeth_pvn(stash, name, len, level, 0)
#define gv_fetchmeth_autoload(stash,name,len,level) gv_fetchmeth_pvn_autoload(stash, name, len, level, 0)
#define gv_fetchmethod(stash, name) gv_fetchmethod_autoload(stash, name, TRUE)
#define gv_fetchmethod_flags(stash,name,flags) gv_fetchmethod_pv_flags(stash, name, flags)
#define gv_fetchsv_nomg(n,f,t) gv_fetchsv(n,(f)|GV_NO_SVGMAGIC,t)
#define gv_fullname3(sv,gv,prefix) gv_fullname4(sv,gv,prefix,TRUE)
#define gv_init(gv,stash,name,len,multi) \
	gv_init_pvn(gv,stash,name,len,GV_ADDMULTI*!!(multi))
#define gv_method_changed(gv)		    \
    (					     \
    	assert_(isGV_with_GP(gv))	      \
	GvREFCNT(gv) > 1		       \
	    ? (void)++PL_sub_generation		\
	    : mro_method_changed_in(GvSTASH(gv)) \
    )
#define newGVgen(pack)  newGVgen_flags(pack, 0)
#define FF_0DECIMAL     16 
#define FF_BLANK        14 
#define FF_CHECKCHOP    6  
#define FF_CHECKNL      5  
#define FF_CHOP         10 
#define FF_DECIMAL      12 
#define FF_END          0  
#define FF_FETCH        4  
#define FF_HALFSPACE    8  
#define FF_ITEM         9  
#define FF_LINEGLOB     11 
#define FF_LINEMARK     1  
#define FF_LINESNGL     17 
#define FF_LITERAL      2  
#define FF_MORE         15 
#define FF_NEWLINE      13 
#define FF_SKIP         3  
#define FF_SPACE        7  
#define HS_APIVERLEN_MAX HSm_APIVERLEN
#  define HS_CXT aTHX
#define HS_GETAPIVERLEN(key) ((key) & HSm_APIVERLEN)
#define HS_GETINTERPSIZE(key) ((key) >> 16)
#define HS_GETXSVERLEN(key) ((key) >> 8 & 0xFF)
#  define HS_KEY(setxsubfn, popmark, apiver, xsver) \
    HS_KEYp(sizeof(PerlInterpreter), TRUE, setxsubfn, popmark, \
    sizeof("" apiver "")-1, sizeof("" xsver "")-1)
#define HS_KEYp(interpsize, cxt, setxsubfn, popmark, apiverlen, xsverlen) \
    (((interpsize)  << 16) \
    | ((xsverlen) > HS_XSVERLEN_MAX \
        ? (Perl_croak_nocontext("panic: handshake overflow"), HS_XSVERLEN_MAX) \
        : (xsverlen) << 8) \
    | (cBOOL(setxsubfn) ? HSf_SETXSUBFN : 0) \
    | (cBOOL(cxt) ? HSf_IMP_CXT : 0) \
    | (cBOOL(popmark) ? HSf_POPMARK : 0) \
    | ((apiverlen) > HS_APIVERLEN_MAX \
        ? (Perl_croak_nocontext("panic: handshake overflow"), HS_APIVERLEN_MAX) \
        : (apiverlen)))
#define HS_XSVERLEN_MAX 0xFF
#define HSf_IMP_CXT 0x00000080 
#define HSf_NOCHK HSm_KEY_MATCH  
#define HSf_POPMARK 0x00000040 
#define HSf_SETXSUBFN 0x00000020
#define HSm_APIVERLEN 0x0000001F 
#define HSm_INTRPSIZE 0xFFFF0000 
#define HSm_KEY_MATCH (HSm_INTRPSIZE|HSf_IMP_CXT)
#define HSm_XSVERLEN 0x0000FF00 
#    define PERL_DRAND48_QUAD
#  define PERL_FILE_IS_ABSOLUTE(f) \
	(*(f) == '/'							\
	 || (strchr(f,':')						\
	     || ((*(f) == '[' || *(f) == '<')				\
		 && (isWORDCHAR((f)[1]) || strchr("$-_]>",(f)[1])))))

#define PL_RANDOM_STATE_TYPE perl_drand48_t
#define Perl_drand48() (Perl_drand48_r(&PL_random_state))
#define Perl_drand48_init(seed) (Perl_drand48_init_r(&PL_random_state, (seed)))
#define Perl_free_c_backtrace(bt) Safefree(bt)
#define Perl_internal_drand48() (Perl_drand48_r(&PL_internal_random_state))
#   define Perl_my_mkostemp(templte, flags) mkostemp(templte, flags)
#   define Perl_my_mkstemp(templte) mkstemp(templte)
#define ibcmp(s1, s2, len)         cBOOL(! foldEQ(s1, s2, len))
#define ibcmp_locale(s1, s2, len)  cBOOL(! foldEQ_locale(s1, s2, len))
#define instr(haystack, needle) strstr(haystack, needle)
#define ASCII_MORE_RESTRICT_PAT_MODS "aa"
#define ASCII_RESTRICT_PAT_MOD 'a'
#define ASCII_RESTRICT_PAT_MODS "a"
#define CASE_STD_PMMOD_FLAGS_PARSE_SET(pmfl, x_count)                       \
    case IGNORE_PAT_MOD:    *(pmfl) |= RXf_PMf_FOLD;       break;           \
    case MULTILINE_PAT_MOD: *(pmfl) |= RXf_PMf_MULTILINE;  break;           \
    case SINGLE_PAT_MOD:    *(pmfl) |= RXf_PMf_SINGLELINE; break;           \
    case XTENDED_PAT_MOD:   if (x_count == 0) {                             \
                                *(pmfl) |= RXf_PMf_EXTENDED;                \
                                *(pmfl) &= ~RXf_PMf_EXTENDED_MORE;          \
                            }                                               \
                            else {                                          \
                                *(pmfl) |= RXf_PMf_EXTENDED                 \
                                          |RXf_PMf_EXTENDED_MORE;           \
                            }                                               \
                            (x_count)++; break;                             \
    case NOCAPTURE_PAT_MOD: *(pmfl) |= RXf_PMf_NOCAPTURE; break;
#define CHARSET_PAT_MODS    ASCII_RESTRICT_PAT_MODS DEPENDS_PAT_MODS LOCALE_PAT_MODS UNICODE_PAT_MODS
#define CONTINUE_PAT_MOD     'c'
#define DEFAULT_PAT_MOD      '^'    
#define DEPENDS_PAT_MOD      'd'
#define DEPENDS_PAT_MODS     "d"
#define EXEC_PAT_MOD         'e'
#define EXEC_PAT_MODS        "e"
#define EXT_PAT_MODS    ONCE_PAT_MODS   KEEPCOPY_PAT_MODS  NOCAPTURE_PAT_MODS
#define FBMcf_TAIL		(FBMcf_TAIL_DOLLAR|FBMcf_TAIL_DOLLARM|FBMcf_TAIL_Z|FBMcf_TAIL_z)
#define GLOBAL_PAT_MOD       'g'
#define IGNORE_PAT_MOD       'i'
#define INT_PAT_MODS    STD_PAT_MODS    KEEPCOPY_PAT_MODS
#define KEEPCOPY_PAT_MOD     'p'
#define KEEPCOPY_PAT_MODS    "p"
#define LOCALE_PAT_MOD       'l'
#define LOCALE_PAT_MODS      "l"
#define LOOP_PAT_MODS        "gc"
#define MAX_RECURSE_EVAL_NOCHANGE_DEPTH 10
#define MULTILINE_PAT_MOD    'm'
#define M_PAT_MODS      QR_PAT_MODS     LOOP_PAT_MODS
#define NOCAPTURE_PAT_MOD    'n'
#define NOCAPTURE_PAT_MODS   "n"
#define NONDESTRUCT_PAT_MOD  'r'
#define NONDESTRUCT_PAT_MODS "r"
#define ONCE_PAT_MOD         'o'
#define ONCE_PAT_MODS        "o"
#define PERL_REGMATCH_SLAB_SLOTS \
    ((4096 - 3 * sizeof (void*)) / sizeof(regmatch_state))
#define QR_PAT_MODS     STD_PAT_MODS    EXT_PAT_MODS	   CHARSET_PAT_MODS
#define REXEC_CHECKED   0x02    
#define REXEC_COPY_SKIP_POST 0x40    
#define REXEC_COPY_SKIP_PRE  0x20    
#define REXEC_COPY_STR  0x01    
#define REXEC_FAIL_ON_UNDERFLOW 0x80 
#define REXEC_IGNOREPOS 0x08    
#define REXEC_NOT_FIRST 0x10    
#define REXEC_SCREAM    0x04    
#define RX_BUFF_IDX_CARET_FULLMATCH -3 
#define RX_BUFF_IDX_CARET_POSTMATCH -4 
#define RX_BUFF_IDX_CARET_PREMATCH  -5 
#define RX_BUFF_IDX_FULLMATCH        0 
#define RX_BUFF_IDX_POSTMATCH       -1 
#define RX_BUFF_IDX_PREMATCH        -2 
#define RX_CHECK_SUBSTR(rx_sv)          (ReANY(rx_sv)->check_substr)
#define RX_COMPFLAGS(rx_sv)             RXp_COMPFLAGS(ReANY(rx_sv))
#define RX_ENGINE(rx_sv)                (RXp_ENGINE(ReANY(rx_sv)))
#define RX_EXTFLAGS(rx_sv)              RXp_EXTFLAGS(ReANY(rx_sv))
#define RX_GOFS(rx_sv)                  (RXp_GOFS(ReANY(rx_sv)))
#  define RX_ISTAINTED(rx_sv)           0
#define RX_LASTCLOSEPAREN(rx_sv)        (ReANY(rx_sv)->lastcloseparen)
#define RX_LASTPAREN(rx_sv)             (ReANY(rx_sv)->lastparen)
#define RX_MATCH_COPIED(rx_sv)          (RX_EXTFLAGS(rx_sv) & RXf_COPY_DONE)
#define RX_MATCH_COPIED_off(rx_sv)      (RX_EXTFLAGS(rx_sv) &= ~RXf_COPY_DONE)
#define RX_MATCH_COPIED_on(rx_sv)       (RX_EXTFLAGS(rx_sv) |= RXf_COPY_DONE)
#define RX_MATCH_COPIED_set(rx_sv,t)    ((t) \
                                         ? RX_MATCH_COPIED_on(rx_sv) \
                                         : RX_MATCH_COPIED_off(rx_sv))
#define RX_MATCH_COPY_FREE(rx_sv)       RXp_MATCH_COPY_FREE(ReANY(rx_sv))
#  define RX_MATCH_TAINTED(rx_sv)       0
#  define RX_MATCH_TAINTED_off(rx_sv)   NOOP
#  define RX_MATCH_TAINTED_on(rx_sv)    NOOP
#define RX_MATCH_TAINTED_set(rx_sv, t)  ((t) \
                                        ? RX_MATCH_TAINTED_on(rx_sv) \
                                        : RX_MATCH_TAINTED_off(rx_sv))
#define RX_MATCH_UTF8(rx_sv)            (RX_EXTFLAGS(rx_sv) & RXf_MATCH_UTF8)
#define RX_MATCH_UTF8_off(rx_sv)        (RXp_MATCH_UTF8_off(ReANY(rx_sv))
#define RX_MATCH_UTF8_on(rx_sv)         (RXp_MATCH_UTF8_on(ReANY(rx_sv)))
#define RX_MATCH_UTF8_set(rx_sv, t)     (RXp_MATCH_UTF8_set(ReANY(rx_sv), t))
#define RX_MINLEN(rx_sv)                (RXp_MINLEN(ReANY(rx_sv)))
#define RX_MINLENRET(rx_sv)             (RXp_MINLENRET(ReANY(rx_sv)))
#define RX_NPARENS(rx_sv)               (RXp_NPARENS(ReANY(rx_sv)))
#define RX_OFFS(rx_sv)                  (RXp_OFFS(ReANY(rx_sv)))
#define RX_PRECOMP(rx_sv)              (RX_WRAPPED(rx_sv) \
                                            + ReANY(rx_sv)->pre_prefix)
#define RX_PRECOMP_const(rx_sv)        (RX_WRAPPED_const(rx_sv) \
                                            + ReANY(rx_sv)->pre_prefix)
#define RX_PRELEN(rx_sv)                (RX_WRAPLEN(rx_sv) \
                                            - ReANY(rx_sv)->pre_prefix - 1)
#define RX_REFCNT(rx_sv)                SvREFCNT(rx_sv)
#define RX_SAVED_COPY(rx_sv)            (RXp_SAVED_COPY(ReANY(rx_sv)))
#define RX_SUBBEG(rx_sv)                (RXp_SUBBEG(ReANY(rx_sv)))
#define RX_SUBCOFFSET(rx_sv)            (ReANY(rx_sv)->subcoffset)
#define RX_SUBLEN(rx_sv)                (ReANY(rx_sv)->sublen)
#define RX_SUBOFFSET(rx_sv)             (RXp_SUBOFFSET(ReANY(rx_sv)))
#  define RX_TAINT_on(rx_sv)            NOOP
#define RX_UTF8(rx_sv)                  SvUTF8(rx_sv)
#define RX_WRAPLEN(rx_sv)               SvCUR(rx_sv)
#define RX_WRAPPED(rx_sv)               SvPVX(rx_sv)
#define RX_WRAPPED_const(rx_sv)         SvPVX_const(rx_sv)
#define RX_ZERO_LEN(rx_sv)              (RXp_ZERO_LEN(ReANY(rx_sv)))
#define RXapif_ALL       0x0200 
#define RXapif_CLEAR     0x0008
#define RXapif_DELETE    0x0004
#define RXapif_EXISTS    0x0010
#define RXapif_FETCH     0x0001
#define RXapif_FIRSTKEY  0x0040
#define RXapif_NEXTKEY   0x0080
#define RXapif_ONE       0x0100 
#define RXapif_REGNAME         0x0400
#define RXapif_REGNAMES        0x0800
#define RXapif_REGNAMES_COUNT  0x1000
#define RXapif_SCALAR    0x0020
#define RXapif_STORE     0x0002
#define RXf_BASE_SHIFT (_RXf_PMf_SHIFT_NEXT + 2)
#define RXf_CHECK_ALL   	(1U<<(RXf_BASE_SHIFT+5))
#define RXf_COPY_DONE   	(1U<<(RXf_BASE_SHIFT+11))
#define RXf_EVAL_SEEN   	(1U<<(RXf_BASE_SHIFT+3))
#define RXf_INTUIT_TAIL 	(1U<<(RXf_BASE_SHIFT+9))
#define RXf_IS_ANCHORED         (1U<<(RXf_BASE_SHIFT+10))
#define RXf_MATCH_UTF8  	(1U<<(RXf_BASE_SHIFT+6)) 
#define RXf_NO_INPLACE_SUBST    (1U<<(RXf_BASE_SHIFT+2))
#define RXf_SKIPWHITE           (1U<<(RXf_BASE_SHIFT+15)) 
#define RXf_SPLIT   RXf_PMf_SPLIT
#define RXf_UNBOUNDED_QUANTIFIER_SEEN   (1U<<(RXf_BASE_SHIFT+4))
#define RXf_USE_INTUIT		(RXf_USE_INTUIT_NOML|RXf_USE_INTUIT_ML)
#define RXp_COMPFLAGS(rx)               ((rx)->compflags)
#define RXp_ENGINE(prog)                ((prog)->engine)
#define RXp_EXTFLAGS(rx)                ((rx)->extflags)
#define RXp_GOFS(prog)                  (prog->gofs)
#define RXp_HAS_CUTGROUP(prog)          ((prog)->intflags & PREGf_CUTGROUP_SEEN)
#  define RXp_ISTAINTED(prog)           0
#define RXp_MATCH_COPIED(prog)          (RXp_EXTFLAGS(prog) & RXf_COPY_DONE)
#define RXp_MATCH_COPIED_off(prog)      (RXp_EXTFLAGS(prog) &= ~RXf_COPY_DONE)
#define RXp_MATCH_COPIED_on(prog)       (RXp_EXTFLAGS(prog) |= RXf_COPY_DONE)
#define RXp_MATCH_COPY_FREE(prog) \
	STMT_START {if (RXp_SAVED_COPY(prog)) { \
	    SV_CHECK_THINKFIRST_COW_DROP(RXp_SAVED_COPY(prog)); \
	} \
	if (RXp_MATCH_COPIED(prog)) { \
	    Safefree(RXp_SUBBEG(prog)); \
	    RXp_MATCH_COPIED_off(prog); \
	}} STMT_END
#  define RXp_MATCH_TAINTED(prog)       0
#  define RXp_MATCH_TAINTED_off(prog)   NOOP
#  define RXp_MATCH_TAINTED_on(prog)    NOOP
#define RXp_MATCH_UTF8(prog)            (RXp_EXTFLAGS(prog) & RXf_MATCH_UTF8)
#define RXp_MATCH_UTF8_off(prog)        (RXp_EXTFLAGS(prog) &= ~RXf_MATCH_UTF8)
#define RXp_MATCH_UTF8_on(prog)         (RXp_EXTFLAGS(prog) |= RXf_MATCH_UTF8)
#define RXp_MATCH_UTF8_set(prog, t)     ((t) \
                                        ? RXp_MATCH_UTF8_on(prog) \
                                        : RXp_MATCH_UTF8_off(prog))
#define RXp_MINLEN(prog)                (prog->minlen)
#define RXp_MINLENRET(prog)             (prog->minlenret)
#define RXp_NPARENS(prog)               (prog->nparens)
#define RXp_OFFS(prog)                  (prog->offs)
#define RXp_PAREN_NAMES(rx)	((rx)->paren_names)
#define RXp_SAVED_COPY(prog)            (prog->saved_copy)
#define RXp_SUBBEG(prog)                (prog->subbeg)
#define RXp_SUBOFFSET(prog)             (prog->suboffset)
#define RXp_ZERO_LEN(prog) \
        (RXp_OFFS(prog)[0].start + (SSize_t)RXp_GOFS(prog) \
          == RXp_OFFS(prog)[0].end)
#define ReANY(re)		S_ReANY((const REGEXP *)(re))
#  define ReREFCNT_dec(re)						\
    ({									\
		\
	REGEXP *const _rerefcnt_dec = (re);				\
	SvREFCNT_dec(_rerefcnt_dec);					\
    })
#  define ReREFCNT_inc(re)						\
    ({									\
		\
	REGEXP *const _rerefcnt_inc = (re);				\
	assert(SvTYPE(_rerefcnt_inc) == SVt_REGEXP);			\
	SvREFCNT_inc(_rerefcnt_inc);					\
	_rerefcnt_inc;							\
    })
#define SINGLE_PAT_MOD       's'
#define STD_PAT_MODS        "msixxn"
#define STD_PMMOD_FLAGS_CLEAR(pmfl)                        \
    *(pmfl) &= ~(RXf_PMf_FOLD|RXf_PMf_MULTILINE|RXf_PMf_SINGLELINE|RXf_PMf_EXTENDED|RXf_PMf_EXTENDED_MORE|RXf_PMf_CHARSET|RXf_PMf_NOCAPTURE)
#define SV_SAVED_COPY   SV *saved_copy; 
#define S_PAT_MODS      M_PAT_MODS      EXEC_PAT_MODS      NONDESTRUCT_PAT_MODS
#define SvRX(sv)   (Perl_get_re_arg(aTHX_ sv))
#define SvRXOK(sv) cBOOL(Perl_get_re_arg(aTHX_ sv))
#define UNICODE_PAT_MOD      'u'
#define UNICODE_PAT_MODS     "u"
#define XTENDED_PAT_MOD      'x'
#define _invlist_intersection(a, b, output) _invlist_intersection_maybe_complement_2nd(a, b, FALSE, output)
#define _invlist_subtract(a, b, output) _invlist_intersection_maybe_complement_2nd(a, b, TRUE, output)
#define _invlist_union(a, b, output) _invlist_union_maybe_complement_2nd(a, b, FALSE, output)
#  define BmFLAGS(sv)		(SvTAIL(sv) ? FBMcf_TAIL : 0)
# define BmPREVIOUS(sv)	0
# define BmRARE(sv)	0
#  define BmUSEFUL(sv)							\
	(*({ SV *const _bmuseful = MUTABLE_SV(sv);			\
	    assert(SvTYPE(_bmuseful) >= SVt_PVIV);			\
	    assert(SvVALID(_bmuseful));					\
	    assert(!SvIOK(_bmuseful));					\
	    &(((XPVIV*) SvANY(_bmuseful))->xiv_u.xivu_iv);              \
	 }))
#define CLONEf_CLONE_HOST 4
#define CLONEf_COPY_STACKS 1
#define CLONEf_JOIN_IN 8
#define CLONEf_KEEP_PTR_TABLE 2
#   define CowREFCNT(sv)	(*(U8 *)(SvPVX(sv)+SvLEN(sv)-1))
#define FmLINES(sv)	((XPVIV*)  SvANY(sv))->xiv_iv
#define Gv_AMG(stash) \
	(HvNAME(stash) && Gv_AMupdate(stash,FALSE) \
	    ? 1					    \
	    : (HvAMAGIC_off(stash), 0))
#define HvAMAGIC(hv)		(SvFLAGS(hv) & SVf_AMAGIC)
#define HvAMAGIC_off(hv)	(SvFLAGS(hv) &=~ SVf_AMAGIC)
#define HvAMAGIC_on(hv)		(SvFLAGS(hv) |= SVf_AMAGIC)
#define IoANY(sv)	((XPVIO*)  SvANY(sv))->xio_any
#define IoBOTTOM_GV(sv)	((XPVIO*)  SvANY(sv))->xio_bottom_gv
#define IoBOTTOM_NAME(sv)((XPVIO*) SvANY(sv))->xio_bottom_name
#define IoDIRP(sv)	((XPVIO*)  SvANY(sv))->xio_dirp
#define IoFLAGS(sv)	((XPVIO*)  SvANY(sv))->xio_flags
#define IoFMT_GV(sv)	((XPVIO*)  SvANY(sv))->xio_fmt_gv
#define IoFMT_NAME(sv)	((XPVIO*)  SvANY(sv))->xio_fmt_name
#define IoIFP(sv)	(sv)->sv_u.svu_fp
#define IoLINES(sv)	((XPVIO*)  SvANY(sv))->xiv_u.xivu_iv
#define IoLINES_LEFT(sv)((XPVIO*)  SvANY(sv))->xio_lines_left
#define IoOFP(sv)	((XPVIO*)  SvANY(sv))->xio_ofp
#define IoPAGE(sv)	((XPVIO*)  SvANY(sv))->xio_page
#define IoPAGE_LEN(sv)	((XPVIO*)  SvANY(sv))->xio_page_len
#define IoTOP_GV(sv)	((XPVIO*)  SvANY(sv))->xio_top_gv
#define IoTOP_NAME(sv)	((XPVIO*)  SvANY(sv))->xio_top_name
#define IoTYPE(sv)	((XPVIO*)  SvANY(sv))->xio_type
#define IoTYPE_APPEND 		'a'
#define LVf_NEG_LEN      0x2
#define LVf_NEG_OFF      0x1
#define LVf_OUT_OF_RANGE 0x4
#define LvFLAGS(sv)	((XPVLV*)  SvANY(sv))->xlv_flags
#define LvSTARGOFF(sv)	((XPVLV*)  SvANY(sv))->xlv_targoff_u.xlvu_stargoff
#define LvTARG(sv)	((XPVLV*)  SvANY(sv))->xlv_targ
#define LvTARGLEN(sv)	((XPVLV*)  SvANY(sv))->xlv_targlen
#define LvTARGOFF(sv)	((XPVLV*)  SvANY(sv))->xlv_targoff
#define LvTYPE(sv)	((XPVLV*)  SvANY(sv))->xlv_type
#  define SET_SVANY_FOR_BODYLESS_IV(sv) \
	SvANY(sv) =   (XPVIV*)((char*)&(sv->sv_u.svu_iv) \
                    - STRUCT_OFFSET(XPVIV, xiv_iv))
#  define SET_SVANY_FOR_BODYLESS_NV(sv) \
	SvANY(sv) =   (XPVNV*)((char*)&(sv->sv_u.svu_nv) \
                    - STRUCT_OFFSET(XPVNV, xnv_u.xnv_nv))
#define SV_CHECK_THINKFIRST(sv) if (SvTHINKFIRST(sv)) \
				    sv_force_normal_flags(sv, 0)
#define SV_CHECK_THINKFIRST_COW_DROP(sv) if (SvTHINKFIRST(sv)) \
				    sv_force_normal_flags(sv, SV_COW_DROP_PV)
#define SV_CONST(name) \
	PL_sv_consts[SV_CONST_##name] \
		? PL_sv_consts[SV_CONST_##name] \
		: (PL_sv_consts[SV_CONST_##name] = newSVpv_share(#name, 0))
#define SV_CONSTS_COUNT 35
#define SV_CONST_BINMODE 28
#define SV_CONST_CLEAR 32
#define SV_CONST_CLOSE 30
#define SV_CONST_DELETE 31
#define SV_CONST_DESTROY 34
#define SV_CONST_EOF 27
#define SV_CONST_EXISTS 8
#define SV_CONST_EXTEND 14
#define SV_CONST_FETCH 4
#define SV_CONST_FETCHSIZE 5
#define SV_CONST_FILENO 29
#define SV_CONST_FIRSTKEY 15
#define SV_CONST_GETC 24
#define SV_CONST_NEXTKEY 16
#define SV_CONST_OPEN 18
#define SV_CONST_POP 10
#define SV_CONST_PRINT 20
#define SV_CONST_PRINTF 21
#define SV_CONST_PUSH 9
#define SV_CONST_READ 22
#define SV_CONST_READLINE 23
#define SV_CONST_SCALAR 17
#define SV_CONST_SEEK 25
#define SV_CONST_SHIFT 11
#define SV_CONST_SPLICE 13
#define SV_CONST_STORE 6
#define SV_CONST_STORESIZE 7
#define SV_CONST_TELL 26
#define SV_CONST_TIEARRAY 1
#define SV_CONST_TIEHANDLE 3
#define SV_CONST_TIEHASH 2
#define SV_CONST_TIESCALAR 0
#define SV_CONST_UNSHIFT 12
#define SV_CONST_UNTIE 33
#define SV_CONST_WRITE 19
#define SVf_UTF8        0x20000000  
#define SVpav_REIFY 	0x80000000  
#define SVphv_SHAREKEYS 0x20000000  
#define SVprv_PCS_IMPORTED  SVp_SCREAM  
#define SVprv_WEAKREF   0x80000000  
#  define SVt_FIRST SVt_NULL	
#define SVt_MASK 0xf	
#define SvAMAGIC(sv)		(SvROK(sv) && SvOBJECT(SvRV(sv)) &&	\
				 HvAMAGIC(SvSTASH(SvRV(sv))))
#define SvANY(sv)	(sv)->sv_any
#   define SvCANCOW(sv)					    \
	(SvIsCOW(sv)					     \
	 ? SvLEN(sv) ? CowREFCNT(sv) != SV_COW_REFCNT_MAX : 1 \
	 : (SvFLAGS(sv) & CAN_COW_MASK) == CAN_COW_FLAGS       \
			    && SvCUR(sv)+1 < SvLEN(sv))
#  define SvCOMPILED(sv)	0
#  define SvCOMPILED_off(sv)
#  define SvCOMPILED_on(sv)
#    define SvCUR(sv)							\
	(*({ const SV *const _svcur = (const SV *)(sv);			\
	    assert(PL_valid_types_PVX[SvTYPE(_svcur) & SVt_MASK]);	\
	    assert(!isGV_with_GP(_svcur));				\
	    assert(!(SvTYPE(_svcur) == SVt_PVIO				\
		     && !(IoFLAGS(_svcur) & IOf_FAKE_DIRP)));		\
	    &(((XPV*) MUTABLE_PTR(SvANY(_svcur)))->xpv_cur);		\
	 }))
#define SvCUR_set(sv, val) \
	STMT_START { \
		assert(PL_valid_types_PVX[SvTYPE(sv) & SVt_MASK]);	\
		assert(!isGV_with_GP(sv));		\
		assert(!(SvTYPE(sv) == SVt_PVIO		\
		     && !(IoFLAGS(sv) & IOf_FAKE_DIRP))); \
		(((XPV*)  SvANY(sv))->xpv_cur = (val)); } STMT_END
#define SvDESTROYABLE(sv) PL_destroyhook(aTHX_ sv)
#  define SvEND(sv) ((sv)->sv_u.svu_pv + ((XPV*)SvANY(sv))->xpv_cur)
#define SvEND_set(sv, val) \
	STMT_START { assert(SvTYPE(sv) >= SVt_PV); \
		SvCUR_set(sv, (val) - SvPVX(sv)); } STMT_END
#define SvENDx(sv) ((PL_Sv = (sv)), SvEND(PL_Sv))
#define SvFAKE(sv)		(SvFLAGS(sv) & SVf_FAKE)
#define SvFAKE_off(sv)		(SvFLAGS(sv) &= ~SVf_FAKE)
#define SvFAKE_on(sv)		(SvFLAGS(sv) |= SVf_FAKE)
#define SvFLAGS(sv)	(sv)->sv_flags
#define SvGAMAGIC(sv)           (SvGMAGICAL(sv) || SvAMAGIC(sv))
#define SvGETMAGIC(x) ((void)(UNLIKELY(SvGMAGICAL(x)) && mg_get(x)))
#define SvGMAGICAL(sv)		(SvFLAGS(sv) & SVs_GMG)
#define SvGMAGICAL_off(sv)	(SvFLAGS(sv) &= ~SVs_GMG)
#define SvGMAGICAL_on(sv)	(SvFLAGS(sv) |= SVs_GMG)
# define SvGROW(sv,len) \
	(SvIsCOW(sv) || SvLEN(sv) < (len) ? sv_grow(sv,len) : SvPVX(sv))
#define SvGROW_mutable(sv,len) \
    (SvLEN(sv) < (len) ? sv_grow(sv,len) : SvPVX_mutable(sv))
#define SvIMMORTAL(sv) \
                (  SvREADONLY(sv) \
                && (SvIMMORTAL_INTERP(sv) || (sv) == &PL_sv_placeholder))
#define SvIMMORTAL_INTERP(sv) ((Size_t)((sv) - &PL_sv_yes) < 4)
#define SvIMMORTAL_TRUE(sv)   ((sv) == &PL_sv_yes)
#define SvIOK(sv)		(SvFLAGS(sv) & SVf_IOK)
#define SvIOK_UV(sv)		((SvFLAGS(sv) & (SVf_IOK|SVf_IVisUV))	\
				 == (SVf_IOK|SVf_IVisUV))
#define SvIOK_nog(sv)		((SvFLAGS(sv) & (SVf_IOK|SVs_GMG)) == SVf_IOK)
#define SvIOK_nogthink(sv)	((SvFLAGS(sv) & (SVf_IOK|SVf_THINKFIRST|SVs_GMG)) == SVf_IOK)
#define SvIOK_notUV(sv)		((SvFLAGS(sv) & (SVf_IOK|SVf_IVisUV))	\
				 == SVf_IOK)
#define SvIOK_off(sv)		(SvFLAGS(sv) &= ~(SVf_IOK|SVp_IOK|SVf_IVisUV))
#define SvIOK_on(sv)		(assert_not_glob(sv)	\
				    SvFLAGS(sv) |= (SVf_IOK|SVp_IOK))
#define SvIOK_only(sv)		(SvOK_off(sv), \
				    SvFLAGS(sv) |= (SVf_IOK|SVp_IOK))
#define SvIOK_only_UV(sv)	(assert_not_glob(sv) SvOK_off_exc_UV(sv), \
				    SvFLAGS(sv) |= (SVf_IOK|SVp_IOK))
#define SvIOKp(sv)		(SvFLAGS(sv) & SVp_IOK)
#define SvIOKp_on(sv)		(assert_not_glob(sv)	\
				    SvFLAGS(sv) |= SVp_IOK)
#define SvIS_FREED(sv)	UNLIKELY(((sv)->sv_flags == SVTYPEMASK))
#define SvIV(sv) (SvIOK_nog(sv) ? SvIVX(sv) : sv_2iv(sv))
#    define SvIVX(sv)							\
	(*({ const SV *const _svivx = (const SV *)(sv);			\
	    assert(PL_valid_types_IVX[SvTYPE(_svivx) & SVt_MASK]);	\
	    assert(!isGV_with_GP(_svivx));				\
	    &(((XPVIV*) MUTABLE_PTR(SvANY(_svivx)))->xiv_iv);		\
	 }))
#define SvIVXx(sv) SvIVX(sv)
#define SvIV_nomg(sv) (SvIOK(sv) ? SvIVX(sv) : sv_2iv_flags(sv, 0))
#define SvIV_please(sv) \
	STMT_START {if (!SvIOKp(sv) && (SvFLAGS(sv) & (SVf_NOK|SVf_POK))) \
		(void) SvIV(sv); } STMT_END
#define SvIV_please_nomg(sv) \
	(!(SvFLAGS(sv) & (SVf_IOK|SVp_IOK)) && (SvFLAGS(sv) & (SVf_NOK|SVf_POK)) \
	    ? (sv_2iv_flags(sv, 0), SvIOK(sv))	  \
	    : SvIOK(sv))
#define SvIV_set(sv, val) \
	STMT_START { \
		assert(PL_valid_types_IV_set[SvTYPE(sv) & SVt_MASK]);	\
		assert(!isGV_with_GP(sv));		\
		(((XPVIV*)  SvANY(sv))->xiv_iv = (val)); } STMT_END
#  define SvIVx(sv) ({SV *_sv = MUTABLE_SV(sv); SvIV(_sv); })
#define SvIsCOW(sv)		(SvFLAGS(sv) & SVf_IsCOW)
#define SvIsCOW_off(sv)		(SvFLAGS(sv) &= ~SVf_IsCOW)
#define SvIsCOW_on(sv)		(SvFLAGS(sv) |= SVf_IsCOW)
#define SvIsCOW_shared_hash(sv)	(SvIsCOW(sv) && SvLEN(sv) == 0)
#define SvIsUV(sv)		(SvFLAGS(sv) & SVf_IVisUV)
#define SvIsUV_off(sv)		(SvFLAGS(sv) &= ~SVf_IVisUV)
#define SvIsUV_on(sv)		(SvFLAGS(sv) |= SVf_IVisUV)
#  define SvLEN(sv) (0 + ((XPV*) SvANY(sv))->xpv_len)
#define SvLEN_set(sv, val) \
	STMT_START { \
		assert(PL_valid_types_PVX[SvTYPE(sv) & SVt_MASK]);	\
		assert(!isGV_with_GP(sv));	\
		assert(!(SvTYPE(sv) == SVt_PVIO		\
		     && !(IoFLAGS(sv) & IOf_FAKE_DIRP))); \
		(((XPV*)  SvANY(sv))->xpv_len = (val)); } STMT_END
#define SvLENx(sv) SvLEN(sv)
#define SvLOCK(sv) PL_lockhook(aTHX_ sv)
#    define SvMAGIC(sv)							\
	(*({ const SV *const _svmagic = (const SV *)(sv);		\
	    assert(SvTYPE(_svmagic) >= SVt_PVMG);			\
	    &(((XPVMG*) MUTABLE_PTR(SvANY(_svmagic)))->xmg_u.xmg_magic); \
	  }))
#define SvMAGICAL(sv)		(SvFLAGS(sv) & (SVs_GMG|SVs_SMG|SVs_RMG))
#define SvMAGICAL_off(sv)	(SvFLAGS(sv) &= ~(SVs_GMG|SVs_SMG|SVs_RMG))
#define SvMAGICAL_on(sv)	(SvFLAGS(sv) |= (SVs_GMG|SVs_SMG|SVs_RMG))
#define SvMAGIC_set(sv, val) \
        STMT_START { assert(SvTYPE(sv) >= SVt_PVMG); \
                (((XPVMG*)SvANY(sv))->xmg_u.xmg_magic = (val)); } STMT_END
#define SvNIOK(sv)		(SvFLAGS(sv) & (SVf_IOK|SVf_NOK))
#define SvNIOK_nog(sv)		(SvNIOK(sv) && !(SvFLAGS(sv) & SVs_GMG))
#define SvNIOK_nogthink(sv)	(SvNIOK(sv) && !(SvFLAGS(sv) & (SVf_THINKFIRST|SVs_GMG)))
#define SvNIOK_off(sv)		(SvFLAGS(sv) &= ~(SVf_IOK|SVf_NOK| \
						  SVp_IOK|SVp_NOK|SVf_IVisUV))
#define SvNIOKp(sv)		(SvFLAGS(sv) & (SVp_IOK|SVp_NOK))
#define SvNOK(sv)		(SvFLAGS(sv) & SVf_NOK)
#define SvNOK_nog(sv)		((SvFLAGS(sv) & (SVf_NOK|SVs_GMG)) == SVf_NOK)
#define SvNOK_nogthink(sv)	((SvFLAGS(sv) & (SVf_NOK|SVf_THINKFIRST|SVs_GMG)) == SVf_NOK)
#define SvNOK_off(sv)		(SvFLAGS(sv) &= ~(SVf_NOK|SVp_NOK))
#define SvNOK_on(sv)		(assert_not_glob(sv) \
				 SvFLAGS(sv) |= (SVf_NOK|SVp_NOK))
#define SvNOK_only(sv)		(SvOK_off(sv), \
				    SvFLAGS(sv) |= (SVf_NOK|SVp_NOK))
#define SvNOKp(sv)		(SvFLAGS(sv) & SVp_NOK)
#define SvNOKp_on(sv)		(assert_not_glob(sv) SvFLAGS(sv) |= SVp_NOK)
#define SvNV(sv) (SvNOK_nog(sv) ? SvNVX(sv) : sv_2nv(sv))
#    define SvNVX(sv)							\
	(*({ const SV *const _svnvx = (const SV *)(sv);			\
	    assert(PL_valid_types_NVX[SvTYPE(_svnvx) & SVt_MASK]);	\
	    assert(!isGV_with_GP(_svnvx));				\
	    &(((XPVNV*) MUTABLE_PTR(SvANY(_svnvx)))->xnv_u.xnv_nv);	\
	 }))
#define SvNVXx(sv) SvNVX(sv)
#define SvNV_nomg(sv) (SvNOK(sv) ? SvNVX(sv) : sv_2nv_flags(sv, 0))
#define SvNV_set(sv, val) \
	STMT_START { \
		assert(PL_valid_types_NV_set[SvTYPE(sv) & SVt_MASK]);	\
		assert(!isGV_with_GP(sv));		\
		(((XPVNV*)SvANY(sv))->xnv_u.xnv_nv = (val)); } STMT_END
#  define SvNVx(sv) ({SV *_sv = MUTABLE_SV(sv); SvNV(_sv); })
#define SvOBJECT(sv)		(SvFLAGS(sv) & SVs_OBJECT)
#define SvOBJECT_off(sv)	(SvFLAGS(sv) &= ~SVs_OBJECT)
#define SvOBJECT_on(sv)		(SvFLAGS(sv) |= SVs_OBJECT)
#define SvOK(sv)		(SvFLAGS(sv) & SVf_OK)
#define SvOK_off(sv)		(assert_not_ROK(sv) assert_not_glob(sv)	\
				 SvFLAGS(sv) &=	~(SVf_OK|		\
						  SVf_IVisUV|SVf_UTF8),	\
							SvOOK_off(sv))
#define SvOK_off_exc_UV(sv)	(assert_not_ROK(sv)			\
				 SvFLAGS(sv) &=	~(SVf_OK|		\
						  SVf_UTF8),		\
							SvOOK_off(sv))
#define SvOKp(sv)		(SvFLAGS(sv) & (SVp_IOK|SVp_NOK|SVp_POK))
#define SvOOK(sv)		(SvFLAGS(sv) & SVf_OOK)
#define SvOOK_off(sv)		((void)(SvOOK(sv) && (sv_backoff(sv),0)))
#  define SvOOK_offset(sv, offset) STMT_START {				\
	assert(sizeof(offset) == sizeof(STRLEN));			\
	if (SvOOK(sv)) {						\
	    const U8 *_crash = (U8*)SvPVX_const(sv);			\
	    (offset) = *--_crash;					\
	    if (!(offset)) {						\
		_crash -= sizeof(STRLEN);				\
		Copy(_crash, (U8 *)&(offset), sizeof(STRLEN), U8);	\
	    }								\
	    {								\
					\
		const U8 *const _bonk = (U8*)SvPVX_const(sv) - (offset);\
		while (_crash > _bonk) {				\
		    --_crash;						\
		    assert (*_crash == (U8)PTR2UV(_crash));		\
		}							\
	    }								\
	} else {							\
	    (offset) = 0;						\
	}								\
    } STMT_END
#define SvOOK_on(sv)		(SvFLAGS(sv) |= SVf_OOK)
#define SvPADMY(sv)		!(SvFLAGS(sv) & SVs_PADTMP)
# define SvPADMY_on(sv)		SvPADTMP_off(sv)
#define SvPADSTALE(sv)		(SvFLAGS(sv) & (SVs_PADSTALE))
#define SvPADTMP(sv)		(SvFLAGS(sv) & (SVs_PADTMP))
#define SvPADTMP_off(sv)	(SvFLAGS(sv) &= ~SVs_PADTMP)
#define SvPADTMP_on(sv)		(SvFLAGS(sv) |= SVs_PADTMP)
#define SvPCS_IMPORTED(sv)	((SvFLAGS(sv) & (SVf_ROK|SVprv_PCS_IMPORTED)) \
				 == (SVf_ROK|SVprv_PCS_IMPORTED))
#define SvPCS_IMPORTED_off(sv)	(SvFLAGS(sv) &= ~(SVf_ROK|SVprv_PCS_IMPORTED))
#define SvPCS_IMPORTED_on(sv)	(SvFLAGS(sv) |=  (SVf_ROK|SVprv_PCS_IMPORTED))
#define SvPEEK(sv) sv_peek(sv)
#define SvPOK(sv)		(SvFLAGS(sv) & SVf_POK)
#define SvPOK_byte_nog(sv)	((SvFLAGS(sv) & (SVf_POK|SVf_UTF8|SVs_GMG)) == SVf_POK)
#define SvPOK_byte_nogthink(sv)	((SvFLAGS(sv) & (SVf_POK|SVf_UTF8|SVf_THINKFIRST|SVs_GMG)) == SVf_POK)
#define SvPOK_byte_pure_nogthink(sv) \
    ((SvFLAGS(sv) & (SVf_POK|SVf_UTF8|SVf_IOK|SVf_NOK|SVf_ROK|SVpgv_GP|SVf_THINKFIRST|SVs_GMG)) == SVf_POK)
#define SvPOK_nog(sv)		((SvFLAGS(sv) & (SVf_POK|SVs_GMG)) == SVf_POK)
#define SvPOK_nogthink(sv)	((SvFLAGS(sv) & (SVf_POK|SVf_THINKFIRST|SVs_GMG)) == SVf_POK)
#define SvPOK_off(sv)		(SvFLAGS(sv) &= ~(SVf_POK|SVp_POK))
#define SvPOK_on(sv)		(assert_not_ROK(sv) assert_not_glob(sv)	\
				 SvFLAGS(sv) |= (SVf_POK|SVp_POK))
#define SvPOK_only(sv)		(assert_not_ROK(sv) assert_not_glob(sv)	\
				 SvFLAGS(sv) &= ~(SVf_OK|		\
						  SVf_IVisUV|SVf_UTF8),	\
				    SvFLAGS(sv) |= (SVf_POK|SVp_POK))
#define SvPOK_only_UTF8(sv)	(assert_not_ROK(sv) assert_not_glob(sv)	\
				 SvFLAGS(sv) &= ~(SVf_OK|		\
						  SVf_IVisUV),		\
				    SvFLAGS(sv) |= (SVf_POK|SVp_POK))
#define SvPOK_pure_nogthink(sv) \
    ((SvFLAGS(sv) & (SVf_POK|SVf_IOK|SVf_NOK|SVf_ROK|SVpgv_GP|SVf_THINKFIRST|SVs_GMG)) == SVf_POK)
#define SvPOK_utf8_nog(sv)	((SvFLAGS(sv) & (SVf_POK|SVf_UTF8|SVs_GMG)) == (SVf_POK|SVf_UTF8))
#define SvPOK_utf8_nogthink(sv)	((SvFLAGS(sv) & (SVf_POK|SVf_UTF8|SVf_THINKFIRST|SVs_GMG)) == (SVf_POK|SVf_UTF8))
#define SvPOK_utf8_pure_nogthink(sv) \
    ((SvFLAGS(sv) & (SVf_POK|SVf_UTF8|SVf_IOK|SVf_NOK|SVf_ROK|SVpgv_GP|SVf_THINKFIRST|SVs_GMG)) == (SVf_POK|SVf_UTF8))
#define SvPOKp(sv)		(SvFLAGS(sv) & SVp_POK)
#define SvPOKp_on(sv)		(assert_not_ROK(sv) assert_not_glob(sv)	\
				 SvFLAGS(sv) |= SVp_POK)
#define SvPV(sv, lp)         SvPV_flags(sv, lp, SV_GMAGIC)
#define SvPVCLEAR(sv) sv_setpv_bufsize(sv,0,0)
#    define SvPVX(sv) (0 + (assert_(!SvREADONLY(sv)) (sv)->sv_u.svu_pv))
#  define SvPVX_const(sv)	((const char*)(0 + (sv)->sv_u.svu_pv))
#  define SvPVX_mutable(sv)	(0 + (sv)->sv_u.svu_pv)
#define SvPVXtrue(sv)	(					\
    ((XPV*)SvANY((sv))) 					\
     && (							\
	((XPV*)SvANY((sv)))->xpv_cur > 1			\
	|| (							\
	    ((XPV*)SvANY((sv)))->xpv_cur			\
	    && *(sv)->sv_u.svu_pv != '0'				\
	)							\
    )								\
)
#define SvPVXx(sv) SvPVX(sv)
#define SvPV_const(sv, lp)   SvPV_flags_const(sv, lp, SV_GMAGIC)
#define SvPV_flags(sv, lp, flags) \
    (SvPOK_nog(sv) \
     ? ((lp = SvCUR(sv)), SvPVX(sv)) : sv_2pv_flags(sv, &lp, flags))
#define SvPV_flags_const(sv, lp, flags) \
    (SvPOK_nog(sv) \
     ? ((lp = SvCUR(sv)), SvPVX_const(sv)) : \
     (const char*) sv_2pv_flags(sv, &lp, (flags|SV_CONST_RETURN)))
#define SvPV_flags_const_nolen(sv, flags) \
    (SvPOK_nog(sv) \
     ? SvPVX_const(sv) : \
     (const char*) sv_2pv_flags(sv, 0, (flags|SV_CONST_RETURN)))
#define SvPV_flags_mutable(sv, lp, flags) \
    (SvPOK_nog(sv) \
     ? ((lp = SvCUR(sv)), SvPVX_mutable(sv)) : \
     sv_2pv_flags(sv, &lp, (flags|SV_MUTABLE_RETURN)))
#define SvPV_force(sv, lp) SvPV_force_flags(sv, lp, SV_GMAGIC)
#define SvPV_force_flags(sv, lp, flags) \
    (SvPOK_pure_nogthink(sv) \
     ? ((lp = SvCUR(sv)), SvPVX(sv)) : sv_pvn_force_flags(sv, &lp, flags))
#define SvPV_force_flags_mutable(sv, lp, flags) \
    (SvPOK_pure_nogthink(sv) \
     ? ((lp = SvCUR(sv)), SvPVX_mutable(sv)) \
     : sv_pvn_force_flags(sv, &lp, flags|SV_MUTABLE_RETURN))
#define SvPV_force_flags_nolen(sv, flags) \
    (SvPOK_pure_nogthink(sv) \
     ? SvPVX(sv) : sv_pvn_force_flags(sv, 0, flags))
#define SvPV_force_mutable(sv, lp) SvPV_force_flags_mutable(sv, lp, SV_GMAGIC)
#define SvPV_force_nolen(sv) SvPV_force_flags_nolen(sv, SV_GMAGIC)
#define SvPV_force_nomg(sv, lp) SvPV_force_flags(sv, lp, 0)
#define SvPV_force_nomg_nolen(sv) SvPV_force_flags_nolen(sv, 0)
#define SvPV_free(sv)							\
    STMT_START {							\
		     assert(SvTYPE(sv) >= SVt_PV);			\
		     if (SvLEN(sv)) {					\
			 assert(!SvROK(sv));				\
			 if(UNLIKELY(SvOOK(sv))) {			\
			     STRLEN zok; 				\
			     SvOOK_offset(sv, zok);			\
			     SvPV_set(sv, SvPVX_mutable(sv) - zok);	\
			     SvFLAGS(sv) &= ~SVf_OOK;			\
			 }						\
			 Safefree(SvPVX(sv));				\
		     }							\
		 } STMT_END
#define SvPV_mutable(sv, lp) SvPV_flags_mutable(sv, lp, SV_GMAGIC)
#define SvPV_nolen(sv) \
    (SvPOK_nog(sv) \
     ? SvPVX(sv) : sv_2pv_flags(sv, 0, SV_GMAGIC))
#define SvPV_nolen_const(sv) \
    (SvPOK_nog(sv) \
     ? SvPVX_const(sv) : sv_2pv_flags(sv, 0, SV_GMAGIC|SV_CONST_RETURN))
#define SvPV_nomg(sv, lp) SvPV_flags(sv, lp, 0)
#define SvPV_nomg_const(sv, lp) SvPV_flags_const(sv, lp, 0)
#define SvPV_nomg_const_nolen(sv) SvPV_flags_const_nolen(sv, 0)
#define SvPV_nomg_nolen(sv) \
    (SvPOK_nog(sv) \
     ? SvPVX(sv) : sv_2pv_flags(sv, 0, 0))
#define SvPV_renew(sv,n) \
	STMT_START { SvLEN_set(sv, n); \
		SvPV_set((sv), (MEM_WRAP_CHECK_(n,char)			\
				(char*)saferealloc((Malloc_t)SvPVX(sv), \
						   (MEM_SIZE)((n)))));  \
		 } STMT_END
#define SvPV_set(sv, val) \
	STMT_START { \
		assert(PL_valid_types_PVX[SvTYPE(sv) & SVt_MASK]);	\
		assert(!isGV_with_GP(sv));		\
		assert(!(SvTYPE(sv) == SVt_PVIO		\
		     && !(IoFLAGS(sv) & IOf_FAKE_DIRP))); \
		((sv)->sv_u.svu_pv = (val)); } STMT_END
#define SvPV_shrink_to_cur(sv) STMT_START { \
		   const STRLEN _lEnGtH = SvCUR(sv) + 1; \
		   SvPV_renew(sv, _lEnGtH); \
		 } STMT_END
#define SvPVbyte(sv, lp) \
    (SvPOK_byte_nog(sv) \
     ? ((lp = SvCUR(sv)), SvPVX(sv)) : sv_2pvbyte(sv, &lp))
#define SvPVbyte_force(sv, lp) \
    (SvPOK_byte_pure_nogthink(sv) \
     ? ((lp = SvCUR(sv)), SvPVX(sv)) : sv_pvbyten_force(sv, &lp))
#define SvPVbyte_nolen(sv) \
    (SvPOK_byte_nog(sv) \
     ? SvPVX(sv) : sv_2pvbyte(sv, 0))
#  define SvPVbytex(sv, lp) ({SV *_sv = (sv); SvPVbyte(_sv, lp); })
#define SvPVbytex_force(sv, lp) sv_pvbyten_force(sv, &lp)
#  define SvPVbytex_nolen(sv) ({SV *_sv = (sv); SvPVbyte_nolen(_sv); })
#define SvPVutf8(sv, lp) \
    (SvPOK_utf8_nog(sv) \
     ? ((lp = SvCUR(sv)), SvPVX(sv)) : sv_2pvutf8(sv, &lp))
#define SvPVutf8_force(sv, lp) \
    (SvPOK_utf8_pure_nogthink(sv) \
     ? ((lp = SvCUR(sv)), SvPVX(sv)) : sv_pvutf8n_force(sv, &lp))
#define SvPVutf8_nolen(sv) \
    (SvPOK_utf8_nog(sv) \
     ? SvPVX(sv) : sv_2pvutf8(sv, 0))
#  define SvPVutf8x(sv, lp) ({SV *_sv = (sv); SvPVutf8(_sv, lp); })
#define SvPVutf8x_force(sv, lp) sv_pvutf8n_force(sv, &lp)
#  define SvPVx(sv, lp) ({SV *_sv = (sv); SvPV(_sv, lp); })
#  define SvPVx_const(sv, lp) ({SV *_sv = (sv); SvPV_const(_sv, lp); })
#define SvPVx_force(sv, lp) sv_pvn_force(sv, &lp)
#  define SvPVx_nolen(sv) ({SV *_sv = (sv); SvPV_nolen(_sv); })
#  define SvPVx_nolen_const(sv) ({SV *_sv = (sv); SvPV_nolen_const(_sv); })
#define SvREADONLY(sv)		(SvFLAGS(sv) & (SVf_READONLY|SVf_PROTECT))
# define SvREADONLY_off(sv)	(SvFLAGS(sv) &=~(SVf_READONLY|SVf_PROTECT))
# define SvREADONLY_on(sv)	(SvFLAGS(sv) |= (SVf_READONLY|SVf_PROTECT))
#define SvREFCNT(sv)	(sv)->sv_refcnt
#  define SvREFCNT_IMMORTAL 1000
#define SvREFCNT_inc(sv)		S_SvREFCNT_inc(MUTABLE_SV(sv))
#define SvREFCNT_inc_NN(sv)		S_SvREFCNT_inc_NN(MUTABLE_SV(sv))
#define SvREFCNT_inc_simple(sv)		SvREFCNT_inc(sv)
#define SvREFCNT_inc_simple_NN(sv)	(++(SvREFCNT(sv)),MUTABLE_SV(sv))
#define SvREFCNT_inc_simple_void(sv)	STMT_START { if (sv) SvREFCNT(sv)++; } STMT_END
#define SvREFCNT_inc_simple_void_NN(sv)	(void)(++SvREFCNT(MUTABLE_SV(sv)))
#define SvREFCNT_inc_void(sv)		S_SvREFCNT_inc_void(MUTABLE_SV(sv))
#define SvREFCNT_inc_void_NN(sv)	(void)(++SvREFCNT(MUTABLE_SV(sv)))
#define SvRMAGICAL(sv)		(SvFLAGS(sv) & SVs_RMG)
#define SvRMAGICAL_off(sv)	(SvFLAGS(sv) &= ~SVs_RMG)
#define SvRMAGICAL_on(sv)	(SvFLAGS(sv) |= SVs_RMG)
#define SvROK(sv)		(SvFLAGS(sv) & SVf_ROK)
#define SvROK_off(sv)		(SvFLAGS(sv) &= ~(SVf_ROK))
#define SvROK_on(sv)		(SvFLAGS(sv) |= SVf_ROK)
#    define SvRV(sv)							\
	(*({ SV *const _svrv = MUTABLE_SV(sv);				\
	    assert(PL_valid_types_RV[SvTYPE(_svrv) & SVt_MASK]);	\
	    assert(!isGV_with_GP(_svrv));				\
	    assert(!(SvTYPE(_svrv) == SVt_PVIO				\
		     && !(IoFLAGS(_svrv) & IOf_FAKE_DIRP)));		\
	    &((_svrv)->sv_u.svu_rv);					\
	 }))
#    define SvRV_const(sv)						\
	({ const SV *const _svrv = (const SV *)(sv);			\
	    assert(PL_valid_types_RV[SvTYPE(_svrv) & SVt_MASK]);	\
	    assert(!isGV_with_GP(_svrv));				\
	    assert(!(SvTYPE(_svrv) == SVt_PVIO				\
		     && !(IoFLAGS(_svrv) & IOf_FAKE_DIRP)));		\
	    (_svrv)->sv_u.svu_rv;					\
	 })
#define SvRV_set(sv, val) \
        STMT_START { \
		assert(PL_valid_types_RV[SvTYPE(sv) & SVt_MASK]);	\
		assert(!isGV_with_GP(sv));		\
		assert(!(SvTYPE(sv) == SVt_PVIO		\
		     && !(IoFLAGS(sv) & IOf_FAKE_DIRP))); \
                ((sv)->sv_u.svu_rv = (val)); } STMT_END
#define SvRVx(sv) SvRV(sv)
#define SvSCREAM(sv) ((SvFLAGS(sv) & (SVp_SCREAM|SVp_POK)) == (SVp_SCREAM|SVp_POK))
#define SvSCREAM_off(sv)	(SvFLAGS(sv) &= ~SVp_SCREAM)
#define SvSCREAM_on(sv)		(SvFLAGS(sv) |= SVp_SCREAM)
#define SvSETMAGIC(x) STMT_START { if (UNLIKELY(SvSMAGICAL(x))) mg_set(x); } STMT_END
#define SvSHARE(sv) PL_sharehook(aTHX_ sv)
#define SvSHARED_HASH(sv) (0 + SvSHARED_HEK_FROM_PV(SvPVX_const(sv))->hek_hash)
#define SvSHARED_HEK_FROM_PV(pvx) \
	((struct hek*)(pvx - STRUCT_OFFSET(struct hek, hek_key)))
#define SvSMAGICAL(sv)		(SvFLAGS(sv) & SVs_SMG)
#define SvSMAGICAL_off(sv)	(SvFLAGS(sv) &= ~SVs_SMG)
#define SvSMAGICAL_on(sv)	(SvFLAGS(sv) |= SVs_SMG)
#    define SvSTASH(sv)							\
	(*({ const SV *const _svstash = (const SV *)(sv);		\
	    assert(SvTYPE(_svstash) >= SVt_PVMG);			\
	    &(((XPVMG*) MUTABLE_PTR(SvANY(_svstash)))->xmg_stash);	\
	  }))
#define SvSTASH_set(sv, val) \
        STMT_START { assert(SvTYPE(sv) >= SVt_PVMG); \
                (((XPVMG*)  SvANY(sv))->xmg_stash = (val)); } STMT_END
#define SvSetMagicSV(dst,src) \
		SvSetSV_and(dst,src,SvSETMAGIC(dst))
#define SvSetMagicSV_nosteal(dst,src) \
		SvSetSV_nosteal_and(dst,src,SvSETMAGIC(dst))
#define SvSetSV(dst,src) \
		SvSetSV_and(dst,src,;)
#define SvSetSV_and(dst,src,finally) \
	STMT_START {					\
	    if (LIKELY((dst) != (src))) {		\
		sv_setsv(dst, src);			\
		finally;				\
	    }						\
	} STMT_END
#define SvSetSV_nosteal(dst,src) \
		SvSetSV_nosteal_and(dst,src,;)
#define SvSetSV_nosteal_and(dst,src,finally) \
	STMT_START {					\
	    if (LIKELY((dst) != (src))) {			\
		sv_setsv_flags(dst, src, SV_GMAGIC | SV_NOSTEAL | SV_DO_COW_SVSETSV);	\
		finally;				\
	    }						\
	} STMT_END
#  define SvTAIL(sv)	({ const SV *const _svtail = (const SV *)(sv);	\
			    assert(SvTYPE(_svtail) != SVt_PVAV);	\
			    assert(SvTYPE(_svtail) != SVt_PVHV);	\
			    assert(!(SvFLAGS(_svtail) & (SVf_NOK|SVp_NOK))); \
			    assert(SvVALID(_svtail));                        \
                            ((XPVNV*)SvANY(_svtail))->xnv_u.xnv_bm_tail;     \
			})
#define SvTAINT(sv)			\
    STMT_START {			\
        assert(TAINTING_get || !TAINT_get); \
        if (UNLIKELY(TAINT_get))	\
            SvTAINTED_on(sv);	        \
    } STMT_END
#   define SvTAINTED(sv) 0
#define SvTAINTED_off(sv) STMT_START{ if(UNLIKELY(TAINTING_get)){sv_untaint(sv);} }STMT_END
#define SvTAINTED_on(sv)  STMT_START{ if(UNLIKELY(TAINTING_get)){sv_taint(sv);}   }STMT_END
#define SvTEMP(sv)		(SvFLAGS(sv) & SVs_TEMP)
#define SvTEMP_off(sv)		(SvFLAGS(sv) &= ~SVs_TEMP)
#define SvTEMP_on(sv)		(SvFLAGS(sv) |= SVs_TEMP)
#define SvTHINKFIRST(sv)	(SvFLAGS(sv) & SVf_THINKFIRST)
#define SvTRUE(sv)         (LIKELY(sv) && SvTRUE_NN(sv))
#define SvTRUE_NN(sv)      (SvGETMAGIC(sv), SvTRUE_nomg_NN(sv))
#define SvTRUE_common(sv,fallback) (			\
      SvIMMORTAL_INTERP(sv)                             \
        ? SvIMMORTAL_TRUE(sv)                           \
    : !SvOK(sv)						\
	? 0						\
    : SvPOK(sv)						\
	? SvPVXtrue(sv)					\
    : SvIOK(sv)                			        \
        ? (SvIVX(sv) != 0 )           \
    : (SvROK(sv) && !(   SvOBJECT(SvRV(sv))             \
                      && HvAMAGIC(SvSTASH(SvRV(sv)))))  \
        ? TRUE                                          \
    : (fallback))
#define SvTRUE_nomg(sv)    (LIKELY(sv) && SvTRUE_nomg_NN(sv))
#define SvTRUE_nomg_NN(sv) (SvTRUE_common(sv, sv_2bool_nomg(sv)))
#  define SvTRUEx(sv)      ({SV *_sv = (sv); SvTRUE(_sv); })
#  define SvTRUEx_nomg(sv) ({SV *_sv = (sv); SvTRUE_nomg(_sv); })
#define SvTYPE(sv)	((svtype)((sv)->sv_flags & SVTYPEMASK))
#define SvUNLOCK(sv) PL_unlockhook(aTHX_ sv)
#define SvUOK(sv)		SvIOK_UV(sv)
#define SvUOK_nog(sv)		((SvFLAGS(sv) & (SVf_IOK|SVf_IVisUV|SVs_GMG)) == (SVf_IOK|SVf_IVisUV))
#define SvUOK_nogthink(sv)	((SvFLAGS(sv) & (SVf_IOK|SVf_IVisUV|SVf_THINKFIRST|SVs_GMG)) == (SVf_IOK|SVf_IVisUV))
#define SvUPGRADE(sv, mt) \
    ((void)(SvTYPE(sv) >= (mt) || (sv_upgrade(sv, mt),1)))
#define SvUTF8(sv)		(SvFLAGS(sv) & SVf_UTF8)
#define SvUTF8_off(sv)		(SvFLAGS(sv) &= ~(SVf_UTF8))
#define SvUTF8_on(sv)		(SvFLAGS(sv) |= (SVf_UTF8))
#define SvUV(sv) (SvUOK_nog(sv) ? SvUVX(sv) : sv_2uv(sv))
#    define SvUVX(sv)							\
	(*({ const SV *const _svuvx = (const SV *)(sv);			\
	    assert(PL_valid_types_IVX[SvTYPE(_svuvx) & SVt_MASK]);	\
	    assert(!isGV_with_GP(_svuvx));				\
	    &(((XPVUV*) MUTABLE_PTR(SvANY(_svuvx)))->xuv_uv);		\
	 }))
#define SvUVXx(sv) SvUVX(sv)
#define SvUV_nomg(sv) (SvIOK(sv) ? SvUVX(sv) : sv_2uv_flags(sv, 0))
#define SvUV_set(sv, val) \
	STMT_START { \
		assert(PL_valid_types_IV_set[SvTYPE(sv) & SVt_MASK]);	\
		assert(!isGV_with_GP(sv));		\
		(((XPVUV*)SvANY(sv))->xuv_uv = (val)); } STMT_END
#  define SvUVx(sv) ({SV *_sv = MUTABLE_SV(sv); SvUV(_sv); })
#define SvVALID(_svvalid) (                                  \
               SvPOKp(_svvalid)                              \
            && SvSMAGICAL(_svvalid)                          \
            && SvMAGIC(_svvalid)                             \
            && (SvMAGIC(_svvalid)->mg_type == PERL_MAGIC_bm  \
                || mg_find(_svvalid, PERL_MAGIC_bm))         \
        )
#define SvVOK(sv)		(SvMAGICAL(sv)				\
				 && mg_find(sv,PERL_MAGIC_vstring))
#define SvVSTRING_mg(sv)	(SvMAGICAL(sv) \
				 ? mg_find(sv,PERL_MAGIC_vstring) : NULL)
#define SvWEAKREF(sv)		((SvFLAGS(sv) & (SVf_ROK|SVprv_WEAKREF)) \
				  == (SVf_ROK|SVprv_WEAKREF))
#define SvWEAKREF_off(sv)	(SvFLAGS(sv) &= ~(SVf_ROK|SVprv_WEAKREF))
#define SvWEAKREF_on(sv)	(SvFLAGS(sv) |=  (SVf_ROK|SVprv_WEAKREF))
#define Sv_Grow sv_grow
#  define _NV_BODYLESS_UNION NV svu_nv;
#define _SV_HEAD(ptrtype) \
    ptrtype	sv_any;			\
    U32		sv_refcnt;		\
    U32		sv_flags	
#define _SV_HEAD_DEBUG ;\
    PERL_BITFIELD32 sv_debug_optype:9;	 \
    PERL_BITFIELD32 sv_debug_inpad:1;	 \
    PERL_BITFIELD32 sv_debug_line:16;	 \
    UV		    sv_debug_serial;	 \
    char *	    sv_debug_file;	 \
    SV *	    sv_debug_parent	
#define _SV_HEAD_UNION \
    union {				\
	char*   svu_pv;			\
	IV      svu_iv;			\
	UV      svu_uv;			\
	_NV_BODYLESS_UNION		\
	SV*     svu_rv;				\
	SV**    svu_array;		\
	HE**	svu_hash;		\
	GP*	svu_gp;			\
	PerlIO *svu_fp;			\
    }	sv_u				\
    _SV_HEAD_DEBUG
#define assert_not_ROK(sv)	assert_(!SvROK(sv) || !SvRV(sv))
#define assert_not_glob(sv)	assert_(!isGV_with_GP(sv))
#define boolSV(b) ((b) ? &PL_sv_yes : &PL_sv_no)
#define isGV(sv) (SvTYPE(sv) == SVt_PVGV)
# define isGV_or_RVCV(kadawp) \
    (isGV(kadawp) || (SvROK(kadawp) && SvTYPE(SvRV(kadawp)) == SVt_PVCV))
#define isGV_with_GP(pwadak) \
	(((SvFLAGS(pwadak) & (SVp_POK|SVpgv_GP)) == SVpgv_GP)	\
	&& (SvTYPE(pwadak) == SVt_PVGV || SvTYPE(pwadak) == SVt_PVLV))
#define isGV_with_GP_off(sv)	STMT_START {			       \
	assert (SvTYPE(sv) == SVt_PVGV || SvTYPE(sv) == SVt_PVLV); \
	assert (!SvPOKp(sv));					       \
	assert (!SvIOKp(sv));					       \
	(SvFLAGS(sv) &= ~SVpgv_GP);				       \
    } STMT_END
#define isGV_with_GP_on(sv)	STMT_START {			       \
	assert (SvTYPE(sv) == SVt_PVGV || SvTYPE(sv) == SVt_PVLV); \
	assert (!SvPOKp(sv));					       \
	assert (!SvIOKp(sv));					       \
	(SvFLAGS(sv) |= SVpgv_GP);				       \
    } STMT_END
#define isREGEXP(sv) \
    (SvTYPE(sv) == SVt_REGEXP				      \
     || (SvFLAGS(sv) & (SVTYPEMASK|SVpgv_GP|SVf_FAKE))        \
	 == (SVt_PVLV|SVf_FAKE))
#define newIO()	MUTABLE_IO(newSV_type(SVt_PVIO))
#define newRV_inc(sv)	newRV(sv)
#define newSVpadname(pn) newSVpvn_utf8(PadnamePV(pn), PadnameLEN(pn), TRUE)
#define newSVpvn_utf8(s, len, u) newSVpvn_flags((s), (len), (u) ? SVf_UTF8 : 0)
#define newSVsv(sv) newSVsv_flags((sv), SV_GMAGIC|SV_NOSTEAL)
#define newSVsv_nomg(sv) newSVsv_flags((sv), SV_NOSTEAL)
#  define prepare_SV_for_RV(sv)						\
    STMT_START {							\
		    if (SvTYPE(sv) < SVt_PV && SvTYPE(sv) != SVt_IV)	\
			sv_upgrade(sv, SVt_IV);				\
		    else if (SvTYPE(sv) >= SVt_PV) {			\
			SvPV_free(sv);					\
			SvLEN_set(sv, 0);				\
                        SvCUR_set(sv, 0);				\
		    }							\
		 } STMT_END
#define sv_2bool(sv) sv_2bool_flags(sv, SV_GMAGIC)
#define sv_2bool_nomg(sv) sv_2bool_flags(sv, 0)
#define sv_2iv(sv) sv_2iv_flags(sv, SV_GMAGIC)
#define sv_2nv(sv) sv_2nv_flags(sv, SV_GMAGIC)
#define sv_2pv(sv, lp) sv_2pv_flags(sv, lp, SV_GMAGIC)
#define sv_2pv_nolen(sv) sv_2pv(sv, 0)
#define sv_2pv_nomg(sv, lp) sv_2pv_flags(sv, lp, 0)
#define sv_2pvbyte_nolen(sv) sv_2pvbyte(sv, 0)
#define sv_2pvutf8_nolen(sv) sv_2pvutf8(sv, 0)
#define sv_2uv(sv) sv_2uv_flags(sv, SV_GMAGIC)
#define sv_cathek(sv,hek)					    \
	STMT_START {						     \
	    HEK * const bmxk = hek;				      \
	    sv_catpvn_flags(sv, HEK_KEY(bmxk), HEK_LEN(bmxk),	       \
			    HEK_UTF8(bmxk) ? SV_CATUTF8 : SV_CATBYTES); \
	} STMT_END
#define sv_catpv_nomg(dsv, sstr) sv_catpv_flags(dsv, sstr, 0)
#define sv_catpvn(dsv, sstr, slen) sv_catpvn_flags(dsv, sstr, slen, SV_GMAGIC)
#define sv_catpvn_mg(sv, sstr, slen) sv_catpvn_flags(sv, sstr, slen, SV_GMAGIC|SV_SMAGIC);
#define sv_catpvn_nomg(dsv, sstr, slen) sv_catpvn_flags(dsv, sstr, slen, 0)
#define sv_catpvn_nomg_maybeutf8(dsv, sstr, slen, is_utf8) \
	sv_catpvn_flags(dsv, sstr, slen, (is_utf8)?SV_CATUTF8:SV_CATBYTES)
#define sv_catpvn_nomg_utf8_upgrade(dsv, sstr, slen, nsv)	\
	STMT_START {					\
	    if (!(nsv))					\
		nsv = newSVpvn_flags(sstr, slen, SVs_TEMP);	\
	    else					\
		sv_setpvn(nsv, sstr, slen);		\
	    SvUTF8_off(nsv);				\
	    sv_utf8_upgrade(nsv);			\
	    sv_catsv_nomg(dsv, nsv);			\
	} STMT_END
#define sv_catsv(dsv, ssv) sv_catsv_flags(dsv, ssv, SV_GMAGIC)
#define sv_catsv_mg(dsv, ssv) sv_catsv_flags(dsv, ssv, SV_GMAGIC|SV_SMAGIC)
#define sv_catsv_nomg(dsv, ssv) sv_catsv_flags(dsv, ssv, 0)
#define sv_cmp(sv1, sv2) sv_cmp_flags(sv1, sv2, SV_GMAGIC)
#define sv_cmp_locale(sv1, sv2) sv_cmp_locale_flags(sv1, sv2, SV_GMAGIC)
#define sv_collxfrm(sv, nxp) sv_cmp_flags(sv, nxp, SV_GMAGIC)
#define sv_copypv(dsv, ssv) sv_copypv_flags(dsv, ssv, SV_GMAGIC)
#define sv_copypv_nomg(dsv, ssv) sv_copypv_flags(dsv, ssv, 0)
#define sv_eq(sv1, sv2) sv_eq_flags(sv1, sv2, SV_GMAGIC)
#define sv_insert(bigstr, offset, len, little, littlelen)		\
	Perl_sv_insert_flags(aTHX_ (bigstr),(offset), (len), (little),	\
			     (littlelen), SV_GMAGIC)
#define sv_mortalcopy(sv) \
	Perl_sv_mortalcopy_flags(aTHX_ sv, SV_GMAGIC|SV_DO_COW_SVSETSV)
# define sv_or_pv_len_utf8(sv, pv, bytelen)	      \
    (SvGAMAGIC(sv)				       \
	? utf8_length((U8 *)(pv), (U8 *)(pv)+(bytelen))	\
	: sv_len_utf8(sv))
#define sv_pv(sv) SvPV_nolen(sv)
#define sv_pvbyte(sv) SvPVbyte_nolen(sv)
#define sv_pvn_force(sv, lp) sv_pvn_force_flags(sv, lp, SV_GMAGIC)
#define sv_pvn_force_nomg(sv, lp) sv_pvn_force_flags(sv, lp, 0)
#define sv_pvutf8(sv) SvPVutf8_nolen(sv)
#define sv_setsv(dsv, ssv) \
	sv_setsv_flags(dsv, ssv, SV_GMAGIC|SV_DO_COW_SVSETSV)
#define sv_setsv_nomg(dsv, ssv) sv_setsv_flags(dsv, ssv, SV_DO_COW_SVSETSV)
#define sv_taint(sv)	  sv_magic((sv), NULL, PERL_MAGIC_taint, NULL, 0)
#define sv_unref(sv)    	sv_unref_flags(sv, 0)
#define sv_usepvn_mg(sv, p, l)	sv_usepvn_flags(sv, p, l, SV_SMAGIC)
#define sv_utf8_upgrade(sv) sv_utf8_upgrade_flags(sv, SV_GMAGIC)
#define sv_utf8_upgrade_flags(sv, flags) sv_utf8_upgrade_flags_grow(sv, flags, 0)
#define sv_utf8_upgrade_nomg(sv) sv_utf8_upgrade_flags(sv, 0)
#define xiv_iv xiv_u.xivu_iv
#define xlv_targoff xlv_targoff_u.xlvu_targoff
#define xuv_uv xuv_u.xivu_uv
#define PERL_BISON_VERSION  30000
# define YYDEBUG 0
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
# define YYTOKENTYPE
#define GCB_BREAKABLE              1
#define GCB_EX_then_EM             3
#define GCB_Maybe_Emoji_NonBreak   4
#define GCB_NOBREAK                0
#define GCB_RI_then_RI             2






#define LB_BREAKABLE                      1
#define LB_CM_ZWJ_foo                     3
#define LB_HY_or_BA_then_foo             13
#define LB_NOBREAK                        0
#define LB_NOBREAK_EVEN_WITH_SP_BETWEEN   2
#define LB_PR_or_PO_then_OP_or_HY         9
#define LB_RI_then_RI                    15
#define LB_SP_foo                         6
#define LB_SY_or_IS_then_various         11
#define LB_various_then_PO_or_PR         32
#define MAX_FOLD_FROMS 3
#define MAX_UNI_KEYWORD_INDEX UNI__PERL_SURROGATE
#define UNI_AHEX   UNI_POSIXXDIGIT
#define UNI_ALNUM   UNI_XPOSIXALNUM
#define UNI_ALPHA   UNI_XPOSIXALPHA
#define UNI_ALPHABETIC   UNI_XPOSIXALPHA
#define UNI_ASCIIHEXDIGIT   UNI_POSIXXDIGIT
#define UNI_BASICLATIN   UNI_ASCII
#define UNI_BLANK   UNI_XPOSIXBLANK
#define UNI_CC   UNI_XPOSIXCNTRL
#define UNI_CNTRL   UNI_XPOSIXCNTRL
#define UNI_CONTROL   UNI_XPOSIXCNTRL
#define UNI_DECIMALNUMBER   UNI_XPOSIXDIGIT
#define UNI_DIGIT   UNI_XPOSIXDIGIT
#define UNI_GRAPH   UNI_XPOSIXGRAPH
#define UNI_HEX   UNI_XPOSIXXDIGIT
#define UNI_HEXDIGIT   UNI_XPOSIXXDIGIT
#define UNI_HORIZSPACE   UNI_XPOSIXBLANK
#define UNI_HYPHEN (UNI_HYPHEN_perl_aux + (MAX_UNI_KEYWORD_INDEX * 2))
#define UNI_LB__SG (UNI_LB__SG_perl_aux + (MAX_UNI_KEYWORD_INDEX * 1))
#define UNI_LC   UNI_CASEDLETTER
#define UNI_LL   UNI_LOWERCASELETTER
#define UNI_LOWER   UNI_XPOSIXLOWER
#define UNI_LOWERCASE   UNI_XPOSIXLOWER
#define UNI_LT   UNI_TITLE
#define UNI_LU   UNI_UPPERCASELETTER
#define UNI_L_   UNI_CASEDLETTER
#define UNI_L_AMP_   UNI_CASEDLETTER
#define UNI_ND   UNI_XPOSIXDIGIT
#define UNI_PERLSPACE   UNI_POSIXSPACE
#define UNI_PERLWORD   UNI_POSIXWORD
#define UNI_PRINT   UNI_XPOSIXPRINT
#define UNI_SPACE   UNI_XPOSIXSPACE
#define UNI_SPACEPERL   UNI_XPOSIXSPACE
#define UNI_TITLECASE   UNI_TITLE
#define UNI_TITLECASELETTER   UNI_TITLE
#define UNI_UPPER   UNI_XPOSIXUPPER
#define UNI_UPPERCASE   UNI_XPOSIXUPPER
#define UNI_WHITESPACE   UNI_XPOSIXSPACE
#define UNI_WORD   UNI_XPOSIXWORD
#define UNI_WSPACE   UNI_XPOSIXSPACE
#define UNI_XDIGIT   UNI_XPOSIXXDIGIT
#define UNI_XPERLSPACE   UNI_XPOSIXSPACE
#define UNI_age_values_index  1
#define UNI_ahex_values_index  2
#define UNI_alpha_values_index  UNI_ahex_values_index
#define UNI_bc_values_index  3
#define UNI_bidic_values_index  UNI_ahex_values_index
#define UNI_bidim_values_index  UNI_ahex_values_index
#define UNI_blk_values_index  4
#define UNI_bpt_values_index  5
#define UNI_cased_values_index  UNI_ahex_values_index
#define UNI_ccc_values_index  6
#define UNI_ce_values_index  UNI_ahex_values_index
#define UNI_ci_values_index  UNI_ahex_values_index
#define UNI_compex_values_index  UNI_ahex_values_index
#define UNI_cwcf_values_index  UNI_ahex_values_index
#define UNI_cwcm_values_index  UNI_ahex_values_index
#define UNI_cwkcf_values_index  UNI_ahex_values_index
#define UNI_cwl_values_index  UNI_ahex_values_index
#define UNI_cwt_values_index  UNI_ahex_values_index
#define UNI_cwu_values_index  UNI_ahex_values_index
#define UNI_dash_values_index  UNI_ahex_values_index
#define UNI_dep_values_index  UNI_ahex_values_index
#define UNI_di_values_index  UNI_ahex_values_index
#define UNI_dia_values_index  UNI_ahex_values_index
#define UNI_dt_values_index  7
#define UNI_ea_values_index  8
#define UNI_ext_values_index  UNI_ahex_values_index
#define UNI_gc_values_index  9
#define UNI_gcb_values_index  10
#define UNI_grbase_values_index  UNI_ahex_values_index
#define UNI_grext_values_index  UNI_ahex_values_index
#define UNI_hex_values_index  UNI_ahex_values_index
#define UNI_hst_values_index  11
#define UNI_hyphen_values_index  UNI_ahex_values_index
#define UNI_idc_values_index  UNI_ahex_values_index
#define UNI_ideo_values_index  UNI_ahex_values_index
#define UNI_ids_values_index  UNI_ahex_values_index
#define UNI_idsb_values_index  UNI_ahex_values_index
#define UNI_idst_values_index  UNI_ahex_values_index
#define UNI_in_values_index  12
#define UNI_inpc_values_index  13
#define UNI_insc_values_index  14
#define UNI_jg_values_index  15
#define UNI_joinc_values_index  UNI_ahex_values_index
#define UNI_jt_values_index  16
#define UNI_lb_values_index  17
#define UNI_loe_values_index  UNI_ahex_values_index
#define UNI_lower_values_index  UNI_ahex_values_index
#define UNI_math_values_index  UNI_ahex_values_index
#define UNI_nchar_values_index  UNI_ahex_values_index
#define UNI_nfcqc_values_index  18
#define UNI_nfdqc_values_index  19
#define UNI_nfkcqc_values_index  UNI_nfcqc_values_index
#define UNI_nfkdqc_values_index  UNI_nfdqc_values_index
#define UNI_nt_values_index  20
#define UNI_nv_values_index  21
#define UNI_patsyn_values_index  UNI_ahex_values_index
#define UNI_patws_values_index  UNI_ahex_values_index
#define UNI_pcm_values_index  UNI_ahex_values_index
#define UNI_qmark_values_index  UNI_ahex_values_index
#define UNI_radical_values_index  UNI_ahex_values_index
#define UNI_ri_values_index  UNI_ahex_values_index
#define UNI_sb_values_index  22
#define UNI_sc_values_index  23
#define UNI_scx_values_index  UNI_sc_values_index
#define UNI_sd_values_index  UNI_ahex_values_index
#define UNI_sterm_values_index  UNI_ahex_values_index
#define UNI_term_values_index  UNI_ahex_values_index
#define UNI_uideo_values_index  UNI_ahex_values_index
#define UNI_upper_values_index  UNI_ahex_values_index
#define UNI_vo_values_index  24
#define UNI_vs_values_index  UNI_ahex_values_index
#define UNI_wb_values_index  25
#define UNI_wspace_values_index  UNI_ahex_values_index
#define UNI_xidc_values_index  UNI_ahex_values_index
#define UNI_xids_values_index  UNI_ahex_values_index
#define WB_BREAKABLE                      1
#define WB_DQ_then_HL                     4
#define WB_Ex_or_FO_or_ZWJ_then_foo       3
#define WB_HL_then_DQ                     6
#define WB_LE_or_HL_then_MB_or_ML_or_SQ   8
#define WB_MB_or_ML_or_SQ_then_LE_or_HL  10
#define WB_MB_or_MN_or_SQ_then_NU        12
#define WB_NOBREAK                        0
#define WB_NU_then_MB_or_MN_or_SQ        14
#define WB_RI_then_RI                    16
#define WB_hs_then_hs                     2
#define BADVERSION(a,b,c) \
	if (b) { \
	    *b = c; \
	} \
	return a;
#define BIT_DIGITS(N)   (((N)*146)/485 + 1)  
#    define CTYPE256
#define C_ARRAY_END(a)		((a) + C_ARRAY_LENGTH(a))
#define C_ARRAY_LENGTH(a)	(sizeof(a)/sizeof((a)[0]))
#define Copy(s,d,n,t)	(MEM_WRAP_CHECK_(n,t) perl_assert_ptr(d), perl_assert_ptr(s), (void)memcpy((char*)(d),(const char*)(s), (n) * sizeof(t)))
#define CopyD(s,d,n,t)	(MEM_WRAP_CHECK_(n,t) perl_assert_ptr(d), perl_assert_ptr(s), memcpy((char*)(d),(const char*)(s), (n) * sizeof(t)))
#define Ctl(ch) ((ch) & 037)
#define FALSE (0)
#define FITS_IN_8_BITS(c) (   (sizeof(c) == 1)                      \
                           || !(((WIDEST_UTYPE)((c) | 0)) & ~0xFF))
#  define FUNCTION__ __func__
#    define HAS_BOOL 1
#define I16_MAX INT16_MAX
#define I16_MIN INT16_MIN
# define I32_MAX PERL_INT_MAX
# define I32_MIN PERL_INT_MIN
#       define INT32_MIN (-2147483647-1)
#       define INT64_MIN (-9223372036854775807LL-1)
#define IN_UTF8_CTYPE_LOCALE PL_in_utf8_CTYPE_locale
#    define MAX(a,b) ((a) > (b) ? (a) : (b))
#define MEM_LOG_ALLOC(n,t,a)     Perl_mem_log_alloc(n,sizeof(t),STRINGIFY(t),a,"__FILE__","__LINE__",FUNCTION__)
#define MEM_LOG_FREE(a)          Perl_mem_log_free(a,"__FILE__","__LINE__",FUNCTION__)
#define MEM_LOG_REALLOC(n,t,v,a) Perl_mem_log_realloc(n,sizeof(t),STRINGIFY(t),v,a,"__FILE__","__LINE__",FUNCTION__)
#define MEM_SIZE_MAX ((MEM_SIZE)-1)
#  define MEM_WRAP_CHECK(n,t) \
	(void)(UNLIKELY(_MEM_WRAP_WILL_WRAP(n,t)) \
        && (croak_memory_wrap(),0))
#define MEM_WRAP_CHECK_(n,t) MEM_WRAP_CHECK(n,t),
#  define MEM_WRAP_CHECK_1(n,t,a) \
	(void)(UNLIKELY(_MEM_WRAP_WILL_WRAP(n,t)) \
	&& (Perl_croak_nocontext("%s",(a)),0))
#  define MEM_WRAP_CHECK_s(n,t,a) \
	(void)(UNLIKELY(_MEM_WRAP_WILL_WRAP(n,t)) \
	&& (Perl_croak_nocontext("" a ""),0))
#    define MIN(a,b) ((a) < (b) ? (a) : (b))
#define MUTABLE_AV(p)	((AV *)MUTABLE_PTR(p))
#define MUTABLE_CV(p)	((CV *)MUTABLE_PTR(p))
#define MUTABLE_GV(p)	((GV *)MUTABLE_PTR(p))
#define MUTABLE_HV(p)	((HV *)MUTABLE_PTR(p))
#define MUTABLE_IO(p)	((IO *)MUTABLE_PTR(p))
#  define MUTABLE_PTR(p) ({ void *_p = (p); _p; })
#define MUTABLE_SV(p)	((SV *)MUTABLE_PTR(p))
#define Move(s,d,n,t)	(MEM_WRAP_CHECK_(n,t) perl_assert_ptr(d), perl_assert_ptr(s), (void)memmove((char*)(d),(const char*)(s), (n) * sizeof(t)))
#define MoveD(s,d,n,t)	(MEM_WRAP_CHECK_(n,t) perl_assert_ptr(d), perl_assert_ptr(s), memmove((char*)(d),(const char*)(s), (n) * sizeof(t)))
#define NEWSV(x,len)	newSV(len)
#define NOLINE ((line_t) 4294967295UL)  
#define Newc(x,v,n,t,c)	Newxc(v,n,t,c)
#define Newx(v,n,t)	(v = (MEM_WRAP_CHECK_(n,t) (t*)MEM_LOG_ALLOC(n,t,safemalloc((MEM_SIZE)((n)*sizeof(t))))))
#define Newxc(v,n,t,c)	(v = (MEM_WRAP_CHECK_(n,t) (c*)MEM_LOG_ALLOC(n,t,safemalloc((MEM_SIZE)((n)*sizeof(t))))))
#define Newxz(v,n,t)	(v = (MEM_WRAP_CHECK_(n,t) (t*)MEM_LOG_ALLOC(n,t,safecalloc((n),sizeof(t)))))
#define Newz(x,v,n,t)	Newxz(v,n,t)
#  define Null(type) ((type)NULL)
#  define Nullch Null(char*)
#  define Nullfp Null(PerlIO*)
#  define Nullsv Null(SV*)
#define OCTAL_VALUE(c) (__ASSERT_(isOCTAL(c)) (7 & (c)))

#  define PERL_POISON_EXPR(x) x
#define PERL_STRLEN_ROUNDUP(n) ((void)(((n) > MEM_SIZE_MAX - 2 * PERL_STRLEN_ROUNDUP_QUANTUM) ? (croak_memory_wrap(),0) : 0), _PERL_STRLEN_ROUNDUP_UNCHECKED(n))
#define POSIX_CC_COUNT    (_HIGHEST_REGCOMP_DOT_H_SYNC + 1)
#  define Perl_va_copy(s, d) va_copy(d, s)
#define Poison(d,n,t)		PoisonFree(d,n,t)
#define PoisonFree(d,n,t)	PoisonWith(d,n,t,0xEF)
#define PoisonNew(d,n,t)	PoisonWith(d,n,t,0xAB)
#define PoisonWith(d,n,t,b)	(MEM_WRAP_CHECK_(n,t) (void)memset((char*)(d), (U8)(b), (n) * sizeof(t)))
#define READ_XDIGIT(s)  (__ASSERT_(isXDIGIT(*s)) (0xf & (isDIGIT(*(s))     \
                                                        ? (*(s)++)         \
                                                        : (*(s)++ + 9))))
#define Renew(v,n,t) \
	  (v = (MEM_WRAP_CHECK_(n,t) (t*)MEM_LOG_REALLOC(n,t,v,saferealloc((Malloc_t)(v),(MEM_SIZE)((n)*sizeof(t))))))
#define Renewc(v,n,t,c) \
	  (v = (MEM_WRAP_CHECK_(n,t) (c*)MEM_LOG_REALLOC(n,t,v,saferealloc((Malloc_t)(v),(MEM_SIZE)((n)*sizeof(t))))))
#define STR_WITH_LEN(s)  ("" s ""), (sizeof(s)-1)
#define Safefree(d) \
  ((d) ? (void)(safefree(MEM_LOG_FREE((Malloc_t)(d))), Poison(&(d), 1, Malloc_t)) : (void) 0)
#define StructCopy(s,d,t) (*((t*)(d)) = *((t*)(s)))
#    define SvGID(sv)                SvNV(sv)
#    define SvUID(sv)                SvNV(sv)
#define TRUE (1)
#define TYPE_CHARS(T)   (TYPE_DIGITS(T) + 2) 
#define TYPE_DIGITS(T)  BIT_DIGITS(sizeof(T) * 8)
#define U16_MAX UINT16_MAX
#define U16_MIN UINT16_MIN
#  define U32_MAX UINT32_MAX
# define U32_MIN PERL_UINT_MIN
#define U8_MAX UINT8_MAX
#define U8_MIN UINT8_MIN
#   define WIDEST_UTYPE U64
#define XDIGIT_VALUE(c) (__ASSERT_(isXDIGIT(c)) (0xf & (isDIGIT(c)        \
                                                        ? (c)             \
                                                        : ((c) + 9))))
#define Zero(d,n,t)	(MEM_WRAP_CHECK_(n,t) perl_assert_ptr(d), (void)memzero((char*)(d), (n) * sizeof(t)))
#define ZeroD(d,n,t)	(MEM_WRAP_CHECK_(n,t) perl_assert_ptr(d), memzero((char*)(d), (n) * sizeof(t)))
#  define _CC_ALPHA              2      
#  define _CC_ALPHANUMERIC       7      
#  define _CC_ASCII             14      
#  define _CC_BLANK             11      
#  define _CC_CASED              9      
#  define _CC_CHARNAME_CONT            17
#  define _CC_CNTRL             13      
#  define _CC_DIGIT              1      
#  define _CC_GRAPH              8      
#  define _CC_IDCONT 24 
#  define _CC_IDFIRST                  16
#  define _CC_IS_IN_SOME_FOLD          22
#  define _CC_LOWER              3      
#  define _CC_MNEMONIC_CNTRL           23
#  define _CC_NONLATIN1_FOLD           18
#  define _CC_NONLATIN1_SIMPLE_FOLD    19
#  define _CC_NON_FINAL_FOLD           21
#  define _CC_PRINT              6      
#  define _CC_PSXSPC            _CC_SPACE   
#  define _CC_PUNCT              5      
#  define _CC_QUOTEMETA                20
#  define _CC_SPACE             10      
#  define _CC_UPPER              4      
#  define _CC_UTF8_IS_CONTINUATION                      31
#  define _CC_UTF8_IS_DOWNGRADEABLE_START               30
#  define _CC_UTF8_IS_START                             29
#  define _CC_UTF8_START_BYTE_IS_FOR_AT_LEAST_SURROGATE 28
#  define _CC_VERTSPACE         15      
#  define _CC_WORDCHAR           0      
#  define _CC_XDIGIT            12      
#   define _CC_mask(classnum) (1U << (classnum))
#   define _CC_mask_A(classnum) (_CC_mask(classnum) | _CC_mask(_CC_ASCII))
#   define _HAS_NONLATIN1_FOLD_CLOSURE_ONLY_FOR_USE_BY_REGCOMP_DOT_C_AND_REGEXEC_DOT_C(c) ((! cBOOL(FITS_IN_8_BITS(c))) || (PL_charclass[(U8) (c)] & _CC_mask(_CC_NONLATIN1_FOLD)))
#   define _HAS_NONLATIN1_SIMPLE_FOLD_CLOSURE_ONLY_FOR_USE_BY_REGCOMP_DOT_C_AND_REGEXEC_DOT_C(c) ((! cBOOL(FITS_IN_8_BITS(c))) || (PL_charclass[(U8) (c)] & _CC_mask(_CC_NONLATIN1_SIMPLE_FOLD)))
#  define _HIGHEST_REGCOMP_DOT_H_SYNC _CC_VERTSPACE
#   define _IS_IN_SOME_FOLD_ONLY_FOR_USE_BY_REGCOMP_DOT_C(c) \
                                           _generic_isCC(c, _CC_IS_IN_SOME_FOLD)
#   define _IS_MNEMONIC_CNTRL_ONLY_FOR_USE_BY_REGCOMP_DOT_C(c) \
                                            _generic_isCC(c, _CC_MNEMONIC_CNTRL)
#   define _IS_NON_FINAL_FOLD_ONLY_FOR_USE_BY_REGCOMP_DOT_C(c) \
                                           _generic_isCC(c, _CC_NON_FINAL_FOLD)
#define _LC_CAST U8
#  define _MEM_WRAP_NEEDS_RUNTIME_CHECK(n,t) \
    (  sizeof(MEM_SIZE) < sizeof(n) \
    || sizeof(t) > ((MEM_SIZE)1 << 8*(sizeof(MEM_SIZE) - sizeof(n))))
#  define _MEM_WRAP_WILL_WRAP(n,t) \
      ((_MEM_WRAP_NEEDS_RUNTIME_CHECK(n,t) ? (MEM_SIZE)(n) : \
            MEM_SIZE_MAX/sizeof(t)) > MEM_SIZE_MAX/sizeof(t))
#define _PERL_STRLEN_ROUNDUP_UNCHECKED(n) (((n) - 1 + PERL_STRLEN_ROUNDUP_QUANTUM) & ~((MEM_SIZE)PERL_STRLEN_ROUNDUP_QUANTUM - 1))
#   define __ASSERT_(statement)  assert(statement),
#define _base_generic_utf8(enum_name, name, p, use_locale )                 \
    _is_utf8_FOO(CAT2(_CC_, enum_name),                                     \
                 (const U8 *) p,                                            \
                 "is" STRINGIFY(name) "_utf8",                              \
                 "is" STRINGIFY(name) "_utf8_safe",                         \
                 1, use_locale, "__FILE__","__LINE__")
#define _generic_LC(c, utf8_locale_classnum, non_utf8_func)                    \
                        _generic_LC_base(c,utf8_locale_classnum,               \
                                         non_utf8_func( (_LC_CAST) (c)))
#define _generic_LC_base(c, utf8_locale_classnum, non_utf8)                    \
           (! FITS_IN_8_BITS(c)                                                \
           ? 0                                                                 \
           : IN_UTF8_CTYPE_LOCALE                                              \
             ? cBOOL(PL_charclass[(U8) (c)] & _CC_mask(utf8_locale_classnum))  \
             : cBOOL(non_utf8))
#define _generic_LC_func_utf8_safe(macro, above_latin1, p, e)               \
            _generic_LC_utf8_safe(macro, p, e, above_latin1(p, e))
#define _generic_LC_non_swash_utf8_safe(classnum, above_latin1, p, e)       \
          _generic_LC_utf8_safe(classnum, p, e,                             \
                             (UNLIKELY((e) - (p) < UTF8SKIP(p))             \
                              ? (_force_out_malformed_utf8_message(         \
                                      (U8 *) (p), (U8 *) (e), 0, 1), 0)     \
                              : above_latin1(p)))
#define _generic_LC_swash_utf8_safe(macro, classnum, p, e)                  \
            _generic_LC_utf8_safe(macro, p, e,                              \
                               _is_utf8_FOO_with_len(classnum, p, e))
#define _generic_LC_swash_uvchr(latin1, classnum, c)                          \
                            (c < 256 ? latin1(c) : _is_uni_FOO(classnum, c))
#define _generic_LC_underscore(c,utf8_locale_classnum,non_utf8_func)           \
                        _generic_LC_base(c, utf8_locale_classnum,              \
                                         (non_utf8_func( (_LC_CAST) (c))       \
                                          || (char)(c) == '_'))
#define _generic_LC_utf8(name, p) _base_generic_utf8(name, name, p, 1)
#define _generic_LC_utf8_safe(macro, p, e, above_latin1)                    \
         (__ASSERT_(_utf8_safe_assert(p, e))                                \
         (UTF8_IS_INVARIANT(*(p)))                                          \
          ? macro(*(p))                                                     \
          : (UTF8_IS_DOWNGRADEABLE_START(*(p))                              \
             ? ((LIKELY((e) - (p) > 1 && UTF8_IS_CONTINUATION(*((p)+1))))   \
                ? macro(EIGHT_BIT_UTF8_TO_NATIVE(*(p), *((p)+1)))           \
                : (_force_out_malformed_utf8_message(                       \
                                        (U8 *) (p), (U8 *) (e), 0, 1), 0))  \
              : above_latin1))
#define _generic_LC_uvchr(latin1, above_latin1, c)                            \
                                    (c < 256 ? latin1(c) : above_latin1(c))
#define _generic_func_utf8_safe(classnum, above_latin1, p, e)               \
                    _generic_utf8_safe(classnum, p, e, above_latin1(p, e))
#   define _generic_isCC(c, classnum) cBOOL(FITS_IN_8_BITS(c)    \
                && (PL_charclass[(U8) (c)] & _CC_mask(classnum)))
#   define _generic_isCC_A(c, classnum) (FITS_IN_8_BITS(c)      \
        && ((PL_charclass[(U8) (c)] & _CC_mask_A(classnum))     \
                                   == _CC_mask_A(classnum)))
#define _generic_non_swash_utf8_safe(classnum, above_latin1, p, e)          \
          _generic_utf8_safe(classnum, p, e,                                \
                             (UNLIKELY((e) - (p) < UTF8SKIP(p))             \
                              ? (_force_out_malformed_utf8_message(         \
                                      (U8 *) (p), (U8 *) (e), 0, 1), 0)     \
                              : above_latin1(p)))
#define _generic_swash_utf8_safe(classnum, p, e)                            \
_generic_utf8_safe(classnum, p, e, _is_utf8_FOO_with_len(classnum, p, e))
#define _generic_swash_uvchr(classnum, c) ((c) < 256                        \
                                             ? _generic_isCC(c, classnum)   \
                                             : _is_uni_FOO(classnum, c))
#define _generic_toFOLD_LC(c, function, cast)                                  \
                    ((UNLIKELY((c) == MICRO_SIGN) && IN_UTF8_CTYPE_LOCALE)     \
                      ? GREEK_SMALL_LETTER_MU                                  \
                      : (__ASSERT_(! IN_UTF8_CTYPE_LOCALE                      \
                                   || (c) != LATIN_SMALL_LETTER_SHARP_S)       \
                         _generic_toLOWER_LC(c, function, cast)))
#define _generic_toLOWER_LC(c, function, cast)  (! FITS_IN_8_BITS(c)           \
                                                ? (c)                          \
                                                : (IN_UTF8_CTYPE_LOCALE)       \
                                                  ? PL_latin1_lc[ (U8) (c) ]   \
                                                  : (cast)function((cast)(c)))
#define _generic_toUPPER_LC(c, function, cast)                                 \
                    (! FITS_IN_8_BITS(c)                                       \
                    ? (c)                                                      \
                    : ((! IN_UTF8_CTYPE_LOCALE)                                \
                      ? (cast)function((cast)(c))                              \
                      : ((((U8)(c)) == MICRO_SIGN)                             \
                        ? GREEK_CAPITAL_LETTER_MU                              \
                        : ((((U8)(c)) == LATIN_SMALL_LETTER_Y_WITH_DIAERESIS)  \
                          ? LATIN_CAPITAL_LETTER_Y_WITH_DIAERESIS              \
                          : ((((U8)(c)) == LATIN_SMALL_LETTER_SHARP_S)         \
                            ? (__ASSERT_(0) (c))                               \
                            : PL_mod_latin1_uc[ (U8) (c) ])))))
#define _generic_utf8(name, p) _base_generic_utf8(name, name, p, 0)
#define _generic_utf8_safe(classnum, p, e, above_latin1)                    \
         (__ASSERT_(_utf8_safe_assert(p, e))                                \
         (UTF8_IS_INVARIANT(*(p)))                                          \
          ? _generic_isCC(*(p), classnum)                                   \
          : (UTF8_IS_DOWNGRADEABLE_START(*(p))                              \
             ? ((LIKELY((e) - (p) > 1 && UTF8_IS_CONTINUATION(*((p)+1))))   \
                ? _generic_isCC(EIGHT_BIT_UTF8_TO_NATIVE(*(p), *((p)+1 )),  \
                                classnum)                                   \
                : (_force_out_malformed_utf8_message(                       \
                                        (U8 *) (p), (U8 *) (e), 0, 1), 0))  \
             : above_latin1))
#define _generic_utf8_safe_no_upper_latin1(classnum, p, e, above_latin1)    \
         (__ASSERT_(_utf8_safe_assert(p, e))                                \
         (UTF8_IS_INVARIANT(*(p)))                                          \
          ? _generic_isCC(*(p), classnum)                                   \
          : (UTF8_IS_DOWNGRADEABLE_START(*(p)))                             \
             ? 0           \
             : above_latin1)
#define _generic_uvchr(classnum, above_latin1, c) ((c) < 256                \
                                             ? _generic_isCC(c, classnum)   \
                                             : above_latin1(c))
#   define _isQUOTEMETA(c) _generic_isCC(c, _CC_QUOTEMETA)
#define _toFOLD_utf8_flags(p,e,s,l,f)  _to_utf8_fold_flags (p,e,s,l,f, "", 0)
#define _toLOWER_utf8_flags(p,e,s,l,f) _to_utf8_lower_flags(p,e,s,l,f, "", 0)
#define _toTITLE_utf8_flags(p,e,s,l,f) _to_utf8_title_flags(p,e,s,l,f, "", 0)
#define _toUPPER_utf8_flags(p,e,s,l,f) _to_utf8_upper_flags(p,e,s,l,f, "", 0)
#  define _utf8_safe_assert(p,e) ((e) > (p) || ((e) == (p) && *(p) == '\0'))
# define bool char
#define cBOOL(cbool) ((cbool) ? (bool)1 : (bool)0)
#  define deprecate(s) Perl_ck_warner_d(aTHX_ packWARN(WARN_DEPRECATED),    \
                                            "Use of " s " is deprecated")
#  define deprecate_disappears_in(when,message) \
              Perl_ck_warner_d(aTHX_ packWARN(WARN_DEPRECATED),    \
                               message ", and will disappear in Perl " when)
#  define deprecate_fatal_in(when,message) \
              Perl_ck_warner_d(aTHX_ packWARN(WARN_DEPRECATED),    \
                               message ". Its use will be fatal in Perl " when)
#define get_cvs(str, flags)					\
	Perl_get_cvn_flags(aTHX_ STR_WITH_LEN(str), (flags))
#define gv_fetchpvn(namebeg, len, add, sv_type) \
    Perl_gv_fetchpvn_flags(aTHX_ namebeg, len, add, sv_type)
#define gv_fetchpvs(namebeg, add, sv_type) \
    Perl_gv_fetchpvn_flags(aTHX_ STR_WITH_LEN(namebeg), add, sv_type)
#define gv_stashpvs(str, create) \
    Perl_gv_stashpvn(aTHX_ STR_WITH_LEN(str), create)
#define inRANGE(c, l, u) (__ASSERT_((l) >= 0) __ASSERT_((u) >= (l))            \
  ((sizeof(c) == 1)                                                            \
   ? (((WIDEST_UTYPE) ((((U8) (c))|0) - (l))) <= ((WIDEST_UTYPE) ((u) - (l)))) \
   : (__ASSERT_(   (((WIDEST_UTYPE) 1) <<  (CHARBITS * sizeof(c) - 1) & (c))   \
                                                  == 0 \
                || (((~ ((WIDEST_UTYPE) 1) << ((CHARBITS * sizeof(c) - 1) - 1))\
                       \
                                          & ~ ((WIDEST_UTYPE) 0)) & (l)) == 0) \
      ((WIDEST_UTYPE) (((c) - (l)) | 0) <= ((WIDEST_UTYPE) ((u) - (l)))))))
#define isALNUM(c)          isWORDCHAR(c)
#define isALNUMC(c)	    isALPHANUMERIC(c)
#define isALNUMC_A(c)       isALPHANUMERIC_A(c)      
#define isALNUMC_L1(c)      isALPHANUMERIC_L1(c)
#define isALNUMC_LC(c)	    isALPHANUMERIC_LC(c)
#define isALNUMC_LC_utf8(p) isALPHANUMERIC_LC_utf8(p)
#define isALNUMC_LC_uvchr(c) isALPHANUMERIC_LC_uvchr(c)
#define isALNUMC_uni(c)     isALPHANUMERIC_uni(c)
#define isALNUMC_utf8(p)    isALPHANUMERIC_utf8(p)
#define isALNUMU(c)         isWORDCHAR_L1(c)
#define isALNUM_LC(c)       isWORDCHAR_LC(c)
#define isALNUM_LC_utf8(p)  isWORDCHAR_LC_utf8(p)
#define isALNUM_LC_uvchr(c) isWORDCHAR_LC_uvchr(c)
#define isALNUM_uni(c)      isWORDCHAR_uni(c)
#define isALNUM_utf8(p)     isWORDCHAR_utf8(p)
#define isALPHA(c)   isALPHA_A(c)
#define isALPHANUMERIC(c)  isALPHANUMERIC_A(c)
#   define isALPHANUMERIC_A(c) _generic_isCC_A(c, _CC_ALPHANUMERIC)
#   define isALPHANUMERIC_L1(c) _generic_isCC(c, _CC_ALPHANUMERIC)
#  define isALPHANUMERIC_LC(c)  (_generic_LC(c, _CC_ALPHANUMERIC, isalnum) && \
                                                              ! isPUNCT_LC(c))
#define isALPHANUMERIC_LC_utf8(p)  _generic_LC_utf8(ALPHANUMERIC, p)
#define isALPHANUMERIC_LC_utf8_safe(p, e)                                   \
            _generic_LC_swash_utf8_safe(isALPHANUMERIC_LC,                  \
                                        _CC_ALPHANUMERIC, p, e)
#define isALPHANUMERIC_LC_uvchr(c)  _generic_LC_swash_uvchr(isALPHANUMERIC_LC, \
                                                         _CC_ALPHANUMERIC, c)
#define isALPHANUMERIC_uni(c)   isALPHANUMERIC_uvchr(c)
#define isALPHANUMERIC_utf8(p)  _generic_utf8(ALPHANUMERIC, p)
#define isALPHANUMERIC_utf8_safe(p, e)                                      \
                        _generic_swash_utf8_safe(_CC_ALPHANUMERIC, p, e)
#define isALPHANUMERIC_uvchr(c) _generic_swash_uvchr(_CC_ALPHANUMERIC, c)
#define isALPHAU(c)         isALPHA_L1(c)
#     define isALPHA_A(c)  _generic_isCC_A(c, _CC_ALPHA)
#define isALPHA_FOLD_EQ(c1, c2)                                         \
                      (__ASSERT_(isALPHA_A(c1) || isALPHA_A(c2))        \
                      ((c1) & ~('A' ^ 'a')) ==  ((c2) & ~('A' ^ 'a')))
#define isALPHA_FOLD_NE(c1, c2) (! isALPHA_FOLD_EQ((c1), (c2)))
#   define isALPHA_L1(c)  _generic_isCC(c, _CC_ALPHA)
#  define isALPHA_LC(c)  (_generic_LC(c, _CC_ALPHA, isalpha)                  \
                                                    && isALPHANUMERIC_LC(c))
#define isALPHA_LC_utf8(p)         _generic_LC_utf8(ALPHA, p)
#define isALPHA_LC_utf8_safe(p, e)                                          \
            _generic_LC_swash_utf8_safe(isALPHA_LC, _CC_ALPHA, p, e)
#define isALPHA_LC_uvchr(c)  _generic_LC_swash_uvchr(isALPHA_LC, _CC_ALPHA, c)
#define isALPHA_uni(c)          isALPHA_uvchr(c)
#define isALPHA_utf8(p)         _generic_utf8(ALPHA, p)
#define isALPHA_utf8_safe(p, e)  _generic_swash_utf8_safe(_CC_ALPHA, p, e)
#define isALPHA_uvchr(c)      _generic_swash_uvchr(_CC_ALPHA, c)
#       define isASCII(c) _generic_isCC(c, _CC_ASCII)
#define isASCII_A(c)  isASCII(c)
#define isASCII_L1(c)  isASCII(c)
#   define isASCII_LC(c) (FITS_IN_8_BITS(c) && isascii( (U8) (c)))
#define isASCII_LC_utf8(p)         _generic_LC_utf8(ASCII, p)
#define isASCII_LC_utf8_safe(p, e)                                          \
                    (__ASSERT_(_utf8_safe_assert(p, e)) isASCII_LC(*(p)))
#define isASCII_LC_uvchr(c)   isASCII_LC(c)
#define isASCII_uni(c)          isASCII_uvchr(c)
#define isASCII_utf8(p)         _generic_utf8(ASCII, p)
#define isASCII_utf8_safe(p, e)                                             \
                                                                  \
    (__ASSERT_(_utf8_safe_assert(p, e)) isASCII(*(p)))
#define isASCII_uvchr(c)      isASCII(c)
#define isBLANK(c)   isBLANK_A(c)
#   define isBLANK_A(c)  _generic_isCC_A(c, _CC_BLANK)
#   define isBLANK_L1(c)  _generic_isCC(c, _CC_BLANK)
#   define isBLANK_LC(c) _generic_LC(c, _CC_BLANK, isblank)
#define isBLANK_LC_uni(c)    isBLANK_LC_uvchr(UNI_TO_NATIVE(c))
#define isBLANK_LC_utf8(p)         _generic_LC_utf8(BLANK, p)
#define isBLANK_LC_utf8_safe(p, e)                                          \
        _generic_LC_non_swash_utf8_safe(isBLANK_LC, is_HORIZWS_high, p, e)
#define isBLANK_LC_uvchr(c)  _generic_LC_uvchr(isBLANK_LC,                    \
                                                        is_HORIZWS_cp_high, c)
#define isBLANK_uni(c)          isBLANK_uvchr(c)
#define isBLANK_utf8(p)         _generic_utf8(BLANK, p)
#define isBLANK_utf8_safe(p, e)                                             \
        _generic_non_swash_utf8_safe(_CC_BLANK, is_HORIZWS_high, p, e)
#define isBLANK_uvchr(c)      _generic_uvchr(_CC_BLANK, is_HORIZWS_cp_high, c)
#   define isCHARNAME_CONT(c) _generic_isCC(c, _CC_CHARNAME_CONT)
#define isCNTRL(c)   isCNTRL_A(c)
#   define isCNTRL_A(c)  _generic_isCC_A(c, _CC_CNTRL)
#   define isCNTRL_L1(c)  _generic_isCC(c, _CC_CNTRL)
#  define isCNTRL_LC(c)  _generic_LC(c, _CC_CNTRL, iscntrl)
#define isCNTRL_LC_utf8(p)         _generic_LC_utf8(CNTRL, p)
#define isCNTRL_LC_utf8_safe(p, e)                                          \
            _generic_LC_utf8_safe(isCNTRL_LC, p, e, 0)
#define isCNTRL_LC_uvchr(c)  (c < 256 ? isCNTRL_LC(c) : 0)
#define isCNTRL_uni(c)          isCNTRL_uvchr(c)
#define isCNTRL_utf8(p)         _generic_utf8(CNTRL, p)
#   define isCNTRL_utf8_safe(p, e)                                          \
                    (__ASSERT_(_utf8_safe_assert(p, e)) isCNTRL_L1(*(p)))
#define isCNTRL_uvchr(c)      isCNTRL_L1(c) 
#define isDIGIT(c)   isDIGIT_A(c)
#   define isDIGIT_A(c)  inRANGE(c, '0', '9')
#define isDIGIT_L1(c)       isDIGIT_A(c)
#  define isDIGIT_LC(c)  (_generic_LC(c, _CC_DIGIT, isdigit) &&               \
                                                         isALPHANUMERIC_LC(c))
#define isDIGIT_LC_utf8(p)         _generic_LC_utf8(DIGIT, p)
#define isDIGIT_LC_utf8_safe(p, e)                                          \
            _generic_LC_swash_utf8_safe(isDIGIT_LC, _CC_DIGIT, p, e)
#define isDIGIT_LC_uvchr(c)  _generic_LC_swash_uvchr(isDIGIT_LC, _CC_DIGIT, c)
#define isDIGIT_uni(c)          isDIGIT_uvchr(c)
#define isDIGIT_utf8(p)         _generic_utf8(DIGIT, p)
#define isDIGIT_utf8_safe(p, e)                                             \
            _generic_utf8_safe_no_upper_latin1(_CC_DIGIT, p, e,             \
                                    _is_utf8_FOO_with_len(_CC_DIGIT, p, e))
#define isDIGIT_uvchr(c)      _generic_swash_uvchr(_CC_DIGIT, c)
#define isGRAPH(c)   isGRAPH_A(c)
#     define isGRAPH_A(c)  _generic_isCC_A(c, _CC_GRAPH)
#   define isGRAPH_L1(c)  _generic_isCC(c, _CC_GRAPH)
#  define isGRAPH_LC(c)  (_generic_LC(c, _CC_GRAPH, isgraph) && isPRINT_LC(c))
#define isGRAPH_LC_utf8(p)         _generic_LC_utf8(GRAPH, p)
#define isGRAPH_LC_utf8_safe(p, e)                                          \
            _generic_LC_swash_utf8_safe(isGRAPH_LC, _CC_GRAPH, p, e)
#define isGRAPH_LC_uvchr(c)  _generic_LC_swash_uvchr(isGRAPH_LC, _CC_GRAPH, c)
#define isGRAPH_uni(c)          isGRAPH_uvchr(c)
#define isGRAPH_utf8(p)         _generic_utf8(GRAPH, p)
#define isGRAPH_utf8_safe(p, e)    _generic_swash_utf8_safe(_CC_GRAPH, p, e)
#define isGRAPH_uvchr(c)      _generic_swash_uvchr(_CC_GRAPH, c)
#define isIDCONT(c)             isWORDCHAR(c)
#define isIDCONT_A(c)           isWORDCHAR_A(c)
#define isIDCONT_L1(c)	        isWORDCHAR_L1(c)
#define isIDCONT_LC(c)	        isWORDCHAR_LC(c)
#define isIDCONT_LC_utf8(p)        _generic_LC_utf8(IDCONT, p)
#define isIDCONT_LC_utf8_safe(p, e)                                         \
            _generic_LC_func_utf8_safe(isIDCONT_LC,                         \
                                _is_utf8_perl_idcont_with_len, p, e)
#define isIDCONT_LC_uvchr(c) _generic_LC_uvchr(isIDCONT_LC,                   \
                                                  _is_uni_perl_idcont, c)
#define isIDCONT_uni(c)         isIDCONT_uvchr(c)
#define isIDCONT_utf8(p)        _generic_utf8(IDCONT, p)
#define isIDCONT_utf8_safe(p, e)   _generic_func_utf8_safe(_CC_WORDCHAR,    \
                                     _is_utf8_perl_idcont_with_len, p, e)
#define isIDCONT_uvchr(c)                                                   \
                    _generic_uvchr(_CC_WORDCHAR, _is_uni_perl_idcont, c)
#define isIDFIRST(c) isIDFIRST_A(c)
#   define isIDFIRST_A(c) _generic_isCC_A(c, _CC_IDFIRST)
#   define isIDFIRST_L1(c) _generic_isCC(c, _CC_IDFIRST)
#  define isIDFIRST_LC(c) (((c) == '_')                                       \
                 || (_generic_LC(c, _CC_IDFIRST, isalpha) && ! isPUNCT_LC(c)))
#define isIDFIRST_LC_utf8(p)       _generic_LC_utf8(IDFIRST, p)
#define isIDFIRST_LC_utf8_safe(p, e)                                        \
            _generic_LC_func_utf8_safe(isIDFIRST_LC,                        \
                                _is_utf8_perl_idstart_with_len, p, e)
#define isIDFIRST_LC_uvchr(c) _generic_LC_uvchr(isIDFIRST_LC,                 \
                                                  _is_uni_perl_idstart, c)
#define isIDFIRST_uni(c)        isIDFIRST_uvchr(c)
#define isIDFIRST_utf8(p)       _generic_utf8(IDFIRST, p)
#define isIDFIRST_utf8_safe(p, e)                                           \
    _generic_func_utf8_safe(_CC_IDFIRST,                                    \
                    _is_utf8_perl_idstart_with_len, (U8 *) (p), (U8 *) (e))
#define isIDFIRST_uvchr(c)                                                  \
                    _generic_uvchr(_CC_IDFIRST, _is_uni_perl_idstart, c)
#define isLOWER(c)   isLOWER_A(c)
#     define isLOWER_A(c)  _generic_isCC_A(c, _CC_LOWER)
#   define isLOWER_L1(c)  _generic_isCC(c, _CC_LOWER)
#  define isLOWER_LC(c)  (_generic_LC(c, _CC_LOWER, islower) && isALPHA_LC(c))
#define isLOWER_LC_utf8(p)         _generic_LC_utf8(LOWER, p)
#define isLOWER_LC_utf8_safe(p, e)                                          \
            _generic_LC_swash_utf8_safe(isLOWER_LC, _CC_LOWER, p, e)
#define isLOWER_LC_uvchr(c)  _generic_LC_swash_uvchr(isLOWER_LC, _CC_LOWER, c)
#define isLOWER_uni(c)          isLOWER_uvchr(c)
#define isLOWER_utf8(p)         _generic_utf8(LOWER, p)
#define isLOWER_utf8_safe(p, e)     _generic_swash_utf8_safe(_CC_LOWER, p, e)
#define isLOWER_uvchr(c)      _generic_swash_uvchr(_CC_LOWER, c)
#define isOCTAL(c)          isOCTAL_A(c)
#define isOCTAL_A(c)  (((WIDEST_UTYPE)((c) | 0) & ~7) == '0')
#define isOCTAL_L1(c)       isOCTAL_A(c)
#  define isPOWER_OF_2(n) ((n) && ((n) & ((n)-1)) == 0)
#define isPRINT(c)   isPRINT_A(c)
#     define isPRINT_A(c)  _generic_isCC_A(c, _CC_PRINT)
#   define isPRINT_L1(c)  _generic_isCC(c, _CC_PRINT)
#  define isPRINT_LC(c)  (_generic_LC(c, _CC_PRINT, isprint) && ! isCNTRL_LC(c))
#define isPRINT_LC_utf8(p)         _generic_LC_utf8(PRINT, p)
#define isPRINT_LC_utf8_safe(p, e)                                          \
            _generic_LC_swash_utf8_safe(isPRINT_LC, _CC_PRINT, p, e)
#define isPRINT_LC_uvchr(c)  _generic_LC_swash_uvchr(isPRINT_LC, _CC_PRINT, c)
#define isPRINT_uni(c)          isPRINT_uvchr(c)
#define isPRINT_utf8(p)         _generic_utf8(PRINT, p)
#define isPRINT_utf8_safe(p, e)     _generic_swash_utf8_safe(_CC_PRINT, p, e)
#define isPRINT_uvchr(c)      _generic_swash_uvchr(_CC_PRINT, c)
#define isPSXSPC(c)  isPSXSPC_A(c)
#define isPSXSPC_A(c) isSPACE_A(c)
#   define isPSXSPC_L1(c)  isSPACE_L1(c)
#define isPSXSPC_LC(c)		isSPACE_LC(c)
#define isPSXSPC_LC_utf8(p)        _generic_LC_utf8(PSXSPC, p)
#define isPSXSPC_LC_utf8_safe(p, e)    isSPACE_LC_utf8_safe(p, e)
#define isPSXSPC_LC_uvchr(c)  isSPACE_LC_uvchr(c)
#define isPSXSPC_uni(c)         isPSXSPC_uvchr(c)
#define isPSXSPC_utf8(p)        _generic_utf8(PSXSPC, p)
#define isPSXSPC_utf8_safe(p, e)     isSPACE_utf8_safe(p, e)
#define isPSXSPC_uvchr(c)     isSPACE_uvchr(c)
#define isPUNCT(c)   isPUNCT_A(c)
#   define isPUNCT_A(c)  _generic_isCC_A(c, _CC_PUNCT)
#   define isPUNCT_L1(c)  _generic_isCC(c, _CC_PUNCT)
#  define isPUNCT_LC(c)  (_generic_LC(c, _CC_PUNCT, ispunct) && ! isCNTRL_LC(c))
#define isPUNCT_LC_utf8(p)         _generic_LC_utf8(PUNCT, p)
#define isPUNCT_LC_utf8_safe(p, e)                                          \
            _generic_LC_swash_utf8_safe(isPUNCT_LC, _CC_PUNCT, p, e)
#define isPUNCT_LC_uvchr(c)  _generic_LC_swash_uvchr(isPUNCT_LC, _CC_PUNCT, c)
#define isPUNCT_uni(c)          isPUNCT_uvchr(c)
#define isPUNCT_utf8(p)         _generic_utf8(PUNCT, p)
#define isPUNCT_utf8_safe(p, e)     _generic_swash_utf8_safe(_CC_PUNCT, p, e)
#define isPUNCT_uvchr(c)      _generic_swash_uvchr(_CC_PUNCT, c)
#define isSPACE(c)   isSPACE_A(c)
#   define isSPACE_A(c)  _generic_isCC_A(c, _CC_SPACE)
#   define isSPACE_L1(c)  _generic_isCC(c, _CC_SPACE)
#  define isSPACE_LC(c)  _generic_LC(c, _CC_SPACE, isspace)
#define isSPACE_LC_utf8(p)         _generic_LC_utf8(SPACE, p)
#define isSPACE_LC_utf8_safe(p, e)                                          \
    _generic_LC_non_swash_utf8_safe(isSPACE_LC, is_XPERLSPACE_high, p, e)
#define isSPACE_LC_uvchr(c)  _generic_LC_uvchr(isSPACE_LC,                    \
                                                    is_XPERLSPACE_cp_high, c)
#define isSPACE_uni(c)          isSPACE_uvchr(c)
#define isSPACE_utf8(p)         _generic_utf8(SPACE, p)
#define isSPACE_utf8_safe(p, e)                                             \
    _generic_non_swash_utf8_safe(_CC_SPACE, is_XPERLSPACE_high, p, e)
#define isSPACE_uvchr(c)      _generic_uvchr(_CC_SPACE, is_XPERLSPACE_cp_high, c)
#define isUPPER(c)   isUPPER_A(c)
#     define isUPPER_A(c)  _generic_isCC_A(c, _CC_UPPER)
#   define isUPPER_L1(c)  _generic_isCC(c, _CC_UPPER)
#  define isUPPER_LC(c)  (_generic_LC(c, _CC_UPPER, isupper) && isALPHA_LC(c))
#define isUPPER_LC_utf8(p)         _generic_LC_utf8(UPPER, p)
#define isUPPER_LC_utf8_safe(p, e)                                          \
            _generic_LC_swash_utf8_safe(isUPPER_LC, _CC_UPPER, p, e)
#define isUPPER_LC_uvchr(c)  _generic_LC_swash_uvchr(isUPPER_LC, _CC_UPPER, c)
#define isUPPER_uni(c)          isUPPER_uvchr(c)
#define isUPPER_utf8(p)         _generic_utf8(UPPER, p)
#define isUPPER_utf8_safe(p, e)  _generic_swash_utf8_safe(_CC_UPPER, p, e)
#define isUPPER_uvchr(c)      _generic_swash_uvchr(_CC_UPPER, c)
#define isVERTWS_uni(c)         isVERTWS_uvchr(c)
#define isVERTWS_utf8(p)        _generic_utf8(VERTSPACE, p)
#define isVERTWS_utf8_safe(p, e)                                            \
        _generic_non_swash_utf8_safe(_CC_VERTSPACE, is_VERTWS_high, p, e)
#define isVERTWS_uvchr(c)     _generic_uvchr(_CC_VERTSPACE, is_VERTWS_cp_high, c)
#define isWORDCHAR(c) isWORDCHAR_A(c)
#   define isWORDCHAR_A(c) _generic_isCC_A(c, _CC_WORDCHAR)
#   define isWORDCHAR_L1(c) _generic_isCC(c, _CC_WORDCHAR)
#  define isWORDCHAR_LC(c) (((c) == '_') || isALPHANUMERIC_LC(c))
#define isWORDCHAR_LC_utf8(p)      _generic_LC_utf8(WORDCHAR, p)
#define isWORDCHAR_LC_utf8_safe(p, e)                                       \
            _generic_LC_swash_utf8_safe(isWORDCHAR_LC, _CC_WORDCHAR, p, e)
#define isWORDCHAR_LC_uvchr(c) _generic_LC_swash_uvchr(isWORDCHAR_LC,         \
                                                           _CC_WORDCHAR, c)
#define isWORDCHAR_uni(c)       isWORDCHAR_uvchr(c)
#define isWORDCHAR_utf8(p)      _generic_utf8(WORDCHAR, p)
#define isWORDCHAR_utf8_safe(p, e)                                          \
                             _generic_swash_utf8_safe(_CC_WORDCHAR, p, e)
#define isWORDCHAR_uvchr(c)   _generic_swash_uvchr(_CC_WORDCHAR, c)
#define isXDIGIT(c)  isXDIGIT_A(c)
#   define isXDIGIT_A(c)  _generic_isCC(c, _CC_XDIGIT) 
#define isXDIGIT_L1(c)      isXDIGIT_A(c)
#  define isXDIGIT_LC(c) (_generic_LC(c, _CC_XDIGIT, isxdigit)                \
                                                    && isALPHANUMERIC_LC(c))
#define isXDIGIT_LC_utf8(p)        _generic_LC_utf8(XDIGIT, p)
#define isXDIGIT_LC_utf8_safe(p, e)                                         \
        _generic_LC_non_swash_utf8_safe(isXDIGIT_LC, is_XDIGIT_high, p, e)
#define isXDIGIT_LC_uvchr(c) _generic_LC_uvchr(isXDIGIT_LC,                  \
                                                       is_XDIGIT_cp_high, c)
#define isXDIGIT_uni(c)         isXDIGIT_uvchr(c)
#define isXDIGIT_utf8(p)        _generic_utf8(XDIGIT, p)
#define isXDIGIT_utf8_safe(p, e)                                            \
                   _generic_utf8_safe_no_upper_latin1(_CC_XDIGIT, p, e,     \
                             (UNLIKELY((e) - (p) < UTF8SKIP(p))             \
                              ? (_force_out_malformed_utf8_message(         \
                                      (U8 *) (p), (U8 *) (e), 0, 1), 0)     \
                              : is_XDIGIT_high(p)))
#define isXDIGIT_uvchr(c)     _generic_uvchr(_CC_XDIGIT, is_XDIGIT_cp_high, c)
#define is_LAX_VERSION(a,b) \
	(a != Perl_prescan_version(aTHX_ a, FALSE, b, NULL, NULL, NULL, NULL))
#define is_STRICT_VERSION(a,b) \
	(a != Perl_prescan_version(aTHX_ a, TRUE, b, NULL, NULL, NULL, NULL))
#define lex_stuff_pvs(pv,flags) Perl_lex_stuff_pvn(aTHX_ STR_WITH_LEN(pv), flags)
#define memBEGINPs(s1, l, s2)                                               \
            (   (Ptrdiff_t) (l) > (Ptrdiff_t) sizeof(s2) - 1                \
             && memEQ(s1, "" s2 "", sizeof(s2)-1))
#define memBEGINs(s1, l, s2)                                                \
            (   (Ptrdiff_t) (l) >= (Ptrdiff_t) sizeof(s2) - 1               \
             && memEQ(s1, "" s2 "", sizeof(s2)-1))
#define memENDPs(s1, l, s2)                                                 \
            (   (Ptrdiff_t) (l) > (Ptrdiff_t) sizeof(s2)                    \
             && memEQ(s1 + (l) - (sizeof(s2) - 1), "" s2 "", sizeof(s2)-1))
#define memENDs(s1, l, s2)                                                  \
            (   (Ptrdiff_t) (l) >= (Ptrdiff_t) sizeof(s2) - 1               \
             && memEQ(s1 + (l) - (sizeof(s2) - 1), "" s2 "", sizeof(s2)-1))
#define memEQ(s1,s2,l) (memcmp(((const void *) (s1)), ((const void *) (s2)), l) == 0)
#define memEQs(s1, l, s2) \
        (((sizeof(s2)-1) == (l)) && memEQ((s1), ("" s2 ""), (sizeof(s2)-1)))
#define memGE(s1,s2,l) (memcmp(s1,s2,l) >= 0)
#define memGT(s1,s2,l) (memcmp(s1,s2,l) > 0)
#define memLE(s1,s2,l) (memcmp(s1,s2,l) <= 0)
#define memLT(s1,s2,l) (memcmp(s1,s2,l) < 0)
#define memNE(s1,s2,l) (! memEQ(s1,s2,l))
#define memNEs(s1, l, s2) (! memEQs(s1, l, s2))
#define newSVpvs(str) Perl_newSVpvn(aTHX_ STR_WITH_LEN(str))
#define newSVpvs_flags(str,flags)	\
    Perl_newSVpvn_flags(aTHX_ STR_WITH_LEN(str), flags)
#define newSVpvs_share(str) Perl_newSVpvn_share(aTHX_ STR_WITH_LEN(str), 0)
#define pTHX_FORMAT  "Perl interpreter: 0x%p"
#define pTHX_VALUE    (void *)my_perl
#define pTHX_VALUE_   (void *)my_perl,
#define pTHX__FORMAT ", Perl interpreter: 0x%p"
#define pTHX__VALUE  ,(void *)my_perl
#define pTHX__VALUE_ ,(void *)my_perl,
#define perl_assert_ptr(p) assert( ((void*)(p)) != 0 )
#define savepvs(str) Perl_savepvn(aTHX_ STR_WITH_LEN(str))
#define savesharedpvs(str) Perl_savesharedpvn(aTHX_ STR_WITH_LEN(str))
#define strBEGINs(s1,s2) (strncmp(s1,"" s2 "", sizeof(s2)-1) == 0)
#define strEQ(s1,s2) (strcmp(s1,s2) == 0)
#define strGE(s1,s2) (strcmp(s1,s2) >= 0)
#define strGT(s1,s2) (strcmp(s1,s2) > 0)
#define strLE(s1,s2) (strcmp(s1,s2) <= 0)
#define strLT(s1,s2) (strcmp(s1,s2) < 0)
#define strNE(s1,s2) (strcmp(s1,s2) != 0)
#define strnEQ(s1,s2,l) (strncmp(s1,s2,l) == 0)
#define strnNE(s1,s2,l) (strncmp(s1,s2,l) != 0)
#define sv_catpvs(sv, str) \
    Perl_sv_catpvn_flags(aTHX_ sv, STR_WITH_LEN(str), SV_GMAGIC)
#define sv_catpvs_flags(sv, str, flags) \
    Perl_sv_catpvn_flags(aTHX_ sv, STR_WITH_LEN(str), flags)
#define sv_catpvs_mg(sv, str) \
    Perl_sv_catpvn_flags(aTHX_ sv, STR_WITH_LEN(str), SV_GMAGIC|SV_SMAGIC)
#define sv_catpvs_nomg(sv, str) \
    Perl_sv_catpvn_flags(aTHX_ sv, STR_WITH_LEN(str), 0)
#define sv_catxmlpvs(dsv, str, utf8) \
    Perl_sv_catxmlpvn(aTHX_ dsv, STR_WITH_LEN(str), utf8)
#    define sv_setgid(sv, gid)       sv_setnv((sv), (NV)(gid))
#define sv_setpvs(sv, str) Perl_sv_setpvn(aTHX_ sv, STR_WITH_LEN(str))
#define sv_setpvs_mg(sv, str) Perl_sv_setpvn_mg(aTHX_ sv, STR_WITH_LEN(str))
#define sv_setref_pvs(rv, classname, str) \
    Perl_sv_setref_pvn(aTHX_ rv, classname, STR_WITH_LEN(str))
#    define sv_setuid(sv, uid)       sv_setnv((sv), (NV)(uid))
#  define toCTRL(c)    (__ASSERT_(FITS_IN_8_BITS(c)) toUPPER(((U8)(c))) ^ 64)
#define toFOLD(c)    toLOWER(c)
#define toFOLD_A(c)  toFOLD(c)
#  define toFOLD_LC(c)  _generic_toFOLD_LC((c), tolower, U8)
#define toFOLD_uni(c,s,l)       toFOLD_uvchr(c,s,l)
#define toFOLD_utf8(p,s,l)	to_utf8_fold(p,s,l)
#define toFOLD_utf8_safe(p,e,s,l)   _toFOLD_utf8_flags(p,e,s,l, FOLD_FLAGS_FULL)
#define toFOLD_uvchr(c,s,l)	to_uni_fold(c,s,l)
#define toLOWER(c)  (isUPPER(c) ? (U8)((c) + ('a' - 'A')) : (c))
#define toLOWER_A(c) toLOWER(c)
#define toLOWER_L1(c)    toLOWER_LATIN1(c)  
#define toLOWER_LATIN1(c)    ((! FITS_IN_8_BITS(c))                        \
                             ? (c)                                         \
                             : PL_latin1_lc[ (U8) (c) ])
#  define toLOWER_LC(c) _generic_toLOWER_LC((c), tolower, U8)
#define toLOWER_uni(c,s,l)      toLOWER_uvchr(c,s,l)
#define toLOWER_utf8(p,s,l)	to_utf8_lower(p,s,l)
#define toLOWER_utf8_safe(p,e,s,l)  _toLOWER_utf8_flags(p,e,s,l, 0)
#define toLOWER_uvchr(c,s,l)	to_uni_lower(c,s,l)
#define toTITLE(c)   toUPPER(c)
#define toTITLE_A(c) toTITLE(c)
#define toTITLE_uni(c,s,l)      toTITLE_uvchr(c,s,l)
#define toTITLE_utf8(p,s,l)	to_utf8_title(p,s,l)
#define toTITLE_utf8_safe(p,e,s,l)  _toTITLE_utf8_flags(p,e,s,l, 0)
#define toTITLE_uvchr(c,s,l)	to_uni_title(c,s,l)
#define toUPPER(c)  (isLOWER(c) ? (U8)((c) - ('a' - 'A')) : (c))
#define toUPPER_A(c) toUPPER(c)
#define toUPPER_LATIN1_MOD(c) ((! FITS_IN_8_BITS(c))                       \
                               ? (c)                                       \
                               : PL_mod_latin1_uc[ (U8) (c) ])
#  define toUPPER_LC(c) _generic_toUPPER_LC((c), toupper, U8)
#define toUPPER_uni(c,s,l)      toUPPER_uvchr(c,s,l)
#define toUPPER_utf8(p,s,l)	to_utf8_upper(p,s,l)
#define toUPPER_utf8_safe(p,e,s,l)  _toUPPER_utf8_flags(p,e,s,l, 0)
#define toUPPER_uvchr(c,s,l)	to_uni_upper(c,s,l)
#      define EXT extern
#      define EXTCONST extern const

#      define dEXT 
#      define dEXTCONST const
