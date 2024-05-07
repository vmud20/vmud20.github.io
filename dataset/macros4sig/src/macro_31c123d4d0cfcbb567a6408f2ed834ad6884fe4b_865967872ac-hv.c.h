#include<sys/fcntl.h>
#include<sys/errno.h>




#include<sys/cdefs.h>




#define AMT_AMAGIC(amt)		((amt)->flags & AMTf_AMAGIC)
#define AMT_AMAGIC_off(amt)	((amt)->flags &= ~AMTf_AMAGIC)
#define AMT_AMAGIC_on(amt)	((amt)->flags |= AMTf_AMAGIC)
#define AMT_OVERLOADED(amt)	((amt)->flags & AMTf_OVERLOADED)
#define AMT_OVERLOADED_off(amt)	((amt)->flags &= ~AMTf_OVERLOADED)
#define AMT_OVERLOADED_on(amt)	((amt)->flags |= AMTf_OVERLOADED)

#   define Atoul(s)	Strtoul(s, NULL, 10)
#      define BSD_GETPGRP(pid)		getpgrp2((pid))
#      define BSD_SETPGRP(pid, pgrp)	setpgrp2((pid), (pgrp))
#       define BSDish
#   define BYTEORDER 0x1234
#define CALLREGCOMP(sv, flags) Perl_pregcomp(aTHX_ (sv),(flags))
#define CALLREGCOMP_ENG(prog, sv, flags) \
    CALL_FPTR(((prog)->comp))(aTHX_ sv, flags)
#define CALLREGDUPE(prog,param) \
    Perl_re_dup(aTHX_ (prog),(param))
#define CALLREGDUPE_PVT(prog,param) \
    (prog ? CALL_FPTR(RX_ENGINE(prog)->dupe)(aTHX_ (prog),(param)) \
          : (REGEXP *)NULL)
#define CALLREGEXEC(prog,stringarg,strend,strbeg,minend,screamer,data,flags) \
    CALL_FPTR(RX_ENGINE(prog)->exec)(aTHX_ (prog),(stringarg),(strend), \
        (strbeg),(minend),(screamer),(data),(flags))
#define CALLREGFREE(prog) \
    Perl_pregfree(aTHX_ (prog))
#define CALLREGFREE_PVT(prog) \
    if(prog) CALL_FPTR(RX_ENGINE(prog)->free)(aTHX_ (prog))
#define CALLREG_INTUIT_START(prog,sv,strpos,strend,flags,data) \
    CALL_FPTR(RX_ENGINE(prog)->intuit)(aTHX_ (prog), (sv), (strpos), \
        (strend),(flags),(data))
#define CALLREG_INTUIT_STRING(prog) \
    CALL_FPTR(RX_ENGINE(prog)->checkstr)(aTHX_ (prog))
#define CALLREG_NAMED_BUFF_ALL(rx, flags) \
    CALL_FPTR(RX_ENGINE(rx)->named_buff)(aTHX_ (rx), NULL, NULL, flags)
#define CALLREG_NAMED_BUFF_CLEAR(rx, flags) \
    CALL_FPTR(RX_ENGINE(rx)->named_buff)(aTHX_ (rx), NULL, NULL, ((flags) | RXapif_CLEAR))
#define CALLREG_NAMED_BUFF_COUNT(rx) \
    CALL_FPTR(RX_ENGINE(rx)->named_buff)(aTHX_ (rx), NULL, NULL, RXapif_REGNAMES_COUNT)
#define CALLREG_NAMED_BUFF_DELETE(rx, key, flags) \
    CALL_FPTR(RX_ENGINE(rx)->named_buff)(aTHX_ (rx),(key), NULL, ((flags) | RXapif_DELETE))
#define CALLREG_NAMED_BUFF_EXISTS(rx, key, flags) \
    CALL_FPTR(RX_ENGINE(rx)->named_buff)(aTHX_ (rx), (key), NULL, ((flags) | RXapif_EXISTS))
#define CALLREG_NAMED_BUFF_FETCH(rx, key, flags) \
    CALL_FPTR(RX_ENGINE(rx)->named_buff)(aTHX_ (rx), (key), NULL, ((flags) | RXapif_FETCH))
#define CALLREG_NAMED_BUFF_FIRSTKEY(rx, flags) \
    CALL_FPTR(RX_ENGINE(rx)->named_buff_iter)(aTHX_ (rx), NULL, ((flags) | RXapif_FIRSTKEY))
#define CALLREG_NAMED_BUFF_NEXTKEY(rx, lastkey, flags) \
    CALL_FPTR(RX_ENGINE(rx)->named_buff_iter)(aTHX_ (rx), (lastkey), ((flags) | RXapif_NEXTKEY))
#define CALLREG_NAMED_BUFF_SCALAR(rx, flags) \
    CALL_FPTR(RX_ENGINE(rx)->named_buff)(aTHX_ (rx), NULL, NULL, ((flags) | RXapif_SCALAR))
#define CALLREG_NAMED_BUFF_STORE(rx, key, value, flags) \
    CALL_FPTR(RX_ENGINE(rx)->named_buff)(aTHX_ (rx), (key), (value), ((flags) | RXapif_STORE))
#define CALLREG_NUMBUF_FETCH(rx,paren,usesv)                                \
    CALL_FPTR(RX_ENGINE(rx)->numbered_buff_FETCH)(aTHX_ (rx),(paren),(usesv))
#define CALLREG_NUMBUF_LENGTH(rx,sv,paren)                              \
    CALL_FPTR(RX_ENGINE(rx)->numbered_buff_LENGTH)(aTHX_ (rx),(sv),(paren))
#define CALLREG_NUMBUF_STORE(rx,paren,value) \
    CALL_FPTR(RX_ENGINE(rx)->numbered_buff_STORE)(aTHX_ (rx),(paren),(value))
#define CALLREG_PACKAGE(rx) \
    CALL_FPTR(RX_ENGINE(rx)->qr_package)(aTHX_ (rx))
#define CALLRUNOPS  CALL_FPTR(PL_runops)
#define CALL_FPTR(fptr) (*fptr)
#  define CHECK_MALLOC_TAINT(newval)				\
	CHECK_MALLOC_TOO_LATE_FOR_(				\
		if (newval) {					\
		  panic_write2("panic: tainting with $ENV{PERL_MALLOC_OPT}\n");\
		  exit(1); })
#  define CHECK_MALLOC_TOO_LATE_FOR(ch)				\
	CHECK_MALLOC_TOO_LATE_FOR_(MALLOC_TOO_LATE_FOR(ch))
#  define CHECK_MALLOC_TOO_LATE_FOR_(code)	STMT_START {		\
	if (!PL_tainting && MallocCfg_ptr[MallocCfg_cfg_env_read])	\
		code;							\
    } STMT_END
#define CLEAR_ERRSV() STMT_START {					\
    if (!GvSV(PL_errgv)) {						\
	sv_setpvs(GvSV(gv_add_by_type(PL_errgv, SVt_PV)), "");		\
    } else if (SvREADONLY(GvSV(PL_errgv))) {				\
	SvREFCNT_dec(GvSV(PL_errgv));					\
	GvSV(PL_errgv) = newSVpvs("");					\
    } else {								\
	SV *const errsv = GvSV(PL_errgv);				\
	sv_setpvs(errsv, "");						\
	if (SvMAGICAL(errsv)) {						\
	    mg_free(errsv);						\
	}								\
	SvPOK_only(errsv);						\
    }									\
    } STMT_END
#define CLUMP_2IV(uv)	((uv) > (UV)IV_MAX ? IV_MAX : (IV)(uv))
#define CLUMP_2UV(iv)	((iv) < 0 ? 0 : (UV)(iv))
#define CPERLarg void

#define CPERLscope(x) x
#  define C_FAC_POSIX 0x35A000
# define DBL_DIG OVR_DBL_DIG
#      define DBL_MAX MAXDOUBLE
#      define DBL_MIN MINDOUBLE
#  define DEBUG_A(a) DEBUG__(DEBUG_A_TEST, a)
#  define DEBUG_A_TEST DEBUG_A_TEST_
#  define DEBUG_A_TEST_ (PL_debug & DEBUG_A_FLAG)
#  define DEBUG_B(a) DEBUG__(DEBUG_B_TEST, a)
#  define DEBUG_B_TEST DEBUG_B_TEST_
#  define DEBUG_B_TEST_ (PL_debug & DEBUG_B_FLAG)
#  define DEBUG_C(a) DEBUG__(DEBUG_C_TEST, a)
#  define DEBUG_C_TEST DEBUG_C_TEST_
#  define DEBUG_C_TEST_ (PL_debug & DEBUG_C_FLAG)
#  define DEBUG_D(a) DEBUG__(DEBUG_D_TEST, a)
#  define DEBUG_D_TEST DEBUG_D_TEST_
#  define DEBUG_D_TEST_ (PL_debug & DEBUG_D_FLAG)
#  define DEBUG_H(a) DEBUG__(DEBUG_H_TEST, a)
#  define DEBUG_H_TEST DEBUG_H_TEST_
#  define DEBUG_H_TEST_ (PL_debug & DEBUG_H_FLAG)
#  define DEBUG_J_TEST DEBUG_J_TEST_
#  define DEBUG_J_TEST_ (PL_debug & DEBUG_J_FLAG)
#  define DEBUG_M(a) DEBUG__(DEBUG_M_TEST, a)
#  define DEBUG_M_TEST DEBUG_M_TEST_
#  define DEBUG_M_TEST_ (PL_debug & DEBUG_M_FLAG)
#  define DEBUG_P(a) if (DEBUG_P_TEST) a
#  define DEBUG_P_TEST DEBUG_P_TEST_
#  define DEBUG_P_TEST_ (PL_debug & DEBUG_P_FLAG)
#  define DEBUG_R(a) DEBUG__(DEBUG_R_TEST, a)
#  define DEBUG_R_TEST DEBUG_R_TEST_
#  define DEBUG_R_TEST_ (PL_debug & DEBUG_R_FLAG)
#define DEBUG_SCOPE(where) \
    DEBUG_l(WITH_THR(Perl_deb(aTHX_ "%s scope %ld at %s:%d\n",	\
		    where, (long)PL_scopestack_ix, "__FILE__", "__LINE__")));
#  define DEBUG_T(a) DEBUG__(DEBUG_T_TEST, a)
#  define DEBUG_T_TEST DEBUG_T_TEST_
#  define DEBUG_T_TEST_ (PL_debug & DEBUG_T_FLAG)
#  define DEBUG_U(a) DEBUG__(DEBUG_U_TEST, a)
#  define DEBUG_U_TEST DEBUG_U_TEST_
#  define DEBUG_U_TEST_ (PL_debug & DEBUG_U_FLAG)
#  define DEBUG_Uv(a) DEBUG__(DEBUG_Uv_TEST, a)
#  define DEBUG_Uv_TEST DEBUG_Uv_TEST_
#  define DEBUG_Uv_TEST_ (DEBUG_U_TEST_ && DEBUG_v_TEST_)
#  define DEBUG_X(a) DEBUG__(DEBUG_X_TEST, a)
#  define DEBUG_X_TEST DEBUG_X_TEST_
#  define DEBUG_X_TEST_ (PL_debug & DEBUG_X_FLAG)
#  define DEBUG_Xv(a) DEBUG__(DEBUG_Xv_TEST, a)
#  define DEBUG_Xv_TEST DEBUG_Xv_TEST_
#  define DEBUG_Xv_TEST_ (DEBUG_X_TEST_ && DEBUG_v_TEST_)
#  define DEBUG__(t, a) \
	STMT_START { \
		if (t) STMT_START {a;} STMT_END; \
	} STMT_END
#  define DEBUG_c(a) if (DEBUG_c_TEST) a
#  define DEBUG_c_TEST DEBUG_c_TEST_
#  define DEBUG_c_TEST_ (PL_debug & DEBUG_c_FLAG)
#  define DEBUG_f(a) DEBUG__(DEBUG_f_TEST, a)
#  define DEBUG_f_TEST DEBUG_f_TEST_
#  define DEBUG_f_TEST_ (PL_debug & DEBUG_f_FLAG)
#  define DEBUG_l(a) if (DEBUG_l_TEST) a
#  define DEBUG_l_TEST DEBUG_l_TEST_
#  define DEBUG_l_TEST_ (PL_debug & DEBUG_l_FLAG)
#  define DEBUG_m(a)  \
    STMT_START {							\
        if (PERL_GET_INTERP) { dTHX; if (DEBUG_m_TEST) {PL_debug&=~DEBUG_m_FLAG; a; PL_debug|=DEBUG_m_FLAG;} } \
    } STMT_END
#  define DEBUG_m_TEST DEBUG_m_TEST_
#  define DEBUG_m_TEST_ (PL_debug & DEBUG_m_FLAG)
#  define DEBUG_o(a) if (DEBUG_o_TEST) a
#  define DEBUG_o_TEST DEBUG_o_TEST_
#  define DEBUG_o_TEST_ (PL_debug & DEBUG_o_FLAG)
#  define DEBUG_p(a) if (DEBUG_p_TEST) a
#  define DEBUG_p_TEST DEBUG_p_TEST_
#  define DEBUG_p_TEST_ (PL_debug & DEBUG_p_FLAG)
#  define DEBUG_q(a) DEBUG__(DEBUG_q_TEST, a)
#  define DEBUG_q_TEST DEBUG_q_TEST_
#  define DEBUG_q_TEST_ (PL_debug & DEBUG_q_FLAG)
#  define DEBUG_r(a) DEBUG__(DEBUG_r_TEST, a)
#  define DEBUG_r_TEST DEBUG_r_TEST_
#  define DEBUG_r_TEST_ (PL_debug & DEBUG_r_FLAG)
#  define DEBUG_s(a) if (DEBUG_s_TEST) a
#  define DEBUG_s_TEST DEBUG_s_TEST_
#  define DEBUG_s_TEST_ (PL_debug & DEBUG_s_FLAG)
#  define DEBUG_t(a) if (DEBUG_t_TEST) a
#  define DEBUG_t_TEST DEBUG_t_TEST_
#  define DEBUG_t_TEST_ (PL_debug & DEBUG_t_FLAG)
#  define DEBUG_u(a) DEBUG__(DEBUG_u_TEST, a)
#  define DEBUG_u_TEST DEBUG_u_TEST_
#  define DEBUG_u_TEST_ (PL_debug & DEBUG_u_FLAG)
#  define DEBUG_v(a) DEBUG__(DEBUG_v_TEST, a)
#  define DEBUG_v_TEST DEBUG_v_TEST_
#  define DEBUG_v_TEST_ (PL_debug & DEBUG_v_FLAG)
#  define DEBUG_x(a) DEBUG__(DEBUG_x_TEST, a)
#  define DEBUG_x_TEST DEBUG_x_TEST_
#  define DEBUG_x_TEST_ (PL_debug & DEBUG_x_FLAG)
# define DEFSV (0 + GvSVn(PL_defgv))
#define DEFSV_set(sv) (GvSV(PL_defgv) = (sv))
#      define DIR void
# define DONT_DECLARE_STD 1
#define DOSISH 1
#define DPTR2FPTR(t,p) ((t)PTR2nat(p))	
#  define END_EXTERN_C }
#define ERRHV GvHV(PL_errgv)	
#define ERRSV GvSVn(PL_errgv)
#define EXEC_ARGV_CAST(x) (char **)x
#  define EXPECT(expr,val)                  __builtin_expect(expr,val)
#  define EXTERN_C extern "C"
#  define EXT_MGVTBL EXTCONST MGVTBL

#  define  FAKE_DEFAULT_SIGNAL_HANDLERS
#  define  FAKE_PERSISTENT_SIGNAL_HANDLERS
#define FILTER_DATA(idx) \
	    (PL_parser ? AvARRAY(PL_parser->rsfp_filters)[idx] : NULL)
#define FILTER_ISREADER(idx) \
	    (PL_parser && PL_parser->rsfp_filters \
		&& idx >= AvFILLp(PL_parser->rsfp_filters))
#define FILTER_READ(idx, sv, len)  filter_read(idx, sv, len)
#define FPTR2DPTR(t,p) ((t)PTR2nat(p))	
#       define FSEEKSIZE LSEEKSIZE
#       define F_atan2_amg  atan2_amg
#       define F_cos_amg    cos_amg
#       define F_exp_amg    exp_amg
#       define F_log_amg    log_amg
#       define F_pow_amg    pow_amg
#       define F_sin_amg    sin_amg
#       define F_sqrt_amg   sqrt_amg
#       define Fpos_t fpos64_t
#define GROK_NUMERIC_RADIX(sp, send) grok_numeric_radix(sp, send)
#    define HASATTRIBUTE_DEPRECATED
#    define HASATTRIBUTE_FORMAT
#    define HASATTRIBUTE_MALLOC
#    define HASATTRIBUTE_NONNULL
#    define HASATTRIBUTE_NORETURN
#    define HASATTRIBUTE_PURE
#    define HASATTRIBUTE_UNUSED 
#    define HASATTRIBUTE_WARN_UNUSED_RESULT
#  define HAS_GETPGRP  


# define HAS_HTOVL
# define HAS_HTOVS


#      define HAS_QUAD
#  define HAS_SETPGRP  
#    define HAS_SETREGID
#    define HAS_SETREUID
# define HAS_VTOHL
# define HAS_VTOHS
#define H_PERL 1
#   define I286
#define I32_MAX_P1 (2.0 * (1 + (((U32)I32_MAX) >> 1)))
#       define INCLUDE_PROTOTYPES 
#  define INIT_TRACK_MEMPOOL(header, interp)			\
	STMT_START {						\
		(header).interpreter = (interp);		\
		(header).prev = (header).next = &(header);	\
	} STMT_END
#  define INT2PTR(any,d)	(any)(d)
#define IN_LOCALE \
	(IN_PERL_COMPILETIME ? IN_LOCALE_COMPILETIME : IN_LOCALE_RUNTIME)
#	    define IOCPARM_LEN(x) (_IOC_SIZE(x) < 256 ? 256 : _IOC_SIZE(x))
#   define ISHISH "vmesa"
#define IS_NUMBER_GREATER_THAN_UV_MAX 0x02 
#define IS_NUMBER_NAN                 0x20 
#define IS_NUMERIC_RADIX(a, b)		(0)
#define IV_DIG (BIT_DIGITS(IVSIZE * 8))
#    define IV_IS_QUAD
#    define IV_MAX INT64_MAX
#define IV_MAX_P1 (2.0 * (1 + (((UV)IV_MAX) >> 1)))
#    define IV_MIN INT64_MIN
#define I_32(what) (cast_i32((NV)(what)))
#    define I_STDARG 1
#define I_V(what) (cast_iv((NV)(what)))
#define KEYWORD_PLUGIN_DECLINE 0
#define KEYWORD_PLUGIN_EXPR    2
#define KEYWORD_PLUGIN_STMT    1
#      define LDBL_DIG DBL_DIG 
#   define LIBERAL 1
#   define LIB_INVARG 		LIB$_INVARG
#define LIKELY(cond)                        EXPECT(cond,1)
#      define LONG_DOUBLE_EQUALS_DOUBLE
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
#  define MEMBER_TO_FPTR(name)		name
#define MEM_SIZE Size_t
#  define MGVTBL_SET(var,a,b,c,d,e,f,g,h) EXT_MGVTBL var = {a,b,c,d,e,f,g,h}
#  define MGVTBL_SET_CONST_MAGIC_GET(var,a,b,c,d,e,f,g,h) EXT_MGVTBL var \
    = {(int (*)(pTHX_ SV *, MAGIC *))a,b,c,d,e,f,g,h}
#    define MULTIPLICITY
#            define MUTEX_INIT_CALLS_MALLOC
#  define MYSWAP
#define MY_CXT_CLONE \
	my_cxt_t *my_cxtp = (my_cxt_t*)SvPVX(newSV(sizeof(my_cxt_t)-1));\
	Copy(PL_my_cxt_list[MY_CXT_INDEX], my_cxtp, 1, my_cxt_t);\
	PL_my_cxt_list[MY_CXT_INDEX] = my_cxtp				\

#define MY_CXT_INDEX Perl_my_cxt_index(aTHX_ MY_CXT_KEY)
#define MY_CXT_INIT \
	my_cxt_t *my_cxtp = \
	    (my_cxt_t*)Perl_my_cxt_init(aTHX_ MY_CXT_KEY, sizeof(my_cxt_t))
#define MY_CXT_INIT_INTERP(my_perl) \
	my_cxt_t *my_cxtp = \
	    (my_cxt_t*)Perl_my_cxt_init(my_perl, MY_CXT_KEY, sizeof(my_cxt_t))
#define NOOP (void)0
#  define NORETURN_FUNCTION_END 

#   define NO_LOCALE
#    define NSIG (_NSIG)
#define NUM2PTR(any,d)	(any)(PTRV)(d)
#   define NV_DIG LDBL_DIG
#       define NV_EPSILON LDBL_EPSILON
#  define NV_INF LDBL_INFINITY
#       define NV_MANT_DIG LDBL_MANT_DIG
#               define NV_MAX ((NV)HUGE_VAL)
#       define NV_MAX_10_EXP LDBL_MAX_10_EXP
#       define NV_MIN LDBL_MIN
#       define NV_MIN_10_EXP LDBL_MIN_10_EXP
#       define NV_NAN LDBL_NAN
#define NV_WITHIN_IV(nv) (I_V(nv) >= IV_MIN && I_V(nv) <= IV_MAX)
#define NV_WITHIN_UV(nv) ((nv)>=0.0 && U_V(nv) >= UV_MIN && U_V(nv) <= UV_MAX)
#  define O_BINARY 0
#  define O_TEXT 0
#       define Off_t off64_t
#define PERLDB_SAVESRC 	(PL_perldb && (PL_perldb & PERLDBf_SAVESRC))
#define PERLDBf_SAVESRC  	0x400	
#        define PERLIO_FUNCS_CONST 
#  define PERLIO_INIT MUTEX_INIT(&PL_perlio_mutex)
#  define PERLIO_TERM 				\
	STMT_START {				\
		PerlIO_teardown();		\
		MUTEX_DESTROY(&PL_perlio_mutex);\
	} STMT_END
#      define PERLIO_USING_CRLF 1
#define PERLVAR(var,type) type var;
#define PERLVARA(var,n,type) type var[n];
#define PERLVARI(var,type,init) type var;
#define PERLVARIC(var,type,init) type var;
#define PERLVARISC(var,init) const char var[sizeof(init)];
#define PERL_ABS(x) ((x) < 0 ? -(x) : (x))
#define PERL_ALLOC_CHECK(p)  NOOP
#define PERL_ARENA_SIZE 4080
#		define PERL_ASYNC_CHECK() if (PL_sig_pending) despatch_signals()
#  define PERL_BITFIELD16 unsigned
#  define PERL_BITFIELD32 unsigned
#  define PERL_BITFIELD8 unsigned
#   define PERL_BLOCKSIG_ADD(set,sig) \
	sigset_t set; sigemptyset(&(set)); sigaddset(&(set), sig)
#   define PERL_BLOCKSIG_BLOCK(set) \
	sigprocmask(SIG_BLOCK, &(set), NULL)
#   define PERL_BLOCKSIG_UNBLOCK(set) \
	sigprocmask(SIG_UNBLOCK, &(set), NULL)

#    define PERL_CALLCONV extern "C"
#define PERL_CKDEF(s)	PERL_CALLCONV OP *s (pTHX_ OP *o);
#  define PERL_DEB(a)                  a
#  define PERL_DEBUG(a) if (PL_debug)  a
#define PERL_DEBUG_PAD(i)	&(PL_debug_pad.pad[i])
#define PERL_DEBUG_PAD_ZERO(i)	(SvPVX(PERL_DEBUG_PAD(i))[0] = 0, \
	(((XPV*) SvANY(PERL_DEBUG_PAD(i)))->xpv_cur = 0), \
	PERL_DEBUG_PAD(i))

#    define PERL_DONT_CREATE_GVSV
#define PERL_EXIT_DESTRUCT_END  0x02  
#    define PERL_EXPORT_C extern "C"
#define PERL_FILTER_EXISTS(i) \
	    (PL_parser && PL_parser->rsfp_filters \
		&& (i) <= av_len(PL_parser->rsfp_filters))
#      define PERL_FPU_INIT       PL_sigfpe_saved = (Sighandler_t) signal(SIGFPE, SIG_IGN)
#      define PERL_FPU_POST_EXEC    rsignal_restore(SIGFPE, &xfpe); }
#      define PERL_FPU_PRE_EXEC   { Sigsave_t xfpe; rsignal_save(SIGFPE, PL_sigfpe_saved, &xfpe);
#    define PERL_GCC_BRACE_GROUPS_FORBIDDEN
#      define PERL_GET_VARS() Perl_GetVarsPrivate() 
#    define PERL_GLOBAL_STRUCT
#define PERL_GPROF_MONCONTROL(x) moncontrol(x)
#    define PERL_IMPLICIT_CONTEXT
#    define PERL_INT_MAX ((int)MAXINT)
#    define PERL_INT_MIN ((int)MININT)
#    define PERL_LONG_MAX ((long)MAXLONG)
#    define PERL_LONG_MIN ((long)MINLONG)
#define PERL_MAGIC_overload_elem  'a' 
#define PERL_MAGIC_overload_table 'c' 
#define PERL_MAGIC_shared_scalar  'n' 
#define PERL_MG_UFUNC(name,ix,sv) I32 name(pTHX_ IV ix, SV *sv)
#      define PERL_MY_SNPRINTF_GUARDED
#      define PERL_MY_VSNPRINTF_GUARDED
#  define PERL_NEED_MY_BETOH16
#  define PERL_NEED_MY_BETOH32
#   define PERL_NEED_MY_BETOH64
#   define PERL_NEED_MY_BETOHI
#   define PERL_NEED_MY_BETOHL
#   define PERL_NEED_MY_BETOHS
#  define PERL_NEED_MY_HTOBE16
#  define PERL_NEED_MY_HTOBE32
#   define PERL_NEED_MY_HTOBE64
#   define PERL_NEED_MY_HTOBEI
#   define PERL_NEED_MY_HTOBEL
#   define PERL_NEED_MY_HTOBES
#  define PERL_NEED_MY_HTOLE16
#  define PERL_NEED_MY_HTOLE32
#   define PERL_NEED_MY_HTOLE64
#   define PERL_NEED_MY_HTOLEI
#   define PERL_NEED_MY_HTOLEL
#   define PERL_NEED_MY_HTOLES
#  define PERL_NEED_MY_LETOH16
#  define PERL_NEED_MY_LETOH32
#   define PERL_NEED_MY_LETOH64
#   define PERL_NEED_MY_LETOHI
#   define PERL_NEED_MY_LETOHL
#   define PERL_NEED_MY_LETOHS



#define PERL_PPDEF(s)	PERL_CALLCONV OP *s (pTHX);
#define PERL_PV_ESCAPE_FIRSTCHAR    0x0008
#define PERL_PV_ESCAPE_NOBACKSLASH  0x2000
#define PERL_PV_ESCAPE_NOCLEAR      0x4000
#define PERL_PV_ESCAPE_QUOTE        0x0001
#define PERL_PV_ESCAPE_RE           0x8000
#define PERL_PV_ESCAPE_UNI          0x0100
#define PERL_PV_ESCAPE_UNI_DETECT   0x0200
#define PERL_PV_PRETTY_DUMP  PERL_PV_PRETTY_ELLIPSES|PERL_PV_PRETTY_QUOTE
#define PERL_PV_PRETTY_ELLIPSES     0x0002
#define PERL_PV_PRETTY_LTGT         0x0004
#define PERL_PV_PRETTY_NOCLEAR      PERL_PV_ESCAPE_NOCLEAR
#define PERL_PV_PRETTY_QUOTE        PERL_PV_ESCAPE_QUOTE
#define PERL_PV_PRETTY_REGPROP PERL_PV_PRETTY_ELLIPSES|PERL_PV_PRETTY_LTGT|PERL_PV_ESCAPE_RE
#    define PERL_QUAD_MAX 	((IV) (PERL_UQUAD_MAX >> 1))
#    define PERL_QUAD_MIN 	(-PERL_QUAD_MAX - ((3 & -1) == 3))
#define PERL_SCAN_ALLOW_UNDERSCORES   0x01 
#define PERL_SCAN_DISALLOW_PREFIX     0x02 
#define PERL_SCAN_GREATER_THAN_UV_MAX 0x02 
#define PERL_SCAN_SILENT_ILLDIGIT     0x04 
#define PERL_SCRIPT_MODE "r"
#  define PERL_SET_CONTEXT(i)		PERL_SET_INTERP(i)
#  define PERL_SET_INTERP(i)		(PL_curinterp = (PerlInterpreter*)(i))
#  define PERL_SET_THX(t)		PERL_SET_CONTEXT(t)
#      define PERL_SHORT_MAX ((short)SHRT_MAX)
#      define PERL_SHORT_MIN ((short)SHRT_MIN)
#       define PERL_SOCKS_NEED_PROTOTYPES
#define PERL_STACK_OVERFLOW_CHECK()  NOOP
#define PERL_STRLEN_ROUNDUP_QUANTUM Size_t_size
#define PERL_SUB_DEPTH_WARN 100
#define PERL_SYS_INIT(argc, argv)	Perl_sys_init(argc, argv)
#define PERL_SYS_INIT3(argc, argv, env)	Perl_sys_init3(argc, argv, env)
#  define PERL_SYS_INIT3_BODY(argvp,argcp,envp) PERL_SYS_INIT_BODY(argvp,argcp)
#define PERL_SYS_TERM()			Perl_sys_term()
#    define PERL_TRACK_MEMPOOL
#    define PERL_UCHAR_MAX ((unsigned char)MAXUCHAR)
#define PERL_UCHAR_MIN ((unsigned char)0)
#    define PERL_UINT_MAX ((unsigned int)MAXUINT)
#define PERL_UINT_MIN ((unsigned int)0)
#    define PERL_ULONG_MAX ((unsigned long)MAXULONG)
#define PERL_ULONG_MIN ((unsigned long)0L)
#    define PERL_UNUSED_ARG(x) NOTE(ARGUNUSED(x))
#  define PERL_UNUSED_CONTEXT PERL_UNUSED_ARG(my_perl)
#    define PERL_UNUSED_DECL __attribute__((unused))
#  define PERL_UNUSED_VAR(x) ((void)x)

#    define PERL_USE_GCC_BRACE_GROUPS
#      define PERL_USHORT_MAX ((unsigned short)USHRT_MAX)
#define PERL_USHORT_MIN ((unsigned short)0)
#  define PERL_WRITE_MSG_TO_CONSOLE(io, msg, len) PerlIO_write(io, msg, len)
#    define PERL_XS_EXPORT_C extern "C"
#  define PIPESOCK_MODE
#    define PL_OP_SLAB_ALLOC
#    define PL_Vars (*((PL_VarsPtr) \
		       ? PL_VarsPtr : (PL_VarsPtr = Perl_GetVars(aTHX))))
#  define PL_madskills 0
#  define PL_xmlfp 0
#      define PRINTF_FORMAT_NULL_OK
#define PTR2IV(p)	INT2PTR(IV,p)
#define PTR2NV(p)	NUM2PTR(NV,p)
#define PTR2UV(p)	INT2PTR(UV,p)
#define PTR2nat(p)	(PTRV)(p)	
#    define PTR2ul(p)		(unsigned long)(p)
#define Pause() sleep((32767<<16)+32767)
#define Perl_assert(what)	PERL_DEB( 				\
	((what) ? ((void) 0) :						\
	    (Perl_croak_nocontext("Assertion %s failed: file \"" "__FILE__" \
			"\", line %d", STRINGIFY(what), "__LINE__"),	\
	    (void) 0)))
#       define Perl_atan2 atan2l
#   define Perl_atof(s) Perl_my_atof(s)
#   define Perl_atof2(s, n) Perl_my_atof2(aTHX_ (s), &(n))
#       define Perl_ceil ceill
#       define Perl_cos cosl
#       define Perl_exp expl
#       define Perl_floor floorl
#       define Perl_fmod fmodl
#        define Perl_fp_class()		fpclassl(x)
#    define Perl_fp_class_denorm(x)	(Perl_fp_class(x)==FP_CLASS_NDENORM||Perl_fp_class(x)==FP_CLASS_PDENORM)
#    define Perl_fp_class_inf(x)	(Perl_fp_class(x)==FP_CLASS_NINF||Perl_fp_class(x)==FP_CLASS_PINF)
#    define Perl_fp_class_nan(x)	(Perl_fp_class(x)==FP_CLASS_SNAN||Perl_fp_class(x)==FP_CLASS_QNAN)
#    define Perl_fp_class_ndenorm(x)	(Perl_fp_class(x)==FP_CLASS_NDENORM)
#    define Perl_fp_class_ninf(x)	(Perl_fp_class(x)==FP_CLASS_NINF)
#    define Perl_fp_class_nnorm(x)	(Perl_fp_class(x)==FP_CLASS_NNORM)
#    define Perl_fp_class_norm(x)	(Perl_fp_class(x)==FP_CLASS_NNORM||Perl_fp_class(x)==FP_CLASS_PNORM)
#    define Perl_fp_class_nzero(x)	(Perl_fp_class(x)==FP_CLASS_NZERO)
#    define Perl_fp_class_pdenorm(x)	(Perl_fp_class(x)==FP_CLASS_PDENORM)
#    define Perl_fp_class_pinf(x)	(Perl_fp_class(x)==FP_CLASS_PINF)
#    define Perl_fp_class_pnorm(x)	(Perl_fp_class(x)==FP_CLASS_PNORM)
#    define Perl_fp_class_pzero(x)	(Perl_fp_class(x)==FP_CLASS_PZERO)
#    define Perl_fp_class_qnan(x)	(Perl_fp_class(x)==FP_CLASS_QNAN)
#    define Perl_fp_class_snan(x)	(Perl_fp_class(x)==FP_CLASS_SNAN)
#    define Perl_fp_class_zero(x)	(Perl_fp_class(x)==FP_CLASS_NZERO||Perl_fp_class(x)==FP_CLASS_PZERO)
#           define Perl_frexp(x,y) Perl_my_frexpl(x,y)
#               define Perl_isfinite(x) Perl_fp_class_finite(x)
#           define Perl_isinf(x) !(finitel(x)||Perl_isnan(x))
#               define Perl_isnan(x) unordered((x), 0.0)
#       define Perl_log logl
#           define Perl_modf(x,y) Perl_my_modfl(x,y)
#       define Perl_pow powl
#  define Perl_safesysmalloc_size(where)	Perl_malloced_size(where)
#  define Perl_signbit signbit
#       define Perl_sin sinl
#       define Perl_sqrt sqrtl
#   define RESTORE_ERRNO  SETERRNO(saved_errno, saved_vms_errno)
#define RESTORE_NUMERIC_LOCAL() \
	if (was_local) SET_NUMERIC_LOCAL();
#define RESTORE_NUMERIC_STANDARD() \
	if (was_standard) SET_NUMERIC_STANDARD();
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
#define SAVE_DEFSV SAVESPTR(GvSV(PL_defgv))
#   define SAVE_ERRNO     ( saved_errno = errno, saved_vms_errno = vaxc$errno )
#define SCAN_DEF 0
#define SCAN_REPL 2
#define SCAN_TR 1
#   define SETERRNO(errcode,vmserrcode) \
	STMT_START {			\
	    set_errno(errcode);		\
	    set_vaxc_errno(vmserrcode);	\
	} STMT_END
#define SET_NUMERIC_LOCAL() \
	set_numeric_local();
#define SET_NUMERIC_STANDARD() \
	set_numeric_standard();
#   define SLOPPYDIVIDE
#   define SS_ACCVIO      	SS$_ACCVIO
#   define SS_IVCHAN  		SS$_IVCHAN
#   define SS_NORMAL  		SS$_NORMAL
# define STANDARD_C 1
#  define START_EXTERN_C extern "C" {
#define START_MY_CXT static int my_cxt_index = -1;
#define STATIC static
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
#define STORE_NUMERIC_LOCAL_SET_STANDARD() \
	bool was_local = PL_numeric_local && IN_LOCALE; \
	if (was_local) SET_NUMERIC_STANDARD();
#define STORE_NUMERIC_STANDARD_SET_LOCAL() \
	bool was_standard = PL_numeric_standard && IN_LOCALE; \
	if (was_standard) SET_NUMERIC_LOCAL();
#   define STRUCT_OFFSET(s,m)  offsetof(s,m)
#   define STRUCT_SV perl_sv
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
#		define S_ISLNK(m) ((m & S_IFMT) == S_IFLNK)
#   define S_ISREG(m) ((m & S_IFMT) == S_IFREG)
#		define S_ISSOCK(m) ((m & S_IFMT) == S_IFSOCK)
#   define S_ISUID 04000
#       define S_IWGRP (S_IWUSR>>3)
#       define S_IWOTH (S_IWUSR>>6)
#   define S_IWRITE S_IWUSR
#       define S_IXGRP (S_IXUSR>>3)
#       define S_IXOTH (S_IXUSR>>6)
#               define Semctl(id, num, cmd, semun) semctl(id, num, cmd, semun.buff)
#define StashHANDLER(stash,meth)	gv_handler((stash),CAT2(meth,_amg))
#           define Strerror strerror
#   define Strtoul(s, e, b)	strchr((s), '-') ? ULONG_MAX : (unsigned long)strtol((s), (e), (b))
#define TAINT_ENV()	if (PL_tainting) { taint_env(); }
#define TAINT_IF(c)	if (c) { PL_tainted = TRUE; }
#define TAINT_PROPER(s)	if (PL_tainting) { taint_proper(NULL, s); }
#define THREADSV_NAMES "_123456789&`'+/.,\\\";^-%=|~:\001\005!@"
#define TOO_LATE_FOR(ch)	TOO_LATE_FOR_(ch, "")
#define TOO_LATE_FOR_(ch,what)	Perl_croak(aTHX_ "\"-%c\" is on the #! line, it must also be used on the command line%s", (char)(ch), what)
#  define U16_CONST(x) ((U16)x##U)
#  define U32_CONST(x) ((U32)x##U)
#define U32_MAX_P1 (4.0 * (1 + ((U32_MAX) >> 2)))
#define U32_MAX_P1_HALF (2.0 * (1 + ((U32_MAX) >> 2)))
#   define U64_CONST(x) ((U64)x##U)
#      define UINT32_MIN 0
#      define UINT64_MIN 0
#define UNLIKELY(cond)                      EXPECT(cond,0)
#define UNLINK unlnk
#  define USEMYBINMODE 
#       define USE_64_BIT_STDIO 
#    define USE_BSDPGRP
#  define USE_ENVIRON_ARRAY
#  define USE_HASH_SEED
#   define USE_HEAP_INSTEAD_OF_STACK
#   define USE_LOCALE
#       define USE_PERL_ATOF
#   define USE_REENTRANT_API

#  define UVTYPE unsigned
#define UV_DIG (BIT_DIGITS(UVSIZE * 8))
#    define UV_IS_QUAD
#        define UV_MAX UINT32_MAX
#define UV_MAX_P1 (4.0 * (1 + ((UV_MAX) >> 2)))
#define UV_MAX_P1_HALF (2.0 * (1 + ((UV_MAX) >> 2)))
#    define UV_MIN UINT64_MIN
#    define UVf UVuf
#define U_32(what) (cast_ulong((NV)(what)))
#define U_I(what) ((unsigned int)U_32(what))
#define U_L(what) U_32(what)
#define U_S(what) ((U16)U_32(what))
#define U_V(what) (cast_uv((NV)(what)))
#    define VDf "vd"
#define VOIDUSED 1
#   define VOL
#define WITH_THR(s) WITH_THX(s)
#define WITH_THX(s) STMT_START { dTHX; s; } STMT_END
#  define YYTOKENTYPE


#   define _SOCKADDR_LEN
#  define __attribute__deprecated__         __attribute__((deprecated))
#  define __attribute__format__(x,y,z)      __attribute__((format(x,y,z)))
#  define __attribute__format__null_ok__(x,y,z)  __attribute__format__(x,y,z)
#  define __attribute__malloc__             __attribute__((__malloc__))
#  define __attribute__nonnull__(a)         __attribute__((nonnull(a)))
#  define __attribute__noreturn__           __attribute__((noreturn))
#  define __attribute__pure__               __attribute__((pure))
#  define __attribute__unused__             __attribute__((unused))
#  define __attribute__warn_unused_result__ __attribute__((warn_unused_result))


# define _swab_16_(x) ((U16)( \
         (((U16)(x) & U16_CONST(0x00ff)) << 8) | \
         (((U16)(x) & U16_CONST(0xff00)) >> 8) ))
# define _swab_32_(x) ((U32)( \
         (((U32)(x) & U32_CONST(0x000000ff)) << 24) | \
         (((U32)(x) & U32_CONST(0x0000ff00)) <<  8) | \
         (((U32)(x) & U32_CONST(0x00ff0000)) >>  8) | \
         (((U32)(x) & U32_CONST(0xff000000)) >> 24) ))
#  define _swab_64_(x) ((U64)( \
          (((U64)(x) & U64_CONST(0x00000000000000ff)) << 56) | \
          (((U64)(x) & U64_CONST(0x000000000000ff00)) << 40) | \
          (((U64)(x) & U64_CONST(0x0000000000ff0000)) << 24) | \
          (((U64)(x) & U64_CONST(0x00000000ff000000)) <<  8) | \
          (((U64)(x) & U64_CONST(0x000000ff00000000)) >>  8) | \
          (((U64)(x) & U64_CONST(0x0000ff0000000000)) >> 24) | \
          (((U64)(x) & U64_CONST(0x00ff000000000000)) >> 40) | \
          (((U64)(x) & U64_CONST(0xff00000000000000)) >> 56) ))


#  define aTHX
#  define aTHX_
#  define assert(what)	Perl_assert(what)
#       define atoll    _atoi64		
#  define child_offset_bits (8)
#define dMY_CXT_INTERP(my_perl)	\
	my_cxt_t *my_cxtp = (my_cxt_t *)(my_perl)->Imy_cxt_list[MY_CXT_INDEX]
#define dNOOP (void)0 
#   define dSAVEDERRNO    int saved_errno; unsigned saved_vms_errno
#   define dSAVE_ERRNO    int saved_errno = errno; unsigned saved_vms_errno = vaxc$errno
#    define dTHXa(a)	dVAR; pTHX = (tTHX)a
#  define dTHXoa(x)	dTHXa(x)
#  define do_aexec(really, mark,sp)	do_aexec5(really, mark, sp, 0, 0)
#  define do_exec(cmd)			do_exec3(cmd,0,0)
#define do_open(g, n, l, a, rm, rp, sf) \
	do_openn(g, n, l, a, rm, rp, sf, (SV **) NULL, 0)
#      define environ (*_NSGetEnviron())
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
#define htonl my_htonl
#define htons my_swap
#  define htovl(x)	vtohl(x)
#  define htovs(x)	vtohs(x)
#       define lockf lockf64
#           define lseek llseek
#       define lstat lstat64
#       define memchr(s,c,n) ninstr((char*)(s), ((char*)(s)) + n, &(c), &(c) + 1)
#	    define memcpy(d,s,l) bcopy(s,d,l)
#	    define memmove(d,s,l) memcpy(d,s,l)
#  define memset(d,c,l) my_memset(d,c,l)
#	    define memzero(d,l) bzero(d,l)
#  define my_betoh16(x)		_swab_16_(x)
#  define my_betoh32(x)		_swab_32_(x)
#   define my_betoh64(x)	_swab_64_(x)
#   define my_betohi(x)		(x)
#   define my_betohl(x)		(x)
#  define my_betohn(p,n)	my_swabn(p,n)
#   define my_betohs(x)		(x)
#  define my_binmode(fp, iotype, mode) \
            (PerlLIO_setmode(fileno(fp), mode) != -1 ? TRUE : FALSE)
#  define my_htobe16(x)		_swab_16_(x)
#  define my_htobe32(x)		_swab_32_(x)
#   define my_htobe64(x)	_swab_64_(x)
#   define my_htobei(x)		(x)
#   define my_htobel(x)		(x)
#  define my_htoben(p,n)	my_swabn(p,n)
#   define my_htobes(x)		(x)
#  define my_htole16(x)		(x)
#  define my_htole32(x)		(x)
#   define my_htole64(x)	(x)
#   define my_htolei(x)		(x)
#   define my_htolel(x)		(x)
#  define my_htolen(p,n)	NOOP
#   define my_htoles(x)		(x)
#  define my_letoh16(x)		(x)
#  define my_letoh32(x)		(x)
#   define my_letoh64(x)	(x)
#   define my_letohi(x)		(x)
#   define my_letohl(x)		(x)
#  define my_letohn(p,n)	NOOP
#   define my_letohs(x)		(x)
#      define my_snprintf(buffer, len, ...) ({ int __len__ = snprintf(buffer, len, __VA_ARGS__); if ((len) > 0 && (Size_t)__len__ >= (len)) Perl_croak_nocontext("panic: snprintf buffer overflow"); __len__; })
#  define my_sprintf sprintf
#  define my_strlcat    strlcat
#      define my_vsnprintf(buffer, len, ...) ({ int __len__ = vsnprintf(buffer, len, __VA_ARGS__); if ((len) > 0 && (Size_t)__len__ >= (len)) Perl_croak_nocontext("panic: vsnprintf buffer overflow"); __len__; })
#   define ntohi ntohs
#define ntohl my_ntohl
#define ntohs my_swap
#    define op_getmad(arg,pegop,slot) NOOP
#       define open open64

#  define pTHX  register tTHX my_perl PERL_UNUSED_DECL
#  define pTHX_
#define pVAR    register struct perl_vars* my_vars PERL_UNUSED_DECL
#  define panic_write2(s)		write(2, s, strlen(s))
#    define pmflag(a,b)		Perl_pmflag(aTHX_ a,b)
#  define register
#  define safecalloc  Perl_calloc
#  define safefree    Perl_mfree
#  define safemalloc  Perl_malloc
#  define saferealloc Perl_realloc
#           define semun gccbug_semun
#    define setregid(r,e) setresgid(r,e,(Gid_t)-1)
#    define setreuid(r,e) setresuid(r,e,(Uid_t)-1)
#  define sprintf UTS_sprintf_wrap
#       define stat stat64
#define strchr index
#    define stringify(s) stringify_immed(s)
#    define stringify_immed(s) #s
#define strrchr rindex
#        define strtoll __strtoll	
#        define strtoull __strtoull	
#       define tmpfile tmpfile64
#       define truncate truncate64
#  define vtohl(x)	((((x)&0xFF)<<24)	\
			+(((x)>>24)&0xFF)	\
			+(((x)&0x0000FF00)<<8)	\
			+(((x)&0x00FF0000)>>8)	)
#  define vtohs(x)	((((x)&0xFF)<<8) + (((x)>>8)&0xFF))
#define NofAMmeth max_amg_code
#define OP_DESC(o) ((o)->op_type == OP_CUSTOM ? custom_op_desc(o) : \
                    PL_op_desc[(o)->op_type])
#define OP_NAME(o) ((o)->op_type == OP_CUSTOM ? custom_op_name(o) : \
                    PL_op_name[(o)->op_type])
#  define PERL_CHECK_INITED
#  define PERL_PPADDR_INITED
#define Perl_pp_i_postdec Perl_pp_postdec
#define Perl_pp_i_postinc Perl_pp_postinc
#define Perl_pp_i_predec Perl_pp_predec
#define Perl_pp_i_preinc Perl_pp_preinc
#define AMG_CALLbinL(left,right,meth) \
            amagic_call(left,right,CAT2(meth,_amg),AMGf_noright)
#define AMG_CALLun(sv,meth) AMG_CALLun_var(sv,CAT2(meth,_amg))
#define AMG_CALLun_var(sv,meth_enum) amagic_call(sv,&PL_sv_undef,  \
					meth_enum,AMGf_noright | AMGf_unary)
#define DIE Perl_die
#define EXTEND(p,n)	STMT_START { if (PL_stack_max - p < (int)(n)) {		\
			    sp = stack_grow(sp,p, (int) (n));		\
			} } STMT_END
#define EXTEND_MORTAL(n) \
    STMT_START {							\
	if (PL_tmps_ix + (n) >= PL_tmps_max)				\
	    tmps_grow(n);						\
    } STMT_END
#define FORCE_SETs(sv) STMT_START { sv_setsv(TARG, (sv)); SETTARG; } STMT_END
#define GETATARGET targ = (PL_op->op_flags & OPf_STACKED ? sp[-1] : PAD_SV(PL_op->op_targ))
#define GETTARGET targ = PAD_SV(PL_op->op_targ)
#define GETTARGETSTACKED targ = (PL_op->op_flags & OPf_STACKED ? POPs : PAD_SV(PL_op->op_targ))
#define LVRET ((PL_op->op_private & OPpMAYBE_LVSUB) && is_lvalue_sub())
#define MARK mark
#define MEXTEND(p,n)	STMT_START {if (PL_stack_max - p < (int)(n)) {	\
			    const int markoff = mark - PL_stack_base;	\
			    sp = stack_grow(sp,p,(int) (n));		\
			    mark = PL_stack_base + markoff;		\
			} } STMT_END
#define NORMAL PL_op->op_next
#define PP(s) OP * Perl_##s(pTHX)
#define PUSHMARK(p)	\
	STMT_START {					\
	    if (++PL_markstack_ptr == PL_markstack_max)	\
	    markstack_grow();				\
	    *PL_markstack_ptr = (I32)((p) - PL_stack_base);\
	} STMT_END
#define PUSHi(i)	STMT_START { sv_setiv(TARG, (IV)(i)); PUSHTARG; } STMT_END
#define PUSHn(n)	STMT_START { sv_setnv(TARG, (NV)(n)); PUSHTARG; } STMT_END
#define PUSHp(p,l)	STMT_START { sv_setpvn(TARG, (p), (l)); PUSHTARG; } STMT_END
#define PUSHs(s)	(*++sp = (s))
#define PUSHu(u)	STMT_START { sv_setuv(TARG, (UV)(u)); PUSHTARG; } STMT_END
#define RETURNOP(o)	return (PUTBACK, o)
#define RETURNX(x)	return (x, PUTBACK, NORMAL)
#define RvDEEPCP(rv) STMT_START { SV* tmpRef=SvRV(rv); SV* rv_copy;     \
  if (SvREFCNT(tmpRef)>1 && (rv_copy = AMG_CALLun(rv,copy))) {          \
    SvRV_set(rv, rv_copy);		    \
    SvREFCNT_dec(tmpRef);                   \
  } } STMT_END
#define SETi(i)		STMT_START { sv_setiv(TARG, (IV)(i)); SETTARG; } STMT_END
#define SETn(n)		STMT_START { sv_setnv(TARG, (NV)(n)); SETTARG; } STMT_END
#define SETp(p,l)	STMT_START { sv_setpvn(TARG, (p), (l)); SETTARG; } STMT_END
#define SETs(s)		(*sp = s)
#define SETsv(sv)	STMT_START {					\
		if (opASSIGN || (SvFLAGS(TARG) & SVs_PADMY))		\
		   { sv_setsv(TARG, (sv)); SETTARG; }			\
		else SETs(sv); } STMT_END
#define SETsvUN(sv)	STMT_START {					\
		if (SvFLAGS(TARG) & SVs_PADMY)		\
		   { sv_setsv(TARG, (sv)); SETTARG; }			\
		else SETs(sv); } STMT_END
#define SETu(u)		STMT_START { sv_setuv(TARG, (UV)(u)); SETTARG; } STMT_END
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
  || ((mg = mg_find((const SV *) sv, PERL_MAGIC_tied))           \
      && (stash = SvSTASH(SvRV(SvTIED_obj(MUTABLE_SV(sv), mg)))) \
      && gv_fetchmethod_autoload(stash, "EXISTS", TRUE)          \
      && gv_fetchmethod_autoload(stash, "DELETE", TRUE)          \
     )                       \
  )
#define TARG targ
#define USE_LEFT(sv) \
	(SvOK(sv) || SvGMAGICAL(sv) || !(PL_op->op_flags & OPf_STACKED))
#define XPUSHi(i)	STMT_START { sv_setiv(TARG, (IV)(i)); XPUSHTARG; } STMT_END
#define XPUSHn(n)	STMT_START { sv_setnv(TARG, (NV)(n)); XPUSHTARG; } STMT_END
#define XPUSHp(p,l)	STMT_START { sv_setpvn(TARG, (p), (l)); XPUSHTARG; } STMT_END
#define XPUSHs(s)	STMT_START { EXTEND(sp,1); (*++sp = (s)); } STMT_END
#define XPUSHu(u)	STMT_START { sv_setuv(TARG, (UV)(u)); XPUSHTARG; } STMT_END
#define dATARGET SV * GETATARGET
#define dPOPXiirl(X)	IV right = POPi; IV left = CAT2(X,i)
#define dPOPXiirl_ul(X) \
    IV right = POPi;					\
    SV *leftsv = CAT2(X,s);				\
    IV left = USE_LEFT(leftsv) ? SvIV(leftsv) : 0
#define dPOPXnnrl(X)	NV right = POPn; NV left = CAT2(X,n)
#define dPOPXnnrl_ul(X)	\
    NV right = POPn;				\
    SV *leftsv = CAT2(X,s);				\
    NV left = USE_LEFT(leftsv) ? SvNV(leftsv) : 0.0
#define dPOPXssrl(X)	SV *right = POPs; SV *left = CAT2(X,s)
#define dTARG SV *targ
#define dTARGET SV * GETTARGET
#define dTARGETSTACKED SV * GETTARGETSTACKED
#define mPUSHi(i)	sv_setiv(PUSHmortal, (IV)(i))
#define mPUSHn(n)	sv_setnv(PUSHmortal, (NV)(n))
#define mPUSHp(p,l)	PUSHs(newSVpvn_flags((p), (l), SVs_TEMP))
#define mPUSHs(s)	PUSHs(sv_2mortal(s))
#define mPUSHu(u)	sv_setuv(PUSHmortal, (UV)(u))
#define mXPUSHi(i)	STMT_START { EXTEND(sp,1); sv_setiv(PUSHmortal, (IV)(i)); } STMT_END
#define mXPUSHn(n)	STMT_START { EXTEND(sp,1); sv_setnv(PUSHmortal, (NV)(n)); } STMT_END
#define mXPUSHp(p,l)	STMT_START { EXTEND(sp,1); mPUSHp((p), (l)); } STMT_END
#define mXPUSHs(s)	XPUSHs(sv_2mortal(s))
#define mXPUSHu(u)	STMT_START { EXTEND(sp,1); sv_setuv(PUSHmortal, (UV)(u)); } STMT_END
#define opASSIGN (PL_op->op_flags & OPf_STACKED)
#define setAGAIN(ref)	\
    STMT_START {					\
	sv = ref;					\
	if (!SvROK(ref))				\
	    Perl_croak(aTHX_ "Overloaded dereference did not return a reference");	\
	if (ref != arg && SvRV(ref) != SvRV(arg)) {	\
	    arg = ref;					\
	    goto am_again;				\
	}						\
    } STMT_END
#define tryAMAGICbin(meth,assign) \
		tryAMAGICbin_var(CAT2(meth,_amg),assign)
#define tryAMAGICbinSET(meth,assign) tryAMAGICbinW(meth,assign,SETs)
#define tryAMAGICbinSET_var(meth_enum,assign) \
    tryAMAGICbinW_var(meth_enum,assign,SETs)
#define tryAMAGICbinW(meth,assign,set) \
    tryAMAGICbinW_var(CAT2(meth,_amg),assign,set)
#define tryAMAGICbinW_var(meth_enum,assign,set) STMT_START { \
	    SV* const left = *(sp-1); \
	    SV* const right = *(sp); \
	    if ((SvAMAGIC(left)||SvAMAGIC(right))) {\
		SV * const tmpsv = amagic_call(left, \
				   right, \
				   (meth_enum), \
				   (assign)? AMGf_assign: 0); \
		if (tmpsv) { \
		    SPAGAIN; \
		    (void)POPs; set(tmpsv); RETURN; } \
		} \
	} STMT_END
#define tryAMAGICbin_var(meth_enum,assign) \
		tryAMAGICbinW_var(meth_enum,assign,SETsv)
#define tryAMAGICftest(chr)				\
    STMT_START {					\
	assert(chr != '?');				\
	if ((PL_op->op_flags & OPf_KIDS)		\
		&& SvAMAGIC(TOPs)) {			\
	    const char tmpchr = (chr);			\
	    SV * const tmpsv = amagic_call(TOPs,	\
		newSVpvn_flags(&tmpchr, 1, SVs_TEMP),	\
		ftest_amg, AMGf_unary);			\
							\
	    if (tmpsv) {				\
		const OP *next = PL_op->op_next;	\
							\
		SPAGAIN;				\
							\
		if (next->op_type >= OP_FTRREAD &&	\
		    next->op_type <= OP_FTBINARY &&	\
		    next->op_private & OPpFT_STACKED	\
		) {					\
		    if (SvTRUE(tmpsv))			\
				\
			RETURN;				\
		}					\
							\
		SETs(tmpsv);				\
		RETURN;					\
	    }						\
	}						\
    } STMT_END
#define tryAMAGICun(meth)	tryAMAGICun_var(CAT2(meth,_amg))
#define tryAMAGICunDEREF(meth) tryAMAGICunW(meth,setAGAIN,0,(void)0)
#define tryAMAGICunDEREF_var(meth_enum) \
	tryAMAGICunW_var(meth_enum,setAGAIN,0,(void)0)
#define tryAMAGICunSET(meth)	tryAMAGICunW(meth,SETs,0,RETURN)
#define tryAMAGICunTARGET(meth, shift)					\
	STMT_START { dSP; sp--; 			\
	    { dTARGETSTACKED; 						\
		{ dSP; tryAMAGICunW(meth,FORCE_SETs,shift,RETURN);}}} STMT_END
#define tryAMAGICunW(meth,set,shift,ret) \
	tryAMAGICunW_var(CAT2(meth,_amg),set,shift,ret)
#define tryAMAGICunW_var(meth_enum,set,shift,ret) STMT_START { \
	    SV* tmpsv; \
	    SV* arg= sp[shift]; \
          if(0) goto am_again;   \
	  am_again: \
	    if ((SvAMAGIC(arg))&&\
		(tmpsv=AMG_CALLun_var(arg,(meth_enum)))) {\
	       SPAGAIN; if (shift) sp += shift; \
	       set(tmpsv); ret; } \
	} STMT_END
#define tryAMAGICun_var(meth_enum) tryAMAGICunW_var(meth_enum,SETsvUN,0,RETURN)
#  define ALLOC_THREAD_KEY \
    STMT_START {						\
	if (pthread_key_create(&PL_thr_key, 0)) {		\
            write(2, STR_WITH_LEN("panic: pthread_key_create failed\n")); \
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
#  define LOCK_DOLLARZERO_MUTEX
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
	if ((_eC_ = pthread_mutex_lock((m))))			\
	    Perl_croak_nocontext("panic: MUTEX_LOCK (%d) [%s:%d]",	\
				 _eC_, "__FILE__", "__LINE__");	\
    } STMT_END
#  define MUTEX_UNLOCK(m) \
    STMT_START {						\
	int _eC_;						\
	if ((_eC_ = pthread_mutex_unlock((m))))			\
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

#  define THREAD_RET_CAST(p)	((void *)(p))
#  define UNLOCK_DOLLARZERO_MUTEX
#        define YIELD pthread_yield()
#  define dTHR dNOOP
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

#define PERL_GIT_UNCOMMITTED_CHANGES 
#define ANYOF_FOLD_SHARP_S(node, input, end)	\
	(ANYOF_BITMAP_TEST(node, LATIN_SMALL_LETTER_SHARP_S) && \
	 (ANYOF_FLAGS(node) & ANYOF_UNICODE) && \
	 (ANYOF_FLAGS(node) & ANYOF_FOLD) && \
	 ((end) > (input) + 1) && \
	 toLOWER((input)[0]) == 's' && \
	 toLOWER((input)[1]) == 's')
#define ASCII_TO_NATIVE(ch)      (ch)
#define ASCII_TO_NEED(enc,ch)    (ch)
#define DO_UTF8(sv) (SvUTF8(sv) && !IN_BYTES)
#define IN_BYTES (CopHINTS_get(PL_curcop) & HINT_BYTES)
#define IN_UNI_8_BIT ( (CopHINTS_get(PL_curcop) & HINT_UNI_8_BIT) \
			&& ! IN_LOCALE_RUNTIME && ! IN_BYTES)
#   define LATIN_SMALL_LETTER_Y_WITH_DIAERESIS 0x00FF
#define MAX_PORTABLE_UTF8_TWO_BYTE 0x3FF    
#   define MICRO_SIGN 0x00B5
#define NATIVE8_TO_UNI(ch)     NATIVE_TO_ASCII(ch)	
#define NATIVE_IS_INVARIANT(c)		UNI_IS_INVARIANT(NATIVE8_TO_UNI(c))
#define NATIVE_TO_ASCII(ch)      (ch)
#define NATIVE_TO_NEED(enc,ch)   (ch)
#define NATIVE_TO_UNI(ch)        (ch)
#define NATIVE_TO_UTF(ch)        (ch)
#define SHARP_S_SKIP 2
#define UNICODE_ALLOW_SURROGATE 0x0001	
#define UNICODE_IS_BYTE_ORDER_MARK(c)	((c) == UNICODE_BYTE_ORDER_MARK)
#define UNICODE_IS_ILLEGAL(c)		((c) == UNICODE_ILLEGAL)
#define UNICODE_IS_REPLACEMENT(c)	((c) == UNICODE_REPLACEMENT)
#define UNICODE_IS_SURROGATE(c)		((c) >= UNICODE_SURROGATE_FIRST && \
					 (c) <= UNICODE_SURROGATE_LAST)
#define UNISKIP(uv) ( (uv) < 0x80           ? 1 : \
		      (uv) < 0x800          ? 2 : \
		      (uv) < 0x10000        ? 3 : \
		      (uv) < 0x200000       ? 4 : \
		      (uv) < 0x4000000      ? 5 : \
		      (uv) < 0x80000000     ? 6 : \
                      (uv) < UTF8_QUAD_MAX ? 7 : 13 )
#define UNI_IS_INVARIANT(c)		(((UV)c) <  0x80)
#define UNI_TO_NATIVE(ch)        (ch)
#    define USE_UTF8_IN_NAMES (!IN_BYTES)
#define UTF8SKIP(s) PL_utf8skip[*(const U8*)(s)]
#define UTF8_ACCUMULATE(old, new)	(((old) << UTF_ACCUMULATION_SHIFT) | (((U8)new) & UTF_CONTINUATION_MASK))
#define UTF8_EIGHT_BIT_HI(c)	UTF8_TWO_BYTE_HI((U8)(c))
#define UTF8_EIGHT_BIT_LO(c)	UTF8_TWO_BYTE_LO((U8)(c))
#define UTF8_IS_ASCII(c) UTF8_IS_INVARIANT(c)
#define UTF8_IS_CONTINUATION(c)		(((U8)c) >= 0x80 && (((U8)c) <= 0xbf))
#define UTF8_IS_CONTINUED(c) 		(((U8)c) &  0x80)
#define UTF8_IS_DOWNGRADEABLE_START(c)	(((U8)c & 0xfc) == 0xc0)
#define UTF8_IS_INVARIANT(c)		UNI_IS_INVARIANT(NATIVE_TO_UTF(c))
#define UTF8_IS_START(c)		(((U8)c) >= 0xc0 && (((U8)c) <= 0xfd))
#define UTF8_MAXBYTES 13
#define UTF8_MAXLEN UTF8_MAXBYTES
#define UTF8_TWO_BYTE_HI(c)	((U8) (UTF8_TWO_BYTE_HI_nocast(c)))
#define UTF8_TWO_BYTE_HI_nocast(c)	UTF_TO_NATIVE(((c)>>UTF_ACCUMULATION_SHIFT)|UTF_START_MARK(2))
#define UTF8_TWO_BYTE_LO(c)	((U8) (UTF8_TWO_BYTE_LO_nocast(c)))
#define UTF8_TWO_BYTE_LO_nocast(c)	UTF_TO_NATIVE(((c)&UTF_CONTINUATION_MASK)|UTF_CONTINUATION_MARK)
#define UTF_START_MARK(len) (((len) >  7) ? 0xFF : (0xFE << (7-(len))))
#define UTF_START_MASK(len) (((len) >= 7) ? 0x00 : (0x1F >> ((len)-2)))
#define UTF_TO_NATIVE(ch)        (ch)
#define isALNUM_lazy(p)		isALNUM_lazy_if(p,1)
#define isALNUM_lazy_if(p,c)   ((IN_BYTES || (!c || ! UTF8_IS_START(*((const U8*)p)))) \
				? isALNUM(*(p)) \
				: isALNUM_utf8((const U8*)p))
#define isIDFIRST_lazy(p)	isIDFIRST_lazy_if(p,1)
#define isIDFIRST_lazy_if(p,c) ((IN_BYTES || (!c || ! UTF8_IS_START(*((const U8*)p)))) \
				? isIDFIRST(*(p)) \
				: isIDFIRST_utf8((const U8*)p))
#define is_utf8_string_loc(s, len, ep)	is_utf8_string_loclen(s, len, ep, 0)
#define utf8n_to_uvchr utf8n_to_uvuni
#define uvchr_to_utf8  uvuni_to_utf8
#define uvuni_to_utf8(d, uv)		uvuni_to_utf8_flags(d, uv, 0)
#define LATIN_SMALL_LETTER_SHARP_S 0x59
#define Bit(x)			(1 << ((x) % 8))
#define DUP_WARNINGS(p)		\
    (specialWARN(p) ? (STRLEN*)(p)	\
    : (STRLEN*)CopyD(p, PerlMemShared_malloc(sizeof(*p)+*p), sizeof(*p)+*p, \
		     			     char))
#define IsSet(a, x)		((a)[Off(x)] & Bit(x))
#define Off(x)			((x) / 8)
#define ckDEAD(x)							\
	   ( ! specialWARN(PL_curcop->cop_warnings) &&			\
	    ( isWARNf_on(PL_curcop->cop_warnings, WARN_ALL) || 		\
	      isWARNf_on(PL_curcop->cop_warnings, unpackWARN1(x)) ||	\
	      isWARNf_on(PL_curcop->cop_warnings, unpackWARN2(x)) ||	\
	      isWARNf_on(PL_curcop->cop_warnings, unpackWARN3(x)) ||	\
	      isWARNf_on(PL_curcop->cop_warnings, unpackWARN4(x))))
#define ckWARN(w)		Perl_ckwarn(aTHX_ packWARN(w))
#define ckWARN2(w1,w2)		Perl_ckwarn(aTHX_ packWARN2(w1,w2))
#define ckWARN2_d(w1,w2)	Perl_ckwarn_d(aTHX_ packWARN2(w1,w2))
#define ckWARN3(w1,w2,w3)	Perl_ckwarn(aTHX_ packWARN3(w1,w2,w3))
#define ckWARN3_d(w1,w2,w3)	Perl_ckwarn_d(aTHX_ packWARN3(w1,w2,w3))
#define ckWARN4(w1,w2,w3,w4)	Perl_ckwarn(aTHX_ packWARN4(w1,w2,w3,w4))
#define ckWARN4_d(w1,w2,w3,w4)	Perl_ckwarn_d(aTHX_ packWARN4(w1,w2,w3,w4))
#define ckWARN_d(w)		Perl_ckwarn_d(aTHX_ packWARN(w))
#define isLEXWARN_on 	(PL_curcop->cop_warnings != pWARN_STD)
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
#define LEAVE_SCOPE(old) if (PL_savestack_ix > old) leave_scope(old)
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
	  save_adelete(MUTABLE_AV(a), (I32)(k))
#define SAVEBOOL(b)	save_bool((bool*)&(b))
#define SAVECLEARSV(sv)	save_clearsv((SV**)&(sv))
#define SAVECOMPILEWARNINGS() save_pushptr(PL_compiling.cop_warnings, SAVEt_COMPILE_WARNINGS)
#define SAVECOMPPAD() save_pushptr(MUTABLE_SV(PL_comppad), SAVEt_COMPPAD)
#define SAVECOPARYBASE(c) save_pushi32ptr(CopARYBASE_get(c), c, SAVEt_COP_ARYBASE);
#  define SAVECOPFILE(c)	SAVEPPTR(CopFILE(c))
#  define SAVECOPFILE_FREE(c)	SAVESHAREDPV(CopFILE(c))
#define SAVECOPLINE(c)		SAVEI32(CopLINE(c))
#  define SAVECOPSTASH(c)	SAVEPPTR(CopSTASHPV(c))
#  define SAVECOPSTASH_FREE(c)	SAVESHAREDPV(CopSTASHPV(c))
#define SAVEDELETE(h,k,l) \
	  save_delete(MUTABLE_HV(h), (char*)(k), (I32)(l))
#define SAVEDESTRUCTOR(f,p) \
	  save_destructor((DESTRUCTORFUNC_NOCONTEXT_t)(f), (void*)(p))
#define SAVEDESTRUCTOR_X(f,p) \
	  save_destructor_x((DESTRUCTORFUNC_t)(f), (void*)(p))
#define SAVEFREEOP(o)	save_freeop((OP*)(o))
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
#define SAVESTACK_CXPOS() \
    STMT_START {                                  \
        SSCHECK(3);                               \
        SSPUSHINT(cxstack[cxstack_ix].blk_oldsp); \
        SSPUSHINT(cxstack_ix);                    \
        SSPUSHINT(SAVEt_STACK_CXPOS);             \
    } STMT_END
#define SAVESTACK_POS() \
    STMT_START {				\
	SSCHECK(2);				\
	SSPUSHINT(PL_stack_sp - PL_stack_base);	\
	SSPUSHINT(SAVEt_STACK_POS);		\
    } STMT_END
#define SAVESWITCHSTACK(f,t) \
    STMT_START {					\
	save_pushptrptr(MUTABLE_SV(f), MUTABLE_SV(t), SAVEt_SAVESWITCHSTACK); \
	SWITCHSTACK((f),(t));				\
	PL_curstackinfo->si_stack = (t);		\
    } STMT_END
#define SAVETMPS save_int((int*)&PL_tmps_floor), PL_tmps_floor = PL_tmps_ix
#define SAVEVPTR(s)	save_vptr((void*)&(s))
#define SCOPE_SAVES_SIGNAL_MASK 0
#define SSCHECK(need) if (PL_savestack_ix + (I32)(need) > PL_savestack_max) savestack_grow()
#define SSGROW(need) if (PL_savestack_ix + (I32)(need) > PL_savestack_max) savestack_grow_cnt(need)
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
#define SSPTR(off,type)         ((type)  ((char*)PL_savestack + off))
#define SSPTRt(off,type)        ((type*) ((char*)PL_savestack + off))
#define SSPUSHBOOL(p) (PL_savestack[PL_savestack_ix++].any_bool = (p))
#define SSPUSHDPTR(p) (PL_savestack[PL_savestack_ix++].any_dptr = (p))
#define SSPUSHDXPTR(p) (PL_savestack[PL_savestack_ix++].any_dxptr = (p))
#define SSPUSHINT(i) (PL_savestack[PL_savestack_ix++].any_i32 = (I32)(i))
#define SSPUSHIV(i) (PL_savestack[PL_savestack_ix++].any_iv = (IV)(i))
#define SSPUSHLONG(i) (PL_savestack[PL_savestack_ix++].any_long = (long)(i))
#define SSPUSHPTR(p) (PL_savestack[PL_savestack_ix++].any_ptr = (void*)(p))
#define save_aelem(av,idx,sptr)	save_aelem_flags(av,idx,sptr,SAVEf_SETMAGIC)
#define save_freeop(op)		save_pushptr((void *)(op), SAVEt_FREEOP)
#define save_freepv(pv)		save_pushptr((void *)(pv), SAVEt_FREEPV)
#define save_freesv(op)		save_pushptr((void *)(op), SAVEt_FREESV)
#define save_helem(hv,key,sptr)	save_helem_flags(hv,key,sptr,SAVEf_SETMAGIC)
#define save_mortalizesv(op)	save_pushptr((void *)(op), SAVEt_MORTALIZESV)
#define save_op()		save_pushptr((void *)(PL_op), SAVEt_OP)
#define MGf_COPY       8	
#define MGf_DUP     0x10 	
#define MGf_GSKIP      4
#define MGf_LOCAL   0x20	
#define MGf_MINMATCH   1        
#define MGf_REFCOUNTED 2
#define MGf_TAINTEDDIR 1        
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
#define AvALLOC(av)	(*((SV***)&((XPVAV*)  SvANY(av))->xav_alloc))
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
#define newAV()	MUTABLE_AV(newSV_type(SVt_PVAV))
#define xav_alloc xiv_u.xivu_p1
#define CATCH_SET(v)		(PL_top_env->je_mustcatch = (v))
#define CLEAR_ARGARRAY(ary) \
    STMT_START {							\
	AvMAX(ary) += AvARRAY(ary) - AvALLOC(ary);			\
	AvARRAY(ary) = AvALLOC(ary);					\
	AvFILLp(ary) = -1;						\
    } STMT_END
#define CXINC (cxstack_ix < cxstack_max ? ++cxstack_ix : (cxstack_ix = cxinc()))
#  define CX_ITERDATA_SET(cx,idata,o)					\
	if ((cx->blk_loop.targoffset = (o)))				\
	    CX_CURPAD_SAVE(cx->blk_loop);				\
	else								\
	    cx->blk_loop.oldcomppad = (idata);
#  define CX_LOOP_NEXTOP_GET(cx)	((cx)->blk_loop.my_op->op_nextop + 0)
#define CXt_EVAL       10
#define CXt_FORMAT      9
#define CXt_SUBST      11
#define CopARYBASE_get(c)	\
	((CopHINTS_get(c) & HINT_ARYBASE)				\
	 ? SvIV(Perl_refcounted_he_fetch(aTHX_ (c)->cop_hints_hash, 0,	\
					 "$[", 2, 0, 0))		\
	 : 0)
#define CopARYBASE_set(c, b) STMT_START { \
	if (b || ((c)->cop_hints & HINT_ARYBASE)) {			\
	    (c)->cop_hints |= HINT_ARYBASE;				\
	    if ((c) == &PL_compiling) {					\
		SV *val = newSViv(b);					\
		(void)hv_stores(GvHV(PL_hintgv), "$[", val);		\
		mg_set(val);						\
		PL_hints |= HINT_ARYBASE;				\
	    } else {							\
		(c)->cop_hints_hash					\
		   = Perl_refcounted_he_new(aTHX_ (c)->cop_hints_hash,	\
					newSVpvs_flags("$[", SVs_TEMP),	\
					sv_2mortal(newSViv(b)));	\
	    }								\
	}								\
    } STMT_END
#  define CopFILE(c)		((c)->cop_file)
#  define CopFILEAV(c)		(CopFILE(c) \
				 ? GvAV(gv_fetchfile(CopFILE(c))) : NULL)
#    define CopFILEAVx(c)	(assert(CopFILE(c)), \
				   GvAV(gv_fetchfile(CopFILE(c))))
#  define CopFILEGV(c)		(CopFILE(c) \
				 ? gv_fetchfile(CopFILE(c)) : NULL)
#  define CopFILEGV_set(c,gv)	((c)->cop_filegv = (GV*)SvREFCNT_inc(gv))
#  define CopFILESV(c)		(CopFILE(c) \
				 ? GvSV(gv_fetchfile(CopFILE(c))) : NULL)
#    define CopFILE_free(c) SAVECOPFILE_FREE(c)
#    define CopFILE_set(c,pv)	((c)->cop_file = savepv(pv))
#    define CopFILE_setn(c,pv,l)  ((c)->cop_file = savepv((pv),(l)))
#define CopHINTS_get(c)		((c)->cop_hints + 0)
#define CopHINTS_set(c, h)	STMT_START {				\
				    (c)->cop_hints = (h);		\
				} STMT_END
#define CopLABEL(c)  Perl_fetch_cop_label(aTHX_ (c)->cop_hints_hash, NULL, NULL)
#define CopLABEL_alloc(pv)	((pv)?savepv(pv):NULL)
#define CopLINE(c)		((c)->cop_line)
#define CopLINE_dec(c)		(--CopLINE(c))
#define CopLINE_inc(c)		(++CopLINE(c))
#define CopLINE_set(c,l)	(CopLINE(c) = (l))
#  define CopSTASH(c)		(CopSTASHPV(c) \
				 ? gv_stashpv(CopSTASHPV(c),GV_ADD) : NULL)
#  define CopSTASHPV(c)		((c)->cop_stashpv)
#    define CopSTASHPV_set(c,pv)	((c)->cop_stashpv = ((pv) ? savepv(pv) : NULL))
#  define CopSTASH_eq(c,hv)	((hv) && stashpv_hvname_match(c,hv))
#    define CopSTASH_free(c) SAVECOPSTASH_FREE(c)
#define CopSTASH_ne(c,hv)	(!CopSTASH_eq(c,hv))
#  define CopSTASH_set(c,hv)	CopSTASHPV_set(c, (hv) ? HvNAME_get(hv) : NULL)
#define CxFOREACH(c)	(CxTYPE_is_LOOP(c) && CxTYPE(c) != CXt_LOOP_PLAIN)
#define CxFOREACHDEF(c)	((CxTYPE_is_LOOP(c) && CxTYPE(c) != CXt_LOOP_PLAIN) \
			 && ((c)->cx_type & CXp_FOR_DEF))
#define CxHASARGS(c)	(((c)->cx_type & CXp_HASARGS) == CXp_HASARGS)
#  define CxITERVAR(c)							\
	((c)->blk_loop.oldcomppad					\
	 ? (CxPADLOOP(c) 						\
	    ? &CX_CURPAD_SV( (c)->blk_loop, (c)->blk_loop.targoffset )	\
	    : &GvSV((GV*)(c)->blk_loop.oldcomppad))			\
	 : (SV**)NULL)
#define CxLABEL(c)	(0 + CopLABEL((c)->blk_oldcop))
#define CxLVAL(c)	(0 + (c)->blk_u16)
#define CxMULTICALL(c)	(((c)->cx_type & CXp_MULTICALL)			\
			 == CXp_MULTICALL)
#define CxOLD_IN_EVAL(cx)	(((cx)->blk_u16) & 0x7F)
#define CxOLD_OP_TYPE(cx)	(((cx)->blk_u16) >> 7)
#define CxONCE(cx)		((cx)->cx_type & CXp_ONCE)
#  define CxPADLOOP(c)	((c)->blk_loop.targoffset)
#define CxREALEVAL(c)	(((c)->cx_type & (CXTYPEMASK|CXp_REAL))		\
			 == (CXt_EVAL|CXp_REAL))
#define CxTRYBLOCK(c)	(((c)->cx_type & (CXTYPEMASK|CXp_TRYBLOCK))	\
			 == (CXt_EVAL|CXp_TRYBLOCK))
#define CxTYPE(c)	((c)->cx_type & CXTYPEMASK)
#define CxTYPE_is_LOOP(c)	(((c)->cx_type & 0xC) == 0x4)
#define G_FAKINGEVAL  256	
#define G_KEEPERR      32	
#define G_METHOD      128       
#define G_NOARGS       16	
#define G_NODEBUG      64	
#define JMPENV_BOOTSTRAP \
    STMT_START {				\
	Zero(&PL_start_env, 1, JMPENV);		\
	PL_start_env.je_ret = -1;		\
	PL_start_env.je_mustcatch = TRUE;	\
	PL_top_env = &PL_start_env;		\
    } STMT_END
#define JMPENV_JUMP(v) \
    STMT_START {						\
	OP_REG_TO_MEM;						\
	if (PL_top_env->je_prev)				\
	    PerlProc_longjmp(PL_top_env->je_buf, (v));		\
	if ((v) == 2)						\
	    PerlProc_exit(STATUS_EXIT);		                \
	PerlIO_printf(PerlIO_stderr(), "panic: top_env\n");	\
	PerlProc_exit(1);					\
    } STMT_END
#define JMPENV_POP \
    STMT_START {							\
	DEBUG_l(Perl_deb(aTHX_ "popping jumplevel was %p, now %p at %s:%d\n",	\
		         (void*)PL_top_env, (void*)cur_env.je_prev,		\
		         "__FILE__", "__LINE__"));					\
	assert(PL_top_env == &cur_env);					\
	PL_top_env = cur_env.je_prev;					\
    } STMT_END
#define JMPENV_PUSH(v) \
    STMT_START {							\
	DEBUG_l(Perl_deb(aTHX_ "Setting up jumplevel %p, was %p at %s:%d\n",	\
		         (void*)&cur_env, (void*)PL_top_env,			\
		         "__FILE__", "__LINE__"));					\
	cur_env.je_prev = PL_top_env;					\
	OP_REG_TO_MEM;							\
	cur_env.je_ret = PerlProc_setjmp(cur_env.je_buf, SCOPE_SAVES_SIGNAL_MASK);		\
	OP_MEM_TO_REG;							\
	PL_top_env = &cur_env;						\
	cur_env.je_mustcatch = FALSE;					\
	(v) = cur_env.je_ret;						\
    } STMT_END
#define LEAVESUB(sv)							\
    STMT_START {							\
	if (sv)								\
	    SvREFCNT_dec(sv);						\
    } STMT_END
#define MULTICALL \
    STMT_START {							\
	PL_op = multicall_cop;						\
	CALLRUNOPS(aTHX);						\
    } STMT_END
#define OutCopFILE(c) CopFILE(c)
#define POPBLOCK(cx,pm) cx = &cxstack[cxstack_ix--],			\
	newsp		 = PL_stack_base + cx->blk_oldsp,		\
	PL_curcop	 = cx->blk_oldcop,				\
	PL_markstack_ptr = PL_markstack + cx->blk_oldmarksp,		\
	PL_scopestack_ix = cx->blk_oldscopesp,				\
	pm		 = cx->blk_oldpm,				\
	gimme		 = cx->blk_gimme;				\
	DEBUG_SCOPE("POPBLOCK");					\
	DEBUG_l( PerlIO_printf(Perl_debug_log, "Leaving block %ld, type %s\n",		\
		    (long)cxstack_ix+1,PL_block_type[CxTYPE(cx)]); )
#define POPEVAL(cx)							\
    STMT_START {							\
	PL_in_eval = CxOLD_IN_EVAL(cx);					\
	optype = CxOLD_OP_TYPE(cx);					\
	PL_eval_root = cx->blk_eval.old_eval_root;			\
	if (cx->blk_eval.old_namesv)					\
	    sv_2mortal(cx->blk_eval.old_namesv);			\
    } STMT_END
#define POPFORMAT(cx)							\
	setdefout(cx->blk_format.dfoutgv);				\
	SvREFCNT_dec(cx->blk_format.dfoutgv);
#define POPLOOP(cx)							\
	if (CxTYPE(cx) == CXt_LOOP_LAZYSV) {				\
	    SvREFCNT_dec(cx->blk_loop.state_u.lazysv.cur);		\
	    SvREFCNT_dec(cx->blk_loop.state_u.lazysv.end);		\
	}								\
	if (CxTYPE(cx) == CXt_LOOP_FOR)					\
	    SvREFCNT_dec(cx->blk_loop.state_u.ary.ary);
#define POPSTACK \
    STMT_START {							\
	dSP;								\
	PERL_SI * const prev = PL_curstackinfo->si_prev;		\
	if (!prev) {							\
	    PerlIO_printf(Perl_error_log, "panic: POPSTACK\n");		\
	    my_exit(1);							\
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
#define POPSUB(cx,sv)							\
    STMT_START {							\
	RETURN_PROBE(GvENAME(CvGV((const CV*)cx->blk_sub.cv)),		\
		CopFILE((COP*)CvSTART((const CV*)cx->blk_sub.cv)),	\
		CopLINE((COP*)CvSTART((const CV*)cx->blk_sub.cv)));	\
									\
	if (CxHASARGS(cx)) {						\
	    POP_SAVEARRAY();						\
	    				\
	    if (AvREAL(cx->blk_sub.argarray)) {				\
		const SSize_t fill = AvFILLp(cx->blk_sub.argarray);	\
		SvREFCNT_dec(cx->blk_sub.argarray);			\
		cx->blk_sub.argarray = newAV();				\
		av_extend(cx->blk_sub.argarray, fill);			\
		AvREIFY_only(cx->blk_sub.argarray);			\
		CX_CURPAD_SV(cx->blk_sub, 0) = MUTABLE_SV(cx->blk_sub.argarray); \
	    }								\
	    else {							\
		CLEAR_ARGARRAY(cx->blk_sub.argarray);			\
	    }								\
	}								\
	sv = MUTABLE_SV(cx->blk_sub.cv);				\
	if (sv && (CvDEPTH((const CV*)sv) = cx->blk_sub.olddepth))	\
	    sv = NULL;						\
    } STMT_END
#  define POPSUBST(cx) cx = &cxstack[cxstack_ix--];			\
	rxres_free(&cx->sb_rxres);					\
	ReREFCNT_dec(cx->sb_rx)
#define POP_MULTICALL \
    STMT_START {							\
	LEAVESUB(multicall_cv);						\
	CvDEPTH(multicall_cv)--;					\
	POPBLOCK(cx,PL_curpm);						\
	POPSTACK;							\
	CATCH_SET(multicall_oldcatch);					\
	LEAVE;								\
	SPAGAIN;							\
    } STMT_END
#define POP_SAVEARRAY()						\
    STMT_START {							\
	SvREFCNT_dec(GvAV(PL_defgv));					\
	GvAV(PL_defgv) = cx->blk_sub.savearray;				\
    } STMT_END
#define PUSHBLOCK(cx,t,sp) CXINC, cx = &cxstack[cxstack_ix],		\
	cx->cx_type		= t,					\
	cx->blk_oldsp		= sp - PL_stack_base,			\
	cx->blk_oldcop		= PL_curcop,				\
	cx->blk_oldmarksp	= PL_markstack_ptr - PL_markstack,	\
	cx->blk_oldscopesp	= PL_scopestack_ix,			\
	cx->blk_oldpm		= PL_curpm,				\
	cx->blk_gimme		= (U8)gimme;				\
	DEBUG_l( PerlIO_printf(Perl_debug_log, "Entering block %ld, type %s\n",	\
		    (long)cxstack_ix, PL_block_type[CxTYPE(cx)]); )
#define PUSHEVAL(cx,n)							\
    STMT_START {							\
	assert(!(PL_in_eval & ~0x7F));					\
	assert(!(PL_op->op_type & ~0x1FF));				\
	cx->blk_u16 = (PL_in_eval & 0x7F) | ((U16)PL_op->op_type << 7);	\
	cx->blk_eval.old_namesv = (n ? newSVpv(n,0) : NULL);		\
	cx->blk_eval.old_eval_root = PL_eval_root;			\
	cx->blk_eval.cur_text = PL_parser ? PL_parser->linestr : NULL;	\
	cx->blk_eval.cv = NULL; 	\
	cx->blk_eval.retop = NULL;					\
	cx->blk_eval.cur_top_env = PL_top_env; 				\
    } STMT_END
#define PUSHFORMAT(cx, retop)						\
	cx->blk_format.cv = cv;						\
	cx->blk_format.gv = gv;						\
	cx->blk_format.retop = (retop);					\
	cx->blk_format.dfoutgv = PL_defoutgv;				\
	SvREFCNT_inc_void(cx->blk_format.dfoutgv)
#define PUSHGIVEN(cx)							\
	cx->blk_givwhen.leave_op = cLOGOP->op_other;
#define PUSHLOOP_FOR(cx, dat, s, offset)				\
	cx->blk_loop.resetsp = s - PL_stack_base;			\
	cx->blk_loop.my_op = cLOOP;					\
	PUSHLOOP_OP_NEXT;						\
	cx->blk_loop.state_u.ary.ary = NULL;				\
	cx->blk_loop.state_u.ary.ix = 0;				\
	CX_ITERDATA_SET(cx, dat, offset);
#define PUSHLOOP_PLAIN(cx, s)						\
	cx->blk_loop.resetsp = s - PL_stack_base;			\
	cx->blk_loop.my_op = cLOOP;					\
	PUSHLOOP_OP_NEXT;						\
	cx->blk_loop.state_u.ary.ary = NULL;				\
	cx->blk_loop.state_u.ary.ix = 0;				\
	CX_ITERDATA_SET(cx, NULL, 0);
#define PUSHSTACK PUSHSTACKi(PERLSI_UNKNOWN)
#define PUSHSTACKi(type) \
    STMT_START {							\
	PERL_SI *next = PL_curstackinfo->si_next;			\
	if (!next) {							\
	    next = new_stackinfo(32, 2048/sizeof(PERL_CONTEXT) - 1);	\
	    next->si_prev = PL_curstackinfo;				\
	    PL_curstackinfo->si_next = next;				\
	}								\
	next->si_type = type;						\
	next->si_cxix = -1;						\
	AvFILLp(next->si_stack) = 0;					\
	SWITCHSTACK(PL_curstack,next->si_stack);			\
	PL_curstackinfo = next;						\
	SET_MARK_OFFSET;						\
    } STMT_END
#define PUSHSUB(cx)							\
	PUSHSUB_BASE(cx)						\
	cx->blk_u16 = PL_op->op_private &				\
	                      (OPpLVAL_INTRO|OPpENTERSUB_INARGS);
#  define PUSHSUBST(cx) CXINC, cx = &cxstack[cxstack_ix],		\
	cx->sb_iters		= iters,				\
	cx->sb_maxiters		= maxiters,				\
	cx->sb_rflags		= r_flags,				\
	cx->sb_oldsave		= oldsave,				\
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
	(void)ReREFCNT_inc(rx)
#define PUSHSUB_BASE(cx)						\
	ENTRY_PROBE(GvENAME(CvGV(cv)),		       			\
		CopFILE((const COP *)CvSTART(cv)),			\
		CopLINE((const COP *)CvSTART(cv)));			\
									\
	cx->blk_sub.cv = cv;						\
	cx->blk_sub.olddepth = CvDEPTH(cv);				\
	cx->cx_type |= (hasargs) ? CXp_HASARGS : 0;			\
	cx->blk_sub.retop = NULL;					\
	if (!CvDEPTH(cv)) {						\
	    SvREFCNT_inc_simple_void_NN(cv);				\
	    SvREFCNT_inc_simple_void_NN(cv);				\
	    SAVEFREESV(cv);						\
	}
#define PUSHSUB_DB(cx)							\
	PUSHSUB_BASE(cx)						\
	cx->blk_u16 = 0;
#define PUSHWHEN PUSHGIVEN
#define PUSH_MULTICALL(the_cv) \
    STMT_START {							\
	CV * const _nOnclAshIngNamE_ = the_cv;				\
	CV * const cv = _nOnclAshIngNamE_;				\
	AV * const padlist = CvPADLIST(cv);				\
	ENTER;								\
 	multicall_oldcatch = CATCH_GET;					\
	SAVETMPS; SAVEVPTR(PL_op);					\
	CATCH_SET(TRUE);						\
	PUSHSTACKi(PERLSI_SORT);					\
	PUSHBLOCK(cx, CXt_SUB|CXp_MULTICALL, PL_stack_sp);		\
	PUSHSUB(cx);							\
	if (++CvDEPTH(cv) >= 2) {					\
	    PERL_STACK_OVERFLOW_CHECK();				\
	    Perl_pad_push(aTHX_ padlist, CvDEPTH(cv));			\
	}								\
	SAVECOMPPAD();							\
	PAD_SET_CUR_NOSAVE(padlist, CvDEPTH(cv));			\
	multicall_cv = cv;						\
	multicall_cop = CvSTART(cv);					\
    } STMT_END
#define TOPBLOCK(cx) cx  = &cxstack[cxstack_ix],			\
	PL_stack_sp	 = PL_stack_base + cx->blk_oldsp,		\
	PL_markstack_ptr = PL_markstack + cx->blk_oldmarksp,		\
	PL_scopestack_ix = cx->blk_oldscopesp,				\
	PL_curpm         = cx->blk_oldpm;				\
	DEBUG_SCOPE("TOPBLOCK");
#define cx_type cx_u.cx_subst.sbu_type
#define dMULTICALL \
    SV **newsp;						\
    PERL_CONTEXT *cx;							\
    CV *multicall_cv;							\
    OP *multicall_cop;							\
    bool multicall_oldcatch; 						\
    U8 hasargs = 0		
#  define ENTRY_PROBE(func, file, line) 	\
    if (PERL_SUB_ENTRY_ENABLED()) {		\
	PERL_SUB_ENTRY(func, file, line); 	\
    }
#  define RETURN_PROBE(func, file, line)	\
    if (PERL_SUB_RETURN_ENABLED()) {		\
	PERL_SUB_RETURN(func, file, line); 	\
    }
#define HEK_FLAGS(hek)	(*((unsigned char *)(HEK_KEY(hek))+HEK_LEN(hek)+1))
#define HEK_HASH(hek)		(hek)->hek_hash
#define HEK_KEY(hek)		(hek)->hek_key
#define HEK_LEN(hek)		(hek)->hek_len
#define HEK_REHASH(hek)		(HEK_FLAGS(hek) & HVhek_REHASH)
#define HEK_REHASH_on(hek)	(HEK_FLAGS(hek) |= HVhek_REHASH)
#define HEK_UTF8(hek)		(HEK_FLAGS(hek) & HVhek_UTF8)
#define HEK_UTF8_off(hek)	(HEK_FLAGS(hek) &= ~HVhek_UTF8)
#define HEK_UTF8_on(hek)	(HEK_FLAGS(hek) |= HVhek_UTF8)
#define HEK_WASUTF8(hek)	(HEK_FLAGS(hek) & HVhek_WASUTF8)
#define HEK_WASUTF8_off(hek)	(HEK_FLAGS(hek) &= ~HVhek_WASUTF8)
#define HEK_WASUTF8_on(hek)	(HEK_FLAGS(hek) |= HVhek_WASUTF8)
#define HVhek_KEYCANONICAL 0x400 
#define HVrhek_typemask 0x70
#define HeHASH(he)		HEK_HASH(HeKEY_hek(he))
#define HeKEY(he)		HEK_KEY(HeKEY_hek(he))
#define HeKEY_hek(he)		(he)->hent_hek
#define HeKEY_sv(he)		(*(SV**)HeKEY(he))
#define HeKFLAGS(he)  HEK_FLAGS(HeKEY_hek(he))
#define HeKLEN(he)		HEK_LEN(HeKEY_hek(he))
#define HeKLEN_UTF8(he)  (HeKUTF8(he) ? -HeKLEN(he) : HeKLEN(he))
#define HeKREHASH(he)  HEK_REHASH(HeKEY_hek(he))
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
						 HeKLEN(he), SVs_TEMP)) : \
				 &PL_sv_undef)
#define HeSVKEY_set(he,sv)	((HeKLEN(he) = HEf_SVKEY), (HeKEY_sv(he) = sv))
#define HeUTF8(he)		((HeKLEN(he) == HEf_SVKEY) ?		\
				 SvUTF8(HeKEY_sv(he)) :			\
				 (U32)HeKUTF8(he))
#define HeVAL(he)		(he)->he_valu.hent_val
#define HvARRAY(hv)	((hv)->sv_u.svu_hash)
#define HvAUX(hv)	((struct xpvhv_aux*)&(HvARRAY(hv)[HvMAX(hv)+1]))
#define HvEITER(hv)	(*Perl_hv_eiter_p(aTHX_ MUTABLE_HV(hv)))
#define HvEITER_get(hv)	(SvOOK(hv) ? HvAUX(hv)->xhv_eiter : NULL)
#define HvEITER_set(hv,e)	Perl_hv_eiter_set(aTHX_ MUTABLE_HV(hv), e)
#define HvFILL(hv)	((XPVHV*)  SvANY(hv))->xhv_fill
#define HvHASKFLAGS(hv)		(SvFLAGS(hv) & SVphv_HASKFLAGS)
#define HvHASKFLAGS_off(hv)	(SvFLAGS(hv) &= ~SVphv_HASKFLAGS)
#define HvHASKFLAGS_on(hv)	(SvFLAGS(hv) |= SVphv_HASKFLAGS)
#define HvKEYS(hv)		HvUSEDKEYS(hv)
#define HvLAZYDEL(hv)		(SvFLAGS(hv) & SVphv_LAZYDEL)
#define HvLAZYDEL_off(hv)	(SvFLAGS(hv) &= ~SVphv_LAZYDEL)
#define HvLAZYDEL_on(hv)	(SvFLAGS(hv) |= SVphv_LAZYDEL)
#define HvMAX(hv)	((XPVHV*)  SvANY(hv))->xhv_max
#define HvMROMETA(hv) (HvAUX(hv)->xhv_mro_meta \
                       ? HvAUX(hv)->xhv_mro_meta \
                       : Perl_mro_meta_init(aTHX_ hv))
#define HvNAME(hv)	HvNAME_get(hv)
#define HvNAMELEN_get(hv)	((SvOOK(hv) && (HvAUX(hv)->xhv_name)) \
				 ? HEK_LEN(HvAUX(hv)->xhv_name) : 0)
#define HvNAME_HEK(hv) (SvOOK(hv) ? HvAUX(hv)->xhv_name : NULL)
#define HvNAME_get(hv)	((SvOOK(hv) && (HvAUX(hv)->xhv_name)) \
			 ? HEK_KEY(HvAUX(hv)->xhv_name) : NULL)
#define HvPLACEHOLDERS(hv)	(*Perl_hv_placeholders_p(aTHX_ MUTABLE_HV(hv)))
#define HvPLACEHOLDERS_get(hv)	(SvMAGIC(hv) ? Perl_hv_placeholders_get(aTHX_ (const HV *)hv) : 0)
#define HvPLACEHOLDERS_set(hv,p)	Perl_hv_placeholders_set(aTHX_ MUTABLE_HV(hv), p)
#define HvREHASH(hv)		(SvFLAGS(hv) & SVphv_REHASH)
#define HvREHASH_off(hv)	(SvFLAGS(hv) &= ~SVphv_REHASH)
#define HvREHASH_on(hv)		(SvFLAGS(hv) |= SVphv_REHASH)
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
#define PERL_HASH(hash,str,len) \
     STMT_START	{ \
	register const char * const s_PeRlHaSh_tmp = str; \
	register const unsigned char *s_PeRlHaSh = (const unsigned char *)s_PeRlHaSh_tmp; \
	register I32 i_PeRlHaSh = len; \
	register U32 hash_PeRlHaSh = PERL_HASH_SEED; \
	while (i_PeRlHaSh--) { \
	    hash_PeRlHaSh += *s_PeRlHaSh++; \
	    hash_PeRlHaSh += (hash_PeRlHaSh << 10); \
	    hash_PeRlHaSh ^= (hash_PeRlHaSh >> 6); \
	} \
	hash_PeRlHaSh += (hash_PeRlHaSh << 3); \
	hash_PeRlHaSh ^= (hash_PeRlHaSh >> 11); \
	(hash) = (hash_PeRlHaSh + (hash_PeRlHaSh << 15)); \
    } STMT_END
#define PERL_HASH_INTERNAL(hash,str,len) \
     STMT_START	{ \
	register const char * const s_PeRlHaSh_tmp = str; \
	register const unsigned char *s_PeRlHaSh = (const unsigned char *)s_PeRlHaSh_tmp; \
	register I32 i_PeRlHaSh = len; \
	register U32 hash_PeRlHaSh = PL_rehash_seed; \
	while (i_PeRlHaSh--) { \
	    hash_PeRlHaSh += *s_PeRlHaSh++; \
	    hash_PeRlHaSh += (hash_PeRlHaSh << 10); \
	    hash_PeRlHaSh ^= (hash_PeRlHaSh >> 6); \
	} \
	hash_PeRlHaSh += (hash_PeRlHaSh << 3); \
	hash_PeRlHaSh ^= (hash_PeRlHaSh >> 11); \
	(hash) = (hash_PeRlHaSh + (hash_PeRlHaSh << 15)); \
    } STMT_END
#  define PERL_HV_ARRAY_ALLOC_BYTES(size) ((size) * sizeof(HE*))
#define Perl_sharepvn(sv, len, hash) HEK_KEY(share_hek(sv, len, hash))
#define REF_HE_KEY(chain)						\
	((((chain->refcounted_he_data[0] & 0x60) == 0x40)		\
	    ? chain->refcounted_he_val.refcounted_he_u_len + 1 : 0)	\
	 + 1 + chain->refcounted_he_data)
#define XHvTOTALKEYS(xhv)	((xhv)->xhv_keys)
#define hv_delete(hv, key, klen, flags)					\
    (MUTABLE_SV(hv_common_key_len((hv), (key), (klen),			\
				  (flags) | HV_DELETE, NULL, 0)))
#define hv_delete_ent(hv, key, flags, hash)				\
    (MUTABLE_SV(hv_common((hv), (key), NULL, 0, 0, (flags) | HV_DELETE,	\
			  NULL, (hash))))
#define hv_exists(hv, key, klen)					\
    (hv_common_key_len((hv), (key), (klen), HV_FETCH_ISEXISTS, NULL, 0) \
     ? TRUE : FALSE)
#define hv_exists_ent(hv, keysv, hash)					\
    (hv_common((hv), (keysv), NULL, 0, 0, HV_FETCH_ISEXISTS, 0, (hash))	\
     ? TRUE : FALSE)
#define hv_fetch(hv, key, klen, lval)					\
    ((SV**) hv_common_key_len((hv), (key), (klen), (lval)		\
			      ? (HV_FETCH_JUST_SV | HV_FETCH_LVALUE)	\
			      : HV_FETCH_JUST_SV, NULL, 0))
#define hv_fetch_ent(hv, keysv, lval, hash)				\
    ((HE *) hv_common((hv), (keysv), NULL, 0, 0,			\
		      ((lval) ? HV_FETCH_LVALUE : 0), NULL, (hash)))
#define hv_iternext(hv)	hv_iternext_flags(hv, 0)
#define hv_magic(hv, gv, how) sv_magic(MUTABLE_SV(hv), MUTABLE_SV(gv), how, NULL, 0)
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
#define newHV()	MUTABLE_HV(newSV_type(SVt_PVHV))
#define share_hek_hek(hek)						\
    (++(((struct shared_he *)(((char *)hek)				\
			      - STRUCT_OFFSET(struct shared_he,		\
					      shared_he_hek)))		\
	->shared_he_he.he_valu.hent_refcount),				\
     hek)
#define sharepvn(sv, len, hash)	     Perl_sharepvn(sv, len, hash)
#define xhv_keys xiv_u.xivu_iv
#define BASEOP BASEOP_DEFINITION
#define FreeOp(p) Perl_Slab_Free(aTHX_ p)
#define GIMME \
	  (PL_op->op_flags & OPf_WANT					\
	   ? ((PL_op->op_flags & OPf_WANT) == OPf_WANT_LIST		\
	      ? G_ARRAY							\
	      : G_SCALAR)						\
	   : dowantarray())
#  define MADPROP_IN_BASEOP
#  define MAD_NULL 1
#  define MAD_OP 3
#  define MAD_PV 2
#  define MAD_SV 4
#define NewOp(m,var,c,type)	\
	(var = (type *) Perl_Slab_Alloc(aTHX_ c*sizeof(type)))
#define NewOpSz(m,var,size)	\
	(var = (OP *) Perl_Slab_Alloc(aTHX_ size))
#  define Nullop ((OP*)NULL)
#define OASHIFT 13
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
#define OA_OPTIONAL 8
#define OA_OTHERINT 32
#define OA_PADOP (7 << OCSHIFT)
#define OA_PMOP (5 << OCSHIFT)
#define OA_PVOP_OR_SVOP (8 << OCSHIFT)
#define OA_RETINTEGER 16
#define OA_RETSCALAR 4
#define OA_SCALAR 1
#define OA_SCALARREF 7
#define OA_SVOP (6 << OCSHIFT)
#define OA_TARGET 8
#define OA_TARGLEX 256
#define OA_UNOP (1 << OCSHIFT)
#define OCSHIFT 9
#define OPCODE U16
#define OP_GIMME(op,dfl) \
	(((op)->op_flags & OPf_WANT) == OPf_WANT_VOID   ? G_VOID   : \
	 ((op)->op_flags & OPf_WANT) == OPf_WANT_SCALAR ? G_SCALAR : \
	 ((op)->op_flags & OPf_WANT) == OPf_WANT_LIST   ? G_ARRAY   : \
	 dfl)
#define OP_GIMME_REVERSE(flags)	((flags) & G_WANT)
#define  OPf_WANT_SCALAR 2	
#  define OpREFCNT_dec(o)		Perl_op_refcnt_dec(aTHX_ o)
#  define OpREFCNT_inc(o)		Perl_op_refcnt_inc(aTHX_ o)
#define OpREFCNT_set(o,n)		((o)->op_targ = (n))
#define PM_GETRE(o)	(SvTYPE(PL_regex_pad[(o)->op_pmoffset]) == SVt_REGEXP \
		 	 ? (REGEXP*)(PL_regex_pad[(o)->op_pmoffset]) : NULL)
#define PM_SETRE(o,r)	STMT_START {					\
                            REGEXP *const _pm_setre = (r);		\
                            assert(_pm_setre);				\
			    PL_regex_pad[(o)->op_pmoffset] = MUTABLE_SV(_pm_setre); \
                        } STMT_END
#define PMf_USED        0x00000400	
#  define PmopSTASH(o)		(PmopSTASHPV(o) \
				 ? gv_stashpv((o)->op_pmstashstartu.op_pmstashpv,GV_ADD) : NULL)
#  define PmopSTASHPV(o)						\
    (((o)->op_pmflags & PMf_ONCE) ? (o)->op_pmstashstartu.op_pmstashpv : NULL)
#    define PmopSTASHPV_set(o,pv)	({				\
	assert((o)->op_pmflags & PMf_ONCE);				\
	((o)->op_pmstashstartu.op_pmstashpv = savesharedpv(pv));	\
    })
#  define PmopSTASH_free(o)	PerlMemShared_free(PmopSTASHPV(o))
#    define PmopSTASH_set(o,hv)		({				\
	assert((o)->op_pmflags & PMf_ONCE);				\
	((o)->op_pmstashstartu.op_pmstash = (hv));			\
    })
#define cBINOPx(o)	((BINOP*)o)
#define cCOPx(o)	((COP*)o)
#define cLISTOPx(o)	((LISTOP*)o)
#define cLOGOPx(o)	((LOGOP*)o)
#define cLOOPx(o)	((LOOP*)o)
#define cPADOPx(o)	((PADOP*)o)
#define cPMOPx(o)	((PMOP*)o)
#define cPVOPx(o)	((PVOP*)o)
#define cSVOPx(o)	((SVOP*)o)
#define cUNOPx(o)	((UNOP*)o)
#define cv_ckproto(cv, gv, p) \
   cv_ckproto_len((cv), (gv), (p), (p) ? strlen(p) : 0)
#  define my(o)	my_attrs((o), NULL)
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
#       define asctime(a) asctime_r(a, PL_reentrant_buffer->_asctime_buffer)
#       define crypt(a, b) crypt_r(a, b, PL_reentrant_buffer->_crypt_struct_buffer)
#       define ctermid(a) ctermid_r(a)
#       define ctime(a) ctime_r(a, PL_reentrant_buffer->_ctime_buffer)
#       define drand48() (drand48_r(&PL_reentrant_buffer->_drand48_struct, &PL_reentrant_buffer->_drand48_double) == 0 ? PL_reentrant_buffer->_drand48_double : 0)
#       define endgrent() (endgrent_r(&PL_reentrant_buffer->_grent_fptr) == 0 ? 1 : 0)
#       define endhostent() (endhostent_r(&PL_reentrant_buffer->_hostent_data) == 0 ? 1 : 0)
#       define endnetent() (endnetent_r(&PL_reentrant_buffer->_netent_data) == 0 ? 1 : 0)
#       define endprotoent() (endprotoent_r(&PL_reentrant_buffer->_protoent_data) == 0 ? 1 : 0)
#       define endpwent() (endpwent_r(&PL_reentrant_buffer->_pwent_fptr) == 0 ? 1 : 0)
#       define endservent() (endservent_r(&PL_reentrant_buffer->_servent_data) == 0 ? 1 : 0)
#       define getgrent() ((PL_reentrant_retint = getgrent_r(&PL_reentrant_buffer->_grent_struct, PL_reentrant_buffer->_grent_buffer, PL_reentrant_buffer->_grent_size, &PL_reentrant_buffer->_grent_ptr)) == 0 ? PL_reentrant_buffer->_grent_ptr : ((PL_reentrant_retint == ERANGE) ? (struct group *) Perl_reentrant_retry("getgrent") : 0))
#       define getgrgid(a) ((PL_reentrant_retint = getgrgid_r(a, &PL_reentrant_buffer->_grent_struct, PL_reentrant_buffer->_grent_buffer, PL_reentrant_buffer->_grent_size, &PL_reentrant_buffer->_grent_ptr)) == 0 ? PL_reentrant_buffer->_grent_ptr : ((PL_reentrant_retint == ERANGE) ? (struct group *) Perl_reentrant_retry("getgrgid", a) : 0))
#       define getgrnam(a) ((PL_reentrant_retint = getgrnam_r(a, &PL_reentrant_buffer->_grent_struct, PL_reentrant_buffer->_grent_buffer, PL_reentrant_buffer->_grent_size, &PL_reentrant_buffer->_grent_ptr)) == 0 ? PL_reentrant_buffer->_grent_ptr : ((PL_reentrant_retint == ERANGE) ? (struct group *) Perl_reentrant_retry("getgrnam", a) : 0))
#       define gethostbyaddr(a, b, c) (gethostbyaddr_r(a, b, c, &PL_reentrant_buffer->_hostent_struct, PL_reentrant_buffer->_hostent_buffer, PL_reentrant_buffer->_hostent_size, &PL_reentrant_buffer->_hostent_errno) ? &PL_reentrant_buffer->_hostent_struct : ((errno == ERANGE) ? (struct hostent *) Perl_reentrant_retry("gethostbyaddr", a, b, c) : 0))
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
#       define random() (random_r(&PL_reentrant_buffer->_random_retval, &PL_reentrant_buffer->_random_struct) == 0 ? PL_reentrant_buffer->_random_retval : 0)
#       define readdir(a) (readdir_r(a, PL_reentrant_buffer->_readdir_struct, &PL_reentrant_buffer->_readdir_ptr) == 0 ? PL_reentrant_buffer->_readdir_ptr : 0)
#       define readdir64(a) (readdir64_r(a, PL_reentrant_buffer->_readdir64_struct, &PL_reentrant_buffer->_readdir64_ptr) == 0 ? PL_reentrant_buffer->_readdir64_ptr : 0)
#       define setgrent() (setgrent_r(&PL_reentrant_buffer->_grent_fptr) == 0 ? 1 : 0)
#       define sethostent(a) (sethostent_r(a, &PL_reentrant_buffer->_hostent_data) == 0 ? 1 : 0)
#       define setlocale(a, b) (setlocale_r(a, b, PL_reentrant_buffer->_setlocale_buffer, PL_reentrant_buffer->_setlocale_size) == 0 ? PL_reentrant_buffer->_setlocale_buffer : 0)
#       define setnetent(a) (setnetent_r(a, &PL_reentrant_buffer->_netent_data) == 0 ? 1 : 0)
#       define setprotoent(a) (setprotoent_r(a, &PL_reentrant_buffer->_protoent_data) == 0 ? 1 : 0)
#       define setpwent() (setpwent_r(&PL_reentrant_buffer->_pwent_fptr) == 0 ? 1 : 0)
#       define setservent(a) (setservent_r(a, &PL_reentrant_buffer->_servent_data) == 0 ? 1 : 0)
#       define srand48(a) (srand48_r(a, &PL_reentrant_buffer->_drand48_struct) == 0 ? &PL_reentrant_buffer->_drand48_struct : 0)
#       define srandom(a) (srandom_r(a, &PL_reentrant_buffer->_srandom_struct) == 0 ? &PL_reentrant_buffer->_srandom_struct : 0)
#       define strerror(a) (strerror_r(a, PL_reentrant_buffer->_strerror_buffer, PL_reentrant_buffer->_strerror_size) == 0 ? PL_reentrant_buffer->_strerror_buffer : 0)
#       define tmpnam(a) tmpnam_r(a)
#       define ttyname(a) (ttyname_r(a, PL_reentrant_buffer->_ttyname_buffer, PL_reentrant_buffer->_ttyname_size) == 0 ? PL_reentrant_buffer->_ttyname_buffer : 0)
#define MAXO 366
#define OP_IS_FILETEST(op)	\
	((op) >= OP_FTRREAD && (op) <= OP_FTBINARY)
#define OP_IS_FILETEST_ACCESS(op)	\
	((op) >= OP_FTRREAD && (op) <= OP_FTEEXEC)
#define OP_IS_SOCKET(op)	\
	((op) >= OP_SEND && (op) <= OP_GETPEERNAME)
#define OP_phoney_INPUT_ONLY -1
#define OP_phoney_OUTPUT_ONLY -2
#define CvANON(cv)		(CvFLAGS(cv) & CVf_ANON)
#define CvANON_off(cv)		(CvFLAGS(cv) &= ~CVf_ANON)
#define CvANON_on(cv)		(CvFLAGS(cv) |= CVf_ANON)
#define CvCLONE(cv)		(CvFLAGS(cv) & CVf_CLONE)
#define CvCLONED(cv)		(CvFLAGS(cv) & CVf_CLONED)
#define CvCLONED_off(cv)	(CvFLAGS(cv) &= ~CVf_CLONED)
#define CvCLONED_on(cv)		(CvFLAGS(cv) |= CVf_CLONED)
#define CvCLONE_off(cv)		(CvFLAGS(cv) &= ~CVf_CLONE)
#define CvCLONE_on(cv)		(CvFLAGS(cv) |= CVf_CLONE)
#define CvCONST(cv)		(CvFLAGS(cv) & CVf_CONST)
#define CvCONST_off(cv)		(CvFLAGS(cv) &= ~CVf_CONST)
#define CvCONST_on(cv)		(CvFLAGS(cv) |= CVf_CONST)
#  define CvDEPTH(sv) (*({const CV *const _cvdepth = (const CV *)sv; \
			  assert(SvTYPE(_cvdepth) == SVt_PVCV);	 \
			  &((XPVCV*)SvANY(_cvdepth))->xiv_u.xivu_i32; \
			}))
#define CvEVAL(cv)		(CvUNIQUE(cv) && !SvFAKE(cv))
#define CvEVAL_off(cv)		CvUNIQUE_off(cv)
#define CvEVAL_on(cv)		(CvUNIQUE_on(cv),SvFAKE_off(cv))
#define CvFILE(sv)	((XPVCV*)MUTABLE_PTR(SvANY(sv)))->xcv_file
#define CvFILEGV(sv)	(gv_fetchfile(CvFILE(sv)))
#  define CvFILE_set_from_cop(sv, cop)	(CvFILE(sv) = savepv(CopFILE(cop)))
#define CvFLAGS(sv)	((XPVCV*)MUTABLE_PTR(SvANY(sv)))->xcv_flags
#define CvGV(sv)	((XPVCV*)MUTABLE_PTR(SvANY(sv)))->xcv_gv
#define CvISXSUB(cv)		(CvFLAGS(cv) & CVf_ISXSUB)
#define CvISXSUB_off(cv)	(CvFLAGS(cv) &= ~CVf_ISXSUB)
#define CvISXSUB_on(cv)		(CvFLAGS(cv) |= CVf_ISXSUB)
#define CvLVALUE(cv)		(CvFLAGS(cv) & CVf_LVALUE)
#define CvLVALUE_off(cv)	(CvFLAGS(cv) &= ~CVf_LVALUE)
#define CvLVALUE_on(cv)		(CvFLAGS(cv) |= CVf_LVALUE)
#define CvMETHOD(cv)		(CvFLAGS(cv) & CVf_METHOD)
#define CvMETHOD_off(cv)	(CvFLAGS(cv) &= ~CVf_METHOD)
#define CvMETHOD_on(cv)		(CvFLAGS(cv) |= CVf_METHOD)
#define CvNODEBUG(cv)		(CvFLAGS(cv) & CVf_NODEBUG)
#define CvNODEBUG_off(cv)	(CvFLAGS(cv) &= ~CVf_NODEBUG)
#define CvNODEBUG_on(cv)	(CvFLAGS(cv) |= CVf_NODEBUG)
#define CvOUTSIDE(sv)	((XPVCV*)MUTABLE_PTR(SvANY(sv)))->xcv_outside
#define CvOUTSIDE_SEQ(sv) ((XPVCV*)MUTABLE_PTR(SvANY(sv)))->xcv_outside_seq
#define CvPADLIST(sv)	((XPVCV*)MUTABLE_PTR(SvANY(sv)))->xcv_padlist
#define CvROOT(sv)	((XPVCV*)MUTABLE_PTR(SvANY(sv)))->xcv_root_u.xcv_root
#define CvSPECIAL(cv)		(CvUNIQUE(cv) && SvFAKE(cv))
#define CvSPECIAL_off(cv)	(CvUNIQUE_off(cv),SvFAKE_off(cv))
#define CvSPECIAL_on(cv)	(CvUNIQUE_on(cv),SvFAKE_on(cv))
#define CvSTART(sv)	((XPVCV*)MUTABLE_PTR(SvANY(sv)))->xcv_start_u.xcv_start
#define CvSTASH(sv)	((XPVCV*)MUTABLE_PTR(SvANY(sv)))->xcv_stash
#define CvUNIQUE(cv)		(CvFLAGS(cv) & CVf_UNIQUE)
#define CvUNIQUE_off(cv)	(CvFLAGS(cv) &= ~CVf_UNIQUE)
#define CvUNIQUE_on(cv)		(CvFLAGS(cv) |= CVf_UNIQUE)
#define CvWEAKOUTSIDE(cv)	(CvFLAGS(cv) & CVf_WEAKOUTSIDE)
#define CvWEAKOUTSIDE_off(cv)	(CvFLAGS(cv) &= ~CVf_WEAKOUTSIDE)
#define CvWEAKOUTSIDE_on(cv)	(CvFLAGS(cv) |= CVf_WEAKOUTSIDE)
#define CvXSUB(sv)	((XPVCV*)MUTABLE_PTR(SvANY(sv)))->xcv_root_u.xcv_xsub
#define CvXSUBANY(sv)	((XPVCV*)MUTABLE_PTR(SvANY(sv)))->xcv_start_u.xcv_xsubany
#  define Nullcv Null(CV*)
#  define ASSERT_CURPAD_ACTIVE(label) \
    pad_peg(label); \
    if (!PL_comppad || (AvARRAY(PL_comppad) != PL_curpad))		  \
	Perl_croak(aTHX_ "panic: invalid pad in %s: 0x%"UVxf"[0x%"UVxf"]",\
	    label, PTR2UV(PL_comppad), PTR2UV(PL_curpad));
#  define ASSERT_CURPAD_LEGAL(label) \
    pad_peg(label); \
    if (PL_comppad ? (AvARRAY(PL_comppad) != PL_curpad) : (PL_curpad != 0))  \
	Perl_croak(aTHX_ "panic: illegal pad in %s: 0x%"UVxf"[0x%"UVxf"]",\
	    label, PTR2UV(PL_comppad), PTR2UV(PL_curpad));
#  define COP_SEQ_RANGE_HIGH(sv)					\
	(({ const SV *const _sv_cop_seq_range_high = (const SV *) (sv);	\
	  assert(SvTYPE(_sv_cop_seq_range_high) == SVt_NV 		\
                 || SvTYPE(_sv_cop_seq_range_high) >= SVt_PVNV);	\
	  assert(SvTYPE(_sv_cop_seq_range_high) != SVt_PVAV);		\
	  assert(SvTYPE(_sv_cop_seq_range_high) != SVt_PVHV);		\
	  assert(SvTYPE(_sv_cop_seq_range_high) != SVt_PVCV);		\
	  assert(SvTYPE(_sv_cop_seq_range_high) != SVt_PVFM);		\
	  assert(!isGV_with_GP(_sv_cop_seq_range_high));		\
	  ((XPVNV*) MUTABLE_PTR(SvANY(_sv_cop_seq_range_high)))->xnv_u.xpad_cop_seq.xhigh; \
	 }))
#  define COP_SEQ_RANGE_LOW(sv)						\
	(({ const SV *const _sv_cop_seq_range_low = (const SV *) (sv);	\
	  assert(SvTYPE(_sv_cop_seq_range_low) == SVt_NV		\
		 || SvTYPE(_sv_cop_seq_range_low) >= SVt_PVNV);		\
	  assert(SvTYPE(_sv_cop_seq_range_low) != SVt_PVAV);		\
	  assert(SvTYPE(_sv_cop_seq_range_low) != SVt_PVHV);		\
	  assert(SvTYPE(_sv_cop_seq_range_low) != SVt_PVCV);		\
	  assert(SvTYPE(_sv_cop_seq_range_low) != SVt_PVFM);		\
	  assert(!isGV_with_GP(_sv_cop_seq_range_low));			\
	  ((XPVNV*) MUTABLE_PTR(SvANY(_sv_cop_seq_range_low)))->xnv_u.xpad_cop_seq.xlow; \
	 }))
#define CX_CURPAD_SAVE(block)  (block).oldcomppad = PL_comppad
#define CX_CURPAD_SV(block,po) (AvARRAY(MUTABLE_AV(((block).oldcomppad)))[po])
#define NOT_IN_PAD ((PADOFFSET) -1)
#define PAD_BASE_SV(padlist, po) \
	(AvARRAY(padlist)[1]) 	\
	? AvARRAY(MUTABLE_AV((AvARRAY(padlist)[1])))[po] : NULL;
#define PAD_CLONE_VARS(proto_perl, param)				\
    PL_comppad = MUTABLE_AV(ptr_table_fetch(PL_ptr_table, proto_perl->Icomppad)); \
    PL_curpad = PL_comppad ?  AvARRAY(PL_comppad) : NULL;		\
    PL_comppad_name		= av_dup(proto_perl->Icomppad_name, param); \
    PL_comppad_name_fill	= proto_perl->Icomppad_name_fill;	\
    PL_comppad_name_floor	= proto_perl->Icomppad_name_floor;	\
    PL_min_intro_pending	= proto_perl->Imin_intro_pending;	\
    PL_max_intro_pending	= proto_perl->Imax_intro_pending;	\
    PL_padix			= proto_perl->Ipadix;			\
    PL_padix_floor		= proto_perl->Ipadix_floor;		\
    PL_pad_reset_pending	= proto_perl->Ipad_reset_pending;	\
    PL_cop_seqmax		= proto_perl->Icop_seqmax;
#define PAD_COMPNAME_FLAGS(po) SvFLAGS(PAD_COMPNAME_SV(po))
#define PAD_COMPNAME_FLAGS_isOUR(po) \
  ((PAD_COMPNAME_FLAGS(po) & (SVpad_NAME|SVpad_OUR)) == (SVpad_NAME|SVpad_OUR))
#define PAD_COMPNAME_GEN(po) ((STRLEN)SvUVX(AvARRAY(PL_comppad_name)[po]))
#define PAD_COMPNAME_GEN_set(po, gen) SvUV_set(AvARRAY(PL_comppad_name)[po], (UV)(gen))
#define PAD_COMPNAME_OURSTASH(po) \
    (SvOURSTASH(PAD_COMPNAME_SV(po)))
#define PAD_COMPNAME_PV(po) SvPV_nolen(PAD_COMPNAME_SV(po))
#define PAD_COMPNAME_SV(po) (*av_fetch(PL_comppad_name, (po), FALSE))
#define PAD_COMPNAME_TYPE(po) pad_compname_type(po)
#define PAD_DUP(dstpad, srcpad, param)				\
    if ((srcpad) && !AvREAL(srcpad)) {				\
	 	\
	AvREAL_on(srcpad);					\
	(dstpad) = av_dup_inc((srcpad), param);			\
	AvREAL_off(srcpad);					\
	AvREAL_off(dstpad);					\
    }								\
    else							\
	(dstpad) = av_dup_inc((srcpad), param);			
#define PAD_FAKELEX_ANON   1 
#define PAD_FAKELEX_MULTI  2 
#define PAD_RESTORE_LOCAL(opad) \
        assert(!opad || !SvIS_FREED(opad));					\
	PL_comppad = opad;						\
	PL_curpad =  PL_comppad ? AvARRAY(PL_comppad) : NULL;	\
	DEBUG_Xv(PerlIO_printf(Perl_debug_log,			\
	      "Pad 0x%"UVxf"[0x%"UVxf"] restore_local\n",	\
	      PTR2UV(PL_comppad), PTR2UV(PL_curpad)));
#define PAD_SAVE_LOCAL(opad,npad) \
	opad = PL_comppad;					\
	PL_comppad = (npad);					\
	PL_curpad =  PL_comppad ? AvARRAY(PL_comppad) : NULL;	\
	DEBUG_Xv(PerlIO_printf(Perl_debug_log,			\
	      "Pad 0x%"UVxf"[0x%"UVxf"] save_local\n",		\
	      PTR2UV(PL_comppad), PTR2UV(PL_curpad)));
#define PAD_SAVE_SETNULLPAD()	SAVECOMPPAD(); \
	PL_comppad = NULL; PL_curpad = NULL;	\
	DEBUG_Xv(PerlIO_printf(Perl_debug_log, "Pad set_null\n"));
#  define PAD_SETSV(po,sv) pad_setsv(po,sv)
#define PAD_SET_CUR(padlist,nth) \
	SAVECOMPPAD();						\
	PAD_SET_CUR_NOSAVE(padlist,nth);
#define PAD_SET_CUR_NOSAVE(padlist,nth) \
	PL_comppad = (PAD*) (AvARRAY(padlist)[nth]);		\
	PL_curpad = AvARRAY(PL_comppad);			\
	DEBUG_Xv(PerlIO_printf(Perl_debug_log,			\
	      "Pad 0x%"UVxf"[0x%"UVxf"] set_cur    depth=%d\n",	\
	      PTR2UV(PL_comppad), PTR2UV(PL_curpad), (int)(nth)));
#  define PAD_SV(po)	   pad_sv(po)
#define PAD_SVl(po)       (PL_curpad[po])
#  define PARENT_FAKELEX_FLAGS(sv)					\
	(({ const SV *const _sv_parent_fakelex_flags = (const SV *) (sv); \
	  assert(SvTYPE(_sv_parent_fakelex_flags) == SVt_NV  		\
		 || SvTYPE(_sv_parent_fakelex_flags) >= SVt_PVNV);	\
	  assert(SvTYPE(_sv_parent_fakelex_flags) != SVt_PVAV);		\
	  assert(SvTYPE(_sv_parent_fakelex_flags) != SVt_PVHV);		\
	  assert(SvTYPE(_sv_parent_fakelex_flags) != SVt_PVCV);		\
	  assert(SvTYPE(_sv_parent_fakelex_flags) != SVt_PVFM);		\
	  assert(!isGV_with_GP(_sv_parent_fakelex_flags));		\
	  ((XPVNV*) MUTABLE_PTR(SvANY(_sv_parent_fakelex_flags)))->xnv_u.xpad_cop_seq.xhigh; \
	 }))
#  define PARENT_PAD_INDEX(sv)						\
	(({ const SV *const _sv_parent_pad_index = (const SV *) (sv);	\
	  assert(SvTYPE(_sv_parent_pad_index) == SVt_NV			\
		 || SvTYPE(_sv_parent_pad_index) >= SVt_PVNV);		\
	  assert(SvTYPE(_sv_parent_pad_index) != SVt_PVAV);		\
	  assert(SvTYPE(_sv_parent_pad_index) != SVt_PVHV);		\
	  assert(SvTYPE(_sv_parent_pad_index) != SVt_PVCV);		\
	  assert(SvTYPE(_sv_parent_pad_index) != SVt_PVFM);		\
	  assert(!isGV_with_GP(_sv_parent_pad_index));			\
	  ((XPVNV*) MUTABLE_PTR(SvANY(_sv_parent_pad_index)))->xnv_u.xpad_cop_seq.xlow; \
	 }))
#  define pad_peg(label)
#define DM_ARRAY 0x004
#define DM_DELAY 0x100
#define DM_EGID   0x020
#define DM_EUID   0x002
#define DM_GID   0x030
#define DM_RGID   0x010
#define DM_RUID   0x001
#define DM_UID   0x003
#define GvASSUMECV(gv)		(GvFLAGS(gv) & GVf_ASSUMECV)
#define GvASSUMECV_off(gv)	(GvFLAGS(gv) &= ~GVf_ASSUMECV)
#define GvASSUMECV_on(gv)	(GvFLAGS(gv) |= GVf_ASSUMECV)
#define GvAV(gv)	(GvGP(gv)->gp_av)
#define GvAVn(gv)	(GvGP(gv)->gp_av ? \
			 GvGP(gv)->gp_av : \
			 GvGP(gv_AVadd(gv))->gp_av)
#define GvCV(gv)	(GvGP(gv)->gp_cv)
#define GvCVGEN(gv)	(GvGP(gv)->gp_cvgen)
#define GvCVu(gv)	(GvGP(gv)->gp_cvgen ? NULL : GvGP(gv)->gp_cv)
#define GvEGV(gv)	(GvGP(gv)->gp_egv)
#define GvENAME(gv)	GvNAME(GvEGV(gv) ? GvEGV(gv) : gv)
#define GvESTASH(gv)	GvSTASH(GvEGV(gv) ? GvEGV(gv) : gv)
#define GvFILE(gv)	(GvFILE_HEK(gv) ? HEK_KEY(GvFILE_HEK(gv)) : NULL)
#define GvFILEGV(gv)	(gv_fetchfile(GvFILE(gv)))
#define GvFILE_HEK(gv)	(GvGP(gv)->gp_file_hek)
#  define GvFLAGS(gv)							\
	(*({GV *const _gvflags = (GV *) (gv);				\
	    assert(SvTYPE(_gvflags) == SVt_PVGV || SvTYPE(_gvflags) == SVt_PVLV); \
	    assert(isGV_with_GP(_gvflags));				\
	    &(GvXPVGV(_gvflags)->xpv_cur);}))
#define GvFORM(gv)	(GvGP(gv)->gp_form)
#  define GvGP(gv)							\
	(*({GV *const _gvgp = (GV *) (gv);				\
	    assert(SvTYPE(_gvgp) == SVt_PVGV || SvTYPE(_gvgp) == SVt_PVLV); \
	    assert(isGV_with_GP(_gvgp));				\
	    &((_gvgp)->sv_u.svu_gp);}))
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
#define GvIN_PAD(gv)		(GvFLAGS(gv) & GVf_IN_PAD)
#define GvIN_PAD_off(gv)	(GvFLAGS(gv) &= ~GVf_IN_PAD)
#define GvIN_PAD_on(gv)		(GvFLAGS(gv) |= GVf_IN_PAD)
#define GvIO(gv)	((gv) && SvTYPE((const SV*)gv) == SVt_PVGV && GvGP(gv) ? GvIOp(gv) : NULL)
#define GvIOn(gv)	(GvIO(gv) ? GvIOp(gv) : GvIOp(gv_IOadd(gv)))
#define GvIOp(gv)	(GvGP(gv)->gp_io)
#define GvLINE(gv)	(GvGP(gv)->gp_line)
#define GvMULTI(gv)		(GvFLAGS(gv) & GVf_MULTI)
#define GvMULTI_off(gv)		(GvFLAGS(gv) &= ~GVf_MULTI)
#define GvMULTI_on(gv)		(GvFLAGS(gv) |= GVf_MULTI)
#define GvNAME(gv)	GvNAME_get(gv)
#define GvNAMELEN(gv)	GvNAMELEN_get(gv)
#  define GvNAMELEN_get(gv)	({ assert(GvNAME_HEK(gv)); HEK_LEN(GvNAME_HEK(gv)); })
#  define GvNAME_HEK(gv)						\
    (*({ GV * const _gvname_hek = (GV *) (gv);				\
	   assert(isGV_with_GP(_gvname_hek));				\
	   assert(SvTYPE(_gvname_hek) == SVt_PVGV || SvTYPE(_gvname_hek) >= SVt_PVLV); \
	   assert(!SvVALID(_gvname_hek));				\
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
#define GvSVn(gv)	(*(GvGP(gv)->gp_sv ? \
			 &(GvGP(gv)->gp_sv) : \
			 &(GvGP(gv_SVadd(gv))->gp_sv)))
#define GvXPVGV(gv)	((XPVGV*)SvANY(gv))
#  define Nullgv Null(GV*)
#define gv_AVadd(gv) gv_add_by_type((gv), SVt_PVAV)
#define gv_HVadd(gv) gv_add_by_type((gv), SVt_PVHV)
#define gv_IOadd(gv) gv_add_by_type((gv), SVt_PVIO)
#define gv_SVadd(gv) gv_add_by_type((gv), SVt_NULL)
#define gv_efullname3(sv,gv,prefix) gv_efullname4(sv,gv,prefix,TRUE)
#define gv_fetchmethod(stash, name) gv_fetchmethod_autoload(stash, name, TRUE)
#define gv_fullname3(sv,gv,prefix) gv_fullname4(sv,gv,prefix,TRUE)
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
#      define PERL_FILE_IS_ABSOLUTE(f) \
	(*(f) == '/'							\
	 || ((f)[0] && (f)[1] == ':'))		
#define CASE_STD_PMMOD_FLAGS_PARSE_SET(pmfl)                        \
    case IGNORE_PAT_MOD:    *(pmfl) |= RXf_PMf_FOLD;       break;   \
    case MULTILINE_PAT_MOD: *(pmfl) |= RXf_PMf_MULTILINE;  break;   \
    case SINGLE_PAT_MOD:    *(pmfl) |= RXf_PMf_SINGLELINE; break;   \
    case XTENDED_PAT_MOD:   *(pmfl) |= RXf_PMf_EXTENDED;   break
#define CONTINUE_PAT_MOD     'c'
#define EXEC_PAT_MOD         'e'
#define EXEC_PAT_MODS        "e"
#define EXT_PAT_MODS    ONCE_PAT_MODS   KEEPCOPY_PAT_MODS
#define GLOBAL_PAT_MOD       'g'
#define IGNORE_PAT_MOD       'i'
#define INT_PAT_MODS    STD_PAT_MODS    KEEPCOPY_PAT_MODS
#define KEEPCOPY_PAT_MOD     'p'
#define KEEPCOPY_PAT_MODS    "p"
#define LOOP_PAT_MODS        "gc"
#define MAX_RECURSE_EVAL_NOCHANGE_DEPTH 1000
#define MULTILINE_PAT_MOD    'm'
#define M_PAT_MODS      QR_PAT_MODS     LOOP_PAT_MODS
#define ONCE_PAT_MOD         'o'
#define ONCE_PAT_MODS        "o"
#define PERL_REGMATCH_SLAB_SLOTS \
    ((4096 - 3 * sizeof (void*)) / sizeof(regmatch_state))
#define QR_PAT_MODS     STD_PAT_MODS    EXT_PAT_MODS
#define RX_BUFF_IDX_FULLMATCH      0 
#define RX_BUFF_IDX_POSTMATCH -1 
#define RX_BUFF_IDX_PREMATCH  -2 
#define RX_CHECK_SUBSTR(prog)	(((struct regexp *)SvANY(prog))->check_substr)
#  define RX_ENGINE(prog)						\
    (*({								\
	const REGEXP *const _rx_engine = (prog);			\
	assert(SvTYPE(_rx_engine) == SVt_REGEXP);			\
	&SvANY(_rx_engine)->engine;					\
    }))
#  define RX_EXTFLAGS(prog)						\
    (*({								\
	const REGEXP *const _rx_extflags = (prog);			\
	assert(SvTYPE(_rx_extflags) == SVt_REGEXP);			\
	&RXp_EXTFLAGS(SvANY(_rx_extflags));				\
    }))
#define RX_GOFS(prog)		(((struct regexp *)SvANY(prog))->gofs)
#define RX_HAS_CUTGROUP(prog) ((prog)->intflags & PREGf_CUTGROUP_SEEN)
#define RX_LASTCLOSEPAREN(prog)	(((struct regexp *)SvANY(prog))->lastcloseparen)
#define RX_LASTPAREN(prog)	(((struct regexp *)SvANY(prog))->lastparen)
#define RX_MATCH_COPIED(prog)		(RX_EXTFLAGS(prog) & RXf_COPY_DONE)
#define RX_MATCH_COPIED_off(prog)	(RX_EXTFLAGS(prog) &= ~RXf_COPY_DONE)
#define RX_MATCH_COPIED_on(prog)	(RX_EXTFLAGS(prog) |= RXf_COPY_DONE)
#define RX_MATCH_COPIED_set(prog,t)	((t) \
					 ? RX_MATCH_COPIED_on(prog) \
					 : RX_MATCH_COPIED_off(prog))
#define RX_MATCH_COPY_FREE(rx) \
	STMT_START {if (RX_SAVED_COPY(rx)) { \
	    SV_CHECK_THINKFIRST_COW_DROP(RX_SAVED_COPY(rx)); \
	} \
	if (RX_MATCH_COPIED(rx)) { \
	    Safefree(RX_SUBBEG(rx)); \
	    RX_MATCH_COPIED_off(rx); \
	}} STMT_END
#define RX_MATCH_TAINTED(prog)	(RX_EXTFLAGS(prog) & RXf_TAINTED_SEEN)
#define RX_MATCH_TAINTED_off(prog) (RX_EXTFLAGS(prog) &= ~RXf_TAINTED_SEEN)
#define RX_MATCH_TAINTED_on(prog) (RX_EXTFLAGS(prog) |= RXf_TAINTED_SEEN)
#define RX_MATCH_TAINTED_set(prog, t) ((t) \
				       ? RX_MATCH_TAINTED_on(prog) \
				       : RX_MATCH_TAINTED_off(prog))
#define RX_MATCH_UTF8(prog)		(RX_EXTFLAGS(prog) & RXf_MATCH_UTF8)
#define RX_MATCH_UTF8_off(prog)		(RX_EXTFLAGS(prog) &= ~RXf_MATCH_UTF8)
#define RX_MATCH_UTF8_on(prog)		(RX_EXTFLAGS(prog) |= RXf_MATCH_UTF8)
#define RX_MATCH_UTF8_set(prog, t)	((t) \
			? (RX_MATCH_UTF8_on(prog), (PL_reg_match_utf8 = 1)) \
			: (RX_MATCH_UTF8_off(prog), (PL_reg_match_utf8 = 0)))
#define RX_MINLEN(prog)		(((struct regexp *)SvANY(prog))->minlen)
#define RX_MINLENRET(prog)	(((struct regexp *)SvANY(prog))->minlenret)
#  define RX_NPARENS(prog)						\
    (*({								\
	const REGEXP *const _rx_nparens = (prog);			\
	assert(SvTYPE(_rx_nparens) == SVt_REGEXP);			\
	&SvANY(_rx_nparens)->nparens;					\
    }))
#  define RX_OFFS(prog)							\
    (*({								\
	const REGEXP *const _rx_offs = (prog);				\
	assert(SvTYPE(_rx_offs) == SVt_REGEXP);				\
	&SvANY(_rx_offs)->offs;						\
    }))
#define RX_PRECOMP(prog)	(RX_WRAPPED(prog) + ((struct regexp *)SvANY(prog))->pre_prefix)
#define RX_PRECOMP_const(prog)	(RX_WRAPPED_const(prog) + ((struct regexp *)SvANY(prog))->pre_prefix)
#define RX_PRELEN(prog)		(RX_WRAPLEN(prog) - ((struct regexp *)SvANY(prog))->pre_prefix - 1)
#define RX_REFCNT(prog)		SvREFCNT(prog)
#define RX_SAVED_COPY(prog)	(((struct regexp *)SvANY(prog))->saved_copy)
#define RX_SEEN_EVALS(prog)	(((struct regexp *)SvANY(prog))->seen_evals)
#  define RX_SUBBEG(prog)						\
    (*({								\
	const REGEXP *const _rx_subbeg = (prog);			\
	assert(SvTYPE(_rx_subbeg) == SVt_REGEXP);			\
	&SvANY(_rx_subbeg)->subbeg;					\
    }))
#define RX_SUBLEN(prog)		(((struct regexp *)SvANY(prog))->sublen)
#define RX_UTF8(prog)			SvUTF8(prog)
#define RX_WRAPLEN(prog)	SvCUR(prog)
#define RX_WRAPPED(prog)	SvPVX(prog)
#define RX_WRAPPED_const(prog)	SvPVX_const(prog)
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
#define RXf_ANCH        	(RXf_ANCH_BOL|RXf_ANCH_MBOL|RXf_ANCH_GPOS|RXf_ANCH_SBOL)
#define RXf_ANCH_BOL    	0x00000100
#define RXf_ANCH_GPOS   	0x00000800
#define RXf_ANCH_MBOL   	0x00000200
#define RXf_ANCH_SBOL   	0x00000400
#define RXf_ANCH_SINGLE         (RXf_ANCH_SBOL|RXf_ANCH_GPOS)
#define RXf_CANY_SEEN   	0x00010000
#define RXf_CHECK_ALL   	0x00040000
#define RXf_COPY_DONE   	0x02000000
#define RXf_EVAL_SEEN   	0x00008000
#define RXf_GPOS_CHECK          (RXf_GPOS_SEEN|RXf_ANCH_GPOS)
#define RXf_GPOS_FLOAT  	0x00002000
#define RXf_GPOS_SEEN   	0x00001000
#define RXf_INTUIT_TAIL 	0x00800000
#define RXf_MATCH_UTF8  	0x00100000
#define RXf_NOSCAN      	0x00020000
#define RXf_PMf_FOLD    	0x00000004 
#define RXf_PMf_LOCALE  	0x00000020 
#define RXp_EXTFLAGS(rx)	((rx)->extflags)
#define RXp_MATCH_COPIED(prog)		(RXp_EXTFLAGS(prog) & RXf_COPY_DONE)
#define RXp_MATCH_COPIED_off(prog)	(RXp_EXTFLAGS(prog) &= ~RXf_COPY_DONE)
#define RXp_MATCH_COPIED_on(prog)	(RXp_EXTFLAGS(prog) |= RXf_COPY_DONE)
#define RXp_MATCH_TAINTED(prog)	(RXp_EXTFLAGS(prog) & RXf_TAINTED_SEEN)
#define RXp_MATCH_UTF8(prog)		(RXp_EXTFLAGS(prog) & RXf_MATCH_UTF8)
#define RXp_PAREN_NAMES(rx)	((rx)->xiv_u.xivu_hv)
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
#define SAVESTACK_ALLOC_FOR_RE_SAVE_STATE \
	(1 + ((sizeof(struct re_save_state) - 1) / sizeof(*PL_savestack)))
#define SINGLE_PAT_MOD       's'
#define STD_PAT_MODS        "msix"
#define SV_SAVED_COPY   SV *saved_copy; 
#define S_PAT_MODS      M_PAT_MODS      EXEC_PAT_MODS
#define SvRX(sv)   (Perl_get_re_arg(aTHX_ sv))
#define SvRXOK(sv) (Perl_get_re_arg(aTHX_ sv) ? TRUE : FALSE)
#define XTENDED_PAT_MOD      'x'
#  define BmFLAGS(sv)							\
	(*({ SV *const _bmflags = MUTABLE_SV(sv);			\
		assert(SvTYPE(_bmflags) == SVt_PVGV);			\
		assert(SvVALID(_bmflags));				\
	    &(((XPVGV*) SvANY(_bmflags))->xnv_u.xbm_s.xbm_flags);	\
	 }))
#  define BmPREVIOUS(sv)						\
    (*({ SV *const _bmprevious = MUTABLE_SV(sv);			\
		assert(SvTYPE(_bmprevious) == SVt_PVGV);		\
		assert(SvVALID(_bmprevious));				\
	    &(((XPVGV*) SvANY(_bmprevious))->xnv_u.xbm_s.xbm_previous);	\
	 }))
#  define BmRARE(sv)							\
	(*({ SV *const _bmrare = MUTABLE_SV(sv);			\
		assert(SvTYPE(_bmrare) == SVt_PVGV);			\
		assert(SvVALID(_bmrare));				\
	    &(((XPVGV*) SvANY(_bmrare))->xnv_u.xbm_s.xbm_rare);		\
	 }))
#  define BmUSEFUL(sv)							\
	(*({ SV *const _bmuseful = MUTABLE_SV(sv);			\
	    assert(SvTYPE(_bmuseful) == SVt_PVGV);			\
	    assert(SvVALID(_bmuseful));					\
	    assert(!SvIOK(_bmuseful));					\
	    &(((XPVGV*) SvANY(_bmuseful))->xiv_u.xivu_i32);		\
	 }))
#define CLONEf_CLONE_HOST 4
#define CLONEf_COPY_STACKS 1
#define CLONEf_JOIN_IN 8
#define CLONEf_KEEP_PTR_TABLE 2
#define FmLINES(sv)	((XPVFM*)  SvANY(sv))->xiv_u.xivu_iv
#define Gv_AMG(stash)           (PL_amagic_generation && Gv_AMupdate(stash, FALSE))
#define IoANY(sv)	((XPVIO*)  SvANY(sv))->xio_any
#define IoBOTTOM_GV(sv)	((XPVIO*)  SvANY(sv))->xio_bottom_gv
#define IoBOTTOM_NAME(sv)((XPVIO*) SvANY(sv))->xio_bottom_name
#define IoDIRP(sv)	((XPVIO*)  SvANY(sv))->xio_dirp
#define IoFLAGS(sv)	((XPVIO*)  SvANY(sv))->xio_flags
#define IoFMT_GV(sv)	((XPVIO*)  SvANY(sv))->xio_fmt_gv
#define IoFMT_NAME(sv)	((XPVIO*)  SvANY(sv))->xio_fmt_name
#define IoIFP(sv)	((XPVIO*)  SvANY(sv))->xio_ifp
#define IoLINES(sv)	((XPVIO*)  SvANY(sv))->xiv_u.xivu_iv
#define IoLINES_LEFT(sv)((XPVIO*)  SvANY(sv))->xio_lines_left
#define IoOFP(sv)	((XPVIO*)  SvANY(sv))->xio_ofp
#define IoPAGE(sv)	((XPVIO*)  SvANY(sv))->xio_page
#define IoPAGE_LEN(sv)	((XPVIO*)  SvANY(sv))->xio_page_len
#define IoTOP_GV(sv)	((XPVIO*)  SvANY(sv))->xio_top_gv
#define IoTOP_NAME(sv)	((XPVIO*)  SvANY(sv))->xio_top_name
#define IoTYPE(sv)	((XPVIO*)  SvANY(sv))->xio_type
#define IoTYPE_APPEND 		'a'
#define LvTARG(sv)	((XPVLV*)  SvANY(sv))->xlv_targ
#define LvTARGLEN(sv)	((XPVLV*)  SvANY(sv))->xlv_targlen
#define LvTARGOFF(sv)	((XPVLV*)  SvANY(sv))->xlv_targoff
#define LvTYPE(sv)	((XPVLV*)  SvANY(sv))->xlv_type
#define PERL_FBM_TABLE_OFFSET 1	
#define PRIVSHIFT 4	
#define SV_CHECK_THINKFIRST(sv) if (SvTHINKFIRST(sv)) \
				    sv_force_normal_flags(sv, 0)
#define SV_CHECK_THINKFIRST_COW_DROP(sv) if (SvTHINKFIRST(sv)) \
				    sv_force_normal_flags(sv, SV_COW_DROP_PV)
#define SVf_UTF8        0x20000000  
#define SVpav_REIFY 	0x80000000  
#define SVphv_SHAREKEYS 0x20000000  
#define SVprv_PCS_IMPORTED  SVp_SCREAM  
#define SVprv_WEAKREF   0x80000000  
#define SvAMAGIC(sv)		(SvROK(sv) && (SvFLAGS(SvRV(sv)) & SVf_AMAGIC))
#  define SvAMAGIC_off(sv)	({ SV * const kloink = sv;		\
				   if(SvROK(kloink))			\
					SvFLAGS(SvRV(kloink)) &= ~SVf_AMAGIC;\
				})
#  define SvAMAGIC_on(sv)	({ SV * const kloink = sv;		\
				   assert(SvROK(kloink));		\
				   SvFLAGS(SvRV(kloink)) |= SVf_AMAGIC;	\
				})
#define SvANY(sv)	(sv)->sv_any
#define SvCOMPILED(sv)		(SvFLAGS(sv) & SVpfm_COMPILED)
#define SvCOMPILED_off(sv)	(SvFLAGS(sv) &= ~SVpfm_COMPILED)
#define SvCOMPILED_on(sv)	(SvFLAGS(sv) |= SVpfm_COMPILED)
#    define SvCUR(sv)							\
	(*({ const SV *const _svcur = (const SV *)(sv);			\
	    assert(SvTYPE(_svcur) >= SVt_PV);				\
	    assert(SvTYPE(_svcur) != SVt_PVAV);				\
	    assert(SvTYPE(_svcur) != SVt_PVHV);				\
	    assert(!isGV_with_GP(_svcur));				\
	    &(((XPV*) MUTABLE_PTR(SvANY(_svcur)))->xpv_cur);		\
	 }))
#define SvCUR_set(sv, val) \
	STMT_START { assert(SvTYPE(sv) >= SVt_PV); \
		assert(SvTYPE(sv) != SVt_PVAV);		\
		assert(SvTYPE(sv) != SVt_PVHV);		\
		assert(!isGV_with_GP(sv));		\
		(((XPV*)  SvANY(sv))->xpv_cur = (val)); } STMT_END
#define SvDESTROYABLE(sv) CALL_FPTR(PL_destroyhook)(aTHX_ sv)
#  define SvEND(sv) ((sv)->sv_u.svu_pv + ((XPV*)SvANY(sv))->xpv_cur)
#define SvEND_set(sv, val) \
	STMT_START { assert(SvTYPE(sv) >= SVt_PV); \
		SvCUR_set(sv, (val) - SvPVX(sv)); } STMT_END
#define SvENDx(sv) ((PL_Sv = (sv)), SvEND(PL_Sv))
#define SvEVALED(sv)		(SvFLAGS(sv) & SVrepl_EVAL)
#define SvEVALED_off(sv)	(SvFLAGS(sv) &= ~SVrepl_EVAL)
#define SvEVALED_on(sv)		(SvFLAGS(sv) |= SVrepl_EVAL)
#define SvFAKE(sv)		(SvFLAGS(sv) & SVf_FAKE)
#define SvFAKE_off(sv)		(SvFLAGS(sv) &= ~SVf_FAKE)
#define SvFAKE_on(sv)		(SvFLAGS(sv) |= SVf_FAKE)
#define SvFLAGS(sv)	(sv)->sv_flags
#define SvGAMAGIC(sv)           (SvGMAGICAL(sv) || SvAMAGIC(sv))
#define SvGETMAGIC(x) STMT_START { if (SvGMAGICAL(x)) mg_get(x); } STMT_END
#define SvGMAGICAL(sv)		(SvFLAGS(sv) & SVs_GMG)
#define SvGMAGICAL_off(sv)	(SvFLAGS(sv) &= ~SVs_GMG)
#define SvGMAGICAL_on(sv)	(SvFLAGS(sv) |= SVs_GMG)
#define SvGROW(sv,len) (SvLEN(sv) < (len) ? sv_grow(sv,len) : SvPVX(sv))
#define SvGROW_mutable(sv,len) \
    (SvLEN(sv) < (len) ? sv_grow(sv,len) : SvPVX_mutable(sv))
#define SvIMMORTAL(sv) ((sv)==&PL_sv_undef || (sv)==&PL_sv_yes || (sv)==&PL_sv_no || (sv)==&PL_sv_placeholder)
#define SvIOK(sv)		(SvFLAGS(sv) & SVf_IOK)
#define SvIOK_UV(sv)		((SvFLAGS(sv) & (SVf_IOK|SVf_IVisUV))	\
				 == (SVf_IOK|SVf_IVisUV))
#define SvIOK_notUV(sv)		((SvFLAGS(sv) & (SVf_IOK|SVf_IVisUV))	\
				 == SVf_IOK)
#define SvIOK_off(sv)		(SvFLAGS(sv) &= ~(SVf_IOK|SVp_IOK|SVf_IVisUV))
#define SvIOK_on(sv)		(assert_not_glob(sv) SvRELEASE_IVX_(sv)	\
				    SvFLAGS(sv) |= (SVf_IOK|SVp_IOK))
#define SvIOK_only(sv)		(SvOK_off(sv), \
				    SvFLAGS(sv) |= (SVf_IOK|SVp_IOK))
#define SvIOK_only_UV(sv)	(assert_not_glob(sv) SvOK_off_exc_UV(sv), \
				    SvFLAGS(sv) |= (SVf_IOK|SVp_IOK))
#define SvIOKp(sv)		(SvFLAGS(sv) & SVp_IOK)
#define SvIOKp_on(sv)		(assert_not_glob(sv) SvRELEASE_IVX_(sv)	\
				    SvFLAGS(sv) |= SVp_IOK)
#define SvIS_FREED(sv)	((sv)->sv_flags == SVTYPEMASK)
#define SvIV(sv) (SvIOK(sv) ? SvIVX(sv) : sv_2iv(sv))
#    define SvIVX(sv)							\
	(*({ const SV *const _svivx = (const SV *)(sv);			\
	    assert(SvTYPE(_svivx) == SVt_IV || SvTYPE(_svivx) >= SVt_PVIV); \
	    assert(SvTYPE(_svivx) != SVt_PVAV);				\
	    assert(SvTYPE(_svivx) != SVt_PVHV);				\
	    assert(SvTYPE(_svivx) != SVt_PVCV);				\
	    assert(SvTYPE(_svivx) != SVt_PVFM);				\
	    assert(SvTYPE(_svivx) != SVt_PVIO);				\
	    assert(!isGV_with_GP(_svivx));				\
	    &(((XPVIV*) MUTABLE_PTR(SvANY(_svivx)))->xiv_iv);		\
	 }))
#define SvIVXx(sv) SvIVX(sv)
#define SvIV_nomg(sv) (SvIOK(sv) ? SvIVX(sv) : sv_2iv_flags(sv, 0))
#define SvIV_please(sv) \
	STMT_START {if (!SvIOKp(sv) && (SvNOK(sv) || SvPOK(sv))) \
		(void) SvIV(sv); } STMT_END
#define SvIV_set(sv, val) \
	STMT_START { assert(SvTYPE(sv) == SVt_IV || SvTYPE(sv) >= SVt_PVIV); \
		assert(SvTYPE(sv) != SVt_PVAV);		\
		assert(SvTYPE(sv) != SVt_PVHV);		\
		assert(SvTYPE(sv) != SVt_PVCV);		\
		assert(!isGV_with_GP(sv));		\
		(((XPVIV*)  SvANY(sv))->xiv_iv = (val)); } STMT_END
#  define SvIVx(sv) ({SV *_sv = MUTABLE_SV(sv); SvIV(_sv); })
#define SvIsCOW(sv)		((SvFLAGS(sv) & (SVf_FAKE | SVf_READONLY)) == \
				    (SVf_FAKE | SVf_READONLY))
#  define SvIsCOW_normal(sv)	(SvIsCOW(sv) && SvLEN(sv))
#define SvIsCOW_shared_hash(sv)	(SvIsCOW(sv) && SvLEN(sv) == 0)
#define SvIsUV(sv)		(SvFLAGS(sv) & SVf_IVisUV)
#define SvIsUV_off(sv)		(SvFLAGS(sv) &= ~SVf_IVisUV)
#define SvIsUV_on(sv)		(SvFLAGS(sv) |= SVf_IVisUV)
#  define SvLEN(sv) (0 + ((XPV*) SvANY(sv))->xpv_len)
#define SvLEN_set(sv, val) \
	STMT_START { assert(SvTYPE(sv) >= SVt_PV); \
		assert(SvTYPE(sv) != SVt_PVAV);	\
		assert(SvTYPE(sv) != SVt_PVHV);	\
		assert(!isGV_with_GP(sv));	\
		(((XPV*)  SvANY(sv))->xpv_len = (val)); } STMT_END
#define SvLENx(sv) SvLEN(sv)
#define SvLOCK(sv) CALL_FPTR(PL_lockhook)(aTHX_ sv)
#    define SvMAGIC(sv)	(0 + *(assert(SvTYPE(sv) >= SVt_PVMG), &((XPVMG*)  SvANY(sv))->xmg_u.xmg_magic))
#define SvMAGICAL(sv)		(SvFLAGS(sv) & (SVs_GMG|SVs_SMG|SVs_RMG))
#define SvMAGICAL_off(sv)	(SvFLAGS(sv) &= ~(SVs_GMG|SVs_SMG|SVs_RMG))
#define SvMAGICAL_on(sv)	(SvFLAGS(sv) |= (SVs_GMG|SVs_SMG|SVs_RMG))
#define SvMAGIC_set(sv, val) \
        STMT_START { assert(SvTYPE(sv) >= SVt_PVMG); \
                (((XPVMG*)SvANY(sv))->xmg_u.xmg_magic = (val)); } STMT_END
#define SvNIOK(sv)		(SvFLAGS(sv) & (SVf_IOK|SVf_NOK))
#define SvNIOK_off(sv)		(SvFLAGS(sv) &= ~(SVf_IOK|SVf_NOK| \
						  SVp_IOK|SVp_NOK|SVf_IVisUV))
#define SvNIOKp(sv)		(SvFLAGS(sv) & (SVp_IOK|SVp_NOK))
#define SvNOK(sv)		(SvFLAGS(sv) & SVf_NOK)
#define SvNOK_off(sv)		(SvFLAGS(sv) &= ~(SVf_NOK|SVp_NOK))
#define SvNOK_on(sv)		(assert_not_glob(sv) \
				 SvFLAGS(sv) |= (SVf_NOK|SVp_NOK))
#define SvNOK_only(sv)		(SvOK_off(sv), \
				    SvFLAGS(sv) |= (SVf_NOK|SVp_NOK))
#define SvNOKp(sv)		(SvFLAGS(sv) & SVp_NOK)
#define SvNOKp_on(sv)		(assert_not_glob(sv) SvFLAGS(sv) |= SVp_NOK)
#define SvNV(sv) (SvNOK(sv) ? SvNVX(sv) : sv_2nv(sv))
#    define SvNVX(sv)							\
	(*({ const SV *const _svnvx = (const SV *)(sv);			\
	    assert(SvTYPE(_svnvx) == SVt_NV || SvTYPE(_svnvx) >= SVt_PVNV); \
	    assert(SvTYPE(_svnvx) != SVt_PVAV);				\
	    assert(SvTYPE(_svnvx) != SVt_PVHV);				\
	    assert(SvTYPE(_svnvx) != SVt_PVCV);				\
	    assert(SvTYPE(_svnvx) != SVt_PVFM);				\
	    assert(SvTYPE(_svnvx) != SVt_PVIO);				\
	    assert(!isGV_with_GP(_svnvx));				\
	    &(((XPVNV*) MUTABLE_PTR(SvANY(_svnvx)))->xnv_u.xnv_nv);	\
	 }))
#define SvNVXx(sv) SvNVX(sv)
#define SvNV_set(sv, val) \
	STMT_START { assert(SvTYPE(sv) == SVt_NV || SvTYPE(sv) >= SVt_PVNV); \
	    assert(SvTYPE(sv) != SVt_PVAV); assert(SvTYPE(sv) != SVt_PVHV); \
	    assert(SvTYPE(sv) != SVt_PVCV); assert(SvTYPE(sv) != SVt_PVFM); \
		assert(SvTYPE(sv) != SVt_PVIO);		\
		assert(!isGV_with_GP(sv));		\
		(((XPVNV*)SvANY(sv))->xnv_u.xnv_nv = (val)); } STMT_END
#  define SvNVx(sv) ({SV *_sv = MUTABLE_SV(sv); SvNV(_sv); })
#define SvOBJECT(sv)		(SvFLAGS(sv) & SVs_OBJECT)
#define SvOBJECT_off(sv)	(SvFLAGS(sv) &= ~SVs_OBJECT)
#define SvOBJECT_on(sv)		(SvFLAGS(sv) |= SVs_OBJECT)
#define SvOK(sv)		((SvTYPE(sv) == SVt_BIND)		\
				 ? (SvFLAGS(SvRV(sv)) & SVf_OK)		\
				 : (SvFLAGS(sv) & SVf_OK))
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
#define SvOOK_off(sv)		((void)(SvOOK(sv) && sv_backoff(sv)))
#  define SvOOK_offset(sv, offset) STMT_START {				\
	assert(sizeof(offset) == sizeof(STRLEN));			\
	if (SvOOK(sv)) {						\
	    const U8 *crash = (U8*)SvPVX_const(sv);			\
	    offset = *--crash;						\
 	    if (!offset) {						\
		crash -= sizeof(STRLEN);				\
		Copy(crash, (U8 *)&offset, sizeof(STRLEN), U8);		\
	    }								\
	    {								\
					\
		const U8 *const bonk = (U8 *) SvPVX_const(sv) - offset;	\
		while (crash > bonk) {					\
		    --crash;						\
		    assert (*crash == (U8)PTR2UV(crash));		\
		}							\
	    }								\
	} else {							\
	    offset = 0;							\
	}								\
    } STMT_END
#define SvOOK_on(sv)		((void)SvIOK_off(sv), SvFLAGS(sv) |= SVf_OOK)
#define SvOURSTASH(sv)	\
	(SvPAD_OUR(sv) ? ((XPVMG*) SvANY(sv))->xmg_u.xmg_ourstash : NULL)
#define SvOURSTASH_set(sv, st)					\
        STMT_START {						\
	    assert(SvTYPE(sv) == SVt_PVMG);			\
	    ((XPVMG*) SvANY(sv))->xmg_u.xmg_ourstash = st;	\
	} STMT_END
#define SvPADMY(sv)		(SvFLAGS(sv) & SVs_PADMY)
#define SvPADMY_on(sv)		(SvFLAGS(sv) |= SVs_PADMY)
#define SvPADSTALE(sv)		(SvFLAGS(sv) & SVs_PADSTALE)
#define SvPADSTALE_off(sv)	(SvFLAGS(sv) &= ~SVs_PADSTALE)
#define SvPADSTALE_on(sv)	(SvFLAGS(sv) |= SVs_PADSTALE)
#define SvPADTMP(sv)		(SvFLAGS(sv) & SVs_PADTMP)
#define SvPADTMP_off(sv)	(SvFLAGS(sv) &= ~SVs_PADTMP)
#define SvPADTMP_on(sv)		(SvFLAGS(sv) |= SVs_PADTMP)
#define SvPAD_OUR(sv)	\
	((SvFLAGS(sv) & (SVpad_NAME|SVpad_OUR)) == (SVpad_NAME|SVpad_OUR))
#  define SvPAD_OUR_on(sv)	(SvFLAGS(sv) |= SVpad_NAME|SVpad_OUR)
#define SvPAD_STATE(sv)	\
	((SvFLAGS(sv) & (SVpad_NAME|SVpad_STATE)) == (SVpad_NAME|SVpad_STATE))
#  define SvPAD_STATE_on(sv)	(SvFLAGS(sv) |= SVpad_NAME|SVpad_STATE)
#define SvPAD_TYPED(sv) \
	((SvFLAGS(sv) & (SVpad_NAME|SVpad_TYPED)) == (SVpad_NAME|SVpad_TYPED))
#  define SvPAD_TYPED_on(sv)	(SvFLAGS(sv) |= SVpad_NAME|SVpad_TYPED)
#define SvPCS_IMPORTED(sv)	((SvFLAGS(sv) & (SVf_ROK|SVprv_PCS_IMPORTED)) \
				 == (SVf_ROK|SVprv_PCS_IMPORTED))
#define SvPCS_IMPORTED_off(sv)	(SvFLAGS(sv) &= ~(SVf_ROK|SVprv_PCS_IMPORTED))
#define SvPCS_IMPORTED_on(sv)	(SvFLAGS(sv) |=  (SVf_ROK|SVprv_PCS_IMPORTED))
#define SvPEEK(sv) sv_peek(sv)
#define SvPOK(sv)		(SvFLAGS(sv) & SVf_POK)
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
#define SvPOKp(sv)		(SvFLAGS(sv) & SVp_POK)
#define SvPOKp_on(sv)		(assert_not_ROK(sv) assert_not_glob(sv)	\
				 SvFLAGS(sv) |= SVp_POK)
#define SvPV(sv, lp) SvPV_flags(sv, lp, SV_GMAGIC)
#    define SvPVX(sv) (0 + (assert(!SvREADONLY(sv)), (sv)->sv_u.svu_pv))
#  define SvPVX_const(sv)	((const char*)(0 + (sv)->sv_u.svu_pv))
#  define SvPVX_mutable(sv)	(0 + (sv)->sv_u.svu_pv)
#define SvPVXx(sv) SvPVX(sv)
#define SvPV_const(sv, lp) SvPV_flags_const(sv, lp, SV_GMAGIC)
#define SvPV_flags(sv, lp, flags) \
    ((SvFLAGS(sv) & (SVf_POK)) == SVf_POK \
     ? ((lp = SvCUR(sv)), SvPVX(sv)) : sv_2pv_flags(sv, &lp, flags))
#define SvPV_flags_const(sv, lp, flags) \
    ((SvFLAGS(sv) & (SVf_POK)) == SVf_POK \
     ? ((lp = SvCUR(sv)), SvPVX_const(sv)) : \
     (const char*) sv_2pv_flags(sv, &lp, flags|SV_CONST_RETURN))
#define SvPV_flags_const_nolen(sv, flags) \
    ((SvFLAGS(sv) & (SVf_POK)) == SVf_POK \
     ? SvPVX_const(sv) : \
     (const char*) sv_2pv_flags(sv, 0, flags|SV_CONST_RETURN))
#define SvPV_flags_mutable(sv, lp, flags) \
    ((SvFLAGS(sv) & (SVf_POK)) == SVf_POK \
     ? ((lp = SvCUR(sv)), SvPVX_mutable(sv)) : \
     sv_2pv_flags(sv, &lp, flags|SV_MUTABLE_RETURN))
#define SvPV_force(sv, lp) SvPV_force_flags(sv, lp, SV_GMAGIC)
#define SvPV_force_flags(sv, lp, flags) \
    ((SvFLAGS(sv) & (SVf_POK|SVf_THINKFIRST)) == SVf_POK \
    ? ((lp = SvCUR(sv)), SvPVX(sv)) : sv_pvn_force_flags(sv, &lp, flags))
#define SvPV_force_flags_mutable(sv, lp, flags) \
    ((SvFLAGS(sv) & (SVf_POK|SVf_THINKFIRST)) == SVf_POK \
    ? ((lp = SvCUR(sv)), SvPVX_mutable(sv)) \
     : sv_pvn_force_flags(sv, &lp, flags|SV_MUTABLE_RETURN))
#define SvPV_force_flags_nolen(sv, flags) \
    ((SvFLAGS(sv) & (SVf_POK|SVf_THINKFIRST)) == SVf_POK \
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
			 if(SvOOK(sv)) {				\
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
    ((SvFLAGS(sv) & (SVf_POK)) == SVf_POK \
     ? SvPVX(sv) : sv_2pv_flags(sv, 0, SV_GMAGIC))
#define SvPV_nolen_const(sv) \
    ((SvFLAGS(sv) & (SVf_POK)) == SVf_POK \
     ? SvPVX_const(sv) : sv_2pv_flags(sv, 0, SV_GMAGIC|SV_CONST_RETURN))
#define SvPV_nomg(sv, lp) SvPV_flags(sv, lp, 0)
#define SvPV_nomg_const(sv, lp) SvPV_flags_const(sv, lp, 0)
#define SvPV_nomg_const_nolen(sv) SvPV_flags_const_nolen(sv, 0)
#define SvPV_renew(sv,n) \
	STMT_START { SvLEN_set(sv, n); \
		SvPV_set((sv), (MEM_WRAP_CHECK_(n,char)			\
				(char*)saferealloc((Malloc_t)SvPVX(sv), \
						   (MEM_SIZE)((n)))));  \
		 } STMT_END
#define SvPV_set(sv, val) \
	STMT_START { assert(SvTYPE(sv) >= SVt_PV); \
		assert(SvTYPE(sv) != SVt_PVAV);		\
		assert(SvTYPE(sv) != SVt_PVHV);		\
		assert(!isGV_with_GP(sv));		\
		((sv)->sv_u.svu_pv = (val)); } STMT_END
#define SvPV_shrink_to_cur(sv) STMT_START { \
		   const STRLEN _lEnGtH = SvCUR(sv) + 1; \
		   SvPV_renew(sv, _lEnGtH); \
		 } STMT_END
#define SvPVbyte(sv, lp) \
    ((SvFLAGS(sv) & (SVf_POK|SVf_UTF8)) == (SVf_POK) \
     ? ((lp = SvCUR(sv)), SvPVX(sv)) : sv_2pvbyte(sv, &lp))
#define SvPVbyte_force(sv, lp) \
    ((SvFLAGS(sv) & (SVf_POK|SVf_UTF8|SVf_THINKFIRST)) == (SVf_POK) \
     ? ((lp = SvCUR(sv)), SvPVX(sv)) : sv_pvbyten_force(sv, &lp))
#define SvPVbyte_nolen(sv) \
    ((SvFLAGS(sv) & (SVf_POK|SVf_UTF8)) == (SVf_POK)\
     ? SvPVX(sv) : sv_2pvbyte(sv, 0))
#  define SvPVbytex(sv, lp) ({SV *_sv = (sv); SvPVbyte(_sv, lp); })
#define SvPVbytex_force(sv, lp) sv_pvbyten_force(sv, &lp)
#  define SvPVbytex_nolen(sv) ({SV *_sv = (sv); SvPVbyte_nolen(_sv); })
#define SvPVutf8(sv, lp) \
    ((SvFLAGS(sv) & (SVf_POK|SVf_UTF8)) == (SVf_POK|SVf_UTF8) \
     ? ((lp = SvCUR(sv)), SvPVX(sv)) : sv_2pvutf8(sv, &lp))
#define SvPVutf8_force(sv, lp) \
    ((SvFLAGS(sv) & (SVf_POK|SVf_UTF8|SVf_THINKFIRST)) == (SVf_POK|SVf_UTF8) \
     ? ((lp = SvCUR(sv)), SvPVX(sv)) : sv_pvutf8n_force(sv, &lp))
#define SvPVutf8_nolen(sv) \
    ((SvFLAGS(sv) & (SVf_POK|SVf_UTF8)) == (SVf_POK|SVf_UTF8)\
     ? SvPVX(sv) : sv_2pvutf8(sv, 0))
#  define SvPVutf8x(sv, lp) ({SV *_sv = (sv); SvPVutf8(_sv, lp); })
#define SvPVutf8x_force(sv, lp) sv_pvutf8n_force(sv, &lp)
#  define SvPVx(sv, lp) ({SV *_sv = (sv); SvPV(_sv, lp); })
#  define SvPVx_const(sv, lp) ({SV *_sv = (sv); SvPV_const(_sv, lp); })
#define SvPVx_force(sv, lp) sv_pvn_force(sv, &lp)
#  define SvPVx_nolen(sv) ({SV *_sv = (sv); SvPV_nolen(_sv); })
#  define SvPVx_nolen_const(sv) ({SV *_sv = (sv); SvPV_nolen_const(_sv); })
#define SvREADONLY(sv)		(SvFLAGS(sv) & SVf_READONLY)
#define SvREADONLY_off(sv)	(SvFLAGS(sv) &= ~SVf_READONLY)
#define SvREADONLY_on(sv)	(SvFLAGS(sv) |= SVf_READONLY)
#define SvREFCNT(sv)	(sv)->sv_refcnt
#  define SvREFCNT_dec(sv)		\
    ({					\
	SV * const _sv = MUTABLE_SV(sv);	\
	if (_sv) {			\
	    if (SvREFCNT(_sv)) {	\
		if (--(SvREFCNT(_sv)) == 0) \
		    Perl_sv_free2(aTHX_ _sv);	\
	    } else {			\
		sv_free(_sv);		\
	    }				\
	}				\
    })
#  define SvREFCNT_inc(sv)		\
    ({					\
	SV * const _sv = MUTABLE_SV(sv);	\
	if (_sv)			\
	     (SvREFCNT(_sv))++;		\
	_sv;				\
    })
#  define SvREFCNT_inc_NN(sv)		\
    ({					\
	SV * const _sv = MUTABLE_SV(sv);	\
	SvREFCNT(_sv)++;		\
	_sv;				\
    })
#  define SvREFCNT_inc_simple(sv)	\
    ({					\
	if (sv)				\
	     (SvREFCNT(sv))++;		\
	MUTABLE_SV(sv);				\
    })
#define SvREFCNT_inc_simple_NN(sv)	(++(SvREFCNT(sv)),MUTABLE_SV(sv))
#define SvREFCNT_inc_simple_void(sv)	STMT_START { if (sv) SvREFCNT(sv)++; } STMT_END
#define SvREFCNT_inc_simple_void_NN(sv)	(void)(++SvREFCNT(MUTABLE_SV(sv)))
#  define SvREFCNT_inc_void(sv)		\
    ({					\
	SV * const _sv = MUTABLE_SV(sv);	\
	if (_sv)			\
	    (void)(SvREFCNT(_sv)++);	\
    })
#define SvREFCNT_inc_void_NN(sv)	(void)(++SvREFCNT(MUTABLE_SV(sv)))
#  define SvRELEASE_IVX(sv)   0
#  define SvRELEASE_IVX_(sv)	SvRELEASE_IVX(sv),
#define SvRMAGICAL(sv)		(SvFLAGS(sv) & SVs_RMG)
#define SvRMAGICAL_off(sv)	(SvFLAGS(sv) &= ~SVs_RMG)
#define SvRMAGICAL_on(sv)	(SvFLAGS(sv) |= SVs_RMG)
#define SvROK(sv)		(SvFLAGS(sv) & SVf_ROK)
#define SvROK_off(sv)		(SvFLAGS(sv) &= ~(SVf_ROK))
#define SvROK_on(sv)		(SvFLAGS(sv) |= SVf_ROK)
#    define SvRV(sv)							\
	(*({ SV *const _svrv = MUTABLE_SV(sv);				\
	    assert(SvTYPE(_svrv) >= SVt_PV || SvTYPE(_svrv) == SVt_IV);	\
	    assert(SvTYPE(_svrv) != SVt_PVAV);				\
	    assert(SvTYPE(_svrv) != SVt_PVHV);				\
	    assert(SvTYPE(_svrv) != SVt_PVCV);				\
	    assert(SvTYPE(_svrv) != SVt_PVFM);				\
	    assert(!isGV_with_GP(_svrv));				\
	    &((_svrv)->sv_u.svu_rv);					\
	 }))
#    define SvRV_const(sv)						\
	({ const SV *const _svrv = (const SV *)(sv);			\
	    assert(SvTYPE(_svrv) >= SVt_PV || SvTYPE(_svrv) == SVt_IV);	\
	    assert(SvTYPE(_svrv) != SVt_PVAV);				\
	    assert(SvTYPE(_svrv) != SVt_PVHV);				\
	    assert(SvTYPE(_svrv) != SVt_PVCV);				\
	    assert(SvTYPE(_svrv) != SVt_PVFM);				\
	    assert(!isGV_with_GP(_svrv));				\
	    (_svrv)->sv_u.svu_rv;					\
	 })
#define SvRV_set(sv, val) \
        STMT_START { assert(SvTYPE(sv) >=  SVt_PV || SvTYPE(sv) ==  SVt_IV); \
		assert(SvTYPE(sv) != SVt_PVAV);		\
		assert(SvTYPE(sv) != SVt_PVHV);		\
		assert(SvTYPE(sv) != SVt_PVCV);		\
		assert(SvTYPE(sv) != SVt_PVFM);		\
		assert(!isGV_with_GP(sv));		\
                ((sv)->sv_u.svu_rv = (val)); } STMT_END
#define SvRVx(sv) SvRV(sv)
#define SvSCREAM(sv) ((SvFLAGS(sv) & (SVp_SCREAM|SVp_POK)) == (SVp_SCREAM|SVp_POK))
#define SvSCREAM_off(sv)	(SvFLAGS(sv) &= ~SVp_SCREAM)
#define SvSCREAM_on(sv)		(SvFLAGS(sv) |= SVp_SCREAM)
#define SvSETMAGIC(x) STMT_START { if (SvSMAGICAL(x)) mg_set(x); } STMT_END
#define SvSHARE(sv) CALL_FPTR(PL_sharehook)(aTHX_ sv)
#define SvSHARED_HASH(sv) (0 + SvSHARED_HEK_FROM_PV(SvPVX_const(sv))->hek_hash)
#define SvSHARED_HEK_FROM_PV(pvx) \
	((struct hek*)(pvx - STRUCT_OFFSET(struct hek, hek_key)))
#define SvSMAGICAL(sv)		(SvFLAGS(sv) & SVs_SMG)
#define SvSMAGICAL_off(sv)	(SvFLAGS(sv) &= ~SVs_SMG)
#define SvSMAGICAL_on(sv)	(SvFLAGS(sv) |= SVs_SMG)
#    define SvSTASH(sv)	(0 + *(assert(SvTYPE(sv) >= SVt_PVMG), &((XPVMG*)  SvANY(sv))->xmg_stash))
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
	    if ((dst) != (src)) {			\
		sv_setsv(dst, src);			\
		finally;				\
	    }						\
	} STMT_END
#define SvSetSV_nosteal(dst,src) \
		SvSetSV_nosteal_and(dst,src,;)
#define SvSetSV_nosteal_and(dst,src,finally) \
	STMT_START {					\
	    if ((dst) != (src)) {			\
		sv_setsv_flags(dst, src, SV_GMAGIC | SV_NOSTEAL | SV_DO_COW_SVSETSV);	\
		finally;				\
	    }						\
	} STMT_END
#  define SvTAIL(sv)	({ const SV *const _svtail = (const SV *)(sv);	\
			    assert(SvTYPE(_svtail) != SVt_PVAV);		\
			    assert(SvTYPE(_svtail) != SVt_PVHV);		\
			    (SvFLAGS(sv) & (SVpbm_TAIL|SVpbm_VALID))	\
				== (SVpbm_TAIL|SVpbm_VALID);		\
			})
#define SvTAIL_off(sv)		(SvFLAGS(sv) &= ~SVpbm_TAIL)
#define SvTAIL_on(sv)		(SvFLAGS(sv) |= SVpbm_TAIL)
#define SvTAINT(sv)			\
    STMT_START {			\
	if (PL_tainting) {		\
	    if (PL_tainted)		\
		SvTAINTED_on(sv);	\
	}				\
    } STMT_END
#define SvTAINTED(sv)	  (SvMAGICAL(sv) && sv_tainted(sv))
#define SvTAINTED_off(sv) STMT_START{ if(PL_tainting){sv_untaint(sv);} }STMT_END
#define SvTAINTED_on(sv)  STMT_START{ if(PL_tainting){sv_taint(sv);}   }STMT_END
#define SvTEMP(sv)		(SvFLAGS(sv) & SVs_TEMP)
#define SvTEMP_off(sv)		(SvFLAGS(sv) &= ~SVs_TEMP)
#define SvTEMP_on(sv)		(SvFLAGS(sv) |= SVs_TEMP)
#define SvTHINKFIRST(sv)	(SvFLAGS(sv) & SVf_THINKFIRST)
#  define SvTRUE(sv) (						\
    !sv								\
    ? 0								\
    :    SvPOK(sv)						\
	?   (({XPV *nxpv = (XPV*)SvANY(sv);			\
	     nxpv &&						\
	     (nxpv->xpv_cur > 1 ||				\
	      (nxpv->xpv_cur && *(sv)->sv_u.svu_pv != '0')); })	\
	     ? 1						\
	     : 0)						\
	:							\
	    SvIOK(sv)						\
	    ? SvIVX(sv) != 0					\
	    :   SvNOK(sv)					\
		? SvNVX(sv) != 0.0				\
		: sv_2bool(sv) )
#  define SvTRUEx(sv) ({SV *_sv = (sv); SvTRUE(_sv); })
#define SvTYPE(sv)	((svtype)((sv)->sv_flags & SVTYPEMASK))
#define SvUNLOCK(sv) CALL_FPTR(PL_unlockhook)(aTHX_ sv)
#define SvUOK(sv)		SvIOK_UV(sv)
#define SvUPGRADE(sv, mt) (SvTYPE(sv) >= (mt) || (sv_upgrade(sv, mt), 1))
#define SvUTF8(sv)		(SvFLAGS(sv) & SVf_UTF8)
#define SvUTF8_off(sv)		(SvFLAGS(sv) &= ~(SVf_UTF8))
#define SvUTF8_on(sv)		(SvFLAGS(sv) |= (SVf_UTF8))
#define SvUV(sv) (SvIOK(sv) ? SvUVX(sv) : sv_2uv(sv))
#    define SvUVX(sv)							\
	(*({ const SV *const _svuvx = (const SV *)(sv);			\
	    assert(SvTYPE(_svuvx) == SVt_IV || SvTYPE(_svuvx) >= SVt_PVIV); \
	    assert(SvTYPE(_svuvx) != SVt_PVAV);				\
	    assert(SvTYPE(_svuvx) != SVt_PVHV);				\
	    assert(SvTYPE(_svuvx) != SVt_PVCV);				\
	    assert(SvTYPE(_svuvx) != SVt_PVFM);				\
	    assert(SvTYPE(_svuvx) != SVt_PVIO);				\
	    assert(!isGV_with_GP(_svuvx));				\
	    &(((XPVUV*) MUTABLE_PTR(SvANY(_svuvx)))->xuv_uv);		\
	 }))
#define SvUVXx(sv) SvUVX(sv)
#define SvUV_nomg(sv) (SvIOK(sv) ? SvUVX(sv) : sv_2uv_flags(sv, 0))
#define SvUV_set(sv, val) \
	STMT_START { assert(SvTYPE(sv) == SVt_IV || SvTYPE(sv) >= SVt_PVIV); \
		assert(SvTYPE(sv) != SVt_PVAV);		\
		assert(SvTYPE(sv) != SVt_PVHV);		\
		assert(SvTYPE(sv) != SVt_PVCV);		\
		assert(!isGV_with_GP(sv));		\
		(((XPVUV*)SvANY(sv))->xuv_uv = (val)); } STMT_END
#  define SvUVx(sv) ({SV *_sv = MUTABLE_SV(sv); SvUV(_sv); })
#  define SvVALID(sv)		({ const SV *const _svvalid = (const SV*)(sv); \
				   if (SvFLAGS(_svvalid) & SVpbm_VALID)	\
				       assert(!isGV_with_GP(_svvalid));	\
				   (SvFLAGS(_svvalid) & SVpbm_VALID);	\
				})
#  define SvVALID_off(sv)	({ SV *const _svvalid = MUTABLE_SV(sv);	\
				   assert(!isGV_with_GP(_svvalid));	\
				   (SvFLAGS(_svvalid) &= ~SVpbm_VALID);	\
				})
#  define SvVALID_on(sv)	({ SV *const _svvalid = MUTABLE_SV(sv);	\
				   assert(!isGV_with_GP(_svvalid));	\
				   (SvFLAGS(_svvalid) |= SVpbm_VALID);	\
				})
#define SvVOK(sv)		(SvMAGICAL(sv)				\
				 && mg_find(sv,PERL_MAGIC_vstring))
#define SvVSTRING_mg(sv)	(SvMAGICAL(sv) \
				 ? mg_find(sv,PERL_MAGIC_vstring) : NULL)
#define SvWEAKREF(sv)		((SvFLAGS(sv) & (SVf_ROK|SVprv_WEAKREF)) \
				  == (SVf_ROK|SVprv_WEAKREF))
#define SvWEAKREF_off(sv)	(SvFLAGS(sv) &= ~(SVf_ROK|SVprv_WEAKREF))
#define SvWEAKREF_on(sv)	(SvFLAGS(sv) |=  (SVf_ROK|SVprv_WEAKREF))
#define Sv_Grow sv_grow
#define _SV_HEAD(ptrtype) \
    ptrtype	sv_any;			\
    U32		sv_refcnt;		\
    U32		sv_flags	
#define _SV_HEAD_UNION \
    union {				\
	char*   svu_pv;			\
	IV      svu_iv;			\
	UV      svu_uv;			\
	SV*     svu_rv;				\
	SV**    svu_array;		\
	HE**	svu_hash;		\
	GP*	svu_gp;			\
    }	sv_u
#define assert_not_ROK(sv)	({assert(!SvROK(sv) || !SvRV(sv));}),
#define assert_not_glob(sv)	({assert(!isGV_with_GP(sv));}),
#define boolSV(b) ((b) ? &PL_sv_yes : &PL_sv_no)
#define isGV(sv) (SvTYPE(sv) == SVt_PVGV)
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
#define newIO()	MUTABLE_IO(newSV_type(SVt_PVIO))
#define newRV_inc(sv)	newRV(sv)
#define newSVpvn_utf8(s, len, u) newSVpvn_flags((s), (len), (u) ? SVf_UTF8 : 0)
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
#define sv_2iv(sv) sv_2iv_flags(sv, SV_GMAGIC)
#define sv_2pv(sv, lp) sv_2pv_flags(sv, lp, SV_GMAGIC)
#define sv_2pv_nolen(sv) sv_2pv(sv, 0)
#define sv_2pv_nomg(sv, lp) sv_2pv_flags(sv, lp, 0)
#define sv_2pvbyte_nolen(sv) sv_2pvbyte(sv, 0)
#define sv_2pvutf8_nolen(sv) sv_2pvutf8(sv, 0)
#define sv_2uv(sv) sv_2uv_flags(sv, SV_GMAGIC)
#define sv_catpvn(dsv, sstr, slen) sv_catpvn_flags(dsv, sstr, slen, SV_GMAGIC)
#define sv_catpvn_mg(sv, sstr, slen) \
	sv_catpvn_flags(sv, sstr, slen, SV_GMAGIC|SV_SMAGIC);
#define sv_catpvn_nomg(dsv, sstr, slen) sv_catpvn_flags(dsv, sstr, slen, 0)
#define sv_catpvn_utf8_upgrade(dsv, sstr, slen, nsv)	\
	STMT_START {					\
	    if (!(nsv))					\
		nsv = newSVpvn_flags(sstr, slen, SVs_TEMP);	\
	    else					\
		sv_setpvn(nsv, sstr, slen);		\
	    SvUTF8_off(nsv);				\
	    sv_utf8_upgrade(nsv);			\
	    sv_catsv(dsv, nsv);	\
	} STMT_END
#define sv_catsv(dsv, ssv) sv_catsv_flags(dsv, ssv, SV_GMAGIC)
#define sv_catsv_mg(dsv, ssv) sv_catsv_flags(dsv, ssv, SV_GMAGIC|SV_SMAGIC)
#define sv_catsv_nomg(dsv, ssv) sv_catsv_flags(dsv, ssv, 0)
#define sv_force_normal(sv)	sv_force_normal_flags(sv, 0)
#define sv_insert(bigstr, offset, len, little, littlelen)		\
	Perl_sv_insert_flags(aTHX_ (bigstr),(offset), (len), (little),	\
			     (littlelen), SV_GMAGIC)
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
#define sv_usepvn(sv, p, l)	sv_usepvn_flags(sv, p, l, 0)
#define sv_usepvn_mg(sv, p, l)	sv_usepvn_flags(sv, p, l, SV_SMAGIC)
#define sv_utf8_upgrade(sv) sv_utf8_upgrade_flags(sv, SV_GMAGIC)
#define sv_utf8_upgrade_flags(sv, flags) sv_utf8_upgrade_flags_grow(sv, flags, 0)
#define sv_utf8_upgrade_nomg(sv) sv_utf8_upgrade_flags(sv, 0)
#define xiv_iv xiv_u.xivu_iv
#define xuv_uv xuv_u.xivu_uv
#define ADDOP 297
#define ANDAND 315
#define ANDOP 310
#define ANONSUB 272
#define ARROW 327
#define ASSIGNOP 312
#define BITANDOP 317
#define BITOROP 316
#define COLONATTR 306
#define CONTINUE 281
#define DEFAULT 285
#define DO 299
#define DOLSHARP 298
#define DORDOR 313
#define DOROP 308
#define DOTDOT 287
#define ELSE 279
#define ELSIF 280
#define EQOP 295
#define FOR 282
#define FORMAT 270
#define FUNC 291
#define FUNC0 289
#define FUNC0SUB 264
#define FUNC1 290
#define FUNCMETH 260
#define GIVEN 283
#define HASHBRACK 300
#define IF 277
#define LABEL 269
#define LOCAL 302
#define LOOPEX 286
#define LSTOP 293
#define LSTOPSUB 266
#define MATCHOP 319
#define METHOD 259
#define MULOP 296
#define MY 303
#define MYSUB 304
#define NOAMP 301
#define NOTOP 311
#define OROP 309
#define OROR 314
#define PACKAGE 273
#define PEG 328
#define PLUGEXPR 267
#define PLUGSTMT 268
#define PMFUNC 262
#define POSTDEC 323
#define POSTINC 324
#define POWOP 322
#define PREC_LOW 307
#define PREDEC 325
#define PREINC 326
#define PRIVATEREF 263
#define REFGEN 320
#define RELOP 294
#define REQUIRE 305
#define SHIFTOP 318
#define SUB 271
#define THING 261
#define UMINUS 321
#define UNIOP 292
#define UNIOPSUB 265
#define UNLESS 278
#define UNTIL 276
#define USE 274
#define WHEN 284
#define WHILE 275
#define WORD 258
#define YADAYADA 288
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
# define yystype YYSTYPE 
#define BADVERSION(a,b,c) \
	if (b) { \
	    *b = c; \
	} \
	return a;
#define BIT_DIGITS(N)   (((N)*146)/485 + 1)  
#    define CTYPE256
#define C_ARRAY_LENGTH(a)	(sizeof(a)/sizeof((a)[0]))
#define Copy(s,d,n,t)	(MEM_WRAP_CHECK_(n,t) (void)memcpy((char*)(d),(const char*)(s), (n) * sizeof(t)))
#define CopyD(s,d,n,t)	(MEM_WRAP_CHECK_(n,t) memcpy((char*)(d),(const char*)(s), (n) * sizeof(t)))
#define Ctl(ch) ((ch) & 037)
# define ENUM_BOOL 1
#define FALSE (0)
#    define FUNCTION__ ""
#    define HAS_BOOL 1
#define I16_MAX INT16_MAX
#define I16_MIN INT16_MIN
# define I32_MAX PERL_INT_MAX
# define I32_MIN PERL_INT_MIN
#       define INT32_MIN (-2147483647-1)
#                   define INT64_C(c)	CAT2(c,I64)
#       define INT64_MIN (-9223372036854775807LL-1)
#define MEM_LOG_ALLOC(n,t,a)     Perl_mem_log_alloc(n,sizeof(t),STRINGIFY(t),a,"__FILE__","__LINE__",FUNCTION__)
#define MEM_LOG_FREE(a)          Perl_mem_log_free(a,"__FILE__","__LINE__",FUNCTION__)
#define MEM_LOG_REALLOC(n,t,v,a) Perl_mem_log_realloc(n,sizeof(t),STRINGIFY(t),v,a,"__FILE__","__LINE__",FUNCTION__)
#define MEM_SIZE_MAX ((MEM_SIZE)~0)
#define MEM_WRAP_CHECK(n,t) MEM_WRAP_CHECK_1(n,t,PL_memory_wrap)
#define MEM_WRAP_CHECK_(n,t) MEM_WRAP_CHECK(n,t),
#define MEM_WRAP_CHECK_1(n,t,a) \
	(void)(sizeof(t) > 1 && ((MEM_SIZE)(n)+0.0) > MEM_SIZE_MAX/sizeof(t) && (Perl_croak_nocontext("%s",(a)),0))

#define MUTABLE_AV(p)	((AV *)MUTABLE_PTR(p))
#define MUTABLE_CV(p)	((CV *)MUTABLE_PTR(p))
#define MUTABLE_GV(p)	((GV *)MUTABLE_PTR(p))
#define MUTABLE_HV(p)	((HV *)MUTABLE_PTR(p))
#define MUTABLE_IO(p)	((IO *)MUTABLE_PTR(p))
#  define MUTABLE_PTR(p) ({ void *_p = (p); _p; })
#define MUTABLE_SV(p)	((SV *)MUTABLE_PTR(p))
#define Move(s,d,n,t)	(MEM_WRAP_CHECK_(n,t) (void)memmove((char*)(d),(const char*)(s), (n) * sizeof(t)))
#define MoveD(s,d,n,t)	(MEM_WRAP_CHECK_(n,t) memmove((char*)(d),(const char*)(s), (n) * sizeof(t)))
#define NEWSV(x,len)	newSV(len)
#define NOLINE ((line_t) 4294967295UL)
#  define NULL 0
#define New(x,v,n,t)	Newx(v,n,t)
#define Newc(x,v,n,t,c)	Newxc(v,n,t,c)
#define Newx(v,n,t)	(v = (MEM_WRAP_CHECK_(n,t) (t*)MEM_LOG_ALLOC(n,t,safemalloc((MEM_SIZE)((n)*sizeof(t))))))
#define Newxc(v,n,t,c)	(v = (MEM_WRAP_CHECK_(n,t) (c*)MEM_LOG_ALLOC(n,t,safemalloc((MEM_SIZE)((n)*sizeof(t))))))
#define Newxz(v,n,t)	(v = (MEM_WRAP_CHECK_(n,t) (t*)MEM_LOG_ALLOC(n,t,safecalloc((n),sizeof(t)))))
#define Newz(x,v,n,t)	Newxz(v,n,t)
#  define Null(type) ((type)NULL)
#  define Nullch Null(char*)
#  define Nullfp Null(PerlIO*)
#  define Nullsv Null(SV*)
#define PERL_STRLEN_ROUNDUP(n) ((void)(((n) > MEM_SIZE_MAX - 2 * PERL_STRLEN_ROUNDUP_QUANTUM) ? (Perl_croak_nocontext("%s",PL_memory_wrap),0):0),((n-1+PERL_STRLEN_ROUNDUP_QUANTUM)&~((MEM_SIZE)PERL_STRLEN_ROUNDUP_QUANTUM-1)))
#   define Perl_va_copy(s, d) __va_copy(d, s)
#define Poison(d,n,t)		PoisonFree(d,n,t)
#define PoisonFree(d,n,t)	PoisonWith(d,n,t,0xEF)
#define PoisonNew(d,n,t)	PoisonWith(d,n,t,0xAB)
#define PoisonWith(d,n,t,b)	(MEM_WRAP_CHECK_(n,t) (void)memset((char*)(d), (U8)(b), (n) * sizeof(t)))
#define Renew(v,n,t) \
	  (v = (MEM_WRAP_CHECK_(n,t) (t*)MEM_LOG_REALLOC(n,t,v,saferealloc((Malloc_t)(v),(MEM_SIZE)((n)*sizeof(t))))))
#define Renewc(v,n,t,c) \
	  (v = (MEM_WRAP_CHECK_(n,t) (c*)MEM_LOG_REALLOC(n,t,v,saferealloc((Malloc_t)(v),(MEM_SIZE)((n)*sizeof(t))))))
#define STR_WITH_LEN(s)  ("" s ""), (sizeof(s)-1)
#define Safefree(d) \
  ((d) ? (void)(safefree(MEM_LOG_FREE((Malloc_t)(d))), Poison(&(d), 1, Malloc_t)) : (void) 0)
#define StructCopy(s,d,t) (*((t*)(d)) = *((t*)(s)))
#define TRUE (1)
#define TYPE_CHARS(T)   (TYPE_DIGITS(T) + 2) 
#define TYPE_DIGITS(T)  BIT_DIGITS(sizeof(T) * 8)
#define U16_MAX UINT16_MAX
#define U16_MIN UINT16_MIN
#  define U32_MAX UINT32_MAX
# define U32_MIN PERL_UINT_MIN
#define U8_MAX UINT8_MAX
#define U8_MIN UINT8_MIN
#                   define UINT64_C(c)	CAT2(c,UI64)
#define Zero(d,n,t)	(MEM_WRAP_CHECK_(n,t) (void)memzero((char*)(d), (n) * sizeof(t)))
#define ZeroD(d,n,t)	(MEM_WRAP_CHECK_(n,t) memzero((char*)(d), (n) * sizeof(t)))
#  define bool int
#  define deprecate(s) Perl_ck_warner_d(aTHX_ packWARN(WARN_DEPRECATED), "Use of " s " is deprecated")
#define get_cvs(str, flags)					\
	Perl_get_cvn_flags(aTHX_ STR_WITH_LEN(str), (flags))
#define gv_fetchpvs(namebeg, add, sv_type) Perl_gv_fetchpvn_flags(aTHX_ STR_WITH_LEN(namebeg), add, sv_type)
#define gv_stashpvs(str, create) Perl_gv_stashpvn(aTHX_ STR_WITH_LEN(str), create)
#define hv_fetchs(hv,key,lval)						\
  ((SV **)Perl_hv_common(aTHX_ (hv), NULL, STR_WITH_LEN(key), 0,	\
			 (lval) ? (HV_FETCH_JUST_SV | HV_FETCH_LVALUE)	\
			 : HV_FETCH_JUST_SV, NULL, 0))
#define hv_stores(hv,key,val)						\
  ((SV **)Perl_hv_common(aTHX_ (hv), NULL, STR_WITH_LEN(key), 0,	\
			 (HV_FETCH_ISSTORE|HV_FETCH_JUST_SV), (val), 0))
#define isALNUM(c)	(isALPHA(c) || isDIGIT(c) || (c) == '_')
#   define isALNUMC(c)	isalnum(c)
#    define isALNUMC_LC(c)	isalnum((unsigned char)(c))
#define isALNUMC_LC_utf8(p)	isALNUMC_LC_uvchr(utf8_to_uvchr(p,  0))
#define isALNUMU(c)	(isDIGIT(c) || isALPHAU(c) || (c) == '_')
#    define isALNUM_LC(c)   (isalnum((unsigned char)(c)) || (char)(c) == '_')
#define isALNUM_LC_utf8(p)	isALNUM_LC_uvchr(utf8_to_uvchr(p,  0))
#define isALNUM_LC_uvchr(c)	(c < 256 ? isALNUM_LC(c) : is_uni_alnum_lc(c))
#define isALNUM_uni(c)		is_uni_alnum(c)
#define isALNUM_utf8(p)		is_utf8_alnum(p)
#define isALPHA(c)	(isUPPER(c) || isLOWER(c))
#define isALPHAU(c)	(isALPHA(c) || (NATIVE_TO_UNI((U8) c) >= 0xAA \
    && ((NATIVE_TO_UNI((U8) c) >= 0xC0 \
	    && NATIVE_TO_UNI((U8) c) != 0xD7 && NATIVE_TO_UNI((U8) c) != 0xF7) \
	|| NATIVE_TO_UNI((U8) c) == 0xAA \
	|| NATIVE_TO_UNI((U8) c) == 0xB5 \
	|| NATIVE_TO_UNI((U8) c) == 0xBA)))
#    define isALPHA_LC(c)	isalpha((unsigned char)(c))
#define isALPHA_LC_utf8(p)	isALPHA_LC_uvchr(utf8_to_uvchr(p,  0))
#define isALPHA_LC_uvchr(c)	(c < 256 ? isALPHA_LC(c) : is_uni_alpha_lc(c))
#define isALPHA_uni(c)		is_uni_alpha(c)
#define isALPHA_utf8(p)		is_utf8_alpha(p)
#   define isASCII(c)	isascii(c)
#define isASCII_uni(c)		is_uni_ascii(c)
#define isASCII_utf8(p)		is_utf8_ascii(p)
#define isBLANK(c)	((c) == ' ' || (c) == '\t')
#define isBLANK_LC(c)		isBLANK(c) 
#define isBLANK_LC_uni(c)	isBLANK(c) 
#define isBLANK_LC_utf8(c)	isBLANK(c) 
#define isBLANK_uni(c)		isBLANK(c) 
#define isBLANK_utf8(c)		isBLANK(c) 
#define isCHARNAME_CONT(c) (isALNUMU(c) || (c) == ' ' || (c) == '-' || (c) == '(' || (c) == ')' || (c) == ':' || NATIVE_TO_UNI((U8) c) == 0xA0)
#   define isCNTRL(c)	iscntrl(c)
#    define isCNTRL_LC(c)	iscntrl((unsigned char)(c))
#define isCNTRL_LC_utf8(p)	isCNTRL_LC_uvchr(utf8_to_uvchr(p,  0))
#define isCNTRL_LC_uvchr(c)	(c < 256 ? isCNTRL_LC(c) : is_uni_cntrl_lc(c))
#define isCNTRL_uni(c)		is_uni_cntrl(c)
#define isCNTRL_utf8(p)		is_utf8_cntrl(p)
#define isDIGIT(c)	((c) >= '0' && (c) <= '9')
#    define isDIGIT_LC(c)	isdigit((unsigned char)(c))
#define isDIGIT_LC_utf8(p)	isDIGIT_LC_uvchr(utf8_to_uvchr(p,  0))
#define isDIGIT_LC_uvchr(c)	(c < 256 ? isDIGIT_LC(c) : is_uni_digit_lc(c))
#define isDIGIT_uni(c)		is_uni_digit(c)
#define isDIGIT_utf8(p)		is_utf8_digit(p)
#   define isGRAPH(c)	isgraph(c)
#    define isGRAPH_LC(c)	isgraph((unsigned char)(c))
#define isGRAPH_LC_utf8(p)	isGRAPH_LC_uvchr(utf8_to_uvchr(p,  0))
#define isGRAPH_LC_uvchr(c)	(c < 256 ? isGRAPH_LC(c) : is_uni_graph_lc(c))
#define isGRAPH_uni(c)		is_uni_graph(c)
#define isGRAPH_utf8(p)		is_utf8_graph(p)
#define isIDFIRST(c)	(isALPHA(c) || (c) == '_')
#    define isIDFIRST_LC(c) (isalpha((unsigned char)(c)) || (char)(c) == '_')
#define isIDFIRST_LC_utf8(p)	isIDFIRST_LC_uvchr(utf8_to_uvchr(p,  0))
#define isIDFIRST_LC_uvchr(c)	(c < 256 ? isIDFIRST_LC(c) : is_uni_idfirst_lc(c))
#define isIDFIRST_uni(c)	is_uni_idfirst(c)
#define isIDFIRST_utf8(p)	(is_utf8_idcont(p) && !is_utf8_digit(p))
#   define isLOWER(c)	islower(c)
#    define isLOWER_LC(c)	islower((unsigned char)(c))
#define isLOWER_LC_utf8(p)	isLOWER_LC_uvchr(utf8_to_uvchr(p,  0))
#define isLOWER_LC_uvchr(c)	(c < 256 ? isLOWER_LC(c) : is_uni_lower_lc(c))
#define isLOWER_uni(c)		is_uni_lower(c)
#define isLOWER_utf8(p)		is_utf8_lower(p)
#   define isPRINT(c)	isprint(c)
#    define isPRINT_LC(c)	isprint((unsigned char)(c))
#define isPRINT_LC_utf8(p)	isPRINT_LC_uvchr(utf8_to_uvchr(p,  0))
#define isPRINT_LC_uvchr(c)	(c < 256 ? isPRINT_LC(c) : is_uni_print_lc(c))
#define isPRINT_uni(c)		is_uni_print(c)
#define isPRINT_utf8(p)		is_utf8_print(p)
#define isPSXSPC(c)	(isSPACE(c) || (c) == '\v')
#define isPSXSPC_LC(c)		(isSPACE_LC(c) || (c) == '\v')
#define isPSXSPC_LC_uni(c)	(isSPACE_LC_uni(c) ||(c) == '\f')
#define isPSXSPC_LC_utf8(c)	(isSPACE_LC_utf8(c) ||(c) == '\f')
#define isPSXSPC_uni(c)		(isSPACE_uni(c) ||(c) == '\f')
#define isPSXSPC_utf8(c)	(isSPACE_utf8(c) ||(c) == '\f')
#   define isPUNCT(c)	ispunct(c)
#    define isPUNCT_LC(c)	ispunct((unsigned char)(c))
#define isPUNCT_LC_utf8(p)	isPUNCT_LC_uvchr(utf8_to_uvchr(p,  0))
#define isPUNCT_LC_uvchr(c)	(c < 256 ? isPUNCT_LC(c) : is_uni_punct_lc(c))
#define isPUNCT_uni(c)		is_uni_punct(c)
#define isPUNCT_utf8(p)		is_utf8_punct(p)
#define isSPACE(c) \
	((c) == ' ' || (c) == '\t' || (c) == '\n' || (c) =='\r' || (c) == '\f')
#    define isSPACE_LC(c)	isspace((unsigned char)(c))
#define isSPACE_LC_utf8(p)	isSPACE_LC_uvchr(utf8_to_uvchr(p,  0))
#define isSPACE_LC_uvchr(c)	(c < 256 ? isSPACE_LC(c) : is_uni_space_lc(c))
#define isSPACE_uni(c)		is_uni_space(c)
#define isSPACE_utf8(p)		is_utf8_space(p)
#   define isUPPER(c)	isupper(c)
#    define isUPPER_LC(c)	isupper((unsigned char)(c))
#define isUPPER_LC_utf8(p)	isUPPER_LC_uvchr(utf8_to_uvchr(p,  0))
#define isUPPER_LC_uvchr(c)	(c < 256 ? isUPPER_LC(c) : is_uni_upper_lc(c))
#define isUPPER_uni(c)		is_uni_upper(c)
#define isUPPER_utf8(p)		is_utf8_upper(p)
#   define isXDIGIT(c)	isxdigit(c)
#define isXDIGIT_uni(c)		is_uni_xdigit(c)
#define isXDIGIT_utf8(p)	is_utf8_xdigit(p)
#define is_LAX_VERSION(a,b) \
	(a != Perl_prescan_version(aTHX_ a, FALSE, b, NULL, NULL, NULL, NULL))
#define is_STRICT_VERSION(a,b) \
	(a != Perl_prescan_version(aTHX_ a, TRUE, b, NULL, NULL, NULL, NULL))
#  define memEQ(s1,s2,l) (!memcmp(s1,s2,l))
#define memEQs(s1, l, s2) \
	(sizeof(s2)-1 == l && memEQ(s1, (s2 ""), (sizeof(s2)-1)))
#  define memNE(s1,s2,l) (memcmp(s1,s2,l))
#define memNEs(s1, l, s2) !memEQs(s1, l, s2)
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
#define savepvs(str) Perl_savepvn(aTHX_ STR_WITH_LEN(str))
#define strEQ(s1,s2) (!strcmp(s1,s2))
#define strGE(s1,s2) (strcmp(s1,s2) >= 0)
#define strGT(s1,s2) (strcmp(s1,s2) > 0)
#define strLE(s1,s2) (strcmp(s1,s2) <= 0)
#define strLT(s1,s2) (strcmp(s1,s2) < 0)
#define strNE(s1,s2) (strcmp(s1,s2))
#define strnEQ(s1,s2,l) (!strncmp(s1,s2,l))
#define strnNE(s1,s2,l) (strncmp(s1,s2,l))
#define sv_catpvs(sv, str) Perl_sv_catpvn_flags(aTHX_ sv, STR_WITH_LEN(str), SV_GMAGIC)
#define sv_setpvs(sv, str) Perl_sv_setpvn(aTHX_ sv, STR_WITH_LEN(str))
#    define toCTRL        Perl_ebcdic_control
#define toFOLD_uni(c,s,l)	to_uni_fold(c,s,l)
#   define toLOWER(c)	tolower(c)
#   define toLOWER_LATIN1(c)	UNI_TO_NATIVE(PL_latin1_lc[(U8) NATIVE_TO_UNI(c)])
#    define toLOWER_LC(c)	tolower((unsigned char)(c))
#define toLOWER_uni(c,s,l)	to_uni_lower(c,s,l)
#define toLOWER_utf8(p,s,l)	to_utf8_lower(p,s,l)
#define toTITLE_uni(c,s,l)	to_uni_title(c,s,l)
#define toTITLE_utf8(p,s,l)	to_utf8_title(p,s,l)
#   define toUPPER(c)	toupper(c)
#   define toUPPER_LATIN1_MOD(c)    UNI_TO_NATIVE(PL_mod_latin1_uc[(U8) NATIVE_TO_UNI(c)])
#    define toUPPER_LC(c)	toupper((unsigned char)(c))
#define toUPPER_uni(c,s,l)	to_uni_upper(c,s,l)
#define toUPPER_utf8(p,s,l)	to_utf8_upper(p,s,l)



#      define EXT extern __declspec(dllexport)
#      define EXTCONST extern __declspec(dllexport) const

#      define dEXT 
#      define dEXTCONST const
