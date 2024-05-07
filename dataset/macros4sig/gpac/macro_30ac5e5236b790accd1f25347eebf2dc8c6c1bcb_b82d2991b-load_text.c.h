



#include<stdarg.h>


#include<ctype.h>
#include<stddef.h>
#include<stdint.h>

#include<time.h>

#include<math.h>

#include<stdlib.h>

#include<float.h>
#include<string.h>
#include<stdio.h>

#include<assert.h>
#include<limits.h>







#define GF_4CC(a,b,c,d) ((((u32)a)<<24)|(((u32)b)<<16)|(((u32)c)<<8)|((u32)d))
#define GF_ARRAY_LENGTH(a) (sizeof(a) / sizeof((a)[0]))
#define GF_LOG(_ll, _lm, __args)
#define GF_SAFEALLOC(__ptr, __struct) {\
		(__ptr) = (__struct *) gf_malloc(sizeof(__struct));\
		if (__ptr) {\
			memset((void *) (__ptr), 0, sizeof(__struct));\
		}\
	}
#define GF_SAFE_ALLOC_N(__ptr, __n, __struct) {\
		(__ptr) = (__struct *) gf_malloc( __n * sizeof(__struct));\
		if (__ptr) {\
			memset((void *) (__ptr), 0, __n * sizeof(__struct));\
		}\
	}
#define GPAC_DISABLE_REMOTERY 1

#define RMT_ENABLED 0
#define TIMESPEC_TO_FILETIME_OFFSET (((LONGLONG)27111902 << 32) + (LONGLONG)3577643008)

#define gf_rmt_begin rmt_BeginCPUSample
#define gf_rmt_begin_gl rmt_BeginOpenGLSample
#define gf_rmt_begin_gl_hash rmt_BeginOpenGLSampleStore
#define gf_rmt_begin_hash rmt_BeginCPUSampleStore
#define gf_rmt_end rmt_EndCPUSample
#define gf_rmt_end_gl rmt_EndOpenGLSample
#define gf_rmt_log_text rmt_LogText
#define gf_rmt_set_thread_name rmt_SetCurrentThreadName
#define gf_stringizer(x) #x
    #define IFDEF_RMT_ENABLED(t, f) t
    #define IFDEF_RMT_USE_CUDA(t, f) t
    #define IFDEF_RMT_USE_D3D11(t, f) t
    #define IFDEF_RMT_USE_METAL(t, f) t
    #define IFDEF_RMT_USE_OPENGL(t, f) t
            #define RMT_API __declspec(dllexport)
#define RMT_ASSUME_LITTLE_ENDIAN 0
#define RMT_D3D11_RESYNC_ON_DISJOINT 1
#define RMT_FALSE ((rmtBool)0)
#define RMT_GPU_CPU_SYNC_NUM_ITERATIONS 16
#define RMT_GPU_CPU_SYNC_SECONDS 30

#define RMT_OPTIONAL(macro, x) IFDEF_ ## macro(x, )
#define RMT_OPTIONAL_RET(macro, x, y) IFDEF_ ## macro(x, (y))




#define RMT_TRUE ((rmtBool)1)
#define RMT_USE_CUDA 0
#define RMT_USE_D3D11 0
#define RMT_USE_METAL 0
#define RMT_USE_OPENGL 0
#define RMT_USE_POSIX_THREADNAMES 0
#define RMT_USE_TINYCRT 0
#define rmt_BeginCPUSample(name, flags)                                             \
    RMT_OPTIONAL(RMT_ENABLED, {                                                     \
        static rmtU32 rmt_sample_hash_##name = 0;                                   \
        _rmt_BeginCPUSample(#name, flags, &rmt_sample_hash_##name);                 \
    })
#define rmt_BeginCPUSampleDynamic(namestr, flags)                                   \
    RMT_OPTIONAL(RMT_ENABLED, _rmt_BeginCPUSample(namestr, flags, NULL))
#define rmt_BeginCPUSampleStore(name, flags, hashptr)                                \
    RMT_OPTIONAL(RMT_ENABLED, {                                                     \
        _rmt_BeginCPUSample(name, flags, hashptr);                 \
    })
#define rmt_BeginCUDASample(name, stream)                                   \
    RMT_OPTIONAL(RMT_USE_CUDA, {                                            \
        static rmtU32 rmt_sample_hash_##name = 0;                           \
        _rmt_BeginCUDASample(#name, &rmt_sample_hash_##name, stream);       \
    })
#define rmt_BeginD3D11Sample(name)                                          \
    RMT_OPTIONAL(RMT_USE_D3D11, {                                           \
        static rmtU32 rmt_sample_hash_##name = 0;                           \
        _rmt_BeginD3D11Sample(#name, &rmt_sample_hash_##name);              \
    })
#define rmt_BeginD3D11SampleDynamic(namestr)                                \
    RMT_OPTIONAL(RMT_USE_D3D11, _rmt_BeginD3D11Sample(namestr, NULL))
#define rmt_BeginMetalSample(name)                                          \
    RMT_OPTIONAL(RMT_USE_METAL, {                                           \
        static rmtU32 rmt_sample_hash_##name = 0;                           \
        _rmt_BeginMetalSample(#name, &rmt_sample_hash_##name);              \
    })
#define rmt_BeginMetalSampleDynamic(namestr)                                \
    RMT_OPTIONAL(RMT_USE_METAL, _rmt_BeginMetalSample(namestr, NULL))
#define rmt_BeginOpenGLSample(name)                                         \
    RMT_OPTIONAL(RMT_USE_OPENGL, {                                          \
        static rmtU32 rmt_sample_hash_##name = 0;                           \
        _rmt_BeginOpenGLSample(#name, &rmt_sample_hash_##name);             \
    })
#define rmt_BeginOpenGLSampleDynamic(namestr)                               \
    RMT_OPTIONAL(RMT_USE_OPENGL, _rmt_BeginOpenGLSample(namestr, NULL))
#define rmt_BeginOpenGLSampleStore(name, hashptr)                                         \
    RMT_OPTIONAL(RMT_USE_OPENGL, {                                          \
        _rmt_BeginOpenGLSample(name, hashptr);             \
    })
#define rmt_BindCUDA(bind)                                                  \
    RMT_OPTIONAL(RMT_USE_CUDA, _rmt_BindCUDA(bind))
#define rmt_BindD3D11(device, context)                                      \
    RMT_OPTIONAL(RMT_USE_D3D11, _rmt_BindD3D11(device, context))
#define rmt_BindMetal(command_buffer)                                       \
    RMT_OPTIONAL(RMT_USE_METAL, _rmt_BindMetal(command_buffer));
#define rmt_BindOpenGL()                                                    \
    RMT_OPTIONAL(RMT_USE_OPENGL, _rmt_BindOpenGL())
#define rmt_CreateGlobalInstance(rmt)                                               \
    RMT_OPTIONAL_RET(RMT_ENABLED, _rmt_CreateGlobalInstance(rmt), RMT_ERROR_NONE)
#define rmt_DestroyGlobalInstance(rmt)                                              \
    RMT_OPTIONAL(RMT_ENABLED, _rmt_DestroyGlobalInstance(rmt))
#define rmt_EnableSampling(enable)                                                           \
    RMT_OPTIONAL(RMT_ENABLED, _rmt_EnableSampling(enable))
#define rmt_EndCPUSample()                                                          \
    RMT_OPTIONAL(RMT_ENABLED, _rmt_EndCPUSample())
#define rmt_EndCUDASample(stream)                                           \
    RMT_OPTIONAL(RMT_USE_CUDA, _rmt_EndCUDASample(stream))
#define rmt_EndD3D11Sample()                                                \
    RMT_OPTIONAL(RMT_USE_D3D11, _rmt_EndD3D11Sample())
#define rmt_EndMetalSample()                                                \
    RMT_OPTIONAL(RMT_USE_METAL, _rmt_EndMetalSample())
#define rmt_EndOpenGLSample()                                               \
    RMT_OPTIONAL(RMT_USE_OPENGL, _rmt_EndOpenGLSample())
#define rmt_GetGlobalInstance()                                                     \
    RMT_OPTIONAL_RET(RMT_ENABLED, _rmt_GetGlobalInstance(), NULL)
#define rmt_LogText(text)                                                           \
    RMT_OPTIONAL(RMT_ENABLED, _rmt_LogText(text))
#define rmt_SamplingEnabled()                                                           \
    RMT_OPTIONAL(RMT_ENABLED, _rmt_SamplingEnabled())
#define rmt_ScopedCPUSample(name, flags)                                                                \
        RMT_OPTIONAL(RMT_ENABLED, rmt_BeginCPUSample(name, flags));                                     \
        RMT_OPTIONAL(RMT_ENABLED, rmt_EndCPUSampleOnScopeExit rmt_ScopedCPUSample##name);
#define rmt_ScopedCUDASample(name, stream)                                                              \
        RMT_OPTIONAL(RMT_USE_CUDA, rmt_BeginCUDASample(name, stream));                                  \
        RMT_OPTIONAL(RMT_USE_CUDA, rmt_EndCUDASampleOnScopeExit rmt_ScopedCUDASample##name(stream));
#define rmt_ScopedD3D11Sample(name)                                                                     \
        RMT_OPTIONAL(RMT_USE_D3D11, rmt_BeginD3D11Sample(name));                                        \
        RMT_OPTIONAL(RMT_USE_D3D11, rmt_EndD3D11SampleOnScopeExit rmt_ScopedD3D11Sample##name);
#define rmt_ScopedMetalSample(name)                                                                     \
        RMT_OPTIONAL(RMT_USE_METAL, rmt_BeginMetalSample(name));                                        \
        RMT_OPTIONAL(RMT_USE_METAL, rmt_EndMetalSampleOnScopeExit rmt_ScopedMetalSample##name);
#define rmt_ScopedOpenGLSample(name)                                                                    \
        RMT_OPTIONAL(RMT_USE_OPENGL, rmt_BeginOpenGLSample(name));                                      \
        RMT_OPTIONAL(RMT_USE_OPENGL, rmt_EndOpenGLSampleOnScopeExit rmt_ScopedOpenGLSample##name);
#define rmt_SetCurrentThreadName(rmt)                                               \
    RMT_OPTIONAL(RMT_ENABLED, _rmt_SetCurrentThreadName(rmt))
#define rmt_SetGlobalInstance(rmt)                                                  \
    RMT_OPTIONAL(RMT_ENABLED, _rmt_SetGlobalInstance(rmt))
#define rmt_Settings()                                                              \
    RMT_OPTIONAL_RET(RMT_ENABLED, _rmt_Settings(), NULL )
#define rmt_UnbindD3D11()                                                   \
    RMT_OPTIONAL(RMT_USE_D3D11, _rmt_UnbindD3D11())
#define rmt_UnbindMetal()                                                   \
    RMT_OPTIONAL(RMT_USE_METAL, _rmt_UnbindMetal());
#define rmt_UnbindOpenGL()                                                  \
    RMT_OPTIONAL(RMT_USE_OPENGL, _rmt_UnbindOpenGL())
#define GPAC_VERSION          "1.1.0-DEV"
#define GPAC_VERSION_MAJOR 10
#define GPAC_VERSION_MICRO 0
#define GPAC_VERSION_MINOR 8
#define ABS(a)	( ( (a) > 0 ) ? (a) : - (a) )
#define ABSDIFF(a, b)	( ( (a) > (b) ) ? ((a) - (b)) : ((b) - (a)) )
#define GFINLINE inline
#define GF_EXPORT __attribute__((visibility("default")))

# define GPAC_DISABLE_BIFS
# define GPAC_DISABLE_BIFS_ENC
# define GPAC_DISABLE_ISOM_DUMP
# define GPAC_DISABLE_ISOM_FRAGMENTS
# define GPAC_DISABLE_ISOM_HINTING
# define GPAC_DISABLE_ISOM_WRITE
# define GPAC_DISABLE_LASER
# define GPAC_DISABLE_LOADER_BT
# define GPAC_DISABLE_LOADER_ISOM
# define GPAC_DISABLE_LOADER_XMT
# define GPAC_DISABLE_MEDIA_EXPORT
# define GPAC_DISABLE_MEDIA_IMPORT
# define GPAC_DISABLE_MPEG2PS
# define GPAC_DISABLE_QTVR
# define GPAC_DISABLE_SCENE_ENCODER
# define GPAC_DISABLE_SENG
# define GPAC_DISABLE_SWF_IMPORT
# define GPAC_DISABLE_X3D


#define LLD "%" LLD_SUF
#define LLD_SUF "lld"
#define LLU "%" LLU_SUF
#define LLU_SUF "llu"
#define LLX "%" LLX_SUF
#define LLX_SUF "llx"
#define MAX(X, Y) ((X)>(Y)?(X):(Y))
#define MIN(X, Y) ((X)<(Y)?(X):(Y))
#define NULL 0
#define PTRDIFF(p1, p2, type)	((p1) - (p2))
#define PTR_TO_U_CAST (u64)



#define assert( t )	CE_Assert((unsigned int) (t), "__FILE__", "__LINE__" )
#define getenv(a) 0L
#define gf_calloc(num, size_of) gf_mem_calloc(num, size_of, "__FILE__", "__LINE__")
#define gf_free(ptr) gf_mem_free(ptr, "__FILE__", "__LINE__")
#define gf_malloc(size) gf_mem_malloc(size, "__FILE__", "__LINE__")
#define gf_realloc(ptr1, size) gf_mem_realloc(ptr1, size, "__FILE__", "__LINE__")
#define gf_strdup(s) gf_mem_strdup(s, "__FILE__", "__LINE__")
#define memccpy _memccpy
#define mkdir _mkdir
#define offsetof(s,m) ((size_t)&(((s*)0)->m))
#define snprintf _snprintf
#define strdup _strdup
#define stricmp _stricmp
#define strlwr _strlwr
#define strnicmp _strnicmp
#define strupr _strupr


#define CAP_4CC(_f, _a, _b) { .code=_a, .val={.type=GF_PROP_4CC, .value.uint = _b}, .flags=(_f) }
#define CAP_BOOL(_f, _a, _b) { .code=_a, .val={.type=GF_PROP_BOOL, .value.boolean = _b}, .flags=(_f) }
#define CAP_DOUBLE(_f, _a, _b) { .code=_a, .val={.type=GF_PROP_DOUBLE, .value.number = _b}, .flags=(_f) }
#define CAP_FIXED(_f, _a, _b) { .code=_a, .val={.type=GF_PROP_FLOAT, .value.fnumber = _b}, .flags=(_f) }
#define CAP_FLOAT(_f, _a, _b) { .code=_a, .val={.type=GF_PROP_FLOAT, .value.fnumber = FLT2FIX(_b)}, .flags=(_f) }
#define CAP_FRAC(_f, _a, _b) { .code=_a, .val={.type=GF_PROP_FRACTION, .value.frac = _b}, .flags=(_f) }
#define CAP_FRAC_INT(_f, _a, _b, _c) { .code=_a, .val={.type=GF_PROP_FRACTION, .value.frac.num = _b, .value.frac.den = _c}, .flags=(_f) }
#define CAP_LSINT(_f, _a, _b) { .code=_a, .val={.type=GF_PROP_LSINT, .value.longsint = _b}, .flags=(_f) }
#define CAP_LUINT(_f, _a, _b) { .code=_a, .val={.type=GF_PROP_LUINT, .value.longuint = _b}, .flags=(_f) }
#define CAP_NAME(_f, _a, _b) { .code=_a, .val={.type=GF_PROP_NAME, .value.string = _b}, .flags=(_f) }
#define CAP_SINT(_f, _a, _b) { .code=_a, .val={.type=GF_PROP_SINT, .value.sint = _b}, .flags=(_f) }
#define CAP_STRING(_f, _a, _b) { .code=_a, .val={.type=GF_PROP_STRING, .value.string = _b}, .flags=(_f) }
#define CAP_UINT(_f, _a, _b) { .code=_a, .val={.type=GF_PROP_UINT, .value.uint = _b}, .flags=(_f) }
#define CAP_UINT_PRIORITY(_f, _a, _b, _p) { .code=_a, .val={.type=GF_PROP_UINT, .value.uint = _b}, .flags=(_f), .priority=_p}
#define FILTER_EVENT_BASE \
	GF_FEventType type; \
	GF_FilterPid *on_pid; \
	\

#define GF_FEVT_INIT(_a, _type, _on_pid)	{ memset(&_a, 0, sizeof(GF_FilterEvent)); _a.base.type = _type; _a.base.on_pid = _on_pid; }
#define GF_FILTER_NO_BO 0xFFFFFFFFFFFFFFFFUL
#define GF_FILTER_NO_TS 0xFFFFFFFFFFFFFFFFUL
#define GF_FILTER_PCK_CRYPT 1
#define GF_FS_DEF_ARG(_name, _offset, _desc, _type, _default, _enum, _flags) { _name, _offset, _desc, _type, _default, _enum, _flags }
#define GF_FS_FLAG_FULL_LINK (1<<11)
#define GF_FS_FLAG_NO_RESERVOIR (1<<10)

#define GF_FS_SET_AUTHOR(_author) .author = _author,
#define GF_FS_SET_DESCRIPTION(_desc) .description = _desc,
#define GF_FS_SET_HELP(_help) .help = _help,
#define GF_PROP_FLAG_GSF_REM 1<<1
#define GF_PROP_FLAG_PCK 1
#define PROP_4CC(_val) (GF_PropertyValue){.type=GF_PROP_4CC, .value.uint = _val}
#define PROP_BOOL(_val) (GF_PropertyValue){.type=GF_PROP_BOOL, .value.boolean = _val}
#define PROP_CONST_DATA(_val, _len) (GF_PropertyValue){.type=GF_PROP_CONST_DATA, .value.data.ptr = _val, .value.data.size = _len}
#define PROP_DATA(_val, _len) (GF_PropertyValue){.type=GF_PROP_DATA, .value.data.ptr = _val, .value.data.size=_len}
#define PROP_DATA_NO_COPY(_val, _len) (GF_PropertyValue){.type=GF_PROP_DATA_NO_COPY, .value.data.ptr = _val, .value.data.size =_len}
#define PROP_DOUBLE(_val) (GF_PropertyValue){.type=GF_PROP_DOUBLE, .value.number = _val}
#define PROP_ENUM(_val, _type) (GF_PropertyValue){.type=_type, .value.uint = _val}
#define PROP_FIXED(_val) (GF_PropertyValue){.type=GF_PROP_FLOAT, .value.fnumber = _val}
#define PROP_FLOAT(_val) (GF_PropertyValue){.type=GF_PROP_FLOAT, .value.fnumber = FLT2FIX(_val)}
#define PROP_FRAC(_val) (GF_PropertyValue){.type=GF_PROP_FRACTION, .value.frac = _val }
#define PROP_FRAC64(_val) (GF_PropertyValue){.type=GF_PROP_FRACTION64, .value.lfrac = _val}
#define PROP_FRAC64_INT(_num, _den) (GF_PropertyValue){.type=GF_PROP_FRACTION64, .value.lfrac.num = _num, .value.lfrac.den = _den}
#define PROP_FRAC_INT(_num, _den) (GF_PropertyValue){.type=GF_PROP_FRACTION, .value.frac.num = _num, .value.frac.den = _den}
#define PROP_LONGSINT(_val) (GF_PropertyValue){.type=GF_PROP_LSINT, .value.longsint = _val}
#define PROP_LONGUINT(_val) (GF_PropertyValue){.type=GF_PROP_LUINT, .value.longuint = _val}
#define PROP_NAME(_val) (GF_PropertyValue){.type=GF_PROP_NAME, .value.string = _val}
#define PROP_POINTER(_val) (GF_PropertyValue){.type=GF_PROP_POINTER, .value.ptr = (void*)_val}
#define PROP_SINT(_val) (GF_PropertyValue){.type=GF_PROP_SINT, .value.sint = _val}
#define PROP_STRING(_val) (GF_PropertyValue){.type=GF_PROP_STRING, .value.string = (char *) _val}
#define PROP_STRING_NO_COPY(_val) (GF_PropertyValue){.type=GF_PROP_STRING_NO_COPY, .value.string = _val}
#define PROP_UINT(_val) (GF_PropertyValue){.type=GF_PROP_UINT, .value.uint = _val}
#define PROP_VEC2(_val) (GF_PropertyValue){.type=GF_PROP_VEC2, .value.vec2 = _val}
#define PROP_VEC2I(_val) (GF_PropertyValue){.type=GF_PROP_VEC2I, .value.vec2i = _val}
#define PROP_VEC2I_INT(_x, _y) (GF_PropertyValue){.type=GF_PROP_VEC2I, .value.vec2i.x = _x, .value.vec2i.y = _y}
#define PROP_VEC3I(_val) (GF_PropertyValue){.type=GF_PROP_VEC3I, .value.vec3i = _val}
#define PROP_VEC3I_INT(_x, _y, _z) (GF_PropertyValue){.type=GF_PROP_VEC3I, .value.vec3i.x = _x, .value.vec3i.y = _y, .value.vec3i.z = _z}
#define PROP_VEC4I(_val) (GF_PropertyValue){.type=GF_PROP_VEC4I, .value.vec4i = _val}
#define PROP_VEC4I_INT(_x, _y, _z, _w) (GF_PropertyValue){.type=GF_PROP_VEC4I, .value.vec4i.x = _x, .value.vec4i.y = _y, .value.vec4i.z = _z, .value.vec4i.w = _w}
#define SETCAPS( __struct ) .caps = __struct, .nb_caps=sizeof(__struct)/sizeof(GF_FilterCapability)

#define GF_ARG_HINT_HIDE 		(1<<3)
#define GF_ARG_SUBSYS_AUDIO 		(1<<10)
#define GF_ARG_SUBSYS_CORE 		(1<<5)
#define GF_ARG_SUBSYS_FILTERS 	(1<<7)
#define GF_ARG_SUBSYS_HACKS 		(1<<13)
#define GF_ARG_SUBSYS_HTTP 		(1<<8)
#define GF_ARG_SUBSYS_LOG 		(1<<6)
#define GF_ARG_SUBSYS_RMT 		(1<<12)
#define GF_ARG_SUBSYS_TEXT 		(1<<11)
#define GF_ARG_SUBSYS_VIDEO 		(1<<9)
#define GF_DEF_ARG(_a, _b, _c, _d, _e, _f, _g) {_a, _b, _c, _d, _e, _f, _g}
#define GF_GPAC_ARG_BASE \
	 \
	const char *name; \
	 \
	const char *altname; \
	 \
	const char *description; \
	 \
	const char *val; \
	 \
	const char *values; \
	 \
	u16 type; \
	 \
	u16 flags; \

#define GF_MAIN_FUNC(__fun) \
int wmain( int argc, wchar_t** wargv )\
{\
	int i;\
	int res;\
	size_t len;\
	size_t res_len;\
	char **argv;\
	argv = (char **)malloc(argc*sizeof(wchar_t *));\
	for (i = 0; i < argc; i++) {\
		wchar_t *src_str = wargv[i];\
		len = UTF8_MAX_BYTES_PER_CHAR*gf_utf8_wcslen(wargv[i]);\
		argv[i] = (char *)malloc(len + 1);\
		res_len = gf_utf8_wcstombs(argv[i], len, (const unsigned short **) &src_str);\
		argv[i][res_len] = 0;\
		if (res_len > len) {\
			fprintf(stderr, "Length allocated for conversion of wide char to UTF-8 not sufficient\n");\
			return -1;\
		}\
	}\
	res = __fun(argc, argv);\
	for (i = 0; i < argc; i++) {\
		free(argv[i]);\
	}\
	free(argv);\
	return res;\
}





#define RFC6381_CODEC_NAME_SIZE_MAX 100


#define GF_MODULE_LOAD_STATIC(_name)			\
	gf_module_load_static(gf_register_module_##_name)
#define GF_MODULE_STATIC_DECLARE(_name)				\
	extern "C" GF_InterfaceRegister *gf_register_module_##_name()
#define GF_REGISTER_MODULE_INTERFACE(_ifce, _ifce_type, _ifce_name, _ifce_author) \
	_ifce->InterfaceType = _ifce_type;	\
	_ifce->module_name = _ifce_name ? _ifce_name : "unknown";	\
	_ifce->author_name = _ifce_author ? _ifce_author : "gpac distribution";	\
	
#define GPAC_MODULE_STATIC_DECLARATION(__name)	\
	GF_InterfaceRegister *gf_register_module_##__name()	{	\
		GF_InterfaceRegister *reg;	\
		GF_SAFEALLOC(reg, GF_InterfaceRegister);	\
		if (!reg) return NULL;\
		reg->name = "gsm_" #__name;	\
		reg->QueryInterfaces = QueryInterfaces;	\
		reg->LoadInterface = LoadInterface;	\
		reg->ShutdownInterface = ShutdownInterface;	\
		return reg;\
	}	\
 



#define FIX2FLT(v)		((Float)( ((Float)(v)) / ((Float) FIX_ONE)))
#define FIX2INT(v)		((s32)(((v)+((FIX_ONE>>1)))>>16))
#define FLT2FIX(v)		((Fixed) ((v) * FIX_ONE))
#define INT2FIX(v)		((Fixed)( ((s32) (v) ) << 16))

#define gf_mx2d_copy(_obj, from) memcpy((_obj).m, (from).m, sizeof(Fixed)*6)
#define gf_mx2d_init(_obj) { memset((_obj).m, 0, sizeof(Fixed)*6); (_obj).m[0] = (_obj).m[4] = FIX_ONE; }
#define gf_mx2d_is_identity(_obj) ((!(_obj).m[1] && !(_obj).m[2] && !(_obj).m[3] && !(_obj).m[5] && ((_obj).m[0]==FIX_ONE) && ((_obj).m[4]==FIX_ONE)) ? 1 : 0)
#define gf_mx_copy(_obj, from) memcpy(&(_obj), &(from), sizeof(GF_Matrix));
#define gf_mx_init(_obj) { memset((_obj).m, 0, sizeof(Fixed)*16); (_obj).m[0] = (_obj).m[5] = (_obj).m[10] = (_obj).m[15] = FIX_ONE; }
#define gf_mx_is_identity(_obj) ((!(_obj).m[1] && !(_obj).m[2] && !(_obj).m[3] && !(_obj).m[4] && !(_obj).m[6] && !(_obj).m[7] && !(_obj).m[8] && !(_obj).m[9] && !(_obj).m[11] && !(_obj).m[12] && !(_obj).m[13] && !(_obj).m[14] && ((_obj).m[0]==FIX_ONE) && ((_obj).m[5]==FIX_ONE)&& ((_obj).m[10]==FIX_ONE)&& ((_obj).m[15]==FIX_ONE)) ? 1 : 0)
#define gf_quat_len(v) gf_sqrt(gf_mulfix((v).q,(v).q) + gf_mulfix((v).x,(v).x) + gf_mulfix((v).y,(v).y) + gf_mulfix((v).z,(v).z))
#define gf_quat_norm(v) { \
	Fixed __mag = gf_quat_len(v);	\
	(v).x = gf_divfix((v).x, __mag); (v).y = gf_divfix((v).y, __mag); (v).z = gf_divfix((v).z, __mag); (v).q = gf_divfix((v).q, __mag);	\
	}	\
 
#define gf_vec_add(res, v1, v2) { (res).x = (v1).x + (v2).x; (res).y = (v1).y + (v2).y; (res).z = (v1).z + (v2).z; }
#define gf_vec_diff(res, v1, v2) { (res).x = (v1).x - (v2).x; (res).y = (v1).y - (v2).y; (res).z = (v1).z - (v2).z; }
#define gf_vec_equal(v1, v2) (((v1).x == (v2).x) && ((v1).y == (v2).y) && ((v1).z == (v2).z))
#define gf_vec_rev(v) { (v).x = -(v).x; (v).y = -(v).y; (v).z = -(v).z; }


#define BASE_DESCRIPTOR \
		u8 tag;
#define BASE_OD_COMMAND \
	u8 tag;
#define QOS_BASE_QUALIFIER \
	u8 tag;	\
	u32 size;




#define GF_COLW_A(c) (u16) ((c)>>48)
#define GF_COLW_B(c) (u16) ( (c) & 0xFFFF)
#define GF_COLW_G(c) (u16) ( ((c)>>16) & 0xFFFF)
#define GF_COLW_R(c) (u16) ( ((c)>>32) & 0xFFFF)
#define GF_COL_555(r, g, b) (u16) (((r & 248)<<7) + ((g & 248)<<2)  + (b>>3))
#define GF_COL_565(r, g, b) (u16) (((r & 248)<<8) + ((g & 252)<<3)  + (b>>3))
#define GF_COL_A(c) (u8) ((c)>>24)
#define GF_COL_ARGB(a, r, g, b) (((u32) a)<<24 | ((u32) r)<<16 | ((u32) g)<<8 | ((u32) b))
#define GF_COL_ARGB_FIXED(_a, _r, _g, _b) GF_COL_ARGB(FIX2INT(255*(_a)), FIX2INT(255*(_r)), FIX2INT(255*(_g)), FIX2INT(255*(_b)))
#define GF_COL_B(c) (u8) ( (c) & 0xFF)
#define GF_COL_G(c) (u8) ( ((c)>>8) & 0xFF)
#define GF_COL_R(c) (u8) ( ((c)>>16) & 0xFF)




#define BOX_FIELD_ASSIGN(_field, _box_cast) \
	if (is_rem) {\
		ptr->_field = NULL;\
		return GF_OK;\
	} else {\
		if (ptr->_field) ERROR_ON_DUPLICATED_BOX(a, ptr)\
		ptr->_field = (_box_cast *)a;\
	}
#define BOX_FIELD_LIST_ASSIGN(_field) \
	if (is_rem) {\
		gf_list_del_item(ptr->_field, a);\
	} else {\
		if (!ptr->_field) ptr->_field = gf_list_new();\
		GF_Err _e = gf_list_add(ptr->_field, a);\
		if (_e) return _e;\
	}
#define ERROR_ON_DUPLICATED_BOX(__abox, __parent) {	\
		char __ptype[GF_4CC_MSIZE];\
		strcpy(__ptype, gf_4cc_to_str(__parent->type) );\
		GF_LOG(GF_LOG_WARNING, GF_LOG_CONTAINER, ("[iso file] extra box %s found in %s, deleting\n", gf_4cc_to_str(__abox->type), __ptype)); \
		gf_isom_box_del_parent(& (__parent->child_boxes), __abox);\
		return GF_OK;\
	}
#define GF_ISOM_BOX_COMPRESSED 2
#define GF_ISOM_DATA_FILE         0x01
#define GF_ISOM_DATA_FILE_EXTERN  0x03
#define GF_ISOM_DATA_MEM          0x04
#define GF_ISOM_FORMAT_FRAG_FLAGS(pad, sync, deg) ( ( (pad) << 17) | ( ( !(sync) ) << 16) | (deg) );
#define GF_ISOM_GET_FRAG_DEG(flag)	(flag) & 0x7FFF
#define GF_ISOM_GET_FRAG_DEPENDED(flag) ( (flag) >> 22) & 0x3
#define GF_ISOM_GET_FRAG_DEPENDS(flag) ( (flag) >> 24) & 0x3
#define GF_ISOM_GET_FRAG_DEPEND_FLAGS(lead, depends, depended, redundant) ( (lead<<26) | (depends<<24) | (depended<<22) | (redundant<<20) )
#define GF_ISOM_GET_FRAG_LEAD(flag) ( (flag) >> 26) & 0x3
#define GF_ISOM_GET_FRAG_PAD(flag) ( (flag) >> 17) & 0x7
#define GF_ISOM_GET_FRAG_REDUNDANT(flag) ( (flag) >> 20) & 0x3
#define GF_ISOM_GET_FRAG_SYNC(flag) ( ! ( ( (flag) >> 16) & 0x1))
#define GF_ISOM_MAC_TIME_OFFSET 2082844800
#define GF_ISOM_ORDER_FREEZE 1
#define GF_ISOM_RESET_FRAG_DEPEND_FLAGS(flags) flags = flags & 0xFFFFF

#define ISOM_DECL_BOX_ALLOC(__TYPE, __4cc)	__TYPE *tmp; \
	GF_SAFEALLOC(tmp, __TYPE);	\
	if (tmp==NULL) return NULL;	\
	tmp->type = __4cc;
#define ISOM_DECREASE_SIZE(__ptr, bytes)	if (__ptr->size < (bytes) ) {\
			GF_LOG(GF_LOG_ERROR, GF_LOG_CONTAINER, ("[isom] not enough bytes in box %s: %d left, reading %d (file %s, line %d)\n", gf_4cc_to_str(__ptr->type), (u32) __ptr->size, (bytes), "__FILE__", "__LINE__" )); \
			return GF_ISOM_INVALID_FILE; \
		}\
		__ptr->size -= bytes; \

#define ISOM_DECREASE_SIZE_GOTO_EXIT(__ptr, bytes)	if (__ptr->size < (bytes) ) {\
			GF_LOG(GF_LOG_ERROR, GF_LOG_CONTAINER, ("[isom] not enough bytes in box %s: %d left, reading %d (file %s, line %d)\n", gf_4cc_to_str(__ptr->type), (u32) __ptr->size, (bytes), "__FILE__", "__LINE__" )); \
			e = GF_ISOM_INVALID_FILE; \
			goto exit;\
		}\
		__ptr->size -= bytes; \

#define ISOM_DECREASE_SIZE_NO_ERR(__ptr, bytes)	if (__ptr->size < (bytes) ) {\
			GF_LOG(GF_LOG_WARNING, GF_LOG_CONTAINER, ("[isom] not enough bytes in box %s: %d left, reading %d (file %s, line %d), skipping box\n", gf_4cc_to_str(__ptr->type), (u32) __ptr->size, (bytes), "__FILE__", "__LINE__" )); \
			return GF_OK; \
		}\
		__ptr->size -= bytes; \


#define AV1_MAX_TILE_COLS 64
#define AV1_MAX_TILE_ROWS 64
#define MAX_NUM_LAYER_SETS 1024
#define VP9_MAX_FRAMES_IN_SUPERFRAME 16
#define VVC_MAX_NUM_LAYER_SETS 1024



#define GF_NTP_SEC_1900_TO_1970 2208988800ul



