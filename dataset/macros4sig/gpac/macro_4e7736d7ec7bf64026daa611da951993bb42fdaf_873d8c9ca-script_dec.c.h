#include<string.h>
#include<time.h>
#include<stdarg.h>


#include<stdint.h>
#include<stdio.h>
#include<ctype.h>



#include<assert.h>

#include<stdlib.h>




#include<limits.h>

#include<float.h>
#include<stddef.h>

#include<math.h>


#define GF_BIFS_WRITE_INT(codec, bs, val, nbBits, str, com)	{\
		gf_bs_write_int(bs, val, nbBits);	\
		GF_LOG(GF_LOG_DEBUG, GF_LOG_CODING, ("[BIFS] %s\t\t%d\t\t%d\t\t%s\n", str, nbBits, val, com ? com : "") );	\
	} \
 



#define GF_NTP_SEC_1900_TO_1970 2208988800ul

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
#define GPAC_VERSION          "2.1-DEV"
#define GPAC_VERSION_MAJOR 12
#define GPAC_VERSION_MICRO 0
#define GPAC_VERSION_MINOR 0
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




#define safe_int64_add(__v, inc_val) InterlockedAdd64((LONG64 *) (__v), inc_val)
#define safe_int64_sub(__v, dec_val) InterlockedAdd64((LONG64 *) (__v), -dec_val)
#define safe_int_add(__v, inc_val) InterlockedAdd((int *) (__v), inc_val)
#define safe_int_dec(__v) InterlockedDecrement((int *) (__v))
#define safe_int_inc(__v) InterlockedIncrement((int *) (__v))
#define safe_int_sub(__v, dec_val) InterlockedAdd((int *) (__v), -dec_val)
#define GF_DOM_BASE_LISTENER 	\
	 \
	struct js_handler_context *js_data;\
	 \
	char *callback; \
	 \
	GF_Node *timed_elt;

#define GF_SMIL_TIME_IS_CLOCK(v) (v<=GF_SMIL_TIME_EVENT_RESOLVED)
#define GF_SMIL_TIME_IS_SPECIFIED_CLOCK(v) (v<GF_SMIL_TIME_EVENT_RESOLVED)
#define USE_GF_PATH 1



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




