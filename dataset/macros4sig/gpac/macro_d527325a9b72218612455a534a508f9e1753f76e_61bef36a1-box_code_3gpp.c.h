#include<assert.h>
#include<stdint.h>
#include<ctype.h>
#include<time.h>
#include<stdio.h>

#include<limits.h>
#include<string.h>
#include<float.h>
#include<stdlib.h>

#include<stddef.h>

#include<stdarg.h>
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
#define GPAC_VERSION_MINOR 7
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



#define BASE_DESCRIPTOR \
		u8 tag;
#define BASE_OD_COMMAND \
	u8 tag;
#define QOS_BASE_QUALIFIER \
	u8 tag;	\
	u32 size;




