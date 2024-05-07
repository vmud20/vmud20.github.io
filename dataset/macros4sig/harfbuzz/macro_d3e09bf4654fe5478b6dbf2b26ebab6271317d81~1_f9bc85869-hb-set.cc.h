





#include<cstddef>





#include<cfloat>
#include<cstdlib>



#include<cstdio>

#include<pthread.h>








#include<cassert>
#include<cmath>
#include<climits>


#include<cstring>


#include<cstdarg>



# define DEFINE_COMPILES_ASSERTION(_code) _DEFINE_COMPILES_ASSERTION0 ("__LINE__", _code)
# define DEFINE_INSTANCE_ASSERTION(_assertion) _DEFINE_INSTANCE_ASSERTION0 ("__LINE__", _assertion)
#define DEFINE_SIZE_ARRAY(size, array) \
  DEFINE_COMPILES_ASSERTION ((void) (array)[0].static_size) \
  DEFINE_INSTANCE_ASSERTION (sizeof (*this) == (size) + (HB_VAR_ARRAY+0) * sizeof ((array)[0])) \
  static constexpr unsigned null_size = (size); \
  static constexpr unsigned min_size = (size)
#define DEFINE_SIZE_ARRAY_SIZED(size, array) \
  unsigned int get_size () const { return (size - (array).min_size + (array).get_size ()); } \
  DEFINE_SIZE_ARRAY(size, array)
#define DEFINE_SIZE_MIN(size) \
  DEFINE_INSTANCE_ASSERTION (sizeof (*this) >= (size)) \
  static constexpr unsigned null_size = (size); \
  static constexpr unsigned min_size = (size)
#define DEFINE_SIZE_STATIC(size) \
  DEFINE_INSTANCE_ASSERTION (sizeof (*this) == (size)) \
  unsigned int get_size () const { return (size); } \
  static constexpr unsigned null_size = (size); \
  static constexpr unsigned min_size = (size); \
  static constexpr unsigned static_size = (size)
#define DEFINE_SIZE_UNBOUNDED(size) \
  DEFINE_INSTANCE_ASSERTION (sizeof (*this) >= (size)) \
  static constexpr unsigned min_size = (size)
#define DEFINE_SIZE_UNION(size, _member) \
  DEFINE_COMPILES_ASSERTION ((void) this->u._member.static_size) \
  DEFINE_INSTANCE_ASSERTION (sizeof(this->u._member) == (size)) \
  static constexpr unsigned null_size = (size); \
  static constexpr unsigned min_size = (size)

#define HB_VAR_ARRAY 1
# define _DEFINE_COMPILES_ASSERTION0(_line, _code) _DEFINE_COMPILES_ASSERTION1 (_line, _code)
#define _DEFINE_COMPILES_ASSERTION1(_line, _code) \
  void _compiles_assertion_on_line_##_line () const \
  { _code; }
# define _DEFINE_INSTANCE_ASSERTION0(_line, _assertion) _DEFINE_INSTANCE_ASSERTION1 (_line, _assertion)
#define _DEFINE_INSTANCE_ASSERTION1(_line, _assertion) \
  void _instance_assertion_on_line_##_line () const \
  { static_assert ((_assertion), ""); }




#define HB_EXTERN __declspec (dllexport) extern
#  define HB_FALLTHROUGH [[clang::fallthrough]]
#define HB_FUNC __PRETTY_FUNCTION__


#  define HB_INTERNAL __attribute__((__visibility__("hidden")))
#  define HB_NODISCARD [[nodiscard]]
#      define HB_NO_ERRNO
#      define HB_NO_GETENV
#define HB_NO_SANITIZE_SIGNED_INTEGER_OVERFLOW __attribute__((no_sanitize("signed-integer-overflow")))
#      define HB_NO_SETLOCALE
#  define HB_NO_VISIBILITY 1

#define HB_PASTE(a,b) HB_PASTE1(a,b)
#define HB_PASTE1(a,b) a##b
#define HB_PRINTF_FUNC(format_idx, arg_idx) __attribute__((__format__ (__printf__, format_idx, arg_idx)))
#define HB_STMT_END   while (0)
#define HB_STMT_START do
#define HB_UNUSED __pragma(warning(suppress: 4100 4101))
#      define HB_USE_ATEXIT 1
#    define STRICT 1
#    define WIN32_LEAN_AND_MEAN 1
# define _ALL_SOURCE 1
# define _GNU_SOURCE 1
# define _POSIX_PTHREAD_SEMANTICS 1
# define _TANDEM_SOURCE 1
#      define _WIN32_WINNT 0x0600
# define __EXTENSIONS__ 1


#  define errno _hb_errno
#define getenv(Name) nullptr
#define hb_calloc calloc
#define hb_free free
#define hb_malloc malloc
#define hb_realloc realloc
#define likely(expr) (__builtin_expect (!!(expr), 1))
#    define snprintf _snprintf
#define static_const static
#define unlikely(expr) (__builtin_expect (!!(expr), 0))
#    define vsnprintf _vsnprintf


#define hb_mutex_impl_finish(M)	pthread_mutex_destroy (M)
#define hb_mutex_impl_init(M)	pthread_mutex_init (M, nullptr)
#define hb_mutex_impl_lock(M)	pthread_mutex_lock (M)
#define hb_mutex_impl_unlock(M)	pthread_mutex_unlock (M)
#define HB_AUTO_RETURN(E) -> decltype ((E)) { return (E); }
#define HB_DELETE_COPY_ASSIGN(TypeName) \
  TypeName(const TypeName&) = delete; \
  void operator=(const TypeName&) = delete
#define HB_DELETE_CREATE_COPY_ASSIGN(TypeName) \
  TypeName() = delete; \
  TypeName(const TypeName&) = delete; \
  void operator=(const TypeName&) = delete
#define HB_FUNCOBJ(x) static_const x HB_UNUSED

#define HB_RETURN(Ret, E) -> hb_head_t<Ret, decltype ((E))> { return (E); }
#define HB_VOID_RETURN(E) -> hb_void_t<decltype ((E))> { (E); }
#define hb_declval(T) (hb_declval<T> ())
#define hb_enable_if(Cond) typename hb_enable_if<(Cond)>::type* = nullptr
#define hb_int_max(T) hb_int_max<T>::value
#define hb_int_min(T) hb_int_min<T>::value
#define hb_is_arithmetic(T) hb_is_arithmetic<T>::value
#define hb_is_assignable(T,U) hb_is_assignable<T, U>::value
#define hb_is_base_of(Base,Derived) hb_is_base_of<Base, Derived>::value
#define hb_is_const(T) hb_match_const<T>::value
#define hb_is_constructible(...) hb_is_constructible<__VA_ARGS__>::value
#define hb_is_convertible(From,To) hb_is_convertible<From, To>::value
#define hb_is_copy_assignable(T) hb_is_copy_assignable<T>::value
#define hb_is_copy_constructible(T) hb_is_copy_constructible<T>::value
#define hb_is_cr_convertible(From,To) hb_is_cr_convertible<From, To>::value
#define hb_is_default_constructible(T) hb_is_default_constructible<T>::value
#define hb_is_destructible(T) hb_is_destructible<T>::value
#define hb_is_floating_point(T) hb_is_floating_point<T>::value
#define hb_is_integral(T) hb_is_integral<T>::value
#define hb_is_move_assignable(T) hb_is_move_assignable<T>::value
#define hb_is_move_constructible(T) hb_is_move_constructible<T>::value
#define hb_is_pointer(T) hb_match_pointer<T>::value
#define hb_is_reference(T) hb_match_reference<T>::value
#define hb_is_same(T, T2) hb_is_same<T, T2>::value
#define hb_is_signed(T) hb_is_signed<T>::value
#define hb_is_trivial(T) hb_is_trivial<T>::value
#define hb_is_trivially_copy_assignable(T) hb_is_trivially_copy_assignable<T>::value
#define hb_is_trivially_copy_constructible(T) hb_is_trivially_copy_constructible<T>::value
#define hb_is_trivially_copyable(T) hb_is_trivially_copyable<T>::value
#define hb_is_trivially_default_constructible(T) hb_is_trivially_default_constructible<T>::value
#define hb_is_trivially_destructible(T) hb_is_trivially_destructible<T>::value
#define hb_is_trivially_move_assignable(T) hb_is_trivially_move_assignable<T>::value
#define hb_is_trivially_move_constructible(T) hb_is_trivially_move_constructible<T>::value
#define hb_is_unsigned(T) hb_is_unsigned<T>::value
#define hb_prioritize hb_priority<16> ()
#define hb_requires(Cond) hb_enable_if((Cond))
#define hb_unwrap_type(T) typename hb_unwrap_type<T>::type
#define static_assert_expr(C) static_assert_expr<C>::value





#define HB_VERSION_ATLEAST(major,minor,micro) \
	((major)*10000+(minor)*100+(micro) <= \
	 HB_VERSION_MAJOR*10000+HB_VERSION_MINOR*100+HB_VERSION_MICRO)

#define HB_VERSION_MAJOR 2
#define HB_VERSION_MICRO 0
#define HB_VERSION_MINOR 9
#define HB_VERSION_STRING "2.9.0"
#  define HB_BEGIN_DECLS
#define HB_COLOR(b,g,r,a) ((hb_color_t) HB_TAG ((b),(g),(r),(a)))

#define HB_DEPRECATED __attribute__((__deprecated__))
#define HB_DEPRECATED_FOR(f) __attribute__((__deprecated__("Use '" #f "' instead")))
#define HB_DIRECTION_IS_BACKWARD(dir)	((((unsigned int) (dir)) & ~2U) == 5)
#define HB_DIRECTION_IS_FORWARD(dir)	((((unsigned int) (dir)) & ~2U) == 4)
#define HB_DIRECTION_IS_HORIZONTAL(dir)	((((unsigned int) (dir)) & ~1U) == 4)
#define HB_DIRECTION_IS_VALID(dir)	((((unsigned int) (dir)) & ~3U) == 4)
#define HB_DIRECTION_IS_VERTICAL(dir)	((((unsigned int) (dir)) & ~1U) == 6)
#define HB_DIRECTION_REVERSE(dir)	((hb_direction_t) (((unsigned int) (dir)) ^ 1))
#  define HB_END_DECLS
#define HB_LANGUAGE_INVALID ((hb_language_t) 0)
#define HB_TAG(c1,c2,c3,c4) ((hb_tag_t)((((uint32_t)(c1)&0xFF)<<24)|(((uint32_t)(c2)&0xFF)<<16)|(((uint32_t)(c3)&0xFF)<<8)|((uint32_t)(c4)&0xFF)))
#define HB_TAG_MAX HB_TAG(0xff,0xff,0xff,0xff)
#define HB_TAG_MAX_SIGNED HB_TAG(0x7f,0xff,0xff,0xff)
#define HB_TAG_NONE HB_TAG(0,0,0,0)
#define HB_UNTAG(tag)   (uint8_t)(((tag)>>24)&0xFF), (uint8_t)(((tag)>>16)&0xFF), (uint8_t)(((tag)>>8)&0xFF), (uint8_t)((tag)&0xFF)
#define hb_color_get_alpha(color)	((color) & 0xFF)
#define hb_color_get_blue(color)	(((color) >> 24) & 0xFF)
#define hb_color_get_green(color)	(((color) >> 16) & 0xFF)
#define hb_color_get_red(color)		(((color) >> 8) & 0xFF)

#define HB_UNICODE_MAX 0x10FFFFu






#define HB_SET_VALUE_INVALID ((hb_codepoint_t) -1)



#define HB_BUFFER_REPLACEMENT_CODEPOINT_DEFAULT 0xFFFDu
#define HB_SEGMENT_PROPERTIES_DEFAULT {HB_DIRECTION_INVALID, \
				       HB_SCRIPT_INVALID, \
				       HB_LANGUAGE_INVALID, \
				       (void *) 0, \
				       (void *) 0}
#define hb_glyph_info_get_glyph_flags(info) \
	((hb_glyph_flags_t) ((unsigned int) (info)->mask & HB_GLYPH_FLAG_DEFINED))

#define HB_MAP_VALUE_INVALID ((hb_codepoint_t) -1)

#define HB_UNICODE_MAX_DECOMPOSITION_LEN (18+1) 





#define HB_OT_MATH_SCRIPT HB_TAG('m','a','t','h')
#define HB_OT_TAG_MATH HB_TAG('M','A','T','H')

#define HB_OT_TAG_BASE HB_TAG('B','A','S','E')
#define HB_OT_TAG_GDEF HB_TAG('G','D','E','F')
#define HB_OT_TAG_GPOS HB_TAG('G','P','O','S')
#define HB_OT_TAG_GSUB HB_TAG('G','S','U','B')
#define HB_OT_TAG_JSTF HB_TAG('J','S','T','F')

#define HB_MATH_GLYPH_PART_FLAG_EXTENDER HB_OT_MATH_GLYPH_PART_FLAG_EXTENDER






























































#define HB_SANITIZE_MAX_EDITS 32
#define HB_SANITIZE_MAX_OPS_FACTOR 64
#define HB_SANITIZE_MAX_OPS_MAX 0x3FFFFFFF
#define HB_SANITIZE_MAX_OPS_MIN 16384
#define HB_SANITIZE_MAX_SUBTABLES 0x4000


