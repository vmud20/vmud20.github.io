





























































































#define FOLLY_AARCH64 1
#define FOLLY_APPLE_IOS 1
#define FOLLY_APPLE_MACOS 1
#define FOLLY_APPLE_TVOS 1
#define FOLLY_APPLE_WATCHOS 1
#define FOLLY_ARM 1
#define FOLLY_CLANG_DISABLE_WARNING(warningName) \
  FOLLY_GNU_DISABLE_WARNING(warningName)
#define FOLLY_CORO_AWAIT_SUSPEND_NONTRIVIAL_ATTRIBUTES FOLLY_NOINLINE
#define FOLLY_CPLUSPLUS _MSVC_LANG
#define FOLLY_GCC_DISABLE_NEW_SHADOW_WARNINGS            \
  FOLLY_GNU_DISABLE_WARNING("-Wshadow-compatible-local") \
  FOLLY_GNU_DISABLE_WARNING("-Wshadow-local")            \
  FOLLY_GNU_DISABLE_WARNING("-Wshadow")

#define FOLLY_GLIBCXX_NAMESPACE_CXX11_BEGIN \
  inline _GLIBCXX_BEGIN_NAMESPACE_CXX11
#define FOLLY_GLIBCXX_NAMESPACE_CXX11_END _GLIBCXX_END_NAMESPACE_CXX11
#define FOLLY_GNU_DISABLE_WARNING(warningName) \
  _Pragma(                                     \
      FOLLY_GNU_DISABLE_WARNING_INTERNAL2(GCC diagnostic ignored warningName))
#define FOLLY_GNU_DISABLE_WARNING_INTERNAL2(warningName) #warningName
#define FOLLY_HAS_COROUTINES 0
#define FOLLY_HAS_EXCEPTIONS 1
#define FOLLY_HAS_INLINE_VARIABLES 1
#define FOLLY_HAS_RTTI 1
#define FOLLY_HAS_STRING_VIEW 1
#define FOLLY_HAVE_NOEXCEPT_FUNCTION_TYPE 1
#define FOLLY_INLINE_VARIABLE inline

#define FOLLY_NAMESPACE_STD_BEGIN _LIBCPP_BEGIN_NAMESPACE_STD
#define FOLLY_NAMESPACE_STD_END _LIBCPP_END_NAMESPACE_STD
#define FOLLY_NEON 1
#define FOLLY_NODISCARD [[nodiscard]]
#define FOLLY_PACK_ATTR 
#define FOLLY_PACK_POP __pragma(pack(pop))
#define FOLLY_PACK_PUSH __pragma(pack(push, 1))
#define FOLLY_POP_WARNING _Pragma("GCC diagnostic pop")
#define FOLLY_PPC64 1
#define FOLLY_PRINTF_FORMAT _Printf_format_string_
#define FOLLY_PRINTF_FORMAT_ATTR(format_param, dots_param) 
#define FOLLY_PUSH_WARNING _Pragma("GCC diagnostic push")
#define FOLLY_S390X 1
#define FOLLY_SSE 4
#define FOLLY_SSE_MINOR 2
#define FOLLY_SSE_PREREQ(major, minor) \
  (FOLLY_SSE > major || FOLLY_SSE == major && FOLLY_SSE_MINOR >= minor)
#define FOLLY_SSSE 3
#define FOLLY_STATIC_CTOR_PRIORITY_MAX __attribute__((__init_priority__(102)))
#define FOLLY_STORAGE_CONSTEXPR constexpr

#define FOLLY_X64 1
#define _USE_ATTRIBUTES_FOR_SAL 1
#define __PRETTY_FUNCTION__ __FUNCSIG__
#define __SSE4_2__ 1

#define HAVE_MODE_T 1
#define FOLLY_ALWAYS_INLINE __forceinline
#define FOLLY_ATTR_VISIBILITY_HIDDEN __attribute__((__visibility__("hidden")))
#define FOLLY_ATTR_WEAK __attribute__((__weak__))
#define FOLLY_DISABLE_ADDRESS_SANITIZER \
  __attribute__((__no_sanitize__("address"), __noinline__))
#define FOLLY_DISABLE_MEMORY_SANITIZER \
  __attribute__((no_sanitize_memory, noinline))
#define FOLLY_DISABLE_SANITIZERS                                 \
  FOLLY_DISABLE_ADDRESS_SANITIZER FOLLY_DISABLE_THREAD_SANITIZER \
      FOLLY_DISABLE_UNDEFINED_BEHAVIOR_SANITIZER("undefined")
#define FOLLY_DISABLE_THREAD_SANITIZER \
  __attribute__((no_sanitize_thread, noinline))
#define FOLLY_DISABLE_UNDEFINED_BEHAVIOR_SANITIZER(...) \
  __attribute__((no_sanitize(__VA_ARGS__)))
#define FOLLY_ERASE FOLLY_ALWAYS_INLINE FOLLY_ATTR_VISIBILITY_HIDDEN
#define FOLLY_ERASE_HACK_GCC FOLLY_ALWAYS_INLINE
#define FOLLY_ERASE_TRYCATCH inline
#define FOLLY_EXPORT __attribute__((__visibility__("default")))
#define FOLLY_HAS_BUILTIN(...) __has_builtin(__VA_ARGS__)
#define FOLLY_HAS_FEATURE(...) __has_feature(__VA_ARGS__)
#define FOLLY_MICROSOFT_ABI_VER _MSC_VER
#define FOLLY_NOINLINE __declspec(noinline)
#define FOLLY_SANITIZE 1
#define FOLLY_SANITIZE_ADDRESS 1
#define FOLLY_SANITIZE_MEMORY 1
#define FOLLY_SANITIZE_THREAD 1
#define __CLANG_PREREQ(maj, min) \
  ((__clang_major__ << 16) + __clang_minor__ >= ((maj) << 16) + (min))
#define __GNUC_PREREQ(maj, min) \

#define FOLLY_MALLOC_CHECKED_MALLOC \
  __attribute__((__returns_nonnull__, __malloc__))
#define MALLOCX_LG_ALIGN(la) (la)
#define MALLOCX_ZERO (static_cast<int>(0x40))
#define FOLLY_TYPE_INFO_OF(...) (&typeid(__VA_ARGS__))
#define FOLLY_ATTR_NO_UNIQUE_ADDRESS [[no_unique_address]]
#define FOLLY_COLD __attribute__((__cold__))
#define FOLLY_FALLTHROUGH [[fallthrough]]
#define FOLLY_HAS_ATTRIBUTE(x) 0
#define FOLLY_HAS_CPP_ATTRIBUTE(x) 0
#define FOLLY_HAS_EXTENSION(x) 0
#define FOLLY_MAYBE_UNUSED [[maybe_unused]]
#define FOLLY_NONNULL                                    \
  FOLLY_PUSH_WARNING                                     \
  FOLLY_CLANG_DISABLE_WARNING("-Wnullability-extension") \
  _Nonnull FOLLY_POP_WARNING
#define FOLLY_NULLABLE                                   \
  FOLLY_PUSH_WARNING                                     \
  FOLLY_CLANG_DISABLE_WARNING("-Wnullability-extension") \
  _Nullable FOLLY_POP_WARNING
#define FOLLY_DECLVAL(...) static_cast<__VA_ARGS__ (*)() noexcept>(nullptr)()
#define FOLLY_ASSUME_FBVECTOR_COMPATIBLE(...) \
  namespace folly {                           \
  template <>                                 \
  FOLLY_ASSUME_RELOCATABLE(__VA_ARGS__);      \
  }
#define FOLLY_ASSUME_FBVECTOR_COMPATIBLE_1(...) \
  namespace folly {                             \
  template <class T1>                           \
  FOLLY_ASSUME_RELOCATABLE(__VA_ARGS__<T1>);    \
  }
#define FOLLY_ASSUME_FBVECTOR_COMPATIBLE_2(...)  \
  namespace folly {                              \
  template <class T1, class T2>                  \
  FOLLY_ASSUME_RELOCATABLE(__VA_ARGS__<T1, T2>); \
  }
#define FOLLY_ASSUME_FBVECTOR_COMPATIBLE_3(...)      \
  namespace folly {                                  \
  template <class T1, class T2, class T3>            \
  FOLLY_ASSUME_RELOCATABLE(__VA_ARGS__<T1, T2, T3>); \
  }
#define FOLLY_ASSUME_FBVECTOR_COMPATIBLE_4(...)          \
  namespace folly {                                      \
  template <class T1, class T2, class T3, class T4>      \
  FOLLY_ASSUME_RELOCATABLE(__VA_ARGS__<T1, T2, T3, T4>); \
  }
#define FOLLY_ASSUME_RELOCATABLE(...) \
  struct IsRelocatable<__VA_ARGS__> : std::true_type {}
#define FOLLY_HAS_TRUE_XXX(name)                                             \
  template <typename T>                                                      \
  using detect_##name = typename T::name;                                    \
  template <class T>                                                         \
  struct name##_is_true : std::is_same<typename T::name, std::true_type> {}; \
  template <class T>                                                         \
  struct has_true_##name : std::conditional<                                 \
                               is_detected_v<detect_##name, T>,              \
                               name##_is_true<T>,                            \
                               std::false_type>::type {}
#define FB_GEN(sz, fn)                                                      \
  static inline uint##sz##_t byteswap_gen(uint##sz##_t v) { return fn(v); } \
  template <>                                                               \
  struct uint_types_by_size<sz / 8> {                                       \
    using type = uint##sz##_t;                                              \
  };
#define FB_GEN1(fn, t, sz) \
  static t fn##sz(t x) { return fn<t>(x); }
#define FB_GEN2(t, sz) \
  FB_GEN1(swap, t, sz) \
  FB_GEN1(big, t, sz)  \
  FB_GEN1(little, t, sz)
#define FOLLY_DETAILFOLLY_DETAIL_MSC_BUILTIN_SUPPORT 1
#define FOLLY_DETAIL_BUILTIN_EXPECT(b, t) (__builtin_expect(b, t))
#define FOLLY_LIKELY(...) FOLLY_DETAIL_BUILTIN_EXPECT((__VA_ARGS__), 1)
#define FOLLY_UNLIKELY(...) FOLLY_DETAIL_BUILTIN_EXPECT((__VA_ARGS__), 0)
#define LIKELY(x) (__builtin_expect((x), 1))
#define UNLIKELY(x) (__builtin_expect((x), 0))
#define IOV_MAX UIO_MAXIOV
#define UIO_MAXIOV 16
#define FOLLY_DETAIL_CPUID_B(name, bit) FOLLY_DETAIL_CPUID_X(name, f7b_, bit)
#define FOLLY_DETAIL_CPUID_C(name, bit) FOLLY_DETAIL_CPUID_X(name, f1c_, bit)
#define FOLLY_DETAIL_CPUID_D(name, bit) FOLLY_DETAIL_CPUID_X(name, f1d_, bit)
#define FOLLY_DETAIL_CPUID_X(name, r, bit) \
  FOLLY_ALWAYS_INLINE bool name() const { return ((r) & (1U << bit)) != 0; }
#define FOLLY_DETAIL_STRCMP __builtin_strcmp
#define FOLLY_DETAIL_STRLEN __builtin_strlen
#define FOLLY_CREATE_FREE_INVOKER(classname, funcname, ...)                \
  namespace classname##__folly_detail_invoke_ns {                          \
    FOLLY_MAYBE_UNUSED void funcname(                                      \
        ::folly::detail::invoke_private_overload&);                        \
    FOLLY_DETAIL_CREATE_FREE_INVOKE_TRAITS_USING(_, funcname, __VA_ARGS__) \
    struct __folly_detail_invoke_obj {                                     \
      template <typename... Args>                                          \
      FOLLY_MAYBE_UNUSED FOLLY_ERASE_HACK_GCC constexpr auto operator()(   \
          Args&&... args) const                                            \
          noexcept(noexcept(funcname(static_cast<Args&&>(args)...)))       \
              -> decltype(funcname(static_cast<Args&&>(args)...)) {        \
        return funcname(static_cast<Args&&>(args)...);                     \
      }                                                                    \
    };                                                                     \
  }                                                                        \
  struct classname                                                         \
      : classname##__folly_detail_invoke_ns::__folly_detail_invoke_obj {}
#define FOLLY_CREATE_FREE_INVOKER_SUITE(membername, ...)               \
  FOLLY_CREATE_FREE_INVOKER(membername##_fn, membername, __VA_ARGS__); \
  FOLLY_MAYBE_UNUSED FOLLY_INLINE_VARIABLE constexpr membername##_fn   \
      membername {}
#define FOLLY_CREATE_MEMBER_INVOKER(classname, membername)                 \
  struct classname {                                                       \
    template <typename O, typename... Args>                                \
    FOLLY_MAYBE_UNUSED FOLLY_ERASE_HACK_GCC constexpr auto operator()(     \
        O&& o, Args&&... args) const                                       \
        noexcept(noexcept(                                                 \
            static_cast<O&&>(o).membername(static_cast<Args&&>(args)...))) \
            -> decltype(static_cast<O&&>(o).membername(                    \
                static_cast<Args&&>(args)...)) {                           \
      return static_cast<O&&>(o).membername(static_cast<Args&&>(args)...); \
    }                                                                      \
  }
#define FOLLY_CREATE_MEMBER_INVOKER_SUITE(membername)                \
  FOLLY_CREATE_MEMBER_INVOKER(membername##_fn, membername);          \
  FOLLY_MAYBE_UNUSED FOLLY_INLINE_VARIABLE constexpr membername##_fn \
      membername {}
#define FOLLY_CREATE_STATIC_MEMBER_INVOKER(classname, membername)             \
  template <typename T>                                                       \
  struct classname {                                                          \
    template <typename... Args, typename U = T>                               \
    FOLLY_MAYBE_UNUSED FOLLY_ERASE constexpr auto operator()(Args&&... args)  \
        const noexcept(noexcept(U::membername(static_cast<Args&&>(args)...))) \
            -> decltype(U::membername(static_cast<Args&&>(args)...)) {        \
      return U::membername(static_cast<Args&&>(args)...);                     \
    }                                                                         \
  }
#define FOLLY_CREATE_STATIC_MEMBER_INVOKER_SUITE(membername)            \
  FOLLY_CREATE_STATIC_MEMBER_INVOKER(membername##_fn, membername);      \
  template <typename T>                                                 \
  FOLLY_MAYBE_UNUSED FOLLY_INLINE_VARIABLE constexpr membername##_fn<T> \
      membername {}
#define FOLLY_DETAIL_CREATE_FREE_INVOKE_TRAITS_USING(_, funcname, ...) \
  BOOST_PP_EXPR_IIF(                                                   \
      BOOST_PP_NOT(BOOST_PP_IS_EMPTY(__VA_ARGS__)),                    \
      BOOST_PP_LIST_FOR_EACH(                                          \
          FOLLY_DETAIL_CREATE_FREE_INVOKE_TRAITS_USING_1,              \
          funcname,                                                    \
          BOOST_PP_TUPLE_TO_LIST((__VA_ARGS__))))
#define FOLLY_DETAIL_CREATE_FREE_INVOKE_TRAITS_USING_1(_, funcname, ns) \
  using ns::funcname;
#define FOLLY_DEFINE_CPO(Type, Name) \
  namespace folly_cpo__ {            \
  inline constexpr Type Name{};      \
  }                                  \
  using namespace folly_cpo__;
#define FB_ANONYMOUS_VARIABLE(str) FB_CONCATENATE(str, __COUNTER__)
#define FB_ARG_1(a, ...) a
#define FB_ARG_2_OR_1(...) FB_ARG_2_OR_1_IMPL(__VA_ARGS__, __VA_ARGS__)
#define FB_ARG_2_OR_1_IMPL(a, b, ...) b
#define FB_CONCATENATE(s1, s2) FB_CONCATENATE_IMPL(s1, s2)
#define FB_CONCATENATE_IMPL(s1, s2) s1##s2
#define FB_ONE_OR_NONE(a, ...) FB_VA_GLUE(FB_THIRD, (a, ##__VA_ARGS__, a))
#define FB_SINGLE_ARG(...) __VA_ARGS__
#define FB_THIRD(a, b, ...) __VA_ARGS__
#define FB_VA_GLUE(a, b) a b

#define FOLLY_PP_DETAIL_APPEND_VA_ARG(...) , ##__VA_ARGS__
#define FOLLY_PP_DETAIL_FOR_EACH_1(fn, n, ...) \
  FOLLY_PP_DETAIL_FOR_EACH_2(fn, n, __VA_ARGS__)
#define FOLLY_PP_DETAIL_FOR_EACH_2(fn, n, ...) \
  FOLLY_PP_DETAIL_FOR_EACH_REC_##n(fn, __VA_ARGS__)
#define FOLLY_PP_DETAIL_FOR_EACH_REC_0(fn, ...)
#define FOLLY_PP_DETAIL_FOR_EACH_REC_1(fn, a, ...) \
  fn(a) FOLLY_PP_DETAIL_FOR_EACH_REC_0(fn, __VA_ARGS__)
#define FOLLY_PP_DETAIL_FOR_EACH_REC_10(fn, a, ...) \
  fn(a) FOLLY_PP_DETAIL_FOR_EACH_REC_9(fn, __VA_ARGS__)
#define FOLLY_PP_DETAIL_FOR_EACH_REC_11(fn, a, ...) \
  fn(a) FOLLY_PP_DETAIL_FOR_EACH_REC_10(fn, __VA_ARGS__)
#define FOLLY_PP_DETAIL_FOR_EACH_REC_12(fn, a, ...) \
  fn(a) FOLLY_PP_DETAIL_FOR_EACH_REC_11(fn, __VA_ARGS__)
#define FOLLY_PP_DETAIL_FOR_EACH_REC_13(fn, a, ...) \
  fn(a) FOLLY_PP_DETAIL_FOR_EACH_REC_12(fn, __VA_ARGS__)
#define FOLLY_PP_DETAIL_FOR_EACH_REC_14(fn, a, ...) \
  fn(a) FOLLY_PP_DETAIL_FOR_EACH_REC_13(fn, __VA_ARGS__)
#define FOLLY_PP_DETAIL_FOR_EACH_REC_15(fn, a, ...) \
  fn(a) FOLLY_PP_DETAIL_FOR_EACH_REC_14(fn, __VA_ARGS__)
#define FOLLY_PP_DETAIL_FOR_EACH_REC_2(fn, a, ...) \
  fn(a) FOLLY_PP_DETAIL_FOR_EACH_REC_1(fn, __VA_ARGS__)
#define FOLLY_PP_DETAIL_FOR_EACH_REC_3(fn, a, ...) \
  fn(a) FOLLY_PP_DETAIL_FOR_EACH_REC_2(fn, __VA_ARGS__)
#define FOLLY_PP_DETAIL_FOR_EACH_REC_4(fn, a, ...) \
  fn(a) FOLLY_PP_DETAIL_FOR_EACH_REC_3(fn, __VA_ARGS__)
#define FOLLY_PP_DETAIL_FOR_EACH_REC_5(fn, a, ...) \
  fn(a) FOLLY_PP_DETAIL_FOR_EACH_REC_4(fn, __VA_ARGS__)
#define FOLLY_PP_DETAIL_FOR_EACH_REC_6(fn, a, ...) \
  fn(a) FOLLY_PP_DETAIL_FOR_EACH_REC_5(fn, __VA_ARGS__)
#define FOLLY_PP_DETAIL_FOR_EACH_REC_7(fn, a, ...) \
  fn(a) FOLLY_PP_DETAIL_FOR_EACH_REC_6(fn, __VA_ARGS__)
#define FOLLY_PP_DETAIL_FOR_EACH_REC_8(fn, a, ...) \
  fn(a) FOLLY_PP_DETAIL_FOR_EACH_REC_7(fn, __VA_ARGS__)
#define FOLLY_PP_DETAIL_FOR_EACH_REC_9(fn, a, ...) \
  fn(a) FOLLY_PP_DETAIL_FOR_EACH_REC_8(fn, __VA_ARGS__)
#define FOLLY_PP_DETAIL_NARGS(...) \
  FOLLY_PP_DETAIL_NARGS_1(         \
      dummy,                       \
      ##__VA_ARGS__,               \
      15,                          \
      14,                          \
      13,                          \
      12,                          \
      11,                          \
      10,                          \
      9,                           \
      8,                           \
      7,                           \
      6,                           \
      5,                           \
      4,                           \
      3,                           \
      2,                           \
      1,                           \
      0)
#define FOLLY_PP_DETAIL_NARGS_1( \
    dummy,                       \
    _15,                         \
    _14,                         \
    _13,                         \
    _12,                         \
    _11,                         \
    _10,                         \
    _9,                          \
    _8,                          \
    _7,                          \
    _6,                          \
    _5,                          \
    _4,                          \
    _3,                          \
    _2,                          \
    _1,                          \
    _0,                          \
    ...)                         \
  _0
#define FOLLY_PP_FOR_EACH(fn, ...) \
  FOLLY_PP_DETAIL_FOR_EACH_1(      \
      fn, FOLLY_PP_DETAIL_NARGS(__VA_ARGS__), __VA_ARGS__)
#define FOLLY_PP_STRINGIZE(x) #x
#define FOLLY_SEMICOLON(...) ;
#define FOLLY_FBV_OP(p) (p)->~T()
#define FOLLY_FBV_UNROLL_PTR(first, last, OP)     \
  do {                                            \
    for (; (last) - (first) >= 4; (first) += 4) { \
      OP(((first) + 0));                          \
      OP(((first) + 1));                          \
      OP(((first) + 2));                          \
      OP(((first) + 3));                          \
    }                                             \
    for (; (first) != (last); ++(first))          \
      OP((first));                                \
  } while (0)
#define SCOPE_EXIT                               \
  auto FB_ANONYMOUS_VARIABLE(SCOPE_EXIT_STATE) = \
      ::folly::detail::ScopeGuardOnExit() + [&]() noexcept
#define SCOPE_FAIL                               \
  auto FB_ANONYMOUS_VARIABLE(SCOPE_FAIL_STATE) = \
      ::folly::detail::ScopeGuardOnFail() + [&]() noexcept
#define SCOPE_SUCCESS                               \
  auto FB_ANONYMOUS_VARIABLE(SCOPE_SUCCESS_STATE) = \
      ::folly::detail::ScopeGuardOnSuccess() + [&]()


#define FBSTRING_DISABLE_SSO true
#define FOLLY_FBSTRING_HASH      \
  FOLLY_FBSTRING_HASH1(char)     \
  FOLLY_FBSTRING_HASH1(char16_t) \
  FOLLY_FBSTRING_HASH1(char32_t) \
  FOLLY_FBSTRING_HASH1(wchar_t)
#define FOLLY_FBSTRING_HASH1(T)                                        \
  template <>                                                          \
  struct hash<::folly::basic_fbstring<T>> {                            \
    size_t operator()(const ::folly::basic_fbstring<T>& s) const {     \
      return ::folly::hash::fnv32_buf(s.data(), s.size() * sizeof(T)); \
    }                                                                  \
  };
#define get16bits(d) folly::loadUnaligned<uint16_t>(d)
#define FOLLY_EXPECTED_ID(X) FB_CONCATENATE(FB_CONCATENATE(Folly, X), "__LINE__")
#define FOLLY_REQUIRES(...) template <FOLLY_REQUIRES_IMPL(__VA_ARGS__)>
#define FOLLY_REQUIRES_IMPL(...)                                            \
  bool FOLLY_EXPECTED_ID(Requires) = false,                                 \
       typename std::enable_if<                                             \
           (FOLLY_EXPECTED_ID(Requires) || static_cast<bool>(__VA_ARGS__)), \
           int>::type = 0
#define FOLLY_REQUIRES_TRAILING(...) , FOLLY_REQUIRES_IMPL(__VA_ARGS__)
