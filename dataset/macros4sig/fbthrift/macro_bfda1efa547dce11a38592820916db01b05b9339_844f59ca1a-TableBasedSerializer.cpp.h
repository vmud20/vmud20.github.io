










#include<stack>

#include<unordered_set>

#include<cstdint>


#include<vector>


#include<bitset>


#include<cstddef>


#include<assert.h>
#include<list>





#include<limits>
#include<stdint.h>
#include<exception>


#include<unordered_map>
#include<typeinfo>


#include<algorithm>
#include<time.h>

#include<type_traits>

#include<set>
#include<string>

#include<utility>

#include<array>
#include<ctime>
#include<sys/types.h>
#include<initializer_list>
#include<inttypes.h>


#include<stdio.h>
#include<string.h>
#include<optional>
#include<map>

#include<memory>
#include<iterator>
#include<iostream>
#define CPP2_PROTOCOL_TSIMPLEJSONPROTOCOL_H_ 1
#define THRIFT2_PROTOCOL_TSIMPLEJSONPROTOCOL_TCC_ 1

#define CPP2_PROTOCOL_PROTOCOL_H_ 1


#define COMPUTE_TIME                                                \
  int64_t nowMs = apache::thrift::concurrency::Util::currentTime(); \
  time_t nowSec = (time_t)(nowMs / 1000);                           \
  nowMs -= nowSec * 1000;                                           \
  int ms = (int)nowMs;                                              \
  char dbgtime[26];                                                 \
  ctime_r(&nowSec, dbgtime);                                        \
  dbgtime[24] = '\0';
#define THRIFT_TLOGGING_H 1
#define T_DEBUG(format_string, ...) T_DEBUG_L(0, format_string, ##__VA_ARGS__)
#define T_DEBUG_L(level, format_string, ...)          \
  do {                                                \
    if (T_GLOBAL_DEBUGGING_LEVEL > (level)) {         \
      COMPUTE_TIME                                    \
      fprintf(                                        \
          stderr,                                     \
          "[%s,%d] [%s, %d ms] " format_string " \n", \
          "__FILE__",                                   \
          "__LINE__",                                   \
          dbgtime,                                    \
          ms,                                         \
          ##__VA_ARGS__);                             \
    }                                                 \
  } while (0)
#define T_DEBUG_T(format_string, ...)                 \
  do {                                                \
    if (T_GLOBAL_DEBUGGING_LEVEL > 0) {               \
      COMPUTE_TIME                                    \
      fprintf(                                        \
          stderr,                                     \
          "[%s,%d] [%s, %d ms] " format_string " \n", \
          "__FILE__",                                   \
          "__LINE__",                                   \
          dbgtime,                                    \
          ms,                                         \
          ##__VA_ARGS__);                             \
    }                                                 \
  } while (0)
#define T_ERROR(format_string, ...)                        \
  {                                                        \
    COMPUTE_TIME                                           \
    fprintf(                                               \
        stderr,                                            \
        "[%s,%d] [%s, %d ms] ERROR: " format_string " \n", \
        "__FILE__",                                          \
        "__LINE__",                                          \
        dbgtime,                                           \
        ms,                                                \
        ##__VA_ARGS__);                                    \
  }
#define T_GLOBAL_DEBUGGING_LEVEL 0
#define T_GLOBAL_LOGGING_LEVEL 1
#define T_LOG_OPER(format_string, ...)        \
  {                                           \
    if (T_GLOBAL_LOGGING_LEVEL > 0) {         \
      COMPUTE_TIME                            \
      fprintf(                                \
          stderr,                             \
          "[%s, %d ms] " format_string " \n", \
          dbgtime,                            \
          ms,                                 \
          ##__VA_ARGS__);                     \
    }                                         \
  }
#define THRIFT_HAVE_CLOCK_GETTIME 1
#define THRIFT_HAVE_LIBSNAPPY 1
#define THRIFT_VERSION "1.0"
#define _LIB_CPP_THRIFT_CONFIG_H 1
#define _THRIFT_CONCURRENCY_UTIL_H_ 1
#define THRIFT_PROTOCOL_TPROTOCOLTYPES_H_ 1
#define _THRIFT_PROTOCOL_TPROTOCOLEXCEPTION_H_ 1
#define THRIFT_PROTOCOL_TPROTOCOL_H_ 1
#define THRIFT_TRANSPORT_TTRANSPORT_H 1
#define _THRIFT_TRANSPORT_TTRANSPORTEXCEPTION_H_ 1
#define CPP2_PROTOCOL_COMPACTPROTOCOL_H_ 1
#define THRIFT2_PROTOCOL_COMPACTPROTOCOL_TCC_ 1
#define THRIFT_UTIL_VARINTUTILS_H_ 1
#define CPP2_PROTOCOL_TBINARYPROTOCOL_H_ 1
#define THRIFT2_PROTOCOL_TBINARYPROTOCOL_TCC_ 1
#define THRIFT_DEFINE_NUMERIC_PTR_TYPE_INFO(TypeClass)                        \
  template <typename T>                                                       \
  struct TypeToInfo<type_class::TypeClass, T, enable_if_smart_ptr_t<T>> {     \
    using numeric_type = std::remove_cv_t<typename T::element_type>;          \
    using underlying_type =                                                   \
        typename TypeToInfo<type_class::TypeClass, numeric_type>::            \
            underlying_type;                                                  \
    static const TypeInfo typeInfo;                                           \
  };                                                                          \
                                                                              \
  template <typename T>                                                       \
  const TypeInfo                                                              \
      TypeToInfo<type_class::TypeClass, T, enable_if_smart_ptr_t<T>>::        \
          typeInfo = {                                                        \
              TypeToInfo<type_class::TypeClass, numeric_type>::typeInfo.type, \
              reinterpret_cast<VoidFuncPtr>(set<T, underlying_type>),         \
              reinterpret_cast<VoidFuncPtr>(                                  \
                  identity(get<underlying_type, T>)),                         \
              nullptr,                                                        \
  }
#define THRIFT_DEFINE_PRIMITIVE_TYPE_TO_INFO(      \
    TypeClass, Type, ThriftType, TTypeValue)       \
  template <>                                      \
  struct TypeToInfo<type_class::TypeClass, Type> { \
    using underlying_type = ThriftType;            \
    static const TypeInfo typeInfo;                \
  }
#define THRIFT_DEFINE_STRING_TYPE_TO_INFO(TypeClass, T, ExtVal) \
  template <>                                                   \
  struct TypeToInfo<type_class::TypeClass, T> {                 \
    static const StringFieldType ext;                           \
    static const TypeInfo typeInfo;                             \
  }
#define THRIFT_DEFINE_STRUCT_PTR_TYPE_INFO(TypeClass)                     \
  template <typename T>                                                   \
  struct TypeToInfo<type_class::TypeClass, T, enable_if_smart_ptr_t<T>> { \
    using struct_type = std::remove_cv_t<typename T::element_type>;       \
    static const TypeInfo typeInfo;                                       \
  };                                                                      \
                                                                          \
  template <typename T>                                                   \
  const TypeInfo TypeToInfo<                                              \
      type_class::TypeClass,                                              \
      T,                                                                  \
      enable_if_smart_ptr_t<T>>::typeInfo = {                             \
      TypeToInfo<type_class::TypeClass, struct_type>::typeInfo.type,      \
      reinterpret_cast<VoidFuncPtr>(set<T>),                              \
      reinterpret_cast<VoidFuncPtr>(identity(get<T>)),                    \
      TypeToInfo<type_class::TypeClass, struct_type>::typeInfo.typeExt,   \
  }
#define THRIFT_PROTOCOL_METHODS_IF_THEN_ELSE_CONSTEXPR(cond, T, E) \
  std::get<(cond) ? 0 : 1>(std::forward_as_tuple(                  \
      [&](auto _) { THRIFT_PROTOCOL_METHODS_UNPAREN T },           \
      [&](auto _) { THRIFT_PROTOCOL_METHODS_UNPAREN E }))(TypeHider{})
#define THRIFT_PROTOCOL_METHODS_REGISTER_OVERLOAD(Class, Type, Method) \
  template <>                                                          \
  struct protocol_methods<type_class::Class, Type> {                   \
    THRIFT_PROTOCOL_METHODS_REGISTER_RW_COMMON(Class, Type, Method)    \
    THRIFT_PROTOCOL_METHODS_REGISTER_SS_COMMON(Class, Type, Method)    \
  }
#define THRIFT_PROTOCOL_METHODS_REGISTER_RW_COMMON(Class, Type, Method)      \
  template <typename Protocol>                                               \
  static void read(Protocol& protocol, Type& out) {                          \
    protocol.read##Method(out);                                              \
  }                                                                          \
  template <typename Protocol, typename Context>                             \
  static void readWithContext(Protocol& protocol, Type& out, Context& ctx) { \
    THRIFT_PROTOCOL_METHODS_IF_THEN_ELSE_CONSTEXPR(                          \
        Context::kAcceptsContext,                                            \
        (_(protocol).read##Method##WithContext(out, ctx);),                  \
        (_(protocol).read##Method(out);));                                   \
  }                                                                          \
  template <typename Protocol>                                               \
  static std::size_t write(Protocol& protocol, Type const& in) {             \
    return protocol.write##Method(in);                                       \
  }
#define THRIFT_PROTOCOL_METHODS_REGISTER_RW_UI(Class, Type, Method)          \
  using SignedType = std::make_signed_t<Type>;                               \
  template <typename Protocol>                                               \
  static void read(Protocol& protocol, Type& out) {                          \
    SignedType tmp;                                                          \
    protocol.read##Method(tmp);                                              \
    out = folly::to_unsigned(tmp);                                           \
  }                                                                          \
  template <typename Protocol, typename Context>                             \
  static void readWithContext(Protocol& protocol, Type& out, Context& ctx) { \
    SignedType tmp;                                                          \
    THRIFT_PROTOCOL_METHODS_IF_THEN_ELSE_CONSTEXPR(                          \
        Context::kAcceptsContext,                                            \
        (_(protocol).read##Method##WithContext(tmp, ctx);),                  \
        (_(protocol).read##Method(tmp);));                                   \
    out = folly::to_unsigned(tmp);                                           \
  }                                                                          \
  template <typename Protocol>                                               \
  static std::size_t write(Protocol& protocol, Type const& in) {             \
    return protocol.write##Method(folly::to_signed(in));                     \
  }
#define THRIFT_PROTOCOL_METHODS_REGISTER_SS_COMMON(Class, Type, Method)   \
  template <bool, typename Protocol>                                      \
  static std::size_t serializedSize(Protocol& protocol, Type const& in) { \
    return protocol.serializedSize##Method(in);                           \
  }
#define THRIFT_PROTOCOL_METHODS_REGISTER_SS_UI(Class, Type, Method)       \
  template <bool, typename Protocol>                                      \
  static std::size_t serializedSize(Protocol& protocol, Type const& in) { \
    return protocol.serializedSize##Method(folly::to_signed(in));         \
  }
#define THRIFT_PROTOCOL_METHODS_REGISTER_UI(Class, Type, Method) \
  template <>                                                    \
  struct protocol_methods<type_class::Class, Type> {             \
    THRIFT_PROTOCOL_METHODS_REGISTER_RW_UI(Class, Type, Method)  \
    THRIFT_PROTOCOL_METHODS_REGISTER_SS_UI(Class, Type, Method)  \
  }
#define THRIFT_PROTOCOL_METHODS_UNPAREN(...) __VA_ARGS__
#define FBTHRIFT_CPP_DEFINE_MEMBER_INDIRECTION_FN(...)                       \
  struct __fbthrift_cpp2_indirection_fn {                                    \
    template <typename __fbthrift_t>                                         \
    FOLLY_ERASE constexpr auto operator()(__fbthrift_t&& __fbthrift_v) const \
        noexcept(                                                            \
            noexcept(static_cast<__fbthrift_t&&>(__fbthrift_v).__VA_ARGS__)) \
            -> decltype(                                                     \
                (static_cast<__fbthrift_t&&>(__fbthrift_v).__VA_ARGS__)) {   \
      return static_cast<__fbthrift_t&&>(__fbthrift_v).__VA_ARGS__;          \
    }                                                                        \
  }


