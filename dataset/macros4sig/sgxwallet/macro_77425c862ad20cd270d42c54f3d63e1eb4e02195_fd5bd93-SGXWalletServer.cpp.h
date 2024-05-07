#include<utility>
#include<stdbool.h>

#include<unordered_map>
#include<stdio.h>
#include<cmath>
#include<cstdio>
#include<string>

#include<stddef.h>


#include<iterator>

#include<mutex>
#include<string.h>

#include<atomic>

#include<map>
#include<type_traits>


#include<stdexcept>
#include<vector>



#include<chrono>
#include<shared_mutex>


#include<algorithm>


#include<initializer_list>

#include<cerrno>

#include<stdlib.h>
#include<ctime>

#include<stdint.h>





#include<execinfo.h>



#include<exception>
#include<cstring>

#include<iostream>
#include<cassert>
#include<unistd.h>


#include<limits>
#include<memory>
#include<functional>
#include<cstdint>

#define HANDLE_SGX_EXCEPTION(__RESULT__) \
    catch (SGXException& _e) { \
      if (_e.status != 0) {__RESULT__["status"] = _e.status;} else { __RESULT__["status"]  = UNKNOWN_ERROR;}; \
      __RESULT__["errorMessage"] = _e.errString;                                                              \
      spdlog::error("JSON call failed {}", __FUNCTION__);                             \
      return __RESULT__; \
      } catch (exception& _e) { \
      __RESULT__["errorMessage"] = _e.what(); \
      spdlog::error("JSON call failed {}", __FUNCTION__);                                   \
      return __RESULT__; \
      }\
      catch (...) { \
      exception_ptr p = current_exception(); \
      printf("Exception %s \n", p.__cxa_exception_type()->name()); \
      __RESULT__["errorMessage"] = "Unknown exception";                                                       \
      spdlog::error("JSON call failed {}", __FUNCTION__);                                   \
      return __RESULT__; \
      }
#define INIT_RESULT(__RESULT__)     Json::Value __RESULT__; \
              int errStatus = UNKNOWN_ERROR; boost::ignore_unused(errStatus); string errMsg(BUF_LEN, '\0');__RESULT__["status"] = UNKNOWN_ERROR; __RESULT__["errorMessage"] = \
"Server error. Please see server log.";
#define LOG(__SEVERITY__, __MESSAGE__) \
    cerr <<  to_string(__SEVERITY__) << " " <<  __MESSAGE__ << " " << className( __PRETTY_FUNCTION__ ) << endl;
#define RETURN_SUCCESS(__RESULT__) \
    __RESULT__["status"] = 0; \
    __RESULT__["errorMessage"] = ""; \
    return __RESULT__;

#define __CLASS_NAME__ className( __PRETTY_FUNCTION__ )
#define CHECK_STATE(_EXPRESSION_) \
    if (!(_EXPRESSION_)) { \
        auto __msg__ = std::string("State check failed::") + #_EXPRESSION_ +  " " + std::string("__FILE__") + ":" + std::to_string("__LINE__"); \
        print_stack();                                \
        throw InvalidStateException(__msg__, __CLASS_NAME__);}
#define HANDLE_TRUSTED_FUNCTION_ERROR(__STATUS__, __ERR_STATUS__, __ERR_MSG__) \
if (__STATUS__ != SGX_SUCCESS) { \
string __ERR_STRING__ = string("SGX enclave call to ") + \
                   __FUNCTION__  +  " failed with status:" \
                   + to_string(__STATUS__) + \
                   " Err message:" + __ERR_MSG__; \
BOOST_THROW_EXCEPTION(runtime_error(__ERR_MSG__)); \
}\
\
if (__ERR_STATUS__ != 0) {\
string __ERR_STRING__ = string("SGX enclave call to ") +\
                   __FUNCTION__  +  " failed with errStatus:" +                \
                     to_string(__ERR_STATUS__) + \
                   " Err message:" + __ERR_MSG__;\
BOOST_THROW_EXCEPTION(runtime_error(__ERR_STRING__)); \
}
#define SAFE_CHAR_BUF(__X__, __Y__)  ;char __X__ [ __Y__ ]; memset(__X__, 0, __Y__);
#define SAFE_FREE(__POINTER__) {if (__POINTER__) {free(__POINTER__); __POINTER__ = NULL;}}
#define SAFE_UINT8_BUF(__X__, __Y__)  ;uint8_t __X__ [ __Y__ ]; memset(__X__, 0, __Y__);


#define USER_SPACE 1
#define EXTERNC extern "C"
#define NUMBER_OF_CURVES (secp521r1+1)


#define EXTERNAL_NUMBER_THEORY_IMPLEMENTATION 0



#define SPDLOG_CRITICAL(...) SPDLOG_LOGGER_CRITICAL(spdlog::default_logger_raw(), __VA_ARGS__)
#define SPDLOG_DEBUG(...) SPDLOG_LOGGER_DEBUG(spdlog::default_logger_raw(), __VA_ARGS__)
#define SPDLOG_ERROR(...) SPDLOG_LOGGER_ERROR(spdlog::default_logger_raw(), __VA_ARGS__)

#define SPDLOG_INFO(...) SPDLOG_LOGGER_INFO(spdlog::default_logger_raw(), __VA_ARGS__)
#define SPDLOG_LOGGER_CALL(logger, level, ...) (logger)->log(spdlog::source_loc{"__FILE__", "__LINE__", SPDLOG_FUNCTION}, level, __VA_ARGS__)
#define SPDLOG_LOGGER_CRITICAL(logger, ...) SPDLOG_LOGGER_CALL(logger, spdlog::level::critical, __VA_ARGS__)
#define SPDLOG_LOGGER_DEBUG(logger, ...) SPDLOG_LOGGER_CALL(logger, spdlog::level::debug, __VA_ARGS__)
#define SPDLOG_LOGGER_ERROR(logger, ...) SPDLOG_LOGGER_CALL(logger, spdlog::level::err, __VA_ARGS__)
#define SPDLOG_LOGGER_INFO(logger, ...) SPDLOG_LOGGER_CALL(logger, spdlog::level::info, __VA_ARGS__)
#define SPDLOG_LOGGER_TRACE(logger, ...) SPDLOG_LOGGER_CALL(logger, spdlog::level::trace, __VA_ARGS__)
#define SPDLOG_LOGGER_WARN(logger, ...) SPDLOG_LOGGER_CALL(logger, spdlog::level::warn, __VA_ARGS__)
#define SPDLOG_TRACE(...) SPDLOG_LOGGER_TRACE(spdlog::default_logger_raw(), __VA_ARGS__)
#define SPDLOG_WARN(...) SPDLOG_LOGGER_WARN(spdlog::default_logger_raw(), __VA_ARGS__)
#define SPDLOG_VERSION (SPDLOG_VER_MAJOR * 10000 + SPDLOG_VER_MINOR * 100 + SPDLOG_VER_PATCH)
#define SPDLOG_VER_MAJOR 1
#define SPDLOG_VER_MINOR 5
#define SPDLOG_VER_PATCH 0
#define SPDLOG_LOGGER_CATCH()                                                                                                              \
    catch (const std::exception &ex)                                                                                                       \
    {                                                                                                                                      \
        err_handler_(ex.what());                                                                                                           \
    }                                                                                                                                      \
    catch (...)                                                                                                                            \
    {                                                                                                                                      \
        err_handler_("Unknown exception in logger");                                                                                       \
    }
#define SPDLOG_EOL "\r\n"
#define NOMINMAX 
#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_INFO

#define SPDLOG_CONSTEXPR constexpr
#define SPDLOG_DEPRECATED __attribute__((deprecated))
#define SPDLOG_FILENAME_T(s) L##s
#define SPDLOG_FUNCTION static_cast<const char *>(__FUNCTION__)

#define SPDLOG_INLINE inline
#define SPDLOG_LEVEL_CRITICAL 5
#define SPDLOG_LEVEL_DEBUG 1
#define SPDLOG_LEVEL_ERROR 4
#define SPDLOG_LEVEL_INFO 2
#define SPDLOG_LEVEL_NAMES                                                                                                                 \
    {                                                                                                                                      \
        "trace", "debug", "info", "warning", "error", "critical", "off"                                                                    \
    }
#define SPDLOG_LEVEL_OFF 6
#define SPDLOG_LEVEL_TRACE 0
#define SPDLOG_LEVEL_WARN 3
#define SPDLOG_NOEXCEPT _NOEXCEPT
#define SPDLOG_NO_TLS 1
#define SPDLOG_SHORT_LEVEL_NAMES                                                                                                           \
    {                                                                                                                                      \
        "T", "D", "I", "W", "E", "C", "O"                                                                                                  \
    }
#define SPDLOG_THROW(ex)                                                                                                                   \
    do                                                                                                                                     \
    {                                                                                                                                      \
        printf("spdlog fatal error: %s\n", ex.what());                                                                                     \
        std::abort();                                                                                                                      \
    } while (0)
#define SPDLOG_TRY try


#define FMT_USE_WINDOWS_H 0
#  define FMT_ALWAYS_INLINE inline __attribute__((always_inline))
#  define FMT_BUILTIN_CLZ(n) __builtin_clz(n)
#  define FMT_BUILTIN_CLZLL(n) __builtin_clzll(n)
#  define FMT_CLANG_VERSION (__clang_major__ * 100 + __clang_minor__)
#  define FMT_CUDA_VERSION (__CUDACC_VER_MAJOR__ * 100 + __CUDACC_VER_MINOR__)
#  define FMT_DEPRECATED_PERCENT 0
#  define FMT_FALLTHROUGH [[fallthrough]]
#define FMT_FORMAT_AS(Type, Base)                                             \
  template <typename Char>                                                    \
  struct formatter<Type, Char> : formatter<Base, Char> {                      \
    template <typename FormatContext>                                         \
    auto format(const Type& val, FormatContext& ctx) -> decltype(ctx.out()) { \
      return formatter<Base, Char>::format(val, ctx);                         \
    }                                                                         \
  }

#  define FMT_FUNC inline
#  define FMT_HAS_BUILTIN(x) __has_builtin(x)
#  define FMT_ICC_VERSION __INTEL_COMPILER
#  define FMT_NUMERIC_ALIGN 1
#define FMT_STRING(s) FMT_STRING_IMPL(s, )
#define FMT_STRING_IMPL(s, ...)                                         \
  [] {                                                                  \
    struct str : fmt::compile_string {                                  \
      using char_type = typename std::remove_cv<std::remove_pointer<    \
          typename std::decay<decltype(s)>::type>::type>::type;         \
      __VA_ARGS__ FMT_CONSTEXPR                                         \
      operator fmt::basic_string_view<char_type>() const {              \
        return {s, sizeof(s) / sizeof(char_type) - 1};                  \
      }                                                                 \
    } result;                                                           \
                \
    (void)static_cast<fmt::basic_string_view<typename str::char_type>>( \
        result);                                                        \
    return result;                                                      \
  }()
#      define FMT_THROW(x) internal::do_throw(x)
#  define FMT_USE_GRISU 1
#    define FMT_USE_UDL_TEMPLATE 1
#    define FMT_USE_USER_DEFINED_LITERALS 1
#  define fmt(s) FMT_STRING_IMPL(s, [[deprecated]])
#    define FMT_API __declspec(dllexport)
#    define FMT_ASSERT(condition, message)
#  define FMT_BEGIN_NAMESPACE \
    namespace fmt {           \
    FMT_INLINE_NAMESPACE v6 {
#  define FMT_CONSTEXPR constexpr
#  define FMT_CONSTEXPR_DECL constexpr

#      define FMT_DEPRECATED __attribute__((deprecated))
#  define FMT_DEPRECATED_ALIAS FMT_DEPRECATED
#  define FMT_DETECTED_NOEXCEPT noexcept
#define FMT_ENABLE_IF(...) enable_if_t<(__VA_ARGS__), int> = 0
#    define FMT_END_NAMESPACE \
      }                       \
      }
#    define FMT_EXCEPTIONS 0
#  define FMT_EXTERN extern
#    define FMT_EXTERN_TEMPLATE_API FMT_API
#  define FMT_GCC_VERSION ("__GNUC__" * 100 + "__GNUC_MINOR__")
#  define FMT_HAS_CPP_ATTRIBUTE(x) __has_cpp_attribute(x)
#  define FMT_HAS_CXX11_NOEXCEPT 1
#  define FMT_HAS_FEATURE(x) __has_feature(x)
#  define FMT_HAS_GXX_CXX11 FMT_GCC_VERSION
#  define FMT_HAS_INCLUDE(x) __has_include(x)
#    define FMT_INLINE_NAMESPACE inline namespace
#  define FMT_MSC_VER _MSC_VER
#    define FMT_NOEXCEPT FMT_DETECTED_NOEXCEPT
#  define FMT_NORETURN [[noreturn]]
#  define FMT_NVCC __NVCC__
#    define FMT_OVERRIDE override
#define FMT_TYPE_CONSTANT(Type, constant) \
  template <typename Char>                \
  struct type_constant<Type, Char> : std::integral_constant<type, constant> {}
#  define FMT_USE_CONSTEXPR                                           \
    (FMT_HAS_FEATURE(cxx_relaxed_constexpr) || FMT_MSC_VER >= 1910 || \
     (FMT_GCC_VERSION >= 600 && "__cplusplus" >= 201402L)) &&           \
        !FMT_NVCC
#  define FMT_USE_EXPERIMENTAL_STRING_VIEW
#  define FMT_USE_INT128 1
#  define FMT_USE_NOEXCEPT 0
#  define FMT_USE_STRING_VIEW
#define FMT_VERSION 60102
#define EXTERNC extern "C"



#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)






#define ENCLAVE_NAME "secure_enclave.signed.so"

#define SGX_OK(x) (x&(SGX_SUPPORT_YES|SGX_SUPPORT_ENABLED|SGX_SUPPORT_HAVE_PSW))
#define SGX_SUPPORT_ENABLED         0x00000100
#define SGX_SUPPORT_ENABLE_REQUIRED 0x00000400
#define SGX_SUPPORT_HAVE_PSW        0x00001000
#define SGX_SUPPORT_NO              0x00000001
#define SGX_SUPPORT_REBOOT_REQUIRED 0x00000200
#define SGX_SUPPORT_UNKNOWN         0x00000000
#define SGX_SUPPORT_YES             0x00000002

#define ADD_ENTROPY_SIZE 32
#define BASE_PORT 1026
#define BUF_LEN 4096
#define CERT_REQUEST_DOES_NOT_EXIST -14
#define COULD_NOT_ACCESS_DATABASE -9
#define ECDSA_BIN_LEN 33
#define ECDSA_ENCR_LEN 93
#define ECDSA_SKEY_BASE 16
#define ECDSA_SKEY_LEN 65
#define ENCRYPTED_KEY_TOO_LONG -6
#define ERROR_IN_ENCLAVE -33
#define FAIL_TO_CREATE_CERTIFICATE -55
#define FILE_NOT_FOUND -44
#define INCORRECT_STRING_CONVERSION -5
#define INVALID_BLS_NAME -15
#define INVALID_DKG_PARAMS -12
#define INVALID_ECDSA_KEY_NAME -20
#define INVALID_ECSDA_SIGNATURE -22
#define INVALID_HEX -21
#define INVALID_POLY_NAME -11
#define INVALID_SECRET_SHARES_LENGTH -13
#define KEY_NAME_ALREADY_EXISTS -23 \

#define KEY_SHARE_ALREADY_EXISTS -8
#define KEY_SHARE_DOES_NOT_EXIST -7
#define MAX_COMPONENT_HEX_LENGTH MAX_COMPONENT_LENGTH * 2
#define MAX_COMPONENT_LENGTH 80
#define MAX_CSR_NUM 1000
#define MAX_ENCRYPTED_KEY_LENGTH 1024
#define MAX_ERR_LEN 1024
#define MAX_KEY_LENGTH 128
#define MAX_SIG_LEN 1024
#define NULL_DATABASE -10
#define NULL_KEY -4
#define PLAINTEXT_KEY_TOO_LONG -2
#define SEAL_KEY_FAILED -7
#define SECRET_SHARE_NUM_BYTES 96
#define SGXDATA_FOLDER "sgx_data/"

#define SGX_ENCLAVE_ERROR -666
#define SHA_256_LEN 32
#define TEST_VALUE "1234567890"
#define UNKNOWN_ERROR -1
#define UNPADDED_KEY -3
#define WALLETDB_NAME  "sgxwallet.db"
