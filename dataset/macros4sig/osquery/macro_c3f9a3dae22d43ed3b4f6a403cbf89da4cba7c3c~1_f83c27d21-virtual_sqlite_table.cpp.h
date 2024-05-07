#include<unistd.h>
#include<vector>
#include<string>

#include<unordered_set>
#include<cassert>


#include<bitset>
#include<typeinfo>
#include<new>

#include<atomic>



#include<unordered_map>
#include<mutex>
#include<cstddef>

#include<utility>




#include<map>

#include<iomanip>


#include<sys/types.h>

#include<fcntl.h>







#include<set>

#include<sstream>

#include<type_traits>



#include<sys/stat.h>
#include<memory>









#include<iostream>
#define SQLITE_SOFT_HEAP_LIMIT (5 * 1024 * 1024)
#define ANY_OP 0xFFU
#define BIGINT(x) __sqliteField(x)
#define BIGINT_LITERAL int64_t
#define DOUBLE(x) __sqliteField(x)
#define DOUBLE_LITERAL double
#define INTEGER(x) __sqliteField(x)
#define INTEGER_LITERAL int
#define OSQUERY_USE_DEPRECATED(expr)                                           \
  do {                                                                         \
    _Pragma("clang diagnostic push") _Pragma(                                  \
        "clang diagnostic ignored \"-Wdeprecated-declarations\"")(expr);       \
    _Pragma("clang diagnostic pop")                                            \
  } while (0)
#define SQL_NULL_RESULT ""
#define SQL_TEXT(x) __sqliteField(x)
#define TEXT(x) __sqliteField(x)
#define TEXT_LITERAL std::string
#define UNSIGNED_BIGINT(x) __sqliteField(x)
#define UNSIGNED_BIGINT_LITERAL uint64_t
#define RAPIDJSON_PARSE_DEFAULT_FLAGS (kParseIterativeFlag)
#define OSQUERY_NODISCARD [[nodiscard]]
#define EXIT_CATASTROPHIC 78
#define CONCAT(x, y) STR(STR_EX(x)STR_EX(y))
#define EXPORT_FUNCTION __declspec(dllexport)
#define STR(x) STR_OF(x)
#define STR_EX(...) __VA_ARGS__
#define STR_OF(x) #x
#define USED_SYMBOL __attribute__((used))
#define CLI_FLAG(t, n, v, d) OSQUERY_FLAG(t, n, v, d, 0, 0, 1, 0)
#define EXTENSION_FLAG(t, n, v, d) OSQUERY_FLAG(t, n, v, d, 0, 1, 0, 0)
#define FLAG(t, n, v, d) OSQUERY_FLAG(t, n, v, d, 0, 0, 0, 0)


#define GFLAGS_NAMESPACE gflags
#define HIDDEN_FLAG(t, n, v, d) OSQUERY_FLAG(t, n, v, d, 0, 0, 0, 1)
#define OSQUERY_FLAG(t, n, v, d, s, e, c, h)                                   \
  DEFINE_##t(n, v, d);                                                         \
  namespace flags {                                                            \
  const int flag_##n = Flag::create(#n, {d, s, e, c, h});                      \
  }
#define SHELL_FLAG(t, n, v, d) OSQUERY_FLAG(t, n, v, d, 1, 0, 0, 0)
#define STRIP_FLAG_HELP 1
#define OSQUERY_PLATFORM STR(OSQUERY_BUILD_PLATFORM)
#define OSQUERY_BUILD_VERSION 1.0.0-unknown
#define OSQUERY_SDK_VERSION STR(OSQUERY_BUILD_SDK_VERSION)


#define RLOG(n) "[Ref #" #n "] "
#define TLOG VLOG(1)
#define PF_APPEND 0x0040
#define PF_CREATE_ALWAYS (1 << 2)
#define PF_CREATE_NEW (0 << 2)
#define PF_GET_OPTIONS(x) ((x & PF_OPTIONS_MASK) >> 2)
#define PF_NONBLOCK 0x0020
#define PF_OPEN_ALWAYS (3 << 2)
#define PF_OPEN_EXISTING (2 << 2)
#define PF_OPTIONS_MASK 0x001c
#define PF_READ 0x0001
#define PF_TRUNCATE (4 << 2)
#define PF_WRITE 0x0002
#define R_OK 4
#define S_IRGRP (S_IRUSR >> 3)
#define S_IROTH (S_IRGRP >> 3)
#define S_IRUSR 0400
#define S_IRWXG (S_IRWXU >> 3)
#define S_IRWXO (S_IRWXG >> 3)
#define S_IRWXU (S_IRUSR | S_IWUSR | S_IXUSR)
#define S_IWGRP (S_IWUSR >> 3)
#define S_IWOTH (S_IWGRP >> 3)
#define S_IWUSR 0200
#define S_IXGRP (S_IXUSR >> 3)
#define S_IXOTH (S_IXGRP >> 3)
#define S_IXUSR 0100
#define W_OK 2
#define X_OK 1
