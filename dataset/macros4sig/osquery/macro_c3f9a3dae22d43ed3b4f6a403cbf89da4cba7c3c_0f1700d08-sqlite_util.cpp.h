
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

#include<functional>






#include<csignal>






#include<set>


#include<sstream>

#include<type_traits>




#include<memory>





#include<iostream>
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
#define CREATE_LAZY_REGISTRY(class_name, registry_name)                        \
  namespace registries {                                                       \
  const RI<class_name> k##class_name(registry_name, registry_name, true);      \
  }
#define CREATE_REGISTRY(class_name, registry_name)                             \
  namespace registries {                                                       \
  const RI<class_name> k##class_name(registry_name, registry_name, false);     \
  }
#define REGISTER(class_name, registry_name, plugin_name)                       \
  namespace registries {                                                       \
  const PI<class_name> k##class_name(registry_name, plugin_name, false);       \
  }
#define REGISTER_INTERNAL(class_name, registry_name, plugin_name)              \
  namespace registries {                                                       \
  const PI<class_name> k##class_name(registry_name, plugin_name, true);        \
  }


#define RLOG(n) "[Ref #" #n "] "
#define TLOG VLOG(1)
#define SQLITE_SOFT_HEAP_LIMIT (5 * 1024 * 1024)
