
#include<limits>


#include<unistd.h>




#include<stack>



#include<arpa/inet.h>


#include<cstring>



#include<cstdint>
#include<sys/socket.h>




#include<list>


#include<atomic>
#include<ifaddrs.h>

#include<stdexcept>
#include<sys/ioctl.h>
#include<linux/netfilter_ipv4.h>

#include<netdb.h>
#include<netinet/in.h>

#include<sys/mman.h>

#include<chrono>



#include<time.h>


#include<netinet/tcp.h>

#include<array>




#include<sstream>
#include<set>

#include<string>
#include<memory>

#include<sys/stat.h>
#include<stdint.h>

#include<zlib.h>




#include<ios>
#include<sys/uio.h>
#include<algorithm>
#include<cstddef>
#include<sys/types.h>
#include<bitset>
#include<netinet/udp.h>

#include<functional>
#include<sys/wait.h>

#include<fcntl.h>
#include<utility>
#include<endian.h>




#include<sys/un.h>
#include<vector>


#define ASSERT _NULL_ASSERT_IMPL
#define ASSERT_ACTION ::abort()
#define ENVOY_BUG(...) PASS_ON(PASS_ON(_ENVOY_BUG_VERBOSE)(__VA_ARGS__))
#define ENVOY_BUG_ACTION ::abort()

#define EXPAND(X) X
#define IS_ENVOY_BUG(...) ENVOY_BUG(false, __VA_ARGS__);
#define KNOWN_ISSUE_ASSERT _NULL_ASSERT_IMPL
#define PANIC(X)                                                                                   \
  do {                                                                                             \
    ENVOY_LOG_TO_LOGGER(Envoy::Logger::Registry::getLog(Envoy::Logger::Id::assert), critical,      \
                        "panic: {}", X);                                                           \
    ::abort();                                                                                     \
  } while (false)
#define PANIC_DUE_TO_CORRUPT_ENUM PANIC("corrupted enum");
#define PANIC_DUE_TO_PROTO_UNSET PANIC("unset oneof")
#define PANIC_ON_PROTO_ENUM_SENTINEL_VALUES                                                        \
  case std::numeric_limits<int32_t>::max():                                                        \
    FALLTHRU;                                                                                      \
  case std::numeric_limits<int32_t>::min():                                                        \
    PANIC("unexpected sentinel value used")
#define PASS_ON(...) __VA_ARGS__
#define RELEASE_ASSERT(X, DETAILS) _ASSERT_IMPL(X, #X, ::abort(), DETAILS)
#define SECURITY_ASSERT(X, DETAILS) _ASSERT_IMPL(X, #X, ::abort(), DETAILS)
#define SLOW_ASSERT _NULL_ASSERT_IMPL
#define STRINGIFY(X) #X
#define TOSTRING(X) STRINGIFY(X)
#define _ASSERT_IMPL(CONDITION, CONDITION_STR, ACTION, DETAILS)                                    \
  do {                                                                                             \
    if (!(CONDITION)) {                                                                            \
      const std::string& details = (DETAILS);                                                      \
      ENVOY_LOG_TO_LOGGER(Envoy::Logger::Registry::getLog(Envoy::Logger::Id::assert), critical,    \
                          "assert failure: {}.{}{}", CONDITION_STR,                                \
                          details.empty() ? "" : " Details: ", details);                           \
      ACTION;                                                                                      \
    }                                                                                              \
  } while (false)
#define _ASSERT_ORIGINAL(X) _ASSERT_IMPL(X, #X, ASSERT_ACTION, "")
#define _ASSERT_SELECTOR(_1, _2, ASSERT_MACRO, ...) ASSERT_MACRO
#define _ASSERT_VERBOSE(X, Y) _ASSERT_IMPL(X, #X, ASSERT_ACTION, Y)
#define _ENVOY_BUG_IMPL(CONDITION, CONDITION_STR, ACTION, DETAILS)                                 \
  do {                                                                                             \
    if (!(CONDITION) && Envoy::Assert::shouldLogAndInvokeEnvoyBugForEnvoyBugMacroUseOnly(          \
                            "__FILE__" ":" TOSTRING("__LINE__"))) {                                    \
      const std::string& details = (DETAILS);                                                      \
      ENVOY_LOG_TO_LOGGER(Envoy::Logger::Registry::getLog(Envoy::Logger::Id::envoy_bug), error,    \
                          "envoy bug failure: {}.{}{}", CONDITION_STR,                             \
                          details.empty() ? "" : " Details: ", details);                           \
      ACTION;                                                                                      \
    }                                                                                              \
  } while (false)
#define _ENVOY_BUG_VERBOSE(X, Y) _ENVOY_BUG_IMPL(X, #X, ENVOY_BUG_ACTION, Y)
#define _NULL_ASSERT_IMPL(X, ...)                                                                  \
  do {                                                                                             \
    constexpr bool __assert_dummy_variable = false && static_cast<bool>(X);                        \
    (void)__assert_dummy_variable;                                                                 \
  } while (false)
#define ALL_LOGGER_IDS(FUNCTION)                                                                   \
  FUNCTION(admin)                                                                                  \
  FUNCTION(alternate_protocols_cache)                                                              \
  FUNCTION(aws)                                                                                    \
  FUNCTION(assert)                                                                                 \
  FUNCTION(backtrace)                                                                              \
  FUNCTION(cache_filter)                                                                           \
  FUNCTION(client)                                                                                 \
  FUNCTION(config)                                                                                 \
  FUNCTION(connection)                                                                             \
  FUNCTION(conn_handler)                                                                           \
  FUNCTION(decompression)                                                                          \
  FUNCTION(dns)                                                                                    \
  FUNCTION(dubbo)                                                                                  \
  FUNCTION(envoy_bug)                                                                              \
  FUNCTION(ext_authz)                                                                              \
  FUNCTION(ext_proc)                                                                               \
  FUNCTION(rocketmq)                                                                               \
  FUNCTION(file)                                                                                   \
  FUNCTION(filter)                                                                                 \
  FUNCTION(forward_proxy)                                                                          \
  FUNCTION(grpc)                                                                                   \
  FUNCTION(happy_eyeballs)                                                                         \
  FUNCTION(hc)                                                                                     \
  FUNCTION(health_checker)                                                                         \
  FUNCTION(http)                                                                                   \
  FUNCTION(http2)                                                                                  \
  FUNCTION(hystrix)                                                                                \
  FUNCTION(init)                                                                                   \
  FUNCTION(io)                                                                                     \
  FUNCTION(jwt)                                                                                    \
  FUNCTION(kafka)                                                                                  \
  FUNCTION(key_value_store)                                                                        \
  FUNCTION(lua)                                                                                    \
  FUNCTION(main)                                                                                   \
  FUNCTION(matcher)                                                                                \
  FUNCTION(misc)                                                                                   \
  FUNCTION(mongo)                                                                                  \
  FUNCTION(quic)                                                                                   \
  FUNCTION(quic_stream)                                                                            \
  FUNCTION(pool)                                                                                   \
  FUNCTION(rbac)                                                                                   \
  FUNCTION(rds)                                                                                    \
  FUNCTION(redis)                                                                                  \
  FUNCTION(router)                                                                                 \
  FUNCTION(runtime)                                                                                \
  FUNCTION(stats)                                                                                  \
  FUNCTION(secret)                                                                                 \
  FUNCTION(tap)                                                                                    \
  FUNCTION(testing)                                                                                \
  FUNCTION(thrift)                                                                                 \
  FUNCTION(tracing)                                                                                \
  FUNCTION(upstream)                                                                               \
  FUNCTION(udp)                                                                                    \
  FUNCTION(wasm)
#define ENVOY_CONN_LOG(LEVEL, FORMAT, CONNECTION, ...)                                             \
  do {                                                                                             \
    if (Envoy::Logger::Context::useFancyLogger()) {                                                \
      FANCY_CONN_LOG(LEVEL, FORMAT, CONNECTION, ##__VA_ARGS__);                                    \
    } else {                                                                                       \
      ENVOY_CONN_LOG_TO_LOGGER(ENVOY_LOGGER(), LEVEL, FORMAT, CONNECTION, ##__VA_ARGS__);          \
    }                                                                                              \
  } while (0)
#define ENVOY_CONN_LOG_EVENT(LEVEL, EVENT_NAME, FORMAT, CONNECTION, ...)                           \
  ENVOY_LOG_EVENT_TO_LOGGER(ENVOY_LOGGER(), LEVEL, EVENT_NAME, "[C{}] " FORMAT, (CONNECTION).id(), \
                            ##__VA_ARGS__);
#define ENVOY_CONN_LOG_TO_LOGGER(LOGGER, LEVEL, FORMAT, CONNECTION, ...)                           \
  ENVOY_LOG_TO_LOGGER(LOGGER, LEVEL, "[C{}] " FORMAT, (CONNECTION).id(), ##__VA_ARGS__)
#define ENVOY_FLUSH_LOG()                                                                          \
  do {                                                                                             \
    if (Envoy::Logger::Context::useFancyLogger()) {                                                \
      FANCY_FLUSH_LOG();                                                                           \
    } else {                                                                                       \
      ENVOY_LOGGER().flush();                                                                      \
    }                                                                                              \
  } while (0)
#define ENVOY_LOG(LEVEL, ...) ENVOY_LOG_TO_LOGGER(ENVOY_LOGGER(), LEVEL, ##__VA_ARGS__)
#define ENVOY_LOGGER() __log_do_not_use_read_comment()
#define ENVOY_LOG_CHECK_LEVEL(LEVEL) ENVOY_LOG_COMP_LEVEL(ENVOY_LOGGER(), LEVEL)
#define ENVOY_LOG_COMP_AND_LOG(LOGGER, LEVEL, ...)                                                 \
  do {                                                                                             \
    if (ENVOY_LOG_COMP_LEVEL(LOGGER, LEVEL)) {                                                     \
      LOGGER.log(::spdlog::source_loc{"__FILE__", "__LINE__", __func__}, ENVOY_SPDLOG_LEVEL(LEVEL),    \
                 __VA_ARGS__);                                                                     \
    }                                                                                              \
  } while (0)
#define ENVOY_LOG_COMP_LEVEL(LOGGER, LEVEL) (ENVOY_SPDLOG_LEVEL(LEVEL) >= (LOGGER).level())
#define ENVOY_LOG_EVENT(LEVEL, EVENT_NAME, ...)                                                    \
  ENVOY_LOG_EVENT_TO_LOGGER(ENVOY_LOGGER(), LEVEL, EVENT_NAME, ##__VA_ARGS__)
#define ENVOY_LOG_EVENT_TO_LOGGER(LOGGER, LEVEL, EVENT_NAME, ...)                                  \
  do {                                                                                             \
    ENVOY_LOG_TO_LOGGER(LOGGER, LEVEL, ##__VA_ARGS__);                                             \
    if (ENVOY_LOG_COMP_LEVEL(LOGGER, LEVEL)) {                                                     \
      ::Envoy::Logger::Registry::getSink()->logWithStableName(EVENT_NAME, #LEVEL, (LOGGER).name(), \
                                                              ##__VA_ARGS__);                      \
    }                                                                                              \
  } while (0)
#define ENVOY_LOG_EVERY_NTH(LEVEL, N, ...)                                                         \
  ENVOY_LOG_EVERY_NTH_TO_LOGGER(ENVOY_LOGGER(), LEVEL, N, ##__VA_ARGS__)
#define ENVOY_LOG_EVERY_NTH_MISC(LEVEL, N, ...)                                                    \
  ENVOY_LOG_EVERY_NTH_TO_LOGGER(GET_MISC_LOGGER(), LEVEL, N, ##__VA_ARGS__)
#define ENVOY_LOG_EVERY_NTH_TO_LOGGER(LOGGER, LEVEL, N, ...)                                       \
  do {                                                                                             \
    if (ENVOY_LOG_COMP_LEVEL(LOGGER, LEVEL)) {                                                     \
      static auto* count = new std::atomic<uint64_t>();                                            \
      if ((count->fetch_add(1) % N) == 0) {                                                        \
        ENVOY_LOG_TO_LOGGER(LOGGER, LEVEL, ##__VA_ARGS__);                                         \
      }                                                                                            \
    }                                                                                              \
  } while (0)
#define ENVOY_LOG_EVERY_POW_2(LEVEL, ...)                                                          \
  ENVOY_LOG_EVERY_POW_2_TO_LOGGER(ENVOY_LOGGER(), LEVEL, ##__VA_ARGS__)
#define ENVOY_LOG_EVERY_POW_2_MISC(LEVEL, ...)                                                     \
  ENVOY_LOG_EVERY_POW_2_TO_LOGGER(GET_MISC_LOGGER(), LEVEL, ##__VA_ARGS__)
#define ENVOY_LOG_EVERY_POW_2_TO_LOGGER(LOGGER, LEVEL, ...)                                        \
  do {                                                                                             \
    if (ENVOY_LOG_COMP_LEVEL(LOGGER, LEVEL)) {                                                     \
      static auto* count = new std::atomic<uint64_t>();                                            \
      if (std::bitset<64>(1  + count->fetch_add(1)).count() == 1) {          \
        ENVOY_LOG_TO_LOGGER(LOGGER, LEVEL, ##__VA_ARGS__);                                         \
      }                                                                                            \
    }                                                                                              \
  } while (0)
#define ENVOY_LOG_FIRST_N(LEVEL, N, ...)                                                           \
  ENVOY_LOG_FIRST_N_TO_LOGGER(ENVOY_LOGGER(), LEVEL, N, ##__VA_ARGS__)
#define ENVOY_LOG_FIRST_N_MISC(LEVEL, N, ...)                                                      \
  ENVOY_LOG_FIRST_N_TO_LOGGER(GET_MISC_LOGGER(), LEVEL, N, ##__VA_ARGS__)
#define ENVOY_LOG_FIRST_N_TO_LOGGER(LOGGER, LEVEL, N, ...)                                         \
  do {                                                                                             \
    if (ENVOY_LOG_COMP_LEVEL(LOGGER, LEVEL)) {                                                     \
      static auto* countdown = new std::atomic<uint64_t>();                                        \
      if (countdown->fetch_add(1) < N) {                                                           \
        ENVOY_LOG_TO_LOGGER(LOGGER, LEVEL, ##__VA_ARGS__);                                         \
      }                                                                                            \
    }                                                                                              \
  } while (0)
#define ENVOY_LOG_MISC(LEVEL, ...) ENVOY_LOG_TO_LOGGER(GET_MISC_LOGGER(), LEVEL, ##__VA_ARGS__)
#define ENVOY_LOG_ONCE(LEVEL, ...) ENVOY_LOG_ONCE_TO_LOGGER(ENVOY_LOGGER(), LEVEL, ##__VA_ARGS__)
#define ENVOY_LOG_ONCE_MISC(LEVEL, ...)                                                            \
  ENVOY_LOG_ONCE_TO_LOGGER(GET_MISC_LOGGER(), LEVEL, ##__VA_ARGS__)
#define ENVOY_LOG_ONCE_TO_LOGGER(LOGGER, LEVEL, ...)                                               \
  ENVOY_LOG_FIRST_N_TO_LOGGER(LOGGER, LEVEL, 1, ##__VA_ARGS__)
#define ENVOY_LOG_PERIODIC(LEVEL, CHRONO_DURATION, ...)                                            \
  ENVOY_LOG_PERIODIC_TO_LOGGER(ENVOY_LOGGER(), LEVEL, CHRONO_DURATION, ##__VA_ARGS__)
#define ENVOY_LOG_PERIODIC_MISC(LEVEL, CHRONO_DURATION, ...)                                       \
  ENVOY_LOG_PERIODIC_TO_LOGGER(GET_MISC_LOGGER(), LEVEL, CHRONO_DURATION, ##__VA_ARGS__)
#define ENVOY_LOG_PERIODIC_TO_LOGGER(LOGGER, LEVEL, CHRONO_DURATION, ...)                          \
  do {                                                                                             \
    if (ENVOY_LOG_COMP_LEVEL(LOGGER, LEVEL)) {                                                     \
      static auto* last_hit = new std::atomic<int64_t>();                                          \
      auto last = last_hit->load();                                                                \
      const auto now = t_logclock::now().time_since_epoch().count();                               \
      if ((now - last) >                                                                           \
              std::chrono::duration_cast<std::chrono::nanoseconds>(CHRONO_DURATION).count() &&     \
          last_hit->compare_exchange_strong(last, now)) {                                          \
        ENVOY_LOG_TO_LOGGER(LOGGER, LEVEL, ##__VA_ARGS__);                                         \
      }                                                                                            \
    }                                                                                              \
  } while (0)
#define ENVOY_LOG_TO_LOGGER(LOGGER, LEVEL, ...)                                                    \
  do {                                                                                             \
    if (Envoy::Logger::Context::useFancyLogger()) {                                                \
      FANCY_LOG(LEVEL, ##__VA_ARGS__);                                                             \
    } else {                                                                                       \
      ENVOY_LOG_COMP_AND_LOG(LOGGER, LEVEL, ##__VA_ARGS__);                                        \
    }                                                                                              \
  } while (0)
#define ENVOY_SPDLOG_LEVEL(LEVEL)                                                                  \
  (static_cast<spdlog::level::level_enum>(Envoy::Logger::Logger::LEVEL))
#define ENVOY_STREAM_LOG(LEVEL, FORMAT, STREAM, ...)                                               \
  do {                                                                                             \
    if (Envoy::Logger::Context::useFancyLogger()) {                                                \
      FANCY_STREAM_LOG(LEVEL, FORMAT, STREAM, ##__VA_ARGS__);                                      \
    } else {                                                                                       \
      ENVOY_STREAM_LOG_TO_LOGGER(ENVOY_LOGGER(), LEVEL, FORMAT, STREAM, ##__VA_ARGS__);            \
    }                                                                                              \
  } while (0)
#define ENVOY_STREAM_LOG_TO_LOGGER(LOGGER, LEVEL, FORMAT, STREAM, ...)                             \
  ENVOY_LOG_TO_LOGGER(LOGGER, LEVEL, "[C{}][S{}] " FORMAT,                                         \
                      (STREAM).connection() ? (STREAM).connection()->id() : 0,                     \
                      (STREAM).streamId(), ##__VA_ARGS__)
#define GET_MISC_LOGGER() ::Envoy::Logger::Registry::getLog(::Envoy::Logger::Id::misc)
#define ARRAY_SIZE(X) (sizeof(X) / sizeof(X[0]))
#define CONSTRUCT_ON_FIRST_USE(type, ...)                                                          \
  do {                                                                                             \
    static const type* objectptr = new type{__VA_ARGS__};                                          \
    return *objectptr;                                                                             \
  } while (0)
#define FALLTHRU [[fallthrough]]

#define GENERATE_ENUM(X) X,
#define GENERATE_STRING(X) #X,
#define MUTABLE_CONSTRUCT_ON_FIRST_USE(type, ...)                                                  \
  do {                                                                                             \
    static type* objectptr = new type{__VA_ARGS__};                                                \
    return *objectptr;                                                                             \
  } while (0)
#define STATIC_STRLEN(X) (sizeof(X) - 1)
#define UNREFERENCED_PARAMETER(X) ((void)(X))
#define CMSG_DATA(msg) WSA_CMSG_DATA(msg)
#define CMSG_FIRSTHDR(msg)                                                                         \
  (((msg)->msg_controllen >= sizeof(WSACMSGHDR)) ? (LPWSACMSGHDR)(msg)->msg_control                \
                                                 : (LPWSACMSGHDR)NULL)
#define CMSG_NXTHDR(msg, cmsg)                                                                     \
  (((cmsg) == NULL)                                                                                \
       ? CMSG_FIRSTHDR(msg)                                                                        \
       : ((((PUCHAR)(cmsg) + WSA_CMSGHDR_ALIGN((cmsg)->cmsg_len) + sizeof(WSACMSGHDR)) >           \
           (PUCHAR)((msg)->msg_control) + (msg)->msg_controllen)                                   \
              ? (LPWSACMSGHDR)NULL                                                                 \
              : (LPWSACMSGHDR)((PUCHAR)(cmsg) + WSA_CMSGHDR_ALIGN((cmsg)->cmsg_len))))
#define ENVOY_MMSG_MORE 1
#define ENVOY_SHUT_RD SD_RECEIVE
#define ENVOY_SHUT_RDWR SD_BOTH
#define ENVOY_SHUT_WR SD_SEND
#define ENVOY_SIGTERM 0
#define ENVOY_TCP_BACKLOG_SIZE -1
#define ENVOY_WIN32_SIGNAL_COUNT 1
#define HANDLE_ERROR_INVALID ERROR_INVALID_HANDLE
#define HANDLE_ERROR_PERM ERROR_ACCESS_DENIED
#define INVALID_HANDLE -1
#define INVALID_SOCKET -1
#define IP6T_SO_ORIGINAL_DST 80
#define IPPROTO_MPTCP 262
#define IPV6_RECVPKTINFO IPV6_PKTINFO
#define MSG_WAITFORONE 0x10000 
#define PACKED_STRUCT(definition, ...) definition, ##__VA_ARGS__ __attribute__((packed))
#define SET_SOCKET_INVALID(sock) (sock) = INVALID_SOCKET
#define SOCKET_ERROR_ACCESS WSAEACCES
#define SOCKET_ERROR_ADDR_IN_USE WSAEADDRINUSE
#define SOCKET_ERROR_ADDR_NOT_AVAIL WSAEADDRNOTAVAIL
#define SOCKET_ERROR_AF_NO_SUP WSAEAFNOSUPPORT
#define SOCKET_ERROR_AGAIN WSAEWOULDBLOCK
#define SOCKET_ERROR_BADF WSAEBADF
#define SOCKET_ERROR_CONNRESET WSAECONNRESET
#define SOCKET_ERROR_INTR WSAEINTR
#define SOCKET_ERROR_INVAL WSAEINVAL
#define SOCKET_ERROR_IN_PROGRESS WSAEINPROGRESS
#define SOCKET_ERROR_MSG_SIZE WSAEMSGSIZE
#define SOCKET_ERROR_NETUNREACH WSAENETUNREACH
#define SOCKET_ERROR_NOT_SUP WSAEOPNOTSUPP
#define SOCKET_ERROR_PERM WSAEACCES
#define SOCKET_FAILURE(rc) ((rc) == SOCKET_ERROR)
#define SOCKET_INVALID(sock) ((sock) == INVALID_SOCKET)
#define SOCKET_VALID(sock) ((sock) != INVALID_SOCKET)
#define SOL_UDP 17
#define SO_REUSEPORT SO_REUSEADDR

#define SUPPORTS_PTHREAD_NAMING 0
#define UDP_GRO 104
#define UDP_SEGMENT 103
#define be16toh(x) OSSwapBigToHostInt16((x))
#define be32toh(x) OSSwapBigToHostInt32((x))
#define be64toh(x) OSSwapBigToHostInt64((x))
#define htobe16(x) OSSwapHostToBigInt16((x))
#define htobe32(x) OSSwapHostToBigInt32((x))
#define htobe64(x) OSSwapHostToBigInt64((x))
#define htole16(x) OSSwapHostToLittleInt16((x))
#define htole32(x) OSSwapHostToLittleInt32((x))
#define htole64(x) OSSwapHostToLittleInt64((x))
#define le16toh(x) OSSwapLittleToHostInt16((x))
#define le32toh(x) OSSwapLittleToHostInt32((x))
#define le64toh(x) OSSwapLittleToHostInt64((x))
#define FANCY_CONN_LOG(LEVEL, FORMAT, CONNECTION, ...)                                             \
  FANCY_LOG(LEVEL, "[C{}] " FORMAT, (CONNECTION).id(), ##__VA_ARGS__)
#define FANCY_FLUSH_LOG()                                                                          \
  do {                                                                                             \
    SpdLoggerSharedPtr p = ::Envoy::getFancyContext().getFancyLogEntry(FANCY_KEY);                 \
    if (p) {                                                                                       \
      p->flush();                                                                                  \
    }                                                                                              \
  } while (0)
#define FANCY_KEY std::string("__FILE__")
#define FANCY_LOG(LEVEL, ...)                                                                      \
  do {                                                                                             \
    static std::atomic<spdlog::logger*> flogger{0};                                                \
    spdlog::logger* local_flogger = flogger.load(std::memory_order_relaxed);                       \
    if (!local_flogger) {                                                                          \
      ::Envoy::getFancyContext().initFancyLogger(FANCY_KEY, flogger);                              \
      local_flogger = flogger.load(std::memory_order_relaxed);                                     \
    }                                                                                              \
    if (ENVOY_LOG_COMP_LEVEL(*local_flogger, LEVEL)) {                                             \
      local_flogger->log(spdlog::source_loc{"__FILE__", "__LINE__", __func__},                         \
                         ENVOY_SPDLOG_LEVEL(LEVEL), __VA_ARGS__);                                  \
    }                                                                                              \
  } while (0)
#define FANCY_STREAM_LOG(LEVEL, FORMAT, STREAM, ...)                                               \
  FANCY_LOG(LEVEL, "[C{}][S{}] " FORMAT, (STREAM).connection() ? (STREAM).connection()->id() : 0,  \
            (STREAM).streamId(), ##__VA_ARGS__)
#define PURE = 0
#define ALL_ZLIB_DECOMPRESSOR_STATS(COUNTER)                                                       \
  COUNTER(zlib_errno)                                                                              \
  COUNTER(zlib_stream_error)                                                                       \
  COUNTER(zlib_data_error)                                                                         \
  COUNTER(zlib_mem_error)                                                                          \
  COUNTER(zlib_buf_error)                                                                          \
  COUNTER(zlib_version_error)
#define FINISH_STAT_DECL_(X) #X)),
#define FINISH_STAT_DECL_MODE_(X, MODE) #X), Envoy::Stats::Gauge::ImportMode::MODE),
#define FINISH_STAT_DECL_UNIT_(X, UNIT) #X), Envoy::Stats::Histogram::Unit::UNIT),
#define GENERATE_COUNTER_STRUCT(NAME) Envoy::Stats::Counter& NAME##_;
#define GENERATE_GAUGE_STRUCT(NAME, MODE) Envoy::Stats::Gauge& NAME##_;
#define GENERATE_HISTOGRAM_STRUCT(NAME, UNIT) Envoy::Stats::Histogram& NAME##_;

#define GENERATE_STAT_NAME_INIT(NAME, ...) , NAME##_(pool_.add(#NAME))
#define GENERATE_STAT_NAME_STRUCT(NAME, ...) Envoy::Stats::StatName NAME##_;
#define GENERATE_TEXT_READOUT_STRUCT(NAME) Envoy::Stats::TextReadout& NAME##_;
#define MAKE_STATS_STRUCT(StatsStruct, StatNamesStruct, ALL_STATS)                                 \
  struct StatsStruct {                                                                             \
    StatsStruct(const StatNamesStruct& stat_names, Envoy::Stats::Scope& scope,                     \
                Envoy::Stats::StatName prefix = Envoy::Stats::StatName())                          \
        : stat_names_(stat_names)                                                                  \
              ALL_STATS(MAKE_STATS_STRUCT_COUNTER_HELPER_, MAKE_STATS_STRUCT_GAUGE_HELPER_,        \
                        MAKE_STATS_STRUCT_HISTOGRAM_HELPER_,                                       \
                        MAKE_STATS_STRUCT_TEXT_READOUT_HELPER_,                                    \
                        MAKE_STATS_STRUCT_STATNAME_HELPER_) {}                                     \
    const StatNamesStruct& stat_names_;                                                            \
    ALL_STATS(GENERATE_COUNTER_STRUCT, GENERATE_GAUGE_STRUCT, GENERATE_HISTOGRAM_STRUCT,           \
              GENERATE_TEXT_READOUT_STRUCT, GENERATE_STATNAME_STRUCT)                              \
  }
#define MAKE_STATS_STRUCT_COUNTER_HELPER_(NAME)                                                    \
  , NAME##_(Envoy::Stats::Utility::counterFromStatNames(scope, {prefix, stat_names.NAME##_}))
#define MAKE_STATS_STRUCT_GAUGE_HELPER_(NAME, MODE)                                                \
  , NAME##_(Envoy::Stats::Utility::gaugeFromStatNames(scope, {prefix, stat_names.NAME##_},         \
                                                      Envoy::Stats::Gauge::ImportMode::MODE))
#define MAKE_STATS_STRUCT_HISTOGRAM_HELPER_(NAME, UNIT)                                            \
  , NAME##_(Envoy::Stats::Utility::histogramFromStatNames(scope, {prefix, stat_names.NAME##_},     \
                                                          Envoy::Stats::Histogram::Unit::UNIT))

#define MAKE_STATS_STRUCT_TEXT_READOUT_HELPER_(NAME)                                               \
  , NAME##_(Envoy::Stats::Utility::textReadoutFromStatNames(scope, {prefix, stat_names.NAME##_}))
#define MAKE_STAT_NAMES_STRUCT(StatNamesStruct, ALL_STATS)                                         \
  struct StatNamesStruct {                                                                         \
    explicit StatNamesStruct(Envoy::Stats::SymbolTable& symbol_table)                              \
        : pool_(symbol_table)                                                                      \
              ALL_STATS(GENERATE_STAT_NAME_INIT, GENERATE_STAT_NAME_INIT, GENERATE_STAT_NAME_INIT, \
                        GENERATE_STAT_NAME_INIT, GENERATE_STAT_NAME_INIT) {}                       \
    Envoy::Stats::StatNamePool pool_;                                                              \
    ALL_STATS(GENERATE_STAT_NAME_STRUCT, GENERATE_STAT_NAME_STRUCT, GENERATE_STAT_NAME_STRUCT,     \
              GENERATE_STAT_NAME_STRUCT, GENERATE_STAT_NAME_STRUCT)                                \
  }
#define NULL_POOL_GAUGE(POOL) (POOL).nullGauge(NULL_STAT_DECL_IGNORE_MODE_
#define NULL_STAT_DECL_(X) std::string(#X)),
#define NULL_STAT_DECL_IGNORE_MODE_(X, MODE) std::string(#X)),
#define POOL_COUNTER(POOL) POOL_COUNTER_PREFIX(POOL, "")
#define POOL_COUNTER_PREFIX(POOL, PREFIX) (POOL).counterFromString(Envoy::statPrefixJoin(PREFIX, FINISH_STAT_DECL_
#define POOL_GAUGE(POOL) POOL_GAUGE_PREFIX(POOL, "")
#define POOL_GAUGE_PREFIX(POOL, PREFIX) (POOL).gaugeFromString(Envoy::statPrefixJoin(PREFIX, FINISH_STAT_DECL_MODE_
#define POOL_HISTOGRAM(POOL) POOL_HISTOGRAM_PREFIX(POOL, "")
#define POOL_HISTOGRAM_PREFIX(POOL, PREFIX) (POOL).histogramFromString(Envoy::statPrefixJoin(PREFIX, FINISH_STAT_DECL_UNIT_
#define POOL_STAT_NAME_PREFIX(POOL, PREFIX) (POOL).symbolTable().textReadoutFromString(Envoy::statPrefixJoin(PREFIX, FINISH_STAT_DECL_
#define POOL_TEXT_READOUT(POOL) POOL_TEXT_READOUT_PREFIX(POOL, "")
#define POOL_TEXT_READOUT_PREFIX(POOL, PREFIX) (POOL).textReadoutFromString(Envoy::statPrefixJoin(PREFIX, FINISH_STAT_DECL_




#define END_TRY }
#define TEST_THREAD_SUPPORTED 1
#define TRY_ASSERT_MAIN_THREAD                                                                     \
  try {                                                                                            \
    ASSERT_IS_MAIN_OR_TEST_THREAD();
#define TRY_NEEDS_AUDIT try

