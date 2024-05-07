
#include<limits>










#include<unistd.h>

#include<tuple>










#include<stack>








#include<arpa/inet.h>











#include<cstring>













#include<cstdint>
#include<sys/socket.h>











#include<list>





#include<atomic>
#include<ifaddrs.h>


#include<numeric>


#include<stdexcept>


#include<sys/ioctl.h>
#include<linux/netfilter_ipv4.h>









#include<netdb.h>



#include<netinet/in.h>









#include<sys/mman.h>


#include<chrono>









#include<time.h>


#include<ostream>


#include<netinet/tcp.h>


#include<array>






#include<map>



#include<sstream>
#include<set>


#include<string>

#include<memory>



#include<sys/stat.h>
#include<stdint.h>




#include<iostream>











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
#define ALL_ZSTD_DECOMPRESSOR_STATS(COUNTER)                                                       \
  COUNTER(zstd_generic_error)                                                                      \
  COUNTER(zstd_dictionary_error)                                                                   \
  COUNTER(zstd_checksum_wrong_error)                                                               \
  COUNTER(zstd_memory_error)
#define ALL_CLUSTER_CIRCUIT_BREAKERS_STATS(COUNTER, GAUGE, HISTOGRAM, TEXT_READOUT, STATNAME)      \
  GAUGE(cx_open, Accumulate)                                                                       \
  GAUGE(cx_pool_open, Accumulate)                                                                  \
  GAUGE(rq_open, Accumulate)                                                                       \
  GAUGE(rq_pending_open, Accumulate)                                                               \
  GAUGE(rq_retry_open, Accumulate)                                                                 \
  GAUGE(remaining_cx, Accumulate)                                                                  \
  GAUGE(remaining_cx_pools, Accumulate)                                                            \
  GAUGE(remaining_pending, Accumulate)                                                             \
  GAUGE(remaining_retries, Accumulate)                                                             \
  GAUGE(remaining_rq, Accumulate)                                                                  \
  STATNAME(circuit_breakers)                                                                       \
  STATNAME(default)                                                                                \
  STATNAME(high)
#define ALL_CLUSTER_LOAD_REPORT_STATS(COUNTER, GAUGE, HISTOGRAM, TEXT_READOUT, STATNAME)           \
  COUNTER(upstream_rq_dropped)
#define ALL_CLUSTER_REQUEST_RESPONSE_SIZE_STATS(COUNTER, GAUGE, HISTOGRAM, TEXT_READOUT, STATNAME) \
  HISTOGRAM(upstream_rq_headers_size, Bytes)                                                       \
  HISTOGRAM(upstream_rq_body_size, Bytes)                                                          \
  HISTOGRAM(upstream_rs_headers_size, Bytes)                                                       \
  HISTOGRAM(upstream_rs_body_size, Bytes)
#define ALL_CLUSTER_STATS(COUNTER, GAUGE, HISTOGRAM, TEXT_READOUT, STATNAME)                       \
  COUNTER(assignment_stale)                                                                        \
  COUNTER(assignment_timeout_received)                                                             \
  COUNTER(bind_errors)                                                                             \
  COUNTER(lb_healthy_panic)                                                                        \
  COUNTER(lb_local_cluster_not_ok)                                                                 \
  COUNTER(lb_recalculate_zone_structures)                                                          \
  COUNTER(lb_subsets_created)                                                                      \
  COUNTER(lb_subsets_fallback)                                                                     \
  COUNTER(lb_subsets_fallback_panic)                                                               \
  COUNTER(lb_subsets_removed)                                                                      \
  COUNTER(lb_subsets_selected)                                                                     \
  COUNTER(lb_zone_cluster_too_small)                                                               \
  COUNTER(lb_zone_no_capacity_left)                                                                \
  COUNTER(lb_zone_number_differs)                                                                  \
  COUNTER(lb_zone_routing_all_directly)                                                            \
  COUNTER(lb_zone_routing_cross_zone)                                                              \
  COUNTER(lb_zone_routing_sampled)                                                                 \
  COUNTER(membership_change)                                                                       \
  COUNTER(original_dst_host_invalid)                                                               \
  COUNTER(retry_or_shadow_abandoned)                                                               \
  COUNTER(update_attempt)                                                                          \
  COUNTER(update_empty)                                                                            \
  COUNTER(update_failure)                                                                          \
  COUNTER(update_no_rebuild)                                                                       \
  COUNTER(update_success)                                                                          \
  COUNTER(upstream_cx_close_notify)                                                                \
  COUNTER(upstream_cx_connect_attempts_exceeded)                                                   \
  COUNTER(upstream_cx_connect_fail)                                                                \
  COUNTER(upstream_cx_connect_timeout)                                                             \
  COUNTER(upstream_cx_connect_with_0_rtt)                                                          \
  COUNTER(upstream_cx_destroy)                                                                     \
  COUNTER(upstream_cx_destroy_local)                                                               \
  COUNTER(upstream_cx_destroy_local_with_active_rq)                                                \
  COUNTER(upstream_cx_destroy_remote)                                                              \
  COUNTER(upstream_cx_destroy_remote_with_active_rq)                                               \
  COUNTER(upstream_cx_destroy_with_active_rq)                                                      \
  COUNTER(upstream_cx_http1_total)                                                                 \
  COUNTER(upstream_cx_http2_total)                                                                 \
  COUNTER(upstream_cx_http3_total)                                                                 \
  COUNTER(upstream_cx_idle_timeout)                                                                \
  COUNTER(upstream_cx_max_duration_reached)                                                        \
  COUNTER(upstream_cx_max_requests)                                                                \
  COUNTER(upstream_cx_none_healthy)                                                                \
  COUNTER(upstream_cx_overflow)                                                                    \
  COUNTER(upstream_cx_pool_overflow)                                                               \
  COUNTER(upstream_cx_protocol_error)                                                              \
  COUNTER(upstream_cx_rx_bytes_total)                                                              \
  COUNTER(upstream_cx_total)                                                                       \
  COUNTER(upstream_cx_tx_bytes_total)                                                              \
  COUNTER(upstream_flow_control_backed_up_total)                                                   \
  COUNTER(upstream_flow_control_drained_total)                                                     \
  COUNTER(upstream_flow_control_paused_reading_total)                                              \
  COUNTER(upstream_flow_control_resumed_reading_total)                                             \
  COUNTER(upstream_internal_redirect_failed_total)                                                 \
  COUNTER(upstream_internal_redirect_succeeded_total)                                              \
  COUNTER(upstream_rq_cancelled)                                                                   \
  COUNTER(upstream_rq_completed)                                                                   \
  COUNTER(upstream_rq_maintenance_mode)                                                            \
  COUNTER(upstream_rq_max_duration_reached)                                                        \
  COUNTER(upstream_rq_pending_failure_eject)                                                       \
  COUNTER(upstream_rq_pending_overflow)                                                            \
  COUNTER(upstream_rq_pending_total)                                                               \
  COUNTER(upstream_rq_per_try_timeout)                                                             \
  COUNTER(upstream_rq_per_try_idle_timeout)                                                        \
  COUNTER(upstream_rq_retry)                                                                       \
  COUNTER(upstream_rq_retry_backoff_exponential)                                                   \
  COUNTER(upstream_rq_retry_backoff_ratelimited)                                                   \
  COUNTER(upstream_rq_retry_limit_exceeded)                                                        \
  COUNTER(upstream_rq_retry_overflow)                                                              \
  COUNTER(upstream_rq_retry_success)                                                               \
  COUNTER(upstream_rq_rx_reset)                                                                    \
  COUNTER(upstream_rq_timeout)                                                                     \
  COUNTER(upstream_rq_total)                                                                       \
  COUNTER(upstream_rq_tx_reset)                                                                    \
  GAUGE(lb_subsets_active, Accumulate)                                                             \
  GAUGE(max_host_weight, NeverImport)                                                              \
  GAUGE(membership_degraded, NeverImport)                                                          \
  GAUGE(membership_excluded, NeverImport)                                                          \
  GAUGE(membership_healthy, NeverImport)                                                           \
  GAUGE(membership_total, NeverImport)                                                             \
  GAUGE(upstream_cx_active, Accumulate)                                                            \
  GAUGE(upstream_cx_rx_bytes_buffered, Accumulate)                                                 \
  GAUGE(upstream_cx_tx_bytes_buffered, Accumulate)                                                 \
  GAUGE(upstream_rq_active, Accumulate)                                                            \
  GAUGE(upstream_rq_pending_active, Accumulate)                                                    \
  GAUGE(version, NeverImport)                                                                      \
  HISTOGRAM(upstream_cx_connect_ms, Milliseconds)                                                  \
  HISTOGRAM(upstream_cx_length_ms, Milliseconds)
#define ALL_CLUSTER_TIMEOUT_BUDGET_STATS(COUNTER, GAUGE, HISTOGRAM, TEXT_READOUT, STATNAME)        \
  HISTOGRAM(upstream_rq_timeout_budget_percent_used, Unspecified)                                  \
  HISTOGRAM(upstream_rq_timeout_budget_per_try_percent_used, Unspecified)
#define DECLARE_ENUM(name, value) name = value,
#define HEALTH_FLAG_ENUM_VALUES(m)                                               \
                        \
  m(FAILED_ACTIVE_HC, 0x1)                                                       \
          \
  m(FAILED_OUTLIER_CHECK, 0x02)                                                  \
                          \
  m(FAILED_EDS_HEALTH, 0x04)                                                     \
   \
  m(DEGRADED_ACTIVE_HC, 0x08)                                                    \
                           \
  m(DEGRADED_EDS_HEALTH, 0x10)                                                   \
        \
                                                                 \
  m(PENDING_DYNAMIC_REMOVAL, 0x20)                                               \
                       \
  m(PENDING_ACTIVE_HC, 0x40)                                                     \
       \
    \
                                              \
  m(EXCLUDED_VIA_IMMEDIATE_HC_FAIL, 0x80)                                        \
                                  \
  m(ACTIVE_HC_TIMEOUT, 0x100)
#define PROTOBUF_GET_MS_OR_DEFAULT(message, field_name, default_value)                             \
  ((message).has_##field_name() ? DurationUtil::durationToMilliseconds((message).field_name())     \
                                : (default_value))
#define PROTOBUF_GET_MS_REQUIRED(message, field_name)                                              \
  ([](const auto& msg) {                                                                           \
    if (!msg.has_##field_name()) {                                                                 \
      ::Envoy::ProtoExceptionUtil::throwMissingFieldException(#field_name, msg);                   \
    }                                                                                              \
    return DurationUtil::durationToMilliseconds(msg.field_name());                                 \
  }((message)))
#define PROTOBUF_GET_OPTIONAL_MS(message, field_name)                                              \
  ((message).has_##field_name()                                                                    \
       ? absl::optional<std::chrono::milliseconds>(                                                \
             DurationUtil::durationToMilliseconds((message).field_name()))                         \
       : absl::nullopt)
#define PROTOBUF_GET_SECONDS_REQUIRED(message, field_name)                                         \
  ([](const auto& msg) {                                                                           \
    if (!msg.has_##field_name()) {                                                                 \
      ::Envoy::ProtoExceptionUtil::throwMissingFieldException(#field_name, msg);                   \
    }                                                                                              \
    return DurationUtil::durationToSeconds(msg.field_name());                                      \
  }((message)))
#define PROTOBUF_GET_STRING_OR_DEFAULT(message, field_name, default_value)                         \
  (!(message).field_name().empty() ? (message).field_name() : (default_value))
#define PROTOBUF_GET_WRAPPED_OR_DEFAULT(message, field_name, default_value)                        \
  ((message).has_##field_name() ? (message).field_name().value() : (default_value))
#define PROTOBUF_GET_WRAPPED_REQUIRED(message, field_name)                                         \
  ([](const auto& msg) {                                                                           \
    if (!msg.has_##field_name()) {                                                                 \
      ::Envoy::ProtoExceptionUtil::throwMissingFieldException(#field_name, msg);                   \
    }                                                                                              \
    return msg.field_name().value();                                                               \
  }((message)))
#define PROTOBUF_PERCENT_TO_DOUBLE_OR_DEFAULT(message, field_name, default_value)                  \
  ([](const auto& msg) -> double {                                                                 \
    if (std::isnan(msg.field_name().value())) {                                                    \
      ::Envoy::ExceptionUtil::throwEnvoyException(                                                 \
          fmt::format("Value not in the range of 0..100 range."));                                 \
    }                                                                                              \
    return (msg).has_##field_name() ? (msg).field_name().value() : default_value;                  \
  }((message)))
#define PROTOBUF_PERCENT_TO_ROUNDED_INTEGER_OR_DEFAULT(message, field_name, max_value,             \
                                                       default_value)                              \
  ([](const auto& msg) {                                                                           \
    if (std::isnan(msg.field_name().value())) {                                                    \
      ::Envoy::ExceptionUtil::throwEnvoyException(                                                 \
          fmt::format("Value not in the range of 0..100 range."));                                 \
    }                                                                                              \
    return (msg).has_##field_name()                                                                \
               ? ProtobufPercentHelper::convertPercent((msg).field_name().value(), max_value)      \
               : ProtobufPercentHelper::checkAndReturnDefault(default_value, max_value);           \
  }((message)))
#define ALL_DISPATCHER_STATS(HISTOGRAM)                                                            \
  HISTOGRAM(loop_duration_us, Microseconds)                                                        \
  HISTOGRAM(poll_delay_us, Microseconds)
#define ALL_HOST_STATS(COUNTER, GAUGE)                                                             \
  COUNTER(cx_connect_fail)                                                                         \
  COUNTER(cx_total)                                                                                \
  COUNTER(rq_error)                                                                                \
  COUNTER(rq_success)                                                                              \
  COUNTER(rq_timeout)                                                                              \
  COUNTER(rq_total)                                                                                \
  GAUGE(cx_active)                                                                                 \
  GAUGE(rq_active)
#define ALL_TRANSPORT_SOCKET_MATCH_STATS(COUNTER) COUNTER(total_match_count)
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

#define GENERATE_PRIMITIVE_COUNTER_STRUCT(NAME) Envoy::Stats::PrimitiveCounter NAME##_;
#define GENERATE_PRIMITIVE_GAUGE_STRUCT(NAME) Envoy::Stats::PrimitiveGauge NAME##_;


#define PRIMITIVE_COUNTER_NAME_AND_REFERENCE(X) {absl::string_view(#X), std::ref(X##_)},
#define PRIMITIVE_GAUGE_NAME_AND_REFERENCE(X) {absl::string_view(#X), std::ref(X##_)},
#define ENVOY_MAKE_SOCKET_OPTION_NAME(level, option)                                               \
  Network::SocketOptionName(level, option, #level "/" #option)
#define DEFINE_INLINE_HEADER(name)                                                                 \
  virtual const HeaderEntry* name() const PURE;                                                    \
  virtual size_t remove##name() PURE;                                                              \
  virtual absl::string_view get##name##Value() const PURE;                                         \
  virtual void set##name(absl::string_view value) PURE;
#define DEFINE_INLINE_NUMERIC_HEADER(name)                                                         \
  DEFINE_INLINE_HEADER(name)                                                                       \
  virtual void set##name(uint64_t) PURE;
#define DEFINE_INLINE_STRING_HEADER(name)                                                          \
  DEFINE_INLINE_HEADER(name)                                                                       \
  virtual void append##name(absl::string_view data, absl::string_view delimiter) PURE;             \
  virtual void setReference##name(absl::string_view value) PURE;
#define INLINE_REQ_HEADERS(HEADER_FUNC)                                                            \
  INLINE_REQ_STRING_HEADERS(HEADER_FUNC)                                                           \
  INLINE_REQ_NUMERIC_HEADERS(HEADER_FUNC)
#define INLINE_REQ_NUMERIC_HEADERS(HEADER_FUNC)                                                    \
  HEADER_FUNC(EnvoyExpectedRequestTimeoutMs)                                                       \
  HEADER_FUNC(EnvoyMaxRetries)                                                                     \
  HEADER_FUNC(EnvoyUpstreamRequestTimeoutMs)                                                       \
  HEADER_FUNC(EnvoyUpstreamRequestPerTryTimeoutMs)                                                 \
  HEADER_FUNC(EnvoyUpstreamStreamDurationMs)
#define INLINE_REQ_RESP_HEADERS(HEADER_FUNC)                                                       \
  INLINE_REQ_RESP_STRING_HEADERS(HEADER_FUNC)                                                      \
  INLINE_REQ_RESP_NUMERIC_HEADERS(HEADER_FUNC)
#define INLINE_REQ_RESP_NUMERIC_HEADERS(HEADER_FUNC)                                               \
  HEADER_FUNC(ContentLength)                                                                       \
  HEADER_FUNC(EnvoyAttemptCount)
#define INLINE_REQ_RESP_STRING_HEADERS(HEADER_FUNC)                                                \
  HEADER_FUNC(Connection)                                                                          \
  HEADER_FUNC(ContentType)                                                                         \
  HEADER_FUNC(EnvoyDecoratorOperation)                                                             \
  HEADER_FUNC(KeepAlive)                                                                           \
  HEADER_FUNC(ProxyConnection)                                                                     \
  HEADER_FUNC(ProxyStatus)                                                                         \
  HEADER_FUNC(RequestId)                                                                           \
  HEADER_FUNC(TransferEncoding)                                                                    \
  HEADER_FUNC(Upgrade)                                                                             \
  HEADER_FUNC(Via)
#define INLINE_REQ_STRING_HEADERS(HEADER_FUNC)                                                     \
  HEADER_FUNC(ClientTraceId)                                                                       \
  HEADER_FUNC(EnvoyDownstreamServiceCluster)                                                       \
  HEADER_FUNC(EnvoyDownstreamServiceNode)                                                          \
  HEADER_FUNC(EnvoyExternalAddress)                                                                \
  HEADER_FUNC(EnvoyForceTrace)                                                                     \
  HEADER_FUNC(EnvoyHedgeOnPerTryTimeout)                                                           \
  HEADER_FUNC(EnvoyInternalRequest)                                                                \
  HEADER_FUNC(EnvoyIpTags)                                                                         \
  HEADER_FUNC(EnvoyRetryOn)                                                                        \
  HEADER_FUNC(EnvoyRetryGrpcOn)                                                                    \
  HEADER_FUNC(EnvoyRetriableStatusCodes)                                                           \
  HEADER_FUNC(EnvoyRetriableHeaderNames)                                                           \
  HEADER_FUNC(EnvoyOriginalPath)                                                                   \
  HEADER_FUNC(EnvoyOriginalUrl)                                                                    \
  HEADER_FUNC(EnvoyUpstreamAltStatName)                                                            \
  HEADER_FUNC(EnvoyUpstreamRequestTimeoutAltResponse)                                              \
  HEADER_FUNC(Expect)                                                                              \
  HEADER_FUNC(ForwardedClientCert)                                                                 \
  HEADER_FUNC(ForwardedFor)                                                                        \
  HEADER_FUNC(ForwardedHost)                                                                       \
  HEADER_FUNC(ForwardedProto)                                                                      \
  HEADER_FUNC(GrpcTimeout)                                                                         \
  HEADER_FUNC(Host)                                                                                \
  HEADER_FUNC(Method)                                                                              \
  HEADER_FUNC(Path)                                                                                \
  HEADER_FUNC(Protocol)                                                                            \
  HEADER_FUNC(Scheme)                                                                              \
  HEADER_FUNC(TE)                                                                                  \
  HEADER_FUNC(UserAgent)
#define INLINE_RESP_HEADERS(HEADER_FUNC)                                                           \
  INLINE_RESP_STRING_HEADERS(HEADER_FUNC)                                                          \
  INLINE_RESP_NUMERIC_HEADERS(HEADER_FUNC)
#define INLINE_RESP_HEADERS_TRAILERS(HEADER_FUNC)                                                  \
  INLINE_RESP_STRING_HEADERS_TRAILERS(HEADER_FUNC)                                                 \
  INLINE_RESP_NUMERIC_HEADERS_TRAILERS(HEADER_FUNC)
#define INLINE_RESP_NUMERIC_HEADERS(HEADER_FUNC)                                                   \
  HEADER_FUNC(EnvoyUpstreamServiceTime)                                                            \
  HEADER_FUNC(Status)
#define INLINE_RESP_NUMERIC_HEADERS_TRAILERS(HEADER_FUNC) HEADER_FUNC(GrpcStatus)
#define INLINE_RESP_STRING_HEADERS(HEADER_FUNC)                                                    \
  HEADER_FUNC(Date)                                                                                \
  HEADER_FUNC(EnvoyDegraded)                                                                       \
  HEADER_FUNC(EnvoyImmediateHealthCheckFail)                                                       \
  HEADER_FUNC(EnvoyRateLimited)                                                                    \
  HEADER_FUNC(EnvoyUpstreamCanary)                                                                 \
  HEADER_FUNC(EnvoyUpstreamHealthCheckedCluster)                                                   \
  HEADER_FUNC(Location)                                                                            \
  HEADER_FUNC(Server)
#define INLINE_RESP_STRING_HEADERS_TRAILERS(HEADER_FUNC) HEADER_FUNC(GrpcMessage)
#define RETURN_IF_ERROR(expr)                                                                      \
  do {                                                                                             \
    if (::Envoy::Http::Details::StatusAdapter adapter{(expr)}) {                                   \
    } else {                                                                                       \
      return std::move(adapter.status_);                                                           \
    }                                                                                              \
  } while (false)
#define ALL_VIRTUAL_CLUSTER_STATS(COUNTER, GAUGE, HISTOGRAM, TEXT_READOUT, STATNAME)               \
  COUNTER(upstream_rq_retry)                                                                       \
  COUNTER(upstream_rq_retry_limit_exceeded)                                                        \
  COUNTER(upstream_rq_retry_overflow)                                                              \
  COUNTER(upstream_rq_retry_success)                                                               \
  COUNTER(upstream_rq_timeout)                                                                     \
  COUNTER(upstream_rq_total)                                                                       \
  STATNAME(other)                                                                                  \
  STATNAME(vcluster)                                                                               \
  STATNAME(vhost)
#define SINGLETON_MANAGER_REGISTERED_NAME(NAME) NAME##_singleton_name
#define SINGLETON_MANAGER_REGISTRATION(NAME)                                                       \
  static constexpr char NAME##_singleton_name[] = #NAME "_singleton";                              \
  static Envoy::Registry::RegisterInternalFactory<                                                 \
      Envoy::Singleton::RegistrationImpl<NAME##_singleton_name>, Envoy::Singleton::Registration>   \
      NAME##_singleton_registered_;
#define DECLARE_FACTORY(FACTORY) ABSL_ATTRIBUTE_UNUSED void forceRegister##FACTORY()
#define FACTORY_VERSION(major, minor, patch, ...) major, minor, patch, __VA_ARGS__
#define REGISTER_FACTORY(FACTORY, BASE)                                                            \
  ABSL_ATTRIBUTE_UNUSED void forceRegister##FACTORY() {}                                           \
  static Envoy::Registry::RegisterFactory<     \
                                          FACTORY, BASE>                                           \
      FACTORY##_registered
#define MAKE_ADMIN_HANDLER(X)                                                                      \
  [this](absl::string_view path_and_query, Http::ResponseHeaderMap& response_headers,              \
         Buffer::Instance& data, Server::AdminStream& admin_stream) -> Http::Code {                \
    return X(path_and_query, response_headers, data, admin_stream);                                \
  }
#define ALL_SUBSCRIPTION_STATS(COUNTER, GAUGE, TEXT_READOUT, HISTOGRAM)                            \
  COUNTER(init_fetch_timeout)                                                                      \
  COUNTER(update_attempt)                                                                          \
  COUNTER(update_failure)                                                                          \
  COUNTER(update_rejected)                                                                         \
  COUNTER(update_success)                                                                          \
  GAUGE(update_time, NeverImport)                                                                  \
  GAUGE(version, NeverImport)                                                                      \
  HISTOGRAM(update_duration, Milliseconds)                                                         \
  TEXT_READOUT(version_text)
#define ALL_CONTROL_PLANE_STATS(COUNTER, GAUGE, TEXT_READOUT)                                      \
  COUNTER(rate_limit_enforced)                                                                     \
  GAUGE(connected_state, NeverImport)                                                              \
  GAUGE(pending_requests, Accumulate)                                                              \
  TEXT_READOUT(identifier)
