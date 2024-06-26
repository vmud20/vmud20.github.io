

#include<syslog.h>

#include<fcntl.h>
#include<math.h>




#include<sys/fcntl.h>

#include<sys/wait.h>

#include<time.h>

#include<netinet/in.h>


#include<unistd.h>
#include<netdb.h>

#include<signal.h>

#include<assert.h>

#include<sys/stat.h>

#include<sys/ioctl.h>
#include<sys/param.h>


#include<arpa/inet.h>

#include<errno.h>
#include<sys/un.h>
#define DIROBJ_MAX_SIG_LEN 256


#define MAX_NETWORKSTATUS_AGE (10*24*60*60)
#define NSSET_ACCEPT_OBSOLETE 8
#define NSSET_DONT_DOWNLOAD_CERTS 4
#define NSSET_FROM_CACHE 1
#define NSSET_REQUIRE_FLAVOR 16
#define NSSET_WAS_WAITING_FOR_CERTS 2


#define microdesc_free(md) \
  microdesc_free_((md), "__FILE__", "__LINE__")

#define TRUSTED_DIRS_CERTS_SRC_DL_BY_ID_DIGEST 2
#define TRUSTED_DIRS_CERTS_SRC_DL_BY_ID_SK_DIGEST 3
#define TRUSTED_DIRS_CERTS_SRC_FROM_STORE 1
#define TRUSTED_DIRS_CERTS_SRC_FROM_VOTE 4
#define TRUSTED_DIRS_CERTS_SRC_SELF 0
#define router_digest_is_trusted_dir(d) \
  router_digest_is_trusted_dir_type((d), NO_DIRINFO)
#define NODE_DESC_BUF_LEN (MAX_VERBOSE_NICKNAME_LEN+4+TOR_ADDR_BUF_LEN)


#define POLICY_BUF_LEN 72

#define DEFAULT_MAX_UNMEASURED_BW_KB 20
#define DGV_BY_ID 1
#define DGV_INCLUDE_PENDING 2
#define DGV_INCLUDE_PREVIOUS 4
#define MAX_SUPPORTED_CONSENSUS_METHOD 17
#define MIN_DIST_SECONDS 20
#define MIN_METHOD_FOR_A_LINES 14
#define MIN_METHOD_FOR_BW_WEIGHTS 9
#define MIN_METHOD_FOR_FOOTER 9
#define MIN_METHOD_FOR_MAJORITY_PARAMS 12
#define MIN_METHOD_FOR_MANDATORY_MICRODESC 13
#define MIN_METHOD_FOR_MICRODESC 8
#define MIN_METHOD_FOR_NTOR_KEY 16
#define MIN_METHOD_FOR_P6_LINES 15
#define MIN_METHOD_FOR_PARAMS 7
#define MIN_METHOD_TO_CLIP_UNMEASURED_BW 17
#define MIN_METHOD_TO_CUT_BADEXIT_WEIGHT 11
#define MIN_VOTE_INTERVAL 300
#define MIN_VOTE_SECONDS 20

#define MAX_EXITPOLICY_SUMMARY_LEN 1000
#define MAX_MEASUREMENT_AGE (3*24*60*60) 
#define MAX_V_LINE_LEN 128
#define REACHABILITY_MODULO_PER_TEST 128
#define REACHABILITY_TEST_CYCLE_PERIOD \
  (REACHABILITY_TEST_INTERVAL*REACHABILITY_MODULO_PER_TEST)
#define REACHABILITY_TEST_INTERVAL 10



#define get_datadir_fname(sub1) get_datadir_fname2_suffix((sub1), NULL, NULL)
#define get_datadir_fname2(sub1,sub2) \
  get_datadir_fname2_suffix((sub1), (sub2), NULL)
#define get_datadir_fname2_suffix(sub1, sub2, suffix) \
  options_get_datadir_fname2_suffix(get_options(), (sub1), (sub2), (suffix))
#define get_datadir_fname_suffix(sub1, suffix) \
  get_datadir_fname2_suffix((sub1), NULL, (suffix))
#define get_primary_dir_port() \
  (get_first_advertised_port_by_type_af(CONN_TYPE_DIR_LISTENER, AF_INET))
#define get_primary_or_port() \
  (get_first_advertised_port_by_type_af(CONN_TYPE_OR_LISTENER, AF_INET))
#define ALL_DIRINFO ((dirinfo_type_t)((1<<7)-1))
#define AP_CONN_STATE_CIRCUIT_WAIT 8
#define AP_CONN_STATE_CONNECT_WAIT 9
#define AP_CONN_STATE_CONTROLLER_WAIT 7
#define AP_CONN_STATE_IS_UNATTACHED(s) \
  ((s) <= AP_CONN_STATE_CIRCUIT_WAIT || (s) == AP_CONN_STATE_NATD_WAIT)
#define AP_CONN_STATE_MAX_ 12
#define AP_CONN_STATE_MIN_ 5
#define AP_CONN_STATE_NATD_WAIT 12
#define AP_CONN_STATE_OPEN 11
#define AP_CONN_STATE_RENDDESC_WAIT 6
#define AP_CONN_STATE_RESOLVE_WAIT 10
#define AP_CONN_STATE_SOCKS_WAIT 5
#define AUTHTYPE_RSA_SHA256_TLSSECRET 1
#define BASE_CONNECTION_MAGIC 0x7C3C304Eu
#define BW_MAX_WEIGHT_SCALE INT32_MAX
#define BW_MIN_WEIGHT_SCALE 1
#define BW_WEIGHT_SCALE   10000
#define CBT_BIN_WIDTH ((build_time_t)50)
#define CBT_BUILD_ABANDONED ((build_time_t)(INT32_MAX-1))
#define CBT_BUILD_TIME_MAX ((build_time_t)(INT32_MAX))
#define CBT_DEFAULT_CLOSE_QUANTILE 95
#define CBT_DEFAULT_MAX_RECENT_TIMEOUT_COUNT (CBT_DEFAULT_RECENT_CIRCUITS*9/10)
#define CBT_DEFAULT_MIN_CIRCUITS_TO_OBSERVE 100
#define CBT_DEFAULT_NUM_XM_MODES 3
#define CBT_DEFAULT_QUANTILE_CUTOFF 80
#define CBT_DEFAULT_RECENT_CIRCUITS 20
#define CBT_DEFAULT_TEST_FREQUENCY 60
#define CBT_DEFAULT_TIMEOUT_INITIAL_VALUE (60*1000)
#define CBT_DEFAULT_TIMEOUT_MIN_VALUE (1500)
#define CBT_MAX_CLOSE_QUANTILE CBT_MAX_QUANTILE_CUTOFF
#define CBT_MAX_MAX_RECENT_TIMEOUT_COUNT 10000
#define CBT_MAX_MIN_CIRCUITS_TO_OBSERVE 10000
#define CBT_MAX_NUM_XM_MODES 20
#define CBT_MAX_QUANTILE_CUTOFF 99
#define CBT_MAX_RECENT_CIRCUITS 1000
#define CBT_MAX_TEST_FREQUENCY INT32_MAX
#define CBT_MAX_TIMEOUT_INITIAL_VALUE INT32_MAX
#define CBT_MAX_TIMEOUT_MIN_VALUE INT32_MAX
#define CBT_MIN_CLOSE_QUANTILE CBT_MIN_QUANTILE_CUTOFF
#define CBT_MIN_MAX_RECENT_TIMEOUT_COUNT 3
#define CBT_MIN_MIN_CIRCUITS_TO_OBSERVE 1
#define CBT_MIN_NUM_XM_MODES 1
#define CBT_MIN_QUANTILE_CUTOFF 10
#define CBT_MIN_RECENT_CIRCUITS 3
#define CBT_MIN_TEST_FREQUENCY 1
#define CBT_MIN_TIMEOUT_INITIAL_VALUE CBT_MIN_TIMEOUT_MIN_VALUE
#define CBT_MIN_TIMEOUT_MIN_VALUE 500
#define CBT_NCIRCUITS_TO_OBSERVE 1000
#define CBT_SAVE_STATE_EVERY 10
#define CELL_AUTHENTICATE 131
#define CELL_AUTHORIZE 132
#define CELL_AUTH_CHALLENGE 130
#define CELL_CERTS 129
#define CELL_CREATE 1
#define CELL_CREATE2 10
#define CELL_CREATED 2
#define CELL_CREATED2 11
#define CELL_CREATED_FAST 6
#define CELL_CREATE_FAST 5
#define CELL_DESTROY 4
#define CELL_MAX_NETWORK_SIZE 514
#define CELL_NETINFO 8
#define CELL_PADDING 0
#define CELL_PAYLOAD_SIZE 509
#define CELL_RELAY 3
#define CELL_RELAY_EARLY 9
#define CELL_VERSIONS 7
#define CELL_VPADDING 128
#define CFG_AUTO_PORT 0xc4005e
#define CIRCUIT_IS_ORCIRC(c) (((circuit_t *)(c))->magic == OR_CIRCUIT_MAGIC)
#define CIRCUIT_IS_ORIGIN(c) (CIRCUIT_PURPOSE_IS_ORIGIN((c)->purpose))
#define CIRCUIT_PURPOSE_CONTROLLER 19
#define CIRCUIT_PURPOSE_C_ESTABLISH_REND 9
#define CIRCUIT_PURPOSE_C_GENERAL 5
#define CIRCUIT_PURPOSE_C_INTRODUCE_ACKED 8
#define CIRCUIT_PURPOSE_C_INTRODUCE_ACK_WAIT 7
#define CIRCUIT_PURPOSE_C_INTRODUCING 6
#define CIRCUIT_PURPOSE_C_MAX_ 13
#define CIRCUIT_PURPOSE_C_MEASURE_TIMEOUT 13
#define CIRCUIT_PURPOSE_C_REND_JOINED 12
#define CIRCUIT_PURPOSE_C_REND_READY 10
#define CIRCUIT_PURPOSE_C_REND_READY_INTRO_ACKED 11
#define CIRCUIT_PURPOSE_INTRO_POINT 2
#define CIRCUIT_PURPOSE_IS_CLIENT(p)  \
  ((p)> CIRCUIT_PURPOSE_OR_MAX_ &&    \
   (p)<=CIRCUIT_PURPOSE_C_MAX_)
#define CIRCUIT_PURPOSE_IS_ESTABLISHED_REND(p) \
  ((p) == CIRCUIT_PURPOSE_C_REND_JOINED ||     \
   (p) == CIRCUIT_PURPOSE_S_REND_JOINED)
#define CIRCUIT_PURPOSE_IS_ORIGIN(p) ((p)>CIRCUIT_PURPOSE_OR_MAX_)
#define CIRCUIT_PURPOSE_MAX_ 20
#define CIRCUIT_PURPOSE_MIN_ 1
#define CIRCUIT_PURPOSE_OR 1
#define CIRCUIT_PURPOSE_OR_MAX_ 4
#define CIRCUIT_PURPOSE_OR_MIN_ 1
#define CIRCUIT_PURPOSE_PATH_BIAS_TESTING 20
#define CIRCUIT_PURPOSE_REND_ESTABLISHED 4
#define CIRCUIT_PURPOSE_REND_POINT_WAITING 3
#define CIRCUIT_PURPOSE_S_CONNECT_REND 16
#define CIRCUIT_PURPOSE_S_ESTABLISH_INTRO 14
#define CIRCUIT_PURPOSE_S_INTRO 15
#define CIRCUIT_PURPOSE_S_REND_JOINED 17
#define CIRCUIT_PURPOSE_TESTING 18
#define CIRCUIT_PURPOSE_UNKNOWN 255
#define CIRCUIT_STATE_BUILDING 0
#define CIRCUIT_STATE_CHAN_WAIT 2
#define CIRCUIT_STATE_ONIONSKIN_PENDING 1
#define CIRCUIT_STATE_OPEN 3
#define CIRCWINDOW_INCREMENT 100
#define CIRCWINDOW_START 1000
#define CIRCWINDOW_START_MAX 1000
#define CIRCWINDOW_START_MIN 100
#define CONFIG_LINE_APPEND 1
#define CONFIG_LINE_CLEAR 2
#define CONFIG_LINE_NORMAL 0
#define CONN_IS_EDGE(x) \
  ((x)->type == CONN_TYPE_EXIT || (x)->type == CONN_TYPE_AP)
#define CONN_LOG_PROTECT(conn, stmt)                                    \
  STMT_BEGIN                                                            \
    int _log_conn_is_control;                                           \
    tor_assert(conn);                                                   \
    _log_conn_is_control = (conn->type == CONN_TYPE_CONTROL);           \
    if (_log_conn_is_control)                                           \
      disable_control_logging();                                        \
  STMT_BEGIN stmt; STMT_END;                                            \
    if (_log_conn_is_control)                                           \
      enable_control_logging();                                         \
  STMT_END
#define CONN_TYPE_AP 7
#define CONN_TYPE_AP_DNS_LISTENER 15
#define CONN_TYPE_AP_LISTENER 6
#define CONN_TYPE_AP_NATD_LISTENER 14
#define CONN_TYPE_AP_TRANS_LISTENER 13
#define CONN_TYPE_CONTROL 12
#define CONN_TYPE_CONTROL_LISTENER 11
#define CONN_TYPE_CPUWORKER 10
#define CONN_TYPE_DIR 9
#define CONN_TYPE_DIR_LISTENER 8
#define CONN_TYPE_EXIT 5
#define CONN_TYPE_MAX_ 15
#define CONN_TYPE_MIN_ 3
#define CONN_TYPE_OR 4
#define CONN_TYPE_OR_LISTENER 3
#define CONTROL_CONNECTION_MAGIC 0x8abc765du
#define CONTROL_CONN_STATE_MAX_ 2
#define CONTROL_CONN_STATE_MIN_ 1
#define CONTROL_CONN_STATE_NEEDAUTH 2
#define CONTROL_CONN_STATE_OPEN 1
#define CPATH_KEY_MATERIAL_LEN (20*2+16*2)
#define CPATH_STATE_AWAITING_KEYS 1
#define CPATH_STATE_CLOSED 0
#define CPATH_STATE_OPEN 2
#define CPUWORKER_STATE_BUSY_ONION 2
#define CPUWORKER_STATE_IDLE 1
#define CPUWORKER_STATE_MAX_ 2
#define CPUWORKER_STATE_MIN_ 1
#define CPUWORKER_TASK_ONION CPUWORKER_STATE_BUSY_ONION
#define CPUWORKER_TASK_SHUTDOWN 255
#define CRYPT_PATH_MAGIC 0x70127012u
#define DEFAULT_CLIENT_NICKNAME "client"
#define DEFAULT_DNS_TTL (30*60)
#define DEFAULT_ROUTE_LEN 3
#define DH_KEY_LEN DH_BYTES
#define DIR_CONNECTION_MAGIC 0x9988ffeeu
#define DIR_CONN_IS_SERVER(conn) ((conn)->purpose == DIR_PURPOSE_SERVER)
#define DIR_CONN_STATE_CLIENT_FINISHED 4
#define DIR_CONN_STATE_CLIENT_READING 3
#define DIR_CONN_STATE_CLIENT_SENDING 2
#define DIR_CONN_STATE_CONNECTING 1
#define DIR_CONN_STATE_MAX_ 6
#define DIR_CONN_STATE_MIN_ 1
#define DIR_CONN_STATE_SERVER_COMMAND_WAIT 5
#define DIR_CONN_STATE_SERVER_WRITING 6
#define DIR_PURPOSE_FETCH_CERTIFICATE 15
#define DIR_PURPOSE_FETCH_CONSENSUS 14
#define DIR_PURPOSE_FETCH_DETACHED_SIGNATURES 13
#define DIR_PURPOSE_FETCH_EXTRAINFO 7
#define DIR_PURPOSE_FETCH_MICRODESC 19
#define DIR_PURPOSE_FETCH_RENDDESC 3
#define DIR_PURPOSE_FETCH_RENDDESC_V2 18
#define DIR_PURPOSE_FETCH_SERVERDESC 6
#define DIR_PURPOSE_FETCH_STATUS_VOTE 12
#define DIR_PURPOSE_FETCH_V2_NETWORKSTATUS 5
#define DIR_PURPOSE_HAS_FETCHED_RENDDESC 4
#define DIR_PURPOSE_IS_UPLOAD(p)                \
  ((p)==DIR_PURPOSE_UPLOAD_DIR ||               \
   (p)==DIR_PURPOSE_UPLOAD_RENDDESC ||          \
   (p)==DIR_PURPOSE_UPLOAD_VOTE ||              \
   (p)==DIR_PURPOSE_UPLOAD_SIGNATURES)
#define DIR_PURPOSE_MAX_ 19
#define DIR_PURPOSE_MIN_ 3
#define DIR_PURPOSE_SERVER 16
#define DIR_PURPOSE_UPLOAD_DIR 8
#define DIR_PURPOSE_UPLOAD_RENDDESC 9
#define DIR_PURPOSE_UPLOAD_RENDDESC_V2 17
#define DIR_PURPOSE_UPLOAD_SIGNATURES 11
#define DIR_PURPOSE_UPLOAD_VOTE 10
#define DOWNCAST(to, ptr) ((to*)SUBTYPE_P(ptr, to, base_))
#define EDGE_CONNECTION_MAGIC 0xF0374013u
#define ELSE_IF_NO_BUFFEREVENT ; else
#define END_CIRC_AT_ORIGIN              -1
#define END_CIRC_REASON_CHANNEL_CLOSED  8
#define END_CIRC_REASON_CONNECTFAILED   6
#define END_CIRC_REASON_DESTROYED       11
#define END_CIRC_REASON_FINISHED        9
#define END_CIRC_REASON_FLAG_REMOTE     512
#define END_CIRC_REASON_HIBERNATING     4
#define END_CIRC_REASON_INTERNAL        2
#define END_CIRC_REASON_MAX_            12
#define END_CIRC_REASON_MEASUREMENT_EXPIRED -3
#define END_CIRC_REASON_MIN_            0
#define END_CIRC_REASON_NONE            0
#define END_CIRC_REASON_NOPATH          -2
#define END_CIRC_REASON_NOSUCHSERVICE   12
#define END_CIRC_REASON_OR_IDENTITY     7
#define END_CIRC_REASON_REQUESTED       3
#define END_CIRC_REASON_RESOURCELIMIT   5
#define END_CIRC_REASON_TIMEOUT         10
#define END_CIRC_REASON_TORPROTOCOL     1
#define END_OR_CONN_REASON_CONNRESET      4 
#define END_OR_CONN_REASON_DONE           1
#define END_OR_CONN_REASON_IO_ERROR       7 
#define END_OR_CONN_REASON_MISC           9
#define END_OR_CONN_REASON_NO_ROUTE       6 
#define END_OR_CONN_REASON_OR_IDENTITY    3
#define END_OR_CONN_REASON_REFUSED        2 
#define END_OR_CONN_REASON_RESOURCE_LIMIT 8 
#define END_OR_CONN_REASON_TIMEOUT        5
#define END_STREAM_REASON_CANT_ATTACH 257
#define END_STREAM_REASON_CANT_FETCH_ORIG_DEST 260
#define END_STREAM_REASON_CONNECTREFUSED 3
#define END_STREAM_REASON_CONNRESET 12
#define END_STREAM_REASON_DESTROY 5
#define END_STREAM_REASON_DONE 6
#define END_STREAM_REASON_ENTRYPOLICY 15
#define END_STREAM_REASON_EXITPOLICY 4
#define END_STREAM_REASON_FLAG_ALREADY_SENT_CLOSED 1024
#define END_STREAM_REASON_FLAG_ALREADY_SOCKS_REPLIED 2048
#define END_STREAM_REASON_FLAG_REMOTE 512
#define END_STREAM_REASON_HIBERNATING 9
#define END_STREAM_REASON_INTERNAL 10
#define END_STREAM_REASON_INVALID_NATD_DEST 261
#define END_STREAM_REASON_MASK 511
#define END_STREAM_REASON_MISC 1
#define END_STREAM_REASON_NET_UNREACHABLE 258
#define END_STREAM_REASON_NOROUTE 8
#define END_STREAM_REASON_NOTDIRECTORY 14
#define END_STREAM_REASON_PRIVATE_ADDR 262
#define END_STREAM_REASON_RESOLVEFAILED 2
#define END_STREAM_REASON_RESOURCELIMIT 11
#define END_STREAM_REASON_SOCKSPROTOCOL 259
#define END_STREAM_REASON_TIMEOUT 7
#define END_STREAM_REASON_TORPROTOCOL 13
#define ENTRY_CONNECTION_MAGIC 0xbb4a5703
#define ENTRY_TO_CONN(c) (TO_CONN(ENTRY_TO_EDGE_CONN(c)))
#define ENTRY_TO_EDGE_CONN(c) (&(((c))->edge_))
#define EXIT_CONN_STATE_CONNECTING 2
#define EXIT_CONN_STATE_MAX_ 4
#define EXIT_CONN_STATE_MIN_ 1
#define EXIT_CONN_STATE_OPEN 3
#define EXIT_CONN_STATE_RESOLVEFAILED 4
#define EXIT_CONN_STATE_RESOLVING 1
#define EXIT_PURPOSE_CONNECT 1
#define EXIT_PURPOSE_MAX_ 2
#define EXIT_PURPOSE_MIN_ 1
#define EXIT_PURPOSE_RESOLVE 2
#define GEOIP_NS_RESPONSE_NUM 6
#define HAS_BUFFEREVENT(c) (((c)->bufev) != NULL)
#define IF_HAS_BUFFEREVENT(c, stmt)                \
  if ((c)->bufev) do {                             \
      stmt ;                                       \
  } while (0)
#define IF_HAS_NO_BUFFEREVENT(c)                   \
  if (NULL == (c)->bufev)
#define IMPOSSIBLE_TO_DOWNLOAD 255
#define INSTRUMENT_DOWNLOADS 1
#define INTRO_POINT_LIFETIME_INTRODUCTIONS 16384
#define INTRO_POINT_LIFETIME_MAX_SECONDS (24*60*60)
#define INTRO_POINT_LIFETIME_MIN_SECONDS (18*60*60)
#define ISO_CLIENTADDR  (1u<<4)
#define ISO_CLIENTPROTO (1u<<3)
#define ISO_DEFAULT (ISO_CLIENTADDR|ISO_SOCKSAUTH|ISO_SESSIONGRP|ISO_NYM_EPOCH)
#define ISO_DESTADDR    (1u<<1)
#define ISO_DESTPORT    (1u<<0)
#define ISO_NYM_EPOCH   (1u<<6)
#define ISO_SESSIONGRP  (1u<<5)
#define ISO_SOCKSAUTH   (1u<<2)
#define ISO_STREAM      (1u<<7)
#define LEGAL_NICKNAME_CHARACTERS \
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
#define LISTENER_CONNECTION_MAGIC 0x1a1ac741u
#define LISTENER_STATE_READY 0
#define LOG_PROTOCOL_WARN (get_options()->ProtocolWarnings ? \
                           LOG_WARN : LOG_INFO)
#define MAX_BUF_SIZE ((1<<24)-1) 
#define MAX_CONSTRAINED_TCP_BUFFER 262144  
#define MAX_DESCRIPTOR_UPLOAD_SIZE 20000
#define MAX_DIR_DL_SIZE MAX_BUF_SIZE
#define MAX_DIR_UL_SIZE MAX_BUF_SIZE
#define MAX_DNS_ENTRY_AGE (30*60)
#define MAX_DNS_TTL (3*60*60)
#define MAX_EXTRAINFO_UPLOAD_SIZE 50000
#define MAX_HEADERS_SIZE 50000
#define MAX_HEX_NICKNAME_LEN (HEX_DIGEST_LEN+1)
#define MAX_INTRO_POINT_REACHABILITY_FAILURES 5
#define MAX_KNOWN_FLAGS_IN_VOTE 64
#define MAX_MAX_CLIENT_CIRCUITS_PENDING 1024
#define MAX_MICRODESC_DOWNLOAD_FAILURES 8
#define MAX_NICKNAME_LEN 19
#define MAX_ONION_HANDSHAKE_TYPE 0x0002
#define MAX_RELAY_EARLY_CELLS_PER_CIRCUIT 8
#define MAX_ROUTERDESC_DOWNLOAD_FAILURES 8
#define MAX_SOCKS_ADDR_LEN 256
#define MAX_SOCKS_REPLY_LEN 1024
#define MAX_SSL_KEY_LIFETIME_INTERNAL (2*60*60)
#define MAX_STATUS_TAG_LEN 32
#define MAX_VERBOSE_NICKNAME_LEN (1+HEX_DIGEST_LEN+1+MAX_NICKNAME_LEN)
#define MIN_CIRCUITS_HANDLING_STREAM 2
#define MIN_CONSTRAINED_TCP_BUFFER 2048
#define MIN_DNS_TTL 60
#define MIN_ONION_KEY_LIFETIME (7*24*60*60)
#define NON_ANONYMOUS_MODE_ENABLED 1
#define NUM_CIRCUITS_LAUNCHED_THRESHOLD 10
#define N_CONSENSUS_FLAVORS ((int)(FLAV_MICRODESC)+1)
#define OLD_ROUTER_DESC_MAX_AGE (60*60*24*5)
#define ONION_HANDSHAKE_TYPE_FAST 0x0001
#define ONION_HANDSHAKE_TYPE_NTOR 0x0002
#define ONION_HANDSHAKE_TYPE_TAP  0x0000
#define ORCIRC_MAX_MIDDLE_CELLS (21*(CIRCWINDOW_START_MAX)/10)
#define ORIGIN_CIRCUIT_MAGIC 0x35315243u
#define OR_AUTH_CHALLENGE_LEN 32
#define OR_CERT_TYPE_AUTH_1024 3
#define OR_CERT_TYPE_ID_1024 2
#define OR_CERT_TYPE_TLS_LINK 1
#define OR_CIRCUIT_MAGIC 0x98ABC04Fu
#define OR_CONNECTION_MAGIC 0x7D31FF03u
#define OR_CONN_STATE_CONNECTING 1
#define OR_CONN_STATE_MAX_ 8
#define OR_CONN_STATE_MIN_ 1
#define OR_CONN_STATE_OPEN 8
#define OR_CONN_STATE_OR_HANDSHAKING_V2 6
#define OR_CONN_STATE_OR_HANDSHAKING_V3 7
#define OR_CONN_STATE_PROXY_HANDSHAKING 2
#define OR_CONN_STATE_TLS_CLIENT_RENEGOTIATING 4
#define OR_CONN_STATE_TLS_HANDSHAKING 3
#define OR_CONN_STATE_TLS_SERVER_RENEGOTIATING 5
#define PATHBIAS_SHOULDCOUNT_COUNTED   2
#define PATHBIAS_SHOULDCOUNT_IGNORED   1
#define PATHBIAS_SHOULDCOUNT_UNDECIDED 0
#define PDS_ALLOW_SELF                 (1<<0)
#define PDS_FOR_GUARD (1<<5)
#define PDS_IGNORE_FASCISTFIREWALL     (1<<2)
#define PDS_NO_EXISTING_MICRODESC_FETCH (1<<4)
#define PDS_NO_EXISTING_SERVERDESC_FETCH (1<<3)
#define PDS_PREFER_TUNNELED_DIR_CONNS_ (1<<16)
#define PDS_RETRY_IF_NO_SERVERS        (1<<1)
#define PROXY_CONNECT 1
#define PROXY_CONNECTED 8
#define PROXY_HTTPS_WANT_CONNECT_OK 2
#define PROXY_INFANT 1
#define PROXY_NONE 0
#define PROXY_PLUGGABLE 4
#define PROXY_SOCKS4 2
#define PROXY_SOCKS4_WANT_CONNECT_OK 3
#define PROXY_SOCKS5 3
#define PROXY_SOCKS5_WANT_AUTH_METHOD_NONE 4
#define PROXY_SOCKS5_WANT_AUTH_METHOD_RFC1929 5
#define PROXY_SOCKS5_WANT_AUTH_RFC1929_OK 6
#define PROXY_SOCKS5_WANT_CONNECT_OK 7
#define RELAY_COMMAND_BEGIN 1
#define RELAY_COMMAND_BEGIN_DIR 13
#define RELAY_COMMAND_CONNECTED 4
#define RELAY_COMMAND_DATA 2
#define RELAY_COMMAND_DROP 10
#define RELAY_COMMAND_END 3
#define RELAY_COMMAND_ESTABLISH_INTRO 32
#define RELAY_COMMAND_ESTABLISH_RENDEZVOUS 33
#define RELAY_COMMAND_EXTEND 6
#define RELAY_COMMAND_EXTEND2 14
#define RELAY_COMMAND_EXTENDED 7
#define RELAY_COMMAND_EXTENDED2 15
#define RELAY_COMMAND_INTRODUCE1 34
#define RELAY_COMMAND_INTRODUCE2 35
#define RELAY_COMMAND_INTRODUCE_ACK 40
#define RELAY_COMMAND_INTRO_ESTABLISHED 38
#define RELAY_COMMAND_RENDEZVOUS1 36
#define RELAY_COMMAND_RENDEZVOUS2 37
#define RELAY_COMMAND_RENDEZVOUS_ESTABLISHED 39
#define RELAY_COMMAND_RESOLVE 11
#define RELAY_COMMAND_RESOLVED 12
#define RELAY_COMMAND_SENDME 5
#define RELAY_COMMAND_TRUNCATE 8
#define RELAY_COMMAND_TRUNCATED 9
#define RELAY_HEADER_SIZE (1+2+2+4+2)
#define RELAY_PAYLOAD_SIZE (CELL_PAYLOAD_SIZE-RELAY_HEADER_SIZE)
#define REMAP_STREAM_SOURCE_CACHE 1
#define REMAP_STREAM_SOURCE_EXIT 2
#define REND_BASIC_AUTH_CLIENT_ENTRY_LEN (REND_BASIC_AUTH_CLIENT_ID_LEN \
                                          + CIPHER_KEY_LEN)
#define REND_BASIC_AUTH_CLIENT_ID_LEN 4
#define REND_BASIC_AUTH_CLIENT_MULTIPLE 16
#define REND_CLIENTNAME_MAX_LEN 16
#define REND_COOKIE_LEN DIGEST_LEN
#define REND_DESC_COOKIE_LEN 16
#define REND_DESC_COOKIE_LEN_BASE64 22
#define REND_DESC_ID_V2_LEN_BASE32 32
#define REND_DESC_MAX_SIZE (20 * 1024)
#define REND_INTRO_POINT_ID_LEN_BASE32 32
#define REND_LEGAL_CLIENTNAME_CHARACTERS \
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-_"
#define REND_NUMBER_OF_CONSECUTIVE_REPLICAS 3
#define REND_NUMBER_OF_NON_CONSECUTIVE_REPLICAS 2
#define REND_PROTOCOL_VERSION_BITMASK_WIDTH 16
#define REND_REPLAY_TIME_INTERVAL (5 * 60)
#define REND_SECRET_ID_PART_LEN_BASE32 32
#define REND_SERVICE_ADDRESS_LEN (16+1+5)
#define REND_SERVICE_ID_LEN 10
#define REND_SERVICE_ID_LEN_BASE32 16
#define REND_TIME_PERIOD_OVERLAPPING_V2_DESCS (60*60)
#define REND_TIME_PERIOD_V2_DESC_VALIDITY (24*60*60)
#define REND_TOKEN_LEN REND_COOKIE_LEN
#define RESOLVED_TYPE_ERROR 0xF1
#define RESOLVED_TYPE_ERROR_TRANSIENT 0xF0
#define RESOLVED_TYPE_HOSTNAME 0
#define RESOLVED_TYPE_IPV4 4
#define RESOLVED_TYPE_IPV6 6
#define ROUTER_ANNOTATION_BUF_LEN 256
#define ROUTER_MAX_AGE (60*60*48)
#define ROUTER_MAX_AGE_TO_PUBLISH (60*60*24)
#define ROUTER_MAX_DECLARED_BANDWIDTH INT32_MAX
#define ROUTER_PURPOSE_BRIDGE 2
#define ROUTER_PURPOSE_CONTROLLER 1
#define ROUTER_PURPOSE_GENERAL 0
#define ROUTER_PURPOSE_UNKNOWN 255
#define ROUTER_REQUIRED_MIN_BANDWIDTH (20*1024)
#define SESSION_GROUP_CONTROL_RESOLVE -3
#define SESSION_GROUP_DIRCONN -2
#define SESSION_GROUP_FIRST_AUTO -4
#define SESSION_GROUP_UNSET -1
#define SIGCLEARDNSCACHE 130
#define SIGHUP 1
#define SIGINT 2
#define SIGNEWNYM 129
#define SIGTERM 15
#define SIGUSR1 10
#define SIGUSR2 12
#define SOCKS4_NETWORK_LEN 8
#define SOCKS_COMMAND_CONNECT       0x01
#define SOCKS_COMMAND_IS_CONNECT(c) ((c)==SOCKS_COMMAND_CONNECT)
#define SOCKS_COMMAND_IS_RESOLVE(c) ((c)==SOCKS_COMMAND_RESOLVE || \
                                     (c)==SOCKS_COMMAND_RESOLVE_PTR)
#define SOCKS_COMMAND_RESOLVE       0xF0
#define SOCKS_COMMAND_RESOLVE_PTR   0xF1
#define SOCKS_NO_AUTH 0x00
#define SOCKS_USER_PASS 0x02
#define STREAMWINDOW_INCREMENT 50
#define STREAMWINDOW_START 500
#define TIMEOUT_UNTIL_UNREACHABILITY_COMPLAINT (20*60)

#define TO_CIRCUIT(x)  (&((x)->base_))
#define TO_CONN(c) (&(((c)->base_)))
#define UNNAMED_ROUTER_NICKNAME "Unnamed"
#define V3_AUTH_BODY_LEN (V3_AUTH_FIXED_PART_LEN + 8 + 16)
#define V3_AUTH_FIXED_PART_LEN (8+(32*6))
#define VAR_CELL_MAX_HEADER_SIZE 7

#define WRITE_STATS_INTERVAL (24*60*60)
#define _WIN32_WINNT 0x0501
#define cell_t tor_cell_t
#define generic_buffer_t struct evbuffer

#define LD_ACCT     (1u<<17)
#define LD_APP      (1u<<8)
#define LD_BUG      (1u<<12)
#define LD_CHANNEL   (1u<<21)
#define LD_CIRC     (1u<<10)
#define LD_CONFIG   (1u<<3)
#define LD_CONTROL  (1u<<9)
#define LD_CRYPTO   (1u<<1)
#define LD_DIR      (1u<<13)
#define LD_DIRSERV  (1u<<14)
#define LD_EDGE     (1u<<16)
#define LD_EXIT     LD_EDGE
#define LD_FS       (1u<<4)
#define LD_GENERAL  (1u<<0)
#define LD_HANDSHAKE (1u<<19)
#define LD_HEARTBEAT (1u<<20)
#define LD_HIST     (1u<<18)
#define LD_HTTP     (1u<<7)
#define LD_MM       (1u<<6)
#define LD_NET      (1u<<2)
#define LD_NOCB (1u<<31)
#define LD_OR       (1u<<15)
#define LD_PROTOCOL (1u<<5)
#define LD_REND     (1u<<11)
#define LOG_DEBUG   7
#define LOG_ERR     3
#define LOG_INFO    6
#define LOG_NOTICE  5
#define LOG_WARN LOG_WARNING
#define N_LOGGING_DOMAINS 22
#define SEVERITY_MASK_IDX(sev) ((sev) - LOG_ERR)
# define TOR_TORLOG_H
#define log_debug log_debug_
#define log_err log_err_
#define log_fn log_fn_
#define log_fn_ratelim log_fn_ratelim_
#define log_info log_info_
#define log_notice log_notice_
#define log_warn log_warn_
