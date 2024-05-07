#include<stdatomic.h>





#include<pthread.h>








#include<stdio.h>

#include<stdint.h>
#include<time.h>




#include<sys/socket.h>
#include<stddef.h>

#include<string.h>




#include<stdlib.h>

#include<inttypes.h>



#include<ctype.h>
#include<stdbool.h>
#include<stdarg.h>
#define MQTT_ERR_INVAL 3
#define MQTT_ERR_MALFORMED 7
#define MQTT_ERR_NOMEM 1
#define MQTT_ERR_NOT_FOUND 6
#define MQTT_ERR_NOT_SUPPORTED 5
#define MQTT_ERR_PAYLOAD_SIZE 4
#define MQTT_ERR_PROTOCOL 2
#define MQTT_LENGTH_CONTINUATION_BIT 0x80
#define MQTT_LENGTH_SHIFT 7
#define MQTT_LENGTH_VALUE_MASK 0x7F
#define MQTT_MAX_LENGTH_BYTES 4
#define MQTT_MAX_MSG_LEN 268435455
#define MQTT_PROTOCOL_NAME "MQTT"
#define MQTT_QOS_0_AT_MOST_ONCE 0
#define MQTT_QOS_1_AT_LEAST_ONCE 1
#define MQTT_QOS_2_EXACTLY_ONCE 2
#define MQTT_SUCCESS 0

#define NNG_CTX_INITIALIZER { 0 }
#define NNG_DECL __declspec(dllexport)
#define NNG_DEPRECATED __attribute__ ((deprecated))
#define NNG_DIALER_INITIALIZER { 0 }
#define NNG_DURATION_DEFAULT (-2)
#define NNG_DURATION_INFINITE (-1)
#define NNG_DURATION_ZERO (0)
#define NNG_FLAG_ALLOC 1u    
#define NNG_FLAG_NONBLOCK 2u 
#define NNG_LISTENER_INITIALIZER { 0 }
#define NNG_MAJOR_VERSION 1
#define NNG_MAXADDRLEN (128)
#define NNG_MINOR_VERSION 6

#define NNG_OPT_IPC_PEER_GID "ipc:peer-gid"
#define NNG_OPT_IPC_PEER_PID "ipc:peer-pid"
#define NNG_OPT_IPC_PEER_UID "ipc:peer-uid"
#define NNG_OPT_IPC_PEER_ZONEID "ipc:peer-zoneid"
#define NNG_OPT_IPC_PERMISSIONS "ipc:permissions"
#define NNG_OPT_IPC_SECURITY_DESCRIPTOR "ipc:security-descriptor"
#define NNG_OPT_LOCADDR "local-address"
#define NNG_OPT_MAXTTL "ttl-max"
#define NNG_OPT_MQTT_CONNMSG "mqtt-connect-msg"
#define NNG_OPT_PEER "peer"
#define NNG_OPT_PEERNAME "peer-name"
#define NNG_OPT_PROTO "protocol"
#define NNG_OPT_PROTONAME "protocol-name"
#define NNG_OPT_RAW "raw"
#define NNG_OPT_RECONNMAXT "reconnect-time-max"
#define NNG_OPT_RECONNMINT "reconnect-time-min"
#define NNG_OPT_RECVBUF "recv-buffer"
#define NNG_OPT_RECVFD "recv-fd"
#define NNG_OPT_RECVMAXSZ "recv-size-max"
#define NNG_OPT_RECVTIMEO "recv-timeout"
#define NNG_OPT_REMADDR "remote-address"
#define NNG_OPT_SENDBUF "send-buffer"
#define NNG_OPT_SENDFD "send-fd"
#define NNG_OPT_SENDTIMEO "send-timeout"
#define NNG_OPT_SOCKNAME "socket-name"
#define NNG_OPT_TCP_BOUND_PORT "tcp-bound-port"
#define NNG_OPT_TCP_KEEPALIVE "tcp-keepalive"
#define NNG_OPT_TCP_NODELAY "tcp-nodelay"
#define NNG_OPT_TLS_AUTH_MODE "tls-authmode"
#define NNG_OPT_TLS_CA_FILE "tls-ca-file"
#define NNG_OPT_TLS_CERT_KEY_FILE "tls-cert-key-file"
#define NNG_OPT_TLS_CONFIG "tls-config"
#define NNG_OPT_TLS_PEER_ALT_NAMES "tls-peer-alt-names"
#define NNG_OPT_TLS_PEER_CN "tls-peer-cn"
#define NNG_OPT_TLS_SERVER_NAME "tls-server-name"
#define NNG_OPT_TLS_VERIFIED "tls-verified"
#define NNG_OPT_URL "url"
#define NNG_OPT_WS_PROTOCOL "ws:protocol"
#define NNG_OPT_WS_RECVMAXFRAME "ws:rxframe-max"
#define NNG_OPT_WS_RECV_TEXT "ws:recv-text"
#define NNG_OPT_WS_REQUEST_HEADER "ws:request-header:"
#define NNG_OPT_WS_REQUEST_HEADERS "ws:request-headers"
#define NNG_OPT_WS_REQUEST_URI "ws:request-uri"
#define NNG_OPT_WS_RESPONSE_HEADER "ws:response-header:"
#define NNG_OPT_WS_RESPONSE_HEADERS "ws:response-headers"
#define NNG_OPT_WS_SENDMAXFRAME "ws:txframe-max"
#define NNG_OPT_WS_SEND_TEXT "ws:send-text"
#define NNG_PATCH_VERSION 0
#define NNG_PIPE_INITIALIZER { 0 }
#define NNG_PROTOCOL_NUMBER(maj, min) (((x) *16) + (y))
#define NNG_RELEASE_SUFFIX "pre" 
#define NNG_SOCKET_INITIALIZER { 0 }
#define CMD_AUTH_V5 0xF0
#define CMD_CONNACK 0x20
#define CMD_CONNECT 0x10
#define CMD_DISCONNECT 0xE0
#define CMD_DISCONNECT_EV 0xE2
#define CMD_LASTWILL 0XE3
#define CMD_PINGREQ 0xC0
#define CMD_PINGRESP 0xD0
#define CMD_PUBACK 0x40
#define CMD_PUBCOMP 0x70
#define CMD_PUBLISH 0x30	
#define CMD_PUBLISH_V5 0x31 
#define CMD_PUBREC 0x50
#define CMD_PUBREL 0x60
#define CMD_SUBACK 0x90
#define CMD_SUBSCRIBE 0x80
#define CMD_UNKNOWN 0x00
#define CMD_UNSUBACK 0xB0
#define CMD_UNSUBSCRIBE 0xA0
#define MQTT_PROTOCOL_NAME_v31 "MQIsdp"
#define MQTT_PROTOCOL_VERSION_v31 3
#define MQTT_PROTOCOL_VERSION_v311 4
#define MQTT_PROTOCOL_VERSION_v5 5
#define NNG_MAX_RECV_LMQ 16
#define NNG_MAX_SEND_LMQ 16

#define NNG_OPT_MQTT_CLIENT_ID "client-id" 
#define NNG_OPT_MQTT_CONNECT_PROPERTY "mqtt-connack-property"
#define NNG_OPT_MQTT_CONNECT_REASON "mqtt-connack-reason"
#define NNG_OPT_MQTT_CONTENT_TYPE "content-type"
#define NNG_OPT_MQTT_CORRELATION_DATA "correlation-data"
#define NNG_OPT_MQTT_DISCONNECT_PROPERTY "mqtt-disconnect-property"
#define NNG_OPT_MQTT_DISCONNECT_REASON "mqtt-disconnect-reason"
#define NNG_OPT_MQTT_DUP "dup"
#define NNG_OPT_MQTT_EXPIRES "expires"
#define NNG_OPT_MQTT_KEEP_ALIVE "mqtt-keep-alive"
#define NNG_OPT_MQTT_MAX_PACKET_SIZE "mqtt-max-packet-size"
#define NNG_OPT_MQTT_MAX_QOS "max-qos"
#define NNG_OPT_MQTT_PASSWORD "password"
#define NNG_OPT_MQTT_PAYLOAD_FORMAT "mqtt-payload-format"
#define NNG_OPT_MQTT_QOS "qos"
#define NNG_OPT_MQTT_REASON "reason"
#define NNG_OPT_MQTT_RECEIVE_MAX "mqtt-receive-max"
#define NNG_OPT_MQTT_RESPONSE_TOPIC "response-topic"
#define NNG_OPT_MQTT_RETAIN "retain"
#define NNG_OPT_MQTT_SESSION_EXPIRES "session-expires"
#define NNG_OPT_MQTT_SQLITE "mqtt-sqlite-option"
#define NNG_OPT_MQTT_TOPIC "topic"
#define NNG_OPT_MQTT_TOPIC_ALIAS "topic-alias"
#define NNG_OPT_MQTT_TOPIC_ALIAS_MAX "alias-max"
#define NNG_OPT_MQTT_USERNAME "username"
#define NNG_OPT_MQTT_USER_PROPS "user-props"
#define NNG_OPT_MQTT_WILL_DELAY "will-delay"
#define NNG_TRAN_MAX_LMQ_SIZE 128





#define NNI_MAXINT ((int) 2147483647)
#define NNI_MAXSZ ((size_t) 0xffffffff)
#define NNI_MININT ((int) -2147483648)
#define NNI_MINSZ (0)


#define NNG_PLATFORM_DIR_SEP "\\"
#define NNI_CV_INITIALIZER(mxp)                                    \
	{                                                          \
		.srl = (void *) mxp, .cv = CONDITION_VARIABLE_INIT \
	}
#define NNI_MTX_INITIALIZER  \
	{                    \
		SRWLOCK_INIT \
	}
#define NNI_RWLOCK_INITIALIZER \
	{                      \
		SRWLOCK_INIT   \
	}



#define NNI_LIST_FOREACH(l, it) \
	for (it = nni_list_first(l); it != NULL; it = nni_list_next(l, it))
#define NNI_LIST_INIT(list, type, field) \
	nni_list_init_offset(list, offsetof(type, field))
#define NNI_LIST_INITIALIZER(list, type, field)          \
	{                                                \
		.ll_head.ln_next = &(list).ll_head,      \
		.ll_head.ln_prev = &(list).ll_head,      \
		.ll_offset       = offsetof(type, field) \
	}
#define NNI_LIST_NODE_INIT(node)                       \
	do {                                           \
		(node)->ln_prev = (node)->ln_next = 0; \
	} while (0)

#define NNI_ALIGN_MASK (NNI_ALIGN_SIZE - 1)
#define NNI_ALIGN_SIZE sizeof(void *)
#define NNI_ALIGN_UP(sz) (((sz) + NNI_ALIGN_MASK) & ~NNI_ALIGN_MASK)
#define NNI_ALLOC_STRUCT(s) nni_zalloc(sizeof(*s))
#define NNI_ALLOC_STRUCTS(s, n) nni_zalloc(sizeof(*s) * n)
#define NNI_ARG_UNUSED(x) ((void) x)
#define NNI_ARRAY_SIZE(x) (sizeof(x) / sizeof(uint32_t))
#define NNI_ASSERT(x) \
	if (!(x))     \
	nni_panic("%s: %d: assert err: %s", "__FILE__", "__LINE__", #x)
#define NNI_EXPIRE_BATCH 100
#define NNI_FLAG_IPV4ONLY 1
#define NNI_FREE_STRUCT(s) nni_free((s), sizeof(*s))
#define NNI_FREE_STRUCTS(s, n) nni_free(s, sizeof(*s) * n)
#define NNI_GCC_VERSION \
	("__GNUC__" * 10000 + "__GNUC_MINOR__" * 100 + "__GNUC_PATCHLEVEL__")
#define NNI_GET16(ptr, v)                               \
	v = (((uint16_t) ((uint8_t) (ptr)[0])) << 8u) + \
	    (((uint16_t) (uint8_t) (ptr)[1]))
#define NNI_GET32(ptr, v)                                \
	v = (((uint32_t) ((uint8_t) (ptr)[0])) << 24u) + \
	    (((uint32_t) ((uint8_t) (ptr)[1])) << 16u) + \
	    (((uint32_t) ((uint8_t) (ptr)[2])) << 8u) +  \
	    (((uint32_t) (uint8_t) (ptr)[3]))
#define NNI_GET64(ptr, v)                                \
	v = (((uint64_t) ((uint8_t) (ptr)[0])) << 56u) + \
	    (((uint64_t) ((uint8_t) (ptr)[1])) << 48u) + \
	    (((uint64_t) ((uint8_t) (ptr)[2])) << 40u) + \
	    (((uint64_t) ((uint8_t) (ptr)[3])) << 32u) + \
	    (((uint64_t) ((uint8_t) (ptr)[4])) << 24u) + \
	    (((uint64_t) ((uint8_t) (ptr)[5])) << 16u) + \
	    (((uint64_t) ((uint8_t) (ptr)[6])) << 8u) +  \
	    (((uint64_t) (uint8_t) (ptr)[7]))
#define NNI_INCPTR(ptr, n) ((ptr) = (void *) ((char *) (ptr) + (n)))
#define NNI_MAX_MAX_TTL 15
#define NNI_NANO_MAX_HEADER_SIZE \
	sizeof(uint8_t) * NANO_HEADER_SIZE 
#define NNI_NUM_ELEMENTS(x) ((unsigned) (sizeof(x) / sizeof((x)[0])))
#define NNI_PUT16(ptr, u)                                      \
	do {                                                   \
		(ptr)[0] = (uint8_t) (((uint16_t) (u)) >> 8u); \
		(ptr)[1] = (uint8_t) ((uint16_t) (u));         \
	} while (0)
#define NNI_PUT32(ptr, u)                                       \
	do {                                                    \
		(ptr)[0] = (uint8_t) (((uint32_t) (u)) >> 24u); \
		(ptr)[1] = (uint8_t) (((uint32_t) (u)) >> 16u); \
		(ptr)[2] = (uint8_t) (((uint32_t) (u)) >> 8u);  \
		(ptr)[3] = (uint8_t) ((uint32_t) (u));          \
	} while (0)
#define NNI_PUT64(ptr, u)                                       \
	do {                                                    \
		(ptr)[0] = (uint8_t) (((uint64_t) (u)) >> 56u); \
		(ptr)[1] = (uint8_t) (((uint64_t) (u)) >> 48u); \
		(ptr)[2] = (uint8_t) (((uint64_t) (u)) >> 40u); \
		(ptr)[3] = (uint8_t) (((uint64_t) (u)) >> 32u); \
		(ptr)[4] = (uint8_t) (((uint64_t) (u)) >> 24u); \
		(ptr)[5] = (uint8_t) (((uint64_t) (u)) >> 16u); \
		(ptr)[6] = (uint8_t) (((uint64_t) (u)) >> 8u);  \
		(ptr)[7] = (uint8_t) ((uint64_t) (u));          \
	} while (0)
#define NNI_SECOND (1000)
#define NNI_TIME_NEVER ((nni_time) -1)
#define NNI_TIME_ZERO ((nni_time) 0)















#define NNG_USE_CLOCKID CLOCK_REALTIME
#define NNG_USE_DEVURANDOM 1
#define NNG_USE_GETENTROPY 1
#define NNG_USE_GETRANDOM 1

#define NNG_USE_POSIX_RESOLV_GAI 1











#define NNI_PROTO(major, minor) (((major) *16) + (minor))
#define NNI_PROTOCOL_V3 0x50520003u 
#define NNI_PROTOCOL_VERSION NNI_PROTOCOL_V3
#define NNI_PROTO_FLAG_RAW 4u    
#define NNI_PROTO_FLAG_RCV 1u    
#define NNI_PROTO_FLAG_SND 2u    
#define NNI_PROTO_FLAG_SNDRCV 3u 






#define UPDATE_FIELD_INT(field, new_obj, old_obj) \
	do {                                      \
		new_obj->field = old_obj->field;  \
	} while (0)
#define UPDATE_FIELD_MQTT_STRING(field, sub_field, new_obj, old_obj)   \
	do {                                                           \
		if (new_obj->field.sub_field == NULL &&                \
		    old_obj->field.sub_field != NULL) {                \
			new_obj->field = old_obj->field;               \
			new_obj->field.sub_field =                     \
			    strdup((char *) old_obj->field.sub_field); \
		}                                                      \
	} while (0)
#define UPDATE_FIELD_MQTT_STRING_PAIR(                                  \
    field, sub_field1, sub_field2, new_obj, old_obj)                    \
	do {                                                            \
		if ((new_obj->field.sub_field1 == NULL &&               \
		        old_obj->field.sub_field1 != NULL) ||           \
		    (new_obj->field.sub_field2 == NULL &&               \
		        old_obj->field.sub_field2 != NULL)) {           \
			new_obj->field = old_obj->field;                \
			new_obj->field.sub_field1 =                     \
			    strdup((char *) old_obj->field.sub_field1); \
			new_obj->field.sub_field2 =                     \
			    strdup((char *) old_obj->field.sub_field2); \
		}                                                       \
	} while (0)



#define NNI_ID_FLAG_RANDOM 2   
#define NNI_ID_FLAG_REGISTER 4 
#define NNI_ID_FLAG_STATIC 1   
#define NNI_ID_MAP_INITIALIZER(min, max, flags)            \
	{                                                  \
		.id_min_val = (min), .id_max_val = (max),  \
		.id_flags = ((flags) | NNI_ID_FLAG_STATIC) \
	}



#define LOG_VERSION "0.2.0"

#define log_debug(...) \
    log_log(NNG_LOG_DEBUG, "__FILE__", "__LINE__", __FUNCTION__, __VA_ARGS__)
#define log_error(...) \
    log_log(NNG_LOG_ERROR, "__FILE__", "__LINE__", __FUNCTION__, __VA_ARGS__)
#define log_fatal(...) \
    log_log(NNG_LOG_FATAL, "__FILE__", "__LINE__", __FUNCTION__, __VA_ARGS__)
#define log_info(...) \
    log_log(NNG_LOG_INFO, "__FILE__", "__LINE__", __FUNCTION__, __VA_ARGS__)
#define log_trace(...) \
    log_log(NNG_LOG_TRACE, "__FILE__", "__LINE__", __FUNCTION__, __VA_ARGS__)
#define log_warn(...) \
    log_log(NNG_LOG_WARN, "__FILE__", "__LINE__", __FUNCTION__, __VA_ARGS__)

#define nni_qos_db_fini_id_hash(db)                                \
	{                                                          \
		nni_id_map_fini((nni_id_map *) (db));              \
		nni_free((nni_id_map *) (db), sizeof(nni_id_map)); \
	}
#define nni_qos_db_fini_sqlite(db) nni_mqtt_qos_db_close((sqlite3 *) (db))
#define nni_qos_db_init_id_hash(db)                              \
	{                                                        \
		db = nng_zalloc(sizeof(nni_id_map));             \
		nni_id_map_init((nni_id_map *) db, 0, 0, false); \
	}
#define nni_qos_db_init_id_hash_with_opt(db, lo, hi, randomize)        \
	{                                                              \
		db = nng_zalloc(sizeof(nni_id_map));                   \
		nni_id_map_init((nni_id_map *) db, lo, hi, randomize); \
	}
#define nni_qos_db_init_sqlite(db, user_path, db_name, is_broker) \
	nni_mqtt_qos_db_init((sqlite3 **) &(db), user_path, db_name, is_broker)
#define BROKER_NMQ_TCP_TLS_URL_PREFIX "tls+nmq-tcp"
#define BROKER_NMQ_TCP_URL_PREFIX "nmq-tcp"
#define BROKER_NMQ_WSS_URL_PREFIX "nmq-wss"
#define BROKER_NMQ_WS_URL_PREFIX "nmq-ws"
#define BROKER_TCP_URL_PREFIX "broker+tcp"
#define BROKER_WSS_URL_PREFIX "nmq+wss"
#define BROKER_WS_URL_PREFIX "nmq+ws"
#define CONF_DDS_GATEWAY_PATH_NAME "/etc/nanomq_dds_gateway.conf"
#define CONF_GATEWAY_PATH_NAME "/etc/nanomq_gateway.conf"

#define CONF_PATH_NAME "/etc/nanomq.conf"
#define CONF_TCP_URL_DEFAULT "nmq-tcp://0.0.0.0:1883"
#define CONF_TLS_URL_DEFAULT "tls+nmq-tcp://0.0.0.0:8883"
#define CONF_VSOMEIP_GATEWAY_PATH_NAME "/etc/nanomq_vsomeip_gateway.conf"
#define CONF_WSS_URL_DEFAULT "nmq-wss://0.0.0.0:8084/mqtt"
#define CONF_WS_URL_DEFAULT "nmq-ws://0.0.0.0:8083/mqtt"
#define FREE_NONULL(p)    \
	if (p) {          \
		free(p);  \
		p = NULL; \
	}
#define LOG_TO_CONSOLE (1 << 1)
#define LOG_TO_FILE (1 << 0)
#define LOG_TO_SYSLOG (1 << 2)
#define PID_PATH_NAME "/tmp/nanomq/nanomq.pid"
#define RULE_ENG_FDB (1 << 1)
#define RULE_ENG_MDB (1 << 2)
#define RULE_ENG_OFF 0
#define RULE_ENG_RPB (1 << 3)
#define RULE_ENG_SDB 1
#define conf_update2_bool(path, key1, key2, key3, var) \
	conf_update_var2(path, key1, key2, key3, 7, (void *) &(var))
#define conf_update2_double(path, key1, key2, key3, var) \
	conf_update_var2(path, key1, key2, key3, 6, (void *) &(var))
#define conf_update2_int(path, key1, key2, key3, var) \
	conf_update_var2(path, key1, key2, key3, 0, (void *) &(var))
#define conf_update2_long(path, key1, key2, key3, var) \
	conf_update_var2(path, key1, key2, key3, 5, (void *) &(var))
#define conf_update2_u16(path, key1, key2, key3, var) \
	conf_update_var2(path, key1, key2, key3, 2, (void *) &(var))
#define conf_update2_u32(path, key1, key2, key3, var) \
	conf_update_var2(path, key1, key2, key3, 3, (void *) &(var))
#define conf_update2_u64(path, key1, key2, key3, var) \
	conf_update_var2(path, key1, key2, key3, 4, (void *) &(var))
#define conf_update2_u8(path, key1, key2, key3, var) \
	conf_update_var2(path, key1, key2, key3, 1, (void *) &(var))
#define conf_update_bool(path, key, var) \
	conf_update_var(path, key, 7, (void *) &(var))
#define conf_update_double(path, key, var) \
	conf_update_var(path, key, 6, (void *) &(var))
#define conf_update_int(path, key, var) \
	conf_update_var(path, key, 0, (void *) &(var))
#define conf_update_long(path, key, var) \
	conf_update_var(path, key, 5, (void *) &(var))
#define conf_update_u16(path, key, var) \
	conf_update_var(path, key, 2, (void *) &(var))
#define conf_update_u32(path, key, var) \
	conf_update_var(path, key, 3, (void *) &(var))
#define conf_update_u64(path, key, var) \
	conf_update_var(path, key, 4, (void *) &(var))
#define conf_update_u8(path, key, var) \
	conf_update_var(path, key, 1, (void *) &(var))

#define CONNECT_MSG                                                           \
	"{\"username\":\"%s\", "                                              \
	"\"ts\":%llu,\"proto_name\":\"%s\",\"keepalive\":%d,\"return_code\":" \
	"\"%x\",\"proto_ver\":%d,\"client_id\":\"%s\", \"clean_start\":%d}"
#define CONNECT_TOPIC "$SYS/brokers/connected"
#define DISCONNECT_MSG          \
	"{\"username\":\"%s\"," \
	"\"ts\":%llu,\"reason_code\":\"%x\",\"client_id\":\"%s\"}"
#define DISCONNECT_TOPIC "$SYS/brokers/disconnected"
#define NANO_NNI_LMQ_GET_MSG_POINTER(msg) \
	((nng_msg *) ((size_t) (msg) & (~0x03)))
#define NANO_NNI_LMQ_GET_QOS_BITS(msg) ((size_t) (msg) &0x03)
#define NANO_NNI_LMQ_PACKED_MSG_QOS(msg, qos) \
	((nng_msg *) ((size_t) (msg) | ((qos) &0x03)))



#define MQTT_PROTOCOL_NAME_v31 "MQIsdp"
#define MQTT_PROTOCOL_VERSION_v31 3
#define MQTT_PROTOCOL_VERSION_v311 4
#define MQTT_PROTOCOL_VERSION_v5 5
#define NANO_CONF "nano:conf"
#define NANO_CONNECT_PACKET_LEN sizeof(uint8_t) * 12
#define NANO_MAX_QOS_PACKET 1024
#define NANO_MAX_RECV_PACKET_SIZE (2*1024*1024)
#define NANO_MIN_FIXED_HEADER_LEN sizeof(uint8_t) * 2
#define NANO_MIN_PACKET_LEN sizeof(uint8_t) * 8
#define NMQ_AUTH_SUB_ERROR 0X87
#define NMQ_KEEP_ALIVE_TIMEOUT 0x8D
#define NMQ_PACKET_TOO_LARGE 0x95
#define NMQ_RECEIVE_MAXIMUM_EXCEEDED 0X93
#define NMQ_SERVER_BUSY 0x89
#define NMQ_SERVER_SHUTTING_DOWN 0x8B
#define NMQ_SERVER_UNAVAILABLE 0x88
#define NMQ_UNSEPECIFY_ERROR 0X80
#define NNI_NANO_MAX_PACKET_SIZE sizeof(uint8_t) * NANO_PACKET_SIZE
#define NNG_OPT_WSS_REQUEST_HEADERS NNG_OPT_WS_REQUEST_HEADERS
#define NNG_OPT_WSS_RESPONSE_HEADERS NNG_OPT_WS_RESPONSE_HEADERS



#define NNI_OPT_WS_MSGMODE "ws:msgmode"

