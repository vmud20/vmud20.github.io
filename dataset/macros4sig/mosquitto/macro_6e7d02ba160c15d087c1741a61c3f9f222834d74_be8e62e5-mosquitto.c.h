#  define EPROTO ECONNABORTED
#  define snprintf sprintf_s
#    define strcasecmp strcmpi
#define strerror_r(e, b, l) strerror_s(b, l, e)
#define strtok_r strtok_s
#define uthash_free(ptr,sz) _mosquitto_free(ptr)
#define uthash_malloc(sz) _mosquitto_malloc(sz)

#define STREMPTY(str) (str[0] == '\0')


#define LIBMOSQUITTO_MAJOR 1
#define LIBMOSQUITTO_MINOR 4
#define LIBMOSQUITTO_REVISION 12
#define LIBMOSQUITTO_VERSION_NUMBER (LIBMOSQUITTO_MAJOR*1000000+LIBMOSQUITTO_MINOR*1000+LIBMOSQUITTO_REVISION)

#define MOSQ_LOG_ALL 0xFFFF
#define MOSQ_LOG_DEBUG 0x10
#define MOSQ_LOG_ERR 0x08
#define MOSQ_LOG_INFO 0x01
#define MOSQ_LOG_NONE 0x00
#define MOSQ_LOG_NOTICE 0x02
#define MOSQ_LOG_SUBSCRIBE 0x20
#define MOSQ_LOG_UNSUBSCRIBE 0x40
#define MOSQ_LOG_WARNING 0x04
#define MOSQ_LOG_WEBSOCKETS 0x80
#define MOSQ_MQTT_ID_MAX_LENGTH 23
#define MQTT_PROTOCOL_V31 3
#define MQTT_PROTOCOL_V311 4
#		define bool char
#		define false 0
#		define libmosq_EXPORT  __declspec(dllexport)
#		define true 1

#    define REAL_WITH_TLS_PSK
#  define SSL_DATA_PENDING(A) ((A)->ssl && SSL_pending((A)->ssl))




#  define COMPAT_CLOSE(a) closesocket(a)
#  define COMPAT_ECONNRESET WSAECONNRESET
#  define COMPAT_EWOULDBLOCK WSAEWOULDBLOCK
#define INVALID_SOCKET -1
#define MOSQ_LSB(A) (uint8_t)(A & 0x00FF)
#define MOSQ_MSB(A) (uint8_t)((A & 0xFF00) >> 8)

#define CONNACK 0x20
#define CONNACK_ACCEPTED 0
#define CONNACK_REFUSED_BAD_USERNAME_PASSWORD 4
#define CONNACK_REFUSED_IDENTIFIER_REJECTED 2
#define CONNACK_REFUSED_NOT_AUTHORIZED 5
#define CONNACK_REFUSED_PROTOCOL_VERSION 1
#define CONNACK_REFUSED_SERVER_UNAVAILABLE 3
#define CONNECT 0x10
#define DISCONNECT 0xE0
#define MQTT_MAX_PAYLOAD 268435455
#define PINGREQ 0xC0
#define PINGRESP 0xD0
#define PROTOCOL_NAME_v31 "MQIsdp"
#define PROTOCOL_NAME_v311 "MQTT"
#define PROTOCOL_VERSION_v31 3
#define PROTOCOL_VERSION_v311 4
#define PUBACK 0x40
#define PUBCOMP 0x70
#define PUBLISH 0x30
#define PUBREC 0x50
#define PUBREL 0x60
#define SUBACK 0x90
#define SUBSCRIBE 0x80
#define UNSUBACK 0xB0
#define UNSUBSCRIBE 0xA0





