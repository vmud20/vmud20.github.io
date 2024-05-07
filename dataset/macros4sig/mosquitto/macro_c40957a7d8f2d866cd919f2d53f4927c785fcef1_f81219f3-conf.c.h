

#include<string.h>

#include<stdlib.h>



#include<limits.h>



#include<stdbool.h>
#include<stdio.h>
#include<errno.h>


#define MOSQ_PAYLOAD_UNION_SIZE 8
#define MOSQ_TOPIC_ELEMENT_UNION_SIZE 8
#define MQTT3_LOG_ALL 0xFF
#define MQTT3_LOG_FILE 0x02
#define MQTT3_LOG_NONE 0x00
#define MQTT3_LOG_STDERR 0x08
#define MQTT3_LOG_STDOUT 0x04
#define MQTT3_LOG_SYSLOG 0x01
#define MQTT3_LOG_TOPIC 0x10
#define UHPA_ACCESS_PAYLOAD(A) UHPA_ACCESS((A)->payload, (A)->payloadlen)
#define UHPA_ACCESS_TOPIC(A) UHPA_ACCESS((A)->topic, (A)->topic_len+1)
#define UHPA_ALLOC_PAYLOAD(A) UHPA_ALLOC((A)->payload, (A)->payloadlen)
#define UHPA_ALLOC_TOPIC(A) UHPA_ALLOC((A)->topic, (A)->topic_len+1)
#define UHPA_FREE_PAYLOAD(A) UHPA_FREE((A)->payload, (A)->payloadlen)
#define UHPA_FREE_TOPIC(A) UHPA_FREE((A)->topic, (A)->topic_len+1)
#define UHPA_MOVE_PAYLOAD(DEST, SRC) UHPA_MOVE((DEST)->payload, (SRC)->payload, (SRC)->payloadlen)
#define UHPA_MOVE_TOPIC(DEST, SRC) UHPA_MOVE((DEST)->topic, (SRC)->topic, (SRC)->topic_len+1)
#define WEBSOCKET_CLIENT -2

#    define libwebsocket lws
#    define libwebsocket_callback_on_writable(A, B) lws_callback_on_writable((B))
#    define libwebsocket_callback_reasons lws_callback_reasons
#    define libwebsocket_context lws_context
#    define libwebsocket_context_destroy(A) lws_context_destroy((A))
#    define libwebsocket_create_context(A) lws_create_context((A))
#    define libwebsocket_get_socket_fd(A) lws_get_socket_fd((A))
#    define libwebsocket_protocols lws_protocols
#    define libwebsocket_service(A, B) lws_service((A), (B))
#    define libwebsocket_write(A, B, C, D) lws_write((A), (B), (C), (D))
#    define libwebsockets_get_protocol(A) lws_get_protocol((A))
#    define libwebsockets_return_http_status(A, B, C, D) lws_return_http_status((B), (C), (D))
#    define lws_pollargs libwebsocket_pollargs
#    define lws_pollfd pollfd
#    define lws_service_fd(A, B) libwebsocket_service_fd((A), (B))
#define uhpa_free(ptr) mosquitto__free(ptr)
#define uhpa_malloc(size) mosquitto__malloc(size)
#  define UHPA_ACCESS(u, size) (u).ptr
#define UHPA_ACCESS_CHK(u, size) ((size) > sizeof((u).array)?(u).ptr:(u).array)
#define UHPA_ACCESS_STR(u, size) ((char *)UHPA_ACCESS((u), (size)+1))
#  define UHPA_ALLOC(u, size) ((u).ptr = uhpa_malloc(size))
#define UHPA_ALLOC_CHK(u, size) \
	((size) > sizeof((u).array)? \
		(((u).ptr = uhpa_malloc((size)))?1:0) \
		:-1)
#define UHPA_ALLOC_STR(u, size) UHPA_ALLOC((u), (size)+1)
#  define UHPA_FREE(u, size) uhpa_free((u).ptr); (u).ptr = NULL;
#define UHPA_FREE_CHK(u, size) \
	if((size) > sizeof((u).array) && (u).ptr){ \
		uhpa_free((u).ptr); \
		(u).ptr = NULL; \
	} 
#define UHPA_FREE_STR(u, size) UHPA_FREE((u), (size)+1)

#  define UHPA_MOVE(dest, src, src_size) {(dest).ptr = (src).ptr; (src).ptr = NULL}
#define UHPA_MOVE_CHK(dest, src, src_size) \
	if((src_size) > sizeof((src).array) && (src).ptr){ \
		(dest).ptr = (src).ptr; \
		(src).ptr = NULL; \
	}else{ \
		memmove((dest).array, (src).array, (src_size)); \
		memset((src).array, 0, (src_size)); \
	}
#define UHPA_MOVE_STR(dest, src, src_size) UHPA_MOVE((dest), (src), (src_size)+1)

#define MOSQ_ACL_NONE 0x00
#define MOSQ_ACL_READ 0x01
#define MOSQ_ACL_SUBSCRIBE 0x04
#define MOSQ_ACL_WRITE 0x02
#define MOSQ_AUTH_PLUGIN_VERSION 3

#  define EPROTO ECONNABORTED
#    define FINAL_WITH_TLS_PSK
#  define HAVE_NETINET_IN_H
#  define _DEFAULT_SOURCE 1

#  define _POSIX_C_SOURCE 200809L
#  define _XOPEN_SOURCE 700
#  define __BSD_VISIBLE 1
#  define __DARWIN_C_SOURCE
#  define snprintf sprintf_s
#    define strcasecmp strcmpi
#  define strerror_r(e, b, l) strerror_s(b, l, e)
#  define strtok_r strtok_s
#define uthash_free(ptr,sz) mosquitto__free(ptr)
#define uthash_malloc(sz) mosquitto__malloc(sz)
