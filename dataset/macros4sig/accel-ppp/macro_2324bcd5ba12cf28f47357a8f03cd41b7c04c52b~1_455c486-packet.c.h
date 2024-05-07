#include<unistd.h>
#include<time.h>

#include<arpa/inet.h>
#include<errno.h>


#include<endian.h>
#include<sys/time.h>


#include<stdint.h>

#include<netinet/in.h>

#include<stdarg.h>
#include<fcntl.h>
#include<stdio.h>

#include<stdlib.h>
#include<sys/types.h>
#include<string.h>
#define ACCM 35
#define Assigned_Connection_ID 61
#define Assigned_Cookie 65
#define Assigned_Session_ID 14
#define Assigned_Tunnel_ID 9
#define Bearer_Capabilities 4
#define Bearer_Type 18
#define Call_Errors 34
#define Call_Serial_Number 15
#define Called_Number 21
#define Calling_Number 22
#define Cause_Code 12
#define Challenge 11
#define Challenge_Response 13
#define Circuit_Status 71
#define Ctrl_Message_Auth_Nonce 73
#define Data_Sequencing 70
#define Firmware_Revision 6
#define Framing_Capabilities 3
#define Framing_Type 19
#define Host_Name 7
#define Init_Recv_LCP 26
#define L2_Specific_Sublayer 69
#define Last_Recv_LCP 28
#define Last_Sent_LCP 27
#define Local_Session_ID 63
#define Maximum_BPS 17
#define Message_Digest 59
#define Message_Type 0
#define Message_Type_Call_Disconnect_Notify 14
#define Message_Type_Explicit_Ack 20
#define Message_Type_Hello 6
#define Message_Type_Incoming_Call_Connected 12
#define Message_Type_Incoming_Call_Reply 11
#define Message_Type_Incoming_Call_Request 10
#define Message_Type_Outgoing_Call_Connected 9
#define Message_Type_Outgoing_Call_Reply 8
#define Message_Type_Outgoing_Call_Request 7
#define Message_Type_Set_Link_Info 16
#define Message_Type_Start_Ctrl_Conn_Connected 3
#define Message_Type_Start_Ctrl_Conn_Reply 2
#define Message_Type_Start_Ctrl_Conn_Request 1
#define Message_Type_Stop_Ctrl_Conn_Notify 4
#define Message_Type_WAN_Error_Notify 15
#define Minimum_BPS 16
#define Physical_Channel_ID 25
#define Prefered_Language 72
#define Private_Group_ID 37
#define Protocol_Version 2
#define Proxy_Authen_Challenge 31
#define Proxy_Authen_ID 32
#define Proxy_Authen_Name 30
#define Proxy_Authen_Response 33
#define Proxy_Authen_Type 29
#define Pseudowire_Capabilities 62
#define Pseudowire_Type 68
#define RX_Connect_Speed 75
#define RX_Speed 38
#define Random_Vector 36
#define Recv_Window_Size 10
#define Remote_End_ID 66
#define Remote_Session_ID 64
#define Result_Code 1
#define Router_ID 60
#define Sequencing_Required 39
#define Sub_Address 23
#define TX_Connect_Speed 74
#define TX_Speed 24
#define Tie_Breaker 5
#define Vendor_Name 8

#define ATTR_TYPE_INT16   1
#define ATTR_TYPE_INT32   2
#define ATTR_TYPE_INT64   3
#define ATTR_TYPE_NONE    0
#define ATTR_TYPE_OCTETS  4
#define ATTR_TYPE_STRING  5
#define L2TP_DATASEQ_ALLOW  -1
#define L2TP_DATASEQ_DENY    0
#define L2TP_DATASEQ_PREFER  1
#define L2TP_DATASEQ_REQUIRE 2
#define L2TP_MAX_PACKET_SIZE 65536
#define L2TP_V2_PROTOCOL_VERSION ( 1 << 8 | 0 )

#define L2TP_PORT 1701

#define INIT_LIST_HEAD(ptr) do { \
	(ptr)->next = (ptr); (ptr)->prev = (ptr); \
} while (0)
#define LIST_HEAD(name) \
	struct list_head name = LIST_HEAD_INIT(name)
#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define __list_for_each(pos, head) \
	for (pos = (head)->next; pos != (head); pos = pos->next)
#define list_entry(ptr, type, member) \
	((type *)((char *)(ptr)-(unsigned long)(&((type *)0)->member)))
#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)
#define list_for_each(pos, head) \
	for (pos = (head)->next, prefetch(pos->next); pos != (head); \
        	pos = pos->next, prefetch(pos->next))
#define list_for_each_entry(pos, head, member)				\
	for (pos = list_entry((head)->next, typeof(*pos), member),	\
		     prefetch(pos->member.next);			\
	     &pos->member != (head); 					\
	     pos = list_entry(pos->member.next, typeof(*pos), member),	\
		     prefetch(pos->member.next))
#define list_for_each_prev(pos, head) \
	for (pos = (head)->prev, prefetch(pos->prev); pos != (head); \
        	pos = pos->prev, prefetch(pos->prev))
#define list_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
		pos = n, n = pos->next)


#define _asprintf(strp, fmt, ...) asprintf(strp, fmt, ##__VA_ARGS__)
#define _free(ptr) free(ptr)
#define _malloc(size) malloc(size)
#define _realloc(ptr, size) realloc(ptr, size)
#define _strdup(str) strdup(str)
#define _strndup(str, size) strndup(str, size)

#define mempool_alloc(pool) md_mempool_alloc(pool, "__FILE__", "__LINE__")
#define mempool_free(ptr) md_free(ptr, "__FILE__", "__LINE__")
#define LOG_CHUNK_SIZE 128
#define LOG_MAX_SIZE 4096

#define DEFINE_INIT(o, func) static void __init __init__(void){triton_register_init(o,func);}
#define DEFINE_INIT2(o, func) static void __init __init2__(void){triton_register_init(o,func);}
#define MD_MODE_READ 1
#define MD_MODE_WRITE 2
#define MD_TRIG_EDGE 0
#define MD_TRIG_LEVEL 1
#define TRITON_ERR_BUSY   -5
#define TRITON_ERR_EXISTS -4
#define TRITON_ERR_NOCHAN -5
#define TRITON_ERR_NOCOMP -1
#define TRITON_ERR_NOINTF -3
#define TRITON_ERR_NOMSG  -6
#define TRITON_ERR_NOSUPP -2

#define TRITON_OK          0
#define __exit __attribute__((destructor))
#define __export __attribute__((visibility("default")))
#define __init __attribute__((constructor))
#define __unused __attribute__((unused))
#define barrier() asm volatile ("" ::: "memory")
#define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#define DES_DECRYPT 0
#define DES_ENCRYPT 1
#define DES_key_schedule symmetric_key
#define DES_set_key(key, schedule) des_setup((const unsigned char *)key, 8, 0, schedule)
#define EVP_MD_CTX_free EVP_MD_CTX_destroy
#define EVP_MD_CTX_new EVP_MD_CTX_create
#define MD4_DIGEST_LENGTH 16
#define MD4_Final(md, c) md4_done(c, (unsigned char*)(md))
#define MD4_Init(c) md4_init(c)
#define MD4_Update(c, data, len) md4_process(c, (const unsigned char *)(data), (unsigned long)(len))
#define MD5_DIGEST_LENGTH 16
#define MD5_Final(md, c) md5_done(c, (unsigned char*)(md))
#define MD5_Init(c) md5_init(c)
#define MD5_Update(c, data, len) md5_process(c, (const unsigned char *)(data), (unsigned long)(len))
#define SHA1_Final(md, c) sha1_done(c, (unsigned char*)(md))
#define SHA1_Init(c) sha1_init(c)
#define SHA1_Update(c, data, len) sha1_process(c, (const unsigned char *)(data), (unsigned long)(len))
#define SHA_DIGEST_LENGTH 20

