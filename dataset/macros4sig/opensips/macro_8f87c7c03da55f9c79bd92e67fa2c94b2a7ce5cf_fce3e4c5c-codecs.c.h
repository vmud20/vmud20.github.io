#include<../error.h>



#include<error.h>

#include<syslog.h>

#include<time.h>



#include<arpa/inet.h>

#include<string.h>





#include<sys/shm.h>
#include<stdlib.h>

#include<sys/socket.h>


#include<sys/time.h>




#include<pthread.h>
#include<stdatomic.h>


#include<sys/syscall.h>
#include<sys/types.h>
#include<regex.h>
#include<limits.h>
#include<semaphore.h>




#include<dlfcn.h>
#include<unistd.h>



#include<sched.h>
#include<stdarg.h>
#include<errno.h>

#include<sys/ipc.h>


#include<netdb.h>
#include<linux/futex.h>



#include<netinet/in.h>


#include<sys/sem.h>
#include<strings.h>



#define EXPR_DROP -127  
#define assignop_str(op) ( \
	(op) == EQ_T ?       "=" : \
	(op) == COLONEQ_T ?  ":=" : \
	(op) == PLUSEQ_T ?   "+=" : \
	(op) == MINUSEQ_T ?  "-=" : \
	(op) == DIVEQ_T ?    "/=" : \
	(op) == MULTEQ_T ?   "*=" : \
	(op) == MODULOEQ_T ? "%=" : \
	(op) == BANDEQ_T ?   "&=" : \
	(op) == BOREQ_T ?    "|=" : \
	(op) == BXOREQ_T ?   "^=" : "unknown")

#define PV_IDX_ALL     2
#define PV_IDX_APPEND  4
#define PV_IDX_INT     3
#define PV_IDX_PVAR    1

#define fix_val_str_flags(_pvv) \
	do { \
		if (_pvv.flags & PV_VAL_STR) { \
			if (!_pvv.rs.s && _pvv.rs.len == 0) \
				_pvv.flags |= PV_VAL_NULL; \
			else if (_pvv.rs.s && _pvv.rs.len == 0) \
				_pvv.flags |= PV_VAL_EMPTY; \
		} \
	} while (0)
#define pv_has_dname(pv) ((pv)->pvp.pvn.type==PV_NAME_PVAR)
#define pv_has_iname(pv) ((pv)->pvp.pvn.type==PV_NAME_INTSTR \
							&& !((pv)->pvp.pvn.u.isname.type&AVP_NAME_STR))
#define pv_has_sname(pv) ((pv)->pvp.pvn.type==PV_NAME_INTSTR \
							&& (pv)->pvp.pvn.u.isname.type&AVP_NAME_STR)
#define pv_is_w(pv)   ((pv)->setf)
#define pv_type(type) (type < PVT_EXTRA ? type : type - PVT_EXTRA)
#define pvv_is_int(v) \
	((v)->flags & (PV_VAL_INT|PV_TYPE_INT) && \
		((v)->flags & PV_TYPE_INT || !((v)->flags & PV_VAL_STR)))
#define pvv_is_str(v) \
	((v)->flags & PV_VAL_STR && !((v)->flags & PV_TYPE_INT))
#define FAKED_REPLY     ((struct sip_msg *) -1)
#define FL_BODY_NO_SDP       (1<<20) 
#define FL_DO_KEEPALIVE      (1<<10) 
#define FL_FORCE_ACTIVE      (1<<1)  
#define FL_FORCE_LOCAL_RPORT (1<<2)  
#define FL_FORCE_RPORT       (1<<0)  
#define FL_NAT_TRACK_DIALOG  (1<<13) 
#define FL_REQ_UPSTREAM      (1<<9)  
#define FL_SDP_IP_AFS        (1<<3)  
#define FL_SDP_PORT_AFS      (1<<4)  
#define FL_SHM_CLONE         (1<<5)  
#define FL_SHM_UPDATABLE     (1<<15) 
#define FL_SHM_UPDATED       (1<<16) 
#define FL_TM_CB_REGISTERED  (1<<17) 
#define FL_TM_FAKE_REQ       (1<<18) 
#define FL_USE_MEDIA_PROXY   (1<<11) 
#define FL_USE_RTPPROXY      (1<<12) 
#define FL_USE_SIPTRACE      (1<<14) 
#define FL_USE_UAC_CSEQ      (1<<8)  
#define FL_USE_UAC_FROM      (1<<6)  
#define FL_USE_UAC_TO        (1<<7)  
#define GET_NEXT_HOP(m) \
(((m)->dst_uri.s && (m)->dst_uri.len) ? (&(m)->dst_uri) : \
(((m)->new_uri.s && (m)->new_uri.len) ? (&(m)->new_uri) : (&(m)->first_line.u.request.uri)))
#define GET_RURI(m) \
(((m)->new_uri.s && (m)->new_uri.len) ? (&(m)->new_uri) : (&(m)->first_line.u.request.uri))
#define IFISMETHOD(methodname,firstchar)                                  \
if (  (*tmp==(firstchar) || *tmp==((firstchar) | 32)) &&                  \
        strncasecmp( tmp+1, (char *)#methodname+1, methodname##_LEN-1)==0 &&     \
        *(tmp+methodname##_LEN)==' ') {                                   \
                fl->type=SIP_REQUEST;                                     \
                fl->u.request.method.len=methodname##_LEN;                \
                fl->u.request.method_value=METHOD_##methodname;           \
                tmp=buffer+methodname##_LEN;                              \
}

#define REPLY_CLASS(_reply) ((_reply)->REPLY_STATUS/100)
#define REPLY_STATUS first_line.u.reply.statuscode
#define REQ_LINE(_msg) ((_msg)->first_line.u.request)
#define REQ_METHOD   first_line.u.request.method_value
#define REQ_METHOD_S first_line.u.request.method
#define URI_MAX_U_PARAMS 10
#define get_header_by_static_name(_msg, _name) \
		get_header_by_name(_msg, _name, sizeof(_name)-1)
#define get_ruri_q(_msg) \
	(_msg)->ruri_q
#define getb0flags(_msg) \
	(_msg)->ruri_bflags
#define set_ruri_q(_msg,_q) \
	(_msg)->ruri_q = _q
#define setb0flags( _msg, _flags) \
	(_msg)->ruri_bflags = _flags
#define AVP_NAME_STR     (1<<0)
#define AVP_VAL_NULL     (1<<2)
#define AVP_VAL_STR      (1<<1)
#define GALIAS_CHAR_MARKER  '$'

#define avp_core_flags(f)	((f)&0x00ff)
#define avp_get_script_flags(f)	(((f)&0xff00)>>8)
#define avp_script_flags(f)	(((f)<<8)&0xff00)
#define is_avp_str_name(a)	(a->flags&AVP_NAME_STR)
#define is_avp_str_val(a)	(a->flags&AVP_VAL_STR)
#define STR_L(s) s, strlen(s)
#define STR_NULL (str){NULL, 0}
#define STR_NULL_const (str_const){NULL, 0}
#define ZSTR(_s)    (!(_s).s || (_s).len == 0)
#define ZSTRP(_sp)  (!(_sp) || ZSTR(*(_sp)))
#define _str(s) ( \
{ \
	static str _st; \
	init_str(&_st, s); \
	 (const str *)&_st; \
})
#define const_str(sbuf) ({static const str_const _stc = str_const_init(sbuf); &_stc;})
#define str_const_init(_string)  (str_const){_string, sizeof(_string) - 1}

#define str_init(_string)  (str){_string, sizeof(_string) - 1}
#define str_static(sbuf) ({static const str _stc = str_init(sbuf); &_stc;})

#define escape_param(sin, sout) ( \
    _Generic(*(sin), str: _escape_paramSS, str_const: _escape_param)(sin, sout) \
)
#define escape_user(sin, sout) ( \
    _Generic(*(sin), str: _escape_userSS, str_const: _escape_user)(sin, sout) \
)
#define str2const(_sp) ( \
    _Generic((_sp), str *: _s2c, const str *: _cs2cc)(_sp) \
)
#define str_casematch(_a, _b) _Generic(*(_a), \
	str: _Generic(*(_b), \
	    str: _str_casematchSS, \
	    str_const: _str_casematchSC), \
	str_const: _Generic(*(_b), \
	    str: _str_casematchCS, \
	    str_const: _str_casematchCC) \
    )(_a, _b)
#define str_match(_a, _b) _Generic(*(_a), \
	str: _Generic(*(_b), \
	    str: _str_matchSS, \
	    str_const: _str_matchSC), \
	str_const: _Generic(*(_b), \
	    str: _str_matchCS, \
	    str_const: _str_matchCC) \
    )(_a, _b)
#define str_strcmp(_a, _b) _Generic(*(_a), \
        str: _Generic(*(_b), \
            str: _str_strcmpSS, \
            str_const: _str_strcmpSC), \
        str_const: _Generic(*(_b), \
            str: _str_strcmpCS, \
            str_const: _str_strcmpCC) \
    )(_a, _b)
#define unescape_param(sin, sout) ( \
    _Generic(*(sin), str: _unescape_paramSS, str_const: _unescape_param)(sin, sout) \
)
#define unescape_user(sin, sout) ( \
    _Generic(*(sin), str: _unescape_userSS, str_const: _unescape_user)(sin, sout) \
)
#define PKG_FRAGMENTS_SIZE_IDX   5
#define PKG_FREE               hp_pkg_free
#define PKG_FREE_SIZE_IDX        4
#define PKG_GET_FRAGS()        qm_get_frags(mem_block)
#define PKG_GET_FREE()         qm_get_free(mem_block)
#define PKG_GET_MUSED()        qm_get_max_real_used(mem_block)
#define PKG_GET_RUSED()        qm_get_real_used(mem_block)
#define PKG_GET_SIZE()         hp_pkg_get_size(mem_block)
#define PKG_GET_USED()         hp_pkg_get_used(mem_block)
#define PKG_INFO               hp_info
#define PKG_MALLOC_            hp_pkg_malloc
#define PKG_MAX_USED_SIZE_IDX    3
#define PKG_REALLOC            hp_pkg_realloc
#define PKG_REAL_USED_SIZE_IDX   2
#define PKG_STATUS             hp_status
#define PKG_TOTAL_SIZE_IDX       0
#define PKG_USED_SIZE_IDX        1

#define __FUNCTION__ ""  
#define func_pkg_relloc sys_realloc
#define init_pkg_stats( _x )  0

#define pkg_free(p)       PKG_FREE(mem_block, (p), \
                                      "__FILE__", __FUNCTION__, "__LINE__")
#define pkg_free_func sys_free
#define pkg_info(i)       PKG_INFO(mem_block, i)
#define pkg_malloc(s)     PKG_MALLOC_(mem_block, (s), \
                                      "__FILE__", __FUNCTION__, "__LINE__")
#define pkg_malloc_func sys_malloc
#define pkg_realloc(p, s) PKG_REALLOC(mem_block, (p), (s), \
                                      "__FILE__", __FUNCTION__, "__LINE__")
#define pkg_status()      PKG_STATUS(mem_block)
#define set_pkg_stats( _x )
#define ALL_ROUTES \
	(REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE| \
	 ERROR_ROUTE|LOCAL_ROUTE|STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE)
#define BRANCH_ROUTE  8   
#define ERROR_ROUTE  16   
#define EVENT_ROUTE  256  
#define FAILURE_ROUTE 2   
#define LOCAL_ROUTE  32   
#define ONREPLY_ROUTE 4   
#define REQUEST_ROUTE 1   
#define STARTUP_ROUTE 64  
#define TIMER_ROUTE  128  
#define is_route_type(_type) (route_type==_type)

#define set_route_type(_new_type) \
	do{\
		route_type=_new_type;\
	}while(0)
#define swap_route_type(_backup, _new_type) \
	do{\
		_backup=route_type;\
		route_type=_new_type;\
	}while(0)
#define E_BAD_ADDRESS     -476		
#define E_BAD_PROTO       -474		
#define E_BAD_RE            -3
#define E_BAD_REQ         -400		
#define E_BAD_TO            -13
#define E_BAD_TUPEL         -9		
#define E_BAD_URI         -475		
#define E_BAD_VIA           -8		
#define E_BUG               -5
#define E_CFG               -6
#define E_EXEC              -11		
#define E_INVALID_PARAMS    -14		
#define E_IP_BLOCKED      -473		
#define E_NO_DESTINATION    -18		
#define E_NO_SOCKET         -7
#define E_OUT_OF_MEM        -2
#define E_Q_EMPTY           -16		
#define E_Q_INV_CHAR        -15		
#define E_Q_TOO_BIG         -17		
#define E_SCRIPT            -10		
#define E_SEND            -477		
#define E_TOO_MANY_BRANCHES -12		
#define E_UNSPEC            -1
#define UNUSED(x) (void)(x)

#define BLOCK_STEP        512			
#define BRANCH_RT_NO  RT_NO 	
#define BUF_SIZE 65535
#define CFG_FILE CFG_DIR "opensips.cfg"
#define CONTENT_LENGTH "Content-Length: "
#define CONTENT_LENGTH_LEN (sizeof(CONTENT_LENGTH)-1)
#define CRLF "\r\n"
#define CRLF_LEN (sizeof(CRLF) - 1)
#define DEFAULT_RT 0 		
#define DEFAULT_SHM_HASH_SPLIT_PERCENTAGE 1	
#define DEFAULT_SHM_SECONDARY_HASH_SIZE 8
#define EVENT_RT_NO   RT_NO 	
#define FAILURE_RT_NO RT_NO	
#define GRACEFUL_SHUTDOWN_TIMEOUT    5 
#define ID_PARAM ";i="
#define ID_PARAM_LEN (sizeof(ID_PARAM) - 1)
#define MAX_BRANCHES    12			
#define MAX_BRANCH_PARAM_LEN  (MCOOKIE_LEN+8  + 1  + \
								MD5_LEN + 1  + 8  + \
								1 )
#define MAX_BUCKET        15			
#define MAX_FIXED_BLOCK   3072
#define MAX_LISTEN 16		
#define MAX_PATH_SIZE 255	
#define MAX_PORT_LEN 7 
#define MAX_REC_LEV 100		
#define MAX_URI_SIZE 1024	
#define MAX_WARNING_LEN  256
#define MCOOKIE "z9hG4bK"			
#define MCOOKIE_LEN (sizeof(MCOOKIE)-1)
#define MEM_WARMING_DEFAULT_PATTERN_FILE CFG_DIR "mem_warming_pattern"
#define MEM_WARMING_DEFAULT_PERCENTAGE 75
#define MIN_UDP_PACKET        20		
#define MY_BRANCH ";branch="
#define MY_BRANCH_LEN (sizeof(MY_BRANCH) - 1)
#define MY_VIA "Via: SIP/2.0/UDP "
#define MY_VIA_LEN (sizeof(MY_VIA) - 1)
#define ONREPLY_RT_NO RT_NO	
#define OPENSER_OID   1,3,6,1,4,1,27483
#define PKG_MEM_SIZE 16				
#define RECEIVED        ";received="
#define RECEIVED_LEN (sizeof(RECEIVED) - 1)
#define RESTART_PERSISTENCY_MEM_FILE ".restart_persistency.cache"
#define ROUTE_MAX_REC_LEV 100 
#define RPORT ";rport="
#define RPORT_LEN (sizeof(RPORT) - 1)
#define RT_NO 100 		
#define SERVER_HDR "Server: OpenSIPS (" VERSION " (" ARCH "/" OS"))"		
#define SERVER_HDR_LEN (sizeof(SERVER_HDR)-1)
#define SHM_MAX_SECONDARY_HASH_SIZE 32
#define SHM_MEM_SIZE 32				
#define SHUTDOWN_TIMEOUT    60 
#define SIPS_PORT 5061		
#define SIP_PORT  5060		
#define SRV_MAX_PREFIX_LEN SRV_TLS_PREFIX_LEN
#define SRV_SCTP_PREFIX "_sip._sctp."
#define SRV_SCTP_PREFIX_LEN (sizeof(SRV_SCTP_PREFIX) - 1)
#define SRV_TCP_PREFIX "_sip._tcp."
#define SRV_TCP_PREFIX_LEN (sizeof(SRV_TCP_PREFIX) - 1)
#define SRV_TLS_PREFIX "_sips._tcp."
#define SRV_TLS_PREFIX_LEN (sizeof(SRV_TLS_PREFIX) - 1)
#define SRV_UDP_PREFIX "_sip._udp."
#define SRV_UDP_PREFIX_LEN (sizeof(SRV_UDP_PREFIX) - 1)
#define SRV_WSS_PREFIX "_wss._tcp."
#define SRV_WSS_PREFIX_LEN (sizeof(SRV_WSS_PREFIX) - 1)
#define SRV_WS_PREFIX "_ws._tcp."
#define SRV_WS_PREFIX_LEN (sizeof(SRV_WS_PREFIX) - 1)
#define TABLENAME_COLUMN  "table_name"		
#define TIMER_RT_NO   RT_NO 	
#define TIMER_TICK   1  			
#define TLS_CA_DIRECTORY      "/etc/pki/CA/"
#define TLS_CA_FILE 0 		
#define TLS_CERT_FILE CFG_DIR "tls/cert.pem"
#define TLS_DH_PARAMS_FILE 0   
#define TLS_PKEY_FILE CFG_DIR "tls/ckey.pem"
#define TOTAG_TOKEN ";tag="
#define TOTAG_TOKEN_LEN (sizeof(TOTAG_TOKEN)-1)
#define TRANSPORT_PARAM ";transport="
#define TRANSPORT_PARAM_LEN (sizeof(TRANSPORT_PARAM) - 1)
#define UDP_WORKERS_NO    8		
#define USER_AGENT "User-Agent: OpenSIPS (" VERSION " (" ARCH "/" OS"))"		
#define USER_AGENT_LEN (sizeof(USER_AGENT)-1)
#define UTIMER_TICK  100*1000			
#define VERSION_COLUMN    "table_version"	
#define VERSION_TABLE     "version" 		

#define      NO_HOLD 0
#define RFC2543_HOLD 1
#define RFC3264_HOLD 2

#define CASE_FPRINTENUM(file, em) \
        case em: printf(# em "\n"); break
#define CASE_PRINTENUM(em) \
	CASE_FPRINTENUM(stdout, em)
#define DPRINT_LEV   L_ERR
#define DP_ALERT_PREFIX  DP_PREFIX DP_ALERT_TEXT
#define DP_ALERT_TEXT    "ALERT:"
#define DP_CRIT_PREFIX   DP_PREFIX DP_CRIT_TEXT
#define DP_CRIT_TEXT     "CRITICAL:"
#define DP_DBG_PREFIX    DP_PREFIX DP_DBG_TEXT
#define DP_DBG_TEXT      "DBG:"
#define DP_ERR_PREFIX    DP_PREFIX DP_ERR_TEXT
#define DP_ERR_TEXT      "ERROR:"
#define DP_INFO_PREFIX   DP_PREFIX DP_INFO_TEXT
#define DP_INFO_TEXT     "INFO:"
#define DP_NOTICE_PREFIX DP_PREFIX DP_NOTICE_TEXT
#define DP_NOTICE_TEXT   "NOTICE:"
#define DP_WARN_PREFIX   DP_PREFIX DP_WARN_TEXT
#define DP_WARN_TEXT     "WARNING:"
		#define LM_ALERT( ...)
#define LM_BUG(format, args...) \
	do { \
		LM_CRIT("\n>>> " format"\nIt seems you have hit a programming bug.\n" \
				"Please help us make OpenSIPS better by reporting it at " \
				"https://github.com/OpenSIPS/opensips/issues\n\n", ##args); \
	} while (0)
		#define LM_CRIT( ...)
			#define LM_DBG( ...)
		#define LM_ERR( ...)
		#define LM_GEN(lev, ...)
		#define LM_GEN1(lev, ...)
		#define LM_GEN2(facility, lev, ...)
		#define LM_INFO( ...)
		#define LM_NOTICE( ...)
		#define LM_WARN( ...)
		#define LOG_PREFIX  LOG_PREFIX_UTIL(MOD_NAME) ": "
		#define LOG_PREFIX_UTIL(_n)  LOG_PREFIX_UTIL2(_n)
		#define LOG_PREFIX_UTIL2(_n) #_n
#define L_ALERT -3	
#define L_CRIT  -2	
#define L_DBG    4	
#define L_ERR   -1	
#define L_INFO   3	
#define L_NOTICE 2	
#define L_WARN   1	
		#define MY_DPRINT( ...) \
				dprint( LOG_PREFIX __VA_ARGS__ ) \

		#define MY_SYSLOG( _log_level, ...) \
				syslog( (_log_level)|log_facility, \
							LOG_PREFIX __VA_ARGS__);\


#define is_printable(_level)  (((int)(*log_level)) >= ((int)(_level)))

#define reset_init_lump_flags() \
	do{\
		init_lump_flags = 0;\
	}while(0)
#define set_init_lump_flags(_flags) \
	do{\
		init_lump_flags = _flags;\
	}while(0)
#define HDR_F_DEF(name)		HDR_T2F(HDR_##name##_T)
#define HDR_T2F(type)	\
		(((type)!=HDR_EOH_T)?((hdr_flags_t)1<<(type)):(~(hdr_flags_t)0))


#define FAKED_REPLY     ((struct sip_msg *) -1)
#define FL_BODY_NO_SDP       (1<<20) 
#define FL_DO_KEEPALIVE      (1<<10) 
#define FL_FORCE_ACTIVE      (1<<1)  
#define FL_FORCE_LOCAL_RPORT (1<<2)  
#define FL_FORCE_RPORT       (1<<0)  
#define FL_NAT_TRACK_DIALOG  (1<<13) 
#define FL_REQ_UPSTREAM      (1<<9)  
#define FL_SDP_IP_AFS        (1<<3)  
#define FL_SDP_PORT_AFS      (1<<4)  
#define FL_SHM_CLONE         (1<<5)  
#define FL_SHM_UPDATABLE     (1<<15) 
#define FL_SHM_UPDATED       (1<<16) 
#define FL_TM_CB_REGISTERED  (1<<17) 
#define FL_TM_FAKE_REQ       (1<<18) 
#define FL_USE_MEDIA_PROXY   (1<<11) 
#define FL_USE_RTPPROXY      (1<<12) 
#define FL_USE_SIPTRACE      (1<<14) 
#define FL_USE_UAC_CSEQ      (1<<8)  
#define FL_USE_UAC_FROM      (1<<6)  
#define FL_USE_UAC_TO        (1<<7)  
#define GET_NEXT_HOP(m) \
(((m)->dst_uri.s && (m)->dst_uri.len) ? (&(m)->dst_uri) : \
(((m)->new_uri.s && (m)->new_uri.len) ? (&(m)->new_uri) : (&(m)->first_line.u.request.uri)))
#define GET_RURI(m) \
(((m)->new_uri.s && (m)->new_uri.len) ? (&(m)->new_uri) : (&(m)->first_line.u.request.uri))
#define IFISMETHOD(methodname,firstchar)                                  \
if (  (*tmp==(firstchar) || *tmp==((firstchar) | 32)) &&                  \
        strncasecmp( tmp+1, (char *)#methodname+1, methodname##_LEN-1)==0 &&     \
        *(tmp+methodname##_LEN)==' ') {                                   \
                fl->type=SIP_REQUEST;                                     \
                fl->u.request.method.len=methodname##_LEN;                \
                fl->u.request.method_value=METHOD_##methodname;           \
                tmp=buffer+methodname##_LEN;                              \
}

#define REPLY_CLASS(_reply) ((_reply)->REPLY_STATUS/100)
#define REPLY_STATUS first_line.u.reply.statuscode
#define REQ_LINE(_msg) ((_msg)->first_line.u.request)
#define REQ_METHOD   first_line.u.request.method_value
#define REQ_METHOD_S first_line.u.request.method
#define URI_MAX_U_PARAMS 10
#define get_header_by_static_name(_msg, _name) \
		get_header_by_name(_msg, _name, sizeof(_name)-1)
#define get_ruri_q(_msg) \
	(_msg)->ruri_q
#define getb0flags(_msg) \
	(_msg)->ruri_bflags
#define set_ruri_q(_msg,_q) \
	(_msg)->ruri_q = _q
#define setb0flags( _msg, _flags) \
	(_msg)->ruri_bflags = _flags

#define TRIM_SWITCH(c) {if (!is_ws(c)) return;}
#define trim_trail_ws(p) while (*(p) && is_ws(*(p))) p--
#define trim_ws(p) while (*(p) && is_ws(*(p))) p++
#define MAX_Q ((qvalue_t)1000)
#define MAX_Q_STR "1"
#define MAX_Q_STR_LEN (sizeof(MAX_Q_STR) - 1)
#define MIN_Q ((qvalue_t)0)
#define MIN_Q_STR "0"
#define MIN_Q_STR_LEN (sizeof(MIN_Q_STR) - 1)
#define Q_PREFIX "0."
#define Q_PREFIX_LEN (sizeof(Q_PREFIX) - 1)
#define Q_UNSPECIFIED ((qvalue_t)-1)
#define _QVALUE_H 1
#define qverr2str(rc) \
	(rc == E_Q_INV_CHAR ? "bad characters" : \
	 rc == E_Q_EMPTY ? "empty value" : \
	 rc == E_Q_TOO_BIG ? "max value is 1.0" : "bad qvalue")

#define AF2PF(af)   (((af)==AF_INET)?PF_INET:((af)==AF_INET6)?PF_INET6:(af))
#define HEX2I(c) \
	(	(((c)>='0') && ((c)<='9'))? (c)-'0' :  \
		(((c)>='A') && ((c)<='F'))? ((c)-'A')+10 : \
		(((c)>='a') && ((c)<='f'))? ((c)-'a')+10 : -1 )
#define IP_ADDR_MAX_STR_SIZE 40 
#define PROTO_LAST PROTO_OTHER
#define get_su_info(_su, _ip_char, _port_no) \
	do { \
		struct ip_addr __ip; \
		sockaddr2ip_addr( &__ip, (struct sockaddr*)_su ); \
		_ip_char = ip_addr2a(&__ip); \
		_port_no = su_getport( (union sockaddr_union*)(void *)_su); \
	} while(0)
#define hostent2ip_addr(ip, he, addr_no) \
	do{ \
		(ip)->af=(he)->h_addrtype; \
		(ip)->len=(he)->h_length;  \
		memcpy((ip)->u.addr, (he)->h_addr_list[(addr_no)], (ip)->len); \
	}while(0)
#define ip_addr2su init_su
#define ip_addr_cmp(ip1, ip2) \
	(((ip1)->af==(ip2)->af)&& \
	 	(memcmp((ip1)->u.addr, (ip2)->u.addr, (ip1)->len)==0))

#define is_anycast(_si) (_si->flags & SI_IS_ANYCAST)
#define is_sip_proto(_proto) (PROTO_UDP<=(_proto) && (_proto)<=PROTO_WSS)
#define sockaddru_len(su)	((su).s.sa_len)
#define FLAG_DELIM                ' '
#define MAX_FLAG  ((unsigned int)( sizeof(flag_t) * CHAR_BIT - 1 ))
#define NAMED_FLAG_ERROR          33
#define PRINT_BUFFER_SIZE         2048

#define fix_flag_name(_s, _flag) \
     do { \
		if (!_s && (int)(_flag) > 0) { \
			LM_WARN("Integer flags are now deprecated! " \
			        "Use unique quoted strings!\n"); \
			_s = int2str(_flag, NULL); \
		} \
	 } while (0)
#define STR_L(s) s, strlen(s)
#define STR_NULL (str){NULL, 0}
#define STR_NULL_const (str_const){NULL, 0}
#define ZSTR(_s)    (!(_s).s || (_s).len == 0)
#define ZSTRP(_sp)  (!(_sp) || ZSTR(*(_sp)))
#define _str(s) ( \
{ \
	static str _st; \
	init_str(&_st, s); \
	 (const str *)&_st; \
})
#define const_str(sbuf) ({static const str_const _stc = str_const_init(sbuf); &_stc;})
#define str_const_init(_string)  (str_const){_string, sizeof(_string) - 1}

#define str_init(_string)  (str){_string, sizeof(_string) - 1}
#define str_static(sbuf) ({static const str _stc = str_init(sbuf); &_stc;})

#define INT_PARAM        (1U<<1)  
#define MODULE_VERSION \
	OPENSIPS_FULL_VERSION, \
	OPENSIPS_COMPILE_FLAGS
#define PARAM_TYPE_MASK(_x)   ((_x)&(~USE_FUNC_PARAM))
#define PROC_FLAG_HAS_IPC      (1<<1)
#define PROC_FLAG_INITCHILD    (1<<0)
#define PROC_FLAG_NEEDS_SCRIPT (1<<2)
#define PROC_MAIN      0  
#define PROC_MODULE   -2  
#define PROC_TCP_MAIN -4  
#define PROC_TIMER    -1  
#define RTLD_NOW DL_LAZY
#define STR_PARAM        (1U<<0)  
#define USE_FUNC_PARAM   (1U<<(8*sizeof(int)-1))

#define DEP_REVERSE (DEP_REVERSE_INIT|DEP_REVERSE_DESTROY)
#define DEP_REVERSE_DESTROY (1 << 4) 
#define DEP_REVERSE_INIT    (1 << 3) 
#define MAX_MOD_DEPS 10

#define CMD_PARAM_FIX_NULL   (1<<5)  
#define CMD_PARAM_INT        (1<<0)  
#define CMD_PARAM_NO_EXPAND  (1<<6)  
#define CMD_PARAM_OPT        (1<<4)  
#define CMD_PARAM_REGEX      (1<<3)  
#define CMD_PARAM_STR        (1<<1)  
#define CMD_PARAM_VAR        (1<<2)  
#define MAX_CMD_PARAMS (MAX_ACTION_ELEMS-1)

#define ASYNC_FD_NONE -1

#define valid_async_fd(fd) (fd >= 0)

#define CC_O0_STR ", CC_O0"
#define DBG_LOCK_STR ", DBG_LOCK"
#define DBG_MALLOC_STR ", DBG_MALLOC"
#define DEBUG_DMALLOC_STR ", DEBUG_DMALLOC"
#define DISABLE_NAGLE_STR ", DISABLE_NAGLE"
#define EXTRA_DEBUG_STR ", EXTRA_DEBUG"
#define EXTRA_STATS_STR ", SHM_EXTRA_STATS"
#define FAST_LOCK_STR ", FAST_LOCK-FUTEX-ADAPTIVE_WAIT"
#define F_MALLOC_STR ", F_MALLOC"
#define HP_MALLOC_STR ", HP_MALLOC"
#define NOSMP_STR "-NOSMP"
#define NO_DEBUG_STR ", NO_DEBUG"
#define NO_LOG_STR ", NO_LOG"
#define OPENSIPS_COMPILE_FLAGS \
	STATS_STR EXTRA_STATS_STR EXTRA_DEBUG_STR \
	DISABLE_NAGLE_STR USE_MCAST_STR NO_DEBUG_STR NO_LOG_STR \
	SHM_MMAP_STR PKG_MALLOC_STR Q_MALLOC_STR F_MALLOC_STR \
	HP_MALLOC_STR DBG_MALLOC_STR CC_O0_STR \
	DEBUG_DMALLOC_STR QM_JOIN_FREE_STR FAST_LOCK_STR NOSMP_STR \
	USE_PTHREAD_MUTEX_STR USE_UMUTEX_STR USE_POSIX_SEM_STR \
	USE_SYSV_SEM_STR DBG_LOCK_STR
#define OPENSIPS_FULL_VERSION  NAME " " VERSION " (" ARCH "/" OS ")"
#define PKG_MALLOC_STR ", PKG_MALLOC"
#define QM_JOIN_FREE_STR ", QM_JOIN_FREE"
#define Q_MALLOC_STR ", Q_MALLOC"
#define SHM_MMAP_STR ", SHM_MMAP"
#define STATS_STR  "STATS: On"
#define USE_MCAST_STR ", USE_MCAST"
#define USE_POSIX_SEM_STR ", USE_POSIX_SEM"
#define USE_PTHREAD_MUTEX_STR ", USE_PTHREAD_MUTEX"
#define USE_SYSV_SEM_STR ", USE_SYSV_SEM"
#define USE_UMUTEX_STR ", USE_UMUTEX"

#define EMPTY_MI_EXPORT 0, 0, 0, 0, {{EMPTY_MI_RECIPE}}
#define EMPTY_MI_RECIPE 0, {0}
#define ERR_DET_AMBIG_CALL_S "Ambiguous call, use named parameters instead"
#define ERR_DET_CMD_NULL_S "Command handler returned null"
#define ERR_DET_MATCH_PARAMS_S "Named parameters do not match"
#define ERR_DET_NO_PARAMS_S  "Too few or too many parameters"
#define ERR_DET_PARAM_HANDLE_S "Failed to handle parameter"
#define ERR_DET_POS_PARAMS_S "Command only supports named parameters"
#define JSONRPC_ID_S "id"
#define JSONRPC_INVAL_PARAMS_CODE  -32602
#define JSONRPC_INVAL_PARAMS_MSG   "Invalid params"
#define JSONRPC_INVAL_REQ_CODE     -32600
#define JSONRPC_INVAL_REQ_MSG      "Invalid Request"
#define JSONRPC_METHOD_S "method"
#define JSONRPC_NOT_FOUND_CODE     -32601
#define JSONRPC_NOT_FOUND_MSG      "Method not found"
#define JSONRPC_PARAMS_S "params"
#define JSONRPC_PARSE_ERR_CODE     -32700
#define JSONRPC_PARSE_ERR_MSG      "Parse error"
#define JSONRPC_SERVER_ERR_MSG     "Server error"
#define MAX_MI_PARAMS  10
#define MAX_MI_RECIPES 11
#define MI_ASYNC_RPL    ((mi_response_t*)-1)
#define MI_ASYNC_RPL_FLAG    (1<<0)
#define MI_NAMED_PARAMS_ONLY (1<<1)
#define MI_NO_RPL 		1

#define DYNAMIC_MODULE_NAME  "dynamic"
#define STATS_HASH_POWER   8
#define STATS_HASH_SIZE    (1<<(STATS_HASH_POWER))
#define STAT_HAS_GROUP (1<<7)
#define STAT_HIDDEN    (1<<5)
#define STAT_IS_FUNC   (1<<3)
#define STAT_NOT_ALLOCATED  (1<<4)
#define STAT_NO_RESET  (1<<0)
#define STAT_NO_SYNC   (1<<1)
#define STAT_PER_PROC  (1<<6)
#define STAT_SHM_NAME  (1<<2)

		#define get_stat_val( _var ) ((unsigned long)\
			((_var)->flags&STAT_IS_FUNC)?(_var)->u.f((_var)->context):*((_var)->u.val))
#define inc_stat(_var) update_stat(_var, 1)
#define register_module_stats(mod, stats) \
	__register_module_stats(mod, stats, 0)
#define register_stat(_mod,_name,_pvar,_flags) \
		register_stat2(_mod,_name,_pvar,_flags, NULL, 0)
		#define reset_stat( _var) \
			do { \
				if ( ((_var)->flags&(STAT_NO_RESET|STAT_IS_FUNC))==0 ) {\
					if ((_var)->flags&STAT_NO_SYNC) {\
						*((_var)->u.val) = 0;\
					} else {\
						lock_get(stat_lock);\
						*((_var)->u.val) = 0;\
						lock_release(stat_lock);\
					}\
				}\
			}while(0)
		#define update_stat( _var, _n) \
			do { \
				if ( !((_var)->flags&STAT_IS_FUNC) ) {\
					if ((_var)->flags&STAT_NO_SYNC) {\
						*((_var)->u.val) += _n;\
					} else {\
						lock_get(stat_lock);\
						*((_var)->u.val) += _n;\
						lock_release(stat_lock);\
					}\
				}\
			}while(0)


#define lock_alloc() shm_malloc(sizeof(gen_lock_t))
#define lock_dealloc(lock) shm_free((void*)lock)
#define lock_set_dealloc(lock_set) shm_free((void*)lock_set)
#define INVALID_MAP ((void *)-1)
#define SHM_FREE               fm_free
#define SHM_FREE_UNSAFE        fm_free
#define SHM_GET_FRAGS          fm_get_frags
#define SHM_GET_FREE           fm_get_free
#define SHM_GET_MUSED          fm_get_max_real_used
#define SHM_GET_RUSED          fm_get_real_used
#define SHM_GET_SIZE           fm_get_size
#define SHM_GET_USED           fm_get_used
#define SHM_INFO               fm_info
#define SHM_MALLOC             fm_malloc
#define SHM_MALLOC_UNSAFE      fm_malloc
#define SHM_REALLOC            fm_realloc
#define SHM_REALLOC_UNSAFE     fm_realloc
#define SHM_STATUS             fm_status
#define shm_frag_file fm_frag_file
#define shm_frag_func fm_frag_func
#define shm_frag_line fm_frag_line
#define shm_frag_overhead FM_FRAG_OVERHEAD
#define shm_frag_size fm_frag_size
#define shm_free( _ptr ) _shm_free( (_ptr), \
	"__FILE__", __FUNCTION__, "__LINE__" )
#define shm_free_bulk( _ptr ) _shm_free_bulk( (_ptr), \
	"__FILE__", __FUNCTION__, "__LINE__" )
#define shm_free_bulk_func _shm_free_bulk
#define shm_free_func _shm_free
#define shm_free_unsafe( _ptr ) _shm_free_unsafe( (_ptr), \
	"__FILE__", __FUNCTION__, "__LINE__" )
#define shm_free_unsafe_func _shm_free_unsafe
#define shm_lock()    lock_get(mem_lock)
#define shm_malloc( _size ) _shm_malloc((_size), \
	"__FILE__", __FUNCTION__, "__LINE__" )
#define shm_malloc_bulk(_size ) _shm_malloc_bulk((_size), \
	"__FILE__", __FUNCTION__, "__LINE__" )
#define shm_malloc_bulk_func  _shm_malloc_bulk
#define shm_malloc_func _shm_malloc
#define shm_malloc_func_unsafe shm_malloc_unsafe
#define shm_malloc_unsafe(_size ) _shm_malloc_unsafe((_size), \
	"__FILE__", __FUNCTION__, "__LINE__" )
#define shm_malloc_unsafe_func _shm_malloc_unsafe

#define shm_realloc( _ptr, _size ) _shm_realloc( (_ptr), (_size), \
	"__FILE__", __FUNCTION__, "__LINE__" )
#define shm_realloc_func _shm_realloc
#define shm_realloc_func_unsafe _shm_realloc_unsafe
#define shm_realloc_unsafe( _ptr, _size ) _shm_realloc_unsafe( (_ptr), (_size), \
	"__FILE__", __FUNCTION__, "__LINE__" )
#define shm_stats_core_init fm_stats_core_init
#define shm_stats_get_index fm_stats_get_index
#define shm_stats_set_index fm_stats_set_index

#define shm_unlock()  lock_release(mem_lock)

#  define USE_UMUTEX_DECL 1

#define lock_destroy(lock) 
#define lock_get(lock) pthread_mutex_lock(lock)
#define lock_release(lock) pthread_mutex_unlock(lock)
#define lock_set_destroy(lock_set) 
#define lock_set_get(set, i) lock_get(&set->locks[i])
#define lock_set_release(set, i) lock_release(&set->locks[i])
#define u_long unsigned long
#define SPIN_OPTIMIZE 


#define atomic_cmpxchg(lock, oldval, newval) __sync_val_compare_and_swap(lock, oldval, newval)
#define atomic_xchg(lock, val) __sync_lock_test_and_set(lock, val)

#define futex_wait(lock, val) syscall(SYS_futex, lock, FUTEX_WAIT, val, 0, 0, 0)
#define futex_wake(lock, val) syscall(SYS_futex, lock, FUTEX_WAKE, val, 0, 0 ,0)

#define ch_h_inc h+=v^(v>>3)
#define ch_icase(_c) (((_c)>='A'&&(_c)<='Z')?((_c)|0x20):(_c))


#define atomic_fetch_add(a, v) \
	if ((long)(v) >= 0L) \
		atomic_add(v, a);\
	else \
		atomic_sub(-(v), a);
#define atomic_init(a, v) atomic_set(a, v)
#define atomic_load(a) ((a)->counter)
#define atomic_set(v,i)		(((v)->counter) = (i))
#define atomic_store(a, v) atomic_set(a, v)
