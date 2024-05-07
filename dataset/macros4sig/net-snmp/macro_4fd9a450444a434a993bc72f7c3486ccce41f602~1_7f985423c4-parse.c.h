#include<sys/socket.h>


#include<limits.h>











#include<pthread.h>



#include<errno.h>





#include<netipx/ipx.h>

#include<stdarg.h>


#include<netinet/in.h>

#include<string.h>






#include<regex.h>

#include<strings.h>
#include<stdlib.h>
#include<getopt.h>

#include<syslog.h>

#include<sys/stat.h>

#include<sys/un.h>
#include<sys/types.h>
#include<stdio.h>





#include<unistd.h>
#include<ctype.h>
#define BYTESIZE(bitsize)       ((bitsize + 7) >> 3)
#define FALSE 0
#define HEX2VAL(s) \
	((isalpha(s) ? (TOLOWER(s)-'a'+10) : (TOLOWER(s)-'0')) & 0xf)
#define NETSNMP_REMOVE_CONST(t, e)                                      \
    (__extension__ ({ const t tmp = (e); (t)(size_t)tmp; }))
#define NETSNMP_TIMERADD(a, b, res)                  \
{                                                    \
    (res)->tv_sec  = (a)->tv_sec  + (b)->tv_sec;     \
    (res)->tv_usec = (a)->tv_usec + (b)->tv_usec;    \
    if ((res)->tv_usec >= 1000000L) {                \
        (res)->tv_usec -= 1000000L;                  \
        (res)->tv_sec++;                             \
    }                                                \
}
#define NETSNMP_TIMERSUB(a, b, res)                             \
{                                                               \
    (res)->tv_sec  = (a)->tv_sec  - (b)->tv_sec - 1;            \
    (res)->tv_usec = (a)->tv_usec - (b)->tv_usec + 1000000L;    \
    if ((res)->tv_usec >= 1000000L) {                           \
        (res)->tv_usec -= 1000000L;                             \
        (res)->tv_sec++;                                        \
    }                                                           \
}
#define QUITFUN(e, l)			\
	if ( (e) != SNMPERR_SUCCESS) {	\
		rval = SNMPERR_GENERR;	\
		goto l ;		\
	}
#define ROUNDUP8(x)		( ( (x+7) >> 3 ) * 8 )
#define SNMP_FREE(s)    do { if (s) { free((void *)s); s=NULL; } } while(0)
#define SNMP_MACRO_VAL_TO_STR(s) SNMP_MACRO_VAL_TO_STR_PRIV(s)  
#define SNMP_MACRO_VAL_TO_STR_PRIV(s) #s
#define SNMP_MALLOC_STRUCT(s)   (struct s *) calloc(1, sizeof(struct s))
#define SNMP_MALLOC_TYPEDEF(td)  (td *) calloc(1, sizeof(td))
#define SNMP_MAX(a,b) ((a) > (b) ? (a) : (b))
#  define SNMP_MAXPATH MAX_PATH
#define SNMP_MIN(a,b) ((a) > (b) ? (b) : (a))
#define SNMP_STRORNULL(x)       ( x ? x : "(null)")
#define SNMP_SWIPE_MEM(n,s) do { if (n) free((void *)n); n = s; s=NULL; } while(0)
#define SNMP_ZERO(s,l)	do { if (s) memset(s, 0, l); } while(0)
#define TOLOWER(c)	(c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c)
#define TOUPPER(c)	(c >= 'a' && c <= 'z' ? c - ('a' - 'A') : c)
#define TRUE  1
#define VAL2HEX(s)	( (s) + (((s) >= 10) ? ('a'-10) : '0') )

#define snmp_cstrcat(b,l,o,a,s) snmp_strcat(b,l,o,a,(const u_char *)s)
#define CLEAR_SNMP_STRIKE_FLAGS(x) \
	x &= ~(SNMP_FLAGS_STRIKE2|SNMP_FLAGS_STRIKE1)
#define MAX_STATS NETSNMP_STAT_MAX_STATS
#define  NETSNMP_STAT_MAX_STATS              (STAT_TLSTM_STATS_END+1)
#define REPORT_STATS_LEN  9	
#define REPORT_STATS_LEN2 8	
#define REPORT_snmpInvalidMsgs_NUM           2
#define REPORT_snmpUnavailableContexts_NUM  4
#define REPORT_snmpUnknownContexts_NUM      5
#define REPORT_snmpUnknownPDUHandlers_NUM    3
#define REPORT_snmpUnknownSecurityModels_NUM 1
#define REPORT_usmStatsDecryptionErrors_NUM 6
#define REPORT_usmStatsNotInTimeWindows_NUM 2
#define REPORT_usmStatsUnknownEngineIDs_NUM 4
#define REPORT_usmStatsUnknownUserNames_NUM 3
#define REPORT_usmStatsUnsupportedSecLevels_NUM 1
#define REPORT_usmStatsWrongDigests_NUM     5
#define SET_SNMP_ERROR(x) snmp_errno=(x)
#define SET_SNMP_STRIKE_FLAGS(x) \
	((   x & SNMP_FLAGS_STRIKE2 ) ? 1 :				\
	 ((( x & SNMP_FLAGS_STRIKE1 ) ? ( x |= SNMP_FLAGS_STRIKE2 ) :	\
	                                ( x |= SNMP_FLAGS_STRIKE1 )),	\
	                                0))
#define SNMPERR_ASN_PARSE_ERR           (-29)
#define SNMPERR_AUTHENTICATION_FAILURE 	(-35)
#define SNMPERR_BAD_ENG_ID 		(-26)
#define SNMPERR_BAD_RECVFROM 		(-25)
#define SNMPERR_BAD_SEC_LEVEL 		(-28)
#define SNMPERR_BAD_SEC_NAME 		(-27)
#define SNMPERR_DECRYPTION_ERR          (-37)
#define SNMPERR_INVALID_MSG             (-31)
#define SNMPERR_JUST_A_CONTEXT_PROBE    (-66)
#define SNMPERR_NOT_IN_TIME_WINDOW 	(-36)
#define SNMPERR_OID_NONINCREASING       (-65)
#define SNMPERR_TIMEOUT 		(-24)
#define SNMPERR_TLS_NO_CERTIFICATE      (-69)
#define SNMPERR_TRANSPORT_CONFIG_ERROR  (-68)
#define SNMPERR_TRANSPORT_NO_CONFIG     (-67)
#define SNMPERR_UNKNOWN_ENG_ID          (-32)
#define SNMPERR_UNKNOWN_REPORT          (-41)
#define SNMPERR_UNKNOWN_SEC_MODEL 	(-30)
#define SNMPERR_UNKNOWN_USER_NAME 	(-33)
#define SNMPERR_UNSUPPORTED_SEC_LEVEL 	(-34)
#define SNMPV3_IGNORE_UNAUTH_REPORTS 0

#define SNMP_DEFAULT_AUTH_PROTO     usmHMACMD5AuthProtocol
#define SNMP_DEFAULT_AUTH_PROTOLEN  OID_LENGTH(SNMP_DEFAULT_AUTH_PROTO)
#define SNMP_DEFAULT_COMMUNITY_LEN  0   
#define SNMP_DEFAULT_CONTEXT        ""
#define SNMP_DEFAULT_PRIV_PROTO     usmDESPrivProtocol
#define SNMP_DEFAULT_PRIV_PROTOLEN  OID_LENGTH(SNMP_DEFAULT_PRIV_PROTO)
#define SNMP_DETAIL_SIZE        512
#define SNMP_FLAGS_DONT_PROBE      0x100      
#define SNMP_FLAGS_LISTENING       0x40 
#define SNMP_FLAGS_RESP_CALLBACK   0x400      
#define SNMP_FLAGS_SHARED_SOCKET   0x10 
#define SNMP_FLAGS_STREAM_SOCKET   0x80
#define SNMP_FLAGS_STRIKE1         0x01
#define SNMP_FLAGS_STRIKE2         0x02
#define SNMP_FLAGS_SUBSESSION      0x20
#define SNMP_FLAGS_UDP_BROADCAST   0x800
#define SNMP_FLAGS_USER_CREATED    0x200      
#define SNMP_MAX_CONTEXT_SIZE      256
#define SNMP_MAX_ENG_SIZE          32
#define SNMP_MAX_MSG_SIZE          1472 
#define SNMP_MAX_MSG_V3_HDRS       (4+3+4+7+7+3+7+16)   
#define SNMP_MAX_RCV_MSG_SIZE      65536
#define SNMP_MAX_SEC_NAME_SIZE     256
#define SNMP_SEC_PARAM_BUF_SIZE    256
#define SNMP_SESS_AUTHORITATIVE    1    
#define SNMP_SESS_NONAUTHORITATIVE 0    
#define SNMP_SESS_UNKNOWNAUTH      2    
#define   STAT_MPD_STATS_END                 STAT_SNMPUNKNOWNPDUHANDLERS
#define   STAT_MPD_STATS_START               STAT_SNMPUNKNOWNSECURITYMODELS
#define  STAT_SNMPINASNPARSEERRS             14
#define  STAT_SNMPINBADCOMMUNITYNAMES        12
#define  STAT_SNMPINBADCOMMUNITYUSES         13
#define  STAT_SNMPINBADVALUES                18
#define  STAT_SNMPINBADVERSIONS              11
#define  STAT_SNMPINGENERRS                  20
#define  STAT_SNMPINGETNEXTS                 24
#define  STAT_SNMPINGETREQUESTS              23
#define  STAT_SNMPINGETRESPONSES             26
#define  STAT_SNMPINNOSUCHNAMES              17
#define  STAT_SNMPINPKTS                     9
#define  STAT_SNMPINREADONLYS                19
#define  STAT_SNMPINSETREQUESTS              25
#define  STAT_SNMPINTOOBIGS                  16
#define  STAT_SNMPINTOTALREQVARS             21
#define  STAT_SNMPINTOTALSETVARS             22
#define  STAT_SNMPINTRAPS                    27
#define   STAT_SNMPINVALIDMSGS               1
#define  STAT_SNMPOUTBADVALUES               30
#define  STAT_SNMPOUTGENERRS                 32
#define  STAT_SNMPOUTGETNEXTS                34
#define  STAT_SNMPOUTGETREQUESTS             33
#define  STAT_SNMPOUTGETRESPONSES            36
#define  STAT_SNMPOUTNOSUCHNAMES             29
#define  STAT_SNMPOUTPKTS                    10
#define  STAT_SNMPOUTSETREQUESTS             35
#define  STAT_SNMPOUTTOOBIGS                 28
#define  STAT_SNMPOUTTRAPS                   37
#define   STAT_SNMPUNKNOWNPDUHANDLERS        2
#define   STAT_SNMPUNKNOWNSECURITYMODELS     0
#define  STAT_SNMP_STATS_END                 STAT_SNMPPROXYDROPS
#define  STAT_SNMP_STATS_START               STAT_SNMPINPKTS
#define  STAT_TARGET_STATS_END               STAT_SNMPUNKNOWNCONTEXTS
#define  STAT_TARGET_STATS_START             STAT_SNMPUNAVAILABLECONTEXTS
#define  STAT_TLSTM_SNMPTLSTMSESSIONACCEPTS                    50
#define  STAT_TLSTM_SNMPTLSTMSESSIONCLIENTCLOSES               48
#define  STAT_TLSTM_SNMPTLSTMSESSIONINVALIDCACHES              56
#define  STAT_TLSTM_SNMPTLSTMSESSIONINVALIDCLIENTCERTIFICATES  53
#define  STAT_TLSTM_SNMPTLSTMSESSIONINVALIDSERVERCERTIFICATES  55
#define  STAT_TLSTM_SNMPTLSTMSESSIONNOSESSIONS                 52
#define  STAT_TLSTM_SNMPTLSTMSESSIONOPENERRORS                 49
#define  STAT_TLSTM_SNMPTLSTMSESSIONOPENS                      47
#define  STAT_TLSTM_SNMPTLSTMSESSIONSERVERCLOSES               51
#define  STAT_TLSTM_SNMPTLSTMSESSIONUNKNOWNSERVERCERTIFICATE   54
#define  STAT_TLSTM_STATS_END          STAT_TLSTM_SNMPTLSTMSESSIONINVALIDCACHES
#define  STAT_TLSTM_STATS_START                 STAT_TLSTM_SNMPTLSTMSESSIONOPENS
#define  STAT_TSM_SNMPTSMINADEQUATESECURITYLEVELS  44
#define  STAT_TSM_SNMPTSMINVALIDCACHES             43
#define  STAT_TSM_SNMPTSMINVALIDPREFIXES           46
#define  STAT_TSM_SNMPTSMUNKNOWNPREFIXES           45
#define  STAT_TSM_STATS_END                   STAT_TSM_SNMPTSMINVALIDPREFIXES
#define  STAT_TSM_STATS_START                 STAT_TSM_SNMPTSMINVALIDCACHES
#define   STAT_USMSTATSDECRYPTIONERRORS      8
#define   STAT_USMSTATSNOTINTIMEWINDOWS      4
#define   STAT_USMSTATSUNKNOWNENGINEIDS      6
#define   STAT_USMSTATSUNKNOWNUSERNAMES      5
#define   STAT_USMSTATSUNSUPPORTEDSECLEVELS  3
#define   STAT_USMSTATSWRONGDIGESTS          7
#define   STAT_USM_STATS_END                 STAT_USMSTATSDECRYPTIONERRORS
#define   STAT_USM_STATS_START               STAT_USMSTATSUNSUPPORTEDSECLEVELS




#define netsnmp_feature_child_of(X, Y)


#define netsnmp_feature_unused(X) char netsnmp_feature_unused_ ## X

#define NETSNMP_SELECT_NOALARMS 0x01
#define NETSNMP_SELECT_NOFLAGS  0x00




#define ASN_APPLICATION     ((u_char)0x40)
#define ASN_APP_COUNTER64 (ASN_APPLICATION | 6)
#define ASN_APP_DOUBLE (ASN_APPLICATION | 9)
#define ASN_APP_FLOAT (ASN_APPLICATION | 8)
#define ASN_APP_I64 (ASN_APPLICATION | 10)
#define ASN_APP_OPAQUE (ASN_APPLICATION | 4)
#define ASN_APP_U64 (ASN_APPLICATION | 11)
#define ASN_APP_UNION (ASN_PRIVATE | 1) 
#define ASN_EXTENSION_ID    (0x1F)
#define ASN_OPAQUE_COUNTER64 (ASN_OPAQUE_TAG2 + ASN_APP_COUNTER64)
#define ASN_OPAQUE_COUNTER64_MX_BER_LEN 12
#define ASN_OPAQUE_DOUBLE (ASN_OPAQUE_TAG2 + ASN_APP_DOUBLE)
#define ASN_OPAQUE_DOUBLE_BER_LEN 11
#define ASN_OPAQUE_FLOAT (ASN_OPAQUE_TAG2 + ASN_APP_FLOAT)
#define ASN_OPAQUE_FLOAT_BER_LEN 7
#define ASN_OPAQUE_I64 (ASN_OPAQUE_TAG2 + ASN_APP_I64)
#define ASN_OPAQUE_I64_MX_BER_LEN 11
#define ASN_OPAQUE_TAG1 (ASN_CONTEXT | ASN_EXTENSION_ID)
#define ASN_OPAQUE_TAG2 ((u_char)0x30)
#define ASN_OPAQUE_TAG2U ((u_char)0x2f) 
#define ASN_OPAQUE_U64 (ASN_OPAQUE_TAG2 + ASN_APP_U64)
#define ASN_OPAQUE_U64_MX_BER_LEN 12
#define ASN_PRIV_DELEGATED  (ASN_PRIVATE | 5)
#define ASN_PRIV_EXCL_RANGE (ASN_PRIVATE | 3)
#define ASN_PRIV_IMPLIED_OBJECT_ID  (ASN_PRIVATE | ASN_OBJECT_ID)       
#define ASN_PRIV_IMPLIED_OCTET_STR  (ASN_PRIVATE | ASN_OCTET_STR)       
#define ASN_PRIV_INCL_RANGE (ASN_PRIVATE | 2)
#define ASN_PRIV_RETRY      (ASN_PRIVATE | 7)   
#define ASN_PRIV_STOP       (ASN_PRIVATE | 8)   
#define IS_CONSTRUCTOR(byte)	((byte) & ASN_CONSTRUCTOR)
#define IS_DELEGATED(x)   ((x) == ASN_PRIV_DELEGATED)
#define IS_EXTENSION_ID(byte)	(((byte) & ASN_EXTENSION_ID) == ASN_EXTENSION_ID)
#define OID_LENGTH(x)  (sizeof(x)/sizeof(oid))
#define MAX_SUBID   0xFFFFFFFFUL

#define NETSNMP_PRIo ""
#  define CMSG_LEN(l)   (_CMSG_HDR_ALIGN(sizeof(struct cmsghdr)) + (l))
#  define CMSG_SPACE(l) \
            ((unsigned int)_CMSG_HDR_ALIGN(sizeof (struct cmsghdr) + (l)))
#define NETSNMP_TM_MAX_SECNAME 256
#define		NETSNMP_TRANSPORT_FLAG_EMPTY_PKT 0x10
#define         NETSNMP_TRANSPORT_FLAG_TMSTATE   0x08  
#define NETSNMP_TSPEC_LOCAL                     0x01 







#define NETSNMP_NO_SUCH_PROCESS INVALID_HANDLE_VALUE

#define USM_AUTH_KU_LEN     64
#define USM_PRIV_KU_LEN     64
#define max_repetitions errindex

#define ONE_SEC         1000000L
#define RS_IS_ACTIVE( x ) ( x == RS_ACTIVE )
#define RS_IS_GOING_ACTIVE( x ) ( x == RS_CREATEANDGO || x == RS_ACTIVE )
#define RS_IS_NOT_ACTIVE( x ) ( ! RS_IS_GOING_ACTIVE(x) )
#define RS_NONEXISTENT    0

#define ST_NONE 0
#define TV_FALSE 2
#define TV_TRUE 1
#define SNMPADMINLENGTH 255
#define SNMP_CMD_CONFIRMED(c) (c == SNMP_MSG_INFORM || c == SNMP_MSG_GETBULK ||\
                               c == SNMP_MSG_GETNEXT || c == SNMP_MSG_GET )
#define SNMP_ENDOFMIBVIEW    (ASN_CONTEXT | ASN_PRIMITIVE | 0x2) 
#define SNMP_ERR_BADVALUE               (3)
#define SNMP_ERR_NOERROR                (0)     
#define SNMP_ERR_NOSUCHNAME             (2)
#define SNMP_ERR_READONLY               (4)

#define SNMP_MAX_PACKET_LEN (0x7fffffff)
#define SNMP_MIN_MAX_LEN    484 
#define SNMP_MSG_FLAG_AUTH_BIT          0x01
#define SNMP_MSG_FLAG_PRIV_BIT          0x02
#define SNMP_MSG_FLAG_RPRT_BIT          0x04
#define SNMP_MSG_GET        (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x0) 
#define SNMP_MSG_GETBULK    (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x5) 
#define SNMP_MSG_GETNEXT    (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x1) 
#define SNMP_MSG_INFORM     (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x6) 
#define SNMP_MSG_INTERNAL_CHECK_CONSISTENCY     21
#define SNMP_MSG_INTERNAL_CHECK_VALUE           17
#define SNMP_MSG_INTERNAL_COMMIT                23
#define SNMP_MSG_INTERNAL_GET_STASH             131
#define SNMP_MSG_INTERNAL_IRREVERSIBLE_COMMIT   25
#define SNMP_MSG_INTERNAL_OBJECT_LOOKUP         129
#define SNMP_MSG_INTERNAL_POST_REQUEST          130
#define SNMP_MSG_INTERNAL_PRE_REQUEST           128
#define SNMP_MSG_INTERNAL_ROW_CREATE            18
#define SNMP_MSG_INTERNAL_SET_ACTION       2
#define SNMP_MSG_INTERNAL_SET_BEGIN        -1
#define SNMP_MSG_INTERNAL_SET_COMMIT       3
#define SNMP_MSG_INTERNAL_SET_FREE         4
#define SNMP_MSG_INTERNAL_SET_MAX          6
#define SNMP_MSG_INTERNAL_SET_RESERVE1     0    
#define SNMP_MSG_INTERNAL_SET_RESERVE2     1
#define SNMP_MSG_INTERNAL_SET_UNDO         5
#define SNMP_MSG_INTERNAL_SET_VALUE             20
#define SNMP_MSG_INTERNAL_UNDO_CLEANUP          26
#define SNMP_MSG_INTERNAL_UNDO_COMMIT           24
#define SNMP_MSG_INTERNAL_UNDO_SET              22
#define SNMP_MSG_INTERNAL_UNDO_SETUP            19
#define SNMP_MSG_REPORT     (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x8) 
#define SNMP_MSG_RESPONSE   (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x2) 
#define SNMP_MSG_SET        (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x3) 
#define SNMP_MSG_TRAP       (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x4) 
#define SNMP_MSG_TRAP2      (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x7) 
#define SNMP_NOSUCHINSTANCE  (ASN_CONTEXT | ASN_PRIMITIVE | 0x1) 
#define SNMP_NOSUCHOBJECT    (ASN_CONTEXT | ASN_PRIMITIVE | 0x0) 
#define SNMP_SEC_MODEL_TSM              4
#define SNMP_STORAGE_NONE  0
#define SNMP_VALIDATE_ERR(x)  ( (x > MAX_SNMP_ERR) ? \
                                   SNMP_ERR_GENERR : \
                                   (x < SNMP_ERR_NOERROR) ? \
                                      SNMP_ERR_GENERR : \
                                      x )
#define SNMP_VERSION_2c    1
#define SNMP_VERSION_2star 130  
#define SNMP_VERSION_2u    2    
#define SNMP_VERSION_3     3
#define SNMP_VERSION_sec   128  
#define UCD_MSG_FLAG_ALWAYS_IN_VIEW          0x800
#define UCD_MSG_FLAG_BULK_TOOBIG          0x010000
#define UCD_MSG_FLAG_EXPECT_RESPONSE         0x200
#define UCD_MSG_FLAG_FORCE_PDU_COPY          0x400
#define UCD_MSG_FLAG_FORWARD_ENCODE         0x8000
#define UCD_MSG_FLAG_ONE_PASS_ONLY          0x2000
#define UCD_MSG_FLAG_PDU_TIMEOUT            0x1000
#define UCD_MSG_FLAG_RESPONSE_PDU            0x100
#define UCD_MSG_FLAG_TUNNELED               0x4000
#define ASN_COUNTER64   (ASN_APPLICATION | 6)
#define ASN_INTEGER64        (ASN_APPLICATION | 10)
#define ASN_IPADDRESS   (ASN_APPLICATION | 0)
#define ASN_TIMETICKS   (ASN_APPLICATION | 3)
#define ASN_UINTEGER    (ASN_APPLICATION | 7)   
#define ASN_UNSIGNED    (ASN_APPLICATION | 2)   
#define ASN_UNSIGNED64       (ASN_APPLICATION | 11)
#define COMMIT      3
#define ERROR_MSG(string)	snmp_set_detail(string)
#define FINISHED_SUCCESS        9
#define FREE        4
#define NETSNMP_OLDAPI_NOACCESS 0x0000  
#define NOACCESS        NETSNMP_OLDAPI_NOACCESS
#define NULL 0
#define RESERVE1    0
#define RESERVE2    1
#define RONLY           NETSNMP_OLDAPI_RONLY
#define RWRITE          NETSNMP_OLDAPI_RWRITE

#define UNDO        5



#define C2SE_ERR_COMMUNITY_TOO_LONG -2
#define C2SE_ERR_CONTEXT_TOO_LONG   -4
#define C2SE_ERR_MASK_MISMATCH      -5
#define C2SE_ERR_MEMORY             -6
#define C2SE_ERR_MISSING_ARG        -1
#define C2SE_ERR_SECNAME_TOO_LONG   -3
#define C2SE_ERR_SUCCESS             0









#define MAX_CALLBACK_IDS    2
#define MAX_CALLBACK_SUBIDS 17
#define NETSNMP_CALLBACK_DEFAULT_PRIORITY       0
#define NETSNMP_CALLBACK_HIGHEST_PRIORITY      -1024 
#define NETSNMP_CALLBACK_LOWEST_PRIORITY        1024
#define SNMP_CALLBACK_APPLICATION 1
#define SNMP_CALLBACK_LIBRARY     0

#define STAT_TIMEOUT 2



#define DEBUGDUMPSETUP(token, buf, len)                                 \
    do { netsnmp_debug_no_dumpsetup(token, buf, len); } while (0)
#define DEBUGIF(x)        if(0)



#define DEBUGMSG(x)			do { netsnmp_debug_no_msg x; } while (0)


#define DEBUGMSGL(x)			do { netsnmp_debug_no_msg x; } while (0)
#define DEBUGMSGOID(x)			do { netsnmp_debug_no_oid x; } while (0)

#define DEBUGMSGSUBOID(x)		do { netsnmp_debug_no_oid x; } while (0)
#define DEBUGMSGT(x)			do { netsnmp_debug_no_msg x; } while (0)
#define DEBUGMSGTL(x)			do { netsnmp_debug_no_msg x; } while (0)
#define DEBUGMSGT_NC(x)			do { netsnmp_debug_no_msg x; } while (0)
#define DEBUGMSGVAR(x)			do { netsnmp_debug_no_var x; } while (0)
#define DEBUGMSG_NC(x)			do { netsnmp_debug_no_msg x; } while (0)

#define DEBUGTRACE         do {if (_DBG_IF_) {__DBGTRACE;} }while(0)
#define DEBUGTRACETOK(x)                                \
    do { netsnmp_debug_no_tracetok(x); } while (0)
#define ERROR_MSG(string)	snmp_set_detail(string)

#define DEFAULT_LOG_ID "net-snmp"
#define LOG_ALERT       1       
#define LOG_CRIT        2       
#define LOG_DEBUG       7       
#define LOG_EMERG       0       
#define LOG_ERR         3       
#define LOG_INFO        6       
#define LOG_NOTICE      5       
#define LOG_WARNING     4       
#define NETSNMP_LOGONCE(x) do { \
        static char logged = 0; \
        if (!logged) {          \
            logged = 1;         \
            snmp_log x ;        \
        }                       \
    } while(0)

#define DEBUG_ALWAYS_TOKEN "all"
#define DEBUG_TOKEN_DELIMITER ","
#define MAX_DEBUG_TOKENS 256
#define MAX_DEBUG_TOKEN_LEN 128

#define _DBG_IF_            snmp_get_do_debugging()
#define __DBGDUMPHEADER(token,x) \
        __DBGPRINTINDENT("dumph_" token); \
        debugmsg("dumph_" token,x); \
        if (debug_is_token_registered("dumpx" token) == SNMPERR_SUCCESS ||    \
            debug_is_token_registered("dumpv" token) == SNMPERR_SUCCESS ||    \
            (debug_is_token_registered("dumpx_" token) != SNMPERR_SUCCESS &&  \
             debug_is_token_registered("dumpv_" token) != SNMPERR_SUCCESS)) { \
            debugmsg("dumph_" token,"\n"); \
        } else { \
            debugmsg("dumph_" token,"  "); \
        } \
        __DBGINDENTMORE()
#define __DBGDUMPSECTION(token,x) \
        __DBGPRINTINDENT("dumph_" token); \
        debugmsg("dumph_" token,"%s\n",x);\
        __DBGINDENTMORE()
#define __DBGDUMPSETUP(token,buf,len) \
        debugmsg("dumpx" token, "dumpx_%s:%*s", token, __DBGINDENT(), ""); \
        __DBGMSGHEX(("dumpx_" token,buf,len)); \
        if (debug_is_token_registered("dumpv" token) == SNMPERR_SUCCESS || \
            debug_is_token_registered("dumpv_" token) != SNMPERR_SUCCESS) { \
            debugmsg("dumpx_" token,"\n"); \
        } else { \
            debugmsg("dumpx_" token,"  "); \
        } \
        debugmsg("dumpv" token, "dumpv_%s:%*s", token, __DBGINDENT(), "");
#define __DBGINDENT()      debug_indent_get()
#define __DBGINDENTADD(x)  debug_indent_add(x)
#define __DBGINDENTLESS()  debug_indent_add(-2)
#define __DBGINDENTMORE()  debug_indent_add(2)
#define __DBGMSGHEX(x)     debugmsg_hex x
#define __DBGMSGHEXTLI(x)  debugmsg_hextli x
#define __DBGMSGL(x)     __DBGTRACE, debugmsg x
#define __DBGMSGL_NC(x)  __DBGTRACE; debugmsg x
#define __DBGMSGOID(x)     debugmsg_oid x
#define __DBGMSGOIDRANGE(x) debugmsg_oidrange x
#define __DBGMSGSUBOID(x)  debugmsg_suboid x
#define __DBGMSGT(x)     debugmsgtoken x,  debugmsg x
#define __DBGMSGTL(x)    __DBGTRACE, debugmsgtoken x, debugmsg x
#define __DBGMSGTL_NC(x) __DBGTRACE; debug_combo_nc x
#define __DBGMSGT_NC(x)  debug_combo_nc x
#define __DBGMSGVAR(x)     debugmsg_var x
#define __DBGMSG_NC(x)   debugmsg x
#define __DBGPRINTINDENT(token) __DBGMSGTL((token, "%*s", __DBGINDENT(), ""))
#define __DBGTRACE       __DBGMSGT(("trace","%s(): %s, %d:\n",\
				NETSNMP_FUNCTION,"__FILE__","__LINE__"))
#define __DBGTRACETOK(x) __DBGMSGT((x,"%s(): %s, %d:\n",       \
                                    NETSNMP_FUNCTION,"__FILE__","__LINE__"))
#define NETSNMP_ATTRIBUTE_FORMAT(type, formatArg, firstArg)



#define MIB NETSNMP_MIB2_OID

#define MIB_IFTYPE_PROPPOINTTOPOINTSERIAL   22
#define MIB_IPROUTEPROTO_BBNSPFIGP  12
#define MIB_IPROUTEPROTO_CISCOIGRP  11
#define MIB_IPROUTEPROTO_NETMGMT    3
#define NETSNMP_MIB2_OID 1, 3, 6, 1, 2, 1
#define NETSNMP_OID_OUTPUT_FULL    3
#define NETSNMP_OID_OUTPUT_MODULE  2
#define NETSNMP_OID_OUTPUT_NONE    6
#define NETSNMP_OID_OUTPUT_NUMERIC 4
#define NETSNMP_OID_OUTPUT_SUFFIX  1
#define NETSNMP_OID_OUTPUT_UCD     5
#define NETSNMP_STRING_OUTPUT_ASCII  2
#define NETSNMP_STRING_OUTPUT_GUESS  1
#define NETSNMP_STRING_OUTPUT_HEX    3

#define OID_STASH_CHILDREN_SIZE 31

#define MAXLABEL        NETSNMP_MAXLABEL
#define MAXQUOTESTR     4096    
#define MAXTOKEN        128     
#define MIB_ACCESS_CREATE      48
#define MIB_ACCESS_NOACCESS    21
#define MIB_ACCESS_NOTIFY      67
#define MIB_ACCESS_READONLY    18
#define MIB_ACCESS_READWRITE   19
#define MIB_STATUS_CURRENT     57
#define MIB_STATUS_DEPRECATED  39
#define MIB_STATUS_MANDATORY   23
#define MIB_STATUS_OBSOLETE    25
#define MIB_STATUS_OPTIONAL    24
#define NETSNMP_MAXLABEL 64      

#define TYPE_AGENTCAP       25
#define TYPE_BITSTRING      12
#define TYPE_COUNTER        6
#define TYPE_COUNTER64      11
#define TYPE_GAUGE          7
#define TYPE_INTEGER        3
#define TYPE_INTEGER32      16
#define TYPE_IPADDR         5
#define TYPE_MODCOMP        26
#define TYPE_NETADDR        4
#define TYPE_NOTIFTYPE      21
#define TYPE_NSAPADDRESS    13
#define TYPE_NULL           10
#define TYPE_OBJID          1
#define TYPE_OBJIDENTITY    27
#define TYPE_OCTETSTR       2
#define TYPE_OPAQUE         9
#define TYPE_OTHER          0
#define TYPE_SIMPLE_LAST    16
#define TYPE_TIMETICKS      8
#define TYPE_UINTEGER       14
#define TYPE_UNSIGNED32     15


#          define NETSNMP_FUNC_FMT " %s()\n"
#          define NETSNMP_FUNC_PARAM NETSNMP_FUNCTION

#    define __STRING(x) #x
#      define netsnmp_assert(x)  do { \
              if ( x ) \
                 ; \
              else \
                 snmp_log(LOG_ERR, \
                          "netsnmp_assert %s failed %s:%d" NETSNMP_FUNC_FMT, \
                          __STRING(x),"__FILE__","__LINE__", \
                          NETSNMP_FUNC_PARAM); \
           }while(0)
#      define netsnmp_assert_or_msgreturn(x, y, z)  do {       \
              if ( x ) \
                 ; \
              else { \
                 snmp_log(LOG_ERR, \
                          "netsnmp_assert %s failed %s:%d" NETSNMP_FUNC_FMT, \
                          __STRING(x),"__FILE__","__LINE__", \
                          NETSNMP_FUNC_PARAM); \
                 snmp_log(LOG_ERR, y); \
                 return z; \
              } \
           }while(0)
#      define netsnmp_assert_or_return(x, y)  do {        \
              if ( x ) \
                 ; \
              else { \
                 snmp_log(LOG_ERR, \
                          "netsnmp_assert %s failed %s:%d" NETSNMP_FUNC_FMT, \
                          __STRING(x),"__FILE__","__LINE__", \
                          NETSNMP_FUNC_PARAM); \
                 return y; \
              } \
           }while(0)
#define netsnmp_malloc_check_LRE(ptr)           \
    netsnmp_assert_or_return( (ptr) != NULL, SNMPERR_MALLOC)
#define netsnmp_malloc_check_LRN(ptr)           \
    netsnmp_assert_or_return( (ptr) != NULL, NULL)
#define netsnmp_malloc_check_LRV(ptr, val)                          \
    netsnmp_assert_or_return( (ptr) != NULL, val)
#define netsnmp_require_ptr_LRV( ptr, val ) \
    netsnmp_assert_or_return( (ptr) != NULL, val)
#define netsnmp_static_assert(x) \
    do { switch(0) { case (x): case 0: ; } } while(0)


#define CONTAINER_CHECK_OPTION(x,o,rc)    do {                          \
        rc = x->flags & 0;                                              \
    } while(0)
#define CONTAINER_COMPARE(x,l,r)    (x)->compare(l,r)
#define CONTAINER_FIND(x,k)         (x)->find(x,k)
#define CONTAINER_FIRST(x)          (x)->find_next(x,NULL)
#define CONTAINER_FLAG_INTERNAL_1                  0x80000000
#define CONTAINER_FOR_EACH(x,f,c)   (x)->for_each(x,f,c)
#define CONTAINER_GET_SUBSET(x,k)   (x)->get_subset(x,k)
#define CONTAINER_ITERATOR(x)       (x)->get_iterator(x)
#define CONTAINER_KEY_ALLOW_DUPLICATES             0x00000001
#define CONTAINER_KEY_UNSORTED                     0x00000002
#define CONTAINER_NEXT(x,k)         (x)->find_next(x,k)
#define CONTAINER_SET_OPTIONS(x,o,rc)  do {                             \
        if (NULL==(x)->options)                                         \
            rc = -1;                                                    \
        else {                                                          \
            rc = (x)->options(x, 1, o);                                 \
            if (rc != -1 )                                              \
                (x)->flags |= o;                                        \
        }                                                               \
    } while(0)
#define CONTAINER_SIZE(x)           (x)->get_size(x)
#define ITERATOR_FIRST(x)  x->first(x)
#define ITERATOR_LAST(x)   x->last(x)
#define ITERATOR_NEXT(x)   x->next(x)
#define ITERATOR_RELEASE(x) do { x->release(x); x = NULL; } while(0)
#define ITERATOR_REMOVE(x) x->remove(x)





#define SA_FIRED 0x10          
#define SA_REPEAT 0x01          

#define MT_APPLICATION_ID  1
#define MT_LIBRARY_ID      0
#define MT_LIB_MAXIMUM     6    
#define MT_LIB_MESSAGEID   3
#define MT_LIB_NONE        0
#define MT_LIB_REQUESTID   2
#define MT_LIB_SESSION     1
#define MT_LIB_SESSIONID   4
#define MT_LIB_TRANSID     5
#define MT_MAX_IDS         3    
#define MT_MAX_SUBIDS      10
#define MT_MUTEX_INIT_DEFAULT pthread_mutexattr_default

#define MT_TOKEN_ID        2
#define I64CHARSZ 21


#define SOCK_CLEANUP winsock_cleanup()
#define SOCK_STARTUP winsock_startup()
#define _GETOPT_H_ 1

#define CONTEXT_MATCH_EXACT  1
#define CONTEXT_MATCH_PREFIX 2
#define VACMSTRINGLEN   34      
#define VACMVIEWSPINLOCK 1

#define VACM_MAX_STRING 32
#define VACM_MAX_VIEWS     8
#define VACM_MODE_CHECK_SUBTREE       2
#define VACM_MODE_FIND                0
#define VACM_MODE_IGNORE_MASK         1
#define VACM_NOACCESS      3
#define VACM_NOGROUP       2
#define VACM_NOSECNAME     1
#define VACM_NOSUCHCONTEXT 6
#define VACM_NOTINVIEW     5
#define VACM_NOVIEW        4
#define VACM_SUBTREE_UNKNOWN 7
#define VACM_SUCCESS       0
#define VACM_VIEW_ENUM_NAME "vacmviews"
#define VACM_VIEW_EXECUTE  4
#define VACM_VIEW_EXECUTE_BIT  (1 << VACM_VIEW_EXECUTE)
#define VACM_VIEW_LOG      3
#define VACM_VIEW_LOG_BIT      (1 << VACM_VIEW_LOG)
#define VACM_VIEW_NET      5
#define VACM_VIEW_NET_BIT      (1 << VACM_VIEW_NET)
#define VACM_VIEW_NOTIFY   2
#define VACM_VIEW_NOTIFY_BIT    (1 << VACM_VIEW_NOTIFY)
#define VACM_VIEW_NO_BITS      0
#define VACM_VIEW_READ     0
#define VACM_VIEW_READ_BIT      (1 << VACM_VIEW_READ)
#define VACM_VIEW_WRITE    1
#define VACM_VIEW_WRITE_BIT     (1 << VACM_VIEW_WRITE)
#define SE_ALREADY_THERE 2
#define SE_APPLICATION_ID 2
#define SE_ASSIGNED_ID    3
#define SE_DNE           -2
#define SE_LIBRARY_ID     0
#define SE_MAX_IDS 5
#define SE_MAX_SUBIDS 32        
#define SE_MIB_ID         1
#define SE_NOMEM         1
#define SE_OK            0

#define NETSNMP_PARSE_ARGS_ERROR         -3
#define NETSNMP_PARSE_ARGS_ERROR_USAGE   -1
#define NETSNMP_PARSE_ARGS_NOLOGGING    0x0001
#define NETSNMP_PARSE_ARGS_NOZERO       0x0002
#define NETSNMP_PARSE_ARGS_SUCCESS       0
#define NETSNMP_PARSE_ARGS_SUCCESS_EXIT  -2


#define NETSNMP_DS_APPLICATION_ID 1
#define NETSNMP_DS_LIBRARY_ID     0
#define NETSNMP_DS_LIB_16BIT_IDS           31   
#define NETSNMP_DS_LIB_2DIGIT_HEX_OUTPUT   33	
#define NETSNMP_DS_LIB_ADD_FORWARDER_INFO  47 
#define NETSNMP_DS_LIB_ALARM_DONT_USE_SIG  11   
#define NETSNMP_DS_LIB_APPEND_LOGFILES     37 
#define NETSNMP_DS_LIB_APPTYPE           6
#define NETSNMP_DS_LIB_APPTYPES          20
#define NETSNMP_DS_LIB_AUTHLOCALIZEDKEY  18
#define NETSNMP_DS_LIB_AUTHMASTERKEY     16
#define NETSNMP_DS_LIB_AUTHPASSPHRASE    3
#define NETSNMP_DS_LIB_CERT_EXTRA_SUBDIR 26
#define NETSNMP_DS_LIB_CLIENTRECVBUF       10 
#define NETSNMP_DS_LIB_CLIENTSENDBUF        9 
#define NETSNMP_DS_LIB_CLIENT_ADDR       14
#define NETSNMP_DS_LIB_CLIENT_ADDR_USES_PORT 42 
#define NETSNMP_DS_LIB_COMMUNITY         7
#define NETSNMP_DS_LIB_CONFIGURATION_DIR 9
#define NETSNMP_DS_LIB_CONTEXT           1
#define NETSNMP_DS_LIB_DEFAULT_PORT         3
#define NETSNMP_DS_LIB_DISABLE_CONFIG_LOAD      NETSNMP_DS_LIB_DONT_READ_CONFIGS
#define NETSNMP_DS_LIB_DISABLE_PERSISTENT_LOAD  35 
#define NETSNMP_DS_LIB_DISABLE_PERSISTENT_SAVE  36 
#define NETSNMP_DS_LIB_DISABLE_V1          43 
#define NETSNMP_DS_LIB_DISABLE_V2c         44 
#define NETSNMP_DS_LIB_DISABLE_V3          45 
#define NETSNMP_DS_LIB_DNSSEC_WARN_ONLY     41 
#define NETSNMP_DS_LIB_DONT_BREAKDOWN_OIDS 10   
#define NETSNMP_DS_LIB_DONT_CHECK_RANGE    16   
#define NETSNMP_DS_LIB_DONT_LOAD_HOST_FILES 40 
#define NETSNMP_DS_LIB_DONT_PERSIST_STATE  32	
#define NETSNMP_DS_LIB_DONT_PRINT_UNITS    29 
#define NETSNMP_DS_LIB_DONT_READ_CONFIGS   6    
#define NETSNMP_DS_LIB_DUMP_PACKET         4
#define NETSNMP_DS_LIB_ESCAPE_QUOTES       19   
#define NETSNMP_DS_LIB_FILTER_SOURCE       46 
#define NETSNMP_DS_LIB_FILTER_TYPE         17 
#define NETSNMP_DS_LIB_HAVE_READ_CONFIG    27   
#define NETSNMP_DS_LIB_HAVE_READ_PREMIB_CONFIG 26       
#define NETSNMP_DS_LIB_HEX_OUTPUT_LENGTH    6
#define NETSNMP_DS_LIB_HOSTNAME          27
#define NETSNMP_DS_LIB_IGNORE_NO_COMMUNITY 34	
#define NETSNMP_DS_LIB_KSM_KEYTAB        21
#define NETSNMP_DS_LIB_KSM_SERVICE_NAME  22
#define NETSNMP_DS_LIB_LOG_TIMESTAMP       5
#define NETSNMP_DS_LIB_MAX_BOOL_ID         48 
#define NETSNMP_DS_LIB_MAX_INT_ID          48 
#define NETSNMP_DS_LIB_MAX_STR_ID        48 
#define NETSNMP_DS_LIB_MIBDIRS           11
#define NETSNMP_DS_LIB_MIB_COMMENT_TERM    2
#define NETSNMP_DS_LIB_MIB_ERRORS          0
#define NETSNMP_DS_LIB_MIB_PARSE_LABEL     3
#define NETSNMP_DS_LIB_MIB_REPLACE         7    
#define NETSNMP_DS_LIB_MIB_WARNINGS         0
#define NETSNMP_DS_LIB_MSG_SEND_MAX        16 
#define NETSNMP_DS_LIB_NO_DISCOVERY        38 
#define NETSNMP_DS_LIB_NO_DISPLAY_HINT     30 
#define NETSNMP_DS_LIB_NO_TOKEN_WARNINGS   17   
#define NETSNMP_DS_LIB_NUMERIC_TIMETICKS   18   
#define NETSNMP_DS_LIB_OIDPREFIX         13
#define NETSNMP_DS_LIB_OIDSUFFIX         12
#define NETSNMP_DS_LIB_OID_OUTPUT_FORMAT    4
#define NETSNMP_DS_LIB_OPTIONALCONFIG    5
#define NETSNMP_DS_LIB_OUTPUT_PRECISION  35
#define NETSNMP_DS_LIB_PASSPHRASE        2
#define NETSNMP_DS_LIB_PERSISTENT_DIR    8
#define NETSNMP_DS_LIB_PRINT_FULL_OID      12   
#define NETSNMP_DS_LIB_PRINT_HEX_TEXT      23   
#define NETSNMP_DS_LIB_PRINT_NUMERIC_ENUM  8    
#define NETSNMP_DS_LIB_PRINT_NUMERIC_OIDS  9    
#define NETSNMP_DS_LIB_PRINT_SUFFIX_ONLY    NETSNMP_DS_LIB_OID_OUTPUT_FORMAT
#define NETSNMP_DS_LIB_PRINT_UCD_STYLE_OID 24   
#define NETSNMP_DS_LIB_PRIVLOCALIZEDKEY  19
#define NETSNMP_DS_LIB_PRIVMASTERKEY     17
#define NETSNMP_DS_LIB_PRIVPASSPHRASE    4
#define NETSNMP_DS_LIB_QUICKE_PRINT        28   
#define NETSNMP_DS_LIB_QUICK_PRINT         13   
#define NETSNMP_DS_LIB_READ_UCD_STYLE_OID  25   
#define NETSNMP_DS_LIB_RETRIES             15
#define NETSNMP_DS_LIB_REVERSE_ENCODE      20   
#define NETSNMP_DS_LIB_SAVE_MIB_DESCRS     1
#define NETSNMP_DS_LIB_SECLEVEL             1
#define NETSNMP_DS_LIB_SECMODEL          10
#define NETSNMP_DS_LIB_SECNAME           0
#define NETSNMP_DS_LIB_SERVERRECVBUF        8 
#define NETSNMP_DS_LIB_SERVERSENDBUF        7 
#define NETSNMP_DS_LIB_SNMPVERSION          2
#define NETSNMP_DS_LIB_SSHTOSNMP_SOCKET  25
#define NETSNMP_DS_LIB_SSH_PRIVKEY       34
#define NETSNMP_DS_LIB_SSH_PUBKEY        33
#define NETSNMP_DS_LIB_SSH_USERNAME      32
#define NETSNMP_DS_LIB_STRING_OUTPUT_FORMAT 5
#define NETSNMP_DS_LIB_TEMP_FILE_PATTERN 15
#define NETSNMP_DS_LIB_TIMEOUT             14
#define NETSNMP_DS_LIB_TLS_ALGORITMS     29
#define NETSNMP_DS_LIB_TLS_LOCAL_CERT    30
#define NETSNMP_DS_LIB_TLS_PEER_CERT     31
#define NETSNMP_DS_LIB_TSM_USE_PREFIX      39 
#define NETSNMP_DS_LIB_X509_CLIENT_PUB   23
#define NETSNMP_DS_LIB_X509_CRL_FILE     28
#define NETSNMP_DS_LIB_X509_SERVER_PUB   24
#define NETSNMP_DS_MAX_IDS 3
#define NETSNMP_DS_MAX_SUBIDS 48        
#define NETSNMP_DS_SNMP_VERSION_1    128        
#define NETSNMP_DS_SNMP_VERSION_2c   1  
#define NETSNMP_DS_SNMP_VERSION_3    3  
#define NETSNMP_DS_SSHDOMAIN_DIR_PERM      12
#define NETSNMP_DS_SSHDOMAIN_SOCK_GROUP    13
#define NETSNMP_DS_SSHDOMAIN_SOCK_PERM     11
#define NETSNMP_DS_SSHDOMAIN_SOCK_USER     12
#define NETSNMP_DS_TOKEN_ID       2
#define NETSNMP_RUNTIME_PROTOCOL_CHECK(pc_ver, pc_target) do {         \
        NETSNMP_RUNTIME_PROTOCOL_CHECK_V1V2(pc_ver, pc_target);            \
        NETSNMP_RUNTIME_PROTOCOL_CHECK_V3(pc_ver, pc_target);            \
    } while(0)
#define NETSNMP_RUNTIME_PROTOCOL_CHECK_V1V2(pc_ver, pc_target) do {    \
        if (NETSNMP_RUNTIME_PROTOCOL_SKIP_V1(pc_ver) ||                \
            NETSNMP_RUNTIME_PROTOCOL_SKIP_V2(pc_ver)) {                \
            DEBUGMSGTL(("snmp:protocol:disabled", "enforced\n"));      \
            goto pc_target;                                            \
        }                                                              \
    } while(0)
#define NETSNMP_RUNTIME_PROTOCOL_CHECK_V3(pc_ver, pc_target) do {      \
        if (NETSNMP_RUNTIME_PROTOCOL_SKIP_V3(pc_ver)) {                \
            DEBUGMSGTL(("snmp:protocol:disabled", "enforced\n"));      \
            goto pc_target;                                            \
        }                                                              \
    } while(0)
#define NETSNMP_RUNTIME_PROTOCOL_SKIP(pc_ver) \
    (NETSNMP_RUNTIME_PROTOCOL_SKIP_V1(pc_ver) ||        \
     NETSNMP_RUNTIME_PROTOCOL_SKIP_V2(pc_ver) ||        \
     NETSNMP_RUNTIME_PROTOCOL_SKIP_V3(pc_ver))
#define NETSNMP_RUNTIME_PROTOCOL_SKIP_V1(pc_ver)                        \
    ((pc_ver) == 0)
#define NETSNMP_RUNTIME_PROTOCOL_SKIP_V2(pc_ver)                        \
    ((pc_ver) == 1)
#define NETSNMP_RUNTIME_PROTOCOL_SKIP_V3(pc_ver) \
    ((pc_ver == SNMP_VERSION_3) &&                                   \
     netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,                     \
                            NETSNMP_DS_LIB_DISABLE_V3))
#define EITHER_CONFIG 2
#define NETSNMP_APPLICATION_CONFIG_TYPE "snmpapp"
#define NORMAL_CONFIG 0
#define PREMIB_CONFIG 1

#define STRINGMAX 1024
