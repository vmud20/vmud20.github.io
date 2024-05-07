










#define PJNATH_EICEFAILED           (PJNATH_ERRNO_START+82) 
#define PJNATH_EICEINCANDID         (PJNATH_ERRNO_START+87) 
#define PJNATH_EICEINCANDSDP        (PJNATH_ERRNO_START+91) 
#define PJNATH_EICEINCOMPID         (PJNATH_ERRNO_START+86) 
#define PJNATH_EICEINPROGRESS       (PJNATH_ERRNO_START+81) 
#define PJNATH_EICEINSRCADDR        (PJNATH_ERRNO_START+88) 
#define PJNATH_EICEMISMATCH         (PJNATH_ERRNO_START+83) 
#define PJNATH_EICEMISSINGSDP       (PJNATH_ERRNO_START+90) 
#define PJNATH_EICENOHOSTCAND       (PJNATH_ERRNO_START+92) 
#define PJNATH_EICENOMTIMEOUT       (PJNATH_ERRNO_START+93) 
#define PJNATH_EINSTUNMSG           (PJNATH_ERRNO_START+1)  
#define PJNATH_EINSTUNMSGLEN        (PJNATH_ERRNO_START+2)  
#define PJNATH_EINSTUNMSGTYPE       (PJNATH_ERRNO_START+3)  
#define PJNATH_EINVAF               (PJNATH_ERRNO_START+42) 
#define PJNATH_ENOICE               (PJNATH_ERRNO_START+80) 
#define PJNATH_ERRNO_START    (PJ_ERRNO_START_USER + PJ_ERRNO_SPACE_SIZE*4)
#define PJNATH_ESTUNDESTROYED       (PJNATH_ERRNO_START+60) 
#define PJNATH_ESTUNDUPATTR         (PJNATH_ERRNO_START+23) 
#define PJNATH_ESTUNFINGERPOS       (PJNATH_ERRNO_START+33) 
#define PJNATH_ESTUNFINGERPRINT     (PJNATH_ERRNO_START+30) 
#define PJNATH_ESTUNINATTRLEN       (PJNATH_ERRNO_START+22) 
#define PJNATH_ESTUNINSERVER        (PJNATH_ERRNO_START+50) 
#define PJNATH_ESTUNIPV6NOTSUPP     (PJNATH_ERRNO_START+41) 
#define PJNATH_ESTUNMSGINTPOS       (PJNATH_ERRNO_START+31) 
#define PJNATH_ESTUNNOMAPPEDADDR    (PJNATH_ERRNO_START+40) 
#define PJNATH_ESTUNTIMEDOUT        (PJNATH_ERRNO_START+4)  
#define PJNATH_ESTUNTOOMANYATTR     (PJNATH_ERRNO_START+21) 
#define PJNATH_ETURNINTP            (PJNATH_ERRNO_START+120) 
#define PJ_STATUS_FROM_STUN_CODE(code)  (PJNATH_ERRNO_START+code)

#define PJ_STUN_ERROR_RESPONSE_BIT      (0x0110)
#define PJ_STUN_GET_CH_NB(u32)      ((pj_uint16_t)(u32>>16))
#define PJ_STUN_GET_METHOD(msg_type)    ((msg_type) & 0xFEEF)
#define PJ_STUN_GET_RT_PROTO(u32)   (u32 >> 24)
#define PJ_STUN_INDICATION_BIT          (0x0010)
#define PJ_STUN_IS_ERROR_RESPONSE(msg_type) (((msg_type) & 0x0110) == 0x0110)
#define PJ_STUN_IS_INDICATION(msg_type) (((msg_type) & 0x0110) == 0x0010)
#define PJ_STUN_IS_REQUEST(msg_type)    (((msg_type) & 0x0110) == 0x0000)
#define PJ_STUN_IS_RESPONSE(msg_type) (((msg_type) & 0x0100) == 0x0100)
#define PJ_STUN_IS_SUCCESS_RESPONSE(msg_type) (((msg_type) & 0x0110) == 0x0100)
#define PJ_STUN_MAGIC                       0x2112A442
#define PJ_STUN_SET_CH_NB(chnum)    (((pj_uint32_t)chnum) << 16)
#define PJ_STUN_SET_RT_PROTO(proto)   (((pj_uint32_t)(proto)) << 24)
#define PJ_STUN_SUCCESS_RESPONSE_BIT    (0x0100)

#   define pj_stun_msg_dump(msg, buf, length, printed_len)  ""
#define PJ_TURN_INVALID_CHANNEL     0xFFFF

# define pjnath_perror(sender, title, status)
#   define ICE_CONTROLLED_AGENT_WAIT_NOMINATION_TIMEOUT 10000
#   define PJNATH_ERROR_LEVEL                       1
#   define PJNATH_ICE_PRIO_STD                      1
#   define PJNATH_MAKE_SW_NAME(a,b,c,d)     "pjnath-" #a "." #b "." #c d
#   define PJNATH_MAKE_SW_NAME2(a,b,c,d)    PJNATH_MAKE_SW_NAME(a,b,c,d)
#   define PJNATH_POOL_INC_ICE_SESS                 512
#   define PJNATH_POOL_INC_ICE_STRANS               512
#   define PJNATH_POOL_INC_NATCK                    512
#   define PJNATH_POOL_INC_STUN_SESS                1000
#   define PJNATH_POOL_INC_STUN_TDATA               1000
#   define PJNATH_POOL_INC_TURN_SESS                1000
#   define PJNATH_POOL_INC_TURN_SOCK                1000
#   define PJNATH_POOL_LEN_ICE_SESS                 512
#   define PJNATH_POOL_LEN_ICE_STRANS               1000
#   define PJNATH_POOL_LEN_NATCK                    512
#   define PJNATH_POOL_LEN_STUN_SESS                1000
#   define PJNATH_POOL_LEN_STUN_TDATA               1000
#   define PJNATH_POOL_LEN_TURN_SESS                1000
#   define PJNATH_POOL_LEN_TURN_SOCK                1000
#   define PJNATH_STUN_SOFTWARE_NAME        PJNATH_MAKE_SW_NAME2( \
                                                    PJ_VERSION_NUM_MAJOR, \
                                                    PJ_VERSION_NUM_MINOR, \
                                                    PJ_VERSION_NUM_REV, \
                                                    PJ_VERSION_NUM_EXTRA)
#   define PJ_ICE_CANCEL_ALL                        1
#       define PJ_ICE_CAND_TYPE_PREF_BITS           8
#   define PJ_ICE_COMP_BITS                         1
#   define PJ_ICE_LOCAL_PREF_BITS                   0
#   define PJ_ICE_MAX_CAND                          16
#   define PJ_ICE_MAX_CHECKS                        32
#define PJ_ICE_MAX_COMP                             (1<<PJ_ICE_COMP_BITS)
#   define PJ_ICE_MAX_STUN                          2
#   define PJ_ICE_MAX_TURN                          3
#   define PJ_ICE_NOMINATED_CHECK_DELAY             (4*PJ_STUN_RTO_VALUE)
#   define PJ_ICE_PWD_LEN                           24
#   define PJ_ICE_SESS_KEEP_ALIVE_MAX_RAND          5
#   define PJ_ICE_SESS_KEEP_ALIVE_MIN               20
#   define PJ_ICE_ST_MAX_CAND                       8
#   define PJ_ICE_ST_USE_TURN_PERMANENT_PERM        PJ_FALSE
#   define PJ_ICE_TA_VAL                            20
#   define PJ_ICE_UFRAG_LEN                         8
#   define PJ_STUN_KEEP_ALIVE_SEC                   15
#   define PJ_STUN_MAX_ATTR                         16
#   define PJ_STUN_MAX_PKT_LEN                      800
#   define PJ_STUN_MAX_TRANSMIT_COUNT               7
#   define PJ_STUN_OLD_STYLE_MI_FINGERPRINT         0
#define PJ_STUN_PORT                                3478
#   define PJ_STUN_RES_CACHE_DURATION               10000
#   define PJ_STUN_RTO_VALUE                        100
#   define PJ_STUN_SOCK_PKT_LEN                     2000
#   define PJ_STUN_STRING_ATTR_PAD_CHR              0
#   define PJ_STUN_TIMEOUT_VALUE                    (16 * PJ_STUN_RTO_VALUE)
#   define PJ_TRICKLE_ICE_END_OF_CAND_TIMEOUT       40
#   define PJ_TURN_CHANNEL_TIMEOUT                  600
#   define PJ_TURN_KEEP_ALIVE_SEC                   15
#   define PJ_TURN_MAX_DNS_SRV_CNT                  4
#   define PJ_TURN_MAX_PKT_LEN                      3000
#   define PJ_TURN_MAX_TCP_CONN_CNT                 8
#   define PJ_TURN_PERM_TIMEOUT                     300
#   define PJ_TURN_REFRESH_SEC_BEFORE               60
#   define PJ_UPNP_DEFAULT_SEARCH_TIME  5

