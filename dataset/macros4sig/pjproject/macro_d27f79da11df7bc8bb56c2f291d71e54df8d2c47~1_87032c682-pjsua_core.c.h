






































#define ERR_MEDIA_CHANGING  " because another media operation is in progress"

#define PJSUA_LOCK_IS_LOCKED()	PJ_TRUE
#define PJSUA_TRY_LOCK()	PJ_SUCCESS


#  define pjsua_vid_win_reset(wid)
#   define PJSUA_ACC_MAX_PROXIES    8
#   define PJSUA_ACQUIRE_CALL_TIMEOUT 2000
#   define PJSUA_CALL_SEND_DTMF_DURATION_DEFAULT    160
#   define PJSUA_DEFAULT_AUDIO_FRAME_PTIME  20
    #define PJSUA_DEFAULT_SRTP_SECURE_SIGNALING 1
    #define PJSUA_DEFAULT_USE_SRTP  PJMEDIA_SRTP_DISABLED
#   define PJSUA_PUBLISH_EXPIRATION PJSIP_PUBC_EXPIRATION_NOT_SPECIFIED
#   define PJSUA_REG_AUTO_REG_REFRESH     1
#   define PJSUA_THIRD_PARTY_STREAM_HAS_GET_INFO    0
#   define PJSUA_THIRD_PARTY_STREAM_HAS_GET_STAT    0
#define PJSUA_UNKNOWN_DTMF_DURATION     ((unsigned)-1)

#define pjsua_schedule_timer(e,d) pjsua_schedule_timer_dbg(e,d,\
                                                           "__FILE__","__LINE__")
#define pjsua_schedule_timer2(cb,u,d) \
			pjsua_schedule_timer2_dbg(cb,u,d,"__FILE__","__LINE__")



#define PJSIP_RETURN_EXCEPTION() pjsip_exception_to_status(PJ_GET_EXCEPTION())


#   define PJSIP_ACCEPT_MULTIPLE_SDP_ANSWERS        PJ_TRUE
#   define PJSIP_HAS_TLS_TRANSPORT          PJ_HAS_SSL_SOCK
#   define PJSIP_INV_ACCEPT_UNKNOWN_BODY    PJ_FALSE
#   define PJSIP_REGISTER_CLIENT_DELAY_BEFORE_REFRESH  5
#   define PJSIP_RESOLVE_HOSTNAME_TO_GET_INTERFACE  PJ_FALSE
#   define PJSIP_TCP_KEEP_ALIVE_INTERVAL    90
#   define PJSIP_TCP_TRANSPORT_DONT_CREATE_LISTENER 0
#   define PJSIP_TLS_KEEP_ALIVE_INTERVAL    90
#   define PJSIP_TLS_TRANSPORT_DONT_CREATE_LISTENER 0
#   define PJSIP_TSX_UAS_CONTINUE_ON_TP_ERROR 1




#define PJSIP_DECL_HDR_MEMBER(hdr)   \
    	\
    PJ_DECL_LIST_MEMBER(hdr);	\
    		\
    pjsip_hdr_e	    type;	\
    		\
    pj_str_t	    name;	\
    	\
    pj_str_t	    sname;		\
    	\
    pjsip_hdr_vptr *vptr
#define PJSIP_IS_STATUS_IN_CLASS(status_code, code_class)    \
	    (status_code/100 == code_class/100)
#define PJSIP_MSG_CID_HDR(msg) \
	    ((pjsip_cid_hdr*)pjsip_msg_find_hdr(msg, PJSIP_H_CALL_ID, NULL))
#define PJSIP_MSG_CSEQ_HDR(msg) \
	    ((pjsip_cseq_hdr*)pjsip_msg_find_hdr(msg, PJSIP_H_CSEQ, NULL))
#define PJSIP_MSG_FROM_HDR(msg) \
	    ((pjsip_from_hdr*)pjsip_msg_find_hdr(msg, PJSIP_H_FROM, NULL))
#define PJSIP_MSG_TO_HDR(msg) \
	    ((pjsip_to_hdr*)pjsip_msg_find_hdr(msg, PJSIP_H_TO, NULL))

#define pjsip_accept_encoding_hdr_create pjsip_generic_string_hdr_create
#define pjsip_accept_lang_hdr_create pjsip_generic_string_hdr_create
#define pjsip_alert_info_hdr_create pjsip_generic_string_hdr_create
#define pjsip_auth_info_hdr_create pjsip_generic_string_hdr_create
#define pjsip_call_info_hdr_create pjsip_generic_string_hdr_create
#define pjsip_content_disposition_hdr_create pjsip_generic_string_hdr_create
#define pjsip_content_encoding_hdr_create pjsip_generic_string_hdr_create
#define pjsip_content_lang_hdr_create pjsip_generic_string_hdr_create
#define pjsip_date_hdr_create pjsip_generic_string_hdr_create
#define pjsip_err_info_hdr_create pjsip_generic_string_hdr_create
#define pjsip_in_reply_to_hdr_create pjsip_generic_string_hdr_create
#define pjsip_mime_version_hdr_create pjsip_generic_string_hdr_create
#define pjsip_organization_hdr_create pjsip_genric_string_hdr_create
#define pjsip_priority_hdr_create pjsip_generic_string_hdr_create
#define pjsip_reply_to_hdr_create pjsip_generic_string_hdr_create
#define pjsip_server_hdr_create pjsip_generic_string_hdr_create
#define pjsip_subject_hdr_create pjsip_generic_string_hdr_create
#define pjsip_timestamp_hdr_create pjsip_generic_string_hdr_create
#define pjsip_user_agent_hdr_create pjsip_generic_string_hdr_create
#define PJSIP_URI_SCHEME_IS_SIP(url)	\
    (pj_stricmp2(pjsip_uri_get_scheme(url), "sip")==0)
#define PJSIP_URI_SCHEME_IS_SIPS(url)	\
    (pj_stricmp2(pjsip_uri_get_scheme(url), "sips")==0)
#define PJSIP_URI_SCHEME_IS_TEL(url)	\
    (pj_stricmp2(pjsip_uri_get_scheme(url), "tel")==0)



#define PJSIP_TRANSPORT_IS_RELIABLE(tp)	    \
	    ((tp)->flag & PJSIP_TRANSPORT_RELIABLE)
#define PJSIP_TRANSPORT_IS_SECURE(tp)	    \
	    ((tp)->flag & PJSIP_TRANSPORT_SECURE)

#define PJSIP_MAX_CONTENT_LENGTH    PJ_MAXINT32
#define PJSIP_MIN_CONTENT_LENGTH    0


#define PJSIP_PRES_STATUS_MAX_INFO  8









#  define DEPRECATED_FOR_TICKET_1902      1

#define PJSIP_EAUTHINVALIDDIGEST (PJSIP_ERRNO_START_PJSIP+110)	
#define PJSIP_EBUFDESTROYED     (PJSIP_ERRNO_START_PJSIP + 63)	
#define PJSIP_EINVALIDAUTHSCHEME (PJSIP_ERRNO_START_PJSIP + 104)
#define PJSIP_EINVALIDMSG       (PJSIP_ERRNO_START_PJSIP + 20)	
#define PJSIP_EINVALIDSCHEME    (PJSIP_ERRNO_START_PJSIP + 40)	
#define PJSIP_EMISSINGHDR       (PJSIP_ERRNO_START_PJSIP + 50)	
#define PJSIP_EMISSINGREQURI    (PJSIP_ERRNO_START_PJSIP + 41)	
#define PJSIP_EPARTIALMSG       (PJSIP_ERRNO_START_PJSIP + 24)	
#define PJSIP_ERRNO_FROM_SIP_STATUS(code)   (PJSIP_ERRNO_START+code)
#define PJSIP_ERRNO_START       (PJ_ERRNO_START_USER)
#define PJSIP_ERRNO_START_PJSIP (PJSIP_ERRNO_START + 1000)
#define PJSIP_ERRNO_TO_SIP_STATUS(status)               \
         ((status>=PJSIP_ERRNO_FROM_SIP_STATUS(100) &&  \
           status<PJSIP_ERRNO_FROM_SIP_STATUS(800)) ?   \
          status-PJSIP_ERRNO_FROM_SIP_STATUS(0) : 599)
#define PJSIP_ERXOVERFLOW       (PJSIP_ERRNO_START_PJSIP + 62)	
#define PJSIP_ESESSIONTERMINATED (PJSIP_ERRNO_START_PJSIP+140)	
#define PJSIP_ETSXDESTROYED     (PJSIP_ERRNO_START_PJSIP + 70)	










#   define PJSIP_SSL_DEFAULT_PROTO  (PJ_SSL_SOCK_PROTO_TLS1 | \
				     PJ_SSL_SOCK_PROTO_TLS1_1 | \
				     PJ_SSL_SOCK_PROTO_TLS1_2)




#define PJSIP_ENDPT_LOG_ERROR(expr)   \
            pjsip_endpt_log_error expr
#define PJSIP_ENDPT_TRACE(tracing,expr) \
            do {                        \
                if ((tracing))          \
                    PJ_LOG(4,expr);     \
            } while (0)

#define pjsip_endpt_schedule_timer(ept,ent,d) \
			pjsip_endpt_schedule_timer_dbg(ept, ent, d, \
			                               "__FILE__", "__LINE__")
#define pjsip_endpt_schedule_timer_w_grp_lock(ept,ent,d,id,gl) \
		pjsip_endpt_schedule_timer_w_grp_lock_dbg(ept,ent,d,id,gl,\
							  "__FILE__", "__LINE__")

#define PJSIP_EVENT_INIT_RX_MSG(event,prdata)	\
        do { \
            (event).type = PJSIP_EVENT_RX_MSG;		\
            (event).body.rx_msg.rdata = prdata;		\
        } while (0)
#define PJSIP_EVENT_INIT_TIMER(event,pentry)            \
        do { \
            (event).type = PJSIP_EVENT_TIMER;           \
            (event).body.timer.entry = pentry;          \
        } while (0)
#define PJSIP_EVENT_INIT_TRANSPORT_ERROR(event,ptsx,ptdata)   \
        do { \
            (event).type = PJSIP_EVENT_TRANSPORT_ERROR; \
            (event).body.tx_error.tsx = ptsx;		\
            (event).body.tx_error.tdata = ptdata;	\
        } while (0)
#define PJSIP_EVENT_INIT_TSX_STATE(event,ptsx,ptype,pdata,prev)   \
        do { \
            (event).type = PJSIP_EVENT_TSX_STATE;           \
            (event).body.tsx_state.tsx = ptsx;		    \
            (event).body.tsx_state.type = ptype;            \
            (event).body.tsx_state.src.data = pdata;        \
	    (event).body.tsx_state.prev_state = prev;	    \
        } while (0)
#define PJSIP_EVENT_INIT_TX_MSG(event,ptdata)	\
        do { \
            (event).type = PJSIP_EVENT_TX_MSG;          \
            (event).body.tx_msg.tdata = ptdata;		\
        } while (0)
#define PJSIP_EVENT_INIT_USER(event,u1,u2,u3,u4)    \
        do { \
            (event).type = PJSIP_EVENT_USER;        \
            (event).body.user.user1 = (void*)u1;     \
            (event).body.user.user2 = (void*)u2;     \
            (event).body.user.user3 = (void*)u3;     \
            (event).body.user.user4 = (void*)u4;     \
        } while (0)


