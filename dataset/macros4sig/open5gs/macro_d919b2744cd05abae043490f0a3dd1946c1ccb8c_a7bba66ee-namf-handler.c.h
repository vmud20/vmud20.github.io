






#define AMF_CREATE_SM_CONTEXT_NO_STATE              0
#define AMF_RELEASE_SM_CONTEXT_NG_CONTEXT_REMOVE    32
#define AMF_RELEASE_SM_CONTEXT_NO_STATE             31
#define AMF_RELEASE_SM_CONTEXT_REGISTRATION_ACCEPT  33
#define AMF_RELEASE_SM_CONTEXT_SERVICE_ACCEPT       34
#define AMF_REMOVE_S1_CONTEXT_BY_LO_CONNREFUSED     51
#define AMF_REMOVE_S1_CONTEXT_BY_RESET_ALL          52
#define AMF_REMOVE_S1_CONTEXT_BY_RESET_PARTIAL      53

#define AMF_UPDATE_SM_CONTEXT_ACTIVATED             11
#define AMF_UPDATE_SM_CONTEXT_DEACTIVATED           12
#define AMF_UPDATE_SM_CONTEXT_DUPLICATED_PDU_SESSION_ID 18
#define AMF_UPDATE_SM_CONTEXT_HANDOVER_CANCEL       23
#define AMF_UPDATE_SM_CONTEXT_HANDOVER_NOTIFY       22
#define AMF_UPDATE_SM_CONTEXT_HANDOVER_REQUIRED     20
#define AMF_UPDATE_SM_CONTEXT_HANDOVER_REQ_ACK      21
#define AMF_UPDATE_SM_CONTEXT_MODIFIED              15
#define AMF_UPDATE_SM_CONTEXT_N1_RELEASED           17
#define AMF_UPDATE_SM_CONTEXT_N2_RELEASED           16
#define AMF_UPDATE_SM_CONTEXT_PATH_SWITCH_REQUEST   19
#define AMF_UPDATE_SM_CONTEXT_REGISTRATION_REQUEST  13
#define AMF_UPDATE_SM_CONTEXT_SERVICE_REQUEST       14


#define AMF_NF_INSTANCE_CLEAR(_cAUSE, _nFInstance) \
    do { \
        ogs_assert(_nFInstance); \
        if ((_nFInstance)->reference_count == 1) { \
            ogs_info("[%s] (%s) NF removed", (_nFInstance)->id, (_cAUSE)); \
            amf_nf_fsm_fini((_nFInstance)); \
        } else { \
             \
            ogs_info("[%s:%d] (%s) NF suspended", \
                    _nFInstance->id, _nFInstance->reference_count, (_cAUSE)); \
            OGS_FSM_TRAN(&_nFInstance->sm, amf_nf_state_de_registered); \
            ogs_fsm_dispatch(&_nFInstance->sm, NULL); \
        } \
        ogs_sbi_nf_instance_remove(_nFInstance); \
    } while(0)
#define AMF_SESS_CLEAR_5GSM_MESSAGE(__sESS) \
    do { \
        if ((__sESS)->gsm_message.n1buf) \
            ogs_pkbuf_free((__sESS)->gsm_message.n1buf); \
        (__sESS)->gsm_message.n1buf = NULL; \
        if ((__sESS)->gsm_message.n2buf) \
            ogs_pkbuf_free((__sESS)->gsm_message.n2buf); \
        (__sESS)->gsm_message.n2buf = NULL; \
        (__sESS)->gsm_message.type = 0; \
    } while(0);
#define AMF_SESS_CLEAR_N2_TRANSFER(__sESS, __n2Type) \
    do { \
        if ((__sESS)->transfer.__n2Type) \
            ogs_pkbuf_free((__sESS)->transfer.__n2Type); \
        (__sESS)->transfer.__n2Type = NULL; \
    } while(0);
#define AMF_SESS_CLEAR_PAGING_INFO(__sESS) \
    do { \
        if ((__sESS)->paging.ongoing == true) { \
            ogs_assert((__sESS)->paging.location); \
            ogs_free((__sESS)->paging.location); \
            ((__sESS)->paging.location) = NULL; \
            if ((__sESS)->paging.n1n2_failure_txf_notif_uri) { \
                ogs_free((__sESS)->paging.n1n2_failure_txf_notif_uri); \
                ((__sESS)->paging.n1n2_failure_txf_notif_uri) = NULL; \
            } \
            ((__sESS)->paging.ongoing) = false; \
        } \
    } while(0);
#define AMF_SESS_STORE_5GSM_MESSAGE(__sESS, __tYPE, __n1Buf, __n2Buf) \
    do { \
        ogs_assert(__sESS); \
        ogs_assert((__sESS)->amf_ue); \
        if ((__sESS)->gsm_message.n1buf) { \
            ogs_warn("[%s:%d] N1 message duplicated. Overwritten", \
                    ((__sESS)->amf_ue)->supi, (__sESS)->psi); \
            ogs_pkbuf_free((__sESS)->gsm_message.n1buf); \
        } \
        (__sESS)->gsm_message.n1buf = __n1Buf; \
        ogs_assert((__sESS)->gsm_message.n1buf); \
        if ((__sESS)->gsm_message.n2buf) { \
            ogs_warn("[%s:%d] N2 message duplicated. Overwritten", \
                    ((__sESS)->amf_ue)->supi, (__sESS)->psi); \
            ogs_pkbuf_free((__sESS)->gsm_message.n2buf); \
        } \
        (__sESS)->gsm_message.n2buf = __n2Buf; \
        ogs_assert((__sESS)->gsm_message.n2buf); \
        (__sESS)->gsm_message.type = __tYPE; \
    } while(0);
#define AMF_SESS_STORE_N2_TRANSFER(__sESS, __n2Type, __n2Buf) \
    do { \
        ogs_assert(__sESS); \
        ogs_assert((__sESS)->amf_ue); \
        if ((__sESS)->transfer.__n2Type) { \
            ogs_warn("[%s:%d] N2 transfer message duplicated. Overwritten", \
                    ((__sESS)->amf_ue)->supi, (__sESS)->psi); \
            ogs_pkbuf_free((__sESS)->transfer.__n2Type); \
        } \
        (__sESS)->transfer.__n2Type = __n2Buf; \
        ogs_assert((__sESS)->transfer.__n2Type); \
    } while(0);
#define AMF_SESS_STORE_PAGING_INFO(__sESS, __lOCATION, __uRI) \
    do { \
        ogs_assert(__sESS); \
        ogs_assert(__lOCATION); \
        AMF_SESS_CLEAR_PAGING_INFO(__sESS) \
        (__sESS)->paging.ongoing = true; \
        ((__sESS)->paging.location) = ogs_strdup(__lOCATION); \
        ogs_assert((__sESS)->paging.location); \
        if (__uRI) { \
            ((__sESS)->paging.n1n2_failure_txf_notif_uri) = ogs_strdup(__uRI); \
            ogs_assert((__sESS)->paging.n1n2_failure_txf_notif_uri); \
        } \
    } while(0);
#define AMF_UE_CLEAR_5GSM_MESSAGE(__aMF) \
    do { \
        amf_sess_t *sess = NULL; \
        ogs_list_for_each(&((__aMF)->sess_list), sess) { \
            AMF_SESS_CLEAR_5GSM_MESSAGE(sess) \
        } \
    } while(0);
#define AMF_UE_CLEAR_N2_TRANSFER(__aMF, __n2Type) \
    do { \
        amf_sess_t *sess = NULL; \
        ogs_list_for_each(&((__aMF)->sess_list), sess) { \
            AMF_SESS_CLEAR_N2_TRANSFER(sess, __n2Type) \
        } \
    } while(0);
#define AMF_UE_CLEAR_PAGING_INFO(__aMF) \
    do { \
        amf_sess_t *sess = NULL; \
        ogs_list_for_each(&((__aMF)->sess_list), sess) { \
            AMF_SESS_CLEAR_PAGING_INFO(sess); \
        } \
    } while(0);
#define AMF_UE_HAVE_SUCI(__aMF) \
    ((__aMF) && ((__aMF)->suci))
#define CLEAR_AMF_UE_ALL_TIMERS(__aMF) \
    do { \
        CLEAR_AMF_UE_TIMER((__aMF)->t3513); \
        CLEAR_AMF_UE_TIMER((__aMF)->t3522); \
        CLEAR_AMF_UE_TIMER((__aMF)->t3550); \
        CLEAR_AMF_UE_TIMER((__aMF)->t3555); \
        CLEAR_AMF_UE_TIMER((__aMF)->t3560); \
        CLEAR_AMF_UE_TIMER((__aMF)->t3570); \
    } while(0);
#define CLEAR_AMF_UE_TIMER(__aMF_UE_TIMER) \
    do { \
        ogs_timer_stop((__aMF_UE_TIMER).timer); \
        if ((__aMF_UE_TIMER).pkbuf) { \
            ogs_pkbuf_free((__aMF_UE_TIMER).pkbuf); \
            (__aMF_UE_TIMER).pkbuf = NULL; \
        } \
        (__aMF_UE_TIMER).retry_count = 0; \
    } while(0);
#define CLEAR_SM_CONTEXT_REF(__sESS) \
    do { \
        ogs_assert(__sESS); \
        ogs_assert((__sESS)->sm_context_ref); \
        ogs_free((__sESS)->sm_context_ref); \
        (__sESS)->sm_context_ref = NULL; \
    } while(0);
#define CM_CONNECTED(__aMF) \
    ((__aMF) && ((__aMF)->ran_ue != NULL) && ran_ue_cycle((__aMF)->ran_ue))
#define CM_IDLE(__aMF) \
    ((__aMF) && \
     (((__aMF)->ran_ue == NULL) || (ran_ue_cycle((__aMF)->ran_ue) == NULL)))
#define DOWNLINK_SIGNALLING_PENDING(__aMF) \
    (amf_downlink_signalling_pending(__aMF) == true)
#define HANDOVER_REQUEST_TRANSFER_NEEDED(__aMF) \
    (amf_handover_request_transfer_needed(__aMF) == true)
#define INVALID_UE_NGAP_ID      0xffffffff 
#define MAX_NUM_OF_SERVED_GUAMI     8
#define NGAP_UE_CTX_REL_INVALID_ACTION                      0
#define NGAP_UE_CTX_REL_NG_CONTEXT_REMOVE                   1
#define NGAP_UE_CTX_REL_NG_HANDOVER_CANCEL                  5
#define NGAP_UE_CTX_REL_NG_HANDOVER_COMPLETE                4
#define NGAP_UE_CTX_REL_NG_HANDOVER_FAILURE                 6
#define NGAP_UE_CTX_REL_NG_REMOVE_AND_UNLINK                2
#define NGAP_UE_CTX_REL_UE_CONTEXT_REMOVE                   3
#define OGS_LOG_DOMAIN __amf_log_domain
#define PAGING_ONGOING(__aMF) \
    (amf_paging_ongoing(__aMF) == true)
#define PDU_RES_SETUP_REQ_TRANSFER_NEEDED(__aMF) \
    (amf_pdu_res_setup_req_transfer_needed(__aMF) == true)
#define SECURITY_CONTEXT_IS_VALID(__aMF) \
    ((__aMF) && \
    ((__aMF)->security_context_available == 1) && \
     ((__aMF)->mac_failed == 0) && \
     ((__aMF)->nas.ue.ksi != OGS_NAS_KSI_NO_KEY_IS_AVAILABLE))
#define SESSION_CONTEXT_IN_SMF(__sESS)  \
    ((__sESS) && (__sESS)->sm_context_ref)
#define SESSION_SYNC_DONE(__aMF, __sTATE) \
    (amf_sess_xact_state_count(__aMF, __sTATE) == 0)


#define amf_sm_debug(__pe) \
    ogs_debug("%s(): %s", __func__, amf_event_get_name(__pe))






#define NGAP_NON_UE_SIGNALLING   0

#define ngap_event_push  amf_sctp_event_push


#define AMF_NAS_BACKOFF_TIME  6    



