#include<netinet/ip.h>
#include<netinet/icmp6.h>




#include<net/if.h>



#include<netinet/ip6.h>


#include<netinet/ip_icmp.h>








#define CLEAR_QOS_FLOW_ID(__sESS) \
    do { \
        ogs_assert((__sESS)); \
        smf_qfi_pool_final(__sESS); \
        smf_qfi_pool_init(__sESS); \
    } while(0)
#define MAX_NUM_OF_DNS              2
#define MAX_NUM_OF_P_CSCF           16
#define OGS_LOG_DOMAIN __smf_log_domain

#define SMF_NF_INSTANCE_CLEAR(_cAUSE, _nFInstance) \
    do { \
        ogs_assert(_nFInstance); \
        if ((_nFInstance)->reference_count == 1) { \
            ogs_info("[%s] (%s) NF removed", (_nFInstance)->id, (_cAUSE)); \
            smf_nf_fsm_fini((_nFInstance)); \
        } else { \
             \
            ogs_info("[%s:%d] (%s) NF suspended", \
                    _nFInstance->id, _nFInstance->reference_count, (_cAUSE)); \
            OGS_FSM_TRAN(&_nFInstance->sm, smf_nf_state_de_registered); \
            ogs_fsm_dispatch(&_nFInstance->sm, NULL); \
        } \
        ogs_sbi_nf_instance_remove(_nFInstance); \
    } while(0)
#define SMF_NGAP_STATE_DELETE_TRIGGER_PCF_INITIATED             2
#define SMF_NGAP_STATE_DELETE_TRIGGER_UE_REQUESTED              1
#define SMF_NGAP_STATE_ERROR_INDICATION_RECEIVED_FROM_5G_AN     3
#define SMF_NGAP_STATE_NONE                                     0
#define SMF_SESS(pfcp_sess) ogs_container_of(pfcp_sess, smf_sess_t, pfcp)
#define SMF_SESS_CLEAR(__sESS) \
    do { \
        smf_ue_t *smf_ue = NULL; \
        ogs_assert(__sESS); \
        smf_ue = __sESS->smf_ue; \
        ogs_assert(smf_ue); \
        if (SMF_UE_IS_LAST_SESSION(smf_ue)) \
            smf_ue_remove(smf_ue); \
        else \
            smf_sess_remove(__sESS); \
    } while(0)
#define SMF_UE_IS_LAST_SESSION(__sMF) \
     ((__sMF) && (ogs_list_count(&(__sMF)->sess_list)) == 1)

#define smf_sm_debug(__pe) \
    ogs_debug("%s(): %s", __func__, smf_event_get_name(__pe))

