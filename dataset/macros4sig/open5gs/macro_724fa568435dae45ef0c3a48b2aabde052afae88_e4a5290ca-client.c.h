#include<netinet/in.h>





#include<arpa/inet.h>










#include<stdio.h>
#include<stdint.h>

#include<sys/time.h>


#include<string.h>

#include<stdlib.h>
#include<errno.h>
#include<stddef.h>


#include<sys/socket.h>






#include<time.h>
























#include<endian.h>

#include<stdbool.h>









#include<pthread.h>







#define OGS_LOG_DOMAIN __ogs_sbi_domain



#define ogs_sbi_send_http_status_no_content(__sTREAM) \
        ogs_sbi_send_response(__sTREAM, OGS_SBI_HTTP_STATUS_NO_CONTENT)



#define ogs_sbi_sm_debug(__e) \
    ogs_debug("%s(): %s", __func__, ogs_event_get_name(__e))
#define NF_INSTANCE_ID_IS_OTHERS(_iD) \
    (_iD) && ogs_sbi_self()->nf_instance && \
        strcmp((_iD), ogs_sbi_self()->nf_instance->id) != 0
#define NF_INSTANCE_ID_IS_SELF(_iD) \
    (_iD) && ogs_sbi_self()->nf_instance && \
        strcmp((_iD), ogs_sbi_self()->nf_instance->id) == 0
#define NF_INSTANCE_TYPE_IS_NRF(__nFInstance) \
    ((__nFInstance->nf_type) == OpenAPI_nf_type_NRF)
#define OGS_MAX_NUM_OF_NF_INFO 8

#define OGS_SBI_DEFAULT_CAPACITY 100
#define OGS_SBI_DEFAULT_LOAD 0
#define OGS_SBI_DEFAULT_PRIORITY 0
#define OGS_SBI_MAX_NUM_OF_IP_ADDRESS 8
#define OGS_SBI_MAX_NUM_OF_NF_TYPE 128
#define OGS_SBI_MAX_NUM_OF_SERVICE_VERSION 8
#define OGS_SBI_SETUP_NF_INSTANCE(__cTX, __nFInstance) \
    do { \
        ogs_assert(__nFInstance); \
        \
        if ((__cTX).nf_instance) { \
            ogs_warn("NF Instance updated [%s]", (__nFInstance)->id); \
            ogs_sbi_nf_instance_remove((__cTX).nf_instance); \
        } \
        \
        OGS_OBJECT_REF(__nFInstance); \
        ((__cTX).nf_instance) = (__nFInstance); \
    } while(0)

#define OGS_SBI_SETUP_CLIENT(__cTX, __pClient) \
    do { \
        ogs_assert((__cTX)); \
        ogs_assert((__pClient)); \
        \
        if ((__cTX)->client) { \
            ogs_sbi_client_t *client = NULL; \
            ogs_sockaddr_t *addr = NULL; \
            char buf[OGS_ADDRSTRLEN]; \
            \
            client = ((__cTX)->client); \
            ogs_assert(client); \
            addr = client->node.addr; \
            ogs_assert(addr); \
            ogs_warn("NF EndPoint updated [%s:%d]", \
                        OGS_ADDR(addr, buf), OGS_PORT(addr)); \
            ogs_sbi_client_remove(client); \
        } \
        \
        OGS_OBJECT_REF(__pClient); \
        ((__cTX)->client) = (__pClient); \
    } while(0)

#define OGS_SBI_ACCEPT                              "Accept"
#define OGS_SBI_ACCEPT_ENCODING                     "Accept-Encoding"
#define OGS_SBI_API_V1                              "v1"
#define OGS_SBI_API_V1_0_0                          "1.0.0"
#define OGS_SBI_API_V2                              "v2"
#define OGS_SBI_API_V2_0_0                          "2.0.0"
#define OGS_SBI_APPLICATION_3GPPHAL_TYPE            "3gppHal+json"
#define OGS_SBI_APPLICATION_5GNAS_TYPE              "vnd.3gpp.5gnas"
#define OGS_SBI_APPLICATION_JSON_TYPE               "json"
#define OGS_SBI_APPLICATION_NGAP_TYPE               "vnd.3gpp.ngap"
#define OGS_SBI_APPLICATION_PATCH_TYPE              "json-patch+json"
#define OGS_SBI_APPLICATION_PROBLEM_TYPE            "problem+json"
#define OGS_SBI_APPLICATION_TYPE                    "application"
#define OGS_SBI_CONTENT_3GPPHAL_TYPE                \
    OGS_SBI_APPLICATION_TYPE "/" OGS_SBI_APPLICATION_3GPPHAL_TYPE
#define OGS_SBI_CONTENT_5GNAS_SM_ID                 "5gnas-sm"
#define OGS_SBI_CONTENT_5GNAS_TYPE                  \
    OGS_SBI_APPLICATION_TYPE "/" OGS_SBI_APPLICATION_5GNAS_TYPE
#define OGS_SBI_CONTENT_ID                          "Content-Id"
#define OGS_SBI_CONTENT_JSON_TYPE                   \
    OGS_SBI_APPLICATION_TYPE "/" OGS_SBI_APPLICATION_JSON_TYPE
#define OGS_SBI_CONTENT_MULTIPART_TYPE              \
    OGS_SBI_MULTIPART_TYPE "/" OGS_SBI_MULTIPART_RELATED_TYPE
#define OGS_SBI_CONTENT_NGAP_SM_ID                  "ngap-sm"
#define OGS_SBI_CONTENT_NGAP_TYPE                   \
    OGS_SBI_APPLICATION_TYPE "/" OGS_SBI_APPLICATION_NGAP_TYPE
#define OGS_SBI_CONTENT_PATCH_TYPE                  \
    OGS_SBI_APPLICATION_TYPE "/" OGS_SBI_APPLICATION_PATCH_TYPE
#define OGS_SBI_CONTENT_PROBLEM_TYPE                \
    OGS_SBI_APPLICATION_TYPE "/" OGS_SBI_APPLICATION_PROBLEM_TYPE
#define OGS_SBI_CONTENT_TYPE                        "Content-Type"
#define OGS_SBI_CUSTOM_3GPP_COMMON                  "3gpp-Sbi-"
#define OGS_SBI_CUSTOM_ACCESS_SCOPE      \
    OGS_SBI_CUSTOM_3GPP_COMMON "Access-Scope"
#define OGS_SBI_CUSTOM_ACCESS_TOKEN      \
    OGS_SBI_CUSTOM_3GPP_COMMON "Access-Token"
#define OGS_SBI_CUSTOM_BINDING           \
    OGS_SBI_CUSTOM_3GPP_COMMON "Binding"
#define OGS_SBI_CUSTOM_CALLBACK          \
    OGS_SBI_CUSTOM_3GPP_COMMON "Callback"
#define OGS_SBI_CUSTOM_CLIENT_CREDENTIALS   \
    OGS_SBI_CUSTOM_3GPP_COMMON "Client-Credentials"
#define OGS_SBI_CUSTOM_DISCOVERY_COMMON  \
    OGS_SBI_CUSTOM_3GPP_COMMON "Discovery-"
#define OGS_SBI_CUSTOM_DISCOVERY_REQUESTER_NF_INSTANCE_ID \
    OGS_SBI_CUSTOM_DISCOVERY_COMMON OGS_SBI_PARAM_REQUESTER_NF_INSTANCE_ID
#define OGS_SBI_CUSTOM_DISCOVERY_REQUESTER_NF_TYPE  \
    OGS_SBI_CUSTOM_DISCOVERY_COMMON OGS_SBI_PARAM_REQUESTER_NF_TYPE
#define OGS_SBI_CUSTOM_DISCOVERY_SERVICE_NAMES  \
    OGS_SBI_CUSTOM_DISCOVERY_COMMON OGS_SBI_PARAM_SERVICE_NAMES
#define OGS_SBI_CUSTOM_DISCOVERY_TARGET_NF_INSTANCE_ID \
    OGS_SBI_CUSTOM_DISCOVERY_COMMON OGS_SBI_PARAM_TARGET_NF_INSTANCE_ID
#define OGS_SBI_CUSTOM_DISCOVERY_TARGET_NF_TYPE     \
    OGS_SBI_CUSTOM_DISCOVERY_COMMON OGS_SBI_PARAM_TARGET_NF_TYPE
#define OGS_SBI_CUSTOM_MESSAGE_PRIORITY  \
    OGS_SBI_CUSTOM_3GPP_COMMON "Message-Priority"
#define OGS_SBI_CUSTOM_NRF_URI           \
    OGS_SBI_CUSTOM_3GPP_COMMON "Nrf-Uri"
#define OGS_SBI_CUSTOM_OCI               \
    OGS_SBI_CUSTOM_3GPP_COMMON "Oci"
#define OGS_SBI_CUSTOM_PRODUCER_ID       \
    OGS_SBI_CUSTOM_3GPP_COMMON "Producer-Id"
#define OGS_SBI_CUSTOM_ROUTING_BINDING   \
    OGS_SBI_CUSTOM_3GPP_COMMON "Routing-Binding"
#define OGS_SBI_CUSTOM_TARGET_APIROOT    \
    OGS_SBI_CUSTOM_3GPP_COMMON "Target-apiRoot"
#define OGS_SBI_CUSTOM_TARGET_NF_ID      \
    OGS_SBI_CUSTOM_3GPP_COMMON "Target-Nf-Id"
#define OGS_SBI_EXPECT                              "Expect"
#define OGS_SBI_FEATURES_IS_SET(__fEATURES, __n) \
    (__fEATURES & (1 << ((__n)-1)))
#define OGS_SBI_FEATURES_SET(__fEATURES, __n) \
    __fEATURES |= (1 << ((__n)-1))
#define OGS_SBI_HTTPS_PORT                          443
#define OGS_SBI_HTTPS_SCHEME                        "https"
#define OGS_SBI_HTTP_METHOD_DELETE                  "DELETE"
#define OGS_SBI_HTTP_METHOD_GET                     "GET"
#define OGS_SBI_HTTP_METHOD_OPTIONS                 "OPTIONS"
#define OGS_SBI_HTTP_METHOD_PATCH                   "PATCH"
#define OGS_SBI_HTTP_METHOD_POST                    "POST"
#define OGS_SBI_HTTP_METHOD_PUT                     "PUT"
#define OGS_SBI_HTTP_PORT                           80
#define OGS_SBI_HTTP_SCHEME                         "http"
#define OGS_SBI_HTTP_STATUS_ACCEPTED                202 
#define OGS_SBI_HTTP_STATUS_BAD_REQUEST             400  
#define OGS_SBI_HTTP_STATUS_CONFLICT                409 
#define OGS_SBI_HTTP_STATUS_CREATED                 201 
#define OGS_SBI_HTTP_STATUS_FORBIDDEN               403 
#define OGS_SBI_HTTP_STATUS_GATEWAY_TIMEOUT         504 
#define OGS_SBI_HTTP_STATUS_GONE                    410 
#define OGS_SBI_HTTP_STATUS_INTERNAL_SERVER_ERROR   500 
#define OGS_SBI_HTTP_STATUS_LENGTH_REQUIRED         411 
#define OGS_SBI_HTTP_STATUS_MEHTOD_NOT_ALLOWED      405 
#define OGS_SBI_HTTP_STATUS_NOT_ACCEPTABLE          406 
#define OGS_SBI_HTTP_STATUS_NOT_FOUND               404 
#define OGS_SBI_HTTP_STATUS_NOT_IMPLEMENTED         501 
#define OGS_SBI_HTTP_STATUS_NO_CONTENT              204 
#define OGS_SBI_HTTP_STATUS_OK                      200
#define OGS_SBI_HTTP_STATUS_PAYLOAD_TOO_LARGE       413 
#define OGS_SBI_HTTP_STATUS_PERMANENT_REDIRECT      308 
#define OGS_SBI_HTTP_STATUS_PRECONDITION_FAILED     412 
#define OGS_SBI_HTTP_STATUS_REQUEST_TIMEOUT         408 
#define OGS_SBI_HTTP_STATUS_SEE_OTHER               303 
#define OGS_SBI_HTTP_STATUS_SERVICE_UNAVAILABLE     503 
#define OGS_SBI_HTTP_STATUS_TEMPORARY_REDIRECT      307 
#define OGS_SBI_HTTP_STATUS_TOO_MANY_REQUESTS       429 
#define OGS_SBI_HTTP_STATUS_UNAUTHORIZED            401 
#define OGS_SBI_HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE  415 
#define OGS_SBI_HTTP_STATUS_URI_TOO_LONG            414 
#define OGS_SBI_LOCATION                            "Location"
#define OGS_SBI_MAX_NUM_OF_PART 8
#define OGS_SBI_MAX_NUM_OF_RESOURCE_COMPONENT 8

#define OGS_SBI_MULTIPART_RELATED_TYPE              "related"
#define OGS_SBI_MULTIPART_TYPE                      "multipart"
#define OGS_SBI_NBSF_MANAGEMENT_BINDING_UPDATE 2
#define OGS_SBI_NBSF_MANAGEMENT_ES3XX 4
#define OGS_SBI_NBSF_MANAGEMENT_EXTENDED_SAME_PCF 5
#define OGS_SBI_NBSF_MANAGEMENT_MULTI_UE_ADDR 1
#define OGS_SBI_NBSF_MANAGEMENT_SAME_PCF 3
#define OGS_SBI_NNRF_NFM_EMPTY_OBJECTS_NRF_INFO 2
#define OGS_SBI_NNRF_NFM_SERVICE_MAP 1
#define OGS_SBI_NPCF_AM_POLICY_CONTROL_DNN_REPLACEMENT_CONTROL 4
#define OGS_SBI_NPCF_AM_POLICY_CONTROL_MULTIPLE_ACCESS_TYPES 5
#define OGS_SBI_NPCF_AM_POLICY_CONTROL_PENDING_TRANSACTION 2
#define OGS_SBI_NPCF_AM_POLICY_CONTROL_SLICE_SUPPORT 1
#define OGS_SBI_NPCF_AM_POLICY_CONTROL_UE_AMBR_AUTHORIZATION 3
#define OGS_SBI_NPCF_AM_POLICY_CONTROL_WIRELINE_WIRELESS_CONVERGE 6
#define OGS_SBI_NPCF_POLICYAUTHORIZATION_ATSSS 23
#define OGS_SBI_NPCF_POLICYAUTHORIZATION_AUTHORIZATION_WITH_REQUIRED_QOS 17
#define OGS_SBI_NPCF_POLICYAUTHORIZATION_CHEM 20
#define OGS_SBI_NPCF_POLICYAUTHORIZATION_DISABLE_UE_NOTIFICATION 27
#define OGS_SBI_NPCF_POLICYAUTHORIZATION_ENHANCED_SUBSCRIPTION_TO_NOTIFICATION 15
#define OGS_SBI_NPCF_POLICYAUTHORIZATION_EPS_FALLBACK_REPORT 22
#define OGS_SBI_NPCF_POLICYAUTHORIZATION_ES3XX 26
#define OGS_SBI_NPCF_POLICYAUTHORIZATION_FLUS 21
#define OGS_SBI_NPCF_POLICYAUTHORIZATION_IMS_SBI 5
#define OGS_SBI_NPCF_POLICYAUTHORIZATION_INFLUENCE_ON_TRAFFIC_ROUTING 1
#define OGS_SBI_NPCF_POLICYAUTHORIZATION_MAC_ADDRESS_RANGE 13
#define OGS_SBI_NPCF_POLICYAUTHORIZATION_MCPTT 9
#define OGS_SBI_NPCF_POLICYAUTHORIZATION_MCPTT_PREEMPTION 12
#define OGS_SBI_NPCF_POLICYAUTHORIZATION_MCVIDEO 10
#define OGS_SBI_NPCF_POLICYAUTHORIZATION_MEDIA_COMPONENT_VERSIONING 3
#define OGS_SBI_NPCF_POLICYAUTHORIZATION_NETLOC 6
#define OGS_SBI_NPCF_POLICYAUTHORIZATION_PATCH_CORRECTION 28
#define OGS_SBI_NPCF_POLICYAUTHORIZATION_PCSCF_RESTORATION_ENHANCEMENT 19
#define OGS_SBI_NPCF_POLICYAUTHORIZATION_PRIORITY_SHARING 11
#define OGS_SBI_NPCF_POLICYAUTHORIZATION_PROV_AF_SIGNAL_FLOW 7
#define OGS_SBI_NPCF_POLICYAUTHORIZATION_QOS_HINT 24
#define OGS_SBI_NPCF_POLICYAUTHORIZATION_QOS_MONITORING 16
#define OGS_SBI_NPCF_POLICYAUTHORIZATION_RAN_NAS_CAUSE 14
#define OGS_SBI_NPCF_POLICYAUTHORIZATION_REALLOCATION_OF_CREDIT 25
#define OGS_SBI_NPCF_POLICYAUTHORIZATION_RESOURCE_SHARING 8
#define OGS_SBI_NPCF_POLICYAUTHORIZATION_SPONSORED_CONNECTIVITY 2
#define OGS_SBI_NPCF_POLICYAUTHORIZATION_TIME_SENSITIVE_NETWORKING 18
#define OGS_SBI_NPCF_POLICYAUTHORIZATION_URLLC 4
#define OGS_SBI_NPCF_SMPOLICYCONTROL_3GPP_PS_DATA_OFF 3
#define OGS_SBI_NPCF_SMPOLICYCONTROL_ACCESS_TYPE_CONDITION 15
#define OGS_SBI_NPCF_SMPOLICYCONTROL_ADC 4
#define OGS_SBI_NPCF_SMPOLICYCONTROL_ADC_MULTI_REDIRECTION 30
#define OGS_SBI_NPCF_SMPOLICYCONTROL_AF_CHARGING_IDENTIFIER 18
#define OGS_SBI_NPCF_SMPOLICYCONTROL_ATSSS 19
#define OGS_SBI_NPCF_SMPOLICYCONTROL_AUTHORIZATION_WITH_REQUIRED_QOS 25
#define OGS_SBI_NPCF_SMPOLICYCONTROL_DDN_EVENT_POLICY_CONTROL 37
#define OGS_SBI_NPCF_SMPOLICYCONTROL_DNN_SELECTION_MODE 34
#define OGS_SBI_NPCF_SMPOLICYCONTROL_DN_AUTHORIZATION 27
#define OGS_SBI_NPCF_SMPOLICYCONTROL_EMDBV 33
#define OGS_SBI_NPCF_SMPOLICYCONTROL_ENHANCED_BACKGROUND_DATA_TRANSFER 26
#define OGS_SBI_NPCF_SMPOLICYCONTROL_EPS_FALLBACK_REPORT 35
#define OGS_SBI_NPCF_SMPOLICYCONTROL_MAC_ADDRESS_RANGE 22
#define OGS_SBI_NPCF_SMPOLICYCONTROL_MULTI_IPV6_ADDR_PREFIX 16
#define OGS_SBI_NPCF_SMPOLICYCONTROL_NET_LOC 6
#define OGS_SBI_NPCF_SMPOLICYCONTROL_PCSCF_RESTORATION_ENHANCEMENT 9
#define OGS_SBI_NPCF_SMPOLICYCONTROL_PDU_SESSION_REL_CAUSE 28
#define OGS_SBI_NPCF_SMPOLICYCONTROL_PENDING_TRANSACTION 20
#define OGS_SBI_NPCF_SMPOLICYCONTROL_POLICY_DECISION_ERROR_HANDLING 36
#define OGS_SBI_NPCF_SMPOLICYCONTROL_POLICY_UPDATE_WHEN_UE_SUSPENDS 14
#define OGS_SBI_NPCF_SMPOLICYCONTROL_PRA 10
#define OGS_SBI_NPCF_SMPOLICYCONTROL_PROV_AF_SIGNAL_FLOW 8
#define OGS_SBI_NPCF_SMPOLICYCONTROL_QOS_MONITORING 24
#define OGS_SBI_NPCF_SMPOLICYCONTROL_RAN_NAS_CAUSE 7
#define OGS_SBI_NPCF_SMPOLICYCONTROL_RAN_SUPPORT_INFO 13
#define OGS_SBI_NPCF_SMPOLICYCONTROL_REALLOCATION_OF_CREDIT 38
#define OGS_SBI_NPCF_SMPOLICYCONTROL_RESP_BASED_SESSION_REL 31
#define OGS_SBI_NPCF_SMPOLICYCONTROL_RES_SHARE 2
#define OGS_SBI_NPCF_SMPOLICYCONTROL_RULE_VERSIONING 11
#define OGS_SBI_NPCF_SMPOLICYCONTROL_SAME_PCF 29
#define OGS_SBI_NPCF_SMPOLICYCONTROL_SESSION_RULE_ERROR_HANDLING 17
#define OGS_SBI_NPCF_SMPOLICYCONTROL_SPONSORED_CONNECTIVITY 12
#define OGS_SBI_NPCF_SMPOLICYCONTROL_TIME_SENSITIVE_NETWORKING 32
#define OGS_SBI_NPCF_SMPOLICYCONTROL_TSC 1
#define OGS_SBI_NPCF_SMPOLICYCONTROL_UMC 5
#define OGS_SBI_NPCF_SMPOLICYCONTROL_URLLC 21
#define OGS_SBI_NPCF_SMPOLICYCONTROL_WWC 23
#define OGS_SBI_PARAM_DNN                           "dnn"
#define OGS_SBI_PARAM_IPV4ADDR                      "ipv4Addr"
#define OGS_SBI_PARAM_IPV6PREFIX                    "ipv6Prefix"
#define OGS_SBI_PARAM_LIMIT                         "limit"
#define OGS_SBI_PARAM_NF_ID                         "nf-id"
#define OGS_SBI_PARAM_NF_TYPE                       "nf-type"
#define OGS_SBI_PARAM_PLMN_ID                       "plmn-id"
#define OGS_SBI_PARAM_REQUESTER_NF_INSTANCE_ID      "requester-nf-instance-id"
#define OGS_SBI_PARAM_REQUESTER_NF_TYPE             "requester-nf-type"
#define OGS_SBI_PARAM_SERVICE_NAMES                 "service-names"
#define OGS_SBI_PARAM_SINGLE_NSSAI                  "single-nssai"
#define OGS_SBI_PARAM_SLICE_INFO_REQUEST_FOR_PDU_SESSION \
        "slice-info-request-for-pdu-session"
#define OGS_SBI_PARAM_SNSSAI                        "snssai"
#define OGS_SBI_PARAM_TARGET_NF_INSTANCE_ID         "target-nf-instance-id"
#define OGS_SBI_PARAM_TARGET_NF_TYPE                "target-nf-type"
#define OGS_SBI_RESOURCE_NAME_5G_AKA                "5g-aka"
#define OGS_SBI_RESOURCE_NAME_5G_AKA_CONFIRMATION   "5g-aka-confirmation"
#define OGS_SBI_RESOURCE_NAME_AMF_3GPP_ACCESS       "amf-3gpp-access"
#define OGS_SBI_RESOURCE_NAME_AM_DATA               "am-data"
#define OGS_SBI_RESOURCE_NAME_AM_POLICY_NOTIFY      "am-policy-notify"
#define OGS_SBI_RESOURCE_NAME_APP_SESSIONS          "app-sessions"
#define OGS_SBI_RESOURCE_NAME_AUTHENTICATION_DATA   "authentication-data"
#define OGS_SBI_RESOURCE_NAME_AUTHENTICATION_STATUS "authentication-status"
#define OGS_SBI_RESOURCE_NAME_AUTHENTICATION_SUBSCRIPTION \
                                            "authentication-subscription"
#define OGS_SBI_RESOURCE_NAME_AUTH_EVENTS           "auth-events"
#define OGS_SBI_RESOURCE_NAME_CONTEXT_DATA          "context-data"
#define OGS_SBI_RESOURCE_NAME_DELETE                "delete"
#define OGS_SBI_RESOURCE_NAME_DEREG_NOTIFY          "dereg-notify"
#define OGS_SBI_RESOURCE_NAME_EAP_SESSION           "eap-session"
#define OGS_SBI_RESOURCE_NAME_GENERATE_AUTH_DATA    "generate-auth-data"
#define OGS_SBI_RESOURCE_NAME_MODIFY                "modify"
#define OGS_SBI_RESOURCE_NAME_N1_N2_FAILURE_NOTIFY  "n1-n2-failure-notify"
#define OGS_SBI_RESOURCE_NAME_N1_N2_MESSAGES        "n1-n2-messages"
#define OGS_SBI_RESOURCE_NAME_NETWORK_SLICE_INFORMATION \
                                                    "network-slice-information"
#define OGS_SBI_RESOURCE_NAME_NF_INSTANCES          "nf-instances"
#define OGS_SBI_RESOURCE_NAME_NF_STATUS_NOTIFY      "nf-status-notify"
#define OGS_SBI_RESOURCE_NAME_NOTIFY                "notify"
#define OGS_SBI_RESOURCE_NAME_PCF_BINDINGS          "pcfBindings"
#define OGS_SBI_RESOURCE_NAME_POLICIES              "policies"
#define OGS_SBI_RESOURCE_NAME_POLICY_DATA           "policy-data"
#define OGS_SBI_RESOURCE_NAME_PROVISIONED_DATA      "provisioned-data"
#define OGS_SBI_RESOURCE_NAME_REGISTRATIONS         "registrations"
#define OGS_SBI_RESOURCE_NAME_RELEASE               "release"
#define OGS_SBI_RESOURCE_NAME_SECURITY_INFORMATION  "security-information"
#define OGS_SBI_RESOURCE_NAME_SMF_SELECTION_SUBSCRIPTION_DATA \
                                            "smf-selection-subscription-data"
#define OGS_SBI_RESOURCE_NAME_SMF_SELECT_DATA       "smf-select-data"
#define OGS_SBI_RESOURCE_NAME_SM_CONTEXTS           "sm-contexts"
#define OGS_SBI_RESOURCE_NAME_SM_CONTEXT_STATUS     "sm-context-status"
#define OGS_SBI_RESOURCE_NAME_SM_DATA               "sm-data"
#define OGS_SBI_RESOURCE_NAME_SM_POLICIES           "sm-policies"
#define OGS_SBI_RESOURCE_NAME_SM_POLICY_NOTIFY      "sm-policy-notify"
#define OGS_SBI_RESOURCE_NAME_SUBSCRIPTIONS         "subscriptions"
#define OGS_SBI_RESOURCE_NAME_SUBSCRIPTION_DATA     "subscription-data"
#define OGS_SBI_RESOURCE_NAME_TERMINATE             "terminate"
#define OGS_SBI_RESOURCE_NAME_UES                   "ues"
#define OGS_SBI_RESOURCE_NAME_UE_AUTHENTICATIONS    "ue-authentications"
#define OGS_SBI_RESOURCE_NAME_UE_CONTEXTS           "ue-contexts"
#define OGS_SBI_RESOURCE_NAME_UE_CONTEXT_IN_SMF_DATA "ue-context-in-smf-data"
#define OGS_SBI_RESOURCE_NAME_UPDATE                "update"
#define ogs_sbi_header_get(ht, key) \
    ogs_hash_get(ht, key, strlen(key))
#define ogs_sbi_header_set(ht, key, val) \
    ogs_hash_set(ht, ogs_strdup(key), strlen(key), ogs_strdup(val))

#define OGS_SBI_BITRATE_BPS     0
#define OGS_SBI_BITRATE_GBPS    3
#define OGS_SBI_BITRATE_KBPS    1
#define OGS_SBI_BITRATE_MBPS    2
#define OGS_SBI_BITRATE_TBPS    4

#define OGS_SBI_SERVICE_NAME_N5G_EIR_EIC "n5g-eir-eic"
#define OGS_SBI_SERVICE_NAME_NAMF_CALLBACK "namf-callback"
#define OGS_SBI_SERVICE_NAME_NAMF_COMM "namf-comm"
#define OGS_SBI_SERVICE_NAME_NAMF_EVTS "namf-evts"
#define OGS_SBI_SERVICE_NAME_NAMF_LOC "namf-loc"
#define OGS_SBI_SERVICE_NAME_NAMF_MT "namf-mt"
#define OGS_SBI_SERVICE_NAME_NAUSF_AUTH "nausf-auth"
#define OGS_SBI_SERVICE_NAME_NAUSF_SORPROTECTION "nausf-sorprotection"
#define OGS_SBI_SERVICE_NAME_NAUSF_UPUPROTECTION "nausf-upuprotection"
#define OGS_SBI_SERVICE_NAME_NBSF_MANAGEMENT "nbsf-management"
#define OGS_SBI_SERVICE_NAME_NCHF_CONVERGEDCHARGING "nchf-convergedcharging"
#define OGS_SBI_SERVICE_NAME_NCHF_OFFLINEONLYCHARGING "nchf-offlineonlycharging"
#define OGS_SBI_SERVICE_NAME_NCHF_SPENDINGLIMITCONTROL \
    "nchf-spendinglimitcontrol"
#define OGS_SBI_SERVICE_NAME_NGMLC_LOC "ngmlc-loc"
#define OGS_SBI_SERVICE_NAME_NHSS_EE "nhss-ee"
#define OGS_SBI_SERVICE_NAME_NHSS_IMS_SDM "nhss-ims-sdm"
#define OGS_SBI_SERVICE_NAME_NHSS_IMS_UEAU "nhss-ims-ueau"
#define OGS_SBI_SERVICE_NAME_NHSS_IMS_UECM "nhss-ims-uecm"
#define OGS_SBI_SERVICE_NAME_NHSS_SDM "nhss-sdm"
#define OGS_SBI_SERVICE_NAME_NHSS_UEAU "nhss-ueau"
#define OGS_SBI_SERVICE_NAME_NHSS_UECM "nhss-uecm"
#define OGS_SBI_SERVICE_NAME_NLMF_LOC "nlmf-loc"
#define OGS_SBI_SERVICE_NAME_NNEF_EVENTEXPOSURE "nnef-eventexposure"
#define OGS_SBI_SERVICE_NAME_NNEF_PFDMANAGEMENT "nnef-pfdmanagement"
#define OGS_SBI_SERVICE_NAME_NNEF_SMCONTEXT "nnef-smcontext"
#define OGS_SBI_SERVICE_NAME_NNRF_DISC "nnrf-disc"
#define OGS_SBI_SERVICE_NAME_NNRF_NFM "nnrf-nfm"
#define OGS_SBI_SERVICE_NAME_NNRF_OAUTH2 "nnrf-oauth2"
#define OGS_SBI_SERVICE_NAME_NNSSAAF_NSSAA "nnssaaf-nssaa"
#define OGS_SBI_SERVICE_NAME_NNSSF_NSSAIAVAILABILITY "nnssf-nssaiavailability"
#define OGS_SBI_SERVICE_NAME_NNSSF_NSSELECTION "nnssf-nsselection"
#define OGS_SBI_SERVICE_NAME_NNWDAF_ANALYTICSINFO "nnwdaf-analyticsinfo"
#define OGS_SBI_SERVICE_NAME_NNWDAF_EVENTSSUBSCRIPTION \
    "nnwdaf-eventssubscription"
#define OGS_SBI_SERVICE_NAME_NPCF_AM_POLICY_CONTROL "npcf-am-policy-control"
#define OGS_SBI_SERVICE_NAME_NPCF_BDTPOLICYCONTROL "npcf-bdtpolicycontrol"
#define OGS_SBI_SERVICE_NAME_NPCF_EVENTEXPOSURE "npcf-eventexposure"
#define OGS_SBI_SERVICE_NAME_NPCF_POLICYAUTHORIZATION "npcf-policyauthorization"
#define OGS_SBI_SERVICE_NAME_NPCF_SMPOLICYCONTROL "npcf-smpolicycontrol"
#define OGS_SBI_SERVICE_NAME_NPCF_UE_POLICY_CONTROL "npcf-ue-policy-control"
#define OGS_SBI_SERVICE_NAME_NSEPP_TELESCOPIC "nsepp-telescopic"
#define OGS_SBI_SERVICE_NAME_NSMF_CALLBACK "nsmf-callback"
#define OGS_SBI_SERVICE_NAME_NSMF_EVENT_EXPOSURE "nsmf-event-exposure"
#define OGS_SBI_SERVICE_NAME_NSMF_NIDD "nsmf-nidd"
#define OGS_SBI_SERVICE_NAME_NSMF_PDUSESSION "nsmf-pdusession"
#define OGS_SBI_SERVICE_NAME_NSMSF_SMS "nsmsf-sms"
#define OGS_SBI_SERVICE_NAME_NSORAF_SOR "nsoraf-sor"
#define OGS_SBI_SERVICE_NAME_NSPAF_SECURED_PACKET "nspaf-secured-packet"
#define OGS_SBI_SERVICE_NAME_NUCMF_PROVISIONING "nucmf-provisioning"
#define OGS_SBI_SERVICE_NAME_NUCMF_UECAPABILITYMANAGEMENT \
    "nucmf-uecapabilitymanagement"
#define OGS_SBI_SERVICE_NAME_NUDM_EE "nudm-ee"
#define OGS_SBI_SERVICE_NAME_NUDM_MT "nudm-mt"
#define OGS_SBI_SERVICE_NAME_NUDM_NIDDAU "nudm-niddau"
#define OGS_SBI_SERVICE_NAME_NUDM_PP "nudm-pp"
#define OGS_SBI_SERVICE_NAME_NUDM_SDM "nudm-sdm"
#define OGS_SBI_SERVICE_NAME_NUDM_UEAU "nudm-ueau"
#define OGS_SBI_SERVICE_NAME_NUDM_UECM "nudm-uecm"
#define OGS_SBI_SERVICE_NAME_NUDR_DR "nudr-dr"
#define OGS_SBI_SERVICE_NAME_NUDR_GROUP_ID_MAP "nudr-group-id-map"
#define OGS_SBI_SERVICE_NAME_NUDSF_DR "nudsf-dr"















#define MAX_BIT_RATE 10000000000UL
#define OGS_5GC_PRE_EMPTION_DISABLED                        1
#define OGS_5GC_PRE_EMPTION_ENABLED                         2
#define OGS_ACCESS_RESTRICTION_GAN_NOT_ALLOWED                  (1<<2)
#define OGS_ACCESS_RESTRICTION_GERAN_NOT_ALLOWED                (1<<1)
#define OGS_ACCESS_RESTRICTION_HO_TO_NON_3GPP_ACCESS_NOT_ALLOWED (1<<5)
#define OGS_ACCESS_RESTRICTION_I_HSPA_EVOLUTION_NOT_ALLOWED     (1<<3)
#define OGS_ACCESS_RESTRICTION_NB_IOT_NOT_ALLOWED               (1<<6)
#define OGS_ACCESS_RESTRICTION_UTRAN_NOT_ALLOWED                (1)
#define OGS_ACCESS_RESTRICTION_WB_E_UTRAN_NOT_ALLOWED           (1<<4)
#define OGS_ACCESS_TYPE_3GPP 1
#define OGS_ACCESS_TYPE_BOTH_3GPP_AND_NON_3GPP 3
#define OGS_ACCESS_TYPE_NON_3GPP 2
#define OGS_BCD_TO_BUFFER_LEN(x)        (((x)+1)/2)
#define OGS_BEARER_PER_UE               8   
#define OGS_CHRGCHARS_LEN               2
#define OGS_COMPARE_ID(__id1, __id2, __max) \
    ((__id2) > (__id1) ? ((__id2) - (__id1) < ((__max)-1) ? -1 : 1) : \
     (__id1) > (__id2) ? ((__id1) - (__id2) < ((__max)-1) ? 1 : -1) : 0)
#define OGS_EPC_PRE_EMPTION_DISABLED                        1
#define OGS_EPC_PRE_EMPTION_ENABLED                         0
#define OGS_FLOW_DOWNLINK_ONLY    1
#define OGS_FLOW_FREE(__fLOW) \
    do { \
        if ((__fLOW)->description) { \
            ogs_free((__fLOW)->description); \
        } \
        else \
            ogs_assert_if_reached(); \
    } while(0)
#define OGS_FLOW_UPLINK_ONLY      2
#define OGS_FLOW_USAGE_AF_SIGNALLING    3
#define OGS_FLOW_USAGE_NO_INFO          1
#define OGS_FLOW_USAGE_RTCP             2
#define OGS_ID_GPSI_TYPE_MSISDN "msisdn"
#define OGS_ID_SUPI_TYPE_IMSI "imsi"
#define OGS_IPV4V6_LEN                      20
#define OGS_IPV4_LEN                        4
#define OGS_IPV6_128_PREFIX_LEN             128
#define OGS_IPV6_DEFAULT_PREFIX_LEN         64
#define OGS_IPV6_LEN                        16
#define OGS_MAX_APN_LEN                 OGS_MAX_DNN_LEN
#define OGS_MAX_DNN_LEN                 100
#define OGS_MAX_FQDN_LEN                256
#define OGS_MAX_IMEISV_BCD_LEN          16
#define OGS_MAX_IMEISV_LEN              \
    OGS_BCD_TO_BUFFER_LEN(OGS_MAX_IMEISV_BCD_LEN)
#define OGS_MAX_IMSI_BCD_LEN            15
#define OGS_MAX_IMSI_LEN                \
    OGS_BCD_TO_BUFFER_LEN(OGS_MAX_IMSI_BCD_LEN)
#define OGS_MAX_MSISDN_BCD_LEN          15
#define OGS_MAX_MSISDN_LEN              \
    OGS_BCD_TO_BUFFER_LEN(OGS_MAX_MSISDN_BCD_LEN)
#define OGS_MAX_NUM_OF_ALGORITHM        8
#define OGS_MAX_NUM_OF_APN              OGS_MAX_NUM_OF_DNN
#define OGS_MAX_NUM_OF_BEARER           4   
#define OGS_MAX_NUM_OF_BPLMN            6
#define OGS_MAX_NUM_OF_CELL_ID          16
#define OGS_MAX_NUM_OF_DNN              16
#define OGS_MAX_NUM_OF_ENB_ID           16
#define OGS_MAX_NUM_OF_FLOW_IN_BEARER   16
#define OGS_MAX_NUM_OF_FLOW_IN_GTP      OGS_MAX_NUM_OF_FLOW_IN_PDR
#define OGS_MAX_NUM_OF_FLOW_IN_MEDIA_SUB_COMPONENT OGS_MAX_NUM_OF_FLOW_IN_PDR
#define OGS_MAX_NUM_OF_FLOW_IN_NAS      OGS_MAX_NUM_OF_FLOW_IN_PDR
#define OGS_MAX_NUM_OF_FLOW_IN_PCC_RULE OGS_MAX_NUM_OF_FLOW_IN_PDR
#define OGS_MAX_NUM_OF_FLOW_IN_PDR      8
#define OGS_MAX_NUM_OF_GTPU_RESOURCE    4
#define OGS_MAX_NUM_OF_HOSTNAME         16
#define OGS_MAX_NUM_OF_MEDIA_COMPONENT 16
#define OGS_MAX_NUM_OF_MEDIA_SUB_COMPONENT     8
#define OGS_MAX_NUM_OF_MSISDN                                   2
#define OGS_MAX_NUM_OF_PACKET_BUFFER    64  
#define OGS_MAX_NUM_OF_PCC_RULE         8   
#define OGS_MAX_NUM_OF_PLMN         6
#define OGS_MAX_NUM_OF_PROTOCOL_OR_CONTAINER_ID    16
#define OGS_MAX_NUM_OF_SERVED_GUAMI     8
#define OGS_MAX_NUM_OF_SERVED_TAI       16
#define OGS_MAX_NUM_OF_SESS             4   
#define OGS_MAX_NUM_OF_SLICE        8
#define OGS_MAX_NUM_OF_TAI              16
#define OGS_MAX_PCO_LEN                 251
#define OGS_MAX_PKT_LEN                 2048
#define OGS_MAX_PLMN_ID_BCD_LEN         6
#define OGS_MAX_QOS_FLOW_ID             63
#define OGS_MAX_SDU_LEN                 8192
#define OGS_MAX_USER_PLANE_IP_RESOURCE_INFO_LEN \
    (23 + (OGS_MAX_APN_LEN+1))
#define OGS_NAS_PDU_SESSION_IDENTITY_UNASSIGNED 0
#define OGS_NAS_PROCEDURE_TRANSACTION_IDENTITY_UNASSIGNED 0
#define OGS_NETWORK_ACCESS_MODE_ONLY_PACKET                     2
#define OGS_NETWORK_ACCESS_MODE_PACKET_AND_CIRCUIT              0
#define OGS_NETWORK_ACCESS_MODE_RESERVED                        1
#define OGS_NEXT_ID(__id, __min, __max) \
    ((__id) = ((__id) == (__max) ? (__min) : ((__id) + 1)))
#define OGS_PAA_IPV4V6_LEN                              22
#define OGS_PAA_IPV4_LEN                                5
#define OGS_PAA_IPV6_LEN                                18
#define OGS_PCC_RULE_FREE(__pCCrULE) \
    do { \
        int __pCCrULE_iNDEX; \
        ogs_assert((__pCCrULE)); \
        if ((__pCCrULE)->id) \
            ogs_free((__pCCrULE)->id); \
        if ((__pCCrULE)->name) \
            ogs_free((__pCCrULE)->name); \
        for (__pCCrULE_iNDEX = 0; \
            __pCCrULE_iNDEX < (__pCCrULE)->num_of_flow; __pCCrULE_iNDEX++) { \
            OGS_FLOW_FREE(&((__pCCrULE)->flow[__pCCrULE_iNDEX])); \
        } \
        (__pCCrULE)->num_of_flow = 0; \
    } while(0)
#define OGS_PCC_RULE_TYPE_INSTALL               1
#define OGS_PCC_RULE_TYPE_REMOVE                2
#define OGS_PCO_ID_CHALLENGE_HANDSHAKE_AUTHENTICATION_PROTOCOL  0xc223
#define OGS_PCO_ID_DNS_SERVER_IPV4_ADDRESS_REQUEST              0x000d
#define OGS_PCO_ID_DNS_SERVER_IPV6_ADDRESS_REQUEST              0x0003
#define OGS_PCO_ID_INTERNET_PROTOCOL_CONTROL_PROTOCOL           0x8021
#define OGS_PCO_ID_IPV4_LINK_MTU_REQUEST                        0x0010
#define OGS_PCO_ID_IP_ADDRESS_ALLOCATION_VIA_NAS_SIGNALLING     0x000a
#define OGS_PCO_ID_MS_SUPPORTS_BCM                              0x0005
#define OGS_PCO_ID_MS_SUPPORT_LOCAL_ADDR_TFT_INDICATOR          0x0011
#define OGS_PCO_ID_PASSWORD_AUTHENTICATION_PROTOCOL             0xc023
#define OGS_PCO_ID_P_CSCF_IPV4_ADDRESS_REQUEST                  0x000c
#define OGS_PCO_ID_P_CSCF_IPV6_ADDRESS_REQUEST                  0x0001
#define OGS_PCO_ID_P_CSCF_RE_SELECTION_SUPPORT                  0x0012
#define OGS_PCO_MAX_NUM_OF_IPCP_OPTIONS 4
#define OGS_PCO_PPP_FOR_USE_WITH_IP_PDP_TYPE_OR_IP_PDN_TYPE 0
#define OGS_PDP_EUA_ETSI_PPP 1
#define OGS_PDP_EUA_IETF_IPV4 0x21
#define OGS_PDP_EUA_IETF_IPV4V6 0x8D
#define OGS_PDP_EUA_IETF_IPV6 0x57
#define OGS_PDP_EUA_ORG_ETSI 0
#define OGS_PDP_EUA_ORG_IETF 1
#define OGS_PDU_SESSION_TYPE_ETHERNET               5
#define OGS_PDU_SESSION_TYPE_FROM_DIAMETER(x)       ((x)+1)
#define OGS_PDU_SESSION_TYPE_IPV4                   1
#define OGS_PDU_SESSION_TYPE_IPV4V6                 3
#define OGS_PDU_SESSION_TYPE_IPV6                   2
#define OGS_PDU_SESSION_TYPE_IS_VALID(x) \
        ((x) == OGS_PDU_SESSION_TYPE_IPV4 || \
         (x) == OGS_PDU_SESSION_TYPE_IPV6 || \
         (x) == OGS_PDU_SESSION_TYPE_IPV4V6) \

#define OGS_PDU_SESSION_TYPE_TO_DIAMETER(x)         ((x)-1)
#define OGS_PDU_SESSION_TYPE_UNSTRUCTURED           4
#define OGS_PFCP_GTPU_INDEX_TO_TEID(__iNDEX, __iND, __rANGE) \
    (__iNDEX | (__rANGE << (32 - __iND)))
#define OGS_PFCP_GTPU_TEID_TO_INDEX(__tEID, __iND, __rANGE) \
    (__tEID & ~(__rANGE << (32 - __iND)))
#define OGS_PLMNIDSTRLEN    (sizeof(ogs_plmn_id_t)*2+1)
#define OGS_PLMN_ID_LEN                 3

#define OGS_QOS_INDEX_1                                       1
#define OGS_QOS_INDEX_2                                       2
#define OGS_QOS_INDEX_5                                       5
#define OGS_RAU_TAU_DEFAULT_TIME                (12*60)     
#define OGS_SSC_MODE_1                              1
#define OGS_SSC_MODE_2                              2
#define OGS_SSC_MODE_3                              3
#define OGS_STORE_PCC_RULE(__dST, __sRC) \
    do { \
        int __iNDEX; \
        ogs_assert((__sRC)); \
        ogs_assert((__dST)); \
        OGS_PCC_RULE_FREE(__dST); \
        (__dST)->type = (__sRC)->type; \
        if ((__sRC)->name) { \
            (__dST)->name = ogs_strdup((__sRC)->name); \
            ogs_assert((__dST)->name); \
        } \
        if ((__sRC)->id) { \
            (__dST)->id = ogs_strdup((__sRC)->id); \
            ogs_assert((__dST)->id); \
        } \
        for (__iNDEX = 0; __iNDEX < (__sRC)->num_of_flow; __iNDEX++) { \
            (__dST)->flow[__iNDEX].direction = \
                (__sRC)->flow[__iNDEX].direction; \
            (__dST)->flow[__iNDEX].description = \
                ogs_strdup((__sRC)->flow[__iNDEX].description);  \
            ogs_assert((__dST)->flow[__iNDEX].description); \
        } \
        (__dST)->num_of_flow = (__sRC)->num_of_flow; \
        (__dST)->flow_status = (__sRC)->flow_status; \
        (__dST)->precedence = (__sRC)->precedence; \
        memcpy(&(__dST)->qos, &(__sRC)->qos, sizeof(ogs_qos_t)); \
    } while(0)
#define OGS_SUBSCRIBER_STATUS_OPERATOR_DETERMINED_BARRING       1
#define OGS_SUBSCRIBER_STATUS_SERVICE_GRANTED                   0
#define OGS_S_NSSAI_NO_SD_VALUE     0xffffff
#define OGS_TIME_TO_BCD(x) \
    (((((x) % 10) << 4) & 0xf0) | (((x) / 10) & 0x0f))


#define OGS_USE_TALLOC 1



#define OGS_HASH_KEY_STRING     (-1)
#define ogs_hash_get(ht, key, klen) \
    ogs_hash_get_debug(ht, key, klen, OGS_FILE_LINE)
#define ogs_hash_get_or_set(ht, key, klen, val) \
    ogs_hash_get_or_set_debug(ht, key, klen, val, OGS_FILE_LINE)
#define ogs_hash_set(ht, key, klen, val) \
    ogs_hash_set_debug(ht, key, klen, val, OGS_FILE_LINE)
#define OGS_FSM_CHECK(__s, __f) \
    (OGS_FSM_STATE(__s) == (ogs_fsm_handler_t)__f)

#define OGS_FSM_STATE(__s) \
    (((ogs_fsm_t *)__s)->state)
#define OGS_FSM_TRAN(__s, __target) \
    ((ogs_fsm_t *)__s)->state = (ogs_fsm_handler_t)(__target)

#define OGS_TLV_1_OR_MORE(__v) __v[OGS_TLV_MAX_MORE]
#define OGS_TLV_CLEAR_DATA(__dATA) \
    do { \
        ogs_assert((__dATA)); \
        if ((__dATA)->data) { \
            ogs_free((__dATA)->data); \
            (__dATA)->data = NULL; \
            (__dATA)->len = 0; \
            (__dATA)->presence = 0; \
        } \
    } while(0)
#define OGS_TLV_MAX_CHILD_DESC 128
#define OGS_TLV_MAX_HEADROOM 16
#define OGS_TLV_MAX_MORE 16

#define OGS_TLV_STORE_DATA(__dST, __sRC) \
    do { \
        ogs_assert((__sRC)); \
        ogs_assert((__sRC)->data); \
        ogs_assert((__dST)); \
        OGS_TLV_CLEAR_DATA(__dST); \
        (__dST)->presence = (__sRC)->presence; \
        (__dST)->len = (__sRC)->len; \
        (__dST)->data = ogs_calloc((__dST)->len, sizeof(uint8_t)); \
        ogs_assert((__dST)->data); \
        memcpy((__dST)->data, (__sRC)->data, (__dST)->len); \
    } while(0)
#define OGS_TLV_VARIABLE_LEN 0

#define OGS_TLV_MODE_T1                 5
#define OGS_TLV_MODE_T1_L1              1
#define OGS_TLV_MODE_T1_L2              2
#define OGS_TLV_MODE_T1_L2_I1           3
#define OGS_TLV_MODE_T2_L2              4
#define ogs_tlv_instance(pTlv) pTlv->instance
#define ogs_tlv_length(pTlv) pTlv->length
#define ogs_tlv_type(pTlv) pTlv->type
#define ogs_tlv_value(pTlv) pTlv->value

#define OGS_POLLIN      0x01
#define OGS_POLLOUT     0x02

#define ogs_pollset_notify ogs_pollset_actions.notify
#define ogs_pollset_poll ogs_pollset_actions.poll




#define AF_SOCKPAIR     AF_INET

#define OGS_DEFAULT_SCTP_MAX_NUM_OF_OSTREAMS 30

#define INVALID_SOCKET -1

#define OGS_ADDR(__aDDR, __bUF) \
    ogs_inet_ntop(__aDDR, __bUF, OGS_ADDRSTRLEN)
#define OGS_ADDRSTRLEN INET6_ADDRSTRLEN
#define OGS_PORT(__aDDR) \
    be16toh((__aDDR)->ogs_sin_port)

#define ogs_sa_family sa.sa_family
#define ogs_sin_port sin.sin_port

#define SIG_DFL (void (*)(int))0
#define SIG_ERR (void (*)(int))-1
#define SIG_IGN (void (*)(int))1


#define ogs_thread_cond_broadcast pthread_cond_broadcast
#define ogs_thread_cond_destroy (void)pthread_cond_destroy
#define ogs_thread_cond_init(_n) (void)pthread_cond_init((_n), NULL)
#define ogs_thread_cond_signal (void)pthread_cond_signal
#define ogs_thread_cond_t pthread_cond_t
#define ogs_thread_cond_wait pthread_cond_wait
#define ogs_thread_id_t pthread_t
#define ogs_thread_join(_n) pthread_join((_n), NULL)
#define ogs_thread_mutex_destroy (void)pthread_mutex_destroy
#define ogs_thread_mutex_init(_n) (void)pthread_mutex_init((_n), NULL)
#define ogs_thread_mutex_lock (void)pthread_mutex_lock
#define ogs_thread_mutex_t pthread_mutex_t
#define ogs_thread_mutex_unlock (void)pthread_mutex_unlock

#define ogs_timer_delete(timer) \
    ogs_timer_delete_debug(timer, OGS_FILE_LINE)
#define ogs_timer_start(timer, duration) \
    ogs_timer_start_debug(timer, duration, OGS_FILE_LINE)
#define ogs_timer_stop(timer) \
    ogs_timer_stop_debug(timer, OGS_FILE_LINE)
#define OGS_RBTREE(name) ogs_rbtree_t name = { NULL }

#define ogs_rb_entry(ptr, type, member) ogs_container_of(ptr, type, member)
#define ogs_rbtree_for_each(tree, node) \
    for (node = ogs_rbtree_first(tree); \
        (node); node = ogs_rbtree_next(node))
#define ogs_rbtree_reverse_for_each(tree, node) \
    for (node = ogs_rbtree_last(tree); \
        (node); node = ogs_rbtree_prev(node))
#define OGS_UUID_FORMATTED_LENGTH 36



#define OGS_MEM_CLEAR(__dATA) \
    do { \
        if ((__dATA)) { \
            ogs_free((__dATA)); \
            (__dATA) = NULL; \
        } \
    } while(0)
#define ogs_calloc(nmemb, size) \
    ogs_talloc_zero_size(__ogs_talloc_core, (nmemb) * (size), __location__)
#define ogs_free(ptr) ogs_talloc_free(ptr, __location__)
#define ogs_malloc(size) \
    ogs_talloc_size(__ogs_talloc_core, size, __location__)
#define ogs_realloc(oldptr, size) \
    ogs_talloc_realloc_size(__ogs_talloc_core, oldptr, size, __location__)

#define ogs_pkbuf_alloc(pool, size) \
    ogs_pkbuf_alloc_debug(pool, size, OGS_FILE_LINE)
#define ogs_pkbuf_copy(pkbuf) \
    ogs_pkbuf_copy_debug(pkbuf, OGS_FILE_LINE)

#define ogs_assert(expr) \
    do { \
        if (ogs_likely(expr)) ; \
        else { \
            ogs_fatal("%s: Assertion `%s' failed.", OGS_FUNC, #expr); \
            ogs_abort(); \
        } \
    } while(0)
#define ogs_assert_if_reached() \
    do { \
        ogs_warn("%s: should not be reached.", OGS_FUNC); \
        ogs_abort(); \
    } while(0)
#define ogs_debug(...) ogs_log_message(OGS_LOG_DEBUG, 0, __VA_ARGS__)
#define ogs_error(...) ogs_log_message(OGS_LOG_ERROR, 0, __VA_ARGS__)
#define ogs_expect(expr) \
    do { \
        if (ogs_likely(expr)) ; \
        else { \
            ogs_error("%s: Expectation `%s' failed.", OGS_FUNC, #expr); \
        } \
    } while (0)
#define ogs_expect_or_return(expr) \
    do { \
        if (ogs_likely(expr)) ; \
        else { \
            ogs_error("%s: Expectation `%s' failed.", OGS_FUNC, #expr); \
            return; \
        } \
    } while (0)
#define ogs_expect_or_return_val(expr, val) \
    do { \
        if (ogs_likely(expr)) ; \
        else { \
            ogs_error("%s: Expectation `%s' failed.", OGS_FUNC, #expr); \
            return (val); \
        } \
    } while (0)
#define ogs_fatal(...) ogs_log_message(OGS_LOG_FATAL, 0, __VA_ARGS__)
#define ogs_info(...) ogs_log_message(OGS_LOG_INFO, 0, __VA_ARGS__)
#define ogs_log_hexdump(level, _d, _l) \
    ogs_log_hexdump_func(level, OGS_LOG_DOMAIN, _d, _l)
#define ogs_log_message(level, err, ...) \
    ogs_log_printf(level, OGS_LOG_DOMAIN, \
    err, "__FILE__", "__LINE__", OGS_FUNC,  \
    0, __VA_ARGS__) 
#define ogs_log_print(level, ...) \
    ogs_log_printf(level, OGS_LOG_DOMAIN, \
    0, NULL, 0, NULL,  \
    1, __VA_ARGS__) 
#define ogs_trace(...) ogs_log_message(OGS_LOG_TRACE, 0, __VA_ARGS__)
#define ogs_warn(...) ogs_log_message(OGS_LOG_WARN, 0, __VA_ARGS__)

#define OGS_HEX(I, I_LEN, O) ogs_ascii_to_hex((char*)I, I_LEN, O, sizeof(O))
#define OGS_1970_1900_SEC_DIFF 2208988800UL 
#define OGS_INFINITE_TIME (-1)
#define OGS_NO_WAIT_TIME (0)

#define OGS_USEC_PER_SEC (1000000LL)
#define ogs_mktime mktime
#define ogs_strftime strftime
#define ogs_strptime strptime
#define ogs_time_from_msec(msec) ((ogs_time_t)(msec) * 1000)
#define ogs_time_from_sec(sec) ((ogs_time_t)(sec) * OGS_USEC_PER_SEC)
#define ogs_time_msec(time) (((time) / 1000) % 1000)
#define ogs_time_sec(time) ((time) / OGS_USEC_PER_SEC)
#define ogs_time_to_msec(time) ((time) ? (1 + ((time) - 1) / 1000) : 0)
#define ogs_time_usec(time) ((time) % OGS_USEC_PER_SEC)
#define OGS_DONE    -4
#define OGS_EACCES                  ERROR_ACCESS_DENIED
#define OGS_EAGAIN                  WSAEWOULDBLOCK
#define OGS_EBADF                   WSAEBADF
#define OGS_ECONNREFUSED            WSAECONNREFUSED
#define OGS_ECONNRESET              WSAECONNRESET
#define OGS_EEXIST                  ERROR_ALREADY_EXISTS
#define OGS_EEXIST_FILE             ERROR_FILE_EXISTS
#define OGS_ENOMEM                  ERROR_NOT_ENOUGH_MEMORY
#define OGS_EPERM                   ERROR_ACCESS_DENIED

#define OGS_ERROR   -1
#define OGS_ETIMEDOUT               WSAETIMEDOUT
#define OGS_OK       0
#define OGS_RETRY   -2
#define OGS_TIMEUP  -3
#define ogs_errno                   GetLastError()
#define ogs_set_errno(err)          SetLastError(err)
#define ogs_set_socket_errno(err)   WSASetLastError(err)
#define ogs_socket_errno            WSAGetLastError()
#define OGS_HUGE_LEN        8192

#define OGS_STRING_DUP(__dST, __sRC) \
    do { \
        OGS_MEM_CLEAR(__dST); \
        __dST = ogs_strdup(__sRC); \
        ogs_assert(__dST); \
    } while(0)
#define ogs_memdup(p, size) \
    ogs_talloc_memdup(__ogs_talloc_core, p, size)
#define ogs_msprintf(...) ogs_msprintf_debug(OGS_FILE_LINE, __VA_ARGS__)
#define ogs_mstrcatf(s, ...) \
    ogs_talloc_asprintf_append(s, __VA_ARGS__)
#define ogs_strcasecmp _stricmp
#define ogs_strdup(p) \
    ogs_talloc_strdup(__ogs_talloc_core, p)
#define ogs_strncasecmp _strnicmp
#define ogs_strndup(p, n) \
    ogs_talloc_strndup(__ogs_talloc_core, p, n)
#define ogs_strtok_r strtok_s

#define OGS_POOL(pool, type) \
    struct { \
        const char *name; \
        int head, tail; \
        int size, avail; \
        type **free, *array, **index; \
    } pool

#define ogs_index_final(pool) do { \
    if (((pool)->size != (pool)->avail)) \
        ogs_error("%d in '%s[%d]' were not released.", \
                (pool)->size - (pool)->avail, (pool)->name, (pool)->size); \
    ogs_free((pool)->free); \
    ogs_free((pool)->array); \
    ogs_free((pool)->index); \
} while (0)
#define ogs_index_init(pool, _size) do { \
    int i; \
    (pool)->name = #pool; \
    (pool)->free = ogs_malloc(sizeof(*(pool)->free) * _size); \
    ogs_assert((pool)->free); \
    (pool)->array = ogs_malloc(sizeof(*(pool)->array) * _size); \
    ogs_assert((pool)->array); \
    (pool)->index = ogs_malloc(sizeof(*(pool)->index) * _size); \
    ogs_assert((pool)->index); \
    (pool)->size = (pool)->avail = _size; \
    (pool)->head = (pool)->tail = 0; \
    for (i = 0; i < _size; i++) { \
        (pool)->free[i] = &((pool)->array[i]); \
        (pool)->index[i] = NULL; \
    } \
} while (0)
#define ogs_pool_alloc(pool, node) do { \
    *(node) = NULL; \
    if ((pool)->avail > 0) { \
        (pool)->avail--; \
        *(node) = (void*)(pool)->free[(pool)->head]; \
        (pool)->free[(pool)->head] = NULL; \
        (pool)->head = ((pool)->head + 1) % ((pool)->size); \
        (pool)->index[ogs_pool_index(pool, *(node))-1] = *(node); \
    } \
} while (0)
#define ogs_pool_avail(pool) ((pool)->avail)
#define ogs_pool_cycle(pool, node) \
    ogs_pool_find((pool), ogs_pool_index((pool), (node)))
#define ogs_pool_final(pool) do { \
    if (((pool)->size != (pool)->avail)) \
        ogs_error("%d in '%s[%d]' were not released.", \
                (pool)->size - (pool)->avail, (pool)->name, (pool)->size); \
    free((pool)->free); \
    free((pool)->array); \
    free((pool)->index); \
} while (0)
#define ogs_pool_find(pool, _index) \
    (_index > 0 && _index <= (pool)->size) ? (pool)->index[_index-1] : NULL
#define ogs_pool_free(pool, node) do { \
    if ((pool)->avail < (pool)->size) { \
        (pool)->avail++; \
        (pool)->free[(pool)->tail] = (void*)(node); \
        (pool)->tail = ((pool)->tail + 1) % ((pool)->size); \
        (pool)->index[ogs_pool_index(pool, node)-1] = NULL; \
    } \
} while (0)
#define ogs_pool_index(pool, node) (((node) - (pool)->array)+1)
#define ogs_pool_init(pool, _size) do { \
    int i; \
    (pool)->name = #pool; \
    (pool)->free = malloc(sizeof(*(pool)->free) * _size); \
    ogs_assert((pool)->free); \
    (pool)->array = malloc(sizeof(*(pool)->array) * _size); \
    ogs_assert((pool)->array); \
    (pool)->index = malloc(sizeof(*(pool)->index) * _size); \
    ogs_assert((pool)->index); \
    (pool)->size = (pool)->avail = _size; \
    (pool)->head = (pool)->tail = 0; \
    for (i = 0; i < _size; i++) { \
        (pool)->free[i] = &((pool)->array[i]); \
        (pool)->index[i] = NULL; \
    } \
} while (0)
#define ogs_pool_size(pool) ((pool)->size)
#define OGS_LIST(name) \
    ogs_list_t name = { NULL, NULL }

#define ogs_list_copy(dst, src) do { \
    (dst)->prev = (src)->prev; \
    (dst)->next = (src)->next; \
} while (0)
#define ogs_list_entry(ptr, type, member) \
    ptr ? ogs_container_of(ptr, type, member) : NULL
#define ogs_list_for_each(list, node) \
    for (node = ogs_list_first(list); (node); \
        node = ogs_list_next(node))
#define ogs_list_for_each_entry(list, node, member) \
    for (node = ogs_list_entry(ogs_list_first(list), typeof(*node), member); \
            (node) && (&node->member); \
                node = ogs_list_entry( \
                        ogs_list_next(&node->member), typeof(*node), member))
#define ogs_list_for_each_entry_safe(list, n, node, member) \
    for (node = ogs_list_entry(ogs_list_first(list), typeof(*node), member); \
            (node) && (&node->member) && \
                (n = ogs_list_entry( \
                    ogs_list_next(&node->member), typeof(*node), member), 1); \
            node = n)
#define ogs_list_for_each_safe(list, n, node) \
    for (node = ogs_list_first(list); \
        (node) && (n = ogs_list_next(node), 1); \
        node = n)
#define ogs_list_init(list) do { \
    (list)->prev = (NULL); \
    (list)->next = (NULL); \
} while (0)
#define ogs_list_insert_sorted(__list, __lnode, __compare) \
    __ogs_list_insert_sorted(__list, __lnode, (ogs_list_compare_f)__compare);
#define ogs_list_reverse_for_each(list, node) \
    for (node = ogs_list_last(list); (node); \
        node = ogs_list_prev(node))
    #define CASE(X)            } if (!__switch_next__ || \
                                     (__switch_next__ = \
                                         strcmp(__switch_p__, X)) == 0) {
    #define DEFAULT            } {
#define ED2(x1, x2) x1 x2
#define ED3(x1, x2, x3) x1 x2 x3
#define ED4(x1, x2, x3, x4) x1 x2 x3 x4
#define ED5(x1, x2, x3, x4, x5) x1 x2 x3 x4 x5
#define ED6(x1, x2, x3, x4, x5, x6) x1 x2 x3 x4 x5 x6
#define ED7(x1, x2, x3, x4, x5, x6, x7) x1 x2 x3 x4 x5 x6 x7
#define ED8(x1, x2, x3, x4, x5, x6, x7, x8) x1 x2 x3 x4 x5 x6 x7 x8
    #define END          }}}
#define OGS_ARG_MAX                     256
#define OGS_ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define OGS_FILE_LINE "__FILE__" ":" OGS_STRINGIFY("__LINE__")
#define OGS_FUNC __FUNCTION__
#define OGS_GNUC_CHECK_VERSION(major, minor) \
    (("__GNUC__" > (major)) || \
     (("__GNUC__" == (major)) && ("__GNUC_MINOR__" >= (minor))))
#define OGS_GNUC_FALLTHROUGH __attribute__ ((fallthrough))
#define OGS_GNUC_NORETURN __attribute__((__noreturn__))
#define OGS_GNUC_PRINTF(f, v) __attribute__ ((format (gnu_printf, f, v)))
#define OGS_INET6_NTOP(src, dst) \
    inet_ntop(AF_INET6, (void *)(src), (dst), INET6_ADDRSTRLEN)
#define OGS_INET_NTOP(src, dst) \
    inet_ntop(AF_INET, (void *)(uintptr_t)(src), (dst), INET_ADDRSTRLEN)
#define OGS_IS_DIR_SEPARATOR(c) ((c) == OGS_DIR_SEPARATOR || (c) == '/')

#define OGS_MAX_FILEPATH_LEN            256
#define OGS_MAX_IFNAME_LEN              32
#define OGS_OBJECT_IS_REF(__oBJ) ((__oBJ)->reference_count > 1)
#define OGS_OBJECT_REF(__oBJ) \
    ((__oBJ)->reference_count)++, \
    ogs_debug("[REF] %d", ((__oBJ)->reference_count))
#define OGS_OBJECT_UNREF(__oBJ) \
    ogs_debug("[UNREF] %d", ((__oBJ)->reference_count)), \
    ((__oBJ)->reference_count)--
#define OGS_PASTE(n1, n2)           OGS_PASTE_HELPER(n1, n2)
#define OGS_PASTE_HELPER(n1, n2)    n1##n2
#define OGS_STATIC_ASSERT(expr) \
    typedef char dummy_for_ogs_static_assert##"__LINE__"[(expr) ? 1 : -1]
#define OGS_STRINGIFY(n)            OGS_STRINGIFY_HELPER(n)
#define OGS_STRINGIFY_HELPER(n)     #n
    #define SWITCH(X)    {char *__switch_p__,  __switch_next__; \
                          for (__switch_p__ = \
                                  X ? (char *)X : (char *)"OGS_SWITCH_NULL", \
                                  __switch_next__ = 1; \
                              __switch_p__; \
                              __switch_p__ = 0, __switch_next__ = 1) { {

#define WORDS_BIGENDIAN 1
#define be16toh(x) ntohs((x))
#define be32toh(x) ntohl((x))
#define be64toh(x) ntohll((x))
#define htobe16(x) htons((x))
#define htobe32(x) htonl((x))
#define htobe64(x) htonll((x))
#define htole16(x) (x)
#define htole32(x) (x)
#define htole64(x) (x)
#define le16toh(x) (x)
#define le32toh(x) (x)
#define le64toh(x) (x)
#define ogs_container_of(ptr, type, member) \
    (type *)((unsigned char *)ptr - offsetof(type, member))
#define ogs_inline __inline
#define ogs_likely(x) __builtin_expect (!!(x), 1)
#define ogs_max(x , y)  (((x) > (y)) ? (x) : (y))
#define ogs_min(x , y)  (((x) < (y)) ? (x) : (y))
#define ogs_uint64_to_uint32(x) ((x >= 0xffffffffUL) ? 0xffffffffU : x)
#define ogs_unlikely(x) __builtin_expect (!!(x), 0)


#define _WIN32_WINNT 0x0600
#define OGS_AK_LEN                      6
#define OGS_AMF_LEN                     2
#define OGS_AUTN_LEN                    16
#define OGS_AUTS_LEN                    14


#define OGS_HASH_MME_LEN                8
#define OGS_KEYSTRLEN(x)                ((x*2)+1)
#define OGS_KEY_LEN                     16
#define OGS_MAC_S_LEN                   8
#define OGS_MAX_RES_LEN                 16
#define OGS_MAX_SQN                     0xffffffffffff
#define OGS_RAND_LEN                    16
#define OGS_SQN_LEN                     6
#define OGS_SQN_XOR_AK_LEN              6


#define OGS_KDF_NAS_ENC_ALG 0x01
#define OGS_KDF_NAS_INT_ALG 0x02





#define OGS_ERR_INVALID_CMAC -2
#define OGS_AES_BLOCK_SIZE 16

#define OGS_AES_KEYLENGTH(keybits) ((keybits)/8)
#define OGS_AES_MAX_KEY_BITS 256
#define OGS_AES_NROUNDS(keybits)   ((keybits)/32+6)
#define OGS_AES_RKLENGTH(keybits)  ((keybits)/8+28)

#define OGS_SHA224_BLOCK_SIZE  OGS_SHA256_BLOCK_SIZE
#define OGS_SHA224_DIGEST_SIZE ( 224 / 8)
#define OGS_SHA256_BLOCK_SIZE  ( 512 / 8)
#define OGS_SHA256_DIGEST_SIZE ( 256 / 8)

#define OGS_SHA384_BLOCK_SIZE  OGS_SHA512_BLOCK_SIZE
#define OGS_SHA384_DIGEST_SIZE ( 384 / 8)
#define OGS_SHA512_BLOCK_SIZE  (1024 / 8)
#define OGS_SHA512_DIGEST_SIZE ( 512 / 8)

#define OGS_SHA1_BLOCK_SIZE  (512 / 8)
#define OGS_SHA1_DIGEST_SIZE (160 / 8)

