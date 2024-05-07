














































#include<string.h>












#define OGS_LOG_DOMAIN __ogs_sbi_domain



#define ogs_sbi_send_http_status_no_content(__sTREAM) \
        ogs_sbi_send_response(__sTREAM, OGS_SBI_HTTP_STATUS_NO_CONTENT)


#define NF_INSTANCE_IS_OTHERS(_iD) \
    strcmp((_iD), ogs_sbi_self()->nf_instance_id) != 0
#define NF_INSTANCE_IS_SELF(_iD) \
    strcmp((_iD), ogs_sbi_self()->nf_instance_id) == 0
#define OGS_MAX_NUM_OF_NF_INFO 8

#define OGS_SBI_DEFAULT_CAPACITY 100
#define OGS_SBI_DEFAULT_LOAD 0
#define OGS_SBI_DEFAULT_PRIORITY 0
#define OGS_SBI_MAX_NF_TYPE 64
#define OGS_SBI_MAX_NUM_OF_IP_ADDRESS 8
#define OGS_SBI_MAX_NUM_OF_NF_TYPE 16
#define OGS_SBI_MAX_NUM_OF_SERVICE_VERSION 8
#define OGS_SBI_NF_INSTANCE(__sBIObject, __nFType) \
    (((__sBIObject)->nf_type_array)[__nFType].nf_instance)
#define OGS_SBI_SETUP_NF(__sBIObject, __nFType, __nFInstance) \
    do { \
        ogs_assert((__sBIObject)); \
        ogs_assert((__nFType)); \
        ogs_assert((__nFInstance)); \
        \
        if (OGS_SBI_NF_INSTANCE((__sBIObject), (__nFType))) { \
            ogs_warn("UE %s-EndPoint updated [%s]", \
                    OpenAPI_nf_type_ToString((__nFType)), \
                    (__nFInstance)->id); \
            ogs_sbi_nf_instance_remove( \
                    OGS_SBI_NF_INSTANCE((__sBIObject), (__nFType))); \
        } \
        \
        if (OGS_SBI_NF_INSTANCE( \
                (__sBIObject), (__nFType)) != (__nFInstance)) { \
            (__nFInstance)->reference_count++; \
        } \
        OGS_SBI_NF_INSTANCE((__sBIObject), (__nFType)) = (__nFInstance); \
        ogs_trace("nf_instance->reference_count = %d", \
                (__nFInstance)->reference_count); \
    } while(0)
#define OGS_SETUP_SBI_NF_INSTANCE(__cTX, __pNF_INSTANCE) \
    do { \
        ogs_assert((__pNF_INSTANCE)); \
        if ((__cTX) != __pNF_INSTANCE) \
            __pNF_INSTANCE->reference_count++; \
        (__cTX) = __pNF_INSTANCE; \
        ogs_trace("nf_instance->reference_count = %d", \
                __pNF_INSTANCE->reference_count); \
    } while(0)

#define OGS_SETUP_SBI_CLIENT(__cTX, __pCLIENT) \
    do { \
        ogs_assert((__cTX)); \
        ogs_assert((__pCLIENT)); \
        if ((__cTX)->client != __pCLIENT) \
            __pCLIENT->reference_count++; \
        (__cTX)->client = __pCLIENT; \
        ogs_trace("client->reference_count = %d", __pCLIENT->reference_count); \
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
#define OGS_SBI_PARAM_REQUESTER_NF_TYPE             "requester-nf-type"
#define OGS_SBI_PARAM_SINGLE_NSSAI                  "single-nssai"
#define OGS_SBI_PARAM_SLICE_INFO_REQUEST_FOR_PDU_SESSION \
        "slice-info-request-for-pdu-session"
#define OGS_SBI_PARAM_SNSSAI                        "snssai"
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
#define OGS_SBI_SERVICE_NAME_NAF_EVENTEXPOSURE      "naf-eventexposure"
#define OGS_SBI_SERVICE_NAME_NAMF_CALLBACK          "namf-callback"
#define OGS_SBI_SERVICE_NAME_NAMF_COMM              "namf-comm"
#define OGS_SBI_SERVICE_NAME_NAUSF_AUTH             "nausf-auth"
#define OGS_SBI_SERVICE_NAME_NBSF_MANAGEMENT        "nbsf-management"
#define OGS_SBI_SERVICE_NAME_NNRF_DISC              "nnrf-disc"
#define OGS_SBI_SERVICE_NAME_NNRF_NFM               "nnrf-nfm"
#define OGS_SBI_SERVICE_NAME_NNSSF_NSSELECTION      "nnssf-nsselection"
#define OGS_SBI_SERVICE_NAME_NPCF_AM_POLICY_CONTROL "npcf-am-policy-control"
#define OGS_SBI_SERVICE_NAME_NPCF_CALLBACK          "npcf-callback"
#define OGS_SBI_SERVICE_NAME_NPCF_POLICYAUTHORIZATION \
                                                    "npcf-policyauthorization"
#define OGS_SBI_SERVICE_NAME_NPCF_SMPOLICYCONTROL   "npcf-smpolicycontrol"
#define OGS_SBI_SERVICE_NAME_NSMF_CALLBACK          "nsmf-callback"
#define OGS_SBI_SERVICE_NAME_NSMF_EVENT_EXPOSURE    "nsmf-event-exposure"
#define OGS_SBI_SERVICE_NAME_NSMF_PDUSESSION        "nsmf-pdusession"
#define OGS_SBI_SERVICE_NAME_NUDM_SDM               "nudm-sdm"
#define OGS_SBI_SERVICE_NAME_NUDM_UEAU              "nudm-ueau"
#define OGS_SBI_SERVICE_NAME_NUDM_UECM              "nudm-uecm"
#define OGS_SBI_SERVICE_NAME_NUDR_DR                "nudr-dr"
#define ogs_sbi_header_get(ht, key) \
    ogs_hash_get(ht, key, strlen(key))
#define ogs_sbi_header_set(ht, key, val) \
    ogs_hash_set(ht, ogs_strdup(key), strlen(key), ogs_strdup(val))
#define OGS_SBI_BITRATE_BPS     0
#define OGS_SBI_BITRATE_GBPS    3
#define OGS_SBI_BITRATE_KBPS    1
#define OGS_SBI_BITRATE_MBPS    2
#define OGS_SBI_BITRATE_TBPS    4




