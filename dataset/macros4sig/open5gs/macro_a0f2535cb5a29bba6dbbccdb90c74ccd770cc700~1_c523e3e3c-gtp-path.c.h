






#define OGS_LOG_DOMAIN __sgwu_log_domain

#define SGWU_SESS(pfcp_sess) ogs_container_of(pfcp_sess, sgwu_sess_t, pfcp)

#define sgwu_sm_debug(__pe) \
    ogs_debug("%s(): %s\n", __func__, sgwu_event_get_name(__pe))



