#include<netinet/ip.h>
#include<netinet/icmp6.h>







#include<net/if.h>



#include<netinet/in.h>
#include<net/ethernet.h>
#include<sys/ioctl.h>
#include<netinet/ip6.h>
#include<sys/socket.h>
#include<netinet/ip_icmp.h>
#include<ifaddrs.h>

#define OGS_LOG_DOMAIN __upf_log_domain

#define UPF_SESS(pfcp_sess) ogs_container_of(pfcp_sess, upf_sess_t, pfcp)

#define upf_sm_debug(__pe) \
    ogs_debug("%s(): %s", __func__, upf_event_get_name(__pe))




#define MAX_ND_SIZE 128
