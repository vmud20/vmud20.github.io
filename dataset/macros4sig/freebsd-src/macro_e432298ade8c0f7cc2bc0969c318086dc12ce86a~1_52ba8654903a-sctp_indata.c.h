#include<sys/queue.h>


























#include<netinet/in.h>







#include<sys/resource.h>

#include<sys/time.h>
#include<sys/sysctl.h>












#include<sys/param.h>





#include<stdint.h>









#include<sys/signal.h>


#include<sys/socket.h>
#include<sys/cdefs.h>



#include<sys/types.h>









#include<sys/select.h>

#define SCTP_RTT_SHIFT 3
#define SCTP_RTT_VAR_SHIFT 2

#define __CC_SUPPORTS_DYNAMIC_ARRAY_INIT 1
#define __CC_SUPPORTS_INLINE 1
#define __CC_SUPPORTS_VARADIC_XXX 1 
#define __CC_SUPPORTS_WARNING 1
#define __CC_SUPPORTS___FUNC__ 1
#define __CC_SUPPORTS___INLINE 1
#define __CC_SUPPORTS___INLINE__ 1
#define __GNUCLIKE_ASM 3
#define __GNUCLIKE_BUILTIN_CONSTANT_P 1
#define __GNUCLIKE_BUILTIN_MEMCPY 1
# define __GNUCLIKE_BUILTIN_NEXT_ARG 1
# define __GNUCLIKE_BUILTIN_STDARG 1
# define __GNUCLIKE_BUILTIN_VAALIST 1
# define __GNUCLIKE_BUILTIN_VARARGS 1
# define __GNUCLIKE_CTOR_SECTION_HANDLING 1

# define __GNUCLIKE_MATH_BUILTIN_RELOPS
#define __GNUCLIKE___OFFSETOF 1
#define __GNUCLIKE___SECTION 1
#define __GNUCLIKE___TYPEOF 1
# define __GNUC_VA_LIST_COMPATIBILITY 1
#define __NO_TLS 1
#define __aligned(x)	__attribute__((__aligned__(x)))
#define __nonnull(x)	__attribute__((__nonnull__(x)))
#define __offsetof(type, field)	 __builtin_offsetof(type, field)
#define __predict_false(exp)    __builtin_expect((exp), 0)
#define __predict_true(exp)     __builtin_expect((exp), 1)
#define __section(x)	__attribute__((__section__(x)))
#define INVALID_SINFO_FLAG(x) (((x) & 0xfffffff0 \
                                    & ~(SCTP_EOF | SCTP_ABORT | SCTP_UNORDERED |\
				        SCTP_ADDR_OVER | SCTP_SENDALL | SCTP_EOR |\
					SCTP_SACK_IMMEDIATELY)) != 0)
#define PR_SCTP_BUF_ENABLED(x)    (PR_SCTP_POLICY(x) == SCTP_PR_SCTP_BUF)
#define PR_SCTP_ENABLED(x)        (PR_SCTP_POLICY(x) != SCTP_PR_SCTP_NONE)
#define PR_SCTP_INVALID_POLICY(x) (PR_SCTP_POLICY(x) > SCTP_PR_SCTP_RTX)
#define PR_SCTP_POLICY(x)         ((x) & 0x0f)
#define PR_SCTP_RTX_ENABLED(x)    (PR_SCTP_POLICY(x) == SCTP_PR_SCTP_RTX)
#define PR_SCTP_TTL_ENABLED(x)    (PR_SCTP_POLICY(x) == SCTP_PR_SCTP_TTL)
#define SCTP_ABORT            0x0200	
#define SCTP_ADAPTATION_INDICATION              0x0006
#define SCTP_ADAPTION_INDICATION                0x0006
#define SCTP_ADDR_OVER        0x0800	
#define SCTP_ALIGN_RESV_PAD 92
#define SCTP_ALIGN_RESV_PAD_SHORT 76
#define SCTP_ALL_ASSOC     2
#define SCTP_ASSOC_CHANGE                       0x0001
#define SCTP_ASSOC_RESET_EVENT                  0x000c
#define SCTP_ASSOC_SUPPORTS_ASCONF    0x03
#define SCTP_ASSOC_SUPPORTS_AUTH      0x02
#define SCTP_ASSOC_SUPPORTS_MAX       0x05
#define SCTP_ASSOC_SUPPORTS_MULTIBUF  0x04
#define SCTP_ASSOC_SUPPORTS_PR        0x01
#define SCTP_ASSOC_SUPPORTS_RE_CONFIG 0x05
#define SCTP_AUTHENTICATION_EVENT               0x0008
#define SCTP_AUTHINFO   0x0008
#define SCTP_CANT_STR_ASSOC     0x0005
#define SCTP_COMM_LOST          0x0002
#define SCTP_COMM_UP            0x0001
#define SCTP_COMPLETE         0x0020	
#define SCTP_CURRENT_ASSOC 1
#define SCTP_DSTADDRV4  0x0009
#define SCTP_DSTADDRV6  0x000a
#define SCTP_EOF              0x0100	
#define SCTP_EOR              0x2000	
#define SCTP_FUTURE_ASSOC  0
#define SCTP_MAX_EXPLICT_STR_RESET   1000
#define SCTP_MAX_LOGGING_SIZE 30000
#define SCTP_NEXT_MSG_AVAIL        0x0001
#define SCTP_NEXT_MSG_ISCOMPLETE   0x0002
#define SCTP_NEXT_MSG_IS_NOTIFICATION 0x0008
#define SCTP_NEXT_MSG_IS_UNORDERED 0x0004
#define SCTP_NOTIFICATION     0x0010	
#define SCTP_NOTIFICATIONS_STOPPED_EVENT        0x000b	
#define SCTP_NO_NEXT_MSG           0x0000
#define SCTP_NXTINFO    0x0006
#define SCTP_PARTIAL_DELIVERY_EVENT             0x0007
#define SCTP_PEER_ADDR_CHANGE                   0x0002
#define SCTP_PRINFO     0x0007
#define SCTP_PR_SCTP_BUF  0x0002
#define SCTP_PR_SCTP_NONE 0x0000
#define SCTP_PR_SCTP_RTX  0x0003
#define SCTP_PR_SCTP_TTL  0x0001
#define SCTP_RCVINFO    0x0005
#define SCTP_RECVV_NOINFO  0
#define SCTP_RECVV_NXTINFO 2
#define SCTP_RECVV_RCVINFO 1
#define SCTP_RECVV_RN      3
#define SCTP_REMOTE_ERROR                       0x0003
#define SCTP_RESTART            0x0003
#define SCTP_SACK_IMMEDIATELY 0x4000	
#define SCTP_SENDALL          0x1000	
#define SCTP_SENDER_DRY_EVENT                   0x000a
#define SCTP_SENDV_AUTHINFO 3
#define SCTP_SENDV_NOINFO   0
#define SCTP_SENDV_PRINFO   2
#define SCTP_SENDV_SNDINFO  1
#define SCTP_SENDV_SPA      4
#define SCTP_SEND_AUTHINFO_VALID 0x00000004
#define SCTP_SEND_FAILED                        0x0004
#define SCTP_SEND_FAILED_EVENT                  0x000e
#define SCTP_SEND_PRINFO_VALID   0x00000002
#define SCTP_SEND_SNDINFO_VALID  0x00000001
#define SCTP_SHUTDOWN_COMP      0x0004
#define SCTP_SHUTDOWN_EVENT                     0x0005
#define SCTP_SNDINFO    0x0004
#define SCTP_STAT_DECR(_x) SCTP_STAT_DECR_BY(_x,1)
#define SCTP_STAT_DECR_BY(_x,_d) (SCTP_BASE_STATS[PCPU_GET(cpuid)]._x -= _d)
#define SCTP_STAT_DECR_COUNTER32(_x) SCTP_STAT_DECR(_x)
#define SCTP_STAT_DECR_COUNTER64(_x) SCTP_STAT_DECR(_x)
#define SCTP_STAT_DECR_GAUGE32(_x) SCTP_STAT_DECR(_x)
#define SCTP_STAT_INCR(_x) SCTP_STAT_INCR_BY(_x,1)
#define SCTP_STAT_INCR_BY(_x,_d) (SCTP_BASE_STATS[PCPU_GET(cpuid)]._x += _d)
#define SCTP_STAT_INCR_COUNTER32(_x) SCTP_STAT_INCR(_x)
#define SCTP_STAT_INCR_COUNTER64(_x) SCTP_STAT_INCR(_x)
#define SCTP_STAT_INCR_GAUGE32(_x) SCTP_STAT_INCR(_x)
#define SCTP_STREAM_CHANGE_EVENT                0x000d
#define SCTP_STREAM_RESET_DENIED        0x0004
#define SCTP_STREAM_RESET_EVENT                 0x0009
#define SCTP_STREAM_RESET_FAILED        0x0008
#define SCTP_STREAM_RESET_INCOMING_SSN  0x0001
#define SCTP_STREAM_RESET_OUTGOING_SSN  0x0002
#define SCTP_TRACE_PARAMS 6	
#define SCTP_UNORDERED        0x0400	
#define SPP_DSCP                0x00000200
#define SPP_HB_TIME_IS_ZERO     0x00000080
#define SPP_IPV4_TOS            SPP_DSCP
#define SPP_IPV6_FLOWLABEL      0x00000100

#define htonll(x) htobe64(x)
#define ntohll(x) be64toh(x)
#define sctp_stream_reset_events sctp_stream_reset_event
#define spp_ipv4_tos spp_dscp


#define IN_LINKLOCAL(i)		(((in_addr_t)(i) & 0xffff0000) == 0xa9fe0000)
#define IN_LOOPBACK(i)		(((in_addr_t)(i) & 0xff000000) == 0x7f000000)
#define IN_ZERONET(i)		(((in_addr_t)(i) & 0xff000000) == 0)
#define IP_FW_NAT_CFG           56   
#define IP_FW_NAT_DEL           57   
#define IP_FW_NAT_GET_CONFIG    58   
#define IP_FW_NAT_GET_LOG       59   

#define IFA6_IS_DEPRECATED(a) \
	((a)->ia6_lifetime.ia6t_pltime != ND6_INFINITE_LIFETIME && \
	 (u_int32_t)((time_uptime - (a)->ia6_updatetime)) > \
	 (a)->ia6_lifetime.ia6t_pltime)
#define IFA6_IS_INVALID(a) \
	((a)->ia6_lifetime.ia6t_vltime != ND6_INFINITE_LIFETIME && \
	 (u_int32_t)((time_uptime - (a)->ia6_updatetime)) > \
	 (a)->ia6_lifetime.ia6t_vltime)
#define IN6ADDR_ANY_INIT \
	{{{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }}}
#define IN6ADDR_INTFACELOCAL_ALLNODES_INIT \
	{{{ 0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }}}
#define IN6ADDR_LINKLOCAL_ALLNODES_INIT \
	{{{ 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }}}
#define IN6ADDR_LINKLOCAL_ALLROUTERS_INIT \
	{{{ 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 }}}
#define IN6ADDR_LINKLOCAL_ALLV2ROUTERS_INIT \
	{{{ 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16 }}}
#define IN6ADDR_LOOPBACK_INIT \
	{{{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }}}
#define IN6ADDR_NODELOCAL_ALLNODES_INIT \
	{{{ 0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }}}
#define IN6_ARE_ADDR_EQUAL(a, b)			\
    (bcmp(&(a)->s6_addr[0], &(b)->s6_addr[0], sizeof(struct in6_addr)) == 0)
#define IN6_IS_ADDR_LINKLOCAL(a)	\
	(((a)->s6_addr[0] == 0xfe) && (((a)->s6_addr[1] & 0xc0) == 0x80))
#define IN6_IS_ADDR_LOOPBACK(a)		\
	((a)->__u6_addr.__u6_addr32[0] == 0 &&	\
	 (a)->__u6_addr.__u6_addr32[1] == 0 &&	\
	 (a)->__u6_addr.__u6_addr32[2] == 0 &&	\
	 (a)->__u6_addr.__u6_addr32[3] == ntohl(1))
#define IN6_IS_ADDR_MC_GLOBAL(a)	\
	(IN6_IS_ADDR_MULTICAST(a) &&	\
	 (IPV6_ADDR_MC_SCOPE(a) == IPV6_ADDR_SCOPE_GLOBAL))
#define IN6_IS_ADDR_MC_INTFACELOCAL(a)	\
	(IN6_IS_ADDR_MULTICAST(a) &&	\
	 (IPV6_ADDR_MC_SCOPE(a) == IPV6_ADDR_SCOPE_INTFACELOCAL))
#define IN6_IS_ADDR_MC_LINKLOCAL(a)	\
	(IN6_IS_ADDR_MULTICAST(a) &&	\
	 (IPV6_ADDR_MC_SCOPE(a) == IPV6_ADDR_SCOPE_LINKLOCAL))
#define IN6_IS_ADDR_MC_NODELOCAL(a)	\
	(IN6_IS_ADDR_MULTICAST(a) &&	\
	 (IPV6_ADDR_MC_SCOPE(a) == IPV6_ADDR_SCOPE_NODELOCAL))
#define IN6_IS_ADDR_MC_ORGLOCAL(a)	\
	(IN6_IS_ADDR_MULTICAST(a) &&	\
	 (IPV6_ADDR_MC_SCOPE(a) == IPV6_ADDR_SCOPE_ORGLOCAL))
#define IN6_IS_ADDR_MC_SITELOCAL(a)	\
	(IN6_IS_ADDR_MULTICAST(a) &&	\
	 (IPV6_ADDR_MC_SCOPE(a) == IPV6_ADDR_SCOPE_SITELOCAL))
#define IN6_IS_ADDR_MULTICAST(a)	((a)->s6_addr[0] == 0xff)
#define IN6_IS_ADDR_SITELOCAL(a)	\
	(((a)->s6_addr[0] == 0xfe) && (((a)->s6_addr[1] & 0xc0) == 0xc0))
#define IN6_IS_ADDR_UNSPECIFIED(a)	\
	((a)->__u6_addr.__u6_addr32[0] == 0 &&	\
	 (a)->__u6_addr.__u6_addr32[1] == 0 &&	\
	 (a)->__u6_addr.__u6_addr32[2] == 0 &&	\
	 (a)->__u6_addr.__u6_addr32[3] == 0)
#define IN6_IS_ADDR_V4COMPAT(a)		\
	((a)->__u6_addr.__u6_addr32[0] == 0 &&	\
	 (a)->__u6_addr.__u6_addr32[1] == 0 &&	\
	 (a)->__u6_addr.__u6_addr32[2] == 0 &&	\
	 (a)->__u6_addr.__u6_addr32[3] != 0 &&	\
	 (a)->__u6_addr.__u6_addr32[3] != ntohl(1))
#define IN6_IS_ADDR_V4MAPPED(a)		      \
	((a)->__u6_addr.__u6_addr32[0] == 0 &&	\
	 (a)->__u6_addr.__u6_addr32[1] == 0 &&	\
	 (a)->__u6_addr.__u6_addr32[2] == ntohl(0x0000ffff))
#define IN6_IS_SCOPE_LINKLOCAL(a)	\
	((IN6_IS_ADDR_LINKLOCAL(a)) ||	\
	 (IN6_IS_ADDR_MC_LINKLOCAL(a)))
#define IPV6CTL_SOURCECHECK_LOGINT 11	
#define IPV6_ADDR_MC_SCOPE(a)		((a)->s6_addr[1] & 0x0f)
#define IPV6_DEFAULT_MULTICAST_HOPS 1	
#define IPV6_DEFAULT_MULTICAST_LOOP 1	
#define IPV6_RTHDR_LOOSE     0 
#define IPV6_RTHDR_STRICT    1 
#define IPV6_RTHDR_TYPE_0    0 


#define __IPV6_ADDR_MC_SCOPE(a)		((a)->s6_addr[1] & 0x0f)

#define s6_addr   __u6_addr.__u6_addr8
#define s6_addr16 __u6_addr.__u6_addr16
#define s6_addr32 __u6_addr.__u6_addr32
#define s6_addr8  __u6_addr.__u6_addr8
#define AF_VENDOR00 39
#define AF_VENDOR01 41
#define AF_VENDOR02 43
#define AF_VENDOR03 45
#define AF_VENDOR04 47
#define AF_VENDOR05 49
#define AF_VENDOR06 51
#define AF_VENDOR07 53
#define AF_VENDOR08 55
#define AF_VENDOR09 57
#define AF_VENDOR10 59
#define AF_VENDOR11 61
#define AF_VENDOR12 63
#define AF_VENDOR13 65
#define AF_VENDOR14 67
#define AF_VENDOR15 69
#define AF_VENDOR16 71
#define AF_VENDOR17 73
#define AF_VENDOR18 75
#define AF_VENDOR19 77
#define AF_VENDOR20 79
#define AF_VENDOR21 81
#define AF_VENDOR22 83
#define AF_VENDOR23 85
#define AF_VENDOR24 87
#define AF_VENDOR25 89
#define AF_VENDOR26 91
#define AF_VENDOR27 93
#define AF_VENDOR28 95
#define AF_VENDOR29 97
#define AF_VENDOR30 99
#define AF_VENDOR31 101
#define AF_VENDOR32 103
#define AF_VENDOR33 105
#define AF_VENDOR34 107
#define AF_VENDOR35 109
#define AF_VENDOR36 111
#define AF_VENDOR37 113
#define AF_VENDOR38 115
#define AF_VENDOR39 117
#define AF_VENDOR40 119
#define AF_VENDOR41 121
#define AF_VENDOR42 123
#define AF_VENDOR43 125
#define AF_VENDOR44 127
#define AF_VENDOR45 129
#define AF_VENDOR46 131
#define AF_VENDOR47 133
#define CMGROUP_MAX 16
#define PRU_FLUSH_RD     SHUT_RD
#define PRU_FLUSH_RDWR   SHUT_RDWR
#define PRU_FLUSH_WR     SHUT_WR
#define pseudo_AF_HDRCMPLT 31		
#define offsetof(type, field) __offsetof(type, field)





#define sctp_build_readq_entry_mac(_ctl, in_it, context, net, tsn, ppid, stream_no, stream_seq, flags, dm) do { \
	if (_ctl) { \
		atomic_add_int(&((net)->ref_count), 1); \
		(_ctl)->sinfo_stream = stream_no; \
		(_ctl)->sinfo_ssn = stream_seq; \
		(_ctl)->sinfo_flags = (flags << 8); \
		(_ctl)->sinfo_ppid = ppid; \
		(_ctl)->sinfo_context = context; \
		(_ctl)->sinfo_timetolive = 0; \
		(_ctl)->sinfo_tsn = tsn; \
		(_ctl)->sinfo_cumtsn = tsn; \
		(_ctl)->sinfo_assoc_id = sctp_get_associd((in_it)); \
		(_ctl)->length = 0; \
		(_ctl)->held_length = 0; \
		(_ctl)->whoFrom = net; \
		(_ctl)->data = dm; \
		(_ctl)->tail_mbuf = NULL; \
	        (_ctl)->aux_data = NULL; \
		(_ctl)->stcb = (in_it); \
		(_ctl)->port_from = (in_it)->rport; \
		(_ctl)->spec_flags = 0; \
		(_ctl)->do_not_ref_stcb = 0; \
		(_ctl)->end_added = 0; \
		(_ctl)->pdapi_aborted = 0; \
		(_ctl)->some_taken = 0; \
	} \
} while (0)


#define SCTP_ADDRESS_SIZE 4
#define SCTP_ARRAY_MIN_LEN 1
#define SCTP_IDENTIFICATION_SIZE 16
#define SCTP_MAX_ADDR_PARAMS_SIZE 12
#define SCTP_MAX_OVERHEAD (sizeof(struct sctp_data_chunk) + \
			   sizeof(struct sctphdr) + \
			   sizeof(struct sctp_ecne_chunk) + \
			   sizeof(struct sctp_sack_chunk) + \
			   sizeof(struct ip6_hdr))
#define SCTP_MAX_SUPPORTED_EXT 256
#define SCTP_MED_OVERHEAD (sizeof(struct sctp_data_chunk) + \
			   sizeof(struct sctphdr) + \
			   sizeof(struct ip6_hdr))
#define SCTP_MED_V4_OVERHEAD (sizeof(struct sctp_data_chunk) + \
			      sizeof(struct sctphdr) + \
			      sizeof(struct ip))
#define SCTP_MIN_OVERHEAD (sizeof(struct ip6_hdr) + \
			   sizeof(struct sctphdr))
#define SCTP_MIN_V4_OVERHEAD (sizeof(struct ip) + \
			      sizeof(struct sctphdr))
#define SCTP_NUM_DB_TO_VERIFY 31
#define SCTP_PACKED __attribute__((packed))
#define SCTP_RANDOM_MAX_SIZE 256
#define SCTP_RESERVE_SPACE 6
#define SCTP_STREAM_RESET_RESULT_DENIED          0x00000002
#define SCTP_STREAM_RESET_RESULT_ERR_BAD_SEQNO   0x00000005
#define SCTP_STREAM_RESET_RESULT_ERR_IN_PROGRESS 0x00000004
#define SCTP_STREAM_RESET_RESULT_ERR__WRONG_SSN  0x00000003	
#define SCTP_STREAM_RESET_RESULT_IN_PROGRESS     0x00000006	
#define SCTP_STREAM_RESET_RESULT_NOTHING_TO_DO   0x00000000	
#define SCTP_STREAM_RESET_RESULT_PERFORMED       0x00000001
#define SCTP_V6_ADDR_BYTES 16

#define IN4_ISLINKLOCAL_ADDRESS(a) \
    ((((uint8_t *)&(a)->s_addr)[0] == 169) && \
     (((uint8_t *)&(a)->s_addr)[1] == 254))
#define IN4_ISLOOPBACK_ADDRESS(a) \
    ((((uint8_t *)&(a)->s_addr)[0] == 127) && \
     (((uint8_t *)&(a)->s_addr)[1] == 0) && \
     (((uint8_t *)&(a)->s_addr)[2] == 0) && \
     (((uint8_t *)&(a)->s_addr)[3] == 1))
#define IN4_ISPRIVATE_ADDRESS(a) \
   ((((uint8_t *)&(a)->s_addr)[0] == 10) || \
    ((((uint8_t *)&(a)->s_addr)[0] == 172) && \
     (((uint8_t *)&(a)->s_addr)[1] >= 16) && \
     (((uint8_t *)&(a)->s_addr)[1] <= 32)) || \
    ((((uint8_t *)&(a)->s_addr)[0] == 192) && \
     (((uint8_t *)&(a)->s_addr)[1] == 168)))
#define IPPROTO_SCTP 132	
#define IP_HDR_SIZE 40		
#define IS_SCTP_CONTROL(a) ((a)->chunk_type != SCTP_DATA)
#define IS_SCTP_DATA(a) ((a)->chunk_type == SCTP_DATA)
#define MSEC_TO_TICKS(x) ((hz == 1000) ? x : ((((x) * hz) + 999) / 1000))
#define SCTP_ADDRESS_LIMIT 1080
#define SCTP_ADDRESS_TICK_DELAY 2
#define SCTP_ADDR_DYNAMIC_ADDED 6
#define SCTP_ADDR_IS_CONFIRMED 8
#define SCTP_ADDR_LOCKED 1
#define SCTP_ADDR_NOT_LOCKED 0
#define SCTP_ADDR_NO_PMTUD              0x002
#define SCTP_ADDR_PF                    0x800
#define SCTP_ADDR_REQ_PRIMARY           0x400
#define SCTP_ADD_SUBSTATE(asoc, substate) ((asoc)->state |= substate)
#define SCTP_ALLOC_ASOC  1
#define SCTP_ASOC_KILL_TIMEOUT 10	
#define SCTP_ASOC_MAX_CHUNKS_ON_QUEUE 512
#define SCTP_AT_END_OF_SACK         79
#define SCTP_AUDIT_SIZE 256
#define SCTP_BLOCK_LOG_CHECK     9
#define SCTP_BLOCK_LOG_INTO_BLK 7
#define SCTP_BLOCK_LOG_INTO_BLKA    81
#define SCTP_BLOCK_LOG_OUTOF_BLK 8
#define SCTP_CALC_TSN_TO_GAP(gap, tsn, mapping_tsn) do { \
	                if (tsn >= mapping_tsn) { \
						gap = tsn - mapping_tsn; \
					} else { \
						gap = (MAX_TSN - mapping_tsn) + tsn + 1; \
					} \
                  } while (0)
#define SCTP_CALLED_AFTER_CMPSET_OFCLOSE  1
#define SCTP_CALLED_DIRECTLY_NOCMPSET     0
#define SCTP_CALLED_FROM_INPKILL_TIMER    2
#define SCTP_CHUNKQUEUE_SCALE 10
#define SCTP_CLEAR_SUBSTATE(asoc, substate) ((asoc)->state &= ~substate)
#define SCTP_COUNT_LIMIT 40
#define SCTP_CWNDLOG_ENDSEND        78
#define SCTP_CWNDLOG_PRESEND        77
#define SCTP_CWND_INITIALIZATION    62
#define SCTP_CWND_LOG_FILL_OUTQ_CALLED 69
#define SCTP_CWND_LOG_FILL_OUTQ_FILLS  70
#define SCTP_CWND_LOG_FROM_RESEND   66
#define SCTP_CWND_LOG_FROM_SACK     64
#define SCTP_CWND_LOG_FROM_SEND     61
#define SCTP_CWND_LOG_FROM_T3       63
#define SCTP_CWND_LOG_NOADV_CA      32
#define SCTP_CWND_LOG_NOADV_SS      31
#define SCTP_CWND_LOG_NO_CUMACK     65
#define SCTP_DECREASE_PEER_RWND     37
#define SCTP_DEFAULT_ADD_MORE 1452
#define SCTP_DEFAULT_MAXSEGMENT 65535
#define SCTP_DEFAULT_MBUFS_IN_CHAIN 5
#define SCTP_DEFAULT_MTU 1500	
#define SCTP_DEFAULT_SACK_FREQ 2
#define SCTP_DEFAULT_SECRET_LIFE_SEC 3600
#define SCTP_DEFAULT_SPLIT_POINT_MIN 2904
#define SCTP_DEFAULT_VRF_SIZE 4
#define SCTP_DEF_ASOC_RESC_LIMIT 10
#define SCTP_DEF_FRMAX_BURST 4
#define SCTP_DEF_HBMAX_BURST 4
#define SCTP_DEF_MAX_BURST 4
#define SCTP_DEF_MAX_SHUTDOWN_SEC 180
#define SCTP_DEF_SYSTEM_RESC_LIMIT 1000
#define SCTP_DIAG_INFO_LEN 64
#define SCTP_DONOT_SETSCOPE 0
#define SCTP_DO_SETSCOPE 1
#define SCTP_ENTER_USER_RECV        82
#define SCTP_FIRST_MBUF_RESV 68
#define SCTP_FLIGHT_LOG_DOWN_CA    107
#define SCTP_FLIGHT_LOG_DOWN_GAP   109
#define SCTP_FLIGHT_LOG_DOWN_PDRP  115
#define SCTP_FLIGHT_LOG_DOWN_PMTU  116
#define SCTP_FLIGHT_LOG_DOWN_RSND  110
#define SCTP_FLIGHT_LOG_DOWN_RSND_TO    112
#define SCTP_FLIGHT_LOG_DOWN_WP    113
#define SCTP_FLIGHT_LOG_DWN_WP_FWD 122
#define SCTP_FLIGHT_LOG_UP         108
#define SCTP_FLIGHT_LOG_UP_REVOKE  114
#define SCTP_FLIGHT_LOG_UP_RSND    111
#define SCTP_FREE_SHOULD_USE_ABORT          1
#define SCTP_FREE_SHOULD_USE_GRACEFUL_CLOSE 0
#define SCTP_FROM_SCTP6_USRREQ 0x70000000
#define SCTP_FROM_SCTPUTIL     0x60000000
#define SCTP_FROM_SCTP_ASCONF  0x80000000
#define SCTP_FROM_SCTP_INDATA  0x30000000
#define SCTP_FROM_SCTP_INPUT   0x10000000
#define SCTP_FROM_SCTP_OUTPUT  0x90000000
#define SCTP_FROM_SCTP_PANDA   0xb0000000
#define SCTP_FROM_SCTP_PCB     0x20000000
#define SCTP_FROM_SCTP_PEELOFF 0xa0000000
#define SCTP_FROM_SCTP_SYSCTL  0xc0000000
#define SCTP_FROM_SCTP_TIMER   0x40000000
#define SCTP_FROM_SCTP_USRREQ  0x50000000
#define SCTP_FR_CWND_REPORT         58
#define SCTP_FR_CWND_REPORT_START   59
#define SCTP_FR_CWND_REPORT_STOP    60
#define SCTP_FR_DUPED               56
#define SCTP_FR_LOG_BIGGEST_TSNS    17
#define SCTP_FR_LOG_CHECK_STRIKE    67
#define SCTP_FR_LOG_STRIKE_CHUNK    19
#define SCTP_FR_LOG_STRIKE_TEST     18
#define SCTP_FR_MARKED              30
#define SCTP_FR_MARKED_EARLY        57
#define SCTP_FR_T3_MARKED           27
#define SCTP_FR_T3_MARK_TIME        26
#define SCTP_FR_T3_STOPPED          28
#define SCTP_FR_T3_TIMEOUT          20
#define SCTP_FWD_TSN_CHECK         123
#define SCTP_GETPTIME_TIMEVAL(x) (microuptime(x))
#define SCTP_GETTIME_TIMEVAL(x) (getmicrouptime(x))
#define SCTP_GET_STATE(asoc)	((asoc)->state & SCTP_STATE_MASK)
#define SCTP_HAS_NAT_SUPPORT            0xc007
#define SCTP_HOLDS_LOCK 1
#define SCTP_IGNORE_CWND_ON_FR 1
#define SCTP_INCREASE_PEER_RWND     36
#define SCTP_INITIAL_CWND 4380
#define SCTP_INITIAL_MAPPING_ARRAY  16
#define SCTP_INP_KILL_TIMEOUT 20
#define SCTP_IN_COOKIE_PROC 100
#define SCTP_ISTREAM_INITIAL 2048
#define SCTP_IS_TIMER_TYPE_VALID(t)	(((t) > SCTP_TIMER_TYPE_NONE) && \
					 ((t) < SCTP_TIMER_TYPE_LAST))
#define SCTP_IS_TSN_PRESENT(arry, gap) ((arry[(gap >> 3)] >> (gap & 0x07)) & 0x01)
#define SCTP_ITERATOR_MAX_AT_ONCE 20
#define SCTP_ITERATOR_TICKS 1
#define SCTP_KTHREAD_PAGES 0
#define SCTP_KTRHEAD_NAME "sctp_iterator"
#define SCTP_LAN_INTERNET 2
#define SCTP_LAN_LOCAL    1
#define SCTP_LAN_UNKNOWN  0
#define SCTP_LARGEST_INIT_ACCEPTED (65535 - 2048)
#define SCTP_LOAD_ADDR_2 2
#define SCTP_LOAD_ADDR_3 3
#define SCTP_LOAD_ADDR_4 4
#define SCTP_LOAD_ADDR_5 5
#define SCTP_LOCAL_LAN_RTT 900
#define SCTP_LOCK_UNKNOWN 2
#define SCTP_LOC_1  0x00000001
#define SCTP_LOC_10 0x0000000a
#define SCTP_LOC_11 0x0000000b
#define SCTP_LOC_12 0x0000000c
#define SCTP_LOC_13 0x0000000d
#define SCTP_LOC_14 0x0000000e
#define SCTP_LOC_15 0x0000000f
#define SCTP_LOC_16 0x00000010
#define SCTP_LOC_17 0x00000011
#define SCTP_LOC_18 0x00000012
#define SCTP_LOC_19 0x00000013
#define SCTP_LOC_2  0x00000002
#define SCTP_LOC_20 0x00000014
#define SCTP_LOC_21 0x00000015
#define SCTP_LOC_22 0x00000016
#define SCTP_LOC_23 0x00000017
#define SCTP_LOC_24 0x00000018
#define SCTP_LOC_25 0x00000019
#define SCTP_LOC_26 0x0000001a
#define SCTP_LOC_27 0x0000001b
#define SCTP_LOC_28 0x0000001c
#define SCTP_LOC_29 0x0000001d
#define SCTP_LOC_3  0x00000003
#define SCTP_LOC_30 0x0000001e
#define SCTP_LOC_31 0x0000001f
#define SCTP_LOC_32 0x00000020
#define SCTP_LOC_33 0x00000021
#define SCTP_LOC_4  0x00000004
#define SCTP_LOC_5  0x00000005
#define SCTP_LOC_6  0x00000006
#define SCTP_LOC_7  0x00000007
#define SCTP_LOC_8  0x00000008
#define SCTP_LOC_9  0x00000009
#define SCTP_LOG_CHUNK_PROC 18
#define SCTP_LOG_ERROR_RET  19
#define SCTP_LOG_EVENT_BLOCK 2
#define SCTP_LOG_EVENT_CLOSE 16
#define SCTP_LOG_EVENT_CWND  1
#define SCTP_LOG_EVENT_FR    4
#define SCTP_LOG_EVENT_MAP   5
#define SCTP_LOG_EVENT_MAXBURST 6
#define SCTP_LOG_EVENT_MBCNT 8
#define SCTP_LOG_EVENT_MBUF 17
#define SCTP_LOG_EVENT_NAGLE 13
#define SCTP_LOG_EVENT_RTT  11
#define SCTP_LOG_EVENT_RWND  7
#define SCTP_LOG_EVENT_SACK  9
#define SCTP_LOG_EVENT_SB   12
#define SCTP_LOG_EVENT_STRM  3
#define SCTP_LOG_EVENT_UNKNOWN 0
#define SCTP_LOG_EVENT_WAKE 14
#define SCTP_LOG_FREE_SENT             71
#define SCTP_LOG_INITIAL_RTT        51
#define SCTP_LOG_LOCK_CREATE        50
#define SCTP_LOG_LOCK_EVENT 10
#define SCTP_LOG_LOCK_INP           46
#define SCTP_LOG_LOCK_SOCK          47
#define SCTP_LOG_LOCK_SOCKBUF_R     48
#define SCTP_LOG_LOCK_SOCKBUF_S     49
#define SCTP_LOG_LOCK_TCB           45
#define SCTP_LOG_MAX_EVENT 20
#define SCTP_LOG_MAX_TYPES 124
#define SCTP_LOG_MBCNT_CHKSET       41
#define SCTP_LOG_MBCNT_DECREASE     40
#define SCTP_LOG_MBCNT_INCREASE     39
#define SCTP_LOG_MISC_EVENT 15
#define SCTP_LOG_NEW_SACK           42
#define SCTP_LOG_RTTVAR             52
#define SCTP_LOG_SBALLOC            53
#define SCTP_LOG_SBFREE             54
#define SCTP_LOG_SBRESULT           55
#define SCTP_LOG_TSN_ACKED          43
#define SCTP_LOG_TSN_REVOKED        44
#define SCTP_MAPPING_ARRAY_INCR     32
#define SCTP_MAP_PREPARE_SLIDE      21
#define SCTP_MAP_SLIDE_FROM         22
#define SCTP_MAP_SLIDE_NONE         25
#define SCTP_MAP_SLIDE_RESULT       23
#define SCTP_MAP_TSN_ENTERS        119
#define SCTP_MAX_BURST_APPLIED      33
#define SCTP_MAX_BURST_ERROR_STOP   35
#define SCTP_MAX_IFP_APPLIED        34
#define SCTP_MAX_RESET_PARAMS 2
#define SCTP_MBUF_IALLOC            91
#define SCTP_MBUF_ICOPY             93
#define SCTP_MBUF_IFREE             92
#define SCTP_MBUF_INPUT             90
#define SCTP_MBUF_SPLIT             94
#define SCTP_MCORE_NAME "sctp_core_worker"
#define SCTP_MINFR_MSEC_FLOOR 20
#define SCTP_MINFR_MSEC_TIMER 250
#define SCTP_NAGLE_APPLIED          72
#define SCTP_NAGLE_SKIPPED          73
#define SCTP_NAT_VTAGS                  0xc008
#define SCTP_NORMAL_PROC      0
#define SCTP_NOTIFY_ASCONF_ADD_IP               12
#define SCTP_NOTIFY_ASCONF_DELETE_IP            13
#define SCTP_NOTIFY_ASCONF_SET_PRIMARY          14
#define SCTP_NOTIFY_ASSOC_DOWN                   2
#define SCTP_NOTIFY_ASSOC_LOC_ABORTED            8
#define SCTP_NOTIFY_ASSOC_REM_ABORTED            9
#define SCTP_NOTIFY_ASSOC_RESTART               10
#define SCTP_NOTIFY_ASSOC_UP                     1
#define SCTP_NOTIFY_AUTH_FREE_KEY               24
#define SCTP_NOTIFY_AUTH_NEW_KEY                23
#define SCTP_NOTIFY_INTERFACE_CONFIRMED         16
#define SCTP_NOTIFY_INTERFACE_DOWN               3
#define SCTP_NOTIFY_INTERFACE_UP                 4
#define SCTP_NOTIFY_NO_PEER_AUTH                25
#define SCTP_NOTIFY_PARTIAL_DELVIERY_INDICATION 15
#define SCTP_NOTIFY_PEER_SHUTDOWN               11
#define SCTP_NOTIFY_REMOTE_ERROR                27
#define SCTP_NOTIFY_SENDER_DRY                  26
#define SCTP_NOTIFY_SENT_DG_FAIL                 5
#define SCTP_NOTIFY_SPECIAL_SP_FAIL              7
#define SCTP_NOTIFY_STR_RESET_DENIED_IN         22
#define SCTP_NOTIFY_STR_RESET_DENIED_OUT        21
#define SCTP_NOTIFY_STR_RESET_FAILED_IN         20
#define SCTP_NOTIFY_STR_RESET_FAILED_OUT        19
#define SCTP_NOTIFY_STR_RESET_RECV              17
#define SCTP_NOTIFY_STR_RESET_SEND              18
#define SCTP_NOTIFY_UNSENT_DG_FAIL               6
#define SCTP_NOT_LOCKED 0
#define SCTP_NOWAKE_FROM_SACK       76
#define SCTP_NO_FR_UNLESS_SEGMENT_SMALLER 1
#define SCTP_NUMBER_IN_VTAG_BLOCK 15
#define SCTP_OSTREAM_INITIAL 10
#define SCTP_OUTPUT_FROM_ASCONF_TMR     8
#define SCTP_OUTPUT_FROM_AUTOCLOSE_TMR  10
#define SCTP_OUTPUT_FROM_CLOSING        16
#define SCTP_OUTPUT_FROM_CONTROL_PROC   3
#define SCTP_OUTPUT_FROM_COOKIE_ACK     14
#define SCTP_OUTPUT_FROM_DRAIN          15
#define SCTP_OUTPUT_FROM_EARLY_FR_TMR   11
#define SCTP_OUTPUT_FROM_HB_TMR         6
#define SCTP_OUTPUT_FROM_INPUT_ERROR    2
#define SCTP_OUTPUT_FROM_SACK_TMR       4
#define SCTP_OUTPUT_FROM_SHUT_ACK_TMR   7
#define SCTP_OUTPUT_FROM_SHUT_TMR       5
#define SCTP_OUTPUT_FROM_SOCKOPT        17
#define SCTP_OUTPUT_FROM_STRRST_REQ     12
#define SCTP_OUTPUT_FROM_STRRST_TMR     9
#define SCTP_OUTPUT_FROM_T3       	1
#define SCTP_OUTPUT_FROM_USR_RCVD       13
#define SCTP_OUTPUT_FROM_USR_SEND       0
#define SCTP_OVER_UDP_TUNNELING_PORT 9899
#define SCTP_PARTIAL_DELIVERY_SHIFT 1
#define SCTP_PCBFREE_FORCE    2
#define SCTP_PCBFREE_NOFORCE  1
#define SCTP_PCBHASHSIZE 256
#define SCTP_RANDY_STUFF           103
#define SCTP_RANDY_STUFF1          104
#define SCTP_REASON_FOR_SC          80
#define SCTP_RECV_BUFFER_SPLITTING 0x00000002
#define SCTP_RETRAN_DONE -1
#define SCTP_RETRAN_EXIT -2
#define SCTP_RETRY_DROPPED_THRESH 4
#define SCTP_RTT_FROM_DATA     1
#define SCTP_RTT_FROM_NON_DATA 0
#define SCTP_RWND_HIWAT_SHIFT 3
#define SCTP_SACK_RWND_UPDATE       87
#define SCTP_SEND_BUFFER_SPLITTING 0x00000001
#define SCTP_SEND_NOW_COMPLETES     68
#define SCTP_SET_PEER_RWND_VIA_SACK 38
#define SCTP_SET_STATE(asoc, newstate)  ((asoc)->state = ((asoc)->state & ~SCTP_STATE_MASK) |  newstate)
#define SCTP_SET_TSN_PRESENT(arry, gap) (arry[(gap >> 3)] |= (0x01 << ((gap & 0x07))))
#define SCTP_SIGNATURE_ALOC_SIZE SCTP_SIGNATURE_SIZE
#define SCTP_SIZE32(x)	((((x) + 3) >> 2) << 2)
#define SCTP_SMALL_CHUNK_STORE 260
#define SCTP_SORCV_ADJD            101
#define SCTP_SORCV_BOTWHILE         99
#define SCTP_SORCV_DOESADJ          98
#define SCTP_SORCV_DOESCPY          96
#define SCTP_SORCV_DOESLCK          97
#define SCTP_SORCV_FREECTL          95
#define SCTP_SORCV_PASSBF          100
#define SCTP_SORECV_BLOCKSA         84
#define SCTP_SORECV_BLOCKSB         85
#define SCTP_SORECV_DONE            86
#define SCTP_SORECV_ENTER           88
#define SCTP_SORECV_ENTERPL         89
#define SCTP_SSN_GE(a, b) (SCTP_SSN_GT(a, b) || (a == b))
#define SCTP_SSN_GT(a, b) (((a < b) && ((uint16_t)(b - a) > (1U<<15))) || \
                           ((a > b) && ((uint16_t)(a - b) < (1U<<15))))
#define SCTP_STACK_VTAG_HASH_SIZE   32
#define SCTP_STATE_ABOUT_TO_BE_FREED    0x0200
#define SCTP_STATE_IN_ACCEPT_QUEUE      0x1000
#define SCTP_STATE_PARTIAL_MSG_LEFT     0x0400
#define SCTP_STATE_WAS_ABORTED          0x0800
#define SCTP_STREAM_RESET_TSN_DELTA    0x1000
#define SCTP_STR_LOG_FROM_EXPRS_DEL 16
#define SCTP_STR_LOG_FROM_IMMED_DEL 11
#define SCTP_STR_LOG_FROM_INSERT_HD 12
#define SCTP_STR_LOG_FROM_INSERT_MD 13
#define SCTP_STR_LOG_FROM_INSERT_TL 14
#define SCTP_STR_LOG_FROM_INTO_STRD 10
#define SCTP_STR_LOG_FROM_MARK_TSN  15
#define SCTP_STR_RESET_ADD_IN_STREAMS   0x0012
#define SCTP_SUPPORTED_CHUNK_EXT    0x8008
#define SCTP_TCBHASHSIZE 1024
#define SCTP_THRESHOLD_CLEAR       120
#define SCTP_THRESHOLD_INCR        121
#define SCTP_TIMER_INIT 	0
#define SCTP_TIMER_RECV 	1
#define SCTP_TIMER_SEND 	2
#define SCTP_TIMER_TYPE_ADDR_WQ         17
#define SCTP_TIMER_TYPE_ASOCKILL        16
#define SCTP_TIMER_TYPE_INPKILL         15
#define SCTP_TIMER_TYPE_LAST            21
#define SCTP_TIMER_TYPE_PRIM_DELETED    20
#define SCTP_TIMER_TYPE_STRRESET        14
#define SCTP_TIMER_TYPE_ZCOPY_SENDQ     19
#define SCTP_TIMER_TYPE_ZERO_COPY       18
#define SCTP_TIME_WAIT 60
#define SCTP_TSN_GE(a, b) (SCTP_TSN_GT(a, b) || (a == b))
#define SCTP_TSN_GT(a, b) (((a < b) && ((uint32_t)(b - a) > (1U<<31))) || \
                           ((a > b) && ((uint32_t)(a - b) < (1U<<31))))
#define SCTP_UNKNOWN_MAX           102
#define SCTP_UNSET_TSN_PRESENT(arry, gap) (arry[(gap >> 3)] &= ((~(0x01 << ((gap & 0x07)))) & 0xff))
#define SCTP_USER_RECV_SACKS        83
#define SCTP_VERSION_STRING "KAME-BSD 1.1"
#define SCTP_WAKESND_FROM_FWDTSN    75
#define SCTP_WAKESND_FROM_SACK      74
#define SCTP_ZERO_COPY_SENDQ_TICK_DELAY (((100 * hz) + 999) / 1000)
#define SCTP_ZERO_COPY_TICK_DELAY (((100 * hz) + 999) / 1000)
#define SEC_TO_TICKS(x) ((x) * hz)
#define TICKS_TO_MSEC(x) ((hz == 1000) ? x : ((((x) * 1000) + (hz - 1)) / hz))
#define TICKS_TO_SEC(x) (((x) + (hz - 1)) / hz)

#define sctp_align_safe_nocopy 0
#define sctp_align_unsafe_makecopy 1
#define sctp_sorwakeup(inp, so) \
do { \
	if (inp->sctp_flags & SCTP_PCB_FLAGS_DONT_WAKE) { \
		inp->sctp_flags |= SCTP_PCB_FLAGS_WAKEINPUT; \
	} else { \
		sorwakeup(so); \
	} \
} while (0)
#define sctp_sorwakeup_locked(inp, so) \
do { \
	if (inp->sctp_flags & SCTP_PCB_FLAGS_DONT_WAKE) { \
		inp->sctp_flags |= SCTP_PCB_FLAGS_WAKEINPUT; \
                SOCKBUF_UNLOCK(&((so)->so_rcv)); \
	} else { \
		sorwakeup_locked(so); \
	} \
} while (0)
#define sctp_sowwakeup(inp, so) \
do { \
	if (inp->sctp_flags & SCTP_PCB_FLAGS_DONT_WAKE) { \
		inp->sctp_flags |= SCTP_PCB_FLAGS_WAKEOUTPUT; \
	} else { \
		sowwakeup(so); \
	} \
} while (0)
#define sctp_sowwakeup_locked(inp, so) \
do { \
	if (inp->sctp_flags & SCTP_PCB_FLAGS_DONT_WAKE) { \
                SOCKBUF_UNLOCK(&((so)->so_snd)); \
		inp->sctp_flags |= SCTP_PCB_FLAGS_WAKEOUTPUT; \
	} else { \
		sowwakeup_locked(so); \
	} \
} while (0)
#define SCTP_AUTHENTICATION     0x0f
#define SCTP_AUTH_ACTIVE_KEY 		0x00000015
#define SCTP_AUTH_CHUNK 		0x00000012
#define SCTP_AUTH_DELETE_KEY 		0x00000016
#define SCTP_AUTH_KEY 			0x00000013
#define SCTP_CAUSE_NAT_COLLIDING_STATE  0x00b0
#define SCTP_CAUSE_NAT_MISSING_STATE    0x00b1
#define SCTP_CC_OPT_STEADY_STEP         0x00002002
#define SCTP_CC_RTCC            0x00000003
#define SCTP_CLR_STAT_LOG               0x00001007
#define SCTP_CMT_BASE           1
#define SCTP_CMT_MAX            SCTP_CMT_MPTCP
#define SCTP_CMT_MPTCP          4
#define SCTP_CMT_OFF            0
#define SCTP_CMT_ON_OFF                 0x00001200
#define SCTP_CMT_RPV1           2
#define SCTP_CMT_RPV2           3
#define SCTP_CMT_USE_DAC                0x00001201
#define SCTP_CONNECT_X_COMPLETE         0x00008009
#define SCTP_CONTEXT                    0x0000001a	
#define SCTP_CWR_IN_SAME_WINDOW  0x02
#define SCTP_CWR_REDUCE_OVERRIDE 0x01
#define SCTP_DATA_FIRST_FRAG       0x02
#define SCTP_DATA_FRAG_MASK        0x03
#define SCTP_DATA_LAST_FRAG        0x01
#define SCTP_DATA_MIDDLE_FRAG      0x00
#define SCTP_DATA_NOT_FRAG         0x03
#define SCTP_DATA_SACK_IMMEDIATELY 0x08
#define SCTP_DATA_UNORDERED        0x04
#define SCTP_DEFAULT_PRINFO             0x00000022
#define SCTP_DEFAULT_SNDINFO            0x00000021
#define SCTP_DELAYED_SACK               0x0000000f
#define SCTP_DEL_VRF_ID                 0x00003005
#define SCTP_ENABLE_CHANGE_ASSOC_REQ 	0x00000004
#define SCTP_ENABLE_RESET_ASSOC_REQ 	0x00000002
#define SCTP_ENABLE_RESET_STREAM_REQ 	0x00000001
#define SCTP_EVENT                      0x0000001e
#define SCTP_EXPLICIT_EOR               0x0000001b
#define SCTP_FRAGMENT_INTERLEAVE        0x00000010
#define SCTP_FRAG_LEVEL_0    0x00000000
#define SCTP_FRAG_LEVEL_1    0x00000001
#define SCTP_FRAG_LEVEL_2    0x00000002
#define SCTP_GET_ADDR_LEN               0x0000800b
#define SCTP_GET_ASOC_VRF               0x00003004
#define SCTP_GET_ASSOC_ID_LIST          0x00000105	
#define SCTP_GET_ASSOC_NUMBER           0x00000104	
#define SCTP_GET_NONCE_VALUES           0x00001105
#define SCTP_GET_PACKET_LOG             0x00004001
#define SCTP_HMAC_IDENT 		0x00000014
#define SCTP_LOCAL_AUTH_CHUNKS 		0x00000103
#define SCTP_LOG_RWND_ENABLE    			0x00100000
#define SCTP_MAXSEG 			0x0000000e
#define SCTP_MAX_COOKIE_LIFE  3600000	
#define SCTP_MAX_HB_INTERVAL 14400000	
#define SCTP_MAX_SACK_DELAY 500	
#define SCTP_MOBILITY_BASE               0x00000001
#define SCTP_MOBILITY_FASTHANDOFF        0x00000002
#define SCTP_MOBILITY_PRIM_DELETED       0x00000004
#define SCTP_PACKET_LOG_SIZE 65536
#define SCTP_PAD_CHUNK          0x84
#define SCTP_PARTIAL_DELIVERY_POINT     0x00000011
#define SCTP_PCB_FLAGS_ADAPTATIONEVNT    0x0000000000010000
#define SCTP_PCB_FLAGS_ASSOC_RESETEVNT   0x0000000020000000
#define SCTP_PCB_FLAGS_AUTHEVNT          0x0000000000040000
#define SCTP_PCB_FLAGS_AUTOCLOSE         0x0000000000000200
#define SCTP_PCB_FLAGS_AUTO_ASCONF       0x0000000000000040
#define SCTP_PCB_FLAGS_CLOSE_IP         0x00040000
#define SCTP_PCB_FLAGS_DONOT_HEARTBEAT   0x0000000000000004
#define SCTP_PCB_FLAGS_DO_ASCONF         0x0000000000000020
#define SCTP_PCB_FLAGS_DO_NOT_PMTUD      0x0000000000000001
#define SCTP_PCB_FLAGS_DRYEVNT           0x0000000004000000
#define SCTP_PCB_FLAGS_EXPLICIT_EOR      0x0000000000400000
#define SCTP_PCB_FLAGS_EXT_RCVINFO       0x0000000000000002	
#define SCTP_PCB_FLAGS_FRAG_INTERLEAVE   0x0000000000000008
#define SCTP_PCB_FLAGS_INTERLEAVE_STRMS  0x0000000000000010
#define SCTP_PCB_FLAGS_MULTIPLE_ASCONFS  0x0000000001000000
#define SCTP_PCB_FLAGS_NEEDS_MAPPED_V4   0x0000000000800000
#define SCTP_PCB_FLAGS_NODELAY           0x0000000000000100
#define SCTP_PCB_FLAGS_NO_FRAGMENT       0x0000000000100000
#define SCTP_PCB_FLAGS_PDAPIEVNT         0x0000000000020000
#define SCTP_PCB_FLAGS_PORTREUSE         0x0000000002000000
#define SCTP_PCB_FLAGS_RECVASSOCEVNT     0x0000000000000800
#define SCTP_PCB_FLAGS_RECVDATAIOEVNT    0x0000000000000400	
#define SCTP_PCB_FLAGS_RECVNSENDFAILEVNT 0x0000000080000000
#define SCTP_PCB_FLAGS_RECVNXTINFO       0x0000000010000000
#define SCTP_PCB_FLAGS_RECVPADDREVNT     0x0000000000001000
#define SCTP_PCB_FLAGS_RECVPEERERR       0x0000000000002000
#define SCTP_PCB_FLAGS_RECVRCVINFO       0x0000000008000000
#define SCTP_PCB_FLAGS_RECVSENDFAILEVNT  0x0000000000004000	
#define SCTP_PCB_FLAGS_RECVSHUTDOWNEVNT  0x0000000000008000
#define SCTP_PCB_FLAGS_STREAM_CHANGEEVNT 0x0000000040000000
#define SCTP_PCB_FLAGS_STREAM_RESETEVNT  0x0000000000080000
#define SCTP_PCB_FLAGS_WAS_ABORTED      0x00100000
#define SCTP_PCB_FLAGS_WAS_CONNECTED    0x00080000
#define SCTP_PCB_FLAGS_ZERO_COPY_ACTIVE  0x0000000000000080
#define SCTP_PEELOFF                    0x0000800a
#define SCTP_PEER_ADDR_PARAMS 		0x0000000a
#define SCTP_PEER_ADDR_THLDS            0x00000023
#define SCTP_PEER_AUTH_CHUNKS 		0x00000102
#define SCTP_PLUGGABLE_CC               0x00001202
#define SCTP_RECVNXTINFO                0x00000020
#define SCTP_RECVRCVINFO                0x0000001f
#define SCTP_REMOTE_UDP_ENCAPS_PORT     0x00000024
#define SCTP_REUSE_PORT                 0x0000001c	
#define SCTP_SACK_CMT_DAC          0x80
#define SCTP_SACK_NONCE_SUM        0x01
#define SCTP_SAT_NETWORK_BURST_INCR  2	
#define SCTP_SET_DYNAMIC_PRIMARY        0x00002001
#define SCTP_SMALLEST_PMTU 512	
#define SCTP_STREAM_RESET       0x82
#define SCTP_TIMEOUTS                   0x00000106




#define SCTP_READ_LOCK_HELD 1
#define SCTP_READ_LOCK_NOT_HELD 0

#define sctp_free_bufspace(stcb, asoc, tp1, chk_cnt)  \
do { \
	if (tp1->data != NULL) { \
                atomic_subtract_int(&((asoc)->chunks_on_out_queue), chk_cnt); \
		if ((asoc)->total_output_queue_size >= tp1->book_size) { \
			atomic_subtract_int(&((asoc)->total_output_queue_size), tp1->book_size); \
		} else { \
			(asoc)->total_output_queue_size = 0; \
		} \
   	        if (stcb->sctp_socket && ((stcb->sctp_ep->sctp_flags & SCTP_PCB_FLAGS_TCPTYPE) || \
	            (stcb->sctp_ep->sctp_flags & SCTP_PCB_FLAGS_IN_TCPPOOL))) { \
			if (stcb->sctp_socket->so_snd.sb_cc >= tp1->book_size) { \
				atomic_subtract_int(&((stcb)->sctp_socket->so_snd.sb_cc), tp1->book_size); \
			} else { \
				stcb->sctp_socket->so_snd.sb_cc = 0; \
			} \
		} \
        } \
} while (0)
#define sctp_free_spbufspace(stcb, asoc, sp)  \
do { \
 	if (sp->data != NULL) { \
		if ((asoc)->total_output_queue_size >= sp->length) { \
			atomic_subtract_int(&(asoc)->total_output_queue_size, sp->length); \
		} else { \
			(asoc)->total_output_queue_size = 0; \
		} \
   	        if (stcb->sctp_socket && ((stcb->sctp_ep->sctp_flags & SCTP_PCB_FLAGS_TCPTYPE) || \
	            (stcb->sctp_ep->sctp_flags & SCTP_PCB_FLAGS_IN_TCPPOOL))) { \
			if (stcb->sctp_socket->so_snd.sb_cc >= sp->length) { \
				atomic_subtract_int(&stcb->sctp_socket->so_snd.sb_cc,sp->length); \
			} else { \
				stcb->sctp_socket->so_snd.sb_cc = 0; \
			} \
		} \
        } \
} while (0)
#define sctp_get_associd(stcb) ((sctp_assoc_t)stcb->asoc.assoc_id)
#define sctp_m_free m_free
#define sctp_m_freem m_freem
#define sctp_recover_scope_mac(addr, store) do { \
	 if ((addr->sin6_family == AF_INET6) && \
	     (IN6_IS_SCOPE_LINKLOCAL(&addr->sin6_addr))) { \
		*store = *addr; \
		if (addr->sin6_scope_id == 0) { \
			if (!sa6_recoverscope(store)) { \
				addr = store; \
			} \
		} else { \
			in6_clearscope(&addr->sin6_addr); \
			addr = store; \
		} \
	 } \
} while (0)
#define sctp_snd_sb_alloc(stcb, sz)  \
do { \
	atomic_add_int(&stcb->asoc.total_output_queue_size,sz); \
	if ((stcb->sctp_socket != NULL) && \
	    ((stcb->sctp_ep->sctp_flags & SCTP_PCB_FLAGS_TCPTYPE) || \
	     (stcb->sctp_ep->sctp_flags & SCTP_PCB_FLAGS_IN_TCPPOOL))) { \
		atomic_add_int(&stcb->sctp_socket->so_snd.sb_cc,sz); \
	} \
} while (0)
#define SCTP_ADDR_DEFER_USE     0x00000004	
#define SCTP_ADDR_IFA_UNUSEABLE 0x00000008
#define SCTP_ADDR_VALID         0x00000001	
#define SCTP_ALIGNM1 (SCTP_ALIGNMENT-1)
#define SCTP_ALIGNMENT 32
#define SCTP_BEING_DELETED      0x00000002	
#define SCTP_PCBHASH_ALLADDR(port, mask) (port & mask)
#define SCTP_PCBHASH_ASOC(tag, mask) (tag & mask)
#define SCTP_READ_LOG_SIZE 135	

#define sctp_lport ip_inp.inp.inp_lport
#define SCTP_ASOC_CREATE_LOCK(_inp) \
	do {								\
	if(SCTP_BASE_SYSCTL(sctp_logging_level) & SCTP_LOCK_LOGGING_ENABLE) sctp_log_lock(_inp, (struct sctp_tcb *)NULL, SCTP_LOG_LOCK_CREATE); \
		mtx_lock(&(_inp)->inp_create_mtx);			\
	} while (0)
#define SCTP_ASOC_CREATE_LOCK_CONTENDED(_inp) ((_inp)->inp_create_mtx.mtx_lock & MTX_CONTESTED)
#define SCTP_ASOC_CREATE_LOCK_DESTROY(_inp) \
	mtx_destroy(&(_inp)->inp_create_mtx)
#define SCTP_ASOC_CREATE_LOCK_INIT(_inp) \
	mtx_init(&(_inp)->inp_create_mtx, "sctp-create", "inp_create", \
		 MTX_DEF | MTX_DUPOK)
#define SCTP_ASOC_CREATE_UNLOCK(_inp)	mtx_unlock(&(_inp)->inp_create_mtx)
#define SCTP_DECR_ASOC_COUNT() \
                do { \
	               atomic_subtract_int(&SCTP_BASE_INFO(ipi_count_asoc), 1); \
	        } while (0)
#define SCTP_DECR_CHK_COUNT() \
                do { \
                       if(SCTP_BASE_INFO(ipi_count_chunk) == 0) \
                             panic("chunk count to 0?");    \
  	               atomic_subtract_int(&SCTP_BASE_INFO(ipi_count_chunk), 1); \
	        } while (0)
#define SCTP_DECR_EP_COUNT() \
                do { \
		       atomic_subtract_int(&SCTP_BASE_INFO(ipi_count_ep), 1); \
	        } while (0)
#define SCTP_DECR_LADDR_COUNT() \
                do { \
	               atomic_subtract_int(&SCTP_BASE_INFO(ipi_count_laddr), 1); \
	        } while (0)
#define SCTP_DECR_RADDR_COUNT() \
                do { \
 	               atomic_subtract_int(&SCTP_BASE_INFO(ipi_count_raddr),1); \
	        } while (0)
#define SCTP_DECR_READQ_COUNT() \
                do { \
		       atomic_subtract_int(&SCTP_BASE_INFO(ipi_count_readq), 1); \
	        } while (0)
#define SCTP_DECR_STRMOQ_COUNT() \
                do { \
		       atomic_subtract_int(&SCTP_BASE_INFO(ipi_count_strmoq), 1); \
	        } while (0)
#define SCTP_INCR_ASOC_COUNT() \
                do { \
	               atomic_add_int(&SCTP_BASE_INFO(ipi_count_asoc), 1); \
	        } while (0)
#define SCTP_INCR_CHK_COUNT() \
                do { \
  	               atomic_add_int(&SCTP_BASE_INFO(ipi_count_chunk), 1); \
	        } while (0)
#define SCTP_INCR_EP_COUNT() \
                do { \
		       atomic_add_int(&SCTP_BASE_INFO(ipi_count_ep), 1); \
	        } while (0)
#define SCTP_INCR_LADDR_COUNT() \
                do { \
	               atomic_add_int(&SCTP_BASE_INFO(ipi_count_laddr), 1); \
	        } while (0)
#define SCTP_INCR_RADDR_COUNT() \
                do { \
 	               atomic_add_int(&SCTP_BASE_INFO(ipi_count_raddr), 1); \
	        } while (0)
#define SCTP_INCR_READQ_COUNT() \
                do { \
		       atomic_add_int(&SCTP_BASE_INFO(ipi_count_readq),1); \
	        } while (0)
#define SCTP_INCR_STRMOQ_COUNT() \
                do { \
		       atomic_add_int(&SCTP_BASE_INFO(ipi_count_strmoq), 1); \
	        } while (0)
#define SCTP_INP_DECR_REF(_inp) atomic_add_int(&((_inp)->refcount), -1)
#define SCTP_INP_INCR_REF(_inp) atomic_add_int(&((_inp)->refcount), 1)
#define SCTP_INP_INFO_LOCK_DESTROY() do { \
        if(rw_wowned(&SCTP_BASE_INFO(ipi_ep_mtx))) { \
             rw_wunlock(&SCTP_BASE_INFO(ipi_ep_mtx)); \
        } \
        rw_destroy(&SCTP_BASE_INFO(ipi_ep_mtx)); \
      }  while (0)
#define SCTP_INP_INFO_LOCK_INIT() \
        rw_init(&SCTP_BASE_INFO(ipi_ep_mtx), "sctp-info");
#define SCTP_INP_INFO_RLOCK()	do { 					\
             rw_rlock(&SCTP_BASE_INFO(ipi_ep_mtx));                         \
} while (0)
#define SCTP_INP_INFO_RUNLOCK()		rw_runlock(&SCTP_BASE_INFO(ipi_ep_mtx))
#define SCTP_INP_INFO_WLOCK()	do { 					\
            rw_wlock(&SCTP_BASE_INFO(ipi_ep_mtx));                         \
} while (0)
#define SCTP_INP_INFO_WUNLOCK()		rw_wunlock(&SCTP_BASE_INFO(ipi_ep_mtx))
#define SCTP_INP_LOCK_CONTENDED(_inp) ((_inp)->inp_mtx.mtx_lock & MTX_CONTESTED)
#define SCTP_INP_LOCK_DESTROY(_inp) \
	mtx_destroy(&(_inp)->inp_mtx)
#define SCTP_INP_LOCK_INIT(_inp) \
	mtx_init(&(_inp)->inp_mtx, "sctp-inp", "inp", MTX_DEF | MTX_DUPOK)
#define SCTP_INP_READ_CONTENDED(_inp) ((_inp)->inp_rdata_mtx.mtx_lock & MTX_CONTESTED)
#define SCTP_INP_READ_DESTROY(_inp) \
	mtx_destroy(&(_inp)->inp_rdata_mtx)
#define SCTP_INP_READ_INIT(_inp) \
	mtx_init(&(_inp)->inp_rdata_mtx, "sctp-read", "inpr", MTX_DEF | MTX_DUPOK)
#define SCTP_INP_READ_LOCK(_inp)	do { \
        mtx_lock(&(_inp)->inp_rdata_mtx);    \
} while (0)
#define SCTP_INP_READ_UNLOCK(_inp) mtx_unlock(&(_inp)->inp_rdata_mtx)
#define SCTP_INP_RLOCK(_inp)	do { 					\
	if(SCTP_BASE_SYSCTL(sctp_logging_level) & SCTP_LOCK_LOGGING_ENABLE) sctp_log_lock(_inp, (struct sctp_tcb *)NULL, SCTP_LOG_LOCK_INP);\
        mtx_lock(&(_inp)->inp_mtx);                                     \
} while (0)
#define SCTP_INP_RUNLOCK(_inp)		mtx_unlock(&(_inp)->inp_mtx)
#define SCTP_INP_SO(sctpinp)	(sctpinp)->ip_inp.inp.inp_socket
#define SCTP_INP_WLOCK(_inp)	do { 					\
	if(SCTP_BASE_SYSCTL(sctp_logging_level) & SCTP_LOCK_LOGGING_ENABLE) sctp_log_lock(_inp, (struct sctp_tcb *)NULL, SCTP_LOG_LOCK_INP);\
        mtx_lock(&(_inp)->inp_mtx);                                     \
} while (0)
#define SCTP_INP_WUNLOCK(_inp)		mtx_unlock(&(_inp)->inp_mtx)
#define SCTP_IPI_ADDR_DESTROY() do  { \
        if(rw_wowned(&SCTP_BASE_INFO(ipi_addr_mtx))) { \
             rw_wunlock(&SCTP_BASE_INFO(ipi_addr_mtx)); \
        } \
	rw_destroy(&SCTP_BASE_INFO(ipi_addr_mtx)); \
      }  while (0)
#define SCTP_IPI_ADDR_INIT()								\
        rw_init(&SCTP_BASE_INFO(ipi_addr_mtx), "sctp-addr")
#define SCTP_IPI_ADDR_RLOCK()	do { 					\
             rw_rlock(&SCTP_BASE_INFO(ipi_addr_mtx));                         \
} while (0)
#define SCTP_IPI_ADDR_RUNLOCK()		rw_runlock(&SCTP_BASE_INFO(ipi_addr_mtx))
#define SCTP_IPI_ADDR_WLOCK()	do { 					\
             rw_wlock(&SCTP_BASE_INFO(ipi_addr_mtx));                         \
} while (0)
#define SCTP_IPI_ADDR_WUNLOCK()		rw_wunlock(&SCTP_BASE_INFO(ipi_addr_mtx))

#define SCTP_IPI_ITERATOR_WQ_DESTROY() \
	mtx_destroy(&sctp_it_ctl.ipi_iterator_wq_mtx)
#define SCTP_IPI_ITERATOR_WQ_INIT() \
        mtx_init(&sctp_it_ctl.ipi_iterator_wq_mtx, "sctp-it-wq", "sctp_it_wq", MTX_DEF)
#define SCTP_IPI_ITERATOR_WQ_LOCK()	do { 					\
             mtx_lock(&sctp_it_ctl.ipi_iterator_wq_mtx);                \
} while (0)
#define SCTP_IPI_ITERATOR_WQ_UNLOCK()		mtx_unlock(&sctp_it_ctl.ipi_iterator_wq_mtx)
#define SCTP_IP_PKTLOG_DESTROY() \
	mtx_destroy(&SCTP_BASE_INFO(ipi_pktlog_mtx))
#define SCTP_IP_PKTLOG_INIT() \
        mtx_init(&SCTP_BASE_INFO(ipi_pktlog_mtx), "sctp-pktlog", "packetlog", MTX_DEF)
#define SCTP_IP_PKTLOG_LOCK()	do { 			\
             mtx_lock(&SCTP_BASE_INFO(ipi_pktlog_mtx));     \
} while (0)
#define SCTP_IP_PKTLOG_UNLOCK()	mtx_unlock(&SCTP_BASE_INFO(ipi_pktlog_mtx))
#define SCTP_ITERATOR_LOCK() \
	do {								\
		if (mtx_owned(&sctp_it_ctl.it_mtx))			\
			panic("Iterator Lock");				\
		mtx_lock(&sctp_it_ctl.it_mtx);				\
	} while (0)
#define SCTP_ITERATOR_LOCK_DESTROY()	mtx_destroy(&sctp_it_ctl.it_mtx)
#define SCTP_ITERATOR_LOCK_INIT() \
        mtx_init(&sctp_it_ctl.it_mtx, "sctp-it", "iterator", MTX_DEF)
#define SCTP_ITERATOR_UNLOCK()	        mtx_unlock(&sctp_it_ctl.it_mtx)
#define SCTP_MCORE_DESTROY(cpstr)  do { \
	if(mtx_owned(&(cpstr)->core_mtx)) {	\
		mtx_unlock(&(cpstr)->core_mtx);	\
        } \
	mtx_destroy(&(cpstr)->core_mtx);	\
} while (0)
#define SCTP_MCORE_LOCK(cpstr)  do { \
		mtx_lock(&(cpstr)->core_mtx);	\
} while (0)
#define SCTP_MCORE_LOCK_INIT(cpstr) do { \
		mtx_init(&(cpstr)->core_mtx,	      \
			 "sctp-cpulck","cpu_proc_lock",	\
			 MTX_DEF|MTX_DUPOK);		\
} while (0)
#define SCTP_MCORE_QDESTROY(cpstr)  do { \
	if(mtx_owned(&(cpstr)->core_mtx)) {	\
		mtx_unlock(&(cpstr)->que_mtx);	\
        } \
	mtx_destroy(&(cpstr)->que_mtx);	\
} while (0)
#define SCTP_MCORE_QLOCK(cpstr)  do { \
		mtx_lock(&(cpstr)->que_mtx);	\
} while (0)
#define SCTP_MCORE_QLOCK_INIT(cpstr) do { \
		mtx_init(&(cpstr)->que_mtx,	      \
			 "sctp-mcore_queue","queue_lock",	\
			 MTX_DEF|MTX_DUPOK);		\
} while (0)
#define SCTP_MCORE_QUNLOCK(cpstr)  do { \
		mtx_unlock(&(cpstr)->que_mtx);	\
} while (0)
#define SCTP_MCORE_UNLOCK(cpstr)  do { \
		mtx_unlock(&(cpstr)->core_mtx);	\
} while (0)
#define SCTP_SOCKET_LOCK(so, refcnt)
#define SCTP_SOCKET_UNLOCK(so, refcnt)




#define SCTP_TCB_LOCK(_tcb)  do {					\
	if(SCTP_BASE_SYSCTL(sctp_logging_level) & SCTP_LOCK_LOGGING_ENABLE)  sctp_log_lock(_tcb->sctp_ep, _tcb, SCTP_LOG_LOCK_TCB);          \
	mtx_lock(&(_tcb)->tcb_mtx);                                     \
} while (0)
#define SCTP_TCB_LOCK_ASSERT(_tcb) do { \
                            if (mtx_owned(&(_tcb)->tcb_mtx) == 0) \
                                panic("Don't own TCB lock"); \
                            } while (0)
#define SCTP_TCB_LOCK_DESTROY(_tcb)	mtx_destroy(&(_tcb)->tcb_mtx)
#define SCTP_TCB_LOCK_INIT(_tcb) \
	mtx_init(&(_tcb)->tcb_mtx, "sctp-tcb", "tcb", MTX_DEF | MTX_DUPOK)
#define SCTP_TCB_SEND_LOCK(_tcb)  do { \
	mtx_lock(&(_tcb)->tcb_send_mtx); \
} while (0)
#define SCTP_TCB_SEND_LOCK_DESTROY(_tcb) mtx_destroy(&(_tcb)->tcb_send_mtx)
#define SCTP_TCB_SEND_LOCK_INIT(_tcb) \
	mtx_init(&(_tcb)->tcb_send_mtx, "sctp-send-tcb", "tcbs", MTX_DEF | MTX_DUPOK)
#define SCTP_TCB_SEND_UNLOCK(_tcb) mtx_unlock(&(_tcb)->tcb_send_mtx)
#define SCTP_TCB_TRYLOCK(_tcb) 	mtx_trylock(&(_tcb)->tcb_mtx)
#define SCTP_TCB_UNLOCK(_tcb)		mtx_unlock(&(_tcb)->tcb_mtx)
#define SCTP_TCB_UNLOCK_IFOWNED(_tcb)	      do { \
                                                if (mtx_owned(&(_tcb)->tcb_mtx)) \
                                                     mtx_unlock(&(_tcb)->tcb_mtx); \
                                              } while (0)
#define SCTP_WQ_ADDR_DESTROY() do  { \
        if(mtx_owned(&SCTP_BASE_INFO(wq_addr_mtx))) { \
             mtx_unlock(&SCTP_BASE_INFO(wq_addr_mtx)); \
        } \
	    mtx_destroy(&SCTP_BASE_INFO(wq_addr_mtx)); \
      }  while (0)
#define SCTP_WQ_ADDR_INIT() do { \
        mtx_init(&SCTP_BASE_INFO(wq_addr_mtx), "sctp-addr-wq","sctp_addr_wq",MTX_DEF); \
 } while (0)
#define SCTP_WQ_ADDR_LOCK()	do { \
             mtx_lock(&SCTP_BASE_INFO(wq_addr_mtx));  \
} while (0)
#define SCTP_WQ_ADDR_UNLOCK() do { \
		mtx_unlock(&SCTP_BASE_INFO(wq_addr_mtx)); \
} while (0)


#define sctp_auth_is_required_chunk(chunk, list) ((list == NULL) ? (0) : (list->chunks[chunk] != 0))
#define SCTP_DEFAULT_VRF 0

#define MODULE_GLOBAL(__SYMBOL) V_##__SYMBOL
#define SCTPDBG(level, params...)					\
{									\
    do {								\
	if (SCTP_BASE_SYSCTL(sctp_debug_on) & level ) {			\
	    SCTP_PRINTF(params);						\
	}								\
    } while (0);							\
}
#define SCTPDBG_ADDR(level, addr)					\
{									\
    do {								\
	if (SCTP_BASE_SYSCTL(sctp_debug_on) & level ) {			\
	    sctp_print_address(addr);					\
	}								\
    } while (0);							\
}
#define SCTP_ALIGN_TO_END(m, len) if(m->m_flags & M_PKTHDR) { \
                                     MH_ALIGN(m, len); \
                                  } else if ((m->m_flags & M_EXT) == 0) { \
                                     M_ALIGN(m, len); \
                                  }
#define SCTP_ATTACH_CHAIN(pak, m, packet_length) do { \
                                                 pak = m; \
                                                 pak->m_pkthdr.len = packet_length; \
                         } while(0)
#define SCTP_BASE_INFO(__m) V_system_base_info.sctppcbinfo.__m
#define SCTP_BASE_STAT(__m)     V_system_base_info.sctpstat.__m
#define SCTP_BASE_STATS V_system_base_info.sctpstat
#define SCTP_BASE_STATS_SYSCTL VNET_NAME(system_base_info.sctpstat)
#define SCTP_BASE_SYSCTL(__m) VNET_NAME(system_base_info.sctpsysctl.__m)
#define SCTP_BASE_VAR(__m) V_system_base_info.__m
#define SCTP_BUF_AT(m, size) m->m_data + size
#define SCTP_BUF_EXTEND_BASE(m) (m->m_ext.ext_buf)
#define SCTP_BUF_EXTEND_REFCNT(m) (*m->m_ext.ref_cnt)
#define SCTP_BUF_EXTEND_SIZE(m) (m->m_ext.ext_size)
#define SCTP_BUF_GET_FLAGS(m) (m->m_flags)
#define SCTP_BUF_IS_EXTENDED(m) (m->m_flags & M_EXT)
#define SCTP_BUF_LEN(m) (m->m_len)
#define SCTP_BUF_NEXT(m) (m->m_next)
#define SCTP_BUF_NEXT_PKT(m) (m->m_nextpkt)
#define SCTP_BUF_RECVIF(m) (m->m_pkthdr.rcvif)
#define SCTP_BUF_RESV_UF(m, size) m->m_data += size
#define SCTP_BUF_TYPE(m) (m->m_type)
#define SCTP_CLEAR_SO_NBIO(so)	((so)->so_state &= ~SS_NBIO)
#define SCTP_CTR6 sctp_log_trace
#define SCTP_DECREMENT_AND_CHECK_REFCOUNT(addr) (atomic_fetchadd_int(addr, -1) == 1)
#define SCTP_DEREGISTER_INTERFACE(ifhandle, af)

#define SCTP_ENABLE_UDP_CSUM(m) do { \
					m->m_pkthdr.csum_flags = CSUM_UDP; \
					m->m_pkthdr.csum_data = offsetof(struct udphdr, uh_sum); \
				} while (0)
#define SCTP_FREE(var, type)	free(var, type)
#define SCTP_FREE_SONAME(var)	free(var, M_SONAME)
#define SCTP_GATHER_MTU_FROM_IFN_INFO(ifn, ifn_index, af) ((struct ifnet *)ifn)->if_mtu
#define SCTP_GATHER_MTU_FROM_INTFC(sctp_ifn) ((sctp_ifn->ifn_p != NULL) ? ((struct ifnet *)(sctp_ifn->ifn_p))->if_mtu : 0)
#define SCTP_GATHER_MTU_FROM_ROUTE(sctp_ifa, sa, rt) ((rt != NULL) ? rt->rt_mtu : 0)
#define SCTP_GET_CYCLECOUNT get_cyclecount()
#define SCTP_GET_HEADER_FOR_OUTPUT(o_pak) 0
#define SCTP_GET_HLIM(inp, ro)	in6_selecthlim((struct in6pcb *)&inp->ip_inp.inp, (ro ? (ro->ro_rt ? (ro->ro_rt->rt_ifp) : (NULL)) : (NULL)));
#define SCTP_GET_IFN_VOID_FROM_ROUTE(ro) (void *)ro->ro_rt->rt_ifp
#define SCTP_GET_IF_INDEX_FROM_ROUTE(ro) (ro)->ro_rt->rt_ifp->if_index
#define SCTP_GET_PKT_VRFID(m, vrf_id)  ((vrf_id = SCTP_DEFAULT_VRFID) != SCTP_DEFAULT_VRFID)
#define SCTP_HASH_FREE(table, hashmark) hashdestroy(table, M_PCB, hashmark)
#define SCTP_HASH_INIT(size, hashmark) hashinit_flags(size, M_PCB, hashmark, HASH_NOWAIT)
#define SCTP_HEADER_LEN(m) ((m)->m_pkthdr.len)
#define SCTP_HEADER_TO_CHAIN(m) (m)
#define SCTP_IFN_IS_IFT_LOOP(ifn) ((ifn)->ifn_type == IFT_LOOP)
#define SCTP_IP6_OUTPUT(result, o_pak, ro, ifp, stcb, vrf_id) \
{ \
	struct sctp_tcb *local_stcb = stcb; \
	m_clrprotoflags(o_pak); \
	if (local_stcb && local_stcb->sctp_ep) \
		result = ip6_output(o_pak, \
				    ((struct in6pcb *)(local_stcb->sctp_ep))->in6p_outputopts, \
				    (ro), 0, 0, ifp, NULL); \
	else \
		result = ip6_output(o_pak, NULL, (ro), 0, 0, ifp, NULL); \
}
#define SCTP_IPV6_V6ONLY(inp)	(((struct inpcb *)inp)->inp_flags & IN6P_IPV6_V6ONLY)
#define SCTP_IP_OUTPUT(result, o_pak, ro, stcb, vrf_id) \
{ \
	int o_flgs = IP_RAWOUTPUT; \
	struct sctp_tcb *local_stcb = stcb; \
	if (local_stcb && \
	    local_stcb->sctp_ep && \
	    local_stcb->sctp_ep->sctp_socket) \
		o_flgs |= local_stcb->sctp_ep->sctp_socket->so_options & SO_DONTROUTE; \
	m_clrprotoflags(o_pak); \
	result = ip_output(o_pak, NULL, ro, o_flgs, 0, NULL); \
}
#define SCTP_IS_IT_BROADCAST(dst, m) ((m->m_flags & M_PKTHDR) ? in_broadcast(dst, m->m_pkthdr.rcvif) : 0)
#define SCTP_IS_IT_LOOPBACK(m) ((m->m_flags & M_PKTHDR) && ((m->m_pkthdr.rcvif == NULL) || (m->m_pkthdr.rcvif->if_type == IFT_LOOP)))
#define SCTP_LTRACE_CHK(a, b, c, d) if(SCTP_BASE_SYSCTL(sctp_logging_level) & SCTP_LTRACE_CHUNK_ENABLE) SCTP_CTR6(KTR_SUBSYS, "SCTP:%d[%d]:%x-%x-%x-%x", SCTP_LOG_CHUNK_PROC, 0, a, b, c, d)
#define SCTP_LTRACE_ERR_RET(inp, stcb, net, file, err) \
	if (SCTP_BASE_SYSCTL(sctp_logging_level) & SCTP_LTRACE_ERROR_ENABLE) \
        	SCTP_PRINTF("inp:%p stcb:%p net:%p file:%x line:%d error:%d\n", \
		            inp, stcb, net, file, "__LINE__", err);
#define SCTP_LTRACE_ERR_RET_PKT(m, inp, stcb, net, file, err) \
	if (SCTP_BASE_SYSCTL(sctp_logging_level) & SCTP_LTRACE_ERROR_ENABLE) \
        	SCTP_PRINTF("mbuf:%p inp:%p stcb:%p net:%p file:%x line:%d error:%d\n", \
		            m, inp, stcb, net, file, "__LINE__", err);
#define SCTP_MALLOC(var, type, size, name) \
    do { \
	var = (type)malloc(size, name, M_NOWAIT); \
    } while (0)
#define SCTP_MALLOC_SONAME(var, type, size) \
    do { \
	var = (type)malloc(size, M_SONAME, M_WAITOK | M_ZERO); \
    } while (0)
#define SCTP_OS_TIMER_DEACTIVATE callout_deactivate
#define SCTP_OS_TIMER_INIT(tmr)	callout_init(tmr, 1)
#define SCTP_OS_TIMER_STOP_DRAIN callout_drain
#define SCTP_PKTLOG_WRITERS_NEED_LOCK 3
#define SCTP_PRINTF(params...)	printf(params)
#define SCTP_PROCESS_STRUCT struct proc *
#define SCTP_READ_RANDOM(buf, len)	read_random(buf, len)
#define SCTP_REGISTER_INTERFACE(ifhandle, af)

#define SCTP_RELEASE_PKT(m)	sctp_m_freem(m)
#define SCTP_ROUTE_HAS_VALID_IFN(ro) ((ro)->ro_rt && (ro)->ro_rt->rt_ifp)
#define SCTP_ROUTE_IS_REAL_LOOP(ro) ((ro)->ro_rt && (ro)->ro_rt->rt_ifa && (ro)->ro_rt->rt_ifa->ifa_ifp && (ro)->ro_rt->rt_ifa->ifa_ifp->if_type == IFT_LOOP)
#define SCTP_RTALLOC(ro, vrf_id) rtalloc_ign((struct route *)ro, 0UL)
#define SCTP_SAVE_ATOMIC_DECREMENT(addr, val) \
{ \
	int32_t oldval; \
	oldval = atomic_fetchadd_int(addr, -val); \
	if (oldval < val) { \
		panic("Counter goes negative"); \
	} \
}
#define SCTP_SB_CLEAR(sb)	\
	(sb).sb_cc = 0;		\
	(sb).sb_mb = NULL;	\
	(sb).sb_mbcnt = 0;
#define SCTP_SB_LIMIT_RCV(so) so->so_rcv.sb_hiwat
#define SCTP_SB_LIMIT_SND(so) so->so_snd.sb_hiwat
#define SCTP_SET_MTU_OF_ROUTE(sa, rt, mtu) do { \
                                              if (rt != NULL) \
                                                 rt->rt_mtu = mtu; \
                                           } while(0)
#define SCTP_SET_SO_NBIO(so)	((so)->so_state |= SS_NBIO)
#define SCTP_SHA1_FINAL(x,y)	SHA1Final((caddr_t)x, y)
#define SCTP_SHA256_FINAL(x,y)	SHA256_Final((caddr_t)x, y)
#define SCTP_SORESERVE(so, send, recv)	soreserve(so, send, recv)
#define SCTP_SOWAKEUP(so)	wakeup(&(so)->so_timeo)
#define SCTP_SO_IS_NBIO(so)	((so)->so_state & SS_NBIO)
#define SCTP_SO_TYPE(so)	((so)->so_type)
#define SCTP_UNUSED __attribute__((unused))
#define SCTP_ZERO_COPY_EVENT(inp, so)
#define SCTP_ZERO_COPY_SENDQ_EVENT(inp, so)
#define SCTP_ZONE_DESTROY(zone) uma_zdestroy(zone)
#define SCTP_ZONE_FREE(zone, element) \
	uma_zfree(zone, element);
#define SCTP_ZONE_GET(zone, type) \
	(type *)uma_zalloc(zone, M_NOWAIT);
#define SCTP_ZONE_INIT(zone, name, size, number) { \
	zone = uma_zcreate(name, size, NULL, NULL, NULL, NULL, UMA_ALIGN_PTR,\
		0); \
	uma_zone_set_max(zone, number); \
}
#define V_system_base_info VNET(system_base_info)

#define sctp_get_tick_count() (ticks)

#define LIST_SWAP(head1, head2, type, field) do {			\
	struct type *swap_tmp = LIST_FIRST((head1));			\
	LIST_FIRST((head1)) = LIST_FIRST((head2));			\
	LIST_FIRST((head2)) = swap_tmp;					\
	if ((swap_tmp = LIST_FIRST((head1))) != NULL)			\
		swap_tmp->field.le_prev = &LIST_FIRST((head1));		\
	if ((swap_tmp = LIST_FIRST((head2))) != NULL)			\
		swap_tmp->field.le_prev = &LIST_FIRST((head2));		\
} while (0)
#define SLIST_REMOVE_AFTER(elm, field) do {				\
	SLIST_NEXT(elm, field) =					\
	    SLIST_NEXT(SLIST_NEXT(elm, field), field);			\
} while (0)
#define SLIST_SWAP(head1, head2, type) do {				\
	struct type *swap_first = SLIST_FIRST(head1);			\
	SLIST_FIRST(head1) = SLIST_FIRST(head2);			\
	SLIST_FIRST(head2) = swap_first;				\
} while (0)
#define STAILQ_REMOVE_AFTER(head, elm, field) do {			\
	if ((STAILQ_NEXT(elm, field) =					\
	     STAILQ_NEXT(STAILQ_NEXT(elm, field), field)) == NULL)	\
		(head)->stqh_last = &STAILQ_NEXT((elm), field);		\
} while (0)
#define STAILQ_SWAP(head1, head2, type) do {				\
	struct type *swap_first = STAILQ_FIRST(head1);			\
	struct type **swap_last = (head1)->stqh_last;			\
	STAILQ_FIRST(head1) = STAILQ_FIRST(head2);			\
	(head1)->stqh_last = (head2)->stqh_last;			\
	STAILQ_FIRST(head2) = swap_first;				\
	(head2)->stqh_last = swap_last;					\
	if (STAILQ_EMPTY(head1))					\
		(head1)->stqh_last = &STAILQ_FIRST(head1);		\
	if (STAILQ_EMPTY(head2))					\
		(head2)->stqh_last = &STAILQ_FIRST(head2);		\
} while (0)
#define TAILQ_SWAP(head1, head2, type, field) do {			\
	struct type *swap_first = (head1)->tqh_first;			\
	struct type **swap_last = (head1)->tqh_last;			\
	(head1)->tqh_first = (head2)->tqh_first;			\
	(head1)->tqh_last = (head2)->tqh_last;				\
	(head2)->tqh_first = swap_first;				\
	(head2)->tqh_last = swap_last;					\
	if ((swap_first = (head1)->tqh_first) != NULL)			\
		swap_first->field.tqe_prev = &(head1)->tqh_first;	\
	else								\
		(head1)->tqh_last = &(head1)->tqh_first;		\
	if ((swap_first = (head2)->tqh_first) != NULL)			\
		swap_first->field.tqe_prev = &(head2)->tqh_first;	\
	else								\
		(head2)->tqh_last = &(head2)->tqh_first;		\
} while (0)
#define UMA_SMALLEST_UNIT       (PAGE_SIZE / 256) 

#define BLKDEV_IOSIZE  PAGE_SIZE	


#define __FreeBSD_version 1100026	
#define __PAST_END(array, offset) (((__typeof__(*(array)) *)(array))[offset])
#define btoc(x)	(((vm_offset_t)(x)+PAGE_MASK)>>PAGE_SHIFT)
#define btodb(bytes)	 		 \
	(sizeof (bytes) > sizeof(long) \
	 ? (daddr_t)((unsigned long long)(bytes) >> DEV_BSHIFT) \
	 : (daddr_t)((unsigned long)(bytes) >> DEV_BSHIFT))
#define ctob(x)	((x)<<PAGE_SHIFT)
#define ctodb(db)			 \
	((db) << (PAGE_SHIFT - DEV_BSHIFT))
#define dbtob(db)			 \
	((off_t)(db) << DEV_BSHIFT)
#define dbtoc(db)			 \
	((db + (ctodb(1) - 1)) >> (PAGE_SHIFT - DEV_BSHIFT))
#define powerof2(x)	((((x)-1)&(x))==0)
#define ILL_BADSTK 	8	
#define ILL_COPROC 	7	
#define ILL_ILLADR 	3	
#define ILL_ILLOPC 	1	
#define ILL_ILLOPN 	2	
#define ILL_ILLTRP 	4	
#define ILL_PRVOPC 	5	
#define ILL_PRVREG 	6	
#define SIG_HOLD        ((__sighandler_t *)3)




#define SHA1Final(x, y)		sha1_result((y), (x))
#define SHA1Init(x)		sha1_init((x))
#define SHA1Update(x, y, z)	sha1_loop((x), (y), (z))

#define V_deembed_scopeid       VNET(deembed_scopeid)

#define VNET_GLOBAL_EVENTHANDLER_REGISTER(name, func, arg, priority)	\
do {									\
	if (IS_DEFAULT_VNET(curvnet)) {					\
		vimage_eventhandler_register(NULL, #name, func,		\
		    arg, priority,					\
		    vnet_global_eventhandler_iterator_func);		\
	}								\
} while(0)
#define VNET_GLOBAL_EVENTHANDLER_REGISTER_TAG(tag, name, func, arg, priority) \
do {									\
	if (IS_DEFAULT_VNET(curvnet)) {					\
		(tag) = vimage_eventhandler_register(NULL, #name, func,	\
		    arg, priority,					\
		    vnet_global_eventhandler_iterator_func);		\
	}								\
} while(0)
#define EVENTHANDLER_DECLARE(name, type)				\
struct eventhandler_entry_ ## name 					\
{									\
	struct eventhandler_entry	ee;				\
	type				eh_func;			\
};									\
struct __hack
#define EVENTHANDLER_DEFINE(name, func, arg, priority)			\
	static eventhandler_tag name ## _tag;				\
	static void name ## _evh_init(void *ctx)			\
	{								\
		name ## _tag = EVENTHANDLER_REGISTER(name, func, ctx,	\
		    priority);						\
	}								\
	SYSINIT(name ## _evh_init, SI_SUB_CONFIGURE, SI_ORDER_ANY,	\
	    name ## _evh_init, arg);					\
	struct __hack
#define EVENTHANDLER_DEREGISTER(name, tag) 				\
do {									\
	struct eventhandler_list *_el;					\
									\
	if ((_el = eventhandler_find_list(#name)) != NULL)		\
		eventhandler_deregister(_el, tag);			\
} while(0)
#define EVENTHANDLER_INVOKE(name, ...)					\
do {									\
	struct eventhandler_list *_el;					\
									\
	if ((_el = eventhandler_find_list(#name)) != NULL) 		\
		_EVENTHANDLER_INVOKE(name, _el , ## __VA_ARGS__);	\
} while (0)
#define EVENTHANDLER_REGISTER(name, func, arg, priority)		\
	eventhandler_register(NULL, #name, func, arg, priority)
#define _EVENTHANDLER_INVOKE(name, list, ...) do {			\
	struct eventhandler_entry *_ep;					\
	struct eventhandler_entry_ ## name *_t;				\
									\
	KASSERT((list)->el_flags & EHL_INITTED,				\
 	   ("eventhandler_invoke: running non-inited list"));		\
	EHL_LOCK_ASSERT((list), MA_OWNED);				\
	(list)->el_runcount++;						\
	KASSERT((list)->el_runcount > 0,				\
	    ("eventhandler_invoke: runcount overflow"));		\
	CTR0(KTR_EVH, "eventhandler_invoke(\"" __STRING(name) "\")");	\
	TAILQ_FOREACH(_ep, &((list)->el_entries), ee_link) {		\
		if (_ep->ee_priority != EHE_DEAD_PRIORITY) {		\
			EHL_UNLOCK((list));				\
			_t = (struct eventhandler_entry_ ## name *)_ep;	\
			CTR1(KTR_EVH, "eventhandler_invoke: executing %p", \
 			    (void *)_t->eh_func);			\
			_t->eh_func(_ep->ee_arg , ## __VA_ARGS__);	\
			EHL_LOCK((list));				\
		}							\
	}								\
	KASSERT((list)->el_runcount > 0,				\
	    ("eventhandler_invoke: runcount underflow"));		\
	(list)->el_runcount--;						\
	if ((list)->el_runcount == 0)					\
		eventhandler_prune_list(list);				\
	EHL_UNLOCK((list));						\
} while (0)

#define DROP_GIANT()							\
do {									\
	int _giantcnt = 0;						\
	WITNESS_SAVE_DECL(Giant);					\
									\
	if (mtx_owned(&Giant)) {					\
		WITNESS_SAVE(&Giant.lock_object, Giant);		\
		for (_giantcnt = 0; mtx_owned(&Giant) &&		\
		    !SCHEDULER_STOPPED(); _giantcnt++)			\
			mtx_unlock(&Giant);				\
	}

#define MTX_NOPROFILE   0x00000020	
#define PARTIAL_PICKUP_GIANT()						\
	mtx_assert(&Giant, MA_NOTOWNED);				\
	if (_giantcnt > 0) {						\
		while (_giantcnt--)					\
			mtx_lock(&Giant);				\
		WITNESS_RESTORE(&Giant.lock_object, Giant);		\
	}
#define PICKUP_GIANT()							\
	PARTIAL_PICKUP_GIANT();						\
} while (0)

#define __mtx_lock(mp, tid, opts, file, line) do {			\
	uintptr_t _tid = (uintptr_t)(tid);				\
									\
	if (!_mtx_obtain_lock((mp), _tid))				\
		_mtx_lock_sleep((mp), _tid, (opts), (file), (line));	\
	else								\
              	LOCKSTAT_PROFILE_OBTAIN_LOCK_SUCCESS(LS_MTX_LOCK_ACQUIRE, \
		    mp, 0, 0, (file), (line));				\
} while (0)
#define __mtx_lock_spin(mp, tid, opts, file, line) do {			\
	uintptr_t _tid = (uintptr_t)(tid);				\
									\
	spinlock_enter();						\
	if (!_mtx_obtain_lock((mp), _tid)) {				\
		if ((mp)->mtx_lock == _tid)				\
			(mp)->mtx_recurse++;				\
		else							\
			_mtx_lock_spin((mp), _tid, (opts), (file), (line)); \
	} else 								\
              	LOCKSTAT_PROFILE_OBTAIN_LOCK_SUCCESS(LS_MTX_SPIN_LOCK_ACQUIRE, \
		    mp, 0, 0, (file), (line));				\
} while (0)
#define __mtx_unlock(mp, tid, opts, file, line) do {			\
	uintptr_t _tid = (uintptr_t)(tid);				\
									\
	if ((mp)->mtx_recurse == 0)					\
		 LOCKSTAT_PROFILE_RELEASE_LOCK(LS_MTX_UNLOCK_RELEASE,	\
		    (mp));						\
	if (!_mtx_release_lock((mp), _tid))				\
		_mtx_unlock_sleep((mp), (opts), (file), (line));	\
} while (0)
#define __mtx_unlock_spin(mp) do {					\
	if (mtx_recursed((mp)))						\
		(mp)->mtx_recurse--;					\
	else {								\
		LOCKSTAT_PROFILE_RELEASE_LOCK(LS_MTX_SPIN_UNLOCK_RELEASE, \
			mp);						\
		_mtx_release_lock_quick((mp));				\
	}                                                               \
	spinlock_exit();				                \
} while (0)
#define _mtx_obtain_lock(mp, tid)					\
	atomic_cmpset_acq_ptr(&(mp)->mtx_lock, MTX_UNOWNED, (tid))
#define _mtx_release_lock(mp, tid)					\
	atomic_cmpset_rel_ptr(&(mp)->mtx_lock, (tid), MTX_UNOWNED)
#define _mtx_release_lock_quick(mp)					\
	atomic_store_rel_ptr(&(mp)->mtx_lock, MTX_UNOWNED)
#define mtx_assert_(m, what, file, line)	(void)0
#define mtx_lock(m)		mtx_lock_flags((m), 0)
#define mtx_lock_spin(m)	mtx_lock_spin_flags((m), 0)
#define mtx_name(m)	((m)->lock_object.lo_name)
#define mtx_owned(m)	(((m)->mtx_lock & ~MTX_FLAGMASK) == (uintptr_t)curthread)
#define mtx_pool_lock(pool, ptr)					\
	mtx_lock(mtx_pool_find((pool), (ptr)))
#define mtx_pool_lock_spin(pool, ptr)					\
	mtx_lock_spin(mtx_pool_find((pool), (ptr)))
#define mtx_pool_unlock(pool, ptr)					\
	mtx_unlock(mtx_pool_find((pool), (ptr)))
#define mtx_pool_unlock_spin(pool, ptr)					\
	mtx_unlock_spin(mtx_pool_find((pool), (ptr)))
#define mtx_recursed(m)	((m)->mtx_recurse != 0)
#define mtx_trylock(m)		mtx_trylock_flags((m), 0)
#define mtx_trylock_flags(m, opts)					\
	mtx_trylock_flags_((m), (opts), LOCK_FILE, LOCK_LINE)
#define mtx_unlock(m)		mtx_unlock_flags((m), 0)
#define mtx_unlock_spin(m)	mtx_unlock_spin_flags((m), 0)

#define lock_profile_obtain_lock_failed(lo, contested, waittime)	(void)0
#define lock_profile_obtain_lock_success(lo, contested, waittime, file, line)	(void)0
#define LO_NOPROFILE    0x10000000      
#define MPASS(ex)		MPASS4(ex, #ex, "__FILE__", "__LINE__")
#define MPASS2(ex, what)	MPASS4(ex, what, "__FILE__", "__LINE__")
#define MPASS3(ex, file, line)	MPASS4(ex, #ex, file, line)
#define MPASS4(ex, what, file, line)					\
	KASSERT((ex), ("Assertion %s failed at %s:%d", what, file, line))
#define WITNESS_DESTROY(lock)						\
	witness_destroy(lock)

#define KTR_COMPILE 0


#define CTR0(m, format)			CTR6(m, format, 0, 0, 0, 0, 0, 0)
#define CTR1(m, format, p1)		CTR6(m, format, p1, 0, 0, 0, 0, 0)
#define CTR6(m, format, p1, p2, p3, p4, p5, p6) do {			\
	if (KTR_COMPILE & (m))						\
		ktr_tracepoint((m), "__FILE__", "__LINE__", format,		\
		    (u_long)(p1), (u_long)(p2), (u_long)(p3),		\
		    (u_long)(p4), (u_long)(p5), (u_long)(p6));		\
	} while(0)
#define KTR_STATE0(m, egroup, ident, state)				\
	KTR_EVENT0(m, egroup, ident, "state:\"%s\"", state)
#define KTR_STATE1(m, egroup, ident, state, a0, v0)			\
	KTR_EVENT1(m, egroup, ident, "state:\"%s\"", state, a0, (v0))
#define KTR_STATE2(m, egroup, ident, state, a0, v0, a1, v1)		\
	KTR_EVENT2(m, egroup, ident, "state:\"%s\"", state, a0, (v0), a1, (v1))
#define KTR_STATE3(m, egroup, ident, state, a0, v0, a1, v1, a2, v2)	\
	KTR_EVENT3(m, egroup, ident, "state:\"%s\"",			\
	    state, a0, (v0), a1, (v1), a2, (v2))
#define KTR_STATE4(m, egroup, ident, state, a0, v0, a1, v1, a2, v2, a3, v3)\
	KTR_EVENT4(m, egroup, ident, "state:\"%s\"",			\
	    state, a0, (v0), a1, (v1), a2, (v2), a3, (v3))

#define ABS_SET(set, sym)	__MAKE_SET(set, sym)
#define BSS_SET(set, sym)	__MAKE_SET(set, sym)
#define DATA_SET(set, sym)	__MAKE_SET(set, sym)
#define SET_BEGIN(set)							\
	(&__CONCAT(__start_set_,set))
#define SET_COUNT(set)							\
	(SET_LIMIT(set) - SET_BEGIN(set))
#define SET_DECLARE(set, ptype)					\
	extern ptype __weak *__CONCAT(__start_set_,set);	\
	extern ptype __weak *__CONCAT(__stop_set_,set)
#define SET_ENTRY(set, sym)	__MAKE_SET(set, sym)
#define SET_FOREACH(pvar, set)						\
	for (pvar = SET_BEGIN(set); pvar < SET_LIMIT(set); pvar++)
#define SET_ITEM(set, i)						\
	((SET_BEGIN(set))[i])
#define SET_LIMIT(set)							\
	(&__CONCAT(__stop_set_,set))
#define TEXT_SET(set, sym)	__MAKE_SET(set, sym)

#define __MAKE_SET(set, sym)				\
	__GLOBL(__CONCAT(__start_set_,set));		\
	__GLOBL(__CONCAT(__stop_set_,set));		\
	static void const * __MAKE_SET_CONST		\
	__set_##set##_sym_##sym __section("set_" #set)	\
	__used = &(sym)

#define PROC_ASSERT_HELD(p) do {					\
	KASSERT((p)->p_lock > 0, ("process not held"));			\
} while (0)
#define PROC_ASSERT_NOT_HELD(p) do {					\
	KASSERT((p)->p_lock == 0, ("process held"));			\
} while (0)
#define TD_IS_IDLETHREAD(td)	((td)->td_flags & TDF_IDLETD)
#define ucontext4 ucontext

#define RTP_PRIO_BASE(P)	PRI_BASE(P)
#define RTP_PRIO_IS_REALTIME(P) PRI_IS_REALTIME(P)
#define RTP_PRIO_NEED_RR(P)	PRI_NEED_RR(P)


#define EV_SET(kevp_, a, b, c, d, e, f) do {	\
	struct kevent *kevp = (kevp_);		\
	(kevp)->ident = (a);			\
	(kevp)->filter = (b);			\
	(kevp)->flags = (c);			\
	(kevp)->fflags = (d);			\
	(kevp)->data = (e);			\
	(kevp)->udata = (f);			\
} while(0)
#define KNOTE(list, hist, flags)	knote(list, hist, flags)
#define KNOTE_LOCKED(list, hint)	knote(list, hint, KNF_LISTLOCKED)
#define KNOTE_UNLOCKED(list, hint)	knote(list, hint, 0)

#define knlist_clear(knl, islocked)				\
		knlist_cleardel((knl), NULL, (islocked), 0)
#define knlist_delete(knl, td, islocked)			\
		knlist_cleardel((knl), (td), (islocked), 1)
#define cv_broadcast(cvp)	cv_broadcastpri(cvp, 0)
#define DRLSTSIZ 10
#define IN6_LINKMTU(ifp) \
	((ND_IFINFO(ifp)->linkmtu && ND_IFINFO(ifp)->linkmtu < (ifp)->if_mtu) \
	    ? ND_IFINFO(ifp)->linkmtu \
	    : ((ND_IFINFO(ifp)->maxmtu && ND_IFINFO(ifp)->maxmtu < (ifp)->if_mtu) \
		? ND_IFINFO(ifp)->maxmtu : (ifp)->if_mtu))
#define ND6_IS_LLINFO_PROBREACH(n) ((n)->ln_state > ND6_LLINFO_INCOMPLETE)
#define ND6_LLINFO_PERMANENT(n) (((n)->la_expire == 0) && ((n)->ln_state > ND6_LLINFO_INCOMPLETE))
#define ND_COMPUTE_RTIME(x) \
		(((MIN_RANDOM_FACTOR * (x >> 10)) + (arc4random() & \
		((MAX_RANDOM_FACTOR - MIN_RANDOM_FACTOR) * (x >> 10)))) /1000)
#define ND_IFINFO(ifp) \
	(((struct in6_ifextra *)(ifp)->if_afdata[AF_INET6])->nd_ifinfo)
#define PRLSTSIZ 10

#define nd6log(x)	do { if (V_nd6_debug) log x; } while ( 0)

#define ICMP6_PARAMPROB_HEADER 	 	0	
#define ICMP6_ROUTER_RENUMBERING_COMMAND  0	
#define ICMP6_ROUTER_RENUMBERING_RESULT   1	
#define ICMP6_ROUTER_RENUMBERING_SEQNUM_RESET   255	
#define ICMP6_RR_PCOUSE_FLAGS_DECRPLTIME     0x40000000
#define ICMP6_RR_PCOUSE_FLAGS_DECRVLTIME     0x80000000
#define ICMP6_TIME_EXCEED_TRANSIT 	0	
#define MLD_LISTENER_REDUCTION MLD_LISTENER_DONE 

#define icmp6_ifoutstat_inc(ifp, type, code) \
do { \
		icmp6_ifstat_inc(ifp, ifs6_out_msg); \
 		if (type < ICMP6_INFOMSG_MASK) \
 			icmp6_ifstat_inc(ifp, ifs6_out_error); \
		switch (type) { \
		 case ICMP6_DST_UNREACH: \
			 icmp6_ifstat_inc(ifp, ifs6_out_dstunreach); \
			 if (code == ICMP6_DST_UNREACH_ADMIN) \
				 icmp6_ifstat_inc(ifp, ifs6_out_adminprohib); \
			 break; \
		 case ICMP6_PACKET_TOO_BIG: \
			 icmp6_ifstat_inc(ifp, ifs6_out_pkttoobig); \
			 break; \
		 case ICMP6_TIME_EXCEEDED: \
			 icmp6_ifstat_inc(ifp, ifs6_out_timeexceed); \
			 break; \
		 case ICMP6_PARAM_PROB: \
			 icmp6_ifstat_inc(ifp, ifs6_out_paramprob); \
			 break; \
		 case ICMP6_ECHO_REQUEST: \
			 icmp6_ifstat_inc(ifp, ifs6_out_echo); \
			 break; \
		 case ICMP6_ECHO_REPLY: \
			 icmp6_ifstat_inc(ifp, ifs6_out_echoreply); \
			 break; \
		 case MLD_LISTENER_QUERY: \
			 icmp6_ifstat_inc(ifp, ifs6_out_mldquery); \
			 break; \
		 case MLD_LISTENER_REPORT: \
			 icmp6_ifstat_inc(ifp, ifs6_out_mldreport); \
			 break; \
		 case MLD_LISTENER_DONE: \
			 icmp6_ifstat_inc(ifp, ifs6_out_mlddone); \
			 break; \
		 case ND_ROUTER_SOLICIT: \
			 icmp6_ifstat_inc(ifp, ifs6_out_routersolicit); \
			 break; \
		 case ND_ROUTER_ADVERT: \
			 icmp6_ifstat_inc(ifp, ifs6_out_routeradvert); \
			 break; \
		 case ND_NEIGHBOR_SOLICIT: \
			 icmp6_ifstat_inc(ifp, ifs6_out_neighborsolicit); \
			 break; \
		 case ND_NEIGHBOR_ADVERT: \
			 icmp6_ifstat_inc(ifp, ifs6_out_neighboradvert); \
			 break; \
		 case ND_REDIRECT: \
			 icmp6_ifstat_inc(ifp, ifs6_out_redirect); \
			 break; \
		} \
} while ( 0)
#define icmp6_ifstat_inc(ifp, tag) \
do {								\
	if (ifp)						\
		counter_u64_add(((struct in6_ifextra *)		\
		    ((ifp)->if_afdata[AF_INET6]))->icmp6_ifstat[\
		    offsetof(struct icmp6_ifstat, tag) / sizeof(uint64_t)], 1);\
} while ( 0)
#define icp6s_odst_unreach_addr icp6s_outerrhist.icp6errs_dst_unreach_addr
#define icp6s_odst_unreach_admin icp6s_outerrhist.icp6errs_dst_unreach_admin
#define icp6s_odst_unreach_beyondscope \
	icp6s_outerrhist.icp6errs_dst_unreach_beyondscope
#define icp6s_odst_unreach_noport icp6s_outerrhist.icp6errs_dst_unreach_noport
#define icp6s_odst_unreach_noroute \
	icp6s_outerrhist.icp6errs_dst_unreach_noroute
#define icp6s_opacket_too_big icp6s_outerrhist.icp6errs_packet_too_big
#define icp6s_oparamprob_header icp6s_outerrhist.icp6errs_paramprob_header
#define icp6s_oparamprob_nextheader \
	icp6s_outerrhist.icp6errs_paramprob_nextheader
#define icp6s_oparamprob_option icp6s_outerrhist.icp6errs_paramprob_option
#define icp6s_oredirect icp6s_outerrhist.icp6errs_redirect
#define icp6s_otime_exceed_reassembly \
	icp6s_outerrhist.icp6errs_time_exceed_reassembly
#define icp6s_otime_exceed_transit \
	icp6s_outerrhist.icp6errs_time_exceed_transit
#define icp6s_ounknown icp6s_outerrhist.icp6errs_unknown
#define rr_seqnum 	rr_hdr.icmp6_data32[0]

#define IP6A_RTALERTSEEN 0x08		
#define IP6PO_TEMPADDR_NOTPREFER 0 
#define IP6_HDR_ALIGNED_P(ip)	1
#define IP6_REASS_MBUF(ip6af) (*(struct mbuf **)&((ip6af)->ip6af_m))

#define IP6OPT_TYPE(o)		((o) & 0xC0)
#define IP6_EXTHDR_CHECK(m, off, hlen, ret)				\
do {									\
    if ((m)->m_next != NULL) {						\
	if (((m)->m_flags & M_LOOP) &&					\
	    ((m)->m_len < (off) + (hlen)) &&				\
	    (((m) = m_pullup((m), (off) + (hlen))) == NULL)) {		\
		IP6STAT_INC(ip6s_exthdrtoolong);				\
		return ret;						\
	} else if ((m)->m_flags & M_EXT) {				\
		if ((m)->m_len < (off) + (hlen)) {			\
			IP6STAT_INC(ip6s_exthdrtoolong);			\
			m_freem(m);					\
			return ret;					\
		}							\
	} else {							\
		if ((m)->m_len < (off) + (hlen)) {			\
			IP6STAT_INC(ip6s_exthdrtoolong);			\
			m_freem(m);					\
			return ret;					\
		}							\
	}								\
    } else {								\
	if ((m)->m_len < (off) + (hlen)) {				\
		IP6STAT_INC(ip6s_tooshort);				\
		in6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_truncated);	\
		m_freem(m);						\
		return ret;						\
	}								\
    }									\
} while ( 0)
#define IP6_EXTHDR_GET(val, typ, m, off, len) \
do {									\
	struct mbuf *t;							\
	int tmp;							\
	if ((m)->m_len >= (off) + (len))				\
		(val) = (typ)(mtod((m), caddr_t) + (off));		\
	else {								\
		t = m_pulldown((m), (off), (len), &tmp);		\
		if (t) {						\
			if (t->m_len < tmp + (len))			\
				panic("m_pulldown malfunction");	\
			(val) = (typ)(mtod(t, caddr_t) + tmp);		\
		} else {						\
			(val) = (typ)NULL;				\
			(m) = NULL;					\
		}							\
	}								\
} while ( 0)
#define IP6_EXTHDR_GET0(val, typ, m, off, len) \
do {									\
	struct mbuf *t;							\
	if ((off) == 0)							\
		(val) = (typ)mtod(m, caddr_t);				\
	else {								\
		t = m_pulldown((m), (off), (len), NULL);		\
		if (t) {						\
			if (t->m_len < (len))				\
				panic("m_pulldown malfunction");	\
			(val) = (typ)mtod(t, caddr_t);			\
		} else {						\
			(val) = (typ)NULL;				\
			(m) = NULL;					\
		}							\
	}								\
} while ( 0)



#define _ARRAYLEN(p) (sizeof(p)/sizeof(p[0]))
#define _KEYBITS(key) ((u_int)((key)->bits))
#define _KEYBUF(key) ((caddr_t)((caddr_t)(key) + sizeof(struct sadb_key)))
#define _KEYLEN(key) ((u_int)((key)->bits >> 3))

#define PFKEYV2_REVISION        199806L
#define PFKEY_ADDR_PREFIX(ext) \
	(((struct sadb_address *)(ext))->sadb_address_prefixlen)
#define PFKEY_ADDR_PROTO(ext) \
	(((struct sadb_address *)(ext))->sadb_address_proto)
#define PFKEY_ADDR_SADDR(ext) \
	((struct sockaddr *)((caddr_t)(ext) + sizeof(struct sadb_address)))
#define PFKEY_ALIGN8(a) (1 + (((a) - 1) | (8 - 1)))
#define PF_KEY_V2 2
#define SADB_ACQUIRE     6
#define SADB_ADD         3
#define SADB_DELETE      4
#define SADB_DUMP        10
#define SADB_EXPIRE      8
#define SADB_EXT_ADDRESS_DST          6
#define SADB_EXT_ADDRESS_PROXY        7
#define SADB_EXT_ADDRESS_SRC          5
#define SADB_EXT_IDENTITY_DST         11
#define SADB_EXT_IDENTITY_SRC         10
#define SADB_EXT_KEY_AUTH             8
#define SADB_EXT_KEY_ENCRYPT          9
#define SADB_EXT_LIFETIME_CURRENT     2
#define SADB_EXT_LIFETIME_HARD        3
#define SADB_EXT_LIFETIME_SOFT        4
#define SADB_EXT_MAX                  25
#define SADB_EXT_PROPOSAL             13
#define SADB_EXT_RESERVED             0
#define SADB_EXT_SA                   1
#define SADB_EXT_SENSITIVITY          12
#define SADB_EXT_SPIRANGE             16
#define SADB_EXT_SUPPORTED_AUTH       14
#define SADB_EXT_SUPPORTED_ENCRYPT    15
#define SADB_FLUSH       9
#define SADB_GET         5
#define SADB_GETSPI      1
#define SADB_IDENTTYPE_FQDN       2
#define SADB_IDENTTYPE_MAX        4
#define SADB_IDENTTYPE_PREFIX     1
#define SADB_IDENTTYPE_RESERVED   0
#define SADB_IDENTTYPE_USERFQDN   3
#define SADB_MAX          22
#define SADB_REGISTER    7
#define SADB_RESERVED    0
#define SADB_SAFLAGS_PFS      1
#define SADB_SASTATE_DEAD     3
#define SADB_SASTATE_DYING    2
#define SADB_SASTATE_LARVAL   0
#define SADB_SASTATE_MATURE   1
#define SADB_SASTATE_MAX      3
#define SADB_UPDATE      2
#define SADB_X_EXT_KMPRIVATE          17
#define SADB_X_EXT_NAT_T_DPORT        22
#define SADB_X_EXT_NAT_T_FRAG         25	
#define SADB_X_EXT_NAT_T_OA           23	
#define SADB_X_EXT_NAT_T_OAI          23	
#define SADB_X_EXT_NAT_T_OAR          24	
#define SADB_X_EXT_NAT_T_SPORT        21
#define SADB_X_EXT_NAT_T_TYPE         20
#define SADB_X_EXT_POLICY             18
#define SADB_X_EXT_SA2                19
#define SADB_X_IDENTTYPE_ADDR     4
#define SADB_X_PCHANGE   12
#define SADB_X_PROMISC   11
#define SADB_X_SPDACQUIRE 17
#define SADB_X_SPDADD     14
#define SADB_X_SPDDELETE  15	
#define SADB_X_SPDDELETE2 22	
#define SADB_X_SPDDUMP    18
#define SADB_X_SPDEXPIRE  21
#define SADB_X_SPDFLUSH   19
#define SADB_X_SPDGET     16
#define SADB_X_SPDSETIDX  20
#define SADB_X_SPDUPDATE  13

#define __PFKEY_V2_H 1


#define IPSEC_REPLAYWSIZE  32

#define ipseclog(x)	do { if (V_ipsec_debug) log x; } while (0)
#define BANDLIM_ICMP6_UNREACH 5
#define BANDLIM_ICMP_ECHO 1
#define BANDLIM_ICMP_TSTAMP 2
#define BANDLIM_ICMP_UNREACH 0
#define BANDLIM_MAX 6
#define BANDLIM_RST_CLOSEDPORT 3 
#define BANDLIM_RST_OPENPORT 4   
#define BANDLIM_SCTP_OOTB 6
#define BANDLIM_UNLIMITED -1

#define		ICMP_PARAMPROB_ERRATPTR 0		
#define		ICMP_PARAMPROB_LENGTH 2			
#define		ICMP_PARAMPROB_OPTABSENT 1		
#define		ICMP_UNREACH_FILTER_PROHIB 13		
#define		ICMP_UNREACH_HOST_PRECEDENCE 14		
#define		ICMP_UNREACH_HOST_PROHIB 10		
#define		ICMP_UNREACH_HOST_UNKNOWN 7		
#define		ICMP_UNREACH_NET_UNKNOWN 6		
#define		ICMP_UNREACH_PRECEDENCE_CUTOFF 15	

#define IP_HDR_ALIGNED_P(ip)	1
#define IA_DSTSIN(ia) (&(((struct in_ifaddr *)(ia))->ia_dstaddr))
#define IA_MASKSIN(ia) (&(((struct in_ifaddr *)(ia))->ia_sockmask))
#define IA_SIN(ia)    (&(((struct in_ifaddr *)(ia))->ia_addr))
#define IFP_TO_IA(ifp, ia)						\
						\
						\
do {									\
	IN_IFADDR_RLOCK();						\
	for ((ia) = TAILQ_FIRST(&V_in_ifaddrhead);			\
	    (ia) != NULL && (ia)->ia_ifp != (ifp);			\
	    (ia) = TAILQ_NEXT((ia), ia_link))				\
		continue;						\
	if ((ia) != NULL)						\
		ifa_ref(&(ia)->ia_ifa);					\
	IN_IFADDR_RUNLOCK();						\
} while (0)
#define INADDR_HASH(x) \
	(&V_in_ifaddrhashtbl[INADDR_HASHVAL(x) & V_in_ifaddrhmask])
#define INADDR_HASHVAL(x)	fnv_32_buf((&(x)), sizeof(x), FNV1_32_INIT)
#define INADDR_NHASH_LOG2       9
#define INADDR_TO_IFADDR(addr, ia) \
	 \
	 \
do { \
\
	LIST_FOREACH(ia, INADDR_HASH((addr).s_addr), ia_hash) \
		if (IA_SIN(ia)->sin_addr.s_addr == (addr).s_addr) \
			break; \
} while (0)
#define INADDR_TO_IFP(addr, ifp) \
	 \
	 \
{ \
	struct in_ifaddr *ia; \
\
	INADDR_TO_IFADDR(addr, ia); \
	(ifp) = (ia == NULL) ? NULL : ia->ia_ifp; \
}
#define IN_LNAOF(in, ifa) \
	((ntohl((in).s_addr) & ~((struct in_ifaddr *)(ifa)->ia_subnetmask))
#define LLTABLE(ifp)	\
	((struct in_ifinfo *)(ifp)->if_afdata[AF_INET])->ii_llt

#define ifra_dstaddr ifra_broadaddr
#define IA6_DSTIN6(ia)	(&((ia)->ia_dstaddr.sin6_addr))
#define IA6_DSTSIN6(ia)	(&((ia)->ia_dstaddr))
#define IA6_IN6(ia)	(&((ia)->ia_addr.sin6_addr))
#define IA6_MASKIN6(ia)	(&((ia)->ia_prefixmask.sin6_addr))
#define IA6_SIN6(ia)	(&((ia)->ia_addr))
#define IFA_DSTIN6(x)	(&((struct sockaddr_in6 *)((x)->ifa_dstaddr))->sin6_addr)
#define IFA_IN6(x)	(&((struct sockaddr_in6 *)((x)->ifa_addr))->sin6_addr)
#define IFPR_IN6(x)	(&((struct sockaddr_in6 *)((x)->ifpr_prefix))->sin6_addr)
#define IN6_ARE_MASKED_ADDR_EQUAL(d, a, m)	(	\
	(((d)->s6_addr32[0] ^ (a)->s6_addr32[0]) & (m)->s6_addr32[0]) == 0 && \
	(((d)->s6_addr32[1] ^ (a)->s6_addr32[1]) & (m)->s6_addr32[1]) == 0 && \
	(((d)->s6_addr32[2] ^ (a)->s6_addr32[2]) & (m)->s6_addr32[2]) == 0 && \
	(((d)->s6_addr32[3] ^ (a)->s6_addr32[3]) & (m)->s6_addr32[3]) == 0 )
#define IN6_ARE_SCOPE_CMP(a,b) ((a)-(b))
#define IN6_ARE_SCOPE_EQUAL(a,b) ((a)==(b))
#define IN6_IFF_NOTREADY (IN6_IFF_TENTATIVE|IN6_IFF_DUPLICATED)
#define IN6_MASK_ADDR(a, m)	do { \
	(a)->s6_addr32[0] &= (m)->s6_addr32[0]; \
	(a)->s6_addr32[1] &= (m)->s6_addr32[1]; \
	(a)->s6_addr32[2] &= (m)->s6_addr32[2]; \
	(a)->s6_addr32[3] &= (m)->s6_addr32[3]; \
} while (0)
#define SIOCSIFPHYADDR_IN6       _IOW('i', 70, struct in6_aliasreq)

#define in6_ifstat_inc(ifp, tag) \
do {								\
	if (ifp)						\
		counter_u64_add(((struct in6_ifextra *)		\
		    ((ifp)->if_afdata[AF_INET6]))->in6_ifstat[	\
		    offsetof(struct in6_ifstat, tag) / sizeof(uint64_t)], 1);\
} while ( 0)
#define CALLOUT_HANDLE_INITIALIZER(handle)	\
	{ NULL }
#define ovbcopy(f, t, l) bcopy((f), (t), (l))

#define FNV1_32_INIT ((Fnv32_t) 33554467UL)
#define FNV1_64_INIT ((Fnv64_t) 0xcbf29ce484222325ULL)
#define FNV_32_PRIME ((Fnv32_t) 0x01000193UL)
#define FNV_64_PRIME ((Fnv64_t) 0x100000001b3ULL)
#define RB_AUGMENT(x)	do {} while (0)
#define RB_COLOR(elm, field)		(elm)->field.rbe_color
#define RB_EMPTY(head)			(RB_ROOT(head) == NULL)
#define RB_ENTRY(type)							\
struct {								\
	struct type *rbe_left;				\
	struct type *rbe_right;				\
	struct type *rbe_parent;			\
	int rbe_color;					\
}
#define RB_FIND(name, x, y)	name##_RB_FIND(x, y)
#define RB_FOREACH(x, name, head)					\
	for ((x) = RB_MIN(name, head);					\
	     (x) != NULL;						\
	     (x) = name##_RB_NEXT(x))
#define RB_FOREACH_FROM(x, name, y)					\
	for ((x) = (y);							\
	    ((x) != NULL) && ((y) = name##_RB_NEXT(x), (x) != NULL);	\
	     (x) = (y))
#define RB_FOREACH_REVERSE(x, name, head)				\
	for ((x) = RB_MAX(name, head);					\
	     (x) != NULL;						\
	     (x) = name##_RB_PREV(x))
#define RB_FOREACH_REVERSE_FROM(x, name, y)				\
	for ((x) = (y);							\
	    ((x) != NULL) && ((y) = name##_RB_PREV(x), (x) != NULL);	\
	     (x) = (y))
#define RB_FOREACH_REVERSE_SAFE(x, name, head, y)			\
	for ((x) = RB_MAX(name, head);					\
	    ((x) != NULL) && ((y) = name##_RB_PREV(x), (x) != NULL);	\
	     (x) = (y))
#define RB_FOREACH_SAFE(x, name, head, y)				\
	for ((x) = RB_MIN(name, head);					\
	    ((x) != NULL) && ((y) = name##_RB_NEXT(x), (x) != NULL);	\
	     (x) = (y))
#define RB_GENERATE_INTERNAL(name, type, field, cmp, attr)		\
attr void								\
name##_RB_INSERT_COLOR(struct name *head, struct type *elm)		\
{									\
	struct type *parent, *gparent, *tmp;				\
	while ((parent = RB_PARENT(elm, field)) != NULL &&		\
	    RB_COLOR(parent, field) == RB_RED) {			\
		gparent = RB_PARENT(parent, field);			\
		if (parent == RB_LEFT(gparent, field)) {		\
			tmp = RB_RIGHT(gparent, field);			\
			if (tmp && RB_COLOR(tmp, field) == RB_RED) {	\
				RB_COLOR(tmp, field) = RB_BLACK;	\
				RB_SET_BLACKRED(parent, gparent, field);\
				elm = gparent;				\
				continue;				\
			}						\
			if (RB_RIGHT(parent, field) == elm) {		\
				RB_ROTATE_LEFT(head, parent, tmp, field);\
				tmp = parent;				\
				parent = elm;				\
				elm = tmp;				\
			}						\
			RB_SET_BLACKRED(parent, gparent, field);	\
			RB_ROTATE_RIGHT(head, gparent, tmp, field);	\
		} else {						\
			tmp = RB_LEFT(gparent, field);			\
			if (tmp && RB_COLOR(tmp, field) == RB_RED) {	\
				RB_COLOR(tmp, field) = RB_BLACK;	\
				RB_SET_BLACKRED(parent, gparent, field);\
				elm = gparent;				\
				continue;				\
			}						\
			if (RB_LEFT(parent, field) == elm) {		\
				RB_ROTATE_RIGHT(head, parent, tmp, field);\
				tmp = parent;				\
				parent = elm;				\
				elm = tmp;				\
			}						\
			RB_SET_BLACKRED(parent, gparent, field);	\
			RB_ROTATE_LEFT(head, gparent, tmp, field);	\
		}							\
	}								\
	RB_COLOR(head->rbh_root, field) = RB_BLACK;			\
}									\
									\
attr void								\
name##_RB_REMOVE_COLOR(struct name *head, struct type *parent, struct type *elm) \
{									\
	struct type *tmp;						\
	while ((elm == NULL || RB_COLOR(elm, field) == RB_BLACK) &&	\
	    elm != RB_ROOT(head)) {					\
		if (RB_LEFT(parent, field) == elm) {			\
			tmp = RB_RIGHT(parent, field);			\
			if (RB_COLOR(tmp, field) == RB_RED) {		\
				RB_SET_BLACKRED(tmp, parent, field);	\
				RB_ROTATE_LEFT(head, parent, tmp, field);\
				tmp = RB_RIGHT(parent, field);		\
			}						\
			if ((RB_LEFT(tmp, field) == NULL ||		\
			    RB_COLOR(RB_LEFT(tmp, field), field) == RB_BLACK) &&\
			    (RB_RIGHT(tmp, field) == NULL ||		\
			    RB_COLOR(RB_RIGHT(tmp, field), field) == RB_BLACK)) {\
				RB_COLOR(tmp, field) = RB_RED;		\
				elm = parent;				\
				parent = RB_PARENT(elm, field);		\
			} else {					\
				if (RB_RIGHT(tmp, field) == NULL ||	\
				    RB_COLOR(RB_RIGHT(tmp, field), field) == RB_BLACK) {\
					struct type *oleft;		\
					if ((oleft = RB_LEFT(tmp, field)) \
					    != NULL)			\
						RB_COLOR(oleft, field) = RB_BLACK;\
					RB_COLOR(tmp, field) = RB_RED;	\
					RB_ROTATE_RIGHT(head, tmp, oleft, field);\
					tmp = RB_RIGHT(parent, field);	\
				}					\
				RB_COLOR(tmp, field) = RB_COLOR(parent, field);\
				RB_COLOR(parent, field) = RB_BLACK;	\
				if (RB_RIGHT(tmp, field))		\
					RB_COLOR(RB_RIGHT(tmp, field), field) = RB_BLACK;\
				RB_ROTATE_LEFT(head, parent, tmp, field);\
				elm = RB_ROOT(head);			\
				break;					\
			}						\
		} else {						\
			tmp = RB_LEFT(parent, field);			\
			if (RB_COLOR(tmp, field) == RB_RED) {		\
				RB_SET_BLACKRED(tmp, parent, field);	\
				RB_ROTATE_RIGHT(head, parent, tmp, field);\
				tmp = RB_LEFT(parent, field);		\
			}						\
			if ((RB_LEFT(tmp, field) == NULL ||		\
			    RB_COLOR(RB_LEFT(tmp, field), field) == RB_BLACK) &&\
			    (RB_RIGHT(tmp, field) == NULL ||		\
			    RB_COLOR(RB_RIGHT(tmp, field), field) == RB_BLACK)) {\
				RB_COLOR(tmp, field) = RB_RED;		\
				elm = parent;				\
				parent = RB_PARENT(elm, field);		\
			} else {					\
				if (RB_LEFT(tmp, field) == NULL ||	\
				    RB_COLOR(RB_LEFT(tmp, field), field) == RB_BLACK) {\
					struct type *oright;		\
					if ((oright = RB_RIGHT(tmp, field)) \
					    != NULL)			\
						RB_COLOR(oright, field) = RB_BLACK;\
					RB_COLOR(tmp, field) = RB_RED;	\
					RB_ROTATE_LEFT(head, tmp, oright, field);\
					tmp = RB_LEFT(parent, field);	\
				}					\
				RB_COLOR(tmp, field) = RB_COLOR(parent, field);\
				RB_COLOR(parent, field) = RB_BLACK;	\
				if (RB_LEFT(tmp, field))		\
					RB_COLOR(RB_LEFT(tmp, field), field) = RB_BLACK;\
				RB_ROTATE_RIGHT(head, parent, tmp, field);\
				elm = RB_ROOT(head);			\
				break;					\
			}						\
		}							\
	}								\
	if (elm)							\
		RB_COLOR(elm, field) = RB_BLACK;			\
}									\
									\
attr struct type *							\
name##_RB_REMOVE(struct name *head, struct type *elm)			\
{									\
	struct type *child, *parent, *old = elm;			\
	int color;							\
	if (RB_LEFT(elm, field) == NULL)				\
		child = RB_RIGHT(elm, field);				\
	else if (RB_RIGHT(elm, field) == NULL)				\
		child = RB_LEFT(elm, field);				\
	else {								\
		struct type *left;					\
		elm = RB_RIGHT(elm, field);				\
		while ((left = RB_LEFT(elm, field)) != NULL)		\
			elm = left;					\
		child = RB_RIGHT(elm, field);				\
		parent = RB_PARENT(elm, field);				\
		color = RB_COLOR(elm, field);				\
		if (child)						\
			RB_PARENT(child, field) = parent;		\
		if (parent) {						\
			if (RB_LEFT(parent, field) == elm)		\
				RB_LEFT(parent, field) = child;		\
			else						\
				RB_RIGHT(parent, field) = child;	\
			RB_AUGMENT(parent);				\
		} else							\
			RB_ROOT(head) = child;				\
		if (RB_PARENT(elm, field) == old)			\
			parent = elm;					\
		(elm)->field = (old)->field;				\
		if (RB_PARENT(old, field)) {				\
			if (RB_LEFT(RB_PARENT(old, field), field) == old)\
				RB_LEFT(RB_PARENT(old, field), field) = elm;\
			else						\
				RB_RIGHT(RB_PARENT(old, field), field) = elm;\
			RB_AUGMENT(RB_PARENT(old, field));		\
		} else							\
			RB_ROOT(head) = elm;				\
		RB_PARENT(RB_LEFT(old, field), field) = elm;		\
		if (RB_RIGHT(old, field))				\
			RB_PARENT(RB_RIGHT(old, field), field) = elm;	\
		if (parent) {						\
			left = parent;					\
			do {						\
				RB_AUGMENT(left);			\
			} while ((left = RB_PARENT(left, field)) != NULL); \
		}							\
		goto color;						\
	}								\
	parent = RB_PARENT(elm, field);					\
	color = RB_COLOR(elm, field);					\
	if (child)							\
		RB_PARENT(child, field) = parent;			\
	if (parent) {							\
		if (RB_LEFT(parent, field) == elm)			\
			RB_LEFT(parent, field) = child;			\
		else							\
			RB_RIGHT(parent, field) = child;		\
		RB_AUGMENT(parent);					\
	} else								\
		RB_ROOT(head) = child;					\
color:									\
	if (color == RB_BLACK)						\
		name##_RB_REMOVE_COLOR(head, parent, child);		\
	return (old);							\
}									\
									\
					\
attr struct type *							\
name##_RB_INSERT(struct name *head, struct type *elm)			\
{									\
	struct type *tmp;						\
	struct type *parent = NULL;					\
	int comp = 0;							\
	tmp = RB_ROOT(head);						\
	while (tmp) {							\
		parent = tmp;						\
		comp = (cmp)(elm, parent);				\
		if (comp < 0)						\
			tmp = RB_LEFT(tmp, field);			\
		else if (comp > 0)					\
			tmp = RB_RIGHT(tmp, field);			\
		else							\
			return (tmp);					\
	}								\
	RB_SET(elm, parent, field);					\
	if (parent != NULL) {						\
		if (comp < 0)						\
			RB_LEFT(parent, field) = elm;			\
		else							\
			RB_RIGHT(parent, field) = elm;			\
		RB_AUGMENT(parent);					\
	} else								\
		RB_ROOT(head) = elm;					\
	name##_RB_INSERT_COLOR(head, elm);				\
	return (NULL);							\
}									\
									\
				\
attr struct type *							\
name##_RB_FIND(struct name *head, struct type *elm)			\
{									\
	struct type *tmp = RB_ROOT(head);				\
	int comp;							\
	while (tmp) {							\
		comp = cmp(elm, tmp);					\
		if (comp < 0)						\
			tmp = RB_LEFT(tmp, field);			\
		else if (comp > 0)					\
			tmp = RB_RIGHT(tmp, field);			\
		else							\
			return (tmp);					\
	}								\
	return (NULL);							\
}									\
									\
	\
attr struct type *							\
name##_RB_NFIND(struct name *head, struct type *elm)			\
{									\
	struct type *tmp = RB_ROOT(head);				\
	struct type *res = NULL;					\
	int comp;							\
	while (tmp) {							\
		comp = cmp(elm, tmp);					\
		if (comp < 0) {						\
			res = tmp;					\
			tmp = RB_LEFT(tmp, field);			\
		}							\
		else if (comp > 0)					\
			tmp = RB_RIGHT(tmp, field);			\
		else							\
			return (tmp);					\
	}								\
	return (res);							\
}									\
									\
								\
attr struct type *							\
name##_RB_NEXT(struct type *elm)					\
{									\
	if (RB_RIGHT(elm, field)) {					\
		elm = RB_RIGHT(elm, field);				\
		while (RB_LEFT(elm, field))				\
			elm = RB_LEFT(elm, field);			\
	} else {							\
		if (RB_PARENT(elm, field) &&				\
		    (elm == RB_LEFT(RB_PARENT(elm, field), field)))	\
			elm = RB_PARENT(elm, field);			\
		else {							\
			while (RB_PARENT(elm, field) &&			\
			    (elm == RB_RIGHT(RB_PARENT(elm, field), field)))\
				elm = RB_PARENT(elm, field);		\
			elm = RB_PARENT(elm, field);			\
		}							\
	}								\
	return (elm);							\
}									\
									\
								\
attr struct type *							\
name##_RB_PREV(struct type *elm)					\
{									\
	if (RB_LEFT(elm, field)) {					\
		elm = RB_LEFT(elm, field);				\
		while (RB_RIGHT(elm, field))				\
			elm = RB_RIGHT(elm, field);			\
	} else {							\
		if (RB_PARENT(elm, field) &&				\
		    (elm == RB_RIGHT(RB_PARENT(elm, field), field)))	\
			elm = RB_PARENT(elm, field);			\
		else {							\
			while (RB_PARENT(elm, field) &&			\
			    (elm == RB_LEFT(RB_PARENT(elm, field), field)))\
				elm = RB_PARENT(elm, field);		\
			elm = RB_PARENT(elm, field);			\
		}							\
	}								\
	return (elm);							\
}									\
									\
attr struct type *							\
name##_RB_MINMAX(struct name *head, int val)				\
{									\
	struct type *tmp = RB_ROOT(head);				\
	struct type *parent = NULL;					\
	while (tmp) {							\
		parent = tmp;						\
		if (val < 0)						\
			tmp = RB_LEFT(tmp, field);			\
		else							\
			tmp = RB_RIGHT(tmp, field);			\
	}								\
	return (parent);						\
}
#define RB_HEAD(name, type)						\
struct name {								\
	struct type *rbh_root; 			\
}
#define RB_INIT(root) do {						\
	(root)->rbh_root = NULL;					\
} while ( 0)
#define RB_INITIALIZER(root)						\
	{ NULL }
#define RB_INSERT(name, x, y)	name##_RB_INSERT(x, y)
#define RB_LEFT(elm, field)		(elm)->field.rbe_left
#define RB_MAX(name, x)		name##_RB_MINMAX(x, RB_INF)
#define RB_MIN(name, x)		name##_RB_MINMAX(x, RB_NEGINF)
#define RB_NEXT(name, x, y)	name##_RB_NEXT(y)
#define RB_NFIND(name, x, y)	name##_RB_NFIND(x, y)
#define RB_PARENT(elm, field)		(elm)->field.rbe_parent
#define RB_PREV(name, x, y)	name##_RB_PREV(y)
#define RB_PROTOTYPE_INTERNAL(name, type, field, cmp, attr)		\
attr void name##_RB_INSERT_COLOR(struct name *, struct type *);		\
attr void name##_RB_REMOVE_COLOR(struct name *, struct type *, struct type *);\
attr struct type *name##_RB_REMOVE(struct name *, struct type *);	\
attr struct type *name##_RB_INSERT(struct name *, struct type *);	\
attr struct type *name##_RB_FIND(struct name *, struct type *);		\
attr struct type *name##_RB_NFIND(struct name *, struct type *);	\
attr struct type *name##_RB_NEXT(struct type *);			\
attr struct type *name##_RB_PREV(struct type *);			\
attr struct type *name##_RB_MINMAX(struct name *, int);			\
									\

#define RB_REMOVE(name, x, y)	name##_RB_REMOVE(x, y)
#define RB_RIGHT(elm, field)		(elm)->field.rbe_right
#define RB_ROOT(head)			(head)->rbh_root
#define RB_ROTATE_LEFT(head, elm, tmp, field) do {			\
	(tmp) = RB_RIGHT(elm, field);					\
	if ((RB_RIGHT(elm, field) = RB_LEFT(tmp, field)) != NULL) {	\
		RB_PARENT(RB_LEFT(tmp, field), field) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	if ((RB_PARENT(tmp, field) = RB_PARENT(elm, field)) != NULL) {	\
		if ((elm) == RB_LEFT(RB_PARENT(elm, field), field))	\
			RB_LEFT(RB_PARENT(elm, field), field) = (tmp);	\
		else							\
			RB_RIGHT(RB_PARENT(elm, field), field) = (tmp);	\
	} else								\
		(head)->rbh_root = (tmp);				\
	RB_LEFT(tmp, field) = (elm);					\
	RB_PARENT(elm, field) = (tmp);					\
	RB_AUGMENT(tmp);						\
	if ((RB_PARENT(tmp, field)))					\
		RB_AUGMENT(RB_PARENT(tmp, field));			\
} while ( 0)
#define RB_ROTATE_RIGHT(head, elm, tmp, field) do {			\
	(tmp) = RB_LEFT(elm, field);					\
	if ((RB_LEFT(elm, field) = RB_RIGHT(tmp, field)) != NULL) {	\
		RB_PARENT(RB_RIGHT(tmp, field), field) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	if ((RB_PARENT(tmp, field) = RB_PARENT(elm, field)) != NULL) {	\
		if ((elm) == RB_LEFT(RB_PARENT(elm, field), field))	\
			RB_LEFT(RB_PARENT(elm, field), field) = (tmp);	\
		else							\
			RB_RIGHT(RB_PARENT(elm, field), field) = (tmp);	\
	} else								\
		(head)->rbh_root = (tmp);				\
	RB_RIGHT(tmp, field) = (elm);					\
	RB_PARENT(elm, field) = (tmp);					\
	RB_AUGMENT(tmp);						\
	if ((RB_PARENT(tmp, field)))					\
		RB_AUGMENT(RB_PARENT(tmp, field));			\
} while ( 0)
#define RB_SET(elm, parent, field) do {					\
	RB_PARENT(elm, field) = parent;					\
	RB_LEFT(elm, field) = RB_RIGHT(elm, field) = NULL;		\
	RB_COLOR(elm, field) = RB_RED;					\
} while ( 0)
#define RB_SET_BLACKRED(black, red, field) do {				\
	RB_COLOR(black, field) = RB_BLACK;				\
	RB_COLOR(red, field) = RB_RED;					\
} while ( 0)
#define SPLAY_ASSEMBLE(head, node, left, right, field) do {		\
	SPLAY_RIGHT(left, field) = SPLAY_LEFT((head)->sph_root, field);	\
	SPLAY_LEFT(right, field) = SPLAY_RIGHT((head)->sph_root, field);\
	SPLAY_LEFT((head)->sph_root, field) = SPLAY_RIGHT(node, field);	\
	SPLAY_RIGHT((head)->sph_root, field) = SPLAY_LEFT(node, field);	\
} while ( 0)
#define SPLAY_EMPTY(head)		(SPLAY_ROOT(head) == NULL)
#define SPLAY_ENTRY(type)						\
struct {								\
	struct type *spe_left; 			\
	struct type *spe_right; 			\
}
#define SPLAY_FIND(name, x, y)		name##_SPLAY_FIND(x, y)
#define SPLAY_FOREACH(x, name, head)					\
	for ((x) = SPLAY_MIN(name, head);				\
	     (x) != NULL;						\
	     (x) = SPLAY_NEXT(name, head, x))
#define SPLAY_GENERATE(name, type, field, cmp)				\
struct type *								\
name##_SPLAY_INSERT(struct name *head, struct type *elm)		\
{									\
    if (SPLAY_EMPTY(head)) {						\
	    SPLAY_LEFT(elm, field) = SPLAY_RIGHT(elm, field) = NULL;	\
    } else {								\
	    int __comp;							\
	    name##_SPLAY(head, elm);					\
	    __comp = (cmp)(elm, (head)->sph_root);			\
	    if(__comp < 0) {						\
		    SPLAY_LEFT(elm, field) = SPLAY_LEFT((head)->sph_root, field);\
		    SPLAY_RIGHT(elm, field) = (head)->sph_root;		\
		    SPLAY_LEFT((head)->sph_root, field) = NULL;		\
	    } else if (__comp > 0) {					\
		    SPLAY_RIGHT(elm, field) = SPLAY_RIGHT((head)->sph_root, field);\
		    SPLAY_LEFT(elm, field) = (head)->sph_root;		\
		    SPLAY_RIGHT((head)->sph_root, field) = NULL;	\
	    } else							\
		    return ((head)->sph_root);				\
    }									\
    (head)->sph_root = (elm);						\
    return (NULL);							\
}									\
									\
struct type *								\
name##_SPLAY_REMOVE(struct name *head, struct type *elm)		\
{									\
	struct type *__tmp;						\
	if (SPLAY_EMPTY(head))						\
		return (NULL);						\
	name##_SPLAY(head, elm);					\
	if ((cmp)(elm, (head)->sph_root) == 0) {			\
		if (SPLAY_LEFT((head)->sph_root, field) == NULL) {	\
			(head)->sph_root = SPLAY_RIGHT((head)->sph_root, field);\
		} else {						\
			__tmp = SPLAY_RIGHT((head)->sph_root, field);	\
			(head)->sph_root = SPLAY_LEFT((head)->sph_root, field);\
			name##_SPLAY(head, elm);			\
			SPLAY_RIGHT((head)->sph_root, field) = __tmp;	\
		}							\
		return (elm);						\
	}								\
	return (NULL);							\
}									\
									\
void									\
name##_SPLAY(struct name *head, struct type *elm)			\
{									\
	struct type __node, *__left, *__right, *__tmp;			\
	int __comp;							\
\
	SPLAY_LEFT(&__node, field) = SPLAY_RIGHT(&__node, field) = NULL;\
	__left = __right = &__node;					\
\
	while ((__comp = (cmp)(elm, (head)->sph_root)) != 0) {		\
		if (__comp < 0) {					\
			__tmp = SPLAY_LEFT((head)->sph_root, field);	\
			if (__tmp == NULL)				\
				break;					\
			if ((cmp)(elm, __tmp) < 0){			\
				SPLAY_ROTATE_RIGHT(head, __tmp, field);	\
				if (SPLAY_LEFT((head)->sph_root, field) == NULL)\
					break;				\
			}						\
			SPLAY_LINKLEFT(head, __right, field);		\
		} else if (__comp > 0) {				\
			__tmp = SPLAY_RIGHT((head)->sph_root, field);	\
			if (__tmp == NULL)				\
				break;					\
			if ((cmp)(elm, __tmp) > 0){			\
				SPLAY_ROTATE_LEFT(head, __tmp, field);	\
				if (SPLAY_RIGHT((head)->sph_root, field) == NULL)\
					break;				\
			}						\
			SPLAY_LINKRIGHT(head, __left, field);		\
		}							\
	}								\
	SPLAY_ASSEMBLE(head, &__node, __left, __right, field);		\
}									\
									\
									\
void name##_SPLAY_MINMAX(struct name *head, int __comp) \
{									\
	struct type __node, *__left, *__right, *__tmp;			\
\
	SPLAY_LEFT(&__node, field) = SPLAY_RIGHT(&__node, field) = NULL;\
	__left = __right = &__node;					\
\
	while (1) {							\
		if (__comp < 0) {					\
			__tmp = SPLAY_LEFT((head)->sph_root, field);	\
			if (__tmp == NULL)				\
				break;					\
			if (__comp < 0){				\
				SPLAY_ROTATE_RIGHT(head, __tmp, field);	\
				if (SPLAY_LEFT((head)->sph_root, field) == NULL)\
					break;				\
			}						\
			SPLAY_LINKLEFT(head, __right, field);		\
		} else if (__comp > 0) {				\
			__tmp = SPLAY_RIGHT((head)->sph_root, field);	\
			if (__tmp == NULL)				\
				break;					\
			if (__comp > 0) {				\
				SPLAY_ROTATE_LEFT(head, __tmp, field);	\
				if (SPLAY_RIGHT((head)->sph_root, field) == NULL)\
					break;				\
			}						\
			SPLAY_LINKRIGHT(head, __left, field);		\
		}							\
	}								\
	SPLAY_ASSEMBLE(head, &__node, __left, __right, field);		\
}
#define SPLAY_HEAD(name, type)						\
struct name {								\
	struct type *sph_root; 			\
}
#define SPLAY_INIT(root) do {						\
	(root)->sph_root = NULL;					\
} while ( 0)
#define SPLAY_INITIALIZER(root)						\
	{ NULL }
#define SPLAY_INSERT(name, x, y)	name##_SPLAY_INSERT(x, y)
#define SPLAY_LEFT(elm, field)		(elm)->field.spe_left
#define SPLAY_LINKLEFT(head, tmp, field) do {				\
	SPLAY_LEFT(tmp, field) = (head)->sph_root;			\
	tmp = (head)->sph_root;						\
	(head)->sph_root = SPLAY_LEFT((head)->sph_root, field);		\
} while ( 0)
#define SPLAY_LINKRIGHT(head, tmp, field) do {				\
	SPLAY_RIGHT(tmp, field) = (head)->sph_root;			\
	tmp = (head)->sph_root;						\
	(head)->sph_root = SPLAY_RIGHT((head)->sph_root, field);	\
} while ( 0)
#define SPLAY_MAX(name, x)		(SPLAY_EMPTY(x) ? NULL	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_INF))
#define SPLAY_MIN(name, x)		(SPLAY_EMPTY(x) ? NULL	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_NEGINF))
#define SPLAY_NEXT(name, x, y)		name##_SPLAY_NEXT(x, y)
#define SPLAY_PROTOTYPE(name, type, field, cmp)				\
void name##_SPLAY(struct name *, struct type *);			\
void name##_SPLAY_MINMAX(struct name *, int);				\
struct type *name##_SPLAY_INSERT(struct name *, struct type *);		\
struct type *name##_SPLAY_REMOVE(struct name *, struct type *);		\
									\
				\
static __inline struct type *						\
name##_SPLAY_FIND(struct name *head, struct type *elm)			\
{									\
	if (SPLAY_EMPTY(head))						\
		return(NULL);						\
	name##_SPLAY(head, elm);					\
	if ((cmp)(elm, (head)->sph_root) == 0)				\
		return (head->sph_root);				\
	return (NULL);							\
}									\
									\
static __inline struct type *						\
name##_SPLAY_NEXT(struct name *head, struct type *elm)			\
{									\
	name##_SPLAY(head, elm);					\
	if (SPLAY_RIGHT(elm, field) != NULL) {				\
		elm = SPLAY_RIGHT(elm, field);				\
		while (SPLAY_LEFT(elm, field) != NULL) {		\
			elm = SPLAY_LEFT(elm, field);			\
		}							\
	} else								\
		elm = NULL;						\
	return (elm);							\
}									\
									\
static __inline struct type *						\
name##_SPLAY_MIN_MAX(struct name *head, int val)			\
{									\
	name##_SPLAY_MINMAX(head, val);					\
        return (SPLAY_ROOT(head));					\
}
#define SPLAY_REMOVE(name, x, y)	name##_SPLAY_REMOVE(x, y)
#define SPLAY_RIGHT(elm, field)		(elm)->field.spe_right
#define SPLAY_ROOT(head)		(head)->sph_root
#define SPLAY_ROTATE_LEFT(head, tmp, field) do {			\
	SPLAY_RIGHT((head)->sph_root, field) = SPLAY_LEFT(tmp, field);	\
	SPLAY_LEFT(tmp, field) = (head)->sph_root;			\
	(head)->sph_root = tmp;						\
} while ( 0)
#define SPLAY_ROTATE_RIGHT(head, tmp, field) do {			\
	SPLAY_LEFT((head)->sph_root, field) = SPLAY_RIGHT(tmp, field);	\
	SPLAY_RIGHT(tmp, field) = (head)->sph_root;			\
	(head)->sph_root = tmp;						\
} while ( 0)
#define INP_INFO_LOCK_DESTROY(ipi)  rw_destroy(&(ipi)->ipi_lock)
#define INP_INFO_LOCK_INIT(ipi, d) \
	rw_init_flags(&(ipi)->ipi_lock, (d), RW_RECURSE)
#define INP_INFO_RLOCK(ipi)	rw_rlock(&(ipi)->ipi_lock)
#define INP_INFO_RLOCK_ASSERT(ipi)	rw_assert(&(ipi)->ipi_lock, RA_RLOCKED)
#define INP_INFO_RUNLOCK(ipi)	rw_runlock(&(ipi)->ipi_lock)
#define INP_INFO_TRY_RLOCK(ipi)	rw_try_rlock(&(ipi)->ipi_lock)
#define INP_INFO_TRY_UPGRADE(ipi)	rw_try_upgrade(&(ipi)->ipi_lock)
#define INP_INFO_TRY_WLOCK(ipi)	rw_try_wlock(&(ipi)->ipi_lock)
#define INP_INFO_UNLOCK_ASSERT(ipi)	rw_assert(&(ipi)->ipi_lock, RA_UNLOCKED)
#define INP_INFO_WLOCK(ipi)	rw_wlock(&(ipi)->ipi_lock)
#define INP_INFO_WLOCK_ASSERT(ipi)	rw_assert(&(ipi)->ipi_lock, RA_WLOCKED)
#define INP_INFO_WUNLOCK(ipi)	rw_wunlock(&(ipi)->ipi_lock)
#define INP_LOCK_DESTROY(inp)	rw_destroy(&(inp)->inp_lock)
#define INP_LOCK_INIT(inp, d, t) \
	rw_init_flags(&(inp)->inp_lock, (t), RW_RECURSE |  RW_DUPOK)
#define INP_PCBHASH(faddr, lport, fport, mask) \
	(((faddr) ^ ((faddr) >> 16) ^ ntohs((lport) ^ (fport))) & (mask))
#define INP_PCBPORTHASH(lport, mask) \
	(ntohs((lport)) & (mask))
#define INP_RLOCK(inp)		rw_rlock(&(inp)->inp_lock)
#define INP_RUNLOCK(inp)	rw_runlock(&(inp)->inp_lock)
#define INP_TRY_RLOCK(inp)	rw_try_rlock(&(inp)->inp_lock)
#define INP_TRY_WLOCK(inp)	rw_try_wlock(&(inp)->inp_lock)
#define INP_WLOCK(inp)		rw_wlock(&(inp)->inp_lock)
#define INP_WUNLOCK(inp)	rw_wunlock(&(inp)->inp_lock)

#define inp_zero_size offsetof(struct inpcb, inp_gencnt)

#define RT_LINK_IS_UP(ifp)	(!((ifp)->if_capabilities & IFCAP_LINKSTATE) \
				 || (ifp)->if_link_state == LINK_STATE_UP)
#define SA_SIZE(sa)						\
    (  (!(sa) || ((struct sockaddr *)(sa))->sa_len == 0) ?	\
	sizeof(long)		:				\
	1 + ( (((struct sockaddr *)(sa))->sa_len - 1) | (sizeof(long) - 1) ) )

#define rtalloc_mpath(_route, _hash) rtalloc_mpath_fib((_route), (_hash), 0)
#define Free(p) free((caddr_t)p, M_RTABLE);
#define R_Free(p) free((char *)p);
#define R_Malloc(p, t, n) (p = (t) malloc((unsigned int)(n)))
#define R_Zalloc(p, t, n) (p = (t) calloc(1,(unsigned int)(n)))
#define IF_LLADDR(ifp)							\
    LLADDR((struct sockaddr_dl *)((ifp)->if_addr->ifa_addr))
#define IF_DEQUEUE(ifq, m) do { 				\
	IF_LOCK(ifq); 						\
	_IF_DEQUEUE(ifq, m); 					\
	IF_UNLOCK(ifq); 					\
} while (0)
#define IF_DRAIN(ifq) do {					\
	IF_LOCK(ifq);						\
	_IF_DRAIN(ifq);						\
	IF_UNLOCK(ifq);						\
} while(0)
#define IF_ENQUEUE(ifq, m) do {					\
	IF_LOCK(ifq); 						\
	_IF_ENQUEUE(ifq, m); 					\
	IF_UNLOCK(ifq); 					\
} while (0)
#define IF_LOCK(ifq)		mtx_lock(&(ifq)->ifq_mtx)
#define IF_PREPEND(ifq, m) do {		 			\
	IF_LOCK(ifq); 						\
	_IF_PREPEND(ifq, m); 					\
	IF_UNLOCK(ifq); 					\
} while (0)
#define IF_UNLOCK(ifq)		mtx_unlock(&(ifq)->ifq_mtx)
#define _IF_DRAIN(ifq) do { 					\
	struct mbuf *m; 					\
	for (;;) { 						\
		_IF_DEQUEUE(ifq, m); 				\
		if (m == NULL) 					\
			break; 					\
		m_freem(m); 					\
	} 							\
} while (0)
#define DEBUG_BUFRING 1
#define M_COPYFLAGS \
    (M_PKTHDR|M_EOR|M_RDONLY|M_BCAST|M_MCAST|M_VLANTAG|M_PROMISC| \
     M_PROTOFLAGS)
#define M_GETFIB(_m)   rt_m_getfib(_m)
 #define M_PROFILE(m) m_profile(m)
#define M_SETFIB(_m, _fib) do {						\
        KASSERT((_m)->m_flags & M_PKTHDR, ("Attempt to set FIB on non header mbuf."));	\
	((_m)->m_pkthdr.fibnum) = (_fib);				\
} while (0)






#define SB_EMPTY_FIXUP(sb) do {						\
	if ((sb)->sb_mb == NULL) {					\
		(sb)->sb_mbtail = NULL;					\
		(sb)->sb_lastrecord = NULL;				\
	}								\
} while (0)


#define CHUNK_FLAGS_PR_SCTP_RTX         SCTP_PR_SCTP_RTX
#define SCTP_FS_SPEC_LOG_SIZE 200
#define SCTP_TSN_LOG_SIZE 40

#define SCTPCTL_ADD_MORE_ON_OUTPUT_DEFAULT SCTP_DEFAULT_ADD_MORE
#define SCTPCTL_CMT_USE_DAC_DEFAULT    	0
#define SCTPCTL_INCOMING_STREAMS_DEFAULT SCTP_ISTREAM_INITIAL
#define SCTPCTL_OUTGOING_STREAMS_DEFAULT SCTP_OSTREAM_INITIAL

#define SCTP_NET_IS_PF(_net) (_net->pf_threshold < _net->error_count)
#define SCTP_PF_ENABLED(_net) (_net->pf_threshold < _net->failure_threshold)

#define sctp_alloc_a_chunk(_stcb, _chk) { \
	if (TAILQ_EMPTY(&(_stcb)->asoc.free_chunks)) { \
		(_chk) = SCTP_ZONE_GET(SCTP_BASE_INFO(ipi_zone_chunk), struct sctp_tmit_chunk); \
		if ((_chk)) { \
			SCTP_INCR_CHK_COUNT(); \
                        (_chk)->whoTo = NULL; \
			(_chk)->holds_key_ref = 0; \
		} \
	} else { \
		(_chk) = TAILQ_FIRST(&(_stcb)->asoc.free_chunks); \
		TAILQ_REMOVE(&(_stcb)->asoc.free_chunks, (_chk), sctp_next); \
		atomic_subtract_int(&SCTP_BASE_INFO(ipi_free_chunks), 1); \
		(_chk)->holds_key_ref = 0; \
                SCTP_STAT_INCR(sctps_cached_chk); \
		(_stcb)->asoc.free_chunk_cnt--; \
	} \
}
#define sctp_alloc_a_readq(_stcb, _readq) { \
	(_readq) = SCTP_ZONE_GET(SCTP_BASE_INFO(ipi_zone_readq), struct sctp_queued_to_read); \
	if ((_readq)) { \
 	     SCTP_INCR_READQ_COUNT(); \
	} \
}
#define sctp_alloc_a_strmoq(_stcb, _strmoq) { \
	(_strmoq) = SCTP_ZONE_GET(SCTP_BASE_INFO(ipi_zone_strmoq), struct sctp_stream_queue_pending); \
         if ((_strmoq)) {			  \
		memset(_strmoq, 0, sizeof(struct sctp_stream_queue_pending)); \
		SCTP_INCR_STRMOQ_COUNT(); \
		(_strmoq)->holds_key_ref = 0; \
 	} \
}
#define sctp_feature_off(inp, feature) (inp->sctp_features &= ~feature)
#define sctp_feature_on(inp, feature)  (inp->sctp_features |= feature)
#define sctp_flight_size_decrease(tp1) do { \
	if (tp1->whoTo->flight_size >= tp1->book_size) \
		tp1->whoTo->flight_size -= tp1->book_size; \
	else \
		tp1->whoTo->flight_size = 0; \
} while (0)
#define sctp_flight_size_increase(tp1) do { \
       (tp1)->whoTo->flight_size += (tp1)->book_size; \
} while (0)
#define sctp_free_a_chunk(_stcb, _chk, _so_locked) { \
	if ((_chk)->holds_key_ref) {\
		sctp_auth_key_release((_stcb), (_chk)->auth_keyid, _so_locked); \
		(_chk)->holds_key_ref = 0; \
	} \
        if (_stcb) { \
          SCTP_TCB_LOCK_ASSERT((_stcb)); \
          if ((_chk)->whoTo) { \
                  sctp_free_remote_addr((_chk)->whoTo); \
                  (_chk)->whoTo = NULL; \
          } \
          if (((_stcb)->asoc.free_chunk_cnt > SCTP_BASE_SYSCTL(sctp_asoc_free_resc_limit)) || \
               (SCTP_BASE_INFO(ipi_free_chunks) > SCTP_BASE_SYSCTL(sctp_system_free_resc_limit))) { \
	 	SCTP_ZONE_FREE(SCTP_BASE_INFO(ipi_zone_chunk), (_chk)); \
	 	SCTP_DECR_CHK_COUNT(); \
	  } else { \
	 	TAILQ_INSERT_TAIL(&(_stcb)->asoc.free_chunks, (_chk), sctp_next); \
	 	(_stcb)->asoc.free_chunk_cnt++; \
	 	atomic_add_int(&SCTP_BASE_INFO(ipi_free_chunks), 1); \
          } \
        } else { \
		SCTP_ZONE_FREE(SCTP_BASE_INFO(ipi_zone_chunk), (_chk)); \
		SCTP_DECR_CHK_COUNT(); \
	} \
}
#define sctp_free_a_readq(_stcb, _readq) { \
	SCTP_ZONE_FREE(SCTP_BASE_INFO(ipi_zone_readq), (_readq)); \
	SCTP_DECR_READQ_COUNT(); \
}
#define sctp_free_a_strmoq(_stcb, _strmoq, _so_locked) { \
	if ((_strmoq)->holds_key_ref) { \
		sctp_auth_key_release(stcb, sp->auth_keyid, _so_locked); \
		(_strmoq)->holds_key_ref = 0; \
	} \
	SCTP_ZONE_FREE(SCTP_BASE_INFO(ipi_zone_strmoq), (_strmoq)); \
	SCTP_DECR_STRMOQ_COUNT(); \
}
#define sctp_free_remote_addr(__net) { \
	if ((__net)) {  \
		if (SCTP_DECREMENT_AND_CHECK_REFCOUNT(&(__net)->ref_count)) { \
			(void)SCTP_OS_TIMER_STOP(&(__net)->rxt_timer.timer); \
			(void)SCTP_OS_TIMER_STOP(&(__net)->pmtu_timer.timer); \
                        if ((__net)->ro.ro_rt) { \
				RTFREE((__net)->ro.ro_rt); \
				(__net)->ro.ro_rt = NULL; \
                        } \
			if ((__net)->src_addr_selected) { \
				sctp_free_ifa((__net)->ro._s_addr); \
				(__net)->ro._s_addr = NULL; \
			} \
                        (__net)->src_addr_selected = 0; \
			(__net)->dest_state &= ~SCTP_ADDR_REACHABLE; \
			SCTP_ZONE_FREE(SCTP_BASE_INFO(ipi_zone_net), (__net)); \
			SCTP_DECR_RADDR_COUNT(); \
		} \
	} \
}
#define sctp_is_feature_off(inp, feature) ((inp->sctp_features & feature) == 0)
#define sctp_is_feature_on(inp, feature) ((inp->sctp_features & feature) == feature)
#define sctp_is_mobility_feature_off(inp, feature) ((inp->sctp_mobility_features & feature) == 0)
#define sctp_is_mobility_feature_on(inp, feature) (inp->sctp_mobility_features & feature)
#define sctp_maxspace(sb) (max((sb)->sb_hiwat,SCTP_MINIMAL_RWND))
#define sctp_mbuf_crush(data) do { \
	struct mbuf *_m; \
	_m = (data); \
	while (_m && (SCTP_BUF_LEN(_m) == 0)) { \
		(data)  = SCTP_BUF_NEXT(_m); \
		SCTP_BUF_NEXT(_m) = NULL; \
		sctp_m_free(_m); \
		_m = (data); \
	} \
} while (0)
#define sctp_mobility_feature_off(inp, feature) (inp->sctp_mobility_features &= ~feature)
#define sctp_mobility_feature_on(inp, feature)  (inp->sctp_mobility_features |= feature)
#define sctp_sballoc(stcb, sb, m) { \
	atomic_add_int(&(sb)->sb_cc,SCTP_BUF_LEN((m))); \
	atomic_add_int(&(sb)->sb_mbcnt, MSIZE); \
	if (stcb) { \
		atomic_add_int(&(stcb)->asoc.sb_cc,SCTP_BUF_LEN((m))); \
		atomic_add_int(&(stcb)->asoc.my_rwnd_control_len, MSIZE); \
	} \
	if (SCTP_BUF_TYPE(m) != MT_DATA && SCTP_BUF_TYPE(m) != MT_HEADER && \
	    SCTP_BUF_TYPE(m) != MT_OOBDATA) \
		atomic_add_int(&(sb)->sb_ctl,SCTP_BUF_LEN((m))); \
}
#define sctp_sbfree(ctl, stcb, sb, m) { \
	SCTP_SAVE_ATOMIC_DECREMENT(&(sb)->sb_cc, SCTP_BUF_LEN((m))); \
	SCTP_SAVE_ATOMIC_DECREMENT(&(sb)->sb_mbcnt, MSIZE); \
	if (((ctl)->do_not_ref_stcb == 0) && stcb) {\
		SCTP_SAVE_ATOMIC_DECREMENT(&(stcb)->asoc.sb_cc, SCTP_BUF_LEN((m))); \
		SCTP_SAVE_ATOMIC_DECREMENT(&(stcb)->asoc.my_rwnd_control_len, MSIZE); \
	} \
	if (SCTP_BUF_TYPE(m) != MT_DATA && SCTP_BUF_TYPE(m) != MT_HEADER && \
	    SCTP_BUF_TYPE(m) != MT_OOBDATA) \
		atomic_subtract_int(&(sb)->sb_ctl,SCTP_BUF_LEN((m))); \
}
#define sctp_sbspace_sub(a,b) ((a > b) ? (a - b) : 0)
#define sctp_stcb_feature_off(inp, stcb, feature) {\
	if (stcb) { \
		stcb->asoc.sctp_features &= ~feature; \
	} else if (inp) { \
		inp->sctp_features &= ~feature; \
	} \
}
#define sctp_stcb_feature_on(inp, stcb, feature) {\
	if (stcb) { \
		stcb->asoc.sctp_features |= feature; \
	} else if (inp) { \
		inp->sctp_features |= feature; \
	} \
}
#define sctp_stcb_is_feature_off(inp, stcb, feature) \
	(((stcb != NULL) && \
	  ((stcb->asoc.sctp_features & feature) == 0)) || \
	 ((stcb == NULL) && (inp != NULL) && \
	  ((inp->sctp_features & feature) == 0)) || \
         ((stcb == NULL) && (inp == NULL)))
#define sctp_stcb_is_feature_on(inp, stcb, feature) \
	(((stcb != NULL) && \
	  ((stcb->asoc.sctp_features & feature) == feature)) || \
	 ((stcb == NULL) && (inp != NULL) && \
	  ((inp->sctp_features & feature) == feature)))
#define sctp_total_flight_decrease(stcb, tp1) do { \
        if (stcb->asoc.fs_index > SCTP_FS_SPEC_LOG_SIZE) \
		stcb->asoc.fs_index = 0;\
	stcb->asoc.fslog[stcb->asoc.fs_index].total_flight = stcb->asoc.total_flight; \
	stcb->asoc.fslog[stcb->asoc.fs_index].tsn = tp1->rec.data.TSN_seq; \
	stcb->asoc.fslog[stcb->asoc.fs_index].book = tp1->book_size; \
	stcb->asoc.fslog[stcb->asoc.fs_index].sent = tp1->sent; \
	stcb->asoc.fslog[stcb->asoc.fs_index].incr = 0; \
	stcb->asoc.fslog[stcb->asoc.fs_index].decr = 1; \
	stcb->asoc.fs_index++; \
        tp1->window_probe = 0; \
	if (stcb->asoc.total_flight >= tp1->book_size) { \
		stcb->asoc.total_flight -= tp1->book_size; \
		if (stcb->asoc.total_flight_count > 0) \
			stcb->asoc.total_flight_count--; \
	} else { \
		stcb->asoc.total_flight = 0; \
		stcb->asoc.total_flight_count = 0; \
	} \
} while (0)
#define sctp_total_flight_increase(stcb, tp1) do { \
        if (stcb->asoc.fs_index > SCTP_FS_SPEC_LOG_SIZE) \
		stcb->asoc.fs_index = 0;\
	stcb->asoc.fslog[stcb->asoc.fs_index].total_flight = stcb->asoc.total_flight; \
	stcb->asoc.fslog[stcb->asoc.fs_index].tsn = tp1->rec.data.TSN_seq; \
	stcb->asoc.fslog[stcb->asoc.fs_index].book = tp1->book_size; \
	stcb->asoc.fslog[stcb->asoc.fs_index].sent = tp1->sent; \
	stcb->asoc.fslog[stcb->asoc.fs_index].incr = 1; \
	stcb->asoc.fslog[stcb->asoc.fs_index].decr = 0; \
	stcb->asoc.fs_index++; \
       (stcb)->asoc.total_flight_count++; \
       (stcb)->asoc.total_flight += (tp1)->book_size; \
} while (0)
#define sctp_ucount_decr(val) { \
	if (val > 0) { \
		val--; \
	} else { \
		val = 0; \
	} \
}
#define sctp_ucount_incr(val) { \
	val++; \
}
