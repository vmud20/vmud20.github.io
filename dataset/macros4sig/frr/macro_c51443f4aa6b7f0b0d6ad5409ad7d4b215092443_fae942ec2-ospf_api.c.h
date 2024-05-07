

#include<memory.h>















#define MAX_SEQ 2147483647
#define MIN_SEQ          1
#define MSG_DELETE_REQUEST        6
#define MSG_DEL_IF               15
#define MSG_ISM_CHANGE           16
#define MSG_LSA_DELETE_NOTIFY    13
#define MSG_LSA_UPDATE_NOTIFY    12
#define MSG_NEW_IF               14
#define MSG_NSM_CHANGE           17
#define MSG_ORIGINATE_REQUEST     5
#define MSG_READY_NOTIFY         11
#define MSG_REGISTER_EVENT        3
#define MSG_REGISTER_OPAQUETYPE   1
#define MSG_REPLY                10
#define MSG_SYNC_LSDB             4
#define MSG_UNREGISTER_OPAQUETYPE 2
#define MTYPE_OSPF_API_FIFO     MTYPE_TMP
#define MTYPE_OSPF_API_MSG      MTYPE_TMP
#define OSPF_API_ERROR                    (-9)
#define OSPF_API_ILLEGALLSATYPE           (-4)
#define OSPF_API_MAX_MSG_SIZE (sizeof(struct apimsg) + OSPF_MAX_LSA_SIZE)
#define OSPF_API_NOMEMORY                 (-8)
#define OSPF_API_NOSUCHAREA               (-2)
#define OSPF_API_NOSUCHINTERFACE          (-1)
#define OSPF_API_NOSUCHLSA                (-3)
#define OSPF_API_NOTREADY                 (-7)
#define OSPF_API_OK                         0
#define OSPF_API_OPAQUETYPEINUSE          (-5)
#define OSPF_API_OPAQUETYPENOTREGISTERED  (-6)
#define OSPF_API_SYNC_PORT      2607
#define OSPF_API_UNDEF                   (-10)
#define OSPF_API_VERSION           1

#define DEFAULT_ROUTE_TYPE(T) ((T) == DEFAULT_ROUTE)
#define EXTERNAL_METRIC_TYPE_1      0
#define EXTERNAL_METRIC_TYPE_2      1



#define AREA_NAME(A)    ospf_area_name_string ((A))
#define CONF_DEBUG_OFF(a, b)	 conf_debug_ospf_ ## a &= ~(OSPF_DEBUG_ ## b)
#define CONF_DEBUG_ON(a, b)	 conf_debug_ospf_ ## a |= (OSPF_DEBUG_ ## b)
#define CONF_DEBUG_PACKET_OFF(a, b)	    conf_debug_ospf_packet[a] &= ~(b)
#define CONF_DEBUG_PACKET_ON(a, b)	    conf_debug_ospf_packet[a] |= (b)
#define DEBUG_OFF(a, b) \
     do { \
       CONF_DEBUG_OFF(a, b); \
       TERM_DEBUG_OFF(a, b); \
     } while (0)
#define DEBUG_ON(a, b) \
     do { \
       CONF_DEBUG_ON(a, b); \
       TERM_DEBUG_ON(a, b); \
     } while (0)
#define DEBUG_PACKET_OFF(a, b) \
    do { \
      CONF_DEBUG_PACKET_OFF(a, b); \
      TERM_DEBUG_PACKET_OFF(a, b); \
    } while (0)
#define DEBUG_PACKET_ON(a, b) \
    do { \
      CONF_DEBUG_PACKET_ON(a, b); \
      TERM_DEBUG_PACKET_ON(a, b); \
    } while (0)
#define IF_NAME(I)      ospf_if_name_string ((I))
#define IS_CONF_DEBUG_OSPF(a, b) \
	(conf_debug_ospf_ ## a & OSPF_DEBUG_ ## b)
#define IS_CONF_DEBUG_OSPF_PACKET(a, b) \
	(conf_debug_ospf_packet[a] & OSPF_DEBUG_ ## b)
#define IS_DEBUG_OSPF(a, b) \
	(term_debug_ospf_ ## a & OSPF_DEBUG_ ## b)
#define IS_DEBUG_OSPF_EVENT IS_DEBUG_OSPF(event,EVENT)
#define IS_DEBUG_OSPF_NSSA  IS_DEBUG_OSPF(nssa,NSSA)
#define IS_DEBUG_OSPF_PACKET(a, b) \
	(term_debug_ospf_packet[a] & OSPF_DEBUG_ ## b)
#define OSPF_DEBUG_EVENT        0x01
#define OSPF_DEBUG_LSA_GENERATE 0x01
#define OSPF_DEBUG_LSA_INSTALL  0x04
#define OSPF_DEBUG_LSA_REFRESH  0x08
#define OSPF_DEBUG_NSM_TIMERS   0x04
#define OSPF_DEBUG_SEND_RECV    0x03
#define OSPF_DEBUG_ZEBRA_INTERFACE     0x01
#define OSPF_DEBUG_ZEBRA_REDISTRIBUTE  0x02
#define TERM_DEBUG_OFF(a, b)	 term_debug_ospf_ ## a &= ~(OSPF_DEBUG_ ## b)
#define TERM_DEBUG_ON(a, b)	 term_debug_ospf_ ## a |= (OSPF_DEBUG_ ## b)
#define TERM_DEBUG_PACKET_OFF(a, b)	    term_debug_ospf_packet[a] &= ~(b)
#define TERM_DEBUG_PACKET_ON(a, b)	    term_debug_ospf_packet[a] |= (b)

#define OSPF_VERTEX_NETWORK 2  
#define OSPF_VERTEX_PROCESSED      0x01
#define OSPF_VERTEX_ROUTER  1  

#define IS_SET_DD_ALL(X)        ((X) & OSPF_DD_FLAG_ALL)
#define IS_SET_DD_I(X)          ((X) & OSPF_DD_FLAG_I)
#define IS_SET_DD_M(X)          ((X) & OSPF_DD_FLAG_M)
#define IS_SET_DD_MS(X)         ((X) & OSPF_DD_FLAG_MS)
#define MSG_NG    1
#define MSG_OK    0
#define OSPF_AUTH_MD5_SIZE       16U
#define OSPF_AUTH_SIMPLE_SIZE     8U
#define OSPF_DB_DESC_MIN_SIZE     8U
#define OSPF_HEADER_SIZE         24U
#define OSPF_HELLO_MIN_SIZE      20U   
#define OSPF_HELLO_REPLY_DELAY          1
#define OSPF_LS_ACK_MIN_SIZE      0U
#define OSPF_LS_REQ_MIN_SIZE      0U
#define OSPF_LS_UPD_MIN_SIZE      4U
#define OSPF_MAX_PACKET_SIZE  65535U   
#define OSPF_MSG_DB_DESC       2  
#define OSPF_MSG_HELLO         1  
#define OSPF_MSG_LS_ACK        5  
#define OSPF_MSG_LS_REQ        3  
#define OSPF_MSG_LS_UPD        4  
#define OSPF_OUTPUT_LENGTH(S)   ((S)->endp)
#define OSPF_OUTPUT_PNT(S)      ((S)->data + (S)->putp)
#define OSPF_PACKET_MAX(oi)     ospf_packet_max (oi)
#define OSPF_SEND_PACKET_DIRECT         1
#define OSPF_SEND_PACKET_INDIRECT       2
#define OSPF_SEND_PACKET_LOOP           3


#define NSM_DependUpon          0
#define NSM_InactivityTimer    12
#define NSM_OneWayReceived     10
#define OSPF_NSM_EVENT_EXECUTE(N,E)                                           \
      thread_execute (master, ospf_nsm_event, (N), (E))
#define OSPF_NSM_EVENT_MAX     14
#define OSPF_NSM_EVENT_SCHEDULE(N,E)                                          \
      thread_add_event (master, ospf_nsm_event, (N), (E))
#define OSPF_NSM_STATE_MAX     10
#define OSPF_NSM_TIMER_OFF(X)                                                 \
      do {                                                                    \
        if (X)                                                                \
          {                                                                   \
            thread_cancel (X);                                                \
            (X) = NULL;                                                       \
          }                                                                   \
      } while (0)
#define OSPF_NSM_TIMER_ON(T,F,V)                                              \
      do {                                                                    \
        if (!(T))                                                             \
          (T) = thread_add_timer (master, (F), nbr, (V));                     \
      } while (0)

#define NBR_IS_BDR(n)   IPV4_ADDR_SAME (&n->address.u.prefix4, &n->bd_router)
#define NBR_IS_DR(n)	IPV4_ADDR_SAME (&n->address.u.prefix4, &n->d_router)

#define AREA_LSDB(A,T)       ((A)->lsdb->type[(T)].db)
#define ASBR_SUMMARY_LSDB(A) ((A)->lsdb->type[OSPF_ASBR_SUMMARY_LSA].db)
#define AS_LSDB(O,T)         ((O)->lsdb->type[(T)].db)
#define EXTERNAL_LSDB(O)     ((O)->lsdb->type[OSPF_AS_EXTERNAL_LSA].db)
#define LSDB_LOOP(T,N,L)                                                      \
  if ((T) != NULL)                                                            \
  for ((N) = route_top ((T)); ((N)); ((N)) = route_next ((N)))                \
    if (((L) = (N)->info))
#define MONITOR_LSDB_CHANGE 1 
#define NETWORK_LSDB(A)	     ((A)->lsdb->type[OSPF_NETWORK_LSA].db)
#define NSSA_LSDB(A)         ((A)->lsdb->type[OSPF_AS_NSSA_LSA].db)
#define OPAQUE_AREA_LSDB(A)  ((A)->lsdb->type[OSPF_OPAQUE_AREA_LSA].db)
#define OPAQUE_AS_LSDB(O)    ((O)->lsdb->type[OSPF_OPAQUE_AS_LSA].db)
#define OPAQUE_LINK_LSDB(A)  ((A)->lsdb->type[OSPF_OPAQUE_LINK_LSA].db)
#define ROUTER_LSDB(A)       ((A)->lsdb->type[OSPF_ROUTER_LSA].db)
#define SUMMARY_LSDB(A)      ((A)->lsdb->type[OSPF_SUMMARY_LSA].db)

#define GET_AGE(x)     (ntohs ((x)->data->ls_age) + time (NULL) - (x)->tv_recv)
#define GET_METRIC(x) get_metric(x)
#define IS_EXTERNAL_METRIC(x)   ((x) & 0x80)
#define IS_LSA_MAXAGE(L)        (LS_AGE ((L)) == OSPF_LSA_MAXAGE)
#define IS_LSA_SELF(L)          (CHECK_FLAG ((L)->flags, OSPF_LSA_SELF))
#define IS_ROUTER_LSA_BORDER(x)	       ((x)->flags & ROUTER_LSA_BORDER)
#define IS_ROUTER_LSA_EXTERNAL(x)      ((x)->flags & ROUTER_LSA_EXTERNAL)
#define IS_ROUTER_LSA_NT(x)            ((x)->flags & ROUTER_LSA_NT)
#define IS_ROUTER_LSA_SHORTCUT(x)      ((x)->flags & ROUTER_LSA_SHORTCUT)
#define IS_ROUTER_LSA_VIRTUAL(x)       ((x)->flags & ROUTER_LSA_VIRTUAL)
#define LSA_LINK_TYPE_POINTOPOINT      1
#define LSA_LINK_TYPE_STUB             3
#define LSA_LINK_TYPE_TRANSIT          2
#define LSA_LINK_TYPE_VIRTUALLINK      4
#define LS_AGE(x)      (OSPF_LSA_MAXAGE < get_age(x) ? \
                                           OSPF_LSA_MAXAGE : get_age(x))
#define OSPF_ASBR_SUMMARY_LSA         4
#define OSPF_AS_EXTERNAL_LSA          5
#define OSPF_AS_EXTERNAL_LSA_MIN_SIZE             16U 
#define OSPF_EXTERNAL_ATTRIBUTES_LSA  8  
#define OSPF_LSA_UPDATE_TIMER_ON(T,F) \
      if (!(T)) \
        (T) = thread_add_timer (master, (F), 0, 2)
#define OSPF_MAX_LSA           12
#define OSPF_NETWORK_LSA              2
#define OSPF_NETWORK_LSA_MIN_SIZE                  8U 
#define OSPF_ROUTER_LSA               1
#define OSPF_ROUTER_LSA_LINK_SIZE    12U
#define OSPF_ROUTER_LSA_MIN_SIZE                   4U 
#define OSPF_ROUTER_LSA_TOS_SIZE      4U
#define OSPF_SUMMARY_LSA              3
#define OSPF_SUMMARY_LSA_MIN_SIZE                  8U 

#define IS_OPAQUE_LSA_ORIGINATION_BLOCKED(V) \
        CHECK_FLAG((V), (OPAQUE_BLOCK_TYPE_09_LSA_BIT | \
                         OPAQUE_BLOCK_TYPE_10_LSA_BIT | \
                         OPAQUE_BLOCK_TYPE_11_LSA_BIT))
#define OPAQUE_TYPE_FLOODGATE                           225
#define OPAQUE_TYPE_RANGE_RESERVED(type) \
	(127 <  (type) && (type) <= 255)
#define OPAQUE_TYPE_RANGE_UNASSIGNED(type) \
	(  4 <= (type) && (type) <= 127)
#define VALID_OPAQUE_INFO_LEN(lsahdr) \
	((ntohs((lsahdr)->length) >= sizeof (struct lsa_header)) && \
	((ntohs((lsahdr)->length) %  sizeof (u_int32_t)) == 0))

#define OSPF_ASBR_CHECK_DELAY 30
#define ROUTEMAP_METRIC(E)      (E)->route_map_set.metric
#define ROUTEMAP_METRIC_TYPE(E) (E)->route_map_set.metric_type

#define ISM_Backup                        6
#define ISM_BackupSeen                    3
#define ISM_DR                            7
#define ISM_DROther                       5
#define ISM_DependUpon                    0
#define ISM_Down                          1
#define ISM_InterfaceDown                 7
#define ISM_InterfaceUp                   1
#define ISM_LoopInd                       5
#define ISM_Loopback                      2
#define ISM_NeighborChange                4
#define ISM_NoEvent                       0
#define ISM_PointToPoint                  4
#define ISM_SNMP(x) (((x) == ISM_DROther) ? ISM_DR : \
                     ((x) == ISM_DR) ? ISM_DROther : (x))
#define ISM_UnloopInd                     6
#define ISM_WaitTimer                     2
#define ISM_Waiting                       3
#define OSPF_HELLO_TIMER_ON(O) \
  do { \
    if (OSPF_IF_PARAM ((O), fast_hello)) \
        OSPF_ISM_TIMER_MSEC_ON ((O)->t_hello, ospf_hello_timer, \
                                1000 / OSPF_IF_PARAM ((O), fast_hello)); \
    else \
        OSPF_ISM_TIMER_ON ((O)->t_hello, ospf_hello_timer, \
                                OSPF_IF_PARAM ((O), v_hello)); \
  } while (0)
#define OSPF_ISM_EVENT_EXECUTE(I,E) \
      thread_execute (master, ospf_ism_event, (I), (E))
#define OSPF_ISM_EVENT_MAX                8
#define OSPF_ISM_EVENT_SCHEDULE(I,E) \
      thread_add_event (master, ospf_ism_event, (I), (E))
#define OSPF_ISM_STATE_MAX   	          8
#define OSPF_ISM_TIMER_MSEC_ON(T,F,V) \
  do { \
    if (!(T)) \
      (T) = thread_add_timer_msec (master, (F), oi, (V)); \
  } while (0)
#define OSPF_ISM_TIMER_OFF(X) \
  do { \
    if (X) \
      { \
	thread_cancel (X); \
	(X) = NULL; \
      } \
  } while (0)
#define OSPF_ISM_TIMER_ON(T,F,V) \
  do { \
    if (!(T)) \
      (T) = thread_add_timer (master, (F), oi, (V)); \
  } while (0)
#define OSPF_ISM_WRITE_ON(O)                                                  \
      do                                                                      \
        {                                                                     \
          if (oi->on_write_q == 0)                                            \
	    {                                                                 \
              listnode_add ((O)->oi_write_q, oi);                             \
	      oi->on_write_q = 1;                                             \
	    }                                                                 \
	  if ((O)->t_write == NULL)                                           \
	    (O)->t_write =                                                    \
	      thread_add_write (master, ospf_write, (O), (O)->fd);            \
        } while (0)

#define BDR(I)			((I)->nbr_self->bd_router)
#define DECLARE_IF_PARAM(T, P) T P; u_char P##__config:1
#define DR(I)			((I)->nbr_self->d_router)
#define IF_DEF_PARAMS(I) (IF_OSPF_IF_INFO (I)->def_params)
#define IF_OIFS(I)  (IF_OSPF_IF_INFO (I)->oifs)
#define IF_OIFS_PARAMS(I) (IF_OSPF_IF_INFO (I)->params)
#define IF_OSPF_IF_INFO(I) ((struct ospf_if_info *)((I)->info))
#define OI_MEMBER_CHECK(O,M) \
    (CHECK_FLAG((O)->multicast_memberships, OI_MEMBER_FLAG(M)))
#define OI_MEMBER_COUNT(O,M) (IF_OSPF_IF_INFO(oi->ifp)->membership_counts[(M)])
#define OI_MEMBER_FLAG(M) (1 << (M))
#define OI_MEMBER_JOINED(O,M) \
  do { \
    SET_FLAG ((O)->multicast_memberships, OI_MEMBER_FLAG(M)); \
    IF_OSPF_IF_INFO((O)->ifp)->membership_counts[(M)]++; \
  } while (0)
#define OI_MEMBER_LEFT(O,M) \
  do { \
    UNSET_FLAG ((O)->multicast_memberships, OI_MEMBER_FLAG(M)); \
    IF_OSPF_IF_INFO((O)->ifp)->membership_counts[(M)]--; \
  } while (0)
#define OPTIONS(I)		((I)->nbr_self->options)
#define OSPF_IFTYPE_LOOPBACK            6
#define OSPF_IF_ACTIVE                  0
#define OSPF_IF_PARAM(O, P) \
        (OSPF_IF_PARAM_CONFIGURED ((O)->params, P)?\
                        (O)->params->P:IF_DEF_PARAMS((O)->ifp)->P)
#define OSPF_IF_PARAM_CONFIGURED(S, P) ((S) && (S)->P##__config)
#define OSPF_IF_PASSIVE_STATUS(O) \
       (OSPF_IF_PARAM_CONFIGURED((O)->params, passive_interface) ? \
         (O)->params->passive_interface : \
         (OSPF_IF_PARAM_CONFIGURED(IF_DEF_PARAMS((O)->ifp), passive_interface) ? \
           IF_DEF_PARAMS((O)->ifp)->passive_interface : \
           (O)->ospf->passive_interface_default))
#define OSPF_VL_FLAG_APPROVED 0x01
#define OSPF_VL_MAX_COUNT 256
#define PRIORITY(I)		((I)->nbr_self->priority)
#define SET_IF_PARAM(S, P) ((S)->P##__config) = 1
#define UNSET_IF_PARAM(S, P) ((S)->P##__config) = 0

#define DISTRIBUTE_LIST(O,T)    (O)->dlist[T].list
#define DISTRIBUTE_NAME(O,T)    (O)->dlist[T].name
#define EXPORT_LIST(A)  (A)->_export.list
#define EXPORT_NAME(A)  (A)->_export.name
#define EXTERNAL_INFO(T)      om->external_info[T]
#define IMPORT_LIST(A)  (A)->import.list
#define IMPORT_NAME(A)  (A)->import.name
#define IPPROTO_OSPFIGP         89
#define IS_OSPF_ABR(O)		((O)->flags & OSPF_FLAG_ABR)
#define IS_OSPF_ASBR(O)		((O)->flags & OSPF_FLAG_ASBR)
#define LSA_OPTIONS_GET(area) \
        (((area)->external_routing == OSPF_AREA_DEFAULT) ? OSPF_OPTION_E : 0)
#define LSA_OPTIONS_NSSA_GET(area) \
        (((area)->external_routing == OSPF_AREA_NSSA)  ? OSPF_OPTION_NP : 0)
#define OSPF_ABR_CISCO          3
#define OSPF_ABR_IBM            2
#define OSPF_ABR_SHORTCUT       4
#define OSPF_ABR_STAND          1
#define OSPF_ALLDROUTERS                0xe0000006      
#define OSPF_ALLSPFROUTERS              0xe0000005      
#define OSPF_AREA_BACKBONE              0x00000000      
#define OSPF_AREA_DEFAULT       0
#define OSPF_AREA_ID_FORMAT_ADDRESS         1
#define OSPF_AREA_ID_FORMAT_DECIMAL         2
#define OSPF_AREA_NSSA          2
#define OSPF_AREA_SAME(X,Y) \
        (memcmp ((X->area_id), (Y->area_id), IPV4_MAX_BYTELEN) == 0)
#define OSPF_AREA_STUB          1
#define OSPF_AREA_TIMER_ON(T,F,V)                                             \
    do {                                                                      \
      if (!(T))                                                               \
        (T) = thread_add_timer (master, (F), area, (V));                      \
    } while (0)
#define OSPF_AUTH_CMD_NOTSEEN              -2
#define OSPF_AUTH_CRYPTOGRAPHIC             2
#define OSPF_AUTH_NOTSET                   -1
#define OSPF_AUTH_NULL                      0
#define OSPF_AUTH_SIMPLE                    1
#define OSPF_CHECK_AGE                         300
#define OSPF_DD_FLAG_ALL                 0x07
#define OSPF_DD_FLAG_I                   0x04
#define OSPF_DD_FLAG_M                   0x02
#define OSPF_DD_FLAG_MS                  0x01
#define OSPF_DEFAULT_CONFIG   "ospfd.conf"
#define OSPF_DEFAULT_DESTINATION        0x00000000      
#define OSPF_FAST_HELLO_DEFAULT             0
#define OSPF_FLAG_ABR           0x0001
#define OSPF_FLAG_ASBR          0x0002
#define OSPF_HELLO_INTERVAL_DEFAULT        10
#define OSPF_INITIAL_SEQUENCE_NUMBER    0x80000001
#define OSPF_IP_TTL             1
#define OSPF_IS_AREA_BACKBONE(A) OSPF_IS_AREA_ID_BACKBONE ((A)->area_id)
#define OSPF_IS_AREA_ID_BACKBONE(I) ((I).s_addr == OSPF_AREA_BACKBONE)
#define OSPF_LSA_INITIAL_AGE                     0	
#define OSPF_LSA_MAXAGE                       3600
#define OSPF_LSA_MAXAGE_DIFF                   900
#define OSPF_LSA_REFRESHER_GRANULARITY 10
#define OSPF_LSA_REFRESHER_SLOTS ((OSPF_LS_REFRESH_TIME + \
                                  OSPF_LS_REFRESH_SHIFT)/10 + 1)
#define OSPF_LSA_REFRESH_INTERVAL_DEFAULT 10
#define OSPF_LS_INFINITY                  0xffffff
#define OSPF_LS_REFRESH_JITTER      60
#define OSPF_LS_REFRESH_SHIFT       (60 * 15)
#define OSPF_LS_REFRESH_TIME                    60
#define OSPF_MASTER_SHUTDOWN (1 << 0)   
#define OSPF_MAX_SEQUENCE_NUMBER        0x7fffffff
#define OSPF_MIN_LS_ARRIVAL                      1
#define OSPF_MIN_LS_INTERVAL                     5
#define OSPF_MTU_IGNORE_DEFAULT             0
#define OSPF_NEIGHBOR_PRIORITY_DEFAULT      0
#define OSPF_NSSA_ROLE_ALWAYS    2
#define OSPF_NSSA_ROLE_CANDIDATE 1
#define OSPF_NSSA_ROLE_NEVER     0
#define OSPF_NSSA_TRANSLATE_DISABLED 0
#define OSPF_NSSA_TRANSLATE_ENABLED  1
#define OSPF_OPTION_DC                   0x20
#define OSPF_OPTION_E                    0x02
#define OSPF_OPTION_EA                   0x10
#define OSPF_OPTION_MC                   0x04
#define OSPF_OPTION_NP                   0x08
#define OSPF_OPTION_O                    0x40
#define OSPF_OPTION_T                    0x01  
#define OSPF_OUTPUT_COST_DEFAULT           10
#define OSPF_POLL_INTERVAL_DEFAULT         60
#define OSPF_POLL_TIMER_OFF(X)		OSPF_TIMER_OFF((X))
#define OSPF_POLL_TIMER_ON(T,F,V)                                             \
    do {                                                                      \
      if (!(T))                                                               \
        (T) = thread_add_timer (master, (F), nbr_nbma, (V));                  \
    } while (0)
#define OSPF_RETRANSMIT_INTERVAL_DEFAULT    5
#define OSPF_RFC1583_COMPATIBLE         (1 << 0)
#define OSPF_ROUTER_DEAD_INTERVAL_DEFAULT  40
#define OSPF_ROUTER_DEAD_INTERVAL_MINIMAL   1
#define OSPF_ROUTER_PRIORITY_DEFAULT        1
#define OSPF_SPF_DELAY_DEFAULT              200
#define OSPF_SPF_HOLDTIME_DEFAULT           1000
#define OSPF_STUB_ROUTER_ADMINISTRATIVE_SET     1
#define OSPF_STUB_ROUTER_ADMINISTRATIVE_UNSET   0
#define OSPF_TIMER_OFF(X)                                                     \
    do {                                                                      \
      if (X)                                                                  \
        {                                                                     \
          thread_cancel (X);                                                  \
          (X) = NULL;                                                         \
        }                                                                     \
    } while (0)
#define OSPF_TIMER_ON(T,F,V)                                                  \
    do {                                                                      \
      if (!(T))                                                               \
	(T) = thread_add_timer (master, (F), ospf, (V));                      \
    } while (0)
#define OSPF_TRANSIT_FALSE      0
#define OSPF_TRANSIT_TRUE       1
#define OSPF_TRANSMIT_DELAY_DEFAULT         1
#define OSPF_VERSION            2
#define OSPF_VL_IP_TTL          100
#define OSPF_VTY_PORT          2604
#define PREFIX_LIST_IN(A)   (A)->plist_in.list
#define PREFIX_LIST_OUT(A)  (A)->plist_out.list
#define PREFIX_NAME_IN(A)   (A)->plist_in.name
#define PREFIX_NAME_OUT(A)  (A)->plist_out.name
#  define ROUNDUP(val, gran)	roundup(val, gran)
#define ROUTEMAP(O,T)        (O)->route_map[T].map
#define ROUTEMAP_NAME(O,T)   (O)->route_map[T].name

