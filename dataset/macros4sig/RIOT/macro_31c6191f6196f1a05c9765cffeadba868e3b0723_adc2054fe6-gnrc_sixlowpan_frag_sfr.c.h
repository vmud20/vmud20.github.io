


#include<stddef.h>









#include<unistd.h>





#include<stdlib.h>







#include<stdbool.h>

#include<errno.h>






#include<stdalign.h>
#include<assert.h>











#include<inttypes.h>
















#include<sched.h>

#include<string.h>


#include<stdint.h>


#define GNRC_SIXLOWPAN_FRAG_SFR_CONGURE_UNIT    (1U)

#define GNRC_SIXLOWPAN_FRAG_SFR_ARQ_TIMEOUT_MSG     (0x0227)
#define GNRC_SIXLOWPAN_FRAG_SFR_INTER_FRAG_GAP_MSG  (0x0228)


#define SIXLOWPAN_SFR_ACK_BITMAP_SIZE   (32U)       
#define SIXLOWPAN_SFR_ACK_REQ           (0x80U)     
#define SIXLOWPAN_SFR_ECN               (0x01U)     
#define SIXLOWPAN_SFR_FRAG_SIZE_MASK    (0x03ffU)   
#define SIXLOWPAN_SFR_FRAG_SIZE_MAX     (0x03ffU)   
#define SIXLOWPAN_SFR_GEN_DISP          (0xe8)      
#define SIXLOWPAN_SFR_GEN_DISP_MASK     (0xfc)
#define SIXLOWPAN_SFR_SEQ_MASK          (0x7cU)     
#define SIXLOWPAN_SFR_SEQ_MAX           (0x1fU)     
#define SIXLOWPAN_SFR_SEQ_POS           (2U)        

#define SIXLOWPAN_FRAG_1_DISP       (0xc0)      
#define SIXLOWPAN_FRAG_DISP_MASK    (0xf8)      
#define SIXLOWPAN_FRAG_MAX_LEN      (2047)      
#define SIXLOWPAN_FRAG_N_DISP       (0xe0)      
#define SIXLOWPAN_FRAG_SIZE_MASK    (0x07ff)    
#define SIXLOWPAN_IPHC1_DISP        (0x60)
#define SIXLOWPAN_IPHC1_DISP_MASK   (0xe0)
#define SIXLOWPAN_IPHC1_HL          (0x03)
#define SIXLOWPAN_IPHC1_NH          (0x04)
#define SIXLOWPAN_IPHC1_TF          (0x18)
#define SIXLOWPAN_IPHC2_CID_EXT     (0x80)
#define SIXLOWPAN_IPHC2_DAC         (0x04)
#define SIXLOWPAN_IPHC2_DAM         (0x03)
#define SIXLOWPAN_IPHC2_M           (0x08)
#define SIXLOWPAN_IPHC2_SAC         (0x40)
#define SIXLOWPAN_IPHC2_SAM         (0x30)
#define SIXLOWPAN_IPHC_CID_EXT_LEN  (1)
#define SIXLOWPAN_IPHC_HDR_LEN      (2)
#define SIXLOWPAN_SFR_ACK_DISP          (0xea)
#define SIXLOWPAN_SFR_DISP_MASK         (0xfe)
#define SIXLOWPAN_SFR_RFRAG_DISP        (0xe8)
#define SIXLOWPAN_UNCOMP            (0x41)      

#   define _byteorder_swap(V, T) (byteorder_swap ## T((V)))
#   define _byteorder_swap_le(V, T) (V)

#define BITFIELD(NAME, SIZE)  uint8_t NAME[((SIZE) + 7) / 8]


#define XTIMER_BACKOFF 30
#define XTIMER_CHAN (0)
#define XTIMER_DEV TIMER_DEV(0)

#define XTIMER_HZ XTIMER_HZ_BASE
#define XTIMER_HZ_BASE (1000000ul)
#define XTIMER_ISR_BACKOFF 20
#define XTIMER_MASK ((0xffffffff >> XTIMER_WIDTH) << XTIMER_WIDTH)
#define XTIMER_SHIFT (0)
#define XTIMER_WIDTH (24)
#define MSG_XTIMER 12345

#define XTIMER_MIN_SPIN _xtimer_usec_from_ticks(1)
#define MSG_ZTIMER 0xc83e   
#define ZTIMER_CLOCK_NO_REQUIRED_PM_MODE (UINT8_MAX)



#define DIV_H_INV_15625_32    0x431bde83ul
#define DIV_H_INV_15625_64    0x431bde82d7b634dbull
#define DIV_H_INV_15625_SHIFT 12


#define TIMEX_MAX_STR_LEN   (20)
#define CS_PER_SEC          (100LU)
#define HOURS_PER_DAY       (24LU)
#define MIN_PER_DAY         (1440LU)
#define MIN_PER_HOUR        (60LU)
#define MS_PER_CS           (10U)
#define MS_PER_HOUR        (3600000LU)
#define MS_PER_SEC          (1000LU)
#define NS_PER_MS           (1000000LU)
#define NS_PER_SEC          (1000000000LLU)
#define NS_PER_US           (1000LU)
#define SEC_PER_DAY         (86400LU)
#define SEC_PER_HOUR        (3600LU)
#define SEC_PER_MIN         (60LU)

#define US_PER_CS           (10000U)
#define US_PER_HOUR        (3600000000LU)
#define US_PER_MS           (1000LU)
#define US_PER_SEC          (1000000LU)

#define MSG_ZTIMER64 0xc83f   




#define CONGURE_WND_SIZE_MAX    (UINT16_MAX)

#define GNRC_SIXLOWPAN_FRAG_RB_GC_MSG       (0x0226)

#define CONFIG_GNRC_SIXLOWPAN_FRAG_FB_SIZE         (4U)
#define CONFIG_GNRC_SIXLOWPAN_FRAG_RBUF_DEL_TIMER              (0U)

#define CONFIG_GNRC_SIXLOWPAN_FRAG_RBUF_SIZE       (4U)
#define CONFIG_GNRC_SIXLOWPAN_FRAG_RBUF_TIMEOUT_US (3U * US_PER_SEC)
#define CONFIG_GNRC_SIXLOWPAN_FRAG_VRB_SIZE        (16U)
#define CONFIG_GNRC_SIXLOWPAN_FRAG_VRB_TIMEOUT_US  (CONFIG_GNRC_SIXLOWPAN_FRAG_RBUF_TIMEOUT_US)
#define CONFIG_GNRC_SIXLOWPAN_MSG_QUEUE_SIZE_EXP   (3U)
#define CONFIG_GNRC_SIXLOWPAN_ND_AR_LTIME          (15U)
#define CONFIG_GNRC_SIXLOWPAN_SFR_DG_RETRIES            0U
#define CONFIG_GNRC_SIXLOWPAN_SFR_ECN_FQUEUE_DEN        2U
#define CONFIG_GNRC_SIXLOWPAN_SFR_ECN_FQUEUE_NUM        1U
#define CONFIG_GNRC_SIXLOWPAN_SFR_ECN_IF_IN_DEN         2U
#define CONFIG_GNRC_SIXLOWPAN_SFR_ECN_IF_IN_NUM         1U
#define CONFIG_GNRC_SIXLOWPAN_SFR_ECN_IF_OUT_DEN        2U
#define CONFIG_GNRC_SIXLOWPAN_SFR_ECN_IF_OUT_NUM        1U
#define CONFIG_GNRC_SIXLOWPAN_SFR_FRAG_RETRIES          2U
#define CONFIG_GNRC_SIXLOWPAN_SFR_INTER_FRAME_GAP_US    100U
#define CONFIG_GNRC_SIXLOWPAN_SFR_MAX_ARQ_TIMEOUT_MS    700U
#define CONFIG_GNRC_SIXLOWPAN_SFR_MAX_FRAG_SIZE     112U
#define CONFIG_GNRC_SIXLOWPAN_SFR_MAX_WIN_SIZE      16U
#define CONFIG_GNRC_SIXLOWPAN_SFR_MIN_ARQ_TIMEOUT_MS    350U
#define CONFIG_GNRC_SIXLOWPAN_SFR_MIN_FRAG_SIZE     96U
#define CONFIG_GNRC_SIXLOWPAN_SFR_MIN_WIN_SIZE      1U
#define CONFIG_GNRC_SIXLOWPAN_SFR_MOCK_ARQ_TIMER        0U
#define CONFIG_GNRC_SIXLOWPAN_SFR_OPT_ARQ_TIMEOUT_MS \
            CONFIG_GNRC_SIXLOWPAN_SFR_MAX_ARQ_TIMEOUT_MS
#define CONFIG_GNRC_SIXLOWPAN_SFR_OPT_FRAG_SIZE     CONFIG_GNRC_SIXLOWPAN_SFR_MAX_FRAG_SIZE
#define CONFIG_GNRC_SIXLOWPAN_SFR_OPT_WIN_SIZE      16U
#define CONFIG_GNRC_SIXLOWPAN_SFR_USE_ECN           1U
#define GNRC_SIXLOWPAN_MSG_QUEUE_SIZE    (1 << CONFIG_GNRC_SIXLOWPAN_MSG_QUEUE_SIZE_EXP)
#define GNRC_SIXLOWPAN_PRIO                 (THREAD_PRIORITY_MAIN - 4)
#define GNRC_SIXLOWPAN_STACK_SIZE           (THREAD_STACKSIZE_DEFAULT)




#define PROTNUM_3PC                  (34)       
#define PROTNUM_ARGUS                (13)       
#define PROTNUM_ARIS                 (104)      
#define PROTNUM_AX_25                (93)       
#define PROTNUM_A_N                  (107)      
#define PROTNUM_BBN_RCC_MON          (10)       
#define PROTNUM_BNA                  (49)       
#define PROTNUM_BR_SAT_MON           (76)       
#define PROTNUM_CBT                  (7)        
#define PROTNUM_CFTP                 (62)       
#define PROTNUM_CHAOS                (16)       
#define PROTNUM_COMPAQ_PEER          (110)      
#define PROTNUM_CPHB                 (73)       
#define PROTNUM_CPNX                 (72)       
#define PROTNUM_CRTP                 (126)      
#define PROTNUM_CRUDP                (127)      
#define PROTNUM_DCCP                 (33)       
#define PROTNUM_DCN_MEAS             (19)       
#define PROTNUM_DDP                  (37)       
#define PROTNUM_DDX                  (116)      
#define PROTNUM_DGP                  (86)       
#define PROTNUM_DSR                  (48)       
#define PROTNUM_EGP                  (8)        
#define PROTNUM_EIGRP                (88)       
#define PROTNUM_EMCON                (14)       
#define PROTNUM_ENCAP                (98)       
#define PROTNUM_ETHERIP              (97)       
#define PROTNUM_FC                   (133)      
#define PROTNUM_FIRE                 (125)      
#define PROTNUM_GGP                  (3)        
#define PROTNUM_GMTP                 (100)      
#define PROTNUM_GRE                  (47)       
#define PROTNUM_HIP                  (139)      
#define PROTNUM_HMP                  (20)       
#define PROTNUM_IATP                 (117)      
#define PROTNUM_ICMP                 (1)        
#define PROTNUM_ICMPV6               (58)       
#define PROTNUM_IDPR                 (35)       
#define PROTNUM_IDPR_CMTP            (38)       
#define PROTNUM_IDRP                 (45)       
#define PROTNUM_IFMP                 (101)      
#define PROTNUM_IGMP                 (2)        
#define PROTNUM_IGP                  (9)        
#define PROTNUM_IL                   (40)       
#define PROTNUM_IPCOMP               (108)      
#define PROTNUM_IPCV                 (71)       
#define PROTNUM_IPIP                 (94)       
#define PROTNUM_IPLT                 (129)      
#define PROTNUM_IPPC                 (67)       
#define PROTNUM_IPTM                 (84)       
#define PROTNUM_IPV4                 (4)        
#define PROTNUM_IPV6                 (41)       
#define PROTNUM_IPV6_EXT_AH          (51)       
#define PROTNUM_IPV6_EXT_DST         (60)       
#define PROTNUM_IPV6_EXT_ESP         (50)       
#define PROTNUM_IPV6_EXT_FRAG        (44)       
#define PROTNUM_IPV6_EXT_HOPOPT      (0)        
#define PROTNUM_IPV6_EXT_MOB         (135)      
#define PROTNUM_IPV6_EXT_RH          (43)       
#define PROTNUM_IPV6_NONXT           (59)       
#define PROTNUM_IPX_IN_IP            (111)      
#define PROTNUM_IRTP                 (28)       
#define PROTNUM_ISIS_OVER_IPV4       (124)      
#define PROTNUM_ISO_IP               (80)       
#define PROTNUM_ISO_TP4              (29)       
#define PROTNUM_I_NLSP               (52)       
#define PROTNUM_KRYPTOLAN            (65)       
#define PROTNUM_L2TP                 (115)      
#define PROTNUM_LARP                 (91)       
#define PROTNUM_LEAF_1               (25)       
#define PROTNUM_LEAF_2               (26)       
#define PROTNUM_MANET                (138)      
#define PROTNUM_MERIT_INP            (32)       
#define PROTNUM_MFE_NSP              (31)       
#define PROTNUM_MICP                 (95)       
#define PROTNUM_MOBILE               (55)       
#define PROTNUM_MPLS_IN_IP           (137)      
#define PROTNUM_MTP                  (92)       
#define PROTNUM_MUX                  (18)       
#define PROTNUM_NARP                 (54)       
#define PROTNUM_NETBLT               (30)       
#define PROTNUM_NSFNET_IGP           (85)       
#define PROTNUM_NVP_II               (11)       
#define PROTNUM_OSPFIGP              (89)       
#define PROTNUM_PGM                  (113)      
#define PROTNUM_PIM                  (103)      
#define PROTNUM_PIPE                 (131)      
#define PROTNUM_PNNI                 (102)      
#define PROTNUM_PRM                  (21)       
#define PROTNUM_PTP                  (123)      
#define PROTNUM_PUP                  (12)       
#define PROTNUM_PVP                  (75)       
#define PROTNUM_QNX                  (106)      
#define PROTNUM_RDP                  (27)       
#define PROTNUM_RESERVED             (255)      
#define PROTNUM_ROHC                 (142)      
#define PROTNUM_RSVP                 (46)       
#define PROTNUM_RSVP_E2E_IGNORE      (134)      
#define PROTNUM_RVD                  (66)       
#define PROTNUM_SAT_EXPAK            (64)       
#define PROTNUM_SAT_MON              (69)       
#define PROTNUM_SCC_SP               (96)       
#define PROTNUM_SCPS                 (105)      
#define PROTNUM_SCTP                 (132)      
#define PROTNUM_SDRP                 (42)       
#define PROTNUM_SECURE_VMTP          (82)       
#define PROTNUM_SHIM6                (140)      
#define PROTNUM_SKIP                 (57)       
#define PROTNUM_SM                   (122)      
#define PROTNUM_SMP                  (121)      
#define PROTNUM_SNP                  (109)      
#define PROTNUM_SPRITE_RPC           (90)       
#define PROTNUM_SPS                  (130)      
#define PROTNUM_SRP                  (119)      
#define PROTNUM_SSCOPMCE             (128)      
#define PROTNUM_ST                   (5)        
#define PROTNUM_STP                  (118)      
#define PROTNUM_SUN_ND               (77)       
#define PROTNUM_SWIPE                (53)       
#define PROTNUM_TCF                  (87)       
#define PROTNUM_TCP                  (6)        
#define PROTNUM_TLSP                 (56)       
#define PROTNUM_TPPLUSPLUS           (39)       
#define PROTNUM_TRUNK_1              (23)       
#define PROTNUM_TRUNK_2              (24)       
#define PROTNUM_TTP                  (84)       
#define PROTNUM_UDP                  (17)       
#define PROTNUM_UDPLITE              (136)      
#define PROTNUM_UTI                  (120)      
#define PROTNUM_VINES                (83)       
#define PROTNUM_VISA                 (70)       
#define PROTNUM_VMTP                 (81)       
#define PROTNUM_VRRP                 (112)      
#define PROTNUM_WB_EXPAK             (79)       
#define PROTNUM_WB_MON               (78)       
#define PROTNUM_WESP                 (141)      
#define PROTNUM_WSN                  (74)       
#define PROTNUM_XNET                 (15)       
#define PROTNUM_XNS_IDP              (22)       
#define PROTNUM_XTP                  (36)       
#define ETHERTYPE_6LOENC        (0xa0ed)    
#define ETHERTYPE_ARP           (0x0806)    
#define ETHERTYPE_CCNX          (0x0801)    
#define ETHERTYPE_CUSTOM        (0x0101)    
#define ETHERTYPE_IPV4          (0x0800)    
#define ETHERTYPE_IPV6          (0x86dd)    
#define ETHERTYPE_NDN           (0x8624)    
#define ETHERTYPE_RESERVED      (0x0000)    
#define ETHERTYPE_UNKNOWN       (0xffff)    

#define GNRC_NETIF_HDR_FLAGS_BROADCAST  (0x80)
#define GNRC_NETIF_HDR_FLAGS_MORE_DATA  (0x10)
#define GNRC_NETIF_HDR_FLAGS_MULTICAST  (0x40)
#define GNRC_NETIF_HDR_FLAGS_TIMESTAMP  (0x08)
#define GNRC_NETIF_HDR_L2ADDR_MAX_LEN   (8)
#define GNRC_NETIF_HDR_L2ADDR_PRINT_LEN (GNRC_NETIF_HDR_L2ADDR_MAX_LEN * 3)
#define GNRC_NETIF_HDR_NO_LQI           (0)
#define GNRC_NETIF_HDR_NO_RSSI          (INT16_MIN)

#define gnrc_netif_hdr_ipv6_iid_from_dst(netif, hdr, iid)   (-ENOTSUP);
#define gnrc_netif_hdr_ipv6_iid_from_src(netif, hdr, iid)   (-ENOTSUP);
#define GNRC_NETIF_EVQ_INDEX_PRIO_HIGH  (0)
#define GNRC_NETIF_EVQ_INDEX_PRIO_LOW   (GNRC_NETIF_EVQ_INDEX_PRIO_HIGH + 1)
#define GNRC_NETIF_EVQ_NUMOF            (GNRC_NETIF_EVQ_INDEX_PRIO_LOW + 1)

#define CONFIG_NETIF_NAMELENMAX    (8U)

#define NETSTATS_ALL        (0xFF)
#define NETSTATS_IPV6       (0x02)
#define NETSTATS_LAYER2     (0x01)
#define NETSTATS_NB_QUEUE_SIZE  (4)
#define NETSTATS_NB_SIZE        (8)
#define NETSTATS_RPL        (0x03)

#define L2UTIL_ADDR_MAX_LEN (8U)    

#define NDP_DAD_TRANSMIT_NUMOF      (1U)
#define NDP_DELAY_FIRST_PROBE_MS    (5000U)     
#define NDP_HOP_LIMIT               (255U)
#define NDP_MAX_ANYCAST_MS_DELAY    (1000U)     
#define NDP_MAX_FIN_RA_NUMOF            (3U)       
#define NDP_MAX_INIT_RA_INTERVAL        (16000U)   
#define NDP_MAX_INIT_RA_NUMOF           (3U)       
#define NDP_MAX_MC_SOL_NUMOF        (3U)        
#define NDP_MAX_NA_NUMOF            (3U)        
#define NDP_MAX_NS_NUMOF            (17U)
#define NDP_MAX_RANDOM_FACTOR       (1500U)     
#define NDP_MAX_RA_DELAY                (500U)     
#define NDP_MAX_RA_INTERVAL_MS          (600000U)  
#define NDP_MAX_RETRANS_TIMER_MS    (60000U)
#define NDP_MAX_RS_MS_DELAY         (1000U)     
#define NDP_MAX_RS_NUMOF            (3U)        
#define NDP_MAX_UC_SOL_NUMOF        (3U)        
#define NDP_MIN_MS_DELAY_BETWEEN_RAS    (3000U)    
#define NDP_MIN_RANDOM_FACTOR       (500U)      
#define NDP_MIN_RA_INTERVAL_MS          (198000U)  
#define NDP_NBR_ADV_FLAGS_MASK      (0xe0)
#define NDP_NBR_ADV_FLAGS_O         (0x20)  
#define NDP_NBR_ADV_FLAGS_R         (0x80)  
#define NDP_NBR_ADV_FLAGS_S         (0x40)  
#define NDP_NBR_ADV_LTIME_NOT_DR    (0)
#define NDP_NBR_ADV_REACH_TIME      (0)     
#define NDP_NBR_ADV_RETRANS_TIMER   (0)     
#define NDP_OPT_6CTX                (34)    
#define NDP_OPT_ABR                 (35)    
#define NDP_OPT_AR                  (33)    
#define NDP_OPT_MTU                 (5)     
#define NDP_OPT_MTU_LEN             (1U)
#define NDP_OPT_PI                  (3)     
#define NDP_OPT_PI_FLAGS_A          (0x40)  
#define NDP_OPT_PI_FLAGS_L          (0x80)  
#define NDP_OPT_PI_FLAGS_MASK       (0xc0)
#define NDP_OPT_PI_LEN              (4U)
#define NDP_OPT_PI_PREF_LTIME_INF   (UINT32_MAX)    
#define NDP_OPT_PI_VALID_LTIME_INF  (UINT32_MAX)    
#define NDP_OPT_RDNSS               (25)    
#define NDP_OPT_RDNSS_MIN_LEN       (3U)
#define NDP_OPT_RH                  (4)     
#define NDP_OPT_RI                  (24)    
#define NDP_OPT_RI_FLAGS_MASK       (0x18)
#define NDP_OPT_RI_FLAGS_PRF_NEG    (0x18)  
#define NDP_OPT_RI_FLAGS_PRF_NONE   (0x10)  
#define NDP_OPT_RI_FLAGS_PRF_POS    (0x8)   
#define NDP_OPT_RI_FLAGS_PRF_ZERO   (0x0)   
#define NDP_OPT_SL2A                (1)     
#define NDP_OPT_TL2A                (2)     
#define NDP_REACH_MS                (30000U)    
#define NDP_RETRANS_TIMER_MS        (1000U)     
#define NDP_RS_MS_INTERVAL          (4000U)     
#define NDP_RTR_ADV_CUR_HL_UNSPEC   (0) 
#define NDP_RTR_ADV_FLAGS_M         (0x80)  
#define NDP_RTR_ADV_FLAGS_MASK      (0xc0)
#define NDP_RTR_ADV_FLAGS_O         (0x40)  
#define NDP_RTR_ADV_LTIME_SEC_MAX   (9000)
#define NDP_RTR_LTIME_SEC               (1800U)    

#define IPV6_ADDR_ALL_NODES_IF_LOCAL        {{ 0xff, 0x01, 0x00, 0x00, \
                                               0x00, 0x00, 0x00, 0x00, \
                                               0x00, 0x00, 0x00, 0x00, \
                                               0x00, 0x00, 0x00, 0x01 }}
#define IPV6_ADDR_ALL_NODES_LINK_LOCAL      {{ 0xff, 0x02, 0x00, 0x00, \
                                               0x00, 0x00, 0x00, 0x00, \
                                               0x00, 0x00, 0x00, 0x00, \
                                               0x00, 0x00, 0x00, 0x01 }}
#define IPV6_ADDR_ALL_ROUTERS_IF_LOCAL      {{ 0xff, 0x01, 0x00, 0x00, \
                                               0x00, 0x00, 0x00, 0x00, \
                                               0x00, 0x00, 0x00, 0x00, \
                                               0x00, 0x00, 0x00, 0x02 }}
#define IPV6_ADDR_ALL_ROUTERS_LINK_LOCAL    {{ 0xff, 0x02, 0x00, 0x00, \
                                               0x00, 0x00, 0x00, 0x00, \
                                               0x00, 0x00, 0x00, 0x00, \
                                               0x00, 0x00, 0x00, 0x02 }}
#define IPV6_ADDR_ALL_ROUTERS_SITE_LOCAL    {{ 0xff, 0x05, 0x00, 0x00, \
                                               0x00, 0x00, 0x00, 0x00, \
                                               0x00, 0x00, 0x00, 0x00, \
                                               0x00, 0x00, 0x00, 0x02 }}
#define IPV6_ADDR_BIT_LEN           (128)
#define IPV6_ADDR_LINK_LOCAL_PREFIX         {{ 0xfe, 0x80, 0x00, 0x00, \
                                               0x00, 0x00, 0x00, 0x00, \
                                               0x00, 0x00, 0x00, 0x00, \
                                               0x00, 0x00, 0x00, 0x00 }}
#define IPV6_ADDR_LOOPBACK                  {{ 0x00, 0x00, 0x00, 0x00, \
                                               0x00, 0x00, 0x00, 0x00, \
                                               0x00, 0x00, 0x00, 0x00, \
                                               0x00, 0x00, 0x00, 0x01 }}
#define IPV6_ADDR_MAX_STR_LEN       (sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"))
#define IPV6_ADDR_MCAST_FLAG_EMBED_ON_RP    (0x04)
#define IPV6_ADDR_MCAST_FLAG_PREFIX_BASED   (0x02)
#define IPV6_ADDR_MCAST_FLAG_TRANSIENT      (0x01)
#define IPV6_ADDR_MCAST_SCP_ADMIN_LOCAL (0x4)      
#define IPV6_ADDR_MCAST_SCP_GLOBAL      (0xe)      
#define IPV6_ADDR_MCAST_SCP_IF_LOCAL        (0x1)   
#define IPV6_ADDR_MCAST_SCP_LINK_LOCAL      (0x2)   
#define IPV6_ADDR_MCAST_SCP_ORG_LOCAL   (0x8)      
#define IPV6_ADDR_MCAST_SCP_REALM_LOCAL (0x3)
#define IPV6_ADDR_MCAST_SCP_SITE_LOCAL  (0x5)      
#define IPV6_ADDR_SITE_LOCAL_PREFIX (0xfec0)
#define IPV6_ADDR_SOLICITED_NODE_PREFIX     {{ 0xff, 0x02, 0x00, 0x00, \
                                               0x00, 0x00, 0x00, 0x00, \
                                               0x00, 0x00, 0x00, 0x01, \
                                               0xff, 0x00, 0x00, 0x00 }}
#define IPV6_ADDR_UNSPECIFIED               {{ 0x00, 0x00, 0x00, 0x00, \
                                               0x00, 0x00, 0x00, 0x00, \
                                               0x00, 0x00, 0x00, 0x00, \
                                               0x00, 0x00, 0x00, 0x00 }}

#define IPV4_ADDR_MAX_STR_LEN       (sizeof("255.255.255.255"))

#define EUI64_GROUP_FLAG        0x01
#define EUI64_LOCAL_FLAG        0x02

#define IPV6_MIN_MTU    (1280)



#define IPV6_EXT_LEN_UNIT   (8U)    

#define IPV6_EXT_RH_TYPE_0          (0U)
#define IPV6_EXT_RH_TYPE_2          (2U)
#define IPV6_EXT_RH_TYPE_NIMROD     (1U)
#define IPV6_EXT_RH_TYPE_RPL_SRH    (3U)

#define IPV6_EXT_FRAG_M             (0x0001)    
#define IPV6_EXT_FRAG_OFFSET_MASK   (0xFFF8)    




#define CDL_COUNT(head,el,counter)                                                             \
    CDL_COUNT2(head,el,counter,next)                                                           \

#define CDL_COUNT2(head, el, counter,next)                                                     \
{                                                                                              \
    counter = 0;                                                                               \
    CDL_FOREACH2(head,el,next){ ++counter; }                                                   \
}
#define CDL_DELETE(head,del)                                                                   \
    CDL_DELETE2(head,del,prev,next)
#define CDL_DELETE2(head,del,prev,next)                                                        \
do {                                                                                           \
  if ( ((head)==(del)) && ((head)->next == (head))) {                                          \
      (head) = 0L;                                                                             \
  } else {                                                                                     \
     (del)->next->prev = (del)->prev;                                                          \
     (del)->prev->next = (del)->next;                                                          \
     if ((del) == (head)) (head)=(del)->next;                                                  \
  }                                                                                            \
} while (0)
#define CDL_FOREACH(head,el)                                                                   \
    CDL_FOREACH2(head,el,next)
#define CDL_FOREACH2(head,el,next)                                                             \
    for(el=head;el;el=((el)->next==head ? 0L : (el)->next))
#define CDL_FOREACH_SAFE(head,el,tmp1,tmp2)                                                    \
    CDL_FOREACH_SAFE2(head,el,tmp1,tmp2,prev,next)
#define CDL_FOREACH_SAFE2(head,el,tmp1,tmp2,prev,next)                                         \
  for((el)=(head), ((tmp1)=(head)?((head)->prev):NULL);                                        \
      (el) && ((tmp2)=(el)->next, 1);                                                          \
      ((el) = (((el)==(tmp1)) ? 0L : (tmp2))))
#define CDL_PREPEND(head,add)                                                                  \
    CDL_PREPEND2(head,add,prev,next)
#define CDL_PREPEND2(head,add,prev,next)                                                       \
do {                                                                                           \
 if (head) {                                                                                   \
   (add)->prev = (head)->prev;                                                                 \
   (add)->next = (head);                                                                       \
   (head)->prev = (add);                                                                       \
   (add)->prev->next = (add);                                                                  \
 } else {                                                                                      \
   (add)->prev = (add);                                                                        \
   (add)->next = (add);                                                                        \
 }                                                                                             \
(head)=(add);                                                                                  \
} while (0)
#define CDL_PREPEND_ELEM(head, el, add)                                                        \
do {                                                                                           \
 assert(head != NULL);                                                                         \
 assert(el != NULL);                                                                           \
 assert(add != NULL);                                                                          \
 (add)->next = (el);                                                                           \
 (add)->prev = (el)->prev;                                                                     \
 (el)->prev = (add);                                                                           \
 (add)->prev->next = (add);                                                                    \
 if ((head) == (el)) {                                                                         \
  (head) = (add);                                                                              \
 }                                                                                             \
} while (0)
#define CDL_REPLACE_ELEM(head, el, add)                                                        \
do {                                                                                           \
 assert(head != NULL);                                                                         \
 assert(el != NULL);                                                                           \
 assert(add != NULL);                                                                          \
 if ((el)->next == (el)) {                                                                     \
  (add)->next = (add);                                                                         \
  (add)->prev = (add);                                                                         \
  (head) = (add);                                                                              \
 } else {                                                                                      \
  (add)->next = (el)->next;                                                                    \
  (add)->prev = (el)->prev;                                                                    \
  (add)->next->prev = (add);                                                                   \
  (add)->prev->next = (add);                                                                   \
  if ((head) == (el)) {                                                                        \
   (head) = (add);                                                                             \
  }                                                                                            \
 }                                                                                             \
} while (0)
#define CDL_SEARCH(head,out,elt,cmp)                                                           \
    CDL_SEARCH2(head,out,elt,cmp,next)
#define CDL_SEARCH2(head,out,elt,cmp,next)                                                     \
do {                                                                                           \
    CDL_FOREACH2(head,out,next) {                                                              \
      if ((cmp(out,elt))==0) break;                                                            \
    }                                                                                          \
} while(0)
#define CDL_SEARCH_SCALAR(head,out,field,val)                                                  \
    CDL_SEARCH_SCALAR2(head,out,field,val,next)
#define CDL_SEARCH_SCALAR2(head,out,field,val,next)                                            \
do {                                                                                           \
    CDL_FOREACH2(head,out,next) {                                                              \
      if ((out)->field == (val)) break;                                                        \
    }                                                                                          \
} while(0)
#define CDL_SORT(list, cmp)                                                                    \
    CDL_SORT2(list, cmp, prev, next)
#define CDL_SORT2(list, cmp, prev, next)                                                       \
do {                                                                                           \
  LDECLTYPE(list) _ls_p;                                                                       \
  LDECLTYPE(list) _ls_q;                                                                       \
  LDECLTYPE(list) _ls_e;                                                                       \
  LDECLTYPE(list) _ls_tail;                                                                    \
  LDECLTYPE(list) _ls_oldhead;                                                                 \
  LDECLTYPE(list) _tmp;                                                                        \
  int _ls_insize, _ls_nmerges, _ls_psize, _ls_qsize, _ls_i, _ls_looping;                       \
  if (list) {                                                                                  \
    _ls_insize = 1;                                                                            \
    _ls_looping = 1;                                                                           \
    while (_ls_looping) {                                                                      \
      _CASTASGN(_ls_p,list);                                                                   \
      _CASTASGN(_ls_oldhead,list);                                                             \
      list = NULL;                                                                             \
      _ls_tail = NULL;                                                                         \
      _ls_nmerges = 0;                                                                         \
      while (_ls_p) {                                                                          \
        _ls_nmerges++;                                                                         \
        _ls_q = _ls_p;                                                                         \
        _ls_psize = 0;                                                                         \
        for (_ls_i = 0; _ls_i < _ls_insize; _ls_i++) {                                         \
          _ls_psize++;                                                                         \
          _SV(_ls_q,list);                                                                     \
          if (_NEXT(_ls_q,list,next) == _ls_oldhead) {                                         \
            _ls_q = NULL;                                                                      \
          } else {                                                                             \
            _ls_q = _NEXT(_ls_q,list,next);                                                    \
          }                                                                                    \
          _RS(list);                                                                           \
          if (!_ls_q) break;                                                                   \
        }                                                                                      \
        _ls_qsize = _ls_insize;                                                                \
        while (_ls_psize > 0 || (_ls_qsize > 0 && _ls_q)) {                                    \
          if (_ls_psize == 0) {                                                                \
            _ls_e = _ls_q; _SV(_ls_q,list); _ls_q =                                            \
              _NEXT(_ls_q,list,next); _RS(list); _ls_qsize--;                                  \
            if (_ls_q == _ls_oldhead) { _ls_q = NULL; }                                        \
          } else if (_ls_qsize == 0 || !_ls_q) {                                               \
            _ls_e = _ls_p; _SV(_ls_p,list); _ls_p =                                            \
              _NEXT(_ls_p,list,next); _RS(list); _ls_psize--;                                  \
            if (_ls_p == _ls_oldhead) { _ls_p = NULL; }                                        \
          } else if (cmp(_ls_p,_ls_q) <= 0) {                                                  \
            _ls_e = _ls_p; _SV(_ls_p,list); _ls_p =                                            \
              _NEXT(_ls_p,list,next); _RS(list); _ls_psize--;                                  \
            if (_ls_p == _ls_oldhead) { _ls_p = NULL; }                                        \
          } else {                                                                             \
            _ls_e = _ls_q; _SV(_ls_q,list); _ls_q =                                            \
              _NEXT(_ls_q,list,next); _RS(list); _ls_qsize--;                                  \
            if (_ls_q == _ls_oldhead) { _ls_q = NULL; }                                        \
          }                                                                                    \
          if (_ls_tail) {                                                                      \
            _SV(_ls_tail,list); _NEXTASGN(_ls_tail,list,_ls_e,next); _RS(list);                \
          } else {                                                                             \
            _CASTASGN(list,_ls_e);                                                             \
          }                                                                                    \
          _SV(_ls_e,list); _PREVASGN(_ls_e,list,_ls_tail,prev); _RS(list);                     \
          _ls_tail = _ls_e;                                                                    \
        }                                                                                      \
        _ls_p = _ls_q;                                                                         \
      }                                                                                        \
      _CASTASGN(list->prev,_ls_tail);                                                          \
      _CASTASGN(_tmp,list);                                                                    \
      _SV(_ls_tail,list); _NEXTASGN(_ls_tail,list,_tmp,next); _RS(list);                       \
      if (_ls_nmerges <= 1) {                                                                  \
        _ls_looping=0;                                                                         \
      }                                                                                        \
      _ls_insize *= 2;                                                                         \
    }                                                                                          \
  }                                                                                            \
} while (0)
#define DL_APPEND(head,add)                                                                    \
    DL_APPEND2(head,add,prev,next)
#define DL_APPEND2(head,add,prev,next)                                                         \
do {                                                                                           \
  if (head) {                                                                                  \
      (add)->prev = (head)->prev;                                                              \
      (head)->prev->next = (add);                                                              \
      (head)->prev = (add);                                                                    \
      (add)->next = NULL;                                                                      \
  } else {                                                                                     \
      (head)=(add);                                                                            \
      (head)->prev = (head);                                                                   \
      (head)->next = NULL;                                                                     \
  }                                                                                            \
} while (0)
#define DL_CONCAT(head1,head2)                                                                 \
    DL_CONCAT2(head1,head2,prev,next)
#define DL_CONCAT2(head1,head2,prev,next)                                                      \
do {                                                                                           \
  LDECLTYPE(head1) _tmp;                                                                       \
  if (head2) {                                                                                 \
    if (head1) {                                                                               \
        _tmp = (head2)->prev;                                                                  \
        (head2)->prev = (head1)->prev;                                                         \
        (head1)->prev->next = (head2);                                                         \
        (head1)->prev = _tmp;                                                                  \
    } else {                                                                                   \
        (head1)=(head2);                                                                       \
    }                                                                                          \
  }                                                                                            \
} while (0)
#define DL_COUNT(head,el,counter)                                                              \
    DL_COUNT2(head,el,counter,next)                                                            \

#define DL_COUNT2(head,el,counter,next)                                                        \
{                                                                                              \
    counter = 0;                                                                               \
    DL_FOREACH2(head,el,next){ ++counter; }                                                    \
}
#define DL_DELETE(head,del)                                                                    \
    DL_DELETE2(head,del,prev,next)
#define DL_DELETE2(head,del,prev,next)                                                         \
do {                                                                                           \
  assert((del)->prev != NULL);                                                                 \
  if ((del)->prev == (del)) {                                                                  \
      (head)=NULL;                                                                             \
  } else if ((del)==(head)) {                                                                  \
      (del)->next->prev = (del)->prev;                                                         \
      (head) = (del)->next;                                                                    \
  } else {                                                                                     \
      (del)->prev->next = (del)->next;                                                         \
      if ((del)->next) {                                                                       \
          (del)->next->prev = (del)->prev;                                                     \
      } else {                                                                                 \
          (head)->prev = (del)->prev;                                                          \
      }                                                                                        \
  }                                                                                            \
} while (0)
#define DL_FOREACH(head,el)                                                                    \
    DL_FOREACH2(head,el,next)
#define DL_FOREACH2(head,el,next)                                                              \
    for(el=head;el;el=(el)->next)
#define DL_FOREACH_SAFE(head,el,tmp)                                                           \
    DL_FOREACH_SAFE2(head,el,tmp,next)
#define DL_FOREACH_SAFE2(head,el,tmp,next)                                                     \
  for((el)=(head);(el) && (tmp = (el)->next, 1); (el) = tmp)
#define DL_PREPEND(head,add)                                                                   \
    DL_PREPEND2(head,add,prev,next)
#define DL_PREPEND2(head,add,prev,next)                                                        \
do {                                                                                           \
 (add)->next = head;                                                                           \
 if (head) {                                                                                   \
   (add)->prev = (head)->prev;                                                                 \
   (head)->prev = (add);                                                                       \
 } else {                                                                                      \
   (add)->prev = (add);                                                                        \
 }                                                                                             \
 (head) = (add);                                                                               \
} while (0)
#define DL_PREPEND_ELEM(head, el, add)                                                         \
do {                                                                                           \
 assert(head != NULL);                                                                         \
 assert(el != NULL);                                                                           \
 assert(add != NULL);                                                                          \
 (add)->next = (el);                                                                           \
 (add)->prev = (el)->prev;                                                                     \
 (el)->prev = (add);                                                                           \
 if ((head) == (el)) {                                                                         \
  (head) = (add);                                                                              \
 } else {                                                                                      \
  (add)->prev->next = (add);                                                                   \
 }                                                                                             \
} while (0)
#define DL_REPLACE_ELEM(head, el, add)                                                         \
do {                                                                                           \
 assert(head != NULL);                                                                         \
 assert(el != NULL);                                                                           \
 assert(add != NULL);                                                                          \
 if ((head) == (el)) {                                                                         \
  (head) = (add);                                                                              \
  (add)->next = (el)->next;                                                                    \
  if ((el)->next == NULL) {                                                                    \
   (add)->prev = (add);                                                                        \
  } else {                                                                                     \
   (add)->prev = (el)->prev;                                                                   \
   (add)->next->prev = (add);                                                                  \
  }                                                                                            \
 } else {                                                                                      \
  (add)->next = (el)->next;                                                                    \
  (add)->prev = (el)->prev;                                                                    \
  (add)->prev->next = (add);                                                                   \
  if ((el)->next == NULL) {                                                                    \
   (head)->prev = (add);                                                                       \
  } else {                                                                                     \
   (add)->next->prev = (add);                                                                  \
  }                                                                                            \
 }                                                                                             \
} while (0)
#define DL_SEARCH LL_SEARCH
#define DL_SEARCH2 LL_SEARCH2
#define DL_SEARCH_SCALAR LL_SEARCH_SCALAR
#define DL_SEARCH_SCALAR2 LL_SEARCH_SCALAR2
#define DL_SORT(list, cmp)                                                                     \
    DL_SORT2(list, cmp, prev, next)
#define DL_SORT2(list, cmp, prev, next)                                                        \
do {                                                                                           \
  LDECLTYPE(list) _ls_p;                                                                       \
  LDECLTYPE(list) _ls_q;                                                                       \
  LDECLTYPE(list) _ls_e;                                                                       \
  LDECLTYPE(list) _ls_tail;                                                                    \
  int _ls_insize, _ls_nmerges, _ls_psize, _ls_qsize, _ls_i, _ls_looping;                       \
  if (list) {                                                                                  \
    _ls_insize = 1;                                                                            \
    _ls_looping = 1;                                                                           \
    while (_ls_looping) {                                                                      \
      _CASTASGN(_ls_p,list);                                                                   \
      list = NULL;                                                                             \
      _ls_tail = NULL;                                                                         \
      _ls_nmerges = 0;                                                                         \
      while (_ls_p) {                                                                          \
        _ls_nmerges++;                                                                         \
        _ls_q = _ls_p;                                                                         \
        _ls_psize = 0;                                                                         \
        for (_ls_i = 0; _ls_i < _ls_insize; _ls_i++) {                                         \
          _ls_psize++;                                                                         \
          _SV(_ls_q,list); _ls_q = _NEXT(_ls_q,list,next); _RS(list);                          \
          if (!_ls_q) break;                                                                   \
        }                                                                                      \
        _ls_qsize = _ls_insize;                                                                \
        while (_ls_psize > 0 || (_ls_qsize > 0 && _ls_q)) {                                    \
          if (_ls_psize == 0) {                                                                \
            _ls_e = _ls_q; _SV(_ls_q,list); _ls_q =                                            \
              _NEXT(_ls_q,list,next); _RS(list); _ls_qsize--;                                  \
          } else if (_ls_qsize == 0 || !_ls_q) {                                               \
            _ls_e = _ls_p; _SV(_ls_p,list); _ls_p =                                            \
              _NEXT(_ls_p,list,next); _RS(list); _ls_psize--;                                  \
          } else if (cmp(_ls_p,_ls_q) <= 0) {                                                  \
            _ls_e = _ls_p; _SV(_ls_p,list); _ls_p =                                            \
              _NEXT(_ls_p,list,next); _RS(list); _ls_psize--;                                  \
          } else {                                                                             \
            _ls_e = _ls_q; _SV(_ls_q,list); _ls_q =                                            \
              _NEXT(_ls_q,list,next); _RS(list); _ls_qsize--;                                  \
          }                                                                                    \
          if (_ls_tail) {                                                                      \
            _SV(_ls_tail,list); _NEXTASGN(_ls_tail,list,_ls_e,next); _RS(list);                \
          } else {                                                                             \
            _CASTASGN(list,_ls_e);                                                             \
          }                                                                                    \
          _SV(_ls_e,list); _PREVASGN(_ls_e,list,_ls_tail,prev); _RS(list);                     \
          _ls_tail = _ls_e;                                                                    \
        }                                                                                      \
        _ls_p = _ls_q;                                                                         \
      }                                                                                        \
      _CASTASGN(list->prev, _ls_tail);                                                         \
      _SV(_ls_tail,list); _NEXTASGN(_ls_tail,list,NULL,next); _RS(list);                       \
      if (_ls_nmerges <= 1) {                                                                  \
        _ls_looping=0;                                                                         \
      }                                                                                        \
      _ls_insize *= 2;                                                                         \
    }                                                                                          \
  }                                                                                            \
} while (0)
#define LDECLTYPE(x) decltype(x)
#define LL_APPEND LL_APPEND_VS2008
#define LL_APPEND2 LL_APPEND2_VS2008
#define LL_APPEND2_VS2008(head,add,next)                                                       \
do {                                                                                           \
  if (head) {                                                                                  \
    (add)->next = head;                                  \
    while ((add)->next->next) { (add)->next = (add)->next->next; }                             \
    (add)->next->next=(add);                                                                   \
  } else {                                                                                     \
    (head)=(add);                                                                              \
  }                                                                                            \
  (add)->next=NULL;                                                                            \
} while (0)
#define LL_APPEND_VS2008(head,add)                                                             \
    LL_APPEND2_VS2008(head,add,next)
#define LL_CONCAT(head1,head2)                                                                 \
    LL_CONCAT2(head1,head2,next)
#define LL_CONCAT2(head1,head2,next)                                                           \
do {                                                                                           \
  LDECLTYPE(head1) _tmp;                                                                       \
  if (head1) {                                                                                 \
    _tmp = head1;                                                                              \
    while (_tmp->next) { _tmp = _tmp->next; }                                                  \
    _tmp->next=(head2);                                                                        \
  } else {                                                                                     \
    (head1)=(head2);                                                                           \
  }                                                                                            \
} while (0)
#define LL_COUNT(head,el,counter)                                                              \
    LL_COUNT2(head,el,counter,next)                                                            \

#define LL_COUNT2(head,el,counter,next)                                                        \
{                                                                                              \
    counter = 0;                                                                               \
    LL_FOREACH2(head,el,next){ ++counter; }                                                    \
}
#define LL_DELETE LL_DELETE_VS2008
#define LL_DELETE2 LL_DELETE2_VS2008
#define LL_DELETE2_VS2008(head,del,next)                                                       \
do {                                                                                           \
  if ((head) == (del)) {                                                                       \
    (head)=(head)->next;                                                                       \
  } else {                                                                                     \
    char *_tmp = (char*)(head);                                                                \
    while ((head)->next && ((head)->next != (del))) {                                          \
      head = (head)->next;                                                                     \
    }                                                                                          \
    if ((head)->next) {                                                                        \
      (head)->next = ((del)->next);                                                            \
    }                                                                                          \
    {                                                                                          \
      char **_head_alias = (char**)&(head);                                                    \
      *_head_alias = _tmp;                                                                     \
    }                                                                                          \
  }                                                                                            \
} while (0)
#define LL_DELETE_VS2008(head,del)                                                             \
    LL_DELETE2_VS2008(head,del,next)
#define LL_FOREACH(head,el)                                                                    \
    LL_FOREACH2(head,el,next)
#define LL_FOREACH2(head,el,next)                                                              \
    for(el=head;el;el=(el)->next)
#define LL_FOREACH_SAFE(head,el,tmp)                                                           \
    LL_FOREACH_SAFE2(head,el,tmp,next)
#define LL_FOREACH_SAFE2(head,el,tmp,next)                                                     \
  for((el)=(head);(el) && (tmp = (el)->next, 1); (el) = tmp)
#define LL_PREPEND(head,add)                                                                   \
    LL_PREPEND2(head,add,next)
#define LL_PREPEND2(head,add,next)                                                             \
do {                                                                                           \
  (add)->next = head;                                                                          \
  head = add;                                                                                  \
} while (0)
#define LL_PREPEND_ELEM(head, el, add)                                                         \
do {                                                                                           \
 LDECLTYPE(head) _tmp;                                                                         \
 assert(head != NULL);                                                                         \
 assert(el != NULL);                                                                           \
 assert(add != NULL);                                                                          \
 (add)->next = (el);                                                                           \
 if ((head) == (el)) {                                                                         \
  (head) = (add);                                                                              \
 } else {                                                                                      \
  _tmp = head;                                                                                 \
  while (_tmp->next && (_tmp->next != (el))) {                                                 \
   _tmp = _tmp->next;                                                                          \
  }                                                                                            \
  if (_tmp->next) {                                                                            \
    _tmp->next = (add);                                                                        \
  }                                                                                            \
 }                                                                                             \
} while (0)
#define LL_REPLACE_ELEM(head, el, add)                                                         \
do {                                                                                           \
 LDECLTYPE(head) _tmp;                                                                         \
 assert(head != NULL);                                                                         \
 assert(el != NULL);                                                                           \
 assert(add != NULL);                                                                          \
 (add)->next = (el)->next;                                                                     \
 if ((head) == (el)) {                                                                         \
  (head) = (add);                                                                              \
 } else {                                                                                      \
  _tmp = head;                                                                                 \
  while (_tmp->next && (_tmp->next != (el))) {                                                 \
   _tmp = _tmp->next;                                                                          \
  }                                                                                            \
  if (_tmp->next) {                                                                            \
    _tmp->next = (add);                                                                        \
  }                                                                                            \
 }                                                                                             \
} while (0)
#define LL_SEARCH(head,out,elt,cmp)                                                            \
    LL_SEARCH2(head,out,elt,cmp,next)
#define LL_SEARCH2(head,out,elt,cmp,next)                                                      \
do {                                                                                           \
    LL_FOREACH2(head,out,next) {                                                               \
      if ((cmp(out,elt))==0) break;                                                            \
    }                                                                                          \
} while(0)
#define LL_SEARCH_SCALAR(head,out,field,val)                                                   \
    LL_SEARCH_SCALAR2(head,out,field,val,next)
#define LL_SEARCH_SCALAR2(head,out,field,val,next)                                             \
do {                                                                                           \
    LL_FOREACH2(head,out,next) {                                                               \
      if ((out)->field == (val)) break;                                                        \
    }                                                                                          \
} while(0)
#define LL_SORT(list, cmp)                                                                     \
    LL_SORT2(list, cmp, next)
#define LL_SORT2(list, cmp, next)                                                              \
do {                                                                                           \
  LDECLTYPE(list) _ls_p;                                                                       \
  LDECLTYPE(list) _ls_q;                                                                       \
  LDECLTYPE(list) _ls_e;                                                                       \
  LDECLTYPE(list) _ls_tail;                                                                    \
  int _ls_insize, _ls_nmerges, _ls_psize, _ls_qsize, _ls_i, _ls_looping;                       \
  if (list) {                                                                                  \
    _ls_insize = 1;                                                                            \
    _ls_looping = 1;                                                                           \
    while (_ls_looping) {                                                                      \
      _CASTASGN(_ls_p,list);                                                                   \
      list = NULL;                                                                             \
      _ls_tail = NULL;                                                                         \
      _ls_nmerges = 0;                                                                         \
      while (_ls_p) {                                                                          \
        _ls_nmerges++;                                                                         \
        _ls_q = _ls_p;                                                                         \
        _ls_psize = 0;                                                                         \
        for (_ls_i = 0; _ls_i < _ls_insize; _ls_i++) {                                         \
          _ls_psize++;                                                                         \
          _SV(_ls_q,list); _ls_q = _NEXT(_ls_q,list,next); _RS(list);                          \
          if (!_ls_q) break;                                                                   \
        }                                                                                      \
        _ls_qsize = _ls_insize;                                                                \
        while (_ls_psize > 0 || (_ls_qsize > 0 && _ls_q)) {                                    \
          if (_ls_psize == 0) {                                                                \
            _ls_e = _ls_q; _SV(_ls_q,list); _ls_q =                                            \
              _NEXT(_ls_q,list,next); _RS(list); _ls_qsize--;                                  \
          } else if (_ls_qsize == 0 || !_ls_q) {                                               \
            _ls_e = _ls_p; _SV(_ls_p,list); _ls_p =                                            \
              _NEXT(_ls_p,list,next); _RS(list); _ls_psize--;                                  \
          } else if (cmp(_ls_p,_ls_q) <= 0) {                                                  \
            _ls_e = _ls_p; _SV(_ls_p,list); _ls_p =                                            \
              _NEXT(_ls_p,list,next); _RS(list); _ls_psize--;                                  \
          } else {                                                                             \
            _ls_e = _ls_q; _SV(_ls_q,list); _ls_q =                                            \
              _NEXT(_ls_q,list,next); _RS(list); _ls_qsize--;                                  \
          }                                                                                    \
          if (_ls_tail) {                                                                      \
            _SV(_ls_tail,list); _NEXTASGN(_ls_tail,list,_ls_e,next); _RS(list);                \
          } else {                                                                             \
            _CASTASGN(list,_ls_e);                                                             \
          }                                                                                    \
          _ls_tail = _ls_e;                                                                    \
        }                                                                                      \
        _ls_p = _ls_q;                                                                         \
      }                                                                                        \
      if (_ls_tail) {                                                                          \
        _SV(_ls_tail,list); _NEXTASGN(_ls_tail,list,NULL,next); _RS(list);                     \
      }                                                                                        \
      if (_ls_nmerges <= 1) {                                                                  \
        _ls_looping=0;                                                                         \
      }                                                                                        \
      _ls_insize *= 2;                                                                         \
    }                                                                                          \
  }                                                                                            \
} while (0)

#define UTLIST_VERSION 1.9.9
#define _CASTASGN(a,b) { char **_alias = (char**)&(a); *_alias=(char*)(b); }
#define _NEXT(elt,list,next) ((char*)((list)->next))
#define _NEXTASGN(elt,list,to,next) { char **_alias = (char**)&((list)->next); *_alias=(char*)(to); }
#define _PREVASGN(elt,list,to,prev) { char **_alias = (char**)&((list)->prev); *_alias=(char*)(to); }
#define _RS(list) { char **_alias = (char**)&(list); *_alias=_tmp; }
#define _SV(elt,list) _tmp = (char*)(list); {char **_alias = (char**)&(list); *_alias = (elt); }
#define GNRC_NETIF_MAC_INFO_CSMA_ENABLED       (0x0100U)
#define GNRC_NETIF_MAC_INFO_RX_STARTED         (0x0004U)
#define GNRC_NETIF_MAC_INFO_TX_FEEDBACK_MASK   (0x0003U)

#define CONFIG_CSMA_SENDER_BACKOFF_PERIOD_UNIT     (320U)
#define CONFIG_CSMA_SENDER_MAX_BACKOFFS_DEFAULT    (4U)
#define CONFIG_CSMA_SENDER_MAX_BE_DEFAULT          (5U)
#define CONFIG_CSMA_SENDER_MIN_BE_DEFAULT          (3U)

#define GNRC_MAC_PHASE_MAX             (-1)
#define GNRC_MAC_PHASE_UNINITIALIZED   (0)
#define GNRC_MAC_RX_INIT { \
        PRIORITY_PKTQUEUE_INIT, \
        { PRIORITY_PKTQUEUE_NODE_INIT(0, NULL) }, \
}
#define GNRC_MAC_TX_FEEDBACK_INIT { TX_FEEDBACK_UNDEF }
#define GNRC_MAC_TX_INIT { \
        { GNRC_MAC_TX_NEIGHBOR_INIT }, \
        NULL, \
        { PRIORITY_PKTQUEUE_NODE_INIT(0, NULL) }, \
        NULL, \
}
#define GNRC_MAC_TX_NEIGHBOR_INIT { \
        { 0 }, \
        0, \
        GNRC_MAC_PHASE_UNINITIALIZED, \
        PRIORITY_PKTQUEUE_INIT, \
}
#define GNRC_MAC_TYPE_GET_DUTYCYCLE      (0x4401)

#define GNRC_GOMACH_DUPCHK_BUFFER_SIZE             (8U)
#define GNRC_GOMACH_EVENT_RTT_NEW_CYCLE     (0x4301)
#define GNRC_GOMACH_EVENT_RTT_TYPE          (0x4300)
#define GNRC_GOMACH_EVENT_TIMEOUT_TYPE      (0x4400)
#define GNRC_GOMACH_PHASE_MAX               (-1)
#define GNRC_GOMACH_PHASE_UNINITIALIZED     (0)
#define GNRC_GOMACH_SLOSCH_UNIT_COUNT           (11U)
#define GNRC_GOMACH_TIMEOUT_COUNT             (6U)
#define GNRC_GOMACH_TIMEOUT_INIT  { {}, {}, false, GNRC_GOMACH_TIMEOUT_DISABLED }
#define GNRC_GOMACH_TYPE_KNOWN             (1U)
#define GNRC_GOMACH_TYPE_UNKNOWN           (0U)

#define GNRC_GOMACH_FRAME_ANNOUNCE           (0x06U)
#define GNRC_GOMACH_FRAME_BEACON             (0x01U)
#define GNRC_GOMACH_FRAME_BROADCAST          (0x05U)
#define GNRC_GOMACH_FRAME_DATA               (0x02U)
#define GNRC_GOMACH_FRAME_PREAMBLE           (0x03U)
#define GNRC_GOMACH_FRAME_PREAMBLE_ACK       (0x04U)
#define GNRC_GOMACH_L2_ADDR_INIT      { { 0 }, 0 }

#define CONFIG_IEEE802154_AUTO_ACK_DISABLE 0
#define CONFIG_IEEE802154_CCA_THRESH_DEFAULT       (-70)
#define CONFIG_IEEE802154_DEFAULT_ACK_REQ          1
#define CONFIG_IEEE802154_DEFAULT_CHANNEL          (26U)
#define CONFIG_IEEE802154_DEFAULT_CSMA_CA_MAX_BE   (5U)
#define CONFIG_IEEE802154_DEFAULT_CSMA_CA_MIN_BE   (3U)
#define CONFIG_IEEE802154_DEFAULT_CSMA_CA_RETRIES  (4U)
#define CONFIG_IEEE802154_DEFAULT_MAX_FRAME_RETRANS     (4U)
#define CONFIG_IEEE802154_DEFAULT_PANID            (0x0023U)
#define CONFIG_IEEE802154_DEFAULT_PHY_MODE          IEEE802154_PHY_BPSK
#define CONFIG_IEEE802154_DEFAULT_SUBGHZ_CHANNEL   (5U)
#define CONFIG_IEEE802154_DEFAULT_SUBGHZ_PAGE      (2U)
#define CONFIG_IEEE802154_DEFAULT_TXPOWER          (0)
#define IEEE802154G_ATURNAROUNDTIME_US          (1 * US_PER_MS)
#define IEEE802154G_FRAME_LEN_MAX      (2047U)  
#define IEEE802154_ACK_FRAME_LEN          (5U)  
#define IEEE802154_ACK_TIMEOUT_SYMS     (54)
#define IEEE802154_ADDR_BCAST               { 0xff, 0xff }
#define IEEE802154_ADDR_BCAST_LEN           (IEEE802154_SHORT_ADDRESS_LEN)
#define IEEE802154_ATURNAROUNDTIME_IN_SYMBOLS   (12)
#define IEEE802154_CCA_DURATION_IN_SYMBOLS      (8)
#define IEEE802154_CHANNEL_MAX          (26U)   
#define IEEE802154_CHANNEL_MAX_SUBGHZ   (10U)   
#define IEEE802154_CHANNEL_MIN          (11U)   
#define IEEE802154_CHANNEL_MIN_SUBGHZ   (0U)    
#define IEEE802154_FCF_ACK_REQ              (0x20)  
#define IEEE802154_FCF_DST_ADDR_LONG        (0x0c)  
#define IEEE802154_FCF_DST_ADDR_MASK        (0x0c)
#define IEEE802154_FCF_DST_ADDR_RESV        (0x04)  
#define IEEE802154_FCF_DST_ADDR_SHORT       (0x08)  
#define IEEE802154_FCF_DST_ADDR_VOID        (0x00)  
#define IEEE802154_FCF_FRAME_PEND           (0x10)  
#define IEEE802154_FCF_LEN                  (2U)
#define IEEE802154_FCF_PAN_COMP             (0x40)  
#define IEEE802154_FCF_SECURITY_EN          (0x08)  
#define IEEE802154_FCF_SRC_ADDR_LONG        (0xc0)  
#define IEEE802154_FCF_SRC_ADDR_MASK        (0xc0)
#define IEEE802154_FCF_SRC_ADDR_RESV        (0x40)  
#define IEEE802154_FCF_SRC_ADDR_SHORT       (0x80)  
#define IEEE802154_FCF_SRC_ADDR_VOID        (0x00)  
#define IEEE802154_FCF_TYPE_ACK             (0x02)
#define IEEE802154_FCF_TYPE_BEACON          (0x00)
#define IEEE802154_FCF_TYPE_DATA            (0x01)
#define IEEE802154_FCF_TYPE_MACCMD          (0x03)
#define IEEE802154_FCF_TYPE_MASK            (0x07)
#define IEEE802154_FCF_VERS_MASK            (0x30)
#define IEEE802154_FCF_VERS_V0              (0x00)
#define IEEE802154_FCF_VERS_V1              (0x10)
#define IEEE802154_FCS_LEN                  (2U)
#define IEEE802154_FRAME_LEN_MAX        (127U)  
#define IEEE802154_LIFS_SYMS            (40U)
#define IEEE802154_LONG_ADDRESS_LEN         (8U)    
#define IEEE802154_MAX_HDR_LEN              (23U)
#define IEEE802154_MIN_FRAME_LEN            (IEEE802154_FCF_LEN + sizeof(uint8_t))
#define IEEE802154_PANID_BCAST              { 0xff, 0xff }
#define IEEE802154_PHY_MR_FSK_2FSK_CODED_SFD_0      (0x6F4E)
#define IEEE802154_PHY_MR_FSK_2FSK_CODED_SFD_1      (0x632D)
#define IEEE802154_PHY_MR_FSK_2FSK_SFD_LEN (2)  
#define IEEE802154_PHY_MR_FSK_2FSK_UNCODED_SFD_0    (0x90E4)
#define IEEE802154_PHY_MR_FSK_2FSK_UNCODED_SFD_1    (0x7A0E)
#define IEEE802154_PHY_MR_FSK_PHR_LEN      (2)  
#define IEEE802154_RADIO_RSSI_OFFSET        (-174)
#define IEEE802154_SFD                      (0xa7)
#define IEEE802154_SHORT_ADDRESS_LEN        (2U)    
#define IEEE802154_SIFS_MAX_FRAME_SIZE  (18U)
#define IEEE802154_SIFS_SYMS            (12U)

#define CONFIG_GNRC_LWMAC_TIMEOUT_COUNT             (3U)
#define GNRC_LWMAC_DUTYCYCLE_ACTIVE          (0x01)
#define GNRC_LWMAC_EVENT_RTT_PAUSE           (0x4303)
#define GNRC_LWMAC_EVENT_RTT_RESUME          (0x4304)
#define GNRC_LWMAC_EVENT_RTT_SLEEP_PENDING   (0x4306)
#define GNRC_LWMAC_EVENT_RTT_START           (0x4301)
#define GNRC_LWMAC_EVENT_RTT_STOP            (0x4302)
#define GNRC_LWMAC_EVENT_RTT_TYPE            (0x4300)
#define GNRC_LWMAC_EVENT_RTT_WAKEUP_PENDING  (0x4305)
#define GNRC_LWMAC_EVENT_TIMEOUT_TYPE        (0x4400)
#define GNRC_LWMAC_NEEDS_RESCHEDULE          (0x02)
#define GNRC_LWMAC_PHASE_MAX             (-1)
#define GNRC_LWMAC_PHASE_UNINITIALIZED   (0)
#define GNRC_LWMAC_RADIO_IS_ON               (0x04)
#define GNRC_LWMAC_RX_STATE_INITIAL GNRC_LWMAC_RX_STATE_STOPPED
#define GNRC_LWMAC_TX_STATE_INITIAL GNRC_LWMAC_TX_STATE_STOPPED

#define GNRC_LWMAC_FRAMETYPE_BROADCAST      (0x05U)
#define GNRC_LWMAC_FRAMETYPE_DATA           (0x03U)
#define GNRC_LWMAC_FRAMETYPE_DATA_PENDING   (0x04U)
#define GNRC_LWMAC_FRAMETYPE_WA             (0x02U)
#define GNRC_LWMAC_FRAMETYPE_WR             (0x01U)
#define GNRC_LWMAC_L2_ADDR_INITIAL      { { 0 }, 0 }


#define CONFIG_GNRC_MAC_DISPATCH_BUFFER_SIZE_EXP   (3U)
#define CONFIG_GNRC_MAC_NEIGHBOR_COUNT      (8U)
#define CONFIG_GNRC_MAC_RX_QUEUE_SIZE_EXP   (3U)
#define CONFIG_GNRC_MAC_TX_QUEUE_SIZE_EXP   (3U)
#define GNRC_MAC_DISPATCH_BUFFER_SIZE  (1 << CONFIG_GNRC_MAC_DISPATCH_BUFFER_SIZE_EXP)
#define GNRC_MAC_ENABLE_DUTYCYCLE_RECORD    (0)
#define GNRC_MAC_RX_QUEUE_SIZE       (1 << CONFIG_GNRC_MAC_RX_QUEUE_SIZE_EXP)
#define GNRC_MAC_TX_QUEUE_SIZE          (1 << CONFIG_GNRC_MAC_TX_QUEUE_SIZE_EXP)


#define PRIORITY_PKTQUEUE_INIT { NULL }
#define PRIORITY_PKTQUEUE_NODE_INIT(priority, pkt) { NULL, priority, pkt }
#define GNRC_NETIF_IPV6_ADDRS_FLAGS_ANYCAST                (0x20U)
#define GNRC_NETIF_IPV6_ADDRS_FLAGS_STATE_DEPRECATED       (0x08U)
#define GNRC_NETIF_IPV6_ADDRS_FLAGS_STATE_MASK             (0x1fU)
#define GNRC_NETIF_IPV6_ADDRS_FLAGS_STATE_TENTATIVE        (0x07U)
#define GNRC_NETIF_IPV6_ADDRS_FLAGS_STATE_VALID            (0x10U)

#define CONFIG_GNRC_NETIF_DEFAULT_HL      (64U)   
#define CONFIG_GNRC_NETIF_IPV6_ADDRS_NUMOF    (2 + \
                                               DHCPV6_CLIENT_ADDRS_NUMOF)
#define CONFIG_GNRC_NETIF_IPV6_BR_AUTO_6CTX   1
#define CONFIG_GNRC_NETIF_MIN_WAIT_AFTER_SEND_US   (0U)
#define CONFIG_GNRC_NETIF_MSG_QUEUE_SIZE_EXP  (4U)
#define CONFIG_GNRC_NETIF_NONSTANDARD_6LO_MTU 0
#define CONFIG_GNRC_NETIF_PKTQ_POOL_SIZE      (16U)
#define CONFIG_GNRC_NETIF_PKTQ_TIMER_US       (5000U)
#define GNRC_NETIF_IPV6_GROUPS_NUMOF   (CONFIG_GNRC_NETIF_IPV6_ADDRS_NUMOF + \
                                        GNRC_NETIF_RPL_ADDR + \
                                        GNRC_NETIF_IPV6_RTR_ADDR + 1)
#define GNRC_NETIF_IPV6_RTR_ADDR   (1)
#define GNRC_NETIF_L2ADDR_MAXLEN   (IEEE802154_LONG_ADDRESS_LEN)
#define GNRC_NETIF_MSG_QUEUE_SIZE   (1 << CONFIG_GNRC_NETIF_MSG_QUEUE_SIZE_EXP)
#define GNRC_NETIF_PRIO            (THREAD_PRIORITY_MAIN - 5)
#define GNRC_NETIF_RPL_ADDR        (1)

#define CONFIG_GNRC_IPV6_NIB_6LBR                     1
#define CONFIG_GNRC_IPV6_NIB_6LN                      1
#define CONFIG_GNRC_IPV6_NIB_6LR                      1
#define CONFIG_GNRC_IPV6_NIB_ABR_NUMOF               (1)
#define CONFIG_GNRC_IPV6_NIB_ADD_RIO_IN_LAST_RA       1
#define CONFIG_GNRC_IPV6_NIB_ADD_RIO_IN_RA            0
#define CONFIG_GNRC_IPV6_NIB_ADV_ROUTER               1
# define CONFIG_GNRC_IPV6_NIB_ARSM                    0
#define CONFIG_GNRC_IPV6_NIB_DC                       1
#define CONFIG_GNRC_IPV6_NIB_DEFAULT_ROUTER_NUMOF    (1)
#define CONFIG_GNRC_IPV6_NIB_DNS                      0
#define CONFIG_GNRC_IPV6_NIB_L2ADDR_MAX_LEN          (8U)
#define CONFIG_GNRC_IPV6_NIB_MULTIHOP_DAD             0
#define CONFIG_GNRC_IPV6_NIB_MULTIHOP_P6C             1
#define CONFIG_GNRC_IPV6_NIB_NO_RTR_SOL               0
# define CONFIG_GNRC_IPV6_NIB_NUMOF                  (1)
#define CONFIG_GNRC_IPV6_NIB_OFFL_NUMOF              (8)
#define CONFIG_GNRC_IPV6_NIB_QUEUE_PKT                0
#define CONFIG_GNRC_IPV6_NIB_REACH_TIME_RESET        (7200000U)
#define CONFIG_GNRC_IPV6_NIB_REDIRECT                 0
#define CONFIG_GNRC_IPV6_NIB_ROUTER                   1
#define CONFIG_GNRC_IPV6_NIB_SLAAC                    1

#define ETHERNET_ADDR_LEN       (6)     
#define ETH_ALEN ETHERNET_ADDR_LEN      

#define CONFIG_DHCPV6_CLIENT_ADDR_LEASE_MAX (1U)
#define CONFIG_DHCPV6_CLIENT_MUD_URL "https://example.org"
#define CONFIG_DHCPV6_CLIENT_PFX_LEASE_MAX (1U)
#define DHCPV6_CLIENT_ADDRS_NUMOF ((int)(CONFIG_DHCPV6_CLIENT_ADDR_LEASE_MAX))
#define DHCPV6_CLIENT_BUFLEN        (256)   
#define DHCPV6_CLIENT_DUID_LEN      (sizeof(dhcpv6_duid_l2_t) + 8U)
#define DHCPV6_CLIENT_PRIORITY      (THREAD_PRIORITY_MAIN - 2)  
#define DHCPV6_CLIENT_SEND_BUFLEN        (DHCPV6_CLIENT_BUFLEN + 256)
#define DHCPV6_CLIENT_STACK_SIZE    (THREAD_STACKSIZE_DEFAULT)  
#define MAX_MUD_URL_LENGTH (0xFF - sizeof(dhcpv6_opt_mud_url_t))


#define EVENT_QUEUE_INIT    { .waiter = thread_get_active() }
#define EVENT_QUEUE_INIT_DETACHED   { .waiter = NULL }
#define THREAD_FLAG_EVENT   (0x1)
#define PTRTAG  __attribute__((aligned(4)))

#define GNRC_NETAPI_MSG_TYPE_ACK        (0x0205)
#define GNRC_NETAPI_MSG_TYPE_GET        (0x0204)
#define GNRC_NETAPI_MSG_TYPE_RCV        (0x0201)
#define GNRC_NETAPI_MSG_TYPE_SET        (0x0203)
#define GNRC_NETAPI_MSG_TYPE_SND        (0x0202)

#define GNRC_NETIF_FLAGS_6LN                       (0x00001000U)
#define GNRC_NETIF_FLAGS_6LO                       (0x00002000U)
#define GNRC_NETIF_FLAGS_6LO_ABR                   (0x00000200U)
#define GNRC_NETIF_FLAGS_6LO_BACKBONE              (0x00000800U)
#define GNRC_NETIF_FLAGS_6LO_HC                    (0x00000100U)
#define GNRC_NETIF_FLAGS_6LO_MESH                  (0x00000400U)
#define GNRC_NETIF_FLAGS_HAS_L2ADDR                (0x00000001U)
#define GNRC_NETIF_FLAGS_IPV6_ADV_CUR_HL           (0x00000010U)
#define GNRC_NETIF_FLAGS_IPV6_ADV_MTU              (0x00000008U)
#define GNRC_NETIF_FLAGS_IPV6_ADV_O_FLAG           (0x00000080U)
#define GNRC_NETIF_FLAGS_IPV6_ADV_REACH_TIME       (0x00000020U)
#define GNRC_NETIF_FLAGS_IPV6_ADV_RETRANS_TIMER    (0x00000040U)
#define GNRC_NETIF_FLAGS_IPV6_FORWARDING           (0x00000002U)
#define GNRC_NETIF_FLAGS_IPV6_RTR_ADV              (0x00000004U)
#define GNRC_NETIF_FLAGS_RAWMODE                   (0x00010000U)
#define GNRC_NETIF_FLAGS_TX_FROM_PKTQUEUE          (0x00000100U)


#define GNRC_NETIF_6LO_LOCAL_FLAGS_SFR  (0x01)


#define GNRC_NETIF_LORAWAN_FLAGS_LINK_CHECK                (0x1U)

#define CONFIG_GNRC_LORAWAN_MIN_SYMBOLS_TIMEOUT 30
#define GNRC_LORAWAN_REQ_STATUS_DEFERRED (1)    
#define GNRC_LORAWAN_REQ_STATUS_SUCCESS (0)     

#define CONFIG_GNRC_PKTBUF_SIZE    (6144)

#define GNRC_NETERR_MSG_TYPE        (0x0206)
#define GNRC_NETERR_SUCCESS         (0)

#define gnrc_neterr_reg(pkt)  (0)
#define GNRC_NETIF_PKTQ_DEQUEUE_MSG     (0x1233)

#define gnrc_netif_ipv6_get_iid(netif, iid)                         (-ENOTSUP)
#define gnrc_netif_ipv6_group_to_l2_group(netif, ipv6_group, l2_group)  (-ENOTSUP)
#define gnrc_netif_ipv6_iid_from_addr(netif, addr, addr_len, iid)   (-ENOTSUP)
#define gnrc_netif_ipv6_iid_to_addr(netif, iid, addr)               (-ENOTSUP)
#define gnrc_netif_ipv6_init_mtu(netif)                             (void)netif
#define gnrc_netif_ndp_addr_len_from_l2ao(netif, opt)               (-ENOTSUP)
#define ARCHITECTURE_BREAKPOINT(value)  do {} while (1)

#define ARCHITECTURE_WORD_BITS      <NUM>
#define ARCHITECTURE_WORD_BYTES     <NUM>
#define HAS_ALIGNMENT_OF(addr, alignment) (((uintptr_t)(addr) & ((alignment) - 1)) == 0)
#define IS_WORD_ALIGNED(addr) HAS_ALIGNMENT_OF(addr, ARCHITECTURE_WORD_BYTES)
#define PRIxTXTPTR PRIxPTR
#define SWORD_MAX                   ((1LL << (ARCHITECTURE_WORD_BITS - 1)) - 1)
#define SWORD_MIN                   (-(1LL << (ARCHITECTURE_WORD_BITS - 1)))
#define UWORD_MAX                   ((1ULL << ARCHITECTURE_WORD_BITS) - 1)
#define UWORD_MIN                   0
#define WORD_ALIGNED __attribute__((aligned(ARCHITECTURE_WORD_BYTES)))


#define GNRC_SIXLOWPAN_FRAG_FB_SND_MSG      (0x0225)






