



























#define IP4_INSTANCE_FROM_PROTOCOL(Ip4) \
          CR ((Ip4), IP4_PROTOCOL, Ip4Proto, IP4_PROTOCOL_SIGNATURE)
#define IP4_NO_MAPPING(IpInstance) (!(IpInstance)->Interface->Configured)
#define IP4_PROTOCOL_SIGNATURE  SIGNATURE_32 ('I', 'P', '4', 'P')
#define IP4_SERVICE_CONFIGED    2
#define IP4_SERVICE_DESTROY     3
#define IP4_SERVICE_FROM_CONFIG2_INSTANCE(This) \
  CR (This, IP4_SERVICE, Ip4Config2Instance, IP4_SERVICE_SIGNATURE)
#define IP4_SERVICE_FROM_PROTOCOL(Sb)   \
          CR ((Sb), IP4_SERVICE, ServiceBinding, IP4_SERVICE_SIGNATURE)
#define IP4_SERVICE_SIGNATURE   SIGNATURE_32 ('I', 'P', '4', 'S')
#define IP4_SERVICE_STARTED     1
#define IP4_SERVICE_UNSTARTED   0
#define IP4_STATE_CONFIGED      1
#define IP4_STATE_UNCONFIGED    0

#define ADDRESS_STR_MAX_SIZE      255
#define FORMID_DEVICE_FORM  2
#define FORMID_MAIN_FORM    1
#define IP4_STR_MAX_SIZE          16
#define IP_MAX_SIZE               15
#define IP_MIN_SIZE               7
#define KEY_DHCP_ENABLE           0x101
#define KEY_DNS                   0x105
#define KEY_ENABLE                0x100
#define KEY_GATE_WAY              0x104
#define KEY_LOCAL_IP              0x102
#define KEY_SAVE_CHANGES          0x106
#define KEY_SUBNET_MASK           0x103
#define MAX_IP4_CONFIG_DNS        16

#define NIC_ITEM_CONFIG_SIZE   (sizeof (IP4_CONFIG2_INSTANCE) + (sizeof (EFI_IPv4_ADDRESS) * MAX_IP4_CONFIG_DNS))

#define DATA_ATTRIB_SET(Attrib, Bits)       (BOOLEAN)((Attrib) & (Bits))
#define DATA_ATTRIB_SIZE_FIXED              0x1
#define DATA_ATTRIB_VOLATILE                0x2
#define IP4_CONFIG2_INSTANCE_FROM_FORM_CALLBACK(Callback) \
  CR ((Callback), \
      IP4_CONFIG2_INSTANCE, \
      CallbackInfo, \
      IP4_CONFIG2_INSTANCE_SIGNATURE \
      )
#define IP4_CONFIG2_INSTANCE_FROM_PROTOCOL(Proto) \
  CR ((Proto), \
      IP4_CONFIG2_INSTANCE, \
      Ip4Config2, \
      IP4_CONFIG2_INSTANCE_SIGNATURE \
      )
#define IP4_CONFIG2_INSTANCE_SIGNATURE    SIGNATURE_32 ('I', 'P', 'C', '2')
#define IP4_CONFIG2_VARIABLE_ATTRIBUTE    (EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS)
#define IP4_FORM_CALLBACK_INFO_FROM_CONFIG_ACCESS(ConfigAccess) \
  CR ((ConfigAccess), \
      IP4_FORM_CALLBACK_INFO, \
      HiiConfigAccessProtocol, \
      IP4_FORM_CALLBACK_INFO_SIGNATURE \
      )
#define IP4_FORM_CALLBACK_INFO_SIGNATURE  SIGNATURE_32 ('I', 'F', 'C', 'I')
#define IP4_SERVICE_FROM_IP4_CONFIG2_INSTANCE(Instance) \
  CR ((Instance), \
      IP4_SERVICE, \
      Ip4Config2Instance, \
      IP4_SERVICE_SIGNATURE \
      )
#define REMOVE_DATA_ATTRIB(Attrib, Bits)    ((Attrib) &= (~Bits))
#define SET_DATA_ATTRIB(Attrib, Bits)       ((Attrib) |= (Bits))


#define IP4_ASSEMBLE_HASH(Dst, Src, Id, Proto)  \
          (((Dst) + (Src) + ((Id) << 16) + (Proto)) % IP4_ASSEMLE_HASH_SIZE)
#define IP4_ASSEMLE_HASH_SIZE  31
#define IP4_FRAGMENT_LIFE      120
#define IP4_GET_CLIP_INFO(Packet) ((IP4_CLIP_INFO *) ((Packet)->ProtoData))
#define IP4_MAX_HEADLEN        60
#define IP4_MAX_IPSEC_HEADLEN  54
#define IP4_MAX_PACKET_SIZE    65535
#define IP4_MIN_HEADLEN        20
#define IP4_RXDATA_WRAP_SIZE(NumFrag) \
          (sizeof (IP4_RXDATA_WRAP) + sizeof (EFI_IP4_FRAGMENT_DATA) * ((NumFrag) - 1))

#define IP4_DIRECT_ROUTE       0x00000001
#define IP4_ROUTE_CACHE_HASH(Dst, Src)  (((Dst) ^ (Src)) % IP4_ROUTE_CACHE_HASH_VALUE)
#define IP4_ROUTE_CACHE_HASH_VALUE 31
#define IP4_ROUTE_CACHE_MAX        64  

#define IP4_ALLONE_ADDRESS    0xFFFFFFFFu
#define IP4_ALLROUTER_ADDRESS 0xE0000002u
#define IP4_ALLSYSTEM_ADDRESS 0xE0000001u
#define IP4_ALLZERO_ADDRESS   0x00000000u
#define IP4_DO_NOT_FRAGMENT(FragmentField) \
          ((BOOLEAN)(((FragmentField) & IP4_HEAD_DF_MASK) == IP4_HEAD_DF_MASK))
#define IP4_ETHER_PROTO       0x0800
#define IP4_FIRST_FRAGMENT(FragmentField) \
          ((BOOLEAN)(((FragmentField) & IP4_HEAD_OFFSET_MASK) == 0))
#define IP4_HEAD_DF_MASK      0x4000
#define IP4_HEAD_FRAGMENT_FIELD(Df, Mf, Offset) \
    ((UINT16)(((Df) ? IP4_HEAD_DF_MASK : 0) | ((Mf) ? IP4_HEAD_MF_MASK : 0) | (((Offset) >> 3) & IP4_HEAD_OFFSET_MASK)))
#define IP4_HEAD_MF_MASK      0x2000
#define IP4_HEAD_OFFSET_MASK  0x1fff
#define IP4_IS_BROADCAST(CastType) ((CastType) >= IP4_LOCAL_BROADCAST)
#define IP4_LAST_FRAGMENT(FragmentField)  \
          (((FragmentField) & IP4_HEAD_MF_MASK) == 0)
#define IP4_LINK_BROADCAST    0x00000001
#define IP4_LINK_MULTICAST    0x00000002
#define IP4_LINK_PROMISC      0x00000004
#define IP4_LOCAL_BROADCAST   4  
#define IP4_LOCAL_HOST        2
#define IP4_MULTICAST         3
#define IP4_NET_BROADCAST     6
#define IP4_PROMISCUOUS       1
#define IP4_SUBNET_BROADCAST  5
#define IP4_US_TO_SEC(Us) (((Us) + 999999) / 1000000)

#define IGMP_LEAVE_GROUP           0x17
#define IGMP_MEMBERSHIP_QUERY      0x11
#define IGMP_UNSOLICIATED_REPORT   10
#define IGMP_V1ROUTER_PRESENT      400
#define IGMP_V1_MEMBERSHIP_REPORT  0x12
#define IGMP_V2_MEMBERSHIP_REPORT  0x16

#define IP4_OPTION_COPY_MASK  0x80
#define IP4_OPTION_EOP        0
#define IP4_OPTION_LSRR       131  
#define IP4_OPTION_NOP        1
#define IP4_OPTION_RR         7    
#define IP4_OPTION_SSRR       137  

#define ICMP_DEFAULT_CODE          0
#define ICMP_DEST_UNREACHABLE      3
#define ICMP_ECHO_REPLY            0
#define ICMP_ECHO_REQUEST          8
#define ICMP_ERROR_MESSAGE         1
#define ICMP_FRAGMENT_FAILED       4
#define ICMP_HOST_PROHIBITED       10
#define ICMP_HOST_REDIRECT         1
#define ICMP_HOST_TOS_REDIRECT     3
#define ICMP_HOST_UNKNOWN          7
#define ICMP_HOST_UNREACHABLE      1
#define ICMP_HOST_UNREACHABLE_TOS  12
#define ICMP_INFO_REPLY            16
#define ICMP_INFO_REQUEST          15
#define ICMP_INVALID_MESSAGE       0
#define ICMP_NET_PROHIBITED        9
#define ICMP_NET_REDIRECT          0
#define ICMP_NET_TOS_REDIRECT      2
#define ICMP_NET_UNKNOWN           6
#define ICMP_NET_UNREACHABLE       0
#define ICMP_NET_UNREACHABLE_TOS   11
#define ICMP_PARAMETER_PROBLEM     12
#define ICMP_PORT_UNREACHABLE      3  
#define ICMP_PROTO_UNREACHABLE     2  
#define ICMP_QUERY_MESSAGE         2
#define ICMP_REDIRECT              5
#define ICMP_SOURCEROUTE_FAILED    5  
#define ICMP_SOURCE_ISOLATED       8
#define ICMP_SOURCE_QUENCH         4
#define ICMP_TIMEOUT_IN_TRANSIT    0
#define ICMP_TIMEOUT_REASSEMBLE    1  
#define ICMP_TIMESTAMP             13
#define ICMP_TIME_EXCEEDED         11
#define ICMP_TYPE_MAX              ICMP_INFO_REPLY

#define IP4_FRAME_ARP_SIGNATURE SIGNATURE_32 ('I', 'P', 'F', 'A')
#define IP4_FRAME_RX_SIGNATURE  SIGNATURE_32 ('I', 'P', 'F', 'R')
#define IP4_FRAME_TX_SIGNATURE  SIGNATURE_32 ('I', 'P', 'F', 'T')
#define IP4_INTERFACE_SIGNATURE SIGNATURE_32 ('I', 'P', 'I', 'F')


