








#define BOOTP_BROADCAST 				(0x8000)

#define DHCPS_MAX_CLIENT_NUM 	(DHCP_POOL_END-DHCP_POOL_START+1)
#define DHCP_CLIENT_PORT  				(68)
#define DHCP_MESSAGE_HLEN  				(6)
#define DHCP_MESSAGE_HTYPE 				(1)
#define DHCP_MESSAGE_OP_REPLY          			(2)
#define DHCP_MESSAGE_OP_REQUEST        			(1)
#define DHCP_MESSAGE_TYPE_ACK       			(5)
#define DHCP_MESSAGE_TYPE_DECLINE   			(4)
#define DHCP_MESSAGE_TYPE_DISCOVER  			(1)
#define DHCP_MESSAGE_TYPE_NAK       			(6)
#define DHCP_MESSAGE_TYPE_OFFER     			(2)
#define DHCP_MESSAGE_TYPE_RELEASE   			(7)
#define DHCP_MESSAGE_TYPE_REQUEST   			(3)
#define DHCP_OPTION_CODE_BROADCAST_ADDRESS 		(28)
#define DHCP_OPTION_CODE_DNS_SERVER    			(6)
#define DHCP_OPTION_CODE_END         			(255)
#define DHCP_OPTION_CODE_INTERFACE_MTU 			(26)
#define DHCP_OPTION_CODE_LEASE_TIME   			(51)
#define DHCP_OPTION_CODE_MSG_TYPE     			(53)
#define DHCP_OPTION_CODE_PERFORM_ROUTER_DISCOVERY 	(31)
#define DHCP_OPTION_CODE_REQUEST_IP_ADDRESS   		(50)
#define DHCP_OPTION_CODE_REQ_LIST     			(55)
#define DHCP_OPTION_CODE_ROUTER        			(3)
#define DHCP_OPTION_CODE_SERVER_ID    			(54)
#define DHCP_OPTION_CODE_SUBNET_MASK   			(1)
#define DHCP_SERVER_PORT  				(67)
#define DHCP_SERVER_STATE_ACK 				(3)
#define DHCP_SERVER_STATE_DECLINE 			(2)
#define DHCP_SERVER_STATE_IDLE 				(5)
#define DHCP_SERVER_STATE_NAK 				(4)
#define DHCP_SERVER_STATE_OFFER 			(1)
#define DNS_SERVER_PORT 				(53)
#define MARK_RANGE1_IP_BIT(table, ip)	((table.ip_range[0]) | (1 << ((ip) - 1)))	 
#define MARK_RANGE2_IP_BIT(table, ip)	((table.ip_range[1]) | (1 << ((ip) - 1)))
#define MARK_RANGE3_IP_BIT(table, ip)	((table.ip_range[2]) | (1 << ((ip) - 1)))
#define MARK_RANGE4_IP_BIT(table, ip)	((table.ip_range[3]) | (1 << ((ip) - 1)))
#define MARK_RANGE5_IP_BIT(table, ip)	((table.ip_range[4]) | (1 << ((ip) - 1)))	 
#define MARK_RANGE6_IP_BIT(table, ip)	((table.ip_range[5]) | (1 << ((ip) - 1)))
#define MARK_RANGE7_IP_BIT(table, ip)	((table.ip_range[6]) | (1 << ((ip) - 1)))
#define MARK_RANGE8_IP_BIT(table, ip)	((table.ip_range[7]) | (1 << ((ip) - 1)))

#define debug_dhcps 0
