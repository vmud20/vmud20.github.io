
#include<stdbool.h>
#include<fcntl.h>



#include<sys/time.h>



#include<unistd.h>
#include<termios.h>
#include<netinet/in.h>
#include<syslog.h>



#include<dirent.h>
#include<sys/wait.h>

#include<sys/uio.h>
#include<sys/param.h>
#include<sys/ioctl.h>
#include<sys/stat.h>
#include<sys/file.h>
#include<stdlib.h>


#include<netinet/ip_icmp.h>


#include<netinet/tcp.h>

#include<string.h>

#include<netinet/if_ether.h>

#include<inttypes.h>



#include<net/if.h>
#include<time.h>
#include<netdb.h>

#include<netinet/ip.h>
#include<netinet/ip6.h>



#include<ctype.h>
#include<sys/un.h>
#include<arpa/inet.h>
#include<sys/types.h>
#include<net/ethernet.h>

#include<sys/socket.h>
#include<signal.h>
#include<stdarg.h>


#include<net/if_arp.h>
#include<stdio.h>
#include<netinet/icmp6.h>
#include<netinet/in_systm.h>
#include<errno.h>




#include<sys/resource.h>


#define sockerrno WSAGetLastError()
#define sockinprogress(x) ((x) == WSAEINPROGRESS || (x) == WSAEWOULDBLOCK)
#define sockinuse(x) ((x) == WSAEADDRINUSE)
#define sockmsgsize(x) ((x) == WSAEMSGSIZE)
#define sockstrerror(x) winerror(x)
#define sockwouldblock(x) ((x) == WSAEWOULDBLOCK || (x) == WSAEINTR)
#define strerror(x) ((x)>0?strerror(x):winerror(GetLastError()))
#define SPTPS_ACK 3           
#define SPTPS_ALERT 129       
#define SPTPS_CLOSE 130       
#define SPTPS_HANDSHAKE 128   
#define SPTPS_KEX 0           
#define SPTPS_SECONDARY_KEX 1 
#define SPTPS_SIG 2           
#define SPTPS_VERSION 0


#define false 0
# define strsignal(p) ""
#define true 1

#define timeradd(a, b, r) do {\
	(r)->tv_sec = (a)->tv_sec + (b)->tv_sec;\
	(r)->tv_usec = (a)->tv_usec + (b)->tv_usec;\
	if((r)->tv_usec >= 1000000)\
		(r)->tv_sec++, (r)->tv_usec -= 1000000;\
} while (0)
#define timersub(a, b, r) do {\
	(r)->tv_sec = (a)->tv_sec - (b)->tv_sec;\
	(r)->tv_usec = (a)->tv_usec - (b)->tv_usec;\
	if((r)->tv_usec < 0)\
		(r)->tv_sec--, (r)->tv_usec += 1000000;\
} while (0)
#define SLASH "\\"

#define WINVER Windows2000

#define MAX_STRING "%2048s"
#define MAX_STRING_SIZE 2049
#define PROT_MAJOR 17
#define PROT_MINOR 2 

#define MAXNETSTR 64


#define IO_READ 1
#define IO_WRITE 2


#define splay_each(type, item, tree) (type *item = (type *)1; item; item = NULL) for(splay_node_t *node = (tree)->head, *next; item = node ? node->data : NULL, next = node ? node->next : NULL, node; node = next)
#define OPTION_CLAMP_MSS        0x0008
#define OPTION_INDIRECT         0x0001
#define OPTION_PMTU_DISCOVERY   0x0004
#define OPTION_TCPONLY          0x0002
#define OPTION_VERSION(x) ((x) >> 24) 

#define AF_UNKNOWN 255
#define MAXBUFSIZE ((MAXSIZE > 2048 ? MAXSIZE : 2048) + 128)
#define MAXSIZE (MTU + 4 + CIPHER_MAX_BLOCK_SIZE + DIGEST_MAX_SIZE + MTU/64 + 20)
#define MAXSOCKETS 8    
#define MTU 9018        
#define PKT_COMPRESSED 1
#define PKT_MAC 2
#define PKT_PROBE 4
#define SALEN(s) SA_LEN(&s)

#define closesocket(s) close(s)

#define list_each(type, item, list) (type *item = (type *)1; item; item = NULL) for(list_node_t *node = (list)->head, *next; item = node ? node->data : NULL, next = node ? node->next : NULL, node; node = next)

#define AF_INET6 10
#define ICMP6_DST_UNREACH 1
#define ICMP6_DST_UNREACH_ADDR 3
#define ICMP6_DST_UNREACH_ADMIN 1
#define ICMP6_DST_UNREACH_NOROUTE 0
#define ICMP6_PACKET_TOO_BIG 2
#define ICMP6_TIME_EXCEEDED 3
#define ICMP6_TIME_EXCEED_TRANSIT 0
#define IN6_IS_ADDR_V4MAPPED(a) \
	((((__const uint32_t *) (a))[0] == 0) \
	&& (((__const uint32_t *) (a))[1] == 0) \
	&& (((__const uint32_t *) (a))[2] == htonl (0xffff)))
#define IPPROTO_ICMPV6 58
#define ND_NEIGHBOR_ADVERT 136
#define ND_NEIGHBOR_SOLICIT 135
#define ND_OPT_SOURCE_LINKADDR 1
#define ND_OPT_TARGET_LINKADDR 2

#define icmp6_data16 icmp6_dataun.icmp6_un_data16
#define icmp6_data32 icmp6_dataun.icmp6_un_data32
#define icmp6_data8 icmp6_dataun.icmp6_un_data8
#define icmp6_mtu icmp6_data32[0]
#define ip6_flow ip6_ctlun.ip6_un1.ip6_un1_flow
#define ip6_hlim ip6_ctlun.ip6_un1.ip6_un1_hlim
#define ip6_hops ip6_ctlun.ip6_un1.ip6_un1_hlim
#define ip6_nxt ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ip6_plen ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_vfc ip6_ctlun.ip6_un2_vfc
#define nd_ns_cksum nd_ns_hdr.icmp6_cksum
#define nd_ns_code nd_ns_hdr.icmp6_code
#define nd_ns_reserved nd_ns_hdr.icmp6_data32[0]
#define nd_ns_type nd_ns_hdr.icmp6_type
#define s6_addr in6_u.u6_addr8
#define s6_addr16 in6_u.u6_addr16
#define s6_addr32 in6_u.u6_addr32




#define LOG_ALERT EVENTLOG_ERROR_TYPE
#define LOG_CRIT EVENTLOG_ERROR_TYPE
#define LOG_DEBUG EVENTLOG_INFORMATION_TYPE
#define LOG_EMERG EVENTLOG_ERROR_TYPE
#define LOG_ERR EVENTLOG_ERROR_TYPE
#define LOG_INFO EVENTLOG_INFORMATION_TYPE
#define LOG_NOTICE EVENTLOG_INFORMATION_TYPE
#define LOG_WARNING EVENTLOG_WARNING_TYPE


#define TINC_CTL_VERSION_CURRENT 0


