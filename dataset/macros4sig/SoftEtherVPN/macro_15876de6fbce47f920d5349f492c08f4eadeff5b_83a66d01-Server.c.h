#include<netinet/tcp.h>

#include<fcntl.h>
#include<stdlib.h>
#include<sys/vfs.h>

#include<sys/param.h>

#include<netdb.h>

#include<stdio.h>
#include<netinet/in.h>
#include<dirent.h>

#include<sys/file.h>
#include<sys/statvfs.h>
#include<sys/poll.h>
#include<sys/types.h>
#include<wchar.h>
#include<ifaddrs.h>
#include<stdarg.h>
#include<termios.h>
#include<iconv.h>
#include<signal.h>
#include<net/if.h>
#include<sys/mount.h>

#include<sys/time.h>
#include<sys/prctl.h>


#include<net/if_arp.h>

#include<sys/ioctl.h>

#include<sys/stat.h>
#include<sys/socket.h>
#include<time.h>
#include<string.h>
#include<pthread.h>

#include<errno.h>
#include<net/ethernet.h>
#include<netpacket/packet.h>
#include<unistd.h>
#include<netinet/if_ether.h>
#include<sys/wait.h>
#include<sys/resource.h>

#define ct_clamp(n,mi,ma) (ct_max(ct_min((n),(ma)),(mi)))
#define ct_clamp01(n) ct_clamp(n,0,1)
#define ct_max(a,b) (((a) > (b)) ? (a): (b))
#define ct_min(a,b) (((a) < (b)) ? (a): (b))
#define PUBLIC_SERVER_HTML_EN "http://www.softether.com/jp/special/se2hub_en.aspx"
#define WU_CONTEXT_EXPIRE 600000
#define MAX_LOGGING_QUEUE_LEN 100000
#define ifr_newname     ifr_ifru.ifru_slave
#define IKE_IS_SUPPORTED_PAYLOAD_TYPE(i) ((((i) >= IKE_PAYLOAD_SA) && ((i) <= IKE_PAYLOAD_VENDOR_ID)) || ((i) == IKE_PAYLOAD_NAT_D) || ((i) == IKE_PAYLOAD_NAT_OA) || ((i) == IKE_PAYLOAD_NAT_OA_DRAFT) || ((i) == IKE_PAYLOAD_NAT_OA_DRAFT_2) || ((i) == IKE_PAYLOAD_NAT_D_DRAFT))
#define MS_WCM_MAX_PROFILE_NAME            256
#define IPV6_GET_FLAGS(h)				((h)->FlagmentOffset2AndFlags & 0x0f)
#define IPV6_GET_FRAGMENT_OFFSET(h)		(((((h)->FlagmentOffset1) << 5) & 0x1fe0) | (((h)->FlagmentOffset2AndFlags >> 3) & 0x1f))
#define IPV6_GET_TRAFFIC_CLASS(h)	((((h)->VersionAndTrafficClass1 << 4) & 0xf0) | ((h)->TrafficClass2AndFlowLabel1 >> 4) & 0x0f)
#define IPV6_GET_VERSION(h)			(((h)->VersionAndTrafficClass1 >> 4) & 0x0f)
#define IPV6_SET_FLAGS(h, v)				((h)->FlagmentOffset2AndFlags = (((h)->FlagmentOffset2AndFlags & 0xf8) | (v & 0x07)))
#define IPV6_SET_FLOW_LABEL(h, v)	((h)->TrafficClass2AndFlowLabel1 = ((h)->TrafficClass2AndFlowLabel1 & 0xf0 | ((v) >> 16) & 0x0f),\
	(h)->FlowLabel2 = ((v) >> 8) & 0xff,\
	(h)->FlowLabel3 = (v) & 0xff)
#define IPV6_SET_FRAGMENT_OFFSET(h, v)	((h)->FlagmentOffset1 = (v / 32) & 0xff,	\
	((h)->FlagmentOffset2AndFlags = ((v % 256) << 3) & 0xf8) | ((h)->FlagmentOffset2AndFlags & 0x07))
#define IPV6_SET_VERSION(h, v)		((h)->VersionAndTrafficClass1 = ((h)->VersionAndTrafficClass1 & 0x0f) | ((v) << 4) & 0xf0)
#define _GETLANG()		(_II("LANG"))
#define DH_GROUP1_PRIME_768 \
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" \
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" \
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" \
	"E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF"
#define DH_GROUP2_PRIME_1024 \
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" \
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" \
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" \
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" \
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381" \
	"FFFFFFFFFFFFFFFF"
#define DH_GROUP5_PRIME_1536 \
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" \
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" \
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" \
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" \
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" \
	"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" \
	"83655D23DCA3AD961C62F356208552BB9ED529077096966D" \
	"670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF"
#define COMPARE_RET(a, b)	(((a) == (b)) ? 0 : (((a) > (b)) ? 1 : -1))
#define DBG      cmn_err
#define IFF_NO_PI       0x1000
#define IFF_ONE_QUEUE   0x2000
#define IFF_TAP         0x0002
#define IFF_TUN         0x0001
#define SNIFFER(a) ( (a & TUN_ALL_SAP) || (a & TUN_ALL_PHY) )
#define TUNGDEBUG       _IOR('t', 89, int)
#define TUNGIFHEAD      _IOR('t', 97, int)
#define TUNGIFINFO      _IOR('t', 92, struct tuninfo)
#define TUNMAXPPA       20
#define TUNMRU          16384
#define TUNMTU          1500
#define TUNNEWPPA       (('T'<<16) | 0x0001)
#define TUNSDEBUG       _IOW('t', 90, int)
#define TUNSETDEBUG   _IOW('T', 201, int) 
#define TUNSETIFF     _IOW('T', 202, int) 
#define TUNSETNOCSUM  _IOW('T', 200, int) 
#define TUNSETOWNER   _IOW('T', 204, int)
#define TUNSETPERSIST _IOW('T', 203, int) 
#define TUNSETPPA       (('T'<<16) | 0x0002)
#define TUNSIFHEAD      _IOW('t', 96, int)
#define TUNSIFINFO      _IOW('t', 91, struct tuninfo)
#define TUNSIFMODE      _IOW('t', 94, int)
#define TUNSIFPID       _IO('t', 95)
#define TUNSLMODE       _IOW('t', 93, int)
#define TUN_ADDR_LEN    (sizeof(struct tundladdr))
#define TUN_ALL_MUL     0x0040
#define TUN_ALL_PHY     0x0010
#define TUN_ALL_SAP     0x0020
#define TUN_CONTROL     0x0001
#define TUN_DROP        1
#define TUN_FAST        0x0200
#define TUN_FASYNC      0x0010
#define TUN_NOCHECKSUM  0x0020
#define TUN_NO_PI       0x0040
#define TUN_ONE_QUEUE   0x0080
#define TUN_PERSIST     0x0100  
#define TUN_PKT_STRIP   0x0001
#define TUN_QUEUE       0
#define TUN_RAW         0x0100
#define TUN_READQ_SIZE  10
#define TUN_TAP_DEV     0x0002
#define TUN_TUN_DEV     0x0001  
#define TUN_TYPE_MASK   0x000f



