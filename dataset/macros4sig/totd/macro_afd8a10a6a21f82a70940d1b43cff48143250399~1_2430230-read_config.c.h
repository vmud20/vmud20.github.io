#include<arpa/inet.h>
#include<stdlib.h>
#include<unistd.h>
#include<sys/time.h>
#include<sys/types.h>
#include<string.h>
#include<assert.h>

#include<stdio.h>
#include<stdint.h>
#include<grp.h>
#include<signal.h>
#include<sys/socket.h>
#include<net/if.h>
#include<time.h>
#include<sys/cdefs.h>

#include<malloc.h>
#include<errno.h>
#include<netdb.h>
#include<sys/termios.h>
#include<fcntl.h>
#include<limits.h>
#include<netinet/in.h>

#include<pwd.h>
#include<syslog.h>
#include<sys/param.h>
#include<ctype.h>
#include<setjmp.h>
#include<sys/ioctl.h>

#define socklen_t int
#define DATADATA_HEAD_LEN sizeof(Data_Data)
#define KEYINFO_HEAD_LEN   (sizeof(uint16_t) * 3)
#define RR_HEAD_LEN (sizeof(uint16_t)+sizeof(uint32_t))
#define data_offset(n, d) (*((uint16_t*)(((u_char*)(d))+\
					  (sizeof(uint16_t)*((n)+1)))))
#define rr_rdata(rr) (((u_char*)(rr))+(sizeof(uint16_t)+sizeof(uint32_t)))
#define rrset_owner(rrset) (((u_char *)(rrset)->key.info) + KEYINFO_HEAD_LEN)
#define rrset_owner_len(rrset) (rrset->key.info->owner_len)
#define C_ANY 255
#define C_IN 1
#define C_NONE 254		
#define DNAME_DELIM '.'		
#define DNCMP_MASK 0xc0
#define DNCMP_MASK_INT16T 0xc000
#define DNCMP_REDIRECT_LIMIT (0x3000-1)
#define EDNS0_ELT_BITLABEL 0x41
#define EDNS0_MASK 0x40
#define EVENT_LIFETIME 60
#define EV_DUP_CMP_LEN 16
#define EV_DUP_TABLE_SIZE 1000
#define EV_TIMEOUT_CONTEXT 1
#define EV_TIMEOUT_NULL 0
#define FORWARDER_DEATH_MARK 3
#define FORWARD_REQUEST 1
#define IF_CHECK_INTERVAL 10
#define MAXARGS 30
#define MAXINTERFACES MAXARGS
#define MAXPREFIXES MAXARGS
#define MAX_DNAME 256		
#define MAX_LABEL 63		
#define MAX_PACKET 512		
#define MAX_STREAM 65535	
#define NEWPTR_TRICK_REQUEST 4
#define OP_QUERY 0		
#define PORT_SRV 53		
#define PORT_TO 53		
#define PTR_SCOPED_TRICK_REQUEST 5
#define PTR_TRICK_REQUEST 3
#define QUERY_TCP 1
#define RC_FMTERR 1		
#define RC_NAMEERR 3		
#define RC_NIMP 4		
#define RC_NOTAUTH 9		
#define RC_NOTZONE 10		
#define RC_NXDOMAIN 3		
#define RC_NXRRSET 8		
#define RC_OK 0			
#define RC_REF 5		
#define RC_SERVERERR 2		
#define RC_YXDOMAIN 6		
#define RC_YXRRSET 7		
#define RT_A 1
#define RT_A6 38		
#define RT_AAAA 28		
#define RT_ALL 255
#define RT_AXFR 252
#define RT_CNAME 5
#define RT_DNAME 39
#define RT_HINFO 13
#define RT_IXFR 251
#define RT_MB 7
#define RT_MD 3
#define RT_MF 4
#define RT_MG 8
#define RT_MINFO 14
#define RT_MR 9
#define RT_MX 15
#define RT_NS 2
#define RT_NULL 10
#define RT_PTR 12
#define RT_RP 17		
#define RT_SOA 6
#define RT_SRV 33		
#define RT_TSIG 250
#define RT_TXT 16
#define RT_UINFO 100
#define RT_VOID 0
#define RT_WKS 11
#define SEARCH_CNAME_LEVEL   6	
#define SEARCH_REMOTE_RETRY   1	
#define SEARCH_REMOTE_TIMEOUT 2	
#define STF_DONE 0
#define STF_FORWARDING 8
#define STF_NSLIST 7
#define STF_REQUEST 6
#define TCP_SRV_TIMEOUT 60      
#define TOTPREFIXLEN 24

#define TOT_PID_FILE "/var/run/totd.pid"
#define TRICK_REQUEST 2
#define WORD_NONE 0
#define WORK_DONE 0
#define CVSID(string) \
        static const char cvsid[] __attribute__((__unused__)) = string
#define GETLONG(ul, ucp) { \
	(ul) = *(ucp)++ << 8; \
	(ul) |= *(ucp)++; (ul) <<= 8; \
	(ul) |= *(ucp)++; (ul) <<= 8; \
	(ul) |= *(ucp)++; \
}
#define GETSHORT(us, ucp) { \
	(us) = *(ucp)++ << 8; \
	(us) |= *(ucp)++; \
}
#define MAXNUM(x,y) (((x)>(y)) ? (x) : (y))
#define PUTLONG(ul, ucp) { \
	(ucp)[3] = ul; \
	(ucp)[2] = (ul >>= 8); \
	(ucp)[1] = (ul >>= 8); \
	(ucp)[0] = ul >> 8; \
	(ucp) += sizeof(uint32_t); \
}
#define PUTSHORT(us, ucp) { \
	*(ucp)++ = (us) >> 8; \
	*(ucp)++ = (us); \
}
#define SOCKADDR_SIZEOF(sa) (MAXNUM((sa).sa_len, sizeof(sa)))
#define V4(x) x
#define V6(x) x
#define HAVE_DAEMON 1
#define HAVE_FCNTL_H 1
#define HAVE_INET_ATON 1
#define HAVE_LIMITS_H 1
#define HAVE_SA_LEN_FIELD 1
#define HAVE_SIN6_SCOPE_ID 1
#define HAVE_STDINT_H 1
#define HAVE_STRLCAT 1
#define HAVE_STRLCPY 1
#define HAVE_SYSLOG_H 1
#define HAVE_SYS_CDEFS_H 1
#define HAVE_SYS_FILIO_H 1
#define HAVE_SYS_IOCTL_H 1
#define HAVE_SYS_SOCKIO_H 1
#define HAVE_SYS_TIME_H 1
#define HAVE_UNISTD_H 1
#define RETSIGTYPE void
#define STDC_HEADERS 1
#define TIME_WITH_SYS_TIME 1
