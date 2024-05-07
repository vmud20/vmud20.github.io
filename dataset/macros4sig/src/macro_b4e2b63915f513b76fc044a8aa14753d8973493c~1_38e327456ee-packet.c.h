#include<netinet/if_ether.h>
#include<netinet/ip.h>
#include<stdarg.h>
#include<sys/time.h>
#include<sys/cdefs.h>
#include<netinet/in.h>


#include<sys/wait.h>
#include<sys/errno.h>
#include<sys/socket.h>


#include<syslog.h>

#include<sys/stat.h>
#include<sys/types.h>
#include<sys/signal.h>


#include<net/if.h>
#include<fcntl.h>
#include<net/route.h>
#include<sys/unistd.h>
#include<sys/queue.h>
#include<netinet/udp.h>
#define BOOTP_BROADCAST 32768L
#define F_LOCK          1	
#define F_TEST          3	
#define F_TLOCK         2	
#define F_ULOCK         0	






#define alloca(n) __builtin_alloca(n)

#define clearerr(p)	(!__isthreaded ? __sclearerr(p) : (clearerr)(p))
#define feof(p)		(!__isthreaded ? __sfeof(p) : (feof)(p))
#define ferror(p)	(!__isthreaded ? __sferror(p) : (ferror)(p))
#define fileno(p)	(!__isthreaded ? __sfileno(p) : (fileno)(p))
#define getc(fp)	(!__isthreaded ? __sgetc(fp) : (getc)(fp))
#define getchar_unlocked()	getc_unlocked(stdin)
#define putc(x, fp)	(!__isthreaded ? __sputc(x, fp) : (putc)(x, fp))
#define putc_unlocked(x, fp)	__sputc(x, fp)
#define putchar_unlocked(c)	putc_unlocked(c, stdout)
#define _PATH_KLOG      "/dev/klog"
#define _PATH_LOGCONF   "/etc/syslog.conf"
#define _PATH_LOGPID    "/var/run/syslog.pid"
#define AI_MASK \
    (AI_PASSIVE | AI_CANONNAME | AI_NUMERICHOST | AI_NUMERICSERV | AI_FQDN | \
     AI_ADDRCONFIG)
#define SCOPE_DELIMITER '%'



#define htonl(x)	__htobe32(x)
#define htons(x)	__htobe16(x)
#define ntohl(x)	__htobe32(x)
#define ntohs(x)	__htobe16(x)
