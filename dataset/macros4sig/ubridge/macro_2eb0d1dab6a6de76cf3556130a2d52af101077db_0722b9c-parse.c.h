#include<sys/un.h>
#include<errno.h>

#include<string.h>
#include<stdlib.h>
#include<stdarg.h>
#include<stdio.h>
#include<pthread.h>


#include<sys/types.h>


#define VMNET_ABI_VERSION_MAJOR(v) ((v) >> 16)
#define VMNET_KEXT_NAME "com.vmware.kext.vmnet"
#define NIO_DEV_MAXLEN      64

#define NIO_MAX_PKT_SIZE    65535
#define m_min(a,b) (((a) < (b)) ? (a) : (b))

#define VLAN_HEADER_LEN 4

#define PCAP_NETMASK_UNKNOWN    0xffffffff




#  define HOST_NAME_MAX MAXHOSTNAMELEN

#define MAX_KEY_SIZE   256


#define CONFIG_FILE   "ubridge.ini"
#define FALSE 0

#define NAME          "ubridge"
#define TRUE  1

#define VERSION       "0.9.15"
#define handle_error_en(en, msg) \
        do { errno = en; perror(msg); exit(EXIT_FAILURE); } while (0)

