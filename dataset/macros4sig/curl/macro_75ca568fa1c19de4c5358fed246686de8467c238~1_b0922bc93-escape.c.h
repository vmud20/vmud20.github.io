
#include<ctype.h>
#include<limits.h>


#include<sys/socket.h>




#include<setjmp.h>


#include<sys/types.h>
#include<errno.h>

#include<fcntl.h>
#include<stdlib.h>






#include<memory.h>


#include<iconv.h>
#include<sys/time.h>


#include<time.h>
#include<stddef.h>


#include<stdbool.h>
#include<assert.h>





#include<sys/select.h>




#include<err.h>
#include<stdio.h>
#include<sys/stat.h>






#include<netinet/in.h>

#include<malloc.h>
#include<string.h>









#include<zlib.h>



#include<stdarg.h>

#define CURL_MT_LOGFNAME_BUFSIZE 512
#define Curl_safefree(ptr) \
  do {if((ptr)) {free((ptr)); (ptr) = NULL;}} WHILE_FALSE

#define accept(sock,addr,len)\
 curl_accept(sock,addr,len,"__LINE__","__FILE__")
#define calloc(nbelem,size) curl_docalloc(nbelem, size, "__LINE__", "__FILE__")
#define fake_sclose(sockfd) curl_mark_sclose(sockfd,"__LINE__","__FILE__")
#define fclose(file) curl_fclose(file,"__LINE__","__FILE__")
#define fdopen(file,mode) curl_fdopen(file,mode,"__LINE__","__FILE__")
#define fopen(file,mode) curl_fopen(file,mode,"__LINE__","__FILE__")
#define free(ptr) curl_dofree(ptr, "__LINE__", "__FILE__")
#define freeaddrinfo(data) \
  curl_dofreeaddrinfo(data,"__LINE__","__FILE__")
#define getaddrinfo(host,serv,hint,res) \
  curl_dogetaddrinfo(host,serv,hint,res,"__LINE__","__FILE__")
#define getnameinfo(sa,salen,host,hostlen,serv,servlen,flags) \
  curl_dogetnameinfo(sa,salen,host,hostlen,serv,servlen,flags, "__LINE__", \
  "__FILE__")
#define logfile curl_debuglogfile
#define malloc(size) curl_domalloc(size, "__LINE__", "__FILE__")
#define ogetaddrinfo(host,serv,hint,res) \
  curl_dogetaddrinfo(host,serv,hint,res,"__LINE__","__FILE__")
#define realloc(ptr,size) curl_dorealloc(ptr, size, "__LINE__", "__FILE__")
#define sclose(sockfd) curl_sclose(sockfd,"__LINE__","__FILE__")
#define socket(domain,type,protocol)\
 curl_socket(domain,type,protocol,"__LINE__","__FILE__")
#define socketpair(domain,type,protocol,socket_vector)\
 curl_socketpair(domain,type,protocol,socket_vector,"__LINE__","__FILE__")
#define strdup(ptr) curl_dostrdup(ptr, "__LINE__", "__FILE__")
#define CFINIT(name) CURLFORM_ ## name
#define CINIT(na,t,nu) CURLOPT_ ## na = CURLOPTTYPE_ ## t + nu
#define CURLAUTH_ANY (~CURLAUTH_DIGEST_IE)  
#define CURLAUTH_ANYSAFE (~(CURLAUTH_BASIC|CURLAUTH_DIGEST_IE))
#define CURLAUTH_BASIC        (1<<0)  
#define CURLAUTH_DIGEST       (1<<1)  
#define CURLAUTH_DIGEST_IE    (1<<4)  
#define CURLAUTH_GSSNEGOTIATE (1<<2)  
#define CURLAUTH_NTLM         (1<<3)  
#define CURLAUTH_NTLM_WB      (1<<5)  
#define CURLAUTH_ONLY         (1<<31) 
#define CURLE_ALREADY_COMPLETE 99999
#define CURLE_BAD_CALLING_ORDER CURLE_OBSOLETE44
#define CURLE_BAD_PASSWORD_ENTERED CURLE_OBSOLETE46
#define CURLE_FTP_ACCESS_DENIED CURLE_REMOTE_ACCESS_DENIED
#define CURLE_FTP_BAD_DOWNLOAD_RESUME CURLE_BAD_DOWNLOAD_RESUME
#define CURLE_FTP_CANT_RECONNECT CURLE_OBSOLETE16
#define CURLE_FTP_COULDNT_GET_SIZE CURLE_OBSOLETE32
#define CURLE_FTP_COULDNT_SET_ASCII CURLE_OBSOLETE29
#define CURLE_FTP_COULDNT_SET_BINARY CURLE_FTP_COULDNT_SET_TYPE
#define CURLE_FTP_COULDNT_STOR_FILE CURLE_UPLOAD_FAILED
#define CURLE_FTP_PARTIAL_FILE CURLE_PARTIAL_FILE
#define CURLE_FTP_QUOTE_ERROR CURLE_QUOTE_ERROR
#define CURLE_FTP_SSL_FAILED CURLE_USE_SSL_FAILED
#define CURLE_FTP_USER_PASSWORD_INCORRECT CURLE_OBSOLETE10
#define CURLE_FTP_WEIRD_USER_REPLY CURLE_OBSOLETE12
#define CURLE_FTP_WRITE_ERROR CURLE_OBSOLETE20
#define CURLE_HTTP_NOT_FOUND CURLE_HTTP_RETURNED_ERROR
#define CURLE_HTTP_PORT_FAILED CURLE_INTERFACE_FAILED
#define CURLE_HTTP_RANGE_ERROR CURLE_RANGE_ERROR
#define CURLE_LIBRARY_NOT_FOUND CURLE_OBSOLETE40
#define CURLE_MALFORMAT_USER CURLE_OBSOLETE24
#define CURLE_OBSOLETE CURLE_OBSOLETE50 
#define CURLE_OBSOLETE10 CURLE_FTP_ACCEPT_FAILED
#define CURLE_OBSOLETE12 CURLE_FTP_ACCEPT_TIMEOUT
#define CURLE_OPERATION_TIMEOUTED CURLE_OPERATION_TIMEDOUT
#define CURLE_SHARE_IN_USE CURLE_OBSOLETE57
#define CURLE_SSL_PEER_CERTIFICATE CURLE_PEER_FAILED_VERIFICATION
#define CURLE_TFTP_DISKFULL CURLE_REMOTE_DISK_FULL
#define CURLE_TFTP_EXISTS CURLE_REMOTE_FILE_EXISTS
#define CURLE_UNKNOWN_TELNET_OPTION CURLE_UNKNOWN_OPTION
#define CURLE_URL_MALFORMAT_USER CURLE_NOT_BUILT_IN
#define CURLFINFOFLAG_KNOWN_FILENAME    (1<<0)
#define CURLFINFOFLAG_KNOWN_FILETYPE    (1<<1)
#define CURLFINFOFLAG_KNOWN_GID         (1<<5)
#define CURLFINFOFLAG_KNOWN_HLINKCOUNT  (1<<7)
#define CURLFINFOFLAG_KNOWN_PERM        (1<<3)
#define CURLFINFOFLAG_KNOWN_SIZE        (1<<6)
#define CURLFINFOFLAG_KNOWN_TIME        (1<<2)
#define CURLFINFOFLAG_KNOWN_UID         (1<<4)
#define CURLFTPSSL_ALL CURLUSESSL_ALL
#define CURLFTPSSL_CONTROL CURLUSESSL_CONTROL
#define CURLFTPSSL_LAST CURLUSESSL_LAST
#define CURLFTPSSL_NONE CURLUSESSL_NONE
#define CURLFTPSSL_TRY CURLUSESSL_TRY
#define CURLGSSAPI_DELEGATION_FLAG        (1<<1) 
#define CURLGSSAPI_DELEGATION_NONE        0      
#define CURLGSSAPI_DELEGATION_POLICY_FLAG (1<<0) 
#define CURLINFO_DOUBLE   0x300000
#define CURLINFO_HTTP_CODE CURLINFO_RESPONSE_CODE
#define CURLINFO_LONG     0x200000
#define CURLINFO_MASK     0x0fffff
#define CURLINFO_SLIST    0x400000
#define CURLINFO_STRING   0x100000
#define CURLINFO_TYPEMASK 0xf00000
#define CURLOPTTYPE_FUNCTIONPOINT 20000
#define CURLOPTTYPE_LONG          0
#define CURLOPTTYPE_OBJECTPOINT   10000
#define CURLOPTTYPE_OFF_T         30000
#define CURLOPT_ENCODING CURLOPT_ACCEPT_ENCODING
#define CURLOPT_FTPAPPEND CURLOPT_APPEND
#define CURLOPT_FTPLISTONLY CURLOPT_DIRLISTONLY
#define CURLOPT_FTP_SSL CURLOPT_USE_SSL
#define CURLOPT_HEADERDATA CURLOPT_WRITEHEADER
#define CURLOPT_KRB4LEVEL CURLOPT_KRBLEVEL
#define CURLOPT_POST301 CURLOPT_POSTREDIR
#define CURLOPT_READDATA  CURLOPT_INFILE
#define CURLOPT_RTSPHEADER CURLOPT_HTTPHEADER
#define CURLOPT_SERVER_RESPONSE_TIMEOUT CURLOPT_FTP_RESPONSE_TIMEOUT
#define CURLOPT_SSLCERTPASSWD CURLOPT_KEYPASSWD
#define CURLOPT_SSLKEYPASSWD CURLOPT_KEYPASSWD
#define CURLOPT_WRITEDATA CURLOPT_FILE
#define CURLPAUSE_ALL       (CURLPAUSE_RECV|CURLPAUSE_SEND)
#define CURLPAUSE_CONT      (CURLPAUSE_RECV_CONT|CURLPAUSE_SEND_CONT)
#define CURLPAUSE_RECV      (1<<0)
#define CURLPAUSE_RECV_CONT (0)
#define CURLPAUSE_SEND      (1<<2)
#define CURLPAUSE_SEND_CONT (0)
#define CURLPROTO_ALL    (~0) 
#define CURLPROTO_DICT   (1<<9)
#define CURLPROTO_FILE   (1<<10)
#define CURLPROTO_FTP    (1<<2)
#define CURLPROTO_FTPS   (1<<3)
#define CURLPROTO_GOPHER (1<<25)
#define CURLPROTO_HTTP   (1<<0)
#define CURLPROTO_HTTPS  (1<<1)
#define CURLPROTO_IMAP   (1<<12)
#define CURLPROTO_IMAPS  (1<<13)
#define CURLPROTO_LDAP   (1<<7)
#define CURLPROTO_LDAPS  (1<<8)
#define CURLPROTO_POP3   (1<<14)
#define CURLPROTO_POP3S  (1<<15)
#define CURLPROTO_RTMP   (1<<19)
#define CURLPROTO_RTMPE  (1<<21)
#define CURLPROTO_RTMPS  (1<<23)
#define CURLPROTO_RTMPT  (1<<20)
#define CURLPROTO_RTMPTE (1<<22)
#define CURLPROTO_RTMPTS (1<<24)
#define CURLPROTO_RTSP   (1<<18)
#define CURLPROTO_SCP    (1<<4)
#define CURLPROTO_SFTP   (1<<5)
#define CURLPROTO_SMTP   (1<<16)
#define CURLPROTO_SMTPS  (1<<17)
#define CURLPROTO_TELNET (1<<6)
#define CURLPROTO_TFTP   (1<<11)
#define CURLSSH_AUTH_ANY       ~0     
#define CURLSSH_AUTH_DEFAULT CURLSSH_AUTH_ANY
#define CURLSSH_AUTH_HOST      (1<<2) 
#define CURLSSH_AUTH_KEYBOARD  (1<<3) 
#define CURLSSH_AUTH_NONE      0      
#define CURLSSH_AUTH_PASSWORD  (1<<1) 
#define CURLSSH_AUTH_PUBLICKEY (1<<0) 
#define CURLVERSION_NOW CURLVERSION_FOURTH
#define CURL_CHUNK_BGN_FUNC_FAIL    1 
#define CURL_CHUNK_BGN_FUNC_OK      0
#define CURL_CHUNK_BGN_FUNC_SKIP    2 
#define CURL_CHUNK_END_FUNC_FAIL    1 
#define CURL_CHUNK_END_FUNC_OK      0
#define CURL_ERROR_SIZE 256
#define CURL_EXTERN  __declspec(dllexport)
#define CURL_FNMATCHFUNC_FAIL     2 
#define CURL_FNMATCHFUNC_MATCH    0 
#define CURL_FNMATCHFUNC_NOMATCH  1 
#define CURL_GLOBAL_ALL (CURL_GLOBAL_SSL|CURL_GLOBAL_WIN32)
#define CURL_GLOBAL_DEFAULT CURL_GLOBAL_ALL
#define CURL_GLOBAL_NOTHING 0
#define CURL_GLOBAL_SSL (1<<0)
#define CURL_GLOBAL_WIN32 (1<<1)
#define CURL_IPRESOLVE_V4       1 
#define CURL_IPRESOLVE_V6       2 
#define CURL_IPRESOLVE_WHATEVER 0 
#define CURL_MAX_HTTP_HEADER (100*1024)
#define CURL_MAX_WRITE_SIZE 16384
#define CURL_READFUNC_ABORT 0x10000000
#define CURL_READFUNC_PAUSE 0x10000001
#define CURL_REDIR_GET_ALL  0
#define CURL_REDIR_POST_301 1
#define CURL_REDIR_POST_302 2
#define CURL_REDIR_POST_ALL (CURL_REDIR_POST_301|CURL_REDIR_POST_302)
#define CURL_SEEKFUNC_CANTSEEK 2 
#define CURL_SEEKFUNC_FAIL     1 
#define CURL_SEEKFUNC_OK       0
#define CURL_SOCKET_BAD INVALID_SOCKET
#define CURL_SOCKOPT_ALREADY_CONNECTED 2
#define CURL_SOCKOPT_ERROR 1 
#define CURL_SOCKOPT_OK 0
#define CURL_VERSION_ASYNCHDNS (1<<7)  
#define CURL_VERSION_CONV      (1<<12) 
#define CURL_VERSION_CURLDEBUG (1<<13) 
#define CURL_VERSION_DEBUG     (1<<6)  
#define CURL_VERSION_GSSNEGOTIATE (1<<5) 
#define CURL_VERSION_IDN       (1<<10) 
#define CURL_VERSION_IPV6      (1<<0)  
#define CURL_VERSION_KERBEROS4 (1<<1)  
#define CURL_VERSION_LARGEFILE (1<<9)  
#define CURL_VERSION_LIBZ      (1<<3)  
#define CURL_VERSION_NTLM      (1<<4)  
#define CURL_VERSION_NTLM_WB   (1<<15) 
#define CURL_VERSION_SPNEGO    (1<<8)  
#define CURL_VERSION_SSL       (1<<2)  
#define CURL_VERSION_SSPI      (1<<11) 
#define CURL_VERSION_TLSAUTH_SRP (1<<14) 
#define CURL_WRITEFUNC_PAUSE 0x10000001
#define FUNCTIONPOINT CURLOPTTYPE_FUNCTIONPOINT
#define HTTPPOST_BUFFER (1<<4)      
#define HTTPPOST_CALLBACK (1<<6)    
#define HTTPPOST_FILENAME (1<<0)    
#define HTTPPOST_PTRBUFFER (1<<5)   
#define HTTPPOST_PTRCONTENTS (1<<3) 
#define HTTPPOST_PTRNAME (1<<2)     
#define HTTPPOST_READFILE (1<<1)    
#define LONG          CURLOPTTYPE_LONG
#define OBJECTPOINT   CURLOPTTYPE_OBJECTPOINT
#define OFF_T         CURLOPTTYPE_OFF_T


#define curl_easy_getinfo(handle,info,arg) curl_easy_getinfo(handle,info,arg)
#define curl_easy_setopt(handle,opt,param) curl_easy_setopt(handle,opt,param)
#define curl_ftpssl curl_usessl
#define curl_multi_setopt(handle,opt,param) curl_multi_setopt(handle,opt,param)
#define curl_share_setopt(share,opt,param) curl_share_setopt(share,opt,param)

#  define CURLRES_ARES
#  define CURLRES_ASYNCH
#  define CURLRES_IPV6
#define CURL_CA_BUNDLE getenv("CURL_CA_BUNDLE")
#    define CURL_DISABLE_DICT
#    define CURL_DISABLE_FILE
#    define CURL_DISABLE_FTP
#    define CURL_DISABLE_LDAP
#    define CURL_DISABLE_RTSP
#    define CURL_DISABLE_TELNET
#    define CURL_DISABLE_TFTP
#  define Curl_nop_stmt do { } WHILE_FALSE
#  define DIR_CHAR      "\\"
#  define DOT_CHAR      "_"
#  define FORMAT_OFF_T  "lld"
#  define FORMAT_OFF_TU "llu"
#    define GETHOSTNAME_TYPE_ARG2 int

#define LIBIDN_REQUIRED_VERSION "0.4.1"
#  define LSEEK_ERROR                (__int64)-1
#  define SHUT_RD   0x00
#  define SHUT_RDWR 0x02
#  define SHUT_WR   0x01
#      define SIZEOF_OFF_T 8
#define SIZEOF_TIME_T 4
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#define UNUSED_PARAM 



#define USE_SSL    
#  define USE_WINSOCK 2
#    define WIN32_LEAN_AND_MEAN
#    define _REENTRANT
#    define _THREAD_SAFE
#  define fstat(fdes,stp)            _fstati64(fdes, stp)
#  define lseek(fdes,offset,whence)  _lseeki64(fdes, offset, whence)
#  define select(a,b,c,d,e) tpf_select_libcurl(a,b,c,d,e)
#  define stat(fname,stp)            _stati64(fname, stp)
#  define struct_stat                struct _stati64
#  define sys_nerr EILSEQ
#define DEBUGASSERT(x) assert(x)
#define DEBUGF(x) x
#define EADDRINUSE       WSAEADDRINUSE
#define EADDRNOTAVAIL    WSAEADDRNOTAVAIL
#define EAFNOSUPPORT     WSAEAFNOSUPPORT
#define EALREADY         WSAEALREADY
#define EBADF            WSAEBADF
#define ECONNABORTED     WSAECONNABORTED
#define ECONNREFUSED     WSAECONNREFUSED
#define ECONNRESET       WSAECONNRESET
#define EDESTADDRREQ     WSAEDESTADDRREQ
#define EDQUOT           WSAEDQUOT
#define EHOSTDOWN        WSAEHOSTDOWN
#define EHOSTUNREACH     WSAEHOSTUNREACH
#define EINPROGRESS      WSAEINPROGRESS
#define EINTR            WSAEINTR
#define EINVAL           WSAEINVAL
#define EISCONN          WSAEISCONN
#define ELOOP            WSAELOOP
#define EMSGSIZE         WSAEMSGSIZE
#define ENAMETOOLONG     WSAENAMETOOLONG
#define ENETDOWN         WSAENETDOWN
#define ENETRESET        WSAENETRESET
#define ENETUNREACH      WSAENETUNREACH
#define ENOBUFS          WSAENOBUFS
#define ENOPROTOOPT      WSAENOPROTOOPT
#define ENOTCONN         WSAENOTCONN
#define ENOTEMPTY        WSAENOTEMPTY
#define ENOTSOCK         WSAENOTSOCK
#define EOPNOTSUPP       WSAEOPNOTSUPP
#define EPFNOSUPPORT     WSAEPFNOSUPPORT
#define EPROCLIM         WSAEPROCLIM
#define EPROTONOSUPPORT  WSAEPROTONOSUPPORT
#define EPROTOTYPE       WSAEPROTOTYPE
#define EREMOTE          WSAEREMOTE
#define ERRNO         ((int)GetLastError())
#define ESHUTDOWN        WSAESHUTDOWN
#define ESOCKTNOSUPPORT  WSAESOCKTNOSUPPORT
#define ESTALE           WSAESTALE
#define ETIMEDOUT        WSAETIMEDOUT
#define ETOOMANYREFS     WSAETOOMANYREFS
#define EUSERS           WSAEUSERS
#define EWOULDBLOCK      WSAEWOULDBLOCK
#define FALSE false
#  define HAVE_BOOL_T

#define ISALNUM(x)  (isalnum((int)  ((unsigned char)x)))
#define ISALPHA(x)  (isalpha((int)  ((unsigned char)x)))
#define ISASCII(x)  (isascii((int)  ((unsigned char)x)))
#define ISBLANK(x)  (int)((((unsigned char)x) == ' ') || \
                          (((unsigned char)x) == '\t'))
#define ISDIGIT(x)  (isdigit((int)  ((unsigned char)x)))
#define ISGRAPH(x)  (isgraph((int)  ((unsigned char)x)))
#define ISLOWER(x)  (islower((int)  ((unsigned char)x)))
#define ISPRINT(x)  (isprint((int)  ((unsigned char)x)))
#define ISSPACE(x)  (isspace((int)  ((unsigned char)x)))
#define ISUPPER(x)  (isupper((int)  ((unsigned char)x)))
#define ISXDIGIT(x) (isxdigit((int) ((unsigned char)x)))
#define RETSIGTYPE void
#define SEND_4TH_ARG MSG_NOSIGNAL
#define SET_ERRNO(x)  (SetLastError((DWORD)(x)))
#define SET_SOCKERRNO(x)  (WSASetLastError((int)(x)))
#define SIG_ATOMIC_T static sig_atomic_t
#define SOCKERRNO         ((int)WSAGetLastError())
#define TOLOWER(x)  (tolower((int)  ((unsigned char)x)))
#define TRUE true
#    define WHILE_FALSE  while(1, 0)
#define ZERO_NULL 0

#define argv_item_t  __char_ptr32
#  define false bool_false
#define getpwuid __32_getpwuid
#define sread(x,y,z) (ssize_t)read((RECV_TYPE_ARG1)(x), \
                                   (RECV_TYPE_ARG2)(y), \
                                   (RECV_TYPE_ARG3)(z))
#define swrite(x,y,z) (ssize_t)write((SEND_TYPE_ARG1)(x), \
                                    (SEND_TYPE_ARG2)(y), \
                                    (SEND_TYPE_ARG3)(z))
#  define true  bool_true


#  define CURL_OFF_TU_C(Val) __CURL_OFF_T_C_HLPR1(Val) ## \
                             __CURL_OFF_T_C_HLPR1(CURL_SUFFIX_CURL_OFF_TU)
#  define CURL_OFF_T_C(Val)  __CURL_OFF_T_C_HLPR1(Val) ## \
                             __CURL_OFF_T_C_HLPR1(CURL_SUFFIX_CURL_OFF_T)
#define CurlchkszEQ(t, s) sizeof(t) == s ? 1 : -1
#define CurlchkszGE(t1, t2) sizeof(t1) >= sizeof(t2) ? 1 : -1

#  define __CURL_OFF_T_C_HLPR1(x) __CURL_OFF_T_C_HLPR2(x)
#    define __CURL_OFF_T_C_HLPR2(Val,Suffix) Val ## Suffix

# define aprintf curl_maprintf
# define fprintf curl_mfprintf
# define printf curl_mprintf
# define snprintf curl_msnprintf
# define sprintf sprintf_was_used
# define vaprintf curl_mvaprintf
# define vfprintf curl_mvfprintf
# define vprintf curl_mvprintf
# define vsnprintf curl_mvsnprintf
# define vsprintf vsprintf_was_used
#define Curl_convert_clone(a,b,c,d) ((void)a, CURLE_OK)
#define Curl_convert_close(x) Curl_nop_stmt
#define Curl_convert_form(a,b) CURLE_OK
#define Curl_convert_from_network(a,b,c) ((void)a, CURLE_OK)
#define Curl_convert_from_utf8(a,b,c) ((void)a, CURLE_OK)
#define Curl_convert_init(x) Curl_nop_stmt
#define Curl_convert_setup(x) Curl_nop_stmt
#define Curl_convert_to_network(a,b,c) ((void)a, CURLE_OK)

#define BUFSIZE CURL_MAX_WRITE_SIZE
#define COMPRESS 3              
#define CURLEASY_MAGIC_NUMBER 0xc0dedbadU
#define CURLMAX(x,y) ((x)>(y)?(x):(y))
#define CURLMIN(x,y) ((x)<(y)?(x):(y))
#define CURL_DEFAULT_PASSWORD "ftp@example.com"
#define CURL_DEFAULT_USER "anonymous"

#define CURR_TIME (5+1) 
#define DEFLATE 1               
#define DICT_DEFINE "/DEFINE:"
#define DICT_DEFINE2 "/D:"
#define DICT_DEFINE3 "/LOOKUP:"
#define DICT_MATCH "/MATCH:"
#define DICT_MATCH2 "/M:"
#define DICT_MATCH3 "/FIND:"
#define FIRSTSOCKET     0
#define GZIP 2                  
#define HEADERSIZE 256

#define IDENTITY 0              
#define KEEP_NONE  0
#define KEEP_RECV  (1<<0)     
#define KEEP_RECVBITS (KEEP_RECV | KEEP_RECV_HOLD | KEEP_RECV_PAUSE)
#define KEEP_RECV_HOLD (1<<2) 
#define KEEP_RECV_PAUSE (1<<4) 
#define KEEP_SEND (1<<1)     
#define KEEP_SENDBITS (KEEP_SEND | KEEP_SEND_HOLD | KEEP_SEND_PAUSE)
#define KEEP_SEND_HOLD (1<<3) 
#define KEEP_SEND_PAUSE (1<<5) 
#define LIBCURL_NAME "libcurl"
#define MAX_CURL_PASSWORD_LENGTH 256
#define MAX_CURL_PASSWORD_LENGTH_TXT "255"
#define MAX_CURL_USER_LENGTH 256
#define MAX_CURL_USER_LENGTH_TXT "255"
#define MAX_IPADR_LEN sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255")
#define MAX_PIPELINE_LENGTH 5
#define PORT_DICT 2628
#define PORT_FTP 21
#define PORT_FTPS 990
#define PORT_GOPHER 70
#define PORT_HTTP 80
#define PORT_HTTPS 443
#define PORT_IMAP 143
#define PORT_IMAPS 993
#define PORT_LDAP 389
#define PORT_LDAPS 636
#define PORT_POP3 110
#define PORT_POP3S 995
#define PORT_RTMP 1935
#define PORT_RTMPS PORT_HTTPS
#define PORT_RTMPT PORT_HTTP
#define PORT_RTSP 554
#define PORT_SMTP 25
#define PORT_SMTPS 465 
#define PORT_SSH 22
#define PORT_TELNET 23
#define PORT_TFTP 69
#define PROTOPT_CLOSEACTION (1<<2) 
#define PROTOPT_DIRLOCK (1<<3)
#define PROTOPT_DUAL (1<<1)        
#define PROTOPT_NEEDSPWD (1<<5)    
#define PROTOPT_NONE 0             
#define PROTOPT_NONETWORK (1<<4)   
#define PROTOPT_NOURLQUERY (1<<6)   
#define PROTOPT_SSL (1<<0)         
#define RESP_TIMEOUT (1800*1000)
#define SECONDARYSOCKET 1

#define SECURITY_WIN32 1
# define SEC_E_BUFFER_TOO_SMALL ((HRESULT)0x80090321L)
# define SEC_E_CONTEXT_EXPIRED ((HRESULT)0x80090317L)
# define SEC_E_CRYPTO_SYSTEM_INVALID ((HRESULT)0x80090337L)
# define SEC_E_MESSAGE_ALTERED ((HRESULT)0x8009030FL)
# define SEC_E_OUT_OF_SEQUENCE ((HRESULT)0x80090310L)
# define SEC_I_CONTEXT_EXPIRED ((HRESULT)0x00090317L)

#define Curl_rtsp_connisdead(x) TRUE
#define Curl_rtsp_parseheader(x,y) CURLE_NOT_BUILT_IN

#define CURLAUTH_PICKNONE (1<<30) 
#define MAX_INITIAL_POST_SIZE (64*1024)
#define TINY_INITIAL_POST_SIZE 1024

#  define HAVE_LIBSSH2_SCP_SEND64 1
#  define HAVE_LIBSSH2_SFTP_SEEK64 1


#define DEFAULT_ACCEPT_TIMEOUT   60000 



#define SMTP_AUTH_CRAM_MD5      0x0004
#define SMTP_AUTH_DIGEST_MD5    0x0008
#define SMTP_AUTH_EXTERNAL      0x0020
#define SMTP_AUTH_GSSAPI        0x0010
#define SMTP_AUTH_LOGIN         0x0001
#define SMTP_AUTH_NTLM          0x0040
#define SMTP_AUTH_PLAIN         0x0002
#define SMTP_EOB "\x0d\x0a\x2e\x0d\x0a"
#define SMTP_EOB_LEN 5
#define SMTP_EOB_REPL "\x0d\x0a\x2e\x2e"
#define SMTP_EOB_REPL_LEN 4



#define Curl_splaycomparekeys(i,j) ( ((i.tv_sec)  < (j.tv_sec))  ? -1 : \
                                   ( ((i.tv_sec)  > (j.tv_sec))  ?  1 : \
                                   ( ((i.tv_usec) < (j.tv_usec)) ? -1 : \
                                   ( ((i.tv_usec) > (j.tv_usec)) ?  1 : 0 ))))
#define Curl_splayprint(x,y,z) Curl_nop_stmt



#define CURLRESOLV_ERROR    -1
#define CURLRESOLV_PENDING   1
#define CURLRESOLV_RESOLVED  0
#define CURLRESOLV_TIMEDOUT -2
#define CURL_ASYNC_SUCCESS CURLE_OK
#define CURL_HOSTENT_SIZE 9000
#define CURL_INADDR_NONE (in_addr_t) ~0
#define CURL_TIMEOUT_RESOLVE 300 
#define Curl_async_resolved(x,y) CURLE_OK
#define Curl_ipv6works() FALSE

#define in_addr_t unsigned long
#define Curl_resolver_asynch() 1
#define Curl_resolver_cancel(x) Curl_nop_stmt
#define Curl_resolver_cleanup(x) Curl_nop_stmt
#define Curl_resolver_duphandle(x,y) CURLE_OK
#define Curl_resolver_getsock(x,y,z) 0
#define Curl_resolver_global_cleanup() Curl_nop_stmt
#define Curl_resolver_global_init() CURLE_OK
#define Curl_resolver_init(x) CURLE_OK
#define Curl_resolver_is_resolved(x,y) CURLE_COULDNT_RESOLVE_HOST
#define Curl_resolver_wait_resolv(x,y) CURLE_COULDNT_RESOLVE_HOST


#define MAXNUM_SIZE 16

#define Curl_tvdiff(x,y) curlx_tvdiff(x,y)
#define Curl_tvdiff_secs(x,y) curlx_tvdiff_secs(x,y)
#define Curl_tvnow() curlx_tvnow()


#define Curl_cookie_cleanup(x) Curl_nop_stmt
#define Curl_cookie_init(x,y,z,w) NULL
#define Curl_cookie_list(x) NULL
#define Curl_cookie_loadfiles(x) Curl_nop_stmt
#define Curl_flush_cookies(x,y) Curl_nop_stmt

#define MAX_COOKIE_LINE 5000
#define MAX_COOKIE_LINE_TXT "4999"
#define MAX_NAME 1024
#define MAX_NAME_TXT "1023"
#  define FD_ISSET(a,b) curlx_FD_ISSET((a),(b))
#  define FD_SET(a,b)   curlx_FD_SET((a),(b))
#  define FD_ZERO(a)    curlx_FD_ZERO((a))

#  define htons(a)      curlx_htons((a))
#  define ntohs(a)      curlx_ntohs((a))

