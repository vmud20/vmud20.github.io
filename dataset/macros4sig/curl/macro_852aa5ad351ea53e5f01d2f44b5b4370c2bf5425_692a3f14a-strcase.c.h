
#include<stdbool.h>


#include<fcntl.h>




#include<string.h>
#include<assert.h>
#include<unistd.h>
#include<sys/time.h>
#include<memory.h>
#include<time.h>
#include<sys/socket.h>
#include<limits.h>




#include<sys/types.h>



#include<stdio.h>

#include<sys/select.h>

#include<ctype.h>
#include<stdarg.h>
#include<errno.h>


#include<sys/stat.h>
#include<malloc.h>
#include<stdlib.h>

#define checkprefix(a,b)    curl_strnequal(b, STRCONST(a))
#define strcasecompare(a,b) Curl_strcasecompare(a,b)
#define strncasecompare(a,b,c) Curl_strncasecompare(a,b,c)
#define CURLALTSVC_H1           (1<<3)
#define CURLALTSVC_H2           (1<<4)
#define CURLALTSVC_H3           (1<<5)
#define CURLALTSVC_READONLYFILE (1<<2)
#define CURLAUTH_ANY          (~CURLAUTH_DIGEST_IE)
#define CURLAUTH_ANYSAFE      (~(CURLAUTH_BASIC|CURLAUTH_DIGEST_IE))
#define CURLAUTH_AWS_SIGV4    (((unsigned long)1)<<7)
#define CURLAUTH_BASIC        (((unsigned long)1)<<0)
#define CURLAUTH_BEARER       (((unsigned long)1)<<6)
#define CURLAUTH_DIGEST       (((unsigned long)1)<<1)
#define CURLAUTH_DIGEST_IE    (((unsigned long)1)<<4)
#define CURLAUTH_GSSAPI CURLAUTH_NEGOTIATE
#define CURLAUTH_GSSNEGOTIATE CURLAUTH_NEGOTIATE
#define CURLAUTH_NEGOTIATE    (((unsigned long)1)<<2)
#define CURLAUTH_NONE         ((unsigned long)0)
#define CURLAUTH_NTLM         (((unsigned long)1)<<3)
#define CURLAUTH_NTLM_WB      (((unsigned long)1)<<5)
#define CURLAUTH_ONLY         (((unsigned long)1)<<31)
#define CURLE_ALREADY_COMPLETE 99999
#define CURLE_BAD_CALLING_ORDER CURLE_OBSOLETE44
#define CURLE_BAD_PASSWORD_ENTERED CURLE_OBSOLETE46
#define CURLE_CONV_REQD CURLE_OBSOLETE76
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
#define CURLE_FTP_WEIRD_SERVER_REPLY CURLE_WEIRD_SERVER_REPLY
#define CURLE_FTP_WEIRD_USER_REPLY CURLE_OBSOLETE12
#define CURLE_FTP_WRITE_ERROR CURLE_OBSOLETE20
#define CURLE_HTTP_NOT_FOUND CURLE_HTTP_RETURNED_ERROR
#define CURLE_HTTP_PORT_FAILED CURLE_INTERFACE_FAILED
#define CURLE_HTTP_RANGE_ERROR CURLE_RANGE_ERROR
#define CURLE_LDAP_INVALID_URL CURLE_OBSOLETE62
#define CURLE_LIBRARY_NOT_FOUND CURLE_OBSOLETE40
#define CURLE_MALFORMAT_USER CURLE_OBSOLETE24
#define CURLE_OBSOLETE CURLE_OBSOLETE50 
#define CURLE_OBSOLETE10 CURLE_FTP_ACCEPT_FAILED
#define CURLE_OBSOLETE12 CURLE_FTP_ACCEPT_TIMEOUT
#define CURLE_OBSOLETE16 CURLE_HTTP2
#define CURLE_OPERATION_TIMEOUTED CURLE_OPERATION_TIMEDOUT
#define CURLE_SHARE_IN_USE CURLE_OBSOLETE57
#define CURLE_SSL_CACERT CURLE_PEER_FAILED_VERIFICATION
#define CURLE_SSL_PEER_CERTIFICATE CURLE_PEER_FAILED_VERIFICATION
#define CURLE_TELNET_OPTION_SYNTAX CURLE_SETOPT_OPTION_SYNTAX
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
#define CURLHEADER_SEPARATE (1<<0)
#define CURLHEADER_UNIFIED  0
#define CURLHSTS_ENABLE       (long)(1<<0)
#define CURLHSTS_READONLYFILE (long)(1<<1)

#define CURLINFO_DOUBLE   0x300000
#define CURLINFO_HTTP_CODE CURLINFO_RESPONSE_CODE
#define CURLINFO_LONG     0x200000
#define CURLINFO_MASK     0x0fffff
#define CURLINFO_OFF_T    0x600000
#define CURLINFO_PTR      0x400000 
#define CURLINFO_SLIST    0x400000
#define CURLINFO_SOCKET   0x500000
#define CURLINFO_STRING   0x100000
#define CURLINFO_TYPEMASK 0xf00000
#define CURLMIMEOPT_FORMESCAPE  (1<<0) 
#define CURLOPT(na,t,nu) na = t + nu
#define CURLOPTTYPE_BLOB          40000
#define CURLOPTTYPE_CBPOINT     CURLOPTTYPE_OBJECTPOINT
#define CURLOPTTYPE_FUNCTIONPOINT 20000
#define CURLOPTTYPE_LONG          0
#define CURLOPTTYPE_OBJECTPOINT   10000
#define CURLOPTTYPE_OFF_T         30000
#define CURLOPTTYPE_SLISTPOINT  CURLOPTTYPE_OBJECTPOINT
#define CURLOPTTYPE_STRINGPOINT CURLOPTTYPE_OBJECTPOINT
#define CURLOPTTYPE_VALUES      CURLOPTTYPE_LONG
#define CURLOPT_CLOSEPOLICY CURLOPT_OBSOLETE72
#define CURLOPT_ENCODING CURLOPT_ACCEPT_ENCODING
#define CURLOPT_FILE CURLOPT_WRITEDATA 
#define CURLOPT_FTPAPPEND CURLOPT_APPEND
#define CURLOPT_FTPLISTONLY CURLOPT_DIRLISTONLY
#define CURLOPT_FTP_SSL CURLOPT_USE_SSL
#define CURLOPT_INFILE CURLOPT_READDATA 
#define CURLOPT_KRB4LEVEL CURLOPT_KRBLEVEL
#define CURLOPT_POST301 CURLOPT_POSTREDIR
#define CURLOPT_PROGRESSDATA CURLOPT_XFERINFODATA
#define CURLOPT_RTSPHEADER CURLOPT_HTTPHEADER
#define CURLOPT_SERVER_RESPONSE_TIMEOUT CURLOPT_FTP_RESPONSE_TIMEOUT
#define CURLOPT_SSLCERTPASSWD CURLOPT_KEYPASSWD
#define CURLOPT_SSLKEYPASSWD CURLOPT_KEYPASSWD
#define CURLOPT_WRITEHEADER CURLOPT_HEADERDATA
#define CURLOPT_WRITEINFO CURLOPT_OBSOLETE40
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
#define CURLPROTO_GOPHERS (1<<29)
#define CURLPROTO_HTTP   (1<<0)
#define CURLPROTO_HTTPS  (1<<1)
#define CURLPROTO_IMAP   (1<<12)
#define CURLPROTO_IMAPS  (1<<13)
#define CURLPROTO_LDAP   (1<<7)
#define CURLPROTO_LDAPS  (1<<8)
#define CURLPROTO_MQTT   (1<<28)
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
#define CURLPROTO_SMB    (1<<26)
#define CURLPROTO_SMBS   (1<<27)
#define CURLPROTO_SMTP   (1<<16)
#define CURLPROTO_SMTPS  (1<<17)
#define CURLPROTO_TELNET (1<<6)
#define CURLPROTO_TFTP   (1<<11)
#define CURLSSH_AUTH_AGENT     (1<<4) 
#define CURLSSH_AUTH_ANY       ~0     
#define CURLSSH_AUTH_DEFAULT CURLSSH_AUTH_ANY
#define CURLSSH_AUTH_GSSAPI    (1<<5) 
#define CURLSSH_AUTH_HOST      (1<<2) 
#define CURLSSH_AUTH_KEYBOARD  (1<<3) 
#define CURLSSH_AUTH_NONE      0      
#define CURLSSH_AUTH_PASSWORD  (1<<1) 
#define CURLSSH_AUTH_PUBLICKEY (1<<0) 
#define CURLSSLBACKEND_BORINGSSL CURLSSLBACKEND_OPENSSL
#define CURLSSLBACKEND_CYASSL CURLSSLBACKEND_WOLFSSL
#define CURLSSLBACKEND_DARWINSSL CURLSSLBACKEND_SECURETRANSPORT
#define CURLSSLBACKEND_LIBRESSL CURLSSLBACKEND_OPENSSL
#define CURLSSLOPT_ALLOW_BEAST (1<<0)
#define CURLSSLOPT_AUTO_CLIENT_CERT (1<<5)
#define CURLSSLOPT_NATIVE_CA (1<<4)
#define CURLSSLOPT_NO_PARTIALCHAIN (1<<2)
#define CURLSSLOPT_NO_REVOKE (1<<1)
#define CURLSSLOPT_REVOKE_BEST_EFFORT (1<<3)
#define CURLVERSION_NOW CURLVERSION_TENTH
#define CURL_CHUNK_BGN_FUNC_FAIL    1 
#define CURL_CHUNK_BGN_FUNC_OK      0
#define CURL_CHUNK_BGN_FUNC_SKIP    2 
#define CURL_CHUNK_END_FUNC_FAIL    1 
#define CURL_CHUNK_END_FUNC_OK      0

#define CURL_ERROR_SIZE 256
#    define CURL_EXTERN  __declspec(dllexport)
#define CURL_FNMATCHFUNC_FAIL     2 
#define CURL_FNMATCHFUNC_MATCH    0 
#define CURL_FNMATCHFUNC_NOMATCH  1 
#define CURL_GLOBAL_ACK_EINTR (1<<2)
#define CURL_GLOBAL_ALL (CURL_GLOBAL_SSL|CURL_GLOBAL_WIN32)
#define CURL_GLOBAL_DEFAULT CURL_GLOBAL_ALL
#define CURL_GLOBAL_NOTHING 0
#define CURL_GLOBAL_SSL (1<<0) 
#define CURL_GLOBAL_WIN32 (1<<1)
#define CURL_HET_DEFAULT 200L
#define CURL_HTTPPOST_BUFFER (1<<4)
#define CURL_HTTPPOST_CALLBACK (1<<6)
#define CURL_HTTPPOST_FILENAME (1<<0)
#define CURL_HTTPPOST_LARGE (1<<7)
#define CURL_HTTPPOST_PTRBUFFER (1<<5)
#define CURL_HTTPPOST_PTRCONTENTS (1<<3)
#define CURL_HTTPPOST_PTRNAME (1<<2)
#define CURL_HTTPPOST_READFILE (1<<1)
#define CURL_HTTP_VERSION_2 CURL_HTTP_VERSION_2_0
#define CURL_IPRESOLVE_V4       1 
#define CURL_IPRESOLVE_V6       2 
#define CURL_IPRESOLVE_WHATEVER 0 
#define CURL_MAX_HTTP_HEADER (100*1024)
#define CURL_MAX_READ_SIZE 524288
#define CURL_MAX_WRITE_SIZE 16384
#define CURL_PREREQFUNC_ABORT 1
#define CURL_PREREQFUNC_OK 0
#define CURL_PROGRESSFUNC_CONTINUE 0x10000001
#define CURL_READFUNC_ABORT 0x10000000
#define CURL_READFUNC_PAUSE 0x10000001
#define CURL_REDIR_GET_ALL  0
#define CURL_REDIR_POST_301 1
#define CURL_REDIR_POST_302 2
#define CURL_REDIR_POST_303 4
#define CURL_REDIR_POST_ALL \
    (CURL_REDIR_POST_301|CURL_REDIR_POST_302|CURL_REDIR_POST_303)
#define CURL_SEEKFUNC_CANTSEEK 2 
#define CURL_SEEKFUNC_FAIL     1 
#define CURL_SEEKFUNC_OK       0
#define CURL_SOCKET_BAD INVALID_SOCKET
#define CURL_SOCKOPT_ALREADY_CONNECTED 2
#define CURL_SOCKOPT_ERROR 1 
#define CURL_SOCKOPT_OK 0

#define CURL_TRAILERFUNC_ABORT 1
#define CURL_TRAILERFUNC_OK 0
#define CURL_UPKEEP_INTERVAL_DEFAULT 60000L
#define CURL_VERSION_ALTSVC       (1<<24) 
#define CURL_VERSION_ASYNCHDNS    (1<<7)  
#define CURL_VERSION_BROTLI       (1<<23) 
#define CURL_VERSION_CONV         (1<<12) 
#define CURL_VERSION_CURLDEBUG    (1<<13) 
#define CURL_VERSION_DEBUG        (1<<6)  
#define CURL_VERSION_GSASL        (1<<29) 
#define CURL_VERSION_GSSAPI       (1<<17) 
#define CURL_VERSION_GSSNEGOTIATE (1<<5)  
#define CURL_VERSION_HSTS         (1<<28) 
#define CURL_VERSION_HTTP2        (1<<16) 
#define CURL_VERSION_HTTP3        (1<<25) 
#define CURL_VERSION_HTTPS_PROXY  (1<<21) 
#define CURL_VERSION_IDN          (1<<10) 
#define CURL_VERSION_IPV6         (1<<0)  
#define CURL_VERSION_KERBEROS4    (1<<1)  
#define CURL_VERSION_KERBEROS5    (1<<18) 
#define CURL_VERSION_LARGEFILE    (1<<9)  
#define CURL_VERSION_LIBZ         (1<<3)  
#define CURL_VERSION_MULTI_SSL    (1<<22) 
#define CURL_VERSION_NTLM         (1<<4)  
#define CURL_VERSION_NTLM_WB      (1<<15) 
#define CURL_VERSION_PSL          (1<<20) 
#define CURL_VERSION_SPNEGO       (1<<8)  
#define CURL_VERSION_SSL          (1<<2)  
#define CURL_VERSION_SSPI         (1<<11) 
#define CURL_VERSION_TLSAUTH_SRP  (1<<14) 
#define CURL_VERSION_UNICODE      (1<<27) 
#define CURL_VERSION_UNIX_SOCKETS (1<<19) 
#define CURL_VERSION_ZSTD         (1<<26) 

#define CURL_WRITEFUNC_PAUSE 0x10000001
#define CURL_ZERO_TERMINATED ((size_t) -1)
#  define __has_declspec_attribute(x) 0
#define curl_easy_getinfo(handle,info,arg) curl_easy_getinfo(handle,info,arg)
#define curl_easy_setopt(handle,opt,param) curl_easy_setopt(handle,opt,param)
#define curl_ftpssl curl_usessl
#define curl_multi_setopt(handle,opt,param) curl_multi_setopt(handle,opt,param)
#define curl_share_setopt(share,opt,param) curl_share_setopt(share,opt,param)

#define CURLMAX(x,y) ((x)>(y)?(x):(y))
#define CURLMIN(x,y) ((x)<(y)?(x):(y))
#  define CURLRES_ARES
#  define CURLRES_ASYNCH
#  define CURLRES_IPV4
#  define CURLRES_IPV6
#  define CURLRES_SYNCH
#  define CURLRES_THREADED
#    define CURL_DISABLE_DICT
#    define CURL_DISABLE_FILE
#    define CURL_DISABLE_FTP
#    define CURL_DISABLE_GOPHER
#    define CURL_DISABLE_IMAP
#      define CURL_DISABLE_LDAP 1
#    define CURL_DISABLE_LDAPS
#    define CURL_DISABLE_MQTT
#    define CURL_DISABLE_POP3
#    define CURL_DISABLE_RTSP
#    define CURL_DISABLE_SMB
#    define CURL_DISABLE_SMTP
#    define CURL_DISABLE_TELNET
#    define CURL_DISABLE_TFTP

#  define CURL_OFF_T_MAX CURL_OFF_T_C(0x7FFFFFFF)
#define CURL_OFF_T_MIN (-CURL_OFF_T_MAX - CURL_OFF_T_C(1))
#    define CURL_OSX_CALL_COPYPROXIES 1
#    define CURL_SA_FAMILY_T sa_family_t
#    define CURL_WINDOWS_APP
#  define Curl_nop_stmt do { } while(0)
#  define DIR_CHAR      "\\"

#define FOPEN_APPENDTEXT "at"
#define FOPEN_READTEXT "rt"
#define FOPEN_WRITETEXT "wt"
#    define GETHOSTNAME_TYPE_ARG2 int

#define LIBIDN_REQUIRED_VERSION "0.4.1"
#  define LSEEK_ERROR                (__int64)-1
#    define NOGDI
#define SHUT_RD 0x00
#define SHUT_RDWR 0x02
#define SHUT_WR 0x01
#      define SIZEOF_OFF_T 8
#define SIZEOF_TIME_T 4
#define SIZE_T_MAX 18446744073709551615U
#define SSIZE_T_MAX 9223372036854775807
#define STRCONST(x) x,sizeof(x)-1
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#  define TIME_T_MAX UINT_MAX
#  define TIME_T_MIN 0
#define UNITTEST static
#    define UNIX_PATH_MAX 108
#  define UNUSED_PARAM __attribute__((__unused__))
#    define USE_CURL_NTLM_CORE



#    define USE_NTLM
#    define USE_RECV_BEFORE_SEND_WORKAROUND
#define USE_RESOLVE_ON_IPS 1


#define USE_SSL    
#  define WARN_UNUSED_RESULT __attribute__((warn_unused_result))

#    define WIN32_LEAN_AND_MEAN
#    define WIN32_SOCKADDR_UN
#    define _POSIX_PTHREAD_SEMANTICS 1
#    define _REENTRANT
#    define _THREAD_SAFE
#  define __NO_NET_API
#    define access(fname,mode)         curlx_win32_access(fname, mode)
#    define fopen(fname,mode)          curlx_win32_fopen(fname, mode)
#    define fstat(fdes,stp)            _fstat(fdes, stp)
#    define ioctl(x,y,z) ioctlsocket(x,y,(char *)(z))
#    define lseek(fdes,offset,whence)  _lseek(fdes, (long)offset, whence)
#    define open                       curlx_win32_open
#    define select(a,b,c,d,e) WaitSelect(a,b,c,d,e,0)
#    define stat(fname,stp)            curlx_win32_stat(fname, stp)
#    define struct_stat                struct _stat
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
#define ESHUTDOWN        WSAESHUTDOWN
#define ESOCKTNOSUPPORT  WSAESOCKTNOSUPPORT
#define ESTALE           WSAESTALE
#define ETIMEDOUT        WSAETIMEDOUT
#define ETOOMANYREFS     WSAETOOMANYREFS
#define EUSERS           WSAEUSERS
#define EWOULDBLOCK      WSAEWOULDBLOCK
#define FALSE false
#  define HAVE_BOOL_T

#      define OLD_APP32_64BIT_OFF_T _APP32_64BIT_OFF_T
#define SEND_4TH_ARG MSG_NOSIGNAL
#define SET_SOCKERRNO(x)  (WSASetLastError((int)(x)))
#define SOCKERRNO         ((int)WSAGetLastError())
#define TOLOWER(x)  (tolower((int)  ((unsigned char)x)))
#define TRUE true
#define ZERO_NULL 0
#      define _APP32_64BIT_OFF_T OLD_APP32_64BIT_OFF_T
#define argv_item_t  __char_ptr32
#  define false 0
#  define sclose(x)  closesocket((x))
#  define sfcntl  lwip_fcntl
#define sread(x,y,z) (ssize_t)read((RECV_TYPE_ARG1)(x), \
                                   (RECV_TYPE_ARG2)(y), \
                                   (RECV_TYPE_ARG3)(z))
#define swrite(x,y,z) (ssize_t)write((SEND_TYPE_ARG1)(x), \
                                    (SEND_TYPE_ARG2)(y), \
                                    (SEND_TYPE_ARG3)(z))
#  define true 1

#define ISALNUM(x)  (Curl_isalnum((int)  ((unsigned char)x)))
#define ISALPHA(x)  (Curl_isalpha((int)  ((unsigned char)x)))
#define ISASCII(x)  (((x) >= 0) && ((x) <= 0x80))
#define ISBLANK(x)  (int)((((unsigned char)x) == ' ') ||        \
                          (((unsigned char)x) == '\t'))
#define ISCNTRL(x)  (Curl_iscntrl((int)  ((unsigned char)x)))
#define ISDIGIT(x)  (Curl_isdigit((int)  ((unsigned char)x)))
#define ISGRAPH(x)  (Curl_isgraph((int)  ((unsigned char)x)))
#define ISLOWER(x)  (Curl_islower((int)  ((unsigned char)x)))
#define ISPRINT(x)  (Curl_isprint((int)  ((unsigned char)x)))
#define ISSPACE(x)  (Curl_isspace((int)  ((unsigned char)x)))
#define ISUPPER(x)  (Curl_isupper((int)  ((unsigned char)x)))
#define ISXDIGIT(x) (Curl_isxdigit((int) ((unsigned char)x)))

