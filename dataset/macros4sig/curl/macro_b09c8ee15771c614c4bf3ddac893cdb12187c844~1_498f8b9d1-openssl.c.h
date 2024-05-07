
#include<sys/socket.h>








#include<unistd.h>

#include<string.h>
#include<stdarg.h>

#include<iconv.h>
#include<assert.h>



#include<stdbool.h>



#include<poll.h>














#include<errno.h>




#include<ctype.h>




#include<sys/poll.h>








#include<time.h>
#include<netinet/in.h>




#include<sys/select.h>
#include<memory.h>
#include<stdlib.h>
#include<stddef.h>

#include<setjmp.h>

#include<stdio.h>




#include<fcntl.h>

#include<sys/stat.h>
#include<malloc.h>


#include<arpa/inet.h>

#include<limits.h>






#include<sys/types.h>


#include<sys/time.h>
#define CURL_MT_LOGFNAME_BUFSIZE 512
#define Curl_safefree(ptr) \
  do { free((ptr)); (ptr) = NULL;} while(0)

#    define _tcsdup(ptr) curl_dbg_wcsdup(ptr, "__LINE__", "__FILE__")
#    define _wcsdup(ptr) curl_dbg_wcsdup(ptr, "__LINE__", "__FILE__")
#define accept(sock,addr,len)\
 curl_dbg_accept(sock, addr, len, "__LINE__", "__FILE__")
#define calloc(nbelem,size) curl_dbg_calloc(nbelem, size, "__LINE__", "__FILE__")
#define fake_sclose(sockfd) curl_dbg_mark_sclose(sockfd,"__LINE__","__FILE__")
#define fclose(file) curl_dbg_fclose(file,"__LINE__","__FILE__")
#define fdopen(file,mode) curl_dbg_fdopen(file,mode,"__LINE__","__FILE__")
#define fopen(file,mode) curl_dbg_fopen(file,mode,"__LINE__","__FILE__")
#define free(ptr) curl_dbg_free(ptr, "__LINE__", "__FILE__")
#define freeaddrinfo(data) \
  curl_dbg_freeaddrinfo(data, "__LINE__", "__FILE__")
#define getaddrinfo(host,serv,hint,res) \
  curl_dbg_getaddrinfo(host, serv, hint, res, "__LINE__", "__FILE__")
#define malloc(size) curl_dbg_malloc(size, "__LINE__", "__FILE__")
#define ogetaddrinfo(host,serv,hint,res) \
  curl_dbg_getaddrinfo(host, serv, hint, res, "__LINE__", "__FILE__")
#define realloc(ptr,size) curl_dbg_realloc(ptr, size, "__LINE__", "__FILE__")
#define recv(a,b,c,d) curl_dbg_recv(a,b,c,d, "__LINE__", "__FILE__")
#define sclose(sockfd) curl_dbg_sclose(sockfd,"__LINE__","__FILE__")
#define send(a,b,c,d) curl_dbg_send(a,b,c,d, "__LINE__", "__FILE__")
#define socket(domain,type,protocol)\
 curl_dbg_socket(domain, type, protocol, "__LINE__", "__FILE__")
#define socketpair(domain,type,protocol,socket_vector)\
 curl_dbg_socketpair(domain, type, protocol, socket_vector, "__LINE__", "__FILE__")
#define strdup(ptr) curl_dbg_strdup(ptr, "__LINE__", "__FILE__")
#    define wcsdup(ptr) curl_dbg_wcsdup(ptr, "__LINE__", "__FILE__")



#define Curl_convert_clone(a,b,c,d) ((void)a, CURLE_OK)
#define Curl_convert_close(x) Curl_nop_stmt
#define Curl_convert_from_network(a,b,c) ((void)a, CURLE_OK)
#define Curl_convert_from_utf8(a,b,c) ((void)a, CURLE_OK)
#define Curl_convert_init(x) Curl_nop_stmt
#define Curl_convert_setup(x) Curl_nop_stmt
#define Curl_convert_to_network(a,b,c) ((void)a, CURLE_OK)

#define BIT(x) bool x
#define CONNCHECK_ISDEAD (1<<0)          
#define CONNCHECK_KEEPALIVE (1<<1)       
#define CONNCHECK_NONE 0                 
#define CONNRESULT_DEAD (1<<0)           
#define CONNRESULT_NONE 0                
#define CONN_INUSE(c) ((c)->easyq.size)
#define CURLEASY_MAGIC_NUMBER 0xc0dedbadU
#define CURL_DEFAULT_PASSWORD "ftp@example.com"
#define CURL_DEFAULT_USER "anonymous"

#define CURL_MAX_INPUT_LENGTH 8000000
#define CURR_TIME (5 + 1) 
#define DEFAULT_CONNCACHE_SIZE 5
#define DICT_DEFINE "/DEFINE:"
#define DICT_DEFINE2 "/D:"
#define DICT_DEFINE3 "/LOOKUP:"
#define DICT_MATCH "/MATCH:"
#define DICT_MATCH2 "/M:"
#define DICT_MATCH3 "/FIND:"
#define FIRSTSOCKET     0
#define GOOD_EASY_HANDLE(x) \
  ((x) && ((x)->magic == CURLEASY_MAGIC_NUMBER))

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
#define MAX_IPADR_LEN sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255")
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
#define PORT_MQTT 1883
#define PORT_POP3 110
#define PORT_POP3S 995
#define PORT_RTMP 1935
#define PORT_RTMPS PORT_HTTPS
#define PORT_RTMPT PORT_HTTP
#define PORT_RTSP 554
#define PORT_SMB 445
#define PORT_SMBS 445
#define PORT_SMTP 25
#define PORT_SMTPS 465 
#define PORT_SSH 22
#define PORT_TELNET 23
#define PORT_TFTP 69
#define PROTOPT_ALPN_NPN (1<<8) 
#define PROTOPT_CLOSEACTION (1<<2) 
#define PROTOPT_CREDSPERREQUEST (1<<7) 
#define PROTOPT_DIRLOCK (1<<3)
#define PROTOPT_DUAL (1<<1)        
#define PROTOPT_NEEDSPWD (1<<5)    
#define PROTOPT_NONE 0             
#define PROTOPT_NONETWORK (1<<4)   
#define PROTOPT_NOURLQUERY (1<<6)   
#define PROTOPT_PROXY_AS_HTTP (1<<11) 
#define PROTOPT_SSL (1<<0)         
#define PROTOPT_STREAM (1<<9) 
#define PROTOPT_URLOPTIONS (1<<10) 
#define PROTOPT_USERPWDCTRL (1<<13) 
#define PROTOPT_WILDCARD (1<<12) 
#define PROTO_FAMILY_FTP  (CURLPROTO_FTP|CURLPROTO_FTPS)
#define PROTO_FAMILY_HTTP (CURLPROTO_HTTP|CURLPROTO_HTTPS)
#define PROTO_FAMILY_POP3 (CURLPROTO_POP3|CURLPROTO_POP3S)
#define PROTO_FAMILY_SMB  (CURLPROTO_SMB|CURLPROTO_SMBS)
#define PROTO_FAMILY_SMTP (CURLPROTO_SMTP|CURLPROTO_SMTPS)
#define PROTO_FAMILY_SSH  (CURLPROTO_SCP|CURLPROTO_SFTP)
#define READBUFFER_MAX  CURL_MAX_READ_SIZE
#define READBUFFER_MIN  1024
#define READBUFFER_SIZE CURL_MAX_WRITE_SIZE
#define RESP_TIMEOUT (120*1000)
#define SECONDARYSOCKET 1
#define SOCKS_STATE(x) (((x) >= CONNECT_SOCKS_INIT) &&  \
                        ((x) < CONNECT_DONE))
#define UPLOADBUFFER_DEFAULT 65536
#define UPLOADBUFFER_MAX (2*1024*1024)
#define UPLOADBUFFER_MIN CURL_MAX_WRITE_SIZE

# define CRYPT_E_REVOKED                      ((HRESULT)0x80092010L)

#define ISC_REQ_USE_HTTP_STYLE                0x01000000
#define ISC_RET_ALLOCATED_MEMORY              0x00000100
#define ISC_RET_CONFIDENTIALITY               0x00000010
#define ISC_RET_REPLAY_DETECT                 0x00000004
#define ISC_RET_SEQUENCE_DETECT               0x00000008
#define ISC_RET_STREAM                        0x00008000
#define KERB_WRAP_NO_ENCRYPT 0x80000001
#  define SECFLAG_WINNT_AUTH_IDENTITY \
     (unsigned long)SEC_WINNT_AUTH_IDENTITY_UNICODE
#define SECURITY_WIN32 1
# define SEC_E_ALGORITHM_MISMATCH             ((HRESULT)0x80090331L)
# define SEC_E_BAD_BINDINGS                   ((HRESULT)0x80090346L)
# define SEC_E_BAD_PKGID                      ((HRESULT)0x80090316L)
# define SEC_E_BUFFER_TOO_SMALL               ((HRESULT)0x80090321L)
# define SEC_E_CANNOT_INSTALL                 ((HRESULT)0x80090307L)
# define SEC_E_CANNOT_PACK                    ((HRESULT)0x80090309L)
# define SEC_E_CERT_EXPIRED                   ((HRESULT)0x80090328L)
# define SEC_E_CERT_UNKNOWN                   ((HRESULT)0x80090327L)
# define SEC_E_CERT_WRONG_USAGE               ((HRESULT)0x80090349L)
# define SEC_E_CONTEXT_EXPIRED                ((HRESULT)0x80090317L)
# define SEC_E_CROSSREALM_DELEGATION_FAILURE  ((HRESULT)0x80090357L)
# define SEC_E_CRYPTO_SYSTEM_INVALID          ((HRESULT)0x80090337L)
# define SEC_E_DECRYPT_FAILURE                ((HRESULT)0x80090330L)
# define SEC_E_DELEGATION_POLICY              ((HRESULT)0x8009035EL)
# define SEC_E_DELEGATION_REQUIRED            ((HRESULT)0x80090345L)
# define SEC_E_DOWNGRADE_DETECTED             ((HRESULT)0x80090350L)
# define SEC_E_ENCRYPT_FAILURE                ((HRESULT)0x80090329L)
# define SEC_E_ILLEGAL_MESSAGE                ((HRESULT)0x80090326L)
# define SEC_E_INCOMPLETE_CREDENTIALS         ((HRESULT)0x80090320L)
# define SEC_E_INCOMPLETE_MESSAGE             ((HRESULT)0x80090318L)
# define SEC_E_INSUFFICIENT_MEMORY            ((HRESULT)0x80090300L)
# define SEC_E_INTERNAL_ERROR                 ((HRESULT)0x80090304L)
# define SEC_E_INVALID_HANDLE                 ((HRESULT)0x80090301L)
# define SEC_E_INVALID_PARAMETER              ((HRESULT)0x8009035DL)
# define SEC_E_INVALID_TOKEN                  ((HRESULT)0x80090308L)
# define SEC_E_ISSUING_CA_UNTRUSTED           ((HRESULT)0x80090352L)
# define SEC_E_ISSUING_CA_UNTRUSTED_KDC       ((HRESULT)0x80090359L)
# define SEC_E_KDC_CERT_EXPIRED               ((HRESULT)0x8009035AL)
# define SEC_E_KDC_CERT_REVOKED               ((HRESULT)0x8009035BL)
# define SEC_E_KDC_INVALID_REQUEST            ((HRESULT)0x80090340L)
# define SEC_E_KDC_UNABLE_TO_REFER            ((HRESULT)0x80090341L)
# define SEC_E_KDC_UNKNOWN_ETYPE              ((HRESULT)0x80090342L)
# define SEC_E_LOGON_DENIED                   ((HRESULT)0x8009030CL)
# define SEC_E_MAX_REFERRALS_EXCEEDED         ((HRESULT)0x80090338L)
# define SEC_E_MESSAGE_ALTERED                ((HRESULT)0x8009030FL)
# define SEC_E_MULTIPLE_ACCOUNTS              ((HRESULT)0x80090347L)
# define SEC_E_MUST_BE_KDC                    ((HRESULT)0x80090339L)
# define SEC_E_NOT_OWNER                      ((HRESULT)0x80090306L)
# define SEC_E_NO_AUTHENTICATING_AUTHORITY    ((HRESULT)0x80090311L)
# define SEC_E_NO_CREDENTIALS                 ((HRESULT)0x8009030EL)
# define SEC_E_NO_IMPERSONATION               ((HRESULT)0x8009030BL)
# define SEC_E_NO_IP_ADDRESSES                ((HRESULT)0x80090335L)
# define SEC_E_NO_KERB_KEY                    ((HRESULT)0x80090348L)
# define SEC_E_NO_PA_DATA                     ((HRESULT)0x8009033CL)
# define SEC_E_NO_S4U_PROT_SUPPORT            ((HRESULT)0x80090356L)
# define SEC_E_NO_TGT_REPLY                   ((HRESULT)0x80090334L)
# define SEC_E_OUT_OF_SEQUENCE                ((HRESULT)0x80090310L)
# define SEC_E_PKINIT_CLIENT_FAILURE          ((HRESULT)0x80090354L)
# define SEC_E_PKINIT_NAME_MISMATCH           ((HRESULT)0x8009033DL)
# define SEC_E_POLICY_NLTM_ONLY               ((HRESULT)0x8009035FL)
# define SEC_E_QOP_NOT_SUPPORTED              ((HRESULT)0x8009030AL)
# define SEC_E_REVOCATION_OFFLINE_C           ((HRESULT)0x80090353L)
# define SEC_E_REVOCATION_OFFLINE_KDC         ((HRESULT)0x80090358L)
# define SEC_E_SECPKG_NOT_FOUND               ((HRESULT)0x80090305L)
# define SEC_E_SECURITY_QOS_FAILED            ((HRESULT)0x80090332L)
# define SEC_E_SHUTDOWN_IN_PROGRESS           ((HRESULT)0x8009033FL)
# define SEC_E_SMARTCARD_CERT_EXPIRED         ((HRESULT)0x80090355L)
# define SEC_E_SMARTCARD_CERT_REVOKED         ((HRESULT)0x80090351L)
# define SEC_E_SMARTCARD_LOGON_REQUIRED       ((HRESULT)0x8009033EL)
# define SEC_E_STRONG_CRYPTO_NOT_SUPPORTED    ((HRESULT)0x8009033AL)
# define SEC_E_TARGET_UNKNOWN                 ((HRESULT)0x80090303L)
# define SEC_E_TIME_SKEW                      ((HRESULT)0x80090324L)
# define SEC_E_TOO_MANY_PRINCIPALS            ((HRESULT)0x8009033BL)
# define SEC_E_UNFINISHED_CONTEXT_DELETED     ((HRESULT)0x80090333L)
# define SEC_E_UNKNOWN_CREDENTIALS            ((HRESULT)0x8009030DL)
# define SEC_E_UNSUPPORTED_FUNCTION           ((HRESULT)0x80090302L)
# define SEC_E_UNSUPPORTED_PREAUTH            ((HRESULT)0x80090343L)
# define SEC_E_UNTRUSTED_ROOT                 ((HRESULT)0x80090325L)
# define SEC_E_WRONG_CREDENTIAL_HANDLE        ((HRESULT)0x80090336L)
# define SEC_E_WRONG_PRINCIPAL                ((HRESULT)0x80090322L)
# define SEC_I_COMPLETE_AND_CONTINUE          ((HRESULT)0x00090314L)
# define SEC_I_COMPLETE_NEEDED                ((HRESULT)0x00090313L)
# define SEC_I_CONTEXT_EXPIRED                ((HRESULT)0x00090317L)
# define SEC_I_CONTINUE_NEEDED                ((HRESULT)0x00090312L)
# define SEC_I_INCOMPLETE_CREDENTIALS         ((HRESULT)0x00090320L)
# define SEC_I_LOCAL_LOGON                    ((HRESULT)0x00090315L)
# define SEC_I_NO_LSA_CONTEXT                 ((HRESULT)0x00090323L)
# define SEC_I_RENEGOTIATE                    ((HRESULT)0x00090321L)
# define SEC_I_SIGNATURE_NEEDED               ((HRESULT)0x0009035CL)
#define SP_NAME_DIGEST              "WDigest"
#define SP_NAME_KERBEROS            "Kerberos"
#define SP_NAME_NEGOTIATE           "Negotiate"
#define SP_NAME_NTLM                "NTLM"
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
#define CURLSSLOPT_NATIVE_CA (1<<4)
#define CURLSSLOPT_NO_PARTIALCHAIN (1<<2)
#define CURLSSLOPT_NO_REVOKE (1<<1)
#define CURLSSLOPT_REVOKE_BEST_EFFORT (1<<3)
#define CURLVERSION_NOW CURLVERSION_NINTH
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
#    define CURL_DISABLE_POP3
#    define CURL_DISABLE_RTSP
#    define CURL_DISABLE_SMB
#    define CURL_DISABLE_SMTP
#    define CURL_DISABLE_TELNET
#    define CURL_DISABLE_TFTP

#  define CURL_OFF_T_MAX CURL_OFF_T_C(0x7FFFFFFF)
#define CURL_OFF_T_MIN (-CURL_OFF_T_MAX - CURL_OFF_T_C(1))
#define CURL_SA_FAMILY_T unsigned short
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
#  define SHUT_RD   0x00
#  define SHUT_RDWR 0x02
#  define SHUT_WR   0x01
#      define SIZEOF_OFF_T 8
#define SIZEOF_TIME_T 4
#define SIZE_T_MAX 18446744073709551615U
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#  define TIME_T_MAX UINT_MAX
#  define TIME_T_MIN 0
#define UNITTEST static
#  define UNUSED_PARAM __attribute__((__unused__))




#    define USE_RECV_BEFORE_SEND_WORKAROUND
#define USE_RESOLVE_ON_IPS 1


#define USE_SSL    
#  define WARN_UNUSED_RESULT __attribute__((warn_unused_result))

#    define WIN32_LEAN_AND_MEAN
#    define _POSIX_PTHREAD_SEMANTICS 1
#    define _REENTRANT
#    define _THREAD_SAFE
#  define __NO_NET_API
#    define access(fname,mode)         curlx_win32_access(fname, mode)
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
#define RETSIGTYPE void
#define SEND_4TH_ARG MSG_NOSIGNAL
#define SET_SOCKERRNO(x)  (WSASetLastError((int)(x)))
#define SIG_ATOMIC_T static sig_atomic_t
#define SOCKERRNO         ((int)WSAGetLastError())
#define TOLOWER(x)  (tolower((int)  ((unsigned char)x)))
#define TRUE true
#define ZERO_NULL 0
#      define _APP32_64BIT_OFF_T OLD_APP32_64BIT_OFF_T
#define argv_item_t  __char_ptr32
#  define false 0
#  define sfcntl  lwip_fcntl
#define sread(x,y,z) (ssize_t)read((RECV_TYPE_ARG1)(x), \
                                   (RECV_TYPE_ARG2)(y), \
                                   (RECV_TYPE_ARG3)(z))
#define swrite(x,y,z) (ssize_t)write((SEND_TYPE_ARG1)(x), \
                                    (SEND_TYPE_ARG2)(y), \
                                    (SEND_TYPE_ARG3)(z))
#  define true 1

#define ISALNUM(x)  (isalnum((int)  ((unsigned char)x)))
#define ISALPHA(x)  (isalpha((int)  ((unsigned char)x)))
#define ISASCII(x)  (isascii((int)  ((unsigned char)x)))
#define ISBLANK(x)  (int)((((unsigned char)x) == ' ') ||        \
                          (((unsigned char)x) == '\t'))
#define ISCNTRL(x)  (iscntrl((int)  ((unsigned char)x)))
#define ISDIGIT(x)  (isdigit((int)  ((unsigned char)x)))
#define ISGRAPH(x)  (isgraph((int)  ((unsigned char)x)))
#define ISLOWER(x)  (islower((int)  ((unsigned char)x)))
#define ISPRINT(x)  (isprint((int)  ((unsigned char)x)))
#define ISSPACE(x)  (isspace((int)  ((unsigned char)x)))
#define ISUPPER(x)  (isupper((int)  ((unsigned char)x)))
#define ISXDIGIT(x) (isxdigit((int) ((unsigned char)x)))










#define CURLPIPE_ANY (CURLPIPE_MULTIPLEX)

#define GETSOCK_READABLE (0x00ff)
#define GETSOCK_WRITABLE (0xff00)

#define INITIAL_MAX_CONCURRENT_STREAMS ((1U << 31) - 1)
#define MAX_SOCKSPEREASYHANDLE 5
#define Curl_socketpair(a,b,c,d) socketpair(a,b,c,d)



#define Curl_psl_use(easy) NULL

#define PSL_TTL (72 * 3600)     
#define BUNDLE_MULTIPLEX   2
#define BUNDLE_NO_MULTIUSE -1
#define BUNDLE_UNKNOWN     0  
#define CONNCACHE_LOCK(x)                                               \
  do {                                                                  \
    if((x)->share) {                                                    \
      Curl_share_lock((x), CURL_LOCK_DATA_CONNECT,                      \
                      CURL_LOCK_ACCESS_SINGLE);                         \
      DEBUGASSERT(!(x)->state.conncache_lock);                          \
      (x)->state.conncache_lock = TRUE;                                 \
    }                                                                   \
  } while(0)
#define CONNCACHE_UNLOCK(x)                                             \
  do {                                                                  \
    if((x)->share) {                                                    \
      DEBUGASSERT((x)->state.conncache_lock);                           \
      (x)->state.conncache_lock = FALSE;                                \
      Curl_share_unlock((x), CURL_LOCK_DATA_CONNECT);                   \
    }                                                                   \
  } while(0)

#define CURL_FORMAT_TIMEDIFF_T CURL_FORMAT_CURL_OFF_T

#define TIMEDIFF_T_MAX CURL_OFF_T_MAX
#define TIMEDIFF_T_MIN CURL_OFF_T_MIN
#define Curl_hash_count(h) ((h)->size)






#  define PACK __attribute__((packed))
#define SMB_CAP_LARGE_FILES           0x08
#define SMB_COM_CLOSE                 0x04
#define SMB_COM_NEGOTIATE             0x72
#define SMB_COM_NO_ANDX_COMMAND       0xff
#define SMB_COM_NT_CREATE_ANDX        0xa2
#define SMB_COM_READ_ANDX             0x2e
#define SMB_COM_SETUP_ANDX            0x73
#define SMB_COM_TREE_CONNECT_ANDX     0x75
#define SMB_COM_TREE_DISCONNECT       0x71
#define SMB_COM_WRITE_ANDX            0x2f
#define SMB_ERR_NOACCESS              0x00050001
#define SMB_FILE_OPEN                 0x01
#define SMB_FILE_OVERWRITE_IF         0x05
#define SMB_FILE_SHARE_ALL            0x07
#define SMB_FLAGS2_IS_LONG_NAME       0x0040
#define SMB_FLAGS2_KNOWS_LONG_NAME    0x0001
#define SMB_FLAGS2_UNICODE_STRINGS    0x8000
#define SMB_FLAGS_CANONICAL_PATHNAMES 0x10
#define SMB_FLAGS_CASELESS_PATHNAMES  0x08
#define SMB_GENERIC_READ              0x80000000
#define SMB_GENERIC_WRITE             0x40000000
#define SMB_WC_CLOSE                  0x03
#define SMB_WC_NT_CREATE_ANDX         0x18
#define SMB_WC_READ_ANDX              0x0c
#define SMB_WC_SETUP_ANDX             0x0d
#define SMB_WC_TREE_CONNECT_ANDX      0x04
#define SMB_WC_WRITE_ANDX             0x0e

#define Curl_rtsp_parseheader(x,y) CURLE_NOT_BUILT_IN

#define CURLAUTH_PICKNONE (1<<30) 
#define Curl_buffer_send(a,b,c,d,e) CURLE_OK
#define Curl_http_cookies(a,b,c) CURLE_OK
#define EXPECT_100_THRESHOLD (1024*1024)
#define H2_BINSETTINGS_LEN 80

#define MAX_INITIAL_POST_SIZE (64*1024)
#define CURL_LIBSSH2_VERSION libssh2_version(0)
#define CURL_LIBSSH_VERSION ssh_version(0)

#define HAVE_LIBSSH2_EXIT 1
#define HAVE_LIBSSH2_INIT 1
#define HAVE_LIBSSH2_KNOWNHOST_CHECKP 1
#define HAVE_LIBSSH2_SCP_SEND64 1
#define HAVE_LIBSSH2_SESSION_HANDSHAKE 1
#define HAVE_LIBSSH2_SFTP_SEEK64 1
#define HAVE_LIBSSH2_VERSION 1


#define DEFAULT_ACCEPT_TIMEOUT   60000 


#define PINGPONG_SETUP(pp,s,e)                   \
  do {                                           \
    pp->response_time = RESP_TIMEOUT;            \
    pp->statemachine = s;                        \
    pp->endofresp = e;                           \
  } while(0)


#define SMTP_EOB "\x0d\x0a\x2e\x0d\x0a"
#define SMTP_EOB_FIND_LEN 3
#define SMTP_EOB_LEN 5
#define SMTP_EOB_REPL "\x0d\x0a\x2e\x2e"
#define SMTP_EOB_REPL_LEN 4

#define SASL_AUTH_ANY           ~0U
#define SASL_AUTH_DEFAULT       (SASL_AUTH_ANY & ~SASL_MECH_EXTERNAL)
#define SASL_AUTH_NONE          0
#define SASL_MECH_CRAM_MD5          (1 << 2)
#define SASL_MECH_DIGEST_MD5        (1 << 3)
#define SASL_MECH_EXTERNAL          (1 << 5)
#define SASL_MECH_GSSAPI            (1 << 4)
#define SASL_MECH_LOGIN             (1 << 0)
#define SASL_MECH_NTLM              (1 << 6)
#define SASL_MECH_OAUTHBEARER       (1 << 8)
#define SASL_MECH_PLAIN             (1 << 1)
#define SASL_MECH_SCRAM_SHA_1       (1 << 9)
#define SASL_MECH_SCRAM_SHA_256     (1 << 10)
#define SASL_MECH_STRING_CRAM_MD5     "CRAM-MD5"
#define SASL_MECH_STRING_DIGEST_MD5   "DIGEST-MD5"
#define SASL_MECH_STRING_EXTERNAL     "EXTERNAL"
#define SASL_MECH_STRING_GSSAPI       "GSSAPI"
#define SASL_MECH_STRING_LOGIN        "LOGIN"
#define SASL_MECH_STRING_NTLM         "NTLM"
#define SASL_MECH_STRING_OAUTHBEARER  "OAUTHBEARER"
#define SASL_MECH_STRING_PLAIN        "PLAIN"
#define SASL_MECH_STRING_SCRAM_SHA_1  "SCRAM-SHA-1"
#define SASL_MECH_STRING_SCRAM_SHA_256 "SCRAM-SHA-256"
#define SASL_MECH_STRING_XOAUTH2      "XOAUTH2"
#define SASL_MECH_XOAUTH2           (1 << 7)
#define sasl_mech_equal(line, wordlen, mech) \
  (wordlen == (sizeof(mech) - 1) / sizeof(char) && \
   !memcmp(line, mech, wordlen))

#define POP3_EOB "\x0d\x0a\x2e\x0d\x0a"
#define POP3_EOB_LEN 5
#define POP3_TYPE_ANY       ~0U
#define POP3_TYPE_APOP      (1 << 1)
#define POP3_TYPE_CLEARTEXT (1 << 0)
#define POP3_TYPE_NONE      0
#define POP3_TYPE_SASL      (1 << 2)

#define IMAP_TYPE_ANY       ~0U
#define IMAP_TYPE_CLEARTEXT (1 << 0)
#define IMAP_TYPE_NONE      0
#define IMAP_TYPE_SASL      (1 << 1)

#define Curl_mime_duppart(x,y) CURLE_OK 

#define Curl_mime_prepare_headers(a,b,c,d) CURLE_NOT_BUILT_IN
#define Curl_mime_read NULL
#define Curl_mime_rewind(x) ((void)x, CURLE_NOT_BUILT_IN)
#define Curl_mime_set_subparts(a,b,c) CURLE_NOT_BUILT_IN
#define Curl_mime_size(x) (curl_off_t) -1

#define DISPOSITION_DEFAULT             "attachment"
#define ENCODING_BUFFER_SIZE            256 
#define FILE_CONTENTTYPE_DEFAULT        "application/octet-stream"

#define MAX_ENCODED_LINE_LENGTH         76  
#define MIME_BODY_ONLY          (1 << 1)
#define MIME_BOUNDARY_LEN (24 + MIME_RAND_BOUNDARY_CHARS + 1)
#define MIME_FAST_READ          (1 << 2)
#define MIME_RAND_BOUNDARY_CHARS        16  
#define MIME_USERHEADERS_OWNER  (1 << 0)
#define MULTIPART_CONTENTTYPE_DEFAULT   "multipart/mixed"
#define Curl_dyn_add(a,b) curlx_dyn_add(a,b)
#define Curl_dyn_addf curlx_dyn_addf
#define Curl_dyn_addn(a,b,c) curlx_dyn_addn(a,b,c)
#define Curl_dyn_free(a) curlx_dyn_free(a)
#define Curl_dyn_init(a,b) curlx_dyn_init(a,b)
#define Curl_dyn_len(a) curlx_dyn_len(a)
#define Curl_dyn_ptr(a) curlx_dyn_ptr(a)
#define Curl_dyn_reset(a) curlx_dyn_reset(a)
#define Curl_dyn_tail(a,b) curlx_dyn_tail(a,b)
#define Curl_dyn_uptr(a) curlx_dyn_uptr(a)
#define Curl_dyn_vaddf curlx_dyn_vaddf
#define DYN_APRINTF         8000000
#define DYN_DOH_CNAME       256
#define DYN_DOH_RESPONSE    3000
#define DYN_H1_TRAILER      4096
#define DYN_H2_HEADERS      (128*1024)
#define DYN_H2_TRAILERS     (128*1024)
#define DYN_HAXPROXY        2048
#define DYN_HTTP_REQUEST    (1024*1024)
#define DYN_IMAP_CMD        (64*1024)
#define DYN_PAUSE_BUFFER    (64 * 1024 * 1024)
#define DYN_PINGPPONG_CMD   (64*1024)
#define DYN_PROXY_CONNECT_HEADERS 16384
#define DYN_QLOG_NAME       1024
#define DYN_RTSP_REQ_HEADER (64*1024)
#define DYN_TRAILERS        (64*1024)

#define curlx_dynbuf dynbuf 
#define Curl_splaycomparekeys(i,j) ( ((i.tv_sec)  < (j.tv_sec)) ? -1 : \
                                   ( ((i.tv_sec)  > (j.tv_sec)) ?  1 : \
                                   ( ((i.tv_usec) < (j.tv_usec)) ? -1 : \
                                   ( ((i.tv_usec) > (j.tv_usec)) ?  1 : 0))))

#define CURL_ASYNC_SUCCESS CURLE_OK
#define CURL_HOSTENT_SIZE 9000
#define CURL_INADDR_NONE (in_addr_t) ~0
#define CURL_TIMEOUT_RESOLVE 300 
#define Curl_ipv6works(x) FALSE

#define in_addr_t unsigned long
#define Curl_resolver_asynch() 1
#define Curl_resolver_cancel(x) Curl_nop_stmt
#define Curl_resolver_cleanup(x) Curl_nop_stmt
#define Curl_resolver_duphandle(x,y,z) CURLE_OK
#define Curl_resolver_global_cleanup() Curl_nop_stmt
#define Curl_resolver_global_init() CURLE_OK
#define Curl_resolver_init(x,y) CURLE_OK
#define Curl_resolver_is_resolved(x,y) CURLE_COULDNT_RESOLVE_HOST
#define Curl_resolver_kill(x) Curl_nop_stmt
#define Curl_resolver_wait_resolv(x,y) CURLE_COULDNT_RESOLVE_HOST



#define CHUNK_MAXNUM_LEN (SIZEOF_CURL_OFF_T * 2)

#define Curl_getformdata(a,b,c,d) CURLE_NOT_BUILT_IN

#define COOKIE_HASH_SIZE 256
#define COOKIE_PREFIX__HOST (1<<1)
#define COOKIE_PREFIX__SECURE (1<<0)
#define Curl_cookie_cleanup(x) Curl_nop_stmt
#define Curl_cookie_init(x,y,z,w) NULL
#define Curl_cookie_list(x) NULL
#define Curl_cookie_loadfiles(x) Curl_nop_stmt
#define Curl_flush_cookies(x,y) Curl_nop_stmt

#define MAX_COOKIE_LINE 5000
#define MAX_NAME 4096
#define MAX_NAME_TXT "4095"
#define CURLX_FUNCTION_CAST(target_type, func) \
  (target_type)(void (*) (void))(func)

#  define read(fd, buf, count)  curlx_read(fd, buf, count)
#  define write(fd, buf, count) curlx_write(fd, buf, count)
#define Curl_amiga_cleanup() Curl_nop_stmt
#define Curl_amiga_init() 1


# define aprintf curl_maprintf
# define fprintf curl_mfprintf
# define msnprintf curl_msnprintf
# define mvsnprintf curl_mvsnprintf
# define printf curl_mprintf
# define vaprintf curl_mvaprintf
# define vfprintf curl_mvfprintf
# define vprintf curl_mvprintf


#define STRERROR_LEN 256 
#define GETSOCK_BLANK 0 
#define GETSOCK_READSOCK(x) (1 << (x))
#define GETSOCK_WRITEBITSTART 16
#define GETSOCK_WRITESOCK(x) (1 << (GETSOCK_WRITEBITSTART + (x)))

#define CURL_HOST_MATCH   1
#define CURL_HOST_NOMATCH 0


#define checkprefix(a,b)    curl_strnequal(a,b,strlen(a))
#define strcasecompare(a,b) Curl_strcasecompare(a,b)
#define strncasecompare(a,b,c) Curl_strncasecompare(a,b,c)

#define ALPN_HTTP_1_1 "http/1.1"
#define ALPN_HTTP_1_1_LENGTH 8
#define CURL_SHA256_DIGEST_LENGTH 32 
#define Curl_ssl_cert_status_request() FALSE
#define Curl_ssl_check_cxn(x) 0
#define Curl_ssl_cleanup() Curl_nop_stmt
#define Curl_ssl_close(x,y,z) Curl_nop_stmt
#define Curl_ssl_close_all(x) Curl_nop_stmt
#define Curl_ssl_connect(x,y,z) CURLE_NOT_BUILT_IN
#define Curl_ssl_connect_nonblocking(x,y,z,w) CURLE_NOT_BUILT_IN
#define Curl_ssl_data_pending(x,y) 0
#define Curl_ssl_engines_list(x) NULL
#define Curl_ssl_false_start() FALSE
#define Curl_ssl_free_certinfo(x) Curl_nop_stmt
#define Curl_ssl_init() 1
#define Curl_ssl_initsessions(x,y) CURLE_OK
#define Curl_ssl_kill_session(x) Curl_nop_stmt
#define Curl_ssl_random(x,y,z) ((void)x, CURLE_NOT_BUILT_IN)
#define Curl_ssl_recv(a,b,c,d,e) -1
#define Curl_ssl_send(a,b,c,d,e) -1
#define Curl_ssl_set_engine(x,y) CURLE_NOT_BUILT_IN
#define Curl_ssl_set_engine_default(x) CURLE_NOT_BUILT_IN
#define Curl_ssl_shutdown(x,y,z) CURLE_NOT_BUILT_IN
#define Curl_ssl_tls13_ciphersuites() FALSE

#define MAX_PINNED_PUBKEY_SIZE 1048576 
#define SSLSUPP_CA_PATH      (1<<0) 
#define SSLSUPP_CERTINFO     (1<<1) 
#define SSLSUPP_HTTPS_PROXY  (1<<4) 
#define SSLSUPP_PINNEDPUBKEY (1<<2) 
#define SSLSUPP_SSL_CTX      (1<<3) 
#define SSLSUPP_TLS13_CIPHERSUITES (1<<5) 
#define SSL_CONN_CONFIG(var)                                            \
  (SSL_IS_PROXY() ? conn->proxy_ssl_config.var : conn->ssl_config.var)
#define SSL_HOST_DISPNAME()                                             \
  (SSL_IS_PROXY() ? conn->http_proxy.host.dispname : conn->host.dispname)
#define SSL_HOST_NAME()                                                 \
  (SSL_IS_PROXY() ? conn->http_proxy.host.name : conn->host.name)
#define SSL_IS_PROXY()                                                  \
  (CURLPROXY_HTTPS == conn->http_proxy.proxytype &&                     \
   ssl_connection_complete !=                                           \
   conn->proxy_ssl[conn->sock[SECONDARYSOCKET] ==                       \
                   CURL_SOCKET_BAD ? FIRSTSOCKET : SECONDARYSOCKET].state)
#define SSL_PINNED_PUB_KEY() (SSL_IS_PROXY()                            \
  ? data->set.str[STRING_SSL_PINNEDPUBLICKEY_PROXY]                     \
  : data->set.str[STRING_SSL_PINNEDPUBLICKEY])
#define SSL_SET_OPTION(var)                                             \
  (SSL_IS_PROXY() ? data->set.proxy_ssl.var : data->set.ssl.var)
#define SSL_SET_OPTION_LVALUE(var)                                      \
  (*(SSL_IS_PROXY() ? &data->set.proxy_ssl.var : &data->set.ssl.var))
#define SSL_SHUTDOWN_TIMEOUT 10000 












#define CURL_CSELECT_IN2 (CURL_CSELECT_ERR << 1)

#define POLLERR     0x08
#define POLLHUP     0x10
#define POLLIN      0x01
#define POLLNVAL    0x20
#define POLLOUT     0x04
#define POLLPRI     0x02
#define POLLRDBAND POLLPRI
#define POLLRDNORM POLLIN
#define POLLWRNORM POLLOUT
#define SOCKET_READABLE(x,z) \
  Curl_socket_check(x, CURL_SOCKET_BAD, CURL_SOCKET_BAD, z)
#define SOCKET_WRITABLE(x,z) \
  Curl_socket_check(CURL_SOCKET_BAD, CURL_SOCKET_BAD, x, z)
#define VALID_SOCK(s) ((s) < INVALID_SOCKET)
#define VERIFY_SOCK(x) do { \
  if(!VALID_SOCK(x)) { \
    SET_SOCKERRNO(WSAEINVAL); \
    return -1; \
  } \
} while(0)

#define CONNCTRL_CONNECTION 1
#define CONNCTRL_KEEP 0 
#define CONNCTRL_STREAM 2
#define Curl_sndbufset(y) Curl_nop_stmt
#define DEFAULT_CONNECT_TIMEOUT 300000 

#define connclose(x,y) Curl_conncontrol(x, CONNCTRL_CONNECTION, y)
#define connkeep(x,y) Curl_conncontrol(x, CONNCTRL_KEEP, y)
#define sa_addr _sa_ex_u.addr
#define streamclose(x,y) Curl_conncontrol(x, CONNCTRL_STREAM, y)


#define Curl_inet_pton(x,y,z) inet_pton(x,y,z)

#define CONNECT_FIRSTSOCKET_PROXY_SSL()\
  (conn->http_proxy.proxytype == CURLPROXY_HTTPS &&\
  !conn->bits.proxy_ssl_connected[FIRSTSOCKET])
#define CONNECT_PROXY_SSL() FALSE
#define CONNECT_SECONDARYSOCKET_PROXY_SSL()\
  (conn->http_proxy.proxytype == CURLPROXY_HTTPS &&\
  !conn->bits.proxy_ssl_connected[SECONDARYSOCKET])
#define CURL_DEFAULT_HTTPS_PROXY_PORT 443 
#define CURL_DEFAULT_PROXY_PORT 1080 
#define Curl_verboseconnect(x,y)  Curl_nop_stmt

#define CLIENTWRITE_BODY   (1<<0)
#define CLIENTWRITE_BOTH   (CLIENTWRITE_BODY|CLIENTWRITE_HEADER)
#define CLIENTWRITE_HEADER (1<<1)

#define failf Curl_failf
#define infof Curl_infof
