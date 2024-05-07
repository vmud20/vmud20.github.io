





#include<sys/socket.h>




#include<time.h>
#include<limits.h>
#include<stdio.h>





#include<sys/select.h>

#include<sys/types.h>


#include<sys/time.h>

#  define CONF_DEFAULT (0|CONF_NOPROGRESS)


#  define OS "unknown"
#  define UNPRINTABLE_CHAR '.'
#  define main(x,y) curl_main(x,y)
#  define select(a,b,c,d,e) tpf_select_bsd(a,b,c,d,e)
#define CFINIT(name) CURLFORM_ ## name
#define CINIT(na,t,nu) CURLOPT_ ## na = CURLOPTTYPE_ ## t + nu
#define CURLAUTH_ANY          (~CURLAUTH_DIGEST_IE)
#define CURLAUTH_ANYSAFE      (~(CURLAUTH_BASIC|CURLAUTH_DIGEST_IE))
#define CURLAUTH_BASIC        (((unsigned long)1)<<0)
#define CURLAUTH_DIGEST       (((unsigned long)1)<<1)
#define CURLAUTH_DIGEST_IE    (((unsigned long)1)<<4)
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
#define CURLINFO_DOUBLE   0x300000
#define CURLINFO_HTTP_CODE CURLINFO_RESPONSE_CODE
#define CURLINFO_LONG     0x200000
#define CURLINFO_MASK     0x0fffff
#define CURLINFO_SLIST    0x400000
#define CURLINFO_SOCKET   0x500000
#define CURLINFO_STRING   0x100000
#define CURLINFO_TYPEMASK 0xf00000
#define CURLOPTTYPE_FUNCTIONPOINT 20000
#define CURLOPTTYPE_LONG          0
#define CURLOPTTYPE_OBJECTPOINT   10000
#define CURLOPTTYPE_OFF_T         30000
#define CURLOPTTYPE_STRINGPOINT   10000
#define CURLOPT_CLOSEPOLICY CURLOPT_OBSOLETE72
#define CURLOPT_ENCODING CURLOPT_ACCEPT_ENCODING
#define CURLOPT_FILE CURLOPT_WRITEDATA 
#define CURLOPT_FTPAPPEND CURLOPT_APPEND
#define CURLOPT_FTPLISTONLY CURLOPT_DIRLISTONLY
#define CURLOPT_FTP_SSL CURLOPT_USE_SSL
#define CURLOPT_INFILE CURLOPT_READDATA 
#define CURLOPT_KRB4LEVEL CURLOPT_KRBLEVEL
#define CURLOPT_POST301 CURLOPT_POSTREDIR
#define CURLOPT_RTSPHEADER CURLOPT_HTTPHEADER
#define CURLOPT_SERVER_RESPONSE_TIMEOUT CURLOPT_FTP_RESPONSE_TIMEOUT
#define CURLOPT_SSLCERTPASSWD CURLOPT_KEYPASSWD
#define CURLOPT_SSLKEYPASSWD CURLOPT_KEYPASSWD
#define CURLOPT_WRITEHEADER CURLOPT_HEADERDATA
#define CURLOPT_WRITEINFO CURLOPT_OBSOLETE40
#define CURLOPT_XFERINFODATA CURLOPT_PROGRESSDATA
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
#define CURLPROTO_SMB    (1<<26)
#define CURLPROTO_SMBS   (1<<27)
#define CURLPROTO_SMTP   (1<<16)
#define CURLPROTO_SMTPS  (1<<17)
#define CURLPROTO_TELNET (1<<6)
#define CURLPROTO_TFTP   (1<<11)
#define CURLSSH_AUTH_AGENT     (1<<4) 
#define CURLSSH_AUTH_ANY       ~0     
#define CURLSSH_AUTH_DEFAULT CURLSSH_AUTH_ANY
#define CURLSSH_AUTH_HOST      (1<<2) 
#define CURLSSH_AUTH_KEYBOARD  (1<<3) 
#define CURLSSH_AUTH_NONE      0      
#define CURLSSH_AUTH_PASSWORD  (1<<1) 
#define CURLSSH_AUTH_PUBLICKEY (1<<0) 
#define CURLSSLOPT_ALLOW_BEAST (1<<0)
#define CURLSSLOPT_NO_REVOKE (1<<1)
#define CURLVERSION_NOW CURLVERSION_FOURTH
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
#define CURL_MAX_WRITE_SIZE 16384
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
#define CURL_VERSION_ASYNCHDNS    (1<<7)  
#define CURL_VERSION_CONV         (1<<12) 
#define CURL_VERSION_CURLDEBUG    (1<<13) 
#define CURL_VERSION_DEBUG        (1<<6)  
#define CURL_VERSION_GSSAPI       (1<<17) 
#define CURL_VERSION_GSSNEGOTIATE (1<<5)  
#define CURL_VERSION_HTTP2        (1<<16) 
#define CURL_VERSION_IDN          (1<<10) 
#define CURL_VERSION_IPV6         (1<<0)  
#define CURL_VERSION_KERBEROS4    (1<<1)  
#define CURL_VERSION_KERBEROS5    (1<<18) 
#define CURL_VERSION_LARGEFILE    (1<<9)  
#define CURL_VERSION_LIBZ         (1<<3)  
#define CURL_VERSION_NTLM         (1<<4)  
#define CURL_VERSION_NTLM_WB      (1<<15) 
#define CURL_VERSION_PSL          (1<<20) 
#define CURL_VERSION_SPNEGO       (1<<8)  
#define CURL_VERSION_SSL          (1<<2)  
#define CURL_VERSION_SSPI         (1<<11) 
#define CURL_VERSION_TLSAUTH_SRP  (1<<14) 
#define CURL_VERSION_UNIX_SOCKETS (1<<19) 
#define CURL_WRITEFUNC_PAUSE 0x10000001
#define FUNCTIONPOINT CURLOPTTYPE_FUNCTIONPOINT
#define LONG          CURLOPTTYPE_LONG
#define OBJECTPOINT   CURLOPTTYPE_OBJECTPOINT
#define OFF_T         CURLOPTTYPE_OFF_T
#define STRINGPOINT   CURLOPTTYPE_OBJECTPOINT


#define curl_easy_getinfo(handle,info,arg) curl_easy_getinfo(handle,info,arg)
#define curl_easy_setopt(handle,opt,param) curl_easy_setopt(handle,opt,param)
#define curl_ftpssl curl_usessl
#define curl_multi_setopt(handle,opt,param) curl_multi_setopt(handle,opt,param)
#define curl_share_setopt(share,opt,param) curl_share_setopt(share,opt,param)



#define  VMSSTS_HIDE  VMS_STS(1,0,0,0)
#define  VMS_STS(c,f,e,s) (((c&0xF)<<28)|((f&0xFFF)<<16)|((e&0x1FFF)<3)|(s&7))
#define exit(__code) vms_special_exit((__code), (0))



#  define ourWriteEnv(x)  Curl_nop_stmt

#define tvdiff(a,b)       tool_tvdiff((a), (b))
#define tvdiff_secs(a,b)  tool_tvdiff_secs((a), (b))
#define tvlong(a)         tool_tvlong((a))
#define tvnow()           tool_tvnow()
#define GLOB_PATTERN_NUM 100



#define SETOPT_CHECK(v) do { \
  result = (v); \
  if(result) \
    goto show_error; \
} WHILE_FALSE
#define my_setopt(x,y,z) \
  SETOPT_CHECK(curl_easy_setopt(x, y, z))
#define my_setopt_bitmask(x,y,z) \
  SETOPT_CHECK(tool_setopt_bitmask(x, global, #y, y, setopt_nv_ ## y, z))
#define my_setopt_enum(x,y,z) \
  SETOPT_CHECK(tool_setopt_enum(x, global, #y, y, setopt_nv_ ## y, z))
#define my_setopt_flags(x,y,z) \
  SETOPT_CHECK(tool_setopt_flags(x, global, #y, y, setopt_nv_ ## y, z))
#define my_setopt_httppost(x,y,z) \
  SETOPT_CHECK(tool_setopt_httppost(x, global, #y, y, z))
#define my_setopt_slist(x,y,z) \
  SETOPT_CHECK(tool_setopt_slist(x, global, #y, y, z))
#define my_setopt_str(x,y,z) \
  SETOPT_CHECK(curl_easy_setopt(x, y, z))
#define res_setopt(x,y,z) tool_setopt(x, FALSE, global, #y, y, z)
#define res_setopt_str(x,y,z) tool_setopt(x, TRUE, global, #y, y, z)
#define setopt_nv_CURLOPT_FTP_SSL_CCC setopt_nv_CURLFTPSSL_CCC
#define setopt_nv_CURLOPT_HTTPAUTH setopt_nv_CURLAUTH
#define setopt_nv_CURLOPT_HTTP_VERSION setopt_nv_CURL_HTTP_VERSION
#define setopt_nv_CURLOPT_NETRC setopt_nv_CURL_NETRC
#define setopt_nv_CURLOPT_PROTOCOLS setopt_nv_CURLPROTO
#define setopt_nv_CURLOPT_PROXYAUTH setopt_nv_CURLAUTH
#define setopt_nv_CURLOPT_PROXYTYPE setopt_nv_CURLPROXY
#define setopt_nv_CURLOPT_REDIR_PROTOCOLS setopt_nv_CURLPROTO
#define setopt_nv_CURLOPT_SSLVERSION setopt_nv_CURL_SSLVERSION
#define setopt_nv_CURLOPT_SSL_OPTIONS setopt_nv_CURLSSLOPT
#define setopt_nv_CURLOPT_TIMECONDITION setopt_nv_CURL_TIMECOND
#define setopt_nv_CURLOPT_USE_SSL setopt_nv_CURLUSESSL





#define CURL_REQ_LIBMETALINK_MAJOR  0
#define CURL_REQ_LIBMETALINK_MINOR  1
#define CURL_REQ_LIBMETALINK_PATCH  0
#define CURL_REQ_LIBMETALINK_VERS  ((CURL_REQ_LIBMETALINK_MAJOR * 10000) + \
                                    (CURL_REQ_LIBMETALINK_MINOR * 100) + \
                                     CURL_REQ_LIBMETALINK_PATCH)

#define clean_metalink(x)  (void)x
#define count_next_metalink_resource(x)  0
#define metalink_cleanup() Curl_nop_stmt
#define DEFAULT_MAXREDIRS  50L

#define RETRY_SLEEP_DEFAULT 1000L   
#define RETRY_SLEEP_MAX     600000L 
#  define STDERR_FILENO  fileno(stderr)
#  define STDIN_FILENO  fileno(stdin)
#  define STDOUT_FILENO  fileno(stdout)








#  define HAVE_FTRUNCATE 1

#define ftruncate(fd,where) tool_ftruncate64(fd,where)

#define CURL_PROGRESS_BAR   1
#define CURL_PROGRESS_STATS 0 




#define GETOUT_METALINK   (1<<5)  
#define GETOUT_NOUPLOAD   (1<<4)  
#define GETOUT_OUTFILE    (1<<0)  
#define GETOUT_UPLOAD     (1<<3)  
#define GETOUT_URL        (1<<1)  
#define GETOUT_USEREMOTE  (1<<2)  


#define set_binmode(x) Curl_nop_stmt
