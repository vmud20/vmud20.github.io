


#include<string.h>






#include<sys/resource.h>








#include<stdarg.h>
#include<stdlib.h>



#include<sys/time.h>


#include<syslog.h>




#define APACHE_ARG_MAX _POSIX_ARG_MAX


#define APLOG_ALERT     LOG_ALERT     
#define APLOG_CRIT      LOG_CRIT      
#define APLOG_DEBUG     LOG_DEBUG     
#define APLOG_EMERG     LOG_EMERG     
#define APLOG_ERR       LOG_ERR       
#define APLOG_INFO      LOG_INFO      
#define APLOG_LEVELMASK LOG_PRIMASK   
#define APLOG_NOTICE    LOG_NOTICE    
#define APLOG_STARTUP           ((APLOG_LEVELMASK + 1) * 4) 
#define APLOG_TOCLIENT          ((APLOG_LEVELMASK + 1) * 2)
#define APLOG_WARNING   LOG_WARNING   
#define LOG_PRIMASK 7
#define ap_piped_log_read_fd(pl)	((pl)->fds[0])
#define ap_piped_log_write_fd(pl)	((pl)->fds[1])

#define AP_SERVER_BASEARGS "C:c:D:d:E:e:f:vVlLtSMh?X"

#define AP_BUCKET_IS_ERROR(e)         (e->type == &ap_bucket_type_error)
#define AP_METHOD_CHECK_ALLOWED(mask, methname) \
    ((mask) & (AP_METHOD_BIT << ap_method_number_of((methname))))
#define ap_rgetline(s, n, read, r, fold, bb) \
        ap_rgetline_core((s), (n), (read), (r), (fold), (bb))
#define AP_FILTER_ERROR         -3

#define AP_FILTER_PROTO_CHANGE 0x1
#define AP_FILTER_PROTO_CHANGE_LENGTH 0x2
#define AP_FILTER_PROTO_NO_BYTERANGE 0x4
#define AP_FILTER_PROTO_NO_CACHE 0x10
#define AP_FILTER_PROTO_NO_PROXY 0x8
#define AP_FILTER_PROTO_TRANSFORM 0x20
#define AP_NOBODY_READ          -2
#define AP_NOBODY_WROTE         -1
#define ap_fputc(f, bb, c) \
        apr_brigade_putc(bb, ap_filter_flush, f, c)
#define ap_fputs(f, bb, str) \
        apr_brigade_puts(bb, ap_filter_flush, f, str)
#define ap_fwrite(f, bb, data, nbyte) \
        apr_brigade_write(bb, ap_filter_flush, f, data, nbyte)

#define APEXIT_CHILDSICK        0x7
#define AP_DEBUG_ASSERT(exp) ap_assert(exp)
# define AP_DECLARE(type)    type
# define AP_DECLARE_DATA
# define AP_DECLARE_NONSTD(type)    type
#define AP_DEFAULT_INDEX "index.html"
#define AP_IOBUFSIZE 8192
#define AP_MAX_REG_MATCH 10
#define AP_MAX_SENDFILE 16777216  
#define AP_METHOD_BIT ((apr_int64_t)1)
# define AP_MODULE_DECLARE(type)    type
# define AP_MODULE_DECLARE_DATA
# define AP_MODULE_DECLARE_NONSTD(type)  type
#define AP_REQ_ACCEPT_PATH_INFO    0
#define AP_REQ_DEFAULT_PATH_INFO   2
#define AP_REQ_REJECT_PATH_INFO    1
#define AP_SERVER_PROTOCOL "HTTP/1.1"
#define AP_TYPES_CONFIG_FILE "conf/mime.types"
#define CGI_MAGIC_TYPE "application/x-httpd-cgi"
#define CR 13
#define CRLF "\015\012"
#define DECLINED -1		
#define DEFAULT_ACCESS_FNAME "htaccess"
#define DEFAULT_ADD_DEFAULT_CHARSET_NAME "iso-8859-1"
#define DEFAULT_ADMIN "[no address given]"
#define DEFAULT_CONTENT_TYPE "text/plain"
#define DEFAULT_ERRORLOG "logs/error.log"
#define DEFAULT_KEEPALIVE 100
#define DEFAULT_KEEPALIVE_TIMEOUT 5
#define DEFAULT_LIMIT_REQUEST_FIELDS 100
#define DEFAULT_LIMIT_REQUEST_FIELDSIZE 8190
#define DEFAULT_LIMIT_REQUEST_LINE 8190
#define DEFAULT_PATH "/bin:/usr/bin:/usr/ucb:/usr/bsd:/usr/local/bin"
#define DEFAULT_TIMEOUT 300 
#define DEFAULT_VHOST_ADDR 0xfffffffful
#define DIR_MAGIC_TYPE "httpd/unix-directory"
#define DOCTYPE_HTML_2_0  "<!DOCTYPE HTML PUBLIC \"-//IETF//" \
                          "DTD HTML 2.0//EN\">\n"
#define DOCTYPE_HTML_3_2  "<!DOCTYPE HTML PUBLIC \"-//W3C//" \
                          "DTD HTML 3.2 Final//EN\">\n"
#define DOCTYPE_HTML_4_0F "<!DOCTYPE HTML PUBLIC \"-//W3C//" \
                          "DTD HTML 4.0 Frameset//EN\"\n" \
                          "\"http://www.w3.org/TR/REC-html40/frameset.dtd\">\n"
#define DOCTYPE_HTML_4_0S "<!DOCTYPE HTML PUBLIC \"-//W3C//" \
                          "DTD HTML 4.0//EN\"\n" \
                          "\"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
#define DOCTYPE_HTML_4_0T "<!DOCTYPE HTML PUBLIC \"-//W3C//" \
                          "DTD HTML 4.0 Transitional//EN\"\n" \
                          "\"http://www.w3.org/TR/REC-html40/loose.dtd\">\n"
#define DOCTYPE_XHTML_1_0F "<!DOCTYPE html PUBLIC \"-//W3C//" \
                           "DTD XHTML 1.0 Frameset//EN\"\n" \
                           "\"http://www.w3.org/TR/xhtml1/DTD/" \
                           "xhtml1-frameset.dtd\">"
#define DOCTYPE_XHTML_1_0S "<!DOCTYPE html PUBLIC \"-//W3C//" \
                           "DTD XHTML 1.0 Strict//EN\"\n" \
                           "\"http://www.w3.org/TR/xhtml1/DTD/" \
                           "xhtml1-strict.dtd\">\n"
#define DOCTYPE_XHTML_1_0T "<!DOCTYPE html PUBLIC \"-//W3C//" \
                           "DTD XHTML 1.0 Transitional//EN\"\n" \
                           "\"http://www.w3.org/TR/xhtml1/DTD/" \
                           "xhtml1-transitional.dtd\">\n"
#define DOCUMENT_LOCATION  HTTPD_ROOT "/docs"
#define DONE -2			
#define DYNAMIC_MODULE_LIMIT 128
#define HTTPD_ROOT "/os2httpd"
#define HTTP_ACCEPTED                      202
#define HTTP_BAD_GATEWAY                   502
#define HTTP_BAD_REQUEST                   400
#define HTTP_CONFLICT                      409
#define HTTP_CONTINUE                      100
#define HTTP_CREATED                       201
#define HTTP_EXPECTATION_FAILED            417
#define HTTP_FAILED_DEPENDENCY             424
#define HTTP_FORBIDDEN                     403
#define HTTP_GATEWAY_TIME_OUT              504
#define HTTP_GONE                          410
#define HTTP_INSUFFICIENT_STORAGE          507
#define HTTP_INTERNAL_SERVER_ERROR         500
#define HTTP_LENGTH_REQUIRED               411
#define HTTP_LOCKED                        423
#define HTTP_METHOD_NOT_ALLOWED            405
#define HTTP_MOVED_PERMANENTLY             301
#define HTTP_MOVED_TEMPORARILY             302
#define HTTP_MULTIPLE_CHOICES              300
#define HTTP_MULTI_STATUS                  207
#define HTTP_NON_AUTHORITATIVE             203
#define HTTP_NOT_ACCEPTABLE                406
#define HTTP_NOT_EXTENDED                  510
#define HTTP_NOT_FOUND                     404
#define HTTP_NOT_IMPLEMENTED               501
#define HTTP_NOT_MODIFIED                  304
#define HTTP_NO_CONTENT                    204
#define HTTP_OK                            200
#define HTTP_PARTIAL_CONTENT               206
#define HTTP_PAYMENT_REQUIRED              402
#define HTTP_PRECONDITION_FAILED           412
#define HTTP_PROCESSING                    102
#define HTTP_PROXY_AUTHENTICATION_REQUIRED 407
#define HTTP_RANGE_NOT_SATISFIABLE         416
#define HTTP_REQUEST_ENTITY_TOO_LARGE      413
#define HTTP_REQUEST_TIME_OUT              408
#define HTTP_REQUEST_URI_TOO_LARGE         414
#define HTTP_RESET_CONTENT                 205
#define HTTP_SEE_OTHER                     303
#define HTTP_SERVICE_UNAVAILABLE           503
#define HTTP_SWITCHING_PROTOCOLS           101
#define HTTP_TEMPORARY_REDIRECT            307
#define HTTP_UNAUTHORIZED                  401
#define HTTP_UNPROCESSABLE_ENTITY          422
#define HTTP_UNSUPPORTED_MEDIA_TYPE        415
#define HTTP_UPGRADE_REQUIRED              426
#define HTTP_USE_PROXY                     305
#define HTTP_VARIANT_ALSO_VARIES           506
#define HTTP_VERSION(major,minor) (1000*(major)+(minor))
#define HTTP_VERSION_MAJOR(number) ((number)/1000)
#define HTTP_VERSION_MINOR(number) ((number)%1000)
#define HTTP_VERSION_NOT_SUPPORTED         505
#define HUGE_STRING_LEN 8192
#define INCLUDES_MAGIC_TYPE "text/x-server-parsed-html"
#define INCLUDES_MAGIC_TYPE3 "text/x-server-parsed-html3"
#define LF 10
#define MAX_STRING_LEN HUGE_STRING_LEN
#define METHODS     64
#define M_BASELINE_CONTROL      24
#define M_CHECKIN               18
#define M_CHECKOUT              16      
#define M_CONNECT               4
#define M_COPY                  11
#define M_DELETE                3
#define M_GET                   0       
#define M_INVALID               26      
#define M_LABEL                 20
#define M_LOCK                  13
#define M_MERGE                 25
#define M_MKACTIVITY            23
#define M_MKCOL                 10
#define M_MKWORKSPACE           22
#define M_MOVE                  12
#define M_OPTIONS               5
#define M_PATCH                 7       
#define M_POST                  2
#define M_PROPFIND              8       
#define M_PROPPATCH             9       
#define M_PUT                   1       
#define M_REPORT                21
#define M_TRACE                 6       
#define M_UNCHECKOUT            17
#define M_UNLOCK                14      
#define M_UPDATE                19
#define M_VERSION_CONTROL       15      
#define OK 0			
#define PROXYREQ_NONE 0		
#define PROXYREQ_PROXY 1	
#define PROXYREQ_RESPONSE 3 
#define PROXYREQ_REVERSE 2	
#define RAISE_SIGSTOP(x)	do { \
	if (raise_sigstop_flags & SIGSTOP_##x) raise(SIGSTOP);\
    } while (0)
#define REQUEST_CHUNKED_DECHUNK  2
#define REQUEST_CHUNKED_ERROR    1
#define REQUEST_NO_BODY          0
#define RESPONSE_CODES 57
#define SERVER_CONFIG_FILE "conf/httpd.conf"
#define SUEXEC_BIN  HTTPD_ROOT "/bin/suexec"
#define ap_assert(exp) ((exp) ? (void)0 : ap_log_assert(#exp,"__FILE__","__LINE__"))
#define ap_default_port(r)	ap_run_default_port(r)
#define ap_escape_uri(ppool,path) ap_os_escape_path(ppool,path,1)
#define ap_http_scheme(r)	ap_run_http_scheme(r)
#define ap_is_HTTP_CLIENT_ERROR(x) (((x) >= 400)&&((x) < 500))
#define ap_is_HTTP_ERROR(x)        (((x) >= 400)&&((x) < 600))
#define ap_is_HTTP_INFO(x)         (((x) >= 100)&&((x) < 200))
#define ap_is_HTTP_REDIRECT(x)     (((x) >= 300)&&((x) < 400))
#define ap_is_HTTP_SERVER_ERROR(x) (((x) >= 500)&&((x) < 600))
#define ap_is_HTTP_SUCCESS(x)      (((x) >= 200)&&((x) < 300))
#define ap_is_default_port(port,r)	((port) == ap_default_port(r))
#define ap_status_drops_connection(x) \
                                   (((x) == HTTP_BAD_REQUEST)           || \
                                    ((x) == HTTP_REQUEST_TIME_OUT)      || \
                                    ((x) == HTTP_LENGTH_REQUIRED)       || \
                                    ((x) == HTTP_REQUEST_ENTITY_TOO_LARGE) || \
                                    ((x) == HTTP_REQUEST_URI_TOO_LARGE) || \
                                    ((x) == HTTP_INTERNAL_SERVER_ERROR) || \
                                    ((x) == HTTP_SERVICE_UNAVAILABLE) || \
				    ((x) == HTTP_NOT_IMPLEMENTED))
# define ap_strchr(s, c)	strchr(s, c)
# define ap_strchr_c(s, c)	strchr(s, c)
# define ap_strrchr(s, c)	strrchr(s, c)
# define ap_strrchr_c(s, c)	strrchr(s, c)
# define ap_strstr(s, c)	strstr(s, c)
# define ap_strstr_c(s, c)	strstr(s, c)
# define strchr(s, c)	ap_strchr(s,c)
# define strrchr(s, c)  ap_strrchr(s,c)
# define strstr(s, c)  ap_strstr(s,c)
#define strtoul strtoul_is_not_a_portable_function_use_strtol_instead

#define AP_REG_EXTENDED (0)  
#define AP_REG_ICASE    0x01 
#define AP_REG_NEWLINE  0x02 
#define AP_REG_NOSUB    (0)  
#define AP_REG_NOTBOL   0x04 
#define AP_REG_NOTEOL   0x08 

#define AP_SERVER_ADD_STRING          "-dev"
#define AP_SERVER_BASEPRODUCT "Apache"
#define AP_SERVER_BASEREVISION  AP_SERVER_MINORREVISION "." AP_SERVER_PATCHLEVEL
#define AP_SERVER_BASEVENDOR "Apache Software Foundation"
#define AP_SERVER_BASEVERSION   AP_SERVER_BASEPRODUCT "/" AP_SERVER_BASEREVISION
#define AP_SERVER_DEVBUILD_BOOLEAN    1
#define AP_SERVER_MAJORVERSION  AP_STRINGIFY(AP_SERVER_MAJORVERSION_NUMBER)
#define AP_SERVER_MAJORVERSION_NUMBER 2
#define AP_SERVER_MINORREVISION AP_SERVER_MAJORVERSION "." AP_SERVER_MINORVERSION
#define AP_SERVER_MINORVERSION  AP_STRINGIFY(AP_SERVER_MINORVERSION_NUMBER)
#define AP_SERVER_MINORVERSION_NUMBER 3
#define AP_SERVER_PATCHLEVEL    AP_STRINGIFY(AP_SERVER_PATCHLEVEL_NUMBER) \
                                AP_SERVER_ADD_STRING
#define AP_SERVER_PATCHLEVEL_CSV AP_SERVER_MAJORVERSION_NUMBER ##, \
                               ##AP_SERVER_MINORVERSION_NUMBER ##, \
                               ##AP_SERVER_PATCHLEVEL_NUMBER
#define AP_SERVER_PATCHLEVEL_NUMBER   0
#define AP_SERVER_VERSION       AP_SERVER_BASEVERSION
#define AP_STRINGIFY(n) AP_STRINGIFY_HELPER(n)
#define AP_STRINGIFY_HELPER(n) #n

#define AP_MODULE_MAGIC_AT_LEAST(major,minor)		\
    ((major) < MODULE_MAGIC_NUMBER_MAJOR 		\
	|| ((major) == MODULE_MAGIC_NUMBER_MAJOR 	\
	    && (minor) <= MODULE_MAGIC_NUMBER_MINOR))
#define MODULE_MAGIC_AT_LEAST old_broken_macro_we_hope_you_are_not_using
#define MODULE_MAGIC_COOKIE 0x41503234UL 
#define MODULE_MAGIC_NUMBER MODULE_MAGIC_NUMBER_MAJOR
#define MODULE_MAGIC_NUMBER_MAJOR 20051115
#define MODULE_MAGIC_NUMBER_MINOR 0                     

# define AP_DECLARE_EXPORT
#define AP_DECLARE_HOOK(ret,name,args) \
	APR_DECLARE_EXTERNAL_HOOK(ap,AP,ret,name,args)
# define AP_DECLARE_STATIC

#define AP_HAVE_RELIABLE_PIPED_LOGS TRUE
#define AP_IMPLEMENT_HOOK_BASE(name) \
	APR_IMPLEMENT_EXTERNAL_HOOK_BASE(ap,AP,name)
#define AP_IMPLEMENT_HOOK_RUN_ALL(ret,name,args_decl,args_use,ok,decline) \
	APR_IMPLEMENT_EXTERNAL_HOOK_RUN_ALL(ap,AP,ret,name,args_decl, \
                                            args_use,ok,decline)
#define AP_IMPLEMENT_HOOK_RUN_FIRST(ret,name,args_decl,args_use,decline) \
	APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(ap,AP,ret,name,args_decl, \
                                              args_use,decline)
#define AP_IMPLEMENT_HOOK_VOID(name,args_decl,args_use) \
	APR_IMPLEMENT_EXTERNAL_HOOK_VOID(ap,AP,name,args_decl,args_use)
#define AP_IMPLEMENT_OPTIONAL_HOOK_RUN_ALL(ret,name,args_decl,args_use,ok, \
					   decline) \
	APR_IMPLEMENT_OPTIONAL_HOOK_RUN_ALL(ap,AP,ret,name,args_decl, \
                                            args_use,ok,decline)

#define AP_NONBLOCK_WHEN_MULTI_LISTEN 1
#define AP_OPTIONAL_HOOK(name,fn,pre,succ,order) \
        APR_OPTIONAL_HOOK(ap,name,fn,pre,succ,order)

#define ADD_DEFAULT_CHARSET_OFF   (0)
#define ADD_DEFAULT_CHARSET_ON    (1)
#define ADD_DEFAULT_CHARSET_UNSET (2)

# define AP_DEFAULT_MAX_INTERNAL_REDIRECTS 10
# define AP_DEFAULT_MAX_SUBREQ_DEPTH 10
#define AP_MIN_BYTES_TO_WRITE  8000
#define AP_NOTE_DIRECTORY_WALK 0
#define AP_NOTE_FILE_WALK      2
#define AP_NOTE_LOCATION_WALK  1
#define AP_NUM_STD_NOTES       3
#define AP_TRACE_DISABLE   0
#define AP_TRACE_ENABLE    1
#define AP_TRACE_EXTENDED  2
#define AP_TRACE_UNSET    -1
#define ENABLE_MMAP_OFF    (0)
#define ENABLE_MMAP_ON     (1)
#define ENABLE_MMAP_UNSET  (2)
#define ENABLE_SENDFILE_OFF    (0)
#define ENABLE_SENDFILE_ON     (1)
#define ENABLE_SENDFILE_UNSET  (2)
#define ETAG_ALL   (ETAG_MTIME | ETAG_INODE | ETAG_SIZE)
#define ETAG_BACKWARD (ETAG_MTIME | ETAG_INODE | ETAG_SIZE)
#define ETAG_INODE (1 << 2)
#define ETAG_MTIME (1 << 1)
#define ETAG_NONE  (1 << 0)
#define ETAG_SIZE  (1 << 3)
#define ETAG_UNSET 0
#define OPT_ALL (OPT_INDEXES|OPT_INCLUDES|OPT_SYM_LINKS|OPT_EXECCGI)
#define OPT_EXECCGI 8
#define OPT_INCLUDES 2
#define OPT_INCNOEXEC 32
#define OPT_INDEXES 1
#define OPT_MULTI 128
#define OPT_NONE 0
#define OPT_SYM_LINKS 4
#define OPT_SYM_OWNER 64
#define OPT_UNSET 16
#define REMOTE_DOUBLE_REV (3)
#define REMOTE_HOST (0)
#define REMOTE_NAME (1)
#define REMOTE_NOLOOKUP (2)
#define SATISFY_ALL 0
#define SATISFY_ANY 1
#define SATISFY_NOSPEC 2
#define USE_CANONICAL_NAME_DNS   (2)
#define USE_CANONICAL_NAME_OFF   (0)
#define USE_CANONICAL_NAME_ON    (1)
#define USE_CANONICAL_NAME_UNSET (3)
#define USE_CANONICAL_PHYS_PORT_OFF   (0)
#define USE_CANONICAL_PHYS_PORT_ON    (1)
#define USE_CANONICAL_PHYS_PORT_UNSET (2)

#define AP_BUCKET_IS_EOR(e)         (e->type == &ap_bucket_type_eor)
#define AP_SUBREQ_MERGE_ARGS 1
#define AP_SUBREQ_NO_ARGS 0
#define MERGE_ALLOW 0
#define REPLACE_ALLOW 1
#define ACCESS_CONF 64       

# define AP_FLAG     func
# define AP_INIT_FLAG(directive, func, mconfig, where, help) \
    { directive, { .flag=func }, mconfig, where, FLAG, help }
# define AP_INIT_ITERATE(directive, func, mconfig, where, help) \
    { directive, { .take1=func }, mconfig, where, ITERATE, help }
# define AP_INIT_ITERATE2(directive, func, mconfig, where, help) \
    { directive, { .take2=func }, mconfig, where, ITERATE2, help }
# define AP_INIT_NO_ARGS(directive, func, mconfig, where, help) \
    { directive, { .no_args=func }, mconfig, where, RAW_ARGS, help }
# define AP_INIT_RAW_ARGS(directive, func, mconfig, where, help) \
    { directive, { .raw_args=func }, mconfig, where, RAW_ARGS, help }
# define AP_INIT_TAKE1(directive, func, mconfig, where, help) \
    { directive, { .take1=func }, mconfig, where, TAKE1, help }
# define AP_INIT_TAKE12(directive, func, mconfig, where, help) \
    { directive, { .take2=func }, mconfig, where, TAKE12, help }
# define AP_INIT_TAKE123(directive, func, mconfig, where, help) \
    { directive, { .take3=func }, mconfig, where, TAKE123, help }
# define AP_INIT_TAKE13(directive, func, mconfig, where, help) \
    { directive, { .take3=func }, mconfig, where, TAKE13, help }
# define AP_INIT_TAKE2(directive, func, mconfig, where, help) \
    { directive, { .take2=func }, mconfig, where, TAKE2, help }
# define AP_INIT_TAKE23(directive, func, mconfig, where, help) \
    { directive, { .take3=func }, mconfig, where, TAKE23, help }
# define AP_INIT_TAKE3(directive, func, mconfig, where, help) \
    { directive, { .take3=func }, mconfig, where, TAKE3, help }
# define AP_INIT_TAKE_ARGV(directive, func, mconfig, where, help) \
    { directive, { .take_argv=func }, mconfig, where, TAKE_ARGV, help }
# define AP_NO_ARGS  func
# define AP_RAW_ARGS func
# define AP_TAKE1    func
# define AP_TAKE2    func
# define AP_TAKE3    func
# define AP_TAKE_ARGV func
#define DECLINE_CMD "\a\b"
#define EXEC_ON_READ 256     
#define  GLOBAL_ONLY            (NOT_IN_VIRTUALHOST|NOT_IN_LIMIT|NOT_IN_DIR_LOC_FILE) 
#define  NOT_IN_DIRECTORY       0x04 
#define  NOT_IN_DIR_LOC_FILE    (NOT_IN_DIRECTORY|NOT_IN_LOCATION|NOT_IN_FILES) 
#define  NOT_IN_FILES           0x10 
#define  NOT_IN_LIMIT           0x02 
#define  NOT_IN_LOCATION        0x08 
#define  NOT_IN_VIRTUALHOST     0x01 
#define OR_ALL (OR_LIMIT|OR_OPTIONS|OR_FILEINFO|OR_AUTHCFG|OR_INDEXES)
#define OR_AUTHCFG 8         
#define OR_FILEINFO 4        
#define OR_INDEXES 16        
#define OR_LIMIT 1	     
#define OR_NONE 0             
#define OR_OPTIONS 2         
#define OR_UNSET 32          
#define RSRC_CONF 128	     
#define ap_get_module_config(v,m)	\
    (((void **)(v))[(m)->module_index])
#define ap_set_module_config(v,m,val)	\
    ((((void **)(v))[(m)->module_index]) = (val))

