#include<sys/time.h>




#include<sys/resource.h>





#include<string.h>


#include<arpa/inet.h>







#include<unistd.h>



#include<netinet/in.h>

#include<stdarg.h>



#include<stdlib.h>
#include<syslog.h>



















#define AP_REG_DOTALL 0x40   
#define AP_REG_EXTENDED (0)  
#define AP_REG_ICASE    0x01 
#define AP_REG_MULTI 0x10    
#define AP_REG_NEWLINE  0x02 
#define AP_REG_NOMEM 0x20    
#define AP_REG_NOSUB    (0)  
#define AP_REG_NOTBOL   0x04 
#define AP_REG_NOTEOL   0x08 
#define ap_rxplus_nmatch(rx) (((rx)->match != NULL) ? (rx)->nmatch : 0)
#define ALIGNED_PROXY_BALANCER_SHARED_SIZE (APR_ALIGN_DEFAULT(sizeof(proxy_balancer_shared)))
#define ALIGNED_PROXY_WORKER_SHARED_SIZE (APR_ALIGN_DEFAULT(sizeof(proxy_worker_shared)))

#define BALANCER_PREFIX "balancer://"
#define CRLF   "\r\n"
#define DEFAULT_MAX_FORWARDS    -1

#define PROXYPASS_INTERPOLATE 0x02
#define PROXYPASS_NOCANON 0x01
#define PROXYPASS_NOQUERY 0x04
#define PROXY_BALANCER_MAX_HOSTNAME_SIZE PROXY_WORKER_MAX_HOSTNAME_SIZE
#define PROXY_BALANCER_MAX_NAME_SIZE PROXY_WORKER_MAX_NAME_SIZE
#define PROXY_BALANCER_MAX_ROUTE_SIZE PROXY_WORKER_MAX_ROUTE_SIZE
#define PROXY_BALANCER_MAX_STICKY_SIZE  64
#define PROXY_COPY_CONF_PARAMS(w, c) \
do {                             \
(w)->s->timeout              = (c)->timeout;               \
(w)->s->timeout_set          = (c)->timeout_set;           \
(w)->s->recv_buffer_size     = (c)->recv_buffer_size;      \
(w)->s->recv_buffer_size_set = (c)->recv_buffer_size_set;  \
(w)->s->io_buffer_size       = (c)->io_buffer_size;        \
(w)->s->io_buffer_size_set   = (c)->io_buffer_size_set;    \
} while (0)
#define PROXY_DECLARE(type)            type
#define PROXY_DECLARE_DATA             __declspec(dllexport)
#define PROXY_DECLARE_NONSTD(type)     type
#define PROXY_DYNAMIC_BALANCER_LIMIT    16
#define PROXY_FLUSH_WAIT 10000
#define PROXY_GLOBAL_LOCK(x)      ( (x) && (x)->gmutex ? apr_global_mutex_lock((x)->gmutex) : APR_SUCCESS)
#define PROXY_GLOBAL_UNLOCK(x)    ( (x) && (x)->gmutex ? apr_global_mutex_unlock((x)->gmutex) : APR_SUCCESS)
#define PROXY_LBMETHOD "proxylbmethod"
#define PROXY_MAX_PROVIDER_NAME_SIZE    16
#define PROXY_STRNCPY(dst, src) ap_proxy_strncpy((dst), (src), (sizeof(dst)))
#define PROXY_THREAD_LOCK(x)      ( (x) && (x)->tmutex ? apr_thread_mutex_lock((x)->tmutex) : APR_SUCCESS)
#define PROXY_THREAD_UNLOCK(x)    ( (x) && (x)->tmutex ? apr_thread_mutex_unlock((x)->tmutex) : APR_SUCCESS)
#define PROXY_WORKER_DEFAULT_RETRY    60
#define PROXY_WORKER_DISABLED       0x0020
#define PROXY_WORKER_DISABLED_FLAG       'D'
#define PROXY_WORKER_DRAIN          0x0004
#define PROXY_WORKER_DRAIN_FLAG          'N'
#define PROXY_WORKER_FREE           0x0200
#define PROXY_WORKER_FREE_FLAG           'F'
#define PROXY_WORKER_HOT_STANDBY    0x0100
#define PROXY_WORKER_HOT_STANDBY_FLAG    'H'
#define PROXY_WORKER_IGNORE_ERRORS  0x0002
#define PROXY_WORKER_IGNORE_ERRORS_FLAG  'I'
#define PROXY_WORKER_INITIALIZED    0x0001
#define PROXY_WORKER_INITIALIZED_FLAG    'O'
#define PROXY_WORKER_IN_ERROR       0x0080
#define PROXY_WORKER_IN_ERROR_FLAG       'E'
#define PROXY_WORKER_IN_SHUTDOWN    0x0010
#define PROXY_WORKER_IN_SHUTDOWN_FLAG    'U'
#define PROXY_WORKER_IS_DRAINING(f)   ( (f)->s->status &  PROXY_WORKER_DRAIN )
#define PROXY_WORKER_IS_INITIALIZED(f)  ( (f)->s->status &  PROXY_WORKER_INITIALIZED )
#define PROXY_WORKER_IS_STANDBY(f)   ( (f)->s->status &  PROXY_WORKER_HOT_STANDBY )
#define PROXY_WORKER_IS_USABLE(f)   ( ( !( (f)->s->status & PROXY_WORKER_NOT_USABLE_BITMAP) ) && \
  PROXY_WORKER_IS_INITIALIZED(f) )
#define PROXY_WORKER_MAX_HOSTNAME_SIZE  64
#define PROXY_WORKER_MAX_NAME_SIZE      96
#define PROXY_WORKER_MAX_ROUTE_SIZE     64
#define PROXY_WORKER_MAX_SCHEME_SIZE    16
#define PROXY_WORKER_NOT_USABLE_BITMAP ( PROXY_WORKER_IN_SHUTDOWN | \
PROXY_WORKER_DISABLED | PROXY_WORKER_STOPPED | PROXY_WORKER_IN_ERROR )
#define PROXY_WORKER_STOPPED        0x0040
#define PROXY_WORKER_STOPPED_FLAG        'S'
#define AP_SLOTMEM_PROVIDER_GROUP "slotmem"
#define AP_SLOTMEM_PROVIDER_VERSION "0"
#define AP_SLOTMEM_TYPE_NOTMPSAFE (1 << 1)
#define AP_SLOTMEM_TYPE_PERSIST   (1 << 0)
#define AP_SLOTMEM_TYPE_PREGRAB   (1 << 2)


#define APREQ_DECLARE(d)                APR_DECLARE(d)
#define APREQ_DECLARE_DATA              __declspec(dllexport)
#define APREQ_DECLARE_NONSTD(d)         APR_DECLARE_NONSTD(d)

#define AP_DECLARE(type)            __declspec(dllimport) type __stdcall
#define AP_DECLARE_DATA             __declspec(dllimport)
# define AP_DECLARE_EXPORT
#define AP_DECLARE_NONSTD(type)     __declspec(dllimport) type
# define AP_DECLARE_STATIC
#define AP_FN_ATTR_ALLOC_SIZE(x)     __attribute__((alloc_size(x)))
#define AP_FN_ATTR_ALLOC_SIZE2(x,y)  __attribute__((alloc_size(x,y)))
#define AP_FN_ATTR_SENTINEL __attribute__((sentinel))
#define AP_FN_ATTR_WARN_UNUSED_RESULT   __attribute__((warn_unused_result))


#define AP_HAVE_RELIABLE_PIPED_LOGS TRUE
#define AP_MODULE_DECLARE(type)            type __stdcall
#define AP_MODULE_DECLARE_DATA           __declspec(dllexport)

#define AP_MODULE_DECLARE_NONSTD(type)     type
#define AP_NONBLOCK_WHEN_MULTI_LISTEN 1
#define DEFAULT_PIDLOG "httpd.pid"
#define __has_attribute(x) 0
#define AP_ACCESS_CHECKER_DISPATCH_COMPLETE(arg0, arg1)
#define AP_ACCESS_CHECKER_DISPATCH_COMPLETE_ENABLED() (0)

#define AP_ACCESS_CHECKER_DISPATCH_INVOKE_ENABLED() (0)

#define AP_ACCESS_CHECKER_ENTRY_ENABLED() (0)

#define AP_ACCESS_CHECKER_RETURN_ENABLED() (0)
#define AP_AUTH_CHECKER_DISPATCH_COMPLETE(arg0, arg1)
#define AP_AUTH_CHECKER_DISPATCH_COMPLETE_ENABLED() (0)

#define AP_AUTH_CHECKER_DISPATCH_INVOKE_ENABLED() (0)

#define AP_AUTH_CHECKER_ENTRY_ENABLED() (0)

#define AP_AUTH_CHECKER_RETURN_ENABLED() (0)
#define AP_CANON_HANDLER_DISPATCH_COMPLETE(arg0, arg1)
#define AP_CANON_HANDLER_DISPATCH_COMPLETE_ENABLED() (0)

#define AP_CANON_HANDLER_DISPATCH_INVOKE_ENABLED() (0)

#define AP_CANON_HANDLER_ENTRY_ENABLED() (0)

#define AP_CANON_HANDLER_RETURN_ENABLED() (0)
#define AP_CHECK_USER_ID_DISPATCH_COMPLETE(arg0, arg1)
#define AP_CHECK_USER_ID_DISPATCH_COMPLETE_ENABLED() (0)

#define AP_CHECK_USER_ID_DISPATCH_INVOKE_ENABLED() (0)

#define AP_CHECK_USER_ID_ENTRY_ENABLED() (0)

#define AP_CHECK_USER_ID_RETURN_ENABLED() (0)
#define AP_CHILD_INIT_DISPATCH_COMPLETE(arg0, arg1)
#define AP_CHILD_INIT_DISPATCH_COMPLETE_ENABLED() (0)

#define AP_CHILD_INIT_DISPATCH_INVOKE_ENABLED() (0)

#define AP_CHILD_INIT_ENTRY_ENABLED() (0)

#define AP_CHILD_INIT_RETURN_ENABLED() (0)
#define AP_CREATE_CONNECTION_DISPATCH_COMPLETE(arg0, arg1)
#define AP_CREATE_CONNECTION_DISPATCH_COMPLETE_ENABLED() (0)

#define AP_CREATE_CONNECTION_DISPATCH_INVOKE_ENABLED() (0)

#define AP_CREATE_CONNECTION_ENTRY_ENABLED() (0)

#define AP_CREATE_CONNECTION_RETURN_ENABLED() (0)
#define AP_CREATE_REQUEST_DISPATCH_COMPLETE(arg0, arg1)
#define AP_CREATE_REQUEST_DISPATCH_COMPLETE_ENABLED() (0)

#define AP_CREATE_REQUEST_DISPATCH_INVOKE_ENABLED() (0)

#define AP_CREATE_REQUEST_ENTRY_ENABLED() (0)

#define AP_CREATE_REQUEST_RETURN_ENABLED() (0)
#define AP_DEFAULT_PORT_DISPATCH_COMPLETE(arg0, arg1)
#define AP_DEFAULT_PORT_DISPATCH_COMPLETE_ENABLED() (0)

#define AP_DEFAULT_PORT_DISPATCH_INVOKE_ENABLED() (0)

#define AP_DEFAULT_PORT_ENTRY_ENABLED() (0)

#define AP_DEFAULT_PORT_RETURN_ENABLED() (0)
#define AP_ERROR_LOG_DISPATCH_COMPLETE(arg0, arg1)
#define AP_ERROR_LOG_DISPATCH_COMPLETE_ENABLED() (0)

#define AP_ERROR_LOG_DISPATCH_INVOKE_ENABLED() (0)

#define AP_ERROR_LOG_ENTRY_ENABLED() (0)

#define AP_ERROR_LOG_RETURN_ENABLED() (0)
#define AP_FIND_LIVEPROP_DISPATCH_COMPLETE(arg0, arg1)
#define AP_FIND_LIVEPROP_DISPATCH_COMPLETE_ENABLED() (0)

#define AP_FIND_LIVEPROP_DISPATCH_INVOKE_ENABLED() (0)

#define AP_FIND_LIVEPROP_ENTRY_ENABLED() (0)

#define AP_FIND_LIVEPROP_RETURN_ENABLED() (0)
#define AP_FIXUPS_DISPATCH_COMPLETE(arg0, arg1)
#define AP_FIXUPS_DISPATCH_COMPLETE_ENABLED() (0)

#define AP_FIXUPS_DISPATCH_INVOKE_ENABLED() (0)

#define AP_FIXUPS_ENTRY_ENABLED() (0)

#define AP_FIXUPS_RETURN_ENABLED() (0)
#define AP_GATHER_PROPSETS_DISPATCH_COMPLETE(arg0, arg1)
#define AP_GATHER_PROPSETS_DISPATCH_COMPLETE_ENABLED() (0)

#define AP_GATHER_PROPSETS_DISPATCH_INVOKE_ENABLED() (0)

#define AP_GATHER_PROPSETS_ENTRY_ENABLED() (0)

#define AP_GATHER_PROPSETS_RETURN_ENABLED() (0)
#define AP_GET_MGMT_ITEMS_DISPATCH_COMPLETE(arg0, arg1)
#define AP_GET_MGMT_ITEMS_DISPATCH_COMPLETE_ENABLED() (0)

#define AP_GET_MGMT_ITEMS_DISPATCH_INVOKE_ENABLED() (0)

#define AP_GET_MGMT_ITEMS_ENTRY_ENABLED() (0)

#define AP_GET_MGMT_ITEMS_RETURN_ENABLED() (0)
#define AP_GET_SUEXEC_IDENTITY_DISPATCH_COMPLETE(arg0, arg1)
#define AP_GET_SUEXEC_IDENTITY_DISPATCH_COMPLETE_ENABLED() (0)

#define AP_GET_SUEXEC_IDENTITY_DISPATCH_INVOKE_ENABLED() (0)

#define AP_GET_SUEXEC_IDENTITY_ENTRY_ENABLED() (0)

#define AP_GET_SUEXEC_IDENTITY_RETURN_ENABLED() (0)
#define AP_HANDLER_DISPATCH_COMPLETE(arg0, arg1)
#define AP_HANDLER_DISPATCH_COMPLETE_ENABLED() (0)

#define AP_HANDLER_DISPATCH_INVOKE_ENABLED() (0)

#define AP_HANDLER_ENTRY_ENABLED() (0)

#define AP_HANDLER_RETURN_ENABLED() (0)
#define AP_HEADER_PARSER_DISPATCH_COMPLETE(arg0, arg1)
#define AP_HEADER_PARSER_DISPATCH_COMPLETE_ENABLED() (0)

#define AP_HEADER_PARSER_DISPATCH_INVOKE_ENABLED() (0)

#define AP_HEADER_PARSER_ENTRY_ENABLED() (0)

#define AP_HEADER_PARSER_RETURN_ENABLED() (0)
#define AP_HTTP_SCHEME_DISPATCH_COMPLETE(arg0, arg1)
#define AP_HTTP_SCHEME_DISPATCH_COMPLETE_ENABLED() (0)

#define AP_HTTP_SCHEME_DISPATCH_INVOKE_ENABLED() (0)

#define AP_HTTP_SCHEME_ENTRY_ENABLED() (0)

#define AP_HTTP_SCHEME_RETURN_ENABLED() (0)
#define AP_INSERT_ALL_LIVEPROPS_DISPATCH_COMPLETE(arg0, arg1)
#define AP_INSERT_ALL_LIVEPROPS_DISPATCH_COMPLETE_ENABLED() (0)

#define AP_INSERT_ALL_LIVEPROPS_DISPATCH_INVOKE_ENABLED() (0)

#define AP_INSERT_ALL_LIVEPROPS_ENTRY_ENABLED() (0)

#define AP_INSERT_ALL_LIVEPROPS_RETURN_ENABLED() (0)
#define AP_INSERT_ERROR_FILTER_DISPATCH_COMPLETE(arg0, arg1)
#define AP_INSERT_ERROR_FILTER_DISPATCH_COMPLETE_ENABLED() (0)

#define AP_INSERT_ERROR_FILTER_DISPATCH_INVOKE_ENABLED() (0)

#define AP_INSERT_ERROR_FILTER_ENTRY_ENABLED() (0)

#define AP_INSERT_ERROR_FILTER_RETURN_ENABLED() (0)
#define AP_INSERT_FILTER_DISPATCH_COMPLETE(arg0, arg1)
#define AP_INSERT_FILTER_DISPATCH_COMPLETE_ENABLED() (0)

#define AP_INSERT_FILTER_DISPATCH_INVOKE_ENABLED() (0)

#define AP_INSERT_FILTER_ENTRY_ENABLED() (0)

#define AP_INSERT_FILTER_RETURN_ENABLED() (0)
#define AP_INTERNAL_REDIRECT(arg0, arg1)
#define AP_INTERNAL_REDIRECT_ENABLED() (0)
#define AP_LOG_TRANSACTION_DISPATCH_COMPLETE(arg0, arg1)
#define AP_LOG_TRANSACTION_DISPATCH_COMPLETE_ENABLED() (0)

#define AP_LOG_TRANSACTION_DISPATCH_INVOKE_ENABLED() (0)

#define AP_LOG_TRANSACTION_ENTRY_ENABLED() (0)

#define AP_LOG_TRANSACTION_RETURN_ENABLED() (0)
#define AP_MAP_TO_STORAGE_DISPATCH_COMPLETE(arg0, arg1)
#define AP_MAP_TO_STORAGE_DISPATCH_COMPLETE_ENABLED() (0)

#define AP_MAP_TO_STORAGE_DISPATCH_INVOKE_ENABLED() (0)

#define AP_MAP_TO_STORAGE_ENTRY_ENABLED() (0)

#define AP_MAP_TO_STORAGE_RETURN_ENABLED() (0)
#define AP_MONITOR_DISPATCH_COMPLETE(arg0, arg1)
#define AP_MONITOR_DISPATCH_COMPLETE_ENABLED() (0)

#define AP_MONITOR_DISPATCH_INVOKE_ENABLED() (0)

#define AP_MONITOR_ENTRY_ENABLED() (0)

#define AP_MONITOR_RETURN_ENABLED() (0)
#define AP_OPEN_LOGS_DISPATCH_COMPLETE(arg0, arg1)
#define AP_OPEN_LOGS_DISPATCH_COMPLETE_ENABLED() (0)

#define AP_OPEN_LOGS_DISPATCH_INVOKE_ENABLED() (0)

#define AP_OPEN_LOGS_ENTRY_ENABLED() (0)

#define AP_OPEN_LOGS_RETURN_ENABLED() (0)
#define AP_OPTIONAL_FN_RETRIEVE_DISPATCH_COMPLETE(arg0, arg1)
#define AP_OPTIONAL_FN_RETRIEVE_DISPATCH_COMPLETE_ENABLED() (0)

#define AP_OPTIONAL_FN_RETRIEVE_DISPATCH_INVOKE_ENABLED() (0)

#define AP_OPTIONAL_FN_RETRIEVE_ENTRY_ENABLED() (0)

#define AP_OPTIONAL_FN_RETRIEVE_RETURN_ENABLED() (0)
#define AP_POST_CONFIG_DISPATCH_COMPLETE(arg0, arg1)
#define AP_POST_CONFIG_DISPATCH_COMPLETE_ENABLED() (0)

#define AP_POST_CONFIG_DISPATCH_INVOKE_ENABLED() (0)

#define AP_POST_CONFIG_ENTRY_ENABLED() (0)

#define AP_POST_CONFIG_RETURN_ENABLED() (0)
#define AP_POST_READ_REQUEST_DISPATCH_COMPLETE(arg0, arg1)
#define AP_POST_READ_REQUEST_DISPATCH_COMPLETE_ENABLED() (0)

#define AP_POST_READ_REQUEST_DISPATCH_INVOKE_ENABLED() (0)

#define AP_POST_READ_REQUEST_ENTRY_ENABLED() (0)

#define AP_POST_READ_REQUEST_RETURN_ENABLED() (0)
#define AP_POST_REQUEST_DISPATCH_COMPLETE(arg0, arg1)
#define AP_POST_REQUEST_DISPATCH_COMPLETE_ENABLED() (0)

#define AP_POST_REQUEST_DISPATCH_INVOKE_ENABLED() (0)

#define AP_POST_REQUEST_ENTRY_ENABLED() (0)

#define AP_POST_REQUEST_RETURN_ENABLED() (0)
#define AP_PRE_CONFIG_DISPATCH_COMPLETE(arg0, arg1)
#define AP_PRE_CONFIG_DISPATCH_COMPLETE_ENABLED() (0)

#define AP_PRE_CONFIG_DISPATCH_INVOKE_ENABLED() (0)

#define AP_PRE_CONFIG_ENTRY_ENABLED() (0)

#define AP_PRE_CONFIG_RETURN_ENABLED() (0)
#define AP_PRE_CONNECTION_DISPATCH_COMPLETE(arg0, arg1)
#define AP_PRE_CONNECTION_DISPATCH_COMPLETE_ENABLED() (0)

#define AP_PRE_CONNECTION_DISPATCH_INVOKE_ENABLED() (0)

#define AP_PRE_CONNECTION_ENTRY_ENABLED() (0)

#define AP_PRE_CONNECTION_RETURN_ENABLED() (0)
#define AP_PRE_MPM_DISPATCH_COMPLETE(arg0, arg1)
#define AP_PRE_MPM_DISPATCH_COMPLETE_ENABLED() (0)

#define AP_PRE_MPM_DISPATCH_INVOKE_ENABLED() (0)

#define AP_PRE_MPM_ENTRY_ENABLED() (0)

#define AP_PRE_MPM_RETURN_ENABLED() (0)
#define AP_PRE_REQUEST_DISPATCH_COMPLETE(arg0, arg1)
#define AP_PRE_REQUEST_DISPATCH_COMPLETE_ENABLED() (0)

#define AP_PRE_REQUEST_DISPATCH_INVOKE_ENABLED() (0)

#define AP_PRE_REQUEST_ENTRY_ENABLED() (0)

#define AP_PRE_REQUEST_RETURN_ENABLED() (0)
#define AP_PROCESS_CONNECTION_DISPATCH_COMPLETE(arg0, arg1)
#define AP_PROCESS_CONNECTION_DISPATCH_COMPLETE_ENABLED() (0)

#define AP_PROCESS_CONNECTION_DISPATCH_INVOKE_ENABLED() (0)

#define AP_PROCESS_CONNECTION_ENTRY_ENABLED() (0)

#define AP_PROCESS_CONNECTION_RETURN_ENABLED() (0)
#define AP_PROCESS_REQUEST_ENTRY(arg0, arg1)
#define AP_PROCESS_REQUEST_ENTRY_ENABLED() (0)
#define AP_PROCESS_REQUEST_RETURN(arg0, arg1, arg2)
#define AP_PROCESS_REQUEST_RETURN_ENABLED() (0)
#define AP_PROXY_RUN(arg0, arg1, arg2, arg3, arg4)
#define AP_PROXY_RUN_ENABLED() (0)
#define AP_PROXY_RUN_FINISHED(arg0, arg1, arg2)
#define AP_PROXY_RUN_FINISHED_ENABLED() (0)
#define AP_QUICK_HANDLER_DISPATCH_COMPLETE(arg0, arg1)
#define AP_QUICK_HANDLER_DISPATCH_COMPLETE_ENABLED() (0)

#define AP_QUICK_HANDLER_DISPATCH_INVOKE_ENABLED() (0)

#define AP_QUICK_HANDLER_ENTRY_ENABLED() (0)

#define AP_QUICK_HANDLER_RETURN_ENABLED() (0)
#define AP_READ_REQUEST_ENTRY(arg0, arg1)
#define AP_READ_REQUEST_ENTRY_ENABLED() (0)

#define AP_READ_REQUEST_FAILURE_ENABLED() (0)
#define AP_READ_REQUEST_SUCCESS(arg0, arg1, arg2, arg3, arg4)
#define AP_READ_REQUEST_SUCCESS_ENABLED() (0)
#define AP_REWRITE_LOG(arg0, arg1, arg2, arg3, arg4)
#define AP_REWRITE_LOG_ENABLED() (0)
#define AP_SCHEME_HANDLER_DISPATCH_COMPLETE(arg0, arg1)
#define AP_SCHEME_HANDLER_DISPATCH_COMPLETE_ENABLED() (0)

#define AP_SCHEME_HANDLER_DISPATCH_INVOKE_ENABLED() (0)

#define AP_SCHEME_HANDLER_ENTRY_ENABLED() (0)

#define AP_SCHEME_HANDLER_RETURN_ENABLED() (0)
#define AP_TEST_CONFIG_DISPATCH_COMPLETE(arg0, arg1)
#define AP_TEST_CONFIG_DISPATCH_COMPLETE_ENABLED() (0)

#define AP_TEST_CONFIG_DISPATCH_INVOKE_ENABLED() (0)

#define AP_TEST_CONFIG_ENTRY_ENABLED() (0)

#define AP_TEST_CONFIG_RETURN_ENABLED() (0)
#define AP_TRANSLATE_NAME_DISPATCH_COMPLETE(arg0, arg1)
#define AP_TRANSLATE_NAME_DISPATCH_COMPLETE_ENABLED() (0)

#define AP_TRANSLATE_NAME_DISPATCH_INVOKE_ENABLED() (0)

#define AP_TRANSLATE_NAME_ENTRY_ENABLED() (0)

#define AP_TRANSLATE_NAME_RETURN_ENABLED() (0)
#define AP_TYPE_CHECKER_DISPATCH_COMPLETE(arg0, arg1)
#define AP_TYPE_CHECKER_DISPATCH_COMPLETE_ENABLED() (0)

#define AP_TYPE_CHECKER_DISPATCH_INVOKE_ENABLED() (0)

#define AP_TYPE_CHECKER_ENTRY_ENABLED() (0)

#define AP_TYPE_CHECKER_RETURN_ENABLED() (0)

#define APR_HOOK_PROBES_ENABLED 1
#define AP_DECLARE_HOOK(ret,name,args) \
        APR_DECLARE_EXTERNAL_HOOK(ap,AP,ret,name,args)

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
#define AP_OPTIONAL_HOOK(name,fn,pre,succ,order) \
        APR_OPTIONAL_HOOK(ap,name,fn,pre,succ,order)

#define APLOGNO(n)              "AH" #n ": "
#define APLOG_ALERT     LOG_ALERT       
#define APLOG_CRIT      LOG_CRIT        
#define APLOG_CS_IS_LEVEL(c,s,level) \
    APLOG_CS_MODULE_IS_LEVEL(c,s,APLOG_MODULE_INDEX,level)
#define APLOG_CS_MODULE_IS_LEVEL(c,s,module_index,level)            \
          ( (((level)&APLOG_LEVELMASK) <= APLOG_NOTICE) ||          \
            (ap_get_conn_server_module_loglevel(c, s, module_index) \
             >= ((level)&APLOG_LEVELMASK) ) )
#define APLOG_C_IS_LEVEL(c,level)   \
    APLOG_C_MODULE_IS_LEVEL(c,APLOG_MODULE_INDEX,level)
#define APLOG_C_MODULE_IS_LEVEL(c,module_index,level)            \
          ( (((level)&APLOG_LEVELMASK) <= APLOG_NOTICE) ||       \
            (ap_get_conn_module_loglevel(c, module_index)        \
             >= ((level)&APLOG_LEVELMASK) ) )
#define APLOG_DEBUG     LOG_DEBUG       
#define APLOG_EMERG     LOG_EMERG       
#define APLOG_ERR       LOG_ERR         
#define APLOG_INFO      LOG_INFO        
#define APLOG_IS_LEVEL(s,level)     \
    APLOG_MODULE_IS_LEVEL(s,APLOG_MODULE_INDEX,level)
#define APLOG_LEVELMASK 15     
#define APLOG_MARK     "__FILE__","__LINE__",APLOG_MODULE_INDEX

#define APLOG_MODULE_INDEX (*aplog_module_index)
#define APLOG_MODULE_IS_LEVEL(s,module_index,level)              \
          ( (((level)&APLOG_LEVELMASK) <= APLOG_NOTICE) ||       \
            (s == NULL) ||                                       \
            (ap_get_server_module_loglevel(s, module_index)      \
             >= ((level)&APLOG_LEVELMASK) ) )
#define APLOG_NOERRNO           (APLOG_LEVELMASK + 1)
#define APLOG_NOTICE    LOG_NOTICE      
#define APLOG_NO_MODULE         -1
#define APLOG_R_IS_LEVEL(r,level)   \
    APLOG_R_MODULE_IS_LEVEL(r,APLOG_MODULE_INDEX,level)
#define APLOG_R_MODULE_IS_LEVEL(r,module_index,level)            \
          ( (((level)&APLOG_LEVELMASK) <= APLOG_NOTICE) ||       \
            (ap_get_request_module_loglevel(r, module_index)     \
             >= ((level)&APLOG_LEVELMASK) ) )
#define APLOG_STARTUP           ((APLOG_LEVELMASK + 1) * 4)
#define APLOG_TOCLIENT          ((APLOG_LEVELMASK + 1) * 2)
#define APLOG_TRACE1   (LOG_DEBUG + 1)  
#define APLOG_TRACE2   (LOG_DEBUG + 2)  
#define APLOG_TRACE3   (LOG_DEBUG + 3)  
#define APLOG_TRACE4   (LOG_DEBUG + 4)  
#define APLOG_TRACE5   (LOG_DEBUG + 5)  
#define APLOG_TRACE6   (LOG_DEBUG + 6)  
#define APLOG_TRACE7   (LOG_DEBUG + 7)  
#define APLOG_TRACE8   (LOG_DEBUG + 8)  
#define APLOG_WARNING   LOG_WARNING     
#define APLOGcdebug(c)              APLOG_C_IS_LEVEL(c,APLOG_DEBUG)
#define APLOGcinfo(c)               APLOG_C_IS_LEVEL(c,APLOG_INFO)
#define APLOGctrace1(c)             APLOG_C_IS_LEVEL(c,APLOG_TRACE1)
#define APLOGctrace2(c)             APLOG_C_IS_LEVEL(c,APLOG_TRACE2)
#define APLOGctrace3(c)             APLOG_C_IS_LEVEL(c,APLOG_TRACE3)
#define APLOGctrace4(c)             APLOG_C_IS_LEVEL(c,APLOG_TRACE4)
#define APLOGctrace5(c)             APLOG_C_IS_LEVEL(c,APLOG_TRACE5)
#define APLOGctrace6(c)             APLOG_C_IS_LEVEL(c,APLOG_TRACE6)
#define APLOGctrace7(c)             APLOG_C_IS_LEVEL(c,APLOG_TRACE7)
#define APLOGctrace8(c)             APLOG_C_IS_LEVEL(c,APLOG_TRACE8)
#define APLOGdebug(s)               APLOG_IS_LEVEL(s,APLOG_DEBUG)
#define APLOGinfo(s)                APLOG_IS_LEVEL(s,APLOG_INFO)
#define APLOGrdebug(r)              APLOG_R_IS_LEVEL(r,APLOG_DEBUG)
#define APLOGrinfo(r)               APLOG_R_IS_LEVEL(r,APLOG_INFO)
#define APLOGrtrace1(r)             APLOG_R_IS_LEVEL(r,APLOG_TRACE1)
#define APLOGrtrace2(r)             APLOG_R_IS_LEVEL(r,APLOG_TRACE2)
#define APLOGrtrace3(r)             APLOG_R_IS_LEVEL(r,APLOG_TRACE3)
#define APLOGrtrace4(r)             APLOG_R_IS_LEVEL(r,APLOG_TRACE4)
#define APLOGrtrace5(r)             APLOG_R_IS_LEVEL(r,APLOG_TRACE5)
#define APLOGrtrace6(r)             APLOG_R_IS_LEVEL(r,APLOG_TRACE6)
#define APLOGrtrace7(r)             APLOG_R_IS_LEVEL(r,APLOG_TRACE7)
#define APLOGrtrace8(r)             APLOG_R_IS_LEVEL(r,APLOG_TRACE8)
#define APLOGtrace1(s)              APLOG_IS_LEVEL(s,APLOG_TRACE1)
#define APLOGtrace2(s)              APLOG_IS_LEVEL(s,APLOG_TRACE2)
#define APLOGtrace3(s)              APLOG_IS_LEVEL(s,APLOG_TRACE3)
#define APLOGtrace4(s)              APLOG_IS_LEVEL(s,APLOG_TRACE4)
#define APLOGtrace5(s)              APLOG_IS_LEVEL(s,APLOG_TRACE5)
#define APLOGtrace6(s)              APLOG_IS_LEVEL(s,APLOG_TRACE6)
#define APLOGtrace7(s)              APLOG_IS_LEVEL(s,APLOG_TRACE7)
#define APLOGtrace8(s)              APLOG_IS_LEVEL(s,APLOG_TRACE8)
#define DEFAULT_LOGLEVEL        APLOG_WARNING
#define LOG_PRIMASK 7
#define ap_log_cerror ap_log_cerror_
#define ap_log_cerror__(file, line, mi, level, status, c, ...)              \
    do { if (APLOG_C_MODULE_IS_LEVEL(c, mi, level))                         \
             ap_log_cerror_(file, line, mi, level, status, c, __VA_ARGS__); \
    } while(0)
#define ap_log_cserror ap_log_cserror_
#define ap_log_cserror__(file, line, mi, level, status, c, s, ...)  \
    do { if (APLOG_CS_MODULE_IS_LEVEL(c, s, mi, level))             \
             ap_log_cserror_(file, line, mi, level, status, c, s,   \
                             __VA_ARGS__);                          \
    } while(0)
#define ap_log_error ap_log_error_
#define ap_log_error__(file, line, mi, level, status, s, ...)           \
    do { const server_rec *sr__ = s; if (APLOG_MODULE_IS_LEVEL(sr__, mi, level)) \
             ap_log_error_(file, line, mi, level, status, sr__, __VA_ARGS__);    \
    } while(0)
#define ap_log_perror ap_log_perror_
#define ap_log_perror__(file, line, mi, level, status, p, ...)            \
    do { if ((level) <= APLOG_MAX_LOGLEVEL )                              \
             ap_log_perror_(file, line, mi, level, status, p,             \
                            __VA_ARGS__); } while(0)
#define ap_log_rerror ap_log_rerror_
#define ap_log_rerror__(file, line, mi, level, status, r, ...)              \
    do { if (APLOG_R_MODULE_IS_LEVEL(r, mi, level))                         \
             ap_log_rerror_(file, line, mi, level, status, r, __VA_ARGS__); \
    } while(0)
#define ACCESS_CONF 64       

#define APLOG_USE_MODULE(foo) \
    extern module AP_MODULE_DECLARE_DATA foo##_module;                  \
    static int * const aplog_module_index = &(foo##_module.module_index)
#define AP_DECLARE_MODULE(foo) \
    APLOG_USE_MODULE(foo);                         \
    module AP_MODULE_DECLARE_DATA foo##_module
# define AP_FLAG        func.flag
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
# define AP_NO_ARGS     func.no_args
# define AP_RAW_ARGS    func.raw_args
# define AP_TAKE1       func.take1
# define AP_TAKE2       func.take2
# define AP_TAKE3       func.take3
# define AP_TAKE_ARGV   func.take_argv
#define DECLINE_CMD "\a\b"
#define EXEC_ON_READ 256     
#define  GLOBAL_ONLY            (NOT_IN_VIRTUALHOST|NOT_IN_LIMIT|NOT_IN_DIR_LOC_FILE)
#define MPM20_MODULE_STUFF      MODULE_MAGIC_NUMBER_MAJOR, \
                                MODULE_MAGIC_NUMBER_MINOR, \
                                -1, \
                                "__FILE__", \
                                NULL, \
                                NULL, \
                                MODULE_MAGIC_COOKIE
#define NONFATAL_ALL (NONFATAL_OVERRIDE|NONFATAL_UNKNOWN)
#define NONFATAL_OVERRIDE 512    
#define NONFATAL_UNKNOWN 1024    
#define  NOT_IN_DIRECTORY       0x04 
#define  NOT_IN_DIR_LOC_FILE    (NOT_IN_DIRECTORY|NOT_IN_LOCATION|NOT_IN_FILES)
#define  NOT_IN_FILES           0x10 
#define  NOT_IN_HTACCESS        0x20 
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
#define STANDARD20_MODULE_STUFF MODULE_MAGIC_NUMBER_MAJOR, \
                                MODULE_MAGIC_NUMBER_MINOR, \
                                -1, \
                                "__FILE__", \
                                NULL, \
                                NULL, \
                                MODULE_MAGIC_COOKIE, \
                                NULL      
#define STANDARD_MODULE_STUFF   this_module_needs_to_be_ported_to_apache_2_0
#define ap_get_conn_logconf(c)                     \
    ((c)->log             ? (c)->log             : \
     &(c)->base_server->log)
#define ap_get_conn_module_loglevel(c,i)  \
    (ap_get_module_loglevel(ap_get_conn_logconf(c),i))
#define ap_get_conn_server_logconf(c,s)                             \
    ( ( (c)->log != &(c)->base_server->log && (c)->log != NULL )  ? \
      (c)->log                                                    : \
      &(s)->log )
#define ap_get_conn_server_module_loglevel(c,s,i)  \
    (ap_get_module_loglevel(ap_get_conn_server_logconf(c,s),i))
#define ap_get_module_config(v,m)       \
    (((void **)(v))[(m)->module_index])
#define ap_get_module_loglevel(l,i)                                     \
    (((i) < 0 || (l)->module_levels == NULL || (l)->module_levels[i] < 0) ?  \
     (l)->level :                                                         \
     (l)->module_levels[i])
#define ap_get_request_logconf(r)                  \
    ((r)->log             ? (r)->log             : \
     (r)->connection->log ? (r)->connection->log : \
     &(r)->server->log)
#define ap_get_request_module_loglevel(r,i)  \
    (ap_get_module_loglevel(ap_get_request_logconf(r),i))
#define ap_get_server_module_loglevel(s,i)  \
    (ap_get_module_loglevel(&(s)->log,i))
#define ap_set_module_config(v,m,val)   \
    ((((void **)(v))[(m)->module_index]) = (val))


#define APEXIT_CHILDFATAL       0xf
#define APEXIT_CHILDINIT        0x3
#define APEXIT_CHILDSICK        0x7
#define APEXIT_INIT             0x2
#define APEXIT_OK               0x0
# define AP_CORE_DECLARE        AP_DECLARE
# define AP_CORE_DECLARE_NONSTD AP_DECLARE_NONSTD
#define AP_DEBUG_ASSERT(exp) ap_assert(exp)
# define AP_DECLARE(type)    type
# define AP_DECLARE_DATA
# define AP_DECLARE_NONSTD(type)    type
#define AP_DECLINED                 (AP_START_USERERR + 0)
#define AP_DEFAULT_INDEX "index.html"
#define AP_FILTER_ERROR         -102
#define AP_IOBUFSIZE 8192
#define AP_MAX_REG_MATCH 10
#define AP_MAX_SENDFILE 16777216  
#define AP_METHOD_BIT ((apr_int64_t)1)
# define AP_MODULE_DECLARE(type)    type
# define AP_MODULE_DECLARE_DATA
# define AP_MODULE_DECLARE_NONSTD(type)  type
#define AP_NOBODY_READ          -101
#define AP_NOBODY_WROTE         -100
#define AP_NORESTART APR_OS_START_USEERR + 1
#define AP_REQ_ACCEPT_PATH_INFO    0
#define AP_REQ_DEFAULT_PATH_INFO   2
#define AP_REQ_REJECT_PATH_INFO    1
#define AP_SERVER_PROTOCOL "HTTP/1.1"
#define AP_START_USERERR            (APR_OS_START_USERERR + 2000)
#define AP_TYPES_CONFIG_FILE "conf/mime.types"
#define AP_USERERR_LEN              1000
#define CGI_MAGIC_TYPE "application/x-httpd-cgi"
#define CR 13
#define CRLF_ASCII "\015\012"
#define DECLINED -1             
#define DEFAULT_ACCESS_FNAME "htaccess"
#define DEFAULT_ADD_DEFAULT_CHARSET_NAME "iso-8859-1"
#define DEFAULT_ADMIN "[no address given]"
#define DEFAULT_ERRORLOG "logs/error.log"
#define DEFAULT_HTTPS_PORT      443
#define DEFAULT_HTTP_PORT       80
#define DEFAULT_KEEPALIVE 100
#define DEFAULT_KEEPALIVE_TIMEOUT 5
#define DEFAULT_LIMIT_REQUEST_FIELDS 100
#define DEFAULT_LIMIT_REQUEST_FIELDSIZE 8190
#define DEFAULT_LIMIT_REQUEST_LINE 8190
#define DEFAULT_PATH "/bin:/usr/bin:/usr/ucb:/usr/bsd:/usr/local/bin"
#define DEFAULT_TIMEOUT 60
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
#define DYNAMIC_MODULE_LIMIT 256
#define HTTPD_ROOT "/os2httpd"
#define HTTP_ACCEPTED                        202
#define HTTP_ALREADY_REPORTED                208
#define HTTP_BAD_GATEWAY                     502
#define HTTP_BAD_REQUEST                     400
#define HTTP_CONFLICT                        409
#define HTTP_CONTINUE                        100
#define HTTP_CREATED                         201
#define HTTP_EXPECTATION_FAILED              417
#define HTTP_FAILED_DEPENDENCY               424
#define HTTP_FORBIDDEN                       403
#define HTTP_GATEWAY_TIME_OUT                504
#define HTTP_GONE                            410
#define HTTP_IM_USED                         226
#define HTTP_INSUFFICIENT_STORAGE            507
#define HTTP_INTERNAL_SERVER_ERROR           500
#define HTTP_LENGTH_REQUIRED                 411
#define HTTP_LOCKED                          423
#define HTTP_LOOP_DETECTED                   508
#define HTTP_METHOD_NOT_ALLOWED              405
#define HTTP_MOVED_PERMANENTLY               301
#define HTTP_MOVED_TEMPORARILY               302
#define HTTP_MULTIPLE_CHOICES                300
#define HTTP_MULTI_STATUS                    207
#define HTTP_NETWORK_AUTHENTICATION_REQUIRED 511
#define HTTP_NON_AUTHORITATIVE               203
#define HTTP_NOT_ACCEPTABLE                  406
#define HTTP_NOT_EXTENDED                    510
#define HTTP_NOT_FOUND                       404
#define HTTP_NOT_IMPLEMENTED                 501
#define HTTP_NOT_MODIFIED                    304
#define HTTP_NO_CONTENT                      204
#define HTTP_OK                              200
#define HTTP_PARTIAL_CONTENT                 206
#define HTTP_PAYMENT_REQUIRED                402
#define HTTP_PERMANENT_REDIRECT              308
#define HTTP_PRECONDITION_FAILED             412
#define HTTP_PRECONDITION_REQUIRED           428
#define HTTP_PROCESSING                      102
#define HTTP_PROXY_AUTHENTICATION_REQUIRED   407
#define HTTP_RANGE_NOT_SATISFIABLE           416
#define HTTP_REQUEST_ENTITY_TOO_LARGE        413
#define HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE 431
#define HTTP_REQUEST_TIME_OUT                408
#define HTTP_REQUEST_URI_TOO_LARGE           414
#define HTTP_RESET_CONTENT                   205
#define HTTP_SEE_OTHER                       303
#define HTTP_SERVICE_UNAVAILABLE             503
#define HTTP_SWITCHING_PROTOCOLS             101
#define HTTP_TEMPORARY_REDIRECT              307
#define HTTP_TOO_MANY_REQUESTS               429
#define HTTP_UNAUTHORIZED                    401
#define HTTP_UNPROCESSABLE_ENTITY            422
#define HTTP_UNSUPPORTED_MEDIA_TYPE          415
#define HTTP_UPGRADE_REQUIRED                426
#define HTTP_USE_PROXY                       305
#define HTTP_VARIANT_ALSO_VARIES             506
#define HTTP_VERSION(major,minor) (1000*(major)+(minor))
#define HTTP_VERSION_MAJOR(number) ((number)/1000)
#define HTTP_VERSION_MINOR(number) ((number)%1000)
#define HTTP_VERSION_NOT_SUPPORTED           505
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
#define PROXYREQ_NONE     0     
#define PROXYREQ_PROXY    1     
#define PROXYREQ_RESPONSE 3     
#define PROXYREQ_REVERSE  2     
#define RAISE_SIGSTOP(x)        do { \
        if (raise_sigstop_flags & SIGSTOP_##x) raise(SIGSTOP);\
    } while (0)
#define REQUEST_CHUNKED_DECHUNK  2
#define REQUEST_CHUNKED_ERROR    1
#define REQUEST_NO_BODY          0
#define RESPONSE_CODES 83
#define SERVER_CONFIG_FILE "conf/httpd.conf"
#define SIGSTOP_CGI_CHILD               16
#define SIGSTOP_DETACH                  1
#define SIGSTOP_MAKE_CHILD              2
#define SIGSTOP_PIPED_LOG_SPAWN         8
#define SIGSTOP_SPAWN_CHILD             4
#define SUEXEC_BIN  HTTPD_ROOT "/bin/suexec"
#define SUSPENDED -3 
#define ap_assert(exp) ((exp) ? (void)0 : ap_log_assert(#exp,"__FILE__","__LINE__"))
#define ap_default_port(r)      ap_run_default_port(r)
#define ap_escape_html(p,s) ap_escape_html2(p,s,0)
#define ap_escape_uri(ppool,path) ap_os_escape_path(ppool,path,1)
#define ap_http_scheme(r)       ap_run_http_scheme(r)
#define ap_is_HTTP_CLIENT_ERROR(x) (((x) >= 400)&&((x) < 500))
#define ap_is_HTTP_ERROR(x)        (((x) >= 400)&&((x) < 600))
#define ap_is_HTTP_INFO(x)         (((x) >= 100)&&((x) < 200))
#define ap_is_HTTP_REDIRECT(x)     (((x) >= 300)&&((x) < 400))
#define ap_is_HTTP_SERVER_ERROR(x) (((x) >= 500)&&((x) < 600))
#define ap_is_HTTP_SUCCESS(x)      (((x) >= 200)&&((x) < 300))
#define ap_is_HTTP_VALID_RESPONSE(x) (((x) >= 100)&&((x) < 600))
#define ap_is_default_port(port,r)      ((port) == ap_default_port(r))
#define ap_status_drops_connection(x) \
                                   (((x) == HTTP_BAD_REQUEST)           || \
                                    ((x) == HTTP_REQUEST_TIME_OUT)      || \
                                    ((x) == HTTP_LENGTH_REQUIRED)       || \
                                    ((x) == HTTP_REQUEST_ENTITY_TOO_LARGE) || \
                                    ((x) == HTTP_REQUEST_URI_TOO_LARGE) || \
                                    ((x) == HTTP_INTERNAL_SERVER_ERROR) || \
                                    ((x) == HTTP_SERVICE_UNAVAILABLE) || \
                                    ((x) == HTTP_NOT_IMPLEMENTED))
# define ap_strchr(s, c)     strchr(s, c)
# define ap_strchr_c(s, c)   strchr(s, c)
# define ap_strrchr(s, c)    strrchr(s, c)
# define ap_strrchr_c(s, c)  strrchr(s, c)
# define ap_strstr(s, c)     strstr(s, c)
# define ap_strstr_c(s, c)   strstr(s, c)
#define apr_palloc     ap_palloc_debug
#define apr_pcalloc    ap_pcalloc_debug
# define strchr(s, c)  ap_strchr(s,c)
# define strrchr(s, c) ap_strrchr(s,c)
# define strstr(s, c)  ap_strstr(s,c)
#define strtoul strtoul_is_not_a_portable_function_use_strtol_instead

#define AP_SERVER_ADD_STRING          "-dev"
#define AP_SERVER_BASEPRODUCT "Apache"
#define AP_SERVER_BASEPROJECT "Apache HTTP Server"
#define AP_SERVER_BASEREVISION  AP_SERVER_MINORREVISION "." AP_SERVER_PATCHLEVEL
#define AP_SERVER_BASEVENDOR "Apache Software Foundation"
#define AP_SERVER_BASEVERSION   AP_SERVER_BASEPRODUCT "/" AP_SERVER_BASEREVISION
#define AP_SERVER_COPYRIGHT \
  "Copyright 2012 The Apache Software Foundation."
#define AP_SERVER_DEVBUILD_BOOLEAN    1
#define AP_SERVER_MAJORVERSION  APR_STRINGIFY(AP_SERVER_MAJORVERSION_NUMBER)
#define AP_SERVER_MAJORVERSION_NUMBER 2
#define AP_SERVER_MINORREVISION AP_SERVER_MAJORVERSION "." AP_SERVER_MINORVERSION
#define AP_SERVER_MINORVERSION  APR_STRINGIFY(AP_SERVER_MINORVERSION_NUMBER)
#define AP_SERVER_MINORVERSION_NUMBER 5
#define AP_SERVER_PATCHLEVEL    APR_STRINGIFY(AP_SERVER_PATCHLEVEL_NUMBER) \
                                AP_SERVER_ADD_STRING
#define AP_SERVER_PATCHLEVEL_CSV AP_SERVER_MAJORVERSION_NUMBER, \
                                 AP_SERVER_MINORVERSION_NUMBER, \
                                 AP_SERVER_PATCHLEVEL_NUMBER
#define AP_SERVER_PATCHLEVEL_NUMBER   0
#define AP_SERVER_VERSION       AP_SERVER_BASEVERSION

#define AP_MODULE_MAGIC_AT_LEAST(major,minor)           \
    ((major) < MODULE_MAGIC_NUMBER_MAJOR                \
     || ((major) == MODULE_MAGIC_NUMBER_MAJOR           \
         && (minor) <= MODULE_MAGIC_NUMBER_MINOR))
#define MODULE_MAGIC_AT_LEAST old_broken_macro_we_hope_you_are_not_using
#define MODULE_MAGIC_COOKIE 0x41503235UL 
#define MODULE_MAGIC_NUMBER MODULE_MAGIC_NUMBER_MAJOR
#define MODULE_MAGIC_NUMBER_MAJOR 20120724
#define MODULE_MAGIC_NUMBER_MINOR 1                   



#define AP_FILTER_PROTO_CHANGE 0x1
#define AP_FILTER_PROTO_CHANGE_LENGTH 0x2
#define AP_FILTER_PROTO_NO_BYTERANGE 0x4
#define AP_FILTER_PROTO_NO_CACHE 0x10
#define AP_FILTER_PROTO_NO_PROXY 0x8
#define AP_FILTER_PROTO_TRANSFORM 0x20
#define ap_fputc(f, bb, c) \
        apr_brigade_putc(bb, ap_filter_flush, f, c)
#define ap_fputs(f, bb, str) \
        apr_brigade_puts(bb, ap_filter_flush, f, str)
#define ap_fwrite(f, bb, data, nbyte) \
        apr_brigade_write(bb, ap_filter_flush, f, data, nbyte)

#define AP_BUCKET_IS_EOC(e)         (e->type == &ap_bucket_type_eoc)

#define AP_SERVER_BASEARGS "C:c:D:d:E:e:f:vVlLtTSMh?X"


#define AP_AUTH_INTERNAL_MASK     0x000F  
#define AP_AUTH_INTERNAL_PER_CONF 1  
#define AP_AUTH_INTERNAL_PER_URI  0  
#define AP_BUCKET_IS_EOR(e)         (e->type == &ap_bucket_type_eor)
#define AP_SUBREQ_MERGE_ARGS 1
#define AP_SUBREQ_NO_ARGS 0
#define MERGE_ALLOW 0
#define REPLACE_ALLOW 1

#define AP_BUCKET_IS_ERROR(e)         (e->type == &ap_bucket_type_error)
#define AP_METHOD_CHECK_ALLOWED(mask, methname) \
    ((mask) & (AP_METHOD_BIT << ap_method_number_of((methname))))
#define ap_rgetline(s, n, read, r, fold, bb) \
        ap_rgetline_core((s), (n), (read), (r), (fold), (bb))
#define ADD_DEFAULT_CHARSET_OFF   (0)
#define ADD_DEFAULT_CHARSET_ON    (1)
#define ADD_DEFAULT_CHARSET_UNSET (2)

#define AP_CONDITION_ELSE      2
#define AP_CONDITION_ELSEIF    (AP_CONDITION_ELSE|AP_CONDITION_IF)
#define AP_CONDITION_IF        1
#define AP_CORE_MODULE_INDEX  0
# define AP_DEFAULT_MAX_INTERNAL_REDIRECTS 10
# define AP_DEFAULT_MAX_SUBREQ_DEPTH 10
#define AP_ERRORLOG_FLAG_FIELD_SEP       1
#define AP_ERRORLOG_FLAG_MESSAGE         2
#define AP_ERRORLOG_FLAG_NULL_AS_HYPHEN  8
#define AP_ERRORLOG_FLAG_REQUIRED        4
#define AP_MAXRANGES_DEFAULT   -2
#define AP_MAXRANGES_NORANGES   0
#define AP_MAXRANGES_UNLIMITED -3
#define AP_MAXRANGES_UNSET     -1
#define AP_MIN_BYTES_TO_WRITE  8000
#define AP_NOTE_DIRECTORY_WALK 0
#define AP_NOTE_FILE_WALK      2
#define AP_NOTE_IF_WALK        3
#define AP_NOTE_LOCATION_WALK  1
#define AP_NUM_STD_NOTES       4
#define AP_SENDFILE_ENABLED(x) \
    ((x) == ENABLE_SENDFILE_ON ? APR_SENDFILE_ENABLED : 0)
#define AP_SQ_CONFIG_GEN        2
#define AP_SQ_MAIN_STATE        0
#define AP_SQ_MS_CREATE_CONFIG     4
#define AP_SQ_MS_CREATE_PRE_CONFIG 2
#define AP_SQ_MS_DESTROY_CONFIG    3
#define AP_SQ_MS_EXITING           6
#define AP_SQ_MS_INITIAL_STARTUP   1
#define AP_SQ_MS_RUN_MPM           5
#define AP_SQ_NOT_SUPPORTED       -1
#define AP_SQ_RM_CONFIG_DUMP       4
#define AP_SQ_RM_CONFIG_TEST       3
#define AP_SQ_RM_NORMAL            2
#define AP_SQ_RM_UNKNOWN           1
#define AP_SQ_RUN_MODE          1
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
#define ETAG_BACKWARD (ETAG_MTIME | ETAG_SIZE)
#define ETAG_INODE (1 << 2)
#define ETAG_MTIME (1 << 1)
#define ETAG_NONE  (1 << 0)
#define ETAG_SIZE  (1 << 3)
#define ETAG_UNSET 0
#define HOSTNAME_LOOKUP_DOUBLE  2
#define HOSTNAME_LOOKUP_OFF     0
#define HOSTNAME_LOOKUP_ON      1
#define HOSTNAME_LOOKUP_UNSET   3
#define OPT_ALL (OPT_INDEXES|OPT_INCLUDES|OPT_INC_WITH_EXEC|OPT_SYM_LINKS|OPT_EXECCGI)
#define OPT_EXECCGI 8
#define OPT_INCLUDES 2
#define OPT_INC_WITH_EXEC 32
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
#define ap_get_core_module_config(v) \
    (((void **)(v))[AP_CORE_MODULE_INDEX])
#define ap_set_core_module_config(v, val) \
    ((((void **)(v))[AP_CORE_MODULE_INDEX]) = (val))
#define AP_EXPR_FLAG_DONT_VARY             2
#define AP_EXPR_FLAG_RESTRICTED            4
#define AP_EXPR_FLAG_SSL_EXPR_COMPAT       1
#define AP_EXPR_FLAG_STRING_RESULT         8
#define AP_EXPR_FUNC_LIST       2
#define AP_EXPR_FUNC_OP_BINARY  4
#define AP_EXPR_FUNC_OP_UNARY   3
#define AP_EXPR_FUNC_STRING     1
#define AP_EXPR_FUNC_VAR        0

#define ap_expr_parse_cmd(cmd, expr, flags, err, lookup_fn) \
        ap_expr_parse_cmd_mi(cmd, expr, flags, err, lookup_fn, APLOG_MODULE_INDEX)
#define AP_ALL_AVAILABLE_MUTEXES_STRING                  \
    "Mutex mechanisms are: 'none', 'default'"            \
    AP_LIST_FLOCK_SERIALIZE   AP_LIST_FCNTL_SERIALIZE    \
    AP_LIST_FILE_SERIALIZE    AP_LIST_PTHREAD_SERIALIZE  \
    AP_LIST_SYSVSEM_SERIALIZE AP_LIST_POSIXSEM_SERIALIZE \
    AP_LIST_SEM_SERIALIZE
#define AP_AVAILABLE_MUTEXES_STRING                      \
    "Mutex mechanisms are: 'default'"                    \
    AP_LIST_FLOCK_SERIALIZE   AP_LIST_FCNTL_SERIALIZE    \
    AP_LIST_FILE_SERIALIZE    AP_LIST_PTHREAD_SERIALIZE  \
    AP_LIST_SYSVSEM_SERIALIZE AP_LIST_POSIXSEM_SERIALIZE \
    AP_LIST_SEM_SERIALIZE
# define AP_LIST_FCNTL_SERIALIZE ", 'fcntl:/path/to/file'"
# define AP_LIST_FILE_SERIALIZE ", 'file:/path/to/file'"
# define AP_LIST_FLOCK_SERIALIZE ", 'flock:/path/to/file'"
# define AP_LIST_POSIXSEM_SERIALIZE ", 'posixsem'"
# define AP_LIST_PTHREAD_SERIALIZE ", 'pthread'"
# define AP_LIST_SEM_SERIALIZE ", 'sem'"
# define AP_LIST_SYSVSEM_SERIALIZE ", 'sysvsem'"
#define AP_MUTEX_ALLOW_NONE    1 
#define AP_MUTEX_DEFAULT_NONE  2 

