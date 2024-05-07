

#include<inttypes.h>
#include<sys/types.h>
#include<stddef.h>
#include<errno.h>
#include<poll.h>
#include<time.h>
#include<ctype.h>
#include<stdint.h>

#include<locale.h>


#include<regex.h>
#include<stdio.h>
#include<netinet/in.h>
#include<unistd.h>
#include<sys/stat.h>
#include<stdlib.h>
#include<stdbool.h>
#include<string.h>
#include<stdarg.h>
#include<libintl.h>



#define CM_DEBUG(cm_ctx, format, ...) do { \
    if (cm_ctx != NULL && cm_ctx->debug != NULL) { \
        cm_ctx->debug(cm_ctx->debug_priv, "__FILE__", "__LINE__", __FUNCTION__, \
                      format, ##__VA_ARGS__); \
    } \
} while (0)
#define DEFAULT_MAP_RULE "LDAP:(userCertificate;binary={cert!bin})"
#define DEFAULT_MATCH_RULE "<KU>digitalSignature<EKU>clientAuth"
#define NT_PRINCIPAL_OID "1.3.6.1.4.1.311.20.2.3"
#define PKINIT_OID "1.3.6.1.5.2.2"
#define SSS_KU_CRL_SIGN             0x0002
#define SSS_KU_DATA_ENCIPHERMENT    0x0010
#define SSS_KU_DECIPHER_ONLY        0x8000
#define SSS_KU_DIGITAL_SIGNATURE    0x0080
#define SSS_KU_ENCIPHER_ONLY        0x0001
#define SSS_KU_KEY_AGREEMENT        0x0008
#define SSS_KU_KEY_CERT_SIGN        0x0004
#define SSS_KU_KEY_ENCIPHERMENT     0x0020
#define SSS_KU_NON_REPUDIATION      0x0040

#define SSS_CERTMAP_MIN_PRIO UINT32_MAX

#define SSS_SHA1_LENGTH 20


#define BUILD_WITH_PAC_RESPONDER true
#define CLEAR_MC_FLAG "clear_mc_flag"
#define DOM_HAS_VIEWS(dom) ((dom)->has_views)
#define ENUM_INDICATOR "*"
#define FLAGS_DAEMON 0x0001
#define FLAGS_GEN_CONF 0x0008
#define FLAGS_INTERACTIVE 0x0002
#define FLAGS_NONE 0x0000
#define FLAGS_NO_WATCHDOG 0x0010
#define FLAGS_PID_FILE 0x0004
#define GUID_BIN_LENGTH 16
#define GUID_STR_BUF_SIZE (2 * GUID_BIN_LENGTH + 4 + 1)
#define IS_SUBDOMAIN(dom) ((dom)->parent != NULL)
#define KRB5_MAPPING_DIR PUBCONF_PATH"/krb5.include.d"
#define MAX(a, b)  (((a) > (b)) ? (a) : (b))
#define MAX_PID_LENGTH 10
#define MIN(a, b)  (((a) < (b)) ? (a) : (b))
#define NULL 0
#define N_ELEMENTS(arr) (sizeof(arr) / sizeof(arr[0]))
#define OUT_OF_ID_RANGE(id, min, max) \
    (id == 0 || (min && (id < min)) || (max && (id > max)))
#define P11_CHILD_LOG_FILE "p11_child"
#define P11_CHILD_PATH SSSD_LIBEXEC_PATH"/p11_child"
#define P11_CHILD_TIMEOUT_DEFAULT 10
#define P11_WAIT_FOR_CARD_TIMEOUT_DEFAULT 60
#define PIPE_CLOSE(p) do {          \
    PIPE_FD_CLOSE(p[0]);            \
    PIPE_FD_CLOSE(p[1]);            \
} while(0);
#define PIPE_FD_CLOSE(fd) do {      \
    if (fd != -1) {                 \
        close(fd);                  \
        fd = -1;                    \
    }                               \
} while(0);
#define PIPE_INIT { -1, -1 }
#define SSSD_MAIN_OPTS SSSD_DEBUG_OPTS
#define SSSD_MONITOR_NAME        "sssd"
#define SSSD_PIDFILE PID_PATH"/"SSSD_MONITOR_NAME".pid"
#define SSSD_RESPONDER_OPTS \
        { "socket-activated", 0, POPT_ARG_NONE, &socket_activated, 0, \
          _("Informs that the responder has been socket-activated"), NULL }, \
        { "dbus-activated", 0, POPT_ARG_NONE, &dbus_activated, 0, \
          _("Informs that the responder has been dbus-activated"), NULL },
#define SSSD_SERVER_OPTS(uid, gid) \
        {"uid", 0, POPT_ARG_INT, &uid, 0, \
          _("The user ID to run the server as"), NULL}, \
        {"gid", 0, POPT_ARG_INT, &gid, 0, \
          _("The group ID to run the server as"), NULL},
#define SSS_DFL_UMASK 0177
#define SSS_DFL_X_UMASK 0077
#define SSS_GND_ALL_DOMAINS (SSS_GND_DESCEND | SSS_GND_INCLUDE_DISABLED)
#define SSS_GND_DESCEND 0x01
#define SSS_GND_INCLUDE_DISABLED 0x02
#define SSS_LOG_ALERT   1   
#define SSS_LOG_CRIT    2   
#define SSS_LOG_DEBUG   7   
#define SSS_LOG_EMERG   0   
#define SSS_LOG_ERR     3   
#define SSS_LOG_INFO    6   
#define SSS_LOG_NOTICE  5   
#define SSS_LOG_WARNING 4   
#define SSS_NO_BROADCAST 0x08
#define SSS_NO_LINKLOCAL 0x01
#define SSS_NO_LOOPBACK 0x02
#define SSS_NO_MULTICAST 0x04
#define SSS_NO_SPECIAL \
        (SSS_NO_LINKLOCAL|SSS_NO_LOOPBACK|SSS_NO_MULTICAST|SSS_NO_BROADCAST)
#define SSS_WATCHDOG_EXIT_CODE 70 
#define TEVENT_REQ_RETURN_ON_ERROR(req) do { \
    enum tevent_req_state TRROEstate; \
    uint64_t TRROEuint64; \
    errno_t TRROEerr; \
    \
    if (tevent_req_is_error(req, &TRROEstate, &TRROEuint64)) { \
        TRROEerr = (errno_t)TRROEuint64; \
        if (TRROEstate == TEVENT_REQ_USER_ERROR) { \
            if (TRROEerr == 0) { \
                return ERR_INTERNAL; \
            } \
            return TRROEerr; \
        } \
        return ERR_INTERNAL; \
    } \
} while (0)
#define _(STRING) gettext (STRING)

# define discard_const_p(type, ptr) ((type *)((intptr_t)(ptr)))
#define talloc_zfree(ptr) do { talloc_free(discard_const(ptr)); ptr = NULL; } while(0)
#define DLIST_ADD(list, p) \
do { \
    if (!(list)) { \
        (list) = (p); \
        (p)->next = (p)->prev = NULL; \
    } else { \
        (list)->prev = (p); \
        (p)->next = (list); \
        (p)->prev = NULL; \
        (list) = (p); \
    } \
} while (0)
#define DLIST_ADD_AFTER(list, p, el) \
do { \
    if (!(list) || !(el)) { \
        DLIST_ADD(list, p); \
    } else { \
        p->prev = el; \
        p->next = el->next; \
        el->next = p; \
        if (p->next) { \
            p->next->prev = p; \
        } \
    } \
} while (0)
#define DLIST_ADD_END(list, p, type) \
do { \
    if (!(list)) { \
        (list) = (p); \
        (p)->next = (p)->prev = NULL; \
    } else { \
        type tmp; \
        for (tmp = (list); tmp->next; tmp = tmp->next) { \
             \
        } \
        tmp->next = (p); \
        (p)->next = NULL; \
        (p)->prev = tmp; \
    } \
} while (0)
#define DLIST_ADD_LIST_AFTER(list1, el, list2, type) \
do { \
    if (!(list1) || !(el) || !(list2)) { \
        DLIST_CONCATENATE(list1, list2, type); \
    } else { \
        type tmp; \
        for (tmp = (list2); tmp->next; tmp = tmp->next) { \
             \
        } \
        (list2)->prev = (el); \
        tmp->next = (el)->next; \
        (el)->next = (list2); \
        if (tmp->next != NULL) { \
            tmp->next->prev = tmp; \
        } \
    } \
} while (0);
#define DLIST_CONCATENATE(list1, list2, type) \
do { \
    if (!(list1)) { \
        (list1) = (list2); \
    } else { \
        type tmp; \
        for (tmp = (list1); tmp->next; tmp = tmp->next) { \
             \
        } \
        tmp->next = (list2); \
        if (list2) { \
            (list2)->prev = tmp; \
        } \
    } \
} while (0)
#define DLIST_DEMOTE(list, p, type) \
do { \
    DLIST_REMOVE(list, p); \
    DLIST_ADD_END(list, p, type); \
} while (0)
#define DLIST_FOR_EACH(p, list) \
    for ((p) = (list); (p) != NULL; (p) = (p)->next)
#define DLIST_FOR_EACH_SAFE(p, q, list) \
    for ((p) = (list), (q) = (p) != NULL ? (p)->next : NULL; \
         (p) != NULL; \
         (p) = (q), (q) = (p) != NULL ? (p)->next : NULL)
#define DLIST_PROMOTE(list, p) \
do { \
    DLIST_REMOVE(list, p); \
    DLIST_ADD(list, p); \
} while (0)
#define DLIST_REMOVE(list, p) \
do { \
    if ((p) == (list)) { \
        (list) = (p)->next; \
        if (list) { \
            (list)->prev = NULL; \
        } \
    } else { \
        if ((p)->prev) { \
            (p)->prev->next = (p)->next; \
        } \
        if ((p)->next) { \
            (p)->next->prev = (p)->prev; \
        } \
    } \
    if ((p) != (list)) { \
        (p)->next = (p)->prev = NULL; \
    } \
} while (0)

#define APPEND_LINE_FEED 0x1
#define DEBUG(level, format, ...) do { \
    int __debug_macro_level = level; \
    if (DEBUG_IS_SET(__debug_macro_level)) { \
        sss_debug_fn("__FILE__", "__LINE__", __FUNCTION__, \
                     __debug_macro_level, \
                     format, ##__VA_ARGS__); \
    } \
} while (0)
#define DEBUG_CLI_INIT(dbg_lvl) do { \
    DEBUG_INIT(dbg_lvl);             \
    debug_to_stderr = 1;             \
} while (0)
#define DEBUG_INIT(dbg_lvl) do { \
    if (dbg_lvl != SSSDBG_INVALID) { \
        debug_level = debug_convert_old_level(dbg_lvl); \
    } else { \
        debug_level = SSSDBG_UNRESOLVED; \
    } \
\
    talloc_set_log_fn(talloc_log_fn); \
} while (0)
#define DEBUG_IS_SET(level) (debug_level & (level) || \
                            (debug_level == SSSDBG_UNRESOLVED && \
                                            (level & (SSSDBG_FATAL_FAILURE | \
                                                      SSSDBG_CRIT_FAILURE))))
#define ERROR(fmt, ...) fprintf(stderr, gettext(fmt), ##__VA_ARGS__)
#define PRINT(fmt, ...) fprintf(stdout, gettext(fmt), ##__VA_ARGS__)
#define SSSDBG_BE_FO          0x8000   
#define SSSDBG_CONF_SETTINGS  0x0100   
#define SSSDBG_CRIT_FAILURE   0x0020   
#define SSSDBG_DEFAULT        SSSDBG_FATAL_FAILURE
#define SSSDBG_FATAL_FAILURE  0x0010   
#define SSSDBG_FUNC_DATA      0x0200   
#define SSSDBG_IMPORTANT_INFO SSSDBG_OP_FAILURE
#define SSSDBG_INVALID        -1
#define SSSDBG_MASK_ALL       0x1F7F0
#define SSSDBG_MICROSECONDS_DEFAULT       0
#define SSSDBG_MICROSECONDS_UNRESOLVED   -1
#define SSSDBG_MINOR_FAILURE  0x0080   
#define SSSDBG_OP_FAILURE     0x0040   
#define SSSDBG_TIMESTAMP_DEFAULT       1
#define SSSDBG_TIMESTAMP_UNRESOLVED   -1
#define SSSDBG_TRACE_ALL      0x4000   
#define SSSDBG_TRACE_FUNC     0x0400   
#define SSSDBG_TRACE_INTERNAL 0x2000   
#define SSSDBG_TRACE_LDB     0x10000   
#define SSSDBG_TRACE_LIBS     0x1000   
#define SSSDBG_UNRESOLVED     0
#define SSSD_DEBUG_OPTS \
        {"debug-level", 'd', POPT_ARG_INT, &debug_level, 0, \
         _("Debug level"), NULL}, \
        {"debug-to-files", 'f', POPT_ARG_NONE | POPT_ARGFLAG_DOC_HIDDEN, &debug_to_file, 0, \
         _("Send the debug output to files instead of stderr"), NULL }, \
        {"debug-to-stderr", 0, POPT_ARG_NONE | POPT_ARGFLAG_DOC_HIDDEN, &debug_to_stderr, 0, \
         _("Send the debug output to stderr directly."), NULL }, \
        {"debug-timestamps", 0, POPT_ARG_INT, &debug_timestamps, 0, \
         _("Add debug timestamps"), NULL}, \
        {"debug-microseconds", 0, POPT_ARG_INT, &debug_microseconds, 0, \
         _("Show timestamps with microseconds"), NULL},
#define SSSD_LOGGER_OPTS \
        {"logger", '\0', POPT_ARG_STRING, &opt_logger, 0, \
         _("Set logger"), "stderr|files|journald",
#define SSS_ATTRIBUTE_PRINTF(a1, a2) __attribute__((format (printf, a1, a2)))
#define SSS_DOM_ENV           "_SSS_DOM"

#    define SSS_REGEXP_DUPNAMES     0
#  define SSS_REGEXP_ERROR_NOMATCH  PCRE2_ERROR_NOMATCH
#  define SSS_REGEXP_ERROR_NOMEMORY PCRE2_ERROR_NOMEMORY
#  define SSS_REGEXP_EXTENDED       PCRE2_EXTENDED

#  define SSS_REGEXP_NOTEMPTY       PCRE2_NOTEMPTY
# define SPRIgid PRIu64
# define SPRIid PRIu64
#define SPRIkey_ser PRId32
#define SPRIrlim PRIu64
# define SPRIuid PRIu64

#define EOK ERR_OK
#define ERR_BASE    0x555D0000
#define ERR_MASK    0x0000FFFF
#define ERR_OK      0

#define IS_SSSD_ERROR(err) \
    ((SSSD_ERR_BASE(err) == ERR_BASE) && ((err) <= ERR_LAST))
#define SSSD_ERR_BASE(err) ((err) & ~ERR_MASK)
#define SSSD_ERR_IDX(err) ((err) & ERR_MASK)


#define sss_atomic_read_s(fd, buf, n)  sss_atomic_io_s(fd, buf, n, true)
#define sss_atomic_write_s(fd, buf, n) sss_atomic_io_s(fd, buf, n, false)
#define DISCARD_ALIGN(ptr, type) ((type)(void *)(ptr))
#define IS_ALIGNED(ptr, type) \
    ((uintptr_t)(ptr) % sizeof(type) == 0)
#define PADDING_SIZE(base, type) \
    ((sizeof(type) - ((base) % sizeof(type))) % sizeof(type))
#define SAFEALIGN_COPY_INT32(dest, src, pctr) \
    safealign_memcpy(dest, src, sizeof(int32_t), pctr)
#define SAFEALIGN_COPY_INT32_CHECK(dest, src, len, pctr) do { \
    if ((*(pctr) + sizeof(int32_t)) > (len) || \
        SIZE_T_OVERFLOW(*(pctr), sizeof(int32_t))) { return EINVAL; } \
    safealign_memcpy(dest, src, sizeof(int32_t), pctr); \
} while(0)
#define SAFEALIGN_COPY_INT64(dest, src, pctr) \
    safealign_memcpy(dest, src, sizeof(int64_t), pctr)
#define SAFEALIGN_COPY_UINT16(dest, src, pctr) \
    safealign_memcpy(dest, src, sizeof(uint16_t), pctr)
#define SAFEALIGN_COPY_UINT16_CHECK(dest, src, len, pctr) do { \
    if ((*(pctr) + sizeof(uint16_t)) > (len) || \
        SIZE_T_OVERFLOW(*(pctr), sizeof(uint16_t))) { return EINVAL; } \
    safealign_memcpy(dest, src, sizeof(uint16_t), pctr); \
} while(0)
#define SAFEALIGN_COPY_UINT32(dest, src, pctr) \
    safealign_memcpy(dest, src, sizeof(uint32_t), pctr)
#define SAFEALIGN_COPY_UINT32_CHECK(dest, src, len, pctr) do { \
    if ((*(pctr) + sizeof(uint32_t)) > (len) || \
        SIZE_T_OVERFLOW(*(pctr), sizeof(uint32_t))) { return EINVAL; } \
    safealign_memcpy(dest, src, sizeof(uint32_t), pctr); \
} while(0)
#define SAFEALIGN_COPY_UINT8_CHECK(dest, src, len, pctr) do { \
    if ((*(pctr) + sizeof(uint8_t)) > (len) || \
        SIZE_T_OVERFLOW(*(pctr), sizeof(uint8_t))) { return EINVAL; } \
    safealign_memcpy(dest, src, sizeof(uint8_t), pctr); \
} while(0)
#define SAFEALIGN_MEMCPY_CHECK(dest, src, srclen, len, pctr) do { \
    if ((*(pctr) + srclen) > (len) || \
        SIZE_T_OVERFLOW(*(pctr), srclen)) { return EINVAL; } \
    safealign_memcpy(dest, src, srclen, pctr); \
} while(0)
#define SAFEALIGN_SETMEM_INT32(dest, value, pctr) \
    SAFEALIGN_SETMEM_VALUE(dest, value, int32_t, pctr)
#define SAFEALIGN_SETMEM_INT64(dest, value, pctr) \
    SAFEALIGN_SETMEM_VALUE(dest, value, int64_t, pctr)
#define SAFEALIGN_SETMEM_STRING(dest, value, length, pctr) do { \
    const char *CV_MACRO_val = (const char *)(value); \
    safealign_memcpy(dest, CV_MACRO_val, sizeof(char) * length, pctr); \
} while(0)
#define SAFEALIGN_SETMEM_UINT16(dest, value, pctr) \
    SAFEALIGN_SETMEM_VALUE(dest, value, uint16_t, pctr)
#define SAFEALIGN_SETMEM_UINT32(dest, value, pctr) \
    SAFEALIGN_SETMEM_VALUE(dest, value, uint32_t, pctr)
#define SAFEALIGN_SETMEM_VALUE(dest, value, type, pctr) do { \
    type CV_MACRO_val = (type)(value); \
    safealign_memcpy(dest, &CV_MACRO_val, sizeof(type), pctr); \
} while(0)
#define SAFEALIGN_SET_INT32 SAFEALIGN_SETMEM_INT32
#define SAFEALIGN_SET_INT64 SAFEALIGN_SETMEM_INT64
#define SAFEALIGN_SET_STRING SAFEALIGN_SETMEM_STRING
#define SAFEALIGN_SET_UINT16 SAFEALIGN_SETMEM_UINT16
#define SAFEALIGN_SET_UINT32 SAFEALIGN_SETMEM_UINT32
#define SAFEALIGN_SET_VALUE SAFEALIGN_SETMEM_VALUE
#define SIZE_T_OVERFLOW(current, add) \
                        (((size_t)(add)) > (SIZE_MAX - ((size_t)(current))))


#define CONFDB_APP_DOMAIN_BASEDN "cn=application,cn=config"
#define CONFDB_AUTOFS_CONF_ENTRY "config/autofs"
#define CONFDB_AUTOFS_MAP_NEG_TIMEOUT "autofs_negative_timeout"
#define CONFDB_CERTMAP_BASEDN "cn=certmap,cn=config"
#define CONFDB_CERTMAP_DOMAINS "domains"
#define CONFDB_CERTMAP_MAPRULE "maprule"
#define CONFDB_CERTMAP_MATCHRULE "matchrule"
#define CONFDB_CERTMAP_NAME "cn"
#define CONFDB_CERTMAP_PRIORITY "priority"
#define CONFDB_DEFAULT_CACHE_CREDS_MIN_FF_LENGTH 8
#define CONFDB_DEFAULT_CFG_FILE_VER 2
#define CONFDB_DEFAULT_CONFIG_DIR SSSD_CONF_DIR"/"CONFDB_DEFAULT_CONFIG_DIR_NAME
#define CONFDB_DEFAULT_CONFIG_DIR_NAME "conf.d"
#define CONFDB_DEFAULT_FULL_NAME_FORMAT           "%1$s@%2$s"
#define CONFDB_DEFAULT_FULL_NAME_FORMAT_INTERNAL  "%1$s@%2$s%3$s"
#define CONFDB_DEFAULT_HOMEDIR_SUBSTRING "/home"
#define CONFDB_DEFAULT_PAM_FAILED_LOGIN_ATTEMPTS 0
#define CONFDB_DEFAULT_PAM_FAILED_LOGIN_DELAY 5
#define CONFDB_DEFAULT_SHELL_FALLBACK "/bin/sh"
#define CONFDB_DEFAULT_SSH_CA_DB SYSCONFDIR"/pki/nssdb"
#define CONFDB_DEFAULT_SSH_HASH_KNOWN_HOSTS true
#define CONFDB_DEFAULT_SSH_KNOWN_HOSTS_TIMEOUT 180
#define CONFDB_DEFAULT_SSH_USE_CERT_KEYS true
#define CONFDB_DEFAULT_SUBDOMAIN_ENUMERATE "none"
#define CONFDB_DEFAULT_SUDO_CACHE_TIMEOUT 180
#define CONFDB_DEFAULT_SUDO_INVERSE_ORDER false
#define CONFDB_DEFAULT_SUDO_THRESHOLD 50
#define CONFDB_DEFAULT_SUDO_TIMED false
#define CONFDB_DOMAIN_ACCESS_PROVIDER "access_provider"
#define CONFDB_DOMAIN_ACCOUNT_CACHE_EXPIRATION "account_cache_expiration"
#define CONFDB_DOMAIN_ATTR "cn"
#define CONFDB_DOMAIN_AUTH_PROVIDER "auth_provider"
#define CONFDB_DOMAIN_AUTOFS_CACHE_TIMEOUT "entry_cache_autofs_timeout"
#define CONFDB_DOMAIN_AUTOFS_PROVIDER "autofs_provider"
#define CONFDB_DOMAIN_AUTO_UPG "auto_private_groups"
#define CONFDB_DOMAIN_BASEDN "cn=domain,cn=config"
#define CONFDB_DOMAIN_CACHED_AUTH_TIMEOUT "cached_auth_timeout"
#define CONFDB_DOMAIN_CACHE_CREDS "cache_credentials"
#define CONFDB_DOMAIN_CACHE_CREDS_MIN_FF_LENGTH \
                                 "cache_credentials_minimal_first_factor_length"
#define CONFDB_DOMAIN_CASE_SENSITIVE "case_sensitive"
#define CONFDB_DOMAIN_CHPASS_PROVIDER "chpass_provider"
#define CONFDB_DOMAIN_COMMAND "command"
#define CONFDB_DOMAIN_COMPUTER_CACHE_TIMEOUT "entry_cache_computer_timeout"
#define CONFDB_DOMAIN_DEFAULT_SUBDOMAIN_HOMEDIR "/home/%d/%u"
#define CONFDB_DOMAIN_ENABLED "enabled"
#define CONFDB_DOMAIN_ENTRY_CACHE_TIMEOUT "entry_cache_timeout"
#define CONFDB_DOMAIN_ENUMERATE "enumerate"
#define CONFDB_DOMAIN_FQ "use_fully_qualified_names"
#define CONFDB_DOMAIN_GROUP_CACHE_TIMEOUT "entry_cache_group_timeout"
#define CONFDB_DOMAIN_HOSTID_PROVIDER "hostid_provider"
#define CONFDB_DOMAIN_ID_PROVIDER "id_provider"
#define CONFDB_DOMAIN_IGNORE_GROUP_MEMBERS "ignore_group_members"
#define CONFDB_DOMAIN_INHERIT_FROM "inherit_from"
#define CONFDB_DOMAIN_MAXID "max_id"
#define CONFDB_DOMAIN_MINID "min_id"
#define CONFDB_DOMAIN_NETGROUP_CACHE_TIMEOUT "entry_cache_netgroup_timeout"
#define CONFDB_DOMAIN_OFFLINE_TIMEOUT "offline_timeout"
#define CONFDB_DOMAIN_OVERRIDE_GID "override_gid"
#define CONFDB_DOMAIN_PATH_TMPL "config/domain/%s"
#define CONFDB_DOMAIN_PWD_EXPIRATION_WARNING "pwd_expiration_warning"
#define CONFDB_DOMAIN_REFRESH_EXPIRED_INTERVAL "refresh_expired_interval"
#define CONFDB_DOMAIN_RESOLVER_CACHE_TIMEOUT "entry_cache_resolver_timeout"
#define CONFDB_DOMAIN_RESOLVER_PROVIDER "resolver_provider"
#define CONFDB_DOMAIN_SELINUX_PROVIDER "selinux_provider"
#define CONFDB_DOMAIN_SERVICE_CACHE_TIMEOUT "entry_cache_service_timeout"
#define CONFDB_DOMAIN_SESSION_PROVIDER "session_provider"
#define CONFDB_DOMAIN_SSH_HOST_CACHE_TIMEOUT "entry_cache_ssh_host_timeout"
#define CONFDB_DOMAIN_SUBDOMAINS_PROVIDER "subdomains_provider"
#define CONFDB_DOMAIN_SUBDOMAIN_HOMEDIR "subdomain_homedir"
#define CONFDB_DOMAIN_SUBDOMAIN_INHERIT "subdomain_inherit"
#define CONFDB_DOMAIN_SUBDOMAIN_REFRESH "subdomain_refresh_interval"
#define CONFDB_DOMAIN_SUBDOMAIN_REFRESH_DEFAULT_VALUE 14400
#define CONFDB_DOMAIN_SUDO_CACHE_TIMEOUT "entry_cache_sudo_timeout"
#define CONFDB_DOMAIN_SUDO_PROVIDER "sudo_provider"
#define CONFDB_DOMAIN_TIMEOUT "timeout"
#define CONFDB_DOMAIN_TYPE "domain_type"
#define CONFDB_DOMAIN_TYPE_APP "application"
#define CONFDB_DOMAIN_TYPE_POSIX "posix"
#define CONFDB_DOMAIN_USER_CACHE_TIMEOUT "entry_cache_user_timeout"
#define CONFDB_FALLBACK_CONFIG \
    "[sssd]\n" \
    "services = nss\n"
#define CONFDB_FILE "config.ldb"
#define CONFDB_FILES_GROUP "group_files"
#define CONFDB_FILES_PASSWD "passwd_files"
#define CONFDB_FULL_NAME_FORMAT "full_name_format"
#define CONFDB_IFP_CONF_ENTRY "config/ifp"
#define CONFDB_IFP_USER_ATTR_LIST "user_attributes"
#define CONFDB_IFP_WILDCARD_LIMIT "wildcard_limit"
#define CONFDB_KCM_CONF_ENTRY "config/kcm"
#define CONFDB_KCM_DB "ccache_storage" 
#define CONFDB_KCM_MAX_CCACHES "max_ccaches"
#define CONFDB_KCM_MAX_CCACHE_SIZE "max_ccache_size"
#define CONFDB_KCM_MAX_UID_CCACHES "max_uid_ccaches"
#define CONFDB_KCM_SOCKET "socket_path"
#define CONFDB_LOCAL_CREATE_HOMEDIR  "create_homedir"
#define CONFDB_LOCAL_DEFAULT_BASEDIR "base_directory"
#define CONFDB_LOCAL_DEFAULT_SHELL   "default_shell"
#define CONFDB_LOCAL_MAIL_DIR        "mail_dir"
#define CONFDB_LOCAL_REMOVE_HOMEDIR  "remove_homedir"
#define CONFDB_LOCAL_SKEL_DIR        "skel_dir"
#define CONFDB_LOCAL_UMASK           "homedir_umask"
#define CONFDB_LOCAL_USERDEL_CMD     "userdel_cmd"
#define CONFDB_MEMCACHE_TIMEOUT "memcache_timeout"
#define CONFDB_MONITOR_ACTIVE_DOMAINS "domains"
#define CONFDB_MONITOR_ACTIVE_SERVICES "services"
#define CONFDB_MONITOR_CERT_VERIFICATION "certificate_verification"
#define CONFDB_MONITOR_CONF_ENTRY "config/sssd"
#define CONFDB_MONITOR_DEFAULT_DOMAIN "default_domain_suffix"
#define CONFDB_MONITOR_DISABLE_NETLINK "disable_netlink"
#define CONFDB_MONITOR_DOMAIN_RESOLUTION_ORDER "domain_resolution_order"
#define CONFDB_MONITOR_ENABLE_FILES_DOM "enable_files_domain"
#define CONFDB_MONITOR_KRB5_RCACHEDIR "krb5_rcache_dir"
#define CONFDB_MONITOR_OVERRIDE_SPACE "override_space"
#define CONFDB_MONITOR_RESOLV_CONF "monitor_resolv_conf"
#define CONFDB_MONITOR_SBUS_TIMEOUT "sbus_timeout"
#define CONFDB_MONITOR_TRY_INOTIFY "try_inotify"
#define CONFDB_MONITOR_USER_RUNAS "user"
#define CONFDB_NAME_REGEX   "re_expression"
#define CONFDB_NSS_ALLOWED_SHELL "allowed_shells"
#define CONFDB_NSS_CONF_ENTRY "config/nss"
#define CONFDB_NSS_DEFAULT_SHELL "default_shell"
#define CONFDB_NSS_ENTRY_CACHE_NOWAIT_PERCENTAGE "entry_cache_nowait_percentage"
#define CONFDB_NSS_ENTRY_NEG_TIMEOUT "entry_negative_timeout"
#define CONFDB_NSS_ENUM_CACHE_TIMEOUT "enum_cache_timeout"
#define CONFDB_NSS_FALLBACK_HOMEDIR "fallback_homedir"
#define CONFDB_NSS_FILTER_GROUPS "filter_groups"
#define CONFDB_NSS_FILTER_USERS "filter_users"
#define CONFDB_NSS_FILTER_USERS_IN_GROUPS "filter_users_in_groups"
#define CONFDB_NSS_HOMEDIR_SUBSTRING "homedir_substring"
#define CONFDB_NSS_MEMCACHE_SIZE_GROUP "memcache_size_group"
#define CONFDB_NSS_MEMCACHE_SIZE_INITGROUPS "memcache_size_initgroups"
#define CONFDB_NSS_MEMCACHE_SIZE_PASSWD "memcache_size_passwd"
#define CONFDB_NSS_OVERRIDE_HOMEDIR "override_homedir"
#define CONFDB_NSS_OVERRIDE_SHELL  "override_shell"
#define CONFDB_NSS_PWFIELD  "pwfield"
#define CONFDB_NSS_SHELL_FALLBACK "shell_fallback"
#define CONFDB_NSS_VETOED_SHELL  "vetoed_shells"
#define CONFDB_PAC_CONF_ENTRY "config/pac"
#define CONFDB_PAC_LIFETIME "pac_lifetime"
#define CONFDB_PAM_ACCOUNT_EXPIRED_MESSAGE "pam_account_expired_message"
#define CONFDB_PAM_ACCOUNT_LOCKED_MESSAGE "pam_account_locked_message"
#define CONFDB_PAM_APP_SERVICES "pam_app_services"
#define CONFDB_PAM_CERT_AUTH "pam_cert_auth"
#define CONFDB_PAM_CERT_DB_PATH "pam_cert_db_path"
#define CONFDB_PAM_CONF_ENTRY "config/pam"
#define CONFDB_PAM_CRED_TIMEOUT "offline_credentials_expiration"
#define CONFDB_PAM_FAILED_LOGIN_ATTEMPTS "offline_failed_login_attempts"
#define CONFDB_PAM_FAILED_LOGIN_DELAY "offline_failed_login_delay"
#define CONFDB_PAM_ID_TIMEOUT "pam_id_timeout"
#define CONFDB_PAM_INITGROUPS_SCHEME "pam_initgroups_scheme"
#define CONFDB_PAM_P11_ALLOWED_SERVICES "pam_p11_allowed_services"
#define CONFDB_PAM_P11_CHILD_TIMEOUT "p11_child_timeout"
#define CONFDB_PAM_P11_URI "p11_uri"
#define CONFDB_PAM_PUBLIC_DOMAINS "pam_public_domains"
#define CONFDB_PAM_PWD_EXPIRATION_WARNING "pam_pwd_expiration_warning"
#define CONFDB_PAM_RESPONSE_FILTER "pam_response_filter"
#define CONFDB_PAM_TRUSTED_USERS "pam_trusted_users"
#define CONFDB_PAM_VERBOSITY "pam_verbosity"
#define CONFDB_PAM_WAIT_FOR_CARD_TIMEOUT "p11_wait_for_card_timeout"
#define CONFDB_PC_2FA_1ST_PROMPT "first_prompt"
#define CONFDB_PC_2FA_2ND_PROMPT "second_prompt"
#define CONFDB_PC_2FA_SINGLE_PROMPT "single_prompt"
#define CONFDB_PC_CONF_ENTRY "config/prompting"
#define CONFDB_PC_PASSWORD_PROMPT "password_prompt"
#define CONFDB_PC_TYPE_2FA "2fa"
#define CONFDB_PC_TYPE_CERT_AUTH "cert_auth"
#define CONFDB_PC_TYPE_PASSWORD "password"
#define CONFDB_PROXY_FAST_ALIAS "proxy_fast_alias"
#define CONFDB_PROXY_LIBNAME "proxy_lib_name"
#define CONFDB_PROXY_MAX_CHILDREN "proxy_max_children"
#define CONFDB_PROXY_PAM_TARGET "proxy_pam_target"
#define CONFDB_PROXY_RESOLVER_LIBNAME "proxy_resolver_lib_name"
#define CONFDB_RESPONDER_CACHE_FIRST "cache_first"
#define CONFDB_RESPONDER_CLI_IDLE_DEFAULT_TIMEOUT 60
#define CONFDB_RESPONDER_CLI_IDLE_TIMEOUT "client_idle_timeout"
#define CONFDB_RESPONDER_GET_DOMAINS_TIMEOUT "get_domains_timeout"
#define CONFDB_RESPONDER_IDLE_DEFAULT_TIMEOUT 300
#define CONFDB_RESPONDER_IDLE_TIMEOUT "responder_idle_timeout"
#define CONFDB_RESPONDER_LOCAL_NEG_TIMEOUT "local_negative_timeout"
#define CONFDB_RESPONDER_LOCAL_NEG_TIMEOUT_DEFAULT 14400
#define CONFDB_SEC_CONF_ENTRY "config/secrets"
#define CONFDB_SEC_CONTAINERS_NEST_LEVEL "containers_nest_level"
#define CONFDB_SEC_MAX_PAYLOAD_SIZE "max_payload_size"
#define CONFDB_SEC_MAX_SECRETS "max_secrets"
#define CONFDB_SEC_MAX_UID_SECRETS "max_uid_secrets"
#define CONFDB_SERVICE_ALLOWED_UIDS "allowed_uids"
#define CONFDB_SERVICE_COMMAND "command"
#define CONFDB_SERVICE_DEBUG_LEVEL "debug_level"
#define CONFDB_SERVICE_DEBUG_LEVEL_ALIAS "debug"
#define CONFDB_SERVICE_DEBUG_MICROSECONDS "debug_microseconds"
#define CONFDB_SERVICE_DEBUG_TIMESTAMPS "debug_timestamps"
#define CONFDB_SERVICE_DEBUG_TO_FILES "debug_to_files"
#define CONFDB_SERVICE_FD_LIMIT "fd_limit"
#define CONFDB_SERVICE_PATH_TMPL "config/%s"
#define CONFDB_SERVICE_RECON_RETRIES "reconnection_retries"
#define CONFDB_SESSION_RECORDING_CONF_ENTRY "config/session_recording"
#define CONFDB_SESSION_RECORDING_GROUPS "groups"
#define CONFDB_SESSION_RECORDING_SCOPE "scope"
#define CONFDB_SESSION_RECORDING_USERS "users"
#define CONFDB_SSH_CA_DB "ca_db"
#define CONFDB_SSH_CONF_ENTRY "config/ssh"
#define CONFDB_SSH_HASH_KNOWN_HOSTS "ssh_hash_known_hosts"
#define CONFDB_SSH_KNOWN_HOSTS_TIMEOUT "ssh_known_hosts_timeout"
#define CONFDB_SSH_USE_CERT_KEYS "ssh_use_certificate_keys"
#define CONFDB_SSH_USE_CERT_RULES "ssh_use_certificate_matching_rules"
#define CONFDB_SUBDOMAIN_ENUMERATE "subdomain_enumerate"
#define CONFDB_SUDO_CACHE_TIMEOUT "sudo_cache_timeout"
#define CONFDB_SUDO_CONF_ENTRY "config/sudo"
#define CONFDB_SUDO_INVERSE_ORDER "sudo_inverse_order"
#define CONFDB_SUDO_THRESHOLD "sudo_threshold"
#define CONFDB_SUDO_TIMED "sudo_timed"
#define SSSD_CONFIG_FILE SSSD_CONF_DIR"/"SSSD_CONFIG_FILE_NAME
#define SSSD_CONFIG_FILE_NAME "sssd.conf"
#define SSSD_LOCAL_MINID 1000
#define SSSD_MIN_ID 1

