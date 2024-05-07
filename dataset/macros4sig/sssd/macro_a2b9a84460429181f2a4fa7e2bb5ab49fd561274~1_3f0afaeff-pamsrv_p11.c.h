
#include<pwd.h>

#include<sys/resource.h>




#include<inttypes.h>

#include<sys/types.h>


#include<stddef.h>
#include<poll.h>
#include<errno.h>
#include<time.h>
#include<ctype.h>
#include<grp.h>


#include<limits.h>
#include<stdint.h>


#include<locale.h>

#include<sys/wait.h>

#include<nss.h>


#include<stdio.h>


#include<netinet/in.h>
#include<unistd.h>
#include<sys/stat.h>
#include<stdbool.h>
#include<stdlib.h>
#include<string.h>
#include<sys/un.h>

#include<stdarg.h>

#include<libintl.h>







#define CACHE_SYSDB_FILE "cache_%s.ldb"
#define CACHE_TIMESTAMPS_FILE "timestamps_%s.ldb"
#define LOCAL_SYSDB_FILE "sssd.ldb"
#define ORIGINALAD_PREFIX "originalAD"
#define OVERRIDE_PREFIX "override"
#define SSS_LDB_SEARCH(ret, ldb, mem_ctx, _result, base, scope, attrs,    \
                       exp_fmt, ...) do {                                 \
    int _sls_lret;                                                        \
                                                                          \
    _sls_lret = ldb_search(ldb, mem_ctx, _result, base, scope, attrs,     \
                           exp_fmt, ##__VA_ARGS__);                       \
    ret = sysdb_error_to_errno(_sls_lret);                                \
    if (ret == EOK && (*_result)->count == 0) {                           \
        ret = ENOENT;                                                     \
    }                                                                     \
} while(0)
#define SYSDB_AD_ACCOUNT_EXPIRES "adAccountExpires"
#define SYSDB_AD_USER_ACCOUNT_CONTROL "adUserAccountControl"
#define SYSDB_AUTHORIZED_HOST "authorizedHost"
#define SYSDB_AUTHORIZED_RHOST "authorizedRHost"
#define SYSDB_AUTHORIZED_SERVICE "authorizedService"
#define SYSDB_AUTH_TYPE "authType"
#define SYSDB_BASE "cn=sysdb"
#define SYSDB_BASE_ID "baseID"
#define SYSDB_BASE_RID "baseRID"
#define SYSDB_CACHEDPWD "cachedPassword"
#define SYSDB_CACHEDPWD_FA2_LEN "cachedPasswordSecondFactorLen"
#define SYSDB_CACHEDPWD_TYPE "cachedPasswordType"
#define SYSDB_CACHE_EXPIRE "dataExpireTimestamp"
#define SYSDB_CANONICAL_UPN "canonicalUserPrincipalName"
#define SYSDB_CCACHE_FILE "ccacheFile"
#define SYSDB_CERTMAP_CLASS "certificateMappingRule"
#define SYSDB_CERTMAP_CONTAINER "cn=certmap"
#define SYSDB_CERTMAP_DOMAINS "domains"
#define SYSDB_CERTMAP_MAPPING_RULE "mappingRule"
#define SYSDB_CERTMAP_MATCHING_RULE "matchingRule"
#define SYSDB_CERTMAP_PRIORITY "priority"
#define SYSDB_CERTMAP_USER_NAME_HINT "userNameHint"
#define SYSDB_CREATE_TIME "createTimestamp"
#define SYSDB_CUSTOM_CONTAINER "cn=custom"
#define SYSDB_DEFAULT_ATTRS SYSDB_LAST_UPDATE, \
                            SYSDB_CACHE_EXPIRE, \
                            SYSDB_INITGR_EXPIRE, \
                            SYSDB_OBJECTCLASS, \
                            SYSDB_OBJECTCATEGORY
#define SYSDB_DEFAULT_OVERRIDE_NAME "defaultOverrideName"
#define SYSDB_DEFAULT_VIEW_NAME "default"
#define SYSDB_DESCRIPTION   "description"
#define SYSDB_DISABLED "disabled"
#define SYSDB_DN "dn"
#define SYSDB_DOMAIN_ID "domainID"
#define SYSDB_DOMAIN_ID_RANGE_CLASS "domainIDRange"
#define SYSDB_DOMAIN_RESOLUTION_ORDER "domainResolutionOrder"
#define SYSDB_DOM_BASE "cn=%s,cn=sysdb"
#define SYSDB_ENABLED "enabled"
#define SYSDB_ENUM_EXPIRE "enumerationExpireTimestamp"
#define SYSDB_EXTERNAL_MEMBER "externalMember"
#define SYSDB_FAILED_LOGIN_ATTEMPTS "failedLoginAttempts"
#define SYSDB_FQDN "fqdn"
#define SYSDB_FULLNAME "fullName"
#define SYSDB_GC SYSDB_OBJECTCATEGORY"="SYSDB_GROUP_CLASS
#define SYSDB_GECOS "gecos"
#define SYSDB_GHOST "ghost"
#define SYSDB_GIDNUM "gidNumber"
#define SYSDB_GPO_ATTRS { \
        SYSDB_NAME, \
        SYSDB_GPO_GUID_ATTR, \
        SYSDB_GPO_VERSION_ATTR, \
        SYSDB_GPO_TIMEOUT_ATTR, \
        NULL }
#define SYSDB_GPO_CONTAINER "cn=gpos,cn=ad,cn=custom"
#define SYSDB_GPO_FILTER "(objectClass="SYSDB_GPO_OC")"
#define SYSDB_GPO_GUID_ATTR "gpoGUID"
#define SYSDB_GPO_GUID_FILTER "(&(objectClass="SYSDB_GPO_OC")("SYSDB_GPO_GUID_ATTR"=%s))"
#define SYSDB_GPO_OC "gpo"
#define SYSDB_GPO_RESULT_FILTER "(objectClass="SYSDB_GPO_RESULT_OC")"
#define SYSDB_GPO_RESULT_OC "gpo_result"
#define SYSDB_GPO_TIMEOUT_ATTR "gpoPolicyFileTimeout"
#define SYSDB_GPO_VERSION_ATTR "gpoVersion"
#define SYSDB_GRENT_FILTER "("SYSDB_GC")"
#define SYSDB_GRENT_MPG_FILTER "("SYSDB_MPGC")"
#define SYSDB_GRGID_FILTER "(&("SYSDB_GC")("SYSDB_GIDNUM"=%lu))"
#define SYSDB_GRGID_MPG_FILTER "(&("SYSDB_MPGC")("SYSDB_GIDNUM"=%lu))"
#define SYSDB_GRNAM_FILTER "(&("SYSDB_GC")(|("SYSDB_NAME_ALIAS"=%s)("SYSDB_NAME_ALIAS"=%s)("SYSDB_NAME"=%s)))"
#define SYSDB_GRNAM_MPG_FILTER "(&("SYSDB_MPGC")(|("SYSDB_NAME_ALIAS"=%s)("SYSDB_NAME_ALIAS"=%s)("SYSDB_NAME"=%s)))"
#define SYSDB_GRORIGGID_FILTER "(&("SYSDB_GC")("ORIGINALAD_PREFIX SYSDB_GIDNUM"=%lu))"
#define SYSDB_GROUPS_CONTAINER "cn=groups"
#define SYSDB_GROUP_CLASS "group"
#define SYSDB_GROUP_TYPE "groupType"
#define SYSDB_GRSID_FILTER "(&("SYSDB_GC")("SYSDB_SID_STR"=%s))"
#define SYSDB_GRSRC_ATTRS {SYSDB_NAME, SYSDB_GIDNUM, \
                           SYSDB_MEMBERUID, \
                           SYSDB_MEMBER, \
                           SYSDB_GHOST, \
                           SYSDB_DEFAULT_ATTRS, \
                           SYSDB_SID_STR, \
                           SYSDB_OVERRIDE_DN, \
                           SYSDB_OVERRIDE_OBJECT_DN, \
                           SYSDB_DEFAULT_OVERRIDE_NAME, \
                           SYSDB_UUID, \
                           ORIGINALAD_PREFIX SYSDB_NAME, \
                           ORIGINALAD_PREFIX SYSDB_GIDNUM, \
                           NULL}
#define SYSDB_HAS_ENUMERATED "has_enumerated"
#define SYSDB_HAS_ENUMERATED_ID       0x00000001
#define SYSDB_HAS_ENUMERATED_RESOLVER 0x00000002
#define SYSDB_HIGH_USN "highestUSN"
#define SYSDB_HOMEDIR "homeDirectory"
#define SYSDB_HOSTGROUP_CLASS "hostgroup"
#define SYSDB_HOST_CATEGORY "hostCategory"
#define SYSDB_HOST_CLASS "host"
#define SYSDB_IDMAP_ATTRS { \
    SYSDB_NAME, \
    SYSDB_IDMAP_SID_ATTR, \
    SYSDB_IDMAP_SLICE_ATTR, \
    NULL }
#define SYSDB_IDMAP_CONTAINER "cn=id_mappings"
#define SYSDB_IDMAP_FILTER "(objectClass="SYSDB_IDMAP_MAPPING_OC")"
#define SYSDB_IDMAP_MAPPING_OC "id_mapping"
#define SYSDB_IDMAP_SID_ATTR "objectSID"
#define SYSDB_IDMAP_SLICE_ATTR "slice"
#define SYSDB_IDMAP_SUBTREE "idmap"
#define SYSDB_ID_FILTER "(|(&("SYSDB_UC")("SYSDB_UIDNUM"=%u))(&("SYSDB_GC")("SYSDB_GIDNUM"=%u)))"
#define SYSDB_ID_RANGE_CLASS "idRange"
#define SYSDB_ID_RANGE_SIZE "idRangeSize"
#define SYSDB_ID_RANGE_TYPE "idRangeType"
#define SYSDB_IFP_CACHED "ifpCached"
#define SYSDB_INITGR_ATTR SYSDB_MEMBEROF
#define SYSDB_INITGR_ATTRS {SYSDB_GIDNUM, SYSDB_POSIX, \
                            SYSDB_DEFAULT_ATTRS, \
                            SYSDB_ORIG_DN, \
                            SYSDB_SID_STR, \
                            SYSDB_NAME, \
                            SYSDB_OVERRIDE_DN, \
                            NULL}
#define SYSDB_INITGR_EXPIRE "initgrExpireTimestamp"
#define SYSDB_INITGR_FILTER "(&("SYSDB_GC")("SYSDB_GIDNUM"=*))"
#define SYSDB_LAST_FAILED_LOGIN "lastFailedLogin"
#define SYSDB_LAST_LOGIN "lastLogin"
#define SYSDB_LAST_ONLINE_AUTH "lastOnlineAuth"
#define SYSDB_LAST_ONLINE_AUTH_WITH_CURR_TOKEN "lastOnlineAuthWithCurrentToken"
#define SYSDB_LAST_UPDATE "lastUpdate"
#define SYSDB_LOCAL_VIEW_NAME "LOCAL" 
#define SYSDB_MEMBER "member"
#define SYSDB_MEMBEROF "memberOf"
#define SYSDB_MEMBERUID "memberUid"
#define SYSDB_MOD_ADD LDB_FLAG_MOD_ADD
#define SYSDB_MOD_DEL LDB_FLAG_MOD_DELETE
#define SYSDB_MOD_REP LDB_FLAG_MOD_REPLACE
#define SYSDB_MPGC "|("SYSDB_UC")("SYSDB_GC")"
#define SYSDB_NAME "name"
#define SYSDB_NAME_ALIAS "nameAlias"
#define SYSDB_NAME_FILTER "(&(|("SYSDB_UC")("SYSDB_GC"))(|("SYSDB_NAME_ALIAS"=%s)("SYSDB_NAME"=%s)))"
#define SYSDB_NC SYSDB_OBJECTCLASS"="SYSDB_NETGROUP_CLASS
#define SYSDB_NETGROUP_CLASS "netgroup"
#define SYSDB_NETGROUP_CONTAINER "cn=Netgroups"
#define SYSDB_NETGROUP_DOMAIN "nisDomain"
#define SYSDB_NETGROUP_MEMBER "memberNisNetgroup"
#define SYSDB_NETGROUP_TRIPLE "netgroupTriple"
#define SYSDB_NETGR_ATTRS {SYSDB_NAME, SYSDB_NETGROUP_TRIPLE, \
                           SYSDB_NETGROUP_MEMBER, \
                           SYSDB_DEFAULT_ATTRS, \
                           NULL}
#define SYSDB_NETGR_FILTER "(&("SYSDB_NC")(|("SYSDB_NAME_ALIAS"=%s)("SYSDB_NAME_ALIAS"=%s)("SYSDB_NAME"=%s)))"
#define SYSDB_NETGR_TRIPLES_FILTER "(|("SYSDB_NAME_ALIAS"=%s)("SYSDB_NAME"=%s)("SYSDB_NAME_ALIAS"=%s)("SYSDB_MEMBEROF"=%s))"
#define SYSDB_NEXTID "nextID"
#define SYSDB_NEXTID_FILTER "("SYSDB_NEXTID"=*)"
#define SYSDB_OBJECTCATEGORY "objectCategory"
#define SYSDB_OBJECTCLASS "objectClass"
#define SYSDB_ORIG_DN "originalDN"
#define SYSDB_ORIG_MEMBER "orig_member"
#define SYSDB_ORIG_MEMBEROF "originalMemberOf"
#define SYSDB_ORIG_MEMBER_HOST "originalMemberHost"
#define SYSDB_ORIG_MEMBER_USER "originalMemberUser"
#define SYSDB_ORIG_MODSTAMP "originalModifyTimestamp"
#define SYSDB_ORIG_NETGROUP_EXTERNAL_HOST "originalExternalHost"
#define SYSDB_ORIG_NETGROUP_MEMBER "originalMemberNisNetgroup"
#define SYSDB_OVERRIDE_ANCHOR_UUID "overrideAnchorUUID"
#define SYSDB_OVERRIDE_CLASS "override"
#define SYSDB_OVERRIDE_DN "overrideDN"
#define SYSDB_OVERRIDE_GROUP_CLASS "groupOverride"
#define SYSDB_OVERRIDE_OBJECT_DN "overrideObjectDN"
#define SYSDB_OVERRIDE_USER_CLASS "userOverride"
#define SYSDB_PAC_BLOB "pacBlob"
#define SYSDB_PAC_BLOB_EXPIRE "pacBlobExpireTimestamp"
#define SYSDB_POSIX "isPosix"
#define SYSDB_PRIMARY_GROUP "ADPrimaryGroupID"
#define SYSDB_PRIMARY_GROUP_GIDNUM "origPrimaryGroupGidNumber"
#define SYSDB_PWD "userPassword"
#define SYSDB_PWENT_FILTER "("SYSDB_UC")"
#define SYSDB_PWNAM_FILTER "(&("SYSDB_UC")(|("SYSDB_NAME_ALIAS"=%s)("SYSDB_NAME_ALIAS"=%s)("SYSDB_NAME"=%s)))"
#define SYSDB_PWSID_FILTER "(&("SYSDB_UC")("SYSDB_SID_STR"=%s))"
#define SYSDB_PWUID_FILTER "(&("SYSDB_UC")("SYSDB_UIDNUM"=%lu))"
#define SYSDB_PWUPN_FILTER "(&("SYSDB_UC")(|("SYSDB_UPN"=%s)("SYSDB_CANONICAL_UPN"=%s)("SYSDB_USER_EMAIL"=%s)))"
#define SYSDB_PW_ATTRS {SYSDB_NAME, SYSDB_UIDNUM, \
                        SYSDB_GIDNUM, SYSDB_GECOS, \
                        SYSDB_HOMEDIR, SYSDB_SHELL, \
                        SYSDB_DEFAULT_ATTRS, \
                        SYSDB_PRIMARY_GROUP_GIDNUM, \
                        SYSDB_SID_STR, \
                        SYSDB_UPN, \
                        SYSDB_USER_CERT, \
                        SYSDB_USER_EMAIL, \
                        SYSDB_OVERRIDE_DN, \
                        SYSDB_OVERRIDE_OBJECT_DN, \
                        SYSDB_DEFAULT_OVERRIDE_NAME, \
                        SYSDB_SESSION_RECORDING, \
                        SYSDB_UUID, \
                        SYSDB_ORIG_DN, \
                        NULL}
#define SYSDB_RANGE_CONTAINER "cn=ranges"
#define SYSDB_SECONDARY_BASE_RID "secondaryBaseRID"
#define SYSDB_SELINUX_CLASS "selinux"
#define SYSDB_SELINUX_USERMAP_CLASS "selinuxusermap"
#define SYSDB_SERVERHOSTNAME "serverHostname"
#define SYSDB_SESSION_RECORDING "sessionRecording"
#define SYSDB_SHELL "loginShell"
#define SYSDB_SID "objectSID"
#define SYSDB_SID_FILTER "(&(|("SYSDB_UC")("SYSDB_GC"))("SYSDB_SID_STR"=%s))"
#define SYSDB_SID_STR "objectSIDString"
#define SYSDB_SITE "site"
#define SYSDB_SSH_PUBKEY "sshPublicKey"
#define SYSDB_SUBDOMAIN_CLASS "subdomain"
#define SYSDB_SUBDOMAIN_ENUM "enumerate"
#define SYSDB_SUBDOMAIN_FLAT "flatName"
#define SYSDB_SUBDOMAIN_FOREST "memberOfForest"
#define SYSDB_SUBDOMAIN_ID "domainID"
#define SYSDB_SUBDOMAIN_MPG "mpg"
#define SYSDB_SUBDOMAIN_REALM "realmName"
#define SYSDB_SUBDOMAIN_TRUST_DIRECTION "trustDirection"
#define SYSDB_TMPL_CERTMAP SYSDB_NAME"=%s,"SYSDB_TMPL_CERTMAP_BASE
#define SYSDB_TMPL_CERTMAP_BASE SYSDB_CERTMAP_CONTAINER","SYSDB_BASE
#define SYSDB_TMPL_CUSTOM SYSDB_NAME"=%s,cn=%s,"SYSDB_TMPL_CUSTOM_BASE
#define SYSDB_TMPL_CUSTOM_BASE SYSDB_CUSTOM_CONTAINER","SYSDB_DOM_BASE
#define SYSDB_TMPL_CUSTOM_SUBTREE "cn=%s,"SYSDB_TMPL_CUSTOM_BASE
#define SYSDB_TMPL_GPO SYSDB_GPO_GUID_ATTR"=%s,"SYSDB_TMPL_GPO_BASE
#define SYSDB_TMPL_GPO_BASE SYSDB_GPO_CONTAINER","SYSDB_DOM_BASE
#define SYSDB_TMPL_GPO_RESULT "cn=%s,"SYSDB_TMPL_GPO_RESULT_BASE
#define SYSDB_TMPL_GPO_RESULT_BASE SYSDB_GPO_CONTAINER","SYSDB_DOM_BASE
#define SYSDB_TMPL_GROUP SYSDB_NAME"=%s,"SYSDB_TMPL_GROUP_BASE
#define SYSDB_TMPL_GROUP_BASE SYSDB_GROUPS_CONTAINER","SYSDB_DOM_BASE
#define SYSDB_TMPL_IDMAP SYSDB_IDMAP_SID_ATTR"=%s,"SYSDB_TMPL_IDMAP_BASE
#define SYSDB_TMPL_IDMAP_BASE SYSDB_IDMAP_CONTAINER",cn=%s,"SYSDB_BASE
#define SYSDB_TMPL_NETGROUP SYSDB_NAME"=%s,"SYSDB_TMPL_NETGROUP_BASE
#define SYSDB_TMPL_NETGROUP_BASE SYSDB_NETGROUP_CONTAINER","SYSDB_DOM_BASE
#define SYSDB_TMPL_OVERRIDE SYSDB_OVERRIDE_ANCHOR_UUID"=%s,"SYSDB_TMPL_VIEW_SEARCH_BASE
#define SYSDB_TMPL_RANGE SYSDB_NAME"=%s,"SYSDB_TMPL_RANGE_BASE
#define SYSDB_TMPL_RANGE_BASE SYSDB_RANGE_CONTAINER","SYSDB_BASE
#define SYSDB_TMPL_USER SYSDB_NAME"=%s,"SYSDB_TMPL_USER_BASE
#define SYSDB_TMPL_USER_BASE SYSDB_USERS_CONTAINER","SYSDB_DOM_BASE
#define SYSDB_TMPL_VIEW_BASE SYSDB_VIEW_CONTAINER","SYSDB_BASE
#define SYSDB_TMPL_VIEW_SEARCH_BASE "cn=%s,"SYSDB_TMPL_VIEW_BASE
#define SYSDB_TRUSTED_AD_DOMAIN_RANGE_CLASS "TrustedADDomainRange"
#define SYSDB_UC SYSDB_OBJECTCATEGORY"="SYSDB_USER_CLASS
#define SYSDB_UIDNUM "uidNumber"
#define SYSDB_UPN "userPrincipalName"
#define SYSDB_UPN_SUFFIXES "upnSuffixes"
#define SYSDB_USERS_CONTAINER "cn=users"
#define SYSDB_USER_CATEGORY "userCategory"
#define SYSDB_USER_CERT "userCertificate"
#define SYSDB_USER_CERT_FILTER "(&("SYSDB_UC")%s)"
#define SYSDB_USER_CLASS "user"
#define SYSDB_USER_EMAIL "mail"
#define SYSDB_USER_MAPPED_CERT "userMappedCertificate"
#define SYSDB_USE_DOMAIN_RESOLUTION_ORDER "useDomainResolutionOrder"
#define SYSDB_USN "entryUSN"
#define SYSDB_UUID "uniqueID"
#define SYSDB_UUID_FILTER "(&(|("SYSDB_UC")("SYSDB_GC"))("SYSDB_UUID"=%s))"
#define SYSDB_VERSION_ERROR(ret) \
    SYSDB_VERSION_LOWER_ERROR(ret); \
    SYSDB_VERSION_HIGHER_ERROR(ret)
#define SYSDB_VERSION_ERROR_DAEMON(ret) \
    SYSDB_VERSION_LOWER_ERROR(ret)
#define SYSDB_VERSION_ERROR_HINT \
    ERROR("Removing cache files in "DB_PATH" should fix the issue, " \
          "but note that removing cache files will also remove all of your " \
          "cached credentials.\n")
#define SYSDB_VERSION_HIGHER_ERROR(ret) do { \
    if (ret == ERR_SYSDB_VERSION_TOO_OLD) { \
        ERROR("Higher version of database is expected!\n"); \
        ERROR("In order to upgrade the database, you must run SSSD.\n"); \
        SYSDB_VERSION_ERROR_HINT; \
    } \
} while(0)
#define SYSDB_VERSION_LOWER_ERROR(ret) do { \
    if (ret == ERR_SYSDB_VERSION_TOO_NEW) { \
        ERROR("Lower version of database is expected!\n"); \
        SYSDB_VERSION_ERROR_HINT; \
    } \
} while(0)
#define SYSDB_VIEW_CLASS "view"
#define SYSDB_VIEW_CONTAINER "cn=views"
#define SYSDB_VIEW_NAME "viewName"

#define sysdb_error_to_errno(ldberr) sss_ldb_error_to_errno(ldberr)
#define sysdb_search_groups_by_orig_dn(mem_ctx, domain, member_dn, attrs, msgs_counts, msgs) \
    sysdb_search_by_orig_dn(mem_ctx, domain, SYSDB_MEMBER_GROUP, member_dn, attrs, msgs_counts, msgs);
#define sysdb_search_users_by_orig_dn(mem_ctx, domain, member_dn, attrs, msgs_counts, msgs) \
    sysdb_search_by_orig_dn(mem_ctx, domain, SYSDB_MEMBER_USER, member_dn, attrs, msgs_counts, msgs);
#define EOK 0

#define PAM_CLI_FLAGS_ALLOW_MISSING_NAME (1 << 6)
#define PAM_CLI_FLAGS_FORWARD_PASS   (1 << 1)
#define PAM_CLI_FLAGS_IGNORE_AUTHINFO_UNAVAIL (1 << 4)
#define PAM_CLI_FLAGS_IGNORE_UNKNOWN_USER (1 << 3)
#define PAM_CLI_FLAGS_PROMPT_ALWAYS (1 << 7)
#define PAM_CLI_FLAGS_REQUIRE_CERT_AUTH (1 << 9)
#define PAM_CLI_FLAGS_TRY_CERT_AUTH (1 << 8)
#define PAM_CLI_FLAGS_USE_2FA (1 << 5)
#define PAM_CLI_FLAGS_USE_AUTHTOK    (1 << 2)
#define PAM_CLI_FLAGS_USE_FIRST_PASS (1 << 0)
#define PAM_PREAUTH_INDICATOR PUBCONF_PATH"/pam_preauth_available"
#define SSS_AUTOFS_PROTOCOL_VERSION 1
#define SSS_CLI_SOCKET_TIMEOUT 300000
#define SSS_END_OF_PAM_REQUEST 0x4950414d
#define SSS_NAME_MAX LOGIN_NAME_MAX
#define SSS_NSS_HEADER_SIZE (sizeof(uint32_t) * 4)
#define SSS_NSS_MAX_ENTRIES 256
#define SSS_NSS_PROTOCOL_VERSION 1
#define SSS_PAC_PROTOCOL_VERSION 1
#define SSS_PAM_PROTOCOL_VERSION 3
#define SSS_SSH_PROTOCOL_VERSION 0
#define SSS_START_OF_PAM_REQUEST 0x4d415049
#define SSS_SUDO_PROTOCOL_VERSION 1

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

#define ERR_BASE    0x555D0000
#define ERR_MASK    0x0000FFFF
#define ERR_OK      0
#define IS_SSSD_ERROR(err) \
    ((SSSD_ERR_BASE(err) == ERR_BASE) && ((err) <= ERR_LAST))
#define SSSD_ERR_BASE(err) ((err) & ~ERR_MASK)
#define SSSD_ERR_IDX(err) ((err) & ERR_MASK)


#define sss_atomic_read_s(fd, buf, n)  sss_atomic_io_s(fd, buf, n, true)
#define sss_atomic_write_s(fd, buf, n) sss_atomic_io_s(fd, buf, n, false)

#define SSS_SHA1_LENGTH 20

#define SSS_CERTMAP_MIN_PRIO UINT32_MAX

#define CERT_AUTH_DEFAULT_MATCHING_RULE "KRB5:<EKU>clientAuth"



#define cache_req_autofs_entry_by_name_recv(mem_ctx, req, _result) \
    cache_req_single_domain_recv(mem_ctx, req, _result)
#define cache_req_autofs_map_by_name_recv(mem_ctx, req, _result) \
    cache_req_single_domain_recv(mem_ctx, req, _result)
#define cache_req_autofs_map_entries_recv(mem_ctx, req, _result) \
    cache_req_single_domain_recv(mem_ctx, req, _result)
#define cache_req_enum_groups_recv(mem_ctx, req, _result) \
    cache_req_recv(mem_ctx, req, _result)
#define cache_req_enum_users_recv(mem_ctx, req, _result) \
    cache_req_recv(mem_ctx, req, _result)
#define cache_req_group_by_filter_recv(mem_ctx, req, _result) \
    cache_req_single_domain_recv(mem_ctx, req, _result)
#define cache_req_group_by_id_recv(mem_ctx, req, _result) \
    cache_req_single_domain_recv(mem_ctx, req, _result)
#define cache_req_group_by_name_recv(mem_ctx, req, _result) \
    cache_req_single_domain_recv(mem_ctx, req, _result)
#define cache_req_initgr_by_name_recv(mem_ctx, req, _result) \
    cache_req_single_domain_recv(mem_ctx, req, _result)
#define cache_req_netgroup_by_name_recv(mem_ctx, req, _result) \
    cache_req_single_domain_recv(mem_ctx, req, _result)
#define cache_req_object_by_id_recv(mem_ctx, req, _result) \
    cache_req_single_domain_recv(mem_ctx, req, _result)
#define cache_req_object_by_name_recv(mem_ctx, req, _result) \
    cache_req_single_domain_recv(mem_ctx, req, _result)
#define cache_req_object_by_sid_recv(mem_ctx, req, _result) \
    cache_req_single_domain_recv(mem_ctx, req, _result)
#define cache_req_ssh_host_id_by_name_recv(mem_ctx, req, _result) \
    cache_req_single_domain_recv(mem_ctx, req, _result)
#define cache_req_svc_by_name_recv(mem_ctx, req, _result) \
    cache_req_single_domain_recv(mem_ctx, req, _result)
#define cache_req_svc_by_port_recv(mem_ctx, req, _result) \
    cache_req_single_domain_recv(mem_ctx, req, _result)
#define cache_req_user_by_cert_recv(mem_ctx, req, _result) \
    cache_req_single_domain_recv(mem_ctx, req, _result)
#define cache_req_user_by_filter_recv(mem_ctx, req, _result) \
    cache_req_single_domain_recv(mem_ctx, req, _result)
#define cache_req_user_by_id_recv(mem_ctx, req, _result) \
    cache_req_single_domain_recv(mem_ctx, req, _result);
#define cache_req_user_by_name_attrs_recv(mem_ctx, req, _result) \
    cache_req_single_domain_recv(mem_ctx, req, _result)
#define cache_req_user_by_name_recv(mem_ctx, req, _result) \
    cache_req_single_domain_recv(mem_ctx, req, _result)

#define DFL_RSP_UMASK SSS_DFL_UMASK
#define GET_DOMAINS_DEFAULT_TIMEOUT 60
#define NEED_CHECK_AUTH_PROVIDER(provider) \
    (provider != NULL && \
      (!local_provider_is_built() || strcmp(provider, "local") != 0))
#define NEED_CHECK_PROVIDER(provider) \
    (provider != NULL && \
     ((!local_provider_is_built() || strcmp(provider, "local") != 0) && \
      strcmp(provider, "files") != 0))
#define SCKT_RSP_UMASK 0111




#define NSS_SBUS_SERVICE_NAME "nss"
#define NSS_SBUS_SERVICE_VERSION 0x0001
#define PAC_SBUS_SERVICE_NAME "pac"
#define PAC_SBUS_SERVICE_VERSION 0x0001
#define SSS_AUTOFS_SBUS_SERVICE_NAME    "autofs"
#define SSS_AUTOFS_SBUS_SERVICE_VERSION 0x0001
#define SSS_BACKEND_ADDRESS "unix:path=" PIPE_PATH "/private/sbus-dp_%s"
#define SSS_BUS_AUTOFS      "sssd.autofs"
#define SSS_BUS_IFP         "sssd.ifp"
#define SSS_BUS_MONITOR     "sssd.monitor"
#define SSS_BUS_NSS         "sssd.nss"
#define SSS_BUS_PAC         "sssd.pac"
#define SSS_BUS_PAM         "sssd.pam"
#define SSS_BUS_PATH        "/sssd"
#define SSS_BUS_SSH         "sssd.ssh"
#define SSS_BUS_SUDO        "sssd.sudo"
#define SSS_IFP_SBUS_SERVICE_NAME    "ifp"
#define SSS_IFP_SBUS_SERVICE_VERSION 0x0001
#define SSS_MONITOR_ADDRESS "unix:path=" PIPE_PATH "/private/sbus-monitor"
#define SSS_PAM_SBUS_SERVICE_NAME "pam"
#define SSS_PAM_SBUS_SERVICE_VERSION 0x0001
#define SSS_SSH_SBUS_SERVICE_NAME    "ssh"
#define SSS_SSH_SBUS_SERVICE_VERSION 0x0001
#define SSS_SUDO_SBUS_SERVICE_NAME "sudo"
#define SSS_SUDO_SBUS_SERVICE_VERSION 0x0001

#define DP_FAST_REPLY   0x0001

#define BE_REQ_BY_CERT        0x0014
#define BE_REQ_BY_SECID       0x0011
#define BE_REQ_BY_UUID        0x0013
#define BE_REQ_GROUP          0x0002
#define BE_REQ_HOST           0x0008
#define BE_REQ_INITGROUPS     0x0003
#define BE_REQ_IP_NETWORK     0x0009
#define BE_REQ_NETGROUP       0x0004
#define BE_REQ_SERVICES       0x0005
#define BE_REQ_SUDO_FULL      0x0006
#define BE_REQ_SUDO_RULES     0x0007
#define BE_REQ_TYPE_MASK      0x00FF
#define BE_REQ_USER           0x0001
#define BE_REQ_USER_AND_GROUP 0x0012



#define DEBUG_PAM_DATA(level, pd) do { \
    if (DEBUG_IS_SET(level)) pam_print_data(level, pd); \
} while(0)





#define sbus_connection_get_data(conn, type) \
    talloc_get_type(_sbus_connection_get_data(conn), type)
#define sbus_connection_set_access_check(conn, check_fn, data) do {           \
    SBUS_CHECK_FUNCTION(check_fn, errno_t,                                    \
                        struct sbus_request *,                                \
                        SBUS_TYPEOF(data));                                   \
    _sbus_connection_set_access_check((conn), #check_fn,                      \
        (sbus_connection_access_check_fn)check_fn,                            \
        (sbus_connection_access_check_data)data);                             \
} while(0)
#define sbus_connection_set_destructor(conn, destructor, data) do {           \
    SBUS_CHECK_FUNCTION(destructor, void, SBUS_TYPEOF(data));                 \
    _sbus_connection_set_destructor((conn), #destructor,                      \
        (sbus_connection_destructor_fn)destructor,                            \
        (sbus_connection_destructor_data)data);                               \
} while(0)
#define sbus_reconnect_enable(conn, max_retries, callback, data) do {         \
    SBUS_CHECK_FUNCTION(callback, void,                                       \
                        struct sbus_connection *,                             \
                        enum sbus_reconnect_status,                           \
                        SBUS_TYPEOF(data));                                   \
    _sbus_reconnect_enable((conn), max_retries,                               \
        (sbus_reconnect_cb)callback, (sbus_reconnect_data)data);              \
} while(0)
#define sbus_server_set_on_connection(server, callback, data) do {            \
    SBUS_CHECK_FUNCTION(callback, errno_t,                                    \
                        struct sbus_connection *,                             \
                        SBUS_TYPEOF(data));                                   \
    _sbus_server_set_on_connection((server), #callback,                       \
        (sbus_server_on_connection_cb)callback,                               \
        (sbus_server_on_connection_data)data);                                \
} while(0)
#define SBUS_ERROR_ERRNO            "sbus.Error.Errno"
#define SBUS_ERROR_INTERNAL         "sbus.Error.Internal"
#define SBUS_ERROR_KILLED           "sbus.Error.ConnectionKilled"
#define SBUS_ERROR_NOT_FOUND        "sbus.Error.NotFound"
#define SBUS_ERROR_SUCCESS          "sbus.Error.Success"

#define SBUS_REQ_STRING(str) (SBUS_REQ_STRING_IS_EMPTY(str) ? NULL : (str))
#define SBUS_REQ_STRING_DEFAULT(str, def) (SBUS_REQ_STRING_IS_EMPTY(str) ? (def) : (str))
#define SBUS_REQ_STRING_IS_EMPTY(str) ((str) == NULL || (str)[0] == '\0')
#define SBUS_SENDER_DBUS  -1
#define SBUS_SENDER_HELLO -2
#define SBUS_SENDER_SIGNAL -3


#define sbus_opath_compose(mem_ctx, base, ...) \
    _sbus_opath_compose(mem_ctx, base, ##__VA_ARGS__, NULL)
#define SBUS_ASYNC(type, iface, property, handler_send, handler_recv, data)   \
    SBUS_ ## type ## _ASYNC_ ## iface ## _ ## property(handler_send, handler_recv, data)
#define SBUS_EMITS(iface, signal)                                             \
    SBUS_SIGNAL_EMITS_ ## iface ## _ ## signal()
#define SBUS_INTERFACE(varname, iface, methods, signals, properties)          \
    const struct sbus_method __ ## varname ## _m[] = methods;                 \
    const struct sbus_signal __ ## varname ## _s[] = signals;                 \
    const struct sbus_property __ ## varname ## _p[] = properties;            \
    struct sbus_interface varname = SBUS_IFACE_ ## iface(                     \
        (__ ## varname ## _m),                                                \
        (__ ## varname ## _s),                                                \
        (__ ## varname ## _p)                                                 \
    )
#define SBUS_LISTENERS(...)                                                   \
    {                                                                         \
        __VA_ARGS__,                                                          \
        SBUS_INTERFACE_SENTINEL                                               \
    }
#define SBUS_LISTEN_ASYNC(iface, property, path, handler_send, handler_recv, data)   \
    SBUS_SIGNAL_ASYNC_ ## iface ## _ ## property(path, handler_send, handler_recv, data)
#define SBUS_LISTEN_SYNC(iface, signal, path, handler, data)                  \
    SBUS_SIGNAL_SYNC_ ## iface ## _ ## signal(path, handler, data)
#define SBUS_METHODS(...)                                                     \
    {                                                                         \
        __VA_ARGS__,                                                          \
        SBUS_INTERFACE_SENTINEL                                               \
    }
#define SBUS_NODES(...)                                                       \
    {                                                                         \
        __VA_ARGS__,                                                          \
        SBUS_INTERFACE_SENTINEL                                               \
    }
#define SBUS_NODE_ASYNC(path, factory_send, factory_recv, data)               \
    _SBUS_NODE_ASYNC(path, handler_send, factory_recv, data)
#define SBUS_NODE_SYNC(path, factory, data)                                   \
    _SBUS_NODE_SYNC(path, factory, data)
#define SBUS_NO_METHODS SBUS_INTERFACE_SENTINEL
#define SBUS_NO_PROPERTIES SBUS_INTERFACE_SENTINEL
#define SBUS_NO_SIGNALS SBUS_INTERFACE_SENTINEL
#define SBUS_PROPERTIES(...)                                                  \
    {                                                                         \
        __VA_ARGS__,                                                          \
        SBUS_INTERFACE_SENTINEL                                               \
    }
#define SBUS_SIGNALS(...)                                                     \
    {                                                                         \
        __VA_ARGS__,                                                          \
        SBUS_INTERFACE_SENTINEL                                               \
    }
#define SBUS_SYNC(type, iface, method, handler, data)                         \
    SBUS_ ## type ## _SYNC_ ## iface ## _ ## method(handler, data)
#define SBUS_WITHOUT_METHODS                                                  \
    SBUS_METHODS(SBUS_NO_METHODS)
#define SBUS_WITHOUT_PROPERTIES                                               \
    SBUS_PROPERTIES(SBUS_NO_PROPERTIES)
#define SBUS_WITHOUT_SIGNALS                                                  \
    SBUS_SIGNALS(SBUS_NO_SIGNALS)

#define SBUS_CHECK_RECV(handler, ...)                                         \
    SBUS_CHECK_FUNCTION((handler),                                            \
                                                             \
                        errno_t,                                              \
                                                  \
                        TALLOC_CTX *,                                         \
                        struct tevent_req *,                                  \
                                 \
                        ## __VA_ARGS__)
#define SBUS_CHECK_SEND(handler, data, ...)                                   \
    SBUS_CHECK_FUNCTION((handler),                                            \
                                                             \
                        struct tevent_req *,                                  \
                                                  \
                        TALLOC_CTX *,                                         \
                        struct tevent_context *,                              \
                        struct sbus_request *,                                \
                        SBUS_TYPEOF(data),                                    \
                                  \
                        ## __VA_ARGS__)                                       \

#define SBUS_CHECK_SYNC(handler, data, ...)                                   \
    SBUS_CHECK_FUNCTION((handler),                                            \
                                                             \
                        errno_t,                                              \
                                                  \
                        TALLOC_CTX *,                                         \
                        struct sbus_request *,                                \
                        SBUS_TYPEOF(data),                                    \
                                        \
                        ## __VA_ARGS__)
#define SBUS_INTERFACE_SENTINEL {0}

#define _SBUS_NODE_ASYNC(path, factory_send, factory_recv, data)  ({          \
    SBUS_CHECK_FUNCTION((factory_send),                                       \
                         struct tevent_req *,                \
                        TALLOC_CTX *, struct tevent_context *ev,              \
                        const char *, SBUS_TYPEOF(data));                     \
    SBUS_CHECK_FUNCTION((factory_recv),                                       \
                         errno_t,                            \
                        TALLOC_CTX *, struct tevent_req *,                    \
                        const char ***);                                      \
    sbus_node_async((path), (factory_send), (factory_recv), (data));          \
})
#define _SBUS_NODE_SYNC(path, factory, data) ({                               \
    SBUS_CHECK_FUNCTION((factory),                                            \
                         errno_t,                            \
                        TALLOC_CTX *, const char *, SBUS_TYPEOF(data),        \
                        const char ***);                                      \
    sbus_node_sync((path), (factory), (data));                                \
})
#define SBUS_CHECK_FUNCTION(handler, return_type, ...) ({                     \
    __attribute__((unused)) return_type (*__fn)(__VA_ARGS__) = (handler);     \
})
#define SBUS_TYPEOF(data) __typeof__(data)



#define SBUS_IFACE_org_freedesktop_FleetCommanderClient(methods, signals, properties) ({ \
    sbus_interface("org.freedesktop.FleetCommanderClient", NULL, \
        (methods), (signals), (properties)); \
})
#define SBUS_IFACE_org_freedesktop_systemd1_Manager(methods, signals, properties) ({ \
    sbus_interface("org.freedesktop.systemd1.Manager", NULL, \
        (methods), (signals), (properties)); \
})
#define SBUS_IFACE_sssd_DataProvider_AccessControl(methods, signals, properties) ({ \
    sbus_interface("sssd.DataProvider.AccessControl", NULL, \
        (methods), (signals), (properties)); \
})
#define SBUS_IFACE_sssd_DataProvider_Autofs(methods, signals, properties) ({ \
    sbus_interface("sssd.DataProvider.Autofs", NULL, \
        (methods), (signals), (properties)); \
})
#define SBUS_IFACE_sssd_DataProvider_Backend(methods, signals, properties) ({ \
    sbus_interface("sssd.DataProvider.Backend", NULL, \
        (methods), (signals), (properties)); \
})
#define SBUS_IFACE_sssd_DataProvider_Client(methods, signals, properties) ({ \
    sbus_interface("sssd.DataProvider.Client", NULL, \
        (methods), (signals), (properties)); \
})
#define SBUS_IFACE_sssd_DataProvider_Failover(methods, signals, properties) ({ \
    sbus_interface("sssd.DataProvider.Failover", NULL, \
        (methods), (signals), (properties)); \
})
#define SBUS_IFACE_sssd_ProxyChild_Auth(methods, signals, properties) ({ \
    sbus_interface("sssd.ProxyChild.Auth", NULL, \
        (methods), (signals), (properties)); \
})
#define SBUS_IFACE_sssd_ProxyChild_Client(methods, signals, properties) ({ \
    sbus_interface("sssd.ProxyChild.Client", NULL, \
        (methods), (signals), (properties)); \
})
#define SBUS_IFACE_sssd_Responder_Domain(methods, signals, properties) ({ \
    sbus_interface("sssd.Responder.Domain", NULL, \
        (methods), (signals), (properties)); \
})
#define SBUS_IFACE_sssd_Responder_NegativeCache(methods, signals, properties) ({ \
    sbus_interface("sssd.Responder.NegativeCache", NULL, \
        (methods), (signals), (properties)); \
})
#define SBUS_IFACE_sssd_dataprovider(methods, signals, properties) ({ \
    sbus_interface("sssd.dataprovider", NULL, \
        (methods), (signals), (properties)); \
})
#define SBUS_IFACE_sssd_monitor(methods, signals, properties) ({ \
    sbus_interface("sssd.monitor", NULL, \
        (methods), (signals), (properties)); \
})
#define SBUS_IFACE_sssd_nss_MemoryCache(methods, signals, properties) ({ \
    sbus_interface("sssd.nss.MemoryCache", NULL, \
        (methods), (signals), (properties)); \
})
#define SBUS_IFACE_sssd_service(methods, signals, properties) ({ \
    sbus_interface("sssd.service", NULL, \
        (methods), (signals), (properties)); \
})
#define SBUS_METHOD_ASYNC_org_freedesktop_FleetCommanderClient_ProcessSSSDFiles(handler_send, handler_recv, data) ({ \
    SBUS_CHECK_SEND((handler_send), (data), uint32_t, const char *, uint16_t); \
    SBUS_CHECK_RECV((handler_recv)); \
    sbus_method_async("ProcessSSSDFiles", \
        &_sbus_sss_args_org_freedesktop_FleetCommanderClient_ProcessSSSDFiles, \
        NULL, \
        _sbus_sss_invoke_in_usq_out__send, \
        NULL, \
        (handler_send), (handler_recv), (data)); \
})
#define SBUS_METHOD_ASYNC_org_freedesktop_systemd1_Manager_RestartUnit(handler_send, handler_recv, data) ({ \
    SBUS_CHECK_SEND((handler_send), (data), const char *, const char *); \
    SBUS_CHECK_RECV((handler_recv), const char **); \
    sbus_method_async("RestartUnit", \
        &_sbus_sss_args_org_freedesktop_systemd1_Manager_RestartUnit, \
        NULL, \
        _sbus_sss_invoke_in_ss_out_o_send, \
        NULL, \
        (handler_send), (handler_recv), (data)); \
})
#define SBUS_METHOD_ASYNC_org_freedesktop_systemd1_Manager_StartUnit(handler_send, handler_recv, data) ({ \
    SBUS_CHECK_SEND((handler_send), (data), const char *, const char *); \
    SBUS_CHECK_RECV((handler_recv), const char **); \
    sbus_method_async("StartUnit", \
        &_sbus_sss_args_org_freedesktop_systemd1_Manager_StartUnit, \
        NULL, \
        _sbus_sss_invoke_in_ss_out_o_send, \
        NULL, \
        (handler_send), (handler_recv), (data)); \
})
#define SBUS_METHOD_ASYNC_org_freedesktop_systemd1_Manager_StopUnit(handler_send, handler_recv, data) ({ \
    SBUS_CHECK_SEND((handler_send), (data), const char *, const char *); \
    SBUS_CHECK_RECV((handler_recv), const char **); \
    sbus_method_async("StopUnit", \
        &_sbus_sss_args_org_freedesktop_systemd1_Manager_StopUnit, \
        NULL, \
        _sbus_sss_invoke_in_ss_out_o_send, \
        NULL, \
        (handler_send), (handler_recv), (data)); \
})
#define SBUS_METHOD_ASYNC_sssd_DataProvider_AccessControl_RefreshRules(handler_send, handler_recv, data) ({ \
    SBUS_CHECK_SEND((handler_send), (data)); \
    SBUS_CHECK_RECV((handler_recv)); \
    sbus_method_async("RefreshRules", \
        &_sbus_sss_args_sssd_DataProvider_AccessControl_RefreshRules, \
        NULL, \
        _sbus_sss_invoke_in__out__send, \
        _sbus_sss_key_, \
        (handler_send), (handler_recv), (data)); \
})
#define SBUS_METHOD_ASYNC_sssd_DataProvider_Autofs_Enumerate(handler_send, handler_recv, data) ({ \
    SBUS_CHECK_SEND((handler_send), (data), uint32_t, const char *); \
    SBUS_CHECK_RECV((handler_recv)); \
    sbus_method_async("Enumerate", \
        &_sbus_sss_args_sssd_DataProvider_Autofs_Enumerate, \
        NULL, \
        _sbus_sss_invoke_in_us_out__send, \
        _sbus_sss_key_us_0_1, \
        (handler_send), (handler_recv), (data)); \
})
#define SBUS_METHOD_ASYNC_sssd_DataProvider_Autofs_GetEntry(handler_send, handler_recv, data) ({ \
    SBUS_CHECK_SEND((handler_send), (data), uint32_t, const char *, const char *); \
    SBUS_CHECK_RECV((handler_recv)); \
    sbus_method_async("GetEntry", \
        &_sbus_sss_args_sssd_DataProvider_Autofs_GetEntry, \
        NULL, \
        _sbus_sss_invoke_in_uss_out__send, \
        _sbus_sss_key_uss_0_1_2, \
        (handler_send), (handler_recv), (data)); \
})
#define SBUS_METHOD_ASYNC_sssd_DataProvider_Autofs_GetMap(handler_send, handler_recv, data) ({ \
    SBUS_CHECK_SEND((handler_send), (data), uint32_t, const char *); \
    SBUS_CHECK_RECV((handler_recv)); \
    sbus_method_async("GetMap", \
        &_sbus_sss_args_sssd_DataProvider_Autofs_GetMap, \
        NULL, \
        _sbus_sss_invoke_in_us_out__send, \
        _sbus_sss_key_us_0_1, \
        (handler_send), (handler_recv), (data)); \
})
#define SBUS_METHOD_ASYNC_sssd_DataProvider_Backend_IsOnline(handler_send, handler_recv, data) ({ \
    SBUS_CHECK_SEND((handler_send), (data), const char *); \
    SBUS_CHECK_RECV((handler_recv), bool*); \
    sbus_method_async("IsOnline", \
        &_sbus_sss_args_sssd_DataProvider_Backend_IsOnline, \
        NULL, \
        _sbus_sss_invoke_in_s_out_b_send, \
        _sbus_sss_key_s_0, \
        (handler_send), (handler_recv), (data)); \
})
#define SBUS_METHOD_ASYNC_sssd_DataProvider_Client_Register(handler_send, handler_recv, data) ({ \
    SBUS_CHECK_SEND((handler_send), (data), const char *); \
    SBUS_CHECK_RECV((handler_recv)); \
    sbus_method_async("Register", \
        &_sbus_sss_args_sssd_DataProvider_Client_Register, \
        NULL, \
        _sbus_sss_invoke_in_s_out__send, \
        NULL, \
        (handler_send), (handler_recv), (data)); \
})
#define SBUS_METHOD_ASYNC_sssd_DataProvider_Failover_ActiveServer(handler_send, handler_recv, data) ({ \
    SBUS_CHECK_SEND((handler_send), (data), const char *); \
    SBUS_CHECK_RECV((handler_recv), const char **); \
    sbus_method_async("ActiveServer", \
        &_sbus_sss_args_sssd_DataProvider_Failover_ActiveServer, \
        NULL, \
        _sbus_sss_invoke_in_s_out_s_send, \
        _sbus_sss_key_s_0, \
        (handler_send), (handler_recv), (data)); \
})
#define SBUS_METHOD_ASYNC_sssd_DataProvider_Failover_ListServers(handler_send, handler_recv, data) ({ \
    SBUS_CHECK_SEND((handler_send), (data), const char *); \
    SBUS_CHECK_RECV((handler_recv), const char ***); \
    sbus_method_async("ListServers", \
        &_sbus_sss_args_sssd_DataProvider_Failover_ListServers, \
        NULL, \
        _sbus_sss_invoke_in_s_out_as_send, \
        _sbus_sss_key_s_0, \
        (handler_send), (handler_recv), (data)); \
})
#define SBUS_METHOD_ASYNC_sssd_DataProvider_Failover_ListServices(handler_send, handler_recv, data) ({ \
    SBUS_CHECK_SEND((handler_send), (data), const char *); \
    SBUS_CHECK_RECV((handler_recv), const char ***); \
    sbus_method_async("ListServices", \
        &_sbus_sss_args_sssd_DataProvider_Failover_ListServices, \
        NULL, \
        _sbus_sss_invoke_in_s_out_as_send, \
        _sbus_sss_key_s_0, \
        (handler_send), (handler_recv), (data)); \
})
#define SBUS_METHOD_ASYNC_sssd_ProxyChild_Auth_PAM(handler_send, handler_recv, data) ({ \
    SBUS_CHECK_SEND((handler_send), (data), struct pam_data *); \
    SBUS_CHECK_RECV((handler_recv), struct pam_data **); \
    sbus_method_async("PAM", \
        &_sbus_sss_args_sssd_ProxyChild_Auth_PAM, \
        NULL, \
        _sbus_sss_invoke_in_pam_data_out_pam_response_send, \
        NULL, \
        (handler_send), (handler_recv), (data)); \
})
#define SBUS_METHOD_ASYNC_sssd_ProxyChild_Client_Register(handler_send, handler_recv, data) ({ \
    SBUS_CHECK_SEND((handler_send), (data), uint32_t); \
    SBUS_CHECK_RECV((handler_recv)); \
    sbus_method_async("Register", \
        &_sbus_sss_args_sssd_ProxyChild_Client_Register, \
        NULL, \
        _sbus_sss_invoke_in_u_out__send, \
        NULL, \
        (handler_send), (handler_recv), (data)); \
})
#define SBUS_METHOD_ASYNC_sssd_Responder_Domain_SetActive(handler_send, handler_recv, data) ({ \
    SBUS_CHECK_SEND((handler_send), (data), const char *); \
    SBUS_CHECK_RECV((handler_recv)); \
    sbus_method_async("SetActive", \
        &_sbus_sss_args_sssd_Responder_Domain_SetActive, \
        NULL, \
        _sbus_sss_invoke_in_s_out__send, \
        _sbus_sss_key_s_0, \
        (handler_send), (handler_recv), (data)); \
})
#define SBUS_METHOD_ASYNC_sssd_Responder_Domain_SetInconsistent(handler_send, handler_recv, data) ({ \
    SBUS_CHECK_SEND((handler_send), (data), const char *); \
    SBUS_CHECK_RECV((handler_recv)); \
    sbus_method_async("SetInconsistent", \
        &_sbus_sss_args_sssd_Responder_Domain_SetInconsistent, \
        NULL, \
        _sbus_sss_invoke_in_s_out__send, \
        _sbus_sss_key_s_0, \
        (handler_send), (handler_recv), (data)); \
})
#define SBUS_METHOD_ASYNC_sssd_Responder_NegativeCache_ResetGroups(handler_send, handler_recv, data) ({ \
    SBUS_CHECK_SEND((handler_send), (data)); \
    SBUS_CHECK_RECV((handler_recv)); \
    sbus_method_async("ResetGroups", \
        &_sbus_sss_args_sssd_Responder_NegativeCache_ResetGroups, \
        NULL, \
        _sbus_sss_invoke_in__out__send, \
        _sbus_sss_key_, \
        (handler_send), (handler_recv), (data)); \
})
#define SBUS_METHOD_ASYNC_sssd_Responder_NegativeCache_ResetUsers(handler_send, handler_recv, data) ({ \
    SBUS_CHECK_SEND((handler_send), (data)); \
    SBUS_CHECK_RECV((handler_recv)); \
    sbus_method_async("ResetUsers", \
        &_sbus_sss_args_sssd_Responder_NegativeCache_ResetUsers, \
        NULL, \
        _sbus_sss_invoke_in__out__send, \
        _sbus_sss_key_, \
        (handler_send), (handler_recv), (data)); \
})
#define SBUS_METHOD_ASYNC_sssd_dataprovider_getAccountDomain(handler_send, handler_recv, data) ({ \
    SBUS_CHECK_SEND((handler_send), (data), uint32_t, const char *); \
    SBUS_CHECK_RECV((handler_recv), uint16_t*, uint32_t*, const char **); \
    sbus_method_async("getAccountDomain", \
        &_sbus_sss_args_sssd_dataprovider_getAccountDomain, \
        NULL, \
        _sbus_sss_invoke_in_us_out_qus_send, \
        _sbus_sss_key_us_0_1, \
        (handler_send), (handler_recv), (data)); \
})
#define SBUS_METHOD_ASYNC_sssd_dataprovider_getAccountInfo(handler_send, handler_recv, data) ({ \
    SBUS_CHECK_SEND((handler_send), (data), uint32_t, uint32_t, const char *, const char *, const char *); \
    SBUS_CHECK_RECV((handler_recv), uint16_t*, uint32_t*, const char **); \
    sbus_method_async("getAccountInfo", \
        &_sbus_sss_args_sssd_dataprovider_getAccountInfo, \
        NULL, \
        _sbus_sss_invoke_in_uusss_out_qus_send, \
        _sbus_sss_key_uusss_0_1_2_3_4, \
        (handler_send), (handler_recv), (data)); \
})
#define SBUS_METHOD_ASYNC_sssd_dataprovider_getDomains(handler_send, handler_recv, data) ({ \
    SBUS_CHECK_SEND((handler_send), (data), const char *); \
    SBUS_CHECK_RECV((handler_recv), uint16_t*, uint32_t*, const char **); \
    sbus_method_async("getDomains", \
        &_sbus_sss_args_sssd_dataprovider_getDomains, \
        NULL, \
        _sbus_sss_invoke_in_s_out_qus_send, \
        _sbus_sss_key_s_0, \
        (handler_send), (handler_recv), (data)); \
})
#define SBUS_METHOD_ASYNC_sssd_dataprovider_hostHandler(handler_send, handler_recv, data) ({ \
    SBUS_CHECK_SEND((handler_send), (data), uint32_t, const char *, const char *); \
    SBUS_CHECK_RECV((handler_recv), uint16_t*, uint32_t*, const char **); \
    sbus_method_async("hostHandler", \
        &_sbus_sss_args_sssd_dataprovider_hostHandler, \
        NULL, \
        _sbus_sss_invoke_in_uss_out_qus_send, \
        _sbus_sss_key_uss_0_1, \
        (handler_send), (handler_recv), (data)); \
})
#define SBUS_METHOD_ASYNC_sssd_dataprovider_pamHandler(handler_send, handler_recv, data) ({ \
    SBUS_CHECK_SEND((handler_send), (data), struct pam_data *); \
    SBUS_CHECK_RECV((handler_recv), struct pam_data **); \
    sbus_method_async("pamHandler", \
        &_sbus_sss_args_sssd_dataprovider_pamHandler, \
        NULL, \
        _sbus_sss_invoke_in_pam_data_out_pam_response_send, \
        NULL, \
        (handler_send), (handler_recv), (data)); \
})
#define SBUS_METHOD_ASYNC_sssd_dataprovider_resolverHandler(handler_send, handler_recv, data) ({ \
    SBUS_CHECK_SEND((handler_send), (data), uint32_t, uint32_t, uint32_t, const char *); \
    SBUS_CHECK_RECV((handler_recv), uint16_t*, uint32_t*, const char **); \
    sbus_method_async("resolverHandler", \
        &_sbus_sss_args_sssd_dataprovider_resolverHandler, \
        NULL, \
        _sbus_sss_invoke_in_uuus_out_qus_send, \
        _sbus_sss_key_uuus_0_1_2_3, \
        (handler_send), (handler_recv), (data)); \
})
#define SBUS_METHOD_ASYNC_sssd_dataprovider_sudoHandler(handler_send, handler_recv, data) ({ \
    SBUS_CHECK_SEND((handler_send), (data), DBusMessageIter *); \
    SBUS_CHECK_RECV((handler_recv), uint16_t*, uint32_t*, const char **); \
    sbus_method_async("sudoHandler", \
        &_sbus_sss_args_sssd_dataprovider_sudoHandler, \
        NULL, \
        _sbus_sss_invoke_in_raw_out_qus_send, \
        NULL, \
        (handler_send), (handler_recv), (data)); \
})
#define SBUS_METHOD_ASYNC_sssd_monitor_RegisterService(handler_send, handler_recv, data) ({ \
    SBUS_CHECK_SEND((handler_send), (data), const char *, uint16_t, uint16_t); \
    SBUS_CHECK_RECV((handler_recv), uint16_t*); \
    sbus_method_async("RegisterService", \
        &_sbus_sss_args_sssd_monitor_RegisterService, \
        NULL, \
        _sbus_sss_invoke_in_sqq_out_q_send, \
        NULL, \
        (handler_send), (handler_recv), (data)); \
})
#define SBUS_METHOD_ASYNC_sssd_nss_MemoryCache_InvalidateAllGroups(handler_send, handler_recv, data) ({ \
    SBUS_CHECK_SEND((handler_send), (data)); \
    SBUS_CHECK_RECV((handler_recv)); \
    sbus_method_async("InvalidateAllGroups", \
        &_sbus_sss_args_sssd_nss_MemoryCache_InvalidateAllGroups, \
        NULL, \
        _sbus_sss_invoke_in__out__send, \
        _sbus_sss_key_, \
        (handler_send), (handler_recv), (data)); \
})
#define SBUS_METHOD_ASYNC_sssd_nss_MemoryCache_InvalidateAllInitgroups(handler_send, handler_recv, data) ({ \
    SBUS_CHECK_SEND((handler_send), (data)); \
    SBUS_CHECK_RECV((handler_recv)); \
    sbus_method_async("InvalidateAllInitgroups", \
        &_sbus_sss_args_sssd_nss_MemoryCache_InvalidateAllInitgroups, \
        NULL, \
        _sbus_sss_invoke_in__out__send, \
        _sbus_sss_key_, \
        (handler_send), (handler_recv), (data)); \
})
#define SBUS_METHOD_ASYNC_sssd_nss_MemoryCache_InvalidateAllUsers(handler_send, handler_recv, data) ({ \
    SBUS_CHECK_SEND((handler_send), (data)); \
    SBUS_CHECK_RECV((handler_recv)); \
    sbus_method_async("InvalidateAllUsers", \
        &_sbus_sss_args_sssd_nss_MemoryCache_InvalidateAllUsers, \
        NULL, \
        _sbus_sss_invoke_in__out__send, \
        _sbus_sss_key_, \
        (handler_send), (handler_recv), (data)); \
})
#define SBUS_METHOD_ASYNC_sssd_nss_MemoryCache_InvalidateGroupById(handler_send, handler_recv, data) ({ \
    SBUS_CHECK_SEND((handler_send), (data), uint32_t); \
    SBUS_CHECK_RECV((handler_recv)); \
    sbus_method_async("InvalidateGroupById", \
        &_sbus_sss_args_sssd_nss_MemoryCache_InvalidateGroupById, \
        NULL, \
        _sbus_sss_invoke_in_u_out__send, \
        _sbus_sss_key_u_0, \
        (handler_send), (handler_recv), (data)); \
})
#define SBUS_METHOD_ASYNC_sssd_nss_MemoryCache_UpdateInitgroups(handler_send, handler_recv, data) ({ \
    SBUS_CHECK_SEND((handler_send), (data), const char *, const char *, uint32_t *); \
    SBUS_CHECK_RECV((handler_recv)); \
    sbus_method_async("UpdateInitgroups", \
        &_sbus_sss_args_sssd_nss_MemoryCache_UpdateInitgroups, \
        NULL, \
        _sbus_sss_invoke_in_ssau_out__send, \
        NULL, \
        (handler_send), (handler_recv), (data)); \
})
#define SBUS_METHOD_ASYNC_sssd_service_clearEnumCache(handler_send, handler_recv, data) ({ \
    SBUS_CHECK_SEND((handler_send), (data)); \
    SBUS_CHECK_RECV((handler_recv)); \
    sbus_method_async("clearEnumCache", \
        &_sbus_sss_args_sssd_service_clearEnumCache, \
        NULL, \
        _sbus_sss_invoke_in__out__send, \
        NULL, \
        (handler_send), (handler_recv), (data)); \
})
#define SBUS_METHOD_ASYNC_sssd_service_clearMemcache(handler_send, handler_recv, data) ({ \
    SBUS_CHECK_SEND((handler_send), (data)); \
    SBUS_CHECK_RECV((handler_recv)); \
    sbus_method_async("clearMemcache", \
        &_sbus_sss_args_sssd_service_clearMemcache, \
        NULL, \
        _sbus_sss_invoke_in__out__send, \
        NULL, \
        (handler_send), (handler_recv), (data)); \
})
#define SBUS_METHOD_ASYNC_sssd_service_goOffline(handler_send, handler_recv, data) ({ \
    SBUS_CHECK_SEND((handler_send), (data)); \
    SBUS_CHECK_RECV((handler_recv)); \
    sbus_method_async("goOffline", \
        &_sbus_sss_args_sssd_service_goOffline, \
        NULL, \
        _sbus_sss_invoke_in__out__send, \
        NULL, \
        (handler_send), (handler_recv), (data)); \
})
#define SBUS_METHOD_ASYNC_sssd_service_resInit(handler_send, handler_recv, data) ({ \
    SBUS_CHECK_SEND((handler_send), (data)); \
    SBUS_CHECK_RECV((handler_recv)); \
    sbus_method_async("resInit", \
        &_sbus_sss_args_sssd_service_resInit, \
        NULL, \
        _sbus_sss_invoke_in__out__send, \
        NULL, \
        (handler_send), (handler_recv), (data)); \
})
#define SBUS_METHOD_ASYNC_sssd_service_resetOffline(handler_send, handler_recv, data) ({ \
    SBUS_CHECK_SEND((handler_send), (data)); \
    SBUS_CHECK_RECV((handler_recv)); \
    sbus_method_async("resetOffline", \
        &_sbus_sss_args_sssd_service_resetOffline, \
        NULL, \
        _sbus_sss_invoke_in__out__send, \
        NULL, \
        (handler_send), (handler_recv), (data)); \
})
#define SBUS_METHOD_ASYNC_sssd_service_rotateLogs(handler_send, handler_recv, data) ({ \
    SBUS_CHECK_SEND((handler_send), (data)); \
    SBUS_CHECK_RECV((handler_recv)); \
    sbus_method_async("rotateLogs", \
        &_sbus_sss_args_sssd_service_rotateLogs, \
        NULL, \
        _sbus_sss_invoke_in__out__send, \
        NULL, \
        (handler_send), (handler_recv), (data)); \
})
#define SBUS_METHOD_ASYNC_sssd_service_sysbusReconnect(handler_send, handler_recv, data) ({ \
    SBUS_CHECK_SEND((handler_send), (data)); \
    SBUS_CHECK_RECV((handler_recv)); \
    sbus_method_async("sysbusReconnect", \
        &_sbus_sss_args_sssd_service_sysbusReconnect, \
        NULL, \
        _sbus_sss_invoke_in__out__send, \
        NULL, \
        (handler_send), (handler_recv), (data)); \
})
#define SBUS_METHOD_SYNC_org_freedesktop_FleetCommanderClient_ProcessSSSDFiles(handler, data) ({ \
    SBUS_CHECK_SYNC((handler), (data), uint32_t, const char *, uint16_t); \
    sbus_method_sync("ProcessSSSDFiles", \
        &_sbus_sss_args_org_freedesktop_FleetCommanderClient_ProcessSSSDFiles, \
        NULL, \
        _sbus_sss_invoke_in_usq_out__send, \
        NULL, \
        (handler), (data)); \
})
#define SBUS_METHOD_SYNC_org_freedesktop_systemd1_Manager_RestartUnit(handler, data) ({ \
    SBUS_CHECK_SYNC((handler), (data), const char *, const char *, const char **); \
    sbus_method_sync("RestartUnit", \
        &_sbus_sss_args_org_freedesktop_systemd1_Manager_RestartUnit, \
        NULL, \
        _sbus_sss_invoke_in_ss_out_o_send, \
        NULL, \
        (handler), (data)); \
})
#define SBUS_METHOD_SYNC_org_freedesktop_systemd1_Manager_StartUnit(handler, data) ({ \
    SBUS_CHECK_SYNC((handler), (data), const char *, const char *, const char **); \
    sbus_method_sync("StartUnit", \
        &_sbus_sss_args_org_freedesktop_systemd1_Manager_StartUnit, \
        NULL, \
        _sbus_sss_invoke_in_ss_out_o_send, \
        NULL, \
        (handler), (data)); \
})
#define SBUS_METHOD_SYNC_org_freedesktop_systemd1_Manager_StopUnit(handler, data) ({ \
    SBUS_CHECK_SYNC((handler), (data), const char *, const char *, const char **); \
    sbus_method_sync("StopUnit", \
        &_sbus_sss_args_org_freedesktop_systemd1_Manager_StopUnit, \
        NULL, \
        _sbus_sss_invoke_in_ss_out_o_send, \
        NULL, \
        (handler), (data)); \
})
#define SBUS_METHOD_SYNC_sssd_DataProvider_AccessControl_RefreshRules(handler, data) ({ \
    SBUS_CHECK_SYNC((handler), (data)); \
    sbus_method_sync("RefreshRules", \
        &_sbus_sss_args_sssd_DataProvider_AccessControl_RefreshRules, \
        NULL, \
        _sbus_sss_invoke_in__out__send, \
        _sbus_sss_key_, \
        (handler), (data)); \
})
#define SBUS_METHOD_SYNC_sssd_DataProvider_Autofs_Enumerate(handler, data) ({ \
    SBUS_CHECK_SYNC((handler), (data), uint32_t, const char *); \
    sbus_method_sync("Enumerate", \
        &_sbus_sss_args_sssd_DataProvider_Autofs_Enumerate, \
        NULL, \
        _sbus_sss_invoke_in_us_out__send, \
        _sbus_sss_key_us_0_1, \
        (handler), (data)); \
})
#define SBUS_METHOD_SYNC_sssd_DataProvider_Autofs_GetEntry(handler, data) ({ \
    SBUS_CHECK_SYNC((handler), (data), uint32_t, const char *, const char *); \
    sbus_method_sync("GetEntry", \
        &_sbus_sss_args_sssd_DataProvider_Autofs_GetEntry, \
        NULL, \
        _sbus_sss_invoke_in_uss_out__send, \
        _sbus_sss_key_uss_0_1_2, \
        (handler), (data)); \
})
#define SBUS_METHOD_SYNC_sssd_DataProvider_Autofs_GetMap(handler, data) ({ \
    SBUS_CHECK_SYNC((handler), (data), uint32_t, const char *); \
    sbus_method_sync("GetMap", \
        &_sbus_sss_args_sssd_DataProvider_Autofs_GetMap, \
        NULL, \
        _sbus_sss_invoke_in_us_out__send, \
        _sbus_sss_key_us_0_1, \
        (handler), (data)); \
})
#define SBUS_METHOD_SYNC_sssd_DataProvider_Backend_IsOnline(handler, data) ({ \
    SBUS_CHECK_SYNC((handler), (data), const char *, bool*); \
    sbus_method_sync("IsOnline", \
        &_sbus_sss_args_sssd_DataProvider_Backend_IsOnline, \
        NULL, \
        _sbus_sss_invoke_in_s_out_b_send, \
        _sbus_sss_key_s_0, \
        (handler), (data)); \
})
#define SBUS_METHOD_SYNC_sssd_DataProvider_Client_Register(handler, data) ({ \
    SBUS_CHECK_SYNC((handler), (data), const char *); \
    sbus_method_sync("Register", \
        &_sbus_sss_args_sssd_DataProvider_Client_Register, \
        NULL, \
        _sbus_sss_invoke_in_s_out__send, \
        NULL, \
        (handler), (data)); \
})
#define SBUS_METHOD_SYNC_sssd_DataProvider_Failover_ActiveServer(handler, data) ({ \
    SBUS_CHECK_SYNC((handler), (data), const char *, const char **); \
    sbus_method_sync("ActiveServer", \
        &_sbus_sss_args_sssd_DataProvider_Failover_ActiveServer, \
        NULL, \
        _sbus_sss_invoke_in_s_out_s_send, \
        _sbus_sss_key_s_0, \
        (handler), (data)); \
})
#define SBUS_METHOD_SYNC_sssd_DataProvider_Failover_ListServers(handler, data) ({ \
    SBUS_CHECK_SYNC((handler), (data), const char *, const char ***); \
    sbus_method_sync("ListServers", \
        &_sbus_sss_args_sssd_DataProvider_Failover_ListServers, \
        NULL, \
        _sbus_sss_invoke_in_s_out_as_send, \
        _sbus_sss_key_s_0, \
        (handler), (data)); \
})
#define SBUS_METHOD_SYNC_sssd_DataProvider_Failover_ListServices(handler, data) ({ \
    SBUS_CHECK_SYNC((handler), (data), const char *, const char ***); \
    sbus_method_sync("ListServices", \
        &_sbus_sss_args_sssd_DataProvider_Failover_ListServices, \
        NULL, \
        _sbus_sss_invoke_in_s_out_as_send, \
        _sbus_sss_key_s_0, \
        (handler), (data)); \
})
#define SBUS_METHOD_SYNC_sssd_ProxyChild_Auth_PAM(handler, data) ({ \
    SBUS_CHECK_SYNC((handler), (data), struct pam_data *, struct pam_data **); \
    sbus_method_sync("PAM", \
        &_sbus_sss_args_sssd_ProxyChild_Auth_PAM, \
        NULL, \
        _sbus_sss_invoke_in_pam_data_out_pam_response_send, \
        NULL, \
        (handler), (data)); \
})
#define SBUS_METHOD_SYNC_sssd_ProxyChild_Client_Register(handler, data) ({ \
    SBUS_CHECK_SYNC((handler), (data), uint32_t); \
    sbus_method_sync("Register", \
        &_sbus_sss_args_sssd_ProxyChild_Client_Register, \
        NULL, \
        _sbus_sss_invoke_in_u_out__send, \
        NULL, \
        (handler), (data)); \
})
#define SBUS_METHOD_SYNC_sssd_Responder_Domain_SetActive(handler, data) ({ \
    SBUS_CHECK_SYNC((handler), (data), const char *); \
    sbus_method_sync("SetActive", \
        &_sbus_sss_args_sssd_Responder_Domain_SetActive, \
        NULL, \
        _sbus_sss_invoke_in_s_out__send, \
        _sbus_sss_key_s_0, \
        (handler), (data)); \
})
#define SBUS_METHOD_SYNC_sssd_Responder_Domain_SetInconsistent(handler, data) ({ \
    SBUS_CHECK_SYNC((handler), (data), const char *); \
    sbus_method_sync("SetInconsistent", \
        &_sbus_sss_args_sssd_Responder_Domain_SetInconsistent, \
        NULL, \
        _sbus_sss_invoke_in_s_out__send, \
        _sbus_sss_key_s_0, \
        (handler), (data)); \
})
#define SBUS_METHOD_SYNC_sssd_Responder_NegativeCache_ResetGroups(handler, data) ({ \
    SBUS_CHECK_SYNC((handler), (data)); \
    sbus_method_sync("ResetGroups", \
        &_sbus_sss_args_sssd_Responder_NegativeCache_ResetGroups, \
        NULL, \
        _sbus_sss_invoke_in__out__send, \
        _sbus_sss_key_, \
        (handler), (data)); \
})
#define SBUS_METHOD_SYNC_sssd_Responder_NegativeCache_ResetUsers(handler, data) ({ \
    SBUS_CHECK_SYNC((handler), (data)); \
    sbus_method_sync("ResetUsers", \
        &_sbus_sss_args_sssd_Responder_NegativeCache_ResetUsers, \
        NULL, \
        _sbus_sss_invoke_in__out__send, \
        _sbus_sss_key_, \
        (handler), (data)); \
})
#define SBUS_METHOD_SYNC_sssd_dataprovider_getAccountDomain(handler, data) ({ \
    SBUS_CHECK_SYNC((handler), (data), uint32_t, const char *, uint16_t*, uint32_t*, const char **); \
    sbus_method_sync("getAccountDomain", \
        &_sbus_sss_args_sssd_dataprovider_getAccountDomain, \
        NULL, \
        _sbus_sss_invoke_in_us_out_qus_send, \
        _sbus_sss_key_us_0_1, \
        (handler), (data)); \
})
#define SBUS_METHOD_SYNC_sssd_dataprovider_getAccountInfo(handler, data) ({ \
    SBUS_CHECK_SYNC((handler), (data), uint32_t, uint32_t, const char *, const char *, const char *, uint16_t*, uint32_t*, const char **); \
    sbus_method_sync("getAccountInfo", \
        &_sbus_sss_args_sssd_dataprovider_getAccountInfo, \
        NULL, \
        _sbus_sss_invoke_in_uusss_out_qus_send, \
        _sbus_sss_key_uusss_0_1_2_3_4, \
        (handler), (data)); \
})
#define SBUS_METHOD_SYNC_sssd_dataprovider_getDomains(handler, data) ({ \
    SBUS_CHECK_SYNC((handler), (data), const char *, uint16_t*, uint32_t*, const char **); \
    sbus_method_sync("getDomains", \
        &_sbus_sss_args_sssd_dataprovider_getDomains, \
        NULL, \
        _sbus_sss_invoke_in_s_out_qus_send, \
        _sbus_sss_key_s_0, \
        (handler), (data)); \
})
#define SBUS_METHOD_SYNC_sssd_dataprovider_hostHandler(handler, data) ({ \
    SBUS_CHECK_SYNC((handler), (data), uint32_t, const char *, const char *, uint16_t*, uint32_t*, const char **); \
    sbus_method_sync("hostHandler", \
        &_sbus_sss_args_sssd_dataprovider_hostHandler, \
        NULL, \
        _sbus_sss_invoke_in_uss_out_qus_send, \
        _sbus_sss_key_uss_0_1, \
        (handler), (data)); \
})
#define SBUS_METHOD_SYNC_sssd_dataprovider_pamHandler(handler, data) ({ \
    SBUS_CHECK_SYNC((handler), (data), struct pam_data *, struct pam_data **); \
    sbus_method_sync("pamHandler", \
        &_sbus_sss_args_sssd_dataprovider_pamHandler, \
        NULL, \
        _sbus_sss_invoke_in_pam_data_out_pam_response_send, \
        NULL, \
        (handler), (data)); \
})
#define SBUS_METHOD_SYNC_sssd_dataprovider_resolverHandler(handler, data) ({ \
    SBUS_CHECK_SYNC((handler), (data), uint32_t, uint32_t, uint32_t, const char *, uint16_t*, uint32_t*, const char **); \
    sbus_method_sync("resolverHandler", \
        &_sbus_sss_args_sssd_dataprovider_resolverHandler, \
        NULL, \
        _sbus_sss_invoke_in_uuus_out_qus_send, \
        _sbus_sss_key_uuus_0_1_2_3, \
        (handler), (data)); \
})
#define SBUS_METHOD_SYNC_sssd_dataprovider_sudoHandler(handler, data) ({ \
    SBUS_CHECK_SYNC((handler), (data), DBusMessageIter *, uint16_t*, uint32_t*, const char **); \
    sbus_method_sync("sudoHandler", \
        &_sbus_sss_args_sssd_dataprovider_sudoHandler, \
        NULL, \
        _sbus_sss_invoke_in_raw_out_qus_send, \
        NULL, \
        (handler), (data)); \
})
#define SBUS_METHOD_SYNC_sssd_monitor_RegisterService(handler, data) ({ \
    SBUS_CHECK_SYNC((handler), (data), const char *, uint16_t, uint16_t, uint16_t*); \
    sbus_method_sync("RegisterService", \
        &_sbus_sss_args_sssd_monitor_RegisterService, \
        NULL, \
        _sbus_sss_invoke_in_sqq_out_q_send, \
        NULL, \
        (handler), (data)); \
})
#define SBUS_METHOD_SYNC_sssd_nss_MemoryCache_InvalidateAllGroups(handler, data) ({ \
    SBUS_CHECK_SYNC((handler), (data)); \
    sbus_method_sync("InvalidateAllGroups", \
        &_sbus_sss_args_sssd_nss_MemoryCache_InvalidateAllGroups, \
        NULL, \
        _sbus_sss_invoke_in__out__send, \
        _sbus_sss_key_, \
        (handler), (data)); \
})
#define SBUS_METHOD_SYNC_sssd_nss_MemoryCache_InvalidateAllInitgroups(handler, data) ({ \
    SBUS_CHECK_SYNC((handler), (data)); \
    sbus_method_sync("InvalidateAllInitgroups", \
        &_sbus_sss_args_sssd_nss_MemoryCache_InvalidateAllInitgroups, \
        NULL, \
        _sbus_sss_invoke_in__out__send, \
        _sbus_sss_key_, \
        (handler), (data)); \
})
#define SBUS_METHOD_SYNC_sssd_nss_MemoryCache_InvalidateAllUsers(handler, data) ({ \
    SBUS_CHECK_SYNC((handler), (data)); \
    sbus_method_sync("InvalidateAllUsers", \
        &_sbus_sss_args_sssd_nss_MemoryCache_InvalidateAllUsers, \
        NULL, \
        _sbus_sss_invoke_in__out__send, \
        _sbus_sss_key_, \
        (handler), (data)); \
})
#define SBUS_METHOD_SYNC_sssd_nss_MemoryCache_InvalidateGroupById(handler, data) ({ \
    SBUS_CHECK_SYNC((handler), (data), uint32_t); \
    sbus_method_sync("InvalidateGroupById", \
        &_sbus_sss_args_sssd_nss_MemoryCache_InvalidateGroupById, \
        NULL, \
        _sbus_sss_invoke_in_u_out__send, \
        _sbus_sss_key_u_0, \
        (handler), (data)); \
})
#define SBUS_METHOD_SYNC_sssd_nss_MemoryCache_UpdateInitgroups(handler, data) ({ \
    SBUS_CHECK_SYNC((handler), (data), const char *, const char *, uint32_t *); \
    sbus_method_sync("UpdateInitgroups", \
        &_sbus_sss_args_sssd_nss_MemoryCache_UpdateInitgroups, \
        NULL, \
        _sbus_sss_invoke_in_ssau_out__send, \
        NULL, \
        (handler), (data)); \
})
#define SBUS_METHOD_SYNC_sssd_service_clearEnumCache(handler, data) ({ \
    SBUS_CHECK_SYNC((handler), (data)); \
    sbus_method_sync("clearEnumCache", \
        &_sbus_sss_args_sssd_service_clearEnumCache, \
        NULL, \
        _sbus_sss_invoke_in__out__send, \
        NULL, \
        (handler), (data)); \
})
#define SBUS_METHOD_SYNC_sssd_service_clearMemcache(handler, data) ({ \
    SBUS_CHECK_SYNC((handler), (data)); \
    sbus_method_sync("clearMemcache", \
        &_sbus_sss_args_sssd_service_clearMemcache, \
        NULL, \
        _sbus_sss_invoke_in__out__send, \
        NULL, \
        (handler), (data)); \
})
#define SBUS_METHOD_SYNC_sssd_service_goOffline(handler, data) ({ \
    SBUS_CHECK_SYNC((handler), (data)); \
    sbus_method_sync("goOffline", \
        &_sbus_sss_args_sssd_service_goOffline, \
        NULL, \
        _sbus_sss_invoke_in__out__send, \
        NULL, \
        (handler), (data)); \
})
#define SBUS_METHOD_SYNC_sssd_service_resInit(handler, data) ({ \
    SBUS_CHECK_SYNC((handler), (data)); \
    sbus_method_sync("resInit", \
        &_sbus_sss_args_sssd_service_resInit, \
        NULL, \
        _sbus_sss_invoke_in__out__send, \
        NULL, \
        (handler), (data)); \
})
#define SBUS_METHOD_SYNC_sssd_service_resetOffline(handler, data) ({ \
    SBUS_CHECK_SYNC((handler), (data)); \
    sbus_method_sync("resetOffline", \
        &_sbus_sss_args_sssd_service_resetOffline, \
        NULL, \
        _sbus_sss_invoke_in__out__send, \
        NULL, \
        (handler), (data)); \
})
#define SBUS_METHOD_SYNC_sssd_service_rotateLogs(handler, data) ({ \
    SBUS_CHECK_SYNC((handler), (data)); \
    sbus_method_sync("rotateLogs", \
        &_sbus_sss_args_sssd_service_rotateLogs, \
        NULL, \
        _sbus_sss_invoke_in__out__send, \
        NULL, \
        (handler), (data)); \
})
#define SBUS_METHOD_SYNC_sssd_service_sysbusReconnect(handler, data) ({ \
    SBUS_CHECK_SYNC((handler), (data)); \
    sbus_method_sync("sysbusReconnect", \
        &_sbus_sss_args_sssd_service_sysbusReconnect, \
        NULL, \
        _sbus_sss_invoke_in__out__send, \
        NULL, \
        (handler), (data)); \
})





#define _sbus_sss_declare_invoker(input, output)                               \
    struct tevent_req *                                                   \
    _sbus_sss_invoke_in_ ## input ## _out_ ## output ## _send                 \
        (TALLOC_CTX *mem_ctx,                                             \
         struct tevent_context *ev,                                       \
         struct sbus_request *sbus_req,                                   \
         sbus_invoker_keygen keygen,                                      \
         const struct sbus_handler *handler,                              \
         DBusMessageIter *read_iterator,                                  \
         DBusMessageIter *write_iterator,                                 \
         const char **_key)

#define CHILD_MSG_CHUNK     256
#define CHILD_TIMEOUT_EXIT_CODE 7
#define IN_BUF_SIZE         512
#define SIGTERM_TO_SIGKILL_TIME 2

#define BE_FILTER_ADDR 8
#define BE_FILTER_CERT 6
#define BE_FILTER_ENUM 3
#define BE_FILTER_IDNUM 2
#define BE_FILTER_NAME 1
#define BE_FILTER_SECID 4
#define BE_FILTER_UUID 5
#define BE_FILTER_WILDCARD 7
#define BOOL_FALSE { .boolean = false }
#define BOOL_TRUE { .boolean = true }
#define DATA_PROVIDER_PIPE "private/sbus-dp"
#define DATA_PROVIDER_VERSION 0x0001
#define DP_CERT "cert"
#define DP_CERT_LEN (sizeof(DP_CERT) - 1)
#define DP_ERR_DECIDE -1
#define DP_ERR_FATAL 3
#define DP_ERR_OFFLINE 1
#define DP_ERR_OK 0
#define DP_ERR_TIMEOUT 2
#define DP_OPTION_TERMINATOR { NULL, 0, NULL_STRING, NULL_STRING }
#define DP_PATH "/org/freedesktop/sssd/dataprovider"
#define DP_REQ_OPT_FILES_INITGR     "files_initgr_request"
#define DP_SEC_ID "secid"
#define DP_SEC_ID_LEN (sizeof(DP_SEC_ID) - 1)
#define DP_WILDCARD "wildcard"
#define DP_WILDCARD_LEN (sizeof(DP_WILDCARD) - 1)
#define EXTRA_INPUT_MAYBE_WITH_VIEW "V"
#define EXTRA_NAME_IS_UPN "U"
#define NULL_BLOB { .blob = { NULL, 0 } }
#define NULL_NUMBER { .number = 0 }
#define NULL_STRING { .string = NULL }
#define SSS_KRB5_INFO 0x40000000
#define SSS_KRB5_INFO_TGT_LIFETIME (SSS_SERVER_INFO|SSS_KRB5_INFO|0x01)
#define SSS_KRB5_INFO_UPN (SSS_SERVER_INFO|SSS_KRB5_INFO|0x02)
#define SSS_LDAP_INFO 0x20000000
#define SSS_PROXY_INFO 0x10000000
#define SSS_SERVER_INFO 0x80000000

#define dp_opt_get_blob(o, i) _dp_opt_get_blob(o, i, __FUNCTION__)
#define dp_opt_get_bool(o, i) _dp_opt_get_bool(o, i, __FUNCTION__)
#define dp_opt_get_cstring(o, i) _dp_opt_get_cstring(o, i, __FUNCTION__)
#define dp_opt_get_int(o, i) _dp_opt_get_int(o, i, __FUNCTION__)
#define dp_opt_get_string(o, i) _dp_opt_get_string(o, i, __FUNCTION__)
#define dp_opt_set_blob(o, i, v) _dp_opt_set_blob(o, i, v, __FUNCTION__)
#define dp_opt_set_bool(o, i, v) _dp_opt_set_bool(o, i, v, __FUNCTION__)
#define dp_opt_set_int(o, i, v) _dp_opt_set_int(o, i, v, __FUNCTION__)
#define dp_opt_set_string(o, i, v) _dp_opt_set_string(o, i, v, __FUNCTION__)
