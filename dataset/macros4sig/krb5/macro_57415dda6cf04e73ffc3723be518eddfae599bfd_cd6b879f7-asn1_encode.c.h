

#include<sys/file.h>

#include<arpa/inet.h>
#include<time.h>
#include<sys/socket.h>

#include<limits.h>

#include<sys/types.h>
#include<stdint.h>

#include<netdb.h>
#include<string.h>

#include<errno.h>




#include<netinet/in.h>
#include<stdlib.h>

#include<fcntl.h>

#include<stdarg.h>
#include<stdio.h>


#include<sys/stat.h>

#include<sys/param.h>
#include<unistd.h>
#include<assert.h>
#include<getopt.h>
#include<libintl.h>
#include<sys/uio.h>

#include<fnmatch.h>

#include<net/if.h>
#include<stddef.h>



#include<sys/time.h>
#define DEFAPPTAGGEDTYPE(DESCNAME, TAG, BASEDESC)                       \
    DEFTAGGEDTYPE(DESCNAME, APPLICATION, CONSTRUCTED, TAG, 0, BASEDESC)
#define DEFBOOLTYPE(DESCNAME, CTYPENAME)                        \
    typedef CTYPENAME aux_type_##DESCNAME;                      \
    const struct atype_info k5_atype_##DESCNAME = {             \
        atype_bool, sizeof(CTYPENAME), NULL                     \
    }
#define DEFCHOICETYPE(DESCNAME, UTYPE, DTYPE, FIELDS)           \
    typedef UTYPE aux_ptrtype_##DESCNAME;                       \
    typedef DTYPE aux_counttype_##DESCNAME;                     \
    static const struct choice_info aux_info_##DESCNAME = {     \
        FIELDS, sizeof(FIELDS) / sizeof(FIELDS[0])              \
    };                                                          \
    const struct cntype_info k5_cntype_##DESCNAME = {           \
        cntype_choice, &aux_info_##DESCNAME                     \
    }
#define DEFCNFIELD(NAME, STYPE, DATAFIELD, LENFIELD, TAG, CDESC)        \
    DEFCOUNTEDTYPE(NAME##_untagged, STYPE, DATAFIELD, LENFIELD, CDESC); \
    DEFCTAGGEDTYPE(NAME, TAG, NAME##_untagged)
#define DEFCOUNTEDDERTYPE(DESCNAME, DTYPE, LTYPE)               \
    typedef DTYPE aux_ptrtype_##DESCNAME;                       \
    typedef LTYPE aux_counttype_##DESCNAME;                     \
    const struct cntype_info k5_cntype_##DESCNAME = {           \
        cntype_der, NULL                                        \
    }
#define DEFCOUNTEDSEQOFTYPE(DESCNAME, LTYPE, BASEDESC)          \
    typedef aux_type_##BASEDESC aux_ptrtype_##DESCNAME;         \
    typedef LTYPE aux_counttype_##DESCNAME;                     \
    const struct cntype_info k5_cntype_##DESCNAME = {           \
        cntype_seqof, &k5_atype_##BASEDESC                      \
    }
#define DEFCOUNTEDSTRINGTYPE(DESCNAME, DTYPE, LTYPE, ENCFN, DECFN, TAGVAL) \
    typedef DTYPE aux_ptrtype_##DESCNAME;                               \
    typedef LTYPE aux_counttype_##DESCNAME;                             \
    static const struct string_info aux_info_##DESCNAME = {             \
        ENCFN, DECFN, TAGVAL                                            \
    };                                                                  \
    const struct cntype_info k5_cntype_##DESCNAME = {                   \
        cntype_string, &aux_info_##DESCNAME                             \
    }
#define DEFCOUNTEDTYPE(DESCNAME, STYPE, DATAFIELD, COUNTFIELD, CDESC) \
    DEFCOUNTEDTYPE_base(DESCNAME, STYPE, DATAFIELD, COUNTFIELD, 0, CDESC)
#define DEFCOUNTEDTYPE_SIGNED(DESCNAME, STYPE, DATAFIELD, COUNTFIELD, CDESC) \
    DEFCOUNTEDTYPE_base(DESCNAME, STYPE, DATAFIELD, COUNTFIELD, 1, CDESC)
#define DEFCOUNTEDTYPE_base(DESCNAME, STYPE, DATAFIELD, COUNTFIELD, SIGNED, \
                            CDESC)                                      \
    typedef STYPE aux_type_##DESCNAME;                                  \
    const struct counted_info aux_info_##DESCNAME = {                   \
        OFFOF(STYPE, DATAFIELD, aux_ptrtype_##CDESC),                   \
        OFFOF(STYPE, COUNTFIELD, aux_counttype_##CDESC),                \
        SIGNED, sizeof(((STYPE*)0)->COUNTFIELD),                        \
        &k5_cntype_##CDESC                                              \
    };                                                                  \
    const struct atype_info k5_atype_##DESCNAME = {                     \
        atype_counted, sizeof(STYPE),                                   \
        &aux_info_##DESCNAME                                            \
    }
#define DEFCTAGGEDTYPE(DESCNAME, TAG, BASEDESC)                         \
    DEFTAGGEDTYPE(DESCNAME, CONTEXT_SPECIFIC, CONSTRUCTED, TAG, 0, BASEDESC)
#define DEFCTAGGEDTYPE_IMPLICIT(DESCNAME, TAG, BASEDESC)                \
    DEFTAGGEDTYPE(DESCNAME, CONTEXT_SPECIFIC, CONSTRUCTED, TAG, 1, BASEDESC)
#define DEFFIELD(NAME, STYPE, FIELDNAME, TAG, DESC)                     \
    DEFOFFSETTYPE(NAME##_untagged, STYPE, FIELDNAME, DESC);             \
    DEFCTAGGEDTYPE(NAME, TAG, NAME##_untagged)
#define DEFFIELD_IMPLICIT(NAME, STYPE, FIELDNAME, TAG, DESC)            \
    DEFOFFSETTYPE(NAME##_untagged, STYPE, FIELDNAME, DESC);             \
    DEFCTAGGEDTYPE_IMPLICIT(NAME, TAG, NAME##_untagged)
#define DEFFNTYPE(DESCNAME, CTYPENAME, ENCFN, DECFN, CHECKFN, FREEFN)   \
    typedef CTYPENAME aux_type_##DESCNAME;                              \
    static const struct fn_info aux_info_##DESCNAME = {                 \
        ENCFN, DECFN, CHECKFN, FREEFN                                   \
    };                                                                  \
    const struct atype_info k5_atype_##DESCNAME = {                     \
        atype_fn, sizeof(CTYPENAME), &aux_info_##DESCNAME               \
    }
#define DEFINTTYPE(DESCNAME, CTYPENAME)                         \
    typedef CTYPENAME aux_type_##DESCNAME;                      \
    const struct atype_info k5_atype_##DESCNAME = {             \
        atype_int, sizeof(CTYPENAME), NULL                      \
    }
#define DEFINT_IMMEDIATE(DESCNAME, VAL, ERR)                    \
    typedef int aux_type_##DESCNAME;                            \
    static const struct immediate_info aux_info_##DESCNAME = {  \
        VAL, ERR                                                \
    };                                                          \
    const struct atype_info k5_atype_##DESCNAME = {             \
        atype_int_immediate, 0, &aux_info_##DESCNAME            \
    }
#define DEFNONEMPTYNULLTERMSEQOFTYPE(DESCNAME,BASEDESCNAME)     \
    typedef aux_type_##BASEDESCNAME aux_type_##DESCNAME;        \
    const struct atype_info k5_atype_##DESCNAME = {             \
        atype_nonempty_nullterm_sequence_of,                    \
        sizeof(aux_type_##DESCNAME),                            \
        &k5_atype_##BASEDESCNAME                                \
    }
#define DEFNULLTERMSEQOFTYPE(DESCNAME,BASEDESCNAME)                     \
    typedef aux_type_##BASEDESCNAME aux_type_##DESCNAME;                \
    const struct atype_info k5_atype_##DESCNAME = {                     \
        atype_nullterm_sequence_of, sizeof(aux_type_##DESCNAME),        \
        &k5_atype_##BASEDESCNAME                                        \
    }
#define DEFOFFSETTYPE(DESCNAME, STYPE, FIELDNAME, BASEDESC)     \
    typedef STYPE aux_type_##DESCNAME;                          \
    static const struct offset_info aux_info_##DESCNAME = {     \
        OFFOF(STYPE, FIELDNAME, aux_type_##BASEDESC),           \
        &k5_atype_##BASEDESC                                    \
    };                                                          \
    const struct atype_info k5_atype_##DESCNAME = {             \
        atype_offset, sizeof(aux_type_##DESCNAME),              \
        &aux_info_##DESCNAME                                    \
    }
#define DEFOPTIONALEMPTYTYPE(DESCNAME, BASEDESC)                        \
    static int                                                          \
    aux_present_##DESCNAME(const void *p)                               \
    {                                                                   \
        const aux_type_##BASEDESC *val = p;                             \
        return (*val != NULL && **val != NULL);                         \
    }                                                                   \
    DEFOPTIONALTYPE(DESCNAME, aux_present_##DESCNAME, NULL, BASEDESC)
#define DEFOPTIONALTYPE(DESCNAME, PRESENT, INIT, BASEDESC)       \
    typedef aux_type_##BASEDESC aux_type_##DESCNAME;             \
    static const struct optional_info aux_info_##DESCNAME = {   \
        PRESENT, INIT, &k5_atype_##BASEDESC                     \
    };                                                          \
    const struct atype_info k5_atype_##DESCNAME = {             \
        atype_optional, sizeof(aux_type_##DESCNAME),            \
        &aux_info_##DESCNAME                                    \
    }
#define DEFOPTIONALZEROTYPE(DESCNAME, BASEDESC)                         \
    static int                                                          \
    aux_present_##DESCNAME(const void *p)                               \
    {                                                                   \
        return *(aux_type_##BASEDESC *)p != 0;                          \
    }                                                                   \
    DEFOPTIONALTYPE(DESCNAME, aux_present_##DESCNAME, NULL, BASEDESC)
#define DEFPTRTYPE(DESCNAME,BASEDESCNAME)                       \
    typedef aux_type_##BASEDESCNAME *aux_type_##DESCNAME;       \
    static const struct ptr_info aux_info_##DESCNAME = {        \
        NULL, NULL, &k5_atype_##BASEDESCNAME                    \
    };                                                          \
    const struct atype_info k5_atype_##DESCNAME = {             \
        atype_ptr, sizeof(aux_type_##DESCNAME),                 \
        &aux_info_##DESCNAME                                    \
    }
#define DEFSEQTYPE(DESCNAME, CTYPENAME, FIELDS)                         \
    typedef CTYPENAME aux_type_##DESCNAME;                              \
    static const struct seq_info aux_seqinfo_##DESCNAME = {             \
        FIELDS, sizeof(FIELDS)/sizeof(FIELDS[0])                        \
    };                                                                  \
    const struct atype_info k5_atype_##DESCNAME = {                     \
        atype_sequence, sizeof(CTYPENAME), &aux_seqinfo_##DESCNAME      \
    }
#define DEFTAGGEDTYPE(DESCNAME, CLASS, CONSTRUCTION, TAG, IMPLICIT, BASEDESC) \
    typedef aux_type_##BASEDESC aux_type_##DESCNAME;                    \
    static const struct tagged_info aux_info_##DESCNAME = {             \
        TAG, CLASS, CONSTRUCTION, IMPLICIT, &k5_atype_##BASEDESC        \
    };                                                                  \
    const struct atype_info k5_atype_##DESCNAME = {                     \
        atype_tagged_thing, sizeof(aux_type_##DESCNAME),                \
        &aux_info_##DESCNAME                                            \
    }
#define DEFUINTTYPE(DESCNAME, CTYPENAME)                        \
    typedef CTYPENAME aux_type_##DESCNAME;                      \
    const struct atype_info k5_atype_##DESCNAME = {             \
        atype_uint, sizeof(CTYPENAME), NULL                     \
    }
#define IMPORT_TYPE(DESCNAME, CTYPENAME)                        \
    typedef CTYPENAME aux_type_##DESCNAME;                      \
    extern const struct atype_info k5_atype_##DESCNAME
#define MAKE_DECODER(FNAME, DESC)                                       \
    krb5_error_code                                                     \
    FNAME(const krb5_data *code, aux_type_##DESC **rep_out)             \
    {                                                                   \
        krb5_error_code ret;                                            \
        void *rep;                                                      \
        *rep_out = NULL;                                                \
        ret = k5_asn1_full_decode(code, &k5_atype_##DESC, &rep);        \
        if (ret)                                                        \
            return ret;                                                 \
        *rep_out = rep;                                                 \
        return 0;                                                       \
    }                                                                   \
    extern int dummy 
#define MAKE_ENCODER(FNAME, DESC)                                       \
    krb5_error_code                                                     \
    FNAME(const aux_type_##DESC *rep, krb5_data **code_out)             \
    {                                                                   \
        return k5_asn1_full_encode(rep, &k5_atype_##DESC, code_out);    \
    }                                                                   \
    extern int dummy 
#define OFFOF(TYPE,FIELD,FTYPE)                                 \
    (offsetof(TYPE, FIELD)                                      \
     + 0 * WARN_IF_TYPE_MISMATCH(((TYPE*)0)->FIELD, FTYPE))
#define WARN_IF_TYPE_MISMATCH(LVALUE, TYPE)     \
    (sizeof(0 ? (TYPE *) 0 : &(LVALUE)))

#define ASN1_BITSTRING          3
#define ASN1_BOOLEAN            1
#define ASN1_ENUMERATED         10
#define ASN1_GENERALSTRING      27
#define ASN1_GENERALTIME        24
#define ASN1_IA5STRING          22
#define ASN1_INTEGER            2
#define ASN1_KRB_AP_REP         15
#define ASN1_KRB_AP_REQ         14
#define ASN1_KRB_AS_REP         11
#define ASN1_KRB_AS_REQ         10
#define ASN1_KRB_CRED           22
#define ASN1_KRB_ERROR          30
#define ASN1_KRB_PRIV           21
#define ASN1_KRB_SAFE           20
#define ASN1_KRB_TGS_REP        13
#define ASN1_KRB_TGS_REQ        12
#define ASN1_NULL               5
#define ASN1_OBJECTIDENTIFIER   6
#define ASN1_OCTETSTRING        4
#define ASN1_PRINTABLESTRING    19
#define ASN1_SEQUENCE           16
#define ASN1_SET                17
#define ASN1_TAGNUM_CEILING INT_MAX
#define ASN1_TAGNUM_MAX (ASN1_TAGNUM_CEILING-1)
#define ASN1_UTCTIME            23
#define ASN1_UTF8STRING         12

#define KVNO 5

#define IGNORE_ENCTYPE 0
#define IGNORE_VNO 0
#define INI_FILES       "Files"
#define INI_KRB5_CONF   "krb5.ini"      
#define INI_KRB_CCACHE  "krb5cc"        
#define K5_SHA256_HASHLEN (256 / 8)
#define KDC_ERR_BADOPTION               13 
#define KDC_ERR_BAD_PVNO                3 
#define KDC_ERR_CANNOT_POSTDATE         10 
#define KDC_ERR_CANT_VERIFY_CERTIFICATE         70 
#define KDC_ERR_CERTIFICATE_MISMATCH            66
#define KDC_ERR_CLIENT_NAME_MISMATCH            75 
#define KDC_ERR_CLIENT_NOTYET           21 
#define KDC_ERR_CLIENT_NOT_TRUSTED              62 
#define KDC_ERR_CLIENT_REVOKED          18 
#define KDC_ERR_C_OLD_MAST_KVNO         4 
#define KDC_ERR_C_PRINCIPAL_UNKNOWN     6 
#define KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED  65 
#define KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED     78 
#define KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED 80 
#define KDC_ERR_ENCTYPE_NOSUPP          14 
#define KDC_ERR_INCONSISTENT_KEY_PURPOSE        77 
#define KDC_ERR_INVALID_CERTIFICATE             71 
#define KDC_ERR_INVALID_SIG                     64 
#define KDC_ERR_KDC_NOT_TRUSTED                 63
#define KDC_ERR_KEY_EXP                 23 
#define KDC_ERR_MORE_PREAUTH_DATA_REQUIRED      91 
#define KDC_ERR_MUST_USE_USER2USER      27 
#define KDC_ERR_NAME_EXP                1 
#define KDC_ERR_NEVER_VALID             11 
#define KDC_ERR_NONE                    0 
#define KDC_ERR_NULL_KEY                9 
#define KDC_ERR_PADATA_TYPE_NOSUPP      16 
#define KDC_ERR_PATH_NOT_ACCEPTED       28 
#define KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED    79 
#define KDC_ERR_POLICY                  12 
#define KDC_ERR_PREAUTH_EXPIRED                 90 
#define KDC_ERR_PREAUTH_FAILED          24 
#define KDC_ERR_PREAUTH_REQUIRED        25 
#define KDC_ERR_PRINCIPAL_NOT_UNIQUE    8 
#define KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED 81
#define KDC_ERR_REVOCATION_STATUS_UNAVAILABLE   74
#define KDC_ERR_REVOCATION_STATUS_UNKNOWN       73 
#define KDC_ERR_REVOKED_CERTIFICATE             72 
#define KDC_ERR_SERVER_NOMATCH          26 
#define KDC_ERR_SERVICE_EXP             2 
#define KDC_ERR_SERVICE_NOTYET          22 
#define KDC_ERR_SERVICE_REVOKED         19 
#define KDC_ERR_SUMTYPE_NOSUPP          15 
#define KDC_ERR_SVC_UNAVAILABLE         29 
#define KDC_ERR_S_OLD_MAST_KVNO         5 
#define KDC_ERR_S_PRINCIPAL_UNKNOWN     7 
#define KDC_ERR_TGT_REVOKED             20 
#define KDC_ERR_TRTYPE_NOSUPP           17 
#define KDC_ERR_WRONG_REALM                     68
#define KERBEROS_INI    "kerberos.ini"
#define KRB5INT_ACCESS_STRUCT_VERSION 23
#define KRB5INT_ACCESS_VERSION                                          \
    (((krb5_int32)((sizeof(krb5int_access) & 0xFFFF) |                  \
                   (KRB5INT_ACCESS_STRUCT_VERSION << 16))) & 0xFFFFFFFF)



#define KRB5_CC_CONF_FAST_AVAIL                "fast_avail"
#define KRB5_CC_CONF_PA_CONFIG_DATA            "pa_config_data"
#define KRB5_CC_CONF_PA_TYPE                   "pa_type"
#define KRB5_CC_CONF_PROXY_IMPERSONATOR        "proxy_impersonator"
#define KRB5_CC_CONF_REFRESH_TIME              "refresh_time"

#define KRB5_CONF_ACL_FILE                     "acl_file"
#define KRB5_CONF_ADMIN_SERVER                 "admin_server"
#define KRB5_CONF_ALLOW_WEAK_CRYPTO            "allow_weak_crypto"
#define KRB5_CONF_AUTH_TO_LOCAL                "auth_to_local"
#define KRB5_CONF_AUTH_TO_LOCAL_NAMES          "auth_to_local_names"
#define KRB5_CONF_CANONICALIZE                 "canonicalize"
#define KRB5_CONF_CCACHE_TYPE                  "ccache_type"
#define KRB5_CONF_CLIENT_AWARE_GSS_BINDINGS    "client_aware_channel_bindings"
#define KRB5_CONF_CLOCKSKEW                    "clockskew"
#define KRB5_CONF_DATABASE_NAME                "database_name"
#define KRB5_CONF_DB_MODULE_DIR                "db_module_dir"
#define KRB5_CONF_DEBUG                        "debug"
#define KRB5_CONF_DEFAULT                      "default"
#define KRB5_CONF_DEFAULT_CCACHE_NAME          "default_ccache_name"
#define KRB5_CONF_DEFAULT_CLIENT_KEYTAB_NAME   "default_client_keytab_name"
#define KRB5_CONF_DEFAULT_DOMAIN               "default_domain"
#define KRB5_CONF_DEFAULT_KEYTAB_NAME          "default_keytab_name"
#define KRB5_CONF_DEFAULT_PRINCIPAL_EXPIRATION "default_principal_expiration"
#define KRB5_CONF_DEFAULT_PRINCIPAL_FLAGS      "default_principal_flags"
#define KRB5_CONF_DEFAULT_RCACHE_NAME          "default_rcache_name"
#define KRB5_CONF_DEFAULT_REALM                "default_realm"
#define KRB5_CONF_DEFAULT_TGS_ENCTYPES         "default_tgs_enctypes"
#define KRB5_CONF_DEFAULT_TKT_ENCTYPES         "default_tkt_enctypes"
#define KRB5_CONF_DICT_FILE                    "dict_file"
#define KRB5_CONF_DISABLE                      "disable"
#define KRB5_CONF_DISABLE_ENCRYPTED_TIMESTAMP  "disable_encrypted_timestamp"
#define KRB5_CONF_DISABLE_LAST_SUCCESS         "disable_last_success"
#define KRB5_CONF_DISABLE_LOCKOUT              "disable_lockout"
#define KRB5_CONF_DNS_CANONICALIZE_HOSTNAME    "dns_canonicalize_hostname"
#define KRB5_CONF_DNS_FALLBACK                 "dns_fallback"
#define KRB5_CONF_DNS_LOOKUP_KDC               "dns_lookup_kdc"
#define KRB5_CONF_DNS_LOOKUP_REALM             "dns_lookup_realm"
#define KRB5_CONF_DNS_URI_LOOKUP               "dns_uri_lookup"
#define KRB5_CONF_DOMAIN_REALM                 "domain_realm"
#define KRB5_CONF_ENABLE_ONLY                  "enable_only"
#define KRB5_CONF_ENCRYPTED_CHALLENGE_INDICATOR "encrypted_challenge_indicator"
#define KRB5_CONF_ENFORCE_OK_AS_DELEGATE       "enforce_ok_as_delegate"
#define KRB5_CONF_ERR_FMT                      "err_fmt"
#define KRB5_CONF_EXTRA_ADDRESSES              "extra_addresses"
#define KRB5_CONF_FORWARDABLE                  "forwardable"
#define KRB5_CONF_HOST_BASED_SERVICES          "host_based_services"
#define KRB5_CONF_HTTP_ANCHORS                 "http_anchors"
#define KRB5_CONF_IGNORE_ACCEPTOR_HOSTNAME     "ignore_acceptor_hostname"
#define KRB5_CONF_IPROP_ENABLE                 "iprop_enable"
#define KRB5_CONF_IPROP_LISTEN                 "iprop_listen"
#define KRB5_CONF_IPROP_LOGFILE                "iprop_logfile"
#define KRB5_CONF_IPROP_MASTER_ULOGSIZE        "iprop_master_ulogsize"
#define KRB5_CONF_IPROP_PORT                   "iprop_port"
#define KRB5_CONF_IPROP_REPLICA_POLL           "iprop_replica_poll"
#define KRB5_CONF_IPROP_RESYNC_TIMEOUT         "iprop_resync_timeout"
#define KRB5_CONF_IPROP_SLAVE_POLL             "iprop_slave_poll"
#define KRB5_CONF_IPROP_ULOGSIZE               "iprop_ulogsize"
#define KRB5_CONF_K5LOGIN_AUTHORITATIVE        "k5login_authoritative"
#define KRB5_CONF_K5LOGIN_DIRECTORY            "k5login_directory"
#define KRB5_CONF_KADMIND_LISTEN               "kadmind_listen"
#define KRB5_CONF_KADMIND_PORT                 "kadmind_port"
#define KRB5_CONF_KCM_MACH_SERVICE             "kcm_mach_service"
#define KRB5_CONF_KCM_SOCKET                   "kcm_socket"
#define KRB5_CONF_KDC                          "kdc"
#define KRB5_CONF_KDCDEFAULTS                  "kdcdefaults"
#define KRB5_CONF_KDC_DEFAULT_OPTIONS          "kdc_default_options"
#define KRB5_CONF_KDC_LISTEN                   "kdc_listen"
#define KRB5_CONF_KDC_MAX_DGRAM_REPLY_SIZE     "kdc_max_dgram_reply_size"
#define KRB5_CONF_KDC_PORTS                    "kdc_ports"
#define KRB5_CONF_KDC_TCP_LISTEN               "kdc_tcp_listen"
#define KRB5_CONF_KDC_TCP_LISTEN_BACKLOG       "kdc_tcp_listen_backlog"
#define KRB5_CONF_KDC_TCP_PORTS                "kdc_tcp_ports"
#define KRB5_CONF_KDC_TIMESYNC                 "kdc_timesync"
#define KRB5_CONF_KEY_STASH_FILE               "key_stash_file"
#define KRB5_CONF_KPASSWD_LISTEN               "kpasswd_listen"
#define KRB5_CONF_KPASSWD_PORT                 "kpasswd_port"
#define KRB5_CONF_KPASSWD_SERVER               "kpasswd_server"
#define KRB5_CONF_KRB524_SERVER                "krb524_server"
#define KRB5_CONF_LDAP_CONNS_PER_SERVER        "ldap_conns_per_server"
#define KRB5_CONF_LDAP_KADMIND_DN              "ldap_kadmind_dn"
#define KRB5_CONF_LDAP_KADMIND_SASL_AUTHCID    "ldap_kadmind_sasl_authcid"
#define KRB5_CONF_LDAP_KADMIND_SASL_AUTHZID    "ldap_kadmind_sasl_authzid"
#define KRB5_CONF_LDAP_KADMIND_SASL_MECH       "ldap_kadmind_sasl_mech"
#define KRB5_CONF_LDAP_KADMIND_SASL_REALM      "ldap_kadmind_sasl_realm"
#define KRB5_CONF_LDAP_KDC_DN                  "ldap_kdc_dn"
#define KRB5_CONF_LDAP_KDC_SASL_AUTHCID        "ldap_kdc_sasl_authcid"
#define KRB5_CONF_LDAP_KDC_SASL_AUTHZID        "ldap_kdc_sasl_authzid"
#define KRB5_CONF_LDAP_KDC_SASL_MECH           "ldap_kdc_sasl_mech"
#define KRB5_CONF_LDAP_KDC_SASL_REALM          "ldap_kdc_sasl_realm"
#define KRB5_CONF_LDAP_KERBEROS_CONTAINER_DN   "ldap_kerberos_container_dn"
#define KRB5_CONF_LDAP_SERVERS                 "ldap_servers"
#define KRB5_CONF_LDAP_SERVICE_PASSWORD_FILE   "ldap_service_password_file"
#define KRB5_CONF_LIBDEFAULTS                  "libdefaults"
#define KRB5_CONF_LOGGING                      "logging"
#define KRB5_CONF_MAPSIZE                      "mapsize"
#define KRB5_CONF_MASTER_KDC                   "master_kdc"
#define KRB5_CONF_MASTER_KEY_NAME              "master_key_name"
#define KRB5_CONF_MASTER_KEY_TYPE              "master_key_type"
#define KRB5_CONF_MAX_LIFE                     "max_life"
#define KRB5_CONF_MAX_READERS                  "max_readers"
#define KRB5_CONF_MAX_RENEWABLE_LIFE           "max_renewable_life"
#define KRB5_CONF_MODULE                       "module"
#define KRB5_CONF_NOADDRESSES                  "noaddresses"
#define KRB5_CONF_NOSYNC                       "nosync"
#define KRB5_CONF_NO_HOST_REFERRAL             "no_host_referral"
#define KRB5_CONF_PERMITTED_ENCTYPES           "permitted_enctypes"
#define KRB5_CONF_PLUGINS                      "plugins"
#define KRB5_CONF_PLUGIN_BASE_DIR              "plugin_base_dir"
#define KRB5_CONF_PREFERRED_PREAUTH_TYPES      "preferred_preauth_types"
#define KRB5_CONF_PRIMARY_KDC                  "primary_kdc"
#define KRB5_CONF_PROXIABLE                    "proxiable"
#define KRB5_CONF_QUALIFY_SHORTNAME            "qualify_shortname"
#define KRB5_CONF_RDNS                         "rdns"
#define KRB5_CONF_REALMS                       "realms"
#define KRB5_CONF_REALM_TRY_DOMAINS            "realm_try_domains"
#define KRB5_CONF_REJECT_BAD_TRANSIT           "reject_bad_transit"
#define KRB5_CONF_RENEW_LIFETIME               "renew_lifetime"
#define KRB5_CONF_RESTRICT_ANONYMOUS_TO_TGT    "restrict_anonymous_to_tgt"
#define KRB5_CONF_SPAKE_PREAUTH_GROUPS         "spake_preauth_groups"
#define KRB5_CONF_SPAKE_PREAUTH_INDICATOR      "spake_preauth_indicator"
#define KRB5_CONF_SPAKE_PREAUTH_KDC_CHALLENGE  "spake_preauth_kdc_challenge"
#define KRB5_CONF_SUPPORTED_ENCTYPES           "supported_enctypes"
#define KRB5_CONF_TICKET_LIFETIME              "ticket_lifetime"
#define KRB5_CONF_UDP_PREFERENCE_LIMIT         "udp_preference_limit"
#define KRB5_CONF_UNLOCKITER                   "unlockiter"
#define KRB5_CONF_V4_INSTANCE_CONVERT          "v4_instance_convert"
#define KRB5_CONF_V4_REALM                     "v4_realm"
#define KRB5_CONF_VERIFY_AP_REQ_NOFAIL         "verify_ap_req_nofail"
#define KRB5_ETYPE_NO_SALT VALID_UINT_BITS
#define KRB5_FAST_OPTION_HIDE_CLIENT_NAMES  0x40000000
#define KRB5_KDB_EXPIRATION     2145830400 
#define KRB5_KDB_MAX_LIFE       (60*60*24) 
#define KRB5_KDB_MAX_RLIFE      (60*60*24*7) 
#define KRB5_LIBOPT_SYNC_KDCTIME        0x0001
#define KRB5_LOCKMODE_DONTBLOCK 0x0004
#define KRB5_LOCKMODE_EXCLUSIVE 0x0002
#define KRB5_LOCKMODE_SHARED    0x0001
#define KRB5_LOCKMODE_UNLOCK    0x0008
#define KRB5_OS_TOFFSET_TIME    2
#define KRB5_OS_TOFFSET_VALID   1
#define KRB5_OTP_FLAG_CHECK_DIGIT    0x01000000
#define KRB5_OTP_FLAG_COLLECT_PIN    0x10000000
#define KRB5_OTP_FLAG_COMBINE        0x20000000
#define KRB5_OTP_FLAG_ENCRYPT_NONCE  0x04000000
#define KRB5_OTP_FLAG_NEXTOTP        0x40000000
#define KRB5_OTP_FLAG_NO_COLLECT_PIN 0x08000000
#define KRB5_OTP_FLAG_SEPARATE_PIN   0x02000000
#define KRB5_OTP_FORMAT_ALPHANUMERIC 0x00000002
#define KRB5_OTP_FORMAT_BASE64       0x00000004
#define KRB5_OTP_FORMAT_BINARY       0x00000003
#define KRB5_OTP_FORMAT_DECIMAL      0x00000000
#define KRB5_OTP_FORMAT_HEXADECIMAL  0x00000001
#define KRB5_PA_PAC_OPTIONS_RBCD 0x10000000

#define        KRB5_REFERRAL_MAXHOPS    10
#define KRB5_S4U_OPTS_CHECK_LOGON_HOURS         0x40000000 
#define KRB5_S4U_OPTS_USE_REPLY_KEY_USAGE       0x20000000 

#define KRB_AP_ERR_BADADDR      38      
#define KRB_AP_ERR_BADDIRECTION 47      
#define KRB_AP_ERR_BADKEYVER    44      
#define KRB_AP_ERR_BADMATCH     36      
#define KRB_AP_ERR_BADORDER     42      
#define KRB_AP_ERR_BADSEQ       49      
#define KRB_AP_ERR_BADVERSION   39      
#define KRB_AP_ERR_BAD_INTEGRITY 31     
#define KRB_AP_ERR_IAKERB_KDC_NOT_FOUND         85 
#define KRB_AP_ERR_IAKERB_KDC_NO_RESPONSE       86 
#define KRB_AP_ERR_INAPP_CKSUM  50      
#define KRB_AP_ERR_METHOD       48      
#define KRB_AP_ERR_MODIFIED     41      
#define KRB_AP_ERR_MSG_TYPE     40      
#define KRB_AP_ERR_MUT_FAIL     46      
#define KRB_AP_ERR_NOKEY        45      
#define KRB_AP_ERR_NOT_US       35      
#define KRB_AP_ERR_NO_TGT                       67
#define KRB_AP_ERR_REPEAT       34      
#define KRB_AP_ERR_SKEW         37      
#define KRB_AP_ERR_TKT_EXPIRED  32      
#define KRB_AP_ERR_TKT_NYV      33      
#define KRB_AP_ERR_USER_TO_USER_REQUIRED        69
#define KRB_AP_PATH_NOT_ACCEPTED 51     
#define KRB_ERR_FIELD_TOOLONG   61      
#define KRB_ERR_GENERIC         60      
#define KRB_ERR_MAX 127 
#define KRB_ERR_RESPONSE_TOO_BIG 52     
#define O_BINARY 0
#define PA_SAM_TYPE_ACTIVCARD_DEC  6   
#define PA_SAM_TYPE_ACTIVCARD_HEX  7   
#define PA_SAM_TYPE_CRYPTOCARD 6   
#define PA_SAM_TYPE_DIGI_PATH  2   
#define PA_SAM_TYPE_DIGI_PATH_HEX  8   
#define PA_SAM_TYPE_ENIGMA     1   
#define PA_SAM_TYPE_EXP_BASE    128 
#define PA_SAM_TYPE_GRAIL               (PA_SAM_TYPE_EXP_BASE+0) 
#define PA_SAM_TYPE_SECURID    5   
#define PA_SAM_TYPE_SECURID_PREDICT     (PA_SAM_TYPE_EXP_BASE+1) 
#define PA_SAM_TYPE_SKEY       4   
#define PA_SAM_TYPE_SKEY_K0    3   
#define PLUGIN_INTERFACE_AUDIT       7
#define PLUGIN_INTERFACE_CCSELECT    4
#define PLUGIN_INTERFACE_CERTAUTH    10
#define PLUGIN_INTERFACE_CLPREAUTH   2
#define PLUGIN_INTERFACE_HOSTREALM   6
#define PLUGIN_INTERFACE_KADM5_AUTH  11
#define PLUGIN_INTERFACE_KADM5_HOOK  1
#define PLUGIN_INTERFACE_KDCAUTHDATA 9
#define PLUGIN_INTERFACE_KDCPOLICY   12
#define PLUGIN_INTERFACE_KDCPREAUTH  3
#define PLUGIN_INTERFACE_LOCALAUTH   5
#define PLUGIN_INTERFACE_PWQUAL      0
#define PLUGIN_INTERFACE_TLS         8
#define PLUGIN_NUM_INTERFACES        13
#define UNSUPPORTED_CRITICAL_FAST_OPTIONS   0xbfff0000

#define k5_prependmsg krb5_prepend_error_message
#define k5_setmsg krb5_set_error_message
#define k5_wrapmsg krb5_wrap_error_message
#define krb5_is_ap_rep(dat)                   krb5int_is_app_tag(dat, 15)
#define krb5_is_ap_req(dat)                   krb5int_is_app_tag(dat, 14)
#define krb5_is_as_rep(dat)                   krb5int_is_app_tag(dat, 11)
#define krb5_is_as_req(dat)                   krb5int_is_app_tag(dat, 10)
#define krb5_is_krb_authenticator(dat)        krb5int_is_app_tag(dat, 2)
#define krb5_is_krb_cred(dat)                 krb5int_is_app_tag(dat, 22)
#define krb5_is_krb_enc_ap_rep_part(dat)      krb5int_is_app_tag(dat, 27)
#define krb5_is_krb_enc_as_rep_part(dat)      krb5int_is_app_tag(dat, 25)
#define krb5_is_krb_enc_krb_cred_part(dat)    krb5int_is_app_tag(dat, 29)
#define krb5_is_krb_enc_krb_priv_part(dat)    krb5int_is_app_tag(dat, 28)
#define krb5_is_krb_enc_tgs_rep_part(dat)     krb5int_is_app_tag(dat, 26)
#define krb5_is_krb_error(dat)                krb5int_is_app_tag(dat, 30)
#define krb5_is_krb_priv(dat)                 krb5int_is_app_tag(dat, 21)
#define krb5_is_krb_safe(dat)                 krb5int_is_app_tag(dat, 20)
#define krb5_is_krb_ticket(dat)               krb5int_is_app_tag(dat, 1)
#define krb5_is_tgs_rep(dat)                  krb5int_is_app_tag(dat, 13)
#define krb5_is_tgs_req(dat)                  krb5int_is_app_tag(dat, 12)
#define krb5int_is_app_tag(dat,tag)                     \
    ((dat != NULL) && (dat)->length &&                  \
     ((((dat)->data[0] & ~0x20) == ((tag) | 0x40))))
#define AD_CAMMAC_PROTECTED     0x20
#define AD_INFORMATIONAL        0x10
#define AD_USAGE_AP_REQ         0x04
#define AD_USAGE_AS_REQ         0x01
#define AD_USAGE_KDC_ISSUED     0x08
#define AD_USAGE_MASK           0x2F
#define AD_USAGE_TGS_REQ        0x02


#define PLUGIN_DIR_INIT(P) ((P)->files = NULL)
#define PLUGIN_DIR_OPEN(P) ((P)->files != NULL)
#define PLUGIN_SYMBOL_NAME(prefix, symbol) prefix ## _ ## symbol
#define EMPTY_ERRINFO { 0, NULL }


#define DEFCKTNAME "FILE:%{WINDOWS}\\krb5clientkt"
#define DEFKTNAME "FILE:%{WINDOWS}\\krb5kt"
#define   DEF_KRB_CONF    "krb.conf"      
#define DEF_KRB_REALMS  "krb.realms"    

#define GETPEERNAME_ARG3_TYPE   GETSOCKNAME_ARG3_TYPE
#define GETSOCKNAME_ARG3_TYPE   size_t













#define ID_READ_PWD_DIALOG  10000
#define ID_READ_PWD_PROMPT  10001
#define ID_READ_PWD_PROMPT2 10002
#define ID_READ_PWD_PWD     10003
#define   INI_ALERT       "Alert"
#define   INI_BEEP        "Beep"
#define INI_DEFAULTS    "Defaults"
#define   INI_DURATION    "Duration"   
#define INI_EXPIRATION  "Expiration" 
#define   INI_FORWARDABLE  "Forwardable" 
#define   INI_INSTANCE    "Instance"      
#define   INI_KRB_CONF    "krb.conf"     
#define INI_KRB_REALMS  "krb.realms"    
#define INI_LOGIN       "Login"
#define   INI_OPTIONS     "Options"
#define   INI_POSITION    "Position"
#define   INI_REALM       "Realm"         
#define INI_RECENT_LOGINS "Recent Logins"
#define INI_TICKETOPTS  "TicketOptions" 
#define   INI_USER        "User"          
#define KERBEROS_HLP    "kerbnet.hlp"
#  define KRB5_CALLCONV_WRONG KRB5_CALLCONV_C
#define MAXHOSTNAMELEN  512
#define MAXPATHLEN      256            




#define SIZEOF_INT      4
#define SIZEOF_LONG     4
#define SIZEOF_SHORT    2
#define SIZE_MAX MAX_SIZE


#define THREEPARAMOPEN(x,y,z) open(x,y,z)
#define WM_KERBEROS5_CHANGED "Kerberos5 Changed"
#define WM_KERBEROS_CHANGED "Kerberos Changed"


#define inline __inline
#define strcasecmp   _stricmp
#define strdup _strdup
#define strncasecmp  _strnicmp
#define strtok_r strtok_s
#define sys_errlist     _sys_errlist
#define sys_nerr        _sys_nerr



#define TRACE(ctx, ...) krb5int_trace(ctx, __VA_ARGS__)
#define TRACE_CCSELECT_DEFAULT(c, cache, server)                    \
    TRACE(c, "ccselect choosing default cache {ccache} for server " \
          "principal {princ}", cache, server)
#define TRACE_CCSELECT_INIT_FAIL(c, name, ret)                          \
    TRACE(c, "ccselect module {str} failed to init: {kerr}", name, ret)
#define TRACE_CCSELECT_MODCHOICE(c, name, server, cache, princ)         \
    TRACE(c, "ccselect module {str} chose cache {ccache} with client "  \
          "principal {princ} for server principal {princ}", name, cache, \
          princ, server)
#define TRACE_CCSELECT_MODFAIL(c, name, ret, server)                  \
    TRACE(c, "ccselect module {str} yielded error {kerr} for server " \
          "principal {princ}", name, ret, server)
#define TRACE_CCSELECT_MODNOTFOUND(c, name, server, princ)              \
    TRACE(c, "ccselect module {str} chose client principal {princ} "    \
          "for server principal {princ} but found no cache", name, princ, \
          server)
#define TRACE_CCSELECT_NOTFOUND(c, server)                          \
    TRACE(c, "ccselect can't find appropriate cache for server "    \
          "principal {princ}", server)
#define TRACE_CCSELECT_VTINIT_FAIL(c, ret)                              \
    TRACE(c, "ccselect module failed to init vtable: {kerr}", ret)
#define TRACE_CC_DESTROY(c, cache)                      \
    TRACE(c, "Destroying ccache {ccache}", cache)
#define TRACE_CC_GEN_NEW(c, cache)                                      \
    TRACE(c, "Generating new unique ccache based on {ccache}", cache)
#define TRACE_CC_GET_CONFIG(c, cache, princ, key, data)             \
    TRACE(c, "Read config in {ccache} for {princ}: {str}: {data}",  \
          cache, princ, key, data)
#define TRACE_CC_INIT(c, cache, princ)                              \
    TRACE(c, "Initializing {ccache} with default princ {princ}",    \
          cache, princ)
#define TRACE_CC_MOVE(c, src, dst)                                      \
    TRACE(c, "Moving contents of ccache {src} to {dst}", src, dst)
#define TRACE_CC_NEW_UNIQUE(c, type)                            \
    TRACE(c, "Resolving unique ccache of type {str}", type)
#define TRACE_CC_REMOVE(c, cache, creds)                        \
    TRACE(c, "Removing {creds} from {ccache}", creds, cache)
#define TRACE_CC_RETRIEVE(c, cache, creds, ret)                      \
    TRACE(c, "Retrieving {creds} from {ccache} with result: {kerr}", \
              creds, cache, ret)
#define TRACE_CC_RETRIEVE_REF(c, cache, creds, ret)                     \
    TRACE(c, "Retrying {creds} with result: {kerr}", creds, ret)
#define TRACE_CC_SET_CONFIG(c, cache, princ, key, data)               \
    TRACE(c, "Storing config in {ccache} for {princ}: {str}: {data}", \
          cache, princ, key, data)
#define TRACE_CC_STORE(c, cache, creds)                         \
    TRACE(c, "Storing {creds} in {ccache}", creds, cache)
#define TRACE_CC_STORE_TKT(c, cache, creds)                     \
    TRACE(c, "Also storing {creds} based on ticket", creds)
#define TRACE_CHECK_REPLY_SERVER_DIFFERS(c, request, reply) \
    TRACE(c, "Reply server {princ} differs from requested {princ}", \
          reply, request)
#define TRACE_DNS_SRV_ANS(c, host, port, prio, weight)                \
    TRACE(c, "SRV answer: {int} {int} {int} \"{str}\"", prio, weight, \
          port, host)
#define TRACE_DNS_SRV_NOTFOUND(c)               \
    TRACE(c, "No SRV records found")
#define TRACE_DNS_SRV_SEND(c, domain)                   \
    TRACE(c, "Sending DNS SRV query for {str}", domain)
#define TRACE_DNS_URI_ANS(c, uri, prio, weight)                         \
    TRACE(c, "URI answer: {int} {int} \"{str}\"", prio, weight, uri)
#define TRACE_DNS_URI_NOTFOUND(c)               \
    TRACE(c, "No URI records found")
#define TRACE_DNS_URI_SEND(c, domain)                   \
    TRACE(c, "Sending DNS URI query for {str}", domain)
#define TRACE_ENCTYPE_LIST_UNKNOWN(c, profvar, name)                    \
    TRACE(c, "Unrecognized enctype name in {str}: {str}", profvar, name)
#define TRACE_FAST_ARMOR_CCACHE(c, ccache_name)         \
    TRACE(c, "FAST armor ccache: {str}", ccache_name)
#define TRACE_FAST_ARMOR_CCACHE_KEY(c, keyblock)                \
    TRACE(c, "Armor ccache sesion key: {keyblock}", keyblock)
#define TRACE_FAST_ARMOR_KEY(c, keyblock)               \
    TRACE(c, "FAST armor key: {keyblock}", keyblock)
#define TRACE_FAST_CCACHE_CONFIG(c)                                     \
    TRACE(c, "Using FAST due to armor ccache negotiation result")
#define TRACE_FAST_DECODE(c)                    \
    TRACE(c, "Decoding FAST response")
#define TRACE_FAST_ENCODE(c)                                            \
    TRACE(c, "Encoding request body and padata into FAST request")
#define TRACE_FAST_NEGO(c, avail)                                       \
    TRACE(c, "FAST negotiation: {str}available", (avail) ? "" : "un")
#define TRACE_FAST_PADATA_UPGRADE(c)                                    \
    TRACE(c, "Upgrading to FAST due to presence of PA_FX_FAST in reply")
#define TRACE_FAST_REPLY_KEY(c, keyblock)                       \
    TRACE(c, "FAST reply key: {keyblock}", keyblock)
#define TRACE_FAST_REQUIRED(c)                                  \
    TRACE(c, "Using FAST due to KRB5_FAST_REQUIRED flag")
#define TRACE_GET_CREDS_FALLBACK(c, hostname)                           \
    TRACE(c, "Falling back to canonicalized server hostname {str}", hostname)
#define TRACE_GET_CRED_VIA_TKT_EXT(c, request, reply, kdcoptions) \
    TRACE(c, "Get cred via TGT {princ} after requesting {princ} " \
          "(canonicalize {str})", \
          reply, request, (kdcoptions & KDC_OPT_CANONICALIZE) ? "on" : "off")
#define TRACE_GET_CRED_VIA_TKT_EXT_RETURN(c, ret) \
    TRACE(c, "Got cred; {kerr}", ret)
#define TRACE_GIC_PWD_CHANGED(c)                                \
    TRACE(c, "Getting initial TGT with changed password")
#define TRACE_GIC_PWD_CHANGEPW(c, tries)                                \
    TRACE(c, "Attempting password change; {int} tries remaining", tries)
#define TRACE_GIC_PWD_EXPIRED(c)                                \
    TRACE(c, "Principal expired; getting changepw ticket")
#define TRACE_GIC_PWD_PRIMARY(c)                        \
    TRACE(c, "Retrying AS request with primary KDC")
#define TRACE_GSS_CLIENT_KEYTAB_FAIL(c, ret)                            \
    TRACE(c, "Unable to resolve default client keytab: {kerr}", ret)
#define TRACE_HOSTREALM_INIT_FAIL(c, name, ret)                         \
    TRACE(c, "hostrealm module {str} failed to init: {kerr}", name, ret)
#define TRACE_HOSTREALM_VTINIT_FAIL(c, ret)                             \
    TRACE(c, "hostrealm module failed to init vtable: {kerr}", ret)
#define TRACE_INIT_CREDS(c, princ)                              \
    TRACE(c, "Getting initial credentials for {princ}", princ)
#define TRACE_INIT_CREDS_AS_KEY_GAK(c, keyblock)                        \
    TRACE(c, "AS key obtained from gak_fct: {keyblock}", keyblock)
#define TRACE_INIT_CREDS_AS_KEY_PREAUTH(c, keyblock)                    \
    TRACE(c, "AS key determined by preauth: {keyblock}", keyblock)
#define TRACE_INIT_CREDS_DECRYPTED_REPLY(c, keyblock)                   \
    TRACE(c, "Decrypted AS reply; session key is: {keyblock}", keyblock)
#define TRACE_INIT_CREDS_ERROR_REPLY(c, code)           \
    TRACE(c, "Received error from KDC: {kerr}", code)
#define TRACE_INIT_CREDS_GAK(c, salt, s2kparams)                    \
    TRACE(c, "Getting AS key, salt \"{data}\", params \"{data}\"",  \
          salt, s2kparams)
#define TRACE_INIT_CREDS_IDENTIFIED_REALM(c, realm)                     \
    TRACE(c, "Identified realm of client principal as {data}", realm)
#define TRACE_INIT_CREDS_KEYTAB_LOOKUP(c, princ, etypes)                \
    TRACE(c, "Found entries for {princ} in keytab: {etypes}", princ, etypes)
#define TRACE_INIT_CREDS_KEYTAB_LOOKUP_FAILED(c, code)          \
    TRACE(c, "Couldn't lookup etypes in keytab: {kerr}", code)
#define TRACE_INIT_CREDS_PREAUTH(c)                     \
    TRACE(c, "Preauthenticating using KDC method data")
#define TRACE_INIT_CREDS_PREAUTH_DECRYPT_FAIL(c, code)                  \
    TRACE(c, "Decrypt with preauth AS key failed: {kerr}", code)
#define TRACE_INIT_CREDS_PREAUTH_MORE(c, patype)                \
    TRACE(c, "Continuing preauth mech {patype}", patype)
#define TRACE_INIT_CREDS_PREAUTH_NONE(c)        \
    TRACE(c, "Sending unauthenticated request")
#define TRACE_INIT_CREDS_PREAUTH_OPTIMISTIC(c)  \
    TRACE(c, "Attempting optimistic preauth")
#define TRACE_INIT_CREDS_PREAUTH_TRYAGAIN(c, patype, code)              \
    TRACE(c, "Recovering from KDC error {int} using preauth mech {patype}", \
          patype, (int)code)
#define TRACE_INIT_CREDS_REFERRAL(c, realm)                     \
    TRACE(c, "Following referral to realm {data}", realm)
#define TRACE_INIT_CREDS_RESTART_FAST(c)        \
    TRACE(c, "Restarting to upgrade to FAST")
#define TRACE_INIT_CREDS_RESTART_PREAUTH_FAILED(c)                      \
    TRACE(c, "Restarting due to PREAUTH_FAILED from FAST negotiation")
#define TRACE_INIT_CREDS_RETRY_TCP(c)                                   \
    TRACE(c, "Request or response is too big for UDP; retrying with TCP")
#define TRACE_INIT_CREDS_SALT_PRINC(c, salt)                    \
    TRACE(c, "Salt derived from principal: {data}", salt)
#define TRACE_INIT_CREDS_SERVICE(c, service)                    \
    TRACE(c, "Setting initial creds service to {str}", service)
#define TRACE_KADM5_AUTH_INIT_FAIL(c, name, ret)                        \
    TRACE(c, "kadm5_auth module {str} failed to init: {kerr}", ret)
#define TRACE_KADM5_AUTH_INIT_SKIP(c, name)                             \
    TRACE(c, "kadm5_auth module {str} declined to initialize", name)
#define TRACE_KADM5_AUTH_VTINIT_FAIL(c, ret)                            \
    TRACE(c, "kadm5_auth module failed to init vtable: {kerr}", ret)
#define TRACE_KDCPOLICY_INIT_SKIP(c, name)                              \
    TRACE(c, "kadm5_auth module {str} declined to initialize", name)
#define TRACE_KDCPOLICY_VTINIT_FAIL(c, ret)                             \
    TRACE(c, "KDC policy module failed to init vtable: {kerr}", ret)
#define TRACE_KT_GET_ENTRY(c, keytab, princ, vno, enctype, err)         \
    TRACE(c, "Retrieving {princ} from {keytab} (vno {int}, enctype {etype}) " \
          "with result: {kerr}", princ, keytab, (int) vno, enctype, err)
#define TRACE_LOCALAUTH_INIT_CONFLICT(c, type, oldname, newname)        \
    TRACE(c, "Ignoring localauth module {str} because it conflicts "    \
          "with an2ln type {str} from module {str}", newname, type, oldname)
#define TRACE_LOCALAUTH_INIT_FAIL(c, name, ret)                         \
    TRACE(c, "localauth module {str} failed to init: {kerr}", name, ret)
#define TRACE_LOCALAUTH_VTINIT_FAIL(c, ret)                             \
    TRACE(c, "localauth module failed to init vtable: {kerr}", ret)
#define TRACE_MK_REP(c, ctime, cusec, subkey, seqnum)                   \
    TRACE(c, "Creating AP-REP, time {long}.{int}, subkey {keyblock}, "  \
          "seqnum {int}", (long) ctime, (int) cusec, subkey, (int) seqnum)
#define TRACE_MK_REQ(c, creds, seqnum, subkey, sesskeyblock)            \
    TRACE(c, "Creating authenticator for {creds}, seqnum {int}, "       \
          "subkey {key}, session key {keyblock}", creds, (int) seqnum,  \
          subkey, sesskeyblock)
#define TRACE_MK_REQ_ETYPES(c, etypes)                                  \
    TRACE(c, "Negotiating for enctypes in authenticator: {etypes}", etypes)
#define TRACE_MSPAC_DISCARD_UNVERF(c)           \
    TRACE(c, "Filtering out unverified MS PAC")
#define TRACE_MSPAC_VERIFY_FAIL(c, err)                         \
    TRACE(c, "PAC checksum verification failed: {kerr}", err)
#define TRACE_NEGOEX_INCOMING(c, seqnum, typestr, info)                 \
    TRACE(c, "NegoEx received [{int}]{str}: {str}", (int)seqnum, typestr, info)
#define TRACE_NEGOEX_OUTGOING(c, seqnum, typestr, info)                 \
    TRACE(c, "NegoEx sending [{int}]{str}: {str}", (int)seqnum, typestr, info)
#define TRACE_PLUGIN_LOAD_FAIL(c, modname, err)                         \
    TRACE(c, "Error loading plugin module {str}: {kerr}", modname, err)
#define TRACE_PLUGIN_LOOKUP_FAIL(c, modname, err)                       \
    TRACE(c, "Error initializing module {str}: {kerr}", modname, err)
#define TRACE_PREAUTH_CONFLICT(c, name1, name2, patype)                 \
    TRACE(c, "Preauth module {str} conflicts with module {str} for pa " \
          "type {patype}", name1, name2, patype)
#define TRACE_PREAUTH_COOKIE(c, len, data)                      \
    TRACE(c, "Received cookie: {lenstr}", (size_t) len, data)
#define TRACE_PREAUTH_ENC_TS(c, sec, usec, plain, enc)                  \
    TRACE(c, "Encrypted timestamp (for {long}.{int}): plain {hexdata}, " \
          "encrypted {hexdata}", (long) sec, (int) usec, plain, enc)
#define TRACE_PREAUTH_ENC_TS_DISABLED(c)                                \
    TRACE(c, "Ignoring encrypted timestamp because it is disabled")
#define TRACE_PREAUTH_ENC_TS_KEY_GAK(c, keyblock)                       \
    TRACE(c, "AS key obtained for encrypted timestamp: {keyblock}", keyblock)
#define TRACE_PREAUTH_ETYPE_INFO(c, etype, salt, s2kparams)          \
    TRACE(c, "Selected etype info: etype {etype}, salt \"{data}\", " \
          "params \"{data}\"", etype, salt, s2kparams)
#define TRACE_PREAUTH_INFO_FAIL(c, patype, code)                        \
    TRACE(c, "Preauth builtin info function failure, type={patype}: {kerr}", \
          patype, code)
#define TRACE_PREAUTH_INPUT(c, padata)                          \
    TRACE(c, "Processing preauth types: {patypes}", padata)
#define TRACE_PREAUTH_OUTPUT(c, padata)                                 \
    TRACE(c, "Produced preauth for next request: {patypes}", padata)
#define TRACE_PREAUTH_PROCESS(c, name, patype, real, code)              \
    TRACE(c, "Preauth module {str} ({int}) ({str}) returned: "          \
          "{kerr}", name, (int) patype, real ? "real" : "info", code)
#define TRACE_PREAUTH_SALT(c, salt, patype)                          \
    TRACE(c, "Received salt \"{data}\" via padata type {patype}", salt, \
          patype)
#define TRACE_PREAUTH_SAM_KEY_GAK(c, keyblock)                  \
    TRACE(c, "AS key obtained for SAM: {keyblock}", keyblock)
#define TRACE_PREAUTH_SKIP(c, name, patype)                           \
    TRACE(c, "Skipping previously used preauth module {str} ({int})", \
          name, (int) patype)
#define TRACE_PREAUTH_TRYAGAIN(c, name, patype, code)                   \
    TRACE(c, "Preauth module {str} ({int}) tryagain returned: {kerr}",  \
          name, (int)patype, code)
#define TRACE_PREAUTH_TRYAGAIN_INPUT(c, patype, padata)                 \
    TRACE(c, "Preauth tryagain input types ({int}): {patypes}", patype, padata)
#define TRACE_PREAUTH_TRYAGAIN_OUTPUT(c, padata)                        \
    TRACE(c, "Followup preauth for next request: {patypes}", padata)
#define TRACE_PREAUTH_WRONG_CONTEXT(c)                                  \
    TRACE(c, "Wrong context passed to krb5_init_creds_free(); leaking " \
          "modreq objects")
#define TRACE_PROFILE_ERR(c,subsection, section, retval)             \
    TRACE(c, "Bad value of {str} from [{str}] in conf file: {kerr}", \
          subsection, section, retval)
#define TRACE_RD_REP(c, ctime, cusec, subkey, seqnum)               \
    TRACE(c, "Read AP-REP, time {long}.{int}, subkey {keyblock}, "      \
          "seqnum {int}", (long) ctime, (int) cusec, subkey, (int) seqnum)
#define TRACE_RD_REP_DCE(c, ctime, cusec, seqnum)                      \
    TRACE(c, "Read DCE-style AP-REP, time {long}.{int}, seqnum {int}", \
          (long) ctime, (int) cusec, (int) seqnum)
#define TRACE_RD_REQ_DECRYPT_ANY(c, princ, keyblock)                \
    TRACE(c, "Decrypted AP-REQ with server principal {princ}: "     \
          "{keyblock}", princ, keyblock)
#define TRACE_RD_REQ_DECRYPT_FAIL(c, err)                       \
    TRACE(c, "Failed to decrypt AP-REQ ticket: {kerr}", err)
#define TRACE_RD_REQ_DECRYPT_SPECIFIC(c, princ, keyblock)               \
    TRACE(c, "Decrypted AP-REQ with specified server principal {princ}: " \
          "{keyblock}", princ, keyblock)
#define TRACE_RD_REQ_NEGOTIATED_ETYPE(c, etype)                     \
    TRACE(c, "Negotiated enctype based on authenticator: {etype}",  \
          etype)
#define TRACE_RD_REQ_SUBKEY(c, keyblock)                                \
    TRACE(c, "Authenticator contains subkey: {keyblock}", keyblock)
#define TRACE_RD_REQ_TICKET(c, client, server, keyblock)                \
    TRACE(c, "AP-REQ ticket: {princ} -> {princ}, session key {keyblock}", \
          client, server, keyblock)
#define TRACE_SENDTO_KDC(c, len, rlm, primary, tcp)                     \
    TRACE(c, "Sending request ({int} bytes) to {data}{str}{str}", len,  \
          rlm, (primary) ? " (primary)" : "", (tcp) ? " (tcp only)" : "")
#define TRACE_SENDTO_KDC_ERROR_SET_MESSAGE(c, raddr, err)               \
    TRACE(c, "Error preparing message to send to {raddr}: {errno}",     \
          raddr, err)
#define TRACE_SENDTO_KDC_HTTPS_ERROR(c, errs)                           \
    TRACE(c, "HTTPS error: {str}", errs)
#define TRACE_SENDTO_KDC_HTTPS_ERROR_CONNECT(c, raddr)          \
    TRACE(c, "HTTPS error connecting to {raddr}", raddr)
#define TRACE_SENDTO_KDC_HTTPS_ERROR_RECV(c, raddr)             \
    TRACE(c, "HTTPS error receiving from {raddr}", raddr)
#define TRACE_SENDTO_KDC_HTTPS_ERROR_SEND(c, raddr)     \
    TRACE(c, "HTTPS error sending to {raddr}", raddr)
#define TRACE_SENDTO_KDC_HTTPS_SEND(c, raddr)                           \
    TRACE(c, "Sending HTTPS request to {raddr}", raddr)
#define TRACE_SENDTO_KDC_K5TLS_LOAD_ERROR(c, ret)       \
    TRACE(c, "Error loading k5tls module: {kerr}", ret)
#define TRACE_SENDTO_KDC_PRIMARY(c, primary)                            \
    TRACE(c, "Response was{str} from primary KDC", (primary) ? "" : " not")
#define TRACE_SENDTO_KDC_RESOLVING(c, hostname)         \
    TRACE(c, "Resolving hostname {str}", hostname)
#define TRACE_SENDTO_KDC_RESPONSE(c, len, raddr)                        \
    TRACE(c, "Received answer ({int} bytes) from {raddr}", len, raddr)
#define TRACE_SENDTO_KDC_TCP_CONNECT(c, raddr)                  \
    TRACE(c, "Initiating TCP connection to {raddr}", raddr)
#define TRACE_SENDTO_KDC_TCP_DISCONNECT(c, raddr)               \
    TRACE(c, "Terminating TCP connection to {raddr}", raddr)
#define TRACE_SENDTO_KDC_TCP_ERROR_CONNECT(c, raddr, err)               \
    TRACE(c, "TCP error connecting to {raddr}: {errno}", raddr, err)
#define TRACE_SENDTO_KDC_TCP_ERROR_RECV(c, raddr, err)                  \
    TRACE(c, "TCP error receiving from {raddr}: {errno}", raddr, err)
#define TRACE_SENDTO_KDC_TCP_ERROR_RECV_LEN(c, raddr, err)              \
    TRACE(c, "TCP error receiving from {raddr}: {errno}", raddr, err)
#define TRACE_SENDTO_KDC_TCP_ERROR_SEND(c, raddr, err)                  \
    TRACE(c, "TCP error sending to {raddr}: {errno}", raddr, err)
#define TRACE_SENDTO_KDC_TCP_SEND(c, raddr)             \
    TRACE(c, "Sending TCP request to {raddr}", raddr)
#define TRACE_SENDTO_KDC_UDP_ERROR_RECV(c, raddr, err)                  \
    TRACE(c, "UDP error receiving from {raddr}: {errno}", raddr, err)
#define TRACE_SENDTO_KDC_UDP_ERROR_SEND_INITIAL(c, raddr, err)          \
    TRACE(c, "UDP error sending to {raddr}: {errno}", raddr, err)
#define TRACE_SENDTO_KDC_UDP_ERROR_SEND_RETRY(c, raddr, err)            \
    TRACE(c, "UDP error sending to {raddr}: {errno}", raddr, err)
#define TRACE_SENDTO_KDC_UDP_SEND_INITIAL(c, raddr)             \
    TRACE(c, "Sending initial UDP request to {raddr}", raddr)
#define TRACE_SENDTO_KDC_UDP_SEND_RETRY(c, raddr)               \
    TRACE(c, "Sending retry UDP request to {raddr}", raddr)
#define TRACE_SEND_TGS_ETYPES(c, etypes)                                \
    TRACE(c, "etypes requested in TGS request: {etypes}", etypes)
#define TRACE_SEND_TGS_SUBKEY(c, keyblock)                              \
    TRACE(c, "Generated subkey for TGS request: {keyblock}", keyblock)
#define TRACE_TGS_REPLY(c, client, server, keyblock)                 \
    TRACE(c, "TGS reply is for {princ} -> {princ} with session key " \
          "{keyblock}", client, server, keyblock)
#define TRACE_TGS_REPLY_DECODE_SESSION(c, keyblock)                     \
    TRACE(c, "TGS reply didn't decode with subkey; trying session key " \
          "({keyblock)}", keyblock)
#define TRACE_TKT_CREDS(c, creds, cache)                            \
    TRACE(c, "Getting credentials {creds} using ccache {ccache}",   \
          creds, cache)
#define TRACE_TKT_CREDS_ADVANCE(c, realm)                               \
    TRACE(c, "Received TGT for {data}; advancing current realm", realm)
#define TRACE_TKT_CREDS_CACHED_INTERMEDIATE_TGT(c, tgt)                 \
    TRACE(c, "Found cached TGT for intermediate realm: {creds}", tgt)
#define TRACE_TKT_CREDS_CACHED_SERVICE_TGT(c, tgt)                      \
    TRACE(c, "Found cached TGT for service realm: {creds}", tgt)
#define TRACE_TKT_CREDS_CLOSER_REALM(c, realm)                  \
    TRACE(c, "Trying next closer realm in path: {data}", realm)
#define TRACE_TKT_CREDS_COMPLETE(c, princ)                              \
    TRACE(c, "Received creds for desired service {princ}", princ)
#define TRACE_TKT_CREDS_FALLBACK(c, realm)                              \
    TRACE(c, "Local realm referral failed; trying fallback realm {data}", \
          realm)
#define TRACE_TKT_CREDS_LOCAL_TGT(c, tgt)                               \
    TRACE(c, "Starting with TGT for client realm: {creds}", tgt)
#define TRACE_TKT_CREDS_NON_TGT(c, princ)                            \
    TRACE(c, "Received non-TGT referral response ({princ}); trying " \
          "again without referrals", princ)
#define TRACE_TKT_CREDS_OFFPATH(c, realm)                       \
    TRACE(c, "Received TGT for offpath realm {data}", realm)
#define TRACE_TKT_CREDS_REFERRAL(c, princ)              \
    TRACE(c, "Following referral TGT {princ}", princ)
#define TRACE_TKT_CREDS_REFERRAL_REALM(c, princ)                        \
    TRACE(c, "Server has referral realm; starting with {princ}", princ)
#define TRACE_TKT_CREDS_RESPONSE_CODE(c, code)          \
    TRACE(c, "TGS request result: {kerr}", code)
#define TRACE_TKT_CREDS_RETRY_TCP(c)                                    \
    TRACE(c, "Request or response is too big for UDP; retrying with TCP")
#define TRACE_TKT_CREDS_SAME_REALM_TGT(c, realm)                        \
    TRACE(c, "Received TGT referral back to same realm ({data}); trying " \
          "again without referrals", realm)
#define TRACE_TKT_CREDS_SERVICE_REQ(c, princ, referral)                \
    TRACE(c, "Requesting tickets for {princ}, referrals {str}", princ, \
          (referral) ? "on" : "off")
#define TRACE_TKT_CREDS_TARGET_TGT(c, princ)                    \
    TRACE(c, "Received TGT for service realm: {princ}", princ)
#define TRACE_TKT_CREDS_TARGET_TGT_OFFPATH(c, princ)            \
    TRACE(c, "Received TGT for service realm: {princ}", princ)
#define TRACE_TKT_CREDS_TGT_REQ(c, next, cur)                           \
    TRACE(c, "Requesting TGT {princ} using TGT {princ}", next, cur)
#define TRACE_TKT_CREDS_WRONG_ENCTYPE(c)                                \
    TRACE(c, "Retrying TGS request with desired service ticket enctypes")
#define TRACE_TLS_CERT_ERROR(c, depth, namelen, name, err, errs)        \
    TRACE(c, "TLS certificate error at {int} ({lenstr}): {int} ({str})", \
          depth, namelen, name, err, errs)
#define TRACE_TLS_ERROR(c, errs)                \
    TRACE(c, "TLS error: {str}", errs)
#define TRACE_TLS_NO_REMOTE_CERTIFICATE(c)              \
    TRACE(c, "TLS server certificate not received")
#define TRACE_TLS_SERVER_NAME_MATCH(c, hostname)                        \
    TRACE(c, "TLS certificate name matched \"{str}\"", hostname)
#define TRACE_TLS_SERVER_NAME_MISMATCH(c, hostname)                     \
    TRACE(c, "TLS certificate name mismatch: server certificate is "    \
          "not for \"{str}\"", hostname)
#define TRACE_TXT_LOOKUP_NOTFOUND(c, host)              \
    TRACE(c, "TXT record {str} not found", host)
#define TRACE_TXT_LOOKUP_SUCCESS(c, host, realm)                \
    TRACE(c, "TXT record {str} found: {str}", host, realm)
#define EMPTY_K5BUF { K5BUF_ERROR }

#define K5_MUTEX_PARTIAL_INITIALIZER    K5_OS_MUTEX_PARTIAL_INITIALIZER
# define K5_ONCE_INIT                   K5_OS_NOTHREAD_ONCE_INIT
# define K5_OS_MUTEX_PARTIAL_INITIALIZER        \
    K5_OS_NOTHREAD_MUTEX_PARTIAL_INITIALIZER
# define K5_OS_NOTHREAD_MUTEX_PARTIAL_INITIALIZER       0
# define K5_OS_NOTHREAD_ONCE_INIT       2

# define USE_CONDITIONAL_PTHREADS
#define k5_assert_locked        k5_mutex_assert_locked
#define k5_assert_unlocked      k5_mutex_assert_unlocked
#define k5_getspecific  krb5int_getspecific
#define k5_key_delete   krb5int_key_delete
#define k5_key_register krb5int_key_register
#define k5_mutex_assert_locked(M)       ((void)(M))
#define k5_mutex_assert_unlocked(M)     ((void)(M))
#define k5_mutex_destroy(M)                     \
    (k5_os_mutex_destroy(M))
#define k5_mutex_lock krb5int_mutex_lock
#define k5_mutex_unlock krb5int_mutex_unlock
# define k5_once                        k5_os_nothread_once
# define k5_once_t                      k5_os_nothread_once_t
# define k5_os_mutex_destroy            k5_os_nothread_mutex_destroy
# define k5_os_mutex_finish_init        k5_os_nothread_mutex_finish_init
# define k5_os_mutex_init               k5_os_nothread_mutex_init
# define k5_os_mutex_lock               k5_os_nothread_mutex_lock
# define k5_os_mutex_unlock             k5_os_nothread_mutex_unlock
# define k5_os_nothread_once(O,F)                               \
    (*(O) == 3 ? 0                                              \
     : *(O) == 2 ? (*(O) = 4, (F)(), *(O) = 3, 0)               \
     : (assert(*(O) != 4), assert(*(O) == 2 || *(O) == 3), 0))
#define k5_setspecific  krb5int_setspecific

# define CALL_INIT_FUNCTION(NAME)       \
        k5_call_init_function(& JOIN__2(NAME, once))

#define FNM_CASEFOLD    0x08    
#define FNM_LEADING_DIR 0x10    
#define FNM_NOESCAPE    0x01    
#define FNM_NOMATCH     1       
#define FNM_NORES       3       
#define FNM_NOSYS       2       
#define FNM_PATHNAME    0x02    
#define FNM_PERIOD      0x04    
# define GET(SIZE,PTR)          (((const struct { uint##SIZE##_t i; } __attribute__((packed)) *)(PTR))->i)
# define GETSWAPPED(SIZE,PTR)           SWAP##SIZE(GET(SIZE,PTR))
# define INITIALIZER_RAN(NAME)  \
        (JOIN__2(NAME, once).did_run && JOIN__2(NAME, once).error == 0)
# define JOIN__2(A,B) JOIN__2_2(A,B)
# define JOIN__2_2(A,B) A ## _ ## _ ## B
#  define K5_BE
#define K5_GETOPT_DECL __declspec(dllimport)
#  define K5_LE

#define KRB5_TEXTDOMAIN "mit-krb5"
#  define MAKE_FINI_FUNCTION(NAME)                                          \
        static void NAME(void);                                             \
        void JOIN__2(NAME, auxfini)(shl_t, int);  \
        void JOIN__2(NAME, auxfini)(shl_t h, int l) { if (!l) NAME(); }     \
        static void NAME(void)
# define MAKE_INIT_FUNCTION(NAME)                               \
        static int NAME(void);                                  \
        MAYBE_DUMMY_INIT(NAME)                                  \
                \
        static void JOIN__2(NAME, aux) (void);                  \
        static k5_init_t JOIN__2(NAME, once) =                  \
                { K5_ONCE_INIT, 0, 0, JOIN__2(NAME, aux) };     \
        MAYBE_DEFINE_CALLINIT_FUNCTION                          \
        static void JOIN__2(NAME, aux) (void)                   \
        {                                                       \
            JOIN__2(NAME, once).did_run = 1;                    \
            JOIN__2(NAME, once).error = NAME();                 \
        }                                                       \
                \
        static int NAME(void)
#  define MAYBE_DEFINE_CALLINIT_FUNCTION                        \
        static inline int k5_call_init_function(k5_init_t *i)   \
        {                                                       \
            int err;                                            \
            err = k5_once(&i->once, i->fn);                     \
            if (err)                                            \
                return err;                                     \
            assert (i->did_run != 0);                           \
            return i->error;                                    \
        }
#  define MAYBE_DUMMY_INIT(NAME)                \
        void JOIN__2(NAME, auxinit) () { }
#define N_(s) s
# define PROGRAM_EXITING()              (0)
# define PUT(SIZE,PTR,VAL)      (((struct { uint##SIZE##_t i; } __attribute__((packed)) *)(PTR))->i = (VAL))
# define PUTSWAPPED(SIZE,PTR,VAL)       PUT(SIZE,PTR,SWAP##SIZE(VAL))
# define SIZE_MAX ((size_t)((size_t)0 - 1))
#define SNPRINTF_OVERFLOW(result, size) \
    ((unsigned int)(result) >= (size_t)(size))
# define SSIZE_MAX ((ssize_t)(SIZE_MAX/2))
# define SWAP16                 bswap_16
# define SWAP32                 bswap_32
#  define SWAP64                bswap_64
#define UINT16_TYPE uint16_t
#define UINT32_TYPE uint32_t
#define UNUSED __attribute__((__unused__))
#define _(s) s
#define asprintf krb5int_asprintf
#define bindtextdomain(p, d)
#define dgettext(d, m) m
#define fnmatch k5_fnmatch
#define getopt k5_getopt
#define getopt_long k5_getopt_long
#define gettimeofday krb5int_gettimeofday
#  define k5_call_init_function(I)                                      \
        (__extension__ ({                                               \
                k5_init_t *k5int_i = (I);                               \
                int k5int_err = k5_once(&k5int_i->once, k5int_i->fn);   \
                (k5int_err                                              \
                 ? k5int_err                                            \
                 : (assert(k5int_i->did_run != 0), k5int_i->error));    \
            }))
#   define k5_getpwnam_r(NAME, REC, BUF, BUFSIZE, OUT)  \
        (getpwnam_r(NAME,REC,BUF,BUFSIZE) == 0          \
         ? (*(OUT) = REC, 0)                            \
         : (*(OUT) = NULL, -1))
#   define k5_getpwuid_r(UID, REC, BUF, BUFSIZE, OUT)   \
        (getpwuid_r(UID,REC,BUF,BUFSIZE) == 0           \
         ? (*(OUT) = REC, 0)                            \
         : (*(OUT) = NULL, -1))
#define mkstemp krb5int_mkstemp
#define ngettext(m1, m2, n) (((n) == 1) ? m1 : m2)
#define no_argument       0
#define optarg k5_optarg
#define opterr k5_opterr
#define optind k5_optind
#define optional_argument 2
#define optopt k5_optopt
#define required_argument 1
#define secure_getenv getenv
#  define set_cloexec_fd(FD)    ((void)fcntl((FD), F_SETFD, FD_CLOEXEC))
#define set_cloexec_file(F)     set_cloexec_fd(fileno(F))
#define strerror_r k5_strerror_r
#define strlcat krb5int_strlcat
#define strlcpy krb5int_strlcpy
#define va_copy(dest, src)      ((dest) = (src))
#define vasprintf krb5int_vasprintf
# define zap(ptr, len) SecureZeroMemory(ptr, len)
#define ECONNABORTED WSAECONNABORTED
#define ECONNREFUSED WSAECONNREFUSED
#define ECONNRESET  WSAECONNRESET
#define EHOSTUNREACH WSAEHOSTUNREACH
#define EINPROGRESS WSAEINPROGRESS
#define ETIMEDOUT WSAETIMEDOUT
#define EWOULDBLOCK WSAEWOULDBLOCK

#define INVALID_SOCKET  ((SOCKET)~0)
#define SG_ADVANCE(SG, N)                       \
    ((SG)->len < (N)                            \
     ? (abort(), 0)                             \
     : ((SG)->buf += (N), (SG)->len -= (N), 0))
#define SG_BUF(SG)              ((SG)->buf + 0)
#define SG_LEN(SG)              ((SG)->len + 0)
#define SG_SET(SG, B, L)        ((SG)->iov_base = (char*)(B), (SG)->iov_len = (L))
#define SHUTDOWN_BOTH   2
#define SHUTDOWN_READ   0
#define SHUTDOWN_WRITE  1
#define SOCKET          int
#define SOCKET_CLOSE            close
#define SOCKET_CONNECT          socket_connect
#define SOCKET_EINTR            EINTR
#define SOCKET_ERRNO            errno
#define SOCKET_ERROR    (-1)
#define SOCKET_GETSOCKNAME      getsockname
#define SOCKET_INITIALIZE()     (0)     
#define SOCKET_NFDS(f)          ((f)+1) 
#define SOCKET_READ             read
#define SOCKET_SET_ERRNO(x)     (errno = (x))
#define SOCKET_WRITE            write
#define SOCKET_WRITEV(FD, SG, LEN, TMP)                 \
    ((TMP) = socket_sendmsg((FD), (SG), (LEN)), (TMP))
#define SOCKET_WRITEV_TEMP int

#define closesocket     close
#define inet_ntop(AF,SRC,DST,CNT)                                       \
    ((AF) == AF_INET                                                    \
     ? ((CNT) < 16                                                      \
        ? (SOCKET_SET_ERRNO(ENOSPC), (const char *)NULL)                \
        : (sprintf((DST), "%d.%d.%d.%d",                                \
                   ((const unsigned char *)(const void *)(SRC))[0] & 0xff, \
                   ((const unsigned char *)(const void *)(SRC))[1] & 0xff, \
                   ((const unsigned char *)(const void *)(SRC))[2] & 0xff, \
                   ((const unsigned char *)(const void *)(SRC))[3] & 0xff), \
           (DST)))                                                      \
     : (SOCKET_SET_ERRNO(EAFNOSUPPORT), (const char *)NULL))
#define ioctlsocket     ioctl
#define sockaddr_storage krb5int_sockaddr_storage

