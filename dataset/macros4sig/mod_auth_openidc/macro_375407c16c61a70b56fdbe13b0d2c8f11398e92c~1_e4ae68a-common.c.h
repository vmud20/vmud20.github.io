













#include<unistd.h>



#include<stdint.h>




#define NAMEVERSION "mod_auth_openidc-0.0.0"
#define OIDCCacheShmEntrySizeMax             "OIDCCacheShmEntrySizeMax"
#define OIDCCacheShmMax                      "OIDCCacheShmMax"
#define OIDCClaimPrefix                      "OIDCClaimPrefix"
#define OIDCCookieDomain                     "OIDCCookieDomain"
#define OIDCCookiePath                       "OIDCCookiePath"
#define OIDCDefaultURL                       "OIDCDefaultURL"
#define OIDCInfoHook                         "OIDCInfoHook"
#define OIDCMemCacheServers                  "OIDCMemCacheServers"
#define OIDCOAuthRemoteUserClaim             "OIDCOAuthRemoteUserClaim"
#define OIDCPrivateKeyFiles                  "OIDCPrivateKeyFiles"
#define OIDCRedirectURI                      "OIDCRedirectURI"
#define OIDCRedisCacheServer                 "OIDCRedisCacheServer"
#define OIDCRemoteUserClaim                  "OIDCRemoteUserClaim"
#define OIDCSessionType                      "OIDCSessionType"
#define OIDCWhiteListedClaims                "OIDCWhiteListedClaims"
#define OIDC_APP_INFO_ACCESS_TOKEN      "access_token"
#define OIDC_APP_INFO_ACCESS_TOKEN_EXP  "access_token_expires"
#define OIDC_APP_INFO_ID_TOKEN          "id_token"
#define OIDC_APP_INFO_ID_TOKEN_PAYLOAD  "id_token_payload"
#define OIDC_APP_INFO_REFRESH_TOKEN     "refresh_token"
#define OIDC_APP_INFO_USERINFO_JSON     "userinfo_json"
#define OIDC_APP_INFO_USERINFO_JWT      "userinfo_jwt"
#define OIDC_AUTH_REQUEST_METHOD_GET  0
#define OIDC_AUTH_REQUEST_METHOD_POST 1
#define OIDC_BACKCHANNEL_STYLE_LOGOUT_PARAM_VALUE "backchannel"
#define OIDC_CACHE_PROVIDER_METADATA_EXPIRY_DEFAULT 86400
#define OIDC_CHAR_AMP           '&'
#define OIDC_CHAR_AT            '@'
#define OIDC_CHAR_COLON         ':'
#define OIDC_CHAR_COMMA         ','
#define OIDC_CHAR_DOT           '.'
#define OIDC_CHAR_EQUAL         '='
#define OIDC_CHAR_FORWARD_SLASH '/'
#define OIDC_CHAR_PIPE          '|'
#define OIDC_CHAR_QUERY         '?'
#define OIDC_CHAR_SEMI_COLON    ';'
#define OIDC_CHAR_SPACE         ' '
#define OIDC_CHAR_TILDE         '~'
#define OIDC_CLAIM_AT_HASH         "at_hash"
#define OIDC_CLAIM_AUD             "aud"
#define OIDC_CLAIM_AZP             "azp"
#define OIDC_CLAIM_CNF             "cnf"
#define OIDC_CLAIM_CNF_TBH         "tbh"
#define OIDC_CLAIM_CNF_X5T_S256    "x5t#S256"
#define OIDC_CLAIM_C_HASH          "c_hash"
#define OIDC_CLAIM_EVENTS          "events"
#define OIDC_CLAIM_EXP             "exp"
#define OIDC_CLAIM_IAT             "iat"
#define OIDC_CLAIM_ISS             "iss"
#define OIDC_CLAIM_JTI             "jti"
#define OIDC_CLAIM_NONCE           "nonce"
#define OIDC_CLAIM_RFP             "rfp"
#define OIDC_CLAIM_SID             "sid"
#define OIDC_CLAIM_SUB             "sub"
#define OIDC_CLAIM_TARGET_LINK_URI "target_link_uri"
#define OIDC_CONTENT_TYPE_ANY           "*/*"
#define OIDC_CONTENT_TYPE_APP_XHTML_XML "application/xhtml+xml"
#define OIDC_CONTENT_TYPE_FORM_ENCODED  "application/x-www-form-urlencoded"
#define OIDC_CONTENT_TYPE_IMAGE_PNG     "image/png"
#define OIDC_CONTENT_TYPE_JSON          "application/json"
#define OIDC_CONTENT_TYPE_JWT           "application/jwt"
#define OIDC_CONTENT_TYPE_TEXT_HTML     "text/html"
#define OIDC_COOKIE_EXT_SAME_SITE_LAX    "SameSite=Lax"
#define OIDC_COOKIE_EXT_SAME_SITE_NONE(r) \
		oidc_util_request_is_secure(r) ? "SameSite=None" : NULL
#define OIDC_COOKIE_EXT_SAME_SITE_STRICT "SameSite=Strict"
#define OIDC_COOKIE_SAMESITE_LAX(c, r) \
		c->cookie_same_site ? OIDC_COOKIE_EXT_SAME_SITE_LAX : OIDC_COOKIE_EXT_SAME_SITE_NONE(r)
#define OIDC_COOKIE_SAMESITE_STRICT(c, r) \
		c->cookie_same_site ? OIDC_COOKIE_EXT_SAME_SITE_STRICT : OIDC_COOKIE_EXT_SAME_SITE_NONE(r)
#define OIDC_CSRF_NAME "x_csrf"
#define OIDC_DEBUG APLOG_DEBUG
#define OIDC_DEFAULT_HEADER_PREFIX "OIDC_"
#define OIDC_DISC_AR_PARAM "auth_request_params"
#define OIDC_DISC_CB_PARAM "oidc_callback"
#define OIDC_DISC_LH_PARAM "login_hint"
#define OIDC_DISC_OP_PARAM "iss"
#define OIDC_DISC_RM_PARAM "method"
#define OIDC_DISC_RT_PARAM "target_link_uri"
#define OIDC_DISC_SC_PARAM "scopes"
#define OIDC_DISC_USER_PARAM "disc_user"
#define OIDC_GET_STYLE_LOGOUT_PARAM_VALUE "get"
#define OIDC_HOOK_INFO_ACCES_TOKEN         "access_token"
#define OIDC_HOOK_INFO_ACCES_TOKEN_EXP     "access_token_expires"
#define OIDC_HOOK_INFO_FORMAT_HTML         "html"
#define OIDC_HOOK_INFO_FORMAT_JSON         "json"
#define OIDC_HOOK_INFO_ID_TOKEN            "id_token"
#define OIDC_HOOK_INFO_REFRESH_TOKEN       "refresh_token"
#define OIDC_HOOK_INFO_SESSION             "session"
#define OIDC_HOOK_INFO_SESSION_EXP         "exp"
#define OIDC_HOOK_INFO_SESSION_REMOTE_USER "remote_user"
#define OIDC_HOOK_INFO_SESSION_STATE       "state"
#define OIDC_HOOK_INFO_SESSION_TIMEOUT     "timeout"
#define OIDC_HOOK_INFO_SESSION_UUID        "uuid"
#define OIDC_HOOK_INFO_TIMESTAMP           "iat"
#define OIDC_HOOK_INFO_USER_INFO           "userinfo"
#define OIDC_IMG_STYLE_LOGOUT_PARAM_VALUE "img"
#define OIDC_INTROSPECTION_METHOD_GET  "GET"
#define OIDC_INTROSPECTION_METHOD_POST "POST"
#define OIDC_JWK_ENC       "enc"
#define OIDC_JWK_KEYS      "keys"
#define OIDC_JWK_SIG       "sig"
#define OIDC_JWK_USE       "use"
#define OIDC_JWK_X5T       "x5t"
#define OIDC_LOGOUT_ON_ERROR_REFRESH 1
#define OIDC_MAX_POST_DATA_LEN 1024 * 1024
#define OIDC_METHOD_FORM_POST "form_post"
#define OIDC_METHOD_GET       "get"
#define OIDC_OAUTH_ACCEPT_TOKEN_IN_BASIC   16
#define OIDC_OAUTH_ACCEPT_TOKEN_IN_COOKIE  8
#define OIDC_OAUTH_ACCEPT_TOKEN_IN_DEFAULT 0
#define OIDC_OAUTH_ACCEPT_TOKEN_IN_HEADER  1
#define OIDC_OAUTH_ACCEPT_TOKEN_IN_OPTION_COOKIE_NAME "cookie-name"
#define OIDC_OAUTH_ACCEPT_TOKEN_IN_POST    2
#define OIDC_OAUTH_ACCEPT_TOKEN_IN_QUERY   4
#define OIDC_PASS_IDTOKEN_AS_CLAIMS     1
#define OIDC_PASS_IDTOKEN_AS_PAYLOAD    2
#define OIDC_PASS_IDTOKEN_AS_SERIALIZED 4
#define OIDC_PASS_USERINFO_AS_CLAIMS      1
#define OIDC_PASS_USERINFO_AS_JSON_OBJECT 2
#define OIDC_PASS_USERINFO_AS_JWT         4
#define OIDC_PROTO_ACCESS_TOKEN          "access_token"
#define OIDC_PROTO_ACTIVE                "active"
#define OIDC_PROTO_BASIC   "Basic"
#define OIDC_PROTO_BEARER  "Bearer"
#define OIDC_PROTO_BEARER_ACCESS_TOKEN "bearer_access_token"
#define OIDC_PROTO_CLIENT_ASSERTION      "client_assertion"
#define OIDC_PROTO_CLIENT_ASSERTION_TYPE "client_assertion_type"
#define OIDC_PROTO_CLIENT_ASSERTION_TYPE_JWT_BEARER "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
#define OIDC_PROTO_CLIENT_ID             "client_id"
#define OIDC_PROTO_CLIENT_SECRET         "client_secret"
#define OIDC_PROTO_CLIENT_SECRET_BASIC "client_secret_basic"
#define OIDC_PROTO_CLIENT_SECRET_JWT   "client_secret_jwt"
#define OIDC_PROTO_CLIENT_SECRET_POST  "client_secret_post"
#define OIDC_PROTO_CODE                  "code"
#define OIDC_PROTO_CODE_CHALLENGE        "code_challenge"
#define OIDC_PROTO_CODE_CHALLENGE_METHOD "code_challenge_method"
#define OIDC_PROTO_CODE_VERIFIER         "code_verifier"
#define OIDC_PROTO_CODE_VERIFIER_LENGTH 32
#define OIDC_PROTO_ENDPOINT_AUTH_NONE  "none"
#define OIDC_PROTO_ERROR                  "error"
#define OIDC_PROTO_ERROR_DESCRIPTION      "error_description"
#define OIDC_PROTO_ERR_INVALID_REQUEST        "invalid_request"
#define OIDC_PROTO_ERR_INVALID_TOKEN          "invalid_token"
#define OIDC_PROTO_EXPIRES_IN            "expires_in"
#define OIDC_PROTO_GRANT_TYPE            "grant_type"
#define OIDC_PROTO_GRANT_TYPE_AUTHZ_CODE    "authorization_code"
#define OIDC_PROTO_GRANT_TYPE_REFRESH_TOKEN "refresh_token"
#define OIDC_PROTO_ID_TOKEN              "id_token"
#define OIDC_PROTO_ID_TOKEN_HINT         "id_token_hint"
#define OIDC_PROTO_ISS                   "iss"
#define OIDC_PROTO_LOGIN_HINT            "login_hint"
#define OIDC_PROTO_LOGOUT_TOKEN          "logout_token"
#define OIDC_PROTO_NONCE                 "nonce"
#define OIDC_PROTO_NONCE_LENGTH 32
#define OIDC_PROTO_PRIVATE_KEY_JWT     "private_key_jwt"
#define OIDC_PROTO_PROMPT                "prompt"
#define OIDC_PROTO_PROMPT_NONE            "none"
#define OIDC_PROTO_REALM                  "realm"
#define OIDC_PROTO_REDIRECT_URI          "redirect_uri"
#define OIDC_PROTO_REFRESH_TOKEN         "refresh_token"
#define OIDC_PROTO_REQUEST_OBJECT        "request"
#define OIDC_PROTO_REQUEST_URI           "request_uri"
#define OIDC_PROTO_RESPONSE_MODE         "response_mode"
#define OIDC_PROTO_RESPONSE_MODE_FORM_POST "form_post"
#define OIDC_PROTO_RESPONSE_MODE_FRAGMENT  "fragment"
#define OIDC_PROTO_RESPONSE_MODE_QUERY     "query"
#define OIDC_PROTO_RESPONSE_TYPE         "response_type"
#define OIDC_PROTO_RESPONSE_TYPE_CODE               "code"
#define OIDC_PROTO_RESPONSE_TYPE_CODE_IDTOKEN       "code id_token"
#define OIDC_PROTO_RESPONSE_TYPE_CODE_IDTOKEN_TOKEN "code id_token token"
#define OIDC_PROTO_RESPONSE_TYPE_CODE_TOKEN         "code token"
#define OIDC_PROTO_RESPONSE_TYPE_IDTOKEN            "id_token"
#define OIDC_PROTO_RESPONSE_TYPE_IDTOKEN_TOKEN      "id_token token"
#define OIDC_PROTO_RESPONSE_TYPE_TOKEN              "token"
#define OIDC_PROTO_SCOPE                 "scope"
#define OIDC_PROTO_SCOPE_OPENID           "openid"
#define OIDC_PROTO_SESSION_STATE         "session_state"
#define OIDC_PROTO_STATE                 "state"
#define OIDC_PROTO_TOKEN_TYPE            "token_type"
#define OIDC_REDIRECT_URI_REQUEST_INFO             "info"
#define OIDC_REDIRECT_URI_REQUEST_JWKS             "jwks"
#define OIDC_REDIRECT_URI_REQUEST_LOGOUT           "logout"
#define OIDC_REDIRECT_URI_REQUEST_REFRESH          "refresh"
#define OIDC_REDIRECT_URI_REQUEST_REMOVE_AT_CACHE  "remove_at_cache"
#define OIDC_REDIRECT_URI_REQUEST_REQUEST_URI      "request_uri"
#define OIDC_REDIRECT_URI_REQUEST_SESSION          "session"
#define OIDC_REQUEST_STATE_KEY_CLAIMS  "c"
#define OIDC_REQUEST_STATE_KEY_IDTOKEN "i"
#define OIDC_REQUEST_URI_CACHE_DURATION 30
#define OIDC_REQUIRE_CLAIMS_EXPR_NAME "claims_expr"
#define OIDC_REQUIRE_CLAIM_NAME "claim"
#define OIDC_SESSION_TYPE_CLIENT_COOKIE 1
#define OIDC_SESSION_TYPE_SERVER_CACHE 0
#define OIDC_STATE_INPUT_HEADERS_USER_AGENT 1
#define OIDC_STATE_INPUT_HEADERS_X_FORWARDED_FOR 2
#define OIDC_STR_AMP           "&"
#define OIDC_STR_AT            "@"
#define OIDC_STR_COLON         ":"
#define OIDC_STR_COMMA         ","
#define OIDC_STR_EQUAL         "="
#define OIDC_STR_FORWARD_SLASH "/"
#define OIDC_STR_HASH          "#"
#define OIDC_STR_QUERY         "?"
#define OIDC_STR_SEMI_COLON    ";"
#define OIDC_STR_SPACE         " "
#define OIDC_TB_CFG_FINGERPRINT_ENV_VAR  "TB_SSL_CLIENT_CERT_FINGERPRINT"
#define OIDC_TB_CFG_PROVIDED_ENV_VAR     "Sec-Provided-Token-Binding-ID"
#define OIDC_TOKEN_BINDING_POLICY_DISABLED  0
#define OIDC_TOKEN_BINDING_POLICY_ENFORCED  3
#define OIDC_TOKEN_BINDING_POLICY_OPTIONAL  1
#define OIDC_TOKEN_BINDING_POLICY_REQUIRED  2
#define OIDC_UNAUTH_AUTHENTICATE 1
#define OIDC_UNAUTH_PASS         2
#define OIDC_UNAUTH_RETURN401    3
#define OIDC_UNAUTH_RETURN407    5
#define OIDC_UNAUTH_RETURN410    4
#define OIDC_UNAUTZ_AUTHENTICATE 3
#define OIDC_UNAUTZ_RETURN401    2
#define OIDC_UNAUTZ_RETURN403    1
#define OIDC_USERDATA_KEY "mod_auth_openidc_state"
#define OIDC_USERDATA_POST_PARAMS_KEY "oidc_userdata_post_params"
#define OIDC_USER_INFO_TOKEN_METHOD_HEADER 0
#define OIDC_USER_INFO_TOKEN_METHOD_POST   1
#define OIDC_UTIL_HTTP_SENDSTRING "OIDC_UTIL_HTTP_SENDSTRING"
#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define oidc_debug(r, fmt, ...) oidc_log(r, OIDC_DEBUG, fmt, ##__VA_ARGS__)
#define oidc_error(r, fmt, ...) oidc_log(r, APLOG_ERR, fmt, ##__VA_ARGS__)
#define oidc_log(r, level, fmt, ...) ap_log_rerror(APLOG_MARK, level, 0, r,"%s: %s", __FUNCTION__, apr_psprintf(r->pool, fmt, ##__VA_ARGS__))
#define oidc_sdebug(s, fmt, ...) oidc_slog(s, OIDC_DEBUG, fmt, ##__VA_ARGS__)
#define oidc_serror(s, fmt, ...) oidc_slog(s, APLOG_ERR, fmt, ##__VA_ARGS__)
#define oidc_slog(s, level, fmt, ...) ap_log_error(APLOG_MARK, level, 0, s, "%s: %s", __FUNCTION__, apr_psprintf(s->process->pool, fmt, ##__VA_ARGS__))
#define oidc_swarn(s, fmt, ...) oidc_slog(s, APLOG_WARNING, fmt, ##__VA_ARGS__)
#define oidc_warn(r, fmt, ...) oidc_log(r, APLOG_WARNING, fmt, ##__VA_ARGS__)

#define OIDC_CLAIM_FORMAT_ABSOLUTE    "absolute"
#define OIDC_CLAIM_FORMAT_RELATIVE    "relative"
#define OIDC_CLAIM_REQUIRED_MANDATORY "mandatory"
#define OIDC_CLAIM_REQUIRED_OPTIONAL  "optional"
#define OIDC_CONFIG_POS_INT_UNSET -1
#define OIDC_CONFIG_STRING_EMPTY  ""
#define OIDC_CONFIG_STRING_UNSET  "_UNSET_"
#define OIDC_ENDPOINT_AUTH_CLIENT_SECRET_BASIC "client_secret_basic"
#define OIDC_PKCE_METHOD_PLAIN        "plain"
#define OIDC_PKCE_METHOD_REFERRED_TB  "referred_tb"
#define OIDC_PKCE_METHOD_S256         "S256"
#define OIDC_CACHE_SECTION_ACCESS_TOKEN      "a"
#define OIDC_CACHE_SECTION_JTI               "t"
#define OIDC_CACHE_SECTION_JWKS              "j"
#define OIDC_CACHE_SECTION_NONCE             "n"
#define OIDC_CACHE_SECTION_OAUTH_PROVIDER    "o"
#define OIDC_CACHE_SECTION_PROVIDER          "p"
#define OIDC_CACHE_SECTION_REQUEST_URI       "r"
#define OIDC_CACHE_SECTION_SESSION           "s"
#define OIDC_CACHE_SECTION_SID               "d"

#define oidc_cache_get_access_token(r, key, value) oidc_cache_get(r, OIDC_CACHE_SECTION_ACCESS_TOKEN, key, value)
#define oidc_cache_get_jti(r, key, value) oidc_cache_get(r, OIDC_CACHE_SECTION_JTI, key, value)
#define oidc_cache_get_jwks(r, key, value) oidc_cache_get(r, OIDC_CACHE_SECTION_JWKS, key, value)
#define oidc_cache_get_nonce(r, key, value) oidc_cache_get(r, OIDC_CACHE_SECTION_NONCE, key, value)
#define oidc_cache_get_oauth_provider(r, key, value) oidc_cache_get(r, OIDC_CACHE_SECTION_OAUTH_PROVIDER, key, value)
#define oidc_cache_get_provider(r, key, value) oidc_cache_get(r, OIDC_CACHE_SECTION_PROVIDER, key, value)
#define oidc_cache_get_request_uri(r, key, value) oidc_cache_get(r, OIDC_CACHE_SECTION_REQUEST_URI, key, value)
#define oidc_cache_get_session(r, key, value) oidc_cache_get(r, OIDC_CACHE_SECTION_SESSION, key, value)
#define oidc_cache_get_sid(r, key, value) oidc_cache_get(r, OIDC_CACHE_SECTION_SID, key, value)
#define oidc_cache_set_access_token(r, key, value, expiry) oidc_cache_set(r, OIDC_CACHE_SECTION_ACCESS_TOKEN, key, value, expiry)
#define oidc_cache_set_jti(r, key, value, expiry) oidc_cache_set(r, OIDC_CACHE_SECTION_JTI, key, value, expiry)
#define oidc_cache_set_jwks(r, key, value, expiry) oidc_cache_set(r, OIDC_CACHE_SECTION_JWKS, key, value, expiry)
#define oidc_cache_set_nonce(r, key, value, expiry) oidc_cache_set(r, OIDC_CACHE_SECTION_NONCE, key, value, expiry)
#define oidc_cache_set_oauth_provider(r, key, value, expiry) oidc_cache_set(r, OIDC_CACHE_SECTION_OAUTH_PROVIDER, key, value, expiry)
#define oidc_cache_set_provider(r, key, value, expiry) oidc_cache_set(r, OIDC_CACHE_SECTION_PROVIDER, key, value, expiry)
#define oidc_cache_set_request_uri(r, key, value, expiry) oidc_cache_set(r, OIDC_CACHE_SECTION_REQUEST_URI, key, value, expiry)
#define oidc_cache_set_session(r, key, value, expiry) oidc_cache_set(r, OIDC_CACHE_SECTION_SESSION, key, value, expiry)
#define oidc_cache_set_sid(r, key, value, expiry) oidc_cache_set(r, OIDC_CACHE_SECTION_SID, key, value, expiry)

#define OIDC_JOSE_ALG_SHA1 "sha1"
#define OIDC_JOSE_ALG_SHA256 "sha256"
#define OIDC_JOSE_EC_SUPPORT  OPENSSL_VERSION_NUMBER >= 0x1000100f
#define OIDC_JOSE_ERROR_FUNCTION_LENGTH 80
#define OIDC_JOSE_ERROR_SOURCE_LENGTH   80
#define OIDC_JOSE_ERROR_TEXT_LENGTH    200
#define OIDC_JOSE_GCM_SUPPORT OPENSSL_VERSION_NUMBER >= 0x1000100f
#define OIDC_JOSE_JWK_KID_STR "kid" 
#define OIDC_JOSE_JWK_KTY_STR "kty" 
#define OIDC_JOSE_JWK_USE_STR "use" 
#define OIDC_JOSE_JWK_X5C_STR "x5c" 
#define OIDC_JOSE_JWK_X5T256_STR "x5t#S256" 
#define OIDC_JOSE_JWK_X5T_STR "x5t" 
#define OIDC_JWT_CLAIM_TIME_EMPTY -1
#define oidc_cjose_e2s(pool, cjose_err) apr_psprintf(pool, "%s [file: %s, function: %s, line: %ld]", cjose_err.message, cjose_err.file, cjose_err.function, cjose_err.line)
#define oidc_jose_e2s(pool, err) apr_psprintf(pool, "[%s:%d: %s]: %s", err.source, err.line, err.function, err.text)
#define oidc_jose_error(err, msg, ...) _oidc_jose_error_set(err, "__FILE__", "__LINE__", __FUNCTION__, msg, ##__VA_ARGS__)
#define oidc_jose_error_openssl(err, msg, ...) _oidc_jose_error_set(err, "__FILE__", "__LINE__", __FUNCTION__, "%s() failed: %s", msg, ERR_error_string(ERR_get_error(), NULL), ##__VA_ARGS__)
