
























typedef enum {
  K_ACCEPT = 0, K_ACCEPT6, K_DIRECTORY_SIGNATURE, K_RECOMMENDED_SOFTWARE, K_REJECT, K_REJECT6, K_ROUTER, K_SIGNED_DIRECTORY, K_SIGNING_KEY, K_ONION_KEY, K_ONION_KEY_NTOR, K_ROUTER_SIGNATURE, K_PUBLISHED, K_RUNNING_ROUTERS, K_ROUTER_STATUS, K_PLATFORM, K_OPT, K_BANDWIDTH, K_CONTACT, K_NETWORK_STATUS, K_UPTIME, K_DIR_SIGNING_KEY, K_FAMILY, K_FINGERPRINT, K_HIBERNATING, K_READ_HISTORY, K_WRITE_HISTORY, K_NETWORK_STATUS_VERSION, K_DIR_SOURCE, K_DIR_OPTIONS, K_CLIENT_VERSIONS, K_SERVER_VERSIONS, K_OR_ADDRESS, K_P, K_P6, K_R, K_A, K_S, K_V, K_W, K_M, K_EXTRA_INFO, K_EXTRA_INFO_DIGEST, K_CACHES_EXTRA_INFO, K_HIDDEN_SERVICE_DIR, K_ALLOW_SINGLE_HOP_EXITS, K_IPV6_POLICY,  K_DIRREQ_END, K_DIRREQ_V2_IPS, K_DIRREQ_V3_IPS, K_DIRREQ_V2_REQS, K_DIRREQ_V3_REQS, K_DIRREQ_V2_SHARE, K_DIRREQ_V3_SHARE, K_DIRREQ_V2_RESP, K_DIRREQ_V3_RESP, K_DIRREQ_V2_DIR, K_DIRREQ_V3_DIR, K_DIRREQ_V2_TUN, K_DIRREQ_V3_TUN, K_ENTRY_END, K_ENTRY_IPS, K_CELL_END, K_CELL_PROCESSED, K_CELL_QUEUED, K_CELL_TIME, K_CELL_CIRCS, K_EXIT_END, K_EXIT_WRITTEN, K_EXIT_READ, K_EXIT_OPENED,  K_DIR_KEY_CERTIFICATE_VERSION, K_DIR_IDENTITY_KEY, K_DIR_KEY_PUBLISHED, K_DIR_KEY_EXPIRES, K_DIR_KEY_CERTIFICATION, K_DIR_KEY_CROSSCERT, K_DIR_ADDRESS,  K_VOTE_STATUS, K_VALID_AFTER, K_FRESH_UNTIL, K_VALID_UNTIL, K_VOTING_DELAY,  K_KNOWN_FLAGS, K_PARAMS, K_BW_WEIGHTS, K_VOTE_DIGEST, K_CONSENSUS_DIGEST, K_ADDITIONAL_DIGEST, K_ADDITIONAL_SIGNATURE, K_CONSENSUS_METHODS, K_CONSENSUS_METHOD, K_LEGACY_DIR_KEY, K_DIRECTORY_FOOTER,  A_PURPOSE, A_LAST_LISTED, A_UNKNOWN_,  R_RENDEZVOUS_SERVICE_DESCRIPTOR, R_VERSION, R_PERMANENT_KEY, R_SECRET_ID_PART, R_PUBLICATION_TIME, R_PROTOCOL_VERSIONS, R_INTRODUCTION_POINTS, R_SIGNATURE,  R_IPO_IDENTIFIER, R_IPO_IP_ADDRESS, R_IPO_ONION_PORT, R_IPO_ONION_KEY, R_IPO_SERVICE_KEY,  C_CLIENT_NAME, C_DESCRIPTOR_COOKIE, C_CLIENT_KEY,  ERR_, EOF_, NIL_ } directory_keyword;

































































































































typedef struct directory_token_t {
  directory_keyword tp;        
  int n_args:30;               
  char **args;                 

  char *object_type;           
  size_t object_size;          
  char *object_body;           

  crypto_pk_t *key;        

  char *error;                 
} directory_token_t;






typedef enum {
  NO_OBJ,         NEED_OBJ, NEED_SKEY_1024, NEED_KEY_1024, NEED_KEY, OBJ_OK, } obj_syntax;










typedef struct token_rule_t {
  
  const char *t;
  
  directory_keyword v;
  
  int min_args;
  
  int max_args;
  
  int concat_args;
  
  obj_syntax os;
  
  int min_cnt;
  
  int max_cnt;
  
  int pos;
  
  int is_annotation;
} token_rule_t;


































static token_rule_t routerdesc_token_table[] = {
  T0N("reject",              K_REJECT,              ARGS,    NO_OBJ ), T0N("accept",              K_ACCEPT,              ARGS,    NO_OBJ ), T0N("reject6",             K_REJECT6,             ARGS,    NO_OBJ ), T0N("accept6",             K_ACCEPT6,             ARGS,    NO_OBJ ), T1_START( "router",        K_ROUTER,              GE(5),   NO_OBJ ), T01("ipv6-policy",         K_IPV6_POLICY,         CONCAT_ARGS, NO_OBJ), T1( "signing-key",         K_SIGNING_KEY,         NO_ARGS, NEED_KEY_1024 ), T1( "onion-key",           K_ONION_KEY,           NO_ARGS, NEED_KEY_1024 ), T01("ntor-onion-key",      K_ONION_KEY_NTOR,      GE(1), NO_OBJ ), T1_END( "router-signature",    K_ROUTER_SIGNATURE,    NO_ARGS, NEED_OBJ ), T1( "published",           K_PUBLISHED,       CONCAT_ARGS, NO_OBJ ), T01("uptime",              K_UPTIME,              GE(1),   NO_OBJ ), T01("fingerprint",         K_FINGERPRINT,     CONCAT_ARGS, NO_OBJ ), T01("hibernating",         K_HIBERNATING,         GE(1),   NO_OBJ ), T01("platform",            K_PLATFORM,        CONCAT_ARGS, NO_OBJ ), T01("contact",             K_CONTACT,         CONCAT_ARGS, NO_OBJ ), T01("read-history",        K_READ_HISTORY,        ARGS,    NO_OBJ ), T01("write-history",       K_WRITE_HISTORY,       ARGS,    NO_OBJ ), T01("extra-info-digest",   K_EXTRA_INFO_DIGEST,   GE(1),   NO_OBJ ), T01("hidden-service-dir",  K_HIDDEN_SERVICE_DIR,  NO_ARGS, NO_OBJ ), T01("allow-single-hop-exits",K_ALLOW_SINGLE_HOP_EXITS,    NO_ARGS, NO_OBJ ),  T01("family",              K_FAMILY,              ARGS,    NO_OBJ ), T01("caches-extra-info",   K_CACHES_EXTRA_INFO,   NO_ARGS, NO_OBJ ), T0N("or-address",          K_OR_ADDRESS,          GE(1),   NO_OBJ ),  T0N("opt",                 K_OPT,             CONCAT_ARGS, OBJ_OK ), T1( "bandwidth",           K_BANDWIDTH,           GE(3),   NO_OBJ ), A01("@purpose",            A_PURPOSE,             GE(1),   NO_OBJ ),  END_OF_TABLE };
































static token_rule_t extrainfo_token_table[] = {
  T1_END( "router-signature",    K_ROUTER_SIGNATURE,    NO_ARGS, NEED_OBJ ), T1( "published",           K_PUBLISHED,       CONCAT_ARGS, NO_OBJ ), T0N("opt",                 K_OPT,             CONCAT_ARGS, OBJ_OK ), T01("read-history",        K_READ_HISTORY,        ARGS,    NO_OBJ ), T01("write-history",       K_WRITE_HISTORY,       ARGS,    NO_OBJ ), T01("dirreq-stats-end",    K_DIRREQ_END,          ARGS,    NO_OBJ ), T01("dirreq-v2-ips",       K_DIRREQ_V2_IPS,       ARGS,    NO_OBJ ), T01("dirreq-v3-ips",       K_DIRREQ_V3_IPS,       ARGS,    NO_OBJ ), T01("dirreq-v2-reqs",      K_DIRREQ_V2_REQS,      ARGS,    NO_OBJ ), T01("dirreq-v3-reqs",      K_DIRREQ_V3_REQS,      ARGS,    NO_OBJ ), T01("dirreq-v2-share",     K_DIRREQ_V2_SHARE,     ARGS,    NO_OBJ ), T01("dirreq-v3-share",     K_DIRREQ_V3_SHARE,     ARGS,    NO_OBJ ), T01("dirreq-v2-resp",      K_DIRREQ_V2_RESP,      ARGS,    NO_OBJ ), T01("dirreq-v3-resp",      K_DIRREQ_V3_RESP,      ARGS,    NO_OBJ ), T01("dirreq-v2-direct-dl", K_DIRREQ_V2_DIR,       ARGS,    NO_OBJ ), T01("dirreq-v3-direct-dl", K_DIRREQ_V3_DIR,       ARGS,    NO_OBJ ), T01("dirreq-v2-tunneled-dl", K_DIRREQ_V2_TUN,     ARGS,    NO_OBJ ), T01("dirreq-v3-tunneled-dl", K_DIRREQ_V3_TUN,     ARGS,    NO_OBJ ), T01("entry-stats-end",     K_ENTRY_END,           ARGS,    NO_OBJ ), T01("entry-ips",           K_ENTRY_IPS,           ARGS,    NO_OBJ ), T01("cell-stats-end",      K_CELL_END,            ARGS,    NO_OBJ ), T01("cell-processed-cells", K_CELL_PROCESSED,     ARGS,    NO_OBJ ), T01("cell-queued-cells",   K_CELL_QUEUED,         ARGS,    NO_OBJ ), T01("cell-time-in-queue",  K_CELL_TIME,           ARGS,    NO_OBJ ), T01("cell-circuits-per-decile", K_CELL_CIRCS,     ARGS,    NO_OBJ ), T01("exit-stats-end",      K_EXIT_END,            ARGS,    NO_OBJ ), T01("exit-kibibytes-written", K_EXIT_WRITTEN,     ARGS,    NO_OBJ ), T01("exit-kibibytes-read", K_EXIT_READ,           ARGS,    NO_OBJ ), T01("exit-streams-opened", K_EXIT_OPENED,         ARGS,    NO_OBJ ),  T1_START( "extra-info",          K_EXTRA_INFO,          GE(2),   NO_OBJ ),  END_OF_TABLE };


































static token_rule_t rtrstatus_token_table[] = {
  T01("p",                   K_P,               CONCAT_ARGS, NO_OBJ ), T1( "r",                   K_R,                   GE(7),   NO_OBJ ), T0N("a",                   K_A,                   GE(1),   NO_OBJ ), T1( "s",                   K_S,                   ARGS,    NO_OBJ ), T01("v",                   K_V,               CONCAT_ARGS, NO_OBJ ), T01("w",                   K_W,                   ARGS,    NO_OBJ ), T0N("m",                   K_M,               CONCAT_ARGS, NO_OBJ ), T0N("opt",                 K_OPT,             CONCAT_ARGS, OBJ_OK ), END_OF_TABLE };










static token_rule_t netstatus_token_table[] = {
  T1( "published",           K_PUBLISHED,       CONCAT_ARGS, NO_OBJ ), T0N("opt",                 K_OPT,             CONCAT_ARGS, OBJ_OK ), T1( "contact",             K_CONTACT,         CONCAT_ARGS, NO_OBJ ), T1( "dir-signing-key",     K_DIR_SIGNING_KEY,  NO_ARGS,    NEED_KEY_1024 ), T1( "fingerprint",         K_FINGERPRINT,     CONCAT_ARGS, NO_OBJ ), T1_START("network-status-version", K_NETWORK_STATUS_VERSION, GE(1),   NO_OBJ ), T1( "dir-source",          K_DIR_SOURCE,          GE(3),   NO_OBJ ), T01("dir-options",         K_DIR_OPTIONS,         ARGS,    NO_OBJ ), T01("client-versions",     K_CLIENT_VERSIONS, CONCAT_ARGS, NO_OBJ ), T01("server-versions",     K_SERVER_VERSIONS, CONCAT_ARGS, NO_OBJ ),  END_OF_TABLE };














static token_rule_t dir_footer_token_table[] = {
  T1("directory-signature", K_DIRECTORY_SIGNATURE, EQ(1), NEED_OBJ ), END_OF_TABLE };















static token_rule_t dir_key_certificate_table[] = {
  CERTIFICATE_MEMBERS T1("fingerprint",      K_FINGERPRINT,              CONCAT_ARGS, NO_OBJ ), END_OF_TABLE };




static token_rule_t desc_token_table[] = {
  T1_START("rendezvous-service-descriptor", R_RENDEZVOUS_SERVICE_DESCRIPTOR, EQ(1), NO_OBJ), T1("version", R_VERSION, EQ(1), NO_OBJ), T1("permanent-key", R_PERMANENT_KEY, NO_ARGS, NEED_KEY_1024), T1("secret-id-part", R_SECRET_ID_PART, EQ(1), NO_OBJ), T1("publication-time", R_PUBLICATION_TIME, CONCAT_ARGS, NO_OBJ), T1("protocol-versions", R_PROTOCOL_VERSIONS, EQ(1), NO_OBJ), T01("introduction-points", R_INTRODUCTION_POINTS, NO_ARGS, NEED_OBJ), T1_END("signature", R_SIGNATURE, NO_ARGS, NEED_OBJ), END_OF_TABLE };











static token_rule_t ipo_token_table[] = {
  T1_START("introduction-point", R_IPO_IDENTIFIER, EQ(1), NO_OBJ), T1("ip-address", R_IPO_IP_ADDRESS, EQ(1), NO_OBJ), T1("onion-port", R_IPO_ONION_PORT, EQ(1), NO_OBJ), T1("onion-key", R_IPO_ONION_KEY, NO_ARGS, NEED_KEY_1024), T1("service-key", R_IPO_SERVICE_KEY, NO_ARGS, NEED_KEY_1024), END_OF_TABLE };







static token_rule_t client_keys_token_table[] = {
  T1_START("client-name", C_CLIENT_NAME, CONCAT_ARGS, NO_OBJ), T1("descriptor-cookie", C_DESCRIPTOR_COOKIE, EQ(1), NO_OBJ), T01("client-key", C_CLIENT_KEY, NO_ARGS, NEED_SKEY_1024), END_OF_TABLE };





static token_rule_t networkstatus_token_table[] = {
  T1_START("network-status-version", K_NETWORK_STATUS_VERSION, GE(1),       NO_OBJ ), T1("vote-status",            K_VOTE_STATUS,      GE(1),       NO_OBJ ), T1("published",              K_PUBLISHED,        CONCAT_ARGS, NO_OBJ ), T1("valid-after",            K_VALID_AFTER,      CONCAT_ARGS, NO_OBJ ), T1("fresh-until",            K_FRESH_UNTIL,      CONCAT_ARGS, NO_OBJ ), T1("valid-until",            K_VALID_UNTIL,      CONCAT_ARGS, NO_OBJ ), T1("voting-delay",           K_VOTING_DELAY,     GE(2),       NO_OBJ ), T1("known-flags",            K_KNOWN_FLAGS,      ARGS,        NO_OBJ ), T01("params",                K_PARAMS,           ARGS,        NO_OBJ ), T( "fingerprint",            K_FINGERPRINT,      CONCAT_ARGS, NO_OBJ ),  CERTIFICATE_MEMBERS  T0N("opt",                 K_OPT,             CONCAT_ARGS, OBJ_OK ), T1( "contact",             K_CONTACT,         CONCAT_ARGS, NO_OBJ ), T1( "dir-source",          K_DIR_SOURCE,      GE(6),       NO_OBJ ), T01("legacy-dir-key",      K_LEGACY_DIR_KEY,  GE(1),       NO_OBJ ), T1( "known-flags",         K_KNOWN_FLAGS,     CONCAT_ARGS, NO_OBJ ), T01("client-versions",     K_CLIENT_VERSIONS, CONCAT_ARGS, NO_OBJ ), T01("server-versions",     K_SERVER_VERSIONS, CONCAT_ARGS, NO_OBJ ), T1( "consensus-methods",   K_CONSENSUS_METHODS, GE(1),     NO_OBJ ),  END_OF_TABLE };

























static token_rule_t networkstatus_consensus_token_table[] = {
  T1_START("network-status-version", K_NETWORK_STATUS_VERSION, GE(1),       NO_OBJ ), T1("vote-status",            K_VOTE_STATUS,      GE(1),       NO_OBJ ), T1("valid-after",            K_VALID_AFTER,      CONCAT_ARGS, NO_OBJ ), T1("fresh-until",            K_FRESH_UNTIL,      CONCAT_ARGS, NO_OBJ ), T1("valid-until",            K_VALID_UNTIL,      CONCAT_ARGS, NO_OBJ ), T1("voting-delay",           K_VOTING_DELAY,     GE(2),       NO_OBJ ),  T0N("opt",                 K_OPT,             CONCAT_ARGS, OBJ_OK ),  T1N("dir-source",          K_DIR_SOURCE,          GE(6),   NO_OBJ ), T1N("contact",             K_CONTACT,         CONCAT_ARGS, NO_OBJ ), T1N("vote-digest",         K_VOTE_DIGEST,         GE(1),   NO_OBJ ),  T1( "known-flags",         K_KNOWN_FLAGS,     CONCAT_ARGS, NO_OBJ ),  T01("client-versions",     K_CLIENT_VERSIONS, CONCAT_ARGS, NO_OBJ ), T01("server-versions",     K_SERVER_VERSIONS, CONCAT_ARGS, NO_OBJ ), T01("consensus-method",    K_CONSENSUS_METHOD,    EQ(1),   NO_OBJ), T01("params",                K_PARAMS,           ARGS,        NO_OBJ ),  END_OF_TABLE };























static token_rule_t networkstatus_vote_footer_token_table[] = {
  T01("directory-footer",    K_DIRECTORY_FOOTER,    NO_ARGS,   NO_OBJ ), T01("bandwidth-weights",   K_BW_WEIGHTS,          ARGS,      NO_OBJ ), T(  "directory-signature", K_DIRECTORY_SIGNATURE, GE(2),     NEED_OBJ ), END_OF_TABLE };





static token_rule_t networkstatus_detached_signature_token_table[] = {
  T1_START("consensus-digest", K_CONSENSUS_DIGEST, GE(1),       NO_OBJ ), T("additional-digest",       K_ADDITIONAL_DIGEST,GE(3),       NO_OBJ ), T1("valid-after",            K_VALID_AFTER,      CONCAT_ARGS, NO_OBJ ), T1("fresh-until",            K_FRESH_UNTIL,      CONCAT_ARGS, NO_OBJ ), T1("valid-until",            K_VALID_UNTIL,      CONCAT_ARGS, NO_OBJ ), T("additional-signature",  K_ADDITIONAL_SIGNATURE, GE(4),   NEED_OBJ ), T1N("directory-signature", K_DIRECTORY_SIGNATURE,  GE(2),   NEED_OBJ ), END_OF_TABLE };









static token_rule_t microdesc_token_table[] = {
  T1_START("onion-key",        K_ONION_KEY,        NO_ARGS,     NEED_KEY_1024), T01("ntor-onion-key",        K_ONION_KEY_NTOR,   GE(1),       NO_OBJ ), T0N("a",                     K_A,                GE(1),       NO_OBJ ), T01("family",                K_FAMILY,           ARGS,        NO_OBJ ), T01("p",                     K_P,                CONCAT_ARGS, NO_OBJ ), T01("p6",                    K_P6,               CONCAT_ARGS, NO_OBJ ), A01("@last-listed",          A_LAST_LISTED,      CONCAT_ARGS, NO_OBJ ), END_OF_TABLE };











static int router_add_exit_policy(routerinfo_t *router,directory_token_t *tok);
static addr_policy_t *router_parse_addr_policy(directory_token_t *tok, unsigned fmt_flags);
static addr_policy_t *router_parse_addr_policy_private(directory_token_t *tok);

static int router_get_hash_impl(const char *s, size_t s_len, char *digest, const char *start_str, const char *end_str, char end_char, digest_algorithm_t alg);


static int router_get_hashes_impl(const char *s, size_t s_len, digests_t *digests, const char *start_str, const char *end_str, char end_char);


static void token_clear(directory_token_t *tok);
static smartlist_t *find_all_by_keyword(smartlist_t *s, directory_keyword k);
static smartlist_t *find_all_exitpolicy(smartlist_t *s);
static directory_token_t *find_by_keyword_(smartlist_t *s, directory_keyword keyword, const char *keyword_str);


static directory_token_t *find_opt_by_keyword(smartlist_t *s, directory_keyword keyword);




static int tokenize_string(memarea_t *area, const char *start, const char *end, smartlist_t *out, token_rule_t *table, int flags);



static directory_token_t *get_next_token(memarea_t *area, const char **s, const char *eos, token_rule_t *table);




static int check_signature_token(const char *digest, ssize_t digest_len, directory_token_t *tok, crypto_pk_t *pkey, int flags, const char *doctype);


















static time_t last_desc_dumped = 0;


static void dump_desc(const char *desc, const char *type)
{
  time_t now = time(NULL);
  tor_assert(desc);
  tor_assert(type);
  if (!last_desc_dumped || last_desc_dumped + 60 < now) {
    char *debugfile = get_datadir_fname("unparseable-desc");
    size_t filelen = 50 + strlen(type) + strlen(desc);
    char *content = tor_malloc_zero(filelen);
    tor_snprintf(content, filelen, "Unable to parse descriptor of type " "%s:\n%s", type, desc);
    write_str_to_file(debugfile, content, 0);
    log_info(LD_DIR, "Unable to parse descriptor of type %s. See file " "unparseable-desc in data directory for details.", type);
    tor_free(content);
    tor_free(debugfile);
    last_desc_dumped = now;
  }
}


int router_get_dir_hash(const char *s, char *digest)
{
  return router_get_hash_impl(s, strlen(s), digest, "signed-directory","\ndirectory-signature",'\n', DIGEST_SHA1);

}


int router_get_router_hash(const char *s, size_t s_len, char *digest)
{
  return router_get_hash_impl(s, s_len, digest, "router ","\nrouter-signature", '\n', DIGEST_SHA1);

}


int router_get_runningrouters_hash(const char *s, char *digest)
{
  return router_get_hash_impl(s, strlen(s), digest, "network-status","\ndirectory-signature", '\n', DIGEST_SHA1);

}


int router_get_networkstatus_v2_hash(const char *s, char *digest)
{
  return router_get_hash_impl(s, strlen(s), digest, "network-status-version","\ndirectory-signature", '\n', DIGEST_SHA1);


}


int router_get_networkstatus_v3_hashes(const char *s, digests_t *digests)
{
  return router_get_hashes_impl(s,strlen(s),digests, "network-status-version", "\ndirectory-signature", ' ');


}


int router_get_extrainfo_hash(const char *s, size_t s_len, char *digest)
{
  return router_get_hash_impl(s, s_len, digest, "extra-info", "\nrouter-signature",'\n', DIGEST_SHA1);
}


char * router_get_dirobj_signature(const char *digest, size_t digest_len, crypto_pk_t *private_key)


{
  char *signature;
  size_t i, keysize;
  int siglen;
  char *buf = NULL;
  size_t buf_len;
  


  keysize = crypto_pk_keysize(private_key);
  signature = tor_malloc(keysize);
  siglen = crypto_pk_private_sign(private_key, signature, keysize, digest, digest_len);
  if (siglen < 0) {
    log_warn(LD_BUG,"Couldn't sign digest.");
    goto err;
  }

  
  buf_len = (siglen * 2) + BEGIN_END_OVERHEAD_LEN;
  buf = tor_malloc(buf_len);

  if (strlcpy(buf, "-----BEGIN SIGNATURE-----\n", buf_len) >= buf_len)
    goto truncated;

  i = strlen(buf);
  if (base64_encode(buf+i, buf_len-i, signature, siglen) < 0) {
    log_warn(LD_BUG,"couldn't base64-encode signature");
    goto err;
  }

  if (strlcat(buf, "-----END SIGNATURE-----\n", buf_len) >= buf_len)
    goto truncated;

  tor_free(signature);
  return buf;

 truncated:
  log_warn(LD_BUG,"tried to exceed string length.");
 err:
  tor_free(signature);
  tor_free(buf);
  return NULL;
}


int router_append_dirobj_signature(char *buf, size_t buf_len, const char *digest, size_t digest_len, crypto_pk_t *private_key)

{
  size_t sig_len, s_len;
  char *sig = router_get_dirobj_signature(digest, digest_len, private_key);
  if (!sig) {
    log_warn(LD_BUG, "No signature generated");
    return -1;
  }
  sig_len = strlen(sig);
  s_len = strlen(buf);
  if (sig_len + s_len + 1 > buf_len) {
    log_warn(LD_BUG, "Not enough room for signature");
    tor_free(sig);
    return -1;
  }
  memcpy(buf+s_len, sig, sig_len+1);
  return 0;
}


version_status_t tor_version_is_obsolete(const char *myversion, const char *versionlist)
{
  tor_version_t mine, other;
  int found_newer = 0, found_older = 0, found_newer_in_series = 0, found_any_in_series = 0, r, same;
  version_status_t ret = VS_UNRECOMMENDED;
  smartlist_t *version_sl;

  log_debug(LD_CONFIG,"Checking whether version '%s' is in '%s'", myversion, versionlist);

  if (tor_version_parse(myversion, &mine)) {
    log_err(LD_BUG,"I couldn't parse my own version (%s)", myversion);
    tor_assert(0);
  }
  version_sl = smartlist_new();
  smartlist_split_string(version_sl, versionlist, ",", SPLIT_SKIP_SPACE, 0);

  if (!strlen(versionlist)) { 
    ret = VS_EMPTY;
    goto done;
  }

  SMARTLIST_FOREACH_BEGIN(version_sl, const char *, cp) {
    if (!strcmpstart(cp, "Tor "))
      cp += 4;

    if (tor_version_parse(cp, &other)) {
      
    } else {
      same = tor_version_same_series(&mine, &other);
      if (same)
        found_any_in_series = 1;
      r = tor_version_compare(&mine, &other);
      if (r==0) {
        ret = VS_RECOMMENDED;
        goto done;
      } else if (r<0) {
        found_newer = 1;
        if (same)
          found_newer_in_series = 1;
      } else if (r>0) {
        found_older = 1;
      }
    }
  } SMARTLIST_FOREACH_END(cp);

  
  if (found_any_in_series && !found_newer_in_series && found_newer) {
    ret = VS_NEW_IN_SERIES;
  } else if (found_newer && !found_older) {
    ret = VS_OLD;
  } else if (found_older && !found_newer) {
    ret = VS_NEW;
  } else {
    ret = VS_UNRECOMMENDED;
  }

 done:
  SMARTLIST_FOREACH(version_sl, char *, version, tor_free(version));
  smartlist_free(version_sl);
  return ret;
}


static int dir_signing_key_is_trusted(crypto_pk_t *key)
{
  char digest[DIGEST_LEN];
  if (!key) return 0;
  if (crypto_pk_get_digest(key, digest) < 0) {
    log_warn(LD_DIR, "Error computing dir-signing-key digest");
    return 0;
  }
  if (!router_digest_is_trusted_dir(digest)) {
    log_warn(LD_DIR, "Listed dir-signing-key is not trusted");
    return 0;
  }
  return 1;
}


static int check_signature_token(const char *digest, ssize_t digest_len, directory_token_t *tok, crypto_pk_t *pkey, int flags, const char *doctype)





{
  char *signed_digest;
  size_t keysize;
  const int check_authority = (flags & CST_CHECK_AUTHORITY);
  const int check_objtype = ! (flags & CST_NO_CHECK_OBJTYPE);

  tor_assert(pkey);
  tor_assert(tok);
  tor_assert(digest);
  tor_assert(doctype);

  if (check_authority && !dir_signing_key_is_trusted(pkey)) {
    log_warn(LD_DIR, "Key on %s did not come from an authority; rejecting", doctype);
    return -1;
  }

  if (check_objtype) {
    if (strcmp(tok->object_type, "SIGNATURE")) {
      log_warn(LD_DIR, "Bad object type on %s signature", doctype);
      return -1;
    }
  }

  keysize = crypto_pk_keysize(pkey);
  signed_digest = tor_malloc(keysize);
  if (crypto_pk_public_checksig(pkey, signed_digest, keysize, tok->object_body, tok->object_size)
      < digest_len) {
    log_warn(LD_DIR, "Error reading %s: invalid signature.", doctype);
    tor_free(signed_digest);
    return -1;
  }


  if (tor_memneq(digest, signed_digest, digest_len)) {
    log_warn(LD_DIR, "Error reading %s: signature does not match.", doctype);
    tor_free(signed_digest);
    return -1;
  }
  tor_free(signed_digest);
  return 0;
}


static int find_start_of_next_router_or_extrainfo(const char **s_ptr, const char *eos, int *is_extrainfo_out)


{
  const char *annotations = NULL;
  const char *s = *s_ptr;

  s = eat_whitespace_eos(s, eos);

  while (s < eos-32) {  
    
    tor_assert(*s != '\n');

    if (*s == '@' && !annotations) {
      annotations = s;
    } else if (*s == 'r' && !strcmpstart(s, "router ")) {
      *s_ptr = annotations ? annotations : s;
      *is_extrainfo_out = 0;
      return 0;
    } else if (*s == 'e' && !strcmpstart(s, "extra-info ")) {
      *s_ptr = annotations ? annotations : s;
      *is_extrainfo_out = 1;
      return 0;
    }

    if (!(s = memchr(s+1, '\n', eos-(s+1))))
      break;
    s = eat_whitespace_eos(s, eos);
  }
  return -1;
}


int router_parse_list_from_string(const char **s, const char *eos, smartlist_t *dest, saved_location_t saved_location, int want_extrainfo, int allow_annotations, const char *prepend_annotations)





{
  routerinfo_t *router;
  extrainfo_t *extrainfo;
  signed_descriptor_t *signed_desc;
  void *elt;
  const char *end, *start;
  int have_extrainfo;

  tor_assert(s);
  tor_assert(*s);
  tor_assert(dest);

  start = *s;
  if (!eos)
    eos = *s + strlen(*s);

  tor_assert(eos >= *s);

  while (1) {
    if (find_start_of_next_router_or_extrainfo(s, eos, &have_extrainfo) < 0)
      break;

    end = tor_memstr(*s, eos-*s, "\nrouter-signature");
    if (end)
      end = tor_memstr(end, eos-end, "\n-----END SIGNATURE-----\n");
    if (end)
      end += strlen("\n-----END SIGNATURE-----\n");

    if (!end)
      break;

    elt = NULL;

    if (have_extrainfo && want_extrainfo) {
      routerlist_t *rl = router_get_routerlist();
      extrainfo = extrainfo_parse_entry_from_string(*s, end, saved_location != SAVED_IN_CACHE, rl->identity_map);

      if (extrainfo) {
        signed_desc = &extrainfo->cache_info;
        elt = extrainfo;
      }
    } else if (!have_extrainfo && !want_extrainfo) {
      router = router_parse_entry_from_string(*s, end, saved_location != SAVED_IN_CACHE, allow_annotations, prepend_annotations);


      if (router) {
        log_debug(LD_DIR, "Read router '%s', purpose '%s'", router_describe(router), router_purpose_to_string(router->purpose));

        signed_desc = &router->cache_info;
        elt = router;
      }
    }
    if (!elt) {
      *s = end;
      continue;
    }
    if (saved_location != SAVED_NOWHERE) {
      signed_desc->saved_location = saved_location;
      signed_desc->saved_offset = *s - start;
    }
    *s = end;
    smartlist_add(dest, elt);
  }

  return 0;
}





static digestmap_t *verified_digests = NULL;



void dump_distinct_digest_count(int severity)
{

  if (!verified_digests)
    verified_digests = digestmap_new();
  tor_log(severity, LD_GENERAL, "%d *distinct* router digests verified", digestmap_size(verified_digests));

  (void)severity; 

}


static int find_single_ipv6_orport(const smartlist_t *list, tor_addr_t *addr_out, uint16_t *port_out)


{
  int ret = 0;
  tor_assert(list != NULL);
  tor_assert(addr_out != NULL);
  tor_assert(port_out != NULL);

  SMARTLIST_FOREACH_BEGIN(list, directory_token_t *, t) {
    tor_addr_t a;
    maskbits_t bits;
    uint16_t port_min, port_max;
    tor_assert(t->n_args >= 1);
    
    if (tor_addr_parse_mask_ports(t->args[0], 0, &a, &bits, &port_min, &port_max) == AF_INET6 && bits == 128 && port_min == port_max) {



      
      tor_addr_copy(addr_out, &a);
      *port_out = port_min;
      ret = 1;
      break;
    }
  } SMARTLIST_FOREACH_END(t);

  return ret;
}


routerinfo_t * router_parse_entry_from_string(const char *s, const char *end, int cache_copy, int allow_annotations, const char *prepend_annotations)


{
  routerinfo_t *router = NULL;
  char digest[128];
  smartlist_t *tokens = NULL, *exit_policy_tokens = NULL;
  directory_token_t *tok;
  struct in_addr in;
  const char *start_of_annotations, *cp, *s_dup = s;
  size_t prepend_len = prepend_annotations ? strlen(prepend_annotations) : 0;
  int ok = 1;
  memarea_t *area = NULL;

  tor_assert(!allow_annotations || !prepend_annotations);

  if (!end) {
    end = s + strlen(s);
  }

  
  while (end > s+2 && *(end-1) == '\n' && *(end-2) == '\n')
    --end;

  area = memarea_new();
  tokens = smartlist_new();
  if (prepend_annotations) {
    if (tokenize_string(area,prepend_annotations,NULL,tokens, routerdesc_token_table,TS_NOCHECK)) {
      log_warn(LD_DIR, "Error tokenizing router descriptor (annotations).");
      goto err;
    }
  }

  start_of_annotations = s;
  cp = tor_memstr(s, end-s, "\nrouter ");
  if (!cp) {
    if (end-s < 7 || strcmpstart(s, "router ")) {
      log_warn(LD_DIR, "No router keyword found.");
      goto err;
    }
  } else {
    s = cp+1;
  }

  if (start_of_annotations != s) { 
    if (allow_annotations) {
      if (tokenize_string(area,start_of_annotations,s,tokens, routerdesc_token_table,TS_NOCHECK)) {
        log_warn(LD_DIR, "Error tokenizing router descriptor (annotations).");
        goto err;
      }
    } else {
      log_warn(LD_DIR, "Found unexpected annotations on router descriptor not " "loaded from disk.  Dropping it.");
      goto err;
    }
  }

  if (router_get_router_hash(s, end - s, digest) < 0) {
    log_warn(LD_DIR, "Couldn't compute router hash.");
    goto err;
  }
  {
    int flags = 0;
    if (allow_annotations)
      flags |= TS_ANNOTATIONS_OK;
    if (prepend_annotations)
      flags |= TS_ANNOTATIONS_OK|TS_NO_NEW_ANNOTATIONS;

    if (tokenize_string(area,s,end,tokens,routerdesc_token_table, flags)) {
      log_warn(LD_DIR, "Error tokenizing router descriptor.");
      goto err;
    }
  }

  if (smartlist_len(tokens) < 2) {
    log_warn(LD_DIR, "Impossibly short router descriptor.");
    goto err;
  }

  tok = find_by_keyword(tokens, K_ROUTER);
  tor_assert(tok->n_args >= 5);

  router = tor_malloc_zero(sizeof(routerinfo_t));
  router->cache_info.routerlist_index = -1;
  router->cache_info.annotations_len = s-start_of_annotations + prepend_len;
  router->cache_info.signed_descriptor_len = end-s;
  if (cache_copy) {
    size_t len = router->cache_info.signed_descriptor_len + router->cache_info.annotations_len;
    char *cp = router->cache_info.signed_descriptor_body = tor_malloc(len+1);
    if (prepend_annotations) {
      memcpy(cp, prepend_annotations, prepend_len);
      cp += prepend_len;
    }
    
    tor_assert(cp+(end-start_of_annotations) == router->cache_info.signed_descriptor_body+len);
    memcpy(cp, start_of_annotations, end-start_of_annotations);
    router->cache_info.signed_descriptor_body[len] = '\0';
    tor_assert(strlen(router->cache_info.signed_descriptor_body) == len);
  }
  memcpy(router->cache_info.signed_descriptor_digest, digest, DIGEST_LEN);

  router->nickname = tor_strdup(tok->args[0]);
  if (!is_legal_nickname(router->nickname)) {
    log_warn(LD_DIR,"Router nickname is invalid");
    goto err;
  }
  router->address = tor_strdup(tok->args[1]);
  if (!tor_inet_aton(router->address, &in)) {
    log_warn(LD_DIR,"Router address is not an IP address.");
    goto err;
  }
  router->addr = ntohl(in.s_addr);

  router->or_port = (uint16_t) tor_parse_long(tok->args[2],10,0,65535,&ok,NULL);
  if (!ok) {
    log_warn(LD_DIR,"Invalid OR port %s", escaped(tok->args[2]));
    goto err;
  }
  router->dir_port = (uint16_t) tor_parse_long(tok->args[4],10,0,65535,&ok,NULL);
  if (!ok) {
    log_warn(LD_DIR,"Invalid dir port %s", escaped(tok->args[4]));
    goto err;
  }

  tok = find_by_keyword(tokens, K_BANDWIDTH);
  tor_assert(tok->n_args >= 3);
  router->bandwidthrate = (int)
    tor_parse_long(tok->args[0],10,1,INT_MAX,&ok,NULL);

  if (!ok) {
    log_warn(LD_DIR, "bandwidthrate %s unreadable or 0. Failing.", escaped(tok->args[0]));
    goto err;
  }
  router->bandwidthburst = (int) tor_parse_long(tok->args[1],10,0,INT_MAX,&ok,NULL);
  if (!ok) {
    log_warn(LD_DIR, "Invalid bandwidthburst %s", escaped(tok->args[1]));
    goto err;
  }
  router->bandwidthcapacity = (int)
    tor_parse_long(tok->args[2],10,0,INT_MAX,&ok,NULL);
  if (!ok) {
    log_warn(LD_DIR, "Invalid bandwidthcapacity %s", escaped(tok->args[1]));
    goto err;
  }

  if ((tok = find_opt_by_keyword(tokens, A_PURPOSE))) {
    tor_assert(tok->n_args);
    router->purpose = router_purpose_from_string(tok->args[0]);
  } else {
    router->purpose = ROUTER_PURPOSE_GENERAL;
  }
  router->cache_info.send_unencrypted = (router->purpose == ROUTER_PURPOSE_GENERAL) ? 1 : 0;

  if ((tok = find_opt_by_keyword(tokens, K_UPTIME))) {
    tor_assert(tok->n_args >= 1);
    router->uptime = tor_parse_long(tok->args[0],10,0,LONG_MAX,&ok,NULL);
    if (!ok) {
      log_warn(LD_DIR, "Invalid uptime %s", escaped(tok->args[0]));
      goto err;
    }
  }

  if ((tok = find_opt_by_keyword(tokens, K_HIBERNATING))) {
    tor_assert(tok->n_args >= 1);
    router->is_hibernating = (tor_parse_long(tok->args[0],10,0,LONG_MAX,NULL,NULL) != 0);
  }

  tok = find_by_keyword(tokens, K_PUBLISHED);
  tor_assert(tok->n_args == 1);
  if (parse_iso_time(tok->args[0], &router->cache_info.published_on) < 0)
    goto err;

  tok = find_by_keyword(tokens, K_ONION_KEY);
  if (!crypto_pk_public_exponent_ok(tok->key)) {
    log_warn(LD_DIR, "Relay's onion key had invalid exponent.");
    goto err;
  }
  router->onion_pkey = tok->key;
  tok->key = NULL; 

  if ((tok = find_opt_by_keyword(tokens, K_ONION_KEY_NTOR))) {
    curve25519_public_key_t k;
    tor_assert(tok->n_args >= 1);
    if (curve25519_public_from_base64(&k, tok->args[0]) < 0) {
      log_warn(LD_DIR, "Bogus ntor-onion-key in routerinfo");
      goto err;
    }
    router->onion_curve25519_pkey = tor_memdup(&k, sizeof(curve25519_public_key_t));
  }

  tok = find_by_keyword(tokens, K_SIGNING_KEY);
  router->identity_pkey = tok->key;
  tok->key = NULL; 
  if (crypto_pk_get_digest(router->identity_pkey, router->cache_info.identity_digest)) {
    log_warn(LD_DIR, "Couldn't calculate key digest"); goto err;
  }

  if ((tok = find_opt_by_keyword(tokens, K_FINGERPRINT))) {
    
    char d[DIGEST_LEN];
    tor_assert(tok->n_args == 1);
    tor_strstrip(tok->args[0], " ");
    if (base16_decode(d, DIGEST_LEN, tok->args[0], strlen(tok->args[0]))) {
      log_warn(LD_DIR, "Couldn't decode router fingerprint %s", escaped(tok->args[0]));
      goto err;
    }
    if (tor_memneq(d,router->cache_info.identity_digest, DIGEST_LEN)) {
      log_warn(LD_DIR, "Fingerprint '%s' does not match identity digest.", tok->args[0]);
      goto err;
    }
  }

  if ((tok = find_opt_by_keyword(tokens, K_PLATFORM))) {
    router->platform = tor_strdup(tok->args[0]);
  }

  if ((tok = find_opt_by_keyword(tokens, K_CONTACT))) {
    router->contact_info = tor_strdup(tok->args[0]);
  }

  if (find_opt_by_keyword(tokens, K_REJECT6) || find_opt_by_keyword(tokens, K_ACCEPT6)) {
    log_warn(LD_DIR, "Rejecting router with reject6/accept6 line: they crash " "older Tors.");
    goto err;
  }
  {
    smartlist_t *or_addresses = find_all_by_keyword(tokens, K_OR_ADDRESS);
    if (or_addresses) {
      find_single_ipv6_orport(or_addresses, &router->ipv6_addr, &router->ipv6_orport);
      smartlist_free(or_addresses);
    }
  }
  exit_policy_tokens = find_all_exitpolicy(tokens);
  if (!smartlist_len(exit_policy_tokens)) {
    log_warn(LD_DIR, "No exit policy tokens in descriptor.");
    goto err;
  }
  SMARTLIST_FOREACH(exit_policy_tokens, directory_token_t *, t, if (router_add_exit_policy(router,t)<0) {
                      log_warn(LD_DIR,"Error in exit policy");
                      goto err;
                    });
  policy_expand_private(&router->exit_policy);

  if ((tok = find_opt_by_keyword(tokens, K_IPV6_POLICY)) && tok->n_args) {
    router->ipv6_exit_policy = parse_short_policy(tok->args[0]);
    if (! router->ipv6_exit_policy) {
      log_warn(LD_DIR , "Error in ipv6-policy %s", escaped(tok->args[0]));
      goto err;
    }
  }

  if (policy_is_reject_star(router->exit_policy, AF_INET) && (!router->ipv6_exit_policy || short_policy_is_reject_star(router->ipv6_exit_policy)))

    router->policy_is_reject_star = 1;

  if ((tok = find_opt_by_keyword(tokens, K_FAMILY)) && tok->n_args) {
    int i;
    router->declared_family = smartlist_new();
    for (i=0;i<tok->n_args;++i) {
      if (!is_legal_nickname_or_hexdigest(tok->args[i])) {
        log_warn(LD_DIR, "Illegal nickname %s in family line", escaped(tok->args[i]));
        goto err;
      }
      smartlist_add(router->declared_family, tor_strdup(tok->args[i]));
    }
  }

  if (find_opt_by_keyword(tokens, K_CACHES_EXTRA_INFO))
    router->caches_extra_info = 1;

  if (find_opt_by_keyword(tokens, K_ALLOW_SINGLE_HOP_EXITS))
    router->allow_single_hop_exits = 1;

  if ((tok = find_opt_by_keyword(tokens, K_EXTRA_INFO_DIGEST))) {
    tor_assert(tok->n_args >= 1);
    if (strlen(tok->args[0]) == HEX_DIGEST_LEN) {
      base16_decode(router->cache_info.extra_info_digest, DIGEST_LEN, tok->args[0], HEX_DIGEST_LEN);
    } else {
      log_warn(LD_DIR, "Invalid extra info digest %s", escaped(tok->args[0]));
    }
  }

  if (find_opt_by_keyword(tokens, K_HIDDEN_SERVICE_DIR)) {
    router->wants_to_be_hs_dir = 1;
  }

  tok = find_by_keyword(tokens, K_ROUTER_SIGNATURE);
  note_crypto_pk_op(VERIFY_RTR);

  if (!verified_digests)
    verified_digests = digestmap_new();
  digestmap_set(verified_digests, signed_digest, (void*)(uintptr_t)1);

  if (check_signature_token(digest, DIGEST_LEN, tok, router->identity_pkey, 0, "router descriptor") < 0)
    goto err;

  if (!router->or_port) {
    log_warn(LD_DIR,"or_port unreadable or 0. Failing.");
    goto err;
  }

  if (!router->platform) {
    router->platform = tor_strdup("<unknown>");
  }

  goto done;

 err:
  dump_desc(s_dup, "router descriptor");
  routerinfo_free(router);
  router = NULL;
 done:
  if (tokens) {
    SMARTLIST_FOREACH(tokens, directory_token_t *, t, token_clear(t));
    smartlist_free(tokens);
  }
  smartlist_free(exit_policy_tokens);
  if (area) {
    DUMP_AREA(area, "routerinfo");
    memarea_drop_all(area);
  }
  return router;
}


extrainfo_t * extrainfo_parse_entry_from_string(const char *s, const char *end, int cache_copy, struct digest_ri_map_t *routermap)

{
  extrainfo_t *extrainfo = NULL;
  char digest[128];
  smartlist_t *tokens = NULL;
  directory_token_t *tok;
  crypto_pk_t *key = NULL;
  routerinfo_t *router = NULL;
  memarea_t *area = NULL;
  const char *s_dup = s;

  if (!end) {
    end = s + strlen(s);
  }

  
  while (end > s+2 && *(end-1) == '\n' && *(end-2) == '\n')
    --end;

  if (router_get_extrainfo_hash(s, end-s, digest) < 0) {
    log_warn(LD_DIR, "Couldn't compute router hash.");
    goto err;
  }
  tokens = smartlist_new();
  area = memarea_new();
  if (tokenize_string(area,s,end,tokens,extrainfo_token_table,0)) {
    log_warn(LD_DIR, "Error tokenizing extra-info document.");
    goto err;
  }

  if (smartlist_len(tokens) < 2) {
    log_warn(LD_DIR, "Impossibly short extra-info document.");
    goto err;
  }

  tok = smartlist_get(tokens,0);
  if (tok->tp != K_EXTRA_INFO) {
    log_warn(LD_DIR,"Entry does not start with \"extra-info\"");
    goto err;
  }

  extrainfo = tor_malloc_zero(sizeof(extrainfo_t));
  extrainfo->cache_info.is_extrainfo = 1;
  if (cache_copy)
    extrainfo->cache_info.signed_descriptor_body = tor_memdup_nulterm(s,end-s);
  extrainfo->cache_info.signed_descriptor_len = end-s;
  memcpy(extrainfo->cache_info.signed_descriptor_digest, digest, DIGEST_LEN);

  tor_assert(tok->n_args >= 2);
  if (!is_legal_nickname(tok->args[0])) {
    log_warn(LD_DIR,"Bad nickname %s on \"extra-info\"",escaped(tok->args[0]));
    goto err;
  }
  strlcpy(extrainfo->nickname, tok->args[0], sizeof(extrainfo->nickname));
  if (strlen(tok->args[1]) != HEX_DIGEST_LEN || base16_decode(extrainfo->cache_info.identity_digest, DIGEST_LEN, tok->args[1], HEX_DIGEST_LEN)) {

    log_warn(LD_DIR,"Invalid fingerprint %s on \"extra-info\"", escaped(tok->args[1]));
    goto err;
  }

  tok = find_by_keyword(tokens, K_PUBLISHED);
  if (parse_iso_time(tok->args[0], &extrainfo->cache_info.published_on)) {
    log_warn(LD_DIR,"Invalid published time %s on \"extra-info\"", escaped(tok->args[0]));
    goto err;
  }

  if (routermap && (router = digestmap_get((digestmap_t*)routermap, extrainfo->cache_info.identity_digest))) {

    key = router->identity_pkey;
  }

  tok = find_by_keyword(tokens, K_ROUTER_SIGNATURE);
  if (strcmp(tok->object_type, "SIGNATURE") || tok->object_size < 128 || tok->object_size > 512) {
    log_warn(LD_DIR, "Bad object type or length on extra-info signature");
    goto err;
  }

  if (key) {
    note_crypto_pk_op(VERIFY_RTR);
    if (check_signature_token(digest, DIGEST_LEN, tok, key, 0, "extra-info") < 0)
      goto err;

    if (router)
      extrainfo->cache_info.send_unencrypted = router->cache_info.send_unencrypted;
  } else {
    extrainfo->pending_sig = tor_memdup(tok->object_body, tok->object_size);
    extrainfo->pending_sig_len = tok->object_size;
  }

  goto done;
 err:
  dump_desc(s_dup, "extra-info descriptor");
  extrainfo_free(extrainfo);
  extrainfo = NULL;
 done:
  if (tokens) {
    SMARTLIST_FOREACH(tokens, directory_token_t *, t, token_clear(t));
    smartlist_free(tokens);
  }
  if (area) {
    DUMP_AREA(area, "extrainfo");
    memarea_drop_all(area);
  }
  return extrainfo;
}


authority_cert_t * authority_cert_parse_from_string(const char *s, const char **end_of_string)
{
  


  authority_cert_t *cert = NULL, *old_cert;
  smartlist_t *tokens = NULL;
  char digest[DIGEST_LEN];
  directory_token_t *tok;
  char fp_declared[DIGEST_LEN];
  char *eos;
  size_t len;
  int found;
  memarea_t *area = NULL;
  const char *s_dup = s;

  s = eat_whitespace(s);
  eos = strstr(s, "\ndir-key-certification");
  if (! eos) {
    log_warn(LD_DIR, "No signature found on key certificate");
    return NULL;
  }
  eos = strstr(eos, "\n-----END SIGNATURE-----\n");
  if (! eos) {
    log_warn(LD_DIR, "No end-of-signature found on key certificate");
    return NULL;
  }
  eos = strchr(eos+2, '\n');
  tor_assert(eos);
  ++eos;
  len = eos - s;

  if (len > MAX_CERT_SIZE) {
    log_warn(LD_DIR, "Certificate is far too big (at %lu bytes long); " "rejecting", (unsigned long)len);
    return NULL;
  }

  tokens = smartlist_new();
  area = memarea_new();
  if (tokenize_string(area,s, eos, tokens, dir_key_certificate_table, 0) < 0) {
    log_warn(LD_DIR, "Error tokenizing key certificate");
    goto err;
  }
  if (router_get_hash_impl(s, strlen(s), digest, "dir-key-certificate-version", "\ndir-key-certification", '\n', DIGEST_SHA1) < 0)
    goto err;
  tok = smartlist_get(tokens, 0);
  if (tok->tp != K_DIR_KEY_CERTIFICATE_VERSION || strcmp(tok->args[0], "3")) {
    log_warn(LD_DIR, "Key certificate does not begin with a recognized version (3).");
    goto err;
  }

  cert = tor_malloc_zero(sizeof(authority_cert_t));
  memcpy(cert->cache_info.signed_descriptor_digest, digest, DIGEST_LEN);

  tok = find_by_keyword(tokens, K_DIR_SIGNING_KEY);
  tor_assert(tok->key);
  cert->signing_key = tok->key;
  tok->key = NULL;
  if (crypto_pk_get_digest(cert->signing_key, cert->signing_key_digest))
    goto err;

  tok = find_by_keyword(tokens, K_DIR_IDENTITY_KEY);
  tor_assert(tok->key);
  cert->identity_key = tok->key;
  tok->key = NULL;

  tok = find_by_keyword(tokens, K_FINGERPRINT);
  tor_assert(tok->n_args);
  if (base16_decode(fp_declared, DIGEST_LEN, tok->args[0], strlen(tok->args[0]))) {
    log_warn(LD_DIR, "Couldn't decode key certificate fingerprint %s", escaped(tok->args[0]));
    goto err;
  }

  if (crypto_pk_get_digest(cert->identity_key, cert->cache_info.identity_digest))
    goto err;

  if (tor_memneq(cert->cache_info.identity_digest, fp_declared, DIGEST_LEN)) {
    log_warn(LD_DIR, "Digest of certificate key didn't match declared " "fingerprint");
    goto err;
  }

  tok = find_opt_by_keyword(tokens, K_DIR_ADDRESS);
  if (tok) {
    struct in_addr in;
    char *address = NULL;
    tor_assert(tok->n_args);
    
    if (tor_addr_port_split(LOG_WARN, tok->args[0], &address, &cert->dir_port) < 0 || tor_inet_aton(address, &in) == 0) {

      log_warn(LD_DIR, "Couldn't parse dir-address in certificate");
      tor_free(address);
      goto err;
    }
    cert->addr = ntohl(in.s_addr);
    tor_free(address);
  }

  tok = find_by_keyword(tokens, K_DIR_KEY_PUBLISHED);
  if (parse_iso_time(tok->args[0], &cert->cache_info.published_on) < 0) {
     goto err;
  }
  tok = find_by_keyword(tokens, K_DIR_KEY_EXPIRES);
  if (parse_iso_time(tok->args[0], &cert->expires) < 0) {
     goto err;
  }

  tok = smartlist_get(tokens, smartlist_len(tokens)-1);
  if (tok->tp != K_DIR_KEY_CERTIFICATION) {
    log_warn(LD_DIR, "Certificate didn't end with dir-key-certification.");
    goto err;
  }

  
  old_cert = authority_cert_get_by_digests( cert->cache_info.identity_digest, cert->signing_key_digest);

  found = 0;
  if (old_cert) {
    
    if (old_cert->cache_info.signed_descriptor_len == len && old_cert->cache_info.signed_descriptor_body && tor_memeq(s, old_cert->cache_info.signed_descriptor_body, len)) {

      log_debug(LD_DIR, "We already checked the signature on this " "certificate; no need to do so again.");
      found = 1;
      cert->is_cross_certified = old_cert->is_cross_certified;
    }
  }
  if (!found) {
    if (check_signature_token(digest, DIGEST_LEN, tok, cert->identity_key, 0, "key certificate")) {
      goto err;
    }

    if ((tok = find_opt_by_keyword(tokens, K_DIR_KEY_CROSSCERT))) {
      
      if (check_signature_token(cert->cache_info.identity_digest, DIGEST_LEN, tok, cert->signing_key, CST_NO_CHECK_OBJTYPE, "key cross-certification")) {




        goto err;
      }
      cert->is_cross_certified = 1;
    }
  }

  cert->cache_info.signed_descriptor_len = len;
  cert->cache_info.signed_descriptor_body = tor_malloc(len+1);
  memcpy(cert->cache_info.signed_descriptor_body, s, len);
  cert->cache_info.signed_descriptor_body[len] = 0;
  cert->cache_info.saved_location = SAVED_NOWHERE;

  if (end_of_string) {
    *end_of_string = eat_whitespace(eos);
  }
  SMARTLIST_FOREACH(tokens, directory_token_t *, t, token_clear(t));
  smartlist_free(tokens);
  if (area) {
    DUMP_AREA(area, "authority cert");
    memarea_drop_all(area);
  }
  return cert;
 err:
  dump_desc(s_dup, "authority cert");
  authority_cert_free(cert);
  SMARTLIST_FOREACH(tokens, directory_token_t *, t, token_clear(t));
  smartlist_free(tokens);
  if (area) {
    DUMP_AREA(area, "authority cert");
    memarea_drop_all(area);
  }
  return NULL;
}


static INLINE const char * find_start_of_next_routerstatus(const char *s)
{
  const char *eos, *footer, *sig;
  if ((eos = strstr(s, "\nr ")))
    ++eos;
  else eos = s + strlen(s);

  footer = tor_memstr(s, eos-s, "\ndirectory-footer");
  sig = tor_memstr(s, eos-s, "\ndirectory-signature");

  if (footer && sig)
    return MIN(footer, sig) + 1;
  else if (footer)
    return footer+1;
  else if (sig)
    return sig+1;
  else return eos;
}


static routerstatus_t * routerstatus_parse_entry_from_string(memarea_t *area, const char **s, smartlist_t *tokens, networkstatus_t *vote, vote_routerstatus_t *vote_rs, int consensus_method, consensus_flavor_t flav)





{
  const char *eos, *s_dup = *s;
  routerstatus_t *rs = NULL;
  directory_token_t *tok;
  char timebuf[ISO_TIME_LEN+1];
  struct in_addr in;
  int offset = 0;
  tor_assert(tokens);
  tor_assert(bool_eq(vote, vote_rs));

  if (!consensus_method)
    flav = FLAV_NS;
  tor_assert(flav == FLAV_NS || flav == FLAV_MICRODESC);

  eos = find_start_of_next_routerstatus(*s);

  if (tokenize_string(area,*s, eos, tokens, rtrstatus_token_table,0)) {
    log_warn(LD_DIR, "Error tokenizing router status");
    goto err;
  }
  if (smartlist_len(tokens) < 1) {
    log_warn(LD_DIR, "Impossibly short router status");
    goto err;
  }
  tok = find_by_keyword(tokens, K_R);
  tor_assert(tok->n_args >= 7); 
  if (flav == FLAV_NS) {
    if (tok->n_args < 8) {
      log_warn(LD_DIR, "Too few arguments to r");
      goto err;
    }
  } else if (flav == FLAV_MICRODESC) {
    offset = -1; 
  }

  if (vote_rs) {
    rs = &vote_rs->status;
  } else {
    rs = tor_malloc_zero(sizeof(routerstatus_t));
  }

  if (!is_legal_nickname(tok->args[0])) {
    log_warn(LD_DIR, "Invalid nickname %s in router status; skipping.", escaped(tok->args[0]));

    goto err;
  }
  strlcpy(rs->nickname, tok->args[0], sizeof(rs->nickname));

  if (digest_from_base64(rs->identity_digest, tok->args[1])) {
    log_warn(LD_DIR, "Error decoding identity digest %s", escaped(tok->args[1]));
    goto err;
  }

  if (flav == FLAV_NS) {
    if (digest_from_base64(rs->descriptor_digest, tok->args[2])) {
      log_warn(LD_DIR, "Error decoding descriptor digest %s", escaped(tok->args[2]));
      goto err;
    }
  }

  if (tor_snprintf(timebuf, sizeof(timebuf), "%s %s", tok->args[3+offset], tok->args[4+offset]) < 0 || parse_iso_time(timebuf, &rs->published_on)<0) {

    log_warn(LD_DIR, "Error parsing time '%s %s' [%d %d]", tok->args[3+offset], tok->args[4+offset], offset, (int)flav);

    goto err;
  }

  if (tor_inet_aton(tok->args[5+offset], &in) == 0) {
    log_warn(LD_DIR, "Error parsing router address in network-status %s", escaped(tok->args[5+offset]));
    goto err;
  }
  rs->addr = ntohl(in.s_addr);

  rs->or_port = (uint16_t) tor_parse_long(tok->args[6+offset], 10,0,65535,NULL,NULL);
  rs->dir_port = (uint16_t) tor_parse_long(tok->args[7+offset], 10,0,65535,NULL,NULL);

  {
    smartlist_t *a_lines = find_all_by_keyword(tokens, K_A);
    if (a_lines) {
      find_single_ipv6_orport(a_lines, &rs->ipv6_addr, &rs->ipv6_orport);
      smartlist_free(a_lines);
    }
  }

  tok = find_opt_by_keyword(tokens, K_S);
  if (tok && vote) {
    int i;
    vote_rs->flags = 0;
    for (i=0; i < tok->n_args; ++i) {
      int p = smartlist_string_pos(vote->known_flags, tok->args[i]);
      if (p >= 0) {
        vote_rs->flags |= (U64_LITERAL(1)<<p);
      } else {
        log_warn(LD_DIR, "Flags line had a flag %s not listed in known_flags.", escaped(tok->args[i]));
        goto err;
      }
    }
  } else if (tok) {
    int i;
    for (i=0; i < tok->n_args; ++i) {
      if (!strcmp(tok->args[i], "Exit"))
        rs->is_exit = 1;
      else if (!strcmp(tok->args[i], "Stable"))
        rs->is_stable = 1;
      else if (!strcmp(tok->args[i], "Fast"))
        rs->is_fast = 1;
      else if (!strcmp(tok->args[i], "Running"))
        rs->is_flagged_running = 1;
      else if (!strcmp(tok->args[i], "Named"))
        rs->is_named = 1;
      else if (!strcmp(tok->args[i], "Valid"))
        rs->is_valid = 1;
      else if (!strcmp(tok->args[i], "V2Dir"))
        rs->is_v2_dir = 1;
      else if (!strcmp(tok->args[i], "Guard"))
        rs->is_possible_guard = 1;
      else if (!strcmp(tok->args[i], "BadExit"))
        rs->is_bad_exit = 1;
      else if (!strcmp(tok->args[i], "BadDirectory"))
        rs->is_bad_directory = 1;
      else if (!strcmp(tok->args[i], "Authority"))
        rs->is_authority = 1;
      else if (!strcmp(tok->args[i], "Unnamed") && consensus_method >= 2) {
        
        rs->is_unnamed = 1;
      } else if (!strcmp(tok->args[i], "HSDir")) {
        rs->is_hs_dir = 1;
      }
    }
  }
  if ((tok = find_opt_by_keyword(tokens, K_V))) {
    tor_assert(tok->n_args == 1);
    rs->version_known = 1;
    if (strcmpstart(tok->args[0], "Tor ")) {
      rs->version_supports_microdesc_cache = 1;
      rs->version_supports_optimistic_data = 1;
    } else {
      rs->version_supports_microdesc_cache = tor_version_supports_microdescriptors(tok->args[0]);
      rs->version_supports_optimistic_data = tor_version_as_new_as(tok->args[0], "0.2.3.1-alpha");
      rs->version_supports_extend2_cells = tor_version_as_new_as(tok->args[0], "0.2.4.8-alpha");
    }
    if (vote_rs) {
      vote_rs->version = tor_strdup(tok->args[0]);
    }
  }

  
  if ((tok = find_opt_by_keyword(tokens, K_W))) {
    int i;
    for (i=0; i < tok->n_args; ++i) {
      if (!strcmpstart(tok->args[i], "Bandwidth=")) {
        int ok;
        rs->bandwidth_kb = (uint32_t)tor_parse_ulong(strchr(tok->args[i], '=')+1, 10, 0, UINT32_MAX, &ok, NULL);


        if (!ok) {
          log_warn(LD_DIR, "Invalid Bandwidth %s", escaped(tok->args[i]));
          goto err;
        }
        rs->has_bandwidth = 1;
      } else if (!strcmpstart(tok->args[i], "Measured=") && vote_rs) {
        int ok;
        vote_rs->measured_bw_kb = (uint32_t)tor_parse_ulong(strchr(tok->args[i], '=')+1, 10, 0, UINT32_MAX, &ok, NULL);

        if (!ok) {
          log_warn(LD_DIR, "Invalid Measured Bandwidth %s", escaped(tok->args[i]));
          goto err;
        }
        vote_rs->has_measured_bw = 1;
        vote->has_measured_bws = 1;
      } else if (!strcmpstart(tok->args[i], "Unmeasured=1")) {
        rs->bw_is_unmeasured = 1;
      }
    }
  }

  
  if ((tok = find_opt_by_keyword(tokens, K_P))) {
    tor_assert(tok->n_args == 1);
    if (strcmpstart(tok->args[0], "accept ") && strcmpstart(tok->args[0], "reject ")) {
      log_warn(LD_DIR, "Unknown exit policy summary type %s.", escaped(tok->args[0]));
      goto err;
    }
    
    rs->exitsummary = tor_strdup(tok->args[0]);
    rs->has_exitsummary = 1;
  }

  if (vote_rs) {
    SMARTLIST_FOREACH_BEGIN(tokens, directory_token_t *, t) {
      if (t->tp == K_M && t->n_args) {
        vote_microdesc_hash_t *line = tor_malloc(sizeof(vote_microdesc_hash_t));
        line->next = vote_rs->microdesc;
        line->microdesc_hash_line = tor_strdup(t->args[0]);
        vote_rs->microdesc = line;
      }
    } SMARTLIST_FOREACH_END(t);
  } else if (flav == FLAV_MICRODESC) {
    tok = find_opt_by_keyword(tokens, K_M);
    if (tok) {
      tor_assert(tok->n_args);
      if (digest256_from_base64(rs->descriptor_digest, tok->args[0])) {
        log_warn(LD_DIR, "Error decoding microdescriptor digest %s", escaped(tok->args[0]));
        goto err;
      }
    } else {
      log_info(LD_BUG, "Found an entry in networkstatus with no " "microdescriptor digest. (Router %s ($%s) at %s:%d.)", rs->nickname, hex_str(rs->identity_digest, DIGEST_LEN), fmt_addr32(rs->addr), rs->or_port);


    }
  }

  if (!strcasecmp(rs->nickname, UNNAMED_ROUTER_NICKNAME))
    rs->is_named = 0;

  goto done;
 err:
  dump_desc(s_dup, "routerstatus entry");
  if (rs && !vote_rs)
    routerstatus_free(rs);
  rs = NULL;
 done:
  SMARTLIST_FOREACH(tokens, directory_token_t *, t, token_clear(t));
  smartlist_clear(tokens);
  if (area) {
    DUMP_AREA(area, "routerstatus entry");
    memarea_clear(area);
  }
  *s = eos;

  return rs;
}


int compare_routerstatus_entries(const void **_a, const void **_b)
{
  const routerstatus_t *a = *_a, *b = *_b;
  return fast_memcmp(a->identity_digest, b->identity_digest, DIGEST_LEN);
}

int compare_vote_routerstatus_entries(const void **_a, const void **_b)
{
  const vote_routerstatus_t *a = *_a, *b = *_b;
  return fast_memcmp(a->status.identity_digest, b->status.identity_digest, DIGEST_LEN);
}


static void free_duplicate_routerstatus_entry_(void *e)
{
  log_warn(LD_DIR, "Network-status has two entries for the same router. " "Dropping one.");

  routerstatus_free(e);
}


networkstatus_v2_t * networkstatus_v2_parse_from_string(const char *s)
{
  const char *eos, *s_dup = s;
  smartlist_t *tokens = smartlist_new();
  smartlist_t *footer_tokens = smartlist_new();
  networkstatus_v2_t *ns = NULL;
  char ns_digest[DIGEST_LEN];
  char tmp_digest[DIGEST_LEN];
  struct in_addr in;
  directory_token_t *tok;
  int i;
  memarea_t *area = NULL;

  if (router_get_networkstatus_v2_hash(s, ns_digest)) {
    log_warn(LD_DIR, "Unable to compute digest of network-status");
    goto err;
  }

  area = memarea_new();
  eos = find_start_of_next_routerstatus(s);
  if (tokenize_string(area, s, eos, tokens, netstatus_token_table,0)) {
    log_warn(LD_DIR, "Error tokenizing network-status header.");
    goto err;
  }
  ns = tor_malloc_zero(sizeof(networkstatus_v2_t));
  memcpy(ns->networkstatus_digest, ns_digest, DIGEST_LEN);

  tok = find_by_keyword(tokens, K_NETWORK_STATUS_VERSION);
  tor_assert(tok->n_args >= 1);
  if (strcmp(tok->args[0], "2")) {
    log_warn(LD_BUG, "Got a non-v2 networkstatus. Version was " "%s", escaped(tok->args[0]));
    goto err;
  }

  tok = find_by_keyword(tokens, K_DIR_SOURCE);
  tor_assert(tok->n_args >= 3);
  ns->source_address = tor_strdup(tok->args[0]);
  if (tor_inet_aton(tok->args[1], &in) == 0) {
    log_warn(LD_DIR, "Error parsing network-status source address %s", escaped(tok->args[1]));
    goto err;
  }
  ns->source_addr = ntohl(in.s_addr);
  ns->source_dirport = (uint16_t) tor_parse_long(tok->args[2],10,0,65535,NULL,NULL);
  if (ns->source_dirport == 0) {
    log_warn(LD_DIR, "Directory source without dirport; skipping.");
    goto err;
  }

  tok = find_by_keyword(tokens, K_FINGERPRINT);
  tor_assert(tok->n_args);
  if (base16_decode(ns->identity_digest, DIGEST_LEN, tok->args[0], strlen(tok->args[0]))) {
    log_warn(LD_DIR, "Couldn't decode networkstatus fingerprint %s", escaped(tok->args[0]));
    goto err;
  }

  if ((tok = find_opt_by_keyword(tokens, K_CONTACT))) {
    tor_assert(tok->n_args);
    ns->contact = tor_strdup(tok->args[0]);
  }

  tok = find_by_keyword(tokens, K_DIR_SIGNING_KEY);
  tor_assert(tok->key);
  ns->signing_key = tok->key;
  tok->key = NULL;

  if (crypto_pk_get_digest(ns->signing_key, tmp_digest)<0) {
    log_warn(LD_DIR, "Couldn't compute signing key digest");
    goto err;
  }
  if (tor_memneq(tmp_digest, ns->identity_digest, DIGEST_LEN)) {
    log_warn(LD_DIR, "network-status fingerprint did not match dir-signing-key");
    goto err;
  }

  if ((tok = find_opt_by_keyword(tokens, K_DIR_OPTIONS))) {
    for (i=0; i < tok->n_args; ++i) {
      if (!strcmp(tok->args[i], "Names"))
        ns->binds_names = 1;
      if (!strcmp(tok->args[i], "Versions"))
        ns->recommends_versions = 1;
      if (!strcmp(tok->args[i], "BadExits"))
        ns->lists_bad_exits = 1;
      if (!strcmp(tok->args[i], "BadDirectories"))
        ns->lists_bad_directories = 1;
    }
  }

  if (ns->recommends_versions) {
    if (!(tok = find_opt_by_keyword(tokens, K_CLIENT_VERSIONS))) {
      log_warn(LD_DIR, "Missing client-versions on versioning directory");
      goto err;
    }
    ns->client_versions = tor_strdup(tok->args[0]);

    if (!(tok = find_opt_by_keyword(tokens, K_SERVER_VERSIONS)) || tok->n_args<1) {
      log_warn(LD_DIR, "Missing server-versions on versioning directory");
      goto err;
    }
    ns->server_versions = tor_strdup(tok->args[0]);
  }

  tok = find_by_keyword(tokens, K_PUBLISHED);
  tor_assert(tok->n_args == 1);
  if (parse_iso_time(tok->args[0], &ns->published_on) < 0) {
     goto err;
  }

  ns->entries = smartlist_new();
  s = eos;
  SMARTLIST_FOREACH(tokens, directory_token_t *, t, token_clear(t));
  smartlist_clear(tokens);
  memarea_clear(area);
  while (!strcmpstart(s, "r ")) {
    routerstatus_t *rs;
    if ((rs = routerstatus_parse_entry_from_string(area, &s, tokens, NULL, NULL, 0, 0)))
      smartlist_add(ns->entries, rs);
  }
  smartlist_sort(ns->entries, compare_routerstatus_entries);
  smartlist_uniq(ns->entries, compare_routerstatus_entries, free_duplicate_routerstatus_entry_);

  if (tokenize_string(area,s, NULL, footer_tokens, dir_footer_token_table,0)) {
    log_warn(LD_DIR, "Error tokenizing network-status footer.");
    goto err;
  }
  if (smartlist_len(footer_tokens) < 1) {
    log_warn(LD_DIR, "Too few items in network-status footer.");
    goto err;
  }
  tok = smartlist_get(footer_tokens, smartlist_len(footer_tokens)-1);
  if (tok->tp != K_DIRECTORY_SIGNATURE) {
    log_warn(LD_DIR, "Expected network-status footer to end with a signature.");
    goto err;
  }

  note_crypto_pk_op(VERIFY_DIR);
  if (check_signature_token(ns_digest, DIGEST_LEN, tok, ns->signing_key, 0, "network-status") < 0)
    goto err;

  goto done;
 err:
  dump_desc(s_dup, "v2 networkstatus");
  networkstatus_v2_free(ns);
  ns = NULL;
 done:
  SMARTLIST_FOREACH(tokens, directory_token_t *, t, token_clear(t));
  smartlist_free(tokens);
  SMARTLIST_FOREACH(footer_tokens, directory_token_t *, t, token_clear(t));
  smartlist_free(footer_tokens);
  if (area) {
    DUMP_AREA(area, "v2 networkstatus");
    memarea_drop_all(area);
  }
  return ns;
}


int networkstatus_verify_bw_weights(networkstatus_t *ns, int consensus_method)
{
  int64_t weight_scale;
  int64_t G=0, M=0, E=0, D=0, T=0;
  double Wgg, Wgm, Wgd, Wmg, Wmm, Wme, Wmd, Weg, Wem, Wee, Wed;
  double Gtotal=0, Mtotal=0, Etotal=0;
  const char *casename = NULL;
  int valid = 1;

  weight_scale = networkstatus_get_weight_scale_param(ns);
  Wgg = networkstatus_get_bw_weight(ns, "Wgg", -1);
  Wgm = networkstatus_get_bw_weight(ns, "Wgm", -1);
  Wgd = networkstatus_get_bw_weight(ns, "Wgd", -1);
  Wmg = networkstatus_get_bw_weight(ns, "Wmg", -1);
  Wmm = networkstatus_get_bw_weight(ns, "Wmm", -1);
  Wme = networkstatus_get_bw_weight(ns, "Wme", -1);
  Wmd = networkstatus_get_bw_weight(ns, "Wmd", -1);
  Weg = networkstatus_get_bw_weight(ns, "Weg", -1);
  Wem = networkstatus_get_bw_weight(ns, "Wem", -1);
  Wee = networkstatus_get_bw_weight(ns, "Wee", -1);
  Wed = networkstatus_get_bw_weight(ns, "Wed", -1);

  if (Wgg<0 || Wgm<0 || Wgd<0 || Wmg<0 || Wmm<0 || Wme<0 || Wmd<0 || Weg<0 || Wem<0 || Wee<0 || Wed<0) {
    log_warn(LD_BUG, "No bandwidth weights produced in consensus!");
    return 0;
  }

  
  
  
  if (fabs(Wmm - weight_scale) > 1) {
    log_warn(LD_BUG, "Wmm=%f != "I64_FORMAT, Wmm, I64_PRINTF_ARG(weight_scale));
    valid = 0;
  }

  if (fabs(Wem - Wee) > 1) {
    log_warn(LD_BUG, "Wem=%f != Wee=%f", Wem, Wee);
    valid = 0;
  }

  if (fabs(Wgm - Wgg) > 1) {
    log_warn(LD_BUG, "Wgm=%f != Wgg=%f", Wgm, Wgg);
    valid = 0;
  }

  if (fabs(Weg - Wed) > 1) {
    log_warn(LD_BUG, "Wed=%f != Weg=%f", Wed, Weg);
    valid = 0;
  }

  if (fabs(Wgg + Wmg - weight_scale) > 0.001*weight_scale) {
    log_warn(LD_BUG, "Wgg=%f != "I64_FORMAT" - Wmg=%f", Wgg, I64_PRINTF_ARG(weight_scale), Wmg);
    valid = 0;
  }

  if (fabs(Wee + Wme - weight_scale) > 0.001*weight_scale) {
    log_warn(LD_BUG, "Wee=%f != "I64_FORMAT" - Wme=%f", Wee, I64_PRINTF_ARG(weight_scale), Wme);
    valid = 0;
  }

  if (fabs(Wgd + Wmd + Wed - weight_scale) > 0.001*weight_scale) {
    log_warn(LD_BUG, "Wgd=%f + Wmd=%f + Wed=%f != "I64_FORMAT, Wgd, Wmd, Wed, I64_PRINTF_ARG(weight_scale));
    valid = 0;
  }

  Wgg /= weight_scale;
  Wgm /= weight_scale;
  Wgd /= weight_scale;

  Wmg /= weight_scale;
  Wmm /= weight_scale;
  Wme /= weight_scale;
  Wmd /= weight_scale;

  Weg /= weight_scale;
  Wem /= weight_scale;
  Wee /= weight_scale;
  Wed /= weight_scale;

  
  SMARTLIST_FOREACH_BEGIN(ns->routerstatus_list, routerstatus_t *, rs) {
    int is_exit = 0;
    if (consensus_method >= MIN_METHOD_TO_CUT_BADEXIT_WEIGHT) {
      
      is_exit = rs->is_exit && !rs->is_bad_exit;
    } else {
      is_exit = rs->is_exit;
    }
    if (rs->has_bandwidth) {
      T += rs->bandwidth_kb;
      if (is_exit && rs->is_possible_guard) {
        D += rs->bandwidth_kb;
        Gtotal += Wgd*rs->bandwidth_kb;
        Mtotal += Wmd*rs->bandwidth_kb;
        Etotal += Wed*rs->bandwidth_kb;
      } else if (is_exit) {
        E += rs->bandwidth_kb;
        Mtotal += Wme*rs->bandwidth_kb;
        Etotal += Wee*rs->bandwidth_kb;
      } else if (rs->is_possible_guard) {
        G += rs->bandwidth_kb;
        Gtotal += Wgg*rs->bandwidth_kb;
        Mtotal += Wmg*rs->bandwidth_kb;
      } else {
        M += rs->bandwidth_kb;
        Mtotal += Wmm*rs->bandwidth_kb;
      }
    } else {
      log_warn(LD_BUG, "Missing consensus bandwidth for router %s", routerstatus_describe(rs));
    }
  } SMARTLIST_FOREACH_END(rs);

  
  
  
  
  if (3*E >= T && 3*G >= T) {
    
    casename = "Case 1";
    if (fabs(Etotal-Mtotal) > 0.01*MAX(Etotal,Mtotal)) {
      log_warn(LD_DIR, "Bw Weight Failure for %s: Etotal %f != Mtotal %f. " "G="I64_FORMAT" M="I64_FORMAT" E="I64_FORMAT" D="I64_FORMAT " T="I64_FORMAT". " "Wgg=%f Wgd=%f Wmg=%f Wme=%f Wmd=%f Wee=%f Wed=%f", casename, Etotal, Mtotal, I64_PRINTF_ARG(G), I64_PRINTF_ARG(M), I64_PRINTF_ARG(E), I64_PRINTF_ARG(D), I64_PRINTF_ARG(T), Wgg, Wgd, Wmg, Wme, Wmd, Wee, Wed);







      valid = 0;
    }
    if (fabs(Etotal-Gtotal) > 0.01*MAX(Etotal,Gtotal)) {
      log_warn(LD_DIR, "Bw Weight Failure for %s: Etotal %f != Gtotal %f. " "G="I64_FORMAT" M="I64_FORMAT" E="I64_FORMAT" D="I64_FORMAT " T="I64_FORMAT". " "Wgg=%f Wgd=%f Wmg=%f Wme=%f Wmd=%f Wee=%f Wed=%f", casename, Etotal, Gtotal, I64_PRINTF_ARG(G), I64_PRINTF_ARG(M), I64_PRINTF_ARG(E), I64_PRINTF_ARG(D), I64_PRINTF_ARG(T), Wgg, Wgd, Wmg, Wme, Wmd, Wee, Wed);







      valid = 0;
    }
    if (fabs(Gtotal-Mtotal) > 0.01*MAX(Gtotal,Mtotal)) {
      log_warn(LD_DIR, "Bw Weight Failure for %s: Mtotal %f != Gtotal %f. " "G="I64_FORMAT" M="I64_FORMAT" E="I64_FORMAT" D="I64_FORMAT " T="I64_FORMAT". " "Wgg=%f Wgd=%f Wmg=%f Wme=%f Wmd=%f Wee=%f Wed=%f", casename, Mtotal, Gtotal, I64_PRINTF_ARG(G), I64_PRINTF_ARG(M), I64_PRINTF_ARG(E), I64_PRINTF_ARG(D), I64_PRINTF_ARG(T), Wgg, Wgd, Wmg, Wme, Wmd, Wee, Wed);







      valid = 0;
    }
  } else if (3*E < T && 3*G < T) {
    int64_t R = MIN(E, G);
    int64_t S = MAX(E, G);
    
    if (R+D < S) { 
      double Rtotal, Stotal;
      if (E < G) {
        Rtotal = Etotal;
        Stotal = Gtotal;
      } else {
        Rtotal = Gtotal;
        Stotal = Etotal;
      }
      casename = "Case 2a";
      
      if (Rtotal > Stotal) {
        log_warn(LD_DIR, "Bw Weight Failure for %s: Rtotal %f > Stotal %f. " "G="I64_FORMAT" M="I64_FORMAT" E="I64_FORMAT" D="I64_FORMAT " T="I64_FORMAT". " "Wgg=%f Wgd=%f Wmg=%f Wme=%f Wmd=%f Wee=%f Wed=%f", casename, Rtotal, Stotal, I64_PRINTF_ARG(G), I64_PRINTF_ARG(M), I64_PRINTF_ARG(E), I64_PRINTF_ARG(D), I64_PRINTF_ARG(T), Wgg, Wgd, Wmg, Wme, Wmd, Wee, Wed);







        valid = 0;
      }
      
      if (3*Rtotal > T) {
        log_warn(LD_DIR, "Bw Weight Failure for %s: 3*Rtotal %f > T " I64_FORMAT". G="I64_FORMAT" M="I64_FORMAT" E="I64_FORMAT " D="I64_FORMAT" T="I64_FORMAT". " "Wgg=%f Wgd=%f Wmg=%f Wme=%f Wmd=%f Wee=%f Wed=%f", casename, Rtotal*3, I64_PRINTF_ARG(T), I64_PRINTF_ARG(G), I64_PRINTF_ARG(M), I64_PRINTF_ARG(E), I64_PRINTF_ARG(D), I64_PRINTF_ARG(T), Wgg, Wgd, Wmg, Wme, Wmd, Wee, Wed);







        valid = 0;
      }
      
      if (3*Stotal > T) {
        log_warn(LD_DIR, "Bw Weight Failure for %s: 3*Stotal %f > T " I64_FORMAT". G="I64_FORMAT" M="I64_FORMAT" E="I64_FORMAT " D="I64_FORMAT" T="I64_FORMAT". " "Wgg=%f Wgd=%f Wmg=%f Wme=%f Wmd=%f Wee=%f Wed=%f", casename, Stotal*3, I64_PRINTF_ARG(T), I64_PRINTF_ARG(G), I64_PRINTF_ARG(M), I64_PRINTF_ARG(E), I64_PRINTF_ARG(D), I64_PRINTF_ARG(T), Wgg, Wgd, Wmg, Wme, Wmd, Wee, Wed);







        valid = 0;
      }
      
      if (3*Mtotal < T) {
        log_warn(LD_DIR, "Bw Weight Failure for %s: 3*Mtotal %f < T " I64_FORMAT". " "G="I64_FORMAT" M="I64_FORMAT" E="I64_FORMAT" D="I64_FORMAT " T="I64_FORMAT". " "Wgg=%f Wgd=%f Wmg=%f Wme=%f Wmd=%f Wee=%f Wed=%f", casename, Mtotal*3, I64_PRINTF_ARG(T), I64_PRINTF_ARG(G), I64_PRINTF_ARG(M), I64_PRINTF_ARG(E), I64_PRINTF_ARG(D), I64_PRINTF_ARG(T), Wgg, Wgd, Wmg, Wme, Wmd, Wee, Wed);








        valid = 0;
      }
    } else { 
      casename = "Case 2b";

      
      if (D != 0 && 3*M < T) {
        casename = "Case 2b (balanced)";
        if (fabs(Etotal-Mtotal) > 0.01*MAX(Etotal,Mtotal)) {
          log_warn(LD_DIR, "Bw Weight Failure for %s: Etotal %f != Mtotal %f. " "G="I64_FORMAT" M="I64_FORMAT" E="I64_FORMAT" D="I64_FORMAT " T="I64_FORMAT". " "Wgg=%f Wgd=%f Wmg=%f Wme=%f Wmd=%f Wee=%f Wed=%f", casename, Etotal, Mtotal, I64_PRINTF_ARG(G), I64_PRINTF_ARG(M), I64_PRINTF_ARG(E), I64_PRINTF_ARG(D), I64_PRINTF_ARG(T), Wgg, Wgd, Wmg, Wme, Wmd, Wee, Wed);







          valid = 0;
        }
        if (fabs(Etotal-Gtotal) > 0.01*MAX(Etotal,Gtotal)) {
          log_warn(LD_DIR, "Bw Weight Failure for %s: Etotal %f != Gtotal %f. " "G="I64_FORMAT" M="I64_FORMAT" E="I64_FORMAT" D="I64_FORMAT " T="I64_FORMAT". " "Wgg=%f Wgd=%f Wmg=%f Wme=%f Wmd=%f Wee=%f Wed=%f", casename, Etotal, Gtotal, I64_PRINTF_ARG(G), I64_PRINTF_ARG(M), I64_PRINTF_ARG(E), I64_PRINTF_ARG(D), I64_PRINTF_ARG(T), Wgg, Wgd, Wmg, Wme, Wmd, Wee, Wed);







          valid = 0;
        }
        if (fabs(Gtotal-Mtotal) > 0.01*MAX(Gtotal,Mtotal)) {
          log_warn(LD_DIR, "Bw Weight Failure for %s: Mtotal %f != Gtotal %f. " "G="I64_FORMAT" M="I64_FORMAT" E="I64_FORMAT" D="I64_FORMAT " T="I64_FORMAT". " "Wgg=%f Wgd=%f Wmg=%f Wme=%f Wmd=%f Wee=%f Wed=%f", casename, Mtotal, Gtotal, I64_PRINTF_ARG(G), I64_PRINTF_ARG(M), I64_PRINTF_ARG(E), I64_PRINTF_ARG(D), I64_PRINTF_ARG(T), Wgg, Wgd, Wmg, Wme, Wmd, Wee, Wed);







          valid = 0;
        }
      } else {
        if (fabs(Etotal-Gtotal) > 0.01*MAX(Etotal,Gtotal)) {
          log_warn(LD_DIR, "Bw Weight Failure for %s: Etotal %f != Gtotal %f. " "G="I64_FORMAT" M="I64_FORMAT" E="I64_FORMAT" D="I64_FORMAT " T="I64_FORMAT". " "Wgg=%f Wgd=%f Wmg=%f Wme=%f Wmd=%f Wee=%f Wed=%f", casename, Etotal, Gtotal, I64_PRINTF_ARG(G), I64_PRINTF_ARG(M), I64_PRINTF_ARG(E), I64_PRINTF_ARG(D), I64_PRINTF_ARG(T), Wgg, Wgd, Wmg, Wme, Wmd, Wee, Wed);







          valid = 0;
        }
      }
    }
  } else { 
    int64_t S = MIN(E, G);
    int64_t NS = MAX(E, G);
    if (3*(S+D) < T) { 
      double Stotal;
      double NStotal;
      if (G < E) {
        casename = "Case 3a (G scarce)";
        Stotal = Gtotal;
        NStotal = Etotal;
      } else { 
        casename = "Case 3a (E scarce)";
        NStotal = Gtotal;
        Stotal = Etotal;
      }
      
      if (3*Stotal > T) {
        log_warn(LD_DIR, "Bw Weight Failure for %s: 3*Stotal %f > T " I64_FORMAT". G="I64_FORMAT" M="I64_FORMAT" E="I64_FORMAT " D="I64_FORMAT" T="I64_FORMAT". " "Wgg=%f Wgd=%f Wmg=%f Wme=%f Wmd=%f Wee=%f Wed=%f", casename, Stotal*3, I64_PRINTF_ARG(T), I64_PRINTF_ARG(G), I64_PRINTF_ARG(M), I64_PRINTF_ARG(E), I64_PRINTF_ARG(D), I64_PRINTF_ARG(T), Wgg, Wgd, Wmg, Wme, Wmd, Wee, Wed);







        valid = 0;
      }
      if (NS >= M) {
        if (fabs(NStotal-Mtotal) > 0.01*MAX(NStotal,Mtotal)) {
          log_warn(LD_DIR, "Bw Weight Failure for %s: NStotal %f != Mtotal %f. " "G="I64_FORMAT" M="I64_FORMAT" E="I64_FORMAT" D="I64_FORMAT " T="I64_FORMAT". " "Wgg=%f Wgd=%f Wmg=%f Wme=%f Wmd=%f Wee=%f Wed=%f", casename, NStotal, Mtotal, I64_PRINTF_ARG(G), I64_PRINTF_ARG(M), I64_PRINTF_ARG(E), I64_PRINTF_ARG(D), I64_PRINTF_ARG(T), Wgg, Wgd, Wmg, Wme, Wmd, Wee, Wed);







          valid = 0;
        }
      } else {
        
        if (3*NStotal < T) {
          log_warn(LD_DIR, "Bw Weight Failure for %s: 3*NStotal %f < T " I64_FORMAT". G="I64_FORMAT" M="I64_FORMAT " E="I64_FORMAT" D="I64_FORMAT" T="I64_FORMAT". " "Wgg=%f Wgd=%f Wmg=%f Wme=%f Wmd=%f Wee=%f Wed=%f", casename, NStotal*3, I64_PRINTF_ARG(T), I64_PRINTF_ARG(G), I64_PRINTF_ARG(M), I64_PRINTF_ARG(E), I64_PRINTF_ARG(D), I64_PRINTF_ARG(T), Wgg, Wgd, Wmg, Wme, Wmd, Wee, Wed);







          valid = 0;
        }
      }
    } else { 
      casename = "Case 3b";
      if (fabs(Etotal-Mtotal) > 0.01*MAX(Etotal,Mtotal)) {
        log_warn(LD_DIR, "Bw Weight Failure for %s: Etotal %f != Mtotal %f. " "G="I64_FORMAT" M="I64_FORMAT" E="I64_FORMAT" D="I64_FORMAT " T="I64_FORMAT". " "Wgg=%f Wgd=%f Wmg=%f Wme=%f Wmd=%f Wee=%f Wed=%f", casename, Etotal, Mtotal, I64_PRINTF_ARG(G), I64_PRINTF_ARG(M), I64_PRINTF_ARG(E), I64_PRINTF_ARG(D), I64_PRINTF_ARG(T), Wgg, Wgd, Wmg, Wme, Wmd, Wee, Wed);







        valid = 0;
      }
      if (fabs(Etotal-Gtotal) > 0.01*MAX(Etotal,Gtotal)) {
        log_warn(LD_DIR, "Bw Weight Failure for %s: Etotal %f != Gtotal %f. " "G="I64_FORMAT" M="I64_FORMAT" E="I64_FORMAT" D="I64_FORMAT " T="I64_FORMAT". " "Wgg=%f Wgd=%f Wmg=%f Wme=%f Wmd=%f Wee=%f Wed=%f", casename, Etotal, Gtotal, I64_PRINTF_ARG(G), I64_PRINTF_ARG(M), I64_PRINTF_ARG(E), I64_PRINTF_ARG(D), I64_PRINTF_ARG(T), Wgg, Wgd, Wmg, Wme, Wmd, Wee, Wed);







        valid = 0;
      }
      if (fabs(Gtotal-Mtotal) > 0.01*MAX(Gtotal,Mtotal)) {
        log_warn(LD_DIR, "Bw Weight Failure for %s: Mtotal %f != Gtotal %f. " "G="I64_FORMAT" M="I64_FORMAT" E="I64_FORMAT" D="I64_FORMAT " T="I64_FORMAT". " "Wgg=%f Wgd=%f Wmg=%f Wme=%f Wmd=%f Wee=%f Wed=%f", casename, Mtotal, Gtotal, I64_PRINTF_ARG(G), I64_PRINTF_ARG(M), I64_PRINTF_ARG(E), I64_PRINTF_ARG(D), I64_PRINTF_ARG(T), Wgg, Wgd, Wmg, Wme, Wmd, Wee, Wed);







        valid = 0;
      }
    }
  }

  if (valid)
    log_notice(LD_DIR, "Bandwidth-weight %s is verified and valid.", casename);

  return valid;
}


networkstatus_t * networkstatus_parse_vote_from_string(const char *s, const char **eos_out, networkstatus_type_t ns_type)

{
  smartlist_t *tokens = smartlist_new();
  smartlist_t *rs_tokens = NULL, *footer_tokens = NULL;
  networkstatus_voter_info_t *voter = NULL;
  networkstatus_t *ns = NULL;
  digests_t ns_digests;
  const char *cert, *end_of_header, *end_of_footer, *s_dup = s;
  directory_token_t *tok;
  int ok;
  struct in_addr in;
  int i, inorder, n_signatures = 0;
  memarea_t *area = NULL, *rs_area = NULL;
  consensus_flavor_t flav = FLAV_NS;
  char *last_kwd=NULL;

  tor_assert(s);

  if (eos_out)
    *eos_out = NULL;

  if (router_get_networkstatus_v3_hashes(s, &ns_digests)) {
    log_warn(LD_DIR, "Unable to compute digest of network-status");
    goto err;
  }

  area = memarea_new();
  end_of_header = find_start_of_next_routerstatus(s);
  if (tokenize_string(area, s, end_of_header, tokens, (ns_type == NS_TYPE_CONSENSUS) ? networkstatus_consensus_token_table :

                      networkstatus_token_table, 0)) {
    log_warn(LD_DIR, "Error tokenizing network-status vote header");
    goto err;
  }

  ns = tor_malloc_zero(sizeof(networkstatus_t));
  memcpy(&ns->digests, &ns_digests, sizeof(ns_digests));

  tok = find_by_keyword(tokens, K_NETWORK_STATUS_VERSION);
  tor_assert(tok);
  if (tok->n_args > 1) {
    int flavor = networkstatus_parse_flavor_name(tok->args[1]);
    if (flavor < 0) {
      log_warn(LD_DIR, "Can't parse document with unknown flavor %s", escaped(tok->args[1]));
      goto err;
    }
    ns->flavor = flav = flavor;
  }
  if (flav != FLAV_NS && ns_type != NS_TYPE_CONSENSUS) {
    log_warn(LD_DIR, "Flavor found on non-consensus networkstatus.");
    goto err;
  }

  if (ns_type != NS_TYPE_CONSENSUS) {
    const char *end_of_cert = NULL;
    if (!(cert = strstr(s, "\ndir-key-certificate-version")))
      goto err;
    ++cert;
    ns->cert = authority_cert_parse_from_string(cert, &end_of_cert);
    if (!ns->cert || !end_of_cert || end_of_cert > end_of_header)
      goto err;
  }

  tok = find_by_keyword(tokens, K_VOTE_STATUS);
  tor_assert(tok->n_args);
  if (!strcmp(tok->args[0], "vote")) {
    ns->type = NS_TYPE_VOTE;
  } else if (!strcmp(tok->args[0], "consensus")) {
    ns->type = NS_TYPE_CONSENSUS;
  } else if (!strcmp(tok->args[0], "opinion")) {
    ns->type = NS_TYPE_OPINION;
  } else {
    log_warn(LD_DIR, "Unrecognized vote status %s in network-status", escaped(tok->args[0]));
    goto err;
  }
  if (ns_type != ns->type) {
    log_warn(LD_DIR, "Got the wrong kind of v3 networkstatus.");
    goto err;
  }

  if (ns->type == NS_TYPE_VOTE || ns->type == NS_TYPE_OPINION) {
    tok = find_by_keyword(tokens, K_PUBLISHED);
    if (parse_iso_time(tok->args[0], &ns->published))
      goto err;

    ns->supported_methods = smartlist_new();
    tok = find_opt_by_keyword(tokens, K_CONSENSUS_METHODS);
    if (tok) {
      for (i=0; i < tok->n_args; ++i)
        smartlist_add(ns->supported_methods, tor_strdup(tok->args[i]));
    } else {
      smartlist_add(ns->supported_methods, tor_strdup("1"));
    }
  } else {
    tok = find_opt_by_keyword(tokens, K_CONSENSUS_METHOD);
    if (tok) {
      ns->consensus_method = (int)tor_parse_long(tok->args[0], 10, 1, INT_MAX, &ok, NULL);
      if (!ok)
        goto err;
    } else {
      ns->consensus_method = 1;
    }
  }

  tok = find_by_keyword(tokens, K_VALID_AFTER);
  if (parse_iso_time(tok->args[0], &ns->valid_after))
    goto err;

  tok = find_by_keyword(tokens, K_FRESH_UNTIL);
  if (parse_iso_time(tok->args[0], &ns->fresh_until))
    goto err;

  tok = find_by_keyword(tokens, K_VALID_UNTIL);
  if (parse_iso_time(tok->args[0], &ns->valid_until))
    goto err;

  tok = find_by_keyword(tokens, K_VOTING_DELAY);
  tor_assert(tok->n_args >= 2);
  ns->vote_seconds = (int) tor_parse_long(tok->args[0], 10, 0, INT_MAX, &ok, NULL);
  if (!ok)
    goto err;
  ns->dist_seconds = (int) tor_parse_long(tok->args[1], 10, 0, INT_MAX, &ok, NULL);
  if (!ok)
    goto err;
  if (ns->valid_after + MIN_VOTE_INTERVAL > ns->fresh_until) {
    log_warn(LD_DIR, "Vote/consensus freshness interval is too short");
    goto err;
  }
  if (ns->valid_after + MIN_VOTE_INTERVAL*2 > ns->valid_until) {
    log_warn(LD_DIR, "Vote/consensus liveness interval is too short");
    goto err;
  }
  if (ns->vote_seconds < MIN_VOTE_SECONDS) {
    log_warn(LD_DIR, "Vote seconds is too short");
    goto err;
  }
  if (ns->dist_seconds < MIN_DIST_SECONDS) {
    log_warn(LD_DIR, "Dist seconds is too short");
    goto err;
  }

  if ((tok = find_opt_by_keyword(tokens, K_CLIENT_VERSIONS))) {
    ns->client_versions = tor_strdup(tok->args[0]);
  }
  if ((tok = find_opt_by_keyword(tokens, K_SERVER_VERSIONS))) {
    ns->server_versions = tor_strdup(tok->args[0]);
  }

  tok = find_by_keyword(tokens, K_KNOWN_FLAGS);
  ns->known_flags = smartlist_new();
  inorder = 1;
  for (i = 0; i < tok->n_args; ++i) {
    smartlist_add(ns->known_flags, tor_strdup(tok->args[i]));
    if (i>0 && strcmp(tok->args[i-1], tok->args[i])>= 0) {
      log_warn(LD_DIR, "%s >= %s", tok->args[i-1], tok->args[i]);
      inorder = 0;
    }
  }
  if (!inorder) {
    log_warn(LD_DIR, "known-flags not in order");
    goto err;
  }
  if (ns->type != NS_TYPE_CONSENSUS && smartlist_len(ns->known_flags) > MAX_KNOWN_FLAGS_IN_VOTE) {
    
    log_warn(LD_DIR, "Too many known-flags in consensus vote or opinion");
    goto err;
  }

  tok = find_opt_by_keyword(tokens, K_PARAMS);
  if (tok) {
    int any_dups = 0;
    inorder = 1;
    ns->net_params = smartlist_new();
    for (i = 0; i < tok->n_args; ++i) {
      int ok=0;
      char *eq = strchr(tok->args[i], '=');
      size_t eq_pos;
      if (!eq) {
        log_warn(LD_DIR, "Bad element '%s' in params", escaped(tok->args[i]));
        goto err;
      }
      eq_pos = eq-tok->args[i];
      tor_parse_long(eq+1, 10, INT32_MIN, INT32_MAX, &ok, NULL);
      if (!ok) {
        log_warn(LD_DIR, "Bad element '%s' in params", escaped(tok->args[i]));
        goto err;
      }
      if (i > 0 && strcmp(tok->args[i-1], tok->args[i]) >= 0) {
        log_warn(LD_DIR, "%s >= %s", tok->args[i-1], tok->args[i]);
        inorder = 0;
      }
      if (last_kwd && eq_pos == strlen(last_kwd) && fast_memeq(last_kwd, tok->args[i], eq_pos)) {
        log_warn(LD_DIR, "Duplicate value for %s parameter", escaped(tok->args[i]));
        any_dups = 1;
      }
      tor_free(last_kwd);
      last_kwd = tor_strndup(tok->args[i], eq_pos);
      smartlist_add(ns->net_params, tor_strdup(tok->args[i]));
    }
    if (!inorder) {
      log_warn(LD_DIR, "params not in order");
      goto err;
    }
    if (any_dups) {
      log_warn(LD_DIR, "Duplicate in parameters");
      goto err;
    }
  }

  ns->voters = smartlist_new();

  SMARTLIST_FOREACH_BEGIN(tokens, directory_token_t *, _tok) {
    tok = _tok;
    if (tok->tp == K_DIR_SOURCE) {
      tor_assert(tok->n_args >= 6);

      if (voter)
        smartlist_add(ns->voters, voter);
      voter = tor_malloc_zero(sizeof(networkstatus_voter_info_t));
      voter->sigs = smartlist_new();
      if (ns->type != NS_TYPE_CONSENSUS)
        memcpy(voter->vote_digest, ns_digests.d[DIGEST_SHA1], DIGEST_LEN);

      voter->nickname = tor_strdup(tok->args[0]);
      if (strlen(tok->args[1]) != HEX_DIGEST_LEN || base16_decode(voter->identity_digest, sizeof(voter->identity_digest), tok->args[1], HEX_DIGEST_LEN) < 0) {

        log_warn(LD_DIR, "Error decoding identity digest %s in " "network-status vote.", escaped(tok->args[1]));
        goto err;
      }
      if (ns->type != NS_TYPE_CONSENSUS && tor_memneq(ns->cert->cache_info.identity_digest, voter->identity_digest, DIGEST_LEN)) {

        log_warn(LD_DIR,"Mismatch between identities in certificate and vote");
        goto err;
      }
      if (ns->type != NS_TYPE_CONSENSUS) {
        if (authority_cert_is_blacklisted(ns->cert)) {
          log_warn(LD_DIR, "Rejecting vote signature made with blacklisted " "signing key %s", hex_str(ns->cert->signing_key_digest, DIGEST_LEN));

          goto err;
        }
      }
      voter->address = tor_strdup(tok->args[2]);
      if (!tor_inet_aton(tok->args[3], &in)) {
        log_warn(LD_DIR, "Error decoding IP address %s in network-status.", escaped(tok->args[3]));
        goto err;
      }
      voter->addr = ntohl(in.s_addr);
      voter->dir_port = (uint16_t)
        tor_parse_long(tok->args[4], 10, 0, 65535, &ok, NULL);
      if (!ok)
        goto err;
      voter->or_port = (uint16_t)
        tor_parse_long(tok->args[5], 10, 0, 65535, &ok, NULL);
      if (!ok)
        goto err;
    } else if (tok->tp == K_CONTACT) {
      if (!voter || voter->contact) {
        log_warn(LD_DIR, "contact element is out of place.");
        goto err;
      }
      voter->contact = tor_strdup(tok->args[0]);
    } else if (tok->tp == K_VOTE_DIGEST) {
      tor_assert(ns->type == NS_TYPE_CONSENSUS);
      tor_assert(tok->n_args >= 1);
      if (!voter || ! tor_digest_is_zero(voter->vote_digest)) {
        log_warn(LD_DIR, "vote-digest element is out of place.");
        goto err;
      }
      if (strlen(tok->args[0]) != HEX_DIGEST_LEN || base16_decode(voter->vote_digest, sizeof(voter->vote_digest), tok->args[0], HEX_DIGEST_LEN) < 0) {

        log_warn(LD_DIR, "Error decoding vote digest %s in " "network-status consensus.", escaped(tok->args[0]));
        goto err;
      }
    }
  } SMARTLIST_FOREACH_END(_tok);
  if (voter) {
    smartlist_add(ns->voters, voter);
    voter = NULL;
  }
  if (smartlist_len(ns->voters) == 0) {
    log_warn(LD_DIR, "Missing dir-source elements in a vote networkstatus.");
    goto err;
  } else if (ns->type != NS_TYPE_CONSENSUS && smartlist_len(ns->voters) != 1) {
    log_warn(LD_DIR, "Too many dir-source elements in a vote networkstatus.");
    goto err;
  }

  if (ns->type != NS_TYPE_CONSENSUS && (tok = find_opt_by_keyword(tokens, K_LEGACY_DIR_KEY))) {
    int bad = 1;
    if (strlen(tok->args[0]) == HEX_DIGEST_LEN) {
      networkstatus_voter_info_t *voter = smartlist_get(ns->voters, 0);
      if (base16_decode(voter->legacy_id_digest, DIGEST_LEN, tok->args[0], HEX_DIGEST_LEN)<0)
        bad = 1;
      else bad = 0;
    }
    if (bad) {
      log_warn(LD_DIR, "Invalid legacy key digest %s on vote.", escaped(tok->args[0]));
    }
  }

  
  rs_tokens = smartlist_new();
  rs_area = memarea_new();
  s = end_of_header;
  ns->routerstatus_list = smartlist_new();

  while (!strcmpstart(s, "r ")) {
    if (ns->type != NS_TYPE_CONSENSUS) {
      vote_routerstatus_t *rs = tor_malloc_zero(sizeof(vote_routerstatus_t));
      if (routerstatus_parse_entry_from_string(rs_area, &s, rs_tokens, ns, rs, 0, 0))
        smartlist_add(ns->routerstatus_list, rs);
      else {
        tor_free(rs->version);
        tor_free(rs);
      }
    } else {
      routerstatus_t *rs;
      if ((rs = routerstatus_parse_entry_from_string(rs_area, &s, rs_tokens, NULL, NULL, ns->consensus_method, flav)))


        smartlist_add(ns->routerstatus_list, rs);
    }
  }
  for (i = 1; i < smartlist_len(ns->routerstatus_list); ++i) {
    routerstatus_t *rs1, *rs2;
    if (ns->type != NS_TYPE_CONSENSUS) {
      vote_routerstatus_t *a = smartlist_get(ns->routerstatus_list, i-1);
      vote_routerstatus_t *b = smartlist_get(ns->routerstatus_list, i);
      rs1 = &a->status; rs2 = &b->status;
    } else {
      rs1 = smartlist_get(ns->routerstatus_list, i-1);
      rs2 = smartlist_get(ns->routerstatus_list, i);
    }
    if (fast_memcmp(rs1->identity_digest, rs2->identity_digest, DIGEST_LEN)
        >= 0) {
      log_warn(LD_DIR, "Vote networkstatus entries not sorted by identity " "digest");
      goto err;
    }
  }

  
  footer_tokens = smartlist_new();
  if ((end_of_footer = strstr(s, "\nnetwork-status-version ")))
    ++end_of_footer;
  else end_of_footer = s + strlen(s);
  if (tokenize_string(area,s, end_of_footer, footer_tokens, networkstatus_vote_footer_token_table, 0)) {
    log_warn(LD_DIR, "Error tokenizing network-status vote footer.");
    goto err;
  }

  {
    int found_sig = 0;
    SMARTLIST_FOREACH_BEGIN(footer_tokens, directory_token_t *, _tok) {
      tok = _tok;
      if (tok->tp == K_DIRECTORY_SIGNATURE)
        found_sig = 1;
      else if (found_sig) {
        log_warn(LD_DIR, "Extraneous token after first directory-signature");
        goto err;
      }
    } SMARTLIST_FOREACH_END(_tok);
  }

  if ((tok = find_opt_by_keyword(footer_tokens, K_DIRECTORY_FOOTER))) {
    if (tok != smartlist_get(footer_tokens, 0)) {
      log_warn(LD_DIR, "Misplaced directory-footer token");
      goto err;
    }
  }

  tok = find_opt_by_keyword(footer_tokens, K_BW_WEIGHTS);
  if (tok) {
    ns->weight_params = smartlist_new();
    for (i = 0; i < tok->n_args; ++i) {
      int ok=0;
      char *eq = strchr(tok->args[i], '=');
      if (!eq) {
        log_warn(LD_DIR, "Bad element '%s' in weight params", escaped(tok->args[i]));
        goto err;
      }
      tor_parse_long(eq+1, 10, INT32_MIN, INT32_MAX, &ok, NULL);
      if (!ok) {
        log_warn(LD_DIR, "Bad element '%s' in params", escaped(tok->args[i]));
        goto err;
      }
      smartlist_add(ns->weight_params, tor_strdup(tok->args[i]));
    }
  }

  SMARTLIST_FOREACH_BEGIN(footer_tokens, directory_token_t *, _tok) {
    char declared_identity[DIGEST_LEN];
    networkstatus_voter_info_t *v;
    document_signature_t *sig;
    const char *id_hexdigest = NULL;
    const char *sk_hexdigest = NULL;
    digest_algorithm_t alg = DIGEST_SHA1;
    tok = _tok;
    if (tok->tp != K_DIRECTORY_SIGNATURE)
      continue;
    tor_assert(tok->n_args >= 2);
    if (tok->n_args == 2) {
      id_hexdigest = tok->args[0];
      sk_hexdigest = tok->args[1];
    } else {
      const char *algname = tok->args[0];
      int a;
      id_hexdigest = tok->args[1];
      sk_hexdigest = tok->args[2];
      a = crypto_digest_algorithm_parse_name(algname);
      if (a<0) {
        log_warn(LD_DIR, "Unknown digest algorithm %s; skipping", escaped(algname));
        continue;
      }
      alg = a;
    }

    if (!tok->object_type || strcmp(tok->object_type, "SIGNATURE") || tok->object_size < 128 || tok->object_size > 512) {

      log_warn(LD_DIR, "Bad object type or length on directory-signature");
      goto err;
    }

    if (strlen(id_hexdigest) != HEX_DIGEST_LEN || base16_decode(declared_identity, sizeof(declared_identity), id_hexdigest, HEX_DIGEST_LEN) < 0) {

      log_warn(LD_DIR, "Error decoding declared identity %s in " "network-status vote.", escaped(id_hexdigest));
      goto err;
    }
    if (!(v = networkstatus_get_voter_by_id(ns, declared_identity))) {
      log_warn(LD_DIR, "ID on signature on network-status vote does not match " "any declared directory source.");
      goto err;
    }
    sig = tor_malloc_zero(sizeof(document_signature_t));
    memcpy(sig->identity_digest, v->identity_digest, DIGEST_LEN);
    sig->alg = alg;
    if (strlen(sk_hexdigest) != HEX_DIGEST_LEN || base16_decode(sig->signing_key_digest, sizeof(sig->signing_key_digest), sk_hexdigest, HEX_DIGEST_LEN) < 0) {

      log_warn(LD_DIR, "Error decoding declared signing key digest %s in " "network-status vote.", escaped(sk_hexdigest));
      tor_free(sig);
      goto err;
    }

    if (ns->type != NS_TYPE_CONSENSUS) {
      if (tor_memneq(declared_identity, ns->cert->cache_info.identity_digest, DIGEST_LEN)) {
        log_warn(LD_DIR, "Digest mismatch between declared and actual on " "network-status vote.");
        tor_free(sig);
        goto err;
      }
    }

    if (voter_get_sig_by_algorithm(v, sig->alg)) {
      
      log_fn(LOG_PROTOCOL_WARN, LD_DIR, "We received a networkstatus " "that contains two votes from the same voter with the same " "algorithm. Ignoring the second vote.");

      tor_free(sig);
      continue;
    }

    if (ns->type != NS_TYPE_CONSENSUS) {
      if (check_signature_token(ns_digests.d[DIGEST_SHA1], DIGEST_LEN, tok, ns->cert->signing_key, 0, "network-status vote")) {

        tor_free(sig);
        goto err;
      }
      sig->good_signature = 1;
    } else {
      if (tok->object_size >= INT_MAX || tok->object_size >= SIZE_T_CEILING) {
        tor_free(sig);
        goto err;
      }
      sig->signature = tor_memdup(tok->object_body, tok->object_size);
      sig->signature_len = (int) tok->object_size;
    }
    smartlist_add(v->sigs, sig);

    ++n_signatures;
  } SMARTLIST_FOREACH_END(_tok);

  if (! n_signatures) {
    log_warn(LD_DIR, "No signatures on networkstatus vote.");
    goto err;
  } else if (ns->type == NS_TYPE_VOTE && n_signatures != 1) {
    log_warn(LD_DIR, "Received more than one signature on a " "network-status vote.");
    goto err;
  }

  if (eos_out)
    *eos_out = end_of_footer;

  goto done;
 err:
  dump_desc(s_dup, "v3 networkstatus");
  networkstatus_vote_free(ns);
  ns = NULL;
 done:
  if (tokens) {
    SMARTLIST_FOREACH(tokens, directory_token_t *, t, token_clear(t));
    smartlist_free(tokens);
  }
  if (voter) {
    if (voter->sigs) {
      SMARTLIST_FOREACH(voter->sigs, document_signature_t *, sig, document_signature_free(sig));
      smartlist_free(voter->sigs);
    }
    tor_free(voter->nickname);
    tor_free(voter->address);
    tor_free(voter->contact);
    tor_free(voter);
  }
  if (rs_tokens) {
    SMARTLIST_FOREACH(rs_tokens, directory_token_t *, t, token_clear(t));
    smartlist_free(rs_tokens);
  }
  if (footer_tokens) {
    SMARTLIST_FOREACH(footer_tokens, directory_token_t *, t, token_clear(t));
    smartlist_free(footer_tokens);
  }
  if (area) {
    DUMP_AREA(area, "v3 networkstatus");
    memarea_drop_all(area);
  }
  if (rs_area)
    memarea_drop_all(rs_area);
  tor_free(last_kwd);

  return ns;
}


static digests_t * detached_get_digests(ns_detached_signatures_t *sigs, const char *flavor_name)
{
  digests_t *d = strmap_get(sigs->digests, flavor_name);
  if (!d) {
    d = tor_malloc_zero(sizeof(digests_t));
    strmap_set(sigs->digests, flavor_name, d);
  }
  return d;
}


static smartlist_t * detached_get_signatures(ns_detached_signatures_t *sigs, const char *flavor_name)

{
  smartlist_t *sl = strmap_get(sigs->signatures, flavor_name);
  if (!sl) {
    sl = smartlist_new();
    strmap_set(sigs->signatures, flavor_name, sl);
  }
  return sl;
}


ns_detached_signatures_t * networkstatus_parse_detached_signatures(const char *s, const char *eos)
{
  
  directory_token_t *tok;
  memarea_t *area = NULL;
  digests_t *digests;

  smartlist_t *tokens = smartlist_new();
  ns_detached_signatures_t *sigs = tor_malloc_zero(sizeof(ns_detached_signatures_t));
  sigs->digests = strmap_new();
  sigs->signatures = strmap_new();

  if (!eos)
    eos = s + strlen(s);

  area = memarea_new();
  if (tokenize_string(area,s, eos, tokens, networkstatus_detached_signature_token_table, 0)) {
    log_warn(LD_DIR, "Error tokenizing detached networkstatus signatures");
    goto err;
  }

  
  SMARTLIST_FOREACH_BEGIN(tokens, directory_token_t *, _tok) {
    const char *algname;
    digest_algorithm_t alg;
    const char *flavor;
    const char *hexdigest;
    size_t expected_length;

    tok = _tok;

    if (tok->tp == K_CONSENSUS_DIGEST) {
      algname = "sha1";
      alg = DIGEST_SHA1;
      flavor = "ns";
      hexdigest = tok->args[0];
    } else if (tok->tp == K_ADDITIONAL_DIGEST) {
      int a = crypto_digest_algorithm_parse_name(tok->args[1]);
      if (a<0) {
        log_warn(LD_DIR, "Unrecognized algorithm name %s", tok->args[0]);
        continue;
      }
      alg = (digest_algorithm_t) a;
      flavor = tok->args[0];
      algname = tok->args[1];
      hexdigest = tok->args[2];
    } else {
      continue;
    }

    expected_length = (alg == DIGEST_SHA1) ? HEX_DIGEST_LEN : HEX_DIGEST256_LEN;

    if (strlen(hexdigest) != expected_length) {
      log_warn(LD_DIR, "Wrong length on consensus-digest in detached " "networkstatus signatures");
      goto err;
    }
    digests = detached_get_digests(sigs, flavor);
    tor_assert(digests);
    if (!tor_mem_is_zero(digests->d[alg], DIGEST256_LEN)) {
      log_warn(LD_DIR, "Multiple digests for %s with %s on detached " "signatures document", flavor, algname);
      continue;
    }
    if (base16_decode(digests->d[alg], DIGEST256_LEN, hexdigest, strlen(hexdigest)) < 0) {
      log_warn(LD_DIR, "Bad encoding on consensus-digest in detached " "networkstatus signatures");
      goto err;
    }
  } SMARTLIST_FOREACH_END(_tok);

  tok = find_by_keyword(tokens, K_VALID_AFTER);
  if (parse_iso_time(tok->args[0], &sigs->valid_after)) {
    log_warn(LD_DIR, "Bad valid-after in detached networkstatus signatures");
    goto err;
  }

  tok = find_by_keyword(tokens, K_FRESH_UNTIL);
  if (parse_iso_time(tok->args[0], &sigs->fresh_until)) {
    log_warn(LD_DIR, "Bad fresh-until in detached networkstatus signatures");
    goto err;
  }

  tok = find_by_keyword(tokens, K_VALID_UNTIL);
  if (parse_iso_time(tok->args[0], &sigs->valid_until)) {
    log_warn(LD_DIR, "Bad valid-until in detached networkstatus signatures");
    goto err;
  }

  SMARTLIST_FOREACH_BEGIN(tokens, directory_token_t *, _tok) {
    const char *id_hexdigest;
    const char *sk_hexdigest;
    const char *algname;
    const char *flavor;
    digest_algorithm_t alg;

    char id_digest[DIGEST_LEN];
    char sk_digest[DIGEST_LEN];
    smartlist_t *siglist;
    document_signature_t *sig;
    int is_duplicate;

    tok = _tok;
    if (tok->tp == K_DIRECTORY_SIGNATURE) {
      tor_assert(tok->n_args >= 2);
      flavor = "ns";
      algname = "sha1";
      id_hexdigest = tok->args[0];
      sk_hexdigest = tok->args[1];
    } else if (tok->tp == K_ADDITIONAL_SIGNATURE) {
      tor_assert(tok->n_args >= 4);
      flavor = tok->args[0];
      algname = tok->args[1];
      id_hexdigest = tok->args[2];
      sk_hexdigest = tok->args[3];
    } else {
      continue;
    }

    {
      int a = crypto_digest_algorithm_parse_name(algname);
      if (a<0) {
        log_warn(LD_DIR, "Unrecognized algorithm name %s", algname);
        continue;
      }
      alg = (digest_algorithm_t) a;
    }

    if (!tok->object_type || strcmp(tok->object_type, "SIGNATURE") || tok->object_size < 128 || tok->object_size > 512) {

      log_warn(LD_DIR, "Bad object type or length on directory-signature");
      goto err;
    }

    if (strlen(id_hexdigest) != HEX_DIGEST_LEN || base16_decode(id_digest, sizeof(id_digest), id_hexdigest, HEX_DIGEST_LEN) < 0) {

      log_warn(LD_DIR, "Error decoding declared identity %s in " "network-status vote.", escaped(id_hexdigest));
      goto err;
    }
    if (strlen(sk_hexdigest) != HEX_DIGEST_LEN || base16_decode(sk_digest, sizeof(sk_digest), sk_hexdigest, HEX_DIGEST_LEN) < 0) {

      log_warn(LD_DIR, "Error decoding declared signing key digest %s in " "network-status vote.", escaped(sk_hexdigest));
      goto err;
    }

    siglist = detached_get_signatures(sigs, flavor);
    is_duplicate = 0;
    SMARTLIST_FOREACH(siglist, document_signature_t *, dsig, {
      if (dsig->alg == alg && tor_memeq(id_digest, dsig->identity_digest, DIGEST_LEN) && tor_memeq(sk_digest, dsig->signing_key_digest, DIGEST_LEN)) {

        is_duplicate = 1;
      }
    });
    if (is_duplicate) {
      log_warn(LD_DIR, "Two signatures with identical keys and algorithm " "found.");
      continue;
    }

    sig = tor_malloc_zero(sizeof(document_signature_t));
    sig->alg = alg;
    memcpy(sig->identity_digest, id_digest, DIGEST_LEN);
    memcpy(sig->signing_key_digest, sk_digest, DIGEST_LEN);
    if (tok->object_size >= INT_MAX || tok->object_size >= SIZE_T_CEILING) {
      tor_free(sig);
      goto err;
    }
    sig->signature = tor_memdup(tok->object_body, tok->object_size);
    sig->signature_len = (int) tok->object_size;

    smartlist_add(siglist, sig);
  } SMARTLIST_FOREACH_END(_tok);

  goto done;
 err:
  ns_detached_signatures_free(sigs);
  sigs = NULL;
 done:
  SMARTLIST_FOREACH(tokens, directory_token_t *, t, token_clear(t));
  smartlist_free(tokens);
  if (area) {
    DUMP_AREA(area, "detached signatures");
    memarea_drop_all(area);
  }
  return sigs;
}


addr_policy_t * router_parse_addr_policy_item_from_string(const char *s, int assume_action)
{
  directory_token_t *tok = NULL;
  const char *cp, *eos;
  
  char line[TOR_ADDR_BUF_LEN*2 + 32];
  addr_policy_t *r;
  memarea_t *area = NULL;

  s = eat_whitespace(s);
  if ((*s == '*' || TOR_ISDIGIT(*s)) && assume_action >= 0) {
    if (tor_snprintf(line, sizeof(line), "%s %s", assume_action == ADDR_POLICY_ACCEPT?"accept":"reject", s)<0) {
      log_warn(LD_DIR, "Policy %s is too long.", escaped(s));
      return NULL;
    }
    cp = line;
    tor_strlower(line);
  } else { 
    cp = s;
  }

  eos = cp + strlen(cp);
  area = memarea_new();
  tok = get_next_token(area, &cp, eos, routerdesc_token_table);
  if (tok->tp == ERR_) {
    log_warn(LD_DIR, "Error reading address policy: %s", tok->error);
    goto err;
  }
  if (tok->tp != K_ACCEPT && tok->tp != K_ACCEPT6 && tok->tp != K_REJECT && tok->tp != K_REJECT6) {
    log_warn(LD_DIR, "Expected 'accept' or 'reject'.");
    goto err;
  }

  r = router_parse_addr_policy(tok, TAPMP_EXTENDED_STAR);
  goto done;
 err:
  r = NULL;
 done:
  token_clear(tok);
  if (area) {
    DUMP_AREA(area, "policy item");
    memarea_drop_all(area);
  }
  return r;
}


static int router_add_exit_policy(routerinfo_t *router, directory_token_t *tok)
{
  addr_policy_t *newe;
  newe = router_parse_addr_policy(tok, 0);
  if (!newe)
    return -1;
  if (! router->exit_policy)
    router->exit_policy = smartlist_new();

  if (((tok->tp == K_ACCEPT6 || tok->tp == K_REJECT6) && tor_addr_family(&newe->addr) == AF_INET)
      || ((tok->tp == K_ACCEPT || tok->tp == K_REJECT) && tor_addr_family(&newe->addr) == AF_INET6)) {

    log_warn(LD_DIR, "Mismatch between field type and address type in exit " "policy");
    addr_policy_free(newe);
    return -1;
  }

  smartlist_add(router->exit_policy, newe);

  return 0;
}


static addr_policy_t * router_parse_addr_policy(directory_token_t *tok, unsigned fmt_flags)
{
  addr_policy_t newe;
  char *arg;

  tor_assert(tok->tp == K_REJECT || tok->tp == K_REJECT6 || tok->tp == K_ACCEPT || tok->tp == K_ACCEPT6);

  if (tok->n_args != 1)
    return NULL;
  arg = tok->args[0];

  if (!strcmpstart(arg,"private"))
    return router_parse_addr_policy_private(tok);

  memset(&newe, 0, sizeof(newe));

  if (tok->tp == K_REJECT || tok->tp == K_REJECT6)
    newe.policy_type = ADDR_POLICY_REJECT;
  else newe.policy_type = ADDR_POLICY_ACCEPT;

  if (tor_addr_parse_mask_ports(arg, fmt_flags, &newe.addr, &newe.maskbits, &newe.prt_min, &newe.prt_max) < 0) {
    log_warn(LD_DIR,"Couldn't parse line %s. Dropping", escaped(arg));
    return NULL;
  }

  return addr_policy_get_canonical_entry(&newe);
}


static addr_policy_t * router_parse_addr_policy_private(directory_token_t *tok)
{
  const char *arg;
  uint16_t port_min, port_max;
  addr_policy_t result;

  arg = tok->args[0];
  if (strcmpstart(arg, "private"))
    return NULL;

  arg += strlen("private");
  arg = (char*) eat_whitespace(arg);
  if (!arg || *arg != ':')
    return NULL;

  if (parse_port_range(arg+1, &port_min, &port_max)<0)
    return NULL;

  memset(&result, 0, sizeof(result));
  if (tok->tp == K_REJECT || tok->tp == K_REJECT6)
    result.policy_type = ADDR_POLICY_REJECT;
  else result.policy_type = ADDR_POLICY_ACCEPT;
  result.is_private = 1;
  result.prt_min = port_min;
  result.prt_max = port_max;

  return addr_policy_get_canonical_entry(&result);
}


void assert_addr_policy_ok(smartlist_t *lst)
{
  if (!lst) return;
  SMARTLIST_FOREACH(lst, addr_policy_t *, t, {
    tor_assert(t->policy_type == ADDR_POLICY_REJECT || t->policy_type == ADDR_POLICY_ACCEPT);
    tor_assert(t->prt_min <= t->prt_max);
  });
}




static void token_clear(directory_token_t *tok)
{
  if (tok->key)
    crypto_pk_free(tok->key);
}















static INLINE directory_token_t * token_check_object(memarea_t *area, const char *kwd, directory_token_t *tok, obj_syntax o_syn)

{
  char ebuf[128];
  switch (o_syn) {
    case NO_OBJ:
      
      if (tok->object_body) {
        tor_snprintf(ebuf, sizeof(ebuf), "Unexpected object for %s", kwd);
        RET_ERR(ebuf);
      }
      if (tok->key) {
        tor_snprintf(ebuf, sizeof(ebuf), "Unexpected public key for %s", kwd);
        RET_ERR(ebuf);
      }
      break;
    case NEED_OBJ:
      
      if (!tok->object_body) {
        tor_snprintf(ebuf, sizeof(ebuf), "Missing object for %s", kwd);
        RET_ERR(ebuf);
      }
      break;
    case NEED_KEY_1024: 
    case NEED_SKEY_1024: 
      if (tok->key && crypto_pk_num_bits(tok->key) != PK_BYTES*8) {
        tor_snprintf(ebuf, sizeof(ebuf), "Wrong size on key for %s: %d bits", kwd, crypto_pk_num_bits(tok->key));
        RET_ERR(ebuf);
      }
      
    case NEED_KEY: 
      if (!tok->key) {
        tor_snprintf(ebuf, sizeof(ebuf), "Missing public key for %s", kwd);
        RET_ERR(ebuf);
      }
      if (o_syn != NEED_SKEY_1024) {
        if (crypto_pk_key_is_private(tok->key)) {
          tor_snprintf(ebuf, sizeof(ebuf), "Private key given for %s, which wants a public key", kwd);
          RET_ERR(ebuf);
        }
      } else { 
        if (!crypto_pk_key_is_private(tok->key)) {
          tor_snprintf(ebuf, sizeof(ebuf), "Public key given for %s, which wants a private key", kwd);
          RET_ERR(ebuf);
        }
      }
      break;
    case OBJ_OK:
      
      break;
  }

 done_tokenizing:
  return tok;
}


static INLINE int get_token_arguments(memarea_t *area, directory_token_t *tok, const char *s, const char *eol)

{


  char *mem = memarea_strndup(area, s, eol-s);
  char *cp = mem;
  int j = 0;
  char *args[MAX_ARGS];
  while (*cp) {
    if (j == MAX_ARGS)
      return -1;
    args[j++] = cp;
    cp = (char*)find_whitespace(cp);
    if (!cp || !*cp)
      break; 
    *cp++ = '\0';
    cp = (char*)eat_whitespace(cp);
  }
  tok->n_args = j;
  tok->args = memarea_memdup(area, args, j*sizeof(char*));
  return j;

}


static directory_token_t * get_next_token(memarea_t *area, const char **s, const char *eos, token_rule_t *table)

{
  

  


  const char *next, *eol, *obstart;
  size_t obname_len;
  int i;
  directory_token_t *tok;
  obj_syntax o_syn = NO_OBJ;
  char ebuf[128];
  const char *kwd = "";

  tor_assert(area);
  tok = ALLOC_ZERO(sizeof(directory_token_t));
  tok->tp = ERR_;

  
  *s = eat_whitespace_eos(*s, eos); 
  tor_assert(eos >= *s);
  eol = memchr(*s, '\n', eos-*s);
  if (!eol)
    eol = eos;
  if (eol - *s > MAX_LINE_LENGTH) {
    RET_ERR("Line far too long");
  }

  next = find_whitespace_eos(*s, eol);

  if (!strcmp_len(*s, "opt", next-*s)) {
    
    *s = eat_whitespace_eos_no_nl(next, eol);
    next = find_whitespace_eos(*s, eol);
  } else if (*s == eos) {  
    RET_ERR("Unexpected EOF");
  }

  
  for (i = 0; table[i].t ; ++i) {
    if (!strcmp_len(*s, table[i].t, next-*s)) {
      
      kwd = table[i].t;
      tok->tp = table[i].v;
      o_syn = table[i].os;
      *s = eat_whitespace_eos_no_nl(next, eol);
      
      if (table[i].concat_args) {
        
        tok->args = ALLOC(sizeof(char*));
        tok->args[0] = STRNDUP(*s,eol-*s); 
        tok->n_args = 1;
      } else {
        
        if (get_token_arguments(area, tok, *s, eol)<0) {
          tor_snprintf(ebuf, sizeof(ebuf),"Far too many arguments to %s", kwd);
          RET_ERR(ebuf);
        }
        *s = eol;
      }
      if (tok->n_args < table[i].min_args) {
        tor_snprintf(ebuf, sizeof(ebuf), "Too few arguments to %s", kwd);
        RET_ERR(ebuf);
      } else if (tok->n_args > table[i].max_args) {
        tor_snprintf(ebuf, sizeof(ebuf), "Too many arguments to %s", kwd);
        RET_ERR(ebuf);
      }
      break;
    }
  }

  if (tok->tp == ERR_) {
    
    if (**s == '@')
      tok->tp = A_UNKNOWN_;
    else tok->tp = K_OPT;
    tok->args = ALLOC(sizeof(char*));
    tok->args[0] = STRNDUP(*s, eol-*s);
    tok->n_args = 1;
    o_syn = OBJ_OK;
  }

  
  *s = eat_whitespace_eos(eol, eos);  
  tor_assert(eos >= *s);
  eol = memchr(*s, '\n', eos-*s);
  if (!eol || eol-*s<11 || strcmpstart(*s, "-----BEGIN ")) 
    goto check_object;

  obstart = *s; 
  if (*s+16 >= eol || memchr(*s+11,'\0',eol-*s-16) ||  strcmp_len(eol-5, "-----", 5) || (eol-*s) > MAX_UNPARSED_OBJECT_SIZE) {

    RET_ERR("Malformed object: bad begin line");
  }
  tok->object_type = STRNDUP(*s+11, eol-*s-16);
  obname_len = eol-*s-16; 
  *s = eol+1;    

  
  next = tor_memstr(*s, eos-*s, "-----END ");
  if (!next) {
    RET_ERR("Malformed object: missing object end line");
  }
  tor_assert(eos >= next);
  eol = memchr(next, '\n', eos-next);
  if (!eol)  
    eol = eos;
  
  if ((size_t)(eol-next) != 9+obname_len+5 || strcmp_len(next+9, tok->object_type, obname_len) || strcmp_len(eol-5, "-----", 5)) {

    tor_snprintf(ebuf, sizeof(ebuf), "Malformed object: mismatched end tag %s", tok->object_type);
    ebuf[sizeof(ebuf)-1] = '\0';
    RET_ERR(ebuf);
  }
  if (next - *s > MAX_UNPARSED_OBJECT_SIZE)
    RET_ERR("Couldn't parse object: missing footer or object much too big.");

  if (!strcmp(tok->object_type, "RSA PUBLIC KEY")) { 
    tok->key = crypto_pk_new();
    if (crypto_pk_read_public_key_from_string(tok->key, obstart, eol-obstart))
      RET_ERR("Couldn't parse public key.");
  } else if (!strcmp(tok->object_type, "RSA PRIVATE KEY")) { 
    tok->key = crypto_pk_new();
    if (crypto_pk_read_private_key_from_string(tok->key, obstart, eol-obstart))
      RET_ERR("Couldn't parse private key.");
  } else { 
    int r;
    tok->object_body = ALLOC(next-*s); 
    r = base64_decode(tok->object_body, next-*s, *s, next-*s);
    if (r<0)
      RET_ERR("Malformed object: bad base64-encoded data");
    tok->object_size = r;
  }
  *s = eol;

 check_object:
  tok = token_check_object(area, kwd, tok, o_syn);

 done_tokenizing:
  return tok;






}


static int tokenize_string(memarea_t *area, const char *start, const char *end, smartlist_t *out, token_rule_t *table, int flags)


{
  const char **s;
  directory_token_t *tok = NULL;
  int counts[NIL_];
  int i;
  int first_nonannotation;
  int prev_len = smartlist_len(out);
  tor_assert(area);

  s = &start;
  if (!end) {
    end = start+strlen(start);
  } else {
    
    if (memchr(start, '\0', end-start)) {
      log_warn(LD_DIR, "parse error: internal NUL character.");
      return -1;
    }
  }
  for (i = 0; i < NIL_; ++i)
    counts[i] = 0;

  SMARTLIST_FOREACH(out, const directory_token_t *, t, ++counts[t->tp]);

  while (*s < end && (!tok || tok->tp != EOF_)) {
    tok = get_next_token(area, s, end, table);
    if (tok->tp == ERR_) {
      log_warn(LD_DIR, "parse error: %s", tok->error);
      token_clear(tok);
      return -1;
    }
    ++counts[tok->tp];
    smartlist_add(out, tok);
    *s = eat_whitespace_eos(*s, end);
  }

  if (flags & TS_NOCHECK)
    return 0;

  if ((flags & TS_ANNOTATIONS_OK)) {
    first_nonannotation = -1;
    for (i = 0; i < smartlist_len(out); ++i) {
      tok = smartlist_get(out, i);
      if (tok->tp < MIN_ANNOTATION || tok->tp > MAX_ANNOTATION) {
        first_nonannotation = i;
        break;
      }
    }
    if (first_nonannotation < 0) {
      log_warn(LD_DIR, "parse error: item contains only annotations");
      return -1;
    }
    for (i=first_nonannotation;  i < smartlist_len(out); ++i) {
      tok = smartlist_get(out, i);
      if (tok->tp >= MIN_ANNOTATION && tok->tp <= MAX_ANNOTATION) {
        log_warn(LD_DIR, "parse error: Annotations mixed with keywords");
        return -1;
      }
    }
    if ((flags & TS_NO_NEW_ANNOTATIONS)) {
      if (first_nonannotation != prev_len) {
        log_warn(LD_DIR, "parse error: Unexpected annotations.");
        return -1;
      }
    }
  } else {
    for (i=0;  i < smartlist_len(out); ++i) {
      tok = smartlist_get(out, i);
      if (tok->tp >= MIN_ANNOTATION && tok->tp <= MAX_ANNOTATION) {
        log_warn(LD_DIR, "parse error: no annotations allowed.");
        return -1;
      }
    }
    first_nonannotation = 0;
  }
  for (i = 0; table[i].t; ++i) {
    if (counts[table[i].v] < table[i].min_cnt) {
      log_warn(LD_DIR, "Parse error: missing %s element.", table[i].t);
      return -1;
    }
    if (counts[table[i].v] > table[i].max_cnt) {
      log_warn(LD_DIR, "Parse error: too many %s elements.", table[i].t);
      return -1;
    }
    if (table[i].pos & AT_START) {
      if (smartlist_len(out) < 1 || (tok = smartlist_get(out, first_nonannotation))->tp != table[i].v) {
        log_warn(LD_DIR, "Parse error: first item is not %s.", table[i].t);
        return -1;
      }
    }
    if (table[i].pos & AT_END) {
      if (smartlist_len(out) < 1 || (tok = smartlist_get(out, smartlist_len(out)-1))->tp != table[i].v) {
        log_warn(LD_DIR, "Parse error: last item is not %s.", table[i].t);
        return -1;
      }
    }
  }
  return 0;
}


static directory_token_t * find_opt_by_keyword(smartlist_t *s, directory_keyword keyword)
{
  SMARTLIST_FOREACH(s, directory_token_t *, t, if (t->tp == keyword) return t);
  return NULL;
}


static directory_token_t * find_by_keyword_(smartlist_t *s, directory_keyword keyword, const char *keyword_as_string)

{
  directory_token_t *tok = find_opt_by_keyword(s, keyword);
  if (PREDICT_UNLIKELY(!tok)) {
    log_err(LD_BUG, "Missing %s [%d] in directory object that should have " "been validated. Internal error.", keyword_as_string, (int)keyword);
    tor_assert(tok);
  }
  return tok;
}


static smartlist_t * find_all_by_keyword(smartlist_t *s, directory_keyword k)
{
  smartlist_t *out = NULL;
  SMARTLIST_FOREACH(s, directory_token_t *, t, if (t->tp == k) {
                      if (!out)
                        out = smartlist_new();
                      smartlist_add(out, t);
                    });
  return out;
}


static smartlist_t * find_all_exitpolicy(smartlist_t *s)
{
  smartlist_t *out = smartlist_new();
  SMARTLIST_FOREACH(s, directory_token_t *, t, if (t->tp == K_ACCEPT || t->tp == K_ACCEPT6 || t->tp == K_REJECT || t->tp == K_REJECT6)

        smartlist_add(out,t));
  return out;
}


static int router_get_hash_impl_helper(const char *s, size_t s_len, const char *start_str, const char *end_str, char end_c, const char **start_out, const char **end_out)



{
  const char *start, *end;
  start = tor_memstr(s, s_len, start_str);
  if (!start) {
    log_warn(LD_DIR,"couldn't find start of hashed material \"%s\"",start_str);
    return -1;
  }
  if (start != s && *(start-1) != '\n') {
    log_warn(LD_DIR, "first occurrence of \"%s\" is not at the start of a line", start_str);

    return -1;
  }
  end = tor_memstr(start+strlen(start_str), s_len - (start-s) - strlen(start_str), end_str);
  if (!end) {
    log_warn(LD_DIR,"couldn't find end of hashed material \"%s\"",end_str);
    return -1;
  }
  end = memchr(end+strlen(end_str), end_c, s_len - (end-s) - strlen(end_str));
  if (!end) {
    log_warn(LD_DIR,"couldn't find EOL");
    return -1;
  }
  ++end;

  *start_out = start;
  *end_out = end;
  return 0;
}


static int router_get_hash_impl(const char *s, size_t s_len, char *digest, const char *start_str, const char *end_str, char end_c, digest_algorithm_t alg)



{
  const char *start=NULL, *end=NULL;
  if (router_get_hash_impl_helper(s,s_len,start_str,end_str,end_c, &start,&end)<0)
    return -1;

  if (alg == DIGEST_SHA1) {
    if (crypto_digest(digest, start, end-start)) {
      log_warn(LD_BUG,"couldn't compute digest");
      return -1;
    }
  } else {
    if (crypto_digest256(digest, start, end-start, alg)) {
      log_warn(LD_BUG,"couldn't compute digest");
      return -1;
    }
  }

  return 0;
}


static int router_get_hashes_impl(const char *s, size_t s_len, digests_t *digests, const char *start_str, const char *end_str, char end_c)


{
  const char *start=NULL, *end=NULL;
  if (router_get_hash_impl_helper(s,s_len,start_str,end_str,end_c, &start,&end)<0)
    return -1;

  if (crypto_digest_all(digests, start, end-start)) {
    log_warn(LD_BUG,"couldn't compute digests");
    return -1;
  }

  return 0;
}


static const char * find_start_of_next_microdesc(const char *s, const char *eos)
{
  int started_with_annotations;
  s = eat_whitespace_eos(s, eos);
  if (!s)
    return NULL;











  CHECK_LENGTH();

  started_with_annotations = (*s == '@');

  if (started_with_annotations) {
    
    while (*s == '@')
      NEXT_LINE();
  }
  CHECK_LENGTH();

  
  if (!strcmpstart(s, "onion-key"))
    NEXT_LINE();

  
  while (s+32 < eos) {
    if (*s == '@' || !strcmpstart(s, "onion-key"))
      return s;
    NEXT_LINE();
  }
  return NULL;



}


smartlist_t * microdescs_parse_from_string(const char *s, const char *eos, int allow_annotations, saved_location_t where)


{
  smartlist_t *tokens;
  smartlist_t *result;
  microdesc_t *md = NULL;
  memarea_t *area;
  const char *start = s;
  const char *start_of_next_microdesc;
  int flags = allow_annotations ? TS_ANNOTATIONS_OK : 0;
  const int copy_body = (where != SAVED_IN_CACHE);

  directory_token_t *tok;

  if (!eos)
    eos = s + strlen(s);

  s = eat_whitespace_eos(s, eos);
  area = memarea_new();
  result = smartlist_new();
  tokens = smartlist_new();

  while (s < eos) {
    start_of_next_microdesc = find_start_of_next_microdesc(s, eos);
    if (!start_of_next_microdesc)
      start_of_next_microdesc = eos;

    if (tokenize_string(area, s, start_of_next_microdesc, tokens, microdesc_token_table, flags)) {
      log_warn(LD_DIR, "Unparseable microdescriptor");
      goto next;
    }

    md = tor_malloc_zero(sizeof(microdesc_t));
    {
      const char *cp = tor_memstr(s, start_of_next_microdesc-s, "onion-key");
      tor_assert(cp);

      md->bodylen = start_of_next_microdesc - cp;
      md->saved_location = where;
      if (copy_body)
        md->body = tor_memdup_nulterm(cp, md->bodylen);
      else md->body = (char*)cp;
      md->off = cp - start;
    }

    if ((tok = find_opt_by_keyword(tokens, A_LAST_LISTED))) {
      if (parse_iso_time(tok->args[0], &md->last_listed)) {
        log_warn(LD_DIR, "Bad last-listed time in microdescriptor");
        goto next;
      }
    }

    tok = find_by_keyword(tokens, K_ONION_KEY);
    if (!crypto_pk_public_exponent_ok(tok->key)) {
      log_warn(LD_DIR, "Relay's onion key had invalid exponent.");
      goto next;
    }
    md->onion_pkey = tok->key;
    tok->key = NULL;

    if ((tok = find_opt_by_keyword(tokens, K_ONION_KEY_NTOR))) {
      curve25519_public_key_t k;
      tor_assert(tok->n_args >= 1);
      if (curve25519_public_from_base64(&k, tok->args[0]) < 0) {
        log_warn(LD_DIR, "Bogus ntor-onion-key in microdesc");
        goto next;
      }
      md->onion_curve25519_pkey = tor_memdup(&k, sizeof(curve25519_public_key_t));
    }

    {
      smartlist_t *a_lines = find_all_by_keyword(tokens, K_A);
      if (a_lines) {
        find_single_ipv6_orport(a_lines, &md->ipv6_addr, &md->ipv6_orport);
        smartlist_free(a_lines);
      }
    }

    if ((tok = find_opt_by_keyword(tokens, K_FAMILY))) {
      int i;
      md->family = smartlist_new();
      for (i=0;i<tok->n_args;++i) {
        if (!is_legal_nickname_or_hexdigest(tok->args[i])) {
          log_warn(LD_DIR, "Illegal nickname %s in family line", escaped(tok->args[i]));
          goto next;
        }
        smartlist_add(md->family, tor_strdup(tok->args[i]));
      }
    }

    if ((tok = find_opt_by_keyword(tokens, K_P))) {
      md->exit_policy = parse_short_policy(tok->args[0]);
    }
    if ((tok = find_opt_by_keyword(tokens, K_P6))) {
      md->ipv6_exit_policy = parse_short_policy(tok->args[0]);
    }

    crypto_digest256(md->digest, md->body, md->bodylen, DIGEST_SHA256);

    smartlist_add(result, md);

    md = NULL;
  next:
    microdesc_free(md);
    md = NULL;

    SMARTLIST_FOREACH(tokens, directory_token_t *, t, token_clear(t));
    memarea_clear(area);
    smartlist_clear(tokens);
    s = start_of_next_microdesc;
  }

  SMARTLIST_FOREACH(tokens, directory_token_t *, t, token_clear(t));
  memarea_drop_all(area);
  smartlist_free(tokens);

  return result;
}


int tor_version_supports_microdescriptors(const char *platform)
{
  return tor_version_as_new_as(platform, "0.2.3.1-alpha");
}


int tor_version_as_new_as(const char *platform, const char *cutoff)
{
  tor_version_t cutoff_version, router_version;
  char *s, *s2, *start;
  char tmp[128];

  tor_assert(platform);

  if (tor_version_parse(cutoff, &cutoff_version)<0) {
    log_warn(LD_BUG,"cutoff version '%s' unparseable.",cutoff);
    return 0;
  }
  if (strcmpstart(platform,"Tor ")) 
    return 1;

  start = (char *)eat_whitespace(platform+3);
  if (!*start) return 0;
  s = (char *)find_whitespace(start); 
  s2 = (char*)eat_whitespace(s);
  if (!strcmpstart(s2, "(r") || !strcmpstart(s2, "(git-"))
    s = (char*)find_whitespace(s2);

  if ((size_t)(s-start+1) >= sizeof(tmp)) 
    return 0;
  strlcpy(tmp, start, s-start+1);

  if (tor_version_parse(tmp, &router_version)<0) {
    log_info(LD_DIR,"Router version '%s' unparseable.",tmp);
    return 1; 
  }

  

  return tor_version_compare(&router_version, &cutoff_version) >= 0;
}


int tor_version_parse(const char *s, tor_version_t *out)
{
  char *eos=NULL;
  const char *cp=NULL;
  
  tor_assert(s);
  tor_assert(out);

  memset(out, 0, sizeof(tor_version_t));

  if (!strcasecmpstart(s, "Tor "))
    s += 4;

  
  out->major = (int)strtol(s,&eos,10);
  if (!eos || eos==s || *eos != '.') return -1;
  cp = eos+1;

  
  out->minor = (int) strtol(cp,&eos,10);
  if (!eos || eos==cp || *eos != '.') return -1;
  cp = eos+1;

  
  out->micro = (int) strtol(cp,&eos,10);
  if (!eos || eos==cp) return -1;
  if (!*eos) {
    out->status = VER_RELEASE;
    out->patchlevel = 0;
    return 0;
  }
  cp = eos;

  
  if (*cp == '.') {
    out->status = VER_RELEASE;
    ++cp;
  } else if (0==strncmp(cp, "pre", 3)) {
    out->status = VER_PRE;
    cp += 3;
  } else if (0==strncmp(cp, "rc", 2)) {
    out->status = VER_RC;
    cp += 2;
  } else {
    return -1;
  }

  
  out->patchlevel = (int) strtol(cp,&eos,10);
  if (!eos || eos==cp) return -1;
  cp = eos;

  
  if (*cp == '-' || *cp == '.')
    ++cp;
  eos = (char*) find_whitespace(cp);
  if (eos-cp >= (int)sizeof(out->status_tag))
    strlcpy(out->status_tag, cp, sizeof(out->status_tag));
  else {
    memcpy(out->status_tag, cp, eos-cp);
    out->status_tag[eos-cp] = 0;
  }
  cp = eat_whitespace(eos);

  if (!strcmpstart(cp, "(r")) {
    cp += 2;
    out->svn_revision = (int) strtol(cp,&eos,10);
  } else if (!strcmpstart(cp, "(git-")) {
    char *close_paren = strchr(cp, ')');
    int hexlen;
    char digest[DIGEST_LEN];
    if (! close_paren)
      return -1;
    cp += 5;
    if (close_paren-cp > HEX_DIGEST_LEN)
      return -1;
    hexlen = (int)(close_paren-cp);
    memwipe(digest, 0, sizeof(digest));
    if ( hexlen == 0 || (hexlen % 2) == 1)
      return -1;
    if (base16_decode(digest, hexlen/2, cp, hexlen))
      return -1;
    memcpy(out->git_tag, digest, hexlen/2);
    out->git_tag_len = hexlen/2;
  }

  return 0;
}


int tor_version_compare(tor_version_t *a, tor_version_t *b)
{
  int i;
  tor_assert(a);
  tor_assert(b);
  if ((i = a->major - b->major))
    return i;
  else if ((i = a->minor - b->minor))
    return i;
  else if ((i = a->micro - b->micro))
    return i;
  else if ((i = a->status - b->status))
    return i;
  else if ((i = a->patchlevel - b->patchlevel))
    return i;
  else if ((i = strcmp(a->status_tag, b->status_tag)))
    return i;
  else if ((i = a->svn_revision - b->svn_revision))
    return i;
  else if ((i = a->git_tag_len - b->git_tag_len))
    return i;
  else if (a->git_tag_len)
    return fast_memcmp(a->git_tag, b->git_tag, a->git_tag_len);
  else return 0;
}


int tor_version_same_series(tor_version_t *a, tor_version_t *b)
{
  tor_assert(a);
  tor_assert(b);
  return ((a->major == b->major) && (a->minor == b->minor) && (a->micro == b->micro));

}


static int compare_tor_version_str_ptr_(const void **_a, const void **_b)
{
  const char *a = *_a, *b = *_b;
  int ca, cb;
  tor_version_t va, vb;
  ca = tor_version_parse(a, &va);
  cb = tor_version_parse(b, &vb);
  
  if (!ca && !cb)
    return tor_version_compare(&va,&vb);
  
  if (!ca && cb)
    return -1;
  if (ca && !cb)
    return 1;
  
  return strcmp(a,b);
}


void sort_version_list(smartlist_t *versions, int remove_duplicates)
{
  smartlist_sort(versions, compare_tor_version_str_ptr_);

  if (remove_duplicates)
    smartlist_uniq(versions, compare_tor_version_str_ptr_, tor_free_);
}


int rend_parse_v2_service_descriptor(rend_service_descriptor_t **parsed_out, char *desc_id_out, char **intro_points_encrypted_out, size_t *intro_points_encrypted_size_out, size_t *encoded_size_out, const char **next_out, const char *desc)





{
  rend_service_descriptor_t *result = tor_malloc_zero(sizeof(rend_service_descriptor_t));
  char desc_hash[DIGEST_LEN];
  const char *eos;
  smartlist_t *tokens = smartlist_new();
  directory_token_t *tok;
  char secret_id_part[DIGEST_LEN];
  int i, version, num_ok=1;
  smartlist_t *versions;
  char public_key_hash[DIGEST_LEN];
  char test_desc_id[DIGEST_LEN];
  memarea_t *area = NULL;
  tor_assert(desc);
  
  if (strncmp(desc, "rendezvous-service-descriptor ", strlen("rendezvous-service-descriptor "))) {
    log_info(LD_REND, "Descriptor does not start correctly.");
    goto err;
  }
  
  if (router_get_hash_impl(desc, strlen(desc), desc_hash, "rendezvous-service-descriptor ", "\nsignature", '\n', DIGEST_SHA1) < 0) {

    log_warn(LD_REND, "Couldn't compute descriptor hash.");
    goto err;
  }
  
  eos = strstr(desc, "\nrendezvous-service-descriptor ");
  if (!eos)
    eos = desc + strlen(desc);
  else eos = eos + 1;
  
  if (eos-desc > REND_DESC_MAX_SIZE) {
    
    log_warn(LD_REND, "Descriptor length is %d which exceeds " "maximum rendezvous descriptor size of %d bytes.", (int)(eos-desc), REND_DESC_MAX_SIZE);

    goto err;
  }
  
  area = memarea_new();
  if (tokenize_string(area, desc, eos, tokens, desc_token_table, 0)) {
    log_warn(LD_REND, "Error tokenizing descriptor.");
    goto err;
  }
  
  *next_out = eos;
  
  *encoded_size_out = eos - desc;
  
  if (smartlist_len(tokens) < 7) {
    log_warn(LD_REND, "Impossibly short descriptor.");
    goto err;
  }
  
  tok = find_by_keyword(tokens, R_RENDEZVOUS_SERVICE_DESCRIPTOR);
  tor_assert(tok == smartlist_get(tokens, 0));
  tor_assert(tok->n_args == 1);
  if (strlen(tok->args[0]) != REND_DESC_ID_V2_LEN_BASE32 || strspn(tok->args[0], BASE32_CHARS) != REND_DESC_ID_V2_LEN_BASE32) {
    log_warn(LD_REND, "Invalid descriptor ID: '%s'", tok->args[0]);
    goto err;
  }
  if (base32_decode(desc_id_out, DIGEST_LEN, tok->args[0], REND_DESC_ID_V2_LEN_BASE32) < 0) {
    log_warn(LD_REND, "Descriptor ID contains illegal characters: %s", tok->args[0]);
    goto err;
  }
  
  tok = find_by_keyword(tokens, R_VERSION);
  tor_assert(tok->n_args == 1);
  result->version = (int) tor_parse_long(tok->args[0], 10, 0, INT_MAX, &num_ok, NULL);
  if (result->version != 2 || !num_ok) {
    
    log_warn(LD_REND, "Unrecognized descriptor version: %s", escaped(tok->args[0]));
    goto err;
  }
  
  tok = find_by_keyword(tokens, R_PERMANENT_KEY);
  result->pk = tok->key;
  tok->key = NULL; 
  
  tok = find_by_keyword(tokens, R_SECRET_ID_PART);
  tor_assert(tok->n_args == 1);
  if (strlen(tok->args[0]) != REND_SECRET_ID_PART_LEN_BASE32 || strspn(tok->args[0], BASE32_CHARS) != REND_SECRET_ID_PART_LEN_BASE32) {
    log_warn(LD_REND, "Invalid secret ID part: '%s'", tok->args[0]);
    goto err;
  }
  if (base32_decode(secret_id_part, DIGEST_LEN, tok->args[0], 32) < 0) {
    log_warn(LD_REND, "Secret ID part contains illegal characters: %s", tok->args[0]);
    goto err;
  }
  
  tok = find_by_keyword(tokens, R_PUBLICATION_TIME);
  tor_assert(tok->n_args == 1);
  if (parse_iso_time(tok->args[0], &result->timestamp) < 0) {
    log_warn(LD_REND, "Invalid publication time: '%s'", tok->args[0]);
    goto err;
  }
  
  tok = find_by_keyword(tokens, R_PROTOCOL_VERSIONS);
  tor_assert(tok->n_args == 1);
  versions = smartlist_new();
  smartlist_split_string(versions, tok->args[0], ",", SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
  for (i = 0; i < smartlist_len(versions); i++) {
    version = (int) tor_parse_long(smartlist_get(versions, i), 10, 0, INT_MAX, &num_ok, NULL);
    if (!num_ok) 
      continue;
    if (version >= REND_PROTOCOL_VERSION_BITMASK_WIDTH)
      
      continue;
    result->protocols |= 1 << version;
  }
  SMARTLIST_FOREACH(versions, char *, cp, tor_free(cp));
  smartlist_free(versions);
  
  tok = find_opt_by_keyword(tokens, R_INTRODUCTION_POINTS);
  if (tok) {
    if (strcmp(tok->object_type, "MESSAGE")) {
      log_warn(LD_DIR, "Bad object type: introduction points should be of " "type MESSAGE");
      goto err;
    }
    *intro_points_encrypted_out = tor_memdup(tok->object_body, tok->object_size);
    *intro_points_encrypted_size_out = tok->object_size;
  } else {
    *intro_points_encrypted_out = NULL;
    *intro_points_encrypted_size_out = 0;
  }
  
  tok = find_by_keyword(tokens, R_SIGNATURE);
  note_crypto_pk_op(VERIFY_RTR);
  if (check_signature_token(desc_hash, DIGEST_LEN, tok, result->pk, 0, "v2 rendezvous service descriptor") < 0)
    goto err;
  
  crypto_pk_get_digest(result->pk, public_key_hash);
  rend_get_descriptor_id_bytes(test_desc_id, public_key_hash, secret_id_part);
  if (tor_memneq(desc_id_out, test_desc_id, DIGEST_LEN)) {
    log_warn(LD_REND, "Parsed descriptor ID does not match " "computed descriptor ID.");
    goto err;
  }
  goto done;
 err:
  rend_service_descriptor_free(result);
  result = NULL;
 done:
  if (tokens) {
    SMARTLIST_FOREACH(tokens, directory_token_t *, t, token_clear(t));
    smartlist_free(tokens);
  }
  if (area)
    memarea_drop_all(area);
  *parsed_out = result;
  if (result)
    return 0;
  return -1;
}


int rend_decrypt_introduction_points(char **ipos_decrypted, size_t *ipos_decrypted_size, const char *descriptor_cookie, const char *ipos_encrypted, size_t ipos_encrypted_size)




{
  tor_assert(ipos_encrypted);
  tor_assert(descriptor_cookie);
  if (ipos_encrypted_size < 2) {
    log_warn(LD_REND, "Size of encrypted introduction points is too " "small.");
    return -1;
  }
  if (ipos_encrypted[0] == (int)REND_BASIC_AUTH) {
    char iv[CIPHER_IV_LEN], client_id[REND_BASIC_AUTH_CLIENT_ID_LEN], session_key[CIPHER_KEY_LEN], *dec;
    int declen, client_blocks;
    size_t pos = 0, len, client_entries_len;
    crypto_digest_t *digest;
    crypto_cipher_t *cipher;
    client_blocks = (int) ipos_encrypted[1];
    client_entries_len = client_blocks * REND_BASIC_AUTH_CLIENT_MULTIPLE * REND_BASIC_AUTH_CLIENT_ENTRY_LEN;
    if (ipos_encrypted_size < 2 + client_entries_len + CIPHER_IV_LEN + 1) {
      log_warn(LD_REND, "Size of encrypted introduction points is too " "small.");
      return -1;
    }
    memcpy(iv, ipos_encrypted + 2 + client_entries_len, CIPHER_IV_LEN);
    digest = crypto_digest_new();
    crypto_digest_add_bytes(digest, descriptor_cookie, REND_DESC_COOKIE_LEN);
    crypto_digest_add_bytes(digest, iv, CIPHER_IV_LEN);
    crypto_digest_get_digest(digest, client_id, REND_BASIC_AUTH_CLIENT_ID_LEN);
    crypto_digest_free(digest);
    for (pos = 2; pos < 2 + client_entries_len;
         pos += REND_BASIC_AUTH_CLIENT_ENTRY_LEN) {
      if (tor_memeq(ipos_encrypted + pos, client_id, REND_BASIC_AUTH_CLIENT_ID_LEN)) {
        
        cipher = crypto_cipher_new(descriptor_cookie);
        if (crypto_cipher_decrypt(cipher, session_key, ipos_encrypted + pos + REND_BASIC_AUTH_CLIENT_ID_LEN, CIPHER_KEY_LEN) < 0) {

          log_warn(LD_REND, "Could not decrypt session key for client.");
          crypto_cipher_free(cipher);
          return -1;
        }
        crypto_cipher_free(cipher);

        len = ipos_encrypted_size - 2 - client_entries_len - CIPHER_IV_LEN;
        dec = tor_malloc(len);
        declen = crypto_cipher_decrypt_with_iv(session_key, dec, len, ipos_encrypted + 2 + client_entries_len, ipos_encrypted_size - 2 - client_entries_len);


        if (declen < 0) {
          log_warn(LD_REND, "Could not decrypt introduction point string.");
          tor_free(dec);
          return -1;
        }
        if (fast_memcmpstart(dec, declen, "introduction-point ")) {
          log_warn(LD_REND, "Decrypted introduction points don't " "look like we could parse them.");
          tor_free(dec);
          continue;
        }
        *ipos_decrypted = dec;
        *ipos_decrypted_size = declen;
        return 0;
      }
    }
    log_warn(LD_REND, "Could not decrypt introduction points. Please " "check your authorization for this service!");
    return -1;
  } else if (ipos_encrypted[0] == (int)REND_STEALTH_AUTH) {
    char *dec;
    int declen;
    if (ipos_encrypted_size < CIPHER_IV_LEN + 2) {
      log_warn(LD_REND, "Size of encrypted introduction points is too " "small.");
      return -1;
    }
    dec = tor_malloc_zero(ipos_encrypted_size - CIPHER_IV_LEN - 1);

    declen = crypto_cipher_decrypt_with_iv(descriptor_cookie, dec, ipos_encrypted_size - CIPHER_IV_LEN - 1, ipos_encrypted + 1, ipos_encrypted_size - 1);




    if (declen < 0) {
      log_warn(LD_REND, "Decrypting introduction points failed!");
      tor_free(dec);
      return -1;
    }
    *ipos_decrypted = dec;
    *ipos_decrypted_size = declen;
    return 0;
  } else {
    log_warn(LD_REND, "Unknown authorization type number: %d", ipos_encrypted[0]);
    return -1;
  }
}


int rend_parse_introduction_points(rend_service_descriptor_t *parsed, const char *intro_points_encoded, size_t intro_points_encoded_size)


{
  const char *current_ipo, *end_of_intro_points;
  smartlist_t *tokens = NULL;
  directory_token_t *tok;
  rend_intro_point_t *intro;
  extend_info_t *info;
  int result, num_ok=1;
  memarea_t *area = NULL;
  tor_assert(parsed);
  
  tor_assert(!parsed->intro_nodes);
  if (!intro_points_encoded || intro_points_encoded_size == 0) {
    log_warn(LD_REND, "Empty or zero size introduction point list");
    goto err;
  }
  
  current_ipo = intro_points_encoded;
  end_of_intro_points = intro_points_encoded + intro_points_encoded_size;
  tokens = smartlist_new();
  parsed->intro_nodes = smartlist_new();
  area = memarea_new();

  while (!fast_memcmpstart(current_ipo, end_of_intro_points-current_ipo, "introduction-point ")) {
    
    const char *eos = tor_memstr(current_ipo, end_of_intro_points-current_ipo, "\nintroduction-point ");
    if (!eos)
      eos = end_of_intro_points;
    else eos = eos+1;
    tor_assert(eos <= intro_points_encoded+intro_points_encoded_size);
    
    SMARTLIST_FOREACH(tokens, directory_token_t *, t, token_clear(t));
    smartlist_clear(tokens);
    memarea_clear(area);
    
    if (tokenize_string(area, current_ipo, eos, tokens, ipo_token_table, 0)) {
      log_warn(LD_REND, "Error tokenizing introduction point");
      goto err;
    }
    
    current_ipo = eos;
    
    if (smartlist_len(tokens) < 5) {
      log_warn(LD_REND, "Impossibly short introduction point.");
      goto err;
    }
    
    intro = tor_malloc_zero(sizeof(rend_intro_point_t));
    info = intro->extend_info = tor_malloc_zero(sizeof(extend_info_t));
    
    tok = find_by_keyword(tokens, R_IPO_IDENTIFIER);
    if (base32_decode(info->identity_digest, DIGEST_LEN, tok->args[0], REND_INTRO_POINT_ID_LEN_BASE32) < 0) {
      log_warn(LD_REND, "Identity digest contains illegal characters: %s", tok->args[0]);
      rend_intro_point_free(intro);
      goto err;
    }
    
    info->nickname[0] = '$';
    base16_encode(info->nickname + 1, sizeof(info->nickname) - 1, info->identity_digest, DIGEST_LEN);
    
    tok = find_by_keyword(tokens, R_IPO_IP_ADDRESS);
    if (tor_addr_parse(&info->addr, tok->args[0])<0) {
      log_warn(LD_REND, "Could not parse introduction point address.");
      rend_intro_point_free(intro);
      goto err;
    }
    if (tor_addr_family(&info->addr) != AF_INET) {
      log_warn(LD_REND, "Introduction point address was not ipv4.");
      rend_intro_point_free(intro);
      goto err;
    }

    
    tok = find_by_keyword(tokens, R_IPO_ONION_PORT);
    info->port = (uint16_t) tor_parse_long(tok->args[0],10,1,65535, &num_ok,NULL);
    if (!info->port || !num_ok) {
      log_warn(LD_REND, "Introduction point onion port %s is invalid", escaped(tok->args[0]));
      rend_intro_point_free(intro);
      goto err;
    }
    
    tok = find_by_keyword(tokens, R_IPO_ONION_KEY);
    if (!crypto_pk_public_exponent_ok(tok->key)) {
      log_warn(LD_REND, "Introduction point's onion key had invalid exponent.");
      rend_intro_point_free(intro);
      goto err;
    }
    info->onion_key = tok->key;
    tok->key = NULL; 
    
    tok = find_by_keyword(tokens, R_IPO_SERVICE_KEY);
    if (!crypto_pk_public_exponent_ok(tok->key)) {
      log_warn(LD_REND, "Introduction point key had invalid exponent.");
      rend_intro_point_free(intro);
      goto err;
    }
    intro->intro_key = tok->key;
    tok->key = NULL; 
    
    smartlist_add(parsed->intro_nodes, intro);
  }
  result = smartlist_len(parsed->intro_nodes);
  goto done;

 err:
  result = -1;

 done:
  
  if (tokens) {
    SMARTLIST_FOREACH(tokens, directory_token_t *, t, token_clear(t));
    smartlist_free(tokens);
  }
  if (area)
    memarea_drop_all(area);

  return result;
}


int rend_parse_client_keys(strmap_t *parsed_clients, const char *ckstr)
{
  int result = -1;
  smartlist_t *tokens;
  directory_token_t *tok;
  const char *current_entry = NULL;
  memarea_t *area = NULL;
  if (!ckstr || strlen(ckstr) == 0)
    return -1;
  tokens = smartlist_new();
  
  area = memarea_new();
  current_entry = eat_whitespace(ckstr);
  while (!strcmpstart(current_entry, "client-name ")) {
    rend_authorized_client_t *parsed_entry;
    size_t len;
    char descriptor_cookie_tmp[REND_DESC_COOKIE_LEN+2];
    
    const char *eos = strstr(current_entry, "\nclient-name ");
    if (!eos)
      eos = current_entry + strlen(current_entry);
    else eos = eos + 1;
    
    SMARTLIST_FOREACH(tokens, directory_token_t *, t, token_clear(t));
    smartlist_clear(tokens);
    memarea_clear(area);
    
    if (tokenize_string(area, current_entry, eos, tokens, client_keys_token_table, 0)) {
      log_warn(LD_REND, "Error tokenizing client keys file.");
      goto err;
    }
    
    current_entry = eos;
    
    if (smartlist_len(tokens) < 2) {
      log_warn(LD_REND, "Impossibly short client key entry.");
      goto err;
    }
    
    tok = find_by_keyword(tokens, C_CLIENT_NAME);
    tor_assert(tok == smartlist_get(tokens, 0));
    tor_assert(tok->n_args == 1);

    len = strlen(tok->args[0]);
    if (len < 1 || len > 19 || strspn(tok->args[0], REND_LEGAL_CLIENTNAME_CHARACTERS) != len) {
      log_warn(LD_CONFIG, "Illegal client name: %s. (Length must be " "between 1 and 19, and valid characters are " "[A-Za-z0-9+-_].)", tok->args[0]);

      goto err;
    }
    
    if (strmap_get(parsed_clients, tok->args[0])) {
      log_warn(LD_CONFIG, "HiddenServiceAuthorizeClient contains a " "duplicate client name: '%s'. Ignoring.", tok->args[0]);
      goto err;
    }
    parsed_entry = tor_malloc_zero(sizeof(rend_authorized_client_t));
    parsed_entry->client_name = tor_strdup(tok->args[0]);
    strmap_set(parsed_clients, parsed_entry->client_name, parsed_entry);
    
    tok = find_opt_by_keyword(tokens, C_CLIENT_KEY);
    if (tok) {
      parsed_entry->client_key = tok->key;
      tok->key = NULL; 
    }

    
    tok = find_by_keyword(tokens, C_DESCRIPTOR_COOKIE);
    tor_assert(tok->n_args == 1);
    if (strlen(tok->args[0]) != REND_DESC_COOKIE_LEN_BASE64 + 2) {
      log_warn(LD_REND, "Descriptor cookie has illegal length: %s", escaped(tok->args[0]));
      goto err;
    }
    
    if (base64_decode(descriptor_cookie_tmp, sizeof(descriptor_cookie_tmp), tok->args[0], strlen(tok->args[0]))
        != REND_DESC_COOKIE_LEN) {
      log_warn(LD_REND, "Descriptor cookie contains illegal characters: " "%s", escaped(tok->args[0]));
      goto err;
    }
    memcpy(parsed_entry->descriptor_cookie, descriptor_cookie_tmp, REND_DESC_COOKIE_LEN);
  }
  result = strmap_size(parsed_clients);
  goto done;
 err:
  result = -1;
 done:
  
  SMARTLIST_FOREACH(tokens, directory_token_t *, t, token_clear(t));
  smartlist_free(tokens);
  if (area)
    memarea_drop_all(area);
  return result;
}

