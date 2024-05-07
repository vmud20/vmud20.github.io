























































PRFileDesc *PR_ImportTCPSocket(PRInt32 osfd);
static PRLock *nss_initlock = NULL;
static PRLock *nss_crllock = NULL;
static PRLock *nss_findslot_lock = NULL;
static struct curl_llist nss_crl_list;
static NSSInitContext *nss_context = NULL;
static volatile int initialized = 0;

typedef struct {
  const char *name;
  int num;
} cipher_s;










static const cipher_s cipherlist[] = {
  
  {"rc4",                        SSL_EN_RC4_128_WITH_MD5}, {"rc4-md5",                    SSL_EN_RC4_128_WITH_MD5}, {"rc4export",                  SSL_EN_RC4_128_EXPORT40_WITH_MD5}, {"rc2",                        SSL_EN_RC2_128_CBC_WITH_MD5}, {"rc2export",                  SSL_EN_RC2_128_CBC_EXPORT40_WITH_MD5}, {"des",                        SSL_EN_DES_64_CBC_WITH_MD5}, {"desede3",                    SSL_EN_DES_192_EDE3_CBC_WITH_MD5},  {"rsa_rc4_128_md5",            SSL_RSA_WITH_RC4_128_MD5}, {"rsa_rc4_128_sha",            SSL_RSA_WITH_RC4_128_SHA}, {"rsa_3des_sha",               SSL_RSA_WITH_3DES_EDE_CBC_SHA}, {"rsa_des_sha",                SSL_RSA_WITH_DES_CBC_SHA}, {"rsa_rc4_40_md5",             SSL_RSA_EXPORT_WITH_RC4_40_MD5}, {"rsa_rc2_40_md5",             SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5}, {"rsa_null_md5",               SSL_RSA_WITH_NULL_MD5}, {"rsa_null_sha",               SSL_RSA_WITH_NULL_SHA}, {"fips_3des_sha",              SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA}, {"fips_des_sha",               SSL_RSA_FIPS_WITH_DES_CBC_SHA}, {"fortezza",                   SSL_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA}, {"fortezza_rc4_128_sha",       SSL_FORTEZZA_DMS_WITH_RC4_128_SHA}, {"fortezza_null",              SSL_FORTEZZA_DMS_WITH_NULL_SHA},  {"rsa_des_56_sha",             TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA}, {"rsa_rc4_56_sha",             TLS_RSA_EXPORT1024_WITH_RC4_56_SHA},  {"dhe_dss_aes_128_cbc_sha",    TLS_DHE_DSS_WITH_AES_128_CBC_SHA}, {"dhe_dss_aes_256_cbc_sha",    TLS_DHE_DSS_WITH_AES_256_CBC_SHA}, {"dhe_rsa_aes_128_cbc_sha",    TLS_DHE_RSA_WITH_AES_128_CBC_SHA}, {"dhe_rsa_aes_256_cbc_sha",    TLS_DHE_RSA_WITH_AES_256_CBC_SHA}, {"rsa_aes_128_sha",            TLS_RSA_WITH_AES_128_CBC_SHA}, {"rsa_aes_256_sha",            TLS_RSA_WITH_AES_256_CBC_SHA},  {"ecdh_ecdsa_null_sha",        TLS_ECDH_ECDSA_WITH_NULL_SHA}, {"ecdh_ecdsa_rc4_128_sha",     TLS_ECDH_ECDSA_WITH_RC4_128_SHA}, {"ecdh_ecdsa_3des_sha",        TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA}, {"ecdh_ecdsa_aes_128_sha",     TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA}, {"ecdh_ecdsa_aes_256_sha",     TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA}, {"ecdhe_ecdsa_null_sha",       TLS_ECDHE_ECDSA_WITH_NULL_SHA}, {"ecdhe_ecdsa_rc4_128_sha",    TLS_ECDHE_ECDSA_WITH_RC4_128_SHA}, {"ecdhe_ecdsa_3des_sha",       TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA}, {"ecdhe_ecdsa_aes_128_sha",    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA}, {"ecdhe_ecdsa_aes_256_sha",    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA}, {"ecdh_rsa_null_sha",          TLS_ECDH_RSA_WITH_NULL_SHA}, {"ecdh_rsa_128_sha",           TLS_ECDH_RSA_WITH_RC4_128_SHA}, {"ecdh_rsa_3des_sha",          TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA}, {"ecdh_rsa_aes_128_sha",       TLS_ECDH_RSA_WITH_AES_128_CBC_SHA}, {"ecdh_rsa_aes_256_sha",       TLS_ECDH_RSA_WITH_AES_256_CBC_SHA}, {"ecdhe_rsa_null",             TLS_ECDHE_RSA_WITH_NULL_SHA}, {"ecdhe_rsa_rc4_128_sha",      TLS_ECDHE_RSA_WITH_RC4_128_SHA}, {"ecdhe_rsa_3des_sha",         TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA}, {"ecdhe_rsa_aes_128_sha",      TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA}, {"ecdhe_rsa_aes_256_sha",      TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA}, {"ecdh_anon_null_sha",         TLS_ECDH_anon_WITH_NULL_SHA}, {"ecdh_anon_rc4_128sha",       TLS_ECDH_anon_WITH_RC4_128_SHA}, {"ecdh_anon_3des_sha",         TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA}, {"ecdh_anon_aes_128_sha",      TLS_ECDH_anon_WITH_AES_128_CBC_SHA}, {"ecdh_anon_aes_256_sha",      TLS_ECDH_anon_WITH_AES_256_CBC_SHA},   {"rsa_null_sha_256",                TLS_RSA_WITH_NULL_SHA256}, {"rsa_aes_128_cbc_sha_256",         TLS_RSA_WITH_AES_128_CBC_SHA256}, {"rsa_aes_256_cbc_sha_256",         TLS_RSA_WITH_AES_256_CBC_SHA256}, {"dhe_rsa_aes_128_cbc_sha_256",     TLS_DHE_RSA_WITH_AES_128_CBC_SHA256}, {"dhe_rsa_aes_256_cbc_sha_256",     TLS_DHE_RSA_WITH_AES_256_CBC_SHA256}, {"ecdhe_ecdsa_aes_128_cbc_sha_256", TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256}, {"ecdhe_rsa_aes_128_cbc_sha_256",   TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256},    {"rsa_aes_128_gcm_sha_256",         TLS_RSA_WITH_AES_128_GCM_SHA256}, {"dhe_rsa_aes_128_gcm_sha_256",     TLS_DHE_RSA_WITH_AES_128_GCM_SHA256}, {"dhe_dss_aes_128_gcm_sha_256",     TLS_DHE_DSS_WITH_AES_128_GCM_SHA256}, {"ecdhe_ecdsa_aes_128_gcm_sha_256", TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}, {"ecdh_ecdsa_aes_128_gcm_sha_256",  TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256}, {"ecdhe_rsa_aes_128_gcm_sha_256",   TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}, {"ecdh_rsa_aes_128_gcm_sha_256",    TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256},    {"rsa_aes_256_gcm_sha_384",         TLS_RSA_WITH_AES_256_GCM_SHA384}, {"dhe_rsa_aes_256_gcm_sha_384",     TLS_DHE_RSA_WITH_AES_256_GCM_SHA384}, {"dhe_dss_aes_256_gcm_sha_384",     TLS_DHE_DSS_WITH_AES_256_GCM_SHA384}, {"ecdhe_ecdsa_aes_256_sha_384",     TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384}, {"ecdhe_rsa_aes_256_sha_384",       TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384}, {"ecdhe_ecdsa_aes_256_gcm_sha_384", TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384}, {"ecdhe_rsa_aes_256_gcm_sha_384",   TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384},    {"ecdhe_rsa_chacha20_poly1305_sha_256", TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256}, {"ecdhe_ecdsa_chacha20_poly1305_sha_256", TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256}, {"dhe_rsa_chacha20_poly1305_sha_256", TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256},  };
































































































static const char *pem_library = "libnsspem.so";
static SECMODModule *mod = NULL;


static PRDescIdentity nspr_io_identity = PR_INVALID_IO_LAYER;
static PRIOMethods nspr_io_methods;

static const char *nss_error_to_name(PRErrorCode code)
{
  const char *name = PR_ErrorToName(code);
  if(name)
    return name;

  return "unknown error";
}

static void nss_print_error_message(struct Curl_easy *data, PRUint32 err)
{
  failf(data, "%s", PR_ErrorToString(err, PR_LANGUAGE_I_DEFAULT));
}

static SECStatus set_ciphers(struct Curl_easy *data, PRFileDesc * model, char *cipher_list)
{
  unsigned int i;
  PRBool cipher_state[NUM_OF_CIPHERS];
  PRBool found;
  char *cipher;

  
  const PRUint16 num_implemented_ciphers = SSL_GetNumImplementedCiphers();
  const PRUint16 *implemented_ciphers = SSL_GetImplementedCiphers();
  if(!implemented_ciphers)
    return SECFailure;

  
  for(i = 0; i < num_implemented_ciphers; i++) {
    SSL_CipherPrefSet(model, implemented_ciphers[i], PR_FALSE);
  }

  
  for(i = 0; i < NUM_OF_CIPHERS; i++) {
    cipher_state[i] = PR_FALSE;
  }

  cipher = cipher_list;

  while(cipher_list && (cipher_list[0])) {
    while((*cipher) && (ISSPACE(*cipher)))
      ++cipher;

    cipher_list = strchr(cipher, ',');
    if(cipher_list) {
      *cipher_list++ = '\0';
    }

    found = PR_FALSE;

    for(i=0; i<NUM_OF_CIPHERS; i++) {
      if(strcasecompare(cipher, cipherlist[i].name)) {
        cipher_state[i] = PR_TRUE;
        found = PR_TRUE;
        break;
      }
    }

    if(found == PR_FALSE) {
      failf(data, "Unknown cipher in list: %s", cipher);
      return SECFailure;
    }

    if(cipher_list) {
      cipher = cipher_list;
    }
  }

  
  for(i=0; i<NUM_OF_CIPHERS; i++) {
    if(!cipher_state[i])
      continue;

    if(SSL_CipherPrefSet(model, cipherlist[i].num, PR_TRUE) != SECSuccess) {
      failf(data, "cipher-suite not supported by NSS: %s", cipherlist[i].name);
      return SECFailure;
    }
  }

  return SECSuccess;
}


static bool any_cipher_enabled(void)
{
  unsigned int i;

  for(i=0; i<NUM_OF_CIPHERS; i++) {
    PRInt32 policy = 0;
    SSL_CipherPolicyGet(cipherlist[i].num, &policy);
    if(policy)
      return TRUE;
  }

  return FALSE;
}


static int is_file(const char *filename)
{
  struct_stat st;

  if(filename == NULL)
    return 0;

  if(stat(filename, &st) == 0)
    if(S_ISREG(st.st_mode))
      return 1;

  return 0;
}


static char *dup_nickname(struct Curl_easy *data, const char *str)
{
  const char *n;

  if(!is_file(str))
    
    return strdup(str);

  
  n = strchr(str, '/');
  if(!n) {
    infof(data, "warning: certificate file name \"%s\" handled as nickname; " "please use \"./%s\" to force file name\n", str, str);
    return strdup(str);
  }

  
  return NULL;
}


static PK11SlotInfo* nss_find_slot_by_name(const char *slot_name)
{
  PK11SlotInfo *slot;
  PR_Lock(nss_findslot_lock);
  slot = PK11_FindSlotByName(slot_name);
  PR_Unlock(nss_findslot_lock);
  return slot;
}


static CURLcode nss_create_object(struct ssl_connect_data *ssl, CK_OBJECT_CLASS obj_class, const char *filename, bool cacert)

{
  PK11SlotInfo *slot;
  PK11GenericObject *obj;
  CK_BBOOL cktrue = CK_TRUE;
  CK_BBOOL ckfalse = CK_FALSE;
  CK_ATTRIBUTE attrs[ 4];
  int attr_cnt = 0;
  CURLcode result = (cacert)
    ? CURLE_SSL_CACERT_BADFILE : CURLE_SSL_CERTPROBLEM;

  const int slot_id = (cacert) ? 0 : 1;
  char *slot_name = aprintf("PEM Token #%d", slot_id);
  if(!slot_name)
    return CURLE_OUT_OF_MEMORY;

  slot = nss_find_slot_by_name(slot_name);
  free(slot_name);
  if(!slot)
    return result;

  PK11_SETATTRS(attrs, attr_cnt, CKA_CLASS, &obj_class, sizeof(obj_class));
  PK11_SETATTRS(attrs, attr_cnt, CKA_TOKEN, &cktrue, sizeof(CK_BBOOL));
  PK11_SETATTRS(attrs, attr_cnt, CKA_LABEL, (unsigned char *)filename, strlen(filename) + 1);

  if(CKO_CERTIFICATE == obj_class) {
    CK_BBOOL *pval = (cacert) ? (&cktrue) : (&ckfalse);
    PK11_SETATTRS(attrs, attr_cnt, CKA_TRUST, pval, sizeof(*pval));
  }

  obj = PK11_CreateGenericObject(slot, attrs, attr_cnt, PR_FALSE);
  PK11_FreeSlot(slot);
  if(!obj)
    return result;

  if(!Curl_llist_insert_next(&ssl->obj_list, ssl->obj_list.tail, obj)) {
    PK11_DestroyGenericObject(obj);
    return CURLE_OUT_OF_MEMORY;
  }

  if(!cacert && CKO_CERTIFICATE == obj_class)
    
    ssl->obj_clicert = obj;

  return CURLE_OK;
}


static void nss_destroy_object(void *user, void *ptr)
{
  PK11GenericObject *obj = (PK11GenericObject *)ptr;
  (void) user;
  PK11_DestroyGenericObject(obj);
}


static void nss_destroy_crl_item(void *user, void *ptr)
{
  SECItem *crl_der = (SECItem *)ptr;
  (void) user;
  SECITEM_FreeItem(crl_der, PR_TRUE);
}

static CURLcode nss_load_cert(struct ssl_connect_data *ssl, const char *filename, PRBool cacert)
{
  CURLcode result = (cacert)
    ? CURLE_SSL_CACERT_BADFILE : CURLE_SSL_CERTPROBLEM;

  
  if(is_file(filename))
    result = nss_create_object(ssl, CKO_CERTIFICATE, filename, cacert);

  if(!result && !cacert) {
    
    CERTCertificate *cert;
    char *nickname = NULL;
    char *n = strrchr(filename, '/');
    if(n)
      n++;

    
    nickname = aprintf("PEM Token #1:%s", n);
    if(nickname) {
      cert = PK11_FindCertFromNickname(nickname, NULL);
      if(cert)
        CERT_DestroyCertificate(cert);

      free(nickname);
    }
  }

  return result;
}


static CURLcode nss_cache_crl(SECItem *crl_der)
{
  CERTCertDBHandle *db = CERT_GetDefaultCertDB();
  CERTSignedCrl *crl = SEC_FindCrlByDERCert(db, crl_der, 0);
  if(crl) {
    
    SEC_DestroyCrl(crl);
    SECITEM_FreeItem(crl_der, PR_TRUE);
    return CURLE_OK;
  }

  
  PR_Lock(nss_crllock);

  
  if(!Curl_llist_insert_next(&nss_crl_list, nss_crl_list.tail, crl_der)) {
    SECITEM_FreeItem(crl_der, PR_TRUE);
    PR_Unlock(nss_crllock);
    return CURLE_OUT_OF_MEMORY;
  }

  if(SECSuccess != CERT_CacheCRL(db, crl_der)) {
    
    PR_Unlock(nss_crllock);
    return CURLE_SSL_CRL_BADFILE;
  }

  
  SSL_ClearSessionCache();
  PR_Unlock(nss_crllock);
  return CURLE_OK;
}

static CURLcode nss_load_crl(const char *crlfilename)
{
  PRFileDesc *infile;
  PRFileInfo  info;
  SECItem filedata = { 0, NULL, 0 };
  SECItem *crl_der = NULL;
  char *body;

  infile = PR_Open(crlfilename, PR_RDONLY, 0);
  if(!infile)
    return CURLE_SSL_CRL_BADFILE;

  if(PR_SUCCESS != PR_GetOpenFileInfo(infile, &info))
    goto fail;

  if(!SECITEM_AllocItem(NULL, &filedata, info.size +  1))
    goto fail;

  if(info.size != PR_Read(infile, filedata.data, info.size))
    goto fail;

  crl_der = SECITEM_AllocItem(NULL, NULL, 0U);
  if(!crl_der)
    goto fail;

  
  body = (char *)filedata.data;
  body[--filedata.len] = '\0';

  body = strstr(body, "-----BEGIN");
  if(body) {
    
    char *trailer;
    char *begin = PORT_Strchr(body, '\n');
    if(!begin)
      begin = PORT_Strchr(body, '\r');
    if(!begin)
      goto fail;

    trailer = strstr(++begin, "-----END");
    if(!trailer)
      goto fail;

    
    *trailer = '\0';
    if(ATOB_ConvertAsciiToItem(crl_der, begin))
      goto fail;

    SECITEM_FreeItem(&filedata, PR_FALSE);
  }
  else  *crl_der = filedata;


  PR_Close(infile);
  return nss_cache_crl(crl_der);

fail:
  PR_Close(infile);
  SECITEM_FreeItem(crl_der, PR_TRUE);
  SECITEM_FreeItem(&filedata, PR_FALSE);
  return CURLE_SSL_CRL_BADFILE;
}

static CURLcode nss_load_key(struct connectdata *conn, int sockindex, char *key_file)
{
  PK11SlotInfo *slot;
  SECStatus status;
  CURLcode result;
  struct ssl_connect_data *ssl = conn->ssl;
  struct Curl_easy *data = conn->data;

  (void)sockindex; 

  result = nss_create_object(ssl, CKO_PRIVATE_KEY, key_file, FALSE);
  if(result) {
    PR_SetError(SEC_ERROR_BAD_KEY, 0);
    return result;
  }

  slot = nss_find_slot_by_name("PEM Token #1");
  if(!slot)
    return CURLE_SSL_CERTPROBLEM;

  
  SECMOD_WaitForAnyTokenEvent(mod, 0, 0);
  PK11_IsPresent(slot);

  status = PK11_Authenticate(slot, PR_TRUE, SSL_SET_OPTION(key_passwd));
  PK11_FreeSlot(slot);

  return (SECSuccess == status) ? CURLE_OK : CURLE_SSL_CERTPROBLEM;
}

static int display_error(struct connectdata *conn, PRInt32 err, const char *filename)
{
  switch(err) {
  case SEC_ERROR_BAD_PASSWORD:
    failf(conn->data, "Unable to load client key: Incorrect password");
    return 1;
  case SEC_ERROR_UNKNOWN_CERT:
    failf(conn->data, "Unable to load certificate %s", filename);
    return 1;
  default:
    break;
  }
  return 0; 
}

static CURLcode cert_stuff(struct connectdata *conn, int sockindex, char *cert_file, char *key_file)
{
  struct Curl_easy *data = conn->data;
  CURLcode result;

  if(cert_file) {
    result = nss_load_cert(&conn->ssl[sockindex], cert_file, PR_FALSE);
    if(result) {
      const PRErrorCode err = PR_GetError();
      if(!display_error(conn, err, cert_file)) {
        const char *err_name = nss_error_to_name(err);
        failf(data, "unable to load client cert: %d (%s)", err, err_name);
      }

      return result;
    }
  }

  if(key_file || (is_file(cert_file))) {
    if(key_file)
      result = nss_load_key(conn, sockindex, key_file);
    else  result = nss_load_key(conn, sockindex, cert_file);

    if(result) {
      const PRErrorCode err = PR_GetError();
      if(!display_error(conn, err, key_file)) {
        const char *err_name = nss_error_to_name(err);
        failf(data, "unable to load client key: %d (%s)", err, err_name);
      }

      return result;
    }
  }

  return CURLE_OK;
}

static char *nss_get_password(PK11SlotInfo *slot, PRBool retry, void *arg)
{
  (void)slot; 

  if(retry || NULL == arg)
    return NULL;
  else return (char *)PORT_Strdup((char *)arg);
}


static SECStatus nss_auth_cert_hook(void *arg, PRFileDesc *fd, PRBool checksig, PRBool isServer)
{
  struct connectdata *conn = (struct connectdata *)arg;


  if(SSL_CONN_CONFIG(verifystatus)) {
    SECStatus cacheResult;

    const SECItemArray *csa = SSL_PeerStapledOCSPResponses(fd);
    if(!csa) {
      failf(conn->data, "Invalid OCSP response");
      return SECFailure;
    }

    if(csa->len == 0) {
      failf(conn->data, "No OCSP response received");
      return SECFailure;
    }

    cacheResult = CERT_CacheOCSPResponseFromSideChannel( CERT_GetDefaultCertDB(), SSL_PeerCertificate(fd), PR_Now(), &csa->items[0], arg );



    if(cacheResult != SECSuccess) {
      failf(conn->data, "Invalid OCSP response");
      return cacheResult;
    }
  }


  if(!SSL_CONN_CONFIG(verifypeer)) {
    infof(conn->data, "skipping SSL peer certificate verification\n");
    return SECSuccess;
  }

  return SSL_AuthCertificate(CERT_GetDefaultCertDB(), fd, checksig, isServer);
}


static void HandshakeCallback(PRFileDesc *sock, void *arg)
{
  struct connectdata *conn = (struct connectdata*) arg;
  unsigned int buflenmax = 50;
  unsigned char buf[50];
  unsigned int buflen;
  SSLNextProtoState state;

  if(!conn->bits.tls_enable_npn && !conn->bits.tls_enable_alpn) {
    return;
  }

  if(SSL_GetNextProto(sock, &state, buf, &buflen, buflenmax) == SECSuccess) {

    switch(state) {

    
    case SSL_NEXT_PROTO_EARLY_VALUE:
      

    case SSL_NEXT_PROTO_NO_SUPPORT:
    case SSL_NEXT_PROTO_NO_OVERLAP:
      infof(conn->data, "ALPN/NPN, server did not agree to a protocol\n");
      return;

    case SSL_NEXT_PROTO_SELECTED:
      infof(conn->data, "ALPN, server accepted to use %.*s\n", buflen, buf);
      break;

    case SSL_NEXT_PROTO_NEGOTIATED:
      infof(conn->data, "NPN, server accepted to use %.*s\n", buflen, buf);
      break;
    }


    if(buflen == NGHTTP2_PROTO_VERSION_ID_LEN && !memcmp(NGHTTP2_PROTO_VERSION_ID, buf, NGHTTP2_PROTO_VERSION_ID_LEN)) {
      conn->negnpn = CURL_HTTP_VERSION_2;
    }
    else  if(buflen == ALPN_HTTP_1_1_LENGTH && !memcmp(ALPN_HTTP_1_1, buf, ALPN_HTTP_1_1_LENGTH)) {


      conn->negnpn = CURL_HTTP_VERSION_1_1;
    }
  }
}


static SECStatus CanFalseStartCallback(PRFileDesc *sock, void *client_data, PRBool *canFalseStart)
{
  struct connectdata *conn = client_data;
  struct Curl_easy *data = conn->data;

  SSLChannelInfo channelInfo;
  SSLCipherSuiteInfo cipherInfo;

  SECStatus rv;
  PRBool negotiatedExtension;

  *canFalseStart = PR_FALSE;

  if(SSL_GetChannelInfo(sock, &channelInfo, sizeof(channelInfo)) != SECSuccess)
    return SECFailure;

  if(SSL_GetCipherSuiteInfo(channelInfo.cipherSuite, &cipherInfo, sizeof(cipherInfo)) != SECSuccess)
    return SECFailure;

  
  if(channelInfo.protocolVersion != SSL_LIBRARY_VERSION_TLS_1_2)
    goto end;

  
  if(cipherInfo.keaType != ssl_kea_ecdh)
    goto end;

  
  if(cipherInfo.symCipher != ssl_calg_aes_gcm)
    goto end;

  
  rv = SSL_HandshakeNegotiatedExtension(sock, ssl_app_layer_protocol_xtn, &negotiatedExtension);
  if(rv != SECSuccess || !negotiatedExtension) {
    rv = SSL_HandshakeNegotiatedExtension(sock, ssl_next_proto_nego_xtn, &negotiatedExtension);
  }

  if(rv != SECSuccess || !negotiatedExtension)
    goto end;

  *canFalseStart = PR_TRUE;

  infof(data, "Trying TLS False Start\n");

end:
  return SECSuccess;
}


static void display_cert_info(struct Curl_easy *data, CERTCertificate *cert)
{
  char *subject, *issuer, *common_name;
  PRExplodedTime printableTime;
  char timeString[256];
  PRTime notBefore, notAfter;

  subject = CERT_NameToAscii(&cert->subject);
  issuer = CERT_NameToAscii(&cert->issuer);
  common_name = CERT_GetCommonName(&cert->subject);
  infof(data, "\tsubject: %s\n", subject);

  CERT_GetCertTimes(cert, &notBefore, &notAfter);
  PR_ExplodeTime(notBefore, PR_GMTParameters, &printableTime);
  PR_FormatTime(timeString, 256, "%b %d %H:%M:%S %Y GMT", &printableTime);
  infof(data, "\tstart date: %s\n", timeString);
  PR_ExplodeTime(notAfter, PR_GMTParameters, &printableTime);
  PR_FormatTime(timeString, 256, "%b %d %H:%M:%S %Y GMT", &printableTime);
  infof(data, "\texpire date: %s\n", timeString);
  infof(data, "\tcommon name: %s\n", common_name);
  infof(data, "\tissuer: %s\n", issuer);

  PR_Free(subject);
  PR_Free(issuer);
  PR_Free(common_name);
}

static CURLcode display_conn_info(struct connectdata *conn, PRFileDesc *sock)
{
  CURLcode result = CURLE_OK;
  SSLChannelInfo channel;
  SSLCipherSuiteInfo suite;
  CERTCertificate *cert;
  CERTCertificate *cert2;
  CERTCertificate *cert3;
  PRTime now;
  int i;

  if(SSL_GetChannelInfo(sock, &channel, sizeof channel) == SECSuccess && channel.length == sizeof channel && channel.cipherSuite) {

    if(SSL_GetCipherSuiteInfo(channel.cipherSuite, &suite, sizeof suite) == SECSuccess) {
      infof(conn->data, "SSL connection using %s\n", suite.cipherSuiteName);
    }
  }

  cert = SSL_PeerCertificate(sock);
  if(cert) {
    infof(conn->data, "Server certificate:\n");

    if(!conn->data->set.ssl.certinfo) {
      display_cert_info(conn->data, cert);
      CERT_DestroyCertificate(cert);
    }
    else {
      
      now = PR_Now();
      i = 1;
      if(!cert->isRoot) {
        cert2 = CERT_FindCertIssuer(cert, now, certUsageSSLCA);
        while(cert2) {
          i++;
          if(cert2->isRoot) {
            CERT_DestroyCertificate(cert2);
            break;
          }
          cert3 = CERT_FindCertIssuer(cert2, now, certUsageSSLCA);
          CERT_DestroyCertificate(cert2);
          cert2 = cert3;
        }
      }

      result = Curl_ssl_init_certinfo(conn->data, i);
      if(!result) {
        for(i = 0; cert; cert = cert2) {
          result = Curl_extract_certinfo(conn, i++, (char *)cert->derCert.data, (char *)cert->derCert.data + cert->derCert.len);

          if(result)
            break;

          if(cert->isRoot) {
            CERT_DestroyCertificate(cert);
            break;
          }

          cert2 = CERT_FindCertIssuer(cert, now, certUsageSSLCA);
          CERT_DestroyCertificate(cert);
        }
      }
    }
  }

  return result;
}

static SECStatus BadCertHandler(void *arg, PRFileDesc *sock)
{
  struct connectdata *conn = (struct connectdata *)arg;
  struct Curl_easy *data = conn->data;
  PRErrorCode err = PR_GetError();
  CERTCertificate *cert;

  
  if(SSL_IS_PROXY())
    data->set.proxy_ssl.certverifyresult = err;
  else data->set.ssl.certverifyresult = err;

  if(err == SSL_ERROR_BAD_CERT_DOMAIN && !SSL_CONN_CONFIG(verifyhost))
    
    return SECSuccess;

  
  cert = SSL_PeerCertificate(sock);
  if(cert) {
    infof(data, "Server certificate:\n");
    display_cert_info(data, cert);
    CERT_DestroyCertificate(cert);
  }

  return SECFailure;
}


static SECStatus check_issuer_cert(PRFileDesc *sock, char *issuer_nickname)
{
  CERTCertificate *cert, *cert_issuer, *issuer;
  SECStatus res=SECSuccess;
  void *proto_win = NULL;

  cert = SSL_PeerCertificate(sock);
  cert_issuer = CERT_FindCertIssuer(cert, PR_Now(), certUsageObjectSigner);

  proto_win = SSL_RevealPinArg(sock);
  issuer = PK11_FindCertFromNickname(issuer_nickname, proto_win);

  if((!cert_issuer) || (!issuer))
    res = SECFailure;
  else if(SECITEM_CompareItem(&cert_issuer->derCert, &issuer->derCert)!=SECEqual)
    res = SECFailure;

  CERT_DestroyCertificate(cert);
  CERT_DestroyCertificate(issuer);
  CERT_DestroyCertificate(cert_issuer);
  return res;
}

static CURLcode cmp_peer_pubkey(struct ssl_connect_data *connssl, const char *pinnedpubkey)
{
  CURLcode result = CURLE_SSL_PINNEDPUBKEYNOTMATCH;
  struct Curl_easy *data = connssl->data;
  CERTCertificate *cert;

  if(!pinnedpubkey)
    
    return CURLE_OK;

  
  cert = SSL_PeerCertificate(connssl->handle);
  if(cert) {
    
    SECKEYPublicKey *pubkey = CERT_ExtractPublicKey(cert);
    if(pubkey) {
      
      SECItem *cert_der = PK11_DEREncodePublicKey(pubkey);
      if(cert_der) {
        
        result = Curl_pin_peer_pubkey(data, pinnedpubkey, cert_der->data, cert_der->len);
        SECITEM_FreeItem(cert_der, PR_TRUE);
      }
      SECKEY_DestroyPublicKey(pubkey);
    }
    CERT_DestroyCertificate(cert);
  }

  
  switch(result) {
  case CURLE_OK:
    infof(data, "pinned public key verified successfully!\n");
    break;
  case CURLE_SSL_PINNEDPUBKEYNOTMATCH:
    failf(data, "failed to verify pinned public key");
    break;
  default:
    
    break;
  }

  return result;
}


static SECStatus SelectClientCert(void *arg, PRFileDesc *sock, struct CERTDistNamesStr *caNames, struct CERTCertificateStr **pRetCert, struct SECKEYPrivateKeyStr **pRetKey)


{
  struct ssl_connect_data *connssl = (struct ssl_connect_data *)arg;
  struct Curl_easy *data = connssl->data;
  const char *nickname = connssl->client_nickname;
  static const char pem_slotname[] = "PEM Token #1";

  if(connssl->obj_clicert) {
    
    SECItem cert_der = { 0, NULL, 0 };
    void *proto_win = SSL_RevealPinArg(sock);
    struct CERTCertificateStr *cert;
    struct SECKEYPrivateKeyStr *key;

    PK11SlotInfo *slot = nss_find_slot_by_name(pem_slotname);
    if(NULL == slot) {
      failf(data, "NSS: PK11 slot not found: %s", pem_slotname);
      return SECFailure;
    }

    if(PK11_ReadRawAttribute(PK11_TypeGeneric, connssl->obj_clicert, CKA_VALUE, &cert_der) != SECSuccess) {
      failf(data, "NSS: CKA_VALUE not found in PK11 generic object");
      PK11_FreeSlot(slot);
      return SECFailure;
    }

    cert = PK11_FindCertFromDERCertItem(slot, &cert_der, proto_win);
    SECITEM_FreeItem(&cert_der, PR_FALSE);
    if(NULL == cert) {
      failf(data, "NSS: client certificate from file not found");
      PK11_FreeSlot(slot);
      return SECFailure;
    }

    key = PK11_FindPrivateKeyFromCert(slot, cert, NULL);
    PK11_FreeSlot(slot);
    if(NULL == key) {
      failf(data, "NSS: private key from file not found");
      CERT_DestroyCertificate(cert);
      return SECFailure;
    }

    infof(data, "NSS: client certificate from file\n");
    display_cert_info(data, cert);

    *pRetCert = cert;
    *pRetKey = key;
    return SECSuccess;
  }

  
  if(SECSuccess != NSS_GetClientAuthData((void *)nickname, sock, caNames, pRetCert, pRetKey)
      || NULL == *pRetCert) {

    if(NULL == nickname)
      failf(data, "NSS: client certificate not found (nickname not " "specified)");
    else failf(data, "NSS: client certificate not found: %s", nickname);

    return SECFailure;
  }

  
  nickname = (*pRetCert)->nickname;
  if(NULL == nickname)
    nickname = "[unknown]";

  if(!strncmp(nickname, pem_slotname, sizeof(pem_slotname) - 1U)) {
    failf(data, "NSS: refusing previously loaded certificate from file: %s", nickname);
    return SECFailure;
  }

  if(NULL == *pRetKey) {
    failf(data, "NSS: private key not found for certificate: %s", nickname);
    return SECFailure;
  }

  infof(data, "NSS: using client certificate: %s\n", nickname);
  display_cert_info(data, *pRetCert);
  return SECSuccess;
}


static void nss_update_connecting_state(ssl_connect_state state, void *secret)
{
  struct ssl_connect_data *connssl = (struct ssl_connect_data *)secret;
  if(PR_GetError() != PR_WOULD_BLOCK_ERROR)
    
    return;

  switch(connssl->connecting_state) {
  case ssl_connect_2:
  case ssl_connect_2_reading:
  case ssl_connect_2_writing:
    break;
  default:
    
    return;
  }

  
  connssl->connecting_state = state;
}


static PRInt32 nspr_io_recv(PRFileDesc *fd, void *buf, PRInt32 amount, PRIntn flags, PRIntervalTime timeout)
{
  const PRRecvFN recv_fn = fd->lower->methods->recv;
  const PRInt32 rv = recv_fn(fd->lower, buf, amount, flags, timeout);
  if(rv < 0)
    
    nss_update_connecting_state(ssl_connect_2_reading, fd->secret);
  return rv;
}


static PRInt32 nspr_io_send(PRFileDesc *fd, const void *buf, PRInt32 amount, PRIntn flags, PRIntervalTime timeout)
{
  const PRSendFN send_fn = fd->lower->methods->send;
  const PRInt32 rv = send_fn(fd->lower, buf, amount, flags, timeout);
  if(rv < 0)
    
    nss_update_connecting_state(ssl_connect_2_writing, fd->secret);
  return rv;
}


static PRStatus nspr_io_close(PRFileDesc *fd)
{
  const PRCloseFN close_fn = PR_GetDefaultIOMethods()->close;
  fd->secret = NULL;
  return close_fn(fd);
}


static CURLcode nss_init_core(struct Curl_easy *data, const char *cert_dir)
{
  NSSInitParameters initparams;

  if(nss_context != NULL)
    return CURLE_OK;

  memset((void *) &initparams, '\0', sizeof(initparams));
  initparams.length = sizeof(initparams);

  if(cert_dir) {
    char *certpath = aprintf("sql:%s", cert_dir);
    if(!certpath)
      return CURLE_OUT_OF_MEMORY;

    infof(data, "Initializing NSS with certpath: %s\n", certpath);
    nss_context = NSS_InitContext(certpath, "", "", "", &initparams, NSS_INIT_READONLY | NSS_INIT_PK11RELOAD);
    free(certpath);

    if(nss_context != NULL)
      return CURLE_OK;

    infof(data, "Unable to initialize NSS database\n");
  }

  infof(data, "Initializing NSS with certpath: none\n");
  nss_context = NSS_InitContext("", "", "", "", &initparams, NSS_INIT_READONLY | NSS_INIT_NOCERTDB   | NSS_INIT_NOMODDB       | NSS_INIT_FORCEOPEN | NSS_INIT_NOROOTINIT | NSS_INIT_OPTIMIZESPACE | NSS_INIT_PK11RELOAD);

  if(nss_context != NULL)
    return CURLE_OK;

  infof(data, "Unable to initialize NSS\n");
  return CURLE_SSL_CACERT_BADFILE;
}


static CURLcode nss_init(struct Curl_easy *data)
{
  char *cert_dir;
  struct_stat st;
  CURLcode result;

  if(initialized)
    return CURLE_OK;

  
  Curl_llist_init(&nss_crl_list, nss_destroy_crl_item);

  
  cert_dir = getenv("SSL_DIR");
  if(cert_dir) {
    if((stat(cert_dir, &st) != 0) || (!S_ISDIR(st.st_mode))) {
      cert_dir = NULL;
    }
  }

  
  if(!cert_dir) {
    if((stat(SSL_DIR, &st) == 0) && (S_ISDIR(st.st_mode))) {
      cert_dir = (char *)SSL_DIR;
    }
  }

  if(nspr_io_identity == PR_INVALID_IO_LAYER) {
    
    nspr_io_identity = PR_GetUniqueIdentity("libcurl");
    if(nspr_io_identity == PR_INVALID_IO_LAYER)
      return CURLE_OUT_OF_MEMORY;

    
    memcpy(&nspr_io_methods, PR_GetDefaultIOMethods(), sizeof nspr_io_methods);

    
    nspr_io_methods.recv  = nspr_io_recv;
    nspr_io_methods.send  = nspr_io_send;
    nspr_io_methods.close = nspr_io_close;
  }

  result = nss_init_core(data, cert_dir);
  if(result)
    return result;

  if(!any_cipher_enabled())
    NSS_SetDomesticPolicy();

  initialized = 1;

  return CURLE_OK;
}


int Curl_nss_init(void)
{
  
  if(nss_initlock == NULL) {
    PR_Init(PR_USER_THREAD, PR_PRIORITY_NORMAL, 256);
    nss_initlock = PR_NewLock();
    nss_crllock = PR_NewLock();
    nss_findslot_lock = PR_NewLock();
  }

  

  return 1;
}


CURLcode Curl_nss_force_init(struct Curl_easy *data)
{
  CURLcode result;
  if(!nss_initlock) {
    if(data)
      failf(data, "unable to initialize NSS, curl_global_init() should have " "been called with CURL_GLOBAL_SSL or CURL_GLOBAL_ALL");
    return CURLE_FAILED_INIT;
  }

  PR_Lock(nss_initlock);
  result = nss_init(data);
  PR_Unlock(nss_initlock);

  return result;
}


void Curl_nss_cleanup(void)
{
  
  PR_Lock(nss_initlock);
  if(initialized) {
    
    SSL_ClearSessionCache();

    if(mod && SECSuccess == SECMOD_UnloadUserModule(mod)) {
      SECMOD_DestroyModule(mod);
      mod = NULL;
    }
    NSS_ShutdownContext(nss_context);
    nss_context = NULL;
  }

  
  Curl_llist_destroy(&nss_crl_list, NULL);

  PR_Unlock(nss_initlock);

  PR_DestroyLock(nss_initlock);
  PR_DestroyLock(nss_crllock);
  PR_DestroyLock(nss_findslot_lock);
  nss_initlock = NULL;

  initialized = 0;
}


int Curl_nss_check_cxn(struct connectdata *conn)
{
  int rc;
  char buf;

  rc = PR_Recv(conn->ssl[FIRSTSOCKET].handle, (void *)&buf, 1, PR_MSG_PEEK, PR_SecondsToInterval(1));

  if(rc > 0)
    return 1; 

  if(rc == 0)
    return 0; 

  return -1;  
}

static void nss_close(struct ssl_connect_data *connssl)
{
  
  const bool client_cert = (connssl->client_nickname != NULL)
    || (connssl->obj_clicert != NULL);

  free(connssl->client_nickname);
  connssl->client_nickname = NULL;

  
  Curl_llist_destroy(&connssl->obj_list, NULL);
  connssl->obj_clicert = NULL;

  if(connssl->handle) {
    if(client_cert)
      
      SSL_InvalidateSession(connssl->handle);

    PR_Close(connssl->handle);
    connssl->handle = NULL;
  }
}


void Curl_nss_close(struct connectdata *conn, int sockindex)
{
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  struct ssl_connect_data *connssl_proxy = &conn->proxy_ssl[sockindex];

  if(connssl->handle || connssl_proxy->handle) {
    
    fake_sclose(conn->sock[sockindex]);
    conn->sock[sockindex] = CURL_SOCKET_BAD;
  }

  if(connssl->handle)
    
    connssl_proxy->handle = NULL;

  nss_close(connssl);
  nss_close(connssl_proxy);
}


static bool is_nss_error(CURLcode err)
{
  switch(err) {
  case CURLE_PEER_FAILED_VERIFICATION:
  case CURLE_SSL_CACERT:
  case CURLE_SSL_CERTPROBLEM:
  case CURLE_SSL_CONNECT_ERROR:
  case CURLE_SSL_ISSUER_ERROR:
    return true;

  default:
    return false;
  }
}


static bool is_cc_error(PRInt32 err)
{
  switch(err) {
  case SSL_ERROR_BAD_CERT_ALERT:
  case SSL_ERROR_EXPIRED_CERT_ALERT:
  case SSL_ERROR_REVOKED_CERT_ALERT:
    return true;

  default:
    return false;
  }
}

static Curl_recv nss_recv;
static Curl_send nss_send;

static CURLcode nss_load_ca_certificates(struct connectdata *conn, int sockindex)
{
  struct Curl_easy *data = conn->data;
  const char *cafile = SSL_CONN_CONFIG(CAfile);
  const char *capath = SSL_CONN_CONFIG(CApath);

  if(cafile) {
    CURLcode result = nss_load_cert(&conn->ssl[sockindex], cafile, PR_TRUE);
    if(result)
      return result;
  }

  if(capath) {
    struct_stat st;
    if(stat(capath, &st) == -1)
      return CURLE_SSL_CACERT_BADFILE;

    if(S_ISDIR(st.st_mode)) {
      PRDirEntry *entry;
      PRDir *dir = PR_OpenDir(capath);
      if(!dir)
        return CURLE_SSL_CACERT_BADFILE;

      while((entry = PR_ReadDir(dir, PR_SKIP_BOTH | PR_SKIP_HIDDEN))) {
        char *fullpath = aprintf("%s/%s", capath, entry->name);
        if(!fullpath) {
          PR_CloseDir(dir);
          return CURLE_OUT_OF_MEMORY;
        }

        if(CURLE_OK != nss_load_cert(&conn->ssl[sockindex], fullpath, PR_TRUE))
          
          infof(data, "failed to load '%s' from CURLOPT_CAPATH\n", fullpath);

        free(fullpath);
      }

      PR_CloseDir(dir);
    }
    else infof(data, "warning: CURLOPT_CAPATH not a directory (%s)\n", capath);
  }

  infof(data, "  CAfile: %s\n  CApath: %s\n", cafile ? cafile : "none", capath ? capath : "none");


  return CURLE_OK;
}

static CURLcode nss_sslver_from_curl(PRUint16 *nssver, long version)
{
  switch(version) {
  case CURL_SSLVERSION_TLSv1:
    

    *nssver = SSL_LIBRARY_VERSION_TLS_1_2;

    *nssver = SSL_LIBRARY_VERSION_TLS_1_1;

    *nssver = SSL_LIBRARY_VERSION_TLS_1_0;

    return CURLE_OK;

  case CURL_SSLVERSION_SSLv2:
    *nssver = SSL_LIBRARY_VERSION_2;
    return CURLE_OK;

  case CURL_SSLVERSION_SSLv3:
    *nssver = SSL_LIBRARY_VERSION_3_0;
    return CURLE_OK;

  case CURL_SSLVERSION_TLSv1_0:
    *nssver = SSL_LIBRARY_VERSION_TLS_1_0;
    return CURLE_OK;

  case CURL_SSLVERSION_TLSv1_1:

    *nssver = SSL_LIBRARY_VERSION_TLS_1_1;
    return CURLE_OK;

    return CURLE_SSL_CONNECT_ERROR;


  case CURL_SSLVERSION_TLSv1_2:

    *nssver = SSL_LIBRARY_VERSION_TLS_1_2;
    return CURLE_OK;

    return CURLE_SSL_CONNECT_ERROR;


  case CURL_SSLVERSION_TLSv1_3:

    *nssver = SSL_LIBRARY_VERSION_TLS_1_3;
    return CURLE_OK;

    return CURLE_SSL_CONNECT_ERROR;


  default:
    return CURLE_SSL_CONNECT_ERROR;
  }
}

static CURLcode nss_init_sslver(SSLVersionRange *sslver, struct Curl_easy *data, struct connectdata *conn)

{
  CURLcode result;
  const long min = SSL_CONN_CONFIG(version);
  const long max = SSL_CONN_CONFIG(version_max);

  
  if(min == CURL_SSLVERSION_DEFAULT || max == CURL_SSLVERSION_MAX_DEFAULT) {
    
    if(SSL_VersionRangeGetDefault(ssl_variant_stream, sslver) != SECSuccess)
      return CURLE_SSL_CONNECT_ERROR;
    
    if(sslver->min < SSL_LIBRARY_VERSION_TLS_1_0)
      sslver->min = SSL_LIBRARY_VERSION_TLS_1_0;
  }

  switch(min) {
  case CURL_SSLVERSION_DEFAULT:
    break;
  case CURL_SSLVERSION_TLSv1:
    sslver->min = SSL_LIBRARY_VERSION_TLS_1_0;
    break;
  default:
    result = nss_sslver_from_curl(&sslver->min, min);
    if(result) {
      failf(data, "unsupported min version passed via CURLOPT_SSLVERSION");
      return result;
    }
    if(max == CURL_SSLVERSION_MAX_NONE)
      sslver->max = sslver->min;
  }

  switch(max) {
  case CURL_SSLVERSION_MAX_NONE:
  case CURL_SSLVERSION_MAX_DEFAULT:
    break;
  default:
    result = nss_sslver_from_curl(&sslver->max, max >> 16);
    if(result) {
      failf(data, "unsupported max version passed via CURLOPT_SSLVERSION");
      return result;
    }
  }

  return CURLE_OK;
}

static CURLcode nss_fail_connect(struct ssl_connect_data *connssl, struct Curl_easy *data, CURLcode curlerr)

{
  PRErrorCode err = 0;

  if(is_nss_error(curlerr)) {
    
    err = PR_GetError();
    if(is_cc_error(err))
      curlerr = CURLE_SSL_CERTPROBLEM;

    
    infof(data, "NSS error %d (%s)\n", err, nss_error_to_name(err));

    
    nss_print_error_message(data, err);
  }

  
  Curl_llist_destroy(&connssl->obj_list, NULL);

  return curlerr;
}


static CURLcode nss_set_blocking(struct ssl_connect_data *connssl, struct Curl_easy *data, bool blocking)

{
  static PRSocketOptionData sock_opt;
  sock_opt.option = PR_SockOpt_Nonblocking;
  sock_opt.value.non_blocking = !blocking;

  if(PR_SetSocketOption(connssl->handle, &sock_opt) != PR_SUCCESS)
    return nss_fail_connect(connssl, data, CURLE_SSL_CONNECT_ERROR);

  return CURLE_OK;
}

static CURLcode nss_setup_connect(struct connectdata *conn, int sockindex)
{
  PRFileDesc *model = NULL;
  PRFileDesc *nspr_io = NULL;
  PRFileDesc *nspr_io_stub = NULL;
  PRBool ssl_no_cache;
  PRBool ssl_cbc_random_iv;
  struct Curl_easy *data = conn->data;
  curl_socket_t sockfd = conn->sock[sockindex];
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  CURLcode result;
  bool second_layer = FALSE;

  SSLVersionRange sslver = {
    SSL_LIBRARY_VERSION_TLS_1_0,   SSL_LIBRARY_VERSION_TLS_1_0 };


  connssl->data = data;

  
  Curl_llist_init(&connssl->obj_list, nss_destroy_object);

  
  PR_Lock(nss_initlock);
  result = nss_init(conn->data);
  if(result) {
    PR_Unlock(nss_initlock);
    goto error;
  }

  result = CURLE_SSL_CONNECT_ERROR;

  if(!mod) {
    char *configstring = aprintf("library=%s name=PEM", pem_library);
    if(!configstring) {
      PR_Unlock(nss_initlock);
      goto error;
    }
    mod = SECMOD_LoadUserModule(configstring, NULL, PR_FALSE);
    free(configstring);

    if(!mod || !mod->loaded) {
      if(mod) {
        SECMOD_DestroyModule(mod);
        mod = NULL;
      }
      infof(data, "WARNING: failed to load NSS PEM library %s. Using " "OpenSSL PEM certificates will not work.\n", pem_library);
    }
  }

  PK11_SetPasswordFunc(nss_get_password);
  PR_Unlock(nss_initlock);

  model = PR_NewTCPSocket();
  if(!model)
    goto error;
  model = SSL_ImportFD(NULL, model);

  if(SSL_OptionSet(model, SSL_SECURITY, PR_TRUE) != SECSuccess)
    goto error;
  if(SSL_OptionSet(model, SSL_HANDSHAKE_AS_SERVER, PR_FALSE) != SECSuccess)
    goto error;
  if(SSL_OptionSet(model, SSL_HANDSHAKE_AS_CLIENT, PR_TRUE) != SECSuccess)
    goto error;

  
  ssl_no_cache = (data->set.general_ssl.sessionid && SSL_CONN_CONFIG(verifypeer)) ? PR_FALSE : PR_TRUE;
  if(SSL_OptionSet(model, SSL_NO_CACHE, ssl_no_cache) != SECSuccess)
    goto error;

  
  if(nss_init_sslver(&sslver, data, conn) != CURLE_OK)
    goto error;
  if(SSL_VersionRangeSet(model, &sslver) != SECSuccess)
    goto error;

  ssl_cbc_random_iv = !SSL_SET_OPTION(enable_beast);

  
  if(SSL_OptionSet(model, SSL_CBC_RANDOM_IV, ssl_cbc_random_iv) != SECSuccess)
    infof(data, "warning: failed to set SSL_CBC_RANDOM_IV = %d\n", ssl_cbc_random_iv);

  if(ssl_cbc_random_iv)
    infof(data, "warning: support for SSL_CBC_RANDOM_IV not compiled in\n");


  if(SSL_CONN_CONFIG(cipher_list)) {
    if(set_ciphers(data, model, SSL_CONN_CONFIG(cipher_list)) != SECSuccess) {
      result = CURLE_SSL_CIPHER;
      goto error;
    }
  }

  if(!SSL_CONN_CONFIG(verifypeer) && SSL_CONN_CONFIG(verifyhost))
    infof(data, "warning: ignoring value of ssl.verifyhost\n");

  
  if(SSL_AuthCertificateHook(model, nss_auth_cert_hook, conn) != SECSuccess)
    goto error;

  
  if(SSL_IS_PROXY())
    data->set.proxy_ssl.certverifyresult = 0;
  else data->set.ssl.certverifyresult = 0;

  if(SSL_BadCertHook(model, BadCertHandler, conn) != SECSuccess)
    goto error;

  if(SSL_HandshakeCallback(model, HandshakeCallback, conn) != SECSuccess)
    goto error;

  {
    const CURLcode rv = nss_load_ca_certificates(conn, sockindex);
    if((rv == CURLE_SSL_CACERT_BADFILE) && !SSL_CONN_CONFIG(verifypeer))
      
      infof(data, "warning: CA certificates failed to load\n");
    else if(rv) {
      result = rv;
      goto error;
    }
  }

  if(SSL_SET_OPTION(CRLfile)) {
    const CURLcode rv = nss_load_crl(SSL_SET_OPTION(CRLfile));
    if(rv) {
      result = rv;
      goto error;
    }
    infof(data, "  CRLfile: %s\n", SSL_SET_OPTION(CRLfile));
  }

  if(SSL_SET_OPTION(cert)) {
    char *nickname = dup_nickname(data, SSL_SET_OPTION(cert));
    if(nickname) {
      
      connssl->obj_clicert = NULL;
    }
    else {
      CURLcode rv = cert_stuff(conn, sockindex, SSL_SET_OPTION(cert), SSL_SET_OPTION(key));
      if(rv) {
        
        result = rv;
        goto error;
      }
    }

    
    connssl->client_nickname = nickname;
  }
  else connssl->client_nickname = NULL;

  if(SSL_GetClientAuthDataHook(model, SelectClientCert, (void *)connssl) != SECSuccess) {
    result = CURLE_SSL_CERTPROBLEM;
    goto error;
  }

  if(conn->proxy_ssl[sockindex].use) {
    DEBUGASSERT(ssl_connection_complete == conn->proxy_ssl[sockindex].state);
    DEBUGASSERT(conn->proxy_ssl[sockindex].handle != NULL);
    nspr_io = conn->proxy_ssl[sockindex].handle;
    second_layer = TRUE;
  }
  else {
    
    nspr_io = PR_ImportTCPSocket(sockfd);
    if(!nspr_io)
      goto error;
  }

  
  nspr_io_stub = PR_CreateIOLayerStub(nspr_io_identity, &nspr_io_methods);
  if(!nspr_io_stub) {
    if(!second_layer)
      PR_Close(nspr_io);
    goto error;
  }

  
  nspr_io_stub->secret = (void *)connssl;

  
  if(PR_PushIOLayer(nspr_io, PR_TOP_IO_LAYER, nspr_io_stub) != PR_SUCCESS) {
    if(!second_layer)
      PR_Close(nspr_io);
    PR_Close(nspr_io_stub);
    goto error;
  }

  
  connssl->handle = SSL_ImportFD(model, nspr_io);
  if(!connssl->handle) {
    if(!second_layer)
      PR_Close(nspr_io);
    goto error;
  }

  PR_Close(model); 
  model = NULL;

  
  if(SSL_SET_OPTION(key_passwd)) {
    SSL_SetPKCS11PinArg(connssl->handle, SSL_SET_OPTION(key_passwd));
  }


  if(SSL_CONN_CONFIG(verifystatus)) {
    if(SSL_OptionSet(connssl->handle, SSL_ENABLE_OCSP_STAPLING, PR_TRUE)
        != SECSuccess)
      goto error;
  }



  if(SSL_OptionSet(connssl->handle, SSL_ENABLE_NPN, conn->bits.tls_enable_npn ? PR_TRUE : PR_FALSE) != SECSuccess)
    goto error;



  if(SSL_OptionSet(connssl->handle, SSL_ENABLE_ALPN, conn->bits.tls_enable_alpn ? PR_TRUE : PR_FALSE) != SECSuccess)
    goto error;



  if(data->set.ssl.falsestart) {
    if(SSL_OptionSet(connssl->handle, SSL_ENABLE_FALSE_START, PR_TRUE)
        != SECSuccess)
      goto error;

    if(SSL_SetCanFalseStartCallback(connssl->handle, CanFalseStartCallback, conn) != SECSuccess)
      goto error;
  }



  if(conn->bits.tls_enable_npn || conn->bits.tls_enable_alpn) {
    int cur = 0;
    unsigned char protocols[128];


    if(data->set.httpversion >= CURL_HTTP_VERSION_2) {
      protocols[cur++] = NGHTTP2_PROTO_VERSION_ID_LEN;
      memcpy(&protocols[cur], NGHTTP2_PROTO_VERSION_ID, NGHTTP2_PROTO_VERSION_ID_LEN);
      cur += NGHTTP2_PROTO_VERSION_ID_LEN;
    }

    protocols[cur++] = ALPN_HTTP_1_1_LENGTH;
    memcpy(&protocols[cur], ALPN_HTTP_1_1, ALPN_HTTP_1_1_LENGTH);
    cur += ALPN_HTTP_1_1_LENGTH;

    if(SSL_SetNextProtoNego(connssl->handle, protocols, cur) != SECSuccess)
      goto error;
  }



  
  if(SSL_ResetHandshake(connssl->handle,  PR_FALSE)
      != SECSuccess)
    goto error;

  
  if(SSL_SetURL(connssl->handle, SSL_IS_PROXY() ? conn->http_proxy.host.name :
                conn->host.name) != SECSuccess)
    goto error;

  
  if(SSL_SetSockPeerID(connssl->handle, SSL_IS_PROXY() ? conn->http_proxy.host.name : conn->host.name)
     != SECSuccess)
    goto error;

  return CURLE_OK;

error:
  if(model)
    PR_Close(model);

  return nss_fail_connect(connssl, data, result);
}

static CURLcode nss_do_connect(struct connectdata *conn, int sockindex)
{
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  struct Curl_easy *data = conn->data;
  CURLcode result = CURLE_SSL_CONNECT_ERROR;
  PRUint32 timeout;
  long * const certverifyresult = SSL_IS_PROXY() ? &data->set.proxy_ssl.certverifyresult : &data->set.ssl.certverifyresult;
  const char * const pinnedpubkey = SSL_IS_PROXY() ? data->set.str[STRING_SSL_PINNEDPUBLICKEY_PROXY] :
              data->set.str[STRING_SSL_PINNEDPUBLICKEY_ORIG];


  
  const long time_left = Curl_timeleft(data, NULL, TRUE);
  if(time_left < 0L) {
    failf(data, "timed out before SSL handshake");
    result = CURLE_OPERATION_TIMEDOUT;
    goto error;
  }

  
  timeout = PR_MillisecondsToInterval((PRUint32) time_left);
  if(SSL_ForceHandshakeWithTimeout(connssl->handle, timeout) != SECSuccess) {
    if(PR_GetError() == PR_WOULD_BLOCK_ERROR)
      
      return CURLE_AGAIN;
    else if(*certverifyresult == SSL_ERROR_BAD_CERT_DOMAIN)
      result = CURLE_PEER_FAILED_VERIFICATION;
    else if(*certverifyresult != 0)
      result = CURLE_SSL_CACERT;
    goto error;
  }

  result = display_conn_info(conn, connssl->handle);
  if(result)
    goto error;

  if(SSL_SET_OPTION(issuercert)) {
    SECStatus ret = SECFailure;
    char *nickname = dup_nickname(data, SSL_SET_OPTION(issuercert));
    if(nickname) {
      
      ret = check_issuer_cert(connssl->handle, nickname);
      free(nickname);
    }

    if(SECFailure == ret) {
      infof(data, "SSL certificate issuer check failed\n");
      result = CURLE_SSL_ISSUER_ERROR;
      goto error;
    }
    else {
      infof(data, "SSL certificate issuer check ok\n");
    }
  }

  result = cmp_peer_pubkey(connssl, pinnedpubkey);
  if(result)
    
    goto error;

  return CURLE_OK;

error:
  return nss_fail_connect(connssl, data, result);
}

static CURLcode nss_connect_common(struct connectdata *conn, int sockindex, bool *done)
{
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  struct Curl_easy *data = conn->data;
  const bool blocking = (done == NULL);
  CURLcode result;

  if(connssl->state == ssl_connection_complete) {
    if(!blocking)
      *done = TRUE;
    return CURLE_OK;
  }

  if(connssl->connecting_state == ssl_connect_1) {
    result = nss_setup_connect(conn, sockindex);
    if(result)
      
      return result;

    connssl->connecting_state = ssl_connect_2;
  }

  
  result = nss_set_blocking(connssl, data, blocking);
  if(result)
    return result;

  result = nss_do_connect(conn, sockindex);
  switch(result) {
  case CURLE_OK:
    break;
  case CURLE_AGAIN:
    if(!blocking)
      
      return CURLE_OK;
    
  default:
    return result;
  }

  if(blocking) {
    
    result = nss_set_blocking(connssl, data,  FALSE);
    if(result)
      return result;
  }
  else  *done = TRUE;


  connssl->state = ssl_connection_complete;
  conn->recv[sockindex] = nss_recv;
  conn->send[sockindex] = nss_send;

  
  connssl->connecting_state = ssl_connect_1;

  return CURLE_OK;
}

CURLcode Curl_nss_connect(struct connectdata *conn, int sockindex)
{
  return nss_connect_common(conn, sockindex,  NULL);
}

CURLcode Curl_nss_connect_nonblocking(struct connectdata *conn, int sockindex, bool *done)
{
  return nss_connect_common(conn, sockindex, done);
}

static ssize_t nss_send(struct connectdata *conn,   int sockindex, const void *mem, size_t len, CURLcode *curlcode)



{
  ssize_t rc = PR_Send(conn->ssl[sockindex].handle, mem, (int)len, 0, PR_INTERVAL_NO_WAIT);
  if(rc < 0) {
    PRInt32 err = PR_GetError();
    if(err == PR_WOULD_BLOCK_ERROR)
      *curlcode = CURLE_AGAIN;
    else {
      
      const char *err_name = nss_error_to_name(err);
      infof(conn->data, "SSL write: error %d (%s)\n", err, err_name);

      
      nss_print_error_message(conn->data, err);

      *curlcode = (is_cc_error(err))
        ? CURLE_SSL_CERTPROBLEM : CURLE_SEND_ERROR;
    }

    return -1;
  }

  return rc; 
}

static ssize_t nss_recv(struct connectdata * conn,  int num, char *buf, size_t buffersize, CURLcode *curlcode)



{
  ssize_t nread = PR_Recv(conn->ssl[num].handle, buf, (int)buffersize, 0, PR_INTERVAL_NO_WAIT);
  if(nread < 0) {
    
    PRInt32 err = PR_GetError();

    if(err == PR_WOULD_BLOCK_ERROR)
      *curlcode = CURLE_AGAIN;
    else {
      
      const char *err_name = nss_error_to_name(err);
      infof(conn->data, "SSL read: errno %d (%s)\n", err, err_name);

      
      nss_print_error_message(conn->data, err);

      *curlcode = (is_cc_error(err))
        ? CURLE_SSL_CERTPROBLEM : CURLE_RECV_ERROR;
    }

    return -1;
  }

  return nread;
}

size_t Curl_nss_version(char *buffer, size_t size)
{
  return snprintf(buffer, size, "NSS/%s", NSS_VERSION);
}


int Curl_nss_seed(struct Curl_easy *data)
{
  
  return !!Curl_nss_force_init(data);
}


CURLcode Curl_nss_random(struct Curl_easy *data, unsigned char *entropy, size_t length)

{
  Curl_nss_seed(data);  

  if(SECSuccess != PK11_GenerateRandom(entropy, curlx_uztosi(length)))
    
    return CURLE_FAILED_INIT;

  return CURLE_OK;
}

void Curl_nss_md5sum(unsigned char *tmp,  size_t tmplen, unsigned char *md5sum, size_t md5len)


{
  PK11Context *MD5pw = PK11_CreateDigestContext(SEC_OID_MD5);
  unsigned int MD5out;

  PK11_DigestOp(MD5pw, tmp, curlx_uztoui(tmplen));
  PK11_DigestFinal(MD5pw, md5sum, &MD5out, curlx_uztoui(md5len));
  PK11_DestroyContext(MD5pw, PR_TRUE);
}

void Curl_nss_sha256sum(const unsigned char *tmp,  size_t tmplen, unsigned char *sha256sum, size_t sha256len)


{
  PK11Context *SHA256pw = PK11_CreateDigestContext(SEC_OID_SHA256);
  unsigned int SHA256out;

  PK11_DigestOp(SHA256pw, tmp, curlx_uztoui(tmplen));
  PK11_DigestFinal(SHA256pw, sha256sum, &SHA256out, curlx_uztoui(sha256len));
  PK11_DestroyContext(SHA256pw, PR_TRUE);
}

bool Curl_nss_cert_status_request(void)
{

  return TRUE;

  return FALSE;

}

bool Curl_nss_false_start(void)
{

  return TRUE;

  return FALSE;

}


