



















































struct ssl_backend_data {
  SSL_CTX* ctx;
  SSL*     handle;
};

static Curl_recv wolfssl_recv;
static Curl_send wolfssl_send;




static int wolfssl_tls13_secret_callback(SSL *ssl, int id, const unsigned char *secret, int secretSz, void *ctx)

{
  const char *label;
  unsigned char client_random[SSL3_RANDOM_SIZE];
  (void)ctx;

  if(!ssl || !Curl_tls_keylog_enabled()) {
    return 0;
  }

  switch(id) {
  case CLIENT_EARLY_TRAFFIC_SECRET:
    label = "CLIENT_EARLY_TRAFFIC_SECRET";
    break;
  case CLIENT_HANDSHAKE_TRAFFIC_SECRET:
    label = "CLIENT_HANDSHAKE_TRAFFIC_SECRET";
    break;
  case SERVER_HANDSHAKE_TRAFFIC_SECRET:
    label = "SERVER_HANDSHAKE_TRAFFIC_SECRET";
    break;
  case CLIENT_TRAFFIC_SECRET:
    label = "CLIENT_TRAFFIC_SECRET_0";
    break;
  case SERVER_TRAFFIC_SECRET:
    label = "SERVER_TRAFFIC_SECRET_0";
    break;
  case EARLY_EXPORTER_SECRET:
    label = "EARLY_EXPORTER_SECRET";
    break;
  case EXPORTER_SECRET:
    label = "EXPORTER_SECRET";
    break;
  default:
    return 0;
  }

  if(SSL_get_client_random(ssl, client_random, SSL3_RANDOM_SIZE) == 0) {
    
    return 0;
  }

  Curl_tls_keylog_write(label, client_random, secret, secretSz);
  return 0;
}


static void wolfssl_log_tls12_secret(SSL *ssl)
{
  unsigned char *ms, *sr, *cr;
  unsigned int msLen, srLen, crLen, i, x = 0;


  
  switch(wolfSSL_GetVersion(ssl)) {
  case WOLFSSL_SSLV3:
  case WOLFSSL_TLSV1:
  case WOLFSSL_TLSV1_1:
  case WOLFSSL_TLSV1_2:
    break;
  default:
    
    return;
  }


  if(SSL_get_keys(ssl, &ms, &msLen, &sr, &srLen, &cr, &crLen) != SSL_SUCCESS) {
    return;
  }

  
  for(i = 0; i < msLen; i++) {
    x |= ms[i];
  }
  if(x == 0) {
    return;
  }

  Curl_tls_keylog_write("CLIENT_RANDOM", cr, ms, msLen);
}


static int do_file_type(const char *type)
{
  if(!type || !type[0])
    return SSL_FILETYPE_PEM;
  if(strcasecompare(type, "PEM"))
    return SSL_FILETYPE_PEM;
  if(strcasecompare(type, "DER"))
    return SSL_FILETYPE_ASN1;
  return -1;
}


static CURLcode wolfssl_connect_step1(struct Curl_easy *data, struct connectdata *conn, int sockindex)

{
  char *ciphers;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  struct ssl_backend_data *backend = connssl->backend;
  SSL_METHOD* req_method = NULL;
  curl_socket_t sockfd = conn->sock[sockindex];

  bool sni = FALSE;





  if(connssl->state == ssl_connection_complete)
    return CURLE_OK;

  if(SSL_CONN_CONFIG(version_max) != CURL_SSLVERSION_MAX_NONE) {
    failf(data, "wolfSSL does not support to set maximum SSL/TLS version");
    return CURLE_SSL_CONNECT_ERROR;
  }

  
  switch(SSL_CONN_CONFIG(version)) {
  case CURL_SSLVERSION_DEFAULT:
  case CURL_SSLVERSION_TLSv1:

    
    req_method = SSLv23_client_method();

    infof(data, "wolfSSL <3.3.0 cannot be configured to use TLS 1.0-1.2, " "TLS 1.0 is used exclusively\n");
    req_method = TLSv1_client_method();

    use_sni(TRUE);
    break;
  case CURL_SSLVERSION_TLSv1_0:

    req_method = TLSv1_client_method();
    use_sni(TRUE);

    failf(data, "wolfSSL does not support TLS 1.0");
    return CURLE_NOT_BUILT_IN;

    break;
  case CURL_SSLVERSION_TLSv1_1:

    req_method = TLSv1_1_client_method();
    use_sni(TRUE);

    failf(data, "wolfSSL does not support TLS 1.1");
    return CURLE_NOT_BUILT_IN;

    break;
  case CURL_SSLVERSION_TLSv1_2:
    req_method = TLSv1_2_client_method();
    use_sni(TRUE);
    break;
  case CURL_SSLVERSION_TLSv1_3:

    req_method = wolfTLSv1_3_client_method();
    use_sni(TRUE);
    break;

    failf(data, "wolfSSL: TLS 1.3 is not yet supported");
    return CURLE_SSL_CONNECT_ERROR;

  default:
    failf(data, "Unrecognized parameter passed via CURLOPT_SSLVERSION");
    return CURLE_SSL_CONNECT_ERROR;
  }

  if(!req_method) {
    failf(data, "SSL: couldn't create a method!");
    return CURLE_OUT_OF_MEMORY;
  }

  if(backend->ctx)
    SSL_CTX_free(backend->ctx);
  backend->ctx = SSL_CTX_new(req_method);

  if(!backend->ctx) {
    failf(data, "SSL: couldn't create a context!");
    return CURLE_OUT_OF_MEMORY;
  }

  switch(SSL_CONN_CONFIG(version)) {
  case CURL_SSLVERSION_DEFAULT:
  case CURL_SSLVERSION_TLSv1:

    
    if((wolfSSL_CTX_SetMinVersion(backend->ctx, WOLFSSL_TLSV1) != 1) && (wolfSSL_CTX_SetMinVersion(backend->ctx, WOLFSSL_TLSV1_1) != 1) && (wolfSSL_CTX_SetMinVersion(backend->ctx, WOLFSSL_TLSV1_2) != 1)


       && (wolfSSL_CTX_SetMinVersion(backend->ctx, WOLFSSL_TLSV1_3) != 1)

      ) {
      failf(data, "SSL: couldn't set the minimum protocol version");
      return CURLE_SSL_CONNECT_ERROR;
    }

    break;
  }

  ciphers = SSL_CONN_CONFIG(cipher_list);
  if(ciphers) {
    if(!SSL_CTX_set_cipher_list(backend->ctx, ciphers)) {
      failf(data, "failed setting cipher list: %s", ciphers);
      return CURLE_SSL_CIPHER;
    }
    infof(data, "Cipher selection: %s\n", ciphers);
  }


  
  if(SSL_CONN_CONFIG(CAfile)) {
    if(1 != SSL_CTX_load_verify_locations(backend->ctx, SSL_CONN_CONFIG(CAfile), SSL_CONN_CONFIG(CApath))) {

      if(SSL_CONN_CONFIG(verifypeer)) {
        
        failf(data, "error setting certificate verify locations:" " CAfile: %s CApath: %s", SSL_CONN_CONFIG(CAfile)? SSL_CONN_CONFIG(CAfile): "none", SSL_CONN_CONFIG(CApath)? SSL_CONN_CONFIG(CApath) : "none");




        return CURLE_SSL_CACERT_BADFILE;
      }
      else {
        
        infof(data, "error setting certificate verify locations," " continuing anyway:\n");
      }
    }
    else {
      
      infof(data, "successfully set certificate verify locations:\n");
    }
    infof(data, " CAfile: %s\n", SSL_CONN_CONFIG(CAfile) ? SSL_CONN_CONFIG(CAfile) : "none");
    infof(data, " CApath: %s\n", SSL_CONN_CONFIG(CApath) ? SSL_CONN_CONFIG(CApath) : "none");
  }

  
  if(SSL_SET_OPTION(primary.clientcert) && SSL_SET_OPTION(key)) {
    int file_type = do_file_type(SSL_SET_OPTION(cert_type));

    if(SSL_CTX_use_certificate_file(backend->ctx, SSL_SET_OPTION(primary.clientcert), file_type) != 1) {

      failf(data, "unable to use client certificate (no key or wrong pass" " phrase?)");
      return CURLE_SSL_CONNECT_ERROR;
    }

    file_type = do_file_type(SSL_SET_OPTION(key_type));
    if(SSL_CTX_use_PrivateKey_file(backend->ctx, SSL_SET_OPTION(key), file_type) != 1) {
      failf(data, "unable to set private key");
      return CURLE_SSL_CONNECT_ERROR;
    }
  }


  
  SSL_CTX_set_verify(backend->ctx, SSL_CONN_CONFIG(verifypeer)?SSL_VERIFY_PEER:
                                                 SSL_VERIFY_NONE, NULL);


  if(sni) {
    struct in_addr addr4;

    struct in6_addr addr6;

    const char * const hostname = SSL_HOST_NAME();
    size_t hostname_len = strlen(hostname);
    if((hostname_len < USHRT_MAX) && (0 == Curl_inet_pton(AF_INET, hostname, &addr4)) &&  (0 == Curl_inet_pton(AF_INET6, hostname, &addr6)) &&  (wolfSSL_CTX_UseSNI(backend->ctx, WOLFSSL_SNI_HOST_NAME, hostname, (unsigned short)hostname_len) != 1)) {





      infof(data, "WARNING: failed to configure server name indication (SNI) " "TLS extension\n");
    }
  }


  
  if(data->set.ssl.fsslctx) {
    CURLcode result = (*data->set.ssl.fsslctx)(data, backend->ctx, data->set.ssl.fsslctxp);
    if(result) {
      failf(data, "error signaled by ssl ctx callback");
      return result;
    }
  }

  else if(SSL_CONN_CONFIG(verifypeer)) {
    failf(data, "SSL: Certificates can't be loaded because wolfSSL was built" " with \"no filesystem\". Either disable peer verification" " (insecure) or if you are building an application with libcurl you" " can load certificates via CURLOPT_SSL_CTX_FUNCTION.");


    return CURLE_SSL_CONNECT_ERROR;
  }


  
  if(backend->handle)
    SSL_free(backend->handle);
  backend->handle = SSL_new(backend->ctx);
  if(!backend->handle) {
    failf(data, "SSL: couldn't create a context (handle)!");
    return CURLE_OUT_OF_MEMORY;
  }


  if(conn->bits.tls_enable_alpn) {
    char protocols[128];
    *protocols = '\0';

    


    if(data->state.httpwant >= CURL_HTTP_VERSION_2) {
      strcpy(protocols + strlen(protocols), ALPN_H2 ",");
      infof(data, "ALPN, offering %s\n", ALPN_H2);
    }


    strcpy(protocols + strlen(protocols), ALPN_HTTP_1_1);
    infof(data, "ALPN, offering %s\n", ALPN_HTTP_1_1);

    if(wolfSSL_UseALPN(backend->handle, protocols, (unsigned)strlen(protocols), WOLFSSL_ALPN_CONTINUE_ON_MISMATCH) != SSL_SUCCESS) {

      failf(data, "SSL: failed setting ALPN protocols");
      return CURLE_SSL_CONNECT_ERROR;
    }
  }



  if(Curl_tls_keylog_enabled()) {
    
    wolfSSL_KeepArrays(backend->handle);

    wolfSSL_set_tls13_secret_cb(backend->handle, wolfssl_tls13_secret_callback, NULL);

  }



  if(wolfSSL_UseSecureRenegotiation(backend->handle) != SSL_SUCCESS) {
    failf(data, "SSL: failed setting secure renegotiation");
    return CURLE_SSL_CONNECT_ERROR;
  }


  
  if(SSL_SET_OPTION(primary.sessionid)) {
    void *ssl_sessionid = NULL;

    Curl_ssl_sessionid_lock(data);
    if(!Curl_ssl_getsessionid(data, conn, SSL_IS_PROXY() ? TRUE : FALSE, &ssl_sessionid, NULL, sockindex)) {

      
      if(!SSL_set_session(backend->handle, ssl_sessionid)) {
        char error_buffer[WOLFSSL_MAX_ERROR_SZ];
        Curl_ssl_sessionid_unlock(data);
        failf(data, "SSL: SSL_set_session failed: %s", ERR_error_string(SSL_get_error(backend->handle, 0), error_buffer));

        return CURLE_SSL_CONNECT_ERROR;
      }
      
      infof(data, "SSL re-using session ID\n");
    }
    Curl_ssl_sessionid_unlock(data);
  }

  
  if(!SSL_set_fd(backend->handle, (int)sockfd)) {
    failf(data, "SSL: SSL_set_fd failed");
    return CURLE_SSL_CONNECT_ERROR;
  }

  connssl->connecting_state = ssl_connect_2;
  return CURLE_OK;
}


static CURLcode wolfssl_connect_step2(struct Curl_easy *data, struct connectdata *conn, int sockindex)

{
  int ret = -1;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  struct ssl_backend_data *backend = connssl->backend;
  const char * const hostname = SSL_HOST_NAME();
  const char * const dispname = SSL_HOST_DISPNAME();
  const char * const pinnedpubkey = SSL_PINNED_PUB_KEY();

  conn->recv[sockindex] = wolfssl_recv;
  conn->send[sockindex] = wolfssl_send;

  
  if(SSL_CONN_CONFIG(verifyhost)) {
    ret = wolfSSL_check_domain_name(backend->handle, hostname);
    if(ret == SSL_FAILURE)
      return CURLE_OUT_OF_MEMORY;
  }

  ret = SSL_connect(backend->handle);


  if(Curl_tls_keylog_enabled()) {
    
    if(ret == SSL_SUCCESS || (!wolfSSL_want_read(backend->handle) && !wolfSSL_want_write(backend->handle))) {

      wolfssl_log_tls12_secret(backend->handle);
      
      wolfSSL_FreeArrays(backend->handle);
    }
  }


  if(ret != 1) {
    char error_buffer[WOLFSSL_MAX_ERROR_SZ];
    int  detail = SSL_get_error(backend->handle, ret);

    if(SSL_ERROR_WANT_READ == detail) {
      connssl->connecting_state = ssl_connect_2_reading;
      return CURLE_OK;
    }
    else if(SSL_ERROR_WANT_WRITE == detail) {
      connssl->connecting_state = ssl_connect_2_writing;
      return CURLE_OK;
    }
    
    else if(DOMAIN_NAME_MISMATCH == detail) {

      failf(data, "\tsubject alt name(s) or common name do not match \"%s\"", dispname);
      return CURLE_PEER_FAILED_VERIFICATION;

      
      if(SSL_CONN_CONFIG(verifyhost)) {
        failf(data, "\tsubject alt name(s) or common name do not match \"%s\"\n", dispname);

        return CURLE_PEER_FAILED_VERIFICATION;
      }
      else {
        infof(data, "\tsubject alt name(s) and/or common name do not match \"%s\"\n", dispname);

        return CURLE_OK;
      }

    }

    else if(ASN_NO_SIGNER_E == detail) {
      if(SSL_CONN_CONFIG(verifypeer)) {
        failf(data, "\tCA signer not available for verification");
        return CURLE_SSL_CACERT_BADFILE;
      }
      else {
        
        infof(data, "CA signer not available for verification, " "continuing anyway\n");
      }
    }

    else {
      failf(data, "SSL_connect failed with error %d: %s", detail, ERR_error_string(detail, error_buffer));
      return CURLE_SSL_CONNECT_ERROR;
    }
  }

  if(pinnedpubkey) {

    X509 *x509;
    const char *x509_der;
    int x509_der_len;
    struct Curl_X509certificate x509_parsed;
    struct Curl_asn1Element *pubkey;
    CURLcode result;

    x509 = SSL_get_peer_certificate(backend->handle);
    if(!x509) {
      failf(data, "SSL: failed retrieving server certificate");
      return CURLE_SSL_PINNEDPUBKEYNOTMATCH;
    }

    x509_der = (const char *)wolfSSL_X509_get_der(x509, &x509_der_len);
    if(!x509_der) {
      failf(data, "SSL: failed retrieving ASN.1 server certificate");
      return CURLE_SSL_PINNEDPUBKEYNOTMATCH;
    }

    memset(&x509_parsed, 0, sizeof(x509_parsed));
    if(Curl_parseX509(&x509_parsed, x509_der, x509_der + x509_der_len))
      return CURLE_SSL_PINNEDPUBKEYNOTMATCH;

    pubkey = &x509_parsed.subjectPublicKeyInfo;
    if(!pubkey->header || pubkey->end <= pubkey->header) {
      failf(data, "SSL: failed retrieving public key from server certificate");
      return CURLE_SSL_PINNEDPUBKEYNOTMATCH;
    }

    result = Curl_pin_peer_pubkey(data, pinnedpubkey, (const unsigned char *)pubkey->header, (size_t)(pubkey->end - pubkey->header));


    if(result) {
      failf(data, "SSL: public key does not match pinned public key!");
      return result;
    }

    failf(data, "Library lacks pinning support built-in");
    return CURLE_NOT_BUILT_IN;

  }


  if(conn->bits.tls_enable_alpn) {
    int rc;
    char *protocol = NULL;
    unsigned short protocol_len = 0;

    rc = wolfSSL_ALPN_GetProtocol(backend->handle, &protocol, &protocol_len);

    if(rc == SSL_SUCCESS) {
      infof(data, "ALPN, server accepted to use %.*s\n", protocol_len, protocol);

      if(protocol_len == ALPN_HTTP_1_1_LENGTH && !memcmp(protocol, ALPN_HTTP_1_1, ALPN_HTTP_1_1_LENGTH))
        conn->negnpn = CURL_HTTP_VERSION_1_1;

      else if(data->state.httpwant >= CURL_HTTP_VERSION_2 && protocol_len == ALPN_H2_LENGTH && !memcmp(protocol, ALPN_H2, ALPN_H2_LENGTH))

        conn->negnpn = CURL_HTTP_VERSION_2;

      else infof(data, "ALPN, unrecognized protocol %.*s\n", protocol_len, protocol);

      Curl_multiuse_state(data, conn->negnpn == CURL_HTTP_VERSION_2 ? BUNDLE_MULTIPLEX : BUNDLE_NO_MULTIUSE);
    }
    else if(rc == SSL_ALPN_NOT_FOUND)
      infof(data, "ALPN, server did not agree to a protocol\n");
    else {
      failf(data, "ALPN, failure getting protocol, error %d", rc);
      return CURLE_SSL_CONNECT_ERROR;
    }
  }


  connssl->connecting_state = ssl_connect_3;

  infof(data, "SSL connection using %s / %s\n", wolfSSL_get_version(backend->handle), wolfSSL_get_cipher_name(backend->handle));


  infof(data, "SSL connected\n");


  return CURLE_OK;
}


static CURLcode wolfssl_connect_step3(struct Curl_easy *data, struct connectdata *conn, int sockindex)

{
  CURLcode result = CURLE_OK;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  struct ssl_backend_data *backend = connssl->backend;

  DEBUGASSERT(ssl_connect_3 == connssl->connecting_state);

  if(SSL_SET_OPTION(primary.sessionid)) {
    bool incache;
    void *old_ssl_sessionid = NULL;
    SSL_SESSION *our_ssl_sessionid = SSL_get_session(backend->handle);
    bool isproxy = SSL_IS_PROXY() ? TRUE : FALSE;

    if(our_ssl_sessionid) {
      Curl_ssl_sessionid_lock(data);
      incache = !(Curl_ssl_getsessionid(data, conn, isproxy, &old_ssl_sessionid, NULL, sockindex));
      if(incache) {
        if(old_ssl_sessionid != our_ssl_sessionid) {
          infof(data, "old SSL session ID is stale, removing\n");
          Curl_ssl_delsessionid(data, old_ssl_sessionid);
          incache = FALSE;
        }
      }

      if(!incache) {
        result = Curl_ssl_addsessionid(data, conn, isproxy, our_ssl_sessionid, 0, sockindex);
        if(result) {
          Curl_ssl_sessionid_unlock(data);
          failf(data, "failed to store ssl session");
          return result;
        }
      }
      Curl_ssl_sessionid_unlock(data);
    }
  }

  connssl->connecting_state = ssl_connect_done;

  return result;
}


static ssize_t wolfssl_send(struct Curl_easy *data, int sockindex, const void *mem, size_t len, CURLcode *curlcode)



{
  struct connectdata *conn = data->conn;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  struct ssl_backend_data *backend = connssl->backend;
  char error_buffer[WOLFSSL_MAX_ERROR_SZ];
  int memlen = (len > (size_t)INT_MAX) ? INT_MAX : (int)len;
  int rc = SSL_write(backend->handle, mem, memlen);

  if(rc <= 0) {
    int err = SSL_get_error(backend->handle, rc);

    switch(err) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      
      *curlcode = CURLE_AGAIN;
      return -1;
    default:
      failf(data, "SSL write: %s, errno %d", ERR_error_string(err, error_buffer), SOCKERRNO);

      *curlcode = CURLE_SEND_ERROR;
      return -1;
    }
  }
  return rc;
}

static void wolfssl_close(struct Curl_easy *data, struct connectdata *conn, int sockindex)
{
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  struct ssl_backend_data *backend = connssl->backend;

  (void) data;

  if(backend->handle) {
    (void)SSL_shutdown(backend->handle);
    SSL_free(backend->handle);
    backend->handle = NULL;
  }
  if(backend->ctx) {
    SSL_CTX_free(backend->ctx);
    backend->ctx = NULL;
  }
}

static ssize_t wolfssl_recv(struct Curl_easy *data, int num, char *buf, size_t buffersize, CURLcode *curlcode)



{
  struct connectdata *conn = data->conn;
  struct ssl_connect_data *connssl = &conn->ssl[num];
  struct ssl_backend_data *backend = connssl->backend;
  char error_buffer[WOLFSSL_MAX_ERROR_SZ];
  int buffsize = (buffersize > (size_t)INT_MAX) ? INT_MAX : (int)buffersize;
  int nread = SSL_read(backend->handle, buf, buffsize);

  if(nread < 0) {
    int err = SSL_get_error(backend->handle, nread);

    switch(err) {
    case SSL_ERROR_ZERO_RETURN: 
      break;
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      
      *curlcode = CURLE_AGAIN;
      return -1;
    default:
      failf(data, "SSL read: %s, errno %d", ERR_error_string(err, error_buffer), SOCKERRNO);
      *curlcode = CURLE_RECV_ERROR;
      return -1;
    }
  }
  return nread;
}


static void wolfssl_session_free(void *ptr)
{
  (void)ptr;
  
}


static size_t wolfssl_version(char *buffer, size_t size)
{

  return msnprintf(buffer, size, "wolfSSL/%s", wolfSSL_lib_version());

  return msnprintf(buffer, size, "wolfSSL/%s", WOLFSSL_VERSION);

}


static int wolfssl_init(void)
{

  Curl_tls_keylog_open();

  return (wolfSSL_Init() == SSL_SUCCESS);
}


static void wolfssl_cleanup(void)
{
  wolfSSL_Cleanup();

  Curl_tls_keylog_close();

}


static bool wolfssl_data_pending(const struct connectdata *conn, int connindex)
{
  const struct ssl_connect_data *connssl = &conn->ssl[connindex];
  struct ssl_backend_data *backend = connssl->backend;
  if(backend->handle)   
    return (0 != SSL_pending(backend->handle)) ? TRUE : FALSE;
  else return FALSE;
}



static int wolfssl_shutdown(struct Curl_easy *data, struct connectdata *conn, int sockindex)
{
  int retval = 0;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  struct ssl_backend_data *backend = connssl->backend;

  (void) data;

  if(backend->handle) {
    SSL_free(backend->handle);
    backend->handle = NULL;
  }
  return retval;
}


static CURLcode wolfssl_connect_common(struct Curl_easy *data, struct connectdata *conn, int sockindex, bool nonblocking, bool *done)




{
  CURLcode result;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  curl_socket_t sockfd = conn->sock[sockindex];
  int what;

  
  if(ssl_connection_complete == connssl->state) {
    *done = TRUE;
    return CURLE_OK;
  }

  if(ssl_connect_1 == connssl->connecting_state) {
    
    const timediff_t timeout_ms = Curl_timeleft(data, NULL, TRUE);

    if(timeout_ms < 0) {
      
      failf(data, "SSL connection timeout");
      return CURLE_OPERATION_TIMEDOUT;
    }

    result = wolfssl_connect_step1(data, conn, sockindex);
    if(result)
      return result;
  }

  while(ssl_connect_2 == connssl->connecting_state || ssl_connect_2_reading == connssl->connecting_state || ssl_connect_2_writing == connssl->connecting_state) {


    
    const timediff_t timeout_ms = Curl_timeleft(data, NULL, TRUE);

    if(timeout_ms < 0) {
      
      failf(data, "SSL connection timeout");
      return CURLE_OPERATION_TIMEDOUT;
    }

    
    if(connssl->connecting_state == ssl_connect_2_reading || connssl->connecting_state == ssl_connect_2_writing) {

      curl_socket_t writefd = ssl_connect_2_writing == connssl->connecting_state?sockfd:CURL_SOCKET_BAD;
      curl_socket_t readfd = ssl_connect_2_reading == connssl->connecting_state?sockfd:CURL_SOCKET_BAD;

      what = Curl_socket_check(readfd, CURL_SOCKET_BAD, writefd, nonblocking?0:timeout_ms);
      if(what < 0) {
        
        failf(data, "select/poll on SSL socket, errno: %d", SOCKERRNO);
        return CURLE_SSL_CONNECT_ERROR;
      }
      else if(0 == what) {
        if(nonblocking) {
          *done = FALSE;
          return CURLE_OK;
        }
        else {
          
          failf(data, "SSL connection timeout");
          return CURLE_OPERATION_TIMEDOUT;
        }
      }
      
    }

    
    result = wolfssl_connect_step2(data, conn, sockindex);
    if(result || (nonblocking && (ssl_connect_2 == connssl->connecting_state || ssl_connect_2_reading == connssl->connecting_state || ssl_connect_2_writing == connssl->connecting_state)))


      return result;
  } 

  if(ssl_connect_3 == connssl->connecting_state) {
    result = wolfssl_connect_step3(data, conn, sockindex);
    if(result)
      return result;
  }

  if(ssl_connect_done == connssl->connecting_state) {
    connssl->state = ssl_connection_complete;
    conn->recv[sockindex] = wolfssl_recv;
    conn->send[sockindex] = wolfssl_send;
    *done = TRUE;
  }
  else *done = FALSE;

  
  connssl->connecting_state = ssl_connect_1;

  return CURLE_OK;
}


static CURLcode wolfssl_connect_nonblocking(struct Curl_easy *data, struct connectdata *conn, int sockindex, bool *done)

{
  return wolfssl_connect_common(data, conn, sockindex, TRUE, done);
}


static CURLcode wolfssl_connect(struct Curl_easy *data, struct connectdata *conn, int sockindex)
{
  CURLcode result;
  bool done = FALSE;

  result = wolfssl_connect_common(data, conn, sockindex, FALSE, &done);
  if(result)
    return result;

  DEBUGASSERT(done);

  return CURLE_OK;
}

static CURLcode wolfssl_random(struct Curl_easy *data, unsigned char *entropy, size_t length)
{
  WC_RNG rng;
  (void)data;
  if(wc_InitRng(&rng))
    return CURLE_FAILED_INIT;
  if(length > UINT_MAX)
    return CURLE_FAILED_INIT;
  if(wc_RNG_GenerateBlock(&rng, entropy, (unsigned)length))
    return CURLE_FAILED_INIT;
  if(wc_FreeRng(&rng))
    return CURLE_FAILED_INIT;
  return CURLE_OK;
}

static CURLcode wolfssl_sha256sum(const unsigned char *tmp,  size_t tmplen, unsigned char *sha256sum , size_t unused)


{
  wc_Sha256 SHA256pw;
  (void)unused;
  wc_InitSha256(&SHA256pw);
  wc_Sha256Update(&SHA256pw, tmp, (word32)tmplen);
  wc_Sha256Final(&SHA256pw, sha256sum);
  return CURLE_OK;
}

static void *wolfssl_get_internals(struct ssl_connect_data *connssl, CURLINFO info UNUSED_PARAM)
{
  struct ssl_backend_data *backend = connssl->backend;
  (void)info;
  return backend->handle;
}

const struct Curl_ssl Curl_ssl_wolfssl = {
  { CURLSSLBACKEND_WOLFSSL, "WolfSSL" },    SSLSUPP_PINNEDPUBKEY |  SSLSUPP_SSL_CTX,  sizeof(struct ssl_backend_data),  wolfssl_init, wolfssl_cleanup, wolfssl_version, Curl_none_check_cxn, wolfssl_shutdown, wolfssl_data_pending, wolfssl_random, Curl_none_cert_status_request, wolfssl_connect, wolfssl_connect_nonblocking, Curl_ssl_getsock, wolfssl_get_internals, wolfssl_close, Curl_none_close_all, wolfssl_session_free, Curl_none_set_engine, Curl_none_set_engine_default, Curl_none_engines_list, Curl_none_false_start, wolfssl_sha256sum };






























