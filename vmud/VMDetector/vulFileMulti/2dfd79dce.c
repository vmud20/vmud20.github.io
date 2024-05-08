











































































static Curl_recv cyassl_recv;
static Curl_send cyassl_send;


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


static CURLcode cyassl_connect_step1(struct connectdata *conn, int sockindex)

{
  char error_buffer[CYASSL_MAX_ERROR_SZ];
  char *ciphers;
  struct Curl_easy *data = conn->data;
  struct ssl_connect_data* conssl = &conn->ssl[sockindex];
  SSL_METHOD* req_method = NULL;
  curl_socket_t sockfd = conn->sock[sockindex];

  bool sni = FALSE;





  if(conssl->state == ssl_connection_complete)
    return CURLE_OK;

  if(SSL_CONN_CONFIG(version_max) != CURL_SSLVERSION_MAX_NONE) {
    failf(data, "CyaSSL does not support to set maximum SSL/TLS version");
    return CURLE_SSL_CONNECT_ERROR;
  }

  
  switch(SSL_CONN_CONFIG(version)) {
  case CURL_SSLVERSION_DEFAULT:
  case CURL_SSLVERSION_TLSv1:

    
    req_method = SSLv23_client_method();

    infof(data, "CyaSSL <3.3.0 cannot be configured to use TLS 1.0-1.2, " "TLS 1.0 is used exclusively\n");
    req_method = TLSv1_client_method();

    use_sni(TRUE);
    break;
  case CURL_SSLVERSION_TLSv1_0:
    req_method = TLSv1_client_method();
    use_sni(TRUE);
    break;
  case CURL_SSLVERSION_TLSv1_1:
    req_method = TLSv1_1_client_method();
    use_sni(TRUE);
    break;
  case CURL_SSLVERSION_TLSv1_2:
    req_method = TLSv1_2_client_method();
    use_sni(TRUE);
    break;
  case CURL_SSLVERSION_TLSv1_3:
    failf(data, "CyaSSL: TLS 1.3 is not yet supported");
    return CURLE_SSL_CONNECT_ERROR;
  case CURL_SSLVERSION_SSLv3:

    req_method = SSLv3_client_method();
    use_sni(FALSE);

    failf(data, "CyaSSL does not support SSLv3");
    return CURLE_NOT_BUILT_IN;

    break;
  case CURL_SSLVERSION_SSLv2:
    failf(data, "CyaSSL does not support SSLv2");
    return CURLE_SSL_CONNECT_ERROR;
  default:
    failf(data, "Unrecognized parameter passed via CURLOPT_SSLVERSION");
    return CURLE_SSL_CONNECT_ERROR;
  }

  if(!req_method) {
    failf(data, "SSL: couldn't create a method!");
    return CURLE_OUT_OF_MEMORY;
  }

  if(conssl->ctx)
    SSL_CTX_free(conssl->ctx);
  conssl->ctx = SSL_CTX_new(req_method);

  if(!conssl->ctx) {
    failf(data, "SSL: couldn't create a context!");
    return CURLE_OUT_OF_MEMORY;
  }

  switch(SSL_CONN_CONFIG(version)) {
  case CURL_SSLVERSION_DEFAULT:
  case CURL_SSLVERSION_TLSv1:

    
    if((wolfSSL_CTX_SetMinVersion(conssl->ctx, WOLFSSL_TLSV1) != 1) && (wolfSSL_CTX_SetMinVersion(conssl->ctx, WOLFSSL_TLSV1_1) != 1) && (wolfSSL_CTX_SetMinVersion(conssl->ctx, WOLFSSL_TLSV1_2) != 1)) {

      failf(data, "SSL: couldn't set the minimum protocol version");
      return CURLE_SSL_CONNECT_ERROR;
    }

    break;
  }

  ciphers = SSL_CONN_CONFIG(cipher_list);
  if(ciphers) {
    if(!SSL_CTX_set_cipher_list(conssl->ctx, ciphers)) {
      failf(data, "failed setting cipher list: %s", ciphers);
      return CURLE_SSL_CIPHER;
    }
    infof(data, "Cipher selection: %s\n", ciphers);
  }


  
  if(SSL_CONN_CONFIG(CAfile)) {
    if(1 != SSL_CTX_load_verify_locations(conssl->ctx, SSL_CONN_CONFIG(CAfile), SSL_CONN_CONFIG(CApath))) {

      if(SSL_CONN_CONFIG(verifypeer)) {
        
        failf(data, "error setting certificate verify locations:\n" "  CAfile: %s\n  CApath: %s", SSL_CONN_CONFIG(CAfile)? SSL_CONN_CONFIG(CAfile): "none", SSL_CONN_CONFIG(CApath)? SSL_CONN_CONFIG(CApath) : "none");




        return CURLE_SSL_CACERT_BADFILE;
      }
      else {
        
        infof(data, "error setting certificate verify locations," " continuing anyway:\n");
      }
    }
    else {
      
      infof(data, "successfully set certificate verify locations:\n");
    }
    infof(data, "  CAfile: %s\n" "  CApath: %s\n", SSL_CONN_CONFIG(CAfile) ? SSL_CONN_CONFIG(CAfile):


          "none", SSL_CONN_CONFIG(CApath) ? SSL_CONN_CONFIG(CApath):
          "none");
  }

  
  if(SSL_SET_OPTION(cert) && SSL_SET_OPTION(key)) {
    int file_type = do_file_type(SSL_SET_OPTION(cert_type));

    if(SSL_CTX_use_certificate_file(conssl->ctx, SSL_SET_OPTION(cert), file_type) != 1) {
      failf(data, "unable to use client certificate (no key or wrong pass" " phrase?)");
      return CURLE_SSL_CONNECT_ERROR;
    }

    file_type = do_file_type(SSL_SET_OPTION(key_type));
    if(SSL_CTX_use_PrivateKey_file(conssl->ctx, SSL_SET_OPTION(key), file_type) != 1) {
      failf(data, "unable to set private key");
      return CURLE_SSL_CONNECT_ERROR;
    }
  }


  
  SSL_CTX_set_verify(conssl->ctx, SSL_CONN_CONFIG(verifypeer)?SSL_VERIFY_PEER:
                                                 SSL_VERIFY_NONE, NULL);


  if(sni) {
    struct in_addr addr4;

    struct in6_addr addr6;

    const char * const hostname = SSL_IS_PROXY() ? conn->http_proxy.host.name :
      conn->host.name;
    size_t hostname_len = strlen(hostname);
    if((hostname_len < USHRT_MAX) && (0 == Curl_inet_pton(AF_INET, hostname, &addr4)) &&  (0 == Curl_inet_pton(AF_INET6, hostname, &addr6)) &&  (CyaSSL_CTX_UseSNI(conssl->ctx, CYASSL_SNI_HOST_NAME, hostname, (unsigned short)hostname_len) != 1)) {





      infof(data, "WARNING: failed to configure server name indication (SNI) " "TLS extension\n");
    }
  }



  
  CyaSSL_CTX_UseSupportedCurve(conssl->ctx, 0x17); 
  CyaSSL_CTX_UseSupportedCurve(conssl->ctx, 0x19); 
  CyaSSL_CTX_UseSupportedCurve(conssl->ctx, 0x18); 


  
  if(data->set.ssl.fsslctx) {
    CURLcode result = CURLE_OK;
    result = (*data->set.ssl.fsslctx)(data, conssl->ctx, data->set.ssl.fsslctxp);
    if(result) {
      failf(data, "error signaled by ssl ctx callback");
      return result;
    }
  }

  else if(SSL_CONN_CONFIG(verifypeer)) {
    failf(data, "SSL: Certificates couldn't be loaded because CyaSSL was built" " with \"no filesystem\". Either disable peer verification" " (insecure) or if you are building an application with libcurl you" " can load certificates via CURLOPT_SSL_CTX_FUNCTION.");


    return CURLE_SSL_CONNECT_ERROR;
  }


  
  if(conssl->handle)
    SSL_free(conssl->handle);
  conssl->handle = SSL_new(conssl->ctx);
  if(!conssl->handle) {
    failf(data, "SSL: couldn't create a context (handle)!");
    return CURLE_OUT_OF_MEMORY;
  }


  if(conn->bits.tls_enable_alpn) {
    char protocols[128];
    *protocols = '\0';

    


    if(data->set.httpversion >= CURL_HTTP_VERSION_2) {
      strcpy(protocols + strlen(protocols), NGHTTP2_PROTO_VERSION_ID ",");
      infof(data, "ALPN, offering %s\n", NGHTTP2_PROTO_VERSION_ID);
    }


    strcpy(protocols + strlen(protocols), ALPN_HTTP_1_1);
    infof(data, "ALPN, offering %s\n", ALPN_HTTP_1_1);

    if(wolfSSL_UseALPN(conssl->handle, protocols, (unsigned)strlen(protocols), WOLFSSL_ALPN_CONTINUE_ON_MISMATCH) != SSL_SUCCESS) {

      failf(data, "SSL: failed setting ALPN protocols");
      return CURLE_SSL_CONNECT_ERROR;
    }
  }


  
  if(data->set.general_ssl.sessionid) {
    void *ssl_sessionid = NULL;

    Curl_ssl_sessionid_lock(conn);
    if(!Curl_ssl_getsessionid(conn, &ssl_sessionid, NULL, sockindex)) {
      
      if(!SSL_set_session(conssl->handle, ssl_sessionid)) {
        Curl_ssl_sessionid_unlock(conn);
        failf(data, "SSL: SSL_set_session failed: %s", ERR_error_string(SSL_get_error(conssl->handle, 0), error_buffer));

        return CURLE_SSL_CONNECT_ERROR;
      }
      
      infof(data, "SSL re-using session ID\n");
    }
    Curl_ssl_sessionid_unlock(conn);
  }

  
  if(!SSL_set_fd(conssl->handle, (int)sockfd)) {
    failf(data, "SSL: SSL_set_fd failed");
    return CURLE_SSL_CONNECT_ERROR;
  }

  conssl->connecting_state = ssl_connect_2;
  return CURLE_OK;
}


static CURLcode cyassl_connect_step2(struct connectdata *conn, int sockindex)

{
  int ret = -1;
  struct Curl_easy *data = conn->data;
  struct ssl_connect_data* conssl = &conn->ssl[sockindex];
  const char * const hostname = SSL_IS_PROXY() ? conn->http_proxy.host.name :
    conn->host.name;
  const char * const dispname = SSL_IS_PROXY() ? conn->http_proxy.host.dispname : conn->host.dispname;
  const char * const pinnedpubkey = SSL_IS_PROXY() ? data->set.str[STRING_SSL_PINNEDPUBLICKEY_PROXY] :
                        data->set.str[STRING_SSL_PINNEDPUBLICKEY_ORIG];

  conn->recv[sockindex] = cyassl_recv;
  conn->send[sockindex] = cyassl_send;

  
  if(SSL_CONN_CONFIG(verifyhost)) {
    ret = CyaSSL_check_domain_name(conssl->handle, hostname);
    if(ret == SSL_FAILURE)
      return CURLE_OUT_OF_MEMORY;
  }

  ret = SSL_connect(conssl->handle);
  if(ret != 1) {
    char error_buffer[CYASSL_MAX_ERROR_SZ];
    int  detail = SSL_get_error(conssl->handle, ret);

    if(SSL_ERROR_WANT_READ == detail) {
      conssl->connecting_state = ssl_connect_2_reading;
      return CURLE_OK;
    }
    else if(SSL_ERROR_WANT_WRITE == detail) {
      conssl->connecting_state = ssl_connect_2_writing;
      return CURLE_OK;
    }
    
    else if(DOMAIN_NAME_MISMATCH == detail) {

      failf(data, "\tsubject alt name(s) or common name do not match \"%s\"\n", dispname);
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
        failf(data, "\tCA signer not available for verification\n");
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
    curl_X509certificate x509_parsed;
    curl_asn1Element *pubkey;
    CURLcode result;

    x509 = SSL_get_peer_certificate(conssl->handle);
    if(!x509) {
      failf(data, "SSL: failed retrieving server certificate");
      return CURLE_SSL_PINNEDPUBKEYNOTMATCH;
    }

    x509_der = (const char *)CyaSSL_X509_get_der(x509, &x509_der_len);
    if(!x509_der) {
      failf(data, "SSL: failed retrieving ASN.1 server certificate");
      return CURLE_SSL_PINNEDPUBKEYNOTMATCH;
    }

    memset(&x509_parsed, 0, sizeof x509_parsed);
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

    rc = wolfSSL_ALPN_GetProtocol(conssl->handle, &protocol, &protocol_len);

    if(rc == SSL_SUCCESS) {
      infof(data, "ALPN, server accepted to use %.*s\n", protocol_len, protocol);

      if(protocol_len == ALPN_HTTP_1_1_LENGTH && !memcmp(protocol, ALPN_HTTP_1_1, ALPN_HTTP_1_1_LENGTH))
        conn->negnpn = CURL_HTTP_VERSION_1_1;

      else if(data->set.httpversion >= CURL_HTTP_VERSION_2 && protocol_len == NGHTTP2_PROTO_VERSION_ID_LEN && !memcmp(protocol, NGHTTP2_PROTO_VERSION_ID, NGHTTP2_PROTO_VERSION_ID_LEN))


        conn->negnpn = CURL_HTTP_VERSION_2;

      else infof(data, "ALPN, unrecognized protocol %.*s\n", protocol_len, protocol);

    }
    else if(rc == SSL_ALPN_NOT_FOUND)
      infof(data, "ALPN, server did not agree to a protocol\n");
    else {
      failf(data, "ALPN, failure getting protocol, error %d", rc);
      return CURLE_SSL_CONNECT_ERROR;
    }
  }


  conssl->connecting_state = ssl_connect_3;

  infof(data, "SSL connection using %s / %s\n", wolfSSL_get_version(conssl->handle), wolfSSL_get_cipher_name(conssl->handle));


  infof(data, "SSL connected\n");


  return CURLE_OK;
}


static CURLcode cyassl_connect_step3(struct connectdata *conn, int sockindex)

{
  CURLcode result = CURLE_OK;
  struct Curl_easy *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];

  DEBUGASSERT(ssl_connect_3 == connssl->connecting_state);

  if(data->set.general_ssl.sessionid) {
    bool incache;
    SSL_SESSION *our_ssl_sessionid;
    void *old_ssl_sessionid = NULL;

    our_ssl_sessionid = SSL_get_session(connssl->handle);

    Curl_ssl_sessionid_lock(conn);
    incache = !(Curl_ssl_getsessionid(conn, &old_ssl_sessionid, NULL, sockindex));
    if(incache) {
      if(old_ssl_sessionid != our_ssl_sessionid) {
        infof(data, "old SSL session ID is stale, removing\n");
        Curl_ssl_delsessionid(conn, old_ssl_sessionid);
        incache = FALSE;
      }
    }

    if(!incache) {
      result = Curl_ssl_addsessionid(conn, our_ssl_sessionid, 0 , sockindex);
      if(result) {
        Curl_ssl_sessionid_unlock(conn);
        failf(data, "failed to store ssl session");
        return result;
      }
    }
    Curl_ssl_sessionid_unlock(conn);
  }

  connssl->connecting_state = ssl_connect_done;

  return result;
}


static ssize_t cyassl_send(struct connectdata *conn, int sockindex, const void *mem, size_t len, CURLcode *curlcode)



{
  char error_buffer[CYASSL_MAX_ERROR_SZ];
  int  memlen = (len > (size_t)INT_MAX) ? INT_MAX : (int)len;
  int  rc     = SSL_write(conn->ssl[sockindex].handle, mem, memlen);

  if(rc < 0) {
    int err = SSL_get_error(conn->ssl[sockindex].handle, rc);

    switch(err) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      
      *curlcode = CURLE_AGAIN;
      return -1;
    default:
      failf(conn->data, "SSL write: %s, errno %d", ERR_error_string(err, error_buffer), SOCKERRNO);

      *curlcode = CURLE_SEND_ERROR;
      return -1;
    }
  }
  return rc;
}

void Curl_cyassl_close(struct connectdata *conn, int sockindex)
{
  struct ssl_connect_data *conssl = &conn->ssl[sockindex];

  if(conssl->handle) {
    (void)SSL_shutdown(conssl->handle);
    SSL_free(conssl->handle);
    conssl->handle = NULL;
  }
  if(conssl->ctx) {
    SSL_CTX_free(conssl->ctx);
    conssl->ctx = NULL;
  }
}

static ssize_t cyassl_recv(struct connectdata *conn, int num, char *buf, size_t buffersize, CURLcode *curlcode)



{
  char error_buffer[CYASSL_MAX_ERROR_SZ];
  int  buffsize = (buffersize > (size_t)INT_MAX) ? INT_MAX : (int)buffersize;
  int  nread    = SSL_read(conn->ssl[num].handle, buf, buffsize);

  if(nread < 0) {
    int err = SSL_get_error(conn->ssl[num].handle, nread);

    switch(err) {
    case SSL_ERROR_ZERO_RETURN: 
      break;
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      
      *curlcode = CURLE_AGAIN;
      return -1;
    default:
      failf(conn->data, "SSL read: %s, errno %d", ERR_error_string(err, error_buffer), SOCKERRNO);

      *curlcode = CURLE_RECV_ERROR;
      return -1;
    }
  }
  return nread;
}


void Curl_cyassl_session_free(void *ptr)
{
  (void)ptr;
  
}


size_t Curl_cyassl_version(char *buffer, size_t size)
{

  return snprintf(buffer, size, "wolfSSL/%s", wolfSSL_lib_version());

  return snprintf(buffer, size, "wolfSSL/%s", WOLFSSL_VERSION);

  return snprintf(buffer, size, "CyaSSL/%s", CYASSL_VERSION);

  return snprintf(buffer, size, "CyaSSL/%s", "<1.8.8");

}


int Curl_cyassl_init(void)
{
  return (CyaSSL_Init() == SSL_SUCCESS);
}


bool Curl_cyassl_data_pending(const struct connectdata* conn, int connindex)
{
  if(conn->ssl[connindex].handle)   
    return (0 != SSL_pending(conn->ssl[connindex].handle)) ? TRUE : FALSE;
  else return FALSE;
}



int Curl_cyassl_shutdown(struct connectdata *conn, int sockindex)
{
  int retval = 0;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];

  if(connssl->handle) {
    SSL_free(connssl->handle);
    connssl->handle = NULL;
  }
  return retval;
}


static CURLcode cyassl_connect_common(struct connectdata *conn, int sockindex, bool nonblocking, bool *done)



{
  CURLcode result;
  struct Curl_easy *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  curl_socket_t sockfd = conn->sock[sockindex];
  time_t timeout_ms;
  int what;

  
  if(ssl_connection_complete == connssl->state) {
    *done = TRUE;
    return CURLE_OK;
  }

  if(ssl_connect_1==connssl->connecting_state) {
    
    timeout_ms = Curl_timeleft(data, NULL, TRUE);

    if(timeout_ms < 0) {
      
      failf(data, "SSL connection timeout");
      return CURLE_OPERATION_TIMEDOUT;
    }

    result = cyassl_connect_step1(conn, sockindex);
    if(result)
      return result;
  }

  while(ssl_connect_2 == connssl->connecting_state || ssl_connect_2_reading == connssl->connecting_state || ssl_connect_2_writing == connssl->connecting_state) {


    
    timeout_ms = Curl_timeleft(data, NULL, TRUE);

    if(timeout_ms < 0) {
      
      failf(data, "SSL connection timeout");
      return CURLE_OPERATION_TIMEDOUT;
    }

    
    if(connssl->connecting_state == ssl_connect_2_reading || connssl->connecting_state == ssl_connect_2_writing) {

      curl_socket_t writefd = ssl_connect_2_writing== connssl->connecting_state?sockfd:CURL_SOCKET_BAD;
      curl_socket_t readfd = ssl_connect_2_reading== connssl->connecting_state?sockfd:CURL_SOCKET_BAD;

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

    
    result = cyassl_connect_step2(conn, sockindex);
    if(result || (nonblocking && (ssl_connect_2 == connssl->connecting_state || ssl_connect_2_reading == connssl->connecting_state || ssl_connect_2_writing == connssl->connecting_state)))


      return result;
  } 

  if(ssl_connect_3 == connssl->connecting_state) {
    result = cyassl_connect_step3(conn, sockindex);
    if(result)
      return result;
  }

  if(ssl_connect_done == connssl->connecting_state) {
    connssl->state = ssl_connection_complete;
    conn->recv[sockindex] = cyassl_recv;
    conn->send[sockindex] = cyassl_send;
    *done = TRUE;
  }
  else *done = FALSE;

  
  connssl->connecting_state = ssl_connect_1;

  return CURLE_OK;
}


CURLcode Curl_cyassl_connect_nonblocking(struct connectdata *conn, int sockindex, bool *done)


{
  return cyassl_connect_common(conn, sockindex, TRUE, done);
}


CURLcode Curl_cyassl_connect(struct connectdata *conn, int sockindex)

{
  CURLcode result;
  bool done = FALSE;

  result = cyassl_connect_common(conn, sockindex, FALSE, &done);
  if(result)
    return result;

  DEBUGASSERT(done);

  return CURLE_OK;
}

CURLcode Curl_cyassl_random(struct Curl_easy *data, unsigned char *entropy, size_t length)

{
  RNG rng;
  (void)data;
  if(InitRng(&rng))
    return CURLE_FAILED_INIT;
  if(length > UINT_MAX)
    return CURLE_FAILED_INIT;
  if(RNG_GenerateBlock(&rng, entropy, (unsigned)length))
    return CURLE_FAILED_INIT;
  return CURLE_OK;
}

void Curl_cyassl_sha256sum(const unsigned char *tmp,  size_t tmplen, unsigned char *sha256sum , size_t unused)


{
  Sha256 SHA256pw;
  (void)unused;
  InitSha256(&SHA256pw);
  Sha256Update(&SHA256pw, tmp, (word32)tmplen);
  Sha256Final(&SHA256pw, sha256sum);
}


