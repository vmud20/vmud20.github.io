


























int Curl_axtls_init(void)
{

  return 1;
}

int Curl_axtls_cleanup(void)
{
  
  return 1;
}

static CURLcode map_error_to_curl(int axtls_err)
{
  switch(axtls_err) {
  case SSL_ERROR_NOT_SUPPORTED:
  case SSL_ERROR_INVALID_VERSION:
  case -70:                       
    return CURLE_UNSUPPORTED_PROTOCOL;
    break;
  case SSL_ERROR_NO_CIPHER:
    return CURLE_SSL_CIPHER;
    break;
  case SSL_ERROR_BAD_CERTIFICATE: 
  case SSL_ERROR_NO_CERT_DEFINED:
  case -42:                       
  case -43:                       
  case -44:                       
  case -45:                       
  case -46:                       
    return CURLE_SSL_CERTPROBLEM;
    break;
  case SSL_X509_ERROR(X509_NOT_OK):
  case SSL_X509_ERROR(X509_VFY_ERROR_NO_TRUSTED_CERT):
  case SSL_X509_ERROR(X509_VFY_ERROR_BAD_SIGNATURE):
  case SSL_X509_ERROR(X509_VFY_ERROR_NOT_YET_VALID):
  case SSL_X509_ERROR(X509_VFY_ERROR_EXPIRED):
  case SSL_X509_ERROR(X509_VFY_ERROR_SELF_SIGNED):
  case SSL_X509_ERROR(X509_VFY_ERROR_INVALID_CHAIN):
  case SSL_X509_ERROR(X509_VFY_ERROR_UNSUPPORTED_DIGEST):
  case SSL_X509_ERROR(X509_INVALID_PRIV_KEY):
    return CURLE_PEER_FAILED_VERIFICATION;
    break;
  case -48:                       
    return CURLE_SSL_CACERT;
    break;
  case -49:                       
    return CURLE_REMOTE_ACCESS_DENIED;
    break;
  case SSL_ERROR_CONN_LOST:
  case SSL_ERROR_SOCK_SETUP_FAILURE:
  case SSL_ERROR_INVALID_HANDSHAKE:
  case SSL_ERROR_INVALID_PROT_MSG:
  case SSL_ERROR_INVALID_HMAC:
  case SSL_ERROR_INVALID_SESSION:
  case SSL_ERROR_INVALID_KEY:     
  case SSL_ERROR_FINISHED_INVALID:
  case SSL_ERROR_NO_CLIENT_RENOG:
  default:
    return CURLE_SSL_CONNECT_ERROR;
    break;
  }
}

static Curl_recv axtls_recv;
static Curl_send axtls_send;

static void free_ssl_structs(struct ssl_connect_data *connssl)
{
  if(connssl->ssl) {
    ssl_free(connssl->ssl);
    connssl->ssl = NULL;
  }
  if(connssl->ssl_ctx) {
    ssl_ctx_free(connssl->ssl_ctx);
    connssl->ssl_ctx = NULL;
  }
}


static CURLcode connect_prep(struct connectdata *conn, int sockindex)
{
  struct Curl_easy *data = conn->data;
  SSL_CTX *ssl_ctx;
  SSL *ssl = NULL;
  int cert_types[] = {SSL_OBJ_X509_CERT, SSL_OBJ_PKCS12, 0};
  int key_types[] = {SSL_OBJ_RSA_KEY, SSL_OBJ_PKCS8, SSL_OBJ_PKCS12, 0};
  int i, ssl_fcn_return;

  
  uint32_t client_option = SSL_NO_DEFAULT_KEY | SSL_SERVER_VERIFY_LATER | SSL_CONNECT_IN_PARTS;


  if(conn->ssl[sockindex].state == ssl_connection_complete)
    
    return CURLE_OK;

  if(SSL_CONN_CONFIG(version_max) != CURL_SSLVERSION_MAX_NONE) {
    failf(data, "axtls does not support CURL_SSLVERSION_MAX");
    return CURLE_SSL_CONNECT_ERROR;
  }


  
  
  switch(SSL_CONN_CONFIG(version)) {
  case CURL_SSLVERSION_DEFAULT:
  case CURL_SSLVERSION_TLSv1:
    break;
  default:
    failf(data, "axTLS only supports TLS 1.0 and 1.1, " "and it cannot be specified which one to use");
    return CURLE_SSL_CONNECT_ERROR;
  }


  client_option |= SSL_DISPLAY_STATES | SSL_DISPLAY_RSA | SSL_DISPLAY_CERTS;


  
  ssl_ctx = ssl_ctx_new(client_option, SSL_DEFAULT_CLNT_SESS);
  if(ssl_ctx == NULL) {
    failf(data, "unable to create client SSL context");
    return CURLE_SSL_CONNECT_ERROR;
  }

  conn->ssl[sockindex].ssl_ctx = ssl_ctx;
  conn->ssl[sockindex].ssl = NULL;

  
  if(SSL_CONN_CONFIG(CAfile)) {
    if(ssl_obj_load(ssl_ctx, SSL_OBJ_X509_CACERT, SSL_CONN_CONFIG(CAfile), NULL) != SSL_OK) {
      infof(data, "error reading ca cert file %s \n", SSL_CONN_CONFIG(CAfile));
      if(SSL_CONN_CONFIG(verifypeer)) {
        return CURLE_SSL_CACERT_BADFILE;
      }
    }
    else infof(data, "found certificates in %s\n", SSL_CONN_CONFIG(CAfile));
  }

  

  
  if(SSL_SET_OPTION(cert)) {
    i=0;
    
    while(cert_types[i] != 0) {
      ssl_fcn_return = ssl_obj_load(ssl_ctx, cert_types[i], SSL_SET_OPTION(cert), NULL);
      if(ssl_fcn_return == SSL_OK) {
        infof(data, "successfully read cert file %s \n", SSL_SET_OPTION(cert));
        break;
      }
      i++;
    }
    
    if(cert_types[i] == 0) {
      failf(data, "%s is not x509 or pkcs12 format", SSL_SET_OPTION(cert));
      return CURLE_SSL_CERTPROBLEM;
    }
  }

  
  if(SSL_SET_OPTION(key) && cert_types[i] != SSL_OBJ_PKCS12) {
    i=0;
    
    while(key_types[i] != 0) {
      ssl_fcn_return = ssl_obj_load(ssl_ctx, key_types[i], SSL_SET_OPTION(key), NULL);
      if(ssl_fcn_return == SSL_OK) {
        infof(data, "successfully read key file %s \n", SSL_SET_OPTION(key));
        break;
      }
      i++;
    }
    
    if(key_types[i] == 0) {
      failf(data, "Failure: %s is not a supported key file", SSL_SET_OPTION(key));
      return CURLE_SSL_CONNECT_ERROR;
    }
  }

  

  if(data->set.general_ssl.sessionid) {
    const uint8_t *ssl_sessionid;
    size_t ssl_idsize;

    
    Curl_ssl_sessionid_lock(conn);
    if(!Curl_ssl_getsessionid(conn, (void **) &ssl_sessionid, &ssl_idsize, sockindex)) {
      
      infof(data, "SSL re-using session ID\n");
      ssl = ssl_client_new(ssl_ctx, conn->sock[sockindex], ssl_sessionid, (uint8_t)ssl_idsize, NULL);
    }
    Curl_ssl_sessionid_unlock(conn);
  }

  if(!ssl)
    ssl = ssl_client_new(ssl_ctx, conn->sock[sockindex], NULL, 0, NULL);

  conn->ssl[sockindex].ssl = ssl;
  return CURLE_OK;
}


static CURLcode connect_finish(struct connectdata *conn, int sockindex)
{
  struct Curl_easy *data = conn->data;
  SSL *ssl = conn->ssl[sockindex].ssl;
  const char *peer_CN;
  uint32_t dns_altname_index;
  const char *dns_altname;
  int8_t found_subject_alt_names = 0;
  int8_t found_subject_alt_name_matching_conn = 0;
  const char * const hostname = SSL_IS_PROXY() ? conn->http_proxy.host.name :
    conn->host.name;
  const char * const dispname = SSL_IS_PROXY() ? conn->http_proxy.host.dispname : conn->host.dispname;

  

  
  if(SSL_CONN_CONFIG(verifypeer)) {
    if(ssl_verify_cert(ssl) != SSL_OK) {
      Curl_axtls_close(conn, sockindex);
      failf(data, "server cert verify failed");
      return CURLE_PEER_FAILED_VERIFICATION;
    }
  }
  else infof(data, "\t server certificate verification SKIPPED\n");

  

  

  
  for(dns_altname_index = 0; ; dns_altname_index++) {
    dns_altname = ssl_get_cert_subject_alt_dnsname(ssl, dns_altname_index);
    if(dns_altname == NULL) {
      break;
    }
    found_subject_alt_names = 1;

    infof(data, "\tComparing subject alt name DNS with hostname: %s <-> %s\n", dns_altname, hostname);
    if(Curl_cert_hostcheck(dns_altname, hostname)) {
      found_subject_alt_name_matching_conn = 1;
      break;
    }
  }

  
  if(found_subject_alt_names && !found_subject_alt_name_matching_conn) {
    if(SSL_CONN_CONFIG(verifyhost)) {
      
      Curl_axtls_close(conn, sockindex);
      failf(data, "\tsubjectAltName(s) do not match %s\n", dispname);
      return CURLE_PEER_FAILED_VERIFICATION;
    }
    else infof(data, "\tsubjectAltName(s) do not match %s\n", dispname);
  }
  else if(found_subject_alt_names == 0) {
    
    peer_CN = ssl_get_cert_dn(ssl, SSL_X509_CERT_COMMON_NAME);
    if(peer_CN == NULL) {
      if(SSL_CONN_CONFIG(verifyhost)) {
        Curl_axtls_close(conn, sockindex);
        failf(data, "unable to obtain common name from peer certificate");
        return CURLE_PEER_FAILED_VERIFICATION;
      }
      else infof(data, "unable to obtain common name from peer certificate");
    }
    else {
      if(!Curl_cert_hostcheck((const char *)peer_CN, hostname)) {
        if(SSL_CONN_CONFIG(verifyhost)) {
          
          Curl_axtls_close(conn, sockindex);
          failf(data, "\tcommon name \"%s\" does not match \"%s\"\n", peer_CN, dispname);
          return CURLE_PEER_FAILED_VERIFICATION;
        }
        else infof(data, "\tcommon name \"%s\" does not match \"%s\"\n", peer_CN, dispname);

      }
    }
  }

  
  conn->ssl[sockindex].state = ssl_connection_complete;
  conn->recv[sockindex] = axtls_recv;
  conn->send[sockindex] = axtls_send;

  
  if(data->set.general_ssl.sessionid) {
    const uint8_t *ssl_sessionid = ssl_get_session_id(ssl);
    size_t ssl_idsize = ssl_get_session_id_size(ssl);
    Curl_ssl_sessionid_lock(conn);
    if(Curl_ssl_addsessionid(conn, (void *) ssl_sessionid, ssl_idsize, sockindex) != CURLE_OK)
      infof(data, "failed to add session to cache\n");
    Curl_ssl_sessionid_unlock(conn);
  }

  return CURLE_OK;
}


CURLcode Curl_axtls_connect_nonblocking( struct connectdata *conn, int sockindex, bool *done)


{
  CURLcode conn_step;
  int ssl_fcn_return;
  int i;

 *done = FALSE;
  
  if(conn->ssl[sockindex].connecting_state == ssl_connect_1) {
    conn_step = connect_prep(conn, sockindex);
    if(conn_step != CURLE_OK) {
      Curl_axtls_close(conn, sockindex);
      return conn_step;
    }
    conn->ssl[sockindex].connecting_state = ssl_connect_2;
  }

  if(conn->ssl[sockindex].connecting_state == ssl_connect_2) {
    
    if(ssl_handshake_status(conn->ssl[sockindex].ssl) != SSL_OK) {
      
      for(i=0; i<5; i++) {
        ssl_fcn_return = ssl_read(conn->ssl[sockindex].ssl, NULL);
        if(ssl_fcn_return < 0) {
          Curl_axtls_close(conn, sockindex);
          ssl_display_error(ssl_fcn_return); 
          return map_error_to_curl(ssl_fcn_return);
        }
        return CURLE_OK;
      }
    }
    infof(conn->data, "handshake completed successfully\n");
    conn->ssl[sockindex].connecting_state = ssl_connect_3;
  }

  if(conn->ssl[sockindex].connecting_state == ssl_connect_3) {
    conn_step = connect_finish(conn, sockindex);
    if(conn_step != CURLE_OK) {
      Curl_axtls_close(conn, sockindex);
      return conn_step;
    }

    
    conn->ssl[sockindex].connecting_state = ssl_connect_1;

    *done = TRUE;
    return CURLE_OK;
  }

  
  conn->ssl[sockindex].state  = ssl_connection_none;
  conn->ssl[sockindex].connecting_state = ssl_connect_1;
  
  return CURLE_BAD_FUNCTION_ARGUMENT;
}



CURLcode Curl_axtls_connect(struct connectdata *conn, int sockindex)


{
  struct Curl_easy *data = conn->data;
  CURLcode conn_step = connect_prep(conn, sockindex);
  int ssl_fcn_return;
  SSL *ssl = conn->ssl[sockindex].ssl;
  long timeout_ms;

  if(conn_step != CURLE_OK) {
    Curl_axtls_close(conn, sockindex);
    return conn_step;
  }

  
  while(ssl_handshake_status(ssl) != SSL_OK) {
    
    timeout_ms = Curl_timeleft(data, NULL, TRUE);

    if(timeout_ms < 0) {
      
      failf(data, "SSL connection timeout");
      return CURLE_OPERATION_TIMEDOUT;
    }

    ssl_fcn_return = ssl_read(ssl, NULL);
    if(ssl_fcn_return < 0) {
      Curl_axtls_close(conn, sockindex);
      ssl_display_error(ssl_fcn_return); 
      return map_error_to_curl(ssl_fcn_return);
    }
    
    Curl_wait_ms(10);
  }
  infof(conn->data, "handshake completed successfully\n");

  conn_step = connect_finish(conn, sockindex);
  if(conn_step != CURLE_OK) {
    Curl_axtls_close(conn, sockindex);
    return conn_step;
  }

  return CURLE_OK;
}


static ssize_t axtls_send(struct connectdata *conn, int sockindex, const void *mem, size_t len, CURLcode *err)



{
  
  int rc = ssl_write(conn->ssl[sockindex].ssl, mem, (int)len);

  infof(conn->data, "  axtls_send\n");

  if(rc < 0) {
    *err = map_error_to_curl(rc);
    rc = -1; 
  }

  *err = CURLE_OK;
  return rc;
}

void Curl_axtls_close(struct connectdata *conn, int sockindex)
{
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];

  infof(conn->data, "  Curl_axtls_close\n");

    

    

  free_ssl_structs(connssl);
}


int Curl_axtls_shutdown(struct connectdata *conn, int sockindex)
{
  
  int retval = 0;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  struct Curl_easy *data = conn->data;
  uint8_t *buf;
  ssize_t nread;

  infof(conn->data, "  Curl_axtls_shutdown\n");

  

  

  if(connssl->ssl) {
    int what = SOCKET_READABLE(conn->sock[sockindex], SSL_SHUTDOWN_TIMEOUT);
    if(what > 0) {
      
      nread = (ssize_t)ssl_read(connssl->ssl, &buf);

      if(nread < SSL_OK) {
        failf(data, "close notify alert not received during shutdown");
        retval = -1;
      }
    }
    else if(0 == what) {
      
      failf(data, "SSL shutdown timeout");
    }
    else {
      
      failf(data, "select/poll on SSL socket, errno: %d", SOCKERRNO);
      retval = -1;
    }

    free_ssl_structs(connssl);
  }
  return retval;
}

static ssize_t axtls_recv(struct connectdata *conn,  int num, char *buf, size_t buffersize, CURLcode *err)



{
  struct ssl_connect_data *connssl = &conn->ssl[num];
  ssize_t ret = 0;
  uint8_t *read_buf;

  infof(conn->data, "  axtls_recv\n");

  *err = CURLE_OK;
  if(connssl) {
    ret = ssl_read(connssl->ssl, &read_buf);
    if(ret > SSL_OK) {
      
      memcpy(buf, read_buf, (size_t)ret > buffersize ? buffersize : (size_t)ret);
    }
    else if(ret == SSL_OK) {
      
      *err = CURLE_AGAIN;
      ret = -1;
    }
    else if(ret == -3) {
      
      Curl_axtls_close(conn, num);
    }
    else {
      failf(conn->data, "axTLS recv error (%d)", ret);
      *err = map_error_to_curl((int) ret);
      ret = -1;
    }
  }

  return ret;
}


int Curl_axtls_check_cxn(struct connectdata *conn)
{
  

  infof(conn->data, "  Curl_axtls_check_cxn\n");
   return 1; 
}

void Curl_axtls_session_free(void *ptr)
{
  (void)ptr;
  
  
}

size_t Curl_axtls_version(char *buffer, size_t size)
{
  return snprintf(buffer, size, "axTLS/%s", ssl_version());
}

CURLcode Curl_axtls_random(struct Curl_easy *data, unsigned char *entropy, size_t length)

{
  static bool ssl_seeded = FALSE;
  (void)data;
  if(!ssl_seeded) {
    ssl_seeded = TRUE;
    
    RNG_initialize();
  }
  get_random((int)length, entropy);
  return CURLE_OK;
}


