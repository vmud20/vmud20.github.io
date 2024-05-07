















































static void tls_log_func(int level, const char *str)
{
    fprintf(stderr, "|<%d>| %s", level, str);
}

static bool gtls_inited = FALSE;


































static int gtls_mapped_sockerrno(void)
{
  switch(SOCKERRNO) {
  case WSAEWOULDBLOCK:
    return gtls_EAGAIN;
  case WSAEINTR:
    return gtls_EINTR;
  default:
    break;
  }
  return gtls_EIO;
}


static ssize_t Curl_gtls_push(void *s, const void *buf, size_t len)
{
  ssize_t ret = swrite(GNUTLS_POINTER_TO_INT_CAST(s), buf, len);

  if(ret < 0)
    gnutls_transport_set_global_errno(gtls_mapped_sockerrno());

  return ret;
}

static ssize_t Curl_gtls_pull(void *s, void *buf, size_t len)
{
  ssize_t ret = sread(GNUTLS_POINTER_TO_INT_CAST(s), buf, len);

  if(ret < 0)
    gnutls_transport_set_global_errno(gtls_mapped_sockerrno());

  return ret;
}

static ssize_t Curl_gtls_push_ssl(void *s, const void *buf, size_t len)
{
  return gnutls_record_send((gnutls_session_t) s, buf, len);
}

static ssize_t Curl_gtls_pull_ssl(void *s, void *buf, size_t len)
{
  return gnutls_record_recv((gnutls_session_t) s, buf, len);
}


int Curl_gtls_init(void)
{
  int ret = 1;
  if(!gtls_inited) {
    ret = gnutls_global_init()?0:1;

    gnutls_global_set_log_function(tls_log_func);
    gnutls_global_set_log_level(2);

    gtls_inited = TRUE;
  }
  return ret;
}

int Curl_gtls_cleanup(void)
{
  if(gtls_inited) {
    gnutls_global_deinit();
    gtls_inited = FALSE;
  }
  return 1;
}

static void showtime(struct Curl_easy *data, const char *text, time_t stamp)

{
  struct tm buffer;
  const struct tm *tm = &buffer;
  CURLcode result = Curl_gmtime(stamp, &buffer);
  if(result)
    return;

  snprintf(data->state.buffer, BUFSIZE, "\t %s: %s, %02d %s %4d %02d:%02d:%02d GMT", text, Curl_wkday[tm->tm_wday?tm->tm_wday-1:6], tm->tm_mday, Curl_month[tm->tm_mon], tm->tm_year + 1900, tm->tm_hour, tm->tm_min, tm->tm_sec);









  infof(data, "%s\n", data->state.buffer);
}

static gnutls_datum_t load_file(const char *file)
{
  FILE *f;
  gnutls_datum_t loaded_file = { NULL, 0 };
  long filelen;
  void *ptr;

  f = fopen(file, "rb");
  if(!f)
    return loaded_file;
  if(fseek(f, 0, SEEK_END) != 0 || (filelen = ftell(f)) < 0 || fseek(f, 0, SEEK_SET) != 0 || !(ptr = malloc((size_t)filelen)))


    goto out;
  if(fread(ptr, 1, (size_t)filelen, f) < (size_t)filelen) {
    free(ptr);
    goto out;
  }

  loaded_file.data = ptr;
  loaded_file.size = (unsigned int)filelen;
out:
  fclose(f);
  return loaded_file;
}

static void unload_file(gnutls_datum_t data)
{
  free(data.data);
}



static CURLcode handshake(struct connectdata *conn, int sockindex, bool duringconnect, bool nonblocking)


{
  struct Curl_easy *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  gnutls_session_t session = conn->ssl[sockindex].session;
  curl_socket_t sockfd = conn->sock[sockindex];
  time_t timeout_ms;
  int rc;
  int what;

  for(;;) {
    
    timeout_ms = Curl_timeleft(data, NULL, duringconnect);

    if(timeout_ms < 0) {
      
      failf(data, "SSL connection timeout");
      return CURLE_OPERATION_TIMEDOUT;
    }

    
    if(connssl->connecting_state == ssl_connect_2_reading || connssl->connecting_state == ssl_connect_2_writing) {

      curl_socket_t writefd = ssl_connect_2_writing== connssl->connecting_state?sockfd:CURL_SOCKET_BAD;
      curl_socket_t readfd = ssl_connect_2_reading== connssl->connecting_state?sockfd:CURL_SOCKET_BAD;

      what = Curl_socket_check(readfd, CURL_SOCKET_BAD, writefd, nonblocking?0:
                               timeout_ms?timeout_ms:1000);
      if(what < 0) {
        
        failf(data, "select/poll on SSL socket, errno: %d", SOCKERRNO);
        return CURLE_SSL_CONNECT_ERROR;
      }
      else if(0 == what) {
        if(nonblocking)
          return CURLE_OK;
        else if(timeout_ms) {
          
          failf(data, "SSL connection timeout at %ld", (long)timeout_ms);
          return CURLE_OPERATION_TIMEDOUT;
        }
      }
      
    }

    rc = gnutls_handshake(session);

    if((rc == GNUTLS_E_AGAIN) || (rc == GNUTLS_E_INTERRUPTED)) {
      connssl->connecting_state = gnutls_record_get_direction(session)? ssl_connect_2_writing:ssl_connect_2_reading;

      continue;
    }
    else if((rc < 0) && !gnutls_error_is_fatal(rc)) {
      const char *strerr = NULL;

      if(rc == GNUTLS_E_WARNING_ALERT_RECEIVED) {
        int alert = gnutls_alert_get(session);
        strerr = gnutls_alert_get_name(alert);
      }

      if(strerr == NULL)
        strerr = gnutls_strerror(rc);

      infof(data, "gnutls_handshake() warning: %s\n", strerr);
      continue;
    }
    else if(rc < 0) {
      const char *strerr = NULL;

      if(rc == GNUTLS_E_FATAL_ALERT_RECEIVED) {
        int alert = gnutls_alert_get(session);
        strerr = gnutls_alert_get_name(alert);
      }

      if(strerr == NULL)
        strerr = gnutls_strerror(rc);

      failf(data, "gnutls_handshake() failed: %s", strerr);
      return CURLE_SSL_CONNECT_ERROR;
    }

    
    connssl->connecting_state = ssl_connect_1;
    return CURLE_OK;
  }
}

static gnutls_x509_crt_fmt_t do_file_type(const char *type)
{
  if(!type || !type[0])
    return GNUTLS_X509_FMT_PEM;
  if(strcasecompare(type, "PEM"))
    return GNUTLS_X509_FMT_PEM;
  if(strcasecompare(type, "DER"))
    return GNUTLS_X509_FMT_DER;
  return -1;
}


static CURLcode set_ssl_version_min_max(int *list, size_t list_size, struct connectdata *conn)
{
  struct Curl_easy *data = conn->data;
  long ssl_version = SSL_CONN_CONFIG(version);
  long ssl_version_max = SSL_CONN_CONFIG(version_max);
  long i = ssl_version;
  long protocol_priority_idx = 0;

  switch(ssl_version_max) {
    case CURL_SSLVERSION_MAX_NONE:
      ssl_version_max = ssl_version << 16;
      break;
    case CURL_SSLVERSION_MAX_DEFAULT:
      ssl_version_max = CURL_SSLVERSION_MAX_TLSv1_2;
      break;
  }

  for(; i <= (ssl_version_max >> 16) && protocol_priority_idx < list_size; ++i) {
    switch(i) {
      case CURL_SSLVERSION_TLSv1_0:
        protocol_priority[protocol_priority_idx++] = GNUTLS_TLS1_0;
        break;
      case CURL_SSLVERSION_TLSv1_1:
        protocol_priority[protocol_priority_idx++] = GNUTLS_TLS1_1;
        break;
      case CURL_SSLVERSION_TLSv1_2:
        protocol_priority[protocol_priority_idx++] = GNUTLS_TLS1_2;
        break;
      case CURL_SSLVERSION_TLSv1_3:
        failf(data, "GnuTLS: TLS 1.3 is not yet supported");
        return CURLE_SSL_CONNECT_ERROR;
    }
  }
  return CURLE_OK;
}





static CURLcode set_ssl_version_min_max(const char **prioritylist, struct connectdata *conn)
{
  struct Curl_easy *data = conn->data;
  long ssl_version = SSL_CONN_CONFIG(version);
  long ssl_version_max = SSL_CONN_CONFIG(version_max);
  if(ssl_version == CURL_SSLVERSION_TLSv1_3 || ssl_version_max == CURL_SSLVERSION_MAX_TLSv1_3) {
    failf(data, "GnuTLS: TLS 1.3 is not yet supported");
    return CURLE_SSL_CONNECT_ERROR;
  }
  if(ssl_version_max == CURL_SSLVERSION_MAX_NONE) {
    ssl_version_max = ssl_version << 16;
  }
  switch(ssl_version | ssl_version_max) {
    case CURL_SSLVERSION_TLSv1_0 | CURL_SSLVERSION_MAX_TLSv1_0:
      *prioritylist = GNUTLS_CIPHERS ":-VERS-SSL3.0:-VERS-TLS-ALL:" "+VERS-TLS1.0:" GNUTLS_SRP;
      return CURLE_OK;
    case CURL_SSLVERSION_TLSv1_0 | CURL_SSLVERSION_MAX_TLSv1_1:
      *prioritylist = GNUTLS_CIPHERS ":-VERS-SSL3.0:-VERS-TLS-ALL:" "+VERS-TLS1.0:+VERS-TLS1.1:" GNUTLS_SRP;
      return CURLE_OK;
    case CURL_SSLVERSION_TLSv1_0 | CURL_SSLVERSION_MAX_TLSv1_2:
    case CURL_SSLVERSION_TLSv1_0 | CURL_SSLVERSION_MAX_DEFAULT:
      *prioritylist = GNUTLS_CIPHERS ":-VERS-SSL3.0:-VERS-TLS-ALL:" "+VERS-TLS1.0:+VERS-TLS1.1:+VERS-TLS1.2:" GNUTLS_SRP;
      return CURLE_OK;
    case CURL_SSLVERSION_TLSv1_1 | CURL_SSLVERSION_MAX_TLSv1_1:
      *prioritylist = GNUTLS_CIPHERS ":-VERS-SSL3.0:-VERS-TLS-ALL:" "+VERS-TLS1.1:" GNUTLS_SRP;
      return CURLE_OK;
    case CURL_SSLVERSION_TLSv1_1 | CURL_SSLVERSION_MAX_TLSv1_2:
    case CURL_SSLVERSION_TLSv1_1 | CURL_SSLVERSION_MAX_DEFAULT:
      *prioritylist = GNUTLS_CIPHERS ":-VERS-SSL3.0:-VERS-TLS-ALL:" "+VERS-TLS1.1:+VERS-TLS1.2:" GNUTLS_SRP;
      return CURLE_OK;
    case CURL_SSLVERSION_TLSv1_2 | CURL_SSLVERSION_MAX_TLSv1_2:
    case CURL_SSLVERSION_TLSv1_2 | CURL_SSLVERSION_MAX_DEFAULT:
      *prioritylist = GNUTLS_CIPHERS ":-VERS-SSL3.0:-VERS-TLS-ALL:" "+VERS-TLS1.2:" GNUTLS_SRP;
      return CURLE_OK;
  }

  failf(data, "GnuTLS: cannot set ssl protocol");
  return CURLE_SSL_CONNECT_ERROR;
}


static CURLcode gtls_connect_step1(struct connectdata *conn, int sockindex)

{
  struct Curl_easy *data = conn->data;
  unsigned int init_flags;
  gnutls_session_t session;
  int rc;
  bool sni = TRUE; 
  void *transport_ptr = NULL;
  gnutls_push_func gnutls_transport_push = NULL;
  gnutls_pull_func gnutls_transport_pull = NULL;

  struct in6_addr addr;

  struct in_addr addr;


  static const int cipher_priority[] = {
  
    GNUTLS_CIPHER_AES_128_CBC, GNUTLS_CIPHER_AES_256_CBC, GNUTLS_CIPHER_CAMELLIA_128_CBC, GNUTLS_CIPHER_CAMELLIA_256_CBC, GNUTLS_CIPHER_3DES_CBC, };




  static const int cert_type_priority[] = { GNUTLS_CRT_X509, 0 };
  int protocol_priority[] = { 0, 0, 0, 0 };

  const char *prioritylist;
  const char *err = NULL;


  const char * const hostname = SSL_IS_PROXY() ? conn->http_proxy.host.name :
    conn->host.name;

  if(conn->ssl[sockindex].state == ssl_connection_complete)
    
    return CURLE_OK;

  if(!gtls_inited)
    Curl_gtls_init();

  if(SSL_CONN_CONFIG(version) == CURL_SSLVERSION_SSLv2) {
    failf(data, "GnuTLS does not support SSLv2");
    return CURLE_SSL_CONNECT_ERROR;
  }
  else if(SSL_CONN_CONFIG(version) == CURL_SSLVERSION_SSLv3)
    sni = FALSE; 

  
  rc = gnutls_certificate_allocate_credentials(&conn->ssl[sockindex].cred);
  if(rc != GNUTLS_E_SUCCESS) {
    failf(data, "gnutls_cert_all_cred() failed: %s", gnutls_strerror(rc));
    return CURLE_SSL_CONNECT_ERROR;
  }


  if(SSL_SET_OPTION(authtype) == CURL_TLSAUTH_SRP) {
    infof(data, "Using TLS-SRP username: %s\n", SSL_SET_OPTION(username));

    rc = gnutls_srp_allocate_client_credentials( &conn->ssl[sockindex].srp_client_cred);
    if(rc != GNUTLS_E_SUCCESS) {
      failf(data, "gnutls_srp_allocate_client_cred() failed: %s", gnutls_strerror(rc));
      return CURLE_OUT_OF_MEMORY;
    }

    rc = gnutls_srp_set_client_credentials(conn->ssl[sockindex]. srp_client_cred, SSL_SET_OPTION(username), SSL_SET_OPTION(password));


    if(rc != GNUTLS_E_SUCCESS) {
      failf(data, "gnutls_srp_set_client_cred() failed: %s", gnutls_strerror(rc));
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }
  }


  if(SSL_CONN_CONFIG(CAfile)) {
    
    gnutls_certificate_set_verify_flags(conn->ssl[sockindex].cred, GNUTLS_VERIFY_ALLOW_X509_V1_CA_CRT);

    rc = gnutls_certificate_set_x509_trust_file(conn->ssl[sockindex].cred, SSL_CONN_CONFIG(CAfile), GNUTLS_X509_FMT_PEM);

    if(rc < 0) {
      infof(data, "error reading ca cert file %s (%s)\n", SSL_CONN_CONFIG(CAfile), gnutls_strerror(rc));
      if(SSL_CONN_CONFIG(verifypeer))
        return CURLE_SSL_CACERT_BADFILE;
    }
    else infof(data, "found %d certificates in %s\n", rc, SSL_CONN_CONFIG(CAfile));

  }


  if(SSL_CONN_CONFIG(CApath)) {
    
    rc = gnutls_certificate_set_x509_trust_dir(conn->ssl[sockindex].cred, SSL_CONN_CONFIG(CApath), GNUTLS_X509_FMT_PEM);

    if(rc < 0) {
      infof(data, "error reading ca cert file %s (%s)\n", SSL_CONN_CONFIG(CApath), gnutls_strerror(rc));
      if(SSL_CONN_CONFIG(verifypeer))
        return CURLE_SSL_CACERT_BADFILE;
    }
    else infof(data, "found %d certificates in %s\n", rc, SSL_CONN_CONFIG(CApath));

  }



  
  if(SSL_CONN_CONFIG(verifypeer) && !(SSL_CONN_CONFIG(CAfile) || SSL_CONN_CONFIG(CApath))) {
    gnutls_certificate_set_x509_system_trust(conn->ssl[sockindex].cred);
  }


  if(SSL_SET_OPTION(CRLfile)) {
    
    rc = gnutls_certificate_set_x509_crl_file(conn->ssl[sockindex].cred, SSL_SET_OPTION(CRLfile), GNUTLS_X509_FMT_PEM);

    if(rc < 0) {
      failf(data, "error reading crl file %s (%s)", SSL_SET_OPTION(CRLfile), gnutls_strerror(rc));
      return CURLE_SSL_CRL_BADFILE;
    }
    else infof(data, "found %d CRL in %s\n", rc, SSL_SET_OPTION(CRLfile));

  }

  
  init_flags = GNUTLS_CLIENT;


  
  init_flags |= GNUTLS_NO_TICKETS;


  rc = gnutls_init(&conn->ssl[sockindex].session, init_flags);
  if(rc != GNUTLS_E_SUCCESS) {
    failf(data, "gnutls_init() failed: %d", rc);
    return CURLE_SSL_CONNECT_ERROR;
  }

  
  session = conn->ssl[sockindex].session;

  if((0 == Curl_inet_pton(AF_INET, hostname, &addr)) &&  (0 == Curl_inet_pton(AF_INET6, hostname, &addr)) &&  sni && (gnutls_server_name_set(session, GNUTLS_NAME_DNS, hostname, strlen(hostname)) < 0))





    infof(data, "WARNING: failed to configure server name indication (SNI) " "TLS extension\n");

  
  rc = gnutls_set_default_priority(session);
  if(rc != GNUTLS_E_SUCCESS)
    return CURLE_SSL_CONNECT_ERROR;


  rc = gnutls_cipher_set_priority(session, cipher_priority);
  if(rc != GNUTLS_E_SUCCESS)
    return CURLE_SSL_CONNECT_ERROR;

  
  rc = gnutls_certificate_type_set_priority(session, cert_type_priority);
  if(rc != GNUTLS_E_SUCCESS)
    return CURLE_SSL_CONNECT_ERROR;

  if(SSL_CONN_CONFIG(cipher_list) != NULL) {
    failf(data, "can't pass a custom cipher list to older GnuTLS" " versions");
    return CURLE_SSL_CONNECT_ERROR;
  }

  switch(SSL_CONN_CONFIG(version)) {
    case CURL_SSLVERSION_SSLv3:
      protocol_priority[0] = GNUTLS_SSL3;
      break;
    case CURL_SSLVERSION_DEFAULT:
    case CURL_SSLVERSION_TLSv1:
      protocol_priority[0] = GNUTLS_TLS1_0;
      protocol_priority[1] = GNUTLS_TLS1_1;
      protocol_priority[2] = GNUTLS_TLS1_2;
      break;
    case CURL_SSLVERSION_TLSv1_0:
    case CURL_SSLVERSION_TLSv1_1:
    case CURL_SSLVERSION_TLSv1_2:
    case CURL_SSLVERSION_TLSv1_3:
      {
        CURLcode result = set_ssl_version_min_max(protocol_priority, sizeof(protocol_priority)/sizeof(protocol_priority[0]), conn);
        if(result != CURLE_OK)
          return result;
        break;
      }
    case CURL_SSLVERSION_SSLv2:
      failf(data, "GnuTLS does not support SSLv2");
      return CURLE_SSL_CONNECT_ERROR;
    default:
      failf(data, "Unrecognized parameter passed via CURLOPT_SSLVERSION");
      return CURLE_SSL_CONNECT_ERROR;
  }
  rc = gnutls_protocol_set_priority(session, protocol_priority);
  if(rc != GNUTLS_E_SUCCESS) {
    failf(data, "Did you pass a valid GnuTLS cipher list?");
    return CURLE_SSL_CONNECT_ERROR;
  }


  
  switch(SSL_CONN_CONFIG(version)) {
    case CURL_SSLVERSION_SSLv3:
      prioritylist = GNUTLS_CIPHERS ":-VERS-TLS-ALL:+VERS-SSL3.0";
      sni = false;
      break;
    case CURL_SSLVERSION_DEFAULT:
    case CURL_SSLVERSION_TLSv1:
      prioritylist = GNUTLS_CIPHERS ":-VERS-SSL3.0:" GNUTLS_SRP;
      break;
    case CURL_SSLVERSION_TLSv1_0:
    case CURL_SSLVERSION_TLSv1_1:
    case CURL_SSLVERSION_TLSv1_2:
    case CURL_SSLVERSION_TLSv1_3:
      {
        CURLcode result = set_ssl_version_min_max(&prioritylist, conn);
        if(result != CURLE_OK)
          return result;
        break;
      }
    case CURL_SSLVERSION_SSLv2:
      failf(data, "GnuTLS does not support SSLv2");
      return CURLE_SSL_CONNECT_ERROR;
    default:
      failf(data, "Unrecognized parameter passed via CURLOPT_SSLVERSION");
      return CURLE_SSL_CONNECT_ERROR;
  }
  rc = gnutls_priority_set_direct(session, prioritylist, &err);
  if((rc == GNUTLS_E_INVALID_REQUEST) && err) {
    if(!strcmp(err, GNUTLS_SRP)) {
      
      int validprioritylen = curlx_uztosi(err - prioritylist);
      char *prioritycopy = strdup(prioritylist);
      if(!prioritycopy)
        return CURLE_OUT_OF_MEMORY;

      infof(data, "This GnuTLS does not support SRP\n");
      if(validprioritylen)
        
        prioritycopy[validprioritylen - 1] = 0;
      rc = gnutls_priority_set_direct(session, prioritycopy, &err);
      free(prioritycopy);
    }
  }
  if(rc != GNUTLS_E_SUCCESS) {
    failf(data, "Error %d setting GnuTLS cipher list starting with %s", rc, err);
    return CURLE_SSL_CONNECT_ERROR;
  }



  if(conn->bits.tls_enable_alpn) {
    int cur = 0;
    gnutls_datum_t protocols[2];


    if(data->set.httpversion >= CURL_HTTP_VERSION_2) {
      protocols[cur].data = (unsigned char *)NGHTTP2_PROTO_VERSION_ID;
      protocols[cur].size = NGHTTP2_PROTO_VERSION_ID_LEN;
      cur++;
      infof(data, "ALPN, offering %s\n", NGHTTP2_PROTO_VERSION_ID);
    }


    protocols[cur].data = (unsigned char *)ALPN_HTTP_1_1;
    protocols[cur].size = ALPN_HTTP_1_1_LENGTH;
    cur++;
    infof(data, "ALPN, offering %s\n", ALPN_HTTP_1_1);

    gnutls_alpn_set_protocols(session, protocols, cur, 0);
  }


  if(SSL_SET_OPTION(cert)) {
    if(SSL_SET_OPTION(key_passwd)) {

      const unsigned int supported_key_encryption_algorithms = GNUTLS_PKCS_USE_PKCS12_3DES | GNUTLS_PKCS_USE_PKCS12_ARCFOUR | GNUTLS_PKCS_USE_PKCS12_RC2_40 | GNUTLS_PKCS_USE_PBES2_3DES | GNUTLS_PKCS_USE_PBES2_AES_128 | GNUTLS_PKCS_USE_PBES2_AES_192 | GNUTLS_PKCS_USE_PBES2_AES_256;



      rc = gnutls_certificate_set_x509_key_file2( conn->ssl[sockindex].cred, SSL_SET_OPTION(cert), SSL_SET_OPTION(key) ? SSL_SET_OPTION(key) : SSL_SET_OPTION(cert), do_file_type(SSL_SET_OPTION(cert_type)), SSL_SET_OPTION(key_passwd), supported_key_encryption_algorithms);






      if(rc != GNUTLS_E_SUCCESS) {
        failf(data, "error reading X.509 potentially-encrypted key file: %s", gnutls_strerror(rc));

        return CURLE_SSL_CONNECT_ERROR;
      }

      failf(data, "gnutls lacks support for encrypted key files");
      return CURLE_SSL_CONNECT_ERROR;

    }
    else {
      if(gnutls_certificate_set_x509_key_file( conn->ssl[sockindex].cred, SSL_SET_OPTION(cert), SSL_SET_OPTION(key) ? SSL_SET_OPTION(key) : SSL_SET_OPTION(cert), do_file_type(SSL_SET_OPTION(cert_type)) ) != GNUTLS_E_SUCCESS) {





        failf(data, "error reading X.509 key or certificate file");
        return CURLE_SSL_CONNECT_ERROR;
      }
    }
  }


  
  if(SSL_SET_OPTION(authtype) == CURL_TLSAUTH_SRP) {
    rc = gnutls_credentials_set(session, GNUTLS_CRD_SRP, conn->ssl[sockindex].srp_client_cred);
    if(rc != GNUTLS_E_SUCCESS) {
      failf(data, "gnutls_credentials_set() failed: %s", gnutls_strerror(rc));
      return CURLE_SSL_CONNECT_ERROR;
    }
  }
  else  {

    rc = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, conn->ssl[sockindex].cred);
    if(rc != GNUTLS_E_SUCCESS) {
      failf(data, "gnutls_credentials_set() failed: %s", gnutls_strerror(rc));
      return CURLE_SSL_CONNECT_ERROR;
    }
  }

  if(conn->proxy_ssl[sockindex].use) {
    transport_ptr = conn->proxy_ssl[sockindex].session;
    gnutls_transport_push = Curl_gtls_push_ssl;
    gnutls_transport_pull = Curl_gtls_pull_ssl;
  }
  else {
    
    transport_ptr = GNUTLS_INT_TO_POINTER_CAST(conn->sock[sockindex]);
    gnutls_transport_push = Curl_gtls_push;
    gnutls_transport_pull = Curl_gtls_pull;
  }

  
  gnutls_transport_set_ptr(session, transport_ptr);

  
  gnutls_transport_set_push_function(session, gnutls_transport_push);
  gnutls_transport_set_pull_function(session, gnutls_transport_pull);

  
  gnutls_transport_set_lowat(session, 0);


  if(SSL_CONN_CONFIG(verifystatus)) {
    rc = gnutls_ocsp_status_request_enable_client(session, NULL, 0, NULL);
    if(rc != GNUTLS_E_SUCCESS) {
      failf(data, "gnutls_ocsp_status_request_enable_client() failed: %d", rc);
      return CURLE_SSL_CONNECT_ERROR;
    }
  }


  
  if(data->set.general_ssl.sessionid) {
    void *ssl_sessionid;
    size_t ssl_idsize;

    Curl_ssl_sessionid_lock(conn);
    if(!Curl_ssl_getsessionid(conn, &ssl_sessionid, &ssl_idsize, sockindex)) {
      
      gnutls_session_set_data(session, ssl_sessionid, ssl_idsize);

      
      infof(data, "SSL re-using session ID\n");
    }
    Curl_ssl_sessionid_unlock(conn);
  }

  return CURLE_OK;
}

static CURLcode pkp_pin_peer_pubkey(struct Curl_easy *data, gnutls_x509_crt_t cert, const char *pinnedpubkey)

{
  
  size_t len1 = 0, len2 = 0;
  unsigned char *buff1 = NULL;

  gnutls_pubkey_t key = NULL;

  
  int ret = 0;
  CURLcode result = CURLE_SSL_PINNEDPUBKEYNOTMATCH;

  
  if(NULL == pinnedpubkey)
    return CURLE_OK;

  if(NULL == cert)
    return result;

  do {
    
    gnutls_pubkey_init(&key);

    ret = gnutls_pubkey_import_x509(key, cert, 0);
    if(ret < 0)
      break; 

    ret = gnutls_pubkey_export(key, GNUTLS_X509_FMT_DER, NULL, &len1);
    if(ret != GNUTLS_E_SHORT_MEMORY_BUFFER || len1 == 0)
      break; 

    buff1 = malloc(len1);
    if(NULL == buff1)
      break; 

    len2 = len1;

    ret = gnutls_pubkey_export(key, GNUTLS_X509_FMT_DER, buff1, &len2);
    if(ret < 0 || len1 != len2)
      break; 

    

    
    result = Curl_pin_peer_pubkey(data, pinnedpubkey, buff1, len1);
  } while(0);

  if(NULL != key)
    gnutls_pubkey_deinit(key);

  Curl_safefree(buff1);

  return result;
}

static Curl_recv gtls_recv;
static Curl_send gtls_send;

static CURLcode gtls_connect_step3(struct connectdata *conn, int sockindex)

{
  unsigned int cert_list_size;
  const gnutls_datum_t *chainp;
  unsigned int verify_status = 0;
  gnutls_x509_crt_t x509_cert, x509_issuer;
  gnutls_datum_t issuerp;
  char certbuf[256] = ""; 
  size_t size;
  unsigned int algo;
  unsigned int bits;
  time_t certclock;
  const char *ptr;
  struct Curl_easy *data = conn->data;
  gnutls_session_t session = conn->ssl[sockindex].session;
  int rc;

  gnutls_datum_t proto;

  CURLcode result = CURLE_OK;

  gnutls_protocol_t version = gnutls_protocol_get_version(session);

  const char * const hostname = SSL_IS_PROXY() ? conn->http_proxy.host.name :
    conn->host.name;

  
  ptr = gnutls_cipher_suite_get_name(gnutls_kx_get(session), gnutls_cipher_get(session), gnutls_mac_get(session));


  infof(data, "SSL connection using %s / %s\n", gnutls_protocol_get_name(version), ptr);

  

  chainp = gnutls_certificate_get_peers(session, &cert_list_size);
  if(!chainp) {
    if(SSL_CONN_CONFIG(verifypeer) || SSL_CONN_CONFIG(verifyhost) || SSL_SET_OPTION(issuercert)) {


      if(SSL_SET_OPTION(authtype) == CURL_TLSAUTH_SRP && SSL_SET_OPTION(username) != NULL && !SSL_CONN_CONFIG(verifypeer)

         && gnutls_cipher_get(session)) {
        
      }
      else {

        failf(data, "failed to get server cert");
        return CURLE_PEER_FAILED_VERIFICATION;

      }

    }
    infof(data, "\t common name: WARNING couldn't obtain\n");
  }

  if(data->set.ssl.certinfo && chainp) {
    unsigned int i;

    result = Curl_ssl_init_certinfo(data, cert_list_size);
    if(result)
      return result;

    for(i = 0; i < cert_list_size; i++) {
      const char *beg = (const char *) chainp[i].data;
      const char *end = beg + chainp[i].size;

      result = Curl_extract_certinfo(conn, i, beg, end);
      if(result)
        return result;
    }
  }

  if(SSL_CONN_CONFIG(verifypeer)) {
    

    rc = gnutls_certificate_verify_peers2(session, &verify_status);
    if(rc < 0) {
      failf(data, "server cert verify failed: %d", rc);
      return CURLE_SSL_CONNECT_ERROR;
    }

    
    if(verify_status & GNUTLS_CERT_INVALID) {
      if(SSL_CONN_CONFIG(verifypeer)) {
        failf(data, "server certificate verification failed. CAfile: %s " "CRLfile: %s", SSL_CONN_CONFIG(CAfile) ? SSL_CONN_CONFIG(CAfile):
              "none", SSL_SET_OPTION(CRLfile)?SSL_SET_OPTION(CRLfile):"none");
        return CURLE_SSL_CACERT;
      }
      else infof(data, "\t server certificate verification FAILED\n");
    }
    else infof(data, "\t server certificate verification OK\n");
  }
  else infof(data, "\t server certificate verification SKIPPED\n");


  if(SSL_CONN_CONFIG(verifystatus)) {
    if(gnutls_ocsp_status_request_is_checked(session, 0) == 0) {
      gnutls_datum_t status_request;
      gnutls_ocsp_resp_t ocsp_resp;

      gnutls_ocsp_cert_status_t status;
      gnutls_x509_crl_reason_t reason;

      rc = gnutls_ocsp_status_request_get(session, &status_request);

      infof(data, "\t server certificate status verification FAILED\n");

      if(rc == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
        failf(data, "No OCSP response received");
        return CURLE_SSL_INVALIDCERTSTATUS;
      }

      if(rc < 0) {
        failf(data, "Invalid OCSP response received");
        return CURLE_SSL_INVALIDCERTSTATUS;
      }

      gnutls_ocsp_resp_init(&ocsp_resp);

      rc = gnutls_ocsp_resp_import(ocsp_resp, &status_request);
      if(rc < 0) {
        failf(data, "Invalid OCSP response received");
        return CURLE_SSL_INVALIDCERTSTATUS;
      }

      rc = gnutls_ocsp_resp_get_single(ocsp_resp, 0, NULL, NULL, NULL, NULL, &status, NULL, NULL, NULL, &reason);

      switch(status) {
      case GNUTLS_OCSP_CERT_GOOD:
        break;

      case GNUTLS_OCSP_CERT_REVOKED: {
        const char *crl_reason;

        switch(reason) {
          default:
          case GNUTLS_X509_CRLREASON_UNSPECIFIED:
            crl_reason = "unspecified reason";
            break;

          case GNUTLS_X509_CRLREASON_KEYCOMPROMISE:
            crl_reason = "private key compromised";
            break;

          case GNUTLS_X509_CRLREASON_CACOMPROMISE:
            crl_reason = "CA compromised";
            break;

          case GNUTLS_X509_CRLREASON_AFFILIATIONCHANGED:
            crl_reason = "affiliation has changed";
            break;

          case GNUTLS_X509_CRLREASON_SUPERSEDED:
            crl_reason = "certificate superseded";
            break;

          case GNUTLS_X509_CRLREASON_CESSATIONOFOPERATION:
            crl_reason = "operation has ceased";
            break;

          case GNUTLS_X509_CRLREASON_CERTIFICATEHOLD:
            crl_reason = "certificate is on hold";
            break;

          case GNUTLS_X509_CRLREASON_REMOVEFROMCRL:
            crl_reason = "will be removed from delta CRL";
            break;

          case GNUTLS_X509_CRLREASON_PRIVILEGEWITHDRAWN:
            crl_reason = "privilege withdrawn";
            break;

          case GNUTLS_X509_CRLREASON_AACOMPROMISE:
            crl_reason = "AA compromised";
            break;
        }

        failf(data, "Server certificate was revoked: %s", crl_reason);
        break;
      }

      default:
      case GNUTLS_OCSP_CERT_UNKNOWN:
        failf(data, "Server certificate status is unknown");
        break;
      }

      gnutls_ocsp_resp_deinit(ocsp_resp);

      return CURLE_SSL_INVALIDCERTSTATUS;
    }
    else infof(data, "\t server certificate status verification OK\n");
  }
  else infof(data, "\t server certificate status verification SKIPPED\n");


  
  gnutls_x509_crt_init(&x509_cert);

  if(chainp)
    
    gnutls_x509_crt_import(x509_cert, chainp, GNUTLS_X509_FMT_DER);

  if(SSL_SET_OPTION(issuercert)) {
    gnutls_x509_crt_init(&x509_issuer);
    issuerp = load_file(SSL_SET_OPTION(issuercert));
    gnutls_x509_crt_import(x509_issuer, &issuerp, GNUTLS_X509_FMT_PEM);
    rc = gnutls_x509_crt_check_issuer(x509_cert, x509_issuer);
    gnutls_x509_crt_deinit(x509_issuer);
    unload_file(issuerp);
    if(rc <= 0) {
      failf(data, "server certificate issuer check failed (IssuerCert: %s)", SSL_SET_OPTION(issuercert)?SSL_SET_OPTION(issuercert):"none");
      gnutls_x509_crt_deinit(x509_cert);
      return CURLE_SSL_ISSUER_ERROR;
    }
    infof(data, "\t server certificate issuer check OK (Issuer Cert: %s)\n", SSL_SET_OPTION(issuercert)?SSL_SET_OPTION(issuercert):"none");
  }

  size=sizeof(certbuf);
  rc = gnutls_x509_crt_get_dn_by_oid(x509_cert, GNUTLS_OID_X520_COMMON_NAME, 0, FALSE, certbuf, &size);



  if(rc) {
    infof(data, "error fetching CN from cert:%s\n", gnutls_strerror(rc));
  }

  
  rc = gnutls_x509_crt_check_hostname(x509_cert, hostname);

  
  if(!rc) {

    #define use_addr in6_addr

    #define use_addr in_addr

    unsigned char addrbuf[sizeof(struct use_addr)];
    unsigned char certaddr[sizeof(struct use_addr)];
    size_t addrlen = 0, certaddrlen;
    int i;
    int ret = 0;

    if(Curl_inet_pton(AF_INET, hostname, addrbuf) > 0)
      addrlen = 4;

    else if(Curl_inet_pton(AF_INET6, hostname, addrbuf) > 0)
      addrlen = 16;


    if(addrlen) {
      for(i=0; ; i++) {
        certaddrlen = sizeof(certaddr);
        ret = gnutls_x509_crt_get_subject_alt_name(x509_cert, i, certaddr, &certaddrlen, NULL);
        
        if(ret == GNUTLS_E_SHORT_MEMORY_BUFFER)
          continue;
        if(ret < 0)
          break;
        if(ret != GNUTLS_SAN_IPADDRESS)
          continue;
        if(certaddrlen == addrlen && !memcmp(addrbuf, certaddr, addrlen)) {
          rc = 1;
          break;
        }
      }
    }
  }

  if(!rc) {
    const char * const dispname = SSL_IS_PROXY() ? conn->http_proxy.host.dispname : conn->host.dispname;

    if(SSL_CONN_CONFIG(verifyhost)) {
      failf(data, "SSL: certificate subject name (%s) does not match " "target host name '%s'", certbuf, dispname);
      gnutls_x509_crt_deinit(x509_cert);
      return CURLE_PEER_FAILED_VERIFICATION;
    }
    else infof(data, "\t common name: %s (does not match '%s')\n", certbuf, dispname);

  }
  else infof(data, "\t common name: %s (matched)\n", certbuf);

  
  certclock = gnutls_x509_crt_get_expiration_time(x509_cert);

  if(certclock == (time_t)-1) {
    if(SSL_CONN_CONFIG(verifypeer)) {
      failf(data, "server cert expiration date verify failed");
      gnutls_x509_crt_deinit(x509_cert);
      return CURLE_SSL_CONNECT_ERROR;
    }
    else infof(data, "\t server certificate expiration date verify FAILED\n");
  }
  else {
    if(certclock < time(NULL)) {
      if(SSL_CONN_CONFIG(verifypeer)) {
        failf(data, "server certificate expiration date has passed.");
        gnutls_x509_crt_deinit(x509_cert);
        return CURLE_PEER_FAILED_VERIFICATION;
      }
      else infof(data, "\t server certificate expiration date FAILED\n");
    }
    else infof(data, "\t server certificate expiration date OK\n");
  }

  certclock = gnutls_x509_crt_get_activation_time(x509_cert);

  if(certclock == (time_t)-1) {
    if(SSL_CONN_CONFIG(verifypeer)) {
      failf(data, "server cert activation date verify failed");
      gnutls_x509_crt_deinit(x509_cert);
      return CURLE_SSL_CONNECT_ERROR;
    }
    else infof(data, "\t server certificate activation date verify FAILED\n");
  }
  else {
    if(certclock > time(NULL)) {
      if(SSL_CONN_CONFIG(verifypeer)) {
        failf(data, "server certificate not activated yet.");
        gnutls_x509_crt_deinit(x509_cert);
        return CURLE_PEER_FAILED_VERIFICATION;
      }
      else infof(data, "\t server certificate activation date FAILED\n");
    }
    else infof(data, "\t server certificate activation date OK\n");
  }

  ptr = SSL_IS_PROXY() ? data->set.str[STRING_SSL_PINNEDPUBLICKEY_PROXY] :
        data->set.str[STRING_SSL_PINNEDPUBLICKEY_ORIG];
  if(ptr) {
    result = pkp_pin_peer_pubkey(data, x509_cert, ptr);
    if(result != CURLE_OK) {
      failf(data, "SSL: public key does not match pinned public key!");
      gnutls_x509_crt_deinit(x509_cert);
      return result;
    }
  }

  

  
  algo = gnutls_x509_crt_get_pk_algorithm(x509_cert, &bits);
  infof(data, "\t certificate public key: %s\n", gnutls_pk_algorithm_get_name(algo));

  
  infof(data, "\t certificate version: #%d\n", gnutls_x509_crt_get_version(x509_cert));


  size = sizeof(certbuf);
  gnutls_x509_crt_get_dn(x509_cert, certbuf, &size);
  infof(data, "\t subject: %s\n", certbuf);

  certclock = gnutls_x509_crt_get_activation_time(x509_cert);
  showtime(data, "start date", certclock);

  certclock = gnutls_x509_crt_get_expiration_time(x509_cert);
  showtime(data, "expire date", certclock);

  size = sizeof(certbuf);
  gnutls_x509_crt_get_issuer_dn(x509_cert, certbuf, &size);
  infof(data, "\t issuer: %s\n", certbuf);

  gnutls_x509_crt_deinit(x509_cert);

  
  ptr = gnutls_compression_get_name(gnutls_compression_get(session));
  
  infof(data, "\t compression: %s\n", ptr);


  if(conn->bits.tls_enable_alpn) {
    rc = gnutls_alpn_get_selected_protocol(session, &proto);
    if(rc == 0) {
      infof(data, "ALPN, server accepted to use %.*s\n", proto.size, proto.data);


      if(proto.size == NGHTTP2_PROTO_VERSION_ID_LEN && !memcmp(NGHTTP2_PROTO_VERSION_ID, proto.data, NGHTTP2_PROTO_VERSION_ID_LEN)) {

        conn->negnpn = CURL_HTTP_VERSION_2;
      }
      else  if(proto.size == ALPN_HTTP_1_1_LENGTH && !memcmp(ALPN_HTTP_1_1, proto.data, ALPN_HTTP_1_1_LENGTH)) {


        conn->negnpn = CURL_HTTP_VERSION_1_1;
      }
    }
    else infof(data, "ALPN, server did not agree to a protocol\n");
  }


  conn->ssl[sockindex].state = ssl_connection_complete;
  conn->recv[sockindex] = gtls_recv;
  conn->send[sockindex] = gtls_send;

  if(data->set.general_ssl.sessionid) {
    
    bool incache;
    void *ssl_sessionid;
    void *connect_sessionid;
    size_t connect_idsize = 0;

    
    gnutls_session_get_data(session, NULL, &connect_idsize);
    connect_sessionid = malloc(connect_idsize); 

    if(connect_sessionid) {
      
      gnutls_session_get_data(session, connect_sessionid, &connect_idsize);

      Curl_ssl_sessionid_lock(conn);
      incache = !(Curl_ssl_getsessionid(conn, &ssl_sessionid, NULL, sockindex));
      if(incache) {
        
        Curl_ssl_delsessionid(conn, ssl_sessionid);
      }

      
      result = Curl_ssl_addsessionid(conn, connect_sessionid, connect_idsize, sockindex);
      Curl_ssl_sessionid_unlock(conn);
      if(result) {
        free(connect_sessionid);
        result = CURLE_OUT_OF_MEMORY;
      }
    }
    else result = CURLE_OUT_OF_MEMORY;
  }

  return result;
}




static CURLcode gtls_connect_common(struct connectdata *conn, int sockindex, bool nonblocking, bool *done)



{
  int rc;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];

  
  if(ssl_connect_1==connssl->connecting_state) {
    rc = gtls_connect_step1(conn, sockindex);
    if(rc)
      return rc;
  }

  rc = handshake(conn, sockindex, TRUE, nonblocking);
  if(rc)
    
    return rc;

  
  if(ssl_connect_1==connssl->connecting_state) {
    rc = gtls_connect_step3(conn, sockindex);
    if(rc)
      return rc;
  }

  *done = ssl_connect_1==connssl->connecting_state;

  return CURLE_OK;
}

CURLcode Curl_gtls_connect_nonblocking(struct connectdata *conn, int sockindex, bool *done)


{
  return gtls_connect_common(conn, sockindex, TRUE, done);
}

CURLcode Curl_gtls_connect(struct connectdata *conn, int sockindex)


{
  CURLcode result;
  bool done = FALSE;

  result = gtls_connect_common(conn, sockindex, FALSE, &done);
  if(result)
    return result;

  DEBUGASSERT(done);

  return CURLE_OK;
}

bool Curl_gtls_data_pending(const struct connectdata *conn, int connindex)
{
  bool res = FALSE;
  if(conn->ssl[connindex].session && 0 != gnutls_record_check_pending(conn->ssl[connindex].session))
    res = TRUE;

  if(conn->proxy_ssl[connindex].session && 0 != gnutls_record_check_pending(conn->proxy_ssl[connindex].session))
    res = TRUE;

  return res;
}

static ssize_t gtls_send(struct connectdata *conn, int sockindex, const void *mem, size_t len, CURLcode *curlcode)



{
  ssize_t rc = gnutls_record_send(conn->ssl[sockindex].session, mem, len);

  if(rc < 0) {
    *curlcode = (rc == GNUTLS_E_AGAIN)
      ? CURLE_AGAIN : CURLE_SEND_ERROR;

    rc = -1;
  }

  return rc;
}

static void close_one(struct ssl_connect_data *ssl)
{
  if(ssl->session) {
    gnutls_bye(ssl->session, GNUTLS_SHUT_RDWR);
    gnutls_deinit(ssl->session);
    ssl->session = NULL;
  }
  if(ssl->cred) {
    gnutls_certificate_free_credentials(ssl->cred);
    ssl->cred = NULL;
  }

  if(ssl->srp_client_cred) {
    gnutls_srp_free_client_credentials(ssl->srp_client_cred);
    ssl->srp_client_cred = NULL;
  }

}

void Curl_gtls_close(struct connectdata *conn, int sockindex)
{
  close_one(&conn->ssl[sockindex]);
  close_one(&conn->proxy_ssl[sockindex]);
}


int Curl_gtls_shutdown(struct connectdata *conn, int sockindex)
{
  ssize_t result;
  int retval = 0;
  struct Curl_easy *data = conn->data;
  int done = 0;
  char buf[120];

  

  if(data->set.ftp_ccc == CURLFTPSSL_CCC_ACTIVE)
      gnutls_bye(conn->ssl[sockindex].session, GNUTLS_SHUT_WR);

  if(conn->ssl[sockindex].session) {
    while(!done) {
      int what = SOCKET_READABLE(conn->sock[sockindex], SSL_SHUTDOWN_TIMEOUT);
      if(what > 0) {
        
        result = gnutls_record_recv(conn->ssl[sockindex].session, buf, sizeof(buf));
        switch(result) {
        case 0:
          
          done = 1;
          break;
        case GNUTLS_E_AGAIN:
        case GNUTLS_E_INTERRUPTED:
          infof(data, "GNUTLS_E_AGAIN || GNUTLS_E_INTERRUPTED\n");
          break;
        default:
          retval = -1;
          done = 1;
          break;
        }
      }
      else if(0 == what) {
        
        failf(data, "SSL shutdown timeout");
        done = 1;
        break;
      }
      else {
        
        failf(data, "select/poll on SSL socket, errno: %d", SOCKERRNO);
        retval = -1;
        done = 1;
      }
    }
    gnutls_deinit(conn->ssl[sockindex].session);
  }
  gnutls_certificate_free_credentials(conn->ssl[sockindex].cred);


  if(SSL_SET_OPTION(authtype) == CURL_TLSAUTH_SRP && SSL_SET_OPTION(username) != NULL)
    gnutls_srp_free_client_credentials(conn->ssl[sockindex].srp_client_cred);


  conn->ssl[sockindex].cred = NULL;
  conn->ssl[sockindex].session = NULL;

  return retval;
}

static ssize_t gtls_recv(struct connectdata *conn,  int num, char *buf, size_t buffersize, CURLcode *curlcode)



{
  ssize_t ret;

  ret = gnutls_record_recv(conn->ssl[num].session, buf, buffersize);
  if((ret == GNUTLS_E_AGAIN) || (ret == GNUTLS_E_INTERRUPTED)) {
    *curlcode = CURLE_AGAIN;
    return -1;
  }

  if(ret == GNUTLS_E_REHANDSHAKE) {
    
    CURLcode result = handshake(conn, num, FALSE, FALSE);
    if(result)
      
      *curlcode = result;
    else *curlcode = CURLE_AGAIN;
    return -1;
  }

  if(ret < 0) {
    failf(conn->data, "GnuTLS recv error (%d): %s", (int)ret, gnutls_strerror((int)ret));
    *curlcode = CURLE_RECV_ERROR;
    return -1;
  }

  return ret;
}

void Curl_gtls_session_free(void *ptr)
{
  free(ptr);
}

size_t Curl_gtls_version(char *buffer, size_t size)
{
  return snprintf(buffer, size, "GnuTLS/%s", gnutls_check_version(NULL));
}


static int Curl_gtls_seed(struct Curl_easy *data)
{
  
  static bool ssl_seeded = FALSE;

  
  gcry_fast_random_poll();

  if(!ssl_seeded || data->set.str[STRING_SSL_RANDOM_FILE] || data->set.str[STRING_SSL_EGDSOCKET]) {

    
    ssl_seeded = TRUE;
  }
  return 0;
}



CURLcode Curl_gtls_random(struct Curl_easy *data, unsigned char *entropy, size_t length)

{

  int rc;
  (void)data;
  rc = gnutls_rnd(GNUTLS_RND_RANDOM, entropy, length);
  return rc?CURLE_FAILED_INIT:CURLE_OK;

  if(data)
    Curl_gtls_seed(data); 
  gcry_randomize(entropy, length, GCRY_STRONG_RANDOM);

  return CURLE_OK;
}

void Curl_gtls_md5sum(unsigned char *tmp,  size_t tmplen, unsigned char *md5sum, size_t md5len)


{

  struct md5_ctx MD5pw;
  md5_init(&MD5pw);
  md5_update(&MD5pw, (unsigned int)tmplen, tmp);
  md5_digest(&MD5pw, (unsigned int)md5len, md5sum);

  gcry_md_hd_t MD5pw;
  gcry_md_open(&MD5pw, GCRY_MD_MD5, 0);
  gcry_md_write(MD5pw, tmp, tmplen);
  memcpy(md5sum, gcry_md_read(MD5pw, 0), md5len);
  gcry_md_close(MD5pw);

}

void Curl_gtls_sha256sum(const unsigned char *tmp,  size_t tmplen, unsigned char *sha256sum, size_t sha256len)


{

  struct sha256_ctx SHA256pw;
  sha256_init(&SHA256pw);
  sha256_update(&SHA256pw, (unsigned int)tmplen, tmp);
  sha256_digest(&SHA256pw, (unsigned int)sha256len, sha256sum);

  gcry_md_hd_t SHA256pw;
  gcry_md_open(&SHA256pw, GCRY_MD_SHA256, 0);
  gcry_md_write(SHA256pw, tmp, tmplen);
  memcpy(sha256sum, gcry_md_read(SHA256pw, 0), sha256len);
  gcry_md_close(SHA256pw);

}

bool Curl_gtls_cert_status_request(void)
{

  return TRUE;

  return FALSE;

}


