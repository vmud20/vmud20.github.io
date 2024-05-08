

































struct ssl_backend_data {
  SSL_CTX *ctx;
  SSL *handle;
};



static Curl_recv mesalink_recv;
static Curl_send mesalink_send;

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


static CURLcode mesalink_connect_step1(struct Curl_easy *data, struct connectdata *conn, int sockindex)

{
  char *ciphers;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  struct in_addr addr4;

  struct in6_addr addr6;

  const char * const hostname = SSL_HOST_NAME();
  size_t hostname_len = strlen(hostname);

  SSL_METHOD *req_method = NULL;
  curl_socket_t sockfd = conn->sock[sockindex];

  if(connssl->state == ssl_connection_complete)
    return CURLE_OK;

  if(SSL_CONN_CONFIG(version_max) != CURL_SSLVERSION_MAX_NONE) {
    failf(data, "MesaLink does not support to set maximum SSL/TLS version");
    return CURLE_SSL_CONNECT_ERROR;
  }

  switch(SSL_CONN_CONFIG(version)) {
  case CURL_SSLVERSION_SSLv3:
  case CURL_SSLVERSION_TLSv1:
  case CURL_SSLVERSION_TLSv1_0:
  case CURL_SSLVERSION_TLSv1_1:
    failf(data, "MesaLink does not support SSL 3.0, TLS 1.0, or TLS 1.1");
    return CURLE_NOT_BUILT_IN;
  case CURL_SSLVERSION_DEFAULT:
  case CURL_SSLVERSION_TLSv1_2:
    req_method = TLSv1_2_client_method();
    break;
  case CURL_SSLVERSION_TLSv1_3:
    req_method = TLSv1_3_client_method();
    break;
  case CURL_SSLVERSION_SSLv2:
    failf(data, "MesaLink does not support SSLv2");
    return CURLE_SSL_CONNECT_ERROR;
  default:
    failf(data, "Unrecognized parameter passed via CURLOPT_SSLVERSION");
    return CURLE_SSL_CONNECT_ERROR;
  }

  if(!req_method) {
    failf(data, "SSL: couldn't create a method!");
    return CURLE_OUT_OF_MEMORY;
  }

  if(BACKEND->ctx)
    SSL_CTX_free(BACKEND->ctx);
  BACKEND->ctx = SSL_CTX_new(req_method);

  if(!BACKEND->ctx) {
    failf(data, "SSL: couldn't create a context!");
    return CURLE_OUT_OF_MEMORY;
  }

  SSL_CTX_set_verify( BACKEND->ctx, SSL_CONN_CONFIG(verifypeer) ? SSL_VERIFY_PEER : SSL_VERIFY_NONE, NULL);


  if(SSL_CONN_CONFIG(CAfile) || SSL_CONN_CONFIG(CApath)) {
    if(!SSL_CTX_load_verify_locations(BACKEND->ctx, SSL_CONN_CONFIG(CAfile), SSL_CONN_CONFIG(CApath))) {
      if(SSL_CONN_CONFIG(verifypeer)) {
        failf(data, "error setting certificate verify locations: " " CAfile: %s CApath: %s", SSL_CONN_CONFIG(CAfile) ? SSL_CONN_CONFIG(CAfile) : "none", SSL_CONN_CONFIG(CApath) ? SSL_CONN_CONFIG(CApath) : "none");





        return CURLE_SSL_CACERT_BADFILE;
      }
      infof(data, "error setting certificate verify locations," " continuing anyway:\n");

    }
    else {
      infof(data, "successfully set certificate verify locations:\n");
    }
    infof(data, " CAfile: %s\n", SSL_CONN_CONFIG(CAfile) ? SSL_CONN_CONFIG(CAfile): "none");
    infof(data, " CApath: %s\n", SSL_CONN_CONFIG(CApath) ? SSL_CONN_CONFIG(CApath): "none");
  }

  if(SSL_SET_OPTION(primary.clientcert) && SSL_SET_OPTION(key)) {
    int file_type = do_file_type(SSL_SET_OPTION(cert_type));

    if(SSL_CTX_use_certificate_chain_file(BACKEND->ctx, SSL_SET_OPTION(primary.clientcert), file_type) != 1) {

      failf(data, "unable to use client certificate (no key or wrong pass" " phrase?)");
      return CURLE_SSL_CONNECT_ERROR;
    }

    file_type = do_file_type(SSL_SET_OPTION(key_type));
    if(SSL_CTX_use_PrivateKey_file(BACKEND->ctx, SSL_SET_OPTION(key), file_type) != 1) {
      failf(data, "unable to set private key");
      return CURLE_SSL_CONNECT_ERROR;
    }
    infof(data, "client cert: %s\n", SSL_CONN_CONFIG(clientcert)? SSL_CONN_CONFIG(clientcert): "none");


  }

  ciphers = SSL_CONN_CONFIG(cipher_list);
  if(ciphers) {

    if(!SSL_CTX_set_cipher_list(BACKEND->ctx, ciphers)) {
      failf(data, "failed setting cipher list: %s", ciphers);
      return CURLE_SSL_CIPHER;
    }

    infof(data, "Cipher selection: %s\n", ciphers);
  }

  if(BACKEND->handle)
    SSL_free(BACKEND->handle);
  BACKEND->handle = SSL_new(BACKEND->ctx);
  if(!BACKEND->handle) {
    failf(data, "SSL: couldn't create a context (handle)!");
    return CURLE_OUT_OF_MEMORY;
  }

  if((hostname_len < USHRT_MAX) && (0 == Curl_inet_pton(AF_INET, hostname, &addr4))

     && (0 == Curl_inet_pton(AF_INET6, hostname, &addr6))

  ) {
    
    if(SSL_set_tlsext_host_name(BACKEND->handle, hostname) != SSL_SUCCESS) {
      failf(data, "WARNING: failed to configure server name indication (SNI) " "TLS extension\n");

      return CURLE_SSL_CONNECT_ERROR;
    }
  }
  else {

    
    if(strncmp(hostname, "127.0.0.1", 9) == 0  || strncmp(hostname, "[::1]", 5) == 0  ) {



      SSL_set_tlsext_host_name(BACKEND->handle, "localhost");
    }
    else  {

      failf(data, "ERROR: MesaLink does not accept an IP address as a hostname\n");
      return CURLE_SSL_CONNECT_ERROR;
    }
  }


  if(SSL_SET_OPTION(primary.sessionid)) {
    void *ssl_sessionid = NULL;

    Curl_ssl_sessionid_lock(data);
    if(!Curl_ssl_getsessionid(data, conn, SSL_IS_PROXY() ? TRUE : FALSE, &ssl_sessionid, NULL, sockindex)) {

      
      if(!SSL_set_session(BACKEND->handle, ssl_sessionid)) {
        Curl_ssl_sessionid_unlock(data);
        failf( data, "SSL: SSL_set_session failed: %s", ERR_error_string(SSL_get_error(BACKEND->handle, 0), error_buffer));


        return CURLE_SSL_CONNECT_ERROR;
      }
      
      infof(data, "SSL re-using session ID\n");
    }
    Curl_ssl_sessionid_unlock(data);
  }


  if(SSL_set_fd(BACKEND->handle, (int)sockfd) != SSL_SUCCESS) {
    failf(data, "SSL: SSL_set_fd failed");
    return CURLE_SSL_CONNECT_ERROR;
  }

  connssl->connecting_state = ssl_connect_2;
  return CURLE_OK;
}

static CURLcode mesalink_connect_step2(struct Curl_easy *data, struct connectdata *conn, int sockindex)

{
  int ret = -1;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];

  conn->recv[sockindex] = mesalink_recv;
  conn->send[sockindex] = mesalink_send;

  ret = SSL_connect(BACKEND->handle);
  if(ret != SSL_SUCCESS) {
    int detail = SSL_get_error(BACKEND->handle, ret);

    if(SSL_ERROR_WANT_CONNECT == detail || SSL_ERROR_WANT_READ == detail) {
      connssl->connecting_state = ssl_connect_2_reading;
      return CURLE_OK;
    }
    else {
      char error_buffer[MESALINK_MAX_ERROR_SZ];
      failf(data, "SSL_connect failed with error %d: %s", detail, ERR_error_string_n(detail, error_buffer, sizeof(error_buffer)));


      ERR_print_errors_fp(stderr);
      if(detail && SSL_CONN_CONFIG(verifypeer)) {
        detail &= ~0xFF;
        if(detail == TLS_ERROR_WEBPKI_ERRORS) {
          failf(data, "Cert verify failed");
          return CURLE_PEER_FAILED_VERIFICATION;
        }
      }
      return CURLE_SSL_CONNECT_ERROR;
    }
  }

  connssl->connecting_state = ssl_connect_3;
  infof(data, "SSL connection using %s / %s\n", SSL_get_version(BACKEND->handle), SSL_get_cipher_name(BACKEND->handle));



  return CURLE_OK;
}

static CURLcode mesalink_connect_step3(struct connectdata *conn, int sockindex)
{
  CURLcode result = CURLE_OK;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];

  DEBUGASSERT(ssl_connect_3 == connssl->connecting_state);


  if(SSL_SET_OPTION(primary.sessionid)) {
    bool incache;
    SSL_SESSION *our_ssl_sessionid;
    void *old_ssl_sessionid = NULL;
    bool isproxy = SSL_IS_PROXY() ? TRUE : FALSE;

    our_ssl_sessionid = SSL_get_session(BACKEND->handle);

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


  connssl->connecting_state = ssl_connect_done;

  return result;
}

static ssize_t mesalink_send(struct Curl_easy *data, int sockindex, const void *mem, size_t len, CURLcode *curlcode)

{
  struct connectdata *conn = data->conn;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  char error_buffer[MESALINK_MAX_ERROR_SZ];
  int memlen = (len > (size_t)INT_MAX) ? INT_MAX : (int)len;
  int rc = SSL_write(BACKEND->handle, mem, memlen);

  if(rc < 0) {
    int err = SSL_get_error(BACKEND->handle, rc);
    switch(err) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      
      *curlcode = CURLE_AGAIN;
      return -1;
    default:
      failf(data, "SSL write: %s, errno %d", ERR_error_string_n(err, error_buffer, sizeof(error_buffer)), SOCKERRNO);


      *curlcode = CURLE_SEND_ERROR;
      return -1;
    }
  }
  return rc;
}

static void mesalink_close(struct Curl_easy *data, struct connectdata *conn, int sockindex)
{
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];

  (void) data;

  if(BACKEND->handle) {
    (void)SSL_shutdown(BACKEND->handle);
    SSL_free(BACKEND->handle);
    BACKEND->handle = NULL;
  }
  if(BACKEND->ctx) {
    SSL_CTX_free(BACKEND->ctx);
    BACKEND->ctx = NULL;
  }
}

static ssize_t mesalink_recv(struct Curl_easy *data, int num, char *buf, size_t buffersize, CURLcode *curlcode)

{
  struct connectdata *conn = data->conn;
  struct ssl_connect_data *connssl = &conn->ssl[num];
  char error_buffer[MESALINK_MAX_ERROR_SZ];
  int buffsize = (buffersize > (size_t)INT_MAX) ? INT_MAX : (int)buffersize;
  int nread = SSL_read(BACKEND->handle, buf, buffsize);

  if(nread <= 0) {
    int err = SSL_get_error(BACKEND->handle, nread);

    switch(err) {
    case SSL_ERROR_ZERO_RETURN: 
    case IO_ERROR_CONNECTION_ABORTED:
      break;
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      
      *curlcode = CURLE_AGAIN;
      return -1;
    default:
      failf(data, "SSL read: %s, errno %d", ERR_error_string_n(err, error_buffer, sizeof(error_buffer)), SOCKERRNO);


      *curlcode = CURLE_RECV_ERROR;
      return -1;
    }
  }
  return nread;
}

static size_t mesalink_version(char *buffer, size_t size)
{
  return msnprintf(buffer, size, "MesaLink/%s", MESALINK_VERSION_STRING);
}

static int mesalink_init(void)
{
  return (SSL_library_init() == SSL_SUCCESS);
}


static int mesalink_shutdown(struct Curl_easy *data, struct connectdata *conn, int sockindex)

{
  int retval = 0;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];

  (void) data;

  if(BACKEND->handle) {
    SSL_free(BACKEND->handle);
    BACKEND->handle = NULL;
  }
  return retval;
}

static CURLcode mesalink_connect_common(struct Curl_easy *data, struct connectdata *conn, int sockindex, bool nonblocking, bool *done)

{
  CURLcode result;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  curl_socket_t sockfd = conn->sock[sockindex];
  timediff_t timeout_ms;
  int what;

  
  if(ssl_connection_complete == connssl->state) {
    *done = TRUE;
    return CURLE_OK;
  }

  if(ssl_connect_1 == connssl->connecting_state) {
    
    timeout_ms = Curl_timeleft(data, NULL, TRUE);

    if(timeout_ms < 0) {
      
      failf(data, "SSL connection timeout");
      return CURLE_OPERATION_TIMEDOUT;
    }

    result = mesalink_connect_step1(data, conn, sockindex);
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

      curl_socket_t writefd = ssl_connect_2_writing == connssl->connecting_state ? sockfd : CURL_SOCKET_BAD;

      curl_socket_t readfd = ssl_connect_2_reading == connssl->connecting_state ? sockfd : CURL_SOCKET_BAD;


      what = Curl_socket_check(readfd, CURL_SOCKET_BAD, writefd, nonblocking ? 0 : timeout_ms);
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

    
    result = mesalink_connect_step2(data, conn, sockindex);

    if(result || (nonblocking && (ssl_connect_2 == connssl->connecting_state || ssl_connect_2_reading == connssl->connecting_state || ssl_connect_2_writing == connssl->connecting_state))) {


      return result;
    }
  } 

  if(ssl_connect_3 == connssl->connecting_state) {
    result = mesalink_connect_step3(conn, sockindex);
    if(result)
      return result;
  }

  if(ssl_connect_done == connssl->connecting_state) {
    connssl->state = ssl_connection_complete;
    conn->recv[sockindex] = mesalink_recv;
    conn->send[sockindex] = mesalink_send;
    *done = TRUE;
  }
  else *done = FALSE;

  
  connssl->connecting_state = ssl_connect_1;

  return CURLE_OK;
}

static CURLcode mesalink_connect_nonblocking(struct Curl_easy *data, struct connectdata *conn, int sockindex, bool *done)

{
  return mesalink_connect_common(data, conn, sockindex, TRUE, done);
}

static CURLcode mesalink_connect(struct Curl_easy *data, struct connectdata *conn, int sockindex)

{
  CURLcode result;
  bool done = FALSE;

  result = mesalink_connect_common(data, conn, sockindex, FALSE, &done);
  if(result)
    return result;

  DEBUGASSERT(done);

  return CURLE_OK;
}

static void * mesalink_get_internals(struct ssl_connect_data *connssl, CURLINFO info UNUSED_PARAM)

{
  (void)info;
  return BACKEND->handle;
}

const struct Curl_ssl Curl_ssl_mesalink = {
  { CURLSSLBACKEND_MESALINK, "MesaLink" },   SSLSUPP_SSL_CTX,  sizeof(struct ssl_backend_data),  mesalink_init, Curl_none_cleanup, mesalink_version, Curl_none_check_cxn, mesalink_shutdown, Curl_none_data_pending, Curl_none_random, Curl_none_cert_status_request, mesalink_connect, mesalink_connect_nonblocking, Curl_ssl_getsock, mesalink_get_internals, mesalink_close, Curl_none_close_all, Curl_none_session_free, Curl_none_set_engine, Curl_none_set_engine_default, Curl_none_engines_list, Curl_none_false_start, NULL };



























