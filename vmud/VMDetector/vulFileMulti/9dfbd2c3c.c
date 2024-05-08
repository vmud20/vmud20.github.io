




















struct ssl_backend_data {
  const struct rustls_client_config *config;
  struct rustls_client_session *session;
  bool data_pending;
  uint8_t *tlsbuf;
};


static CURLcode map_error(rustls_result r)
{
  if(rustls_result_is_cert_error(r)) {
    return CURLE_PEER_FAILED_VERIFICATION;
  }
  switch(r) {
    case RUSTLS_RESULT_OK:
      return CURLE_OK;
    case RUSTLS_RESULT_NULL_PARAMETER:
      return CURLE_BAD_FUNCTION_ARGUMENT;
    default:
      return CURLE_READ_ERROR;
  }
}

static bool cr_data_pending(const struct connectdata *conn, int sockindex)
{
  const struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  struct ssl_backend_data *backend = connssl->backend;
  return backend->data_pending;
}

static CURLcode cr_connect(struct Curl_easy *data UNUSED_PARAM, struct connectdata *conn UNUSED_PARAM, int sockindex UNUSED_PARAM)


{
  infof(data, "rustls_connect: unimplemented\n");
  return CURLE_SSL_CONNECT_ERROR;
}


static ssize_t cr_recv(struct Curl_easy *data, int sockindex, char *plainbuf, size_t plainlen, CURLcode *err)

{
  struct connectdata *conn = data->conn;
  struct ssl_connect_data *const connssl = &conn->ssl[sockindex];
  struct ssl_backend_data *const backend = connssl->backend;
  struct rustls_client_session *const session = backend->session;
  curl_socket_t sockfd = conn->sock[sockindex];
  size_t n = 0;
  ssize_t tls_bytes_read = 0;
  size_t tls_bytes_processed = 0;
  size_t plain_bytes_copied = 0;
  rustls_result rresult = 0;
  char errorbuf[255];

  tls_bytes_read = sread(sockfd, backend->tlsbuf, TLSBUF_SIZE);
  if(tls_bytes_read == 0) {
    failf(data, "connection closed without TLS close_notify alert");
    *err = CURLE_READ_ERROR;
    return -1;
  }
  else if(tls_bytes_read < 0) {
    if(SOCKERRNO == EAGAIN || SOCKERRNO == EWOULDBLOCK) {
      infof(data, "sread: EAGAIN or EWOULDBLOCK\n");
      
      tls_bytes_read = 0;
    }
    else {
      failf(data, "reading from socket: %s", strerror(SOCKERRNO));
      *err = CURLE_READ_ERROR;
      return -1;
    }
  }

  
  DEBUGASSERT(tls_bytes_read >= 0);
  while(tls_bytes_processed < (size_t)tls_bytes_read) {
    rresult = rustls_client_session_read_tls(session, backend->tlsbuf + tls_bytes_processed, tls_bytes_read - tls_bytes_processed, &n);


    if(rresult != RUSTLS_RESULT_OK) {
      failf(data, "error in rustls_client_session_read_tls");
      *err = CURLE_READ_ERROR;
      return -1;
    }
    else if(n == 0) {
      infof(data, "EOF from rustls_client_session_read_tls\n");
      break;
    }

    rresult = rustls_client_session_process_new_packets(session);
    if(rresult != RUSTLS_RESULT_OK) {
      rustls_error(rresult, errorbuf, sizeof(errorbuf), &n);
      failf(data, "%.*s", n, errorbuf);
      *err = map_error(rresult);
      return -1;
    }

    tls_bytes_processed += n;
    backend->data_pending = TRUE;
  }

  while(plain_bytes_copied < plainlen) {
    rresult = rustls_client_session_read(session, (uint8_t *)plainbuf + plain_bytes_copied, plainlen - plain_bytes_copied, &n);


    if(rresult == RUSTLS_RESULT_ALERT_CLOSE_NOTIFY) {
      *err = CURLE_OK;
      return 0;
    }
    else if(rresult != RUSTLS_RESULT_OK) {
      failf(data, "error in rustls_client_session_read");
      *err = CURLE_READ_ERROR;
      return -1;
    }
    else if(n == 0) {
      
      infof(data, "EOF from rustls_client_session_read\n");
      backend->data_pending = FALSE;
      break;
    }
    else {
      plain_bytes_copied += n;
    }
  }

  
  if(plain_bytes_copied == 0) {
    *err = CURLE_AGAIN;
    return -1;
  }

  return plain_bytes_copied;
}


static ssize_t cr_send(struct Curl_easy *data, int sockindex, const void *plainbuf, size_t plainlen, CURLcode *err)

{
  struct connectdata *conn = data->conn;
  struct ssl_connect_data *const connssl = &conn->ssl[sockindex];
  struct ssl_backend_data *const backend = connssl->backend;
  struct rustls_client_session *const session = backend->session;
  curl_socket_t sockfd = conn->sock[sockindex];
  ssize_t n = 0;
  size_t plainwritten = 0;
  size_t tlslen = 0;
  size_t tlswritten = 0;
  rustls_result rresult;

  if(plainlen > 0) {
    rresult = rustls_client_session_write(session, plainbuf, plainlen, &plainwritten);
    if(rresult != RUSTLS_RESULT_OK) {
      failf(data, "error in rustls_client_session_write");
      *err = CURLE_WRITE_ERROR;
      return -1;
    }
    else if(plainwritten == 0) {
      failf(data, "EOF in rustls_client_session_write");
      *err = CURLE_WRITE_ERROR;
      return -1;
    }
  }

  while(rustls_client_session_wants_write(session)) {
    rresult = rustls_client_session_write_tls( session, backend->tlsbuf, TLSBUF_SIZE, &tlslen);
    if(rresult != RUSTLS_RESULT_OK) {
      failf(data, "error in rustls_client_session_write_tls");
      *err = CURLE_WRITE_ERROR;
      return -1;
    }
    else if(tlslen == 0) {
      failf(data, "EOF in rustls_client_session_write_tls");
      *err = CURLE_WRITE_ERROR;
      return -1;
    }

    tlswritten = 0;

    while(tlswritten < tlslen) {
      n = swrite(sockfd, backend->tlsbuf + tlswritten, tlslen - tlswritten);
      if(n < 0) {
        if(SOCKERRNO == EAGAIN || SOCKERRNO == EWOULDBLOCK) {
          
          infof(data, "swrite: EAGAIN after %ld bytes\n", tlswritten);
          DEBUGASSERT(tlswritten > 0);
          break;
        }
        failf(data, "error in swrite");
        *err = CURLE_WRITE_ERROR;
        return -1;
      }
      if(n == 0) {
        failf(data, "EOF in swrite");
        *err = CURLE_WRITE_ERROR;
        return -1;
      }
      tlswritten += n;
    }

    DEBUGASSERT(tlswritten <= tlslen);
  }

  return plainwritten;
}


static enum rustls_result cr_verify_none(void *userdata UNUSED_PARAM, const rustls_verify_server_cert_params *params UNUSED_PARAM)

{
  return RUSTLS_RESULT_OK;
}

static bool cr_hostname_is_ip(const char *hostname)
{
  struct in_addr in;

  struct in6_addr in6;
  if(Curl_inet_pton(AF_INET6, hostname, &in6) > 0) {
    return true;
  }

  if(Curl_inet_pton(AF_INET, hostname, &in) > 0) {
    return true;
  }
  return false;
}

static CURLcode cr_init_backend(struct Curl_easy *data, struct connectdata *conn, struct ssl_backend_data *const backend)

{
  struct rustls_client_session *session = backend->session;
  struct rustls_client_config_builder *config_builder = NULL;
  const char *const ssl_cafile = SSL_CONN_CONFIG(CAfile);
  const bool verifypeer = SSL_CONN_CONFIG(verifypeer);
  const char *hostname = conn->host.name;
  char errorbuf[256];
  size_t errorlen;
  int result;
  rustls_slice_bytes alpn[2] = {
    { (const uint8_t *)ALPN_HTTP_1_1, ALPN_HTTP_1_1_LENGTH }, { (const uint8_t *)ALPN_H2, ALPN_H2_LENGTH }, };


  backend->tlsbuf = calloc(TLSBUF_SIZE, 1);
  if(!backend->tlsbuf) {
    return CURLE_OUT_OF_MEMORY;
  }

  config_builder = rustls_client_config_builder_new();

  infof(data, "offering ALPN for HTTP/1.1 and HTTP/2\n");
  rustls_client_config_builder_set_protocols(config_builder, alpn, 2);

  infof(data, "offering ALPN for HTTP/1.1 only\n");
  rustls_client_config_builder_set_protocols(config_builder, alpn, 1);

  if(!verifypeer) {
    rustls_client_config_builder_dangerous_set_certificate_verifier( config_builder, cr_verify_none, NULL);
    
    if(cr_hostname_is_ip(hostname)) {
      rustls_client_config_builder_set_enable_sni(config_builder, false);
      hostname = "example.invalid";
    }
  }
  else if(ssl_cafile) {
    result = rustls_client_config_builder_load_roots_from_file( config_builder, ssl_cafile);
    if(result != RUSTLS_RESULT_OK) {
      failf(data, "failed to load trusted certificates");
      rustls_client_config_free( rustls_client_config_builder_build(config_builder));
      return CURLE_SSL_CACERT_BADFILE;
    }
  }
  else {
    result = rustls_client_config_builder_load_native_roots(config_builder);
    if(result != RUSTLS_RESULT_OK) {
      failf(data, "failed to load trusted certificates");
      rustls_client_config_free( rustls_client_config_builder_build(config_builder));
      return CURLE_SSL_CACERT_BADFILE;
    }
  }

  backend->config = rustls_client_config_builder_build(config_builder);
  DEBUGASSERT(session == NULL);
  result = rustls_client_session_new( backend->config, hostname, &session);
  if(result != RUSTLS_RESULT_OK) {
    rustls_error(result, errorbuf, sizeof(errorbuf), &errorlen);
    failf(data, "failed to create client session: %.*s", errorlen, errorbuf);
    return CURLE_COULDNT_CONNECT;
  }
  backend->session = session;
  return CURLE_OK;
}

static void cr_set_negotiated_alpn(struct Curl_easy *data, struct connectdata *conn, const struct rustls_client_session *session)

{
  const uint8_t *protocol = NULL;
  size_t len = 0;

  rustls_client_session_get_alpn_protocol(session, &protocol, &len);
  if(NULL == protocol) {
    infof(data, "ALPN, server did not agree to a protocol\n");
    return;
  }


  if(len == ALPN_H2_LENGTH && 0 == memcmp(ALPN_H2, protocol, len)) {
    infof(data, "ALPN, negotiated h2\n");
    conn->negnpn = CURL_HTTP_VERSION_2;
  }
  else  if(len == ALPN_HTTP_1_1_LENGTH && 0 == memcmp(ALPN_HTTP_1_1, protocol, len)) {


    infof(data, "ALPN, negotiated http/1.1\n");
    conn->negnpn = CURL_HTTP_VERSION_1_1;
  }
  else {
    infof(data, "ALPN, negotiated an unrecognized protocol\n");
  }

  Curl_multiuse_state(data, conn->negnpn == CURL_HTTP_VERSION_2 ? BUNDLE_MULTIPLEX : BUNDLE_NO_MULTIUSE);
}

static CURLcode cr_connect_nonblocking(struct Curl_easy *data, struct connectdata *conn, int sockindex, bool *done)

{
  struct ssl_connect_data *const connssl = &conn->ssl[sockindex];
  curl_socket_t sockfd = conn->sock[sockindex];
  struct ssl_backend_data *const backend = connssl->backend;
  struct rustls_client_session *session = NULL;
  CURLcode tmperr = CURLE_OK;
  int result;
  int what;
  bool wants_read;
  bool wants_write;
  curl_socket_t writefd;
  curl_socket_t readfd;

  if(ssl_connection_none == connssl->state) {
    result = cr_init_backend(data, conn, connssl->backend);
    if(result != CURLE_OK) {
      return result;
    }
    connssl->state = ssl_connection_negotiating;
  }

  session = backend->session;

  
  for(;;) {
    
    if(!rustls_client_session_is_handshaking(session)) {
      infof(data, "Done handshaking\n");
      
      connssl->state = ssl_connection_complete;

      cr_set_negotiated_alpn(data, conn, session);

      conn->recv[sockindex] = cr_recv;
      conn->send[sockindex] = cr_send;
      *done = TRUE;
      return CURLE_OK;
    }

    wants_read = rustls_client_session_wants_read(session);
    wants_write = rustls_client_session_wants_write(session);
    DEBUGASSERT(wants_read || wants_write);
    writefd = wants_write?sockfd:CURL_SOCKET_BAD;
    readfd = wants_read?sockfd:CURL_SOCKET_BAD;

    what = Curl_socket_check(readfd, CURL_SOCKET_BAD, writefd, 0);
    if(what < 0) {
      
      failf(data, "select/poll on SSL socket, errno: %d", SOCKERRNO);
      return CURLE_SSL_CONNECT_ERROR;
    }
    if(0 == what) {
      infof(data, "Curl_socket_check: %s would block\n", wants_read&&wants_write ? "writing and reading" :

            wants_write ? "writing" :
              "reading");
      *done = FALSE;
      return CURLE_OK;
    }
    

    if(wants_write) {
      infof(data, "ClientSession wants us to write_tls.\n");
      cr_send(data, sockindex, NULL, 0, &tmperr);
      if(tmperr == CURLE_AGAIN) {
        infof(data, "writing would block\n");
        
      }
      else if(tmperr != CURLE_OK) {
        return tmperr;
      }
    }

    if(wants_read) {
      infof(data, "ClientSession wants us to read_tls.\n");

      cr_recv(data, sockindex, NULL, 0, &tmperr);
      if(tmperr == CURLE_AGAIN) {
        infof(data, "reading would block\n");
        
      }
      else if(tmperr != CURLE_OK) {
        if(tmperr == CURLE_READ_ERROR) {
          return CURLE_SSL_CONNECT_ERROR;
        }
        else {
          return tmperr;
        }
      }
    }
  }

  
  DEBUGASSERT(false);
}


static int cr_getsock(struct connectdata *conn, curl_socket_t *socks)
{
  struct ssl_connect_data *const connssl = &conn->ssl[FIRSTSOCKET];
  curl_socket_t sockfd = conn->sock[FIRSTSOCKET];
  struct ssl_backend_data *const backend = connssl->backend;
  struct rustls_client_session *session = backend->session;

  if(rustls_client_session_wants_write(session)) {
    socks[0] = sockfd;
    return GETSOCK_WRITESOCK(0);
  }
  if(rustls_client_session_wants_read(session)) {
    socks[0] = sockfd;
    return GETSOCK_READSOCK(0);
  }

  return GETSOCK_BLANK;
}

static void * cr_get_internals(struct ssl_connect_data *connssl, CURLINFO info UNUSED_PARAM)

{
  struct ssl_backend_data *backend = connssl->backend;
  return &backend->session;
}

static void cr_close(struct Curl_easy *data, struct connectdata *conn, int sockindex)

{
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  struct ssl_backend_data *backend = connssl->backend;
  CURLcode tmperr = CURLE_OK;
  ssize_t n = 0;

  if(backend->session) {
    rustls_client_session_send_close_notify(backend->session);
    n = cr_send(data, sockindex, NULL, 0, &tmperr);
    if(n < 0) {
      failf(data, "error sending close notify: %d", tmperr);
    }

    rustls_client_session_free(backend->session);
    backend->session = NULL;
  }
  if(backend->config) {
    rustls_client_config_free(backend->config);
    backend->config = NULL;
  }
  free(backend->tlsbuf);
}

const struct Curl_ssl Curl_ssl_rustls = {
  { CURLSSLBACKEND_RUSTLS, "rustls" }, SSLSUPP_TLS13_CIPHERSUITES, sizeof(struct ssl_backend_data),  Curl_none_init, Curl_none_cleanup, rustls_version, Curl_none_check_cxn, Curl_none_shutdown, cr_data_pending, Curl_none_random, Curl_none_cert_status_request, cr_connect, cr_connect_nonblocking, cr_getsock, cr_get_internals, cr_close, Curl_none_close_all, Curl_none_session_free, Curl_none_set_engine, Curl_none_set_engine_default, Curl_none_engines_list, Curl_none_false_start, NULL };

























