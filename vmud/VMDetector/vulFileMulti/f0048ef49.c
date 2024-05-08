









































static mbedtls_entropy_context entropy;

static int entropy_init_initialized = 0;


static void entropy_init_mutex(mbedtls_entropy_context *ctx)
{
  
  Curl_polarsslthreadlock_lock_function(0);
  if(entropy_init_initialized == 0) {
    mbedtls_entropy_init(ctx);
    entropy_init_initialized = 1;
  }
  Curl_polarsslthreadlock_unlock_function(0);
}



static int entropy_func_mutex(void *data, unsigned char *output, size_t len)
{
  int ret;
  
  Curl_polarsslthreadlock_lock_function(1);
  ret = mbedtls_entropy_func(data, output, len);
  Curl_polarsslthreadlock_unlock_function(1);

  return ret;
}








static void mbed_debug(void *context, int level, const char *f_name, int line_nb, const char *line)
{
  struct SessionHandle *data = NULL;

  if(!context)
    return;

  data = (struct SessionHandle *)context;

  infof(data, "%s", line);
  (void) level;
}













const mbedtls_x509_crt_profile mbedtls_x509_crt_profile_fr = {
  
  MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA1) | MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_RIPEMD160) | MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA224) | MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA256) | MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA384) | MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA512), 0xFFFFFFF, 0xFFFFFFF, 1024, };















static Curl_recv mbed_recv;
static Curl_send mbed_send;

static CURLcode mbed_connect_step1(struct connectdata *conn, int sockindex)

{
  struct SessionHandle *data = conn->data;
  struct ssl_connect_data* connssl = &conn->ssl[sockindex];

  bool sni = TRUE; 
  int ret = -1;

  struct in6_addr addr;

  struct in_addr addr;

  void *old_session = NULL;
  char errorbuf[128];
  errorbuf[0]=0;

  
  if(data->set.ssl.version == CURL_SSLVERSION_SSLv2) {
    failf(data, "mbedTLS does not support SSLv2");
    return CURLE_SSL_CONNECT_ERROR;
  }
  else if(data->set.ssl.version == CURL_SSLVERSION_SSLv3)
    sni = FALSE; 


  entropy_init_mutex(&entropy);
  mbedtls_ctr_drbg_init(&connssl->ctr_drbg);

  ret = mbedtls_ctr_drbg_seed(&connssl->ctr_drbg, entropy_func_mutex, &entropy, NULL, 0);
  if(ret) {

    mbedtls_strerror(ret, errorbuf, sizeof(errorbuf));

    failf(data, "Failed - mbedTLS: ctr_drbg_init returned (-0x%04X) %s\n", -ret, errorbuf);
  }

  mbedtls_entropy_init(&connssl->entropy);
  mbedtls_ctr_drbg_init(&connssl->ctr_drbg);

  ret = mbedtls_ctr_drbg_seed(&connssl->ctr_drbg, mbedtls_entropy_func, &connssl->entropy, NULL, 0);
  if(ret) {

    mbedtls_strerror(ret, errorbuf, sizeof(errorbuf));

    failf(data, "Failed - mbedTLS: ctr_drbg_init returned (-0x%04X) %s\n", -ret, errorbuf);
  }


  
  mbedtls_x509_crt_init(&connssl->cacert);

  if(data->set.str[STRING_SSL_CAFILE]) {
    ret = mbedtls_x509_crt_parse_file(&connssl->cacert, data->set.str[STRING_SSL_CAFILE]);

    if(ret<0) {

      mbedtls_strerror(ret, errorbuf, sizeof(errorbuf));

      failf(data, "Error reading ca cert file %s - mbedTLS: (-0x%04X) %s", data->set.str[STRING_SSL_CAFILE], -ret, errorbuf);

      if(data->set.ssl.verifypeer)
        return CURLE_SSL_CACERT_BADFILE;
    }
  }

  if(data->set.str[STRING_SSL_CAPATH]) {
    ret = mbedtls_x509_crt_parse_path(&connssl->cacert, data->set.str[STRING_SSL_CAPATH]);

    if(ret<0) {

      mbedtls_strerror(ret, errorbuf, sizeof(errorbuf));

      failf(data, "Error reading ca cert path %s - mbedTLS: (-0x%04X) %s", data->set.str[STRING_SSL_CAPATH], -ret, errorbuf);

      if(data->set.ssl.verifypeer)
        return CURLE_SSL_CACERT_BADFILE;
    }
  }

  
  mbedtls_x509_crt_init(&connssl->clicert);

  if(data->set.str[STRING_CERT]) {
    ret = mbedtls_x509_crt_parse_file(&connssl->clicert, data->set.str[STRING_CERT]);

    if(ret) {

      mbedtls_strerror(ret, errorbuf, sizeof(errorbuf));

      failf(data, "Error reading client cert file %s - mbedTLS: (-0x%04X) %s", data->set.str[STRING_CERT], -ret, errorbuf);

      return CURLE_SSL_CERTPROBLEM;
    }
  }

  
  mbedtls_pk_init(&connssl->pk);

  if(data->set.str[STRING_KEY]) {
    ret = mbedtls_pk_parse_keyfile(&connssl->pk, data->set.str[STRING_KEY], data->set.str[STRING_KEY_PASSWD]);
    if(ret == 0 && !mbedtls_pk_can_do(&connssl->pk, MBEDTLS_PK_RSA))
      ret = MBEDTLS_ERR_PK_TYPE_MISMATCH;

    if(ret) {

      mbedtls_strerror(ret, errorbuf, sizeof(errorbuf));

      failf(data, "Error reading private key %s - mbedTLS: (-0x%04X) %s", data->set.str[STRING_KEY], -ret, errorbuf);

      return CURLE_SSL_CERTPROBLEM;
    }
  }

  
  mbedtls_x509_crl_init(&connssl->crl);

  if(data->set.str[STRING_SSL_CRLFILE]) {
    ret = mbedtls_x509_crl_parse_file(&connssl->crl, data->set.str[STRING_SSL_CRLFILE]);

    if(ret) {

      mbedtls_strerror(ret, errorbuf, sizeof(errorbuf));

      failf(data, "Error reading CRL file %s - mbedTLS: (-0x%04X) %s", data->set.str[STRING_SSL_CRLFILE], -ret, errorbuf);

      return CURLE_SSL_CRL_BADFILE;
    }
  }

  infof(data, "mbedTLS: Connecting to %s:%d\n", conn->host.name, conn->remote_port);

  mbedtls_ssl_config_init(&connssl->config);

  mbedtls_ssl_init(&connssl->ssl);
  if(mbedtls_ssl_setup(&connssl->ssl, &connssl->config)) {
    failf(data, "mbedTLS: ssl_init failed");
    return CURLE_SSL_CONNECT_ERROR;
  }
  ret = mbedtls_ssl_config_defaults(&connssl->config, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);


  if(ret) {
    failf(data, "mbedTLS: ssl_config failed");
    return CURLE_SSL_CONNECT_ERROR;
  }

  
  mbedtls_ssl_conf_cert_profile(&connssl->config, &mbedtls_x509_crt_profile_fr);

  switch(data->set.ssl.version) {
  case CURL_SSLVERSION_DEFAULT:
  case CURL_SSLVERSION_TLSv1:
    mbedtls_ssl_conf_min_version(&connssl->config, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_1);
    infof(data, "mbedTLS: Set min SSL version to TLS 1.0\n");
    break;
  case CURL_SSLVERSION_SSLv3:
    mbedtls_ssl_conf_min_version(&connssl->config, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_0);
    mbedtls_ssl_conf_max_version(&connssl->config, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_0);
    infof(data, "mbedTLS: Set SSL version to SSLv3\n");
    break;
  case CURL_SSLVERSION_TLSv1_0:
    mbedtls_ssl_conf_min_version(&connssl->config, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_1);
    mbedtls_ssl_conf_max_version(&connssl->config, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_1);
    infof(data, "mbedTLS: Set SSL version to TLS 1.0\n");
    break;
  case CURL_SSLVERSION_TLSv1_1:
    mbedtls_ssl_conf_min_version(&connssl->config, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_2);
    mbedtls_ssl_conf_max_version(&connssl->config, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_2);
    infof(data, "mbedTLS: Set SSL version to TLS 1.1\n");
    break;
  case CURL_SSLVERSION_TLSv1_2:
    mbedtls_ssl_conf_min_version(&connssl->config, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
    mbedtls_ssl_conf_max_version(&connssl->config, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
    infof(data, "mbedTLS: Set SSL version to TLS 1.2\n");
    break;
  default:
    failf(data, "mbedTLS: Unsupported SSL protocol version");
    return CURLE_SSL_CONNECT_ERROR;
  }

  mbedtls_ssl_conf_authmode(&connssl->config, MBEDTLS_SSL_VERIFY_OPTIONAL);

  mbedtls_ssl_conf_rng(&connssl->config, mbedtls_ctr_drbg_random, &connssl->ctr_drbg);
  mbedtls_ssl_set_bio(&connssl->ssl, &conn->sock[sockindex], mbedtls_net_send, mbedtls_net_recv, NULL );



  mbedtls_ssl_conf_ciphersuites(&connssl->config, mbedtls_ssl_list_ciphersuites());
  if(!Curl_ssl_getsessionid(conn, &old_session, NULL)) {
    ret = mbedtls_ssl_set_session(&connssl->ssl, old_session);
    if(ret) {
      failf(data, "mbedtls_ssl_set_session returned -0x%x", -ret);
      return CURLE_SSL_CONNECT_ERROR;
    }
    infof(data, "mbedTLS re-using session\n");
  }

  mbedtls_ssl_conf_ca_chain(&connssl->config, &connssl->cacert, &connssl->crl);


  if(data->set.str[STRING_KEY]) {
    mbedtls_ssl_conf_own_cert(&connssl->config, &connssl->clicert, &connssl->pk);
  }
  if(!Curl_inet_pton(AF_INET, conn->host.name, &addr) &&  !Curl_inet_pton(AF_INET6, conn->host.name, &addr) &&  sni && mbedtls_ssl_set_hostname(&connssl->ssl, conn->host.name)) {



    infof(data, "WARNING: failed to configure " "server name indication (SNI) TLS extension\n");
  }


  if(conn->bits.tls_enable_alpn) {
    const char **p = &connssl->protocols[0];

    if(data->set.httpversion >= CURL_HTTP_VERSION_2)
      *p++ = NGHTTP2_PROTO_VERSION_ID;

    *p++ = ALPN_HTTP_1_1;
    *p = NULL;
    
    if(mbedtls_ssl_conf_alpn_protocols(&connssl->config, &connssl->protocols[0])) {
      failf(data, "Failed setting ALPN protocols");
      return CURLE_SSL_CONNECT_ERROR;
    }
    for(p = &connssl->protocols[0]; *p; ++p)
      infof(data, "ALPN, offering %s\n", *p);
  }



  mbedtls_ssl_conf_dbg(&connssl->config, mbedtls_debug, data);


  connssl->connecting_state = ssl_connect_2;

  return CURLE_OK;
}

static CURLcode mbed_connect_step2(struct connectdata *conn, int sockindex)

{
  int ret;
  struct SessionHandle *data = conn->data;
  struct ssl_connect_data* connssl = &conn->ssl[sockindex];
  const mbedtls_x509_crt *peercert;


  const char* next_protocol;


  char errorbuf[128];
  errorbuf[0] = 0;

  conn->recv[sockindex] = mbed_recv;
  conn->send[sockindex] = mbed_send;

  ret = mbedtls_ssl_handshake(&connssl->ssl);

  if(ret == MBEDTLS_ERR_SSL_WANT_READ) {
    connssl->connecting_state = ssl_connect_2_reading;
    return CURLE_OK;
  }
  else if(ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
    connssl->connecting_state = ssl_connect_2_writing;
    return CURLE_OK;
  }
  else if(ret) {

    mbedtls_strerror(ret, errorbuf, sizeof(errorbuf));

    failf(data, "ssl_handshake returned - mbedTLS: (-0x%04X) %s", -ret, errorbuf);
    return CURLE_SSL_CONNECT_ERROR;
  }

  infof(data, "mbedTLS: Handshake complete, cipher is %s\n", mbedtls_ssl_get_ciphersuite(&conn->ssl[sockindex].ssl)
    );

  ret = mbedtls_ssl_get_verify_result(&conn->ssl[sockindex].ssl);

  if(ret && data->set.ssl.verifypeer) {
    if(ret & MBEDTLS_X509_BADCERT_EXPIRED)
      failf(data, "Cert verify failed: BADCERT_EXPIRED");

    if(ret & MBEDTLS_X509_BADCERT_REVOKED) {
      failf(data, "Cert verify failed: BADCERT_REVOKED");
      return CURLE_SSL_CACERT;
    }

    if(ret & MBEDTLS_X509_BADCERT_CN_MISMATCH)
      failf(data, "Cert verify failed: BADCERT_CN_MISMATCH");

    if(ret & MBEDTLS_X509_BADCERT_NOT_TRUSTED)
      failf(data, "Cert verify failed: BADCERT_NOT_TRUSTED");

    return CURLE_PEER_FAILED_VERIFICATION;
  }

  peercert = mbedtls_ssl_get_peer_cert(&connssl->ssl);

  if(peercert && data->set.verbose) {
    const size_t bufsize = 16384;
    char *buffer = malloc(bufsize);

    if(!buffer)
      return CURLE_OUT_OF_MEMORY;

    if(mbedtls_x509_crt_info(buffer, bufsize, "* ", peercert) > 0)
      infof(data, "Dumping cert info:\n%s\n", buffer);
    else infof(data, "Unable to dump certificate information.\n");

    free(buffer);
  }

  if(data->set.str[STRING_SSL_PINNEDPUBLICKEY]) {
    int size;
    CURLcode result;
    mbedtls_x509_crt *p;
    unsigned char pubkey[PUB_DER_MAX_BYTES];

    if(!peercert || !peercert->raw.p || !peercert->raw.len) {
      failf(data, "Failed due to missing peer certificate");
      return CURLE_SSL_PINNEDPUBKEYNOTMATCH;
    }

    p = calloc(1, sizeof(*p));

    if(!p)
      return CURLE_OUT_OF_MEMORY;

    mbedtls_x509_crt_init(p);

    
    if(mbedtls_x509_crt_parse_der(p, peercert->raw.p, peercert->raw.len)) {
      failf(data, "Failed copying peer certificate");
      mbedtls_x509_crt_free(p);
      free(p);
      return CURLE_SSL_PINNEDPUBKEYNOTMATCH;
    }

    size = mbedtls_pk_write_pubkey_der(&p->pk, pubkey, PUB_DER_MAX_BYTES);

    if(size <= 0) {
      failf(data, "Failed copying public key from peer certificate");
      mbedtls_x509_crt_free(p);
      free(p);
      return CURLE_SSL_PINNEDPUBKEYNOTMATCH;
    }

    
    result = Curl_pin_peer_pubkey(data, data->set.str[STRING_SSL_PINNEDPUBLICKEY], &pubkey[PUB_DER_MAX_BYTES - size], size);

    if(result) {
      mbedtls_x509_crt_free(p);
      free(p);
      return result;
    }

    mbedtls_x509_crt_free(p);
    free(p);
  }


  if(conn->bits.tls_enable_alpn) {
    next_protocol = mbedtls_ssl_get_alpn_protocol(&connssl->ssl);

    if(next_protocol) {
      infof(data, "ALPN, server accepted to use %s\n", next_protocol);

      if(!strncmp(next_protocol, NGHTTP2_PROTO_VERSION_ID, NGHTTP2_PROTO_VERSION_ID_LEN) && !next_protocol[NGHTTP2_PROTO_VERSION_ID_LEN]) {

        conn->negnpn = CURL_HTTP_VERSION_2;
      }
      else  if(!strncmp(next_protocol, ALPN_HTTP_1_1, ALPN_HTTP_1_1_LENGTH) && !next_protocol[ALPN_HTTP_1_1_LENGTH]) {


          conn->negnpn = CURL_HTTP_VERSION_1_1;
        }
    }
    else {
      infof(data, "ALPN, server did not agree to a protocol\n");
    }
  }


  connssl->connecting_state = ssl_connect_3;
  infof(data, "SSL connected\n");

  return CURLE_OK;
}

static CURLcode mbed_connect_step3(struct connectdata *conn, int sockindex)

{
  CURLcode retcode = CURLE_OK;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  struct SessionHandle *data = conn->data;
  void *old_ssl_sessionid = NULL;
  mbedtls_ssl_session *our_ssl_sessionid;
  int ret;

  DEBUGASSERT(ssl_connect_3 == connssl->connecting_state);

  our_ssl_sessionid = malloc(sizeof(mbedtls_ssl_session));
  if(!our_ssl_sessionid)
    return CURLE_OUT_OF_MEMORY;

  mbedtls_ssl_session_init(our_ssl_sessionid);

  ret = mbedtls_ssl_get_session(&connssl->ssl, our_ssl_sessionid);
  if(ret) {
    failf(data, "mbedtls_ssl_get_session returned -0x%x", -ret);
    return CURLE_SSL_CONNECT_ERROR;
  }

  
  if(!Curl_ssl_getsessionid(conn, &old_ssl_sessionid, NULL))
    Curl_ssl_delsessionid(conn, old_ssl_sessionid);

  retcode = Curl_ssl_addsessionid(conn, our_ssl_sessionid, 0);
  if(retcode) {
    free(our_ssl_sessionid);
    failf(data, "failed to store ssl session");
    return retcode;
  }

  connssl->connecting_state = ssl_connect_done;

  return CURLE_OK;
}

static ssize_t mbed_send(struct connectdata *conn, int sockindex, const void *mem, size_t len, CURLcode *curlcode)

{
  int ret = -1;

  ret = mbedtls_ssl_write(&conn->ssl[sockindex].ssl, (unsigned char *)mem, len);

  if(ret < 0) {
    *curlcode = (ret == MBEDTLS_ERR_SSL_WANT_WRITE) ? CURLE_AGAIN : CURLE_SEND_ERROR;
    ret = -1;
  }

  return ret;
}

void Curl_mbedtls_close_all(struct SessionHandle *data)
{
  (void)data;
}

void Curl_mbedtls_close(struct connectdata *conn, int sockindex)
{
  mbedtls_pk_free(&conn->ssl[sockindex].pk);
  mbedtls_x509_crt_free(&conn->ssl[sockindex].clicert);
  mbedtls_x509_crt_free(&conn->ssl[sockindex].cacert);
  mbedtls_x509_crl_free(&conn->ssl[sockindex].crl);
  mbedtls_ssl_config_free(&conn->ssl[sockindex].config);
  mbedtls_ssl_free(&conn->ssl[sockindex].ssl);
  mbedtls_ctr_drbg_free(&conn->ssl[sockindex].ctr_drbg);

  mbedtls_entropy_free(&conn->ssl[sockindex].entropy);

}

static ssize_t mbed_recv(struct connectdata *conn, int num, char *buf, size_t buffersize, CURLcode *curlcode)

{
  int ret = -1;
  ssize_t len = -1;

  memset(buf, 0, buffersize);
  ret = mbedtls_ssl_read(&conn->ssl[num].ssl, (unsigned char *)buf, buffersize);

  if(ret <= 0) {
    if(ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
      return 0;

    *curlcode = (ret == MBEDTLS_ERR_SSL_WANT_READ) ? CURLE_AGAIN : CURLE_RECV_ERROR;
    return -1;
  }

  len = ret;

  return len;
}

void Curl_mbedtls_session_free(void *ptr)
{
  mbedtls_ssl_session_free(ptr);
  free(ptr);
}

size_t Curl_mbedtls_version(char *buffer, size_t size)
{
  unsigned int version = mbedtls_version_get_number();
  return snprintf(buffer, size, "mbedTLS/%d.%d.%d", version>>24, (version>>16)&0xff, (version>>8)&0xff);
}

static CURLcode mbed_connect_common(struct connectdata *conn, int sockindex, bool nonblocking, bool *done)



{
  CURLcode retcode;
  struct SessionHandle *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  curl_socket_t sockfd = conn->sock[sockindex];
  long timeout_ms;
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
    retcode = mbed_connect_step1(conn, sockindex);
    if(retcode)
      return retcode;
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

      what = Curl_socket_ready(readfd, writefd, nonblocking ? 0 : timeout_ms);
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

    
    retcode = mbed_connect_step2(conn, sockindex);
    if(retcode || (nonblocking && (ssl_connect_2 == connssl->connecting_state || ssl_connect_2_reading == connssl->connecting_state || ssl_connect_2_writing == connssl->connecting_state)))


      return retcode;

  } 

  if(ssl_connect_3==connssl->connecting_state) {
    retcode = mbed_connect_step3(conn, sockindex);
    if(retcode)
      return retcode;
  }

  if(ssl_connect_done==connssl->connecting_state) {
    connssl->state = ssl_connection_complete;
    conn->recv[sockindex] = mbed_recv;
    conn->send[sockindex] = mbed_send;
    *done = TRUE;
  }
  else *done = FALSE;

  
  connssl->connecting_state = ssl_connect_1;

  return CURLE_OK;
}

CURLcode Curl_mbedtls_connect_nonblocking(struct connectdata *conn, int sockindex, bool *done)


{
  return mbed_connect_common(conn, sockindex, TRUE, done);
}


CURLcode Curl_mbedtls_connect(struct connectdata *conn, int sockindex)

{
  CURLcode retcode;
  bool done = FALSE;

  retcode = mbed_connect_common(conn, sockindex, FALSE, &done);
  if(retcode)
    return retcode;

  DEBUGASSERT(done);

  return CURLE_OK;
}


int Curl_mbedtls_init(void)
{
  return Curl_polarsslthreadlock_thread_setup();
}

void Curl_mbedtls_cleanup(void)
{
  (void)Curl_polarsslthreadlock_thread_cleanup();
}

int Curl_mbedtls_data_pending(const struct connectdata *conn, int sockindex)
{
  mbedtls_ssl_context *ssl = (mbedtls_ssl_context *)&conn->ssl[sockindex].ssl;
  return ssl->in_msglen != 0;
}


