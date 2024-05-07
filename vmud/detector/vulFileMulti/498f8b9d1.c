
























































































































































































struct ssl_backend_data {
  struct Curl_easy *logger; 
  
  SSL_CTX* ctx;
  SSL*     handle;
  X509*    server_cert;

  
  bool     keylog_done;

};





static void ossl_keylog_callback(const SSL *ssl, const char *line)
{
  (void)ssl;

  Curl_tls_keylog_write_line(line);
}


static void ossl_log_tls12_secret(const SSL *ssl, bool *keylog_done)
{
  const SSL_SESSION *session = SSL_get_session(ssl);
  unsigned char client_random[SSL3_RANDOM_SIZE];
  unsigned char master_key[SSL_MAX_MASTER_KEY_LENGTH];
  int master_key_length = 0;

  if(!session || *keylog_done)
    return;



  
  SSL_get_client_random(ssl, client_random, SSL3_RANDOM_SIZE);
  master_key_length = (int)
    SSL_SESSION_get_master_key(session, master_key, SSL_MAX_MASTER_KEY_LENGTH);

  if(ssl->s3 && session->master_key_length > 0) {
    master_key_length = session->master_key_length;
    memcpy(master_key, session->master_key, session->master_key_length);
    memcpy(client_random, ssl->s3->client_random, SSL3_RANDOM_SIZE);
  }


  
  if(master_key_length <= 0)
    return;

  *keylog_done = true;
  Curl_tls_keylog_write("CLIENT_RANDOM", client_random, master_key, master_key_length);
}


static const char *SSL_ERROR_to_str(int err)
{
  switch(err) {
  case SSL_ERROR_NONE:
    return "SSL_ERROR_NONE";
  case SSL_ERROR_SSL:
    return "SSL_ERROR_SSL";
  case SSL_ERROR_WANT_READ:
    return "SSL_ERROR_WANT_READ";
  case SSL_ERROR_WANT_WRITE:
    return "SSL_ERROR_WANT_WRITE";
  case SSL_ERROR_WANT_X509_LOOKUP:
    return "SSL_ERROR_WANT_X509_LOOKUP";
  case SSL_ERROR_SYSCALL:
    return "SSL_ERROR_SYSCALL";
  case SSL_ERROR_ZERO_RETURN:
    return "SSL_ERROR_ZERO_RETURN";
  case SSL_ERROR_WANT_CONNECT:
    return "SSL_ERROR_WANT_CONNECT";
  case SSL_ERROR_WANT_ACCEPT:
    return "SSL_ERROR_WANT_ACCEPT";

  case SSL_ERROR_WANT_ASYNC:
    return "SSL_ERROR_WANT_ASYNC";


  case SSL_ERROR_WANT_ASYNC_JOB:
    return "SSL_ERROR_WANT_ASYNC_JOB";


  case SSL_ERROR_WANT_EARLY:
    return "SSL_ERROR_WANT_EARLY";

  default:
    return "SSL_ERROR unknown";
  }
}


static char *ossl_strerror(unsigned long error, char *buf, size_t size)
{
  if(size)
    *buf = '\0';


  ERR_error_string_n((uint32_t)error, buf, size);

  ERR_error_string_n(error, buf, size);


  if(size > 1 && !*buf) {
    strncpy(buf, (error ? "Unknown error" : "No error"), size);
    buf[size - 1] = '\0';
  }

  return buf;
}


static int ossl_get_ssl_data_index(void)
{
  static int ssl_ex_data_data_index = -1;
  if(ssl_ex_data_data_index < 0) {
    ssl_ex_data_data_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
  }
  return ssl_ex_data_data_index;
}


static int ossl_get_ssl_conn_index(void)
{
  static int ssl_ex_data_conn_index = -1;
  if(ssl_ex_data_conn_index < 0) {
    ssl_ex_data_conn_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
  }
  return ssl_ex_data_conn_index;
}


static int ossl_get_ssl_sockindex_index(void)
{
  static int ssl_ex_data_sockindex_index = -1;
  if(ssl_ex_data_sockindex_index < 0) {
    ssl_ex_data_sockindex_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
  }
  return ssl_ex_data_sockindex_index;
}

static int passwd_callback(char *buf, int num, int encrypting, void *global_passwd)
{
  DEBUGASSERT(0 == encrypting);

  if(!encrypting) {
    int klen = curlx_uztosi(strlen((char *)global_passwd));
    if(num > klen) {
      memcpy(buf, global_passwd, klen + 1);
      return klen;
    }
  }
  return 0;
}


static bool rand_enough(void)
{
  return (0 != RAND_status()) ? TRUE : FALSE;
}

static CURLcode ossl_seed(struct Curl_easy *data)
{
  
  static bool ssl_seeded = FALSE;
  char fname[256];

  if(ssl_seeded)
    return CURLE_OK;

  if(rand_enough()) {
    
    ssl_seeded = TRUE;
    return CURLE_OK;
  }


  
  if(data->set.str[STRING_SSL_RANDOM_FILE])


  {
    
    RAND_load_file((data->set.str[STRING_SSL_RANDOM_FILE]? data->set.str[STRING_SSL_RANDOM_FILE]:
                    RANDOM_FILE), RAND_LOAD_LENGTH);
    if(rand_enough())
      return CURLE_OK;
  }


  
  

  
  if(data->set.str[STRING_SSL_EGDSOCKET])


  {
    
    int ret = RAND_egd(data->set.str[STRING_SSL_EGDSOCKET]? data->set.str[STRING_SSL_EGDSOCKET]:EGD_SOCKET);
    if(-1 != ret) {
      if(rand_enough())
        return CURLE_OK;
    }
  }


  
  do {
    unsigned char randb[64];
    size_t len = sizeof(randb);
    size_t i, i_max;
    for(i = 0, i_max = len / sizeof(struct curltime); i < i_max; ++i) {
      struct curltime tv = Curl_now();
      Curl_wait_ms(1);
      tv.tv_sec *= i + 1;
      tv.tv_usec *= (unsigned int)i + 2;
      tv.tv_sec ^= ((Curl_now().tv_sec + Curl_now().tv_usec) * (i + 3)) << 8;
      tv.tv_usec ^= (unsigned int) ((Curl_now().tv_sec + Curl_now().tv_usec) * (i + 4)) << 16;

      memcpy(&randb[i * sizeof(struct curltime)], &tv, sizeof(struct curltime));
    }
    RAND_add(randb, (int)len, (double)len/2);
  } while(!rand_enough());

  
  fname[0] = 0; 
  RAND_file_name(fname, sizeof(fname));
  if(fname[0]) {
    
    RAND_load_file(fname, RAND_LOAD_LENGTH);
    if(rand_enough())
      return CURLE_OK;
  }

  infof(data, "libcurl is now using a weak random seed!\n");
  return (rand_enough() ? CURLE_OK :
    CURLE_SSL_CONNECT_ERROR );
}







static int do_file_type(const char *type)
{
  if(!type || !type[0])
    return SSL_FILETYPE_PEM;
  if(strcasecompare(type, "PEM"))
    return SSL_FILETYPE_PEM;
  if(strcasecompare(type, "DER"))
    return SSL_FILETYPE_ASN1;
  if(strcasecompare(type, "ENG"))
    return SSL_FILETYPE_ENGINE;
  if(strcasecompare(type, "P12"))
    return SSL_FILETYPE_PKCS12;
  return -1;
}



static int ssl_ui_reader(UI *ui, UI_STRING *uis)
{
  const char *password;
  switch(UI_get_string_type(uis)) {
  case UIT_PROMPT:
  case UIT_VERIFY:
    password = (const char *)UI_get0_user_data(ui);
    if(password && (UI_get_input_flags(uis) & UI_INPUT_FLAG_DEFAULT_PWD)) {
      UI_set_result(ui, uis, password);
      return 1;
    }
  default:
    break;
  }
  return (UI_method_get_reader(UI_OpenSSL()))(ui, uis);
}


static int ssl_ui_writer(UI *ui, UI_STRING *uis)
{
  switch(UI_get_string_type(uis)) {
  case UIT_PROMPT:
  case UIT_VERIFY:
    if(UI_get0_user_data(ui) && (UI_get_input_flags(uis) & UI_INPUT_FLAG_DEFAULT_PWD)) {
      return 1;
    }
  default:
    break;
  }
  return (UI_method_get_writer(UI_OpenSSL()))(ui, uis);
}


static bool is_pkcs11_uri(const char *string)
{
  return (string && strncasecompare(string, "pkcs11:", 7));
}



static CURLcode ossl_set_engine(struct Curl_easy *data, const char *engine);

static int SSL_CTX_use_certificate_bio(SSL_CTX *ctx, BIO *in, int type, const char *key_passwd)

{
  int ret = 0;
  X509 *x = NULL;

  if(type == SSL_FILETYPE_ASN1) {
    
    x = d2i_X509_bio(in, NULL);
  }
  else if(type == SSL_FILETYPE_PEM) {
    
    x = PEM_read_bio_X509(in, NULL, passwd_callback, (void *)key_passwd);
  }
  else {
    ret = 0;
    goto end;
  }

  if(x == NULL) {
    ret = 0;
    goto end;
  }

  ret = SSL_CTX_use_certificate(ctx, x);
 end:
  X509_free(x);
  return ret;
}

static int SSL_CTX_use_PrivateKey_bio(SSL_CTX *ctx, BIO* in, int type, const char *key_passwd)

{
  int ret = 0;
  EVP_PKEY *pkey = NULL;

  if(type == SSL_FILETYPE_PEM)
    pkey = PEM_read_bio_PrivateKey(in, NULL, passwd_callback, (void *)key_passwd);
  else if(type == SSL_FILETYPE_ASN1)
    pkey = d2i_PrivateKey_bio(in, NULL);
  else {
    ret = 0;
    goto end;
  }
  if(pkey == NULL) {
    ret = 0;
    goto end;
  }
  ret = SSL_CTX_use_PrivateKey(ctx, pkey);
  EVP_PKEY_free(pkey);
  end:
  return ret;
}

static int SSL_CTX_use_certificate_chain_bio(SSL_CTX *ctx, BIO* in, const char *key_passwd)

{



  int ret = 0;
  X509 *x = NULL;
  void *passwd_callback_userdata = (void *)key_passwd;

  ERR_clear_error();

  x = PEM_read_bio_X509_AUX(in, NULL, passwd_callback, (void *)key_passwd);

  if(x == NULL) {
    ret = 0;
    goto end;
  }

  ret = SSL_CTX_use_certificate(ctx, x);

  if(ERR_peek_error() != 0)
      ret = 0;

  if(ret) {
    X509 *ca;
    unsigned long err;

    if(!SSL_CTX_clear_chain_certs(ctx)) {
      ret = 0;
      goto end;
    }

    while((ca = PEM_read_bio_X509(in, NULL, passwd_callback, passwd_callback_userdata))
          != NULL) {

      if(!SSL_CTX_add0_chain_cert(ctx, ca)) {
        X509_free(ca);
        ret = 0;
        goto end;
      }
    }

    err = ERR_peek_last_error();
    if((ERR_GET_LIB(err) == ERR_LIB_PEM) && (ERR_GET_REASON(err) == PEM_R_NO_START_LINE))
      ERR_clear_error();
    else ret = 0;
  }

 end:
  X509_free(x);
  return ret;

  (void)ctx; 
  (void)in; 
  (void)key_passwd; 
  return 0;

}

static int cert_stuff(struct Curl_easy *data, SSL_CTX* ctx, char *cert_file, BIO *cert_bio, const char *cert_type, char *key_file, BIO* key_bio, const char *key_type, char *key_passwd)








{
  char error_buffer[256];
  bool check_privkey = TRUE;

  int file_type = do_file_type(cert_type);

  if(cert_file || cert_bio || (file_type == SSL_FILETYPE_ENGINE)) {
    SSL *ssl;
    X509 *x509;
    int cert_done = 0;
    int cert_use_result;

    if(key_passwd) {
      
      SSL_CTX_set_default_passwd_cb_userdata(ctx, key_passwd);
      
      SSL_CTX_set_default_passwd_cb(ctx, passwd_callback);
    }


    switch(file_type) {
    case SSL_FILETYPE_PEM:
      
      cert_use_result = cert_bio ? SSL_CTX_use_certificate_chain_bio(ctx, cert_bio, key_passwd) :
          SSL_CTX_use_certificate_chain_file(ctx, cert_file);
      if(cert_use_result != 1) {
        failf(data, "could not load PEM client certificate, " OSSL_PACKAGE " error %s, " "(no key found, wrong pass phrase, or wrong file format?)", ossl_strerror(ERR_get_error(), error_buffer, sizeof(error_buffer)) );




        return 0;
      }
      break;

    case SSL_FILETYPE_ASN1:
      

      cert_use_result = cert_bio ? SSL_CTX_use_certificate_bio(ctx, cert_bio, file_type, key_passwd) :

          SSL_CTX_use_certificate_file(ctx, cert_file, file_type);
      if(cert_use_result != 1) {
        failf(data, "could not load ASN1 client certificate, " OSSL_PACKAGE " error %s, " "(no key found, wrong pass phrase, or wrong file format?)", ossl_strerror(ERR_get_error(), error_buffer, sizeof(error_buffer)) );




        return 0;
      }
      break;
    case SSL_FILETYPE_ENGINE:

      {
        
        if(!data->state.engine) {
          if(is_pkcs11_uri(cert_file)) {
            if(ossl_set_engine(data, "pkcs11") != CURLE_OK) {
              return 0;
            }
          }
        }

        if(data->state.engine) {
          const char *cmd_name = "LOAD_CERT_CTRL";
          struct {
            const char *cert_id;
            X509 *cert;
          } params;

          params.cert_id = cert_file;
          params.cert = NULL;

          
          if(!ENGINE_ctrl(data->state.engine, ENGINE_CTRL_GET_CMD_FROM_NAME, 0, (void *)cmd_name, NULL)) {
            failf(data, "ssl engine does not support loading certificates");
            return 0;
          }

          
          if(!ENGINE_ctrl_cmd(data->state.engine, cmd_name, 0, &params, NULL, 1)) {
            failf(data, "ssl engine cannot load client cert with id" " '%s' [%s]", cert_file, ossl_strerror(ERR_get_error(), error_buffer, sizeof(error_buffer)));


            return 0;
          }

          if(!params.cert) {
            failf(data, "ssl engine didn't initialized the certificate " "properly.");
            return 0;
          }

          if(SSL_CTX_use_certificate(ctx, params.cert) != 1) {
            failf(data, "unable to set client certificate");
            X509_free(params.cert);
            return 0;
          }
          X509_free(params.cert); 
        }
        else {
          failf(data, "crypto engine not set, can't load certificate");
          return 0;
        }
      }
      break;

      failf(data, "file type ENG for certificate not implemented");
      return 0;


    case SSL_FILETYPE_PKCS12:
    {
      BIO *fp = NULL;
      PKCS12 *p12 = NULL;
      EVP_PKEY *pri;
      STACK_OF(X509) *ca = NULL;
      if(!cert_bio) {
        fp = BIO_new(BIO_s_file());
        if(fp == NULL) {
          failf(data, "BIO_new return NULL, " OSSL_PACKAGE " error %s", ossl_strerror(ERR_get_error(), error_buffer, sizeof(error_buffer)) );



          return 0;
        }

        if(BIO_read_filename(fp, cert_file) <= 0) {
          failf(data, "could not open PKCS12 file '%s'", cert_file);
          BIO_free(fp);
          return 0;
        }
      }

      p12 = d2i_PKCS12_bio(cert_bio ? cert_bio : fp, NULL);
      if(fp)
        BIO_free(fp);

      if(!p12) {
        failf(data, "error reading PKCS12 file '%s'", cert_bio ? "(memory blob)" : cert_file);
        return 0;
      }

      PKCS12_PBE_add();

      if(!PKCS12_parse(p12, key_passwd, &pri, &x509, &ca)) {
        failf(data, "could not parse PKCS12 file, check password, " OSSL_PACKAGE " error %s", ossl_strerror(ERR_get_error(), error_buffer, sizeof(error_buffer)) );



        PKCS12_free(p12);
        return 0;
      }

      PKCS12_free(p12);

      if(SSL_CTX_use_certificate(ctx, x509) != 1) {
        failf(data, "could not load PKCS12 client certificate, " OSSL_PACKAGE " error %s", ossl_strerror(ERR_get_error(), error_buffer, sizeof(error_buffer)) );



        goto fail;
      }

      if(SSL_CTX_use_PrivateKey(ctx, pri) != 1) {
        failf(data, "unable to use private key from PKCS12 file '%s'", cert_file);
        goto fail;
      }

      if(!SSL_CTX_check_private_key (ctx)) {
        failf(data, "private key from PKCS12 file '%s' " "does not match certificate in same file", cert_file);
        goto fail;
      }
      
      if(ca) {
        while(sk_X509_num(ca)) {
          
          X509 *x = sk_X509_pop(ca);
          if(!SSL_CTX_add_client_CA(ctx, x)) {
            X509_free(x);
            failf(data, "cannot add certificate to client CA list");
            goto fail;
          }
          if(!SSL_CTX_add_extra_chain_cert(ctx, x)) {
            X509_free(x);
            failf(data, "cannot add certificate to certificate chain");
            goto fail;
          }
        }
      }

      cert_done = 1;
  fail:
      EVP_PKEY_free(pri);
      X509_free(x509);

      sk_X509_pop_free(ca, Curl_amiga_X509_free);

      sk_X509_pop_free(ca, X509_free);

      if(!cert_done)
        return 0; 
      break;
    }
    default:
      failf(data, "not supported file type '%s' for certificate", cert_type);
      return 0;
    }

    if((!key_file) && (!key_bio)) {
      key_file = cert_file;
      key_bio = cert_bio;
    }
    else file_type = do_file_type(key_type);

    switch(file_type) {
    case SSL_FILETYPE_PEM:
      if(cert_done)
        break;
      
    case SSL_FILETYPE_ASN1:
      cert_use_result = key_bio ? SSL_CTX_use_PrivateKey_bio(ctx, key_bio, file_type, key_passwd) :
        SSL_CTX_use_PrivateKey_file(ctx, key_file, file_type);
      if(cert_use_result != 1) {
        failf(data, "unable to set private key file: '%s' type %s", key_file?key_file:"(memory blob)", key_type?key_type:"PEM");
        return 0;
      }
      break;
    case SSL_FILETYPE_ENGINE:

      {                         
        EVP_PKEY *priv_key = NULL;

        
        if(!data->state.engine) {
          if(is_pkcs11_uri(key_file)) {
            if(ossl_set_engine(data, "pkcs11") != CURLE_OK) {
              return 0;
            }
          }
        }

        if(data->state.engine) {
          UI_METHOD *ui_method = UI_create_method((char *)"curl user interface");
          if(!ui_method) {
            failf(data, "unable do create " OSSL_PACKAGE " user-interface method");
            return 0;
          }
          UI_method_set_opener(ui_method, UI_method_get_opener(UI_OpenSSL()));
          UI_method_set_closer(ui_method, UI_method_get_closer(UI_OpenSSL()));
          UI_method_set_reader(ui_method, ssl_ui_reader);
          UI_method_set_writer(ui_method, ssl_ui_writer);
          
          priv_key = (EVP_PKEY *)
            ENGINE_load_private_key(data->state.engine, key_file, ui_method, key_passwd);

          UI_destroy_method(ui_method);
          if(!priv_key) {
            failf(data, "failed to load private key from crypto engine");
            return 0;
          }
          if(SSL_CTX_use_PrivateKey(ctx, priv_key) != 1) {
            failf(data, "unable to set private key");
            EVP_PKEY_free(priv_key);
            return 0;
          }
          EVP_PKEY_free(priv_key);  
        }
        else {
          failf(data, "crypto engine not set, can't load private key");
          return 0;
        }
      }
      break;

      failf(data, "file type ENG for private key not supported");
      return 0;

    case SSL_FILETYPE_PKCS12:
      if(!cert_done) {
        failf(data, "file type P12 for private key not supported");
        return 0;
      }
      break;
    default:
      failf(data, "not supported file type for private key");
      return 0;
    }

    ssl = SSL_new(ctx);
    if(!ssl) {
      failf(data, "unable to create an SSL structure");
      return 0;
    }

    x509 = SSL_get_certificate(ssl);

    
    if(x509) {
      EVP_PKEY *pktmp = X509_get_pubkey(x509);
      EVP_PKEY_copy_parameters(pktmp, SSL_get_privatekey(ssl));
      EVP_PKEY_free(pktmp);
    }


    {
      
      EVP_PKEY *priv_key = SSL_get_privatekey(ssl);
      int pktype;

      pktype = EVP_PKEY_id(priv_key);

      pktype = priv_key->type;

      if(pktype == EVP_PKEY_RSA) {
        RSA *rsa = EVP_PKEY_get1_RSA(priv_key);
        if(RSA_flags(rsa) & RSA_METHOD_FLAG_NO_CHECK)
          check_privkey = FALSE;
        RSA_free(rsa); 
      }
    }


    SSL_free(ssl);

    

    if(check_privkey == TRUE) {
      
      if(!SSL_CTX_check_private_key(ctx)) {
        failf(data, "Private key does not match the certificate public key");
        return 0;
      }
    }
  }
  return 1;
}


static int x509_name_oneline(X509_NAME *a, char *buf, size_t size)
{
  BIO *bio_out = BIO_new(BIO_s_mem());
  BUF_MEM *biomem;
  int rc;

  if(!bio_out)
    return 1; 

  rc = X509_NAME_print_ex(bio_out, a, 0, XN_FLAG_SEP_SPLUS_SPC);
  BIO_get_mem_ptr(bio_out, &biomem);

  if((size_t)biomem->length < size)
    size = biomem->length;
  else size--;

  memcpy(buf, biomem->data, size);
  buf[size] = 0;

  BIO_free(bio_out);

  return !rc;
}


static int ossl_init(void)
{

  const uint64_t flags =   OPENSSL_INIT_ENGINE_ALL_BUILTIN |   OPENSSL_INIT_NO_LOAD_CONFIG |  OPENSSL_INIT_LOAD_CONFIG |  0;









  OPENSSL_init_ssl(flags, NULL);

  OPENSSL_load_builtin_modules();


  ENGINE_load_builtin_engines();








  CONF_modules_load_file(NULL, NULL, CONF_MFLAGS_DEFAULT_SECTION| CONF_MFLAGS_IGNORE_MISSING_FILE);



  
  SSL_load_error_strings();

  
  if(!SSLeay_add_ssl_algorithms())
    return 0;

  OpenSSL_add_all_algorithms();


  Curl_tls_keylog_open();

  
  if(ossl_get_ssl_data_index() < 0 || ossl_get_ssl_conn_index() < 0 || ossl_get_ssl_sockindex_index() < 0)
    return 0;

  return 1;
}


static void ossl_cleanup(void)
{

  

  
  EVP_cleanup();


  
  ENGINE_cleanup();


  
  ERR_free_strings();

  

  ERR_remove_thread_state(NULL);

  ERR_remove_state(0);


  
  CONF_modules_free();


  SSL_COMP_free_compression_methods();



  Curl_tls_keylog_close();
}


static int ossl_check_cxn(struct connectdata *conn)
{
  

  char buf;
  ssize_t nread;
  nread = recv((RECV_TYPE_ARG1)conn->sock[FIRSTSOCKET], (RECV_TYPE_ARG2)&buf, (RECV_TYPE_ARG3)1, (RECV_TYPE_ARG4)MSG_PEEK);
  if(nread == 0)
    return 0; 
  if(nread == 1)
    return 1; 
  else if(nread == -1) {
      int err = SOCKERRNO;
      if(err == EINPROGRESS ||  err == EAGAIN ||  err == EWOULDBLOCK)



        return 1; 
      if(err == ECONNRESET ||  err == ECONNABORTED ||   err == ENETDOWN ||   err == ENETRESET ||   err == ESHUTDOWN ||   err == ETIMEDOUT ||  err == ENOTCONN)















        return 0; 
  }

  return -1; 
}


static CURLcode ossl_set_engine(struct Curl_easy *data, const char *engine)
{

  ENGINE *e;


  e = ENGINE_by_id(engine);

  
  for(e = ENGINE_get_first(); e; e = ENGINE_get_next(e)) {
    const char *e_id = ENGINE_get_id(e);
    if(!strcmp(engine, e_id))
      break;
  }


  if(!e) {
    failf(data, "SSL Engine '%s' not found", engine);
    return CURLE_SSL_ENGINE_NOTFOUND;
  }

  if(data->state.engine) {
    ENGINE_finish(data->state.engine);
    ENGINE_free(data->state.engine);
    data->state.engine = NULL;
  }
  if(!ENGINE_init(e)) {
    char buf[256];

    ENGINE_free(e);
    failf(data, "Failed to initialise SSL Engine '%s': %s", engine, ossl_strerror(ERR_get_error(), buf, sizeof(buf)));
    return CURLE_SSL_ENGINE_INITFAILED;
  }
  data->state.engine = e;
  return CURLE_OK;

  (void)engine;
  failf(data, "SSL Engine not supported");
  return CURLE_SSL_ENGINE_NOTFOUND;

}


static CURLcode ossl_set_engine_default(struct Curl_easy *data)
{

  if(data->state.engine) {
    if(ENGINE_set_default(data->state.engine, ENGINE_METHOD_ALL) > 0) {
      infof(data, "set default crypto engine '%s'\n", ENGINE_get_id(data->state.engine));
    }
    else {
      failf(data, "set default crypto engine '%s' failed", ENGINE_get_id(data->state.engine));
      return CURLE_SSL_ENGINE_SETFAILED;
    }
  }

  (void) data;

  return CURLE_OK;
}


static struct curl_slist *ossl_engines_list(struct Curl_easy *data)
{
  struct curl_slist *list = NULL;

  struct curl_slist *beg;
  ENGINE *e;

  for(e = ENGINE_get_first(); e; e = ENGINE_get_next(e)) {
    beg = curl_slist_append(list, ENGINE_get_id(e));
    if(!beg) {
      curl_slist_free_all(list);
      return NULL;
    }
    list = beg;
  }

  (void) data;
  return list;
}



static void ossl_closeone(struct Curl_easy *data, struct connectdata *conn, struct ssl_connect_data *connssl)

{
  struct ssl_backend_data *backend = connssl->backend;
  if(backend->handle) {
    set_logger(conn, data);
    (void)SSL_shutdown(backend->handle);
    SSL_set_connect_state(backend->handle);

    SSL_free(backend->handle);
    backend->handle = NULL;
  }
  if(backend->ctx) {
    SSL_CTX_free(backend->ctx);
    backend->ctx = NULL;
  }
}


static void ossl_close(struct Curl_easy *data, struct connectdata *conn, int sockindex)
{
  ossl_closeone(data, conn, &conn->ssl[sockindex]);

  ossl_closeone(data, conn, &conn->proxy_ssl[sockindex]);

}


static int ossl_shutdown(struct Curl_easy *data, struct connectdata *conn, int sockindex)
{
  int retval = 0;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  char buf[256]; 
  unsigned long sslerror;
  ssize_t nread;
  int buffsize;
  int err;
  bool done = FALSE;
  struct ssl_backend_data *backend = connssl->backend;


  

  if(data->set.ftp_ccc == CURLFTPSSL_CCC_ACTIVE)
      (void)SSL_shutdown(backend->handle);


  if(backend->handle) {
    buffsize = (int)sizeof(buf);
    while(!done) {
      int what = SOCKET_READABLE(conn->sock[sockindex], SSL_SHUTDOWN_TIMEOUT);
      if(what > 0) {
        ERR_clear_error();

        
        nread = (ssize_t)SSL_read(backend->handle, buf, buffsize);
        err = SSL_get_error(backend->handle, (int)nread);

        switch(err) {
        case SSL_ERROR_NONE: 
        case SSL_ERROR_ZERO_RETURN: 
          
          done = TRUE;
          break;
        case SSL_ERROR_WANT_READ:
          
          infof(data, "SSL_ERROR_WANT_READ\n");
          break;
        case SSL_ERROR_WANT_WRITE:
          
          infof(data, "SSL_ERROR_WANT_WRITE\n");
          done = TRUE;
          break;
        default:
          
          sslerror = ERR_get_error();
          failf(data, OSSL_PACKAGE " SSL_read on shutdown: %s, errno %d", (sslerror ? ossl_strerror(sslerror, buf, sizeof(buf)) :

                 SSL_ERROR_to_str(err)), SOCKERRNO);
          done = TRUE;
          break;
        }
      }
      else if(0 == what) {
        
        failf(data, "SSL shutdown timeout");
        done = TRUE;
      }
      else {
        
        failf(data, "select/poll on SSL socket, errno: %d", SOCKERRNO);
        retval = -1;
        done = TRUE;
      }
    } 

    if(data->set.verbose) {

      switch(SSL_get_shutdown(backend->handle)) {
      case SSL_SENT_SHUTDOWN:
        infof(data, "SSL_get_shutdown() returned SSL_SENT_SHUTDOWN\n");
        break;
      case SSL_RECEIVED_SHUTDOWN:
        infof(data, "SSL_get_shutdown() returned SSL_RECEIVED_SHUTDOWN\n");
        break;
      case SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN:
        infof(data, "SSL_get_shutdown() returned SSL_SENT_SHUTDOWN|" "SSL_RECEIVED__SHUTDOWN\n");
        break;
      }

    }

    SSL_free(backend->handle);
    backend->handle = NULL;
  }
  return retval;
}

static void ossl_session_free(void *ptr)
{
  
  SSL_SESSION_free(ptr);
}


static void ossl_close_all(struct Curl_easy *data)
{

  if(data->state.engine) {
    ENGINE_finish(data->state.engine);
    ENGINE_free(data->state.engine);
    data->state.engine = NULL;
  }

  (void)data;


  
  ERR_remove_thread_state(NULL);

}




static bool subj_alt_hostcheck(struct Curl_easy *data, const char *match_pattern, const char *hostname, const char *dispname)


{
  bool res = FALSE;

  
  char *match_pattern2 = strdup(match_pattern);

  if(match_pattern2) {
    if(Curl_convert_from_network(data, match_pattern2, strlen(match_pattern2)) == CURLE_OK) {
      if(Curl_cert_hostcheck(match_pattern2, hostname)) {
        res = TRUE;
        infof(data, " subjectAltName: host \"%s\" matched cert's \"%s\"\n", dispname, match_pattern2);

      }
    }
    free(match_pattern2);
  }
  else {
    failf(data, "SSL: out of memory when allocating temporary for subjectAltName");
  }
  return res;
}

{

  (void)dispname;
  (void)data;

  if(Curl_cert_hostcheck(match_pattern, hostname)) {
    infof(data, " subjectAltName: host \"%s\" matched cert's \"%s\"\n", dispname, match_pattern);
    return TRUE;
  }
  return FALSE;
}




static CURLcode verifyhost(struct Curl_easy *data, struct connectdata *conn, X509 *server_cert)
{
  bool matched = FALSE;
  int target = GEN_DNS; 
  size_t addrlen = 0;
  STACK_OF(GENERAL_NAME) *altnames;

  struct in6_addr addr;

  struct in_addr addr;

  CURLcode result = CURLE_OK;
  bool dNSName = FALSE; 
  bool iPAddress = FALSE; 
  const char * const hostname = SSL_HOST_NAME();
  const char * const dispname = SSL_HOST_DISPNAME();


  if(conn->bits.ipv6_ip && Curl_inet_pton(AF_INET6, hostname, &addr)) {
    target = GEN_IPADD;
    addrlen = sizeof(struct in6_addr);
  }
  else  if(Curl_inet_pton(AF_INET, hostname, &addr)) {

      target = GEN_IPADD;
      addrlen = sizeof(struct in_addr);
    }

  
  altnames = X509_get_ext_d2i(server_cert, NID_subject_alt_name, NULL, NULL);

  if(altnames) {

    size_t numalts;
    size_t i;

    int numalts;
    int i;

    bool dnsmatched = FALSE;
    bool ipmatched = FALSE;

    
    numalts = sk_GENERAL_NAME_num(altnames);

    
    for(i = 0; (i < numalts) && !dnsmatched; i++) {
      
      const GENERAL_NAME *check = sk_GENERAL_NAME_value(altnames, i);

      if(check->type == GEN_DNS)
        dNSName = TRUE;
      else if(check->type == GEN_IPADD)
        iPAddress = TRUE;

      
      if(check->type == target) {
        
        const char *altptr = (char *)ASN1_STRING_get0_data(check->d.ia5);
        size_t altlen = (size_t) ASN1_STRING_length(check->d.ia5);

        switch(target) {
        case GEN_DNS: 
          
          if((altlen == strlen(altptr)) &&  subj_alt_hostcheck(data, altptr, hostname, dispname)) {

            dnsmatched = TRUE;
          }
          break;

        case GEN_IPADD: 
          
          if((altlen == addrlen) && !memcmp(altptr, &addr, altlen)) {
            ipmatched = TRUE;
            infof(data, " subjectAltName: host \"%s\" matched cert's IP address!\n", dispname);

          }
          break;
        }
      }
    }
    GENERAL_NAMES_free(altnames);

    if(dnsmatched || ipmatched)
      matched = TRUE;
  }

  if(matched)
    
    ;
  else if(dNSName || iPAddress) {
    infof(data, " subjectAltName does not match %s\n", dispname);
    failf(data, "SSL: no alternative certificate subject name matches " "target host name '%s'", dispname);
    result = CURLE_PEER_FAILED_VERIFICATION;
  }
  else {
    
    int j, i = -1;

    

    unsigned char *nulstr = (unsigned char *)"";
    unsigned char *peer_CN = nulstr;

    X509_NAME *name = X509_get_subject_name(server_cert);
    if(name)
      while((j = X509_NAME_get_index_by_NID(name, NID_commonName, i)) >= 0)
        i = j;

    

    if(i >= 0) {
      ASN1_STRING *tmp = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(name, i));

      
      if(tmp) {
        if(ASN1_STRING_type(tmp) == V_ASN1_UTF8STRING) {
          j = ASN1_STRING_length(tmp);
          if(j >= 0) {
            peer_CN = OPENSSL_malloc(j + 1);
            if(peer_CN) {
              memcpy(peer_CN, ASN1_STRING_get0_data(tmp), j);
              peer_CN[j] = '\0';
            }
          }
        }
        else  j = ASN1_STRING_to_UTF8(&peer_CN, tmp);

        if(peer_CN && (curlx_uztosi(strlen((char *)peer_CN)) != j)) {
          
          failf(data, "SSL: illegal cert name field");
          result = CURLE_PEER_FAILED_VERIFICATION;
        }
      }
    }

    if(peer_CN == nulstr)
       peer_CN = NULL;
    else {
      
      CURLcode rc = Curl_convert_from_utf8(data, (char *)peer_CN, strlen((char *)peer_CN));
      
      if(rc) {
        OPENSSL_free(peer_CN);
        return rc;
      }
    }

    if(result)
      
      ;
    else if(!peer_CN) {
      failf(data, "SSL: unable to obtain common name from peer certificate");
      result = CURLE_PEER_FAILED_VERIFICATION;
    }
    else if(!Curl_cert_hostcheck((const char *)peer_CN, hostname)) {
      failf(data, "SSL: certificate subject name '%s' does not match " "target host name '%s'", peer_CN, dispname);
      result = CURLE_PEER_FAILED_VERIFICATION;
    }
    else {
      infof(data, " common name: %s (matched)\n", peer_CN);
    }
    if(peer_CN)
      OPENSSL_free(peer_CN);
  }

  return result;
}


static CURLcode verifystatus(struct Curl_easy *data, struct ssl_connect_data *connssl)
{
  int i, ocsp_status;
  unsigned char *status;
  const unsigned char *p;
  CURLcode result = CURLE_OK;
  OCSP_RESPONSE *rsp = NULL;
  OCSP_BASICRESP *br = NULL;
  X509_STORE     *st = NULL;
  STACK_OF(X509) *ch = NULL;
  struct ssl_backend_data *backend = connssl->backend;
  X509 *cert;
  OCSP_CERTID *id = NULL;
  int cert_status, crl_reason;
  ASN1_GENERALIZEDTIME *rev, *thisupd, *nextupd;
  int ret;

  long len = SSL_get_tlsext_status_ocsp_resp(backend->handle, &status);

  if(!status) {
    failf(data, "No OCSP response received");
    result = CURLE_SSL_INVALIDCERTSTATUS;
    goto end;
  }
  p = status;
  rsp = d2i_OCSP_RESPONSE(NULL, &p, len);
  if(!rsp) {
    failf(data, "Invalid OCSP response");
    result = CURLE_SSL_INVALIDCERTSTATUS;
    goto end;
  }

  ocsp_status = OCSP_response_status(rsp);
  if(ocsp_status != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
    failf(data, "Invalid OCSP response status: %s (%d)", OCSP_response_status_str(ocsp_status), ocsp_status);
    result = CURLE_SSL_INVALIDCERTSTATUS;
    goto end;
  }

  br = OCSP_response_get1_basic(rsp);
  if(!br) {
    failf(data, "Invalid OCSP response");
    result = CURLE_SSL_INVALIDCERTSTATUS;
    goto end;
  }

  ch = SSL_get_peer_cert_chain(backend->handle);
  st = SSL_CTX_get_cert_store(backend->ctx);



  

  
  if(sk_X509_num(ch) >= 2 && sk_X509_num(br->certs) >= 1) {
    X509 *responder = sk_X509_value(br->certs, sk_X509_num(br->certs) - 1);

    
    for(i = 0; i < sk_X509_num(ch); i++) {
      X509 *issuer = sk_X509_value(ch, i);
      if(X509_check_issued(issuer, responder) == X509_V_OK) {
        if(!OCSP_basic_add1_cert(br, issuer)) {
          failf(data, "Could not add issuer cert to OCSP response");
          result = CURLE_SSL_INVALIDCERTSTATUS;
          goto end;
        }
      }
    }
  }


  if(OCSP_basic_verify(br, ch, st, 0) <= 0) {
    failf(data, "OCSP response verification failed");
    result = CURLE_SSL_INVALIDCERTSTATUS;
    goto end;
  }

  
  cert = SSL_get_peer_certificate(backend->handle);
  if(!cert) {
    failf(data, "Error getting peer certificate");
    result = CURLE_SSL_INVALIDCERTSTATUS;
    goto end;
  }

  for(i = 0; i < sk_X509_num(ch); i++) {
    X509 *issuer = sk_X509_value(ch, i);
    if(X509_check_issued(issuer, cert) == X509_V_OK) {
      id = OCSP_cert_to_id(EVP_sha1(), cert, issuer);
      break;
    }
  }
  X509_free(cert);

  if(!id) {
    failf(data, "Error computing OCSP ID");
    result = CURLE_SSL_INVALIDCERTSTATUS;
    goto end;
  }

  
  ret = OCSP_resp_find_status(br, id, &cert_status, &crl_reason, &rev, &thisupd, &nextupd);
  OCSP_CERTID_free(id);
  if(ret != 1) {
    failf(data, "Could not find certificate ID in OCSP response");
    result = CURLE_SSL_INVALIDCERTSTATUS;
    goto end;
  }

  
  if(!OCSP_check_validity(thisupd, nextupd, 300L, -1L)) {
    failf(data, "OCSP response has expired");
    result = CURLE_SSL_INVALIDCERTSTATUS;
    goto end;
  }

  infof(data, "SSL certificate status: %s (%d)\n", OCSP_cert_status_str(cert_status), cert_status);

  switch(cert_status) {
  case V_OCSP_CERTSTATUS_GOOD:
    break;

  case V_OCSP_CERTSTATUS_REVOKED:
    result = CURLE_SSL_INVALIDCERTSTATUS;
    failf(data, "SSL certificate revocation reason: %s (%d)", OCSP_crl_reason_str(crl_reason), crl_reason);
    goto end;

  case V_OCSP_CERTSTATUS_UNKNOWN:
  default:
    result = CURLE_SSL_INVALIDCERTSTATUS;
    goto end;
  }

end:
  if(br)
    OCSP_BASICRESP_free(br);
  OCSP_RESPONSE_free(rsp);

  return result;
}







static const char *ssl_msg_type(int ssl_ver, int msg)
{

  if(ssl_ver == SSL2_VERSION_MAJOR) {
    switch(msg) {
      case SSL2_MT_ERROR:
        return "Error";
      case SSL2_MT_CLIENT_HELLO:
        return "Client hello";
      case SSL2_MT_CLIENT_MASTER_KEY:
        return "Client key";
      case SSL2_MT_CLIENT_FINISHED:
        return "Client finished";
      case SSL2_MT_SERVER_HELLO:
        return "Server hello";
      case SSL2_MT_SERVER_VERIFY:
        return "Server verify";
      case SSL2_MT_SERVER_FINISHED:
        return "Server finished";
      case SSL2_MT_REQUEST_CERTIFICATE:
        return "Request CERT";
      case SSL2_MT_CLIENT_CERTIFICATE:
        return "Client CERT";
    }
  }
  else  if(ssl_ver == SSL3_VERSION_MAJOR) {

    switch(msg) {
      case SSL3_MT_HELLO_REQUEST:
        return "Hello request";
      case SSL3_MT_CLIENT_HELLO:
        return "Client hello";
      case SSL3_MT_SERVER_HELLO:
        return "Server hello";

      case SSL3_MT_NEWSESSION_TICKET:
        return "Newsession Ticket";

      case SSL3_MT_CERTIFICATE:
        return "Certificate";
      case SSL3_MT_SERVER_KEY_EXCHANGE:
        return "Server key exchange";
      case SSL3_MT_CLIENT_KEY_EXCHANGE:
        return "Client key exchange";
      case SSL3_MT_CERTIFICATE_REQUEST:
        return "Request CERT";
      case SSL3_MT_SERVER_DONE:
        return "Server finished";
      case SSL3_MT_CERTIFICATE_VERIFY:
        return "CERT verify";
      case SSL3_MT_FINISHED:
        return "Finished";

      case SSL3_MT_CERTIFICATE_STATUS:
        return "Certificate Status";


      case SSL3_MT_ENCRYPTED_EXTENSIONS:
        return "Encrypted Extensions";


      case SSL3_MT_END_OF_EARLY_DATA:
        return "End of early data";


      case SSL3_MT_KEY_UPDATE:
        return "Key update";


      case SSL3_MT_NEXT_PROTO:
        return "Next protocol";


      case SSL3_MT_MESSAGE_HASH:
        return "Message hash";

    }
  }
  return "Unknown";
}

static const char *tls_rt_type(int type)
{
  switch(type) {

  case SSL3_RT_HEADER:
    return "TLS header";

  case SSL3_RT_CHANGE_CIPHER_SPEC:
    return "TLS change cipher";
  case SSL3_RT_ALERT:
    return "TLS alert";
  case SSL3_RT_HANDSHAKE:
    return "TLS handshake";
  case SSL3_RT_APPLICATION_DATA:
    return "TLS app data";
  default:
    return "TLS Unknown";
  }
}


static void ossl_trace(int direction, int ssl_ver, int content_type, const void *buf, size_t len, SSL *ssl, void *userp)

{
  char unknown[32];
  const char *verstr = NULL;
  struct connectdata *conn = userp;
  struct ssl_connect_data *connssl = &conn->ssl[0];
  struct ssl_backend_data *backend = connssl->backend;
  struct Curl_easy *data = backend->logger;

  if(!conn || !data || !data->set.fdebug || (direction != 0 && direction != 1))
    return;

  switch(ssl_ver) {

  case SSL2_VERSION:
    verstr = "SSLv2";
    break;


  case SSL3_VERSION:
    verstr = "SSLv3";
    break;

  case TLS1_VERSION:
    verstr = "TLSv1.0";
    break;

  case TLS1_1_VERSION:
    verstr = "TLSv1.1";
    break;


  case TLS1_2_VERSION:
    verstr = "TLSv1.2";
    break;


  case TLS1_3_VERSION:
    verstr = "TLSv1.3";
    break;

  case 0:
    break;
  default:
    msnprintf(unknown, sizeof(unknown), "(%x)", ssl_ver);
    verstr = unknown;
    break;
  }

  
  if(ssl_ver  && content_type != SSL3_RT_INNER_CONTENT_TYPE  ) {



    const char *msg_name, *tls_rt_name;
    char ssl_buf[1024];
    int msg_type, txt_len;

    

    ssl_ver >>= 8; 

    
    if(ssl_ver == SSL3_VERSION_MAJOR && content_type)
      tls_rt_name = tls_rt_type(content_type);
    else tls_rt_name = "";

    if(content_type == SSL3_RT_CHANGE_CIPHER_SPEC) {
      msg_type = *(char *)buf;
      msg_name = "Change cipher spec";
    }
    else if(content_type == SSL3_RT_ALERT) {
      msg_type = (((char *)buf)[0] << 8) + ((char *)buf)[1];
      msg_name = SSL_alert_desc_string_long(msg_type);
    }
    else {
      msg_type = *(char *)buf;
      msg_name = ssl_msg_type(ssl_ver, msg_type);
    }

    txt_len = msnprintf(ssl_buf, sizeof(ssl_buf), "%s (%s), %s, %s (%d):\n", verstr, direction?"OUT":"IN", tls_rt_name, msg_name, msg_type);

    if(0 <= txt_len && (unsigned)txt_len < sizeof(ssl_buf)) {
      Curl_debug(data, CURLINFO_TEXT, ssl_buf, (size_t)txt_len);
    }
  }

  Curl_debug(data, (direction == 1) ? CURLINFO_SSL_DATA_OUT :
             CURLINFO_SSL_DATA_IN, (char *)buf, len);
  (void) ssl;
}




























static int select_next_protocol(unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, const char *key, unsigned int keylen)


{
  unsigned int i;
  for(i = 0; i + keylen <= inlen; i += in[i] + 1) {
    if(memcmp(&in[i + 1], key, keylen) == 0) {
      *out = (unsigned char *) &in[i + 1];
      *outlen = in[i];
      return 0;
    }
  }
  return -1;
}

static int select_next_proto_cb(SSL *ssl, unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg)



{
  struct Curl_easy *data = (struct Curl_easy *)arg;
  struct connectdata *conn = data->conn;
  (void)ssl;


  if(data->state.httpwant >= CURL_HTTP_VERSION_2 && !select_next_protocol(out, outlen, in, inlen, NGHTTP2_PROTO_VERSION_ID, NGHTTP2_PROTO_VERSION_ID_LEN)) {

    infof(data, "NPN, negotiated HTTP2 (%s)\n", NGHTTP2_PROTO_VERSION_ID);
    conn->negnpn = CURL_HTTP_VERSION_2;
    return SSL_TLSEXT_ERR_OK;
  }


  if(!select_next_protocol(out, outlen, in, inlen, ALPN_HTTP_1_1, ALPN_HTTP_1_1_LENGTH)) {
    infof(data, "NPN, negotiated HTTP1.1\n");
    conn->negnpn = CURL_HTTP_VERSION_1_1;
    return SSL_TLSEXT_ERR_OK;
  }

  infof(data, "NPN, no overlap, use HTTP1.1\n");
  *out = (unsigned char *)ALPN_HTTP_1_1;
  *outlen = ALPN_HTTP_1_1_LENGTH;
  conn->negnpn = CURL_HTTP_VERSION_1_1;

  return SSL_TLSEXT_ERR_OK;
}



static CURLcode set_ssl_version_min_max(SSL_CTX *ctx, struct connectdata *conn)
{
  
  long curl_ssl_version_min = SSL_CONN_CONFIG(version);
  long curl_ssl_version_max;

  

  uint16_t ossl_ssl_version_min = 0;
  uint16_t ossl_ssl_version_max = 0;

  long ossl_ssl_version_min = 0;
  long ossl_ssl_version_max = 0;

  switch(curl_ssl_version_min) {
    case CURL_SSLVERSION_TLSv1: 
    case CURL_SSLVERSION_TLSv1_0:
      ossl_ssl_version_min = TLS1_VERSION;
      break;
    case CURL_SSLVERSION_TLSv1_1:
      ossl_ssl_version_min = TLS1_1_VERSION;
      break;
    case CURL_SSLVERSION_TLSv1_2:
      ossl_ssl_version_min = TLS1_2_VERSION;
      break;

    case CURL_SSLVERSION_TLSv1_3:
      ossl_ssl_version_min = TLS1_3_VERSION;
      break;

  }

  
  if(curl_ssl_version_min != CURL_SSLVERSION_DEFAULT) {
    if(!SSL_CTX_set_min_proto_version(ctx, ossl_ssl_version_min)) {
      return CURLE_SSL_CONNECT_ERROR;
    }
  }

  
  curl_ssl_version_max = SSL_CONN_CONFIG(version_max);

  
  switch(curl_ssl_version_max) {
    case CURL_SSLVERSION_MAX_TLSv1_0:
      ossl_ssl_version_max = TLS1_VERSION;
      break;
    case CURL_SSLVERSION_MAX_TLSv1_1:
      ossl_ssl_version_max = TLS1_1_VERSION;
      break;
    case CURL_SSLVERSION_MAX_TLSv1_2:
      ossl_ssl_version_max = TLS1_2_VERSION;
      break;

    case CURL_SSLVERSION_MAX_TLSv1_3:
      ossl_ssl_version_max = TLS1_3_VERSION;
      break;

    case CURL_SSLVERSION_MAX_NONE:  
    case CURL_SSLVERSION_MAX_DEFAULT:  
    default:
      
      ossl_ssl_version_max = 0;
      break;
  }

  if(!SSL_CTX_set_max_proto_version(ctx, ossl_ssl_version_max)) {
    return CURLE_SSL_CONNECT_ERROR;
  }

  return CURLE_OK;
}



typedef uint32_t ctx_option_t;

typedef long ctx_option_t;



static CURLcode set_ssl_version_min_max_legacy(ctx_option_t *ctx_options, struct Curl_easy *data, struct connectdata *conn, int sockindex)


{
  long ssl_version = SSL_CONN_CONFIG(version);
  long ssl_version_max = SSL_CONN_CONFIG(version_max);

  (void) data; 

  switch(ssl_version) {
    case CURL_SSLVERSION_TLSv1_3:

    {
      struct ssl_connect_data *connssl = &conn->ssl[sockindex];
      SSL_CTX_set_max_proto_version(backend->ctx, TLS1_3_VERSION);
      *ctx_options |= SSL_OP_NO_TLSv1_2;
    }

      (void)sockindex;
      (void)ctx_options;
      failf(data, OSSL_PACKAGE " was built without TLS 1.3 support");
      return CURLE_NOT_BUILT_IN;

      
    case CURL_SSLVERSION_TLSv1_2:

      *ctx_options |= SSL_OP_NO_TLSv1_1;

      failf(data, OSSL_PACKAGE " was built without TLS 1.2 support");
      return CURLE_NOT_BUILT_IN;

      
    case CURL_SSLVERSION_TLSv1_1:

      *ctx_options |= SSL_OP_NO_TLSv1;

      failf(data, OSSL_PACKAGE " was built without TLS 1.1 support");
      return CURLE_NOT_BUILT_IN;

      
    case CURL_SSLVERSION_TLSv1_0:
    case CURL_SSLVERSION_TLSv1:
      break;
  }

  switch(ssl_version_max) {
    case CURL_SSLVERSION_MAX_TLSv1_0:

      *ctx_options |= SSL_OP_NO_TLSv1_1;

      
    case CURL_SSLVERSION_MAX_TLSv1_1:

      *ctx_options |= SSL_OP_NO_TLSv1_2;

      
    case CURL_SSLVERSION_MAX_TLSv1_2:

      *ctx_options |= SSL_OP_NO_TLSv1_3;

      break;
    case CURL_SSLVERSION_MAX_TLSv1_3:

      break;

      failf(data, OSSL_PACKAGE " was built without TLS 1.3 support");
      return CURLE_NOT_BUILT_IN;

  }
  return CURLE_OK;
}



static int ossl_new_session_cb(SSL *ssl, SSL_SESSION *ssl_sessionid)
{
  int res = 0;
  struct connectdata *conn;
  struct Curl_easy *data;
  int sockindex;
  curl_socket_t *sockindex_ptr;
  int data_idx = ossl_get_ssl_data_index();
  int connectdata_idx = ossl_get_ssl_conn_index();
  int sockindex_idx = ossl_get_ssl_sockindex_index();

  if(data_idx < 0 || connectdata_idx < 0 || sockindex_idx < 0)
    return 0;

  conn = (struct connectdata*) SSL_get_ex_data(ssl, connectdata_idx);
  if(!conn)
    return 0;

  data = (struct Curl_easy *) SSL_get_ex_data(ssl, data_idx);

  
  sockindex_ptr = (curl_socket_t*) SSL_get_ex_data(ssl, sockindex_idx);
  sockindex = (int)(sockindex_ptr - conn->sock);

  if(SSL_SET_OPTION(primary.sessionid)) {
    bool incache;
    void *old_ssl_sessionid = NULL;

    Curl_ssl_sessionid_lock(data);
    incache = !(Curl_ssl_getsessionid(data, conn, &old_ssl_sessionid, NULL, sockindex));
    if(incache) {
      if(old_ssl_sessionid != ssl_sessionid) {
        infof(data, "old SSL session ID is stale, removing\n");
        Curl_ssl_delsessionid(data, old_ssl_sessionid);
        incache = FALSE;
      }
    }

    if(!incache) {
      if(!Curl_ssl_addsessionid(data, conn, ssl_sessionid, 0 , sockindex)) {
        
        res = 1;
      }
      else failf(data, "failed to store ssl session");
    }
    Curl_ssl_sessionid_unlock(data);
  }

  return res;
}

static CURLcode ossl_connect_step1(struct Curl_easy *data, struct connectdata *conn, int sockindex)
{
  CURLcode result = CURLE_OK;
  char *ciphers;
  SSL_METHOD_QUAL SSL_METHOD *req_method = NULL;
  X509_LOOKUP *lookup = NULL;
  curl_socket_t sockfd = conn->sock[sockindex];
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  ctx_option_t ctx_options = 0;


  bool sni;
  const char * const hostname = SSL_HOST_NAME();


  struct in6_addr addr;

  struct in_addr addr;


  const long int ssl_version = SSL_CONN_CONFIG(version);

  const enum CURL_TLSAUTH ssl_authtype = SSL_SET_OPTION(authtype);

  char * const ssl_cert = SSL_SET_OPTION(primary.clientcert);
  const struct curl_blob *ssl_cert_blob = SSL_SET_OPTION(primary.cert_blob);
  const char * const ssl_cert_type = SSL_SET_OPTION(cert_type);
  const char * const ssl_cafile = SSL_CONN_CONFIG(CAfile);
  const char * const ssl_capath = SSL_CONN_CONFIG(CApath);
  const bool verifypeer = SSL_CONN_CONFIG(verifypeer);
  const char * const ssl_crlfile = SSL_SET_OPTION(CRLfile);
  char error_buffer[256];
  struct ssl_backend_data *backend = connssl->backend;
  bool imported_native_ca = false;

  DEBUGASSERT(ssl_connect_1 == connssl->connecting_state);

  
  result = ossl_seed(data);
  if(result)
    return result;

  SSL_SET_OPTION_LVALUE(certverifyresult) = !X509_V_OK;

  

  switch(ssl_version) {
  case CURL_SSLVERSION_DEFAULT:
  case CURL_SSLVERSION_TLSv1:
  case CURL_SSLVERSION_TLSv1_0:
  case CURL_SSLVERSION_TLSv1_1:
  case CURL_SSLVERSION_TLSv1_2:
  case CURL_SSLVERSION_TLSv1_3:
    

    req_method = TLS_client_method();

    req_method = SSLv23_client_method();

    use_sni(TRUE);
    break;
  case CURL_SSLVERSION_SSLv2:

    failf(data, OSSL_PACKAGE " was built without SSLv2 support");
    return CURLE_NOT_BUILT_IN;


    if(ssl_authtype == CURL_TLSAUTH_SRP)
      return CURLE_SSL_CONNECT_ERROR;

    req_method = SSLv2_client_method();
    use_sni(FALSE);
    break;

  case CURL_SSLVERSION_SSLv3:

    failf(data, OSSL_PACKAGE " was built without SSLv3 support");
    return CURLE_NOT_BUILT_IN;


    if(ssl_authtype == CURL_TLSAUTH_SRP)
      return CURLE_SSL_CONNECT_ERROR;

    req_method = SSLv3_client_method();
    use_sni(FALSE);
    break;

  default:
    failf(data, "Unrecognized parameter passed via CURLOPT_SSLVERSION");
    return CURLE_SSL_CONNECT_ERROR;
  }

  if(backend->ctx)
    SSL_CTX_free(backend->ctx);
  backend->ctx = SSL_CTX_new(req_method);

  if(!backend->ctx) {
    failf(data, "SSL: couldn't create a context: %s", ossl_strerror(ERR_peek_error(), error_buffer, sizeof(error_buffer)));
    return CURLE_OUT_OF_MEMORY;
  }


  SSL_CTX_set_mode(backend->ctx, SSL_MODE_RELEASE_BUFFERS);



  if(data->set.fdebug && data->set.verbose) {
    
    SSL_CTX_set_msg_callback(backend->ctx, ossl_trace);
    SSL_CTX_set_msg_callback_arg(backend->ctx, conn);
    set_logger(conn, data);
  }


  

  ctx_options = SSL_OP_ALL;


  ctx_options |= SSL_OP_NO_TICKET;



  ctx_options |= SSL_OP_NO_COMPRESSION;



  
  ctx_options &= ~SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG;



  
  if(!SSL_SET_OPTION(enable_beast))
    ctx_options &= ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS;


  switch(ssl_version) {
    
    case CURL_SSLVERSION_SSLv2:

      SSL_CTX_set_min_proto_version(backend->ctx, SSL2_VERSION);
      SSL_CTX_set_max_proto_version(backend->ctx, SSL2_VERSION);

      ctx_options |= SSL_OP_NO_SSLv3;
      ctx_options |= SSL_OP_NO_TLSv1;

      ctx_options |= SSL_OP_NO_TLSv1_1;
      ctx_options |= SSL_OP_NO_TLSv1_2;

      ctx_options |= SSL_OP_NO_TLSv1_3;



      break;

    
    case CURL_SSLVERSION_SSLv3:

      SSL_CTX_set_min_proto_version(backend->ctx, SSL3_VERSION);
      SSL_CTX_set_max_proto_version(backend->ctx, SSL3_VERSION);

      ctx_options |= SSL_OP_NO_SSLv2;
      ctx_options |= SSL_OP_NO_TLSv1;

      ctx_options |= SSL_OP_NO_TLSv1_1;
      ctx_options |= SSL_OP_NO_TLSv1_2;

      ctx_options |= SSL_OP_NO_TLSv1_3;



      break;

    
    case CURL_SSLVERSION_DEFAULT:
    case CURL_SSLVERSION_TLSv1: 
    case CURL_SSLVERSION_TLSv1_0: 
    case CURL_SSLVERSION_TLSv1_1: 
    case CURL_SSLVERSION_TLSv1_2: 
    case CURL_SSLVERSION_TLSv1_3: 
      
      ctx_options |= SSL_OP_NO_SSLv2;
      ctx_options |= SSL_OP_NO_SSLv3;


      result = set_ssl_version_min_max(backend->ctx, conn);

      result = set_ssl_version_min_max_legacy(&ctx_options, data, conn, sockindex);

      if(result != CURLE_OK)
        return result;
      break;

    default:
      failf(data, "Unrecognized parameter passed via CURLOPT_SSLVERSION");
      return CURLE_SSL_CONNECT_ERROR;
  }

  SSL_CTX_set_options(backend->ctx, ctx_options);


  if(conn->bits.tls_enable_npn)
    SSL_CTX_set_next_proto_select_cb(backend->ctx, select_next_proto_cb, data);



  if(conn->bits.tls_enable_alpn) {
    int cur = 0;
    unsigned char protocols[128];


    if(data->state.httpwant >= CURL_HTTP_VERSION_2  && (!SSL_IS_PROXY() || !conn->bits.tunnel_proxy)


      ) {
      protocols[cur++] = NGHTTP2_PROTO_VERSION_ID_LEN;

      memcpy(&protocols[cur], NGHTTP2_PROTO_VERSION_ID, NGHTTP2_PROTO_VERSION_ID_LEN);
      cur += NGHTTP2_PROTO_VERSION_ID_LEN;
      infof(data, "ALPN, offering %s\n", NGHTTP2_PROTO_VERSION_ID);
    }


    protocols[cur++] = ALPN_HTTP_1_1_LENGTH;
    memcpy(&protocols[cur], ALPN_HTTP_1_1, ALPN_HTTP_1_1_LENGTH);
    cur += ALPN_HTTP_1_1_LENGTH;
    infof(data, "ALPN, offering %s\n", ALPN_HTTP_1_1);

    
    if(SSL_CTX_set_alpn_protos(backend->ctx, protocols, cur)) {
      failf(data, "Error setting ALPN");
      return CURLE_SSL_CONNECT_ERROR;
    }
  }


  if(ssl_cert || ssl_cert_blob || ssl_cert_type) {
    BIO *ssl_cert_bio = NULL;
    BIO *ssl_key_bio = NULL;
    if(ssl_cert_blob) {
      
      ssl_cert_bio = BIO_new_mem_buf(ssl_cert_blob->data, (int)ssl_cert_blob->len);
      if(!ssl_cert_bio)
        result = CURLE_OUT_OF_MEMORY;
    }
    if(!result && SSL_SET_OPTION(key_blob)) {
      ssl_key_bio = BIO_new_mem_buf(SSL_SET_OPTION(key_blob)->data, (int)SSL_SET_OPTION(key_blob)->len);
      if(!ssl_key_bio)
        result = CURLE_OUT_OF_MEMORY;
    }
    if(!result && !cert_stuff(data, backend->ctx, ssl_cert, ssl_cert_bio, ssl_cert_type, SSL_SET_OPTION(key), ssl_key_bio, SSL_SET_OPTION(key_type), SSL_SET_OPTION(key_passwd)))



      result = CURLE_SSL_CERTPROBLEM;
    if(ssl_cert_bio)
      BIO_free(ssl_cert_bio);
    if(ssl_key_bio)
      BIO_free(ssl_key_bio);
    if(result)
      
      return result;
  }

  ciphers = SSL_CONN_CONFIG(cipher_list);
  if(!ciphers)
    ciphers = (char *)DEFAULT_CIPHER_SELECTION;
  if(ciphers) {
    if(!SSL_CTX_set_cipher_list(backend->ctx, ciphers)) {
      failf(data, "failed setting cipher list: %s", ciphers);
      return CURLE_SSL_CIPHER;
    }
    infof(data, "Cipher selection: %s\n", ciphers);
  }


  {
    char *ciphers13 = SSL_CONN_CONFIG(cipher_list13);
    if(ciphers13) {
      if(!SSL_CTX_set_ciphersuites(backend->ctx, ciphers13)) {
        failf(data, "failed setting TLS 1.3 cipher suite: %s", ciphers13);
        return CURLE_SSL_CIPHER;
      }
      infof(data, "TLS 1.3 cipher selection: %s\n", ciphers13);
    }
  }



  
  SSL_CTX_set_post_handshake_auth(backend->ctx, 1);



  {
    char *curves = SSL_CONN_CONFIG(curves);
    if(curves) {
      if(!SSL_CTX_set1_curves_list(backend->ctx, curves)) {
        failf(data, "failed setting curves list: '%s'", curves);
        return CURLE_SSL_CIPHER;
      }
    }
  }



  if(ssl_authtype == CURL_TLSAUTH_SRP) {
    char * const ssl_username = SSL_SET_OPTION(username);

    infof(data, "Using TLS-SRP username: %s\n", ssl_username);

    if(!SSL_CTX_set_srp_username(backend->ctx, ssl_username)) {
      failf(data, "Unable to set SRP user name");
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    if(!SSL_CTX_set_srp_password(backend->ctx, SSL_SET_OPTION(password))) {
      failf(data, "failed setting SRP password");
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    if(!SSL_CONN_CONFIG(cipher_list)) {
      infof(data, "Setting cipher list SRP\n");

      if(!SSL_CTX_set_cipher_list(backend->ctx, "SRP")) {
        failf(data, "failed setting SRP cipher list");
        return CURLE_SSL_CIPHER;
      }
    }
  }




  
  if((SSL_CONN_CONFIG(verifypeer) || SSL_CONN_CONFIG(verifyhost)) && (SSL_SET_OPTION(native_ca_store))) {
    X509_STORE *store = SSL_CTX_get_cert_store(backend->ctx);
    HCERTSTORE hStore = CertOpenSystemStore((HCRYPTPROV_LEGACY)NULL, TEXT("ROOT"));

    if(hStore) {
      PCCERT_CONTEXT pContext = NULL;
      
      CERT_ENHKEY_USAGE *enhkey_usage = NULL;
      DWORD enhkey_usage_size = 0;

      
      result = CURLE_OK;
      for(;;) {
        X509 *x509;
        FILETIME now;
        BYTE key_usage[2];
        DWORD req_size;
        const unsigned char *encoded_cert;

        char cert_name[256];


        pContext = CertEnumCertificatesInStore(hStore, pContext);
        if(!pContext)
          break;


        if(!CertGetNameStringA(pContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, cert_name, sizeof(cert_name))) {
          strcpy(cert_name, "Unknown");
        }
        infof(data, "SSL: Checking cert \"%s\"\n", cert_name);


        encoded_cert = (const unsigned char *)pContext->pbCertEncoded;
        if(!encoded_cert)
          continue;

        GetSystemTimeAsFileTime(&now);
        if(CompareFileTime(&pContext->pCertInfo->NotBefore, &now) > 0 || CompareFileTime(&now, &pContext->pCertInfo->NotAfter) > 0)
          continue;

        
        if(CertGetIntendedKeyUsage(pContext->dwCertEncodingType, pContext->pCertInfo, key_usage, sizeof(key_usage))) {

          if(!(key_usage[0] & CERT_KEY_CERT_SIGN_KEY_USAGE))
            continue;
        }
        else if(GetLastError())
          continue;

        
        if(CertGetEnhancedKeyUsage(pContext, 0, NULL, &req_size)) {
          if(req_size && req_size > enhkey_usage_size) {
            void *tmp = realloc(enhkey_usage, req_size);

            if(!tmp) {
              failf(data, "SSL: Out of memory allocating for OID list");
              result = CURLE_OUT_OF_MEMORY;
              break;
            }

            enhkey_usage = (CERT_ENHKEY_USAGE *)tmp;
            enhkey_usage_size = req_size;
          }

          if(CertGetEnhancedKeyUsage(pContext, 0, enhkey_usage, &req_size)) {
            if(!enhkey_usage->cUsageIdentifier) {
              
              if((HRESULT)GetLastError() != CRYPT_E_NOT_FOUND)
                continue;
            }
            else {
              DWORD i;
              bool found = false;

              for(i = 0; i < enhkey_usage->cUsageIdentifier; ++i) {
                if(!strcmp("1.3.6.1.5.5.7.3.1" , enhkey_usage->rgpszUsageIdentifier[i])) {
                  found = true;
                  break;
                }
              }

              if(!found)
                continue;
            }
          }
          else continue;
        }
        else continue;

        x509 = d2i_X509(NULL, &encoded_cert, pContext->cbCertEncoded);
        if(!x509)
          continue;

        
        if(X509_STORE_add_cert(store, x509) == 1) {

          infof(data, "SSL: Imported cert \"%s\"\n", cert_name);

          imported_native_ca = true;
        }
        X509_free(x509);
      }

      free(enhkey_usage);
      CertFreeCertificateContext(pContext);
      CertCloseStore(hStore, 0);

      if(result)
        return result;
    }
    if(imported_native_ca)
      infof(data, "successfully imported windows ca store\n");
    else infof(data, "error importing windows ca store, continuing anyway\n");
  }



  
  {
    if(ssl_cafile) {
      if(!SSL_CTX_load_verify_file(backend->ctx, ssl_cafile)) {
        if(verifypeer && !imported_native_ca) {
          
          failf(data, "error setting certificate file: %s", ssl_cafile);
          return CURLE_SSL_CACERT_BADFILE;
        }
        
        infof(data, "error setting certificate file, continuing anyway\n");
      }
      infof(data, " CAfile: %s\n", ssl_cafile);
    }
    if(ssl_capath) {
      if(!SSL_CTX_load_verify_dir(backend->ctx, ssl_capath)) {
        if(verifypeer && !imported_native_ca) {
          
          failf(data, "error setting certificate path: %s", ssl_capath);
          return CURLE_SSL_CACERT_BADFILE;
        }
        
        infof(data, "error setting certificate path, continuing anyway\n");
      }
      infof(data, " CApath: %s\n", ssl_capath);
    }
  }

  if(ssl_cafile || ssl_capath) {
    
    if(!SSL_CTX_load_verify_locations(backend->ctx, ssl_cafile, ssl_capath)) {
      if(verifypeer && !imported_native_ca) {
        
        failf(data, "error setting certificate verify locations:" "  CAfile: %s CApath: %s", ssl_cafile ? ssl_cafile : "none", ssl_capath ? ssl_capath : "none");


        return CURLE_SSL_CACERT_BADFILE;
      }
      
      infof(data, "error setting certificate verify locations," " continuing anyway:\n");
    }
    else {
      
      infof(data, "successfully set certificate verify locations:\n");
    }
    infof(data, " CAfile: %s\n", ssl_cafile ? ssl_cafile : "none");
    infof(data, " CApath: %s\n", ssl_capath ? ssl_capath : "none");
  }



  if(verifypeer && !ssl_cafile && !ssl_capath && !imported_native_ca) {
    
    SSL_CTX_set_default_verify_paths(backend->ctx);
  }


  if(ssl_crlfile) {
    
    lookup = X509_STORE_add_lookup(SSL_CTX_get_cert_store(backend->ctx), X509_LOOKUP_file());
    if(!lookup || (!X509_load_crl_file(lookup, ssl_crlfile, X509_FILETYPE_PEM)) ) {
      failf(data, "error loading CRL file: %s", ssl_crlfile);
      return CURLE_SSL_CRL_BADFILE;
    }
    
    infof(data, "successfully load CRL file:\n");
    X509_STORE_set_flags(SSL_CTX_get_cert_store(backend->ctx), X509_V_FLAG_CRL_CHECK|X509_V_FLAG_CRL_CHECK_ALL);

    infof(data, "  CRLfile: %s\n", ssl_crlfile);
  }

  if(verifypeer) {
    

    X509_STORE_set_flags(SSL_CTX_get_cert_store(backend->ctx), X509_V_FLAG_TRUSTED_FIRST);


    if(!SSL_SET_OPTION(no_partialchain) && !ssl_crlfile) {
      
      X509_STORE_set_flags(SSL_CTX_get_cert_store(backend->ctx), X509_V_FLAG_PARTIAL_CHAIN);
    }

  }

  
  SSL_CTX_set_verify(backend->ctx, verifypeer ? SSL_VERIFY_PEER : SSL_VERIFY_NONE, NULL);

  

  if(Curl_tls_keylog_enabled()) {
    SSL_CTX_set_keylog_callback(backend->ctx, ossl_keylog_callback);
  }


  
  SSL_CTX_set_session_cache_mode(backend->ctx, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL);
  SSL_CTX_sess_set_new_cb(backend->ctx, ossl_new_session_cb);

  
  if(data->set.ssl.fsslctx) {
    Curl_set_in_callback(data, true);
    result = (*data->set.ssl.fsslctx)(data, backend->ctx, data->set.ssl.fsslctxp);
    Curl_set_in_callback(data, false);
    if(result) {
      failf(data, "error signaled by ssl ctx callback");
      return result;
    }
  }

  
  if(backend->handle)
    SSL_free(backend->handle);
  backend->handle = SSL_new(backend->ctx);
  if(!backend->handle) {
    failf(data, "SSL: couldn't create a context (handle)!");
    return CURLE_OUT_OF_MEMORY;
  }


  if(SSL_CONN_CONFIG(verifystatus))
    SSL_set_tlsext_status_type(backend->handle, TLSEXT_STATUSTYPE_ocsp);



  SSL_set_renegotiate_mode(backend->handle, ssl_renegotiate_freely);


  SSL_set_connect_state(backend->handle);

  backend->server_cert = 0x0;

  if((0 == Curl_inet_pton(AF_INET, hostname, &addr)) &&  (0 == Curl_inet_pton(AF_INET6, hostname, &addr)) &&  sni) {



    size_t nlen = strlen(hostname);
    if((long)nlen >= data->set.buffer_size)
      
      return CURLE_SSL_CONNECT_ERROR;

    
    Curl_strntolower(data->state.buffer, hostname, nlen);
    data->state.buffer[nlen] = 0;
    if(!SSL_set_tlsext_host_name(backend->handle, data->state.buffer))
      infof(data, "WARNING: failed to configure server name indication (SNI) " "TLS extension\n");
  }


  
  if(SSL_SET_OPTION(primary.sessionid)) {
    void *ssl_sessionid = NULL;
    int data_idx = ossl_get_ssl_data_index();
    int connectdata_idx = ossl_get_ssl_conn_index();
    int sockindex_idx = ossl_get_ssl_sockindex_index();

    if(data_idx >= 0 && connectdata_idx >= 0 && sockindex_idx >= 0) {
      
      SSL_set_ex_data(backend->handle, data_idx, data);
      SSL_set_ex_data(backend->handle, connectdata_idx, conn);
      SSL_set_ex_data(backend->handle, sockindex_idx, conn->sock + sockindex);
    }

    Curl_ssl_sessionid_lock(data);
    if(!Curl_ssl_getsessionid(data, conn, &ssl_sessionid, NULL, sockindex)) {
      
      if(!SSL_set_session(backend->handle, ssl_sessionid)) {
        Curl_ssl_sessionid_unlock(data);
        failf(data, "SSL: SSL_set_session failed: %s", ossl_strerror(ERR_get_error(), error_buffer, sizeof(error_buffer)));

        return CURLE_SSL_CONNECT_ERROR;
      }
      
      infof(data, "SSL re-using session ID\n");
    }
    Curl_ssl_sessionid_unlock(data);
  }


  if(conn->proxy_ssl[sockindex].use) {
    BIO *const bio = BIO_new(BIO_f_ssl());
    SSL *handle = conn->proxy_ssl[sockindex].backend->handle;
    DEBUGASSERT(ssl_connection_complete == conn->proxy_ssl[sockindex].state);
    DEBUGASSERT(handle != NULL);
    DEBUGASSERT(bio != NULL);
    BIO_set_ssl(bio, handle, FALSE);
    SSL_set_bio(backend->handle, bio, bio);
  }
  else  if(!SSL_set_fd(backend->handle, (int)sockfd)) {

    
    failf(data, "SSL: SSL_set_fd failed: %s", ossl_strerror(ERR_get_error(), error_buffer, sizeof(error_buffer)));
    return CURLE_SSL_CONNECT_ERROR;
  }

  connssl->connecting_state = ssl_connect_2;

  return CURLE_OK;
}

static CURLcode ossl_connect_step2(struct Curl_easy *data, struct connectdata *conn, int sockindex)
{
  int err;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  struct ssl_backend_data *backend = connssl->backend;
  DEBUGASSERT(ssl_connect_2 == connssl->connecting_state || ssl_connect_2_reading == connssl->connecting_state || ssl_connect_2_writing == connssl->connecting_state);


  ERR_clear_error();

  err = SSL_connect(backend->handle);

  if(Curl_tls_keylog_enabled()) {
    
    ossl_log_tls12_secret(backend->handle, &backend->keylog_done);
  }


  
  if(1 != err) {
    int detail = SSL_get_error(backend->handle, err);

    if(SSL_ERROR_WANT_READ == detail) {
      connssl->connecting_state = ssl_connect_2_reading;
      return CURLE_OK;
    }
    if(SSL_ERROR_WANT_WRITE == detail) {
      connssl->connecting_state = ssl_connect_2_writing;
      return CURLE_OK;
    }

    if(SSL_ERROR_WANT_ASYNC == detail) {
      connssl->connecting_state = ssl_connect_2;
      return CURLE_OK;
    }

    else {
      
      unsigned long errdetail;
      char error_buffer[256]="";
      CURLcode result;
      long lerr;
      int lib;
      int reason;

      
      connssl->connecting_state = ssl_connect_2;

      
      errdetail = ERR_get_error();

      
      lib = ERR_GET_LIB(errdetail);
      reason = ERR_GET_REASON(errdetail);

      if((lib == ERR_LIB_SSL) && ((reason == SSL_R_CERTIFICATE_VERIFY_FAILED) || (reason == SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED))) {

        result = CURLE_PEER_FAILED_VERIFICATION;

        lerr = SSL_get_verify_result(backend->handle);
        if(lerr != X509_V_OK) {
          SSL_SET_OPTION_LVALUE(certverifyresult) = lerr;
          msnprintf(error_buffer, sizeof(error_buffer), "SSL certificate problem: %s", X509_verify_cert_error_string(lerr));

        }
        else  strcpy(error_buffer, "SSL certificate verification failed");

      }
      else {
        result = CURLE_SSL_CONNECT_ERROR;
        ossl_strerror(errdetail, error_buffer, sizeof(error_buffer));
      }

      

      
      if(CURLE_SSL_CONNECT_ERROR == result && errdetail == 0) {
        const char * const hostname = SSL_HOST_NAME();

        const long int port = SSL_IS_PROXY() ? conn->port : conn->remote_port;

        const long int port = conn->remote_port;

        char extramsg[80]="";
        int sockerr = SOCKERRNO;
        if(sockerr && detail == SSL_ERROR_SYSCALL)
          Curl_strerror(sockerr, extramsg, sizeof(extramsg));
        failf(data, OSSL_PACKAGE " SSL_connect: %s in connection to %s:%ld ", extramsg[0] ? extramsg : SSL_ERROR_to_str(detail), hostname, port);

        return result;
      }

      
      failf(data, "%s", error_buffer);

      return result;
    }
  }
  else {
    
    connssl->connecting_state = ssl_connect_3;

    
    infof(data, "SSL connection using %s / %s\n", SSL_get_version(backend->handle), SSL_get_cipher(backend->handle));



    
    if(conn->bits.tls_enable_alpn) {
      const unsigned char *neg_protocol;
      unsigned int len;
      SSL_get0_alpn_selected(backend->handle, &neg_protocol, &len);
      if(len != 0) {
        infof(data, "ALPN, server accepted to use %.*s\n", len, neg_protocol);


        if(len == NGHTTP2_PROTO_VERSION_ID_LEN && !memcmp(NGHTTP2_PROTO_VERSION_ID, neg_protocol, len)) {
          conn->negnpn = CURL_HTTP_VERSION_2;
        }
        else  if(len == ALPN_HTTP_1_1_LENGTH && !memcmp(ALPN_HTTP_1_1, neg_protocol, ALPN_HTTP_1_1_LENGTH)) {


          conn->negnpn = CURL_HTTP_VERSION_1_1;
        }
      }
      else infof(data, "ALPN, server did not agree to a protocol\n");

      Curl_multiuse_state(data, conn->negnpn == CURL_HTTP_VERSION_2 ? BUNDLE_MULTIPLEX : BUNDLE_NO_MULTIUSE);
    }


    return CURLE_OK;
  }
}

static int asn1_object_dump(ASN1_OBJECT *a, char *buf, size_t len)
{
  int i, ilen;

  ilen = (int)len;
  if(ilen < 0)
    return 1; 

  i = i2t_ASN1_OBJECT(buf, ilen, a);

  if(i >= ilen)
    return 1; 

  return 0;
}








static void pubkey_show(struct Curl_easy *data, BIO *mem, int num, const char *type, const char *name,  const  BIGNUM *bn)







{
  char *ptr;
  char namebuf[32];

  msnprintf(namebuf, sizeof(namebuf), "%s(%s)", type, name);

  if(bn)
    BN_print(mem, bn);
  push_certinfo(namebuf, num);
}












static void X509V3_ext(struct Curl_easy *data, int certnum, CONST_EXTS STACK_OF(X509_EXTENSION) *exts)

{
  int i;

  if((int)sk_X509_EXTENSION_num(exts) <= 0)
    
    return;

  for(i = 0; i < (int)sk_X509_EXTENSION_num(exts); i++) {
    ASN1_OBJECT *obj;
    X509_EXTENSION *ext = sk_X509_EXTENSION_value(exts, i);
    BUF_MEM *biomem;
    char namebuf[128];
    BIO *bio_out = BIO_new(BIO_s_mem());

    if(!bio_out)
      return;

    obj = X509_EXTENSION_get_object(ext);

    asn1_object_dump(obj, namebuf, sizeof(namebuf));

    if(!X509V3_EXT_print(bio_out, ext, 0, 0))
      ASN1_STRING_print(bio_out, (ASN1_STRING *)X509_EXTENSION_get_data(ext));

    BIO_get_mem_ptr(bio_out, &biomem);
    Curl_ssl_push_certinfo_len(data, certnum, namebuf, biomem->data, biomem->length);
    BIO_free(bio_out);
  }
}


typedef size_t numcert_t;

typedef int numcert_t;








static CURLcode get_cert_chain(struct Curl_easy *data, struct ssl_connect_data *connssl)
{
  CURLcode result;
  STACK_OF(X509) *sk;
  int i;
  numcert_t numcerts;
  BIO *mem;
  struct ssl_backend_data *backend = connssl->backend;

  sk = SSL_get_peer_cert_chain(backend->handle);
  if(!sk) {
    return CURLE_OUT_OF_MEMORY;
  }

  numcerts = sk_X509_num(sk);

  result = Curl_ssl_init_certinfo(data, (int)numcerts);
  if(result) {
    return result;
  }

  mem = BIO_new(BIO_s_mem());

  for(i = 0; i < (int)numcerts; i++) {
    ASN1_INTEGER *num;
    X509 *x = sk_X509_value(sk, i);
    EVP_PKEY *pubkey = NULL;
    int j;
    char *ptr;
    const ASN1_BIT_STRING *psig = NULL;

    X509_NAME_print_ex(mem, X509_get_subject_name(x), 0, XN_FLAG_ONELINE);
    push_certinfo("Subject", i);

    X509_NAME_print_ex(mem, X509_get_issuer_name(x), 0, XN_FLAG_ONELINE);
    push_certinfo("Issuer", i);

    BIO_printf(mem, "%lx", X509_get_version(x));
    push_certinfo("Version", i);

    num = X509_get_serialNumber(x);
    if(num->type == V_ASN1_NEG_INTEGER)
      BIO_puts(mem, "-");
    for(j = 0; j < num->length; j++)
      BIO_printf(mem, "%02x", num->data[j]);
    push_certinfo("Serial Number", i);


    {
      const X509_ALGOR *sigalg = NULL;
      X509_PUBKEY *xpubkey = NULL;
      ASN1_OBJECT *pubkeyoid = NULL;

      X509_get0_signature(&psig, &sigalg, x);
      if(sigalg) {
        i2a_ASN1_OBJECT(mem, sigalg->algorithm);
        push_certinfo("Signature Algorithm", i);
      }

      xpubkey = X509_get_X509_PUBKEY(x);
      if(xpubkey) {
        X509_PUBKEY_get0_param(&pubkeyoid, NULL, NULL, NULL, xpubkey);
        if(pubkeyoid) {
          i2a_ASN1_OBJECT(mem, pubkeyoid);
          push_certinfo("Public Key Algorithm", i);
        }
      }

      X509V3_ext(data, i, X509_get0_extensions(x));
    }

    {
      
      X509_CINF *cinf = x->cert_info;

      i2a_ASN1_OBJECT(mem, cinf->signature->algorithm);
      push_certinfo("Signature Algorithm", i);

      i2a_ASN1_OBJECT(mem, cinf->key->algor->algorithm);
      push_certinfo("Public Key Algorithm", i);

      X509V3_ext(data, i, cinf->extensions);

      psig = x->signature;
    }


    ASN1_TIME_print(mem, X509_get0_notBefore(x));
    push_certinfo("Start date", i);

    ASN1_TIME_print(mem, X509_get0_notAfter(x));
    push_certinfo("Expire date", i);

    pubkey = X509_get_pubkey(x);
    if(!pubkey)
      infof(data, "   Unable to load public key\n");
    else {
      int pktype;

      pktype = EVP_PKEY_id(pubkey);

      pktype = pubkey->type;

      switch(pktype) {
      case EVP_PKEY_RSA:
      {
        OSSL3_CONST RSA *rsa;

        rsa = EVP_PKEY_get0_RSA(pubkey);

        rsa = pubkey->pkey.rsa;



        {
          const BIGNUM *n;
          const BIGNUM *e;

          RSA_get0_key(rsa, &n, &e, NULL);
          BIO_printf(mem, "%d", BN_num_bits(n));
          push_certinfo("RSA Public Key", i);
          print_pubkey_BN(rsa, n, i);
          print_pubkey_BN(rsa, e, i);
        }

        BIO_printf(mem, "%d", BN_num_bits(rsa->n));
        push_certinfo("RSA Public Key", i);
        print_pubkey_BN(rsa, n, i);
        print_pubkey_BN(rsa, e, i);


        break;
      }
      case EVP_PKEY_DSA:
      {

        OSSL3_CONST DSA *dsa;

        dsa = EVP_PKEY_get0_DSA(pubkey);

        dsa = pubkey->pkey.dsa;


        {
          const BIGNUM *p;
          const BIGNUM *q;
          const BIGNUM *g;
          const BIGNUM *pub_key;

          DSA_get0_pqg(dsa, &p, &q, &g);
          DSA_get0_key(dsa, &pub_key, NULL);

          print_pubkey_BN(dsa, p, i);
          print_pubkey_BN(dsa, q, i);
          print_pubkey_BN(dsa, g, i);
          print_pubkey_BN(dsa, pub_key, i);
        }

        print_pubkey_BN(dsa, p, i);
        print_pubkey_BN(dsa, q, i);
        print_pubkey_BN(dsa, g, i);
        print_pubkey_BN(dsa, pub_key, i);


        break;
      }
      case EVP_PKEY_DH:
      {
        OSSL3_CONST DH *dh;

        dh = EVP_PKEY_get0_DH(pubkey);

        dh = pubkey->pkey.dh;


        {
          const BIGNUM *p;
          const BIGNUM *q;
          const BIGNUM *g;
          const BIGNUM *pub_key;
          DH_get0_pqg(dh, &p, &q, &g);
          DH_get0_key(dh, &pub_key, NULL);
          print_pubkey_BN(dh, p, i);
          print_pubkey_BN(dh, q, i);
          print_pubkey_BN(dh, g, i);
          print_pubkey_BN(dh, pub_key, i);
       }

        print_pubkey_BN(dh, p, i);
        print_pubkey_BN(dh, g, i);
        print_pubkey_BN(dh, pub_key, i);

        break;
      }
      }
      EVP_PKEY_free(pubkey);
    }

    if(psig) {
      for(j = 0; j < psig->length; j++)
        BIO_printf(mem, "%02x:", psig->data[j]);
      push_certinfo("Signature", i);
    }

    PEM_write_bio_X509(mem, x);
    push_certinfo("Cert", i);
  }

  BIO_free(mem);

  return CURLE_OK;
}


static CURLcode pkp_pin_peer_pubkey(struct Curl_easy *data, X509* cert, const char *pinnedpubkey)
{
  
  int len1 = 0, len2 = 0;
  unsigned char *buff1 = NULL, *temp = NULL;

  
  CURLcode result = CURLE_SSL_PINNEDPUBKEYNOTMATCH;

  
  if(!pinnedpubkey)
    return CURLE_OK;

  if(!cert)
    return result;

  do {
    
    

    
    len1 = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), NULL);
    if(len1 < 1)
      break; 

    buff1 = temp = malloc(len1);
    if(!buff1)
      break; 

    
    len2 = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &temp);

    
    if((len1 != len2) || !temp || ((temp - buff1) != len1))
      break; 

    

    
    result = Curl_pin_peer_pubkey(data, pinnedpubkey, buff1, len1);
  } while(0);

  if(buff1)
    free(buff1);

  return result;
}


static CURLcode servercert(struct Curl_easy *data, struct connectdata *conn, struct ssl_connect_data *connssl, bool strict)


{
  CURLcode result = CURLE_OK;
  int rc;
  long lerr;
  X509 *issuer;
  BIO *fp = NULL;
  char error_buffer[256]="";
  char buffer[2048];
  const char *ptr;
  BIO *mem = BIO_new(BIO_s_mem());
  struct ssl_backend_data *backend = connssl->backend;

  if(data->set.ssl.certinfo)
    
    (void)get_cert_chain(data, connssl);

  backend->server_cert = SSL_get_peer_certificate(backend->handle);
  if(!backend->server_cert) {
    BIO_free(mem);
    if(!strict)
      return CURLE_OK;

    failf(data, "SSL: couldn't get peer certificate!");
    return CURLE_PEER_FAILED_VERIFICATION;
  }

  infof(data, "%s certificate:\n", SSL_IS_PROXY() ? "Proxy" : "Server");

  rc = x509_name_oneline(X509_get_subject_name(backend->server_cert), buffer, sizeof(buffer));
  infof(data, " subject: %s\n", rc?"[NONE]":buffer);


  {
    long len;
    ASN1_TIME_print(mem, X509_get0_notBefore(backend->server_cert));
    len = BIO_get_mem_data(mem, (char **) &ptr);
    infof(data, " start date: %.*s\n", len, ptr);
    (void)BIO_reset(mem);

    ASN1_TIME_print(mem, X509_get0_notAfter(backend->server_cert));
    len = BIO_get_mem_data(mem, (char **) &ptr);
    infof(data, " expire date: %.*s\n", len, ptr);
    (void)BIO_reset(mem);
  }


  BIO_free(mem);

  if(SSL_CONN_CONFIG(verifyhost)) {
    result = verifyhost(data, conn, backend->server_cert);
    if(result) {
      X509_free(backend->server_cert);
      backend->server_cert = NULL;
      return result;
    }
  }

  rc = x509_name_oneline(X509_get_issuer_name(backend->server_cert), buffer, sizeof(buffer));
  if(rc) {
    if(strict)
      failf(data, "SSL: couldn't get X509-issuer name!");
    result = CURLE_PEER_FAILED_VERIFICATION;
  }
  else {
    infof(data, " issuer: %s\n", buffer);

    

    
    if(SSL_SET_OPTION(issuercert) || SSL_SET_OPTION(issuercert_blob)) {
      if(SSL_SET_OPTION(issuercert_blob))
        fp = BIO_new_mem_buf(SSL_SET_OPTION(issuercert_blob)->data, (int)SSL_SET_OPTION(issuercert_blob)->len);
      else {
        fp = BIO_new(BIO_s_file());
        if(fp == NULL) {
          failf(data, "BIO_new return NULL, " OSSL_PACKAGE " error %s", ossl_strerror(ERR_get_error(), error_buffer, sizeof(error_buffer)) );



          X509_free(backend->server_cert);
          backend->server_cert = NULL;
          return CURLE_OUT_OF_MEMORY;
        }

        if(BIO_read_filename(fp, SSL_SET_OPTION(issuercert)) <= 0) {
          if(strict)
            failf(data, "SSL: Unable to open issuer cert (%s)", SSL_SET_OPTION(issuercert));
          BIO_free(fp);
          X509_free(backend->server_cert);
          backend->server_cert = NULL;
          return CURLE_SSL_ISSUER_ERROR;
        }
      }

      issuer = PEM_read_bio_X509(fp, NULL, ZERO_NULL, NULL);
      if(!issuer) {
        if(strict)
          failf(data, "SSL: Unable to read issuer cert (%s)", SSL_SET_OPTION(issuercert));
        BIO_free(fp);
        X509_free(issuer);
        X509_free(backend->server_cert);
        backend->server_cert = NULL;
        return CURLE_SSL_ISSUER_ERROR;
      }

      if(X509_check_issued(issuer, backend->server_cert) != X509_V_OK) {
        if(strict)
          failf(data, "SSL: Certificate issuer check failed (%s)", SSL_SET_OPTION(issuercert));
        BIO_free(fp);
        X509_free(issuer);
        X509_free(backend->server_cert);
        backend->server_cert = NULL;
        return CURLE_SSL_ISSUER_ERROR;
      }

      infof(data, " SSL certificate issuer check ok (%s)\n", SSL_SET_OPTION(issuercert));
      BIO_free(fp);
      X509_free(issuer);
    }

    lerr = SSL_get_verify_result(backend->handle);
    SSL_SET_OPTION_LVALUE(certverifyresult) = lerr;
    if(lerr != X509_V_OK) {
      if(SSL_CONN_CONFIG(verifypeer)) {
        
        if(strict)
          failf(data, "SSL certificate verify result: %s (%ld)", X509_verify_cert_error_string(lerr), lerr);
        result = CURLE_PEER_FAILED_VERIFICATION;
      }
      else infof(data, " SSL certificate verify result: %s (%ld)," " continuing anyway.\n", X509_verify_cert_error_string(lerr), lerr);


    }
    else infof(data, " SSL certificate verify ok.\n");
  }


  if(SSL_CONN_CONFIG(verifystatus)) {
    result = verifystatus(data, connssl);
    if(result) {
      X509_free(backend->server_cert);
      backend->server_cert = NULL;
      return result;
    }
  }


  if(!strict)
    
    result = CURLE_OK;

  ptr = SSL_IS_PROXY() ? data->set.str[STRING_SSL_PINNEDPUBLICKEY_PROXY] :
    data->set.str[STRING_SSL_PINNEDPUBLICKEY];
  if(!result && ptr) {
    result = pkp_pin_peer_pubkey(data, backend->server_cert, ptr);
    if(result)
      failf(data, "SSL: public key does not match pinned public key!");
  }

  X509_free(backend->server_cert);
  backend->server_cert = NULL;
  connssl->connecting_state = ssl_connect_done;

  return result;
}

static CURLcode ossl_connect_step3(struct Curl_easy *data, struct connectdata *conn, int sockindex)
{
  CURLcode result = CURLE_OK;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];

  DEBUGASSERT(ssl_connect_3 == connssl->connecting_state);

  

  result = servercert(data, conn, connssl, (SSL_CONN_CONFIG(verifypeer) || SSL_CONN_CONFIG(verifyhost)));

  if(!result)
    connssl->connecting_state = ssl_connect_done;

  return result;
}

static Curl_recv ossl_recv;
static Curl_send ossl_send;

static CURLcode ossl_connect_common(struct Curl_easy *data, struct connectdata *conn, int sockindex, bool nonblocking, bool *done)



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

    result = ossl_connect_step1(data, conn, sockindex);
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
      if(0 == what) {
        if(nonblocking) {
          *done = FALSE;
          return CURLE_OK;
        }
        
        failf(data, "SSL connection timeout");
        return CURLE_OPERATION_TIMEDOUT;
      }
      
    }

    
    result = ossl_connect_step2(data, conn, sockindex);
    if(result || (nonblocking && (ssl_connect_2 == connssl->connecting_state || ssl_connect_2_reading == connssl->connecting_state || ssl_connect_2_writing == connssl->connecting_state)))


      return result;

  } 

  if(ssl_connect_3 == connssl->connecting_state) {
    result = ossl_connect_step3(data, conn, sockindex);
    if(result)
      return result;
  }

  if(ssl_connect_done == connssl->connecting_state) {
    connssl->state = ssl_connection_complete;
    conn->recv[sockindex] = ossl_recv;
    conn->send[sockindex] = ossl_send;
    *done = TRUE;
  }
  else *done = FALSE;

  
  connssl->connecting_state = ssl_connect_1;

  return CURLE_OK;
}

static CURLcode ossl_connect_nonblocking(struct Curl_easy *data, struct connectdata *conn, int sockindex, bool *done)


{
  return ossl_connect_common(data, conn, sockindex, TRUE, done);
}

static CURLcode ossl_connect(struct Curl_easy *data, struct connectdata *conn, int sockindex)
{
  CURLcode result;
  bool done = FALSE;

  result = ossl_connect_common(data, conn, sockindex, FALSE, &done);
  if(result)
    return result;

  DEBUGASSERT(done);

  return CURLE_OK;
}

static bool ossl_data_pending(const struct connectdata *conn, int connindex)
{
  const struct ssl_connect_data *connssl = &conn->ssl[connindex];
  if(connssl->backend->handle && SSL_pending(connssl->backend->handle))
    return TRUE;

  {
    const struct ssl_connect_data *proxyssl = &conn->proxy_ssl[connindex];
    if(proxyssl->backend->handle && SSL_pending(proxyssl->backend->handle))
      return TRUE;
  }

  return FALSE;
}

static size_t ossl_version(char *buffer, size_t size);

static ssize_t ossl_send(struct Curl_easy *data, int sockindex, const void *mem, size_t len, CURLcode *curlcode)



{
  
  int err;
  char error_buffer[256];
  unsigned long sslerror;
  int memlen;
  int rc;
  struct connectdata *conn = data->conn;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  struct ssl_backend_data *backend = connssl->backend;

  ERR_clear_error();

  memlen = (len > (size_t)INT_MAX) ? INT_MAX : (int)len;
  set_logger(conn, data);
  rc = SSL_write(backend->handle, mem, memlen);

  if(rc <= 0) {
    err = SSL_get_error(backend->handle, rc);

    switch(err) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      
      *curlcode = CURLE_AGAIN;
      return -1;
    case SSL_ERROR_SYSCALL:
      {
        int sockerr = SOCKERRNO;
        sslerror = ERR_get_error();
        if(sslerror)
          ossl_strerror(sslerror, error_buffer, sizeof(error_buffer));
        else if(sockerr)
          Curl_strerror(sockerr, error_buffer, sizeof(error_buffer));
        else {
          strncpy(error_buffer, SSL_ERROR_to_str(err), sizeof(error_buffer));
          error_buffer[sizeof(error_buffer) - 1] = '\0';
        }
        failf(data, OSSL_PACKAGE " SSL_write: %s, errno %d", error_buffer, sockerr);
        *curlcode = CURLE_SEND_ERROR;
        return -1;
      }
    case SSL_ERROR_SSL:
      
      sslerror = ERR_get_error();
      if(ERR_GET_LIB(sslerror) == ERR_LIB_SSL && ERR_GET_REASON(sslerror) == SSL_R_BIO_NOT_SET && conn->ssl[sockindex].state == ssl_connection_complete  && conn->proxy_ssl[sockindex].state == ssl_connection_complete  ) {





        char ver[120];
        ossl_version(ver, 120);
        failf(data, "Error: %s does not support double SSL tunneling.", ver);
      }
      else failf(data, "SSL_write() error: %s", ossl_strerror(sslerror, error_buffer, sizeof(error_buffer)));

      *curlcode = CURLE_SEND_ERROR;
      return -1;
    }
    
    failf(data, OSSL_PACKAGE " SSL_write: %s, errno %d", SSL_ERROR_to_str(err), SOCKERRNO);
    *curlcode = CURLE_SEND_ERROR;
    return -1;
  }
  *curlcode = CURLE_OK;
  return (ssize_t)rc; 
}

static ssize_t ossl_recv(struct Curl_easy *data,    int num, char *buf, size_t buffersize, CURLcode *curlcode)



{
  char error_buffer[256];
  unsigned long sslerror;
  ssize_t nread;
  int buffsize;
  struct connectdata *conn = data->conn;
  struct ssl_connect_data *connssl = &conn->ssl[num];
  struct ssl_backend_data *backend = connssl->backend;

  ERR_clear_error();

  buffsize = (buffersize > (size_t)INT_MAX) ? INT_MAX : (int)buffersize;
  set_logger(conn, data);
  nread = (ssize_t)SSL_read(backend->handle, buf, buffsize);
  if(nread <= 0) {
    
    int err = SSL_get_error(backend->handle, (int)nread);

    switch(err) {
    case SSL_ERROR_NONE: 
      break;
    case SSL_ERROR_ZERO_RETURN: 
      
      if(num == FIRSTSOCKET)
        
        connclose(conn, "TLS close_notify");
      break;
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      
      *curlcode = CURLE_AGAIN;
      return -1;
    default:
      
      
      sslerror = ERR_get_error();
      if((nread < 0) || sslerror) {
        
        int sockerr = SOCKERRNO;
        if(sslerror)
          ossl_strerror(sslerror, error_buffer, sizeof(error_buffer));
        else if(sockerr && err == SSL_ERROR_SYSCALL)
          Curl_strerror(sockerr, error_buffer, sizeof(error_buffer));
        else {
          strncpy(error_buffer, SSL_ERROR_to_str(err), sizeof(error_buffer));
          error_buffer[sizeof(error_buffer) - 1] = '\0';
        }
        failf(data, OSSL_PACKAGE " SSL_read: %s, errno %d", error_buffer, sockerr);
        *curlcode = CURLE_RECV_ERROR;
        return -1;
      }
      

      if(err == SSL_ERROR_SYSCALL) {
        int sockerr = SOCKERRNO;
        if(sockerr)
          Curl_strerror(sockerr, error_buffer, sizeof(error_buffer));
        else {
          msnprintf(error_buffer, sizeof(error_buffer), "Connection closed abruptly");
        }
        failf(data, OSSL_PACKAGE " SSL_read: %s, errno %d" " (Fatal because this is a curl debug build)", error_buffer, sockerr);

        *curlcode = CURLE_RECV_ERROR;
        return -1;
      }

    }
  }
  return nread;
}

static size_t ossl_version(char *buffer, size_t size)
{


  return msnprintf(buffer, size, "%s/%lx.%lx.%lx", OSSL_PACKAGE, (LIBRESSL_VERSION_NUMBER>>28)&0xf, (LIBRESSL_VERSION_NUMBER>>20)&0xff, (LIBRESSL_VERSION_NUMBER>>12)&0xff);




  char *p;
  int count;
  const char *ver = OpenSSL_version(OPENSSL_VERSION);
  const char expected[] = OSSL_PACKAGE " "; 
  if(Curl_strncasecompare(ver, expected, sizeof(expected) - 1)) {
    ver += sizeof(expected) - 1;
  }
  count = msnprintf(buffer, size, "%s/%s", OSSL_PACKAGE, ver);
  for(p = buffer; *p; ++p) {
    if(ISSPACE(*p))
      *p = '_';
  }
  return count;


  return msnprintf(buffer, size, OSSL_PACKAGE);

  return msnprintf(buffer, size, "%s/%s", OSSL_PACKAGE, OpenSSL_version(OPENSSL_VERSION_STRING));

  

  char sub[3];
  unsigned long ssleay_value;
  sub[2]='\0';
  sub[1]='\0';
  ssleay_value = OpenSSL_version_num();
  if(ssleay_value < 0x906000) {
    ssleay_value = SSLEAY_VERSION_NUMBER;
    sub[0]='\0';
  }
  else {
    if(ssleay_value&0xff0) {
      int minor_ver = (ssleay_value >> 4) & 0xff;
      if(minor_ver > 26) {
        
        sub[1] = (char) ((minor_ver - 1) % 26 + 'a' + 1);
        sub[0] = 'z';
      }
      else {
        sub[0] = (char) (minor_ver + 'a' - 1);
      }
    }
    else sub[0]='\0';
  }

  return msnprintf(buffer, size, "%s/%lx.%lx.%lx%s"  "-fips"  , OSSL_PACKAGE, (ssleay_value>>28)&0xf, (ssleay_value>>20)&0xff, (ssleay_value>>12)&0xff, sub);









}


static CURLcode ossl_random(struct Curl_easy *data, unsigned char *entropy, size_t length)
{
  int rc;
  if(data) {
    if(ossl_seed(data)) 
      return CURLE_FAILED_INIT; 
  }
  else {
    if(!rand_enough())
      return CURLE_FAILED_INIT;
  }
  
  rc = RAND_bytes(entropy, curlx_uztosi(length));
  return (rc == 1 ? CURLE_OK : CURLE_FAILED_INIT);
}


static CURLcode ossl_sha256sum(const unsigned char *tmp,  size_t tmplen, unsigned char *sha256sum , size_t unused)


{
  EVP_MD_CTX *mdctx;
  unsigned int len = 0;
  (void) unused;

  mdctx = EVP_MD_CTX_create();
  if(!mdctx)
    return CURLE_OUT_OF_MEMORY;
  EVP_DigestInit(mdctx, EVP_sha256());
  EVP_DigestUpdate(mdctx, tmp, tmplen);
  EVP_DigestFinal_ex(mdctx, sha256sum, &len);
  EVP_MD_CTX_destroy(mdctx);
  return CURLE_OK;
}


static bool ossl_cert_status_request(void)
{

  return TRUE;

  return FALSE;

}

static void *ossl_get_internals(struct ssl_connect_data *connssl, CURLINFO info)
{
  
  struct ssl_backend_data *backend = connssl->backend;
  return info == CURLINFO_TLS_SESSION ? (void *)backend->ctx : (void *)backend->handle;
}

const struct Curl_ssl Curl_ssl_openssl = {
  { CURLSSLBACKEND_OPENSSL, "openssl" },   SSLSUPP_CA_PATH | SSLSUPP_CERTINFO | SSLSUPP_PINNEDPUBKEY | SSLSUPP_SSL_CTX |  SSLSUPP_TLS13_CIPHERSUITES |  SSLSUPP_HTTPS_PROXY,  sizeof(struct ssl_backend_data),  ossl_init, ossl_cleanup, ossl_version, ossl_check_cxn, ossl_shutdown, ossl_data_pending, ossl_random, ossl_cert_status_request, ossl_connect, ossl_connect_nonblocking, Curl_ssl_getsock, ossl_get_internals, ossl_close, ossl_close_all, ossl_session_free, ossl_set_engine, ossl_set_engine_default, ossl_engines_list, Curl_none_false_start,  ossl_sha256sum  NULL  };






































