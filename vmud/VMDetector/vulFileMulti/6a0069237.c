























































static CURLcode blobdup(struct curl_blob **dest, struct curl_blob *src)
{
  DEBUGASSERT(dest);
  DEBUGASSERT(!*dest);
  if(src) {
    
    struct curl_blob *d;
    d = malloc(sizeof(struct curl_blob) + src->len);
    if(!d)
      return CURLE_OUT_OF_MEMORY;
    d->len = src->len;
    
    d->flags = CURL_BLOB_COPY;
    d->data = (void *)((char *)d + sizeof(struct curl_blob));
    memcpy(d->data, src->data, src->len);
    *dest = d;
  }
  return CURLE_OK;
}


static bool blobcmp(struct curl_blob *first, struct curl_blob *second)
{
  if(!first && !second) 
    return TRUE;
  if(!first || !second) 
    return FALSE;
  if(first->len != second->len) 
    return FALSE;
  return !memcmp(first->data, second->data, first->len); 
}

bool Curl_ssl_config_matches(struct ssl_primary_config *data, struct ssl_primary_config *needle)

{
  if((data->version == needle->version) && (data->version_max == needle->version_max) && (data->verifypeer == needle->verifypeer) && (data->verifyhost == needle->verifyhost) && (data->verifystatus == needle->verifystatus) && blobcmp(data->cert_blob, needle->cert_blob) && Curl_safe_strcasecompare(data->CApath, needle->CApath) && Curl_safe_strcasecompare(data->CAfile, needle->CAfile) && Curl_safe_strcasecompare(data->clientcert, needle->clientcert) && Curl_safe_strcasecompare(data->random_file, needle->random_file) && Curl_safe_strcasecompare(data->egdsocket, needle->egdsocket) && Curl_safe_strcasecompare(data->cipher_list, needle->cipher_list) && Curl_safe_strcasecompare(data->cipher_list13, needle->cipher_list13) && Curl_safe_strcasecompare(data->curves, needle->curves) && Curl_safe_strcasecompare(data->pinned_key, needle->pinned_key))













    return TRUE;

  return FALSE;
}

bool Curl_clone_primary_ssl_config(struct ssl_primary_config *source, struct ssl_primary_config *dest)

{
  dest->version = source->version;
  dest->version_max = source->version_max;
  dest->verifypeer = source->verifypeer;
  dest->verifyhost = source->verifyhost;
  dest->verifystatus = source->verifystatus;
  dest->sessionid = source->sessionid;

  CLONE_BLOB(cert_blob);
  CLONE_STRING(CApath);
  CLONE_STRING(CAfile);
  CLONE_STRING(clientcert);
  CLONE_STRING(random_file);
  CLONE_STRING(egdsocket);
  CLONE_STRING(cipher_list);
  CLONE_STRING(cipher_list13);
  CLONE_STRING(pinned_key);
  CLONE_STRING(curves);

  return TRUE;
}

void Curl_free_primary_ssl_config(struct ssl_primary_config *sslc)
{
  Curl_safefree(sslc->CApath);
  Curl_safefree(sslc->CAfile);
  Curl_safefree(sslc->clientcert);
  Curl_safefree(sslc->random_file);
  Curl_safefree(sslc->egdsocket);
  Curl_safefree(sslc->cipher_list);
  Curl_safefree(sslc->cipher_list13);
  Curl_safefree(sslc->pinned_key);
  Curl_safefree(sslc->cert_blob);
  Curl_safefree(sslc->curves);
}


static int multissl_setup(const struct Curl_ssl *backend);


int Curl_ssl_backend(void)
{

  multissl_setup(NULL);
  return Curl_ssl->info.id;

  return (int)CURLSSLBACKEND_NONE;

}




static bool init_ssl = FALSE;


int Curl_ssl_init(void)
{
  
  if(init_ssl)
    return 1;
  init_ssl = TRUE; 

  return Curl_ssl->init();
}


static const struct Curl_ssl Curl_ssl_multi;



void Curl_ssl_cleanup(void)
{
  if(init_ssl) {
    
    Curl_ssl->cleanup();

    Curl_ssl = &Curl_ssl_multi;

    init_ssl = FALSE;
  }
}

static bool ssl_prefs_check(struct Curl_easy *data)
{
  
  const long sslver = data->set.ssl.primary.version;
  if((sslver < 0) || (sslver >= CURL_SSLVERSION_LAST)) {
    failf(data, "Unrecognized parameter value passed via CURLOPT_SSLVERSION");
    return FALSE;
  }

  switch(data->set.ssl.primary.version_max) {
  case CURL_SSLVERSION_MAX_NONE:
  case CURL_SSLVERSION_MAX_DEFAULT:
    break;

  default:
    if((data->set.ssl.primary.version_max >> 16) < sslver) {
      failf(data, "CURL_SSLVERSION_MAX incompatible with CURL_SSLVERSION");
      return FALSE;
    }
  }

  return TRUE;
}


static CURLcode ssl_connect_init_proxy(struct connectdata *conn, int sockindex)
{
  DEBUGASSERT(conn->bits.proxy_ssl_connected[sockindex]);
  if(ssl_connection_complete == conn->ssl[sockindex].state && !conn->proxy_ssl[sockindex].use) {
    struct ssl_backend_data *pbdata;

    if(!(Curl_ssl->supports & SSLSUPP_HTTPS_PROXY))
      return CURLE_NOT_BUILT_IN;

    
    pbdata = conn->proxy_ssl[sockindex].backend;
    conn->proxy_ssl[sockindex] = conn->ssl[sockindex];

    memset(&conn->ssl[sockindex], 0, sizeof(conn->ssl[sockindex]));
    memset(pbdata, 0, Curl_ssl->sizeof_ssl_backend_data);

    conn->ssl[sockindex].backend = pbdata;
  }
  return CURLE_OK;
}


CURLcode Curl_ssl_connect(struct Curl_easy *data, struct connectdata *conn, int sockindex)

{
  CURLcode result;


  if(conn->bits.proxy_ssl_connected[sockindex]) {
    result = ssl_connect_init_proxy(conn, sockindex);
    if(result)
      return result;
  }


  if(!ssl_prefs_check(data))
    return CURLE_SSL_CONNECT_ERROR;

  
  conn->ssl[sockindex].use = TRUE;
  conn->ssl[sockindex].state = ssl_connection_negotiating;

  result = Curl_ssl->connect_blocking(data, conn, sockindex);

  if(!result)
    Curl_pgrsTime(data, TIMER_APPCONNECT); 

  return result;
}

CURLcode Curl_ssl_connect_nonblocking(struct Curl_easy *data, struct connectdata *conn, int sockindex, bool *done)

{
  CURLcode result;


  if(conn->bits.proxy_ssl_connected[sockindex]) {
    result = ssl_connect_init_proxy(conn, sockindex);
    if(result)
      return result;
  }

  if(!ssl_prefs_check(data))
    return CURLE_SSL_CONNECT_ERROR;

  
  conn->ssl[sockindex].use = TRUE;
  result = Curl_ssl->connect_nonblocking(data, conn, sockindex, done);
  if(!result && *done)
    Curl_pgrsTime(data, TIMER_APPCONNECT); 
  return result;
}


void Curl_ssl_sessionid_lock(struct Curl_easy *data)
{
  if(SSLSESSION_SHARED(data))
    Curl_share_lock(data, CURL_LOCK_DATA_SSL_SESSION, CURL_LOCK_ACCESS_SINGLE);
}


void Curl_ssl_sessionid_unlock(struct Curl_easy *data)
{
  if(SSLSESSION_SHARED(data))
    Curl_share_unlock(data, CURL_LOCK_DATA_SSL_SESSION);
}


bool Curl_ssl_getsessionid(struct Curl_easy *data, struct connectdata *conn, void **ssl_sessionid, size_t *idsize, int sockindex)



{
  struct Curl_ssl_session *check;
  size_t i;
  long *general_age;
  bool no_match = TRUE;


  const bool isProxy = CONNECT_PROXY_SSL();
  struct ssl_primary_config * const ssl_config = isProxy ? &conn->proxy_ssl_config :
    &conn->ssl_config;
  const char * const name = isProxy ? conn->http_proxy.host.name : conn->host.name;
  int port = isProxy ? (int)conn->port : conn->remote_port;

  
  struct ssl_primary_config * const ssl_config = &conn->ssl_config;
  const char * const name = conn->host.name;
  int port = conn->remote_port;
  (void)sockindex;

  *ssl_sessionid = NULL;

  DEBUGASSERT(SSL_SET_OPTION(primary.sessionid));

  if(!SSL_SET_OPTION(primary.sessionid))
    
    return TRUE;

  
  if(SSLSESSION_SHARED(data))
    general_age = &data->share->sessionage;
  else general_age = &data->state.sessionage;

  for(i = 0; i < data->set.general_ssl.max_ssl_sessions; i++) {
    check = &data->state.session[i];
    if(!check->sessionid)
      
      continue;
    if(strcasecompare(name, check->name) && ((!conn->bits.conn_to_host && !check->conn_to_host) || (conn->bits.conn_to_host && check->conn_to_host && strcasecompare(conn->conn_to_host.name, check->conn_to_host))) && ((!conn->bits.conn_to_port && check->conn_to_port == -1) || (conn->bits.conn_to_port && check->conn_to_port != -1 && conn->conn_to_port == check->conn_to_port)) && (port == check->remote_port) && strcasecompare(conn->handler->scheme, check->scheme) && Curl_ssl_config_matches(ssl_config, &check->ssl_config)) {








      
      (*general_age)++;          
      check->age = *general_age; 
      *ssl_sessionid = check->sessionid;
      if(idsize)
        *idsize = check->idsize;
      no_match = FALSE;
      break;
    }
  }

  return no_match;
}


void Curl_ssl_kill_session(struct Curl_ssl_session *session)
{
  if(session->sessionid) {
    

    
    Curl_ssl->session_free(session->sessionid);

    session->sessionid = NULL;
    session->age = 0; 

    Curl_free_primary_ssl_config(&session->ssl_config);

    Curl_safefree(session->name);
    Curl_safefree(session->conn_to_host);
  }
}


void Curl_ssl_delsessionid(struct Curl_easy *data, void *ssl_sessionid)
{
  size_t i;

  for(i = 0; i < data->set.general_ssl.max_ssl_sessions; i++) {
    struct Curl_ssl_session *check = &data->state.session[i];

    if(check->sessionid == ssl_sessionid) {
      Curl_ssl_kill_session(check);
      break;
    }
  }
}


CURLcode Curl_ssl_addsessionid(struct Curl_easy *data, struct connectdata *conn, void *ssl_sessionid, size_t idsize, int sockindex)



{
  size_t i;
  struct Curl_ssl_session *store = &data->state.session[0];
  long oldest_age = data->state.session[0].age; 
  char *clone_host;
  char *clone_conn_to_host;
  int conn_to_port;
  long *general_age;

  const bool isProxy = CONNECT_PROXY_SSL();
  struct ssl_primary_config * const ssl_config = isProxy ? &conn->proxy_ssl_config :
    &conn->ssl_config;
  const char *hostname = isProxy ? conn->http_proxy.host.name :
    conn->host.name;

  
  const bool isProxy = FALSE;
  struct ssl_primary_config * const ssl_config = &conn->ssl_config;
  const char *hostname = conn->host.name;
  (void)sockindex;

  DEBUGASSERT(SSL_SET_OPTION(primary.sessionid));

  clone_host = strdup(hostname);
  if(!clone_host)
    return CURLE_OUT_OF_MEMORY; 

  if(conn->bits.conn_to_host) {
    clone_conn_to_host = strdup(conn->conn_to_host.name);
    if(!clone_conn_to_host) {
      free(clone_host);
      return CURLE_OUT_OF_MEMORY; 
    }
  }
  else clone_conn_to_host = NULL;

  if(conn->bits.conn_to_port)
    conn_to_port = conn->conn_to_port;
  else conn_to_port = -1;

  

  
  if(SSLSESSION_SHARED(data)) {
    general_age = &data->share->sessionage;
  }
  else {
    general_age = &data->state.sessionage;
  }

  
  for(i = 1; (i < data->set.general_ssl.max_ssl_sessions) && data->state.session[i].sessionid; i++) {
    if(data->state.session[i].age < oldest_age) {
      oldest_age = data->state.session[i].age;
      store = &data->state.session[i];
    }
  }
  if(i == data->set.general_ssl.max_ssl_sessions)
    
    Curl_ssl_kill_session(store);
  else store = &data->state.session[i];

  
  store->sessionid = ssl_sessionid;
  store->idsize = idsize;
  store->age = *general_age;    
  
  free(store->name);
  free(store->conn_to_host);
  store->name = clone_host;               
  store->conn_to_host = clone_conn_to_host; 
  store->conn_to_port = conn_to_port; 
  
  store->remote_port = isProxy ? (int)conn->port : conn->remote_port;
  store->scheme = conn->handler->scheme;

  if(!Curl_clone_primary_ssl_config(ssl_config, &store->ssl_config)) {
    Curl_free_primary_ssl_config(&store->ssl_config);
    store->sessionid = NULL; 
    free(clone_host);
    free(clone_conn_to_host);
    return CURLE_OUT_OF_MEMORY;
  }

  return CURLE_OK;
}


void Curl_ssl_close_all(struct Curl_easy *data)
{
  
  if(data->state.session && !SSLSESSION_SHARED(data)) {
    size_t i;
    for(i = 0; i < data->set.general_ssl.max_ssl_sessions; i++)
      
      Curl_ssl_kill_session(&data->state.session[i]);

    
    Curl_safefree(data->state.session);
  }

  Curl_ssl->close_all(data);
}

int Curl_ssl_getsock(struct connectdata *conn, curl_socket_t *socks)
{
  struct ssl_connect_data *connssl = &conn->ssl[FIRSTSOCKET];

  if(connssl->connecting_state == ssl_connect_2_writing) {
    
    socks[0] = conn->sock[FIRSTSOCKET];
    return GETSOCK_WRITESOCK(0);
  }
  if(connssl->connecting_state == ssl_connect_2_reading) {
    
    socks[0] = conn->sock[FIRSTSOCKET];
    return GETSOCK_READSOCK(0);
  }

  return GETSOCK_BLANK;
}

void Curl_ssl_close(struct Curl_easy *data, struct connectdata *conn, int sockindex)
{
  DEBUGASSERT((sockindex <= 1) && (sockindex >= -1));
  Curl_ssl->close_one(data, conn, sockindex);
  conn->ssl[sockindex].state = ssl_connection_none;
}

CURLcode Curl_ssl_shutdown(struct Curl_easy *data, struct connectdata *conn, int sockindex)
{
  if(Curl_ssl->shut_down(data, conn, sockindex))
    return CURLE_SSL_SHUTDOWN_FAILED;

  conn->ssl[sockindex].use = FALSE; 
  conn->ssl[sockindex].state = ssl_connection_none;

  conn->recv[sockindex] = Curl_recv_plain;
  conn->send[sockindex] = Curl_send_plain;

  return CURLE_OK;
}


CURLcode Curl_ssl_set_engine(struct Curl_easy *data, const char *engine)
{
  return Curl_ssl->set_engine(data, engine);
}


CURLcode Curl_ssl_set_engine_default(struct Curl_easy *data)
{
  return Curl_ssl->set_engine_default(data);
}


struct curl_slist *Curl_ssl_engines_list(struct Curl_easy *data)
{
  return Curl_ssl->engines_list(data);
}


CURLcode Curl_ssl_initsessions(struct Curl_easy *data, size_t amount)
{
  struct Curl_ssl_session *session;

  if(data->state.session)
    
    return CURLE_OK;

  session = calloc(amount, sizeof(struct Curl_ssl_session));
  if(!session)
    return CURLE_OUT_OF_MEMORY;

  
  data->set.general_ssl.max_ssl_sessions = amount;
  data->state.session = session;
  data->state.sessionage = 1; 
  return CURLE_OK;
}

static size_t multissl_version(char *buffer, size_t size);

size_t Curl_ssl_version(char *buffer, size_t size)
{

  return multissl_version(buffer, size);

  return Curl_ssl->version(buffer, size);

}


int Curl_ssl_check_cxn(struct connectdata *conn)
{
  return Curl_ssl->check_cxn(conn);
}

bool Curl_ssl_data_pending(const struct connectdata *conn, int connindex)
{
  return Curl_ssl->data_pending(conn, connindex);
}

void Curl_ssl_free_certinfo(struct Curl_easy *data)
{
  struct curl_certinfo *ci = &data->info.certs;

  if(ci->num_of_certs) {
    
    int i;
    for(i = 0; i<ci->num_of_certs; i++) {
      curl_slist_free_all(ci->certinfo[i]);
      ci->certinfo[i] = NULL;
    }

    free(ci->certinfo); 
    ci->certinfo = NULL;
    ci->num_of_certs = 0;
  }
}

CURLcode Curl_ssl_init_certinfo(struct Curl_easy *data, int num)
{
  struct curl_certinfo *ci = &data->info.certs;
  struct curl_slist **table;

  
  Curl_ssl_free_certinfo(data);

  
  table = calloc((size_t) num, sizeof(struct curl_slist *));
  if(!table)
    return CURLE_OUT_OF_MEMORY;

  ci->num_of_certs = num;
  ci->certinfo = table;

  return CURLE_OK;
}


CURLcode Curl_ssl_push_certinfo_len(struct Curl_easy *data, int certnum, const char *label, const char *value, size_t valuelen)



{
  struct curl_certinfo *ci = &data->info.certs;
  char *output;
  struct curl_slist *nl;
  CURLcode result = CURLE_OK;
  size_t labellen = strlen(label);
  size_t outlen = labellen + 1 + valuelen + 1; 

  output = malloc(outlen);
  if(!output)
    return CURLE_OUT_OF_MEMORY;

  
  msnprintf(output, outlen, "%s:", label);

  
  memcpy(&output[labellen + 1], value, valuelen);

  
  output[labellen + 1 + valuelen] = 0;

  nl = Curl_slist_append_nodup(ci->certinfo[certnum], output);
  if(!nl) {
    free(output);
    curl_slist_free_all(ci->certinfo[certnum]);
    result = CURLE_OUT_OF_MEMORY;
  }

  ci->certinfo[certnum] = nl;
  return result;
}


CURLcode Curl_ssl_push_certinfo(struct Curl_easy *data, int certnum, const char *label, const char *value)


{
  size_t valuelen = strlen(value);

  return Curl_ssl_push_certinfo_len(data, certnum, label, value, valuelen);
}

CURLcode Curl_ssl_random(struct Curl_easy *data, unsigned char *entropy, size_t length)

{
  return Curl_ssl->random(data, entropy, length);
}



static CURLcode pubkey_pem_to_der(const char *pem, unsigned char **der, size_t *der_len)
{
  char *stripped_pem, *begin_pos, *end_pos;
  size_t pem_count, stripped_pem_count = 0, pem_len;
  CURLcode result;

  
  if(!pem)
    return CURLE_BAD_CONTENT_ENCODING;

  begin_pos = strstr(pem, "-----BEGIN PUBLIC KEY-----");
  if(!begin_pos)
    return CURLE_BAD_CONTENT_ENCODING;

  pem_count = begin_pos - pem;
  
  if(0 != pem_count && '\n' != pem[pem_count - 1])
    return CURLE_BAD_CONTENT_ENCODING;

  
  pem_count += 26;

  
  end_pos = strstr(pem + pem_count, "\n-----END PUBLIC KEY-----");
  if(!end_pos)
    return CURLE_BAD_CONTENT_ENCODING;

  pem_len = end_pos - pem;

  stripped_pem = malloc(pem_len - pem_count + 1);
  if(!stripped_pem)
    return CURLE_OUT_OF_MEMORY;

  
  while(pem_count < pem_len) {
    if('\n' != pem[pem_count] && '\r' != pem[pem_count])
      stripped_pem[stripped_pem_count++] = pem[pem_count];
    ++pem_count;
  }
  
  stripped_pem[stripped_pem_count] = '\0';

  result = Curl_base64_decode(stripped_pem, der, der_len);

  Curl_safefree(stripped_pem);

  return result;
}



CURLcode Curl_pin_peer_pubkey(struct Curl_easy *data, const char *pinnedpubkey, const unsigned char *pubkey, size_t pubkeylen)

{
  FILE *fp;
  unsigned char *buf = NULL, *pem_ptr = NULL;
  CURLcode result = CURLE_SSL_PINNEDPUBKEYNOTMATCH;

  
  if(!pinnedpubkey)
    return CURLE_OK;
  if(!pubkey || !pubkeylen)
    return result;

  
  if(strncmp(pinnedpubkey, "sha256//", 8) == 0) {
    CURLcode encode;
    size_t encodedlen, pinkeylen;
    char *encoded, *pinkeycopy, *begin_pos, *end_pos;
    unsigned char *sha256sumdigest;

    if(!Curl_ssl->sha256sum) {
      
      return result;
    }

    
    sha256sumdigest = malloc(CURL_SHA256_DIGEST_LENGTH);
    if(!sha256sumdigest)
      return CURLE_OUT_OF_MEMORY;
    encode = Curl_ssl->sha256sum(pubkey, pubkeylen, sha256sumdigest, CURL_SHA256_DIGEST_LENGTH);

    if(encode != CURLE_OK)
      return encode;

    encode = Curl_base64_encode(data, (char *)sha256sumdigest, CURL_SHA256_DIGEST_LENGTH, &encoded, &encodedlen);

    Curl_safefree(sha256sumdigest);

    if(encode)
      return encode;

    infof(data, "\t public key hash: sha256//%s\n", encoded);

    
    pinkeylen = strlen(pinnedpubkey) + 1;
    pinkeycopy = malloc(pinkeylen);
    if(!pinkeycopy) {
      Curl_safefree(encoded);
      return CURLE_OUT_OF_MEMORY;
    }
    memcpy(pinkeycopy, pinnedpubkey, pinkeylen);
    
    begin_pos = pinkeycopy;
    do {
      end_pos = strstr(begin_pos, ";sha256//");
      
      if(end_pos)
        end_pos[0] = '\0';

      
      if(encodedlen == strlen(begin_pos + 8) && !memcmp(encoded, begin_pos + 8, encodedlen)) {
        result = CURLE_OK;
        break;
      }

      
      if(end_pos) {
        end_pos[0] = ';';
        begin_pos = strstr(end_pos, "sha256//");
      }
    } while(end_pos && begin_pos);
    Curl_safefree(encoded);
    Curl_safefree(pinkeycopy);
    return result;
  }

  fp = fopen(pinnedpubkey, "rb");
  if(!fp)
    return result;

  do {
    long filesize;
    size_t size, pem_len;
    CURLcode pem_read;

    
    if(fseek(fp, 0, SEEK_END))
      break;
    filesize = ftell(fp);
    if(fseek(fp, 0, SEEK_SET))
      break;
    if(filesize < 0 || filesize > MAX_PINNED_PUBKEY_SIZE)
      break;

    
    size = curlx_sotouz((curl_off_t) filesize);
    if(pubkeylen > size)
      break;

    
    buf = malloc(size + 1);
    if(!buf)
      break;

    
    if((int) fread(buf, size, 1, fp) != 1)
      break;

    
    if(pubkeylen == size) {
      if(!memcmp(pubkey, buf, pubkeylen))
        result = CURLE_OK;
      break;
    }

    
    buf[size] = '\0';
    pem_read = pubkey_pem_to_der((const char *)buf, &pem_ptr, &pem_len);
    
    if(pem_read)
      break;

    
    if(pubkeylen == pem_len && !memcmp(pubkey, pem_ptr, pubkeylen))
      result = CURLE_OK;
  } while(0);

  Curl_safefree(buf);
  Curl_safefree(pem_ptr);
  fclose(fp);

  return result;
}


bool Curl_ssl_cert_status_request(void)
{
  return Curl_ssl->cert_status_request();
}


bool Curl_ssl_false_start(void)
{
  return Curl_ssl->false_start();
}


bool Curl_ssl_tls13_ciphersuites(void)
{
  return Curl_ssl->supports & SSLSUPP_TLS13_CIPHERSUITES;
}



int Curl_none_init(void)
{
  return 1;
}

void Curl_none_cleanup(void)
{ }

int Curl_none_shutdown(struct Curl_easy *data UNUSED_PARAM, struct connectdata *conn UNUSED_PARAM, int sockindex UNUSED_PARAM)

{
  (void)data;
  (void)conn;
  (void)sockindex;
  return 0;
}

int Curl_none_check_cxn(struct connectdata *conn UNUSED_PARAM)
{
  (void)conn;
  return -1;
}

CURLcode Curl_none_random(struct Curl_easy *data UNUSED_PARAM, unsigned char *entropy UNUSED_PARAM, size_t length UNUSED_PARAM)

{
  (void)data;
  (void)entropy;
  (void)length;
  return CURLE_NOT_BUILT_IN;
}

void Curl_none_close_all(struct Curl_easy *data UNUSED_PARAM)
{
  (void)data;
}

void Curl_none_session_free(void *ptr UNUSED_PARAM)
{
  (void)ptr;
}

bool Curl_none_data_pending(const struct connectdata *conn UNUSED_PARAM, int connindex UNUSED_PARAM)
{
  (void)conn;
  (void)connindex;
  return 0;
}

bool Curl_none_cert_status_request(void)
{
  return FALSE;
}

CURLcode Curl_none_set_engine(struct Curl_easy *data UNUSED_PARAM, const char *engine UNUSED_PARAM)
{
  (void)data;
  (void)engine;
  return CURLE_NOT_BUILT_IN;
}

CURLcode Curl_none_set_engine_default(struct Curl_easy *data UNUSED_PARAM)
{
  (void)data;
  return CURLE_NOT_BUILT_IN;
}

struct curl_slist *Curl_none_engines_list(struct Curl_easy *data UNUSED_PARAM)
{
  (void)data;
  return (struct curl_slist *)NULL;
}

bool Curl_none_false_start(void)
{
  return FALSE;
}

static int multissl_init(void)
{
  if(multissl_setup(NULL))
    return 1;
  return Curl_ssl->init();
}

static CURLcode multissl_connect(struct Curl_easy *data, struct connectdata *conn, int sockindex)
{
  if(multissl_setup(NULL))
    return CURLE_FAILED_INIT;
  return Curl_ssl->connect_blocking(data, conn, sockindex);
}

static CURLcode multissl_connect_nonblocking(struct Curl_easy *data, struct connectdata *conn, int sockindex, bool *done)

{
  if(multissl_setup(NULL))
    return CURLE_FAILED_INIT;
  return Curl_ssl->connect_nonblocking(data, conn, sockindex, done);
}

static int multissl_getsock(struct connectdata *conn, curl_socket_t *socks)
{
  if(multissl_setup(NULL))
    return 0;
  return Curl_ssl->getsock(conn, socks);
}

static void *multissl_get_internals(struct ssl_connect_data *connssl, CURLINFO info)
{
  if(multissl_setup(NULL))
    return NULL;
  return Curl_ssl->get_internals(connssl, info);
}

static void multissl_close(struct Curl_easy *data, struct connectdata *conn, int sockindex)
{
  if(multissl_setup(NULL))
    return;
  Curl_ssl->close_one(data, conn, sockindex);
}

static const struct Curl_ssl Curl_ssl_multi = {
  { CURLSSLBACKEND_NONE, "multi" },   0, (size_t)-1,  multissl_init, Curl_none_cleanup, multissl_version, Curl_none_check_cxn, Curl_none_shutdown, Curl_none_data_pending, Curl_none_random, Curl_none_cert_status_request, multissl_connect, multissl_connect_nonblocking, multissl_getsock, multissl_get_internals, multissl_close, Curl_none_close_all, Curl_none_session_free, Curl_none_set_engine, Curl_none_set_engine_default, Curl_none_engines_list, Curl_none_false_start, NULL };
























const struct Curl_ssl *Curl_ssl =  &Curl_ssl_multi;


  &Curl_ssl_wolfssl;

  &Curl_ssl_sectransp;

  &Curl_ssl_gnutls;

  &Curl_ssl_gskit;

  &Curl_ssl_mbedtls;

  &Curl_ssl_nss;

  &Curl_ssl_rustls;

  &Curl_ssl_openssl;

  &Curl_ssl_schannel;

  &Curl_ssl_mesalink;

  &Curl_ssl_bearssl;




static const struct Curl_ssl *available_backends[] = {

  &Curl_ssl_wolfssl,   &Curl_ssl_sectransp,   &Curl_ssl_gnutls,   &Curl_ssl_gskit,   &Curl_ssl_mbedtls,   &Curl_ssl_nss,   &Curl_ssl_openssl,   &Curl_ssl_schannel,   &Curl_ssl_mesalink,   &Curl_ssl_bearssl,   &Curl_ssl_rustls,  NULL };

































static size_t multissl_version(char *buffer, size_t size)
{
  static const struct Curl_ssl *selected;
  static char backends[200];
  static size_t backends_len;
  const struct Curl_ssl *current;

  current = Curl_ssl == &Curl_ssl_multi ? available_backends[0] : Curl_ssl;

  if(current != selected) {
    char *p = backends;
    char *end = backends + sizeof(backends);
    int i;

    selected = current;

    backends[0] = '\0';

    for(i = 0; available_backends[i]; ++i) {
      char vb[200];
      bool paren = (selected != available_backends[i]);

      if(available_backends[i]->version(vb, sizeof(vb))) {
        p += msnprintf(p, end - p, "%s%s%s%s", (p != backends ? " " : ""), (paren ? "(" : ""), vb, (paren ? ")" : ""));
      }
    }

    backends_len = p - backends;
  }

  if(!size)
    return 0;

  if(size <= backends_len) {
    strncpy(buffer, backends, size - 1);
    buffer[size - 1] = '\0';
    return size - 1;
  }

  strcpy(buffer, backends);
  return backends_len;
}

static int multissl_setup(const struct Curl_ssl *backend)
{
  const char *env;
  char *env_tmp;

  if(Curl_ssl != &Curl_ssl_multi)
    return 1;

  if(backend) {
    Curl_ssl = backend;
    return 0;
  }

  if(!available_backends[0])
    return 1;

  env = env_tmp = curl_getenv("CURL_SSL_BACKEND");

  if(!env)
    env = CURL_DEFAULT_SSL_BACKEND;

  if(env) {
    int i;
    for(i = 0; available_backends[i]; i++) {
      if(strcasecompare(env, available_backends[i]->info.name)) {
        Curl_ssl = available_backends[i];
        curl_free(env_tmp);
        return 0;
      }
    }
  }

  
  Curl_ssl = available_backends[0];
  curl_free(env_tmp);
  return 0;
}

CURLsslset curl_global_sslset(curl_sslbackend id, const char *name, const curl_ssl_backend ***avail)
{
  int i;

  if(avail)
    *avail = (const curl_ssl_backend **)&available_backends;

  if(Curl_ssl != &Curl_ssl_multi)
    return id == Curl_ssl->info.id || (name && strcasecompare(name, Curl_ssl->info.name)) ? CURLSSLSET_OK :


           CURLSSLSET_TOO_LATE;

           CURLSSLSET_UNKNOWN_BACKEND;


  for(i = 0; available_backends[i]; i++) {
    if(available_backends[i]->info.id == id || (name && strcasecompare(available_backends[i]->info.name, name))) {
      multissl_setup(available_backends[i]);
      return CURLSSLSET_OK;
    }
  }

  return CURLSSLSET_UNKNOWN_BACKEND;
}


CURLsslset curl_global_sslset(curl_sslbackend id, const char *name, const curl_ssl_backend ***avail)
{
  (void)id;
  (void)name;
  (void)avail;
  return CURLSSLSET_NO_BACKENDS;
}


