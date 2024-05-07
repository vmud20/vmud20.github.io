















































bool Curl_ssl_config_matches(struct ssl_primary_config* data, struct ssl_primary_config* needle)

{
  if((data->version == needle->version) && (data->version_max == needle->version_max) && (data->verifypeer == needle->verifypeer) && (data->verifyhost == needle->verifyhost) && Curl_safe_strcasecompare(data->CApath, needle->CApath) && Curl_safe_strcasecompare(data->CAfile, needle->CAfile) && Curl_safe_strcasecompare(data->clientcert, needle->clientcert) && Curl_safe_strcasecompare(data->cipher_list, needle->cipher_list))






    return TRUE;

  return FALSE;
}

bool Curl_clone_primary_ssl_config(struct ssl_primary_config *source, struct ssl_primary_config *dest)

{
  dest->verifyhost = source->verifyhost;
  dest->verifypeer = source->verifypeer;
  dest->version = source->version;
  dest->version_max = source->version_max;

  CLONE_STRING(CAfile);
  CLONE_STRING(CApath);
  CLONE_STRING(cipher_list);
  CLONE_STRING(egdsocket);
  CLONE_STRING(random_file);
  CLONE_STRING(clientcert);
  return TRUE;
}

void Curl_free_primary_ssl_config(struct ssl_primary_config* sslc)
{
  Curl_safefree(sslc->CAfile);
  Curl_safefree(sslc->CApath);
  Curl_safefree(sslc->cipher_list);
  Curl_safefree(sslc->egdsocket);
  Curl_safefree(sslc->random_file);
  Curl_safefree(sslc->clientcert);
}

int Curl_ssl_backend(void)
{
  return (int)CURL_SSL_BACKEND;
}




static bool init_ssl=FALSE;


int Curl_ssl_init(void)
{
  
  if(init_ssl)
    return 1;
  init_ssl = TRUE; 

  return curlssl_init();
}



void Curl_ssl_cleanup(void)
{
  if(init_ssl) {
    
    curlssl_cleanup();
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

    conn->proxy_ssl[sockindex] = conn->ssl[sockindex];
    memset(&conn->ssl[sockindex], 0, sizeof(conn->ssl[sockindex]));

    return CURLE_NOT_BUILT_IN;

  }
  return CURLE_OK;
}

CURLcode Curl_ssl_connect(struct connectdata *conn, int sockindex)
{
  CURLcode result;

  if(conn->bits.proxy_ssl_connected[sockindex]) {
    result = ssl_connect_init_proxy(conn, sockindex);
    if(result)
      return result;
  }

  if(!ssl_prefs_check(conn->data))
    return CURLE_SSL_CONNECT_ERROR;

  
  conn->ssl[sockindex].use = TRUE;
  conn->ssl[sockindex].state = ssl_connection_negotiating;

  result = curlssl_connect(conn, sockindex);

  if(!result)
    Curl_pgrsTime(conn->data, TIMER_APPCONNECT); 

  return result;
}

CURLcode Curl_ssl_connect_nonblocking(struct connectdata *conn, int sockindex, bool *done)

{
  CURLcode result;
  if(conn->bits.proxy_ssl_connected[sockindex]) {
    result = ssl_connect_init_proxy(conn, sockindex);
    if(result)
      return result;
  }

  if(!ssl_prefs_check(conn->data))
    return CURLE_SSL_CONNECT_ERROR;

  
  conn->ssl[sockindex].use = TRUE;

  result = curlssl_connect_nonblocking(conn, sockindex, done);

  *done = TRUE; 
  result = curlssl_connect(conn, sockindex);

  if(!result && *done)
    Curl_pgrsTime(conn->data, TIMER_APPCONNECT); 
  return result;
}


void Curl_ssl_sessionid_lock(struct connectdata *conn)
{
  if(SSLSESSION_SHARED(conn->data))
    Curl_share_lock(conn->data, CURL_LOCK_DATA_SSL_SESSION, CURL_LOCK_ACCESS_SINGLE);
}


void Curl_ssl_sessionid_unlock(struct connectdata *conn)
{
  if(SSLSESSION_SHARED(conn->data))
    Curl_share_unlock(conn->data, CURL_LOCK_DATA_SSL_SESSION);
}


bool Curl_ssl_getsessionid(struct connectdata *conn, void **ssl_sessionid, size_t *idsize, int sockindex)


{
  struct curl_ssl_session *check;
  struct Curl_easy *data = conn->data;
  size_t i;
  long *general_age;
  bool no_match = TRUE;

  const bool isProxy = CONNECT_PROXY_SSL();
  struct ssl_primary_config * const ssl_config = isProxy ? &conn->proxy_ssl_config :
    &conn->ssl_config;
  const char * const name = isProxy ? conn->http_proxy.host.name :
    conn->host.name;
  int port = isProxy ? (int)conn->port : conn->remote_port;
  *ssl_sessionid = NULL;

  DEBUGASSERT(data->set.general_ssl.sessionid);

  if(!data->set.general_ssl.sessionid)
    
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


void Curl_ssl_kill_session(struct curl_ssl_session *session)
{
  if(session->sessionid) {
    

    
    curlssl_session_free(session->sessionid);

    session->sessionid = NULL;
    session->age = 0; 

    Curl_free_primary_ssl_config(&session->ssl_config);

    Curl_safefree(session->name);
    Curl_safefree(session->conn_to_host);
  }
}


void Curl_ssl_delsessionid(struct connectdata *conn, void *ssl_sessionid)
{
  size_t i;
  struct Curl_easy *data=conn->data;

  for(i = 0; i < data->set.general_ssl.max_ssl_sessions; i++) {
    struct curl_ssl_session *check = &data->state.session[i];

    if(check->sessionid == ssl_sessionid) {
      Curl_ssl_kill_session(check);
      break;
    }
  }
}


CURLcode Curl_ssl_addsessionid(struct connectdata *conn, void *ssl_sessionid, size_t idsize, int sockindex)


{
  size_t i;
  struct Curl_easy *data=conn->data; 
  struct curl_ssl_session *store = &data->state.session[0];
  long oldest_age=data->state.session[0].age; 
  char *clone_host;
  char *clone_conn_to_host;
  int conn_to_port;
  long *general_age;
  const bool isProxy = CONNECT_PROXY_SSL();
  struct ssl_primary_config * const ssl_config = isProxy ? &conn->proxy_ssl_config :
    &conn->ssl_config;

  DEBUGASSERT(data->set.general_ssl.sessionid);

  clone_host = strdup(isProxy ? conn->http_proxy.host.name : conn->host.name);
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
    store->sessionid = NULL; 
    free(clone_host);
    free(clone_conn_to_host);
    return CURLE_OUT_OF_MEMORY;
  }

  return CURLE_OK;
}


void Curl_ssl_close_all(struct Curl_easy *data)
{
  size_t i;
  
  if(data->state.session && !SSLSESSION_SHARED(data)) {
    for(i = 0; i < data->set.general_ssl.max_ssl_sessions; i++)
      
      Curl_ssl_kill_session(&data->state.session[i]);

    
    Curl_safefree(data->state.session);
  }

  curlssl_close_all(data);
}



int Curl_ssl_getsock(struct connectdata *conn, curl_socket_t *socks, int numsocks)
{
  struct ssl_connect_data *connssl = &conn->ssl[FIRSTSOCKET];

  if(!numsocks)
    return GETSOCK_BLANK;

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

int Curl_ssl_getsock(struct connectdata *conn, curl_socket_t *socks, int numsocks)

{
  (void)conn;
  (void)socks;
  (void)numsocks;
  return GETSOCK_BLANK;
}



void Curl_ssl_close(struct connectdata *conn, int sockindex)
{
  DEBUGASSERT((sockindex <= 1) && (sockindex >= -1));
  curlssl_close(conn, sockindex);
}

CURLcode Curl_ssl_shutdown(struct connectdata *conn, int sockindex)
{
  if(curlssl_shutdown(conn, sockindex))
    return CURLE_SSL_SHUTDOWN_FAILED;

  conn->ssl[sockindex].use = FALSE; 
  conn->ssl[sockindex].state = ssl_connection_none;

  conn->recv[sockindex] = Curl_recv_plain;
  conn->send[sockindex] = Curl_send_plain;

  return CURLE_OK;
}


CURLcode Curl_ssl_set_engine(struct Curl_easy *data, const char *engine)
{
  return curlssl_set_engine(data, engine);
}


CURLcode Curl_ssl_set_engine_default(struct Curl_easy *data)
{
  return curlssl_set_engine_default(data);
}


struct curl_slist *Curl_ssl_engines_list(struct Curl_easy *data)
{
  return curlssl_engines_list(data);
}


CURLcode Curl_ssl_initsessions(struct Curl_easy *data, size_t amount)
{
  struct curl_ssl_session *session;

  if(data->state.session)
    
    return CURLE_OK;

  session = calloc(amount, sizeof(struct curl_ssl_session));
  if(!session)
    return CURLE_OUT_OF_MEMORY;

  
  data->set.general_ssl.max_ssl_sessions = amount;
  data->state.session = session;
  data->state.sessionage = 1; 
  return CURLE_OK;
}

size_t Curl_ssl_version(char *buffer, size_t size)
{
  return curlssl_version(buffer, size);
}


int Curl_ssl_check_cxn(struct connectdata *conn)
{
  return curlssl_check_cxn(conn);
}

bool Curl_ssl_data_pending(const struct connectdata *conn, int connindex)
{
  return curlssl_data_pending(conn, connindex);
}

void Curl_ssl_free_certinfo(struct Curl_easy *data)
{
  int i;
  struct curl_certinfo *ci = &data->info.certs;

  if(ci->num_of_certs) {
    
    for(i=0; i<ci->num_of_certs; i++) {
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

  
  snprintf(output, outlen, "%s:", label);

  
  memcpy(&output[labellen+1], value, valuelen);

  
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
  return curlssl_random(data, entropy, length);
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
  long filesize;
  size_t size, pem_len;
  CURLcode pem_read;
  CURLcode result = CURLE_SSL_PINNEDPUBKEYNOTMATCH;

  CURLcode encode;
  size_t encodedlen, pinkeylen;
  char *encoded, *pinkeycopy, *begin_pos, *end_pos;
  unsigned char *sha256sumdigest = NULL;


  
  if(!pinnedpubkey)
    return CURLE_OK;
  if(!pubkey || !pubkeylen)
    return result;

  
  if(strncmp(pinnedpubkey, "sha256//", 8) == 0) {

    
    sha256sumdigest = malloc(SHA256_DIGEST_LENGTH);
    if(!sha256sumdigest)
      return CURLE_OUT_OF_MEMORY;
    curlssl_sha256sum(pubkey, pubkeylen, sha256sumdigest, SHA256_DIGEST_LENGTH);
    encode = Curl_base64_encode(data, (char *)sha256sumdigest, SHA256_DIGEST_LENGTH, &encoded, &encodedlen);
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

    
    (void)data;

    return result;
  }

  fp = fopen(pinnedpubkey, "rb");
  if(!fp)
    return result;

  do {
    
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


CURLcode Curl_ssl_md5sum(unsigned char *tmp,  size_t tmplen, unsigned char *md5sum, size_t md5len)


{

  curlssl_md5sum(tmp, tmplen, md5sum, md5len);

  MD5_context *MD5pw;

  (void) md5len;

  MD5pw = Curl_MD5_init(Curl_DIGEST_MD5);
  if(!MD5pw)
    return CURLE_OUT_OF_MEMORY;
  Curl_MD5_update(MD5pw, tmp, curlx_uztoui(tmplen));
  Curl_MD5_final(MD5pw, md5sum);

  return CURLE_OK;
}



bool Curl_ssl_cert_status_request(void)
{

  return curlssl_cert_status_request();

  return FALSE;

}


bool Curl_ssl_false_start(void)
{

  return curlssl_false_start();

  return FALSE;

}


