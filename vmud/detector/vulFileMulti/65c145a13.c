


































































static int http_getsock_do(struct connectdata *conn, curl_socket_t *socks, int numsocks);

static int http_should_fail(struct connectdata *conn);


static CURLcode https_connecting(struct connectdata *conn, bool *done);
static int https_getsock(struct connectdata *conn, curl_socket_t *socks, int numsocks);






const struct Curl_handler Curl_handler_http = {
  "HTTP",                                Curl_http_setup_conn, Curl_http, Curl_http_done, ZERO_NULL, Curl_http_connect, ZERO_NULL, ZERO_NULL, ZERO_NULL, http_getsock_do, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, PORT_HTTP, CURLPROTO_HTTP, PROTOPT_CREDSPERREQUEST };



















const struct Curl_handler Curl_handler_https = {
  "HTTPS",                               Curl_http_setup_conn, Curl_http, Curl_http_done, ZERO_NULL, Curl_http_connect, https_connecting, ZERO_NULL, https_getsock, http_getsock_do, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, PORT_HTTPS, CURLPROTO_HTTPS, PROTOPT_SSL | PROTOPT_CREDSPERREQUEST | PROTOPT_ALPN_NPN };


















CURLcode Curl_http_setup_conn(struct connectdata *conn)
{
  
  struct HTTP *http;
  DEBUGASSERT(conn->data->req.protop == NULL);

  http = calloc(1, sizeof(struct HTTP));
  if(!http)
    return CURLE_OUT_OF_MEMORY;

  conn->data->req.protop = http;

  Curl_http2_setup_conn(conn);
  Curl_http2_setup_req(conn->data);

  return CURLE_OK;
}


char *Curl_checkheaders(const struct connectdata *conn, const char *thisheader)
{
  struct curl_slist *head;
  size_t thislen = strlen(thisheader);
  struct Curl_easy *data = conn->data;

  for(head = data->set.headers;head; head=head->next) {
    if(Curl_raw_nequal(head->data, thisheader, thislen))
      return head->data;
  }

  return NULL;
}


char *Curl_checkProxyheaders(const struct connectdata *conn, const char *thisheader)
{
  struct curl_slist *head;
  size_t thislen = strlen(thisheader);
  struct Curl_easy *data = conn->data;

  for(head = (conn->bits.proxy && data->set.sep_headers) ? data->set.proxyheaders : data->set.headers;
      head; head=head->next) {
    if(Curl_raw_nequal(head->data, thisheader, thislen))
      return head->data;
  }

  return NULL;
}


char *Curl_copy_header_value(const char *header)
{
  const char *start;
  const char *end;
  char *value;
  size_t len;

  DEBUGASSERT(header);

  
  while(*header && (*header != ':'))
    ++header;

  if(*header)
    
    ++header;

  
  start = header;
  while(*start && ISSPACE(*start))
    start++;

  
  end = strchr(start, '\r');
  if(!end)
    end = strchr(start, '\n');
  if(!end)
    end = strchr(start, '\0');
  if(!end)
    return NULL;

  
  while((end > start) && ISSPACE(*end))
    end--;

  
  len = end - start + 1;

  value = malloc(len + 1);
  if(!value)
    return NULL;

  memcpy(value, start, len);
  value[len] = 0; 

  return value;
}


static CURLcode http_output_basic(struct connectdata *conn, bool proxy)
{
  size_t size = 0;
  char *authorization = NULL;
  struct Curl_easy *data = conn->data;
  char **userp;
  const char *user;
  const char *pwd;
  CURLcode result;

  if(proxy) {
    userp = &conn->allocptr.proxyuserpwd;
    user = conn->proxyuser;
    pwd = conn->proxypasswd;
  }
  else {
    userp = &conn->allocptr.userpwd;
    user = conn->user;
    pwd = conn->passwd;
  }

  snprintf(data->state.buffer, sizeof(data->state.buffer), "%s:%s", user, pwd);

  result = Curl_base64_encode(data, data->state.buffer, strlen(data->state.buffer), &authorization, &size);

  if(result)
    return result;

  if(!authorization)
    return CURLE_REMOTE_ACCESS_DENIED;

  free(*userp);
  *userp = aprintf("%sAuthorization: Basic %s\r\n", proxy ? "Proxy-" : "", authorization);

  free(authorization);
  if(!*userp)
    return CURLE_OUT_OF_MEMORY;

  return CURLE_OK;
}


static bool pickoneauth(struct auth *pick)
{
  bool picked;
  
  unsigned long avail = pick->avail & pick->want;
  picked = TRUE;

  
  if(avail & CURLAUTH_NEGOTIATE)
    pick->picked = CURLAUTH_NEGOTIATE;
  else if(avail & CURLAUTH_DIGEST)
    pick->picked = CURLAUTH_DIGEST;
  else if(avail & CURLAUTH_NTLM)
    pick->picked = CURLAUTH_NTLM;
  else if(avail & CURLAUTH_NTLM_WB)
    pick->picked = CURLAUTH_NTLM_WB;
  else if(avail & CURLAUTH_BASIC)
    pick->picked = CURLAUTH_BASIC;
  else {
    pick->picked = CURLAUTH_PICKNONE; 
    picked = FALSE;
  }
  pick->avail = CURLAUTH_NONE; 

  return picked;
}


static CURLcode http_perhapsrewind(struct connectdata *conn)
{
  struct Curl_easy *data = conn->data;
  struct HTTP *http = data->req.protop;
  curl_off_t bytessent;
  curl_off_t expectsend = -1; 

  if(!http)
    
    return CURLE_OK;

  switch(data->set.httpreq) {
  case HTTPREQ_GET:
  case HTTPREQ_HEAD:
    return CURLE_OK;
  default:
    break;
  }

  bytessent = http->writebytecount;

  if(conn->bits.authneg) {
    
    expectsend = 0;
  }
  else if(!conn->bits.protoconnstart) {
    
    expectsend = 0;
  }
  else {
    
    switch(data->set.httpreq) {
    case HTTPREQ_POST:
      if(data->state.infilesize != -1)
        expectsend = data->state.infilesize;
      else if(data->set.postfields)
        expectsend = (curl_off_t)strlen(data->set.postfields);
      break;
    case HTTPREQ_PUT:
      if(data->state.infilesize != -1)
        expectsend = data->state.infilesize;
      break;
    case HTTPREQ_POST_FORM:
      expectsend = http->postsize;
      break;
    default:
      break;
    }
  }

  conn->bits.rewindaftersend = FALSE; 

  if((expectsend == -1) || (expectsend > bytessent)) {

    
    if((data->state.authproxy.picked == CURLAUTH_NTLM) || (data->state.authhost.picked == CURLAUTH_NTLM) || (data->state.authproxy.picked == CURLAUTH_NTLM_WB) || (data->state.authhost.picked == CURLAUTH_NTLM_WB)) {


      if(((expectsend - bytessent) < 2000) || (conn->ntlm.state != NTLMSTATE_NONE) || (conn->proxyntlm.state != NTLMSTATE_NONE)) {

        

        
        if(!conn->bits.authneg) {
          conn->bits.rewindaftersend = TRUE;
          infof(data, "Rewind stream after send\n");
        }

        return CURLE_OK;
      }

      if(conn->bits.close)
        
        return CURLE_OK;

      infof(data, "NTLM send, close instead of sending %" CURL_FORMAT_CURL_OFF_T " bytes\n", (curl_off_t)(expectsend - bytessent));

    }


    
    streamclose(conn, "Mid-auth HTTP and much data left to send");
    data->req.size = 0; 

    
  }

  if(bytessent)
    
    return Curl_readrewind(conn);

  return CURLE_OK;
}



CURLcode Curl_http_auth_act(struct connectdata *conn)
{
  struct Curl_easy *data = conn->data;
  bool pickhost = FALSE;
  bool pickproxy = FALSE;
  CURLcode result = CURLE_OK;

  if(100 <= data->req.httpcode && 199 >= data->req.httpcode)
    
    return CURLE_OK;

  if(data->state.authproblem)
    return data->set.http_fail_on_error?CURLE_HTTP_RETURNED_ERROR:CURLE_OK;

  if(conn->bits.user_passwd && ((data->req.httpcode == 401) || (conn->bits.authneg && data->req.httpcode < 300))) {

    pickhost = pickoneauth(&data->state.authhost);
    if(!pickhost)
      data->state.authproblem = TRUE;
  }
  if(conn->bits.proxy_user_passwd && ((data->req.httpcode == 407) || (conn->bits.authneg && data->req.httpcode < 300))) {

    pickproxy = pickoneauth(&data->state.authproxy);
    if(!pickproxy)
      data->state.authproblem = TRUE;
  }

  if(pickhost || pickproxy) {
    
    Curl_safefree(data->req.newurl);
    data->req.newurl = strdup(data->change.url); 
    if(!data->req.newurl)
      return CURLE_OUT_OF_MEMORY;

    if((data->set.httpreq != HTTPREQ_GET) && (data->set.httpreq != HTTPREQ_HEAD) && !conn->bits.rewindaftersend) {

      result = http_perhapsrewind(conn);
      if(result)
        return result;
    }
  }
  else if((data->req.httpcode < 300) && (!data->state.authhost.done) && conn->bits.authneg) {

    
    if((data->set.httpreq != HTTPREQ_GET) && (data->set.httpreq != HTTPREQ_HEAD)) {
      data->req.newurl = strdup(data->change.url); 
      if(!data->req.newurl)
        return CURLE_OUT_OF_MEMORY;
      data->state.authhost.done = TRUE;
    }
  }
  if(http_should_fail(conn)) {
    failf (data, "The requested URL returned error: %d", data->req.httpcode);
    result = CURLE_HTTP_RETURNED_ERROR;
  }

  return result;
}


static CURLcode output_auth_headers(struct connectdata *conn, struct auth *authstatus, const char *request, const char *path, bool proxy)




{
  const char *auth = NULL;
  CURLcode result = CURLE_OK;

  struct Curl_easy *data = conn->data;


  struct negotiatedata *negdata = proxy ? &data->state.proxyneg : &data->state.negotiate;



  (void)request;
  (void)path;



  negdata->state = GSS_AUTHNONE;
  if((authstatus->picked == CURLAUTH_NEGOTIATE) && negdata->context && !GSS_ERROR(negdata->status)) {
    auth = "Negotiate";
    result = Curl_output_negotiate(conn, proxy);
    if(result)
      return result;
    authstatus->done = TRUE;
    negdata->state = GSS_AUTHSENT;
  }
  else   if(authstatus->picked == CURLAUTH_NTLM) {


    auth = "NTLM";
    result = Curl_output_ntlm(conn, proxy);
    if(result)
      return result;
  }
  else   if(authstatus->picked == CURLAUTH_NTLM_WB) {


    auth="NTLM_WB";
    result = Curl_output_ntlm_wb(conn, proxy);
    if(result)
      return result;
  }
  else   if(authstatus->picked == CURLAUTH_DIGEST) {


    auth = "Digest";
    result = Curl_output_digest(conn, proxy, (const unsigned char *)request, (const unsigned char *)path);


    if(result)
      return result;
  }
  else  if(authstatus->picked == CURLAUTH_BASIC) {

    
    if((proxy && conn->bits.proxy_user_passwd && !Curl_checkProxyheaders(conn, "Proxy-authorization:")) || (!proxy && conn->bits.user_passwd && !Curl_checkheaders(conn, "Authorization:"))) {


      auth = "Basic";
      result = http_output_basic(conn, proxy);
      if(result)
        return result;
    }

    
    authstatus->done = TRUE;
  }

  if(auth) {
    infof(data, "%s auth using %s with user '%s'\n", proxy ? "Proxy" : "Server", auth, proxy ? (conn->proxyuser ? conn->proxyuser : "") :

                  (conn->user ? conn->user : ""));
    authstatus->multi = (!authstatus->done) ? TRUE : FALSE;
  }
  else authstatus->multi = FALSE;

  return CURLE_OK;
}


CURLcode Curl_http_output_auth(struct connectdata *conn, const char *request, const char *path, bool proxytunnel)



{
  CURLcode result = CURLE_OK;
  struct Curl_easy *data = conn->data;
  struct auth *authhost;
  struct auth *authproxy;

  DEBUGASSERT(data);

  authhost = &data->state.authhost;
  authproxy = &data->state.authproxy;

  if((conn->bits.httpproxy && conn->bits.proxy_user_passwd) || conn->bits.user_passwd)
    ;
  else {
    authhost->done = TRUE;
    authproxy->done = TRUE;
    return CURLE_OK; 
  }

  if(authhost->want && !authhost->picked)
    
    authhost->picked = authhost->want;

  if(authproxy->want && !authproxy->picked)
    
    authproxy->picked = authproxy->want;


  
  if(conn->bits.httpproxy && (conn->bits.tunnel_proxy == proxytunnel)) {
    result = output_auth_headers(conn, authproxy, request, path, TRUE);
    if(result)
      return result;
  }
  else  (void)proxytunnel;


    
    authproxy->done = TRUE;

  
  if(!data->state.this_is_a_follow || conn->bits.netrc || !data->state.first_host || data->set.http_disable_hostname_check_before_authentication || Curl_raw_equal(data->state.first_host, conn->host.name)) {



    result = output_auth_headers(conn, authhost, request, path, FALSE);
  }
  else authhost->done = TRUE;

  return result;
}



CURLcode Curl_http_input_auth(struct connectdata *conn, bool proxy, const char *auth)
{
  
  struct Curl_easy *data = conn->data;


  struct negotiatedata *negdata = proxy? &data->state.proxyneg:&data->state.negotiate;

  unsigned long *availp;
  struct auth *authp;

  if(proxy) {
    availp = &data->info.proxyauthavail;
    authp = &data->state.authproxy;
  }
  else {
    availp = &data->info.httpauthavail;
    authp = &data->state.authhost;
  }

  

  while(*auth) {

    if(checkprefix("Negotiate", auth)) {
      if((authp->avail & CURLAUTH_NEGOTIATE) || Curl_auth_is_spnego_supported()) {
        *availp |= CURLAUTH_NEGOTIATE;
        authp->avail |= CURLAUTH_NEGOTIATE;

        if(authp->picked == CURLAUTH_NEGOTIATE) {
          if(negdata->state == GSS_AUTHSENT || negdata->state == GSS_AUTHNONE) {
            CURLcode result = Curl_input_negotiate(conn, proxy, auth);
            if(!result) {
              DEBUGASSERT(!data->req.newurl);
              data->req.newurl = strdup(data->change.url);
              if(!data->req.newurl)
                return CURLE_OUT_OF_MEMORY;
              data->state.authproblem = FALSE;
              
              negdata->state = GSS_AUTHRECV;
            }
            else data->state.authproblem = TRUE;
          }
        }
      }
    }
    else    if(checkprefix("NTLM", auth)) {



        if((authp->avail & CURLAUTH_NTLM) || (authp->avail & CURLAUTH_NTLM_WB) || Curl_auth_is_ntlm_supported()) {

          *availp |= CURLAUTH_NTLM;
          authp->avail |= CURLAUTH_NTLM;

          if(authp->picked == CURLAUTH_NTLM || authp->picked == CURLAUTH_NTLM_WB) {
            
            CURLcode result = Curl_input_ntlm(conn, proxy, auth);
            if(!result) {
              data->state.authproblem = FALSE;

              if(authp->picked == CURLAUTH_NTLM_WB) {
                *availp &= ~CURLAUTH_NTLM;
                authp->avail &= ~CURLAUTH_NTLM;
                *availp |= CURLAUTH_NTLM_WB;
                authp->avail |= CURLAUTH_NTLM_WB;

                
                while(*auth && ISSPACE(*auth))
                  auth++;
                if(checkprefix("NTLM", auth)) {
                  auth += strlen("NTLM");
                  while(*auth && ISSPACE(*auth))
                    auth++;
                  if(*auth)
                    if((conn->challenge_header = strdup(auth)) == NULL)
                      return CURLE_OUT_OF_MEMORY;
                }
              }

            }
            else {
              infof(data, "Authentication problem. Ignoring this.\n");
              data->state.authproblem = TRUE;
            }
          }
        }
      }
      else   if(checkprefix("Digest", auth)) {


          if((authp->avail & CURLAUTH_DIGEST) != 0)
            infof(data, "Ignoring duplicate digest auth header.\n");
          else if(Curl_auth_is_digest_supported()) {
            CURLcode result;

            *availp |= CURLAUTH_DIGEST;
            authp->avail |= CURLAUTH_DIGEST;

            
            result = Curl_input_digest(conn, proxy, auth);
            if(result) {
              infof(data, "Authentication problem. Ignoring this.\n");
              data->state.authproblem = TRUE;
            }
          }
        }
        else  if(checkprefix("Basic", auth)) {

            *availp |= CURLAUTH_BASIC;
            authp->avail |= CURLAUTH_BASIC;
            if(authp->picked == CURLAUTH_BASIC) {
              
              authp->avail = CURLAUTH_NONE;
              infof(data, "Authentication problem. Ignoring this.\n");
              data->state.authproblem = TRUE;
            }
          }

    
    while(*auth && *auth != ',') 
      auth++;
    if(*auth == ',') 
      auth++;
    while(*auth && ISSPACE(*auth))
      auth++;
  }

  return CURLE_OK;
}


static int http_should_fail(struct connectdata *conn)
{
  struct Curl_easy *data;
  int httpcode;

  DEBUGASSERT(conn);
  data = conn->data;
  DEBUGASSERT(data);

  httpcode = data->req.httpcode;

  
  if(!data->set.http_fail_on_error)
    return 0;

  
  if(httpcode < 400)
    return 0;

  
  if((httpcode != 401) && (httpcode != 407))
    return 1;

  
  DEBUGASSERT((httpcode == 401) || (httpcode == 407));

  

  
  if((httpcode == 401) && !conn->bits.user_passwd)
    return TRUE;
  if((httpcode == 407) && !conn->bits.proxy_user_passwd)
    return TRUE;

  return data->state.authproblem;
}


static size_t readmoredata(char *buffer, size_t size, size_t nitems, void *userp)


{
  struct connectdata *conn = (struct connectdata *)userp;
  struct HTTP *http = conn->data->req.protop;
  size_t fullsize = size * nitems;

  if(!http->postsize)
    
    return 0;

  
  conn->data->req.forbidchunk = (http->sending == HTTPSEND_REQUEST)?TRUE:FALSE;

  if(http->postsize <= (curl_off_t)fullsize) {
    memcpy(buffer, http->postdata, (size_t)http->postsize);
    fullsize = (size_t)http->postsize;

    if(http->backup.postsize) {
      
      http->postdata = http->backup.postdata;
      http->postsize = http->backup.postsize;
      conn->data->state.fread_func = http->backup.fread_func;
      conn->data->state.in = http->backup.fread_in;

      http->sending++; 

      http->backup.postsize=0;
    }
    else http->postsize = 0;

    return fullsize;
  }

  memcpy(buffer, http->postdata, fullsize);
  http->postdata += fullsize;
  http->postsize -= fullsize;

  return fullsize;
}





Curl_send_buffer *Curl_add_buffer_init(void)
{
  return calloc(1, sizeof(Curl_send_buffer));
}


void Curl_add_buffer_free(Curl_send_buffer *buff)
{
  if(buff) 
    free(buff->buffer);
  free(buff);
}


CURLcode Curl_add_buffer_send(Curl_send_buffer *in, struct connectdata *conn,   long *bytes_written,   size_t included_body_bytes, int socketindex)








{
  ssize_t amount;
  CURLcode result;
  char *ptr;
  size_t size;
  struct HTTP *http = conn->data->req.protop;
  size_t sendsize;
  curl_socket_t sockfd;
  size_t headersize;

  DEBUGASSERT(socketindex <= SECONDARYSOCKET);

  sockfd = conn->sock[socketindex];

  

  ptr = in->buffer;
  size = in->size_used;

  headersize = size - included_body_bytes; 

  DEBUGASSERT(size > included_body_bytes);

  result = Curl_convert_to_network(conn->data, ptr, headersize);
  
  if(result) {
    
    Curl_add_buffer_free(in);
    return result;
  }

  if((conn->handler->flags & PROTOPT_SSL) && conn->httpversion != 20) {
    

    sendsize = (size > CURL_MAX_WRITE_SIZE) ? CURL_MAX_WRITE_SIZE : size;

    
    memcpy(conn->data->state.uploadbuffer, ptr, sendsize);
    ptr = conn->data->state.uploadbuffer;
  }
  else sendsize = size;

  result = Curl_write(conn, sockfd, ptr, sendsize, &amount);

  if(!result) {
    
    
    size_t headlen = (size_t)amount>headersize ? headersize : (size_t)amount;
    size_t bodylen = amount - headlen;

    if(conn->data->set.verbose) {
      
      Curl_debug(conn->data, CURLINFO_HEADER_OUT, ptr, headlen, conn);
      if(bodylen) {
        
        Curl_debug(conn->data, CURLINFO_DATA_OUT, ptr+headlen, bodylen, conn);
      }
    }

    
    *bytes_written += (long)amount;

    if(http) {
      
      http->writebytecount += bodylen;

      if((size_t)amount != size) {
        

        size -= amount;

        ptr = in->buffer + amount;

        
        http->backup.fread_func = conn->data->state.fread_func;
        http->backup.fread_in = conn->data->state.in;
        http->backup.postdata = http->postdata;
        http->backup.postsize = http->postsize;

        
        conn->data->state.fread_func = (curl_read_callback)readmoredata;
        conn->data->state.in = (void *)conn;
        http->postdata = ptr;
        http->postsize = (curl_off_t)size;

        http->send_buffer = in;
        http->sending = HTTPSEND_REQUEST;

        return CURLE_OK;
      }
      http->sending = HTTPSEND_BODY;
      
    }
    else {
      if((size_t)amount != size)
        
        return CURLE_SEND_ERROR;
      else Curl_pipeline_leave_write(conn);
    }
  }
  Curl_add_buffer_free(in);

  return result;
}



CURLcode Curl_add_bufferf(Curl_send_buffer *in, const char *fmt, ...)
{
  char *s;
  va_list ap;
  va_start(ap, fmt);
  s = vaprintf(fmt, ap); 
  va_end(ap);

  if(s) {
    CURLcode result = Curl_add_buffer(in, s, strlen(s));
    free(s);
    return result;
  }
  
  free(in->buffer);
  free(in);
  return CURLE_OUT_OF_MEMORY;
}


CURLcode Curl_add_buffer(Curl_send_buffer *in, const void *inptr, size_t size)
{
  char *new_rb;
  size_t new_size;

  if(~size < in->size_used) {
    
    Curl_safefree(in->buffer);
    free(in);
    return CURLE_OUT_OF_MEMORY;
  }

  if(!in->buffer || ((in->size_used + size) > (in->size_max - 1))) {

    

    if((size > (size_t)-1 / 2) || (in->size_used > (size_t)-1 / 2) || (~(size * 2) < (in->size_used * 2)))
      new_size = (size_t)-1;
    else new_size = (in->size_used+size) * 2;

    if(in->buffer)
      
      new_rb = realloc(in->buffer, new_size);
    else  new_rb = malloc(new_size);


    if(!new_rb) {
      
      Curl_safefree(in->buffer);
      free(in);
      return CURLE_OUT_OF_MEMORY;
    }

    in->buffer = new_rb;
    in->size_max = new_size;
  }
  memcpy(&in->buffer[in->size_used], inptr, size);

  in->size_used += size;

  return CURLE_OK;
}







bool Curl_compareheader(const char *headerline, const char *header, const char *content)


{
  

  size_t hlen = strlen(header);
  size_t clen;
  size_t len;
  const char *start;
  const char *end;

  if(!Curl_raw_nequal(headerline, header, hlen))
    return FALSE; 

  
  start = &headerline[hlen];

  
  while(*start && ISSPACE(*start))
    start++;

  
  end = strchr(start, '\r'); 
  if(!end) {
    
    end = strchr(start, '\n');

    if(!end)
      
      end = strchr(start, '\0');
  }

  len = end-start; 
  clen = strlen(content); 

  
  for(;len>=clen;len--, start++) {
    if(Curl_raw_nequal(start, content, clen))
      return TRUE; 
  }

  return FALSE; 
}


CURLcode Curl_http_connect(struct connectdata *conn, bool *done)
{
  CURLcode result;

  
  connkeep(conn, "HTTP default");

  
  result = Curl_proxy_connect(conn);
  if(result)
    return result;

  if(conn->tunnel_state[FIRSTSOCKET] == TUNNEL_CONNECT)
    
    return CURLE_OK;

  if(conn->given->flags & PROTOPT_SSL) {
    
    result = https_connecting(conn, done);
    if(result)
      return result;
  }
  else *done = TRUE;

  return CURLE_OK;
}


static int http_getsock_do(struct connectdata *conn, curl_socket_t *socks, int numsocks)

{
  
  (void)numsocks; 
  socks[0] = conn->sock[FIRSTSOCKET];
  return GETSOCK_WRITESOCK(0);
}


static CURLcode https_connecting(struct connectdata *conn, bool *done)
{
  CURLcode result;
  DEBUGASSERT((conn) && (conn->handler->flags & PROTOPT_SSL));

  
  result = Curl_ssl_connect_nonblocking(conn, FIRSTSOCKET, done);
  if(result)
    connclose(conn, "Failed HTTPS connection");

  return result;
}





static int https_getsock(struct connectdata *conn, curl_socket_t *socks, int numsocks)

{
  if(conn->handler->flags & PROTOPT_SSL) {
    struct ssl_connect_data *connssl = &conn->ssl[FIRSTSOCKET];

    if(!numsocks)
      return GETSOCK_BLANK;

    if(connssl->connecting_state == ssl_connect_2_writing) {
      
      socks[0] = conn->sock[FIRSTSOCKET];
      return GETSOCK_WRITESOCK(0);
    }
    else if(connssl->connecting_state == ssl_connect_2_reading) {
      
      socks[0] = conn->sock[FIRSTSOCKET];
      return GETSOCK_READSOCK(0);
    }
  }

  return CURLE_OK;
}


static int https_getsock(struct connectdata *conn, curl_socket_t *socks, int numsocks)

{
  (void)conn;
  (void)socks;
  (void)numsocks;
  return GETSOCK_BLANK;
}





CURLcode Curl_http_done(struct connectdata *conn, CURLcode status, bool premature)
{
  struct Curl_easy *data = conn->data;
  struct HTTP *http = data->req.protop;

  infof(data, "Curl_http_done: called premature == %d\n", premature);

  Curl_unencode_cleanup(conn);


  if(data->state.proxyneg.state == GSS_AUTHSENT || data->state.negotiate.state == GSS_AUTHSENT) {
    
    if((data->req.httpcode != 401) && (data->req.httpcode != 407) && !data->set.connect_only)
      streamclose(conn, "Negotiate transfer completed");
    Curl_cleanup_negotiate(data);
  }


  
  conn->seek_func = data->set.seek_func; 
  conn->seek_client = data->set.seek_client; 

  if(!http)
    return CURLE_OK;

  if(http->send_buffer) {
    Curl_add_buffer_free(http->send_buffer);
    http->send_buffer = NULL; 
  }

  Curl_http2_done(conn, premature);

  if(HTTPREQ_POST_FORM == data->set.httpreq) {
    data->req.bytecount = http->readbytecount + http->writebytecount;

    Curl_formclean(&http->sendit); 
    if(http->form.fp) {
      
      fclose(http->form.fp);
      http->form.fp = NULL;
    }
  }
  else if(HTTPREQ_PUT == data->set.httpreq)
    data->req.bytecount = http->readbytecount + http->writebytecount;

  if(status)
    return status;

  if(!premature &&  !conn->bits.retry && !data->set.connect_only && (http->readbytecount + data->req.headerbytecount - data->req.deductheadercount) <= 0) {




    
    failf(data, "Empty reply from server");
    return CURLE_GOT_NOTHING;
  }

  return CURLE_OK;
}


static bool use_http_1_1plus(const struct Curl_easy *data, const struct connectdata *conn)
{
  if((data->state.httpversion == 10) || (conn->httpversion == 10))
    return FALSE;
  if((data->set.httpversion == CURL_HTTP_VERSION_1_0) && (conn->httpversion <= 10))
    return FALSE;
  return ((data->set.httpversion == CURL_HTTP_VERSION_NONE) || (data->set.httpversion >= CURL_HTTP_VERSION_1_1));
}


static CURLcode expect100(struct Curl_easy *data, struct connectdata *conn, Curl_send_buffer *req_buffer)

{
  CURLcode result = CURLE_OK;
  const char *ptr;
  data->state.expect100header = FALSE; 
  if(use_http_1_1plus(data, conn) && (conn->httpversion != 20)) {
    
    ptr = Curl_checkheaders(conn, "Expect:");
    if(ptr) {
      data->state.expect100header = Curl_compareheader(ptr, "Expect:", "100-continue");
    }
    else {
      result = Curl_add_bufferf(req_buffer, "Expect: 100-continue\r\n");
      if(!result)
        data->state.expect100header = TRUE;
    }
  }

  return result;
}

enum proxy_use {
  HEADER_SERVER,   HEADER_PROXY, HEADER_CONNECT };



CURLcode Curl_add_custom_headers(struct connectdata *conn, bool is_connect, Curl_send_buffer *req_buffer)

{
  char *ptr;
  struct curl_slist *h[2];
  struct curl_slist *headers;
  int numlists=1; 
  struct Curl_easy *data = conn->data;
  int i;

  enum proxy_use proxy;

  if(is_connect)
    proxy = HEADER_CONNECT;
  else proxy = conn->bits.httpproxy && !conn->bits.tunnel_proxy? HEADER_PROXY:HEADER_SERVER;


  switch(proxy) {
  case HEADER_SERVER:
    h[0] = data->set.headers;
    break;
  case HEADER_PROXY:
    h[0] = data->set.headers;
    if(data->set.sep_headers) {
      h[1] = data->set.proxyheaders;
      numlists++;
    }
    break;
  case HEADER_CONNECT:
    if(data->set.sep_headers)
      h[0] = data->set.proxyheaders;
    else h[0] = data->set.headers;
    break;
  }

  
  for(i=0; i < numlists; i++) {
    headers = h[i];

    while(headers) {
      ptr = strchr(headers->data, ':');
      if(ptr) {
        

        ptr++; 
        while(*ptr && ISSPACE(*ptr))
          ptr++;

        if(*ptr) {
          

          if(conn->allocptr.host &&  checkprefix("Host:", headers->data))

            ;
          else if(data->set.httpreq == HTTPREQ_POST_FORM &&  checkprefix("Content-Type:", headers->data))

            ;
          else if(conn->bits.authneg &&  checkprefix("Content-Length", headers->data))

            ;
          else if(conn->allocptr.te &&  checkprefix("Connection", headers->data))

            ;
          else if((conn->httpversion == 20) && checkprefix("Transfer-Encoding:", headers->data))
            
            ;
          else {
            CURLcode result = Curl_add_bufferf(req_buffer, "%s\r\n", headers->data);
            if(result)
              return result;
          }
        }
      }
      else {
        ptr = strchr(headers->data, ';');
        if(ptr) {

          ptr++; 
          while(*ptr && ISSPACE(*ptr))
            ptr++;

          if(*ptr) {
            
          }
          else {
            if(*(--ptr) == ';') {
              CURLcode result;

              
              *ptr = ':';
              result = Curl_add_bufferf(req_buffer, "%s\r\n", headers->data);
              if(result)
                return result;
            }
          }
        }
      }
      headers = headers->next;
    }
  }

  return CURLE_OK;
}

CURLcode Curl_add_timecondition(struct Curl_easy *data, Curl_send_buffer *req_buffer)
{
  const struct tm *tm;
  char *buf = data->state.buffer;
  struct tm keeptime;
  CURLcode result;

  if(data->set.timecondition == CURL_TIMECOND_NONE)
    
    return CURLE_OK;

  result = Curl_gmtime(data->set.timevalue, &keeptime);
  if(result) {
    failf(data, "Invalid TIMEVALUE");
    return result;
  }
  tm = &keeptime;

  

  
  snprintf(buf, BUFSIZE-1, "%s, %02d %s %4d %02d:%02d:%02d GMT", Curl_wkday[tm->tm_wday?tm->tm_wday-1:6], tm->tm_mday, Curl_month[tm->tm_mon], tm->tm_year + 1900, tm->tm_hour, tm->tm_min, tm->tm_sec);








  switch(data->set.timecondition) {
  default:
    break;
  case CURL_TIMECOND_IFMODSINCE:
    result = Curl_add_bufferf(req_buffer, "If-Modified-Since: %s\r\n", buf);
    break;
  case CURL_TIMECOND_IFUNMODSINCE:
    result = Curl_add_bufferf(req_buffer, "If-Unmodified-Since: %s\r\n", buf);
    break;
  case CURL_TIMECOND_LASTMOD:
    result = Curl_add_bufferf(req_buffer, "Last-Modified: %s\r\n", buf);
    break;
  }

  return result;
}


CURLcode Curl_http(struct connectdata *conn, bool *done)
{
  struct Curl_easy *data = conn->data;
  CURLcode result = CURLE_OK;
  struct HTTP *http;
  const char *ppath = data->state.path;
  bool paste_ftp_userpwd = FALSE;
  char ftp_typecode[sizeof("/;type=?")] = "";
  const char *host = conn->host.name;
  const char *te = ""; 
  const char *ptr;
  const char *request;
  Curl_HttpReq httpreq = data->set.httpreq;

  char *addcookies = NULL;

  curl_off_t included_body = 0;
  const char *httpstring;
  Curl_send_buffer *req_buffer;
  curl_off_t postsize = 0; 
  int seekerr = CURL_SEEKFUNC_OK;

  
  *done = TRUE;

  if(conn->httpversion < 20) { 
    switch(conn->negnpn) {
    case CURL_HTTP_VERSION_2:
      conn->httpversion = 20; 

      result = Curl_http2_switched(conn, NULL, 0);
      if(result)
        return result;
      break;
    case CURL_HTTP_VERSION_1_1:
      
      break;
    default:
      

      if(conn->data->set.httpversion == CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE) {
        DEBUGF(infof(data, "HTTP/2 over clean TCP\n"));
        conn->httpversion = 20;

        result = Curl_http2_switched(conn, NULL, 0);
        if(result)
          return result;
      }

      break;
    }
  }
  else {
    
    result = Curl_http2_setup(conn);
    if(result)
      return result;
  }

  http = data->req.protop;

  if(!data->state.this_is_a_follow) {
    
    free(data->state.first_host);

    data->state.first_host = strdup(conn->host.name);
    if(!data->state.first_host)
      return CURLE_OUT_OF_MEMORY;

    data->state.first_remote_port = conn->remote_port;
  }
  http->writebytecount = http->readbytecount = 0;

  if((conn->handler->protocol&(PROTO_FAMILY_HTTP|CURLPROTO_FTP)) && data->set.upload) {
    httpreq = HTTPREQ_PUT;
  }

  
  if(data->set.str[STRING_CUSTOMREQUEST])
    request = data->set.str[STRING_CUSTOMREQUEST];
  else {
    if(data->set.opt_no_body)
      request = "HEAD";
    else {
      DEBUGASSERT((httpreq > HTTPREQ_NONE) && (httpreq < HTTPREQ_LAST));
      switch(httpreq) {
      case HTTPREQ_POST:
      case HTTPREQ_POST_FORM:
        request = "POST";
        break;
      case HTTPREQ_PUT:
        request = "PUT";
        break;
      default: 
      case HTTPREQ_GET:
        request = "GET";
        break;
      case HTTPREQ_HEAD:
        request = "HEAD";
        break;
      }
    }
  }

  
  if(Curl_checkheaders(conn, "User-Agent:")) {
    free(conn->allocptr.uagent);
    conn->allocptr.uagent=NULL;
  }

  
  result = Curl_http_output_auth(conn, request, ppath, FALSE);
  if(result)
    return result;

  if((data->state.authhost.multi || data->state.authproxy.multi) && (httpreq != HTTPREQ_GET) && (httpreq != HTTPREQ_HEAD)) {

    
    conn->bits.authneg = TRUE;
  }
  else conn->bits.authneg = FALSE;

  Curl_safefree(conn->allocptr.ref);
  if(data->change.referer && !Curl_checkheaders(conn, "Referer:")) {
    conn->allocptr.ref = aprintf("Referer: %s\r\n", data->change.referer);
    if(!conn->allocptr.ref)
      return CURLE_OUT_OF_MEMORY;
  }
  else conn->allocptr.ref = NULL;


  if(data->set.str[STRING_COOKIE] && !Curl_checkheaders(conn, "Cookie:"))
    addcookies = data->set.str[STRING_COOKIE];


  if(!Curl_checkheaders(conn, "Accept-Encoding:") && data->set.str[STRING_ENCODING]) {
    Curl_safefree(conn->allocptr.accept_encoding);
    conn->allocptr.accept_encoding = aprintf("Accept-Encoding: %s\r\n", data->set.str[STRING_ENCODING]);
    if(!conn->allocptr.accept_encoding)
      return CURLE_OUT_OF_MEMORY;
  }
  else {
    Curl_safefree(conn->allocptr.accept_encoding);
    conn->allocptr.accept_encoding = NULL;
  }


  

  if(!Curl_checkheaders(conn, "TE:") && data->set.http_transfer_encoding) {
    
    char *cptr = Curl_checkheaders(conn, "Connection:");


    Curl_safefree(conn->allocptr.te);

    
    conn->allocptr.te = cptr? aprintf("%s, TE\r\n" TE_HEADER, cptr):
      strdup("Connection: TE\r\n" TE_HEADER);

    if(!conn->allocptr.te)
      return CURLE_OUT_OF_MEMORY;
  }


  ptr = Curl_checkheaders(conn, "Transfer-Encoding:");
  if(ptr) {
    
    data->req.upload_chunky = Curl_compareheader(ptr, "Transfer-Encoding:", "chunked");
  }
  else {
    if((conn->handler->protocol&PROTO_FAMILY_HTTP) && data->set.upload && (data->state.infilesize == -1)) {

      if(conn->bits.authneg)
        
        ;
      else if(use_http_1_1plus(data, conn)) {
        
        data->req.upload_chunky = TRUE;
      }
      else {
        failf(data, "Chunky upload is not supported by HTTP 1.0");
        return CURLE_UPLOAD_FAILED;
      }
    }
    else {
      
      data->req.upload_chunky = FALSE;
    }

    if(data->req.upload_chunky)
      te = "Transfer-Encoding: chunked\r\n";
  }

  Curl_safefree(conn->allocptr.host);

  ptr = Curl_checkheaders(conn, "Host:");
  if(ptr && (!data->state.this_is_a_follow || Curl_raw_equal(data->state.first_host, conn->host.name))) {

    
    char *cookiehost = Curl_copy_header_value(ptr);
    if(!cookiehost)
      return CURLE_OUT_OF_MEMORY;
    if(!*cookiehost)
      
      free(cookiehost);
    else {
      
      int startsearch = 0;
      if(*cookiehost == '[') {
        char *closingbracket;
        
        memmove(cookiehost, cookiehost + 1, strlen(cookiehost) - 1);
        closingbracket = strchr(cookiehost, ']');
        if(closingbracket)
          *closingbracket = 0;
      }
      else {
        char *colon = strchr(cookiehost + startsearch, ':');
        if(colon)
          *colon = 0; 
      }
      Curl_safefree(conn->allocptr.cookiehost);
      conn->allocptr.cookiehost = cookiehost;
    }


    if(strcmp("Host:", ptr)) {
      conn->allocptr.host = aprintf("%s\r\n", ptr);
      if(!conn->allocptr.host)
        return CURLE_OUT_OF_MEMORY;
    }
    else  conn->allocptr.host = NULL;

  }
  else {
    

    if(((conn->given->protocol&CURLPROTO_HTTPS) && (conn->remote_port == PORT_HTTPS)) || ((conn->given->protocol&CURLPROTO_HTTP) && (conn->remote_port == PORT_HTTP)) )


      
      conn->allocptr.host = aprintf("Host: %s%s%s\r\n", conn->bits.ipv6_ip?"[":"", host, conn->bits.ipv6_ip?"]":"");


    else conn->allocptr.host = aprintf("Host: %s%s%s:%hu\r\n", conn->bits.ipv6_ip?"[":"", host, conn->bits.ipv6_ip?"]":"", conn->remote_port);





    if(!conn->allocptr.host)
      
      return CURLE_OUT_OF_MEMORY;
  }


  if(conn->bits.httpproxy && !conn->bits.tunnel_proxy)  {
    

    
    if(conn->host.dispname != conn->host.name) {
      char *url = data->change.url;
      ptr = strstr(url, conn->host.dispname);
      if(ptr) {
        
        size_t currlen = strlen(conn->host.dispname);
        size_t newlen = strlen(conn->host.name);
        size_t urllen = strlen(url);

        char *newurl;

        newurl = malloc(urllen + newlen - currlen + 1);
        if(newurl) {
          
          memcpy(newurl, url, ptr - url);
          
          memcpy(newurl + (ptr - url), conn->host.name, newlen);
          
          memcpy(newurl + newlen + (ptr - url), ptr + currlen, urllen - (ptr-url) - currlen + 1);

          if(data->change.url_alloc) {
            Curl_safefree(data->change.url);
            data->change.url_alloc = FALSE;
          }
          data->change.url = newurl;
          data->change.url_alloc = TRUE;
        }
        else return CURLE_OUT_OF_MEMORY;
      }
    }
    ppath = data->change.url;
    if(checkprefix("ftp://", ppath)) {
      if(data->set.proxy_transfer_mode) {
        
        char *type = strstr(ppath, ";type=");
        if(type && type[6] && type[7] == 0) {
          switch (Curl_raw_toupper(type[6])) {
          case 'A':
          case 'D':
          case 'I':
            break;
          default:
            type = NULL;
          }
        }
        if(!type) {
          char *p = ftp_typecode;
          
          if(!*data->state.path && ppath[strlen(ppath) - 1] != '/') {
            *p++ = '/';
          }
          snprintf(p, sizeof(ftp_typecode) - 1, ";type=%c", data->set.prefer_ascii ? 'a' : 'i');
        }
      }
      if(conn->bits.user_passwd && !conn->bits.userpwd_in_url)
        paste_ftp_userpwd = TRUE;
    }
  }


  if(HTTPREQ_POST_FORM == httpreq) {
    
    result = Curl_getformdata(data, &http->sendit, data->set.httppost, Curl_checkheaders(conn, "Content-Type:"), &http->postsize);

    if(result)
      return result;
  }

  http->p_accept = Curl_checkheaders(conn, "Accept:")?NULL:"Accept: */*\r\n";

  if(( (HTTPREQ_POST == httpreq) || (HTTPREQ_POST_FORM == httpreq) || (HTTPREQ_PUT == httpreq) ) && data->state.resume_from) {


    

    if(data->state.resume_from < 0) {
      
      data->state.resume_from = 0;
    }

    if(data->state.resume_from && !data->state.this_is_a_follow) {
      

      
      if(conn->seek_func) {
        seekerr = conn->seek_func(conn->seek_client, data->state.resume_from, SEEK_SET);
      }

      if(seekerr != CURL_SEEKFUNC_OK) {
        if(seekerr != CURL_SEEKFUNC_CANTSEEK) {
          failf(data, "Could not seek stream");
          return CURLE_READ_ERROR;
        }
        
        else {
          curl_off_t passed=0;
          do {
            size_t readthisamountnow = (data->state.resume_from - passed > CURL_OFF_T_C(BUFSIZE)) ? BUFSIZE : curlx_sotouz(data->state.resume_from - passed);


            size_t actuallyread = data->state.fread_func(data->state.buffer, 1, readthisamountnow, data->state.in);


            passed += actuallyread;
            if((actuallyread == 0) || (actuallyread > readthisamountnow)) {
              
              failf(data, "Could only read %" CURL_FORMAT_CURL_OFF_T " bytes from the input", passed);
              return CURLE_READ_ERROR;
            }
          } while(passed < data->state.resume_from);
        }
      }

      
      if(data->state.infilesize>0) {
        data->state.infilesize -= data->state.resume_from;

        if(data->state.infilesize <= 0) {
          failf(data, "File already completely uploaded");
          return CURLE_PARTIAL_FILE;
        }
      }
      
    }
  }
  if(data->state.use_range) {
    
    if(((httpreq == HTTPREQ_GET) || (httpreq == HTTPREQ_HEAD)) && !Curl_checkheaders(conn, "Range:")) {
      
      free(conn->allocptr.rangeline);
      conn->allocptr.rangeline = aprintf("Range: bytes=%s\r\n", data->state.range);
    }
    else if((httpreq != HTTPREQ_GET) && !Curl_checkheaders(conn, "Content-Range:")) {

      
      free(conn->allocptr.rangeline);

      if(data->set.set_resume_from < 0) {
        
        conn->allocptr.rangeline = aprintf("Content-Range: bytes 0-%" CURL_FORMAT_CURL_OFF_T "/%" CURL_FORMAT_CURL_OFF_T "\r\n", data->state.infilesize - 1, data->state.infilesize);



      }
      else if(data->state.resume_from) {
        
        curl_off_t total_expected_size= data->state.resume_from + data->state.infilesize;
        conn->allocptr.rangeline = aprintf("Content-Range: bytes %s%" CURL_FORMAT_CURL_OFF_T "/%" CURL_FORMAT_CURL_OFF_T "\r\n", data->state.range, total_expected_size-1, total_expected_size);



      }
      else {
        
        conn->allocptr.rangeline = aprintf("Content-Range: bytes %s/%" CURL_FORMAT_CURL_OFF_T "\r\n", data->state.range, data->state.infilesize);

      }
      if(!conn->allocptr.rangeline)
        return CURLE_OUT_OF_MEMORY;
    }
  }

  
  httpstring= use_http_1_1plus(data, conn)?"1.1":"1.0";

  
  req_buffer = Curl_add_buffer_init();

  if(!req_buffer)
    return CURLE_OUT_OF_MEMORY;

  
  
  result = Curl_add_bufferf(req_buffer, "%s ", request);
  if(result)
    return result;

  
  if(paste_ftp_userpwd)
    result = Curl_add_bufferf(req_buffer, "ftp://%s:%s@%s", conn->user, conn->passwd, ppath + sizeof("ftp://") - 1);

  else result = Curl_add_buffer(req_buffer, ppath, strlen(ppath));
  if(result)
    return result;

  result = Curl_add_bufferf(req_buffer, "%s" " HTTP/%s\r\n" "%s" "%s" "%s" "%s" "%s" "%s" "%s" "%s" "%s" "%s" "%s",  ftp_typecode, httpstring, (conn->allocptr.host?conn->allocptr.host:""), conn->allocptr.proxyuserpwd? conn->allocptr.proxyuserpwd:"", conn->allocptr.userpwd?conn->allocptr.userpwd:"", (data->state.use_range && conn->allocptr.rangeline)? conn->allocptr.rangeline:"", (data->set.str[STRING_USERAGENT] && *data->set.str[STRING_USERAGENT] && conn->allocptr.uagent)? conn->allocptr.uagent:"", http->p_accept?http->p_accept:"", conn->allocptr.te?conn->allocptr.te:"", (data->set.str[STRING_ENCODING] && *data->set.str[STRING_ENCODING] && conn->allocptr.accept_encoding)? conn->allocptr.accept_encoding:"", (data->change.referer && conn->allocptr.ref)? conn->allocptr.ref:"" , (conn->bits.httpproxy && !conn->bits.tunnel_proxy && !Curl_checkProxyheaders(conn, "Proxy-Connection:"))? "Proxy-Connection: Keep-Alive\r\n":"", te );









































  
  Curl_safefree(conn->allocptr.userpwd);

  
  switch (data->state.authproxy.picked) {
  case CURLAUTH_NEGOTIATE:
  case CURLAUTH_NTLM:
  case CURLAUTH_NTLM_WB:
    Curl_safefree(conn->allocptr.proxyuserpwd);
    break;
  }

  if(result)
    return result;

  if(!(conn->handler->flags&PROTOPT_SSL) && conn->httpversion != 20 && (data->set.httpversion == CURL_HTTP_VERSION_2)) {

    
    result = Curl_http2_request_upgrade(req_buffer, conn);
    if(result)
      return result;
  }


  if(data->cookies || addcookies) {
    struct Cookie *co=NULL; 
    int count=0;

    if(data->cookies) {
      Curl_share_lock(data, CURL_LOCK_DATA_COOKIE, CURL_LOCK_ACCESS_SINGLE);
      co = Curl_cookie_getlist(data->cookies, conn->allocptr.cookiehost? conn->allocptr.cookiehost:host, data->state.path, (conn->handler->protocol&CURLPROTO_HTTPS)? TRUE:FALSE);




      Curl_share_unlock(data, CURL_LOCK_DATA_COOKIE);
    }
    if(co) {
      struct Cookie *store=co;
      
      while(co) {
        if(co->value) {
          if(0 == count) {
            result = Curl_add_bufferf(req_buffer, "Cookie: ");
            if(result)
              break;
          }
          result = Curl_add_bufferf(req_buffer, "%s%s=%s", count?"; ":"", co->name, co->value);

          if(result)
            break;
          count++;
        }
        co = co->next; 
      }
      Curl_cookie_freelist(store, FALSE); 
    }
    if(addcookies && !result) {
      if(!count)
        result = Curl_add_bufferf(req_buffer, "Cookie: ");
      if(!result) {
        result = Curl_add_bufferf(req_buffer, "%s%s", count?"; ":"", addcookies);
        count++;
      }
    }
    if(count && !result)
      result = Curl_add_buffer(req_buffer, "\r\n", 2);

    if(result)
      return result;
  }


  result = Curl_add_timecondition(data, req_buffer);
  if(result)
    return result;

  result = Curl_add_custom_headers(conn, FALSE, req_buffer);
  if(result)
    return result;

  http->postdata = NULL;  
  Curl_pgrsSetUploadSize(data, -1); 

  

  switch(httpreq) {

  case HTTPREQ_POST_FORM:
    if(!http->sendit || conn->bits.authneg) {
      
      result = Curl_add_bufferf(req_buffer, "Content-Length: 0\r\n\r\n");
      if(result)
        return result;

      result = Curl_add_buffer_send(req_buffer, conn, &data->info.request_size, 0, FIRSTSOCKET);
      if(result)
        failf(data, "Failed sending POST request");
      else  Curl_setup_transfer(conn, FIRSTSOCKET, -1, TRUE, &http->readbytecount, -1, NULL);


      break;
    }

    if(Curl_FormInit(&http->form, http->sendit)) {
      failf(data, "Internal HTTP POST error!");
      return CURLE_HTTP_POST_ERROR;
    }

    
    http->form.fread_func = data->state.fread_func;

    
    data->state.fread_func = (curl_read_callback)Curl_FormReader;
    data->state.in = &http->form;

    http->sending = HTTPSEND_BODY;

    if(!data->req.upload_chunky && !Curl_checkheaders(conn, "Content-Length:")) {
      
      result = Curl_add_bufferf(req_buffer, "Content-Length: %" CURL_FORMAT_CURL_OFF_T "\r\n", http->postsize);

      if(result)
        return result;
    }

    result = expect100(data, conn, req_buffer);
    if(result)
      return result;

    {

      
      char *contentType;
      size_t linelength=0;
      contentType = Curl_formpostheader((void *)&http->form, &linelength);
      if(!contentType) {
        failf(data, "Could not get Content-Type header line!");
        return CURLE_HTTP_POST_ERROR;
      }

      result = Curl_add_buffer(req_buffer, contentType, linelength);
      if(result)
        return result;
    }

    
    result = Curl_add_buffer(req_buffer, "\r\n", 2);
    if(result)
      return result;

    
    Curl_pgrsSetUploadSize(data, http->postsize);

    
    result = Curl_add_buffer_send(req_buffer, conn, &data->info.request_size, 0, FIRSTSOCKET);
    if(result)
      failf(data, "Failed sending POST request");
    else  Curl_setup_transfer(conn, FIRSTSOCKET, -1, TRUE, &http->readbytecount, FIRSTSOCKET, &http->writebytecount);




    if(result) {
      Curl_formclean(&http->sendit); 
      return result;
    }

    
    result = Curl_convert_form(data, http->sendit);
    if(result) {
      Curl_formclean(&http->sendit); 
      return result;
    }

    break;

  case HTTPREQ_PUT: 

    if(conn->bits.authneg)
      postsize = 0;
    else postsize = data->state.infilesize;

    if((postsize != -1) && !data->req.upload_chunky && !Curl_checkheaders(conn, "Content-Length:")) {
      
      result = Curl_add_bufferf(req_buffer, "Content-Length: %" CURL_FORMAT_CURL_OFF_T "\r\n", postsize);

      if(result)
        return result;
    }

    if(postsize != 0) {
      result = expect100(data, conn, req_buffer);
      if(result)
        return result;
    }

    result = Curl_add_buffer(req_buffer, "\r\n", 2); 
    if(result)
      return result;

    
    Curl_pgrsSetUploadSize(data, postsize);

    
    result = Curl_add_buffer_send(req_buffer, conn, &data->info.request_size, 0, FIRSTSOCKET);
    if(result)
      failf(data, "Failed sending PUT request");
    else  Curl_setup_transfer(conn, FIRSTSOCKET, -1, TRUE, &http->readbytecount, postsize?FIRSTSOCKET:-1, postsize?&http->writebytecount:NULL);



    if(result)
      return result;
    break;

  case HTTPREQ_POST:
    

    if(conn->bits.authneg)
      postsize = 0;
    else {
      
      postsize = (data->state.infilesize != -1)? data->state.infilesize:
        (data->set.postfields? (curl_off_t)strlen(data->set.postfields):-1);
    }

    
    if((postsize != -1) && !data->req.upload_chunky && !Curl_checkheaders(conn, "Content-Length:")) {
      
      result = Curl_add_bufferf(req_buffer, "Content-Length: %" CURL_FORMAT_CURL_OFF_T "\r\n", postsize);

      if(result)
        return result;
    }

    if(!Curl_checkheaders(conn, "Content-Type:")) {
      result = Curl_add_bufferf(req_buffer, "Content-Type: application/" "x-www-form-urlencoded\r\n");

      if(result)
        return result;
    }

    
    ptr = Curl_checkheaders(conn, "Expect:");
    if(ptr) {
      data->state.expect100header = Curl_compareheader(ptr, "Expect:", "100-continue");
    }
    else if(postsize > TINY_INITIAL_POST_SIZE || postsize < 0) {
      result = expect100(data, conn, req_buffer);
      if(result)
        return result;
    }
    else data->state.expect100header = FALSE;

    if(data->set.postfields) {

      
      if(conn->httpversion != 20 && !data->state.expect100header && (postsize < MAX_INITIAL_POST_SIZE))  {

        

        result = Curl_add_buffer(req_buffer, "\r\n", 2); 
        if(result)
          return result;

        if(!data->req.upload_chunky) {
          
          result = Curl_add_buffer(req_buffer, data->set.postfields, (size_t)postsize);
          included_body = postsize;
        }
        else {
          if(postsize) {
            
            result = Curl_add_bufferf(req_buffer, "%x\r\n", (int)postsize);
            if(!result) {
              result = Curl_add_buffer(req_buffer, data->set.postfields, (size_t)postsize);
              if(!result)
                result = Curl_add_buffer(req_buffer, "\r\n", 2);
              included_body = postsize + 2;
            }
          }
          if(!result)
            result = Curl_add_buffer(req_buffer, "\x30\x0d\x0a\x0d\x0a", 5);
          
          included_body += 5;
        }
        if(result)
          return result;
        
        Curl_pgrsSetUploadSize(data, postsize);
      }
      else {
        
        http->postsize = postsize;
        http->postdata = data->set.postfields;

        http->sending = HTTPSEND_BODY;

        data->state.fread_func = (curl_read_callback)readmoredata;
        data->state.in = (void *)conn;

        
        Curl_pgrsSetUploadSize(data, http->postsize);

        result = Curl_add_buffer(req_buffer, "\r\n", 2); 
        if(result)
          return result;
      }
    }
    else {
      result = Curl_add_buffer(req_buffer, "\r\n", 2); 
      if(result)
        return result;

      if(data->req.upload_chunky && conn->bits.authneg) {
        
        result = Curl_add_buffer(req_buffer, "\x30\x0d\x0a\x0d\x0a", 5);
        
        if(result)
          return result;
      }

      else if(data->state.infilesize) {
        
        Curl_pgrsSetUploadSize(data, postsize?postsize:-1);

        
        if(!conn->bits.authneg) {
          http->postdata = (char *)&http->postdata;
          http->postsize = postsize;
        }
      }
    }
    
    result = Curl_add_buffer_send(req_buffer, conn, &data->info.request_size, (size_t)included_body, FIRSTSOCKET);

    if(result)
      failf(data, "Failed sending HTTP POST request");
    else Curl_setup_transfer(conn, FIRSTSOCKET, -1, TRUE, &http->readbytecount, http->postdata?FIRSTSOCKET:-1, http->postdata?&http->writebytecount:NULL);


    break;

  default:
    result = Curl_add_buffer(req_buffer, "\r\n", 2);
    if(result)
      return result;

    
    result = Curl_add_buffer_send(req_buffer, conn, &data->info.request_size, 0, FIRSTSOCKET);

    if(result)
      failf(data, "Failed sending HTTP request");
    else  Curl_setup_transfer(conn, FIRSTSOCKET, -1, TRUE, &http->readbytecount, http->postdata?FIRSTSOCKET:-1, http->postdata?&http->writebytecount:NULL);



  }
  if(result)
    return result;

  if(http->writebytecount) {
    
    Curl_pgrsSetUploadCounter(data, http->writebytecount);
    if(Curl_pgrsUpdate(conn))
      result = CURLE_ABORTED_BY_CALLBACK;

    if(http->writebytecount >= postsize) {
      
      infof(data, "upload completely sent off: %" CURL_FORMAT_CURL_OFF_T " out of %" CURL_FORMAT_CURL_OFF_T " bytes\n", http->writebytecount, postsize);

      data->req.upload_done = TRUE;
      data->req.keepon &= ~KEEP_SEND; 
      data->req.exp100 = EXP100_SEND_DATA; 
    }
  }

  if((conn->httpversion == 20) && data->req.upload_chunky)
    
    data->req.upload_chunky = FALSE;
  return result;
}


static bool checkhttpprefix(struct Curl_easy *data, const char *s)

{
  struct curl_slist *head = data->set.http200aliases;
  bool rc = FALSE;

  
  char *scratch = strdup(s);
  if(NULL == scratch) {
    failf (data, "Failed to allocate memory for conversion!");
    return FALSE; 
  }
  if(CURLE_OK != Curl_convert_from_network(data, scratch, strlen(s)+1)) {
    
    free(scratch);
    return FALSE; 
  }
  s = scratch;


  while(head) {
    if(checkprefix(head->data, s)) {
      rc = TRUE;
      break;
    }
    head = head->next;
  }

  if(!rc && (checkprefix("HTTP/", s)))
    rc = TRUE;


  free(scratch);

  return rc;
}


static bool checkrtspprefix(struct Curl_easy *data, const char *s)

{


  
  char *scratch = strdup(s);
  if(NULL == scratch) {
    failf (data, "Failed to allocate memory for conversion!");
    return FALSE; 
  }
  if(CURLE_OK != Curl_convert_from_network(data, scratch, strlen(s)+1)) {
    
    free(scratch);
    return FALSE; 
  }
  s = scratch;

  (void)data; 

  if(checkprefix("RTSP/", s))
    return TRUE;
  else return FALSE;
}


static bool checkprotoprefix(struct Curl_easy *data, struct connectdata *conn, const char *s)

{

  if(conn->handler->protocol & CURLPROTO_RTSP)
    return checkrtspprefix(data, s);

  (void)conn;


  return checkhttpprefix(data, s);
}


static CURLcode header_append(struct Curl_easy *data, struct SingleRequest *k, size_t length)

{
  if(k->hbuflen + length >= data->state.headersize) {
    
    char *newbuff;
    size_t hbufp_index;
    size_t newsize;

    if(k->hbuflen + length > CURL_MAX_HTTP_HEADER) {
      
      failf (data, "Avoided giant realloc for header (max is %d)!", CURL_MAX_HTTP_HEADER);
      return CURLE_OUT_OF_MEMORY;
    }

    newsize=CURLMAX((k->hbuflen+ length)*3/2, data->state.headersize*2);
    hbufp_index = k->hbufp - data->state.headerbuff;
    newbuff = realloc(data->state.headerbuff, newsize);
    if(!newbuff) {
      failf (data, "Failed to alloc memory for big header!");
      return CURLE_OUT_OF_MEMORY;
    }
    data->state.headersize=newsize;
    data->state.headerbuff = newbuff;
    k->hbufp = data->state.headerbuff + hbufp_index;
  }
  memcpy(k->hbufp, k->str_start, length);
  k->hbufp += length;
  k->hbuflen += length;
  *k->hbufp = 0;

  return CURLE_OK;
}

static void print_http_error(struct Curl_easy *data)
{
  struct SingleRequest *k = &data->req;
  char *beg = k->p;

  
  if(!strncmp(beg, "HTTP", 4)) {

    
    beg = strchr(beg, ' ');
    if(beg && *++beg) {

      
      char end_char = '\r';
      char *end = strchr(beg, end_char);
      if(!end) {
        
        end_char = '\n';
        end = strchr(beg, end_char);
      }

      if(end) {
        
        *end = '\0';
        failf(data, "The requested URL returned error: %s", beg);

        
        *end = end_char;
        return;
      }
    }
  }

  
  failf(data, "The requested URL returned error: %d", k->httpcode);
}


CURLcode Curl_http_readwrite_headers(struct Curl_easy *data, struct connectdata *conn, ssize_t *nread, bool *stop_reading)


{
  CURLcode result;
  struct SingleRequest *k = &data->req;

  
  do {
    size_t rest_length;
    size_t full_length;
    int writetype;

    
    k->str_start = k->str;

    
    k->end_ptr = memchr(k->str_start, 0x0a, *nread);

    if(!k->end_ptr) {
      
      result = header_append(data, k, *nread);
      if(result)
        return result;

      if(!k->headerline && (k->hbuflen>5)) {
        
        if(!checkprotoprefix(data, conn, data->state.headerbuff)) {
          
          k->header = FALSE;
          k->badheader = HEADER_ALLBAD;
          break;
        }
      }

      break; 
    }

    
    rest_length = (k->end_ptr - k->str)+1;
    *nread -= (ssize_t)rest_length;

    k->str = k->end_ptr + 1; 

    full_length = k->str - k->str_start;

    result = header_append(data, k, full_length);
    if(result)
      return result;

    k->end_ptr = k->hbufp;
    k->p = data->state.headerbuff;

    

    if(!k->headerline) {
      
      if((k->hbuflen>5) && !checkprotoprefix(data, conn, data->state.headerbuff)) {
        
        k->header = FALSE;
        if(*nread)
          
          k->badheader = HEADER_PARTHEADER;
        else {
          
          k->badheader = HEADER_ALLBAD;
          *nread = (ssize_t)rest_length;
        }
        break;
      }
    }

    
    if((0x0a == *k->p) || (0x0d == *k->p)) {
      size_t headerlen;
      


      if(0x0d == *k->p) {
        *k->p = '\r'; 
        k->p++;       
      }
      if(0x0a == *k->p) {
        *k->p = '\n'; 
        k->p++;       
      }

      if('\r' == *k->p)
        k->p++; 
      if('\n' == *k->p)
        k->p++; 


      if(100 <= k->httpcode && 199 >= k->httpcode) {
        
        switch(k->httpcode) {
        case 100:
          
          k->header = TRUE;
          k->headerline = 0; 

          
          if(k->exp100 > EXP100_SEND_DATA) {
            k->exp100 = EXP100_SEND_DATA;
            k->keepon |= KEEP_SEND;
          }
          break;
        case 101:
          
          if(k->upgr101 == UPGR101_REQUESTED) {
            
            infof(data, "Received 101\n");
            k->upgr101 = UPGR101_RECEIVED;

            
            k->header = TRUE;
            k->headerline = 0; 

            
            result = Curl_http2_switched(conn, k->str, *nread);
            if(result)
              return result;
            *nread = 0;
          }
          else {
            
            k->header = FALSE; 
          }
          break;
        default:
          
          k->header = TRUE;
          k->headerline = 0; 
          break;
        }
      }
      else {
        k->header = FALSE; 

        if((k->size == -1) && !k->chunk && !conn->bits.close && (conn->httpversion == 11) && !(conn->handler->protocol & CURLPROTO_RTSP) && data->set.httpreq != HTTPREQ_HEAD) {


          
          infof(data, "no chunk, no close, no size. Assume close to " "signal end\n");
          streamclose(conn, "HTTP: No end-of-message indicator");
        }
      }

      

      if(conn->bits.close && (((data->req.httpcode == 401) && (conn->ntlm.state == NTLMSTATE_TYPE2)) || ((data->req.httpcode == 407) && (conn->proxyntlm.state == NTLMSTATE_TYPE2)))) {



        infof(data, "Connection closure while negotiating auth (HTTP 1.0?)\n");
        data->state.authproblem = TRUE;
      }


      
      if(http_should_fail(conn)) {
        failf (data, "The requested URL returned error: %d", k->httpcode);
        return CURLE_HTTP_RETURNED_ERROR;
      }

      
      writetype = CLIENTWRITE_HEADER;
      if(data->set.include_header)
        writetype |= CLIENTWRITE_BODY;

      headerlen = k->p - data->state.headerbuff;

      result = Curl_client_write(conn, writetype, data->state.headerbuff, headerlen);

      if(result)
        return result;

      data->info.header_size += (long)headerlen;
      data->req.headerbytecount += (long)headerlen;

      data->req.deductheadercount = (100 <= k->httpcode && 199 >= k->httpcode)?data->req.headerbytecount:0;

      
      result = Curl_http_auth_act(conn);

      if(result)
        return result;

      if(k->httpcode >= 300) {
        if((!conn->bits.authneg) && !conn->bits.close && !conn->bits.rewindaftersend) {
          

          switch(data->set.httpreq) {
          case HTTPREQ_PUT:
          case HTTPREQ_POST:
          case HTTPREQ_POST_FORM:
            
            if(!k->upload_done) {
              if(data->set.http_keep_sending_on_error) {
                infof(data, "HTTP error before end of send, keep sending\n");
                if(k->exp100 > EXP100_SEND_DATA) {
                  k->exp100 = EXP100_SEND_DATA;
                  k->keepon |= KEEP_SEND;
                }
              }
              else {
                infof(data, "HTTP error before end of send, stop sending\n");
                streamclose(conn, "Stop sending data before everything sent");
                k->upload_done = TRUE;
                k->keepon &= ~KEEP_SEND; 
                if(data->state.expect100header)
                  k->exp100 = EXP100_FAILED;
              }
            }
            break;

          default: 
            break;
          }
        }

        if(conn->bits.rewindaftersend) {
          
          infof(data, "Keep sending data to get tossed away!\n");
          k->keepon |= KEEP_SEND;
        }
      }

      if(!k->header) {
        
        if(data->set.opt_no_body)
          *stop_reading = TRUE;

        else if((conn->handler->protocol & CURLPROTO_RTSP) && (data->set.rtspreq == RTSPREQ_DESCRIBE) && (k->size <= -1))

          
          *stop_reading = TRUE;

        else {
          
          
          if(k->chunk)
            k->maxdownload = k->size = -1;
        }
        if(-1 != k->size) {
          

          Curl_pgrsSetDownloadSize(data, k->size);
          k->maxdownload = k->size;
        }

        
        if(0 == k->maxdownload)
          *stop_reading = TRUE;

        if(*stop_reading) {
          
          k->keepon &= ~KEEP_RECV;
        }

        if(data->set.verbose)
          Curl_debug(data, CURLINFO_HEADER_IN, k->str_start, headerlen, conn);
        break;          
      }

      
      k->hbufp = data->state.headerbuff;
      k->hbuflen = 0;
      continue;
    }

    

    if(!k->headerline++) {
      
      int httpversion_major;
      int rtspversion_major;
      int nc = 0;



      CURLcode res;
      char scratch[SCRATCHSIZE+1]; 
      
      strncpy(&scratch[0], k->p, SCRATCHSIZE);
      scratch[SCRATCHSIZE] = 0; 
      res = Curl_convert_from_network(data, &scratch[0], SCRATCHSIZE);

      if(res)
        
        return res;




      if(conn->handler->protocol & PROTO_FAMILY_HTTP) {
        
        nc = sscanf(HEADER1, " HTTP/%d.%d %d", &httpversion_major, &conn->httpversion, &k->httpcode);




        if(nc == 1 && httpversion_major == 2 && 1 == sscanf(HEADER1, " HTTP/2 %d", &k->httpcode)) {
          conn->httpversion = 0;
          nc = 3;
        }

        if(nc==3) {
          conn->httpversion += 10 * httpversion_major;

          if(k->upgr101 == UPGR101_RECEIVED) {
            
            if(conn->httpversion != 20)
              infof(data, "Lying server, not serving HTTP/2\n");
          }
        }
        else {
          
          nc=sscanf(HEADER1, " HTTP %3d", &k->httpcode);
          conn->httpversion = 10;

          
          if(!nc) {
            if(checkhttpprefix(data, k->p)) {
              nc = 1;
              k->httpcode = 200;
              conn->httpversion = 10;
            }
          }
        }
      }
      else if(conn->handler->protocol & CURLPROTO_RTSP) {
        nc = sscanf(HEADER1, " RTSP/%d.%d %3d", &rtspversion_major, &conn->rtspversion, &k->httpcode);



        if(nc==3) {
          conn->rtspversion += 10 * rtspversion_major;
          conn->httpversion = 11; 
        }
        else {
          
          nc = 0;
        }
      }

      if(nc) {
        data->info.httpcode = k->httpcode;

        data->info.httpversion = conn->httpversion;
        if(!data->state.httpversion || data->state.httpversion > conn->httpversion)
          
          data->state.httpversion = conn->httpversion;

        
        if(data->set.http_fail_on_error && (k->httpcode >= 400) && ((k->httpcode != 401) || !conn->bits.user_passwd) && ((k->httpcode != 407) || !conn->bits.proxy_user_passwd) ) {


          if(data->state.resume_from && (data->set.httpreq==HTTPREQ_GET) && (k->httpcode == 416)) {

            
          }
          else {
            
            print_http_error(data);
            return CURLE_HTTP_RETURNED_ERROR;
          }
        }

        if(conn->httpversion == 10) {
          
          infof(data, "HTTP 1.0, assume close after body\n");
          connclose(conn, "HTTP/1.0 close after body");
        }
        else if(conn->httpversion == 20 || (k->upgr101 == UPGR101_REQUESTED && k->httpcode == 101)) {
          DEBUGF(infof(data, "HTTP/2 found, allow multiplexing\n"));

          
          conn->bundle->multiuse = BUNDLE_MULTIPLEX;
        }
        else if(conn->httpversion >= 11 && !conn->bits.close) {
          
          DEBUGF(infof(data, "HTTP 1.1 or later with persistent connection, " "pipelining supported\n"));

          
          if(conn->bundle) {
            if(!Curl_pipeline_site_blacklisted(data, conn))
              conn->bundle->multiuse = BUNDLE_PIPELINING;
          }
        }

        switch(k->httpcode) {
        case 204:
          
          
        case 304:
          
          if(data->set.timecondition)
            data->info.timecond = TRUE;
          k->size=0;
          k->maxdownload=0;
          k->ignorecl = TRUE; 
          break;
        default:
          
          break;
        }
      }
      else {
        k->header = FALSE;   
        break;
      }
    }

    result = Curl_convert_from_network(data, k->p, strlen(k->p));
    
    if(result)
      return result;

    
    if(!k->ignorecl && !data->set.ignorecl && checkprefix("Content-Length:", k->p)) {
      curl_off_t contentlength = curlx_strtoofft(k->p+15, NULL, 10);
      if(data->set.max_filesize && contentlength > data->set.max_filesize) {
        failf(data, "Maximum file size exceeded");
        return CURLE_FILESIZE_EXCEEDED;
      }
      if(contentlength >= 0) {
        k->size = contentlength;
        k->maxdownload = k->size;
        
        Curl_pgrsSetDownloadSize(data, k->size);
      }
      else {
        
        streamclose(conn, "negative content-length");
        infof(data, "Negative content-length: %" CURL_FORMAT_CURL_OFF_T ", closing after transfer\n", contentlength);
      }
    }
    
    else if(checkprefix("Content-Type:", k->p)) {
      char *contenttype = Curl_copy_header_value(k->p);
      if(!contenttype)
        return CURLE_OUT_OF_MEMORY;
      if(!*contenttype)
        
        free(contenttype);
      else {
        Curl_safefree(data->info.contenttype);
        data->info.contenttype = contenttype;
      }
    }
    else if(checkprefix("Server:", k->p)) {
      if(conn->httpversion < 20) {
        
        char *server_name = Curl_copy_header_value(k->p);

        
        if(conn->bundle && (conn->bundle->multiuse == BUNDLE_PIPELINING)) {
          if(Curl_pipeline_server_blacklisted(data, server_name))
            conn->bundle->multiuse = BUNDLE_NO_MULTIUSE;
        }
        free(server_name);
      }
    }
    else if((conn->httpversion == 10) && conn->bits.httpproxy && Curl_compareheader(k->p, "Proxy-Connection:", "keep-alive")) {


      
      connkeep(conn, "Proxy-Connection keep-alive"); 
      infof(data, "HTTP/1.0 proxy connection set to keep alive!\n");
    }
    else if((conn->httpversion == 11) && conn->bits.httpproxy && Curl_compareheader(k->p, "Proxy-Connection:", "close")) {


      
      connclose(conn, "Proxy-Connection: asked to close after done");
      infof(data, "HTTP/1.1 proxy connection set close!\n");
    }
    else if((conn->httpversion == 10) && Curl_compareheader(k->p, "Connection:", "keep-alive")) {
      
      connkeep(conn, "Connection keep-alive");
      infof(data, "HTTP/1.0 connection set to keep alive!\n");
    }
    else if(Curl_compareheader(k->p, "Connection:", "close")) {
      
      streamclose(conn, "Connection: close used");
    }
    else if(checkprefix("Transfer-Encoding:", k->p)) {
      
      

      char *start;

      
      start = k->p + 18;

      for(;;) {
        
        while(*start && (ISSPACE(*start) || (*start == ',')))
          start++;

        if(checkprefix("chunked", start)) {
          k->chunk = TRUE; 

          
          Curl_httpchunk_init(conn);

          start += 7;
        }

        if(k->auto_decoding)
          
          break;

        if(checkprefix("identity", start)) {
          k->auto_decoding = IDENTITY;
          start += 8;
        }
        else if(checkprefix("deflate", start)) {
          k->auto_decoding = DEFLATE;
          start += 7;
        }
        else if(checkprefix("gzip", start)) {
          k->auto_decoding = GZIP;
          start += 4;
        }
        else if(checkprefix("x-gzip", start)) {
          k->auto_decoding = GZIP;
          start += 6;
        }
        else  break;


      }

    }
    else if(checkprefix("Content-Encoding:", k->p) && data->set.str[STRING_ENCODING]) {
      
      char *start;

      
      start = k->p + 17;
      while(*start && ISSPACE(*start))
        start++;

      
      if(checkprefix("identity", start))
        k->auto_decoding = IDENTITY;
      else if(checkprefix("deflate", start))
        k->auto_decoding = DEFLATE;
      else if(checkprefix("gzip", start)
              || checkprefix("x-gzip", start))
        k->auto_decoding = GZIP;
    }
    else if(checkprefix("Content-Range:", k->p)) {
      

      char *ptr = k->p + 14;

      
      while(*ptr && !ISDIGIT(*ptr) && *ptr != '*')
        ptr++;

      
      if(ISDIGIT(*ptr)) {
        k->offset = curlx_strtoofft(ptr, NULL, 10);

        if(data->state.resume_from == k->offset)
          
          k->content_range = TRUE;
      }
      else data->state.resume_from = 0;
    }

    else if(data->cookies && checkprefix("Set-Cookie:", k->p)) {
      Curl_share_lock(data, CURL_LOCK_DATA_COOKIE, CURL_LOCK_ACCESS_SINGLE);
      Curl_cookie_add(data, data->cookies, TRUE, k->p+11,  conn->allocptr.cookiehost? conn->allocptr.cookiehost:conn->host.name, data->state.path);




      Curl_share_unlock(data, CURL_LOCK_DATA_COOKIE);
    }

    else if(checkprefix("Last-Modified:", k->p) && (data->set.timecondition || data->set.get_filetime) ) {
      time_t secs=time(NULL);
      k->timeofdoc = curl_getdate(k->p+strlen("Last-Modified:"), &secs);
      if(data->set.get_filetime)
        data->info.filetime = (long)k->timeofdoc;
    }
    else if((checkprefix("WWW-Authenticate:", k->p) && (401 == k->httpcode)) || (checkprefix("Proxy-authenticate:", k->p) && (407 == k->httpcode))) {



      bool proxy = (k->httpcode == 407) ? TRUE : FALSE;
      char *auth = Curl_copy_header_value(k->p);
      if(!auth)
        return CURLE_OUT_OF_MEMORY;

      result = Curl_http_input_auth(conn, proxy, auth);

      free(auth);

      if(result)
        return result;
    }
    else if((k->httpcode >= 300 && k->httpcode < 400) && checkprefix("Location:", k->p) && !data->req.location) {

      
      char *location = Curl_copy_header_value(k->p);
      if(!location)
        return CURLE_OUT_OF_MEMORY;
      if(!*location)
        
        free(location);
      else {
        data->req.location = location;

        if(data->set.http_follow_location) {
          DEBUGASSERT(!data->req.newurl);
          data->req.newurl = strdup(data->req.location); 
          if(!data->req.newurl)
            return CURLE_OUT_OF_MEMORY;

          
          result = http_perhapsrewind(conn);
          if(result)
            return result;
        }
      }
    }
    else if(conn->handler->protocol & CURLPROTO_RTSP) {
      result = Curl_rtsp_parseheader(conn, k->p);
      if(result)
        return result;
    }

    

    writetype = CLIENTWRITE_HEADER;
    if(data->set.include_header)
      writetype |= CLIENTWRITE_BODY;

    if(data->set.verbose)
      Curl_debug(data, CURLINFO_HEADER_IN, k->p, (size_t)k->hbuflen, conn);

    result = Curl_client_write(conn, writetype, k->p, k->hbuflen);
    if(result)
      return result;

    data->info.header_size += (long)k->hbuflen;
    data->req.headerbytecount += (long)k->hbuflen;

    
    k->hbufp = data->state.headerbuff;
    k->hbuflen = 0;
  }
  while(*k->str); 

  

  return CURLE_OK;
}


