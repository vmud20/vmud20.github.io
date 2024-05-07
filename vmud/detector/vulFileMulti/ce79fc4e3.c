








































































static int http_getsock_do(struct Curl_easy *data, struct connectdata *conn, curl_socket_t *socks);

static bool http_should_fail(struct Curl_easy *data);


static CURLcode add_haproxy_protocol_header(struct Curl_easy *data);



static CURLcode https_connecting(struct Curl_easy *data, bool *done);
static int https_getsock(struct Curl_easy *data, struct connectdata *conn, curl_socket_t *socks);




static CURLcode http_setup_conn(struct Curl_easy *data, struct connectdata *conn);


const struct Curl_handler Curl_handler_http = {
  "HTTP",                                http_setup_conn, Curl_http, Curl_http_done, ZERO_NULL, Curl_http_connect, ZERO_NULL, ZERO_NULL, ZERO_NULL, http_getsock_do, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, PORT_HTTP, CURLPROTO_HTTP, CURLPROTO_HTTP, PROTOPT_CREDSPERREQUEST | PROTOPT_USERPWDCTRL };























const struct Curl_handler Curl_handler_https = {
  "HTTPS",                               http_setup_conn, Curl_http, Curl_http_done, ZERO_NULL, Curl_http_connect, https_connecting, ZERO_NULL, https_getsock, http_getsock_do, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, PORT_HTTPS, CURLPROTO_HTTPS, CURLPROTO_HTTP, PROTOPT_SSL | PROTOPT_CREDSPERREQUEST | PROTOPT_ALPN_NPN | PROTOPT_USERPWDCTRL };






















static CURLcode http_setup_conn(struct Curl_easy *data, struct connectdata *conn)
{
  
  struct HTTP *http;
  DEBUGASSERT(data->req.p.http == NULL);

  http = calloc(1, sizeof(struct HTTP));
  if(!http)
    return CURLE_OUT_OF_MEMORY;

  Curl_mime_initpart(&http->form, data);
  data->req.p.http = http;

  if(data->state.httpwant == CURL_HTTP_VERSION_3) {
    if(conn->handler->flags & PROTOPT_SSL)
      
      conn->transport = TRNSPRT_QUIC;
    else {
      failf(data, "HTTP/3 requested for non-HTTPS URL");
      return CURLE_URL_MALFORMAT;
    }
  }
  else {
    if(!CONN_INUSE(conn))
      
      Curl_http2_setup_conn(conn);
    Curl_http2_setup_req(data);
  }
  return CURLE_OK;
}



char *Curl_checkProxyheaders(struct Curl_easy *data, const struct connectdata *conn, const char *thisheader, const size_t thislen)


{
  struct curl_slist *head;

  for(head = (conn->bits.proxy && data->set.sep_headers) ? data->set.proxyheaders : data->set.headers;
      head; head = head->next) {
    if(strncasecompare(head->data, thisheader, thislen) && Curl_headersep(head->data[thislen]))
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



static CURLcode http_output_basic(struct Curl_easy *data, bool proxy)
{
  size_t size = 0;
  char *authorization = NULL;
  char **userp;
  const char *user;
  const char *pwd;
  CURLcode result;
  char *out;

  
  if(proxy) {

    userp = &data->state.aptr.proxyuserpwd;
    user = data->state.aptr.proxyuser;
    pwd = data->state.aptr.proxypasswd;

    return CURLE_NOT_BUILT_IN;

  }
  else {
    userp = &data->state.aptr.userpwd;
    user = data->state.aptr.user;
    pwd = data->state.aptr.passwd;
  }

  out = aprintf("%s:%s", user ? user : "", pwd ? pwd : "");
  if(!out)
    return CURLE_OUT_OF_MEMORY;

  result = Curl_base64_encode(out, strlen(out), &authorization, &size);
  if(result)
    goto fail;

  if(!authorization) {
    result = CURLE_REMOTE_ACCESS_DENIED;
    goto fail;
  }

  free(*userp);
  *userp = aprintf("%sAuthorization: Basic %s\r\n", proxy ? "Proxy-" : "", authorization);

  free(authorization);
  if(!*userp) {
    result = CURLE_OUT_OF_MEMORY;
    goto fail;
  }

  fail:
  free(out);
  return result;
}


static CURLcode http_output_bearer(struct Curl_easy *data)
{
  char **userp;
  CURLcode result = CURLE_OK;

  userp = &data->state.aptr.userpwd;
  free(*userp);
  *userp = aprintf("Authorization: Bearer %s\r\n", data->set.str[STRING_BEARER]);

  if(!*userp) {
    result = CURLE_OUT_OF_MEMORY;
    goto fail;
  }

  fail:
  return result;
}




static bool pickoneauth(struct auth *pick, unsigned long mask)
{
  bool picked;
  
  unsigned long avail = pick->avail & pick->want & mask;
  picked = TRUE;

  
  if(avail & CURLAUTH_NEGOTIATE)
    pick->picked = CURLAUTH_NEGOTIATE;
  else if(avail & CURLAUTH_BEARER)
    pick->picked = CURLAUTH_BEARER;
  else if(avail & CURLAUTH_DIGEST)
    pick->picked = CURLAUTH_DIGEST;
  else if(avail & CURLAUTH_NTLM)
    pick->picked = CURLAUTH_NTLM;
  else if(avail & CURLAUTH_NTLM_WB)
    pick->picked = CURLAUTH_NTLM_WB;
  else if(avail & CURLAUTH_BASIC)
    pick->picked = CURLAUTH_BASIC;
  else if(avail & CURLAUTH_AWS_SIGV4)
    pick->picked = CURLAUTH_AWS_SIGV4;
  else {
    pick->picked = CURLAUTH_PICKNONE; 
    picked = FALSE;
  }
  pick->avail = CURLAUTH_NONE; 

  return picked;
}


static CURLcode http_perhapsrewind(struct Curl_easy *data, struct connectdata *conn)
{
  struct HTTP *http = data->req.p.http;
  curl_off_t bytessent;
  curl_off_t expectsend = -1; 

  if(!http)
    
    return CURLE_OK;

  switch(data->state.httpreq) {
  case HTTPREQ_GET:
  case HTTPREQ_HEAD:
    return CURLE_OK;
  default:
    break;
  }

  bytessent = data->req.writebytecount;

  if(conn->bits.authneg) {
    
    expectsend = 0;
  }
  else if(!conn->bits.protoconnstart) {
    
    expectsend = 0;
  }
  else {
    
    switch(data->state.httpreq) {
    case HTTPREQ_POST:
    case HTTPREQ_PUT:
      if(data->state.infilesize != -1)
        expectsend = data->state.infilesize;
      break;
    case HTTPREQ_POST_FORM:
    case HTTPREQ_POST_MIME:
      expectsend = http->postsize;
      break;
    default:
      break;
    }
  }

  conn->bits.rewindaftersend = FALSE; 

  if((expectsend == -1) || (expectsend > bytessent)) {

    
    if((data->state.authproxy.picked == CURLAUTH_NTLM) || (data->state.authhost.picked == CURLAUTH_NTLM) || (data->state.authproxy.picked == CURLAUTH_NTLM_WB) || (data->state.authhost.picked == CURLAUTH_NTLM_WB)) {


      if(((expectsend - bytessent) < 2000) || (conn->http_ntlm_state != NTLMSTATE_NONE) || (conn->proxy_ntlm_state != NTLMSTATE_NONE)) {

        

        
        if(!conn->bits.authneg && (conn->writesockfd != CURL_SOCKET_BAD)) {
          conn->bits.rewindaftersend = TRUE;
          infof(data, "Rewind stream after send");
        }

        return CURLE_OK;
      }

      if(conn->bits.close)
        
        return CURLE_OK;

      infof(data, "NTLM send, close instead of sending %" CURL_FORMAT_CURL_OFF_T " bytes", (curl_off_t)(expectsend - bytessent));

    }


    
    if((data->state.authproxy.picked == CURLAUTH_NEGOTIATE) || (data->state.authhost.picked == CURLAUTH_NEGOTIATE)) {
      if(((expectsend - bytessent) < 2000) || (conn->http_negotiate_state != GSS_AUTHNONE) || (conn->proxy_negotiate_state != GSS_AUTHNONE)) {

        

        
        if(!conn->bits.authneg && (conn->writesockfd != CURL_SOCKET_BAD)) {
          conn->bits.rewindaftersend = TRUE;
          infof(data, "Rewind stream after send");
        }

        return CURLE_OK;
      }

      if(conn->bits.close)
        
        return CURLE_OK;

      infof(data, "NEGOTIATE send, close instead of sending %" CURL_FORMAT_CURL_OFF_T " bytes", (curl_off_t)(expectsend - bytessent));

    }


    
    streamclose(conn, "Mid-auth HTTP and much data left to send");
    data->req.size = 0; 

    
  }

  if(bytessent)
    
    return Curl_readrewind(data);

  return CURLE_OK;
}



CURLcode Curl_http_auth_act(struct Curl_easy *data)
{
  struct connectdata *conn = data->conn;
  bool pickhost = FALSE;
  bool pickproxy = FALSE;
  CURLcode result = CURLE_OK;
  unsigned long authmask = ~0ul;

  if(!data->set.str[STRING_BEARER])
    authmask &= (unsigned long)~CURLAUTH_BEARER;

  if(100 <= data->req.httpcode && 199 >= data->req.httpcode)
    
    return CURLE_OK;

  if(data->state.authproblem)
    return data->set.http_fail_on_error?CURLE_HTTP_RETURNED_ERROR:CURLE_OK;

  if((data->state.aptr.user || data->set.str[STRING_BEARER]) && ((data->req.httpcode == 401) || (conn->bits.authneg && data->req.httpcode < 300))) {

    pickhost = pickoneauth(&data->state.authhost, authmask);
    if(!pickhost)
      data->state.authproblem = TRUE;
    if(data->state.authhost.picked == CURLAUTH_NTLM && conn->httpversion > 11) {
      infof(data, "Forcing HTTP/1.1 for NTLM");
      connclose(conn, "Force HTTP/1.1 connection");
      data->state.httpwant = CURL_HTTP_VERSION_1_1;
    }
  }

  if(conn->bits.proxy_user_passwd && ((data->req.httpcode == 407) || (conn->bits.authneg && data->req.httpcode < 300))) {

    pickproxy = pickoneauth(&data->state.authproxy, authmask & ~CURLAUTH_BEARER);
    if(!pickproxy)
      data->state.authproblem = TRUE;
  }


  if(pickhost || pickproxy) {
    if((data->state.httpreq != HTTPREQ_GET) && (data->state.httpreq != HTTPREQ_HEAD) && !conn->bits.rewindaftersend) {

      result = http_perhapsrewind(data, conn);
      if(result)
        return result;
    }
    
    Curl_safefree(data->req.newurl);
    data->req.newurl = strdup(data->state.url); 
    if(!data->req.newurl)
      return CURLE_OUT_OF_MEMORY;
  }
  else if((data->req.httpcode < 300) && (!data->state.authhost.done) && conn->bits.authneg) {

    
    if((data->state.httpreq != HTTPREQ_GET) && (data->state.httpreq != HTTPREQ_HEAD)) {
      data->req.newurl = strdup(data->state.url); 
      if(!data->req.newurl)
        return CURLE_OUT_OF_MEMORY;
      data->state.authhost.done = TRUE;
    }
  }
  if(http_should_fail(data)) {
    failf(data, "The requested URL returned error: %d", data->req.httpcode);
    result = CURLE_HTTP_RETURNED_ERROR;
  }

  return result;
}



static CURLcode output_auth_headers(struct Curl_easy *data, struct connectdata *conn, struct auth *authstatus, const char *request, const char *path, bool proxy)





{
  const char *auth = NULL;
  CURLcode result = CURLE_OK;
  (void)conn;


  (void)request;
  (void)path;


  if(authstatus->picked == CURLAUTH_AWS_SIGV4) {
    auth = "AWS_SIGV4";
    result = Curl_output_aws_sigv4(data, proxy);
    if(result)
      return result;
  }
  else   if(authstatus->picked == CURLAUTH_NEGOTIATE) {


    auth = "Negotiate";
    result = Curl_output_negotiate(data, conn, proxy);
    if(result)
      return result;
  }
  else   if(authstatus->picked == CURLAUTH_NTLM) {


    auth = "NTLM";
    result = Curl_output_ntlm(data, proxy);
    if(result)
      return result;
  }
  else   if(authstatus->picked == CURLAUTH_NTLM_WB) {


    auth = "NTLM_WB";
    result = Curl_output_ntlm_wb(data, conn, proxy);
    if(result)
      return result;
  }
  else   if(authstatus->picked == CURLAUTH_DIGEST) {


    auth = "Digest";
    result = Curl_output_digest(data, proxy, (const unsigned char *)request, (const unsigned char *)path);


    if(result)
      return result;
  }
  else  if(authstatus->picked == CURLAUTH_BASIC) {

    
    if(  (proxy && conn->bits.proxy_user_passwd && !Curl_checkProxyheaders(data, conn, STRCONST("Proxy-authorization"))) ||  (!proxy && data->state.aptr.user && !Curl_checkheaders(data, STRCONST("Authorization")))) {





      auth = "Basic";
      result = http_output_basic(data, proxy);
      if(result)
        return result;
    }

    
    authstatus->done = TRUE;
  }
  if(authstatus->picked == CURLAUTH_BEARER) {
    
    if((!proxy && data->set.str[STRING_BEARER] && !Curl_checkheaders(data, STRCONST("Authorization")))) {
      auth = "Bearer";
      result = http_output_bearer(data);
      if(result)
        return result;
    }

    
    authstatus->done = TRUE;
  }

  if(auth) {

    infof(data, "%s auth using %s with user '%s'", proxy ? "Proxy" : "Server", auth, proxy ? (data->state.aptr.proxyuser ? data->state.aptr.proxyuser : "") :


          (data->state.aptr.user ? data->state.aptr.user : ""));

    infof(data, "Server auth using %s with user '%s'", auth, data->state.aptr.user ? data->state.aptr.user : "");


    authstatus->multipass = (!authstatus->done) ? TRUE : FALSE;
  }
  else authstatus->multipass = FALSE;

  return CURLE_OK;
}


CURLcode Curl_http_output_auth(struct Curl_easy *data, struct connectdata *conn, const char *request, Curl_HttpReq httpreq, const char *path, bool proxytunnel)





{
  CURLcode result = CURLE_OK;
  struct auth *authhost;
  struct auth *authproxy;

  DEBUGASSERT(data);

  authhost = &data->state.authhost;
  authproxy = &data->state.authproxy;

  if(  (conn->bits.httpproxy && conn->bits.proxy_user_passwd) ||  data->state.aptr.user || data->set.str[STRING_BEARER])



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


  
  if(conn->bits.httpproxy && (conn->bits.tunnel_proxy == (bit)proxytunnel)) {
    result = output_auth_headers(data, conn, authproxy, request, path, TRUE);
    if(result)
      return result;
  }
  else  (void)proxytunnel;


    
    authproxy->done = TRUE;

  
  if(!data->state.this_is_a_follow ||  conn->bits.netrc ||  !data->state.first_host || data->set.allow_auth_to_other_hosts || strcasecompare(data->state.first_host, conn->host.name)) {





    result = output_auth_headers(data, conn, authhost, request, path, FALSE);
  }
  else authhost->done = TRUE;

  if(((authhost->multipass && !authhost->done) || (authproxy->multipass && !authproxy->done)) && (httpreq != HTTPREQ_GET) && (httpreq != HTTPREQ_HEAD)) {


    
    conn->bits.authneg = TRUE;
  }
  else conn->bits.authneg = FALSE;

  return result;
}



CURLcode Curl_http_output_auth(struct Curl_easy *data, struct connectdata *conn, const char *request, Curl_HttpReq httpreq, const char *path, bool proxytunnel)





{
  (void)data;
  (void)conn;
  (void)request;
  (void)httpreq;
  (void)path;
  (void)proxytunnel;
  return CURLE_OK;
}




static int is_valid_auth_separator(char ch)
{
  return ch == '\0' || ch == ',' || ISSPACE(ch);
}

CURLcode Curl_http_input_auth(struct Curl_easy *data, bool proxy, const char *auth)
{
  
  struct connectdata *conn = data->conn;

  curlnegotiate *negstate = proxy ? &conn->proxy_negotiate_state :
                                    &conn->http_negotiate_state;

  unsigned long *availp;
  struct auth *authp;

  (void) conn; 

  if(proxy) {
    availp = &data->info.proxyauthavail;
    authp = &data->state.authproxy;
  }
  else {
    availp = &data->info.httpauthavail;
    authp = &data->state.authhost;
  }

  

  while(*auth) {

    if(checkprefix("Negotiate", auth) && is_valid_auth_separator(auth[9])) {
      if((authp->avail & CURLAUTH_NEGOTIATE) || Curl_auth_is_spnego_supported()) {
        *availp |= CURLAUTH_NEGOTIATE;
        authp->avail |= CURLAUTH_NEGOTIATE;

        if(authp->picked == CURLAUTH_NEGOTIATE) {
          CURLcode result = Curl_input_negotiate(data, conn, proxy, auth);
          if(!result) {
            DEBUGASSERT(!data->req.newurl);
            data->req.newurl = strdup(data->state.url);
            if(!data->req.newurl)
              return CURLE_OUT_OF_MEMORY;
            data->state.authproblem = FALSE;
            
            *negstate = GSS_AUTHRECV;
          }
          else data->state.authproblem = TRUE;
        }
      }
    }
    else    if(checkprefix("NTLM", auth) && is_valid_auth_separator(auth[4])) {



        if((authp->avail & CURLAUTH_NTLM) || (authp->avail & CURLAUTH_NTLM_WB) || Curl_auth_is_ntlm_supported()) {

          *availp |= CURLAUTH_NTLM;
          authp->avail |= CURLAUTH_NTLM;

          if(authp->picked == CURLAUTH_NTLM || authp->picked == CURLAUTH_NTLM_WB) {
            
            CURLcode result = Curl_input_ntlm(data, proxy, auth);
            if(!result) {
              data->state.authproblem = FALSE;

              if(authp->picked == CURLAUTH_NTLM_WB) {
                *availp &= ~CURLAUTH_NTLM;
                authp->avail &= ~CURLAUTH_NTLM;
                *availp |= CURLAUTH_NTLM_WB;
                authp->avail |= CURLAUTH_NTLM_WB;

                result = Curl_input_ntlm_wb(data, conn, proxy, auth);
                if(result) {
                  infof(data, "Authentication problem. Ignoring this.");
                  data->state.authproblem = TRUE;
                }
              }

            }
            else {
              infof(data, "Authentication problem. Ignoring this.");
              data->state.authproblem = TRUE;
            }
          }
        }
      }
      else   if(checkprefix("Digest", auth) && is_valid_auth_separator(auth[6])) {


          if((authp->avail & CURLAUTH_DIGEST) != 0)
            infof(data, "Ignoring duplicate digest auth header.");
          else if(Curl_auth_is_digest_supported()) {
            CURLcode result;

            *availp |= CURLAUTH_DIGEST;
            authp->avail |= CURLAUTH_DIGEST;

            
            result = Curl_input_digest(data, proxy, auth);
            if(result) {
              infof(data, "Authentication problem. Ignoring this.");
              data->state.authproblem = TRUE;
            }
          }
        }
        else  if(checkprefix("Basic", auth) && is_valid_auth_separator(auth[5])) {


            *availp |= CURLAUTH_BASIC;
            authp->avail |= CURLAUTH_BASIC;
            if(authp->picked == CURLAUTH_BASIC) {
              
              authp->avail = CURLAUTH_NONE;
              infof(data, "Authentication problem. Ignoring this.");
              data->state.authproblem = TRUE;
            }
          }
          else if(checkprefix("Bearer", auth) && is_valid_auth_separator(auth[6])) {

              *availp |= CURLAUTH_BEARER;
              authp->avail |= CURLAUTH_BEARER;
              if(authp->picked == CURLAUTH_BEARER) {
                
                authp->avail = CURLAUTH_NONE;
                infof(data, "Authentication problem. Ignoring this.");
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


static bool http_should_fail(struct Curl_easy *data)
{
  int httpcode;
  DEBUGASSERT(data);
  DEBUGASSERT(data->conn);

  httpcode = data->req.httpcode;

  
  if(!data->set.http_fail_on_error)
    return FALSE;

  
  if(httpcode < 400)
    return FALSE;

  
  if(data->state.resume_from && data->state.httpreq == HTTPREQ_GET && httpcode == 416)
    return FALSE;

  
  if((httpcode != 401) && (httpcode != 407))
    return TRUE;

  
  DEBUGASSERT((httpcode == 401) || (httpcode == 407));

  

  
  if((httpcode == 401) && !data->state.aptr.user)
    return TRUE;

  if((httpcode == 407) && !data->conn->bits.proxy_user_passwd)
    return TRUE;


  return data->state.authproblem;
}


static size_t readmoredata(char *buffer, size_t size, size_t nitems, void *userp)


{
  struct Curl_easy *data = (struct Curl_easy *)userp;
  struct HTTP *http = data->req.p.http;
  size_t fullsize = size * nitems;

  if(!http->postsize)
    
    return 0;

  
  data->req.forbidchunk = (http->sending == HTTPSEND_REQUEST)?TRUE:FALSE;

  if(data->set.max_send_speed && (data->set.max_send_speed < (curl_off_t)fullsize) && (data->set.max_send_speed < http->postsize))

    
    fullsize = (size_t)data->set.max_send_speed;

  else if(http->postsize <= (curl_off_t)fullsize) {
    memcpy(buffer, http->postdata, (size_t)http->postsize);
    fullsize = (size_t)http->postsize;

    if(http->backup.postsize) {
      
      http->postdata = http->backup.postdata;
      http->postsize = http->backup.postsize;
      data->state.fread_func = http->backup.fread_func;
      data->state.in = http->backup.fread_in;

      http->sending++; 

      http->backup.postsize = 0;
    }
    else http->postsize = 0;

    return fullsize;
  }

  memcpy(buffer, http->postdata, fullsize);
  http->postdata += fullsize;
  http->postsize -= fullsize;

  return fullsize;
}


CURLcode Curl_buffer_send(struct dynbuf *in, struct Curl_easy *data,  curl_off_t *bytes_written,  curl_off_t included_body_bytes, int socketindex)





{
  ssize_t amount;
  CURLcode result;
  char *ptr;
  size_t size;
  struct connectdata *conn = data->conn;
  struct HTTP *http = data->req.p.http;
  size_t sendsize;
  curl_socket_t sockfd;
  size_t headersize;

  DEBUGASSERT(socketindex <= SECONDARYSOCKET);

  sockfd = conn->sock[socketindex];

  

  ptr = Curl_dyn_ptr(in);
  size = Curl_dyn_len(in);

  headersize = size - (size_t)included_body_bytes; 

  DEBUGASSERT(size > (size_t)included_body_bytes);

  if((conn->handler->flags & PROTOPT_SSL  || conn->http_proxy.proxytype == CURLPROXY_HTTPS  )



     && conn->httpversion != 20) {
    
    if(data->set.max_send_speed && (included_body_bytes > data->set.max_send_speed)) {
      curl_off_t overflow = included_body_bytes - data->set.max_send_speed;
      DEBUGASSERT((size_t)overflow < size);
      sendsize = size - (size_t)overflow;
    }
    else sendsize = size;

    
    result = Curl_get_upload_buffer(data);
    if(result) {
      
      Curl_dyn_free(in);
      return result;
    }
    
    if(sendsize > (size_t)data->set.upload_buffer_size)
      sendsize = (size_t)data->set.upload_buffer_size;

    memcpy(data->state.ulbuf, ptr, sendsize);
    ptr = data->state.ulbuf;
  }
  else {

    
    char *p = getenv("CURL_SMALLREQSEND");
    if(p) {
      size_t altsize = (size_t)strtoul(p, NULL, 10);
      if(altsize)
        sendsize = CURLMIN(size, altsize);
      else sendsize = size;
    }
    else  {

      
      if(data->set.max_send_speed && (included_body_bytes > data->set.max_send_speed)) {
        curl_off_t overflow = included_body_bytes - data->set.max_send_speed;
        DEBUGASSERT((size_t)overflow < size);
        sendsize = size - (size_t)overflow;
      }
      else sendsize = size;
    }
  }

  result = Curl_write(data, sockfd, ptr, sendsize, &amount);

  if(!result) {
    
    
    size_t headlen = (size_t)amount>headersize ? headersize : (size_t)amount;
    size_t bodylen = amount - headlen;

    
    Curl_debug(data, CURLINFO_HEADER_OUT, ptr, headlen);
    if(bodylen)
      
      Curl_debug(data, CURLINFO_DATA_OUT, ptr + headlen, bodylen);

    
    *bytes_written += (long)amount;

    if(http) {
      
      data->req.writebytecount += bodylen;
      Curl_pgrsSetUploadCounter(data, data->req.writebytecount);

      if((size_t)amount != size) {
        

        size -= amount;

        ptr = Curl_dyn_ptr(in) + amount;

        
        http->backup.fread_func = data->state.fread_func;
        http->backup.fread_in = data->state.in;
        http->backup.postdata = http->postdata;
        http->backup.postsize = http->postsize;

        
        data->state.fread_func = (curl_read_callback)readmoredata;
        data->state.in = (void *)data;
        http->postdata = ptr;
        http->postsize = (curl_off_t)size;

        
        data->req.pendingheader = headersize - headlen;

        http->send_buffer = *in; 
        http->sending = HTTPSEND_REQUEST;

        return CURLE_OK;
      }
      http->sending = HTTPSEND_BODY;
      
    }
    else {
      if((size_t)amount != size)
        
        return CURLE_SEND_ERROR;
    }
  }
  Curl_dyn_free(in);

  
  data->req.pendingheader = 0;
  return result;
}







bool Curl_compareheader(const char *headerline, const char *header, const size_t hlen, const char *content, const size_t clen)




{
  

  size_t len;
  const char *start;
  const char *end;
  DEBUGASSERT(hlen);
  DEBUGASSERT(clen);
  DEBUGASSERT(header);
  DEBUGASSERT(content);

  if(!strncasecompare(headerline, header, hlen))
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

  
  for(; len >= clen; len--, start++) {
    if(strncasecompare(start, content, clen))
      return TRUE; 
  }

  return FALSE; 
}


CURLcode Curl_http_connect(struct Curl_easy *data, bool *done)
{
  CURLcode result;
  struct connectdata *conn = data->conn;

  
  connkeep(conn, "HTTP default");


  
  result = Curl_proxy_connect(data, FIRSTSOCKET);
  if(result)
    return result;

  if(conn->bits.proxy_connect_closed)
    
    return CURLE_OK;

  if(CONNECT_FIRSTSOCKET_PROXY_SSL())
    return CURLE_OK; 

  if(Curl_connect_ongoing(conn))
    
    return CURLE_OK;

  if(data->set.haproxyprotocol) {
    
    result = add_haproxy_protocol_header(data);
    if(result)
      return result;
  }


  if(conn->given->protocol & CURLPROTO_HTTPS) {
    
    result = https_connecting(data, done);
    if(result)
      return result;
  }
  else *done = TRUE;

  return CURLE_OK;
}


static int http_getsock_do(struct Curl_easy *data, struct connectdata *conn, curl_socket_t *socks)

{
  
  (void)data;
  socks[0] = conn->sock[FIRSTSOCKET];
  return GETSOCK_WRITESOCK(0);
}


static CURLcode add_haproxy_protocol_header(struct Curl_easy *data)
{
  struct dynbuf req;
  CURLcode result;
  const char *tcp_version;
  DEBUGASSERT(data->conn);
  Curl_dyn_init(&req, DYN_HAXPROXY);


  if(data->conn->unix_domain_socket)
    
    result = Curl_dyn_addn(&req, STRCONST("PROXY UNKNOWN\r\n"));
  else {

  
  tcp_version = data->conn->bits.ipv6 ? "TCP6" : "TCP4";

  result = Curl_dyn_addf(&req, "PROXY %s %s %s %i %i\r\n", tcp_version, data->info.conn_local_ip, data->info.conn_primary_ip, data->info.conn_local_port, data->info.conn_primary_port);






  }


  if(!result)
    result = Curl_buffer_send(&req, data, &data->info.request_size, 0, FIRSTSOCKET);
  return result;
}



static CURLcode https_connecting(struct Curl_easy *data, bool *done)
{
  CURLcode result;
  struct connectdata *conn = data->conn;
  DEBUGASSERT((data) && (data->conn->handler->flags & PROTOPT_SSL));


  if(conn->transport == TRNSPRT_QUIC) {
    *done = TRUE;
    return CURLE_OK;
  }


  
  result = Curl_ssl_connect_nonblocking(data, conn, FALSE, FIRSTSOCKET, done);
  if(result)
    connclose(conn, "Failed HTTPS connection");

  return result;
}

static int https_getsock(struct Curl_easy *data, struct connectdata *conn, curl_socket_t *socks)

{
  (void)data;
  if(conn->handler->flags & PROTOPT_SSL)
    return Curl_ssl->getsock(conn, socks);
  return GETSOCK_BLANK;
}




CURLcode Curl_http_done(struct Curl_easy *data, CURLcode status, bool premature)
{
  struct connectdata *conn = data->conn;
  struct HTTP *http = data->req.p.http;

  
  data->state.authhost.multipass = FALSE;
  data->state.authproxy.multipass = FALSE;

  Curl_unencode_cleanup(data);

  
  conn->seek_func = data->set.seek_func; 
  conn->seek_client = data->set.seek_client; 

  if(!http)
    return CURLE_OK;

  Curl_dyn_free(&http->send_buffer);
  Curl_http2_done(data, premature);
  Curl_quic_done(data, premature);
  Curl_mime_cleanpart(&http->form);
  Curl_dyn_reset(&data->state.headerb);
  Curl_hyper_done(data);

  if(status)
    return status;

  if(!premature &&  !conn->bits.retry && !data->set.connect_only && (data->req.bytecount + data->req.headerbytecount - data->req.deductheadercount) <= 0) {




    
    failf(data, "Empty reply from server");
    
    streamclose(conn, "Empty reply from server");
    return CURLE_GOT_NOTHING;
  }

  return CURLE_OK;
}


bool Curl_use_http_1_1plus(const struct Curl_easy *data, const struct connectdata *conn)
{
  if((data->state.httpversion == 10) || (conn->httpversion == 10))
    return FALSE;
  if((data->state.httpwant == CURL_HTTP_VERSION_1_0) && (conn->httpversion <= 10))
    return FALSE;
  return ((data->state.httpwant == CURL_HTTP_VERSION_NONE) || (data->state.httpwant >= CURL_HTTP_VERSION_1_1));
}


static const char *get_http_string(const struct Curl_easy *data, const struct connectdata *conn)
{

  if((data->state.httpwant == CURL_HTTP_VERSION_3) || (conn->httpversion == 30))
    return "3";



  if(conn->proto.httpc.h2)
    return "2";


  if(Curl_use_http_1_1plus(data, conn))
    return "1.1";

  return "1.0";
}



static CURLcode expect100(struct Curl_easy *data, struct connectdata *conn, struct dynbuf *req)

{
  CURLcode result = CURLE_OK;
  data->state.expect100header = FALSE; 
  if(!data->state.disableexpect && Curl_use_http_1_1plus(data, conn) && (conn->httpversion < 20)) {
    
    const char *ptr = Curl_checkheaders(data, STRCONST("Expect"));
    if(ptr) {
      data->state.expect100header = Curl_compareheader(ptr, STRCONST("Expect:"), STRCONST("100-continue"));
    }
    else {
      result = Curl_dyn_addn(req, STRCONST("Expect: 100-continue\r\n"));
      if(!result)
        data->state.expect100header = TRUE;
    }
  }

  return result;
}

enum proxy_use {
  HEADER_SERVER,   HEADER_PROXY, HEADER_CONNECT };




CURLcode Curl_http_compile_trailers(struct curl_slist *trailers, struct dynbuf *b, struct Curl_easy *handle)

{
  char *ptr = NULL;
  CURLcode result = CURLE_OK;
  const char *endofline_native = NULL;
  const char *endofline_network = NULL;

  if(  (handle->state.prefer_ascii) ||  (handle->set.crlf)) {



    
    endofline_native  = "\n";
    endofline_network = "\x0a";
  }
  else {
    endofline_native  = "\r\n";
    endofline_network = "\x0d\x0a";
  }

  while(trailers) {
    
    ptr = strchr(trailers->data, ':');
    if(ptr && *(ptr + 1) == ' ') {
      result = Curl_dyn_add(b, trailers->data);
      if(result)
        return result;
      result = Curl_dyn_add(b, endofline_native);
      if(result)
        return result;
    }
    else infof(handle, "Malformatted trailing header, skipping trailer");
    trailers = trailers->next;
  }
  result = Curl_dyn_add(b, endofline_network);
  return result;
}

CURLcode Curl_add_custom_headers(struct Curl_easy *data, bool is_connect,  struct dynbuf *req  void *req  )






{
  struct connectdata *conn = data->conn;
  char *ptr;
  struct curl_slist *h[2];
  struct curl_slist *headers;
  int numlists = 1; 
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

  (void)is_connect;
  h[0] = data->set.headers;


  
  for(i = 0; i < numlists; i++) {
    headers = h[i];

    while(headers) {
      char *semicolonp = NULL;
      ptr = strchr(headers->data, ':');
      if(!ptr) {
        char *optr;
        
        ptr = strchr(headers->data, ';');
        if(ptr) {
          optr = ptr;
          ptr++; 
          while(*ptr && ISSPACE(*ptr))
            ptr++;

          if(*ptr) {
            
            optr = NULL;
          }
          else {
            if(*(--ptr) == ';') {
              
              semicolonp = strdup(headers->data);
              if(!semicolonp) {

                Curl_dyn_free(req);

                return CURLE_OUT_OF_MEMORY;
              }
              
              semicolonp[ptr - headers->data] = ':';
              
              optr = &semicolonp [ptr - headers->data];
            }
          }
          ptr = optr;
        }
      }
      if(ptr && (ptr != headers->data)) {
        

        ptr++; 
        while(*ptr && ISSPACE(*ptr))
          ptr++;

        if(*ptr || semicolonp) {
          
          CURLcode result = CURLE_OK;
          char *compare = semicolonp ? semicolonp : headers->data;

          if(data->state.aptr.host &&  checkprefix("Host:", compare))

            ;
          else if(data->state.httpreq == HTTPREQ_POST_FORM &&  checkprefix("Content-Type:", compare))

            ;
          else if(data->state.httpreq == HTTPREQ_POST_MIME &&  checkprefix("Content-Type:", compare))

            ;
          else if(conn->bits.authneg &&  checkprefix("Content-Length:", compare))

            ;
          else if(data->state.aptr.te &&  checkprefix("Connection:", compare))

            ;
          else if((conn->httpversion >= 20) && checkprefix("Transfer-Encoding:", compare))
            
            ;
          else if((checkprefix("Authorization:", compare) || checkprefix("Cookie:", compare)) &&  (data->state.this_is_a_follow && data->state.first_host && !data->set.allow_auth_to_other_hosts && !strcasecompare(data->state.first_host, conn->host.name)))





            ;
          else {

            result = Curl_hyper_header(data, req, compare);

            result = Curl_dyn_addf(req, "%s\r\n", compare);

          }
          if(semicolonp)
            free(semicolonp);
          if(result)
            return result;
        }
      }
      headers = headers->next;
    }
  }

  return CURLE_OK;
}


CURLcode Curl_add_timecondition(struct Curl_easy *data,  struct dynbuf *req  void *req  )





{
  const struct tm *tm;
  struct tm keeptime;
  CURLcode result;
  char datestr[80];
  const char *condp;
  size_t len;

  if(data->set.timecondition == CURL_TIMECOND_NONE)
    
    return CURLE_OK;

  result = Curl_gmtime(data->set.timevalue, &keeptime);
  if(result) {
    failf(data, "Invalid TIMEVALUE");
    return result;
  }
  tm = &keeptime;

  switch(data->set.timecondition) {
  default:
    return CURLE_BAD_FUNCTION_ARGUMENT;

  case CURL_TIMECOND_IFMODSINCE:
    condp = "If-Modified-Since";
    len = 17;
    break;
  case CURL_TIMECOND_IFUNMODSINCE:
    condp = "If-Unmodified-Since";
    len = 19;
    break;
  case CURL_TIMECOND_LASTMOD:
    condp = "Last-Modified";
    len = 13;
    break;
  }

  if(Curl_checkheaders(data, condp, len)) {
    
    return CURLE_OK;
  }

  

  
  msnprintf(datestr, sizeof(datestr), "%s: %s, %02d %s %4d %02d:%02d:%02d GMT\r\n", condp, Curl_wkday[tm->tm_wday?tm->tm_wday-1:6], tm->tm_mday, Curl_month[tm->tm_mon], tm->tm_year + 1900, tm->tm_hour, tm->tm_min, tm->tm_sec);










  result = Curl_dyn_add(req, datestr);

  result = Curl_hyper_header(data, req, datestr);


  return result;
}


CURLcode Curl_add_timecondition(struct Curl_easy *data, struct dynbuf *req)
{
  (void)data;
  (void)req;
  return CURLE_OK;
}


void Curl_http_method(struct Curl_easy *data, struct connectdata *conn, const char **method, Curl_HttpReq *reqp)
{
  Curl_HttpReq httpreq = data->state.httpreq;
  const char *request;
  if((conn->handler->protocol&(PROTO_FAMILY_HTTP|CURLPROTO_FTP)) && data->set.upload)
    httpreq = HTTPREQ_PUT;

  
  if(data->set.str[STRING_CUSTOMREQUEST])
    request = data->set.str[STRING_CUSTOMREQUEST];
  else {
    if(data->set.opt_no_body)
      request = "HEAD";
    else {
      DEBUGASSERT((httpreq >= HTTPREQ_GET) && (httpreq <= HTTPREQ_HEAD));
      switch(httpreq) {
      case HTTPREQ_POST:
      case HTTPREQ_POST_FORM:
      case HTTPREQ_POST_MIME:
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
  *method = request;
  *reqp = httpreq;
}

CURLcode Curl_http_useragent(struct Curl_easy *data)
{
  
  if(Curl_checkheaders(data, STRCONST("User-Agent"))) {
    free(data->state.aptr.uagent);
    data->state.aptr.uagent = NULL;
  }
  return CURLE_OK;
}


CURLcode Curl_http_host(struct Curl_easy *data, struct connectdata *conn)
{
  const char *ptr;
  if(!data->state.this_is_a_follow) {
    
    free(data->state.first_host);

    data->state.first_host = strdup(conn->host.name);
    if(!data->state.first_host)
      return CURLE_OUT_OF_MEMORY;

    data->state.first_remote_port = conn->remote_port;
  }
  Curl_safefree(data->state.aptr.host);

  ptr = Curl_checkheaders(data, STRCONST("Host"));
  if(ptr && (!data->state.this_is_a_follow || strcasecompare(data->state.first_host, conn->host.name))) {

    
    char *cookiehost = Curl_copy_header_value(ptr);
    if(!cookiehost)
      return CURLE_OUT_OF_MEMORY;
    if(!*cookiehost)
      
      free(cookiehost);
    else {
      
      if(*cookiehost == '[') {
        char *closingbracket;
        
        memmove(cookiehost, cookiehost + 1, strlen(cookiehost) - 1);
        closingbracket = strchr(cookiehost, ']');
        if(closingbracket)
          *closingbracket = 0;
      }
      else {
        int startsearch = 0;
        char *colon = strchr(cookiehost + startsearch, ':');
        if(colon)
          *colon = 0; 
      }
      Curl_safefree(data->state.aptr.cookiehost);
      data->state.aptr.cookiehost = cookiehost;
    }


    if(strcmp("Host:", ptr)) {
      data->state.aptr.host = aprintf("Host:%s\r\n", &ptr[5]);
      if(!data->state.aptr.host)
        return CURLE_OUT_OF_MEMORY;
    }
    else  data->state.aptr.host = NULL;

  }
  else {
    
    const char *host = conn->host.name;

    if(((conn->given->protocol&CURLPROTO_HTTPS) && (conn->remote_port == PORT_HTTPS)) || ((conn->given->protocol&CURLPROTO_HTTP) && (conn->remote_port == PORT_HTTP)) )


      
      data->state.aptr.host = aprintf("Host: %s%s%s\r\n", conn->bits.ipv6_ip?"[":"", host, conn->bits.ipv6_ip?"]":"");


    else data->state.aptr.host = aprintf("Host: %s%s%s:%d\r\n", conn->bits.ipv6_ip?"[":"", host, conn->bits.ipv6_ip?"]":"", conn->remote_port);





    if(!data->state.aptr.host)
      
      return CURLE_OUT_OF_MEMORY;
  }
  return CURLE_OK;
}


CURLcode Curl_http_target(struct Curl_easy *data, struct connectdata *conn, struct dynbuf *r)

{
  CURLcode result = CURLE_OK;
  const char *path = data->state.up.path;
  const char *query = data->state.up.query;

  if(data->set.str[STRING_TARGET]) {
    path = data->set.str[STRING_TARGET];
    query = NULL;
  }


  if(conn->bits.httpproxy && !conn->bits.tunnel_proxy) {
    

    

    
    CURLUcode uc;
    char *url;
    CURLU *h = curl_url_dup(data->state.uh);
    if(!h)
      return CURLE_OUT_OF_MEMORY;

    if(conn->host.dispname != conn->host.name) {
      uc = curl_url_set(h, CURLUPART_HOST, conn->host.name, 0);
      if(uc) {
        curl_url_cleanup(h);
        return CURLE_OUT_OF_MEMORY;
      }
    }
    uc = curl_url_set(h, CURLUPART_FRAGMENT, NULL, 0);
    if(uc) {
      curl_url_cleanup(h);
      return CURLE_OUT_OF_MEMORY;
    }

    if(strcasecompare("http", data->state.up.scheme)) {
      
      uc = curl_url_set(h, CURLUPART_USER, NULL, 0);
      if(uc) {
        curl_url_cleanup(h);
        return CURLE_OUT_OF_MEMORY;
      }
      uc = curl_url_set(h, CURLUPART_PASSWORD, NULL, 0);
      if(uc) {
        curl_url_cleanup(h);
        return CURLE_OUT_OF_MEMORY;
      }
    }
    
    uc = curl_url_get(h, CURLUPART_URL, &url, CURLU_NO_DEFAULT_PORT);
    if(uc) {
      curl_url_cleanup(h);
      return CURLE_OUT_OF_MEMORY;
    }

    curl_url_cleanup(h);

    
    result = Curl_dyn_add(r, data->set.str[STRING_TARGET]? data->set.str[STRING_TARGET]:url);
    free(url);
    if(result)
      return (result);

    if(strcasecompare("ftp", data->state.up.scheme)) {
      if(data->set.proxy_transfer_mode) {
        
        char *type = strstr(path, ";type=");
        if(type && type[6] && type[7] == 0) {
          switch(Curl_raw_toupper(type[6])) {
          case 'A':
          case 'D':
          case 'I':
            break;
          default:
            type = NULL;
          }
        }
        if(!type) {
          result = Curl_dyn_addf(r, ";type=%c", data->state.prefer_ascii ? 'a' : 'i');
          if(result)
            return result;
        }
      }
    }
  }

  else  (void)conn;


  {
    result = Curl_dyn_add(r, path);
    if(result)
      return result;
    if(query)
      result = Curl_dyn_addf(r, "?%s", query);
  }

  return result;
}

CURLcode Curl_http_body(struct Curl_easy *data, struct connectdata *conn, Curl_HttpReq httpreq, const char **tep)
{
  CURLcode result = CURLE_OK;
  const char *ptr;
  struct HTTP *http = data->req.p.http;
  http->postsize = 0;

  switch(httpreq) {
  case HTTPREQ_POST_MIME:
    http->sendit = &data->set.mimepost;
    break;
  case HTTPREQ_POST_FORM:
    
    Curl_mime_cleanpart(&http->form);
    result = Curl_getformdata(data, &http->form, data->set.httppost, data->state.fread_func);
    if(result)
      return result;
    http->sendit = &http->form;
    break;
  default:
    http->sendit = NULL;
  }


  if(http->sendit) {
    const char *cthdr = Curl_checkheaders(data, STRCONST("Content-Type"));

    
    http->sendit->flags |= MIME_BODY_ONLY;

    

    if(cthdr)
      for(cthdr += 13; *cthdr == ' '; cthdr++)
        ;
    else if(http->sendit->kind == MIMEKIND_MULTIPART)
      cthdr = "multipart/form-data";

    curl_mime_headers(http->sendit, data->set.headers, 0);
    result = Curl_mime_prepare_headers(http->sendit, cthdr, NULL, MIMESTRATEGY_FORM);
    curl_mime_headers(http->sendit, NULL, 0);
    if(!result)
      result = Curl_mime_rewind(http->sendit);
    if(result)
      return result;
    http->postsize = Curl_mime_size(http->sendit);
  }


  ptr = Curl_checkheaders(data, STRCONST("Transfer-Encoding"));
  if(ptr) {
    
    data->req.upload_chunky = Curl_compareheader(ptr, STRCONST("Transfer-Encoding:"), STRCONST("chunked"));

  }
  else {
    if((conn->handler->protocol & PROTO_FAMILY_HTTP) && (((httpreq == HTTPREQ_POST_MIME || httpreq == HTTPREQ_POST_FORM) && http->postsize < 0) || ((data->set.upload || httpreq == HTTPREQ_POST) && data->state.infilesize == -1))) {



      if(conn->bits.authneg)
        
        ;
      else if(Curl_use_http_1_1plus(data, conn)) {
        if(conn->httpversion < 20)
          
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
      *tep = "Transfer-Encoding: chunked\r\n";
  }
  return result;
}

CURLcode Curl_http_bodysend(struct Curl_easy *data, struct connectdata *conn, struct dynbuf *r, Curl_HttpReq httpreq)
{

  
  curl_off_t included_body = 0;

  


  CURLcode result = CURLE_OK;
  struct HTTP *http = data->req.p.http;
  const char *ptr;

  

  switch(httpreq) {

  case HTTPREQ_PUT: 

    if(conn->bits.authneg)
      http->postsize = 0;
    else http->postsize = data->state.infilesize;

    if((http->postsize != -1) && !data->req.upload_chunky && (conn->bits.authneg || !Curl_checkheaders(data, STRCONST("Content-Length")))) {

      
      result = Curl_dyn_addf(r, "Content-Length: %" CURL_FORMAT_CURL_OFF_T "\r\n", http->postsize);
      if(result)
        return result;
    }

    if(http->postsize) {
      result = expect100(data, conn, r);
      if(result)
        return result;
    }

    
    result = Curl_dyn_addn(r, STRCONST("\r\n"));
    if(result)
      return result;

    
    Curl_pgrsSetUploadSize(data, http->postsize);

    
    result = Curl_buffer_send(r, data, &data->info.request_size, 0, FIRSTSOCKET);
    if(result)
      failf(data, "Failed sending PUT request");
    else  Curl_setup_transfer(data, FIRSTSOCKET, -1, TRUE, http->postsize?FIRSTSOCKET:-1);


    if(result)
      return result;
    break;

  case HTTPREQ_POST_FORM:
  case HTTPREQ_POST_MIME:
    
    if(conn->bits.authneg) {
      
      result = Curl_dyn_addn(r, STRCONST("Content-Length: 0\r\n\r\n"));
      if(result)
        return result;

      result = Curl_buffer_send(r, data, &data->info.request_size, 0, FIRSTSOCKET);
      if(result)
        failf(data, "Failed sending POST request");
      else  Curl_setup_transfer(data, FIRSTSOCKET, -1, TRUE, -1);

      break;
    }

    data->state.infilesize = http->postsize;

    
    if(http->postsize != -1 && !data->req.upload_chunky && (conn->bits.authneg || !Curl_checkheaders(data, STRCONST("Content-Length")))) {

      
      result = Curl_dyn_addf(r, "Content-Length: %" CURL_FORMAT_CURL_OFF_T "\r\n", http->postsize);

      if(result)
        return result;
    }


    
    {
      struct curl_slist *hdr;

      for(hdr = http->sendit->curlheaders; hdr; hdr = hdr->next) {
        result = Curl_dyn_addf(r, "%s\r\n", hdr->data);
        if(result)
          return result;
      }
    }


    
    ptr = Curl_checkheaders(data, STRCONST("Expect"));
    if(ptr) {
      data->state.expect100header = Curl_compareheader(ptr, STRCONST("Expect:"), STRCONST("100-continue"));
    }
    else if(http->postsize > EXPECT_100_THRESHOLD || http->postsize < 0) {
      result = expect100(data, conn, r);
      if(result)
        return result;
    }
    else data->state.expect100header = FALSE;

    
    result = Curl_dyn_addn(r, STRCONST("\r\n"));
    if(result)
      return result;

    
    Curl_pgrsSetUploadSize(data, http->postsize);

    
    data->state.fread_func = (curl_read_callback) Curl_mime_read;
    data->state.in = (void *) http->sendit;
    http->sending = HTTPSEND_BODY;

    
    result = Curl_buffer_send(r, data, &data->info.request_size, 0, FIRSTSOCKET);
    if(result)
      failf(data, "Failed sending POST request");
    else  Curl_setup_transfer(data, FIRSTSOCKET, -1, TRUE, http->postsize?FIRSTSOCKET:-1);


    if(result)
      return result;

    break;

  case HTTPREQ_POST:
    

    if(conn->bits.authneg)
      http->postsize = 0;
    else  http->postsize = data->state.infilesize;


    
    if((http->postsize != -1) && !data->req.upload_chunky && (conn->bits.authneg || !Curl_checkheaders(data, STRCONST("Content-Length")))) {

      
      result = Curl_dyn_addf(r, "Content-Length: %" CURL_FORMAT_CURL_OFF_T "\r\n", http->postsize);
      if(result)
        return result;
    }

    if(!Curl_checkheaders(data, STRCONST("Content-Type"))) {
      result = Curl_dyn_addn(r, STRCONST("Content-Type: application/" "x-www-form-urlencoded\r\n"));
      if(result)
        return result;
    }

    
    ptr = Curl_checkheaders(data, STRCONST("Expect"));
    if(ptr) {
      data->state.expect100header = Curl_compareheader(ptr, STRCONST("Expect:"), STRCONST("100-continue"));
    }
    else if(http->postsize > EXPECT_100_THRESHOLD || http->postsize < 0) {
      result = expect100(data, conn, r);
      if(result)
        return result;
    }
    else data->state.expect100header = FALSE;


    
    if(data->set.postfields) {

      
      if(conn->httpversion != 20 && !data->state.expect100header && (http->postsize < MAX_INITIAL_POST_SIZE)) {

        

        
        result = Curl_dyn_addn(r, STRCONST("\r\n"));
        if(result)
          return result;

        if(!data->req.upload_chunky) {
          
          result = Curl_dyn_addn(r, data->set.postfields, (size_t)http->postsize);
          included_body = http->postsize;
        }
        else {
          if(http->postsize) {
            char chunk[16];
            
            msnprintf(chunk, sizeof(chunk), "%x\r\n", (int)http->postsize);
            result = Curl_dyn_add(r, chunk);
            if(!result) {
              included_body = http->postsize + strlen(chunk);
              result = Curl_dyn_addn(r, data->set.postfields, (size_t)http->postsize);
              if(!result)
                result = Curl_dyn_addn(r, STRCONST("\r\n"));
              included_body += 2;
            }
          }
          if(!result) {
            result = Curl_dyn_addn(r, STRCONST("\x30\x0d\x0a\x0d\x0a"));
            
            included_body += 5;
          }
        }
        if(result)
          return result;
        
        Curl_pgrsSetUploadSize(data, http->postsize);
      }
      else {
        
        http->postdata = data->set.postfields;

        http->sending = HTTPSEND_BODY;

        data->state.fread_func = (curl_read_callback)readmoredata;
        data->state.in = (void *)data;

        
        Curl_pgrsSetUploadSize(data, http->postsize);

        
        result = Curl_dyn_addn(r, STRCONST("\r\n"));
        if(result)
          return result;
      }
    }
    else  {

       
      result = Curl_dyn_addn(r, STRCONST("\r\n"));
      if(result)
        return result;

      if(data->req.upload_chunky && conn->bits.authneg) {
        
        result = Curl_dyn_addn(r, (char *)STRCONST("\x30\x0d\x0a\x0d\x0a"));
        
        if(result)
          return result;
      }

      else if(data->state.infilesize) {
        
        Curl_pgrsSetUploadSize(data, http->postsize?http->postsize:-1);

        
        if(!conn->bits.authneg)
          http->postdata = (char *)&http->postdata;
      }
    }
    
    result = Curl_buffer_send(r, data, &data->info.request_size, included_body, FIRSTSOCKET);

    if(result)
      failf(data, "Failed sending HTTP POST request");
    else Curl_setup_transfer(data, FIRSTSOCKET, -1, TRUE, http->postdata?FIRSTSOCKET:-1);

    break;

  default:
    result = Curl_dyn_addn(r, STRCONST("\r\n"));
    if(result)
      return result;

    
    result = Curl_buffer_send(r, data, &data->info.request_size, 0, FIRSTSOCKET);
    if(result)
      failf(data, "Failed sending HTTP request");
    else  Curl_setup_transfer(data, FIRSTSOCKET, -1, TRUE, -1);

  }

  return result;
}


CURLcode Curl_http_cookies(struct Curl_easy *data, struct connectdata *conn, struct dynbuf *r)

{
  CURLcode result = CURLE_OK;
  char *addcookies = NULL;
  if(data->set.str[STRING_COOKIE] && !Curl_checkheaders(data, STRCONST("Cookie")))
    addcookies = data->set.str[STRING_COOKIE];

  if(data->cookies || addcookies) {
    struct Cookie *co = NULL; 
    int count = 0;

    if(data->cookies && data->state.cookie_engine) {
      const char *host = data->state.aptr.cookiehost ? data->state.aptr.cookiehost : conn->host.name;
      const bool secure_context = conn->handler->protocol&CURLPROTO_HTTPS || strcasecompare("localhost", host) || !strcmp(host, "127.0.0.1") || !strcmp(host, "[::1]") ? TRUE : FALSE;



      Curl_share_lock(data, CURL_LOCK_DATA_COOKIE, CURL_LOCK_ACCESS_SINGLE);
      co = Curl_cookie_getlist(data->cookies, host, data->state.up.path, secure_context);
      Curl_share_unlock(data, CURL_LOCK_DATA_COOKIE);
    }
    if(co) {
      struct Cookie *store = co;
      
      while(co) {
        if(co->value) {
          if(0 == count) {
            result = Curl_dyn_addn(r, STRCONST("Cookie: "));
            if(result)
              break;
          }
          result = Curl_dyn_addf(r, "%s%s=%s", count?"; ":"", co->name, co->value);
          if(result)
            break;
          count++;
        }
        co = co->next; 
      }
      Curl_cookie_freelist(store);
    }
    if(addcookies && !result) {
      if(!count)
        result = Curl_dyn_addn(r, STRCONST("Cookie: "));
      if(!result) {
        result = Curl_dyn_addf(r, "%s%s", count?"; ":"", addcookies);
        count++;
      }
    }
    if(count && !result)
      result = Curl_dyn_addn(r, STRCONST("\r\n"));

    if(result)
      return result;
  }
  return result;
}


CURLcode Curl_http_range(struct Curl_easy *data, Curl_HttpReq httpreq)
{
  if(data->state.use_range) {
    
    if(((httpreq == HTTPREQ_GET) || (httpreq == HTTPREQ_HEAD)) && !Curl_checkheaders(data, STRCONST("Range"))) {
      
      free(data->state.aptr.rangeline);
      data->state.aptr.rangeline = aprintf("Range: bytes=%s\r\n", data->state.range);
    }
    else if((httpreq == HTTPREQ_POST || httpreq == HTTPREQ_PUT) && !Curl_checkheaders(data, STRCONST("Content-Range"))) {

      
      free(data->state.aptr.rangeline);

      if(data->set.set_resume_from < 0) {
        
        data->state.aptr.rangeline = aprintf("Content-Range: bytes 0-%" CURL_FORMAT_CURL_OFF_T "/%" CURL_FORMAT_CURL_OFF_T "\r\n", data->state.infilesize - 1, data->state.infilesize);



      }
      else if(data->state.resume_from) {
        
        curl_off_t total_expected_size = data->state.resume_from + data->state.infilesize;
        data->state.aptr.rangeline = aprintf("Content-Range: bytes %s%" CURL_FORMAT_CURL_OFF_T "/%" CURL_FORMAT_CURL_OFF_T "\r\n", data->state.range, total_expected_size-1, total_expected_size);



      }
      else {
        
        data->state.aptr.rangeline = aprintf("Content-Range: bytes %s/%" CURL_FORMAT_CURL_OFF_T "\r\n", data->state.range, data->state.infilesize);

      }
      if(!data->state.aptr.rangeline)
        return CURLE_OUT_OF_MEMORY;
    }
  }
  return CURLE_OK;
}

CURLcode Curl_http_resume(struct Curl_easy *data, struct connectdata *conn, Curl_HttpReq httpreq)

{
  if((HTTPREQ_POST == httpreq || HTTPREQ_PUT == httpreq) && data->state.resume_from) {
    

    if(data->state.resume_from < 0) {
      
      data->state.resume_from = 0;
    }

    if(data->state.resume_from && !data->state.this_is_a_follow) {
      

      
      int seekerr = CURL_SEEKFUNC_CANTSEEK;
      if(conn->seek_func) {
        Curl_set_in_callback(data, true);
        seekerr = conn->seek_func(conn->seek_client, data->state.resume_from, SEEK_SET);
        Curl_set_in_callback(data, false);
      }

      if(seekerr != CURL_SEEKFUNC_OK) {
        curl_off_t passed = 0;

        if(seekerr != CURL_SEEKFUNC_CANTSEEK) {
          failf(data, "Could not seek stream");
          return CURLE_READ_ERROR;
        }
        
        do {
          size_t readthisamountnow = (data->state.resume_from - passed > data->set.buffer_size) ? (size_t)data->set.buffer_size :

            curlx_sotouz(data->state.resume_from - passed);

          size_t actuallyread = data->state.fread_func(data->state.buffer, 1, readthisamountnow, data->state.in);


          passed += actuallyread;
          if((actuallyread == 0) || (actuallyread > readthisamountnow)) {
            
            failf(data, "Could only read %" CURL_FORMAT_CURL_OFF_T " bytes from the input", passed);
            return CURLE_READ_ERROR;
          }
        } while(passed < data->state.resume_from);
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
  return CURLE_OK;
}

CURLcode Curl_http_firstwrite(struct Curl_easy *data, struct connectdata *conn, bool *done)

{
  struct SingleRequest *k = &data->req;

  if(data->req.newurl) {
    if(conn->bits.close) {
      
      k->keepon &= ~KEEP_RECV;
      *done = TRUE;
      return CURLE_OK;
    }
    
    k->ignorebody = TRUE;
    infof(data, "Ignoring the response-body");
  }
  if(data->state.resume_from && !k->content_range && (data->state.httpreq == HTTPREQ_GET) && !k->ignorebody) {


    if(k->size == data->state.resume_from) {
      
      infof(data, "The entire document is already downloaded");
      streamclose(conn, "already downloaded");
      
      k->keepon &= ~KEEP_RECV;
      *done = TRUE;
      return CURLE_OK;
    }

    
    failf(data, "HTTP server doesn't seem to support " "byte ranges. Cannot resume.");
    return CURLE_RANGE_ERROR;
  }

  if(data->set.timecondition && !data->state.range) {
    

    if(!Curl_meets_timecondition(data, k->timeofdoc)) {
      *done = TRUE;
      
      data->info.httpcode = 304;
      infof(data, "Simulate a HTTP 304 response");
      
      streamclose(conn, "Simulated 304 handling");
      return CURLE_OK;
    }
  } 

  return CURLE_OK;
}


CURLcode Curl_transferencode(struct Curl_easy *data)
{
  if(!Curl_checkheaders(data, STRCONST("TE")) && data->set.http_transfer_encoding) {
    
    char *cptr = Curl_checkheaders(data, STRCONST("Connection"));


    Curl_safefree(data->state.aptr.te);

    if(cptr) {
      cptr = Curl_copy_header_value(cptr);
      if(!cptr)
        return CURLE_OUT_OF_MEMORY;
    }

    
    data->state.aptr.te = aprintf("Connection: %s%sTE\r\n" TE_HEADER, cptr ? cptr : "", (cptr && *cptr) ? ", ":"");

    free(cptr);
    if(!data->state.aptr.te)
      return CURLE_OUT_OF_MEMORY;
  }
  return CURLE_OK;
}




CURLcode Curl_http(struct Curl_easy *data, bool *done)
{
  struct connectdata *conn = data->conn;
  CURLcode result = CURLE_OK;
  struct HTTP *http;
  Curl_HttpReq httpreq;
  const char *te = ""; 
  const char *request;
  const char *httpstring;
  struct dynbuf req;
  char *altused = NULL;
  const char *p_accept;      

  
  *done = TRUE;

  if(conn->transport != TRNSPRT_QUIC) {
    if(conn->httpversion < 20) { 
      switch(conn->negnpn) {
      case CURL_HTTP_VERSION_2:
        conn->httpversion = 20; 

        result = Curl_http2_switched(data, NULL, 0);
        if(result)
          return result;
        break;
      case CURL_HTTP_VERSION_1_1:
        
        break;
      default:
        

        if(data->state.httpwant == CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE) {

          if(conn->bits.httpproxy && !conn->bits.tunnel_proxy) {
            
            infof(data, "Ignoring HTTP/2 prior knowledge due to proxy");
            break;
          }

          DEBUGF(infof(data, "HTTP/2 over clean TCP"));
          conn->httpversion = 20;

          result = Curl_http2_switched(data, NULL, 0);
          if(result)
            return result;
        }

        break;
      }
    }
    else {
      
      result = Curl_http2_setup(data, conn);
      if(result)
        return result;
    }
  }
  http = data->req.p.http;
  DEBUGASSERT(http);

  result = Curl_http_host(data, conn);
  if(result)
    return result;

  result = Curl_http_useragent(data);
  if(result)
    return result;

  Curl_http_method(data, conn, &request, &httpreq);

  
  {
    char *pq = NULL;
    if(data->state.up.query) {
      pq = aprintf("%s?%s", data->state.up.path, data->state.up.query);
      if(!pq)
        return CURLE_OUT_OF_MEMORY;
    }
    result = Curl_http_output_auth(data, conn, request, httpreq, (pq ? pq : data->state.up.path), FALSE);
    free(pq);
    if(result)
      return result;
  }

  Curl_safefree(data->state.aptr.ref);
  if(data->state.referer && !Curl_checkheaders(data, STRCONST("Referer"))) {
    data->state.aptr.ref = aprintf("Referer: %s\r\n", data->state.referer);
    if(!data->state.aptr.ref)
      return CURLE_OUT_OF_MEMORY;
  }

  if(!Curl_checkheaders(data, STRCONST("Accept-Encoding")) && data->set.str[STRING_ENCODING]) {
    Curl_safefree(data->state.aptr.accept_encoding);
    data->state.aptr.accept_encoding = aprintf("Accept-Encoding: %s\r\n", data->set.str[STRING_ENCODING]);
    if(!data->state.aptr.accept_encoding)
      return CURLE_OUT_OF_MEMORY;
  }
  else Curl_safefree(data->state.aptr.accept_encoding);


  
  result = Curl_transferencode(data);
  if(result)
    return result;


  result = Curl_http_body(data, conn, httpreq, &te);
  if(result)
    return result;

  p_accept = Curl_checkheaders(data, STRCONST("Accept"))?NULL:"Accept: */*\r\n";

  result = Curl_http_resume(data, conn, httpreq);
  if(result)
    return result;

  result = Curl_http_range(data, httpreq);
  if(result)
    return result;

  httpstring = get_http_string(data, conn);

  
  Curl_dyn_init(&req, DYN_HTTP_REQUEST);

  
  Curl_dyn_reset(&data->state.headerb);

  
  
  result = Curl_dyn_addf(&req, "%s ", request);
  if(!result)
    result = Curl_http_target(data, conn, &req);
  if(result) {
    Curl_dyn_free(&req);
    return result;
  }


  if(conn->bits.altused && !Curl_checkheaders(data, STRCONST("Alt-Used"))) {
    altused = aprintf("Alt-Used: %s:%d\r\n", conn->conn_to_host.name, conn->conn_to_port);
    if(!altused) {
      Curl_dyn_free(&req);
      return CURLE_OUT_OF_MEMORY;
    }
  }

  result = Curl_dyn_addf(&req, " HTTP/%s\r\n" "%s" "%s" "%s" "%s" "%s" "%s" "%s" "%s" "%s" "%s" "%s" "%s",  httpstring, (data->state.aptr.host?data->state.aptr.host:""), data->state.aptr.proxyuserpwd? data->state.aptr.proxyuserpwd:"", data->state.aptr.userpwd?data->state.aptr.userpwd:"", (data->state.use_range && data->state.aptr.rangeline)? data->state.aptr.rangeline:"", (data->set.str[STRING_USERAGENT] && *data->set.str[STRING_USERAGENT] && data->state.aptr.uagent)? data->state.aptr.uagent:"", p_accept?p_accept:"", data->state.aptr.te?data->state.aptr.te:"", (data->set.str[STRING_ENCODING] && *data->set.str[STRING_ENCODING] && data->state.aptr.accept_encoding)? data->state.aptr.accept_encoding:"", (data->state.referer && data->state.aptr.ref)? data->state.aptr.ref:"" ,  (conn->bits.httpproxy && !conn->bits.tunnel_proxy && !Curl_checkheaders(data, STRCONST("Proxy-Connection")) && !Curl_checkProxyheaders(data, conn, STRCONST("Proxy-Connection")))? "Proxy-Connection: Keep-Alive\r\n":"",  "",  te, altused ? altused : "" );
















































  
  Curl_safefree(data->state.aptr.userpwd);
  Curl_safefree(data->state.aptr.proxyuserpwd);
  free(altused);

  if(result) {
    Curl_dyn_free(&req);
    return result;
  }

  if(!(conn->handler->flags&PROTOPT_SSL) && conn->httpversion != 20 && (data->state.httpwant == CURL_HTTP_VERSION_2)) {

    
    result = Curl_http2_request_upgrade(&req, data);
    if(result) {
      Curl_dyn_free(&req);
      return result;
    }
  }

  result = Curl_http_cookies(data, conn, &req);
  if(!result)
    result = Curl_add_timecondition(data, &req);
  if(!result)
    result = Curl_add_custom_headers(data, FALSE, &req);

  if(!result) {
    http->postdata = NULL;  
    if((httpreq == HTTPREQ_GET) || (httpreq == HTTPREQ_HEAD))
      Curl_pgrsSetUploadSize(data, 0); 

    
    result = Curl_http_bodysend(data, conn, &req, httpreq);
  }
  if(result) {
    Curl_dyn_free(&req);
    return result;
  }

  if((http->postsize > -1) && (http->postsize <= data->req.writebytecount) && (http->sending != HTTPSEND_REQUEST))

    data->req.upload_done = TRUE;

  if(data->req.writebytecount) {
    
    Curl_pgrsSetUploadCounter(data, data->req.writebytecount);
    if(Curl_pgrsUpdate(data))
      result = CURLE_ABORTED_BY_CALLBACK;

    if(!http->postsize) {
      
      infof(data, "upload completely sent off: %" CURL_FORMAT_CURL_OFF_T " out of %" CURL_FORMAT_CURL_OFF_T " bytes", data->req.writebytecount, http->postsize);

      data->req.upload_done = TRUE;
      data->req.keepon &= ~KEEP_SEND; 
      data->req.exp100 = EXP100_SEND_DATA; 
      Curl_expire_done(data, EXPIRE_100_TIMEOUT);
    }
  }

  if((conn->httpversion == 20) && data->req.upload_chunky)
    
    data->req.upload_chunky = FALSE;
  return result;
}



typedef enum {
  STATUS_UNKNOWN,  STATUS_DONE, STATUS_BAD } statusline;





static bool checkprefixmax(const char *prefix, const char *buffer, size_t len)
{
  size_t ch = CURLMIN(strlen(prefix), len);
  return curl_strnequal(prefix, buffer, ch);
}


static statusline checkhttpprefix(struct Curl_easy *data, const char *s, size_t len)

{
  struct curl_slist *head = data->set.http200aliases;
  statusline rc = STATUS_BAD;
  statusline onmatch = len >= 5? STATUS_DONE : STATUS_UNKNOWN;

  while(head) {
    if(checkprefixmax(head->data, s, len)) {
      rc = onmatch;
      break;
    }
    head = head->next;
  }

  if((rc != STATUS_DONE) && (checkprefixmax("HTTP/", s, len)))
    rc = onmatch;

  return rc;
}


static statusline checkrtspprefix(struct Curl_easy *data, const char *s, size_t len)

{
  statusline result = STATUS_BAD;
  statusline onmatch = len >= 5? STATUS_DONE : STATUS_UNKNOWN;
  (void)data; 
  if(checkprefixmax("RTSP/", s, len))
    result = onmatch;

  return result;
}


static statusline checkprotoprefix(struct Curl_easy *data, struct connectdata *conn, const char *s, size_t len)

{

  if(conn->handler->protocol & CURLPROTO_RTSP)
    return checkrtspprefix(data, s, len);

  (void)conn;


  return checkhttpprefix(data, s, len);
}


CURLcode Curl_http_header(struct Curl_easy *data, struct connectdata *conn, char *headp)
{
  CURLcode result;
  struct SingleRequest *k = &data->req;
  
  if(!k->http_bodyless && !data->set.ignorecl && checkprefix("Content-Length:", headp)) {
    curl_off_t contentlength;
    CURLofft offt = curlx_strtoofft(headp + strlen("Content-Length:"), NULL, 10, &contentlength);

    if(offt == CURL_OFFT_OK) {
      k->size = contentlength;
      k->maxdownload = k->size;
    }
    else if(offt == CURL_OFFT_FLOW) {
      
      if(data->set.max_filesize) {
        failf(data, "Maximum file size exceeded");
        return CURLE_FILESIZE_EXCEEDED;
      }
      streamclose(conn, "overflow content-length");
      infof(data, "Overflow Content-Length: value");
    }
    else {
      
      failf(data, "Invalid Content-Length: value");
      return CURLE_WEIRD_SERVER_REPLY;
    }
  }
  
  else if(checkprefix("Content-Type:", headp)) {
    char *contenttype = Curl_copy_header_value(headp);
    if(!contenttype)
      return CURLE_OUT_OF_MEMORY;
    if(!*contenttype)
      
      free(contenttype);
    else {
      Curl_safefree(data->info.contenttype);
      data->info.contenttype = contenttype;
    }
  }

  else if((conn->httpversion == 10) && conn->bits.httpproxy && Curl_compareheader(headp, STRCONST("Proxy-Connection:"), STRCONST("keep-alive"))) {



    
    connkeep(conn, "Proxy-Connection keep-alive"); 
    infof(data, "HTTP/1.0 proxy connection set to keep alive");
  }
  else if((conn->httpversion == 11) && conn->bits.httpproxy && Curl_compareheader(headp, STRCONST("Proxy-Connection:"), STRCONST("close"))) {



    
    connclose(conn, "Proxy-Connection: asked to close after done");
    infof(data, "HTTP/1.1 proxy connection set close");
  }

  else if((conn->httpversion == 10) && Curl_compareheader(headp, STRCONST("Connection:"), STRCONST("keep-alive"))) {


    
    connkeep(conn, "Connection keep-alive");
    infof(data, "HTTP/1.0 connection set to keep alive");
  }
  else if(Curl_compareheader(headp, STRCONST("Connection:"), STRCONST("close"))) {
    
    streamclose(conn, "Connection: close used");
  }
  else if(!k->http_bodyless && checkprefix("Transfer-Encoding:", headp)) {
    
    

    result = Curl_build_unencoding_stack(data, headp + strlen("Transfer-Encoding:"), TRUE);

    if(result)
      return result;
    if(!k->chunk) {
      
      connclose(conn, "HTTP/1.1 transfer-encoding without chunks");
      k->ignore_cl = TRUE;
    }
  }
  else if(!k->http_bodyless && checkprefix("Content-Encoding:", headp) && data->set.str[STRING_ENCODING]) {
    
    result = Curl_build_unencoding_stack(data, headp + strlen("Content-Encoding:"), FALSE);

    if(result)
      return result;
  }
  else if(checkprefix("Retry-After:", headp)) {
    
    curl_off_t retry_after = 0; 
    time_t date = Curl_getdate_capped(headp + strlen("Retry-After:"));
    if(-1 == date) {
      
      (void)curlx_strtoofft(headp + strlen("Retry-After:"), NULL, 10, &retry_after);
    }
    else  retry_after = date - time(NULL);

    data->info.retry_after = retry_after; 
  }
  else if(!k->http_bodyless && checkprefix("Content-Range:", headp)) {
    

    char *ptr = headp + strlen("Content-Range:");

    
    while(*ptr && !ISDIGIT(*ptr) && *ptr != '*')
      ptr++;

    
    if(ISDIGIT(*ptr)) {
      if(!curlx_strtoofft(ptr, NULL, 10, &k->offset)) {
        if(data->state.resume_from == k->offset)
          
          k->content_range = TRUE;
      }
    }
    else data->state.resume_from = 0;
  }

  else if(data->cookies && data->state.cookie_engine && checkprefix("Set-Cookie:", headp)) {
    
    const char *host = data->state.aptr.cookiehost? data->state.aptr.cookiehost:conn->host.name;
    const bool secure_context = conn->handler->protocol&CURLPROTO_HTTPS || strcasecompare("localhost", host) || !strcmp(host, "127.0.0.1") || !strcmp(host, "[::1]") ? TRUE : FALSE;




    Curl_share_lock(data, CURL_LOCK_DATA_COOKIE, CURL_LOCK_ACCESS_SINGLE);
    Curl_cookie_add(data, data->cookies, TRUE, FALSE, headp + strlen("Set-Cookie:"), host, data->state.up.path, secure_context);

    Curl_share_unlock(data, CURL_LOCK_DATA_COOKIE);
  }

  else if(!k->http_bodyless && checkprefix("Last-Modified:", headp) && (data->set.timecondition || data->set.get_filetime) ) {
    k->timeofdoc = Curl_getdate_capped(headp + strlen("Last-Modified:"));
    if(data->set.get_filetime)
      data->info.filetime = k->timeofdoc;
  }
  else if((checkprefix("WWW-Authenticate:", headp) && (401 == k->httpcode)) || (checkprefix("Proxy-authenticate:", headp) && (407 == k->httpcode))) {



    bool proxy = (k->httpcode == 407) ? TRUE : FALSE;
    char *auth = Curl_copy_header_value(headp);
    if(!auth)
      return CURLE_OUT_OF_MEMORY;

    result = Curl_http_input_auth(data, proxy, auth);

    free(auth);

    if(result)
      return result;
  }

  else if(checkprefix("Persistent-Auth:", headp)) {
    struct negotiatedata *negdata = &conn->negotiate;
    struct auth *authp = &data->state.authhost;
    if(authp->picked == CURLAUTH_NEGOTIATE) {
      char *persistentauth = Curl_copy_header_value(headp);
      if(!persistentauth)
        return CURLE_OUT_OF_MEMORY;
      negdata->noauthpersist = checkprefix("false", persistentauth)? TRUE:FALSE;
      negdata->havenoauthpersist = TRUE;
      infof(data, "Negotiate: noauthpersist -> %d, header part: %s", negdata->noauthpersist, persistentauth);
      free(persistentauth);
    }
  }

  else if((k->httpcode >= 300 && k->httpcode < 400) && checkprefix("Location:", headp) && !data->req.location) {

    
    char *location = Curl_copy_header_value(headp);
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

        
        result = http_perhapsrewind(data, conn);
        if(result)
          return result;
      }
    }
  }


  
  else if(data->hsts && checkprefix("Strict-Transport-Security:", headp) && (conn->handler->flags & PROTOPT_SSL)) {
    CURLcode check = Curl_hsts_parse(data->hsts, data->state.up.hostname, headp + strlen("Strict-Transport-Security:"));

    if(check)
      infof(data, "Illegal STS header skipped");

    else infof(data, "Parsed STS header fine (%zu entries)", data->hsts->list.size);


  }


  
  else if(data->asi && checkprefix("Alt-Svc:", headp) && ((conn->handler->flags & PROTOPT_SSL) ||   getenv("CURL_ALTSVC_HTTP")




           0  )) {

    
    enum alpnid id = (conn->httpversion == 20) ? ALPN_h2 : ALPN_h1;
    result = Curl_altsvc_parse(data, data->asi, headp + strlen("Alt-Svc:"), id, conn->host.name, curlx_uitous(conn->remote_port));


    if(result)
      return result;
  }

  else if(conn->handler->protocol & CURLPROTO_RTSP) {
    result = Curl_rtsp_parseheader(data, headp);
    if(result)
      return result;
  }
  return CURLE_OK;
}



CURLcode Curl_http_statusline(struct Curl_easy *data, struct connectdata *conn)
{
  struct SingleRequest *k = &data->req;
  data->info.httpcode = k->httpcode;

  data->info.httpversion = conn->httpversion;
  if(!data->state.httpversion || data->state.httpversion > conn->httpversion)
    
    data->state.httpversion = conn->httpversion;

  
  if(data->state.resume_from && data->state.httpreq == HTTPREQ_GET && k->httpcode == 416) {
    
    k->ignorebody = TRUE; 
  }

  if(conn->httpversion == 10) {
    
    infof(data, "HTTP 1.0, assume close after body");
    connclose(conn, "HTTP/1.0 close after body");
  }
  else if(conn->httpversion == 20 || (k->upgr101 == UPGR101_REQUESTED && k->httpcode == 101)) {
    DEBUGF(infof(data, "HTTP/2 found, allow multiplexing"));
    
    conn->bundle->multiuse = BUNDLE_MULTIPLEX;
  }
  else if(conn->httpversion >= 11 && !conn->bits.close) {
    
    DEBUGF(infof(data, "HTTP 1.1 or later with persistent connection"));
  }

  k->http_bodyless = k->httpcode >= 100 && k->httpcode < 200;
  switch(k->httpcode) {
  case 304:
    
    if(data->set.timecondition)
      data->info.timecond = TRUE;
    
  case 204:
    
    k->size = 0;
    k->maxdownload = 0;
    k->http_bodyless = TRUE;
    break;
  default:
    break;
  }
  return CURLE_OK;
}


CURLcode Curl_http_size(struct Curl_easy *data)
{
  struct SingleRequest *k = &data->req;
  if(data->req.ignore_cl || k->chunk) {
    k->size = k->maxdownload = -1;
  }
  else if(k->size != -1) {
    if(data->set.max_filesize && k->size > data->set.max_filesize) {
      failf(data, "Maximum file size exceeded");
      return CURLE_FILESIZE_EXCEEDED;
    }
    Curl_pgrsSetDownloadSize(data, k->size);
    k->maxdownload = k->size;
  }
  return CURLE_OK;
}

static CURLcode verify_header(struct Curl_easy *data)
{
  struct SingleRequest *k = &data->req;
  const char *header = Curl_dyn_ptr(&data->state.headerb);
  size_t hlen = Curl_dyn_len(&data->state.headerb);
  char *ptr = memchr(header, 0x00, hlen);
  if(ptr) {
    
    failf(data, "Nul byte in header");
    return CURLE_WEIRD_SERVER_REPLY;
  }
  if(k->headerline < 2)
    
    return CURLE_OK;
  ptr = memchr(header, ':', hlen);
  if(!ptr) {
    
    failf(data, "Header without colon");
    return CURLE_WEIRD_SERVER_REPLY;
  }
  return CURLE_OK;
}


CURLcode Curl_http_readwrite_headers(struct Curl_easy *data, struct connectdata *conn, ssize_t *nread, bool *stop_reading)


{
  CURLcode result;
  struct SingleRequest *k = &data->req;
  ssize_t onread = *nread;
  char *ostr = k->str;
  char *headp;
  char *str_start;
  char *end_ptr;

  
  do {
    size_t rest_length;
    size_t full_length;
    int writetype;

    
    str_start = k->str;

    
    end_ptr = memchr(str_start, 0x0a, *nread);

    if(!end_ptr) {
      
      result = Curl_dyn_addn(&data->state.headerb, str_start, *nread);
      if(result)
        return result;

      if(!k->headerline) {
        
        statusline st = checkprotoprefix(data, conn, Curl_dyn_ptr(&data->state.headerb), Curl_dyn_len(&data->state.headerb));



        if(st == STATUS_BAD) {
          
          k->header = FALSE;
          k->badheader = HEADER_ALLBAD;
          streamclose(conn, "bad HTTP: No end-of-message indicator");
          if(!data->set.http09_allowed) {
            failf(data, "Received HTTP/0.9 when not allowed");
            return CURLE_UNSUPPORTED_PROTOCOL;
          }
          break;
        }
      }

      break; 
    }

    
    rest_length = (end_ptr - k->str) + 1;
    *nread -= (ssize_t)rest_length;

    k->str = end_ptr + 1; 

    full_length = k->str - str_start;

    result = Curl_dyn_addn(&data->state.headerb, str_start, full_length);
    if(result)
      return result;

    

    if(!k->headerline) {
      
      statusline st = checkprotoprefix(data, conn, Curl_dyn_ptr(&data->state.headerb), Curl_dyn_len(&data->state.headerb));

      if(st == STATUS_BAD) {
        streamclose(conn, "bad HTTP: No end-of-message indicator");
        
        if(!data->set.http09_allowed) {
          failf(data, "Received HTTP/0.9 when not allowed");
          return CURLE_UNSUPPORTED_PROTOCOL;
        }
        k->header = FALSE;
        if(*nread)
          
          k->badheader = HEADER_PARTHEADER;
        else {
          
          k->badheader = HEADER_ALLBAD;
          *nread = onread;
          k->str = ostr;
          return CURLE_OK;
        }
        break;
      }
    }

    
    headp = Curl_dyn_ptr(&data->state.headerb);
    if((0x0a == *headp) || (0x0d == *headp)) {
      size_t headerlen;
      

      if('\r' == *headp)
        headp++; 
      if('\n' == *headp)
        headp++; 

      if(100 <= k->httpcode && 199 >= k->httpcode) {
        
        switch(k->httpcode) {
        case 100:
          
          k->header = TRUE;
          k->headerline = 0; 

          
          if(k->exp100 > EXP100_SEND_DATA) {
            k->exp100 = EXP100_SEND_DATA;
            k->keepon |= KEEP_SEND;
            Curl_expire_done(data, EXPIRE_100_TIMEOUT);
          }
          break;
        case 101:
          
          if(k->upgr101 == UPGR101_REQUESTED) {
            
            infof(data, "Received 101");
            k->upgr101 = UPGR101_RECEIVED;

            
            k->header = TRUE;
            k->headerline = 0; 

            
            result = Curl_http2_switched(data, k->str, *nread);
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

        if((k->size == -1) && !k->chunk && !conn->bits.close && (conn->httpversion == 11) && !(conn->handler->protocol & CURLPROTO_RTSP) && data->state.httpreq != HTTPREQ_HEAD) {


          
          infof(data, "no chunk, no close, no size. Assume close to " "signal end");
          streamclose(conn, "HTTP: No end-of-message indicator");
        }
      }

      if(!k->header) {
        result = Curl_http_size(data);
        if(result)
          return result;
      }

      

      if(conn->bits.close && (((data->req.httpcode == 401) && (conn->http_ntlm_state == NTLMSTATE_TYPE2)) || ((data->req.httpcode == 407) && (conn->proxy_ntlm_state == NTLMSTATE_TYPE2)))) {



        infof(data, "Connection closure while negotiating auth (HTTP 1.0?)");
        data->state.authproblem = TRUE;
      }


      if(conn->bits.close && (((data->req.httpcode == 401) && (conn->http_negotiate_state == GSS_AUTHRECV)) || ((data->req.httpcode == 407) && (conn->proxy_negotiate_state == GSS_AUTHRECV)))) {



        infof(data, "Connection closure while negotiating auth (HTTP 1.0?)");
        data->state.authproblem = TRUE;
      }
      if((conn->http_negotiate_state == GSS_AUTHDONE) && (data->req.httpcode != 401)) {
        conn->http_negotiate_state = GSS_AUTHSUCC;
      }
      if((conn->proxy_negotiate_state == GSS_AUTHDONE) && (data->req.httpcode != 407)) {
        conn->proxy_negotiate_state = GSS_AUTHSUCC;
      }


      
      writetype = CLIENTWRITE_HEADER | (data->set.include_header ? CLIENTWRITE_BODY : 0) | ((k->httpcode/100 == 1) ? CLIENTWRITE_1XX : 0);


      headerlen = Curl_dyn_len(&data->state.headerb);
      result = Curl_client_write(data, writetype, Curl_dyn_ptr(&data->state.headerb), headerlen);

      if(result)
        return result;

      data->info.header_size += (long)headerlen;
      data->req.headerbytecount += (long)headerlen;

      
      if(http_should_fail(data)) {
        failf(data, "The requested URL returned error: %d", k->httpcode);
        return CURLE_HTTP_RETURNED_ERROR;
      }

      data->req.deductheadercount = (100 <= k->httpcode && 199 >= k->httpcode)?data->req.headerbytecount:0;

      
      result = Curl_http_auth_act(data);

      if(result)
        return result;

      if(k->httpcode >= 300) {
        if((!conn->bits.authneg) && !conn->bits.close && !conn->bits.rewindaftersend) {
          

          switch(data->state.httpreq) {
          case HTTPREQ_PUT:
          case HTTPREQ_POST:
          case HTTPREQ_POST_FORM:
          case HTTPREQ_POST_MIME:
            
            Curl_expire_done(data, EXPIRE_100_TIMEOUT);
            if(!k->upload_done) {
              if((k->httpcode == 417) && data->state.expect100header) {
                
                infof(data, "Got 417 while waiting for a 100");
                data->state.disableexpect = TRUE;
                DEBUGASSERT(!data->req.newurl);
                data->req.newurl = strdup(data->state.url);
                Curl_done_sending(data, k);
              }
              else if(data->set.http_keep_sending_on_error) {
                infof(data, "HTTP error before end of send, keep sending");
                if(k->exp100 > EXP100_SEND_DATA) {
                  k->exp100 = EXP100_SEND_DATA;
                  k->keepon |= KEEP_SEND;
                }
              }
              else {
                infof(data, "HTTP error before end of send, stop sending");
                streamclose(conn, "Stop sending data before everything sent");
                result = Curl_done_sending(data, k);
                if(result)
                  return result;
                k->upload_done = TRUE;
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
          
          infof(data, "Keep sending data to get tossed away");
          k->keepon |= KEEP_SEND;
        }
      }

      if(!k->header) {
        
        if(data->set.opt_no_body)
          *stop_reading = TRUE;

        else if((conn->handler->protocol & CURLPROTO_RTSP) && (data->set.rtspreq == RTSPREQ_DESCRIBE) && (k->size <= -1))

          
          *stop_reading = TRUE;


        
        if(0 == k->maxdownload  && !((conn->handler->protocol & PROTO_FAMILY_HTTP) && conn->httpversion == 20)



           )
          *stop_reading = TRUE;

        if(*stop_reading) {
          
          k->keepon &= ~KEEP_RECV;
        }

        Curl_debug(data, CURLINFO_HEADER_IN, str_start, headerlen);
        break; 
      }

      
      Curl_dyn_reset(&data->state.headerb);
      continue;
    }

    

    writetype = CLIENTWRITE_HEADER;
    if(!k->headerline++) {
      
      int httpversion_major;
      int rtspversion_major;
      int nc = 0;


      if(conn->handler->protocol & PROTO_FAMILY_HTTP) {
        
        char separator;
        char twoorthree[2];
        int httpversion = 0;
        char digit4 = 0;
        nc = sscanf(HEADER1, " HTTP/%1d.%1d%c%3d%c", &httpversion_major, &httpversion, &separator, &k->httpcode, &digit4);






        if(nc == 1 && httpversion_major >= 2 && 2 == sscanf(HEADER1, " HTTP/%1[23] %d", twoorthree, &k->httpcode)) {
          conn->httpversion = 0;
          nc = 4;
          separator = ' ';
        }

        
        else if(ISDIGIT(digit4) || (nc >= 4 && k->httpcode < 100)) {
          failf(data, "Unsupported response code in HTTP response");
          return CURLE_UNSUPPORTED_PROTOCOL;
        }

        if((nc >= 4) && (' ' == separator)) {
          httpversion += 10 * httpversion_major;
          switch(httpversion) {
          case 10:
          case 11:

          case 20:


          case 30:

            conn->httpversion = (unsigned char)httpversion;
            break;
          default:
            failf(data, "Unsupported HTTP version (%u.%d) in response", httpversion/10, httpversion%10);
            return CURLE_UNSUPPORTED_PROTOCOL;
          }

          if(k->upgr101 == UPGR101_RECEIVED) {
            
            if(conn->httpversion != 20)
              infof(data, "Lying server, not serving HTTP/2");
          }
          if(conn->httpversion < 20) {
            conn->bundle->multiuse = BUNDLE_NO_MULTIUSE;
            infof(data, "Mark bundle as not supporting multiuse");
          }
        }
        else if(!nc) {
          
          nc = sscanf(HEADER1, " HTTP %3d", &k->httpcode);
          conn->httpversion = 10;

          
          if(!nc) {
            statusline check = checkhttpprefix(data, Curl_dyn_ptr(&data->state.headerb), Curl_dyn_len(&data->state.headerb));


            if(check == STATUS_DONE) {
              nc = 1;
              k->httpcode = 200;
              conn->httpversion = 10;
            }
          }
        }
        else {
          failf(data, "Unsupported HTTP version in response");
          return CURLE_UNSUPPORTED_PROTOCOL;
        }
      }
      else if(conn->handler->protocol & CURLPROTO_RTSP) {
        char separator;
        int rtspversion;
        nc = sscanf(HEADER1, " RTSP/%1d.%1d%c%3d", &rtspversion_major, &rtspversion, &separator, &k->httpcode);




        if((nc == 4) && (' ' == separator)) {
          conn->httpversion = 11; 
        }
        else {
          nc = 0;
        }
      }

      if(nc) {
        result = Curl_http_statusline(data, conn);
        if(result)
          return result;
        writetype |= CLIENTWRITE_STATUS;
      }
      else {
        k->header = FALSE;   
        break;
      }
    }

    result = verify_header(data);
    if(result)
      return result;

    result = Curl_http_header(data, conn, headp);
    if(result)
      return result;

    
    if(data->set.include_header)
      writetype |= CLIENTWRITE_BODY;
    if(k->httpcode/100 == 1)
      writetype |= CLIENTWRITE_1XX;

    Curl_debug(data, CURLINFO_HEADER_IN, headp, Curl_dyn_len(&data->state.headerb));

    result = Curl_client_write(data, writetype, headp, Curl_dyn_len(&data->state.headerb));
    if(result)
      return result;

    data->info.header_size += Curl_dyn_len(&data->state.headerb);
    data->req.headerbytecount += Curl_dyn_len(&data->state.headerb);

    Curl_dyn_reset(&data->state.headerb);
  }
  while(*k->str); 

  

  return CURLE_OK;
}


