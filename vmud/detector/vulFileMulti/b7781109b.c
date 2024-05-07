


































































static CURLcode pop3_parse_url_path(struct connectdata *conn);
static CURLcode pop3_regular_transfer(struct connectdata *conn, bool *done);
static CURLcode pop3_do(struct connectdata *conn, bool *done);
static CURLcode pop3_done(struct connectdata *conn, CURLcode, bool premature);
static CURLcode pop3_connect(struct connectdata *conn, bool *done);
static CURLcode pop3_disconnect(struct connectdata *conn, bool dead);
static CURLcode pop3_multi_statemach(struct connectdata *conn, bool *done);
static int pop3_getsock(struct connectdata *conn, curl_socket_t *socks, int numsocks);

static CURLcode pop3_doing(struct connectdata *conn, bool *dophase_done);
static CURLcode pop3_setup_connection(struct connectdata * conn);



const struct Curl_handler Curl_handler_pop3 = {
  "POP3",                            pop3_setup_connection, pop3_do, pop3_done, ZERO_NULL, pop3_connect, pop3_multi_statemach, pop3_doing, pop3_getsock, pop3_getsock, ZERO_NULL, ZERO_NULL, pop3_disconnect, ZERO_NULL, PORT_POP3, CURLPROTO_POP3, PROTOPT_CLOSEACTION | PROTOPT_NOURLQUERY };





















const struct Curl_handler Curl_handler_pop3s = {
  "POP3S",                           pop3_setup_connection, pop3_do, pop3_done, ZERO_NULL, pop3_connect, pop3_multi_statemach, pop3_doing, pop3_getsock, pop3_getsock, ZERO_NULL, ZERO_NULL, pop3_disconnect, ZERO_NULL, PORT_POP3S, CURLPROTO_POP3 | CURLPROTO_POP3S, PROTOPT_CLOSEACTION | PROTOPT_SSL | PROTOPT_NOURLQUERY };






















static const struct Curl_handler Curl_handler_pop3_proxy = {
  "POP3",                                ZERO_NULL, Curl_http, Curl_http_done, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, PORT_POP3, CURLPROTO_HTTP, PROTOPT_NONE };





















static const struct Curl_handler Curl_handler_pop3s_proxy = {
  "POP3S",                               ZERO_NULL, Curl_http, Curl_http_done, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, PORT_POP3S, CURLPROTO_HTTP, PROTOPT_NONE };





















static int pop3_endofresp(struct pingpong *pp, int *resp)
{
  char *line = pp->linestart_resp;
  size_t len = pp->nread_resp;

  if(((len >= 3) && !memcmp("+OK", line, 3)) || ((len >= 4) && !memcmp("-ERR", line, 4))) {
    *resp=line[1]; 
    return TRUE;
  }

  return FALSE; 
}


static void state(struct connectdata *conn, pop3state newstate)
{

  
  static const char * const names[]={
    "STOP", "SERVERGREET", "USER", "PASS", "STARTTLS", "LIST", "LIST_SINGLE", "RETR", "QUIT",  };










  struct pop3_conn *pop3c = &conn->proto.pop3c;

  if(pop3c->state != newstate)
    infof(conn->data, "POP3 %p state change from %s to %s\n", pop3c, names[pop3c->state], names[newstate]);

  pop3c->state = newstate;
}

static CURLcode pop3_state_user(struct connectdata *conn)
{
  CURLcode result;
  struct FTP *pop3 = conn->data->state.proto.pop3;

  
  result = Curl_pp_sendf(&conn->proto.pop3c.pp, "USER %s", pop3->user?pop3->user:"");
  if(result)
    return result;

  state(conn, POP3_USER);

  return CURLE_OK;
}


static int pop3_getsock(struct connectdata *conn, curl_socket_t *socks, int numsocks)

{
  return Curl_pp_getsock(&conn->proto.pop3c.pp, socks, numsocks);
}


static void pop3_to_pop3s(struct connectdata *conn)
{
  conn->handler = &Curl_handler_pop3s;
}





static CURLcode pop3_state_starttls_resp(struct connectdata *conn, int pop3code, pop3state instate)

{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  (void)instate; 

  if(pop3code != 'O') {
    if(data->set.use_ssl != CURLUSESSL_TRY) {
      failf(data, "STARTTLS denied. %c", pop3code);
      result = CURLE_USE_SSL_FAILED;
      state(conn, POP3_STOP);
    }
    else result = pop3_state_user(conn);
  }
  else {
    
    result = Curl_ssl_connect(conn, FIRSTSOCKET);
    if(CURLE_OK == result) {
      pop3_to_pop3s(conn);
      result = pop3_state_user(conn);
    }
    else {
      state(conn, POP3_STOP);
    }
  }
  return result;
}


static CURLcode pop3_state_user_resp(struct connectdata *conn, int pop3code, pop3state instate)

{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  struct FTP *pop3 = data->state.proto.pop3;

  (void)instate; 

  if(pop3code != 'O') {
    failf(data, "Access denied. %c", pop3code);
    result = CURLE_LOGIN_DENIED;
  }
  else  result = Curl_pp_sendf(&conn->proto.pop3c.pp, "PASS %s", pop3->passwd?pop3->passwd:"");


  if(result)
    return result;

  state(conn, POP3_PASS);
  return result;
}


static CURLcode pop3_state_pass_resp(struct connectdata *conn, int pop3code, pop3state instate)

{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  (void)instate; 

  if(pop3code != 'O') {
    failf(data, "Access denied. %c", pop3code);
    result = CURLE_LOGIN_DENIED;
  }

  state(conn, POP3_STOP);
  return result;
}


static CURLcode pop3_state_retr_resp(struct connectdata *conn, int pop3code, pop3state instate)

{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  struct FTP *pop3 = data->state.proto.pop3;
  struct pop3_conn *pop3c = &conn->proto.pop3c;
  struct pingpong *pp = &pop3c->pp;

  (void)instate; 

  if('O' != pop3code) {
    state(conn, POP3_STOP);
    return CURLE_RECV_ERROR;
  }

  
  Curl_setup_transfer(conn, FIRSTSOCKET, -1, FALSE, pop3->bytecountp, -1, NULL);

  if(pp->cache) {
    

    
    result = Curl_pop3_write(conn, pp->cache, pp->cache_size);
    if(result)
      return result;

    
    free(pp->cache);
    pp->cache = NULL;
    pp->cache_size = 0;
  }

  state(conn, POP3_STOP);
  return result;
}



static CURLcode pop3_state_list_resp(struct connectdata *conn, int pop3code, pop3state instate)

{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  struct FTP *pop3 = data->state.proto.pop3;
  struct pop3_conn *pop3c = &conn->proto.pop3c;
  struct pingpong *pp = &pop3c->pp;

  (void)instate; 

  if('O' != pop3code) {
    state(conn, POP3_STOP);
    return CURLE_RECV_ERROR;
  }

  
  pop3c->eob = 2;

  
  pop3c->strip = 2;

  
  Curl_setup_transfer(conn, FIRSTSOCKET, -1, FALSE, pop3->bytecountp, -1, NULL);

  if(pp->cache) {
    

    
    result = Curl_pop3_write(conn, pp->cache, pp->cache_size);
    if(result)
      return result;

    
    free(pp->cache);
    pp->cache = NULL;
    pp->cache_size = 0;
  }

  state(conn, POP3_STOP);
  return result;
}


static CURLcode pop3_state_list_single_resp(struct connectdata *conn, int pop3code, pop3state instate)

{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  (void)instate; 

  if(pop3code != 'O') {
    failf(data, "Invalid message. %c", pop3code);
    result = CURLE_REMOTE_FILE_NOT_FOUND;
  }

  state(conn, POP3_STOP);
  return result;
}


static CURLcode pop3_retr(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct pop3_conn *pop3c = &conn->proto.pop3c;

  result = Curl_pp_sendf(&conn->proto.pop3c.pp, "RETR %s", pop3c->mailbox);
  if(result)
    return result;

  state(conn, POP3_RETR);
  return result;
}


static CURLcode pop3_list(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct pop3_conn *pop3c = &conn->proto.pop3c;

  if(pop3c->mailbox[0] != '\0')
    result = Curl_pp_sendf(&conn->proto.pop3c.pp, "LIST %s", pop3c->mailbox);
  else result = Curl_pp_sendf(&conn->proto.pop3c.pp, "LIST");
  if(result)
    return result;

  if(pop3c->mailbox[0] != '\0')
    state(conn, POP3_LIST_SINGLE);
  else state(conn, POP3_LIST);
  return result;
}

static CURLcode pop3_statemach_act(struct connectdata *conn)
{
  CURLcode result;
  curl_socket_t sock = conn->sock[FIRSTSOCKET];
  struct SessionHandle *data=conn->data;
  int pop3code;
  struct pop3_conn *pop3c = &conn->proto.pop3c;
  struct pingpong *pp = &pop3c->pp;
  size_t nread = 0;

  if(pp->sendleft)
    return Curl_pp_flushsend(pp);

  
  result = Curl_pp_readresp(sock, pp, &pop3code, &nread);
  if(result)
    return result;

  if(pop3code) {
    
    switch(pop3c->state) {
    case POP3_SERVERGREET:
      if(pop3code != 'O') {
        failf(data, "Got unexpected pop3-server response");
        return CURLE_FTP_WEIRD_SERVER_REPLY;
      }

      if(data->set.use_ssl && !conn->ssl[FIRSTSOCKET].use) {
        
        result = Curl_pp_sendf(&pop3c->pp, "STLS");
        state(conn, POP3_STARTTLS);
      }
      else result = pop3_state_user(conn);
      if(result)
        return result;
      break;

    case POP3_USER:
      result = pop3_state_user_resp(conn, pop3code, pop3c->state);
      break;

    case POP3_PASS:
      result = pop3_state_pass_resp(conn, pop3code, pop3c->state);
      break;

    case POP3_STARTTLS:
      result = pop3_state_starttls_resp(conn, pop3code, pop3c->state);
      break;

    case POP3_RETR:
      result = pop3_state_retr_resp(conn, pop3code, pop3c->state);
      break;

    case POP3_LIST:
      result = pop3_state_list_resp(conn, pop3code, pop3c->state);
      break;

    case POP3_LIST_SINGLE:
      result = pop3_state_list_single_resp(conn, pop3code, pop3c->state);
      break;

    case POP3_QUIT:
      
    default:
      
      state(conn, POP3_STOP);
      break;
    }
  }
  return result;
}


static CURLcode pop3_multi_statemach(struct connectdata *conn, bool *done)
{
  struct pop3_conn *pop3c = &conn->proto.pop3c;
  CURLcode result = Curl_pp_multi_statemach(&pop3c->pp);

  *done = (pop3c->state == POP3_STOP) ? TRUE : FALSE;

  return result;
}

static CURLcode pop3_easy_statemach(struct connectdata *conn)
{
  struct pop3_conn *pop3c = &conn->proto.pop3c;
  struct pingpong *pp = &pop3c->pp;
  CURLcode result = CURLE_OK;

  while(pop3c->state != POP3_STOP) {
    result = Curl_pp_easy_statemach(pp);
    if(result)
      break;
  }

  return result;
}


static CURLcode pop3_init(struct connectdata *conn)
{
  struct SessionHandle *data = conn->data;
  struct FTP *pop3 = data->state.proto.pop3;
  if(!pop3) {
    pop3 = data->state.proto.pop3 = calloc(sizeof(struct FTP), 1);
    if(!pop3)
      return CURLE_OUT_OF_MEMORY;
  }

  
  pop3->bytecountp = &data->req.bytecount;

  
  pop3->user = conn->user;
  pop3->passwd = conn->passwd;

  return CURLE_OK;
}


static CURLcode pop3_connect(struct connectdata *conn, bool *done)
{
  CURLcode result;
  struct pop3_conn *pop3c = &conn->proto.pop3c;
  struct SessionHandle *data=conn->data;
  struct pingpong *pp = &pop3c->pp;

  *done = FALSE; 

  
  Curl_reset_reqproto(conn);

  result = pop3_init(conn);
  if(CURLE_OK != result)
    return result;

  
  conn->bits.close = FALSE;

  pp->response_time = RESP_TIMEOUT; 
  pp->statemach_act = pop3_statemach_act;
  pp->endofresp = pop3_endofresp;
  pp->conn = conn;

  if(conn->bits.tunnel_proxy && conn->bits.httpproxy) {
    
    struct HTTP http_proxy;
    struct FTP *pop3_save;

    
    

    
    pop3_save = data->state.proto.pop3;
    memset(&http_proxy, 0, sizeof(http_proxy));
    data->state.proto.http = &http_proxy;

    result = Curl_proxyCONNECT(conn, FIRSTSOCKET, conn->host.name, conn->remote_port);

    data->state.proto.pop3 = pop3_save;

    if(CURLE_OK != result)
      return result;
  }

  if(conn->handler->flags & PROTOPT_SSL) {
    
    result = Curl_ssl_connect(conn, FIRSTSOCKET);
    if(result)
      return result;
  }

  Curl_pp_init(pp); 

  
  state(conn, POP3_SERVERGREET);

  if(data->state.used_interface == Curl_if_multi)
    result = pop3_multi_statemach(conn, done);
  else {
    result = pop3_easy_statemach(conn);
    if(!result)
      *done = TRUE;
  }

  return result;
}


static CURLcode pop3_done(struct connectdata *conn, CURLcode status, bool premature)
{
  struct SessionHandle *data = conn->data;
  struct FTP *pop3 = data->state.proto.pop3;
  struct pop3_conn *pop3c = &conn->proto.pop3c;
  CURLcode result=CURLE_OK;
  (void)premature;

  if(!pop3)
    
    return CURLE_OK;

  if(status) {
    conn->bits.close = TRUE; 
    result = status;      
  }

  Curl_safefree(pop3c->mailbox);
  pop3c->mailbox = NULL;

  
  pop3->transfer = FTPTRANSFER_BODY;

  return result;
}



static CURLcode pop3_perform(struct connectdata *conn, bool *connected, bool *dophase_done)


{
  
  CURLcode result=CURLE_OK;
  struct pop3_conn *pop3c = &conn->proto.pop3c;

  DEBUGF(infof(conn->data, "DO phase starts\n"));

  if(conn->data->set.opt_no_body) {
    
    struct FTP *pop3 = conn->data->state.proto.pop3;
    pop3->transfer = FTPTRANSFER_INFO;
  }

  *dophase_done = FALSE; 

  
  
  if(strlen(pop3c->mailbox) && !conn->data->set.ftp_list_only)
    result = pop3_retr(conn);
  else result = pop3_list(conn);
  if(result)
    return result;

  
  if(conn->data->state.used_interface == Curl_if_multi)
    result = pop3_multi_statemach(conn, dophase_done);
  else {
    result = pop3_easy_statemach(conn);
    *dophase_done = TRUE; 
  }
  *connected = conn->bits.tcpconnect[FIRSTSOCKET];

  if(*dophase_done)
    DEBUGF(infof(conn->data, "DO phase is complete\n"));

  return result;
}


static CURLcode pop3_do(struct connectdata *conn, bool *done)
{
  CURLcode retcode = CURLE_OK;

  *done = FALSE; 

  
  Curl_reset_reqproto(conn);
  retcode = pop3_init(conn);
  if(retcode)
    return retcode;

  retcode = pop3_parse_url_path(conn);
  if(retcode)
    return retcode;

  retcode = pop3_regular_transfer(conn, done);

  return retcode;
}


static CURLcode pop3_quit(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;

  result = Curl_pp_sendf(&conn->proto.pop3c.pp, "QUIT", NULL);
  if(result)
    return result;
  state(conn, POP3_QUIT);

  result = pop3_easy_statemach(conn);

  return result;
}


static CURLcode pop3_disconnect(struct connectdata *conn, bool dead_connection)
{
  struct pop3_conn *pop3c= &conn->proto.pop3c;

  

  
  if(!dead_connection && pop3c->pp.conn)
    (void)pop3_quit(conn); 


  Curl_pp_disconnect(&pop3c->pp);

  return CURLE_OK;
}


static CURLcode pop3_parse_url_path(struct connectdata *conn)
{
  
  struct pop3_conn *pop3c = &conn->proto.pop3c;
  struct SessionHandle *data = conn->data;
  const char *path = data->state.path;

  
  pop3c->mailbox = curl_easy_unescape(data, path, 0, NULL);
  if(!pop3c->mailbox)
    return CURLE_OUT_OF_MEMORY;

  return CURLE_OK;
}


static CURLcode pop3_dophase_done(struct connectdata *conn, bool connected)
{
  struct FTP *pop3 = conn->data->state.proto.pop3;
  (void)connected;

  if(pop3->transfer != FTPTRANSFER_BODY)
    
    Curl_setup_transfer(conn, -1, -1, FALSE, NULL, -1, NULL);

  return CURLE_OK;
}


static CURLcode pop3_doing(struct connectdata *conn, bool *dophase_done)
{
  CURLcode result;
  result = pop3_multi_statemach(conn, dophase_done);

  if(*dophase_done) {
    result = pop3_dophase_done(conn, FALSE );

    DEBUGF(infof(conn->data, "DO phase is complete\n"));
  }
  return result;
}


static CURLcode pop3_regular_transfer(struct connectdata *conn, bool *dophase_done)

{
  CURLcode result=CURLE_OK;
  bool connected=FALSE;
  struct SessionHandle *data = conn->data;
  data->req.size = -1; 

  Curl_pgrsSetUploadCounter(data, 0);
  Curl_pgrsSetDownloadCounter(data, 0);
  Curl_pgrsSetUploadSize(data, 0);
  Curl_pgrsSetDownloadSize(data, 0);

  result = pop3_perform(conn, &connected, dophase_done);


  if(CURLE_OK == result) {

    if(!*dophase_done)
      
      return CURLE_OK;

    result = pop3_dophase_done(conn, connected);
    if(result)
      return result;
  }

  return result;
}

static CURLcode pop3_setup_connection(struct connectdata * conn)
{
  struct SessionHandle *data = conn->data;

  if(conn->bits.httpproxy && !data->set.tunnel_thru_httpproxy) {
    

    if(conn->handler == &Curl_handler_pop3)
      conn->handler = &Curl_handler_pop3_proxy;
    else {

      conn->handler = &Curl_handler_pop3s_proxy;

      failf(data, "POP3S not supported!");
      return CURLE_UNSUPPORTED_PROTOCOL;

    }
    
    conn->bits.close = FALSE;

    failf(data, "POP3 over http proxy requires HTTP support built-in!");
    return CURLE_UNSUPPORTED_PROTOCOL;

  }

  data->state.path++;   

  return CURLE_OK;
}






CURLcode Curl_pop3_write(struct connectdata *conn, char *str, size_t nread)

{
  
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  struct SingleRequest *k = &data->req;

  struct pop3_conn *pop3c = &conn->proto.pop3c;
  bool strip_dot = FALSE;
  size_t last = 0;
  size_t i;

  
  for(i = 0; i < nread; i++) {
    size_t prev = pop3c->eob;

    switch(str[i]) {
    case 0x0d:
      if(pop3c->eob == 0) {
        pop3c->eob++;

        if(i) {
          
          result = Curl_client_write(conn, CLIENTWRITE_BODY, &str[last], i - last);

          if(result)
            return result;

          last = i;
        }
      }
      else if(pop3c->eob == 3)
        pop3c->eob++;
      else  pop3c->eob = 1;

      break;

    case 0x0a:
      if(pop3c->eob == 1 || pop3c->eob == 4)
        pop3c->eob++;
      else  pop3c->eob = 0;

      break;

    case 0x2e:
      if(pop3c->eob == 2)
        pop3c->eob++;
      else if(pop3c->eob == 3) {
        
        strip_dot = TRUE;
        pop3c->eob = 0;
      }
      else  pop3c->eob = 0;

      break;

    default:
      pop3c->eob = 0;
      break;
    }

    
    if(prev && prev >= pop3c->eob) {
      
      while(prev && pop3c->strip) {
        prev--;
        pop3c->strip--;
      }

      if(prev) {
        
        result = Curl_client_write(conn, CLIENTWRITE_BODY, (char*)POP3_EOB, strip_dot ? prev - 1 : prev);

        if(result)
          return result;

        last = i;
        strip_dot = FALSE;
      }
    }
  }

  if(pop3c->eob == POP3_EOB_LEN) {
    
    k->keepon &= ~KEEP_RECV;
    pop3c->eob = 0;
    return CURLE_OK;
  }

  if(pop3c->eob)
    
    return CURLE_OK;

  if(nread - last) {
    result = Curl_client_write(conn, CLIENTWRITE_BODY, &str[last], nread - last);
  }

  return result;
}


