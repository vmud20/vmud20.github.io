


































































static CURLcode imap_parse_url_path(struct connectdata *conn);
static CURLcode imap_regular_transfer(struct connectdata *conn, bool *done);
static CURLcode imap_do(struct connectdata *conn, bool *done);
static CURLcode imap_done(struct connectdata *conn, CURLcode, bool premature);
static CURLcode imap_connect(struct connectdata *conn, bool *done);
static CURLcode imap_disconnect(struct connectdata *conn, bool dead);
static CURLcode imap_multi_statemach(struct connectdata *conn, bool *done);
static int imap_getsock(struct connectdata *conn, curl_socket_t *socks, int numsocks);

static CURLcode imap_doing(struct connectdata *conn, bool *dophase_done);
static CURLcode imap_setup_connection(struct connectdata * conn);
static CURLcode imap_state_upgrade_tls(struct connectdata *conn);



const struct Curl_handler Curl_handler_imap = {
  "IMAP",                            imap_setup_connection, imap_do, imap_done, ZERO_NULL, imap_connect, imap_multi_statemach, imap_doing, imap_getsock, imap_getsock, ZERO_NULL, ZERO_NULL, imap_disconnect, ZERO_NULL, PORT_IMAP, CURLPROTO_IMAP, PROTOPT_CLOSEACTION | PROTOPT_NEEDSPWD | PROTOPT_NOURLQUERY };






















const struct Curl_handler Curl_handler_imaps = {
  "IMAPS",                           imap_setup_connection, imap_do, imap_done, ZERO_NULL, imap_connect, imap_multi_statemach, imap_doing, imap_getsock, imap_getsock, ZERO_NULL, ZERO_NULL, imap_disconnect, ZERO_NULL, PORT_IMAPS, CURLPROTO_IMAP | CURLPROTO_IMAPS, PROTOPT_CLOSEACTION | PROTOPT_SSL | PROTOPT_NEEDSPWD | PROTOPT_NOURLQUERY };






















static const struct Curl_handler Curl_handler_imap_proxy = {
  "IMAP",                                ZERO_NULL, Curl_http, Curl_http_done, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, PORT_IMAP, CURLPROTO_HTTP, PROTOPT_NONE };





















static const struct Curl_handler Curl_handler_imaps_proxy = {
  "IMAPS",                               ZERO_NULL, Curl_http, Curl_http_done, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, PORT_IMAPS, CURLPROTO_HTTP, PROTOPT_NONE };




















static CURLcode imapsendf(struct connectdata *conn, const char *idstr, const char *fmt, ...)

{
  CURLcode res;
  struct imap_conn *imapc = &conn->proto.imapc;
  va_list ap;
  va_start(ap, fmt);

  imapc->idstr = idstr; 

  res = Curl_pp_vsendf(&imapc->pp, fmt, ap);

  va_end(ap);

  return res;
}

static const char *getcmdid(struct connectdata *conn)
{
  static const char * const ids[]= {
    "A", "B", "C", "D" };




  struct imap_conn *imapc = &conn->proto.imapc;

  
  imapc->cmdid = (int)((imapc->cmdid+1) % (sizeof(ids)/sizeof(ids[0])));

  return ids[imapc->cmdid];
}


static int imap_getsock(struct connectdata *conn, curl_socket_t *socks, int numsocks)

{
  return Curl_pp_getsock(&conn->proto.imapc.pp, socks, numsocks);
}


static int imap_endofresp(struct pingpong *pp, int *resp)
{
  char *line = pp->linestart_resp;
  size_t len = pp->nread_resp;
  struct imap_conn *imapc = &pp->conn->proto.imapc;
  const char *id = imapc->idstr;
  size_t id_len = strlen(id);

  if(len >= id_len + 3) {
    if(!memcmp(id, line, id_len) && (line[id_len] == ' ') ) {
      
      *resp = line[id_len+1]; 
      return TRUE;
    }
    else if((imapc->state == IMAP_FETCH) && !memcmp("* ", line, 2) ) {
      
      *resp = '*';
      return TRUE;
    }
  }
  return FALSE; 
}


static void state(struct connectdata *conn, imapstate newstate)
{

  
  static const char * const names[]={
    "STOP", "SERVERGREET", "LOGIN", "STARTTLS", "UPGRADETLS", "SELECT", "FETCH", "LOGOUT",  };









  struct imap_conn *imapc = &conn->proto.imapc;

  if(imapc->state != newstate)
    infof(conn->data, "IMAP %p state change from %s to %s\n", imapc, names[imapc->state], names[newstate]);

  imapc->state = newstate;
}

static CURLcode imap_state_login(struct connectdata *conn)
{
  CURLcode result;
  struct FTP *imap = conn->data->state.proto.imap;
  const char *str;

  str = getcmdid(conn);

  
  result = imapsendf(conn, str, "%s LOGIN %s %s", str, imap->user?imap->user:"", imap->passwd?imap->passwd:"");

  if(result)
    return result;

  state(conn, IMAP_LOGIN);

  return CURLE_OK;
}


static void imap_to_imaps(struct connectdata *conn)
{
  conn->handler = &Curl_handler_imaps;
}





static CURLcode imap_state_starttls_resp(struct connectdata *conn, int imapcode, imapstate instate)

{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  (void)instate; 

  if(imapcode != 'O') {
    if(data->set.use_ssl != CURLUSESSL_TRY) {
      failf(data, "STARTTLS denied. %c", imapcode);
      result = CURLE_USE_SSL_FAILED;
    }
    else result = imap_state_login(conn);
  }
  else {
    if(data->state.used_interface == Curl_if_multi) {
      state(conn, IMAP_UPGRADETLS);
      return imap_state_upgrade_tls(conn);
    }
    else {
      result = Curl_ssl_connect(conn, FIRSTSOCKET);
      if(CURLE_OK == result) {
        imap_to_imaps(conn);
        result = imap_state_login(conn);
      }
    }
  }
  state(conn, IMAP_STOP);
  return result;
}

static CURLcode imap_state_upgrade_tls(struct connectdata *conn)
{
  struct imap_conn *imapc = &conn->proto.imapc;
  CURLcode result;

  result = Curl_ssl_connect_nonblocking(conn, FIRSTSOCKET, &imapc->ssldone);

  if(imapc->ssldone) {
    imap_to_imaps(conn);
    result = imap_state_login(conn);
    state(conn, IMAP_STOP);
  }

  return result;
}


static CURLcode imap_state_login_resp(struct connectdata *conn, int imapcode, imapstate instate)

{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  (void)instate; 

  if(imapcode != 'O') {
    failf(data, "Access denied. %c", imapcode);
    result = CURLE_LOGIN_DENIED;
  }

  state(conn, IMAP_STOP);
  return result;
}


static CURLcode imap_state_fetch_resp(struct connectdata *conn, int imapcode, imapstate instate)

{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  struct imap_conn *imapc = &conn->proto.imapc;
  struct FTP *imap = data->state.proto.imap;
  struct pingpong *pp = &imapc->pp;
  const char *ptr = data->state.buffer;
  (void)instate; 

  if('*' != imapcode) {
    Curl_pgrsSetDownloadSize(data, 0);
    state(conn, IMAP_STOP);
    return CURLE_OK;
  }

  
  while(*ptr && (*ptr != '{'))
    ptr++;

  if(*ptr == '{') {
    curl_off_t filesize = curlx_strtoofft(ptr+1, NULL, 10);
    if(filesize)
      Curl_pgrsSetDownloadSize(data, filesize);

    infof(data, "Found %" FORMAT_OFF_TU " bytes to download\n", filesize);

    if(pp->cache) {
      
      size_t chunk = pp->cache_size;

      if(chunk > (size_t)filesize)
        
        chunk = (size_t)filesize;

      result = Curl_client_write(conn, CLIENTWRITE_BODY, pp->cache, chunk);
      if(result)
        return result;

      filesize -= chunk;

      
      if(pp->cache_size > chunk) {
        
        memmove(pp->cache, pp->cache+chunk, pp->cache_size - chunk);
        pp->cache_size -= chunk;
      }
      else {
        
        free(pp->cache);
        pp->cache = NULL;
        pp->cache_size = 0;
      }
    }

    infof(data, "Filesize left: %" FORMAT_OFF_T "\n", filesize);

    if(!filesize)
      
      Curl_setup_transfer(conn, -1, -1, FALSE, NULL, -1, NULL);
    else  Curl_setup_transfer(conn, FIRSTSOCKET, filesize, FALSE, imap->bytecountp, -1, NULL);



    data->req.maxdownload = filesize;
  }
  else  result = CURLE_FTP_WEIRD_SERVER_REPLY;


  state(conn, IMAP_STOP);
  return result;
}


static CURLcode imap_select(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct imap_conn *imapc = &conn->proto.imapc;
  const char *str;

  str = getcmdid(conn);

  result = imapsendf(conn, str, "%s SELECT %s", str, imapc->mailbox?imapc->mailbox:"");
  if(result)
    return result;

  state(conn, IMAP_SELECT);
  return result;
}

static CURLcode imap_fetch(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  const char *str;

  str = getcmdid(conn);

  
  result = imapsendf(conn, str, "%s FETCH 1 BODY[TEXT]", str);
  if(result)
    return result;

  

  state(conn, IMAP_FETCH);
  return result;
}


static CURLcode imap_state_select_resp(struct connectdata *conn, int imapcode, imapstate instate)

{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  (void)instate; 

  if(imapcode != 'O') {
    failf(data, "Select failed");
    result = CURLE_LOGIN_DENIED;
  }
  else result = imap_fetch(conn);
  return result;
}

static CURLcode imap_statemach_act(struct connectdata *conn)
{
  CURLcode result;
  curl_socket_t sock = conn->sock[FIRSTSOCKET];
  struct SessionHandle *data=conn->data;
  int imapcode;
  struct imap_conn *imapc = &conn->proto.imapc;
  struct pingpong *pp = &imapc->pp;
  size_t nread = 0;

  
  if(imapc->state == IMAP_UPGRADETLS)
    return imap_state_upgrade_tls(conn);

  if(pp->sendleft)
    return Curl_pp_flushsend(pp);

  
  result = Curl_pp_readresp(sock, pp, &imapcode, &nread);
  if(result)
    return result;

  if(imapcode)
  
  switch(imapc->state) {
  case IMAP_SERVERGREET:
    if(imapcode != 'O') {
      failf(data, "Got unexpected imap-server response");
      return CURLE_FTP_WEIRD_SERVER_REPLY;
    }

    if(data->set.use_ssl && !conn->ssl[FIRSTSOCKET].use) {
      
      const char *str;

      str = getcmdid(conn);
      result = imapsendf(conn, str, "%s STARTTLS", str);
      state(conn, IMAP_STARTTLS);
    }
    else result = imap_state_login(conn);
    if(result)
      return result;
    break;

  case IMAP_LOGIN:
    result = imap_state_login_resp(conn, imapcode, imapc->state);
    break;

  case IMAP_STARTTLS:
    result = imap_state_starttls_resp(conn, imapcode, imapc->state);
    break;

  case IMAP_FETCH:
    result = imap_state_fetch_resp(conn, imapcode, imapc->state);
    break;

  case IMAP_SELECT:
    result = imap_state_select_resp(conn, imapcode, imapc->state);
    break;

  case IMAP_LOGOUT:
    
  default:
    
    state(conn, IMAP_STOP);
    break;
  }

  return result;
}


static CURLcode imap_multi_statemach(struct connectdata *conn, bool *done)
{
  struct imap_conn *imapc = &conn->proto.imapc;
  CURLcode result;

  if((conn->handler->flags & PROTOPT_SSL) && !imapc->ssldone)
    result = Curl_ssl_connect_nonblocking(conn, FIRSTSOCKET, &imapc->ssldone);
  else result = Curl_pp_multi_statemach(&imapc->pp);

  *done = (imapc->state == IMAP_STOP) ? TRUE : FALSE;

  return result;
}

static CURLcode imap_easy_statemach(struct connectdata *conn)
{
  struct imap_conn *imapc = &conn->proto.imapc;
  struct pingpong *pp = &imapc->pp;
  CURLcode result = CURLE_OK;

  while(imapc->state != IMAP_STOP) {
    result = Curl_pp_easy_statemach(pp);
    if(result)
      break;
  }

  return result;
}


static CURLcode imap_init(struct connectdata *conn)
{
  struct SessionHandle *data = conn->data;
  struct FTP *imap = data->state.proto.imap;
  if(!imap) {
    imap = data->state.proto.imap = calloc(sizeof(struct FTP), 1);
    if(!imap)
      return CURLE_OUT_OF_MEMORY;
  }

  
  imap->bytecountp = &data->req.bytecount;

  
  imap->user = conn->user;
  imap->passwd = conn->passwd;

  return CURLE_OK;
}


static CURLcode imap_connect(struct connectdata *conn, bool *done)
{
  CURLcode result;
  struct imap_conn *imapc = &conn->proto.imapc;
  struct SessionHandle *data=conn->data;
  struct pingpong *pp = &imapc->pp;

  *done = FALSE; 

  
  Curl_reset_reqproto(conn);

  result = imap_init(conn);
  if(CURLE_OK != result)
    return result;

  
  conn->bits.close = FALSE;

  pp->response_time = RESP_TIMEOUT; 
  pp->statemach_act = imap_statemach_act;
  pp->endofresp = imap_endofresp;
  pp->conn = conn;

  if(conn->bits.tunnel_proxy && conn->bits.httpproxy) {
    
    struct HTTP http_proxy;
    struct FTP *imap_save;

    
    

    
    imap_save = data->state.proto.imap;
    memset(&http_proxy, 0, sizeof(http_proxy));
    data->state.proto.http = &http_proxy;

    result = Curl_proxyCONNECT(conn, FIRSTSOCKET, conn->host.name, conn->remote_port);

    data->state.proto.imap = imap_save;

    if(CURLE_OK != result)
      return result;
  }

  if((conn->handler->flags & PROTOPT_SSL) && data->state.used_interface != Curl_if_multi) {
    
    result = Curl_ssl_connect(conn, FIRSTSOCKET);
    if(result)
      return result;
  }

  Curl_pp_init(pp); 

  
  state(conn, IMAP_SERVERGREET);
  imapc->idstr = "*"; 

  if(data->state.used_interface == Curl_if_multi)
    result = imap_multi_statemach(conn, done);
  else {
    result = imap_easy_statemach(conn);
    if(!result)
      *done = TRUE;
  }

  return result;
}


static CURLcode imap_done(struct connectdata *conn, CURLcode status, bool premature)
{
  struct SessionHandle *data = conn->data;
  struct FTP *imap = data->state.proto.imap;
  CURLcode result=CURLE_OK;
  (void)premature;

  if(!imap)
    
    return CURLE_OK;

  if(status) {
    conn->bits.close = TRUE; 
    result = status;      
  }

  
  imap->transfer = FTPTRANSFER_BODY;

  return result;
}



static CURLcode imap_perform(struct connectdata *conn, bool *connected, bool *dophase_done)


{
  
  CURLcode result=CURLE_OK;

  DEBUGF(infof(conn->data, "DO phase starts\n"));

  if(conn->data->set.opt_no_body) {
    
    struct FTP *imap = conn->data->state.proto.imap;
    imap->transfer = FTPTRANSFER_INFO;
  }

  *dophase_done = FALSE; 

  
  result = imap_select(conn);
  if(result)
    return result;

  
  if(conn->data->state.used_interface == Curl_if_multi)
    result = imap_multi_statemach(conn, dophase_done);
  else {
    result = imap_easy_statemach(conn);
    *dophase_done = TRUE; 
  }
  *connected = conn->bits.tcpconnect[FIRSTSOCKET];

  if(*dophase_done)
    DEBUGF(infof(conn->data, "DO phase is complete\n"));

  return result;
}


static CURLcode imap_do(struct connectdata *conn, bool *done)
{
  CURLcode retcode = CURLE_OK;

  *done = FALSE; 

  
  Curl_reset_reqproto(conn);
  retcode = imap_init(conn);
  if(retcode)
    return retcode;

  retcode = imap_parse_url_path(conn);
  if(retcode)
    return retcode;

  retcode = imap_regular_transfer(conn, done);

  return retcode;
}


static CURLcode imap_logout(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  const char *str;

  str = getcmdid(conn);

  result = imapsendf(conn, str, "%s LOGOUT", str, NULL);
  if(result)
    return result;
  state(conn, IMAP_LOGOUT);

  result = imap_easy_statemach(conn);

  return result;
}


static CURLcode imap_disconnect(struct connectdata *conn, bool dead_connection)
{
  struct imap_conn *imapc= &conn->proto.imapc;

  
  if(!dead_connection && imapc->pp.conn)
    (void)imap_logout(conn); 

  Curl_pp_disconnect(&imapc->pp);

  Curl_safefree(imapc->mailbox);

  return CURLE_OK;
}


static CURLcode imap_parse_url_path(struct connectdata *conn)
{
  
  struct imap_conn *imapc = &conn->proto.imapc;
  struct SessionHandle *data = conn->data;
  const char *path = data->state.path;
  int len;

  if(!*path)
    path = "INBOX";

  
  imapc->mailbox = curl_easy_unescape(data, path, 0, &len);
  if(!imapc->mailbox)
    return CURLE_OUT_OF_MEMORY;

  return CURLE_OK;
}


static CURLcode imap_dophase_done(struct connectdata *conn, bool connected)
{
  struct FTP *imap = conn->data->state.proto.imap;
  (void)connected;

  if(imap->transfer != FTPTRANSFER_BODY)
    
    Curl_setup_transfer(conn, -1, -1, FALSE, NULL, -1, NULL);

  return CURLE_OK;
}


static CURLcode imap_doing(struct connectdata *conn, bool *dophase_done)
{
  CURLcode result;
  result = imap_multi_statemach(conn, dophase_done);

  if(*dophase_done) {
    result = imap_dophase_done(conn, FALSE );

    DEBUGF(infof(conn->data, "DO phase is complete\n"));
  }
  return result;
}


static CURLcode imap_regular_transfer(struct connectdata *conn, bool *dophase_done)

{
  CURLcode result=CURLE_OK;
  bool connected=FALSE;
  struct SessionHandle *data = conn->data;
  data->req.size = -1; 

  Curl_pgrsSetUploadCounter(data, 0);
  Curl_pgrsSetDownloadCounter(data, 0);
  Curl_pgrsSetUploadSize(data, 0);
  Curl_pgrsSetDownloadSize(data, 0);

  result = imap_perform(conn, &connected, dophase_done);


  if(CURLE_OK == result) {

    if(!*dophase_done)
      
      return CURLE_OK;

    result = imap_dophase_done(conn, connected);
    if(result)
      return result;
  }

  return result;
}

static CURLcode imap_setup_connection(struct connectdata * conn)
{
  struct SessionHandle *data = conn->data;

  if(conn->bits.httpproxy && !data->set.tunnel_thru_httpproxy) {
    

    if(conn->handler == &Curl_handler_imap)
      conn->handler = &Curl_handler_imap_proxy;
    else {

      conn->handler = &Curl_handler_imaps_proxy;

      failf(data, "IMAPS not supported!");
      return CURLE_UNSUPPORTED_PROTOCOL;

    }
    
    conn->bits.close = FALSE;

    failf(data, "IMAP over http proxy requires HTTP support built-in!");
    return CURLE_UNSUPPORTED_PROTOCOL;

  }

  data->state.path++;   

  return CURLE_OK;
}


