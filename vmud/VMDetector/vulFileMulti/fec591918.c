













































































static void _state(struct connectdata *conn, ftpstate newstate);


static void _state(struct connectdata *conn, ftpstate newstate, int lineno);




static CURLcode ftp_sendquote(struct connectdata *conn, struct curl_slist *quote);
static CURLcode ftp_quit(struct connectdata *conn);
static CURLcode ftp_parse_url_path(struct connectdata *conn);
static CURLcode ftp_regular_transfer(struct connectdata *conn, bool *done);

static void ftp_pasv_verbose(struct connectdata *conn, Curl_addrinfo *ai, char *newhost, int port);



static CURLcode ftp_state_prepare_transfer(struct connectdata *conn);
static CURLcode ftp_state_mdtm(struct connectdata *conn);
static CURLcode ftp_state_quote(struct connectdata *conn, bool init, ftpstate instate);
static CURLcode ftp_nb_type(struct connectdata *conn, bool ascii, ftpstate newstate);
static int ftp_need_type(struct connectdata *conn, bool ascii);
static CURLcode ftp_do(struct connectdata *conn, bool *done);
static CURLcode ftp_done(struct connectdata *conn, CURLcode, bool premature);
static CURLcode ftp_connect(struct connectdata *conn, bool *done);
static CURLcode ftp_disconnect(struct connectdata *conn, bool dead_connection);
static CURLcode ftp_do_more(struct connectdata *conn, int *completed);
static CURLcode ftp_multi_statemach(struct connectdata *conn, bool *done);
static int ftp_getsock(struct connectdata *conn, curl_socket_t *socks, int numsocks);
static int ftp_domore_getsock(struct connectdata *conn, curl_socket_t *socks, int numsocks);
static CURLcode ftp_doing(struct connectdata *conn, bool *dophase_done);
static CURLcode ftp_setup_connection(struct connectdata * conn);

static CURLcode init_wc_data(struct connectdata *conn);
static CURLcode wc_statemach(struct connectdata *conn);

static void wc_data_dtor(void *ptr);

static CURLcode ftp_state_retr(struct connectdata *conn, curl_off_t filesize);

static CURLcode ftp_readresp(curl_socket_t sockfd, struct pingpong *pp, int *ftpcode, size_t *size);


static CURLcode ftp_dophase_done(struct connectdata *conn, bool connected);








const struct Curl_handler Curl_handler_ftp = {
  "FTP",                            ftp_setup_connection, ftp_do, ftp_done, ftp_do_more, ftp_connect, ftp_multi_statemach, ftp_doing, ftp_getsock, ftp_getsock, ftp_domore_getsock, ZERO_NULL, ftp_disconnect, ZERO_NULL, ZERO_NULL, PORT_FTP, CURLPROTO_FTP, PROTOPT_DUAL | PROTOPT_CLOSEACTION | PROTOPT_NEEDSPWD | PROTOPT_NOURLQUERY | PROTOPT_PROXY_AS_HTTP | PROTOPT_WILDCARD };
























const struct Curl_handler Curl_handler_ftps = {
  "FTPS",                           ftp_setup_connection, ftp_do, ftp_done, ftp_do_more, ftp_connect, ftp_multi_statemach, ftp_doing, ftp_getsock, ftp_getsock, ftp_domore_getsock, ZERO_NULL, ftp_disconnect, ZERO_NULL, ZERO_NULL, PORT_FTPS, CURLPROTO_FTPS, PROTOPT_SSL | PROTOPT_DUAL | PROTOPT_CLOSEACTION | PROTOPT_NEEDSPWD | PROTOPT_NOURLQUERY | PROTOPT_WILDCARD };




















static void close_secondarysocket(struct connectdata *conn)
{
  if(CURL_SOCKET_BAD != conn->sock[SECONDARYSOCKET]) {
    Curl_closesocket(conn, conn->sock[SECONDARYSOCKET]);
    conn->sock[SECONDARYSOCKET] = CURL_SOCKET_BAD;
  }
  conn->bits.tcpconnect[SECONDARYSOCKET] = FALSE;
}




static void freedirs(struct ftp_conn *ftpc)
{
  int i;
  if(ftpc->dirs) {
    for(i = 0; i < ftpc->dirdepth; i++) {
      free(ftpc->dirs[i]);
      ftpc->dirs[i] = NULL;
    }
    free(ftpc->dirs);
    ftpc->dirs = NULL;
    ftpc->dirdepth = 0;
  }
  Curl_safefree(ftpc->file);

  
  Curl_safefree(ftpc->newhost);
}


static bool isBadFtpString(const char *string)
{
  return ((NULL != strchr(string, '\r')) || (NULL != strchr(string, '\n'))) ? TRUE : FALSE;
}


static CURLcode AcceptServerConnect(struct connectdata *conn)
{
  struct Curl_easy *data = conn->data;
  curl_socket_t sock = conn->sock[SECONDARYSOCKET];
  curl_socket_t s = CURL_SOCKET_BAD;

  struct Curl_sockaddr_storage add;

  struct sockaddr_in add;

  curl_socklen_t size = (curl_socklen_t) sizeof(add);

  if(0 == getsockname(sock, (struct sockaddr *) &add, &size)) {
    size = sizeof(add);

    s = accept(sock, (struct sockaddr *) &add, &size);
  }
  Curl_closesocket(conn, sock); 

  if(CURL_SOCKET_BAD == s) {
    failf(data, "Error accept()ing server connect");
    return CURLE_FTP_PORT_FAILED;
  }
  infof(data, "Connection accepted from server\n");
  
  conn->bits.do_more = FALSE;

  conn->sock[SECONDARYSOCKET] = s;
  (void)curlx_nonblock(s, TRUE); 
  conn->sock_accepted[SECONDARYSOCKET] = TRUE;

  if(data->set.fsockopt) {
    int error = 0;

    
    Curl_set_in_callback(data, true);
    error = data->set.fsockopt(data->set.sockopt_client, s, CURLSOCKTYPE_ACCEPT);

    Curl_set_in_callback(data, false);

    if(error) {
      close_secondarysocket(conn);
      return CURLE_ABORTED_BY_CALLBACK;
    }
  }

  return CURLE_OK;

}


static timediff_t ftp_timeleft_accept(struct Curl_easy *data)
{
  timediff_t timeout_ms = DEFAULT_ACCEPT_TIMEOUT;
  timediff_t other;
  struct curltime now;

  if(data->set.accepttimeout > 0)
    timeout_ms = data->set.accepttimeout;

  now = Curl_now();

  
  other =  Curl_timeleft(data, &now, FALSE);
  if(other && (other < timeout_ms))
    
    timeout_ms = other;
  else {
    
    timeout_ms -= Curl_timediff(now, data->progress.t_acceptdata);
    if(!timeout_ms)
      
      return -1;
  }

  return timeout_ms;
}



static CURLcode ReceivedServerConnect(struct connectdata *conn, bool *received)
{
  struct Curl_easy *data = conn->data;
  curl_socket_t ctrl_sock = conn->sock[FIRSTSOCKET];
  curl_socket_t data_sock = conn->sock[SECONDARYSOCKET];
  struct ftp_conn *ftpc = &conn->proto.ftpc;
  struct pingpong *pp = &ftpc->pp;
  int result;
  time_t timeout_ms;
  ssize_t nread;
  int ftpcode;

  *received = FALSE;

  timeout_ms = ftp_timeleft_accept(data);
  infof(data, "Checking for server connect\n");
  if(timeout_ms < 0) {
    
    failf(data, "Accept timeout occurred while waiting server connect");
    return CURLE_FTP_ACCEPT_TIMEOUT;
  }

  
  if(pp->cache_size && pp->cache && pp->cache[0] > '3') {
    
    infof(data, "There is negative response in cache while serv connect\n");
    Curl_GetFTPResponse(&nread, conn, &ftpcode);
    return CURLE_FTP_ACCEPT_FAILED;
  }

  result = Curl_socket_check(ctrl_sock, data_sock, CURL_SOCKET_BAD, 0);

  
  switch(result) {
  case -1: 
    
    failf(data, "Error while waiting for server connect");
    return CURLE_FTP_ACCEPT_FAILED;
  case 0:  
    break; 
  default:

    if(result & CURL_CSELECT_IN2) {
      infof(data, "Ready to accept data connection from server\n");
      *received = TRUE;
    }
    else if(result & CURL_CSELECT_IN) {
      infof(data, "Ctrl conn has data while waiting for data conn\n");
      Curl_GetFTPResponse(&nread, conn, &ftpcode);

      if(ftpcode/100 > 3)
        return CURLE_FTP_ACCEPT_FAILED;

      return CURLE_WEIRD_SERVER_REPLY;
    }

    break;
  } 

  return CURLE_OK;
}



static CURLcode InitiateTransfer(struct connectdata *conn)
{
  struct Curl_easy *data = conn->data;
  struct FTP *ftp = data->req.protop;
  CURLcode result = CURLE_OK;

  if(conn->bits.ftp_use_data_ssl) {
    
    infof(data, "Doing the SSL/TLS handshake on the data stream\n");
    result = Curl_ssl_connect(conn, SECONDARYSOCKET);
    if(result)
      return result;
  }

  if(conn->proto.ftpc.state_saved == FTP_STOR) {
    *(ftp->bytecountp) = 0;

    

    Curl_pgrsSetUploadSize(data, data->state.infilesize);

    
    Curl_sndbufset(conn->sock[SECONDARYSOCKET]);

    Curl_setup_transfer(conn, -1, -1, FALSE, NULL,  SECONDARYSOCKET, ftp->bytecountp);
  }
  else {
    
    Curl_setup_transfer(conn, SECONDARYSOCKET, conn->proto.ftpc.retr_size_saved, FALSE, ftp->bytecountp, -1, NULL);

  }

  conn->proto.ftpc.pp.pending_resp = TRUE; 
  state(conn, FTP_STOP);

  return CURLE_OK;
}


static CURLcode AllowServerConnect(struct connectdata *conn, bool *connected)
{
  struct Curl_easy *data = conn->data;
  time_t timeout_ms;
  CURLcode result = CURLE_OK;

  *connected = FALSE;
  infof(data, "Preparing for accepting server on data port\n");

  
  Curl_pgrsTime(data, TIMER_STARTACCEPT);

  timeout_ms = ftp_timeleft_accept(data);
  if(timeout_ms < 0) {
    
    failf(data, "Accept timeout occurred while waiting server connect");
    return CURLE_FTP_ACCEPT_TIMEOUT;
  }

  
  result = ReceivedServerConnect(conn, connected);
  if(result)
    return result;

  if(*connected) {
    result = AcceptServerConnect(conn);
    if(result)
      return result;

    result = InitiateTransfer(conn);
    if(result)
      return result;
  }
  else {
    
    if(!result && *connected == FALSE) {
      Curl_expire(data, data->set.accepttimeout > 0 ? data->set.accepttimeout: DEFAULT_ACCEPT_TIMEOUT, 0);
    }
  }

  return result;
}







static bool ftp_endofresp(struct connectdata *conn, char *line, size_t len, int *code)
{
  (void)conn;

  if((len > 3) && LASTLINE(line)) {
    *code = curlx_sltosi(strtol(line, NULL, 10));
    return TRUE;
  }

  return FALSE;
}

static CURLcode ftp_readresp(curl_socket_t sockfd, struct pingpong *pp, int *ftpcode, size_t *size)


{
  struct connectdata *conn = pp->conn;
  struct Curl_easy *data = conn->data;

  char * const buf = data->state.buffer;

  CURLcode result = CURLE_OK;
  int code;

  result = Curl_pp_readresp(sockfd, pp, &code, size);


  
  
  switch(code) {
  case 631:
    code = Curl_sec_read_msg(conn, buf, PROT_SAFE);
    break;
  case 632:
    code = Curl_sec_read_msg(conn, buf, PROT_PRIVATE);
    break;
  case 633:
    code = Curl_sec_read_msg(conn, buf, PROT_CONFIDENTIAL);
    break;
  default:
    
    break;
  }


  
  data->info.httpcode = code;

  if(ftpcode)
    *ftpcode = code;

  if(421 == code) {
    
    infof(data, "We got a 421 - timeout!\n");
    state(conn, FTP_STOP);
    return CURLE_OPERATION_TIMEDOUT;
  }

  return result;
}





CURLcode Curl_GetFTPResponse(ssize_t *nreadp,  struct connectdata *conn, int *ftpcode)

{
  

  curl_socket_t sockfd = conn->sock[FIRSTSOCKET];
  time_t timeout;              
  time_t interval_ms;
  struct Curl_easy *data = conn->data;
  CURLcode result = CURLE_OK;
  struct ftp_conn *ftpc = &conn->proto.ftpc;
  struct pingpong *pp = &ftpc->pp;
  size_t nread;
  int cache_skip = 0;
  int value_to_be_ignored = 0;

  if(ftpcode)
    *ftpcode = 0; 
  else  ftpcode = &value_to_be_ignored;


  *nreadp = 0;

  while(!*ftpcode && !result) {
    
    timeout = Curl_pp_state_timeout(pp);

    if(timeout <= 0) {
      failf(data, "FTP response timeout");
      return CURLE_OPERATION_TIMEDOUT; 
    }

    interval_ms = 1000;  
    if(timeout < interval_ms)
      interval_ms = timeout;

    

    if(pp->cache && (cache_skip < 2)) {
      
    }
    else if(!Curl_conn_data_pending(conn, FIRSTSOCKET)) {
      switch(SOCKET_READABLE(sockfd, interval_ms)) {
      case -1: 
        failf(data, "FTP response aborted due to select/poll error: %d", SOCKERRNO);
        return CURLE_RECV_ERROR;

      case 0: 
        if(Curl_pgrsUpdate(conn))
          return CURLE_ABORTED_BY_CALLBACK;
        continue; 

      default: 
        break;
      }
    }
    result = ftp_readresp(sockfd, pp, ftpcode, &nread);
    if(result)
      break;

    if(!nread && pp->cache)
      
      cache_skip++;
    else  cache_skip = 0;


    *nreadp += nread;

  } 

  pp->pending_resp = FALSE;

  return result;
}


  
static const char * const ftp_state_names[]={
  "STOP", "WAIT220", "AUTH", "USER", "PASS", "ACCT", "PBSZ", "PROT", "CCC", "PWD", "SYST", "NAMEFMT", "QUOTE", "RETR_PREQUOTE", "STOR_PREQUOTE", "POSTQUOTE", "CWD", "MKD", "MDTM", "TYPE", "LIST_TYPE", "RETR_TYPE", "STOR_TYPE", "SIZE", "RETR_SIZE", "STOR_SIZE", "REST", "RETR_REST", "PORT", "PRET", "PASV", "LIST", "RETR", "STOR", "QUIT" };





































static void _state(struct connectdata *conn, ftpstate newstate  , int lineno  )




{
  struct ftp_conn *ftpc = &conn->proto.ftpc;




  (void) lineno;

  if(ftpc->state != newstate)
    infof(conn->data, "FTP %p (line %d) state change from %s to %s\n", (void *)ftpc, lineno, ftp_state_names[ftpc->state], ftp_state_names[newstate]);




  ftpc->state = newstate;
}

static CURLcode ftp_state_user(struct connectdata *conn)
{
  CURLcode result;
  struct FTP *ftp = conn->data->req.protop;
  
  PPSENDF(&conn->proto.ftpc.pp, "USER %s", ftp->user?ftp->user:"");

  state(conn, FTP_USER);
  conn->data->state.ftp_trying_alternative = FALSE;

  return CURLE_OK;
}

static CURLcode ftp_state_pwd(struct connectdata *conn)
{
  CURLcode result;

  
  PPSENDF(&conn->proto.ftpc.pp, "%s", "PWD");
  state(conn, FTP_PWD);

  return CURLE_OK;
}


static int ftp_getsock(struct connectdata *conn, curl_socket_t *socks, int numsocks)

{
  return Curl_pp_getsock(&conn->proto.ftpc.pp, socks, numsocks);
}


static int ftp_domore_getsock(struct connectdata *conn, curl_socket_t *socks, int numsocks)
{
  struct ftp_conn *ftpc = &conn->proto.ftpc;

  if(!numsocks)
    return GETSOCK_BLANK;

  

  if(FTP_STOP == ftpc->state) {
    int bits = GETSOCK_READSOCK(0);

    
    socks[0] = conn->sock[FIRSTSOCKET];

    if(!conn->data->set.ftp_use_port) {
      int s;
      int i;
      
      for(s = 1, i = 0; i<2; i++) {
        if(conn->tempsock[i] != CURL_SOCKET_BAD) {
          socks[s] = conn->tempsock[i];
          bits |= GETSOCK_WRITESOCK(s++);
        }
      }
    }
    else {
      socks[1] = conn->sock[SECONDARYSOCKET];
      bits |= GETSOCK_WRITESOCK(1) | GETSOCK_READSOCK(1);
    }

    return bits;
  }
  return Curl_pp_getsock(&conn->proto.ftpc.pp, socks, numsocks);
}


static CURLcode ftp_state_cwd(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct ftp_conn *ftpc = &conn->proto.ftpc;

  if(ftpc->cwddone)
    
    result = ftp_state_mdtm(conn);
  else {
    ftpc->count2 = 0; 

    
    ftpc->count3 = (conn->data->set.ftp_create_missing_dirs == 2)?1:0;

    if((conn->data->set.ftp_filemethod == FTPFILE_NOCWD) && !ftpc->cwdcount)
      
      result = ftp_state_mdtm(conn);
    else if(conn->bits.reuse && ftpc->entrypath) {
      
      ftpc->cwdcount = 0; 
      PPSENDF(&conn->proto.ftpc.pp, "CWD %s", ftpc->entrypath);
      state(conn, FTP_CWD);
    }
    else {
      if(ftpc->dirdepth) {
        ftpc->cwdcount = 1;
        
        PPSENDF(&conn->proto.ftpc.pp, "CWD %s", ftpc->dirs[ftpc->cwdcount -1]);
        state(conn, FTP_CWD);
      }
      else {
        
        result = ftp_state_mdtm(conn);
      }
    }
  }
  return result;
}

typedef enum {
  EPRT, PORT, DONE } ftpport;



static CURLcode ftp_state_use_port(struct connectdata *conn, ftpport fcmd)

{
  CURLcode result = CURLE_OK;
  struct ftp_conn *ftpc = &conn->proto.ftpc;
  struct Curl_easy *data = conn->data;
  curl_socket_t portsock = CURL_SOCKET_BAD;
  char myhost[256] = "";

  struct Curl_sockaddr_storage ss;
  Curl_addrinfo *res, *ai;
  curl_socklen_t sslen;
  char hbuf[NI_MAXHOST];
  struct sockaddr *sa = (struct sockaddr *)&ss;
  struct sockaddr_in * const sa4 = (void *)sa;

  struct sockaddr_in6 * const sa6 = (void *)sa;

  char tmp[1024];
  static const char mode[][5] = { "EPRT", "PORT" };
  int rc;
  int error;
  char *host = NULL;
  char *string_ftpport = data->set.str[STRING_FTPPORT];
  struct Curl_dns_entry *h = NULL;
  unsigned short port_min = 0;
  unsigned short port_max = 0;
  unsigned short port;
  bool possibly_non_local = TRUE;

  char *addr = NULL;

  

  if(data->set.str[STRING_FTPPORT] && (strlen(data->set.str[STRING_FTPPORT]) > 1)) {


    size_t addrlen = INET6_ADDRSTRLEN > strlen(string_ftpport) ? INET6_ADDRSTRLEN : strlen(string_ftpport);

    size_t addrlen = INET_ADDRSTRLEN > strlen(string_ftpport) ? INET_ADDRSTRLEN : strlen(string_ftpport);

    char *ip_start = string_ftpport;
    char *ip_end = NULL;
    char *port_start = NULL;
    char *port_sep = NULL;

    addr = calloc(addrlen + 1, 1);
    if(!addr)
      return CURLE_OUT_OF_MEMORY;


    if(*string_ftpport == '[') {
      
      ip_start = string_ftpport + 1;
      ip_end = strchr(string_ftpport, ']');
      if(ip_end)
        strncpy(addr, ip_start, ip_end - ip_start);
    }
    else  if(*string_ftpport == ':') {

        
        ip_end = string_ftpport;
      }
      else {
        ip_end = strchr(string_ftpport, ':');
        if(ip_end) {
          

          if(Curl_inet_pton(AF_INET6, string_ftpport, sa6) == 1) {
            
            port_min = port_max = 0;
            strcpy(addr, string_ftpport);
            ip_end = NULL; 
          }
          else   strncpy(addr, string_ftpport, ip_end - ip_start);


        }
        else  strcpy(addr, string_ftpport);

      }

    
    if(ip_end != NULL) {
      port_start = strchr(ip_end, ':');
      if(port_start) {
        port_min = curlx_ultous(strtoul(port_start + 1, NULL, 10));
        port_sep = strchr(port_start, '-');
        if(port_sep) {
          port_max = curlx_ultous(strtoul(port_sep + 1, NULL, 10));
        }
        else port_max = port_min;
      }
    }

    
    if(port_min > port_max)
      port_min = port_max = 0;


    if(*addr != '\0') {
      
      switch(Curl_if2ip(conn->ip_addr->ai_family, Curl_ipv6_scope(conn->ip_addr->ai_addr), conn->scope_id, addr, hbuf, sizeof(hbuf))) {

        case IF2IP_NOT_FOUND:
          
          host = addr;
          break;
        case IF2IP_AF_NOT_SUPPORTED:
          return CURLE_FTP_PORT_FAILED;
        case IF2IP_FOUND:
          host = hbuf; 
      }
    }
    else  host = NULL;

  } 

  if(!host) {
    

    sslen = sizeof(ss);
    if(getsockname(conn->sock[FIRSTSOCKET], sa, &sslen)) {
      failf(data, "getsockname() failed: %s", Curl_strerror(conn, SOCKERRNO) );
      free(addr);
      return CURLE_FTP_PORT_FAILED;
    }
    switch(sa->sa_family) {

    case AF_INET6:
      Curl_inet_ntop(sa->sa_family, &sa6->sin6_addr, hbuf, sizeof(hbuf));
      break;

    default:
      Curl_inet_ntop(sa->sa_family, &sa4->sin_addr, hbuf, sizeof(hbuf));
      break;
    }
    host = hbuf; 
    possibly_non_local = FALSE; 
  }

  
  rc = Curl_resolv(conn, host, 0, &h);
  if(rc == CURLRESOLV_PENDING)
    (void)Curl_resolver_wait_resolv(conn, &h);
  if(h) {
    res = h->addr;
    
    Curl_resolv_unlock(data, h);
  } 
  else res = NULL;

  if(res == NULL) {
    failf(data, "failed to resolve the address provided to PORT: %s", host);
    free(addr);
    return CURLE_FTP_PORT_FAILED;
  }

  free(addr);
  host = NULL;

  

  portsock = CURL_SOCKET_BAD;
  error = 0;
  for(ai = res; ai; ai = ai->ai_next) {
    result = Curl_socket(conn, ai, NULL, &portsock);
    if(result) {
      error = SOCKERRNO;
      continue;
    }
    break;
  }
  if(!ai) {
    failf(data, "socket failure: %s", Curl_strerror(conn, error));
    return CURLE_FTP_PORT_FAILED;
  }

  

  memcpy(sa, ai->ai_addr, ai->ai_addrlen);
  sslen = ai->ai_addrlen;

  for(port = port_min; port <= port_max;) {
    if(sa->sa_family == AF_INET)
      sa4->sin_port = htons(port);

    else sa6->sin6_port = htons(port);

    
    if(bind(portsock, sa, sslen) ) {
      
      error = SOCKERRNO;
      if(possibly_non_local && (error == EADDRNOTAVAIL)) {
        

        infof(data, "bind(port=%hu) on non-local address failed: %s\n", port, Curl_strerror(conn, error) );

        sslen = sizeof(ss);
        if(getsockname(conn->sock[FIRSTSOCKET], sa, &sslen)) {
          failf(data, "getsockname() failed: %s", Curl_strerror(conn, SOCKERRNO) );
          Curl_closesocket(conn, portsock);
          return CURLE_FTP_PORT_FAILED;
        }
        port = port_min;
        possibly_non_local = FALSE; 
        continue;
      }
      if(error != EADDRINUSE && error != EACCES) {
        failf(data, "bind(port=%hu) failed: %s", port, Curl_strerror(conn, error) );
        Curl_closesocket(conn, portsock);
        return CURLE_FTP_PORT_FAILED;
      }
    }
    else break;

    port++;
  }

  
  if(port > port_max) {
    failf(data, "bind() failed, we ran out of ports!");
    Curl_closesocket(conn, portsock);
    return CURLE_FTP_PORT_FAILED;
  }

  
  sslen = sizeof(ss);
  if(getsockname(portsock, (struct sockaddr *)sa, &sslen)) {
    failf(data, "getsockname() failed: %s", Curl_strerror(conn, SOCKERRNO) );
    Curl_closesocket(conn, portsock);
    return CURLE_FTP_PORT_FAILED;
  }

  

  if(listen(portsock, 1)) {
    failf(data, "socket failure: %s", Curl_strerror(conn, SOCKERRNO));
    Curl_closesocket(conn, portsock);
    return CURLE_FTP_PORT_FAILED;
  }

  

  
  Curl_printable_address(ai, myhost, sizeof(myhost));


  if(!conn->bits.ftp_use_eprt && conn->bits.ipv6)
    
    conn->bits.ftp_use_eprt = TRUE;


  for(; fcmd != DONE; fcmd++) {

    if(!conn->bits.ftp_use_eprt && (EPRT == fcmd))
      
      continue;

    if((PORT == fcmd) && sa->sa_family != AF_INET)
      
      continue;

    switch(sa->sa_family) {
    case AF_INET:
      port = ntohs(sa4->sin_port);
      break;

    case AF_INET6:
      port = ntohs(sa6->sin6_port);
      break;

    default:
      continue; 
    }

    if(EPRT == fcmd) {
      

      result = Curl_pp_sendf(&ftpc->pp, "%s |%d|%s|%hu|", mode[fcmd], sa->sa_family == AF_INET?1:2, myhost, port);

      if(result) {
        failf(data, "Failure sending EPRT command: %s", curl_easy_strerror(result));
        Curl_closesocket(conn, portsock);
        
        ftpc->count1 = PORT;
        
        state(conn, FTP_STOP);
        return result;
      }
      break;
    }
    if(PORT == fcmd) {
      char *source = myhost;
      char *dest = tmp;

      
      while(source && *source) {
        if(*source == '.')
          *dest = ',';
        else *dest = *source;
        dest++;
        source++;
      }
      *dest = 0;
      snprintf(dest, 20, ",%d,%d", (int)(port>>8), (int)(port&0xff));

      result = Curl_pp_sendf(&ftpc->pp, "%s %s", mode[fcmd], tmp);
      if(result) {
        failf(data, "Failure sending PORT command: %s", curl_easy_strerror(result));
        Curl_closesocket(conn, portsock);
        
        state(conn, FTP_STOP);
        return result;
      }
      break;
    }
  }

  
  ftpc->count1 = fcmd;

  close_secondarysocket(conn);

  
  conn->sock[SECONDARYSOCKET] = portsock;

  
  conn->bits.tcpconnect[SECONDARYSOCKET] = TRUE;

  state(conn, FTP_PORT);
  return result;
}

static CURLcode ftp_state_use_pasv(struct connectdata *conn)
{
  struct ftp_conn *ftpc = &conn->proto.ftpc;
  CURLcode result = CURLE_OK;
  

  static const char mode[][5] = { "EPSV", "PASV" };
  int modeoff;


  if(!conn->bits.ftp_use_epsv && conn->bits.ipv6)
    
    conn->bits.ftp_use_epsv = TRUE;


  modeoff = conn->bits.ftp_use_epsv?0:1;

  PPSENDF(&ftpc->pp, "%s", mode[modeoff]);

  ftpc->count1 = modeoff;
  state(conn, FTP_PASV);
  infof(conn->data, "Connect data stream passively\n");

  return result;
}


static CURLcode ftp_state_prepare_transfer(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct FTP *ftp = conn->data->req.protop;
  struct Curl_easy *data = conn->data;

  if(ftp->transfer != FTPTRANSFER_BODY) {
    

    
    state(conn, FTP_RETR_PREQUOTE);
    result = ftp_state_quote(conn, TRUE, FTP_RETR_PREQUOTE);
  }
  else if(data->set.ftp_use_port) {
    
    result = ftp_state_use_port(conn, EPRT);
  }
  else {
    
    if(data->set.ftp_use_pret) {
      
      if(!conn->proto.ftpc.file) {
        PPSENDF(&conn->proto.ftpc.pp, "PRET %s", data->set.str[STRING_CUSTOMREQUEST]? data->set.str[STRING_CUSTOMREQUEST]:

                (data->set.ftp_list_only?"NLST":"LIST"));
      }
      else if(data->set.upload) {
        PPSENDF(&conn->proto.ftpc.pp, "PRET STOR %s", conn->proto.ftpc.file);
      }
      else {
        PPSENDF(&conn->proto.ftpc.pp, "PRET RETR %s", conn->proto.ftpc.file);
      }
      state(conn, FTP_PRET);
    }
    else {
      result = ftp_state_use_pasv(conn);
    }
  }
  return result;
}

static CURLcode ftp_state_rest(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct FTP *ftp = conn->data->req.protop;
  struct ftp_conn *ftpc = &conn->proto.ftpc;

  if((ftp->transfer != FTPTRANSFER_BODY) && ftpc->file) {
    

    
    PPSENDF(&conn->proto.ftpc.pp, "REST %d", 0);

    state(conn, FTP_REST);
  }
  else result = ftp_state_prepare_transfer(conn);

  return result;
}

static CURLcode ftp_state_size(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct FTP *ftp = conn->data->req.protop;
  struct ftp_conn *ftpc = &conn->proto.ftpc;

  if((ftp->transfer == FTPTRANSFER_INFO) && ftpc->file) {
    

    
    PPSENDF(&ftpc->pp, "SIZE %s", ftpc->file);

    state(conn, FTP_SIZE);
  }
  else result = ftp_state_rest(conn);

  return result;
}

static CURLcode ftp_state_list(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct Curl_easy *data = conn->data;

  

  
  char *cmd, *lstArg, *slashPos;
  const char *inpath = data->state.path;

  lstArg = NULL;
  if((data->set.ftp_filemethod == FTPFILE_NOCWD) && inpath && inpath[0] && strchr(inpath, '/')) {
    size_t n = strlen(inpath);

    
    if(inpath[n - 1] != '/') {
      
      slashPos = strrchr(inpath, '/');
      n = slashPos - inpath;
    }
    result = Curl_urldecode(data, inpath, n, &lstArg, NULL, FALSE);
    if(result)
      return result;
  }

  cmd = aprintf("%s%s%s", data->set.str[STRING_CUSTOMREQUEST]? data->set.str[STRING_CUSTOMREQUEST]:

                (data->set.ftp_list_only?"NLST":"LIST"), lstArg? " ": "", lstArg? lstArg: "");


  if(!cmd) {
    free(lstArg);
    return CURLE_OUT_OF_MEMORY;
  }

  result = Curl_pp_sendf(&conn->proto.ftpc.pp, "%s", cmd);

  free(lstArg);
  free(cmd);

  if(result)
    return result;

  state(conn, FTP_LIST);

  return result;
}

static CURLcode ftp_state_retr_prequote(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;

  

  result = ftp_state_quote(conn, TRUE, FTP_RETR_PREQUOTE);

  return result;
}

static CURLcode ftp_state_stor_prequote(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;

  

  result = ftp_state_quote(conn, TRUE, FTP_STOR_PREQUOTE);

  return result;
}

static CURLcode ftp_state_type(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct FTP *ftp = conn->data->req.protop;
  struct Curl_easy *data = conn->data;
  struct ftp_conn *ftpc = &conn->proto.ftpc;

  
  if(data->set.opt_no_body && ftpc->file && ftp_need_type(conn, data->set.prefer_ascii)) {
    

    ftp->transfer = FTPTRANSFER_INFO;
    

    
    result = ftp_nb_type(conn, data->set.prefer_ascii, FTP_TYPE);
    if(result)
      return result;
  }
  else result = ftp_state_size(conn);

  return result;
}


static CURLcode ftp_state_mdtm(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct Curl_easy *data = conn->data;
  struct ftp_conn *ftpc = &conn->proto.ftpc;

  
  if((data->set.get_filetime || data->set.timecondition) && ftpc->file) {

    
    PPSENDF(&ftpc->pp, "MDTM %s", ftpc->file);

    state(conn, FTP_MDTM);
  }
  else result = ftp_state_type(conn);

  return result;
}



static CURLcode ftp_state_ul_setup(struct connectdata *conn, bool sizechecked)
{
  CURLcode result = CURLE_OK;
  struct FTP *ftp = conn->data->req.protop;
  struct Curl_easy *data = conn->data;
  struct ftp_conn *ftpc = &conn->proto.ftpc;
  int seekerr = CURL_SEEKFUNC_OK;

  if((data->state.resume_from && !sizechecked) || ((data->state.resume_from > 0) && sizechecked)) {
    
    

    

    
    
    

    if(data->state.resume_from < 0) {
      
      PPSENDF(&ftpc->pp, "SIZE %s", ftpc->file);
      state(conn, FTP_STOR_SIZE);
      return result;
    }

    
    data->set.ftp_append = TRUE;

    
    if(conn->seek_func) {
      Curl_set_in_callback(data, true);
      seekerr = conn->seek_func(conn->seek_client, data->state.resume_from, SEEK_SET);
      Curl_set_in_callback(data, true);
    }

    if(seekerr != CURL_SEEKFUNC_OK) {
      curl_off_t passed = 0;
      if(seekerr != CURL_SEEKFUNC_CANTSEEK) {
        failf(data, "Could not seek stream");
        return CURLE_FTP_COULDNT_USE_REST;
      }
      
      do {
        size_t readthisamountnow = (data->state.resume_from - passed > data->set.buffer_size) ? (size_t)data->set.buffer_size :

          curlx_sotouz(data->state.resume_from - passed);

        size_t actuallyread = data->state.fread_func(data->state.buffer, 1, readthisamountnow, data->state.in);


        passed += actuallyread;
        if((actuallyread == 0) || (actuallyread > readthisamountnow)) {
          
          failf(data, "Failed to read data");
          return CURLE_FTP_COULDNT_USE_REST;
        }
      } while(passed < data->state.resume_from);
    }
    
    if(data->state.infilesize>0) {
      data->state.infilesize -= data->state.resume_from;

      if(data->state.infilesize <= 0) {
        infof(data, "File already completely uploaded\n");

        
        Curl_setup_transfer(conn, -1, -1, FALSE, NULL, -1, NULL);

        
        ftp->transfer = FTPTRANSFER_NONE;

        state(conn, FTP_STOP);
        return CURLE_OK;
      }
    }
    
  } 

  PPSENDF(&ftpc->pp, data->set.ftp_append?"APPE %s":"STOR %s", ftpc->file);

  state(conn, FTP_STOR);

  return result;
}

static CURLcode ftp_state_quote(struct connectdata *conn, bool init, ftpstate instate)

{
  CURLcode result = CURLE_OK;
  struct Curl_easy *data = conn->data;
  struct FTP *ftp = data->req.protop;
  struct ftp_conn *ftpc = &conn->proto.ftpc;
  bool quote = FALSE;
  struct curl_slist *item;

  switch(instate) {
  case FTP_QUOTE:
  default:
    item = data->set.quote;
    break;
  case FTP_RETR_PREQUOTE:
  case FTP_STOR_PREQUOTE:
    item = data->set.prequote;
    break;
  case FTP_POSTQUOTE:
    item = data->set.postquote;
    break;
  }

  

  if(init)
    ftpc->count1 = 0;
  else ftpc->count1++;

  if(item) {
    int i = 0;

    
    while((i< ftpc->count1) && item) {
      item = item->next;
      i++;
    }
    if(item) {
      char *cmd = item->data;
      if(cmd[0] == '*') {
        cmd++;
        ftpc->count2 = 1; 
      }
      else ftpc->count2 = 0;

      PPSENDF(&ftpc->pp, "%s", cmd);
      state(conn, instate);
      quote = TRUE;
    }
  }

  if(!quote) {
    
    switch(instate) {
    case FTP_QUOTE:
    default:
      result = ftp_state_cwd(conn);
      break;
    case FTP_RETR_PREQUOTE:
      if(ftp->transfer != FTPTRANSFER_BODY)
        state(conn, FTP_STOP);
      else {
        if(ftpc->known_filesize != -1) {
          Curl_pgrsSetDownloadSize(data, ftpc->known_filesize);
          result = ftp_state_retr(conn, ftpc->known_filesize);
        }
        else {
          if(data->set.ignorecl) {
            
            PPSENDF(&ftpc->pp, "RETR %s", ftpc->file);
            state(conn, FTP_RETR);
          }
          else {
            PPSENDF(&ftpc->pp, "SIZE %s", ftpc->file);
            state(conn, FTP_RETR_SIZE);
          }
        }
      }
      break;
    case FTP_STOR_PREQUOTE:
      result = ftp_state_ul_setup(conn, FALSE);
      break;
    case FTP_POSTQUOTE:
      break;
    }
  }

  return result;
}


static CURLcode ftp_epsv_disable(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;

  if(conn->bits.ipv6) {
    
    failf(conn->data, "Failed EPSV attempt, exiting\n");
    return CURLE_WEIRD_SERVER_REPLY;
  }

  infof(conn->data, "Failed EPSV attempt. Disabling EPSV\n");
  
  conn->bits.ftp_use_epsv = FALSE;
  conn->data->state.errorbuf = FALSE; 
  PPSENDF(&conn->proto.ftpc.pp, "%s", "PASV");
  conn->proto.ftpc.count1++;
  
  state(conn, FTP_PASV);
  return result;
}


static char *control_address(struct connectdata *conn)
{
  
  if(conn->bits.tunnel_proxy || conn->bits.socksproxy)
    return conn->host.name;

  return conn->ip_addr_str;
}

static CURLcode ftp_state_pasv_resp(struct connectdata *conn, int ftpcode)
{
  struct ftp_conn *ftpc = &conn->proto.ftpc;
  CURLcode result;
  struct Curl_easy *data = conn->data;
  struct Curl_dns_entry *addr = NULL;
  int rc;
  unsigned short connectport; 
  char *str = &data->state.buffer[4];  

  
  Curl_safefree(ftpc->newhost);

  if((ftpc->count1 == 0) && (ftpcode == 229)) {
    
    char *ptr = strchr(str, '(');
    if(ptr) {
      unsigned int num;
      char separator[4];
      ptr++;
      if(5 == sscanf(ptr, "%c%c%c%u%c", &separator[0], &separator[1], &separator[2], &num, &separator[3])) {




        const char sep1 = separator[0];
        int i;

        
        for(i = 1; i<4; i++) {
          if(separator[i] != sep1) {
            ptr = NULL; 
            break;
          }
        }
        if(num > 0xffff) {
          failf(data, "Illegal port number in EPSV reply");
          return CURLE_FTP_WEIRD_PASV_REPLY;
        }
        if(ptr) {
          ftpc->newport = (unsigned short)(num & 0xffff);
          ftpc->newhost = strdup(control_address(conn));
          if(!ftpc->newhost)
            return CURLE_OUT_OF_MEMORY;
        }
      }
      else ptr = NULL;
    }
    if(!ptr) {
      failf(data, "Weirdly formatted EPSV reply");
      return CURLE_FTP_WEIRD_PASV_REPLY;
    }
  }
  else if((ftpc->count1 == 1) && (ftpcode == 227)) {
    
    unsigned int ip[4];
    unsigned int port[2];

    
    while(*str) {
      if(6 == sscanf(str, "%u,%u,%u,%u,%u,%u", &ip[0], &ip[1], &ip[2], &ip[3], &port[0], &port[1]))

        break;
      str++;
    }

    if(!*str || (ip[0] > 255) || (ip[1] > 255)  || (ip[2] > 255)  || (ip[3] > 255) || (port[0] > 255)  || (port[1] > 255) ) {
      failf(data, "Couldn't interpret the 227-response");
      return CURLE_FTP_WEIRD_227_FORMAT;
    }

    
    if(data->set.ftp_skip_ip) {
      
      infof(data, "Skip %d.%d.%d.%d for data connection, re-use %s instead\n", ip[0], ip[1], ip[2], ip[3], conn->host.name);

      ftpc->newhost = strdup(control_address(conn));
    }
    else ftpc->newhost = aprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);

    if(!ftpc->newhost)
      return CURLE_OUT_OF_MEMORY;

    ftpc->newport = (unsigned short)(((port[0]<<8) + port[1]) & 0xffff);
  }
  else if(ftpc->count1 == 0) {
    
    return ftp_epsv_disable(conn);
  }
  else {
    failf(data, "Bad PASV/EPSV response: %03d", ftpcode);
    return CURLE_FTP_WEIRD_PASV_REPLY;
  }

  if(conn->bits.proxy) {
    
    const char * const host_name = conn->bits.socksproxy ? conn->socks_proxy.host.name : conn->http_proxy.host.name;
    rc = Curl_resolv(conn, host_name, (int)conn->port, &addr);
    if(rc == CURLRESOLV_PENDING)
      
      (void)Curl_resolver_wait_resolv(conn, &addr);

    connectport = (unsigned short)conn->port;

    if(!addr) {
      failf(data, "Can't resolve proxy host %s:%hu", host_name, connectport);
      return CURLE_COULDNT_RESOLVE_PROXY;
    }
  }
  else {
    
    rc = Curl_resolv(conn, ftpc->newhost, ftpc->newport, &addr);
    if(rc == CURLRESOLV_PENDING)
      
      (void)Curl_resolver_wait_resolv(conn, &addr);

    connectport = ftpc->newport; 

    if(!addr) {
      failf(data, "Can't resolve new host %s:%hu", ftpc->newhost, connectport);
      return CURLE_FTP_CANT_GET_HOST;
    }
  }

  conn->bits.tcpconnect[SECONDARYSOCKET] = FALSE;
  result = Curl_connecthost(conn, addr);

  if(result) {
    Curl_resolv_unlock(data, addr); 
    if(ftpc->count1 == 0 && ftpcode == 229)
      return ftp_epsv_disable(conn);

    return result;
  }


  

  if(data->set.verbose)
    
    ftp_pasv_verbose(conn, addr->addr, ftpc->newhost, connectport);

  Curl_resolv_unlock(data, addr); 

  Curl_safefree(conn->secondaryhostname);
  conn->secondary_port = ftpc->newport;
  conn->secondaryhostname = strdup(ftpc->newhost);
  if(!conn->secondaryhostname)
    return CURLE_OUT_OF_MEMORY;

  conn->bits.do_more = TRUE;
  state(conn, FTP_STOP); 

  return result;
}

static CURLcode ftp_state_port_resp(struct connectdata *conn, int ftpcode)
{
  struct Curl_easy *data = conn->data;
  struct ftp_conn *ftpc = &conn->proto.ftpc;
  ftpport fcmd = (ftpport)ftpc->count1;
  CURLcode result = CURLE_OK;

  
  if(ftpcode / 100 != 2) {
    

    if(EPRT == fcmd) {
      infof(data, "disabling EPRT usage\n");
      conn->bits.ftp_use_eprt = FALSE;
    }
    fcmd++;

    if(fcmd == DONE) {
      failf(data, "Failed to do PORT");
      result = CURLE_FTP_PORT_FAILED;
    }
    else  result = ftp_state_use_port(conn, fcmd);

  }
  else {
    infof(data, "Connect data stream actively\n");
    state(conn, FTP_STOP); 
    result = ftp_dophase_done(conn, FALSE);
  }

  return result;
}

static CURLcode ftp_state_mdtm_resp(struct connectdata *conn, int ftpcode)
{
  CURLcode result = CURLE_OK;
  struct Curl_easy *data = conn->data;
  struct FTP *ftp = data->req.protop;
  struct ftp_conn *ftpc = &conn->proto.ftpc;

  switch(ftpcode) {
  case 213:
    {
      
      int year, month, day, hour, minute, second;
      if(6 == sscanf(&data->state.buffer[4], "%04d%02d%02d%02d%02d%02d", &year, &month, &day, &hour, &minute, &second)) {
        
        char timebuf[24];
        time_t secs = time(NULL);

        snprintf(timebuf, sizeof(timebuf), "%04d%02d%02d %02d:%02d:%02d GMT", year, month, day, hour, minute, second);

        
        data->info.filetime = curl_getdate(timebuf, &secs);
      }


      

      if(data->set.opt_no_body && ftpc->file && data->set.get_filetime && (data->info.filetime >= 0) ) {


        char headerbuf[128];
        time_t filetime = data->info.filetime;
        struct tm buffer;
        const struct tm *tm = &buffer;

        result = Curl_gmtime(filetime, &buffer);
        if(result)
          return result;

        
        snprintf(headerbuf, sizeof(headerbuf), "Last-Modified: %s, %02d %s %4d %02d:%02d:%02d GMT\r\n", Curl_wkday[tm->tm_wday?tm->tm_wday-1:6], tm->tm_mday, Curl_month[tm->tm_mon], tm->tm_year + 1900, tm->tm_hour, tm->tm_min, tm->tm_sec);







        result = Curl_client_write(conn, CLIENTWRITE_BOTH, headerbuf, 0);
        if(result)
          return result;
      } 

    }
    break;
  default:
    infof(data, "unsupported MDTM reply format\n");
    break;
  case 550: 
    failf(data, "Given file does not exist");
    result = CURLE_FTP_COULDNT_RETR_FILE;
    break;
  }

  if(data->set.timecondition) {
    if((data->info.filetime > 0) && (data->set.timevalue > 0)) {
      switch(data->set.timecondition) {
      case CURL_TIMECOND_IFMODSINCE:
      default:
        if(data->info.filetime <= data->set.timevalue) {
          infof(data, "The requested document is not new enough\n");
          ftp->transfer = FTPTRANSFER_NONE; 
          data->info.timecond = TRUE;
          state(conn, FTP_STOP);
          return CURLE_OK;
        }
        break;
      case CURL_TIMECOND_IFUNMODSINCE:
        if(data->info.filetime > data->set.timevalue) {
          infof(data, "The requested document is not old enough\n");
          ftp->transfer = FTPTRANSFER_NONE; 
          data->info.timecond = TRUE;
          state(conn, FTP_STOP);
          return CURLE_OK;
        }
        break;
      } 
    }
    else {
      infof(data, "Skipping time comparison\n");
    }
  }

  if(!result)
    result = ftp_state_type(conn);

  return result;
}

static CURLcode ftp_state_type_resp(struct connectdata *conn, int ftpcode, ftpstate instate)

{
  CURLcode result = CURLE_OK;
  struct Curl_easy *data = conn->data;

  if(ftpcode/100 != 2) {
    
    failf(data, "Couldn't set desired mode");
    return CURLE_FTP_COULDNT_SET_TYPE;
  }
  if(ftpcode != 200)
    infof(data, "Got a %03d response code instead of the assumed 200\n", ftpcode);

  if(instate == FTP_TYPE)
    result = ftp_state_size(conn);
  else if(instate == FTP_LIST_TYPE)
    result = ftp_state_list(conn);
  else if(instate == FTP_RETR_TYPE)
    result = ftp_state_retr_prequote(conn);
  else if(instate == FTP_STOR_TYPE)
    result = ftp_state_stor_prequote(conn);

  return result;
}

static CURLcode ftp_state_retr(struct connectdata *conn, curl_off_t filesize)
{
  CURLcode result = CURLE_OK;
  struct Curl_easy *data = conn->data;
  struct FTP *ftp = data->req.protop;
  struct ftp_conn *ftpc = &conn->proto.ftpc;

  if(data->set.max_filesize && (filesize > data->set.max_filesize)) {
    failf(data, "Maximum file size exceeded");
    return CURLE_FILESIZE_EXCEEDED;
  }
  ftp->downloadsize = filesize;

  if(data->state.resume_from) {
    
    if(filesize == -1) {
      infof(data, "ftp server doesn't support SIZE\n");
      
    }
    else {
      
      if(data->state.resume_from< 0) {
        
        if(filesize < -data->state.resume_from) {
          failf(data, "Offset (%" CURL_FORMAT_CURL_OFF_T ") was beyond file size (%" CURL_FORMAT_CURL_OFF_T ")", data->state.resume_from, filesize);

          return CURLE_BAD_DOWNLOAD_RESUME;
        }
        
        ftp->downloadsize = -data->state.resume_from;
        
        data->state.resume_from = filesize - ftp->downloadsize;
      }
      else {
        if(filesize < data->state.resume_from) {
          failf(data, "Offset (%" CURL_FORMAT_CURL_OFF_T ") was beyond file size (%" CURL_FORMAT_CURL_OFF_T ")", data->state.resume_from, filesize);

          return CURLE_BAD_DOWNLOAD_RESUME;
        }
        
        ftp->downloadsize = filesize-data->state.resume_from;
      }
    }

    if(ftp->downloadsize == 0) {
      
      Curl_setup_transfer(conn, -1, -1, FALSE, NULL, -1, NULL);
      infof(data, "File already completely downloaded\n");

      
      ftp->transfer = FTPTRANSFER_NONE;
      state(conn, FTP_STOP);
      return CURLE_OK;
    }

    
    infof(data, "Instructs server to resume from offset %" CURL_FORMAT_CURL_OFF_T "\n", data->state.resume_from);

    PPSENDF(&ftpc->pp, "REST %" CURL_FORMAT_CURL_OFF_T, data->state.resume_from);

    state(conn, FTP_RETR_REST);
  }
  else {
    
    PPSENDF(&ftpc->pp, "RETR %s", ftpc->file);
    state(conn, FTP_RETR);
  }

  return result;
}

static CURLcode ftp_state_size_resp(struct connectdata *conn, int ftpcode, ftpstate instate)

{
  CURLcode result = CURLE_OK;
  struct Curl_easy *data = conn->data;
  curl_off_t filesize = -1;
  char *buf = data->state.buffer;

  
  if(ftpcode == 213)
    
    (void)curlx_strtoofft(buf + 4, NULL, 0, &filesize);

  if(instate == FTP_SIZE) {

    if(-1 != filesize) {
      char clbuf[128];
      snprintf(clbuf, sizeof(clbuf), "Content-Length: %" CURL_FORMAT_CURL_OFF_T "\r\n", filesize);
      result = Curl_client_write(conn, CLIENTWRITE_BOTH, clbuf, 0);
      if(result)
        return result;
    }

    Curl_pgrsSetDownloadSize(data, filesize);
    result = ftp_state_rest(conn);
  }
  else if(instate == FTP_RETR_SIZE) {
    Curl_pgrsSetDownloadSize(data, filesize);
    result = ftp_state_retr(conn, filesize);
  }
  else if(instate == FTP_STOR_SIZE) {
    data->state.resume_from = filesize;
    result = ftp_state_ul_setup(conn, TRUE);
  }

  return result;
}

static CURLcode ftp_state_rest_resp(struct connectdata *conn, int ftpcode, ftpstate instate)

{
  CURLcode result = CURLE_OK;
  struct ftp_conn *ftpc = &conn->proto.ftpc;

  switch(instate) {
  case FTP_REST:
  default:

    if(ftpcode == 350) {
      char buffer[24]= { "Accept-ranges: bytes\r\n" };
      result = Curl_client_write(conn, CLIENTWRITE_BOTH, buffer, 0);
      if(result)
        return result;
    }

    result = ftp_state_prepare_transfer(conn);
    break;

  case FTP_RETR_REST:
    if(ftpcode != 350) {
      failf(conn->data, "Couldn't use REST");
      result = CURLE_FTP_COULDNT_USE_REST;
    }
    else {
      PPSENDF(&ftpc->pp, "RETR %s", ftpc->file);
      state(conn, FTP_RETR);
    }
    break;
  }

  return result;
}

static CURLcode ftp_state_stor_resp(struct connectdata *conn, int ftpcode, ftpstate instate)
{
  CURLcode result = CURLE_OK;
  struct Curl_easy *data = conn->data;

  if(ftpcode >= 400) {
    failf(data, "Failed FTP upload: %0d", ftpcode);
    state(conn, FTP_STOP);
    
    return CURLE_UPLOAD_FAILED;
  }

  conn->proto.ftpc.state_saved = instate;

  
  if(data->set.ftp_use_port) {
    bool connected;

    state(conn, FTP_STOP); 

    result = AllowServerConnect(conn, &connected);
    if(result)
      return result;

    if(!connected) {
      struct ftp_conn *ftpc = &conn->proto.ftpc;
      infof(data, "Data conn was not available immediately\n");
      ftpc->wait_data_conn = TRUE;
    }

    return CURLE_OK;
  }
  return InitiateTransfer(conn);
}


static CURLcode ftp_state_get_resp(struct connectdata *conn, int ftpcode, ftpstate instate)

{
  CURLcode result = CURLE_OK;
  struct Curl_easy *data = conn->data;
  struct FTP *ftp = data->req.protop;

  if((ftpcode == 150) || (ftpcode == 125)) {

    

    curl_off_t size = -1; 


    

    if((instate != FTP_LIST) && !data->set.prefer_ascii && (ftp->downloadsize < 1)) {

      
      char *bytes;
      char *buf = data->state.buffer;
      bytes = strstr(buf, " bytes");
      if(bytes) {
        long in = (long)(--bytes-buf);
        
        while(--in) {
          
          if('(' == *bytes)
            break;
          
          if(!ISDIGIT(*bytes)) {
            bytes = NULL;
            break;
          }
          
          bytes--;
        }
        
        if(bytes++) {
          
          (void)curlx_strtoofft(bytes, NULL, 0, &size);
        }
      }
    }
    else if(ftp->downloadsize > -1)
      size = ftp->downloadsize;

    if(size > data->req.maxdownload && data->req.maxdownload > 0)
      size = data->req.size = data->req.maxdownload;
    else if((instate != FTP_LIST) && (data->set.prefer_ascii))
      size = -1; 

    infof(data, "Maxdownload = %" CURL_FORMAT_CURL_OFF_T "\n", data->req.maxdownload);

    if(instate != FTP_LIST)
      infof(data, "Getting file with size: %" CURL_FORMAT_CURL_OFF_T "\n", size);

    
    conn->proto.ftpc.state_saved = instate;
    conn->proto.ftpc.retr_size_saved = size;

    if(data->set.ftp_use_port) {
      bool connected;

      result = AllowServerConnect(conn, &connected);
      if(result)
        return result;

      if(!connected) {
        struct ftp_conn *ftpc = &conn->proto.ftpc;
        infof(data, "Data conn was not available immediately\n");
        state(conn, FTP_STOP);
        ftpc->wait_data_conn = TRUE;
      }
    }
    else return InitiateTransfer(conn);
  }
  else {
    if((instate == FTP_LIST) && (ftpcode == 450)) {
      
      ftp->transfer = FTPTRANSFER_NONE; 
      state(conn, FTP_STOP); 
    }
    else {
      failf(data, "RETR response: %03d", ftpcode);
      return instate == FTP_RETR && ftpcode == 550? CURLE_REMOTE_FILE_NOT_FOUND:
        CURLE_FTP_COULDNT_RETR_FILE;
    }
  }

  return result;
}


static CURLcode ftp_state_loggedin(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;

  if(conn->ssl[FIRSTSOCKET].use) {
    
    PPSENDF(&conn->proto.ftpc.pp, "PBSZ %d", 0);
    state(conn, FTP_PBSZ);
  }
  else {
    result = ftp_state_pwd(conn);
  }
  return result;
}


static CURLcode ftp_state_user_resp(struct connectdata *conn, int ftpcode, ftpstate instate)

{
  CURLcode result = CURLE_OK;
  struct Curl_easy *data = conn->data;
  struct FTP *ftp = data->req.protop;
  struct ftp_conn *ftpc = &conn->proto.ftpc;
  (void)instate; 

  
  if((ftpcode == 331) && (ftpc->state == FTP_USER)) {
    
    PPSENDF(&ftpc->pp, "PASS %s", ftp->passwd?ftp->passwd:"");
    state(conn, FTP_PASS);
  }
  else if(ftpcode/100 == 2) {
    
    result = ftp_state_loggedin(conn);
  }
  else if(ftpcode == 332) {
    if(data->set.str[STRING_FTP_ACCOUNT]) {
      PPSENDF(&ftpc->pp, "ACCT %s", data->set.str[STRING_FTP_ACCOUNT]);
      state(conn, FTP_ACCT);
    }
    else {
      failf(data, "ACCT requested but none available");
      result = CURLE_LOGIN_DENIED;
    }
  }
  else {
    

    if(conn->data->set.str[STRING_FTP_ALTERNATIVE_TO_USER] && !conn->data->state.ftp_trying_alternative) {
      
      PPSENDF(&conn->proto.ftpc.pp, "%s", conn->data->set.str[STRING_FTP_ALTERNATIVE_TO_USER]);
      conn->data->state.ftp_trying_alternative = TRUE;
      state(conn, FTP_USER);
      result = CURLE_OK;
    }
    else {
      failf(data, "Access denied: %03d", ftpcode);
      result = CURLE_LOGIN_DENIED;
    }
  }
  return result;
}


static CURLcode ftp_state_acct_resp(struct connectdata *conn, int ftpcode)
{
  CURLcode result = CURLE_OK;
  struct Curl_easy *data = conn->data;
  if(ftpcode != 230) {
    failf(data, "ACCT rejected by server: %03d", ftpcode);
    result = CURLE_FTP_WEIRD_PASS_REPLY; 
  }
  else result = ftp_state_loggedin(conn);

  return result;
}


static CURLcode ftp_statemach_act(struct connectdata *conn)
{
  CURLcode result;
  curl_socket_t sock = conn->sock[FIRSTSOCKET];
  struct Curl_easy *data = conn->data;
  int ftpcode;
  struct ftp_conn *ftpc = &conn->proto.ftpc;
  struct pingpong *pp = &ftpc->pp;
  static const char ftpauth[][4]  = { "SSL", "TLS" };
  size_t nread = 0;

  if(pp->sendleft)
    return Curl_pp_flushsend(pp);

  result = ftp_readresp(sock, pp, &ftpcode, &nread);
  if(result)
    return result;

  if(ftpcode) {
    
    switch(ftpc->state) {
    case FTP_WAIT220:
      if(ftpcode == 230)
        
        return ftp_state_user_resp(conn, ftpcode, ftpc->state);
      else if(ftpcode != 220) {
        failf(data, "Got a %03d ftp-server response when 220 was expected", ftpcode);
        return CURLE_WEIRD_SERVER_REPLY;
      }

      

      if(data->set.krb) {
        

        Curl_sec_request_prot(conn, "private");
        
        Curl_sec_request_prot(conn, data->set.str[STRING_KRB_LEVEL]);

        if(Curl_sec_login(conn))
          infof(data, "Logging in with password in cleartext!\n");
        else infof(data, "Authentication successful\n");
      }


      if(data->set.use_ssl && (!conn->ssl[FIRSTSOCKET].use || (conn->bits.proxy_ssl_connected[FIRSTSOCKET] && !conn->proxy_ssl[FIRSTSOCKET].use))) {


        

        ftpc->count3 = 0;
        switch(data->set.ftpsslauth) {
        case CURLFTPAUTH_DEFAULT:
        case CURLFTPAUTH_SSL:
          ftpc->count2 = 1; 
          ftpc->count1 = 0;
          break;
        case CURLFTPAUTH_TLS:
          ftpc->count2 = -1; 
          ftpc->count1 = 1;
          break;
        default:
          failf(data, "unsupported parameter to CURLOPT_FTPSSLAUTH: %d", (int)data->set.ftpsslauth);
          return CURLE_UNKNOWN_OPTION; 
        }
        PPSENDF(&ftpc->pp, "AUTH %s", ftpauth[ftpc->count1]);
        state(conn, FTP_AUTH);
      }
      else {
        result = ftp_state_user(conn);
        if(result)
          return result;
      }

      break;

    case FTP_AUTH:
      

      

      if((ftpcode == 234) || (ftpcode == 334)) {
        
        result = Curl_ssl_connect(conn, FIRSTSOCKET);
        if(!result) {
          conn->bits.ftp_use_data_ssl = FALSE; 
          result = ftp_state_user(conn);
        }
      }
      else if(ftpc->count3 < 1) {
        ftpc->count3++;
        ftpc->count1 += ftpc->count2; 
        result = Curl_pp_sendf(&ftpc->pp, "AUTH %s", ftpauth[ftpc->count1]);
        
      }
      else {
        if(data->set.use_ssl > CURLUSESSL_TRY)
          
          result = CURLE_USE_SSL_FAILED;
        else  result = ftp_state_user(conn);

      }

      if(result)
        return result;
      break;

    case FTP_USER:
    case FTP_PASS:
      result = ftp_state_user_resp(conn, ftpcode, ftpc->state);
      break;

    case FTP_ACCT:
      result = ftp_state_acct_resp(conn, ftpcode);
      break;

    case FTP_PBSZ:
      PPSENDF(&ftpc->pp, "PROT %c", data->set.use_ssl == CURLUSESSL_CONTROL ? 'C' : 'P');
      state(conn, FTP_PROT);

      break;

    case FTP_PROT:
      if(ftpcode/100 == 2)
        
        conn->bits.ftp_use_data_ssl = (data->set.use_ssl != CURLUSESSL_CONTROL) ? TRUE : FALSE;
      
      else if(data->set.use_ssl > CURLUSESSL_CONTROL)
        
        return CURLE_USE_SSL_FAILED;

      if(data->set.ftp_ccc) {
        
        PPSENDF(&ftpc->pp, "%s", "CCC");
        state(conn, FTP_CCC);
      }
      else {
        result = ftp_state_pwd(conn);
        if(result)
          return result;
      }
      break;

    case FTP_CCC:
      if(ftpcode < 500) {
        
        result = Curl_ssl_shutdown(conn, FIRSTSOCKET);

        if(result) {
          failf(conn->data, "Failed to clear the command channel (CCC)");
          return result;
        }
      }

      
      result = ftp_state_pwd(conn);
      if(result)
        return result;
      break;

    case FTP_PWD:
      if(ftpcode == 257) {
        char *ptr = &data->state.buffer[4];  
        const size_t buf_size = data->set.buffer_size;
        char *dir;
        char *store;
        bool entry_extracted = FALSE;

        dir = malloc(nread + 1);
        if(!dir)
          return CURLE_OUT_OF_MEMORY;

        

        
        while(ptr < &data->state.buffer[buf_size] && *ptr != '\n' && *ptr != '\0' && *ptr != '"')
          ptr++;

        if('\"' == *ptr) {
          
          ptr++;
          for(store = dir; *ptr;) {
            if('\"' == *ptr) {
              if('\"' == ptr[1]) {
                
                *store = ptr[1];
                ptr++;
              }
              else {
                
                entry_extracted = TRUE;
                break; 
              }
            }
            else *store = *ptr;
            store++;
            ptr++;
          }
          *store = '\0'; 
        }
        if(entry_extracted) {
          

          if(!ftpc->server_os && dir[0] != '/') {

            result = Curl_pp_sendf(&ftpc->pp, "%s", "SYST");
            if(result) {
              free(dir);
              return result;
            }
            Curl_safefree(ftpc->entrypath);
            ftpc->entrypath = dir; 
            infof(data, "Entry path is '%s'\n", ftpc->entrypath);
            
            data->state.most_recent_ftp_entrypath = ftpc->entrypath;
            state(conn, FTP_SYST);
            break;
          }

          Curl_safefree(ftpc->entrypath);
          ftpc->entrypath = dir; 
          infof(data, "Entry path is '%s'\n", ftpc->entrypath);
          
          data->state.most_recent_ftp_entrypath = ftpc->entrypath;
        }
        else {
          
          free(dir);
          infof(data, "Failed to figure out path\n");
        }
      }
      state(conn, FTP_STOP); 
      DEBUGF(infof(data, "protocol connect phase DONE\n"));
      break;

    case FTP_SYST:
      if(ftpcode == 215) {
        char *ptr = &data->state.buffer[4];  
        char *os;
        char *store;

        os = malloc(nread + 1);
        if(!os)
          return CURLE_OUT_OF_MEMORY;

        
        while(*ptr == ' ')
          ptr++;
        for(store = os; *ptr && *ptr != ' ';)
          *store++ = *ptr++;
        *store = '\0'; 

        

        if(strcasecompare(os, "OS/400")) {
          
          result = Curl_pp_sendf(&ftpc->pp, "%s", "SITE NAMEFMT 1");
          if(result) {
            free(os);
            return result;
          }
          
          Curl_safefree(ftpc->server_os);
          ftpc->server_os = os;
          state(conn, FTP_NAMEFMT);
          break;
        }
        
        
        Curl_safefree(ftpc->server_os);
        ftpc->server_os = os;
      }
      else {
        
      }

      state(conn, FTP_STOP); 
      DEBUGF(infof(data, "protocol connect phase DONE\n"));
      break;

    case FTP_NAMEFMT:
      if(ftpcode == 250) {
        
        ftp_state_pwd(conn);
        break;
      }

      state(conn, FTP_STOP); 
      DEBUGF(infof(data, "protocol connect phase DONE\n"));
      break;

    case FTP_QUOTE:
    case FTP_POSTQUOTE:
    case FTP_RETR_PREQUOTE:
    case FTP_STOR_PREQUOTE:
      if((ftpcode >= 400) && !ftpc->count2) {
        
        failf(conn->data, "QUOT command failed with %03d", ftpcode);
        return CURLE_QUOTE_ERROR;
      }
      result = ftp_state_quote(conn, FALSE, ftpc->state);
      if(result)
        return result;

      break;

    case FTP_CWD:
      if(ftpcode/100 != 2) {
        
        if(conn->data->set.ftp_create_missing_dirs && ftpc->cwdcount && !ftpc->count2) {
          
          ftpc->count2++; 
          PPSENDF(&ftpc->pp, "MKD %s", ftpc->dirs[ftpc->cwdcount - 1]);
          state(conn, FTP_MKD);
        }
        else {
          
          failf(data, "Server denied you to change to the given directory");
          ftpc->cwdfail = TRUE; 
          return CURLE_REMOTE_ACCESS_DENIED;
        }
      }
      else {
        
        ftpc->count2 = 0;
        if(++ftpc->cwdcount <= ftpc->dirdepth) {
          
          PPSENDF(&ftpc->pp, "CWD %s", ftpc->dirs[ftpc->cwdcount - 1]);
        }
        else {
          result = ftp_state_mdtm(conn);
          if(result)
            return result;
        }
      }
      break;

    case FTP_MKD:
      if((ftpcode/100 != 2) && !ftpc->count3--) {
        
        failf(data, "Failed to MKD dir: %03d", ftpcode);
        return CURLE_REMOTE_ACCESS_DENIED;
      }
      state(conn, FTP_CWD);
      
      PPSENDF(&ftpc->pp, "CWD %s", ftpc->dirs[ftpc->cwdcount - 1]);
      break;

    case FTP_MDTM:
      result = ftp_state_mdtm_resp(conn, ftpcode);
      break;

    case FTP_TYPE:
    case FTP_LIST_TYPE:
    case FTP_RETR_TYPE:
    case FTP_STOR_TYPE:
      result = ftp_state_type_resp(conn, ftpcode, ftpc->state);
      break;

    case FTP_SIZE:
    case FTP_RETR_SIZE:
    case FTP_STOR_SIZE:
      result = ftp_state_size_resp(conn, ftpcode, ftpc->state);
      break;

    case FTP_REST:
    case FTP_RETR_REST:
      result = ftp_state_rest_resp(conn, ftpcode, ftpc->state);
      break;

    case FTP_PRET:
      if(ftpcode != 200) {
        
        failf(data, "PRET command not accepted: %03d", ftpcode);
        return CURLE_FTP_PRET_FAILED;
      }
      result = ftp_state_use_pasv(conn);
      break;

    case FTP_PASV:
      result = ftp_state_pasv_resp(conn, ftpcode);
      break;

    case FTP_PORT:
      result = ftp_state_port_resp(conn, ftpcode);
      break;

    case FTP_LIST:
    case FTP_RETR:
      result = ftp_state_get_resp(conn, ftpcode, ftpc->state);
      break;

    case FTP_STOR:
      result = ftp_state_stor_resp(conn, ftpcode, ftpc->state);
      break;

    case FTP_QUIT:
      
    default:
      
      state(conn, FTP_STOP);
      break;
    }
  } 

  return result;
}



static CURLcode ftp_multi_statemach(struct connectdata *conn, bool *done)
{
  struct ftp_conn *ftpc = &conn->proto.ftpc;
  CURLcode result = Curl_pp_statemach(&ftpc->pp, FALSE);

  
  *done = (ftpc->state == FTP_STOP) ? TRUE : FALSE;

  return result;
}

static CURLcode ftp_block_statemach(struct connectdata *conn)
{
  struct ftp_conn *ftpc = &conn->proto.ftpc;
  struct pingpong *pp = &ftpc->pp;
  CURLcode result = CURLE_OK;

  while(ftpc->state != FTP_STOP) {
    result = Curl_pp_statemach(pp, TRUE);
    if(result)
      break;
  }

  return result;
}


static CURLcode ftp_connect(struct connectdata *conn, bool *done)
{
  CURLcode result;
  struct ftp_conn *ftpc = &conn->proto.ftpc;
  struct pingpong *pp = &ftpc->pp;

  *done = FALSE; 

  
  connkeep(conn, "FTP default");

  pp->response_time = RESP_TIMEOUT; 
  pp->statemach_act = ftp_statemach_act;
  pp->endofresp = ftp_endofresp;
  pp->conn = conn;

  if(conn->handler->flags & PROTOPT_SSL) {
    
    result = Curl_ssl_connect(conn, FIRSTSOCKET);
    if(result)
      return result;
  }

  Curl_pp_init(pp); 

  
  state(conn, FTP_WAIT220);

  result = ftp_multi_statemach(conn, done);

  return result;
}


static CURLcode ftp_done(struct connectdata *conn, CURLcode status, bool premature)
{
  struct Curl_easy *data = conn->data;
  struct FTP *ftp = data->req.protop;
  struct ftp_conn *ftpc = &conn->proto.ftpc;
  struct pingpong *pp = &ftpc->pp;
  ssize_t nread;
  int ftpcode;
  CURLcode result = CURLE_OK;
  char *path = NULL;
  const char *path_to_use = data->state.path;

  if(!ftp)
    return CURLE_OK;

  switch(status) {
  case CURLE_BAD_DOWNLOAD_RESUME:
  case CURLE_FTP_WEIRD_PASV_REPLY:
  case CURLE_FTP_PORT_FAILED:
  case CURLE_FTP_ACCEPT_FAILED:
  case CURLE_FTP_ACCEPT_TIMEOUT:
  case CURLE_FTP_COULDNT_SET_TYPE:
  case CURLE_FTP_COULDNT_RETR_FILE:
  case CURLE_PARTIAL_FILE:
  case CURLE_UPLOAD_FAILED:
  case CURLE_REMOTE_ACCESS_DENIED:
  case CURLE_FILESIZE_EXCEEDED:
  case CURLE_REMOTE_FILE_NOT_FOUND:
  case CURLE_WRITE_ERROR:
    
    
  case CURLE_OK: 
    if(!premature)
      break;

    
    
  default:       
    ftpc->ctl_valid = FALSE;
    ftpc->cwdfail = TRUE; 
    connclose(conn, "FTP ended with bad error code");
    result = status;      
    break;
  }

  
  free(ftpc->prevpath);

  if(data->state.wildcardmatch) {
    if(data->set.chunk_end && ftpc->file) {
      Curl_set_in_callback(data, true);
      data->set.chunk_end(data->wildcard.customptr);
      Curl_set_in_callback(data, false);
    }
    ftpc->known_filesize = -1;
  }

  if(!result)
    
    result = Curl_urldecode(data, path_to_use, 0, &path, NULL, FALSE);
  if(result) {
    
    ftpc->ctl_valid = FALSE; 
    connclose(conn, "FTP: out of memory!"); 
    ftpc->prevpath = NULL; 
  }
  else {
    size_t flen = ftpc->file?strlen(ftpc->file):0; 
    size_t dlen = strlen(path)-flen;
    if(!ftpc->cwdfail) {
      ftpc->prevmethod = data->set.ftp_filemethod;
      if(dlen && (data->set.ftp_filemethod != FTPFILE_NOCWD)) {
        ftpc->prevpath = path;
        if(flen)
          
          ftpc->prevpath[dlen] = 0; 
      }
      else {
        
        ftpc->prevpath = strdup("");
        free(path);
      }
      if(ftpc->prevpath)
        infof(data, "Remembering we are in dir \"%s\"\n", ftpc->prevpath);
    }
    else {
      ftpc->prevpath = NULL; 
      free(path);
    }
  }
  
  freedirs(ftpc);

  


  shutdown(conn->sock[SECONDARYSOCKET], 2);  


  if(conn->sock[SECONDARYSOCKET] != CURL_SOCKET_BAD) {
    if(!result && ftpc->dont_check && data->req.maxdownload > 0) {
      
      result = Curl_pp_sendf(pp, "%s", "ABOR");
      if(result) {
        failf(data, "Failure sending ABOR command: %s", curl_easy_strerror(result));
        ftpc->ctl_valid = FALSE; 
        connclose(conn, "ABOR command failed"); 
      }
    }

    if(conn->ssl[SECONDARYSOCKET].use) {
      
      Curl_ssl_close(conn, SECONDARYSOCKET);

      
    }
    close_secondarysocket(conn);
  }

  if(!result && (ftp->transfer == FTPTRANSFER_BODY) && ftpc->ctl_valid && pp->pending_resp && !premature) {
    
    long old_time = pp->response_time;

    pp->response_time = 60*1000; 
    pp->response = Curl_now(); 

    result = Curl_GetFTPResponse(&nread, conn, &ftpcode);

    pp->response_time = old_time; 

    if(!nread && (CURLE_OPERATION_TIMEDOUT == result)) {
      failf(data, "control connection looks dead");
      ftpc->ctl_valid = FALSE; 
      connclose(conn, "Timeout or similar in FTP DONE operation"); 
    }

    if(result)
      return result;

    if(ftpc->dont_check && data->req.maxdownload > 0) {
      
      infof(data, "partial download completed, closing connection\n");
      connclose(conn, "Partial download with no ability to check");
      return result;
    }

    if(!ftpc->dont_check) {
      
      if((ftpcode != 226) && (ftpcode != 250)) {
        failf(data, "server did not report OK, got %d", ftpcode);
        result = CURLE_PARTIAL_FILE;
      }
    }
  }

  if(result || premature)
    
    ;
  else if(data->set.upload) {
    if((-1 != data->state.infilesize) && (data->state.infilesize != *ftp->bytecountp) && !data->set.crlf && (ftp->transfer == FTPTRANSFER_BODY)) {


      failf(data, "Uploaded unaligned file size (%" CURL_FORMAT_CURL_OFF_T " out of %" CURL_FORMAT_CURL_OFF_T " bytes)", *ftp->bytecountp, data->state.infilesize);

      result = CURLE_PARTIAL_FILE;
    }
  }
  else {
    if((-1 != data->req.size) && (data->req.size != *ftp->bytecountp) &&   ((data->req.size + data->state.crlf_conversions) != *ftp->bytecountp) &&  (data->req.maxdownload != *ftp->bytecountp)) {






      failf(data, "Received only partial file: %" CURL_FORMAT_CURL_OFF_T " bytes", *ftp->bytecountp);
      result = CURLE_PARTIAL_FILE;
    }
    else if(!ftpc->dont_check && !*ftp->bytecountp && (data->req.size>0)) {

      failf(data, "No data was received!");
      result = CURLE_FTP_COULDNT_RETR_FILE;
    }
  }

  
  ftp->transfer = FTPTRANSFER_BODY;
  ftpc->dont_check = FALSE;

  
  if(!status && !result && !premature && data->set.postquote)
    result = ftp_sendquote(conn, data->set.postquote);

  return result;
}



static CURLcode ftp_sendquote(struct connectdata *conn, struct curl_slist *quote)
{
  struct curl_slist *item;
  ssize_t nread;
  int ftpcode;
  CURLcode result;
  struct ftp_conn *ftpc = &conn->proto.ftpc;
  struct pingpong *pp = &ftpc->pp;

  item = quote;
  while(item) {
    if(item->data) {
      char *cmd = item->data;
      bool acceptfail = FALSE;

      

      if(cmd[0] == '*') {
        cmd++;
        acceptfail = TRUE;
      }

      PPSENDF(&conn->proto.ftpc.pp, "%s", cmd);

      pp->response = Curl_now(); 

      result = Curl_GetFTPResponse(&nread, conn, &ftpcode);
      if(result)
        return result;

      if(!acceptfail && (ftpcode >= 400)) {
        failf(conn->data, "QUOT string not accepted: %s", cmd);
        return CURLE_QUOTE_ERROR;
      }
    }

    item = item->next;
  }

  return CURLE_OK;
}


static int ftp_need_type(struct connectdata *conn, bool ascii_wanted)
{
  return conn->proto.ftpc.transfertype != (ascii_wanted?'A':'I');
}


static CURLcode ftp_nb_type(struct connectdata *conn, bool ascii, ftpstate newstate)
{
  struct ftp_conn *ftpc = &conn->proto.ftpc;
  CURLcode result;
  char want = (char)(ascii?'A':'I');

  if(ftpc->transfertype == want) {
    state(conn, newstate);
    return ftp_state_type_resp(conn, 200, newstate);
  }

  PPSENDF(&ftpc->pp, "TYPE %c", want);
  state(conn, newstate);

  
  ftpc->transfertype = want;
  return CURLE_OK;
}



static void ftp_pasv_verbose(struct connectdata *conn, Curl_addrinfo *ai, char *newhost, int port)



{
  char buf[256];
  Curl_printable_address(ai, buf, sizeof(buf));
  infof(conn->data, "Connecting to %s (%s) port %d\n", newhost, buf, port);
}




static CURLcode ftp_do_more(struct connectdata *conn, int *completep)
{
  struct Curl_easy *data = conn->data;
  struct ftp_conn *ftpc = &conn->proto.ftpc;
  CURLcode result = CURLE_OK;
  bool connected = FALSE;
  bool complete = FALSE;

  
  struct FTP *ftp = data->req.protop;

  
  if(!conn->bits.tcpconnect[SECONDARYSOCKET]) {
    if(Curl_connect_ongoing(conn)) {
      
      result = Curl_proxyCONNECT(conn, SECONDARYSOCKET, NULL, 0);

      return result;
    }

    result = Curl_is_connected(conn, SECONDARYSOCKET, &connected);

    
    if(connected) {
      DEBUGF(infof(data, "DO-MORE connected phase starts\n"));
    }
    else {
      if(result && (ftpc->count1 == 0)) {
        *completep = -1; 
        
        return ftp_epsv_disable(conn);
      }
      return result;
    }
  }

  result = Curl_proxy_connect(conn, SECONDARYSOCKET);
  if(result)
    return result;

  if(CONNECT_SECONDARYSOCKET_PROXY_SSL())
    return result;

  if(conn->bits.tunnel_proxy && conn->bits.httpproxy && Curl_connect_ongoing(conn))
    return result;


  if(ftpc->state) {
    
    result = ftp_multi_statemach(conn, &complete);

    *completep = (int)complete;

    
    if(result || (ftpc->wait_data_conn != TRUE))
      return result;

    if(ftpc->wait_data_conn)
      
      *completep = 0;
  }

  if(ftp->transfer <= FTPTRANSFER_INFO) {
    

    if(ftpc->wait_data_conn == TRUE) {
      bool serv_conned;

      result = ReceivedServerConnect(conn, &serv_conned);
      if(result)
        return result; 

      if(serv_conned) {
        
        result = AcceptServerConnect(conn);
        ftpc->wait_data_conn = FALSE;
        if(!result)
          result = InitiateTransfer(conn);

        if(result)
          return result;

        *completep = 1; 
      }
    }
    else if(data->set.upload) {
      result = ftp_nb_type(conn, data->set.prefer_ascii, FTP_STOR_TYPE);
      if(result)
        return result;

      result = ftp_multi_statemach(conn, &complete);
      if(ftpc->wait_data_conn)
        
        *completep = 0;
      else *completep = (int)complete;
    }
    else {
      
      ftp->downloadsize = -1; 

      result = Curl_range(conn);

      if(result == CURLE_OK && data->req.maxdownload >= 0) {
        
        ftpc->dont_check = TRUE;
      }

      if(result)
        ;
      else if(data->set.ftp_list_only || !ftpc->file) {
        

        
        if(ftp->transfer == FTPTRANSFER_BODY) {
          result = ftp_nb_type(conn, TRUE, FTP_LIST_TYPE);
          if(result)
            return result;
        }
        
      }
      else {
        result = ftp_nb_type(conn, data->set.prefer_ascii, FTP_RETR_TYPE);
        if(result)
          return result;
      }

      result = ftp_multi_statemach(conn, &complete);
      *completep = (int)complete;
    }
    return result;
  }

  if(!result && (ftp->transfer != FTPTRANSFER_BODY))
    
    Curl_setup_transfer(conn, -1, -1, FALSE, NULL, -1, NULL);

  if(!ftpc->wait_data_conn) {
    
    *completep = 1;
    DEBUGF(infof(data, "DO-MORE phase ends with %d\n", (int)result));
  }

  return result;
}





static CURLcode ftp_perform(struct connectdata *conn, bool *connected, bool *dophase_done)


{
  
  CURLcode result = CURLE_OK;

  DEBUGF(infof(conn->data, "DO phase starts\n"));

  if(conn->data->set.opt_no_body) {
    
    struct FTP *ftp = conn->data->req.protop;
    ftp->transfer = FTPTRANSFER_INFO;
  }

  *dophase_done = FALSE; 

  
  result = ftp_state_quote(conn, TRUE, FTP_QUOTE);
  if(result)
    return result;

  
  result = ftp_multi_statemach(conn, dophase_done);

  *connected = conn->bits.tcpconnect[SECONDARYSOCKET];

  infof(conn->data, "ftp_perform ends with SECONDARY: %d\n", *connected);

  if(*dophase_done)
    DEBUGF(infof(conn->data, "DO phase is complete1\n"));

  return result;
}

static void wc_data_dtor(void *ptr)
{
  struct ftp_wc_tmpdata *tmp = ptr;
  if(tmp)
    Curl_ftp_parselist_data_free(&tmp->parser);
  free(tmp);
}

static CURLcode init_wc_data(struct connectdata *conn)
{
  char *last_slash;
  char *path = conn->data->state.path;
  struct WildcardData *wildcard = &(conn->data->wildcard);
  CURLcode result = CURLE_OK;
  struct ftp_wc_tmpdata *ftp_tmp;

  last_slash = strrchr(conn->data->state.path, '/');
  if(last_slash) {
    last_slash++;
    if(last_slash[0] == '\0') {
      wildcard->state = CURLWC_CLEAN;
      result = ftp_parse_url_path(conn);
      return result;
    }
    wildcard->pattern = strdup(last_slash);
    if(!wildcard->pattern)
      return CURLE_OUT_OF_MEMORY;
    last_slash[0] = '\0'; 
  }
  else { 
    if(path[0]) {
      wildcard->pattern = strdup(path);
      if(!wildcard->pattern)
        return CURLE_OUT_OF_MEMORY;
      path[0] = '\0';
    }
    else { 
      wildcard->state = CURLWC_CLEAN;
      result = ftp_parse_url_path(conn);
      return result;
    }
  }

  

  
  ftp_tmp = calloc(1, sizeof(struct ftp_wc_tmpdata));
  if(!ftp_tmp) {
    Curl_safefree(wildcard->pattern);
    return CURLE_OUT_OF_MEMORY;
  }

  
  ftp_tmp->parser = Curl_ftp_parselist_data_alloc();
  if(!ftp_tmp->parser) {
    Curl_safefree(wildcard->pattern);
    free(ftp_tmp);
    return CURLE_OUT_OF_MEMORY;
  }

  wildcard->tmp = ftp_tmp; 
  wildcard->tmp_dtor = wc_data_dtor;

  
  if(conn->data->set.ftp_filemethod == FTPFILE_NOCWD)
    conn->data->set.ftp_filemethod = FTPFILE_MULTICWD;

  
  result = ftp_parse_url_path(conn);
  if(result) {
    Curl_safefree(wildcard->pattern);
    wildcard->tmp_dtor(wildcard->tmp);
    wildcard->tmp_dtor = ZERO_NULL;
    wildcard->tmp = NULL;
    return result;
  }

  wildcard->path = strdup(conn->data->state.path);
  if(!wildcard->path) {
    Curl_safefree(wildcard->pattern);
    wildcard->tmp_dtor(wildcard->tmp);
    wildcard->tmp_dtor = ZERO_NULL;
    wildcard->tmp = NULL;
    return CURLE_OUT_OF_MEMORY;
  }

  
  ftp_tmp->backup.write_function = conn->data->set.fwrite_func;
  
  conn->data->set.fwrite_func = Curl_ftp_parselist;
  
  ftp_tmp->backup.file_descriptor = conn->data->set.out;
  
  conn->data->set.out = conn;

  infof(conn->data, "Wildcard - Parsing started\n");
  return CURLE_OK;
}


static CURLcode wc_statemach(struct connectdata *conn)
{
  struct WildcardData * const wildcard = &(conn->data->wildcard);
  CURLcode result = CURLE_OK;

  switch(wildcard->state) {
  case CURLWC_INIT:
    result = init_wc_data(conn);
    if(wildcard->state == CURLWC_CLEAN)
      
      break;
    wildcard->state = result ? CURLWC_ERROR : CURLWC_MATCHING;
    break;

  case CURLWC_MATCHING: {
    
    struct ftp_wc_tmpdata *ftp_tmp = wildcard->tmp;
    conn->data->set.fwrite_func = ftp_tmp->backup.write_function;
    conn->data->set.out = ftp_tmp->backup.file_descriptor;
    ftp_tmp->backup.write_function = ZERO_NULL;
    ftp_tmp->backup.file_descriptor = NULL;
    wildcard->state = CURLWC_DOWNLOADING;

    if(Curl_ftp_parselist_geterror(ftp_tmp->parser)) {
      
      wildcard->state = CURLWC_CLEAN;
      return wc_statemach(conn);
    }
    if(wildcard->filelist.size == 0) {
      
      wildcard->state = CURLWC_CLEAN;
      return CURLE_REMOTE_FILE_NOT_FOUND;
    }
    return wc_statemach(conn);
  }

  case CURLWC_DOWNLOADING: {
    
    struct ftp_conn *ftpc = &conn->proto.ftpc;
    struct curl_fileinfo *finfo = wildcard->filelist.head->ptr;

    char *tmp_path = aprintf("%s%s", wildcard->path, finfo->filename);
    if(!tmp_path)
      return CURLE_OUT_OF_MEMORY;

    
    Curl_safefree(conn->data->state.pathbuffer);
    conn->data->state.pathbuffer = tmp_path;
    conn->data->state.path = tmp_path;

    infof(conn->data, "Wildcard - START of \"%s\"\n", finfo->filename);
    if(conn->data->set.chunk_bgn) {
      long userresponse;
      Curl_set_in_callback(conn->data, true);
      userresponse = conn->data->set.chunk_bgn( finfo, wildcard->customptr, (int)wildcard->filelist.size);
      Curl_set_in_callback(conn->data, false);
      switch(userresponse) {
      case CURL_CHUNK_BGN_FUNC_SKIP:
        infof(conn->data, "Wildcard - \"%s\" skipped by user\n", finfo->filename);
        wildcard->state = CURLWC_SKIP;
        return wc_statemach(conn);
      case CURL_CHUNK_BGN_FUNC_FAIL:
        return CURLE_CHUNK_FAILED;
      }
    }

    if(finfo->filetype != CURLFILETYPE_FILE) {
      wildcard->state = CURLWC_SKIP;
      return wc_statemach(conn);
    }

    if(finfo->flags & CURLFINFOFLAG_KNOWN_SIZE)
      ftpc->known_filesize = finfo->size;

    result = ftp_parse_url_path(conn);
    if(result)
      return result;

    
    Curl_llist_remove(&wildcard->filelist, wildcard->filelist.head, NULL);

    if(wildcard->filelist.size == 0) { 
      wildcard->state = CURLWC_CLEAN;
      
      return CURLE_OK;
    }
  } break;

  case CURLWC_SKIP: {
    if(conn->data->set.chunk_end) {
      Curl_set_in_callback(conn->data, true);
      conn->data->set.chunk_end(conn->data->wildcard.customptr);
      Curl_set_in_callback(conn->data, false);
    }
    Curl_llist_remove(&wildcard->filelist, wildcard->filelist.head, NULL);
    wildcard->state = (wildcard->filelist.size == 0) ? CURLWC_CLEAN : CURLWC_DOWNLOADING;
    return wc_statemach(conn);
  }

  case CURLWC_CLEAN: {
    struct ftp_wc_tmpdata *ftp_tmp = wildcard->tmp;
    result = CURLE_OK;
    if(ftp_tmp)
      result = Curl_ftp_parselist_geterror(ftp_tmp->parser);

    wildcard->state = result ? CURLWC_ERROR : CURLWC_DONE;
  } break;

  case CURLWC_DONE:
  case CURLWC_ERROR:
  case CURLWC_CLEAR:
    break;
  }

  return result;
}


static CURLcode ftp_do(struct connectdata *conn, bool *done)
{
  CURLcode result = CURLE_OK;
  struct ftp_conn *ftpc = &conn->proto.ftpc;

  *done = FALSE; 
  ftpc->wait_data_conn = FALSE; 

  if(conn->data->state.wildcardmatch) {
    result = wc_statemach(conn);
    if(conn->data->wildcard.state == CURLWC_SKIP || conn->data->wildcard.state == CURLWC_DONE) {
      
      return CURLE_OK;
    }
    if(result) 
      return result;
  }
  else { 
    result = ftp_parse_url_path(conn);
    if(result)
      return result;
  }

  result = ftp_regular_transfer(conn, done);

  return result;
}


CURLcode Curl_ftpsend(struct connectdata *conn, const char *cmd)
{
  ssize_t bytes_written;

  char s[SBUF_SIZE];
  size_t write_len;
  char *sptr = s;
  CURLcode result = CURLE_OK;

  enum protection_level data_sec = conn->data_prot;


  write_len = strlen(cmd);
  if(write_len > (sizeof(s) -3))
    return CURLE_BAD_FUNCTION_ARGUMENT;

  strcpy(&s[write_len], "\r\n"); 
  write_len += 2;
  bytes_written = 0;

  result = Curl_convert_to_network(conn->data, s, write_len);
  
  if(result)
    return result;

  for(;;) {

    conn->data_prot = PROT_CMD;

    result = Curl_write(conn, conn->sock[FIRSTSOCKET], sptr, write_len, &bytes_written);

    DEBUGASSERT(data_sec > PROT_NONE && data_sec < PROT_LAST);
    conn->data_prot = data_sec;


    if(result)
      break;

    if(conn->data->set.verbose)
      Curl_debug(conn->data, CURLINFO_HEADER_OUT, sptr, (size_t)bytes_written, conn);

    if(bytes_written != (ssize_t)write_len) {
      write_len -= bytes_written;
      sptr += bytes_written;
    }
    else break;
  }

  return result;
}


static CURLcode ftp_quit(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;

  if(conn->proto.ftpc.ctl_valid) {
    result = Curl_pp_sendf(&conn->proto.ftpc.pp, "%s", "QUIT");
    if(result) {
      failf(conn->data, "Failure sending QUIT command: %s", curl_easy_strerror(result));
      conn->proto.ftpc.ctl_valid = FALSE; 
      connclose(conn, "QUIT command failed"); 
      state(conn, FTP_STOP);
      return result;
    }

    state(conn, FTP_QUIT);

    result = ftp_block_statemach(conn);
  }

  return result;
}


static CURLcode ftp_disconnect(struct connectdata *conn, bool dead_connection)
{
  struct ftp_conn *ftpc = &conn->proto.ftpc;
  struct pingpong *pp = &ftpc->pp;

  
  if(dead_connection)
    ftpc->ctl_valid = FALSE;

  
  (void)ftp_quit(conn); 

  if(ftpc->entrypath) {
    struct Curl_easy *data = conn->data;
    if(data->state.most_recent_ftp_entrypath == ftpc->entrypath) {
      data->state.most_recent_ftp_entrypath = NULL;
    }
    free(ftpc->entrypath);
    ftpc->entrypath = NULL;
  }

  freedirs(ftpc);
  free(ftpc->prevpath);
  ftpc->prevpath = NULL;
  free(ftpc->server_os);
  ftpc->server_os = NULL;

  Curl_pp_disconnect(pp);


  Curl_sec_end(conn);


  return CURLE_OK;
}


static CURLcode ftp_parse_url_path(struct connectdata *conn)
{
  struct Curl_easy *data = conn->data;
  
  struct FTP *ftp = data->req.protop;
  struct ftp_conn *ftpc = &conn->proto.ftpc;
  const char *slash_pos;  
  const char *path_to_use = data->state.path;
  const char *cur_pos;
  const char *filename = NULL;

  cur_pos = path_to_use; 

  ftpc->ctl_valid = FALSE;
  ftpc->cwdfail = FALSE;

  switch(data->set.ftp_filemethod) {
  case FTPFILE_NOCWD:
    

    
    if(path_to_use[0] && (path_to_use[strlen(path_to_use) - 1] != '/') )
      filename = path_to_use;  
    
    break;

  case FTPFILE_SINGLECWD:
    
    if(!path_to_use[0]) {
      
      ftpc->dirdepth = 0;
      break;
    }
    slash_pos = strrchr(cur_pos, '/');
    if(slash_pos || !*cur_pos) {
      size_t dirlen = slash_pos-cur_pos;
      CURLcode result;

      ftpc->dirs = calloc(1, sizeof(ftpc->dirs[0]));
      if(!ftpc->dirs)
        return CURLE_OUT_OF_MEMORY;

      if(!dirlen)
        dirlen++;

      result = Curl_urldecode(conn->data, slash_pos ? cur_pos : "/", slash_pos ? dirlen : 1, &ftpc->dirs[0], NULL, FALSE);


      if(result) {
        freedirs(ftpc);
        return result;
      }
      ftpc->dirdepth = 1; 
      filename = slash_pos ? slash_pos + 1 : cur_pos; 
    }
    else filename = cur_pos;
    break;

  default: 
  case FTPFILE_MULTICWD:
    ftpc->dirdepth = 0;
    ftpc->diralloc = 5; 
    ftpc->dirs = calloc(ftpc->diralloc, sizeof(ftpc->dirs[0]));
    if(!ftpc->dirs)
      return CURLE_OUT_OF_MEMORY;

    
    if(!strcmp(path_to_use, "/")) {
      cur_pos++; 
      ftpc->dirs[0] = strdup("/");
      ftpc->dirdepth++;
    }
    else {
      
      while((slash_pos = strchr(cur_pos, '/')) != NULL) {
        
        ssize_t absolute_dir = ((cur_pos - data->state.path > 0) && (ftpc->dirdepth == 0))?1:0;

        
        if(slash_pos-cur_pos) {
          
          size_t len = slash_pos - cur_pos + absolute_dir;
          CURLcode result = Curl_urldecode(conn->data, cur_pos - absolute_dir, len, &ftpc->dirs[ftpc->dirdepth], NULL, TRUE);


          if(result) {
            freedirs(ftpc);
            return result;
          }
        }
        else {
          cur_pos = slash_pos + 1; 
          if(!ftpc->dirdepth) {
            
            ftpc->dirs[ftpc->dirdepth] = strdup("/");
            if(!ftpc->dirs[ftpc->dirdepth++]) { 
              failf(data, "no memory");
              freedirs(ftpc);
              return CURLE_OUT_OF_MEMORY;
            }
          }
          continue;
        }

        cur_pos = slash_pos + 1; 
        if(++ftpc->dirdepth >= ftpc->diralloc) {
          
          char **bigger;
          ftpc->diralloc *= 2; 
          bigger = realloc(ftpc->dirs, ftpc->diralloc * sizeof(ftpc->dirs[0]));
          if(!bigger) {
            freedirs(ftpc);
            return CURLE_OUT_OF_MEMORY;
          }
          ftpc->dirs = bigger;
        }
      }
    }
    filename = cur_pos;  
    break;
  } 

  if(filename && *filename) {
    CURLcode result = Curl_urldecode(conn->data, filename, 0,  &ftpc->file, NULL, TRUE);

    if(result) {
      freedirs(ftpc);
      return result;
    }
  }
  else ftpc->file = NULL;

  if(data->set.upload && !ftpc->file && (ftp->transfer == FTPTRANSFER_BODY)) {
    
    failf(data, "Uploading to a URL without a file name!");
    return CURLE_URL_MALFORMAT;
  }

  ftpc->cwddone = FALSE; 

  if(ftpc->prevpath) {
    
    size_t dlen;
    char *path;
    CURLcode result = Curl_urldecode(conn->data, data->state.path, 0, &path, &dlen, FALSE);
    if(result) {
      freedirs(ftpc);
      return result;
    }

    dlen -= ftpc->file?strlen(ftpc->file):0;
    if((dlen == strlen(ftpc->prevpath)) && !strncmp(path, ftpc->prevpath, dlen) && (ftpc->prevmethod == data->set.ftp_filemethod)) {

      infof(data, "Request has same path as previous transfer\n");
      ftpc->cwddone = TRUE;
    }
    free(path);
  }

  return CURLE_OK;
}


static CURLcode ftp_dophase_done(struct connectdata *conn, bool connected)
{
  struct FTP *ftp = conn->data->req.protop;
  struct ftp_conn *ftpc = &conn->proto.ftpc;

  if(connected) {
    int completed;
    CURLcode result = ftp_do_more(conn, &completed);

    if(result) {
      close_secondarysocket(conn);
      return result;
    }
  }

  if(ftp->transfer != FTPTRANSFER_BODY)
    
    Curl_setup_transfer(conn, -1, -1, FALSE, NULL, -1, NULL);
  else if(!connected)
    
    conn->bits.do_more = TRUE;

  ftpc->ctl_valid = TRUE; 

  return CURLE_OK;
}


static CURLcode ftp_doing(struct connectdata *conn, bool *dophase_done)
{
  CURLcode result = ftp_multi_statemach(conn, dophase_done);

  if(result)
    DEBUGF(infof(conn->data, "DO phase failed\n"));
  else if(*dophase_done) {
    result = ftp_dophase_done(conn, FALSE );

    DEBUGF(infof(conn->data, "DO phase is complete2\n"));
  }
  return result;
}


static CURLcode ftp_regular_transfer(struct connectdata *conn, bool *dophase_done)

{
  CURLcode result = CURLE_OK;
  bool connected = FALSE;
  struct Curl_easy *data = conn->data;
  struct ftp_conn *ftpc = &conn->proto.ftpc;
  data->req.size = -1; 

  Curl_pgrsSetUploadCounter(data, 0);
  Curl_pgrsSetDownloadCounter(data, 0);
  Curl_pgrsSetUploadSize(data, -1);
  Curl_pgrsSetDownloadSize(data, -1);

  ftpc->ctl_valid = TRUE; 

  result = ftp_perform(conn, &connected, dophase_done);


  if(!result) {

    if(!*dophase_done)
      
      return CURLE_OK;

    result = ftp_dophase_done(conn, connected);

    if(result)
      return result;
  }
  else freedirs(ftpc);

  return result;
}

static CURLcode ftp_setup_connection(struct connectdata *conn)
{
  struct Curl_easy *data = conn->data;
  char *type;
  char command;
  struct FTP *ftp;

  conn->data->req.protop = ftp = malloc(sizeof(struct FTP));
  if(NULL == ftp)
    return CURLE_OUT_OF_MEMORY;

  data->state.path++;   
  data->state.slash_removed = TRUE; 

  
  type = strstr(data->state.path, ";type=");

  if(!type)
    type = strstr(conn->host.rawalloc, ";type=");

  if(type) {
    *type = 0;                     
    command = Curl_raw_toupper(type[6]);
    conn->bits.type_set = TRUE;

    switch(command) {
    case 'A': 
      data->set.prefer_ascii = TRUE;
      break;

    case 'D': 
      data->set.ftp_list_only = TRUE;
      break;

    case 'I': 
    default:
      
      data->set.prefer_ascii = FALSE;
      break;
    }
  }

  
  ftp->bytecountp = &conn->data->req.bytecount;
  ftp->transfer = FTPTRANSFER_BODY;
  ftp->downloadsize = 0;

  
  ftp->user = conn->user;
  ftp->passwd = conn->passwd;
  if(isBadFtpString(ftp->user))
    return CURLE_URL_MALFORMAT;
  if(isBadFtpString(ftp->passwd))
    return CURLE_URL_MALFORMAT;

  conn->proto.ftpc.known_filesize = -1; 

  return CURLE_OK;
}


