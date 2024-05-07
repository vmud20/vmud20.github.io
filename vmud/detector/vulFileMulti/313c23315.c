





































































static bool verifyconnect(curl_socket_t sockfd, int *error);











struct tcp_keepalive {
  u_long onoff;
  u_long keepalivetime;
  u_long keepaliveinterval;
};


static void tcpkeepalive(struct Curl_easy *data, curl_socket_t sockfd)

{
  int optval = data->set.tcp_keepalive?1:0;

  
  if(setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, (void *)&optval, sizeof(optval)) < 0) {
    infof(data, "Failed to set SO_KEEPALIVE on fd %d\n", sockfd);
  }
  else {

    struct tcp_keepalive vals;
    DWORD dummy;
    vals.onoff = 1;
    optval = curlx_sltosi(data->set.tcp_keepidle);
    KEEPALIVE_FACTOR(optval);
    vals.keepalivetime = optval;
    optval = curlx_sltosi(data->set.tcp_keepintvl);
    KEEPALIVE_FACTOR(optval);
    vals.keepaliveinterval = optval;
    if(WSAIoctl(sockfd, SIO_KEEPALIVE_VALS, (LPVOID) &vals, sizeof(vals), NULL, 0, &dummy, NULL, NULL) != 0) {
      infof(data, "Failed to set SIO_KEEPALIVE_VALS on fd %d: %d\n", (int)sockfd, WSAGetLastError());
    }


    optval = curlx_sltosi(data->set.tcp_keepidle);
    KEEPALIVE_FACTOR(optval);
    if(setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPIDLE, (void *)&optval, sizeof(optval)) < 0) {
      infof(data, "Failed to set TCP_KEEPIDLE on fd %d\n", sockfd);
    }


    optval = curlx_sltosi(data->set.tcp_keepintvl);
    KEEPALIVE_FACTOR(optval);
    if(setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPINTVL, (void *)&optval, sizeof(optval)) < 0) {
      infof(data, "Failed to set TCP_KEEPINTVL on fd %d\n", sockfd);
    }


    
    optval = curlx_sltosi(data->set.tcp_keepidle);
    KEEPALIVE_FACTOR(optval);
    if(setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPALIVE, (void *)&optval, sizeof(optval)) < 0) {
      infof(data, "Failed to set TCP_KEEPALIVE on fd %d\n", sockfd);
    }


  }
}

static CURLcode singleipconnect(struct connectdata *conn, const struct Curl_addrinfo *ai, int tempindex);




timediff_t Curl_timeleft(struct Curl_easy *data, struct curltime *nowp, bool duringconnect)

{
  int timeout_set = 0;
  timediff_t timeout_ms = duringconnect?DEFAULT_CONNECT_TIMEOUT:0;
  struct curltime now;

  

  if(data->set.timeout > 0)
    timeout_set |= 1;
  if(duringconnect && (data->set.connecttimeout > 0))
    timeout_set |= 2;

  switch(timeout_set) {
  case 1:
    timeout_ms = data->set.timeout;
    break;
  case 2:
    timeout_ms = data->set.connecttimeout;
    break;
  case 3:
    if(data->set.timeout < data->set.connecttimeout)
      timeout_ms = data->set.timeout;
    else timeout_ms = data->set.connecttimeout;
    break;
  default:
    
    if(!duringconnect)
      
      return 0;
    break;
  }

  if(!nowp) {
    now = Curl_now();
    nowp = &now;
  }

  
  if(duringconnect)
    
    timeout_ms -= Curl_timediff(*nowp, data->progress.t_startsingle);
  else  timeout_ms -= Curl_timediff(*nowp, data->progress.t_startop);

  if(!timeout_ms)
    
    return -1;

  return timeout_ms;
}

static CURLcode bindlocal(struct connectdata *conn, curl_socket_t sockfd, int af, unsigned int scope)
{
  struct Curl_easy *data = conn->data;

  struct Curl_sockaddr_storage sa;
  struct sockaddr *sock = (struct sockaddr *)&sa;  
  curl_socklen_t sizeof_sa = 0; 
  struct sockaddr_in *si4 = (struct sockaddr_in *)&sa;

  struct sockaddr_in6 *si6 = (struct sockaddr_in6 *)&sa;


  struct Curl_dns_entry *h = NULL;
  unsigned short port = data->set.localport; 
  
  int portnum = data->set.localportrange;
  const char *dev = data->set.str[STRING_DEVICE];
  int error;

  
  if(!dev && !port)
    
    return CURLE_OK;

  memset(&sa, 0, sizeof(struct Curl_sockaddr_storage));

  if(dev && (strlen(dev)<255) ) {
    char myhost[256] = "";
    int done = 0; 
    bool is_interface = FALSE;
    bool is_host = FALSE;
    static const char *if_prefix = "if!";
    static const char *host_prefix = "host!";

    if(strncmp(if_prefix, dev, strlen(if_prefix)) == 0) {
      dev += strlen(if_prefix);
      is_interface = TRUE;
    }
    else if(strncmp(host_prefix, dev, strlen(host_prefix)) == 0) {
      dev += strlen(host_prefix);
      is_host = TRUE;
    }

    
    if(!is_host) {

      
      if(setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, dev, (curl_socklen_t)strlen(dev) + 1) == 0) {
        
        return CURLE_OK;
      }


      switch(Curl_if2ip(af, scope, conn->scope_id, dev, myhost, sizeof(myhost))) {
        case IF2IP_NOT_FOUND:
          if(is_interface) {
            
            failf(data, "Couldn't bind to interface '%s'", dev);
            return CURLE_INTERFACE_FAILED;
          }
          break;
        case IF2IP_AF_NOT_SUPPORTED:
          
          return CURLE_UNSUPPORTED_PROTOCOL;
        case IF2IP_FOUND:
          is_interface = TRUE;
          
          infof(data, "Local Interface %s is ip %s using address family %i\n", dev, myhost, af);
          done = 1;
          break;
      }
    }
    if(!is_interface) {
      
      long ipver = conn->ip_version;
      int rc;

      if(af == AF_INET)
        conn->ip_version = CURL_IPRESOLVE_V4;

      else if(af == AF_INET6)
        conn->ip_version = CURL_IPRESOLVE_V6;


      rc = Curl_resolv(conn, dev, 0, FALSE, &h);
      if(rc == CURLRESOLV_PENDING)
        (void)Curl_resolver_wait_resolv(conn, &h);
      conn->ip_version = ipver;

      if(h) {
        
        Curl_printable_address(h->addr, myhost, sizeof(myhost));
        infof(data, "Name '%s' family %i resolved to '%s' family %i\n", dev, af, myhost, h->addr->ai_family);
        Curl_resolv_unlock(data, h);
        if(af != h->addr->ai_family) {
          
          return CURLE_UNSUPPORTED_PROTOCOL;
        }
        done = 1;
      }
      else {
        
        done = -1;
      }
    }

    if(done > 0) {

      
      if(af == AF_INET6) {

        char *scope_ptr = strchr(myhost, '%');
        if(scope_ptr)
          *(scope_ptr++) = 0;

        if(Curl_inet_pton(AF_INET6, myhost, &si6->sin6_addr) > 0) {
          si6->sin6_family = AF_INET6;
          si6->sin6_port = htons(port);

          if(scope_ptr)
            
            si6->sin6_scope_id = atoi(scope_ptr);

        }
        sizeof_sa = sizeof(struct sockaddr_in6);
      }
      else   if((af == AF_INET) && (Curl_inet_pton(AF_INET, myhost, &si4->sin_addr) > 0)) {



        si4->sin_family = AF_INET;
        si4->sin_port = htons(port);
        sizeof_sa = sizeof(struct sockaddr_in);
      }
    }

    if(done < 1) {
      
      data->state.errorbuf = FALSE;
      failf(data, "Couldn't bind to '%s'", dev);
      return CURLE_INTERFACE_FAILED;
    }
  }
  else {
    

    if(af == AF_INET6) {
      si6->sin6_family = AF_INET6;
      si6->sin6_port = htons(port);
      sizeof_sa = sizeof(struct sockaddr_in6);
    }
    else  if(af == AF_INET) {

      si4->sin_family = AF_INET;
      si4->sin_port = htons(port);
      sizeof_sa = sizeof(struct sockaddr_in);
    }
  }

  for(;;) {
    if(bind(sockfd, sock, sizeof_sa) >= 0) {
      
      struct Curl_sockaddr_storage add;
      curl_socklen_t size = sizeof(add);
      memset(&add, 0, sizeof(struct Curl_sockaddr_storage));
      if(getsockname(sockfd, (struct sockaddr *) &add, &size) < 0) {
        char buffer[STRERROR_LEN];
        data->state.os_errno = error = SOCKERRNO;
        failf(data, "getsockname() failed with errno %d: %s", error, Curl_strerror(error, buffer, sizeof(buffer)));
        return CURLE_INTERFACE_FAILED;
      }
      infof(data, "Local port: %hu\n", port);
      conn->bits.bound = TRUE;
      return CURLE_OK;
    }

    if(--portnum > 0) {
      infof(data, "Bind to local port %hu failed, trying next\n", port);
      port++; 
      
      if(sock->sa_family == AF_INET)
        si4->sin_port = ntohs(port);

      else si6->sin6_port = ntohs(port);

    }
    else break;
  }
  {
    char buffer[STRERROR_LEN];
    data->state.os_errno = error = SOCKERRNO;
    failf(data, "bind failed with errno %d: %s", error, Curl_strerror(error, buffer, sizeof(buffer)));
  }

  return CURLE_INTERFACE_FAILED;
}


static bool verifyconnect(curl_socket_t sockfd, int *error)
{
  bool rc = TRUE;

  int err = 0;
  curl_socklen_t errSize = sizeof(err);


  


  Sleep(0);

  SleepEx(0, FALSE);




  if(0 != getsockopt(sockfd, SOL_SOCKET, SO_ERROR, (void *)&err, &errSize))
    err = SOCKERRNO;

  
  if(WSAENOPROTOOPT == err) {
    SET_SOCKERRNO(0);
    err = 0;
  }


  
  if(EBADIOCTL == err) {
    SET_SOCKERRNO(0);
    err = 0;
  }

  if((0 == err) || (EISCONN == err))
    
    rc = TRUE;
  else  rc = FALSE;

  if(error)
    *error = err;

  (void)sockfd;
  if(error)
    *error = SOCKERRNO;

  return rc;
}


static struct Curl_addrinfo *ainext(struct connectdata *conn, int tempindex, bool next)

{
  struct Curl_addrinfo *ai = conn->tempaddr[tempindex];
  if(ai && next)
    ai = ai->ai_next;
  while(ai && (ai->ai_family != conn->tempfamily[tempindex]))
    ai = ai->ai_next;
  conn->tempaddr[tempindex] = ai;
  return ai;
}


static CURLcode trynextip(struct connectdata *conn, int sockindex, int tempindex)

{
  CURLcode result = CURLE_COULDNT_CONNECT;

  
  curl_socket_t fd_to_close = conn->tempsock[tempindex];
  conn->tempsock[tempindex] = CURL_SOCKET_BAD;

  if(sockindex == FIRSTSOCKET) {
    struct Curl_addrinfo *ai = conn->tempaddr[tempindex];

    while(ai) {
      if(ai) {
        result = singleipconnect(conn, ai, tempindex);
        if(result == CURLE_COULDNT_CONNECT) {
          ai = ainext(conn, tempindex, TRUE);
          continue;
        }
      }
      break;
    }
  }

  if(fd_to_close != CURL_SOCKET_BAD)
    Curl_closesocket(conn, fd_to_close);

  return result;
}


void Curl_persistconninfo(struct connectdata *conn)
{
  memcpy(conn->data->info.conn_primary_ip, conn->primary_ip, MAX_IPADR_LEN);
  memcpy(conn->data->info.conn_local_ip, conn->local_ip, MAX_IPADR_LEN);
  conn->data->info.conn_scheme = conn->handler->scheme;
  conn->data->info.conn_protocol = conn->handler->protocol;
  conn->data->info.conn_primary_port = conn->primary_port;
  conn->data->info.conn_local_port = conn->local_port;
}


bool Curl_addr2string(struct sockaddr *sa, curl_socklen_t salen, char *addr, long *port)
{
  struct sockaddr_in *si = NULL;

  struct sockaddr_in6 *si6 = NULL;


  struct sockaddr_un *su = NULL;

  (void)salen;


  switch(sa->sa_family) {
    case AF_INET:
      si = (struct sockaddr_in *)(void *) sa;
      if(Curl_inet_ntop(sa->sa_family, &si->sin_addr, addr, MAX_IPADR_LEN)) {
        unsigned short us_port = ntohs(si->sin_port);
        *port = us_port;
        return TRUE;
      }
      break;

    case AF_INET6:
      si6 = (struct sockaddr_in6 *)(void *) sa;
      if(Curl_inet_ntop(sa->sa_family, &si6->sin6_addr, addr, MAX_IPADR_LEN)) {
        unsigned short us_port = ntohs(si6->sin6_port);
        *port = us_port;
        return TRUE;
      }
      break;


    case AF_UNIX:
      if(salen > (curl_socklen_t)sizeof(sa_family_t)) {
        su = (struct sockaddr_un*)sa;
        msnprintf(addr, MAX_IPADR_LEN, "%s", su->sun_path);
      }
      else addr[0] = 0;
      *port = 0;
      return TRUE;

    default:
      break;
  }

  addr[0] = '\0';
  *port = 0;
  errno = EAFNOSUPPORT;
  return FALSE;
}


void Curl_updateconninfo(struct connectdata *conn, curl_socket_t sockfd)
{
  if(conn->transport == TRNSPRT_TCP) {

    if(!conn->bits.reuse && !conn->bits.tcp_fastopen) {
      struct Curl_easy *data = conn->data;
      char buffer[STRERROR_LEN];
      struct Curl_sockaddr_storage ssrem;
      struct Curl_sockaddr_storage ssloc;
      curl_socklen_t plen;
      curl_socklen_t slen;

      plen = sizeof(struct Curl_sockaddr_storage);
      if(getpeername(sockfd, (struct sockaddr*) &ssrem, &plen)) {
        int error = SOCKERRNO;
        failf(data, "getpeername() failed with errno %d: %s", error, Curl_strerror(error, buffer, sizeof(buffer)));
        return;
      }


      slen = sizeof(struct Curl_sockaddr_storage);
      memset(&ssloc, 0, sizeof(ssloc));
      if(getsockname(sockfd, (struct sockaddr*) &ssloc, &slen)) {
        int error = SOCKERRNO;
        failf(data, "getsockname() failed with errno %d: %s", error, Curl_strerror(error, buffer, sizeof(buffer)));
        return;
      }


      if(!Curl_addr2string((struct sockaddr*)&ssrem, plen, conn->primary_ip, &conn->primary_port)) {
        failf(data, "ssrem inet_ntop() failed with errno %d: %s", errno, Curl_strerror(errno, buffer, sizeof(buffer)));
        return;
      }
      memcpy(conn->ip_addr_str, conn->primary_ip, MAX_IPADR_LEN);


      if(!Curl_addr2string((struct sockaddr*)&ssloc, slen, conn->local_ip, &conn->local_port)) {
        failf(data, "ssloc inet_ntop() failed with errno %d: %s", errno, Curl_strerror(errno, buffer, sizeof(buffer)));
        return;
      }

    }

    (void)sockfd; 

  } 

  
  Curl_persistconninfo(conn);
}


static CURLcode connect_SOCKS(struct connectdata *conn, int sockindex, bool *done)
{
  CURLcode result = CURLE_OK;


  if(conn->bits.socksproxy) {
    
    const char * const host = conn->bits.httpproxy ? conn->http_proxy.host.name :

      conn->bits.conn_to_host ? conn->conn_to_host.name :
      sockindex == SECONDARYSOCKET ? conn->secondaryhostname : conn->host.name;
    const int port = conn->bits.httpproxy ? (int)conn->http_proxy.port :
      sockindex == SECONDARYSOCKET ? conn->secondary_port :
      conn->bits.conn_to_port ? conn->conn_to_port :
      conn->remote_port;
    switch(conn->socks_proxy.proxytype) {
    case CURLPROXY_SOCKS5:
    case CURLPROXY_SOCKS5_HOSTNAME:
      result = Curl_SOCKS5(conn->socks_proxy.user, conn->socks_proxy.passwd, host, port, sockindex, conn, done);
      break;

    case CURLPROXY_SOCKS4:
    case CURLPROXY_SOCKS4A:
      result = Curl_SOCKS4(conn->socks_proxy.user, host, port, sockindex, conn, done);
      break;

    default:
      failf(conn->data, "unknown proxytype option given");
      result = CURLE_COULDNT_CONNECT;
    } 
  }
  else  (void)conn;

    (void)sockindex;

    *done = TRUE; 

  return result;
}


static void post_SOCKS(struct connectdata *conn, int sockindex, bool *connected)

{
  conn->bits.tcpconnect[sockindex] = TRUE;

  *connected = TRUE;
  if(sockindex == FIRSTSOCKET)
    Curl_pgrsTime(conn->data, TIMER_CONNECT); 
  Curl_updateconninfo(conn, conn->sock[sockindex]);
  Curl_verboseconnect(conn);
  conn->data->info.numconnects++; 
}



CURLcode Curl_is_connected(struct connectdata *conn, int sockindex, bool *connected)

{
  struct Curl_easy *data = conn->data;
  CURLcode result = CURLE_OK;
  timediff_t allow;
  int error = 0;
  struct curltime now;
  int rc = 0;
  unsigned int i;

  DEBUGASSERT(sockindex >= FIRSTSOCKET && sockindex <= SECONDARYSOCKET);

  *connected = FALSE; 

  if(conn->bits.tcpconnect[sockindex]) {
    
    *connected = TRUE;
    return CURLE_OK;
  }

  now = Curl_now();

  
  allow = Curl_timeleft(data, &now, TRUE);

  if(allow < 0) {
    
    failf(data, "Connection time-out");
    return CURLE_OPERATION_TIMEDOUT;
  }

  if(SOCKS_STATE(conn->cnnct.state)) {
    
    result = connect_SOCKS(conn, sockindex, connected);
    if(!result && *connected)
      post_SOCKS(conn, sockindex, connected);
    return result;
  }

  for(i = 0; i<2; i++) {
    const int other = i ^ 1;
    if(conn->tempsock[i] == CURL_SOCKET_BAD)
      continue;
    error = 0;

    if(conn->transport == TRNSPRT_QUIC) {
      result = Curl_quic_is_connected(conn, i, connected);
      if(!result && *connected) {
        
        conn->sock[sockindex] = conn->tempsock[i];
        conn->ip_addr = conn->tempaddr[i];
        conn->tempsock[i] = CURL_SOCKET_BAD;
        post_SOCKS(conn, sockindex, connected);
        connkeep(conn, "HTTP/3 default");
        return CURLE_OK;
      }
      if(result)
        error = SOCKERRNO;
    }
    else  {


      
      (void)verifyconnect(conn->tempsock[i], NULL);


      
      rc = SOCKET_WRITABLE(conn->tempsock[i], 0);
    }

    if(rc == 0) { 
      if(Curl_timediff(now, conn->connecttime) >= conn->timeoutms_per_addr[i]) {
        infof(data, "After %" CURL_FORMAT_TIMEDIFF_T "ms connect time, move on!\n", conn->timeoutms_per_addr[i]);
        error = ETIMEDOUT;
      }

      
      if(i == 0 && !conn->bits.parallel_connect && (Curl_timediff(now, conn->connecttime) >= data->set.happy_eyeballs_timeout)) {

        conn->bits.parallel_connect = TRUE; 
        trynextip(conn, sockindex, 1);
      }
    }
    else if(rc == CURL_CSELECT_OUT || conn->bits.tcp_fastopen) {
      if(verifyconnect(conn->tempsock[i], &error)) {
        

        
        conn->sock[sockindex] = conn->tempsock[i];
        conn->ip_addr = conn->tempaddr[i];
        conn->tempsock[i] = CURL_SOCKET_BAD;

        conn->bits.ipv6 = (conn->ip_addr->ai_family == AF_INET6)?TRUE:FALSE;


        
        if(conn->tempsock[other] != CURL_SOCKET_BAD) {
          Curl_closesocket(conn, conn->tempsock[other]);
          conn->tempsock[other] = CURL_SOCKET_BAD;
        }

        
        result = connect_SOCKS(conn, sockindex, connected);
        if(result || !*connected)
          return result;

        post_SOCKS(conn, sockindex, connected);

        return CURLE_OK;
      }
    }
    else if(rc & CURL_CSELECT_ERR) {
      (void)verifyconnect(conn->tempsock[i], &error);
    }

    
    if(error) {
      data->state.os_errno = error;
      SET_SOCKERRNO(error);
      if(conn->tempaddr[i]) {
        CURLcode status;

        char ipaddress[MAX_IPADR_LEN];
        char buffer[STRERROR_LEN];
        Curl_printable_address(conn->tempaddr[i], ipaddress, sizeof(ipaddress));
        infof(data, "connect to %s port %ld failed: %s\n", ipaddress, conn->port, Curl_strerror(error, buffer, sizeof(buffer)));



        conn->timeoutms_per_addr[i] = conn->tempaddr[i]->ai_next == NULL ? allow : allow / 2;
        ainext(conn, i, TRUE);
        status = trynextip(conn, sockindex, i);
        if((status != CURLE_COULDNT_CONNECT) || conn->tempsock[other] == CURL_SOCKET_BAD)
          
          result = status;
      }
    }
  }

  if(result && (conn->tempsock[0] == CURL_SOCKET_BAD) && (conn->tempsock[1] == CURL_SOCKET_BAD)) {

    
    const char *hostname;
    char buffer[STRERROR_LEN];

    
    result = trynextip(conn, sockindex, 1);
    if(!result)
      return result;


    if(conn->bits.socksproxy)
      hostname = conn->socks_proxy.host.name;
    else if(conn->bits.httpproxy)
      hostname = conn->http_proxy.host.name;
    else  if(conn->bits.conn_to_host)

        hostname = conn->conn_to_host.name;
    else hostname = conn->host.name;

    failf(data, "Failed to connect to %s port %ld: %s", hostname, conn->port, Curl_strerror(error, buffer, sizeof(buffer)));


    Curl_quic_disconnect(conn, 0);
    Curl_quic_disconnect(conn, 1);


    if(WSAETIMEDOUT == data->state.os_errno)
      result = CURLE_OPERATION_TIMEDOUT;

    if(ETIMEDOUT == data->state.os_errno)
      result = CURLE_OPERATION_TIMEDOUT;

  }
  else result = CURLE_OK;

  return result;
}

static void tcpnodelay(struct connectdata *conn, curl_socket_t sockfd)
{

  curl_socklen_t onoff = (curl_socklen_t) 1;
  int level = IPPROTO_TCP;

  struct Curl_easy *data = conn->data;
  char buffer[STRERROR_LEN];

  (void) conn;


  if(setsockopt(sockfd, level, TCP_NODELAY, (void *)&onoff, sizeof(onoff)) < 0)
    infof(data, "Could not set TCP_NODELAY: %s\n", Curl_strerror(SOCKERRNO, buffer, sizeof(buffer)));

  (void)conn;
  (void)sockfd;

}



static void nosigpipe(struct connectdata *conn, curl_socket_t sockfd)
{
  struct Curl_easy *data = conn->data;
  int onoff = 1;
  if(setsockopt(sockfd, SOL_SOCKET, SO_NOSIGPIPE, (void *)&onoff, sizeof(onoff)) < 0) {
    char buffer[STRERROR_LEN];
    infof(data, "Could not set SO_NOSIGPIPE: %s\n", Curl_strerror(SOCKERRNO, buffer, sizeof(buffer)));
  }
}










void Curl_sndbufset(curl_socket_t sockfd)
{
  int val = CURL_MAX_WRITE_SIZE + 32;
  int curval = 0;
  int curlen = sizeof(curval);

  static int detectOsState = DETECT_OS_NONE;

  if(detectOsState == DETECT_OS_NONE) {
    if(curlx_verify_windows_version(6, 0, PLATFORM_WINNT, VERSION_GREATER_THAN_EQUAL))
      detectOsState = DETECT_OS_VISTA_OR_LATER;
    else detectOsState = DETECT_OS_PREVISTA;
  }

  if(detectOsState == DETECT_OS_VISTA_OR_LATER)
    return;

  if(getsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (char *)&curval, &curlen) == 0)
    if(curval > val)
      return;

  setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (const char *)&val, sizeof(val));
}



static CURLcode singleipconnect(struct connectdata *conn, const struct Curl_addrinfo *ai, int tempindex)

{
  struct Curl_sockaddr_ex addr;
  int rc = -1;
  int error = 0;
  bool isconnected = FALSE;
  struct Curl_easy *data = conn->data;
  curl_socket_t sockfd;
  CURLcode result;
  char ipaddress[MAX_IPADR_LEN];
  long port;
  bool is_tcp;

  int optval = 1;

  char buffer[STRERROR_LEN];
  curl_socket_t *sockp = &conn->tempsock[tempindex];
  *sockp = CURL_SOCKET_BAD;

  result = Curl_socket(conn, ai, &addr, &sockfd);
  if(result)
    return result;

  
  if(!Curl_addr2string((struct sockaddr*)&addr.sa_addr, addr.addrlen, ipaddress, &port)) {
    
    failf(data, "sa_addr inet_ntop() failed with errno %d: %s", errno, Curl_strerror(errno, buffer, sizeof(buffer)));
    Curl_closesocket(conn, sockfd);
    return CURLE_OK;
  }
  infof(data, "  Trying %s:%ld...\n", ipaddress, port);


  is_tcp = (addr.family == AF_INET || addr.family == AF_INET6) && addr.socktype == SOCK_STREAM;

  is_tcp = (addr.family == AF_INET) && addr.socktype == SOCK_STREAM;

  if(is_tcp && data->set.tcp_nodelay)
    tcpnodelay(conn, sockfd);

  nosigpipe(conn, sockfd);

  Curl_sndbufset(sockfd);

  if(is_tcp && data->set.tcp_keepalive)
    tcpkeepalive(data, sockfd);

  if(data->set.fsockopt) {
    
    Curl_set_in_callback(data, true);
    error = data->set.fsockopt(data->set.sockopt_client, sockfd, CURLSOCKTYPE_IPCXN);

    Curl_set_in_callback(data, false);

    if(error == CURL_SOCKOPT_ALREADY_CONNECTED)
      isconnected = TRUE;
    else if(error) {
      Curl_closesocket(conn, sockfd); 
      return CURLE_ABORTED_BY_CALLBACK;
    }
  }

  
  if(addr.family == AF_INET  || addr.family == AF_INET6  ) {



    result = bindlocal(conn, sockfd, addr.family, Curl_ipv6_scope((struct sockaddr*)&addr.sa_addr));
    if(result) {
      Curl_closesocket(conn, sockfd); 
      if(result == CURLE_UNSUPPORTED_PROTOCOL) {
        
        return CURLE_COULDNT_CONNECT;
      }
      return result;
    }
  }

  
  (void)curlx_nonblock(sockfd, TRUE);

  conn->connecttime = Curl_now();
  if(conn->num_addr > 1) {
    Curl_expire(data, conn->timeoutms_per_addr[0], EXPIRE_DNS_PER_NAME);
    Curl_expire(data, conn->timeoutms_per_addr[1], EXPIRE_DNS_PER_NAME2);
  }

  
  if(!isconnected && (conn->transport != TRNSPRT_UDP)) {
    if(conn->bits.tcp_fastopen) {


      
      if(__builtin_available(macOS 10.11, iOS 9.0, tvOS 9.0, watchOS 2.0, *)) {
        sa_endpoints_t endpoints;
        endpoints.sae_srcif = 0;
        endpoints.sae_srcaddr = NULL;
        endpoints.sae_srcaddrlen = 0;
        endpoints.sae_dstaddr = &addr.sa_addr;
        endpoints.sae_dstaddrlen = addr.addrlen;

        rc = connectx(sockfd, &endpoints, SAE_ASSOCID_ANY, CONNECT_RESUME_ON_READ_WRITE | CONNECT_DATA_IDEMPOTENT, NULL, 0, NULL, NULL);

      }
      else {
        rc = connect(sockfd, &addr.sa_addr, addr.addrlen);
      }

      rc = connect(sockfd, &addr.sa_addr, addr.addrlen);


      if(setsockopt(sockfd, IPPROTO_TCP, TCP_FASTOPEN_CONNECT, (void *)&optval, sizeof(optval)) < 0)
        infof(data, "Failed to enable TCP Fast Open on fd %d\n", sockfd);

      rc = connect(sockfd, &addr.sa_addr, addr.addrlen);

      if(conn->given->flags & PROTOPT_SSL)
        rc = connect(sockfd, &addr.sa_addr, addr.addrlen);
      else rc = 0;

    }
    else {
      rc = connect(sockfd, &addr.sa_addr, addr.addrlen);
    }

    if(-1 == rc)
      error = SOCKERRNO;

    else if(conn->transport == TRNSPRT_QUIC) {
      
      result = Curl_quic_connect(conn, sockfd, tempindex, &addr.sa_addr, addr.addrlen);
      if(result)
        error = SOCKERRNO;
    }

  }
  else {
    *sockp = sockfd;
    return CURLE_OK;
  }

  if(-1 == rc) {
    switch(error) {
    case EINPROGRESS:
    case EWOULDBLOCK:


      
    case EAGAIN:


      result = CURLE_OK;
      break;

    default:
      
      infof(data, "Immediate connect fail for %s: %s\n", ipaddress, Curl_strerror(error, buffer, sizeof(buffer)));
      data->state.os_errno = error;

      
      Curl_closesocket(conn, sockfd);
      result = CURLE_COULDNT_CONNECT;
    }
  }

  if(!result)
    *sockp = sockfd;

  return result;
}



CURLcode Curl_connecthost(struct connectdata *conn,   const struct Curl_dns_entry *remotehost)
{
  struct Curl_easy *data = conn->data;
  struct curltime before = Curl_now();
  CURLcode result = CURLE_COULDNT_CONNECT;
  int i;
  timediff_t timeout_ms = Curl_timeleft(data, &before, TRUE);

  if(timeout_ms < 0) {
    
    failf(data, "Connection time-out");
    return CURLE_OPERATION_TIMEDOUT;
  }

  conn->num_addr = Curl_num_addresses(remotehost->addr);
  conn->tempaddr[0] = conn->tempaddr[1] = remotehost->addr;
  conn->tempsock[0] = conn->tempsock[1] = CURL_SOCKET_BAD;

  
  conn->timeoutms_per_addr[0] = conn->tempaddr[0]->ai_next == NULL ? timeout_ms : timeout_ms / 2;
  conn->timeoutms_per_addr[1] = conn->tempaddr[1]->ai_next == NULL ? timeout_ms : timeout_ms / 2;

  conn->tempfamily[0] = conn->tempaddr[0]? conn->tempaddr[0]->ai_family:0;
  conn->tempfamily[1] = conn->tempfamily[0] == AF_INET6 ? AF_INET : AF_INET6;
  ainext(conn, 1, FALSE); 

  DEBUGF(infof(data, "family0 == %s, family1 == %s\n", conn->tempfamily[0] == AF_INET ? "v4" : "v6", conn->tempfamily[1] == AF_INET ? "v4" : "v6"));


  
  for(i = 0; (i < 2) && result; i++) {
    while(conn->tempaddr[i]) {
      result = singleipconnect(conn, conn->tempaddr[i], i);
      if(!result)
        break;
      ainext(conn, i, TRUE);
    }
  }
  if(result)
    return result;

  Curl_expire(conn->data, data->set.happy_eyeballs_timeout, EXPIRE_HAPPY_EYEBALLS);

  return CURLE_OK;
}

struct connfind {
  struct connectdata *tofind;
  bool found;
};

static int conn_is_conn(struct connectdata *conn, void *param)
{
  struct connfind *f = (struct connfind *)param;
  if(conn == f->tofind) {
    f->found = TRUE;
    return 1;
  }
  return 0;
}


curl_socket_t Curl_getconnectinfo(struct Curl_easy *data, struct connectdata **connp)
{
  DEBUGASSERT(data);

  
  if(data->state.lastconnect && (data->multi_easy || data->multi)) {
    struct connectdata *c = data->state.lastconnect;
    struct connfind find;
    find.tofind = data->state.lastconnect;
    find.found = FALSE;

    Curl_conncache_foreach(data, data->multi_easy? &data->multi_easy->conn_cache:
                           &data->multi->conn_cache, &find, conn_is_conn);

    if(!find.found) {
      data->state.lastconnect = NULL;
      return CURL_SOCKET_BAD;
    }

    if(connp) {
      
      *connp = c;
      c->data = data;
    }
    return c->sock[FIRSTSOCKET];
  }
  else return CURL_SOCKET_BAD;
}


bool Curl_connalive(struct connectdata *conn)
{
  
  if(conn->ssl[FIRSTSOCKET].use) {
    
    if(!Curl_ssl_check_cxn(conn))
      return false;   
  }


  else if(conn->sock[FIRSTSOCKET] == CURL_SOCKET_BAD)
    return false;
  else {
    
    char buf;
    if(recv((RECV_TYPE_ARG1)conn->sock[FIRSTSOCKET], (RECV_TYPE_ARG2)&buf, (RECV_TYPE_ARG3)1, (RECV_TYPE_ARG4)MSG_PEEK) == 0) {
      return false;   
    }
  }

  return true;
}


int Curl_closesocket(struct connectdata *conn, curl_socket_t sock)
{
  if(conn && conn->fclosesocket) {
    if((sock == conn->sock[SECONDARYSOCKET]) && conn->bits.sock_accepted)
      
      conn->bits.sock_accepted = FALSE;
    else {
      int rc;
      Curl_multi_closed(conn->data, sock);
      Curl_set_in_callback(conn->data, true);
      rc = conn->fclosesocket(conn->closesocket_client, sock);
      Curl_set_in_callback(conn->data, false);
      return rc;
    }
  }

  if(conn)
    
    Curl_multi_closed(conn->data, sock);

  sclose(sock);

  return 0;
}


CURLcode Curl_socket(struct connectdata *conn, const struct Curl_addrinfo *ai, struct Curl_sockaddr_ex *addr, curl_socket_t *sockfd)


{
  struct Curl_easy *data = conn->data;
  struct Curl_sockaddr_ex dummy;

  if(!addr)
    
    addr = &dummy;

  

  addr->family = ai->ai_family;
  addr->socktype = (conn->transport == TRNSPRT_TCP) ? SOCK_STREAM : SOCK_DGRAM;
  addr->protocol = conn->transport != TRNSPRT_TCP ? IPPROTO_UDP :
    ai->ai_protocol;
  addr->addrlen = ai->ai_addrlen;

  if(addr->addrlen > sizeof(struct Curl_sockaddr_storage))
     addr->addrlen = sizeof(struct Curl_sockaddr_storage);
  memcpy(&addr->sa_addr, ai->ai_addr, addr->addrlen);

  if(data->set.fopensocket) {
   
    Curl_set_in_callback(data, true);
    *sockfd = data->set.fopensocket(data->set.opensocket_client, CURLSOCKTYPE_IPCXN, (struct curl_sockaddr *)addr);

    Curl_set_in_callback(data, false);
  }
  else  *sockfd = socket(addr->family, addr->socktype, addr->protocol);


  if(*sockfd == CURL_SOCKET_BAD)
    
    return CURLE_COULDNT_CONNECT;

  if(conn->transport == TRNSPRT_QUIC) {
    
    (void)curlx_nonblock(*sockfd, TRUE);
  }


  if(conn->scope_id && (addr->family == AF_INET6)) {
    struct sockaddr_in6 * const sa6 = (void *)&addr->sa_addr;
    sa6->sin6_scope_id = conn->scope_id;
  }


  return CURLE_OK;

}


void Curl_conncontrol(struct connectdata *conn, int ctrl  , const char *reason  )




{
  
  bool closeit = (ctrl == CONNCTRL_CONNECTION) || ((ctrl == CONNCTRL_STREAM) && !(conn->handler->flags & PROTOPT_STREAM));
  DEBUGASSERT(conn);
  if((ctrl == CONNCTRL_STREAM) && (conn->handler->flags & PROTOPT_STREAM))
    DEBUGF(infof(conn->data, "Kill stream: %s\n", reason));
  else if((bit)closeit != conn->bits.close) {
    DEBUGF(infof(conn->data, "Marked for [%s]: %s\n", closeit?"closure":"keep alive", reason));
    conn->bits.close = closeit; 
  }
}


bool Curl_conn_data_pending(struct connectdata *conn, int sockindex)
{
  int readable;
  DEBUGASSERT(conn);

  if(Curl_ssl_data_pending(conn, sockindex) || Curl_recv_has_postponed_data(conn, sockindex))
    return true;

  readable = SOCKET_READABLE(conn->sock[sockindex], 0);
  return (readable > 0 && (readable & CURL_CSELECT_IN));
}
