





















void PrintInHex(char *buf, int len);

rfbBool errorMessageOnReadFailure = TRUE;



rfbBool ReadFromRFBServer(rfbClient* client, char *out, unsigned int n)
{


	char* oout=out;
	unsigned int nn=n;
	rfbClientLog("ReadFromRFBServer %d bytes\n",n);


  
  if(!out)
    return FALSE;

  if (client->serverPort==-1) {
    
    rfbVNCRec* rec = client->vncRec;
    struct timeval tv;

    if (rec->readTimestamp) {
      rec->readTimestamp = FALSE;
      if (!fread(&tv,sizeof(struct timeval),1,rec->file))
        return FALSE;

      tv.tv_sec = rfbClientSwap32IfLE (tv.tv_sec);
      tv.tv_usec = rfbClientSwap32IfLE (tv.tv_usec);

      if (rec->tv.tv_sec!=0 && !rec->doNotSleep) {
        struct timeval diff;
        diff.tv_sec = tv.tv_sec - rec->tv.tv_sec;
        diff.tv_usec = tv.tv_usec - rec->tv.tv_usec;
        if(diff.tv_usec<0) {
	  diff.tv_sec--;
	  diff.tv_usec+=1000000;
        }

        sleep (diff.tv_sec);
        usleep (diff.tv_usec);

	Sleep (diff.tv_sec * 1000 + diff.tv_usec/1000);

      }

      rec->tv=tv;
    }
    
    return (fread(out,1,n,rec->file) != n ? FALSE : TRUE);
  }
  
  if (n <= client->buffered) {
    memcpy(out, client->bufoutptr, n);
    client->bufoutptr += n;
    client->buffered -= n;

    goto hexdump;

    return TRUE;
  }

  memcpy(out, client->bufoutptr, client->buffered);

  out += client->buffered;
  n -= client->buffered;

  client->bufoutptr = client->buf;
  client->buffered = 0;

  if (n <= RFB_BUF_SIZE) {

    while (client->buffered < n) {
      int i;
      if (client->tlsSession)
        i = ReadFromTLS(client, client->buf + client->buffered, RFB_BUF_SIZE - client->buffered);
      else  if (client->saslconn)

        i = ReadFromSASL(client, client->buf + client->buffered, RFB_BUF_SIZE - client->buffered);
      else {

        i = read(client->sock, client->buf + client->buffered, RFB_BUF_SIZE - client->buffered);

	if (i < 0) errno=WSAGetLastError();


      }

  
      if (i <= 0) {
	if (i < 0) {
	  if (errno == EWOULDBLOCK || errno == EAGAIN) {
	    
	    WaitForMessage(client, 100000);
	    i = 0;
	  } else {
	    rfbClientErr("read (%d: %s)\n",errno,strerror(errno));
	    return FALSE;
	  }
	} else {
	  if (errorMessageOnReadFailure) {
	    rfbClientLog("VNC server closed connection\n");
	  }
	  return FALSE;
	}
      }
      client->buffered += i;
    }

    memcpy(out, client->bufoutptr, n);
    client->bufoutptr += n;
    client->buffered -= n;

  } else {

    while (n > 0) {
      int i;
      if (client->tlsSession)
        i = ReadFromTLS(client, out, n);
      else  if (client->saslconn)

        i = ReadFromSASL(client, out, n);
      else  i = read(client->sock, out, n);


      if (i <= 0) {
	if (i < 0) {

	  errno=WSAGetLastError();

	  if (errno == EWOULDBLOCK || errno == EAGAIN) {
	    
	    WaitForMessage(client, 100000);
	    i = 0;
	  } else {
	    rfbClientErr("read (%s)\n",strerror(errno));
	    return FALSE;
	  }
	} else {
	  if (errorMessageOnReadFailure) {
	    rfbClientLog("VNC server closed connection\n");
	  }
	  return FALSE;
	}
      }
      out += i;
      n -= i;
    }
  }


hexdump:
  { unsigned int ii;
    for(ii=0;ii<nn;ii++)
      fprintf(stderr,"%02x ",(unsigned char)oout[ii]);
    fprintf(stderr,"\n");
  }


  return TRUE;
}




rfbBool WriteToRFBServer(rfbClient* client, const char *buf, unsigned int n)
{
  fd_set fds;
  int i = 0;
  int j;
  const char *obuf = buf;

  const char *output;
  unsigned int outputlen;
  int err;


  if (client->serverPort==-1)
    return TRUE; 

  if (client->tlsSession) {
    
    i = WriteToTLS(client, buf, n);
    if (i <= 0) return FALSE;

    return TRUE;
  }

  if (client->saslconn) {
    err = sasl_encode(client->saslconn, buf, n, &output, &outputlen);

    if (err != SASL_OK) {
      rfbClientLog("Failed to encode SASL data %s", sasl_errstring(err, NULL, NULL));
      return FALSE;
    }
    obuf = output;
    n = outputlen;
  }


  while (i < n) {
    j = write(client->sock, obuf + i, (n - i));
    if (j <= 0) {
      if (j < 0) {

	 errno=WSAGetLastError();

	if (errno == EWOULDBLOCK ||  errno == ENOENT ||  errno == EAGAIN) {



	  FD_ZERO(&fds);
	  FD_SET(client->sock,&fds);

	  if (select(client->sock+1, NULL, &fds, NULL, NULL) <= 0) {
	    rfbClientErr("select\n");
	    return FALSE;
	  }
	  j = 0;
	} else {
	  rfbClientErr("write\n");
	  return FALSE;
	}
      } else {
	rfbClientLog("write failed\n");
	return FALSE;
      }
    }
    i += j;
  }
  return TRUE;
}


static rfbBool WaitForConnected(int socket, unsigned int secs)
{
  fd_set writefds;
  fd_set exceptfds;
  struct timeval timeout;

  timeout.tv_sec=secs;
  timeout.tv_usec=0;

  FD_ZERO(&writefds);
  FD_SET(socket, &writefds);
  FD_ZERO(&exceptfds);
  FD_SET(socket, &exceptfds);
  if (select(socket+1, NULL, &writefds, &exceptfds, &timeout)==1) {

    if (FD_ISSET(socket, &exceptfds))
      return FALSE;

    int so_error;
    socklen_t len = sizeof so_error;
    getsockopt(socket, SOL_SOCKET, SO_ERROR, &so_error, &len);
    if (so_error!=0)
      return FALSE;

    return TRUE;
  }

  return FALSE;
}


rfbSocket ConnectClientToTcpAddr(unsigned int host, int port)
{
  rfbSocket sock = ConnectClientToTcpAddrWithTimeout(host, port, DEFAULT_CONNECT_TIMEOUT);
  
  if (sock != RFB_INVALID_SOCKET) {
    SetBlocking(sock);
  }
  return sock;
}

rfbSocket ConnectClientToTcpAddrWithTimeout(unsigned int host, int port, unsigned int timeout)
{
  rfbSocket sock;
  struct sockaddr_in addr;
  int one = 1;

  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = host;

  sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock == RFB_INVALID_SOCKET) {

    errno=WSAGetLastError();

    rfbClientErr("ConnectToTcpAddr: socket (%s)\n",strerror(errno));
    return RFB_INVALID_SOCKET;
  }

  if (!SetNonBlocking(sock))
    return FALSE;

  if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {

    errno=WSAGetLastError();

    if (!((errno == EWOULDBLOCK || errno == EINPROGRESS) && WaitForConnected(sock, timeout))) {
      rfbClientErr("ConnectToTcpAddr: connect\n");
      rfbCloseSocket(sock);
      return RFB_INVALID_SOCKET;
    }
  }

  if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&one, sizeof(one)) < 0) {
    rfbClientErr("ConnectToTcpAddr: setsockopt\n");
    rfbCloseSocket(sock);
    return RFB_INVALID_SOCKET;
  }

  return sock;
}

rfbSocket ConnectClientToTcpAddr6(const char *hostname, int port)
{
  rfbSocket sock = ConnectClientToTcpAddr6WithTimeout(hostname, port, DEFAULT_CONNECT_TIMEOUT);
  
  if (sock != RFB_INVALID_SOCKET) {
    SetBlocking(sock);
  }
  return sock;
}

rfbSocket ConnectClientToTcpAddr6WithTimeout(const char *hostname, int port, unsigned int timeout)
{

  rfbSocket sock;
  int n;
  struct addrinfo hints, *res, *ressave;
  char port_s[10];
  int one = 1;

  snprintf(port_s, 10, "%d", port);
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  if ((n = getaddrinfo(strcmp(hostname,"") == 0 ? "localhost": hostname, port_s, &hints, &res)))
  {
    rfbClientErr("ConnectClientToTcpAddr6: getaddrinfo (%s)\n", gai_strerror(n));
    return RFB_INVALID_SOCKET;
  }

  ressave = res;
  sock = RFB_INVALID_SOCKET;
  while (res)
  {
    sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock != RFB_INVALID_SOCKET)
    {
      if (SetNonBlocking(sock)) {
        if (connect(sock, res->ai_addr, res->ai_addrlen) == 0) {
          break;
        } else {

          errno=WSAGetLastError();

          if ((errno == EWOULDBLOCK || errno == EINPROGRESS) && WaitForConnected(sock, timeout))
            break;
          rfbCloseSocket(sock);
          sock = RFB_INVALID_SOCKET;
        }
      } else {
        rfbCloseSocket(sock);
        sock = RFB_INVALID_SOCKET;
      }
    }
    res = res->ai_next;
  }
  freeaddrinfo(ressave);

  if (sock == RFB_INVALID_SOCKET)
  {
    rfbClientErr("ConnectClientToTcpAddr6: connect\n");
    return RFB_INVALID_SOCKET;
  }

  if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&one, sizeof(one)) < 0) {
    rfbClientErr("ConnectToTcpAddr: setsockopt\n");
    rfbCloseSocket(sock);
    return RFB_INVALID_SOCKET;
  }

  return sock;



  rfbClientErr("ConnectClientToTcpAddr6: IPv6 disabled\n");
  return RFB_INVALID_SOCKET;


}

rfbSocket ConnectClientToUnixSock(const char *sockFile)
{
  rfbSocket sock = ConnectClientToUnixSockWithTimeout(sockFile, DEFAULT_CONNECT_TIMEOUT);
  
  if (sock != RFB_INVALID_SOCKET) {
    SetBlocking(sock);
  }
  return sock;
}

rfbSocket ConnectClientToUnixSockWithTimeout(const char *sockFile, unsigned int timeout)
{

  rfbClientErr("Windows doesn't support UNIX sockets\n");
  return RFB_INVALID_SOCKET;

  rfbSocket sock;
  struct sockaddr_un addr;
  addr.sun_family = AF_UNIX;
  if(strlen(sockFile) + 1 > sizeof(addr.sun_path)) {
      rfbClientErr("ConnectToUnixSock: socket file name too long\n");
      return RFB_INVALID_SOCKET;
  }
  strcpy(addr.sun_path, sockFile);

  sock = socket(AF_UNIX, SOCK_STREAM, 0);
  if (sock == RFB_INVALID_SOCKET) {
    rfbClientErr("ConnectToUnixSock: socket (%s)\n",strerror(errno));
    return RFB_INVALID_SOCKET;
  }

  if (!SetNonBlocking(sock))
    return RFB_INVALID_SOCKET;

  if (connect(sock, (struct sockaddr *)&addr, sizeof(addr.sun_family) + strlen(addr.sun_path)) < 0 && !(errno == EINPROGRESS && WaitForConnected(sock, timeout))) {
    rfbClientErr("ConnectToUnixSock: connect\n");
    rfbCloseSocket(sock);
    return RFB_INVALID_SOCKET;
  }

  return sock;

}





int FindFreeTcpPort(void)
{
  rfbSocket sock;
  int port;
  struct sockaddr_in addr;

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);

  sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock == RFB_INVALID_SOCKET) {
    rfbClientErr(": FindFreeTcpPort: socket\n");
    return 0;
  }

  for (port = TUNNEL_PORT_OFFSET + 99; port > TUNNEL_PORT_OFFSET; port--) {
    addr.sin_port = htons((unsigned short)port);
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
      rfbCloseSocket(sock);
      return port;
    }
  }

  rfbCloseSocket(sock);
  return 0;
}




rfbSocket ListenAtTcpPort(int port)
{
  return ListenAtTcpPortAndAddress(port, NULL);
}





rfbSocket ListenAtTcpPortAndAddress(int port, const char *address)
{
  rfbSocket sock = RFB_INVALID_SOCKET;
  int one = 1;

  struct sockaddr_in addr;

  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  if (address) {
    addr.sin_addr.s_addr = inet_addr(address);
  } else {
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
  }

  sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock == RFB_INVALID_SOCKET) {
    rfbClientErr("ListenAtTcpPort: socket\n");
    return RFB_INVALID_SOCKET;
  }

  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof(one)) < 0) {
    rfbClientErr("ListenAtTcpPort: setsockopt\n");
    rfbCloseSocket(sock);
    return RFB_INVALID_SOCKET;
  }

  if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    rfbClientErr("ListenAtTcpPort: bind\n");
    rfbCloseSocket(sock);
    return RFB_INVALID_SOCKET;
  }


  int rv;
  struct addrinfo hints, *servinfo, *p;
  char port_str[8];

  snprintf(port_str, 8, "%d", port);

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE; 

  if ((rv = getaddrinfo(address, port_str, &hints, &servinfo)) != 0) {
    rfbClientErr("ListenAtTcpPortAndAddress: error in getaddrinfo: %s\n", gai_strerror(rv));
    return RFB_INVALID_SOCKET;
  }

  
  for(p = servinfo; p != NULL; p = p->ai_next) {
    if ((sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == RFB_INVALID_SOCKET) {
      continue;
    }


    
    if (p->ai_family == AF_INET6 && setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&one, sizeof(one)) < 0) {
      rfbClientErr("ListenAtTcpPortAndAddress: error in setsockopt IPV6_V6ONLY: %s\n", strerror(errno));
      rfbCloseSocket(sock);
      freeaddrinfo(servinfo);
      return RFB_INVALID_SOCKET;
    }


    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof(one)) < 0) {
      rfbClientErr("ListenAtTcpPortAndAddress: error in setsockopt SO_REUSEADDR: %s\n", strerror(errno));
      rfbCloseSocket(sock);
      freeaddrinfo(servinfo);
      return RFB_INVALID_SOCKET;
    }

    if (bind(sock, p->ai_addr, p->ai_addrlen) < 0) {
      rfbCloseSocket(sock);
      continue;
    }

    break;
  }

  if (p == NULL)  {
    rfbClientErr("ListenAtTcpPortAndAddress: error in bind: %s\n", strerror(errno));
    return RFB_INVALID_SOCKET;
  }

  
  freeaddrinfo(servinfo);


  if (listen(sock, 5) < 0) {
    rfbClientErr("ListenAtTcpPort: listen\n");
    rfbCloseSocket(sock);
    return RFB_INVALID_SOCKET;
  }

  return sock;
}




rfbSocket AcceptTcpConnection(rfbSocket listenSock)
{
  rfbSocket sock;
  struct sockaddr_in addr;
  socklen_t addrlen = sizeof(addr);
  int one = 1;

  sock = accept(listenSock, (struct sockaddr *) &addr, &addrlen);
  if (sock == RFB_INVALID_SOCKET) {
    rfbClientErr("AcceptTcpConnection: accept\n");
    return RFB_INVALID_SOCKET;
  }

  if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&one, sizeof(one)) < 0) {
    rfbClientErr("AcceptTcpConnection: setsockopt\n");
    rfbCloseSocket(sock);
    return RFB_INVALID_SOCKET;
  }

  return sock;
}




rfbBool SetNonBlocking(rfbSocket sock)
{

  unsigned long block=1;
  if(ioctlsocket(sock, FIONBIO, &block) == SOCKET_ERROR) {
    errno=WSAGetLastError();

  int flags = fcntl(sock, F_GETFL);
  if(flags < 0 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {

    rfbClientErr("Setting socket to non-blocking failed: %s\n",strerror(errno));
    return FALSE;
  }
  return TRUE;
}


rfbBool SetBlocking(rfbSocket sock)
{

  unsigned long block=0;
  if(ioctlsocket(sock, FIONBIO, &block) == SOCKET_ERROR) {
    errno=WSAGetLastError();

  int flags = fcntl(sock, F_GETFL);
  if(flags < 0 || fcntl(sock, F_SETFL, flags & ~O_NONBLOCK) < 0) {

    rfbClientErr("Setting socket to blocking failed: %s\n",strerror(errno));
    return FALSE;
  }
  return TRUE;
}




rfbBool SetDSCP(rfbSocket sock, int dscp)
{

  rfbClientErr("Setting of QoS IP DSCP not implemented for Windows\n");
  return TRUE;

  int level, cmd;
  struct sockaddr addr;
  socklen_t addrlen = sizeof(addr);

  if(getsockname(sock, &addr, &addrlen) != 0) {
    rfbClientErr("Setting socket QoS failed while getting socket address: %s\n",strerror(errno));
    return FALSE;
  }

  switch(addr.sa_family)
    {

    case AF_INET6:
      level = IPPROTO_IPV6;
      cmd = IPV6_TCLASS;
      break;

    case AF_INET:
      level = IPPROTO_IP;
      cmd = IP_TOS;
      break;
    default:
      rfbClientErr("Setting socket QoS failed: Not bound to IP address");
      return FALSE;
    }

  if(setsockopt(sock, level, cmd, (void*)&dscp, sizeof(dscp)) != 0) {
    rfbClientErr("Setting socket QoS failed: %s\n", strerror(errno));
    return FALSE;
  }

  return TRUE;

}





rfbBool StringToIPAddr(const char *str, unsigned int *addr)
{
  struct hostent *hp;

  if (strcmp(str,"") == 0) {
    *addr = htonl(INADDR_LOOPBACK); 
    return TRUE;
  }

  *addr = inet_addr(str);

  if (*addr != -1)
    return TRUE;

  hp = gethostbyname(str);

  if (hp) {
    *addr = *(unsigned int *)hp->h_addr;
    return TRUE;
  }

  return FALSE;
}




rfbBool SameMachine(rfbSocket sock)
{
  struct sockaddr_in peeraddr, myaddr;
  socklen_t addrlen = sizeof(struct sockaddr_in);

  getpeername(sock, (struct sockaddr *)&peeraddr, &addrlen);
  getsockname(sock, (struct sockaddr *)&myaddr, &addrlen);

  return (peeraddr.sin_addr.s_addr == myaddr.sin_addr.s_addr);
}




void PrintInHex(char *buf, int len)
{
  int i, j;
  char c, str[17];

  str[16] = 0;

  rfbClientLog("ReadExact: ");

  for (i = 0; i < len; i++)
    {
      if ((i % 16 == 0) && (i != 0)) {
	rfbClientLog("           ");
      }
      c = buf[i];
      str[i % 16] = (((c > 31) && (c < 127)) ? c : '.');
      rfbClientLog("%02x ",(unsigned char)c);
      if ((i % 4) == 3)
	rfbClientLog(" ");
      if ((i % 16) == 15)
	{
	  rfbClientLog("%s\n",str);
	}
    }
  if ((i % 16) != 0)
    {
      for (j = i % 16; j < 16; j++)
	{
	  rfbClientLog("   ");
	  if ((j % 4) == 3) rfbClientLog(" ");
	}
      str[i % 16] = 0;
      rfbClientLog("%s\n",str);
    }

  fflush(stderr);
}

int WaitForMessage(rfbClient* client,unsigned int usecs)
{
  fd_set fds;
  struct timeval timeout;
  int num;

  if (client->serverPort==-1)
    
    return 1;
  
  timeout.tv_sec=(usecs/1000000);
  timeout.tv_usec=(usecs%1000000);

  FD_ZERO(&fds);
  FD_SET(client->sock,&fds);

  num=select(client->sock+1, &fds, NULL, NULL, &timeout);
  if(num<0) {

    errno=WSAGetLastError();

    rfbClientLog("Waiting for message failed: %d (%s)\n",errno,strerror(errno));
  }

  return num;
}

