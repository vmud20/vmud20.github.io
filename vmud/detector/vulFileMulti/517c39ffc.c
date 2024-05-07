

























































void Curl_version_init(void);


static void win32_cleanup(void)
{

  WSACleanup();


  Curl_sspi_global_cleanup();

}


static CURLcode win32_init(void)
{

  WORD wVersionRequested;
  WSADATA wsaData;
  int res;


  Error IPV6_requires_winsock2   wVersionRequested = MAKEWORD(USE_WINSOCK, USE_WINSOCK);



  res = WSAStartup(wVersionRequested, &wsaData);

  if(res != 0)
    
    
    return CURLE_FAILED_INIT;

  
  
  
  
  

  if(LOBYTE(wsaData.wVersion) != LOBYTE(wVersionRequested) || HIBYTE(wsaData.wVersion) != HIBYTE(wVersionRequested) ) {
    

    
    WSACleanup();
    return CURLE_FAILED_INIT;
  }
  

  lwip_init();



  {
    CURLcode result = Curl_sspi_global_init();
    if(result)
      return result;
  }


  return CURLE_OK;
}



static void idna_init (void)
{

  char buf[60];
  UINT cp = GetACP();

  if(!getenv("CHARSET") && cp > 0) {
    snprintf(buf, sizeof(buf), "CHARSET=cp%u", cp);
    putenv(buf);
  }

  

}



static unsigned int  initialized;
static long          init_flags;
















curl_malloc_callback Curl_cmalloc = (curl_malloc_callback)malloc;
curl_free_callback Curl_cfree = (curl_free_callback)free;
curl_realloc_callback Curl_crealloc = (curl_realloc_callback)realloc;
curl_strdup_callback Curl_cstrdup = (curl_strdup_callback)system_strdup;
curl_calloc_callback Curl_ccalloc = (curl_calloc_callback)calloc;

curl_wcsdup_callback Curl_cwcsdup = (curl_wcsdup_callback)_wcsdup;



curl_malloc_callback Curl_cmalloc;
curl_free_callback Curl_cfree;
curl_realloc_callback Curl_crealloc;
curl_strdup_callback Curl_cstrdup;
curl_calloc_callback Curl_ccalloc;







static CURLcode global_init(long flags, bool memoryfuncs)
{
  if(initialized++)
    return CURLE_OK;

  if(memoryfuncs) {
    
    Curl_cmalloc = (curl_malloc_callback)malloc;
    Curl_cfree = (curl_free_callback)free;
    Curl_crealloc = (curl_realloc_callback)realloc;
    Curl_cstrdup = (curl_strdup_callback)system_strdup;
    Curl_ccalloc = (curl_calloc_callback)calloc;

    Curl_cwcsdup = (curl_wcsdup_callback)_wcsdup;

  }

  if(flags & CURL_GLOBAL_SSL)
    if(!Curl_ssl_init()) {
      DEBUGF(fprintf(stderr, "Error: Curl_ssl_init failed\n"));
      return CURLE_FAILED_INIT;
    }

  if(flags & CURL_GLOBAL_WIN32)
    if(win32_init()) {
      DEBUGF(fprintf(stderr, "Error: win32_init failed\n"));
      return CURLE_FAILED_INIT;
    }


  if(!Curl_amiga_init()) {
    DEBUGF(fprintf(stderr, "Error: Curl_amiga_init failed\n"));
    return CURLE_FAILED_INIT;
  }



  if(netware_init()) {
    DEBUGF(fprintf(stderr, "Warning: LONG namespace not available\n"));
  }



  idna_init();


  if(Curl_resolver_global_init()) {
    DEBUGF(fprintf(stderr, "Error: resolver_global_init failed\n"));
    return CURLE_FAILED_INIT;
  }

  (void)Curl_ipv6works();


  if(libssh2_init(0)) {
    DEBUGF(fprintf(stderr, "Error: libssh2_init failed\n"));
    return CURLE_FAILED_INIT;
  }


  if(flags & CURL_GLOBAL_ACK_EINTR)
    Curl_ack_eintr = 1;

  init_flags = flags;

  Curl_version_init();

  return CURLE_OK;
}



CURLcode curl_global_init(long flags)
{
  return global_init(flags, TRUE);
}


CURLcode curl_global_init_mem(long flags, curl_malloc_callback m, curl_free_callback f, curl_realloc_callback r, curl_strdup_callback s, curl_calloc_callback c)

{
  
  if(!m || !f || !r || !s || !c)
    return CURLE_FAILED_INIT;

  if(initialized) {
    
    initialized++;
    return CURLE_OK;
  }

  
  Curl_cmalloc = m;
  Curl_cfree = f;
  Curl_cstrdup = s;
  Curl_crealloc = r;
  Curl_ccalloc = c;

  
  return global_init(flags, FALSE);
}


void curl_global_cleanup(void)
{
  if(!initialized)
    return;

  if(--initialized)
    return;

  Curl_global_host_cache_dtor();

  if(init_flags & CURL_GLOBAL_SSL)
    Curl_ssl_cleanup();

  Curl_resolver_global_cleanup();

  if(init_flags & CURL_GLOBAL_WIN32)
    win32_cleanup();

  Curl_amiga_cleanup();


  (void)libssh2_exit();


  init_flags  = 0;
}


struct Curl_easy *curl_easy_init(void)
{
  CURLcode result;
  struct Curl_easy *data;

  
  if(!initialized) {
    result = curl_global_init(CURL_GLOBAL_DEFAULT);
    if(result) {
      
      DEBUGF(fprintf(stderr, "Error: curl_global_init failed\n"));
      return NULL;
    }
  }

  
  result = Curl_open(&data);
  if(result) {
    DEBUGF(fprintf(stderr, "Error: Curl_open failed\n"));
    return NULL;
  }

  return data;
}




CURLcode curl_easy_setopt(struct Curl_easy *data, CURLoption tag, ...)
{
  va_list arg;
  CURLcode result;

  if(!data)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  va_start(arg, tag);

  result = Curl_setopt(data, tag, arg);

  va_end(arg);
  return result;
}



struct socketmonitor {
  struct socketmonitor *next; 
  struct pollfd socket; 
};

struct events {
  long ms;              
  bool msbump;          
  int num_sockets;      
  struct socketmonitor *list; 
  int running_handles;  
};



static int events_timer(struct Curl_multi *multi,     long timeout_ms, void *userp)

{
  struct events *ev = userp;
  (void)multi;
  if(timeout_ms == -1)
    
    timeout_ms = 0;
  else if(timeout_ms == 0)
    
    timeout_ms = 1; 

  ev->ms = timeout_ms;
  ev->msbump = TRUE;
  return 0;
}



static int poll2cselect(int pollmask)
{
  int omask=0;
  if(pollmask & POLLIN)
    omask |= CURL_CSELECT_IN;
  if(pollmask & POLLOUT)
    omask |= CURL_CSELECT_OUT;
  if(pollmask & POLLERR)
    omask |= CURL_CSELECT_ERR;
  return omask;
}



static short socketcb2poll(int pollmask)
{
  short omask=0;
  if(pollmask & CURL_POLL_IN)
    omask |= POLLIN;
  if(pollmask & CURL_POLL_OUT)
    omask |= POLLOUT;
  return omask;
}


static int events_socket(struct Curl_easy *easy,       curl_socket_t s, int what, void *userp, void *socketp)



{
  struct events *ev = userp;
  struct socketmonitor *m;
  struct socketmonitor *prev=NULL;


  (void) easy;

  (void)socketp;

  m = ev->list;
  while(m) {
    if(m->socket.fd == s) {

      if(what == CURL_POLL_REMOVE) {
        struct socketmonitor *nxt = m->next;
        
        if(prev)
          prev->next = nxt;
        else ev->list = nxt;
        free(m);
        m = nxt;
        infof(easy, "socket cb: socket %d REMOVED\n", s);
      }
      else {
        
        m->socket.events = socketcb2poll(what);
        infof(easy, "socket cb: socket %d UPDATED as %s%s\n", s, what&CURL_POLL_IN?"IN":"", what&CURL_POLL_OUT?"OUT":"");

      }
      break;
    }
    prev = m;
    m = m->next; 
  }
  if(!m) {
    if(what == CURL_POLL_REMOVE) {
      
      
    }
    else {
      m = malloc(sizeof(struct socketmonitor));
      if(m) {
        m->next = ev->list;
        m->socket.fd = s;
        m->socket.events = socketcb2poll(what);
        m->socket.revents = 0;
        ev->list = m;
        infof(easy, "socket cb: socket %d ADDED as %s%s\n", s, what&CURL_POLL_IN?"IN":"", what&CURL_POLL_OUT?"OUT":"");

      }
      else return CURLE_OUT_OF_MEMORY;
    }
  }

  return 0;
}



static void events_setup(struct Curl_multi *multi, struct events *ev)
{
  
  curl_multi_setopt(multi, CURLMOPT_TIMERFUNCTION, events_timer);
  curl_multi_setopt(multi, CURLMOPT_TIMERDATA, ev);

  
  curl_multi_setopt(multi, CURLMOPT_SOCKETFUNCTION, events_socket);
  curl_multi_setopt(multi, CURLMOPT_SOCKETDATA, ev);
}




static CURLcode wait_or_timeout(struct Curl_multi *multi, struct events *ev)
{
  bool done = FALSE;
  CURLMcode mcode;
  CURLcode result = CURLE_OK;

  while(!done) {
    CURLMsg *msg;
    struct socketmonitor *m;
    struct pollfd *f;
    struct pollfd fds[4];
    int numfds=0;
    int pollrc;
    int i;
    struct timeval before;
    struct timeval after;

    
    for(m = ev->list, f=&fds[0]; m; m = m->next) {
      f->fd = m->socket.fd;
      f->events = m->socket.events;
      f->revents = 0;
      
      f++;
      numfds++;
    }

    
    before = curlx_tvnow();

    
    pollrc = Curl_poll(fds, numfds, (int)ev->ms);

    after = curlx_tvnow();

    ev->msbump = FALSE; 

    if(0 == pollrc) {
      
      ev->ms = 0;
      
      mcode = curl_multi_socket_action(multi, CURL_SOCKET_TIMEOUT, 0, &ev->running_handles);
    }
    else if(pollrc > 0) {
      
      for(i = 0; i< numfds; i++) {
        if(fds[i].revents) {
          
          int act = poll2cselect(fds[i].revents); 
          infof(multi->easyp, "call curl_multi_socket_action(socket %d)\n", fds[i].fd);
          mcode = curl_multi_socket_action(multi, fds[i].fd, act, &ev->running_handles);
        }
      }

      if(!ev->msbump)
        
        ev->ms += curlx_tvdiff(after, before);

    }
    else return CURLE_RECV_ERROR;

    if(mcode)
      return CURLE_URL_MALFORMAT; 

    
    msg = curl_multi_info_read(multi, &pollrc);
    if(msg) {
      result = msg->data.result;
      done = TRUE;
    }
  }

  return result;
}



static CURLcode easy_events(struct Curl_multi *multi)
{
  struct events evs= {2, FALSE, 0, NULL, 0};

  
  events_setup(multi, &evs);

  return wait_or_timeout(multi, &evs);
}





static CURLcode easy_transfer(struct Curl_multi *multi)
{
  bool done = FALSE;
  CURLMcode mcode = CURLM_OK;
  CURLcode result = CURLE_OK;
  struct timeval before;
  int without_fds = 0;  

  while(!done && !mcode) {
    int still_running = 0;
    int rc;

    before = curlx_tvnow();
    mcode = curl_multi_wait(multi, NULL, 0, 1000, &rc);

    if(!mcode) {
      if(!rc) {
        struct timeval after = curlx_tvnow();

        
        if(curlx_tvdiff(after, before) <= 10) {
          without_fds++;
          if(without_fds > 2) {
            int sleep_ms = without_fds < 10 ? (1 << (without_fds - 1)) : 1000;
            Curl_wait_ms(sleep_ms);
          }
        }
        else  without_fds = 0;

      }
      else  without_fds = 0;


      mcode = curl_multi_perform(multi, &still_running);
    }

    
    if(!mcode && !still_running) {
      CURLMsg *msg = curl_multi_info_read(multi, &rc);
      if(msg) {
        result = msg->data.result;
        done = TRUE;
      }
    }
  }

  
  if(mcode) {
    result = (mcode == CURLM_OUT_OF_MEMORY) ? CURLE_OUT_OF_MEMORY :
              
              CURLE_BAD_FUNCTION_ARGUMENT;
  }

  return result;
}



static CURLcode easy_perform(struct Curl_easy *data, bool events)
{
  struct Curl_multi *multi;
  CURLMcode mcode;
  CURLcode result = CURLE_OK;
  SIGPIPE_VARIABLE(pipe_st);

  if(!data)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  if(data->multi) {
    failf(data, "easy handle already used in multi handle");
    return CURLE_FAILED_INIT;
  }

  if(data->multi_easy)
    multi = data->multi_easy;
  else {
    
    multi = Curl_multi_handle(1, 3);
    if(!multi)
      return CURLE_OUT_OF_MEMORY;
    data->multi_easy = multi;
  }

  
  curl_multi_setopt(multi, CURLMOPT_MAXCONNECTS, data->set.maxconnects);

  mcode = curl_multi_add_handle(multi, data);
  if(mcode) {
    curl_multi_cleanup(multi);
    if(mcode == CURLM_OUT_OF_MEMORY)
      return CURLE_OUT_OF_MEMORY;
    else return CURLE_FAILED_INIT;
  }

  sigpipe_ignore(data, &pipe_st);

  
  data->multi = multi;

  
  result = events ? easy_events(multi) : easy_transfer(multi);

  
  (void)curl_multi_remove_handle(multi, data);

  sigpipe_restore(&pipe_st);

  
  return result;
}



CURLcode curl_easy_perform(struct Curl_easy *data)
{
  return easy_perform(data, FALSE);
}



CURLcode curl_easy_perform_ev(struct Curl_easy *data)
{
  return easy_perform(data, TRUE);
}




void curl_easy_cleanup(struct Curl_easy *data)
{
  SIGPIPE_VARIABLE(pipe_st);

  if(!data)
    return;

  sigpipe_ignore(data, &pipe_st);
  Curl_close(data);
  sigpipe_restore(&pipe_st);
}



CURLcode curl_easy_getinfo(struct Curl_easy *data, CURLINFO info, ...)
{
  va_list arg;
  void *paramp;
  CURLcode result;

  va_start(arg, info);
  paramp = va_arg(arg, void *);

  result = Curl_getinfo(data, info, paramp);

  va_end(arg);
  return result;
}


struct Curl_easy *curl_easy_duphandle(struct Curl_easy *data)
{
  struct Curl_easy *outcurl = calloc(1, sizeof(struct Curl_easy));
  if(NULL == outcurl)
    goto fail;

  
  outcurl->state.headerbuff = malloc(HEADERSIZE);
  if(!outcurl->state.headerbuff)
    goto fail;
  outcurl->state.headersize = HEADERSIZE;

  
  if(Curl_dupset(outcurl, data))
    goto fail;

  
  outcurl->state.conn_cache = NULL;

  outcurl->state.lastconnect = NULL;

  outcurl->progress.flags    = data->progress.flags;
  outcurl->progress.callback = data->progress.callback;

  if(data->cookies) {
    
    outcurl->cookies = Curl_cookie_init(data, data->cookies->filename, outcurl->cookies, data->set.cookiesession);


    if(!outcurl->cookies)
      goto fail;
  }

  
  if(data->change.cookielist) {
    outcurl->change.cookielist = Curl_slist_duplicate(data->change.cookielist);
    if(!outcurl->change.cookielist)
      goto fail;
  }

  if(data->change.url) {
    outcurl->change.url = strdup(data->change.url);
    if(!outcurl->change.url)
      goto fail;
    outcurl->change.url_alloc = TRUE;
  }

  if(data->change.referer) {
    outcurl->change.referer = strdup(data->change.referer);
    if(!outcurl->change.referer)
      goto fail;
    outcurl->change.referer_alloc = TRUE;
  }

  
  if(Curl_resolver_duphandle(&outcurl->state.resolver, data->state.resolver))
    goto fail;

  Curl_convert_setup(outcurl);

  outcurl->magic = CURLEASY_MAGIC_NUMBER;

  

  return outcurl;

  fail:

  if(outcurl) {
    curl_slist_free_all(outcurl->change.cookielist);
    outcurl->change.cookielist = NULL;
    Curl_safefree(outcurl->state.headerbuff);
    Curl_safefree(outcurl->change.url);
    Curl_safefree(outcurl->change.referer);
    Curl_freeset(outcurl);
    free(outcurl);
  }

  return NULL;
}


void curl_easy_reset(struct Curl_easy *data)
{
  Curl_safefree(data->state.pathbuffer);

  data->state.path = NULL;

  Curl_free_request_state(data);

  
  Curl_freeset(data);
  memset(&data->set, 0, sizeof(struct UserDefined));
  (void)Curl_init_userdefined(&data->set);

  
  memset(&data->progress, 0, sizeof(struct Progress));

  
  Curl_initinfo(data);

  data->progress.flags |= PGRS_HIDE;
  data->state.current_speed = -1; 
}


CURLcode curl_easy_pause(struct Curl_easy *data, int action)
{
  struct SingleRequest *k = &data->req;
  CURLcode result = CURLE_OK;

  
  int newstate = k->keepon &~ (KEEP_RECV_PAUSE| KEEP_SEND_PAUSE);

  
  newstate |= ((action & CURLPAUSE_RECV)?KEEP_RECV_PAUSE:0) | ((action & CURLPAUSE_SEND)?KEEP_SEND_PAUSE:0);

  
  k->keepon = newstate;

  if(!(newstate & KEEP_RECV_PAUSE) && data->state.tempwrite) {
    

    
    char *tempwrite = data->state.tempwrite;

    data->state.tempwrite = NULL;
    result = Curl_client_chop_write(data->easy_conn, data->state.tempwritetype, tempwrite, data->state.tempwritesize);
    free(tempwrite);
  }

  
  if(!result && ((newstate&(KEEP_RECV_PAUSE|KEEP_SEND_PAUSE)) != (KEEP_RECV_PAUSE|KEEP_SEND_PAUSE)) )

    Curl_expire(data, 0); 

  return result;
}


static CURLcode easy_connection(struct Curl_easy *data, curl_socket_t *sfd, struct connectdata **connp)

{
  if(data == NULL)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  
  if(!data->set.connect_only) {
    failf(data, "CONNECT_ONLY is required!");
    return CURLE_UNSUPPORTED_PROTOCOL;
  }

  *sfd = Curl_getconnectinfo(data, connp);

  if(*sfd == CURL_SOCKET_BAD) {
    failf(data, "Failed to get recent socket");
    return CURLE_UNSUPPORTED_PROTOCOL;
  }

  return CURLE_OK;
}


CURLcode curl_easy_recv(struct Curl_easy *data, void *buffer, size_t buflen, size_t *n)
{
  curl_socket_t sfd;
  CURLcode result;
  ssize_t n1;
  struct connectdata *c;

  result = easy_connection(data, &sfd, &c);
  if(result)
    return result;

  *n = 0;
  result = Curl_read(c, sfd, buffer, buflen, &n1);

  if(result)
    return result;

  *n = (size_t)n1;

  return CURLE_OK;
}


CURLcode curl_easy_send(struct Curl_easy *data, const void *buffer, size_t buflen, size_t *n)
{
  curl_socket_t sfd;
  CURLcode result;
  ssize_t n1;
  struct connectdata *c = NULL;

  result = easy_connection(data, &sfd, &c);
  if(result)
    return result;

  *n = 0;
  result = Curl_write(c, sfd, buffer, buflen, &n1);

  if(n1 == -1)
    return CURLE_SEND_ERROR;

  
  if(!result && !n1)
    return CURLE_AGAIN;

  *n = (size_t)n1;

  return result;
}
