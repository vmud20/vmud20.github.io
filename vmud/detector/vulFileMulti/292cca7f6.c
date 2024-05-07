
































































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

  if(!Curl_ssl_init()) {
    DEBUGF(fprintf(stderr, "Error: Curl_ssl_init failed\n"));
    goto fail;
  }


  if(Curl_win32_init(flags)) {
    DEBUGF(fprintf(stderr, "Error: win32_init failed\n"));
    goto fail;
  }



  if(!Curl_amiga_init()) {
    DEBUGF(fprintf(stderr, "Error: Curl_amiga_init failed\n"));
    goto fail;
  }



  if(netware_init()) {
    DEBUGF(fprintf(stderr, "Warning: LONG namespace not available\n"));
  }


  if(Curl_resolver_global_init()) {
    DEBUGF(fprintf(stderr, "Error: resolver_global_init failed\n"));
    goto fail;
  }


  if(Curl_ssh_init()) {
    goto fail;
  }



  if(WS_SUCCESS != wolfSSH_Init()) {
    DEBUGF(fprintf(stderr, "Error: wolfSSH_Init failed\n"));
    return CURLE_FAILED_INIT;
  }


  init_flags = flags;

  return CURLE_OK;

  fail:
  initialized--; 
  return CURLE_FAILED_INIT;
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

  Curl_ssl_cleanup();
  Curl_resolver_global_cleanup();


  Curl_win32_cleanup(init_flags);


  Curl_amiga_cleanup();

  Curl_ssh_cleanup();


  (void)wolfSSH_Cleanup();


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
  int omask = 0;
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
  short omask = 0;
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
  struct socketmonitor *prev = NULL;


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
        infof(easy, "socket cb: socket %d UPDATED as %s%s\n", s, (what&CURL_POLL_IN)?"IN":"", (what&CURL_POLL_OUT)?"OUT":"");

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
        infof(easy, "socket cb: socket %d ADDED as %s%s\n", s, (what&CURL_POLL_IN)?"IN":"", (what&CURL_POLL_OUT)?"OUT":"");

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
  CURLMcode mcode = CURLM_OK;
  CURLcode result = CURLE_OK;

  while(!done) {
    CURLMsg *msg;
    struct socketmonitor *m;
    struct pollfd *f;
    struct pollfd fds[4];
    int numfds = 0;
    int pollrc;
    int i;
    struct curltime before;
    struct curltime after;

    
    for(m = ev->list, f = &fds[0]; m; m = m->next) {
      f->fd = m->socket.fd;
      f->events = m->socket.events;
      f->revents = 0;
      
      f++;
      numfds++;
    }

    
    before = Curl_now();

    
    pollrc = Curl_poll(fds, numfds, ev->ms);

    after = Curl_now();

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

      if(!ev->msbump) {
        
        timediff_t timediff = Curl_timediff(after, before);
        if(timediff > 0) {
          if(timediff > ev->ms)
            ev->ms = 0;
          else ev->ms -= (long)timediff;
        }
      }
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
  
  static struct events evs = {2, FALSE, 0, NULL, 0};

  
  events_setup(multi, &evs);

  return wait_or_timeout(multi, &evs);
}





static CURLcode easy_transfer(struct Curl_multi *multi)
{
  bool done = FALSE;
  CURLMcode mcode = CURLM_OK;
  CURLcode result = CURLE_OK;

  while(!done && !mcode) {
    int still_running = 0;

    mcode = curl_multi_poll(multi, NULL, 0, 1000, NULL);

    if(!mcode)
      mcode = curl_multi_perform(multi, &still_running);

    
    if(!mcode && !still_running) {
      int rc;
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

  if(data->set.errorbuffer)
    
    data->set.errorbuffer[0] = 0;

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

  if(multi->in_callback)
    return CURLE_RECURSIVE_API_CALL;

  
  curl_multi_setopt(multi, CURLMOPT_MAXCONNECTS, data->set.maxconnects);

  mcode = curl_multi_add_handle(multi, data);
  if(mcode) {
    curl_multi_cleanup(multi);
    data->multi_easy = NULL;
    if(mcode == CURLM_OUT_OF_MEMORY)
      return CURLE_OUT_OF_MEMORY;
    return CURLE_FAILED_INIT;
  }

  sigpipe_ignore(data, &pipe_st);

  
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
  Curl_close(&data);
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

static CURLcode dupset(struct Curl_easy *dst, struct Curl_easy *src)
{
  CURLcode result = CURLE_OK;
  enum dupstring i;
  enum dupblob j;

  
  dst->set = src->set;
  Curl_mime_initpart(&dst->set.mimepost, dst);

  
  memset(dst->set.str, 0, STRING_LAST * sizeof(char *));

  
  for(i = (enum dupstring)0; i< STRING_LASTZEROTERMINATED; i++) {
    result = Curl_setstropt(&dst->set.str[i], src->set.str[i]);
    if(result)
      return result;
  }

  
  memset(dst->set.blobs, 0, BLOB_LAST * sizeof(struct curl_blob *));
  
  for(j = (enum dupblob)0; j < BLOB_LAST; j++) {
    result = Curl_setblobopt(&dst->set.blobs[j], src->set.blobs[j]);
    
    if(result)
      return result;
  }

  
  i = STRING_COPYPOSTFIELDS;
  if(src->set.postfieldsize && src->set.str[i]) {
    
    dst->set.str[i] = Curl_memdup(src->set.str[i], curlx_sotouz(src->set.postfieldsize));
    if(!dst->set.str[i])
      return CURLE_OUT_OF_MEMORY;
    
    dst->set.postfields = dst->set.str[i];
  }

  
  result = Curl_mime_duppart(&dst->set.mimepost, &src->set.mimepost);

  if(src->set.resolve)
    dst->change.resolve = dst->set.resolve;

  return result;
}


struct Curl_easy *curl_easy_duphandle(struct Curl_easy *data)
{
  struct Curl_easy *outcurl = calloc(1, sizeof(struct Curl_easy));
  if(NULL == outcurl)
    goto fail;

  
  outcurl->set.buffer_size = data->set.buffer_size;

  
  if(dupset(outcurl, data))
    goto fail;

  Curl_dyn_init(&outcurl->state.headerb, CURL_MAX_HTTP_HEADER);

  
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

  
  if(outcurl->set.str[STRING_SSL_ENGINE]) {
    if(Curl_ssl_set_engine(outcurl, outcurl->set.str[STRING_SSL_ENGINE]))
      goto fail;
  }

  
  if(Curl_resolver_duphandle(outcurl, &outcurl->state.resolver, data->state.resolver))

    goto fail;


  {
    CURLcode rc;

    rc = Curl_set_dns_servers(outcurl, data->set.str[STRING_DNS_SERVERS]);
    if(rc && rc != CURLE_NOT_BUILT_IN)
      goto fail;

    rc = Curl_set_dns_interface(outcurl, data->set.str[STRING_DNS_INTERFACE]);
    if(rc && rc != CURLE_NOT_BUILT_IN)
      goto fail;

    rc = Curl_set_dns_local_ip4(outcurl, data->set.str[STRING_DNS_LOCAL_IP4]);
    if(rc && rc != CURLE_NOT_BUILT_IN)
      goto fail;

    rc = Curl_set_dns_local_ip6(outcurl, data->set.str[STRING_DNS_LOCAL_IP6]);
    if(rc && rc != CURLE_NOT_BUILT_IN)
      goto fail;
  }


  Curl_convert_setup(outcurl);

  Curl_initinfo(outcurl);

  outcurl->magic = CURLEASY_MAGIC_NUMBER;

  

  return outcurl;

  fail:

  if(outcurl) {
    curl_slist_free_all(outcurl->change.cookielist);
    outcurl->change.cookielist = NULL;
    Curl_safefree(outcurl->state.buffer);
    Curl_dyn_free(&outcurl->state.headerb);
    Curl_safefree(outcurl->change.url);
    Curl_safefree(outcurl->change.referer);
    Curl_freeset(outcurl);
    free(outcurl);
  }

  return NULL;
}


void curl_easy_reset(struct Curl_easy *data)
{
  Curl_free_request_state(data);

  
  Curl_freeset(data);
  memset(&data->set, 0, sizeof(struct UserDefined));
  (void)Curl_init_userdefined(data);

  
  memset(&data->progress, 0, sizeof(struct Progress));

  
  Curl_initinfo(data);

  data->progress.flags |= PGRS_HIDE;
  data->state.current_speed = -1; 

  
  memset(&data->state.authhost, 0, sizeof(struct auth));
  memset(&data->state.authproxy, 0, sizeof(struct auth));


  Curl_http_auth_cleanup_digest(data);

}


CURLcode curl_easy_pause(struct Curl_easy *data, int action)
{
  struct SingleRequest *k;
  CURLcode result = CURLE_OK;
  int oldstate;
  int newstate;

  if(!GOOD_EASY_HANDLE(data) || !data->conn)
    
    return CURLE_BAD_FUNCTION_ARGUMENT;

  k = &data->req;
  oldstate = k->keepon & (KEEP_RECV_PAUSE| KEEP_SEND_PAUSE);

  
  newstate = (k->keepon &~ (KEEP_RECV_PAUSE| KEEP_SEND_PAUSE)) | ((action & CURLPAUSE_RECV)?KEEP_RECV_PAUSE:0) | ((action & CURLPAUSE_SEND)?KEEP_SEND_PAUSE:0);


  if((newstate & (KEEP_RECV_PAUSE| KEEP_SEND_PAUSE)) == oldstate) {
    
    DEBUGF(infof(data, "pause: no change, early return\n"));
    return CURLE_OK;
  }

  
  if((k->keepon & ~newstate & KEEP_SEND_PAUSE) && (data->mstate == CURLM_STATE_PERFORM || data->mstate == CURLM_STATE_TOOFAST) && data->state.fread_func == (curl_read_callback) Curl_mime_read) {


    Curl_mime_unpause(data->state.in);
  }

  
  k->keepon = newstate;

  if(!(newstate & KEEP_RECV_PAUSE)) {
    Curl_http2_stream_pause(data, FALSE);

    if(data->state.tempcount) {
      
      unsigned int i;
      unsigned int count = data->state.tempcount;
      struct tempbuf writebuf[3]; 
      struct connectdata *conn = data->conn;
      struct Curl_easy *saved_data = NULL;

      
      for(i = 0; i < data->state.tempcount; i++) {
        writebuf[i] = data->state.tempwrite[i];
        Curl_dyn_init(&data->state.tempwrite[i].b, DYN_PAUSE_BUFFER);
      }
      data->state.tempcount = 0;

      
      if(conn->data != data) {
        saved_data = conn->data;
        conn->data = data;
      }

      for(i = 0; i < count; i++) {
        
        if(!result)
          result = Curl_client_write(conn, writebuf[i].type, Curl_dyn_ptr(&writebuf[i].b), Curl_dyn_len(&writebuf[i].b));

        Curl_dyn_free(&writebuf[i].b);
      }

      
      if(saved_data)
        conn->data = saved_data;

      if(result)
        return result;
    }
  }

  
  if((newstate & (KEEP_RECV_PAUSE|KEEP_SEND_PAUSE)) != (KEEP_RECV_PAUSE|KEEP_SEND_PAUSE)) {
    Curl_expire(data, 0, EXPIRE_RUN_NOW); 

    
    data->conn->cselect_bits = CURL_CSELECT_IN | CURL_CSELECT_OUT;
    if(data->multi)
      Curl_update_timer(data->multi);
  }

  if(!data->state.done)
    
    Curl_updatesocket(data);

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

  if(Curl_is_in_callback(data))
    return CURLE_RECURSIVE_API_CALL;

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

  if(Curl_is_in_callback(data))
    return CURLE_RECURSIVE_API_CALL;

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


static int conn_upkeep(struct connectdata *conn, void *param)
{
  
  (void)param;

  if(conn->handler->connection_check) {
    
    conn->handler->connection_check(conn, CONNCHECK_KEEPALIVE);
  }

  return 0; 
}

static CURLcode upkeep(struct conncache *conn_cache, void *data)
{
  
  Curl_conncache_foreach(data, conn_cache, data, conn_upkeep);


  return CURLE_OK;
}


CURLcode curl_easy_upkeep(struct Curl_easy *data)
{
  
  if(!GOOD_EASY_HANDLE(data))
    return CURLE_BAD_FUNCTION_ARGUMENT;

  if(data->multi_easy) {
    
    return upkeep(&data->multi_easy->conn_cache, data);
  }
  else {
    
    return CURLE_OK;
  }
}
