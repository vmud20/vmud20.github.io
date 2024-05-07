















































static CURLMcode singlesocket(struct Curl_multi *multi, struct Curl_easy *data);
static CURLMcode add_next_timeout(struct curltime now, struct Curl_multi *multi, struct Curl_easy *d);

static CURLMcode multi_timeout(struct Curl_multi *multi, long *timeout_ms);
static void process_pending_handles(struct Curl_multi *multi);


static const char * const statename[]={
  "INIT", "CONNECT_PEND", "CONNECT", "WAITRESOLVE", "WAITCONNECT", "WAITPROXYCONNECT", "SENDPROTOCONNECT", "PROTOCONNECT", "DO", "DOING", "DO_MORE", "DO_DONE", "PERFORM", "TOOFAST", "DONE", "COMPLETED", "MSGSENT", };



















typedef void (*init_multistate_func)(struct Curl_easy *data);

static void Curl_init_completed(struct Curl_easy *data)
{
  

  
  Curl_detach_connnection(data);
  Curl_expire_clear(data); 
}


static void mstate(struct Curl_easy *data, CURLMstate state  , int lineno  )



{
  CURLMstate oldstate = data->mstate;
  static const init_multistate_func finit[CURLM_STATE_LAST] = {
    NULL,               NULL, Curl_init_CONNECT, NULL, NULL, NULL, NULL, NULL, Curl_connect_free, NULL, NULL, NULL, NULL, NULL, NULL, Curl_init_completed, NULL };


















  (void) lineno;


  if(oldstate == state)
    
    return;

  data->mstate = state;


  if(data->mstate >= CURLM_STATE_CONNECT_PEND && data->mstate < CURLM_STATE_COMPLETED) {
    long connection_id = -5000;

    if(data->conn)
      connection_id = data->conn->connection_id;

    infof(data, "STATE: %s => %s handle %p; line %d (connection #%ld)\n", statename[oldstate], statename[data->mstate], (void *)data, lineno, connection_id);


  }


  if(state == CURLM_STATE_COMPLETED) {
    
    DEBUGASSERT(data->multi->num_alive > 0);
    data->multi->num_alive--;
  }

  
  if(finit[state])
    finit[state](data);
}









struct Curl_sh_entry {
  struct curl_hash transfers; 
  unsigned int action;  
  void *socketp; 
  unsigned int users; 
  unsigned int readers; 
  unsigned int writers; 
};





static struct Curl_sh_entry *sh_getentry(struct curl_hash *sh, curl_socket_t s)
{
  if(s != CURL_SOCKET_BAD) {
    
    return Curl_hash_pick(sh, (char *)&s, sizeof(curl_socket_t));
  }
  return NULL;
}


static size_t trhash(void *key, size_t key_length, size_t slots_num)
{
  size_t keyval = (size_t)*(struct Curl_easy **)key;
  (void) key_length;

  return (keyval % slots_num);
}

static size_t trhash_compare(void *k1, size_t k1_len, void *k2, size_t k2_len)
{
  (void)k1_len;
  (void)k2_len;

  return *(struct Curl_easy **)k1 == *(struct Curl_easy **)k2;
}

static void trhash_dtor(void *nada)
{
  (void)nada;
}



static struct Curl_sh_entry *sh_addentry(struct curl_hash *sh, curl_socket_t s)
{
  struct Curl_sh_entry *there = sh_getentry(sh, s);
  struct Curl_sh_entry *check;

  if(there) {
    
    return there;
  }

  
  check = calloc(1, sizeof(struct Curl_sh_entry));
  if(!check)
    return NULL; 

  if(Curl_hash_init(&check->transfers, TRHASH_SIZE, trhash, trhash_compare, trhash_dtor)) {
    free(check);
    return NULL;
  }

  
  if(!Curl_hash_add(sh, (char *)&s, sizeof(curl_socket_t), check)) {
    Curl_hash_destroy(&check->transfers);
    free(check);
    return NULL; 
  }

  return check; 
}



static void sh_delentry(struct Curl_sh_entry *entry, struct curl_hash *sh, curl_socket_t s)
{
  Curl_hash_destroy(&entry->transfers);

  
  Curl_hash_delete(sh, (char *)&s, sizeof(curl_socket_t));
}


static void sh_freeentry(void *freethis)
{
  struct Curl_sh_entry *p = (struct Curl_sh_entry *) freethis;

  free(p);
}

static size_t fd_key_compare(void *k1, size_t k1_len, void *k2, size_t k2_len)
{
  (void) k1_len; (void) k2_len;

  return (*((curl_socket_t *) k1)) == (*((curl_socket_t *) k2));
}

static size_t hash_fd(void *key, size_t key_length, size_t slots_num)
{
  curl_socket_t fd = *((curl_socket_t *) key);
  (void) key_length;

  return (fd % slots_num);
}


static int sh_init(struct curl_hash *hash, int hashsize)
{
  return Curl_hash_init(hash, hashsize, hash_fd, fd_key_compare, sh_freeentry);
}


static CURLMcode multi_addmsg(struct Curl_multi *multi, struct Curl_message *msg)
{
  Curl_llist_insert_next(&multi->msglist, multi->msglist.tail, msg, &msg->list);
  return CURLM_OK;
}

struct Curl_multi *Curl_multi_handle(int hashsize,  int chashsize)
{
  struct Curl_multi *multi = calloc(1, sizeof(struct Curl_multi));

  if(!multi)
    return NULL;

  multi->type = CURL_MULTI_HANDLE;

  if(Curl_mk_dnscache(&multi->hostcache))
    goto error;

  if(sh_init(&multi->sockhash, hashsize))
    goto error;

  if(Curl_conncache_init(&multi->conn_cache, chashsize))
    goto error;

  Curl_llist_init(&multi->msglist, NULL);
  Curl_llist_init(&multi->pending, NULL);

  multi->multiplexing = TRUE;

  
  multi->maxconnects = -1;
  multi->max_concurrent_streams = 100;
  multi->ipv6_works = Curl_ipv6works(NULL);


  if(Curl_socketpair(AF_UNIX, SOCK_STREAM, 0, multi->wakeup_pair) < 0) {
    multi->wakeup_pair[0] = CURL_SOCKET_BAD;
    multi->wakeup_pair[1] = CURL_SOCKET_BAD;
  }
  else if(curlx_nonblock(multi->wakeup_pair[0], TRUE) < 0 || curlx_nonblock(multi->wakeup_pair[1], TRUE) < 0) {
    sclose(multi->wakeup_pair[0]);
    sclose(multi->wakeup_pair[1]);
    multi->wakeup_pair[0] = CURL_SOCKET_BAD;
    multi->wakeup_pair[1] = CURL_SOCKET_BAD;
  }


  return multi;

  error:

  Curl_hash_destroy(&multi->sockhash);
  Curl_hash_destroy(&multi->hostcache);
  Curl_conncache_destroy(&multi->conn_cache);
  Curl_llist_destroy(&multi->msglist, NULL);
  Curl_llist_destroy(&multi->pending, NULL);

  free(multi);
  return NULL;
}

struct Curl_multi *curl_multi_init(void)
{
  return Curl_multi_handle(CURL_SOCKET_HASH_TABLE_SIZE, CURL_CONNECTION_HASH_SIZE);
}

CURLMcode curl_multi_add_handle(struct Curl_multi *multi, struct Curl_easy *data)
{
  
  if(!GOOD_MULTI_HANDLE(multi))
    return CURLM_BAD_HANDLE;

  
  if(!GOOD_EASY_HANDLE(data))
    return CURLM_BAD_EASY_HANDLE;

  
  if(data->multi)
    return CURLM_ADDED_ALREADY;

  if(multi->in_callback)
    return CURLM_RECURSIVE_API_CALL;

  
  Curl_llist_init(&data->state.timeoutlist, NULL);

  
  if(data->set.errorbuffer)
    data->set.errorbuffer[0] = 0;

  
  multistate(data, CURLM_STATE_INIT);

  
  if(!data->dns.hostcache || (data->dns.hostcachetype == HCACHE_NONE)) {
    data->dns.hostcache = &multi->hostcache;
    data->dns.hostcachetype = HCACHE_MULTI;
  }

  
  if(data->share && (data->share->specifier & (1<< CURL_LOCK_DATA_CONNECT)))
    data->state.conn_cache = &data->share->conn_cache;
  else data->state.conn_cache = &multi->conn_cache;


  
  if(data->share && (data->share->specifier & (1 << CURL_LOCK_DATA_PSL)))
    data->psl = &data->share->psl;
  else data->psl = &multi->psl;


  
  data->next = NULL; 
  if(multi->easyp) {
    struct Curl_easy *last = multi->easylp;
    last->next = data;
    data->prev = last;
    multi->easylp = data; 
  }
  else {
    
    data->prev = NULL;
    multi->easylp = multi->easyp = data; 
  }

  
  data->multi = multi;

  
  Curl_expire(data, 0, EXPIRE_RUN_NOW);

  
  multi->num_easy++;

  
  multi->num_alive++;

  
  memset(&multi->timer_lastcall, 0, sizeof(multi->timer_lastcall));

  CONNCACHE_LOCK(data);
  
  data->state.conn_cache->closure_handle->set.timeout = data->set.timeout;
  data->state.conn_cache->closure_handle->set.server_response_timeout = data->set.server_response_timeout;
  data->state.conn_cache->closure_handle->set.no_signal = data->set.no_signal;
  CONNCACHE_UNLOCK(data);

  Curl_update_timer(multi);
  return CURLM_OK;
}



static void debug_print_sock_hash(void *p)
{
  struct Curl_sh_entry *sh = (struct Curl_sh_entry *)p;

  fprintf(stderr, " [easy %p/magic %x/socket %d]", (void *)sh->data, sh->data->magic, (int)sh->socket);
}


static CURLcode multi_done(struct Curl_easy *data, CURLcode status, bool premature)

{
  CURLcode result;
  struct connectdata *conn = data->conn;
  unsigned int i;

  DEBUGF(infof(data, "multi_done\n"));

  if(data->state.done)
    
    return CURLE_OK;

  conn->data = data; 

  
  Curl_resolver_kill(conn);

  
  Curl_safefree(data->req.newurl);
  Curl_safefree(data->req.location);

  switch(status) {
  case CURLE_ABORTED_BY_CALLBACK:
  case CURLE_READ_ERROR:
  case CURLE_WRITE_ERROR:
    
    premature = TRUE;
  default:
    break;
  }

  
  if(conn->handler->done)
    result = conn->handler->done(conn, status, premature);
  else result = status;

  if(CURLE_ABORTED_BY_CALLBACK != result) {
    
    CURLcode rc = Curl_pgrsDone(conn);
    if(!result && rc)
      result = CURLE_ABORTED_BY_CALLBACK;
  }

  process_pending_handles(data->multi); 

  CONNCACHE_LOCK(data);
  Curl_detach_connnection(data);
  if(CONN_INUSE(conn)) {
    
    
    conn->data = conn->easyq.head->ptr;
    CONNCACHE_UNLOCK(data);
    DEBUGF(infof(data, "Connection still in use %zu, " "no more multi_done now!\n", conn->easyq.size));

    return CURLE_OK;
  }
  conn->data = NULL; 
  data->state.done = TRUE; 

  if(conn->dns_entry) {
    Curl_resolv_unlock(data, conn->dns_entry); 
    conn->dns_entry = NULL;
  }
  Curl_hostcache_prune(data);
  Curl_safefree(data->state.ulbuf);

  
  for(i = 0; i < data->state.tempcount; i++) {
    Curl_dyn_free(&data->state.tempwrite[i].b);
  }
  data->state.tempcount = 0;

  

  if((data->set.reuse_forbid  && !(conn->http_ntlm_state == NTLMSTATE_TYPE2 || conn->proxy_ntlm_state == NTLMSTATE_TYPE2)




      && !(conn->http_negotiate_state == GSS_AUTHRECV || conn->proxy_negotiate_state == GSS_AUTHRECV)

     ) || conn->bits.close || (premature && !(conn->handler->flags & PROTOPT_STREAM))) {
    CURLcode res2;
    connclose(conn, "disconnecting");
    Curl_conncache_remove_conn(data, conn, FALSE);
    CONNCACHE_UNLOCK(data);
    res2 = Curl_disconnect(data, conn, premature);

    
    if(!result && res2)
      result = res2;
  }
  else {
    char buffer[256];
    const char *host =  conn->bits.socksproxy ? conn->socks_proxy.host.dispname :


      conn->bits.httpproxy ? conn->http_proxy.host.dispname :

      conn->bits.conn_to_host ? conn->conn_to_host.dispname :
      conn->host.dispname;
    
    msnprintf(buffer, sizeof(buffer), "Connection #%ld to host %s left intact", conn->connection_id, host);

    
    CONNCACHE_UNLOCK(data);
    if(Curl_conncache_return_conn(data, conn)) {
      
      data->state.lastconnect = conn;
      infof(data, "%s\n", buffer);
    }
    else data->state.lastconnect = NULL;
  }

  Curl_safefree(data->state.buffer);
  Curl_free_request_state(data);
  return result;
}

static int close_connect_only(struct connectdata *conn, void *param)
{
  struct Curl_easy *data = param;

  if(data->state.lastconnect != conn)
    return 0;

  if(conn->data != data)
    return 1;
  conn->data = NULL;

  if(!conn->bits.connect_only)
    return 1;

  connclose(conn, "Removing connect-only easy handle");
  conn->bits.connect_only = FALSE;

  return 1;
}

CURLMcode curl_multi_remove_handle(struct Curl_multi *multi, struct Curl_easy *data)
{
  struct Curl_easy *easy = data;
  bool premature;
  bool easy_owns_conn;
  struct curl_llist_element *e;

  
  if(!GOOD_MULTI_HANDLE(multi))
    return CURLM_BAD_HANDLE;

  
  if(!GOOD_EASY_HANDLE(data))
    return CURLM_BAD_EASY_HANDLE;

  
  if(!data->multi)
    return CURLM_OK; 

  
  if(data->multi != multi)
    return CURLM_BAD_EASY_HANDLE;

  if(multi->in_callback)
    return CURLM_RECURSIVE_API_CALL;

  premature = (data->mstate < CURLM_STATE_COMPLETED) ? TRUE : FALSE;
  easy_owns_conn = (data->conn && (data->conn->data == easy)) ? TRUE : FALSE;

  
  if(premature) {
    
    multi->num_alive--;
  }

  if(data->conn && data->mstate > CURLM_STATE_DO && data->mstate < CURLM_STATE_COMPLETED) {

    
    data->conn->data = easy;
    streamclose(data->conn, "Removed with partial response");
    easy_owns_conn = TRUE;
  }

  if(data->conn) {

    
    if(easy_owns_conn) {

      
      (void)multi_done(data, data->result, premature);
    }
  }

  
  Curl_expire_clear(data);

  if(data->connect_queue.ptr)
    
    Curl_llist_remove(&multi->pending, &data->connect_queue, NULL);

  if(data->dns.hostcachetype == HCACHE_MULTI) {
    
    data->dns.hostcache = NULL;
    data->dns.hostcachetype = HCACHE_NONE;
  }

  Curl_wildcard_dtor(&data->wildcard);

  
  Curl_llist_destroy(&data->state.timeoutlist, NULL);

  
  data->mstate = CURLM_STATE_COMPLETED;
  singlesocket(multi, easy); 

  
  Curl_detach_connnection(data);

  if(data->state.lastconnect) {
    
    Curl_conncache_foreach(data, data->state.conn_cache, data, &close_connect_only);
  }


  
  if(data->psl == &multi->psl)
    data->psl = NULL;


  
  data->state.conn_cache = NULL;

  data->multi = NULL; 

  

  for(e = multi->msglist.head; e; e = e->next) {
    struct Curl_message *msg = e->ptr;

    if(msg->extmsg.easy_handle == easy) {
      Curl_llist_remove(&multi->msglist, e, NULL);
      
      break;
    }
  }

  
  if(data->prev)
    data->prev->next = data->next;
  else multi->easyp = data->next;

  
  if(data->next)
    data->next->prev = data->prev;
  else multi->easylp = data->prev;

  
  multi->num_easy--; 

  Curl_update_timer(multi);
  return CURLM_OK;
}


bool Curl_multiplex_wanted(const struct Curl_multi *multi)
{
  return (multi && (multi->multiplexing));
}


void Curl_detach_connnection(struct Curl_easy *data)
{
  struct connectdata *conn = data->conn;
  if(conn)
    Curl_llist_remove(&conn->easyq, &data->conn_queue, NULL);
  data->conn = NULL;
}


void Curl_attach_connnection(struct Curl_easy *data, struct connectdata *conn)
{
  DEBUGASSERT(!data->conn);
  DEBUGASSERT(conn);
  data->conn = conn;
  Curl_llist_insert_next(&conn->easyq, conn->easyq.tail, data, &data->conn_queue);
}

static int waitconnect_getsock(struct connectdata *conn, curl_socket_t *sock)
{
  int i;
  int s = 0;
  int rc = 0;



  if(CONNECT_FIRSTSOCKET_PROXY_SSL())
    return Curl_ssl_getsock(conn, sock);



  if(SOCKS_STATE(conn->cnnct.state))
    return Curl_SOCKS_getsock(conn, sock, FIRSTSOCKET);

  for(i = 0; i<2; i++) {
    if(conn->tempsock[i] != CURL_SOCKET_BAD) {
      sock[s] = conn->tempsock[i];
      rc |= GETSOCK_WRITESOCK(s);

      if(conn->transport == TRNSPRT_QUIC)
        
        rc |= GETSOCK_READSOCK(s);

      s++;
    }
  }

  return rc;
}

static int waitproxyconnect_getsock(struct connectdata *conn, curl_socket_t *sock)
{
  sock[0] = conn->sock[FIRSTSOCKET];

  
  if(conn->connect_state)
    return GETSOCK_READSOCK(0);

  return GETSOCK_WRITESOCK(0);
}

static int domore_getsock(struct connectdata *conn, curl_socket_t *socks)
{
  if(conn && conn->handler->domore_getsock)
    return conn->handler->domore_getsock(conn, socks);
  return GETSOCK_BLANK;
}

static int doing_getsock(struct connectdata *conn, curl_socket_t *socks)
{
  if(conn && conn->handler->doing_getsock)
    return conn->handler->doing_getsock(conn, socks);
  return GETSOCK_BLANK;
}

static int protocol_getsock(struct connectdata *conn, curl_socket_t *socks)
{
  if(conn->handler->proto_getsock)
    return conn->handler->proto_getsock(conn, socks);
  
  socks[0] = conn->sock[FIRSTSOCKET];
  return GETSOCK_READSOCK(0) | GETSOCK_WRITESOCK(0);
}


static int multi_getsock(struct Curl_easy *data, curl_socket_t *socks)
{
  
  if(!data->conn)
    return 0;

  if(data->mstate > CURLM_STATE_CONNECT && data->mstate < CURLM_STATE_COMPLETED) {
    
    data->conn->data = data;
  }

  switch(data->mstate) {
  default:
    return 0;

  case CURLM_STATE_WAITRESOLVE:
    return Curl_resolv_getsock(data->conn, socks);

  case CURLM_STATE_PROTOCONNECT:
  case CURLM_STATE_SENDPROTOCONNECT:
    return protocol_getsock(data->conn, socks);

  case CURLM_STATE_DO:
  case CURLM_STATE_DOING:
    return doing_getsock(data->conn, socks);

  case CURLM_STATE_WAITPROXYCONNECT:
    return waitproxyconnect_getsock(data->conn, socks);

  case CURLM_STATE_WAITCONNECT:
    return waitconnect_getsock(data->conn, socks);

  case CURLM_STATE_DO_MORE:
    return domore_getsock(data->conn, socks);

  case CURLM_STATE_DO_DONE: 
  case CURLM_STATE_PERFORM:
    return Curl_single_getsock(data->conn, socks);
  }

}

CURLMcode curl_multi_fdset(struct Curl_multi *multi, fd_set *read_fd_set, fd_set *write_fd_set, fd_set *exc_fd_set, int *max_fd)

{
  
  struct Curl_easy *data;
  int this_max_fd = -1;
  curl_socket_t sockbunch[MAX_SOCKSPEREASYHANDLE];
  int i;
  (void)exc_fd_set; 

  if(!GOOD_MULTI_HANDLE(multi))
    return CURLM_BAD_HANDLE;

  if(multi->in_callback)
    return CURLM_RECURSIVE_API_CALL;

  data = multi->easyp;
  while(data) {
    int bitmap = multi_getsock(data, sockbunch);

    for(i = 0; i< MAX_SOCKSPEREASYHANDLE; i++) {
      curl_socket_t s = CURL_SOCKET_BAD;

      if((bitmap & GETSOCK_READSOCK(i)) && VALID_SOCK((sockbunch[i]))) {
        FD_SET(sockbunch[i], read_fd_set);
        s = sockbunch[i];
      }
      if((bitmap & GETSOCK_WRITESOCK(i)) && VALID_SOCK((sockbunch[i]))) {
        FD_SET(sockbunch[i], write_fd_set);
        s = sockbunch[i];
      }
      if(s == CURL_SOCKET_BAD)
        
        break;
      if((int)s > this_max_fd)
        this_max_fd = (int)s;
    }

    data = data->next; 
  }

  *max_fd = this_max_fd;

  return CURLM_OK;
}



static CURLMcode Curl_multi_wait(struct Curl_multi *multi, struct curl_waitfd extra_fds[], unsigned int extra_nfds, int timeout_ms, int *ret, bool extrawait, bool use_wakeup)





{
  struct Curl_easy *data;
  curl_socket_t sockbunch[MAX_SOCKSPEREASYHANDLE];
  int bitmap;
  unsigned int i;
  unsigned int nfds = 0;
  unsigned int curlfds;
  bool ufds_malloc = FALSE;
  long timeout_internal;
  int retcode = 0;
  struct pollfd a_few_on_stack[NUM_POLLS_ON_STACK];
  struct pollfd *ufds = &a_few_on_stack[0];

  if(!GOOD_MULTI_HANDLE(multi))
    return CURLM_BAD_HANDLE;

  if(multi->in_callback)
    return CURLM_RECURSIVE_API_CALL;

  if(timeout_ms < 0)
    return CURLM_BAD_FUNCTION_ARGUMENT;

  
  data = multi->easyp;
  while(data) {
    bitmap = multi_getsock(data, sockbunch);

    for(i = 0; i< MAX_SOCKSPEREASYHANDLE; i++) {
      curl_socket_t s = CURL_SOCKET_BAD;

      if(bitmap & GETSOCK_READSOCK(i)) {
        ++nfds;
        s = sockbunch[i];
      }
      if(bitmap & GETSOCK_WRITESOCK(i)) {
        ++nfds;
        s = sockbunch[i];
      }
      if(s == CURL_SOCKET_BAD) {
        break;
      }
    }

    data = data->next; 
  }

  
  (void)multi_timeout(multi, &timeout_internal);
  if((timeout_internal >= 0) && (timeout_internal < (long)timeout_ms))
    timeout_ms = (int)timeout_internal;

  curlfds = nfds; 
  nfds += extra_nfds; 


  if(use_wakeup && multi->wakeup_pair[0] != CURL_SOCKET_BAD) {
    ++nfds;
  }


  if(nfds > NUM_POLLS_ON_STACK) {
    
    ufds = malloc(nfds * sizeof(struct pollfd));
    if(!ufds)
      return CURLM_OUT_OF_MEMORY;
    ufds_malloc = TRUE;
  }
  nfds = 0;

  

  if(curlfds) {
    
    data = multi->easyp;
    while(data) {
      bitmap = multi_getsock(data, sockbunch);

      for(i = 0; i< MAX_SOCKSPEREASYHANDLE; i++) {
        curl_socket_t s = CURL_SOCKET_BAD;

        if(bitmap & GETSOCK_READSOCK(i)) {
          ufds[nfds].fd = sockbunch[i];
          ufds[nfds].events = POLLIN;
          ++nfds;
          s = sockbunch[i];
        }
        if(bitmap & GETSOCK_WRITESOCK(i)) {
          ufds[nfds].fd = sockbunch[i];
          ufds[nfds].events = POLLOUT;
          ++nfds;
          s = sockbunch[i];
        }
        if(s == CURL_SOCKET_BAD) {
          break;
        }
      }

      data = data->next; 
    }
  }

  
  for(i = 0; i < extra_nfds; i++) {
    ufds[nfds].fd = extra_fds[i].fd;
    ufds[nfds].events = 0;
    if(extra_fds[i].events & CURL_WAIT_POLLIN)
      ufds[nfds].events |= POLLIN;
    if(extra_fds[i].events & CURL_WAIT_POLLPRI)
      ufds[nfds].events |= POLLPRI;
    if(extra_fds[i].events & CURL_WAIT_POLLOUT)
      ufds[nfds].events |= POLLOUT;
    ++nfds;
  }


  if(use_wakeup && multi->wakeup_pair[0] != CURL_SOCKET_BAD) {
    ufds[nfds].fd = multi->wakeup_pair[0];
    ufds[nfds].events = POLLIN;
    ++nfds;
  }


  if(nfds) {
    int pollrc;
    
    pollrc = Curl_poll(ufds, nfds, timeout_ms);

    if(pollrc > 0) {
      retcode = pollrc;
      
      for(i = 0; i < extra_nfds; i++) {
        unsigned short mask = 0;
        unsigned r = ufds[curlfds + i].revents;

        if(r & POLLIN)
          mask |= CURL_WAIT_POLLIN;
        if(r & POLLOUT)
          mask |= CURL_WAIT_POLLOUT;
        if(r & POLLPRI)
          mask |= CURL_WAIT_POLLPRI;

        extra_fds[i].revents = mask;
      }


      if(use_wakeup && multi->wakeup_pair[0] != CURL_SOCKET_BAD) {
        if(ufds[curlfds + extra_nfds].revents & POLLIN) {
          char buf[64];
          ssize_t nread;
          while(1) {
            
            nread = sread(multi->wakeup_pair[0], buf, sizeof(buf));
            if(nread <= 0) {

              if(nread < 0 && EINTR == SOCKERRNO)
                continue;

              break;
            }
          }
          
          retcode--;
        }
      }

    }
  }

  if(ufds_malloc)
    free(ufds);
  if(ret)
    *ret = retcode;
  if(!extrawait || nfds)
    
    ;
  else {
    long sleep_ms = 0;

    
    if(!curl_multi_timeout(multi, &sleep_ms) && sleep_ms) {
      if(sleep_ms > timeout_ms)
        sleep_ms = timeout_ms;
      
      else if(sleep_ms < 0)
        sleep_ms = timeout_ms;
      Curl_wait_ms(sleep_ms);
    }
  }

  return CURLM_OK;
}

CURLMcode curl_multi_wait(struct Curl_multi *multi, struct curl_waitfd extra_fds[], unsigned int extra_nfds, int timeout_ms, int *ret)



{
  return Curl_multi_wait(multi, extra_fds, extra_nfds, timeout_ms, ret, FALSE, FALSE);
}

CURLMcode curl_multi_poll(struct Curl_multi *multi, struct curl_waitfd extra_fds[], unsigned int extra_nfds, int timeout_ms, int *ret)



{
  return Curl_multi_wait(multi, extra_fds, extra_nfds, timeout_ms, ret, TRUE, TRUE);
}

CURLMcode curl_multi_wakeup(struct Curl_multi *multi)
{
  

  
  if(!GOOD_MULTI_HANDLE(multi))
    return CURLM_BAD_HANDLE;


  
  if(multi->wakeup_pair[1] != CURL_SOCKET_BAD) {
    char buf[1];
    buf[0] = 1;
    while(1) {
      
      if(swrite(multi->wakeup_pair[1], buf, sizeof(buf)) < 0) {
        int err = SOCKERRNO;
        int return_success;

        return_success = WSAEWOULDBLOCK == err;

        if(EINTR == err)
          continue;
        return_success = EWOULDBLOCK == err || EAGAIN == err;

        if(!return_success)
          return CURLM_WAKEUP_FAILURE;
      }
      return CURLM_OK;
    }
  }

  return CURLM_WAKEUP_FAILURE;
}


static bool multi_ischanged(struct Curl_multi *multi, bool clear)
{
  bool retval = multi->recheckstate;
  if(clear)
    multi->recheckstate = FALSE;
  return retval;
}

CURLMcode Curl_multi_add_perform(struct Curl_multi *multi, struct Curl_easy *data, struct connectdata *conn)

{
  CURLMcode rc;

  if(multi->in_callback)
    return CURLM_RECURSIVE_API_CALL;

  rc = curl_multi_add_handle(multi, data);
  if(!rc) {
    struct SingleRequest *k = &data->req;

    
    Curl_init_do(data, NULL);

    
    multistate(data, CURLM_STATE_PERFORM);
    Curl_attach_connnection(data, conn);
    k->keepon |= KEEP_RECV; 
  }
  return rc;
}


static void do_complete(struct connectdata *conn)
{
  conn->data->req.chunk = FALSE;
  Curl_pgrsTime(conn->data, TIMER_PRETRANSFER);
}

static CURLcode multi_do(struct Curl_easy *data, bool *done)
{
  CURLcode result = CURLE_OK;
  struct connectdata *conn = data->conn;

  DEBUGASSERT(conn);
  DEBUGASSERT(conn->handler);
  DEBUGASSERT(conn->data == data);

  if(conn->handler->do_it) {
    
    result = conn->handler->do_it(conn, done);

    if(!result && *done)
      
      do_complete(conn);
  }
  return result;
}



static CURLcode multi_do_more(struct connectdata *conn, int *complete)
{
  CURLcode result = CURLE_OK;

  *complete = 0;

  if(conn->handler->do_more)
    result = conn->handler->do_more(conn, complete);

  if(!result && (*complete == 1))
    
    do_complete(conn);

  return result;
}



static CURLcode protocol_connecting(struct connectdata *conn, bool *done)
{
  CURLcode result = CURLE_OK;

  if(conn && conn->handler->connecting) {
    *done = FALSE;
    result = conn->handler->connecting(conn, done);
  }
  else *done = TRUE;

  return result;
}



static CURLcode protocol_doing(struct connectdata *conn, bool *done)
{
  CURLcode result = CURLE_OK;

  if(conn && conn->handler->doing) {
    *done = FALSE;
    result = conn->handler->doing(conn, done);
  }
  else *done = TRUE;

  return result;
}


static CURLcode protocol_connect(struct connectdata *conn, bool *protocol_done)
{
  CURLcode result = CURLE_OK;

  DEBUGASSERT(conn);
  DEBUGASSERT(protocol_done);

  *protocol_done = FALSE;

  if(conn->bits.tcpconnect[FIRSTSOCKET] && conn->bits.protoconnstart) {
    
    if(!conn->handler->connecting)
      *protocol_done = TRUE;

    return CURLE_OK;
  }

  if(!conn->bits.protoconnstart) {

    result = Curl_proxy_connect(conn, FIRSTSOCKET);
    if(result)
      return result;

    if(CONNECT_FIRSTSOCKET_PROXY_SSL())
      
      return CURLE_OK;

    if(conn->bits.tunnel_proxy && conn->bits.httpproxy && Curl_connect_ongoing(conn))
      
      return CURLE_OK;

    if(conn->handler->connect_it) {
      

      
      result = conn->handler->connect_it(conn, protocol_done);
    }
    else *protocol_done = TRUE;

    
    if(!result)
      conn->bits.protoconnstart = TRUE;
  }

  return result; 
}


CURLcode Curl_preconnect(struct Curl_easy *data)
{
  if(!data->state.buffer) {
    data->state.buffer = malloc(data->set.buffer_size + 1);
    if(!data->state.buffer)
      return CURLE_OUT_OF_MEMORY;
  }
  return CURLE_OK;
}


static CURLMcode multi_runsingle(struct Curl_multi *multi, struct curltime now, struct Curl_easy *data)

{
  struct Curl_message *msg = NULL;
  bool connected;
  bool async;
  bool protocol_connected = FALSE;
  bool dophase_done = FALSE;
  bool done = FALSE;
  CURLMcode rc;
  CURLcode result = CURLE_OK;
  timediff_t timeout_ms;
  timediff_t recv_timeout_ms;
  timediff_t send_timeout_ms;
  int control;

  if(!GOOD_EASY_HANDLE(data))
    return CURLM_BAD_EASY_HANDLE;

  do {
    
    bool stream_error = FALSE;
    rc = CURLM_OK;

    if(multi_ischanged(multi, TRUE)) {
      DEBUGF(infof(data, "multi changed, check CONNECT_PEND queue!\n"));
      process_pending_handles(multi); 
    }

    if(data->conn && data->mstate > CURLM_STATE_CONNECT && data->mstate < CURLM_STATE_COMPLETED) {
      
      data->conn->data = data;
    }

    if(data->conn && (data->mstate >= CURLM_STATE_CONNECT) && (data->mstate < CURLM_STATE_COMPLETED)) {

      
      timeout_ms = Curl_timeleft(data, &now, (data->mstate <= CURLM_STATE_DO)? TRUE:FALSE);


      if(timeout_ms < 0) {
        
        if(data->mstate == CURLM_STATE_WAITRESOLVE)
          failf(data, "Resolving timed out after %" CURL_FORMAT_TIMEDIFF_T " milliseconds", Curl_timediff(now, data->progress.t_startsingle));

        else if(data->mstate == CURLM_STATE_WAITCONNECT)
          failf(data, "Connection timed out after %" CURL_FORMAT_TIMEDIFF_T " milliseconds", Curl_timediff(now, data->progress.t_startsingle));

        else {
          struct SingleRequest *k = &data->req;
          if(k->size != -1) {
            failf(data, "Operation timed out after %" CURL_FORMAT_TIMEDIFF_T " milliseconds with %" CURL_FORMAT_CURL_OFF_T " out of %" CURL_FORMAT_CURL_OFF_T " bytes received", Curl_timediff(now, data->progress.t_startsingle), k->bytecount, k->size);



          }
          else {
            failf(data, "Operation timed out after %" CURL_FORMAT_TIMEDIFF_T " milliseconds with %" CURL_FORMAT_CURL_OFF_T " bytes received", Curl_timediff(now, data->progress.t_startsingle), k->bytecount);



          }
        }

        
        if(data->mstate > CURLM_STATE_DO) {
          streamclose(data->conn, "Disconnected with pending data");
          stream_error = TRUE;
        }
        result = CURLE_OPERATION_TIMEDOUT;
        (void)multi_done(data, result, TRUE);
        
        goto statemachine_end;
      }
    }

    switch(data->mstate) {
    case CURLM_STATE_INIT:
      
      result = Curl_pretransfer(data);

      if(!result) {
        
        multistate(data, CURLM_STATE_CONNECT);
        Curl_pgrsTime(data, TIMER_STARTOP);
        rc = CURLM_CALL_MULTI_PERFORM;
      }
      break;

    case CURLM_STATE_CONNECT_PEND:
      
      break;

    case CURLM_STATE_CONNECT:
      
      
      result = Curl_preconnect(data);
      if(result)
        break;

      Curl_pgrsTime(data, TIMER_STARTSINGLE);
      if(data->set.timeout)
        Curl_expire(data, data->set.timeout, EXPIRE_TIMEOUT);

      if(data->set.connecttimeout)
        Curl_expire(data, data->set.connecttimeout, EXPIRE_CONNECTTIMEOUT);

      result = Curl_connect(data, &async, &protocol_connected);
      if(CURLE_NO_CONNECTION_AVAILABLE == result) {
        
        multistate(data, CURLM_STATE_CONNECT_PEND);

        
        Curl_llist_insert_next(&multi->pending, multi->pending.tail, data, &data->connect_queue);
        result = CURLE_OK;
        break;
      }
      else if(data->state.previouslypending) {
        
        infof(data, "Transfer was pending, now try another\n");
        process_pending_handles(data->multi);
      }

      if(!result) {
        if(async)
          
          multistate(data, CURLM_STATE_WAITRESOLVE);
        else {
          
          rc = CURLM_CALL_MULTI_PERFORM;

          if(protocol_connected)
            multistate(data, CURLM_STATE_DO);
          else {

            if(Curl_connect_ongoing(data->conn))
              multistate(data, CURLM_STATE_WAITPROXYCONNECT);
            else  multistate(data, CURLM_STATE_WAITCONNECT);

          }
        }
      }
      break;

    case CURLM_STATE_WAITRESOLVE:
      
    {
      struct Curl_dns_entry *dns = NULL;
      struct connectdata *conn = data->conn;
      const char *hostname;

      DEBUGASSERT(conn);

      if(conn->bits.httpproxy)
        hostname = conn->http_proxy.host.name;
      else  if(conn->bits.conn_to_host)

        hostname = conn->conn_to_host.name;
      else hostname = conn->host.name;

      
      dns = Curl_fetch_addr(conn, hostname, (int)conn->port);

      if(dns) {

        conn->async.dns = dns;
        conn->async.done = TRUE;

        result = CURLE_OK;
        infof(data, "Hostname '%s' was found in DNS cache\n", hostname);
      }

      if(!dns)
        result = Curl_resolv_check(data->conn, &dns);

      
      singlesocket(multi, data);

      if(dns) {
        
        result = Curl_once_resolved(data->conn, &protocol_connected);

        if(result)
          
          data->conn = NULL; 
        else {
          
          rc = CURLM_CALL_MULTI_PERFORM;
          if(protocol_connected)
            multistate(data, CURLM_STATE_DO);
          else {

            if(Curl_connect_ongoing(data->conn))
              multistate(data, CURLM_STATE_WAITPROXYCONNECT);
            else  multistate(data, CURLM_STATE_WAITCONNECT);

          }
        }
      }

      if(result) {
        
        stream_error = TRUE;
        break;
      }
    }
    break;


    case CURLM_STATE_WAITPROXYCONNECT:
      
      DEBUGASSERT(data->conn);
      result = Curl_http_connect(data->conn, &protocol_connected);

      if(data->conn->bits.proxy_connect_closed) {
        rc = CURLM_CALL_MULTI_PERFORM;
        
        result = CURLE_OK;
        multi_done(data, CURLE_OK, FALSE);
        multistate(data, CURLM_STATE_CONNECT);
      }
      else  if(!result) {

          if(  (data->conn->http_proxy.proxytype != CURLPROXY_HTTPS || data->conn->bits.proxy_ssl_connected[FIRSTSOCKET]) &&  Curl_connect_complete(data->conn)) {




            rc = CURLM_CALL_MULTI_PERFORM;
            
            multistate(data, CURLM_STATE_SENDPROTOCONNECT);
          }
        }
      else stream_error = TRUE;
      break;


    case CURLM_STATE_WAITCONNECT:
      
      DEBUGASSERT(data->conn);
      result = Curl_is_connected(data->conn, FIRSTSOCKET, &connected);
      if(connected && !result) {

        if(  (data->conn->http_proxy.proxytype == CURLPROXY_HTTPS && !data->conn->bits.proxy_ssl_connected[FIRSTSOCKET]) ||  Curl_connect_ongoing(data->conn)) {




          multistate(data, CURLM_STATE_WAITPROXYCONNECT);
          break;
        }

        rc = CURLM_CALL_MULTI_PERFORM;

        multistate(data, data->conn->bits.tunnel_proxy? CURLM_STATE_WAITPROXYCONNECT:

                   CURLM_STATE_SENDPROTOCONNECT);

        multistate(data, CURLM_STATE_SENDPROTOCONNECT);

      }
      else if(result) {
        
        Curl_posttransfer(data);
        multi_done(data, result, TRUE);
        stream_error = TRUE;
        break;
      }
      break;

    case CURLM_STATE_SENDPROTOCONNECT:
      result = protocol_connect(data->conn, &protocol_connected);
      if(!result && !protocol_connected)
        
        multistate(data, CURLM_STATE_PROTOCONNECT);
      else if(!result) {
        
        multistate(data, CURLM_STATE_DO);
        rc = CURLM_CALL_MULTI_PERFORM;
      }
      else {
        
        Curl_posttransfer(data);
        multi_done(data, result, TRUE);
        stream_error = TRUE;
      }
      break;

    case CURLM_STATE_PROTOCONNECT:
      
      result = protocol_connecting(data->conn, &protocol_connected);
      if(!result && protocol_connected) {
        
        multistate(data, CURLM_STATE_DO);
        rc = CURLM_CALL_MULTI_PERFORM;
      }
      else if(result) {
        
        Curl_posttransfer(data);
        multi_done(data, result, TRUE);
        stream_error = TRUE;
      }
      break;

    case CURLM_STATE_DO:
      if(data->set.connect_only) {
        
        connkeep(data->conn, "CONNECT_ONLY");
        multistate(data, CURLM_STATE_DONE);
        result = CURLE_OK;
        rc = CURLM_CALL_MULTI_PERFORM;
      }
      else {
        
        result = multi_do(data, &dophase_done);

        

        if(!result) {
          if(!dophase_done) {

            
            if(data->state.wildcardmatch) {
              struct WildcardData *wc = &data->wildcard;
              if(wc->state == CURLWC_DONE || wc->state == CURLWC_SKIP) {
                
                multi_done(data, CURLE_OK, FALSE);
                multistate(data, CURLM_STATE_DONE);
                rc = CURLM_CALL_MULTI_PERFORM;
                break;
              }
            }

            
            multistate(data, CURLM_STATE_DOING);
            rc = CURLM_OK;
          }

          
          else if(data->conn->bits.do_more) {
            
            multistate(data, CURLM_STATE_DO_MORE);
            rc = CURLM_OK;
          }
          else {
            
            multistate(data, CURLM_STATE_DO_DONE);
            rc = CURLM_CALL_MULTI_PERFORM;
          }
        }
        else if((CURLE_SEND_ERROR == result) && data->conn->bits.reuse) {
          
          char *newurl = NULL;
          followtype follow = FOLLOW_NONE;
          CURLcode drc;

          drc = Curl_retry_request(data->conn, &newurl);
          if(drc) {
            
            result = drc;
            stream_error = TRUE;
          }

          Curl_posttransfer(data);
          drc = multi_done(data, result, FALSE);

          
          if(newurl) {
            if(!drc || (drc == CURLE_SEND_ERROR)) {
              follow = FOLLOW_RETRY;
              drc = Curl_follow(data, newurl, follow);
              if(!drc) {
                multistate(data, CURLM_STATE_CONNECT);
                rc = CURLM_CALL_MULTI_PERFORM;
                result = CURLE_OK;
              }
              else {
                
                result = drc;
              }
            }
            else {
              
              result = drc;
            }
          }
          else {
            
            stream_error = TRUE;
          }
          free(newurl);
        }
        else {
          
          Curl_posttransfer(data);
          if(data->conn)
            multi_done(data, result, FALSE);
          stream_error = TRUE;
        }
      }
      break;

    case CURLM_STATE_DOING:
      
      DEBUGASSERT(data->conn);
      result = protocol_doing(data->conn, &dophase_done);
      if(!result) {
        if(dophase_done) {
          
          multistate(data, data->conn->bits.do_more? CURLM_STATE_DO_MORE:
                     CURLM_STATE_DO_DONE);
          rc = CURLM_CALL_MULTI_PERFORM;
        } 
      }
      else {
        
        Curl_posttransfer(data);
        multi_done(data, result, FALSE);
        stream_error = TRUE;
      }
      break;

    case CURLM_STATE_DO_MORE:
      
      DEBUGASSERT(data->conn);
      result = multi_do_more(data->conn, &control);

      if(!result) {
        if(control) {
          
          multistate(data, control == 1? CURLM_STATE_DO_DONE:
                     CURLM_STATE_DOING);
          rc = CURLM_CALL_MULTI_PERFORM;
        }
        else  rc = CURLM_OK;

      }
      else {
        
        Curl_posttransfer(data);
        multi_done(data, result, FALSE);
        stream_error = TRUE;
      }
      break;

    case CURLM_STATE_DO_DONE:
      DEBUGASSERT(data->conn);
      if(data->conn->bits.multiplex)
        
        process_pending_handles(multi); 

      
      if((data->conn->sockfd != CURL_SOCKET_BAD) || (data->conn->writesockfd != CURL_SOCKET_BAD))
        multistate(data, CURLM_STATE_PERFORM);
      else {

        if(data->state.wildcardmatch && ((data->conn->handler->flags & PROTOPT_WILDCARD) == 0)) {
          data->wildcard.state = CURLWC_DONE;
        }

        multistate(data, CURLM_STATE_DONE);
      }
      rc = CURLM_CALL_MULTI_PERFORM;
      break;

    case CURLM_STATE_TOOFAST: 
      DEBUGASSERT(data->conn);
      
      if(Curl_pgrsUpdate(data->conn))
        result = CURLE_ABORTED_BY_CALLBACK;
      else result = Curl_speedcheck(data, now);

      if(!result) {
        send_timeout_ms = 0;
        if(data->set.max_send_speed > 0)
          send_timeout_ms = Curl_pgrsLimitWaitTime(data->progress.uploaded, data->progress.ul_limit_size, data->set.max_send_speed, data->progress.ul_limit_start, now);





        recv_timeout_ms = 0;
        if(data->set.max_recv_speed > 0)
          recv_timeout_ms = Curl_pgrsLimitWaitTime(data->progress.downloaded, data->progress.dl_limit_size, data->set.max_recv_speed, data->progress.dl_limit_start, now);





        if(!send_timeout_ms && !recv_timeout_ms) {
          multistate(data, CURLM_STATE_PERFORM);
          Curl_ratelimit(data, now);
        }
        else if(send_timeout_ms >= recv_timeout_ms)
          Curl_expire(data, send_timeout_ms, EXPIRE_TOOFAST);
        else Curl_expire(data, recv_timeout_ms, EXPIRE_TOOFAST);
      }
      break;

    case CURLM_STATE_PERFORM:
    {
      char *newurl = NULL;
      bool retry = FALSE;
      bool comeback = FALSE;
      DEBUGASSERT(data->state.buffer);
      
      send_timeout_ms = 0;
      if(data->set.max_send_speed > 0)
        send_timeout_ms = Curl_pgrsLimitWaitTime(data->progress.uploaded, data->progress.ul_limit_size, data->set.max_send_speed, data->progress.ul_limit_start, now);




      
      recv_timeout_ms = 0;
      if(data->set.max_recv_speed > 0)
        recv_timeout_ms = Curl_pgrsLimitWaitTime(data->progress.downloaded, data->progress.dl_limit_size, data->set.max_recv_speed, data->progress.dl_limit_start, now);




      if(send_timeout_ms || recv_timeout_ms) {
        Curl_ratelimit(data, now);
        multistate(data, CURLM_STATE_TOOFAST);
        if(send_timeout_ms >= recv_timeout_ms)
          Curl_expire(data, send_timeout_ms, EXPIRE_TOOFAST);
        else Curl_expire(data, recv_timeout_ms, EXPIRE_TOOFAST);
        break;
      }

      
      result = Curl_readwrite(data->conn, data, &done, &comeback);

      if(done || (result == CURLE_RECV_ERROR)) {
        
        CURLcode ret = Curl_retry_request(data->conn, &newurl);
        if(!ret)
          retry = (newurl)?TRUE:FALSE;
        else if(!result)
          result = ret;

        if(retry) {
          
          result = CURLE_OK;
          done = TRUE;
        }
      }
      else if((CURLE_HTTP2_STREAM == result) && Curl_h2_http_1_1_error(data->conn)) {
        CURLcode ret = Curl_retry_request(data->conn, &newurl);

        if(!ret) {
          infof(data, "Downgrades to HTTP/1.1!\n");
          data->set.httpversion = CURL_HTTP_VERSION_1_1;
          
          data->state.errorbuf = FALSE;
          if(!newurl)
            
            newurl = strdup(data->change.url);
          
          retry = TRUE;
          result = CURLE_OK;
          done = TRUE;
        }
        else result = ret;
      }

      if(result) {
        

        if(!(data->conn->handler->flags & PROTOPT_DUAL) && result != CURLE_HTTP2_STREAM)
          streamclose(data->conn, "Transfer returned error");

        Curl_posttransfer(data);
        multi_done(data, result, TRUE);
      }
      else if(done) {
        followtype follow = FOLLOW_NONE;

        
        Curl_posttransfer(data);

        
        if(data->req.newurl || retry) {
          if(!retry) {
            
            free(newurl);
            newurl = data->req.newurl;
            data->req.newurl = NULL;
            follow = FOLLOW_REDIR;
          }
          else follow = FOLLOW_RETRY;
          (void)multi_done(data, CURLE_OK, FALSE);
          
          result = Curl_follow(data, newurl, follow);
          if(!result) {
            multistate(data, CURLM_STATE_CONNECT);
            rc = CURLM_CALL_MULTI_PERFORM;
          }
          free(newurl);
        }
        else {
          

          
          if(data->req.location) {
            free(newurl);
            newurl = data->req.location;
            data->req.location = NULL;
            result = Curl_follow(data, newurl, FOLLOW_FAKE);
            free(newurl);
            if(result) {
              stream_error = TRUE;
              result = multi_done(data, result, TRUE);
            }
          }

          if(!result) {
            multistate(data, CURLM_STATE_DONE);
            rc = CURLM_CALL_MULTI_PERFORM;
          }
        }
      }
      else if(comeback) {
        
        Curl_expire(data, 0, EXPIRE_RUN_NOW);
        rc = CURLM_OK;
      }
      break;
    }

    case CURLM_STATE_DONE:
      
      rc = CURLM_CALL_MULTI_PERFORM;

      if(data->conn) {
        CURLcode res;

        if(data->conn->bits.multiplex)
          
          process_pending_handles(multi); 

        
        res = multi_done(data, result, FALSE);

        
        if(!result)
          result = res;

        
        Curl_detach_connnection(data);
      }


      if(data->state.wildcardmatch) {
        if(data->wildcard.state != CURLWC_DONE) {
          
          multistate(data, CURLM_STATE_INIT);
          break;
        }
      }

      
      multistate(data, CURLM_STATE_COMPLETED);
      break;

    case CURLM_STATE_COMPLETED:
      break;

    case CURLM_STATE_MSGSENT:
      data->result = result;
      return CURLM_OK; 

    default:
      return CURLM_INTERNAL_ERROR;
    }
    statemachine_end:

    if(data->mstate < CURLM_STATE_COMPLETED) {
      if(result) {
        

        

        
        process_pending_handles(multi); 

        if(data->conn) {
          if(stream_error) {
            
            bool dead_connection = result == CURLE_OPERATION_TIMEDOUT;
            struct connectdata *conn = data->conn;

            
            Curl_detach_connnection(data);

            
            Curl_conncache_remove_conn(data, conn, TRUE);

            
            Curl_disconnect(data, conn, dead_connection);
          }
        }
        else if(data->mstate == CURLM_STATE_CONNECT) {
          
          (void)Curl_posttransfer(data);
        }

        multistate(data, CURLM_STATE_COMPLETED);
        rc = CURLM_CALL_MULTI_PERFORM;
      }
      
      else if(data->conn && Curl_pgrsUpdate(data->conn)) {
        
        result = CURLE_ABORTED_BY_CALLBACK;
        streamclose(data->conn, "Aborted by callback");

        
        multistate(data, (data->mstate < CURLM_STATE_DONE)? CURLM_STATE_DONE: CURLM_STATE_COMPLETED);
        rc = CURLM_CALL_MULTI_PERFORM;
      }
    }

    if(CURLM_STATE_COMPLETED == data->mstate) {
      if(data->set.fmultidone) {
        
        data->set.fmultidone(data, result);
      }
      else {
        
        msg = &data->msg;

        msg->extmsg.msg = CURLMSG_DONE;
        msg->extmsg.easy_handle = data;
        msg->extmsg.data.result = result;

        rc = multi_addmsg(multi, msg);
        DEBUGASSERT(!data->conn);
      }
      multistate(data, CURLM_STATE_MSGSENT);
    }
  } while((rc == CURLM_CALL_MULTI_PERFORM) || multi_ischanged(multi, FALSE));

  data->result = result;
  return rc;
}


CURLMcode curl_multi_perform(struct Curl_multi *multi, int *running_handles)
{
  struct Curl_easy *data;
  CURLMcode returncode = CURLM_OK;
  struct Curl_tree *t;
  struct curltime now = Curl_now();

  if(!GOOD_MULTI_HANDLE(multi))
    return CURLM_BAD_HANDLE;

  if(multi->in_callback)
    return CURLM_RECURSIVE_API_CALL;

  data = multi->easyp;
  while(data) {
    CURLMcode result;
    SIGPIPE_VARIABLE(pipe_st);

    sigpipe_ignore(data, &pipe_st);
    result = multi_runsingle(multi, now, data);
    sigpipe_restore(&pipe_st);

    if(result)
      returncode = result;

    data = data->next; 
  }

  
  do {
    multi->timetree = Curl_splaygetbest(now, multi->timetree, &t);
    if(t)
      
      (void)add_next_timeout(now, multi, t->payload);

  } while(t);

  *running_handles = multi->num_alive;

  if(CURLM_OK >= returncode)
    Curl_update_timer(multi);

  return returncode;
}

CURLMcode curl_multi_cleanup(struct Curl_multi *multi)
{
  struct Curl_easy *data;
  struct Curl_easy *nextdata;

  if(GOOD_MULTI_HANDLE(multi)) {
    if(multi->in_callback)
      return CURLM_RECURSIVE_API_CALL;

    multi->type = 0; 

    
    data = multi->easyp;
    while(data) {
      nextdata = data->next;
      if(!data->state.done && data->conn)
        
        (void)multi_done(data, CURLE_OK, TRUE);
      if(data->dns.hostcachetype == HCACHE_MULTI) {
        
        Curl_hostcache_clean(data, data->dns.hostcache);
        data->dns.hostcache = NULL;
        data->dns.hostcachetype = HCACHE_NONE;
      }

      
      data->state.conn_cache = NULL;
      data->multi = NULL; 


      if(data->psl == &multi->psl)
        data->psl = NULL;


      data = nextdata;
    }

    
    Curl_conncache_close_all_connections(&multi->conn_cache);

    Curl_hash_destroy(&multi->sockhash);
    Curl_conncache_destroy(&multi->conn_cache);
    Curl_llist_destroy(&multi->msglist, NULL);
    Curl_llist_destroy(&multi->pending, NULL);

    Curl_hash_destroy(&multi->hostcache);
    Curl_psl_destroy(&multi->psl);


    sclose(multi->wakeup_pair[0]);
    sclose(multi->wakeup_pair[1]);

    free(multi);

    return CURLM_OK;
  }
  return CURLM_BAD_HANDLE;
}



CURLMsg *curl_multi_info_read(struct Curl_multi *multi, int *msgs_in_queue)
{
  struct Curl_message *msg;

  *msgs_in_queue = 0; 

  if(GOOD_MULTI_HANDLE(multi) && !multi->in_callback && Curl_llist_count(&multi->msglist)) {

    
    struct curl_llist_element *e;

    
    e = multi->msglist.head;

    msg = e->ptr;

    
    Curl_llist_remove(&multi->msglist, e, NULL);

    *msgs_in_queue = curlx_uztosi(Curl_llist_count(&multi->msglist));

    return &msg->extmsg;
  }
  return NULL;
}


static CURLMcode singlesocket(struct Curl_multi *multi, struct Curl_easy *data)
{
  curl_socket_t socks[MAX_SOCKSPEREASYHANDLE];
  int i;
  struct Curl_sh_entry *entry;
  curl_socket_t s;
  int num;
  unsigned int curraction;
  int actions[MAX_SOCKSPEREASYHANDLE];

  for(i = 0; i< MAX_SOCKSPEREASYHANDLE; i++)
    socks[i] = CURL_SOCKET_BAD;

  
  curraction = multi_getsock(data, socks);

  

  
  for(i = 0; (i< MAX_SOCKSPEREASYHANDLE) && (curraction & (GETSOCK_READSOCK(i) | GETSOCK_WRITESOCK(i)));
      i++) {
    unsigned int action = CURL_POLL_NONE;
    unsigned int prevaction = 0;
    unsigned int comboaction;
    bool sincebefore = FALSE;

    s = socks[i];

    
    entry = sh_getentry(&multi->sockhash, s);

    if(curraction & GETSOCK_READSOCK(i))
      action |= CURL_POLL_IN;
    if(curraction & GETSOCK_WRITESOCK(i))
      action |= CURL_POLL_OUT;

    actions[i] = action;
    if(entry) {
      
      int j;
      for(j = 0; j< data->numsocks; j++) {
        if(s == data->sockets[j]) {
          prevaction = data->actions[j];
          sincebefore = TRUE;
          break;
        }
      }
    }
    else {
      
      entry = sh_addentry(&multi->sockhash, s);
      if(!entry)
        
        return CURLM_OUT_OF_MEMORY;
    }
    if(sincebefore && (prevaction != action)) {
      
      if(prevaction & CURL_POLL_IN)
        entry->readers--;
      if(prevaction & CURL_POLL_OUT)
        entry->writers--;
      if(action & CURL_POLL_IN)
        entry->readers++;
      if(action & CURL_POLL_OUT)
        entry->writers++;
    }
    else if(!sincebefore) {
      
      entry->users++;
      if(action & CURL_POLL_IN)
        entry->readers++;
      if(action & CURL_POLL_OUT)
        entry->writers++;

      
      if(!Curl_hash_add(&entry->transfers, (char *)&data,  sizeof(struct Curl_easy *), data))
        return CURLM_OUT_OF_MEMORY;
    }

    comboaction = (entry->writers? CURL_POLL_OUT : 0) | (entry->readers ? CURL_POLL_IN : 0);

    
    if(sincebefore && (entry->action == comboaction))
      
      continue;

    if(multi->socket_cb)
      multi->socket_cb(data, s, comboaction, multi->socket_userp, entry->socketp);

    entry->action = comboaction; 
  }

  num = i; 

  
  for(i = 0; i< data->numsocks; i++) {
    int j;
    bool stillused = FALSE;
    s = data->sockets[i];
    for(j = 0; j < num; j++) {
      if(s == socks[j]) {
        
        stillused = TRUE;
        break;
      }
    }
    if(stillused)
      continue;

    entry = sh_getentry(&multi->sockhash, s);
    
    if(entry) {
      int oldactions = data->actions[i];
      
      entry->users--;
      if(oldactions & CURL_POLL_OUT)
        entry->writers--;
      if(oldactions & CURL_POLL_IN)
        entry->readers--;
      if(!entry->users) {
        if(multi->socket_cb)
          multi->socket_cb(data, s, CURL_POLL_REMOVE, multi->socket_userp, entry->socketp);

        sh_delentry(entry, &multi->sockhash, s);
      }
      else {
        
        if(Curl_hash_delete(&entry->transfers, (char *)&data, sizeof(struct Curl_easy *))) {
          DEBUGASSERT(NULL);
        }
      }
    }
  } 

  memcpy(data->sockets, socks, num*sizeof(curl_socket_t));
  memcpy(data->actions, actions, num*sizeof(int));
  data->numsocks = num;
  return CURLM_OK;
}

void Curl_updatesocket(struct Curl_easy *data)
{
  singlesocket(data->multi, data);
}




void Curl_multi_closed(struct Curl_easy *data, curl_socket_t s)
{
  if(data) {
    
    struct Curl_multi *multi = data->multi;
    if(multi) {
      
      struct Curl_sh_entry *entry = sh_getentry(&multi->sockhash, s);

      if(entry) {
        if(multi->socket_cb)
          multi->socket_cb(data, s, CURL_POLL_REMOVE, multi->socket_userp, entry->socketp);


        
        sh_delentry(entry, &multi->sockhash, s);
      }
    }
  }
}


static CURLMcode add_next_timeout(struct curltime now, struct Curl_multi *multi, struct Curl_easy *d)

{
  struct curltime *tv = &d->state.expiretime;
  struct curl_llist *list = &d->state.timeoutlist;
  struct curl_llist_element *e;
  struct time_node *node = NULL;

  
  for(e = list->head; e;) {
    struct curl_llist_element *n = e->next;
    timediff_t diff;
    node = (struct time_node *)e->ptr;
    diff = Curl_timediff(node->time, now);
    if(diff <= 0)
      
      Curl_llist_remove(list, e, NULL);
    else  break;

    e = n;
  }
  e = list->head;
  if(!e) {
    
    tv->tv_sec = 0;
    tv->tv_usec = 0;
  }
  else {
    
    memcpy(tv, &node->time, sizeof(*tv));

    
    multi->timetree = Curl_splayinsert(*tv, multi->timetree, &d->state.timenode);
  }
  return CURLM_OK;
}

static CURLMcode multi_socket(struct Curl_multi *multi, bool checkall, curl_socket_t s, int ev_bitmask, int *running_handles)



{
  CURLMcode result = CURLM_OK;
  struct Curl_easy *data = NULL;
  struct Curl_tree *t;
  struct curltime now = Curl_now();

  if(checkall) {
    
    result = curl_multi_perform(multi, running_handles);

    
    if(result != CURLM_BAD_HANDLE) {
      data = multi->easyp;
      while(data && !result) {
        result = singlesocket(multi, data);
        data = data->next;
      }
    }

    
    return result;
  }
  if(s != CURL_SOCKET_TIMEOUT) {
    struct Curl_sh_entry *entry = sh_getentry(&multi->sockhash, s);

    if(!entry)
      
      ;
    else {
      struct curl_hash_iterator iter;
      struct curl_hash_element *he;

      
      Curl_hash_start_iterate(&entry->transfers, &iter);
      for(he = Curl_hash_next_element(&iter); he;
          he = Curl_hash_next_element(&iter)) {
        data = (struct Curl_easy *)he->ptr;
        DEBUGASSERT(data);
        DEBUGASSERT(data->magic == CURLEASY_MAGIC_NUMBER);

        if(data->conn && !(data->conn->handler->flags & PROTOPT_DIRLOCK))
          
          data->conn->cselect_bits = ev_bitmask;

        Curl_expire(data, 0, EXPIRE_RUN_NOW);
      }

      

      data = NULL; 
      now = Curl_now(); 
    }
  }
  else {
    
    memset(&multi->timer_lastcall, 0, sizeof(multi->timer_lastcall));
  }

  
  do {
    
    if(data) {
      SIGPIPE_VARIABLE(pipe_st);

      sigpipe_ignore(data, &pipe_st);
      result = multi_runsingle(multi, now, data);
      sigpipe_restore(&pipe_st);

      if(CURLM_OK >= result) {
        
        result = singlesocket(multi, data);
        if(result)
          return result;
      }
    }

    

    multi->timetree = Curl_splaygetbest(now, multi->timetree, &t);
    if(t) {
      data = t->payload; 
      (void)add_next_timeout(now, multi, t->payload);
    }

  } while(t);

  *running_handles = multi->num_alive;
  return result;
}


CURLMcode curl_multi_setopt(struct Curl_multi *multi, CURLMoption option, ...)
{
  CURLMcode res = CURLM_OK;
  va_list param;

  if(!GOOD_MULTI_HANDLE(multi))
    return CURLM_BAD_HANDLE;

  if(multi->in_callback)
    return CURLM_RECURSIVE_API_CALL;

  va_start(param, option);

  switch(option) {
  case CURLMOPT_SOCKETFUNCTION:
    multi->socket_cb = va_arg(param, curl_socket_callback);
    break;
  case CURLMOPT_SOCKETDATA:
    multi->socket_userp = va_arg(param, void *);
    break;
  case CURLMOPT_PUSHFUNCTION:
    multi->push_cb = va_arg(param, curl_push_callback);
    break;
  case CURLMOPT_PUSHDATA:
    multi->push_userp = va_arg(param, void *);
    break;
  case CURLMOPT_PIPELINING:
    multi->multiplexing = va_arg(param, long) & CURLPIPE_MULTIPLEX;
    break;
  case CURLMOPT_TIMERFUNCTION:
    multi->timer_cb = va_arg(param, curl_multi_timer_callback);
    break;
  case CURLMOPT_TIMERDATA:
    multi->timer_userp = va_arg(param, void *);
    break;
  case CURLMOPT_MAXCONNECTS:
    multi->maxconnects = va_arg(param, long);
    break;
  case CURLMOPT_MAX_HOST_CONNECTIONS:
    multi->max_host_connections = va_arg(param, long);
    break;
  case CURLMOPT_MAX_TOTAL_CONNECTIONS:
    multi->max_total_connections = va_arg(param, long);
    break;
    
  case CURLMOPT_MAX_PIPELINE_LENGTH:
    break;
  case CURLMOPT_CONTENT_LENGTH_PENALTY_SIZE:
    break;
  case CURLMOPT_CHUNK_LENGTH_PENALTY_SIZE:
    break;
  case CURLMOPT_PIPELINING_SITE_BL:
    break;
  case CURLMOPT_PIPELINING_SERVER_BL:
    break;
  case CURLMOPT_MAX_CONCURRENT_STREAMS:
    {
      long streams = va_arg(param, long);
      if(streams < 1)
        streams = 100;
      multi->max_concurrent_streams = curlx_sltoui(streams);
    }
    break;
  default:
    res = CURLM_UNKNOWN_OPTION;
    break;
  }
  va_end(param);
  return res;
}




CURLMcode curl_multi_socket(struct Curl_multi *multi, curl_socket_t s, int *running_handles)
{
  CURLMcode result;
  if(multi->in_callback)
    return CURLM_RECURSIVE_API_CALL;
  result = multi_socket(multi, FALSE, s, 0, running_handles);
  if(CURLM_OK >= result)
    Curl_update_timer(multi);
  return result;
}

CURLMcode curl_multi_socket_action(struct Curl_multi *multi, curl_socket_t s, int ev_bitmask, int *running_handles)
{
  CURLMcode result;
  if(multi->in_callback)
    return CURLM_RECURSIVE_API_CALL;
  result = multi_socket(multi, FALSE, s, ev_bitmask, running_handles);
  if(CURLM_OK >= result)
    Curl_update_timer(multi);
  return result;
}

CURLMcode curl_multi_socket_all(struct Curl_multi *multi, int *running_handles)

{
  CURLMcode result;
  if(multi->in_callback)
    return CURLM_RECURSIVE_API_CALL;
  result = multi_socket(multi, TRUE, CURL_SOCKET_BAD, 0, running_handles);
  if(CURLM_OK >= result)
    Curl_update_timer(multi);
  return result;
}

static CURLMcode multi_timeout(struct Curl_multi *multi, long *timeout_ms)
{
  static struct curltime tv_zero = {0, 0};

  if(multi->timetree) {
    
    struct curltime now = Curl_now();

    
    multi->timetree = Curl_splay(tv_zero, multi->timetree);

    if(Curl_splaycomparekeys(multi->timetree->key, now) > 0) {
      
      timediff_t diff = Curl_timediff(multi->timetree->key, now);
      if(diff <= 0)
        
        *timeout_ms = 1;
      else  *timeout_ms = (long)diff;

    }
    else  *timeout_ms = 0;

  }
  else *timeout_ms = -1;

  return CURLM_OK;
}

CURLMcode curl_multi_timeout(struct Curl_multi *multi, long *timeout_ms)
{
  
  if(!GOOD_MULTI_HANDLE(multi))
    return CURLM_BAD_HANDLE;

  if(multi->in_callback)
    return CURLM_RECURSIVE_API_CALL;

  return multi_timeout(multi, timeout_ms);
}


void Curl_update_timer(struct Curl_multi *multi)
{
  long timeout_ms;

  if(!multi->timer_cb)
    return;
  if(multi_timeout(multi, &timeout_ms)) {
    return;
  }
  if(timeout_ms < 0) {
    static const struct curltime none = {0, 0};
    if(Curl_splaycomparekeys(none, multi->timer_lastcall)) {
      multi->timer_lastcall = none;
      
      multi->timer_cb(multi, -1, multi->timer_userp);
      return;
    }
    return;
  }

  
  if(Curl_splaycomparekeys(multi->timetree->key, multi->timer_lastcall) == 0)
    return;

  multi->timer_lastcall = multi->timetree->key;

  multi->timer_cb(multi, timeout_ms, multi->timer_userp);
}


static void multi_deltimeout(struct Curl_easy *data, expire_id eid)
{
  struct curl_llist_element *e;
  struct curl_llist *timeoutlist = &data->state.timeoutlist;
  
  for(e = timeoutlist->head; e; e = e->next) {
    struct time_node *n = (struct time_node *)e->ptr;
    if(n->eid == eid) {
      Curl_llist_remove(timeoutlist, e, NULL);
      return;
    }
  }
}


static CURLMcode multi_addtimeout(struct Curl_easy *data, struct curltime *stamp, expire_id eid)


{
  struct curl_llist_element *e;
  struct time_node *node;
  struct curl_llist_element *prev = NULL;
  size_t n;
  struct curl_llist *timeoutlist = &data->state.timeoutlist;

  node = &data->state.expires[eid];

  
  memcpy(&node->time, stamp, sizeof(*stamp));
  node->eid = eid; 

  n = Curl_llist_count(timeoutlist);
  if(n) {
    
    for(e = timeoutlist->head; e; e = e->next) {
      struct time_node *check = (struct time_node *)e->ptr;
      timediff_t diff = Curl_timediff(check->time, node->time);
      if(diff > 0)
        break;
      prev = e;
    }

  }
  

  Curl_llist_insert_next(timeoutlist, prev, node, &node->list);
  return CURLM_OK;
}


void Curl_expire(struct Curl_easy *data, timediff_t milli, expire_id id)
{
  struct Curl_multi *multi = data->multi;
  struct curltime *nowp = &data->state.expiretime;
  struct curltime set;

  
  if(!multi)
    return;

  DEBUGASSERT(id < EXPIRE_LAST);

  set = Curl_now();
  set.tv_sec += (time_t)(milli/1000); 
  set.tv_usec += (unsigned int)(milli%1000)*1000;

  if(set.tv_usec >= 1000000) {
    set.tv_sec++;
    set.tv_usec -= 1000000;
  }

  
  multi_deltimeout(data, id);

  
  multi_addtimeout(data, &set, id);

  if(nowp->tv_sec || nowp->tv_usec) {
    
    timediff_t diff = Curl_timediff(set, *nowp);
    int rc;

    if(diff > 0) {
      
      return;
    }

    
    rc = Curl_splayremovebyaddr(multi->timetree, &data->state.timenode, &multi->timetree);

    if(rc)
      infof(data, "Internal error removing splay node = %d\n", rc);
  }

  
  *nowp = set;
  data->state.timenode.payload = data;
  multi->timetree = Curl_splayinsert(*nowp, multi->timetree, &data->state.timenode);
}


void Curl_expire_done(struct Curl_easy *data, expire_id id)
{
  
  multi_deltimeout(data, id);
}


void Curl_expire_clear(struct Curl_easy *data)
{
  struct Curl_multi *multi = data->multi;
  struct curltime *nowp = &data->state.expiretime;

  
  if(!multi)
    return;

  if(nowp->tv_sec || nowp->tv_usec) {
    
    struct curl_llist *list = &data->state.timeoutlist;
    int rc;

    rc = Curl_splayremovebyaddr(multi->timetree, &data->state.timenode, &multi->timetree);

    if(rc)
      infof(data, "Internal error clearing splay node = %d\n", rc);

    
    while(list->size > 0) {
      Curl_llist_remove(list, list->tail, NULL);
    }


    infof(data, "Expire cleared (transfer %p)\n", data);

    nowp->tv_sec = 0;
    nowp->tv_usec = 0;
  }
}




CURLMcode curl_multi_assign(struct Curl_multi *multi, curl_socket_t s, void *hashp)
{
  struct Curl_sh_entry *there = NULL;

  if(multi->in_callback)
    return CURLM_RECURSIVE_API_CALL;

  there = sh_getentry(&multi->sockhash, s);

  if(!there)
    return CURLM_BAD_SOCKET;

  there->socketp = hashp;

  return CURLM_OK;
}

size_t Curl_multi_max_host_connections(struct Curl_multi *multi)
{
  return multi ? multi->max_host_connections : 0;
}

size_t Curl_multi_max_total_connections(struct Curl_multi *multi)
{
  return multi ? multi->max_total_connections : 0;
}



void Curl_multiuse_state(struct connectdata *conn, int bundlestate)
{
  DEBUGASSERT(conn);
  DEBUGASSERT(conn->bundle);
  DEBUGASSERT(conn->data);
  DEBUGASSERT(conn->data->multi);

  conn->bundle->multiuse = bundlestate;
  process_pending_handles(conn->data->multi);
}

static void process_pending_handles(struct Curl_multi *multi)
{
  struct curl_llist_element *e = multi->pending.head;
  if(e) {
    struct Curl_easy *data = e->ptr;

    DEBUGASSERT(data->mstate == CURLM_STATE_CONNECT_PEND);

    multistate(data, CURLM_STATE_CONNECT);

    
    Curl_llist_remove(&multi->pending, e, NULL);

    
    Curl_expire(data, 0, EXPIRE_RUN_NOW);

    
    data->state.previouslypending = TRUE;
  }
}

void Curl_set_in_callback(struct Curl_easy *data, bool value)
{
  
  if(data) {
    if(data->multi_easy)
      data->multi_easy->in_callback = value;
    else if(data->multi)
      data->multi->in_callback = value;
  }
}

bool Curl_is_in_callback(struct Curl_easy *easy)
{
  return ((easy->multi && easy->multi->in_callback) || (easy->multi_easy && easy->multi_easy->in_callback));
}


void Curl_multi_dump(struct Curl_multi *multi)
{
  struct Curl_easy *data;
  int i;
  fprintf(stderr, "* Multi status: %d handles, %d alive\n", multi->num_easy, multi->num_alive);
  for(data = multi->easyp; data; data = data->next) {
    if(data->mstate < CURLM_STATE_COMPLETED) {
      
      fprintf(stderr, "handle %p, state %s, %d sockets\n", (void *)data, statename[data->mstate], data->numsocks);

      for(i = 0; i < data->numsocks; i++) {
        curl_socket_t s = data->sockets[i];
        struct Curl_sh_entry *entry = sh_getentry(&multi->sockhash, s);

        fprintf(stderr, "%d ", (int)s);
        if(!entry) {
          fprintf(stderr, "INTERNAL CONFUSION\n");
          continue;
        }
        fprintf(stderr, "[%s %s] ", (entry->action&CURL_POLL_IN)?"RECVING":"", (entry->action&CURL_POLL_OUT)?"SENDING":"");

      }
      if(data->numsocks)
        fprintf(stderr, "\n");
    }
  }
}


unsigned int Curl_multi_max_concurrent_streams(struct Curl_multi *multi)
{
  DEBUGASSERT(multi);
  return multi->max_concurrent_streams;
}
