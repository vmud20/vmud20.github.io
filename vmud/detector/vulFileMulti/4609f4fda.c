













































bool curl_win32_idn_to_ascii(const char *in, char **out);




























































static struct connectdata * find_oldest_idle_connection_in_bundle(struct Curl_easy *data, struct connectbundle *bundle);

static void conn_free(struct connectdata *conn);
static void free_fixed_hostname(struct hostname *host);
static void signalPipeClose(struct curl_llist *pipeline, bool pipe_broke);
static CURLcode parse_url_login(struct Curl_easy *data, struct connectdata *conn, char **userptr, char **passwdptr, char **optionsptr);


static CURLcode parse_login_details(const char *login, const size_t len, char **userptr, char **passwdptr, char **optionsptr);

static unsigned int get_protocol_family(unsigned int protocol);



static const struct Curl_handler * const protocols[] = {


  &Curl_handler_http,    &Curl_handler_https,    &Curl_handler_ftp,    &Curl_handler_ftps,    &Curl_handler_telnet,    &Curl_handler_dict,    &Curl_handler_ldap,   &Curl_handler_ldaps,     &Curl_handler_file,    &Curl_handler_tftp,    &Curl_handler_scp, &Curl_handler_sftp,    &Curl_handler_imap,  &Curl_handler_imaps,     &Curl_handler_pop3,  &Curl_handler_pop3s,      &Curl_handler_smb,  &Curl_handler_smbs,     &Curl_handler_smtp,  &Curl_handler_smtps,     &Curl_handler_rtsp,    &Curl_handler_gopher,    &Curl_handler_rtmp, &Curl_handler_rtmpt, &Curl_handler_rtmpe, &Curl_handler_rtmpte, &Curl_handler_rtmps, &Curl_handler_rtmpts,   (struct Curl_handler *) NULL };





























































































static const struct Curl_handler Curl_handler_dummy = {
  "<no protocol>",                       ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, 0, 0, PROTOPT_NONE };

















void Curl_freeset(struct Curl_easy *data)
{
  
  enum dupstring i;
  for(i=(enum dupstring)0; i < STRING_LAST; i++) {
    Curl_safefree(data->set.str[i]);
  }

  if(data->change.referer_alloc) {
    Curl_safefree(data->change.referer);
    data->change.referer_alloc = FALSE;
  }
  data->change.referer = NULL;
  if(data->change.url_alloc) {
    Curl_safefree(data->change.url);
    data->change.url_alloc = FALSE;
  }
  data->change.url = NULL;
}

static CURLcode setstropt(char **charp, const char *s)
{
  

  Curl_safefree(*charp);

  if(s) {
    char *str = strdup(s);

    if(!str)
      return CURLE_OUT_OF_MEMORY;

    *charp = str;
  }

  return CURLE_OK;
}

static CURLcode setstropt_userpwd(char *option, char **userp, char **passwdp)
{
  CURLcode result = CURLE_OK;
  char *user = NULL;
  char *passwd = NULL;

  
  if(option) {
    result = parse_login_details(option, strlen(option), (userp ? &user : NULL), (passwdp ? &passwd : NULL), NULL);


  }

  if(!result) {
    
    if(userp) {
      if(!user && option && option[0] == ':') {
        
        user = strdup("");
        if(!user)
          result = CURLE_OUT_OF_MEMORY;
      }

      Curl_safefree(*userp);
      *userp = user;
    }

    
    if(passwdp) {
      Curl_safefree(*passwdp);
      *passwdp = passwd;
    }
  }

  return result;
}

CURLcode Curl_dupset(struct Curl_easy *dst, struct Curl_easy *src)
{
  CURLcode result = CURLE_OK;
  enum dupstring i;

  
  dst->set = src->set;

  
  memset(dst->set.str, 0, STRING_LAST * sizeof(char *));

  
  for(i=(enum dupstring)0; i< STRING_LASTZEROTERMINATED; i++) {
    result = setstropt(&dst->set.str[i], src->set.str[i]);
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

  return CURLE_OK;
}



CURLcode Curl_close(struct Curl_easy *data)
{
  struct Curl_multi *m;

  if(!data)
    return CURLE_OK;

  Curl_expire_clear(data); 

  m = data->multi;

  if(m)
    
    curl_multi_remove_handle(data->multi, data);

  if(data->multi_easy)
    
    curl_multi_cleanup(data->multi_easy);

  
  Curl_llist_destroy(&data->state.timeoutlist, NULL);

  data->magic = 0; 

  if(data->state.rangestringalloc)
    free(data->state.range);

  
  Curl_safefree(data->state.pathbuffer);
  data->state.path = NULL;

  
  Curl_free_request_state(data);

  
  Curl_ssl_close_all(data);
  Curl_safefree(data->state.first_host);
  Curl_safefree(data->state.scratch);
  Curl_ssl_free_certinfo(data);

  
  free(data->req.newurl);
  data->req.newurl = NULL;

  if(data->change.referer_alloc) {
    Curl_safefree(data->change.referer);
    data->change.referer_alloc = FALSE;
  }
  data->change.referer = NULL;

  if(data->change.url_alloc) {
    Curl_safefree(data->change.url);
    data->change.url_alloc = FALSE;
  }
  data->change.url = NULL;

  Curl_safefree(data->state.buffer);
  Curl_safefree(data->state.headerbuff);

  Curl_flush_cookies(data, 1);

  Curl_digest_cleanup(data);

  Curl_safefree(data->info.contenttype);
  Curl_safefree(data->info.wouldredirect);

  
  Curl_resolver_cleanup(data->state.resolver);

  Curl_http2_cleanup_dependencies(data);
  Curl_convert_close(data);

  
  if(data->share) {
    Curl_share_lock(data, CURL_LOCK_DATA_SHARE, CURL_LOCK_ACCESS_SINGLE);
    data->share->dirty--;
    Curl_share_unlock(data, CURL_LOCK_DATA_SHARE);
  }

  if(data->set.wildcardmatch) {
    
    struct WildcardData *wc = &data->wildcard;
    Curl_wildcard_dtor(wc);
  }

  Curl_freeset(data);
  free(data);
  return CURLE_OK;
}


CURLcode Curl_init_userdefined(struct UserDefined *set)
{
  CURLcode result = CURLE_OK;

  set->out = stdout; 
  set->in_set = stdin;  
  set->err  = stderr;  

  
  set->fwrite_func = (curl_write_callback)fwrite;

  
  set->fread_func_set = (curl_read_callback)fread;
  set->is_fread_set = 0;
  set->is_fwrite_set = 0;

  set->seek_func = ZERO_NULL;
  set->seek_client = ZERO_NULL;

  
  set->convfromnetwork = ZERO_NULL;
  set->convtonetwork   = ZERO_NULL;
  set->convfromutf8    = ZERO_NULL;

  set->filesize = -1;        
  set->postfieldsize = -1;   
  set->maxredirs = -1;       

  set->httpreq = HTTPREQ_GET; 
  set->rtspreq = RTSPREQ_OPTIONS; 
  set->ftp_use_epsv = TRUE;   
  set->ftp_use_eprt = TRUE;   
  set->ftp_use_pret = FALSE;  
  set->ftp_filemethod = FTPFILE_MULTICWD;

  set->dns_cache_timeout = 60; 

  
  set->general_ssl.max_ssl_sessions = 5;

  set->proxyport = 0;
  set->proxytype = CURLPROXY_HTTP; 
  set->httpauth = CURLAUTH_BASIC;  
  set->proxyauth = CURLAUTH_BASIC; 

  
  set->hide_progress = TRUE;  

  
  set->ssl.primary.verifypeer = TRUE;
  set->ssl.primary.verifyhost = TRUE;

  set->ssl.authtype = CURL_TLSAUTH_NONE;

  set->ssh_auth_types = CURLSSH_AUTH_DEFAULT; 
  set->general_ssl.sessionid = TRUE; 
  set->proxy_ssl = set->ssl;

  set->new_file_perms = 0644;    
  set->new_directory_perms = 0755; 

  
  set->allowed_protocols = CURLPROTO_ALL;
  set->redir_protocols = CURLPROTO_ALL &   ~(CURLPROTO_FILE | CURLPROTO_SCP | CURLPROTO_SMB | CURLPROTO_SMBS);



  
  set->socks5_gssapi_nec = FALSE;


  

  result = setstropt(&set->str[STRING_SSL_CAFILE_ORIG], CURL_CA_BUNDLE);
  if(result)
    return result;

  result = setstropt(&set->str[STRING_SSL_CAFILE_PROXY], CURL_CA_BUNDLE);
  if(result)
    return result;


  result = setstropt(&set->str[STRING_SSL_CAPATH_ORIG], CURL_CA_PATH);
  if(result)
    return result;

  result = setstropt(&set->str[STRING_SSL_CAPATH_PROXY], CURL_CA_PATH);
  if(result)
    return result;


  set->wildcardmatch  = FALSE;
  set->chunk_bgn      = ZERO_NULL;
  set->chunk_end      = ZERO_NULL;

  
  set->tcp_keepalive = FALSE;
  set->tcp_keepintvl = 60;
  set->tcp_keepidle = 60;
  set->tcp_fastopen = FALSE;
  set->tcp_nodelay = TRUE;

  set->ssl_enable_npn = TRUE;
  set->ssl_enable_alpn = TRUE;

  set->expect_100_timeout = 1000L; 
  set->sep_headers = TRUE; 

  Curl_http2_init_userset(set);
  return result;
}



CURLcode Curl_open(struct Curl_easy **curl)
{
  CURLcode result;
  struct Curl_easy *data;

  
  data = calloc(1, sizeof(struct Curl_easy));
  if(!data) {
    
    DEBUGF(fprintf(stderr, "Error: calloc of Curl_easy failed\n"));
    return CURLE_OUT_OF_MEMORY;
  }

  data->magic = CURLEASY_MAGIC_NUMBER;

  result = Curl_resolver_init(&data->state.resolver);
  if(result) {
    DEBUGF(fprintf(stderr, "Error: resolver_init failed\n"));
    free(data);
    return result;
  }

  

  data->state.buffer = malloc(BUFSIZE + 1);
  if(!data->state.buffer) {
    DEBUGF(fprintf(stderr, "Error: malloc of buffer failed\n"));
    result = CURLE_OUT_OF_MEMORY;
  }

  data->state.headerbuff = malloc(HEADERSIZE);
  if(!data->state.headerbuff) {
    DEBUGF(fprintf(stderr, "Error: malloc of headerbuff failed\n"));
    result = CURLE_OUT_OF_MEMORY;
  }
  else {
    result = Curl_init_userdefined(&data->set);

    data->state.headersize=HEADERSIZE;

    Curl_convert_init(data);

    Curl_initinfo(data);

    
    data->state.lastconnect = NULL;

    data->progress.flags |= PGRS_HIDE;
    data->state.current_speed = -1; 
    data->set.fnmatch = ZERO_NULL;
    data->set.maxconnects = DEFAULT_CONNCACHE_SIZE; 

    Curl_http2_init_state(&data->state);
  }

  if(result) {
    Curl_resolver_cleanup(data->state.resolver);
    free(data->state.buffer);
    free(data->state.headerbuff);
    Curl_freeset(data);
    free(data);
    data = NULL;
  }
  else *curl = data;

  return result;
}




CURLcode Curl_setopt(struct Curl_easy *data, CURLoption option, va_list param)
{
  char *argptr;
  CURLcode result = CURLE_OK;
  long arg;

  curl_off_t bigsize;


  switch(option) {
  case CURLOPT_DNS_CACHE_TIMEOUT:
    data->set.dns_cache_timeout = va_arg(param, long);
    break;
  case CURLOPT_DNS_USE_GLOBAL_CACHE:
    
    arg = va_arg(param, long);
    data->set.global_dns_cache = (0 != arg) ? TRUE : FALSE;
    break;
  case CURLOPT_SSL_CIPHER_LIST:
    
    result = setstropt(&data->set.str[STRING_SSL_CIPHER_LIST_ORIG], va_arg(param, char *));
    break;
  case CURLOPT_PROXY_SSL_CIPHER_LIST:
    
    result = setstropt(&data->set.str[STRING_SSL_CIPHER_LIST_PROXY], va_arg(param, char *));
    break;

  case CURLOPT_RANDOM_FILE:
    
    result = setstropt(&data->set.str[STRING_SSL_RANDOM_FILE], va_arg(param, char *));
    break;
  case CURLOPT_EGDSOCKET:
    
    result = setstropt(&data->set.str[STRING_SSL_EGDSOCKET], va_arg(param, char *));
    break;
  case CURLOPT_MAXCONNECTS:
    
    data->set.maxconnects = va_arg(param, long);
    break;
  case CURLOPT_FORBID_REUSE:
    
    data->set.reuse_forbid = (0 != va_arg(param, long)) ? TRUE : FALSE;
    break;
  case CURLOPT_FRESH_CONNECT:
    
    data->set.reuse_fresh = (0 != va_arg(param, long)) ? TRUE : FALSE;
    break;
  case CURLOPT_VERBOSE:
    
    data->set.verbose = (0 != va_arg(param, long)) ? TRUE : FALSE;
    break;
  case CURLOPT_HEADER:
    
    data->set.include_header = (0 != va_arg(param, long)) ? TRUE : FALSE;
    break;
  case CURLOPT_NOPROGRESS:
    
    data->set.hide_progress = (0 != va_arg(param, long)) ? TRUE : FALSE;
    if(data->set.hide_progress)
      data->progress.flags |= PGRS_HIDE;
    else data->progress.flags &= ~PGRS_HIDE;
    break;
  case CURLOPT_NOBODY:
    
    data->set.opt_no_body = (0 != va_arg(param, long)) ? TRUE : FALSE;
    break;
  case CURLOPT_FAILONERROR:
    
    data->set.http_fail_on_error = (0 != va_arg(param, long)) ? TRUE : FALSE;
    break;
  case CURLOPT_KEEP_SENDING_ON_ERROR:
    data->set.http_keep_sending_on_error = (0 != va_arg(param, long)) ? TRUE : FALSE;
    break;
  case CURLOPT_UPLOAD:
  case CURLOPT_PUT:
    
    data->set.upload = (0 != va_arg(param, long)) ? TRUE : FALSE;
    if(data->set.upload) {
      
      data->set.httpreq = HTTPREQ_PUT;
      data->set.opt_no_body = FALSE; 
    }
    else  data->set.httpreq = HTTPREQ_GET;

    break;
  case CURLOPT_FILETIME:
    
    data->set.get_filetime = (0 != va_arg(param, long)) ? TRUE : FALSE;
    break;
  case CURLOPT_FTP_CREATE_MISSING_DIRS:
    
    switch(va_arg(param, long)) {
    case 0:
      data->set.ftp_create_missing_dirs = 0;
      break;
    case 1:
      data->set.ftp_create_missing_dirs = 1;
      break;
    case 2:
      data->set.ftp_create_missing_dirs = 2;
      break;
    default:
      
      result = CURLE_UNKNOWN_OPTION;
      break;
    }
    break;
  case CURLOPT_SERVER_RESPONSE_TIMEOUT:
    
    data->set.server_response_timeout = va_arg(param, long) * 1000;
    break;
  case CURLOPT_TFTP_NO_OPTIONS:
    
    data->set.tftp_no_options = va_arg(param, long) != 0;
    break;
  case CURLOPT_TFTP_BLKSIZE:
    
    data->set.tftp_blksize = va_arg(param, long);
    break;
  case CURLOPT_DIRLISTONLY:
    
    data->set.ftp_list_only = (0 != va_arg(param, long)) ? TRUE : FALSE;
    break;
  case CURLOPT_APPEND:
    
    data->set.ftp_append = (0 != va_arg(param, long)) ? TRUE : FALSE;
    break;
  case CURLOPT_FTP_FILEMETHOD:
    
    data->set.ftp_filemethod = (curl_ftpfile)va_arg(param, long);
    break;
  case CURLOPT_NETRC:
    
    data->set.use_netrc = (enum CURL_NETRC_OPTION)va_arg(param, long);
    break;
  case CURLOPT_NETRC_FILE:
    
    result = setstropt(&data->set.str[STRING_NETRC_FILE], va_arg(param, char *));
    break;
  case CURLOPT_TRANSFERTEXT:
    
    data->set.prefer_ascii = (0 != va_arg(param, long)) ? TRUE : FALSE;
    break;
  case CURLOPT_TIMECONDITION:
    
    data->set.timecondition = (curl_TimeCond)va_arg(param, long);
    break;
  case CURLOPT_TIMEVALUE:
    
    data->set.timevalue = (time_t)va_arg(param, long);
    break;
  case CURLOPT_SSLVERSION:
    

    arg = va_arg(param, long);
    data->set.ssl.primary.version = C_SSLVERSION_VALUE(arg);
    data->set.ssl.primary.version_max = C_SSLVERSION_MAX_VALUE(arg);

    result = CURLE_UNKNOWN_OPTION;

    break;
  case CURLOPT_PROXY_SSLVERSION:
    

    arg = va_arg(param, long);
    data->set.proxy_ssl.primary.version = C_SSLVERSION_VALUE(arg);
    data->set.proxy_ssl.primary.version_max = C_SSLVERSION_MAX_VALUE(arg);

    result = CURLE_UNKNOWN_OPTION;

    break;


  case CURLOPT_AUTOREFERER:
    
    data->set.http_auto_referer = (0 != va_arg(param, long)) ? TRUE : FALSE;
    break;

  case CURLOPT_ACCEPT_ENCODING:
    
    argptr = va_arg(param, char *);
    result = setstropt(&data->set.str[STRING_ENCODING], (argptr && !*argptr)? ALL_CONTENT_ENCODINGS: argptr);

    break;

  case CURLOPT_TRANSFER_ENCODING:
    data->set.http_transfer_encoding = (0 != va_arg(param, long)) ? TRUE : FALSE;
    break;

  case CURLOPT_FOLLOWLOCATION:
    
    data->set.http_follow_location = (0 != va_arg(param, long)) ? TRUE : FALSE;
    break;

  case CURLOPT_UNRESTRICTED_AUTH:
    
    data->set.http_disable_hostname_check_before_authentication = (0 != va_arg(param, long)) ? TRUE : FALSE;
    break;

  case CURLOPT_MAXREDIRS:
    
    data->set.maxredirs = va_arg(param, long);
    break;

  case CURLOPT_POSTREDIR:
  {
    
    int postRedir = curlx_sltosi(va_arg(param, long));
    data->set.keep_post = postRedir & CURL_REDIR_POST_ALL;
  }
  break;

  case CURLOPT_POST:
    
    if(va_arg(param, long)) {
      data->set.httpreq = HTTPREQ_POST;
      data->set.opt_no_body = FALSE; 
    }
    else data->set.httpreq = HTTPREQ_GET;
    break;

  case CURLOPT_COPYPOSTFIELDS:
    
    argptr = va_arg(param, char *);

    if(!argptr || data->set.postfieldsize == -1)
      result = setstropt(&data->set.str[STRING_COPYPOSTFIELDS], argptr);
    else {
      

      if((data->set.postfieldsize < 0) || ((sizeof(curl_off_t) != sizeof(size_t)) && (data->set.postfieldsize > (curl_off_t)((size_t)-1))))

        result = CURLE_OUT_OF_MEMORY;
      else {
        char *p;

        (void) setstropt(&data->set.str[STRING_COPYPOSTFIELDS], NULL);

        
        p = malloc((size_t)(data->set.postfieldsize? data->set.postfieldsize:1));

        if(!p)
          result = CURLE_OUT_OF_MEMORY;
        else {
          if(data->set.postfieldsize)
            memcpy(p, argptr, (size_t)data->set.postfieldsize);

          data->set.str[STRING_COPYPOSTFIELDS] = p;
        }
      }
    }

    data->set.postfields = data->set.str[STRING_COPYPOSTFIELDS];
    data->set.httpreq = HTTPREQ_POST;
    break;

  case CURLOPT_POSTFIELDS:
    
    data->set.postfields = va_arg(param, void *);
    
    (void) setstropt(&data->set.str[STRING_COPYPOSTFIELDS], NULL);
    data->set.httpreq = HTTPREQ_POST;
    break;

  case CURLOPT_POSTFIELDSIZE:
    
    bigsize = va_arg(param, long);

    if(data->set.postfieldsize < bigsize && data->set.postfields == data->set.str[STRING_COPYPOSTFIELDS]) {
      
      (void) setstropt(&data->set.str[STRING_COPYPOSTFIELDS], NULL);
      data->set.postfields = NULL;
    }

    data->set.postfieldsize = bigsize;
    break;

  case CURLOPT_POSTFIELDSIZE_LARGE:
    
    bigsize = va_arg(param, curl_off_t);

    if(data->set.postfieldsize < bigsize && data->set.postfields == data->set.str[STRING_COPYPOSTFIELDS]) {
      
      (void) setstropt(&data->set.str[STRING_COPYPOSTFIELDS], NULL);
      data->set.postfields = NULL;
    }

    data->set.postfieldsize = bigsize;
    break;

  case CURLOPT_HTTPPOST:
    
    data->set.httppost = va_arg(param, struct curl_httppost *);
    data->set.httpreq = HTTPREQ_POST_FORM;
    data->set.opt_no_body = FALSE; 
    break;

  case CURLOPT_REFERER:
    
    if(data->change.referer_alloc) {
      Curl_safefree(data->change.referer);
      data->change.referer_alloc = FALSE;
    }
    result = setstropt(&data->set.str[STRING_SET_REFERER], va_arg(param, char *));
    data->change.referer = data->set.str[STRING_SET_REFERER];
    break;

  case CURLOPT_USERAGENT:
    
    result = setstropt(&data->set.str[STRING_USERAGENT], va_arg(param, char *));
    break;

  case CURLOPT_HTTPHEADER:
    
    data->set.headers = va_arg(param, struct curl_slist *);
    break;

  case CURLOPT_PROXYHEADER:
    
    data->set.proxyheaders = va_arg(param, struct curl_slist *);
    break;

  case CURLOPT_HEADEROPT:
    
    arg = va_arg(param, long);
    data->set.sep_headers = (arg & CURLHEADER_SEPARATE)? TRUE: FALSE;
    break;

  case CURLOPT_HTTP200ALIASES:
    
    data->set.http200aliases = va_arg(param, struct curl_slist *);
    break;


  case CURLOPT_COOKIE:
    
    result = setstropt(&data->set.str[STRING_COOKIE], va_arg(param, char *));
    break;

  case CURLOPT_COOKIEFILE:
    
    argptr = (char *)va_arg(param, void *);
    if(argptr) {
      struct curl_slist *cl;
      
      cl = curl_slist_append(data->change.cookielist, argptr);
      if(!cl) {
        curl_slist_free_all(data->change.cookielist);
        data->change.cookielist = NULL;
        return CURLE_OUT_OF_MEMORY;
      }
      data->change.cookielist = cl; 
    }
    break;

  case CURLOPT_COOKIEJAR:
    
  {
    struct CookieInfo *newcookies;
    result = setstropt(&data->set.str[STRING_COOKIEJAR], va_arg(param, char *));

    
    newcookies = Curl_cookie_init(data, NULL, data->cookies, data->set.cookiesession);
    if(!newcookies)
      result = CURLE_OUT_OF_MEMORY;
    data->cookies = newcookies;
  }
    break;

  case CURLOPT_COOKIESESSION:
    
    data->set.cookiesession = (0 != va_arg(param, long)) ? TRUE : FALSE;
    break;

  case CURLOPT_COOKIELIST:
    argptr = va_arg(param, char *);

    if(argptr == NULL)
      break;

    if(strcasecompare(argptr, "ALL")) {
      
      Curl_share_lock(data, CURL_LOCK_DATA_COOKIE, CURL_LOCK_ACCESS_SINGLE);
      Curl_cookie_clearall(data->cookies);
      Curl_share_unlock(data, CURL_LOCK_DATA_COOKIE);
    }
    else if(strcasecompare(argptr, "SESS")) {
      
      Curl_share_lock(data, CURL_LOCK_DATA_COOKIE, CURL_LOCK_ACCESS_SINGLE);
      Curl_cookie_clearsess(data->cookies);
      Curl_share_unlock(data, CURL_LOCK_DATA_COOKIE);
    }
    else if(strcasecompare(argptr, "FLUSH")) {
      
      Curl_flush_cookies(data, 0);
    }
    else if(strcasecompare(argptr, "RELOAD")) {
      
      Curl_cookie_loadfiles(data);
      break;
    }
    else {
      if(!data->cookies)
        
        data->cookies = Curl_cookie_init(data, NULL, NULL, TRUE);

      argptr = strdup(argptr);
      if(!argptr || !data->cookies) {
        result = CURLE_OUT_OF_MEMORY;
        free(argptr);
      }
      else {
        Curl_share_lock(data, CURL_LOCK_DATA_COOKIE, CURL_LOCK_ACCESS_SINGLE);

        if(checkprefix("Set-Cookie:", argptr))
          
          Curl_cookie_add(data, data->cookies, TRUE, argptr + 11, NULL, NULL);

        else  Curl_cookie_add(data, data->cookies, FALSE, argptr, NULL, NULL);


        Curl_share_unlock(data, CURL_LOCK_DATA_COOKIE);
        free(argptr);
      }
    }

    break;


  case CURLOPT_HTTPGET:
    
    if(va_arg(param, long)) {
      data->set.httpreq = HTTPREQ_GET;
      data->set.upload = FALSE; 
      data->set.opt_no_body = FALSE; 
    }
    break;

  case CURLOPT_HTTP_VERSION:
    
    arg = va_arg(param, long);

    if(arg >= CURL_HTTP_VERSION_2)
      return CURLE_UNSUPPORTED_PROTOCOL;

    data->set.httpversion = arg;
    break;

  case CURLOPT_HTTPAUTH:
    
  {
    int bitcheck;
    bool authbits;
    unsigned long auth = va_arg(param, unsigned long);

    if(auth == CURLAUTH_NONE) {
      data->set.httpauth = auth;
      break;
    }

    
    data->state.authhost.iestyle = (auth & CURLAUTH_DIGEST_IE) ? TRUE : FALSE;

    if(auth & CURLAUTH_DIGEST_IE) {
      auth |= CURLAUTH_DIGEST; 
      auth &= ~CURLAUTH_DIGEST_IE; 
    }

    

    auth &= ~CURLAUTH_NTLM;    
    auth &= ~CURLAUTH_NTLM_WB; 

    auth &= ~CURLAUTH_NTLM_WB; 


    auth &= ~CURLAUTH_NEGOTIATE; 


    
    bitcheck = 0;
    authbits = FALSE;
    while(bitcheck < 31) {
      if(auth & (1UL << bitcheck++)) {
        authbits = TRUE;
        break;
      }
    }
    if(!authbits)
      return CURLE_NOT_BUILT_IN; 

    data->set.httpauth = auth;
  }
  break;

  case CURLOPT_EXPECT_100_TIMEOUT_MS:
    
    data->set.expect_100_timeout = va_arg(param, long);
    break;



  case CURLOPT_CUSTOMREQUEST:
    
    result = setstropt(&data->set.str[STRING_CUSTOMREQUEST], va_arg(param, char *));

    
    break;


  case CURLOPT_HTTPPROXYTUNNEL:
    
    data->set.tunnel_thru_httpproxy = (0 != va_arg(param, long)) ? TRUE : FALSE;
    break;

  case CURLOPT_PROXYPORT:
    
    data->set.proxyport = va_arg(param, long);
    break;

  case CURLOPT_PROXYAUTH:
    
  {
    int bitcheck;
    bool authbits;
    unsigned long auth = va_arg(param, unsigned long);

    if(auth == CURLAUTH_NONE) {
      data->set.proxyauth = auth;
      break;
    }

    
    data->state.authproxy.iestyle = (auth & CURLAUTH_DIGEST_IE) ? TRUE : FALSE;

    if(auth & CURLAUTH_DIGEST_IE) {
      auth |= CURLAUTH_DIGEST; 
      auth &= ~CURLAUTH_DIGEST_IE; 
    }
    

    auth &= ~CURLAUTH_NTLM;    
    auth &= ~CURLAUTH_NTLM_WB; 

    auth &= ~CURLAUTH_NTLM_WB; 


    auth &= ~CURLAUTH_NEGOTIATE; 


    
    bitcheck = 0;
    authbits = FALSE;
    while(bitcheck < 31) {
      if(auth & (1UL << bitcheck++)) {
        authbits = TRUE;
        break;
      }
    }
    if(!authbits)
      return CURLE_NOT_BUILT_IN; 

    data->set.proxyauth = auth;
  }
  break;

  case CURLOPT_PROXY:
    
    result = setstropt(&data->set.str[STRING_PROXY], va_arg(param, char *));
    break;

  case CURLOPT_PRE_PROXY:
    
    result = setstropt(&data->set.str[STRING_PRE_PROXY], va_arg(param, char *));
    break;

  case CURLOPT_PROXYTYPE:
    
    data->set.proxytype = (curl_proxytype)va_arg(param, long);
    break;

  case CURLOPT_PROXY_TRANSFER_MODE:
    
    switch(va_arg(param, long)) {
    case 0:
      data->set.proxy_transfer_mode = FALSE;
      break;
    case 1:
      data->set.proxy_transfer_mode = TRUE;
      break;
    default:
      
      result = CURLE_UNKNOWN_OPTION;
      break;
    }
    break;



  case CURLOPT_SOCKS5_GSSAPI_NEC:
    
    data->set.socks5_gssapi_nec = (0 != va_arg(param, long)) ? TRUE : FALSE;
    break;

  case CURLOPT_SOCKS5_GSSAPI_SERVICE:
  case CURLOPT_PROXY_SERVICE_NAME:
    
    result = setstropt(&data->set.str[STRING_PROXY_SERVICE_NAME], va_arg(param, char *));
    break;



  case CURLOPT_SERVICE_NAME:
    
    result = setstropt(&data->set.str[STRING_SERVICE_NAME], va_arg(param, char *));
    break;



  case CURLOPT_HEADERDATA:
    
    data->set.writeheader = (void *)va_arg(param, void *);
    break;
  case CURLOPT_ERRORBUFFER:
    
    data->set.errorbuffer = va_arg(param, char *);
    break;
  case CURLOPT_WRITEDATA:
    
    data->set.out = va_arg(param, void *);
    break;
  case CURLOPT_FTPPORT:
    
    result = setstropt(&data->set.str[STRING_FTPPORT], va_arg(param, char *));
    data->set.ftp_use_port = (data->set.str[STRING_FTPPORT]) ? TRUE : FALSE;
    break;

  case CURLOPT_FTP_USE_EPRT:
    data->set.ftp_use_eprt = (0 != va_arg(param, long)) ? TRUE : FALSE;
    break;

  case CURLOPT_FTP_USE_EPSV:
    data->set.ftp_use_epsv = (0 != va_arg(param, long)) ? TRUE : FALSE;
    break;

  case CURLOPT_FTP_USE_PRET:
    data->set.ftp_use_pret = (0 != va_arg(param, long)) ? TRUE : FALSE;
    break;

  case CURLOPT_FTP_SSL_CCC:
    data->set.ftp_ccc = (curl_ftpccc)va_arg(param, long);
    break;

  case CURLOPT_FTP_SKIP_PASV_IP:
    
    data->set.ftp_skip_ip = (0 != va_arg(param, long)) ? TRUE : FALSE;
    break;

  case CURLOPT_READDATA:
    
    data->set.in_set = va_arg(param, void *);
    break;
  case CURLOPT_INFILESIZE:
    
    data->set.filesize = va_arg(param, long);
    break;
  case CURLOPT_INFILESIZE_LARGE:
    
    data->set.filesize = va_arg(param, curl_off_t);
    break;
  case CURLOPT_LOW_SPEED_LIMIT:
    
    data->set.low_speed_limit=va_arg(param, long);
    break;
  case CURLOPT_MAX_SEND_SPEED_LARGE:
    
    data->set.max_send_speed=va_arg(param, curl_off_t);
    break;
  case CURLOPT_MAX_RECV_SPEED_LARGE:
    
    data->set.max_recv_speed=va_arg(param, curl_off_t);
    break;
  case CURLOPT_LOW_SPEED_TIME:
    
    data->set.low_speed_time=va_arg(param, long);
    break;
  case CURLOPT_URL:
    
    if(data->change.url_alloc) {
      
      Curl_safefree(data->change.url);
      data->change.url_alloc = FALSE;
    }
    result = setstropt(&data->set.str[STRING_SET_URL], va_arg(param, char *));
    data->change.url = data->set.str[STRING_SET_URL];
    break;
  case CURLOPT_PORT:
    
    data->set.use_port = va_arg(param, long);
    break;
  case CURLOPT_TIMEOUT:
    
    data->set.timeout = va_arg(param, long) * 1000L;
    break;

  case CURLOPT_TIMEOUT_MS:
    data->set.timeout = va_arg(param, long);
    break;

  case CURLOPT_CONNECTTIMEOUT:
    
    data->set.connecttimeout = va_arg(param, long) * 1000L;
    break;

  case CURLOPT_CONNECTTIMEOUT_MS:
    data->set.connecttimeout = va_arg(param, long);
    break;

  case CURLOPT_ACCEPTTIMEOUT_MS:
    
    data->set.accepttimeout = va_arg(param, long);
    break;

  case CURLOPT_USERPWD:
    
    result = setstropt_userpwd(va_arg(param, char *), &data->set.str[STRING_USERNAME], &data->set.str[STRING_PASSWORD]);

    break;

  case CURLOPT_USERNAME:
    
    result = setstropt(&data->set.str[STRING_USERNAME], va_arg(param, char *));
    break;

  case CURLOPT_PASSWORD:
    
    result = setstropt(&data->set.str[STRING_PASSWORD], va_arg(param, char *));
    break;

  case CURLOPT_LOGIN_OPTIONS:
    
    result = setstropt(&data->set.str[STRING_OPTIONS], va_arg(param, char *));
    break;

  case CURLOPT_XOAUTH2_BEARER:
    
    result = setstropt(&data->set.str[STRING_BEARER], va_arg(param, char *));
    break;

  case CURLOPT_POSTQUOTE:
    
    data->set.postquote = va_arg(param, struct curl_slist *);
    break;
  case CURLOPT_PREQUOTE:
    
    data->set.prequote = va_arg(param, struct curl_slist *);
    break;
  case CURLOPT_QUOTE:
    
    data->set.quote = va_arg(param, struct curl_slist *);
    break;
  case CURLOPT_RESOLVE:
    
    data->set.resolve = va_arg(param, struct curl_slist *);
    data->change.resolve = data->set.resolve;
    break;
  case CURLOPT_PROGRESSFUNCTION:
    
    data->set.fprogress = va_arg(param, curl_progress_callback);
    if(data->set.fprogress)
      data->progress.callback = TRUE; 
    else data->progress.callback = FALSE;
    break;

  case CURLOPT_XFERINFOFUNCTION:
    
    data->set.fxferinfo = va_arg(param, curl_xferinfo_callback);
    if(data->set.fxferinfo)
      data->progress.callback = TRUE; 
    else data->progress.callback = FALSE;

    break;

  case CURLOPT_PROGRESSDATA:
    
    data->set.progress_client = va_arg(param, void *);
    break;


  case CURLOPT_PROXYUSERPWD:
    
    result = setstropt_userpwd(va_arg(param, char *), &data->set.str[STRING_PROXYUSERNAME], &data->set.str[STRING_PROXYPASSWORD]);

    break;
  case CURLOPT_PROXYUSERNAME:
    
    result = setstropt(&data->set.str[STRING_PROXYUSERNAME], va_arg(param, char *));
    break;
  case CURLOPT_PROXYPASSWORD:
    
    result = setstropt(&data->set.str[STRING_PROXYPASSWORD], va_arg(param, char *));
    break;
  case CURLOPT_NOPROXY:
    
    result = setstropt(&data->set.str[STRING_NOPROXY], va_arg(param, char *));
    break;


  case CURLOPT_RANGE:
    
    result = setstropt(&data->set.str[STRING_SET_RANGE], va_arg(param, char *));
    break;
  case CURLOPT_RESUME_FROM:
    
    data->set.set_resume_from = va_arg(param, long);
    break;
  case CURLOPT_RESUME_FROM_LARGE:
    
    data->set.set_resume_from = va_arg(param, curl_off_t);
    break;
  case CURLOPT_DEBUGFUNCTION:
    
    data->set.fdebug = va_arg(param, curl_debug_callback);
    
    break;
  case CURLOPT_DEBUGDATA:
    
    data->set.debugdata = va_arg(param, void *);
    break;
  case CURLOPT_STDERR:
    
    data->set.err = va_arg(param, FILE *);
    if(!data->set.err)
      data->set.err = stderr;
    break;
  case CURLOPT_HEADERFUNCTION:
    
    data->set.fwrite_header = va_arg(param, curl_write_callback);
    break;
  case CURLOPT_WRITEFUNCTION:
    
    data->set.fwrite_func = va_arg(param, curl_write_callback);
    if(!data->set.fwrite_func) {
      data->set.is_fwrite_set = 0;
      
      data->set.fwrite_func = (curl_write_callback)fwrite;
    }
    else data->set.is_fwrite_set = 1;
    break;
  case CURLOPT_READFUNCTION:
    
    data->set.fread_func_set = va_arg(param, curl_read_callback);
    if(!data->set.fread_func_set) {
      data->set.is_fread_set = 0;
      
      data->set.fread_func_set = (curl_read_callback)fread;
    }
    else data->set.is_fread_set = 1;
    break;
  case CURLOPT_SEEKFUNCTION:
    
    data->set.seek_func = va_arg(param, curl_seek_callback);
    break;
  case CURLOPT_SEEKDATA:
    
    data->set.seek_client = va_arg(param, void *);
    break;
  case CURLOPT_CONV_FROM_NETWORK_FUNCTION:
    
    data->set.convfromnetwork = va_arg(param, curl_conv_callback);
    break;
  case CURLOPT_CONV_TO_NETWORK_FUNCTION:
    
    data->set.convtonetwork = va_arg(param, curl_conv_callback);
    break;
  case CURLOPT_CONV_FROM_UTF8_FUNCTION:
    
    data->set.convfromutf8 = va_arg(param, curl_conv_callback);
    break;
  case CURLOPT_IOCTLFUNCTION:
    
    data->set.ioctl_func = va_arg(param, curl_ioctl_callback);
    break;
  case CURLOPT_IOCTLDATA:
    
    data->set.ioctl_client = va_arg(param, void *);
    break;
  case CURLOPT_SSLCERT:
    
    result = setstropt(&data->set.str[STRING_CERT_ORIG], va_arg(param, char *));
    break;
  case CURLOPT_PROXY_SSLCERT:
    
    result = setstropt(&data->set.str[STRING_CERT_PROXY], va_arg(param, char *));
    break;
  case CURLOPT_SSLCERTTYPE:
    
    result = setstropt(&data->set.str[STRING_CERT_TYPE_ORIG], va_arg(param, char *));
    break;
  case CURLOPT_PROXY_SSLCERTTYPE:
    
    result = setstropt(&data->set.str[STRING_CERT_TYPE_PROXY], va_arg(param, char *));
    break;
  case CURLOPT_SSLKEY:
    
    result = setstropt(&data->set.str[STRING_KEY_ORIG], va_arg(param, char *));
    break;
  case CURLOPT_PROXY_SSLKEY:
    
    result = setstropt(&data->set.str[STRING_KEY_PROXY], va_arg(param, char *));
    break;
  case CURLOPT_SSLKEYTYPE:
    
    result = setstropt(&data->set.str[STRING_KEY_TYPE_ORIG], va_arg(param, char *));
    break;
  case CURLOPT_PROXY_SSLKEYTYPE:
    
    result = setstropt(&data->set.str[STRING_KEY_TYPE_PROXY], va_arg(param, char *));
    break;
  case CURLOPT_KEYPASSWD:
    
    result = setstropt(&data->set.str[STRING_KEY_PASSWD_ORIG], va_arg(param, char *));
    break;
  case CURLOPT_PROXY_KEYPASSWD:
    
    result = setstropt(&data->set.str[STRING_KEY_PASSWD_PROXY], va_arg(param, char *));
    break;
  case CURLOPT_SSLENGINE:
    
    argptr = va_arg(param, char *);
    if(argptr && argptr[0])
      result = Curl_ssl_set_engine(data, argptr);
    break;

  case CURLOPT_SSLENGINE_DEFAULT:
    
    result = Curl_ssl_set_engine_default(data);
    break;
  case CURLOPT_CRLF:
    
    data->set.crlf = (0 != va_arg(param, long)) ? TRUE : FALSE;
    break;

  case CURLOPT_INTERFACE:
    
    result = setstropt(&data->set.str[STRING_DEVICE], va_arg(param, char *));
    break;
  case CURLOPT_LOCALPORT:
    
    data->set.localport = curlx_sltous(va_arg(param, long));
    break;
  case CURLOPT_LOCALPORTRANGE:
    
    data->set.localportrange = curlx_sltosi(va_arg(param, long));
    break;
  case CURLOPT_KRBLEVEL:
    
    result = setstropt(&data->set.str[STRING_KRB_LEVEL], va_arg(param, char *));
    data->set.krb = (data->set.str[STRING_KRB_LEVEL]) ? TRUE : FALSE;
    break;
  case CURLOPT_GSSAPI_DELEGATION:
    
    data->set.gssapi_delegation = va_arg(param, long);
    break;
  case CURLOPT_SSL_VERIFYPEER:
    
    data->set.ssl.primary.verifypeer = (0 != va_arg(param, long)) ? TRUE : FALSE;
    break;
  case CURLOPT_PROXY_SSL_VERIFYPEER:
    
    data->set.proxy_ssl.primary.verifypeer = (0 != va_arg(param, long))?TRUE:FALSE;
    break;
  case CURLOPT_SSL_VERIFYHOST:
    
    arg = va_arg(param, long);

    

    if(1 == arg) {
      failf(data, "CURLOPT_SSL_VERIFYHOST no longer supports 1 as value!");
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }

    data->set.ssl.primary.verifyhost = (0 != arg) ? TRUE : FALSE;
    break;
  case CURLOPT_PROXY_SSL_VERIFYHOST:
    
    arg = va_arg(param, long);

    

    if(1 == arg) {
      failf(data, "CURLOPT_SSL_VERIFYHOST no longer supports 1 as value!");
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }

    data->set.proxy_ssl.primary.verifyhost = (0 != arg)?TRUE:FALSE;
    break;
  case CURLOPT_SSL_VERIFYSTATUS:
    
    if(!Curl_ssl_cert_status_request()) {
      result = CURLE_NOT_BUILT_IN;
      break;
    }

    data->set.ssl.primary.verifystatus = (0 != va_arg(param, long)) ? TRUE : FALSE;
    break;
  case CURLOPT_SSL_CTX_FUNCTION:

    
    data->set.ssl.fsslctx = va_arg(param, curl_ssl_ctx_callback);

    result = CURLE_NOT_BUILT_IN;

    break;
  case CURLOPT_SSL_CTX_DATA:

    
    data->set.ssl.fsslctxp = va_arg(param, void *);

    result = CURLE_NOT_BUILT_IN;

    break;
  case CURLOPT_SSL_FALSESTART:
    
    if(!Curl_ssl_false_start()) {
      result = CURLE_NOT_BUILT_IN;
      break;
    }

    data->set.ssl.falsestart = (0 != va_arg(param, long)) ? TRUE : FALSE;
    break;
  case CURLOPT_CERTINFO:

    data->set.ssl.certinfo = (0 != va_arg(param, long)) ? TRUE : FALSE;

    result = CURLE_NOT_BUILT_IN;

    break;
  case CURLOPT_PINNEDPUBLICKEY:

    
    result = setstropt(&data->set.str[STRING_SSL_PINNEDPUBLICKEY_ORIG], va_arg(param, char *));

    result = CURLE_NOT_BUILT_IN;

    break;
  case CURLOPT_PROXY_PINNEDPUBLICKEY:

    
    result = setstropt(&data->set.str[STRING_SSL_PINNEDPUBLICKEY_PROXY], va_arg(param, char *));

    result = CURLE_NOT_BUILT_IN;

    break;
  case CURLOPT_CAINFO:
    
    result = setstropt(&data->set.str[STRING_SSL_CAFILE_ORIG], va_arg(param, char *));
    break;
  case CURLOPT_PROXY_CAINFO:
    
    result = setstropt(&data->set.str[STRING_SSL_CAFILE_PROXY], va_arg(param, char *));
    break;
  case CURLOPT_CAPATH:

    
    
    result = setstropt(&data->set.str[STRING_SSL_CAPATH_ORIG], va_arg(param, char *));

    result = CURLE_NOT_BUILT_IN;

    break;
  case CURLOPT_PROXY_CAPATH:

    
    
    result = setstropt(&data->set.str[STRING_SSL_CAPATH_PROXY], va_arg(param, char *));

    result = CURLE_NOT_BUILT_IN;

    break;
  case CURLOPT_CRLFILE:
    
    result = setstropt(&data->set.str[STRING_SSL_CRLFILE_ORIG], va_arg(param, char *));
    break;
  case CURLOPT_PROXY_CRLFILE:
    
    result = setstropt(&data->set.str[STRING_SSL_CRLFILE_PROXY], va_arg(param, char *));
    break;
  case CURLOPT_ISSUERCERT:
    
    result = setstropt(&data->set.str[STRING_SSL_ISSUERCERT_ORIG], va_arg(param, char *));
    break;
  case CURLOPT_TELNETOPTIONS:
    
    data->set.telnet_options = va_arg(param, struct curl_slist *);
    break;

  case CURLOPT_BUFFERSIZE:
    
    data->set.buffer_size = va_arg(param, long);

    if(data->set.buffer_size > MAX_BUFSIZE)
      data->set.buffer_size = MAX_BUFSIZE; 
    else if(data->set.buffer_size < 1)
      data->set.buffer_size = BUFSIZE;

    
    if(data->set.buffer_size > BUFSIZE) {
      data->state.buffer = realloc(data->state.buffer, data->set.buffer_size + 1);
      if(!data->state.buffer) {
        DEBUGF(fprintf(stderr, "Error: realloc of buffer failed\n"));
        result = CURLE_OUT_OF_MEMORY;
      }
    }

    break;

  case CURLOPT_NOSIGNAL:
    
    data->set.no_signal = (0 != va_arg(param, long)) ? TRUE : FALSE;
    break;

  case CURLOPT_SHARE:
  {
    struct Curl_share *set;
    set = va_arg(param, struct Curl_share *);

    
    if(data->share) {
      Curl_share_lock(data, CURL_LOCK_DATA_SHARE, CURL_LOCK_ACCESS_SINGLE);

      if(data->dns.hostcachetype == HCACHE_SHARED) {
        data->dns.hostcache = NULL;
        data->dns.hostcachetype = HCACHE_NONE;
      }


      if(data->share->cookies == data->cookies)
        data->cookies = NULL;


      if(data->share->sslsession == data->state.session)
        data->state.session = NULL;

      data->share->dirty--;

      Curl_share_unlock(data, CURL_LOCK_DATA_SHARE);
      data->share = NULL;
    }

    
    data->share = set;
    if(data->share) {

      Curl_share_lock(data, CURL_LOCK_DATA_SHARE, CURL_LOCK_ACCESS_SINGLE);

      data->share->dirty++;

      if(data->share->specifier & (1<< CURL_LOCK_DATA_DNS)) {
        
        data->dns.hostcache = &data->share->hostcache;
        data->dns.hostcachetype = HCACHE_SHARED;
      }

      if(data->share->cookies) {
        
        Curl_cookie_cleanup(data->cookies);
        
        data->cookies = data->share->cookies;
      }

      if(data->share->sslsession) {
        data->set.general_ssl.max_ssl_sessions = data->share->max_ssl_sessions;
        data->state.session = data->share->sslsession;
      }
      Curl_share_unlock(data, CURL_LOCK_DATA_SHARE);

    }
    
  }
  break;

  case CURLOPT_PRIVATE:
    
    data->set.private_data = va_arg(param, void *);
    break;

  case CURLOPT_MAXFILESIZE:
    
    data->set.max_filesize = va_arg(param, long);
    break;


  case CURLOPT_USE_SSL:
    
    data->set.use_ssl = (curl_usessl)va_arg(param, long);
    break;

  case CURLOPT_SSL_OPTIONS:
    arg = va_arg(param, long);
    data->set.ssl.enable_beast = arg&CURLSSLOPT_ALLOW_BEAST?TRUE:FALSE;
    data->set.ssl.no_revoke = !!(arg & CURLSSLOPT_NO_REVOKE);
    break;

  case CURLOPT_PROXY_SSL_OPTIONS:
    arg = va_arg(param, long);
    data->set.proxy_ssl.enable_beast = arg&CURLSSLOPT_ALLOW_BEAST?TRUE:FALSE;
    data->set.proxy_ssl.no_revoke = !!(arg & CURLSSLOPT_NO_REVOKE);
    break;


  case CURLOPT_FTPSSLAUTH:
    
    data->set.ftpsslauth = (curl_ftpauth)va_arg(param, long);
    break;

  case CURLOPT_IPRESOLVE:
    data->set.ipver = va_arg(param, long);
    break;

  case CURLOPT_MAXFILESIZE_LARGE:
    
    data->set.max_filesize = va_arg(param, curl_off_t);
    break;

  case CURLOPT_TCP_NODELAY:
    
    data->set.tcp_nodelay = (0 != va_arg(param, long)) ? TRUE : FALSE;
    break;

  case CURLOPT_FTP_ACCOUNT:
    result = setstropt(&data->set.str[STRING_FTP_ACCOUNT], va_arg(param, char *));
    break;

  case CURLOPT_IGNORE_CONTENT_LENGTH:
    data->set.ignorecl = (0 != va_arg(param, long)) ? TRUE : FALSE;
    break;

  case CURLOPT_CONNECT_ONLY:
    
    data->set.connect_only = (0 != va_arg(param, long)) ? TRUE : FALSE;
    break;

  case CURLOPT_FTP_ALTERNATIVE_TO_USER:
    result = setstropt(&data->set.str[STRING_FTP_ALTERNATIVE_TO_USER], va_arg(param, char *));
    break;

  case CURLOPT_SOCKOPTFUNCTION:
    
    data->set.fsockopt = va_arg(param, curl_sockopt_callback);
    break;

  case CURLOPT_SOCKOPTDATA:
    
    data->set.sockopt_client = va_arg(param, void *);
    break;

  case CURLOPT_OPENSOCKETFUNCTION:
    
    data->set.fopensocket = va_arg(param, curl_opensocket_callback);
    break;

  case CURLOPT_OPENSOCKETDATA:
    
    data->set.opensocket_client = va_arg(param, void *);
    break;

  case CURLOPT_CLOSESOCKETFUNCTION:
    
    data->set.fclosesocket = va_arg(param, curl_closesocket_callback);
    break;

  case CURLOPT_CLOSESOCKETDATA:
    
    data->set.closesocket_client = va_arg(param, void *);
    break;

  case CURLOPT_SSL_SESSIONID_CACHE:
    data->set.general_ssl.sessionid = (0 != va_arg(param, long)) ? TRUE : FALSE;
    break;


    
  case CURLOPT_SSH_AUTH_TYPES:
    data->set.ssh_auth_types = va_arg(param, long);
    break;

  case CURLOPT_SSH_PUBLIC_KEYFILE:
    
    result = setstropt(&data->set.str[STRING_SSH_PUBLIC_KEY], va_arg(param, char *));
    break;

  case CURLOPT_SSH_PRIVATE_KEYFILE:
    
    result = setstropt(&data->set.str[STRING_SSH_PRIVATE_KEY], va_arg(param, char *));
    break;
  case CURLOPT_SSH_HOST_PUBLIC_KEY_MD5:
    
    result = setstropt(&data->set.str[STRING_SSH_HOST_PUBLIC_KEY_MD5], va_arg(param, char *));
    break;

  case CURLOPT_SSH_KNOWNHOSTS:
    
    result = setstropt(&data->set.str[STRING_SSH_KNOWNHOSTS], va_arg(param, char *));
    break;

  case CURLOPT_SSH_KEYFUNCTION:
    
    data->set.ssh_keyfunc = va_arg(param, curl_sshkeycallback);
    break;

  case CURLOPT_SSH_KEYDATA:
    
    data->set.ssh_keyfunc_userp = va_arg(param, void *);
    break;




  case CURLOPT_HTTP_TRANSFER_DECODING:
    
    data->set.http_te_skip = (0 == va_arg(param, long)) ? TRUE : FALSE;
    break;

  case CURLOPT_HTTP_CONTENT_DECODING:
    
    data->set.http_ce_skip = (0 == va_arg(param, long)) ? TRUE : FALSE;
    break;

  case CURLOPT_NEW_FILE_PERMS:
    
    data->set.new_file_perms = va_arg(param, long);
    break;

  case CURLOPT_NEW_DIRECTORY_PERMS:
    
    data->set.new_directory_perms = va_arg(param, long);
    break;

  case CURLOPT_ADDRESS_SCOPE:
    
    data->set.scope_id = curlx_sltoui(va_arg(param, long));
    break;

  case CURLOPT_PROTOCOLS:
    
    data->set.allowed_protocols = va_arg(param, long);
    break;

  case CURLOPT_REDIR_PROTOCOLS:
    
    data->set.redir_protocols = va_arg(param, long);
    break;

  case CURLOPT_DEFAULT_PROTOCOL:
    
    result = setstropt(&data->set.str[STRING_DEFAULT_PROTOCOL], va_arg(param, char *));
    break;

  case CURLOPT_MAIL_FROM:
    
    result = setstropt(&data->set.str[STRING_MAIL_FROM], va_arg(param, char *));
    break;

  case CURLOPT_MAIL_AUTH:
    
    result = setstropt(&data->set.str[STRING_MAIL_AUTH], va_arg(param, char *));
    break;

  case CURLOPT_MAIL_RCPT:
    
    data->set.mail_rcpt = va_arg(param, struct curl_slist *);
    break;

  case CURLOPT_SASL_IR:
    
    data->set.sasl_ir = (0 != va_arg(param, long)) ? TRUE : FALSE;
    break;

  case CURLOPT_RTSP_REQUEST:
    {
      
      long curl_rtspreq = va_arg(param, long);
      Curl_RtspReq rtspreq = RTSPREQ_NONE;
      switch(curl_rtspreq) {
        case CURL_RTSPREQ_OPTIONS:
          rtspreq = RTSPREQ_OPTIONS;
          break;

        case CURL_RTSPREQ_DESCRIBE:
          rtspreq = RTSPREQ_DESCRIBE;
          break;

        case CURL_RTSPREQ_ANNOUNCE:
          rtspreq = RTSPREQ_ANNOUNCE;
          break;

        case CURL_RTSPREQ_SETUP:
          rtspreq = RTSPREQ_SETUP;
          break;

        case CURL_RTSPREQ_PLAY:
          rtspreq = RTSPREQ_PLAY;
          break;

        case CURL_RTSPREQ_PAUSE:
          rtspreq = RTSPREQ_PAUSE;
          break;

        case CURL_RTSPREQ_TEARDOWN:
          rtspreq = RTSPREQ_TEARDOWN;
          break;

        case CURL_RTSPREQ_GET_PARAMETER:
          rtspreq = RTSPREQ_GET_PARAMETER;
          break;

        case CURL_RTSPREQ_SET_PARAMETER:
          rtspreq = RTSPREQ_SET_PARAMETER;
          break;

        case CURL_RTSPREQ_RECORD:
          rtspreq = RTSPREQ_RECORD;
          break;

        case CURL_RTSPREQ_RECEIVE:
          rtspreq = RTSPREQ_RECEIVE;
          break;
        default:
          rtspreq = RTSPREQ_NONE;
      }

      data->set.rtspreq = rtspreq;
    break;
    }


  case CURLOPT_RTSP_SESSION_ID:
    
    result = setstropt(&data->set.str[STRING_RTSP_SESSION_ID], va_arg(param, char *));
    break;

  case CURLOPT_RTSP_STREAM_URI:
    
    result = setstropt(&data->set.str[STRING_RTSP_STREAM_URI], va_arg(param, char *));
    break;

  case CURLOPT_RTSP_TRANSPORT:
    
    result = setstropt(&data->set.str[STRING_RTSP_TRANSPORT], va_arg(param, char *));
    break;

  case CURLOPT_RTSP_CLIENT_CSEQ:
    
    data->state.rtsp_next_client_CSeq = va_arg(param, long);
    break;

  case CURLOPT_RTSP_SERVER_CSEQ:
    
    data->state.rtsp_next_client_CSeq = va_arg(param, long);
    break;

  case CURLOPT_INTERLEAVEDATA:
    data->set.rtp_out = va_arg(param, void *);
    break;
  case CURLOPT_INTERLEAVEFUNCTION:
    
    data->set.fwrite_rtp = va_arg(param, curl_write_callback);
    break;

  case CURLOPT_WILDCARDMATCH:
    data->set.wildcardmatch = (0 != va_arg(param, long)) ? TRUE : FALSE;
    break;
  case CURLOPT_CHUNK_BGN_FUNCTION:
    data->set.chunk_bgn = va_arg(param, curl_chunk_bgn_callback);
    break;
  case CURLOPT_CHUNK_END_FUNCTION:
    data->set.chunk_end = va_arg(param, curl_chunk_end_callback);
    break;
  case CURLOPT_FNMATCH_FUNCTION:
    data->set.fnmatch = va_arg(param, curl_fnmatch_callback);
    break;
  case CURLOPT_CHUNK_DATA:
    data->wildcard.customptr = va_arg(param, void *);
    break;
  case CURLOPT_FNMATCH_DATA:
    data->set.fnmatch_data = va_arg(param, void *);
    break;

  case CURLOPT_TLSAUTH_USERNAME:
    result = setstropt(&data->set.str[STRING_TLSAUTH_USERNAME_ORIG], va_arg(param, char *));
    if(data->set.str[STRING_TLSAUTH_USERNAME_ORIG] && !data->set.ssl.authtype)
      data->set.ssl.authtype = CURL_TLSAUTH_SRP; 
    break;
  case CURLOPT_PROXY_TLSAUTH_USERNAME:
    result = setstropt(&data->set.str[STRING_TLSAUTH_USERNAME_PROXY], va_arg(param, char *));
    if(data->set.str[STRING_TLSAUTH_USERNAME_PROXY] && !data->set.proxy_ssl.authtype)
      data->set.proxy_ssl.authtype = CURL_TLSAUTH_SRP; 
    break;
  case CURLOPT_TLSAUTH_PASSWORD:
    result = setstropt(&data->set.str[STRING_TLSAUTH_PASSWORD_ORIG], va_arg(param, char *));
    if(data->set.str[STRING_TLSAUTH_USERNAME_ORIG] && !data->set.ssl.authtype)
      data->set.ssl.authtype = CURL_TLSAUTH_SRP; 
    break;
  case CURLOPT_PROXY_TLSAUTH_PASSWORD:
    result = setstropt(&data->set.str[STRING_TLSAUTH_PASSWORD_PROXY], va_arg(param, char *));
    if(data->set.str[STRING_TLSAUTH_USERNAME_PROXY] && !data->set.proxy_ssl.authtype)
      data->set.proxy_ssl.authtype = CURL_TLSAUTH_SRP; 
    break;
  case CURLOPT_TLSAUTH_TYPE:
    if(strncasecompare((char *)va_arg(param, char *), "SRP", strlen("SRP")))
      data->set.ssl.authtype = CURL_TLSAUTH_SRP;
    else data->set.ssl.authtype = CURL_TLSAUTH_NONE;
    break;
  case CURLOPT_PROXY_TLSAUTH_TYPE:
    if(strncasecompare((char *)va_arg(param, char *), "SRP", strlen("SRP")))
      data->set.proxy_ssl.authtype = CURL_TLSAUTH_SRP;
    else data->set.proxy_ssl.authtype = CURL_TLSAUTH_NONE;
    break;

  case CURLOPT_DNS_SERVERS:
    result = Curl_set_dns_servers(data, va_arg(param, char *));
    break;
  case CURLOPT_DNS_INTERFACE:
    result = Curl_set_dns_interface(data, va_arg(param, char *));
    break;
  case CURLOPT_DNS_LOCAL_IP4:
    result = Curl_set_dns_local_ip4(data, va_arg(param, char *));
    break;
  case CURLOPT_DNS_LOCAL_IP6:
    result = Curl_set_dns_local_ip6(data, va_arg(param, char *));
    break;

  case CURLOPT_TCP_KEEPALIVE:
    data->set.tcp_keepalive = (0 != va_arg(param, long)) ? TRUE : FALSE;
    break;
  case CURLOPT_TCP_KEEPIDLE:
    data->set.tcp_keepidle = va_arg(param, long);
    break;
  case CURLOPT_TCP_KEEPINTVL:
    data->set.tcp_keepintvl = va_arg(param, long);
    break;
  case CURLOPT_TCP_FASTOPEN:

    data->set.tcp_fastopen = (0 != va_arg(param, long))?TRUE:FALSE;

    result = CURLE_NOT_BUILT_IN;

    break;
  case CURLOPT_SSL_ENABLE_NPN:
    data->set.ssl_enable_npn = (0 != va_arg(param, long)) ? TRUE : FALSE;
    break;
  case CURLOPT_SSL_ENABLE_ALPN:
    data->set.ssl_enable_alpn = (0 != va_arg(param, long)) ? TRUE : FALSE;
    break;


  case CURLOPT_UNIX_SOCKET_PATH:
    data->set.abstract_unix_socket = FALSE;
    result = setstropt(&data->set.str[STRING_UNIX_SOCKET_PATH], va_arg(param, char *));
    break;
  case CURLOPT_ABSTRACT_UNIX_SOCKET:
    data->set.abstract_unix_socket = TRUE;
    result = setstropt(&data->set.str[STRING_UNIX_SOCKET_PATH], va_arg(param, char *));
    break;


  case CURLOPT_PATH_AS_IS:
    data->set.path_as_is = (0 != va_arg(param, long)) ? TRUE : FALSE;
    break;
  case CURLOPT_PIPEWAIT:
    data->set.pipewait = (0 != va_arg(param, long)) ? TRUE : FALSE;
    break;
  case CURLOPT_STREAM_WEIGHT:

    return CURLE_NOT_BUILT_IN;

    arg = va_arg(param, long);
    if((arg>=1) && (arg <= 256))
      data->set.stream_weight = (int)arg;
    break;

  case CURLOPT_STREAM_DEPENDS:
  case CURLOPT_STREAM_DEPENDS_E:
  {

    return CURLE_NOT_BUILT_IN;

    struct Curl_easy *dep = va_arg(param, struct Curl_easy *);
    if(!dep || GOOD_EASY_HANDLE(dep)) {
      if(data->set.stream_depends_on) {
        Curl_http2_remove_child(data->set.stream_depends_on, data);
      }
      Curl_http2_add_child(dep, data, (option == CURLOPT_STREAM_DEPENDS_E));
    }
    break;

  }
  case CURLOPT_CONNECT_TO:
    data->set.connect_to = va_arg(param, struct curl_slist *);
    break;
  case CURLOPT_SUPPRESS_CONNECT_HEADERS:
    data->set.suppress_connect_headers = (0 != va_arg(param, long))?TRUE:FALSE;
    break;
  default:
    
    result = CURLE_UNKNOWN_OPTION;
    break;
  }

  return result;
}


static void conn_reset_postponed_data(struct connectdata *conn, int num)
{
  struct postponed_data * const psnd = &(conn->postponed[num]);
  if(psnd->buffer) {
    DEBUGASSERT(psnd->allocated_size > 0);
    DEBUGASSERT(psnd->recv_size <= psnd->allocated_size);
    DEBUGASSERT(psnd->recv_size ? (psnd->recv_processed < psnd->recv_size) :
                (psnd->recv_processed == 0));
    DEBUGASSERT(psnd->bindsock != CURL_SOCKET_BAD);
    free(psnd->buffer);
    psnd->buffer = NULL;
    psnd->allocated_size = 0;
    psnd->recv_size = 0;
    psnd->recv_processed = 0;

    psnd->bindsock = CURL_SOCKET_BAD; 

  }
  else {
    DEBUGASSERT(psnd->allocated_size == 0);
    DEBUGASSERT(psnd->recv_size == 0);
    DEBUGASSERT(psnd->recv_processed == 0);
    DEBUGASSERT(psnd->bindsock == CURL_SOCKET_BAD);
  }
}

static void conn_reset_all_postponed_data(struct connectdata *conn)
{
  conn_reset_postponed_data(conn, 0);
  conn_reset_postponed_data(conn, 1);
}






static void conn_free(struct connectdata *conn)
{
  if(!conn)
    return;

  
  Curl_resolver_cancel(conn);

  
  Curl_ssl_close(conn, FIRSTSOCKET);
  Curl_ssl_close(conn, SECONDARYSOCKET);

  
  if(CURL_SOCKET_BAD != conn->sock[SECONDARYSOCKET])
    Curl_closesocket(conn, conn->sock[SECONDARYSOCKET]);
  if(CURL_SOCKET_BAD != conn->sock[FIRSTSOCKET])
    Curl_closesocket(conn, conn->sock[FIRSTSOCKET]);
  if(CURL_SOCKET_BAD != conn->tempsock[0])
    Curl_closesocket(conn, conn->tempsock[0]);
  if(CURL_SOCKET_BAD != conn->tempsock[1])
    Curl_closesocket(conn, conn->tempsock[1]);


  Curl_ntlm_wb_cleanup(conn);


  Curl_safefree(conn->user);
  Curl_safefree(conn->passwd);
  Curl_safefree(conn->oauth_bearer);
  Curl_safefree(conn->options);
  Curl_safefree(conn->http_proxy.user);
  Curl_safefree(conn->socks_proxy.user);
  Curl_safefree(conn->http_proxy.passwd);
  Curl_safefree(conn->socks_proxy.passwd);
  Curl_safefree(conn->allocptr.proxyuserpwd);
  Curl_safefree(conn->allocptr.uagent);
  Curl_safefree(conn->allocptr.userpwd);
  Curl_safefree(conn->allocptr.accept_encoding);
  Curl_safefree(conn->allocptr.te);
  Curl_safefree(conn->allocptr.rangeline);
  Curl_safefree(conn->allocptr.ref);
  Curl_safefree(conn->allocptr.host);
  Curl_safefree(conn->allocptr.cookiehost);
  Curl_safefree(conn->allocptr.rtsp_transport);
  Curl_safefree(conn->trailer);
  Curl_safefree(conn->host.rawalloc); 
  Curl_safefree(conn->conn_to_host.rawalloc); 
  Curl_safefree(conn->secondaryhostname);
  Curl_safefree(conn->http_proxy.host.rawalloc); 
  Curl_safefree(conn->socks_proxy.host.rawalloc); 
  Curl_safefree(conn->master_buffer);

  conn_reset_all_postponed_data(conn);

  Curl_llist_destroy(&conn->send_pipe, NULL);
  Curl_llist_destroy(&conn->recv_pipe, NULL);

  Curl_safefree(conn->localdev);
  Curl_free_primary_ssl_config(&conn->ssl_config);
  Curl_free_primary_ssl_config(&conn->proxy_ssl_config);


  Curl_safefree(conn->unix_domain_socket);


  free(conn); 
}



CURLcode Curl_disconnect(struct connectdata *conn, bool dead_connection)
{
  struct Curl_easy *data;
  if(!conn)
    return CURLE_OK; 
  data = conn->data;

  if(!data) {
    DEBUGF(fprintf(stderr, "DISCONNECT without easy handle, ignoring\n"));
    return CURLE_OK;
  }

  
  if(!conn->bits.close && (conn->send_pipe.size + conn->recv_pipe.size)) {
    DEBUGF(infof(data, "Curl_disconnect, usecounter: %d\n", conn->send_pipe.size + conn->recv_pipe.size));
    return CURLE_OK;
  }

  if(conn->dns_entry != NULL) {
    Curl_resolv_unlock(data, conn->dns_entry);
    conn->dns_entry = NULL;
  }

  Curl_hostcache_prune(data); 


  
  Curl_http_ntlm_cleanup(conn);


  if(conn->handler->disconnect)
    
    conn->handler->disconnect(conn, dead_connection);

    
  infof(data, "Closing connection %ld\n", conn->connection_id);
  Curl_conncache_remove_conn(data->state.conn_cache, conn);

  free_fixed_hostname(&conn->host);
  free_fixed_hostname(&conn->conn_to_host);
  free_fixed_hostname(&conn->http_proxy.host);
  free_fixed_hostname(&conn->socks_proxy.host);

  Curl_ssl_close(conn, FIRSTSOCKET);

  
  if(Curl_pipeline_wanted(data->multi, CURLPIPE_ANY)) {
    signalPipeClose(&conn->send_pipe, TRUE);
    signalPipeClose(&conn->recv_pipe, TRUE);
  }

  conn_free(conn);

  return CURLE_OK;
}


static bool SocketIsDead(curl_socket_t sock)
{
  int sval;
  bool ret_val = TRUE;

  sval = SOCKET_READABLE(sock, 0);
  if(sval == 0)
    
    ret_val = FALSE;

  return ret_val;
}


static bool IsPipeliningPossible(const struct Curl_easy *handle, const struct connectdata *conn)
{
  
  if((conn->handler->protocol & PROTO_FAMILY_HTTP) && (!conn->bits.protoconnstart || !conn->bits.close)) {

    if(Curl_pipeline_wanted(handle->multi, CURLPIPE_HTTP1) && (handle->set.httpversion != CURL_HTTP_VERSION_1_0) && (handle->set.httpreq == HTTPREQ_GET || handle->set.httpreq == HTTPREQ_HEAD))


      
      return TRUE;

    if(Curl_pipeline_wanted(handle->multi, CURLPIPE_MULTIPLEX) && (handle->set.httpversion >= CURL_HTTP_VERSION_2))
      
      return TRUE;
  }
  return FALSE;
}

int Curl_removeHandleFromPipeline(struct Curl_easy *handle, struct curl_llist *pipeline)
{
  if(pipeline) {
    struct curl_llist_element *curr;

    curr = pipeline->head;
    while(curr) {
      if(curr->ptr == handle) {
        Curl_llist_remove(pipeline, curr, NULL);
        return 1; 
      }
      curr = curr->next;
    }
  }

  return 0;
}


static void Curl_printPipeline(struct curl_llist *pipeline)
{
  struct curl_llist_element *curr;

  curr = pipeline->head;
  while(curr) {
    struct Curl_easy *data = (struct Curl_easy *) curr->ptr;
    infof(data, "Handle in pipeline: %s\n", data->state.path);
    curr = curr->next;
  }
}


static struct Curl_easy* gethandleathead(struct curl_llist *pipeline)
{
  struct curl_llist_element *curr = pipeline->head;
  if(curr) {
    return (struct Curl_easy *) curr->ptr;
  }

  return NULL;
}


void Curl_getoff_all_pipelines(struct Curl_easy *data, struct connectdata *conn)
{
  bool recv_head = (conn->readchannel_inuse && Curl_recvpipe_head(data, conn));
  bool send_head = (conn->writechannel_inuse && Curl_sendpipe_head(data, conn));

  if(Curl_removeHandleFromPipeline(data, &conn->recv_pipe) && recv_head)
    Curl_pipeline_leave_read(conn);
  if(Curl_removeHandleFromPipeline(data, &conn->send_pipe) && send_head)
    Curl_pipeline_leave_write(conn);
}

static void signalPipeClose(struct curl_llist *pipeline, bool pipe_broke)
{
  struct curl_llist_element *curr;

  if(!pipeline)
    return;

  curr = pipeline->head;
  while(curr) {
    struct curl_llist_element *next = curr->next;
    struct Curl_easy *data = (struct Curl_easy *) curr->ptr;


    if(data->magic != CURLEASY_MAGIC_NUMBER) {
      
      infof(data, "signalPipeClose() found BAAD easy handle\n");
    }


    if(pipe_broke)
      data->state.pipe_broke = TRUE;
    Curl_multi_handlePipeBreak(data);
    Curl_llist_remove(pipeline, curr, NULL);
    curr = next;
  }
}


struct connectdata * Curl_oldest_idle_connection(struct Curl_easy *data)
{
  struct conncache *bc = data->state.conn_cache;
  struct curl_hash_iterator iter;
  struct curl_llist_element *curr;
  struct curl_hash_element *he;
  time_t highscore=-1;
  time_t score;
  struct timeval now;
  struct connectdata *conn_candidate = NULL;
  struct connectbundle *bundle;

  now = Curl_tvnow();

  Curl_hash_start_iterate(&bc->hash, &iter);

  he = Curl_hash_next_element(&iter);
  while(he) {
    struct connectdata *conn;

    bundle = he->ptr;

    curr = bundle->conn_list.head;
    while(curr) {
      conn = curr->ptr;

      if(!conn->inuse) {
        
        score = Curl_tvdiff(now, conn->now);

        if(score > highscore) {
          highscore = score;
          conn_candidate = conn;
        }
      }
      curr = curr->next;
    }

    he = Curl_hash_next_element(&iter);
  }

  return conn_candidate;
}

static bool proxy_info_matches(const struct proxy_info* data, const struct proxy_info* needle)

{
  if((data->proxytype == needle->proxytype) && (data->port == needle->port) && Curl_safe_strcasecompare(data->host.name, needle->host.name))

    return TRUE;

  return FALSE;
}



static struct connectdata * find_oldest_idle_connection_in_bundle(struct Curl_easy *data, struct connectbundle *bundle)

{
  struct curl_llist_element *curr;
  time_t highscore=-1;
  time_t score;
  struct timeval now;
  struct connectdata *conn_candidate = NULL;
  struct connectdata *conn;

  (void)data;

  now = Curl_tvnow();

  curr = bundle->conn_list.head;
  while(curr) {
    conn = curr->ptr;

    if(!conn->inuse) {
      
      score = Curl_tvdiff(now, conn->now);

      if(score > highscore) {
        highscore = score;
        conn_candidate = conn;
      }
    }
    curr = curr->next;
  }

  return conn_candidate;
}


static bool disconnect_if_dead(struct connectdata *conn, struct Curl_easy *data)
{
  size_t pipeLen = conn->send_pipe.size + conn->recv_pipe.size;
  if(!pipeLen && !conn->inuse) {
    
    bool dead;
    if(conn->handler->protocol & CURLPROTO_RTSP)
      
      dead = Curl_rtsp_connisdead(conn);
    else dead = SocketIsDead(conn->sock[FIRSTSOCKET]);

    if(dead) {
      conn->data = data;
      infof(data, "Connection %ld seems to be dead!\n", conn->connection_id);

      
      Curl_disconnect(conn, TRUE);
      return TRUE;
    }
  }
  return FALSE;
}


static int call_disconnect_if_dead(struct connectdata *conn, void *param)
{
  struct Curl_easy* data = (struct Curl_easy*)param;
  disconnect_if_dead(conn, data);
  return 0; 
}


static void prune_dead_connections(struct Curl_easy *data)
{
  struct timeval now = Curl_tvnow();
  time_t elapsed = Curl_tvdiff(now, data->state.conn_cache->last_cleanup);

  if(elapsed >= 1000L) {
    Curl_conncache_foreach(data->state.conn_cache, data, call_disconnect_if_dead);
    data->state.conn_cache->last_cleanup = now;
  }
}


static size_t max_pipeline_length(struct Curl_multi *multi)
{
  return multi ? multi->max_pipeline_length : 0;
}



static bool ConnectionExists(struct Curl_easy *data, struct connectdata *needle, struct connectdata **usethis, bool *force_reuse, bool *waitpipe)




{
  struct connectdata *check;
  struct connectdata *chosen = 0;
  bool foundPendingCandidate = FALSE;
  bool canPipeline = IsPipeliningPossible(data, needle);
  struct connectbundle *bundle;


  bool wantNTLMhttp = ((data->state.authhost.want & (CURLAUTH_NTLM | CURLAUTH_NTLM_WB)) && (needle->handler->protocol & PROTO_FAMILY_HTTP));

  bool wantProxyNTLMhttp = (needle->bits.proxy_user_passwd && ((data->state.authproxy.want & (CURLAUTH_NTLM | CURLAUTH_NTLM_WB)) && (needle->handler->protocol & PROTO_FAMILY_HTTP)));




  *force_reuse = FALSE;
  *waitpipe = FALSE;

  
  if(canPipeline && Curl_pipeline_site_blacklisted(data, needle)) {
    canPipeline = FALSE;
  }

  
  bundle = Curl_conncache_find_bundle(needle, data->state.conn_cache);
  if(bundle) {
    
    size_t max_pipe_len = (bundle->multiuse != BUNDLE_MULTIPLEX)? max_pipeline_length(data->multi):0;
    size_t best_pipe_len = max_pipe_len;
    struct curl_llist_element *curr;

    infof(data, "Found bundle for host %s: %p [%s]\n", (needle->bits.conn_to_host ? needle->conn_to_host.name :
           needle->host.name), (void *)bundle, (bundle->multiuse == BUNDLE_PIPELINING ? "can pipeline" :

           (bundle->multiuse == BUNDLE_MULTIPLEX ? "can multiplex" : "serially")));

    
    if(canPipeline) {
      if(bundle->multiuse <= BUNDLE_UNKNOWN) {
        if((bundle->multiuse == BUNDLE_UNKNOWN) && data->set.pipewait) {
          infof(data, "Server doesn't support multi-use yet, wait\n");
          *waitpipe = TRUE;
          return FALSE; 
        }

        infof(data, "Server doesn't support multi-use (yet)\n");
        canPipeline = FALSE;
      }
      if((bundle->multiuse == BUNDLE_PIPELINING) && !Curl_pipeline_wanted(data->multi, CURLPIPE_HTTP1)) {
        
        infof(data, "Could pipeline, but not asked to!\n");
        canPipeline = FALSE;
      }
      else if((bundle->multiuse == BUNDLE_MULTIPLEX) && !Curl_pipeline_wanted(data->multi, CURLPIPE_MULTIPLEX)) {
        infof(data, "Could multiplex, but not asked to!\n");
        canPipeline = FALSE;
      }
    }

    curr = bundle->conn_list.head;
    while(curr) {
      bool match = FALSE;
      size_t pipeLen;

      
      check = curr->ptr;
      curr = curr->next;

      if(disconnect_if_dead(check, data))
        continue;

      pipeLen = check->send_pipe.size + check->recv_pipe.size;

      if(canPipeline) {
        if(check->bits.protoconnstart && check->bits.close)
          continue;

        if(!check->bits.multiplex) {
          
          struct Curl_easy* sh = gethandleathead(&check->send_pipe);
          struct Curl_easy* rh = gethandleathead(&check->recv_pipe);
          if(sh) {
            if(!IsPipeliningPossible(sh, check))
              continue;
          }
          else if(rh) {
            if(!IsPipeliningPossible(rh, check))
              continue;
          }
        }
      }
      else {
        if(pipeLen > 0) {
          
          continue;
        }

        if(Curl_resolver_asynch()) {
          
          if(!check->ip_addr_str[0]) {
            infof(data, "Connection #%ld is still name resolving, can't reuse\n", check->connection_id);

            continue;
          }
        }

        if((check->sock[FIRSTSOCKET] == CURL_SOCKET_BAD) || check->bits.close) {
          if(!check->bits.close)
            foundPendingCandidate = TRUE;
          
          infof(data, "Connection #%ld isn't open enough, can't reuse\n", check->connection_id);

          if(check->recv_pipe.size > 0) {
            infof(data, "BAD! Unconnected #%ld has a non-empty recv pipeline!\n", check->connection_id);

          }

          continue;
        }
      }


      if(needle->unix_domain_socket) {
        if(!check->unix_domain_socket)
          continue;
        if(strcmp(needle->unix_domain_socket, check->unix_domain_socket))
          continue;
        if(needle->abstract_unix_socket != check->abstract_unix_socket)
          continue;
      }
      else if(check->unix_domain_socket)
        continue;


      if((needle->handler->flags&PROTOPT_SSL) != (check->handler->flags&PROTOPT_SSL))
        
        if(get_protocol_family(check->handler->protocol) != needle->handler->protocol || !check->tls_upgraded)
          
          continue;

      if(needle->bits.httpproxy != check->bits.httpproxy || needle->bits.socksproxy != check->bits.socksproxy)
        continue;

      if(needle->bits.socksproxy && !proxy_info_matches(&needle->socks_proxy, &check->socks_proxy))
        continue;

      if(needle->bits.conn_to_host != check->bits.conn_to_host)
        
        continue;

      if(needle->bits.conn_to_port != check->bits.conn_to_port)
        
        continue;

      if(needle->bits.httpproxy) {
        if(!proxy_info_matches(&needle->http_proxy, &check->http_proxy))
          continue;

        if(needle->bits.tunnel_proxy != check->bits.tunnel_proxy)
          continue;

        if(needle->http_proxy.proxytype == CURLPROXY_HTTPS) {
          
          if(needle->handler->flags&PROTOPT_SSL) {
            
            if(!Curl_ssl_config_matches(&needle->proxy_ssl_config, &check->proxy_ssl_config))
              continue;
            if(check->proxy_ssl[FIRSTSOCKET].state != ssl_connection_complete)
              continue;
          }
          else {
            if(!Curl_ssl_config_matches(&needle->ssl_config, &check->ssl_config))
              continue;
            if(check->ssl[FIRSTSOCKET].state != ssl_connection_complete)
              continue;
          }
        }
      }

      if(!canPipeline && check->inuse)
        
        continue;

      if(needle->localdev || needle->localport) {
        
        if((check->localport != needle->localport) || (check->localportrange != needle->localportrange) || (needle->localdev && (!check->localdev || strcmp(check->localdev, needle->localdev))))


          continue;
      }

      if(!(needle->handler->flags & PROTOPT_CREDSPERREQUEST)) {
        
        if(strcmp(needle->user, check->user) || strcmp(needle->passwd, check->passwd)) {
          
          continue;
        }
      }

      if(!needle->bits.httpproxy || (needle->handler->flags&PROTOPT_SSL) || needle->bits.tunnel_proxy) {
        

        if((strcasecompare(needle->handler->scheme, check->handler->scheme) || (get_protocol_family(check->handler->protocol) == needle->handler->protocol && check->tls_upgraded)) && (!needle->bits.conn_to_host || strcasecompare( needle->conn_to_host.name, check->conn_to_host.name)) && (!needle->bits.conn_to_port || needle->conn_to_port == check->conn_to_port) && strcasecompare(needle->host.name, check->host.name) && needle->remote_port == check->remote_port) {







          
          if(needle->handler->flags & PROTOPT_SSL) {
            
            if(!Curl_ssl_config_matches(&needle->ssl_config, &check->ssl_config)) {
              DEBUGF(infof(data, "Connection #%ld has different SSL parameters, " "can't reuse\n", check->connection_id));


              continue;
            }
            if(check->ssl[FIRSTSOCKET].state != ssl_connection_complete) {
              foundPendingCandidate = TRUE;
              DEBUGF(infof(data, "Connection #%ld has not started SSL connect, " "can't reuse\n", check->connection_id));


              continue;
            }
          }
          match = TRUE;
        }
      }
      else {
        
        match = TRUE;
      }

      if(match) {

        
        if(wantNTLMhttp) {
          if(strcmp(needle->user, check->user) || strcmp(needle->passwd, check->passwd))
            continue;
        }
        else if(check->ntlm.state != NTLMSTATE_NONE) {
          
          continue;
        }

        
        if(wantProxyNTLMhttp) {
          
          if(!check->http_proxy.user || !check->http_proxy.passwd)
            continue;

          if(strcmp(needle->http_proxy.user, check->http_proxy.user) || strcmp(needle->http_proxy.passwd, check->http_proxy.passwd))
            continue;
        }
        else if(check->proxyntlm.state != NTLMSTATE_NONE) {
          
          continue;
        }

        if(wantNTLMhttp || wantProxyNTLMhttp) {
          
          chosen = check;

          if((wantNTLMhttp && (check->ntlm.state != NTLMSTATE_NONE)) || (wantProxyNTLMhttp && (check->proxyntlm.state != NTLMSTATE_NONE))) {


            
            *force_reuse = TRUE;
            break;
          }

          
          continue;
        }

        if(canPipeline) {
          

          if(pipeLen == 0) {
            
            chosen = check;
            break;
          }

          
          if(max_pipe_len && (pipeLen >= max_pipe_len)) {
            infof(data, "Pipe is full, skip (%zu)\n", pipeLen);
            continue;
          }

          
          if(check->bits.multiplex) {
            
            struct http_conn *httpc = &check->proto.httpc;
            if(pipeLen >= httpc->settings.max_concurrent_streams) {
              infof(data, "MAX_CONCURRENT_STREAMS reached, skip (%zu)\n", pipeLen);
              continue;
            }
          }

          
          if(Curl_pipeline_penalized(data, check)) {
            infof(data, "Penalized, skip\n");
            continue;
          }

          if(max_pipe_len) {
            if(pipeLen < best_pipe_len) {
              
              chosen = check;
              best_pipe_len = pipeLen;
              continue;
            }
          }
          else {
            
            chosen = check;
            infof(data, "Multiplexed connection found!\n");
            break;
          }
        }
        else {
          
          chosen = check;
          break;
        }
      }
    }
  }

  if(chosen) {
    *usethis = chosen;
    return TRUE; 
  }

  if(foundPendingCandidate && data->set.pipewait) {
    infof(data, "Found pending candidate for reuse and CURLOPT_PIPEWAIT is set\n");
    *waitpipe = TRUE;
  }

  return FALSE; 
}


CURLcode Curl_connected_proxy(struct connectdata *conn, int sockindex)
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
    conn->bits.socksproxy_connecting = TRUE;
    switch(conn->socks_proxy.proxytype) {
    case CURLPROXY_SOCKS5:
    case CURLPROXY_SOCKS5_HOSTNAME:
      result = Curl_SOCKS5(conn->socks_proxy.user, conn->socks_proxy.passwd, host, port, sockindex, conn);
      break;

    case CURLPROXY_SOCKS4:
    case CURLPROXY_SOCKS4A:
      result = Curl_SOCKS4(conn->socks_proxy.user, host, port, sockindex, conn);
      break;

    default:
      failf(conn->data, "unknown proxytype option given");
      result = CURLE_COULDNT_CONNECT;
    } 
    conn->bits.socksproxy_connecting = FALSE;

  (void)sockindex;

  }

  return result;
}



void Curl_verboseconnect(struct connectdata *conn)
{
  if(conn->data->set.verbose)
    infof(conn->data, "Connected to %s (%s) port %ld (#%ld)\n", conn->bits.socksproxy ? conn->socks_proxy.host.dispname :
          conn->bits.httpproxy ? conn->http_proxy.host.dispname :
          conn->bits.conn_to_host ? conn->conn_to_host.dispname :
          conn->host.dispname, conn->ip_addr_str, conn->port, conn->connection_id);
}


int Curl_protocol_getsock(struct connectdata *conn, curl_socket_t *socks, int numsocks)

{
  if(conn->handler->proto_getsock)
    return conn->handler->proto_getsock(conn, socks, numsocks);
  return GETSOCK_BLANK;
}

int Curl_doing_getsock(struct connectdata *conn, curl_socket_t *socks, int numsocks)

{
  if(conn && conn->handler->doing_getsock)
    return conn->handler->doing_getsock(conn, socks, numsocks);
  return GETSOCK_BLANK;
}



CURLcode Curl_protocol_connecting(struct connectdata *conn, bool *done)
{
  CURLcode result=CURLE_OK;

  if(conn && conn->handler->connecting) {
    *done = FALSE;
    result = conn->handler->connecting(conn, done);
  }
  else *done = TRUE;

  return result;
}



CURLcode Curl_protocol_doing(struct connectdata *conn, bool *done)
{
  CURLcode result=CURLE_OK;

  if(conn && conn->handler->doing) {
    *done = FALSE;
    result = conn->handler->doing(conn, done);
  }
  else *done = TRUE;

  return result;
}


CURLcode Curl_protocol_connect(struct connectdata *conn, bool *protocol_done)
{
  CURLcode result=CURLE_OK;

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

    if(conn->bits.tunnel_proxy && conn->bits.httpproxy && (conn->tunnel_state[FIRSTSOCKET] != TUNNEL_COMPLETE))
      
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


static bool is_ASCII_name(const char *hostname)
{
  const unsigned char *ch = (const unsigned char *)hostname;

  while(*ch) {
    if(*ch++ & 0x80)
      return FALSE;
  }
  return TRUE;
}


static void fix_hostname(struct connectdata *conn, struct hostname *host)
{
  size_t len;
  struct Curl_easy *data = conn->data;


  (void)data;
  (void)conn;

  (void)conn;


  
  host->dispname = host->name;

  len = strlen(host->name);
  if(len && (host->name[len-1] == '.'))
    
    host->name[len-1]=0;

  
  if(!is_ASCII_name(host->name)) {

    if(idn2_check_version(IDN2_VERSION)) {
      char *ace_hostname = NULL;

      
      int flags = IDN2_NFC_INPUT | IDN2_NONTRANSITIONAL;

      int flags = IDN2_NFC_INPUT;

      int rc = idn2_lookup_ul((const char *)host->name, &ace_hostname, flags);
      if(rc == IDN2_OK) {
        host->encalloc = (char *)ace_hostname;
        
        host->name = host->encalloc;
      }
      else infof(data, "Failed to convert %s to ACE; %s\n", host->name, idn2_strerror(rc));

    }

    char *ace_hostname = NULL;

    if(curl_win32_idn_to_ascii(host->name, &ace_hostname)) {
      host->encalloc = ace_hostname;
      
      host->name = host->encalloc;
    }
    else infof(data, "Failed to convert %s to ACE;\n", host->name);

    infof(data, "IDN support not present, can't parse Unicode domains\n");

  }
}


static void free_fixed_hostname(struct hostname *host)
{

  if(host->encalloc) {
    idn2_free(host->encalloc); 
    host->encalloc = NULL;
  }

  free(host->encalloc); 
  host->encalloc = NULL;

  (void)host;

}

static void llist_dtor(void *user, void *element)
{
  (void)user;
  (void)element;
  
}


static struct connectdata *allocate_conn(struct Curl_easy *data)
{
  struct connectdata *conn = calloc(1, sizeof(struct connectdata));
  if(!conn)
    return NULL;

  conn->handler = &Curl_handler_dummy;  

  

  conn->sock[FIRSTSOCKET] = CURL_SOCKET_BAD;     
  conn->sock[SECONDARYSOCKET] = CURL_SOCKET_BAD; 
  conn->tempsock[0] = CURL_SOCKET_BAD; 
  conn->tempsock[1] = CURL_SOCKET_BAD; 
  conn->connection_id = -1;    
  conn->port = -1; 
  conn->remote_port = -1; 

  conn->postponed[0].bindsock = CURL_SOCKET_BAD; 
  conn->postponed[1].bindsock = CURL_SOCKET_BAD; 


  
  connclose(conn, "Default to force-close");

  
  conn->created = Curl_tvnow();

  conn->data = data; 

  conn->http_proxy.proxytype = data->set.proxytype;
  conn->socks_proxy.proxytype = CURLPROXY_SOCKS4;



  conn->bits.proxy = FALSE;
  conn->bits.httpproxy = FALSE;
  conn->bits.socksproxy = FALSE;
  conn->bits.proxy_user_passwd = FALSE;
  conn->bits.tunnel_proxy = FALSE;



  
  conn->bits.proxy = (data->set.str[STRING_PROXY] && *data->set.str[STRING_PROXY]) ? TRUE : FALSE;
  conn->bits.httpproxy = (conn->bits.proxy && (conn->http_proxy.proxytype == CURLPROXY_HTTP || conn->http_proxy.proxytype == CURLPROXY_HTTP_1_0 || conn->http_proxy.proxytype == CURLPROXY_HTTPS)) ? TRUE : FALSE;



  conn->bits.socksproxy = (conn->bits.proxy && !conn->bits.httpproxy) ? TRUE : FALSE;

  if(data->set.str[STRING_PRE_PROXY] && *data->set.str[STRING_PRE_PROXY]) {
    conn->bits.proxy = TRUE;
    conn->bits.socksproxy = TRUE;
  }

  conn->bits.proxy_user_passwd = (data->set.str[STRING_PROXYUSERNAME]) ? TRUE : FALSE;
  conn->bits.tunnel_proxy = data->set.tunnel_thru_httpproxy;



  conn->bits.user_passwd = (data->set.str[STRING_USERNAME]) ? TRUE : FALSE;
  conn->bits.ftp_use_epsv = data->set.ftp_use_epsv;
  conn->bits.ftp_use_eprt = data->set.ftp_use_eprt;

  conn->ssl_config.verifystatus = data->set.ssl.primary.verifystatus;
  conn->ssl_config.verifypeer = data->set.ssl.primary.verifypeer;
  conn->ssl_config.verifyhost = data->set.ssl.primary.verifyhost;
  conn->proxy_ssl_config.verifystatus = data->set.proxy_ssl.primary.verifystatus;
  conn->proxy_ssl_config.verifypeer = data->set.proxy_ssl.primary.verifypeer;
  conn->proxy_ssl_config.verifyhost = data->set.proxy_ssl.primary.verifyhost;

  conn->ip_version = data->set.ipver;


  conn->ntlm_auth_hlpr_socket = CURL_SOCKET_BAD;
  conn->ntlm_auth_hlpr_pid = 0;
  conn->challenge_header = NULL;
  conn->response_header = NULL;


  if(Curl_pipeline_wanted(data->multi, CURLPIPE_HTTP1) && !conn->master_buffer) {
    
    conn->master_buffer = calloc(BUFSIZE, sizeof(char));
    if(!conn->master_buffer)
      goto error;
  }

  
  Curl_llist_init(&conn->send_pipe, (curl_llist_dtor) llist_dtor);
  Curl_llist_init(&conn->recv_pipe, (curl_llist_dtor) llist_dtor);


  conn->data_prot = PROT_CLEAR;


  
  if(data->set.str[STRING_DEVICE]) {
    conn->localdev = strdup(data->set.str[STRING_DEVICE]);
    if(!conn->localdev)
      goto error;
  }
  conn->localportrange = data->set.localportrange;
  conn->localport = data->set.localport;

  
  conn->fclosesocket = data->set.fclosesocket;
  conn->closesocket_client = data->set.closesocket_client;

  return conn;
  error:

  Curl_llist_destroy(&conn->send_pipe, NULL);
  Curl_llist_destroy(&conn->recv_pipe, NULL);

  free(conn->master_buffer);
  free(conn->localdev);
  free(conn);
  return NULL;
}

static CURLcode findprotocol(struct Curl_easy *data, struct connectdata *conn, const char *protostr)

{
  const struct Curl_handler * const *pp;
  const struct Curl_handler *p;

  
  for(pp = protocols; (p = *pp) != NULL; pp++) {
    if(strcasecompare(p->scheme, protostr)) {
      
      if(!(data->set.allowed_protocols & p->protocol))
        
        break;

      
      if(data->state.this_is_a_follow && !(data->set.redir_protocols & p->protocol))
        
        break;

      
      conn->handler = conn->given = p;

      
      return CURLE_OK;
    }
  }


  
  failf(data, "Protocol \"%s\" not supported or disabled in " LIBCURL_NAME, protostr);

  return CURLE_UNSUPPORTED_PROTOCOL;
}


static CURLcode parseurlandfillconn(struct Curl_easy *data, struct connectdata *conn, bool *prot_missing, char **userp, char **passwdp, char **optionsp)



{
  char *at;
  char *fragment;
  char *path = data->state.path;
  char *query;
  int i;
  int rc;
  const char *protop = "";
  CURLcode result;
  bool rebuild_url = FALSE;
  bool url_has_scheme = FALSE;
  char protobuf[16];

  *prot_missing = FALSE;

  
  if(strpbrk(data->change.url, "\r\n")) {
    failf(data, "Illegal characters found in URL");
    return CURLE_URL_MALFORMAT;
  }

  
  if(data->change.url[0] == ':') {
    failf(data, "Bad URL, colon is first character");
    return CURLE_URL_MALFORMAT;
  }

  
  if((('a' <= data->change.url[0] && data->change.url[0] <= 'z') || ('A' <= data->change.url[0] && data->change.url[0] <= 'Z')) && data->change.url[1] == ':' && data->set.str[STRING_DEFAULT_PROTOCOL] && strcasecompare(data->set.str[STRING_DEFAULT_PROTOCOL], "file")) {


    ; 
  }
  else { 
    for(i = 0; i < 16 && data->change.url[i]; ++i) {
      if(data->change.url[i] == '/')
        break;
      if(data->change.url[i] == ':') {
        url_has_scheme = TRUE;
        break;
      }
    }
  }

  
  if((url_has_scheme && strncasecompare(data->change.url, "file:", 5)) || (!url_has_scheme && data->set.str[STRING_DEFAULT_PROTOCOL] && strcasecompare(data->set.str[STRING_DEFAULT_PROTOCOL], "file"))) {

    bool path_has_drive = FALSE;

    if(url_has_scheme)
      rc = sscanf(data->change.url, "%*15[^\n/:]:%[^\n]", path);
    else rc = sscanf(data->change.url, "%[^\n]", path);

    if(rc != 1) {
      failf(data, "Bad URL");
      return CURLE_URL_MALFORMAT;
    }

    if(url_has_scheme && path[0] == '/' && path[1] == '/') {
      

      
      memmove(path, path + 2, strlen(path + 2)+1);
    }

    
    path_has_drive = (('a' <= path[0] && path[0] <= 'z') || ('A' <= path[0] && path[0] <= 'Z')) && path[1] == ':';

    
    if(path[0] != '/' && !path_has_drive) {
      
      char *ptr;
      if(!checkprefix("localhost/", path) && !checkprefix("127.0.0.1/", path)) {
        failf(data, "Invalid file://hostname/, " "expected localhost or 127.0.0.1 or none");
        return CURLE_URL_MALFORMAT;
      }
      ptr = &path[9]; 

      

      if('/' == ptr[1])
        
        ptr++;

      
      memmove(path, ptr, strlen(ptr)+1);

      path_has_drive = (('a' <= path[0] && path[0] <= 'z') || ('A' <= path[0] && path[0] <= 'Z')) && path[1] == ':';
    }


    if(path_has_drive) {
      failf(data, "File drive letters are only accepted in MSDOS/Windows.");
      return CURLE_URL_MALFORMAT;
    }


    protop = "file"; 
  }
  else {
    
    char slashbuf[4];
    path[0]=0;

    rc = sscanf(data->change.url, "%15[^\n/:]:%3[/]%[^\n/?#]%[^\n]", protobuf, slashbuf, conn->host.name, path);

    if(2 == rc) {
      failf(data, "Bad URL");
      return CURLE_URL_MALFORMAT;
    }
    if(3 > rc) {

      
      rc = sscanf(data->change.url, "%[^\n/?#]%[^\n]", conn->host.name, path);
      if(1 > rc) {
        

        if(!(rc == -1 && *conn->host.name))

        {
          failf(data, "<url> malformed");
          return CURLE_URL_MALFORMAT;
        }
      }

      

      protop = data->set.str[STRING_DEFAULT_PROTOCOL];
      if(!protop) {
        
        if(checkprefix("FTP.", conn->host.name))
          protop = "ftp";
        else if(checkprefix("DICT.", conn->host.name))
          protop = "DICT";
        else if(checkprefix("LDAP.", conn->host.name))
          protop = "LDAP";
        else if(checkprefix("IMAP.", conn->host.name))
          protop = "IMAP";
        else if(checkprefix("SMTP.", conn->host.name))
          protop = "smtp";
        else if(checkprefix("POP3.", conn->host.name))
          protop = "pop3";
        else protop = "http";
      }

      *prot_missing = TRUE; 
    }
    else {
      size_t s = strlen(slashbuf);
      protop = protobuf;
      if(s != 2) {
        infof(data, "Unwillingly accepted illegal URL using %d slash%s!\n", s, s>1?"es":"");

        if(data->change.url_alloc)
          free(data->change.url);
        
        data->change.url = aprintf("%s://%s%s", protobuf, conn->host.name, path);
        if(!data->change.url)
          return CURLE_OUT_OF_MEMORY;
        data->change.url_alloc = TRUE;
      }
    }
  }

  
  at = strchr(conn->host.name, '@');
  if(at)
    query = strchr(at+1, '?');
  else query = strchr(conn->host.name, '?');

  if(query) {
    

    size_t hostlen = strlen(query);
    size_t pathlen = strlen(path);

    
    memmove(path+hostlen+1, path, pathlen+1);

     
    memcpy(path+1, query, hostlen);

    path[0]='/'; 
    rebuild_url = TRUE;

    *query=0; 
  }
  else if(!path[0]) {
    
    strcpy(path, "/");
    rebuild_url = TRUE;
  }

  
  if(path[0] != '/') {
    
    memmove(&path[1], path, strlen(path)+1);
    path[0] = '/';
    rebuild_url = TRUE;
  }
  else if(!data->set.path_as_is) {
    
    char *newp = Curl_dedotdotify(path);
    if(!newp)
      return CURLE_OUT_OF_MEMORY;

    if(strcmp(newp, path)) {
      rebuild_url = TRUE;
      free(data->state.pathbuffer);
      data->state.pathbuffer = newp;
      data->state.path = newp;
      path = newp;
    }
    else free(newp);
  }

  
  if(rebuild_url) {
    char *reurl;

    size_t plen = strlen(path); 
    size_t urllen = strlen(data->change.url); 

    size_t prefixlen = strlen(conn->host.name);

    if(!*prot_missing)
      prefixlen += strlen(protop) + strlen("://");

    reurl = malloc(urllen + 2); 
    if(!reurl)
      return CURLE_OUT_OF_MEMORY;

    
    memcpy(reurl, data->change.url, prefixlen);

    
    memcpy(&reurl[prefixlen], path, plen + 1);

    
    if(data->change.url_alloc) {
      Curl_safefree(data->change.url);
      data->change.url_alloc = FALSE;
    }

    infof(data, "Rebuilt URL to: %s\n", reurl);

    data->change.url = reurl;
    data->change.url_alloc = TRUE; 
  }

  result = findprotocol(data, conn, protop);
  if(result)
    return result;

  
  result = parse_url_login(data, conn, userp, passwdp, optionsp);
  if(result)
    return result;

  if(conn->host.name[0] == '[') {
    
    char *percent = strchr(conn->host.name, '%');
    if(percent) {
      unsigned int identifier_offset = 3;
      char *endp;
      unsigned long scope;
      if(strncmp("%25", percent, 3) != 0) {
        infof(data, "Please URL encode %% as %%25, see RFC 6874.\n");
        identifier_offset = 1;
      }
      scope = strtoul(percent + identifier_offset, &endp, 10);
      if(*endp == ']') {
        
        memmove(percent, endp, strlen(endp)+1);
        conn->scope_id = (unsigned int)scope;
      }
      else {
        

        char ifname[IFNAMSIZ + 2];
        char *square_bracket;
        unsigned int scopeidx = 0;
        strncpy(ifname, percent + identifier_offset, IFNAMSIZ + 2);
        
        ifname[IFNAMSIZ + 1] = '\0';
        square_bracket = strchr(ifname, ']');
        if(square_bracket) {
          
          *square_bracket = '\0';
          scopeidx = if_nametoindex(ifname);
          if(scopeidx == 0) {
            infof(data, "Invalid network interface: %s; %s\n", ifname, strerror(errno));
          }
        }
        if(scopeidx > 0) {
          char *p = percent + identifier_offset + strlen(ifname);

          
          memmove(percent, p, strlen(p) + 1);
          conn->scope_id = scopeidx;
        }
        else  infof(data, "Invalid IPv6 address format\n");

      }
    }
  }

  if(data->set.scope_id)
    
    conn->scope_id = data->set.scope_id;

  
  fragment = strchr(path, '#');
  if(fragment) {
    *fragment = 0;

    
    fragment = strchr(data->change.url, '#');
    if(fragment)
      *fragment = 0;
  }

  
  return CURLE_OK;
}


static CURLcode setup_range(struct Curl_easy *data)
{
  struct UrlState *s = &data->state;
  s->resume_from = data->set.set_resume_from;
  if(s->resume_from || data->set.str[STRING_SET_RANGE]) {
    if(s->rangestringalloc)
      free(s->range);

    if(s->resume_from)
      s->range = aprintf("%" CURL_FORMAT_CURL_OFF_TU "-", s->resume_from);
    else s->range = strdup(data->set.str[STRING_SET_RANGE]);

    s->rangestringalloc = (s->range) ? TRUE : FALSE;

    if(!s->range)
      return CURLE_OUT_OF_MEMORY;

    
    s->use_range = TRUE;        
  }
  else s->use_range = FALSE;

  return CURLE_OK;
}



static CURLcode setup_connection_internals(struct connectdata *conn)
{
  const struct Curl_handler * p;
  CURLcode result;
  struct Curl_easy *data = conn->data;

  
  Curl_free_request_state(data);

  memset(&data->req, 0, sizeof(struct SingleRequest));
  data->req.maxdownload = -1;

  conn->socktype = SOCK_STREAM; 

  
  p = conn->handler;

  if(p->setup_connection) {
    result = (*p->setup_connection)(conn);

    if(result)
      return result;

    p = conn->handler;              
  }

  if(conn->port < 0)
    
    conn->port = p->defport;

  return CURLE_OK;
}



void Curl_free_request_state(struct Curl_easy *data)
{
  Curl_safefree(data->req.protop);
  Curl_safefree(data->req.newurl);
}




static bool check_noproxy(const char *name, const char *no_proxy)
{
  
  size_t tok_start;
  size_t tok_end;
  const char *separator = ", ";
  size_t no_proxy_len;
  size_t namelen;
  char *endptr;

  if(no_proxy && no_proxy[0]) {
    if(strcasecompare("*", no_proxy)) {
      return TRUE;
    }

    

    no_proxy_len = strlen(no_proxy);
    endptr = strchr(name, ':');
    if(endptr)
      namelen = endptr - name;
    else namelen = strlen(name);

    for(tok_start = 0; tok_start < no_proxy_len; tok_start = tok_end + 1) {
      while(tok_start < no_proxy_len && strchr(separator, no_proxy[tok_start]) != NULL) {
        
        ++tok_start;
      }

      if(tok_start == no_proxy_len)
        break; 

      for(tok_end = tok_start; tok_end < no_proxy_len && strchr(separator, no_proxy[tok_end]) == NULL; ++tok_end)
        
        ;

      
      if(no_proxy[tok_start] == '.')
        ++tok_start;

      if((tok_end - tok_start) <= namelen) {
        
        const char *checkn = name + namelen - (tok_end - tok_start);
        if(strncasecompare(no_proxy + tok_start, checkn, tok_end - tok_start)) {
          if((tok_end - tok_start) == namelen || *(checkn - 1) == '.') {
            
            return TRUE;
          }
        }
      } 
    } 
  } 

  return FALSE;
}



static char *detect_proxy(struct connectdata *conn)
{
  char *proxy = NULL;

  
  char proxy_env[128];
  const char *protop = conn->handler->scheme;
  char *envp = proxy_env;
  char *prox;

  
  while(*protop)
    *envp++ = (char)tolower((int)*protop++);

  
  strcpy(envp, "_proxy");

  
  prox=curl_getenv(proxy_env);

  
  if(!prox && !strcasecompare("http_proxy", proxy_env)) {
    
    Curl_strntoupper(proxy_env, proxy_env, sizeof(proxy_env));
    prox=curl_getenv(proxy_env);
  }

  if(prox)
    proxy = prox; 
  else {
    proxy = curl_getenv("all_proxy"); 
    if(!proxy)
      proxy=curl_getenv("ALL_PROXY");
  }

  return proxy;
}



static CURLcode parse_proxy(struct Curl_easy *data, struct connectdata *conn, char *proxy, curl_proxytype proxytype)

{
  char *prox_portno;
  char *endofprot;

  
  char *proxyptr;
  char *portptr;
  char *atsign;
  long port = -1;
  char *proxyuser = NULL;
  char *proxypasswd = NULL;
  bool sockstype;

  

  
  endofprot = strstr(proxy, "://");
  if(endofprot) {
    proxyptr = endofprot+3;
    if(checkprefix("https", proxy))
      proxytype = CURLPROXY_HTTPS;
    else if(checkprefix("socks5h", proxy))
      proxytype = CURLPROXY_SOCKS5_HOSTNAME;
    else if(checkprefix("socks5", proxy))
      proxytype = CURLPROXY_SOCKS5;
    else if(checkprefix("socks4a", proxy))
      proxytype = CURLPROXY_SOCKS4A;
    else if(checkprefix("socks4", proxy) || checkprefix("socks", proxy))
      proxytype = CURLPROXY_SOCKS4;
    else if(checkprefix("http:", proxy))
      ; 
    else {
      
      failf(data, "Unsupported proxy scheme for \'%s\'", proxy);
      return CURLE_COULDNT_CONNECT;
    }
  }
  else proxyptr = proxy;


  if(proxytype == CURLPROXY_HTTPS) {
    failf(data, "Unsupported proxy \'%s\'" ", libcurl is built without the HTTPS-proxy support.", proxy);
    return CURLE_NOT_BUILT_IN;
  }


  sockstype = proxytype == CURLPROXY_SOCKS5_HOSTNAME || proxytype == CURLPROXY_SOCKS5 || proxytype == CURLPROXY_SOCKS4A || proxytype == CURLPROXY_SOCKS4;



  
  atsign = strchr(proxyptr, '@');
  if(atsign) {
    CURLcode result = parse_login_details(proxyptr, atsign - proxyptr, &proxyuser, &proxypasswd, NULL);

    if(result)
      return result;
    proxyptr = atsign + 1;
  }

  
  portptr = proxyptr;

  
  if(*proxyptr == '[') {
    char *ptr = ++proxyptr; 
    while(*ptr && (ISXDIGIT(*ptr) || (*ptr == ':') || (*ptr == '.')))
      ptr++;
    if(*ptr == '%') {
      
      if(strncmp("%25", ptr, 3))
        infof(data, "Please URL encode %% as %%25, see RFC 6874.\n");
      ptr++;
      
      while(*ptr && (ISALPHA(*ptr) || ISXDIGIT(*ptr) || (*ptr == '-') || (*ptr == '.') || (*ptr == '_') || (*ptr == '~')))
        ptr++;
    }
    if(*ptr == ']')
      
      *ptr++ = 0;
    else infof(data, "Invalid IPv6 address format\n");
    portptr = ptr;
    
  }

  
  prox_portno = strchr(portptr, ':');
  if(prox_portno) {
    char *endp = NULL;

    *prox_portno = 0x0; 
    prox_portno ++;
    
    port = strtol(prox_portno, &endp, 10);
    if((endp && *endp && (*endp != '/') && (*endp != ' ')) || (port < 0) || (port > 65535)) {
      
      infof(data, "No valid port number in proxy string (%s)\n", prox_portno);
    }
    else conn->port = port;
  }
  else {
    if(proxyptr[0]=='/')
      
      return CURLE_COULDNT_RESOLVE_PROXY;

    
    atsign = strchr(proxyptr, '/');
    if(atsign)
      *atsign = '\0'; 

    if(data->set.proxyport)
      
      port = data->set.proxyport;
    else {
      if(proxytype == CURLPROXY_HTTPS)
        port = CURL_DEFAULT_HTTPS_PROXY_PORT;
      else port = CURL_DEFAULT_PROXY_PORT;
    }
  }

  if(*proxyptr) {
    struct proxy_info *proxyinfo = sockstype ? &conn->socks_proxy : &conn->http_proxy;
    proxyinfo->proxytype = proxytype;

    if(proxyuser) {
      
      Curl_safefree(proxyinfo->user);
      proxyinfo->user = curl_easy_unescape(data, proxyuser, 0, NULL);
      Curl_safefree(proxyuser);

      if(!proxyinfo->user) {
        Curl_safefree(proxypasswd);
        return CURLE_OUT_OF_MEMORY;
      }

      Curl_safefree(proxyinfo->passwd);
      if(proxypasswd && strlen(proxypasswd) < MAX_CURL_PASSWORD_LENGTH)
        proxyinfo->passwd = curl_easy_unescape(data, proxypasswd, 0, NULL);
      else proxyinfo->passwd = strdup("");
      Curl_safefree(proxypasswd);

      if(!proxyinfo->passwd)
        return CURLE_OUT_OF_MEMORY;

      conn->bits.proxy_user_passwd = TRUE; 
    }

    if(port >= 0) {
      proxyinfo->port = port;
      if(conn->port < 0 || sockstype || !conn->socks_proxy.host.rawalloc)
        conn->port = port;
    }

    
    Curl_safefree(proxyinfo->host.rawalloc);
    proxyinfo->host.rawalloc = strdup(proxyptr);
    proxyinfo->host.name = proxyinfo->host.rawalloc;

    if(!proxyinfo->host.rawalloc)
      return CURLE_OUT_OF_MEMORY;
  }

  Curl_safefree(proxyuser);
  Curl_safefree(proxypasswd);

  return CURLE_OK;
}


static CURLcode parse_proxy_auth(struct Curl_easy *data, struct connectdata *conn)
{
  char proxyuser[MAX_CURL_USER_LENGTH]="";
  char proxypasswd[MAX_CURL_PASSWORD_LENGTH]="";
  CURLcode result;

  if(data->set.str[STRING_PROXYUSERNAME] != NULL) {
    strncpy(proxyuser, data->set.str[STRING_PROXYUSERNAME], MAX_CURL_USER_LENGTH);
    proxyuser[MAX_CURL_USER_LENGTH-1] = '\0';   
  }
  if(data->set.str[STRING_PROXYPASSWORD] != NULL) {
    strncpy(proxypasswd, data->set.str[STRING_PROXYPASSWORD], MAX_CURL_PASSWORD_LENGTH);
    proxypasswd[MAX_CURL_PASSWORD_LENGTH-1] = '\0'; 
  }

  result = Curl_urldecode(data, proxyuser, 0, &conn->http_proxy.user, NULL, FALSE);
  if(!result)
    result = Curl_urldecode(data, proxypasswd, 0, &conn->http_proxy.passwd, NULL, FALSE);
  return result;
}


static CURLcode create_conn_helper_init_proxy(struct connectdata *conn)
{
  char *proxy = NULL;
  char *socksproxy = NULL;
  char *no_proxy = NULL;
  CURLcode result = CURLE_OK;
  struct Curl_easy *data = conn->data;

  
  if(conn->bits.proxy_user_passwd) {
    result = parse_proxy_auth(data, conn);
    if(result)
      goto out;
  }

  
  if(data->set.str[STRING_PROXY]) {
    proxy = strdup(data->set.str[STRING_PROXY]);
    
    if(NULL == proxy) {
      failf(data, "memory shortage");
      result = CURLE_OUT_OF_MEMORY;
      goto out;
    }
  }

  if(data->set.str[STRING_PRE_PROXY]) {
    socksproxy = strdup(data->set.str[STRING_PRE_PROXY]);
    
    if(NULL == socksproxy) {
      failf(data, "memory shortage");
      result = CURLE_OUT_OF_MEMORY;
      goto out;
    }
  }

  no_proxy = curl_getenv("no_proxy");
  if(!no_proxy)
    no_proxy = curl_getenv("NO_PROXY");

  if(check_noproxy(conn->host.name, data->set.str[STRING_NOPROXY]) || (!data->set.str[STRING_NOPROXY] && check_noproxy(conn->host.name, no_proxy))) {

    Curl_safefree(proxy);
    Curl_safefree(socksproxy);
  }
  else if(!proxy && !socksproxy)

    
    proxy = detect_proxy(conn);

    proxy = NULL;


  Curl_safefree(no_proxy);


  
  if(proxy && conn->unix_domain_socket) {
    free(proxy);
    proxy = NULL;
  }


  if(proxy && (!*proxy || (conn->handler->flags & PROTOPT_NONETWORK))) {
    free(proxy);  
    proxy = NULL;
  }
  if(socksproxy && (!*socksproxy || (conn->handler->flags & PROTOPT_NONETWORK))) {
    free(socksproxy);  
    socksproxy = NULL;
  }

  
  if(proxy || socksproxy) {
    if(proxy) {
      result = parse_proxy(data, conn, proxy, conn->http_proxy.proxytype);
      Curl_safefree(proxy); 
      if(result)
        goto out;
    }

    if(socksproxy) {
      result = parse_proxy(data, conn, socksproxy, conn->socks_proxy.proxytype);
      
      Curl_safefree(socksproxy);
      if(result)
        goto out;
    }

    if(conn->http_proxy.host.rawalloc) {

      
      result = CURLE_UNSUPPORTED_PROTOCOL;
      goto out;

      
      if(!(conn->handler->protocol & PROTO_FAMILY_HTTP) && !conn->bits.tunnel_proxy)
        conn->handler = &Curl_handler_http;

      conn->bits.httpproxy = TRUE;

    }
    else {
      conn->bits.httpproxy = FALSE; 
      conn->bits.tunnel_proxy = FALSE; 
    }

    if(conn->socks_proxy.host.rawalloc) {
      if(!conn->http_proxy.host.rawalloc) {
        
        if(!conn->socks_proxy.user) {
          conn->socks_proxy.user = conn->http_proxy.user;
          conn->http_proxy.user = NULL;
          Curl_safefree(conn->socks_proxy.passwd);
          conn->socks_proxy.passwd = conn->http_proxy.passwd;
          conn->http_proxy.passwd = NULL;
        }
      }
      conn->bits.socksproxy = TRUE;
    }
    else conn->bits.socksproxy = FALSE;
  }
  else {
    conn->bits.socksproxy = FALSE;
    conn->bits.httpproxy = FALSE;
  }
  conn->bits.proxy = conn->bits.httpproxy || conn->bits.socksproxy;

  if(!conn->bits.proxy) {
    
    conn->bits.proxy = FALSE;
    conn->bits.httpproxy = FALSE;
    conn->bits.socksproxy = FALSE;
    conn->bits.proxy_user_passwd = FALSE;
    conn->bits.tunnel_proxy = FALSE;
  }

out:

  free(socksproxy);
  free(proxy);
  return result;
}



static CURLcode parse_url_login(struct Curl_easy *data, struct connectdata *conn, char **user, char **passwd, char **options)

{
  CURLcode result = CURLE_OK;
  char *userp = NULL;
  char *passwdp = NULL;
  char *optionsp = NULL;

  

  char *ptr = strchr(conn->host.name, '@');
  char *login = conn->host.name;

  DEBUGASSERT(!**user);
  DEBUGASSERT(!**passwd);
  DEBUGASSERT(!**options);
  DEBUGASSERT(conn->handler);

  if(!ptr)
    goto out;

  
  conn->host.name = ++ptr;

  

  if(data->set.use_netrc == CURL_NETRC_REQUIRED)
    goto out;

  
  result = parse_login_details(login, ptr - login - 1, &userp, &passwdp, (conn->handler->flags & PROTOPT_URLOPTIONS)? &optionsp:NULL);


  if(result)
    goto out;

  if(userp) {
    char *newname;

    
    conn->bits.userpwd_in_url = TRUE;
    conn->bits.user_passwd = TRUE; 

    
    result = Curl_urldecode(data, userp, 0, &newname, NULL, FALSE);
    if(result) {
      goto out;
    }

    free(*user);
    *user = newname;
  }

  if(passwdp) {
    
    char *newpasswd;
    result = Curl_urldecode(data, passwdp, 0, &newpasswd, NULL, FALSE);
    if(result) {
      goto out;
    }

    free(*passwd);
    *passwd = newpasswd;
  }

  if(optionsp) {
    
    char *newoptions;
    result = Curl_urldecode(data, optionsp, 0, &newoptions, NULL, FALSE);
    if(result) {
      goto out;
    }

    free(*options);
    *options = newoptions;
  }


  out:

  free(userp);
  free(passwdp);
  free(optionsp);

  return result;
}


static CURLcode parse_login_details(const char *login, const size_t len, char **userp, char **passwdp, char **optionsp)

{
  CURLcode result = CURLE_OK;
  char *ubuf = NULL;
  char *pbuf = NULL;
  char *obuf = NULL;
  const char *psep = NULL;
  const char *osep = NULL;
  size_t ulen;
  size_t plen;
  size_t olen;

  
  if(passwdp) {
    psep = strchr(login, ':');

    
    if(psep >= login + len)
      psep = NULL;
  }

  
  if(optionsp) {
    osep = strchr(login, ';');

    
    if(osep >= login + len)
      osep = NULL;
  }

  
  ulen = (psep ? (size_t)(osep && psep > osep ? osep - login : psep - login) :
          (osep ? (size_t)(osep - login) : len));
  plen = (psep ? (osep && osep > psep ? (size_t)(osep - psep) :
                                 (size_t)(login + len - psep)) - 1 : 0);
  olen = (osep ? (psep && psep > osep ? (size_t)(psep - osep) :
                                 (size_t)(login + len - osep)) - 1 : 0);

  
  if(userp && ulen) {
    ubuf = malloc(ulen + 1);
    if(!ubuf)
      result = CURLE_OUT_OF_MEMORY;
  }

  
  if(!result && passwdp && plen) {
    pbuf = malloc(plen + 1);
    if(!pbuf) {
      free(ubuf);
      result = CURLE_OUT_OF_MEMORY;
    }
  }

  
  if(!result && optionsp && olen) {
    obuf = malloc(olen + 1);
    if(!obuf) {
      free(pbuf);
      free(ubuf);
      result = CURLE_OUT_OF_MEMORY;
    }
  }

  if(!result) {
    
    if(ubuf) {
      memcpy(ubuf, login, ulen);
      ubuf[ulen] = '\0';
      Curl_safefree(*userp);
      *userp = ubuf;
    }

    
    if(pbuf) {
      memcpy(pbuf, psep + 1, plen);
      pbuf[plen] = '\0';
      Curl_safefree(*passwdp);
      *passwdp = pbuf;
    }

    
    if(obuf) {
      memcpy(obuf, osep + 1, olen);
      obuf[olen] = '\0';
      Curl_safefree(*optionsp);
      *optionsp = obuf;
    }
  }

  return result;
}


static CURLcode parse_remote_port(struct Curl_easy *data, struct connectdata *conn)
{
  char *portptr;
  char endbracket;

  
  if((1 == sscanf(conn->host.name, "[%*45[0123456789abcdefABCDEF:.]%c", &endbracket)) && (']' == endbracket)) {

    
    conn->bits.ipv6_ip = TRUE;

    conn->host.name++; 
    portptr = strchr(conn->host.name, ']');
    if(portptr) {
      *portptr++ = '\0'; 
      if(':' != *portptr)
        portptr = NULL; 
    }
  }
  else {

    struct in6_addr in6;
    if(Curl_inet_pton(AF_INET6, conn->host.name, &in6) > 0) {
      
      failf(data, "IPv6 numerical address used in URL without brackets");
      return CURLE_URL_MALFORMAT;
    }


    portptr = strchr(conn->host.name, ':');
  }

  if(data->set.use_port && data->state.allow_port) {
    
    conn->remote_port = (unsigned short)data->set.use_port;
    if(portptr)
      *portptr = '\0'; 
    if(conn->bits.httpproxy) {
      
      char *url;
      char type[12]="";

      if(conn->bits.type_set)
        snprintf(type, sizeof(type), ";type=%c", data->set.prefer_ascii?'A':
                 (data->set.ftp_list_only?'D':'I'));

      
      url = aprintf("%s://%s%s%s:%hu%s%s%s", conn->given->scheme, conn->bits.ipv6_ip?"[":"", conn->host.name, conn->bits.ipv6_ip?"]":"", conn->remote_port, data->state.slash_removed?"/":"", data->state.path, type);



      if(!url)
        return CURLE_OUT_OF_MEMORY;

      if(data->change.url_alloc) {
        Curl_safefree(data->change.url);
        data->change.url_alloc = FALSE;
      }

      data->change.url = url;
      data->change.url_alloc = TRUE;
    }
  }
  else if(portptr) {
    

    char *rest;
    long port;

    port=strtol(portptr+1, &rest, 10);  

    if((port < 0) || (port > 0xffff)) {
      
      failf(data, "Port number out of range");
      return CURLE_URL_MALFORMAT;
    }

    if(rest[0]) {
      failf(data, "Port number ended with '%c'", rest[0]);
      return CURLE_URL_MALFORMAT;
    }

    if(rest != &portptr[1]) {
      *portptr = '\0'; 
      conn->remote_port = curlx_ultous(port);
    }
    else {
      
      *portptr = '\0';
    }
  }

  
  if(conn->remote_port < 0)
    conn->remote_port = (unsigned short)conn->given->defport;

  return CURLE_OK;
}


static CURLcode override_login(struct Curl_easy *data, struct connectdata *conn, char **userp, char **passwdp, char **optionsp)

{
  if(data->set.str[STRING_USERNAME]) {
    free(*userp);
    *userp = strdup(data->set.str[STRING_USERNAME]);
    if(!*userp)
      return CURLE_OUT_OF_MEMORY;
  }

  if(data->set.str[STRING_PASSWORD]) {
    free(*passwdp);
    *passwdp = strdup(data->set.str[STRING_PASSWORD]);
    if(!*passwdp)
      return CURLE_OUT_OF_MEMORY;
  }

  if(data->set.str[STRING_OPTIONS]) {
    free(*optionsp);
    *optionsp = strdup(data->set.str[STRING_OPTIONS]);
    if(!*optionsp)
      return CURLE_OUT_OF_MEMORY;
  }

  conn->bits.netrc = FALSE;
  if(data->set.use_netrc != CURL_NETRC_IGNORED) {
    int ret = Curl_parsenetrc(conn->host.name, userp, passwdp, data->set.str[STRING_NETRC_FILE]);

    if(ret > 0) {
      infof(data, "Couldn't find host %s in the " DOT_CHAR "netrc file; using defaults\n", conn->host.name);

    }
    else if(ret < 0) {
      return CURLE_OUT_OF_MEMORY;
    }
    else {
      
      conn->bits.netrc = TRUE;

      conn->bits.user_passwd = TRUE; 
    }
  }

  return CURLE_OK;
}


static CURLcode set_login(struct connectdata *conn, const char *user, const char *passwd, const char *options)

{
  CURLcode result = CURLE_OK;

  
  if((conn->handler->flags & PROTOPT_NEEDSPWD) && !conn->bits.user_passwd) {
    
    conn->user = strdup(CURL_DEFAULT_USER);

    
    if(conn->user)
      conn->passwd = strdup(CURL_DEFAULT_PASSWORD);
    else conn->passwd = NULL;

    
  }
  else {
    
    conn->user = strdup(user);

    
    if(conn->user)
      conn->passwd = strdup(passwd);
    else conn->passwd = NULL;
  }

  if(!conn->user || !conn->passwd)
    result = CURLE_OUT_OF_MEMORY;

  
  if(!result && options[0]) {
    conn->options = strdup(options);

    if(!conn->options)
      result = CURLE_OUT_OF_MEMORY;
  }

  return result;
}


static CURLcode parse_connect_to_host_port(struct Curl_easy *data, const char *host, char **hostname_result, int *port_result)


{
  char *host_dup;
  char *hostptr;
  char *host_portno;
  char *portptr;
  int port = -1;


  (void) data;


  *hostname_result = NULL;
  *port_result = -1;

  if(!host || !*host)
    return CURLE_OK;

  host_dup = strdup(host);
  if(!host_dup)
    return CURLE_OUT_OF_MEMORY;

  hostptr = host_dup;

  
  portptr = hostptr;

  
  if(*hostptr == '[') {
    char *ptr = ++hostptr; 
    while(*ptr && (ISXDIGIT(*ptr) || (*ptr == ':') || (*ptr == '.')))
      ptr++;
    if(*ptr == '%') {
      
      if(strncmp("%25", ptr, 3))
        infof(data, "Please URL encode %% as %%25, see RFC 6874.\n");
      ptr++;
      
      while(*ptr && (ISALPHA(*ptr) || ISXDIGIT(*ptr) || (*ptr == '-') || (*ptr == '.') || (*ptr == '_') || (*ptr == '~')))
        ptr++;
    }
    if(*ptr == ']')
      
      *ptr++ = '\0';
    else infof(data, "Invalid IPv6 address format\n");
    portptr = ptr;
    
  }

  
  host_portno = strchr(portptr, ':');
  if(host_portno) {
    char *endp = NULL;
    *host_portno = '\0'; 
    host_portno++;
    if(*host_portno) {
      long portparse = strtol(host_portno, &endp, 10);
      if((endp && *endp) || (portparse < 0) || (portparse > 65535)) {
        infof(data, "No valid port number in connect to host string (%s)\n", host_portno);
        hostptr = NULL;
        port = -1;
      }
      else port = (int)portparse;
    }
  }

  
  if(hostptr) {
    *hostname_result = strdup(hostptr);
    if(!*hostname_result) {
      free(host_dup);
      return CURLE_OUT_OF_MEMORY;
    }
  }

  *port_result = port;

  free(host_dup);
  return CURLE_OK;
}


static CURLcode parse_connect_to_string(struct Curl_easy *data, struct connectdata *conn, const char *conn_to_host, char **host_result, int *port_result)



{
  CURLcode result = CURLE_OK;
  const char *ptr = conn_to_host;
  int host_match = FALSE;
  int port_match = FALSE;

  *host_result = NULL;
  *port_result = -1;

  if(*ptr == ':') {
    
    host_match = TRUE;
    ptr++;
  }
  else {
    
    size_t hostname_to_match_len;
    char *hostname_to_match = aprintf("%s%s%s", conn->bits.ipv6_ip ? "[" : "", conn->host.name, conn->bits.ipv6_ip ? "]" : "");


    if(!hostname_to_match)
      return CURLE_OUT_OF_MEMORY;
    hostname_to_match_len = strlen(hostname_to_match);
    host_match = strncasecompare(ptr, hostname_to_match, hostname_to_match_len);
    free(hostname_to_match);
    ptr += hostname_to_match_len;

    host_match = host_match && *ptr == ':';
    ptr++;
  }

  if(host_match) {
    if(*ptr == ':') {
      
      port_match = TRUE;
      ptr++;
    }
    else {
      
      char *ptr_next = strchr(ptr, ':');
      if(ptr_next) {
        char *endp = NULL;
        long port_to_match = strtol(ptr, &endp, 10);
        if((endp == ptr_next) && (port_to_match == conn->remote_port)) {
          port_match = TRUE;
          ptr = ptr_next + 1;
        }
      }
    }
  }

  if(host_match && port_match) {
    
    result = parse_connect_to_host_port(data, ptr, host_result, port_result);
  }

  return result;
}


static CURLcode parse_connect_to_slist(struct Curl_easy *data, struct connectdata *conn, struct curl_slist *conn_to_host)

{
  CURLcode result = CURLE_OK;
  char *host = NULL;
  int port = -1;

  while(conn_to_host && !host && port == -1) {
    result = parse_connect_to_string(data, conn, conn_to_host->data, &host, &port);
    if(result)
      return result;

    if(host && *host) {
      conn->conn_to_host.rawalloc = host;
      conn->conn_to_host.name = host;
      conn->bits.conn_to_host = TRUE;

      infof(data, "Connecting to hostname: %s\n", host);
    }
    else {
      
      conn->bits.conn_to_host = FALSE;
      Curl_safefree(host);
    }

    if(port >= 0) {
      conn->conn_to_port = port;
      conn->bits.conn_to_port = TRUE;
      infof(data, "Connecting to port: %d\n", port);
    }
    else {
      
      conn->bits.conn_to_port = FALSE;
      port = -1;
    }

    conn_to_host = conn_to_host->next;
  }

  return result;
}


static CURLcode resolve_server(struct Curl_easy *data, struct connectdata *conn, bool *async)

{
  CURLcode result=CURLE_OK;
  time_t timeout_ms = Curl_timeleft(data, NULL, TRUE);

  
  if(conn->bits.reuse)
    
    *async = FALSE;

  else {
    
    int rc;
    struct Curl_dns_entry *hostaddr;


    if(conn->unix_domain_socket) {
      
      const char *path = conn->unix_domain_socket;

      hostaddr = calloc(1, sizeof(struct Curl_dns_entry));
      if(!hostaddr)
        result = CURLE_OUT_OF_MEMORY;
      else {
        bool longpath = FALSE;
        hostaddr->addr = Curl_unix2addr(path, &longpath, conn->abstract_unix_socket);
        if(hostaddr->addr)
          hostaddr->inuse++;
        else {
          
          if(longpath) {
            failf(data, "Unix socket path too long: '%s'", path);
            result = CURLE_COULDNT_RESOLVE_HOST;
          }
          else result = CURLE_OUT_OF_MEMORY;
          free(hostaddr);
          hostaddr = NULL;
        }
      }
    }
    else  if(!conn->bits.proxy) {

      struct hostname *connhost;
      if(conn->bits.conn_to_host)
        connhost = &conn->conn_to_host;
      else connhost = &conn->host;

      
      if(conn->bits.conn_to_port)
        conn->port = conn->conn_to_port;
      else conn->port = conn->remote_port;

      
      rc = Curl_resolv_timeout(conn, connhost->name, (int)conn->port, &hostaddr, timeout_ms);
      if(rc == CURLRESOLV_PENDING)
        *async = TRUE;

      else if(rc == CURLRESOLV_TIMEDOUT)
        result = CURLE_OPERATION_TIMEDOUT;

      else if(!hostaddr) {
        failf(data, "Couldn't resolve host '%s'", connhost->dispname);
        result =  CURLE_COULDNT_RESOLVE_HOST;
        
      }
    }
    else {
      

      struct hostname * const host = conn->bits.socksproxy ? &conn->socks_proxy.host : &conn->http_proxy.host;

      
      rc = Curl_resolv_timeout(conn, host->name, (int)conn->port, &hostaddr, timeout_ms);

      if(rc == CURLRESOLV_PENDING)
        *async = TRUE;

      else if(rc == CURLRESOLV_TIMEDOUT)
        result = CURLE_OPERATION_TIMEDOUT;

      else if(!hostaddr) {
        failf(data, "Couldn't resolve proxy '%s'", host->dispname);
        result = CURLE_COULDNT_RESOLVE_PROXY;
        
      }
    }
    DEBUGASSERT(conn->dns_entry == NULL);
    conn->dns_entry = hostaddr;
  }

  return result;
}


static void reuse_conn(struct connectdata *old_conn, struct connectdata *conn)
{
  free_fixed_hostname(&old_conn->http_proxy.host);
  free_fixed_hostname(&old_conn->socks_proxy.host);

  free(old_conn->http_proxy.host.rawalloc);
  free(old_conn->socks_proxy.host.rawalloc);

  
  Curl_free_primary_ssl_config(&old_conn->ssl_config);
  Curl_free_primary_ssl_config(&old_conn->proxy_ssl_config);

  conn->data = old_conn->data;

  
  conn->bits.user_passwd = old_conn->bits.user_passwd;
  if(conn->bits.user_passwd) {
    
    Curl_safefree(conn->user);
    Curl_safefree(conn->passwd);
    conn->user = old_conn->user;
    conn->passwd = old_conn->passwd;
    old_conn->user = NULL;
    old_conn->passwd = NULL;
  }

  conn->bits.proxy_user_passwd = old_conn->bits.proxy_user_passwd;
  if(conn->bits.proxy_user_passwd) {
    
    Curl_safefree(conn->http_proxy.user);
    Curl_safefree(conn->socks_proxy.user);
    Curl_safefree(conn->http_proxy.passwd);
    Curl_safefree(conn->socks_proxy.passwd);
    conn->http_proxy.user = old_conn->http_proxy.user;
    conn->socks_proxy.user = old_conn->socks_proxy.user;
    conn->http_proxy.passwd = old_conn->http_proxy.passwd;
    conn->socks_proxy.passwd = old_conn->socks_proxy.passwd;
    old_conn->http_proxy.user = NULL;
    old_conn->socks_proxy.user = NULL;
    old_conn->http_proxy.passwd = NULL;
    old_conn->socks_proxy.passwd = NULL;
  }

  
  free_fixed_hostname(&conn->host);
  free_fixed_hostname(&conn->conn_to_host);
  Curl_safefree(conn->host.rawalloc);
  Curl_safefree(conn->conn_to_host.rawalloc);
  conn->host=old_conn->host;
  conn->bits.conn_to_host = old_conn->bits.conn_to_host;
  conn->conn_to_host = old_conn->conn_to_host;
  conn->bits.conn_to_port = old_conn->bits.conn_to_port;
  conn->conn_to_port = old_conn->conn_to_port;

  
  Curl_persistconninfo(conn);

  conn_reset_all_postponed_data(old_conn); 

  
  conn->bits.reuse = TRUE; 

  Curl_safefree(old_conn->user);
  Curl_safefree(old_conn->passwd);
  Curl_safefree(old_conn->http_proxy.user);
  Curl_safefree(old_conn->socks_proxy.user);
  Curl_safefree(old_conn->http_proxy.passwd);
  Curl_safefree(old_conn->socks_proxy.passwd);
  Curl_safefree(old_conn->localdev);

  Curl_llist_destroy(&old_conn->send_pipe, NULL);
  Curl_llist_destroy(&old_conn->recv_pipe, NULL);

  Curl_safefree(old_conn->master_buffer);


  Curl_safefree(old_conn->unix_domain_socket);

}



static CURLcode create_conn(struct Curl_easy *data, struct connectdata **in_connect, bool *async)

{
  CURLcode result = CURLE_OK;
  struct connectdata *conn;
  struct connectdata *conn_temp = NULL;
  size_t urllen;
  char *user = NULL;
  char *passwd = NULL;
  char *options = NULL;
  bool reuse;
  bool prot_missing = FALSE;
  bool connections_available = TRUE;
  bool force_reuse = FALSE;
  bool waitpipe = FALSE;
  size_t max_host_connections = Curl_multi_max_host_connections(data->multi);
  size_t max_total_connections = Curl_multi_max_total_connections(data->multi);

  *async = FALSE;

  

  if(!data->change.url) {
    result = CURLE_URL_MALFORMAT;
    goto out;
  }

  
  conn = allocate_conn(data);

  if(!conn) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  
  *in_connect = conn;

  

  

  urllen=strlen(data->change.url);
  if(urllen < LEAST_PATH_ALLOC)
    urllen=LEAST_PATH_ALLOC;

  

  Curl_safefree(data->state.pathbuffer);
  data->state.path = NULL;

  data->state.pathbuffer = malloc(urllen+2);
  if(NULL == data->state.pathbuffer) {
    result = CURLE_OUT_OF_MEMORY; 
    goto out;
  }
  data->state.path = data->state.pathbuffer;

  conn->host.rawalloc = malloc(urllen+2);
  if(NULL == conn->host.rawalloc) {
    Curl_safefree(data->state.pathbuffer);
    data->state.path = NULL;
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  conn->host.name = conn->host.rawalloc;
  conn->host.name[0] = 0;

  user = strdup("");
  passwd = strdup("");
  options = strdup("");
  if(!user || !passwd || !options) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  result = parseurlandfillconn(data, conn, &prot_missing, &user, &passwd, &options);
  if(result)
    goto out;

  
  if(prot_missing) {
    
    char *reurl;
    char *ch_lower;

    reurl = aprintf("%s://%s", conn->handler->scheme, data->change.url);

    if(!reurl) {
      result = CURLE_OUT_OF_MEMORY;
      goto out;
    }

    
    for(ch_lower = reurl; *ch_lower != ':'; ch_lower++)
      *ch_lower = (char)TOLOWER(*ch_lower);

    if(data->change.url_alloc) {
      Curl_safefree(data->change.url);
      data->change.url_alloc = FALSE;
    }

    data->change.url = reurl;
    data->change.url_alloc = TRUE; 
  }

  
  if((conn->given->flags&PROTOPT_NOURLQUERY)) {
    char *path_q_sep = strchr(conn->data->state.path, '?');
    if(path_q_sep) {
      

      
      path_q_sep[0] = 0;
    }
  }

  if(data->set.str[STRING_BEARER]) {
    conn->oauth_bearer = strdup(data->set.str[STRING_BEARER]);
    if(!conn->oauth_bearer) {
      result = CURLE_OUT_OF_MEMORY;
      goto out;
    }
  }


  if(data->set.str[STRING_UNIX_SOCKET_PATH]) {
    conn->unix_domain_socket = strdup(data->set.str[STRING_UNIX_SOCKET_PATH]);
    if(conn->unix_domain_socket == NULL) {
      result = CURLE_OUT_OF_MEMORY;
      goto out;
    }
    conn->abstract_unix_socket = data->set.abstract_unix_socket;
  }


  

  result = create_conn_helper_init_proxy(conn);
  if(result)
    goto out;


  
  if((conn->given->flags&PROTOPT_SSL) && conn->bits.httpproxy)
    conn->bits.tunnel_proxy = TRUE;

  
  result = parse_remote_port(data, conn);
  if(result)
    goto out;

  
  result = override_login(data, conn, &user, &passwd, &options);
  if(result)
    goto out;
  result = set_login(conn, user, passwd, options);
  if(result)
    goto out;

  
  result = parse_connect_to_slist(data, conn, data->set.connect_to);
  if(result)
    goto out;

  
  fix_hostname(conn, &conn->host);
  if(conn->bits.conn_to_host)
    fix_hostname(conn, &conn->conn_to_host);
  if(conn->bits.httpproxy)
    fix_hostname(conn, &conn->http_proxy.host);
  if(conn->bits.socksproxy)
    fix_hostname(conn, &conn->socks_proxy.host);

  
  if(conn->bits.conn_to_host && strcasecompare(conn->conn_to_host.name, conn->host.name)) {
    conn->bits.conn_to_host = FALSE;
  }

  
  if(conn->bits.conn_to_port && conn->conn_to_port == conn->remote_port) {
    conn->bits.conn_to_port = FALSE;
  }

  
  if((conn->bits.conn_to_host || conn->bits.conn_to_port) && conn->bits.httpproxy)
    conn->bits.tunnel_proxy = TRUE;

  
  result = setup_connection_internals(conn);
  if(result)
    goto out;

  conn->recv[FIRSTSOCKET] = Curl_recv_plain;
  conn->send[FIRSTSOCKET] = Curl_send_plain;
  conn->recv[SECONDARYSOCKET] = Curl_recv_plain;
  conn->send[SECONDARYSOCKET] = Curl_send_plain;

  conn->bits.tcp_fastopen = data->set.tcp_fastopen;

  

  if(conn->handler->flags & PROTOPT_NONETWORK) {
    bool done;
    
    DEBUGASSERT(conn->handler->connect_it);
    result = conn->handler->connect_it(conn, &done);

    
    if(!result) {
      conn->data = data;
      conn->bits.tcpconnect[FIRSTSOCKET] = TRUE; 

      Curl_conncache_add_conn(data->state.conn_cache, conn);

      
      result = setup_range(data);
      if(result) {
        DEBUGASSERT(conn->handler->done);
        
        (void)conn->handler->done(conn, result, FALSE);
        goto out;
      }

      Curl_setup_transfer(conn, -1, -1, FALSE, NULL,  -1, NULL);
    }

    
    Curl_init_do(data, conn);

    goto out;
  }


  
  data->set.ssl.primary.CApath = data->set.str[STRING_SSL_CAPATH_ORIG];
  data->set.proxy_ssl.primary.CApath = data->set.str[STRING_SSL_CAPATH_PROXY];
  data->set.ssl.primary.CAfile = data->set.str[STRING_SSL_CAFILE_ORIG];
  data->set.proxy_ssl.primary.CAfile = data->set.str[STRING_SSL_CAFILE_PROXY];
  data->set.ssl.primary.random_file = data->set.str[STRING_SSL_RANDOM_FILE];
  data->set.proxy_ssl.primary.random_file = data->set.str[STRING_SSL_RANDOM_FILE];
  data->set.ssl.primary.egdsocket = data->set.str[STRING_SSL_EGDSOCKET];
  data->set.proxy_ssl.primary.egdsocket = data->set.str[STRING_SSL_EGDSOCKET];
  data->set.ssl.primary.cipher_list = data->set.str[STRING_SSL_CIPHER_LIST_ORIG];
  data->set.proxy_ssl.primary.cipher_list = data->set.str[STRING_SSL_CIPHER_LIST_PROXY];

  data->set.ssl.CRLfile = data->set.str[STRING_SSL_CRLFILE_ORIG];
  data->set.proxy_ssl.CRLfile = data->set.str[STRING_SSL_CRLFILE_PROXY];
  data->set.ssl.issuercert = data->set.str[STRING_SSL_ISSUERCERT_ORIG];
  data->set.proxy_ssl.issuercert = data->set.str[STRING_SSL_ISSUERCERT_PROXY];
  data->set.ssl.cert = data->set.str[STRING_CERT_ORIG];
  data->set.proxy_ssl.cert = data->set.str[STRING_CERT_PROXY];
  data->set.ssl.cert_type = data->set.str[STRING_CERT_TYPE_ORIG];
  data->set.proxy_ssl.cert_type = data->set.str[STRING_CERT_TYPE_PROXY];
  data->set.ssl.key = data->set.str[STRING_KEY_ORIG];
  data->set.proxy_ssl.key = data->set.str[STRING_KEY_PROXY];
  data->set.ssl.key_type = data->set.str[STRING_KEY_TYPE_ORIG];
  data->set.proxy_ssl.key_type = data->set.str[STRING_KEY_TYPE_PROXY];
  data->set.ssl.key_passwd = data->set.str[STRING_KEY_PASSWD_ORIG];
  data->set.proxy_ssl.key_passwd = data->set.str[STRING_KEY_PASSWD_PROXY];
  data->set.ssl.primary.clientcert = data->set.str[STRING_CERT_ORIG];
  data->set.proxy_ssl.primary.clientcert = data->set.str[STRING_CERT_PROXY];

  data->set.ssl.username = data->set.str[STRING_TLSAUTH_USERNAME_ORIG];
  data->set.proxy_ssl.username = data->set.str[STRING_TLSAUTH_USERNAME_PROXY];
  data->set.ssl.password = data->set.str[STRING_TLSAUTH_PASSWORD_ORIG];
  data->set.proxy_ssl.password = data->set.str[STRING_TLSAUTH_PASSWORD_PROXY];


  if(!Curl_clone_primary_ssl_config(&data->set.ssl.primary, &conn->ssl_config)) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  if(!Curl_clone_primary_ssl_config(&data->set.proxy_ssl.primary, &conn->proxy_ssl_config)) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  prune_dead_connections(data);

  

  
  if(data->set.reuse_fresh && !data->state.this_is_a_follow)
    reuse = FALSE;
  else reuse = ConnectionExists(data, conn, &conn_temp, &force_reuse, &waitpipe);

  
  if(reuse && !force_reuse && IsPipeliningPossible(data, conn_temp)) {
    size_t pipelen = conn_temp->send_pipe.size + conn_temp->recv_pipe.size;
    if(pipelen > 0) {
      infof(data, "Found connection %ld, with requests in the pipe (%zu)\n", conn_temp->connection_id, pipelen);

      if(conn_temp->bundle->num_connections < max_host_connections && data->state.conn_cache->num_connections < max_total_connections) {
        
        reuse = FALSE;

        infof(data, "We can reuse, but we want a new connection anyway\n");
      }
    }
  }

  if(reuse) {
    
    conn_temp->inuse = TRUE; 
    reuse_conn(conn, conn_temp);
    free(conn);          
    conn = conn_temp;
    *in_connect = conn;

    infof(data, "Re-using existing connection! (#%ld) with %s %s\n", conn->connection_id, conn->bits.proxy?"proxy":"host", conn->socks_proxy.host.name ? conn->socks_proxy.host.dispname :


          conn->http_proxy.host.name ? conn->http_proxy.host.dispname :
                                       conn->host.dispname);
  }
  else {
    
    struct connectbundle *bundle = NULL;

    if(conn->handler->flags & PROTOPT_ALPN_NPN) {
      
      if(data->set.ssl_enable_alpn)
        conn->bits.tls_enable_alpn = TRUE;
      if(data->set.ssl_enable_npn)
        conn->bits.tls_enable_npn = TRUE;
    }

    if(waitpipe)
      
      connections_available = FALSE;
    else bundle = Curl_conncache_find_bundle(conn, data->state.conn_cache);

    if(max_host_connections > 0 && bundle && (bundle->num_connections >= max_host_connections)) {
      struct connectdata *conn_candidate;

      
      conn_candidate = find_oldest_idle_connection_in_bundle(data, bundle);

      if(conn_candidate) {
        
        conn_candidate->data = data;
        (void)Curl_disconnect(conn_candidate,  FALSE);
      }
      else {
        infof(data, "No more connections allowed to host: %d\n", max_host_connections);
        connections_available = FALSE;
      }
    }

    if(connections_available && (max_total_connections > 0) && (data->state.conn_cache->num_connections >= max_total_connections)) {

      struct connectdata *conn_candidate;

      
      conn_candidate = Curl_oldest_idle_connection(data);

      if(conn_candidate) {
        
        conn_candidate->data = data;
        (void)Curl_disconnect(conn_candidate,  FALSE);
      }
      else {
        infof(data, "No connections available in cache\n");
        connections_available = FALSE;
      }
    }

    if(!connections_available) {
      infof(data, "No connections available.\n");

      conn_free(conn);
      *in_connect = NULL;

      result = CURLE_NO_CONNECTION_AVAILABLE;
      goto out;
    }
    else {
      
      Curl_conncache_add_conn(data->state.conn_cache, conn);
    }


    
    if((data->state.authhost.picked & (CURLAUTH_NTLM | CURLAUTH_NTLM_WB)) && data->state.authhost.done) {
      infof(data, "NTLM picked AND auth done set, clear picked!\n");
      data->state.authhost.picked = CURLAUTH_NONE;
      data->state.authhost.done = FALSE;
    }

    if((data->state.authproxy.picked & (CURLAUTH_NTLM | CURLAUTH_NTLM_WB)) && data->state.authproxy.done) {
      infof(data, "NTLM-proxy picked AND auth done set, clear picked!\n");
      data->state.authproxy.picked = CURLAUTH_NONE;
      data->state.authproxy.done = FALSE;
    }

  }

  
  conn->inuse = TRUE;

  
  Curl_init_do(data, conn);

  
  result = setup_range(data);
  if(result)
    goto out;

  

  
  conn->seek_func = data->set.seek_func;
  conn->seek_client = data->set.seek_client;

  
  result = resolve_server(data, conn, async);

out:

  free(options);
  free(passwd);
  free(user);
  return result;
}



CURLcode Curl_setup_conn(struct connectdata *conn, bool *protocol_done)
{
  CURLcode result = CURLE_OK;
  struct Curl_easy *data = conn->data;

  Curl_pgrsTime(data, TIMER_NAMELOOKUP);

  if(conn->handler->flags & PROTOPT_NONETWORK) {
    
    *protocol_done = TRUE;
    return result;
  }
  *protocol_done = FALSE; 

  
  conn->bits.proxy_connect_closed = FALSE;

  
  if(data->set.str[STRING_USERAGENT]) {
    Curl_safefree(conn->allocptr.uagent);
    conn->allocptr.uagent = aprintf("User-Agent: %s\r\n", data->set.str[STRING_USERAGENT]);
    if(!conn->allocptr.uagent)
      return CURLE_OUT_OF_MEMORY;
  }

  data->req.headerbytecount = 0;


  data->state.crlf_conversions = 0; 


  
  conn->now = Curl_tvnow();

  if(CURL_SOCKET_BAD == conn->sock[FIRSTSOCKET]) {
    conn->bits.tcpconnect[FIRSTSOCKET] = FALSE;
    result = Curl_connecthost(conn, conn->dns_entry);
    if(result)
      return result;
  }
  else {
    Curl_pgrsTime(data, TIMER_CONNECT);    
    Curl_pgrsTime(data, TIMER_APPCONNECT); 
    conn->bits.tcpconnect[FIRSTSOCKET] = TRUE;
    *protocol_done = TRUE;
    Curl_updateconninfo(conn, conn->sock[FIRSTSOCKET]);
    Curl_verboseconnect(conn);
  }

  conn->now = Curl_tvnow(); 


  

  if((data->set.out)->_handle == NULL) {
    _fsetmode(stdout, "b");
  }


  return result;
}

CURLcode Curl_connect(struct Curl_easy *data, struct connectdata **in_connect, bool *asyncp, bool *protocol_done)


{
  CURLcode result;

  *asyncp = FALSE; 

  
  result = create_conn(data, in_connect, asyncp);

  if(!result) {
    
    if((*in_connect)->send_pipe.size || (*in_connect)->recv_pipe.size)
      
      *protocol_done = TRUE;
    else if(!*asyncp) {
      
      result = Curl_setup_conn(*in_connect, protocol_done);
    }
  }

  if(result == CURLE_NO_CONNECTION_AVAILABLE) {
    *in_connect = NULL;
    return result;
  }

  if(result && *in_connect) {
    
    Curl_disconnect(*in_connect, FALSE); 
    *in_connect = NULL;           
  }

  return result;
}



CURLcode Curl_init_do(struct Curl_easy *data, struct connectdata *conn)
{
  struct SingleRequest *k = &data->req;

  if(conn)
    conn->bits.do_more = FALSE; 

  data->state.done = FALSE; 
  data->state.expect100header = FALSE;

  if(data->set.opt_no_body)
    
    data->set.httpreq = HTTPREQ_HEAD;
  else if(HTTPREQ_HEAD == data->set.httpreq)
    
    data->set.httpreq = HTTPREQ_GET;

  k->start = Curl_tvnow(); 
  k->now = k->start;   
  k->header = TRUE; 

  k->bytecount = 0;

  k->buf = data->state.buffer;
  k->uploadbuf = data->state.uploadbuffer;
  k->hbufp = data->state.headerbuff;
  k->ignorebody=FALSE;

  Curl_speedinit(data);

  Curl_pgrsSetUploadCounter(data, 0);
  Curl_pgrsSetDownloadCounter(data, 0);

  return CURLE_OK;
}



unsigned int get_protocol_family(unsigned int protocol)
{
  unsigned int family;

  switch(protocol) {
  case CURLPROTO_HTTP:
  case CURLPROTO_HTTPS:
    family = CURLPROTO_HTTP;
    break;

  case CURLPROTO_FTP:
  case CURLPROTO_FTPS:
    family = CURLPROTO_FTP;
    break;

  case CURLPROTO_SCP:
    family = CURLPROTO_SCP;
    break;

  case CURLPROTO_SFTP:
    family = CURLPROTO_SFTP;
    break;

  case CURLPROTO_TELNET:
    family = CURLPROTO_TELNET;
    break;

  case CURLPROTO_LDAP:
  case CURLPROTO_LDAPS:
    family = CURLPROTO_LDAP;
    break;

  case CURLPROTO_DICT:
    family = CURLPROTO_DICT;
    break;

  case CURLPROTO_FILE:
    family = CURLPROTO_FILE;
    break;

  case CURLPROTO_TFTP:
    family = CURLPROTO_TFTP;
    break;

  case CURLPROTO_IMAP:
  case CURLPROTO_IMAPS:
    family = CURLPROTO_IMAP;
    break;

  case CURLPROTO_POP3:
  case CURLPROTO_POP3S:
    family = CURLPROTO_POP3;
    break;

  case CURLPROTO_SMTP:
  case CURLPROTO_SMTPS:
      family = CURLPROTO_SMTP;
      break;

  case CURLPROTO_RTSP:
    family = CURLPROTO_RTSP;
    break;

  case CURLPROTO_RTMP:
  case CURLPROTO_RTMPS:
    family = CURLPROTO_RTMP;
    break;

  case CURLPROTO_RTMPT:
  case CURLPROTO_RTMPTS:
    family = CURLPROTO_RTMPT;
    break;

  case CURLPROTO_RTMPE:
    family = CURLPROTO_RTMPE;
    break;

  case CURLPROTO_RTMPTE:
    family = CURLPROTO_RTMPTE;
    break;

  case CURLPROTO_GOPHER:
    family = CURLPROTO_GOPHER;
    break;

  case CURLPROTO_SMB:
  case CURLPROTO_SMBS:
    family = CURLPROTO_SMB;
    break;

  default:
      family = 0;
      break;
  }

  return family;
}
