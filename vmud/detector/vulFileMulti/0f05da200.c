





























static void freecookie(struct Cookie *co)
{
  free(co->expirestr);
  free(co->domain);
  free(co->path);
  free(co->spath);
  free(co->name);
  free(co->value);
  free(co->maxage);
  free(co->version);
  free(co);
}

static bool tailmatch(const char *cooke_domain, const char *hostname)
{
  size_t cookie_domain_len = strlen(cooke_domain);
  size_t hostname_len = strlen(hostname);

  if(hostname_len < cookie_domain_len)
    return FALSE;

  if(!Curl_raw_equal(cooke_domain, hostname+hostname_len-cookie_domain_len))
    return FALSE;

  
  if(hostname_len == cookie_domain_len)
    return TRUE;
  if('.' == *(hostname + hostname_len - cookie_domain_len - 1))
    return TRUE;
  return FALSE;
}


static bool pathmatch(const char* cookie_path, const char* request_uri)
{
  size_t cookie_path_len;
  size_t uri_path_len;
  char* uri_path = NULL;
  char* pos;
  bool ret = FALSE;

  
  cookie_path_len = strlen(cookie_path);
  if(1 == cookie_path_len) {
    
    return TRUE;
  }

  uri_path = strdup(request_uri);
  if(!uri_path)
    return FALSE;
  pos = strchr(uri_path, '?');
  if(pos)
    *pos = 0x0;

  
  if(0 == strlen(uri_path) || uri_path[0] != '/') {
    free(uri_path);
    uri_path = strdup("/");
    if(!uri_path)
      return FALSE;
  }

  

  uri_path_len = strlen(uri_path);

  if(uri_path_len < cookie_path_len) {
    ret = FALSE;
    goto pathmatched;
  }

  
  if(strncmp(cookie_path, uri_path, cookie_path_len)) {
    ret = FALSE;
    goto pathmatched;
  }

  
  if(cookie_path_len == uri_path_len) {
    ret = TRUE;
    goto pathmatched;
  }

  
  if(uri_path[cookie_path_len] == '/') {
    ret = TRUE;
    goto pathmatched;
  }

  ret = FALSE;

pathmatched:
  free(uri_path);
  return ret;
}


static char *sanitize_cookie_path(const char *cookie_path)
{
  size_t len;
  char *new_path = strdup(cookie_path);
  if(!new_path)
    return NULL;

  
  len = strlen(new_path);
  if(new_path[0] == '\"') {
    memmove((void *)new_path, (const void *)(new_path + 1), len);
    len--;
  }
  if(len && (new_path[len - 1] == '\"')) {
    new_path[len - 1] = 0x0;
    len--;
  }

  
  if(new_path[0] != '/') {
    
    free(new_path);
    new_path = strdup("/");
    return new_path;
  }

  
  if(len && new_path[len - 1] == '/') {
    new_path[len - 1] = 0x0;
  }

  return new_path;
}


void Curl_cookie_loadfiles(struct Curl_easy *data)
{
  struct curl_slist *list = data->change.cookielist;
  if(list) {
    Curl_share_lock(data, CURL_LOCK_DATA_COOKIE, CURL_LOCK_ACCESS_SINGLE);
    while(list) {
      struct CookieInfo *newcookies = Curl_cookie_init(data, list->data, data->cookies, data->set.cookiesession);


      if(!newcookies)
        
        infof(data, "ignoring failed cookie_init for %s\n", list->data);
      else data->cookies = newcookies;
      list = list->next;
    }
    curl_slist_free_all(data->change.cookielist); 
    data->change.cookielist = NULL; 
    Curl_share_unlock(data, CURL_LOCK_DATA_COOKIE);
  }
}


static void strstore(char **str, const char *newstr)
{
  free(*str);
  *str = strdup(newstr);
}


static void remove_expired(struct CookieInfo *cookies)
{
  struct Cookie *co, *nx, *pv;
  curl_off_t now = (curl_off_t)time(NULL);

  co = cookies->cookies;
  pv = NULL;
  while(co) {
    nx = co->next;
    if(co->expires && co->expires < now) {
      if(co == cookies->cookies) {
        cookies->cookies = co->next;
      }
      else {
        pv->next = co->next;
      }
      cookies->numcookies--;
      freecookie(co);
    }
    else {
      pv = co;
    }
    co = nx;
  }
}


static bool isip(const char *domain)
{
  struct in_addr addr;

  struct in6_addr addr6;


  if(Curl_inet_pton(AF_INET, domain, &addr)

     || Curl_inet_pton(AF_INET6, domain, &addr6)

    ) {
    
    return TRUE;
  }

  return FALSE;
}



struct Cookie * Curl_cookie_add(struct Curl_easy *data,   struct CookieInfo *c, bool httpheader, char *lineptr, const char *domain, const char *path)







{
  struct Cookie *clist;
  char name[MAX_NAME];
  struct Cookie *co;
  struct Cookie *lastc=NULL;
  time_t now = time(NULL);
  bool replace_old = FALSE;
  bool badcookie = FALSE; 


  const psl_ctx_t *psl;



  (void)data;


  
  co = calloc(1, sizeof(struct Cookie));
  if(!co)
    return NULL; 

  if(httpheader) {
    
    const char *ptr;
    const char *semiptr;
    char *what;

    what = malloc(MAX_COOKIE_LINE);
    if(!what) {
      free(co);
      return NULL;
    }

    semiptr=strchr(lineptr, ';'); 

    while(*lineptr && ISBLANK(*lineptr))
      lineptr++;

    ptr = lineptr;
    do {
      
      name[0]=what[0]=0; 
      if(1 <= sscanf(ptr, "%" MAX_NAME_TXT "[^;\r\n=] =%" MAX_COOKIE_LINE_TXT "[^;\r\n]", name, what)) {

        
        const char *whatptr;
        bool done = FALSE;
        bool sep;
        size_t len=strlen(what);
        size_t nlen = strlen(name);
        const char *endofn = &ptr[ nlen ];

        
        sep = (*endofn == '=')?TRUE:FALSE;

        if(nlen) {
          endofn--; 
          if(ISBLANK(*endofn)) {
            
            while(*endofn && ISBLANK(*endofn) && nlen) {
              endofn--;
              nlen--;
            }
            name[nlen]=0; 
          }
        }

        
        while(len && ISBLANK(what[len-1])) {
          what[len-1]=0;
          len--;
        }

        
        whatptr=what;
        while(*whatptr && ISBLANK(*whatptr))
          whatptr++;

        if(!co->name && sep) {
          
          co->name = strdup(name);
          co->value = strdup(whatptr);
          if(!co->name || !co->value) {
            badcookie = TRUE;
            break;
          }
        }
        else if(!len) {
          
          done = TRUE;
          if(Curl_raw_equal("secure", name))
            co->secure = TRUE;
          else if(Curl_raw_equal("httponly", name))
            co->httponly = TRUE;
          else if(sep)
            
            done = FALSE;
        }
        if(done)
          ;
        else if(Curl_raw_equal("path", name)) {
          strstore(&co->path, whatptr);
          if(!co->path) {
            badcookie = TRUE; 
            break;
          }
          co->spath = sanitize_cookie_path(co->path);
          if(!co->spath) {
            badcookie = TRUE; 
            break;
          }
        }
        else if(Curl_raw_equal("domain", name)) {
          bool is_ip;
          const char *dotp;

          

          if('.' == whatptr[0])
            whatptr++; 

          is_ip = isip(domain ? domain : whatptr);

          
          dotp = strchr(whatptr, '.');
          if(!dotp)
            domain=":";

          if(!domain || (is_ip && !strcmp(whatptr, domain))
             || (!is_ip && tailmatch(whatptr, domain))) {
            strstore(&co->domain, whatptr);
            if(!co->domain) {
              badcookie = TRUE;
              break;
            }
            if(!is_ip)
              co->tailmatch=TRUE; 
          }
          else {
            
            badcookie=TRUE;
            infof(data, "skipped cookie with bad tailmatch domain: %s\n", whatptr);
          }
        }
        else if(Curl_raw_equal("version", name)) {
          strstore(&co->version, whatptr);
          if(!co->version) {
            badcookie = TRUE;
            break;
          }
        }
        else if(Curl_raw_equal("max-age", name)) {
          
          strstore(&co->maxage, whatptr);
          if(!co->maxage) {
            badcookie = TRUE;
            break;
          }
        }
        else if(Curl_raw_equal("expires", name)) {
          strstore(&co->expirestr, whatptr);
          if(!co->expirestr) {
            badcookie = TRUE;
            break;
          }
        }
        
      }
      else {
        
      }

      if(!semiptr || !*semiptr) {
        
        semiptr = NULL;
        continue;
      }

      ptr=semiptr+1;
      while(*ptr && ISBLANK(*ptr))
        ptr++;
      semiptr=strchr(ptr, ';'); 

      if(!semiptr && *ptr)
        
        semiptr=strchr(ptr, '\0');
    } while(semiptr);

    if(co->maxage) {
      co->expires = curlx_strtoofft((*co->maxage=='\"')? &co->maxage[1]:&co->maxage[0], NULL, 10);

      if(CURL_OFF_T_MAX - now < co->expires)
        
        co->expires = CURL_OFF_T_MAX;
      else co->expires += now;
    }
    else if(co->expirestr) {
      
      co->expires = curl_getdate(co->expirestr, NULL);

      
      if(co->expires == 0)
        co->expires = 1;
      else if(co->expires < 0)
        co->expires = 0;
    }

    if(!badcookie && !co->domain) {
      if(domain) {
        
        co->domain=strdup(domain);
        if(!co->domain)
          badcookie = TRUE;
      }
    }

    if(!badcookie && !co->path && path) {
      
      char *queryp = strchr(path, '?');

      
      char *endslash;
      if(!queryp)
        endslash = strrchr(path, '/');
      else endslash = memrchr(path, '/', (size_t)(queryp - path));
      if(endslash) {
        size_t pathlen = (size_t)(endslash-path+1); 
        co->path=malloc(pathlen+1); 
        if(co->path) {
          memcpy(co->path, path, pathlen);
          co->path[pathlen]=0; 
          co->spath = sanitize_cookie_path(co->path);
          if(!co->spath)
            badcookie = TRUE; 
        }
        else badcookie = TRUE;
      }
    }

    free(what);

    if(badcookie || !co->name) {
      
      freecookie(co);
      return NULL;
    }

  }
  else {
    
    char *ptr;
    char *firstptr;
    char *tok_buf=NULL;
    int fields;

    
    if(strncmp(lineptr, "#HttpOnly_", 10) == 0) {
      lineptr += 10;
      co->httponly = TRUE;
    }

    if(lineptr[0]=='#') {
      
      free(co);
      return NULL;
    }
    
    ptr=strchr(lineptr, '\r');
    if(ptr)
      *ptr=0; 
    ptr=strchr(lineptr, '\n');
    if(ptr)
      *ptr=0; 

    firstptr=strtok_r(lineptr, "\t", &tok_buf); 

    
    for(ptr=firstptr, fields=0; ptr && !badcookie;
        ptr=strtok_r(NULL, "\t", &tok_buf), fields++) {
      switch(fields) {
      case 0:
        if(ptr[0]=='.') 
          ptr++;
        co->domain = strdup(ptr);
        if(!co->domain)
          badcookie = TRUE;
        break;
      case 1:
        
        co->tailmatch = Curl_raw_equal(ptr, "TRUE")?TRUE:FALSE;
        break;
      case 2:
        
        if(strcmp("TRUE", ptr) && strcmp("FALSE", ptr)) {
          
          co->path = strdup(ptr);
          if(!co->path)
            badcookie = TRUE;
          else {
            co->spath = sanitize_cookie_path(co->path);
            if(!co->spath) {
              badcookie = TRUE; 
            }
          }
          break;
        }
        
        co->path = strdup("/");
        if(!co->path)
          badcookie = TRUE;
        co->spath = strdup("/");
        if(!co->spath)
          badcookie = TRUE;
        fields++; 
        
      case 3:
        co->secure = Curl_raw_equal(ptr, "TRUE")?TRUE:FALSE;
        break;
      case 4:
        co->expires = curlx_strtoofft(ptr, NULL, 10);
        break;
      case 5:
        co->name = strdup(ptr);
        if(!co->name)
          badcookie = TRUE;
        break;
      case 6:
        co->value = strdup(ptr);
        if(!co->value)
          badcookie = TRUE;
        break;
      }
    }
    if(6 == fields) {
      
      co->value = strdup("");
      if(!co->value)
        badcookie = TRUE;
      else fields++;
    }

    if(!badcookie && (7 != fields))
      
      badcookie = TRUE;

    if(badcookie) {
      freecookie(co);
      return NULL;
    }

  }

  if(!c->running &&     c->newsession && !co->expires) {

    freecookie(co);
    return NULL;
  }

  co->livecookie = c->running;

  

  
  remove_expired(c);


  
  if(domain && co->domain && !isip(co->domain)) {
    if(((psl = psl_builtin()) != NULL)
        && !psl_is_cookie_domain_acceptable(psl, domain, co->domain)) {
      infof(data, "cookie '%s' dropped, domain '%s' must not set cookies for '%s'\n", co->name, domain, co->domain);

      freecookie(co);
      return NULL;
    }
  }


  clist = c->cookies;
  replace_old = FALSE;
  while(clist) {
    if(Curl_raw_equal(clist->name, co->name)) {
      

      if(clist->domain && co->domain) {
        if(Curl_raw_equal(clist->domain, co->domain) && (clist->tailmatch == co->tailmatch))
          
          replace_old=TRUE;
      }
      else if(!clist->domain && !co->domain)
        replace_old = TRUE;

      if(replace_old) {
        

        if(clist->spath && co->spath) {
          if(Curl_raw_equal(clist->spath, co->spath)) {
            replace_old = TRUE;
          }
          else replace_old = FALSE;
        }
        else if(!clist->spath && !co->spath)
          replace_old = TRUE;
        else replace_old = FALSE;

      }

      if(replace_old && !co->livecookie && clist->livecookie) {
        

        
        freecookie(co);
        return NULL;
      }

      if(replace_old) {
        co->next = clist->next; 

        
        free(clist->name);
        free(clist->value);
        free(clist->domain);
        free(clist->path);
        free(clist->spath);
        free(clist->expirestr);
        free(clist->version);
        free(clist->maxage);

        *clist = *co;  

        free(co);   
        co = clist; 

        
        do {
          lastc = clist;
          clist = clist->next;
        } while(clist);
        break;
      }
    }
    lastc = clist;
    clist = clist->next;
  }

  if(c->running)
    
    infof(data, "%s cookie %s=\"%s\" for domain %s, path %s, " "expire %" CURL_FORMAT_CURL_OFF_T "\n", replace_old?"Replaced":"Added", co->name, co->value, co->domain, co->path, co->expires);



  if(!replace_old) {
    
    if(lastc)
      lastc->next = co;
    else c->cookies = co;
    c->numcookies++; 
  }

  return co;
}


struct CookieInfo *Curl_cookie_init(struct Curl_easy *data, const char *file, struct CookieInfo *inc, bool newsession)


{
  struct CookieInfo *c;
  FILE *fp = NULL;
  bool fromfile=TRUE;
  char *line = NULL;

  if(NULL == inc) {
    
    c = calloc(1, sizeof(struct CookieInfo));
    if(!c)
      return NULL; 
    c->filename = strdup(file?file:"none"); 
    if(!c->filename)
      goto fail; 
  }
  else {
    
    c = inc;
  }
  c->running = FALSE; 

  if(file && strequal(file, "-")) {
    fp = stdin;
    fromfile=FALSE;
  }
  else if(file && !*file) {
    
    fp = NULL;
  }
  else fp = file?fopen(file, FOPEN_READTEXT):NULL;

  c->newsession = newsession; 

  if(fp) {
    char *lineptr;
    bool headerline;

    line = malloc(MAX_COOKIE_LINE);
    if(!line)
      goto fail;
    while(fgets(line, MAX_COOKIE_LINE, fp)) {
      if(checkprefix("Set-Cookie:", line)) {
        
        lineptr=&line[11];
        headerline=TRUE;
      }
      else {
        lineptr=line;
        headerline=FALSE;
      }
      while(*lineptr && ISBLANK(*lineptr))
        lineptr++;

      Curl_cookie_add(data, c, headerline, lineptr, NULL, NULL);
    }
    free(line); 

    if(fromfile)
      fclose(fp);
  }

  c->running = TRUE;          

  return c;

fail:
  free(line);
  if(!inc)
    
    Curl_cookie_cleanup(c);
  if(fromfile && fp)
    fclose(fp);
  return NULL; 
}


static int cookie_sort(const void *p1, const void *p2)
{
  struct Cookie *c1 = *(struct Cookie **)p1;
  struct Cookie *c2 = *(struct Cookie **)p2;
  size_t l1, l2;

  
  l1 = c1->path ? strlen(c1->path) : 0;
  l2 = c2->path ? strlen(c2->path) : 0;

  if(l1 != l2)
    return (l2 > l1) ? 1 : -1 ; 

  
  l1 = c1->domain ? strlen(c1->domain) : 0;
  l2 = c2->domain ? strlen(c2->domain) : 0;

  if(l1 != l2)
    return (l2 > l1) ? 1 : -1 ;  

  
  if(c1->name && c2->name)
    return strcmp(c1->name, c2->name);

  
  return 0;
}



struct Cookie *Curl_cookie_getlist(struct CookieInfo *c, const char *host, const char *path, bool secure)

{
  struct Cookie *newco;
  struct Cookie *co;
  time_t now = time(NULL);
  struct Cookie *mainco=NULL;
  size_t matches = 0;
  bool is_ip;

  if(!c || !c->cookies)
    return NULL; 

  
  remove_expired(c);

  
  is_ip = isip(host);

  co = c->cookies;

  while(co) {
    
    if((!co->expires || (co->expires > now)) && (co->secure?secure:TRUE)) {

      
      if(!co->domain || (co->tailmatch && !is_ip && tailmatch(co->domain, host)) || ((!co->tailmatch || is_ip) && Curl_raw_equal(host, co->domain)) ) {

        

        
        if(!co->spath || pathmatch(co->spath, path) ) {

          

          newco = malloc(sizeof(struct Cookie));
          if(newco) {
            
            memcpy(newco, co, sizeof(struct Cookie));

            
            newco->next = mainco;

            
            mainco = newco;

            matches++;
          }
          else {
            fail:
            
            while(mainco) {
              co = mainco->next;
              free(mainco);
              mainco = co;
            }

            return NULL;
          }
        }
      }
    }
    co = co->next;
  }

  if(matches) {
    
    struct Cookie **array;
    size_t i;

    
    array = malloc(sizeof(struct Cookie *) * matches);
    if(!array)
      goto fail;

    co = mainco;

    for(i=0; co; co = co->next)
      array[i++] = co;

    
    qsort(array, matches, sizeof(struct Cookie *), cookie_sort);

    

    mainco = array[0]; 
    for(i=0; i<matches-1; i++)
      array[i]->next = array[i+1];
    array[matches-1]->next = NULL; 

    free(array); 
  }

  return mainco; 
}


void Curl_cookie_clearall(struct CookieInfo *cookies)
{
  if(cookies) {
    Curl_cookie_freelist(cookies->cookies, TRUE);
    cookies->cookies = NULL;
    cookies->numcookies = 0;
  }
}



void Curl_cookie_freelist(struct Cookie *co, bool cookiestoo)
{
  struct Cookie *next;
  while(co) {
    next = co->next;
    if(cookiestoo)
      freecookie(co);
    else free(co);
    co = next;
  }
}



void Curl_cookie_clearsess(struct CookieInfo *cookies)
{
  struct Cookie *first, *curr, *next, *prev = NULL;

  if(!cookies || !cookies->cookies)
    return;

  first = curr = prev = cookies->cookies;

  for(; curr; curr = next) {
    next = curr->next;
    if(!curr->expires) {
      if(first == curr)
        first = next;

      if(prev == curr)
        prev = next;
      else prev->next = next;

      freecookie(curr);
      cookies->numcookies--;
    }
    else prev = curr;
  }

  cookies->cookies = first;
}



void Curl_cookie_cleanup(struct CookieInfo *c)
{
  if(c) {
    free(c->filename);
    Curl_cookie_freelist(c->cookies, TRUE);
    free(c); 
  }
}


static char *get_netscape_format(const struct Cookie *co)
{
  return aprintf( "%s" "%s%s\t" "%s\t" "%s\t" "%s\t" "%" CURL_FORMAT_CURL_OFF_T "\t" "%s\t" "%s", co->httponly?"#HttpOnly_":"",  (co->tailmatch && co->domain && co->domain[0] != '.')? ".":"", co->domain?co->domain:"unknown", co->tailmatch?"TRUE":"FALSE", co->path?co->path:"/", co->secure?"TRUE":"FALSE", co->expires, co->name, co->value?co->value:"");

















}


static int cookie_output(struct CookieInfo *c, const char *dumphere)
{
  struct Cookie *co;
  FILE *out;
  bool use_stdout=FALSE;
  char *format_ptr;

  if((NULL == c) || (0 == c->numcookies))
    
    return 0;

  
  remove_expired(c);

  if(strequal("-", dumphere)) {
    
    out = stdout;
    use_stdout=TRUE;
  }
  else {
    out = fopen(dumphere, FOPEN_WRITETEXT);
    if(!out)
      return 1; 
  }

  fputs("# Netscape HTTP Cookie File\n" "# https://curl.haxx.se/docs/http-cookies.html\n" "# This file was generated by libcurl! Edit at your own risk.\n\n", out);



  for(co = c->cookies; co; co = co->next) {
    if(!co->domain)
      continue;
    format_ptr = get_netscape_format(co);
    if(format_ptr == NULL) {
      fprintf(out, "#\n# Fatal libcurl error\n");
      if(!use_stdout)
        fclose(out);
      return 1;
    }
    fprintf(out, "%s\n", format_ptr);
    free(format_ptr);
  }

  if(!use_stdout)
    fclose(out);

  return 0;
}

struct curl_slist *Curl_cookie_list(struct Curl_easy *data)
{
  struct curl_slist *list = NULL;
  struct curl_slist *beg;
  struct Cookie *c;
  char *line;

  if((data->cookies == NULL) || (data->cookies->numcookies == 0))
    return NULL;

  for(c = data->cookies->cookies; c; c = c->next) {
    if(!c->domain)
      continue;
    line = get_netscape_format(c);
    if(!line) {
      curl_slist_free_all(list);
      return NULL;
    }
    beg = Curl_slist_append_nodup(list, line);
    if(!beg) {
      free(line);
      curl_slist_free_all(list);
      return NULL;
    }
    list = beg;
  }

  return list;
}

void Curl_flush_cookies(struct Curl_easy *data, int cleanup)
{
  if(data->set.str[STRING_COOKIEJAR]) {
    if(data->change.cookielist) {
      
      Curl_cookie_loadfiles(data);
    }

    Curl_share_lock(data, CURL_LOCK_DATA_COOKIE, CURL_LOCK_ACCESS_SINGLE);

    
    if(cookie_output(data->cookies, data->set.str[STRING_COOKIEJAR]))
      infof(data, "WARNING: failed to save cookies in %s\n", data->set.str[STRING_COOKIEJAR]);
  }
  else {
    if(cleanup && data->change.cookielist) {
      
      curl_slist_free_all(data->change.cookielist); 
      data->change.cookielist = NULL;
    }
    Curl_share_lock(data, CURL_LOCK_DATA_COOKIE, CURL_LOCK_ACCESS_SINGLE);
  }

  if(cleanup && (!data->share || (data->cookies != data->share->cookies))) {
    Curl_cookie_cleanup(data->cookies);
  }
  Curl_share_unlock(data, CURL_LOCK_DATA_COOKIE);
}


