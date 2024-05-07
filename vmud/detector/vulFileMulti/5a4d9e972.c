




























static void strstore(char **str, const char *newstr);

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

  if(!strcasecompare(cooke_domain, hostname + hostname_len-cookie_domain_len))
    return FALSE;

  
  if(hostname_len == cookie_domain_len)
    return TRUE;
  if('.' == *(hostname + hostname_len - cookie_domain_len - 1))
    return TRUE;
  return FALSE;
}


static bool pathmatch(const char *cookie_path, const char *request_uri)
{
  size_t cookie_path_len;
  size_t uri_path_len;
  char *uri_path = NULL;
  char *pos;
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
    strstore(&uri_path, "/");
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


static const char *get_top_domain(const char * const domain, size_t *outlen)
{
  size_t len = 0;
  const char *first = NULL, *last;

  if(domain) {
    len = strlen(domain);
    last = memrchr(domain, '.', len);
    if(last) {
      first = memrchr(domain, '.', (last - domain));
      if(first)
        len -= (++first - domain);
    }
  }

  if(outlen)
    *outlen = len;

  return first? first: domain;
}







static size_t cookie_hash_domain(const char *domain, const size_t len)
{
  const char *end = domain + len;
  size_t h = 5381;

  while(domain < end) {
    h += h << 5;
    h ^= Curl_raw_toupper(*domain++);
  }

  return (h % COOKIE_HASH_SIZE);
}






static size_t cookiehash(const char * const domain)
{
  const char *top;
  size_t len;

  if(!domain || Curl_host_is_ipnum(domain))
    return 0;

  top = get_top_domain(domain, &len);
  return cookie_hash_domain(top, len);
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
    
    strstore(&new_path, "/");
    return new_path;
  }

  
  if(len && new_path[len - 1] == '/') {
    new_path[len - 1] = 0x0;
  }

  return new_path;
}


void Curl_cookie_loadfiles(struct Curl_easy *data)
{
  struct curl_slist *list = data->state.cookielist;
  if(list) {
    Curl_share_lock(data, CURL_LOCK_DATA_COOKIE, CURL_LOCK_ACCESS_SINGLE);
    while(list) {
      struct CookieInfo *newcookies = Curl_cookie_init(data, list->data, data->cookies, data->set.cookiesession);


      if(!newcookies)
        
        infof(data, "ignoring failed cookie_init for %s", list->data);
      else data->cookies = newcookies;
      list = list->next;
    }
    curl_slist_free_all(data->state.cookielist); 
    data->state.cookielist = NULL; 
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
  struct Cookie *co, *nx;
  curl_off_t now = (curl_off_t)time(NULL);
  unsigned int i;

  
  if(now < cookies->next_expiration && cookies->next_expiration != CURL_OFF_T_MAX)
    return;
  else cookies->next_expiration = CURL_OFF_T_MAX;

  for(i = 0; i < COOKIE_HASH_SIZE; i++) {
    struct Cookie *pv = NULL;
    co = cookies->cookies[i];
    while(co) {
      nx = co->next;
      if(co->expires && co->expires < now) {
        if(!pv) {
          cookies->cookies[i] = co->next;
        }
        else {
          pv->next = co->next;
        }
        cookies->numcookies--;
        freecookie(co);
      }
      else {
        
        if(co->expires && co->expires < cookies->next_expiration)
          cookies->next_expiration = co->expires;
        pv = co;
      }
      co = nx;
    }
  }
}


static bool bad_domain(const char *domain)
{
  if(strcasecompare(domain, "localhost"))
    return FALSE;
  else {
    
    char *dot = strchr(domain, '.');
    if(dot)
      return dot[1] ? FALSE : TRUE;
  }
  return TRUE;
}


struct Cookie * Curl_cookie_add(struct Curl_easy *data,  struct CookieInfo *c, bool httpheader, bool noexpire, char *lineptr, const char *domain, const char *path, bool secure)








{
  struct Cookie *clist;
  struct Cookie *co;
  struct Cookie *lastc = NULL;
  struct Cookie *replace_co = NULL;
  struct Cookie *replace_clist = NULL;
  time_t now = time(NULL);
  bool replace_old = FALSE;
  bool badcookie = FALSE; 
  size_t myhash;


  (void)data;


  DEBUGASSERT(MAX_SET_COOKIE_AMOUNT <= 255); 
  if(data->req.setcookies >= MAX_SET_COOKIE_AMOUNT)
    return NULL;

  
  co = calloc(1, sizeof(struct Cookie));
  if(!co)
    return NULL; 

  if(httpheader) {
    
    char name[MAX_NAME];
    char what[MAX_NAME];
    const char *ptr;
    const char *semiptr;

    size_t linelength = strlen(lineptr);
    if(linelength > MAX_COOKIE_LINE) {
      
      free(co);
      return NULL;
    }

    semiptr = strchr(lineptr, ';'); 

    while(*lineptr && ISBLANK(*lineptr))
      lineptr++;

    ptr = lineptr;
    do {
      
      name[0] = what[0] = 0; 
      if(1 <= sscanf(ptr, "%" MAX_NAME_TXT "[^;\r\n=] =%" MAX_NAME_TXT "[^;\r\n]", name, what)) {

        
        const char *whatptr;
        bool done = FALSE;
        bool sep;
        size_t len = strlen(what);
        size_t nlen = strlen(name);
        const char *endofn = &ptr[ nlen ];

        
        if(nlen >= (MAX_NAME-1) || len >= (MAX_NAME-1) || ((nlen + len) > MAX_NAME)) {
          freecookie(co);
          infof(data, "oversized cookie dropped, name/val %zu + %zu bytes", nlen, len);
          return NULL;
        }

        
        sep = (*endofn == '=')?TRUE:FALSE;

        if(nlen) {
          endofn--; 
          if(ISBLANK(*endofn)) {
            
            while(*endofn && ISBLANK(*endofn) && nlen) {
              endofn--;
              nlen--;
            }
            name[nlen] = 0; 
          }
        }

        
        while(len && ISBLANK(what[len-1])) {
          what[len-1] = 0;
          len--;
        }

        
        whatptr = what;
        while(*whatptr && ISBLANK(*whatptr))
          whatptr++;

        
        if(nlen > 3 && name[0] == '_' && name[1] == '_') {
          if(!strncmp("__Secure-", name, 9))
            co->prefix |= COOKIE_PREFIX__SECURE;
          else if(!strncmp("__Host-", name, 7))
            co->prefix |= COOKIE_PREFIX__HOST;
        }

        if(!co->name) {
          
          if(!sep) {
            
            badcookie = TRUE;
            break;
          }
          co->name = strdup(name);
          co->value = strdup(whatptr);
          done = TRUE;
          if(!co->name || !co->value) {
            badcookie = TRUE;
            break;
          }
        }
        else if(!len) {
          
          done = TRUE;
          
          if(strcasecompare("secure", name)) {
            if(secure || !c->running) {
              co->secure = TRUE;
            }
            else {
              badcookie = TRUE;
              break;
            }
          }
          else if(strcasecompare("httponly", name))
            co->httponly = TRUE;
          else if(sep)
            
            done = FALSE;
        }
        if(done)
          ;
        else if(strcasecompare("path", name)) {
          strstore(&co->path, whatptr);
          if(!co->path) {
            badcookie = TRUE; 
            break;
          }
          free(co->spath); 
          co->spath = sanitize_cookie_path(co->path);
          if(!co->spath) {
            badcookie = TRUE; 
            break;
          }
        }
        else if(strcasecompare("domain", name) && whatptr[0]) {
          bool is_ip;

          

          if('.' == whatptr[0])
            whatptr++; 


          
          if(bad_domain(whatptr))
            domain = ":";


          is_ip = Curl_host_is_ipnum(domain ? domain : whatptr);

          if(!domain || (is_ip && !strcmp(whatptr, domain))
             || (!is_ip && tailmatch(whatptr, domain))) {
            strstore(&co->domain, whatptr);
            if(!co->domain) {
              badcookie = TRUE;
              break;
            }
            if(!is_ip)
              co->tailmatch = TRUE; 
          }
          else {
            
            badcookie = TRUE;
            infof(data, "skipped cookie with bad tailmatch domain: %s", whatptr);
          }
        }
        else if(strcasecompare("version", name)) {
          strstore(&co->version, whatptr);
          if(!co->version) {
            badcookie = TRUE;
            break;
          }
        }
        else if(strcasecompare("max-age", name)) {
          
          strstore(&co->maxage, whatptr);
          if(!co->maxage) {
            badcookie = TRUE;
            break;
          }
        }
        else if(strcasecompare("expires", name)) {
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

      ptr = semiptr + 1;
      while(*ptr && ISBLANK(*ptr))
        ptr++;
      semiptr = strchr(ptr, ';'); 

      if(!semiptr && *ptr)
        
        semiptr = strchr(ptr, '\0');
    } while(semiptr);

    if(co->maxage) {
      CURLofft offt;
      offt = curlx_strtoofft((*co->maxage == '\"')? &co->maxage[1]:&co->maxage[0], NULL, 10, &co->expires);

      if(offt == CURL_OFFT_FLOW)
        
        co->expires = CURL_OFF_T_MAX;
      else if(!offt) {
        if(!co->expires)
          
          co->expires = 1;
        else if(CURL_OFF_T_MAX - now < co->expires)
          
          co->expires = CURL_OFF_T_MAX;
        else co->expires += now;
      }
    }
    else if(co->expirestr) {
      
      co->expires = Curl_getdate_capped(co->expirestr);

      
      if(co->expires == 0)
        co->expires = 1;
      else if(co->expires < 0)
        co->expires = 0;
    }

    if(!badcookie && !co->domain) {
      if(domain) {
        
        co->domain = strdup(domain);
        if(!co->domain)
          badcookie = TRUE;
      }
    }

    if(!badcookie && !co->path && path) {
      
      char *queryp = strchr(path, '?');

      
      char *endslash;
      if(!queryp)
        endslash = strrchr(path, '/');
      else endslash = memrchr(path, '/', (queryp - path));
      if(endslash) {
        size_t pathlen = (endslash-path + 1); 
        co->path = malloc(pathlen + 1); 
        if(co->path) {
          memcpy(co->path, path, pathlen);
          co->path[pathlen] = 0; 
          co->spath = sanitize_cookie_path(co->path);
          if(!co->spath)
            badcookie = TRUE; 
        }
        else badcookie = TRUE;
      }
    }

    
    if(badcookie || !co->name) {
      freecookie(co);
      return NULL;
    }
    data->req.setcookies++;
  }
  else {
    
    char *ptr;
    char *firstptr;
    char *tok_buf = NULL;
    int fields;

    
    if(strncmp(lineptr, "#HttpOnly_", 10) == 0) {
      lineptr += 10;
      co->httponly = TRUE;
    }

    if(lineptr[0]=='#') {
      
      free(co);
      return NULL;
    }
    
    ptr = strchr(lineptr, '\r');
    if(ptr)
      *ptr = 0; 
    ptr = strchr(lineptr, '\n');
    if(ptr)
      *ptr = 0; 

    firstptr = strtok_r(lineptr, "\t", &tok_buf); 

    
    for(ptr = firstptr, fields = 0; ptr && !badcookie;
        ptr = strtok_r(NULL, "\t", &tok_buf), fields++) {
      switch(fields) {
      case 0:
        if(ptr[0]=='.') 
          ptr++;
        co->domain = strdup(ptr);
        if(!co->domain)
          badcookie = TRUE;
        break;
      case 1:
        
        co->tailmatch = strcasecompare(ptr, "TRUE")?TRUE:FALSE;
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
        co->secure = FALSE;
        if(strcasecompare(ptr, "TRUE")) {
          if(secure || c->running)
            co->secure = TRUE;
          else badcookie = TRUE;
        }
        break;
      case 4:
        if(curlx_strtoofft(ptr, NULL, 10, &co->expires))
          badcookie = TRUE;
        break;
      case 5:
        co->name = strdup(ptr);
        if(!co->name)
          badcookie = TRUE;
        else {
          
          if(strncasecompare("__Secure-", co->name, 9))
            co->prefix |= COOKIE_PREFIX__SECURE;
          else if(strncasecompare("__Host-", co->name, 7))
            co->prefix |= COOKIE_PREFIX__HOST;
        }
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

  if(co->prefix & COOKIE_PREFIX__SECURE) {
    
    if(!co->secure) {
      freecookie(co);
      return NULL;
    }
  }
  if(co->prefix & COOKIE_PREFIX__HOST) {
    
    if(co->secure && co->path && strcmp(co->path, "/") == 0 && !co->tailmatch)
      ;
    else {
      freecookie(co);
      return NULL;
    }
  }

  if(!c->running &&     c->newsession && !co->expires) {

    freecookie(co);
    return NULL;
  }

  co->livecookie = c->running;
  co->creationtime = ++c->lastct;

  

  
  if(!noexpire)
    remove_expired(c);


  
  if(data && (domain && co->domain && !Curl_host_is_ipnum(co->domain))) {
    const psl_ctx_t *psl = Curl_psl_use(data);
    int acceptable;

    if(psl) {
      acceptable = psl_is_cookie_domain_acceptable(psl, domain, co->domain);
      Curl_psl_release(data);
    }
    else acceptable = !bad_domain(domain);

    if(!acceptable) {
      infof(data, "cookie '%s' dropped, domain '%s' must not " "set cookies for '%s'", co->name, domain, co->domain);
      freecookie(co);
      return NULL;
    }
  }


  
  myhash = cookiehash(co->domain);
  clist = c->cookies[myhash];
  while(clist) {
    if(strcasecompare(clist->name, co->name)) {
      
      bool matching_domains = FALSE;

      if(clist->domain && co->domain) {
        if(strcasecompare(clist->domain, co->domain))
          
          matching_domains = TRUE;
      }
      else if(!clist->domain && !co->domain)
        matching_domains = TRUE;

      if(matching_domains &&  clist->spath && co->spath && clist->secure && !co->secure && !secure) {

        size_t cllen;
        const char *sep;

        

        sep = strchr(clist->spath + 1, '/');

        if(sep)
          cllen = sep - clist->spath;
        else cllen = strlen(clist->spath);

        if(strncasecompare(clist->spath, co->spath, cllen)) {
          infof(data, "cookie '%s' for domain '%s' dropped, would " "overlay an existing cookie", co->name, co->domain);
          freecookie(co);
          return NULL;
        }
      }
    }

    if(!replace_co && strcasecompare(clist->name, co->name)) {
      

      if(clist->domain && co->domain) {
        if(strcasecompare(clist->domain, co->domain) && (clist->tailmatch == co->tailmatch))
          
          replace_old = TRUE;
      }
      else if(!clist->domain && !co->domain)
        replace_old = TRUE;

      if(replace_old) {
        

        if(clist->spath && co->spath) {
          if(strcasecompare(clist->spath, co->spath))
            replace_old = TRUE;
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
        replace_co = co;
        replace_clist = clist;
      }
    }
    lastc = clist;
    clist = clist->next;
  }
  if(replace_co) {
    co = replace_co;
    clist = replace_clist;
    co->next = clist->next; 

    
    co->creationtime = clist->creationtime;

    
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
  }

  if(c->running)
    
    infof(data, "%s cookie %s=\"%s\" for domain %s, path %s, " "expire %" CURL_FORMAT_CURL_OFF_T, replace_old?"Replaced":"Added", co->name, co->value, co->domain, co->path, co->expires);



  if(!replace_old) {
    
    if(lastc)
      lastc->next = co;
    else c->cookies[myhash] = co;
    c->numcookies++; 
  }

  
  if(co->expires && (co->expires < c->next_expiration))
    c->next_expiration = co->expires;

  return co;
}



struct CookieInfo *Curl_cookie_init(struct Curl_easy *data, const char *file, struct CookieInfo *inc, bool newsession)


{
  struct CookieInfo *c;
  FILE *fp = NULL;
  bool fromfile = TRUE;
  char *line = NULL;

  if(!inc) {
    
    c = calloc(1, sizeof(struct CookieInfo));
    if(!c)
      return NULL; 
    c->filename = strdup(file?file:"none"); 
    if(!c->filename)
      goto fail; 
    
    c->next_expiration = CURL_OFF_T_MAX;
  }
  else {
    
    c = inc;
  }
  c->running = FALSE; 

  if(file && !strcmp(file, "-")) {
    fp = stdin;
    fromfile = FALSE;
  }
  else if(!file || !*file) {
    
    fp = NULL;
  }
  else {
    fp = fopen(file, FOPEN_READTEXT);
    if(!fp)
      infof(data, "WARNING: failed to open cookie file \"%s\"", file);
  }

  c->newsession = newsession; 

  if(fp) {
    char *lineptr;
    bool headerline;

    line = malloc(MAX_COOKIE_LINE);
    if(!line)
      goto fail;
    while(Curl_get_line(line, MAX_COOKIE_LINE, fp)) {
      if(checkprefix("Set-Cookie:", line)) {
        
        lineptr = &line[11];
        headerline = TRUE;
      }
      else {
        lineptr = line;
        headerline = FALSE;
      }
      while(*lineptr && ISBLANK(*lineptr))
        lineptr++;

      Curl_cookie_add(data, c, headerline, TRUE, lineptr, NULL, NULL, TRUE);
    }
    free(line); 

    
    remove_expired(c);

    if(fromfile && fp)
      fclose(fp);
  }

  c->running = TRUE;          
  if(data)
    data->state.cookie_engine = TRUE;

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

  
  l1 = c1->name ? strlen(c1->name) : 0;
  l2 = c2->name ? strlen(c2->name) : 0;

  if(l1 != l2)
    return (l2 > l1) ? 1 : -1;

  
  return (c2->creationtime > c1->creationtime) ? 1 : -1;
}


static int cookie_sort_ct(const void *p1, const void *p2)
{
  struct Cookie *c1 = *(struct Cookie **)p1;
  struct Cookie *c2 = *(struct Cookie **)p2;

  return (c2->creationtime > c1->creationtime) ? 1 : -1;
}









static struct Cookie *dup_cookie(struct Cookie *src)
{
  struct Cookie *d = calloc(sizeof(struct Cookie), 1);
  if(d) {
    CLONE(expirestr);
    CLONE(domain);
    CLONE(path);
    CLONE(spath);
    CLONE(name);
    CLONE(value);
    CLONE(maxage);
    CLONE(version);
    d->expires = src->expires;
    d->tailmatch = src->tailmatch;
    d->secure = src->secure;
    d->livecookie = src->livecookie;
    d->httponly = src->httponly;
    d->creationtime = src->creationtime;
  }
  return d;

  fail:
  freecookie(d);
  return NULL;
}


struct Cookie *Curl_cookie_getlist(struct Curl_easy *data, struct CookieInfo *c, const char *host, const char *path, bool secure)


{
  struct Cookie *newco;
  struct Cookie *co;
  struct Cookie *mainco = NULL;
  size_t matches = 0;
  bool is_ip;
  const size_t myhash = cookiehash(host);

  if(!c || !c->cookies[myhash])
    return NULL; 

  
  remove_expired(c);

  
  is_ip = Curl_host_is_ipnum(host);

  co = c->cookies[myhash];

  while(co) {
    
    if(co->secure?secure:TRUE) {

      
      if(!co->domain || (co->tailmatch && !is_ip && tailmatch(co->domain, host)) || ((!co->tailmatch || is_ip) && strcasecompare(host, co->domain)) ) {

        

        
        if(!co->spath || pathmatch(co->spath, path) ) {

          

          newco = dup_cookie(co);
          if(newco) {
            
            newco->next = mainco;

            
            mainco = newco;

            matches++;
            if(matches >= MAX_COOKIE_SEND_AMOUNT) {
              infof(data, "Included max number of cookies (%zu) in request!", matches);
              break;
            }
          }
          else goto fail;
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

    for(i = 0; co; co = co->next)
      array[i++] = co;

    
    qsort(array, matches, sizeof(struct Cookie *), cookie_sort);

    

    mainco = array[0]; 
    for(i = 0; i<matches-1; i++)
      array[i]->next = array[i + 1];
    array[matches-1]->next = NULL; 

    free(array); 
  }

  return mainco; 

fail:
  
  Curl_cookie_freelist(mainco);
  return NULL;
}


void Curl_cookie_clearall(struct CookieInfo *cookies)
{
  if(cookies) {
    unsigned int i;
    for(i = 0; i < COOKIE_HASH_SIZE; i++) {
      Curl_cookie_freelist(cookies->cookies[i]);
      cookies->cookies[i] = NULL;
    }
    cookies->numcookies = 0;
  }
}


void Curl_cookie_freelist(struct Cookie *co)
{
  struct Cookie *next;
  while(co) {
    next = co->next;
    freecookie(co);
    co = next;
  }
}


void Curl_cookie_clearsess(struct CookieInfo *cookies)
{
  struct Cookie *first, *curr, *next, *prev = NULL;
  unsigned int i;

  if(!cookies)
    return;

  for(i = 0; i < COOKIE_HASH_SIZE; i++) {
    if(!cookies->cookies[i])
      continue;

    first = curr = prev = cookies->cookies[i];

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

    cookies->cookies[i] = first;
  }
}


void Curl_cookie_cleanup(struct CookieInfo *c)
{
  if(c) {
    unsigned int i;
    free(c->filename);
    for(i = 0; i < COOKIE_HASH_SIZE; i++)
      Curl_cookie_freelist(c->cookies[i]);
    free(c); 
  }
}


static char *get_netscape_format(const struct Cookie *co)
{
  return aprintf( "%s" "%s%s\t" "%s\t" "%s\t" "%s\t" "%" CURL_FORMAT_CURL_OFF_T "\t" "%s\t" "%s", co->httponly?"#HttpOnly_":"",  (co->tailmatch && co->domain && co->domain[0] != '.')? ".":"", co->domain?co->domain:"unknown", co->tailmatch?"TRUE":"FALSE", co->path?co->path:"/", co->secure?"TRUE":"FALSE", co->expires, co->name, co->value?co->value:"");

















}


static CURLcode cookie_output(struct Curl_easy *data, struct CookieInfo *c, const char *filename)
{
  struct Cookie *co;
  FILE *out = NULL;
  bool use_stdout = FALSE;
  char *tempstore = NULL;
  CURLcode error = CURLE_OK;

  if(!c)
    
    return CURLE_OK;

  
  remove_expired(c);

  if(!strcmp("-", filename)) {
    
    out = stdout;
    use_stdout = TRUE;
  }
  else {
    error = Curl_fopen(data, filename, &out, &tempstore);
    if(error)
      goto error;
  }

  fputs("# Netscape HTTP Cookie File\n" "# https://curl.se/docs/http-cookies.html\n" "# This file was generated by libcurl! Edit at your own risk.\n\n", out);



  if(c->numcookies) {
    unsigned int i;
    size_t nvalid = 0;
    struct Cookie **array;

    array = calloc(1, sizeof(struct Cookie *) * c->numcookies);
    if(!array) {
      error = CURLE_OUT_OF_MEMORY;
      goto error;
    }

    
    for(i = 0; i < COOKIE_HASH_SIZE; i++) {
      for(co = c->cookies[i]; co; co = co->next) {
        if(!co->domain)
          continue;
        array[nvalid++] = co;
      }
    }

    qsort(array, nvalid, sizeof(struct Cookie *), cookie_sort_ct);

    for(i = 0; i < nvalid; i++) {
      char *format_ptr = get_netscape_format(array[i]);
      if(!format_ptr) {
        free(array);
        error = CURLE_OUT_OF_MEMORY;
        goto error;
      }
      fprintf(out, "%s\n", format_ptr);
      free(format_ptr);
    }

    free(array);
  }

  if(!use_stdout) {
    fclose(out);
    out = NULL;
    if(tempstore && Curl_rename(tempstore, filename)) {
      unlink(tempstore);
      error = CURLE_WRITE_ERROR;
      goto error;
    }
  }

  
  free(tempstore);
  return CURLE_OK;

error:
  if(out && !use_stdout)
    fclose(out);
  free(tempstore);
  return error;
}

static struct curl_slist *cookie_list(struct Curl_easy *data)
{
  struct curl_slist *list = NULL;
  struct curl_slist *beg;
  struct Cookie *c;
  char *line;
  unsigned int i;

  if(!data->cookies || (data->cookies->numcookies == 0))
    return NULL;

  for(i = 0; i < COOKIE_HASH_SIZE; i++) {
    for(c = data->cookies->cookies[i]; c; c = c->next) {
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
  }

  return list;
}

struct curl_slist *Curl_cookie_list(struct Curl_easy *data)
{
  struct curl_slist *list;
  Curl_share_lock(data, CURL_LOCK_DATA_COOKIE, CURL_LOCK_ACCESS_SINGLE);
  list = cookie_list(data);
  Curl_share_unlock(data, CURL_LOCK_DATA_COOKIE);
  return list;
}

void Curl_flush_cookies(struct Curl_easy *data, bool cleanup)
{
  CURLcode res;

  if(data->set.str[STRING_COOKIEJAR]) {
    if(data->state.cookielist) {
      
      Curl_cookie_loadfiles(data);
    }

    Curl_share_lock(data, CURL_LOCK_DATA_COOKIE, CURL_LOCK_ACCESS_SINGLE);

    
    res = cookie_output(data, data->cookies, data->set.str[STRING_COOKIEJAR]);
    if(res)
      infof(data, "WARNING: failed to save cookies in %s: %s", data->set.str[STRING_COOKIEJAR], curl_easy_strerror(res));
  }
  else {
    if(cleanup && data->state.cookielist) {
      
      curl_slist_free_all(data->state.cookielist); 
      data->state.cookielist = NULL;
    }
    Curl_share_lock(data, CURL_LOCK_DATA_COOKIE, CURL_LOCK_ACCESS_SINGLE);
  }

  if(cleanup && (!data->share || (data->cookies != data->share->cookies))) {
    Curl_cookie_cleanup(data->cookies);
    data->cookies = NULL;
  }
  Curl_share_unlock(data, CURL_LOCK_DATA_COOKIE);
}


