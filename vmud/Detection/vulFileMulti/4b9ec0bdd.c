

























static void freecookie(struct Cookie *co)
{
  if(co->expirestr)
    free(co->expirestr);
  if(co->domain)
    free(co->domain);
  if(co->path)
    free(co->path);
  if(co->name)
    free(co->name);
  if(co->value)
    free(co->value);
  if(co->maxage)
    free(co->maxage);
  if(co->version)
    free(co->version);

  free(co);
}

static bool tailmatch(const char *little, const char *bigone)
{
  size_t littlelen = strlen(little);
  size_t biglen = strlen(bigone);

  if(littlelen > biglen)
    return FALSE;

  return Curl_raw_equal(little, bigone+biglen-littlelen) ? TRUE : FALSE;
}


void Curl_cookie_loadfiles(struct SessionHandle *data)
{
  struct curl_slist *list = data->change.cookielist;
  if(list) {
    Curl_share_lock(data, CURL_LOCK_DATA_COOKIE, CURL_LOCK_ACCESS_SINGLE);
    while(list) {
      data->cookies = Curl_cookie_init(data, list->data, data->cookies, data->set.cookiesession);


      list = list->next;
    }
    curl_slist_free_all(data->change.cookielist); 
    data->change.cookielist = NULL; 
    Curl_share_unlock(data, CURL_LOCK_DATA_COOKIE);
  }
}


static void strstore(char **str, const char *newstr)
{
  if(*str)
    free(*str);
  *str = strdup(newstr);
}




struct Cookie * Curl_cookie_add(struct SessionHandle *data,   struct CookieInfo *c, bool httpheader, char *lineptr, const char *domain, const char *path)







{
  struct Cookie *clist;
  char name[MAX_NAME];
  struct Cookie *co;
  struct Cookie *lastc=NULL;
  time_t now = time(NULL);
  bool replace_old = FALSE;
  bool badcookie = FALSE; 


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
      if(1 <= sscanf(ptr, "%" MAX_NAME_TXT "[^;\r\n =]=%" MAX_COOKIE_LINE_TXT "[^;\r\n]", name, what)) {

        
        const char *whatptr;
        bool done = FALSE;
        bool sep;
        size_t len=strlen(what);
        const char *endofn = &ptr[ strlen(name) ];

        
        while(*endofn && ISBLANK(*endofn))
          endofn++;

        
        sep = (*endofn == '=')?TRUE:FALSE;

        
        while(len && ISBLANK(what[len-1])) {
          what[len-1]=0;
          len--;
        }

        
        whatptr=what;
        while(*whatptr && ISBLANK(*whatptr))
          whatptr++;

        if(!len) {
          
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
        }
        else if(Curl_raw_equal("domain", name)) {
          

          const char *domptr=whatptr;
          const char *nextptr;
          int dotcount=1;

          

          if('.' == whatptr[0])
            
            domptr++;

          do {
            nextptr = strchr(domptr, '.');
            if(nextptr) {
              if(domptr != nextptr)
                dotcount++;
              domptr = nextptr+1;
            }
          } while(nextptr);

          

          if(dotcount < 2) {
            
            badcookie=TRUE; 
            infof(data, "skipped cookie with illegal dotcount domain: %s\n", whatptr);
          }
          else {
            

            if('.' == whatptr[0])
              whatptr++; 

            if(!domain || tailmatch(whatptr, domain)) {
              const char *tailptr=whatptr;
              if(tailptr[0] == '.')
                tailptr++;
              strstore(&co->domain, tailptr); 
              if(!co->domain) {
                badcookie = TRUE;
                break;
              }
              co->tailmatch=TRUE; 
            }
            else {
              
              badcookie=TRUE;
              infof(data, "skipped cookie with bad tailmatch domain: %s\n", whatptr);
            }
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
          co->expires = strtol((*co->maxage=='\"')?&co->maxage[1]:&co->maxage[0],NULL,10)
            + (long)now;
        }
        else if(Curl_raw_equal("expires", name)) {
          strstore(&co->expirestr, whatptr);
          if(!co->expirestr) {
            badcookie = TRUE;
            break;
          }
          
          co->expires = curl_getdate(what, &now);

          
          if(co->expires == 0)
            co->expires = 1;
          else if(co->expires < 0)
            co->expires = 0;
        }
        else if(!co->name) {
          co->name = strdup(name);
          co->value = strdup(whatptr);
          if(!co->name || !co->value) {
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

    
    if(!firstptr || strchr(firstptr, ':')) {
      free(co);
      return NULL;
    }

    
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
          break;
        }
        
        co->path = strdup("/");
        if(!co->path)
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

  

  clist = c->cookies;
  replace_old = FALSE;
  while(clist) {
    if(Curl_raw_equal(clist->name, co->name)) {
      

      if(clist->domain && co->domain) {
        if(Curl_raw_equal(clist->domain, co->domain))
          
          replace_old=TRUE;
      }
      else if(!clist->domain && !co->domain)
        replace_old = TRUE;

      if(replace_old) {
        

        if(clist->path && co->path) {
          if(Curl_raw_equal(clist->path, co->path)) {
            replace_old = TRUE;
          }
          else replace_old = FALSE;
        }
        else if(!clist->path && !co->path)
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
        if(clist->value)
          free(clist->value);
        if(clist->domain)
          free(clist->domain);
        if(clist->path)
          free(clist->path);
        if(clist->expirestr)
          free(clist->expirestr);

        if(clist->version)
          free(clist->version);
        if(clist->maxage)
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
    
    infof(data, "%s cookie %s=\"%s\" for domain %s, path %s, " "expire %" FORMAT_OFF_T "\n", replace_old?"Replaced":"Added", co->name, co->value, co->domain, co->path, co->expires);



  if(!replace_old) {
    
    if(lastc)
      lastc->next = co;
    else c->cookies = co;
    c->numcookies++; 
  }

  return co;
}


struct CookieInfo *Curl_cookie_init(struct SessionHandle *data, const char *file, struct CookieInfo *inc, bool newsession)


{
  struct CookieInfo *c;
  FILE *fp;
  bool fromfile=TRUE;

  if(NULL == inc) {
    
    c = calloc(1, sizeof(struct CookieInfo));
    if(!c)
      return NULL; 
    c->filename = strdup(file?file:"none"); 
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
  else fp = file?fopen(file, "r"):NULL;

  c->newsession = newsession; 

  if(fp) {
    char *lineptr;
    bool headerline;

    char *line = malloc(MAX_COOKIE_LINE);
    if(line) {
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
    }
    if(fromfile)
      fclose(fp);
  }

  c->running = TRUE;          

  return c;
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

  if(!c || !c->cookies)
    return NULL; 

  co = c->cookies;

  while(co) {
    
    if((!co->expires || (co->expires > now)) && (co->secure?secure:TRUE)) {

      
      if(!co->domain || (co->tailmatch && tailmatch(co->domain, host)) || (!co->tailmatch && Curl_raw_equal(host, co->domain)) ) {

        

        
        if(!co->path ||  !strncmp(co->path, path, strlen(co->path)) ) {


          

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
  if(co) {
    while(co) {
      next = co->next;
      if(cookiestoo)
        freecookie(co);
      else free(co);
      co = next;
    }
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
  struct Cookie *co;
  struct Cookie *next;
  if(c) {
    if(c->filename)
      free(c->filename);
    co = c->cookies;

    while(co) {
      next = co->next;
      freecookie(co);
      co = next;
    }
    free(c); 
  }
}


static char *get_netscape_format(const struct Cookie *co)
{
  return aprintf( "%s" "%s%s\t" "%s\t" "%s\t" "%s\t" "%" FORMAT_OFF_T "\t" "%s\t" "%s", co->httponly?"#HttpOnly_":"",  (co->tailmatch && co->domain && co->domain[0] != '.')? ".":"", co->domain?co->domain:"unknown", co->tailmatch?"TRUE":"FALSE", co->path?co->path:"/", co->secure?"TRUE":"FALSE", co->expires, co->name, co->value?co->value:"");

















}


static int cookie_output(struct CookieInfo *c, const char *dumphere)
{
  struct Cookie *co;
  FILE *out;
  bool use_stdout=FALSE;

  if((NULL == c) || (0 == c->numcookies))
    
    return 0;

  if(strequal("-", dumphere)) {
    
    out = stdout;
    use_stdout=TRUE;
  }
  else {
    out = fopen(dumphere, "w");
    if(!out)
      return 1; 
  }

  if(c) {
    char *format_ptr;

    fputs("# Netscape HTTP Cookie File\n" "# http://curl.haxx.se/docs/http-cookies.html\n" "# This file was generated by libcurl! Edit at your own risk.\n\n", out);


    co = c->cookies;

    while(co) {
      format_ptr = get_netscape_format(co);
      if(format_ptr == NULL) {
        fprintf(out, "#\n# Fatal libcurl error\n");
        if(!use_stdout)
          fclose(out);
        return 1;
      }
      fprintf(out, "%s\n", format_ptr);
      free(format_ptr);
      co=co->next;
    }
  }

  if(!use_stdout)
    fclose(out);

  return 0;
}

struct curl_slist *Curl_cookie_list(struct SessionHandle *data)
{
  struct curl_slist *list = NULL;
  struct curl_slist *beg;
  struct Cookie *c;
  char *line;

  if((data->cookies == NULL) || (data->cookies->numcookies == 0))
    return NULL;

  c = data->cookies->cookies;

  while(c) {
    
    line = get_netscape_format(c);
    if(!line) {
      curl_slist_free_all(list);
      return NULL;
    }
    beg = curl_slist_append(list, line);
    free(line);
    if(!beg) {
      curl_slist_free_all(list);
      return NULL;
    }
    list = beg;
    c = c->next;
  }

  return list;
}

void Curl_flush_cookies(struct SessionHandle *data, int cleanup)
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


