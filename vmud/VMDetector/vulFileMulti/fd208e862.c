














static char *parse_filename(const char *ptr, size_t len);



size_t tool_header_cb(void *ptr, size_t size, size_t nmemb, void *userdata)
{
  struct HdrCbData *hdrcbdata = userdata;
  struct OutStruct *outs = hdrcbdata->outs;
  struct OutStruct *heads = hdrcbdata->heads;
  const char *str = ptr;
  const size_t cb = size * nmemb;
  const char *end = (char*)ptr + cb;

  
  size_t failure = (size * nmemb) ? 0 : 1;

  if(!heads->config)
    return failure;


  if(size * nmemb > (size_t)CURL_MAX_HTTP_HEADER) {
    warnf(heads->config->global, "Header data exceeds single call write " "limit!\n");
    return failure;
  }


  

  if(heads->config->headerfile && heads->stream) {
    size_t rc = fwrite(ptr, size, nmemb, heads->stream);
    if(rc != cb)
      return rc;
    
    (void)fflush(heads->stream);
  }

  

  if(hdrcbdata->honor_cd_filename && (cb > 20) && checkprefix("Content-disposition:", str)) {
    const char *p = str + 20;

    
    for(;;) {
      char *filename;
      size_t len;

      while(*p && (p < end) && !ISALPHA(*p))
        p++;
      if(p > end - 9)
        break;

      if(memcmp(p, "filename=", 9)) {
        
        while((p < end) && (*p != ';'))
          p++;
        continue;
      }
      p += 9;

      
      len = (ssize_t)cb - (p - str);
      filename = parse_filename(p, len);
      if(filename) {
        outs->filename = filename;
        outs->alloc_filename = TRUE;
        outs->is_cd_filename = TRUE;
        outs->s_isreg = TRUE;
        outs->fopened = FALSE;
        outs->stream = NULL;
        hdrcbdata->honor_cd_filename = FALSE;
        break;
      }
      else return failure;
    }
  }

  return cb;
}


static char *parse_filename(const char *ptr, size_t len)
{
  char *copy;
  char *p;
  char *q;
  char  stop = '\0';

  
  copy = malloc(len+1);
  if(!copy)
    return NULL;
  memcpy(copy, ptr, len);
  copy[len] = '\0';

  p = copy;
  if(*p == '\'' || *p == '"') {
    
    stop = *p;
    p++;
  }
  else stop = ';';

  
  q = strrchr(copy, '/');
  if(q) {
    p = q + 1;
    if(!*p) {
      Curl_safefree(copy);
      return NULL;
    }
  }

  
  q = strrchr(p, '\\');
  if(q) {
    p = q + 1;
    if(!*p) {
      Curl_safefree(copy);
      return NULL;
    }
  }

  
  q = p;
  while(*q) {
    if(q[1] && (q[0] == '\\'))
      q++;
    else if(q[0] == stop)
      break;
    q++;
  }
  *q = '\0';

  
  q = strchr(p, '\r');
  if(q)
    *q = '\0';

  q = strchr(p, '\n');
  if(q)
    *q = '\0';

  if(copy != p)
    memmove(copy, p, strlen(p) + 1);

  

  {
    char *tdir = curlx_getenv("CURL_TESTDIR");
    if(tdir) {
      char buffer[512]; 
      snprintf(buffer, sizeof(buffer), "%s/%s", tdir, copy);
      Curl_safefree(copy);
      copy = strdup(buffer); 
      curl_free(tdir);
    }
  }


  return copy;
}

