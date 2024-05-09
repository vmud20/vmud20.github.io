






























































static const char *msdosify (const char *file_name);
static char *rename_if_dos_device_name (char *file_name);



char *sanitize_dos_name(char *file_name)
{
  char new_name[PATH_MAX];

  if(!file_name)
    return NULL;

  if(strlen(file_name) >= PATH_MAX)
    file_name[PATH_MAX-1] = '\0'; 

  strcpy(new_name, msdosify(file_name));

  Curl_safefree(file_name);

  return strdup(rename_if_dos_device_name(new_name));
}



static const char *msdosify (const char *file_name)
{
  static char dos_name[PATH_MAX];
  static const char illegal_chars_dos[] = ".+, ;=[]"  "|<>\\\":?*";
  static const char *illegal_chars_w95 = &illegal_chars_dos[8];
  int idx, dot_idx;
  const char *s = file_name;
  char *d = dos_name;
  const char *const dlimit = dos_name + sizeof(dos_name) - 1;
  const char *illegal_aliens = illegal_chars_dos;
  size_t len = sizeof(illegal_chars_dos) - 1;

  
  if(_use_lfn(file_name)) {
    illegal_aliens = illegal_chars_w95;
    len -= (illegal_chars_w95 - illegal_chars_dos);
  }

  
  if(s[0] >= 'A' && s[0] <= 'z' && s[1] == ':') {
    *d++ = *s++;
    *d++ = *s++;
  }

  for(idx = 0, dot_idx = -1; *s && d < dlimit; s++, d++) {
    if(memchr(illegal_aliens, *s, len)) {
      
      if(*s == '.') {
        if(idx == 0 && (s[1] == '/' || (s[1] == '.' && s[2] == '/'))) {
          
          *d++ = *s++;
          if(*s == '.')
            *d++ = *s++;
          *d = *s;
        }
        else if(idx == 0)
          *d = '_';
        else if(dot_idx >= 0) {
          if(dot_idx < 5) { 
            d[dot_idx - idx] = '_'; 
            *d = '.';
          }
          else *d = '-';
        }
        else *d = '.';

        if(*s == '.')
          dot_idx = idx;
      }
      else if(*s == '+' && s[1] == '+') {
        if(idx - 2 == dot_idx) { 
          *d++ = 'x';
          *d   = 'x';
        }
        else {
          
          memcpy (d, "plus", 4);
          d += 3;
        }
        s++;
        idx++;
      }
      else *d = '_';
    }
    else *d = *s;
    if(*s == '/') {
      idx = 0;
      dot_idx = -1;
    }
    else idx++;
  }

  *d = '\0';
  return dos_name;
}

static char *rename_if_dos_device_name (char *file_name)
{
  
  char *base;
  struct_stat st_buf;
  char fname[PATH_MAX];

  strncpy(fname, file_name, PATH_MAX-1);
  fname[PATH_MAX-1] = '\0';
  base = basename(fname);
  if(((stat(base, &st_buf)) == 0) && (S_ISCHR(st_buf.st_mode))) {
    size_t blen = strlen(base);

    if(strlen(fname) >= PATH_MAX-1) {
      
      blen--;
      base[blen] = '\0';
    }
    
    memmove(base + 1, base, blen + 1);
    base[0] = '_';
    strcpy(file_name, fname);
  }
  return file_name;
}




char **__crt0_glob_function(char *arg)
{
  (void)arg;
  return (char**)0;
}







CURLcode FindWin32CACert(struct OperationConfig *config, const char *bundle_file)
{
  CURLcode result = CURLE_OK;

  
  if(curlinfo->features & CURL_VERSION_SSL) {

    DWORD res_len;
    DWORD buf_tchar_size = PATH_MAX + 1;
    DWORD buf_bytes_size = sizeof(TCHAR) * buf_tchar_size;
    char *ptr = NULL;

    char *buf = malloc(buf_bytes_size);
    if(!buf)
      return CURLE_OUT_OF_MEMORY;
    buf[0] = '\0';

    res_len = SearchPathA(NULL, bundle_file, NULL, buf_tchar_size, buf, &ptr);
    if(res_len > 0) {
      Curl_safefree(config->cacert);
      config->cacert = strdup(buf);
      if(!config->cacert)
        result = CURLE_OUT_OF_MEMORY;
    }

    Curl_safefree(buf);
  }

  return result;
}




