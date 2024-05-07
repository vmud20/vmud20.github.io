



































































CURLcode curl_easy_perform_ev(CURL *easy);























static bool is_fatal_error(CURLcode code)
{
  switch(code) {
  
  case CURLE_FAILED_INIT:
  case CURLE_OUT_OF_MEMORY:
  case CURLE_UNKNOWN_OPTION:
  case CURLE_FUNCTION_NOT_FOUND:
  case CURLE_BAD_FUNCTION_ARGUMENT:
    
    return TRUE;
  default:
    break;
  }

  
  return FALSE;
}



static curl_off_t vms_realfilesize(const char * name, const struct_stat * stat_buf)
{
  char buffer[8192];
  curl_off_t count;
  int ret_stat;
  FILE * file;

  file = fopen(name, "r"); 
  if(file == NULL) {
    return 0;
  }
  count = 0;
  ret_stat = 1;
  while(ret_stat > 0) {
    ret_stat = fread(buffer, 1, sizeof(buffer), file);
    if(ret_stat != 0)
      count += ret_stat;
  }
  fclose(file);

  return count;
}


static curl_off_t VmsSpecialSize(const char * name, const struct_stat * stat_buf)
{
  switch(stat_buf->st_fab_rfm) {
  case FAB$C_VAR:
  case FAB$C_VFC:
    return vms_realfilesize(name, stat_buf);
    break;
  default:
    return stat_buf->st_size;
  }
}


static CURLcode operate_do(struct GlobalConfig *global, struct OperationConfig *config)
{
  char errorbuffer[CURL_ERROR_SIZE];
  struct ProgressData progressbar;
  struct getout *urlnode;

  struct HdrCbData hdrcbdata;
  struct OutStruct heads;

  metalinkfile *mlfile_last = NULL;

  CURL *curl = config->easy;
  char *httpgetfields = NULL;

  CURLcode result = CURLE_OK;
  unsigned long li;

  
  bool orig_noprogress = global->noprogress;
  bool orig_isatty = global->isatty;

  errorbuffer[0] = '\0';

  
  memset(&hdrcbdata, 0, sizeof(struct HdrCbData));
  memset(&heads, 0, sizeof(struct OutStruct));
  heads.stream = stdout;
  heads.config = config;

  

  
  if(!config->url_list || !config->url_list->url) {
    helpf(global->errors, "no URL specified!\n");
    result = CURLE_FAILED_INIT;
    goto quit_curl;
  }

  
  if(!config->cacert && !config->capath && !config->insecure_ok) {

    char *env;
    env = curlx_getenv("CURL_CA_BUNDLE");
    if(env) {
      config->cacert = strdup(env);
      if(!config->cacert) {
        curl_free(env);
        helpf(global->errors, "out of memory\n");
        result = CURLE_OUT_OF_MEMORY;
        goto quit_curl;
      }
    }
    else {
      env = curlx_getenv("SSL_CERT_DIR");
      if(env) {
        config->capath = strdup(env);
        if(!config->capath) {
          curl_free(env);
          helpf(global->errors, "out of memory\n");
          result = CURLE_OUT_OF_MEMORY;
          goto quit_curl;
        }
      }
      else {
        env = curlx_getenv("SSL_CERT_FILE");
        if(env) {
          config->cacert = strdup(env);
          if(!config->cacert) {
            curl_free(env);
            helpf(global->errors, "out of memory\n");
            result = CURLE_OUT_OF_MEMORY;
            goto quit_curl;
          }
        }
      }
    }

    if(env)
      curl_free(env);

    else {
      result = FindWin32CACert(config, "curl-ca-bundle.crt");
      if(result)
        goto quit_curl;
    }

  }

  if(config->postfields) {
    if(config->use_httpget) {
      
      httpgetfields = strdup(config->postfields);
      Curl_safefree(config->postfields);
      if(!httpgetfields) {
        helpf(global->errors, "out of memory\n");
        result = CURLE_OUT_OF_MEMORY;
        goto quit_curl;
      }
      if(SetHTTPrequest(config, (config->no_body?HTTPREQ_HEAD:HTTPREQ_GET), &config->httpreq)) {

        result = CURLE_FAILED_INIT;
        goto quit_curl;
      }
    }
    else {
      if(SetHTTPrequest(config, HTTPREQ_SIMPLEPOST, &config->httpreq)) {
        result = CURLE_FAILED_INIT;
        goto quit_curl;
      }
    }
  }

  
  if(config->headerfile) {
    
    if(!curlx_strequal(config->headerfile, "-")) {
      FILE *newfile = fopen(config->headerfile, "wb");
      if(!newfile) {
        warnf(config->global, "Failed to open %s\n", config->headerfile);
        result = CURLE_WRITE_ERROR;
        goto quit_curl;
      }
      else {
        heads.filename = config->headerfile;
        heads.s_isreg = TRUE;
        heads.fopened = TRUE;
        heads.stream = newfile;
      }
    }
    else {
      
      set_binmode(heads.stream);
    }
  }

  

  

  for(urlnode = config->url_list; urlnode; urlnode = urlnode->next) {

    unsigned long up; 
    char *infiles; 
    char *outfiles;
    unsigned long infilenum;
    URLGlob *inglob;

    int metalink = 0; 
    metalinkfile *mlfile;
    metalink_resource *mlres;

    outfiles = NULL;
    infilenum = 1;
    inglob = NULL;

    if(urlnode->flags & GETOUT_METALINK) {
      metalink = 1;
      if(mlfile_last == NULL) {
        mlfile_last = config->metalinkfile_list;
      }
      mlfile = mlfile_last;
      mlfile_last = mlfile_last->next;
      mlres = mlfile->resource;
    }
    else {
      mlfile = NULL;
      mlres = NULL;
    }

    

    if(!urlnode->url) {
      
      Curl_safefree(urlnode->outfile);
      Curl_safefree(urlnode->infile);
      urlnode->flags = 0;
      continue; 
    }

    
    if(urlnode->outfile) {
      outfiles = strdup(urlnode->outfile);
      if(!outfiles) {
        helpf(global->errors, "out of memory\n");
        result = CURLE_OUT_OF_MEMORY;
        break;
      }
    }

    infiles = urlnode->infile;

    if(!config->globoff && infiles) {
      
      result = glob_url(&inglob, infiles, &infilenum, global->showerror?global->errors:NULL);
      if(result) {
        Curl_safefree(outfiles);
        break;
      }
    }

    
    for(up = 0 ; up < infilenum; up++) {

      char *uploadfile; 
      int separator;
      URLGlob *urls;
      unsigned long urlnum;

      uploadfile = NULL;
      urls = NULL;
      urlnum = 0;

      if(!up && !infiles)
        Curl_nop_stmt;
      else {
        if(inglob) {
          result = glob_next_url(&uploadfile, inglob);
          if(result == CURLE_OUT_OF_MEMORY)
            helpf(global->errors, "out of memory\n");
        }
        else if(!up) {
          uploadfile = strdup(infiles);
          if(!uploadfile) {
            helpf(global->errors, "out of memory\n");
            result = CURLE_OUT_OF_MEMORY;
          }
        }
        else uploadfile = NULL;
        if(!uploadfile)
          break;
      }

      if(metalink) {
        
        urlnum = count_next_metalink_resource(mlfile);
      }
      else if(!config->globoff) {
        
        result = glob_url(&urls, urlnode->url, &urlnum, global->showerror?global->errors:NULL);
        if(result) {
          Curl_safefree(uploadfile);
          break;
        }
      }
      else urlnum = 1;

      
      separator= ((!outfiles || curlx_strequal(outfiles, "-")) && urlnum > 1);

      
      for(li = 0 ; li < urlnum; li++) {

        int infd;
        bool infdopen;
        char *outfile;
        struct OutStruct outs;
        struct InStruct input;
        struct timeval retrystart;
        curl_off_t uploadfilesize;
        long retry_numretries;
        long retry_sleep_default;
        long retry_sleep;
        char *this_url = NULL;
        int metalink_next_res = 0;

        outfile = NULL;
        infdopen = FALSE;
        infd = STDIN_FILENO;
        uploadfilesize = -1; 

        
        memset(&outs, 0, sizeof(struct OutStruct));
        outs.stream = stdout;
        outs.config = config;

        if(metalink) {
          
          outfile = strdup(mlfile->filename);
          if(!outfile) {
            result = CURLE_OUT_OF_MEMORY;
            goto show_error;
          }
          this_url = strdup(mlres->url);
          if(!this_url) {
            result = CURLE_OUT_OF_MEMORY;
            goto show_error;
          }
        }
        else {
          if(urls) {
            result = glob_next_url(&this_url, urls);
            if(result)
              goto show_error;
          }
          else if(!li) {
            this_url = strdup(urlnode->url);
            if(!this_url) {
              result = CURLE_OUT_OF_MEMORY;
              goto show_error;
            }
          }
          else this_url = NULL;
          if(!this_url)
            break;

          if(outfiles) {
            outfile = strdup(outfiles);
            if(!outfile) {
              result = CURLE_OUT_OF_MEMORY;
              goto show_error;
            }
          }
        }

        if(((urlnode->flags&GETOUT_USEREMOTE) || (outfile && !curlx_strequal("-", outfile))) && (metalink || !config->use_metalink)) {


          

          if(!outfile) {
            
            result = get_url_file_name(&outfile, this_url);
            if(result)
              goto show_error;
            if(!*outfile && !config->content_disposition) {
              helpf(global->errors, "Remote file name has no length!\n");
              result = CURLE_WRITE_ERROR;
              goto quit_urls;
            }

            
            outfile = sanitize_dos_name(outfile);
            if(!outfile) {
              result = CURLE_OUT_OF_MEMORY;
              goto show_error;
            }

          }
          else if(urls) {
            
            char *storefile = outfile;
            result = glob_match_url(&outfile, storefile, urls);
            Curl_safefree(storefile);
            if(result) {
              
              warnf(config->global, "bad output glob!\n");
              goto quit_urls;
            }
          }

          

          if(config->create_dirs || metalink) {
            result = create_dir_hierarchy(outfile, global->errors);
            
            if(result == CURLE_WRITE_ERROR)
              goto quit_urls;
            if(result) {
              goto show_error;
            }
          }

          if((urlnode->flags & GETOUT_USEREMOTE)
             && config->content_disposition) {
            
            DEBUGASSERT(!outs.filename);
          }

          if(config->resume_from_current) {
            
            struct_stat fileinfo;
            
            if(0 == stat(outfile, &fileinfo))
              
              config->resume_from = fileinfo.st_size;
            else  config->resume_from = 0;

          }

          if(config->resume_from) {

            
            FILE *file = fopen(outfile, config->resume_from?"ab":"wb", "ctx=stm", "rfm=stmlf", "rat=cr", "mrs=0");

            
            FILE *file = fopen(outfile, config->resume_from?"ab":"wb");

            if(!file) {
              helpf(global->errors, "Can't open '%s'!\n", outfile);
              result = CURLE_WRITE_ERROR;
              goto quit_urls;
            }
            outs.fopened = TRUE;
            outs.stream = file;
            outs.init = config->resume_from;
          }
          else {
            outs.stream = NULL; 
          }
          outs.filename = outfile;
          outs.s_isreg = TRUE;
        }

        if(uploadfile && !stdin_upload(uploadfile)) {
          
          struct_stat fileinfo;

          this_url = add_file_name_to_url(curl, this_url, uploadfile);
          if(!this_url) {
            result = CURLE_OUT_OF_MEMORY;
            goto show_error;
          }
          

          
          infd = -1;
          if(stat(uploadfile, &fileinfo) == 0) {
            fileinfo.st_size = VmsSpecialSize(uploadfile, &fileinfo);
            switch (fileinfo.st_fab_rfm) {
            case FAB$C_VAR:
            case FAB$C_VFC:
            case FAB$C_STMCR:
              infd = open(uploadfile, O_RDONLY | O_BINARY);
              break;
            default:
              infd = open(uploadfile, O_RDONLY | O_BINARY, "rfm=stmlf", "ctx=stm");
            }
          }
          if(infd == -1)

          infd = open(uploadfile, O_RDONLY | O_BINARY);
          if((infd == -1) || fstat(infd, &fileinfo))

          {
            helpf(global->errors, "Can't open '%s'!\n", uploadfile);
            if(infd != -1) {
              close(infd);
              infd = STDIN_FILENO;
            }
            result = CURLE_READ_ERROR;
            goto quit_urls;
          }
          infdopen = TRUE;

          
          if(S_ISREG(fileinfo.st_mode))
            uploadfilesize = fileinfo.st_size;

        }
        else if(uploadfile && stdin_upload(uploadfile)) {
          
          int authbits = 0;
          int bitcheck = 0;
          while(bitcheck < 32) {
            if(config->authtype & (1UL << bitcheck++)) {
              authbits++;
              if(authbits > 1) {
                
                break;
              }
            }
          }

          
          if(config->proxyanyauth || (authbits>1)) {
            warnf(config->global, "Using --anyauth or --proxy-anyauth with upload from stdin" " involves a big risk of it not working. Use a temporary" " file or a fixed auth type instead!\n");


          }

          DEBUGASSERT(infdopen == FALSE);
          DEBUGASSERT(infd == STDIN_FILENO);

          set_binmode(stdin);
          if(curlx_strequal(uploadfile, ".")) {
            if(curlx_nonblock((curl_socket_t)infd, TRUE) < 0)
              warnf(config->global, "fcntl failed on fd=%d: %s\n", infd, strerror(errno));
          }
        }

        if(uploadfile && config->resume_from_current)
          config->resume_from = -1; 

        if(output_expected(this_url, uploadfile) && outs.stream && isatty(fileno(outs.stream)))
          
          global->noprogress = global->isatty = TRUE;
        else {
          
          global->noprogress = orig_noprogress;
          global->isatty = orig_isatty;
        }

        if(urlnum > 1 && !global->mute) {
          fprintf(global->errors, "\n[%lu/%lu]: %s --> %s\n", li+1, urlnum, this_url, outfile ? outfile : "<stdout>");
          if(separator)
            printf("%s%s\n", CURLseparator, this_url);
        }
        if(httpgetfields) {
          char *urlbuffer;
          
          const char *pc = strstr(this_url, "://");
          char sep = '?';
          if(pc)
            pc += 3;
          else pc = this_url;

          pc = strrchr(pc, '/'); 

          if(pc) {
            

            if(strchr(pc, '?'))
              
              sep='&';
          }
          
          if(pc)
            urlbuffer = aprintf("%s%c%s", this_url, sep, httpgetfields);
          else  urlbuffer = aprintf("%s/?%s", this_url, httpgetfields);


          if(!urlbuffer) {
            result = CURLE_OUT_OF_MEMORY;
            goto show_error;
          }

          Curl_safefree(this_url); 
          this_url = urlbuffer; 
        }

        if(!global->errors)
          global->errors = stderr;

        if((!outfile || !strcmp(outfile, "-")) && !config->use_ascii) {
          
          set_binmode(stdout);
        }

        if(config->tcp_nodelay)
          my_setopt(curl, CURLOPT_TCP_NODELAY, 1L);

        
        my_setopt(curl, CURLOPT_WRITEDATA, &outs);
        if(metalink || !config->use_metalink)
          
          my_setopt(curl, CURLOPT_WRITEFUNCTION, tool_write_cb);

        else  my_setopt(curl, CURLOPT_WRITEFUNCTION, metalink_write_cb);



        
        input.fd = infd;
        input.config = config;
        
        my_setopt(curl, CURLOPT_READDATA, &input);
        
        my_setopt(curl, CURLOPT_READFUNCTION, tool_read_cb);

        
        my_setopt(curl, CURLOPT_SEEKDATA, &input);
        my_setopt(curl, CURLOPT_SEEKFUNCTION, tool_seek_cb);

        if(config->recvpersecond)
          
          my_setopt(curl, CURLOPT_BUFFERSIZE, (long)config->recvpersecond);

        
        if(uploadfilesize != -1)
          my_setopt(curl, CURLOPT_INFILESIZE_LARGE, uploadfilesize);
        my_setopt_str(curl, CURLOPT_URL, this_url);     
        my_setopt(curl, CURLOPT_NOPROGRESS, global->noprogress?1L:0L);
        if(config->no_body) {
          my_setopt(curl, CURLOPT_NOBODY, 1L);
          my_setopt(curl, CURLOPT_HEADER, 1L);
        }
        
        else if(!config->use_metalink)
          my_setopt(curl, CURLOPT_HEADER, config->include_headers?1L:0L);

        if(config->oauth_bearer)
          my_setopt_str(curl, CURLOPT_XOAUTH2_BEARER, config->oauth_bearer);


        {
          

          my_setopt_str(curl, CURLOPT_PROXY, config->proxy);
          my_setopt_str(curl, CURLOPT_PROXYUSERPWD, config->proxyuserpwd);

          
          my_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, config->proxytunnel?1L:0L);

          
          if(config->proxy)
            my_setopt_enum(curl, CURLOPT_PROXYTYPE, (long)config->proxyver);

          
          if(config->socksproxy) {
            my_setopt_str(curl, CURLOPT_PROXY, config->socksproxy);
            my_setopt_enum(curl, CURLOPT_PROXYTYPE, (long)config->socksver);
          }

          
          if(config->proxyanyauth)
            my_setopt_bitmask(curl, CURLOPT_PROXYAUTH, (long)CURLAUTH_ANY);
          else if(config->proxynegotiate)
            my_setopt_bitmask(curl, CURLOPT_PROXYAUTH, (long)CURLAUTH_GSSNEGOTIATE);
          else if(config->proxyntlm)
            my_setopt_bitmask(curl, CURLOPT_PROXYAUTH, (long)CURLAUTH_NTLM);
          else if(config->proxydigest)
            my_setopt_bitmask(curl, CURLOPT_PROXYAUTH, (long)CURLAUTH_DIGEST);
          else if(config->proxybasic)
            my_setopt_bitmask(curl, CURLOPT_PROXYAUTH, (long)CURLAUTH_BASIC);

          
          my_setopt_str(curl, CURLOPT_NOPROXY, config->noproxy);
        }


        my_setopt(curl, CURLOPT_FAILONERROR, config->failonerror?1L:0L);
        my_setopt(curl, CURLOPT_UPLOAD, uploadfile?1L:0L);
        my_setopt(curl, CURLOPT_DIRLISTONLY, config->dirlistonly?1L:0L);
        my_setopt(curl, CURLOPT_APPEND, config->ftp_append?1L:0L);

        if(config->netrc_opt)
          my_setopt_enum(curl, CURLOPT_NETRC, (long)CURL_NETRC_OPTIONAL);
        else if(config->netrc || config->netrc_file)
          my_setopt_enum(curl, CURLOPT_NETRC, (long)CURL_NETRC_REQUIRED);
        else my_setopt_enum(curl, CURLOPT_NETRC, (long)CURL_NETRC_IGNORED);

        if(config->netrc_file)
          my_setopt_str(curl, CURLOPT_NETRC_FILE, config->netrc_file);

        my_setopt(curl, CURLOPT_TRANSFERTEXT, config->use_ascii?1L:0L);
        if(config->login_options)
          my_setopt_str(curl, CURLOPT_LOGIN_OPTIONS, config->login_options);
        my_setopt_str(curl, CURLOPT_USERPWD, config->userpwd);
        my_setopt_str(curl, CURLOPT_RANGE, config->range);
        my_setopt(curl, CURLOPT_ERRORBUFFER, errorbuffer);
        my_setopt(curl, CURLOPT_TIMEOUT_MS, (long)(config->timeout * 1000));

        if(built_in_protos & CURLPROTO_HTTP) {

          long postRedir = 0;

          my_setopt(curl, CURLOPT_FOLLOWLOCATION, config->followlocation?1L:0L);
          my_setopt(curl, CURLOPT_UNRESTRICTED_AUTH, config->unrestricted_auth?1L:0L);

          switch(config->httpreq) {
          case HTTPREQ_SIMPLEPOST:
            my_setopt_str(curl, CURLOPT_POSTFIELDS, config->postfields);
            my_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, config->postfieldsize);
            break;
          case HTTPREQ_FORMPOST:
            my_setopt_httppost(curl, CURLOPT_HTTPPOST, config->httppost);
            break;
          default:
            break;
          }

          my_setopt_str(curl, CURLOPT_REFERER, config->referer);
          my_setopt(curl, CURLOPT_AUTOREFERER, config->autoreferer?1L:0L);
          my_setopt_str(curl, CURLOPT_USERAGENT, config->useragent);
          my_setopt_slist(curl, CURLOPT_HTTPHEADER, config->headers);

          
          if(config->proxyheaders) {
            my_setopt_slist(curl, CURLOPT_PROXYHEADER, config->proxyheaders);
            my_setopt(curl, CURLOPT_HEADEROPT, CURLHEADER_SEPARATE);
          }

          
          my_setopt(curl, CURLOPT_MAXREDIRS, config->maxredirs);

          if(config->httpversion)
            my_setopt_enum(curl, CURLOPT_HTTP_VERSION, config->httpversion);
          else if(curlinfo->features & CURL_VERSION_HTTP2) {
            my_setopt_enum(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);
          }

          
          if(config->authtype)
            my_setopt_bitmask(curl, CURLOPT_HTTPAUTH, (long)config->authtype);

          
          if(config->post301)
            postRedir |= CURL_REDIR_POST_301;
          if(config->post302)
            postRedir |= CURL_REDIR_POST_302;
          if(config->post303)
            postRedir |= CURL_REDIR_POST_303;
          my_setopt(curl, CURLOPT_POSTREDIR, postRedir);

          
          if(config->encoding)
            my_setopt_str(curl, CURLOPT_ACCEPT_ENCODING, "");

          
          if(config->tr_encoding)
            my_setopt(curl, CURLOPT_TRANSFER_ENCODING, 1L);

        } 

        my_setopt_str(curl, CURLOPT_FTPPORT, config->ftpport);
        my_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, config->low_speed_limit);
        my_setopt(curl, CURLOPT_LOW_SPEED_TIME, config->low_speed_time);
        my_setopt(curl, CURLOPT_MAX_SEND_SPEED_LARGE, config->sendpersecond);
        my_setopt(curl, CURLOPT_MAX_RECV_SPEED_LARGE, config->recvpersecond);

        if(config->use_resume)
          my_setopt(curl, CURLOPT_RESUME_FROM_LARGE, config->resume_from);
        else my_setopt(curl, CURLOPT_RESUME_FROM_LARGE, CURL_OFF_T_C(0));

        my_setopt_str(curl, CURLOPT_KEYPASSWD, config->key_passwd);

        if(built_in_protos & (CURLPROTO_SCP|CURLPROTO_SFTP)) {

          
          
          my_setopt_str(curl, CURLOPT_SSH_PRIVATE_KEYFILE, config->key);
          
          my_setopt_str(curl, CURLOPT_SSH_PUBLIC_KEYFILE, config->pubkey);

          
          my_setopt_str(curl, CURLOPT_SSH_HOST_PUBLIC_KEY_MD5, config->hostpubmd5);
        }

        if(config->cacert)
          my_setopt_str(curl, CURLOPT_CAINFO, config->cacert);
        if(config->capath)
          my_setopt_str(curl, CURLOPT_CAPATH, config->capath);
        if(config->crlfile)
          my_setopt_str(curl, CURLOPT_CRLFILE, config->crlfile);

        if(config->pinnedpubkey)
          my_setopt_str(curl, CURLOPT_PINNEDPUBLICKEY, config->pinnedpubkey);

        if(curlinfo->features & CURL_VERSION_SSL) {
          my_setopt_str(curl, CURLOPT_SSLCERT, config->cert);
          my_setopt_str(curl, CURLOPT_SSLCERTTYPE, config->cert_type);
          my_setopt_str(curl, CURLOPT_SSLKEY, config->key);
          my_setopt_str(curl, CURLOPT_SSLKEYTYPE, config->key_type);

          if(config->insecure_ok) {
            my_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
            my_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
          }
          else {
            my_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
            
            
          }

          if(config->verifystatus)
            my_setopt(curl, CURLOPT_SSL_VERIFYSTATUS, 1L);

          if(config->falsestart)
            my_setopt(curl, CURLOPT_SSL_FALSESTART, 1L);

          my_setopt_enum(curl, CURLOPT_SSLVERSION, config->ssl_version);
        }
        if(config->path_as_is)
          my_setopt(curl, CURLOPT_PATH_AS_IS, 1L);

        if(built_in_protos & (CURLPROTO_SCP|CURLPROTO_SFTP)) {
          if(!config->insecure_ok) {
            char *home;
            char *file;
            result = CURLE_OUT_OF_MEMORY;
            home = homedir();
            if(home) {
              file = aprintf("%s/%sssh/known_hosts", home, DOT_CHAR);
              if(file) {
                
                result = res_setopt_str(curl, CURLOPT_SSH_KNOWNHOSTS, file);
                curl_free(file);
                if(result == CURLE_UNKNOWN_OPTION)
                  
                  result = CURLE_OK;
              }
              Curl_safefree(home);
            }
            if(result)
              goto show_error;
          }
        }

        if(config->no_body || config->remote_time) {
          
          my_setopt(curl, CURLOPT_FILETIME, 1L);
        }

        my_setopt(curl, CURLOPT_CRLF, config->crlf?1L:0L);
        my_setopt_slist(curl, CURLOPT_QUOTE, config->quote);
        my_setopt_slist(curl, CURLOPT_POSTQUOTE, config->postquote);
        my_setopt_slist(curl, CURLOPT_PREQUOTE, config->prequote);


        if(config->cookie)
          my_setopt_str(curl, CURLOPT_COOKIE, config->cookie);

        if(config->cookiefile)
          my_setopt_str(curl, CURLOPT_COOKIEFILE, config->cookiefile);

        
        if(config->cookiejar)
          my_setopt_str(curl, CURLOPT_COOKIEJAR, config->cookiejar);

        
        my_setopt(curl, CURLOPT_COOKIESESSION, config->cookiesession?1L:0L);

        if(config->cookie || config->cookiefile || config->cookiejar) {
          warnf(config->global, "cookie option(s) used even though cookie " "support is disabled!\n");
          return CURLE_NOT_BUILT_IN;
        }


        my_setopt_enum(curl, CURLOPT_TIMECONDITION, (long)config->timecond);
        my_setopt(curl, CURLOPT_TIMEVALUE, (long)config->condtime);
        my_setopt_str(curl, CURLOPT_CUSTOMREQUEST, config->customrequest);
        customrequest_helper(config, config->httpreq, config->customrequest);
        my_setopt(curl, CURLOPT_STDERR, global->errors);

        
        my_setopt_str(curl, CURLOPT_INTERFACE, config->iface);
        my_setopt_str(curl, CURLOPT_KRBLEVEL, config->krblevel);

        progressbarinit(&progressbar, config);
        if((global->progressmode == CURL_PROGRESS_BAR) && !global->noprogress && !global->mute) {
          
          my_setopt(curl, CURLOPT_XFERINFOFUNCTION, tool_progress_cb);
          my_setopt(curl, CURLOPT_XFERINFODATA, &progressbar);
        }

        
        if(config->dns_servers)
          my_setopt_str(curl, CURLOPT_DNS_SERVERS, config->dns_servers);

        
        if(config->dns_interface)
          my_setopt_str(curl, CURLOPT_DNS_INTERFACE, config->dns_interface);
        if(config->dns_ipv4_addr)
          my_setopt_str(curl, CURLOPT_DNS_LOCAL_IP4, config->dns_ipv4_addr);
        if(config->dns_ipv6_addr)
        my_setopt_str(curl, CURLOPT_DNS_LOCAL_IP6, config->dns_ipv6_addr);

        
        my_setopt_slist(curl, CURLOPT_TELNETOPTIONS, config->telnet_options);

        
        my_setopt_str(curl, CURLOPT_RANDOM_FILE, config->random_file);
        my_setopt_str(curl, CURLOPT_EGDSOCKET, config->egd_file);
        my_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, (long)(config->connecttimeout * 1000));

        if(config->cipher_list)
          my_setopt_str(curl, CURLOPT_SSL_CIPHER_LIST, config->cipher_list);

        
        if(config->disable_epsv)
          
          my_setopt(curl, CURLOPT_FTP_USE_EPSV, 0L);

        
        if(config->disable_eprt)
          
          my_setopt(curl, CURLOPT_FTP_USE_EPRT, 0L);

        if(global->tracetype != TRACE_NONE) {
          my_setopt(curl, CURLOPT_DEBUGFUNCTION, tool_debug_cb);
          my_setopt(curl, CURLOPT_DEBUGDATA, config);
          my_setopt(curl, CURLOPT_VERBOSE, 1L);
        }

        
        if(config->engine) {
          result = res_setopt_str(curl, CURLOPT_SSLENGINE, config->engine);
          if(result)
            goto show_error;
          my_setopt(curl, CURLOPT_SSLENGINE_DEFAULT, 1L);
        }

        
        my_setopt(curl, CURLOPT_FTP_CREATE_MISSING_DIRS, config->ftp_create_dirs?1L:0L);

        
        if(config->max_filesize)
          my_setopt(curl, CURLOPT_MAXFILESIZE_LARGE, config->max_filesize);

        if(4 == config->ip_version)
          my_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
        else if(6 == config->ip_version)
          my_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V6);
        else my_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_WHATEVER);

        
        if(config->ftp_ssl_reqd)
          my_setopt_enum(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);

        
        else if(config->ftp_ssl)
          my_setopt_enum(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_TRY);

        
        else if(config->ftp_ssl_control)
          my_setopt_enum(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_CONTROL);

        
        if(config->ftp_ssl_ccc)
          my_setopt_enum(curl, CURLOPT_FTP_SSL_CCC, (long)config->ftp_ssl_ccc_mode);

        
        if(config->socks5_gssapi_service)
          my_setopt_str(curl, CURLOPT_SOCKS5_GSSAPI_SERVICE, config->socks5_gssapi_service);

        
        if(config->socks5_gssapi_nec)
          my_setopt_str(curl, CURLOPT_SOCKS5_GSSAPI_NEC, config->socks5_gssapi_nec);

        
        if(config->proxy_service_name)
          my_setopt_str(curl, CURLOPT_PROXY_SERVICE_NAME, config->proxy_service_name);

        
        if(config->service_name)
          my_setopt_str(curl, CURLOPT_SERVICE_NAME, config->service_name);

        
        my_setopt_str(curl, CURLOPT_FTP_ACCOUNT, config->ftp_account);

        my_setopt(curl, CURLOPT_IGNORE_CONTENT_LENGTH, config->ignorecl?1L:0L);

        
        my_setopt(curl, CURLOPT_FTP_SKIP_PASV_IP, config->ftp_skip_ip?1L:0L);

        
        my_setopt(curl, CURLOPT_FTP_FILEMETHOD, (long)config->ftp_filemethod);

        
        if(config->localport) {
          my_setopt(curl, CURLOPT_LOCALPORT, (long)config->localport);
          my_setopt_str(curl, CURLOPT_LOCALPORTRANGE, (long)config->localportrange);
        }

        
        my_setopt_str(curl, CURLOPT_FTP_ALTERNATIVE_TO_USER, config->ftp_alternative_to_user);

        
        if(config->disable_sessionid)
          
          my_setopt(curl, CURLOPT_SSL_SESSIONID_CACHE, 0L);

        
        if(config->raw) {
          my_setopt(curl, CURLOPT_HTTP_CONTENT_DECODING, 0L);
          my_setopt(curl, CURLOPT_HTTP_TRANSFER_DECODING, 0L);
        }

        
        if(!config->nokeepalive) {
          my_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
          if(config->alivetime != 0) {
            my_setopt(curl, CURLOPT_TCP_KEEPIDLE, config->alivetime);
            my_setopt(curl, CURLOPT_TCP_KEEPINTVL, config->alivetime);
          }
        }
        else my_setopt(curl, CURLOPT_TCP_KEEPALIVE, 0L);

        
        if(config->tftp_blksize)
          my_setopt(curl, CURLOPT_TFTP_BLKSIZE, config->tftp_blksize);

        if(config->mail_from)
          my_setopt_str(curl, CURLOPT_MAIL_FROM, config->mail_from);

        if(config->mail_rcpt)
          my_setopt_slist(curl, CURLOPT_MAIL_RCPT, config->mail_rcpt);

        
        if(config->ftp_pret)
          my_setopt(curl, CURLOPT_FTP_USE_PRET, 1L);

        if(config->proto_present)
          my_setopt_flags(curl, CURLOPT_PROTOCOLS, config->proto);
        if(config->proto_redir_present)
          my_setopt_flags(curl, CURLOPT_REDIR_PROTOCOLS, config->proto_redir);

        if(config->content_disposition && (urlnode->flags & GETOUT_USEREMOTE)
           && (checkprefix("http://", this_url) || checkprefix("https://", this_url)))
          hdrcbdata.honor_cd_filename = TRUE;
        else hdrcbdata.honor_cd_filename = FALSE;

        hdrcbdata.outs = &outs;
        hdrcbdata.heads = &heads;

        my_setopt(curl, CURLOPT_HEADERFUNCTION, tool_header_cb);
        my_setopt(curl, CURLOPT_HEADERDATA, &hdrcbdata);

        if(config->resolve)
          
          my_setopt_slist(curl, CURLOPT_RESOLVE, config->resolve);

        
        if(curlinfo->features & CURL_VERSION_TLSAUTH_SRP) {
          if(config->tls_username)
            my_setopt_str(curl, CURLOPT_TLSAUTH_USERNAME, config->tls_username);
          if(config->tls_password)
            my_setopt_str(curl, CURLOPT_TLSAUTH_PASSWORD, config->tls_password);
          if(config->tls_authtype)
            my_setopt_str(curl, CURLOPT_TLSAUTH_TYPE, config->tls_authtype);
        }

        
        if(config->gssapi_delegation)
          my_setopt_str(curl, CURLOPT_GSSAPI_DELEGATION, config->gssapi_delegation);

        
        {
          long mask = (config->ssl_allow_beast ? CURLSSLOPT_ALLOW_BEAST : 0) | (config->ssl_no_revoke ? CURLSSLOPT_NO_REVOKE : 0);
          if(mask)
            my_setopt_bitmask(curl, CURLOPT_SSL_OPTIONS, mask);
        }

        if(config->mail_auth)
          my_setopt_str(curl, CURLOPT_MAIL_AUTH, config->mail_auth);

        
        if(config->sasl_ir)
          my_setopt(curl, CURLOPT_SASL_IR, 1L);

        if(config->nonpn) {
          my_setopt(curl, CURLOPT_SSL_ENABLE_NPN, 0L);
        }

        if(config->noalpn) {
          my_setopt(curl, CURLOPT_SSL_ENABLE_ALPN, 0L);
        }

        
        if(config->unix_socket_path)
          my_setopt_str(curl, CURLOPT_UNIX_SOCKET_PATH, config->unix_socket_path);

        
        if(config->proto_default)
          my_setopt_str(curl, CURLOPT_DEFAULT_PROTOCOL, config->proto_default);

        
        if(config->expect100timeout > 0)
          my_setopt_str(curl, CURLOPT_EXPECT_100_TIMEOUT_MS, (long)(config->expect100timeout*1000));

        
        retry_sleep_default = (config->retry_delay) ? config->retry_delay*1000L : RETRY_SLEEP_DEFAULT;

        retry_numretries = config->req_retry;
        retry_sleep = retry_sleep_default; 
        retrystart = tvnow();


        if(global->libcurl) {
          result = easysrc_perform();
          if(result)
            goto show_error;
        }


        for(;;) {

          if(!metalink && config->use_metalink) {
            
            if(outs.metalink_parser)
              metalink_parser_context_delete(outs.metalink_parser);
            outs.metalink_parser = metalink_parser_context_new();
            if(outs.metalink_parser == NULL) {
              result = CURLE_OUT_OF_MEMORY;
              goto show_error;
            }
            fprintf(config->global->errors, "Metalink: parsing (%s) metalink/XML...\n", this_url);
          }
          else if(metalink)
            fprintf(config->global->errors, "Metalink: fetching (%s) from (%s)...\n", mlfile->filename, this_url);




          if(config->test_event_based)
            result = curl_easy_perform_ev(curl);
          else  result = curl_easy_perform(curl);


          if(!result && !outs.stream && !outs.bytes) {
            
            long cond_unmet = 0L;
            
            curl_easy_getinfo(curl, CURLINFO_CONDITION_UNMET, &cond_unmet);
            if(!cond_unmet && !tool_create_output_file(&outs))
              result = CURLE_WRITE_ERROR;
          }

          if(outs.is_cd_filename && outs.stream && !global->mute && outs.filename)
            printf("curl: Saved to filename '%s'\n", outs.filename);

          
          if(retry_numretries && (!config->retry_maxtime || (tvdiff(tvnow(), retrystart) < config->retry_maxtime*1000L)) ) {


            enum {
              RETRY_NO, RETRY_TIMEOUT, RETRY_HTTP, RETRY_FTP, RETRY_LAST } retry = RETRY_NO;




            long response;
            if((CURLE_OPERATION_TIMEDOUT == result) || (CURLE_COULDNT_RESOLVE_HOST == result) || (CURLE_COULDNT_RESOLVE_PROXY == result) || (CURLE_FTP_ACCEPT_TIMEOUT == result))


              
              retry = RETRY_TIMEOUT;
            else if((CURLE_OK == result) || (config->failonerror && (CURLE_HTTP_RETURNED_ERROR == result))) {

              
              char *effective_url = NULL;
              curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &effective_url);
              if(effective_url && checkprefix("http", effective_url)) {
                
                curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response);

                switch(response) {
                case 500: 
                case 502: 
                case 503: 
                case 504: 
                  retry = RETRY_HTTP;
                  
                  break;
                }
              }
            } 
            else if(result) {
              curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response);

              if(response/100 == 4)
                
                retry = RETRY_FTP;
            }

            if(retry) {
              static const char * const m[]={
                NULL, "timeout", "HTTP error", "FTP error" };

              warnf(config->global, "Transient problem: %s " "Will retry in %ld seconds. " "%ld retries left.\n", m[retry], retry_sleep/1000L, retry_numretries);



              tool_go_sleep(retry_sleep);
              retry_numretries--;
              if(!config->retry_delay) {
                retry_sleep *= 2;
                if(retry_sleep > RETRY_SLEEP_MAX)
                  retry_sleep = RETRY_SLEEP_MAX;
              }
              if(outs.bytes && outs.filename && outs.stream) {
                
                if(!global->mute)
                  fprintf(global->errors, "Throwing away %" CURL_FORMAT_CURL_OFF_T " bytes\n", outs.bytes);

                fflush(outs.stream);
                

                if(ftruncate( fileno(outs.stream), outs.init)) {
                  
                  if(!global->mute)
                    fprintf(global->errors, "failed to truncate, exiting\n");
                  result = CURLE_WRITE_ERROR;
                  goto quit_urls;
                }
                
                fseek(outs.stream, 0, SEEK_END);

                
                fseek(outs.stream, (long)outs.init, SEEK_SET);

                outs.bytes = 0; 
              }
              continue; 
            }
          } 
          else if(metalink) {
            
            long response;
            if(CURLE_OK == result) {
              
              char *effective_url = NULL;
              curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &effective_url);
              if(effective_url && curlx_strnequal(effective_url, "http", 4)) {
                
                curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response);
                if(response != 200 && response != 206) {
                  metalink_next_res = 1;
                  fprintf(global->errors, "Metalink: fetching (%s) from (%s) FAILED " "(HTTP status code %d)\n", mlfile->filename, this_url, response);


                }
              }
            }
            else {
              metalink_next_res = 1;
              fprintf(global->errors, "Metalink: fetching (%s) from (%s) FAILED (%s)\n", mlfile->filename, this_url, (errorbuffer[0]) ? errorbuffer : curl_easy_strerror(result));



            }
          }
          if(metalink && !metalink_next_res)
            fprintf(global->errors, "Metalink: fetching (%s) from (%s) OK\n", mlfile->filename, this_url);

          
          break; 

        }

        if((global->progressmode == CURL_PROGRESS_BAR) && progressbar.calls)
          
          fputs("\n", progressbar.out);

        if(config->writeout)
          ourWriteOut(curl, &outs, config->writeout);

        if(config->writeenv)
          ourWriteEnv(curl);

        

        show_error:


        if(is_vms_shell()) {
          
          if(!global->showerror)
            vms_show = VMSSTS_HIDE;
        }
        else  if(result && global->showerror) {

          fprintf(global->errors, "curl: (%d) %s\n", result, (errorbuffer[0]) ? errorbuffer : curl_easy_strerror(result));
          if(result == CURLE_SSL_CACERT)
            fprintf(global->errors, "%s%s", CURL_CA_CERT_ERRORMSG1, CURL_CA_CERT_ERRORMSG2);
        }

        

        

        quit_urls:

        
        if(!result && config->xattr && outs.fopened && outs.stream) {
          int rc = fwrite_xattr(curl, fileno(outs.stream));
          if(rc)
            warnf(config->global, "Error setting extended attributes: %s\n", strerror(errno));
        }

        
        if(outs.fopened && outs.stream) {
          int rc = fclose(outs.stream);
          if(!result && rc) {
            
            result = CURLE_WRITE_ERROR;
            fprintf(global->errors, "(%d) Failed writing body\n", result);
          }
        }
        else if(!outs.s_isreg && outs.stream) {
          
          int rc = fflush(outs.stream);
          if(!result && rc) {
            
            result = CURLE_WRITE_ERROR;
            fprintf(global->errors, "(%d) Failed writing body\n", result);
          }
        }


        if(!result && outs.s_isreg && outs.filename) {
          
          if(strlen(url) > 78)
            url[79] = '\0';
          SetComment(outs.filename, url);
        }



        
        if(!result && config->remote_time && outs.s_isreg && outs.filename) {
          
          long filetime = -1;
          curl_easy_getinfo(curl, CURLINFO_FILETIME, &filetime);
          if(filetime >= 0) {
            struct utimbuf times;
            times.actime = (time_t)filetime;
            times.modtime = (time_t)filetime;
            utime(outs.filename, &times); 
          }
        }



        if(!metalink && config->use_metalink && result == CURLE_OK) {
          int rv = parse_metalink(config, &outs, this_url);
          if(rv == 0)
            fprintf(config->global->errors, "Metalink: parsing (%s) OK\n", this_url);
          else if(rv == -1)
            fprintf(config->global->errors, "Metalink: parsing (%s) FAILED\n", this_url);
        }
        else if(metalink && result == CURLE_OK && !metalink_next_res) {
          int rv = metalink_check_hash(global, mlfile, outs.filename);
          if(rv == 0) {
            metalink_next_res = 1;
          }
        }


        
        if(outs.alloc_filename)
          Curl_safefree(outs.filename);

        if(outs.metalink_parser)
          metalink_parser_context_delete(outs.metalink_parser);

        memset(&outs, 0, sizeof(struct OutStruct));
        hdrcbdata.outs = NULL;

        

        Curl_safefree(outfile);
        Curl_safefree(this_url);

        if(infdopen)
          close(infd);

        if(metalink) {
          
          if(is_fatal_error(result)) {
            break;
          }
          if(!metalink_next_res)
            break;
          mlres = mlres->next;
          if(mlres == NULL)
            
            break;
        }
        else if(urlnum > 1) {
          
          if(is_fatal_error(result))
            break;
        }
        else if(result)
          
          break;

      } 

      

      Curl_safefree(uploadfile);

      if(urls) {
        
        glob_cleanup(urls);
        urls = NULL;
      }

      if(infilenum > 1) {
        
        if(is_fatal_error(result))
          break;
      }
      else if(result)
        
        break;

    } 

    

    Curl_safefree(outfiles);

    if(inglob) {
      
      glob_cleanup(inglob);
      inglob = NULL;
    }

    
    Curl_safefree(urlnode->url);
    Curl_safefree(urlnode->outfile);
    Curl_safefree(urlnode->infile);
    urlnode->flags = 0;

    
    if(is_fatal_error(result))
      goto quit_curl;

  } 

  

  quit_curl:

  
  global->noprogress = orig_noprogress;
  global->isatty = orig_isatty;

  
  Curl_safefree(httpgetfields);

  
  clean_getout(config);

  hdrcbdata.heads = NULL;

  
  if(heads.fopened && heads.stream)
    fclose(heads.stream);

  if(heads.alloc_filename)
    Curl_safefree(heads.filename);

  
  clean_metalink(config);

  return result;
}

CURLcode operate(struct GlobalConfig *config, int argc, argv_item_t argv[])
{
  CURLcode result = CURLE_OK;

  

  setlocale(LC_ALL, "");


  
  if((argc == 1) || (!curlx_strequal(argv[1], "-q"))) {
    parseconfig(NULL, config); 

    
    if((argc < 2) && (!config->first->url_list)) {
      helpf(config->errors, NULL);
      result = CURLE_FAILED_INIT;
    }
  }

  if(!result) {
    
    ParameterError res = parse_args(config, argc, argv);
    if(res) {
      result = CURLE_OK;

      
      if(res == PARAM_HELP_REQUESTED)
        tool_help();
      
      else if(res == PARAM_MANUAL_REQUESTED)
        hugehelp();
      
      else if(res == PARAM_VERSION_INFO_REQUESTED)
        tool_version_info();
      
      else if(res == PARAM_ENGINES_REQUESTED)
        tool_list_engines(config->easy);
      else if(res == PARAM_LIBCURL_UNSUPPORTED_PROTOCOL)
        result = CURLE_UNSUPPORTED_PROTOCOL;
      else result = CURLE_FAILED_INIT;
    }
    else {

      if(config->libcurl) {
        
        result = easysrc_init();
      }


      
      if(!result) {
        size_t count = 0;
        struct OperationConfig *operation = config->first;

        
        while(!result && operation) {
          result = get_args(operation, count++);

          operation = operation->next;
        }

        
        config->current = config->first;

        
        while(!result && config->current) {
          result = operate_do(config, config->current);

          config->current = config->current->next;
        }


        if(config->libcurl) {
          
          easysrc_cleanup();

          
          dumpeasysrc(config);
        }

      }
      else helpf(config->errors, "out of memory\n");
    }
  }

  return result;
}
