








































struct LongShort {
  const char *letter; 
  const char *lname;  
  enum {
    ARG_NONE,    ARG_BOOL, ARG_STRING, ARG_FILENAME } desc;



};

static const struct LongShort aliases[]= {
  
  {"*@", "url",                      ARG_STRING}, {"*4", "dns-ipv4-addr",            ARG_STRING}, {"*6", "dns-ipv6-addr",            ARG_STRING}, {"*a", "random-file",              ARG_FILENAME}, {"*b", "egd-file",                 ARG_STRING}, {"*B", "oauth2-bearer",            ARG_STRING}, {"*c", "connect-timeout",          ARG_STRING}, {"*C", "doh-url"        ,          ARG_STRING}, {"*d", "ciphers",                  ARG_STRING}, {"*D", "dns-interface",            ARG_STRING}, {"*e", "disable-epsv",             ARG_BOOL}, {"*f", "disallow-username-in-url", ARG_BOOL}, {"*E", "epsv",                     ARG_BOOL},  {"*F", "dns-servers",              ARG_STRING}, {"*g", "trace",                    ARG_FILENAME}, {"*G", "npn",                      ARG_BOOL}, {"*h", "trace-ascii",              ARG_FILENAME}, {"*H", "alpn",                     ARG_BOOL}, {"*i", "limit-rate",               ARG_STRING}, {"*j", "compressed",               ARG_BOOL}, {"*J", "tr-encoding",              ARG_BOOL}, {"*k", "digest",                   ARG_BOOL}, {"*l", "negotiate",                ARG_BOOL}, {"*m", "ntlm",                     ARG_BOOL}, {"*M", "ntlm-wb",                  ARG_BOOL}, {"*n", "basic",                    ARG_BOOL}, {"*o", "anyauth",                  ARG_BOOL},  {"*p", "wdebug",                   ARG_BOOL},  {"*q", "ftp-create-dirs",          ARG_BOOL}, {"*r", "create-dirs",              ARG_BOOL}, {"*s", "max-redirs",               ARG_STRING}, {"*t", "proxy-ntlm",               ARG_BOOL}, {"*u", "crlf",                     ARG_BOOL}, {"*v", "stderr",                   ARG_FILENAME}, {"*w", "interface",                ARG_STRING}, {"*x", "krb",                      ARG_STRING}, {"*x", "krb4",                     ARG_STRING},  {"*X", "haproxy-protocol",         ARG_BOOL}, {"*y", "max-filesize",             ARG_STRING}, {"*z", "disable-eprt",             ARG_BOOL}, {"*Z", "eprt",                     ARG_BOOL},  {"*~", "xattr",                    ARG_BOOL}, {"$a", "ftp-ssl",                  ARG_BOOL},  {"$a", "ssl",                      ARG_BOOL},  {"$b", "ftp-pasv",                 ARG_BOOL}, {"$c", "socks5",                   ARG_STRING}, {"$d", "tcp-nodelay",              ARG_BOOL}, {"$e", "proxy-digest",             ARG_BOOL}, {"$f", "proxy-basic",              ARG_BOOL}, {"$g", "retry",                    ARG_STRING}, {"$V", "retry-connrefused",        ARG_BOOL}, {"$h", "retry-delay",              ARG_STRING}, {"$i", "retry-max-time",           ARG_STRING}, {"$k", "proxy-negotiate",          ARG_BOOL}, {"$m", "ftp-account",              ARG_STRING}, {"$n", "proxy-anyauth",            ARG_BOOL}, {"$o", "trace-time",               ARG_BOOL}, {"$p", "ignore-content-length",    ARG_BOOL}, {"$q", "ftp-skip-pasv-ip",         ARG_BOOL}, {"$r", "ftp-method",               ARG_STRING}, {"$s", "local-port",               ARG_STRING}, {"$t", "socks4",                   ARG_STRING}, {"$T", "socks4a",                  ARG_STRING}, {"$u", "ftp-alternative-to-user",  ARG_STRING}, {"$v", "ftp-ssl-reqd",             ARG_BOOL},  {"$v", "ssl-reqd",                 ARG_BOOL},  {"$w", "sessionid",                ARG_BOOL},  {"$x", "ftp-ssl-control",          ARG_BOOL}, {"$y", "ftp-ssl-ccc",              ARG_BOOL}, {"$j", "ftp-ssl-ccc-mode",         ARG_STRING}, {"$z", "libcurl",                  ARG_STRING}, {"$#", "raw",                      ARG_BOOL}, {"$0", "post301",                  ARG_BOOL}, {"$1", "keepalive",                ARG_BOOL},  {"$2", "socks5-hostname",          ARG_STRING}, {"$3", "keepalive-time",           ARG_STRING}, {"$4", "post302",                  ARG_BOOL}, {"$5", "noproxy",                  ARG_STRING}, {"$7", "socks5-gssapi-nec",        ARG_BOOL}, {"$8", "proxy1.0",                 ARG_STRING}, {"$9", "tftp-blksize",             ARG_STRING}, {"$A", "mail-from",                ARG_STRING}, {"$B", "mail-rcpt",                ARG_STRING}, {"$C", "ftp-pret",                 ARG_BOOL}, {"$D", "proto",                    ARG_STRING}, {"$E", "proto-redir",              ARG_STRING}, {"$F", "resolve",                  ARG_STRING}, {"$G", "delegation",               ARG_STRING}, {"$H", "mail-auth",                ARG_STRING}, {"$I", "post303",                  ARG_BOOL}, {"$J", "metalink",                 ARG_BOOL}, {"$6", "sasl-authzid",             ARG_STRING}, {"$K", "sasl-ir",                  ARG_BOOL }, {"$L", "test-event",               ARG_BOOL}, {"$M", "unix-socket",              ARG_FILENAME}, {"$N", "path-as-is",               ARG_BOOL}, {"$O", "socks5-gssapi-service",    ARG_STRING},  {"$O", "proxy-service-name",       ARG_STRING}, {"$P", "service-name",             ARG_STRING}, {"$Q", "proto-default",            ARG_STRING}, {"$R", "expect100-timeout",        ARG_STRING}, {"$S", "tftp-no-options",          ARG_BOOL}, {"$U", "connect-to",               ARG_STRING}, {"$W", "abstract-unix-socket",     ARG_FILENAME}, {"$X", "tls-max",                  ARG_STRING}, {"$Y", "suppress-connect-headers", ARG_BOOL}, {"$Z", "compressed-ssh",           ARG_BOOL}, {"$~", "happy-eyeballs-timeout-ms", ARG_STRING}, {"$!", "retry-all-errors",         ARG_BOOL}, {"0",   "http1.0",                 ARG_NONE}, {"01",  "http1.1",                 ARG_NONE}, {"02",  "http2",                   ARG_NONE}, {"03",  "http2-prior-knowledge",   ARG_NONE}, {"04",  "http3",                   ARG_NONE}, {"09",  "http0.9",                 ARG_BOOL}, {"1",  "tlsv1",                    ARG_NONE}, {"10",  "tlsv1.0",                 ARG_NONE}, {"11",  "tlsv1.1",                 ARG_NONE}, {"12",  "tlsv1.2",                 ARG_NONE}, {"13",  "tlsv1.3",                 ARG_NONE}, {"1A", "tls13-ciphers",            ARG_STRING}, {"1B", "proxy-tls13-ciphers",      ARG_STRING}, {"2",  "sslv2",                    ARG_NONE}, {"3",  "sslv3",                    ARG_NONE}, {"4",  "ipv4",                     ARG_NONE}, {"6",  "ipv6",                     ARG_NONE}, {"a",  "append",                   ARG_BOOL}, {"A",  "user-agent",               ARG_STRING}, {"b",  "cookie",                   ARG_STRING}, {"ba", "alt-svc",                  ARG_STRING}, {"B",  "use-ascii",                ARG_BOOL}, {"c",  "cookie-jar",               ARG_STRING}, {"C",  "continue-at",              ARG_STRING}, {"d",  "data",                     ARG_STRING}, {"dr", "data-raw",                 ARG_STRING}, {"da", "data-ascii",               ARG_STRING}, {"db", "data-binary",              ARG_STRING}, {"de", "data-urlencode",           ARG_STRING}, {"D",  "dump-header",              ARG_FILENAME}, {"e",  "referer",                  ARG_STRING}, {"E",  "cert",                     ARG_FILENAME}, {"Ea", "cacert",                   ARG_FILENAME}, {"Eb", "cert-type",                ARG_STRING}, {"Ec", "key",                      ARG_FILENAME}, {"Ed", "key-type",                 ARG_STRING}, {"Ee", "pass",                     ARG_STRING}, {"Ef", "engine",                   ARG_STRING}, {"Eg", "capath",                   ARG_FILENAME}, {"Eh", "pubkey",                   ARG_STRING}, {"Ei", "hostpubmd5",               ARG_STRING}, {"Ej", "crlfile",                  ARG_FILENAME}, {"Ek", "tlsuser",                  ARG_STRING}, {"El", "tlspassword",              ARG_STRING}, {"Em", "tlsauthtype",              ARG_STRING}, {"En", "ssl-allow-beast",          ARG_BOOL},  {"Ep", "pinnedpubkey",             ARG_STRING}, {"EP", "proxy-pinnedpubkey",       ARG_STRING}, {"Eq", "cert-status",              ARG_BOOL}, {"Er", "false-start",              ARG_BOOL}, {"Es", "ssl-no-revoke",            ARG_BOOL}, {"ES", "ssl-revoke-best-effort",   ARG_BOOL}, {"Et", "tcp-fastopen",             ARG_BOOL}, {"Eu", "proxy-tlsuser",            ARG_STRING}, {"Ev", "proxy-tlspassword",        ARG_STRING}, {"Ew", "proxy-tlsauthtype",        ARG_STRING}, {"Ex", "proxy-cert",               ARG_FILENAME}, {"Ey", "proxy-cert-type",          ARG_STRING}, {"Ez", "proxy-key",                ARG_FILENAME}, {"E0", "proxy-key-type",           ARG_STRING}, {"E1", "proxy-pass",               ARG_STRING}, {"E2", "proxy-ciphers",            ARG_STRING}, {"E3", "proxy-crlfile",            ARG_FILENAME}, {"E4", "proxy-ssl-allow-beast",    ARG_BOOL}, {"E5", "login-options",            ARG_STRING}, {"E6", "proxy-cacert",             ARG_FILENAME}, {"E7", "proxy-capath",             ARG_FILENAME}, {"E8", "proxy-insecure",           ARG_BOOL}, {"E9", "proxy-tlsv1",              ARG_NONE}, {"EA", "socks5-basic",             ARG_BOOL}, {"EB", "socks5-gssapi",            ARG_BOOL}, {"EC", "etag-save",                ARG_FILENAME}, {"ED", "etag-compare",             ARG_FILENAME}, {"f",  "fail",                     ARG_BOOL}, {"fa", "fail-early",               ARG_BOOL}, {"fb", "styled-output",            ARG_BOOL}, {"fc", "mail-rcpt-allowfails",     ARG_BOOL}, {"F",  "form",                     ARG_STRING}, {"Fs", "form-string",              ARG_STRING}, {"g",  "globoff",                  ARG_BOOL}, {"G",  "get",                      ARG_NONE}, {"Ga", "request-target",           ARG_STRING}, {"h",  "help",                     ARG_BOOL}, {"H",  "header",                   ARG_STRING}, {"Hp", "proxy-header",             ARG_STRING}, {"i",  "include",                  ARG_BOOL}, {"I",  "head",                     ARG_BOOL}, {"j",  "junk-session-cookies",     ARG_BOOL}, {"J",  "remote-header-name",       ARG_BOOL}, {"k",  "insecure",                 ARG_BOOL}, {"K",  "config",                   ARG_FILENAME}, {"l",  "list-only",                ARG_BOOL}, {"L",  "location",                 ARG_BOOL}, {"Lt", "location-trusted",         ARG_BOOL}, {"m",  "max-time",                 ARG_STRING}, {"M",  "manual",                   ARG_BOOL}, {"n",  "netrc",                    ARG_BOOL}, {"no", "netrc-optional",           ARG_BOOL}, {"ne", "netrc-file",               ARG_FILENAME}, {"N",  "buffer",                   ARG_BOOL},  {"o",  "output",                   ARG_FILENAME}, {"O",  "remote-name",              ARG_NONE}, {"Oa", "remote-name-all",          ARG_BOOL}, {"p",  "proxytunnel",              ARG_BOOL}, {"P",  "ftp-port",                 ARG_STRING}, {"q",  "disable",                  ARG_BOOL}, {"Q",  "quote",                    ARG_STRING}, {"r",  "range",                    ARG_STRING}, {"R",  "remote-time",              ARG_BOOL}, {"s",  "silent",                   ARG_BOOL}, {"S",  "show-error",               ARG_BOOL}, {"t",  "telnet-option",            ARG_STRING}, {"T",  "upload-file",              ARG_FILENAME}, {"u",  "user",                     ARG_STRING}, {"U",  "proxy-user",               ARG_STRING}, {"v",  "verbose",                  ARG_BOOL}, {"V",  "version",                  ARG_BOOL}, {"w",  "write-out",                ARG_STRING}, {"x",  "proxy",                    ARG_STRING}, {"xa", "preproxy",                 ARG_STRING}, {"X",  "request",                  ARG_STRING}, {"Y",  "speed-limit",              ARG_STRING}, {"y",  "speed-time",               ARG_STRING}, {"z",  "time-cond",                ARG_STRING}, {"Z",  "parallel",                 ARG_BOOL}, {"Zb", "parallel-max",             ARG_STRING}, {"Zc", "parallel-immediate",       ARG_BOOL}, {"#",  "progress-bar",             ARG_BOOL}, {"#m", "progress-meter",           ARG_BOOL}, {":",  "next",                     ARG_NONE}, };































































































































































































































































static  void parse_cert_parameter(const char *cert_parameter, char **certname, char **passphrase)



{
  size_t param_length = strlen(cert_parameter);
  size_t span;
  const char *param_place = NULL;
  char *certname_place = NULL;
  *certname = NULL;
  *passphrase = NULL;

  
  if(param_length == 0)
    return;

  
  if(curl_strnequal(cert_parameter, "pkcs11:", 7) || !strpbrk(cert_parameter, ":\\")) {
    *certname = strdup(cert_parameter);
    return;
  }
  
  certname_place = malloc(param_length + 1);
  if(!certname_place)
    return;

  *certname = certname_place;
  param_place = cert_parameter;
  while(*param_place) {
    span = strcspn(param_place, ":\\");
    strncpy(certname_place, param_place, span);
    param_place += span;
    certname_place += span;
    
    switch(*param_place) {
    case '\0':
      break;
    case '\\':
      param_place++;
      switch(*param_place) {
        case '\0':
          *certname_place++ = '\\';
          break;
        case '\\':
          *certname_place++ = '\\';
          param_place++;
          break;
        case ':':
          *certname_place++ = ':';
          param_place++;
          break;
        default:
          *certname_place++ = '\\';
          *certname_place++ = *param_place;
          param_place++;
          break;
      }
      break;
    case ':':
      

      if(param_place && (param_place == &cert_parameter[1]) && (cert_parameter[2] == '\\' || cert_parameter[2] == '/') && (ISALPHA(cert_parameter[0])) ) {


        
        *certname_place++ = ':';
        param_place++;
        break;
      }

      
      param_place++;
      if(*param_place) {
        *passphrase = strdup(param_place);
      }
      goto done;
    }
  }
done:
  *certname_place = '\0';
}

static void GetFileAndPassword(char *nextarg, char **file, char **password)
{
  char *certname, *passphrase;
  parse_cert_parameter(nextarg, &certname, &passphrase);
  Curl_safefree(*file);
  *file = certname;
  if(passphrase) {
    Curl_safefree(*password);
    *password = passphrase;
  }
  cleanarg(nextarg);
}


static ParameterError GetSizeParameter(struct GlobalConfig *global, const char *arg, const char *which, curl_off_t *value_out)


{
  char *unit;
  curl_off_t value;

  if(curlx_strtoofft(arg, &unit, 0, &value)) {
    warnf(global, "invalid number specified for %s\n", which);
    return PARAM_BAD_USE;
  }

  if(!*unit)
    unit = (char *)"b";
  else if(strlen(unit) > 1)
    unit = (char *)"w"; 

  switch(*unit) {
  case 'G':
  case 'g':
    if(value > (CURL_OFF_T_MAX / (1024*1024*1024)))
      return PARAM_NUMBER_TOO_LARGE;
    value *= 1024*1024*1024;
    break;
  case 'M':
  case 'm':
    if(value > (CURL_OFF_T_MAX / (1024*1024)))
      return PARAM_NUMBER_TOO_LARGE;
    value *= 1024*1024;
    break;
  case 'K':
  case 'k':
    if(value > (CURL_OFF_T_MAX / 1024))
      return PARAM_NUMBER_TOO_LARGE;
    value *= 1024;
    break;
  case 'b':
  case 'B':
    
    break;
  default:
    warnf(global, "unsupported %s unit. Use G, M, K or B!\n", which);
    return PARAM_BAD_USE;
  }
  *value_out = value;
  return PARAM_OK;
}

ParameterError getparameter(const char *flag,  char *nextarg, bool *usedarg, struct GlobalConfig *global, struct OperationConfig *config)



{
  char letter;
  char subletter = '\0'; 
  int rc;
  const char *parse = NULL;
  unsigned int j;
  time_t now;
  int hit = -1;
  bool longopt = FALSE;
  bool singleopt = FALSE; 
  ParameterError err;
  bool toggle = TRUE; 

  *usedarg = FALSE; 

  if(('-' != flag[0]) || ('-' == flag[1])) {
    
    const char *word = ('-' == flag[0]) ? flag + 2 : flag;
    size_t fnam = strlen(word);
    int numhits = 0;
    bool noflagged = FALSE;

    if(!strncmp(word, "no-", 3)) {
      
      word += 3;
      toggle = FALSE;
      noflagged = TRUE;
    }

    for(j = 0; j < sizeof(aliases)/sizeof(aliases[0]); j++) {
      if(curl_strnequal(aliases[j].lname, word, fnam)) {
        longopt = TRUE;
        numhits++;
        if(curl_strequal(aliases[j].lname, word)) {
          parse = aliases[j].letter;
          hit = j;
          numhits = 1; 
          break;
        }
        parse = aliases[j].letter;
        hit = j;
      }
    }
    if(numhits > 1) {
      
      return PARAM_OPTION_AMBIGUOUS;
    }
    if(hit < 0) {
      return PARAM_OPTION_UNKNOWN;
    }
    if(noflagged && (aliases[hit].desc != ARG_BOOL))
      
      return PARAM_NO_NOT_BOOLEAN;
  }
  else {
    flag++; 
    hit = -1;
    parse = flag;
  }

  do {
    

    if(!longopt) {
      letter = (char)*parse;
      subletter = '\0';
    }
    else {
      letter = parse[0];
      subletter = parse[1];
    }

    if(hit < 0) {
      for(j = 0; j < sizeof(aliases)/sizeof(aliases[0]); j++) {
        if(letter == aliases[j].letter[0]) {
          hit = j;
          break;
        }
      }
      if(hit < 0) {
        return PARAM_OPTION_UNKNOWN;
      }
    }

    if(aliases[hit].desc >= ARG_STRING) {
      
      if(!longopt && parse[1]) {
        nextarg = (char *)&parse[1]; 
        singleopt = TRUE;   
      }
      else if(!nextarg)
        return PARAM_REQUIRES_PARAMETER;
      else *usedarg = TRUE;

      if((aliases[hit].desc == ARG_FILENAME) && (nextarg[0] == '-') && nextarg[1]) {
        
        warnf(global, "The file name argument '%s' looks like a flag.\n", nextarg);
      }
    }
    else if((aliases[hit].desc == ARG_NONE) && !toggle)
      return PARAM_NO_PREFIX;

    switch(letter) {
    case '*': 
      switch(subletter) {
      case '4': 
        
        GetStr(&config->dns_ipv4_addr, nextarg);
        break;
      case '6': 
        
        GetStr(&config->dns_ipv6_addr, nextarg);
        break;
      case 'a': 
        GetStr(&config->random_file, nextarg);
        break;
      case 'b': 
        GetStr(&config->egd_file, nextarg);
        break;
      case 'B': 
        GetStr(&config->oauth_bearer, nextarg);
        config->authtype |= CURLAUTH_BEARER;
        break;
      case 'c': 
        err = str2udouble(&config->connecttimeout, nextarg, LONG_MAX/1000);
        if(err)
          return err;
        break;
      case 'C': 
        GetStr(&config->doh_url, nextarg);
        break;
      case 'd': 
        GetStr(&config->cipher_list, nextarg);
        break;
      case 'D': 
        
        GetStr(&config->dns_interface, nextarg);
        break;
      case 'e': 
        config->disable_epsv = toggle;
        break;
      case 'f': 
        config->disallow_username_in_url = toggle;
        break;
      case 'E': 
        config->disable_epsv = (!toggle)?TRUE:FALSE;
        break;
      case 'F': 
        
        GetStr(&config->dns_servers, nextarg);
        break;
      case 'g': 
        GetStr(&global->trace_dump, nextarg);
        if(global->tracetype && (global->tracetype != TRACE_BIN))
          warnf(global, "--trace overrides an earlier trace/verbose option\n");
        global->tracetype = TRACE_BIN;
        break;
      case 'G': 
        config->nonpn = (!toggle)?TRUE:FALSE;
        break;
      case 'h': 
        GetStr(&global->trace_dump, nextarg);
        if(global->tracetype && (global->tracetype != TRACE_ASCII))
          warnf(global, "--trace-ascii overrides an earlier trace/verbose option\n");
        global->tracetype = TRACE_ASCII;
        break;
      case 'H': 
        config->noalpn = (!toggle)?TRUE:FALSE;
        break;
      case 'i': 
      {
        curl_off_t value;
        ParameterError pe = GetSizeParameter(global, nextarg, "rate", &value);

        if(pe != PARAM_OK)
           return pe;
        config->recvpersecond = value;
        config->sendpersecond = value;
      }
      break;

      case 'j': 
        if(toggle && !(curlinfo->features & (CURL_VERSION_LIBZ | CURL_VERSION_BROTLI)))
          return PARAM_LIBCURL_DOESNT_SUPPORT;
        config->encoding = toggle;
        break;

      case 'J': 
        config->tr_encoding = toggle;
        break;

      case 'k': 
        if(toggle)
          config->authtype |= CURLAUTH_DIGEST;
        else config->authtype &= ~CURLAUTH_DIGEST;
        break;

      case 'l': 
        if(toggle) {
          if(curlinfo->features & CURL_VERSION_SPNEGO)
            config->authtype |= CURLAUTH_NEGOTIATE;
          else return PARAM_LIBCURL_DOESNT_SUPPORT;
        }
        else config->authtype &= ~CURLAUTH_NEGOTIATE;
        break;

      case 'm': 
        if(toggle) {
          if(curlinfo->features & CURL_VERSION_NTLM)
            config->authtype |= CURLAUTH_NTLM;
          else return PARAM_LIBCURL_DOESNT_SUPPORT;
        }
        else config->authtype &= ~CURLAUTH_NTLM;
        break;

      case 'M': 
        if(toggle) {
          if(curlinfo->features & CURL_VERSION_NTLM_WB)
            config->authtype |= CURLAUTH_NTLM_WB;
          else return PARAM_LIBCURL_DOESNT_SUPPORT;
        }
        else config->authtype &= ~CURLAUTH_NTLM_WB;
        break;

      case 'n': 
        if(toggle)
          config->authtype |= CURLAUTH_BASIC;
        else config->authtype &= ~CURLAUTH_BASIC;
        break;

      case 'o': 
        if(toggle)
          config->authtype = CURLAUTH_ANY;
        
        break;


      case 'p': 
        dbug_init();
        break;

      case 'q': 
        config->ftp_create_dirs = toggle;
        break;

      case 'r': 
        config->create_dirs = toggle;
        break;

      case 's': 
        
        err = str2num(&config->maxredirs, nextarg);
        if(err)
          return err;
        if(config->maxredirs < -1)
          return PARAM_BAD_NUMERIC;
        break;

      case 't': 
        if(curlinfo->features & CURL_VERSION_NTLM)
          config->proxyntlm = toggle;
        else return PARAM_LIBCURL_DOESNT_SUPPORT;
        break;

      case 'u': 
        
        config->crlf = toggle;
        break;

      case 'v': 
        if(strcmp(nextarg, "-")) {
          FILE *newfile = fopen(nextarg, FOPEN_WRITETEXT);
          if(!newfile)
            warnf(global, "Failed to open %s!\n", nextarg);
          else {
            if(global->errors_fopened)
              fclose(global->errors);
            global->errors = newfile;
            global->errors_fopened = TRUE;
          }
        }
        else global->errors = stdout;
        break;
      case 'w': 
        
        GetStr(&config->iface, nextarg);
        break;
      case 'x': 
        
        if(curlinfo->features & CURL_VERSION_KERBEROS4)
          GetStr(&config->krblevel, nextarg);
        else return PARAM_LIBCURL_DOESNT_SUPPORT;
        break;
      case 'X': 
        config->haproxy_protocol = toggle;
        break;
      case 'y': 
        {
          curl_off_t value;
          ParameterError pe = GetSizeParameter(global, nextarg, "max-filesize", &value);

          if(pe != PARAM_OK)
             return pe;
          config->max_filesize = value;
        }
        break;
      case 'z': 
        config->disable_eprt = toggle;
        break;
      case 'Z': 
        config->disable_eprt = (!toggle)?TRUE:FALSE;
        break;
      case '~': 
        config->xattr = toggle;
        break;
      case '@': 
      {
        struct getout *url;

        if(!config->url_get)
          config->url_get = config->url_list;

        if(config->url_get) {
          
          while(config->url_get && (config->url_get->flags & GETOUT_URL))
            config->url_get = config->url_get->next;
        }

        

        if(config->url_get)
          
          url = config->url_get;
        else  config->url_get = url = new_getout(config);


        if(!url)
          return PARAM_NO_MEM;

        
        GetStr(&url->url, nextarg);
        url->flags |= GETOUT_URL;
      }
      }
      break;
    case '$': 
      switch(subletter) {
      case 'a': 
        if(toggle && !(curlinfo->features & CURL_VERSION_SSL))
          return PARAM_LIBCURL_DOESNT_SUPPORT;
        config->ftp_ssl = toggle;
        break;
      case 'b': 
        Curl_safefree(config->ftpport);
        break;
      case 'c': 
        GetStr(&config->proxy, nextarg);
        config->proxyver = CURLPROXY_SOCKS5;
        break;
      case 't': 
        GetStr(&config->proxy, nextarg);
        config->proxyver = CURLPROXY_SOCKS4;
        break;
      case 'T': 
        GetStr(&config->proxy, nextarg);
        config->proxyver = CURLPROXY_SOCKS4A;
        break;
      case '2': 
        GetStr(&config->proxy, nextarg);
        config->proxyver = CURLPROXY_SOCKS5_HOSTNAME;
        break;
      case 'd': 
        config->tcp_nodelay = toggle;
        break;
      case 'e': 
        config->proxydigest = toggle;
        break;
      case 'f': 
        config->proxybasic = toggle;
        break;
      case 'g': 
        err = str2unum(&config->req_retry, nextarg);
        if(err)
          return err;
        break;
      case 'V': 
        config->retry_connrefused = toggle;
        break;
      case 'h': 
        err = str2unummax(&config->retry_delay, nextarg, LONG_MAX/1000);
        if(err)
          return err;
        break;
      case 'i': 
        err = str2unummax(&config->retry_maxtime, nextarg, LONG_MAX/1000);
        if(err)
          return err;
        break;
      case '!': 
        config->retry_all_errors = toggle;
        break;

      case 'k': 
        if(curlinfo->features & CURL_VERSION_SPNEGO)
          config->proxynegotiate = toggle;
        else return PARAM_LIBCURL_DOESNT_SUPPORT;
        break;

      case 'm': 
        GetStr(&config->ftp_account, nextarg);
        break;
      case 'n': 
        config->proxyanyauth = toggle;
        break;
      case 'o': 
        global->tracetime = toggle;
        break;
      case 'p': 
        config->ignorecl = toggle;
        break;
      case 'q': 
        config->ftp_skip_ip = toggle;
        break;
      case 'r': 
        config->ftp_filemethod = ftpfilemethod(config, nextarg);
        break;
      case 's': { 
        char lrange[7];  
        char *p = nextarg;
        while(ISDIGIT(*p))
          p++;
        if(*p) {
          
          rc = sscanf(p, " - %6s", lrange);
          *p = 0; 
        }
        else rc = 0;

        err = str2unum(&config->localport, nextarg);
        if(err || (config->localport > 65535))
          return PARAM_BAD_USE;
        if(!rc)
          config->localportrange = 1; 
        else {
          err = str2unum(&config->localportrange, lrange);
          if(err || (config->localportrange > 65535))
            return PARAM_BAD_USE;
          config->localportrange -= (config->localport-1);
          if(config->localportrange < 1)
            return PARAM_BAD_USE;
        }
        break;
      }
      case 'u': 
        GetStr(&config->ftp_alternative_to_user, nextarg);
        break;
      case 'v': 
        if(toggle && !(curlinfo->features & CURL_VERSION_SSL))
          return PARAM_LIBCURL_DOESNT_SUPPORT;
        config->ftp_ssl_reqd = toggle;
        break;
      case 'w': 
        config->disable_sessionid = (!toggle)?TRUE:FALSE;
        break;
      case 'x': 
        if(toggle && !(curlinfo->features & CURL_VERSION_SSL))
          return PARAM_LIBCURL_DOESNT_SUPPORT;
        config->ftp_ssl_control = toggle;
        break;
      case 'y': 
        config->ftp_ssl_ccc = toggle;
        if(!config->ftp_ssl_ccc_mode)
          config->ftp_ssl_ccc_mode = CURLFTPSSL_CCC_PASSIVE;
        break;
      case 'j': 
        config->ftp_ssl_ccc = TRUE;
        config->ftp_ssl_ccc_mode = ftpcccmethod(config, nextarg);
        break;
      case 'z': 

        warnf(global, "--libcurl option was disabled at build-time!\n");
        return PARAM_OPTION_UNKNOWN;

        GetStr(&global->libcurl, nextarg);
        break;

      case '#': 
        config->raw = toggle;
        break;
      case '0': 
        config->post301 = toggle;
        break;
      case '1': 
        config->nokeepalive = (!toggle)?TRUE:FALSE;
        break;
      case '3': 
        err = str2unum(&config->alivetime, nextarg);
        if(err)
          return err;
        break;
      case '4': 
        config->post302 = toggle;
        break;
      case 'I': 
        config->post303 = toggle;
        break;
      case '5': 
        
        GetStr(&config->noproxy, nextarg);
        break;
       case '7': 
        config->socks5_gssapi_nec = toggle;
        break;
      case '8': 
        
        GetStr(&config->proxy, nextarg);
        config->proxyver = CURLPROXY_HTTP_1_0;
        break;
      case '9': 
        err = str2unum(&config->tftp_blksize, nextarg);
        if(err)
          return err;
        break;
      case 'A': 
        GetStr(&config->mail_from, nextarg);
        break;
      case 'B': 
        
        err = add2list(&config->mail_rcpt, nextarg);
        if(err)
          return err;
        break;
      case 'C': 
        config->ftp_pret = toggle;
        break;
      case 'D': 
        config->proto_present = TRUE;
        if(proto2num(config, &config->proto, nextarg))
          return PARAM_BAD_USE;
        break;
      case 'E': 
        config->proto_redir_present = TRUE;
        if(proto2num(config, &config->proto_redir, nextarg))
          return PARAM_BAD_USE;
        break;
      case 'F': 
        err = add2list(&config->resolve, nextarg);
        if(err)
          return err;
        break;
      case 'G': 
        config->gssapi_delegation = delegation(config, nextarg);
        break;
      case 'H': 
        GetStr(&config->mail_auth, nextarg);
        break;
      case 'J': 
        {

          int mlmaj, mlmin, mlpatch;
          metalink_get_version(&mlmaj, &mlmin, &mlpatch);
          if((mlmaj*10000)+(mlmin*100) + mlpatch < CURL_REQ_LIBMETALINK_VERS) {
            warnf(global, "--metalink option cannot be used because the version of " "the linked libmetalink library is too old. " "Required: %d.%d.%d, found %d.%d.%d\n", CURL_REQ_LIBMETALINK_MAJOR, CURL_REQ_LIBMETALINK_MINOR, CURL_REQ_LIBMETALINK_PATCH, mlmaj, mlmin, mlpatch);






            return PARAM_BAD_USE;
          }
          else config->use_metalink = toggle;

          warnf(global, "--metalink option is ignored because the binary is " "built without the Metalink support.\n");

          break;
        }
      case '6': 
        GetStr(&config->sasl_authzid, nextarg);
        break;
      case 'K': 
        config->sasl_ir = toggle;
        break;
      case 'L': 

        global->test_event_based = toggle;

        warnf(global, "--test-event is ignored unless a debug build!\n");

        break;
      case 'M': 
        config->abstract_unix_socket = FALSE;
        GetStr(&config->unix_socket_path, nextarg);
        break;
      case 'N': 
        config->path_as_is = toggle;
        break;
      case 'O': 
        GetStr(&config->proxy_service_name, nextarg);
        break;
      case 'P': 
        GetStr(&config->service_name, nextarg);
        break;
      case 'Q': 
        GetStr(&config->proto_default, nextarg);
        err = check_protocol(config->proto_default);
        if(err)
          return err;
        break;
      case 'R': 
        err = str2udouble(&config->expect100timeout, nextarg, LONG_MAX/1000);
        if(err)
          return err;
        break;
      case 'S': 
        config->tftp_no_options = toggle;
        break;
      case 'U': 
        err = add2list(&config->connect_to, nextarg);
        if(err)
          return err;
        break;
      case 'W': 
        config->abstract_unix_socket = TRUE;
        GetStr(&config->unix_socket_path, nextarg);
        break;
      case 'X': 
        err = str2tls_max(&config->ssl_version_max, nextarg);
        if(err)
          return err;
        break;
      case 'Y': 
        config->suppress_connect_headers = toggle;
        break;
      case 'Z': 
        config->ssh_compression = toggle;
        break;
      case '~': 
        err = str2unum(&config->happy_eyeballs_timeout_ms, nextarg);
        if(err)
          return err;
        
        break;
      }
      break;
    case '#':
      switch(subletter) {
      case 'm': 
        global->noprogress = !toggle;
        break;
      default:  
        global->progressmode = toggle ? CURL_PROGRESS_BAR : CURL_PROGRESS_STATS;
        break;
      }
      break;
    case ':': 
      return PARAM_NEXT_OPERATION;
    case '0': 
      switch(subletter) {
      case '\0':
        
        config->httpversion = CURL_HTTP_VERSION_1_0;
        break;
      case '1':
        
        config->httpversion = CURL_HTTP_VERSION_1_1;
        break;
      case '2':
        
        config->httpversion = CURL_HTTP_VERSION_2_0;
        break;
      case '3': 
        
        config->httpversion = CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE;
        break;
      case '4': 
        
        if(curlinfo->features & CURL_VERSION_HTTP3)
          config->httpversion = CURL_HTTP_VERSION_3;
        else return PARAM_LIBCURL_DOESNT_SUPPORT;
        break;
      case '9':
        
        config->http09_allowed = toggle;
        break;
      }
      break;
    case '1': 
      switch(subletter) {
      case '\0':
        
        config->ssl_version = CURL_SSLVERSION_TLSv1;
        break;
      case '0':
        
        config->ssl_version = CURL_SSLVERSION_TLSv1_0;
        break;
      case '1':
        
        config->ssl_version = CURL_SSLVERSION_TLSv1_1;
        break;
      case '2':
        
        config->ssl_version = CURL_SSLVERSION_TLSv1_2;
        break;
      case '3':
        
        config->ssl_version = CURL_SSLVERSION_TLSv1_3;
        break;
      case 'A': 
        GetStr(&config->cipher13_list, nextarg);
        break;
      case 'B': 
        GetStr(&config->proxy_cipher13_list, nextarg);
        break;
      }
      break;
    case '2':
      
      config->ssl_version = CURL_SSLVERSION_SSLv2;
      break;
    case '3':
      
      config->ssl_version = CURL_SSLVERSION_SSLv3;
      break;
    case '4':
      
      config->ip_version = 4;
      break;
    case '6':
      
      config->ip_version = 6;
      break;
    case 'a':
      
      config->ftp_append = toggle;
      break;
    case 'A':
      
      GetStr(&config->useragent, nextarg);
      break;
    case 'b':
      switch(subletter) {
      case 'a': 
        if(curlinfo->features & CURL_VERSION_ALTSVC)
          GetStr(&config->altsvc, nextarg);
        else return PARAM_LIBCURL_DOESNT_SUPPORT;
        break;
      default:  
        if(nextarg[0] == '@') {
          nextarg++;
        }
        else if(strchr(nextarg, '=')) {
          
          GetStr(&config->cookie, nextarg);
          break;
        }
        
        GetStr(&config->cookiefile, nextarg);
      }
      break;
    case 'B':
      
      config->use_ascii = toggle;
      break;
    case 'c':
      
      GetStr(&config->cookiejar, nextarg);
      break;
    case 'C':
      
      if(strcmp(nextarg, "-")) {
        err = str2offset(&config->resume_from, nextarg);
        if(err)
          return err;
        config->resume_from_current = FALSE;
      }
      else {
        config->resume_from_current = TRUE;
        config->resume_from = 0;
      }
      config->use_resume = TRUE;
      break;
    case 'd':
      
    {
      char *postdata = NULL;
      FILE *file;
      size_t size = 0;
      bool raw_mode = (subletter == 'r');

      if(subletter == 'e') { 
        
        const char *p = strchr(nextarg, '=');
        size_t nlen;
        char is_file;
        if(!p)
          
          p = strchr(nextarg, '@');
        if(p) {
          nlen = p - nextarg; 
          is_file = *p++; 
        }
        else {
          
          nlen = is_file = 0;
          p = nextarg;
        }
        if('@' == is_file) {
          
          if(!strcmp("-", p)) {
            file = stdin;
            set_binmode(stdin);
          }
          else {
            file = fopen(p, "rb");
            if(!file)
              warnf(global, "Couldn't read data from file \"%s\", this makes " "an empty POST.\n", nextarg);

          }

          err = file2memory(&postdata, &size, file);

          if(file && (file != stdin))
            fclose(file);
          if(err)
            return err;
        }
        else {
          GetStr(&postdata, p);
          if(postdata)
            size = strlen(postdata);
        }

        if(!postdata) {
          
          postdata = strdup("");
          if(!postdata)
            return PARAM_NO_MEM;
          size = 0;
        }
        else {
          char *enc = curl_easy_escape(NULL, postdata, (int)size);
          Curl_safefree(postdata); 
          if(enc) {
            
            size_t outlen = nlen + strlen(enc) + 2;
            char *n = malloc(outlen);
            if(!n) {
              curl_free(enc);
              return PARAM_NO_MEM;
            }
            if(nlen > 0) { 
              msnprintf(n, outlen, "%.*s=%s", nlen, nextarg, enc);
              size = outlen-1;
            }
            else {
              strcpy(n, enc);
              size = outlen-2; 
            }
            curl_free(enc);
            postdata = n;
          }
          else return PARAM_NO_MEM;
        }
      }
      else if('@' == *nextarg && !raw_mode) {
        
        nextarg++; 

        if(!strcmp("-", nextarg)) {
          file = stdin;
          if(subletter == 'b') 
            set_binmode(stdin);
        }
        else {
          file = fopen(nextarg, "rb");
          if(!file)
            warnf(global, "Couldn't read data from file \"%s\", this makes " "an empty POST.\n", nextarg);
        }

        if(subletter == 'b')
          
          err = file2memory(&postdata, &size, file);
        else {
          err = file2string(&postdata, file);
          if(postdata)
            size = strlen(postdata);
        }

        if(file && (file != stdin))
          fclose(file);
        if(err)
          return err;

        if(!postdata) {
          
          postdata = strdup("");
          if(!postdata)
            return PARAM_NO_MEM;
        }
      }
      else {
        GetStr(&postdata, nextarg);
        if(postdata)
          size = strlen(postdata);
      }


      if(subletter != 'b') {
        
        if(convert_to_network(postdata, strlen(postdata))) {
          Curl_safefree(postdata);
          return PARAM_NO_MEM;
        }
      }


      if(config->postfields) {
        
        char *oldpost = config->postfields;
        curl_off_t oldlen = config->postfieldsize;
        curl_off_t newlen = oldlen + curlx_uztoso(size) + 2;
        config->postfields = malloc((size_t)newlen);
        if(!config->postfields) {
          Curl_safefree(oldpost);
          Curl_safefree(postdata);
          return PARAM_NO_MEM;
        }
        memcpy(config->postfields, oldpost, (size_t)oldlen);
        
        config->postfields[oldlen] = '\x26';
        memcpy(&config->postfields[oldlen + 1], postdata, size);
        config->postfields[oldlen + 1 + size] = '\0';
        Curl_safefree(oldpost);
        Curl_safefree(postdata);
        config->postfieldsize += size + 1;
      }
      else {
        config->postfields = postdata;
        config->postfieldsize = curlx_uztoso(size);
      }
    }
    
    break;
    case 'D':
      
      GetStr(&config->headerfile, nextarg);
      break;
    case 'e':
    {
      char *ptr = strstr(nextarg, ";auto");
      if(ptr) {
        
        config->autoreferer = TRUE;
        *ptr = 0; 
      }
      else config->autoreferer = FALSE;
      GetStr(&config->referer, nextarg);
    }
    break;
    case 'E':
      switch(subletter) {
      case '\0': 
        GetFileAndPassword(nextarg, &config->cert, &config->key_passwd);
        break;
      case 'a': 
        GetStr(&config->cacert, nextarg);
        break;
      case 'b': 
        GetStr(&config->cert_type, nextarg);
        break;
      case 'c': 
        GetStr(&config->key, nextarg);
        break;
      case 'd': 
        GetStr(&config->key_type, nextarg);
        break;
      case 'e': 
        GetStr(&config->key_passwd, nextarg);
        cleanarg(nextarg);
        break;
      case 'f': 
        GetStr(&config->engine, nextarg);
        if(config->engine && curl_strequal(config->engine, "list"))
          return PARAM_ENGINES_REQUESTED;
        break;
      case 'g': 
        GetStr(&config->capath, nextarg);
        break;
      case 'h': 
        GetStr(&config->pubkey, nextarg);
        break;
      case 'i': 
        GetStr(&config->hostpubmd5, nextarg);
        if(!config->hostpubmd5 || strlen(config->hostpubmd5) != 32)
          return PARAM_BAD_USE;
        break;
      case 'j': 
        GetStr(&config->crlfile, nextarg);
        break;
      case 'k': 
        if(curlinfo->features & CURL_VERSION_TLSAUTH_SRP)
          GetStr(&config->tls_username, nextarg);
        else return PARAM_LIBCURL_DOESNT_SUPPORT;
        break;
      case 'l': 
        if(curlinfo->features & CURL_VERSION_TLSAUTH_SRP)
          GetStr(&config->tls_password, nextarg);
        else return PARAM_LIBCURL_DOESNT_SUPPORT;
        break;
      case 'm': 
        if(curlinfo->features & CURL_VERSION_TLSAUTH_SRP) {
          GetStr(&config->tls_authtype, nextarg);
          if(!curl_strequal(config->tls_authtype, "SRP"))
            return PARAM_LIBCURL_DOESNT_SUPPORT; 
        }
        else return PARAM_LIBCURL_DOESNT_SUPPORT;
        break;
      case 'n': 
        if(curlinfo->features & CURL_VERSION_SSL)
          config->ssl_allow_beast = toggle;
        break;

      case 'p': 
        GetStr(&config->pinnedpubkey, nextarg);
        break;

      case 'P': 
        GetStr(&config->proxy_pinnedpubkey, nextarg);
        break;

      case 'q': 
        config->verifystatus = TRUE;
        break;

      case 'r': 
        config->falsestart = TRUE;
        break;

      case 's': 
        if(curlinfo->features & CURL_VERSION_SSL)
          config->ssl_no_revoke = TRUE;
        break;

      case 'S': 
        if(curlinfo->features & CURL_VERSION_SSL)
          config->ssl_revoke_best_effort = TRUE;
        break;

      case 't': 
        config->tcp_fastopen = TRUE;
        break;

      case 'u': 
        if(curlinfo->features & CURL_VERSION_TLSAUTH_SRP)
          GetStr(&config->proxy_tls_username, nextarg);
        else return PARAM_LIBCURL_DOESNT_SUPPORT;
        break;

      case 'v': 
        if(curlinfo->features & CURL_VERSION_TLSAUTH_SRP)
          GetStr(&config->proxy_tls_password, nextarg);
        else return PARAM_LIBCURL_DOESNT_SUPPORT;
        break;

      case 'w': 
        if(curlinfo->features & CURL_VERSION_TLSAUTH_SRP) {
          GetStr(&config->proxy_tls_authtype, nextarg);
          if(!curl_strequal(config->proxy_tls_authtype, "SRP"))
            return PARAM_LIBCURL_DOESNT_SUPPORT; 
        }
        else return PARAM_LIBCURL_DOESNT_SUPPORT;
        break;

      case 'x': 
        GetFileAndPassword(nextarg, &config->proxy_cert, &config->proxy_key_passwd);
        break;

      case 'y': 
        GetStr(&config->proxy_cert_type, nextarg);
        break;

      case 'z': 
        GetStr(&config->proxy_key, nextarg);
        break;

      case '0': 
        GetStr(&config->proxy_key_type, nextarg);
        break;

      case '1': 
        GetStr(&config->proxy_key_passwd, nextarg);
        cleanarg(nextarg);
        break;

      case '2': 
        GetStr(&config->proxy_cipher_list, nextarg);
        break;

      case '3': 
        GetStr(&config->proxy_crlfile, nextarg);
        break;

      case '4': 
        if(curlinfo->features & CURL_VERSION_SSL)
          config->proxy_ssl_allow_beast = toggle;
        break;

      case '5': 
        GetStr(&config->login_options, nextarg);
        break;

      case '6': 
        GetStr(&config->proxy_cacert, nextarg);
        break;

      case '7': 
        GetStr(&config->proxy_capath, nextarg);
        break;

      case '8': 
        config->proxy_insecure_ok = toggle;
        break;

      case '9': 
        
        config->proxy_ssl_version = CURL_SSLVERSION_TLSv1;
        break;

      case 'A':
        
        if(toggle)
          config->socks5_auth |= CURLAUTH_BASIC;
        else config->socks5_auth &= ~CURLAUTH_BASIC;
        break;

      case 'B':
        
        if(toggle)
          config->socks5_auth |= CURLAUTH_GSSAPI;
        else config->socks5_auth &= ~CURLAUTH_GSSAPI;
        break;

      case 'C':
        GetStr(&config->etag_save_file, nextarg);
        break;

      case 'D':
        GetStr(&config->etag_compare_file, nextarg);
        break;

      default: 
        return PARAM_OPTION_UNKNOWN;
      }
      break;
    case 'f':
      switch(subletter) {
      case 'a': 
        global->fail_early = toggle;
        break;
      case 'b': 
        global->styled_output = toggle;
        break;
      case 'c': 
        config->mail_rcpt_allowfails = toggle;
        break;
      default: 
        config->failonerror = toggle;
      }
      break;
    case 'F':
      
      if(formparse(config, nextarg, &config->mimeroot, &config->mimecurrent, (subletter == 's')?TRUE:FALSE))



        return PARAM_BAD_USE;
      if(SetHTTPrequest(config, HTTPREQ_MIMEPOST, &config->httpreq))
        return PARAM_BAD_USE;
      break;

    case 'g': 
      config->globoff = toggle;
      break;

    case 'G': 
      if(subletter == 'a') { 
        GetStr(&config->request_target, nextarg);
      }
      else config->use_httpget = TRUE;
      break;

    case 'h': 
      if(toggle) {
        return PARAM_HELP_REQUESTED;
      }
      
      break;
    case 'H':
      
      if(nextarg[0] == '@') {
        
        char *string;
        size_t len;
        bool use_stdin = !strcmp(&nextarg[1], "-");
        FILE *file = use_stdin?stdin:fopen(&nextarg[1], FOPEN_READTEXT);
        if(!file)
          warnf(global, "Failed to open %s!\n", &nextarg[1]);
        else {
          err = file2memory(&string, &len, file);
          if(!err && string) {
            
            
            char *h = strtok(string, "\r\n");
            while(h) {
              if(subletter == 'p') 
                err = add2list(&config->proxyheaders, h);
              else err = add2list(&config->headers, h);
              if(err)
                break;
              h = strtok(NULL, "\r\n");
            }
            free(string);
          }
          if(!use_stdin)
            fclose(file);
          if(err)
            return err;
        }
      }
      else {
        if(subletter == 'p') 
          err = add2list(&config->proxyheaders, nextarg);
        else err = add2list(&config->headers, nextarg);
        if(err)
          return err;
      }
      break;
    case 'i':
      config->show_headers = toggle; 
      break;
    case 'j':
      config->cookiesession = toggle;
      break;
    case 'I': 
      config->no_body = toggle;
      config->show_headers = toggle;
      if(SetHTTPrequest(config, (config->no_body)?HTTPREQ_HEAD:HTTPREQ_GET, &config->httpreq))

        return PARAM_BAD_USE;
      break;
    case 'J': 
      if(config->show_headers) {
        warnf(global, "--include and --remote-header-name cannot be combined.\n");
        return PARAM_BAD_USE;
      }
      config->content_disposition = toggle;
      break;
    case 'k': 
      config->insecure_ok = toggle;
      break;
    case 'K': 
      if(parseconfig(nextarg, global))
        warnf(global, "error trying read config from the '%s' file\n", nextarg);
      break;
    case 'l':
      config->dirlistonly = toggle; 
      break;
    case 'L':
      config->followlocation = toggle; 
      switch(subletter) {
      case 't':
        
        config->unrestricted_auth = toggle;
        break;
      }
      break;
    case 'm':
      
      err = str2udouble(&config->timeout, nextarg, LONG_MAX/1000);
      if(err)
        return err;
      break;
    case 'M': 
      if(toggle) { 

        return PARAM_MANUAL_REQUESTED;

        warnf(global, "built-in manual was disabled at build-time!\n");
        return PARAM_OPTION_UNKNOWN;

      }
      break;
    case 'n':
      switch(subletter) {
      case 'o': 
        config->netrc_opt = toggle;
        break;
      case 'e': 
        GetStr(&config->netrc_file, nextarg);
        break;
      default:
        
        config->netrc = toggle;
        break;
      }
      break;
    case 'N':
      
      if(longopt)
        config->nobuffer = (!toggle)?TRUE:FALSE;
      else config->nobuffer = toggle;
      break;
    case 'O': 
      if(subletter == 'a') { 
        config->default_node_flags = toggle?GETOUT_USEREMOTE:0;
        break;
      }
      
    case 'o': 
      
    {
      struct getout *url;
      if(!config->url_out)
        config->url_out = config->url_list;
      if(config->url_out) {
        
        while(config->url_out && (config->url_out->flags & GETOUT_OUTFILE))
          config->url_out = config->url_out->next;
      }

      

      if(config->url_out)
        
        url = config->url_out;
      else  config->url_out = url = new_getout(config);


      if(!url)
        return PARAM_NO_MEM;

      
      if('o' == letter) {
        GetStr(&url->outfile, nextarg);
        url->flags &= ~GETOUT_USEREMOTE; 
      }
      else {
        url->outfile = NULL; 
        if(toggle)
          url->flags |= GETOUT_USEREMOTE;  
        else url->flags &= ~GETOUT_USEREMOTE;
      }
      url->flags |= GETOUT_OUTFILE;
    }
    break;
    case 'P':
      
      
      GetStr(&config->ftpport, nextarg);
      break;
    case 'p':
      
      config->proxytunnel = toggle;
      break;

    case 'q': 
      break;
    case 'Q':
      
      switch(nextarg[0]) {
      case '-':
        
        nextarg++;
        err = add2list(&config->postquote, nextarg);
        break;
      case '+':
        
        nextarg++;
        err = add2list(&config->prequote, nextarg);
        break;
      default:
        err = add2list(&config->quote, nextarg);
        break;
      }
      if(err)
        return err;
      break;
    case 'r':
      
      if(ISDIGIT(*nextarg) && !strchr(nextarg, '-')) {
        char buffer[32];
        curl_off_t off;
        if(curlx_strtoofft(nextarg, NULL, 10, &off)) {
          warnf(global, "unsupported range point\n");
          return PARAM_BAD_USE;
        }
        warnf(global, "A specified range MUST include at least one dash (-). " "Appending one for you!\n");

        msnprintf(buffer, sizeof(buffer), "%" CURL_FORMAT_CURL_OFF_T "-", off);
        Curl_safefree(config->range);
        config->range = strdup(buffer);
        if(!config->range)
          return PARAM_NO_MEM;
      }
      {
        
        const char *tmp_range = nextarg;
        while(*tmp_range != '\0') {
          if(!ISDIGIT(*tmp_range) && *tmp_range != '-' && *tmp_range != ',') {
            warnf(global, "Invalid character is found in given range. " "A specified range MUST have only digits in " "\'start\'-\'stop\'. The server's response to this " "request is uncertain.\n");


            break;
          }
          tmp_range++;
        }
        
        GetStr(&config->range, nextarg);
      }
      break;
    case 'R':
      
      config->remote_time = toggle;
      break;
    case 's':
      
      if(toggle)
        global->mute = global->noprogress = TRUE;
      else global->mute = global->noprogress = FALSE;
      if(global->showerror < 0)
        
        global->showerror = (!toggle)?TRUE:FALSE; 
      break;
    case 'S':
      
      global->showerror = toggle?1:0; 
      break;
    case 't':
      
      err = add2list(&config->telnet_options, nextarg);
      if(err)
        return err;
      break;
    case 'T':
      
    {
      struct getout *url;
      if(!config->url_ul)
        config->url_ul = config->url_list;
      if(config->url_ul) {
        
        while(config->url_ul && (config->url_ul->flags & GETOUT_UPLOAD))
          config->url_ul = config->url_ul->next;
      }

      

      if(config->url_ul)
        
        url = config->url_ul;
      else  config->url_ul = url = new_getout(config);


      if(!url)
        return PARAM_NO_MEM;

      url->flags |= GETOUT_UPLOAD; 
      if(!*nextarg)
        url->flags |= GETOUT_NOUPLOAD;
      else {
        
        GetStr(&url->infile, nextarg);
      }
    }
    break;
    case 'u':
      
      GetStr(&config->userpwd, nextarg);
      cleanarg(nextarg);
      break;
    case 'U':
      
      GetStr(&config->proxyuserpwd, nextarg);
      cleanarg(nextarg);
      break;
    case 'v':
      if(toggle) {
        
        Curl_safefree(global->trace_dump);
        global->trace_dump = strdup("%");
        if(!global->trace_dump)
          return PARAM_NO_MEM;
        if(global->tracetype && (global->tracetype != TRACE_PLAIN))
          warnf(global, "-v, --verbose overrides an earlier trace/verbose option\n");
        global->tracetype = TRACE_PLAIN;
      }
      else  global->tracetype = TRACE_NONE;

      break;
    case 'V':
      if(toggle)    
        return PARAM_VERSION_INFO_REQUESTED;
      break;

    case 'w':
      
      if('@' == *nextarg) {
        
        FILE *file;
        const char *fname;
        nextarg++; 
        if(!strcmp("-", nextarg)) {
          fname = "<stdin>";
          file = stdin;
        }
        else {
          fname = nextarg;
          file = fopen(nextarg, FOPEN_READTEXT);
        }
        Curl_safefree(config->writeout);
        err = file2string(&config->writeout, file);
        if(file && (file != stdin))
          fclose(file);
        if(err)
          return err;
        if(!config->writeout)
          warnf(global, "Failed to read %s", fname);
      }
      else GetStr(&config->writeout, nextarg);
      break;
    case 'x':
      switch(subletter) {
      case 'a': 
        GetStr(&config->preproxy, nextarg);
        break;
      default:
        
        GetStr(&config->proxy, nextarg);
        config->proxyver = CURLPROXY_HTTP;
        break;
      }
      break;
    case 'X':
      
      GetStr(&config->customrequest, nextarg);
      break;
    case 'y':
      
      err = str2unum(&config->low_speed_time, nextarg);
      if(err)
        return err;
      if(!config->low_speed_limit)
        config->low_speed_limit = 1;
      break;
    case 'Y':
      
      err = str2unum(&config->low_speed_limit, nextarg);
      if(err)
        return err;
      if(!config->low_speed_time)
        config->low_speed_time = 30;
      break;
    case 'Z':
      switch(subletter) {
      case '\0':  
        global->parallel = toggle;
        break;
      case 'b':   
        err = str2unum(&global->parallel_max, nextarg);
        if(err)
          return err;
        if((global->parallel_max > MAX_PARALLEL) || (global->parallel_max < 1))
          global->parallel_max = PARALLEL_DEFAULT;
        break;
      case 'c':   
        global->parallel_connect = toggle;
        break;
      }
      break;
    case 'z': 
      switch(*nextarg) {
      case '+':
        nextarg++;
        
      default:
        
        config->timecond = CURL_TIMECOND_IFMODSINCE;
        break;
      case '-':
        
        config->timecond = CURL_TIMECOND_IFUNMODSINCE;
        nextarg++;
        break;
      case '=':
        
        config->timecond = CURL_TIMECOND_LASTMOD;
        nextarg++;
        break;
      }
      now = time(NULL);
      config->condtime = (curl_off_t)curl_getdate(nextarg, &now);
      if(-1 == config->condtime) {
        
        curl_off_t filetime = getfiletime(nextarg, config->global->errors);
        if(filetime >= 0) {
          
          config->condtime = filetime;
        }
        else {
          
          config->timecond = CURL_TIMECOND_NONE;
          warnf(global, "Illegal date format for -z, --time-cond (and not " "a file name). Disabling time condition. " "See curl_getdate(3) for valid date syntax.\n");


        }
      }
      break;
    default: 
      return PARAM_OPTION_UNKNOWN;
    }
    hit = -1;

  } while(!longopt && !singleopt && *++parse && !*usedarg);

  return PARAM_OK;
}

ParameterError parse_args(struct GlobalConfig *global, int argc, argv_item_t argv[])
{
  int i;
  bool stillflags;
  char *orig_opt = NULL;
  ParameterError result = PARAM_OK;
  struct OperationConfig *config = global->first;

  for(i = 1, stillflags = TRUE; i < argc && !result; i++) {
    orig_opt = curlx_convert_tchar_to_UTF8(argv[i]);

    if(stillflags && ('-' == orig_opt[0])) {
      bool passarg;

      if(!strcmp("--", orig_opt))
        
        stillflags = FALSE;
      else {
        char *nextarg = (i < (argc - 1))
          ? curlx_convert_tchar_to_UTF8(argv[i + 1])
          : NULL;

        result = getparameter(orig_opt, nextarg, &passarg, global, config);
        curlx_unicodefree(nextarg);
        config = global->last;
        if(result == PARAM_NEXT_OPERATION) {
          
          result = PARAM_OK;

          if(config->url_list && config->url_list->url) {
            
            config->next = malloc(sizeof(struct OperationConfig));
            if(config->next) {
              
              config_init(config->next);

              
              config->next->global = global;

              
              global->last = config->next;

              
              config->next->prev = config;
              config = config->next;
            }
            else result = PARAM_NO_MEM;
          }
        }
        else if(!result && passarg)
          i++; 
      }
    }
    else {
      bool used;

      
      result = getparameter("--url", orig_opt, &used, global, config);
    }

    if(!result)
      curlx_unicodefree(orig_opt);
  }

  if(result && result != PARAM_HELP_REQUESTED && result != PARAM_MANUAL_REQUESTED && result != PARAM_VERSION_INFO_REQUESTED && result != PARAM_ENGINES_REQUESTED) {


    const char *reason = param2text(result);

    if(orig_opt && strcmp(":", orig_opt))
      helpf(global->errors, "option %s: %s\n", orig_opt, reason);
    else helpf(global->errors, "%s\n", reason);
  }

  curlx_unicodefree(orig_opt);
  return result;
}
