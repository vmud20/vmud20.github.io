






















































static CURLcode smtp_regular_transfer(struct Curl_easy *data, bool *done);
static CURLcode smtp_do(struct Curl_easy *data, bool *done);
static CURLcode smtp_done(struct Curl_easy *data, CURLcode status, bool premature);
static CURLcode smtp_connect(struct Curl_easy *data, bool *done);
static CURLcode smtp_disconnect(struct Curl_easy *data, struct connectdata *conn, bool dead);
static CURLcode smtp_multi_statemach(struct Curl_easy *data, bool *done);
static int smtp_getsock(struct Curl_easy *data, struct connectdata *conn, curl_socket_t *socks);
static CURLcode smtp_doing(struct Curl_easy *data, bool *dophase_done);
static CURLcode smtp_setup_connection(struct Curl_easy *data, struct connectdata *conn);
static CURLcode smtp_parse_url_options(struct connectdata *conn);
static CURLcode smtp_parse_url_path(struct Curl_easy *data);
static CURLcode smtp_parse_custom_request(struct Curl_easy *data);
static CURLcode smtp_parse_address(struct Curl_easy *data, const char *fqma, char **address, struct hostname *host);
static CURLcode smtp_perform_auth(struct Curl_easy *data, struct connectdata *conn, const char *mech, const char *initresp);

static CURLcode smtp_continue_auth(struct Curl_easy *data, struct connectdata *conn, const char *resp);
static void smtp_get_message(char *buffer, char **outptr);



const struct Curl_handler Curl_handler_smtp = {
  "SMTP",                            smtp_setup_connection, smtp_do, smtp_done, ZERO_NULL, smtp_connect, smtp_multi_statemach, smtp_doing, smtp_getsock, smtp_getsock, ZERO_NULL, ZERO_NULL, smtp_disconnect, ZERO_NULL, ZERO_NULL, ZERO_NULL, PORT_SMTP, CURLPROTO_SMTP, CURLPROTO_SMTP, PROTOPT_CLOSEACTION | PROTOPT_NOURLQUERY | PROTOPT_URLOPTIONS };
























const struct Curl_handler Curl_handler_smtps = {
  "SMTPS",                           smtp_setup_connection, smtp_do, smtp_done, ZERO_NULL, smtp_connect, smtp_multi_statemach, smtp_doing, smtp_getsock, smtp_getsock, ZERO_NULL, ZERO_NULL, smtp_disconnect, ZERO_NULL, ZERO_NULL, ZERO_NULL, PORT_SMTPS, CURLPROTO_SMTPS, CURLPROTO_SMTP, PROTOPT_CLOSEACTION | PROTOPT_SSL | PROTOPT_NOURLQUERY | PROTOPT_URLOPTIONS };























static const struct SASLproto saslsmtp = {
  "smtp",                      334, 235, 512 - 8, smtp_perform_auth, smtp_continue_auth, smtp_get_message };








static void smtp_to_smtps(struct connectdata *conn)
{
  
  conn->handler = &Curl_handler_smtps;

  
  conn->bits.tls_upgraded = TRUE;
}





static bool smtp_endofresp(struct Curl_easy *data, struct connectdata *conn, char *line, size_t len, int *resp)
{
  struct smtp_conn *smtpc = &conn->proto.smtpc;
  bool result = FALSE;
  (void)data;

  
  if(len < 4 || !ISDIGIT(line[0]) || !ISDIGIT(line[1]) || !ISDIGIT(line[2]))
    return FALSE;

  
  if(line[3] == ' ' || len == 5) {
    char tmpline[6];

    result = TRUE;
    memset(tmpline, '\0', sizeof(tmpline));
    memcpy(tmpline, line, (len == 5 ? 5 : 3));
    *resp = curlx_sltosi(strtol(tmpline, NULL, 10));

    
    if(*resp == 1)
      *resp = 0;
  }
  
  else if(line[3] == '-' && (smtpc->state == SMTP_EHLO || smtpc->state == SMTP_COMMAND)) {
    result = TRUE;
    *resp = 1;  
  }

  return result;
}


static void smtp_get_message(char *buffer, char **outptr)
{
  size_t len = strlen(buffer);
  char *message = NULL;

  if(len > 4) {
    
    len -= 4;
    for(message = buffer + 4; *message == ' ' || *message == '\t';
        message++, len--)
      ;

    
    for(; len--;)
      if(message[len] != '\r' && message[len] != '\n' && message[len] != ' ' && message[len] != '\t')
        break;

    
    if(++len) {
      message[len] = '\0';
    }
  }
  else  message = &buffer[len];


  *outptr = message;
}


static void state(struct Curl_easy *data, smtpstate newstate)
{
  struct smtp_conn *smtpc = &data->conn->proto.smtpc;

  
  static const char * const names[] = {
    "STOP", "SERVERGREET", "EHLO", "HELO", "STARTTLS", "UPGRADETLS", "AUTH", "COMMAND", "MAIL", "RCPT", "DATA", "POSTDATA", "QUIT",  };














  if(smtpc->state != newstate)
    infof(data, "SMTP %p state change from %s to %s", (void *)smtpc, names[smtpc->state], names[newstate]);


  smtpc->state = newstate;
}


static CURLcode smtp_perform_ehlo(struct Curl_easy *data)
{
  CURLcode result = CURLE_OK;
  struct connectdata *conn = data->conn;
  struct smtp_conn *smtpc = &conn->proto.smtpc;

  smtpc->sasl.authmechs = SASL_AUTH_NONE; 
  smtpc->sasl.authused = SASL_AUTH_NONE;  
  smtpc->tls_supported = FALSE;           
  smtpc->auth_supported = FALSE;          

  
  result = Curl_pp_sendf(data, &smtpc->pp, "EHLO %s", smtpc->domain);

  if(!result)
    state(data, SMTP_EHLO);

  return result;
}


static CURLcode smtp_perform_helo(struct Curl_easy *data, struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct smtp_conn *smtpc = &conn->proto.smtpc;

  smtpc->sasl.authused = SASL_AUTH_NONE; 

  
  result = Curl_pp_sendf(data, &smtpc->pp, "HELO %s", smtpc->domain);

  if(!result)
    state(data, SMTP_HELO);

  return result;
}


static CURLcode smtp_perform_starttls(struct Curl_easy *data, struct connectdata *conn)
{
  
  CURLcode result = Curl_pp_sendf(data, &conn->proto.smtpc.pp, "%s", "STARTTLS");

  if(!result)
    state(data, SMTP_STARTTLS);

  return result;
}


static CURLcode smtp_perform_upgrade_tls(struct Curl_easy *data)
{
  
  struct connectdata *conn = data->conn;
  struct smtp_conn *smtpc = &conn->proto.smtpc;
  CURLcode result = Curl_ssl_connect_nonblocking(data, conn, FALSE, FIRSTSOCKET, &smtpc->ssldone);


  if(!result) {
    if(smtpc->state != SMTP_UPGRADETLS)
      state(data, SMTP_UPGRADETLS);

    if(smtpc->ssldone) {
      smtp_to_smtps(conn);
      result = smtp_perform_ehlo(data);
    }
  }

  return result;
}


static CURLcode smtp_perform_auth(struct Curl_easy *data, struct connectdata *conn, const char *mech, const char *initresp)


{
  CURLcode result = CURLE_OK;
  struct smtp_conn *smtpc = &conn->proto.smtpc;

  if(initresp) {                                  
    
    result = Curl_pp_sendf(data, &smtpc->pp, "AUTH %s %s", mech, initresp);
  }
  else {
    
    result = Curl_pp_sendf(data, &smtpc->pp, "AUTH %s", mech);
  }

  return result;
}


static CURLcode smtp_continue_auth(struct Curl_easy *data, struct connectdata *conn, const char *resp)
{
  struct smtp_conn *smtpc = &conn->proto.smtpc;

  return Curl_pp_sendf(data, &smtpc->pp, "%s", resp);
}


static CURLcode smtp_perform_authentication(struct Curl_easy *data)
{
  CURLcode result = CURLE_OK;
  struct connectdata *conn = data->conn;
  struct smtp_conn *smtpc = &conn->proto.smtpc;
  saslprogress progress;

  
  if(!smtpc->auth_supported || !Curl_sasl_can_authenticate(&smtpc->sasl, conn)) {
    state(data, SMTP_STOP);
    return result;
  }

  
  result = Curl_sasl_start(&smtpc->sasl, data, conn, FALSE, &progress);

  if(!result) {
    if(progress == SASL_INPROGRESS)
      state(data, SMTP_AUTH);
    else {
      
      infof(data, "No known authentication mechanisms supported!");
      result = CURLE_LOGIN_DENIED;
    }
  }

  return result;
}


static CURLcode smtp_perform_command(struct Curl_easy *data)
{
  CURLcode result = CURLE_OK;
  struct connectdata *conn = data->conn;
  struct SMTP *smtp = data->req.p.smtp;

  if(smtp->rcpt) {
    
    bool utf8 = FALSE;

    if((!smtp->custom) || (!smtp->custom[0])) {
      char *address = NULL;
      struct hostname host = { NULL, NULL, NULL, NULL };

      
      result = smtp_parse_address(data, smtp->rcpt->data, &address, &host);
      if(result)
        return result;

      
      utf8 = (conn->proto.smtpc.utf8_supported) && ((host.encalloc) || (!Curl_is_ASCII_name(address)) || (!Curl_is_ASCII_name(host.name)));


      
      result = Curl_pp_sendf(data, &conn->proto.smtpc.pp, "VRFY %s%s%s%s", address, host.name ? "@" : "", host.name ? host.name : "", utf8 ? " SMTPUTF8" : "");




      Curl_free_idnconverted_hostname(&host);
      free(address);
    }
    else {
      
      utf8 = (conn->proto.smtpc.utf8_supported) && (!strcmp(smtp->custom, "EXPN"));

      
      result = Curl_pp_sendf(data, &conn->proto.smtpc.pp, "%s %s%s", smtp->custom, smtp->rcpt->data, utf8 ? " SMTPUTF8" : "");


    }
  }
  else  result = Curl_pp_sendf(data, &conn->proto.smtpc.pp, "%s", smtp->custom && smtp->custom[0] != '\0' ? smtp->custom : "HELP");




  if(!result)
    state(data, SMTP_COMMAND);

  return result;
}


static CURLcode smtp_perform_mail(struct Curl_easy *data)
{
  char *from = NULL;
  char *auth = NULL;
  char *size = NULL;
  CURLcode result = CURLE_OK;
  struct connectdata *conn = data->conn;

  
  bool utf8 = FALSE;

  
  if(data->set.str[STRING_MAIL_FROM]) {
    char *address = NULL;
    struct hostname host = { NULL, NULL, NULL, NULL };

    
    result = smtp_parse_address(data, data->set.str[STRING_MAIL_FROM], &address, &host);
    if(result)
      return result;

    
    utf8 = (conn->proto.smtpc.utf8_supported) && ((host.encalloc) || (!Curl_is_ASCII_name(address)) || (!Curl_is_ASCII_name(host.name)));


    if(host.name) {
      from = aprintf("<%s@%s>", address, host.name);

      Curl_free_idnconverted_hostname(&host);
    }
    else  from = aprintf("<%s>", address);


    free(address);
  }
  else  from = strdup("<>");


  if(!from)
    return CURLE_OUT_OF_MEMORY;

  
  if(data->set.str[STRING_MAIL_AUTH] && conn->proto.smtpc.sasl.authused) {
    if(data->set.str[STRING_MAIL_AUTH][0] != '\0') {
      char *address = NULL;
      struct hostname host = { NULL, NULL, NULL, NULL };

      
      result = smtp_parse_address(data, data->set.str[STRING_MAIL_AUTH], &address, &host);
      if(result) {
        free(from);
        return result;
      }

      
      if((!utf8) && (conn->proto.smtpc.utf8_supported) && ((host.encalloc) || (!Curl_is_ASCII_name(address)) || (!Curl_is_ASCII_name(host.name))))

        utf8 = TRUE;

      if(host.name) {
        auth = aprintf("<%s@%s>", address, host.name);

        Curl_free_idnconverted_hostname(&host);
      }
      else  auth = aprintf("<%s>", address);


      free(address);
    }
    else  auth = strdup("<>");


    if(!auth) {
      free(from);

      return CURLE_OUT_OF_MEMORY;
    }
  }

  
  if(data->set.mimepost.kind != MIMEKIND_NONE) {
    
    data->set.mimepost.flags &= ~MIME_BODY_ONLY;

    
    curl_mime_headers(&data->set.mimepost, data->set.headers, 0);
    result = Curl_mime_prepare_headers(&data->set.mimepost, NULL, NULL, MIMESTRATEGY_MAIL);

    if(!result)
      if(!Curl_checkheaders(data, "Mime-Version"))
        result = Curl_mime_add_header(&data->set.mimepost.curlheaders, "Mime-Version: 1.0");

    
    if(!result)
      result = Curl_mime_rewind(&data->set.mimepost);

    if(result) {
      free(from);
      free(auth);

      return result;
    }

    data->state.infilesize = Curl_mime_size(&data->set.mimepost);

    
    data->state.fread_func = (curl_read_callback) Curl_mime_read;
    data->state.in = (void *) &data->set.mimepost;
  }

  
  if(conn->proto.smtpc.size_supported && data->state.infilesize > 0) {
    size = aprintf("%" CURL_FORMAT_CURL_OFF_T, data->state.infilesize);

    if(!size) {
      free(from);
      free(auth);

      return CURLE_OUT_OF_MEMORY;
    }
  }

  
  if(conn->proto.smtpc.utf8_supported && !utf8) {
    struct SMTP *smtp = data->req.p.smtp;
    struct curl_slist *rcpt = smtp->rcpt;

    while(rcpt && !utf8) {
      
      if(!Curl_is_ASCII_name(rcpt->data))
        utf8 = TRUE;

      rcpt = rcpt->next;
    }
  }

  
  result = Curl_pp_sendf(data, &conn->proto.smtpc.pp, "MAIL FROM:%s%s%s%s%s%s", from, auth ? " AUTH=" : "", auth ? auth : "", size ? " SIZE=" : "", size ? size : "", utf8 ? " SMTPUTF8" : "");








  free(from);
  free(auth);
  free(size);

  if(!result)
    state(data, SMTP_MAIL);

  return result;
}


static CURLcode smtp_perform_rcpt_to(struct Curl_easy *data)
{
  CURLcode result = CURLE_OK;
  struct connectdata *conn = data->conn;
  struct SMTP *smtp = data->req.p.smtp;
  char *address = NULL;
  struct hostname host = { NULL, NULL, NULL, NULL };

  
  result = smtp_parse_address(data, smtp->rcpt->data, &address, &host);
  if(result)
    return result;

  
  if(host.name)
    result = Curl_pp_sendf(data, &conn->proto.smtpc.pp, "RCPT TO:<%s@%s>", address, host.name);
  else  result = Curl_pp_sendf(data, &conn->proto.smtpc.pp, "RCPT TO:<%s>", address);



  Curl_free_idnconverted_hostname(&host);
  free(address);

  if(!result)
    state(data, SMTP_RCPT);

  return result;
}


static CURLcode smtp_perform_quit(struct Curl_easy *data, struct connectdata *conn)
{
  
  CURLcode result = Curl_pp_sendf(data, &conn->proto.smtpc.pp, "%s", "QUIT");

  if(!result)
    state(data, SMTP_QUIT);

  return result;
}


static CURLcode smtp_state_servergreet_resp(struct Curl_easy *data, int smtpcode, smtpstate instate)

{
  CURLcode result = CURLE_OK;
  (void)instate; 

  if(smtpcode/100 != 2) {
    failf(data, "Got unexpected smtp-server response: %d", smtpcode);
    result = CURLE_WEIRD_SERVER_REPLY;
  }
  else result = smtp_perform_ehlo(data);

  return result;
}


static CURLcode smtp_state_starttls_resp(struct Curl_easy *data, int smtpcode, smtpstate instate)

{
  CURLcode result = CURLE_OK;
  (void)instate; 

  if(smtpcode != 220) {
    if(data->set.use_ssl != CURLUSESSL_TRY) {
      failf(data, "STARTTLS denied, code %d", smtpcode);
      result = CURLE_USE_SSL_FAILED;
    }
    else result = smtp_perform_authentication(data);
  }
  else result = smtp_perform_upgrade_tls(data);

  return result;
}


static CURLcode smtp_state_ehlo_resp(struct Curl_easy *data, struct connectdata *conn, int smtpcode, smtpstate instate)

{
  CURLcode result = CURLE_OK;
  struct smtp_conn *smtpc = &conn->proto.smtpc;
  const char *line = data->state.buffer;
  size_t len = strlen(line);

  (void)instate; 

  if(smtpcode/100 != 2 && smtpcode != 1) {
    if(data->set.use_ssl <= CURLUSESSL_TRY || conn->ssl[FIRSTSOCKET].use)
      result = smtp_perform_helo(data, conn);
    else {
      failf(data, "Remote access denied: %d", smtpcode);
      result = CURLE_REMOTE_ACCESS_DENIED;
    }
  }
  else if(len >= 4) {
    line += 4;
    len -= 4;

    
    if(len >= 8 && !memcmp(line, "STARTTLS", 8))
      smtpc->tls_supported = TRUE;

    
    else if(len >= 4 && !memcmp(line, "SIZE", 4))
      smtpc->size_supported = TRUE;

    
    else if(len >= 8 && !memcmp(line, "SMTPUTF8", 8))
      smtpc->utf8_supported = TRUE;

    
    else if(len >= 5 && !memcmp(line, "AUTH ", 5)) {
      smtpc->auth_supported = TRUE;

      
      line += 5;
      len -= 5;

      
      for(;;) {
        size_t llen;
        size_t wordlen;
        unsigned short mechbit;

        while(len && (*line == ' ' || *line == '\t' || *line == '\r' || *line == '\n')) {


          line++;
          len--;
        }

        if(!len)
          break;

        
        for(wordlen = 0; wordlen < len && line[wordlen] != ' ' && line[wordlen] != '\t' && line[wordlen] != '\r' && line[wordlen] != '\n';)

          wordlen++;

        
        mechbit = Curl_sasl_decode_mech(line, wordlen, &llen);
        if(mechbit && llen == wordlen)
          smtpc->sasl.authmechs |= mechbit;

        line += wordlen;
        len -= wordlen;
      }
    }

    if(smtpcode != 1) {
      if(data->set.use_ssl && !conn->ssl[FIRSTSOCKET].use) {
        
        if(smtpc->tls_supported)
          
          result = smtp_perform_starttls(data, conn);
        else if(data->set.use_ssl == CURLUSESSL_TRY)
          
          result = smtp_perform_authentication(data);
        else {
          failf(data, "STARTTLS not supported.");
          result = CURLE_USE_SSL_FAILED;
        }
      }
      else result = smtp_perform_authentication(data);
    }
  }
  else {
    failf(data, "Unexpectedly short EHLO response");
    result = CURLE_WEIRD_SERVER_REPLY;
  }

  return result;
}


static CURLcode smtp_state_helo_resp(struct Curl_easy *data, int smtpcode, smtpstate instate)
{
  CURLcode result = CURLE_OK;
  (void)instate; 

  if(smtpcode/100 != 2) {
    failf(data, "Remote access denied: %d", smtpcode);
    result = CURLE_REMOTE_ACCESS_DENIED;
  }
  else  state(data, SMTP_STOP);


  return result;
}


static CURLcode smtp_state_auth_resp(struct Curl_easy *data, int smtpcode, smtpstate instate)

{
  CURLcode result = CURLE_OK;
  struct connectdata *conn = data->conn;
  struct smtp_conn *smtpc = &conn->proto.smtpc;
  saslprogress progress;

  (void)instate; 

  result = Curl_sasl_continue(&smtpc->sasl, data, conn, smtpcode, &progress);
  if(!result)
    switch(progress) {
    case SASL_DONE:
      state(data, SMTP_STOP);  
      break;
    case SASL_IDLE:            
      failf(data, "Authentication cancelled");
      result = CURLE_LOGIN_DENIED;
      break;
    default:
      break;
    }

  return result;
}


static CURLcode smtp_state_command_resp(struct Curl_easy *data, int smtpcode, smtpstate instate)
{
  CURLcode result = CURLE_OK;
  struct SMTP *smtp = data->req.p.smtp;
  char *line = data->state.buffer;
  size_t len = strlen(line);

  (void)instate; 

  if((smtp->rcpt && smtpcode/100 != 2 && smtpcode != 553 && smtpcode != 1) || (!smtp->rcpt && smtpcode/100 != 2 && smtpcode != 1)) {
    failf(data, "Command failed: %d", smtpcode);
    result = CURLE_RECV_ERROR;
  }
  else {
    
    if(!data->set.opt_no_body) {
      line[len] = '\n';
      result = Curl_client_write(data, CLIENTWRITE_BODY, line, len + 1);
      line[len] = '\0';
    }

    if(smtpcode != 1) {
      if(smtp->rcpt) {
        smtp->rcpt = smtp->rcpt->next;

        if(smtp->rcpt) {
          
          result = smtp_perform_command(data);
        }
        else  state(data, SMTP_STOP);

      }
      else  state(data, SMTP_STOP);

    }
  }

  return result;
}


static CURLcode smtp_state_mail_resp(struct Curl_easy *data, int smtpcode, smtpstate instate)
{
  CURLcode result = CURLE_OK;
  (void)instate; 

  if(smtpcode/100 != 2) {
    failf(data, "MAIL failed: %d", smtpcode);
    result = CURLE_SEND_ERROR;
  }
  else  result = smtp_perform_rcpt_to(data);


  return result;
}


static CURLcode smtp_state_rcpt_resp(struct Curl_easy *data, struct connectdata *conn, int smtpcode, smtpstate instate)

{
  CURLcode result = CURLE_OK;
  struct SMTP *smtp = data->req.p.smtp;
  bool is_smtp_err = FALSE;
  bool is_smtp_blocking_err = FALSE;

  (void)instate; 

  is_smtp_err = (smtpcode/100 != 2) ? TRUE : FALSE;

  
  is_smtp_blocking_err = (is_smtp_err && !data->set.mail_rcpt_allowfails) ? TRUE : FALSE;

  if(is_smtp_err) {
    
    smtp->rcpt_last_error = smtpcode;

    if(is_smtp_blocking_err) {
      failf(data, "RCPT failed: %d", smtpcode);
      result = CURLE_SEND_ERROR;
    }
  }
  else {
    
    smtp->rcpt_had_ok = TRUE;
  }

  if(!is_smtp_blocking_err) {
    smtp->rcpt = smtp->rcpt->next;

    if(smtp->rcpt)
      
      result = smtp_perform_rcpt_to(data);
    else {
      
      if(!smtp->rcpt_had_ok) {
        failf(data, "RCPT failed: %d (last error)", smtp->rcpt_last_error);
        result = CURLE_SEND_ERROR;
      }
      else {
        
        result = Curl_pp_sendf(data, &conn->proto.smtpc.pp, "%s", "DATA");

        if(!result)
          state(data, SMTP_DATA);
      }
    }
  }

  return result;
}


static CURLcode smtp_state_data_resp(struct Curl_easy *data, int smtpcode, smtpstate instate)
{
  CURLcode result = CURLE_OK;
  (void)instate; 

  if(smtpcode != 354) {
    failf(data, "DATA failed: %d", smtpcode);
    result = CURLE_SEND_ERROR;
  }
  else {
    
    Curl_pgrsSetUploadSize(data, data->state.infilesize);

    
    Curl_setup_transfer(data, -1, -1, FALSE, FIRSTSOCKET);

    
    state(data, SMTP_STOP);
  }

  return result;
}


static CURLcode smtp_state_postdata_resp(struct Curl_easy *data, int smtpcode, smtpstate instate)

{
  CURLcode result = CURLE_OK;

  (void)instate; 

  if(smtpcode != 250)
    result = CURLE_RECV_ERROR;

  
  state(data, SMTP_STOP);

  return result;
}

static CURLcode smtp_statemachine(struct Curl_easy *data, struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  curl_socket_t sock = conn->sock[FIRSTSOCKET];
  int smtpcode;
  struct smtp_conn *smtpc = &conn->proto.smtpc;
  struct pingpong *pp = &smtpc->pp;
  size_t nread = 0;

  
  if(smtpc->state == SMTP_UPGRADETLS)
    return smtp_perform_upgrade_tls(data);

  
  if(pp->sendleft)
    return Curl_pp_flushsend(data, pp);

  do {
    
    result = Curl_pp_readresp(data, sock, pp, &smtpcode, &nread);
    if(result)
      return result;

    
    if(smtpc->state != SMTP_QUIT && smtpcode != 1)
      data->info.httpcode = smtpcode;

    if(!smtpcode)
      break;

    
    switch(smtpc->state) {
    case SMTP_SERVERGREET:
      result = smtp_state_servergreet_resp(data, smtpcode, smtpc->state);
      break;

    case SMTP_EHLO:
      result = smtp_state_ehlo_resp(data, conn, smtpcode, smtpc->state);
      break;

    case SMTP_HELO:
      result = smtp_state_helo_resp(data, smtpcode, smtpc->state);
      break;

    case SMTP_STARTTLS:
      result = smtp_state_starttls_resp(data, smtpcode, smtpc->state);
      break;

    case SMTP_AUTH:
      result = smtp_state_auth_resp(data, smtpcode, smtpc->state);
      break;

    case SMTP_COMMAND:
      result = smtp_state_command_resp(data, smtpcode, smtpc->state);
      break;

    case SMTP_MAIL:
      result = smtp_state_mail_resp(data, smtpcode, smtpc->state);
      break;

    case SMTP_RCPT:
      result = smtp_state_rcpt_resp(data, conn, smtpcode, smtpc->state);
      break;

    case SMTP_DATA:
      result = smtp_state_data_resp(data, smtpcode, smtpc->state);
      break;

    case SMTP_POSTDATA:
      result = smtp_state_postdata_resp(data, smtpcode, smtpc->state);
      break;

    case SMTP_QUIT:
      
    default:
      
      state(data, SMTP_STOP);
      break;
    }
  } while(!result && smtpc->state != SMTP_STOP && Curl_pp_moredata(pp));

  return result;
}


static CURLcode smtp_multi_statemach(struct Curl_easy *data, bool *done)
{
  CURLcode result = CURLE_OK;
  struct connectdata *conn = data->conn;
  struct smtp_conn *smtpc = &conn->proto.smtpc;

  if((conn->handler->flags & PROTOPT_SSL) && !smtpc->ssldone) {
    result = Curl_ssl_connect_nonblocking(data, conn, FALSE, FIRSTSOCKET, &smtpc->ssldone);
    if(result || !smtpc->ssldone)
      return result;
  }

  result = Curl_pp_statemach(data, &smtpc->pp, FALSE, FALSE);
  *done = (smtpc->state == SMTP_STOP) ? TRUE : FALSE;

  return result;
}

static CURLcode smtp_block_statemach(struct Curl_easy *data, struct connectdata *conn, bool disconnecting)

{
  CURLcode result = CURLE_OK;
  struct smtp_conn *smtpc = &conn->proto.smtpc;

  while(smtpc->state != SMTP_STOP && !result)
    result = Curl_pp_statemach(data, &smtpc->pp, TRUE, disconnecting);

  return result;
}


static CURLcode smtp_init(struct Curl_easy *data)
{
  CURLcode result = CURLE_OK;
  struct SMTP *smtp;

  smtp = data->req.p.smtp = calloc(sizeof(struct SMTP), 1);
  if(!smtp)
    result = CURLE_OUT_OF_MEMORY;

  return result;
}


static int smtp_getsock(struct Curl_easy *data, struct connectdata *conn, curl_socket_t *socks)
{
  return Curl_pp_getsock(data, &conn->proto.smtpc.pp, socks);
}


static CURLcode smtp_connect(struct Curl_easy *data, bool *done)
{
  CURLcode result = CURLE_OK;
  struct connectdata *conn = data->conn;
  struct smtp_conn *smtpc = &conn->proto.smtpc;
  struct pingpong *pp = &smtpc->pp;

  *done = FALSE; 

  
  connkeep(conn, "SMTP default");

  PINGPONG_SETUP(pp, smtp_statemachine, smtp_endofresp);

  
  Curl_sasl_init(&smtpc->sasl, &saslsmtp);

  
  Curl_pp_setup(pp);
  Curl_pp_init(data, pp);

  
  result = smtp_parse_url_options(conn);
  if(result)
    return result;

  
  result = smtp_parse_url_path(data);
  if(result)
    return result;

  
  state(data, SMTP_SERVERGREET);

  result = smtp_multi_statemach(data, done);

  return result;
}


static CURLcode smtp_done(struct Curl_easy *data, CURLcode status, bool premature)
{
  CURLcode result = CURLE_OK;
  struct connectdata *conn = data->conn;
  struct SMTP *smtp = data->req.p.smtp;
  struct pingpong *pp = &conn->proto.smtpc.pp;
  char *eob;
  ssize_t len;
  ssize_t bytes_written;

  (void)premature;

  if(!smtp)
    return CURLE_OK;

  
  Curl_safefree(smtp->custom);

  if(status) {
    connclose(conn, "SMTP done with bad status"); 
    result = status;         
  }
  else if(!data->set.connect_only && data->set.mail_rcpt && (data->set.upload || data->set.mimepost.kind)) {
    
    if(smtp->trailing_crlf || !data->state.infilesize) {
      eob = strdup(&SMTP_EOB[2]);
      len = SMTP_EOB_LEN - 2;
    }
    else {
      eob = strdup(SMTP_EOB);
      len = SMTP_EOB_LEN;
    }

    if(!eob)
      return CURLE_OUT_OF_MEMORY;

    
    result = Curl_write(data, conn->writesockfd, eob, len, &bytes_written);
    if(result) {
      free(eob);
      return result;
    }

    if(bytes_written != len) {
      
      pp->sendthis = eob;
      pp->sendsize = len;
      pp->sendleft = len - bytes_written;
    }
    else {
      
      pp->response = Curl_now();

      free(eob);
    }

    state(data, SMTP_POSTDATA);

    
    result = smtp_block_statemach(data, conn, FALSE);
  }

  
  smtp->transfer = PPTRANSFER_BODY;

  return result;
}


static CURLcode smtp_perform(struct Curl_easy *data, bool *connected, bool *dophase_done)
{
  
  CURLcode result = CURLE_OK;
  struct connectdata *conn = data->conn;
  struct SMTP *smtp = data->req.p.smtp;

  DEBUGF(infof(data, "DO phase starts"));

  if(data->set.opt_no_body) {
    
    smtp->transfer = PPTRANSFER_INFO;
  }

  *dophase_done = FALSE; 

  
  smtp->rcpt = data->set.mail_rcpt;

  
  smtp->rcpt_had_ok = FALSE;

  
  smtp->rcpt_last_error = 0;

  
  smtp->trailing_crlf = TRUE;
  smtp->eob = 2;

  
  if((data->set.upload || data->set.mimepost.kind) && data->set.mail_rcpt)
    
    result = smtp_perform_mail(data);
  else  result = smtp_perform_command(data);


  if(result)
    return result;

  
  result = smtp_multi_statemach(data, dophase_done);

  *connected = conn->bits.tcpconnect[FIRSTSOCKET];

  if(*dophase_done)
    DEBUGF(infof(data, "DO phase is complete"));

  return result;
}


static CURLcode smtp_do(struct Curl_easy *data, bool *done)
{
  CURLcode result = CURLE_OK;
  *done = FALSE; 

  
  result = smtp_parse_custom_request(data);
  if(result)
    return result;

  result = smtp_regular_transfer(data, done);

  return result;
}


static CURLcode smtp_disconnect(struct Curl_easy *data, struct connectdata *conn, bool dead_connection)

{
  struct smtp_conn *smtpc = &conn->proto.smtpc;
  (void)data;

  

  if(!dead_connection && conn->bits.protoconnstart) {
    if(!smtp_perform_quit(data, conn))
      (void)smtp_block_statemach(data, conn, TRUE); 
  }

  
  Curl_pp_disconnect(&smtpc->pp);

  
  Curl_sasl_cleanup(conn, smtpc->sasl.authused);

  
  Curl_safefree(smtpc->domain);

  return CURLE_OK;
}


static CURLcode smtp_dophase_done(struct Curl_easy *data, bool connected)
{
  struct SMTP *smtp = data->req.p.smtp;

  (void)connected;

  if(smtp->transfer != PPTRANSFER_BODY)
    
    Curl_setup_transfer(data, -1, -1, FALSE, -1);

  return CURLE_OK;
}


static CURLcode smtp_doing(struct Curl_easy *data, bool *dophase_done)
{
  CURLcode result = smtp_multi_statemach(data, dophase_done);

  if(result)
    DEBUGF(infof(data, "DO phase failed"));
  else if(*dophase_done) {
    result = smtp_dophase_done(data, FALSE );

    DEBUGF(infof(data, "DO phase is complete"));
  }

  return result;
}


static CURLcode smtp_regular_transfer(struct Curl_easy *data, bool *dophase_done)
{
  CURLcode result = CURLE_OK;
  bool connected = FALSE;

  
  data->req.size = -1;

  
  Curl_pgrsSetUploadCounter(data, 0);
  Curl_pgrsSetDownloadCounter(data, 0);
  Curl_pgrsSetUploadSize(data, -1);
  Curl_pgrsSetDownloadSize(data, -1);

  
  result = smtp_perform(data, &connected, dophase_done);

  
  if(!result && *dophase_done)
    result = smtp_dophase_done(data, connected);

  return result;
}

static CURLcode smtp_setup_connection(struct Curl_easy *data, struct connectdata *conn)
{
  CURLcode result;

  
  conn->bits.tls_upgraded = FALSE;

  
  result = smtp_init(data);
  if(result)
    return result;

  return CURLE_OK;
}


static CURLcode smtp_parse_url_options(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct smtp_conn *smtpc = &conn->proto.smtpc;
  const char *ptr = conn->options;

  smtpc->sasl.resetprefs = TRUE;

  while(!result && ptr && *ptr) {
    const char *key = ptr;
    const char *value;

    while(*ptr && *ptr != '=')
      ptr++;

    value = ptr + 1;

    while(*ptr && *ptr != ';')
      ptr++;

    if(strncasecompare(key, "AUTH=", 5))
      result = Curl_sasl_parse_url_auth_option(&smtpc->sasl, value, ptr - value);
    else result = CURLE_URL_MALFORMAT;

    if(*ptr == ';')
      ptr++;
  }

  return result;
}


static CURLcode smtp_parse_url_path(struct Curl_easy *data)
{
  
  struct connectdata *conn = data->conn;
  struct smtp_conn *smtpc = &conn->proto.smtpc;
  const char *path = &data->state.up.path[1]; 
  char localhost[HOSTNAME_MAX + 1];

  
  if(!*path) {
    if(!Curl_gethostname(localhost, sizeof(localhost)))
      path = localhost;
    else path = "localhost";
  }

  
  return Curl_urldecode(data, path, 0, &smtpc->domain, NULL, REJECT_CTRL);
}


static CURLcode smtp_parse_custom_request(struct Curl_easy *data)
{
  CURLcode result = CURLE_OK;
  struct SMTP *smtp = data->req.p.smtp;
  const char *custom = data->set.str[STRING_CUSTOMREQUEST];

  
  if(custom)
    result = Curl_urldecode(data, custom, 0, &smtp->custom, NULL, REJECT_CTRL);

  return result;
}


static CURLcode smtp_parse_address(struct Curl_easy *data, const char *fqma, char **address, struct hostname *host)
{
  CURLcode result = CURLE_OK;
  size_t length;

  
  char *dup = strdup(fqma[0] == '<' ? fqma + 1  : fqma);
  if(!dup)
    return CURLE_OUT_OF_MEMORY;

  length = strlen(dup);
  if(length) {
    if(dup[length - 1] == '>')
      dup[length - 1] = '\0';
  }

  
  host->name = strpbrk(dup, "@");
  if(host->name) {
    *host->name = '\0';
    host->name = host->name + 1;

    
    (void) Curl_idnconvert_hostname(data, host);

    
  }

  
  *address = dup;

  return result;
}

CURLcode Curl_smtp_escape_eob(struct Curl_easy *data, const ssize_t nread)
{
  
  ssize_t i;
  ssize_t si;
  struct SMTP *smtp = data->req.p.smtp;
  char *scratch = data->state.scratch;
  char *newscratch = NULL;
  char *oldscratch = NULL;
  size_t eob_sent;

  
  if(!scratch || data->set.crlf) {
    oldscratch = scratch;

    scratch = newscratch = malloc(2 * data->set.upload_buffer_size);
    if(!newscratch) {
      failf(data, "Failed to alloc scratch buffer!");

      return CURLE_OUT_OF_MEMORY;
    }
  }
  DEBUGASSERT((size_t)data->set.upload_buffer_size >= (size_t)nread);

  
  eob_sent = smtp->eob;

  
  for(i = 0, si = 0; i < nread; i++) {
    if(SMTP_EOB[smtp->eob] == data->req.upload_fromhere[i]) {
      smtp->eob++;

      
      if(2 == smtp->eob || SMTP_EOB_LEN == smtp->eob)
        smtp->trailing_crlf = TRUE;
      else smtp->trailing_crlf = FALSE;
    }
    else if(smtp->eob) {
      
      memcpy(&scratch[si], &SMTP_EOB[eob_sent], smtp->eob - eob_sent);
      si += smtp->eob - eob_sent;

      
      if(SMTP_EOB[0] == data->req.upload_fromhere[i])
        smtp->eob = 1;
      else smtp->eob = 0;

      eob_sent = 0;

      
      smtp->trailing_crlf = FALSE;
    }

    
    if(SMTP_EOB_FIND_LEN == smtp->eob) {
      
      memcpy(&scratch[si], &SMTP_EOB_REPL[eob_sent], SMTP_EOB_REPL_LEN - eob_sent);
      si += SMTP_EOB_REPL_LEN - eob_sent;
      smtp->eob = 0;
      eob_sent = 0;
    }
    else if(!smtp->eob)
      scratch[si++] = data->req.upload_fromhere[i];
  }

  if(smtp->eob - eob_sent) {
    
    memcpy(&scratch[si], &SMTP_EOB[eob_sent], smtp->eob - eob_sent);
    si += smtp->eob - eob_sent;
  }

  
  if(si != nread) {
    
    data->req.upload_fromhere = scratch;

    
    data->state.scratch = scratch;

    
    free(oldscratch);

    
    data->req.upload_present = si;
  }
  else free(newscratch);

  return CURLE_OK;
}


