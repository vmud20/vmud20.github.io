








































































static CURLcode smtp_regular_transfer(struct connectdata *conn, bool *done);
static CURLcode smtp_do(struct connectdata *conn, bool *done);
static CURLcode smtp_done(struct connectdata *conn, CURLcode, bool premature);
static CURLcode smtp_connect(struct connectdata *conn, bool *done);
static CURLcode smtp_disconnect(struct connectdata *conn, bool dead);
static CURLcode smtp_multi_statemach(struct connectdata *conn, bool *done);
static int smtp_getsock(struct connectdata *conn, curl_socket_t *socks, int numsocks);

static CURLcode smtp_doing(struct connectdata *conn, bool *dophase_done);
static CURLcode smtp_setup_connection(struct connectdata * conn);
static CURLcode smtp_state_upgrade_tls(struct connectdata *conn);



const struct Curl_handler Curl_handler_smtp = {
  "SMTP",                            smtp_setup_connection, smtp_do, smtp_done, ZERO_NULL, smtp_connect, smtp_multi_statemach, smtp_doing, smtp_getsock, smtp_getsock, ZERO_NULL, ZERO_NULL, smtp_disconnect, ZERO_NULL, PORT_SMTP, CURLPROTO_SMTP, PROTOPT_CLOSEACTION | PROTOPT_NOURLQUERY };




















const struct Curl_handler Curl_handler_smtps = {
  "SMTPS",                           smtp_setup_connection, smtp_do, smtp_done, ZERO_NULL, smtp_connect, smtp_multi_statemach, smtp_doing, smtp_getsock, smtp_getsock, ZERO_NULL, ZERO_NULL, smtp_disconnect, ZERO_NULL, PORT_SMTPS, CURLPROTO_SMTP | CURLPROTO_SMTPS, PROTOPT_CLOSEACTION | PROTOPT_SSL | PROTOPT_NOURLQUERY };






















static const struct Curl_handler Curl_handler_smtp_proxy = {
  "SMTP",                                ZERO_NULL, Curl_http, Curl_http_done, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, PORT_SMTP, CURLPROTO_HTTP, PROTOPT_NONE };




















static const struct Curl_handler Curl_handler_smtps_proxy = {
  "SMTPS",                               ZERO_NULL, Curl_http, Curl_http_done, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, ZERO_NULL, PORT_SMTPS, CURLPROTO_HTTP, PROTOPT_NONE };




















static int smtp_endofresp(struct pingpong *pp, int *resp)
{
  char *line = pp->linestart_resp;
  size_t len = pp->nread_resp;
  struct connectdata *conn = pp->conn;
  struct smtp_conn *smtpc = &conn->proto.smtpc;
  int result;
  size_t wordlen;

  if(len < 4 || !ISDIGIT(line[0]) || !ISDIGIT(line[1]) || !ISDIGIT(line[2]))
    return FALSE;       

  if((result = (line[3] == ' ')) != 0)
    *resp = curlx_sltosi(strtol(line, NULL, 10));

  line += 4;
  len -= 4;

  if(smtpc->state == SMTP_EHLO && len >= 5 && !memcmp(line, "AUTH ", 5)) {
    line += 5;
    len -= 5;

    for(;;) {
      while(len && (*line == ' ' || *line == '\t' || *line == '\r' || *line == '\n')) {

        line++;
        len--;
      }

      if(!len)
        break;

      for(wordlen = 0; wordlen < len && line[wordlen] != ' ' && line[wordlen] != '\t' && line[wordlen] != '\r' && line[wordlen] != '\n';)

        wordlen++;

      if(wordlen == 5 && !memcmp(line, "LOGIN", 5))
        smtpc->authmechs |= SMTP_AUTH_LOGIN;
      else if(wordlen == 5 && !memcmp(line, "PLAIN", 5))
        smtpc->authmechs |= SMTP_AUTH_PLAIN;
      else if(wordlen == 8 && !memcmp(line, "CRAM-MD5", 8))
        smtpc->authmechs |= SMTP_AUTH_CRAM_MD5;
      else if(wordlen == 10 && !memcmp(line, "DIGEST-MD5", 10))
        smtpc->authmechs |= SMTP_AUTH_DIGEST_MD5;
      else if(wordlen == 6 && !memcmp(line, "GSSAPI", 6))
        smtpc->authmechs |= SMTP_AUTH_GSSAPI;
      else if(wordlen == 8 && !memcmp(line, "EXTERNAL", 8))
        smtpc->authmechs |= SMTP_AUTH_EXTERNAL;
      else if(wordlen == 4 && !memcmp(line, "NTLM", 4))
        smtpc->authmechs |= SMTP_AUTH_NTLM;

      line += wordlen;
      len -= wordlen;
    }
  }

  return result;
}


static void state(struct connectdata *conn, smtpstate newstate)
{
  struct smtp_conn *smtpc = &conn->proto.smtpc;

  
  static const char * const names[] = {
    "STOP", "SERVERGREET", "EHLO", "HELO", "STARTTLS", "UPGRADETLS", "AUTHPLAIN", "AUTHLOGIN", "AUTHPASSWD", "AUTHCRAM", "AUTHNTLM", "AUTHNTLM_TYPE2MSG", "AUTH", "MAIL", "RCPT", "DATA", "POSTDATA", "QUIT",  };


















  if(smtpc->state != newstate)
    infof(conn->data, "SMTP %p state change from %s to %s\n", smtpc, names[smtpc->state], names[newstate]);

  smtpc->state = newstate;
}

static CURLcode smtp_state_ehlo(struct connectdata *conn)
{
  CURLcode result;
  struct smtp_conn *smtpc = &conn->proto.smtpc;

  smtpc->authmechs = 0;         
  smtpc->authused = 0;          

  
  result = Curl_pp_sendf(&smtpc->pp, "EHLO %s", smtpc->domain);

  if(result)
    return result;

  state(conn, SMTP_EHLO);
  return CURLE_OK;
}

static CURLcode smtp_state_helo(struct connectdata *conn)
{
  CURLcode result;
  struct smtp_conn *smtpc = &conn->proto.smtpc;

  smtpc->authused = 0;          

  
  result = Curl_pp_sendf(&smtpc->pp, "HELO %s", smtpc->domain);

  if(result)
    return result;

  state(conn, SMTP_HELO);
  return CURLE_OK;
}

static CURLcode smtp_auth_plain_data(struct connectdata *conn, char **outptr, size_t *outlen)
{
  char plainauth[2 * MAX_CURL_USER_LENGTH + MAX_CURL_PASSWORD_LENGTH];
  size_t ulen;
  size_t plen;

  ulen = strlen(conn->user);
  plen = strlen(conn->passwd);

  if(2 * ulen + plen + 2 > sizeof plainauth) {
    *outlen = 0;
    *outptr = NULL;
    return CURLE_OUT_OF_MEMORY; 
  }

  memcpy(plainauth, conn->user, ulen);
  plainauth[ulen] = '\0';
  memcpy(plainauth + ulen + 1, conn->user, ulen);
  plainauth[2 * ulen + 1] = '\0';
  memcpy(plainauth + 2 * ulen + 2, conn->passwd, plen);
  return Curl_base64_encode(conn->data, plainauth, 2 * ulen + plen + 2, outptr, outlen);
}

static CURLcode smtp_auth_login_user(struct connectdata *conn, char **outptr, size_t *outlen)
{
  size_t ulen = strlen(conn->user);

  if(!ulen) {
    *outptr = strdup("=");
    if(*outptr) {
      *outlen = (size_t) 1;
      return CURLE_OK;
    }
    *outlen = 0;
    return CURLE_OUT_OF_MEMORY;
  }

  return Curl_base64_encode(conn->data, conn->user, ulen, outptr, outlen);
}


static CURLcode smtp_auth_ntlm_type1_message(struct connectdata *conn, char **outptr, size_t *outlen)
{
  return Curl_ntlm_create_type1_message(conn->user, conn->passwd, &conn->ntlm, outptr, outlen);
}


static CURLcode smtp_authenticate(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct smtp_conn *smtpc = &conn->proto.smtpc;
  char *initresp = NULL;
  const char *mech = NULL;
  size_t len = 0;
  smtpstate state1 = SMTP_STOP;
  smtpstate state2 = SMTP_STOP;

  
  if(!conn->bits.user_passwd) {
    state(conn, SMTP_STOP);

    return result;
  }

  

  if(smtpc->authmechs & SMTP_AUTH_CRAM_MD5) {
    mech = "CRAM-MD5";
    state1 = SMTP_AUTHCRAM;
    smtpc->authused = SMTP_AUTH_CRAM_MD5;
  }
  else   if(smtpc->authmechs & SMTP_AUTH_NTLM) {


    mech = "NTLM";
    state1 = SMTP_AUTHNTLM;
    state2 = SMTP_AUTHNTLM_TYPE2MSG;
    smtpc->authused = SMTP_AUTH_NTLM;
    result = smtp_auth_ntlm_type1_message(conn, &initresp, &len);
  }
  else  if(smtpc->authmechs & SMTP_AUTH_LOGIN) {

    mech = "LOGIN";
    state1 = SMTP_AUTHLOGIN;
    state2 = SMTP_AUTHPASSWD;
    smtpc->authused = SMTP_AUTH_LOGIN;
    result = smtp_auth_login_user(conn, &initresp, &len);
  }
  else if(smtpc->authmechs & SMTP_AUTH_PLAIN) {
    mech = "PLAIN";
    state1 = SMTP_AUTHPLAIN;
    state2 = SMTP_AUTH;
    smtpc->authused = SMTP_AUTH_PLAIN;
    result = smtp_auth_plain_data(conn, &initresp, &len);
  }
  else {
    infof(conn->data, "No known auth mechanisms supported!\n");
    result = CURLE_LOGIN_DENIED;      
  }

  if(!result) {
    if(initresp && strlen(mech) + len <= 512 - 8) {
       result = Curl_pp_sendf(&smtpc->pp, "AUTH %s %s", mech, initresp);

      if(!result)
        state(conn, state2);
    }
    else {
      result = Curl_pp_sendf(&smtpc->pp, "AUTH %s", mech);

      if(!result)
        state(conn, state1);
    }
    Curl_safefree(initresp);
  }

  return result;
}


static int smtp_getsock(struct connectdata *conn, curl_socket_t *socks, int numsocks)

{
  return Curl_pp_getsock(&conn->proto.smtpc.pp, socks, numsocks);
}


static void smtp_to_smtps(struct connectdata *conn)
{
  conn->handler = &Curl_handler_smtps;
}





static CURLcode smtp_state_starttls_resp(struct connectdata *conn, int smtpcode, smtpstate instate)

{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  (void)instate; 

  if(smtpcode != 220) {
    if(data->set.use_ssl != CURLUSESSL_TRY) {
      failf(data, "STARTTLS denied. %c", smtpcode);
      result = CURLE_USE_SSL_FAILED;
    }
    else result = smtp_authenticate(conn);
  }
  else {
    if(data->state.used_interface == Curl_if_multi) {
      state(conn, SMTP_UPGRADETLS);
      return smtp_state_upgrade_tls(conn);
    }
    else {
      result = Curl_ssl_connect(conn, FIRSTSOCKET);
      if(CURLE_OK == result) {
        smtp_to_smtps(conn);
        result = smtp_state_ehlo(conn);
      }
    }
  }

  return result;
}

static CURLcode smtp_state_upgrade_tls(struct connectdata *conn)
{
  struct smtp_conn *smtpc = &conn->proto.smtpc;
  CURLcode result;

  result = Curl_ssl_connect_nonblocking(conn, FIRSTSOCKET, &smtpc->ssldone);

  if(smtpc->ssldone) {
    smtp_to_smtps(conn);
    result = smtp_state_ehlo(conn);
  }

  return result;
}


static CURLcode smtp_state_ehlo_resp(struct connectdata *conn, int smtpcode, smtpstate instate)

{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;

  (void)instate; 

  if(smtpcode/100 != 2) {
    if((data->set.use_ssl <= CURLUSESSL_TRY || conn->ssl[FIRSTSOCKET].use) && !conn->bits.user_passwd)
      result = smtp_state_helo(conn);
    else {
      failf(data, "Access denied: %d", smtpcode);
      result = CURLE_LOGIN_DENIED;
    }
  }
  else if(data->set.use_ssl && !conn->ssl[FIRSTSOCKET].use) {
    
    result = Curl_pp_sendf(&conn->proto.smtpc.pp, "STARTTLS");
    state(conn, SMTP_STARTTLS);
  }
  else result = smtp_authenticate(conn);

  return result;
}


static CURLcode smtp_state_helo_resp(struct connectdata *conn, int smtpcode, smtpstate instate)

{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;

  (void)instate; 

  if(smtpcode/100 != 2) {
    failf(data, "Access denied: %d", smtpcode);
    result = CURLE_LOGIN_DENIED;
  }
  else {
    
    state(conn, SMTP_STOP);
  }

  return result;
}


static CURLcode smtp_state_authplain_resp(struct connectdata *conn, int smtpcode, smtpstate instate)

{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  size_t len = 0;
  char *plainauth = NULL;

  (void)instate; 

  if(smtpcode != 334) {
    failf(data, "Access denied: %d", smtpcode);
    result = CURLE_LOGIN_DENIED;
  }
  else {
    result = smtp_auth_plain_data(conn, &plainauth, &len);

    if(!result) {
      if(plainauth) {
        result = Curl_pp_sendf(&conn->proto.smtpc.pp, "%s", plainauth);

        if(!result)
          state(conn, SMTP_AUTH);
      }
      Curl_safefree(plainauth);
    }
  }

  return result;
}


static CURLcode smtp_state_authlogin_resp(struct connectdata *conn, int smtpcode, smtpstate instate)

{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  size_t len = 0;
  char *authuser = NULL;

  (void)instate; 

  if(smtpcode != 334) {
    failf(data, "Access denied: %d", smtpcode);
    result = CURLE_LOGIN_DENIED;
  }
  else {
    result = smtp_auth_login_user(conn, &authuser, &len);

    if(!result) {
      if(authuser) {
        result = Curl_pp_sendf(&conn->proto.smtpc.pp, "%s", authuser);

        if(!result)
          state(conn, SMTP_AUTHPASSWD);
      }
      Curl_safefree(authuser);
    }
  }

  return result;
}


static CURLcode smtp_state_authpasswd_resp(struct connectdata *conn, int smtpcode, smtpstate instate)

{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  size_t plen;
  size_t len = 0;
  char *authpasswd = NULL;

  (void)instate; 

  if(smtpcode != 334) {
    failf(data, "Access denied: %d", smtpcode);
    result = CURLE_LOGIN_DENIED;
  }
  else {
    plen = strlen(conn->passwd);

    if(!plen)
      result = Curl_pp_sendf(&conn->proto.smtpc.pp, "=");
    else {
      result = Curl_base64_encode(data, conn->passwd, plen, &authpasswd, &len);

      if(!result) {
        if(authpasswd) {
          result = Curl_pp_sendf(&conn->proto.smtpc.pp, "%s", authpasswd);

          if(!result)
            state(conn, SMTP_AUTH);
        }
        Curl_safefree(authpasswd);
      }
    }
  }

  return result;
}




static CURLcode smtp_state_authcram_resp(struct connectdata *conn, int smtpcode, smtpstate instate)

{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  char * chlg64 = data->state.buffer;
  unsigned char * chlg;
  size_t chlglen;
  size_t len = 0;
  char *rplyb64 = NULL;
  HMAC_context *ctxt;
  unsigned char digest[16];
  char reply[MAX_CURL_USER_LENGTH + 32  + 1];

  (void)instate; 

  if(smtpcode != 334) {
    failf(data, "Access denied: %d", smtpcode);
    return CURLE_LOGIN_DENIED;
  }

  
  for(chlg64 += 4; *chlg64 == ' ' || *chlg64 == '\t'; chlg64++)
    ;

  chlg = (unsigned char *) NULL;
  chlglen = 0;

  if(*chlg64 != '=') {
    for(len = strlen(chlg64); len--;)
      if(chlg64[len] != '\r' && chlg64[len] != '\n' && chlg64[len] != ' ' && chlg64[len] != '\t')
        break;

    if(++len) {
      chlg64[len] = '\0';

      result = Curl_base64_decode(chlg64, &chlg, &chlglen);
      if(result)
        return result;
    }
  }

  
  ctxt = Curl_HMAC_init(Curl_HMAC_MD5, (const unsigned char *) conn->passwd, (unsigned int)(strlen(conn->passwd)));


  if(!ctxt) {
    Curl_safefree(chlg);
    return CURLE_OUT_OF_MEMORY;
  }

  if(chlglen > 0)
    Curl_HMAC_update(ctxt, chlg, (unsigned int)(chlglen));

  Curl_safefree(chlg);

  Curl_HMAC_final(ctxt, digest);

  
  snprintf(reply, sizeof reply, "%s %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", conn->user, digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7], digest[8], digest[9], digest[10], digest[11], digest[12], digest[13], digest[14], digest[15]);





  
  result = Curl_base64_encode(data, reply, 0, &rplyb64, &len);

  if(!result) {
    if(rplyb64) {
      result = Curl_pp_sendf(&conn->proto.smtpc.pp, "%s", rplyb64);

      if(!result)
        state(conn, SMTP_AUTH);
    }
    Curl_safefree(rplyb64);
  }

  return result;
}





static CURLcode smtp_state_auth_ntlm_resp(struct connectdata *conn, int smtpcode, smtpstate instate)

{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  char *type1msg = NULL;
  size_t len = 0;

  (void)instate; 

  if(smtpcode != 334) {
    failf(data, "Access denied: %d", smtpcode);
    result = CURLE_LOGIN_DENIED;
  }
  else {
    result = smtp_auth_ntlm_type1_message(conn, &type1msg, &len);

    if(!result) {
      if(type1msg) {
        result = Curl_pp_sendf(&conn->proto.smtpc.pp, "%s", type1msg);

        if(!result)
          state(conn, SMTP_AUTHNTLM_TYPE2MSG);
      }
      Curl_safefree(type1msg);
    }
  }

  return result;
}


static CURLcode smtp_state_auth_ntlm_type2msg_resp(struct connectdata *conn, int smtpcode, smtpstate instate)

{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  char *type3msg = NULL;
  size_t len = 0;

  (void)instate; 

  if(smtpcode != 334) {
    failf(data, "Access denied: %d", smtpcode);
    result = CURLE_LOGIN_DENIED;
  }
  else {
    result = Curl_ntlm_decode_type2_message(data, data->state.buffer + 4, &conn->ntlm);
    if(!result) {
      result = Curl_ntlm_create_type3_message(conn->data, conn->user, conn->passwd, &conn->ntlm, &type3msg, &len);

      if(!result) {
        if(type3msg) {
          result = Curl_pp_sendf(&conn->proto.smtpc.pp, "%s", type3msg);

          if(!result)
            state(conn, SMTP_AUTH);
        }
        Curl_safefree(type3msg);
      }
    }
  }

  return result;
}



static CURLcode smtp_state_auth_resp(struct connectdata *conn, int smtpcode, smtpstate instate)

{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;

  (void)instate; 

  if(smtpcode != 235) {
    failf(data, "Authentication failed: %d", smtpcode);
    result = CURLE_LOGIN_DENIED;
  }
  else state(conn, SMTP_STOP);

  return result;
}


static CURLcode smtp_mail(struct connectdata *conn)
{
  char *from = NULL;
  char *size = NULL;
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;

  
  if(!data->set.str[STRING_MAIL_FROM])
    
    from = strdup("<>");
  else if(data->set.str[STRING_MAIL_FROM][0] == '<')
    from = aprintf("%s", data->set.str[STRING_MAIL_FROM]);
  else from = aprintf("<%s>", data->set.str[STRING_MAIL_FROM]);

  if(!from)
    return CURLE_OUT_OF_MEMORY;

  
  if(conn->data->set.infilesize > 0) {
    size = aprintf("%" FORMAT_OFF_T, data->set.infilesize);

    if(!size) {
      Curl_safefree(from);

      return CURLE_OUT_OF_MEMORY;
    }
  }

  
  if(!size)
    result = Curl_pp_sendf(&conn->proto.smtpc.pp, "MAIL FROM:%s", from);
  else result = Curl_pp_sendf(&conn->proto.smtpc.pp, "MAIL FROM:%s SIZE=%s", from, size);


  Curl_safefree(size);
  Curl_safefree(from);

  if(result)
    return result;

  state(conn, SMTP_MAIL);

  return result;
}

static CURLcode smtp_rcpt_to(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct smtp_conn *smtpc = &conn->proto.smtpc;

  
  if(smtpc->rcpt) {
    if(smtpc->rcpt->data[0] == '<')
      result = Curl_pp_sendf(&conn->proto.smtpc.pp, "RCPT TO:%s", smtpc->rcpt->data);
    else result = Curl_pp_sendf(&conn->proto.smtpc.pp, "RCPT TO:<%s>", smtpc->rcpt->data);

    if(!result)
      state(conn, SMTP_RCPT);
  }

  return result;
}


static CURLcode smtp_state_mail_resp(struct connectdata *conn, int smtpcode, smtpstate instate)

{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  (void)instate; 

  if(smtpcode/100 != 2) {
    failf(data, "Access denied: %d", smtpcode);
    result = CURLE_LOGIN_DENIED;
    state(conn, SMTP_STOP);
  }
  else {
    struct smtp_conn *smtpc = &conn->proto.smtpc;
    smtpc->rcpt = data->set.mail_rcpt;

    result = smtp_rcpt_to(conn);
  }

  return result;
}


static CURLcode smtp_state_rcpt_resp(struct connectdata *conn, int smtpcode, smtpstate instate)

{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  (void)instate; 

  if(smtpcode/100 != 2) {
    failf(data, "Access denied: %d", smtpcode);
    result = CURLE_LOGIN_DENIED;
    state(conn, SMTP_STOP);
  }
  else {
    struct smtp_conn *smtpc = &conn->proto.smtpc;

    if(smtpc->rcpt) {
      smtpc->rcpt = smtpc->rcpt->next;
      result = smtp_rcpt_to(conn);

      
      if(result || smtpc->rcpt)
        return result;
    }

    
    result = Curl_pp_sendf(&conn->proto.smtpc.pp, "DATA");
    if(result)
      return result;

    state(conn, SMTP_DATA);
  }

  return result;
}


static CURLcode smtp_state_data_resp(struct connectdata *conn, int smtpcode, smtpstate instate)

{
  struct SessionHandle *data = conn->data;
  struct FTP *smtp = data->state.proto.smtp;

  (void)instate; 

  if(smtpcode != 354) {
    state(conn, SMTP_STOP);
    return CURLE_RECV_ERROR;
  }

  
  Curl_setup_transfer(conn, -1, -1, FALSE, NULL,  FIRSTSOCKET, smtp->bytecountp);

  state(conn, SMTP_STOP);
  return CURLE_OK;
}


static CURLcode smtp_state_postdata_resp(struct connectdata *conn, int smtpcode, smtpstate instate)

{
  CURLcode result = CURLE_OK;

  (void)instate; 

  if(smtpcode != 250)
    result = CURLE_RECV_ERROR;

  state(conn, SMTP_STOP);

  return result;
}

static CURLcode smtp_statemach_act(struct connectdata *conn)
{
  CURLcode result;
  curl_socket_t sock = conn->sock[FIRSTSOCKET];
  struct SessionHandle *data = conn->data;
  int smtpcode;
  struct smtp_conn *smtpc = &conn->proto.smtpc;
  struct pingpong *pp = &smtpc->pp;
  size_t nread = 0;

  if(smtpc->state == SMTP_UPGRADETLS)
    return smtp_state_upgrade_tls(conn);

  if(pp->sendleft)
    
    return Curl_pp_flushsend(pp);

  
  result = Curl_pp_readresp(sock, pp, &smtpcode, &nread);
  if(result)
    return result;

  if(smtpcode) {
    
    switch(smtpc->state) {
    case SMTP_SERVERGREET:
      if(smtpcode/100 != 2) {
        failf(data, "Got unexpected smtp-server response: %d", smtpcode);
        return CURLE_FTP_WEIRD_SERVER_REPLY;
      }

      result = smtp_state_ehlo(conn);
      if(result)
        return result;
      break;

    case SMTP_EHLO:
      result = smtp_state_ehlo_resp(conn, smtpcode, smtpc->state);
      break;

    case SMTP_HELO:
      result = smtp_state_helo_resp(conn, smtpcode, smtpc->state);
      break;

    case SMTP_STARTTLS:
      result = smtp_state_starttls_resp(conn, smtpcode, smtpc->state);
      break;

    case SMTP_AUTHPLAIN:
      result = smtp_state_authplain_resp(conn, smtpcode, smtpc->state);
      break;

    case SMTP_AUTHLOGIN:
      result = smtp_state_authlogin_resp(conn, smtpcode, smtpc->state);
      break;

    case SMTP_AUTHPASSWD:
      result = smtp_state_authpasswd_resp(conn, smtpcode, smtpc->state);
      break;


    case SMTP_AUTHCRAM:
      result = smtp_state_authcram_resp(conn, smtpcode, smtpc->state);
      break;



    case SMTP_AUTHNTLM:
      result = smtp_state_auth_ntlm_resp(conn, smtpcode, smtpc->state);
      break;

    case SMTP_AUTHNTLM_TYPE2MSG:
      result = smtp_state_auth_ntlm_type2msg_resp(conn, smtpcode, smtpc->state);
      break;


    case SMTP_AUTH:
      result = smtp_state_auth_resp(conn, smtpcode, smtpc->state);
      break;

    case SMTP_MAIL:
      result = smtp_state_mail_resp(conn, smtpcode, smtpc->state);
      break;

    case SMTP_RCPT:
      result = smtp_state_rcpt_resp(conn, smtpcode, smtpc->state);
      break;

    case SMTP_DATA:
      result = smtp_state_data_resp(conn, smtpcode, smtpc->state);
      break;

    case SMTP_POSTDATA:
      result = smtp_state_postdata_resp(conn, smtpcode, smtpc->state);
      break;

    case SMTP_QUIT:
      
    default:
      
      state(conn, SMTP_STOP);
      break;
    }
  }

  return result;
}


static CURLcode smtp_multi_statemach(struct connectdata *conn, bool *done)
{
  struct smtp_conn *smtpc = &conn->proto.smtpc;
  CURLcode result;

  if((conn->handler->flags & PROTOPT_SSL) && !smtpc->ssldone)
    result = Curl_ssl_connect_nonblocking(conn, FIRSTSOCKET, &smtpc->ssldone);
  else result = Curl_pp_multi_statemach(&smtpc->pp);

  *done = (smtpc->state == SMTP_STOP) ? TRUE : FALSE;

  return result;
}

static CURLcode smtp_easy_statemach(struct connectdata *conn)
{
  struct smtp_conn *smtpc = &conn->proto.smtpc;
  struct pingpong *pp = &smtpc->pp;
  CURLcode result = CURLE_OK;

  while(smtpc->state != SMTP_STOP) {
    result = Curl_pp_easy_statemach(pp);
    if(result)
      break;
  }

  return result;
}


static CURLcode smtp_init(struct connectdata *conn)
{
  struct SessionHandle *data = conn->data;
  struct FTP *smtp = data->state.proto.smtp;
  if(!smtp) {
    smtp = data->state.proto.smtp = calloc(sizeof(struct FTP), 1);
    if(!smtp)
      return CURLE_OUT_OF_MEMORY;
  }

  
  smtp->bytecountp = &data->req.bytecount;

  
  smtp->user = conn->user;
  smtp->passwd = conn->passwd;

  return CURLE_OK;
}


static CURLcode smtp_connect(struct connectdata *conn, bool *done)
{
  CURLcode result;
  struct smtp_conn *smtpc = &conn->proto.smtpc;
  struct SessionHandle *data = conn->data;
  struct pingpong *pp = &smtpc->pp;
  const char *path = conn->data->state.path;
  int len;
  char localhost[HOSTNAME_MAX + 1];

  *done = FALSE; 

  
  Curl_reset_reqproto(conn);

  result = smtp_init(conn);
  if(CURLE_OK != result)
    return result;

  
  conn->bits.close = FALSE;

  pp->response_time = RESP_TIMEOUT; 
  pp->statemach_act = smtp_statemach_act;
  pp->endofresp = smtp_endofresp;
  pp->conn = conn;

  if(conn->bits.tunnel_proxy && conn->bits.httpproxy) {
    
    struct HTTP http_proxy;
    struct FTP *smtp_save;

    
    

    
    smtp_save = data->state.proto.smtp;
    memset(&http_proxy, 0, sizeof(http_proxy));
    data->state.proto.http = &http_proxy;

    result = Curl_proxyCONNECT(conn, FIRSTSOCKET, conn->host.name, conn->remote_port);

    data->state.proto.smtp = smtp_save;

    if(CURLE_OK != result)
      return result;
  }

  if((conn->handler->protocol & CURLPROTO_SMTPS) && data->state.used_interface != Curl_if_multi) {
    
    
    result = Curl_ssl_connect(conn, FIRSTSOCKET);
    if(result)
      return result;
  }

  Curl_pp_init(pp); 

  pp->response_time = RESP_TIMEOUT; 
  pp->statemach_act = smtp_statemach_act;
  pp->endofresp = smtp_endofresp;
  pp->conn = conn;

  if(!*path) {
    if(!Curl_gethostname(localhost, sizeof localhost))
      path = localhost;
    else path = "localhost";
  }

  
  smtpc->domain = curl_easy_unescape(conn->data, path, 0, &len);
  if(!smtpc->domain)
    return CURLE_OUT_OF_MEMORY;

  
  state(conn, SMTP_SERVERGREET);

  if(data->state.used_interface == Curl_if_multi)
    result = smtp_multi_statemach(conn, done);
  else {
    result = smtp_easy_statemach(conn);
    if(!result)
      *done = TRUE;
  }

  return result;
}


static CURLcode smtp_done(struct connectdata *conn, CURLcode status, bool premature)
{
  struct SessionHandle *data = conn->data;
  struct FTP *smtp = data->state.proto.smtp;
  CURLcode result = CURLE_OK;
  ssize_t bytes_written;
  (void)premature;

  if(!smtp)
    
    return CURLE_OK;

  if(status) {
    conn->bits.close = TRUE; 
    result = status;      
  }
  else    result = Curl_write(conn, conn->writesockfd, SMTP_EOB, SMTP_EOB_LEN, &bytes_written);









  if(status == CURLE_OK) {
    struct smtp_conn *smtpc = &conn->proto.smtpc;
    struct pingpong *pp = &smtpc->pp;
    pp->response = Curl_tvnow(); 

    state(conn, SMTP_POSTDATA);
    
    result = smtp_easy_statemach(conn);
  }

  
  smtp->transfer = FTPTRANSFER_BODY;

  return result;
}



static CURLcode smtp_perform(struct connectdata *conn, bool *connected, bool *dophase_done)


{
  
  CURLcode result = CURLE_OK;

  DEBUGF(infof(conn->data, "DO phase starts\n"));

  if(conn->data->set.opt_no_body) {
    
    struct FTP *smtp = conn->data->state.proto.smtp;
    smtp->transfer = FTPTRANSFER_INFO;
  }

  *dophase_done = FALSE; 

  
  result = smtp_mail(conn);
  if(result)
    return result;

  
  if(conn->data->state.used_interface == Curl_if_multi)
    result = smtp_multi_statemach(conn, dophase_done);
  else {
    result = smtp_easy_statemach(conn);
    *dophase_done = TRUE; 
  }
  *connected = conn->bits.tcpconnect[FIRSTSOCKET];

  if(*dophase_done)
    DEBUGF(infof(conn->data, "DO phase is complete\n"));

  return result;
}


static CURLcode smtp_do(struct connectdata *conn, bool *done)
{
  CURLcode retcode = CURLE_OK;

  *done = FALSE; 

  
  Curl_reset_reqproto(conn);
  retcode = smtp_init(conn);
  if(retcode)
    return retcode;

  retcode = smtp_regular_transfer(conn, done);

  return retcode;
}


static CURLcode smtp_quit(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;

  result = Curl_pp_sendf(&conn->proto.smtpc.pp, "QUIT");
  if(result)
    return result;
  state(conn, SMTP_QUIT);

  result = smtp_easy_statemach(conn);

  return result;
}


static CURLcode smtp_disconnect(struct connectdata *conn, bool dead_connection)
{
  struct smtp_conn *smtpc = &conn->proto.smtpc;

  

  
  if(!dead_connection && smtpc->pp.conn)
    (void)smtp_quit(conn); 

  Curl_pp_disconnect(&smtpc->pp);


  
  if(smtpc->authused == SMTP_AUTH_NTLM) {
    Curl_ntlm_sspi_cleanup(&conn->ntlm);
  }


  
  Curl_safefree(smtpc->domain);
  smtpc->domain = NULL;

  return CURLE_OK;
}


static CURLcode smtp_dophase_done(struct connectdata *conn, bool connected)
{
  struct FTP *smtp = conn->data->state.proto.smtp;
  struct smtp_conn *smtpc = &conn->proto.smtpc;
  (void)connected;

  if(smtp->transfer != FTPTRANSFER_BODY)
    
    Curl_setup_transfer(conn, -1, -1, FALSE, NULL, -1, NULL);

  free(smtpc->domain);
  smtpc->domain = NULL;

  return CURLE_OK;
}


static CURLcode smtp_doing(struct connectdata *conn, bool *dophase_done)
{
  CURLcode result;
  result = smtp_multi_statemach(conn, dophase_done);

  if(*dophase_done) {
    result = smtp_dophase_done(conn, FALSE );

    DEBUGF(infof(conn->data, "DO phase is complete\n"));
  }

  return result;
}


static CURLcode smtp_regular_transfer(struct connectdata *conn, bool *dophase_done)

{
  CURLcode result = CURLE_OK;
  bool connected = FALSE;
  struct SessionHandle *data = conn->data;
  data->req.size = -1; 

  Curl_pgrsSetUploadCounter(data, 0);
  Curl_pgrsSetDownloadCounter(data, 0);
  Curl_pgrsSetUploadSize(data, 0);
  Curl_pgrsSetDownloadSize(data, 0);

  result = smtp_perform(conn, &connected, dophase_done);


  if(CURLE_OK == result) {

    if(!*dophase_done)
      
      return CURLE_OK;

    result = smtp_dophase_done(conn, connected);
    if(result)
      return result;
  }

  return result;
}

static CURLcode smtp_setup_connection(struct connectdata *conn)
{
  struct SessionHandle *data = conn->data;

  if(conn->bits.httpproxy && !data->set.tunnel_thru_httpproxy) {
    

    if(conn->handler == &Curl_handler_smtp)
      conn->handler = &Curl_handler_smtp_proxy;
    else {

      conn->handler = &Curl_handler_smtps_proxy;

      failf(data, "SMTPS not supported!");
      return CURLE_UNSUPPORTED_PROTOCOL;

    }
    
    conn->bits.close = FALSE;

    failf(data, "SMTP over http proxy requires HTTP support built-in!");
    return CURLE_UNSUPPORTED_PROTOCOL;

  }

  data->state.path++;   

  return CURLE_OK;
}

CURLcode Curl_smtp_escape_eob(struct connectdata *conn, ssize_t nread)
{
  
  ssize_t i;
  ssize_t si;
  struct smtp_conn *smtpc = &conn->proto.smtpc;
  struct SessionHandle *data = conn->data;

  if(data->state.scratch == NULL)
    data->state.scratch = malloc(2 * BUFSIZE);
  if(data->state.scratch == NULL) {
    failf (data, "Failed to alloc scratch buffer!");
    return CURLE_OUT_OF_MEMORY;
  }
  
  for(i = 0, si = 0; i < nread; i++) {

    if(SMTP_EOB[smtpc->eob] == data->req.upload_fromhere[i])
      smtpc->eob++;
    else if(smtpc->eob) {
      
      memcpy(&data->state.scratch[si], SMTP_EOB, smtpc->eob);
      si += smtpc->eob;

      
      if(SMTP_EOB[0] == data->req.upload_fromhere[i])
        smtpc->eob = 1;
      else smtpc->eob = 0;
    }

    if(SMTP_EOB_LEN == smtpc->eob) {
      
      memcpy(&data->state.scratch[si], SMTP_EOB_REPL, SMTP_EOB_REPL_LEN);
      si += SMTP_EOB_REPL_LEN;
      smtpc->eob = 2; 
    }
    else if(!smtpc->eob)
      data->state.scratch[si++] = data->req.upload_fromhere[i];

  } 

  if(si != nread) {
    
    nread = si;

    
    data->req.upload_fromhere = data->state.scratch;

    
    data->req.upload_present = nread;
  }

  return CURLE_OK;
}


