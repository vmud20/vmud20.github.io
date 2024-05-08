



































struct stat;



bool C_ImapDeflate; 

bool C_ImapIdle; 
bool C_ImapRfc5161; 


static int check_capabilities(struct ImapAccountData *adata)
{
  if (imap_exec(adata, "CAPABILITY", IMAP_CMD_NO_FLAGS) != IMAP_EXEC_SUCCESS)
  {
    imap_error("check_capabilities", adata->buf);
    return -1;
  }

  if (!((adata->capabilities & IMAP_CAP_IMAP4) || (adata->capabilities & IMAP_CAP_IMAP4REV1)))
  {
    mutt_error( _("This IMAP server is ancient. NeoMutt does not work with it."));
    return -1;
  }

  return 0;
}


static char *get_flags(struct ListHead *hflags, char *s)
{
  
  const size_t plen = mutt_str_startswith(s, "FLAGS", CASE_IGNORE);
  if (plen == 0)
  {
    mutt_debug(LL_DEBUG1, "not a FLAGS response: %s\n", s);
    return NULL;
  }
  s += plen;
  SKIPWS(s);
  if (*s != '(')
  {
    mutt_debug(LL_DEBUG1, "bogus FLAGS response: %s\n", s);
    return NULL;
  }

  
  while (*s && (*s != ')'))
  {
    s++;
    SKIPWS(s);
    const char *flag_word = s;
    while (*s && (*s != ')') && !IS_SPACE(*s))
      s++;
    const char ctmp = *s;
    *s = '\0';
    if (*flag_word)
      mutt_list_insert_tail(hflags, mutt_str_strdup(flag_word));
    *s = ctmp;
  }

  
  if (*s != ')')
  {
    mutt_debug(LL_DEBUG1, "Unterminated FLAGS response: %s\n", s);
    mutt_list_free(hflags);

    return NULL;
  }

  s++;

  return s;
}


static void set_flag(struct Mailbox *m, AclFlags aclflag, int flag, const char *str, char *flags, size_t flsize)
{
  if (m->rights & aclflag)
    if (flag && imap_has_flag(&imap_mdata_get(m)->flags, str))
      mutt_str_strcat(flags, flsize, str);
}


static int make_msg_set(struct Mailbox *m, struct Buffer *buf, int flag, bool changed, bool invert, int *pos)
{
  int count = 0;             
  unsigned int setstart = 0; 
  int n;
  bool started = false;

  struct ImapAccountData *adata = imap_adata_get(m);
  if (!adata || (adata->mailbox != m))
    return -1;

  for (n = *pos; (n < m->msg_count) && (mutt_buffer_len(buf) < IMAP_MAX_CMDLEN); n++)
  {
    struct Email *e = m->emails[n];
    if (!e)
      break;
    bool match = false; 
    
    if (e->active && (e->index != INT_MAX))
    {
      switch (flag)
      {
        case MUTT_DELETED:
          if (e->deleted != imap_edata_get(e)->deleted)
            match = invert ^ e->deleted;
          break;
        case MUTT_FLAG:
          if (e->flagged != imap_edata_get(e)->flagged)
            match = invert ^ e->flagged;
          break;
        case MUTT_OLD:
          if (e->old != imap_edata_get(e)->old)
            match = invert ^ e->old;
          break;
        case MUTT_READ:
          if (e->read != imap_edata_get(e)->read)
            match = invert ^ e->read;
          break;
        case MUTT_REPLIED:
          if (e->replied != imap_edata_get(e)->replied)
            match = invert ^ e->replied;
          break;
        case MUTT_TAG:
          if (e->tagged)
            match = true;
          break;
        case MUTT_TRASH:
          if (e->deleted && !e->purge)
            match = true;
          break;
      }
    }

    if (match && (!changed || e->changed))
    {
      count++;
      if (setstart == 0)
      {
        setstart = imap_edata_get(e)->uid;
        if (started)
        {
          mutt_buffer_add_printf(buf, ",%u", imap_edata_get(e)->uid);
        }
        else {
          mutt_buffer_add_printf(buf, "%u", imap_edata_get(e)->uid);
          started = true;
        }
      }
      
      else if (n == (m->msg_count - 1))
        mutt_buffer_add_printf(buf, ":%u", imap_edata_get(e)->uid);
    }
    
    else if (setstart && (e->active || (n == adata->mailbox->msg_count - 1)))
    {
      if (imap_edata_get(m->emails[n - 1])->uid > setstart)
        mutt_buffer_add_printf(buf, ":%u", imap_edata_get(m->emails[n - 1])->uid);
      setstart = 0;
    }
  }

  *pos = n;

  return count;
}


static bool compare_flags_for_copy(struct Email *e)
{
  struct ImapEmailData *edata = e->edata;

  if (e->read != edata->read)
    return true;
  if (e->old != edata->old)
    return true;
  if (e->flagged != edata->flagged)
    return true;
  if (e->replied != edata->replied)
    return true;

  return false;
}


static int sync_helper(struct Mailbox *m, AclFlags right, int flag, const char *name)
{
  int count = 0;
  int rc;
  char buf[1024];

  if (!m)
    return -1;

  if ((m->rights & right) == 0)
    return 0;

  if ((right == MUTT_ACL_WRITE) && !imap_has_flag(&imap_mdata_get(m)->flags, name))
    return 0;

  snprintf(buf, sizeof(buf), "+FLAGS.SILENT (%s)", name);
  rc = imap_exec_msgset(m, "UID STORE", buf, flag, true, false);
  if (rc < 0)
    return rc;
  count += rc;

  buf[0] = '-';
  rc = imap_exec_msgset(m, "UID STORE", buf, flag, true, true);
  if (rc < 0)
    return rc;
  count += rc;

  return count;
}


static size_t longest_common_prefix(char *dest, const char *src, size_t start, size_t dlen)
{
  size_t pos = start;

  while ((pos < dlen) && dest[pos] && (dest[pos] == src[pos]))
    pos++;
  dest[pos] = '\0';

  return pos;
}


static int complete_hosts(char *buf, size_t buflen)
{
  
  int rc = -1;
  size_t matchlen;

  matchlen = mutt_str_strlen(buf);
  struct MailboxList ml = STAILQ_HEAD_INITIALIZER(ml);
  neomutt_mailboxlist_get_all(&ml, NeoMutt, MUTT_MAILBOX_ANY);
  struct MailboxNode *np = NULL;
  STAILQ_FOREACH(np, &ml, entries)
  {
    if (!mutt_str_startswith(mailbox_path(np->mailbox), buf, CASE_MATCH))
      continue;

    if (rc)
    {
      mutt_str_strfcpy(buf, mailbox_path(np->mailbox), buflen);
      rc = 0;
    }
    else longest_common_prefix(buf, mailbox_path(np->mailbox), matchlen, buflen);
  }
  neomutt_mailboxlist_clear(&ml);


  TAILQ_FOREACH(conn, mutt_socket_head(), entries)
  {
    struct Url url = { 0 };
    char urlstr[1024];

    if (conn->account.type != MUTT_ACCT_TYPE_IMAP)
      continue;

    mutt_account_tourl(&conn->account, &url);
    
    url.user = NULL;
    url.path = NULL;
    url_tostring(&url, urlstr, sizeof(urlstr), 0);
    if (mutt_str_strncmp(buf, urlstr, matchlen) == 0)
    {
      if (rc)
      {
        mutt_str_strfcpy(buf, urlstr, buflen);
        rc = 0;
      }
      else longest_common_prefix(buf, urlstr, matchlen, buflen);
    }
  }


  return rc;
}


int imap_create_mailbox(struct ImapAccountData *adata, char *mailbox)
{
  char buf[2048], mbox[1024];

  imap_munge_mbox_name(adata->unicode, mbox, sizeof(mbox), mailbox);
  snprintf(buf, sizeof(buf), "CREATE %s", mbox);

  if (imap_exec(adata, buf, IMAP_CMD_NO_FLAGS) != IMAP_EXEC_SUCCESS)
  {
    mutt_error(_("CREATE failed: %s"), imap_cmd_trailer(adata));
    return -1;
  }

  return 0;
}


int imap_access(const char *path)
{
  if (imap_path_status(path, false) >= 0)
    return 0;
  return -1;
}


int imap_rename_mailbox(struct ImapAccountData *adata, char *oldname, const char *newname)
{
  char oldmbox[1024];
  char newmbox[1024];
  int rc = 0;

  imap_munge_mbox_name(adata->unicode, oldmbox, sizeof(oldmbox), oldname);
  imap_munge_mbox_name(adata->unicode, newmbox, sizeof(newmbox), newname);

  struct Buffer *buf = mutt_buffer_pool_get();
  mutt_buffer_printf(buf, "RENAME %s %s", oldmbox, newmbox);

  if (imap_exec(adata, mutt_b2s(buf), IMAP_CMD_NO_FLAGS) != IMAP_EXEC_SUCCESS)
    rc = -1;

  mutt_buffer_pool_release(&buf);

  return rc;
}


int imap_delete_mailbox(struct Mailbox *m, char *path)
{
  char buf[PATH_MAX + 7];
  char mbox[PATH_MAX];
  struct Url *url = url_parse(path);

  struct ImapAccountData *adata = imap_adata_get(m);
  imap_munge_mbox_name(adata->unicode, mbox, sizeof(mbox), url->path);
  url_free(&url);
  snprintf(buf, sizeof(buf), "DELETE %s", mbox);
  if (imap_exec(m->account->adata, buf, IMAP_CMD_NO_FLAGS) != IMAP_EXEC_SUCCESS)
    return -1;

  return 0;
}


static void imap_logout(struct ImapAccountData *adata)
{
  
  if (adata->state == IMAP_DISCONNECTED)
  {
    return;
  }

  adata->status = IMAP_BYE;
  imap_cmd_start(adata, "LOGOUT");
  if ((C_ImapPollTimeout <= 0) || (mutt_socket_poll(adata->conn, C_ImapPollTimeout) != 0))
  {
    while (imap_cmd_step(adata) == IMAP_RES_CONTINUE)
      ; 
  }
  mutt_socket_close(adata->conn);
  adata->state = IMAP_DISCONNECTED;
}


void imap_logout_all(void)
{
  struct Account *np = NULL;
  TAILQ_FOREACH(np, &NeoMutt->accounts, entries)
  {
    if (np->type != MUTT_IMAP)
      continue;

    struct ImapAccountData *adata = np->adata;
    if (!adata)
      continue;

    struct Connection *conn = adata->conn;
    if (!conn || (conn->fd < 0))
      continue;

    mutt_message(_("Closing connection to %s..."), conn->account.host);
    imap_logout(np->adata);
    mutt_clear_error();
  }
}


int imap_read_literal(FILE *fp, struct ImapAccountData *adata, unsigned long bytes, struct Progress *pbar)
{
  char c;
  bool r = false;
  struct Buffer buf = { 0 }; 

  if (C_DebugLevel >= IMAP_LOG_LTRL)
    mutt_buffer_alloc(&buf, bytes + 10);

  mutt_debug(LL_DEBUG2, "reading %ld bytes\n", bytes);

  for (unsigned long pos = 0; pos < bytes; pos++)
  {
    if (mutt_socket_readchar(adata->conn, &c) != 1)
    {
      mutt_debug(LL_DEBUG1, "error during read, %ld bytes read\n", pos);
      adata->status = IMAP_FATAL;

      mutt_buffer_dealloc(&buf);
      return -1;
    }

    if (r && (c != '\n'))
      fputc('\r', fp);

    if (c == '\r')
    {
      r = true;
      continue;
    }
    else r = false;

    fputc(c, fp);

    if (pbar && !(pos % 1024))
      mutt_progress_update(pbar, pos, -1);
    if (C_DebugLevel >= IMAP_LOG_LTRL)
      mutt_buffer_addch(&buf, c);
  }

  if (C_DebugLevel >= IMAP_LOG_LTRL)
  {
    mutt_debug(IMAP_LOG_LTRL, "\n%s", buf.data);
    mutt_buffer_dealloc(&buf);
  }
  return 0;
}


void imap_expunge_mailbox(struct Mailbox *m)
{
  struct ImapAccountData *adata = imap_adata_get(m);
  struct ImapMboxData *mdata = imap_mdata_get(m);
  if (!adata || !mdata)
    return;

  struct Email *e = NULL;


  mdata->hcache = imap_hcache_open(adata, mdata);


  for (int i = 0; i < m->msg_count; i++)
  {
    e = m->emails[i];
    if (!e)
      break;

    if (e->index == INT_MAX)
    {
      mutt_debug(LL_DEBUG2, "Expunging message UID %u\n", imap_edata_get(e)->uid);

      e->deleted = true;

      imap_cache_del(m, e);

      imap_hcache_del(mdata, imap_edata_get(e)->uid);


      mutt_hash_int_delete(mdata->uid_hash, imap_edata_get(e)->uid, e);

      imap_edata_free((void **) &e->edata);
    }
    else {
      e->index = i;
      
      e->active = true;
    }
  }


  imap_hcache_close(mdata);


  mailbox_changed(m, NT_MAILBOX_UPDATE);
  mailbox_changed(m, NT_MAILBOX_RESORT);
}


int imap_open_connection(struct ImapAccountData *adata)
{
  if (mutt_socket_open(adata->conn) < 0)
    return -1;

  adata->state = IMAP_CONNECTED;

  if (imap_cmd_step(adata) != IMAP_RES_OK)
  {
    imap_close_connection(adata);
    return -1;
  }

  if (mutt_str_startswith(adata->buf, "* OK", CASE_IGNORE))
  {
    if (!mutt_str_startswith(adata->buf, "* OK [CAPABILITY", CASE_IGNORE) && check_capabilities(adata))
    {
      goto bail;
    }

    
    if (!adata->conn->ssf && (C_SslForceTls || (adata->capabilities & IMAP_CAP_STARTTLS)))
    {
      enum QuadOption ans;

      if (C_SslForceTls)
        ans = MUTT_YES;
      else if ((ans = query_quadoption(C_SslStarttls, _("Secure connection with TLS?"))) == MUTT_ABORT)
      {
        goto err_close_conn;
      }
      if (ans == MUTT_YES)
      {
        enum ImapExecResult rc = imap_exec(adata, "STARTTLS", IMAP_CMD_NO_FLAGS);
        if (rc == IMAP_EXEC_FATAL)
          goto bail;
        if (rc != IMAP_EXEC_ERROR)
        {
          if (mutt_ssl_starttls(adata->conn))
          {
            mutt_error(_("Could not negotiate TLS connection"));
            goto err_close_conn;
          }
          else {
            
            if (imap_exec(adata, "CAPABILITY", IMAP_CMD_NO_FLAGS))
              goto bail;
          }
        }
      }
    }

    if (C_SslForceTls && !adata->conn->ssf)
    {
      mutt_error(_("Encrypted connection unavailable"));
      goto err_close_conn;
    }

  }
  else if (mutt_str_startswith(adata->buf, "* PREAUTH", CASE_IGNORE))
  {

    
    if (adata->conn->ssf == 0)
    {
      bool proceed = true;
      if (C_SslForceTls)
      {
        proceed = false;
      }
      else if (C_SslStarttls != MUTT_NO)
      {
        proceed = mutt_yesorno(_("Abort unencrypted PREAUTH connection?"), C_SslStarttls) != MUTT_NO;
      }
      if (!proceed)
      {
        mutt_error(_("Encrypted connection unavailable"));
        goto err_close_conn;
      }
    }


    adata->state = IMAP_AUTHENTICATED;
    if (check_capabilities(adata) != 0)
      goto bail;
    FREE(&adata->capstr);
  }
  else {
    imap_error("imap_open_connection()", adata->buf);
    goto bail;
  }

  return 0;


err_close_conn:
  imap_close_connection(adata);

bail:
  FREE(&adata->capstr);
  return -1;
}


void imap_close_connection(struct ImapAccountData *adata)
{
  if (adata->state != IMAP_DISCONNECTED)
  {
    mutt_socket_close(adata->conn);
    adata->state = IMAP_DISCONNECTED;
  }
  adata->seqno = 0;
  adata->nextcmd = 0;
  adata->lastcmd = 0;
  adata->status = 0;
  memset(adata->cmds, 0, sizeof(struct ImapCommand) * adata->cmdslots);
}


bool imap_has_flag(struct ListHead *flag_list, const char *flag)
{
  if (STAILQ_EMPTY(flag_list))
    return false;

  const size_t flaglen = mutt_str_strlen(flag);
  struct ListNode *np = NULL;
  STAILQ_FOREACH(np, flag_list, entries)
  {
    const size_t nplen = strlen(np->data);
    if ((flaglen >= nplen) && ((flag[nplen] == '\0') || (flag[nplen] == ' ')) && (mutt_str_strncasecmp(np->data, flag, nplen) == 0))
    {
      return true;
    }

    if (mutt_str_strcmp(np->data, "\\*") == 0)
      return true;
  }

  return false;
}


static int compare_uid(const void *a, const void *b)
{
  const struct Email *ea = *(struct Email const *const *) a;
  const struct Email *eb = *(struct Email const *const *) b;
  return imap_edata_get((struct Email *) ea)->uid - imap_edata_get((struct Email *) eb)->uid;
}


int imap_exec_msgset(struct Mailbox *m, const char *pre, const char *post, int flag, bool changed, bool invert)
{
  struct ImapAccountData *adata = imap_adata_get(m);
  if (!adata || (adata->mailbox != m))
    return -1;

  struct Email **emails = NULL;
  short oldsort;
  int pos;
  int rc;
  int count = 0;

  struct Buffer cmd = mutt_buffer_make(0);

  
  oldsort = C_Sort;
  if (C_Sort != SORT_ORDER)
  {
    emails = m->emails;
    
    m->emails = mutt_mem_malloc(m->email_max * sizeof(struct Email *));
    memcpy(m->emails, emails, m->email_max * sizeof(struct Email *));

    C_Sort = SORT_ORDER;
    qsort(m->emails, m->msg_count, sizeof(struct Email *), compare_uid);
  }

  pos = 0;

  do {
    mutt_buffer_reset(&cmd);
    mutt_buffer_add_printf(&cmd, "%s ", pre);
    rc = make_msg_set(m, &cmd, flag, changed, invert, &pos);
    if (rc > 0)
    {
      mutt_buffer_add_printf(&cmd, " %s", post);
      if (imap_exec(adata, cmd.data, IMAP_CMD_QUEUE) != IMAP_EXEC_SUCCESS)
      {
        rc = -1;
        goto out;
      }
      count += rc;
    }
  } while (rc > 0);

  rc = count;

out:
  mutt_buffer_dealloc(&cmd);
  if (oldsort != C_Sort)
  {
    C_Sort = oldsort;
    FREE(&m->emails);
    m->emails = emails;
  }

  return rc;
}


int imap_sync_message_for_copy(struct Mailbox *m, struct Email *e, struct Buffer *cmd, enum QuadOption *err_continue)
{
  struct ImapAccountData *adata = imap_adata_get(m);
  if (!adata || (adata->mailbox != m))
    return -1;

  char flags[1024];
  char *tags = NULL;
  char uid[11];

  if (!compare_flags_for_copy(e))
  {
    if (e->deleted == imap_edata_get(e)->deleted)
      e->changed = false;
    return 0;
  }

  snprintf(uid, sizeof(uid), "%u", imap_edata_get(e)->uid);
  mutt_buffer_reset(cmd);
  mutt_buffer_addstr(cmd, "UID STORE ");
  mutt_buffer_addstr(cmd, uid);

  flags[0] = '\0';

  set_flag(m, MUTT_ACL_SEEN, e->read, "\\Seen ", flags, sizeof(flags));
  set_flag(m, MUTT_ACL_WRITE, e->old, "Old ", flags, sizeof(flags));
  set_flag(m, MUTT_ACL_WRITE, e->flagged, "\\Flagged ", flags, sizeof(flags));
  set_flag(m, MUTT_ACL_WRITE, e->replied, "\\Answered ", flags, sizeof(flags));
  set_flag(m, MUTT_ACL_DELETE, imap_edata_get(e)->deleted, "\\Deleted ", flags, sizeof(flags));

  if (m->rights & MUTT_ACL_WRITE)
  {
    
    if (imap_edata_get(e)->flags_system)
      mutt_str_strcat(flags, sizeof(flags), imap_edata_get(e)->flags_system);
    
    tags = driver_tags_get_with_hidden(&e->tags);
    if (tags)
    {
      mutt_str_strcat(flags, sizeof(flags), tags);
      FREE(&tags);
    }
  }

  mutt_str_remove_trailing_ws(flags);

  
  if (*flags == '\0')
  {
    set_flag(m, MUTT_ACL_SEEN, 1, "\\Seen ", flags, sizeof(flags));
    set_flag(m, MUTT_ACL_WRITE, 1, "Old ", flags, sizeof(flags));
    set_flag(m, MUTT_ACL_WRITE, 1, "\\Flagged ", flags, sizeof(flags));
    set_flag(m, MUTT_ACL_WRITE, 1, "\\Answered ", flags, sizeof(flags));
    set_flag(m, MUTT_ACL_DELETE, !imap_edata_get(e)->deleted, "\\Deleted ", flags, sizeof(flags));

    
    if ((m->rights & MUTT_ACL_WRITE) && imap_edata_get(e)->flags_remote)
      mutt_str_strcat(flags, sizeof(flags), imap_edata_get(e)->flags_remote);

    mutt_str_remove_trailing_ws(flags);

    mutt_buffer_addstr(cmd, " -FLAGS.SILENT (");
  }
  else mutt_buffer_addstr(cmd, " FLAGS.SILENT (");

  mutt_buffer_addstr(cmd, flags);
  mutt_buffer_addstr(cmd, ")");

  
  if (*flags && (imap_exec(adata, cmd->data, IMAP_CMD_NO_FLAGS) != IMAP_EXEC_SUCCESS) && err_continue && (*err_continue != MUTT_YES))
  {
    *err_continue = imap_continue("imap_sync_message: STORE failed", adata->buf);
    if (*err_continue != MUTT_YES)
      return -1;
  }

  
  FREE(&imap_edata_get(e)->flags_remote);
  imap_edata_get(e)->flags_remote = driver_tags_get_with_hidden(&e->tags);

  if (e->deleted == imap_edata_get(e)->deleted)
    e->changed = false;

  return 0;
}


int imap_check_mailbox(struct Mailbox *m, bool force)
{
  if (!m || !m->account)
    return -1;

  struct ImapAccountData *adata = imap_adata_get(m);
  struct ImapMboxData *mdata = imap_mdata_get(m);

  
  int rc = 0;

  
  if (!force && C_ImapIdle && (adata->capabilities & IMAP_CAP_IDLE) && ((adata->state != IMAP_IDLE) || (mutt_date_epoch() >= adata->lastread + C_ImapKeepalive)))
  {
    if (imap_cmd_idle(adata) < 0)
      return -1;
  }
  if (adata->state == IMAP_IDLE)
  {
    while ((rc = mutt_socket_poll(adata->conn, 0)) > 0)
    {
      if (imap_cmd_step(adata) != IMAP_RES_CONTINUE)
      {
        mutt_debug(LL_DEBUG1, "Error reading IDLE response\n");
        return -1;
      }
    }
    if (rc < 0)
    {
      mutt_debug(LL_DEBUG1, "Poll failed, disabling IDLE\n");
      adata->capabilities &= ~IMAP_CAP_IDLE; 
    }
  }

  if ((force || ((adata->state != IMAP_IDLE) && (mutt_date_epoch() >= adata->lastread + C_Timeout))) && (imap_exec(adata, "NOOP", IMAP_CMD_POLL) != IMAP_EXEC_SUCCESS))

  {
    return -1;
  }

  
  imap_cmd_finish(adata);

  if (mdata->check_status & IMAP_EXPUNGE_PENDING)
    rc = MUTT_REOPENED;
  else if (mdata->check_status & IMAP_NEWMAIL_PENDING)
    rc = MUTT_NEW_MAIL;
  else if (mdata->check_status & IMAP_FLAGS_PENDING)
    rc = MUTT_FLAGS;

  mdata->check_status = IMAP_OPEN_NO_FLAGS;

  return rc;
}


static int imap_status(struct ImapAccountData *adata, struct ImapMboxData *mdata, bool queue)
{
  char *uidvalidity_flag = NULL;
  char cmd[2048];

  if (!adata || !mdata)
    return -1;

  
  if (adata->mailbox && (adata->mailbox->mdata == mdata))
  {
    adata->mailbox->has_new = false;
    return mdata->messages;
  }

  if (adata->capabilities & IMAP_CAP_IMAP4REV1)
    uidvalidity_flag = "UIDVALIDITY";
  else if (adata->capabilities & IMAP_CAP_STATUS)
    uidvalidity_flag = "UID-VALIDITY";
  else {
    mutt_debug(LL_DEBUG2, "Server doesn't support STATUS\n");
    return -1;
  }

  snprintf(cmd, sizeof(cmd), "STATUS %s (UIDNEXT %s UNSEEN RECENT MESSAGES)", mdata->munge_name, uidvalidity_flag);

  int rc = imap_exec(adata, cmd, queue ? IMAP_CMD_QUEUE : IMAP_CMD_NO_FLAGS | IMAP_CMD_POLL);
  if (rc < 0)
  {
    mutt_debug(LL_DEBUG1, "Error queueing command\n");
    return rc;
  }
  return mdata->messages;
}


static int imap_mbox_check_stats(struct Mailbox *m, int flags)
{
  return imap_mailbox_status(m, true);
}


int imap_path_status(const char *path, bool queue)
{
  struct Mailbox *m = mx_mbox_find2(path);
  if (m)
    return imap_mailbox_status(m, queue);

  
  struct ImapAccountData *adata = NULL;
  struct ImapMboxData *mdata = NULL;

  if (imap_adata_find(path, &adata, &mdata) < 0)
    return -1;
  int rc = imap_status(adata, mdata, queue);
  imap_mdata_free((void *) &mdata);
  return rc;
}


int imap_mailbox_status(struct Mailbox *m, bool queue)
{
  struct ImapAccountData *adata = imap_adata_get(m);
  struct ImapMboxData *mdata = imap_mdata_get(m);
  if (!adata || !mdata)
    return -1;
  return imap_status(adata, mdata, queue);
}


int imap_subscribe(char *path, bool subscribe)
{
  struct ImapAccountData *adata = NULL;
  struct ImapMboxData *mdata = NULL;
  char buf[2048];
  struct Buffer err;

  if (imap_adata_find(path, &adata, &mdata) < 0)
    return -1;

  if (C_ImapCheckSubscribed)
  {
    char mbox[1024];
    mutt_buffer_init(&err);
    err.dsize = 256;
    err.data = mutt_mem_malloc(err.dsize);
    size_t len = snprintf(mbox, sizeof(mbox), "%smailboxes ", subscribe ? "" : "un");
    imap_quote_string(mbox + len, sizeof(mbox) - len, path, true);
    if (mutt_parse_rc_line(mbox, &err))
      mutt_debug(LL_DEBUG1, "Error adding subscribed mailbox: %s\n", err.data);
    FREE(&err.data);
  }

  if (subscribe)
    mutt_message(_("Subscribing to %s..."), mdata->name);
  else mutt_message(_("Unsubscribing from %s..."), mdata->name);

  snprintf(buf, sizeof(buf), "%sSUBSCRIBE %s", subscribe ? "" : "UN", mdata->munge_name);

  if (imap_exec(adata, buf, IMAP_CMD_NO_FLAGS) != IMAP_EXEC_SUCCESS)
  {
    imap_mdata_free((void *) &mdata);
    return -1;
  }

  if (subscribe)
    mutt_message(_("Subscribed to %s"), mdata->name);
  else mutt_message(_("Unsubscribed from %s"), mdata->name);
  imap_mdata_free((void *) &mdata);
  return 0;
}


int imap_complete(char *buf, size_t buflen, const char *path)
{
  struct ImapAccountData *adata = NULL;
  struct ImapMboxData *mdata = NULL;
  char tmp[2048];
  struct ImapList listresp = { 0 };
  char completion[1024];
  int clen;
  size_t matchlen = 0;
  int completions = 0;
  int rc;

  if (imap_adata_find(path, &adata, &mdata) < 0)
  {
    mutt_str_strfcpy(buf, path, buflen);
    return complete_hosts(buf, buflen);
  }

  
  snprintf(tmp, sizeof(tmp), "%s \"\" \"%s%%\"", C_ImapListSubscribed ? "LSUB" : "LIST", mdata->real_name);

  imap_cmd_start(adata, tmp);

  
  mutt_str_strfcpy(completion, mdata->name, sizeof(completion));
  imap_mdata_free((void *) &mdata);

  adata->cmdresult = &listresp;
  do {
    listresp.name = NULL;
    rc = imap_cmd_step(adata);

    if ((rc == IMAP_RES_CONTINUE) && listresp.name)
    {
      
      if (listresp.noselect)
      {
        clen = strlen(listresp.name);
        listresp.name[clen++] = listresp.delim;
        listresp.name[clen] = '\0';
      }
      
      if (!completions)
      {
        mutt_str_strfcpy(completion, listresp.name, sizeof(completion));
        matchlen = strlen(completion);
        completions++;
        continue;
      }

      matchlen = longest_common_prefix(completion, listresp.name, 0, matchlen);
      completions++;
    }
  } while (rc == IMAP_RES_CONTINUE);
  adata->cmdresult = NULL;

  if (completions)
  {
    
    imap_qualify_path(buf, buflen, &adata->conn->account, completion);
    mutt_pretty_mailbox(buf, buflen);
    return 0;
  }

  return -1;
}


int imap_fast_trash(struct Mailbox *m, char *dest)
{
  char prompt[1024];
  int rc = -1;
  bool triedcreate = false;
  enum QuadOption err_continue = MUTT_NO;

  struct ImapAccountData *adata = imap_adata_get(m);
  struct ImapAccountData *dest_adata = NULL;
  struct ImapMboxData *dest_mdata = NULL;

  if (imap_adata_find(dest, &dest_adata, &dest_mdata) < 0)
    return -1;

  struct Buffer sync_cmd = mutt_buffer_make(0);

  
  if (!imap_account_match(&(adata->conn->account), &(dest_adata->conn->account)))
  {
    mutt_debug(LL_DEBUG3, "%s not same server as %s\n", dest, mailbox_path(m));
    goto out;
  }

  for (int i = 0; i < m->msg_count; i++)
  {
    struct Email *e = m->emails[i];
    if (!e)
      break;
    if (e->active && e->changed && e->deleted && !e->purge)
    {
      rc = imap_sync_message_for_copy(m, e, &sync_cmd, &err_continue);
      if (rc < 0)
      {
        mutt_debug(LL_DEBUG1, "could not sync\n");
        goto out;
      }
    }
  }

  
  do {
    rc = imap_exec_msgset(m, "UID COPY", dest_mdata->munge_name, MUTT_TRASH, false, false);
    if (rc == 0)
    {
      mutt_debug(LL_DEBUG1, "No messages to trash\n");
      rc = -1;
      goto out;
    }
    else if (rc < 0)
    {
      mutt_debug(LL_DEBUG1, "could not queue copy\n");
      goto out;
    }
    else if (m->verbose)
    {
      mutt_message(ngettext("Copying %d message to %s...", "Copying %d messages to %s...", rc), rc, dest_mdata->name);
    }

    
    rc = imap_exec(adata, NULL, IMAP_CMD_NO_FLAGS);
    if (rc == IMAP_EXEC_ERROR)
    {
      if (triedcreate)
      {
        mutt_debug(LL_DEBUG1, "Already tried to create mailbox %s\n", dest_mdata->name);
        break;
      }
      
      if (!mutt_str_startswith(imap_get_qualifier(adata->buf), "[TRYCREATE]", CASE_IGNORE))
        break;
      mutt_debug(LL_DEBUG3, "server suggests TRYCREATE\n");
      snprintf(prompt, sizeof(prompt), _("Create %s?"), dest_mdata->name);
      if (C_Confirmcreate && (mutt_yesorno(prompt, MUTT_YES) != MUTT_YES))
      {
        mutt_clear_error();
        goto out;
      }
      if (imap_create_mailbox(adata, dest_mdata->name) < 0)
        break;
      triedcreate = true;
    }
  } while (rc == IMAP_EXEC_ERROR);

  if (rc != IMAP_EXEC_SUCCESS)
  {
    imap_error("imap_fast_trash", adata->buf);
    goto out;
  }

  rc = IMAP_EXEC_SUCCESS;

out:
  mutt_buffer_dealloc(&sync_cmd);
  imap_mdata_free((void *) &dest_mdata);

  return ((rc == IMAP_EXEC_SUCCESS) ? 0 : -1);
}


int imap_sync_mailbox(struct Mailbox *m, bool expunge, bool close)
{
  if (!m)
    return -1;

  struct Email **emails = NULL;
  int oldsort;
  int rc;
  int check;

  struct ImapAccountData *adata = imap_adata_get(m);
  struct ImapMboxData *mdata = imap_mdata_get(m);

  if (adata->state < IMAP_SELECTED)
  {
    mutt_debug(LL_DEBUG2, "no mailbox selected\n");
    return -1;
  }

  
  imap_allow_reopen(m);

  check = imap_check_mailbox(m, false);
  if (check < 0)
    return check;

  
  if (expunge && (m->rights & MUTT_ACL_DELETE))
  {
    rc = imap_exec_msgset(m, "UID STORE", "+FLAGS.SILENT (\\Deleted)", MUTT_DELETED, true, false);
    if (rc < 0)
    {
      mutt_error(_("Expunge failed"));
      return rc;
    }

    if (rc > 0)
    {
      
      for (int i = 0; i < m->msg_count; i++)
      {
        struct Email *e = m->emails[i];
        if (!e)
          break;
        if (e->deleted && e->changed)
          e->active = false;
      }
      if (m->verbose)
      {
        mutt_message(ngettext("Marking %d message deleted...", "Marking %d messages deleted...", rc), rc);

      }
    }
  }


  mdata->hcache = imap_hcache_open(adata, mdata);


  
  for (int i = 0; i < m->msg_count; i++)
  {
    struct Email *e = m->emails[i];
    if (!e)
      break;

    if (e->deleted)
    {
      imap_cache_del(m, e);

      imap_hcache_del(mdata, imap_edata_get(e)->uid);

    }

    if (e->active && e->changed)
    {

      imap_hcache_put(mdata, e);

      
      
      if ((e->env && e->env->changed) || e->attach_del)
      {
        
        if (m->verbose)
        {
          mutt_message(ngettext("Saving changed message... [%d/%d]", "Saving changed messages... [%d/%d]", m->msg_count), i + 1, m->msg_count);

        }
        bool save_append = m->append;
        m->append = true;
        mutt_save_message_ctx(e, true, false, false, m);
        m->append = save_append;
        
        if (e->env)
          e->env->changed = 0;
      }
    }
  }


  imap_hcache_close(mdata);


  
  oldsort = C_Sort;
  if (C_Sort != SORT_ORDER)
  {
    emails = m->emails;
    m->emails = mutt_mem_malloc(m->msg_count * sizeof(struct Email *));
    memcpy(m->emails, emails, m->msg_count * sizeof(struct Email *));

    C_Sort = SORT_ORDER;
    qsort(m->emails, m->msg_count, sizeof(struct Email *), mutt_get_sort_func(SORT_ORDER));
  }

  rc = sync_helper(m, MUTT_ACL_DELETE, MUTT_DELETED, "\\Deleted");
  if (rc >= 0)
    rc |= sync_helper(m, MUTT_ACL_WRITE, MUTT_FLAG, "\\Flagged");
  if (rc >= 0)
    rc |= sync_helper(m, MUTT_ACL_WRITE, MUTT_OLD, "Old");
  if (rc >= 0)
    rc |= sync_helper(m, MUTT_ACL_SEEN, MUTT_READ, "\\Seen");
  if (rc >= 0)
    rc |= sync_helper(m, MUTT_ACL_WRITE, MUTT_REPLIED, "\\Answered");

  if (oldsort != C_Sort)
  {
    C_Sort = oldsort;
    FREE(&m->emails);
    m->emails = emails;
  }

  
  if (rc > 0)
    if (imap_exec(adata, NULL, IMAP_CMD_NO_FLAGS) != IMAP_EXEC_SUCCESS)
      rc = -1;

  if (rc < 0)
  {
    if (close)
    {
      if (mutt_yesorno(_("Error saving flags. Close anyway?"), MUTT_NO) == MUTT_YES)
      {
        adata->state = IMAP_AUTHENTICATED;
        return 0;
      }
    }
    else mutt_error(_("Error saving flags"));
    return -1;
  }

  
  for (int i = 0; i < m->msg_count; i++)
  {
    struct Email *e = m->emails[i];
    if (!e)
      break;
    struct ImapEmailData *edata = imap_edata_get(e);
    edata->deleted = e->deleted;
    edata->flagged = e->flagged;
    edata->old = e->old;
    edata->read = e->read;
    edata->replied = e->replied;
    e->changed = false;
  }
  m->changed = false;

  
  if (expunge && !close && (m->rights & MUTT_ACL_DELETE))
  {
    if (m->verbose)
      mutt_message(_("Expunging messages from server..."));
    
    mdata->reopen |= IMAP_EXPUNGE_EXPECTED;
    if (imap_exec(adata, "EXPUNGE", IMAP_CMD_NO_FLAGS) != IMAP_EXEC_SUCCESS)
    {
      mdata->reopen &= ~IMAP_EXPUNGE_EXPECTED;
      imap_error(_("imap_sync_mailbox: EXPUNGE failed"), adata->buf);
      return -1;
    }
    mdata->reopen &= ~IMAP_EXPUNGE_EXPECTED;
  }

  if (expunge && close)
  {
    adata->closing = true;
    imap_exec(adata, "CLOSE", IMAP_CMD_QUEUE);
    adata->state = IMAP_AUTHENTICATED;
  }

  if (C_MessageCacheClean)
    imap_cache_clean(m);

  return check;
}


static struct Account *imap_ac_find(struct Account *a, const char *path)
{
  if (!a || (a->type != MUTT_IMAP) || !path)
    return NULL;

  struct Url *url = url_parse(path);
  if (!url)
    return NULL;

  struct ImapAccountData *adata = a->adata;
  struct ConnAccount *cac = &adata->conn->account;

  if (mutt_str_strcasecmp(url->host, cac->host) != 0)
    a = NULL;
  else if (url->user && (mutt_str_strcasecmp(url->user, cac->user) != 0))
    a = NULL;

  url_free(&url);
  return a;
}


static int imap_ac_add(struct Account *a, struct Mailbox *m)
{
  if (!a || !m || (m->type != MUTT_IMAP))
    return -1;

  struct ImapAccountData *adata = a->adata;

  if (!adata)
  {
    struct ConnAccount cac = { { 0 } };
    char mailbox[PATH_MAX];

    if (imap_parse_path(mailbox_path(m), &cac, mailbox, sizeof(mailbox)) < 0)
      return -1;

    adata = imap_adata_new(a);
    adata->conn = mutt_conn_new(&cac);
    if (!adata->conn)
    {
      imap_adata_free((void **) &adata);
      return -1;
    }

    mutt_account_hook(m->realpath);

    if (imap_login(adata) < 0)
    {
      imap_adata_free((void **) &adata);
      return -1;
    }

    a->adata = adata;
    a->adata_free = imap_adata_free;
  }

  if (!m->mdata)
  {
    struct Url *url = url_parse(mailbox_path(m));
    struct ImapMboxData *mdata = imap_mdata_new(adata, url->path);

    
    char buf[1024];
    imap_qualify_path(buf, sizeof(buf), &adata->conn->account, mdata->name);
    mutt_buffer_strcpy(&m->pathbuf, buf);
    mutt_str_replace(&m->realpath, mailbox_path(m));

    m->mdata = mdata;
    m->mdata_free = imap_mdata_free;
    url_free(&url);
  }
  return 0;
}


static void imap_mbox_select(struct Mailbox *m)
{
  struct ImapAccountData *adata = imap_adata_get(m);
  struct ImapMboxData *mdata = imap_mdata_get(m);
  if (!adata || !mdata)
    return;

  const char *condstore = NULL;

  if ((adata->capabilities & IMAP_CAP_CONDSTORE) && C_ImapCondstore)
    condstore = " (CONDSTORE)";
  else  condstore = "";


  char buf[PATH_MAX];
  snprintf(buf, sizeof(buf), "%s %s%s", m->readonly ? "EXAMINE" : "SELECT", mdata->munge_name, condstore);

  adata->state = IMAP_SELECTED;

  imap_cmd_start(adata, buf);
}


int imap_login(struct ImapAccountData *adata)
{
  if (!adata)
    return -1;

  if (adata->state == IMAP_DISCONNECTED)
  {
    mutt_buffer_reset(&adata->cmdbuf); 
    imap_open_connection(adata);
  }
  if (adata->state == IMAP_CONNECTED)
  {
    if (imap_authenticate(adata) == IMAP_AUTH_SUCCESS)
    {
      adata->state = IMAP_AUTHENTICATED;
      FREE(&adata->capstr);
      if (adata->conn->ssf)
      {
        mutt_debug(LL_DEBUG2, "Communication encrypted at %d bits\n", adata->conn->ssf);
      }
    }
    else mutt_account_unsetpass(&adata->conn->account);
  }
  if (adata->state == IMAP_AUTHENTICATED)
  {
    
    imap_exec(adata, "CAPABILITY", IMAP_CMD_PASS);


    
    if ((adata->capabilities & IMAP_CAP_COMPRESS) && C_ImapDeflate && (imap_exec(adata, "COMPRESS DEFLATE", IMAP_CMD_PASS) == IMAP_EXEC_SUCCESS))
    {
      mutt_debug(LL_DEBUG2, "IMAP compression is enabled on connection to %s\n", adata->conn->account.host);
      mutt_zstrm_wrap_conn(adata->conn);
    }


    
    if (C_ImapRfc5161 && (adata->capabilities & IMAP_CAP_ENABLE))
      imap_exec(adata, "ENABLE UTF8=ACCEPT", IMAP_CMD_QUEUE);

    
    if (adata->capabilities & IMAP_CAP_QRESYNC)
    {
      adata->capabilities |= IMAP_CAP_CONDSTORE;
      if (C_ImapRfc5161 && C_ImapQresync)
        imap_exec(adata, "ENABLE QRESYNC", IMAP_CMD_QUEUE);
    }

    
    adata->delim = '/';
    imap_exec(adata, "LIST \"\" \"\"", IMAP_CMD_QUEUE);

    
    imap_exec(adata, NULL, IMAP_CMD_NO_FLAGS);

    
    if (adata->mailbox)
    {
      imap_mbox_select(adata->mailbox);
    }
  }

  if (adata->state < IMAP_AUTHENTICATED)
    return -1;

  return 0;
}


static int imap_mbox_open(struct Mailbox *m)
{
  if (!m || !m->account || !m->mdata)
    return -1;

  char buf[PATH_MAX];
  int count = 0;
  int rc;

  struct ImapAccountData *adata = imap_adata_get(m);
  struct ImapMboxData *mdata = imap_mdata_get(m);

  mutt_debug(LL_DEBUG3, "opening %s, saving %s\n", m->pathbuf.data, (adata->mailbox ? adata->mailbox->pathbuf.data : "(none)"));
  adata->prev_mailbox = adata->mailbox;
  adata->mailbox = m;

  
  adata->status = 0;
  m->rights = 0;
  mdata->new_mail_count = 0;

  if (m->verbose)
    mutt_message(_("Selecting %s..."), mdata->name);

  
  if (adata->capabilities & IMAP_CAP_ACL)
  {
    snprintf(buf, sizeof(buf), "MYRIGHTS %s", mdata->munge_name);
    imap_exec(adata, buf, IMAP_CMD_QUEUE);
  }
  
  else {
    m->rights |= MUTT_ACL_LOOKUP | MUTT_ACL_READ | MUTT_ACL_SEEN | MUTT_ACL_WRITE | MUTT_ACL_INSERT | MUTT_ACL_POST | MUTT_ACL_CREATE | MUTT_ACL_DELETE;
  }

  
  struct Mailbox *m_postponed = mx_mbox_find2(C_Postponed);
  struct ImapAccountData *postponed_adata = imap_adata_get(m_postponed);
  if (postponed_adata && imap_account_match(&postponed_adata->conn->account, &adata->conn->account))
  {
    imap_mailbox_status(m_postponed, true);
  }

  if (C_ImapCheckSubscribed)
    imap_exec(adata, "LSUB \"\" \"*\"", IMAP_CMD_QUEUE);

  imap_mbox_select(m);

  do {
    char *pc = NULL;

    rc = imap_cmd_step(adata);
    if (rc != IMAP_RES_CONTINUE)
      break;

    pc = adata->buf + 2;

    
    if (mutt_str_startswith(pc, "FLAGS", CASE_IGNORE))
    {
      
      if (STAILQ_EMPTY(&mdata->flags))
      {
        mutt_debug(LL_DEBUG3, "Getting mailbox FLAGS\n");
        pc = get_flags(&mdata->flags, pc);
        if (!pc)
          goto fail;
      }
    }
    
    else if (mutt_str_startswith(pc, "OK [PERMANENTFLAGS", CASE_IGNORE))
    {
      mutt_debug(LL_DEBUG3, "Getting mailbox PERMANENTFLAGS\n");
      
      mutt_list_free(&mdata->flags);
      
      pc += 13;
      pc = get_flags(&(mdata->flags), pc);
      if (!pc)
        goto fail;
    }
    
    else if (mutt_str_startswith(pc, "OK [UIDVALIDITY", CASE_IGNORE))
    {
      mutt_debug(LL_DEBUG3, "Getting mailbox UIDVALIDITY\n");
      pc += 3;
      pc = imap_next_word(pc);
      if (mutt_str_atoui(pc, &mdata->uidvalidity) < 0)
        goto fail;
    }
    else if (mutt_str_startswith(pc, "OK [UIDNEXT", CASE_IGNORE))
    {
      mutt_debug(LL_DEBUG3, "Getting mailbox UIDNEXT\n");
      pc += 3;
      pc = imap_next_word(pc);
      if (mutt_str_atoui(pc, &mdata->uid_next) < 0)
        goto fail;
    }
    else if (mutt_str_startswith(pc, "OK [HIGHESTMODSEQ", CASE_IGNORE))
    {
      mutt_debug(LL_DEBUG3, "Getting mailbox HIGHESTMODSEQ\n");
      pc += 3;
      pc = imap_next_word(pc);
      if (mutt_str_atoull(pc, &mdata->modseq) < 0)
        goto fail;
    }
    else if (mutt_str_startswith(pc, "OK [NOMODSEQ", CASE_IGNORE))
    {
      mutt_debug(LL_DEBUG3, "Mailbox has NOMODSEQ set\n");
      mdata->modseq = 0;
    }
    else {
      pc = imap_next_word(pc);
      if (mutt_str_startswith(pc, "EXISTS", CASE_IGNORE))
      {
        count = mdata->new_mail_count;
        mdata->new_mail_count = 0;
      }
    }
  } while (rc == IMAP_RES_CONTINUE);

  if (rc == IMAP_RES_NO)
  {
    char *s = imap_next_word(adata->buf); 
    s = imap_next_word(s);                
    mutt_error("%s", s);
    goto fail;
  }

  if (rc != IMAP_RES_OK)
    goto fail;

  
  if (mutt_str_startswith(imap_get_qualifier(adata->buf), "[READ-ONLY]", CASE_IGNORE) && !(adata->capabilities & IMAP_CAP_ACL))
  {
    mutt_debug(LL_DEBUG2, "Mailbox is read-only\n");
    m->readonly = true;
  }

  
  if (C_DebugLevel > LL_DEBUG2)
  {
    if (STAILQ_EMPTY(&mdata->flags))
      mutt_debug(LL_DEBUG3, "No folder flags found\n");
    else {
      struct ListNode *np = NULL;
      struct Buffer flag_buffer;
      mutt_buffer_init(&flag_buffer);
      mutt_buffer_printf(&flag_buffer, "Mailbox flags: ");
      STAILQ_FOREACH(np, &mdata->flags, entries)
      {
        mutt_buffer_add_printf(&flag_buffer, "[%s] ", np->data);
      }
      mutt_debug(LL_DEBUG3, "%s\n", flag_buffer.data);
      FREE(&flag_buffer.data);
    }
  }

  if (!((m->rights & MUTT_ACL_DELETE) || (m->rights & MUTT_ACL_SEEN) || (m->rights & MUTT_ACL_WRITE) || (m->rights & MUTT_ACL_INSERT)))
  {
    m->readonly = true;
  }

  while (m->email_max < count)
    mx_alloc_memory(m);

  m->msg_count = 0;
  m->msg_unread = 0;
  m->msg_flagged = 0;
  m->msg_new = 0;
  m->msg_deleted = 0;
  m->size = 0;
  m->vcount = 0;

  if (count && (imap_read_headers(m, 1, count, true) < 0))
  {
    mutt_error(_("Error opening mailbox"));
    goto fail;
  }

  mutt_debug(LL_DEBUG2, "msg_count is %d\n", m->msg_count);
  return 0;

fail:
  if (adata->state == IMAP_SELECTED)
    adata->state = IMAP_AUTHENTICATED;
  return -1;
}


static int imap_mbox_open_append(struct Mailbox *m, OpenMailboxFlags flags)
{
  if (!m || !m->account)
    return -1;

  
  struct ImapAccountData *adata = imap_adata_get(m);
  struct ImapMboxData *mdata = imap_mdata_get(m);

  int rc = imap_mailbox_status(m, false);
  if (rc >= 0)
    return 0;
  if (rc == -1)
    return -1;

  char buf[PATH_MAX + 64];
  snprintf(buf, sizeof(buf), _("Create %s?"), mdata->name);
  if (C_Confirmcreate && (mutt_yesorno(buf, MUTT_YES) != MUTT_YES))
    return -1;

  if (imap_create_mailbox(adata, mdata->name) < 0)
    return -1;

  return 0;
}


static int imap_mbox_check(struct Mailbox *m, int *index_hint)
{
  if (!m)
    return -1;

  imap_allow_reopen(m);
  int rc = imap_check_mailbox(m, false);
  
  imap_disallow_reopen(m);

  return rc;
}


static int imap_mbox_close(struct Mailbox *m)
{
  if (!m)
    return -1;

  struct ImapAccountData *adata = imap_adata_get(m);
  struct ImapMboxData *mdata = imap_mdata_get(m);

  
  if (!adata || !mdata)
    return 0;

  
  if (m == adata->mailbox)
  {
    if ((adata->status != IMAP_FATAL) && (adata->state >= IMAP_SELECTED))
    {
      
      if (m->msg_deleted == 0)
      {
        adata->closing = true;
        imap_exec(adata, "CLOSE", IMAP_CMD_QUEUE);
      }
      adata->state = IMAP_AUTHENTICATED;
    }

    mutt_debug(LL_DEBUG3, "closing %s, restoring %s\n", m->pathbuf.data, (adata->prev_mailbox ? adata->prev_mailbox->pathbuf.data : "(none)"));
    adata->mailbox = adata->prev_mailbox;
    imap_mbox_select(adata->prev_mailbox);
    imap_mdata_cache_reset(m->mdata);
  }

  return 0;
}


static int imap_msg_open_new(struct Mailbox *m, struct Message *msg, struct Email *e)
{
  int rc = -1;

  struct Buffer *tmp = mutt_buffer_pool_get();
  mutt_buffer_mktemp(tmp);

  msg->fp = mutt_file_fopen(mutt_b2s(tmp), "w");
  if (!msg->fp)
  {
    mutt_perror(mutt_b2s(tmp));
    goto cleanup;
  }

  msg->path = mutt_buffer_strdup(tmp);
  rc = 0;

cleanup:
  mutt_buffer_pool_release(&tmp);
  return rc;
}


static int imap_tags_edit(struct Mailbox *m, const char *tags, char *buf, size_t buflen)
{
  struct ImapMboxData *mdata = imap_mdata_get(m);
  if (!mdata)
    return -1;

  char *new_tag = NULL;
  char *checker = NULL;

  
  if (!imap_has_flag(&mdata->flags, NULL))
  {
    mutt_error(_("IMAP server doesn't support custom flags"));
    return -1;
  }

  *buf = '\0';
  if (tags)
    mutt_str_strfcpy(buf, tags, buflen);

  if (mutt_get_field("Tags: ", buf, buflen, MUTT_COMP_NO_FLAGS) != 0)
    return -1;

  

  new_tag = buf;
  checker = buf;
  SKIPWS(checker);
  while (*checker != '\0')
  {
    if ((*checker < 32) || (*checker >= 127) ||  (*checker == 40) || (*checker == 41) || (*checker == 60) || (*checker == 62) || (*checker == 64) || (*checker == 44) || (*checker == 59) || (*checker == 58) || (*checker == 92) || (*checker == 34) || (*checker == 46) || (*checker == 91) || (*checker == 93))












    {
      mutt_error(_("Invalid IMAP flags"));
      return 0;
    }

    
    while ((checker[0] == ' ') && (checker[1] == ' '))
      checker++;

    
    *new_tag++ = *checker++;
  }
  *new_tag = '\0';
  new_tag = buf; 
  mutt_str_remove_trailing_ws(new_tag);

  if (mutt_str_strcmp(tags, buf) == 0)
    return 0;
  return 1;
}


static int imap_tags_commit(struct Mailbox *m, struct Email *e, char *buf)
{
  if (!m)
    return -1;

  char uid[11];

  struct ImapAccountData *adata = imap_adata_get(m);

  if (*buf == '\0')
    buf = NULL;

  if (!(adata->mailbox->rights & MUTT_ACL_WRITE))
    return 0;

  snprintf(uid, sizeof(uid), "%u", imap_edata_get(e)->uid);

  
  if (imap_edata_get(e)->flags_remote)
  {
    struct Buffer cmd = mutt_buffer_make(128); 
    mutt_buffer_addstr(&cmd, "UID STORE ");
    mutt_buffer_addstr(&cmd, uid);
    mutt_buffer_addstr(&cmd, " -FLAGS.SILENT (");
    mutt_buffer_addstr(&cmd, imap_edata_get(e)->flags_remote);
    mutt_buffer_addstr(&cmd, ")");

    
    int rc = imap_exec(adata, cmd.data, IMAP_CMD_NO_FLAGS);
    mutt_buffer_dealloc(&cmd);
    if (rc != IMAP_EXEC_SUCCESS)
    {
      return -1;
    }
  }

  
  if (buf)
  {
    struct Buffer cmd = mutt_buffer_make(128); 
    mutt_buffer_addstr(&cmd, "UID STORE ");
    mutt_buffer_addstr(&cmd, uid);
    mutt_buffer_addstr(&cmd, " +FLAGS.SILENT (");
    mutt_buffer_addstr(&cmd, buf);
    mutt_buffer_addstr(&cmd, ")");

    int rc = imap_exec(adata, cmd.data, IMAP_CMD_NO_FLAGS);
    mutt_buffer_dealloc(&cmd);
    if (rc != IMAP_EXEC_SUCCESS)
    {
      mutt_debug(LL_DEBUG1, "fail to add new flags\n");
      return -1;
    }
  }

  
  mutt_debug(LL_DEBUG1, "NEW TAGS: %s\n", buf);
  driver_tags_replace(&e->tags, buf);
  FREE(&imap_edata_get(e)->flags_remote);
  imap_edata_get(e)->flags_remote = driver_tags_get_with_hidden(&e->tags);
  return 0;
}


enum MailboxType imap_path_probe(const char *path, const struct stat *st)
{
  if (!path)
    return MUTT_UNKNOWN;

  if (mutt_str_startswith(path, "imap://", CASE_IGNORE))
    return MUTT_IMAP;

  if (mutt_str_startswith(path, "imaps://", CASE_IGNORE))
    return MUTT_IMAP;

  return MUTT_UNKNOWN;
}


int imap_path_canon(char *buf, size_t buflen)
{
  if (!buf)
    return -1;

  struct Url *url = url_parse(buf);
  if (!url)
    return 0;

  char tmp[PATH_MAX];
  char tmp2[PATH_MAX];

  imap_fix_path('\0', url->path, tmp, sizeof(tmp));
  url->path = tmp;
  url_tostring(url, tmp2, sizeof(tmp2), 0);
  mutt_str_strfcpy(buf, tmp2, buflen);
  url_free(&url);

  return 0;
}


int imap_expand_path(struct Buffer *buf)
{
  mutt_buffer_alloc(buf, PATH_MAX);
  return imap_path_canon(buf->data, PATH_MAX);
}


static int imap_path_pretty(char *buf, size_t buflen, const char *folder)
{
  if (!buf || !folder)
    return -1;

  imap_pretty_mailbox(buf, buflen, folder);
  return 0;
}


static int imap_path_parent(char *buf, size_t buflen)
{
  char tmp[PATH_MAX] = { 0 };

  imap_get_parent_path(buf, tmp, sizeof(tmp));
  mutt_str_strfcpy(buf, tmp, buflen);
  return 0;
}



struct MxOps MxImapOps = {
  .type            = MUTT_IMAP, .name             = "imap", .is_local         = false, .ac_find          = imap_ac_find, .ac_add           = imap_ac_add, .mbox_open        = imap_mbox_open, .mbox_open_append = imap_mbox_open_append, .mbox_check       = imap_mbox_check, .mbox_check_stats = imap_mbox_check_stats, .mbox_sync        = NULL, .mbox_close       = imap_mbox_close, .msg_open         = imap_msg_open, .msg_open_new     = imap_msg_open_new, .msg_commit       = imap_msg_commit, .msg_close        = imap_msg_close, .msg_padding_size = NULL, .msg_save_hcache  = imap_msg_save_hcache, .tags_edit        = imap_tags_edit, .tags_commit      = imap_tags_commit, .path_probe       = imap_path_probe, .path_canon       = imap_path_canon, .path_pretty      = imap_path_pretty, .path_parent      = imap_path_parent, };























