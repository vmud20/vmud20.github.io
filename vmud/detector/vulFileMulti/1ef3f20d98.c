

































extern int __idna_to_ascii_lz (const char *input, char **output, int flags);
extern int __idna_to_unicode_lzlz (const char *input, char **output, int flags);



struct gaih_service {
    const char *name;
    int num;
  };

struct gaih_servtuple {
    struct gaih_servtuple *next;
    int socktype;
    int protocol;
    int port;
  };

static const struct gaih_servtuple nullserv;


struct gaih_typeproto {
    int socktype;
    int protocol;
    uint8_t protoflag;
    bool defaultflag;
    char name[8];
  };





static const struct gaih_typeproto gaih_inet_typeproto[] = {
  { 0, 0, 0, false, "" }, { SOCK_STREAM, IPPROTO_TCP, 0, true, "tcp" }, { SOCK_DGRAM, IPPROTO_UDP, 0, true, "udp" },  { SOCK_DCCP, IPPROTO_DCCP, 0, false, "dccp" },   { SOCK_DGRAM, IPPROTO_UDPLITE, 0, false, "udplite" },   { SOCK_STREAM, IPPROTO_SCTP, 0, false, "sctp" }, { SOCK_SEQPACKET, IPPROTO_SCTP, 0, false, "sctp" },  { SOCK_RAW, 0, GAI_PROTO_PROTOANY|GAI_PROTO_NOSERVICE, true, "raw" }, { 0, 0, 0, false, "" }













};

static const struct addrinfo default_hints = {
    .ai_flags = AI_DEFAULT, .ai_family = PF_UNSPEC, .ai_socktype = 0, .ai_protocol = 0, .ai_addrlen = 0, .ai_addr = NULL, .ai_canonname = NULL, .ai_next = NULL };









static int gaih_inet_serv (const char *servicename, const struct gaih_typeproto *tp, const struct addrinfo *req, struct gaih_servtuple *st)

{
  struct servent *s;
  size_t tmpbuflen = 1024;
  struct servent ts;
  char *tmpbuf;
  int r;

  do {
      tmpbuf = __alloca (tmpbuflen);

      r = __getservbyname_r (servicename, tp->name, &ts, tmpbuf, tmpbuflen, &s);
      if (r != 0 || s == NULL)
	{
	  if (r == ERANGE)
	    tmpbuflen *= 2;
	  else return -EAI_SERVICE;
	}
    }
  while (r);

  st->next = NULL;
  st->socktype = tp->socktype;
  st->protocol = ((tp->protoflag & GAI_PROTO_PROTOANY)
		  ? req->ai_protocol : tp->protocol);
  st->port = s->s_port;

  return 0;
}






















































































typedef enum nss_status (*nss_gethostbyname4_r)
  (const char *name, struct gaih_addrtuple **pat, char *buffer, size_t buflen, int *errnop, int *h_errnop, int32_t *ttlp);

typedef enum nss_status (*nss_gethostbyname3_r)
  (const char *name, int af, struct hostent *host, char *buffer, size_t buflen, int *errnop, int *h_errnop, int32_t *ttlp, char **canonp);

typedef enum nss_status (*nss_getcanonname_r)
  (const char *name, char *buffer, size_t buflen, char **result, int *errnop, int *h_errnop);
extern service_user *__nss_hosts_database attribute_hidden;


static int gaih_inet (const char *name, const struct gaih_service *service, const struct addrinfo *req, struct addrinfo **pai, unsigned int *naddrs)


{
  const struct gaih_typeproto *tp = gaih_inet_typeproto;
  struct gaih_servtuple *st = (struct gaih_servtuple *) &nullserv;
  struct gaih_addrtuple *at = NULL;
  int rc;
  bool got_ipv6 = false;
  const char *canon = NULL;
  const char *orig_name = name;
  size_t alloca_used = 0;

  if (req->ai_protocol || req->ai_socktype)
    {
      ++tp;

      while (tp->name[0] && ((req->ai_socktype != 0 && req->ai_socktype != tp->socktype)
		 || (req->ai_protocol != 0 && !(tp->protoflag & GAI_PROTO_PROTOANY)
		     && req->ai_protocol != tp->protocol)))
	++tp;

      if (! tp->name[0])
	{
	  if (req->ai_socktype)
	    return -EAI_SOCKTYPE;
	  else return -EAI_SERVICE;
	}
    }

  int port = 0;
  if (service != NULL)
    {
      if ((tp->protoflag & GAI_PROTO_NOSERVICE) != 0)
	return -EAI_SERVICE;

      if (service->num < 0)
	{
	  if (tp->name[0])
	    {
	      st = (struct gaih_servtuple *)
		alloca_account (sizeof (struct gaih_servtuple), alloca_used);

	      if ((rc = gaih_inet_serv (service->name, tp, req, st)))
		return rc;
	    }
	  else {
	      struct gaih_servtuple **pst = &st;
	      for (tp++; tp->name[0]; tp++)
		{
		  struct gaih_servtuple *newp;

		  if ((tp->protoflag & GAI_PROTO_NOSERVICE) != 0)
		    continue;

		  if (req->ai_socktype != 0 && req->ai_socktype != tp->socktype)
		    continue;
		  if (req->ai_protocol != 0 && !(tp->protoflag & GAI_PROTO_PROTOANY)
		      && req->ai_protocol != tp->protocol)
		    continue;

		  newp = (struct gaih_servtuple *)
		    alloca_account (sizeof (struct gaih_servtuple), alloca_used);

		  if ((rc = gaih_inet_serv (service->name, tp, req, newp)))
		    {
		      if (rc)
			continue;
		      return rc;
		    }

		  *pst = newp;
		  pst = &(newp->next);
		}
	      if (st == (struct gaih_servtuple *) &nullserv)
		return -EAI_SERVICE;
	    }
	}
      else {
	  port = htons (service->num);
	  goto got_port;
	}
    }
  else {
    got_port:

      if (req->ai_socktype || req->ai_protocol)
	{
	  st = alloca_account (sizeof (struct gaih_servtuple), alloca_used);
	  st->next = NULL;
	  st->socktype = tp->socktype;
	  st->protocol = ((tp->protoflag & GAI_PROTO_PROTOANY)
			  ? req->ai_protocol : tp->protocol);
	  st->port = port;
	}
      else {
	  
	  struct gaih_servtuple **lastp = &st;
	  for (++tp; tp->name[0]; ++tp)
	    if (tp->defaultflag)
	      {
		struct gaih_servtuple *newp;

		newp = alloca_account (sizeof (struct gaih_servtuple), alloca_used);
		newp->next = NULL;
		newp->socktype = tp->socktype;
		newp->protocol = tp->protocol;
		newp->port = port;

		*lastp = newp;
		lastp = &newp->next;
	      }
	}
    }

  bool malloc_name = false;
  bool malloc_addrmem = false;
  struct gaih_addrtuple *addrmem = NULL;
  bool malloc_canonbuf = false;
  char *canonbuf = NULL;
  bool malloc_tmpbuf = false;
  char *tmpbuf = NULL;
  int result = 0;
  if (name != NULL)
    {
      at = alloca_account (sizeof (struct gaih_addrtuple), alloca_used);
      at->family = AF_UNSPEC;
      at->scopeid = 0;
      at->next = NULL;


      if (req->ai_flags & AI_IDN)
	{
	  int idn_flags = 0;
	  if (req->ai_flags & AI_IDN_ALLOW_UNASSIGNED)
	    idn_flags |= IDNA_ALLOW_UNASSIGNED;
	  if (req->ai_flags & AI_IDN_USE_STD3_ASCII_RULES)
	    idn_flags |= IDNA_USE_STD3_ASCII_RULES;

	  char *p = NULL;
	  rc = __idna_to_ascii_lz (name, &p, idn_flags);
	  if (rc != IDNA_SUCCESS)
	    {
	      
	      if (rc == IDNA_MALLOC_ERROR)
		return -EAI_MEMORY;
	      if (rc == IDNA_DLOPEN_ERROR)
		return -EAI_SYSTEM;
	      return -EAI_IDN_ENCODE;
	    }
	  
	  if (p != name)
	    {
	      name = p;
	      malloc_name = true;
	    }
	}


      if (__inet_aton (name, (struct in_addr *) at->addr) != 0)
	{
	  if (req->ai_family == AF_UNSPEC || req->ai_family == AF_INET)
	    at->family = AF_INET;
	  else if (req->ai_family == AF_INET6 && (req->ai_flags & AI_V4MAPPED))
	    {
	      at->addr[3] = at->addr[0];
	      at->addr[2] = htonl (0xffff);
	      at->addr[1] = 0;
	      at->addr[0] = 0;
	      at->family = AF_INET6;
	    }
	  else {
	      result = -EAI_ADDRFAMILY;
	      goto free_and_return;
	    }

	  if (req->ai_flags & AI_CANONNAME)
	    canon = name;
	}
      else if (at->family == AF_UNSPEC)
	{
	  char *scope_delim = strchr (name, SCOPE_DELIMITER);
	  int e;

	  {
	    bool malloc_namebuf = false;
	    char *namebuf = (char *) name;

	    if (__glibc_unlikely (scope_delim != NULL))
	      {
		if (malloc_name)
		  *scope_delim = '\0';
		else {
		    if (__libc_use_alloca (alloca_used + scope_delim - name + 1))
		      {
			namebuf = alloca_account (scope_delim - name + 1, alloca_used);
			*((char *) __mempcpy (namebuf, name, scope_delim - name)) = '\0';
		      }
		    else {
			namebuf = strndup (name, scope_delim - name);
			if (namebuf == NULL)
			  {
			    assert (!malloc_name);
			    return -EAI_MEMORY;
			  }
			malloc_namebuf = true;
		      }
		  }
	      }

	    e = inet_pton (AF_INET6, namebuf, at->addr);

	    if (malloc_namebuf)
	      free (namebuf);
	    else if (scope_delim != NULL && malloc_name)
	      
	      *scope_delim = SCOPE_DELIMITER;
	  }
	  if (e > 0)
	    {
	      if (req->ai_family == AF_UNSPEC || req->ai_family == AF_INET6)
		at->family = AF_INET6;
	      else if (req->ai_family == AF_INET && IN6_IS_ADDR_V4MAPPED (at->addr))
		{
		  at->addr[0] = at->addr[3];
		  at->family = AF_INET;
		}
	      else {
		  result = -EAI_ADDRFAMILY;
		  goto free_and_return;
		}

	      if (scope_delim != NULL)
		{
		  int try_numericscope = 0;
		  if (IN6_IS_ADDR_LINKLOCAL (at->addr)
		      || IN6_IS_ADDR_MC_LINKLOCAL (at->addr))
		    {
		      at->scopeid = if_nametoindex (scope_delim + 1);
		      if (at->scopeid == 0)
			try_numericscope = 1;
		    }
		  else try_numericscope = 1;

		  if (try_numericscope != 0)
		    {
		      char *end;
		      assert (sizeof (uint32_t) <= sizeof (unsigned long));
		      at->scopeid = (uint32_t) strtoul (scope_delim + 1, &end, 10);
		      if (*end != '\0')
			{
			  result = -EAI_NONAME;
			  goto free_and_return;
			}
		    }
		}

	      if (req->ai_flags & AI_CANONNAME)
		canon = name;
	    }
	}

      if (at->family == AF_UNSPEC && (req->ai_flags & AI_NUMERICHOST) == 0)
	{
	  struct gaih_addrtuple **pat = &at;
	  int no_data = 0;
	  int no_inet6_data = 0;
	  service_user *nip;
	  enum nss_status inet6_status = NSS_STATUS_UNAVAIL;
	  enum nss_status status = NSS_STATUS_UNAVAIL;
	  int no_more;
	  int old_res_options;

	  
	  if (req->ai_family == AF_INET && (req->ai_flags & AI_CANONNAME) == 0)
	    {
	      
	      size_t tmpbuflen = (512 + MAX_NR_ALIASES * sizeof(char*)
				  + 16 * sizeof(char));
	      assert (tmpbuf == NULL);
	      tmpbuf = alloca_account (tmpbuflen, alloca_used);
	      int rc;
	      struct hostent th;
	      struct hostent *h;
	      int herrno;

	      while (1)
		{
		  rc = __gethostbyname2_r (name, AF_INET, &th, tmpbuf, tmpbuflen, &h, &herrno);
		  if (rc != ERANGE || herrno != NETDB_INTERNAL)
		    break;

		  if (!malloc_tmpbuf && __libc_use_alloca (alloca_used + 2 * tmpbuflen))
		    tmpbuf = extend_alloca_account (tmpbuf, tmpbuflen, 2 * tmpbuflen, alloca_used);

		  else {
		      char *newp = realloc (malloc_tmpbuf ? tmpbuf : NULL, 2 * tmpbuflen);
		      if (newp == NULL)
			{
			  result = -EAI_MEMORY;
			  goto free_and_return;
			}
		      tmpbuf = newp;
		      malloc_tmpbuf = true;
		      tmpbuflen = 2 * tmpbuflen;
		    }
		}

	      if (rc == 0)
		{
		  if (h != NULL)
		    {
		      int i;
		      
		      for (i = 0; h->h_addr_list[i]; ++i)
			;
		      if (i > 0 && *pat != NULL)
			--i;

		      if (__libc_use_alloca (alloca_used + i * sizeof (struct gaih_addrtuple)))
			addrmem = alloca_account (i * sizeof (struct gaih_addrtuple), alloca_used);
		      else {
			  addrmem = malloc (i * sizeof (struct gaih_addrtuple));
			  if (addrmem == NULL)
			    {
			      result = -EAI_MEMORY;
			      goto free_and_return;
			    }
			  malloc_addrmem = true;
			}

		      
		      struct gaih_addrtuple *addrfree = addrmem;
		      for (i = 0; h->h_addr_list[i]; ++i)
			{
			  if (*pat == NULL)
			    {
			      *pat = addrfree++;
			      (*pat)->scopeid = 0;
			    }
			  (*pat)->next = NULL;
			  (*pat)->family = AF_INET;
			  memcpy ((*pat)->addr, h->h_addr_list[i], h->h_length);
			  pat = &((*pat)->next);
			}
		    }
		}
	      else {
		  if (herrno == NETDB_INTERNAL)
		    {
		      __set_h_errno (herrno);
		      result = -EAI_SYSTEM;
		    }
		  else if (herrno == TRY_AGAIN)
		    result = -EAI_AGAIN;
		  else  result = -EAI_NODATA;


		  goto free_and_return;
		}

	      goto process_list;
	    }


	  if (__nss_not_use_nscd_hosts > 0 && ++__nss_not_use_nscd_hosts > NSS_NSCD_RETRY)
	    __nss_not_use_nscd_hosts = 0;

	  if (!__nss_not_use_nscd_hosts && !__nss_database_custom[NSS_DBSIDX_hosts])
	    {
	      
	      struct nscd_ai_result *air = NULL;
	      int herrno;
	      int err = __nscd_getai (name, &air, &herrno);
	      if (air != NULL)
		{
		  
		  bool added_canon = (req->ai_flags & AI_CANONNAME) == 0;
		  char *addrs = air->addrs;

		  if (__libc_use_alloca (alloca_used + air->naddrs * sizeof (struct gaih_addrtuple)))
		    addrmem = alloca_account (air->naddrs * sizeof (struct gaih_addrtuple), alloca_used);

		  else {
		      addrmem = malloc (air->naddrs * sizeof (struct gaih_addrtuple));
		      if (addrmem == NULL)
			{
			  result = -EAI_MEMORY;
			  goto free_and_return;
			}
		      malloc_addrmem = true;
		    }

		  struct gaih_addrtuple *addrfree = addrmem;
		  for (int i = 0; i < air->naddrs; ++i)
		    {
		      socklen_t size = (air->family[i] == AF_INET ? INADDRSZ : IN6ADDRSZ);

		      if (!((air->family[i] == AF_INET && req->ai_family == AF_INET6 && (req->ai_flags & AI_V4MAPPED) != 0)

			    || req->ai_family == AF_UNSPEC || air->family[i] == req->ai_family))
			{
			  
			  addrs += size;
			  continue;
			}

		      if (*pat == NULL)
			{
			  *pat = addrfree++;
			  (*pat)->scopeid = 0;
			}
		      uint32_t *pataddr = (*pat)->addr;
		      (*pat)->next = NULL;
		      if (added_canon || air->canon == NULL)
			(*pat)->name = NULL;
		      else if (canonbuf == NULL)
			{
			  size_t canonlen = strlen (air->canon) + 1;
			  if ((req->ai_flags & AI_CANONIDN) != 0 && __libc_use_alloca (alloca_used + canonlen))
			    canonbuf = alloca_account (canonlen, alloca_used);
			  else {
			      canonbuf = malloc (canonlen);
			      if (canonbuf == NULL)
				{
				  result = -EAI_MEMORY;
				  goto free_and_return;
				}
			      malloc_canonbuf = true;
			    }
			  canon = (*pat)->name = memcpy (canonbuf, air->canon, canonlen);
			}

		      if (air->family[i] == AF_INET && req->ai_family == AF_INET6 && (req->ai_flags & AI_V4MAPPED))

			{
			  (*pat)->family = AF_INET6;
			  pataddr[3] = *(uint32_t *) addrs;
			  pataddr[2] = htonl (0xffff);
			  pataddr[1] = 0;
			  pataddr[0] = 0;
			  pat = &((*pat)->next);
			  added_canon = true;
			}
		      else if (req->ai_family == AF_UNSPEC || air->family[i] == req->ai_family)
			{
			  (*pat)->family = air->family[i];
			  memcpy (pataddr, addrs, size);
			  pat = &((*pat)->next);
			  added_canon = true;
			  if (air->family[i] == AF_INET6)
			    got_ipv6 = true;
			}
		      addrs += size;
		    }

		  free (air);

		  if (at->family == AF_UNSPEC)
		    {
		      result = -EAI_NONAME;
		      goto free_and_return;
		    }

		  goto process_list;
		}
	      else if (err == 0)
		
		goto free_and_return;
	      else if (__nss_not_use_nscd_hosts == 0)
		{
		  if (herrno == NETDB_INTERNAL && errno == ENOMEM)
		    result = -EAI_MEMORY;
		  else if (herrno == TRY_AGAIN)
		    result = -EAI_AGAIN;
		  else result = -EAI_SYSTEM;

		  goto free_and_return;
		}
	    }


	  if (__nss_hosts_database == NULL)
	    no_more = __nss_database_lookup ("hosts", NULL, "dns [!UNAVAIL=return] files", &__nss_hosts_database);

	  else no_more = 0;
	  nip = __nss_hosts_database;

	  
	  if (__glibc_unlikely (!_res_hconf.initialized))
	    _res_hconf_init ();
	  if (__res_maybe_init (&_res, 0) == -1)
	    no_more = 1;

	  
	  old_res_options = _res.options;
	  _res.options &= ~RES_USE_INET6;

	  size_t tmpbuflen = 1024 + sizeof(struct gaih_addrtuple);
	  malloc_tmpbuf = !__libc_use_alloca (alloca_used + tmpbuflen);
	  assert (tmpbuf == NULL);
	  if (!malloc_tmpbuf)
	    tmpbuf = alloca_account (tmpbuflen, alloca_used);
	  else {
	      tmpbuf = malloc (tmpbuflen);
	      if (tmpbuf == NULL)
		{
		  _res.options |= old_res_options & RES_USE_INET6;
		  result = -EAI_MEMORY;
		  goto free_and_return;
		}
	    }

	  while (!no_more)
	    {
	      no_data = 0;
	      nss_gethostbyname4_r fct4 = NULL;

	      
	      if (req->ai_family == PF_UNSPEC)
		fct4 = __nss_lookup_function (nip, "gethostbyname4_r");

	      if (fct4 != NULL)
		{
		  int herrno;

		  while (1)
		    {
		      rc = 0;
		      status = DL_CALL_FCT (fct4, (name, pat, tmpbuf, tmpbuflen, &rc, &herrno, NULL));

		      if (status == NSS_STATUS_SUCCESS)
			break;
		      if (status != NSS_STATUS_TRYAGAIN || rc != ERANGE || herrno != NETDB_INTERNAL)
			{
			  if (herrno == TRY_AGAIN)
			    no_data = EAI_AGAIN;
			  else no_data = herrno == NO_DATA;
			  break;
			}

		      if (!malloc_tmpbuf && __libc_use_alloca (alloca_used + 2 * tmpbuflen))
			tmpbuf = extend_alloca_account (tmpbuf, tmpbuflen, 2 * tmpbuflen, alloca_used);

		      else {
			  char *newp = realloc (malloc_tmpbuf ? tmpbuf : NULL, 2 * tmpbuflen);
			  if (newp == NULL)
			    {
			      _res.options |= old_res_options & RES_USE_INET6;
			      result = -EAI_MEMORY;
			      goto free_and_return;
			    }
			  tmpbuf = newp;
			  malloc_tmpbuf = true;
			  tmpbuflen = 2 * tmpbuflen;
			}
		    }

		  if (status == NSS_STATUS_SUCCESS)
		    {
		      assert (!no_data);
		      no_data = 1;

		      if ((req->ai_flags & AI_CANONNAME) != 0 && canon == NULL)
			canon = (*pat)->name;

		      while (*pat != NULL)
			{
			  if ((*pat)->family == AF_INET && req->ai_family == AF_INET6 && (req->ai_flags & AI_V4MAPPED) != 0)

			    {
			      uint32_t *pataddr = (*pat)->addr;
			      (*pat)->family = AF_INET6;
			      pataddr[3] = pataddr[0];
			      pataddr[2] = htonl (0xffff);
			      pataddr[1] = 0;
			      pataddr[0] = 0;
			      pat = &((*pat)->next);
			      no_data = 0;
			    }
			  else if (req->ai_family == AF_UNSPEC || (*pat)->family == req->ai_family)
			    {
			      pat = &((*pat)->next);

			      no_data = 0;
			      if (req->ai_family == AF_INET6)
				got_ipv6 = true;
			    }
			  else *pat = ((*pat)->next);
			}
		    }

		  no_inet6_data = no_data;
		}
	      else {
		  nss_gethostbyname3_r fct = NULL;
		  if (req->ai_flags & AI_CANONNAME)
		    
		    fct = __nss_lookup_function (nip, "gethostbyname3_r");
		  if (fct == NULL)
		    
		    fct = __nss_lookup_function (nip, "gethostbyname2_r");

		  if (fct != NULL)
		    {
		      if (req->ai_family == AF_INET6 || req->ai_family == AF_UNSPEC)
			{
			  gethosts (AF_INET6, struct in6_addr);
			  no_inet6_data = no_data;
			  inet6_status = status;
			}
		      if (req->ai_family == AF_INET || req->ai_family == AF_UNSPEC || (req->ai_family == AF_INET6 && (req->ai_flags & AI_V4MAPPED)


			      
			      && ((req->ai_flags & AI_ALL) || !got_ipv6)))
			{
			  gethosts (AF_INET, struct in_addr);

			  if (req->ai_family == AF_INET)
			    {
			      no_inet6_data = no_data;
			      inet6_status = status;
			    }
			}

		      
		      if (inet6_status == NSS_STATUS_SUCCESS || status == NSS_STATUS_SUCCESS)
			{
			  if ((req->ai_flags & AI_CANONNAME) != 0 && canon == NULL)
			    {
			      
			      nss_getcanonname_r cfct;
			      int herrno;

			      cfct = __nss_lookup_function (nip, "getcanonname_r");
			      if (cfct != NULL)
				{
				  const size_t max_fqdn_len = 256;
				  if ((req->ai_flags & AI_CANONIDN) != 0 && __libc_use_alloca (alloca_used + max_fqdn_len))

				    canonbuf = alloca_account (max_fqdn_len, alloca_used);
				  else {
				      canonbuf = malloc (max_fqdn_len);
				      if (canonbuf == NULL)
					{
					  _res.options |= old_res_options & RES_USE_INET6;
					  result = -EAI_MEMORY;
					  goto free_and_return;
					}
				      malloc_canonbuf = true;
				    }
				  char *s;

				  if (DL_CALL_FCT (cfct, (at->name ?: name, canonbuf, max_fqdn_len, &s, &rc, &herrno))


				      == NSS_STATUS_SUCCESS)
				    canon = s;
				  else {
				      
				      if (malloc_canonbuf)
					{
					  free (canonbuf);
					  malloc_canonbuf = false;
					}
				      canon = name;
				    }
				}
			    }
			  status = NSS_STATUS_SUCCESS;
			}
		      else {
			  
			  if (inet6_status == NSS_STATUS_TRYAGAIN)
			    status = NSS_STATUS_TRYAGAIN;
			  else if (status == NSS_STATUS_UNAVAIL && inet6_status != NSS_STATUS_UNAVAIL)
			    status = inet6_status;
			}
		    }
		  else {
		      status = NSS_STATUS_UNAVAIL;
		      
		      if (errno != 0 && errno != ENOENT)
			__set_h_errno (NETDB_INTERNAL);
		    }
		}

	      if (nss_next_action (nip, status) == NSS_ACTION_RETURN)
		break;

	      if (nip->next == NULL)
		no_more = -1;
	      else nip = nip->next;
	    }

	  _res.options |= old_res_options & RES_USE_INET6;

	  if (h_errno == NETDB_INTERNAL)
	    {
	      result = -EAI_SYSTEM;
	      goto free_and_return;
	    }

	  if (no_data != 0 && no_inet6_data != 0)
	    {
	      
	      if (no_data == EAI_AGAIN && no_inet6_data == EAI_AGAIN)
		result = -EAI_AGAIN;
	      else  result = -EAI_NODATA;


	      goto free_and_return;
	    }
	}

    process_list:
      if (at->family == AF_UNSPEC)
	{
	  result = -EAI_NONAME;
	  goto free_and_return;
	}
    }
  else {
      struct gaih_addrtuple *atr;
      atr = at = alloca_account (sizeof (struct gaih_addrtuple), alloca_used);
      memset (at, '\0', sizeof (struct gaih_addrtuple));

      if (req->ai_family == AF_UNSPEC)
	{
	  at->next = __alloca (sizeof (struct gaih_addrtuple));
	  memset (at->next, '\0', sizeof (struct gaih_addrtuple));
	}

      if (req->ai_family == AF_UNSPEC || req->ai_family == AF_INET6)
	{
	  at->family = AF_INET6;
	  if ((req->ai_flags & AI_PASSIVE) == 0)
	    memcpy (at->addr, &in6addr_loopback, sizeof (struct in6_addr));
	  atr = at->next;
	}

      if (req->ai_family == AF_UNSPEC || req->ai_family == AF_INET)
	{
	  atr->family = AF_INET;
	  if ((req->ai_flags & AI_PASSIVE) == 0)
	    atr->addr[0] = htonl (INADDR_LOOPBACK);
	}
    }

  {
    struct gaih_servtuple *st2;
    struct gaih_addrtuple *at2 = at;
    size_t socklen;
    sa_family_t family;

    
    while (at2 != NULL)
      {
	
	if (at2 == at && (req->ai_flags & AI_CANONNAME) != 0)
	  {
	    if (canon == NULL)
	      
	      canon = orig_name;


	    if (req->ai_flags & AI_CANONIDN)
	      {
		int idn_flags = 0;
		if (req->ai_flags & AI_IDN_ALLOW_UNASSIGNED)
		  idn_flags |= IDNA_ALLOW_UNASSIGNED;
		if (req->ai_flags & AI_IDN_USE_STD3_ASCII_RULES)
		  idn_flags |= IDNA_USE_STD3_ASCII_RULES;

		char *out;
		int rc = __idna_to_unicode_lzlz (canon, &out, idn_flags);
		if (rc != IDNA_SUCCESS)
		  {
		    if (rc == IDNA_MALLOC_ERROR)
		      result = -EAI_MEMORY;
		    else if (rc == IDNA_DLOPEN_ERROR)
		      result = -EAI_SYSTEM;
		    else result = -EAI_IDN_ENCODE;
		    goto free_and_return;
		  }
		
		if (out == canon)
		  goto make_copy;
		canon = out;
	      }
	    else  {


	      make_copy:

		if (malloc_canonbuf)
		  
		  malloc_canonbuf = false;
		else {
		    canon = strdup (canon);
		    if (canon == NULL)
		      {
			result = -EAI_MEMORY;
			goto free_and_return;
		      }
		  }
	      }
	  }

	family = at2->family;
	if (family == AF_INET6)
	  {
	    socklen = sizeof (struct sockaddr_in6);

	    
	    if (got_ipv6 && (req->ai_flags & (AI_V4MAPPED|AI_ALL)) == AI_V4MAPPED && IN6_IS_ADDR_V4MAPPED (at2->addr))

	      goto ignore;
	  }
	else socklen = sizeof (struct sockaddr_in);

	for (st2 = st; st2 != NULL; st2 = st2->next)
	  {
	    struct addrinfo *ai;
	    ai = *pai = malloc (sizeof (struct addrinfo) + socklen);
	    if (ai == NULL)
	      {
		free ((char *) canon);
		result = -EAI_MEMORY;
		goto free_and_return;
	      }

	    ai->ai_flags = req->ai_flags;
	    ai->ai_family = family;
	    ai->ai_socktype = st2->socktype;
	    ai->ai_protocol = st2->protocol;
	    ai->ai_addrlen = socklen;
	    ai->ai_addr = (void *) (ai + 1);

	    
	    ai->ai_canonname = (char *) canon;
	    canon = NULL;


	    ai->ai_addr->sa_len = socklen;

	    ai->ai_addr->sa_family = family;

	    
	    ai->ai_next = NULL;

	    if (family == AF_INET6)
	      {
		struct sockaddr_in6 *sin6p = (struct sockaddr_in6 *) ai->ai_addr;

		sin6p->sin6_port = st2->port;
		sin6p->sin6_flowinfo = 0;
		memcpy (&sin6p->sin6_addr, at2->addr, sizeof (struct in6_addr));
		sin6p->sin6_scope_id = at2->scopeid;
	      }
	    else {
		struct sockaddr_in *sinp = (struct sockaddr_in *) ai->ai_addr;
		sinp->sin_port = st2->port;
		memcpy (&sinp->sin_addr, at2->addr, sizeof (struct in_addr));
		memset (sinp->sin_zero, '\0', sizeof (sinp->sin_zero));
	      }

	    pai = &(ai->ai_next);
	  }

	++*naddrs;

      ignore:
	at2 = at2->next;
      }
  }

 free_and_return:
  if (malloc_name)
    free ((char *) name);
  if (malloc_addrmem)
    free (addrmem);
  if (malloc_canonbuf)
    free (canonbuf);
  if (malloc_tmpbuf)
    free (tmpbuf);

  return result;
}


struct sort_result {
  struct addrinfo *dest_addr;
  
  struct sockaddr_in6 source_addr;
  uint8_t source_addr_len;
  bool got_source_addr;
  uint8_t source_addr_flags;
  uint8_t prefixlen;
  uint32_t index;
  int32_t native;
};

struct sort_result_combo {
  struct sort_result *results;
  int nresults;
};








static const struct scopeentry {
  union {
    char addr[4];
    uint32_t addr32;
  };
  uint32_t netmask;
  int32_t scope;
} default_scopes[] = {
    
    { { { 169, 254, 0, 0 } }, htonl_c (0xffff0000), 2 }, { { { 127, 0, 0, 0 } }, htonl_c (0xff000000), 2 },  { { { 0, 0, 0, 0 } }, htonl_c (0x00000000), 14 }


  };


static const struct scopeentry *scopes;


static int get_scope (const struct sockaddr_in6 *in6)
{
  int scope;
  if (in6->sin6_family == PF_INET6)
    {
      if (! IN6_IS_ADDR_MULTICAST (&in6->sin6_addr))
	{
	  if (IN6_IS_ADDR_LINKLOCAL (&in6->sin6_addr)
	      
	      || IN6_IS_ADDR_LOOPBACK (&in6->sin6_addr))
	    scope = 2;
	  else if (IN6_IS_ADDR_SITELOCAL (&in6->sin6_addr))
	    scope = 5;
	  else  scope = 14;

	}
      else scope = in6->sin6_addr.s6_addr[1] & 0xf;
    }
  else if (in6->sin6_family == PF_INET)
    {
      const struct sockaddr_in *in = (const struct sockaddr_in *) in6;

      size_t cnt = 0;
      while (1)
	{
	  if ((in->sin_addr.s_addr & scopes[cnt].netmask)
	      == scopes[cnt].addr32)
	    return scopes[cnt].scope;

	  ++cnt;
	}
      
    }
  else  scope = 15;


  return scope;
}


struct prefixentry {
  struct in6_addr prefix;
  unsigned int bits;
  int val;
};



static const struct prefixentry *labels;


static const struct prefixentry default_labels[] = {
    
    { { .__in6_u = { .__u6_addr8 = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 } }

      }, 128, 0 }, { { .__in6_u = { .__u6_addr8 = { 0x20, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } }


      }, 16, 2 }, { { .__in6_u = { .__u6_addr8 = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } }


      }, 96, 3 }, { { .__in6_u = { .__u6_addr8 = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 } }


      }, 96, 4 },  { { .__in6_u = { .__u6_addr8 = { 0xfe, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } }



      }, 10, 5 }, { { .__in6_u = { .__u6_addr8 = { 0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } }


      }, 7, 6 },  { { .__in6_u = { .__u6_addr8 = { 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } }



      }, 32, 7 }, { { .__in6_u = { .__u6_addr8 = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } }


      }, 0, 1 }
  };



static const struct prefixentry *precedence;


static const struct prefixentry default_precedence[] = {
    
    { { .__in6_u = { .__u6_addr8 = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 } }

      }, 128, 50 }, { { .__in6_u = { .__u6_addr8 = { 0x20, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } }


      }, 16, 30 }, { { .__in6_u = { .__u6_addr8 = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } }


      }, 96, 20 }, { { .__in6_u = { .__u6_addr8 = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 } }


      }, 96, 10 }, { { .__in6_u = { .__u6_addr8 = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } }


      }, 0, 40 }
  };


static int match_prefix (const struct sockaddr_in6 *in6, const struct prefixentry *list, int default_val)

{
  int idx;
  struct sockaddr_in6 in6_mem;

  if (in6->sin6_family == PF_INET)
    {
      const struct sockaddr_in *in = (const struct sockaddr_in *) in6;

      
      in6_mem.sin6_family = PF_INET6;
      in6_mem.sin6_port = in->sin_port;
      in6_mem.sin6_flowinfo = 0;
      memset (&in6_mem.sin6_addr, '\0', sizeof (in6_mem.sin6_addr));
      in6_mem.sin6_addr.s6_addr16[5] = 0xffff;
      in6_mem.sin6_addr.s6_addr32[3] = in->sin_addr.s_addr;
      in6_mem.sin6_scope_id = 0;

      in6 = &in6_mem;
    }
  else if (in6->sin6_family != PF_INET6)
    return default_val;

  for (idx = 0; ; ++idx)
    {
      unsigned int bits = list[idx].bits;
      const uint8_t *mask = list[idx].prefix.s6_addr;
      const uint8_t *val = in6->sin6_addr.s6_addr;

      while (bits >= 8)
	{
	  if (*mask != *val)
	    break;

	  ++mask;
	  ++val;
	  bits -= 8;
	}

      if (bits < 8)
	{
	  if ((*mask & (0xff00 >> bits)) == (*val & (0xff00 >> bits)))
	    
	    break;
	}
    }

  return list[idx].val;
}


static int get_label (const struct sockaddr_in6 *in6)
{
  
  return match_prefix (in6, labels, INT_MAX);
}


static int get_precedence (const struct sockaddr_in6 *in6)
{
  
  return match_prefix (in6, precedence, 0);
}



static int fls (uint32_t a)
{
  uint32_t mask;
  int n;
  for (n = 0, mask = 1 << 31; n < 32; mask >>= 1, ++n)
    if ((a & mask) != 0)
      break;
  return n;
}


static int rfc3484_sort (const void *p1, const void *p2, void *arg)
{
  const size_t idx1 = *(const size_t *) p1;
  const size_t idx2 = *(const size_t *) p2;
  struct sort_result_combo *src = (struct sort_result_combo *) arg;
  struct sort_result *a1 = &src->results[idx1];
  struct sort_result *a2 = &src->results[idx2];

  
  if (a1->got_source_addr && ! a2->got_source_addr)
    return -1;
  if (! a1->got_source_addr && a2->got_source_addr)
    return 1;


  
  int a1_dst_scope = get_scope ((struct sockaddr_in6 *) a1->dest_addr->ai_addr);

  int a2_dst_scope = get_scope ((struct sockaddr_in6 *) a2->dest_addr->ai_addr);

  if (a1->got_source_addr)
    {
      int a1_src_scope = get_scope (&a1->source_addr);
      int a2_src_scope = get_scope (&a2->source_addr);

      if (a1_dst_scope == a1_src_scope && a2_dst_scope != a2_src_scope)
	return -1;
      if (a1_dst_scope != a1_src_scope && a2_dst_scope == a2_src_scope)
	return 1;
    }


  
  if (a1->got_source_addr)
    {
      if (!(a1->source_addr_flags & in6ai_deprecated)
	  && (a2->source_addr_flags & in6ai_deprecated))
	return -1;
      if ((a1->source_addr_flags & in6ai_deprecated)
	  && !(a2->source_addr_flags & in6ai_deprecated))
	return 1;
    }

  
  if (a1->got_source_addr)
    {
      if (!(a1->source_addr_flags & in6ai_homeaddress)
	  && (a2->source_addr_flags & in6ai_homeaddress))
	return 1;
      if ((a1->source_addr_flags & in6ai_homeaddress)
	  && !(a2->source_addr_flags & in6ai_homeaddress))
	return -1;
    }

  
  if (a1->got_source_addr)
    {
      int a1_dst_label = get_label ((struct sockaddr_in6 *) a1->dest_addr->ai_addr);
      int a1_src_label = get_label (&a1->source_addr);

      int a2_dst_label = get_label ((struct sockaddr_in6 *) a2->dest_addr->ai_addr);
      int a2_src_label = get_label (&a2->source_addr);

      if (a1_dst_label == a1_src_label && a2_dst_label != a2_src_label)
	return -1;
      if (a1_dst_label != a1_src_label && a2_dst_label == a2_src_label)
	return 1;
    }


  
  int a1_prec = get_precedence ((struct sockaddr_in6 *) a1->dest_addr->ai_addr);
  int a2_prec = get_precedence ((struct sockaddr_in6 *) a2->dest_addr->ai_addr);

  if (a1_prec > a2_prec)
    return -1;
  if (a1_prec < a2_prec)
    return 1;


  
  if (a1->got_source_addr)
    {
      
      if (a1->index != a2->index)
	{
	  int a1_native = a1->native;
	  int a2_native = a2->native;

	  if (a1_native == -1 || a2_native == -1)
	    {
	      uint32_t a1_index;
	      if (a1_native == -1)
		{
		  
		  a1_native = 0;
		  a1_index = a1->index;
		}
	      else a1_index = 0xffffffffu;

	      uint32_t a2_index;
	      if (a2_native == -1)
		{
		  
		  a2_native = 0;
		  a2_index = a2->index;
		}
	      else a2_index = 0xffffffffu;

	      __check_native (a1_index, &a1_native, a2_index, &a2_native);

	      
	      for (int i = 0; i < src->nresults; ++i)
		if (a1_index != -1 && src->results[i].index == a1_index)
		  {
		    assert (src->results[i].native == -1 || src->results[i].native == a1_native);
		    src->results[i].native = a1_native;
		  }
		else if (a2_index != -1 && src->results[i].index == a2_index)
		  {
		    assert (src->results[i].native == -1 || src->results[i].native == a2_native);
		    src->results[i].native = a2_native;
		  }
	    }

	  if (a1_native && !a2_native)
	    return -1;
	  if (!a1_native && a2_native)
	    return 1;
	}
    }


  
  if (a1_dst_scope < a2_dst_scope)
    return -1;
  if (a1_dst_scope > a2_dst_scope)
    return 1;


  
  if (a1->got_source_addr && a1->dest_addr->ai_family == a2->dest_addr->ai_family)
    {
      int bit1 = 0;
      int bit2 = 0;

      if (a1->dest_addr->ai_family == PF_INET)
	{
	  assert (a1->source_addr.sin6_family == PF_INET);
	  assert (a2->source_addr.sin6_family == PF_INET);

	  
	  struct sockaddr_in *in1_dst = (struct sockaddr_in *) a1->dest_addr->ai_addr;
	  in_addr_t in1_dst_addr = ntohl (in1_dst->sin_addr.s_addr);
	  struct sockaddr_in *in1_src = (struct sockaddr_in *) &a1->source_addr;
	  in_addr_t in1_src_addr = ntohl (in1_src->sin_addr.s_addr);
	  in_addr_t netmask1 = 0xffffffffu << (32 - a1->prefixlen);

	  if ((in1_src_addr & netmask1) == (in1_dst_addr & netmask1))
	    bit1 = fls (in1_dst_addr ^ in1_src_addr);

	  struct sockaddr_in *in2_dst = (struct sockaddr_in *) a2->dest_addr->ai_addr;
	  in_addr_t in2_dst_addr = ntohl (in2_dst->sin_addr.s_addr);
	  struct sockaddr_in *in2_src = (struct sockaddr_in *) &a2->source_addr;
	  in_addr_t in2_src_addr = ntohl (in2_src->sin_addr.s_addr);
	  in_addr_t netmask2 = 0xffffffffu << (32 - a2->prefixlen);

	  if ((in2_src_addr & netmask2) == (in2_dst_addr & netmask2))
	    bit2 = fls (in2_dst_addr ^ in2_src_addr);
	}
      else if (a1->dest_addr->ai_family == PF_INET6)
	{
	  assert (a1->source_addr.sin6_family == PF_INET6);
	  assert (a2->source_addr.sin6_family == PF_INET6);

	  struct sockaddr_in6 *in1_dst;
	  struct sockaddr_in6 *in1_src;
	  struct sockaddr_in6 *in2_dst;
	  struct sockaddr_in6 *in2_src;

	  in1_dst = (struct sockaddr_in6 *) a1->dest_addr->ai_addr;
	  in1_src = (struct sockaddr_in6 *) &a1->source_addr;
	  in2_dst = (struct sockaddr_in6 *) a2->dest_addr->ai_addr;
	  in2_src = (struct sockaddr_in6 *) &a2->source_addr;

	  int i;
	  for (i = 0; i < 4; ++i)
	    if (in1_dst->sin6_addr.s6_addr32[i] != in1_src->sin6_addr.s6_addr32[i] || (in2_dst->sin6_addr.s6_addr32[i] != in2_src->sin6_addr.s6_addr32[i]))


	      break;

	  if (i < 4)
	    {
	      bit1 = fls (ntohl (in1_dst->sin6_addr.s6_addr32[i] ^ in1_src->sin6_addr.s6_addr32[i]));
	      bit2 = fls (ntohl (in2_dst->sin6_addr.s6_addr32[i] ^ in2_src->sin6_addr.s6_addr32[i]));
	    }
	}

      if (bit1 > bit2)
	return -1;
      if (bit1 < bit2)
	return 1;
    }


  
  return idx1 < idx2 ? -1 : 1;
}


static int in6aicmp (const void *p1, const void *p2)
{
  struct in6addrinfo *a1 = (struct in6addrinfo *) p1;
  struct in6addrinfo *a2 = (struct in6addrinfo *) p2;

  return memcmp (a1->addr, a2->addr, sizeof (a1->addr));
}







static int gaiconf_reload_flag;


static int gaiconf_reload_flag_ever_set;




static struct timespec gaiconf_mtime;

static inline void save_gaiconf_mtime (const struct stat64 *st)
{
  gaiconf_mtime = st->st_mtim;
}

static inline bool check_gaiconf_mtime (const struct stat64 *st)
{
  return (st->st_mtim.tv_sec == gaiconf_mtime.tv_sec && st->st_mtim.tv_nsec == gaiconf_mtime.tv_nsec);
}



static time_t gaiconf_mtime;

static inline void save_gaiconf_mtime (const struct stat64 *st)
{
  gaiconf_mtime = st->st_mtime;
}

static inline bool check_gaiconf_mtime (const struct stat64 *st)
{
  return st->st_mtime == gaiconf_mtime;
}




libc_freeres_fn(fini)
{
  if (labels != default_labels)
    {
      const struct prefixentry *old = labels;
      labels = default_labels;
      free ((void *) old);
    }

  if (precedence != default_precedence)
    {
      const struct prefixentry *old = precedence;
      precedence = default_precedence;
      free ((void *) old);
    }

  if (scopes != default_scopes)
    {
      const struct scopeentry *old = scopes;
      scopes = default_scopes;
      free ((void *) old);
    }
}


struct prefixlist {
  struct prefixentry entry;
  struct prefixlist *next;
};


struct scopelist {
  struct scopeentry entry;
  struct scopelist *next;
};


static void free_prefixlist (struct prefixlist *list)
{
  while (list != NULL)
    {
      struct prefixlist *oldp = list;
      list = list->next;
      free (oldp);
    }
}


static void free_scopelist (struct scopelist *list)
{
  while (list != NULL)
    {
      struct scopelist *oldp = list;
      list = list->next;
      free (oldp);
    }
}


static int prefixcmp (const void *p1, const void *p2)
{
  const struct prefixentry *e1 = (const struct prefixentry *) p1;
  const struct prefixentry *e2 = (const struct prefixentry *) p2;

  if (e1->bits < e2->bits)
    return 1;
  if (e1->bits == e2->bits)
    return 0;
  return -1;
}


static int scopecmp (const void *p1, const void *p2)
{
  const struct scopeentry *e1 = (const struct scopeentry *) p1;
  const struct scopeentry *e2 = (const struct scopeentry *) p2;

  if (e1->netmask > e2->netmask)
    return -1;
  if (e1->netmask == e2->netmask)
    return 0;
  return 1;
}


static void gaiconf_init (void)
{
  struct prefixlist *labellist = NULL;
  size_t nlabellist = 0;
  bool labellist_nullbits = false;
  struct prefixlist *precedencelist = NULL;
  size_t nprecedencelist = 0;
  bool precedencelist_nullbits = false;
  struct scopelist *scopelist =  NULL;
  size_t nscopelist = 0;
  bool scopelist_nullbits = false;

  FILE *fp = fopen (GAICONF_FNAME, "rce");
  if (fp != NULL)
    {
      struct stat64 st;
      if (__fxstat64 (_STAT_VER, fileno (fp), &st) != 0)
	{
	  fclose (fp);
	  goto no_file;
	}

      char *line = NULL;
      size_t linelen = 0;

      __fsetlocking (fp, FSETLOCKING_BYCALLER);

      while (!feof_unlocked (fp))
	{
	  ssize_t n = __getline (&line, &linelen, fp);
	  if (n <= 0)
	    break;

	  
	  char *cp = strchr (line, '#');
	  if (cp != NULL)
	    *cp = '\0';

	  cp = line;
	  while (isspace (*cp))
	    ++cp;

	  char *cmd = cp;
	  while (*cp != '\0' && !isspace (*cp))
	    ++cp;
	  size_t cmdlen = cp - cmd;

	  if (*cp != '\0')
	    *cp++ = '\0';
	  while (isspace (*cp))
	    ++cp;

	  char *val1 = cp;
	  while (*cp != '\0' && !isspace (*cp))
	    ++cp;
	  size_t val1len = cp - cmd;

	  
	  if (val1len == 0)
	    continue;

	  if (*cp != '\0')
	    *cp++ = '\0';
	  while (isspace (*cp))
	    ++cp;

	  char *val2 = cp;
	  while (*cp != '\0' && !isspace (*cp))
	    ++cp;

	  
	  *cp = '\0';

	  struct prefixlist **listp;
	  size_t *lenp;
	  bool *nullbitsp;
	  switch (cmdlen)
	    {
	    case 5:
	      if (strcmp (cmd, "label") == 0)
		{
		  struct in6_addr prefix;
		  unsigned long int bits;
		  unsigned long int val;
		  char *endp;

		  listp = &labellist;
		  lenp = &nlabellist;
		  nullbitsp = &labellist_nullbits;

		new_elem:
		  bits = 128;
		  __set_errno (0);
		  cp = strchr (val1, '/');
		  if (cp != NULL)
		    *cp++ = '\0';
		  if (inet_pton (AF_INET6, val1, &prefix)
		      && (cp == NULL || (bits = strtoul (cp, &endp, 10)) != ULONG_MAX || errno != ERANGE)

		      && *endp == '\0' && bits <= 128 && ((val = strtoul (val2, &endp, 10)) != ULONG_MAX || errno != ERANGE)


		      && *endp == '\0' && val <= INT_MAX)
		    {
		      struct prefixlist *newp = malloc (sizeof (*newp));
		      if (newp == NULL)
			{
			  free (line);
			  fclose (fp);
			  goto no_file;
			}

		      memcpy (&newp->entry.prefix, &prefix, sizeof (prefix));
		      newp->entry.bits = bits;
		      newp->entry.val = val;
		      newp->next = *listp;
		      *listp = newp;
		      ++*lenp;
		      *nullbitsp |= bits == 0;
		    }
		}
	      break;

	    case 6:
	      if (strcmp (cmd, "reload") == 0)
		{
		  gaiconf_reload_flag = strcmp (val1, "yes") == 0;
		  if (gaiconf_reload_flag)
		    gaiconf_reload_flag_ever_set = 1;
		}
	      break;

	    case 7:
	      if (strcmp (cmd, "scopev4") == 0)
		{
		  struct in6_addr prefix;
		  unsigned long int bits;
		  unsigned long int val;
		  char *endp;

		  bits = 32;
		  __set_errno (0);
		  cp = strchr (val1, '/');
		  if (cp != NULL)
		    *cp++ = '\0';
		  if (inet_pton (AF_INET6, val1, &prefix))
		    {
		      bits = 128;
		      if (IN6_IS_ADDR_V4MAPPED (&prefix)
			  && (cp == NULL || (bits = strtoul (cp, &endp, 10)) != ULONG_MAX || errno != ERANGE)

			  && *endp == '\0' && bits >= 96 && bits <= 128 && ((val = strtoul (val2, &endp, 10)) != ULONG_MAX || errno != ERANGE)



			  && *endp == '\0' && val <= INT_MAX)
			{
			  struct scopelist *newp;
			new_scope:
			  newp = malloc (sizeof (*newp));
			  if (newp == NULL)
			    {
			      free (line);
			      fclose (fp);
			      goto no_file;
			    }

			  newp->entry.netmask = htonl (bits != 96 ? (0xffffffff << (128 - bits))

						       : 0);
			  newp->entry.addr32 = (prefix.s6_addr32[3] & newp->entry.netmask);
			  newp->entry.scope = val;
			  newp->next = scopelist;
			  scopelist = newp;
			  ++nscopelist;
			  scopelist_nullbits |= bits == 96;
			}
		    }
		  else if (inet_pton (AF_INET, val1, &prefix.s6_addr32[3])
			   && (cp == NULL || (bits = strtoul (cp, &endp, 10)) != ULONG_MAX || errno != ERANGE)

			   && *endp == '\0' && bits <= 32 && ((val = strtoul (val2, &endp, 10)) != ULONG_MAX || errno != ERANGE)


			   && *endp == '\0' && val <= INT_MAX)
		    {
		      bits += 96;
		      goto new_scope;
		    }
		}
	      break;

	    case 10:
	      if (strcmp (cmd, "precedence") == 0)
		{
		  listp = &precedencelist;
		  lenp = &nprecedencelist;
		  nullbitsp = &precedencelist_nullbits;
		  goto new_elem;
		}
	      break;
	    }
	}

      free (line);

      fclose (fp);

      
      struct prefixentry *new_labels;
      if (nlabellist > 0)
	{
	  if (!labellist_nullbits)
	    ++nlabellist;
	  new_labels = malloc (nlabellist * sizeof (*new_labels));
	  if (new_labels == NULL)
	    goto no_file;

	  int i = nlabellist;
	  if (!labellist_nullbits)
	    {
	      --i;
	      memset (&new_labels[i].prefix, '\0', sizeof (struct in6_addr));
	      new_labels[i].bits = 0;
	      new_labels[i].val = 1;
	    }

	  struct prefixlist *l = labellist;
	  while (i-- > 0)
	    {
	      new_labels[i] = l->entry;
	      l = l->next;
	    }
	  free_prefixlist (labellist);

	  
	  qsort (new_labels, nlabellist, sizeof (*new_labels), prefixcmp);
	}
      else new_labels = (struct prefixentry *) default_labels;

      struct prefixentry *new_precedence;
      if (nprecedencelist > 0)
	{
	  if (!precedencelist_nullbits)
	    ++nprecedencelist;
	  new_precedence = malloc (nprecedencelist * sizeof (*new_precedence));
	  if (new_precedence == NULL)
	    {
	      if (new_labels != default_labels)
		free (new_labels);
	      goto no_file;
	    }

	  int i = nprecedencelist;
	  if (!precedencelist_nullbits)
	    {
	      --i;
	      memset (&new_precedence[i].prefix, '\0', sizeof (struct in6_addr));
	      new_precedence[i].bits = 0;
	      new_precedence[i].val = 40;
	    }

	  struct prefixlist *l = precedencelist;
	  while (i-- > 0)
	    {
	      new_precedence[i] = l->entry;
	      l = l->next;
	    }
	  free_prefixlist (precedencelist);

	  
	  qsort (new_precedence, nprecedencelist, sizeof (*new_precedence), prefixcmp);
	}
      else new_precedence = (struct prefixentry *) default_precedence;

      struct scopeentry *new_scopes;
      if (nscopelist > 0)
	{
	  if (!scopelist_nullbits)
	    ++nscopelist;
	  new_scopes = malloc (nscopelist * sizeof (*new_scopes));
	  if (new_scopes == NULL)
	    {
	      if (new_labels != default_labels)
		free (new_labels);
	      if (new_precedence != default_precedence)
		free (new_precedence);
	      goto no_file;
	    }

	  int i = nscopelist;
	  if (!scopelist_nullbits)
	    {
	      --i;
	      new_scopes[i].addr32 = 0;
	      new_scopes[i].netmask = 0;
	      new_scopes[i].scope = 14;
	    }

	  struct scopelist *l = scopelist;
	  while (i-- > 0)
	    {
	      new_scopes[i] = l->entry;
	      l = l->next;
	    }
	  free_scopelist (scopelist);

	  
	  qsort (new_scopes, nscopelist, sizeof (*new_scopes), scopecmp);
	}
      else new_scopes = (struct scopeentry *) default_scopes;

      
      const struct prefixentry *old = labels;
      labels = new_labels;
      if (old != default_labels)
	free ((void *) old);

      old = precedence;
      precedence = new_precedence;
      if (old != default_precedence)
	free ((void *) old);

      const struct scopeentry *oldscope = scopes;
      scopes = new_scopes;
      if (oldscope != default_scopes)
	free ((void *) oldscope);

      save_gaiconf_mtime (&st);
    }
  else {
    no_file:
      free_prefixlist (labellist);
      free_prefixlist (precedencelist);
      free_scopelist (scopelist);

      
      fini ();
    }
}


static void gaiconf_reload (void)
{
  struct stat64 st;
  if (__xstat64 (_STAT_VER, GAICONF_FNAME, &st) != 0 || !check_gaiconf_mtime (&st))
    gaiconf_init ();
}


int getaddrinfo (const char *name, const char *service, const struct addrinfo *hints, struct addrinfo **pai)

{
  int i = 0, last_i = 0;
  int nresults = 0;
  struct addrinfo *p = NULL;
  struct gaih_service gaih_service, *pservice;
  struct addrinfo local_hints;

  if (name != NULL && name[0] == '*' && name[1] == 0)
    name = NULL;

  if (service != NULL && service[0] == '*' && service[1] == 0)
    service = NULL;

  if (name == NULL && service == NULL)
    return EAI_NONAME;

  if (hints == NULL)
    hints = &default_hints;

  if (hints->ai_flags & ~(AI_PASSIVE|AI_CANONNAME|AI_NUMERICHOST|AI_ADDRCONFIG|AI_V4MAPPED  |AI_IDN|AI_CANONIDN|AI_IDN_ALLOW_UNASSIGNED |AI_IDN_USE_STD3_ASCII_RULES  |AI_NUMERICSERV|AI_ALL))





    return EAI_BADFLAGS;

  if ((hints->ai_flags & AI_CANONNAME) && name == NULL)
    return EAI_BADFLAGS;

  struct in6addrinfo *in6ai = NULL;
  size_t in6ailen = 0;
  bool seen_ipv4 = false;
  bool seen_ipv6 = false;
  bool check_pf_called = false;

  if (hints->ai_flags & AI_ADDRCONFIG)
    {
      
      __check_pf (&seen_ipv4, &seen_ipv6, &in6ai, &in6ailen);
      check_pf_called = true;

      
      if (hints->ai_family == PF_UNSPEC && (seen_ipv4 || seen_ipv6))
	{
	  
	  if ((! seen_ipv4 || ! seen_ipv6) && (seen_ipv4 || seen_ipv6))
	    {
	      local_hints = *hints;
	      local_hints.ai_family = seen_ipv4 ? PF_INET : PF_INET6;
	      hints = &local_hints;
	    }
	}
      else if ((hints->ai_family == PF_INET && ! seen_ipv4)
	       || (hints->ai_family == PF_INET6 && ! seen_ipv6))
	{
	  
	  __free_in6ai (in6ai);
	  return EAI_NONAME;
	}
    }

  if (service && service[0])
    {
      char *c;
      gaih_service.name = service;
      gaih_service.num = strtoul (gaih_service.name, &c, 10);
      if (*c != '\0')
	{
	  if (hints->ai_flags & AI_NUMERICSERV)
	    {
	      __free_in6ai (in6ai);
	      return EAI_NONAME;
	    }

	  gaih_service.num = -1;
	}

      pservice = &gaih_service;
    }
  else pservice = NULL;

  struct addrinfo **end = &p;

  unsigned int naddrs = 0;
  if (hints->ai_family == AF_UNSPEC || hints->ai_family == AF_INET || hints->ai_family == AF_INET6)
    {
      last_i = gaih_inet (name, pservice, hints, end, &naddrs);
      if (last_i != 0)
	{
	  freeaddrinfo (p);
	  __free_in6ai (in6ai);

	  return -last_i;
	}
      while (*end)
	{
	  end = &((*end)->ai_next);
	  ++nresults;
	}
    }
  else {
      __free_in6ai (in6ai);
      return EAI_FAMILY;
    }

  if (naddrs > 1)
    {
      
      __libc_once_define (static, once);
      __typeof (once) old_once = once;
      __libc_once (once, gaiconf_init);
      
      struct sort_result *results;
      size_t *order;
      struct addrinfo *q;
      struct addrinfo *last = NULL;
      char *canonname = NULL;
      bool malloc_results;
      size_t alloc_size = nresults * (sizeof (*results) + sizeof (size_t));

      malloc_results = !__libc_use_alloca (alloc_size);
      if (malloc_results)
	{
	  results = malloc (alloc_size);
	  if (results == NULL)
	    {
	      __free_in6ai (in6ai);
	      return EAI_MEMORY;
	    }
	}
      else results = alloca (alloc_size);
      order = (size_t *) (results + nresults);

      
      if (! check_pf_called)
	__check_pf (&seen_ipv4, &seen_ipv6, &in6ai, &in6ailen);

      
      if (in6ai != NULL)
	qsort (in6ai, in6ailen, sizeof (*in6ai), in6aicmp);

      int fd = -1;
      int af = AF_UNSPEC;

      for (i = 0, q = p; q != NULL; ++i, last = q, q = q->ai_next)
	{
	  results[i].dest_addr = q;
	  results[i].native = -1;
	  order[i] = i;

	  
	  if (last != NULL && last->ai_addrlen == q->ai_addrlen && memcmp (last->ai_addr, q->ai_addr, q->ai_addrlen) == 0)
	    {
	      memcpy (&results[i].source_addr, &results[i - 1].source_addr, results[i - 1].source_addr_len);
	      results[i].source_addr_len = results[i - 1].source_addr_len;
	      results[i].got_source_addr = results[i - 1].got_source_addr;
	      results[i].source_addr_flags = results[i - 1].source_addr_flags;
	      results[i].prefixlen = results[i - 1].prefixlen;
	      results[i].index = results[i - 1].index;
	    }
	  else {
	      results[i].got_source_addr = false;
	      results[i].source_addr_flags = 0;
	      results[i].prefixlen = 0;
	      results[i].index = 0xffffffffu;

	      
	      if (fd == -1 || (af == AF_INET && q->ai_family == AF_INET6))
		{
		  if (fd != -1)
		  close_retry:
		    close_not_cancel_no_status (fd);
		  af = q->ai_family;
		  fd = __socket (af, SOCK_DGRAM, IPPROTO_IP);
		}
	      else {
		  
		  struct sockaddr sa = { .sa_family = AF_UNSPEC };
		  __connect (fd, &sa, sizeof (sa));
		}

	      socklen_t sl = sizeof (results[i].source_addr);
	      if (fd != -1 && __connect (fd, q->ai_addr, q->ai_addrlen) == 0 && __getsockname (fd, (struct sockaddr *) &results[i].source_addr, &sl) == 0)



		{
		  results[i].source_addr_len = sl;
		  results[i].got_source_addr = true;

		  if (in6ai != NULL)
		    {
		      
		      struct in6addrinfo tmp;

		      if (q->ai_family == AF_INET && af == AF_INET)
			{
			  struct sockaddr_in *sinp = (struct sockaddr_in *) &results[i].source_addr;
			  tmp.addr[0] = 0;
			  tmp.addr[1] = 0;
			  tmp.addr[2] = htonl (0xffff);
			  
			  if ((ntohl(sinp->sin_addr.s_addr) & 0xff000000)
			      == 0x7f000000)
			    tmp.addr[3] = htonl(0x7f000001);
			  else tmp.addr[3] = sinp->sin_addr.s_addr;
			}
		      else {
			  struct sockaddr_in6 *sin6p = (struct sockaddr_in6 *) &results[i].source_addr;
			  memcpy (tmp.addr, &sin6p->sin6_addr, IN6ADDRSZ);
			}

		      struct in6addrinfo *found = bsearch (&tmp, in6ai, in6ailen, sizeof (*in6ai), in6aicmp);

		      if (found != NULL)
			{
			  results[i].source_addr_flags = found->flags;
			  results[i].prefixlen = found->prefixlen;
			  results[i].index = found->index;
			}
		    }

		  if (q->ai_family == AF_INET && af == AF_INET6)
		    {
		      
		      struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &results[i].source_addr;
		      struct sockaddr_in *sin = (struct sockaddr_in *) &results[i].source_addr;
		      assert (IN6_IS_ADDR_V4MAPPED (sin6->sin6_addr.s6_addr32));
		      sin->sin_family = AF_INET;
		      
		      assert (offsetof (struct sockaddr_in, sin_port)
			      == offsetof (struct sockaddr_in6, sin6_port));
		      assert (sizeof (sin->sin_port)
			      == sizeof (sin6->sin6_port));
		      memcpy (&sin->sin_addr, &sin6->sin6_addr.s6_addr32[3], INADDRSZ);
		      results[i].source_addr_len = sizeof (struct sockaddr_in);
		    }
		}
	      else if (errno == EAFNOSUPPORT && af == AF_INET6 && q->ai_family == AF_INET)
		
		goto close_retry;
	      else  results[i].source_addr_len = 0;

	    }

	  
	  if (q->ai_canonname != NULL)
	    {
	      assert (canonname == NULL);
	      canonname = q->ai_canonname;
	      q->ai_canonname = NULL;
	    }
	}

      if (fd != -1)
	close_not_cancel_no_status (fd);

      
      struct sort_result_combo src = { .results = results, .nresults = nresults };
      if (__glibc_unlikely (gaiconf_reload_flag_ever_set))
	{
	  __libc_lock_define_initialized (static, lock);

	  __libc_lock_lock (lock);
	  if (__libc_once_get (old_once) && gaiconf_reload_flag)
	    gaiconf_reload ();
	  __qsort_r (order, nresults, sizeof (order[0]), rfc3484_sort, &src);
	  __libc_lock_unlock (lock);
	}
      else __qsort_r (order, nresults, sizeof (order[0]), rfc3484_sort, &src);

      
      q = p = results[order[0]].dest_addr;
      for (i = 1; i < nresults; ++i)
	q = q->ai_next = results[order[i]].dest_addr;
      q->ai_next = NULL;

      
      p->ai_canonname = canonname;

      if (malloc_results)
	free (results);
    }

  __free_in6ai (in6ai);

  if (p)
    {
      *pai = p;
      return 0;
    }

  return last_i ? -last_i : EAI_NONAME;
}
libc_hidden_def (getaddrinfo)

nss_interface_function (getaddrinfo)

void freeaddrinfo (struct addrinfo *ai)
{
  struct addrinfo *p;

  while (ai != NULL)
    {
      p = ai;
      ai = ai->ai_next;
      free (p->ai_canonname);
      free (p);
    }
}
libc_hidden_def (freeaddrinfo)
