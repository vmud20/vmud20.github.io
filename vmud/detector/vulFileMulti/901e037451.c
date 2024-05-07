



































typedef union querybuf {
  HEADER hdr;
  u_char buf[MAXPACKET];
} querybuf;



extern int __ns_name_ntop (const u_char *, char *, size_t);
extern int __ns_name_unpack (const u_char *, const u_char *, const u_char *, u_char *, size_t);


static enum nss_status getanswer_r (const querybuf *answer, int anslen, const char *qname, int qtype, struct hostent *result, char *buffer, size_t buflen, int *errnop, int *h_errnop, int map, int32_t *ttlp, char **canonp);




static enum nss_status gaih_getanswer (const querybuf *answer1, int anslen1, const querybuf *answer2, int anslen2, const char *qname, struct gaih_addrtuple **pat, char *buffer, size_t buflen, int *errnop, int *h_errnop, int32_t *ttlp);






extern enum nss_status _nss_dns_gethostbyname3_r (const char *name, int af, struct hostent *result, char *buffer, size_t buflen, int *errnop, int *h_errnop, int32_t *ttlp, char **canonp);




hidden_proto (_nss_dns_gethostbyname3_r)


static int rrtype_to_rdata_length (int type)
{
  switch (type)
    {
    case T_A:
      return INADDRSZ;
    case T_AAAA:
      return IN6ADDRSZ;
    default:
      return -1;
    }
}

enum nss_status _nss_dns_gethostbyname3_r (const char *name, int af, struct hostent *result, char *buffer, size_t buflen, int *errnop, int *h_errnop, int32_t *ttlp, char **canonp)


{
  union {
    querybuf *buf;
    u_char *ptr;
  } host_buffer;
  querybuf *orig_host_buffer;
  char tmp[NS_MAXDNAME];
  int size, type, n;
  const char *cp;
  int map = 0;
  int olderr = errno;
  enum nss_status status;

  if (__res_maybe_init (&_res, 0) == -1)
    return NSS_STATUS_UNAVAIL;

  switch (af) {
  case AF_INET:
    size = INADDRSZ;
    type = T_A;
    break;
  case AF_INET6:
    size = IN6ADDRSZ;
    type = T_AAAA;
    break;
  default:
    *h_errnop = NO_DATA;
    *errnop = EAFNOSUPPORT;
    return NSS_STATUS_UNAVAIL;
  }

  result->h_addrtype = af;
  result->h_length = size;

  
  if (strchr (name, '.') == NULL && (cp = res_hostalias (&_res, name, tmp, sizeof (tmp))) != NULL)
    name = cp;

  host_buffer.buf = orig_host_buffer = (querybuf *) alloca (1024);

  n = __libc_res_nsearch (&_res, name, C_IN, type, host_buffer.buf->buf, 1024, &host_buffer.ptr, NULL, NULL, NULL, NULL);
  if (n < 0)
    {
      switch (errno)
	{
	case ESRCH:
	  status = NSS_STATUS_TRYAGAIN;
	  h_errno = TRY_AGAIN;
	  break;
	
	case EMFILE:
	case ENFILE:
	  h_errno = NETDB_INTERNAL;
	  
	case ECONNREFUSED:
	case ETIMEDOUT:
	  status = NSS_STATUS_UNAVAIL;
	  break;
	default:
	  status = NSS_STATUS_NOTFOUND;
	  break;
	}
      *h_errnop = h_errno;
      if (h_errno == TRY_AGAIN)
	*errnop = EAGAIN;
      else __set_errno (olderr);

      
      if (af == AF_INET6 && res_use_inet6 ())
	n = __libc_res_nsearch (&_res, name, C_IN, T_A, host_buffer.buf->buf, host_buffer.buf != orig_host_buffer ? MAXPACKET : 1024, &host_buffer.ptr, NULL, NULL, NULL, NULL);



      if (n < 0)
	{
	  if (host_buffer.buf != orig_host_buffer)
	    free (host_buffer.buf);
	  return status;
	}

      map = 1;

      result->h_addrtype = AF_INET;
      result->h_length = INADDRSZ;
    }

  status = getanswer_r (host_buffer.buf, n, name, type, result, buffer, buflen, errnop, h_errnop, map, ttlp, canonp);
  if (host_buffer.buf != orig_host_buffer)
    free (host_buffer.buf);
  return status;
}
hidden_def (_nss_dns_gethostbyname3_r)


enum nss_status _nss_dns_gethostbyname2_r (const char *name, int af, struct hostent *result, char *buffer, size_t buflen, int *errnop, int *h_errnop)


{
  return _nss_dns_gethostbyname3_r (name, af, result, buffer, buflen, errnop, h_errnop, NULL, NULL);
}


enum nss_status _nss_dns_gethostbyname_r (const char *name, struct hostent *result, char *buffer, size_t buflen, int *errnop, int *h_errnop)


{
  enum nss_status status = NSS_STATUS_NOTFOUND;

  if (res_use_inet6 ())
    status = _nss_dns_gethostbyname3_r (name, AF_INET6, result, buffer, buflen, errnop, h_errnop, NULL, NULL);
  if (status == NSS_STATUS_NOTFOUND)
    status = _nss_dns_gethostbyname3_r (name, AF_INET, result, buffer, buflen, errnop, h_errnop, NULL, NULL);

  return status;
}


enum nss_status _nss_dns_gethostbyname4_r (const char *name, struct gaih_addrtuple **pat, char *buffer, size_t buflen, int *errnop, int *herrnop, int32_t *ttlp)


{
  if (__res_maybe_init (&_res, 0) == -1)
    return NSS_STATUS_UNAVAIL;

  
  if (strchr (name, '.') == NULL)
    {
      char *tmp = alloca (NS_MAXDNAME);
      const char *cp = res_hostalias (&_res, name, tmp, NS_MAXDNAME);
      if (cp != NULL)
	name = cp;
    }

  union {
    querybuf *buf;
    u_char *ptr;
  } host_buffer;
  querybuf *orig_host_buffer;
  host_buffer.buf = orig_host_buffer = (querybuf *) alloca (2048);
  u_char *ans2p = NULL;
  int nans2p = 0;
  int resplen2 = 0;
  int ans2p_malloced = 0;

  int olderr = errno;
  enum nss_status status;
  int n = __libc_res_nsearch (&_res, name, C_IN, T_UNSPEC, host_buffer.buf->buf, 2048, &host_buffer.ptr, &ans2p, &nans2p, &resplen2, &ans2p_malloced);

  if (n >= 0)
    {
      status = gaih_getanswer (host_buffer.buf, n, (const querybuf *) ans2p, resplen2, name, pat, buffer, buflen, errnop, herrnop, ttlp);

    }
  else {
      switch (errno)
	{
	case ESRCH:
	  status = NSS_STATUS_TRYAGAIN;
	  h_errno = TRY_AGAIN;
	  break;
	
	case EMFILE:
	case ENFILE:
	  h_errno = NETDB_INTERNAL;
	  
	case ECONNREFUSED:
	case ETIMEDOUT:
	  status = NSS_STATUS_UNAVAIL;
	  break;
	default:
	  status = NSS_STATUS_NOTFOUND;
	  break;
	}

      *herrnop = h_errno;
      if (h_errno == TRY_AGAIN)
	*errnop = EAGAIN;
      else __set_errno (olderr);
    }

  
  if (ans2p_malloced)
    free (ans2p);

  if (host_buffer.buf != orig_host_buffer)
    free (host_buffer.buf);

  return status;
}


extern enum nss_status _nss_dns_gethostbyaddr2_r (const void *addr, socklen_t len, int af, struct hostent *result, char *buffer, size_t buflen, int *errnop, int *h_errnop, int32_t *ttlp);




hidden_proto (_nss_dns_gethostbyaddr2_r)

enum nss_status _nss_dns_gethostbyaddr2_r (const void *addr, socklen_t len, int af, struct hostent *result, char *buffer, size_t buflen, int *errnop, int *h_errnop, int32_t *ttlp)


{
  static const u_char mapped[] = { 0,0, 0,0, 0,0, 0,0, 0,0, 0xff,0xff };
  static const u_char tunnelled[] = { 0,0, 0,0, 0,0, 0,0, 0,0, 0,0 };
  static const u_char v6local[] = { 0,0, 0,1 };
  const u_char *uaddr = (const u_char *)addr;
  struct host_data {
    char *aliases[MAX_NR_ALIASES];
    unsigned char host_addr[16];	
    char *h_addr_ptrs[MAX_NR_ADDRS + 1];
    char linebuffer[0];
  } *host_data = (struct host_data *) buffer;
  union {
    querybuf *buf;
    u_char *ptr;
  } host_buffer;
  querybuf *orig_host_buffer;
  char qbuf[MAXDNAME+1], *qp = NULL;
  size_t size;
  int n, status;
  int olderr = errno;

 uintptr_t pad = -(uintptr_t) buffer % __alignof__ (struct host_data);
 buffer += pad;
 buflen = buflen > pad ? buflen - pad : 0;

 if (__glibc_unlikely (buflen < sizeof (struct host_data)))
   {
     *errnop = ERANGE;
     *h_errnop = NETDB_INTERNAL;
     return NSS_STATUS_TRYAGAIN;
   }

 host_data = (struct host_data *) buffer;

  if (__res_maybe_init (&_res, 0) == -1)
    return NSS_STATUS_UNAVAIL;

  if (af == AF_INET6 && len == IN6ADDRSZ && (memcmp (uaddr, mapped, sizeof mapped) == 0 || (memcmp (uaddr, tunnelled, sizeof tunnelled) == 0 && memcmp (&uaddr[sizeof tunnelled], v6local, sizeof v6local))))


    {
      
      addr += sizeof mapped;
      uaddr += sizeof mapped;
      af = AF_INET;
      len = INADDRSZ;
    }

  switch (af)
    {
    case AF_INET:
      size = INADDRSZ;
      break;
    case AF_INET6:
      size = IN6ADDRSZ;
      break;
    default:
      *errnop = EAFNOSUPPORT;
      *h_errnop = NETDB_INTERNAL;
      return NSS_STATUS_UNAVAIL;
    }
  if (size > len)
    {
      *errnop = EAFNOSUPPORT;
      *h_errnop = NETDB_INTERNAL;
      return NSS_STATUS_UNAVAIL;
    }

  host_buffer.buf = orig_host_buffer = (querybuf *) alloca (1024);

  switch (af)
    {
    case AF_INET:
      sprintf (qbuf, "%u.%u.%u.%u.in-addr.arpa", (uaddr[3] & 0xff), (uaddr[2] & 0xff), (uaddr[1] & 0xff), (uaddr[0] & 0xff));
      break;
    case AF_INET6:
      qp = qbuf;
      for (n = IN6ADDRSZ - 1; n >= 0; n--)
	{
	  static const char nibblechar[16] = "0123456789abcdef";
	  *qp++ = nibblechar[uaddr[n] & 0xf];
	  *qp++ = '.';
	  *qp++ = nibblechar[(uaddr[n] >> 4) & 0xf];
	  *qp++ = '.';
	}
      strcpy(qp, "ip6.arpa");
      break;
    default:
      
      break;
    }

  n = __libc_res_nquery (&_res, qbuf, C_IN, T_PTR, host_buffer.buf->buf, 1024, &host_buffer.ptr, NULL, NULL, NULL, NULL);
  if (n < 0)
    {
      *h_errnop = h_errno;
      __set_errno (olderr);
      if (host_buffer.buf != orig_host_buffer)
	free (host_buffer.buf);
      return errno == ECONNREFUSED ? NSS_STATUS_UNAVAIL : NSS_STATUS_NOTFOUND;
    }

  status = getanswer_r (host_buffer.buf, n, qbuf, T_PTR, result, buffer, buflen, errnop, h_errnop, 0 , ttlp, NULL);
  if (host_buffer.buf != orig_host_buffer)
    free (host_buffer.buf);
  if (status != NSS_STATUS_SUCCESS)
    return status;

  result->h_addrtype = af;
  result->h_length = len;
  memcpy (host_data->host_addr, addr, len);
  host_data->h_addr_ptrs[0] = (char *) host_data->host_addr;
  host_data->h_addr_ptrs[1] = NULL;
  *h_errnop = NETDB_SUCCESS;
  return NSS_STATUS_SUCCESS;
}
hidden_def (_nss_dns_gethostbyaddr2_r)


enum nss_status _nss_dns_gethostbyaddr_r (const void *addr, socklen_t len, int af, struct hostent *result, char *buffer, size_t buflen, int *errnop, int *h_errnop)


{
  return _nss_dns_gethostbyaddr2_r (addr, len, af, result, buffer, buflen, errnop, h_errnop, NULL);
}

static void addrsort (char **ap, int num);

static void addrsort (char **ap, int num)
{
  int i, j;
  char **p;
  short aval[MAX_NR_ADDRS];
  int needsort = 0;

  p = ap;
  if (num > MAX_NR_ADDRS)
    num = MAX_NR_ADDRS;
  for (i = 0; i < num; i++, p++)
    {
      for (j = 0 ; (unsigned)j < _res.nsort; j++)
	if (_res.sort_list[j].addr.s_addr == (((struct in_addr *)(*p))->s_addr & _res.sort_list[j].mask))
	  break;
      aval[i] = j;
      if (needsort == 0 && i > 0 && j < aval[i-1])
	needsort = i;
    }
  if (!needsort)
    return;

  while (needsort++ < num)
    for (j = needsort - 2; j >= 0; j--)
      if (aval[j] > aval[j+1])
	{
	  char *hp;

	  i = aval[j];
	  aval[j] = aval[j+1];
	  aval[j+1] = i;

	  hp = ap[j];
	  ap[j] = ap[j+1];
	  ap[j+1] = hp;
	}
      else break;
}

static enum nss_status getanswer_r (const querybuf *answer, int anslen, const char *qname, int qtype, struct hostent *result, char *buffer, size_t buflen, int *errnop, int *h_errnop, int map, int32_t *ttlp, char **canonp)


{
  struct host_data {
    char *aliases[MAX_NR_ALIASES];
    unsigned char host_addr[16];	
    char *h_addr_ptrs[0];
  } *host_data;
  int linebuflen;
  const HEADER *hp;
  const u_char *end_of_message, *cp;
  int n, ancount, qdcount;
  int haveanswer, had_error;
  char *bp, **ap, **hap;
  char tbuf[MAXDNAME];
  const char *tname;
  int (*name_ok) (const char *);
  u_char packtmp[NS_MAXCDNAME];
  int have_to_map = 0;
  uintptr_t pad = -(uintptr_t) buffer % __alignof__ (struct host_data);
  buffer += pad;
  buflen = buflen > pad ? buflen - pad : 0;
  if (__glibc_unlikely (buflen < sizeof (struct host_data)))
    {
      
    too_small:
      *errnop = ERANGE;
      *h_errnop = NETDB_INTERNAL;
      return NSS_STATUS_TRYAGAIN;
    }
  host_data = (struct host_data *) buffer;
  linebuflen = buflen - sizeof (struct host_data);
  if (buflen - sizeof (struct host_data) != linebuflen)
    linebuflen = INT_MAX;

  tname = qname;
  result->h_name = NULL;
  end_of_message = answer->buf + anslen;
  switch (qtype)
    {
    case T_A:
    case T_AAAA:
      name_ok = res_hnok;
      break;
    case T_PTR:
      name_ok = res_dnok;
      break;
    default:
      *errnop = ENOENT;
      return NSS_STATUS_UNAVAIL;  
    }

  
  hp = &answer->hdr;
  ancount = ntohs (hp->ancount);
  qdcount = ntohs (hp->qdcount);
  cp = answer->buf + HFIXEDSZ;
  if (__builtin_expect (qdcount, 1) != 1)
    {
      *h_errnop = NO_RECOVERY;
      return NSS_STATUS_UNAVAIL;
    }
  if (sizeof (struct host_data) + (ancount + 1) * sizeof (char *) >= buflen)
    goto too_small;
  bp = (char *) &host_data->h_addr_ptrs[ancount + 1];
  linebuflen -= (ancount + 1) * sizeof (char *);

  n = __ns_name_unpack (answer->buf, end_of_message, cp, packtmp, sizeof packtmp);
  if (n != -1 && __ns_name_ntop (packtmp, bp, linebuflen) == -1)
    {
      if (__builtin_expect (errno, 0) == EMSGSIZE)
	goto too_small;

      n = -1;
    }

  if (n > 0 && bp[0] == '.')
    bp[0] = '\0';

  if (__builtin_expect (n < 0 || ((*name_ok) (bp) == 0 && (errno = EBADMSG)), 0))
    {
      *errnop = errno;
      *h_errnop = NO_RECOVERY;
      return NSS_STATUS_UNAVAIL;
    }
  cp += n + QFIXEDSZ;

  if (qtype == T_A || qtype == T_AAAA)
    {
      
      n = strlen (bp) + 1;             
      if (n >= MAXHOSTNAMELEN)
	{
	  *h_errnop = NO_RECOVERY;
	  *errnop = ENOENT;
	  return NSS_STATUS_TRYAGAIN;
	}
      result->h_name = bp;
      bp += n;
      linebuflen -= n;
      if (linebuflen < 0)
	goto too_small;
      
      qname = result->h_name;
    }

  ap = host_data->aliases;
  *ap = NULL;
  result->h_aliases = host_data->aliases;
  hap = host_data->h_addr_ptrs;
  *hap = NULL;
  result->h_addr_list = host_data->h_addr_ptrs;
  haveanswer = 0;
  had_error = 0;

  while (ancount-- > 0 && cp < end_of_message && had_error == 0)
    {
      int type, class;

      n = __ns_name_unpack (answer->buf, end_of_message, cp, packtmp, sizeof packtmp);
      if (n != -1 && __ns_name_ntop (packtmp, bp, linebuflen) == -1)
	{
	  if (__builtin_expect (errno, 0) == EMSGSIZE)
	    goto too_small;

	  n = -1;
	}

      if (__glibc_unlikely (n < 0 || (*name_ok) (bp) == 0))
	{
	  ++had_error;
	  continue;
	}
      cp += n;				

      if (__glibc_unlikely (cp + 10 > end_of_message))
	{
	  ++had_error;
	  continue;
	}

      type = __ns_get16 (cp);
      cp += INT16SZ;			
      class = __ns_get16 (cp);
      cp += INT16SZ;			
      int32_t ttl = __ns_get32 (cp);
      cp += INT32SZ;			
      n = __ns_get16 (cp);
      cp += INT16SZ;			

      if (end_of_message - cp < n)
	{
	  
	  ++had_error;
	  continue;
	}

      if (__glibc_unlikely (class != C_IN))
	{
	  
	  cp += n;
	  continue;			
	}

      if ((qtype == T_A || qtype == T_AAAA) && type == T_CNAME)
	{
	  
	  if (ttlp != NULL && ttl < *ttlp)
	      *ttlp = ttl;

	  if (ap >= &host_data->aliases[MAX_NR_ALIASES - 1])
	    continue;
	  n = dn_expand (answer->buf, end_of_message, cp, tbuf, sizeof tbuf);
	  if (__glibc_unlikely (n < 0 || (*name_ok) (tbuf) == 0))
	    {
	      ++had_error;
	      continue;
	    }
	  cp += n;
	  
	  *ap++ = bp;
	  n = strlen (bp) + 1;		
	  if (__builtin_expect (n, 0) >= MAXHOSTNAMELEN)
	    {
	      ++had_error;
	      continue;
	    }
	  bp += n;
	  linebuflen -= n;
	  
	  n = strlen (tbuf) + 1;	
	  if (__glibc_unlikely (n > linebuflen))
	    goto too_small;
	  if (__builtin_expect (n, 0) >= MAXHOSTNAMELEN)
	    {
	      ++had_error;
	      continue;
	    }
	  result->h_name = bp;
	  bp = __mempcpy (bp, tbuf, n);	
	  linebuflen -= n;
	  continue;
	}

      if (qtype == T_PTR && type == T_CNAME)
	{
	  
	  if (ttlp != NULL && ttl < *ttlp)
	      *ttlp = ttl;

	  n = dn_expand (answer->buf, end_of_message, cp, tbuf, sizeof tbuf);
	  if (__glibc_unlikely (n < 0 || res_dnok (tbuf) == 0))
	    {
	      ++had_error;
	      continue;
	    }
	  cp += n;
	  
	  n = strlen (tbuf) + 1;   
	  if (__glibc_unlikely (n > linebuflen))
	    goto too_small;
	  if (__builtin_expect (n, 0) >= MAXHOSTNAMELEN)
	    {
	      ++had_error;
	      continue;
	    }
	  tname = bp;
	  bp = __mempcpy (bp, tbuf, n);	
	  linebuflen -= n;
	  continue;
	}

      if (type == T_A && qtype == T_AAAA && map)
	have_to_map = 1;
      else if (__glibc_unlikely (type != qtype))
	{
	  cp += n;
	  continue;			
	}

      switch (type)
	{
	case T_PTR:
	  if (__glibc_unlikely (strcasecmp (tname, bp) != 0))
	    {
	      cp += n;
	      continue;			
	    }

	  n = __ns_name_unpack (answer->buf, end_of_message, cp, packtmp, sizeof packtmp);
	  if (n != -1 && __ns_name_ntop (packtmp, bp, linebuflen) == -1)
	    {
	      if (__builtin_expect (errno, 0) == EMSGSIZE)
		goto too_small;

	      n = -1;
	    }

	  if (__glibc_unlikely (n < 0 || res_hnok (bp) == 0))
	    {
	      ++had_error;
	      break;
	    }
	  if (ttlp != NULL && ttl < *ttlp)
	      *ttlp = ttl;
	  
	  result->h_name = bp;
	  if (have_to_map)
	    {
	      n = strlen (bp) + 1;	
	      if (__glibc_unlikely (n >= MAXHOSTNAMELEN))
		{
		  ++had_error;
		  break;
		}
	      bp += n;
	      linebuflen -= n;
	      if (map_v4v6_hostent (result, &bp, &linebuflen))
		goto too_small;
	    }
	  *h_errnop = NETDB_SUCCESS;
	  return NSS_STATUS_SUCCESS;
	case T_A:
	case T_AAAA:
	  if (__builtin_expect (strcasecmp (result->h_name, bp), 0) != 0)
	    {
	      cp += n;
	      continue;			
	    }

	  
	  if (n != rrtype_to_rdata_length (type))
	    {
	      ++had_error;
	      break;
	    }

	  
	  if (n != result->h_length)
	    {
	      cp += n;
	      continue;
	    }
	  if (!haveanswer)
	    {
	      int nn;

	      
	      if (ttlp != NULL && ttl < *ttlp)
		*ttlp = ttl;
	      if (canonp != NULL)
		*canonp = bp;
	      result->h_name = bp;
	      nn = strlen (bp) + 1;	
	      bp += nn;
	      linebuflen -= nn;
	    }

	  linebuflen -= sizeof (align) - ((u_long) bp % sizeof (align));
	  bp += sizeof (align) - ((u_long) bp % sizeof (align));

	  if (__glibc_unlikely (n > linebuflen))
	    goto too_small;
	  bp = __mempcpy (*hap++ = bp, cp, n);
	  cp += n;
	  linebuflen -= n;
	  break;
	default:
	  abort ();
	}
      if (had_error == 0)
	++haveanswer;
    }

  if (haveanswer > 0)
    {
      *ap = NULL;
      *hap = NULL;
      
      if (_res.nsort && haveanswer > 1 && qtype == T_A)
	addrsort (host_data->h_addr_ptrs, haveanswer);

      if (result->h_name == NULL)
	{
	  n = strlen (qname) + 1;	
	  if (n > linebuflen)
	    goto too_small;
	  if (n >= MAXHOSTNAMELEN)
	    goto no_recovery;
	  result->h_name = bp;
	  bp = __mempcpy (bp, qname, n);	
	  linebuflen -= n;
	}

      if (have_to_map)
	if (map_v4v6_hostent (result, &bp, &linebuflen))
	  goto too_small;
      *h_errnop = NETDB_SUCCESS;
      return NSS_STATUS_SUCCESS;
    }
 no_recovery:
  *h_errnop = NO_RECOVERY;
  *errnop = ENOENT;
  
  return ((qtype == T_A || qtype == T_AAAA) && ap != host_data->aliases ? NSS_STATUS_NOTFOUND : NSS_STATUS_TRYAGAIN);
}


static enum nss_status gaih_getanswer_slice (const querybuf *answer, int anslen, const char *qname, struct gaih_addrtuple ***patp, char **bufferp, size_t *buflenp, int *errnop, int *h_errnop, int32_t *ttlp, int *firstp)



{
  char *buffer = *bufferp;
  size_t buflen = *buflenp;

  struct gaih_addrtuple **pat = *patp;
  const HEADER *hp = &answer->hdr;
  int ancount = ntohs (hp->ancount);
  int qdcount = ntohs (hp->qdcount);
  const u_char *cp = answer->buf + HFIXEDSZ;
  const u_char *end_of_message = answer->buf + anslen;
  if (__glibc_unlikely (qdcount != 1))
    {
      *h_errnop = NO_RECOVERY;
      return NSS_STATUS_UNAVAIL;
    }

  u_char packtmp[NS_MAXCDNAME];
  int n = __ns_name_unpack (answer->buf, end_of_message, cp, packtmp, sizeof packtmp);
  
  if (n != -1 && __ns_name_ntop (packtmp, buffer, buflen) == -1)
    {
      if (__builtin_expect (errno, 0) == EMSGSIZE)
	{
	too_small:
	  *errnop = ERANGE;
	  *h_errnop = NETDB_INTERNAL;
	  return NSS_STATUS_TRYAGAIN;
	}

      n = -1;
    }

  if (__builtin_expect (n < 0 || (res_hnok (buffer) == 0 && (errno = EBADMSG)), 0))
    {
      *errnop = errno;
      *h_errnop = NO_RECOVERY;
      return NSS_STATUS_UNAVAIL;
    }
  cp += n + QFIXEDSZ;

  int haveanswer = 0;
  int had_error = 0;
  char *canon = NULL;
  char *h_name = NULL;
  int h_namelen = 0;

  if (ancount == 0)
    {
      *h_errnop = HOST_NOT_FOUND;
      return NSS_STATUS_NOTFOUND;
    }

  while (ancount-- > 0 && cp < end_of_message && had_error == 0)
    {
      n = __ns_name_unpack (answer->buf, end_of_message, cp, packtmp, sizeof packtmp);
      if (n != -1 && (h_namelen = __ns_name_ntop (packtmp, buffer, buflen)) == -1)
	{
	  if (__builtin_expect (errno, 0) == EMSGSIZE)
	    goto too_small;

	  n = -1;
	}
      if (__glibc_unlikely (n < 0 || res_hnok (buffer) == 0))
	{
	  ++had_error;
	  continue;
	}
      if (*firstp && canon == NULL)
	{
	  h_name = buffer;
	  buffer += h_namelen;
	  buflen -= h_namelen;
	}

      cp += n;				

      if (__glibc_unlikely (cp + 10 > end_of_message))
	{
	  ++had_error;
	  continue;
	}

      int type = __ns_get16 (cp);
      cp += INT16SZ;			
      int class = __ns_get16 (cp);
      cp += INT16SZ;			
      int32_t ttl = __ns_get32 (cp);
      cp += INT32SZ;			
      n = __ns_get16 (cp);
      cp += INT16SZ;			

      if (end_of_message - cp < n)
	{
	  
	  ++had_error;
	  continue;
	}

      if (class != C_IN)
	{
	  cp += n;
	  continue;
	}

      if (type == T_CNAME)
	{
	  char tbuf[MAXDNAME];

	  
	  if (ttlp != NULL && ttl < *ttlp)
	      *ttlp = ttl;

	  n = dn_expand (answer->buf, end_of_message, cp, tbuf, sizeof tbuf);
	  if (__glibc_unlikely (n < 0 || res_hnok (tbuf) == 0))
	    {
	      ++had_error;
	      continue;
	    }
	  cp += n;

	  if (*firstp)
	    {
	      
	      if (h_name + h_namelen == buffer)
		{
		  buffer = h_name;
		  buflen += h_namelen;
		}

	      n = strlen (tbuf) + 1;
	      if (__glibc_unlikely (n > buflen))
		goto too_small;
	      if (__glibc_unlikely (n >= MAXHOSTNAMELEN))
		{
		  ++had_error;
		  continue;
		}

	      canon = buffer;
	      buffer = __mempcpy (buffer, tbuf, n);
	      buflen -= n;
	      h_namelen = 0;
	    }
	  continue;
	}

      
      if (type == T_A || type == T_AAAA)
	{
	  if (n != rrtype_to_rdata_length (type))
	    {
	      ++had_error;
	      continue;
	    }
	}
      else {
	  
	  cp += n;
	  continue;
	}

      assert (type == T_A || type == T_AAAA);
      if (*pat == NULL)
	{
	  uintptr_t pad = (-(uintptr_t) buffer % __alignof__ (struct gaih_addrtuple));
	  buffer += pad;
	  buflen = buflen > pad ? buflen - pad : 0;

	  if (__builtin_expect (buflen < sizeof (struct gaih_addrtuple), 0))
	    goto too_small;

	  *pat = (struct gaih_addrtuple *) buffer;
	  buffer += sizeof (struct gaih_addrtuple);
	  buflen -= sizeof (struct gaih_addrtuple);
	}

      (*pat)->name = NULL;
      (*pat)->next = NULL;

      if (*firstp)
	{
	  
	  if (ttlp != NULL && ttl < *ttlp)
	    *ttlp = ttl;

	  (*pat)->name = canon ?: h_name;

	  *firstp = 0;
	}

      (*pat)->family = type == T_A ? AF_INET : AF_INET6;
      memcpy ((*pat)->addr, cp, n);
      cp += n;
      (*pat)->scopeid = 0;

      pat = &((*pat)->next);

      haveanswer = 1;
    }

  if (haveanswer)
    {
      *patp = pat;
      *bufferp = buffer;
      *buflenp = buflen;

      *h_errnop = NETDB_SUCCESS;
      return NSS_STATUS_SUCCESS;
    }

  
  if (canon != NULL)
    {
      *h_errnop = HOST_NOT_FOUND;
      return NSS_STATUS_NOTFOUND;
    }

  *h_errnop = NETDB_INTERNAL;
  return NSS_STATUS_TRYAGAIN;
}


static enum nss_status gaih_getanswer (const querybuf *answer1, int anslen1, const querybuf *answer2, int anslen2, const char *qname, struct gaih_addrtuple **pat, char *buffer, size_t buflen, int *errnop, int *h_errnop, int32_t *ttlp)



{
  int first = 1;

  enum nss_status status = NSS_STATUS_NOTFOUND;

  

  if (anslen1 > 0)
    status = gaih_getanswer_slice(answer1, anslen1, qname, &pat, &buffer, &buflen, errnop, h_errnop, ttlp, &first);



  if ((status == NSS_STATUS_SUCCESS || status == NSS_STATUS_NOTFOUND || (status == NSS_STATUS_TRYAGAIN  && (*errnop != ERANGE || *h_errnop == NO_RECOVERY)))


      && answer2 != NULL && anslen2 > 0)
    {
      enum nss_status status2 = gaih_getanswer_slice(answer2, anslen2, qname, &pat, &buffer, &buflen, errnop, h_errnop, ttlp, &first);


      
      if (status != NSS_STATUS_SUCCESS && status2 != NSS_STATUS_NOTFOUND)
	status = status2;
      
      if (status == NSS_STATUS_SUCCESS && (status2 == NSS_STATUS_TRYAGAIN && *errnop == ERANGE && *h_errnop != NO_RECOVERY))

	status = NSS_STATUS_TRYAGAIN;
    }

  return status;
}
