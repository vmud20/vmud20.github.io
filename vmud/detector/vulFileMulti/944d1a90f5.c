






























static int __libc_res_nquerydomain(res_state statp, const char *name, const char *domain, int class, int type, u_char *answer, int anslen, u_char **answerp, u_char **answerp2, int *nanswerp2, int *resplen2, int *answerp2_malloced);





int __libc_res_nquery(res_state statp, const char *name, int class, int type, u_char *answer, int anslen, u_char **answerp, u_char **answerp2, int *nanswerp2, int *resplen2, int *answerp2_malloced)









{
	HEADER *hp = (HEADER *) answer;
	HEADER *hp2;
	int n, use_malloc = 0;
	u_int oflags = statp->_flags;

	size_t bufsize = (type == T_UNSPEC ? 2 : 1) * QUERYSIZE;
	u_char *buf = alloca (bufsize);
	u_char *query1 = buf;
	int nquery1 = -1;
	u_char *query2 = NULL;
	int nquery2 = 0;

 again:
	hp->rcode = NOERROR;	


	if (statp->options & RES_DEBUG)
		printf(";; res_query(%s, %d, %d)\n", name, class, type);


	if (type == T_UNSPEC)
	  {
	    n = res_nmkquery(statp, QUERY, name, class, T_A, NULL, 0, NULL, query1, bufsize);
	    if (n > 0)
	      {
		if ((oflags & RES_F_EDNS0ERR) == 0 && (statp->options & (RES_USE_EDNS0|RES_USE_DNSSEC)) != 0)
		  {
		    n = __res_nopt(statp, n, query1, bufsize, anslen / 2);
		    if (n < 0)
		      goto unspec_nomem;
		  }

		nquery1 = n;
		
		int npad = ((nquery1 + __alignof__ (HEADER) - 1)
			    & ~(__alignof__ (HEADER) - 1)) - nquery1;
		if (n > bufsize - npad)
		  {
		    n = -1;
		    goto unspec_nomem;
		  }
		int nused = n + npad;
		query2 = buf + nused;
		n = res_nmkquery(statp, QUERY, name, class, T_AAAA, NULL, 0, NULL, query2, bufsize - nused);
		if (n > 0 && (oflags & RES_F_EDNS0ERR) == 0 && (statp->options & (RES_USE_EDNS0|RES_USE_DNSSEC)) != 0)

		  n = __res_nopt(statp, n, query2, bufsize - nused - n, anslen / 2);
		nquery2 = n;
	      }

	  unspec_nomem:;
	  }
	else {
	    n = res_nmkquery(statp, QUERY, name, class, type, NULL, 0, NULL, query1, bufsize);

	    if (n > 0 && (oflags & RES_F_EDNS0ERR) == 0 && (statp->options & (RES_USE_EDNS0|RES_USE_DNSSEC)) != 0)

	      n = __res_nopt(statp, n, query1, bufsize, anslen);

	    nquery1 = n;
	  }

	if (__builtin_expect (n <= 0, 0) && !use_malloc) {
		
		bufsize = (type == T_UNSPEC ? 2 : 1) * MAXPACKET;
		buf = malloc (bufsize);
		if (buf != NULL) {
			query1 = buf;
			use_malloc = 1;
			goto again;
		}
	}
	if (__glibc_unlikely (n <= 0))       {
		
		if ((statp->options & (RES_USE_EDNS0|RES_USE_DNSSEC)) != 0 && ((oflags ^ statp->_flags) & RES_F_EDNS0ERR) != 0) {
			statp->_flags |= RES_F_EDNS0ERR;

			if (statp->options & RES_DEBUG)
				printf(";; res_nquery: retry without EDNS0\n");

			goto again;
		}

		if (statp->options & RES_DEBUG)
			printf(";; res_query: mkquery failed\n");

		RES_SET_H_ERRNO(statp, NO_RECOVERY);
		if (use_malloc)
			free (buf);
		return (n);
	}
	assert (answerp == NULL || (void *) *answerp == (void *) answer);
	n = __libc_res_nsend(statp, query1, nquery1, query2, nquery2, answer, anslen, answerp, answerp2, nanswerp2, resplen2, answerp2_malloced);

	if (use_malloc)
		free (buf);
	if (n < 0) {

		if (statp->options & RES_DEBUG)
			printf(";; res_query: send error\n");

		RES_SET_H_ERRNO(statp, TRY_AGAIN);
		return (n);
	}

	if (answerp != NULL)
	  
	  hp = (HEADER *) *answerp;

	
	if (answerp2 == NULL || *resplen2 < (int) sizeof (HEADER))
	  {
	    hp2 = hp;
	  }
	else {
	    hp2 = (HEADER *) *answerp2;
	    if (n < (int) sizeof (HEADER))
	      {
	        hp = hp2;
	      }
	  }

	
	assert((hp != NULL) && (hp2 != NULL));

	if ((hp->rcode != NOERROR || ntohs(hp->ancount) == 0)
	    && (hp2->rcode != NOERROR || ntohs(hp2->ancount) == 0)) {

		if (statp->options & RES_DEBUG) {
			printf(";; rcode = %d, ancount=%d\n", hp->rcode, ntohs(hp->ancount));
			if (hp != hp2)
			  printf(";; rcode2 = %d, ancount2=%d\n", hp2->rcode, ntohs(hp2->ancount));
		}

		switch (hp->rcode == NOERROR ? hp2->rcode : hp->rcode) {
		case NXDOMAIN:
			if ((hp->rcode == NOERROR && ntohs (hp->ancount) != 0)
			    || (hp2->rcode == NOERROR && ntohs (hp2->ancount) != 0))
				goto success;
			RES_SET_H_ERRNO(statp, HOST_NOT_FOUND);
			break;
		case SERVFAIL:
			RES_SET_H_ERRNO(statp, TRY_AGAIN);
			break;
		case NOERROR:
			if (ntohs (hp->ancount) != 0 || ntohs (hp2->ancount) != 0)
				goto success;
			RES_SET_H_ERRNO(statp, NO_DATA);
			break;
		case FORMERR:
		case NOTIMP:
			
			if ((hp->rcode == NOERROR && ntohs (hp->ancount) != 0)
			    || (hp2->rcode == NOERROR && ntohs (hp2->ancount) != 0))
				goto success;
			
		case REFUSED:
		default:
			RES_SET_H_ERRNO(statp, NO_RECOVERY);
			break;
		}
		return (-1);
	}
 success:
	return (n);
}
libresolv_hidden_def (__libc_res_nquery)

int res_nquery(res_state statp, const char *name, int class, int type, u_char *answer, int anslen)




{
	return __libc_res_nquery(statp, name, class, type, answer, anslen, NULL, NULL, NULL, NULL, NULL);
}
libresolv_hidden_def (res_nquery)


int __libc_res_nsearch(res_state statp, const char *name, int class, int type, u_char *answer, int anslen, u_char **answerp, u_char **answerp2, int *nanswerp2, int *resplen2, int *answerp2_malloced)









{
	const char *cp, * const *domain;
	HEADER *hp = (HEADER *) answer;
	char tmp[NS_MAXDNAME];
	u_int dots;
	int trailing_dot, ret, saved_herrno;
	int got_nodata = 0, got_servfail = 0, root_on_list = 0;
	int tried_as_is = 0;
	int searched = 0;

	__set_errno (0);
	RES_SET_H_ERRNO(statp, HOST_NOT_FOUND);  

	dots = 0;
	for (cp = name; *cp != '\0'; cp++)
		dots += (*cp == '.');
	trailing_dot = 0;
	if (cp > name && *--cp == '.')
		trailing_dot++;

	
	if (!dots && (cp = res_hostalias(statp, name, tmp, sizeof tmp))!= NULL)
		return (__libc_res_nquery(statp, cp, class, type, answer, anslen, answerp, answerp2, nanswerp2, resplen2, answerp2_malloced));



	if (statp->options & RES_DEBUG)
		printf("dots=%d, statp->ndots=%d, trailing_dot=%d, name=%s\n", (int)dots,(int)statp->ndots,(int)trailing_dot,name);


	
	saved_herrno = -1;
	if (dots >= statp->ndots || trailing_dot) {
		ret = __libc_res_nquerydomain(statp, name, NULL, class, type, answer, anslen, answerp, answerp2, nanswerp2, resplen2, answerp2_malloced);


		if (ret > 0 || trailing_dot  || (ret == 0 && resplen2 != NULL && *resplen2 > 0))

			return (ret);
		saved_herrno = h_errno;
		tried_as_is++;
		if (answerp && *answerp != answer) {
			answer = *answerp;
			anslen = MAXPACKET;
		}
		if (answerp2 && *answerp2_malloced)
		  {
		    free (*answerp2);
		    *answerp2 = NULL;
		    *nanswerp2 = 0;
		    *answerp2_malloced = 0;
		  }
	}

	
	if ((!dots && (statp->options & RES_DEFNAMES) != 0) || (dots && !trailing_dot && (statp->options & RES_DNSRCH) != 0)) {
		int done = 0;

		for (domain = (const char * const *)statp->dnsrch;
		     *domain && !done;
		     domain++) {
			const char *dname = domain[0];
			searched = 1;

			
			if (dname[0] == '.')
				dname++;
			if (dname[0] == '\0')
				root_on_list++;

			ret = __libc_res_nquerydomain(statp, name, dname, class, type, answer, anslen, answerp, answerp2, nanswerp2, resplen2, answerp2_malloced);



			if (ret > 0 || (ret == 0 && resplen2 != NULL && *resplen2 > 0))
				return (ret);

			if (answerp && *answerp != answer) {
				answer = *answerp;
				anslen = MAXPACKET;
			}
			if (answerp2 && *answerp2_malloced)
			  {
			    free (*answerp2);
			    *answerp2 = NULL;
			    *nanswerp2 = 0;
			    *answerp2_malloced = 0;
			  }

			
			if (errno == ECONNREFUSED) {
				RES_SET_H_ERRNO(statp, TRY_AGAIN);
				return (-1);
			}

			switch (statp->res_h_errno) {
			case NO_DATA:
				got_nodata++;
				
			case HOST_NOT_FOUND:
				
				break;
			case TRY_AGAIN:
				if (hp->rcode == SERVFAIL) {
					
					got_servfail++;
					break;
				}
				
			default:
				
				done++;
			}

			
			if ((statp->options & RES_DNSRCH) == 0)
				done++;
		}
	}

	
	if ((dots || !searched || (statp->options & RES_NOTLDQUERY) == 0)
	    && !(tried_as_is || root_on_list)) {
		ret = __libc_res_nquerydomain(statp, name, NULL, class, type, answer, anslen, answerp, answerp2, nanswerp2, resplen2, answerp2_malloced);


		if (ret > 0 || (ret == 0 && resplen2 != NULL && *resplen2 > 0))
			return (ret);
	}

	
	if (answerp2 && *answerp2_malloced)
	  {
	    free (*answerp2);
	    *answerp2 = NULL;
	    *nanswerp2 = 0;
	    *answerp2_malloced = 0;
	  }
	if (saved_herrno != -1)
		RES_SET_H_ERRNO(statp, saved_herrno);
	else if (got_nodata)
		RES_SET_H_ERRNO(statp, NO_DATA);
	else if (got_servfail)
		RES_SET_H_ERRNO(statp, TRY_AGAIN);
	return (-1);
}
libresolv_hidden_def (__libc_res_nsearch)

int res_nsearch(res_state statp, const char *name, int class, int type, u_char *answer, int anslen)




{
	return __libc_res_nsearch(statp, name, class, type, answer, anslen, NULL, NULL, NULL, NULL, NULL);
}
libresolv_hidden_def (res_nsearch)


static int __libc_res_nquerydomain(res_state statp, const char *name, const char *domain, int class, int type, u_char *answer, int anslen, u_char **answerp, u_char **answerp2, int *nanswerp2, int *resplen2, int *answerp2_malloced)










{
	char nbuf[MAXDNAME];
	const char *longname = nbuf;
	size_t n, d;


	if (statp->options & RES_DEBUG)
		printf(";; res_nquerydomain(%s, %s, %d, %d)\n", name, domain?domain:"<Nil>", class, type);

	if (domain == NULL) {
		n = strlen(name);

		
		n--;
		if (n >= MAXDNAME - 1) {
			RES_SET_H_ERRNO(statp, NO_RECOVERY);
			return (-1);
		}
		longname = name;
	} else {
		n = strlen(name);
		d = strlen(domain);
		if (n + d + 1 >= MAXDNAME) {
			RES_SET_H_ERRNO(statp, NO_RECOVERY);
			return (-1);
		}
		sprintf(nbuf, "%s.%s", name, domain);
	}
	return (__libc_res_nquery(statp, longname, class, type, answer, anslen, answerp, answerp2, nanswerp2, resplen2, answerp2_malloced));

}

int res_nquerydomain(res_state statp, const char *name, const char *domain, int class, int type, u_char *answer, int anslen)





{
	return __libc_res_nquerydomain(statp, name, domain, class, type, answer, anslen, NULL, NULL, NULL, NULL, NULL);

}
libresolv_hidden_def (res_nquerydomain)

const char * res_hostalias(const res_state statp, const char *name, char *dst, size_t siz) {
	char *file, *cp1, *cp2;
	char buf[BUFSIZ];
	FILE *fp;

	if (statp->options & RES_NOALIASES)
		return (NULL);
	file = getenv("HOSTALIASES");
	if (file == NULL || (fp = fopen(file, "rce")) == NULL)
		return (NULL);
	setbuf(fp, NULL);
	buf[sizeof(buf) - 1] = '\0';
	while (fgets(buf, sizeof(buf), fp)) {
		for (cp1 = buf; *cp1 && !isspace(*cp1); ++cp1)
			;
		if (!*cp1)
			break;
		*cp1 = '\0';
		if (ns_samename(buf, name) == 1) {
			while (isspace(*++cp1))
				;
			if (!*cp1)
				break;
			for (cp2 = cp1 + 1; *cp2 && !isspace(*cp2); ++cp2)
				;
			*cp2 = '\0';
			strncpy(dst, cp1, siz - 1);
			dst[siz - 1] = '\0';
			fclose(fp);
			return (dst);
		}
	}
	fclose(fp);
	return (NULL);
}
libresolv_hidden_def (res_hostalias)
