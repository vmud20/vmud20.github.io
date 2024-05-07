

























int res_nmkquery(res_state statp, int op, const char *dname, int class, int type, const u_char *data, int datalen, const u_char *newrr_in, u_char *buf, int buflen)








{
	HEADER *hp;
	u_char *cp;
	int n;
	u_char *dnptrs[20], **dpp, **lastdnptr;


	if (statp->options & RES_DEBUG)
		printf(";; res_nmkquery(%s, %s, %s, %s)\n", _res_opcodes[op], dname, p_class(class), p_type(type));

	
	if ((buf == NULL) || (buflen < HFIXEDSZ))
		return (-1);
	memset(buf, 0, HFIXEDSZ);
	hp = (HEADER *) buf;
	
	int randombits;
	do {

	    RANDOM_BITS (randombits);

	    struct timeval tv;
	    __gettimeofday (&tv, NULL);
	    randombits = (tv.tv_sec << 8) ^ tv.tv_usec;

	  }
	while ((randombits & 0xffff) == 0);
	statp->id = (statp->id + randombits) & 0xffff;
	hp->id = statp->id;
	hp->opcode = op;
	hp->rd = (statp->options & RES_RECURSE) != 0;
	hp->rcode = NOERROR;
	cp = buf + HFIXEDSZ;
	buflen -= HFIXEDSZ;
	dpp = dnptrs;
	*dpp++ = buf;
	*dpp++ = NULL;
	lastdnptr = dnptrs + sizeof dnptrs / sizeof dnptrs[0];
	
	switch (op) {
	case NS_NOTIFY_OP:
		if ((buflen -= QFIXEDSZ + (data == NULL ? 0 : RRFIXEDSZ)) < 0)
			return (-1);
		goto compose;

	case QUERY:
		if ((buflen -= QFIXEDSZ) < 0)
			return (-1);
	compose:
		n = ns_name_compress(dname, cp, buflen, (const u_char **) dnptrs, (const u_char **) lastdnptr);

		if (n < 0)
			return (-1);
		cp += n;
		buflen -= n;
		NS_PUT16 (type, cp);
		NS_PUT16 (class, cp);
		hp->qdcount = htons(1);
		if (op == QUERY || data == NULL)
			break;
		
		n = ns_name_compress((char *)data, cp, buflen, (const u_char **) dnptrs, (const u_char **) lastdnptr);

		if (__glibc_unlikely (n < 0))
			return (-1);
		cp += n;
		buflen -= n;
		NS_PUT16 (T_NULL, cp);
		NS_PUT16 (class, cp);
		NS_PUT32 (0, cp);
		NS_PUT16 (0, cp);
		hp->arcount = htons(1);
		break;

	case IQUERY:
		
		if (__glibc_unlikely (buflen < 1 + RRFIXEDSZ + datalen))
			return (-1);
		*cp++ = '\0';	
		NS_PUT16 (type, cp);
		NS_PUT16 (class, cp);
		NS_PUT32 (0, cp);
		NS_PUT16 (datalen, cp);
		if (datalen) {
			memcpy(cp, data, datalen);
			cp += datalen;
		}
		hp->ancount = htons(1);
		break;

	default:
		return (-1);
	}
	return (cp - buf);
}
libresolv_hidden_def (res_nmkquery)







int __res_nopt(res_state statp, int n0, u_char *buf, int buflen, int anslen)




{
	u_int16_t flags = 0;


	if ((statp->options & RES_DEBUG) != 0U)
		printf(";; res_nopt()\n");


	HEADER *hp = (HEADER *) buf;
	u_char *cp = buf + n0;
	u_char *ep = buf + buflen;

	if ((ep - cp) < 1 + RRFIXEDSZ)
		return -1;

	*cp++ = 0;	

	NS_PUT16(T_OPT, cp);	
	NS_PUT16(MIN(anslen, 0xffff), cp);	
	*cp++ = NOERROR;	
	*cp++ = 0;		

	if (statp->options & RES_USE_DNSSEC) {

		if (statp->options & RES_DEBUG)
			printf(";; res_opt()... ENDS0 DNSSEC\n");

		flags |= NS_OPT_DNSSEC_OK;
	}

	NS_PUT16(flags, cp);
	NS_PUT16(0, cp);	
	hp->arcount = htons(ntohs(hp->arcount) + 1);

	return cp - buf;
}
libresolv_hidden_def (__res_nopt)
