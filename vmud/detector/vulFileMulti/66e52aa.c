





static int write_dname (u_char *, u_char *, uint16_t *, int, u_char *, u_char *);
static int dname_copy (u_char *, u_char *, int);
static u_char *dname_redirect (u_char *, u_char *);
static u_char *mesg_read_sec (G_List *, u_char *, int, u_char *, int);

uint16_t mesg_id (void) {
	static uint16_t id = 0;

	if (!id) {
		srandom (time (NULL));
		id = random ();
	}
	id++;

	if (T.debug > 4)
		syslog (LOG_DEBUG, "mesg_id() = %d", id);
	return id;
}

int mesg_make_query (u_char *qname, uint16_t qtype, uint16_t qclass, uint32_t id, int rd, u_char *buf, int buflen) {
	char *fn = "mesg_make_query()";
	u_char *ucp;
	int i, written_len;
	Mesg_Hdr *hdr;

	if (T.debug > 4)
		syslog (LOG_DEBUG, "%s: (qtype: %s, id: %d): start", fn, string_rtype (qtype), id);

	hdr = (Mesg_Hdr *) buf;

	
	hdr->id = id;
	hdr->opcode = OP_QUERY;
	hdr->rcode = RC_OK;
	hdr->rd = rd;
	hdr->qr = hdr->aa = hdr->tc = hdr->ra = hdr->zero = 0;
	hdr->qdcnt = ntohs (1);
	hdr->ancnt = hdr->nscnt = hdr->arcnt = ntohs (0);

	written_len = sizeof (Mesg_Hdr);
	ucp = (u_char *) (hdr + 1);

	
	if (T.debug > 4)
		syslog (LOG_DEBUG, "%s: qname offset = %zd", fn, ucp - buf);

	i = dname_copy (qname, ucp, buflen - written_len);
	if (i < 0)
		return -1;

	written_len += i;
	ucp += i;

	
	if (T.debug > 4)
		syslog (LOG_DEBUG, "%s: qtype/qclass offset = %zd", fn, ucp - buf);

	written_len += sizeof (uint16_t) * 2;
	if (written_len > buflen)
		return -1;

	PUTSHORT (qtype, ucp);
	PUTSHORT (qclass, ucp);

	return written_len;
}

int labellen (const u_char *cp) {
	uint i;

	i = *cp;
	if ((i & DNCMP_MASK) == 0)
		return(i);
	else if ((i & DNCMP_MASK) == EDNS0_MASK) {
		uint bitlen;

		if (i != EDNS0_ELT_BITLABEL)
			return -1;

		bitlen = *(cp + 1);
		if (bitlen == 0)
			bitlen = 256;

		return (((bitlen + 7) / 8) + 1);
	} else return -1;
}

u_char *mesg_skip_dname (u_char *dname, u_char *end) {
	int l;

	if (dname >= end)
		return NULL;

	while(*dname) {
		if ((*dname & DNCMP_MASK) == DNCMP_MASK) {
			dname += 2;	
			return dname;
		}
		if (dname + 2 > end) 
			return NULL;

		l = labellen(dname);
		if (l < 0)
			return NULL;
		dname += l + 1;

		if (dname >= end)
			return NULL;
	}
	dname++;	
	return dname;
}

int mesg_dname_cmp (u_char *msg, u_char *dname_mesg, u_char *dname) {

	
	dname_mesg = dname_redirect (dname_mesg, msg);
	while (*dname_mesg != '\0' && (*dname == *dname_mesg)) {
		int len;

		len  = labellen(dname_mesg);
		if (len != labellen(dname))
			return -1;

		if (*dname == EDNS0_ELT_BITLABEL) {
			if (memcmp (dname_mesg + 1, dname + 1,  (size_t)len))
				return -1;
		} else if (strncasecmp ((const char *)dname_mesg + 1,  (const char *)dname + 1, (size_t)len))
				return -1;

		dname += len + 1;
		dname_mesg += len + 1;
		dname_mesg = dname_redirect (dname_mesg, msg);
	}

	if (*dname != *dname_mesg)
		return -1;
	else return 0;
}

int mesg_write_rrset_list (G_List *rrls, u_char *msg, u_char *msg_tail, uint16_t *dnames, int dnames_len, u_char **wp, uint16_t *cnt) {

	char *fn = "mesg_write_rrset_list()";
	u_char *wp_start, *wp_period;
	uint16_t us;
	uint32_t ul;
	RRset *rrsp;
	RR *rrp;
	int i, ret;

	if (T.debug > 4)
		syslog (LOG_DEBUG, "%s: start.", fn);

	if (!rrls)
		return 0;

	wp_start = *wp;

	for (rrls = rrls->next; rrls->list_data; rrls = rrls->next) {
		if (T.debug > 4)
			syslog (LOG_DEBUG, "%s: write a record", fn);

		rrsp = (RRset *) rrls->list_data;
		for (i = 0; i < rrsp->data.d->data_cnt; i++) {
			wp_period = *wp;

			
			ret = write_dname (msg, msg_tail, dnames, dnames_len, rrset_owner (rrsp), *wp);
			if (ret < 0) {
				syslog (LOG_DEBUG, "write ownername failed");
				*wp = wp_period;
				return wp_period - wp_start;
			}
			*wp += ret;

			
			rrp = (RR *) (rrsp->data.p + data_offset (i, rrsp->data.p));
			if (*wp + sizeof (uint16_t) * 3 + sizeof (uint32_t)
			    + rrp->rd_len > msg_tail) {
				syslog (LOG_DEBUG, "write rdata failed");
				*wp = wp_period;
				return wp_period - wp_start;
			}

			PUTSHORT (rrsp->key.info->r_type, *wp);
			PUTSHORT (rrsp->key.info->r_class, *wp);
			ul = rrp->ttl;
			PUTLONG (ul, *wp);

			
			PUTSHORT (rrp->rd_len, *wp);
			memcpy (*wp, rr_rdata (rrp), rrp->rd_len);
			*wp += rrp->rd_len;

			
			us = ntohs (*cnt) + 1;
			
			*cnt = htons (us);

			if (T.debug > 4)
				syslog (LOG_DEBUG, "%s: now counter = %zd", fn, (size_t)us);
		}
	}

	if (T.debug > 4)
		syslog (LOG_DEBUG, "%s: return %d", fn, (int)(*wp - wp_start));

	return (*wp - wp_start);
}



int mesg_assemble (G_List *an_list, G_List *ns_list, G_List *ar_list, u_char *buf, uint16_t buflen, u_char *mesg, int mesg_len) {
	uint16_t dnames[MESG_ASSEMBLE_OFFSET_LEN];
	u_char *ucp, *ucp_tmp;
	int written_len, ret;
	Mesg_Hdr *hdr;

	
	if (mesg)
		memcpy (buf, mesg, mesg_len);
	else memset (buf, 0, buflen);

	hdr = (Mesg_Hdr *) buf;

	written_len = 0;

	
	hdr->qr = 1;
	hdr->ancnt = 0;
	hdr->nscnt = 0;
	hdr->arcnt = 0;

	if (hdr->qdcnt) {
		int qdcnt = ntohs(hdr->qdcnt);

		
		dnames[0] = (uint16_t) (sizeof (Mesg_Hdr));
		dnames[1] = 0;	

		
		ucp = buf + sizeof(Mesg_Hdr);
		while (qdcnt--) {
			
			if (!(ucp = mesg_skip_dname(ucp, buf + mesg_len)) || ucp + 2 * sizeof(uint16_t) > buf + mesg_len) {
				syslog (LOG_NOTICE, "query message overrun");
				return -1;
			}
			
			ucp += (2 * sizeof(uint16_t));
		}
		written_len = ucp - buf;
	} else {
		
		written_len = sizeof (Mesg_Hdr);
		ucp = buf + written_len;
		dnames[0] = 0;
	}

	
	ucp_tmp = ucp;
	ret = mesg_write_rrset_list (an_list, buf, buf + buflen, dnames, MESG_ASSEMBLE_OFFSET_LEN, &ucp, &(hdr->ancnt));

	if (ret < 0) {
		
		hdr->tc = 1;
		return ucp_tmp - buf;
	}
	written_len += ret;

	
	ucp_tmp = ucp;
	ret = mesg_write_rrset_list (ns_list, buf, buf + buflen, dnames, MESG_ASSEMBLE_OFFSET_LEN, &ucp, &(hdr->nscnt));

	if (ret < 0) {
		
		hdr->tc = 1;
		return ucp_tmp - buf;
	}
	written_len += ret;

	
	ucp_tmp = ucp;
	ret = mesg_write_rrset_list (ar_list, buf, buf + buflen, dnames, MESG_ASSEMBLE_OFFSET_LEN, &ucp, &(hdr->arcnt));

	
	if (ret < 0)
		return ucp_tmp - buf;
	else return written_len + ret;
}

int mesg_extract_rr (u_char *mesg, u_char *msg_end, uint16_t r_type, uint16_t r_class, u_char *rrp, u_char *buf, int buflen) {
	int i, written_len;
	u_char *rp, *wp;

	written_len = 0;

	switch (r_type) {
	case RT_NS:
	case RT_CNAME:
	case RT_PTR:
		
		if (!dname_decompress (buf, buflen, rrp, mesg, msg_end, &written_len)) {
			syslog (LOG_INFO, "record invalid -- %s", string_rtype (r_type));
			return -1;
		}
		break;
	case RT_SOA:
		rp = rrp;
		wp = buf;
		rp = dname_decompress (wp, buflen, rp, mesg, msg_end, &i);
		if (!rp) {
			syslog (LOG_INFO, "record invalid -- SOA MNAME");
			return -1;
		}

		wp += i;
		rp = dname_decompress (wp, buflen - (wp - buf), rp, mesg, msg_end, &i);
		if (!rp) {
			syslog (LOG_INFO, "record invalid -- SOA RNAME");
			return -1;
		}

		wp += i;
		memcpy (wp, rp, (i = sizeof (uint32_t) * 5));
		wp += i;
		written_len = wp - buf;
		break;
	case RT_MX:
		rp = rrp;
		wp = buf;
		memcpy (wp, rp, (i = sizeof (uint16_t) * 1));	
		wp += i;
		rp += i;
		if (!dname_decompress (wp, buflen - (wp - buf), rp, mesg, msg_end, &i)) {
			syslog (LOG_INFO, "record invalid -- MX EXCHANGE");
			return -1;
		}
		wp += i;
		written_len = wp - buf;
		break;
	case RT_RP:
		
		rp = rrp;
		wp = buf;
		rp = dname_decompress (wp, buflen, rp, mesg, msg_end, &i);
		if (!rp) {
			syslog (LOG_INFO, "record invalid -- RP MBOX-DNAME");
			return -1;
		}
		wp += i;
		rp = dname_decompress (wp, buflen - (wp - buf), rp, mesg, msg_end, &i);
		if (!rp) {
			syslog (LOG_INFO, "record invalid -- RP TXT-DNAME");
			return -1;
		}
		wp += i;
		written_len = wp - buf;
		break;
	case RT_A:
	case RT_HINFO:
	case RT_AAAA:
	case RT_A6:
	case RT_SRV:
	case RT_TXT:
		
		return 0;
	default:
		syslog (LOG_INFO, "unknown resource type %d", r_type);
		return 0;
	}

	return written_len;
}

int mesg_parse (u_char *msg, int msg_len, G_List *an_list, G_List *ns_list, G_List *ar_list) {
	char *fn = "mesg_parse()";
	Mesg_Hdr *hdr;
	u_char *rp;

	if (T.debug > 4)
		syslog (LOG_DEBUG, "%s: start", fn);

	if (msg_len < sizeof (*hdr))
		return -1;

	hdr = (Mesg_Hdr *) msg;
	rp = (u_char *) (hdr + 1);	

	if (hdr->qdcnt) {
		
		rp = mesg_skip_dname (rp, msg + msg_len);
		rp += 4;	
		if (rp > msg + msg_len)
			return -1;
	}

	rp = mesg_read_sec (an_list, rp, ntohs(hdr->ancnt), msg, msg_len);
	if (!rp)
		return -1;

	rp = mesg_read_sec (ns_list, rp, ntohs(hdr->nscnt), msg, msg_len);
	if (!rp)
		return -1;

	rp = mesg_read_sec (ar_list, rp, ntohs(hdr->arcnt), msg, msg_len);
	if (!rp)
		return -1;

	return 0;
}

u_char *dname_decompress (u_char *buf, int buflen, u_char *dname, u_char *m_head, u_char *m_tail, int *written) {
	int token_len, written_len, iter;
	u_char *cp, *next;
	int pktsiz = m_tail - m_head;

	next = NULL;
	written_len = token_len = 0;
	for (cp = dname; *cp; cp += token_len) {
		iter = 0;
	  top:
		if ((*cp & DNCMP_MASK) == DNCMP_MASK) {
			uint16_t ui;

			if (iter++ >= pktsiz) 
				return NULL;

			if (!m_head || !m_tail) 
				return NULL;

			
			next = cp + 2;
			GETSHORT (ui, cp);
			ui = ui & ~DNCMP_MASK_INT16T;

			cp = m_head + ui;
			if (cp < m_head || m_tail < cp)
				return NULL;

			goto top;
		}

		token_len = labellen(cp);
		if (token_len < 0)
			return NULL;
		else token_len++;

		if (T.debug > 4)
			syslog (LOG_DEBUG, "token_len: %d", token_len);

		if (written_len + token_len >= buflen)
			return NULL; 
		if (m_tail && cp + token_len > m_tail)
			return NULL; 

		if (written) {
			
			memcpy (buf, cp, token_len);
			written_len += token_len;
			buf += token_len;
		} else {
			
			if ((*cp & DNCMP_MASK) != EDNS0_MASK) {
				memcpy (buf, cp + 1, token_len - 1);
				*(buf + (token_len - 1)) = DNAME_DELIM;
				written_len += token_len;
				buf += token_len;
			} else if (*cp == EDNS0_ELT_BITLABEL) {
				int bitlength, i;
				u_char *wp;

				
				if (written_len + token_len*2 + 7 >= buflen)
					return NULL; 

				wp = buf;
				wp += sprintf((char *)wp, "\\[x");
				for (i = 1; i < token_len-1; i++) {
					u_char d1, d2;
					uint b;

					b = (int) *(cp + 1 + i);
					d1 = hex[(b >> 4) & 0x0f];
					d2 = hex[b & 0x0f];
					wp += sprintf((char *)wp, "%c%c", d1, d2);
				}
				bitlength = *(cp + 1) ? *(cp + 1) : 256;
				wp += sprintf((char *)wp, "/%u].", bitlength);

				written_len += (wp - buf);
				buf += written_len;
			}
		}
	}

	*buf = '\0';
	if (written)
		*written = written_len + 1;

	if (!next)
		next = cp+1;

	return next;
}


char *string_rclass (uint16_t rclass) {
	switch (rclass) {
		case C_IN:
		return "IN";
	case C_NONE:
		return "NONE";
	case C_ANY:
		return "ANY";
	default:
		syslog (LOG_NOTICE, "Unknown resource class(%d)", rclass);
		return "UNKNOWN";
	}
}

char *string_rtype (uint16_t rtype) {
	switch (rtype) {
		case RT_VOID:
		return "(void)";
	case RT_A:
		return "A";
	case RT_NS:
		return "NS";
	case RT_MD:
		return "MD";
	case RT_MF:
		return "MF";
	case RT_CNAME:
		return "CNAME";
	case RT_SOA:
		return "SOA";
	case RT_MB:
		return "MB";
	case RT_MG:
		return "MG";
	case RT_MR:
		return "MR";
	case RT_NULL:
		return "NULL";
	case RT_WKS:
		return "WKS";
	case RT_PTR:
		return "PTR";
	case RT_HINFO:
		return "HINFO";
	case RT_MINFO:
		return "MINFO";
	case RT_MX:
		return "MX";
	case RT_TXT:
		return "TXT";
	case RT_RP:
		return "RP";
	case RT_AAAA:
		return "AAAA";
	case RT_SRV:
		return "SRV";
	case RT_A6:
		return "A6";
	case RT_UINFO:
		return "UINFO";
	case RT_TSIG:
		return "TSIG";
	case RT_IXFR:
		return "IXFR";
	case RT_AXFR:
		return "AXFR";
	case RT_ALL:
		return "ANY";
	default:
		syslog (LOG_NOTICE, "Unknown resource type(%d)", rtype);
		return "UNKNOWN";
	}
}

static int dname_copy (u_char *from, u_char *to, int tolen) {
	int skip, llen, written_len;

	written_len = 0;
	while (*from) {
		llen = labellen(from);
		if (llen == -1) 
			return -1;
		skip = llen + 1;
		written_len += skip;
		if (written_len >= tolen)
			return -1;

		memcpy (to, from, skip);
		from += skip;
		to += skip;
	}
	*to = '\0';
	written_len++;

	return written_len;
}

static u_char *dname_redirect (u_char *label, u_char *msg) {
	uint16_t us;

	if (msg && (*label & DNCMP_MASK) == DNCMP_MASK) {
		GETSHORT (us, label);
		us = us & (~DNCMP_MASK_INT16T);
		label = msg + us;
	}
	return label;
}

static int write_dname (u_char *msg, u_char *msg_tail, uint16_t *dnames, int dnames_len, u_char *dname, u_char *wp) {
	char *fn = "write_dname()";
	u_char *bestmatch_rpd = NULL;
	u_char *bestmatch_rpm = NULL;
	int bestmatch_len;
	u_char *rpd, *rpm;
	int written_len;

	if (T.debug > 4)
		syslog (LOG_DEBUG, "%s: start", fn);

	
	bestmatch_len = 0;
	for (rpd = dname; *rpd && !bestmatch_len; rpd += labellen(rpd) + 1) {
		int i;

		
		for (i = 0; dnames[i] != 0 && i < dnames_len; i++) {
			
			for (rpm = dname_redirect (msg + dnames[i], msg); *rpm;
			     rpm = dname_redirect (labellen(rpm)+rpm+1, msg)) {
				u_char *cpd, *cpm;
				int match_len;

				if (rpm < msg || msg_tail < rpm)
					return -1; 

				
				cpd = rpd;
				cpm = rpm;

				match_len = 0;
				while (*cpm && *cpm == *cpd) {
					int mlen;

					mlen = labellen(cpm);
					if (mlen != labellen(cpd))
						break;

					
					if (*cpm == EDNS0_ELT_BITLABEL && memcmp (cpm+1, cpd+1, mlen))
							break;

					
					if (*cpm != EDNS0_ELT_BITLABEL && strncasecmp ((const char *)cpm+1, (const char *)cpd+1, *cpm))


						break;
					
					
					cpm += mlen + 1;
					cpd += mlen + 1;

					
					cpm = dname_redirect (cpm, msg);
					if (cpm < msg || msg_tail < cpm)
						return -1; 

					match_len++;
				}

				
				if (*cpm == '\0' && *cpd == '\0' && match_len > bestmatch_len) {
					bestmatch_rpd = rpd;
					bestmatch_rpm = rpm;
					bestmatch_len = match_len;
				}
			}
		}
	}

	
	if (bestmatch_rpd != dname) {
		int i;
		
		for (i = 0; dnames[i] != 0; i++);

		if (i + 1 < dnames_len) {
			
			if (((uint16_t) (bestmatch_rpm - msg)
			    < DNCMP_REDIRECT_LIMIT)) {
				

				dnames[i] = (uint16_t) (wp - msg);
				dnames[i + 1] = 0;
			}
		}
	}

	
	written_len = 0;
	rpd = dname;

	
	while (*rpd && rpd != bestmatch_rpd) {
		int i;

		i = labellen(rpd) + 1;
		if (wp + i > msg_tail)
			return -1; 

		memcpy (wp, rpd, i);
		written_len += i;
		rpd += i;
		wp += i;
	}

	
	if (rpd == bestmatch_rpd) {
		uint16_t us;

		
		if (wp + sizeof (uint16_t) > msg_tail)
			return -1; 

		us = (uint16_t) (bestmatch_rpm - msg) | DNCMP_MASK_INT16T;
		PUTSHORT (us, wp);
		written_len += sizeof (uint16_t);
	} else {
		*wp = '\0';
		written_len++;
	}

	if (T.debug > 4)
		syslog (LOG_DEBUG, "%s: return (written_len = %d)", fn, written_len);

	return written_len;
}

static u_char *mesg_read_sec (G_List *target_list, u_char *section, int count, u_char *mesg, int mesg_len) {
	char *fn = "mesg_read_sec()";
	G_List *rc_list, *gl;
	u_char buf[MAX_PACKET];
	u_char *msg_end, *rp;
	int i;

	if (T.debug > 4)
		syslog (LOG_DEBUG, "%s: start", fn);

	
	rc_list = list_init ();
	if (!rc_list)
		return NULL;

	rp = section;
	msg_end = mesg + mesg_len;
	for (i = 0; i < count; i++) {
		u_char *rname, *rp_ex, *rdp;
		uint16_t r_type, r_class;
		uint16_t rdlen, rdlen_ex;
		uint32_t r_ttl;
		RR_List *rrl;

		
		rname = rp;
		rp = mesg_skip_dname (rp, msg_end);
		if (!rp)
			goto error;

		if (rp + sizeof(uint16_t)*3 + sizeof(uint32_t) > msg_end)
			goto error;

		GETSHORT (r_type, rp);
		GETSHORT (r_class, rp);
		GETLONG (r_ttl, rp);
		GETSHORT (rdlen, rp);

		rdp = rp;
		rp += rdlen;
		if (rp > msg_end)
			goto error;

		
		for (gl = rc_list->next; gl->list_data; gl = gl->next) {
			RRset_Couple *rc;

			rc = (RRset_Couple *) (gl->list_data);
			if ((rc->rrs->key.info->r_type == r_type) && (rc->rrs->key.info->r_class == r_class) && !mesg_dname_cmp (mesg, rname, rrset_owner (rc->rrs))) {

				if (T.debug > 4)
					syslog (LOG_DEBUG, "%s: matching record  found rrs->dname = %s / rname = %s", fn, rrset_owner (rc->rrs), rname)
				break;
			}
		}

		
		if (!gl->list_data) {
			RRset_Couple *rc;
			int dname_len;

			if (!dname_decompress (buf, sizeof (buf), rname, mesg, msg_end, &dname_len))
				goto error;

			rc = malloc (sizeof (RRset_Couple));
			if (!rc)
				goto error;

			rc->rrl = rr_list_alloc ();
			rc->rrs = rrset_create (r_type, r_class, dname_len, buf, NULL);

			
			if (!rc->rrl || !rc->rrs || list_add (rc_list, rc)) {
				rrset_couple_free(rc);
				goto error;
			}

			
			gl = rc_list->next;
		}

		
		if (rdlen) {
			int ret;

			ret = mesg_extract_rr (mesg, msg_end, r_type, r_class, rdp, buf, sizeof (buf));
			if (ret < 0)
				goto error;

			if (!ret) {
				rp_ex = rdp;
				rdlen_ex = rdlen;
			} else {
				rp_ex = buf;
				rdlen_ex = ret;
			}
		} else {
			rp_ex = NULL;
			rdlen_ex = 0;
		}

		
		rrl = rr_list_add (((RRset_Couple *) (gl->list_data))->rrl, r_ttl, rdlen_ex, rp_ex);
		if (!rrl)
			goto error;

		((RRset_Couple *) (gl->list_data))->rrl = rrl;
	}

	if (T.debug > 4)
		syslog (LOG_DEBUG, "%s: make each RRset from list.", fn);

	rc_list->list_data = NULL;
	for (gl = rc_list->next; gl->list_data; gl = gl->next) {
		RRset_Couple *rc;
		RRset *rrs;

		
		rc = (RRset_Couple *) (gl->list_data);
		rrs = rrset_create (rc->rrs->key.info->r_type, rc->rrs->key.info->r_class, rc->rrs->key.info->owner_len, rrset_owner (rc->rrs), rc->rrl);


		if (!rrs)
			goto error;

		if (target_list) {
			if (list_add (target_list, rrset_copy (rrs)) < 0) {
				rrset_free (rrs);
				goto error;
			}
		}

		rrset_free (rrs);
	}

	
	list_destroy (rc_list, rrset_couple_freev);

	if (T.debug > 4)
		syslog (LOG_DEBUG, "%s: end", fn);

	return rp;  

error:
	syslog (LOG_INFO, "%s: message extraction failed", fn);
	list_destroy (rc_list, rrset_couple_freev);
	return NULL;
}

