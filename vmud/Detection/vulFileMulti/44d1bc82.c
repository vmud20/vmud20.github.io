


















static const char *ns_ops[] = {
	"", " inv_q", " stat", " op3", " notify", " update", " op6", " op7", " op8", " updateA", " updateD", " updateDA", " updateM", " updateMA", " zoneInit", " zoneRef", };



static const char *ns_resp[] = {
	"", " FormErr", " ServFail", " NXDomain", " NotImp", " Refused", " YXDomain", " YXRRSet", " NXRRSet", " NotAuth", " NotZone", " Resp11", " Resp12", " Resp13", " Resp14", " NoChange", };





static const u_char * ns_nskip(netdissect_options *ndo, register const u_char *cp)

{
	register u_char i;

	if (!ND_TTEST2(*cp, 1))
		return (NULL);
	i = *cp++;
	while (i) {
		if ((i & INDIR_MASK) == INDIR_MASK)
			return (cp + 1);
		if ((i & INDIR_MASK) == EDNS0_MASK) {
			int bitlen, bytelen;

			if ((i & ~INDIR_MASK) != EDNS0_ELT_BITLABEL)
				return(NULL); 
			if (!ND_TTEST2(*cp, 1))
				return (NULL);
			if ((bitlen = *cp++) == 0)
				bitlen = 256;
			bytelen = (bitlen + 7) / 8;
			cp += bytelen;
		} else cp += i;
		if (!ND_TTEST2(*cp, 1))
			return (NULL);
		i = *cp++;
	}
	return (cp);
}


static const u_char * blabel_print(netdissect_options *ndo, const u_char *cp)

{
	int bitlen, slen, b;
	const u_char *bitp, *lim;
	char tc;

	if (!ND_TTEST2(*cp, 1))
		return(NULL);
	if ((bitlen = *cp) == 0)
		bitlen = 256;
	slen = (bitlen + 3) / 4;
	lim = cp + 1 + slen;

	
	ND_PRINT((ndo, "\\[x"));
	for (bitp = cp + 1, b = bitlen; bitp < lim && b > 7; b -= 8, bitp++) {
		ND_TCHECK(*bitp);
		ND_PRINT((ndo, "%02x", *bitp));
	}
	if (b > 4) {
		ND_TCHECK(*bitp);
		tc = *bitp++;
		ND_PRINT((ndo, "%02x", tc & (0xff << (8 - b))));
	} else if (b > 0) {
		ND_TCHECK(*bitp);
		tc = *bitp++;
		ND_PRINT((ndo, "%1x", ((tc >> 4) & 0x0f) & (0x0f << (4 - b))));
	}
	ND_PRINT((ndo, "/%d]", bitlen));
	return lim;
trunc:
	ND_PRINT((ndo, ".../%d]", bitlen));
	return NULL;
}

static int labellen(netdissect_options *ndo, const u_char *cp)

{
	register u_int i;

	if (!ND_TTEST2(*cp, 1))
		return(-1);
	i = *cp;
	if ((i & INDIR_MASK) == EDNS0_MASK) {
		int bitlen, elt;
		if ((elt = (i & ~INDIR_MASK)) != EDNS0_ELT_BITLABEL) {
			ND_PRINT((ndo, "<ELT %d>", elt));
			return(-1);
		}
		if (!ND_TTEST2(*(cp + 1), 1))
			return(-1);
		if ((bitlen = *(cp + 1)) == 0)
			bitlen = 256;
		return(((bitlen + 7) / 8) + 1);
	} else return(i);
}

const u_char * ns_nprint(netdissect_options *ndo, register const u_char *cp, register const u_char *bp)

{
	register u_int i, l;
	register const u_char *rp = NULL;
	register int compress = 0;
	int chars_processed;
	int elt;
	int data_size = ndo->ndo_snapend - bp;

	if ((l = labellen(ndo, cp)) == (u_int)-1)
		return(NULL);
	if (!ND_TTEST2(*cp, 1))
		return(NULL);
	chars_processed = 1;
	if (((i = *cp++) & INDIR_MASK) != INDIR_MASK) {
		compress = 0;
		rp = cp + l;
	}

	if (i != 0)
		while (i && cp < ndo->ndo_snapend) {
			if ((i & INDIR_MASK) == INDIR_MASK) {
				if (!compress) {
					rp = cp + 1;
					compress = 1;
				}
				if (!ND_TTEST2(*cp, 1))
					return(NULL);
				cp = bp + (((i << 8) | *cp) & 0x3fff);
				if ((l = labellen(ndo, cp)) == (u_int)-1)
					return(NULL);
				if (!ND_TTEST2(*cp, 1))
					return(NULL);
				i = *cp++;
				chars_processed++;

				
				if (chars_processed >= data_size) {
					ND_PRINT((ndo, "<LOOP>"));
					return (NULL);
				}
				continue;
			}
			if ((i & INDIR_MASK) == EDNS0_MASK) {
				elt = (i & ~INDIR_MASK);
				switch(elt) {
				case EDNS0_ELT_BITLABEL:
					if (blabel_print(ndo, cp) == NULL)
						return (NULL);
					break;
				default:
					
					ND_PRINT((ndo, "<ELT %d>", elt));
					return(NULL);
				}
			} else {
				if (fn_printn(ndo, cp, l, ndo->ndo_snapend))
					return(NULL);
			}

			cp += l;
			chars_processed += l;
			ND_PRINT((ndo, "."));
			if ((l = labellen(ndo, cp)) == (u_int)-1)
				return(NULL);
			if (!ND_TTEST2(*cp, 1))
				return(NULL);
			i = *cp++;
			chars_processed++;
			if (!compress)
				rp += l + 1;
		}
	else ND_PRINT((ndo, "."));
	return (rp);
}


static const u_char * ns_cprint(netdissect_options *ndo, register const u_char *cp)

{
	register u_int i;

	if (!ND_TTEST2(*cp, 1))
		return (NULL);
	i = *cp++;
	if (fn_printn(ndo, cp, i, ndo->ndo_snapend))
		return (NULL);
	return (cp + i);
}


const struct tok ns_type2str[] = {
	{ T_A,		"A" },			 { T_NS,		"NS" }, { T_MD,		"MD" }, { T_MF,		"MF" }, { T_CNAME,	"CNAME" }, { T_SOA,	"SOA" }, { T_MB,		"MB" }, { T_MG,		"MG" }, { T_MR,		"MR" }, { T_NULL,	"NULL" }, { T_WKS,	"WKS" }, { T_PTR,	"PTR" }, { T_HINFO,	"HINFO" }, { T_MINFO,	"MINFO" }, { T_MX,		"MX" }, { T_TXT,	"TXT" }, { T_RP,		"RP" }, { T_AFSDB,	"AFSDB" }, { T_X25,	"X25" }, { T_ISDN,	"ISDN" }, { T_RT,		"RT" }, { T_NSAP,	"NSAP" }, { T_NSAP_PTR,	"NSAP_PTR" }, { T_SIG,	"SIG" }, { T_KEY,	"KEY" }, { T_PX,		"PX" }, { T_GPOS,	"GPOS" }, { T_AAAA,	"AAAA" }, { T_LOC,	"LOC" }, { T_NXT,	"NXT" }, { T_EID,	"EID" }, { T_NIMLOC,	"NIMLOC" }, { T_SRV,	"SRV" }, { T_ATMA,	"ATMA" }, { T_NAPTR,	"NAPTR" }, { T_KX,		"KX" }, { T_CERT,	"CERT" }, { T_A6,		"A6" }, { T_DNAME,	"DNAME" }, { T_SINK, 	"SINK" }, { T_OPT,	"OPT" }, { T_APL, 	"APL" }, { T_DS,		"DS" }, { T_SSHFP,	"SSHFP" }, { T_IPSECKEY,	"IPSECKEY" }, { T_RRSIG, 	"RRSIG" }, { T_NSEC,	"NSEC" }, { T_DNSKEY,	"DNSKEY" }, { T_SPF,	"SPF" }, { T_UINFO,	"UINFO" }, { T_UID,	"UID" }, { T_GID,	"GID" }, { T_UNSPEC,	"UNSPEC" }, { T_UNSPECA,	"UNSPECA" }, { T_TKEY,	"TKEY" }, { T_TSIG,	"TSIG" }, { T_IXFR,	"IXFR" }, { T_AXFR,	"AXFR" }, { T_MAILB,	"MAILB" }, { T_MAILA,	"MAILA" }, { T_ANY,	"ANY" }, { 0,		NULL }




























































};

const struct tok ns_class2str[] = {
	{ C_IN,		"IN" },		 { C_CHAOS,	"CHAOS" }, { C_HS,		"HS" }, { C_ANY,	"ANY" }, { 0,		NULL }



};


static const u_char * ns_qprint(netdissect_options *ndo, register const u_char *cp, register const u_char *bp, int is_mdns)

{
	register const u_char *np = cp;
	register u_int i, class;

	cp = ns_nskip(ndo, cp);

	if (cp == NULL || !ND_TTEST2(*cp, 4))
		return(NULL);

	
	i = EXTRACT_16BITS(cp);
	cp += 2;
	ND_PRINT((ndo, " %s", tok2str(ns_type2str, "Type%d", i)));
	
	i = EXTRACT_16BITS(cp);
	cp += 2;
	if (is_mdns)
		class = (i & ~C_QU);
	else class = i;
	if (class != C_IN)
		ND_PRINT((ndo, " %s", tok2str(ns_class2str, "(Class %d)", class)));
	if (is_mdns) {
		ND_PRINT((ndo, i & C_QU ? " (QU)" : " (QM)"));
	}

	ND_PRINT((ndo, "? "));
	cp = ns_nprint(ndo, np, bp);
	return(cp ? cp + 4 : NULL);
}


static const u_char * ns_rprint(netdissect_options *ndo, register const u_char *cp, register const u_char *bp, int is_mdns)

{
	register u_int i, class, opt_flags = 0;
	register u_short typ, len;
	register const u_char *rp;

	if (ndo->ndo_vflag) {
		ND_PRINT((ndo, " "));
		if ((cp = ns_nprint(ndo, cp, bp)) == NULL)
			return NULL;
	} else cp = ns_nskip(ndo, cp);

	if (cp == NULL || !ND_TTEST2(*cp, 10))
		return (ndo->ndo_snapend);

	
	typ = EXTRACT_16BITS(cp);
	cp += 2;
	
	i = EXTRACT_16BITS(cp);
	cp += 2;
	if (is_mdns)
		class = (i & ~C_CACHE_FLUSH);
	else class = i;
	if (class != C_IN && typ != T_OPT)
		ND_PRINT((ndo, " %s", tok2str(ns_class2str, "(Class %d)", class)));
	if (is_mdns) {
		if (i & C_CACHE_FLUSH)
			ND_PRINT((ndo, " (Cache flush)"));
	}

	if (typ == T_OPT) {
		
		cp += 2;
		opt_flags = EXTRACT_16BITS(cp);
		
		cp += 2;
	} else if (ndo->ndo_vflag > 2) {
		
		ND_PRINT((ndo, " ["));
		relts_print(ndo, EXTRACT_32BITS(cp));
		ND_PRINT((ndo, "]"));
		cp += 4;
	} else {
		
		cp += 4;
	}

	len = EXTRACT_16BITS(cp);
	cp += 2;

	rp = cp + len;

	ND_PRINT((ndo, " %s", tok2str(ns_type2str, "Type%d", typ)));
	if (rp > ndo->ndo_snapend)
		return(NULL);

	switch (typ) {
	case T_A:
		if (!ND_TTEST2(*cp, sizeof(struct in_addr)))
			return(NULL);
		ND_PRINT((ndo, " %s", intoa(htonl(EXTRACT_32BITS(cp)))));
		break;

	case T_NS:
	case T_CNAME:
	case T_PTR:

	case T_DNAME:

		ND_PRINT((ndo, " "));
		if (ns_nprint(ndo, cp, bp) == NULL)
			return(NULL);
		break;

	case T_SOA:
		if (!ndo->ndo_vflag)
			break;
		ND_PRINT((ndo, " "));
		if ((cp = ns_nprint(ndo, cp, bp)) == NULL)
			return(NULL);
		ND_PRINT((ndo, " "));
		if ((cp = ns_nprint(ndo, cp, bp)) == NULL)
			return(NULL);
		if (!ND_TTEST2(*cp, 5 * 4))
			return(NULL);
		ND_PRINT((ndo, " %u", EXTRACT_32BITS(cp)));
		cp += 4;
		ND_PRINT((ndo, " %u", EXTRACT_32BITS(cp)));
		cp += 4;
		ND_PRINT((ndo, " %u", EXTRACT_32BITS(cp)));
		cp += 4;
		ND_PRINT((ndo, " %u", EXTRACT_32BITS(cp)));
		cp += 4;
		ND_PRINT((ndo, " %u", EXTRACT_32BITS(cp)));
		cp += 4;
		break;
	case T_MX:
		ND_PRINT((ndo, " "));
		if (!ND_TTEST2(*cp, 2))
			return(NULL);
		if (ns_nprint(ndo, cp + 2, bp) == NULL)
			return(NULL);
		ND_PRINT((ndo, " %d", EXTRACT_16BITS(cp)));
		break;

	case T_TXT:
		while (cp < rp) {
			ND_PRINT((ndo, " \""));
			cp = ns_cprint(ndo, cp);
			if (cp == NULL)
				return(NULL);
			ND_PRINT((ndo, "\""));
		}
		break;

	case T_SRV:
		ND_PRINT((ndo, " "));
		if (!ND_TTEST2(*cp, 6))
			return(NULL);
		if (ns_nprint(ndo, cp + 6, bp) == NULL)
			return(NULL);
		ND_PRINT((ndo, ":%d %d %d", EXTRACT_16BITS(cp + 4), EXTRACT_16BITS(cp), EXTRACT_16BITS(cp + 2)));
		break;

	case T_AAAA:
	    {
		char ntop_buf[INET6_ADDRSTRLEN];

		if (!ND_TTEST2(*cp, sizeof(struct in6_addr)))
			return(NULL);
		ND_PRINT((ndo, " %s", addrtostr6(cp, ntop_buf, sizeof(ntop_buf))));

		break;
	    }

	case T_A6:
	    {
		struct in6_addr a;
		int pbit, pbyte;
		char ntop_buf[INET6_ADDRSTRLEN];

		if (!ND_TTEST2(*cp, 1))
			return(NULL);
		pbit = *cp;
		pbyte = (pbit & ~7) / 8;
		if (pbit > 128) {
			ND_PRINT((ndo, " %u(bad plen)", pbit));
			break;
		} else if (pbit < 128) {
			if (!ND_TTEST2(*(cp + 1), sizeof(a) - pbyte))
				return(NULL);
			memset(&a, 0, sizeof(a));
			memcpy(&a.s6_addr[pbyte], cp + 1, sizeof(a) - pbyte);
			ND_PRINT((ndo, " %u %s", pbit, addrtostr6(&a, ntop_buf, sizeof(ntop_buf))));
		}
		if (pbit > 0) {
			ND_PRINT((ndo, " "));
			if (ns_nprint(ndo, cp + 1 + sizeof(a) - pbyte, bp) == NULL)
				return(NULL);
		}
		break;
	    }

	case T_OPT:
		ND_PRINT((ndo, " UDPsize=%u", class));
		if (opt_flags & 0x8000)
			ND_PRINT((ndo, " DO"));
		break;

	case T_UNSPECA:		
		if (!ND_TTEST2(*cp, len))
			return(NULL);
		if (fn_printn(ndo, cp, len, ndo->ndo_snapend))
			return(NULL);
		break;

	case T_TSIG:
	    {
		if (cp + len > ndo->ndo_snapend)
			return(NULL);
		if (!ndo->ndo_vflag)
			break;
		ND_PRINT((ndo, " "));
		if ((cp = ns_nprint(ndo, cp, bp)) == NULL)
			return(NULL);
		cp += 6;
		if (!ND_TTEST2(*cp, 2))
			return(NULL);
		ND_PRINT((ndo, " fudge=%u", EXTRACT_16BITS(cp)));
		cp += 2;
		if (!ND_TTEST2(*cp, 2))
			return(NULL);
		ND_PRINT((ndo, " maclen=%u", EXTRACT_16BITS(cp)));
		cp += 2 + EXTRACT_16BITS(cp);
		if (!ND_TTEST2(*cp, 2))
			return(NULL);
		ND_PRINT((ndo, " origid=%u", EXTRACT_16BITS(cp)));
		cp += 2;
		if (!ND_TTEST2(*cp, 2))
			return(NULL);
		ND_PRINT((ndo, " error=%u", EXTRACT_16BITS(cp)));
		cp += 2;
		if (!ND_TTEST2(*cp, 2))
			return(NULL);
		ND_PRINT((ndo, " otherlen=%u", EXTRACT_16BITS(cp)));
		cp += 2;
	    }
	}
	return (rp);		
}

void ns_print(netdissect_options *ndo, register const u_char *bp, u_int length, int is_mdns)

{
	register const HEADER *np;
	register int qdcount, ancount, nscount, arcount;
	register const u_char *cp;
	uint16_t b2;

	np = (const HEADER *)bp;
	ND_TCHECK(*np);
	
	qdcount = EXTRACT_16BITS(&np->qdcount);
	ancount = EXTRACT_16BITS(&np->ancount);
	nscount = EXTRACT_16BITS(&np->nscount);
	arcount = EXTRACT_16BITS(&np->arcount);

	if (DNS_QR(np)) {
		
		ND_PRINT((ndo, "%d%s%s%s%s%s%s", EXTRACT_16BITS(&np->id), ns_ops[DNS_OPCODE(np)], ns_resp[DNS_RCODE(np)], DNS_AA(np)? "*" : "", DNS_RA(np)? "" : "-", DNS_TC(np)? "|" : "", DNS_AD(np)? "$" : ""));







		if (qdcount != 1)
			ND_PRINT((ndo, " [%dq]", qdcount));
		
		cp = (const u_char *)(np + 1);
		while (qdcount--) {
			if (qdcount < EXTRACT_16BITS(&np->qdcount) - 1)
				ND_PRINT((ndo, ","));
			if (ndo->ndo_vflag > 1) {
				ND_PRINT((ndo, " q:"));
				if ((cp = ns_qprint(ndo, cp, bp, is_mdns)) == NULL)
					goto trunc;
			} else {
				if ((cp = ns_nskip(ndo, cp)) == NULL)
					goto trunc;
				cp += 4;	
			}
		}
		ND_PRINT((ndo, " %d/%d/%d", ancount, nscount, arcount));
		if (ancount--) {
			if ((cp = ns_rprint(ndo, cp, bp, is_mdns)) == NULL)
				goto trunc;
			while (cp < ndo->ndo_snapend && ancount--) {
				ND_PRINT((ndo, ","));
				if ((cp = ns_rprint(ndo, cp, bp, is_mdns)) == NULL)
					goto trunc;
			}
		}
		if (ancount > 0)
			goto trunc;
		
		if (ndo->ndo_vflag > 1) {
			if (cp < ndo->ndo_snapend && nscount--) {
				ND_PRINT((ndo, " ns:"));
				if ((cp = ns_rprint(ndo, cp, bp, is_mdns)) == NULL)
					goto trunc;
				while (cp < ndo->ndo_snapend && nscount--) {
					ND_PRINT((ndo, ","));
					if ((cp = ns_rprint(ndo, cp, bp, is_mdns)) == NULL)
						goto trunc;
				}
			}
			if (nscount > 0)
				goto trunc;
			if (cp < ndo->ndo_snapend && arcount--) {
				ND_PRINT((ndo, " ar:"));
				if ((cp = ns_rprint(ndo, cp, bp, is_mdns)) == NULL)
					goto trunc;
				while (cp < ndo->ndo_snapend && arcount--) {
					ND_PRINT((ndo, ","));
					if ((cp = ns_rprint(ndo, cp, bp, is_mdns)) == NULL)
						goto trunc;
				}
			}
			if (arcount > 0)
				goto trunc;
		}
	}
	else {
		
		ND_PRINT((ndo, "%d%s%s%s", EXTRACT_16BITS(&np->id), ns_ops[DNS_OPCODE(np)], DNS_RD(np) ? "+" : "", DNS_CD(np) ? "%" : ""));


		
		b2 = EXTRACT_16BITS(((const u_short *)np)+1);
		if (b2 & 0x6cf)
			ND_PRINT((ndo, " [b2&3=0x%x]", b2));

		if (DNS_OPCODE(np) == IQUERY) {
			if (qdcount)
				ND_PRINT((ndo, " [%dq]", qdcount));
			if (ancount != 1)
				ND_PRINT((ndo, " [%da]", ancount));
		}
		else {
			if (ancount)
				ND_PRINT((ndo, " [%da]", ancount));
			if (qdcount != 1)
				ND_PRINT((ndo, " [%dq]", qdcount));
		}
		if (nscount)
			ND_PRINT((ndo, " [%dn]", nscount));
		if (arcount)
			ND_PRINT((ndo, " [%dau]", arcount));

		cp = (const u_char *)(np + 1);
		if (qdcount--) {
			cp = ns_qprint(ndo, cp, (const u_char *)np, is_mdns);
			if (!cp)
				goto trunc;
			while (cp < ndo->ndo_snapend && qdcount--) {
				cp = ns_qprint(ndo, (const u_char *)cp, (const u_char *)np, is_mdns);

				if (!cp)
					goto trunc;
			}
		}
		if (qdcount > 0)
			goto trunc;

		
		if (ndo->ndo_vflag > 1) {
			if (ancount--) {
				if ((cp = ns_rprint(ndo, cp, bp, is_mdns)) == NULL)
					goto trunc;
				while (cp < ndo->ndo_snapend && ancount--) {
					ND_PRINT((ndo, ","));
					if ((cp = ns_rprint(ndo, cp, bp, is_mdns)) == NULL)
						goto trunc;
				}
			}
			if (ancount > 0)
				goto trunc;
			if (cp < ndo->ndo_snapend && nscount--) {
				ND_PRINT((ndo, " ns:"));
				if ((cp = ns_rprint(ndo, cp, bp, is_mdns)) == NULL)
					goto trunc;
				while (nscount-- && cp < ndo->ndo_snapend) {
					ND_PRINT((ndo, ","));
					if ((cp = ns_rprint(ndo, cp, bp, is_mdns)) == NULL)
						goto trunc;
				}
			}
			if (nscount > 0)
				goto trunc;
			if (cp < ndo->ndo_snapend && arcount--) {
				ND_PRINT((ndo, " ar:"));
				if ((cp = ns_rprint(ndo, cp, bp, is_mdns)) == NULL)
					goto trunc;
				while (cp < ndo->ndo_snapend && arcount--) {
					ND_PRINT((ndo, ","));
					if ((cp = ns_rprint(ndo, cp, bp, is_mdns)) == NULL)
						goto trunc;
				}
			}
			if (arcount > 0)
				goto trunc;
		}
	}
	ND_PRINT((ndo, " (%d)", length));
	return;

  trunc:
	ND_PRINT((ndo, "[|domain]"));
}
