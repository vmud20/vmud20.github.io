




















static inline void null_hdr_print(netdissect_options *ndo, u_int family, u_int length)
{
	if (!ndo->ndo_qflag) {
		ND_PRINT((ndo, "AF %s (%u)", tok2str(bsd_af_values,"Unknown",family),family));
	} else {
		ND_PRINT((ndo, "%s", tok2str(bsd_af_values,"Unknown AF %u",family)));
	}

	ND_PRINT((ndo, ", length %u: ", length));
}


u_int null_if_print(netdissect_options *ndo, const struct pcap_pkthdr *h, const u_char *p)
{
	u_int length = h->len;
	u_int caplen = h->caplen;
	u_int family;

	if (caplen < NULL_HDRLEN) {
		ND_PRINT((ndo, "[|null]"));
		return (NULL_HDRLEN);
	}

	memcpy((char *)&family, (const char *)p, sizeof(family));

	
	if ((family & 0xFFFF0000) != 0)
		family = SWAPLONG(family);

	if (ndo->ndo_eflag)
		null_hdr_print(ndo, family, length);

	length -= NULL_HDRLEN;
	caplen -= NULL_HDRLEN;
	p += NULL_HDRLEN;

	switch (family) {

	case BSD_AFNUM_INET:
		ip_print(ndo, p, length);
		break;

	case BSD_AFNUM_INET6_BSD:
	case BSD_AFNUM_INET6_FREEBSD:
	case BSD_AFNUM_INET6_DARWIN:
		ip6_print(ndo, p, length);
		break;

	case BSD_AFNUM_ISO:
		isoclns_print(ndo, p, length, caplen);
		break;

	case BSD_AFNUM_APPLETALK:
		atalk_print(ndo, p, length);
		break;

	case BSD_AFNUM_IPX:
		ipx_print(ndo, p, length);
		break;

	default:
		
		if (!ndo->ndo_eflag)
			null_hdr_print(ndo, family, length + NULL_HDRLEN);
		if (!ndo->ndo_suppress_default_print)
			ND_DEFAULTPRINT(p, caplen);
	}

	return (NULL_HDRLEN);
}


