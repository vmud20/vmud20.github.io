















static void chdlc_slarp_print(netdissect_options *, const u_char *, u_int);

static const struct tok chdlc_cast_values[] = {
    { CHDLC_UNICAST, "unicast" }, { CHDLC_BCAST, "bcast" }, { 0, NULL}

};



u_int chdlc_if_print(netdissect_options *ndo, const struct pcap_pkthdr *h, register const u_char *p)
{
	return chdlc_print(ndo, p, h->len);
}

u_int chdlc_print(netdissect_options *ndo, register const u_char *p, u_int length)
{
	u_int proto;
	const u_char *bp = p;

	if (length < CHDLC_HDRLEN)
		goto trunc;
	ND_TCHECK2(*p, CHDLC_HDRLEN);
	proto = EXTRACT_16BITS(&p[2]);
	if (ndo->ndo_eflag) {
                ND_PRINT((ndo, "%s, ethertype %s (0x%04x), length %u: ", tok2str(chdlc_cast_values, "0x%02x", p[0]), tok2str(ethertype_values, "Unknown", proto), proto, length));



	}

	length -= CHDLC_HDRLEN;
	p += CHDLC_HDRLEN;

	switch (proto) {
	case ETHERTYPE_IP:
		ip_print(ndo, p, length);
		break;
	case ETHERTYPE_IPV6:
		ip6_print(ndo, p, length);
		break;
	case CHDLC_TYPE_SLARP:
		chdlc_slarp_print(ndo, p, length);
		break;

	case CHDLC_TYPE_CDP:
		chdlc_cdp_print(p, length);
		break;

        case ETHERTYPE_MPLS:
        case ETHERTYPE_MPLS_MULTI:
                mpls_print(ndo, p, length);
		break;
        case ETHERTYPE_ISO:
                
                if (length < 2)
                    goto trunc;
                ND_TCHECK_16BITS(p);
                if (*(p+1) == 0x81 || *(p+1) == 0x82 || *(p+1) == 0x83)

                    isoclns_print(ndo, p + 1, length - 1, ndo->ndo_snapend - p - 1);
                else isoclns_print(ndo, p, length, ndo->ndo_snapend - p);
                break;
	default:
                if (!ndo->ndo_eflag)
                        ND_PRINT((ndo, "unknown CHDLC protocol (0x%04x)", proto));
                break;
	}

	return (CHDLC_HDRLEN);

trunc:
	ND_PRINT((ndo, "[|chdlc]"));
	return ndo->ndo_snapend - bp;
}


struct cisco_slarp {
	uint8_t code[4];



	union {
		struct {
			uint8_t addr[4];
			uint8_t mask[4];
		} addr;
		struct {
			uint8_t myseq[4];
			uint8_t yourseq[4];
			uint8_t rel[2];
		} keep;
	} un;
};




static void chdlc_slarp_print(netdissect_options *ndo, const u_char *cp, u_int length)
{
	const struct cisco_slarp *slarp;
        u_int sec,min,hrs,days;

	ND_PRINT((ndo, "SLARP (length: %u), ",length));
	if (length < SLARP_MIN_LEN)
		goto trunc;

	slarp = (const struct cisco_slarp *)cp;
	ND_TCHECK2(*slarp, SLARP_MIN_LEN);
	switch (EXTRACT_32BITS(&slarp->code)) {
	case SLARP_REQUEST:
		ND_PRINT((ndo, "request"));
		
		break;
	case SLARP_REPLY:
		ND_PRINT((ndo, "reply %s/%s", ipaddr_string(ndo, &slarp->un.addr.addr), ipaddr_string(ndo, &slarp->un.addr.mask)));

		break;
	case SLARP_KEEPALIVE:
		ND_PRINT((ndo, "keepalive: mineseen=0x%08x, yourseen=0x%08x, reliability=0x%04x", EXTRACT_32BITS(&slarp->un.keep.myseq), EXTRACT_32BITS(&slarp->un.keep.yourseq), EXTRACT_16BITS(&slarp->un.keep.rel)));



                if (length >= SLARP_MAX_LEN) { 
                        cp += SLARP_MIN_LEN;
                        ND_TCHECK2(*cp, 4);
                        sec = EXTRACT_32BITS(cp) / 1000;
                        min = sec / 60; sec -= min * 60;
                        hrs = min / 60; min -= hrs * 60;
                        days = hrs / 24; hrs -= days * 24;
                        ND_PRINT((ndo, ", link uptime=%ud%uh%um%us",days,hrs,min,sec));
                }
		break;
	default:
		ND_PRINT((ndo, "0x%02x unknown", EXTRACT_32BITS(&slarp->code)));
                if (ndo->ndo_vflag <= 1)
                    print_unknown_data(ndo,cp+4,"\n\t",length-4);
		break;
	}

	if (SLARP_MAX_LEN < length && ndo->ndo_vflag)
		ND_PRINT((ndo, ", (trailing junk: %d bytes)", length - SLARP_MAX_LEN));
        if (ndo->ndo_vflag > 1)
            print_unknown_data(ndo,cp+4,"\n\t",length-4);
	return;

trunc:
	ND_PRINT((ndo, "[|slarp]"));
}



