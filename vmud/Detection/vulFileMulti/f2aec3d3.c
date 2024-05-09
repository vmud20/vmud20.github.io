




















static const char tstr[] = "[|gre]";









static const struct tok gre_flag_values[] = {
    { GRE_CP, "checksum present", { GRE_RP, "routing present", { GRE_KP, "key present", { GRE_SP, "sequence# present", { GRE_sP, "source routing present", { GRE_RECRS, "recursion count", { GRE_AP, "ack present", { 0, NULL }






};







static void gre_print_0(netdissect_options *, const u_char *, u_int);
static void gre_print_1(netdissect_options *, const u_char *, u_int);
static void gre_sre_print(netdissect_options *, uint16_t, uint8_t, uint8_t, const u_char *, u_int);
static void gre_sre_ip_print(netdissect_options *, uint8_t, uint8_t, const u_char *, u_int);
static void gre_sre_asn_print(netdissect_options *, uint8_t, uint8_t, const u_char *, u_int);

void gre_print(netdissect_options *ndo, const u_char *bp, u_int length)
{
	u_int len = length, vers;

	if (len < 2) {
		ND_PRINT((ndo, "%s", tstr));
		return;
	}
	vers = EXTRACT_16BITS(bp) & GRE_VERS_MASK;
        ND_PRINT((ndo, "GREv%u",vers));

        switch(vers) {
        case 0:
            gre_print_0(ndo, bp, len);
            break;
        case 1:
            gre_print_1(ndo, bp, len);
            break;
	default:
            ND_PRINT((ndo, " ERROR: unknown-version"));
            break;
        }
}

static void gre_print_0(netdissect_options *ndo, const u_char *bp, u_int length)
{
	u_int len = length;
	uint16_t flags, prot;

	flags = EXTRACT_16BITS(bp);
        if (ndo->ndo_vflag)
            ND_PRINT((ndo, ", Flags [%s]", bittok2str(gre_flag_values,"none",flags)));

	len -= 2;
	bp += 2;

	if (len < 2)
		goto trunc;
	prot = EXTRACT_16BITS(bp);
	len -= 2;
	bp += 2;

	if ((flags & GRE_CP) | (flags & GRE_RP)) {
		if (len < 2)
			goto trunc;
		if (ndo->ndo_vflag)
			ND_PRINT((ndo, ", sum 0x%x", EXTRACT_16BITS(bp)));
		bp += 2;
		len -= 2;

		if (len < 2)
			goto trunc;
		ND_PRINT((ndo, ", off 0x%x", EXTRACT_16BITS(bp)));
		bp += 2;
		len -= 2;
	}

	if (flags & GRE_KP) {
		if (len < 4)
			goto trunc;
		ND_PRINT((ndo, ", key=0x%x", EXTRACT_32BITS(bp)));
		bp += 4;
		len -= 4;
	}

	if (flags & GRE_SP) {
		if (len < 4)
			goto trunc;
		ND_PRINT((ndo, ", seq %u", EXTRACT_32BITS(bp)));
		bp += 4;
		len -= 4;
	}

	if (flags & GRE_RP) {
		for (;;) {
			uint16_t af;
			uint8_t sreoff;
			uint8_t srelen;

			if (len < 4)
				goto trunc;
			af = EXTRACT_16BITS(bp);
			sreoff = *(bp + 2);
			srelen = *(bp + 3);
			bp += 4;
			len -= 4;

			if (af == 0 && srelen == 0)
				break;

			gre_sre_print(ndo, af, sreoff, srelen, bp, len);

			if (len < srelen)
				goto trunc;
			bp += srelen;
			len -= srelen;
		}
	}

        if (ndo->ndo_eflag)
            ND_PRINT((ndo, ", proto %s (0x%04x)", tok2str(ethertype_values,"unknown",prot), prot));


        ND_PRINT((ndo, ", length %u",length));

        if (ndo->ndo_vflag < 1)
            ND_PRINT((ndo, ": ")); 
        else ND_PRINT((ndo, "\n\t"));

	switch (prot) {
	case ETHERTYPE_IP:
	        ip_print(ndo, bp, len);
		break;
	case ETHERTYPE_IPV6:
		ip6_print(ndo, bp, len);
		break;
	case ETHERTYPE_MPLS:
		mpls_print(ndo, bp, len);
		break;
	case ETHERTYPE_IPX:
		ipx_print(ndo, bp, len);
		break;
	case ETHERTYPE_ATALK:
		atalk_print(ndo, bp, len);
		break;
	case ETHERTYPE_GRE_ISO:
		isoclns_print(ndo, bp, len, len);
		break;
	case ETHERTYPE_TEB:
		ether_print(ndo, bp, len, len, NULL, NULL);
		break;
	default:
		ND_PRINT((ndo, "gre-proto-0x%x", prot));
	}
	return;

trunc:
	ND_PRINT((ndo, "%s", tstr));
}

static void gre_print_1(netdissect_options *ndo, const u_char *bp, u_int length)
{
	u_int len = length;
	uint16_t flags, prot;

	flags = EXTRACT_16BITS(bp);
	len -= 2;
	bp += 2;

	if (ndo->ndo_vflag)
            ND_PRINT((ndo, ", Flags [%s]", bittok2str(gre_flag_values,"none",flags)));

	if (len < 2)
		goto trunc;
	prot = EXTRACT_16BITS(bp);
	len -= 2;
	bp += 2;


	if (flags & GRE_KP) {
		uint32_t k;

		if (len < 4)
			goto trunc;
		k = EXTRACT_32BITS(bp);
		ND_PRINT((ndo, ", call %d", k & 0xffff));
		len -= 4;
		bp += 4;
	}

	if (flags & GRE_SP) {
		if (len < 4)
			goto trunc;
		ND_PRINT((ndo, ", seq %u", EXTRACT_32BITS(bp)));
		bp += 4;
		len -= 4;
	}

	if (flags & GRE_AP) {
		if (len < 4)
			goto trunc;
		ND_PRINT((ndo, ", ack %u", EXTRACT_32BITS(bp)));
		bp += 4;
		len -= 4;
	}

	if ((flags & GRE_SP) == 0)
		ND_PRINT((ndo, ", no-payload"));

        if (ndo->ndo_eflag)
            ND_PRINT((ndo, ", proto %s (0x%04x)", tok2str(ethertype_values,"unknown",prot), prot));


        ND_PRINT((ndo, ", length %u",length));

        if ((flags & GRE_SP) == 0)
            return;

        if (ndo->ndo_vflag < 1)
            ND_PRINT((ndo, ": ")); 
        else ND_PRINT((ndo, "\n\t"));

	switch (prot) {
	case ETHERTYPE_PPP:
		ppp_print(ndo, bp, len);
		break;
	default:
		ND_PRINT((ndo, "gre-proto-0x%x", prot));
		break;
	}
	return;

trunc:
	ND_PRINT((ndo, "%s", tstr));
}

static void gre_sre_print(netdissect_options *ndo, uint16_t af, uint8_t sreoff, uint8_t srelen, const u_char *bp, u_int len)

{
	switch (af) {
	case GRESRE_IP:
		ND_PRINT((ndo, ", (rtaf=ip"));
		gre_sre_ip_print(ndo, sreoff, srelen, bp, len);
		ND_PRINT((ndo, ")"));
		break;
	case GRESRE_ASN:
		ND_PRINT((ndo, ", (rtaf=asn"));
		gre_sre_asn_print(ndo, sreoff, srelen, bp, len);
		ND_PRINT((ndo, ")"));
		break;
	default:
		ND_PRINT((ndo, ", (rtaf=0x%x)", af));
	}
}

static void gre_sre_ip_print(netdissect_options *ndo, uint8_t sreoff, uint8_t srelen, const u_char *bp, u_int len)

{
	const u_char *up = bp;
	char buf[INET_ADDRSTRLEN];

	if (sreoff & 3) {
		ND_PRINT((ndo, ", badoffset=%u", sreoff));
		return;
	}
	if (srelen & 3) {
		ND_PRINT((ndo, ", badlength=%u", srelen));
		return;
	}
	if (sreoff >= srelen) {
		ND_PRINT((ndo, ", badoff/len=%u/%u", sreoff, srelen));
		return;
	}

	for (;;) {
		if (len < 4 || srelen == 0)
			return;

		addrtostr(bp, buf, sizeof(buf));
		ND_PRINT((ndo, " %s%s", ((bp - up) == sreoff) ? "*" : "", buf));

		bp += 4;
		len -= 4;
		srelen -= 4;
	}
}

static void gre_sre_asn_print(netdissect_options *ndo, uint8_t sreoff, uint8_t srelen, const u_char *bp, u_int len)

{
	const u_char *up = bp;

	if (sreoff & 1) {
		ND_PRINT((ndo, ", badoffset=%u", sreoff));
		return;
	}
	if (srelen & 1) {
		ND_PRINT((ndo, ", badlength=%u", srelen));
		return;
	}
	if (sreoff >= srelen) {
		ND_PRINT((ndo, ", badoff/len=%u/%u", sreoff, srelen));
		return;
	}

	for (;;) {
		if (len < 2 || srelen == 0)
			return;

		ND_PRINT((ndo, " %s%x", ((bp - up) == sreoff) ? "*" : "", EXTRACT_16BITS(bp)));


		bp += 2;
		len -= 2;
		srelen -= 2;
	}
}
