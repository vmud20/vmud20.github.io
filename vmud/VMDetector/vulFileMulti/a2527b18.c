

















					














static int print_probe(netdissect_options *, const u_char *, const u_char *, u_int);
static int print_report(netdissect_options *, const u_char *, const u_char *, u_int);
static int print_neighbors(netdissect_options *, const u_char *, const u_char *, u_int);
static int print_neighbors2(netdissect_options *, const u_char *, const u_char *, u_int);
static int print_prune(netdissect_options *, const u_char *);
static int print_graft(netdissect_options *, const u_char *);
static int print_graft_ack(netdissect_options *, const u_char *);

static uint32_t target_level;

void dvmrp_print(netdissect_options *ndo, register const u_char *bp, register u_int len)

{
	register const u_char *ep;
	register u_char type;

	ep = (const u_char *)ndo->ndo_snapend;
	if (bp >= ep)
		return;

	ND_TCHECK(bp[1]);
	type = bp[1];

	
	bp += 8;
	len -= 8;

	switch (type) {

	case DVMRP_PROBE:
		ND_PRINT((ndo, " Probe"));
		if (ndo->ndo_vflag) {
			if (print_probe(ndo, bp, ep, len) < 0)
				goto trunc;
		}
		break;

	case DVMRP_REPORT:
		ND_PRINT((ndo, " Report"));
		if (ndo->ndo_vflag > 1) {
			if (print_report(ndo, bp, ep, len) < 0)
				goto trunc;
		}
		break;

	case DVMRP_ASK_NEIGHBORS:
		ND_PRINT((ndo, " Ask-neighbors(old)"));
		break;

	case DVMRP_NEIGHBORS:
		ND_PRINT((ndo, " Neighbors(old)"));
		if (print_neighbors(ndo, bp, ep, len) < 0)
			goto trunc;
		break;

	case DVMRP_ASK_NEIGHBORS2:
		ND_PRINT((ndo, " Ask-neighbors2"));
		break;

	case DVMRP_NEIGHBORS2:
		ND_PRINT((ndo, " Neighbors2"));
		
		bp -= 4;
		ND_TCHECK2(bp[0], 4);
		target_level = (bp[0] << 24) | (bp[1] << 16) | (bp[2] << 8) | bp[3];
		bp += 4;
		if (print_neighbors2(ndo, bp, ep, len) < 0)
			goto trunc;
		break;

	case DVMRP_PRUNE:
		ND_PRINT((ndo, " Prune"));
		if (print_prune(ndo, bp) < 0)
			goto trunc;
		break;

	case DVMRP_GRAFT:
		ND_PRINT((ndo, " Graft"));
		if (print_graft(ndo, bp) < 0)
			goto trunc;
		break;

	case DVMRP_GRAFT_ACK:
		ND_PRINT((ndo, " Graft-ACK"));
		if (print_graft_ack(ndo, bp) < 0)
			goto trunc;
		break;

	default:
		ND_PRINT((ndo, " [type %d]", type));
		break;
	}
	return;

trunc:
	ND_PRINT((ndo, "[|dvmrp]"));
	return;
}

static int print_report(netdissect_options *ndo, register const u_char *bp, register const u_char *ep, register u_int len)


{
	register uint32_t mask, origin;
	register int metric, done;
	register u_int i, width;

	while (len > 0) {
		if (len < 3) {
			ND_PRINT((ndo, " [|]"));
			return (0);
		}
		ND_TCHECK2(bp[0], 3);
		mask = (uint32_t)0xff << 24 | bp[0] << 16 | bp[1] << 8 | bp[2];
		width = 1;
		if (bp[0])
			width = 2;
		if (bp[1])
			width = 3;
		if (bp[2])
			width = 4;

		ND_PRINT((ndo, "\n\tMask %s", intoa(htonl(mask))));
		bp += 3;
		len -= 3;
		do {
			if (bp + width + 1 > ep) {
				ND_PRINT((ndo, " [|]"));
				return (0);
			}
			if (len < width + 1) {
				ND_PRINT((ndo, "\n\t  [Truncated Report]"));
				return (0);
			}
			origin = 0;
			for (i = 0; i < width; ++i) {
				ND_TCHECK(*bp);
				origin = origin << 8 | *bp++;
			}
			for ( ; i < 4; ++i)
				origin <<= 8;

			ND_TCHECK(*bp);
			metric = *bp++;
			done = metric & 0x80;
			metric &= 0x7f;
			ND_PRINT((ndo, "\n\t  %s metric %d", intoa(htonl(origin)), metric));
			len -= width + 1;
		} while (!done);
	}
	return (0);
trunc:
	return (-1);
}

static int print_probe(netdissect_options *ndo, register const u_char *bp, register const u_char *ep, register u_int len)


{
	register uint32_t genid;

	ND_TCHECK2(bp[0], 4);
	if ((len < 4) || ((bp + 4) > ep)) {
		
		ND_PRINT((ndo, " [|}"));
		return (0);
	}
	genid = (bp[0] << 24) | (bp[1] << 16) | (bp[2] << 8) | bp[3];
	bp += 4;
	len -= 4;
	ND_PRINT((ndo, ndo->ndo_vflag > 1 ? "\n\t" : " "));
	ND_PRINT((ndo, "genid %u", genid));
	if (ndo->ndo_vflag < 2)
		return (0);

	while ((len > 0) && (bp < ep)) {
		ND_TCHECK2(bp[0], 4);
		ND_PRINT((ndo, "\n\tneighbor %s", ipaddr_string(ndo, bp)));
		bp += 4; len -= 4;
	}
	return (0);
trunc:
	return (-1);
}

static int print_neighbors(netdissect_options *ndo, register const u_char *bp, register const u_char *ep, register u_int len)


{
	const u_char *laddr;
	register u_char metric;
	register u_char thresh;
	register int ncount;

	while (len > 0 && bp < ep) {
		ND_TCHECK2(bp[0], 7);
		laddr = bp;
		bp += 4;
		metric = *bp++;
		thresh = *bp++;
		ncount = *bp++;
		len -= 7;
		while (--ncount >= 0) {
			ND_TCHECK2(bp[0], 4);
			ND_PRINT((ndo, " [%s ->", ipaddr_string(ndo, laddr)));
			ND_PRINT((ndo, " %s, (%d/%d)]", ipaddr_string(ndo, bp), metric, thresh));
			bp += 4;
			len -= 4;
		}
	}
	return (0);
trunc:
	return (-1);
}

static int print_neighbors2(netdissect_options *ndo, register const u_char *bp, register const u_char *ep, register u_int len)


{
	const u_char *laddr;
	register u_char metric, thresh, flags;
	register int ncount;

	ND_PRINT((ndo, " (v %d.%d):", (int)target_level & 0xff, (int)(target_level >> 8) & 0xff));


	while (len > 0 && bp < ep) {
		ND_TCHECK2(bp[0], 8);
		laddr = bp;
		bp += 4;
		metric = *bp++;
		thresh = *bp++;
		flags = *bp++;
		ncount = *bp++;
		len -= 8;
		while (--ncount >= 0 && (len >= 4) && (bp + 4) <= ep) {
			ND_PRINT((ndo, " [%s -> ", ipaddr_string(ndo, laddr)));
			ND_PRINT((ndo, "%s (%d/%d", ipaddr_string(ndo, bp), metric, thresh));
			if (flags & DVMRP_NF_TUNNEL)
				ND_PRINT((ndo, "/tunnel"));
			if (flags & DVMRP_NF_SRCRT)
				ND_PRINT((ndo, "/srcrt"));
			if (flags & DVMRP_NF_QUERIER)
				ND_PRINT((ndo, "/querier"));
			if (flags & DVMRP_NF_DISABLED)
				ND_PRINT((ndo, "/disabled"));
			if (flags & DVMRP_NF_DOWN)
				ND_PRINT((ndo, "/down"));
			ND_PRINT((ndo, ")]"));
			bp += 4;
			len -= 4;
		}
		if (ncount != -1) {
			ND_PRINT((ndo, " [|]"));
			return (0);
		}
	}
	return (0);
trunc:
	return (-1);
}

static int print_prune(netdissect_options *ndo, register const u_char *bp)

{
	ND_TCHECK2(bp[0], 12);
	ND_PRINT((ndo, " src %s grp %s", ipaddr_string(ndo, bp), ipaddr_string(ndo, bp + 4)));
	bp += 8;
	ND_PRINT((ndo, " timer "));
	relts_print(ndo, EXTRACT_32BITS(bp));
	return (0);
trunc:
	return (-1);
}

static int print_graft(netdissect_options *ndo, register const u_char *bp)

{
	ND_TCHECK2(bp[0], 8);
	ND_PRINT((ndo, " src %s grp %s", ipaddr_string(ndo, bp), ipaddr_string(ndo, bp + 4)));
	return (0);
trunc:
	return (-1);
}

static int print_graft_ack(netdissect_options *ndo, register const u_char *bp)

{
	ND_TCHECK2(bp[0], 8);
	ND_PRINT((ndo, " src %s grp %s", ipaddr_string(ndo, bp), ipaddr_string(ndo, bp + 4)));
	return (0);
trunc:
	return (-1);
}
