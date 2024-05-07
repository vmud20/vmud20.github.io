


















static const char tstr[] = "[|ip]";

static const struct tok ip_option_values[] = {
    { IPOPT_EOL, "EOL" }, { IPOPT_NOP, "NOP" }, { IPOPT_TS, "timestamp" }, { IPOPT_SECURITY, "security" }, { IPOPT_RR, "RR" }, { IPOPT_SSRR, "SSRR" }, { IPOPT_LSRR, "LSRR" }, { IPOPT_RA, "RA" }, { IPOPT_RFC1393, "traceroute" }, { 0, NULL }








};


static int ip_printroute(netdissect_options *ndo, register const u_char *cp, u_int length)

{
	register u_int ptr;
	register u_int len;

	if (length < 3) {
		ND_PRINT((ndo, " [bad length %u]", length));
		return (0);
	}
	if ((length + 1) & 3)
		ND_PRINT((ndo, " [bad length %u]", length));
	ND_TCHECK(cp[2]);
	ptr = cp[2] - 1;
	if (ptr < 3 || ((ptr + 1) & 3) || ptr > length + 1)
		ND_PRINT((ndo, " [bad ptr %u]", cp[2]));

	for (len = 3; len < length; len += 4) {
		ND_TCHECK2(cp[len], 4);
		ND_PRINT((ndo, " %s", ipaddr_string(ndo, &cp[len])));
		if (ptr > len)
			ND_PRINT((ndo, ","));
	}
	return (0);

trunc:
	return (-1);
}


static uint32_t ip_finddst(netdissect_options *ndo, const struct ip *ip)

{
	int length;
	int len;
	const u_char *cp;
	uint32_t retval;

	cp = (const u_char *)(ip + 1);
	length = (IP_HL(ip) << 2) - sizeof(struct ip);

	for (; length > 0; cp += len, length -= len) {
		int tt;

		ND_TCHECK(*cp);
		tt = *cp;
		if (tt == IPOPT_EOL)
			break;
		else if (tt == IPOPT_NOP)
			len = 1;
		else {
			ND_TCHECK(cp[1]);
			len = cp[1];
			if (len < 2)
				break;
		}
		ND_TCHECK2(*cp, len);
		switch (tt) {

		case IPOPT_SSRR:
		case IPOPT_LSRR:
			if (len < 7)
				break;
			UNALIGNED_MEMCPY(&retval, cp + len - 4, 4);
			return retval;
		}
	}
trunc:
	UNALIGNED_MEMCPY(&retval, &ip->ip_dst, sizeof(uint32_t));
	return retval;
}


int nextproto4_cksum(netdissect_options *ndo, const struct ip *ip, const uint8_t *data, u_int len, u_int covlen, u_int next_proto)


{
	struct phdr {
		uint32_t src;
		uint32_t dst;
		u_char mbz;
		u_char proto;
		uint16_t len;
	} ph;
	struct cksum_vec vec[2];

	
	ph.len = htons((uint16_t)len);
	ph.mbz = 0;
	ph.proto = next_proto;
	UNALIGNED_MEMCPY(&ph.src, &ip->ip_src, sizeof(uint32_t));
	if (IP_HL(ip) == 5)
		UNALIGNED_MEMCPY(&ph.dst, &ip->ip_dst, sizeof(uint32_t));
	else ph.dst = ip_finddst(ndo, ip);

	vec[0].ptr = (const uint8_t *)(void *)&ph;
	vec[0].len = sizeof(ph);
	vec[1].ptr = data;
	vec[1].len = covlen;
	return (in_cksum(vec, 2));
}

static void ip_printts(netdissect_options *ndo, register const u_char *cp, u_int length)

{
	register u_int ptr;
	register u_int len;
	int hoplen;
	const char *type;

	if (length < 4) {
		ND_PRINT((ndo, "[bad length %u]", length));
		return;
	}
	ND_PRINT((ndo, " TS{"));
	hoplen = ((cp[3]&0xF) != IPOPT_TS_TSONLY) ? 8 : 4;
	if ((length - 4) & (hoplen-1))
		ND_PRINT((ndo, "[bad length %u]", length));
	ptr = cp[2] - 1;
	len = 0;
	if (ptr < 4 || ((ptr - 4) & (hoplen-1)) || ptr > length + 1)
		ND_PRINT((ndo, "[bad ptr %u]", cp[2]));
	switch (cp[3]&0xF) {
	case IPOPT_TS_TSONLY:
		ND_PRINT((ndo, "TSONLY"));
		break;
	case IPOPT_TS_TSANDADDR:
		ND_PRINT((ndo, "TS+ADDR"));
		break;
	

	case 2:
		ND_PRINT((ndo, "PRESPEC2.0"));
		break;
	case 3:			
		ND_PRINT((ndo, "PRESPEC"));
		break;
	default:
		ND_PRINT((ndo, "[bad ts type %d]", cp[3]&0xF));
		goto done;
	}

	type = " ";
	for (len = 4; len < length; len += hoplen) {
		if (ptr == len)
			type = " ^ ";
		ND_PRINT((ndo, "%s%d@%s", type, EXTRACT_32BITS(&cp[len+hoplen-4]), hoplen!=8 ? "" : ipaddr_string(ndo, &cp[len])));
		type = " ";
	}

done:
	ND_PRINT((ndo, "%s", ptr == len ? " ^ " : ""));

	if (cp[3]>>4)
		ND_PRINT((ndo, " [%d hops not recorded]} ", cp[3]>>4));
	else ND_PRINT((ndo, "}"));
}


static void ip_optprint(netdissect_options *ndo, register const u_char *cp, u_int length)

{
	register u_int option_len;
	const char *sep = "";

	for (; length > 0; cp += option_len, length -= option_len) {
		u_int option_code;

		ND_PRINT((ndo, "%s", sep));
		sep = ",";

		ND_TCHECK(*cp);
		option_code = *cp;

		ND_PRINT((ndo, "%s", tok2str(ip_option_values,"unknown %u",option_code)));

		if (option_code == IPOPT_NOP || option_code == IPOPT_EOL)
			option_len = 1;

		else {
			ND_TCHECK(cp[1]);
			option_len = cp[1];
			if (option_len < 2) {
				ND_PRINT((ndo, " [bad length %u]", option_len));
				return;
			}
		}

		if (option_len > length) {
			ND_PRINT((ndo, " [bad length %u]", option_len));
			return;
		}

		ND_TCHECK2(*cp, option_len);

		switch (option_code) {
		case IPOPT_EOL:
			return;

		case IPOPT_TS:
			ip_printts(ndo, cp, option_len);
			break;

		case IPOPT_RR:       
		case IPOPT_SSRR:
		case IPOPT_LSRR:
			if (ip_printroute(ndo, cp, option_len) == -1)
				goto trunc;
			break;

		case IPOPT_RA:
			if (option_len < 4) {
				ND_PRINT((ndo, " [bad length %u]", option_len));
				break;
			}
			ND_TCHECK(cp[3]);
			if (EXTRACT_16BITS(&cp[2]) != 0)
				ND_PRINT((ndo, " value %u", EXTRACT_16BITS(&cp[2])));
			break;

		case IPOPT_NOP:       
		case IPOPT_SECURITY:
		default:
			break;
		}
	}
	return;

trunc:
	ND_PRINT((ndo, "%s", tstr));
}



static const struct tok ip_frag_values[] = {
        { IP_MF,        "+" }, { IP_DF,        "DF" }, { IP_RES,       "rsvd" }, { 0,            NULL }


};

struct ip_print_demux_state {
	const struct ip *ip;
	const u_char *cp;
	u_int   len, off;
	u_char  nh;
	int     advance;
};

static void ip_print_demux(netdissect_options *ndo, struct ip_print_demux_state *ipds)

{
	const char *p_name;

again:
	switch (ipds->nh) {

	case IPPROTO_AH:
		if (!ND_TTEST(*ipds->cp)) {
			ND_PRINT((ndo, "[|AH]"));
			break;
		}
		ipds->nh = *ipds->cp;
		ipds->advance = ah_print(ndo, ipds->cp);
		if (ipds->advance <= 0)
			break;
		ipds->cp += ipds->advance;
		ipds->len -= ipds->advance;
		goto again;

	case IPPROTO_ESP:
	{
		int enh, padlen;
		ipds->advance = esp_print(ndo, ipds->cp, ipds->len, (const u_char *)ipds->ip, &enh, &padlen);

		if (ipds->advance <= 0)
			break;
		ipds->cp += ipds->advance;
		ipds->len -= ipds->advance + padlen;
		ipds->nh = enh & 0xff;
		goto again;
	}

	case IPPROTO_IPCOMP:
	{
		ipcomp_print(ndo, ipds->cp);
		
		break;
	}

	case IPPROTO_SCTP:
		sctp_print(ndo, ipds->cp, (const u_char *)ipds->ip, ipds->len);
		break;

	case IPPROTO_DCCP:
		dccp_print(ndo, ipds->cp, (const u_char *)ipds->ip, ipds->len);
		break;

	case IPPROTO_TCP:
		
		tcp_print(ndo, ipds->cp, ipds->len, (const u_char *)ipds->ip, ipds->off & (IP_MF|IP_OFFMASK));
		break;

	case IPPROTO_UDP:
		
		udp_print(ndo, ipds->cp, ipds->len, (const u_char *)ipds->ip, ipds->off & (IP_MF|IP_OFFMASK));
		break;

	case IPPROTO_ICMP:
		
		icmp_print(ndo, ipds->cp, ipds->len, (const u_char *)ipds->ip, ipds->off & (IP_MF|IP_OFFMASK));
		break;

	case IPPROTO_PIGP:
		
		igrp_print(ndo, ipds->cp, ipds->len);
		break;

	case IPPROTO_EIGRP:
		eigrp_print(ndo, ipds->cp, ipds->len);
		break;

	case IPPROTO_ND:
		ND_PRINT((ndo, " nd %d", ipds->len));
		break;

	case IPPROTO_EGP:
		egp_print(ndo, ipds->cp, ipds->len);
		break;

	case IPPROTO_OSPF:
		ospf_print(ndo, ipds->cp, ipds->len, (const u_char *)ipds->ip);
		break;

	case IPPROTO_IGMP:
		igmp_print(ndo, ipds->cp, ipds->len);
		break;

	case IPPROTO_IPV4:
		
		ip_print(ndo, ipds->cp, ipds->len);
		if (! ndo->ndo_vflag) {
			ND_PRINT((ndo, " (ipip-proto-4)"));
			return;
		}
		break;

	case IPPROTO_IPV6:
		
		ip6_print(ndo, ipds->cp, ipds->len);
		break;

	case IPPROTO_RSVP:
		rsvp_print(ndo, ipds->cp, ipds->len);
		break;

	case IPPROTO_GRE:
		
		gre_print(ndo, ipds->cp, ipds->len);
		break;

	case IPPROTO_MOBILE:
		mobile_print(ndo, ipds->cp, ipds->len);
		break;

	case IPPROTO_PIM:
		pim_print(ndo, ipds->cp, ipds->len, (const u_char *)ipds->ip);
		break;

	case IPPROTO_VRRP:
		if (ndo->ndo_packettype == PT_CARP) {
			if (ndo->ndo_vflag)
				ND_PRINT((ndo, "carp %s > %s: ", ipaddr_string(ndo, &ipds->ip->ip_src), ipaddr_string(ndo, &ipds->ip->ip_dst)));

			carp_print(ndo, ipds->cp, ipds->len, ipds->ip->ip_ttl);
		} else {
			if (ndo->ndo_vflag)
				ND_PRINT((ndo, "vrrp %s > %s: ", ipaddr_string(ndo, &ipds->ip->ip_src), ipaddr_string(ndo, &ipds->ip->ip_dst)));

			vrrp_print(ndo, ipds->cp, ipds->len, (const u_char *)ipds->ip, ipds->ip->ip_ttl);
		}
		break;

	case IPPROTO_PGM:
		pgm_print(ndo, ipds->cp, ipds->len, (const u_char *)ipds->ip);
		break;

	default:
		if (ndo->ndo_nflag==0 && (p_name = netdb_protoname(ipds->nh)) != NULL)
			ND_PRINT((ndo, " %s", p_name));
		else ND_PRINT((ndo, " ip-proto-%d", ipds->nh));
		ND_PRINT((ndo, " %d", ipds->len));
		break;
	}
}

void ip_print_inner(netdissect_options *ndo, const u_char *bp, u_int length, u_int nh, const u_char *bp2)



{
	struct ip_print_demux_state  ipd;

	ipd.ip = (const struct ip *)bp2;
	ipd.cp = bp;
	ipd.len  = length;
	ipd.off  = 0;
	ipd.nh   = nh;
	ipd.advance = 0;

	ip_print_demux(ndo, &ipd);
}



void ip_print(netdissect_options *ndo, const u_char *bp, u_int length)


{
	struct ip_print_demux_state  ipd;
	struct ip_print_demux_state *ipds=&ipd;
	const u_char *ipend;
	u_int hlen;
	struct cksum_vec vec[1];
	uint16_t sum, ip_sum;
	const char *p_name;

	ipds->ip = (const struct ip *)bp;
	ND_TCHECK(ipds->ip->ip_vhl);
	if (IP_V(ipds->ip) != 4) { 
	    if (IP_V(ipds->ip) == 6)
	      ND_PRINT((ndo, "IP6, wrong link-layer encapsulation "));
	    else ND_PRINT((ndo, "IP%u ", IP_V(ipds->ip)));
	    return;
	}
	if (!ndo->ndo_eflag)
		ND_PRINT((ndo, "IP "));

	ND_TCHECK(*ipds->ip);
	if (length < sizeof (struct ip)) {
		ND_PRINT((ndo, "truncated-ip %u", length));
		return;
	}
	hlen = IP_HL(ipds->ip) * 4;
	if (hlen < sizeof (struct ip)) {
		ND_PRINT((ndo, "bad-hlen %u", hlen));
		return;
	}

	ipds->len = EXTRACT_16BITS(&ipds->ip->ip_len);
	if (length < ipds->len)
		ND_PRINT((ndo, "truncated-ip - %u bytes missing! ", ipds->len - length));
	if (ipds->len < hlen) {

            if (ipds->len) {
                ND_PRINT((ndo, "bad-len %u", ipds->len));
                return;
            }
            else {
                
                ipds->len = length;
            }

            ND_PRINT((ndo, "bad-len %u", ipds->len));
            return;

	}

	
	ipend = bp + ipds->len;
	if (ipend < ndo->ndo_snapend)
		ndo->ndo_snapend = ipend;

	ipds->len -= hlen;

	ipds->off = EXTRACT_16BITS(&ipds->ip->ip_off);

        if (ndo->ndo_vflag) {
            ND_PRINT((ndo, "(tos 0x%x", (int)ipds->ip->ip_tos));
            
            switch (ipds->ip->ip_tos & 0x03) {

            case 0:
                break;

            case 1:
                ND_PRINT((ndo, ",ECT(1)"));
                break;

            case 2:
                ND_PRINT((ndo, ",ECT(0)"));
                break;

            case 3:
                ND_PRINT((ndo, ",CE"));
                break;
            }

            if (ipds->ip->ip_ttl >= 1)
                ND_PRINT((ndo, ", ttl %u", ipds->ip->ip_ttl));

	    

	    ND_PRINT((ndo, ", id %u, offset %u, flags [%s], proto %s (%u)", EXTRACT_16BITS(&ipds->ip->ip_id), (ipds->off & 0x1fff) * 8, bittok2str(ip_frag_values, "none", ipds->off&0xe000), tok2str(ipproto_values,"unknown",ipds->ip->ip_p), ipds->ip->ip_p));





            ND_PRINT((ndo, ", length %u", EXTRACT_16BITS(&ipds->ip->ip_len)));

            if ((hlen - sizeof(struct ip)) > 0) {
                ND_PRINT((ndo, ", options ("));
                ip_optprint(ndo, (const u_char *)(ipds->ip + 1), hlen - sizeof(struct ip));
                ND_PRINT((ndo, ")"));
            }

	    if (!ndo->ndo_Kflag && (const u_char *)ipds->ip + hlen <= ndo->ndo_snapend) {
	        vec[0].ptr = (const uint8_t *)(const void *)ipds->ip;
	        vec[0].len = hlen;
	        sum = in_cksum(vec, 1);
		if (sum != 0) {
		    ip_sum = EXTRACT_16BITS(&ipds->ip->ip_sum);
		    ND_PRINT((ndo, ", bad cksum %x (->%x)!", ip_sum, in_cksum_shouldbe(ip_sum, sum)));
		}
	    }

		ND_PRINT((ndo, ")\n    "));
	}

	
	if ((ipds->off & 0x1fff) == 0) {
		ipds->cp = (const u_char *)ipds->ip + hlen;
		ipds->nh = ipds->ip->ip_p;

		if (ipds->nh != IPPROTO_TCP && ipds->nh != IPPROTO_UDP && ipds->nh != IPPROTO_SCTP && ipds->nh != IPPROTO_DCCP) {
			ND_PRINT((ndo, "%s > %s: ", ipaddr_string(ndo, &ipds->ip->ip_src), ipaddr_string(ndo, &ipds->ip->ip_dst)));

		}
		ip_print_demux(ndo, ipds);
	} else {
		
		if (ndo->ndo_qflag > 1)
			return;

		
		ND_PRINT((ndo, "%s > %s:", ipaddr_string(ndo, &ipds->ip->ip_src), ipaddr_string(ndo, &ipds->ip->ip_dst)));
		if (!ndo->ndo_nflag && (p_name = netdb_protoname(ipds->ip->ip_p)) != NULL)
			ND_PRINT((ndo, " %s", p_name));
		else ND_PRINT((ndo, " ip-proto-%d", ipds->ip->ip_p));
	}
	return;

trunc:
	ND_PRINT((ndo, "%s", tstr));
	return;
}

void ipN_print(netdissect_options *ndo, register const u_char *bp, register u_int length)
{
	if (length < 1) {
		ND_PRINT((ndo, "truncated-ip %d", length));
		return;
	}

	ND_TCHECK(*bp);
	switch (*bp & 0xF0) {
	case 0x40:
		ip_print (ndo, bp, length);
		break;
	case 0x60:
		ip6_print (ndo, bp, length);
		break;
	default:
		ND_PRINT((ndo, "unknown ip %d", (*bp & 0xF0) >> 4));
		break;
	}
	return;

trunc:
	ND_PRINT((ndo, "%s", tstr));
	return;
}




