



















static void ip6_finddst(netdissect_options *ndo, struct in6_addr *dst, const struct ip6_hdr *ip6)

{
	const u_char *cp;
	int advance;
	u_int nh;
	const void *dst_addr;
	const struct ip6_rthdr *dp;
	const struct ip6_rthdr0 *dp0;
	const struct in6_addr *addr;
	int i, len;

	cp = (const u_char *)ip6;
	advance = sizeof(struct ip6_hdr);
	nh = ip6->ip6_nxt;
	dst_addr = (const void *)&ip6->ip6_dst;

	while (cp < ndo->ndo_snapend) {
		cp += advance;

		switch (nh) {

		case IPPROTO_HOPOPTS:
		case IPPROTO_DSTOPTS:
		case IPPROTO_MOBILITY_OLD:
		case IPPROTO_MOBILITY:
			
			ND_TCHECK2(*cp, 2);
			advance = (int)((*(cp + 1) + 1) << 3);
			nh = *cp;
			break;

		case IPPROTO_FRAGMENT:
			
			ND_TCHECK2(*cp, 1);
			advance = sizeof(struct ip6_frag);
			nh = *cp;
			break;

		case IPPROTO_ROUTING:
			
			dp = (const struct ip6_rthdr *)cp;
			ND_TCHECK(*dp);
			len = dp->ip6r_len;
			switch (dp->ip6r_type) {

			case IPV6_RTHDR_TYPE_0:
			case IPV6_RTHDR_TYPE_2:		
				dp0 = (const struct ip6_rthdr0 *)dp;
				if (len % 2 == 1)
					goto trunc;
				len >>= 1;
				addr = &dp0->ip6r0_addr[0];
				for (i = 0; i < len; i++) {
					if ((const u_char *)(addr + 1) > ndo->ndo_snapend)
						goto trunc;

					dst_addr = (const void *)addr;
					addr++;
				}
				break;

			default:
				break;
			}

			
			goto done;

		case IPPROTO_AH:
		case IPPROTO_ESP:
		case IPPROTO_IPCOMP:
		default:
			
			goto done;
		}
	}

done:
trunc:
	UNALIGNED_MEMCPY(dst, dst_addr, sizeof(struct in6_addr));
}


int nextproto6_cksum(netdissect_options *ndo, const struct ip6_hdr *ip6, const uint8_t *data, u_int len, u_int covlen, u_int next_proto)


{
        struct {
                struct in6_addr ph_src;
                struct in6_addr ph_dst;
                uint32_t       ph_len;
                uint8_t        ph_zero[3];
                uint8_t        ph_nxt;
        } ph;
        struct cksum_vec vec[2];

        
        memset(&ph, 0, sizeof(ph));
        UNALIGNED_MEMCPY(&ph.ph_src, &ip6->ip6_src, sizeof (struct in6_addr));
        switch (ip6->ip6_nxt) {

        case IPPROTO_HOPOPTS:
        case IPPROTO_DSTOPTS:
        case IPPROTO_MOBILITY_OLD:
        case IPPROTO_MOBILITY:
        case IPPROTO_FRAGMENT:
        case IPPROTO_ROUTING:
                
                ip6_finddst(ndo, &ph.ph_dst, ip6);
                break;

        default:
                UNALIGNED_MEMCPY(&ph.ph_dst, &ip6->ip6_dst, sizeof (struct in6_addr));
                break;
        }
        ph.ph_len = htonl(len);
        ph.ph_nxt = next_proto;

        vec[0].ptr = (const uint8_t *)(void *)&ph;
        vec[0].len = sizeof(ph);
        vec[1].ptr = data;
        vec[1].len = covlen;

        return in_cksum(vec, 2);
}


void ip6_print(netdissect_options *ndo, const u_char *bp, u_int length)
{
	register const struct ip6_hdr *ip6;
	register int advance;
	u_int len;
	const u_char *ipend;
	register const u_char *cp;
	register u_int payload_len;
	int nh;
	int fragmented = 0;
	u_int flow;

	ip6 = (const struct ip6_hdr *)bp;

	ND_TCHECK(*ip6);
	if (length < sizeof (struct ip6_hdr)) {
		ND_PRINT((ndo, "truncated-ip6 %u", length));
		return;
	}

        if (!ndo->ndo_eflag)
            ND_PRINT((ndo, "IP6 "));

	if (IP6_VERSION(ip6) != 6) {
          ND_PRINT((ndo,"version error: %u != 6", IP6_VERSION(ip6)));
          return;
	}

	payload_len = EXTRACT_16BITS(&ip6->ip6_plen);
	len = payload_len + sizeof(struct ip6_hdr);
	if (length < len)
		ND_PRINT((ndo, "truncated-ip6 - %u bytes missing!", len - length));

        if (ndo->ndo_vflag) {
            flow = EXTRACT_32BITS(&ip6->ip6_flow);
            ND_PRINT((ndo, "("));

            
            if (flow & 0x0f000000)
		ND_PRINT((ndo, "pri 0x%02x, ", (flow & 0x0f000000) >> 24));
            if (flow & 0x00ffffff)
		ND_PRINT((ndo, "flowlabel 0x%06x, ", flow & 0x00ffffff));

            
            if (flow & 0x0ff00000)
		ND_PRINT((ndo, "class 0x%02x, ", (flow & 0x0ff00000) >> 20));
            if (flow & 0x000fffff)
		ND_PRINT((ndo, "flowlabel 0x%05x, ", flow & 0x000fffff));


            ND_PRINT((ndo, "hlim %u, next-header %s (%u) payload length: %u) ", ip6->ip6_hlim, tok2str(ipproto_values,"unknown",ip6->ip6_nxt), ip6->ip6_nxt, payload_len));



        }

	
	ipend = bp + len;
	if (ipend < ndo->ndo_snapend)
		ndo->ndo_snapend = ipend;

	cp = (const u_char *)ip6;
	advance = sizeof(struct ip6_hdr);
	nh = ip6->ip6_nxt;
	while (cp < ndo->ndo_snapend && advance > 0) {
		cp += advance;
		len -= advance;

		if (cp == (const u_char *)(ip6 + 1) && nh != IPPROTO_TCP && nh != IPPROTO_UDP && nh != IPPROTO_DCCP && nh != IPPROTO_SCTP) {

			ND_PRINT((ndo, "%s > %s: ", ip6addr_string(ndo, &ip6->ip6_src), ip6addr_string(ndo, &ip6->ip6_dst)));
		}

		switch (nh) {
		case IPPROTO_HOPOPTS:
			advance = hbhopt_print(ndo, cp);
			if (advance < 0)
				return;
			nh = *cp;
			break;
		case IPPROTO_DSTOPTS:
			advance = dstopt_print(ndo, cp);
			if (advance < 0)
				return;
			nh = *cp;
			break;
		case IPPROTO_FRAGMENT:
			advance = frag6_print(ndo, cp, (const u_char *)ip6);
			if (advance < 0 || ndo->ndo_snapend <= cp + advance)
				return;
			nh = *cp;
			fragmented = 1;
			break;

		case IPPROTO_MOBILITY_OLD:
		case IPPROTO_MOBILITY:
			
			advance = mobility_print(ndo, cp, (const u_char *)ip6);
			nh = *cp;
			return;
		case IPPROTO_ROUTING:
			advance = rt6_print(ndo, cp, (const u_char *)ip6);
			nh = *cp;
			break;
		case IPPROTO_SCTP:
			sctp_print(ndo, cp, (const u_char *)ip6, len);
			return;
		case IPPROTO_DCCP:
			dccp_print(ndo, cp, (const u_char *)ip6, len);
			return;
		case IPPROTO_TCP:
			tcp_print(ndo, cp, len, (const u_char *)ip6, fragmented);
			return;
		case IPPROTO_UDP:
			udp_print(ndo, cp, len, (const u_char *)ip6, fragmented);
			return;
		case IPPROTO_ICMPV6:
			icmp6_print(ndo, cp, len, (const u_char *)ip6, fragmented);
			return;
		case IPPROTO_AH:
			advance = ah_print(ndo, cp);
			nh = *cp;
			break;
		case IPPROTO_ESP:
		    {
			int enh, padlen;
			advance = esp_print(ndo, cp, len, (const u_char *)ip6, &enh, &padlen);
			nh = enh & 0xff;
			len -= padlen;
			break;
		    }
		case IPPROTO_IPCOMP:
		    {
			ipcomp_print(ndo, cp);
			
			advance = -1;
			break;
		    }

		case IPPROTO_PIM:
			pim_print(ndo, cp, len, (const u_char *)ip6);
			return;

		case IPPROTO_OSPF:
			ospf6_print(ndo, cp, len);
			return;

		case IPPROTO_IPV6:
			ip6_print(ndo, cp, len);
			return;

		case IPPROTO_IPV4:
		        ip_print(ndo, cp, len);
			return;

                case IPPROTO_PGM:
                        pgm_print(ndo, cp, len, (const u_char *)ip6);
                        return;

		case IPPROTO_GRE:
			gre_print(ndo, cp, len);
			return;

		case IPPROTO_RSVP:
			rsvp_print(ndo, cp, len);
			return;

		case IPPROTO_NONE:
			ND_PRINT((ndo, "no next header"));
			return;

		default:
			ND_PRINT((ndo, "ip-proto-%d %d", nh, len));
			return;
		}
	}

	return;
trunc:
	ND_PRINT((ndo, "[|ip6]"));
}
