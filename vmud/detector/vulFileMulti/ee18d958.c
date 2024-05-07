


























static const struct tok pimv1_type_str[] = {
	{ PIMV1_TYPE_QUERY,           "Query"         }, { PIMV1_TYPE_REGISTER,        "Register"      }, { PIMV1_TYPE_REGISTER_STOP,   "Register-Stop" }, { PIMV1_TYPE_JOIN_PRUNE,      "Join/Prune"    }, { PIMV1_TYPE_RP_REACHABILITY, "RP-reachable"  }, { PIMV1_TYPE_ASSERT,          "Assert"        }, { PIMV1_TYPE_GRAFT,           "Graft"         }, { PIMV1_TYPE_GRAFT_ACK,       "Graft-ACK"     }, { 0, NULL }







};














static const struct tok pimv2_type_values[] = {
    { PIMV2_TYPE_HELLO,         "Hello" }, { PIMV2_TYPE_REGISTER,      "Register" }, { PIMV2_TYPE_REGISTER_STOP, "Register Stop" }, { PIMV2_TYPE_JOIN_PRUNE,    "Join / Prune" }, { PIMV2_TYPE_BOOTSTRAP,     "Bootstrap" }, { PIMV2_TYPE_ASSERT,        "Assert" }, { PIMV2_TYPE_GRAFT,         "Graft" }, { PIMV2_TYPE_GRAFT_ACK,     "Graft Acknowledgement" }, { PIMV2_TYPE_CANDIDATE_RP,  "Candidate RP Advertisement" }, { PIMV2_TYPE_PRUNE_REFRESH, "Prune Refresh" }, { PIMV2_TYPE_DF_ELECTION,   "DF Election" }, { PIMV2_TYPE_ECMP_REDIRECT, "ECMP Redirect" }, { 0, NULL}











};











static const struct tok pimv2_hello_option_values[] = {
    { PIMV2_HELLO_OPTION_HOLDTIME,         "Hold Time" }, { PIMV2_HELLO_OPTION_LANPRUNEDELAY,    "LAN Prune Delay" }, { PIMV2_HELLO_OPTION_DR_PRIORITY_OLD,  "DR Priority (Old)" }, { PIMV2_HELLO_OPTION_DR_PRIORITY,      "DR Priority" }, { PIMV2_HELLO_OPTION_GENID,            "Generation ID" }, { PIMV2_HELLO_OPTION_REFRESH_CAP,      "State Refresh Capability" }, { PIMV2_HELLO_OPTION_BIDIR_CAP,        "Bi-Directional Capability" }, { PIMV2_HELLO_OPTION_ADDRESS_LIST,     "Address List" }, { PIMV2_HELLO_OPTION_ADDRESS_LIST_OLD, "Address List (Old)" }, { 0, NULL}








};





static const struct tok pimv2_register_flag_values[] = {
    { PIMV2_REGISTER_FLAG_BORDER, "Border" }, { PIMV2_REGISTER_FLAG_NULL, "Null" }, { 0, NULL}

};



struct pim {
	uint8_t pim_typever;
			
			


	u_char  pim_rsv;	
	u_short	pim_cksum;	
};

static void pimv2_print(netdissect_options *, register const u_char *bp, register u_int len, const u_char *);

static void pimv1_join_prune_print(netdissect_options *ndo, register const u_char *bp, register u_int len)

{
	int ngroups, njoin, nprune;
	int njp;

	
	if (ND_TTEST2(bp[0], 30) && bp[11] == 1 && ((njoin = EXTRACT_16BITS(&bp[20])) + EXTRACT_16BITS(&bp[22])) == 1) {
		int hold;

		ND_PRINT((ndo, " RPF %s ", ipaddr_string(ndo, bp)));
		hold = EXTRACT_16BITS(&bp[6]);
		if (hold != 180) {
			ND_PRINT((ndo, "Hold "));
			unsigned_relts_print(ndo, hold);
		}
		ND_PRINT((ndo, "%s (%s/%d, %s", njoin ? "Join" : "Prune", ipaddr_string(ndo, &bp[26]), bp[25] & 0x3f, ipaddr_string(ndo, &bp[12])));

		if (EXTRACT_32BITS(&bp[16]) != 0xffffffff)
			ND_PRINT((ndo, "/%s", ipaddr_string(ndo, &bp[16])));
		ND_PRINT((ndo, ") %s%s %s", (bp[24] & 0x01) ? "Sparse" : "Dense", (bp[25] & 0x80) ? " WC" : "", (bp[25] & 0x40) ? "RP" : "SPT"));


		return;
	}

	ND_TCHECK2(bp[0], sizeof(struct in_addr));
	if (ndo->ndo_vflag > 1)
		ND_PRINT((ndo, "\n"));
	ND_PRINT((ndo, " Upstream Nbr: %s", ipaddr_string(ndo, bp)));
	ND_TCHECK2(bp[6], 2);
	if (ndo->ndo_vflag > 1)
		ND_PRINT((ndo, "\n"));
	ND_PRINT((ndo, " Hold time: "));
	unsigned_relts_print(ndo, EXTRACT_16BITS(&bp[6]));
	if (ndo->ndo_vflag < 2)
		return;
	bp += 8;
	len -= 8;

	ND_TCHECK2(bp[0], 4);
	ngroups = bp[3];
	bp += 4;
	len -= 4;
	while (ngroups--) {
		
		ND_TCHECK2(bp[0], sizeof(struct in_addr));
		ND_PRINT((ndo, "\n\tGroup: %s", ipaddr_string(ndo, bp)));
		ND_TCHECK2(bp[4], sizeof(struct in_addr));
		if (EXTRACT_32BITS(&bp[4]) != 0xffffffff)
			ND_PRINT((ndo, "/%s", ipaddr_string(ndo, &bp[4])));
		ND_TCHECK2(bp[8], 4);
		njoin = EXTRACT_16BITS(&bp[8]);
		nprune = EXTRACT_16BITS(&bp[10]);
		ND_PRINT((ndo, " joined: %d pruned: %d", njoin, nprune));
		bp += 12;
		len -= 12;
		for (njp = 0; njp < (njoin + nprune); njp++) {
			const char *type;

			if (njp < njoin)
				type = "Join ";
			else type = "Prune";
			ND_TCHECK2(bp[0], 6);
			ND_PRINT((ndo, "\n\t%s %s%s%s%s/%d", type, (bp[0] & 0x01) ? "Sparse " : "Dense ", (bp[1] & 0x80) ? "WC " : "", (bp[1] & 0x40) ? "RP " : "SPT ", ipaddr_string(ndo, &bp[2]), bp[1] & 0x3f));



			bp += 6;
			len -= 6;
		}
	}
	return;
trunc:
	ND_PRINT((ndo, "[|pim]"));
	return;
}

void pimv1_print(netdissect_options *ndo, register const u_char *bp, register u_int len)

{
	register const u_char *ep;
	register u_char type;

	ep = (const u_char *)ndo->ndo_snapend;
	if (bp >= ep)
		return;

	ND_TCHECK(bp[1]);
	type = bp[1];

	ND_PRINT((ndo, " %s", tok2str(pimv1_type_str, "[type %u]", type)));
	switch (type) {
	case PIMV1_TYPE_QUERY:
		if (ND_TTEST(bp[8])) {
			switch (bp[8] >> 4) {
			case 0:
				ND_PRINT((ndo, " Dense-mode"));
				break;
			case 1:
				ND_PRINT((ndo, " Sparse-mode"));
				break;
			case 2:
				ND_PRINT((ndo, " Sparse-Dense-mode"));
				break;
			default:
				ND_PRINT((ndo, " mode-%d", bp[8] >> 4));
				break;
			}
		}
		if (ndo->ndo_vflag) {
			ND_TCHECK2(bp[10],2);
			ND_PRINT((ndo, " (Hold-time "));
			unsigned_relts_print(ndo, EXTRACT_16BITS(&bp[10]));
			ND_PRINT((ndo, ")"));
		}
		break;

	case PIMV1_TYPE_REGISTER:
		ND_TCHECK2(bp[8], 20);			
		ND_PRINT((ndo, " for %s > %s", ipaddr_string(ndo, &bp[20]), ipaddr_string(ndo, &bp[24])));
		break;
	case PIMV1_TYPE_REGISTER_STOP:
		ND_TCHECK2(bp[12], sizeof(struct in_addr));
		ND_PRINT((ndo, " for %s > %s", ipaddr_string(ndo, &bp[8]), ipaddr_string(ndo, &bp[12])));
		break;
	case PIMV1_TYPE_RP_REACHABILITY:
		if (ndo->ndo_vflag) {
			ND_TCHECK2(bp[22], 2);
			ND_PRINT((ndo, " group %s", ipaddr_string(ndo, &bp[8])));
			if (EXTRACT_32BITS(&bp[12]) != 0xffffffff)
				ND_PRINT((ndo, "/%s", ipaddr_string(ndo, &bp[12])));
			ND_PRINT((ndo, " RP %s hold ", ipaddr_string(ndo, &bp[16])));
			unsigned_relts_print(ndo, EXTRACT_16BITS(&bp[22]));
		}
		break;
	case PIMV1_TYPE_ASSERT:
		ND_TCHECK2(bp[16], sizeof(struct in_addr));
		ND_PRINT((ndo, " for %s > %s", ipaddr_string(ndo, &bp[16]), ipaddr_string(ndo, &bp[8])));
		if (EXTRACT_32BITS(&bp[12]) != 0xffffffff)
			ND_PRINT((ndo, "/%s", ipaddr_string(ndo, &bp[12])));
		ND_TCHECK2(bp[24], 4);
		ND_PRINT((ndo, " %s pref %d metric %d", (bp[20] & 0x80) ? "RP-tree" : "SPT", EXTRACT_32BITS(&bp[20]) & 0x7fffffff, EXTRACT_32BITS(&bp[24])));


		break;
	case PIMV1_TYPE_JOIN_PRUNE:
	case PIMV1_TYPE_GRAFT:
	case PIMV1_TYPE_GRAFT_ACK:
		if (ndo->ndo_vflag)
			pimv1_join_prune_print(ndo, &bp[8], len - 8);
		break;
	}
	ND_TCHECK(bp[4]);
	if ((bp[4] >> 4) != 1)
		ND_PRINT((ndo, " [v%d]", bp[4] >> 4));
	return;

trunc:
	ND_PRINT((ndo, "[|pim]"));
	return;
}


void cisco_autorp_print(netdissect_options *ndo, register const u_char *bp, register u_int len)

{
	int type;
	int numrps;
	int hold;

	ND_TCHECK(bp[0]);
	ND_PRINT((ndo, " auto-rp "));
	type = bp[0];
	switch (type) {
	case 0x11:
		ND_PRINT((ndo, "candidate-advert"));
		break;
	case 0x12:
		ND_PRINT((ndo, "mapping"));
		break;
	default:
		ND_PRINT((ndo, "type-0x%02x", type));
		break;
	}

	ND_TCHECK(bp[1]);
	numrps = bp[1];

	ND_TCHECK2(bp[2], 2);
	ND_PRINT((ndo, " Hold "));
	hold = EXTRACT_16BITS(&bp[2]);
	if (hold)
		unsigned_relts_print(ndo, EXTRACT_16BITS(&bp[2]));
	else ND_PRINT((ndo, "FOREVER"));

	

	bp += 8; len -= 8;

	

	
	while (numrps--) {
		int nentries;
		char s;

		ND_TCHECK2(bp[0], 4);
		ND_PRINT((ndo, " RP %s", ipaddr_string(ndo, bp)));
		ND_TCHECK(bp[4]);
		switch (bp[4] & 0x3) {
		case 0: ND_PRINT((ndo, " PIMv?"));
			break;
		case 1:	ND_PRINT((ndo, " PIMv1"));
			break;
		case 2:	ND_PRINT((ndo, " PIMv2"));
			break;
		case 3:	ND_PRINT((ndo, " PIMv1+2"));
			break;
		}
		if (bp[4] & 0xfc)
			ND_PRINT((ndo, " [rsvd=0x%02x]", bp[4] & 0xfc));
		ND_TCHECK(bp[5]);
		nentries = bp[5];
		bp += 6; len -= 6;
		s = ' ';
		for (; nentries; nentries--) {
			ND_TCHECK2(bp[0], 6);
			ND_PRINT((ndo, "%c%s%s/%d", s, bp[0] & 1 ? "!" : "", ipaddr_string(ndo, &bp[2]), bp[1]));
			if (bp[0] & 0x02) {
				ND_PRINT((ndo, " bidir"));
			}
			if (bp[0] & 0xfc) {
				ND_PRINT((ndo, "[rsvd=0x%02x]", bp[0] & 0xfc));
			}
			s = ',';
			bp += 6; len -= 6;
		}
	}
	return;

trunc:
	ND_PRINT((ndo, "[|autorp]"));
	return;
}

void pim_print(netdissect_options *ndo, register const u_char *bp, register u_int len, const u_char *bp2)

{
	register const u_char *ep;
	register const struct pim *pim = (const struct pim *)bp;

	ep = (const u_char *)ndo->ndo_snapend;
	if (bp >= ep)
		return;

	ND_TCHECK(pim->pim_rsv);


	switch (PIM_VER(pim->pim_typever)) {
	case 2:
		if (!ndo->ndo_vflag) {
			ND_PRINT((ndo, "PIMv%u, %s, length %u", PIM_VER(pim->pim_typever), tok2str(pimv2_type_values,"Unknown Type",PIM_TYPE(pim->pim_typever)), len));


			return;
		} else {
			ND_PRINT((ndo, "PIMv%u, length %u\n\t%s", PIM_VER(pim->pim_typever), len, tok2str(pimv2_type_values,"Unknown Type",PIM_TYPE(pim->pim_typever))));


			pimv2_print(ndo, bp, len, bp2);
		}
		break;
	default:
		ND_PRINT((ndo, "PIMv%u, length %u", PIM_VER(pim->pim_typever), len));

		break;
	}
	return;
}



static int pimv2_addr_len;

enum pimv2_addrtype {
	pimv2_unicast, pimv2_group, pimv2_source };


static int pimv2_addr_print(netdissect_options *ndo, const u_char *bp, enum pimv2_addrtype at, int silent)

{
	int af;
	int len, hdrlen;

	ND_TCHECK(bp[0]);

	if (pimv2_addr_len == 0) {
		ND_TCHECK(bp[1]);
		switch (bp[0]) {
		case 1:
			af = AF_INET;
			len = sizeof(struct in_addr);
			break;
		case 2:
			af = AF_INET6;
			len = sizeof(struct in6_addr);
			break;
		default:
			return -1;
		}
		if (bp[1] != 0)
			return -1;
		hdrlen = 2;
	} else {
		switch (pimv2_addr_len) {
		case sizeof(struct in_addr):
			af = AF_INET;
			break;
		case sizeof(struct in6_addr):
			af = AF_INET6;
			break;
		default:
			return -1;
			break;
		}
		len = pimv2_addr_len;
		hdrlen = 0;
	}

	bp += hdrlen;
	switch (at) {
	case pimv2_unicast:
		ND_TCHECK2(bp[0], len);
		if (af == AF_INET) {
			if (!silent)
				ND_PRINT((ndo, "%s", ipaddr_string(ndo, bp)));
		}
		else if (af == AF_INET6) {
			if (!silent)
				ND_PRINT((ndo, "%s", ip6addr_string(ndo, bp)));
		}
		return hdrlen + len;
	case pimv2_group:
	case pimv2_source:
		ND_TCHECK2(bp[0], len + 2);
		if (af == AF_INET) {
			if (!silent) {
				ND_PRINT((ndo, "%s", ipaddr_string(ndo, bp + 2)));
				if (bp[1] != 32)
					ND_PRINT((ndo, "/%u", bp[1]));
			}
		}
		else if (af == AF_INET6) {
			if (!silent) {
				ND_PRINT((ndo, "%s", ip6addr_string(ndo, bp + 2)));
				if (bp[1] != 128)
					ND_PRINT((ndo, "/%u", bp[1]));
			}
		}
		if (bp[0] && !silent) {
			if (at == pimv2_group) {
				ND_PRINT((ndo, "(0x%02x)", bp[0]));
			} else {
				ND_PRINT((ndo, "(%s%s%s", bp[0] & 0x04 ? "S" : "", bp[0] & 0x02 ? "W" : "", bp[0] & 0x01 ? "R" : ""));


				if (bp[0] & 0xf8) {
					ND_PRINT((ndo, "+0x%02x", bp[0] & 0xf8));
				}
				ND_PRINT((ndo, ")"));
			}
		}
		return hdrlen + 2 + len;
	default:
		return -1;
	}
trunc:
	return -1;
}

enum checksum_status {
	CORRECT, INCORRECT, UNVERIFIED };



static enum checksum_status pimv2_check_checksum(netdissect_options *ndo, const u_char *bp, const u_char *bp2, u_int len)

{
	const struct ip *ip;
	u_int cksum;

	if (!ND_TTEST2(bp[0], len)) {
		
		return (UNVERIFIED);
	}
	ip = (const struct ip *)bp2;
	if (IP_V(ip) == 4) {
		struct cksum_vec vec[1];

		vec[0].ptr = bp;
		vec[0].len = len;
		cksum = in_cksum(vec, 1);
		return (cksum ? INCORRECT : CORRECT);
	} else if (IP_V(ip) == 6) {
		const struct ip6_hdr *ip6;

		ip6 = (const struct ip6_hdr *)bp2;
		cksum = nextproto6_cksum(ndo, ip6, bp, len, len, IPPROTO_PIM);
		return (cksum ? INCORRECT : CORRECT);
	} else {
		return (UNVERIFIED);
	}
}

static void pimv2_print(netdissect_options *ndo, register const u_char *bp, register u_int len, const u_char *bp2)

{
	register const u_char *ep;
	register const struct pim *pim = (const struct pim *)bp;
	int advance;
	enum checksum_status cksum_status;

	ep = (const u_char *)ndo->ndo_snapend;
	if (bp >= ep)
		return;
	if (ep > bp + len)
		ep = bp + len;
	ND_TCHECK(pim->pim_rsv);
	pimv2_addr_len = pim->pim_rsv;
	if (pimv2_addr_len != 0)
		ND_PRINT((ndo, ", RFC2117-encoding"));

	ND_PRINT((ndo, ", cksum 0x%04x ", EXTRACT_16BITS(&pim->pim_cksum)));
	if (EXTRACT_16BITS(&pim->pim_cksum) == 0) {
		ND_PRINT((ndo, "(unverified)"));
	} else {
		if (PIM_TYPE(pim->pim_typever) == PIMV2_TYPE_REGISTER) {
			
			cksum_status = pimv2_check_checksum(ndo, bp, bp2, 8);
			if (cksum_status == INCORRECT) {
				
				cksum_status = pimv2_check_checksum(ndo, bp, bp2, len);
			}
		} else {
			
			cksum_status = pimv2_check_checksum(ndo, bp, bp2, len);
		}
		switch (cksum_status) {

		case CORRECT:
			ND_PRINT((ndo, "(correct)"));
			break;

		case INCORRECT:
			ND_PRINT((ndo, "(incorrect)"));
			break;

		case UNVERIFIED:
			ND_PRINT((ndo, "(unverified)"));
			break;
		}
	}

	switch (PIM_TYPE(pim->pim_typever)) {
	case PIMV2_TYPE_HELLO:
	    {
		uint16_t otype, olen;
		bp += 4;
		while (bp < ep) {
			ND_TCHECK2(bp[0], 4);
			otype = EXTRACT_16BITS(&bp[0]);
			olen = EXTRACT_16BITS(&bp[2]);
			ND_TCHECK2(bp[0], 4 + olen);
			ND_PRINT((ndo, "\n\t  %s Option (%u), length %u, Value: ", tok2str(pimv2_hello_option_values, "Unknown", otype), otype, olen));


			bp += 4;

			switch (otype) {
			case PIMV2_HELLO_OPTION_HOLDTIME:
				if (olen != 2) {
					ND_PRINT((ndo, "ERROR: Option Length != 2 Bytes (%u)", olen));
				} else {
					unsigned_relts_print(ndo, EXTRACT_16BITS(bp));
				}
				break;

			case PIMV2_HELLO_OPTION_LANPRUNEDELAY:
				if (olen != 4) {
					ND_PRINT((ndo, "ERROR: Option Length != 4 Bytes (%u)", olen));
				} else {
					char t_bit;
					uint16_t lan_delay, override_interval;
					lan_delay = EXTRACT_16BITS(bp);
					override_interval = EXTRACT_16BITS(bp+2);
					t_bit = (lan_delay & 0x8000)? 1 : 0;
					lan_delay &= ~0x8000;
					ND_PRINT((ndo, "\n\t    T-bit=%d, LAN delay %dms, Override interval %dms", t_bit, lan_delay, override_interval));
				}
				break;

			case PIMV2_HELLO_OPTION_DR_PRIORITY_OLD:
			case PIMV2_HELLO_OPTION_DR_PRIORITY:
				switch (olen) {
				case 0:
					ND_PRINT((ndo, "Bi-Directional Capability (Old)"));
					break;
				case 4:
					ND_PRINT((ndo, "%u", EXTRACT_32BITS(bp)));
					break;
				default:
					ND_PRINT((ndo, "ERROR: Option Length != 4 Bytes (%u)", olen));
					break;
				}
				break;

			case PIMV2_HELLO_OPTION_GENID:
				if (olen != 4) {
					ND_PRINT((ndo, "ERROR: Option Length != 4 Bytes (%u)", olen));
				} else {
					ND_PRINT((ndo, "0x%08x", EXTRACT_32BITS(bp)));
				}
				break;

			case PIMV2_HELLO_OPTION_REFRESH_CAP:
				if (olen != 4) {
					ND_PRINT((ndo, "ERROR: Option Length != 4 Bytes (%u)", olen));
				} else {
					ND_PRINT((ndo, "v%d", *bp));
					if (*(bp+1) != 0) {
						ND_PRINT((ndo, ", interval "));
						unsigned_relts_print(ndo, *(bp+1));
					}
					if (EXTRACT_16BITS(bp+2) != 0) {
						ND_PRINT((ndo, " ?0x%04x?", EXTRACT_16BITS(bp+2)));
					}
				}
				break;

			case  PIMV2_HELLO_OPTION_BIDIR_CAP:
				break;

			case PIMV2_HELLO_OPTION_ADDRESS_LIST_OLD:
			case PIMV2_HELLO_OPTION_ADDRESS_LIST:
				if (ndo->ndo_vflag > 1) {
					const u_char *ptr = bp;
					while (ptr < (bp+olen)) {
						ND_PRINT((ndo, "\n\t    "));
						advance = pimv2_addr_print(ndo, ptr, pimv2_unicast, 0);
						if (advance < 0) {
							ND_PRINT((ndo, "..."));
							break;
						}
						ptr += advance;
					}
				}
				break;
			default:
				if (ndo->ndo_vflag <= 1)
					print_unknown_data(ndo, bp, "\n\t    ", olen);
				break;
			}
			
			if (ndo->ndo_vflag> 1)
				print_unknown_data(ndo, bp, "\n\t    ", olen);
			bp += olen;
		}
		break;
	    }

	case PIMV2_TYPE_REGISTER:
	{
		const struct ip *ip;

		ND_TCHECK2(*(bp + 4), PIMV2_REGISTER_FLAG_LEN);

		ND_PRINT((ndo, ", Flags [ %s ]\n\t", tok2str(pimv2_register_flag_values, "none", EXTRACT_32BITS(bp+4))));



		bp += 8; len -= 8;
		
		ip = (const struct ip *)bp;
		switch (IP_V(ip)) {
                case 0: 
			ND_PRINT((ndo, "IP-Null-header %s > %s", ipaddr_string(ndo, &ip->ip_src), ipaddr_string(ndo, &ip->ip_dst)));

			break;

		case 4:	
			ip_print(ndo, bp, len);
			break;

		case 6:	
			ip6_print(ndo, bp, len);
			break;

		default:
			ND_PRINT((ndo, "IP ver %d", IP_V(ip)));
			break;
		}
		break;
	}

	case PIMV2_TYPE_REGISTER_STOP:
		bp += 4; len -= 4;
		if (bp >= ep)
			break;
		ND_PRINT((ndo, " group="));
		if ((advance = pimv2_addr_print(ndo, bp, pimv2_group, 0)) < 0) {
			ND_PRINT((ndo, "..."));
			break;
		}
		bp += advance; len -= advance;
		if (bp >= ep)
			break;
		ND_PRINT((ndo, " source="));
		if ((advance = pimv2_addr_print(ndo, bp, pimv2_unicast, 0)) < 0) {
			ND_PRINT((ndo, "..."));
			break;
		}
		bp += advance; len -= advance;
		break;

	case PIMV2_TYPE_JOIN_PRUNE:
	case PIMV2_TYPE_GRAFT:
	case PIMV2_TYPE_GRAFT_ACK:


        

	    {
		uint8_t ngroup;
		uint16_t holdtime;
		uint16_t njoin;
		uint16_t nprune;
		int i, j;

		bp += 4; len -= 4;
		if (PIM_TYPE(pim->pim_typever) != 7) {	
			if (bp >= ep)
				break;
			ND_PRINT((ndo, ", upstream-neighbor: "));
			if ((advance = pimv2_addr_print(ndo, bp, pimv2_unicast, 0)) < 0) {
				ND_PRINT((ndo, "..."));
				break;
			}
			bp += advance; len -= advance;
		}
		if (bp + 4 > ep)
			break;
		ngroup = bp[1];
		holdtime = EXTRACT_16BITS(&bp[2]);
		ND_PRINT((ndo, "\n\t  %u group(s)", ngroup));
		if (PIM_TYPE(pim->pim_typever) != 7) {	
			ND_PRINT((ndo, ", holdtime: "));
			if (holdtime == 0xffff)
				ND_PRINT((ndo, "infinite"));
			else unsigned_relts_print(ndo, holdtime);
		}
		bp += 4; len -= 4;
		for (i = 0; i < ngroup; i++) {
			if (bp >= ep)
				goto jp_done;
			ND_PRINT((ndo, "\n\t    group #%u: ", i+1));
			if ((advance = pimv2_addr_print(ndo, bp, pimv2_group, 0)) < 0) {
				ND_PRINT((ndo, "...)"));
				goto jp_done;
			}
			bp += advance; len -= advance;
			if (bp + 4 > ep) {
				ND_PRINT((ndo, "...)"));
				goto jp_done;
			}
			njoin = EXTRACT_16BITS(&bp[0]);
			nprune = EXTRACT_16BITS(&bp[2]);
			ND_PRINT((ndo, ", joined sources: %u, pruned sources: %u", njoin, nprune));
			bp += 4; len -= 4;
			for (j = 0; j < njoin; j++) {
				ND_PRINT((ndo, "\n\t      joined source #%u: ", j+1));
				if ((advance = pimv2_addr_print(ndo, bp, pimv2_source, 0)) < 0) {
					ND_PRINT((ndo, "...)"));
					goto jp_done;
				}
				bp += advance; len -= advance;
			}
			for (j = 0; j < nprune; j++) {
				ND_PRINT((ndo, "\n\t      pruned source #%u: ", j+1));
				if ((advance = pimv2_addr_print(ndo, bp, pimv2_source, 0)) < 0) {
					ND_PRINT((ndo, "...)"));
					goto jp_done;
				}
				bp += advance; len -= advance;
			}
		}
	jp_done:
		break;
	    }

	case PIMV2_TYPE_BOOTSTRAP:
	{
		int i, j, frpcnt;
		bp += 4;

		
		if (bp + sizeof(uint16_t) >= ep) break;
		ND_PRINT((ndo, " tag=%x", EXTRACT_16BITS(bp)));
		bp += sizeof(uint16_t);
		if (bp >= ep) break;
		ND_PRINT((ndo, " hashmlen=%d", bp[0]));
		if (bp + 1 >= ep) break;
		ND_PRINT((ndo, " BSRprio=%d", bp[1]));
		bp += 2;

		
		if (bp >= ep) break;
		ND_PRINT((ndo, " BSR="));
		if ((advance = pimv2_addr_print(ndo, bp, pimv2_unicast, 0)) < 0) {
			ND_PRINT((ndo, "..."));
			break;
		}
		bp += advance;

		for (i = 0; bp < ep; i++) {
			
			ND_PRINT((ndo, " (group%d: ", i));
			if ((advance = pimv2_addr_print(ndo, bp, pimv2_group, 0))
			    < 0) {
				ND_PRINT((ndo, "...)"));
				goto bs_done;
			}
			bp += advance;

			
			if (bp >= ep) {
				ND_PRINT((ndo, "...)"));
				goto bs_done;
			}
			ND_PRINT((ndo, " RPcnt=%d", bp[0]));
			if (bp + 1 >= ep) {
				ND_PRINT((ndo, "...)"));
				goto bs_done;
			}
			ND_PRINT((ndo, " FRPcnt=%d", frpcnt = bp[1]));
			bp += 4;

			for (j = 0; j < frpcnt && bp < ep; j++) {
				
				ND_PRINT((ndo, " RP%d=", j));
				if ((advance = pimv2_addr_print(ndo, bp, pimv2_unicast, 0)) < 0) {

					ND_PRINT((ndo, "...)"));
					goto bs_done;
				}
				bp += advance;

				if (bp + 1 >= ep) {
					ND_PRINT((ndo, "...)"));
					goto bs_done;
				}
				ND_PRINT((ndo, ",holdtime="));
				unsigned_relts_print(ndo, EXTRACT_16BITS(bp));
				if (bp + 2 >= ep) {
					ND_PRINT((ndo, "...)"));
					goto bs_done;
				}
				ND_PRINT((ndo, ",prio=%d", bp[2]));
				bp += 4;
			}
			ND_PRINT((ndo, ")"));
		}
	   bs_done:
		break;
	}
	case PIMV2_TYPE_ASSERT:
		bp += 4; len -= 4;
		if (bp >= ep)
			break;
		ND_PRINT((ndo, " group="));
		if ((advance = pimv2_addr_print(ndo, bp, pimv2_group, 0)) < 0) {
			ND_PRINT((ndo, "..."));
			break;
		}
		bp += advance; len -= advance;
		if (bp >= ep)
			break;
		ND_PRINT((ndo, " src="));
		if ((advance = pimv2_addr_print(ndo, bp, pimv2_unicast, 0)) < 0) {
			ND_PRINT((ndo, "..."));
			break;
		}
		bp += advance; len -= advance;
		if (bp + 8 > ep)
			break;
		if (bp[0] & 0x80)
			ND_PRINT((ndo, " RPT"));
		ND_PRINT((ndo, " pref=%u", EXTRACT_32BITS(&bp[0]) & 0x7fffffff));
		ND_PRINT((ndo, " metric=%u", EXTRACT_32BITS(&bp[4])));
		break;

	case PIMV2_TYPE_CANDIDATE_RP:
	{
		int i, pfxcnt;
		bp += 4;

		
		if (bp >= ep) break;
		ND_PRINT((ndo, " prefix-cnt=%d", bp[0]));
		pfxcnt = bp[0];
		if (bp + 1 >= ep) break;
		ND_PRINT((ndo, " prio=%d", bp[1]));
		if (bp + 3 >= ep) break;
		ND_PRINT((ndo, " holdtime="));
		unsigned_relts_print(ndo, EXTRACT_16BITS(&bp[2]));
		bp += 4;

		
		if (bp >= ep) break;
		ND_PRINT((ndo, " RP="));
		if ((advance = pimv2_addr_print(ndo, bp, pimv2_unicast, 0)) < 0) {
			ND_PRINT((ndo, "..."));
			break;
		}
		bp += advance;

		
		for (i = 0; i < pfxcnt && bp < ep; i++) {
			ND_PRINT((ndo, " Group%d=", i));
			if ((advance = pimv2_addr_print(ndo, bp, pimv2_group, 0))
			    < 0) {
				ND_PRINT((ndo, "..."));
				break;
			}
			bp += advance;
		}
		break;
	}

	case PIMV2_TYPE_PRUNE_REFRESH:
		ND_PRINT((ndo, " src="));
		if ((advance = pimv2_addr_print(ndo, bp, pimv2_unicast, 0)) < 0) {
			ND_PRINT((ndo, "..."));
			break;
		}
		bp += advance;
		ND_PRINT((ndo, " grp="));
		if ((advance = pimv2_addr_print(ndo, bp, pimv2_group, 0)) < 0) {
			ND_PRINT((ndo, "..."));
			break;
		}
		bp += advance;
		ND_PRINT((ndo, " forwarder="));
		if ((advance = pimv2_addr_print(ndo, bp, pimv2_unicast, 0)) < 0) {
			ND_PRINT((ndo, "..."));
			break;
		}
		bp += advance;
		ND_TCHECK2(bp[0], 2);
		ND_PRINT((ndo, " TUNR "));
		unsigned_relts_print(ndo, EXTRACT_16BITS(bp));
		break;


	 default:
		ND_PRINT((ndo, " [type %d]", PIM_TYPE(pim->pim_typever)));
		break;
	}

	return;

trunc:
	ND_PRINT((ndo, "[|pim]"));
}


