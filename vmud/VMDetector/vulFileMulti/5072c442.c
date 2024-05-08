















const struct tok ethertype_values[] = {
    { ETHERTYPE_IP,		"IPv4" }, { ETHERTYPE_MPLS,		"MPLS unicast" }, { ETHERTYPE_MPLS_MULTI,	"MPLS multicast" }, { ETHERTYPE_IPV6,		"IPv6" }, { ETHERTYPE_8021Q,		"802.1Q" }, { ETHERTYPE_8021Q9100,	"802.1Q-9100" }, { ETHERTYPE_8021QinQ,	"802.1Q-QinQ" }, { ETHERTYPE_8021Q9200,	"802.1Q-9200" }, { ETHERTYPE_VMAN,		"VMAN" }, { ETHERTYPE_PUP,            "PUP" }, { ETHERTYPE_ARP,            "ARP", { ETHERTYPE_REVARP,         "Reverse ARP", { ETHERTYPE_NS,             "NS" }, { ETHERTYPE_SPRITE,         "Sprite" }, { ETHERTYPE_TRAIL,          "Trail" }, { ETHERTYPE_MOPDL,          "MOP DL" }, { ETHERTYPE_MOPRC,          "MOP RC" }, { ETHERTYPE_DN,             "DN" }, { ETHERTYPE_LAT,            "LAT" }, { ETHERTYPE_SCA,            "SCA" }, { ETHERTYPE_TEB,            "TEB" }, { ETHERTYPE_LANBRIDGE,      "Lanbridge" }, { ETHERTYPE_DECDNS,         "DEC DNS" }, { ETHERTYPE_DECDTS,         "DEC DTS" }, { ETHERTYPE_VEXP,           "VEXP" }, { ETHERTYPE_VPROD,          "VPROD" }, { ETHERTYPE_ATALK,          "Appletalk" }, { ETHERTYPE_AARP,           "Appletalk ARP" }, { ETHERTYPE_IPX,            "IPX" }, { ETHERTYPE_PPP,            "PPP" }, { ETHERTYPE_MPCP,           "MPCP" }, { ETHERTYPE_SLOW,           "Slow Protocols" }, { ETHERTYPE_PPPOED,         "PPPoE D" }, { ETHERTYPE_PPPOES,         "PPPoE S" }, { ETHERTYPE_EAPOL,          "EAPOL" }, { ETHERTYPE_RRCP,           "RRCP" }, { ETHERTYPE_MS_NLB_HB,      "MS NLB heartbeat" }, { ETHERTYPE_JUMBO,          "Jumbo" }, { ETHERTYPE_LOOPBACK,       "Loopback" }, { ETHERTYPE_ISO,            "OSI" }, { ETHERTYPE_GRE_ISO,        "GRE-OSI" }, { ETHERTYPE_CFM_OLD,        "CFM (old)" }, { ETHERTYPE_CFM,            "CFM" }, { ETHERTYPE_IEEE1905_1,     "IEEE1905.1" }, { ETHERTYPE_LLDP,           "LLDP" }, { ETHERTYPE_TIPC,           "TIPC", { ETHERTYPE_GEONET_OLD,     "GeoNet (old)", { ETHERTYPE_GEONET,         "GeoNet", { ETHERTYPE_CALM_FAST,      "CALM FAST", { ETHERTYPE_AOE,            "AoE" }, { ETHERTYPE_MEDSA,          "MEDSA" }, { 0, NULL}


















































};

static inline void ether_hdr_print(netdissect_options *ndo, const u_char *bp, u_int length)

{
	register const struct ether_header *ep;
	uint16_t length_type;

	ep = (const struct ether_header *)bp;

	ND_PRINT((ndo, "%s > %s", etheraddr_string(ndo, ESRC(ep)), etheraddr_string(ndo, EDST(ep))));


	length_type = EXTRACT_16BITS(&ep->ether_length_type);
	if (!ndo->ndo_qflag) {
	        if (length_type <= ETHERMTU) {
		        ND_PRINT((ndo, ", 802.3"));
			length = length_type;
		} else ND_PRINT((ndo, ", ethertype %s (0x%04x)", tok2str(ethertype_values,"Unknown", length_type), length_type));


        } else {
                if (length_type <= ETHERMTU) {
                        ND_PRINT((ndo, ", 802.3"));
			length = length_type;
		} else ND_PRINT((ndo, ", %s", tok2str(ethertype_values,"Unknown Ethertype (0x%04x)", length_type)));
        }

	ND_PRINT((ndo, ", length %u: ", length));
}


u_int ether_print(netdissect_options *ndo, const u_char *p, u_int length, u_int caplen, void (*print_encap_header)(netdissect_options *ndo, const u_char *), const u_char *encap_header_arg)


{
	const struct ether_header *ep;
	u_int orig_length;
	u_short length_type;
	u_int hdrlen;
	int llc_hdrlen;
	struct lladdr_info src, dst;

	if (caplen < ETHER_HDRLEN) {
		ND_PRINT((ndo, "[|ether]"));
		return (caplen);
	}
	if (length < ETHER_HDRLEN) {
		ND_PRINT((ndo, "[|ether]"));
		return (length);
	}

	if (ndo->ndo_eflag) {
		if (print_encap_header != NULL)
			(*print_encap_header)(ndo, encap_header_arg);
		ether_hdr_print(ndo, p, length);
	}
	orig_length = length;

	length -= ETHER_HDRLEN;
	caplen -= ETHER_HDRLEN;
	ep = (const struct ether_header *)p;
	p += ETHER_HDRLEN;
	hdrlen = ETHER_HDRLEN;

	src.addr = ESRC(ep);
	src.addr_string = etheraddr_string;
	dst.addr = EDST(ep);
	dst.addr_string = etheraddr_string;
	length_type = EXTRACT_16BITS(&ep->ether_length_type);

recurse:
	
	if (length_type <= ETHERMTU) {
		
		llc_hdrlen = llc_print(ndo, p, length, caplen, &src, &dst);
		if (llc_hdrlen < 0) {
			
			if (!ndo->ndo_suppress_default_print)
				ND_DEFAULTPRINT(p, caplen);
			llc_hdrlen = -llc_hdrlen;
		}
		hdrlen += llc_hdrlen;
	} else if (length_type == ETHERTYPE_8021Q  || length_type == ETHERTYPE_8021Q9100 || length_type == ETHERTYPE_8021Q9200 || length_type == ETHERTYPE_8021QinQ) {


		
		if (caplen < 4) {
			ND_PRINT((ndo, "[|vlan]"));
			return (hdrlen + caplen);
		}
		if (length < 4) {
			ND_PRINT((ndo, "[|vlan]"));
			return (hdrlen + length);
		}
	        if (ndo->ndo_eflag) {
			uint16_t tag = EXTRACT_16BITS(p);

			ND_PRINT((ndo, "%s, ", ieee8021q_tci_string(tag)));
		}

		length_type = EXTRACT_16BITS(p + 2);
		if (ndo->ndo_eflag && length_type > ETHERMTU)
			ND_PRINT((ndo, "ethertype %s, ", tok2str(ethertype_values,"0x%04x", length_type)));
		p += 4;
		length -= 4;
		caplen -= 4;
		hdrlen += 4;
		goto recurse;
	} else if (length_type == ETHERTYPE_JUMBO) {
		
		
		llc_hdrlen = llc_print(ndo, p, length, caplen, &src, &dst);
		if (llc_hdrlen < 0) {
			
			if (!ndo->ndo_suppress_default_print)
				ND_DEFAULTPRINT(p, caplen);
			llc_hdrlen = -llc_hdrlen;
		}
		hdrlen += llc_hdrlen;
	} else {
		if (ethertype_print(ndo, length_type, p, length, caplen, &src, &dst) == 0) {
			
			if (!ndo->ndo_eflag) {
				if (print_encap_header != NULL)
					(*print_encap_header)(ndo, encap_header_arg);
				ether_hdr_print(ndo, (const u_char *)ep, orig_length);
			}

			if (!ndo->ndo_suppress_default_print)
				ND_DEFAULTPRINT(p, caplen);
		}
	}
	return (hdrlen);
}


u_int ether_if_print(netdissect_options *ndo, const struct pcap_pkthdr *h, const u_char *p)

{
	return (ether_print(ndo, p, h->len, h->caplen, NULL, NULL));
}


u_int netanalyzer_if_print(netdissect_options *ndo, const struct pcap_pkthdr *h, const u_char *p)

{
	
	if (h->len < 4 || h->caplen < 4) {
		ND_PRINT((ndo, "[|netanalyzer]"));
		return (h->caplen);
	}

	
	return (4 + ether_print(ndo, p + 4, h->len - 4, h->caplen - 4, NULL, NULL));
}


u_int netanalyzer_transparent_if_print(netdissect_options *ndo, const struct pcap_pkthdr *h, const u_char *p)


{
	
	if (h->len < 12 || h->caplen < 12) {
		ND_PRINT((ndo, "[|netanalyzer-transparent]"));
		return (h->caplen);
	}

	
	return (12 + ether_print(ndo, p + 12, h->len - 12, h->caplen - 12, NULL, NULL));
}



int ethertype_print(netdissect_options *ndo, u_short ether_type, const u_char *p, u_int length, u_int caplen, const struct lladdr_info *src, const struct lladdr_info *dst)



{
	switch (ether_type) {

	case ETHERTYPE_IP:
	        ip_print(ndo, p, length);
		return (1);

	case ETHERTYPE_IPV6:
		ip6_print(ndo, p, length);
		return (1);

	case ETHERTYPE_ARP:
	case ETHERTYPE_REVARP:
	        arp_print(ndo, p, length, caplen);
		return (1);

	case ETHERTYPE_DN:
		decnet_print(ndo, p, length, caplen);
		return (1);

	case ETHERTYPE_ATALK:
		if (ndo->ndo_vflag)
			ND_PRINT((ndo, "et1 "));
		atalk_print(ndo, p, length);
		return (1);

	case ETHERTYPE_AARP:
		aarp_print(ndo, p, length);
		return (1);

	case ETHERTYPE_IPX:
		ND_PRINT((ndo, "(NOV-ETHII) "));
		ipx_print(ndo, p, length);
		return (1);

	case ETHERTYPE_ISO:
		if (length == 0 || caplen == 0) {
			ND_PRINT((ndo, " [|osi]"));
			return (1);
		}
		isoclns_print(ndo, p + 1, length - 1, caplen - 1);
		return(1);

	case ETHERTYPE_PPPOED:
	case ETHERTYPE_PPPOES:
	case ETHERTYPE_PPPOED2:
	case ETHERTYPE_PPPOES2:
		pppoe_print(ndo, p, length);
		return (1);

	case ETHERTYPE_EAPOL:
	        eap_print(ndo, p, length);
		return (1);

	case ETHERTYPE_RRCP:
	        rrcp_print(ndo, p, length, src, dst);
		return (1);

	case ETHERTYPE_PPP:
		if (length) {
			ND_PRINT((ndo, ": "));
			ppp_print(ndo, p, length);
		}
		return (1);

	case ETHERTYPE_MPCP:
	        mpcp_print(ndo, p, length);
		return (1);

	case ETHERTYPE_SLOW:
	        slow_print(ndo, p, length);
		return (1);

	case ETHERTYPE_CFM:
	case ETHERTYPE_CFM_OLD:
		cfm_print(ndo, p, length);
		return (1);

	case ETHERTYPE_LLDP:
		lldp_print(ndo, p, length);
		return (1);

        case ETHERTYPE_LOOPBACK:
		loopback_print(ndo, p, length);
                return (1);

	case ETHERTYPE_MPLS:
	case ETHERTYPE_MPLS_MULTI:
		mpls_print(ndo, p, length);
		return (1);

	case ETHERTYPE_TIPC:
		tipc_print(ndo, p, length, caplen);
		return (1);

	case ETHERTYPE_MS_NLB_HB:
		msnlb_print(ndo, p);
		return (1);

        case ETHERTYPE_GEONET_OLD:
        case ETHERTYPE_GEONET:
                geonet_print(ndo, p, length, src);
                return (1);

        case ETHERTYPE_CALM_FAST:
                calm_fast_print(ndo, p, length, src);
                return (1);

	case ETHERTYPE_AOE:
		aoe_print(ndo, p, length);
		return (1);

	case ETHERTYPE_MEDSA:
		medsa_print(ndo, p, length, caplen);
		return (1);

	case ETHERTYPE_LAT:
	case ETHERTYPE_SCA:
	case ETHERTYPE_MOPRC:
	case ETHERTYPE_MOPDL:
	case ETHERTYPE_IEEE1905_1:
		
	default:
		return (0);
	}
}




