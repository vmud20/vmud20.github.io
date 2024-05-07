














static const char tstr[] = "[|MOBILITY]";


struct ip6_mobility {
	uint8_t ip6m_pproto;	
	uint8_t ip6m_len;	
	uint8_t ip6m_type;	
	uint8_t reserved;	
	uint16_t ip6m_cksum;	
	union {
		uint16_t	ip6m_un_data16[1]; 
		uint8_t		ip6m_un_data8[2];  
	} ip6m_dataun;
};



















static const struct tok ip6m_str[] = {
	{ IP6M_BINDING_REQUEST,  "BRR"  }, { IP6M_HOME_TEST_INIT,   "HoTI" }, { IP6M_CAREOF_TEST_INIT, "CoTI" }, { IP6M_HOME_TEST,        "HoT"  }, { IP6M_CAREOF_TEST,      "CoT"  }, { IP6M_BINDING_UPDATE,   "BU"   }, { IP6M_BINDING_ACK,      "BA"   }, { IP6M_BINDING_ERROR,    "BE"   }, { 0, NULL }







};

static const unsigned ip6m_hdrlen[IP6M_MAX + 1] = {
	IP6M_MINLEN,       IP6M_MINLEN + 8, IP6M_MINLEN + 8, IP6M_MINLEN + 16, IP6M_MINLEN + 16, IP6M_MINLEN + 4, IP6M_MINLEN + 4, IP6M_MINLEN + 16, };





















static int mobility_opt_print(netdissect_options *ndo, const u_char *bp, const unsigned len)

{
	unsigned i, optlen;

	for (i = 0; i < len; i += optlen) {
		ND_TCHECK(bp[i]);
		if (bp[i] == IP6MOPT_PAD1)
			optlen = 1;
		else {
			if (i + 1 < len) {
				ND_TCHECK(bp[i + 1]);
				optlen = bp[i + 1] + 2;
			}
			else goto trunc;
		}
		if (i + optlen > len)
			goto trunc;
		ND_TCHECK(bp[i + optlen]);

		switch (bp[i]) {
		case IP6MOPT_PAD1:
			ND_PRINT((ndo, "(pad1)"));
			break;
		case IP6MOPT_PADN:
			if (len - i < IP6MOPT_MINLEN) {
				ND_PRINT((ndo, "(padn: trunc)"));
				goto trunc;
			}
			ND_PRINT((ndo, "(padn)"));
			break;
		case IP6MOPT_REFRESH:
			if (len - i < IP6MOPT_REFRESH_MINLEN) {
				ND_PRINT((ndo, "(refresh: trunc)"));
				goto trunc;
			}
			
			ND_PRINT((ndo, "(refresh: %u)", EXTRACT_16BITS(&bp[i+2]) << 2));
			break;
		case IP6MOPT_ALTCOA:
			if (len - i < IP6MOPT_ALTCOA_MINLEN) {
				ND_PRINT((ndo, "(altcoa: trunc)"));
				goto trunc;
			}
			ND_PRINT((ndo, "(alt-CoA: %s)", ip6addr_string(ndo, &bp[i+2])));
			break;
		case IP6MOPT_NONCEID:
			if (len - i < IP6MOPT_NONCEID_MINLEN) {
				ND_PRINT((ndo, "(ni: trunc)"));
				goto trunc;
			}
			ND_PRINT((ndo, "(ni: ho=0x%04x co=0x%04x)", EXTRACT_16BITS(&bp[i+2]), EXTRACT_16BITS(&bp[i+4])));

			break;
		case IP6MOPT_AUTH:
			if (len - i < IP6MOPT_AUTH_MINLEN) {
				ND_PRINT((ndo, "(auth: trunc)"));
				goto trunc;
			}
			ND_PRINT((ndo, "(auth)"));
			break;
		default:
			if (len - i < IP6MOPT_MINLEN) {
				ND_PRINT((ndo, "(sopt_type %u: trunc)", bp[i]));
				goto trunc;
			}
			ND_PRINT((ndo, "(type-0x%02x: len=%u)", bp[i], bp[i + 1]));
			break;
		}
	}
	return 0;

trunc:
	return 1;
}


int mobility_print(netdissect_options *ndo, const u_char *bp, const u_char *bp2 _U_)

{
	const struct ip6_mobility *mh;
	const u_char *ep;
	unsigned mhlen, hlen;
	uint8_t type;

	mh = (const struct ip6_mobility *)bp;

	
	ep = ndo->ndo_snapend;

	if (!ND_TTEST(mh->ip6m_len)) {
		
		mhlen = ep - bp;
		goto trunc;
	}
	mhlen = (mh->ip6m_len + 1) << 3;

	

	ND_TCHECK(mh->ip6m_type);
	type = mh->ip6m_type;
	if (type <= IP6M_MAX && mhlen < ip6m_hdrlen[type]) {
		ND_PRINT((ndo, "(header length %u is too small for type %u)", mhlen, type));
		goto trunc;
	}
	ND_PRINT((ndo, "mobility: %s", tok2str(ip6m_str, "type-#%u", type)));
	switch (type) {
	case IP6M_BINDING_REQUEST:
		hlen = IP6M_MINLEN;
		break;
	case IP6M_HOME_TEST_INIT:
	case IP6M_CAREOF_TEST_INIT:
		hlen = IP6M_MINLEN;
		if (ndo->ndo_vflag) {
			ND_TCHECK2(*mh, hlen + 8);
			ND_PRINT((ndo, " %s Init Cookie=%08x:%08x", type == IP6M_HOME_TEST_INIT ? "Home" : "Care-of", EXTRACT_32BITS(&bp[hlen]), EXTRACT_32BITS(&bp[hlen + 4])));


		}
		hlen += 8;
		break;
	case IP6M_HOME_TEST:
	case IP6M_CAREOF_TEST:
		ND_TCHECK(mh->ip6m_data16[0]);
		ND_PRINT((ndo, " nonce id=0x%x", EXTRACT_16BITS(&mh->ip6m_data16[0])));
		hlen = IP6M_MINLEN;
		if (ndo->ndo_vflag) {
			ND_TCHECK2(*mh, hlen + 8);
			ND_PRINT((ndo, " %s Init Cookie=%08x:%08x", type == IP6M_HOME_TEST ? "Home" : "Care-of", EXTRACT_32BITS(&bp[hlen]), EXTRACT_32BITS(&bp[hlen + 4])));


		}
		hlen += 8;
		if (ndo->ndo_vflag) {
			ND_TCHECK2(*mh, hlen + 8);
			ND_PRINT((ndo, " %s Keygen Token=%08x:%08x", type == IP6M_HOME_TEST ? "Home" : "Care-of", EXTRACT_32BITS(&bp[hlen]), EXTRACT_32BITS(&bp[hlen + 4])));


		}
		hlen += 8;
		break;
	case IP6M_BINDING_UPDATE:
		ND_TCHECK(mh->ip6m_data16[0]);
		ND_PRINT((ndo, " seq#=%u", EXTRACT_16BITS(&mh->ip6m_data16[0])));
		hlen = IP6M_MINLEN;
		ND_TCHECK2(*mh, hlen + 1);
		if (bp[hlen] & 0xf0)
			ND_PRINT((ndo, " "));
		if (bp[hlen] & 0x80)
			ND_PRINT((ndo, "A"));
		if (bp[hlen] & 0x40)
			ND_PRINT((ndo, "H"));
		if (bp[hlen] & 0x20)
			ND_PRINT((ndo, "L"));
		if (bp[hlen] & 0x10)
			ND_PRINT((ndo, "K"));
		
		hlen += 1;
		
		hlen += 1;
		ND_TCHECK2(*mh, hlen + 2);
		
		ND_PRINT((ndo, " lifetime=%u", EXTRACT_16BITS(&bp[hlen]) << 2));
		hlen += 2;
		break;
	case IP6M_BINDING_ACK:
		ND_TCHECK(mh->ip6m_data8[0]);
		ND_PRINT((ndo, " status=%u", mh->ip6m_data8[0]));
		if (mh->ip6m_data8[1] & 0x80)
			ND_PRINT((ndo, " K"));
		
		hlen = IP6M_MINLEN;
		ND_TCHECK2(*mh, hlen + 2);
		ND_PRINT((ndo, " seq#=%u", EXTRACT_16BITS(&bp[hlen])));
		hlen += 2;
		ND_TCHECK2(*mh, hlen + 2);
		
		ND_PRINT((ndo, " lifetime=%u", EXTRACT_16BITS(&bp[hlen]) << 2));
		hlen += 2;
		break;
	case IP6M_BINDING_ERROR:
		ND_TCHECK(mh->ip6m_data8[0]);
		ND_PRINT((ndo, " status=%u", mh->ip6m_data8[0]));
		
		hlen = IP6M_MINLEN;
		ND_TCHECK2(*mh, hlen + 16);
		ND_PRINT((ndo, " homeaddr %s", ip6addr_string(ndo, &bp[hlen])));
		hlen += 16;
		break;
	default:
		ND_PRINT((ndo, " len=%u", mh->ip6m_len));
		return(mhlen);
		break;
	}
	if (ndo->ndo_vflag)
		if (mobility_opt_print(ndo, &bp[hlen], mhlen - hlen))
			goto trunc;

	return(mhlen);

 trunc:
	ND_PRINT((ndo, "%s", tstr));
	return(mhlen);
}
