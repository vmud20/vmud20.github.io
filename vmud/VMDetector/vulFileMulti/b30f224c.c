






























static const struct tok ppptype2str[] = {
        { PPP_IP,	  "IP" }, { PPP_OSI,	  "OSI" }, { PPP_NS,	  "NS" }, { PPP_DECNET,	  "DECNET" }, { PPP_APPLE,	  "APPLE" }, { PPP_IPX,	  "IPX" }, { PPP_VJC,	  "VJC IP" }, { PPP_VJNC,	  "VJNC IP" }, { PPP_BRPDU,	  "BRPDU" }, { PPP_STII,	  "STII" }, { PPP_VINES,	  "VINES" }, { PPP_MPLS_UCAST, "MPLS" }, { PPP_MPLS_MCAST, "MPLS" }, { PPP_COMP,       "Compressed", { PPP_ML,         "MLPPP", { PPP_IPV6,       "IP6",  { PPP_HELLO,	  "HELLO" }, { PPP_LUXCOM,	  "LUXCOM" }, { PPP_SNS,	  "SNS" }, { PPP_IPCP,	  "IPCP" }, { PPP_OSICP,	  "OSICP" }, { PPP_NSCP,	  "NSCP" }, { PPP_DECNETCP,   "DECNETCP" }, { PPP_APPLECP,	  "APPLECP" }, { PPP_IPXCP,	  "IPXCP" }, { PPP_STIICP,	  "STIICP" }, { PPP_VINESCP,	  "VINESCP" }, { PPP_IPV6CP,     "IP6CP" }, { PPP_MPLSCP,	  "MPLSCP" },  { PPP_LCP,	  "LCP" }, { PPP_PAP,	  "PAP" }, { PPP_LQM,	  "LQM" }, { PPP_CHAP,	  "CHAP" }, { PPP_EAP,	  "EAP" }, { PPP_SPAP,	  "SPAP" }, { PPP_SPAP_OLD,	  "Old-SPAP" }, { PPP_BACP,	  "BACP" }, { PPP_BAP,	  "BAP" }, { PPP_MPCP,	  "MLPPP-CP" }, { PPP_CCP,	  "CCP" }, { 0,		  NULL }









































};




















static const struct tok cpcodes[] = {
	{CPCODES_VEXT,      "Vendor-Extension",  {CPCODES_CONF_REQ,  "Conf-Request", {CPCODES_CONF_ACK,  "Conf-Ack", {CPCODES_CONF_NAK,  "Conf-Nack", {CPCODES_CONF_REJ,  "Conf-Reject", {CPCODES_TERM_REQ,  "Term-Request", {CPCODES_TERM_ACK,  "Term-Ack", {CPCODES_CODE_REJ,  "Code-Reject", {CPCODES_PROT_REJ,  "Prot-Reject", {CPCODES_ECHO_REQ,  "Echo-Request", {CPCODES_ECHO_RPL,  "Echo-Reply", {CPCODES_DISC_REQ,  "Disc-Req", {CPCODES_ID,        "Ident", {CPCODES_TIME_REM,  "Time-Rem", {CPCODES_RESET_REQ, "Reset-Req", {CPCODES_RESET_REP, "Reset-Ack", {0,                 NULL}















};






































static const char *lcpconfopts[] = {
	"Vend-Ext",		 "MRU", "ACCM", "Auth-Prot", "Qual-Prot", "Magic-Num", "deprecated(6)", "PFC", "ACFC", "FCS-Alt", "SDP", "Num-Mode", "deprecated(12)", "Call-Back", "deprecated(14)", "deprecated(15)", "deprecated(16)", "MRRU", "12-Bit seq #", "End-Disc", "Proprietary", "DCE-Id", "MP+", "Link-Disc", "LCP-Auth-Opt", "COBS", "Prefix-elision", "Multilink-header-Form", "I18N", "SDL-over-SONET/SDH", "PPP-Muxing", };






















































static const struct tok ccpconfopts_values[] = {
        { CCPOPT_OUI, "OUI" }, { CCPOPT_PRED1, "Pred-1" }, { CCPOPT_PRED2, "Pred-2" }, { CCPOPT_PJUMP, "Puddle" }, { CCPOPT_HPPPC, "HP-PPC" }, { CCPOPT_STACLZS, "Stac-LZS" }, { CCPOPT_MPPC, "MPPC" }, { CCPOPT_GFZA, "Gand-FZA" }, { CCPOPT_V42BIS, "V.42bis" }, { CCPOPT_BSDCOMP, "BSD-Comp" }, { CCPOPT_LZSDCP, "LZS-DCP" }, { CCPOPT_MVRCA, "MVRCA" }, { CCPOPT_DEC, "DEC" }, { CCPOPT_DEFLATE, "Deflate" }, { CCPOPT_RESV, "Reserved", {0,                 NULL}














};





static const struct tok bacconfopts_values[] = {
        { BACPOPT_FPEER, "Favored-Peer" }, {0,                 NULL}
};














static const struct tok ipcpopt_values[] = {
        { IPCPOPT_2ADDR, "IP-Addrs" }, { IPCPOPT_IPCOMP, "IP-Comp" }, { IPCPOPT_ADDR, "IP-Addr" }, { IPCPOPT_MOBILE4, "Home-Addr" }, { IPCPOPT_PRIDNS, "Pri-DNS" }, { IPCPOPT_PRINBNS, "Pri-NBNS" }, { IPCPOPT_SECDNS, "Sec-DNS" }, { IPCPOPT_SECNBNS, "Sec-NBNS" }, { 0,		  NULL }







};




static const struct tok ipcpopt_compproto_values[] = {
        { PPP_VJC, "VJ-Comp" }, { IPCPOPT_IPCOMP_HDRCOMP, "IP Header Compression" }, { 0,		  NULL }

};

static const struct tok ipcpopt_compproto_subopt_values[] = {
        { 1, "RTP-Compression" }, { 2, "Enhanced RTP-Compression" }, { 0,		  NULL }

};




static const struct tok ip6cpopt_values[] = {
        { IP6CP_IFID, "Interface-ID" }, { 0,		  NULL }
};















static const struct tok authalg_values[] = {
        { AUTHALG_CHAPMD5, "MD5" }, { AUTHALG_MSCHAP1, "MS-CHAPv1" }, { AUTHALG_MSCHAP2, "MS-CHAPv2" }, { 0,		  NULL }


};



















static const struct tok ppp_callback_values[] = {
        { CALLBACK_AUTH, "UserAuth" }, { CALLBACK_DSTR, "DialString" }, { CALLBACK_LID, "LocalID" }, { CALLBACK_E164, "E.164" }, { CALLBACK_X500, "X.500" }, { CALLBACK_CBCP, "CBCP" }, { 0,		  NULL }





};








static const struct tok chapcode_values[] = {
	{ CHAP_CHAL, "Challenge" }, { CHAP_RESP, "Response" }, { CHAP_SUCC, "Success" }, { CHAP_FAIL, "Fail" }, { 0, NULL}



};







static const struct tok papcode_values[] = {
        { PAP_AREQ, "Auth-Req" }, { PAP_AACK, "Auth-ACK" }, { PAP_ANAK, "Auth-NACK" }, { 0, NULL }


};











static int print_lcp_config_options(netdissect_options *, const u_char *p, int);
static int print_ipcp_config_options(netdissect_options *, const u_char *p, int);
static int print_ip6cp_config_options(netdissect_options *, const u_char *p, int);
static int print_ccp_config_options(netdissect_options *, const u_char *p, int);
static int print_bacp_config_options(netdissect_options *, const u_char *p, int);
static void handle_ppp(netdissect_options *, u_int proto, const u_char *p, int length);


static void handle_ctrl_proto(netdissect_options *ndo, u_int proto, const u_char *pptr, int length)

{
	const char *typestr;
	u_int code, len;
	int (*pfunc)(netdissect_options *, const u_char *, int);
	int x, j;
        const u_char *tptr;

        tptr=pptr;

        typestr = tok2str(ppptype2str, "unknown ctrl-proto (0x%04x)", proto);
	ND_PRINT((ndo, "%s, ", typestr));

	if (length < 4) 
		goto trunc;
	ND_TCHECK2(*tptr, 2);

	code = *tptr++;

	ND_PRINT((ndo, "%s (0x%02x), id %u, length %u", tok2str(cpcodes, "Unknown Opcode",code), code, *tptr++, length + 2));




	if (!ndo->ndo_vflag)
		return;

	if (length <= 4)
		return;    

	ND_TCHECK2(*tptr, 2);
	len = EXTRACT_16BITS(tptr);
	tptr += 2;

	ND_PRINT((ndo, "\n\tencoded length %u (=Option(s) length %u)", len, len - 4));

	if (ndo->ndo_vflag > 1)
		print_unknown_data(ndo, pptr - 2, "\n\t", 6);


	switch (code) {
	case CPCODES_VEXT:
		if (length < 11)
			break;
		ND_TCHECK2(*tptr, 4);
		ND_PRINT((ndo, "\n\t  Magic-Num 0x%08x", EXTRACT_32BITS(tptr)));
		tptr += 4;
		ND_TCHECK2(*tptr, 3);
		ND_PRINT((ndo, " Vendor: %s (%u)", tok2str(oui_values,"Unknown",EXTRACT_24BITS(tptr)), EXTRACT_24BITS(tptr)));

		
		break;
	case CPCODES_CONF_REQ:
	case CPCODES_CONF_ACK:
	case CPCODES_CONF_NAK:
	case CPCODES_CONF_REJ:
		x = len - 4;	
		do {
			switch (proto) {
			case PPP_LCP:
				pfunc = print_lcp_config_options;
				break;
			case PPP_IPCP:
				pfunc = print_ipcp_config_options;
				break;
			case PPP_IPV6CP:
				pfunc = print_ip6cp_config_options;
				break;
			case PPP_CCP:
				pfunc = print_ccp_config_options;
				break;
			case PPP_BACP:
				pfunc = print_bacp_config_options;
				break;
			default:
				
				pfunc = NULL;
				break;
			}

			if (pfunc == NULL) 
				break;

			if ((j = (*pfunc)(ndo, tptr, len)) == 0)
				break;
			x -= j;
			tptr += j;
		} while (x > 0);
		break;

	case CPCODES_TERM_REQ:
	case CPCODES_TERM_ACK:
		
		break;
	case CPCODES_CODE_REJ:
		
		break;
	case CPCODES_PROT_REJ:
		if (length < 6)
			break;
		ND_TCHECK2(*tptr, 2);
		ND_PRINT((ndo, "\n\t  Rejected %s Protocol (0x%04x)", tok2str(ppptype2str,"unknown", EXTRACT_16BITS(tptr)), EXTRACT_16BITS(tptr)));

		
		if (len > 6) {
			ND_PRINT((ndo, "\n\t  Rejected Packet"));
			print_unknown_data(ndo, tptr + 2, "\n\t    ", len - 2);
		}
		break;
	case CPCODES_ECHO_REQ:
	case CPCODES_ECHO_RPL:
	case CPCODES_DISC_REQ:
		if (length < 8)
			break;
		ND_TCHECK2(*tptr, 4);
		ND_PRINT((ndo, "\n\t  Magic-Num 0x%08x", EXTRACT_32BITS(tptr)));
		
		if (len > 8) {
			ND_PRINT((ndo, "\n\t  -----trailing data-----"));
			ND_TCHECK2(tptr[4], len - 8);
			print_unknown_data(ndo, tptr + 4, "\n\t  ", len - 8);
		}
		break;
	case CPCODES_ID:
		if (length < 8)
			break;
		ND_TCHECK2(*tptr, 4);
		ND_PRINT((ndo, "\n\t  Magic-Num 0x%08x", EXTRACT_32BITS(tptr)));
		
		if (len > 8) {
			ND_PRINT((ndo, "\n\t  Message\n\t    "));
			if (fn_printn(ndo, tptr + 4, len - 4, ndo->ndo_snapend))
				goto trunc;
		}
		break;
	case CPCODES_TIME_REM:
		if (length < 12)
			break;
		ND_TCHECK2(*tptr, 4);
		ND_PRINT((ndo, "\n\t  Magic-Num 0x%08x", EXTRACT_32BITS(tptr)));
		ND_TCHECK2(*(tptr + 4), 4);
		ND_PRINT((ndo, ", Seconds-Remaining %us", EXTRACT_32BITS(tptr + 4)));
		
		break;
	default:
		
		if (ndo->ndo_vflag <= 1)
			print_unknown_data(ndo, pptr - 2, "\n\t  ", length + 2);
		break;
	}
	return;

trunc:
	ND_PRINT((ndo, "[|%s]", typestr));
}


static int print_lcp_config_options(netdissect_options *ndo, const u_char *p, int length)

{
	int len, opt;

	if (length < 2)
		return 0;
	ND_TCHECK2(*p, 2);
	len = p[1];
	opt = p[0];
	if (length < len)
		return 0;
	if (len < 2) {
		if ((opt >= LCPOPT_MIN) && (opt <= LCPOPT_MAX))
			ND_PRINT((ndo, "\n\t  %s Option (0x%02x), length %u (length bogus, should be >= 2)", lcpconfopts[opt], opt, len));
		else ND_PRINT((ndo, "\n\tunknown LCP option 0x%02x", opt));
		return 0;
	}
	if ((opt >= LCPOPT_MIN) && (opt <= LCPOPT_MAX))
		ND_PRINT((ndo, "\n\t  %s Option (0x%02x), length %u", lcpconfopts[opt], opt, len));
	else {
		ND_PRINT((ndo, "\n\tunknown LCP option 0x%02x", opt));
		return len;
	}

	switch (opt) {
	case LCPOPT_VEXT:
		if (len < 6) {
			ND_PRINT((ndo, " (length bogus, should be >= 6)"));
			return len;
		}
		ND_TCHECK2(*(p + 2), 3);
		ND_PRINT((ndo, ": Vendor: %s (%u)", tok2str(oui_values,"Unknown",EXTRACT_24BITS(p+2)), EXTRACT_24BITS(p + 2)));


		ND_TCHECK(p[5]);
		ND_PRINT((ndo, ", kind: 0x%02x", p[5]));
		ND_PRINT((ndo, ", Value: 0x"));
		for (i = 0; i < len - 6; i++) {
			ND_TCHECK(p[6 + i]);
			ND_PRINT((ndo, "%02x", p[6 + i]));
		}

		break;
	case LCPOPT_MRU:
		if (len != 4) {
			ND_PRINT((ndo, " (length bogus, should be = 4)"));
			return len;
		}
		ND_TCHECK2(*(p + 2), 2);
		ND_PRINT((ndo, ": %u", EXTRACT_16BITS(p + 2)));
		break;
	case LCPOPT_ACCM:
		if (len != 6) {
			ND_PRINT((ndo, " (length bogus, should be = 6)"));
			return len;
		}
		ND_TCHECK2(*(p + 2), 4);
		ND_PRINT((ndo, ": 0x%08x", EXTRACT_32BITS(p + 2)));
		break;
	case LCPOPT_AP:
		if (len < 4) {
			ND_PRINT((ndo, " (length bogus, should be >= 4)"));
			return len;
		}
		ND_TCHECK2(*(p + 2), 2);
		ND_PRINT((ndo, ": %s", tok2str(ppptype2str, "Unknown Auth Proto (0x04x)", EXTRACT_16BITS(p + 2))));

		switch (EXTRACT_16BITS(p+2)) {
		case PPP_CHAP:
			ND_TCHECK(p[4]);
			ND_PRINT((ndo, ", %s", tok2str(authalg_values, "Unknown Auth Alg %u", p[4])));
			break;
		case PPP_PAP: 
		case PPP_EAP:
		case PPP_SPAP:
		case PPP_SPAP_OLD:
                        break;
		default:
			print_unknown_data(ndo, p, "\n\t", len);
		}
		break;
	case LCPOPT_QP:
		if (len < 4) {
			ND_PRINT((ndo, " (length bogus, should be >= 4)"));
			return 0;
		}
		ND_TCHECK2(*(p + 2), 2);
		if (EXTRACT_16BITS(p+2) == PPP_LQM)
			ND_PRINT((ndo, ": LQR"));
		else ND_PRINT((ndo, ": unknown"));
		break;
	case LCPOPT_MN:
		if (len != 6) {
			ND_PRINT((ndo, " (length bogus, should be = 6)"));
			return 0;
		}
		ND_TCHECK2(*(p + 2), 4);
		ND_PRINT((ndo, ": 0x%08x", EXTRACT_32BITS(p + 2)));
		break;
	case LCPOPT_PFC:
		break;
	case LCPOPT_ACFC:
		break;
	case LCPOPT_LD:
		if (len != 4) {
			ND_PRINT((ndo, " (length bogus, should be = 4)"));
			return 0;
		}
		ND_TCHECK2(*(p + 2), 2);
		ND_PRINT((ndo, ": 0x%04x", EXTRACT_16BITS(p + 2)));
		break;
	case LCPOPT_CBACK:
		if (len < 3) {
			ND_PRINT((ndo, " (length bogus, should be >= 3)"));
			return 0;
		}
		ND_PRINT((ndo, ": "));
		ND_TCHECK(p[2]);
		ND_PRINT((ndo, ": Callback Operation %s (%u)", tok2str(ppp_callback_values, "Unknown", p[2]), p[2]));

		break;
	case LCPOPT_MLMRRU:
		if (len != 4) {
			ND_PRINT((ndo, " (length bogus, should be = 4)"));
			return 0;
		}
		ND_TCHECK2(*(p + 2), 2);
		ND_PRINT((ndo, ": %u", EXTRACT_16BITS(p + 2)));
		break;
	case LCPOPT_MLED:
		if (len < 3) {
			ND_PRINT((ndo, " (length bogus, should be >= 3)"));
			return 0;
		}
		ND_TCHECK(p[2]);
		switch (p[2]) {		
		case MEDCLASS_NULL:
			ND_PRINT((ndo, ": Null"));
			break;
		case MEDCLASS_LOCAL:
			ND_PRINT((ndo, ": Local")); 
			break;
		case MEDCLASS_IPV4:
			if (len != 7) {
				ND_PRINT((ndo, " (length bogus, should be = 7)"));
				return 0;
			}
			ND_TCHECK2(*(p + 3), 4);
			ND_PRINT((ndo, ": IPv4 %s", ipaddr_string(ndo, p + 3)));
			break;
		case MEDCLASS_MAC:
			if (len != 9) {
				ND_PRINT((ndo, " (length bogus, should be = 9)"));
				return 0;
			}
			ND_TCHECK2(*(p + 3), 6);
			ND_PRINT((ndo, ": MAC %s", etheraddr_string(ndo, p + 3)));
			break;
		case MEDCLASS_MNB:
			ND_PRINT((ndo, ": Magic-Num-Block")); 
			break;
		case MEDCLASS_PSNDN:
			ND_PRINT((ndo, ": PSNDN")); 
			break;
		default:
			ND_PRINT((ndo, ": Unknown class %u", p[2]));
			break;
		}
		break;



	case LCPOPT_DEP6:
	case LCPOPT_FCSALT:
	case LCPOPT_SDP:
	case LCPOPT_NUMMODE:
	case LCPOPT_DEP12:
	case LCPOPT_DEP14:
	case LCPOPT_DEP15:
	case LCPOPT_DEP16:
        case LCPOPT_MLSSNHF:
	case LCPOPT_PROP:
	case LCPOPT_DCEID:
	case LCPOPT_MPP:
	case LCPOPT_LCPAOPT:
	case LCPOPT_COBS:
	case LCPOPT_PE:
	case LCPOPT_MLHF:
	case LCPOPT_I18N:
	case LCPOPT_SDLOS:
	case LCPOPT_PPPMUX:
		break;

	default:
		
		if (ndo->ndo_vflag < 2)
			print_unknown_data(ndo, &p[2], "\n\t    ", len - 2);
		break;
	}

	if (ndo->ndo_vflag > 1)
		print_unknown_data(ndo, &p[2], "\n\t    ", len - 2); 

	return len;

trunc:
	ND_PRINT((ndo, "[|lcp]"));
	return 0;
}


static const struct tok ppp_ml_flag_values[] = {
    { 0x80, "begin" }, { 0x40, "end" }, { 0, NULL }

};

static void handle_mlppp(netdissect_options *ndo, const u_char *p, int length)

{
    if (!ndo->ndo_eflag)
        ND_PRINT((ndo, "MLPPP, "));

    ND_PRINT((ndo, "seq 0x%03x, Flags [%s], length %u", (EXTRACT_16BITS(p))&0x0fff, bittok2str(ppp_ml_flag_values, "none", *p & 0xc0), length));


}


static void handle_chap(netdissect_options *ndo, const u_char *p, int length)

{
	u_int code, len;
	int val_size, name_size, msg_size;
	const u_char *p0;
	int i;

	p0 = p;
	if (length < 1) {
		ND_PRINT((ndo, "[|chap]"));
		return;
	} else if (length < 4) {
		ND_TCHECK(*p);
		ND_PRINT((ndo, "[|chap 0x%02x]", *p));
		return;
	}

	ND_TCHECK(*p);
	code = *p;
	ND_PRINT((ndo, "CHAP, %s (0x%02x)", tok2str(chapcode_values,"unknown",code), code));

	p++;

	ND_TCHECK(*p);
	ND_PRINT((ndo, ", id %u", *p));		
	p++;

	ND_TCHECK2(*p, 2);
	len = EXTRACT_16BITS(p);
	p += 2;

	
	switch (code) {
	case CHAP_CHAL:
	case CHAP_RESP:
		if (length - (p - p0) < 1)
			return;
		ND_TCHECK(*p);
		val_size = *p;		
		p++;
		if (length - (p - p0) < val_size)
			return;
		ND_PRINT((ndo, ", Value "));
		for (i = 0; i < val_size; i++) {
			ND_TCHECK(*p);
			ND_PRINT((ndo, "%02x", *p++));
		}
		name_size = len - (p - p0);
		ND_PRINT((ndo, ", Name "));
		for (i = 0; i < name_size; i++) {
			ND_TCHECK(*p);
			safeputchar(ndo, *p++);
		}
		break;
	case CHAP_SUCC:
	case CHAP_FAIL:
		msg_size = len - (p - p0);
		ND_PRINT((ndo, ", Msg "));
		for (i = 0; i< msg_size; i++) {
			ND_TCHECK(*p);
			safeputchar(ndo, *p++);
		}
		break;
	}
	return;

trunc:
	ND_PRINT((ndo, "[|chap]"));
}


static void handle_pap(netdissect_options *ndo, const u_char *p, int length)

{
	u_int code, len;
	int peerid_len, passwd_len, msg_len;
	const u_char *p0;
	int i;

	p0 = p;
	if (length < 1) {
		ND_PRINT((ndo, "[|pap]"));
		return;
	} else if (length < 4) {
		ND_TCHECK(*p);
		ND_PRINT((ndo, "[|pap 0x%02x]", *p));
		return;
	}

	ND_TCHECK(*p);
	code = *p;
	ND_PRINT((ndo, "PAP, %s (0x%02x)", tok2str(papcode_values, "unknown", code), code));

	p++;

	ND_TCHECK(*p);
	ND_PRINT((ndo, ", id %u", *p));		
	p++;

	ND_TCHECK2(*p, 2);
	len = EXTRACT_16BITS(p);
	p += 2;

	if ((int)len > length) {
		ND_PRINT((ndo, ", length %u > packet size", len));
		return;
	}
	length = len;
	if (length < (p - p0)) {
		ND_PRINT((ndo, ", length %u < PAP header length", length));
		return;
	}

	switch (code) {
	case PAP_AREQ:
		
		if (len < 6)
			goto trunc;
		if (length - (p - p0) < 1)
			return;
		ND_TCHECK(*p);
		peerid_len = *p;	
		p++;
		if (length - (p - p0) < peerid_len)
			return;
		ND_PRINT((ndo, ", Peer "));
		for (i = 0; i < peerid_len; i++) {
			ND_TCHECK(*p);
			safeputchar(ndo, *p++);
		}

		if (length - (p - p0) < 1)
			return;
		ND_TCHECK(*p);
		passwd_len = *p;	
		p++;
		if (length - (p - p0) < passwd_len)
			return;
		ND_PRINT((ndo, ", Name "));
		for (i = 0; i < passwd_len; i++) {
			ND_TCHECK(*p);
			safeputchar(ndo, *p++);
		}
		break;
	case PAP_AACK:
	case PAP_ANAK:
		
		if (len < 5)
			goto trunc;
		if (length - (p - p0) < 1)
			return;
		ND_TCHECK(*p);
		msg_len = *p;		
		p++;
		if (length - (p - p0) < msg_len)
			return;
		ND_PRINT((ndo, ", Msg "));
		for (i = 0; i< msg_len; i++) {
			ND_TCHECK(*p);
			safeputchar(ndo, *p++);
		}
		break;
	}
	return;

trunc:
	ND_PRINT((ndo, "[|pap]"));
}


static void handle_bap(netdissect_options *ndo _U_, const u_char *p _U_, int length _U_)

{
	
}



static int print_ipcp_config_options(netdissect_options *ndo, const u_char *p, int length)

{
	int len, opt;
        u_int compproto, ipcomp_subopttotallen, ipcomp_subopt, ipcomp_suboptlen;

	if (length < 2)
		return 0;
	ND_TCHECK2(*p, 2);
	len = p[1];
	opt = p[0];
	if (length < len)
		return 0;
	if (len < 2) {
		ND_PRINT((ndo, "\n\t  %s Option (0x%02x), length %u (length bogus, should be >= 2)", tok2str(ipcpopt_values,"unknown",opt), opt, len));


		return 0;
	}

	ND_PRINT((ndo, "\n\t  %s Option (0x%02x), length %u", tok2str(ipcpopt_values,"unknown",opt), opt, len));



	switch (opt) {
	case IPCPOPT_2ADDR:		
		if (len != 10) {
			ND_PRINT((ndo, " (length bogus, should be = 10)"));
			return len;
		}
		ND_TCHECK2(*(p + 6), 4);
		ND_PRINT((ndo, ": src %s, dst %s", ipaddr_string(ndo, p + 2), ipaddr_string(ndo, p + 6)));

		break;
	case IPCPOPT_IPCOMP:
		if (len < 4) {
			ND_PRINT((ndo, " (length bogus, should be >= 4)"));
			return 0;
		}
		ND_TCHECK2(*(p + 2), 2);
		compproto = EXTRACT_16BITS(p+2);

		ND_PRINT((ndo, ": %s (0x%02x):", tok2str(ipcpopt_compproto_values, "Unknown", compproto), compproto));


		switch (compproto) {
                case PPP_VJC:
			
                        break;
                case IPCPOPT_IPCOMP_HDRCOMP:
                        if (len < IPCPOPT_IPCOMP_MINLEN) {
                        	ND_PRINT((ndo, " (length bogus, should be >= %u)", IPCPOPT_IPCOMP_MINLEN));
                        	return 0;
                        }

                        ND_TCHECK2(*(p + 2), IPCPOPT_IPCOMP_MINLEN);
                        ND_PRINT((ndo, "\n\t    TCP Space %u, non-TCP Space %u"  ", maxPeriod %u, maxTime %u, maxHdr %u" EXTRACT_16BITS(p+4), EXTRACT_16BITS(p+6), EXTRACT_16BITS(p+8), EXTRACT_16BITS(p+10), EXTRACT_16BITS(p+12)));





                        
                        if (len > IPCPOPT_IPCOMP_MINLEN) {
                                ipcomp_subopttotallen = len - IPCPOPT_IPCOMP_MINLEN;
                                p += IPCPOPT_IPCOMP_MINLEN;

                                ND_PRINT((ndo, "\n\t      Suboptions, length %u", ipcomp_subopttotallen));

                                while (ipcomp_subopttotallen >= 2) {
                                        ND_TCHECK2(*p, 2);
                                        ipcomp_subopt = *p;
                                        ipcomp_suboptlen = *(p+1);

                                        
                                        if (ipcomp_subopt == 0 || ipcomp_suboptlen == 0 )
                                                break;

                                        
                                        ND_PRINT((ndo, "\n\t\t%s Suboption #%u, length %u", tok2str(ipcpopt_compproto_subopt_values, "Unknown", ipcomp_subopt), ipcomp_subopt, ipcomp_suboptlen));





                                        ipcomp_subopttotallen -= ipcomp_suboptlen;
                                        p += ipcomp_suboptlen;
                                }
                        }
                        break;
                default:
                        break;
		}
		break;

	case IPCPOPT_ADDR:     
	case IPCPOPT_MOBILE4:
	case IPCPOPT_PRIDNS:
	case IPCPOPT_PRINBNS:
	case IPCPOPT_SECDNS:
	case IPCPOPT_SECNBNS:
		if (len != 6) {
			ND_PRINT((ndo, " (length bogus, should be = 6)"));
			return 0;
		}
		ND_TCHECK2(*(p + 2), 4);
		ND_PRINT((ndo, ": %s", ipaddr_string(ndo, p + 2)));
		break;
	default:
		
		if (ndo->ndo_vflag < 2)
			print_unknown_data(ndo, &p[2], "\n\t    ", len - 2);
		break;
	}
	if (ndo->ndo_vflag > 1)
		print_unknown_data(ndo, &p[2], "\n\t    ", len - 2); 
	return len;

trunc:
	ND_PRINT((ndo, "[|ipcp]"));
	return 0;
}


static int print_ip6cp_config_options(netdissect_options *ndo, const u_char *p, int length)

{
	int len, opt;

	if (length < 2)
		return 0;
	ND_TCHECK2(*p, 2);
	len = p[1];
	opt = p[0];
	if (length < len)
		return 0;
	if (len < 2) {
		ND_PRINT((ndo, "\n\t  %s Option (0x%02x), length %u (length bogus, should be >= 2)", tok2str(ip6cpopt_values,"unknown",opt), opt, len));


		return 0;
	}

	ND_PRINT((ndo, "\n\t  %s Option (0x%02x), length %u", tok2str(ip6cpopt_values,"unknown",opt), opt, len));



	switch (opt) {
	case IP6CP_IFID:
		if (len != 10) {
			ND_PRINT((ndo, " (length bogus, should be = 10)"));
			return len;
		}
		ND_TCHECK2(*(p + 2), 8);
		ND_PRINT((ndo, ": %04x:%04x:%04x:%04x", EXTRACT_16BITS(p + 2), EXTRACT_16BITS(p + 4), EXTRACT_16BITS(p + 6), EXTRACT_16BITS(p + 8)));



		break;
	default:
		
		if (ndo->ndo_vflag < 2)
			print_unknown_data(ndo, &p[2], "\n\t    ", len - 2);
		break;
	}
	if (ndo->ndo_vflag > 1)
		print_unknown_data(ndo, &p[2], "\n\t    ", len - 2); 

	return len;

trunc:
	ND_PRINT((ndo, "[|ip6cp]"));
	return 0;
}



static int print_ccp_config_options(netdissect_options *ndo, const u_char *p, int length)

{
	int len, opt;

	if (length < 2)
		return 0;
	ND_TCHECK2(*p, 2);
	len = p[1];
	opt = p[0];
	if (length < len)
		return 0;
	if (len < 2) {
		ND_PRINT((ndo, "\n\t  %s Option (0x%02x), length %u (length bogus, should be >= 2)", tok2str(ccpconfopts_values, "Unknown", opt), opt, len));


		return 0;
	}

	ND_PRINT((ndo, "\n\t  %s Option (0x%02x), length %u", tok2str(ccpconfopts_values, "Unknown", opt), opt, len));



	switch (opt) {
	case CCPOPT_BSDCOMP:
		if (len < 3) {
			ND_PRINT((ndo, " (length bogus, should be >= 3)"));
			return len;
		}
		ND_TCHECK2(*(p + 2), 1);
		ND_PRINT((ndo, ": Version: %u, Dictionary Bits: %u", p[2] >> 5, p[2] & 0x1f));
		break;
	case CCPOPT_MVRCA:
		if (len < 4) {
			ND_PRINT((ndo, " (length bogus, should be >= 4)"));
			return len;
		}
		ND_TCHECK2(*(p + 2), 1);
		ND_PRINT((ndo, ": Features: %u, PxP: %s, History: %u, #CTX-ID: %u", (p[2] & 0xc0) >> 6, (p[2] & 0x20) ? "Enabled" : "Disabled", p[2] & 0x1f, p[3]));


		break;
	case CCPOPT_DEFLATE:
		if (len < 4) {
			ND_PRINT((ndo, " (length bogus, should be >= 4)"));
			return len;
		}
		ND_TCHECK2(*(p + 2), 1);
		ND_PRINT((ndo, ": Window: %uK, Method: %s (0x%x), MBZ: %u, CHK: %u", (p[2] & 0xf0) >> 4, ((p[2] & 0x0f) == 8) ? "zlib" : "unknown", p[2] & 0x0f, (p[3] & 0xfc) >> 2, p[3] & 0x03));


		break;



	case CCPOPT_OUI:
	case CCPOPT_PRED1:
	case CCPOPT_PRED2:
	case CCPOPT_PJUMP:
	case CCPOPT_HPPPC:
	case CCPOPT_STACLZS:
	case CCPOPT_MPPC:
	case CCPOPT_GFZA:
	case CCPOPT_V42BIS:
	case CCPOPT_LZSDCP:
	case CCPOPT_DEC:
	case CCPOPT_RESV:
		break;

	default:
		
		if (ndo->ndo_vflag < 2)
			print_unknown_data(ndo, &p[2], "\n\t    ", len - 2);
		break;
	}
	if (ndo->ndo_vflag > 1)
		print_unknown_data(ndo, &p[2], "\n\t    ", len - 2); 

	return len;

trunc:
	ND_PRINT((ndo, "[|ccp]"));
	return 0;
}


static int print_bacp_config_options(netdissect_options *ndo, const u_char *p, int length)

{
	int len, opt;

	if (length < 2)
		return 0;
	ND_TCHECK2(*p, 2);
	len = p[1];
	opt = p[0];
	if (length < len)
		return 0;
	if (len < 2) {
		ND_PRINT((ndo, "\n\t  %s Option (0x%02x), length %u (length bogus, should be >= 2)", tok2str(bacconfopts_values, "Unknown", opt), opt, len));


		return 0;
	}

	ND_PRINT((ndo, "\n\t  %s Option (0x%02x), length %u", tok2str(bacconfopts_values, "Unknown", opt), opt, len));



	switch (opt) {
	case BACPOPT_FPEER:
		if (len != 6) {
			ND_PRINT((ndo, " (length bogus, should be = 6)"));
			return len;
		}
		ND_TCHECK2(*(p + 2), 4);
		ND_PRINT((ndo, ": Magic-Num 0x%08x", EXTRACT_32BITS(p + 2)));
		break;
	default:
		
		if (ndo->ndo_vflag < 2)
			print_unknown_data(ndo, &p[2], "\n\t    ", len - 2);
		break;
	}
	if (ndo->ndo_vflag > 1)
		print_unknown_data(ndo, &p[2], "\n\t    ", len - 2); 

	return len;

trunc:
	ND_PRINT((ndo, "[|bacp]"));
	return 0;
}

static void ppp_hdlc(netdissect_options *ndo, const u_char *p, int length)

{
	u_char *b, *t, c;
	const u_char *s;
	int i, proto;
	const void *se;

        if (length <= 0)
                return;

	b = (u_char *)malloc(length);
	if (b == NULL)
		return;

	
	for (s = p, t = b, i = length; i > 0 && ND_TTEST(*s); i--) {
		c = *s++;
		if (c == 0x7d) {
			if (i <= 1 || !ND_TTEST(*s))
				break;
			i--;
			c = *s++ ^ 0x20;
		}
		*t++ = c;
	}

	se = ndo->ndo_snapend;
	ndo->ndo_snapend = t;
	length = t - b;

        
        if (length < 1)
                goto trunc;
        proto = *b; 

        switch (proto) {
        case PPP_IP:
		ip_print(ndo, b + 1, length - 1);
		goto cleanup;
        case PPP_IPV6:
		ip6_print(ndo, b + 1, length - 1);
		goto cleanup;
        default: 
		break;
        }

        if (length < 2)
                goto trunc;
        proto = EXTRACT_16BITS(b); 

        switch (proto) {
        case (PPP_ADDRESS << 8 | PPP_CONTROL): 
            if (length < 4)
                goto trunc;
            proto = EXTRACT_16BITS(b+2); 
            handle_ppp(ndo, proto, b + 4, length - 4);
            break;
        default: 
            handle_ppp(ndo, proto, b + 2, length - 2);
            break;
        }

cleanup:
	ndo->ndo_snapend = se;
	free(b);
        return;

trunc:
	ndo->ndo_snapend = se;
	free(b);
	ND_PRINT((ndo, "[|ppp]"));
}



static void handle_ppp(netdissect_options *ndo, u_int proto, const u_char *p, int length)

{
	if ((proto & 0xff00) == 0x7e00) { 
		ppp_hdlc(ndo, p - 1, length);
		return;
	}

	switch (proto) {
	case PPP_LCP: 
	case PPP_IPCP:
	case PPP_OSICP:
	case PPP_MPLSCP:
	case PPP_IPV6CP:
	case PPP_CCP:
	case PPP_BACP:
		handle_ctrl_proto(ndo, proto, p, length);
		break;
	case PPP_ML:
		handle_mlppp(ndo, p, length);
		break;
	case PPP_CHAP:
		handle_chap(ndo, p, length);
		break;
	case PPP_PAP:
		handle_pap(ndo, p, length);
		break;
	case PPP_BAP:		
		handle_bap(ndo, p, length);
		break;
	case ETHERTYPE_IP:	
        case PPP_VJNC:
	case PPP_IP:
		ip_print(ndo, p, length);
		break;
	case ETHERTYPE_IPV6:	
	case PPP_IPV6:
		ip6_print(ndo, p, length);
		break;
	case ETHERTYPE_IPX:	
	case PPP_IPX:
		ipx_print(ndo, p, length);
		break;
	case PPP_OSI:
		isoclns_print(ndo, p, length, length);
		break;
	case PPP_MPLS_UCAST:
	case PPP_MPLS_MCAST:
		mpls_print(ndo, p, length);
		break;
	case PPP_COMP:
		ND_PRINT((ndo, "compressed PPP data"));
		break;
	default:
		ND_PRINT((ndo, "%s ", tok2str(ppptype2str, "unknown PPP protocol (0x%04x)", proto)));
		print_unknown_data(ndo, p, "\n\t", length);
		break;
	}
}


u_int ppp_print(netdissect_options *ndo, register const u_char *p, u_int length)

{
	u_int proto,ppp_header;
        u_int olen = length; 
	u_int hdr_len = 0;

	
	if (length < 2)
		goto trunc;
	ND_TCHECK2(*p, 2);
        ppp_header = EXTRACT_16BITS(p);

        switch(ppp_header) {
        case (PPP_WITHDIRECTION_IN  << 8 | PPP_CONTROL):
            if (ndo->ndo_eflag) ND_PRINT((ndo, "In  "));
            p += 2;
            length -= 2;
            hdr_len += 2;
            break;
        case (PPP_WITHDIRECTION_OUT << 8 | PPP_CONTROL):
            if (ndo->ndo_eflag) ND_PRINT((ndo, "Out "));
            p += 2;
            length -= 2;
            hdr_len += 2;
            break;
        case (PPP_ADDRESS << 8 | PPP_CONTROL):
            p += 2;			
            length -= 2;
            hdr_len += 2;
            break;

        default:
            break;
        }

	if (length < 2)
		goto trunc;
	ND_TCHECK(*p);
	if (*p % 2) {
		proto = *p;		
		p++;
		length--;
		hdr_len++;
	} else {
		ND_TCHECK2(*p, 2);
		proto = EXTRACT_16BITS(p);
		p += 2;
		length -= 2;
		hdr_len += 2;
	}

	if (ndo->ndo_eflag)
		ND_PRINT((ndo, "%s (0x%04x), length %u: ", tok2str(ppptype2str, "unknown", proto), proto, olen));



	handle_ppp(ndo, proto, p, length);
	return (hdr_len);
trunc:
	ND_PRINT((ndo, "[|ppp]"));
	return (0);
}



u_int ppp_if_print(netdissect_options *ndo, const struct pcap_pkthdr *h, register const u_char *p)

{
	register u_int length = h->len;
	register u_int caplen = h->caplen;

	if (caplen < PPP_HDRLEN) {
		ND_PRINT((ndo, "[|ppp]"));
		return (caplen);
	}


	
	if (ndo->ndo_eflag)
		ND_PRINT((ndo, "%c %4d %02x ", p[0] ? 'O' : 'I', length, p[1]));


	ppp_print(ndo, p, length);

	return (0);
}


u_int ppp_hdlc_if_print(netdissect_options *ndo, const struct pcap_pkthdr *h, register const u_char *p)

{
	register u_int length = h->len;
	register u_int caplen = h->caplen;
	u_int proto;
	u_int hdrlen = 0;

	if (caplen < 2) {
		ND_PRINT((ndo, "[|ppp]"));
		return (caplen);
	}

	switch (p[0]) {

	case PPP_ADDRESS:
		if (caplen < 4) {
			ND_PRINT((ndo, "[|ppp]"));
			return (caplen);
		}

		if (ndo->ndo_eflag)
			ND_PRINT((ndo, "%02x %02x %d ", p[0], p[1], length));
		p += 2;
		length -= 2;
		hdrlen += 2;

		proto = EXTRACT_16BITS(p);
		p += 2;
		length -= 2;
		hdrlen += 2;
		ND_PRINT((ndo, "%s: ", tok2str(ppptype2str, "unknown PPP protocol (0x%04x)", proto)));

		handle_ppp(ndo, proto, p, length);
		break;

	case CHDLC_UNICAST:
	case CHDLC_BCAST:
		return (chdlc_if_print(ndo, h, p));

	default:
		if (caplen < 4) {
			ND_PRINT((ndo, "[|ppp]"));
			return (caplen);
		}

		if (ndo->ndo_eflag)
			ND_PRINT((ndo, "%02x %02x %d ", p[0], p[1], length));
		p += 2;
		hdrlen += 2;

		
		ND_PRINT((ndo, "unknown addr %02x; ctrl %02x", p[0], p[1]));
		break;
	}

	return (hdrlen);
}




u_int ppp_bsdos_if_print(netdissect_options *ndo _U_, const struct pcap_pkthdr *h _U_, register const u_char *p _U_)

{
	register int hdrlength;

	register u_int length = h->len;
	register u_int caplen = h->caplen;
	uint16_t ptype;
	const u_char *q;
	int i;

	if (caplen < PPP_BSDI_HDRLEN) {
		ND_PRINT((ndo, "[|ppp]"));
		return (caplen)
	}

	hdrlength = 0;


	if (p[0] == PPP_ADDRESS && p[1] == PPP_CONTROL) {
		if (ndo->ndo_eflag)
			ND_PRINT((ndo, "%02x %02x ", p[0], p[1]));
		p += 2;
		hdrlength = 2;
	}

	if (ndo->ndo_eflag)
		ND_PRINT((ndo, "%d ", length));
	
	if (*p & 01) {
		
		ptype = *p;
		if (ndo->ndo_eflag)
			ND_PRINT((ndo, "%02x ", ptype));
		p++;
		hdrlength += 1;
	} else {
		
		ptype = EXTRACT_16BITS(p);
		if (ndo->ndo_eflag)
			ND_PRINT((ndo, "%04x ", ptype));
		p += 2;
		hdrlength += 2;
	}

	ptype = 0;	
	if (ndo->ndo_eflag)
		ND_PRINT((ndo, "%c ", p[SLC_DIR] ? 'O' : 'I'));
	if (p[SLC_LLHL]) {
		
		struct ppp_header *ph;

		q = p + SLC_BPFHDRLEN;
		ph = (struct ppp_header *)q;
		if (ph->phdr_addr == PPP_ADDRESS && ph->phdr_ctl == PPP_CONTROL) {
			if (ndo->ndo_eflag)
				ND_PRINT((ndo, "%02x %02x ", q[0], q[1]));
			ptype = EXTRACT_16BITS(&ph->phdr_type);
			if (ndo->ndo_eflag && (ptype == PPP_VJC || ptype == PPP_VJNC)) {
				ND_PRINT((ndo, "%s ", tok2str(ppptype2str, "proto-#%d", ptype)));
			}
		} else {
			if (ndo->ndo_eflag) {
				ND_PRINT((ndo, "LLH=["));
				for (i = 0; i < p[SLC_LLHL]; i++)
					ND_PRINT((ndo, "%02x", q[i]));
				ND_PRINT((ndo, "] "));
			}
		}
	}
	if (ndo->ndo_eflag)
		ND_PRINT((ndo, "%d ", length));
	if (p[SLC_CHL]) {
		q = p + SLC_BPFHDRLEN + p[SLC_LLHL];

		switch (ptype) {
		case PPP_VJC:
			ptype = vjc_print(ndo, q, ptype);
			hdrlength = PPP_BSDI_HDRLEN;
			p += hdrlength;
			switch (ptype) {
			case PPP_IP:
				ip_print(ndo, p, length);
				break;
			case PPP_IPV6:
				ip6_print(ndo, p, length);
				break;
			case PPP_MPLS_UCAST:
			case PPP_MPLS_MCAST:
				mpls_print(ndo, p, length);
				break;
			}
			goto printx;
		case PPP_VJNC:
			ptype = vjc_print(ndo, q, ptype);
			hdrlength = PPP_BSDI_HDRLEN;
			p += hdrlength;
			switch (ptype) {
			case PPP_IP:
				ip_print(ndo, p, length);
				break;
			case PPP_IPV6:
				ip6_print(ndo, p, length);
				break;
			case PPP_MPLS_UCAST:
			case PPP_MPLS_MCAST:
				mpls_print(ndo, p, length);
				break;
			}
			goto printx;
		default:
			if (ndo->ndo_eflag) {
				ND_PRINT((ndo, "CH=["));
				for (i = 0; i < p[SLC_LLHL]; i++)
					ND_PRINT((ndo, "%02x", q[i]));
				ND_PRINT((ndo, "] "));
			}
			break;
		}
	}

	hdrlength = PPP_BSDI_HDRLEN;


	length -= hdrlength;
	p += hdrlength;

	switch (ptype) {
	case PPP_IP:
		ip_print(p, length);
		break;
	case PPP_IPV6:
		ip6_print(ndo, p, length);
		break;
	case PPP_MPLS_UCAST:
	case PPP_MPLS_MCAST:
		mpls_print(ndo, p, length);
		break;
	default:
		ND_PRINT((ndo, "%s ", tok2str(ppptype2str, "unknown PPP protocol (0x%04x)", ptype)));
	}

printx:

	hdrlength = 0;

	return (hdrlength);
}



