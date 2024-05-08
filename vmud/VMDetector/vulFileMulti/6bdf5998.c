

















static const struct tok llc_values[] = {
        { LLCSAP_NULL,     "Null" }, { LLCSAP_GLOBAL,   "Global" }, { LLCSAP_8021B_I,  "802.1B I" }, { LLCSAP_8021B_G,  "802.1B G" }, { LLCSAP_IP,       "IP" }, { LLCSAP_SNA,      "SNA" }, { LLCSAP_PROWAYNM, "ProWay NM" }, { LLCSAP_8021D,    "STP" }, { LLCSAP_RS511,    "RS511" }, { LLCSAP_ISO8208,  "ISO8208" }, { LLCSAP_PROWAY,   "ProWay" }, { LLCSAP_SNAP,     "SNAP" }, { LLCSAP_IPX,      "IPX" }, { LLCSAP_NETBEUI,  "NetBeui" }, { LLCSAP_ISONS,    "OSI" }, { 0,               NULL }, };
















static const struct tok llc_cmd_values[] = {
	{ LLC_UI,	"ui" }, { LLC_TEST,	"test" }, { LLC_XID,	"xid" }, { LLC_UA,	"ua" }, { LLC_DISC,	"disc" }, { LLC_DM,	"dm" }, { LLC_SABME,	"sabme" }, { LLC_FRMR,	"frmr" }, { 0,		NULL }







};

static const struct tok llc_flag_values[] = {
        { 0, "Command" }, { LLC_GSAP, "Response" }, { LLC_U_POLL, "Poll" }, { LLC_GSAP|LLC_U_POLL, "Final" }, { LLC_IS_POLL, "Poll" }, { LLC_GSAP|LLC_IS_POLL, "Final" }, { 0, NULL }





};


static const struct tok llc_ig_flag_values[] = {
        { 0, "Individual" }, { LLC_IG, "Group" }, { 0, NULL }

};


static const struct tok llc_supervisory_values[] = {
        { 0, "Receiver Ready" }, { 1, "Receiver not Ready" }, { 2, "Reject" }, { 0,             NULL }


};


static const struct tok cisco_values[] = {
	{ PID_CISCO_CDP, "CDP" }, { PID_CISCO_VTP, "VTP" }, { PID_CISCO_DTP, "DTP" }, { PID_CISCO_UDLD, "UDLD" }, { PID_CISCO_PVST, "PVST" }, { PID_CISCO_VLANBRIDGE, "VLAN Bridge" }, { 0,             NULL }





};

static const struct tok bridged_values[] = {
	{ PID_RFC2684_ETH_FCS,     "Ethernet + FCS" }, { PID_RFC2684_ETH_NOFCS,   "Ethernet w/o FCS" }, { PID_RFC2684_802_4_FCS,   "802.4 + FCS" }, { PID_RFC2684_802_4_NOFCS, "802.4 w/o FCS" }, { PID_RFC2684_802_5_FCS,   "Token Ring + FCS" }, { PID_RFC2684_802_5_NOFCS, "Token Ring w/o FCS" }, { PID_RFC2684_FDDI_FCS,    "FDDI + FCS" }, { PID_RFC2684_FDDI_NOFCS,  "FDDI w/o FCS" }, { PID_RFC2684_802_6_FCS,   "802.6 + FCS" }, { PID_RFC2684_802_6_NOFCS, "802.6 w/o FCS" }, { PID_RFC2684_BPDU,        "BPDU" }, { 0,                       NULL }, };












static const struct tok null_values[] = {
	{ 0,             NULL }
};

struct oui_tok {
	uint32_t	oui;
	const struct tok *tok;
};

static const struct oui_tok oui_to_tok[] = {
	{ OUI_ENCAP_ETHER, ethertype_values }, { OUI_CISCO_90, ethertype_values }, { OUI_APPLETALK, ethertype_values }, { OUI_CISCO, cisco_values }, { OUI_RFC2684, bridged_values }, { 0, NULL }




};


int llc_print(netdissect_options *ndo, const u_char *p, u_int length, u_int caplen, const struct lladdr_info *src, const struct lladdr_info *dst)

{
	uint8_t dsap_field, dsap, ssap_field, ssap;
	uint16_t control;
	int hdrlen;
	int is_u;

	if (caplen < 3) {
		ND_PRINT((ndo, "[|llc]"));
		ND_DEFAULTPRINT((const u_char *)p, caplen);
		return (caplen);
	}
	if (length < 3) {
		ND_PRINT((ndo, "[|llc]"));
		ND_DEFAULTPRINT((const u_char *)p, caplen);
		return (length);
	}

	dsap_field = *p;
	ssap_field = *(p + 1);

	
	control = *(p + 2);
	if ((control & LLC_U_FMT) == LLC_U_FMT) {
		
		is_u = 1;
		hdrlen = 3;	
	} else {
		
		if (caplen < 4) {
			ND_PRINT((ndo, "[|llc]"));
			ND_DEFAULTPRINT((const u_char *)p, caplen);
			return (caplen);
		}
		if (length < 4) {
			ND_PRINT((ndo, "[|llc]"));
			ND_DEFAULTPRINT((const u_char *)p, caplen);
			return (length);
		}

		
		control = EXTRACT_LE_16BITS(p + 2);
		is_u = 0;
		hdrlen = 4;	
	}

	if (ssap_field == LLCSAP_GLOBAL && dsap_field == LLCSAP_GLOBAL) {
		

            if (ndo->ndo_eflag)
		ND_PRINT((ndo, "IPX 802.3: "));

            ipx_print(ndo, p, length);
            return (0);		
	}

	dsap = dsap_field & ~LLC_IG;
	ssap = ssap_field & ~LLC_GSAP;

	if (ndo->ndo_eflag) {
                ND_PRINT((ndo, "LLC, dsap %s (0x%02x) %s, ssap %s (0x%02x) %s", tok2str(llc_values, "Unknown", dsap), dsap, tok2str(llc_ig_flag_values, "Unknown", dsap_field & LLC_IG), tok2str(llc_values, "Unknown", ssap), ssap, tok2str(llc_flag_values, "Unknown", ssap_field & LLC_GSAP)));






		if (is_u) {
			ND_PRINT((ndo, ", ctrl 0x%02x: ", control));
		} else {
			ND_PRINT((ndo, ", ctrl 0x%04x: ", control));
		}
	}

	
	p += hdrlen;
	length -= hdrlen;
	caplen -= hdrlen;

	if (ssap == LLCSAP_SNAP && dsap == LLCSAP_SNAP && control == LLC_UI) {
		
		if (!snap_print(ndo, p, length, caplen, src, dst, 2)) {
			
			return (-(hdrlen + 5));	
		} else return (hdrlen + 5);
	}

	if (ssap == LLCSAP_8021D && dsap == LLCSAP_8021D && control == LLC_UI) {
		stp_print(ndo, p, length);
		return (hdrlen);
	}

	if (ssap == LLCSAP_IP && dsap == LLCSAP_IP && control == LLC_UI) {
		
		ip_print(ndo, p, length);
		return (hdrlen);
	}

	if (ssap == LLCSAP_IPX && dsap == LLCSAP_IPX && control == LLC_UI) {
		
                if (ndo->ndo_eflag)
                        ND_PRINT((ndo, "IPX 802.2: "));

		ipx_print(ndo, p, length);
		return (hdrlen);
	}


	if (ssap == LLCSAP_NETBEUI && dsap == LLCSAP_NETBEUI && (!(control & LLC_S_FMT) || control == LLC_U_FMT)) {
		
		netbeui_print(ndo, control, p, length);
		return (hdrlen);
	}

	if (ssap == LLCSAP_ISONS && dsap == LLCSAP_ISONS && control == LLC_UI) {
		isoclns_print(ndo, p, length, caplen);
		return (hdrlen);
	}

	if (!ndo->ndo_eflag) {
		if (ssap == dsap) {
			if (src == NULL || dst == NULL)
				ND_PRINT((ndo, "%s ", tok2str(llc_values, "Unknown DSAP 0x%02x", dsap)));
			else ND_PRINT((ndo, "%s > %s %s ", (src->addr_string)(ndo, src->addr), (dst->addr_string)(ndo, dst->addr), tok2str(llc_values, "Unknown DSAP 0x%02x", dsap)));



		} else {
			if (src == NULL || dst == NULL)
				ND_PRINT((ndo, "%s > %s ", tok2str(llc_values, "Unknown SSAP 0x%02x", ssap), tok2str(llc_values, "Unknown DSAP 0x%02x", dsap)));

			else ND_PRINT((ndo, "%s %s > %s %s ", (src->addr_string)(ndo, src->addr), tok2str(llc_values, "Unknown SSAP 0x%02x", ssap), (dst->addr_string)(ndo, dst->addr), tok2str(llc_values, "Unknown DSAP 0x%02x", dsap)));




		}
	}

	if (is_u) {
		ND_PRINT((ndo, "Unnumbered, %s, Flags [%s], length %u", tok2str(llc_cmd_values, "%02x", LLC_U_CMD(control)), tok2str(llc_flag_values,"?",(ssap_field & LLC_GSAP) | (control & LLC_U_POLL)), length + hdrlen));



		if ((control & ~LLC_U_POLL) == LLC_XID) {
			if (length == 0) {
				
				return (hdrlen);
			}
			if (caplen < 1) {
				ND_PRINT((ndo, "[|llc]"));
				if (caplen > 0)
					ND_DEFAULTPRINT((const u_char *)p, caplen);
				return (hdrlen);
			}
			if (*p == LLC_XID_FI) {
				if (caplen < 3 || length < 3) {
					ND_PRINT((ndo, "[|llc]"));
					if (caplen > 0)
						ND_DEFAULTPRINT((const u_char *)p, caplen);
				} else ND_PRINT((ndo, ": %02x %02x", p[1], p[2]));
				return (hdrlen);
			}
		}
	} else {
		if ((control & LLC_S_FMT) == LLC_S_FMT) {
			ND_PRINT((ndo, "Supervisory, %s, rcv seq %u, Flags [%s], length %u", tok2str(llc_supervisory_values,"?",LLC_S_CMD(control)), LLC_IS_NR(control), tok2str(llc_flag_values,"?",(ssap_field & LLC_GSAP) | (control & LLC_IS_POLL)), length + hdrlen));



			return (hdrlen);	
		} else {
			ND_PRINT((ndo, "Information, send seq %u, rcv seq %u, Flags [%s], length %u", LLC_I_NS(control), LLC_IS_NR(control), tok2str(llc_flag_values,"?",(ssap_field & LLC_GSAP) | (control & LLC_IS_POLL)), length + hdrlen));



		}
	}
	return (-hdrlen);
}

static const struct tok * oui_to_struct_tok(uint32_t orgcode)
{
	const struct tok *tok = null_values;
	const struct oui_tok *otp;

	for (otp = &oui_to_tok[0]; otp->tok != NULL; otp++) {
		if (otp->oui == orgcode) {
			tok = otp->tok;
			break;
		}
	}
	return (tok);
}

int snap_print(netdissect_options *ndo, const u_char *p, u_int length, u_int caplen, const struct lladdr_info *src, const struct lladdr_info *dst, u_int bridge_pad)


{
	uint32_t orgcode;
	register u_short et;
	register int ret;

	ND_TCHECK2(*p, 5);
	if (caplen < 5 || length < 5)
		goto trunc;
	orgcode = EXTRACT_24BITS(p);
	et = EXTRACT_16BITS(p + 3);

	if (ndo->ndo_eflag) {
		
		ND_PRINT((ndo, "oui %s (0x%06x), %s %s (0x%04x), length %u: ", tok2str(oui_values, "Unknown", orgcode), orgcode, (orgcode == 0x000000 ? "ethertype" : "pid"), tok2str(oui_to_struct_tok(orgcode), "Unknown", et), et, length - 5));




	}
	p += 5;
	length -= 5;
	caplen -= 5;

	switch (orgcode) {
	case OUI_ENCAP_ETHER:
	case OUI_CISCO_90:
		
		ret = ethertype_print(ndo, et, p, length, caplen, src, dst);
		if (ret)
			return (ret);
		break;

	case OUI_APPLETALK:
		if (et == ETHERTYPE_ATALK) {
			
			ret = ethertype_print(ndo, et, p, length, caplen, src, dst);
			if (ret)
				return (ret);
		}
		break;

	case OUI_CISCO:
                switch (et) {
                case PID_CISCO_CDP:
                        cdp_print(ndo, p, length, caplen);
                        return (1);
                case PID_CISCO_DTP:
                        dtp_print(ndo, p, length);
                        return (1);
                case PID_CISCO_UDLD:
                        udld_print(ndo, p, length);
                        return (1);
                case PID_CISCO_VTP:
                        vtp_print(ndo, p, length);
                        return (1);
                case PID_CISCO_PVST:
                case PID_CISCO_VLANBRIDGE:
                        stp_print(ndo, p, length);
                        return (1);
                default:
                        break;
                }
		break;

	case OUI_RFC2684:
		switch (et) {

		case PID_RFC2684_ETH_FCS:
		case PID_RFC2684_ETH_NOFCS:
			
			
			ND_TCHECK2(*p, bridge_pad);
			caplen -= bridge_pad;
			length -= bridge_pad;
			p += bridge_pad;

			
			ether_print(ndo, p, length, caplen, NULL, NULL);
			return (1);

		case PID_RFC2684_802_5_FCS:
		case PID_RFC2684_802_5_NOFCS:
			
			
			ND_TCHECK2(*p, bridge_pad);
			caplen -= bridge_pad;
			length -= bridge_pad;
			p += bridge_pad;

			
			token_print(ndo, p, length, caplen);
			return (1);

		case PID_RFC2684_FDDI_FCS:
		case PID_RFC2684_FDDI_NOFCS:
			
			
			ND_TCHECK2(*p, bridge_pad + 1);
			caplen -= bridge_pad + 1;
			length -= bridge_pad + 1;
			p += bridge_pad + 1;

			
			fddi_print(ndo, p, length, caplen);
			return (1);

		case PID_RFC2684_BPDU:
			stp_print(ndo, p, length);
			return (1);
		}
	}
	if (!ndo->ndo_eflag) {
		
		if (src != NULL && dst != NULL) {
			ND_PRINT((ndo, "%s > %s ", (src->addr_string)(ndo, src->addr), (dst->addr_string)(ndo, dst->addr)));

		}
		
		if (orgcode == 0x000000) {
			ND_PRINT((ndo, "SNAP, ethertype %s (0x%04x), length %u: ", tok2str(ethertype_values, "Unknown", et), et, length));

		} else {
			ND_PRINT((ndo, "SNAP, oui %s (0x%06x), pid %s (0x%04x), length %u: ", tok2str(oui_values, "Unknown", orgcode), orgcode, tok2str(oui_to_struct_tok(orgcode), "Unknown", et), et, length));



		}
	}
	return (0);

trunc:
	ND_PRINT((ndo, "[|snap]"));
	return (1);
}



