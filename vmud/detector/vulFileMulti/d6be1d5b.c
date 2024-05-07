















static const char tstr[] = " [|bootp]";



struct bootp {
	uint8_t		bp_op;		
	uint8_t		bp_htype;	
	uint8_t		bp_hlen;	
	uint8_t		bp_hops;	
	uint32_t	bp_xid;		
	uint16_t	bp_secs;	
	uint16_t	bp_flags;	
	struct in_addr	bp_ciaddr;	
	struct in_addr	bp_yiaddr;	
	struct in_addr	bp_siaddr;	
	struct in_addr	bp_giaddr;	
	uint8_t		bp_chaddr[16];	
	uint8_t		bp_sname[64];	
	uint8_t		bp_file[128];	
	uint8_t		bp_vend[64];	
} UNALIGNED;




























































































































































struct cmu_vend {
	uint8_t		v_magic[4];	
	uint32_t	v_flags;	
	struct in_addr	v_smask;	
	struct in_addr	v_dgate;	
	struct in_addr	v_dns1, v_dns2; 
	struct in_addr	v_ins1, v_ins2; 
	struct in_addr	v_ts1, v_ts2;	
	uint8_t		v_unused[24];	
} UNALIGNED;













static void rfc1048_print(netdissect_options *, const u_char *);
static void cmu_print(netdissect_options *, const u_char *);
static char *client_fqdn_flags(u_int flags);

static const struct tok bootp_flag_values[] = {
	{ 0x8000,	"Broadcast" }, { 0, NULL}
};

static const struct tok bootp_op_values[] = {
	{ BOOTPREQUEST,	"Request" }, { BOOTPREPLY,	"Reply" }, { 0, NULL}

};


void bootp_print(netdissect_options *ndo, register const u_char *cp, u_int length)

{
	register const struct bootp *bp;
	static const u_char vm_cmu[4] = VM_CMU;
	static const u_char vm_rfc1048[4] = VM_RFC1048;

	bp = (const struct bootp *)cp;
	ND_TCHECK(bp->bp_op);

	ND_PRINT((ndo, "BOOTP/DHCP, %s", tok2str(bootp_op_values, "unknown (0x%02x)", bp->bp_op)));

	if (bp->bp_htype == 1 && bp->bp_hlen == 6 && bp->bp_op == BOOTPREQUEST) {
		ND_TCHECK2(bp->bp_chaddr[0], 6);
		ND_PRINT((ndo, " from %s", etheraddr_string(ndo, bp->bp_chaddr)));
	}

	ND_PRINT((ndo, ", length %u", length));

	if (!ndo->ndo_vflag)
		return;

	ND_TCHECK(bp->bp_secs);

	
	if (bp->bp_htype != 1)
		ND_PRINT((ndo, ", htype %d", bp->bp_htype));

	
	if (bp->bp_htype != 1 || bp->bp_hlen != 6)
		ND_PRINT((ndo, ", hlen %d", bp->bp_hlen));

	
	if (bp->bp_hops)
		ND_PRINT((ndo, ", hops %d", bp->bp_hops));
	if (EXTRACT_32BITS(&bp->bp_xid))
		ND_PRINT((ndo, ", xid 0x%x", EXTRACT_32BITS(&bp->bp_xid)));
	if (EXTRACT_16BITS(&bp->bp_secs))
		ND_PRINT((ndo, ", secs %d", EXTRACT_16BITS(&bp->bp_secs)));

	ND_PRINT((ndo, ", Flags [%s]", bittok2str(bootp_flag_values, "none", EXTRACT_16BITS(&bp->bp_flags))));
	if (ndo->ndo_vflag > 1)
		ND_PRINT((ndo, " (0x%04x)", EXTRACT_16BITS(&bp->bp_flags)));

	
	ND_TCHECK(bp->bp_ciaddr);
	if (EXTRACT_32BITS(&bp->bp_ciaddr.s_addr))
		ND_PRINT((ndo, "\n\t  Client-IP %s", ipaddr_string(ndo, &bp->bp_ciaddr)));

	
	ND_TCHECK(bp->bp_yiaddr);
	if (EXTRACT_32BITS(&bp->bp_yiaddr.s_addr))
		ND_PRINT((ndo, "\n\t  Your-IP %s", ipaddr_string(ndo, &bp->bp_yiaddr)));

	
	ND_TCHECK(bp->bp_siaddr);
	if (EXTRACT_32BITS(&bp->bp_siaddr.s_addr))
		ND_PRINT((ndo, "\n\t  Server-IP %s", ipaddr_string(ndo, &bp->bp_siaddr)));

	
	ND_TCHECK(bp->bp_giaddr);
	if (EXTRACT_32BITS(&bp->bp_giaddr.s_addr))
		ND_PRINT((ndo, "\n\t  Gateway-IP %s", ipaddr_string(ndo, &bp->bp_giaddr)));

	
	if (bp->bp_htype == 1 && bp->bp_hlen == 6) {
		ND_TCHECK2(bp->bp_chaddr[0], 6);
		ND_PRINT((ndo, "\n\t  Client-Ethernet-Address %s", etheraddr_string(ndo, bp->bp_chaddr)));
	}

	ND_TCHECK2(bp->bp_sname[0], 1);		
	if (*bp->bp_sname) {
		ND_PRINT((ndo, "\n\t  sname \""));
		if (fn_print(ndo, bp->bp_sname, ndo->ndo_snapend)) {
			ND_PRINT((ndo, "\""));
			ND_PRINT((ndo, "%s", tstr + 1));
			return;
		}
		ND_PRINT((ndo, "\""));
	}
	ND_TCHECK2(bp->bp_file[0], 1);		
	if (*bp->bp_file) {
		ND_PRINT((ndo, "\n\t  file \""));
		if (fn_print(ndo, bp->bp_file, ndo->ndo_snapend)) {
			ND_PRINT((ndo, "\""));
			ND_PRINT((ndo, "%s", tstr + 1));
			return;
		}
		ND_PRINT((ndo, "\""));
	}

	
	ND_TCHECK(bp->bp_vend[0]);
	if (memcmp((const char *)bp->bp_vend, vm_rfc1048, sizeof(uint32_t)) == 0)
		rfc1048_print(ndo, bp->bp_vend);
	else if (memcmp((const char *)bp->bp_vend, vm_cmu, sizeof(uint32_t)) == 0)
		cmu_print(ndo, bp->bp_vend);
	else {
		uint32_t ul;

		ul = EXTRACT_32BITS(&bp->bp_vend);
		if (ul != 0)
			ND_PRINT((ndo, "\n\t  Vendor-#0x%x", ul));
	}

	return;
trunc:
	ND_PRINT((ndo, "%s", tstr));
}


static const struct tok tag2str[] = {

	{ TAG_PAD,		" PAD" }, { TAG_SUBNET_MASK,	"iSubnet-Mask" }, { TAG_TIME_OFFSET,	"LTime-Zone" }, { TAG_GATEWAY,		"iDefault-Gateway" }, { TAG_TIME_SERVER,	"iTime-Server" }, { TAG_NAME_SERVER,	"iIEN-Name-Server" }, { TAG_DOMAIN_SERVER,	"iDomain-Name-Server" }, { TAG_LOG_SERVER,	"iLOG" }, { TAG_COOKIE_SERVER,	"iCS" }, { TAG_LPR_SERVER,	"iLPR-Server" }, { TAG_IMPRESS_SERVER,	"iIM" }, { TAG_RLP_SERVER,	"iRL" }, { TAG_HOSTNAME,		"aHostname" }, { TAG_BOOTSIZE,		"sBS" }, { TAG_END,		" END" },  { TAG_DUMPPATH,		"aDP" }, { TAG_DOMAINNAME,	"aDomain-Name" }, { TAG_SWAP_SERVER,	"iSS" }, { TAG_ROOTPATH,		"aRP" }, { TAG_EXTPATH,		"aEP" },  { TAG_IP_FORWARD,	"BIPF" }, { TAG_NL_SRCRT,		"BSRT" }, { TAG_PFILTERS,		"pPF" }, { TAG_REASS_SIZE,	"sRSZ" }, { TAG_DEF_TTL,		"bTTL" }, { TAG_MTU_TIMEOUT,	"lMTU-Timeout" }, { TAG_MTU_TABLE,	"sMTU-Table" }, { TAG_INT_MTU,		"sMTU" }, { TAG_LOCAL_SUBNETS,	"BLSN" }, { TAG_BROAD_ADDR,	"iBR" }, { TAG_DO_MASK_DISC,	"BMD" }, { TAG_SUPPLY_MASK,	"BMS" }, { TAG_DO_RDISC,		"BRouter-Discovery" }, { TAG_RTR_SOL_ADDR,	"iRSA" }, { TAG_STATIC_ROUTE,	"pStatic-Route" }, { TAG_USE_TRAILERS,	"BUT" }, { TAG_ARP_TIMEOUT,	"lAT" }, { TAG_ETH_ENCAP,	"BIE" }, { TAG_TCP_TTL,		"bTT" }, { TAG_TCP_KEEPALIVE,	"lKI" }, { TAG_KEEPALIVE_GO,	"BKG" }, { TAG_NIS_DOMAIN,	"aYD" }, { TAG_NIS_SERVERS,	"iYS" }, { TAG_NTP_SERVERS,	"iNTP" }, { TAG_VENDOR_OPTS,	"bVendor-Option" }, { TAG_NETBIOS_NS,	"iNetbios-Name-Server" }, { TAG_NETBIOS_DDS,	"iWDD" }, { TAG_NETBIOS_NODE,	"$Netbios-Node" }, { TAG_NETBIOS_SCOPE,	"aNetbios-Scope" }, { TAG_XWIN_FS,		"iXFS" }, { TAG_XWIN_DM,		"iXDM" }, { TAG_NIS_P_DOMAIN,	"sN+D" }, { TAG_NIS_P_SERVERS,	"iN+S" }, { TAG_MOBILE_HOME,	"iMH" }, { TAG_SMPT_SERVER,	"iSMTP" }, { TAG_POP3_SERVER,	"iPOP3" }, { TAG_NNTP_SERVER,	"iNNTP" }, { TAG_WWW_SERVER,	"iWWW" }, { TAG_FINGER_SERVER,	"iFG" }, { TAG_IRC_SERVER,	"iIRC" }, { TAG_STREETTALK_SRVR,	"iSTS" }, { TAG_STREETTALK_STDA,	"iSTDA" }, { TAG_REQUESTED_IP,	"iRequested-IP" }, { TAG_IP_LEASE,		"lLease-Time" }, { TAG_OPT_OVERLOAD,	"$OO" }, { TAG_TFTP_SERVER,	"aTFTP" }, { TAG_BOOTFILENAME,	"aBF" }, { TAG_DHCP_MESSAGE,	" DHCP-Message" }, { TAG_SERVER_ID,	"iServer-ID" }, { TAG_PARM_REQUEST,	"bParameter-Request" }, { TAG_MESSAGE,		"aMSG" }, { TAG_MAX_MSG_SIZE,	"sMSZ" }, { TAG_RENEWAL_TIME,	"lRN" }, { TAG_REBIND_TIME,	"lRB" }, { TAG_VENDOR_CLASS,	"aVendor-Class" }, { TAG_CLIENT_ID,	"$Client-ID" },  { TAG_OPEN_GROUP_UAP,	"aUAP" },  { TAG_DISABLE_AUTOCONF,	"BNOAUTO" },  { TAG_SLP_DA,		"bSLP-DA" }, { TAG_SLP_SCOPE,	"bSLP-SCOPE" },  { TAG_NS_SEARCH,	"sNSSEARCH" },  { TAG_USER_CLASS,	"$User-Class" },  { TAG_IP4_SUBNET_SELECT, "iSUBNET" },  { TAG_CLASSLESS_STATIC_RT, "$Classless-Static-Route" }, { TAG_CLASSLESS_STA_RT_MS, "$Classless-Static-Route-Microsoft" },  { TAG_TFTP_SERVER_ADDRESS, "iTFTP-Server-Address" },  { TAG_SLP_NAMING_AUTH,	"aSLP-NA" }, { TAG_CLIENT_FQDN,	"$FQDN" }, { TAG_AGENT_CIRCUIT,	"$Agent-Information" }, { TAG_AGENT_REMOTE,	"bARMT" }, { TAG_AGENT_MASK,	"bAMSK" }, { TAG_TZ_STRING,	"aTZSTR" }, { TAG_FQDN_OPTION,	"bFQDNS" }, { TAG_AUTH,		"bAUTH" }, { TAG_VINES_SERVERS,	"iVINES" }, { TAG_SERVER_RANK,	"sRANK" }, { TAG_CLIENT_ARCH,	"sARCH" }, { TAG_CLIENT_NDI,	"bNDI" }, { TAG_CLIENT_GUID,	"bGUID" }, { TAG_LDAP_URL,		"aLDAP" }, { TAG_6OVER4,		"i6o4" }, { TAG_TZ_PCODE, 	"aPOSIX-TZ" }, { TAG_TZ_TCODE, 	"aTZ-Name" }, { TAG_IPX_COMPAT,	"bIPX" }, { TAG_NETINFO_PARENT,	"iNI" }, { TAG_NETINFO_PARENT_TAG, "aNITAG" }, { TAG_URL,		"aURL" }, { TAG_FAILOVER,		"bFAIL" }, { TAG_MUDURL,           "aMUD-URL" }, { 0, NULL }























































































































};

static const struct tok xtag2str[] = {
	{ 0, NULL }
};


static const struct tok oo2str[] = {
	{ 1,	"file" }, { 2,	"sname" }, { 3,	"file+sname" }, { 0, NULL }


};


static const struct tok nbo2str[] = {
	{ 0x1,	"b-node" }, { 0x2,	"p-node" }, { 0x4,	"m-node" }, { 0x8,	"h-node" }, { 0, NULL }



};


static const struct tok arp2str[] = {
	{ 0x1,	"ether" }, { 0x6,	"ieee802" }, { 0x7,	"arcnet" }, { 0xf,	"frelay" }, { 0x17,	"strip" }, { 0x18,	"ieee1394" }, { 0, NULL }





};

static const struct tok dhcp_msg_values[] = {
	{ DHCPDISCOVER,	"Discover" }, { DHCPOFFER,	"Offer" }, { DHCPREQUEST,	"Request" }, { DHCPDECLINE,	"Decline" }, { DHCPACK,	"ACK" }, { DHCPNAK,	"NACK" }, { DHCPRELEASE,	"Release" }, { DHCPINFORM,	"Inform" }, { 0, NULL }







};




static const struct tok agent_suboption_values[] = {
	{ AGENT_SUBOPTION_CIRCUIT_ID,    "Circuit-ID" }, { AGENT_SUBOPTION_REMOTE_ID,     "Remote-ID" }, { AGENT_SUBOPTION_SUBSCRIBER_ID, "Subscriber-ID" }, { 0, NULL }


};


static void rfc1048_print(netdissect_options *ndo, register const u_char *bp)

{
	register uint16_t tag;
	register u_int len;
	register const char *cp;
	register char c;
	int first, idx;
	uint32_t ul;
	uint16_t us;
	uint8_t uc, subopt, suboptlen;

	ND_PRINT((ndo, "\n\t  Vendor-rfc1048 Extensions"));

	
	ND_PRINT((ndo, "\n\t    Magic Cookie 0x%08x", EXTRACT_32BITS(bp)));
	bp += sizeof(int32_t);

	
	while (ND_TTEST2(*bp, 1)) {
		tag = *bp++;
		if (tag == TAG_PAD && ndo->ndo_vflag < 3)
			continue;
		if (tag == TAG_END && ndo->ndo_vflag < 3)
			return;
		if (tag == TAG_EXTENDED_OPTION) {
			ND_TCHECK2(*(bp + 1), 2);
			tag = EXTRACT_16BITS(bp + 1);
			
			cp = tok2str(xtag2str, "?xT%u", tag);
		} else cp = tok2str(tag2str, "?T%u", tag);
		c = *cp++;

		if (tag == TAG_PAD || tag == TAG_END)
			len = 0;
		else {
			
			ND_TCHECK2(*bp, 1);
			len = *bp++;
		}

		ND_PRINT((ndo, "\n\t    %s Option %u, length %u%s", cp, tag, len, len > 0 ? ": " : ""));

		if (tag == TAG_PAD && ndo->ndo_vflag > 2) {
			u_int ntag = 1;
			while (ND_TTEST2(*bp, 1) && *bp == TAG_PAD) {
				bp++;
				ntag++;
			}
			if (ntag > 1)
				ND_PRINT((ndo, ", occurs %u", ntag));
		}

		if (!ND_TTEST2(*bp, len)) {
			ND_PRINT((ndo, "[|rfc1048 %u]", len));
			return;
		}

		if (tag == TAG_DHCP_MESSAGE && len == 1) {
			uc = *bp++;
			ND_PRINT((ndo, "%s", tok2str(dhcp_msg_values, "Unknown (%u)", uc)));
			continue;
		}

		if (tag == TAG_PARM_REQUEST) {
			idx = 0;
			while (len-- > 0) {
				uc = *bp++;
				cp = tok2str(tag2str, "?Option %u", uc);
				if (idx % 4 == 0)
					ND_PRINT((ndo, "\n\t      "));
				else ND_PRINT((ndo, ", "));
				ND_PRINT((ndo, "%s", cp + 1));
				idx++;
			}
			continue;
		}

		if (tag == TAG_EXTENDED_REQUEST) {
			first = 1;
			while (len > 1) {
				len -= 2;
				us = EXTRACT_16BITS(bp);
				bp += 2;
				cp = tok2str(xtag2str, "?xT%u", us);
				if (!first)
					ND_PRINT((ndo, "+"));
				ND_PRINT((ndo, "%s", cp + 1));
				first = 0;
			}
			continue;
		}

		
		if (c == '?') {
			
			if (len & 1)
				c = 'b';
			else if (len & 2)
				c = 's';
			else c = 'l';
		}
		first = 1;
		switch (c) {

		case 'a':
			
			ND_PRINT((ndo, "\""));
			if (fn_printn(ndo, bp, len, ndo->ndo_snapend)) {
				ND_PRINT((ndo, "\""));
				goto trunc;
			}
			ND_PRINT((ndo, "\""));
			bp += len;
			len = 0;
			break;

		case 'i':
		case 'l':
		case 'L':
			
			while (len >= sizeof(ul)) {
				if (!first)
					ND_PRINT((ndo, ","));
				ul = EXTRACT_32BITS(bp);
				if (c == 'i') {
					ul = htonl(ul);
					ND_PRINT((ndo, "%s", ipaddr_string(ndo, &ul)));
				} else if (c == 'L')
					ND_PRINT((ndo, "%d", ul));
				else ND_PRINT((ndo, "%u", ul));
				bp += sizeof(ul);
				len -= sizeof(ul);
				first = 0;
			}
			break;

		case 'p':
			
			while (len >= 2*sizeof(ul)) {
				if (!first)
					ND_PRINT((ndo, ","));
				memcpy((char *)&ul, (const char *)bp, sizeof(ul));
				ND_PRINT((ndo, "(%s:", ipaddr_string(ndo, &ul)));
				bp += sizeof(ul);
				memcpy((char *)&ul, (const char *)bp, sizeof(ul));
				ND_PRINT((ndo, "%s)", ipaddr_string(ndo, &ul)));
				bp += sizeof(ul);
				len -= 2*sizeof(ul);
				first = 0;
			}
			break;

		case 's':
			
			while (len >= sizeof(us)) {
				if (!first)
					ND_PRINT((ndo, ","));
				us = EXTRACT_16BITS(bp);
				ND_PRINT((ndo, "%u", us));
				bp += sizeof(us);
				len -= sizeof(us);
				first = 0;
			}
			break;

		case 'B':
			
			while (len > 0) {
				if (!first)
					ND_PRINT((ndo, ","));
				switch (*bp) {
				case 0:
					ND_PRINT((ndo, "N"));
					break;
				case 1:
					ND_PRINT((ndo, "Y"));
					break;
				default:
					ND_PRINT((ndo, "%u?", *bp));
					break;
				}
				++bp;
				--len;
				first = 0;
			}
			break;

		case 'b':
		case 'x':
		default:
			
			while (len > 0) {
				if (!first)
					ND_PRINT((ndo, c == 'x' ? ":" : "."));
				if (c == 'x')
					ND_PRINT((ndo, "%02x", *bp));
				else ND_PRINT((ndo, "%u", *bp));
				++bp;
				--len;
				first = 0;
			}
			break;

		case '$':
			
			switch (tag) {

			case TAG_NETBIOS_NODE:
				
				if (len < 1) {
					ND_PRINT((ndo, "ERROR: length < 1 bytes"));
					break;
				}
				tag = *bp++;
				--len;
				ND_PRINT((ndo, "%s", tok2str(nbo2str, NULL, tag)));
				break;

			case TAG_OPT_OVERLOAD:
				
				if (len < 1) {
					ND_PRINT((ndo, "ERROR: length < 1 bytes"));
					break;
				}
				tag = *bp++;
				--len;
				ND_PRINT((ndo, "%s", tok2str(oo2str, NULL, tag)));
				break;

			case TAG_CLIENT_FQDN:
				
				if (len < 3) {
					ND_PRINT((ndo, "ERROR: length < 3 bytes"));
					bp += len;
					len = 0;
					break;
				}
				if (*bp)
					ND_PRINT((ndo, "[%s] ", client_fqdn_flags(*bp)));
				bp++;
				if (*bp || *(bp+1))
					ND_PRINT((ndo, "%u/%u ", *bp, *(bp+1)));
				bp += 2;
				ND_PRINT((ndo, "\""));
				if (fn_printn(ndo, bp, len - 3, ndo->ndo_snapend)) {
					ND_PRINT((ndo, "\""));
					goto trunc;
				}
				ND_PRINT((ndo, "\""));
				bp += len - 3;
				len = 0;
				break;

			case TAG_CLIENT_ID:
			    {
				int type;

				
				if (len < 1) {
					ND_PRINT((ndo, "ERROR: length < 1 bytes"));
					break;
				}
				type = *bp++;
				len--;
				if (type == 0) {
					ND_PRINT((ndo, "\""));
					if (fn_printn(ndo, bp, len, ndo->ndo_snapend)) {
						ND_PRINT((ndo, "\""));
						goto trunc;
					}
					ND_PRINT((ndo, "\""));
					bp += len;
					len = 0;
					break;
				} else {
					ND_PRINT((ndo, "%s ", tok2str(arp2str, "hardware-type %u,", type)));
					while (len > 0) {
						if (!first)
							ND_PRINT((ndo, ":"));
						ND_PRINT((ndo, "%02x", *bp));
						++bp;
						--len;
						first = 0;
					}
				}
				break;
			    }

			case TAG_AGENT_CIRCUIT:
				while (len >= 2) {
					subopt = *bp++;
					suboptlen = *bp++;
					len -= 2;
					if (suboptlen > len) {
						ND_PRINT((ndo, "\n\t      %s SubOption %u, length %u: length goes past end of option", tok2str(agent_suboption_values, "Unknown", subopt), subopt, suboptlen));


						bp += len;
						len = 0;
						break;
					}
					ND_PRINT((ndo, "\n\t      %s SubOption %u, length %u: ", tok2str(agent_suboption_values, "Unknown", subopt), subopt, suboptlen));


					switch (subopt) {

					case AGENT_SUBOPTION_CIRCUIT_ID: 
					case AGENT_SUBOPTION_REMOTE_ID:
					case AGENT_SUBOPTION_SUBSCRIBER_ID:
						if (fn_printn(ndo, bp, suboptlen, ndo->ndo_snapend))
							goto trunc;
						break;

					default:
						print_unknown_data(ndo, bp, "\n\t\t", suboptlen);
					}

					len -= suboptlen;
					bp += suboptlen;
				}
				break;

			case TAG_CLASSLESS_STATIC_RT:
			case TAG_CLASSLESS_STA_RT_MS:
			    {
				u_int mask_width, significant_octets, i;

				
				if (len < 5) {
					ND_PRINT((ndo, "ERROR: length < 5 bytes"));
					bp += len;
					len = 0;
					break;
				}
				while (len > 0) {
					if (!first)
						ND_PRINT((ndo, ","));
					mask_width = *bp++;
					len--;
					
					if (mask_width > 32) {
						ND_PRINT((ndo, "[ERROR: Mask width (%d) > 32]", mask_width));
						bp += len;
						len = 0;
						break;
					}
					significant_octets = (mask_width + 7) / 8;
					
					if (len < significant_octets + 4) {
						ND_PRINT((ndo, "[ERROR: Remaining length (%u) < %u bytes]", len, significant_octets + 4));
						bp += len;
						len = 0;
						break;
					}
					ND_PRINT((ndo, "("));
					if (mask_width == 0)
						ND_PRINT((ndo, "default"));
					else {
						for (i = 0; i < significant_octets ; i++) {
							if (i > 0)
								ND_PRINT((ndo, "."));
							ND_PRINT((ndo, "%d", *bp++));
						}
						for (i = significant_octets ; i < 4 ; i++)
							ND_PRINT((ndo, ".0"));
						ND_PRINT((ndo, "/%d", mask_width));
					}
					memcpy((char *)&ul, (const char *)bp, sizeof(ul));
					ND_PRINT((ndo, ":%s)", ipaddr_string(ndo, &ul)));
					bp += sizeof(ul);
					len -= (significant_octets + 4);
					first = 0;
				}
				break;
			    }

			case TAG_USER_CLASS:
			    {
				u_int suboptnumber = 1;

				first = 1;
				if (len < 2) {
					ND_PRINT((ndo, "ERROR: length < 2 bytes"));
					bp += len;
					len = 0;
					break;
				}
				while (len > 0) {
					suboptlen = *bp++;
					len--;
					ND_PRINT((ndo, "\n\t      "));
					ND_PRINT((ndo, "instance#%u: ", suboptnumber));
					if (suboptlen == 0) {
						ND_PRINT((ndo, "ERROR: suboption length must be non-zero"));
						bp += len;
						len = 0;
						break;
					}
					if (len < suboptlen) {
						ND_PRINT((ndo, "ERROR: invalid option"));
						bp += len;
						len = 0;
						break;
					}
					ND_PRINT((ndo, "\""));
					if (fn_printn(ndo, bp, suboptlen, ndo->ndo_snapend)) {
						ND_PRINT((ndo, "\""));
						goto trunc;
					}
					ND_PRINT((ndo, "\""));
					ND_PRINT((ndo, ", length %d", suboptlen));
					suboptnumber++;
					len -= suboptlen;
					bp += suboptlen;
				}
				break;
			    }

			default:
				ND_PRINT((ndo, "[unknown special tag %u, size %u]", tag, len));
				bp += len;
				len = 0;
				break;
			}
			break;
		}
		
		if (len) {
			ND_PRINT((ndo, "\n\t  trailing data length %u", len));
			bp += len;
		}
	}
	return;
trunc:
	ND_PRINT((ndo, "|[rfc1048]"));
}

static void cmu_print(netdissect_options *ndo, register const u_char *bp)

{
	register const struct cmu_vend *cmu;




	ND_PRINT((ndo, " vend-cmu"));
	cmu = (const struct cmu_vend *)bp;

	
	ND_TCHECK(cmu->v_flags);
	if ((cmu->v_flags & ~(VF_SMASK)) != 0)
		ND_PRINT((ndo, " F:0x%x", cmu->v_flags));
	PRINTCMUADDR(v_dgate, "DG");
	PRINTCMUADDR(v_smask, cmu->v_flags & VF_SMASK ? "SM" : "SM*");
	PRINTCMUADDR(v_dns1, "NS1");
	PRINTCMUADDR(v_dns2, "NS2");
	PRINTCMUADDR(v_ins1, "IEN1");
	PRINTCMUADDR(v_ins2, "IEN2");
	PRINTCMUADDR(v_ts1, "TS1");
	PRINTCMUADDR(v_ts2, "TS2");
	return;

trunc:
	ND_PRINT((ndo, "%s", tstr));

}

static char * client_fqdn_flags(u_int flags)
{
	static char buf[8+1];
	int i = 0;

	if (flags & CLIENT_FQDN_FLAGS_S)
		buf[i++] = 'S';
	if (flags & CLIENT_FQDN_FLAGS_O)
		buf[i++] = 'O';
	if (flags & CLIENT_FQDN_FLAGS_E)
		buf[i++] = 'E';
	if (flags & CLIENT_FQDN_FLAGS_N)
		buf[i++] = 'N';
	buf[i] = '\0';

	return buf;
}
