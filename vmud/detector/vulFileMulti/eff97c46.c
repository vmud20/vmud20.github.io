

















static const char tstr[] = "[|ARP]";


struct  arp_pkthdr {
        u_short ar_hrd;         







        u_short ar_pro;         
        u_char  ar_hln;         
        u_char  ar_pln;         
        u_short ar_op;          










	u_char	ar_sha[];	
	u_char	ar_spa[];	
	u_char	ar_tha[];	
	u_char	ar_tpa[];	





};














static const struct tok arpop_values[] = {
    { ARPOP_REQUEST, "Request" }, { ARPOP_REPLY, "Reply" }, { ARPOP_REVREQUEST, "Reverse Request" }, { ARPOP_REVREPLY, "Reverse Reply" }, { ARPOP_INVREQUEST, "Inverse Request" }, { ARPOP_INVREPLY, "Inverse Reply" }, { ARPOP_NAK, "NACK Reply" }, { 0, NULL }






};

static const struct tok arphrd_values[] = {
    { ARPHRD_ETHER, "Ethernet" }, { ARPHRD_IEEE802, "TokenRing" }, { ARPHRD_ARCNET, "ArcNet" }, { ARPHRD_FRELAY, "FrameRelay" }, { ARPHRD_STRIP, "Strip" }, { ARPHRD_IEEE1394, "IEEE 1394" }, { ARPHRD_ATM2225, "ATM" }, { 0, NULL }






};


struct  atmarp_pkthdr {
        u_short aar_hrd;        
        u_short aar_pro;        
        u_char  aar_shtl;       
        u_char  aar_sstl;       


        u_short aar_op;         
        u_char  aar_spln;       
        u_char  aar_thtl;       
        u_char  aar_tstl;       
        u_char  aar_tpln;       


	u_char	aar_sha[];	
	u_char	aar_ssa[];	
	u_char	aar_spa[];	
	u_char	aar_tha[];	
	u_char	aar_tsa[];	
	u_char	aar_tpa[];	

















};








static int isnonzero(const u_char *a, size_t len)
{
	while (len > 0) {
		if (*a != 0)
			return (1);
		a++;
		len--;
	}
	return (0);
}

static void atmarp_addr_print(netdissect_options *ndo, const u_char *ha, u_int ha_len, const u_char *srca, u_int srca_len)


{
	if (ha_len == 0)
		ND_PRINT((ndo, "<No address>"));
	else {
		ND_PRINT((ndo, "%s", linkaddr_string(ndo, ha, LINKADDR_ATM, ha_len)));
		if (srca_len != 0)
			ND_PRINT((ndo, ",%s", linkaddr_string(ndo, srca, LINKADDR_ATM, srca_len)));
	}
}

static void atmarp_print(netdissect_options *ndo, const u_char *bp, u_int length, u_int caplen)

{
	const struct atmarp_pkthdr *ap;
	u_short pro, hrd, op;

	ap = (const struct atmarp_pkthdr *)bp;
	ND_TCHECK(*ap);

	hrd = ATMHRD(ap);
	pro = ATMPRO(ap);
	op = ATMOP(ap);

	if (!ND_TTEST2(*aar_tpa(ap), ATMTPROTO_LEN(ap))) {
		ND_PRINT((ndo, "%s", tstr));
		ND_DEFAULTPRINT((const u_char *)ap, length);
		return;
	}

        if (!ndo->ndo_eflag) {
            ND_PRINT((ndo, "ARP, "));
        }

	if ((pro != ETHERTYPE_IP && pro != ETHERTYPE_TRAIL) || ATMSPROTO_LEN(ap) != 4 || ATMTPROTO_LEN(ap) != 4 || ndo->ndo_vflag) {


                ND_PRINT((ndo, "%s, %s (len %u/%u)", tok2str(arphrd_values, "Unknown Hardware (%u)", hrd), tok2str(ethertype_values, "Unknown Protocol (0x%04x)", pro), ATMSPROTO_LEN(ap), ATMTPROTO_LEN(ap)));




                
                if (!ndo->ndo_vflag) {
                    goto out;
                }
	}

        
        ND_PRINT((ndo, "%s%s ", ndo->ndo_vflag ? ", " : "", tok2str(arpop_values, "Unknown (%u)", op)));


	switch (op) {

	case ARPOP_REQUEST:
		ND_PRINT((ndo, "who-has %s", ipaddr_string(ndo, ATMTPA(ap))));
		if (ATMTHRD_LEN(ap) != 0) {
			ND_PRINT((ndo, " ("));
			atmarp_addr_print(ndo, ATMTHA(ap), ATMTHRD_LEN(ap), ATMTSA(ap), ATMTSLN(ap));
			ND_PRINT((ndo, ")"));
		}
		ND_PRINT((ndo, "tell %s", ipaddr_string(ndo, ATMSPA(ap))));
		break;

	case ARPOP_REPLY:
		ND_PRINT((ndo, "%s is-at ", ipaddr_string(ndo, ATMSPA(ap))));
		atmarp_addr_print(ndo, ATMSHA(ap), ATMSHRD_LEN(ap), ATMSSA(ap), ATMSSLN(ap));
		break;

	case ARPOP_INVREQUEST:
		ND_PRINT((ndo, "who-is "));
		atmarp_addr_print(ndo, ATMTHA(ap), ATMTHRD_LEN(ap), ATMTSA(ap), ATMTSLN(ap));
		ND_PRINT((ndo, " tell "));
		atmarp_addr_print(ndo, ATMSHA(ap), ATMSHRD_LEN(ap), ATMSSA(ap), ATMSSLN(ap));
		break;

	case ARPOP_INVREPLY:
		atmarp_addr_print(ndo, ATMSHA(ap), ATMSHRD_LEN(ap), ATMSSA(ap), ATMSSLN(ap));
		ND_PRINT((ndo, "at %s", ipaddr_string(ndo, ATMSPA(ap))));
		break;

	case ARPOP_NAK:
		ND_PRINT((ndo, "for %s", ipaddr_string(ndo, ATMSPA(ap))));
		break;

	default:
		ND_DEFAULTPRINT((const u_char *)ap, caplen);
		return;
	}

 out:
        ND_PRINT((ndo, ", length %u", length));
        return;

trunc:
	ND_PRINT((ndo, "%s", tstr));
}

void arp_print(netdissect_options *ndo, const u_char *bp, u_int length, u_int caplen)

{
	const struct arp_pkthdr *ap;
	u_short pro, hrd, op, linkaddr;

	ap = (const struct arp_pkthdr *)bp;
	ND_TCHECK(*ap);

	hrd = HRD(ap);
	pro = PRO(ap);
	op = OP(ap);


        

        switch(hrd) {
        case ARPHRD_ATM2225:
            atmarp_print(ndo, bp, length, caplen);
            return;
        case ARPHRD_FRELAY:
            linkaddr = LINKADDR_FRELAY;
            break;
        default:
            linkaddr = LINKADDR_ETHER;
            break;
	}

	if (!ND_TTEST2(*ar_tpa(ap), PROTO_LEN(ap))) {
		ND_PRINT((ndo, "%s", tstr));
		ND_DEFAULTPRINT((const u_char *)ap, length);
		return;
	}

        if (!ndo->ndo_eflag) {
            ND_PRINT((ndo, "ARP, "));
        }

        
        if ((pro != ETHERTYPE_IP && pro != ETHERTYPE_TRAIL) || PROTO_LEN(ap) != 4 || HRD_LEN(ap) == 0 || ndo->ndo_vflag) {


            ND_PRINT((ndo, "%s (len %u), %s (len %u)", tok2str(arphrd_values, "Unknown Hardware (%u)", hrd), HRD_LEN(ap), tok2str(ethertype_values, "Unknown Protocol (0x%04x)", pro), PROTO_LEN(ap)));




            
            if (!ndo->ndo_vflag) {
                goto out;
            }
	}

        
        ND_PRINT((ndo, "%s%s ", ndo->ndo_vflag ? ", " : "", tok2str(arpop_values, "Unknown (%u)", op)));


	switch (op) {

	case ARPOP_REQUEST:
		ND_PRINT((ndo, "who-has %s", ipaddr_string(ndo, TPA(ap))));
		if (isnonzero((const u_char *)THA(ap), HRD_LEN(ap)))
			ND_PRINT((ndo, " (%s)", linkaddr_string(ndo, THA(ap), linkaddr, HRD_LEN(ap))));
		ND_PRINT((ndo, " tell %s", ipaddr_string(ndo, SPA(ap))));
		break;

	case ARPOP_REPLY:
		ND_PRINT((ndo, "%s is-at %s", ipaddr_string(ndo, SPA(ap)), linkaddr_string(ndo, SHA(ap), linkaddr, HRD_LEN(ap))));

		break;

	case ARPOP_REVREQUEST:
		ND_PRINT((ndo, "who-is %s tell %s", linkaddr_string(ndo, THA(ap), linkaddr, HRD_LEN(ap)), linkaddr_string(ndo, SHA(ap), linkaddr, HRD_LEN(ap))));

		break;

	case ARPOP_REVREPLY:
		ND_PRINT((ndo, "%s at %s", linkaddr_string(ndo, THA(ap), linkaddr, HRD_LEN(ap)), ipaddr_string(ndo, TPA(ap))));

		break;

	case ARPOP_INVREQUEST:
		ND_PRINT((ndo, "who-is %s tell %s", linkaddr_string(ndo, THA(ap), linkaddr, HRD_LEN(ap)), linkaddr_string(ndo, SHA(ap), linkaddr, HRD_LEN(ap))));

		break;

	case ARPOP_INVREPLY:
		ND_PRINT((ndo,"%s at %s", linkaddr_string(ndo, SHA(ap), linkaddr, HRD_LEN(ap)), ipaddr_string(ndo, SPA(ap))));

		break;

	default:
		ND_DEFAULTPRINT((const u_char *)ap, caplen);
		return;
	}

 out:
        ND_PRINT((ndo, ", length %u", length));

	return;
trunc:
	ND_PRINT((ndo, "%s", tstr));
}



