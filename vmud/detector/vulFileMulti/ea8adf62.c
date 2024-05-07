
















static const unsigned char rfcllc[] = {
	0xaa,	 0xaa, 0x03, 0x00, 0x00, 0x00 };





static inline void cip_print(netdissect_options *ndo, int length)
{
	
	ND_PRINT((ndo, "%d: ", length));
}


u_int cip_if_print(netdissect_options *ndo, const struct pcap_pkthdr *h, const u_char *p)
{
	u_int caplen = h->caplen;
	u_int length = h->len;
	int llc_hdrlen;

	if (memcmp(rfcllc, p, sizeof(rfcllc))==0 && caplen < RFC1483LLC_LEN) {
		ND_PRINT((ndo, "[|cip]"));
		return (0);
	}

	if (ndo->ndo_eflag)
		cip_print(ndo, length);

	if (memcmp(rfcllc, p, sizeof(rfcllc)) == 0) {
		
		llc_hdrlen = llc_print(ndo, p, length, caplen, NULL, NULL);
		if (llc_hdrlen < 0) {
			
			if (!ndo->ndo_suppress_default_print)
				ND_DEFAULTPRINT(p, caplen);
			llc_hdrlen = -llc_hdrlen;
		}
	} else {
		
		llc_hdrlen = 0;
		ip_print(ndo, p, length);
	}

	return (llc_hdrlen);
}



