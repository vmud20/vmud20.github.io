




















static void frf15_print(netdissect_options *ndo, const u_char *, u_int);












static const struct tok fr_header_flag_values[] = {
    { FR_CR_BIT, "C!" }, { FR_DE_BIT, "DE" }, { FR_BECN_BIT, "BECN" }, { FR_FECN_BIT, "FECN" }, { FR_SDLC_BIT, "sdlcore" }, { 0, NULL }




};









static const struct tok frf_flag_values[] = {
    { MFR_B_BIT, "Begin" }, { MFR_E_BIT, "End" }, { MFR_C_BIT, "Control" }, { 0, NULL }


};


static int parse_q922_addr(netdissect_options *ndo, const u_char *p, u_int *dlci, u_int *addr_len, uint8_t *flags, u_int length)

{
	if (!ND_TTEST(p[0]) || length < 1)
		return -1;
	if ((p[0] & FR_EA_BIT))
		return 0;

	if (!ND_TTEST(p[1]) || length < 2)
		return -1;
	*addr_len = 2;
	*dlci = ((p[0] & 0xFC) << 2) | ((p[1] & 0xF0) >> 4);

        flags[0] = p[0] & 0x02; 
        flags[1] = p[1] & 0x0c;
        flags[2] = 0;           
        flags[3] = 0;

	if (p[1] & FR_EA_BIT)
		return 1;	

	p += 2;
	length -= 2;
	if (!ND_TTEST(p[0]) || length < 1)
		return -1;
	(*addr_len)++;		
	if ((p[0] & FR_EA_BIT) == 0) {
		*dlci = (*dlci << 7) | (p[0] >> 1);
		(*addr_len)++;	
		p++;
		length--;
	}

	if (!ND_TTEST(p[0]) || length < 1)
		return -1;
	if ((p[0] & FR_EA_BIT) == 0)
		return 0; 

        flags[3] = p[0] & 0x02;

        *dlci = (*dlci << 6) | (p[0] >> 2);

	return 1;
}

char * q922_string(netdissect_options *ndo, const u_char *p, u_int length)
{

    static u_int dlci, addr_len;
    static uint8_t flags[4];
    static char buffer[sizeof("DLCI xxxxxxxxxx")];
    memset(buffer, 0, sizeof(buffer));

    if (parse_q922_addr(ndo, p, &dlci, &addr_len, flags, length) == 1){
        snprintf(buffer, sizeof(buffer), "DLCI %u", dlci);
    }

    return buffer;
}




static void fr_hdr_print(netdissect_options *ndo, int length, u_int addr_len, u_int dlci, uint8_t *flags, uint16_t nlpid)

{
    if (ndo->ndo_qflag) {
        ND_PRINT((ndo, "Q.922, DLCI %u, length %u: ", dlci, length));

    } else {
        if (nlpid <= 0xff) 
            ND_PRINT((ndo, "Q.922, hdr-len %u, DLCI %u, Flags [%s], NLPID %s (0x%02x), length %u: ", addr_len, dlci, bittok2str(fr_header_flag_values, "none", EXTRACT_32BITS(flags)), tok2str(nlpid_values,"unknown", nlpid), nlpid, length));





        else  ND_PRINT((ndo, "Q.922, hdr-len %u, DLCI %u, Flags [%s], cisco-ethertype %s (0x%04x), length %u: ", addr_len, dlci, bittok2str(fr_header_flag_values, "none", EXTRACT_32BITS(flags)), tok2str(ethertype_values, "unknown", nlpid), nlpid, length));






    }
}

u_int fr_if_print(netdissect_options *ndo, const struct pcap_pkthdr *h, register const u_char *p)

{
	register u_int length = h->len;
	register u_int caplen = h->caplen;

        ND_TCHECK2(*p, 4); 

        if ((length = fr_print(ndo, p, length)) == 0)
            return (0);
        else return length;
 trunc:
        ND_PRINT((ndo, "[|fr]"));
        return caplen;
}

u_int fr_print(netdissect_options *ndo, register const u_char *p, u_int length)

{
	int ret;
	uint16_t extracted_ethertype;
	u_int dlci;
	u_int addr_len;
	uint16_t nlpid;
	u_int hdr_len;
	uint8_t flags[4];

	ret = parse_q922_addr(ndo, p, &dlci, &addr_len, flags, length);
	if (ret == -1)
		goto trunc;
	if (ret == 0) {
		ND_PRINT((ndo, "Q.922, invalid address"));
		return 0;
	}

	ND_TCHECK(p[addr_len]);
	if (length < addr_len + 1)
		goto trunc;

	if (p[addr_len] != LLC_UI && dlci != 0) {
                
		if (!ND_TTEST2(p[addr_len], 2) || length < addr_len + 2) {
                        
                        ND_PRINT((ndo, "UI %02x! ", p[addr_len]));
                } else {
                        extracted_ethertype = EXTRACT_16BITS(p+addr_len);

                        if (ndo->ndo_eflag)
                                fr_hdr_print(ndo, length, addr_len, dlci, flags, extracted_ethertype);

                        if (ethertype_print(ndo, extracted_ethertype, p+addr_len+ETHERTYPE_LEN, length-addr_len-ETHERTYPE_LEN, ndo->ndo_snapend-p-addr_len-ETHERTYPE_LEN, NULL, NULL) == 0)



                                
                                ND_PRINT((ndo, "UI %02x! ", p[addr_len]));
                        else return addr_len + 2;
                }
        }

	ND_TCHECK(p[addr_len+1]);
	if (length < addr_len + 2)
		goto trunc;

	if (p[addr_len + 1] == 0) {
		
		if (addr_len != 3)
			ND_PRINT((ndo, "Pad! "));
		hdr_len = addr_len + 1  + 1  + 1 ;
	} else {
		
		if (addr_len == 3)
			ND_PRINT((ndo, "No pad! "));
		hdr_len = addr_len + 1  + 1 ;
	}

        ND_TCHECK(p[hdr_len - 1]);
	if (length < hdr_len)
		goto trunc;
	nlpid = p[hdr_len - 1];

	if (ndo->ndo_eflag)
		fr_hdr_print(ndo, length, addr_len, dlci, flags, nlpid);
	p += hdr_len;
	length -= hdr_len;

	switch (nlpid) {
	case NLPID_IP:
	        ip_print(ndo, p, length);
		break;

	case NLPID_IP6:
		ip6_print(ndo, p, length);
		break;

	case NLPID_CLNP:
	case NLPID_ESIS:
	case NLPID_ISIS:
		isoclns_print(ndo, p - 1, length + 1, ndo->ndo_snapend - p + 1); 
		break;

	case NLPID_SNAP:
		if (snap_print(ndo, p, length, ndo->ndo_snapend - p, NULL, NULL, 0) == 0) {
			
                        if (!ndo->ndo_eflag)
                            fr_hdr_print(ndo, length + hdr_len, hdr_len, dlci, flags, nlpid);
			if (!ndo->ndo_suppress_default_print)
				ND_DEFAULTPRINT(p - hdr_len, length + hdr_len);
		}
		break;

        case NLPID_Q933:
		q933_print(ndo, p, length);
		break;

        case NLPID_MFR:
                frf15_print(ndo, p, length);
                break;

        case NLPID_PPP:
                ppp_print(ndo, p, length);
                break;

	default:
		if (!ndo->ndo_eflag)
                    fr_hdr_print(ndo, length + hdr_len, addr_len, dlci, flags, nlpid);
		if (!ndo->ndo_xflag)
			ND_DEFAULTPRINT(p, length);
	}

	return hdr_len;

 trunc:
        ND_PRINT((ndo, "[|fr]"));
        return 0;

}

u_int mfr_if_print(netdissect_options *ndo, const struct pcap_pkthdr *h, register const u_char *p)

{
	register u_int length = h->len;
	register u_int caplen = h->caplen;

        ND_TCHECK2(*p, 2); 

        if ((length = mfr_print(ndo, p, length)) == 0)
            return (0);
        else return length;
 trunc:
        ND_PRINT((ndo, "[|mfr]"));
        return caplen;
}










static const struct tok mfr_ctrl_msg_values[] = {
    { MFR_CTRL_MSG_ADD_LINK, "Add Link" }, { MFR_CTRL_MSG_ADD_LINK_ACK, "Add Link ACK" }, { MFR_CTRL_MSG_ADD_LINK_REJ, "Add Link Reject" }, { MFR_CTRL_MSG_HELLO, "Hello" }, { MFR_CTRL_MSG_HELLO_ACK, "Hello ACK" }, { MFR_CTRL_MSG_REMOVE_LINK, "Remove Link" }, { MFR_CTRL_MSG_REMOVE_LINK_ACK, "Remove Link ACK" }, { 0, NULL }






};








static const struct tok mfr_ctrl_ie_values[] = {
    { MFR_CTRL_IE_BUNDLE_ID, "Bundle ID", { MFR_CTRL_IE_LINK_ID, "Link ID", { MFR_CTRL_IE_MAGIC_NUM, "Magic Number", { MFR_CTRL_IE_TIMESTAMP, "Timestamp", { MFR_CTRL_IE_VENDOR_EXT, "Vendor Extension", { MFR_CTRL_IE_CAUSE, "Cause", { 0, NULL }





};



struct ie_tlv_header_t {
    uint8_t ie_type;
    uint8_t ie_len;
};

u_int mfr_print(netdissect_options *ndo, register const u_char *p, u_int length)

{
    u_int tlen,idx,hdr_len = 0;
    uint16_t sequence_num;
    uint8_t ie_type,ie_len;
    const uint8_t *tptr;




    ND_TCHECK2(*p, 4); 

    if ((p[0] & MFR_BEC_MASK) == MFR_CTRL_FRAME && p[1] == 0) {
        ND_PRINT((ndo, "FRF.16 Control, Flags [%s], %s, length %u", bittok2str(frf_flag_values,"none",(p[0] & MFR_BEC_MASK)), tok2str(mfr_ctrl_msg_values,"Unknown Message (0x%02x)",p[2]), length));


        tptr = p + 3;
        tlen = length -3;
        hdr_len = 3;

        if (!ndo->ndo_vflag)
            return hdr_len;

        while (tlen>sizeof(struct ie_tlv_header_t)) {
            ND_TCHECK2(*tptr, sizeof(struct ie_tlv_header_t));
            ie_type=tptr[0];
            ie_len=tptr[1];

            ND_PRINT((ndo, "\n\tIE %s (%u), length %u: ", tok2str(mfr_ctrl_ie_values,"Unknown",ie_type), ie_type, ie_len));



            
            if (ie_type == 0 || ie_len <= sizeof(struct ie_tlv_header_t))
                return hdr_len;

            ND_TCHECK2(*tptr, ie_len);
            tptr+=sizeof(struct ie_tlv_header_t);
            
            ie_len-=sizeof(struct ie_tlv_header_t);
            tlen-=sizeof(struct ie_tlv_header_t);

            switch (ie_type) {

            case MFR_CTRL_IE_MAGIC_NUM:
                ND_PRINT((ndo, "0x%08x", EXTRACT_32BITS(tptr)));
                break;

            case MFR_CTRL_IE_BUNDLE_ID: 
            case MFR_CTRL_IE_LINK_ID:
                for (idx = 0; idx < ie_len && idx < MFR_ID_STRING_MAXLEN; idx++) {
                    if (*(tptr+idx) != 0) 
                        safeputchar(ndo, *(tptr + idx));
                    else break;
                }
                break;

            case MFR_CTRL_IE_TIMESTAMP:
                if (ie_len == sizeof(struct timeval)) {
                    ts_print(ndo, (const struct timeval *)tptr);
                    break;
                }
                
                ND_FALL_THROUGH;

                

            case MFR_CTRL_IE_VENDOR_EXT:
            case MFR_CTRL_IE_CAUSE:

            default:
                if (ndo->ndo_vflag <= 1)
                    print_unknown_data(ndo, tptr, "\n\t  ", ie_len);
                break;
            }

            
            if (ndo->ndo_vflag > 1 )
                print_unknown_data(ndo, tptr, "\n\t  ", ie_len);

            tlen-=ie_len;
            tptr+=ie_len;
        }
        return hdr_len;
    }


    sequence_num = (p[0]&0x1e)<<7 | p[1];
    
    if ((p[0] & MFR_BEC_MASK) == MFR_FRAG_FRAME || (p[0] & MFR_BEC_MASK) == MFR_B_BIT) {
        ND_PRINT((ndo, "FRF.16 Frag, seq %u, Flags [%s], ", sequence_num, bittok2str(frf_flag_values,"none",(p[0] & MFR_BEC_MASK))));

        hdr_len = 2;
        fr_print(ndo, p+hdr_len,length-hdr_len);
        return hdr_len;
    }

    
    ND_PRINT((ndo, "FRF.16 Frag, seq %u, Flags [%s]", sequence_num, bittok2str(frf_flag_values,"none",(p[0] & MFR_BEC_MASK))));

    print_unknown_data(ndo, p, "\n\t", length);

    return hdr_len;

 trunc:
    ND_PRINT((ndo, "[|mfr]"));
    return length;
}





static void frf15_print(netdissect_options *ndo, const u_char *p, u_int length)

{
    uint16_t sequence_num, flags;

    if (length < 2)
        goto trunc;
    ND_TCHECK2(*p, 2);

    flags = p[0]&MFR_BEC_MASK;
    sequence_num = (p[0]&0x1e)<<7 | p[1];

    ND_PRINT((ndo, "FRF.15, seq 0x%03x, Flags [%s],%s Fragmentation, length %u", sequence_num, bittok2str(frf_flag_values,"none",flags), p[0]&FR_FRF15_FRAGTYPE ? "Interface" : "End-to-End", length));





    return;

trunc:
    ND_PRINT((ndo, "[|frf.15]"));
}


























static const struct tok fr_q933_msg_values[] = {
    { MSG_TYPE_ESC_TO_NATIONAL, "ESC to National" }, { MSG_TYPE_ALERT, "Alert" }, { MSG_TYPE_CALL_PROCEEDING, "Call proceeding" }, { MSG_TYPE_CONNECT, "Connect" }, { MSG_TYPE_CONNECT_ACK, "Connect ACK" }, { MSG_TYPE_PROGRESS, "Progress" }, { MSG_TYPE_SETUP, "Setup" }, { MSG_TYPE_DISCONNECT, "Disconnect" }, { MSG_TYPE_RELEASE, "Release" }, { MSG_TYPE_RELEASE_COMPLETE, "Release Complete" }, { MSG_TYPE_RESTART, "Restart" }, { MSG_TYPE_RESTART_ACK, "Restart ACK" }, { MSG_TYPE_STATUS, "Status Reply" }, { MSG_TYPE_STATUS_ENQ, "Status Enquiry" }, { 0, NULL }













};
















static const struct tok fr_q933_ie_values_codeset_0_5[] = {
    { FR_LMI_ANSI_REPORT_TYPE_IE, "ANSI Report Type" }, { FR_LMI_ANSI_LINK_VERIFY_IE_91, "ANSI Link Verify" }, { FR_LMI_ANSI_LINK_VERIFY_IE, "ANSI Link Verify" }, { FR_LMI_ANSI_PVC_STATUS_IE, "ANSI PVC Status" }, { FR_LMI_CCITT_REPORT_TYPE_IE, "CCITT Report Type" }, { FR_LMI_CCITT_LINK_VERIFY_IE, "CCITT Link Verify" }, { FR_LMI_CCITT_PVC_STATUS_IE, "CCITT PVC Status" }, { 0, NULL }






};





static const struct tok fr_lmi_report_type_ie_values[] = {
    { FR_LMI_REPORT_TYPE_IE_FULL_STATUS, "Full Status" }, { FR_LMI_REPORT_TYPE_IE_LINK_VERIFY, "Link verify" }, { FR_LMI_REPORT_TYPE_IE_ASYNC_PVC, "Async PVC Status" }, { 0, NULL }


};


static const struct tok *fr_q933_ie_codesets[] = {
    fr_q933_ie_values_codeset_0_5, NULL, NULL, NULL, NULL, fr_q933_ie_values_codeset_0_5, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };
















static int fr_q933_print_ie_codeset_0_5(netdissect_options *ndo, u_int iecode, u_int ielength, const u_char *p);

typedef int (*codeset_pr_func_t)(netdissect_options *, u_int iecode, u_int ielength, const u_char *p);


static const codeset_pr_func_t fr_q933_print_ie_codeset[] = {
    fr_q933_print_ie_codeset_0_5, NULL, NULL, NULL, NULL, fr_q933_print_ie_codeset_0_5, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };

















void q933_print(netdissect_options *ndo, const u_char *p, u_int length)

{
	u_int olen;
	u_int call_ref_length, i;
	uint8_t call_ref[15];	
	u_int msgtype;
	u_int iecode;
	u_int ielength;
	u_int codeset = 0;
	u_int is_ansi = 0;
	u_int ie_is_known;
	u_int non_locking_shift;
	u_int unshift_codeset;

	ND_PRINT((ndo, "%s", ndo->ndo_eflag ? "" : "Q.933"));

	if (length == 0 || !ND_TTEST(*p)) {
		if (!ndo->ndo_eflag)
			ND_PRINT((ndo, ", "));
		ND_PRINT((ndo, "length %u", length));
		goto trunc;
	}

	
	olen = length; 
	call_ref_length = (*p) & 0x0f;
	p++;
	length--;

	
	for (i = 0; i < call_ref_length; i++) {
		if (length == 0 || !ND_TTEST(*p)) {
			if (!ndo->ndo_eflag)
				ND_PRINT((ndo, ", "));
			ND_PRINT((ndo, "length %u", olen));
			goto trunc;
		}
		call_ref[i] = *p;
		p++;
		length--;
	}

	
	if (length == 0 || !ND_TTEST(*p)) {
		if (!ndo->ndo_eflag)
			ND_PRINT((ndo, ", "));
		ND_PRINT((ndo, "length %u", olen));
		goto trunc;
	}
	msgtype = *p;
	p++;
	length--;

	
	non_locking_shift = 0;
	unshift_codeset = codeset;
	if (length != 0) {
		if (!ND_TTEST(*p)) {
			if (!ndo->ndo_eflag)
				ND_PRINT((ndo, ", "));
			ND_PRINT((ndo, "length %u", olen));
			goto trunc;
		}
		iecode = *p;
		if (IE_IS_SHIFT(iecode)) {
			
			p++;
			length--;

			
			codeset = IE_SHIFT_CODESET(iecode);

			
			if (IE_SHIFT_IS_LOCKING(iecode)) {
				
				if (codeset == 5) {
					
					is_ansi = 1;
				}
			} else {
				
				non_locking_shift = 1;
				unshift_codeset = 0;
			}
		}
	}

	
	if (!ndo->ndo_eflag)
		ND_PRINT((ndo, ", "));
	ND_PRINT((ndo, "%s, codeset %u", is_ansi ? "ANSI" : "CCITT", codeset));

	if (call_ref_length != 0) {
		ND_TCHECK(p[0]);
		if (call_ref_length > 1 || p[0] != 0) {
			
			ND_PRINT((ndo, ", Call Ref: 0x"));
			for (i = 0; i < call_ref_length; i++)
				ND_PRINT((ndo, "%02x", call_ref[i]));
		}
	}
	if (ndo->ndo_vflag) {
		ND_PRINT((ndo, ", %s (0x%02x), length %u", tok2str(fr_q933_msg_values, "unknown message", msgtype), msgtype, olen));



	} else {
		ND_PRINT((ndo, ", %s", tok2str(fr_q933_msg_values, "unknown message 0x%02x", msgtype)));

	}

	
	while (length != 0) {
		
		if (non_locking_shift == 1) {
			
			non_locking_shift = 2;
		} else if (non_locking_shift == 2) {
			
			codeset = unshift_codeset;
			non_locking_shift = 0;
		}

		
		if (!ND_TTEST(*p)) {
			if (!ndo->ndo_vflag) {
				ND_PRINT((ndo, ", length %u", olen));
			}
			goto trunc;
		}
		iecode = *p;
		p++;
		length--;

		
		if (IE_IS_SINGLE_OCTET(iecode)) {
			
			if (IE_IS_SHIFT(iecode)) {
				
				if (IE_SHIFT_IS_LOCKING(iecode)) {
					
					non_locking_shift = 0;
				} else {
					
					non_locking_shift = 1;
					unshift_codeset = codeset;
				}

				
				codeset = IE_SHIFT_CODESET(iecode);
			}
		} else {
			
			if (length == 0 || !ND_TTEST(*p)) {
				if (!ndo->ndo_vflag) {
					ND_PRINT((ndo, ", length %u", olen));
				}
				goto trunc;
			}
			ielength = *p;
			p++;
			length--;

			
			if (ndo->ndo_vflag) {
				ND_PRINT((ndo, "\n\t%s IE (0x%02x), length %u: ", tok2str(fr_q933_ie_codesets[codeset], "unknown", iecode), iecode, ielength));



			}

			
			if (iecode == 0 || ielength == 0) {
				return;
			}
			if (length < ielength || !ND_TTEST2(*p, ielength)) {
				if (!ndo->ndo_vflag) {
					ND_PRINT((ndo, ", length %u", olen));
				}
				goto trunc;
			}

			ie_is_known = 0;
			if (fr_q933_print_ie_codeset[codeset] != NULL) {
				ie_is_known = fr_q933_print_ie_codeset[codeset](ndo, iecode, ielength, p);
			}

			if (ie_is_known) {
				
				if (ndo->ndo_vflag > 1) {
					
					print_unknown_data(ndo, p, "\n\t  ", ielength);
				}
			} else {
				
				if (ndo->ndo_vflag >= 1) {
					print_unknown_data(ndo, p, "\n\t", ielength);
				}
			}

			length -= ielength;
			p += ielength;
		}
	}
	if (!ndo->ndo_vflag) {
	    ND_PRINT((ndo, ", length %u", olen));
	}
	return;

trunc:
	ND_PRINT((ndo, "[|q.933]"));
}

static int fr_q933_print_ie_codeset_0_5(netdissect_options *ndo, u_int iecode, u_int ielength, const u_char *p)

{
        u_int dlci;

        switch (iecode) {

        case FR_LMI_ANSI_REPORT_TYPE_IE: 
        case FR_LMI_CCITT_REPORT_TYPE_IE:
            if (ielength < 1) {
                if (!ndo->ndo_vflag) {
                    ND_PRINT((ndo, ", "));
	        }
                ND_PRINT((ndo, "Invalid REPORT TYPE IE"));
                return 1;
            }
            if (ndo->ndo_vflag) {
                ND_PRINT((ndo, "%s (%u)", tok2str(fr_lmi_report_type_ie_values,"unknown",p[0]), p[0]));

	    }
            return 1;

        case FR_LMI_ANSI_LINK_VERIFY_IE: 
        case FR_LMI_CCITT_LINK_VERIFY_IE:
        case FR_LMI_ANSI_LINK_VERIFY_IE_91:
            if (!ndo->ndo_vflag) {
                ND_PRINT((ndo, ", "));
	    }
            if (ielength < 2) {
                ND_PRINT((ndo, "Invalid LINK VERIFY IE"));
                return 1;
            }
            ND_PRINT((ndo, "TX Seq: %3d, RX Seq: %3d", p[0], p[1]));
            return 1;

        case FR_LMI_ANSI_PVC_STATUS_IE: 
        case FR_LMI_CCITT_PVC_STATUS_IE:
            if (!ndo->ndo_vflag) {
                ND_PRINT((ndo, ", "));
	    }
            
            if ((ielength < 3) || (p[0] & 0x80) || ((ielength == 3) && !(p[1] & 0x80)) || ((ielength == 4) && ((p[1] & 0x80) || !(p[2] & 0x80))) || ((ielength == 5) && ((p[1] & 0x80) || (p[2] & 0x80) || !(p[3] & 0x80))) || (ielength > 5) || !(p[ielength - 1] & 0x80)) {






                ND_PRINT((ndo, "Invalid DLCI in PVC STATUS IE"));
                return 1;
	    }

            dlci = ((p[0] & 0x3F) << 4) | ((p[1] & 0x78) >> 3);
            if (ielength == 4) {
                dlci = (dlci << 6) | ((p[2] & 0x7E) >> 1);
	    }
            else if (ielength == 5) {
                dlci = (dlci << 13) | (p[2] & 0x7F) | ((p[3] & 0x7E) >> 1);
	    }

            ND_PRINT((ndo, "DLCI %u: status %s%s", dlci, p[ielength - 1] & 0x8 ? "New, " : "", p[ielength - 1] & 0x2 ? "Active" : "Inactive"));

            return 1;
	}

        return 0;
}

