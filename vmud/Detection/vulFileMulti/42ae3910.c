
















































static const char tstr[] = " [|l2tp]";
















static const struct tok l2tp_msgtype2str[] = {
	{ L2TP_MSGTYPE_SCCRQ, 	"SCCRQ" }, { L2TP_MSGTYPE_SCCRP,	"SCCRP" }, { L2TP_MSGTYPE_SCCCN,	"SCCCN" }, { L2TP_MSGTYPE_STOPCCN,	"StopCCN" }, { L2TP_MSGTYPE_HELLO,	"HELLO" }, { L2TP_MSGTYPE_OCRQ,	"OCRQ" }, { L2TP_MSGTYPE_OCRP,	"OCRP" }, { L2TP_MSGTYPE_OCCN,	"OCCN" }, { L2TP_MSGTYPE_ICRQ,	"ICRQ" }, { L2TP_MSGTYPE_ICRP,	"ICRP" }, { L2TP_MSGTYPE_ICCN,	"ICCN" }, { L2TP_MSGTYPE_CDN,	"CDN" }, { L2TP_MSGTYPE_WEN,	"WEN" }, { L2TP_MSGTYPE_SLI,	"SLI" }, { 0,			NULL }













};











































static const struct tok l2tp_avp2str[] = {
	{ L2TP_AVP_MSGTYPE,		"MSGTYPE" }, { L2TP_AVP_RESULT_CODE,		"RESULT_CODE" }, { L2TP_AVP_PROTO_VER,		"PROTO_VER" }, { L2TP_AVP_FRAMING_CAP,		"FRAMING_CAP" }, { L2TP_AVP_BEARER_CAP,		"BEARER_CAP" }, { L2TP_AVP_TIE_BREAKER,		"TIE_BREAKER" }, { L2TP_AVP_FIRM_VER,		"FIRM_VER" }, { L2TP_AVP_HOST_NAME,		"HOST_NAME" }, { L2TP_AVP_VENDOR_NAME,		"VENDOR_NAME" }, { L2TP_AVP_ASSND_TUN_ID,	"ASSND_TUN_ID" }, { L2TP_AVP_RECV_WIN_SIZE,	"RECV_WIN_SIZE" }, { L2TP_AVP_CHALLENGE,		"CHALLENGE" }, { L2TP_AVP_Q931_CC,		"Q931_CC", }, { L2TP_AVP_CHALLENGE_RESP,	"CHALLENGE_RESP" }, { L2TP_AVP_ASSND_SESS_ID,	"ASSND_SESS_ID" }, { L2TP_AVP_CALL_SER_NUM,	"CALL_SER_NUM" }, { L2TP_AVP_MINIMUM_BPS,		"MINIMUM_BPS" }, { L2TP_AVP_MAXIMUM_BPS,		"MAXIMUM_BPS" }, { L2TP_AVP_BEARER_TYPE,		"BEARER_TYPE" }, { L2TP_AVP_FRAMING_TYPE,	"FRAMING_TYPE" }, { L2TP_AVP_PACKET_PROC_DELAY,	"PACKET_PROC_DELAY" }, { L2TP_AVP_CALLED_NUMBER,	"CALLED_NUMBER" }, { L2TP_AVP_CALLING_NUMBER,	"CALLING_NUMBER" }, { L2TP_AVP_SUB_ADDRESS,		"SUB_ADDRESS" }, { L2TP_AVP_TX_CONN_SPEED,	"TX_CONN_SPEED" }, { L2TP_AVP_PHY_CHANNEL_ID,	"PHY_CHANNEL_ID" }, { L2TP_AVP_INI_RECV_LCP,	"INI_RECV_LCP" }, { L2TP_AVP_LAST_SENT_LCP,	"LAST_SENT_LCP" }, { L2TP_AVP_LAST_RECV_LCP,	"LAST_RECV_LCP" }, { L2TP_AVP_PROXY_AUTH_TYPE,	"PROXY_AUTH_TYPE" }, { L2TP_AVP_PROXY_AUTH_NAME,	"PROXY_AUTH_NAME" }, { L2TP_AVP_PROXY_AUTH_CHAL,	"PROXY_AUTH_CHAL" }, { L2TP_AVP_PROXY_AUTH_ID,	"PROXY_AUTH_ID" }, { L2TP_AVP_PROXY_AUTH_RESP,	"PROXY_AUTH_RESP" }, { L2TP_AVP_CALL_ERRORS,		"CALL_ERRORS" }, { L2TP_AVP_ACCM,		"ACCM" }, { L2TP_AVP_RANDOM_VECTOR,	"RANDOM_VECTOR" }, { L2TP_AVP_PRIVATE_GRP_ID,	"PRIVATE_GRP_ID" }, { L2TP_AVP_RX_CONN_SPEED,	"RX_CONN_SPEED" }, { L2TP_AVP_SEQ_REQUIRED,	"SEQ_REQUIRED" }, { L2TP_AVP_PPP_DISCON_CC,	"PPP_DISCON_CC" }, { 0,				NULL }








































};

static const struct tok l2tp_authentype2str[] = {
	{ L2TP_AUTHEN_TYPE_RESERVED,	"Reserved" }, { L2TP_AUTHEN_TYPE_TEXTUAL,	"Textual" }, { L2TP_AUTHEN_TYPE_CHAP,	"CHAP" }, { L2TP_AUTHEN_TYPE_PAP,		"PAP" }, { L2TP_AUTHEN_TYPE_NO_AUTH,	"No Auth" }, { L2TP_AUTHEN_TYPE_MSCHAPv1,	"MS-CHAPv1" }, { 0,				NULL }





};





static const struct tok l2tp_cc_direction2str[] = {
	{ L2TP_PPP_DISCON_CC_DIRECTION_GLOBAL,	"global error" }, { L2TP_PPP_DISCON_CC_DIRECTION_AT_PEER,	"at peer" }, { L2TP_PPP_DISCON_CC_DIRECTION_AT_LOCAL,"at local" }, { 0,					NULL }


};


static char *l2tp_result_code_StopCCN[] = {
         "Reserved", "General request to clear control connection", "General error--Error Code indicates the problem", "Control channel already exists", "Requester is not authorized to establish a control channel", "The protocol version of the requester is not supported", "Requester is being shut down", "Finite State Machine error"  };











static char *l2tp_result_code_CDN[] = {
	"Reserved", "Call disconnected due to loss of carrier", "Call disconnected for the reason indicated in error code", "Call disconnected for administrative reasons", "Call failed due to lack of appropriate facilities being "  "available (temporary condition)" "Call failed due to lack of appropriate facilities being "  "available (permanent condition)" "Invalid destination", "Call failed due to no carrier detected", "Call failed due to detection of a busy signal", "Call failed due to lack of a dial tone", "Call was not established within time allotted by LAC", "Call was connected but no appropriate framing was detected"  };















static char *l2tp_error_code_general[] = {
	"No general error", "No control connection exists yet for this LAC-LNS pair", "Length is wrong", "One of the field values was out of range or "  "reserved field was non-zero "Insufficient resources to handle this operation now", "The Session ID is invalid in this context", "A generic vendor-specific error occurred in the LAC", "Try another"  };













static void print_string(netdissect_options *ndo, const u_char *dat, u_int length)
{
	u_int i;
	for (i=0; i<length; i++) {
		ND_PRINT((ndo, "%c", *dat++));
	}
}

static void print_octets(netdissect_options *ndo, const u_char *dat, u_int length)
{
	u_int i;
	for (i=0; i<length; i++) {
		ND_PRINT((ndo, "%02x", *dat++));
	}
}

static void print_16bits_val(netdissect_options *ndo, const uint16_t *dat)
{
	ND_PRINT((ndo, "%u", EXTRACT_16BITS(dat)));
}

static void print_32bits_val(netdissect_options *ndo, const uint32_t *dat)
{
	ND_PRINT((ndo, "%lu", (u_long)EXTRACT_32BITS(dat)));
}




static void l2tp_msgtype_print(netdissect_options *ndo, const u_char *dat)
{
	const uint16_t *ptr = (const uint16_t *)dat;

	ND_PRINT((ndo, "%s", tok2str(l2tp_msgtype2str, "MSGTYPE-#%u", EXTRACT_16BITS(ptr))));
}

static void l2tp_result_code_print(netdissect_options *ndo, const u_char *dat, u_int length)
{
	const uint16_t *ptr = (const uint16_t *)dat;

	ND_PRINT((ndo, "%u", EXTRACT_16BITS(ptr))); ptr++;	
	if (length > 2) {				
	        ND_PRINT((ndo, "/%u", EXTRACT_16BITS(ptr))); ptr++;
	}
	if (length > 4) {				
		ND_PRINT((ndo, " "));
		print_string(ndo, (const u_char *)ptr, length - 4);
	}
}

static void l2tp_proto_ver_print(netdissect_options *ndo, const uint16_t *dat)
{
	ND_PRINT((ndo, "%u.%u", (EXTRACT_16BITS(dat) >> 8), (EXTRACT_16BITS(dat) & 0xff)));
}

static void l2tp_framing_cap_print(netdissect_options *ndo, const u_char *dat)
{
	const uint32_t *ptr = (const uint32_t *)dat;

	if (EXTRACT_32BITS(ptr) &  L2TP_FRAMING_CAP_ASYNC_MASK) {
		ND_PRINT((ndo, "A"));
	}
	if (EXTRACT_32BITS(ptr) &  L2TP_FRAMING_CAP_SYNC_MASK) {
		ND_PRINT((ndo, "S"));
	}
}

static void l2tp_bearer_cap_print(netdissect_options *ndo, const u_char *dat)
{
	const uint32_t *ptr = (const uint32_t *)dat;

	if (EXTRACT_32BITS(ptr) &  L2TP_BEARER_CAP_ANALOG_MASK) {
		ND_PRINT((ndo, "A"));
	}
	if (EXTRACT_32BITS(ptr) &  L2TP_BEARER_CAP_DIGITAL_MASK) {
		ND_PRINT((ndo, "D"));
	}
}

static void l2tp_q931_cc_print(netdissect_options *ndo, const u_char *dat, u_int length)
{
	print_16bits_val(ndo, (const uint16_t *)dat);
	ND_PRINT((ndo, ", %02x", dat[2]));
	if (length > 3) {
		ND_PRINT((ndo, " "));
		print_string(ndo, dat+3, length-3);
	}
}

static void l2tp_bearer_type_print(netdissect_options *ndo, const u_char *dat)
{
	const uint32_t *ptr = (const uint32_t *)dat;

	if (EXTRACT_32BITS(ptr) &  L2TP_BEARER_TYPE_ANALOG_MASK) {
		ND_PRINT((ndo, "A"));
	}
	if (EXTRACT_32BITS(ptr) &  L2TP_BEARER_TYPE_DIGITAL_MASK) {
		ND_PRINT((ndo, "D"));
	}
}

static void l2tp_framing_type_print(netdissect_options *ndo, const u_char *dat)
{
	const uint32_t *ptr = (const uint32_t *)dat;

	if (EXTRACT_32BITS(ptr) &  L2TP_FRAMING_TYPE_ASYNC_MASK) {
		ND_PRINT((ndo, "A"));
	}
	if (EXTRACT_32BITS(ptr) &  L2TP_FRAMING_TYPE_SYNC_MASK) {
		ND_PRINT((ndo, "S"));
	}
}

static void l2tp_packet_proc_delay_print(netdissect_options *ndo)
{
	ND_PRINT((ndo, "obsolete"));
}

static void l2tp_proxy_auth_type_print(netdissect_options *ndo, const u_char *dat)
{
	const uint16_t *ptr = (const uint16_t *)dat;

	ND_PRINT((ndo, "%s", tok2str(l2tp_authentype2str, "AuthType-#%u", EXTRACT_16BITS(ptr))));
}

static void l2tp_proxy_auth_id_print(netdissect_options *ndo, const u_char *dat)
{
	const uint16_t *ptr = (const uint16_t *)dat;

	ND_PRINT((ndo, "%u", EXTRACT_16BITS(ptr) & L2TP_PROXY_AUTH_ID_MASK));
}

static void l2tp_call_errors_print(netdissect_options *ndo, const u_char *dat)
{
	const uint16_t *ptr = (const uint16_t *)dat;
	uint16_t val_h, val_l;

	ptr++;		

	val_h = EXTRACT_16BITS(ptr); ptr++;
	val_l = EXTRACT_16BITS(ptr); ptr++;
	ND_PRINT((ndo, "CRCErr=%u ", (val_h<<16) + val_l));

	val_h = EXTRACT_16BITS(ptr); ptr++;
	val_l = EXTRACT_16BITS(ptr); ptr++;
	ND_PRINT((ndo, "FrameErr=%u ", (val_h<<16) + val_l));

	val_h = EXTRACT_16BITS(ptr); ptr++;
	val_l = EXTRACT_16BITS(ptr); ptr++;
	ND_PRINT((ndo, "HardOver=%u ", (val_h<<16) + val_l));

	val_h = EXTRACT_16BITS(ptr); ptr++;
	val_l = EXTRACT_16BITS(ptr); ptr++;
	ND_PRINT((ndo, "BufOver=%u ", (val_h<<16) + val_l));

	val_h = EXTRACT_16BITS(ptr); ptr++;
	val_l = EXTRACT_16BITS(ptr); ptr++;
	ND_PRINT((ndo, "Timeout=%u ", (val_h<<16) + val_l));

	val_h = EXTRACT_16BITS(ptr); ptr++;
	val_l = EXTRACT_16BITS(ptr); ptr++;
	ND_PRINT((ndo, "AlignErr=%u ", (val_h<<16) + val_l));
}

static void l2tp_accm_print(netdissect_options *ndo, const u_char *dat)
{
	const uint16_t *ptr = (const uint16_t *)dat;
	uint16_t val_h, val_l;

	ptr++;		

	val_h = EXTRACT_16BITS(ptr); ptr++;
	val_l = EXTRACT_16BITS(ptr); ptr++;
	ND_PRINT((ndo, "send=%08x ", (val_h<<16) + val_l));

	val_h = EXTRACT_16BITS(ptr); ptr++;
	val_l = EXTRACT_16BITS(ptr); ptr++;
	ND_PRINT((ndo, "recv=%08x ", (val_h<<16) + val_l));
}

static void l2tp_ppp_discon_cc_print(netdissect_options *ndo, const u_char *dat, u_int length)
{
	const uint16_t *ptr = (const uint16_t *)dat;

	ND_PRINT((ndo, "%04x, ", EXTRACT_16BITS(ptr))); ptr++;	
	ND_PRINT((ndo, "%04x ",  EXTRACT_16BITS(ptr))); ptr++;	
	ND_PRINT((ndo, "%s", tok2str(l2tp_cc_direction2str, "Direction-#%u", *((const u_char *)ptr++))));

	if (length > 5) {
		ND_PRINT((ndo, " "));
		print_string(ndo, (const u_char *)ptr, length-5);
	}
}

static void l2tp_avp_print(netdissect_options *ndo, const u_char *dat, int length)
{
	u_int len;
	const uint16_t *ptr = (const uint16_t *)dat;
	uint16_t attr_type;
	int hidden = FALSE;

	if (length <= 0) {
		return;
	}

	ND_PRINT((ndo, " "));

	ND_TCHECK(*ptr);	
	len = EXTRACT_16BITS(ptr) & L2TP_AVP_HDR_LEN_MASK;

	
	if (len < 6)
		goto trunc;

	
	if (len > (u_int)length)
		goto trunc;

	
	ND_TCHECK2(*ptr, len);
	

	if (EXTRACT_16BITS(ptr) & L2TP_AVP_HDR_FLAG_MANDATORY) {
		ND_PRINT((ndo, "*"));
	}
	if (EXTRACT_16BITS(ptr) & L2TP_AVP_HDR_FLAG_HIDDEN) {
		hidden = TRUE;
		ND_PRINT((ndo, "?"));
	}
	ptr++;

	if (EXTRACT_16BITS(ptr)) {
		
	        ND_PRINT((ndo, "VENDOR%04x:", EXTRACT_16BITS(ptr))); ptr++;
		ND_PRINT((ndo, "ATTR%04x", EXTRACT_16BITS(ptr))); ptr++;
		ND_PRINT((ndo, "("));
		print_octets(ndo, (const u_char *)ptr, len-6);
		ND_PRINT((ndo, ")"));
	} else {
		
		ptr++;
		attr_type = EXTRACT_16BITS(ptr); ptr++;
		ND_PRINT((ndo, "%s", tok2str(l2tp_avp2str, "AVP-#%u", attr_type)));
		ND_PRINT((ndo, "("));
		if (hidden) {
			ND_PRINT((ndo, "???"));
		} else {
			switch (attr_type) {
			case L2TP_AVP_MSGTYPE:
				l2tp_msgtype_print(ndo, (const u_char *)ptr);
				break;
			case L2TP_AVP_RESULT_CODE:
				l2tp_result_code_print(ndo, (const u_char *)ptr, len-6);
				break;
			case L2TP_AVP_PROTO_VER:
				l2tp_proto_ver_print(ndo, ptr);
				break;
			case L2TP_AVP_FRAMING_CAP:
				l2tp_framing_cap_print(ndo, (const u_char *)ptr);
				break;
			case L2TP_AVP_BEARER_CAP:
				l2tp_bearer_cap_print(ndo, (const u_char *)ptr);
				break;
			case L2TP_AVP_TIE_BREAKER:
				print_octets(ndo, (const u_char *)ptr, 8);
				break;
			case L2TP_AVP_FIRM_VER:
			case L2TP_AVP_ASSND_TUN_ID:
			case L2TP_AVP_RECV_WIN_SIZE:
			case L2TP_AVP_ASSND_SESS_ID:
				print_16bits_val(ndo, ptr);
				break;
			case L2TP_AVP_HOST_NAME:
			case L2TP_AVP_VENDOR_NAME:
			case L2TP_AVP_CALLING_NUMBER:
			case L2TP_AVP_CALLED_NUMBER:
			case L2TP_AVP_SUB_ADDRESS:
			case L2TP_AVP_PROXY_AUTH_NAME:
			case L2TP_AVP_PRIVATE_GRP_ID:
				print_string(ndo, (const u_char *)ptr, len-6);
				break;
			case L2TP_AVP_CHALLENGE:
			case L2TP_AVP_INI_RECV_LCP:
			case L2TP_AVP_LAST_SENT_LCP:
			case L2TP_AVP_LAST_RECV_LCP:
			case L2TP_AVP_PROXY_AUTH_CHAL:
			case L2TP_AVP_PROXY_AUTH_RESP:
			case L2TP_AVP_RANDOM_VECTOR:
				print_octets(ndo, (const u_char *)ptr, len-6);
				break;
			case L2TP_AVP_Q931_CC:
				l2tp_q931_cc_print(ndo, (const u_char *)ptr, len-6);
				break;
			case L2TP_AVP_CHALLENGE_RESP:
				print_octets(ndo, (const u_char *)ptr, 16);
				break;
			case L2TP_AVP_CALL_SER_NUM:
			case L2TP_AVP_MINIMUM_BPS:
			case L2TP_AVP_MAXIMUM_BPS:
			case L2TP_AVP_TX_CONN_SPEED:
			case L2TP_AVP_PHY_CHANNEL_ID:
			case L2TP_AVP_RX_CONN_SPEED:
				print_32bits_val(ndo, (const uint32_t *)ptr);
				break;
			case L2TP_AVP_BEARER_TYPE:
				l2tp_bearer_type_print(ndo, (const u_char *)ptr);
				break;
			case L2TP_AVP_FRAMING_TYPE:
				l2tp_framing_type_print(ndo, (const u_char *)ptr);
				break;
			case L2TP_AVP_PACKET_PROC_DELAY:
				l2tp_packet_proc_delay_print(ndo);
				break;
			case L2TP_AVP_PROXY_AUTH_TYPE:
				l2tp_proxy_auth_type_print(ndo, (const u_char *)ptr);
				break;
			case L2TP_AVP_PROXY_AUTH_ID:
				l2tp_proxy_auth_id_print(ndo, (const u_char *)ptr);
				break;
			case L2TP_AVP_CALL_ERRORS:
				l2tp_call_errors_print(ndo, (const u_char *)ptr);
				break;
			case L2TP_AVP_ACCM:
				l2tp_accm_print(ndo, (const u_char *)ptr);
				break;
			case L2TP_AVP_SEQ_REQUIRED:
				break;	
			case L2TP_AVP_PPP_DISCON_CC:
				l2tp_ppp_discon_cc_print(ndo, (const u_char *)ptr, len-6);
				break;
			default:
				break;
			}
		}
		ND_PRINT((ndo, ")"));
	}

	l2tp_avp_print(ndo, dat+len, length-len);
	return;

 trunc:
	ND_PRINT((ndo, "|..."));
}


void l2tp_print(netdissect_options *ndo, const u_char *dat, u_int length)
{
	const u_char *ptr = dat;
	u_int cnt = 0;			
	uint16_t pad;
	int flag_t, flag_l, flag_s, flag_o;
	uint16_t l2tp_len;

	flag_t = flag_l = flag_s = flag_o = FALSE;

	ND_TCHECK2(*ptr, 2);	
	if ((EXTRACT_16BITS(ptr) & L2TP_VERSION_MASK) == L2TP_VERSION_L2TP) {
		ND_PRINT((ndo, " l2tp:"));
	} else if ((EXTRACT_16BITS(ptr) & L2TP_VERSION_MASK) == L2TP_VERSION_L2F) {
		ND_PRINT((ndo, " l2f:"));
		return;		
	} else {
		ND_PRINT((ndo, " Unknown Version, neither L2F(1) nor L2TP(2)"));
		return;		
	}

	ND_PRINT((ndo, "["));
	if (EXTRACT_16BITS(ptr) & L2TP_FLAG_TYPE) {
		flag_t = TRUE;
		ND_PRINT((ndo, "T"));
	}
	if (EXTRACT_16BITS(ptr) & L2TP_FLAG_LENGTH) {
		flag_l = TRUE;
		ND_PRINT((ndo, "L"));
	}
	if (EXTRACT_16BITS(ptr) & L2TP_FLAG_SEQUENCE) {
		flag_s = TRUE;
		ND_PRINT((ndo, "S"));
	}
	if (EXTRACT_16BITS(ptr) & L2TP_FLAG_OFFSET) {
		flag_o = TRUE;
		ND_PRINT((ndo, "O"));
	}
	if (EXTRACT_16BITS(ptr) & L2TP_FLAG_PRIORITY)
		ND_PRINT((ndo, "P"));
	ND_PRINT((ndo, "]"));

	ptr += 2;
	cnt += 2;

	if (flag_l) {
		ND_TCHECK2(*ptr, 2);	
		l2tp_len = EXTRACT_16BITS(ptr);
		ptr += 2;
		cnt += 2;
	} else {
		l2tp_len = 0;
	}

	ND_TCHECK2(*ptr, 2);		
	ND_PRINT((ndo, "(%u/", EXTRACT_16BITS(ptr)));
	ptr += 2;
	cnt += 2;
	ND_TCHECK2(*ptr, 2);		
	ND_PRINT((ndo, "%u)",  EXTRACT_16BITS(ptr)));
	ptr += 2;
	cnt += 2;

	if (flag_s) {
		ND_TCHECK2(*ptr, 2);	
		ND_PRINT((ndo, "Ns=%u,", EXTRACT_16BITS(ptr)));
		ptr += 2;
		cnt += 2;
		ND_TCHECK2(*ptr, 2);	
		ND_PRINT((ndo, "Nr=%u",  EXTRACT_16BITS(ptr)));
		ptr += 2;
		cnt += 2;
	}

	if (flag_o) {
		ND_TCHECK2(*ptr, 2);	
		pad =  EXTRACT_16BITS(ptr);
		ptr += (2 + pad);
		cnt += (2 + pad);
	}

	if (flag_l) {
		if (length < l2tp_len) {
			ND_PRINT((ndo, " Length %u larger than packet", l2tp_len));
			return;
		}
		length = l2tp_len;
	}
	if (length < cnt) {
		ND_PRINT((ndo, " Length %u smaller than header length", length));
		return;
	}
	if (flag_t) {
		if (!flag_l) {
			ND_PRINT((ndo, " No length"));
			return;
		}
		if (length - cnt == 0) {
			ND_PRINT((ndo, " ZLB"));
		} else {
			l2tp_avp_print(ndo, ptr, length - cnt);
		}
	} else {
		ND_PRINT((ndo, " {"));
		ppp_print(ndo, ptr, length - cnt);
		ND_PRINT((ndo, "}"));
	}

	return;

 trunc:
	ND_PRINT((ndo, "%s", tstr));
}
