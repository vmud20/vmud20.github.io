
























struct	tftphdr {
	unsigned short	th_opcode;		
	union {
		unsigned short	tu_block;	
		unsigned short	tu_code;	
		char	tu_stuff[1];	
	} th_u;
	char	th_data[1];		
};
















static const char tstr[] = " [|tftp]";


static const struct tok op2str[] = {
	{ RRQ,		"RRQ" },	 { WRQ,		"WRQ" }, { DATA,		"DATA" }, { ACK,		"ACK" }, { TFTP_ERROR,	"ERROR" }, { OACK,		"OACK" }, { 0,		NULL }





};


static const struct tok err2str[] = {
	{ EUNDEF,	"EUNDEF" },	 { ENOTFOUND,	"ENOTFOUND" }, { EACCESS,	"EACCESS" }, { ENOSPACE,	"ENOSPACE" }, { EBADOP,	"EBADOP" }, { EBADID,	"EBADID" }, { EEXISTS,	"EEXISTS" }, { ENOUSER,	"ENOUSER" }, { 0,		NULL }







};


void tftp_print(netdissect_options *ndo, register const u_char *bp, u_int length)

{
	register const struct tftphdr *tp;
	register const char *cp;
	register const u_char *p;
	register int opcode, i;

	tp = (const struct tftphdr *)bp;

	
	ND_PRINT((ndo, " %d", length));

	
	ND_TCHECK(tp->th_opcode);
	opcode = EXTRACT_16BITS(&tp->th_opcode);
	cp = tok2str(op2str, "tftp-#%d", opcode);
	ND_PRINT((ndo, " %s", cp));
	
	if (*cp == 't')
		return;

	switch (opcode) {

	case RRQ:
	case WRQ:
	case OACK:
		p = (const u_char *)tp->th_stuff;
		ND_PRINT((ndo, " "));
		
		if (opcode != OACK)
			ND_PRINT((ndo, "\""));
		i = fn_print(ndo, p, ndo->ndo_snapend);
		if (opcode != OACK)
			ND_PRINT((ndo, "\""));

		
		while ((p = (const u_char *)strchr((const char *)p, '\0')) != NULL) {
			if (length <= (u_int)(p - (const u_char *)&tp->th_block))
				break;
			p++;
			if (*p != '\0') {
				ND_PRINT((ndo, " "));
				fn_print(ndo, p, ndo->ndo_snapend);
			}
		}

		if (i)
			goto trunc;
		break;

	case ACK:
	case DATA:
		ND_TCHECK(tp->th_block);
		ND_PRINT((ndo, " block %d", EXTRACT_16BITS(&tp->th_block)));
		break;

	case TFTP_ERROR:
		
		ND_TCHECK(tp->th_code);
		ND_PRINT((ndo, " %s \"", tok2str(err2str, "tftp-err-#%d \"", EXTRACT_16BITS(&tp->th_code))));
		
		i = fn_print(ndo, (const u_char *)tp->th_data, ndo->ndo_snapend);
		ND_PRINT((ndo, "\""));
		if (i)
			goto trunc;
		break;

	default:
		
		ND_PRINT((ndo, "(unknown #%d)", opcode));
		break;
	}
	return;
trunc:
	ND_PRINT((ndo, "%s", tstr));
	return;
}
