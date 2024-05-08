
























int32_t thiszone;		

const char istr[] = " (invalid)";







void fn_print_char(netdissect_options *ndo, u_char c)
{
	if (!ND_ISASCII(c)) {
		c = ND_TOASCII(c);
		ND_PRINT((ndo, "M-"));
	}
	if (!ND_ISPRINT(c)) {
		c ^= 0x40;	
		ND_PRINT((ndo, "^"));
	}
	ND_PRINT((ndo, "%c", c));
}


int fn_print(netdissect_options *ndo, register const u_char *s, register const u_char *ep)

{
	register int ret;
	register u_char c;

	ret = 1;			
	while (ep == NULL || s < ep) {
		c = *s++;
		if (c == '\0') {
			ret = 0;
			break;
		}
		if (!ND_ISASCII(c)) {
			c = ND_TOASCII(c);
			ND_PRINT((ndo, "M-"));
		}
		if (!ND_ISPRINT(c)) {
			c ^= 0x40;	
			ND_PRINT((ndo, "^"));
		}
		ND_PRINT((ndo, "%c", c));
	}
	return(ret);
}


u_int fn_printztn(netdissect_options *ndo, register const u_char *s, register u_int n, register const u_char *ep)

{
	register u_int bytes;
	register u_char c;

	bytes = 0;
	for (;;) {
		if (n == 0 || (ep != NULL && s >= ep)) {
			
			bytes = 0;
			break;
		}

		c = *s++;
		bytes++;
		n--;
		if (c == '\0') {
			
			break;
		}
		if (!ND_ISASCII(c)) {
			c = ND_TOASCII(c);
			ND_PRINT((ndo, "M-"));
		}
		if (!ND_ISPRINT(c)) {
			c ^= 0x40;	
			ND_PRINT((ndo, "^"));
		}
		ND_PRINT((ndo, "%c", c));
	}
	return(bytes);
}


int fn_printn(netdissect_options *ndo, register const u_char *s, register u_int n, register const u_char *ep)

{
	register u_char c;

	while (n > 0 && (ep == NULL || s < ep)) {
		n--;
		c = *s++;
		if (!ND_ISASCII(c)) {
			c = ND_TOASCII(c);
			ND_PRINT((ndo, "M-"));
		}
		if (!ND_ISPRINT(c)) {
			c ^= 0x40;	
			ND_PRINT((ndo, "^"));
		}
		ND_PRINT((ndo, "%c", c));
	}
	return (n == 0) ? 0 : 1;
}


int fn_printzp(netdissect_options *ndo, register const u_char *s, register u_int n, register const u_char *ep)


{
	register int ret;
	register u_char c;

	ret = 1;			
	while (n > 0 && (ep == NULL || s < ep)) {
		n--;
		c = *s++;
		if (c == '\0') {
			ret = 0;
			break;
		}
		if (!ND_ISASCII(c)) {
			c = ND_TOASCII(c);
			ND_PRINT((ndo, "M-"));
		}
		if (!ND_ISPRINT(c)) {
			c ^= 0x40;	
			ND_PRINT((ndo, "^"));
		}
		ND_PRINT((ndo, "%c", c));
	}
	return (n == 0) ? 0 : ret;
}


static char * ts_format(netdissect_options *ndo  _U_  , int sec, int usec, char *buf)




{
	const char *format;


	switch (ndo->ndo_tstamp_precision) {

	case PCAP_TSTAMP_PRECISION_MICRO:
		format = "%02d:%02d:%02d.%06u";
		break;

	case PCAP_TSTAMP_PRECISION_NANO:
		format = "%02d:%02d:%02d.%09u";
		break;

	default:
		format = "%02d:%02d:%02d.{unknown}";
		break;
	}

	format = "%02d:%02d:%02d.%06u";


	snprintf(buf, TS_BUF_SIZE, format, sec / 3600, (sec % 3600) / 60, sec % 60, usec);

        return buf;
}


static char * ts_unix_format(netdissect_options *ndo  _U_  , int sec, int usec, char *buf)




{
	const char *format;


	switch (ndo->ndo_tstamp_precision) {

	case PCAP_TSTAMP_PRECISION_MICRO:
		format = "%u.%06u";
		break;

	case PCAP_TSTAMP_PRECISION_NANO:
		format = "%u.%09u";
		break;

	default:
		format = "%u.{unknown}";
		break;
	}

	format = "%u.%06u";


	snprintf(buf, TS_BUF_SIZE, format, (unsigned)sec, (unsigned)usec);

	return buf;
}


void ts_print(netdissect_options *ndo, register const struct timeval *tvp)

{
	register int s;
	struct tm *tm;
	time_t Time;
	char buf[TS_BUF_SIZE];
	static struct timeval tv_ref;
	struct timeval tv_result;
	int negative_offset;
	int nano_prec;

	switch (ndo->ndo_tflag) {

	case 0: 
		s = (tvp->tv_sec + thiszone) % 86400;
		ND_PRINT((ndo, "%s ", ts_format(ndo, s, tvp->tv_usec, buf)));
		break;

	case 1: 
		break;

	case 2: 
		ND_PRINT((ndo, "%s ", ts_unix_format(ndo, tvp->tv_sec, tvp->tv_usec, buf)));
		break;

	case 3: 
        case 5: 

		switch (ndo->ndo_tstamp_precision) {
		case PCAP_TSTAMP_PRECISION_MICRO:
			nano_prec = 0;
			break;
		case PCAP_TSTAMP_PRECISION_NANO:
			nano_prec = 1;
			break;
		default:
			nano_prec = 0;
			break;
		}

		nano_prec = 0;

		if (!(netdissect_timevalisset(&tv_ref)))
			tv_ref = *tvp; 

		negative_offset = netdissect_timevalcmp(tvp, &tv_ref, <);
		if (negative_offset)
			netdissect_timevalsub(&tv_ref, tvp, &tv_result, nano_prec);
		else netdissect_timevalsub(tvp, &tv_ref, &tv_result, nano_prec);

		ND_PRINT((ndo, (negative_offset ? "-" : " ")));

		ND_PRINT((ndo, "%s ", ts_format(ndo, tv_result.tv_sec, tv_result.tv_usec, buf)));

                if (ndo->ndo_tflag == 3)
			tv_ref = *tvp; 
		break;

	case 4: 
		s = (tvp->tv_sec + thiszone) % 86400;
		Time = (tvp->tv_sec + thiszone) - s;
		tm = gmtime (&Time);
		if (!tm)
			ND_PRINT((ndo, "Date fail  "));
		else ND_PRINT((ndo, "%04d-%02d-%02d %s ", tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday, ts_format(ndo, s, tvp->tv_usec, buf)));


		break;
	}
}


void relts_print(netdissect_options *ndo, int secs)

{
	static const char *lengths[] = {"y", "w", "d", "h", "m", "s";
	static const int seconds[] = {31536000, 604800, 86400, 3600, 60, 1};
	const char **l = lengths;
	const int *s = seconds;

	if (secs == 0) {
		ND_PRINT((ndo, "0s"));
		return;
	}
	if (secs < 0) {
		ND_PRINT((ndo, "-"));
		secs = -secs;
	}
	while (secs > 0) {
		if (secs >= *s) {
			ND_PRINT((ndo, "%d%s", secs / *s, *l));
			secs -= (secs / *s) * *s;
		}
		s++;
		l++;
	}
}



int print_unknown_data(netdissect_options *ndo, const u_char *cp,const char *ident,int len)
{
	if (len < 0) {
          ND_PRINT((ndo,"%sDissector error: print_unknown_data called with negative length", ident));
		return(0);
	}
	if (ndo->ndo_snapend - cp < len)
		len = ndo->ndo_snapend - cp;
	if (len < 0) {
          ND_PRINT((ndo,"%sDissector error: print_unknown_data called with pointer past end of packet", ident));
		return(0);
	}
        hex_print(ndo, ident,cp,len);
	return(1); 
}


const char * tok2strbuf(register const struct tok *lp, register const char *fmt, register u_int v, char *buf, size_t bufsize)

{
	if (lp != NULL) {
		while (lp->s != NULL) {
			if (lp->v == v)
				return (lp->s);
			++lp;
		}
	}
	if (fmt == NULL)
		fmt = "#%d";

	(void)snprintf(buf, bufsize, fmt, v);
	return (const char *)buf;
}


const char * tok2str(register const struct tok *lp, register const char *fmt, register u_int v)

{
	static char buf[4][TOKBUFSIZE];
	static int idx = 0;
	char *ret;

	ret = buf[idx];
	idx = (idx+1) & 3;
	return tok2strbuf(lp, fmt, v, ret, sizeof(buf[0]));
}


static char * bittok2str_internal(register const struct tok *lp, register const char *fmt, register u_int v, const char *sep)

{
        static char buf[256]; 
        int buflen=0;
        register u_int rotbit; 
        register u_int tokval;
        const char * sepstr = "";

	while (lp != NULL && lp->s != NULL) {
            tokval=lp->v;   
            rotbit=1;
            while (rotbit != 0) {
                
		if (tokval == (v&rotbit)) {
                    
                    buflen+=snprintf(buf+buflen, sizeof(buf)-buflen, "%s%s", sepstr, lp->s);
                    sepstr = sep;
                    break;
                }
                rotbit=rotbit<<1; 
            }
            lp++;
	}

        if (buflen == 0)
            
            (void)snprintf(buf, sizeof(buf), fmt == NULL ? "#%08x" : fmt, v);
        return (buf);
}


char * bittok2str_nosep(register const struct tok *lp, register const char *fmt, register u_int v)

{
    return (bittok2str_internal(lp, fmt, v, ""));
}


char * bittok2str(register const struct tok *lp, register const char *fmt, register u_int v)

{
    return (bittok2str_internal(lp, fmt, v, ", "));
}


const char * tok2strary_internal(register const char **lp, int n, register const char *fmt, register int v)

{
	static char buf[TOKBUFSIZE];

	if (v >= 0 && v < n && lp[v] != NULL)
		return lp[v];
	if (fmt == NULL)
		fmt = "#%d";
	(void)snprintf(buf, sizeof(buf), fmt, v);
	return (buf);
}



int mask2plen(uint32_t mask)
{
	uint32_t bitmasks[33] = {
		0x00000000, 0x80000000, 0xc0000000, 0xe0000000, 0xf0000000, 0xf8000000, 0xfc000000, 0xfe000000, 0xff000000, 0xff800000, 0xffc00000, 0xffe00000, 0xfff00000, 0xfff80000, 0xfffc0000, 0xfffe0000, 0xffff0000, 0xffff8000, 0xffffc000, 0xffffe000, 0xfffff000, 0xfffff800, 0xfffffc00, 0xfffffe00, 0xffffff00, 0xffffff80, 0xffffffc0, 0xffffffe0, 0xfffffff0, 0xfffffff8, 0xfffffffc, 0xfffffffe, 0xffffffff };








	int prefix_len = 32;

	
	while (prefix_len >= 0) {
		if (bitmasks[prefix_len] == mask)
			break;
		prefix_len--;
	}
	return (prefix_len);
}

int mask62plen(const u_char *mask)
{
	u_char bitmasks[9] = {
		0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff };


	int byte;
	int cidr_len = 0;

	for (byte = 0; byte < 16; byte++) {
		u_int bits;

		for (bits = 0; bits < (sizeof (bitmasks) / sizeof (bitmasks[0])); bits++) {
			if (mask[byte] == bitmasks[bits]) {
				cidr_len += bits;
				break;
			}
		}

		if (mask[byte] != 0xff)
			break;
	}
	return (cidr_len);
}





static int fetch_token(netdissect_options *ndo, const u_char *pptr, u_int idx, u_int len, u_char *tbuf, size_t tbuflen)

{
	size_t toklen = 0;

	for (; idx < len; idx++) {
		if (!ND_TTEST(*(pptr + idx))) {
			
			return (0);
		}
		if (!isascii(*(pptr + idx))) {
			
			return (0);
		}
		if (isspace(*(pptr + idx))) {
			
			break;
		}
		if (!isprint(*(pptr + idx))) {
			
			return (0);
		}
		if (toklen + 2 > tbuflen) {
			
			return (0);
		}
		tbuf[toklen] = *(pptr + idx);
		toklen++;
	}
	if (toklen == 0) {
		
		return (0);
	}
	tbuf[toklen] = '\0';

	
	for (; idx < len; idx++) {
		if (!ND_TTEST(*(pptr + idx))) {
			
			break;
		}
		if (*(pptr + idx) == '\r' || *(pptr + idx) == '\n') {
			
			break;
		}
		if (!isascii(*(pptr + idx)) || !isprint(*(pptr + idx))) {
			
			break;
		}
		if (!isspace(*(pptr + idx))) {
			
			break;
		}
	}
	return (idx);
}


static u_int print_txt_line(netdissect_options *ndo, const char *protoname, const char *prefix, const u_char *pptr, u_int idx, u_int len)

{
	u_int startidx;
	u_int linelen;

	startidx = idx;
	while (idx < len) {
		ND_TCHECK(*(pptr+idx));
		if (*(pptr+idx) == '\n') {
			
			linelen = idx - startidx;
			idx++;
			goto print;
		} else if (*(pptr+idx) == '\r') {
			
			if ((idx+1) >= len) {
				
				return (0);
			}
			ND_TCHECK(*(pptr+idx+1));
			if (*(pptr+idx+1) == '\n') {
				
				linelen = idx - startidx;
				idx += 2;
				goto print;
			}

			
			return (0);
		} else if (!isascii(*(pptr+idx)) || (!isprint(*(pptr+idx)) && *(pptr+idx) != '\t')) {
			
			return (0);
		}
		idx++;
	}

	
trunc:
	linelen = idx - startidx;
	ND_PRINT((ndo, "%s%.*s[!%s]", prefix, (int)linelen, pptr + startidx, protoname));
	return (0);

print:
	ND_PRINT((ndo, "%s%.*s", prefix, (int)linelen, pptr + startidx));
	return (idx);
}

void txtproto_print(netdissect_options *ndo, const u_char *pptr, u_int len, const char *protoname, const char **cmds, u_int flags)

{
	u_int idx, eol;
	u_char token[MAX_TOKEN+1];
	const char *cmd;
	int is_reqresp = 0;
	const char *pnp;

	if (cmds != NULL) {
		
		idx = fetch_token(ndo, pptr, 0, len, token, sizeof(token));
		if (idx != 0) {
			
			while ((cmd = *cmds++) != NULL) {
				if (ascii_strcasecmp((const char *)token, cmd) == 0) {
					
					is_reqresp = 1;
					break;
				}
			}

			
			if (flags & RESP_CODE_SECOND_TOKEN) {
				
				idx = fetch_token(ndo, pptr, idx, len, token, sizeof(token));
			}
			if (idx != 0) {
				if (isdigit(token[0]) && isdigit(token[1]) && isdigit(token[2]) && token[3] == '\0') {
					
					is_reqresp = 1;
				}
			}
		}
	} else {
		
		is_reqresp = 1;
	}

	
	for (pnp = protoname; *pnp != '\0'; pnp++)
		ND_PRINT((ndo, "%c", toupper((u_char)*pnp)));

	if (is_reqresp) {
		
		if (ndo->ndo_vflag) {
			
			ND_PRINT((ndo, ", length: %u", len));
			for (idx = 0;
			    idx < len && (eol = print_txt_line(ndo, protoname, "\n\t", pptr, idx, len)) != 0;
			    idx = eol)
				;
		} else {
			
			print_txt_line(ndo, protoname, ": ", pptr, 0, len);
		}
	}
}

void safeputs(netdissect_options *ndo, const u_char *s, const u_int maxlen)

{
	u_int idx = 0;

	while (*s && idx < maxlen) {
		safeputchar(ndo, *s);
		idx++;
		s++;
	}
}

void safeputchar(netdissect_options *ndo, const u_char c)

{
	ND_PRINT((ndo, (c < 0x80 && ND_ISPRINT(c)) ? "%c" : "\\0x%02x", c));
}



void unaligned_memcpy(void *p, const void *q, size_t l)
{
	memcpy(p, q, l);
}


int unaligned_memcmp(const void *p, const void *q, size_t l)
{
	return (memcmp(p, q, l));
}


