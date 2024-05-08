



static const char sccsid[] = "@(#)utility.c	8.4 (Berkeley) 5/30/95";



__FBSDID("$FreeBSD$");




















    void ttloop()
{

    DIAG(TD_REPORT, output_data("td: ttloop\r\n"));
    if (nfrontp - nbackp > 0) {
	netflush();
    }
    ncc = read(net, netibuf, sizeof netibuf);
    if (ncc < 0) {
	syslog(LOG_INFO, "ttloop:  read: %m");
	exit(1);
    } else if (ncc == 0) {
	syslog(LOG_INFO, "ttloop:  peer died: %m");
	exit(1);
    }
    DIAG(TD_REPORT, output_data("td: ttloop read %d chars\r\n", ncc));
    netip = netibuf;
    telrcv();			
    if (ncc > 0) {
	pfrontp = pbackp = ptyobuf;
	telrcv();
    }
}  


int stilloob(int s)
{
    static struct timeval timeout = { 0, 0 };
    fd_set	excepts;
    int value;

    do {
	FD_ZERO(&excepts);
	FD_SET(s, &excepts);
	memset((char *)&timeout, 0, sizeof timeout);
	value = select(s+1, (fd_set *)0, (fd_set *)0, &excepts, &timeout);
    } while ((value == -1) && (errno == EINTR));

    if (value < 0) {
	fatalperror(pty, "select");
    }
    if (FD_ISSET(s, &excepts)) {
	return 1;
    } else {
	return 0;
    }
}

void ptyflush(void)
{
	int n;

	if ((n = pfrontp - pbackp) > 0) {
		DIAG(TD_REPORT | TD_PTYDATA, output_data("td: ptyflush %d chars\r\n", n));
		DIAG(TD_PTYDATA, printdata("pd", pbackp, n));
		n = write(pty, pbackp, n);
	}
	if (n < 0) {
		if (errno == EWOULDBLOCK || errno == EINTR)
			return;
		cleanup(0);
	}
	pbackp += n;
	if (pbackp == pfrontp)
		pbackp = pfrontp = ptyobuf;
}


static char * nextitem(char *current)
{
    if ((*current&0xff) != IAC) {
	return current+1;
    }
    switch (*(current+1)&0xff) {
    case DO:
    case DONT:
    case WILL:
    case WONT:
	return current+3;
    case SB:		
	{
	    char *look = current+2;

	    for (;;) {
		if ((*look++&0xff) == IAC) {
		    if ((*look++&0xff) == SE) {
			return look;
		    }
		}
	    }
	}
    default:
	return current+2;
    }
}  


void netclear(void)
{
    char *thisitem, *next;
    char *good;



    thisitem = nclearto > netobuf ? nclearto : netobuf;

    thisitem = netobuf;


    while ((next = nextitem(thisitem)) <= nbackp) {
	thisitem = next;
    }

    


    good = nclearto > netobuf ? nclearto : netobuf;

    good = netobuf;	


    while (nfrontp > thisitem) {
	if (wewant(thisitem)) {
	    int length;

	    next = thisitem;
	    do {
		next = nextitem(next);
	    } while (wewant(next) && (nfrontp > next));
	    length = next-thisitem;
	    memmove(good, thisitem, length);
	    good += length;
	    thisitem = next;
	} else {
	    thisitem = nextitem(thisitem);
	}
    }

    nbackp = netobuf;
    nfrontp = good;		
    neturg = 0;
}  


void netflush(void)
{
    int n;
    extern int not42;

    while ((n = nfrontp - nbackp) > 0) {

	
	DIAG(TD_REPORT, {
	    n += output_data("td: netflush %d chars\r\n", n);
	});


	if (encrypt_output) {
		char *s = nclearto ? nclearto : nbackp;
		if (nfrontp - s > 0) {
			(*encrypt_output)((unsigned char *)s, nfrontp-s);
			nclearto = nfrontp;
		}
	}

	
	if ((neturg == 0) || (not42 == 0)) {
	    n = write(net, nbackp, n);	
	} else {
	    n = neturg - nbackp;
	    
	    if (n > 1) {
		n = send(net, nbackp, n-1, 0);	
	    } else {
		n = send(net, nbackp, n, MSG_OOB);	
	    }
	}
	if (n == -1) {
	    if (errno == EWOULDBLOCK || errno == EINTR)
		continue;
	    cleanup(0);
	    
	}
	nbackp += n;

	if (nbackp > nclearto)
	    nclearto = 0;

	if (nbackp >= neturg) {
	    neturg = 0;
	}
	if (nbackp == nfrontp) {
	    nbackp = nfrontp = netobuf;

	    nclearto = 0;

	}
    }
    return;
}  





void fatal(int f, const char *msg)
{
	char buf[BUFSIZ];

	(void) snprintf(buf, sizeof(buf), "telnetd: %s.\r\n", msg);

	if (encrypt_output) {
		
		encrypt_send_end();
		netflush();
	}

	(void) write(f, buf, (int)strlen(buf));
	sleep(1);	
	exit(1);
}

void fatalperror(int f, const char *msg)
{
	char buf[BUFSIZ];

	(void) snprintf(buf, sizeof(buf), "%s: %s", msg, strerror(errno));
	fatal(f, buf);
}

char editedhost[32];

void edithost(char *pat, char *host)
{
	char *res = editedhost;

	if (pat) {
		while (*pat) {
			switch (*pat) {

			case '#':
				if (*host)
					host++;
				break;

			case '@':
				if (*host)
					*res++ = *host++;
				break;

			default:
				*res++ = *pat;
				break;
			}
			if (res == &editedhost[sizeof editedhost - 1]) {
				*res = '\0';
				return;
			}
			pat++;
		}
	}
	if (*host)
		(void) strncpy(res, host, sizeof editedhost - (res - editedhost) -1);
	else *res = '\0';
	editedhost[sizeof editedhost - 1] = '\0';
}

static char *putlocation;

static void putstr(const char *s)
{

	while (*s)
		putchr(*s++);
}

void putchr(int cc)
{
	*putlocation++ = cc;
}


static char fmtstr[] = { "%+" };

static char fmtstr[] = { "%l:%M%P on %A, %d %B %Y" };


void putf(char *cp, char *where)
{
	char *slash;
	time_t t;
	char db[100];

	static struct utsname kerninfo;

	if (!*kerninfo.sysname)
		uname(&kerninfo);


	putlocation = where;

	while (*cp) {
		if (*cp =='\n') {
			putstr("\r\n");
			cp++;
			continue;
		} else if (*cp != '%') {
			putchr(*cp++);
			continue;
		}
		switch (*++cp) {

		case 't':

			
			slash = strchr(line+1, '/');

			slash = strrchr(line, '/');

			if (slash == (char *) 0)
				putstr(line);
			else putstr(&slash[1]);
			break;

		case 'h':
			putstr(editedhost);
			break;

		case 'd':

			setlocale(LC_TIME, "");

			(void)time(&t);
			(void)strftime(db, sizeof(db), fmtstr, localtime(&t));
			putstr(db);
			break;


		case 's':
			putstr(kerninfo.sysname);
			break;

		case 'm':
			putstr(kerninfo.machine);
			break;

		case 'r':
			putstr(kerninfo.release);
			break;

		case 'v':
			putstr(kerninfo.version);
			break;


		case '%':
			putchr('%');
			break;
		}
		cp++;
	}
}



void printoption(const char *fmt, int option)
{
	if (TELOPT_OK(option))
		output_data("%s %s\r\n", fmt, TELOPT(option));
	else if (TELCMD_OK(option))
		output_data("%s %s\r\n", fmt, TELCMD(option));
	else output_data("%s %d\r\n", fmt, option);
	return;
}

void printsub(char direction, unsigned char *pointer, int length)
{
    int i = 0;

	if (!(diagnostic & TD_OPTIONS))
		return;

	if (direction) {
	    output_data("td: %s suboption ", direction == '<' ? "recv" : "send");
	    if (length >= 3) {
		int j;

		i = pointer[length-2];
		j = pointer[length-1];

		if (i != IAC || j != SE) {
		    output_data("(terminated by ");
		    if (TELOPT_OK(i))
			output_data("%s ", TELOPT(i));
		    else if (TELCMD_OK(i))
			output_data("%s ", TELCMD(i));
		    else output_data("%d ", i);
		    if (TELOPT_OK(j))
			output_data("%s", TELOPT(j));
		    else if (TELCMD_OK(j))
			output_data("%s", TELCMD(j));
		    else output_data("%d", j);
		    output_data(", not IAC SE!) ");
		}
	    }
	    length -= 2;
	}
	if (length < 1) {
	    output_data("(Empty suboption??\?)");
	    return;
	}
	switch (pointer[0]) {
	case TELOPT_TTYPE:
	    output_data("TERMINAL-TYPE ");
	    switch (pointer[1]) {
	    case TELQUAL_IS:
		output_data("IS \"%.*s\"", length-2, (char *)pointer+2);
		break;
	    case TELQUAL_SEND:
		output_data("SEND");
		break;
	    default:
		output_data( "- unknown qualifier %d (0x%x).", pointer[1], pointer[1]);

	    }
	    break;
	case TELOPT_TSPEED:
	    output_data("TERMINAL-SPEED");
	    if (length < 2) {
		output_data(" (empty suboption??\?)");
		break;
	    }
	    switch (pointer[1]) {
	    case TELQUAL_IS:
		output_data(" IS %.*s", length-2, (char *)pointer+2);
		break;
	    default:
		if (pointer[1] == 1)
		    output_data(" SEND");
		else output_data(" %d (unknown)", pointer[1]);
		for (i = 2; i < length; i++) {
		    output_data(" ?%d?", pointer[i]);
		}
		break;
	    }
	    break;

	case TELOPT_LFLOW:
	    output_data("TOGGLE-FLOW-CONTROL");
	    if (length < 2) {
		output_data(" (empty suboption??\?)");
		break;
	    }
	    switch (pointer[1]) {
	    case LFLOW_OFF:
		output_data(" OFF"); break;
	    case LFLOW_ON:
		output_data(" ON"); break;
	    case LFLOW_RESTART_ANY:
		output_data(" RESTART-ANY"); break;
	    case LFLOW_RESTART_XON:
		output_data(" RESTART-XON"); break;
	    default:
		output_data(" %d (unknown)", pointer[1]);
	    }
	    for (i = 2; i < length; i++) {
		output_data(" ?%d?", pointer[i]);
	    }
	    break;

	case TELOPT_NAWS:
	    output_data("NAWS");
	    if (length < 2) {
		output_data(" (empty suboption??\?)");
		break;
	    }
	    if (length == 2) {
		output_data(" ?%d?", pointer[1]);
		break;
	    }
	    output_data(" %d %d (%d)", pointer[1], pointer[2], (int)((((unsigned int)pointer[1])<<8)|((unsigned int)pointer[2])));

	    if (length == 4) {
		output_data(" ?%d?", pointer[3]);
		break;
	    }
	    output_data(" %d %d (%d)", pointer[3], pointer[4], (int)((((unsigned int)pointer[3])<<8)|((unsigned int)pointer[4])));

	    for (i = 5; i < length; i++) {
		output_data(" ?%d?", pointer[i]);
	    }
	    break;

	case TELOPT_LINEMODE:
	    output_data("LINEMODE ");
	    if (length < 2) {
		output_data(" (empty suboption??\?)");
		break;
	    }
	    switch (pointer[1]) {
	    case WILL:
		output_data("WILL ");
		goto common;
	    case WONT:
		output_data("WONT ");
		goto common;
	    case DO:
		output_data("DO ");
		goto common;
	    case DONT:
		output_data("DONT ");
	    common:
		if (length < 3) {
		    output_data("(no option??\?)");
		    break;
		}
		switch (pointer[2]) {
		case LM_FORWARDMASK:
		    output_data("Forward Mask");
		    for (i = 3; i < length; i++) {
			output_data(" %x", pointer[i]);
		    }
		    break;
		default:
		    output_data("%d (unknown)", pointer[2]);
		    for (i = 3; i < length; i++) {
			output_data(" %d", pointer[i]);
		    }
		    break;
		}
		break;

	    case LM_SLC:
		output_data("SLC");
		for (i = 2; i < length - 2; i += 3) {
		    if (SLC_NAME_OK(pointer[i+SLC_FUNC]))
			output_data(" %s", SLC_NAME(pointer[i+SLC_FUNC]));
		    else output_data(" %d", pointer[i+SLC_FUNC]);
		    switch (pointer[i+SLC_FLAGS]&SLC_LEVELBITS) {
		    case SLC_NOSUPPORT:
			output_data(" NOSUPPORT"); break;
		    case SLC_CANTCHANGE:
			output_data(" CANTCHANGE"); break;
		    case SLC_VARIABLE:
			output_data(" VARIABLE"); break;
		    case SLC_DEFAULT:
			output_data(" DEFAULT"); break;
		    }
		    output_data("%s%s%s", pointer[i+SLC_FLAGS]&SLC_ACK ? "|ACK" : "", pointer[i+SLC_FLAGS]&SLC_FLUSHIN ? "|FLUSHIN" : "", pointer[i+SLC_FLAGS]&SLC_FLUSHOUT ? "|FLUSHOUT" : "");


		    if (pointer[i+SLC_FLAGS]& ~(SLC_ACK|SLC_FLUSHIN| SLC_FLUSHOUT| SLC_LEVELBITS)) {
			output_data("(0x%x)", pointer[i+SLC_FLAGS]);
		    }
		    output_data(" %d;", pointer[i+SLC_VALUE]);
		    if ((pointer[i+SLC_VALUE] == IAC) && (pointer[i+SLC_VALUE+1] == IAC))
				i++;
		}
		for (; i < length; i++) {
		    output_data(" ?%d?", pointer[i]);
		}
		break;

	    case LM_MODE:
		output_data("MODE ");
		if (length < 3) {
		    output_data("(no mode??\?)");
		    break;
		}
		{
		    char tbuf[32];
		    sprintf(tbuf, "%s%s%s%s%s", pointer[2]&MODE_EDIT ? "|EDIT" : "", pointer[2]&MODE_TRAPSIG ? "|TRAPSIG" : "", pointer[2]&MODE_SOFT_TAB ? "|SOFT_TAB" : "", pointer[2]&MODE_LIT_ECHO ? "|LIT_ECHO" : "", pointer[2]&MODE_ACK ? "|ACK" : "");




		    output_data("%s", tbuf[1] ? &tbuf[1] : "0");
		}
		if (pointer[2]&~(MODE_EDIT|MODE_TRAPSIG|MODE_ACK)) {
		    output_data(" (0x%x)", pointer[2]);
		}
		for (i = 3; i < length; i++) {
		    output_data(" ?0x%x?", pointer[i]);
		}
		break;
	    default:
		output_data("%d (unknown)", pointer[1]);
		for (i = 2; i < length; i++) {
		    output_data(" %d", pointer[i]);
		}
	    }
	    break;

	case TELOPT_STATUS: {
	    const char *cp;
	    int j, k;

	    output_data("STATUS");

	    switch (pointer[1]) {
	    default:
		if (pointer[1] == TELQUAL_SEND)
		    output_data(" SEND");
		else output_data(" %d (unknown)", pointer[1]);
		for (i = 2; i < length; i++) {
		    output_data(" ?%d?", pointer[i]);
		}
		break;
	    case TELQUAL_IS:
		output_data(" IS\r\n");

		for (i = 2; i < length; i++) {
		    switch(pointer[i]) {
		    case DO:	cp = "DO"; goto common2;
		    case DONT:	cp = "DONT"; goto common2;
		    case WILL:	cp = "WILL"; goto common2;
		    case WONT:	cp = "WONT"; goto common2;
		    common2:
			i++;
			if (TELOPT_OK(pointer[i]))
			    output_data(" %s %s", cp, TELOPT(pointer[i]));
			else output_data(" %s %d", cp, pointer[i]);

			output_data("\r\n");
			break;

		    case SB:
			output_data(" SB ");
			i++;
			j = k = i;
			while (j < length) {
			    if (pointer[j] == SE) {
				if (j+1 == length)
				    break;
				if (pointer[j+1] == SE)
				    j++;
				else break;
			    }
			    pointer[k++] = pointer[j++];
			}
			printsub(0, &pointer[i], k - i);
			if (i < length) {
			    output_data(" SE");
			    i = j;
			} else i = j - 1;

			output_data("\r\n");

			break;

		    default:
			output_data(" %d", pointer[i]);
			break;
		    }
		}
		break;
	    }
	    break;
	  }

	case TELOPT_XDISPLOC:
	    output_data("X-DISPLAY-LOCATION ");
	    switch (pointer[1]) {
	    case TELQUAL_IS:
		output_data("IS \"%.*s\"", length-2, (char *)pointer+2);
		break;
	    case TELQUAL_SEND:
		output_data("SEND");
		break;
	    default:
		output_data("- unknown qualifier %d (0x%x).", pointer[1], pointer[1]);
	    }
	    break;

	case TELOPT_NEW_ENVIRON:
	    output_data("NEW-ENVIRON ");
	    goto env_common1;
	case TELOPT_OLD_ENVIRON:
	    output_data("OLD-ENVIRON");
	env_common1:
	    switch (pointer[1]) {
	    case TELQUAL_IS:
		output_data("IS ");
		goto env_common;
	    case TELQUAL_SEND:
		output_data("SEND ");
		goto env_common;
	    case TELQUAL_INFO:
		output_data("INFO ");
	    env_common:
		{
		    int noquote = 2;
		    for (i = 2; i < length; i++ ) {
			switch (pointer[i]) {
			case NEW_ENV_VAR:
			    output_data("%s", "\" VAR " + noquote);
			    noquote = 2;
			    break;

			case NEW_ENV_VALUE:
			    output_data("%s", "\" VALUE " + noquote);
			    noquote = 2;
			    break;

			case ENV_ESC:
			    output_data("%s", "\" ESC " + noquote);
			    noquote = 2;
			    break;

			case ENV_USERVAR:
			    output_data("%s", "\" USERVAR " + noquote);
			    noquote = 2;
			    break;

			default:
			    if (isprint(pointer[i]) && pointer[i] != '"') {
				if (noquote) {
				    output_data("\"");
				    noquote = 0;
				}
				output_data("%c", pointer[i]);
			    } else {
				output_data("\" %03o " + noquote, pointer[i]);
				noquote = 2;
			    }
			    break;
			}
		    }
		    if (!noquote)
			output_data("\"");
		    break;
		}
	    }
	    break;


	case TELOPT_AUTHENTICATION:
	    output_data("AUTHENTICATION");

	    if (length < 2) {
		output_data(" (empty suboption??\?)");
		break;
	    }
	    switch (pointer[1]) {
	    case TELQUAL_REPLY:
	    case TELQUAL_IS:
		output_data(" %s ", (pointer[1] == TELQUAL_IS) ? "IS" : "REPLY");
		if (AUTHTYPE_NAME_OK(pointer[2]))
		    output_data("%s ", AUTHTYPE_NAME(pointer[2]));
		else output_data("%d ", pointer[2]);
		if (length < 3) {
		    output_data("(partial suboption??\?)");
		    break;
		}
		output_data("%s|%s", ((pointer[3] & AUTH_WHO_MASK) == AUTH_WHO_CLIENT) ? "CLIENT" : "SERVER", ((pointer[3] & AUTH_HOW_MASK) == AUTH_HOW_MUTUAL) ? "MUTUAL" : "ONE-WAY");




    		{
		    char buf[512];
		    auth_printsub(&pointer[1], length - 1, buf, sizeof(buf));
		    output_data("%s", buf);
		}
		break;

	    case TELQUAL_SEND:
		i = 2;
		output_data(" SEND ");
		while (i < length) {
		    if (AUTHTYPE_NAME_OK(pointer[i]))
			output_data("%s ", AUTHTYPE_NAME(pointer[i]));
		    else output_data("%d ", pointer[i]);
		    if (++i >= length) {
			output_data("(partial suboption??\?)");
			break;
		    }
		    output_data("%s|%s ", ((pointer[i] & AUTH_WHO_MASK) == AUTH_WHO_CLIENT) ? "CLIENT" : "SERVER", ((pointer[i] & AUTH_HOW_MASK) == AUTH_HOW_MUTUAL) ? "MUTUAL" : "ONE-WAY");



		    ++i;
		}
		break;

	    case TELQUAL_NAME:
		output_data(" NAME \"%.*s\"", length - 2, pointer + 2);
		break;

	    default:
		    for (i = 2; i < length; i++) {
			output_data(" ?%d?", pointer[i]);
		    }
		    break;
	    }
	    break;



	case TELOPT_ENCRYPT:
	    output_data("ENCRYPT");
	    if (length < 2) {
		output_data(" (empty suboption??\?)");
		break;
	    }
	    switch (pointer[1]) {
	    case ENCRYPT_START:
		output_data(" START");
		break;

	    case ENCRYPT_END:
		output_data(" END");
		break;

	    case ENCRYPT_REQSTART:
		output_data(" REQUEST-START");
		break;

	    case ENCRYPT_REQEND:
		output_data(" REQUEST-END");
		break;

	    case ENCRYPT_IS:
	    case ENCRYPT_REPLY:
		output_data(" %s ", (pointer[1] == ENCRYPT_IS) ? "IS" : "REPLY");
		if (length < 3) {
		    output_data(" (partial suboption??\?)");
		    break;
		}
		if (ENCTYPE_NAME_OK(pointer[2]))
		    output_data("%s ", ENCTYPE_NAME(pointer[2]));
		else output_data(" %d (unknown)", pointer[2]);

		{
		    char buf[512];
		    encrypt_printsub(&pointer[1], length - 1, buf, sizeof(buf));
		    output_data("%s", buf);
		}
		break;

	    case ENCRYPT_SUPPORT:
		i = 2;
		output_data(" SUPPORT ");
		while (i < length) {
		    if (ENCTYPE_NAME_OK(pointer[i]))
			output_data("%s ", ENCTYPE_NAME(pointer[i]));
		    else output_data("%d ", pointer[i]);
		    i++;
		}
		break;

	    case ENCRYPT_ENC_KEYID:
		output_data(" ENC_KEYID");
		goto encommon;

	    case ENCRYPT_DEC_KEYID:
		output_data(" DEC_KEYID");
		goto encommon;

	    default:
		output_data(" %d (unknown)", pointer[1]);
	    encommon:
		for (i = 2; i < length; i++) {
		    output_data(" %d", pointer[i]);
		}
		break;
	    }
	    break;


	default:
	    if (TELOPT_OK(pointer[0]))
		output_data("%s (unknown)", TELOPT(pointer[0]));
	    else output_data("%d (unknown)", pointer[i]);
	    for (i = 1; i < length; i++) {
		output_data(" %d", pointer[i]);
	    }
	    break;
	}
	output_data("\r\n");
}


void printdata(const char *tag, char *ptr, int cnt)
{
	int i;
	char xbuf[30];

	while (cnt) {
		
		if ((&netobuf[BUFSIZ] - nfrontp) < 80) {
			netflush();
		}

		
		output_data("%s: ", tag);
		for (i = 0; i < 20 && cnt; i++) {
			output_data("%02x", *ptr);
			if (isprint(*ptr)) {
				xbuf[i] = *ptr;
			} else {
				xbuf[i] = '.';
			}
			if (i % 2) {
				output_data(" ");
			}
			cnt--;
			ptr++;
		}
		xbuf[i] = '\0';
		output_data(" %s\r\n", xbuf );
	}
}
