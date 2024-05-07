







mod_export char *scriptname;     




mod_export char *scriptfilename;




mod_export int incompfunc;


struct widechar_array {
    wchar_t *chars;
    size_t len;
};
typedef struct widechar_array *Widechar_array;


static struct widechar_array wordchars_wide;


static struct widechar_array ifs_wide;



static void set_widearray(char *mb_array, Widechar_array wca)
{
    if (wca->chars) {
	free(wca->chars);
	wca->chars = NULL;
    }
    wca->len = 0;

    if (!isset(MULTIBYTE))
	return;

    if (mb_array) {
	VARARR(wchar_t, tmpwcs, strlen(mb_array));
	wchar_t *wcptr = tmpwcs;
	wint_t wci;

	mb_charinit();
	while (*mb_array) {
	    int mblen;

	    if (STOUC(*mb_array) <= 0x7f) {
		mb_array++;
		*wcptr++ = (wchar_t)*mb_array;
		continue;
	    }

	    mblen = mb_metacharlenconv(mb_array, &wci);

	    if (!mblen)
		break;
	    
	    if (wci == WEOF)
		return;
	    *wcptr++ = (wchar_t)wci;

	    
	    if (wcptr[-1] < 0)
		fprintf(stderr, "BUG: Bad cast to wchar_t\n");

	    mb_array += mblen;
	}

	wca->len = wcptr - tmpwcs;
	wca->chars = (wchar_t *)zalloc(wca->len * sizeof(wchar_t));
	wmemcpy(wca->chars, tmpwcs, wca->len);
    }
}





static void zwarning(const char *cmd, const char *fmt, va_list ap)
{
    if (isatty(2))
	zleentry(ZLE_CMD_TRASH);

    char *prefix = scriptname ? scriptname : (argzero ? argzero : "");

    if (cmd) {
	if (unset(SHINSTDIN) || locallevel) {
	    nicezputs(prefix, stderr);
	    fputc((unsigned char)':', stderr);
	}
	nicezputs(cmd, stderr);
	fputc((unsigned char)':', stderr);
    } else {
	
	nicezputs((isset(SHINSTDIN) && !locallevel) ? "zsh" : prefix, stderr);
	fputc((unsigned char)':', stderr);
    }

    zerrmsg(stderr, fmt, ap);
}



mod_export void zerr(VA_ALIST1(const char *fmt))
VA_DCL {
    va_list ap;
    VA_DEF_ARG(const char *fmt);

    if (errflag || noerrs) {
	if (noerrs < 2)
	    errflag |= ERRFLAG_ERROR;
	return;
    }
    errflag |= ERRFLAG_ERROR;

    VA_START(ap, fmt);
    VA_GET_ARG(ap, fmt, const char *);
    zwarning(NULL, fmt, ap);
    va_end(ap);
}


mod_export void zerrnam(VA_ALIST2(const char *cmd, const char *fmt))
VA_DCL {
    va_list ap;
    VA_DEF_ARG(const char *cmd);
    VA_DEF_ARG(const char *fmt);

    if (errflag || noerrs)
	return;
    errflag |= ERRFLAG_ERROR;

    VA_START(ap, fmt);
    VA_GET_ARG(ap, cmd, const char *);
    VA_GET_ARG(ap, fmt, const char *);
    zwarning(cmd, fmt, ap);
    va_end(ap);
}


mod_export void zwarn(VA_ALIST1(const char *fmt))
VA_DCL {
    va_list ap;
    VA_DEF_ARG(const char *fmt);

    if (errflag || noerrs)
	return;

    VA_START(ap, fmt);
    VA_GET_ARG(ap, fmt, const char *);
    zwarning(NULL, fmt, ap);
    va_end(ap);
}


mod_export void zwarnnam(VA_ALIST2(const char *cmd, const char *fmt))
VA_DCL {
    va_list ap;
    VA_DEF_ARG(const char *cmd);
    VA_DEF_ARG(const char *fmt);

    if (errflag || noerrs)
	return;

    VA_START(ap, fmt);
    VA_GET_ARG(ap, cmd, const char *);
    VA_GET_ARG(ap, fmt, const char *);
    zwarning(cmd, fmt, ap);
    va_end(ap);
}





mod_export void dputs(VA_ALIST1(const char *message))
VA_DCL {
    char *filename;
    FILE *file;
    va_list ap;
    VA_DEF_ARG(const char *message);

    VA_START(ap, message);
    VA_GET_ARG(ap, message, const char *);
    if ((filename = getsparam_u("ZSH_DEBUG_LOG")) != NULL && (file = fopen(filename, "a")) != NULL) {
	zerrmsg(file, message, ap);
	fclose(file);
    } else zerrmsg(stderr, message, ap);
    va_end(ap);
}





mod_export void zz_plural_z_alpha(void)
{
}



void zerrmsg(FILE *file, const char *fmt, va_list ap)
{
    const char *str;
    int num;

    long lnum;



    int olderrno;
    char errbuf[ERRBUFSIZE];

    char *errmsg;

    if ((unset(SHINSTDIN) || locallevel) && lineno) {

	fprintf(file, "%lld: ", lineno);

	fprintf(file, "%ld: ", (long)lineno);

    } else fputc((unsigned char)' ', file);

    while (*fmt)
	if (*fmt == '%') {
	    fmt++;
	    switch (*fmt++) {
	    case 's':
		str = va_arg(ap, const char *);
		nicezputs(str, file);
		break;
	    case 'l': {
		char *s;
		str = va_arg(ap, const char *);
		num = va_arg(ap, int);
		num = metalen(str, num);
		s = zhalloc(num + 1);
		memcpy(s, str, num);
		s[num] = '\0';
		nicezputs(s, file);
		break;
	    }

	    case 'L':
		lnum = va_arg(ap, long);
		fprintf(file, "%ld", lnum);
		break;

	    case 'd':
		num = va_arg(ap, int);
		fprintf(file, "%d", num);
		break;
	    case '%':
		putc('%', file);
		break;
	    case 'c':
		num = va_arg(ap, int);

		mb_charinit();
		zputs(wcs_nicechar(num, NULL, NULL), file);

		zputs(nicechar(num), file);

		break;
	    case 'e':
		
		num = va_arg(ap, int);
		if (num == EINTR) {
		    fputs("interrupt\n", file);
		    errflag |= ERRFLAG_ERROR;
		    return;
		}
		errmsg = strerror(num);
		
		if (num == EIO)
		    fputs(errmsg, file);
		else {
		    fputc(tulower(errmsg[0]), file);
		    fputs(errmsg + 1, file);
		}
		break;
	    
	    }
	} else {
	    putc(*fmt == Meta ? *++fmt ^ 32 : *fmt, file);
	    fmt++;
	}
    putc('\n', file);
    fflush(file);
}




mod_export int putraw(int c)
{
    putc(c, stdout);
    return 0;
}




mod_export int putshout(int c)
{
    putc(c, shout);
    return 0;
}





mod_export char * nicechar_sel(int c, int quotable)
{
    static char buf[10];
    char *s = buf;
    c &= 0xff;
    if (ZISPRINT(c))
	goto done;
    if (c & 0x80) {
	if (isset(PRINTEIGHTBIT))
	    goto done;
	*s++ = '\\';
	*s++ = 'M';
	*s++ = '-';
	c &= 0x7f;
	if(ZISPRINT(c))
	    goto done;
    }
    if (c == 0x7f) {
	if (quotable) {
	    *s++ = '\\';
	    *s++ = 'C';
	    *s++ = '-';
	} else *s++ = '^';
	c = '?';
    } else if (c == '\n') {
	*s++ = '\\';
	c = 'n';
    } else if (c == '\t') {
	*s++ = '\\';
	c = 't';
    } else if (c < 0x20) {
	if (quotable) {
	    *s++ = '\\';
	    *s++ = 'C';
	    *s++ = '-';
	} else *s++ = '^';
	c += 0x40;
    }
    done:
    
    if (imeta(c)) {
	*s++ = Meta;
	*s++ = c ^ 32;
    } else *s++ = c;
    *s = 0;
    return buf;
}


mod_export char * nicechar(int c)
{
    return nicechar_sel(c, 0);
}




mod_export char * nicechar(int c)
{
    static char buf[10];
    char *s = buf;
    c &= 0xff;
    if (ZISPRINT(c))
	goto done;
    if (c & 0x80) {
	if (isset(PRINTEIGHTBIT))
	    goto done;
	*s++ = '\\';
	*s++ = 'M';
	*s++ = '-';
	c &= 0x7f;
	if(ZISPRINT(c))
	    goto done;
    }
    if (c == 0x7f) {
	*s++ = '\\';
	*s++ = 'C';
	*s++ = '-';
	c = '?';
    } else if (c == '\n') {
	*s++ = '\\';
	c = 'n';
    } else if (c == '\t') {
	*s++ = '\\';
	c = 't';
    } else if (c < 0x20) {
	*s++ = '\\';
	*s++ = 'C';
	*s++ = '-';
	c += 0x40;
    }
    done:
    
    if (imeta(c)) {
	*s++ = Meta;
	*s++ = c ^ 32;
    } else *s++ = c;
    *s = 0;
    return buf;
}






mod_export int is_nicechar(int c)
{
    c &= 0xff;
    if (ZISPRINT(c))
	return 0;
    if (c & 0x80)
	return !isset(PRINTEIGHTBIT);
    return (c == 0x7f || c == '\n' || c == '\t' || c < 0x20);
}



static mbstate_t mb_shiftstate;




mod_export void mb_charinit(void)
{
    memset(&mb_shiftstate, 0, sizeof(mb_shiftstate));
}






mod_export char * wcs_nicechar_sel(wchar_t c, size_t *widthp, char **swidep, int quotable)
{
    static char *buf;
    static int bufalloc = 0, newalloc;
    char *s, *mbptr;
    int ret = 0;
    VARARR(char, mbstr, MB_CUR_MAX);

    
    newalloc = NICECHAR_MAX;
    if (bufalloc != newalloc)
    {
	bufalloc = newalloc;
	buf = (char *)zrealloc(buf, bufalloc);
    }

    s = buf;
    if (!WC_ISPRINT(c) && (c < 0x80 || !isset(PRINTEIGHTBIT))) {
	if (c == 0x7f) {
	    if (quotable) {
		*s++ = '\\';
		*s++ = 'C';
		*s++ = '-';
	    } else *s++ = '^';
	    c = '?';
	} else if (c == L'\n') {
	    *s++ = '\\';
	    c = 'n';
	} else if (c == L'\t') {
	    *s++ = '\\';
	    c = 't';
	} else if (c < 0x20) {
	    if (quotable) {
		*s++ = '\\';
		*s++ = 'C';
		*s++ = '-';
	    } else *s++ = '^';
	    c += 0x40;
	} else if (c >= 0x80) {
	    ret = -1;
	}
    }

    if (ret != -1)
	ret = wcrtomb(mbstr, c, &mb_shiftstate);

    if (ret == -1) {
	memset(&mb_shiftstate, 0, sizeof(mb_shiftstate));
	
	if (c >=  0x10000) {
	    sprintf(buf, "\\U%.8x", (unsigned int)c);
	    if (widthp)
		*widthp = 10;
	} else if (c >= 0x100) {
	    sprintf(buf, "\\u%.4x", (unsigned int)c);
	    if (widthp)
		*widthp = 6;
	} else {
	    strcpy(buf, nicechar((int)c));
	    
	    if (widthp)
		*widthp = ztrlen(buf);
	    if (swidep)
	      *swidep = buf + strlen(buf);
	    return buf;
	}
	if (swidep)
	    *swidep = widthp ? buf + *widthp : buf;
	return buf;
    }

    if (widthp) {
	int wcw = WCWIDTH(c);
	*widthp = (s - buf);
	if (wcw >= 0)
	    *widthp += wcw;
	else (*widthp)++;
    }
    if (swidep)
	*swidep = s;
    for (mbptr = mbstr; ret; s++, mbptr++, ret--) {
	DPUTS(s >= buf + NICECHAR_MAX, "BUG: buffer too small in wcs_nicechar");
	if (imeta(*mbptr)) {
	    *s++ = Meta;
	    DPUTS(s >= buf + NICECHAR_MAX, "BUG: buffer too small for metafied char in wcs_nicechar");
	    *s = *mbptr ^ 32;
	} else {
	    *s = *mbptr;
	}
    }
    *s = 0;
    return buf;
}


mod_export char * wcs_nicechar(wchar_t c, size_t *widthp, char **swidep)
{
    return wcs_nicechar_sel(c, widthp, swidep, 0);
}




mod_export int is_wcs_nicechar(wchar_t c)
{
    if (!WC_ISPRINT(c) && (c < 0x80 || !isset(PRINTEIGHTBIT))) {
	if (c == 0x7f || c == L'\n' || c == L'\t' || c < 0x20)
	    return 1;
	if (c >= 0x80) {
	    return (c >= 0x100);
	}
    }
    return 0;
}


mod_export int zwcwidth(wint_t wc)
{
    int wcw;
    
    if (wc == WEOF || unset(MULTIBYTE))
	return 1;
    wcw = WCWIDTH(wc);
    
    if (wcw < 0)
	return 1;
    return wcw;
}






char * pathprog(char *prog, char **namep)
{
    char **pp, ppmaxlen = 0, *buf, *funmeta;
    struct stat st;

    for (pp = path; *pp; pp++)
    {
	int len = strlen(*pp);
	if (len > ppmaxlen)
	    ppmaxlen = len;
    }
    buf = zhalloc(ppmaxlen + strlen(prog) + 2);
    for (pp = path; *pp; pp++) {
	sprintf(buf, "%s/%s", *pp, prog);
	funmeta = unmeta(buf);
	if (access(funmeta, F_OK) == 0 && stat(funmeta, &st) >= 0 && !S_ISDIR(st.st_mode)) {

	    if (namep)
		*namep = buf;
	    return funmeta;
	}
    }

    return NULL;
}




char * findpwd(char *s)
{
    char *t;

    if (*s == '/')
	return xsymlink(s, 0);
    s = tricat((pwd[1]) ? pwd : "", "/", s);
    t = xsymlink(s, 0);
    zsfree(s);
    return t;
}




int ispwd(char *s)
{
    struct stat sbuf, tbuf;

    
    if (*s != '/')
	return 0;

    if (stat((s = unmeta(s)), &sbuf) == 0 && stat(".", &tbuf) == 0)
	if (sbuf.st_dev == tbuf.st_dev && sbuf.st_ino == tbuf.st_ino) {
	    
	    while (*s) {
		if (s[0] == '.' && (!s[1] || s[1] == '/' || (s[1] == '.' && (!s[2] || s[2] == '/'))))

		    break;
		while (*s++ != '/' && *s)
		    continue;
	    }
	    return !*s;
	}
    return 0;
}

static char xbuf[PATH_MAX*2+1];


static char ** slashsplit(char *s)
{
    char *t, **r, **q;
    int t0;

    if (!*s)
	return (char **) zshcalloc(sizeof(char *));

    for (t = s, t0 = 0; *t; t++)
	if (*t == '/')
	    t0++;
    q = r = (char **) zalloc(sizeof(char *) * (t0 + 2));

    while ((t = strchr(s, '/'))) {
	*q++ = ztrduppfx(s, t - s);
	while (*t == '/')
	    t++;
	if (!*t) {
	    *q = NULL;
	    return r;
	}
	s = t;
    }
    *q++ = ztrdup(s);
    *q = NULL;
    return r;
}




static int xsymlinks(char *s, int full)
{
    char **pp, **opp;
    char xbuf2[PATH_MAX*3+1], xbuf3[PATH_MAX*2+1];
    int t0, ret = 0;
    zulong xbuflen = strlen(xbuf), pplen;

    opp = pp = slashsplit(s);
    for (; xbuflen < sizeof(xbuf) && *pp && ret >= 0; pp++) {
	if (!strcmp(*pp, "."))
	    continue;
	if (!strcmp(*pp, "..")) {
	    char *p;

	    if (!strcmp(xbuf, "/"))
		continue;
	    if (!*xbuf)
		continue;
	    p = xbuf + xbuflen;
	    while (*--p != '/')
		xbuflen--;
	    *p = '\0';
	    
	    xbuflen--;
	    continue;
	}
	
	pplen = strlen(*pp) + 1;
	if (xbuflen + pplen + 1 > sizeof(xbuf2)) {
	    *xbuf = 0;
	    ret = -1;
	    break;
	}
	memcpy(xbuf2, xbuf, xbuflen);
	xbuf2[xbuflen] = '/';
	memcpy(xbuf2 + xbuflen + 1, *pp, pplen);
	t0 = readlink(unmeta(xbuf2), xbuf3, PATH_MAX);
	if (t0 == -1) {
	    if ((xbuflen += pplen) < sizeof(xbuf)) {
		strcat(xbuf, "/");
		strcat(xbuf, *pp);
	    } else {
		*xbuf = 0;
		ret = -1;
		break;
	    }
	} else {
	    ret = 1;
	    metafy(xbuf3, t0, META_NOALLOC);
	    if (!full) {
		
		zulong len = xbuflen;
		if (*xbuf3 == '/')
		    strcpy(xbuf, xbuf3);
		else if ((len += strlen(xbuf3) + 1) < sizeof(xbuf)) {
		    strcpy(xbuf + xbuflen, "/");
		    strcpy(xbuf + xbuflen + 1, xbuf3);
		} else {
		    *xbuf = 0;
		    ret = -1;
		    break;
		}

		while (*++pp) {
		    zulong newlen = len + strlen(*pp) + 1;
		    if (newlen < sizeof(xbuf)) {
			strcpy(xbuf + len, "/");
			strcpy(xbuf + len + 1, *pp);
			len = newlen;
		    } else {
			*xbuf = 01;
			ret = -1;
			break;
		    }
		}
		
		break;
	    }
	    if (*xbuf3 == '/') {
		strcpy(xbuf, "");
		if (xsymlinks(xbuf3 + 1, 1) < 0)
		    ret = -1;
		else xbuflen = strlen(xbuf);
	    } else if (xsymlinks(xbuf3, 1) < 0)
		    ret = -1;
		else xbuflen = strlen(xbuf);
	}
    }
    freearray(opp);
    return ret;
}




char * xsymlink(char *s, int heap)
{
    if (*s != '/')
	return NULL;
    *xbuf = '\0';
    if (xsymlinks(s + 1, 1) < 0)
	zwarn("path expansion failed, using root directory");
    if (!*xbuf)
	return heap ? dupstring("/") : ztrdup("/");
    return heap ? dupstring(xbuf) : ztrdup(xbuf);
}


void print_if_link(char *s, int all)
{
    if (*s == '/') {
	*xbuf = '\0';
	if (all) {
	    char *start = s + 1;
	    char xbuflink[PATH_MAX+1];
	    for (;;) {
		if (xsymlinks(start, 0) > 0) {
		    printf(" -> ");
		    zputs(*xbuf ? xbuf : "/", stdout);
		    if (!*xbuf)
			break;
		    strcpy(xbuflink, xbuf);
		    start = xbuflink + 1;
		    *xbuf = '\0';
		} else {
		    break;
		}
	    }
	} else {
	    if (xsymlinks(s + 1, 1) > 0)
		printf(" -> "), zputs(*xbuf ? xbuf : "/", stdout);
	}
    }
}




void fprintdir(char *s, FILE *f)
{
    Nameddir d = finddir(s);

    if (!d)
	fputs(unmeta(s), f);
    else {
	putc('~', f);
	fputs(unmeta(d->node.nam), f);
	fputs(unmeta(s + strlen(d->dir)), f);
    }
}




char * substnamedir(char *s)
{
    Nameddir d = finddir(s);

    if (!d)
	return quotestring(s, QT_BACKSLASH);
    return zhtricat("~", d->node.nam, quotestring(s + strlen(d->dir), QT_BACKSLASH));
}





uid_t cached_uid;

char *cached_username;


char * get_username(void)
{

    struct passwd *pswd;
    uid_t current_uid;

    current_uid = getuid();
    if (current_uid != cached_uid) {
	cached_uid = current_uid;
	zsfree(cached_username);
	if ((pswd = getpwuid(current_uid)))
	    cached_username = ztrdup(pswd->pw_name);
	else cached_username = ztrdup("");
    }

    cached_uid = getuid();

    return cached_username;
}



static char *finddir_full;
static Nameddir finddir_last;
static int finddir_best;




static void finddir_scan(HashNode hn, UNUSED(int flags))
{
    Nameddir nd = (Nameddir) hn;

    if(nd->diff > finddir_best && !dircmp(nd->dir, finddir_full)
       && !(nd->node.flags & ND_NOABBREV)) {
	finddir_last=nd;
	finddir_best=nd->diff;
    }
}




Nameddir finddir(char *s)
{
    static struct nameddir homenode = { {NULL, "", 0}, NULL, 0 };
    static int ffsz;
    char **ares;
    int len;

    
    if (!s) {
	homenode.dir = home ? home : "";
	homenode.diff = home ? strlen(home) : 0;
	if(homenode.diff==1)
	    homenode.diff = 0;
	if(!finddir_full)
	    finddir_full = zalloc(ffsz = PATH_MAX+1);
	finddir_full[0] = 0;
	return finddir_last = NULL;
    }


    
    if (!strcmp(s, finddir_full) && *finddir_full)
	return finddir_last;


    if ((int)strlen(s) >= ffsz) {
	free(finddir_full);
	finddir_full = zalloc(ffsz = strlen(s) * 2);
    }
    strcpy(finddir_full, s);
    finddir_best=0;
    finddir_last=NULL;
    finddir_scan(&homenode.node, 0);
    scanhashtable(nameddirtab, 0, 0, 0, finddir_scan, 0);

    ares = subst_string_by_hook("zsh_directory_name", "d", finddir_full);
    if (ares && arrlen_ge(ares, 2) && (len = (int)zstrtol(ares[1], NULL, 10)) > finddir_best) {
	
	finddir_last = (Nameddir)hcalloc(sizeof(struct nameddir));
	finddir_last->node.nam = zhtricat("[", dupstring(ares[0]), "]");
	finddir_last->dir = dupstrpfx(finddir_full, len);
	finddir_last->diff = len - strlen(finddir_last->node.nam);
	finddir_best = len;
    }

    return finddir_last;
}




mod_export void adduserdir(char *s, char *t, int flags, int always)
{
    Nameddir nd;
    char *eptr;

    
    if (!interact)
	return;

    
    if ((flags & ND_USERNAME) && nameddirtab->getnode2(nameddirtab, s))
	return;

    
    if (!always && unset(AUTONAMEDIRS) && !nameddirtab->getnode2(nameddirtab, s))
	return;

    if (!t || *t != '/' || strlen(t) >= PATH_MAX) {
	
	HashNode hn = nameddirtab->removenode(nameddirtab, s);

	if(hn)
	    nameddirtab->freenode(hn);
	return;
    }

    
    nd = (Nameddir) zshcalloc(sizeof *nd);
    nd->node.flags = flags;
    eptr = t + strlen(t);
    while (eptr > t && eptr[-1] == '/')
	eptr--;
    if (eptr == t) {
	
	nd->dir = metafy(t, -1, META_DUP);
    } else nd->dir = metafy(t, eptr - t, META_DUP);
    
    if (!strcmp(s, "PWD") || !strcmp(s, "OLDPWD"))
	nd->node.flags |= ND_NOABBREV;
    nameddirtab->addnode(nameddirtab, metafy(s, -1, META_DUP), nd);
}




char * getnameddir(char *name)
{
    Param pm;
    char *str;
    Nameddir nd;

    
    if ((nd = (Nameddir) nameddirtab->getnode(nameddirtab, name)))
	return dupstring(nd->dir);

    
    if ((pm = (Param) paramtab->getnode(paramtab, name)) && (PM_TYPE(pm->node.flags) == PM_SCALAR) && (str = getsparam(name)) && *str == '/') {

	pm->node.flags |= PM_NAMEDDIR;
	adduserdir(name, str, 0, 1);
	return str;
    }


    {
	
	struct passwd *pw;
	if ((pw = getpwnam(name))) {
	    char *dir = isset(CHASELINKS) ? xsymlink(pw->pw_dir, 0)
		: ztrdup(pw->pw_dir);
	    if (dir) {
		adduserdir(name, dir, ND_USERNAME, 1);
		str = dupstring(dir);
		zsfree(dir);
		return str;
	    } else return dupstring(pw->pw_dir);
	}
    }


    
    return NULL;
}




static int dircmp(char *s, char *t)
{
    if (s) {
	for (; *s == *t; s++, t++)
	    if (!*s)
		return 0;
	if (!*s && *t == '/')
	    return 0;
    }
    return 1;
}



static LinkList prepromptfns;




mod_export void addprepromptfn(voidvoidfnptr_t func)
{
    Prepromptfn ppdat = (Prepromptfn)zalloc(sizeof(struct prepromptfn));
    ppdat->func = func;
    if (!prepromptfns)
	prepromptfns = znewlinklist();
    zaddlinknode(prepromptfns, ppdat);
}




mod_export void delprepromptfn(voidvoidfnptr_t func)
{
    LinkNode ln;

    for (ln = firstnode(prepromptfns); ln; ln = nextnode(ln)) {
	Prepromptfn ppdat = (Prepromptfn)getdata(ln);
	if (ppdat->func == func) {
	    (void)remnode(prepromptfns, ln);
	    zfree(ppdat, sizeof(struct prepromptfn));
	    return;
	}
    }

    dputs("BUG: failed to delete node from prepromptfns");

}




mod_export LinkList timedfns;




mod_export void addtimedfn(voidvoidfnptr_t func, time_t when)
{
    Timedfn tfdat = (Timedfn)zalloc(sizeof(struct timedfn));
    tfdat->func = func;
    tfdat->when = when;

    if (!timedfns) {
	timedfns = znewlinklist();
	zaddlinknode(timedfns, tfdat);
    } else {
	LinkNode ln = firstnode(timedfns);

	
	if (!ln) {
	    zaddlinknode(timedfns, tfdat);
	    return;
	}
	for (;;) {
	    Timedfn tfdat2;
	    LinkNode next = nextnode(ln);
	    if (!next) {
		zaddlinknode(timedfns, tfdat);
		return;
	    }
	    tfdat2 = (Timedfn)getdata(next);
	    if (when < tfdat2->when) {
		zinsertlinknode(timedfns, ln, tfdat);
		return;
	    }
	    ln = next;
	}
    }
}




mod_export void deltimedfn(voidvoidfnptr_t func)
{
    LinkNode ln;

    for (ln = firstnode(timedfns); ln; ln = nextnode(ln)) {
	Timedfn ppdat = (Timedfn)getdata(ln);
	if (ppdat->func == func) {
	    (void)remnode(timedfns, ln);
	    zfree(ppdat, sizeof(struct timedfn));
	    return;
	}
    }

    dputs("BUG: failed to delete node from timedfns");

}




time_t lastmailcheck;




time_t lastwatch;




mod_export int callhookfunc(char *name, LinkList lnklst, int arrayp, int *retval)
{
    Shfunc shfunc;
	
    int osc = sfcontext, osm = stopmsg, stat = 1, ret = 0;
    int old_incompfunc = incompfunc;

    sfcontext = SFC_HOOK;
    incompfunc = 0;

    if ((shfunc = getshfunc(name))) {
	ret = doshfunc(shfunc, lnklst, 1);
	stat = 0;
    }

    if (arrayp) {
	char **arrptr;
	int namlen = strlen(name);
	VARARR(char, arrnam, namlen + HOOK_SUFFIX_LEN);
	memcpy(arrnam, name, namlen);
	memcpy(arrnam + namlen, HOOK_SUFFIX, HOOK_SUFFIX_LEN);

	if ((arrptr = getaparam(arrnam))) {
	    arrptr = arrdup(arrptr);
	    for (; *arrptr; arrptr++) {
		if ((shfunc = getshfunc(*arrptr))) {
		    int newret = doshfunc(shfunc, lnklst, 1);
		    if (!ret)
			ret = newret;
		    stat = 0;
		}
	    }
	}
    }

    sfcontext = osc;
    stopmsg = osm;
    incompfunc = old_incompfunc;

    if (retval)
	*retval = ret;
    return stat;
}




void preprompt(void)
{
    static time_t lastperiodic;
    time_t currentmailcheck;
    LinkNode ln;
    zlong period = getiparam("PERIOD");
    zlong mailcheck = getiparam("MAILCHECK");

    
    winch_unblock();
    winch_block();

    if (isset(PROMPTSP) && isset(PROMPTCR) && !use_exit_printed && shout) {
	
	char *eolmark = getsparam("PROMPT_EOL_MARK");
	char *str;
	int percents = opts[PROMPTPERCENT], w = 0;
	if (!eolmark)
	    eolmark = "%B%S%#%s%b";
	opts[PROMPTPERCENT] = 1;
	str = promptexpand(eolmark, 1, NULL, NULL, NULL);
	countprompt(str, &w, 0, -1);
	opts[PROMPTPERCENT] = percents;
	zputs(str, shout);
	fprintf(shout, "%*s\r%*s\r", (int)zterm_columns - w - !hasxn, "", w, "");
	fflush(shout);
	free(str);
    }

    
    if (unset(NOTIFY))
	scanjobs();
    if (errflag)
	return;

    
    callhookfunc("precmd", NULL, 1, NULL);
    if (errflag)
	return;

    
    if (period && ((zlong)time(NULL) > (zlong)lastperiodic + period) && !callhookfunc("periodic", NULL, 1, NULL))
	lastperiodic = time(NULL);
    if (errflag)
	return;

    
    if (watch) {
	if ((int) difftime(time(NULL), lastwatch) > getiparam("LOGCHECK")) {
	    dowatch();
	    lastwatch = time(NULL);
	}
    }
    if (errflag)
	return;

    
    currentmailcheck = time(NULL);
    if (mailcheck && (zlong) difftime(currentmailcheck, lastmailcheck) > mailcheck) {
	char *mailfile;

	if (mailpath && *mailpath && **mailpath)
	    checkmailpath(mailpath);
	else {
	    queue_signals();
	    if ((mailfile = getsparam("MAIL")) && *mailfile) {
		char *x[2];

		x[0] = mailfile;
		x[1] = NULL;
		checkmailpath(x);
	    }
	    unqueue_signals();
	}
	lastmailcheck = currentmailcheck;
    }

    if (prepromptfns) {
	for(ln = firstnode(prepromptfns); ln; ln = nextnode(ln)) {
	    Prepromptfn ppnode = (Prepromptfn)getdata(ln);
	    ppnode->func();
	}
    }
}


static void checkmailpath(char **s)
{
    struct stat st;
    char *v, *u, c;

    while (*s) {
	for (v = *s; *v && *v != '?'; v++);
	c = *v;
	*v = '\0';
	if (c != '?')
	    u = NULL;
	else u = v + 1;
	if (**s == 0) {
	    *v = c;
	    zerr("empty MAILPATH component: %s", *s);
	} else if (mailstat(unmeta(*s), &st) == -1) {
	    if (errno != ENOENT)
		zerr("%e: %s", errno, *s);
	} else if (S_ISDIR(st.st_mode)) {
	    LinkList l;
	    DIR *lock = opendir(unmeta(*s));
	    char buf[PATH_MAX * 2 + 1], **arr, **ap;
	    int ct = 1;

	    if (lock) {
		char *fn;

		pushheap();
		l = newlinklist();
		while ((fn = zreaddir(lock, 1)) && !errflag) {
		    if (u)
			sprintf(buf, "%s/%s?%s", *s, fn, u);
		    else sprintf(buf, "%s/%s", *s, fn);
		    addlinknode(l, dupstring(buf));
		    ct++;
		}
		closedir(lock);
		ap = arr = (char **) zhalloc(ct * sizeof(char *));

		while ((*ap++ = (char *)ugetnode(l)));
		checkmailpath(arr);
		popheap();
	    }
	} else if (shout) {
	    if (st.st_size && st.st_atime <= st.st_mtime && st.st_mtime >= lastmailcheck) {
		if (!u) {
		    fprintf(shout, "You have new mail.\n");
		    fflush(shout);
		} else {
		    char *usav;
		    int uusav = underscoreused;

		    usav = zalloc(underscoreused);

		    if (usav)
			memcpy(usav, zunderscore, underscoreused);

		    setunderscore(*s);

		    u = dupstring(u);
		    if (!parsestr(&u)) {
			singsub(&u);
			zputs(u, shout);
			fputc('\n', shout);
			fflush(shout);
		    }
		    if (usav) {
			setunderscore(usav);
			zfree(usav, uusav);
		    }
		}
	    }
	    if (isset(MAILWARNING) && st.st_atime > st.st_mtime && st.st_atime > lastmailcheck && st.st_size) {
		fprintf(shout, "The mail in %s has been read.\n", unmeta(*s));
		fflush(shout);
	    }
	}
	*v = c;
	s++;
    }
}




FILE *xtrerr = 0;


void printprompt4(void)
{
    if (!xtrerr)
	xtrerr = stderr;
    if (prompt4) {
	int l, t = opts[XTRACE];
	char *s = dupstring(prompt4);

	opts[XTRACE] = 0;
	unmetafy(s, &l);
	s = unmetafy(promptexpand(metafy(s, l, META_NOALLOC), 0, NULL, NULL, NULL), &l);
	opts[XTRACE] = t;

	fprintf(xtrerr, "%s", s);
	free(s);
    }
}


mod_export void freestr(void *a)
{
    zsfree(a);
}


mod_export void gettyinfo(struct ttyinfo *ti)
{
    if (SHTTY != -1) {


	if (tcgetattr(SHTTY, &ti->tio) == -1)

	if (ioctl(SHTTY, TCGETS, &ti->tio) == -1)

	    zerr("bad tcgets: %e", errno);


	ioctl(SHTTY, TCGETA, &ti->tio);

	ioctl(SHTTY, TIOCGETP, &ti->sgttyb);
	ioctl(SHTTY, TIOCLGET, &ti->lmodes);
	ioctl(SHTTY, TIOCGETC, &ti->tchars);
	ioctl(SHTTY, TIOCGLTC, &ti->ltchars);


    }
}


mod_export void settyinfo(struct ttyinfo *ti)
{
    if (SHTTY != -1) {





	while (tcsetattr(SHTTY, TCSADRAIN, &ti->tio) == -1 && errno == EINTR)
	    ;

	while (ioctl(SHTTY, TCSETS, &ti->tio) == -1 && errno == EINTR)
	    ;

	


	ioctl(SHTTY, TCSETA, &ti->tio);

	ioctl(SHTTY, TIOCSETN, &ti->sgttyb);
	ioctl(SHTTY, TIOCLSET, &ti->lmodes);
	ioctl(SHTTY, TIOCSETC, &ti->tchars);
	ioctl(SHTTY, TIOCSLTC, &ti->ltchars);


    }
}




mod_export struct ttyinfo shttyinfo;




mod_export int resetneeded;





mod_export int winchanged;


static int adjustlines(int signalled)
{
    int oldlines = zterm_lines;


    if (signalled || zterm_lines <= 0)
	zterm_lines = shttyinfo.winsize.ws_row;
    else shttyinfo.winsize.ws_row = zterm_lines;

    if (zterm_lines < 0) {
	DPUTS(signalled, "BUG: Impossible TIOCGWINSZ rows");
	zterm_lines = tclines > 0 ? tclines : 24;
    }

    if (zterm_lines > 2)
	termflags &= ~TERM_SHORT;
    else termflags |= TERM_SHORT;

    return (zterm_lines != oldlines);
}

static int adjustcolumns(int signalled)
{
    int oldcolumns = zterm_columns;


    if (signalled || zterm_columns <= 0)
	zterm_columns = shttyinfo.winsize.ws_col;
    else shttyinfo.winsize.ws_col = zterm_columns;

    if (zterm_columns < 0) {
	DPUTS(signalled, "BUG: Impossible TIOCGWINSZ cols");
	zterm_columns = tccolumns > 0 ? tccolumns : 80;
    }

    if (zterm_columns > 2)
	termflags &= ~TERM_NARROW;
    else termflags |= TERM_NARROW;

    return (zterm_columns != oldcolumns);
}




void adjustwinsize(int from)
{
    static int getwinsz = 1;

    int ttyrows = shttyinfo.winsize.ws_row;
    int ttycols = shttyinfo.winsize.ws_col;

    int resetzle = 0;

    if (getwinsz || from == 1) {

	if (SHTTY == -1)
	    return;
	if (ioctl(SHTTY, TIOCGWINSZ, (char *)&shttyinfo.winsize) == 0) {
	    resetzle = (ttyrows != shttyinfo.winsize.ws_row || ttycols != shttyinfo.winsize.ws_col);
	    if (from == 0 && resetzle && ttyrows && ttycols)
		from = 1; 
	    ttyrows = shttyinfo.winsize.ws_row;
	    ttycols = shttyinfo.winsize.ws_col;
	} else {
	    
	    shttyinfo.winsize.ws_row = zterm_lines;
	    shttyinfo.winsize.ws_col = zterm_columns;
	    resetzle = (from == 1);
	}

	resetzle = from == 1;

    } 

    switch (from) {
    case 0:
    case 1:
	getwinsz = 0;
	
	if (adjustlines(from) && zgetenv("LINES"))
	    setiparam("LINES", zterm_lines);
	if (adjustcolumns(from) && zgetenv("COLUMNS"))
	    setiparam("COLUMNS", zterm_columns);
	getwinsz = 1;
	break;
    case 2:
	resetzle = adjustlines(0);
	break;
    case 3:
	resetzle = adjustcolumns(0);
	break;
    }


    if (interact && from >= 2 && (shttyinfo.winsize.ws_row != ttyrows || shttyinfo.winsize.ws_col != ttycols)) {

	
	
    }


    if (zleactive && resetzle) {

	winchanged =  resetneeded = 1;

	zleentry(ZLE_CMD_RESET_PROMPT);
	zleentry(ZLE_CMD_REFRESH);
    }
}


static void check_fd_table(int fd)
{
    if (fd <= max_zsh_fd)
	return;

    if (fd >= fdtable_size) {
	int old_size = fdtable_size;
	while (fd >= fdtable_size)
	    fdtable = zrealloc(fdtable, (fdtable_size *= 2)*sizeof(*fdtable));
	memset(fdtable + old_size, 0, (fdtable_size - old_size) * sizeof(*fdtable));
    }
    max_zsh_fd = fd;
}




mod_export int movefd(int fd)
{
    if(fd != -1 && fd < 10) {

	int fe = fcntl(fd, F_DUPFD, 10);

	int fe = movefd(dup(fd));

	
	zclose(fd);
	fd = fe;
    }
    if(fd != -1) {
	check_fd_table(fd);
	fdtable[fd] = FDT_INTERNAL;
    }
    return fd;
}




mod_export int redup(int x, int y)
{
    int ret = y;

    if(x < 0)
	zclose(y);
    else if (x != y) {
	if (dup2(x, y) == -1) {
	    ret = -1;
	} else {
	    check_fd_table(y);
	    fdtable[y] = fdtable[x];
	    if (fdtable[y] == FDT_FLOCK || fdtable[y] == FDT_FLOCK_EXEC)
		fdtable[y] = FDT_INTERNAL;
	}
	
	if (fdtable[x] == FDT_FLOCK)
	    fdtable_flocks--;
	zclose(x);
    }

    return ret;
}



mod_export void addmodulefd(int fd, int fdt)
{
    if (fd >= 0) {
	check_fd_table(fd);
	fdtable[fd] = fdt;
    }
}






mod_export void addlockfd(int fd, int cloexec)
{
    if (cloexec) {
	if (fdtable[fd] != FDT_FLOCK)
	    fdtable_flocks++;
	fdtable[fd] = FDT_FLOCK;
    } else {
	fdtable[fd] = FDT_FLOCK_EXEC;
    }
}




mod_export int zclose(int fd)
{
    if (fd >= 0) {
	
	if (fd <= max_zsh_fd) {
	    if (fdtable[fd] == FDT_FLOCK)
		fdtable_flocks--;
	    fdtable[fd] = FDT_UNUSED;
	    while (max_zsh_fd > 0 && fdtable[max_zsh_fd] == FDT_UNUSED)
		max_zsh_fd--;
	    if (fd == coprocin)
		coprocin = -1;
	    if (fd == coprocout)
		coprocout = -1;
	}
	return close(fd);
    }
    return -1;
}




mod_export int zcloselockfd(int fd)
{
    if (fd > max_zsh_fd)
	return -1;
    if (fdtable[fd] != FDT_FLOCK && fdtable[fd] != FDT_FLOCK_EXEC)
	return -1;
    zclose(fd);
    return 0;
}


extern char *_mktemp(char *);





mod_export char * gettempname(const char *prefix, int use_heap)
{
    char *ret, *suffix = prefix ? ".XXXXXX" : "XXXXXX";

    queue_signals();
    if (!prefix && !(prefix = getsparam("TMPPREFIX")))
	prefix = DEFAULT_TMPPREFIX;
    if (use_heap)
	ret = dyncat(unmeta(prefix), suffix);
    else ret = bicat(unmeta(prefix), suffix);


    
    ret = (char *) _mktemp(ret);

    ret = (char *) mktemp(ret);

    unqueue_signals();

    return ret;
}




mod_export int gettempfile(const char *prefix, int use_heap, char **tempname)
{
    char *fn;
    int fd;

    char *suffix = prefix ? ".XXXXXX" : "XXXXXX";

    queue_signals();
    if (!prefix && !(prefix = getsparam("TMPPREFIX")))
	prefix = DEFAULT_TMPPREFIX;
    if (use_heap)
	fn = dyncat(unmeta(prefix), suffix);
    else fn = bicat(unmeta(prefix), suffix);

    fd = mkstemp(fn);
    if (fd < 0) {
	if (!use_heap)
	    free(fn);
	fn = NULL;
    }

    int failures = 0;

    queue_signals();
    do {
	if (!(fn = gettempname(prefix, use_heap))) {
	    fd = -1;
	    break;
	}
	if ((fd = open(fn, O_RDWR | O_CREAT | O_EXCL, 0600)) >= 0)
	    break;
	if (!use_heap)
	    free(fn);
	fn = NULL;
    } while (errno == EEXIST && ++failures < 16);

    *tempname = fn;

    unqueue_signals();
    return fd;
}




mod_export int has_token(const char *s)
{
    while(*s)
	if(itok(*s++))
	    return 1;
    return 0;
}




mod_export void chuck(char *str)
{
    while ((str[0] = str[1]))
	str++;
}


mod_export int tulower(int c)
{
    c &= 0xff;
    return (isupper(c) ? tolower(c) : c);
}


mod_export int tuupper(int c)
{
    c &= 0xff;
    return (islower(c) ? toupper(c) : c);
}




void ztrncpy(char *s, char *t, int len)
{
    while (len--)
	*s++ = *t++;
    *s = '\0';
}




mod_export void strucpy(char **s, char *t)
{
    char *u = *s;

    while ((*u++ = *t++));
    *s = u - 1;
}


mod_export void struncpy(char **s, char *t, int n)
{
    char *u = *s;

    while (n--)
	*u++ = *t++;
    *s = u;
    *u = '\0';
}




mod_export int arrlen(char **s)
{
    int count;

    for (count = 0; *s; s++, count++);
    return count;
}




mod_export char arrlen_ge(char **s, unsigned lower_bound)
{
    while (lower_bound--)
	if (!*s++)
	    return 0 ;

    return 1 ;
}




mod_export char arrlen_gt(char **s, unsigned lower_bound)
{
    return arrlen_ge(s, 1+lower_bound);
}




mod_export char arrlen_le(char **s, unsigned upper_bound)
{
    return arrlen_lt(s, 1+upper_bound);
}




mod_export char arrlen_lt(char **s, unsigned upper_bound)
{
    return !arrlen_ge(s, upper_bound);
}




mod_export int skipparens(char inpar, char outpar, char **s)
{
    int level;

    if (**s != inpar)
	return -1;

    for (level = 1; *++*s && level;)
	if (**s == inpar)
	   ++level;
	else if (**s == outpar)
	   --level;

   return level;
}


mod_export zlong zstrtol(const char *s, char **t, int base)
{
    return zstrtol_underscore(s, t, base, 0);
}




mod_export zlong zstrtol_underscore(const char *s, char **t, int base, int underscore)
{
    const char *inp, *trunc = NULL;
    zulong calc = 0, newcalc = 0;
    int neg;

    while (inblank(*s))
	s++;

    if ((neg = IS_DASH(*s)))
	s++;
    else if (*s == '+')
	s++;

    if (!base) {
	if (*s != '0')
	    base = 10;
	else if (*++s == 'x' || *s == 'X')
	    base = 16, s++;
	else if (*s == 'b' || *s == 'B')
	    base = 2, s++;
	else base = 8;
    }
    inp = s;
    if (base < 2 || base > 36) {
	zerr("invalid base (must be 2 to 36 inclusive): %d", base);
	return (zlong)0;
    } else if (base <= 10) {
	for (; (*s >= '0' && *s < ('0' + base)) || (underscore && *s == '_'); s++) {
	    if (trunc || *s == '_')
		continue;
	    newcalc = calc * base + *s - '0';
	    if (newcalc < calc)
	    {
		trunc = s;
		continue;
	    }
	    calc = newcalc;
	}
    } else {
	for (; idigit(*s) || (*s >= 'a' && *s < ('a' + base - 10))
	     || (*s >= 'A' && *s < ('A' + base - 10))
	     || (underscore && *s == '_'); s++) {
	    if (trunc || *s == '_')
		continue;
	    newcalc = calc*base + (idigit(*s) ? (*s - '0') : (*s & 0x1f) + 9);
	    if (newcalc < calc)
	    {
		trunc = s;
		continue;
	    }
	    calc = newcalc;
	}
    }

    
    if (!trunc && (zlong)calc < 0 && (!neg || calc & ~((zulong)1 << (8*sizeof(zulong)-1))))
    {
	trunc = s - 1;
	calc /= base;
    }

    if (trunc)
	zwarn("number truncated after %d digits: %s", (int)(trunc - inp), inp);

    if (t)
	*t = (char *)s;
    return neg ? -(zlong)calc : (zlong)calc;
}




mod_export int zstrtoul_underscore(const char *s, zulong *retval)
{
    zulong calc = 0, newcalc = 0, base;

    if (*s == '+')
	s++;

    if (*s != '0')
	base = 10;
    else if (*++s == 'x' || *s == 'X')
	base = 16, s++;
    else if (*s == 'b' || *s == 'B')
	base = 2, s++;
    else base = isset(OCTALZEROES) ? 8 : 10;
    if (base < 2 || base > 36) {
	return 0;
    } else if (base <= 10) {
	for (; (*s >= '0' && *s < ('0' + base)) || *s == '_'; s++) {
	    if (*s == '_')
		continue;
	    newcalc = calc * base + *s - '0';
	    if (newcalc < calc)
	    {
		return 0;
	    }
	    calc = newcalc;
	}
    } else {
	for (; idigit(*s) || (*s >= 'a' && *s < ('a' + base - 10))
	     || (*s >= 'A' && *s < ('A' + base - 10))
	     || *s == '_'; s++) {
	    if (*s == '_')
		continue;
	    newcalc = calc*base + (idigit(*s) ? (*s - '0') : (*s & 0x1f) + 9);
	    if (newcalc < calc)
	    {
		return 0;
	    }
	    calc = newcalc;
	}
    }

    if (*s)
	return 0;
    *retval = calc;
    return 1;
}


mod_export int setblock_fd(int turnonblocking, int fd, long *modep)
{















    struct stat st;

    if (!fstat(fd, &st) && !S_ISREG(st.st_mode)) {
	*modep = fcntl(fd, F_GETFL, 0);
	if (*modep != -1) {
	    if (!turnonblocking) {
		
		if ((*modep & NONBLOCK) || !fcntl(fd, F_SETFL, *modep | NONBLOCK))
		    return 1;
	    } else if ((*modep & NONBLOCK) && !fcntl(fd, F_SETFL, *modep & ~NONBLOCK)) {
		
		return 1;
	    }
	}
    } else  *modep = -1;

    return 0;


}


int setblock_stdin(void)
{
    long mode;
    return setblock_fd(1, 0, &mode);
}




mod_export int read_poll(int fd, int *readchar, int polltty, zlong microseconds)
{
    int ret = -1;
    long mode = -1;
    char c;

    fd_set foofd;
    struct timeval expire_tv;


    int val;



    struct ttyinfo ti;


    if (fd < 0 || (polltty && !isatty(fd)))
	polltty = 0;		


    
    if (polltty && fd >= 0) {
	gettyinfo(&ti);
	if ((polltty = ti.tio.c_cc[VMIN])) {
	    ti.tio.c_cc[VMIN] = 0;
	    
	    ti.tio.c_cc[VTIME] = (int) (microseconds / (zlong)100000);
	    settyinfo(&ti);
	}
    }

    polltty = 0;


    expire_tv.tv_sec = (int) (microseconds / (zlong)1000000);
    expire_tv.tv_usec = microseconds % (zlong)1000000;
    FD_ZERO(&foofd);
    if (fd > -1) {
	FD_SET(fd, &foofd);
	ret = select(fd+1, (SELECT_ARG_2_T) &foofd, NULL, NULL, &expire_tv);
    } else ret = select(0, NULL, NULL, NULL, &expire_tv);

    if (fd < 0) {
	
	sleep(1);
	return 1;
    }

    if (ioctl(fd, FIONREAD, (char *) &val) == 0)
	ret = (val > 0);



    if (fd >= 0 && ret < 0 && !errflag) {
	
	if ((polltty || setblock_fd(0, fd, &mode)) && read(fd, &c, 1) > 0) {
	    *readchar = c;
	    ret = 1;
	}
	if (mode != -1)
	    fcntl(fd, F_SETFL, mode);
    }

    if (polltty) {
	ti.tio.c_cc[VMIN] = 1;
	ti.tio.c_cc[VTIME] = 0;
	settyinfo(&ti);
    }

    return (ret > 0);
}




int zsleep(long us)
{

    struct timespec sleeptime;

    sleeptime.tv_sec = (time_t)us / (time_t)1000000;
    sleeptime.tv_nsec = (us % 1000000L) * 1000L;
    for (;;) {
	struct timespec rem;
	int ret = nanosleep(&sleeptime, &rem);

	if (ret == 0)
	    return 1;
	else if (errno != EINTR)
	    return 0;
	sleeptime = rem;
    }

    int dummy;
    return read_poll(-1, &dummy, 0, us);

}




int zsleep_random(long max_us, time_t end_time)
{
    long r;
    time_t now = time(NULL);

    
    r = (long)(rand() & 0xFFFF);
    
    r = (max_us >> 16) * r;
    
    while (r && now + (time_t)(r / 1000000) > end_time)
	r >>= 1;
    if (r) 
	return zsleep(r);
    return 0;
}


int checkrmall(char *s)
{
    DIR *rmd;
    int count = 0;
    if (!shout)
	return 1;
    if (*s != '/') {
	if (pwd[1])
	    s = zhtricat(pwd, "/", s);
	else s = dyncat("/", s);
    }
    const int max_count = 100;
    if ((rmd = opendir(unmeta(s)))) {
	int ignoredots = !isset(GLOBDOTS);
	
	while (zreaddir(rmd, ignoredots)) {
	    count++;
	    if (count > max_count)
		break;
	}
	closedir(rmd);
    }
    if (count > max_count)
	fprintf(shout, "zsh: sure you want to delete more than %d files in ", max_count);
    else if (count == 1)
	fprintf(shout, "zsh: sure you want to delete the only file in ");
    else if (count > 0)
	fprintf(shout, "zsh: sure you want to delete all %d files in ", count);
    else {
	
	fprintf(shout, "zsh: sure you want to delete all the files in ");
    }
    nicezputs(s, shout);
    if(isset(RMSTARWAIT)) {
	fputs("? (waiting ten seconds)", shout);
	fflush(shout);
	zbeep();
	sleep(10);
	fputc('\n', shout);
    }
    if (errflag)
      return 0;
    fputs(" [yn]? ", shout);
    fflush(shout);
    zbeep();
    return (getquery("ny", 1) == 'y');
}


mod_export ssize_t read_loop(int fd, char *buf, size_t len)
{
    ssize_t got = len;

    while (1) {
	ssize_t ret = read(fd, buf, len);
	if (ret == len)
	    break;
	if (ret <= 0) {
	    if (ret < 0) {
		if (errno == EINTR)
		    continue;
		if (fd != SHTTY)
		    zwarn("read failed: %e", errno);
	    }
	    return ret;
	}
	buf += ret;
	len -= ret;
    }

    return got;
}


mod_export ssize_t write_loop(int fd, const char *buf, size_t len)
{
    ssize_t wrote = len;

    while (1) {
	ssize_t ret = write(fd, buf, len);
	if (ret == len)
	    break;
	if (ret < 0) {
	    if (errno == EINTR)
		continue;
	    if (fd != SHTTY)
		zwarn("write failed: %e", errno);
	    return -1;
	}
	buf += ret;
	len -= ret;
    }

    return wrote;
}

static int read1char(int echo)
{
    char c;
    int q = queue_signal_level();

    dont_queue_signals();
    while (read(SHTTY, &c, 1) != 1) {
	if (errno != EINTR || errflag || retflag || breaks || contflag) {
	    restore_queue_signals(q);
	    return -1;
	}
    }
    restore_queue_signals(q);
    if (echo)
	write_loop(SHTTY, &c, 1);
    return STOUC(c);
}


mod_export int noquery(int purge)
{
    int val = 0;


    char c;

    ioctl(SHTTY, FIONREAD, (char *)&val);
    if (purge) {
	for (; val; val--) {
	    if (read(SHTTY, &c, 1) != 1) {
		
	    }
	}
    }


    return val;
}


int getquery(char *valid_chars, int purge)
{
    int c, d, nl = 0;
    int isem = !strcmp(term, "emacs");
    struct ttyinfo ti;

    attachtty(mypgrp);

    gettyinfo(&ti);

    ti.tio.c_lflag &= ~ECHO;
    if (!isem) {
	ti.tio.c_lflag &= ~ICANON;
	ti.tio.c_cc[VMIN] = 1;
	ti.tio.c_cc[VTIME] = 0;
    }

    ti.sgttyb.sg_flags &= ~ECHO;
    if (!isem)
	ti.sgttyb.sg_flags |= CBREAK;

    settyinfo(&ti);

    if (noquery(purge)) {
	if (!isem)
	    settyinfo(&shttyinfo);
	write_loop(SHTTY, "n\n", 2);
	return 'n';
    }

    while ((c = read1char(0)) >= 0) {
	if (c == 'Y')
	    c = 'y';
	else if (c == 'N')
	    c = 'n';
	if (!valid_chars)
	    break;
	if (c == '\n') {
	    c = *valid_chars;
	    nl = 1;
	    break;
	}
	if (strchr(valid_chars, c)) {
	    nl = 1;
	    break;
	}
	zbeep();
    }
    if (c >= 0) {
	char buf = (char)c;
	write_loop(SHTTY, &buf, 1);
    }
    if (nl)
	write_loop(SHTTY, "\n", 1);

    if (isem) {
	if (c != '\n')
	    while ((d = read1char(1)) >= 0 && d != '\n');
    } else {
	if (c != '\n' && !valid_chars) {

	    if (isset(MULTIBYTE) && c >= 0) {
		
		mbstate_t mbs;
		char cc = (char)c;
		memset(&mbs, 0, sizeof(mbs));
		for (;;) {
		    size_t ret = mbrlen(&cc, 1, &mbs);

		    if (ret != MB_INCOMPLETE)
			break;
		    c = read1char(1);
		    if (c < 0)
			break;
		    cc = (char)c;
		}
	    }

	    write_loop(SHTTY, "\n", 1);
	}
    }
    settyinfo(&shttyinfo);
    return c;
}

static int d;
static char *guess, *best;
static Patprog spckpat, spnamepat;


static void spscan(HashNode hn, UNUSED(int scanflags))
{
    int nd;

    if (spckpat && pattry(spckpat, hn->nam))
	return;

    nd = spdist(hn->nam, guess, (int) strlen(guess) / 4 + 1);
    if (nd <= d) {
	best = hn->nam;
	d = nd;
    }
}





mod_export void spckword(char **s, int hist, int cmd, int ask)
{
    char *t, *correct_ignore;
    char ic = '\0';
    int preflen = 0;
    int autocd = cmd && isset(AUTOCD) && strcmp(*s, ".") && strcmp(*s, "..");

    if ((histdone & HISTFLAG_NOEXEC) || **s == '-' || **s == '%')
	return;
    if (!strcmp(*s, "in"))
	return;
    if (!(*s)[0] || !(*s)[1])
	return;
    if (cmd) {
	if (shfunctab->getnode(shfunctab, *s) || builtintab->getnode(builtintab, *s) || cmdnamtab->getnode(cmdnamtab, *s) || aliastab->getnode(aliastab, *s)  || reswdtab->getnode(reswdtab, *s))



	    return;
	else if (isset(HASHLISTALL)) {
	    cmdnamtab->filltable(cmdnamtab);
	    if (cmdnamtab->getnode(cmdnamtab, *s))
		return;
	}
    }
    t = *s;
    if (*t == Tilde || *t == Equals || *t == String)
	t++;
    for (; *t; t++)
	if (itok(*t))
	    return;
    best = NULL;
    for (t = *s; *t; t++)
	if (*t == '/')
	    break;
    if (**s == Tilde && !*t)
	return;

    if ((correct_ignore = getsparam("CORRECT_IGNORE")) != NULL) {
	tokenize(correct_ignore = dupstring(correct_ignore));
	remnulargs(correct_ignore);
	spckpat = patcompile(correct_ignore, 0, NULL);
    } else spckpat = NULL;

    if ((correct_ignore = getsparam("CORRECT_IGNORE_FILE")) != NULL) {
	tokenize(correct_ignore = dupstring(correct_ignore));
	remnulargs(correct_ignore);
	spnamepat = patcompile(correct_ignore, 0, NULL);
    } else spnamepat = NULL;

    if (**s == String && !*t) {
	guess = *s + 1;
	if (itype_end(guess, IIDENT, 1) == guess)
	    return;
	ic = String;
	d = 100;
	scanhashtable(paramtab, 1, 0, 0, spscan, 0);
    } else if (**s == Equals) {
	if (*t)
	    return;
	if (hashcmd(guess = *s + 1, pathchecked))
	    return;
	d = 100;
	ic = Equals;
	scanhashtable(aliastab, 1, 0, 0, spscan, 0);
	scanhashtable(cmdnamtab, 1, 0, 0, spscan, 0);
    } else {
	guess = *s;
	if (*guess == Tilde || *guess == String) {
	    int ne;
	    ic = *guess;
	    if (!*++t)
		return;
	    guess = dupstring(guess);
	    ne = noerrs;
	    noerrs = 2;
	    singsub(&guess);
	    noerrs = ne;
	    if (!guess)
		return;
	    preflen = strlen(guess) - strlen(t);
	}
	if (access(unmeta(guess), F_OK) == 0)
	    return;
	best = spname(guess);
	if (!*t && cmd) {
	    if (hashcmd(guess, pathchecked))
		return;
	    d = 100;
	    scanhashtable(reswdtab, 1, 0, 0, spscan, 0);
	    scanhashtable(aliastab, 1, 0, 0, spscan, 0);
	    scanhashtable(shfunctab, 1, 0, 0, spscan, 0);
	    scanhashtable(builtintab, 1, 0, 0, spscan, 0);
	    scanhashtable(cmdnamtab, 1, 0, 0, spscan, 0);
	    if (autocd) {
		char **pp;
		for (pp = cdpath; *pp; pp++) {
		    char bestcd[PATH_MAX + 1];
		    int thisdist;
		    
		    if ((thisdist = mindist(*pp, *s, bestcd, 1)) < d) {
			best = dupstring(bestcd);
			d = thisdist;
		    }
		}
	    }
	}
    }
    if (errflag)
	return;
    if (best && (int)strlen(best) > 1 && strcmp(best, guess)) {
	int x;
	if (ic) {
	    char *u;
	    if (preflen) {
		
		if (strncmp(guess, best, preflen))
		    return;
		
		u = (char *) zhalloc(t - *s + strlen(best + preflen) + 1);
		strncpy(u, *s, t - *s);
		strcpy(u + (t - *s), best + preflen);
	    } else {
		u = (char *) zhalloc(strlen(best) + 2);
		*u = '\0';
		strcpy(u + 1, best);
	    }
	    best = u;
	    guess = *s;
	    *guess = *best = ztokens[ic - Pound];
	}
	if (ask) {
	    if (noquery(0)) {
		x = 'n';
	    } else if (shout) {
		char *pptbuf;
		pptbuf = promptexpand(sprompt, 0, best, guess, NULL);
		zputs(pptbuf, shout);
		free(pptbuf);
		fflush(shout);
		zbeep();
		x = getquery("nyae", 0);
		if (cmd && x == 'n')
		    pathchecked = path;
	    } else x = 'n';
	} else x = 'y';
	if (x == 'y') {
	    *s = dupstring(best);
	    if (hist)
		hwrep(best);
	} else if (x == 'a') {
	    histdone |= HISTFLAG_NOEXEC;
	} else if (x == 'e') {
	    histdone |= HISTFLAG_NOEXEC | HISTFLAG_RECALL;
	}
	if (ic)
	    **s = ic;
    }
}



static int ztrftimebuf(int *bufsizeptr, int decr)
{
    if (*bufsizeptr <= decr)
	return 1;
    *bufsizeptr -= decr;
    return 0;
}




mod_export int ztrftime(char *buf, int bufsize, char *fmt, struct tm *tm, long usec)
{
    int hr12;

    int decr;
    char *fmtstart;

    static char *astr[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat";
    static char *estr[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec";


    char *origbuf = buf;


    while (*fmt) {
	if (*fmt == Meta) {
	    int chr = fmt[1] ^ 32;
	    if (ztrftimebuf(&bufsize, 1))
		return -1;
	    *buf++ = chr;
	    fmt += 2;
	} else if (*fmt == '%') {
	    int strip;
	    int digs = 3;


	    fmtstart =  fmt++;


	    if (*fmt == '-') {
		strip = 1;
		fmt++;
	    } else strip = 0;
	    if (idigit(*fmt)) {
		
		char *dstart = fmt;
		char *dend = fmt+1;
		while (idigit(*dend))
		    dend++;
		if (*dend == '.') {
		    fmt = dend;
		    digs = atoi(dstart);
		}
	    }
	    
	    if (ztrftimebuf(&bufsize, 2))
		return -1;

	    
morefmt:
	    if (!((fmt - fmtstart == 1) || (fmt - fmtstart == 2 && strip) || *fmt == '.')) {
		while (*fmt && strchr("OE^#_-0123456789", *fmt))
		    fmt++;
		if (*fmt) {
		    fmt++;
		    goto strftimehandling;
		}
	    }

	    switch (*fmt++) {
	    case '.':
		if (ztrftimebuf(&bufsize, digs))
		    return -1;
		if (digs > 6)
		    digs = 6;
		if (digs < 6) {
		    int trunc;
		    for (trunc = 5 - digs; trunc; trunc--)
			usec /= 10;
		    usec  = (usec + 5) / 10;
		}
		sprintf(buf, "%0*ld", digs, usec);
		buf += digs;
		break;
	    case '\0':
		
		*buf++ = '%';
		fmt--;
		break;
	    case 'f':
		strip = 1;
		
	    case 'e':
		if (tm->tm_mday > 9)
		    *buf++ = '0' + tm->tm_mday / 10;
		else if (!strip)
		    *buf++ = ' ';
		*buf++ = '0' + tm->tm_mday % 10;
		break;
	    case 'K':
		strip = 1;
		
	    case 'H':
	    case 'k':
		if (tm->tm_hour > 9)
		    *buf++ = '0' + tm->tm_hour / 10;
		else if (!strip) {
		    if (fmt[-1] == 'H')
			*buf++ = '0';
		    else *buf++ = ' ';
		}
		*buf++ = '0' + tm->tm_hour % 10;
		break;
	    case 'L':
		strip = 1;
		
	    case 'l':
		hr12 = tm->tm_hour % 12;
		if (hr12 == 0)
		    hr12 = 12;
	        if (hr12 > 9)
		    *buf++ = '1';
		else if (!strip)
		    *buf++ = ' ';

		*buf++ = '0' + (hr12 % 10);
		break;
	    case 'd':
		if (tm->tm_mday > 9 || !strip)
		    *buf++ = '0' + tm->tm_mday / 10;
		*buf++ = '0' + tm->tm_mday % 10;
		break;
	    case 'm':
		if (tm->tm_mon > 8 || !strip)
		    *buf++ = '0' + (tm->tm_mon + 1) / 10;
		*buf++ = '0' + (tm->tm_mon + 1) % 10;
		break;
	    case 'M':
		if (tm->tm_min > 9 || !strip)
		    *buf++ = '0' + tm->tm_min / 10;
		*buf++ = '0' + tm->tm_min % 10;
		break;
	    case 'S':
		if (tm->tm_sec > 9 || !strip)
		    *buf++ = '0' + tm->tm_sec / 10;
		*buf++ = '0' + tm->tm_sec % 10;
		break;
	    case 'y':
		if (tm->tm_year > 9 || !strip)
		    *buf++ = '0' + (tm->tm_year / 10) % 10;
		*buf++ = '0' + tm->tm_year % 10;
		break;

	    case 'Y':
	    {
		int year, digits, testyear;
		year = tm->tm_year + 1900;
		digits = 1;
		testyear = year;
		while (testyear > 9) {
		    digits++;
		    testyear /= 10;
		}
		if (ztrftimebuf(&bufsize, digits))
		    return -1;
		sprintf(buf, "%d", year);
		buf += digits;
		break;
	    }
	    case 'a':
		if (ztrftimebuf(&bufsize, strlen(astr[tm->tm_wday]) - 2))
		    return -1;
		strucpy(&buf, astr[tm->tm_wday]);
		break;
	    case 'b':
		if (ztrftimebuf(&bufsize, strlen(estr[tm->tm_mon]) - 2))
		    return -1;
		strucpy(&buf, estr[tm->tm_mon]);
		break;
	    case 'p':
		*buf++ = (tm->tm_hour > 11) ? 'p' : 'a';
		*buf++ = 'm';
		break;
	    default:
		*buf++ = '%';
		if (fmt[-1] != '%')
		    *buf++ = fmt[-1];

	    case 'E':
	    case 'O':
	    case '^':
	    case '#':
	    case '_':
	    case '-':
	    case '0': case '1': case '2': case '3': case '4':
	    case '5': case '6': case '7': case '8': case '9':
		goto morefmt;
strftimehandling:
	    default:
		
		{
		    char origchar = fmt[-1];
		    int size = fmt - fmtstart;
		    char *tmp, *last;
		    tmp = zhalloc(size + 1);
		    strncpy(tmp, fmtstart, size);
		    last = fmt-1;
		    if (*last == Meta) {
			
			*last = *++fmt ^ 32;
		    }
		    tmp[size] = '\0';
		    *buf = '\1';
		    if (!strftime(buf, bufsize + 2, tmp, tm))
		    {
			
			if (*buf || (origchar != 'p' && origchar != 'P')) {
			    if (*buf) {
				buf[0] = '\0';
				return -1;
			    }
			    return 0;
			}
		    }
		    decr = strlen(buf);
		    buf += decr;
		    bufsize -= decr - 2;
		}

		break;
	    }
	} else {
	    if (ztrftimebuf(&bufsize, 1))
		return -1;
	    *buf++ = *fmt++;
	}
    }
    *buf = '\0';
    return buf - origbuf;
}


mod_export char * zjoin(char **arr, int delim, int heap)
{
    int len = 0;
    char **s, *ret, *ptr;

    for (s = arr; *s; s++)
	len += strlen(*s) + 1 + (imeta(delim) ? 1 : 0);
    if (!len)
	return heap? "" : ztrdup("");
    ptr = ret = (char *) (heap ? zhalloc(len) : zalloc(len));
    for (s = arr; *s; s++) {
	strucpy(&ptr, *s);
	    if (imeta(delim)) {
		*ptr++ = Meta;
		*ptr++ = delim ^ 32;
	    }
	    else *ptr++ = delim;
    }
    ptr[-1 - (imeta(delim) ? 1 : 0)] = '\0';
    return ret;
}




mod_export char ** colonsplit(char *s, int uniq)
{
    int ct;
    char *t, **ret, **ptr, **p;

    for (t = s, ct = 0; *t; t++) 
	if (*t == ':')
	    ct++;
    ptr = ret = (char **) zalloc(sizeof(char *) * (ct + 2));

    t = s;
    do {
	s = t;
        
	for (; *t && *t != ':'; t++);
	if (uniq)
	    for (p = ret; p < ptr; p++)
		if ((int)strlen(*p) == t - s && ! strncmp(*p, s, t - s))
		    goto cont;
	*ptr = (char *) zalloc((t - s) + 1);
	ztrncpy(*ptr++, s, t - s);
      cont: ;
    }
    while (*t++);
    *ptr = NULL;
    return ret;
}


static int skipwsep(char **s)
{
    char *t = *s;
    int i = 0;

    
    while (*t && iwsep(*t == Meta ? t[1] ^ 32 : *t)) {
	if (*t == Meta)
	    t++;
	t++;
	i++;
    }
    *s = t;
    return i;
}




mod_export char ** spacesplit(char *s, int allownull, int heap, int quote)
{
    char *t, **ret, **ptr;
    int l = sizeof(*ret) * (wordcount(s, NULL, -!allownull) + 1);
    char *(*dup)(const char *) = (heap ? dupstring : ztrdup);

    
    ptr = ret = (char **) (heap ? hcalloc(l) : zshcalloc(l));

    if (quote) {
	
	s = dupstring(s);
    }

    t = s;
    skipwsep(&s);
    MB_METACHARINIT();
    if (*s && itype_end(s, ISEP, 1) != s)
	*ptr++ = dup(allownull ? "" : nulstring);
    else if (!allownull && t != s)
	*ptr++ = dup("");
    while (*s) {
	char *iend = itype_end(s, ISEP, 1);
	if (iend != s) {
	    s = iend;
	    skipwsep(&s);
	}
	else if (quote && *s == '\\') {
	    s++;
	    skipwsep(&s);
	}
	t = s;
	(void)findsep(&s, NULL, quote);
	if (s > t || allownull) {
	    *ptr = (char *) (heap ? zhalloc((s - t) + 1) :
		                     zalloc((s - t) + 1));
	    ztrncpy(*ptr++, t, s - t);
	} else *ptr++ = dup(nulstring);
	t = s;
	skipwsep(&s);
    }
    if (!allownull && t != s)
	*ptr++ = dup("");
    *ptr = NULL;
    return ret;
}




static int findsep(char **s, char *sep, int quote)
{
    
    int i, ilen;
    char *t, *tt;
    convchar_t c;

    MB_METACHARINIT();
    if (!sep) {
	for (t = *s; *t; t += ilen) {
	    if (quote && *t == '\\') {
		if (t[1] == '\\') {
		    chuck(t);
		    ilen = 1;
		    continue;
		} else {
		    ilen = MB_METACHARLENCONV(t+1, &c);
		    if (WC_ZISTYPE(c, ISEP)) {
			chuck(t);
			
		    } else {
			
			if (isep(*t))
			    break;
			ilen = 1;
		    }
		}
	    } else {
		ilen = MB_METACHARLENCONV(t, &c);
		if (WC_ZISTYPE(c, ISEP))
		    break;
	    }
	}
	i = (t > *s);
	*s = t;
	return i;
    }
    if (!sep[0]) {
	
	if (**s) {
	    *s += MB_METACHARLEN(*s);
	    return 1;
	}
	return -1;
    }
    for (i = 0; **s; i++) {
	
	for (t = sep, tt = *s; *t && *tt && *t == *tt; t++, tt++);
	if (!*t)
	    return (i > 0);
	*s += MB_METACHARLEN(*s);
    }
    return -1;
}


char * findword(char **s, char *sep)
{
    char *r, *t;
    int sl;

    if (!**s)
	return NULL;

    if (sep) {
	sl = strlen(sep);
	r = *s;
	while (! findsep(s, sep, 0)) {
	    r = *s += sl;
	}
	return r;
    }
    MB_METACHARINIT();
    for (t = *s; *t; t += sl) {
	convchar_t c;
	sl = MB_METACHARLENCONV(t, &c);
	if (!WC_ZISTYPE(c, ISEP))
	    break;
    }
    *s = t;
    (void)findsep(s, sep, 0);
    return t;
}


int wordcount(char *s, char *sep, int mul)
{
    int r, sl, c;

    if (sep) {
	r = 1;
	sl = strlen(sep);
	for (; (c = findsep(&s, sep, 0)) >= 0; s += sl)
	    if ((c || mul) && (sl || *(s + sl)))
		r++;
    } else {
	char *t = s;

	r = 0;
	if (mul <= 0)
	    skipwsep(&s);
	if ((*s && itype_end(s, ISEP, 1) != s) || (mul < 0 && t != s))
	    r++;
	for (; *s; r++) {
	    char *ie = itype_end(s, ISEP, 1);
	    if (ie != s) {
		s = ie;
		if (mul <= 0)
		    skipwsep(&s);
	    }
	    (void)findsep(&s, NULL, 0);
	    t = s;
	    if (mul <= 0)
		skipwsep(&s);
	}
	if (mul < 0 && t != s)
	    r++;
    }
    return r;
}


mod_export char * sepjoin(char **s, char *sep, int heap)
{
    char *r, *p, **t;
    int l, sl;
    char sepbuf[2];

    if (!*s)
	return heap ? "" : ztrdup("");
    if (!sep) {
	
	if (ifs && *ifs != ' ') {
	    MB_METACHARINIT();
	    sep = dupstrpfx(ifs, MB_METACHARLEN(ifs));
	} else {
	    p = sep = sepbuf;
	    *p++ = ' ';
	    *p = '\0';
	}
    }
    sl = strlen(sep);
    for (t = s, l = 1 - sl; *t; l += strlen(*t) + sl, t++);
    r = p = (char *) (heap ? zhalloc(l) : zalloc(l));
    t = s;
    while (*t) {
	strucpy(&p, *t);
	if (*++t)
	    strucpy(&p, sep);
    }
    *p = '\0';
    return r;
}


char ** sepsplit(char *s, char *sep, int allownull, int heap)
{
    int n, sl;
    char *t, *tt, **r, **p;

    
    if (s[0] == Nularg && !s[1])
	s++;

    if (!sep)
	return spacesplit(s, allownull, heap, 0);

    sl = strlen(sep);
    n = wordcount(s, sep, 1);
    r = p = (char **) (heap ? zhalloc((n + 1) * sizeof(char *)) :
	                       zalloc((n + 1) * sizeof(char *)));

    for (t = s; n--;) {
	tt = t;
	(void)findsep(&t, sep, 0);
	*p = (char *) (heap ? zhalloc(t - tt + 1) :
	                       zalloc(t - tt + 1));
	strncpy(*p, tt, t - tt);
	(*p)[t - tt] = '\0';
	p++;
	t += sl;
    }
    *p = NULL;

    return r;
}




mod_export Shfunc getshfunc(char *nam)
{
    return (Shfunc) shfunctab->getnode(shfunctab, nam);
}




char ** subst_string_by_func(Shfunc func, char *arg1, char *orig)
{
    int osc = sfcontext, osm = stopmsg, old_incompfunc = incompfunc;
    LinkList l = newlinklist();
    char **ret;

    addlinknode(l, func->node.nam);
    if (arg1)
	addlinknode(l, arg1);
    addlinknode(l, orig);
    sfcontext = SFC_SUBST;
    incompfunc = 0;

    if (doshfunc(func, l, 1))
	ret = NULL;
    else ret = getaparam("reply");

    sfcontext = osc;
    stopmsg = osm;
    incompfunc = old_incompfunc;
    return ret;
}



char ** subst_string_by_hook(char *name, char *arg1, char *orig)
{
    Shfunc func;
    char **ret = NULL;

    if ((func = getshfunc(name))) {
	ret = subst_string_by_func(func, arg1, orig);
    }

    if (!ret) {
	char **arrptr;
	int namlen = strlen(name);
	VARARR(char, arrnam, namlen + HOOK_SUFFIX_LEN);
	memcpy(arrnam, name, namlen);
	memcpy(arrnam + namlen, HOOK_SUFFIX, HOOK_SUFFIX_LEN);

	if ((arrptr = getaparam(arrnam))) {
	    
	    arrptr = arrdup(arrptr);
	    for (; *arrptr; arrptr++) {
		if ((func = getshfunc(*arrptr))) {
		    ret = subst_string_by_func(func, arg1, orig);
		    if (ret)
			break;
		}
	    }
	}
    }

    return ret;
}


mod_export char ** mkarray(char *s)
{
    char **t = (char **) zalloc((s) ? (2 * sizeof s) : (sizeof s));

    if ((*t = s))
	t[1] = NULL;
    return t;
}


mod_export char ** hmkarray(char *s)
{
    char **t = (char **) zhalloc((s) ? (2 * sizeof s) : (sizeof s));

    if ((*t = s))
	t[1] = NULL;
    return t;
}


mod_export void zbeep(void)
{
    char *vb;
    queue_signals();
    if ((vb = getsparam_u("ZBEEP"))) {
	int len;
	vb = getkeystring(vb, &len, GETKEYS_BINDKEY, NULL);
	write_loop(SHTTY, vb, len);
    } else if (isset(BEEP))
	write_loop(SHTTY, "\07", 1);
    unqueue_signals();
}


mod_export void freearray(char **s)
{
    char **t = s;

    DPUTS(!s, "freearray() with zero argument");

    while (*s)
	zsfree(*s++);
    free(t);
}


int equalsplit(char *s, char **t)
{
    for (; *s && *s != '='; s++);
    if (*s == '=') {
	*s++ = '\0';
	*t = s;
	return 1;
    }
    return 0;
}





mod_export short int typtab[256];
static int typtab_flags = 0;




void inittyptab(void)
{
    int t0;
    char *s;

    if (!(typtab_flags & ZTF_INIT)) {
	typtab_flags = ZTF_INIT;
	if (interact && isset(SHINSTDIN))
	    typtab_flags |= ZTF_INTERACT;
    }

    queue_signals();

    memset(typtab, 0, sizeof(typtab));
    for (t0 = 0; t0 != 32; t0++)
	typtab[t0] = typtab[t0 + 128] = ICNTRL;
    typtab[127] = ICNTRL;
    for (t0 = '0'; t0 <= '9'; t0++)
	typtab[t0] = IDIGIT | IALNUM | IWORD | IIDENT | IUSER;
    for (t0 = 'a'; t0 <= 'z'; t0++)
	typtab[t0] = typtab[t0 - 'a' + 'A'] = IALPHA | IALNUM | IIDENT | IUSER | IWORD;

    
    for (t0 = 0240; t0 != 0400; t0++)
	typtab[t0] = IALPHA | IALNUM | IIDENT | IUSER | IWORD;

     
    typtab['_'] = IIDENT | IUSER;
    typtab['-'] = typtab['.'] = typtab[STOUC(Dash)] = IUSER;
    typtab[' '] |= IBLANK | INBLANK;
    typtab['\t'] |= IBLANK | INBLANK;
    typtab['\n'] |= INBLANK;
    typtab['\0'] |= IMETA;
    typtab[STOUC(Meta)  ] |= IMETA;
    typtab[STOUC(Marker)] |= IMETA;
    for (t0 = (int)STOUC(Pound); t0 <= (int)STOUC(LAST_NORMAL_TOK); t0++)
	typtab[t0] |= ITOK | IMETA;
    for (t0 = (int)STOUC(Snull); t0 <= (int)STOUC(Nularg); t0++)
	typtab[t0] |= ITOK | IMETA | INULL;
    for (s = ifs ? ifs : EMULATION(EMULATE_KSH|EMULATE_SH) ? DEFAULT_IFS_SH : DEFAULT_IFS; *s; s++) {
	int c = STOUC(*s == Meta ? *++s ^ 32 : *s);

	if (!isascii(c)) {
	    
	    continue;
	}

	if (inblank(c)) {
	    if (s[1] == c)
		s++;
	    else typtab[c] |= IWSEP;
	}
	typtab[c] |= ISEP;
    }
    for (s = wordchars ? wordchars : DEFAULT_WORDCHARS; *s; s++) {
	int c = STOUC(*s == Meta ? *++s ^ 32 : *s);

	if (!isascii(c)) {
	    
	    continue;
	}

	typtab[c] |= IWORD;
    }

    set_widearray(wordchars, &wordchars_wide);
    set_widearray(ifs ? ifs : EMULATION(EMULATE_KSH|EMULATE_SH) ? DEFAULT_IFS_SH : DEFAULT_IFS, &ifs_wide);

    for (s = SPECCHARS; *s; s++)
	typtab[STOUC(*s)] |= ISPECIAL;
    if (typtab_flags & ZTF_SP_COMMA)
	typtab[STOUC(',')] |= ISPECIAL;
    if (isset(BANGHIST) && bangchar && (typtab_flags & ZTF_INTERACT)) {
	typtab_flags |= ZTF_BANGCHAR;
	typtab[bangchar] |= ISPECIAL;
    } else typtab_flags &= ~ZTF_BANGCHAR;
    for (s = PATCHARS; *s; s++)
	typtab[STOUC(*s)] |= IPATTERN;

    unqueue_signals();
}


mod_export void makecommaspecial(int yesno)
{
    if (yesno != 0) {
	typtab_flags |= ZTF_SP_COMMA;
	typtab[STOUC(',')] |= ISPECIAL;
    } else {
	typtab_flags &= ~ZTF_SP_COMMA;
	typtab[STOUC(',')] &= ~ISPECIAL;
    }
}


mod_export void makebangspecial(int yesno)
{
     
    if (yesno == 0) {
	typtab[bangchar] &= ~ISPECIAL;
    } else if (typtab_flags & ZTF_BANGCHAR) {
	typtab[bangchar] |= ISPECIAL;
    }
}






mod_export int wcsiblank(wint_t wc)
{
    if (iswspace(wc) && wc != L'\n')
	return 1;
    return 0;
}




mod_export int wcsitype(wchar_t c, int itype)
{
    int len;
    mbstate_t mbs;
    VARARR(char, outstr, MB_CUR_MAX);

    if (!isset(MULTIBYTE))
	return zistype(c, itype);

    
    memset(&mbs, 0, sizeof(mbs));
    len = wcrtomb(outstr, c, &mbs);

    if (len == 0) {
	
	return zistype(0, itype);
    } else if (len == 1 && isascii(outstr[0])) {
	return zistype(outstr[0], itype);
    } else {
	switch (itype) {
	case IIDENT:
	    if (!isset(POSIXIDENTIFIERS))
		return 0;
	    return iswalnum(c);

	case IWORD:
	    if (iswalnum(c))
		return 1;
	    
	    if (IS_COMBINING(c))
		return 1;
	    return !!wmemchr(wordchars_wide.chars, c, wordchars_wide.len);

	case ISEP:
	    return !!wmemchr(ifs_wide.chars, c, ifs_wide.len);

	default:
	    return iswalnum(c);
	}
    }
}








mod_export char * itype_end(const char *ptr, int itype, int once)
{

    if (isset(MULTIBYTE) && (itype != IIDENT || !isset(POSIXIDENTIFIERS))) {
	mb_charinit();
	while (*ptr) {
	    int len;
	    if (itok(*ptr)) {
		
		len = 1;
		if (!zistype(*ptr,itype))
		    break;
	    } else {
		wint_t wc;
		len = mb_metacharlenconv(ptr, &wc);

		if (!len)
		    break;

		if (wc == WEOF) {
		    
		    int chr = STOUC(*ptr == Meta ? ptr[1] ^ 32 : *ptr);
		    
		    if (chr > 127 || !zistype(chr,itype))
			break;
		} else if (len == 1 && isascii(*ptr)) {
		    
		    if (!zistype(*ptr,itype))
			break;
		} else {
		    
		    switch (itype) {
		    case IWORD:
			if (!iswalnum(wc) && !wmemchr(wordchars_wide.chars, wc, wordchars_wide.len))

			    return (char *)ptr;
			break;

		    case ISEP:
			if (!wmemchr(ifs_wide.chars, wc, ifs_wide.len))
			    return (char *)ptr;
			break;

		    default:
			if (!iswalnum(wc))
			    return (char *)ptr;
		    }
		}
	    }
	    ptr += len;

	    if (once)
		break;
	}
    } else  for (;;) {

	    int chr = STOUC(*ptr == Meta ? ptr[1] ^ 32 : *ptr);
	    if (!zistype(chr,itype))
		break;
	    ptr += (*ptr == Meta) ? 2 : 1;

	    if (once)
		break;
	}

    
    return (char *)ptr;
}


mod_export char ** arrdup(char **s)
{
    char **x, **y;

    y = x = (char **) zhalloc(sizeof(char *) * (arrlen(s) + 1));

    while ((*x++ = dupstring(*s++)));

    return y;
}




mod_export char ** arrdup_max(char **s, unsigned max)
{
    char **x, **y, **send;
    int len = 0;

    if (max)
	len = arrlen(s);

    
    if (max > len)
        max = len;

    y = x = (char **) zhalloc(sizeof(char *) * (max + 1));

    send = s + max;
    while (s < send)
	*x++ = dupstring(*s++);
    *x = NULL;

    return y;
}


mod_export char ** zarrdup(char **s)
{
    char **x, **y;

    y = x = (char **) zalloc(sizeof(char *) * (arrlen(s) + 1));

    while ((*x++ = ztrdup(*s++)));

    return y;
}




mod_export wchar_t ** wcs_zarrdup(wchar_t **s)
{
    wchar_t **x, **y;

    y = x = (wchar_t **) zalloc(sizeof(wchar_t *) * (arrlen((char **)s) + 1));

    while ((*x++ = wcs_ztrdup(*s++)));

    return y;
}




static char * spname(char *oldname)
{
    char *p, spnameguess[PATH_MAX + 1], spnamebest[PATH_MAX + 1];
    static char newname[PATH_MAX + 1];
    char *new = newname, *old = oldname;
    int bestdist = 0, thisdist, thresh, maxthresh = 0;

    
    for (;;) {
	while (*old == '/') {
	    if ((new - newname) >= (sizeof(newname)-1))
		return NULL;
	    *new++ = *old++;
	}
	*new = '\0';
	if (*old == '\0')
	    return newname;
	p = spnameguess;
	for (; *old != '/' && *old != '\0'; old++)
	    if (p < spnameguess + PATH_MAX)
		*p++ = *old;
	*p = '\0';
	
	thresh = (int)(p - spnameguess) / 4 + 1;
	if (thresh < 3)
	    thresh = 3;
	else if (thresh > 100)
	    thresh = 100;
	thisdist = mindist(newname, spnameguess, spnamebest, *old == '/');
	if (thisdist >= thresh) {
	    
	    if (bestdist < maxthresh) {
		strcpy(new, spnameguess);
		strcat(new, old);
		return newname;
	    } else return NULL;
	} else {
	    maxthresh = bestdist + thresh;
	    bestdist += thisdist;
	}
	for (p = spnamebest; (*new = *p++);)
	    new++;
    }
}


static int mindist(char *dir, char *mindistguess, char *mindistbest, int wantdir)
{
    int mindistd, nd;
    DIR *dd;
    char *fn;
    char *buf;
    struct stat st;
    size_t dirlen;

    if (dir[0] == '\0')
	dir = ".";
    mindistd = 100;

    if (!(buf = zalloc((dirlen = strlen(dir)) + strlen(mindistguess) + 2)))
	return 0;
    sprintf(buf, "%s/%s", dir, mindistguess);

    if (stat(unmeta(buf), &st) == 0 && (!wantdir || S_ISDIR(st.st_mode))) {
	strcpy(mindistbest, mindistguess);
	free(buf);
	return 0;
    }

    if ((dd = opendir(unmeta(dir)))) {
	while ((fn = zreaddir(dd, 0))) {
	    if (spnamepat && pattry(spnamepat, fn))
		continue;
	    nd = spdist(fn, mindistguess, (int)strlen(mindistguess) / 4 + 1);
	    if (nd <= mindistd) {
		if (wantdir) {
		    if (!(buf = zrealloc(buf, dirlen + strlen(fn) + 2)))
			continue;
		    sprintf(buf, "%s/%s", dir, fn);
		    if (stat(unmeta(buf), &st) != 0 || !S_ISDIR(st.st_mode))
			continue;
		}
		strcpy(mindistbest, fn);
		mindistd = nd;
		if (mindistd == 0)
		    break;
	    }
	}
	closedir(dd);
    }
    free(buf);
    return mindistd;
}


static int spdist(char *s, char *t, int thresh)
{
    
    char *p, *q;
    const char qwertykeymap[] = "\n\n\n\n\n\n\n\n\n\n\n\n\n\n \t1234567890-=\t \tqwertyuiop[]\t \tasdfghjkl;'\n\t \tzxcvbnm,./\t\t\t \n\n\n\n\n\n\n\n\n\n\n\n\n\n \t!@#$%^&*()_+\t \tQWERTYUIOP{}\t \tASDFGHJKL:\"\n\t \tZXCVBNM<>?\n\n\t \n\n\n\n\n\n\n\n\n\n\n\n\n\n"          const char dvorakkeymap[] = "\n\n\n\n\n\n\n\n\n\n\n\n\n\n \t1234567890[]\t \t',.pyfgcrl/=\t \taoeuidhtns-\n\t \t;qjkxbmwvz\t\t\t \n\n\n\n\n\n\n\n\n\n\n\n\n\n \t!@#$%^&*(){}\t \t\"<>PYFGCRL?+\t \tAOEUIDHTNS_\n\t \t:QJKXBMWVZ\n\n\t \n\n\n\n\n\n\n\n\n\n\n\n\n\n"          const char *keymap;





















    if ( isset( DVORAK ) )
      keymap = dvorakkeymap;
    else keymap = qwertykeymap;

    if (!strcmp(s, t))
	return 0;
    
    for (p = s, q = t; *p && tulower(*p) == tulower(*q); p++, q++);
    if (!*p && !*q)
	return 1;
    if (!thresh)
	return 200;
    for (p = s, q = t; *p && *q; p++, q++)
	if (*p == *q)
	    continue;		
	else if (p[1] == q[0] && q[1] == p[0])	
	    return spdist(p + 2, q + 2, thresh - 1) + 1;
	else if (p[1] == q[0])	
	    return spdist(p + 1, q + 0, thresh - 1) + 2;
	else if (p[0] == q[1])	
	    return spdist(p + 0, q + 1, thresh - 1) + 2;
	else if (*p != *q)
	    break;
    if ((!*p && strlen(q) == 1) || (!*q && strlen(p) == 1))
	return 2;
    for (p = s, q = t; *p && *q; p++, q++)
	if (p[0] != q[0] && p[1] == q[1]) {
	    int t0;
	    char *z;

	    

	    if (!(z = strchr(keymap, p[0])) || *z == '\n' || *z == '\t')
		return spdist(p + 1, q + 1, thresh - 1) + 1;
	    t0 = z - keymap;
	    if (*q == keymap[t0 - 15] || *q == keymap[t0 - 14] || *q == keymap[t0 - 13] || *q == keymap[t0 - 1] || *q == keymap[t0 + 1] || *q == keymap[t0 + 13] || *q == keymap[t0 + 14] || *q == keymap[t0 + 15])



		return spdist(p + 1, q + 1, thresh - 1) + 2;
	    return 200;
	} else if (*p != *q)
	    break;
    return 200;
}




void setcbreak(void)
{
    struct ttyinfo ti;

    ti = shttyinfo;

    ti.tio.c_lflag &= ~ICANON;
    ti.tio.c_cc[VMIN] = 1;
    ti.tio.c_cc[VTIME] = 0;

    ti.sgttyb.sg_flags |= CBREAK;

    settyinfo(&ti);
}




mod_export void attachtty(pid_t pgrp)
{
    static int ep = 0;

    if (jobbing && interact) {

	if (SHTTY != -1 && tcsetpgrp(SHTTY, pgrp) == -1 && !ep)


	if (SHTTY != -1 && setpgrp() == -1 && !ep)

	int arg = pgrp;

	if (SHTTY != -1 && ioctl(SHTTY, TIOCSPGRP, &arg) == -1 && !ep)


	{
	    if (pgrp != mypgrp && kill(-pgrp, 0) == -1)
		attachtty(mypgrp);
	    else {
		if (errno != ENOTTY)
		{
		    zwarn("can't set tty pgrp: %e", errno);
		    fflush(stderr);
		}
		opts[MONITOR] = 0;
		ep = 1;
	    }
	}
    }
}




pid_t gettygrp(void)
{
    pid_t arg;

    if (SHTTY == -1)
	return -1;


    arg = tcgetpgrp(SHTTY);

    ioctl(SHTTY, TIOCGPGRP, &arg);


    return arg;
}





mod_export char * metafy(char *buf, int len, int heap)
{
    int meta = 0;
    char *t, *p, *e;
    static char mbuf[PATH_MAX*2+1];

    if (len == -1) {
	for (e = buf, len = 0; *e; len++)
	    if (imeta(*e++))
		meta++;
    } else for (e = buf; e < buf + len;)
	    if (imeta(*e++))
		meta++;

    if (meta || heap == META_DUP || heap == META_HEAPDUP) {
	switch (heap) {
	case META_REALLOC:
	    buf = zrealloc(buf, len + meta + 1);
	    break;
	case META_HREALLOC:
	    buf = hrealloc(buf, len, len + meta + 1);
	    break;
	case META_ALLOC:
	case META_DUP:
	    buf = memcpy(zalloc(len + meta + 1), buf, len);
	    break;
	case META_USEHEAP:
	case META_HEAPDUP:
	    buf = memcpy(zhalloc(len + meta + 1), buf, len);
	    break;
	case META_STATIC:

	    if (len > PATH_MAX) {
		fprintf(stderr, "BUG: len = %d > PATH_MAX in metafy\n", len);
		fflush(stderr);
	    }

	    buf = memcpy(mbuf, buf, len);
	    break;

	case META_NOALLOC:
	    break;
	default:
	    fprintf(stderr, "BUG: metafy called with invalid heap value\n");
	    fflush(stderr);
	    break;

	}
	p = buf + len;
	e = t = buf + len + meta;
	while (meta) {
	    if (imeta(*--t = *--p)) {
		*t-- ^= 32;
		*t = Meta;
		meta--;
	    }
	}
    }
    *e = '\0';
    return buf;
}




mod_export char * ztrdup_metafy(const char *s)
{
    
    if (!s)
	return NULL;
    
    return metafy((char *)s, -1, META_DUP);
}





mod_export char * unmetafy(char *s, int *len)
{
    char *p, *t;

    for (p = s; *p && *p != Meta; p++);
    for (t = p; (*t = *p++);)
	if (*t++ == Meta && *p)
	    t[-1] = *p++ ^ 32;
    if (len)
	*len = t - s;
    return s;
}




mod_export int metalen(const char *s, int len)
{
    int mlen = len;

    while (len--) {
	if (*s++ == Meta) {
	    mlen++;
	    s++;
	}
    }
    return mlen;
}




mod_export char * unmeta(const char *file_name)
{
    static char *fn;
    static int sz;
    char *p;
    const char *t;
    int newsz, meta;

    if (!file_name)
	return NULL;

    meta = 0;
    for (t = file_name; *t; t++) {
	if (*t == Meta)
	    meta = 1;
    }
    if (!meta) {
	
	if (sz > 4 * PATH_MAX) {
	    zfree(fn, sz);
	    fn = NULL;
	    sz = 0;
	}
	return (char *) file_name;
    }

    newsz = (t - file_name) + 1;
    
    if (!fn || newsz > sz || (sz > 4 * PATH_MAX && newsz <= 4 * PATH_MAX))
    {
	if (fn)
	    zfree(fn, sz);
	sz = newsz;
	fn = (char *)zalloc(sz);
	if (!fn) {
	    sz = 0;
	    
	    return NULL;
	}
    }

    for (t = file_name, p = fn; *t; p++)
	if ((*p = *t++) == Meta && *t)
	    *p = *t++ ^ 32;
    *p = '\0';
    return fn;
}



mod_export convchar_t unmeta_one(const char *in, int *sz)
{
    convchar_t wc;
    int newsz;

    mbstate_t wstate;


    if (!sz)
	sz = &newsz;
    *sz = 0;

    if (!in || !*in)
	return 0;


    memset(&wstate, 0, sizeof(wstate));
    *sz = mb_metacharlenconv_r(in, &wc, &wstate);

    if (in[0] == Meta) {
      *sz = 2;
      wc = STOUC(in[1] ^ 32);
    } else {
      *sz = 1;
      wc = STOUC(in[0]);
    }

    return wc;
}




int ztrcmp(char const *s1, char const *s2)
{
    int c1, c2;

    while(*s1 && *s1 == *s2) {
	s1++;
	s2++;
    }

    if(!(c1 = *s1))
	c1 = -1;
    else if(c1 == STOUC(Meta))
	c1 = *++s1 ^ 32;
    if(!(c2 = *s2))
	c2 = -1;
    else if(c2 == STOUC(Meta))
	c2 = *++s2 ^ 32;

    if(c1 == c2)
	return 0;
    else if(c1 < c2)
	return -1;
    else return 1;
}




mod_export int ztrlen(char const *s)
{
    int l;

    for (l = 0; *s; l++) {
	if (*s++ == Meta) {

	    if (! *s) {
		fprintf(stderr, "BUG: unexpected end of string in ztrlen()\n");
		break;
	    } else  s++;

	}
    }
    return l;
}





mod_export int ztrlenend(char const *s, char const *eptr)
{
    int l;

    for (l = 0; s < eptr; l++) {
	if (*s++ == Meta) {

	    if (! *s) {
		fprintf(stderr, "BUG: unexpected end of string in ztrlenend()\n");
		break;
	    } else  s++;

	}
    }
    return l;
}






mod_export int ztrsub(char const *t, char const *s)
{
    int l = t - s;

    while (s != t) {
	if (*s++ == Meta) {

	    if (! *s || s == t)
		fprintf(stderr, "BUG: substring ends in the middle of a metachar in ztrsub()\n");
	    else  s++;

	    l--;
	}
    }
    return l;
}




mod_export char * zreaddir(DIR *dir, int ignoredots)
{
    struct dirent *de;

    static iconv_t conv_ds = (iconv_t)0;
    static char *conv_name = 0;
    char *conv_name_ptr, *orig_name_ptr;
    size_t conv_name_len, orig_name_len;


    do {
	de = readdir(dir);
	if(!de)
	    return NULL;
    } while(ignoredots && de->d_name[0] == '.' && (!de->d_name[1] || (de->d_name[1] == '.' && !de->d_name[2])));


    if (!conv_ds)
	conv_ds = iconv_open("UTF-8", "UTF-8-MAC");
    if (conv_ds != (iconv_t)(-1)) {
	
	(void) iconv(conv_ds, 0, &orig_name_len, 0, &conv_name_len);

	orig_name_ptr = de->d_name;
	orig_name_len = strlen(de->d_name);
	conv_name = zrealloc(conv_name, orig_name_len+1);
	conv_name_ptr = conv_name;
	conv_name_len = orig_name_len;
	if (iconv(conv_ds, &orig_name_ptr, &orig_name_len, &conv_name_ptr, &conv_name_len) != (size_t)(-1) && orig_name_len == 0) {


	    
	    *conv_name_ptr = '\0';
	    return metafy(conv_name, -1, META_STATIC);
	}
	
    }


    return metafy(de->d_name, -1, META_STATIC);
}




mod_export int zputs(char const *s, FILE *stream)
{
    int c;

    while (*s) {
	if (*s == Meta)
	    c = *++s ^ 32;
	else if(itok(*s)) {
	    s++;
	    continue;
	} else c = *s;
	s++;
	if (fputc(c, stream) < 0)
	    return EOF;
    }
    return 0;
}





mod_export char * nicedup(char const *s, int heap)
{
    int c, len = strlen(s) * 5 + 1;
    VARARR(char, buf, len);
    char *p = buf, *n;

    while ((c = *s++)) {
	if (itok(c)) {
	    if (c <= Comma)
		c = ztokens[c - Pound];
	    else continue;
	}
	if (c == Meta)
	    c = *s++ ^ 32;
	
	n = nicechar(c);
	while(*n)
	    *p++ = *n++;
    }
    *p = '\0';
    return heap ? dupstring(buf) : ztrdup(buf);
}



mod_export char * nicedupstring(char const *s)
{
    return nicedup(s, 1);
}






mod_export int nicezputs(char const *s, FILE *stream)
{
    int c;

    while ((c = *s++)) {
	if (itok(c)) {
	    if (c <= Comma)
		c = ztokens[c - Pound];
	    else continue;
	}
	if (c == Meta)
	    c = *s++ ^ 32;
	if(zputs(nicechar(c), stream) < 0)
	    return EOF;
    }
    return 0;
}





mod_export size_t niceztrlen(char const *s)
{
    size_t l = 0;
    int c;

    while ((c = *s++)) {
	if (itok(c)) {
	    if (c <= Comma)
		c = ztokens[c - Pound];
	    else continue;
	}
	if (c == Meta)
	    c = *s++ ^ 32;
	l += strlen(nicechar(c));
    }
    return l;
}








mod_export size_t mb_niceformat(const char *s, FILE *stream, char **outstrp, int flags)
{
    size_t l = 0, newl;
    int umlen, outalloc, outleft, eol = 0;
    wchar_t c;
    char *ums, *ptr, *fmt, *outstr, *outptr;
    mbstate_t mbs;

    if (outstrp) {
	outleft = outalloc = 5 * strlen(s);
	outptr = outstr = zalloc(outalloc);
    } else {
	outleft = outalloc = 0;
	outptr = outstr = NULL;
    }

    ums = ztrdup(s);
    
    untokenize(ums);
    ptr = unmetafy(ums, &umlen);

    memset(&mbs, 0, sizeof mbs);
    while (umlen > 0) {
	size_t cnt = eol ? MB_INVALID : mbrtowc(&c, ptr, umlen, &mbs);

	switch (cnt) {
	case MB_INCOMPLETE:
	    eol = 1;
	    
	case MB_INVALID:
	    
	    fmt = nicechar_sel(*ptr, flags & NICEFLAG_QUOTE);
	    newl = strlen(fmt);
	    cnt = 1;
	    
	    memset(&mbs, 0, sizeof mbs);
	    break;
	case 0:
	    
	    cnt = 1;
	    
	default:
	    if (c == L'\'' && (flags & NICEFLAG_QUOTE)) {
		fmt = "\\'";
		newl = 2;
	    }
	    else if (c == L'\\' && (flags & NICEFLAG_QUOTE)) {
		fmt = "\\\\";
		newl = 2;
	    }
	    else fmt = wcs_nicechar_sel(c, &newl, NULL, flags & NICEFLAG_QUOTE);
	    break;
	}

	umlen -= cnt;
	ptr += cnt;
	l += newl;

	if (stream)
	    zputs(fmt, stream);
	if (outstr) {
	    
	    int outlen = strlen(fmt);
	    if (outlen >= outleft) {
		
		int outoffset = outptr - outstr;

		outleft += outalloc;
		outalloc *= 2;
		outstr = zrealloc(outstr, outalloc);
		outptr = outstr + outoffset;
	    }
	    memcpy(outptr, fmt, outlen);
	    
	    outptr += outlen;
	    
	    outleft -= outlen;
	}
    }

    free(ums);
    if (outstrp) {
	*outptr = '\0';
	
	if (flags & NICEFLAG_NODUP)
	    *outstrp = outstr;
	else {
	    *outstrp = (flags & NICEFLAG_HEAP) ? dupstring(outstr) :
		ztrdup(outstr);
	    free(outstr);
	}
    }

    return l;
}




mod_export int is_mb_niceformat(const char *s)
{
    int umlen, eol = 0, ret = 0;
    wchar_t c;
    char *ums, *ptr;
    mbstate_t mbs;

    ums = ztrdup(s);
    untokenize(ums);
    ptr = unmetafy(ums, &umlen);

    memset(&mbs, 0, sizeof mbs);
    while (umlen > 0) {
	size_t cnt = eol ? MB_INVALID : mbrtowc(&c, ptr, umlen, &mbs);

	switch (cnt) {
	case MB_INCOMPLETE:
	    eol = 1;
	    
	case MB_INVALID:
	    
	    if (is_nicechar(*ptr))  {
		ret = 1;
		break;
	    }
	    cnt = 1;
	    
	    memset(&mbs, 0, sizeof mbs);
	    break;
	case 0:
	    
	    cnt = 1;
	    
	default:
	    if (is_wcs_nicechar(c))
		ret = 1;
	    break;
	}

	if (ret)
	    break;

	umlen -= cnt;
	ptr += cnt;
    }

    free(ums);

    return ret;
}




mod_export char * nicedup(const char *s, int heap)
{
    char *retstr;

    (void)mb_niceformat(s, NULL, &retstr, heap ? NICEFLAG_HEAP : 0);

    return retstr;
}





mod_export int mb_metacharlenconv_r(const char *s, wint_t *wcp, mbstate_t *mbsp)
{
    size_t ret = MB_INVALID;
    char inchar;
    const char *ptr;
    wchar_t wc;

    if (STOUC(*s) <= 0x7f) {
	if (wcp)
	    *wcp = (wint_t)*s;
	return 1;
    }

    for (ptr = s; *ptr; ) {
	if (*ptr == Meta) {
	    inchar = *++ptr ^ 32;
	    DPUTS(!*ptr, "BUG: unexpected end of string in mb_metacharlen()\n");
	} else if (imeta(*ptr)) {
	    
	    break;
	} else inchar = *ptr;
	ptr++;
	ret = mbrtowc(&wc, &inchar, 1, mbsp);

	if (ret == MB_INVALID)
	    break;
	if (ret == MB_INCOMPLETE)
	    continue;
	if (wcp)
	    *wcp = wc;
	return ptr - s;
    }

    if (wcp)
	*wcp = WEOF;
    
    memset(mbsp, 0, sizeof(*mbsp));
    if (ptr > s) {
	return 1 + (*s == Meta);	
    } else return 0;
}




mod_export int mb_metacharlenconv(const char *s, wint_t *wcp)
{
    if (!isset(MULTIBYTE) || STOUC(*s) <= 0x7f) {
	
	if (wcp)
	    *wcp = (wint_t)(*s == Meta ? s[1] ^ 32 : *s);
	return 1 + (*s == Meta);
    }
    
    if (itok(*s)) {
	if (wcp)
	    *wcp = WEOF;
	return 1;
    }

    return mb_metacharlenconv_r(s, wcp, &mb_shiftstate);
}




mod_export int mb_metastrlenend(char *ptr, int width, char *eptr)
{
    char inchar, *laststart;
    size_t ret;
    wchar_t wc;
    int num, num_in_char, complete;

    if (!isset(MULTIBYTE))
	return eptr ? (int)(eptr - ptr) : ztrlen(ptr);

    laststart = ptr;
    ret = MB_INVALID;
    num = num_in_char = 0;
    complete = 1;

    memset(&mb_shiftstate, 0, sizeof(mb_shiftstate));
    while (*ptr && !(eptr && ptr >= eptr)) {
	if (*ptr == Meta)
	    inchar = *++ptr ^ 32;
	else inchar = *ptr;
	ptr++;

	if (complete && STOUC(inchar) <= STOUC(0x7f)) {
	    
	    num++;
	    laststart = ptr;
	    num_in_char = 0;
	    continue;
	}

	ret = mbrtowc(&wc, &inchar, 1, &mb_shiftstate);

	if (ret == MB_INCOMPLETE) {
	    
	    num_in_char++;
	    complete = 0;
	} else {
	    if (ret == MB_INVALID) {
		
		memset(&mb_shiftstate, 0, sizeof(mb_shiftstate));
		ptr = laststart + (*laststart == Meta) + 1;
		num++;
	    } else if (width) {
		
		int wcw = WCWIDTH(wc);
		if (wcw > 0) {
		    if (width == 1)
			num += wcw;
		    else num++;
		}
	    } else num++;
	    laststart = ptr;
	    num_in_char = 0;
	    complete = 1;
	}
    }

    
    return num + (num_in_char ? 1 : 0);
}




mod_export int mb_charlenconv_r(const char *s, int slen, wint_t *wcp, mbstate_t *mbsp)
{
    size_t ret = MB_INVALID;
    char inchar;
    const char *ptr;
    wchar_t wc;

    if (slen && STOUC(*s) <= 0x7f) {
	if (wcp)
	    *wcp = (wint_t)*s;
	return 1;
    }

    for (ptr = s; slen;  ) {
	inchar = *ptr;
	ptr++;
	slen--;
	ret = mbrtowc(&wc, &inchar, 1, mbsp);

	if (ret == MB_INVALID)
	    break;
	if (ret == MB_INCOMPLETE)
	    continue;
	if (wcp)
	    *wcp = wc;
	return ptr - s;
    }

    if (wcp)
	*wcp = WEOF;
    
    memset(mbsp, 0, sizeof(*mbsp));
    if (ptr > s) {
	return 1;	
    } else return 0;
}




mod_export int mb_charlenconv(const char *s, int slen, wint_t *wcp)
{
    if (!isset(MULTIBYTE) || STOUC(*s) <= 0x7f) {
	if (wcp)
	    *wcp = (wint_t)*s;
	return 1;
    }

    return mb_charlenconv_r(s, slen, wcp, &mb_shiftstate);
}







mod_export int metacharlenconv(const char *x, int *c)
{
    
    if (*x == Meta) {
	if (c)
	    *c = x[1] ^ 32;
	return 2;
    }
    if (c)
	*c = (char)*x;
    return 1;
}




mod_export int charlenconv(const char *x, int len, int *c)
{
    if (!len) {
	if (c)
	    *c = '\0';
	return 0;
    }

    if (c)
	*c = (char)*x;
    return 1;
}







mod_export int zexpandtabs(const char *s, int len, int width, int startpos, FILE *fout, int all)

{
    int at_start = 1;


    mbstate_t mbs;
    size_t ret;
    wchar_t wc;

    memset(&mbs, 0, sizeof(mbs));


    while (len) {
	if (*s == '\t') {
	    if (all || at_start) {
		s++;
		len--;
		if (width <= 0 || !(startpos % width)) {
		    
		    fputc(' ', fout);
		    startpos++;
		}
		if (width <= 0)
		    continue;	
		while (startpos % width) {
		    fputc(' ', fout);
		    startpos++;
		}
	    } else {
		
		startpos += width - startpos % width;
		s++;
		len--;
		fputc('\t', fout);
	    }
	    continue;
	} else if (*s == '\n' || *s == '\r') {
	    fputc(*s, fout);
	    s++;
	    len--;
	    startpos = 0;
	    at_start = 1;
	    continue;
	}

	at_start = 0;

	if (isset(MULTIBYTE)) {
	    const char *sstart = s;
	    ret = mbrtowc(&wc, s, len, &mbs);
	    if (ret == MB_INVALID) {
		
		memset(&mbs, 0, sizeof(mbs));
		s++;
		len--;
	    } else if (ret == MB_INCOMPLETE) {
		
		s++;
		len--;
	    } else {
		s += ret;
		len -= (int)ret;
	    }
	    if (ret == MB_INVALID || ret == MB_INCOMPLETE) {
		startpos++;
	    } else {
		int wcw = WCWIDTH(wc);
		if (wcw > 0)	
		    startpos += wcw;
	    }
	    fwrite(sstart, s - sstart, 1, fout);

	    continue;
	}

	fputc(*s, fout);
	s++;
	len--;
	startpos++;
    }

    return startpos;
}




mod_export int hasspecial(char const *s)
{
    for (; *s; s++) {
	if (ispecial(*s == Meta ? *++s ^ 32 : *s))
	    return 1;
    }
    return 0;
}


static char * addunprintable(char *v, const char *u, const char *uend)
{
    for (; u < uend; u++) {
	
	int c;
	if (*u == Meta)
	    c = STOUC(*++u ^ 32);
	else c = STOUC(*u);
	switch (c) {
	case '\0':
	    *v++ = '\\';
	    *v++ = '0';
	    if ('0' <= u[1] && u[1] <= '7') {
		*v++ = '0';
		*v++ = '0';
	    }
	    break;

	case '\007': *v++ = '\\'; *v++ = 'a'; break;
	case '\b': *v++ = '\\'; *v++ = 'b'; break;
	case '\f': *v++ = '\\'; *v++ = 'f'; break;
	case '\n': *v++ = '\\'; *v++ = 'n'; break;
	case '\r': *v++ = '\\'; *v++ = 'r'; break;
	case '\t': *v++ = '\\'; *v++ = 't'; break;
	case '\v': *v++ = '\\'; *v++ = 'v'; break;

	default:
	    *v++ = '\\';
	    *v++ = '0' + ((c >> 6) & 7);
	    *v++ = '0' + ((c >> 3) & 7);
	    *v++ = '0' + (c & 7);
	    break;
	}
    }

    return v;
}




mod_export char * quotestring(const char *s, int instring)
{
    const char *u;
    char *v;
    int alloclen;
    char *buf;
    int shownull = 0;
    
    int quotesub = 0, slen;
    char *quotestart;
    convchar_t cc;
    const char *uend;

    slen = strlen(s);
    switch (instring)
    {
    case QT_BACKSLASH_SHOWNULL:
	shownull = 1;
	instring = QT_BACKSLASH;
	
    case QT_BACKSLASH:
	
	alloclen = slen * 7 + 1;
	break;

    case QT_BACKSLASH_PATTERN:
	alloclen = slen * 2  + 1;
	break;

    case QT_SINGLE_OPTIONAL:
	
	alloclen = slen * 4 + 3;
	quotesub = shownull = 1;
	break;

    default:
	alloclen = slen * 4 + 1;
	break;
    }
    if (!*s && shownull)
	alloclen += 2;	

    quotestart = v = buf = zshcalloc(alloclen);

    DPUTS(instring < QT_BACKSLASH || instring == QT_BACKTICK || instring > QT_BACKSLASH_PATTERN, "BUG: bad quote type in quotestring");

    u = s;
    if (instring == QT_DOLLARS) {
	
	if (inull(*u))
	    u++;
	
	MB_METACHARINIT();
	while (*u) {
	    uend = u + MB_METACHARLENCONV(u, &cc);

	    if (  cc != WEOF &&  WC_ISPRINT(cc)) {



		switch (cc) {
		case ZWC('\\'):
		case ZWC('\''):
		    *v++ = '\\';
		    break;

		default:
		    if (isset(BANGHIST) && cc == (wchar_t)bangchar)
			*v++ = '\\';
		    break;
		}
		while (u < uend)
		    *v++ = *u++;
	    } else {
		
		v = addunprintable(v, u, uend);
		u = uend;
	    }
	}
    } else if (instring == QT_BACKSLASH_PATTERN) {
	while (*u) {
	    if (ipattern(*u))
		*v++ = '\\';
	    *v++ = *u++;
	}
    } else {
	if (shownull) {
	    
	    if (!*u) {
		*v++ = '\'';
		*v++ = '\'';
	    }
	}
	
	while (*u) {
	    int dobackslash = 0;
	    if (*u == Tick || *u == Qtick) {
		char c = *u++;

		*v++ = c;
		while (*u && *u != c)
		    *v++ = *u++;
		*v++ = c;
		if (*u)
		    u++;
		continue;
	    } else if ((*u == Qstring || *u == '$') && u[1] == '\'' && instring == QT_DOUBLE) {
		
		*v++ = *u++;
	    } else if ((*u == String || *u == Qstring) && (u[1] == Inpar || u[1] == Inbrack || u[1] == Inbrace)) {
		char c = (u[1] == Inpar ? Outpar : (u[1] == Inbrace ? Outbrace : Outbrack));
		char beg = *u;
		int level = 0;

		*v++ = *u++;
		*v++ = *u++;
		while (*u && (*u != c || level)) {
		    if (*u == beg)
			level++;
		    else if (*u == c)
			level--;
		    *v++ = *u++;
		}
		if (*u)
		    *v++ = *u++;
		continue;
	    }
	    else if (ispecial(*u) && ((*u != '=' && *u != '~') || u == s || (isset(MAGICEQUALSUBST) && (u[-1] == '=' || u[-1] == ':')) || (*u == '~' && isset(EXTENDEDGLOB))) && (instring == QT_BACKSLASH || instring == QT_SINGLE_OPTIONAL || (isset(BANGHIST) && *u == (char)bangchar && instring != QT_SINGLE) || (instring == QT_DOUBLE && (*u == '$' || *u == '`' || *u == '\"' || *u == '\\')) || (instring == QT_SINGLE && *u == '\''))) {











		if (instring == QT_SINGLE_OPTIONAL) {
		    if (quotesub == 1) {
			
			if (*u == '\'') {
			    
			    *v++ = '\\';
			} else {
			    
			    if (v > quotestart)
			    {
				char *addq;

				for (addq = v; addq > quotestart; addq--)
				    *addq = addq[-1];
			    }
			    *quotestart = '\'';
			    v++;
			    quotesub = 2;
			}
			*v++ = *u++;
			
			quotestart = v;
		    } else if (*u == '\'') {
			if (unset(RCQUOTES)) {
			    *v++ = '\'';
			    *v++ = '\\';
			    *v++ = '\'';
			    
			    quotesub = 1;
			    quotestart = v;
			} else {
			    
			    *v++ = '\'';
			    *v++ = '\'';
			}
			
			u++;
		    } else {
			
			*v++ = *u++;
		    }
		    continue;
		} else if (*u == '\n' || (instring == QT_SINGLE && *u == '\'')) {
		    if (*u == '\n') {
			*v++ = '$';
			*v++ = '\'';
			*v++ = '\\';
			*v++ = 'n';
			*v++ = '\'';
		    } else if (unset(RCQUOTES)) {
			*v++ = '\'';
			if (*u == '\'')
			    *v++ = '\\';
			*v++ = *u;
			*v++ = '\'';
		    } else *v++ = '\'', *v++ = '\'';
		    u++;
		    continue;
		} else {
		    
		    dobackslash = 1;
		}
	    }

	    if (itok(*u) || instring != QT_BACKSLASH) {
		
		if (dobackslash)
		    *v++ = '\\';
		if (*u == Inparmath) {
		    
		    int inmath = 1;
		    *v++ = *u++;
		    for (;;) {
			char uc = *u;
			*v++ = *u++;
			if (uc == '\0')
			    break;
			else if (uc == Outparmath && !--inmath)
			    break;
			else if (uc == Inparmath)
			    ++inmath;
		    }
		} else *v++ = *u++;
		continue;
	    }

	    
	    uend = u + MB_METACHARLENCONV(u, &cc);
	    if (  cc != WEOF &&  WC_ISPRINT(cc)) {



		if (dobackslash)
		    *v++ = '\\';
		while (u < uend) {
		    if (*u == Meta)
			*v++ = *u++;
		    *v++ = *u++;
		}
	    } else {
		
		*v++ = '$';
		*v++ = '\'';
		v = addunprintable(v, u, uend);
		*v++ = '\'';
		u = uend;
	    }
	}
    }
    if (quotesub == 2)
	*v++ = '\'';
    *v = '\0';

    v = dupstring(buf);
    zfree(buf, alloclen);
    return v;
}




mod_export char * quotedzputs(char const *s, FILE *stream)
{
    int inquote = 0, c;
    char *outstr, *ptr;

    
    if(!*s) {
	if (!stream)
	    return dupstring("''");
	fputs("''", stream);
	return NULL;
    }


    if (is_mb_niceformat(s)) {
	if (stream) {
	    fputs("$'", stream);
	    mb_niceformat(s, stream, NULL, NICEFLAG_QUOTE);
	    fputc('\'', stream);
	    return NULL;
	} else {
	    char *substr;
	    mb_niceformat(s, NULL, &substr, NICEFLAG_QUOTE|NICEFLAG_NODUP);
	    outstr = (char *)zhalloc(4 + strlen(substr));
	    sprintf(outstr, "$'%s'", substr);
	    free(substr);
	    return outstr;
	}
    }


    if (!hasspecial(s)) {
	if (stream) {
	    zputs(s, stream);
	    return NULL;
	} else {
	    return dupstring(s);
	}
    }

    if (!stream) {
	const char *cptr;
	int l = strlen(s) + 2;
	for (cptr = s; *cptr; cptr++) {
	    if (*cptr == Meta)
		cptr++;
	    else if (*cptr == '\'')
		l += isset(RCQUOTES) ? 1 : 3;
	}
	ptr = outstr = zhalloc(l + 1);
    } else {
	ptr = outstr = NULL;
    }
    if (isset(RCQUOTES)) {
	
	if (stream) {
	    if (fputc('\'', stream) < 0)
		return NULL;
	} else *ptr++ = '\'';
	while(*s) {
	    if (*s == Dash)
		c = '-';
	    else if (*s == Meta)
		c = *++s ^ 32;
	    else c = *s;
	    s++;
	    if (c == '\'') {
		if (stream) {
		    if (fputc('\'', stream) < 0)
			return NULL;
		} else *ptr++ = '\'';
	    } else if (c == '\n' && isset(CSHJUNKIEQUOTES)) {
		if (stream) {
		    if (fputc('\\', stream) < 0)
			return NULL;
		} else *ptr++ = '\\';
	    }
	    if (stream) {
		if (fputc(c, stream) < 0)
		    return NULL;
	    } else {
		if (imeta(c)) {
		    *ptr++ = Meta;
		    *ptr++ = c ^ 32;
		} else *ptr++ = c;
	    }
	}
	if (stream) {
	    if (fputc('\'', stream) < 0)
		return NULL;
	} else *ptr++ = '\'';
    } else {
	
	while (*s) {
	    if (*s == Dash)
		c = '-';
	    else if (*s == Meta)
		c = *++s ^ 32;
	    else c = *s;
	    s++;
	    if (c == '\'') {
		if (inquote) {
		    if (stream) {
			if (putc('\'', stream) < 0)
			    return NULL;
		    } else *ptr++ = '\'';
		    inquote=0;
		}
		if (stream) {
		    if (fputs("\\'", stream) < 0)
			return NULL;
		} else {
		    *ptr++ = '\\';
		    *ptr++ = '\'';
		}
	    } else {
		if (!inquote) {
		    if (stream) {
			if (fputc('\'', stream) < 0)
			    return NULL;
		    } else *ptr++ = '\'';
		    inquote=1;
		}
		if (c == '\n' && isset(CSHJUNKIEQUOTES)) {
		    if (stream) {
			if (fputc('\\', stream) < 0)
			    return NULL;
		    } else *ptr++ = '\\';
		}
		if (stream) {
		    if (fputc(c, stream) < 0)
			return NULL;
		} else {
		    if (imeta(c)) {
			*ptr++ = Meta;
			*ptr++ = c ^ 32;
		    } else *ptr++ = c;
		}
	    }
	}
	if (inquote) {
	    if (stream) {
		if (fputc('\'', stream) < 0)
		    return NULL;
	    } else *ptr++ = '\'';
	}
    }
    if (!stream)
	*ptr++ = '\0';

    return outstr;
}




mod_export char * dquotedztrdup(char const *s)
{
    int len = strlen(s) * 4 + 2;
    char *buf = zalloc(len);
    char *p = buf, *ret;

    if(isset(CSHJUNKIEQUOTES)) {
	int inquote = 0;

	while(*s) {
	    int c = *s++;

	    if (c == Meta)
		c = *s++ ^ 32;
	    switch(c) {
		case '"':
		case '$':
		case '`':
		    if(inquote) {
			*p++ = '"';
			inquote = 0;
		    }
		    *p++ = '\\';
		    *p++ = c;
		    break;
		default:
		    if(!inquote) {
			*p++ = '"';
			inquote = 1;
		    }
		    if(c == '\n')
			*p++ = '\\';
		    *p++ = c;
		    break;
	    }
	}
	if (inquote)
	    *p++ = '"';
    } else {
	int pending = 0;

	*p++ = '"';
	while(*s) {
	    int c = *s++;

	    if (c == Meta)
		c = *s++ ^ 32;
	    switch(c) {
		case '\\':
		    if(pending)
			*p++ = '\\';
		    *p++ = '\\';
		    pending = 1;
		    break;
		case '"':
		case '$':
		case '`':
		    if(pending)
			*p++ = '\\';
		    *p++ = '\\';
		    
		default:
		    *p++ = c;
		    pending = 0;
		    break;
	    }
	}
	if(pending)
	    *p++ = '\\';
	*p++ = '"';
    }
    ret = metafy(buf, p - buf, META_DUP);
    zfree(buf, len);
    return ret;
}




int dquotedzputs(char const *s, FILE *stream)
{
    char *d = dquotedztrdup(s);
    int ret = zputs(d, stream);

    zsfree(d);
    return ret;
}





static size_t ucs4toutf8(char *dest, unsigned int wval)
{
    size_t len;

    if (wval < 0x80)
      len = 1;
    else if (wval < 0x800)
      len = 2;
    else if (wval < 0x10000)
      len = 3;
    else if (wval < 0x200000)
      len = 4;
    else if (wval < 0x4000000)
      len = 5;
    else len = 6;

    switch (len) { 
    case 6: dest[5] = (wval & 0x3f) | 0x80; wval >>= 6;
    case 5: dest[4] = (wval & 0x3f) | 0x80; wval >>= 6;
    case 4: dest[3] = (wval & 0x3f) | 0x80; wval >>= 6;
    case 3: dest[2] = (wval & 0x3f) | 0x80; wval >>= 6;
    case 2: dest[1] = (wval & 0x3f) | 0x80; wval >>= 6;
	*dest = wval | ((0xfc << (6 - len)) & 0xfc);
	break;
    case 1: *dest = wval;
    }

    return len;
}


























mod_export char * getkeystring(char *s, int *len, int how, int *misc)
{
    char *buf, tmp[1];
    char *t, *tdest = NULL, *u = NULL, *sstart = s, *tbuf = NULL;
    char svchar = '\0';
    int meta = 0, control = 0, ignoring = 0;
    int i;

    wint_t wval;
    int count;

    unsigned int wval;


    iconv_t cd;
    char inbuf[4];
    size_t inbytes, outbytes;

    size_t count;



    DPUTS((how & GETKEY_UPDATE_OFFSET) && (how & ~(GETKEYS_DOLLARS_QUOTE|GETKEY_UPDATE_OFFSET)), "BUG: offset updating in getkeystring only supported with $'.");

    DPUTS((how & (GETKEY_DOLLAR_QUOTE|GETKEY_SINGLE_CHAR)) == (GETKEY_DOLLAR_QUOTE|GETKEY_SINGLE_CHAR), "BUG: incompatible options in getkeystring");


    if (how & GETKEY_SINGLE_CHAR)
	t = buf = tmp;
    else {
	
	int maxlen = 1;
	
	for (t = s; *t; t++) {
	    if (*t == '\\') {
		if (!t[1]) {
		    maxlen++;
		    break;
		}
		if (t[1] == 'u' || t[1] == 'U')
		    maxlen += MB_CUR_MAX * 2;
		else maxlen += 2;
		
		t++;
	    } else maxlen++;
	}
	if (how & GETKEY_DOLLAR_QUOTE) {
	    
	    buf = tdest = zhalloc(maxlen);
	    t = tbuf = zhalloc(MB_CUR_MAX * 3 + 1);
	} else {
	    t = buf = zhalloc(maxlen);
	}
    }
    for (; *s; s++) {
	if (*s == '\\' && s[1]) {
	    int miscadded;
	    if ((how & GETKEY_UPDATE_OFFSET) && s - sstart < *misc) {
		(*misc)--;
		miscadded = 1;
	    } else miscadded = 0;
	    switch (*++s) {
	    case 'a':

		*t++ = '\a';

		*t++ = '\07';

		break;
	    case 'n':
		*t++ = '\n';
		break;
	    case 'b':
		*t++ = '\b';
		break;
	    case 't':
		*t++ = '\t';
		break;
	    case 'v':
		*t++ = '\v';
		break;
	    case 'f':
		*t++ = '\f';
		break;
	    case 'r':
		*t++ = '\r';
		break;
	    case 'E':
		if (!(how & GETKEY_EMACS)) {
		    *t++ = '\\', s--;
		    if (miscadded)
			(*misc)++;
		    continue;
		}
		
	    case 'e':
		*t++ = '\033';
		break;
	    case 'M':
		
		if (how & GETKEY_EMACS) {
		    if (s[1] == '-')
			s++;
		    meta = 1 + control;	
		} else {
		    if (miscadded)
			(*misc)++;
		    *t++ = '\\', s--;
		}
		continue;
	    case 'C':
		
		if (how & GETKEY_EMACS) {
		    if (s[1] == '-')
			s++;
		    control = 1;
		} else {
		    if (miscadded)
			(*misc)++;
		    *t++ = '\\', s--;
		}
		continue;
	    case Meta:
		if (miscadded)
		    (*misc)++;
		*t++ = '\\', s--;
		break;
	    case '-':
		if (how & GETKEY_BACKSLASH_MINUS) {
		    *misc  = 1;
		    break;
		}
		goto def;
	    case 'c':
		if (how & GETKEY_BACKSLASH_C) {
		    *misc = 1;
		    *t = '\0';
		    *len = t - buf;
		    return buf;
		}
		goto def;
	    case 'U':
		if ((how & GETKEY_UPDATE_OFFSET) && s - sstart < *misc)
		    (*misc) -= 4;
		
	    case 'u':
		if ((how & GETKEY_UPDATE_OFFSET) && s - sstart < *misc) {
		    (*misc) -= 6; 
		    
		}
	    	wval = 0;
		for (i=(*s == 'u' ? 4 : 8); i>0; i--) {
		    if (*++s && idigit(*s))
		        wval = wval * 16 + (*s - '0');
		    else if (*s && ((*s >= 'a' && *s <= 'f') || (*s >= 'A' && *s <= 'F')))
		        wval = wval * 16 + (*s & 0x1f) + 9;
		    else {
		    	s--;
		        break;
		    }
		}
    	    	if (how & GETKEY_SINGLE_CHAR) {
		    *misc = wval;
		    return s+1;
		}

		count = wctomb(t, (wchar_t)wval);
		if (count == -1) {
		    zerr("character not in range");
		    CHARSET_FAILED();
		}
		if ((how & GETKEY_UPDATE_OFFSET) && s - sstart < *misc)
		    (*misc) += count;
		t += count;


		if (!strcmp(nl_langinfo(CODESET), "UTF-8")) {
		    count = ucs4toutf8(t, wval);
		    t += count;
		    if ((how & GETKEY_UPDATE_OFFSET) && s - sstart < *misc)
			(*misc) += count;
		} else {

		    ICONV_CONST char *inptr = inbuf;
		    const char *codesetstr = nl_langinfo(CODESET);
    	    	    inbytes = 4;
		    outbytes = 6;
		    
		    for (i=3;i>=0;i--) {
			inbuf[i] = wval & 0xff;
			wval >>= 8;
		    }

		    

		    if (!codesetstr || !*codesetstr)
			codesetstr = "US-ASCII";

    	    	    cd = iconv_open(codesetstr, "UCS-4BE");

		    if (cd == (iconv_t)-1 &&  !strcmp(codesetstr, "646")) {
			codesetstr = "US-ASCII";
			cd = iconv_open(codesetstr, "UCS-4BE");
		    }

		    if (cd == (iconv_t)-1) {
			zerr("cannot do charset conversion (iconv failed)");
			CHARSET_FAILED();
		    }
                    count = iconv(cd, &inptr, &inbytes, &t, &outbytes);
		    iconv_close(cd);
		    if (count == (size_t)-1) {
                        zerr("character not in range");
			CHARSET_FAILED();
		    }
		    if ((how & GETKEY_UPDATE_OFFSET) && s - sstart < *misc)
			(*misc) += count;

                    zerr("cannot do charset conversion (iconv not available)");
		    CHARSET_FAILED();

		}

                zerr("cannot do charset conversion (NLS not supported)");
		CHARSET_FAILED();


		if (how & GETKEY_DOLLAR_QUOTE) {
		    char *t2;
		    for (t2 = tbuf; t2 < t; t2++) {
			if (imeta(*t2)) {
			    *tdest++ = Meta;
			    *tdest++ = *t2 ^ 32;
			} else *tdest++ = *t2;
		    }
		    
		    t = tbuf;
		}
		continue;
	    case '\'':
	    case '\\':
		if (how & GETKEY_DOLLAR_QUOTE) {
		    
		    *t++ = *s;
		    break;
		}
		
	    default:
	    def:
		
		if ((idigit(*s) && *s < '8') || *s == 'x') {
		    if (!(how & GETKEY_OCTAL_ESC)) {
			if (*s == '0')
			    s++;
			else if (*s != 'x') {
			    *t++ = '\\', s--;
			    continue;
			}
		    }
		    if (s[1] && s[2] && s[3]) {
			svchar = s[3];
			s[3] = '\0';
			u = s;
		    }
		    *t++ = zstrtol(s + (*s == 'x'), &s, (*s == 'x') ? 16 : 8);
		    if ((how & GETKEY_PRINTF_PERCENT) && t[-1] == '%')
		        *t++ = '%';
		    if (svchar) {
			u[3] = svchar;
			svchar = '\0';
		    }
		    s--;
		} else {
		    if (!(how & GETKEY_EMACS) && *s != '\\') {
			if (miscadded)
			    (*misc)++;
			*t++ = '\\';
		    }
		    *t++ = *s;
		}
		break;
	    }
	} else if ((how & GETKEY_DOLLAR_QUOTE) && *s == Snull) {
	    
	    *len = (s - sstart) + 1;
	    *tdest = '\0';
	    return buf;
	} else if (*s == '^' && !control && (how & GETKEY_CTRL) && s[1]) {
	    control = 1;
	    continue;

	} else if ((how & GETKEY_SINGLE_CHAR) && isset(MULTIBYTE) && STOUC(*s) > 127) {
	    wint_t wc;
	    int len;
	    len = mb_metacharlenconv(s, &wc);
	    if (wc != WEOF) {
		*misc = (int)wc;
		return s + len;
	    }


	} else if (*s == Meta)
	    *t++ = *++s ^ 32;
	else {
	    if (itok(*s)) {
		
		if (meta || control) {
		    
		    if ((how & GETKEY_DOLLAR_QUOTE) && *s == Bnull)
			*t++ = *++s;
		    else *t++ = ztokens[*s - Pound];
		} else if (how & GETKEY_DOLLAR_QUOTE) {
		    
		    *tdest++ = *s;
		    if (*s == Bnull) {
			
			*tdest++ = *++s;
		    }
		    
		    t = tbuf;
		    continue;
		} else *t++ = *s;
	    } else *t++ = *s;
	}
	if (meta == 2) {
	    t[-1] |= 0x80;
	    meta = 0;
	}
	if (control) {
	    if (t[-1] == '?')
		t[-1] = 0x7f;
	    else t[-1] &= 0x9f;
	    control = 0;
	}
	if (meta) {
	    t[-1] |= 0x80;
	    meta = 0;
	}
	if (how & GETKEY_DOLLAR_QUOTE) {
	    char *t2;
	    for (t2 = tbuf; t2 < t; t2++) {
		
		if (isset(POSIXSTRINGS)) {
		    if (*t2 == '\0')
			ignoring = 1;
		    if (ignoring)
			break;
		}
		if (imeta(*t2)) {
		    *tdest++ = Meta;
		    *tdest++ = *t2 ^ 32;
		} else {
		    *tdest++ = *t2;
		}
	    }
	    
	    t = tbuf;
	}
	if ((how & GETKEY_SINGLE_CHAR) && t != tmp) {
	    *misc = STOUC(tmp[0]);
	    return s + 1;
	}
    }
    
    DPUTS((how & (GETKEY_DOLLAR_QUOTE|GETKEY_UPDATE_OFFSET)) == GETKEY_DOLLAR_QUOTE, "BUG: unterminated $' substitution");
    *t = '\0';
    if (how & GETKEY_DOLLAR_QUOTE)
	*tdest = '\0';
    if (how & GETKEY_SINGLE_CHAR)
	*misc = 0;
    else *len = ((how & GETKEY_DOLLAR_QUOTE) ? tdest : t) - buf;
    return buf;
}




mod_export int strpfx(const char *s, const char *t)
{
    while (*s && *s == *t)
	s++, t++;
    return !*s;
}




mod_export int strsfx(char *s, char *t)
{
    int ls = strlen(s), lt = strlen(t);

    if (ls <= lt)
	return !strcmp(t + lt - ls, s);
    return 0;
}


static int upchdir(int n)
{
    char buf[PATH_MAX+1];
    char *s;
    int err = -1;

    while (n > 0) {
	for (s = buf; s < buf + PATH_MAX - 4 && n--; )
	    *s++ = '.', *s++ = '.', *s++ = '/';
	s[-1] = '\0';
	if (chdir(buf))
	    return err;
	err = -2;
    }
    return 0;
}




mod_export void init_dirsav(Dirsav d)
{
    d->ino = d->dev = 0;
    d->dirname = NULL;
    d->dirfd = d->level = -1;
}




mod_export int lchdir(char const *path, struct dirsav *d, int hard)
{
    char const *pptr;
    int level;
    struct stat st1;
    struct dirsav ds;

    char buf[PATH_MAX + 1], *ptr;
    int err;
    struct stat st2;


    int close_dir = 0;


    if (!d) {
	init_dirsav(&ds);
	d = &ds;
    }

    if ((*path == '/' || !hard) && (d != &ds || hard)){

    if (*path == '/') {

	level = -1;

	if (!d->dirname)
	    zgetdir(d);

    } else {
	level = 0;
	if (!d->dev && !d->ino) {
	    stat(".", &st1);
	    d->dev = st1.st_dev;
	    d->ino = st1.st_ino;
	}
    }


    if (!hard)

    {
	if (d != &ds) {
	    for (pptr = path; *pptr; level++) {
		while (*pptr && *pptr++ != '/');
		while (*pptr == '/')
		    pptr++;
	    }
	    d->level = level;
	}
	return zchdir((char *) path);
    }



    if (d->dirfd < 0) {
	close_dir = 1;
        if ((d->dirfd = open(".", O_RDONLY | O_NOCTTY)) < 0 && zgetdir(d) && *d->dirname != '/')
	    d->dirfd = open("..", O_RDONLY | O_NOCTTY);
    }

    if (*path == '/')
	if (chdir("/") < 0)
	    zwarn("failed to chdir(/): %e", errno);
    for(;;) {
	while(*path == '/')
	    path++;
	if(!*path) {
	    if (d == &ds)
		zsfree(ds.dirname);
	    else d->level = level;

	    if (d->dirfd >=0 && close_dir) {
		close(d->dirfd);
		d->dirfd = -1;
	    }

	    return 0;
	}
	for(pptr = path; *++pptr && *pptr != '/'; ) ;
	if(pptr - path > PATH_MAX) {
	    err = ENAMETOOLONG;
	    break;
	}
	for(ptr = buf; path != pptr; )
	    *ptr++ = *path++;
	*ptr = 0;
	if(lstat(buf, &st1)) {
	    err = errno;
	    break;
	}
	if(!S_ISDIR(st1.st_mode)) {
	    err = ENOTDIR;
	    break;
	}
	if(chdir(buf)) {
	    err = errno;
	    break;
	}
	if (level >= 0)
	    level++;
	if(lstat(".", &st2)) {
	    err = errno;
	    break;
	}
	if(st1.st_dev != st2.st_dev || st1.st_ino != st2.st_ino) {
	    err = ENOTDIR;
	    break;
	}
    }
    if (restoredir(d)) {
	int restoreerr = errno;
	int i;
	
	for (i = 0; i < 2; i++) {
	    const char *cdest;
	    if (i)
		cdest = "/";
	    else {
		if (!home)
		    continue;
		cdest = home;
	    }
	    zsfree(pwd);
	    pwd = ztrdup(cdest);
	    if (chdir(pwd) == 0)
		break;
	}
	if (i == 2)
	    zerr("lost current directory, failed to cd to /: %e", errno);
	else zerr("lost current directory: %e: changed to `%s'", restoreerr, pwd);

	if (d == &ds)
	    zsfree(ds.dirname);

	if (d->dirfd >=0 && close_dir) {
	    close(d->dirfd);
	    d->dirfd = -1;
	}

	errno = err;
	return -2;
    }
    if (d == &ds)
	zsfree(ds.dirname);

    if (d->dirfd >=0 && close_dir) {
	close(d->dirfd);
	d->dirfd = -1;
    }

    errno = err;
    return -1;

}


mod_export int restoredir(struct dirsav *d)
{
    int err = 0;
    struct stat sbuf;

    if (d->dirname && *d->dirname == '/')
	return chdir(d->dirname);

    if (d->dirfd >= 0) {
	if (!fchdir(d->dirfd)) {
	    if (!d->dirname) {
		return 0;
	    } else if (chdir(d->dirname)) {
		close(d->dirfd);
		d->dirfd = -1;
		err = -2;
	    }
	} else {
	    close(d->dirfd);
	    d->dirfd = err = -1;
	}
    } else  if (d->level > 0)

	err = upchdir(d->level);
    else if (d->level < 0)
	err = -1;
    if (d->dev || d->ino) {
	stat(".", &sbuf);
	if (sbuf.st_ino != d->ino || sbuf.st_dev != d->dev)
	    err = -2;
    }
    return err;
}





int privasserted(void)
{
    if(!geteuid())
	return 1;

    {
	cap_t caps = cap_get_proc();
	if(caps) {
	    
	    cap_flag_value_t val;
	    cap_value_t n;
	    for(n = 0; !cap_get_flag(caps, n, CAP_EFFECTIVE, &val); n++)
		if(val) {
		    cap_free(caps);
		    return 1;
		}
	}
	cap_free(caps);
    }

    return 0;
}


mod_export int mode_to_octal(mode_t mode)
{
    int m = 0;

    if(mode & S_ISUID)
	m |= 04000;
    if(mode & S_ISGID)
	m |= 02000;
    if(mode & S_ISVTX)
	m |= 01000;
    if(mode & S_IRUSR)
	m |= 00400;
    if(mode & S_IWUSR)
	m |= 00200;
    if(mode & S_IXUSR)
	m |= 00100;
    if(mode & S_IRGRP)
	m |= 00040;
    if(mode & S_IWGRP)
	m |= 00020;
    if(mode & S_IXGRP)
	m |= 00010;
    if(mode & S_IROTH)
	m |= 00004;
    if(mode & S_IWOTH)
	m |= 00002;
    if(mode & S_IXOTH)
	m |= 00001;
    return m;
}





int mailstat(char *path, struct stat *st)
{
       DIR                     *dd;
       struct                  dirent *fn;
       struct stat             st_ret, st_tmp;
       static struct stat      st_ret_last;
       char                    *dir, *file = 0;
       int                     i;
       time_t                  atime = 0, mtime = 0;
       size_t                  plen = strlen(path), dlen;

       
       if ((i = stat(path, st)) != 0 || !S_ISDIR(st->st_mode))
               return i;

       st_ret = *st;
       st_ret.st_nlink = 1;
       st_ret.st_size  = 0;
       st_ret.st_blocks  = 0;
       st_ret.st_mode  &= ~S_IFDIR;
       st_ret.st_mode  |= S_IFREG;

       
       dir = appstr(ztrdup(path), "/cur");
       if (stat(dir, &st_tmp) || !S_ISDIR(st_tmp.st_mode)) return 0;
       st_ret.st_atime = st_tmp.st_atime;

       
       dir[plen] = 0;
       dir = appstr(dir, "/tmp");
       if (stat(dir, &st_tmp) || !S_ISDIR(st_tmp.st_mode)) return 0;
       st_ret.st_mtime = st_tmp.st_mtime;

       
       dir[plen] = 0;
       dir = appstr(dir, "/new");
       if (stat(dir, &st_tmp) || !S_ISDIR(st_tmp.st_mode)) return 0;
       st_ret.st_mtime = st_tmp.st_mtime;


       {
       static struct stat      st_new_last;
       
       if (st_tmp.st_dev == st_new_last.st_dev && st_tmp.st_ino == st_new_last.st_ino && st_tmp.st_atime == st_new_last.st_atime && st_tmp.st_mtime == st_new_last.st_mtime) {


	   *st = st_ret_last;
	   return 0;
       }
       st_new_last = st_tmp;
       }


       
       for (i = 0; i < 2; i++) {
	   dir[plen] = 0;
	   dir = appstr(dir, i ? "/cur" : "/new");
	   if ((dd = opendir(dir)) == NULL) {
	       zsfree(file);
	       zsfree(dir);
	       return 0;
	   }
	   dlen = strlen(dir) + 1; 
	   while ((fn = readdir(dd)) != NULL) {
	       if (fn->d_name[0] == '.')
		   continue;
	       if (file) {
		   file[dlen] = 0;
		   file = appstr(file, fn->d_name);
	       } else {
		   file = tricat(dir, "/", fn->d_name);
	       }
	       if (stat(file, &st_tmp) != 0)
		   continue;
	       st_ret.st_size += st_tmp.st_size;
	       st_ret.st_blocks++;
	       if (st_tmp.st_atime != st_tmp.st_mtime && st_tmp.st_atime > atime)
		   atime = st_tmp.st_atime;
	       if (st_tmp.st_mtime > mtime)
		   mtime = st_tmp.st_mtime;
	   }
	   closedir(dd);
       }
       zsfree(file);
       zsfree(dir);

       if (atime) st_ret.st_atime = atime;
       if (mtime) st_ret.st_mtime = mtime;

       *st = st_ret_last = st_ret;
       return 0;
}

