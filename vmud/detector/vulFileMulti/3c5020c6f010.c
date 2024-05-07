


static char sccsid[] = "@(#)glob.c	8.3 (Berkeley) 10/13/93";


__FBSDID("$FreeBSD$");
















































typedef uint_fast64_t Char;








typedef char Char;















static int	 compare(const void *, const void *);
static int	 g_Ctoc(const Char *, char *, size_t);
static int	 g_lstat(Char *, struct stat *, glob_t *);
static DIR	*g_opendir(Char *, glob_t *);
static const Char *g_strchr(const Char *, wchar_t);

static Char	*g_strcat(Char *, const Char *);

static int	 g_stat(Char *, struct stat *, glob_t *);
static int	 glob0(const Char *, glob_t *, size_t *);
static int	 glob1(Char *, glob_t *, size_t *);
static int	 glob2(Char *, Char *, Char *, Char *, glob_t *, size_t *);
static int	 glob3(Char *, Char *, Char *, Char *, Char *, glob_t *, size_t *);
static int	 globextend(const Char *, glob_t *, size_t *);
static const Char *	 globtilde(const Char *, Char *, size_t, glob_t *);
static int	 globexp1(const Char *, glob_t *, size_t *);
static int	 globexp2(const Char *, const Char *, glob_t *, int *, size_t *);
static int	 match(Char *, Char *, Char *);

static void	 qprintf(const char *, Char *);


int glob(const char * __restrict pattern, int flags, int (*errfunc)(const char *, int), glob_t * __restrict pglob)

{
	const char *patnext;
	size_t limit;
	Char *bufnext, *bufend, patbuf[MAXPATHLEN], prot;
	mbstate_t mbs;
	wchar_t wc;
	size_t clen;

	patnext = pattern;
	if (!(flags & GLOB_APPEND)) {
		pglob->gl_pathc = 0;
		pglob->gl_pathv = NULL;
		if (!(flags & GLOB_DOOFFS))
			pglob->gl_offs = 0;
	}
	if (flags & GLOB_LIMIT) {
		limit = pglob->gl_matchc;
		if (limit == 0)
			limit = ARG_MAX;
	} else limit = 0;
	pglob->gl_flags = flags & ~GLOB_MAGCHAR;
	pglob->gl_errfunc = errfunc;
	pglob->gl_matchc = 0;

	bufnext = patbuf;
	bufend = bufnext + MAXPATHLEN - 1;
	if (flags & GLOB_NOESCAPE) {
		memset(&mbs, 0, sizeof(mbs));
		while (bufend - bufnext >= MB_CUR_MAX) {
			clen = mbrtowc(&wc, patnext, MB_LEN_MAX, &mbs);
			if (clen == (size_t)-1 || clen == (size_t)-2)
				return (GLOB_NOMATCH);
			else if (clen == 0)
				break;
			*bufnext++ = wc;
			patnext += clen;
		}
	} else {
		
		memset(&mbs, 0, sizeof(mbs));
		while (bufend - bufnext >= MB_CUR_MAX) {
			if (*patnext == QUOTE) {
				if (*++patnext == EOS) {
					*bufnext++ = QUOTE | M_PROTECT;
					continue;
				}
				prot = M_PROTECT;
			} else prot = 0;
			clen = mbrtowc(&wc, patnext, MB_LEN_MAX, &mbs);
			if (clen == (size_t)-1 || clen == (size_t)-2)
				return (GLOB_NOMATCH);
			else if (clen == 0)
				break;
			*bufnext++ = wc | prot;
			patnext += clen;
		}
	}
	*bufnext = EOS;

	if (flags & GLOB_BRACE)
	    return (globexp1(patbuf, pglob, &limit));
	else return (glob0(patbuf, pglob, &limit));
}


static int globexp1(const Char *pattern, glob_t *pglob, size_t *limit)
{
	const Char* ptr = pattern;
	int rv;

	
	if (pattern[0] == LBRACE && pattern[1] == RBRACE && pattern[2] == EOS)
		return glob0(pattern, pglob, limit);

	while ((ptr = g_strchr(ptr, LBRACE)) != NULL)
		if (!globexp2(ptr, pattern, pglob, &rv, limit))
			return rv;

	return glob0(pattern, pglob, limit);
}



static int globexp2(const Char *ptr, const Char *pattern, glob_t *pglob, int *rv, size_t *limit)
{
	int     i;
	Char   *lm, *ls;
	const Char *pe, *pm, *pm1, *pl;
	Char    patbuf[MAXPATHLEN];

	
	for (lm = patbuf, pm = pattern; pm != ptr; *lm++ = *pm++)
		continue;
	*lm = EOS;
	ls = lm;

	
	for (i = 0, pe = ++ptr; *pe; pe++)
		if (*pe == LBRACKET) {
			
			for (pm = pe++; *pe != RBRACKET && *pe != EOS; pe++)
				continue;
			if (*pe == EOS) {
				
				pe = pm;
			}
		}
		else if (*pe == LBRACE)
			i++;
		else if (*pe == RBRACE) {
			if (i == 0)
				break;
			i--;
		}

	
	if (i != 0 || *pe == EOS) {
		*rv = glob0(patbuf, pglob, limit);
		return (0);
	}

	for (i = 0, pl = pm = ptr; pm <= pe; pm++)
		switch (*pm) {
		case LBRACKET:
			
			for (pm1 = pm++; *pm != RBRACKET && *pm != EOS; pm++)
				continue;
			if (*pm == EOS) {
				
				pm = pm1;
			}
			break;

		case LBRACE:
			i++;
			break;

		case RBRACE:
			if (i) {
			    i--;
			    break;
			}
			
		case COMMA:
			if (i && *pm == COMMA)
				break;
			else {
				
				for (lm = ls; (pl < pm); *lm++ = *pl++)
					continue;
				
				for (pl = pe + 1; (*lm++ = *pl++) != EOS;)
					continue;

				

				qprintf("globexp2:", patbuf);

				*rv = globexp1(patbuf, pglob, limit);

				
				pl = pm + 1;
			}
			break;

		default:
			break;
		}
	*rv = 0;
	return (0);
}




static const Char * globtilde(const Char *pattern, Char *patbuf, size_t patbuf_len, glob_t *pglob)
{
	struct passwd *pwd;
	char *h;
	const Char *p;
	Char *b, *eb;

	if (*pattern != TILDE || !(pglob->gl_flags & GLOB_TILDE))
		return (pattern);

	
	eb = &patbuf[patbuf_len - 1];
	for (p = pattern + 1, h = (char *) patbuf;
	    h < (char *)eb && *p && *p != SLASH; *h++ = *p++)
		continue;

	*h = EOS;

	if (((char *) patbuf)[0] == EOS) {
		
		if (issetugid() != 0 || (h = getenv("HOME")) == NULL) {
			if (((h = getlogin()) != NULL && (pwd = getpwnam(h)) != NULL) || (pwd = getpwuid(getuid())) != NULL)

				h = pwd->pw_dir;
			else return (pattern);
		}
	}
	else {
		
		if ((pwd = getpwnam((char*) patbuf)) == NULL)
			return (pattern);
		else h = pwd->pw_dir;
	}

	
	for (b = patbuf; b < eb && *h; *b++ = *h++)
		continue;

	
	while (b < eb && (*b++ = *p++) != EOS)
		continue;
	*b = EOS;

	return (patbuf);
}



static int glob0(const Char *pattern, glob_t *pglob, size_t *limit)
{
	const Char *qpatnext;
	int err;
	size_t oldpathc;
	Char *bufnext, c, patbuf[MAXPATHLEN];

	qpatnext = globtilde(pattern, patbuf, MAXPATHLEN, pglob);
	oldpathc = pglob->gl_pathc;
	bufnext = patbuf;

	
	while ((c = *qpatnext++) != EOS) {
		switch (c) {
		case LBRACKET:
			c = *qpatnext;
			if (c == NOT)
				++qpatnext;
			if (*qpatnext == EOS || g_strchr(qpatnext+1, RBRACKET) == NULL) {
				*bufnext++ = LBRACKET;
				if (c == NOT)
					--qpatnext;
				break;
			}
			*bufnext++ = M_SET;
			if (c == NOT)
				*bufnext++ = M_NOT;
			c = *qpatnext++;
			do {
				*bufnext++ = CHAR(c);
				if (*qpatnext == RANGE && (c = qpatnext[1]) != RBRACKET) {
					*bufnext++ = M_RNG;
					*bufnext++ = CHAR(c);
					qpatnext += 2;
				}
			} while ((c = *qpatnext++) != RBRACKET);
			pglob->gl_flags |= GLOB_MAGCHAR;
			*bufnext++ = M_END;
			break;
		case QUESTION:
			pglob->gl_flags |= GLOB_MAGCHAR;
			*bufnext++ = M_ONE;
			break;
		case STAR:
			pglob->gl_flags |= GLOB_MAGCHAR;
			
			if (bufnext == patbuf || bufnext[-1] != M_ALL)
			    *bufnext++ = M_ALL;
			break;
		default:
			*bufnext++ = CHAR(c);
			break;
		}
	}
	*bufnext = EOS;

	qprintf("glob0:", patbuf);


	if ((err = glob1(patbuf, pglob, limit)) != 0)
		return(err);

	
	if (pglob->gl_pathc == oldpathc) {
		if (((pglob->gl_flags & GLOB_NOCHECK) || ((pglob->gl_flags & GLOB_NOMAGIC) && !(pglob->gl_flags & GLOB_MAGCHAR))))

			return (globextend(pattern, pglob, limit));
		else return (GLOB_NOMATCH);
	}
	if (!(pglob->gl_flags & GLOB_NOSORT))
		qsort(pglob->gl_pathv + pglob->gl_offs + oldpathc, pglob->gl_pathc - oldpathc, sizeof(char *), compare);
	return (0);
}

static int compare(const void *p, const void *q)
{
	return (strcmp(*(char **)p, *(char **)q));
}

static int glob1(Char *pattern, glob_t *pglob, size_t *limit)
{
	Char pathbuf[MAXPATHLEN];

	
	if (*pattern == EOS)
		return (0);
	return (glob2(pathbuf, pathbuf, pathbuf + MAXPATHLEN - 1, pattern, pglob, limit));
}


static int glob2(Char *pathbuf, Char *pathend, Char *pathend_last, Char *pattern, glob_t *pglob, size_t *limit)

{
	struct stat sb;
	Char *p, *q;
	int anymeta;

	
	for (anymeta = 0;;) {
		if (*pattern == EOS) {		
			*pathend = EOS;
			if (g_lstat(pathbuf, &sb, pglob))
				return (0);

			if (((pglob->gl_flags & GLOB_MARK) && pathend[-1] != SEP) && (S_ISDIR(sb.st_mode)
			    || (S_ISLNK(sb.st_mode) && (g_stat(pathbuf, &sb, pglob) == 0) && S_ISDIR(sb.st_mode)))) {

				if (pathend + 1 > pathend_last)
					return (GLOB_ABORTED);
				*pathend++ = SEP;
				*pathend = EOS;
			}
			++pglob->gl_matchc;
			return (globextend(pathbuf, pglob, limit));
		}

		
		q = pathend;
		p = pattern;
		while (*p != EOS && *p != SEP) {
			if (ismeta(*p))
				anymeta = 1;
			if (q + 1 > pathend_last)
				return (GLOB_ABORTED);
			*q++ = *p++;
		}

		if (!anymeta) {		
			pathend = q;
			pattern = p;
			while (*pattern == SEP) {
				if (pathend + 1 > pathend_last)
					return (GLOB_ABORTED);
				*pathend++ = *pattern++;
			}
		} else			 return (glob3(pathbuf, pathend, pathend_last, pattern, p, pglob, limit));

	}
	
}

static int glob3(Char *pathbuf, Char *pathend, Char *pathend_last, Char *pattern, Char *restpattern, glob_t *pglob, size_t *limit)


{
	struct dirent *dp;
	DIR *dirp;
	int err;
	char buf[MAXPATHLEN];

	
	struct dirent *(*readdirfunc)();

	if (pathend > pathend_last)
		return (GLOB_ABORTED);
	*pathend = EOS;
	errno = 0;

	if ((dirp = g_opendir(pathbuf, pglob)) == NULL) {
		
		if (pglob->gl_errfunc) {
			if (g_Ctoc(pathbuf, buf, sizeof(buf)))
				return (GLOB_ABORTED);
			if (pglob->gl_errfunc(buf, errno) || pglob->gl_flags & GLOB_ERR)
				return (GLOB_ABORTED);
		}
		return (0);
	}

	err = 0;

	
	if (pglob->gl_flags & GLOB_ALTDIRFUNC)
		readdirfunc = pglob->gl_readdir;
	else readdirfunc = readdir;
	while ((dp = (*readdirfunc)(dirp))) {
		char *sc;
		Char *dc;
		wchar_t wc;
		size_t clen;
		mbstate_t mbs;

		
		if (dp->d_name[0] == DOT && *pattern != DOT)
			continue;
		memset(&mbs, 0, sizeof(mbs));
		dc = pathend;
		sc = dp->d_name;
		while (dc < pathend_last) {
			clen = mbrtowc(&wc, sc, MB_LEN_MAX, &mbs);
			if (clen == (size_t)-1 || clen == (size_t)-2) {
				wc = *sc;
				clen = 1;
				memset(&mbs, 0, sizeof(mbs));
			}
			if ((*dc++ = wc) == EOS)
				break;
			sc += clen;
		}
		if (!match(pathend, pattern, restpattern)) {
			*pathend = EOS;
			continue;
		}
		err = glob2(pathbuf, --dc, pathend_last, restpattern, pglob, limit);
		if (err)
			break;
	}

	if (pglob->gl_flags & GLOB_ALTDIRFUNC)
		(*pglob->gl_closedir)(dirp);
	else closedir(dirp);
	return (err);
}



static int globextend(const Char *path, glob_t *pglob, size_t *limit)
{
	char **pathv;
	size_t i, newsize, len;
	char *copy;
	const Char *p;

	if (*limit && pglob->gl_pathc > *limit) {
		errno = 0;
		return (GLOB_NOSPACE);
	}

	newsize = sizeof(*pathv) * (2 + pglob->gl_pathc + pglob->gl_offs);
	
	pathv = realloc((void *)pglob->gl_pathv, newsize);
	if (pathv == NULL)
		return (GLOB_NOSPACE);

	if (pglob->gl_pathv == NULL && pglob->gl_offs > 0) {
		
		pathv += pglob->gl_offs;
		for (i = pglob->gl_offs + 1; --i > 0; )
			*--pathv = NULL;
	}
	pglob->gl_pathv = pathv;

	for (p = path; *p++;)
		continue;
	len = MB_CUR_MAX * (size_t)(p - path);	
	if ((copy = malloc(len)) != NULL) {
		if (g_Ctoc(path, copy, len)) {
			free(copy);
			return (GLOB_NOSPACE);
		}
		pathv[pglob->gl_offs + pglob->gl_pathc++] = copy;
	}
	pathv[pglob->gl_offs + pglob->gl_pathc] = NULL;
	return (copy == NULL ? GLOB_NOSPACE : 0);
}


static int match(Char *name, Char *pat, Char *patend)
{
	int ok, negate_range;
	Char c, k;
	struct xlocale_collate *table = (struct xlocale_collate*)__get_locale()->components[XLC_COLLATE];

	while (pat < patend) {
		c = *pat++;
		switch (c & M_MASK) {
		case M_ALL:
			if (pat == patend)
				return (1);
			do if (match(name, pat, patend))
				    return (1);
			while (*name++ != EOS);
			return (0);
		case M_ONE:
			if (*name++ == EOS)
				return (0);
			break;
		case M_SET:
			ok = 0;
			if ((k = *name++) == EOS)
				return (0);
			if ((negate_range = ((*pat & M_MASK) == M_NOT)) != EOS)
				++pat;
			while (((c = *pat++) & M_MASK) != M_END)
				if ((*pat & M_MASK) == M_RNG) {
					if (table->__collate_load_error ? CHAR(c) <= CHAR(k) && CHAR(k) <= CHAR(pat[1]) :
					       __collate_range_cmp(table, CHAR(c), CHAR(k)) <= 0 && __collate_range_cmp(table, CHAR(k), CHAR(pat[1])) <= 0 )

						ok = 1;
					pat += 2;
				} else if (c == k)
					ok = 1;
			if (ok == negate_range)
				return (0);
			break;
		default:
			if (*name++ != c)
				return (0);
			break;
		}
	}
	return (*name == EOS);
}


void globfree(glob_t *pglob)
{
	size_t i;
	char **pp;

	if (pglob->gl_pathv != NULL) {
		pp = pglob->gl_pathv + pglob->gl_offs;
		for (i = pglob->gl_pathc; i--; ++pp)
			if (*pp)
				free(*pp);
		free(pglob->gl_pathv);
		pglob->gl_pathv = NULL;
	}
}

static DIR * g_opendir(Char *str, glob_t *pglob)
{
	char buf[MAXPATHLEN];

	if (!*str)
		strcpy(buf, ".");
	else {
		if (g_Ctoc(str, buf, sizeof(buf)))
			return (NULL);
	}

	if (pglob->gl_flags & GLOB_ALTDIRFUNC)
		return ((*pglob->gl_opendir)(buf));

	return (opendir(buf));
}

static int g_lstat(Char *fn, struct stat *sb, glob_t *pglob)
{
	char buf[MAXPATHLEN];

	if (g_Ctoc(fn, buf, sizeof(buf))) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	if (pglob->gl_flags & GLOB_ALTDIRFUNC)
		return((*pglob->gl_lstat)(buf, sb));
	return (lstat(buf, sb));
}

static int g_stat(Char *fn, struct stat *sb, glob_t *pglob)
{
	char buf[MAXPATHLEN];

	if (g_Ctoc(fn, buf, sizeof(buf))) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	if (pglob->gl_flags & GLOB_ALTDIRFUNC)
		return ((*pglob->gl_stat)(buf, sb));
	return (stat(buf, sb));
}

static const Char * g_strchr(const Char *str, wchar_t ch)
{

	do {
		if (*str == ch)
			return (str);
	} while (*str++);
	return (NULL);
}

static int g_Ctoc(const Char *str, char *buf, size_t len)
{
	mbstate_t mbs;
	size_t clen;

	memset(&mbs, 0, sizeof(mbs));
	while (len >= MB_CUR_MAX) {
		clen = wcrtomb(buf, *str, &mbs);
		if (clen == (size_t)-1)
			return (1);
		if (*str == L'\0')
			return (0);
		str++;
		buf += clen;
		len -= clen;
	}
	return (1);
}


static void qprintf(const char *str, Char *s)
{
	Char *p;

	(void)printf("%s:\n", str);
	for (p = s; *p; p++)
		(void)printf("%c", CHAR(*p));
	(void)printf("\n");
	for (p = s; *p; p++)
		(void)printf("%c", *p & M_PROTECT ? '"' : ' ');
	(void)printf("\n");
	for (p = s; *p; p++)
		(void)printf("%c", ismeta(*p) ? '_' : ' ');
	(void)printf("\n");
}

