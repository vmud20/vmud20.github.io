



















static sig_atomic_t dummy_timeout_flag = 0;
static volatile sig_atomic_t *timeout_flag = &dummy_timeout_flag;







    static int no_Magic(int x)
{
    if (is_Magic(x))
	return un_Magic(x);
    return x;
}

    static int toggle_Magic(int x)
{
    if (is_Magic(x))
	return un_Magic(x);
    return Magic(x);
}


    void init_regexp_timeout(long msec)
{
    timeout_flag = start_timeout(msec);
}

    void disable_regexp_timeout(void)
{
    stop_timeout();
    timeout_flag = &dummy_timeout_flag;
}


































    static int re_multi_type(int c)
{
    if (c == Magic('@') || c == Magic('=') || c == Magic('?'))
	return MULTI_ONE;
    if (c == Magic('*') || c == Magic('+') || c == Magic('{'))
	return MULTI_MULT;
    return NOT_MULTI;
}

static char_u		*reg_prev_sub = NULL;


static char_u REGEXP_INRANGE[] = "]^-n\\";
static char_u REGEXP_ABBR[] = "nrtebdoxuU";


    static int backslash_trans(int c)
{
    switch (c)
    {
	case 'r':   return CAR;
	case 't':   return TAB;
	case 'e':   return ESC;
	case 'b':   return BS;
    }
    return c;
}


    static int get_char_class(char_u **pp)
{
    static const char *(class_names[]) = {
	"alnum:]",  "alpha:]",  "blank:]",  "cntrl:]",  "digit:]",  "graph:]",  "lower:]",  "print:]",  "punct:]",  "space:]",  "upper:]",  "xdigit:]",  "tab:]",  "return:]",  "backspace:]",  "escape:]",  "ident:]",  "keyword:]",  "fname:]",  };






































    int i;

    if ((*pp)[1] == ':')
    {
	for (i = 0; i < (int)ARRAY_LENGTH(class_names); ++i)
	    if (STRNCMP(*pp + 2, class_names[i], STRLEN(class_names[i])) == 0)
	    {
		*pp += STRLEN(class_names[i]) + 2;
		return i;
	    }
    }
    return CLASS_NONE;
}


static short	class_tab[256];











    static void init_class_tab(void)
{
    int		i;
    static int	done = FALSE;

    if (done)
	return;

    for (i = 0; i < 256; ++i)
    {
	if (i >= '0' && i <= '7')
	    class_tab[i] = RI_DIGIT + RI_HEX + RI_OCTAL + RI_WORD;
	else if (i >= '8' && i <= '9')
	    class_tab[i] = RI_DIGIT + RI_HEX + RI_WORD;
	else if (i >= 'a' && i <= 'f')
	    class_tab[i] = RI_HEX + RI_WORD + RI_HEAD + RI_ALPHA + RI_LOWER;
	else if (i >= 'g' && i <= 'z')
	    class_tab[i] = RI_WORD + RI_HEAD + RI_ALPHA + RI_LOWER;
	else if (i >= 'A' && i <= 'F')
	    class_tab[i] = RI_HEX + RI_WORD + RI_HEAD + RI_ALPHA + RI_UPPER;
	else if (i >= 'G' && i <= 'Z')
	    class_tab[i] = RI_WORD + RI_HEAD + RI_ALPHA + RI_UPPER;
	else if (i == '_')
	    class_tab[i] = RI_WORD + RI_HEAD;
	else class_tab[i] = 0;
    }
    class_tab[' '] |= RI_WHITE;
    class_tab['\t'] |= RI_WHITE;
    done = TRUE;
}




















static char_u	*regparse;	
static int	regnpar;	
static int	wants_nfa;	

static int	regnzpar;	
static int	re_has_z;	

static unsigned	regflags;	

static int	had_eol;	


static magic_T	reg_magic;	

static int	reg_string;	
				
static int	reg_strict;	




static char_u META_flags[] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 0,  0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1,  1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1,  1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1,  0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1,  1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1 };














static int	curchr;		



static int	prevchr;
static int	prevprevchr;	
static int	nextchr;	







typedef struct {
     char_u	*regparse;
     int	prevchr_len;
     int	curchr;
     int	prevchr;
     int	prevprevchr;
     int	nextchr;
     int	at_start;
     int	prev_at_start;
     int	regnpar;
} parse_state_T;

static void	initchr(char_u *);
static int	getchr(void);
static void	skipchr_keepstart(void);
static int	peekchr(void);
static void	skipchr(void);
static void	ungetchr(void);
static long	gethexchrs(int maxinputlen);
static long	getoctchrs(void);
static long	getdecchrs(void);
static int	coll_get_char(void);
static int	prog_magic_wrong(void);
static int	cstrncmp(char_u *s1, char_u *s2, int *n);
static char_u	*cstrchr(char_u *, int);
static int	re_mult_next(char *what);
static int	reg_iswordc(int);

static void report_re_switch(char_u *pat);


static regengine_T bt_regengine;
static regengine_T nfa_regengine;


    int re_multiline(regprog_T *prog)
{
    return (prog->regflags & RF_HASNL);
}


    static int get_equi_class(char_u **pp)
{
    int		c;
    int		l = 1;
    char_u	*p = *pp;

    if (p[1] == '=' && p[2] != NUL)
    {
	if (has_mbyte)
	    l = (*mb_ptr2len)(p + 2);
	if (p[l + 2] == '=' && p[l + 3] == ']')
	{
	    if (has_mbyte)
		c = mb_ptr2char(p + 2);
	    else c = p[2];
	    *pp += l + 4;
	    return c;
	}
    }
    return 0;
}


    static int get_coll_element(char_u **pp)
{
    int		c;
    int		l = 1;
    char_u	*p = *pp;

    if (p[0] != NUL && p[1] == '.' && p[2] != NUL)
    {
	if (has_mbyte)
	    l = (*mb_ptr2len)(p + 2);
	if (p[l + 2] == '.' && p[l + 3] == ']')
	{
	    if (has_mbyte)
		c = mb_ptr2char(p + 2);
	    else c = p[2];
	    *pp += l + 4;
	    return c;
	}
    }
    return 0;
}

static int reg_cpo_lit; 
static int reg_cpo_bsl; 

    static void get_cpo_flags(void)
{
    reg_cpo_lit = vim_strchr(p_cpo, CPO_LITERAL) != NULL;
    reg_cpo_bsl = vim_strchr(p_cpo, CPO_BACKSL) != NULL;
}


    static char_u * skip_anyof(char_u *p)
{
    int		l;

    if (*p == '^')	
	++p;
    if (*p == ']' || *p == '-')
	++p;
    while (*p != NUL && *p != ']')
    {
	if (has_mbyte && (l = (*mb_ptr2len)(p)) > 1)
	    p += l;
	else if (*p == '-')
	    {
		++p;
		if (*p != ']' && *p != NUL)
		    MB_PTR_ADV(p);
	    }
	else if (*p == '\\' && !reg_cpo_bsl && (vim_strchr(REGEXP_INRANGE, p[1]) != NULL || (!reg_cpo_lit && vim_strchr(REGEXP_ABBR, p[1]) != NULL)))


	    p += 2;
	else if (*p == '[')
	{
	    if (get_char_class(&p) == CLASS_NONE && get_equi_class(&p) == 0 && get_coll_element(&p) == 0 && *p != NUL)


		++p; 
	}
	else ++p;
    }

    return p;
}


    char_u * skip_regexp( char_u	*startp, int		delim, int		magic)



{
    return skip_regexp_ex(startp, delim, magic, NULL, NULL, NULL);
}


    char_u * skip_regexp_err( char_u	*startp, int		delim, int		magic)



{
    char_u *p = skip_regexp(startp, delim, magic);

    if (*p != delim)
    {
	semsg(_(e_missing_delimiter_after_search_pattern_str), startp);
	return NULL;
    }
    return p;
}


    char_u * skip_regexp_ex( char_u	*startp, int		dirc, int		magic, char_u	**newp, int		*dropped, magic_T	*magic_val)






{
    magic_T	mymagic;
    char_u	*p = startp;

    if (magic)
	mymagic = MAGIC_ON;
    else mymagic = MAGIC_OFF;
    get_cpo_flags();

    for (; p[0] != NUL; MB_PTR_ADV(p))
    {
	if (p[0] == dirc)	
	    break;
	if ((p[0] == '[' && mymagic >= MAGIC_ON)
		|| (p[0] == '\\' && p[1] == '[' && mymagic <= MAGIC_OFF))
	{
	    p = skip_anyof(p + 1);
	    if (p[0] == NUL)
		break;
	}
	else if (p[0] == '\\' && p[1] != NUL)
	{
	    if (dirc == '?' && newp != NULL && p[1] == '?')
	    {
		
		if (*newp == NULL)
		{
		    *newp = vim_strsave(startp);
		    if (*newp != NULL)
			p = *newp + (p - startp);
		}
		if (dropped != NULL)
		    ++*dropped;
		if (*newp != NULL)
		    STRMOVE(p, p + 1);
		else ++p;
	    }
	    else ++p;
	    if (*p == 'v')
		mymagic = MAGIC_ALL;
	    else if (*p == 'V')
		mymagic = MAGIC_NONE;
	}
    }
    if (magic_val != NULL)
	*magic_val = mymagic;
    return p;
}


static int	prevchr_len;	
static int	at_start;	
static int	prev_at_start;  


    static void initchr(char_u *str)
{
    regparse = str;
    prevchr_len = 0;
    curchr = prevprevchr = prevchr = nextchr = -1;
    at_start = TRUE;
    prev_at_start = FALSE;
}


    static void save_parse_state(parse_state_T *ps)
{
    ps->regparse = regparse;
    ps->prevchr_len = prevchr_len;
    ps->curchr = curchr;
    ps->prevchr = prevchr;
    ps->prevprevchr = prevprevchr;
    ps->nextchr = nextchr;
    ps->at_start = at_start;
    ps->prev_at_start = prev_at_start;
    ps->regnpar = regnpar;
}


    static void restore_parse_state(parse_state_T *ps)
{
    regparse = ps->regparse;
    prevchr_len = ps->prevchr_len;
    curchr = ps->curchr;
    prevchr = ps->prevchr;
    prevprevchr = ps->prevprevchr;
    nextchr = ps->nextchr;
    at_start = ps->at_start;
    prev_at_start = ps->prev_at_start;
    regnpar = ps->regnpar;
}



    static int peekchr(void)
{
    static int	after_slash = FALSE;

    if (curchr == -1)
    {
	switch (curchr = regparse[0])
	{
	case '.':
	case '[':
	case '~':
	    
	    if (reg_magic >= MAGIC_ON)
		curchr = Magic(curchr);
	    break;
	case '(':
	case ')':
	case '{':
	case '%':
	case '+':
	case '=':
	case '?':
	case '@':
	case '!':
	case '&':
	case '|':
	case '<':
	case '>':
	case '#':	
	case '"':	
	case '\'':	
	case ',':	
	case '-':	
	case ':':	
	case ';':	
	case '`':	
	case '/':	
	    
	    if (reg_magic == MAGIC_ALL)
		curchr = Magic(curchr);
	    break;
	case '*':
	    
	    
	    
	    if (reg_magic >= MAGIC_ON && !at_start && !(prev_at_start && prevchr == Magic('^'))

		    && (after_slash || (prevchr != Magic('(')
			    && prevchr != Magic('&')
			    && prevchr != Magic('|'))))
		curchr = Magic('*');
	    break;
	case '^':
	    
	    
	    if (reg_magic >= MAGIC_OFF && (at_start || reg_magic == MAGIC_ALL || prevchr == Magic('(')


			|| prevchr == Magic('|')
			|| prevchr == Magic('&')
			|| prevchr == Magic('n')
			|| (no_Magic(prevchr) == '(' && prevprevchr == Magic('%'))))
	    {
		curchr = Magic('^');
		at_start = TRUE;
		prev_at_start = FALSE;
	    }
	    break;
	case '$':
	    
	    
	    if (reg_magic >= MAGIC_OFF)
	    {
		char_u *p = regparse + 1;
		int is_magic_all = (reg_magic == MAGIC_ALL);

		
		while (p[0] == '\\' && (p[1] == 'c' || p[1] == 'C' || p[1] == 'm' || p[1] == 'M' || p[1] == 'v' || p[1] == 'V' || p[1] == 'Z'))

		{
		    if (p[1] == 'v')
			is_magic_all = TRUE;
		    else if (p[1] == 'm' || p[1] == 'M' || p[1] == 'V')
			is_magic_all = FALSE;
		    p += 2;
		}
		if (p[0] == NUL || (p[0] == '\\' && (p[1] == '|' || p[1] == '&' || p[1] == ')' || p[1] == 'n'))


			|| (is_magic_all && (p[0] == '|' || p[0] == '&' || p[0] == ')'))
			|| reg_magic == MAGIC_ALL)
		    curchr = Magic('$');
	    }
	    break;
	case '\\':
	    {
		int c = regparse[1];

		if (c == NUL)
		    curchr = '\\';	
		else if (c <= '~' && META_flags[c])
		{
		    
		    curchr = -1;
		    prev_at_start = at_start;
		    at_start = FALSE;	
		    ++regparse;
		    ++after_slash;
		    peekchr();
		    --regparse;
		    --after_slash;
		    curchr = toggle_Magic(curchr);
		}
		else if (vim_strchr(REGEXP_ABBR, c))
		{
		    
		    curchr = backslash_trans(c);
		}
		else if (reg_magic == MAGIC_NONE && (c == '$' || c == '^'))
		    curchr = toggle_Magic(c);
		else {
		    
		    if (has_mbyte)
			curchr = (*mb_ptr2char)(regparse + 1);
		    else curchr = c;
		}
		break;
	    }

	default:
	    if (has_mbyte)
		curchr = (*mb_ptr2char)(regparse);
	}
    }

    return curchr;
}


    static void skipchr(void)
{
    
    if (*regparse == '\\')
	prevchr_len = 1;
    else prevchr_len = 0;
    if (regparse[prevchr_len] != NUL)
    {
	if (enc_utf8)
	    
	    prevchr_len += utf_ptr2len(regparse + prevchr_len);
	else if (has_mbyte)
	    prevchr_len += (*mb_ptr2len)(regparse + prevchr_len);
	else ++prevchr_len;
    }
    regparse += prevchr_len;
    prev_at_start = at_start;
    at_start = FALSE;
    prevprevchr = prevchr;
    prevchr = curchr;
    curchr = nextchr;	    
    nextchr = -1;
}


    static void skipchr_keepstart(void)
{
    int as = prev_at_start;
    int pr = prevchr;
    int prpr = prevprevchr;

    skipchr();
    at_start = as;
    prevchr = pr;
    prevprevchr = prpr;
}


    static int getchr(void)
{
    int chr = peekchr();

    skipchr();
    return chr;
}


    static void ungetchr(void)
{
    nextchr = curchr;
    curchr = prevchr;
    prevchr = prevprevchr;
    at_start = prev_at_start;
    prev_at_start = FALSE;

    
    
    regparse -= prevchr_len;
}


    static long gethexchrs(int maxinputlen)
{
    long_u	nr = 0;
    int		c;
    int		i;

    for (i = 0; i < maxinputlen; ++i)
    {
	c = regparse[0];
	if (!vim_isxdigit(c))
	    break;
	nr <<= 4;
	nr |= hex2nr(c);
	++regparse;
    }

    if (i == 0)
	return -1;
    return (long)nr;
}


    static long getdecchrs(void)
{
    long_u	nr = 0;
    int		c;
    int		i;

    for (i = 0; ; ++i)
    {
	c = regparse[0];
	if (c < '0' || c > '9')
	    break;
	nr *= 10;
	nr += c - '0';
	++regparse;
	curchr = -1; 
    }

    if (i == 0)
	return -1;
    return (long)nr;
}


    static long getoctchrs(void)
{
    long_u	nr = 0;
    int		c;
    int		i;

    for (i = 0; i < 3 && nr < 040; ++i)
    {
	c = regparse[0];
	if (c < '0' || c > '7')
	    break;
	nr <<= 3;
	nr |= hex2nr(c);
	++regparse;
    }

    if (i == 0)
	return -1;
    return (long)nr;
}


    static int read_limits(long *minval, long *maxval)
{
    int		reverse = FALSE;
    char_u	*first_char;
    long	tmp;

    if (*regparse == '-')
    {
	
	regparse++;
	reverse = TRUE;
    }
    first_char = regparse;
    *minval = getdigits(&regparse);
    if (*regparse == ',')	    
    {
	if (vim_isdigit(*++regparse))
	    *maxval = getdigits(&regparse);
	else *maxval = MAX_LIMIT;
    }
    else if (VIM_ISDIGIT(*first_char))
	*maxval = *minval;	    
    else *maxval = MAX_LIMIT;
    if (*regparse == '\\')
	regparse++;	
    if (*regparse != '}')
	EMSG2_RET_FAIL(_(e_syntax_error_in_str_curlies), reg_magic == MAGIC_ALL);

    
    if ((!reverse && *minval > *maxval) || (reverse && *minval < *maxval))
    {
	tmp = *minval;
	*minval = *maxval;
	*maxval = tmp;
    }
    skipchr();		
    return OK;
}





static void	cleanup_subexpr(void);

static void	cleanup_zsubexpr(void);

static void	reg_nextline(void);
static int	match_with_backref(linenr_T start_lnum, colnr_T start_col, linenr_T end_lnum, colnr_T end_col, int *bytelen);


static char_u	*reg_tofree = NULL;
static unsigned	reg_tofreelen;


typedef struct {
    regmatch_T		*reg_match;
    regmmatch_T		*reg_mmatch;
    char_u		**reg_startp;
    char_u		**reg_endp;
    lpos_T		*reg_startpos;
    lpos_T		*reg_endpos;
    win_T		*reg_win;
    buf_T		*reg_buf;
    linenr_T		reg_firstlnum;
    linenr_T		reg_maxline;
    int			reg_line_lbr;	

    
    linenr_T	lnum;		
    char_u	*line;		
    char_u	*input;		

    int	need_clear_subexpr;	

    int	need_clear_zsubexpr;	
				


    
    
    
    int			reg_ic;

    
    
    int			reg_icombine;

    
    
    colnr_T		reg_maxcol;

    
    int nfa_has_zend;	    
    int nfa_has_backref;    
    int nfa_nsubexpr;	    
			    
			    
    
    
    
    int nfa_listid;
    int nfa_alt_listid;


    int nfa_has_zsubexpr;   

} regexec_T;

static regexec_T	rex;
static int		rex_in_use = FALSE;


    static int reg_iswordc(int c)
{
    return vim_iswordc_buf(c, rex.reg_buf);
}


    static char_u * reg_getline(linenr_T lnum)
{
    
    
    if (rex.reg_firstlnum + lnum < 1)
	return NULL;
    if (lnum > rex.reg_maxline)
	
	return (char_u *)"";
    return ml_get_buf(rex.reg_buf, rex.reg_firstlnum + lnum, FALSE);
}


static char_u	*reg_startzp[NSUBEXP];	
static char_u	*reg_endzp[NSUBEXP];	
static lpos_T	reg_startzpos[NSUBEXP];	
static lpos_T	reg_endzpos[NSUBEXP];	







    static reg_extmatch_T * make_extmatch(void)
{
    reg_extmatch_T	*em;

    em = ALLOC_CLEAR_ONE(reg_extmatch_T);
    if (em != NULL)
	em->refcnt = 1;
    return em;
}


    reg_extmatch_T * ref_extmatch(reg_extmatch_T *em)
{
    if (em != NULL)
	em->refcnt++;
    return em;
}


    void unref_extmatch(reg_extmatch_T *em)
{
    int i;

    if (em != NULL && --em->refcnt <= 0)
    {
	for (i = 0; i < NSUBEXP; ++i)
	    vim_free(em->matches[i]);
	vim_free(em);
    }
}



    static int reg_prev_class(void)
{
    if (rex.input > rex.line)
	return mb_get_class_buf(rex.input - 1 - (*mb_head_off)(rex.line, rex.input - 1), rex.reg_buf);
    return -1;
}


    static int reg_match_visual(void)
{
    pos_T	top, bot;
    linenr_T    lnum;
    colnr_T	col;
    win_T	*wp = rex.reg_win == NULL ? curwin : rex.reg_win;
    int		mode;
    colnr_T	start, end;
    colnr_T	start2, end2;
    colnr_T	cols;
    colnr_T	curswant;

    
    if (rex.reg_buf != curbuf || VIsual.lnum == 0 || !REG_MULTI)
	return FALSE;

    if (VIsual_active)
    {
	if (LT_POS(VIsual, wp->w_cursor))
	{
	    top = VIsual;
	    bot = wp->w_cursor;
	}
	else {
	    top = wp->w_cursor;
	    bot = VIsual;
	}
	mode = VIsual_mode;
	curswant = wp->w_curswant;
    }
    else {
	if (LT_POS(curbuf->b_visual.vi_start, curbuf->b_visual.vi_end))
	{
	    top = curbuf->b_visual.vi_start;
	    bot = curbuf->b_visual.vi_end;
	}
	else {
	    top = curbuf->b_visual.vi_end;
	    bot = curbuf->b_visual.vi_start;
	}
	mode = curbuf->b_visual.vi_mode;
	curswant = curbuf->b_visual.vi_curswant;
    }
    lnum = rex.lnum + rex.reg_firstlnum;
    if (lnum < top.lnum || lnum > bot.lnum)
	return FALSE;

    col = (colnr_T)(rex.input - rex.line);
    if (mode == 'v')
    {
	if ((lnum == top.lnum && col < top.col)
		|| (lnum == bot.lnum && col >= bot.col + (*p_sel != 'e')))
	    return FALSE;
    }
    else if (mode == Ctrl_V)
    {
	getvvcol(wp, &top, &start, NULL, &end);
	getvvcol(wp, &bot, &start2, NULL, &end2);
	if (start2 < start)
	    start = start2;
	if (end2 > end)
	    end = end2;
	if (top.col == MAXCOL || bot.col == MAXCOL || curswant == MAXCOL)
	    end = MAXCOL;

	
	rex.line = reg_getline(rex.lnum);
	rex.input = rex.line + col;

	cols = win_linetabsize(wp, rex.line, col);
	if (cols < start || cols > end - (*p_sel == 'e'))
	    return FALSE;
    }
    return TRUE;
}


    static int prog_magic_wrong(void)
{
    regprog_T	*prog;

    prog = REG_MULTI ? rex.reg_mmatch->regprog : rex.reg_match->regprog;
    if (prog->engine == &nfa_regengine)
	
	return FALSE;

    if (UCHARAT(((bt_regprog_T *)prog)->program) != REGMAGIC)
    {
	emsg(_(e_corrupted_regexp_program));
	return TRUE;
    }
    return FALSE;
}


    static void cleanup_subexpr(void)
{
    if (rex.need_clear_subexpr)
    {
	if (REG_MULTI)
	{
	    
	    vim_memset(rex.reg_startpos, 0xff, sizeof(lpos_T) * NSUBEXP);
	    vim_memset(rex.reg_endpos, 0xff, sizeof(lpos_T) * NSUBEXP);
	}
	else {
	    vim_memset(rex.reg_startp, 0, sizeof(char_u *) * NSUBEXP);
	    vim_memset(rex.reg_endp, 0, sizeof(char_u *) * NSUBEXP);
	}
	rex.need_clear_subexpr = FALSE;
    }
}


    static void cleanup_zsubexpr(void)
{
    if (rex.need_clear_zsubexpr)
    {
	if (REG_MULTI)
	{
	    
	    vim_memset(reg_startzpos, 0xff, sizeof(lpos_T) * NSUBEXP);
	    vim_memset(reg_endzpos, 0xff, sizeof(lpos_T) * NSUBEXP);
	}
	else {
	    vim_memset(reg_startzp, 0, sizeof(char_u *) * NSUBEXP);
	    vim_memset(reg_endzp, 0, sizeof(char_u *) * NSUBEXP);
	}
	rex.need_clear_zsubexpr = FALSE;
    }
}



    static void reg_nextline(void)
{
    rex.line = reg_getline(++rex.lnum);
    rex.input = rex.line;
    fast_breakcheck();
}


    static int match_with_backref( linenr_T start_lnum, colnr_T  start_col, linenr_T end_lnum, colnr_T  end_col, int	     *bytelen)





{
    linenr_T	clnum = start_lnum;
    colnr_T	ccol = start_col;
    int		len;
    char_u	*p;

    if (bytelen != NULL)
	*bytelen = 0;
    for (;;)
    {
	
	
	if (rex.line != reg_tofree)
	{
	    len = (int)STRLEN(rex.line);
	    if (reg_tofree == NULL || len >= (int)reg_tofreelen)
	    {
		len += 50;	
		vim_free(reg_tofree);
		reg_tofree = alloc(len);
		if (reg_tofree == NULL)
		    return RA_FAIL; 
		reg_tofreelen = len;
	    }
	    STRCPY(reg_tofree, rex.line);
	    rex.input = reg_tofree + (rex.input - rex.line);
	    rex.line = reg_tofree;
	}

	
	p = reg_getline(clnum);
	if (clnum == end_lnum)
	    len = end_col - ccol;
	else len = (int)STRLEN(p + ccol);

	if (cstrncmp(p + ccol, rex.input, &len) != 0)
	    return RA_NOMATCH;  
	if (bytelen != NULL)
	    *bytelen += len;
	if (clnum == end_lnum)
	    break;		
	if (rex.lnum >= rex.reg_maxline)
	    return RA_NOMATCH;  

	
	reg_nextline();
	if (bytelen != NULL)
	    *bytelen = 0;
	++clnum;
	ccol = 0;
	if (got_int)
	    return RA_FAIL;
    }

    
    
    return RA_MATCH;
}


    static int re_mult_next(char *what)
{
    if (re_multi_type(peekchr()) == MULTI_MULT)
    {
       semsg(_(e_nfa_regexp_cannot_repeat_str), what);
       rc_did_emsg = TRUE;
       return FAIL;
    }
    return OK;
}

typedef struct {
    int a, b, c;
} decomp_T;



static decomp_T decomp_table[0xfb4f-0xfb20+1] = {
    {0x5e2,0,0},		 {0x5d0,0,0}, {0x5d3,0,0}, {0x5d4,0,0}, {0x5db,0,0}, {0x5dc,0,0}, {0x5dd,0,0}, {0x5e8,0,0}, {0x5ea,0,0}, {'+', 0, 0}, {0x5e9, 0x5c1, 0}, {0x5e9, 0x5c2, 0}, {0x5e9, 0x5c1, 0x5bc}, {0x5e9, 0x5c2, 0x5bc}, {0x5d0, 0x5b7, 0}, {0x5d0, 0x5b8, 0}, {0x5d0, 0x5b4, 0}, {0x5d1, 0x5bc, 0}, {0x5d2, 0x5bc, 0}, {0x5d3, 0x5bc, 0}, {0x5d4, 0x5bc, 0}, {0x5d5, 0x5bc, 0}, {0x5d6, 0x5bc, 0}, {0xfb37, 0, 0}, {0x5d8, 0x5bc, 0}, {0x5d9, 0x5bc, 0}, {0x5da, 0x5bc, 0}, {0x5db, 0x5bc, 0}, {0x5dc, 0x5bc, 0}, {0xfb3d, 0, 0}, {0x5de, 0x5bc, 0}, {0xfb3f, 0, 0}, {0x5e0, 0x5bc, 0}, {0x5e1, 0x5bc, 0}, {0xfb42, 0, 0}, {0x5e3, 0x5bc, 0}, {0x5e4, 0x5bc,0}, {0xfb45, 0, 0}, {0x5e6, 0x5bc, 0}, {0x5e7, 0x5bc, 0}, {0x5e8, 0x5bc, 0}, {0x5e9, 0x5bc, 0}, {0x5ea, 0x5bc, 0}, {0x5d5, 0x5b9, 0}, {0x5d1, 0x5bf, 0}, {0x5db, 0x5bf, 0}, {0x5e4, 0x5bf, 0}, {0x5d0, 0x5dc, 0}














































};

    static void mb_decompose(int c, int *c1, int *c2, int *c3)
{
    decomp_T d;

    if (c >= 0xfb20 && c <= 0xfb4f)
    {
	d = decomp_table[c - 0xfb20];
	*c1 = d.a;
	*c2 = d.b;
	*c3 = d.c;
    }
    else {
	*c1 = c;
	*c2 = *c3 = 0;
    }
}


    static int cstrncmp(char_u *s1, char_u *s2, int *n)
{
    int		result;

    if (!rex.reg_ic)
	result = STRNCMP(s1, s2, *n);
    else result = MB_STRNICMP(s1, s2, *n);

    
    if (result != 0 && enc_utf8 && rex.reg_icombine)
    {
	char_u	*str1, *str2;
	int	c1, c2, c11, c12;
	int	junk;

	
	
	str1 = s1;
	str2 = s2;
	c1 = c2 = 0;
	while ((int)(str1 - s1) < *n)
	{
	    c1 = mb_ptr2char_adv(&str1);
	    c2 = mb_ptr2char_adv(&str2);

	    
	    
	    if (c1 != c2 && (!rex.reg_ic || utf_fold(c1) != utf_fold(c2)))
	    {
		
		mb_decompose(c1, &c11, &junk, &junk);
		mb_decompose(c2, &c12, &junk, &junk);
		c1 = c11;
		c2 = c12;
		if (c11 != c12 && (!rex.reg_ic || utf_fold(c11) != utf_fold(c12)))
		    break;
	    }
	}
	result = c2 - c1;
	if (result == 0)
	    *n = (int)(str2 - s2);
    }

    return result;
}


    static char_u * cstrchr(char_u *s, int c)
{
    char_u	*p;
    int		cc;

    if (!rex.reg_ic || (!enc_utf8 && mb_char2len(c) > 1))
	return vim_strchr(s, c);

    
    
    
    if (enc_utf8 && c > 0x80)
	cc = utf_fold(c);
    else if (MB_ISUPPER(c))
	cc = MB_TOLOWER(c);
    else if (MB_ISLOWER(c))
	cc = MB_TOUPPER(c);
    else return vim_strchr(s, c);

    if (has_mbyte)
    {
	for (p = s; *p != NUL; p += (*mb_ptr2len)(p))
	{
	    if (enc_utf8 && c > 0x80)
	    {
		if (utf_fold(utf_ptr2char(p)) == cc)
		    return p;
	    }
	    else if (*p == c || *p == cc)
		return p;
	}
    }
    else  for (p = s; *p != NUL; ++p)

	    if (*p == c || *p == cc)
		return p;

    return NULL;
}






typedef void (*(*fptr_T)(int *, int));

static int vim_regsub_both(char_u *source, typval_T *expr, char_u *dest, int destlen, int flags);

    static fptr_T do_upper(int *d, int c)
{
    *d = MB_TOUPPER(c);

    return (fptr_T)NULL;
}

    static fptr_T do_Upper(int *d, int c)
{
    *d = MB_TOUPPER(c);

    return (fptr_T)do_Upper;
}

    static fptr_T do_lower(int *d, int c)
{
    *d = MB_TOLOWER(c);

    return (fptr_T)NULL;
}

    static fptr_T do_Lower(int *d, int c)
{
    *d = MB_TOLOWER(c);

    return (fptr_T)do_Lower;
}


    char_u * regtilde(char_u *source, int magic)
{
    char_u	*newsub = source;
    char_u	*tmpsub;
    char_u	*p;
    int		len;
    int		prevlen;

    for (p = newsub; *p; ++p)
    {
	if ((*p == '~' && magic) || (*p == '\\' && *(p + 1) == '~' && !magic))
	{
	    if (reg_prev_sub != NULL)
	    {
		
		prevlen = (int)STRLEN(reg_prev_sub);
		tmpsub = alloc(STRLEN(newsub) + prevlen);
		if (tmpsub != NULL)
		{
		    
		    len = (int)(p - newsub);	
		    mch_memmove(tmpsub, newsub, (size_t)len);
		    
		    mch_memmove(tmpsub + len, reg_prev_sub, (size_t)prevlen);
		    
		    if (!magic)
			++p;			
		    STRCPY(tmpsub + len + prevlen, p + 1);

		    if (newsub != source)	
			vim_free(newsub);
		    newsub = tmpsub;
		    p = newsub + len + prevlen;
		}
	    }
	    else if (magic)
		STRMOVE(p, p + 1);	
	    else STRMOVE(p, p + 2);
	    --p;
	}
	else {
	    if (*p == '\\' && p[1])		
		++p;
	    if (has_mbyte)
		p += (*mb_ptr2len)(p) - 1;
	}
    }

    vim_free(reg_prev_sub);
    if (newsub != source)	
	reg_prev_sub = newsub;
    else			 reg_prev_sub = vim_strsave(newsub);
    return newsub;
}


static int can_f_submatch = FALSE;	




typedef struct {
    regmatch_T	*sm_match;
    regmmatch_T	*sm_mmatch;
    linenr_T	sm_firstlnum;
    linenr_T	sm_maxline;
    int		sm_line_lbr;
} regsubmatch_T;

static regsubmatch_T rsm;  





    static int fill_submatch_list(int argc UNUSED, typval_T *argv, int argskip, int argcount)
{
    listitem_T	*li;
    int		i;
    char_u	*s;
    typval_T	*listarg = argv + argskip;

    if (argcount == argskip)
	
	return argskip;

    
    init_static_list((staticList10_T *)(listarg->vval.v_list));

    
    li = listarg->vval.v_list->lv_first;
    for (i = 0; i < 10; ++i)
    {
	s = rsm.sm_match->startp[i];
	if (s == NULL || rsm.sm_match->endp[i] == NULL)
	    s = NULL;
	else s = vim_strnsave(s, rsm.sm_match->endp[i] - s);
	li->li_tv.v_type = VAR_STRING;
	li->li_tv.vval.v_string = s;
	li = li->li_next;
    }
    return argskip + 1;
}

    static void clear_submatch_list(staticList10_T *sl)
{
    int i;

    for (i = 0; i < 10; ++i)
	vim_free(sl->sl_items[i].li_tv.vval.v_string);
}



    int vim_regsub( regmatch_T	*rmp, char_u	*source, typval_T	*expr, char_u	*dest, int		destlen, int		flags)






{
    int		result;
    regexec_T	rex_save;
    int		rex_in_use_save = rex_in_use;

    if (rex_in_use)
	
	rex_save = rex;
    rex_in_use = TRUE;

    rex.reg_match = rmp;
    rex.reg_mmatch = NULL;
    rex.reg_maxline = 0;
    rex.reg_buf = curbuf;
    rex.reg_line_lbr = TRUE;
    result = vim_regsub_both(source, expr, dest, destlen, flags);

    rex_in_use = rex_in_use_save;
    if (rex_in_use)
	rex = rex_save;

    return result;
}

    int vim_regsub_multi( regmmatch_T	*rmp, linenr_T	lnum, char_u	*source, char_u	*dest, int		destlen, int		flags)






{
    int		result;
    regexec_T	rex_save;
    int		rex_in_use_save = rex_in_use;

    if (rex_in_use)
	
	rex_save = rex;
    rex_in_use = TRUE;

    rex.reg_match = NULL;
    rex.reg_mmatch = rmp;
    rex.reg_buf = curbuf;	
    rex.reg_firstlnum = lnum;
    rex.reg_maxline = curbuf->b_ml.ml_line_count - lnum;
    rex.reg_line_lbr = FALSE;
    result = vim_regsub_both(source, NULL, dest, destlen, flags);

    rex_in_use = rex_in_use_save;
    if (rex_in_use)
	rex = rex_save;

    return result;
}




static char_u   *eval_result[MAX_REGSUB_NESTING] = {NULL, NULL, NULL, NULL};


    void free_resub_eval_result(void)
{
    int i;

    for (i = 0; i < MAX_REGSUB_NESTING; ++i)
	VIM_CLEAR(eval_result[i]);
}



    static int vim_regsub_both( char_u	*source, typval_T	*expr, char_u	*dest, int		destlen, int		flags)





{
    char_u	*src;
    char_u	*dst;
    char_u	*s;
    int		c;
    int		cc;
    int		no = -1;
    fptr_T	func_all = (fptr_T)NULL;
    fptr_T	func_one = (fptr_T)NULL;
    linenr_T	clnum = 0;	
    int		len = 0;	

    static int  nesting = 0;
    int		nested;

    int		copy = flags & REGSUB_COPY;

    
    if ((source == NULL && expr == NULL) || dest == NULL)
    {
	emsg(_(e_null_argument));
	return 0;
    }
    if (prog_magic_wrong())
	return 0;

    if (nesting == MAX_REGSUB_NESTING)
    {
	emsg(_(e_substitute_nesting_too_deep));
	return 0;
    }
    nested = nesting;

    src = source;
    dst = dest;

    
    if (expr != NULL || (source[0] == '\\' && source[1] == '='))
    {

	
	
	
	
	
	if (copy)
	{
	    if (eval_result[nested] != NULL)
	    {
		STRCPY(dest, eval_result[nested]);
		dst += STRLEN(eval_result[nested]);
		VIM_CLEAR(eval_result[nested]);
	    }
	}
	else {
	    int		    prev_can_f_submatch = can_f_submatch;
	    regsubmatch_T   rsm_save;

	    VIM_CLEAR(eval_result[nested]);

	    
	    
	    
	    if (can_f_submatch)
		rsm_save = rsm;
	    can_f_submatch = TRUE;
	    rsm.sm_match = rex.reg_match;
	    rsm.sm_mmatch = rex.reg_mmatch;
	    rsm.sm_firstlnum = rex.reg_firstlnum;
	    rsm.sm_maxline = rex.reg_maxline;
	    rsm.sm_line_lbr = rex.reg_line_lbr;

	    
	    
	    
	    ++nesting;

	    if (expr != NULL)
	    {
		typval_T	argv[2];
		char_u		buf[NUMBUFLEN];
		typval_T	rettv;
		staticList10_T	matchList;
		funcexe_T	funcexe;

		rettv.v_type = VAR_STRING;
		rettv.vval.v_string = NULL;
		argv[0].v_type = VAR_LIST;
		argv[0].vval.v_list = &matchList.sl_list;
		matchList.sl_list.lv_len = 0;
		CLEAR_FIELD(funcexe);
		funcexe.fe_argv_func = fill_submatch_list;
		funcexe.fe_evaluate = TRUE;
		if (expr->v_type == VAR_FUNC)
		{
		    s = expr->vval.v_string;
		    call_func(s, -1, &rettv, 1, argv, &funcexe);
		}
		else if (expr->v_type == VAR_PARTIAL)
		{
		    partial_T   *partial = expr->vval.v_partial;

		    s = partial_name(partial);
		    funcexe.fe_partial = partial;
		    call_func(s, -1, &rettv, 1, argv, &funcexe);
		}
		else if (expr->v_type == VAR_INSTR)
		{
		    exe_typval_instr(expr, &rettv);
		}
		if (matchList.sl_list.lv_len > 0)
		    
		    clear_submatch_list(&matchList);

		if (rettv.v_type == VAR_UNKNOWN)
		    
		    eval_result[nested] = NULL;
		else {
		    eval_result[nested] = tv_get_string_buf_chk(&rettv, buf);
		    if (eval_result[nested] != NULL)
			eval_result[nested] = vim_strsave(eval_result[nested]);
		}
		clear_tv(&rettv);
	    }
	    else if (substitute_instr != NULL)
		
		eval_result[nested] = exe_substitute_instr();
	    else eval_result[nested] = eval_to_string(source + 2, TRUE);
	    --nesting;

	    if (eval_result[nested] != NULL)
	    {
		int had_backslash = FALSE;

		for (s = eval_result[nested]; *s != NUL; MB_PTR_ADV(s))
		{
		    
		    
		    
		    if (*s == NL && !rsm.sm_line_lbr)
			*s = CAR;
		    else if (*s == '\\' && s[1] != NUL)
		    {
			++s;
			
			if (*s == NL && !rsm.sm_line_lbr)
			    *s = CAR;
			had_backslash = TRUE;
		    }
		}
		if (had_backslash && (flags & REGSUB_BACKSLASH))
		{
		    
		    s = vim_strsave_escaped(eval_result[nested], (char_u *)"\\");
		    if (s != NULL)
		    {
			vim_free(eval_result[nested]);
			eval_result[nested] = s;
		    }
		}

		dst += STRLEN(eval_result[nested]);
	    }

	    can_f_submatch = prev_can_f_submatch;
	    if (can_f_submatch)
		rsm = rsm_save;
	}

    }
    else while ((c = *src++) != NUL)
      {
	if (c == '&' && (flags & REGSUB_MAGIC))
	    no = 0;
	else if (c == '\\' && *src != NUL)
	{
	    if (*src == '&' && !(flags & REGSUB_MAGIC))
	    {
		++src;
		no = 0;
	    }
	    else if ('0' <= *src && *src <= '9')
	    {
		no = *src++ - '0';
	    }
	    else if (vim_strchr((char_u *)"uUlLeE", *src))
	    {
		switch (*src++)
		{
		case 'u':   func_one = (fptr_T)do_upper;
			    continue;
		case 'U':   func_all = (fptr_T)do_Upper;
			    continue;
		case 'l':   func_one = (fptr_T)do_lower;
			    continue;
		case 'L':   func_all = (fptr_T)do_Lower;
			    continue;
		case 'e':
		case 'E':   func_one = func_all = (fptr_T)NULL;
			    continue;
		}
	    }
	}
	if (no < 0)	      
	{
	    if (c == K_SPECIAL && src[0] != NUL && src[1] != NUL)
	    {
		
		if (copy)
		{
		    if (dst + 3 > dest + destlen)
		    {
			iemsg("vim_regsub_both(): not enough space");
			return 0;
		    }
		    *dst++ = c;
		    *dst++ = *src++;
		    *dst++ = *src++;
		}
		else {
		    dst += 3;
		    src += 2;
		}
		continue;
	    }

	    if (c == '\\' && *src != NUL)
	    {
		
		switch (*src)
		{
		    case 'r':	c = CAR;	++src;	break;
		    case 'n':	c = NL;		++src;	break;
		    case 't':	c = TAB;	++src;	break;
		 
		 
		    case 'b':	c = Ctrl_H;	++src;	break;

		    
		    
		    default:	if (flags & REGSUB_BACKSLASH)
				{
				    if (copy)
				    {
					if (dst + 1 > dest + destlen)
					{
					    iemsg("vim_regsub_both(): not enough space");
					    return 0;
					}
					*dst = '\\';
				    }
				    ++dst;
				}
				c = *src++;
		}
	    }
	    else if (has_mbyte)
		c = mb_ptr2char(src - 1);

	    
	    if (func_one != (fptr_T)NULL)
		
		func_one = (fptr_T)(func_one(&cc, c));
	    else if (func_all != (fptr_T)NULL)
		
		func_all = (fptr_T)(func_all(&cc, c));
	    else  cc = c;

	    if (has_mbyte)
	    {
		int totlen = mb_ptr2len(src - 1);
		int charlen = mb_char2len(cc);

		if (copy)
		{
		    if (dst + charlen > dest + destlen)
		    {
			iemsg("vim_regsub_both(): not enough space");
			return 0;
		    }
		    mb_char2bytes(cc, dst);
		}
		dst += charlen - 1;
		if (enc_utf8)
		{
		    int clen = utf_ptr2len(src - 1);

		    
		    
		    if (clen < totlen)
		    {
			if (copy)
			{
			    if (dst + totlen - clen > dest + destlen)
			    {
				iemsg("vim_regsub_both(): not enough space");
				return 0;
			    }
			    mch_memmove(dst + 1, src - 1 + clen, (size_t)(totlen - clen));
			}
			dst += totlen - clen;
		    }
		}
		src += totlen - 1;
	    }
	    else if (copy)
	    {
		if (dst + 1 > dest + destlen)
		{
		    iemsg("vim_regsub_both(): not enough space");
		    return 0;
		}
		*dst = cc;
	    }
	    dst++;
	}
	else {
	    if (REG_MULTI)
	    {
		clnum = rex.reg_mmatch->startpos[no].lnum;
		if (clnum < 0 || rex.reg_mmatch->endpos[no].lnum < 0)
		    s = NULL;
		else {
		    s = reg_getline(clnum) + rex.reg_mmatch->startpos[no].col;
		    if (rex.reg_mmatch->endpos[no].lnum == clnum)
			len = rex.reg_mmatch->endpos[no].col - rex.reg_mmatch->startpos[no].col;
		    else len = (int)STRLEN(s);
		}
	    }
	    else {
		s = rex.reg_match->startp[no];
		if (rex.reg_match->endp[no] == NULL)
		    s = NULL;
		else len = (int)(rex.reg_match->endp[no] - s);
	    }
	    if (s != NULL)
	    {
		for (;;)
		{
		    if (len == 0)
		    {
			if (REG_MULTI)
			{
			    if (rex.reg_mmatch->endpos[no].lnum == clnum)
				break;
			    if (copy)
			    {
				if (dst + 1 > dest + destlen)
				{
				    iemsg("vim_regsub_both(): not enough space");
				    return 0;
				}
				*dst = CAR;
			    }
			    ++dst;
			    s = reg_getline(++clnum);
			    if (rex.reg_mmatch->endpos[no].lnum == clnum)
				len = rex.reg_mmatch->endpos[no].col;
			    else len = (int)STRLEN(s);
			}
			else break;
		    }
		    else if (*s == NUL) 
		    {
			if (copy)
			    iemsg(_(e_damaged_match_string));
			goto exit;
		    }
		    else {
			if ((flags & REGSUB_BACKSLASH)
						  && (*s == CAR || *s == '\\'))
			{
			    
			    if (copy)
			    {
				if (dst + 2 > dest + destlen)
				{
				    iemsg("vim_regsub_both(): not enough space");
				    return 0;
				}
				dst[0] = '\\';
				dst[1] = *s;
			    }
			    dst += 2;
			}
			else {
			    if (has_mbyte)
				c = mb_ptr2char(s);
			    else c = *s;

			    if (func_one != (fptr_T)NULL)
				
				func_one = (fptr_T)(func_one(&cc, c));
			    else if (func_all != (fptr_T)NULL)
				
				func_all = (fptr_T)(func_all(&cc, c));
			    else  cc = c;

			    if (has_mbyte)
			    {
				int l;
				int charlen;

				
				
				if (enc_utf8)
				    l = utf_ptr2len(s) - 1;
				else l = mb_ptr2len(s) - 1;

				s += l;
				len -= l;
				charlen = mb_char2len(cc);
				if (copy)
				{
				    if (dst + charlen > dest + destlen)
				    {
					iemsg("vim_regsub_both(): not enough space");
					return 0;
				    }
				    mb_char2bytes(cc, dst);
				}
				dst += charlen - 1;
			    }
			    else if (copy)
			    {
				if (dst + 1 > dest + destlen)
				{
				    iemsg("vim_regsub_both(): not enough space");
				    return 0;
				}
				*dst = cc;
			    }
			    dst++;
			}

			++s;
			--len;
		    }
		}
	    }
	    no = -1;
	}
      }
    if (copy)
	*dst = NUL;

exit:
    return (int)((dst - dest) + 1);
}



    static char_u * reg_getline_submatch(linenr_T lnum)
{
    char_u *s;
    linenr_T save_first = rex.reg_firstlnum;
    linenr_T save_max = rex.reg_maxline;

    rex.reg_firstlnum = rsm.sm_firstlnum;
    rex.reg_maxline = rsm.sm_maxline;

    s = reg_getline(lnum);

    rex.reg_firstlnum = save_first;
    rex.reg_maxline = save_max;
    return s;
}


    char_u * reg_submatch(int no)
{
    char_u	*retval = NULL;
    char_u	*s;
    int		len;
    int		round;
    linenr_T	lnum;

    if (!can_f_submatch || no < 0)
	return NULL;

    if (rsm.sm_match == NULL)
    {
	
	for (round = 1; round <= 2; ++round)
	{
	    lnum = rsm.sm_mmatch->startpos[no].lnum;
	    if (lnum < 0 || rsm.sm_mmatch->endpos[no].lnum < 0)
		return NULL;

	    s = reg_getline_submatch(lnum);
	    if (s == NULL)  
		break;
	    s += rsm.sm_mmatch->startpos[no].col;
	    if (rsm.sm_mmatch->endpos[no].lnum == lnum)
	    {
		
		len = rsm.sm_mmatch->endpos[no].col - rsm.sm_mmatch->startpos[no].col;
		if (round == 2)
		    vim_strncpy(retval, s, len);
		++len;
	    }
	    else {
		
		
		len = (int)STRLEN(s);
		if (round == 2)
		{
		    STRCPY(retval, s);
		    retval[len] = '\n';
		}
		++len;
		++lnum;
		while (lnum < rsm.sm_mmatch->endpos[no].lnum)
		{
		    s = reg_getline_submatch(lnum++);
		    if (round == 2)
			STRCPY(retval + len, s);
		    len += (int)STRLEN(s);
		    if (round == 2)
			retval[len] = '\n';
		    ++len;
		}
		if (round == 2)
		    STRNCPY(retval + len, reg_getline_submatch(lnum), rsm.sm_mmatch->endpos[no].col);
		len += rsm.sm_mmatch->endpos[no].col;
		if (round == 2)
		    retval[len] = NUL;
		++len;
	    }

	    if (retval == NULL)
	    {
		retval = alloc(len);
		if (retval == NULL)
		    return NULL;
	    }
	}
    }
    else {
	s = rsm.sm_match->startp[no];
	if (s == NULL || rsm.sm_match->endp[no] == NULL)
	    retval = NULL;
	else retval = vim_strnsave(s, rsm.sm_match->endp[no] - s);
    }

    return retval;
}


    list_T * reg_submatch_list(int no)
{
    char_u	*s;
    linenr_T	slnum;
    linenr_T	elnum;
    colnr_T	scol;
    colnr_T	ecol;
    int		i;
    list_T	*list;
    int		error = FALSE;

    if (!can_f_submatch || no < 0)
	return NULL;

    if (rsm.sm_match == NULL)
    {
	slnum = rsm.sm_mmatch->startpos[no].lnum;
	elnum = rsm.sm_mmatch->endpos[no].lnum;
	if (slnum < 0 || elnum < 0)
	    return NULL;

	scol = rsm.sm_mmatch->startpos[no].col;
	ecol = rsm.sm_mmatch->endpos[no].col;

	list = list_alloc();
	if (list == NULL)
	    return NULL;

	s = reg_getline_submatch(slnum) + scol;
	if (slnum == elnum)
	{
	    if (list_append_string(list, s, ecol - scol) == FAIL)
		error = TRUE;
	}
	else {
	    if (list_append_string(list, s, -1) == FAIL)
		error = TRUE;
	    for (i = 1; i < elnum - slnum; i++)
	    {
		s = reg_getline_submatch(slnum + i);
		if (list_append_string(list, s, -1) == FAIL)
		    error = TRUE;
	    }
	    s = reg_getline_submatch(elnum);
	    if (list_append_string(list, s, ecol) == FAIL)
		error = TRUE;
	}
    }
    else {
	s = rsm.sm_match->startp[no];
	if (s == NULL || rsm.sm_match->endp[no] == NULL)
	    return NULL;
	list = list_alloc();
	if (list == NULL)
	    return NULL;
	if (list_append_string(list, s, (int)(rsm.sm_match->endp[no] - s)) == FAIL)
	    error = TRUE;
    }

    if (error)
    {
	list_free(list);
	return NULL;
    }
    ++list->lv_refcount;
    return list;
}



    static void init_regexec_multi( regmmatch_T	*rmp, win_T		*win, buf_T		*buf, linenr_T	lnum)




{
    rex.reg_match = NULL;
    rex.reg_mmatch = rmp;
    rex.reg_buf = buf;
    rex.reg_win = win;
    rex.reg_firstlnum = lnum;
    rex.reg_maxline = rex.reg_buf->b_ml.ml_line_count - lnum;
    rex.reg_line_lbr = FALSE;
    rex.reg_ic = rmp->rmm_ic;
    rex.reg_icombine = FALSE;
    rex.reg_maxcol = rmp->rmm_maxcol;
}



static regengine_T bt_regengine = {
    bt_regcomp, bt_regfree, bt_regexec_nl, bt_regexec_multi, };






static regengine_T nfa_regengine = {
    nfa_regcomp, nfa_regfree, nfa_regexec_nl, nfa_regexec_multi, };






static int regexp_engine = 0;


static char_u regname[][30] = {
		    "AUTOMATIC Regexp Engine", "BACKTRACKING Regexp Engine", "NFA Regexp Engine" };





    regprog_T * vim_regcomp(char_u *expr_arg, int re_flags)
{
    regprog_T   *prog = NULL;
    char_u	*expr = expr_arg;
    int		called_emsg_before;

    regexp_engine = p_re;

    
    if (STRNCMP(expr, "\\%#=", 4) == 0)
    {
	int newengine = expr[4] - '0';

	if (newengine == AUTOMATIC_ENGINE || newengine == BACKTRACKING_ENGINE || newengine == NFA_ENGINE)

	{
	    regexp_engine = expr[4] - '0';
	    expr += 5;

	    smsg("New regexp mode selected (%d): %s", regexp_engine, regname[newengine]);

	}
	else {
	    emsg(_(e_percent_hash_can_only_be_followed_by_zero_one_two_automatic_engine_will_be_used));
	    regexp_engine = AUTOMATIC_ENGINE;
	}
    }

    bt_regengine.expr = expr;
    nfa_regengine.expr = expr;

    
    rex.reg_buf = curbuf;

    
    called_emsg_before = called_emsg;
    if (regexp_engine != BACKTRACKING_ENGINE)
	prog = nfa_regengine.regcomp(expr, re_flags + (regexp_engine == AUTOMATIC_ENGINE ? RE_AUTO : 0));
    else prog = bt_regengine.regcomp(expr, re_flags);

    
    if (prog == NULL)
    {

	if (regexp_engine == BACKTRACKING_ENGINE)   
	{
	    FILE *f;
	    f = fopen(BT_REGEXP_DEBUG_LOG_NAME, "a");
	    if (f)
	    {
		fprintf(f, "Syntax error in \"%s\"\n", expr);
		fclose(f);
	    }
	    else semsg("(NFA) Could not open \"%s\" to write !!!", BT_REGEXP_DEBUG_LOG_NAME);

	}

	
	if (regexp_engine == AUTOMATIC_ENGINE && called_emsg == called_emsg_before)
	{
	    regexp_engine = BACKTRACKING_ENGINE;

	    report_re_switch(expr);

	    prog = bt_regengine.regcomp(expr, re_flags);
	}
    }

    if (prog != NULL)
    {
	
	
	prog->re_engine = regexp_engine;
	prog->re_flags  = re_flags;
    }

    return prog;
}


    void vim_regfree(regprog_T *prog)
{
    if (prog != NULL)
	prog->engine->regfree(prog);
}


    void free_regexp_stuff(void)
{
    ga_clear(&regstack);
    ga_clear(&backpos);
    vim_free(reg_tofree);
    vim_free(reg_prev_sub);
}



    static void report_re_switch(char_u *pat)
{
    if (p_verbose > 0)
    {
	verbose_enter();
	msg_puts(_("Switching to backtracking RE engine for pattern: "));
	msg_puts((char *)pat);
	verbose_leave();
    }
}




    int regprog_in_use(regprog_T *prog)
{
    return prog->re_in_use;
}



    static int vim_regexec_string( regmatch_T	*rmp, char_u	*line, colnr_T	col, int		nl)




{
    int		result;
    regexec_T	rex_save;
    int		rex_in_use_save = rex_in_use;

    
    if (rmp->regprog->re_in_use)
    {
	emsg(_(e_cannot_use_pattern_recursively));
	return FALSE;
    }
    rmp->regprog->re_in_use = TRUE;

    if (rex_in_use)
	
	rex_save = rex;
    rex_in_use = TRUE;

    rex.reg_startp = NULL;
    rex.reg_endp = NULL;
    rex.reg_startpos = NULL;
    rex.reg_endpos = NULL;

    result = rmp->regprog->engine->regexec_nl(rmp, line, col, nl);
    rmp->regprog->re_in_use = FALSE;

    
    if (rmp->regprog->re_engine == AUTOMATIC_ENGINE && result == NFA_TOO_EXPENSIVE)
    {
	int    save_p_re = p_re;
	int    re_flags = rmp->regprog->re_flags;
	char_u *pat = vim_strsave(((nfa_regprog_T *)rmp->regprog)->pattern);

	p_re = BACKTRACKING_ENGINE;
	vim_regfree(rmp->regprog);
	if (pat != NULL)
	{

	    report_re_switch(pat);

	    rmp->regprog = vim_regcomp(pat, re_flags);
	    if (rmp->regprog != NULL)
	    {
		rmp->regprog->re_in_use = TRUE;
		result = rmp->regprog->engine->regexec_nl(rmp, line, col, nl);
		rmp->regprog->re_in_use = FALSE;
	    }
	    vim_free(pat);
	}

	p_re = save_p_re;
    }

    rex_in_use = rex_in_use_save;
    if (rex_in_use)
	rex = rex_save;

    return result > 0;
}


    int vim_regexec_prog( regprog_T	**prog, int		ignore_case, char_u	*line, colnr_T	col)




{
    int		r;
    regmatch_T	regmatch;

    regmatch.regprog = *prog;
    regmatch.rm_ic = ignore_case;
    r = vim_regexec_string(&regmatch, line, col, FALSE);
    *prog = regmatch.regprog;
    return r;
}


    int vim_regexec(regmatch_T *rmp, char_u *line, colnr_T col)
{
    return vim_regexec_string(rmp, line, col, FALSE);
}


    int vim_regexec_nl(regmatch_T *rmp, char_u *line, colnr_T col)
{
    return vim_regexec_string(rmp, line, col, TRUE);
}


    long vim_regexec_multi( regmmatch_T *rmp, win_T       *win, buf_T       *buf, linenr_T	lnum, colnr_T	col, int		*timed_out)






{
    int		result;
    regexec_T	rex_save;
    int		rex_in_use_save = rex_in_use;

    
    if (rmp->regprog->re_in_use)
    {
	emsg(_(e_cannot_use_pattern_recursively));
	return FALSE;
    }
    rmp->regprog->re_in_use = TRUE;

    if (rex_in_use)
	
	rex_save = rex;
    rex_in_use = TRUE;

    result = rmp->regprog->engine->regexec_multi( rmp, win, buf, lnum, col, timed_out);
    rmp->regprog->re_in_use = FALSE;

    
    if (rmp->regprog->re_engine == AUTOMATIC_ENGINE && result == NFA_TOO_EXPENSIVE)
    {
	int    save_p_re = p_re;
	int    re_flags = rmp->regprog->re_flags;
	char_u *pat = vim_strsave(((nfa_regprog_T *)rmp->regprog)->pattern);

	p_re = BACKTRACKING_ENGINE;
	if (pat != NULL)
	{
	    regprog_T *prev_prog = rmp->regprog;


	    report_re_switch(pat);


	    
	    
	    reg_do_extmatch = REX_ALL;

	    rmp->regprog = vim_regcomp(pat, re_flags);

	    reg_do_extmatch = 0;

	    if (rmp->regprog == NULL)
	    {
		
		
		rmp->regprog = prev_prog;
	    }
	    else {
		vim_regfree(prev_prog);

		rmp->regprog->re_in_use = TRUE;
		result = rmp->regprog->engine->regexec_multi( rmp, win, buf, lnum, col, timed_out);
		rmp->regprog->re_in_use = FALSE;
	    }
	    vim_free(pat);
	}
	p_re = save_p_re;
    }

    rex_in_use = rex_in_use_save;
    if (rex_in_use)
	rex = rex_save;

    return result <= 0 ? 0 : result;
}
