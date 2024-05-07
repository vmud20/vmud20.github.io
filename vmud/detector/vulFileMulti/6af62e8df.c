







struct dir_stack_T {
    struct dir_stack_T	*next;
    char_u		*dirname;
};


typedef struct qfline_S qfline_T;
struct qfline_S {
    qfline_T	*qf_next;	
    qfline_T	*qf_prev;	
    linenr_T	qf_lnum;	
    linenr_T	qf_end_lnum;	
    int		qf_fnum;	
    int		qf_col;		
    int		qf_end_col;	
    int		qf_nr;		
    char_u	*qf_module;	
    char_u	*qf_pattern;	
    char_u	*qf_text;	
    char_u	qf_viscol;	
				
    char_u	qf_cleared;	
    char_u	qf_type;	
				
    char_u	qf_valid;	
};







typedef enum {
    QFLT_QUICKFIX,  QFLT_LOCATION, QFLT_INTERNAL } qfltype_T;




typedef struct qf_list_S {
    int_u	qf_id;		
    qfltype_T	qfl_type;
    qfline_T	*qf_start;	
    qfline_T	*qf_last;	
    qfline_T	*qf_ptr;	
    int		qf_count;	
    int		qf_index;	
    int		qf_nonevalid;	
    char_u	*qf_title;	
				
    typval_T	*qf_ctx;	
    callback_T  qf_qftf_cb;	

    struct dir_stack_T	*qf_dir_stack;
    char_u		*qf_directory;
    struct dir_stack_T	*qf_file_stack;
    char_u		*qf_currfile;
    int			qf_multiline;
    int			qf_multiignore;
    int			qf_multiscan;
    long		qf_changedtick;
} qf_list_T;


struct qf_info_S {
    
    
    
    
    int		qf_refcount;
    int		qf_listcount;	    
    int		qf_curlist;	    
    qf_list_T	qf_lists[LISTCOUNT];
    qfltype_T	qfl_type;	    
    int		qf_bufnr;	    
};

static qf_info_T ql_info;	
static int_u last_qf_id = 0;	




typedef struct efm_S efm_T;
struct efm_S {
    regprog_T	    *prog;	
    efm_T	    *next;	
    char_u	    addr[FMT_PATTERNS]; 
    char_u	    prefix;	
				
				
				
				
				
				
				
				
				
				
				
				
				
    char_u	    flags;	
				
				
    int		    conthere;	
};



typedef struct qf_delq_S {
    struct qf_delq_S	*next;
    qf_info_T		*qi;
} qf_delq_T;
static qf_delq_T *qf_delq_head = NULL;



static int	quickfix_busy = 0;

static efm_T	*fmt_start = NULL; 


static callback_T qftf_cb;

static void	qf_new_list(qf_info_T *qi, char_u *qf_title);
static int	qf_add_entry(qf_list_T *qfl, char_u *dir, char_u *fname, char_u *module, int bufnum, char_u *mesg, long lnum, long end_lnum, int col, int end_col, int vis_col, char_u *pattern, int nr, int type, int valid);
static void	qf_free(qf_list_T *qfl);
static char_u	*qf_types(int, int);
static int	qf_get_fnum(qf_list_T *qfl, char_u *, char_u *);
static char_u	*qf_push_dir(char_u *, struct dir_stack_T **, int is_file_stack);
static char_u	*qf_pop_dir(struct dir_stack_T **);
static char_u	*qf_guess_filepath(qf_list_T *qfl, char_u *);
static void	qf_jump_newwin(qf_info_T *qi, int dir, int errornr, int forceit, int newwin);
static void	qf_fmt_text(char_u *text, char_u *buf, int bufsize);
static void	qf_range_text(qfline_T *qfp, char_u *buf, int bufsize);
static int	qf_win_pos_update(qf_info_T *qi, int old_qf_index);
static win_T	*qf_find_win(qf_info_T *qi);
static buf_T	*qf_find_buf(qf_info_T *qi);
static void	qf_update_buffer(qf_info_T *qi, qfline_T *old_last);
static void	qf_fill_buffer(qf_list_T *qfl, buf_T *buf, qfline_T *old_last, int qf_winid);
static buf_T	*load_dummy_buffer(char_u *fname, char_u *dirname_start, char_u *resulting_dir);
static void	wipe_dummy_buffer(buf_T *buf, char_u *dirname_start);
static void	unload_dummy_buffer(buf_T *buf, char_u *dirname_start);
static qf_info_T *ll_get_or_alloc_list(win_T *);






















static char_u   *qf_last_bufname = NULL;
static bufref_T  qf_last_bufref = {NULL, 0, 0};





static struct fmtpattern {
    char_u	convchar;
    char	*pattern;
} fmt_pat[FMT_PATTERNS] = {
	{'f', ".\\+",	     {'n', "\\d\\+", {'l', "\\d\\+", {'e', "\\d\\+", {'c', "\\d\\+", {'k', "\\d\\+", {'t', ".",  {'m', ".\\+",  {'r', ".*", {'p', "[- 	.]*", {'v', "\\d\\+", {'s', ".\\+", {'o', ".\\+" };
















    static char_u * efmpat_to_regpat( char_u	*efmpat, char_u	*regpat, efm_T	*efminfo, int	idx, int	round)





{
    char_u	*srcptr;

    if (efminfo->addr[idx])
    {
	
	semsg(_(e_too_many_chr_in_format_string), *efmpat);
	return NULL;
    }
    if ((idx && idx < FMT_PATTERN_R && vim_strchr((char_u *)"DXOPQ", efminfo->prefix) != NULL)
	    || (idx == FMT_PATTERN_R && vim_strchr((char_u *)"OPQ", efminfo->prefix) == NULL))
    {
	semsg(_(e_unexpected_chr_in_format_str), *efmpat);
	return NULL;
    }
    efminfo->addr[idx] = (char_u)++round;
    *regpat++ = '\\';
    *regpat++ = '(';

    if (*efmpat == 'f')
    {
	
	
	
	STRCPY(regpat, "\\%(\\a:\\)\\=");
	regpat += 10;
    }

    if (*efmpat == 'f' && efmpat[1] != NUL)
    {
	if (efmpat[1] != '\\' && efmpat[1] != '%')
	{
	    
	    
	    
	    
	    
	    STRCPY(regpat, ".\\{-1,}");
	    regpat += 7;
	}
	else {
	    
	    
	    STRCPY(regpat, "\\f\\+");
	    regpat += 4;
	}
    }
    else {
	srcptr = (char_u *)fmt_pat[idx].pattern;
	while ((*regpat = *srcptr++) != NUL)
	    ++regpat;
    }
    *regpat++ = '\\';
    *regpat++ = ')';

    return regpat;
}


    static char_u * scanf_fmt_to_regpat( char_u	**pefmp, char_u	*efm, int	len, char_u	*regpat)




{
    char_u	*efmp = *pefmp;

    if (*efmp == '[' || *efmp == '\\')
    {
	if ((*regpat++ = *efmp) == '[')	
	{
	    if (efmp[1] == '^')
		*regpat++ = *++efmp;
	    if (efmp < efm + len)
	    {
		*regpat++ = *++efmp;	    
		while (efmp < efm + len && (*regpat++ = *++efmp) != ']')
		    
		if (efmp == efm + len)
		{
		    emsg(_(e_missing_rsb_in_format_string));
		    return NULL;
		}
	    }
	}
	else if (efmp < efm + len)	
	    *regpat++ = *++efmp;
	*regpat++ = '\\';
	*regpat++ = '+';
    }
    else {
	
	semsg(_(e_unsupported_chr_in_format_string), *efmp);
	return NULL;
    }

    *pefmp = efmp;

    return regpat;
}


    static char_u * efm_analyze_prefix(char_u *efmp, efm_T *efminfo)
{
    if (vim_strchr((char_u *)"+-", *efmp) != NULL)
	efminfo->flags = *efmp++;
    if (vim_strchr((char_u *)"DXAEWINCZGOPQ", *efmp) != NULL)
	efminfo->prefix = *efmp;
    else {
	semsg(_(e_invalid_chr_in_format_string_prefix), *efmp);
	return NULL;
    }

    return efmp;
}


    static int efm_to_regpat( char_u	*efm, int	len, efm_T	*fmt_ptr, char_u	*regpat)




{
    char_u	*ptr;
    char_u	*efmp;
    int		round;
    int		idx = 0;

    
    ptr = regpat;
    *ptr++ = '^';
    round = 0;
    for (efmp = efm; efmp < efm + len; ++efmp)
    {
	if (*efmp == '%')
	{
	    ++efmp;
	    for (idx = 0; idx < FMT_PATTERNS; ++idx)
		if (fmt_pat[idx].convchar == *efmp)
		    break;
	    if (idx < FMT_PATTERNS)
	    {
		ptr = efmpat_to_regpat(efmp, ptr, fmt_ptr, idx, round);
		if (ptr == NULL)
		    return FAIL;
		round++;
	    }
	    else if (*efmp == '*')
	    {
		++efmp;
		ptr = scanf_fmt_to_regpat(&efmp, efm, len, ptr);
		if (ptr == NULL)
		    return FAIL;
	    }
	    else if (vim_strchr((char_u *)"%\\.^$~[", *efmp) != NULL)
		*ptr++ = *efmp;		
	    else if (*efmp == '#')
		*ptr++ = '*';
	    else if (*efmp == '>')
		fmt_ptr->conthere = TRUE;
	    else if (efmp == efm + 1)		
	    {
		
		
		efmp = efm_analyze_prefix(efmp, fmt_ptr);
		if (efmp == NULL)
		    return FAIL;
	    }
	    else {
		semsg(_(e_invalid_chr_in_format_string), *efmp);
		return FAIL;
	    }
	}
	else			 {
	    if (*efmp == '\\' && efmp + 1 < efm + len)
		++efmp;
	    else if (vim_strchr((char_u *)".*^$~[", *efmp) != NULL)
		*ptr++ = '\\';	
	    if (*efmp)
		*ptr++ = *efmp;
	}
    }
    *ptr++ = '$';
    *ptr = NUL;

    return OK;
}


    static void free_efm_list(efm_T **efm_first)
{
    efm_T *efm_ptr;

    for (efm_ptr = *efm_first; efm_ptr != NULL; efm_ptr = *efm_first)
    {
	*efm_first = efm_ptr->next;
	vim_regfree(efm_ptr->prog);
	vim_free(efm_ptr);
    }
    fmt_start = NULL;
}


    static int efm_regpat_bufsz(char_u *efm)
{
    int sz;
    int i;

    sz = (FMT_PATTERNS * 3) + ((int)STRLEN(efm) << 2);
    for (i = FMT_PATTERNS; i > 0; )
	sz += (int)STRLEN(fmt_pat[--i].pattern);

    sz += 12; 

    sz += 2; 


    return sz;
}


    static int efm_option_part_len(char_u *efm)
{
    int len;

    for (len = 0; efm[len] != NUL && efm[len] != ','; ++len)
	if (efm[len] == '\\' && efm[len + 1] != NUL)
	    ++len;

    return len;
}


    static efm_T * parse_efm_option(char_u *efm)
{
    efm_T	*fmt_ptr = NULL;
    efm_T	*fmt_first = NULL;
    efm_T	*fmt_last = NULL;
    char_u	*fmtstr = NULL;
    int		len;
    int		sz;

    
    

    
    sz = efm_regpat_bufsz(efm);
    if ((fmtstr = alloc_id(sz, aid_qf_efm_fmtstr)) == NULL)
	goto parse_efm_error;

    while (efm[0] != NUL)
    {
	
	fmt_ptr = ALLOC_CLEAR_ONE_ID(efm_T, aid_qf_efm_fmtpart);
	if (fmt_ptr == NULL)
	    goto parse_efm_error;
	if (fmt_first == NULL)	    
	    fmt_first = fmt_ptr;
	else fmt_last->next = fmt_ptr;
	fmt_last = fmt_ptr;

	
	len = efm_option_part_len(efm);

	if (efm_to_regpat(efm, len, fmt_ptr, fmtstr) == FAIL)
	    goto parse_efm_error;
	if ((fmt_ptr->prog = vim_regcomp(fmtstr, RE_MAGIC + RE_STRING)) == NULL)
	    goto parse_efm_error;
	
	efm = skip_to_option_part(efm + len);	
    }

    if (fmt_first == NULL)	
	emsg(_(e_errorformat_contains_no_pattern));

    goto parse_efm_end;

parse_efm_error:
    free_efm_list(&fmt_first);

parse_efm_end:
    vim_free(fmtstr);

    return fmt_first;
}

enum {
    QF_FAIL = 0, QF_OK = 1, QF_END_OF_INPUT = 2, QF_NOMEM = 3, QF_IGNORE_LINE = 4, QF_MULTISCAN = 5, };







typedef struct {
    char_u	*linebuf;
    int		linelen;
    char_u	*growbuf;
    int		growbufsiz;
    FILE	*fd;
    typval_T	*tv;
    char_u	*p_str;
    listitem_T	*p_li;
    buf_T	*buf;
    linenr_T	buflnum;
    linenr_T	lnumlast;
    vimconv_T	vc;
} qfstate_T;


    static char_u * qf_grow_linebuf(qfstate_T *state, int newsz)
{
    char_u	*p;

    
    
    state->linelen = newsz > LINE_MAXLEN ? LINE_MAXLEN - 1 : newsz;
    if (state->growbuf == NULL)
    {
	state->growbuf = alloc_id(state->linelen + 1, aid_qf_linebuf);
	if (state->growbuf == NULL)
	    return NULL;
	state->growbufsiz = state->linelen;
    }
    else if (state->linelen > state->growbufsiz)
    {
	if ((p = vim_realloc(state->growbuf, state->linelen + 1)) == NULL)
	    return NULL;
	state->growbuf = p;
	state->growbufsiz = state->linelen;
    }
    return state->growbuf;
}


    static int qf_get_next_str_line(qfstate_T *state)
{
    
    char_u	*p_str = state->p_str;
    char_u	*p;
    int		len;

    if (*p_str == NUL) 
	return QF_END_OF_INPUT;

    p = vim_strchr(p_str, '\n');
    if (p != NULL)
	len = (int)(p - p_str) + 1;
    else len = (int)STRLEN(p_str);

    if (len > IOSIZE - 2)
    {
	state->linebuf = qf_grow_linebuf(state, len);
	if (state->linebuf == NULL)
	    return QF_NOMEM;
    }
    else {
	state->linebuf = IObuff;
	state->linelen = len;
    }
    vim_strncpy(state->linebuf, p_str, state->linelen);

    
    
    p_str += len;
    state->p_str = p_str;

    return QF_OK;
}


    static int qf_get_next_list_line(qfstate_T *state)
{
    listitem_T	*p_li = state->p_li;
    int		len;

    while (p_li != NULL && (p_li->li_tv.v_type != VAR_STRING || p_li->li_tv.vval.v_string == NULL))

	p_li = p_li->li_next;	

    if (p_li == NULL)		
    {
	state->p_li = NULL;
	return QF_END_OF_INPUT;
    }

    len = (int)STRLEN(p_li->li_tv.vval.v_string);
    if (len > IOSIZE - 2)
    {
	state->linebuf = qf_grow_linebuf(state, len);
	if (state->linebuf == NULL)
	    return QF_NOMEM;
    }
    else {
	state->linebuf = IObuff;
	state->linelen = len;
    }

    vim_strncpy(state->linebuf, p_li->li_tv.vval.v_string, state->linelen);

    state->p_li = p_li->li_next;	
    return QF_OK;
}


    static int qf_get_next_buf_line(qfstate_T *state)
{
    char_u	*p_buf = NULL;
    int		len;

    
    if (state->buflnum > state->lnumlast)
	return QF_END_OF_INPUT;

    p_buf = ml_get_buf(state->buf, state->buflnum, FALSE);
    state->buflnum += 1;

    len = (int)STRLEN(p_buf);
    if (len > IOSIZE - 2)
    {
	state->linebuf = qf_grow_linebuf(state, len);
	if (state->linebuf == NULL)
	    return QF_NOMEM;
    }
    else {
	state->linebuf = IObuff;
	state->linelen = len;
    }
    vim_strncpy(state->linebuf, p_buf, state->linelen);

    return QF_OK;
}


    static int qf_get_next_file_line(qfstate_T *state)
{
    int	    discard;
    int	    growbuflen;

    if (fgets((char *)IObuff, IOSIZE, state->fd) == NULL)
	return QF_END_OF_INPUT;

    discard = FALSE;
    state->linelen = (int)STRLEN(IObuff);
    if (state->linelen == IOSIZE - 1 && !(IObuff[state->linelen - 1] == '\n'))
    {
	
	
	if (state->growbuf == NULL)
	{
	    state->growbufsiz = 2 * (IOSIZE - 1);
	    state->growbuf = alloc_id(state->growbufsiz, aid_qf_linebuf);
	    if (state->growbuf == NULL)
		return QF_NOMEM;
	}

	
	memcpy(state->growbuf, IObuff, IOSIZE - 1);
	growbuflen = state->linelen;

	for (;;)
	{
	    char_u	*p;

	    if (fgets((char *)state->growbuf + growbuflen, state->growbufsiz - growbuflen, state->fd) == NULL)
		break;
	    state->linelen = (int)STRLEN(state->growbuf + growbuflen);
	    growbuflen += state->linelen;
	    if ((state->growbuf)[growbuflen - 1] == '\n')
		break;
	    if (state->growbufsiz == LINE_MAXLEN)
	    {
		discard = TRUE;
		break;
	    }

	    state->growbufsiz = 2 * state->growbufsiz < LINE_MAXLEN ? 2 * state->growbufsiz : LINE_MAXLEN;
	    if ((p = vim_realloc(state->growbuf, state->growbufsiz)) == NULL)
		return QF_NOMEM;
	    state->growbuf = p;
	}

	while (discard)
	{
	    
	    
	    
	    if (fgets((char *)IObuff, IOSIZE, state->fd) == NULL || (int)STRLEN(IObuff) < IOSIZE - 1 || IObuff[IOSIZE - 2] == '\n')

		break;
	}

	state->linebuf = state->growbuf;
	state->linelen = growbuflen;
    }
    else state->linebuf = IObuff;

    
    if (state->vc.vc_type != CONV_NONE && has_non_ascii(state->linebuf))
    {
	char_u	*line;

	line = string_convert(&state->vc, state->linebuf, &state->linelen);
	if (line != NULL)
	{
	    if (state->linelen < IOSIZE)
	    {
		STRCPY(state->linebuf, line);
		vim_free(line);
	    }
	    else {
		vim_free(state->growbuf);
		state->linebuf = state->growbuf = line;
		state->growbufsiz = state->linelen < LINE_MAXLEN ? state->linelen : LINE_MAXLEN;
	    }
	}
    }

    return QF_OK;
}


    static int qf_get_nextline(qfstate_T *state)
{
    int status = QF_FAIL;

    if (state->fd == NULL)
    {
	if (state->tv != NULL)
	{
	    if (state->tv->v_type == VAR_STRING)
		
		status = qf_get_next_str_line(state);
	    else if (state->tv->v_type == VAR_LIST)
		
		status = qf_get_next_list_line(state);
	}
	else  status = qf_get_next_buf_line(state);

    }
    else  status = qf_get_next_file_line(state);


    if (status != QF_OK)
	return status;

    
    if (state->linelen > 0 && state->linebuf[state->linelen - 1] == '\n')
    {
	state->linebuf[state->linelen - 1] = NUL;

	if (state->linelen > 1 && state->linebuf[state->linelen - 2] == '\r')
	    state->linebuf[state->linelen - 2] = NUL;

    }

    remove_bom(state->linebuf);

    return QF_OK;
}

typedef struct {
    char_u	*namebuf;
    char_u	*module;
    char_u	*errmsg;
    int		errmsglen;
    long	lnum;
    long	end_lnum;
    int		col;
    int		end_col;
    char_u	use_viscol;
    char_u	*pattern;
    int		enr;
    int		type;
    int		valid;
} qffields_T;


    static int qf_parse_fmt_f(regmatch_T *rmp, int midx, qffields_T *fields, int prefix)
{
    int c;

    if (rmp->startp[midx] == NULL || rmp->endp[midx] == NULL)
	return QF_FAIL;

    
    c = *rmp->endp[midx];
    *rmp->endp[midx] = NUL;
    expand_env(rmp->startp[midx], fields->namebuf, CMDBUFFSIZE);
    *rmp->endp[midx] = c;

    
    
    if (vim_strchr((char_u *)"OPQ", prefix) != NULL && mch_getperm(fields->namebuf) == -1)
	return QF_FAIL;

    return QF_OK;
}


    static int qf_parse_fmt_n(regmatch_T *rmp, int midx, qffields_T *fields)
{
    if (rmp->startp[midx] == NULL)
	return QF_FAIL;
    fields->enr = (int)atol((char *)rmp->startp[midx]);
    return QF_OK;
}


    static int qf_parse_fmt_l(regmatch_T *rmp, int midx, qffields_T *fields)
{
    if (rmp->startp[midx] == NULL)
	return QF_FAIL;
    fields->lnum = atol((char *)rmp->startp[midx]);
    return QF_OK;
}


    static int qf_parse_fmt_e(regmatch_T *rmp, int midx, qffields_T *fields)
{
    if (rmp->startp[midx] == NULL)
	return QF_FAIL;
    fields->end_lnum = atol((char *)rmp->startp[midx]);
    return QF_OK;
}


    static int qf_parse_fmt_c(regmatch_T *rmp, int midx, qffields_T *fields)
{
    if (rmp->startp[midx] == NULL)
	return QF_FAIL;
    fields->col = (int)atol((char *)rmp->startp[midx]);
    return QF_OK;
}


    static int qf_parse_fmt_k(regmatch_T *rmp, int midx, qffields_T *fields)
{
    if (rmp->startp[midx] == NULL)
	return QF_FAIL;
    fields->end_col = (int)atol((char *)rmp->startp[midx]);
    return QF_OK;
}


    static int qf_parse_fmt_t(regmatch_T *rmp, int midx, qffields_T *fields)
{
    if (rmp->startp[midx] == NULL)
	return QF_FAIL;
    fields->type = *rmp->startp[midx];
    return QF_OK;
}


    static int copy_nonerror_line(char_u *linebuf, int linelen, qffields_T *fields)
{
    char_u	*p;

    if (linelen >= fields->errmsglen)
    {
	
	if ((p = vim_realloc(fields->errmsg, linelen + 1)) == NULL)
	    return QF_NOMEM;
	fields->errmsg = p;
	fields->errmsglen = linelen + 1;
    }
    
    vim_strncpy(fields->errmsg, linebuf, linelen);

    return QF_OK;
}


    static int qf_parse_fmt_m(regmatch_T *rmp, int midx, qffields_T *fields)
{
    char_u	*p;
    int		len;

    if (rmp->startp[midx] == NULL || rmp->endp[midx] == NULL)
	return QF_FAIL;
    len = (int)(rmp->endp[midx] - rmp->startp[midx]);
    if (len >= fields->errmsglen)
    {
	
	if ((p = vim_realloc(fields->errmsg, len + 1)) == NULL)
	    return QF_NOMEM;
	fields->errmsg = p;
	fields->errmsglen = len + 1;
    }
    vim_strncpy(fields->errmsg, rmp->startp[midx], len);
    return QF_OK;
}


    static int qf_parse_fmt_r(regmatch_T *rmp, int midx, char_u **tail)
{
    if (rmp->startp[midx] == NULL)
	return QF_FAIL;
    *tail = rmp->startp[midx];
    return QF_OK;
}


    static int qf_parse_fmt_p(regmatch_T *rmp, int midx, qffields_T *fields)
{
    char_u	*match_ptr;

    if (rmp->startp[midx] == NULL || rmp->endp[midx] == NULL)
	return QF_FAIL;
    fields->col = 0;
    for (match_ptr = rmp->startp[midx]; match_ptr != rmp->endp[midx];
								++match_ptr)
    {
	++fields->col;
	if (*match_ptr == TAB)
	{
	    fields->col += 7;
	    fields->col -= fields->col % 8;
	}
    }
    ++fields->col;
    fields->use_viscol = TRUE;
    return QF_OK;
}


    static int qf_parse_fmt_v(regmatch_T *rmp, int midx, qffields_T *fields)
{
    if (rmp->startp[midx] == NULL)
	return QF_FAIL;
    fields->col = (int)atol((char *)rmp->startp[midx]);
    fields->use_viscol = TRUE;
    return QF_OK;
}


    static int qf_parse_fmt_s(regmatch_T *rmp, int midx, qffields_T *fields)
{
    int		len;

    if (rmp->startp[midx] == NULL || rmp->endp[midx] == NULL)
	return QF_FAIL;
    len = (int)(rmp->endp[midx] - rmp->startp[midx]);
    if (len > CMDBUFFSIZE - 5)
	len = CMDBUFFSIZE - 5;
    STRCPY(fields->pattern, "^\\V");
    STRNCAT(fields->pattern, rmp->startp[midx], len);
    fields->pattern[len + 3] = '\\';
    fields->pattern[len + 4] = '$';
    fields->pattern[len + 5] = NUL;
    return QF_OK;
}


    static int qf_parse_fmt_o(regmatch_T *rmp, int midx, qffields_T *fields)
{
    int		len;

    if (rmp->startp[midx] == NULL || rmp->endp[midx] == NULL)
	return QF_FAIL;
    len = (int)(rmp->endp[midx] - rmp->startp[midx]);
    if (len > CMDBUFFSIZE)
	len = CMDBUFFSIZE;
    STRNCAT(fields->module, rmp->startp[midx], len);
    return QF_OK;
}


static int (*qf_parse_fmt[FMT_PATTERNS])(regmatch_T *, int, qffields_T *) = {
    NULL,  qf_parse_fmt_n, qf_parse_fmt_l, qf_parse_fmt_e, qf_parse_fmt_c, qf_parse_fmt_k, qf_parse_fmt_t, qf_parse_fmt_m, NULL, qf_parse_fmt_p, qf_parse_fmt_v, qf_parse_fmt_s, qf_parse_fmt_o };














    static int qf_parse_match( char_u		*linebuf, int		linelen, efm_T		*fmt_ptr, regmatch_T	*regmatch, qffields_T	*fields, int		qf_multiline, int		qf_multiscan, char_u		**tail)








{
    int		idx = fmt_ptr->prefix;
    int		i;
    int		midx;
    int		status;

    if ((idx == 'C' || idx == 'Z') && !qf_multiline)
	return QF_FAIL;
    if (vim_strchr((char_u *)"EWIN", idx) != NULL)
	fields->type = idx;
    else fields->type = 0;

    
    
    
    for (i = 0; i < FMT_PATTERNS; i++)
    {
	status = QF_OK;
	midx = (int)fmt_ptr->addr[i];
	if (i == 0 && midx > 0)				
	    status = qf_parse_fmt_f(regmatch, midx, fields, idx);
	else if (i == FMT_PATTERN_M)
	{
	    if (fmt_ptr->flags == '+' && !qf_multiscan)	
		status = copy_nonerror_line(linebuf, linelen, fields);
	    else if (midx > 0)				
		status = qf_parse_fmt_m(regmatch, midx, fields);
	}
	else if (i == FMT_PATTERN_R && midx > 0)	
	    status = qf_parse_fmt_r(regmatch, midx, tail);
	else if (midx > 0)				
	    status = (qf_parse_fmt[i])(regmatch, midx, fields);

	if (status != QF_OK)
	    return status;
    }

    return QF_OK;
}


    static int qf_parse_get_fields( char_u		*linebuf, int		linelen, efm_T		*fmt_ptr, qffields_T	*fields, int		qf_multiline, int		qf_multiscan, char_u		**tail)







{
    regmatch_T	regmatch;
    int		status = QF_FAIL;
    int		r;

    if (qf_multiscan && vim_strchr((char_u *)"OPQ", fmt_ptr->prefix) == NULL)
	return QF_FAIL;

    fields->namebuf[0] = NUL;
    fields->module[0] = NUL;
    fields->pattern[0] = NUL;
    if (!qf_multiscan)
	fields->errmsg[0] = NUL;
    fields->lnum = 0;
    fields->end_lnum = 0;
    fields->col = 0;
    fields->end_col = 0;
    fields->use_viscol = FALSE;
    fields->enr = -1;
    fields->type = 0;
    *tail = NULL;

    
    regmatch.rm_ic = TRUE;
    regmatch.regprog = fmt_ptr->prog;
    r = vim_regexec(&regmatch, linebuf, (colnr_T)0);
    fmt_ptr->prog = regmatch.regprog;
    if (r)
	status = qf_parse_match(linebuf, linelen, fmt_ptr, &regmatch, fields, qf_multiline, qf_multiscan, tail);

    return status;
}


    static int qf_parse_dir_pfx(int idx, qffields_T *fields, qf_list_T *qfl)
{
    if (idx == 'D')				
    {
	if (*fields->namebuf == NUL)
	{
	    emsg(_(e_missing_or_empty_directory_name));
	    return QF_FAIL;
	}
	qfl->qf_directory = qf_push_dir(fields->namebuf, &qfl->qf_dir_stack, FALSE);
	if (qfl->qf_directory == NULL)
	    return QF_FAIL;
    }
    else if (idx == 'X')			
	qfl->qf_directory = qf_pop_dir(&qfl->qf_dir_stack);

    return QF_OK;
}


    static int qf_parse_file_pfx( int idx, qffields_T *fields, qf_list_T *qfl, char_u *tail)




{
    fields->valid = FALSE;
    if (*fields->namebuf == NUL || mch_getperm(fields->namebuf) >= 0)
    {
	if (*fields->namebuf && idx == 'P')
	    qfl->qf_currfile = qf_push_dir(fields->namebuf, &qfl->qf_file_stack, TRUE);
	else if (idx == 'Q')
	    qfl->qf_currfile = qf_pop_dir(&qfl->qf_file_stack);
	*fields->namebuf = NUL;
	if (tail && *tail)
	{
	    STRMOVE(IObuff, skipwhite(tail));
	    qfl->qf_multiscan = TRUE;
	    return QF_MULTISCAN;
	}
    }

    return QF_OK;
}


    static int qf_parse_line_nomatch(char_u *linebuf, int linelen, qffields_T *fields)
{
    fields->namebuf[0] = NUL;	
    fields->lnum = 0;		
    fields->valid = FALSE;

    return copy_nonerror_line(linebuf, linelen, fields);
}


    static int qf_parse_multiline_pfx( int idx, qf_list_T *qfl, qffields_T *fields)



{
    char_u		*ptr;
    int			len;

    if (!qfl->qf_multiignore)
    {
	qfline_T *qfprev = qfl->qf_last;

	if (qfprev == NULL)
	    return QF_FAIL;
	if (*fields->errmsg && !qfl->qf_multiignore)
	{
	    len = (int)STRLEN(qfprev->qf_text);
	    ptr = alloc_id(len + STRLEN(fields->errmsg) + 2, aid_qf_multiline_pfx);
	    if (ptr == NULL)
		return QF_FAIL;
	    STRCPY(ptr, qfprev->qf_text);
	    vim_free(qfprev->qf_text);
	    qfprev->qf_text = ptr;
	    *(ptr += len) = '\n';
	    STRCPY(++ptr, fields->errmsg);
	}
	if (qfprev->qf_nr == -1)
	    qfprev->qf_nr = fields->enr;
	if (vim_isprintc(fields->type) && !qfprev->qf_type)
	    
	    qfprev->qf_type = fields->type;

	if (!qfprev->qf_lnum)
	    qfprev->qf_lnum = fields->lnum;
	if (!qfprev->qf_end_lnum)
	    qfprev->qf_end_lnum = fields->end_lnum;
	if (!qfprev->qf_col)
	{
	    qfprev->qf_col = fields->col;
	    qfprev->qf_viscol = fields->use_viscol;
	}
	if (!qfprev->qf_end_col)
	    qfprev->qf_end_col = fields->end_col;
	if (!qfprev->qf_fnum)
	    qfprev->qf_fnum = qf_get_fnum(qfl, qfl->qf_directory, *fields->namebuf || qfl->qf_directory != NULL ? fields->namebuf : qfl->qf_currfile != NULL && fields->valid ? qfl->qf_currfile : 0);




    }
    if (idx == 'Z')
	qfl->qf_multiline = qfl->qf_multiignore = FALSE;
    line_breakcheck();

    return QF_IGNORE_LINE;
}


    static int qf_parse_line( qf_list_T	*qfl, char_u		*linebuf, int		linelen, efm_T		*fmt_first, qffields_T	*fields)





{
    efm_T		*fmt_ptr;
    int			idx = 0;
    char_u		*tail = NULL;
    int			status;

restofline:
    
    if (fmt_start == NULL)
	fmt_ptr = fmt_first;
    else {
	
	fmt_ptr = fmt_start;
	fmt_start = NULL;
    }

    
    
    fields->valid = TRUE;
    for ( ; fmt_ptr != NULL; fmt_ptr = fmt_ptr->next)
    {
	idx = fmt_ptr->prefix;
	status = qf_parse_get_fields(linebuf, linelen, fmt_ptr, fields, qfl->qf_multiline, qfl->qf_multiscan, &tail);
	if (status == QF_NOMEM)
	    return status;
	if (status == QF_OK)
	    break;
    }
    qfl->qf_multiscan = FALSE;

    if (fmt_ptr == NULL || idx == 'D' || idx == 'X')
    {
	if (fmt_ptr != NULL)
	{
	    
	    status = qf_parse_dir_pfx(idx, fields, qfl);
	    if (status != QF_OK)
		return status;
	}

	status = qf_parse_line_nomatch(linebuf, linelen, fields);
	if (status != QF_OK)
	    return status;

	if (fmt_ptr == NULL)
	    qfl->qf_multiline = qfl->qf_multiignore = FALSE;
    }
    else if (fmt_ptr != NULL)
    {
	
	if (fmt_ptr->conthere)
	    fmt_start = fmt_ptr;

	if (vim_strchr((char_u *)"AEWIN", idx) != NULL)
	{
	    qfl->qf_multiline = TRUE;	
	    qfl->qf_multiignore = FALSE;
	}
	else if (vim_strchr((char_u *)"CZ", idx) != NULL)
	{				
	    status = qf_parse_multiline_pfx(idx, qfl, fields);
	    if (status != QF_OK)
		return status;
	}
	else if (vim_strchr((char_u *)"OPQ", idx) != NULL)
	{				
	    status = qf_parse_file_pfx(idx, fields, qfl, tail);
	    if (status == QF_MULTISCAN)
		goto restofline;
	}
	if (fmt_ptr->flags == '-')	
	{
	    if (qfl->qf_multiline)
		
		qfl->qf_multiignore = TRUE;
	    return QF_IGNORE_LINE;
	}
    }

    return QF_OK;
}


    static int qf_stack_empty(qf_info_T *qi)
{
    return qi == NULL || qi->qf_listcount <= 0;
}


    static int qf_list_empty(qf_list_T *qfl)
{
    return qfl == NULL || qfl->qf_count <= 0;
}


    static int qf_list_has_valid_entries(qf_list_T *qfl)
{
    return !qf_list_empty(qfl) && !qfl->qf_nonevalid;
}


    static qf_list_T * qf_get_list(qf_info_T *qi, int idx)
{
    return &qi->qf_lists[idx];
}


    static int qf_alloc_fields(qffields_T *pfields)
{
    pfields->namebuf = alloc_id(CMDBUFFSIZE + 1, aid_qf_namebuf);
    pfields->module = alloc_id(CMDBUFFSIZE + 1, aid_qf_module);
    pfields->errmsglen = CMDBUFFSIZE + 1;
    pfields->errmsg = alloc_id(pfields->errmsglen, aid_qf_errmsg);
    pfields->pattern = alloc_id(CMDBUFFSIZE + 1, aid_qf_pattern);
    if (pfields->namebuf == NULL || pfields->errmsg == NULL || pfields->pattern == NULL || pfields->module == NULL)
	return FAIL;

    return OK;
}


    static void qf_free_fields(qffields_T *pfields)
{
    vim_free(pfields->namebuf);
    vim_free(pfields->module);
    vim_free(pfields->errmsg);
    vim_free(pfields->pattern);
}


    static int qf_setup_state( qfstate_T	*pstate, char_u		*enc, char_u		*efile, typval_T	*tv, buf_T		*buf, linenr_T	lnumfirst, linenr_T	lnumlast)







{
    pstate->vc.vc_type = CONV_NONE;
    if (enc != NULL && *enc != NUL)
	convert_setup(&pstate->vc, enc, p_enc);

    if (efile != NULL && (pstate->fd = mch_fopen((char *)efile, "r")) == NULL)
    {
	semsg(_(e_cant_open_errorfile_str), efile);
	return FAIL;
    }

    if (tv != NULL)
    {
	if (tv->v_type == VAR_STRING)
	    pstate->p_str = tv->vval.v_string;
	else if (tv->v_type == VAR_LIST)
	    pstate->p_li = tv->vval.v_list->lv_first;
	pstate->tv = tv;
    }
    pstate->buf = buf;
    pstate->buflnum = lnumfirst;
    pstate->lnumlast = lnumlast;

    return OK;
}


    static void qf_cleanup_state(qfstate_T *pstate)
{
    if (pstate->fd != NULL)
	fclose(pstate->fd);

    vim_free(pstate->growbuf);
    if (pstate->vc.vc_type != CONV_NONE)
	convert_setup(&pstate->vc, NULL, NULL);
}


    static int qf_init_process_nextline( qf_list_T	*qfl, efm_T		*fmt_first, qfstate_T	*state, qffields_T	*fields)




{
    int		    status;

    
    status = qf_get_nextline(state);
    if (status != QF_OK)
	return status;

    status = qf_parse_line(qfl, state->linebuf, state->linelen, fmt_first, fields);
    if (status != QF_OK)
	return status;

    return qf_add_entry(qfl, qfl->qf_directory, (*fields->namebuf || qfl->qf_directory != NULL)

		? fields->namebuf : ((qfl->qf_currfile != NULL && fields->valid)
		    ? qfl->qf_currfile : (char_u *)NULL), fields->module, 0, fields->errmsg, fields->lnum, fields->end_lnum, fields->col, fields->end_col, fields->use_viscol, fields->pattern, fields->enr, fields->type, fields->valid);











}


    static int qf_init_ext( qf_info_T	    *qi, int		    qf_idx, char_u	    *efile, buf_T	    *buf, typval_T	    *tv, char_u	    *errorformat, int		    newlist, linenr_T	    lnumfirst, linenr_T	    lnumlast, char_u	    *qf_title, char_u	    *enc)











{
    qf_list_T	    *qfl;
    qfstate_T	    state;
    qffields_T	    fields;
    qfline_T	    *old_last = NULL;
    int		    adding = FALSE;
    static efm_T    *fmt_first = NULL;
    char_u	    *efm;
    static char_u   *last_efm = NULL;
    int		    retval = -1;	
    int		    status;

    
    VIM_CLEAR(qf_last_bufname);

    CLEAR_FIELD(state);
    CLEAR_FIELD(fields);
    if ((qf_alloc_fields(&fields) == FAIL) || (qf_setup_state(&state, enc, efile, tv, buf, lnumfirst, lnumlast) == FAIL))

	goto qf_init_end;

    if (newlist || qf_idx == qi->qf_listcount)
    {
	
	qf_new_list(qi, qf_title);
	qf_idx = qi->qf_curlist;
	qfl = qf_get_list(qi, qf_idx);
    }
    else {
	
	adding = TRUE;
	qfl = qf_get_list(qi, qf_idx);
	if (!qf_list_empty(qfl))
	    old_last = qfl->qf_last;
    }

    
    if (errorformat == p_efm && tv == NULL && *buf->b_p_efm != NUL)
	efm = buf->b_p_efm;
    else efm = errorformat;

    
    
    if (last_efm == NULL || (STRCMP(last_efm, efm) != 0))
    {
	
	VIM_CLEAR(last_efm);
	free_efm_list(&fmt_first);

	
	fmt_first = parse_efm_option(efm);
	if (fmt_first != NULL)
	    last_efm = vim_strsave(efm);
    }

    if (fmt_first == NULL)	
	goto error2;

    
    
    got_int = FALSE;

    
    
    while (!got_int)
    {
	status = qf_init_process_nextline(qfl, fmt_first, &state, &fields);
	if (status == QF_NOMEM)		
	    goto qf_init_end;
	if (status == QF_END_OF_INPUT)	
	    break;
	if (status == QF_FAIL)
	    goto error2;

	line_breakcheck();
    }
    if (state.fd == NULL || !ferror(state.fd))
    {
	if (qfl->qf_index == 0)
	{
	    
	    qfl->qf_ptr = qfl->qf_start;
	    qfl->qf_index = 1;
	    qfl->qf_nonevalid = TRUE;
	}
	else {
	    qfl->qf_nonevalid = FALSE;
	    if (qfl->qf_ptr == NULL)
		qfl->qf_ptr = qfl->qf_start;
	}
	
	retval = qfl->qf_count;
	goto qf_init_end;
    }
    emsg(_(e_error_while_reading_errorfile));
error2:
    if (!adding)
    {
	
	qf_free(qfl);
	qi->qf_listcount--;
	if (qi->qf_curlist > 0)
	    --qi->qf_curlist;
    }
qf_init_end:
    if (qf_idx == qi->qf_curlist)
	qf_update_buffer(qi, old_last);
    qf_cleanup_state(&state);
    qf_free_fields(&fields);

    return retval;
}


    int qf_init(win_T	    *wp, char_u	    *efile, char_u	    *errorformat, int	    newlist, char_u	    *qf_title, char_u	    *enc)





{
    qf_info_T	    *qi = &ql_info;

    if (wp != NULL)
    {
	qi = ll_get_or_alloc_list(wp);
	if (qi == NULL)
	    return FAIL;
    }

    return qf_init_ext(qi, qi->qf_curlist, efile, curbuf, NULL, errorformat, newlist, (linenr_T)0, (linenr_T)0, qf_title, enc);
}


    static void qf_store_title(qf_list_T *qfl, char_u *title)
{
    VIM_CLEAR(qfl->qf_title);

    if (title != NULL)
    {
	char_u *p = alloc_id(STRLEN(title) + 2, aid_qf_title);

	qfl->qf_title = p;
	if (p != NULL)
	    STRCPY(p, title);
    }
}


    static char_u * qf_cmdtitle(char_u *cmd)
{
    static char_u qftitle_str[IOSIZE];

    vim_snprintf((char *)qftitle_str, IOSIZE, ":%s", (char *)cmd);
    return qftitle_str;
}


    static qf_list_T * qf_get_curlist(qf_info_T *qi)
{
    return qf_get_list(qi, qi->qf_curlist);
}


    static void qf_new_list(qf_info_T *qi, char_u *qf_title)
{
    int		i;
    qf_list_T	*qfl;

    
    
    
    while (qi->qf_listcount > qi->qf_curlist + 1)
	qf_free(&qi->qf_lists[--qi->qf_listcount]);

    
    
    if (qi->qf_listcount == LISTCOUNT)
    {
	qf_free(&qi->qf_lists[0]);
	for (i = 1; i < LISTCOUNT; ++i)
	    qi->qf_lists[i - 1] = qi->qf_lists[i];
	qi->qf_curlist = LISTCOUNT - 1;
    }
    else qi->qf_curlist = qi->qf_listcount++;
    qfl = qf_get_curlist(qi);
    CLEAR_POINTER(qfl);
    qf_store_title(qfl, qf_title);
    qfl->qfl_type = qi->qfl_type;
    qfl->qf_id = ++last_qf_id;
}


    static void locstack_queue_delreq(qf_info_T *qi)
{
    qf_delq_T	*q;

    q = ALLOC_ONE(qf_delq_T);
    if (q != NULL)
    {
	q->qi = qi;
	q->next = qf_delq_head;
	qf_delq_head = q;
    }
}


    int qf_stack_get_bufnr(void)
{
    return ql_info.qf_bufnr;
}


    static void wipe_qf_buffer(qf_info_T *qi)
{
    buf_T	*qfbuf;

    if (qi->qf_bufnr != INVALID_QFBUFNR)
    {
	qfbuf = buflist_findnr(qi->qf_bufnr);
	if (qfbuf != NULL && qfbuf->b_nwindows == 0)
	{
	    
	    
	    close_buffer(NULL, qfbuf, DOBUF_WIPE, FALSE, FALSE);
	    qi->qf_bufnr = INVALID_QFBUFNR;
	}
    }
}


    static void ll_free_all(qf_info_T **pqi)
{
    int		i;
    qf_info_T	*qi;

    qi = *pqi;
    if (qi == NULL)
	return;
    *pqi = NULL;	

    
    
    if (quickfix_busy > 0)
    {
	locstack_queue_delreq(qi);
	return;
    }

    qi->qf_refcount--;
    if (qi->qf_refcount < 1)
    {
	
	
	wipe_qf_buffer(qi);

	for (i = 0; i < qi->qf_listcount; ++i)
	    qf_free(qf_get_list(qi, i));
	vim_free(qi);
    }
}


    void qf_free_all(win_T *wp)
{
    int		i;
    qf_info_T	*qi = &ql_info;

    if (wp != NULL)
    {
	
	ll_free_all(&wp->w_llist);
	ll_free_all(&wp->w_llist_ref);
    }
    else  for (i = 0; i < qi->qf_listcount; ++i)

	    qf_free(qf_get_list(qi, i));
}


    static void incr_quickfix_busy(void)
{
    quickfix_busy++;
}


    static void decr_quickfix_busy(void)
{
    if (--quickfix_busy == 0)
    {
	
	
	while (qf_delq_head != NULL)
	{
	    qf_delq_T	*q = qf_delq_head;

	    qf_delq_head = q->next;
	    ll_free_all(&q->qi);
	    vim_free(q);
	}
    }

    if (quickfix_busy < 0)
    {
	emsg("quickfix_busy has become negative");
	abort();
    }

}


    void check_quickfix_busy(void)
{
    if (quickfix_busy != 0)
    {
	semsg("quickfix_busy not zero on exit: %ld", (long)quickfix_busy);

	abort();

    }
}



    static int qf_add_entry( qf_list_T	*qfl, char_u	*dir, char_u	*fname, char_u	*module, int		bufnum, char_u	*mesg, long	lnum, long	end_lnum, int		col, int		end_col, int		vis_col, char_u	*pattern, int		nr, int		type, int		valid)















{
    qfline_T	*qfp;
    qfline_T	**lastp;	

    if ((qfp = ALLOC_ONE_ID(qfline_T, aid_qf_qfline)) == NULL)
	return QF_FAIL;
    if (bufnum != 0)
    {
	buf_T *buf = buflist_findnr(bufnum);

	qfp->qf_fnum = bufnum;
	if (buf != NULL)
	    buf->b_has_qf_entry |= IS_QF_LIST(qfl) ? BUF_HAS_QF_ENTRY : BUF_HAS_LL_ENTRY;
    }
    else qfp->qf_fnum = qf_get_fnum(qfl, dir, fname);
    if ((qfp->qf_text = vim_strsave(mesg)) == NULL)
    {
	vim_free(qfp);
	return QF_FAIL;
    }
    qfp->qf_lnum = lnum;
    qfp->qf_end_lnum = end_lnum;
    qfp->qf_col = col;
    qfp->qf_end_col = end_col;
    qfp->qf_viscol = vis_col;
    if (pattern == NULL || *pattern == NUL)
	qfp->qf_pattern = NULL;
    else if ((qfp->qf_pattern = vim_strsave(pattern)) == NULL)
    {
	vim_free(qfp->qf_text);
	vim_free(qfp);
	return QF_FAIL;
    }
    if (module == NULL || *module == NUL)
	qfp->qf_module = NULL;
    else if ((qfp->qf_module = vim_strsave(module)) == NULL)
    {
	vim_free(qfp->qf_text);
	vim_free(qfp->qf_pattern);
	vim_free(qfp);
	return QF_FAIL;
    }
    qfp->qf_nr = nr;
    if (type != 1 && !vim_isprintc(type)) 
	type = 0;
    qfp->qf_type = type;
    qfp->qf_valid = valid;

    lastp = &qfl->qf_last;
    if (qf_list_empty(qfl))		
    {
	qfl->qf_start = qfp;
	qfl->qf_ptr = qfp;
	qfl->qf_index = 0;
	qfp->qf_prev = NULL;
    }
    else {
	qfp->qf_prev = *lastp;
	(*lastp)->qf_next = qfp;
    }
    qfp->qf_next = NULL;
    qfp->qf_cleared = FALSE;
    *lastp = qfp;
    ++qfl->qf_count;
    if (qfl->qf_index == 0 && qfp->qf_valid)	
    {
	qfl->qf_index = qfl->qf_count;
	qfl->qf_ptr = qfp;
    }

    return QF_OK;
}


    static qf_info_T * qf_alloc_stack(qfltype_T qfltype)
{
    qf_info_T *qi;

    qi = ALLOC_CLEAR_ONE_ID(qf_info_T, aid_qf_qfinfo);
    if (qi != NULL)
    {
	qi->qf_refcount++;
	qi->qfl_type = qfltype;
	qi->qf_bufnr = INVALID_QFBUFNR;
    }
    return qi;
}


    static qf_info_T * ll_get_or_alloc_list(win_T *wp)
{
    if (IS_LL_WINDOW(wp))
	
	return wp->w_llist_ref;

    
    
    ll_free_all(&wp->w_llist_ref);

    if (wp->w_llist == NULL)
	wp->w_llist = qf_alloc_stack(QFLT_LOCATION);	
    return wp->w_llist;
}


    static qf_info_T * qf_cmd_get_stack(exarg_T *eap, int print_emsg)
{
    qf_info_T	*qi = &ql_info;

    if (is_loclist_cmd(eap->cmdidx))
    {
	qi = GET_LOC_LIST(curwin);
	if (qi == NULL)
	{
	    if (print_emsg)
		emsg(_(e_no_location_list));
	    return NULL;
	}
    }

    return qi;
}


    static qf_info_T * qf_cmd_get_or_alloc_stack(exarg_T *eap, win_T **pwinp)
{
    qf_info_T	*qi = &ql_info;

    if (is_loclist_cmd(eap->cmdidx))
    {
	qi = ll_get_or_alloc_list(curwin);
	if (qi == NULL)
	    return NULL;
	*pwinp = curwin;
    }

    return qi;
}


    static int copy_loclist_entries(qf_list_T *from_qfl, qf_list_T *to_qfl)
{
    int		i;
    qfline_T    *from_qfp;
    qfline_T    *prevp;

    
    FOR_ALL_QFL_ITEMS(from_qfl, from_qfp, i)
    {
	if (qf_add_entry(to_qfl, NULL, NULL, from_qfp->qf_module, 0, from_qfp->qf_text, from_qfp->qf_lnum, from_qfp->qf_end_lnum, from_qfp->qf_col, from_qfp->qf_end_col, from_qfp->qf_viscol, from_qfp->qf_pattern, from_qfp->qf_nr, 0, from_qfp->qf_valid) == QF_FAIL)













	    return FAIL;

	
	
	
	prevp = to_qfl->qf_last;
	prevp->qf_fnum = from_qfp->qf_fnum;	
	prevp->qf_type = from_qfp->qf_type;	
	if (from_qfl->qf_ptr == from_qfp)
	    to_qfl->qf_ptr = prevp;		
    }

    return OK;
}


    static int copy_loclist(qf_list_T *from_qfl, qf_list_T *to_qfl)
{
    
    to_qfl->qfl_type = from_qfl->qfl_type;
    to_qfl->qf_nonevalid = from_qfl->qf_nonevalid;
    to_qfl->qf_count = 0;
    to_qfl->qf_index = 0;
    to_qfl->qf_start = NULL;
    to_qfl->qf_last = NULL;
    to_qfl->qf_ptr = NULL;
    if (from_qfl->qf_title != NULL)
	to_qfl->qf_title = vim_strsave(from_qfl->qf_title);
    else to_qfl->qf_title = NULL;
    if (from_qfl->qf_ctx != NULL)
    {
	to_qfl->qf_ctx = alloc_tv();
	if (to_qfl->qf_ctx != NULL)
	    copy_tv(from_qfl->qf_ctx, to_qfl->qf_ctx);
    }
    else to_qfl->qf_ctx = NULL;
    if (from_qfl->qf_qftf_cb.cb_name != NULL)
	copy_callback(&to_qfl->qf_qftf_cb, &from_qfl->qf_qftf_cb);
    else to_qfl->qf_qftf_cb.cb_name = NULL;

    if (from_qfl->qf_count)
	if (copy_loclist_entries(from_qfl, to_qfl) == FAIL)
	    return FAIL;

    to_qfl->qf_index = from_qfl->qf_index;	

    
    to_qfl->qf_id = ++last_qf_id;
    to_qfl->qf_changedtick = 0L;

    
    
    if (to_qfl->qf_nonevalid)
    {
	to_qfl->qf_ptr = to_qfl->qf_start;
	to_qfl->qf_index = 1;
    }

    return OK;
}


    void copy_loclist_stack(win_T *from, win_T *to)
{
    qf_info_T	*qi;
    int		idx;

    
    
    
    if (IS_LL_WINDOW(from))
	qi = from->w_llist_ref;
    else qi = from->w_llist;

    if (qi == NULL)		    
	return;

    
    if ((to->w_llist = qf_alloc_stack(QFLT_LOCATION)) == NULL)
	return;

    to->w_llist->qf_listcount = qi->qf_listcount;

    
    for (idx = 0; idx < qi->qf_listcount; ++idx)
    {
	to->w_llist->qf_curlist = idx;

	if (copy_loclist(qf_get_list(qi, idx), qf_get_list(to->w_llist, idx)) == FAIL)
	{
	    qf_free_all(to);
	    return;
	}
    }

    to->w_llist->qf_curlist = qi->qf_curlist;	
}


    static int qf_get_fnum(qf_list_T *qfl, char_u *directory, char_u *fname)
{
    char_u	*ptr = NULL;
    buf_T	*buf;
    char_u	*bufname;

    if (fname == NULL || *fname == NUL)		
	return 0;


    vms_remove_version(fname);


    if (directory != NULL)
	slash_adjust(directory);
    slash_adjust(fname);

    if (directory != NULL && !vim_isAbsName(fname)
	    && (ptr = concat_fnames(directory, fname, TRUE)) != NULL)
    {
	
	
	
	
	if (mch_getperm(ptr) < 0)
	{
	    vim_free(ptr);
	    directory = qf_guess_filepath(qfl, fname);
	    if (directory)
		ptr = concat_fnames(directory, fname, TRUE);
	    else ptr = vim_strsave(fname);
	}
	
	bufname = ptr;
    }
    else bufname = fname;

    if (qf_last_bufname != NULL && STRCMP(bufname, qf_last_bufname) == 0 && bufref_valid(&qf_last_bufref))
    {
	buf = qf_last_bufref.br_buf;
	vim_free(ptr);
    }
    else {
	vim_free(qf_last_bufname);
	buf = buflist_new(bufname, NULL, (linenr_T)0, BLN_NOOPT);
	if (bufname == ptr)
	    qf_last_bufname = bufname;
	else qf_last_bufname = vim_strsave(bufname);
	set_bufref(&qf_last_bufref, buf);
    }
    if (buf == NULL)
	return 0;

    buf->b_has_qf_entry = IS_QF_LIST(qfl) ? BUF_HAS_QF_ENTRY : BUF_HAS_LL_ENTRY;
    return buf->b_fnum;
}


    static char_u * qf_push_dir(char_u *dirbuf, struct dir_stack_T **stackptr, int is_file_stack)
{
    struct dir_stack_T  *ds_new;
    struct dir_stack_T  *ds_ptr;

    
    ds_new = ALLOC_ONE_ID(struct dir_stack_T, aid_qf_dirstack);
    if (ds_new == NULL)
	return NULL;

    ds_new->next = *stackptr;
    *stackptr = ds_new;

    
    if (vim_isAbsName(dirbuf)
	    || (*stackptr)->next == NULL || is_file_stack)
	(*stackptr)->dirname = vim_strsave(dirbuf);
    else {
	
	
	
	ds_new = (*stackptr)->next;
	(*stackptr)->dirname = NULL;
	while (ds_new)
	{
	    vim_free((*stackptr)->dirname);
	    (*stackptr)->dirname = concat_fnames(ds_new->dirname, dirbuf, TRUE);
	    if (mch_isdir((*stackptr)->dirname) == TRUE)
		break;

	    ds_new = ds_new->next;
	}

	
	while ((*stackptr)->next != ds_new)
	{
	    ds_ptr = (*stackptr)->next;
	    (*stackptr)->next = (*stackptr)->next->next;
	    vim_free(ds_ptr->dirname);
	    vim_free(ds_ptr);
	}

	
	if (ds_new == NULL)
	{
	    vim_free((*stackptr)->dirname);
	    (*stackptr)->dirname = vim_strsave(dirbuf);
	}
    }

    if ((*stackptr)->dirname != NULL)
	return (*stackptr)->dirname;
    else {
	ds_ptr = *stackptr;
	*stackptr = (*stackptr)->next;
	vim_free(ds_ptr);
	return NULL;
    }
}


    static char_u * qf_pop_dir(struct dir_stack_T **stackptr)
{
    struct dir_stack_T  *ds_ptr;

    
    

    
    if (*stackptr != NULL)
    {
	ds_ptr = *stackptr;
	*stackptr = (*stackptr)->next;
	vim_free(ds_ptr->dirname);
	vim_free(ds_ptr);
    }

    
    return *stackptr ? (*stackptr)->dirname : NULL;
}


    static void qf_clean_dir_stack(struct dir_stack_T **stackptr)
{
    struct dir_stack_T  *ds_ptr;

    while ((ds_ptr = *stackptr) != NULL)
    {
	*stackptr = (*stackptr)->next;
	vim_free(ds_ptr->dirname);
	vim_free(ds_ptr);
    }
}


    static char_u * qf_guess_filepath(qf_list_T *qfl, char_u *filename)
{
    struct dir_stack_T     *ds_ptr;
    struct dir_stack_T     *ds_tmp;
    char_u		   *fullname;

    
    if (qfl->qf_dir_stack == NULL)
	return NULL;

    ds_ptr = qfl->qf_dir_stack->next;
    fullname = NULL;
    while (ds_ptr)
    {
	vim_free(fullname);
	fullname = concat_fnames(ds_ptr->dirname, filename, TRUE);

	
	
	if ((fullname != NULL) && (mch_getperm(fullname) >= 0))
	    break;

	ds_ptr = ds_ptr->next;
    }

    vim_free(fullname);

    
    while (qfl->qf_dir_stack->next != ds_ptr)
    {
	ds_tmp = qfl->qf_dir_stack->next;
	qfl->qf_dir_stack->next = qfl->qf_dir_stack->next->next;
	vim_free(ds_tmp->dirname);
	vim_free(ds_tmp);
    }

    return ds_ptr == NULL ? NULL : ds_ptr->dirname;
}


    static int qflist_valid(win_T *wp, int_u qf_id)
{
    qf_info_T	*qi = &ql_info;
    int		i;

    if (wp != NULL)
    {
	if (!win_valid(wp))
	    return FALSE;
	qi = GET_LOC_LIST(wp);	    
	if (qi == NULL)
	    return FALSE;
    }

    for (i = 0; i < qi->qf_listcount; ++i)
	if (qi->qf_lists[i].qf_id == qf_id)
	    return TRUE;

    return FALSE;
}


    static int is_qf_entry_present(qf_list_T *qfl, qfline_T *qf_ptr)
{
    qfline_T	*qfp;
    int		i;

    
    FOR_ALL_QFL_ITEMS(qfl, qfp, i)
	if (qfp == qf_ptr)
	    break;

    if (i > qfl->qf_count) 
	return FALSE;

    return TRUE;
}


    static qfline_T * get_next_valid_entry( qf_list_T	*qfl, qfline_T	*qf_ptr, int		*qf_index, int		dir)




{
    int			idx;
    int			old_qf_fnum;

    idx = *qf_index;
    old_qf_fnum = qf_ptr->qf_fnum;

    do {
	if (idx == qfl->qf_count || qf_ptr->qf_next == NULL)
	    return NULL;
	++idx;
	qf_ptr = qf_ptr->qf_next;
    } while ((!qfl->qf_nonevalid && !qf_ptr->qf_valid)
	    || (dir == FORWARD_FILE && qf_ptr->qf_fnum == old_qf_fnum));

    *qf_index = idx;
    return qf_ptr;
}


    static qfline_T * get_prev_valid_entry( qf_list_T	*qfl, qfline_T	*qf_ptr, int		*qf_index, int		dir)




{
    int			idx;
    int			old_qf_fnum;

    idx = *qf_index;
    old_qf_fnum = qf_ptr->qf_fnum;

    do {
	if (idx == 1 || qf_ptr->qf_prev == NULL)
	    return NULL;
	--idx;
	qf_ptr = qf_ptr->qf_prev;
    } while ((!qfl->qf_nonevalid && !qf_ptr->qf_valid)
	    || (dir == BACKWARD_FILE && qf_ptr->qf_fnum == old_qf_fnum));

    *qf_index = idx;
    return qf_ptr;
}


    static qfline_T * get_nth_valid_entry( qf_list_T	*qfl, int		errornr, int		dir, int		*new_qfidx)




{
    qfline_T		*qf_ptr = qfl->qf_ptr;
    int			qf_idx = qfl->qf_index;
    qfline_T		*prev_qf_ptr;
    int			prev_index;
    char		*err = e_no_more_items;

    while (errornr--)
    {
	prev_qf_ptr = qf_ptr;
	prev_index = qf_idx;

	if (dir == FORWARD || dir == FORWARD_FILE)
	    qf_ptr = get_next_valid_entry(qfl, qf_ptr, &qf_idx, dir);
	else qf_ptr = get_prev_valid_entry(qfl, qf_ptr, &qf_idx, dir);
	if (qf_ptr == NULL)
	{
	    qf_ptr = prev_qf_ptr;
	    qf_idx = prev_index;
	    if (err != NULL)
	    {
		emsg(_(err));
		return NULL;
	    }
	    break;
	}

	err = NULL;
    }

    *new_qfidx = qf_idx;
    return qf_ptr;
}


    static qfline_T * get_nth_entry(qf_list_T *qfl, int errornr, int *new_qfidx)
{
    qfline_T	*qf_ptr = qfl->qf_ptr;
    int		qf_idx = qfl->qf_index;

    
    while (errornr < qf_idx && qf_idx > 1 && qf_ptr->qf_prev != NULL)
    {
	--qf_idx;
	qf_ptr = qf_ptr->qf_prev;
    }
    
    while (errornr > qf_idx && qf_idx < qfl->qf_count && qf_ptr->qf_next != NULL)
    {
	++qf_idx;
	qf_ptr = qf_ptr->qf_next;
    }

    *new_qfidx = qf_idx;
    return qf_ptr;
}


    static qfline_T * qf_get_entry( qf_list_T	*qfl, int		errornr, int		dir, int		*new_qfidx)




{
    qfline_T	*qf_ptr = qfl->qf_ptr;
    int		qfidx = qfl->qf_index;

    if (dir != 0)    
	qf_ptr = get_nth_valid_entry(qfl, errornr, dir, &qfidx);
    else if (errornr != 0)	
	qf_ptr = get_nth_entry(qfl, errornr, &qfidx);

    *new_qfidx = qfidx;
    return qf_ptr;
}


    static win_T * qf_find_help_win(void)
{
    win_T *wp;

    FOR_ALL_WINDOWS(wp)
	if (bt_help(wp->w_buffer))
	    return wp;

    return NULL;
}


    static void win_set_loclist(win_T *wp, qf_info_T *qi)
{
    wp->w_llist = qi;
    qi->qf_refcount++;
}


    static int jump_to_help_window(qf_info_T *qi, int newwin, int *opened_window)
{
    win_T	*wp;
    int		flags;

    if (cmdmod.cmod_tab != 0 || newwin)
	wp = NULL;
    else wp = qf_find_help_win();
    if (wp != NULL && wp->w_buffer->b_nwindows > 0)
	win_enter(wp, TRUE);
    else {
	
	
	flags = WSP_HELP;
	if (cmdmod.cmod_split == 0 && curwin->w_width != Columns && curwin->w_width < 80)
	    flags |= WSP_TOP;
	
	
	if (IS_LL_STACK(qi) && !newwin)
	    flags |= WSP_NEWLOC;

	if (win_split(0, flags) == FAIL)
	    return FAIL;

	*opened_window = TRUE;

	if (curwin->w_height < p_hh)
	    win_setheight((int)p_hh);

	
	
	
	if (IS_LL_STACK(qi) && !newwin)
	    win_set_loclist(curwin, qi);
    }

    if (!p_im)
	restart_edit = 0;	    

    return OK;
}


    static win_T * qf_find_win_with_loclist(qf_info_T *ll)
{
    win_T	*wp;

    FOR_ALL_WINDOWS(wp)
	if (wp->w_llist == ll && !bt_quickfix(wp->w_buffer))
	    return wp;

    return NULL;
}


    static win_T * qf_find_win_with_normal_buf(void)
{
    win_T	*wp;

    FOR_ALL_WINDOWS(wp)
	if (bt_normal(wp->w_buffer))
	    return wp;

    return NULL;
}


    static int qf_goto_tabwin_with_file(int fnum)
{
    tabpage_T	*tp;
    win_T	*wp;

    FOR_ALL_TAB_WINDOWS(tp, wp)
	if (wp->w_buffer->b_fnum == fnum)
	{
	    goto_tabpage_win(tp, wp);
	    return TRUE;
	}

    return FALSE;
}


    static int qf_open_new_file_win(qf_info_T *ll_ref)
{
    int		flags;

    flags = WSP_ABOVE;
    if (ll_ref != NULL)
	flags |= WSP_NEWLOC;
    if (win_split(0, flags) == FAIL)
	return FAIL;		
    p_swb = empty_option;	
    swb_flags = 0;
    RESET_BINDING(curwin);
    if (ll_ref != NULL)
	
	
	win_set_loclist(curwin, ll_ref);
    return OK;
}


    static void qf_goto_win_with_ll_file(win_T *use_win, int qf_fnum, qf_info_T *ll_ref)
{
    win_T	*win = use_win;

    if (win == NULL)
    {
	
	FOR_ALL_WINDOWS(win)
	    if (win->w_buffer->b_fnum == qf_fnum)
		break;
	if (win == NULL)
	{
	    
	    win = curwin;
	    do {
		if (bt_normal(win->w_buffer))
		    break;
		if (win->w_prev == NULL)
		    win = lastwin;	
		else win = win->w_prev;
	    } while (win != curwin);
	}
    }
    win_goto(win);

    
    
    if (win->w_llist == NULL && ll_ref != NULL)
	win_set_loclist(win, ll_ref);
}


    static void qf_goto_win_with_qfl_file(int qf_fnum)
{
    win_T	*win;
    win_T	*altwin;

    win = curwin;
    altwin = NULL;
    for (;;)
    {
	if (win->w_buffer->b_fnum == qf_fnum)
	    break;
	if (win->w_prev == NULL)
	    win = lastwin;	
	else win = win->w_prev;

	if (IS_QF_WINDOW(win))
	{
	    
	    
	    
	    if ((swb_flags & SWB_USELAST) && win_valid(prevwin))
		win = prevwin;
	    else if (altwin != NULL)
		win = altwin;
	    else if (curwin->w_prev != NULL)
		win = curwin->w_prev;
	    else win = curwin->w_next;
	    break;
	}

	
	if (altwin == NULL && !win->w_p_pvw && bt_normal(win->w_buffer))
	    altwin = win;
    }

    win_goto(win);
}


    static int qf_jump_to_usable_window(int qf_fnum, int newwin, int *opened_window)
{
    win_T	*usable_wp = NULL;
    int		usable_win = FALSE;
    qf_info_T	*ll_ref = NULL;

    
    
    
    if (!newwin)
	ll_ref = curwin->w_llist_ref;

    if (ll_ref != NULL)
    {
	
	usable_wp = qf_find_win_with_loclist(ll_ref);
	if (usable_wp != NULL)
	    usable_win = TRUE;
    }

    if (!usable_win)
    {
	
	win_T	*win = qf_find_win_with_normal_buf();
	if (win != NULL)
	    usable_win = TRUE;
    }

    
    
    if (!usable_win && (swb_flags & SWB_USETAB))
	usable_win = qf_goto_tabwin_with_file(qf_fnum);

    
    
    if ((ONE_WINDOW && bt_quickfix(curbuf)) || !usable_win || newwin)
    {
	if (qf_open_new_file_win(ll_ref) != OK)
	    return FAIL;
	*opened_window = TRUE;	
    }
    else {
	if (curwin->w_llist_ref != NULL)	
	    qf_goto_win_with_ll_file(usable_wp, qf_fnum, ll_ref);
	else					 qf_goto_win_with_qfl_file(qf_fnum);
    }

    return OK;
}


    static int qf_jump_edit_buffer( qf_info_T	*qi, qfline_T	*qf_ptr, int		forceit, int		prev_winid, int		*opened_window)





{
    qf_list_T	*qfl = qf_get_curlist(qi);
    int		old_changedtick = qfl->qf_changedtick;
    qfltype_T	qfl_type = qfl->qfl_type;
    int		retval = OK;
    int		old_qf_curlist = qi->qf_curlist;
    int		save_qfid = qfl->qf_id;

    if (qf_ptr->qf_type == 1)
    {
	
	
	if (!can_abandon(curbuf, forceit))
	{
	    no_write_message();
	    return FAIL;
	}

	retval = do_ecmd(qf_ptr->qf_fnum, NULL, NULL, NULL, (linenr_T)1, ECMD_HIDE + ECMD_SET_HELP, prev_winid == curwin->w_id ? curwin : NULL);

    }
    else retval = buflist_getfile(qf_ptr->qf_fnum, (linenr_T)1, GETF_SETMARK | GETF_SWITCH, forceit);


    
    
    if (qfl_type == QFLT_LOCATION)
    {
	win_T	*wp = win_id2wp(prev_winid);

	if (wp == NULL && curwin->w_llist != qi)
	{
	    emsg(_(e_current_window_was_closed));
	    *opened_window = FALSE;
	    return NOTDONE;
	}
    }

    if (qfl_type == QFLT_QUICKFIX && !qflist_valid(NULL, save_qfid))
    {
	emsg(_(e_current_quickfix_list_was_changed));
	return NOTDONE;
    }

    
    
    if (old_qf_curlist != qi->qf_curlist || old_changedtick != qfl->qf_changedtick || !is_qf_entry_present(qfl, qf_ptr))

    {
	if (qfl_type == QFLT_QUICKFIX)
	    emsg(_(e_current_quickfix_list_was_changed));
	else emsg(_(e_current_location_list_was_changed));
	return NOTDONE;
    }

    return retval;
}


    static void qf_jump_goto_line( linenr_T	qf_lnum, int		qf_col, char_u		qf_viscol, char_u		*qf_pattern)




{
    linenr_T		i;

    if (qf_pattern == NULL)
    {
	
	i = qf_lnum;
	if (i > 0)
	{
	    if (i > curbuf->b_ml.ml_line_count)
		i = curbuf->b_ml.ml_line_count;
	    curwin->w_cursor.lnum = i;
	}
	if (qf_col > 0)
	{
	    curwin->w_cursor.coladd = 0;
	    if (qf_viscol == TRUE)
		coladvance(qf_col - 1);
	    else curwin->w_cursor.col = qf_col - 1;
	    curwin->w_set_curswant = TRUE;
	    check_cursor();
	}
	else beginline(BL_WHITE | BL_FIX);
    }
    else {
	pos_T save_cursor;

	
	save_cursor = curwin->w_cursor;
	curwin->w_cursor.lnum = 0;
	if (!do_search(NULL, '/', '/', qf_pattern, (long)1, SEARCH_KEEP, NULL))
	    curwin->w_cursor = save_cursor;
    }
}


    static void qf_jump_print_msg( qf_info_T	*qi, int		qf_index, qfline_T	*qf_ptr, buf_T		*old_curbuf, linenr_T	old_lnum)





{
    linenr_T		i;
    int			len;

    
    
    if (!msg_scrolled)
	update_topline_redraw();
    sprintf((char *)IObuff, _("(%d of %d)%s%s: "), qf_index, qf_get_curlist(qi)->qf_count, qf_ptr->qf_cleared ? _(" (line deleted)") : "", (char *)qf_types(qf_ptr->qf_type, qf_ptr->qf_nr));


    
    len = (int)STRLEN(IObuff);
    qf_fmt_text(skipwhite(qf_ptr->qf_text), IObuff + len, IOSIZE - len);

    
    
    
    i = msg_scroll;
    if (curbuf == old_curbuf && curwin->w_cursor.lnum == old_lnum)
	msg_scroll = TRUE;
    else if (!msg_scrolled && shortmess(SHM_OVERALL))
	msg_scroll = FALSE;
    msg_attr_keep((char *)IObuff, 0, TRUE);
    msg_scroll = i;
}


    static int qf_jump_open_window( qf_info_T	*qi, qfline_T	*qf_ptr, int		newwin, int		*opened_window)




{
    qf_list_T	*qfl = qf_get_curlist(qi);
    int		old_changedtick = qfl->qf_changedtick;
    int		old_qf_curlist = qi->qf_curlist;
    qfltype_T	qfl_type = qfl->qfl_type;

    
    if (qf_ptr->qf_type == 1 && (!bt_help(curwin->w_buffer)
						      || cmdmod.cmod_tab != 0))
	if (jump_to_help_window(qi, newwin, opened_window) == FAIL)
	    return FAIL;
    if (old_qf_curlist != qi->qf_curlist || old_changedtick != qfl->qf_changedtick || !is_qf_entry_present(qfl, qf_ptr))

    {
	if (qfl_type == QFLT_QUICKFIX)
	    emsg(_(e_current_quickfix_list_was_changed));
	else emsg(_(e_current_location_list_was_changed));
	return FAIL;
    }

    
    
    if (bt_quickfix(curbuf) && !*opened_window)
    {
	
	
	if (qf_ptr->qf_fnum == 0)
	    return NOTDONE;

	if (qf_jump_to_usable_window(qf_ptr->qf_fnum, newwin, opened_window) == FAIL)
	    return FAIL;
    }
    if (old_qf_curlist != qi->qf_curlist || old_changedtick != qfl->qf_changedtick || !is_qf_entry_present(qfl, qf_ptr))

    {
	if (qfl_type == QFLT_QUICKFIX)
	    emsg(_(e_current_quickfix_list_was_changed));
	else emsg(_(e_current_location_list_was_changed));
	return FAIL;
    }

    return OK;
}


    static int qf_jump_to_buffer( qf_info_T	*qi, int		qf_index, qfline_T	*qf_ptr, int		forceit, int		prev_winid, int		*opened_window, int		openfold, int		print_message)








{
    buf_T	*old_curbuf;
    linenr_T	old_lnum;
    int		retval = OK;

    
    
    old_curbuf = curbuf;
    old_lnum = curwin->w_cursor.lnum;

    if (qf_ptr->qf_fnum != 0)
    {
	retval = qf_jump_edit_buffer(qi, qf_ptr, forceit, prev_winid, opened_window);
	if (retval != OK)
	    return retval;
    }

    
    if (curbuf == old_curbuf)
	setpcmark();

    qf_jump_goto_line(qf_ptr->qf_lnum, qf_ptr->qf_col, qf_ptr->qf_viscol, qf_ptr->qf_pattern);


    if ((fdo_flags & FDO_QUICKFIX) && openfold)
	foldOpenCursor();

    if (print_message)
	qf_jump_print_msg(qi, qf_index, qf_ptr, old_curbuf, old_lnum);

    return retval;
}


    void qf_jump(qf_info_T	*qi, int		dir, int		errornr, int		forceit)



{
    qf_jump_newwin(qi, dir, errornr, forceit, FALSE);
}


    static void qf_jump_newwin(qf_info_T	*qi, int		dir, int		errornr, int		forceit, int		newwin)




{
    qf_list_T		*qfl;
    qfline_T		*qf_ptr;
    qfline_T		*old_qf_ptr;
    int			qf_index;
    int			old_qf_index;
    char_u		*old_swb = p_swb;
    unsigned		old_swb_flags = swb_flags;
    int			prev_winid;
    int			opened_window = FALSE;
    int			print_message = TRUE;
    int			old_KeyTyped = KeyTyped; 
    int			retval = OK;

    if (qi == NULL)
	qi = &ql_info;

    if (qf_stack_empty(qi) || qf_list_empty(qf_get_curlist(qi)))
    {
	emsg(_(e_no_errors));
	return;
    }

    incr_quickfix_busy();

    qfl = qf_get_curlist(qi);

    qf_ptr = qfl->qf_ptr;
    old_qf_ptr = qf_ptr;
    qf_index = qfl->qf_index;
    old_qf_index = qf_index;

    qf_ptr = qf_get_entry(qfl, errornr, dir, &qf_index);
    if (qf_ptr == NULL)
    {
	qf_ptr = old_qf_ptr;
	qf_index = old_qf_index;
	goto theend;
    }

    qfl->qf_index = qf_index;
    qfl->qf_ptr = qf_ptr;
    if (qf_win_pos_update(qi, old_qf_index))
	
	
	print_message = FALSE;

    prev_winid = curwin->w_id;

    retval = qf_jump_open_window(qi, qf_ptr, newwin, &opened_window);
    if (retval == FAIL)
	goto failed;
    if (retval == NOTDONE)
	goto theend;

    retval = qf_jump_to_buffer(qi, qf_index, qf_ptr, forceit, prev_winid, &opened_window, old_KeyTyped, print_message);
    if (retval == NOTDONE)
    {
	
	qi = NULL;
	qf_ptr = NULL;
    }

    if (retval != OK)
    {
	if (opened_window)
	    win_close(curwin, TRUE);    
	if (qf_ptr != NULL && qf_ptr->qf_fnum != 0)
	{
	    
	    
failed:
	    qf_ptr = old_qf_ptr;
	    qf_index = old_qf_index;
	}
    }
theend:
    if (qi != NULL)
    {
	qfl->qf_ptr = qf_ptr;
	qfl->qf_index = qf_index;
    }
    if (p_swb != old_swb && p_swb == empty_option)
    {
	
	
	p_swb = old_swb;
	swb_flags = old_swb_flags;
    }
    decr_quickfix_busy();
}


static int	qfFileAttr;
static int	qfSepAttr;
static int	qfLineAttr;


    static void qf_list_entry(qfline_T *qfp, int qf_idx, int cursel)
{
    char_u	*fname;
    buf_T	*buf;
    int		filter_entry;

    fname = NULL;
    if (qfp->qf_module != NULL && *qfp->qf_module != NUL)
	vim_snprintf((char *)IObuff, IOSIZE, "%2d %s", qf_idx, (char *)qfp->qf_module);
    else {
	if (qfp->qf_fnum != 0 && (buf = buflist_findnr(qfp->qf_fnum)) != NULL)
	{
	    fname = buf->b_fname;
	    if (qfp->qf_type == 1)	
		fname = gettail(fname);
	}
	if (fname == NULL)
	    sprintf((char *)IObuff, "%2d", qf_idx);
	else vim_snprintf((char *)IObuff, IOSIZE, "%2d %s", qf_idx, (char *)fname);

    }

    
    
    
    filter_entry = TRUE;
    if (qfp->qf_module != NULL && *qfp->qf_module != NUL)
	filter_entry &= message_filtered(qfp->qf_module);
    if (filter_entry && fname != NULL)
	filter_entry &= message_filtered(fname);
    if (filter_entry && qfp->qf_pattern != NULL)
	filter_entry &= message_filtered(qfp->qf_pattern);
    if (filter_entry)
	filter_entry &= message_filtered(qfp->qf_text);
    if (filter_entry)
	return;

    msg_putchar('\n');
    msg_outtrans_attr(IObuff, cursel ? HL_ATTR(HLF_QFL) : qfFileAttr);

    if (qfp->qf_lnum != 0)
	msg_puts_attr(":", qfSepAttr);
    if (qfp->qf_lnum == 0)
	IObuff[0] = NUL;
    else qf_range_text(qfp, IObuff, IOSIZE);
    sprintf((char *)IObuff + STRLEN(IObuff), "%s", (char *)qf_types(qfp->qf_type, qfp->qf_nr));
    msg_puts_attr((char *)IObuff, qfLineAttr);
    msg_puts_attr(":", qfSepAttr);
    if (qfp->qf_pattern != NULL)
    {
	qf_fmt_text(qfp->qf_pattern, IObuff, IOSIZE);
	msg_puts((char *)IObuff);
	msg_puts_attr(":", qfSepAttr);
    }
    msg_puts(" ");

    {
	char_u *tbuf = IObuff;
	size_t	tbuflen = IOSIZE;
	size_t	len = STRLEN(qfp->qf_text) + 3;

	if (len > IOSIZE)
	{
	    tbuf = alloc(len);
	    if (tbuf != NULL)
		tbuflen = len;
	    else tbuf = IObuff;
	}

	
	
	
	qf_fmt_text((fname != NULL || qfp->qf_lnum != 0)
				    ? skipwhite(qfp->qf_text) : qfp->qf_text, tbuf, (int)tbuflen);
	msg_prt_line(tbuf, FALSE);

	if (tbuf != IObuff)
	    vim_free(tbuf);
    }
    out_flush();		
}


    void qf_list(exarg_T *eap)
{
    qf_list_T	*qfl;
    qfline_T	*qfp;
    int		i;
    int		idx1 = 1;
    int		idx2 = -1;
    char_u	*arg = eap->arg;
    int		plus = FALSE;
    int		all = eap->forceit;	
					
    qf_info_T	*qi;

    if ((qi = qf_cmd_get_stack(eap, TRUE)) == NULL)
	return;

    if (qf_stack_empty(qi) || qf_list_empty(qf_get_curlist(qi)))
    {
	emsg(_(e_no_errors));
	return;
    }
    if (*arg == '+')
    {
	++arg;
	plus = TRUE;
    }
    if (!get_list_range(&arg, &idx1, &idx2) || *arg != NUL)
    {
	semsg(_(e_trailing_characters_str), arg);
	return;
    }
    qfl = qf_get_curlist(qi);
    if (plus)
    {
	i = qfl->qf_index;
	idx2 = i + idx1;
	idx1 = i;
    }
    else {
	i = qfl->qf_count;
	if (idx1 < 0)
	    idx1 = (-idx1 > i) ? 0 : idx1 + i + 1;
	if (idx2 < 0)
	    idx2 = (-idx2 > i) ? 0 : idx2 + i + 1;
    }

    
    shorten_fnames(FALSE);

    
    
    qfFileAttr = syn_name2attr((char_u *)"qfFileName");
    if (qfFileAttr == 0)
	qfFileAttr = HL_ATTR(HLF_D);
    qfSepAttr = syn_name2attr((char_u *)"qfSeparator");
    if (qfSepAttr == 0)
	qfSepAttr = HL_ATTR(HLF_D);
    qfLineAttr = syn_name2attr((char_u *)"qfLineNr");
    if (qfLineAttr == 0)
	qfLineAttr = HL_ATTR(HLF_N);

    if (qfl->qf_nonevalid)
	all = TRUE;
    FOR_ALL_QFL_ITEMS(qfl, qfp, i)
    {
	if ((qfp->qf_valid || all) && idx1 <= i && i <= idx2)
	    qf_list_entry(qfp, i, i == qfl->qf_index);

	ui_breakcheck();
    }
}


    static void qf_fmt_text(char_u *text, char_u *buf, int bufsize)
{
    int		i;
    char_u	*p = text;

    for (i = 0; *p != NUL && i < bufsize - 1; ++i)
    {
	if (*p == '\n')
	{
	    buf[i] = ' ';
	    while (*++p != NUL)
		if (!VIM_ISWHITE(*p) && *p != '\n')
		    break;
	}
	else buf[i] = *p++;
    }
    buf[i] = NUL;
}


    static void qf_range_text(qfline_T *qfp, char_u *buf, int bufsize)
{
    int len;
    vim_snprintf((char *)buf, bufsize, "%ld", qfp->qf_lnum);
    len = (int)STRLEN(buf);

    if (qfp->qf_end_lnum > 0 && qfp->qf_lnum != qfp->qf_end_lnum)
    {
	vim_snprintf((char *)buf + len, bufsize - len, "-%ld", qfp->qf_end_lnum);
	len += (int)STRLEN(buf + len);
    }
    if (qfp->qf_col > 0)
    {
	vim_snprintf((char *)buf + len, bufsize - len, " col %d", qfp->qf_col);
	len += (int)STRLEN(buf + len);
	if (qfp->qf_end_col > 0 && qfp->qf_col != qfp->qf_end_col)
	{
	    vim_snprintf((char *)buf + len, bufsize - len, "-%d", qfp->qf_end_col);
	    len += (int)STRLEN(buf + len);
	}
    }
    buf[len] = NUL;
}


    static void qf_msg(qf_info_T *qi, int which, char *lead)
{
    char   *title = (char *)qi->qf_lists[which].qf_title;
    int    count = qi->qf_lists[which].qf_count;
    char_u buf[IOSIZE];

    vim_snprintf((char *)buf, IOSIZE, _("%serror list %d of %d; %d errors "), lead, which + 1, qi->qf_listcount, count);




    if (title != NULL)
    {
	size_t	len = STRLEN(buf);

	if (len < 34)
	{
	    vim_memset(buf + len, ' ', 34 - len);
	    buf[34] = NUL;
	}
	vim_strcat(buf, (char_u *)title, IOSIZE);
    }
    trunc_string(buf, buf, Columns - 1, IOSIZE);
    msg((char *)buf);
}


    void qf_age(exarg_T *eap)
{
    qf_info_T	*qi;
    int		count;

    if ((qi = qf_cmd_get_stack(eap, TRUE)) == NULL)
	return;

    if (eap->addr_count != 0)
	count = eap->line2;
    else count = 1;
    while (count--)
    {
	if (eap->cmdidx == CMD_colder || eap->cmdidx == CMD_lolder)
	{
	    if (qi->qf_curlist == 0)
	    {
		emsg(_(e_at_bottom_of_quickfix_stack));
		break;
	    }
	    --qi->qf_curlist;
	}
	else {
	    if (qi->qf_curlist >= qi->qf_listcount - 1)
	    {
		emsg(_(e_at_top_of_quickfix_stack));
		break;
	    }
	    ++qi->qf_curlist;
	}
    }
    qf_msg(qi, qi->qf_curlist, "");
    qf_update_buffer(qi, NULL);
}


    void qf_history(exarg_T *eap)
{
    qf_info_T	*qi = qf_cmd_get_stack(eap, FALSE);
    int		i;

    if (eap->addr_count > 0)
    {
	if (qi == NULL)
	{
	    emsg(_(e_no_location_list));
	    return;
	}

	
	if (eap->line2 > 0 && eap->line2 <= qi->qf_listcount)
	{
	    qi->qf_curlist = eap->line2 - 1;
	    qf_msg(qi, qi->qf_curlist, "");
	    qf_update_buffer(qi, NULL);
	}
	else emsg(_(e_invalid_range));

	return;
    }

    if (qf_stack_empty(qi))
	msg(_("No entries"));
    else for (i = 0; i < qi->qf_listcount; ++i)
	    qf_msg(qi, i, i == qi->qf_curlist ? "> " : "  ");
}


    static void qf_free_items(qf_list_T *qfl)
{
    qfline_T	*qfp;
    qfline_T	*qfpnext;
    int		stop = FALSE;

    while (qfl->qf_count && qfl->qf_start != NULL)
    {
	qfp = qfl->qf_start;
	qfpnext = qfp->qf_next;
	if (!stop)
	{
	    vim_free(qfp->qf_module);
	    vim_free(qfp->qf_text);
	    vim_free(qfp->qf_pattern);
	    stop = (qfp == qfpnext);
	    vim_free(qfp);
	    if (stop)
		
		
		
		qfl->qf_count = 1;
	}
	qfl->qf_start = qfpnext;
	--qfl->qf_count;
    }

    qfl->qf_index = 0;
    qfl->qf_start = NULL;
    qfl->qf_last = NULL;
    qfl->qf_ptr = NULL;
    qfl->qf_nonevalid = TRUE;

    qf_clean_dir_stack(&qfl->qf_dir_stack);
    qfl->qf_directory = NULL;
    qf_clean_dir_stack(&qfl->qf_file_stack);
    qfl->qf_currfile = NULL;
    qfl->qf_multiline = FALSE;
    qfl->qf_multiignore = FALSE;
    qfl->qf_multiscan = FALSE;
}


    static void qf_free(qf_list_T *qfl)
{
    qf_free_items(qfl);

    VIM_CLEAR(qfl->qf_title);
    free_tv(qfl->qf_ctx);
    qfl->qf_ctx = NULL;
    free_callback(&qfl->qf_qftf_cb);
    qfl->qf_id = 0;
    qfl->qf_changedtick = 0L;
}


   void qf_mark_adjust( win_T	*wp, linenr_T	line1, linenr_T	line2, long	amount, long	amount_after)





{
    int		i;
    qfline_T	*qfp;
    int		idx;
    qf_info_T	*qi = &ql_info;
    int		found_one = FALSE;
    int		buf_has_flag = wp == NULL ? BUF_HAS_QF_ENTRY : BUF_HAS_LL_ENTRY;

    if (!(curbuf->b_has_qf_entry & buf_has_flag))
	return;
    if (wp != NULL)
    {
	if (wp->w_llist == NULL)
	    return;
	qi = wp->w_llist;
    }

    for (idx = 0; idx < qi->qf_listcount; ++idx)
    {
	qf_list_T	*qfl = qf_get_list(qi, idx);

	if (!qf_list_empty(qfl))
	    FOR_ALL_QFL_ITEMS(qfl, qfp, i)
		if (qfp->qf_fnum == curbuf->b_fnum)
		{
		    found_one = TRUE;
		    if (qfp->qf_lnum >= line1 && qfp->qf_lnum <= line2)
		    {
			if (amount == MAXLNUM)
			    qfp->qf_cleared = TRUE;
			else qfp->qf_lnum += amount;
		    }
		    else if (amount_after && qfp->qf_lnum > line2)
			qfp->qf_lnum += amount_after;
		}
    }

    if (!found_one)
	curbuf->b_has_qf_entry &= ~buf_has_flag;
}


    static char_u * qf_types(int c, int nr)
{
    static char_u	buf[20];
    static char_u	cc[3];
    char_u		*p;

    if (c == 'W' || c == 'w')
	p = (char_u *)" warning";
    else if (c == 'I' || c == 'i')
	p = (char_u *)" info";
    else if (c == 'N' || c == 'n')
	p = (char_u *)" note";
    else if (c == 'E' || c == 'e' || (c == 0 && nr > 0))
	p = (char_u *)" error";
    else if (c == 0 || c == 1)
	p = (char_u *)"";
    else {
	cc[0] = ' ';
	cc[1] = c;
	cc[2] = NUL;
	p = cc;
    }

    if (nr <= 0)
	return p;

    sprintf((char *)buf, "%s %3d", (char *)p, nr);
    return buf;
}


    void qf_view_result(int split)
{
    qf_info_T   *qi = &ql_info;

    if (IS_LL_WINDOW(curwin))
	qi = GET_LOC_LIST(curwin);

    if (qf_list_empty(qf_get_curlist(qi)))
    {
	emsg(_(e_no_errors));
	return;
    }

    if (split)
    {
	
	qf_jump_newwin(qi, 0, (long)curwin->w_cursor.lnum, FALSE, TRUE);
	do_cmdline_cmd((char_u *) "clearjumps");
	return;
    }

    do_cmdline_cmd((char_u *)(IS_LL_WINDOW(curwin) ? ".ll" : ".cc"));
}


    void ex_cwindow(exarg_T *eap)
{
    qf_info_T	*qi;
    qf_list_T	*qfl;
    win_T	*win;

    if ((qi = qf_cmd_get_stack(eap, TRUE)) == NULL)
	return;

    qfl = qf_get_curlist(qi);

    
    win = qf_find_win(qi);

    
    
    
    if (qf_stack_empty(qi)
	    || qfl->qf_nonevalid || qf_list_empty(qfl))
    {
	if (win != NULL)
	    ex_cclose(eap);
    }
    else if (win == NULL)
	ex_copen(eap);
}


    void ex_cclose(exarg_T *eap)
{
    win_T	*win = NULL;
    qf_info_T	*qi;

    if ((qi = qf_cmd_get_stack(eap, FALSE)) == NULL)
	return;

    
    win = qf_find_win(qi);
    if (win != NULL)
	win_close(win, FALSE);
}


    static void qf_set_title_var(qf_list_T *qfl)
{
    if (qfl->qf_title != NULL)
	set_internal_string_var((char_u *)"w:quickfix_title", qfl->qf_title);
}


    static int qf_goto_cwindow(qf_info_T *qi, int resize, int sz, int vertsplit)
{
    win_T	*win;

    win = qf_find_win(qi);
    if (win == NULL)
	return FAIL;

    win_goto(win);
    if (resize)
    {
	if (vertsplit)
	{
	    if (sz != win->w_width)
		win_setwidth(sz);
	}
	else if (sz != win->w_height && win->w_height + win->w_status_height + tabline_height() < cmdline_row)
	    win_setheight(sz);
    }

    return OK;
}


    static void qf_set_cwindow_options(void)
{
    
    set_option_value_give_err((char_u *)"swf", 0L, NULL, OPT_LOCAL);
    set_option_value_give_err((char_u *)"bt", 0L, (char_u *)"quickfix", OPT_LOCAL);
    set_option_value_give_err((char_u *)"bh", 0L, (char_u *)"hide", OPT_LOCAL);
    RESET_BINDING(curwin);

    curwin->w_p_diff = FALSE;


    set_option_value_give_err((char_u *)"fdm", 0L, (char_u *)"manual", OPT_LOCAL);

}


    static int qf_open_new_cwindow(qf_info_T *qi, int height)
{
    buf_T	*qf_buf;
    win_T	*oldwin = curwin;
    tabpage_T	*prevtab = curtab;
    int		flags = 0;
    win_T	*win;

    qf_buf = qf_find_buf(qi);

    
    win = curwin;

    if (IS_QF_STACK(qi) && cmdmod.cmod_split == 0)
	
	
	win_goto(lastwin);
    
    if (cmdmod.cmod_split == 0)
	flags = WSP_BELOW;
    flags |= WSP_NEWLOC;
    if (win_split(height, flags) == FAIL)
	return FAIL;		
    RESET_BINDING(curwin);

    if (IS_LL_STACK(qi))
    {
	
	
	curwin->w_llist_ref = qi;
	qi->qf_refcount++;
    }

    if (oldwin != curwin)
	oldwin = NULL;  
    if (qf_buf != NULL)
    {
	
	if (do_ecmd(qf_buf->b_fnum, NULL, NULL, NULL, ECMD_ONE, ECMD_HIDE + ECMD_OLDBUF + ECMD_NOWINENTER, oldwin) == FAIL)
	    return FAIL;
    }
    else {
	
	if (do_ecmd(0, NULL, NULL, NULL, ECMD_ONE, ECMD_HIDE + ECMD_NOWINENTER, oldwin) == FAIL)
	    return FAIL;

	
	qi->qf_bufnr = curbuf->b_fnum;
    }

    
    
    
    if (!bt_quickfix(curbuf))
	qf_set_cwindow_options();

    
    
    if (curtab == prevtab && curwin->w_width == Columns)
	win_setheight(height);
    curwin->w_p_wfh = TRUE;	    
    if (win_valid(win))
	prevwin = win;

    return OK;
}


    void ex_copen(exarg_T *eap)
{
    qf_info_T	*qi;
    qf_list_T	*qfl;
    int		height;
    int		status = FAIL;
    int		lnum;

    if ((qi = qf_cmd_get_stack(eap, TRUE)) == NULL)
	return;

    incr_quickfix_busy();

    if (eap->addr_count != 0)
	height = eap->line2;
    else height = QF_WINHEIGHT;

    reset_VIsual_and_resel();			

    need_mouse_correct = TRUE;


    
    if (cmdmod.cmod_tab == 0)
	status = qf_goto_cwindow(qi, eap->addr_count != 0, height, cmdmod.cmod_split & WSP_VERT);
    if (status == FAIL)
	if (qf_open_new_cwindow(qi, height) == FAIL)
	{
	    decr_quickfix_busy();
	    return;
	}

    qfl = qf_get_curlist(qi);
    qf_set_title_var(qfl);
    
    
    lnum = qfl->qf_index;

    
    qf_fill_buffer(qfl, curbuf, NULL, curwin->w_id);

    decr_quickfix_busy();

    curwin->w_cursor.lnum = lnum;
    curwin->w_cursor.col = 0;
    check_cursor();
    update_topline();		
}


    static void qf_win_goto(win_T *win, linenr_T lnum)
{
    win_T	*old_curwin = curwin;

    curwin = win;
    curbuf = win->w_buffer;
    curwin->w_cursor.lnum = lnum;
    curwin->w_cursor.col = 0;
    curwin->w_cursor.coladd = 0;
    curwin->w_curswant = 0;
    update_topline();		
    redraw_later(UPD_VALID);
    curwin->w_redr_status = TRUE;	
    curwin = old_curwin;
    curbuf = curwin->w_buffer;
}


    void ex_cbottom(exarg_T *eap)
{
    qf_info_T	*qi;
    win_T	*win;

    if ((qi = qf_cmd_get_stack(eap, TRUE)) == NULL)
	return;

    win = qf_find_win(qi);
    if (win != NULL && win->w_cursor.lnum != win->w_buffer->b_ml.ml_line_count)
	qf_win_goto(win, win->w_buffer->b_ml.ml_line_count);
}


     linenr_T qf_current_entry(win_T *wp)
{
    qf_info_T	*qi = &ql_info;

    if (IS_LL_WINDOW(wp))
	
	qi = wp->w_llist_ref;

    return qf_get_curlist(qi)->qf_index;
}


    static int qf_win_pos_update( qf_info_T	*qi, int		old_qf_index)


{
    win_T	*win;
    int		qf_index = qf_get_curlist(qi)->qf_index;

    
    
    win = qf_find_win(qi);
    if (win != NULL && qf_index <= win->w_buffer->b_ml.ml_line_count && old_qf_index != qf_index)

    {
	if (qf_index > old_qf_index)
	{
	    win->w_redraw_top = old_qf_index;
	    win->w_redraw_bot = qf_index;
	}
	else {
	    win->w_redraw_top = qf_index;
	    win->w_redraw_bot = old_qf_index;
	}
	qf_win_goto(win, qf_index);
    }
    return win != NULL;
}


    static int is_qf_win(win_T *win, qf_info_T *qi)
{
    
    
    
    
    if (bt_quickfix(win->w_buffer))
	if ((IS_QF_STACK(qi) && win->w_llist_ref == NULL)
		|| (IS_LL_STACK(qi) && win->w_llist_ref == qi))
	    return TRUE;

    return FALSE;
}


    static win_T * qf_find_win(qf_info_T *qi)
{
    win_T	*win;

    FOR_ALL_WINDOWS(win)
	if (is_qf_win(win, qi))
	    return win;
    return NULL;
}


    static buf_T * qf_find_buf(qf_info_T *qi)
{
    tabpage_T	*tp;
    win_T	*win;

    if (qi->qf_bufnr != INVALID_QFBUFNR)
    {
	buf_T	*qfbuf;
	qfbuf = buflist_findnr(qi->qf_bufnr);
	if (qfbuf != NULL)
	    return qfbuf;
	
	qi->qf_bufnr = INVALID_QFBUFNR;
    }

    FOR_ALL_TAB_WINDOWS(tp, win)
	if (is_qf_win(win, qi))
	    return win->w_buffer;

    return NULL;
}


    int qf_process_qftf_option(void)
{
    return option_set_callback_func(p_qftf, &qftf_cb);
}


    static void qf_update_win_titlevar(qf_info_T *qi)
{
    qf_list_T	*qfl = qf_get_curlist(qi);
    tabpage_T	*tp;
    win_T	*win;
    win_T	*save_curwin = curwin;

    FOR_ALL_TAB_WINDOWS(tp, win)
    {
	if (is_qf_win(win, qi))
	{
	    curwin = win;
	    qf_set_title_var(qfl);
	}
    }
    curwin = save_curwin;
}


    static void qf_update_buffer(qf_info_T *qi, qfline_T *old_last)
{
    buf_T	*buf;
    win_T	*win;
    aco_save_T	aco;

    
    buf = qf_find_buf(qi);
    if (buf != NULL)
    {
	linenr_T	old_line_count = buf->b_ml.ml_line_count;
	int		qf_winid = 0;

	if (IS_LL_STACK(qi))
	{
	    if (curwin->w_llist == qi)
		win = curwin;
	    else {
		
		win = qf_find_win_with_loclist(qi);
		if (win == NULL)
		    
		    win = qf_find_win(qi);
		if (win == NULL)
		    return;
	    }
	    qf_winid = win->w_id;
	}

	if (old_last == NULL)
	    
	    aucmd_prepbuf(&aco, buf);

	qf_update_win_titlevar(qi);

	qf_fill_buffer(qf_get_curlist(qi), buf, old_last, qf_winid);
	++CHANGEDTICK(buf);

	if (old_last == NULL)
	{
	    (void)qf_win_pos_update(qi, 0);

	    
	    aucmd_restbuf(&aco);
	}

	
	
	if ((win = qf_find_win(qi)) != NULL && old_line_count < win->w_botline)
	    redraw_buf_later(buf, UPD_NOT_VALID);
    }
}


    static int qf_buf_add_line( buf_T		*buf, linenr_T	lnum, qfline_T	*qfp, char_u		*dirname, int		first_bufline, char_u		*qftf_str)






{
    int		len;
    buf_T	*errbuf;

    
    
    if (qftf_str != NULL && *qftf_str != NUL)
	vim_strncpy(IObuff, qftf_str, IOSIZE - 1);
    else {
	if (qfp->qf_module != NULL)
	{
	    vim_strncpy(IObuff, qfp->qf_module, IOSIZE - 1);
	    len = (int)STRLEN(IObuff);
	}
	else if (qfp->qf_fnum != 0 && (errbuf = buflist_findnr(qfp->qf_fnum)) != NULL && errbuf->b_fname != NULL)

	{
	    if (qfp->qf_type == 1)	
		vim_strncpy(IObuff, gettail(errbuf->b_fname), IOSIZE - 1);
	    else {
		
		
		
		if (first_bufline && (errbuf->b_sfname == NULL || mch_isFullName(errbuf->b_sfname)))
		{
		    if (*dirname == NUL)
			mch_dirname(dirname, MAXPATHL);
		    shorten_buf_fname(errbuf, dirname, FALSE);
		}
		vim_strncpy(IObuff, errbuf->b_fname, IOSIZE - 1);
	    }
	    len = (int)STRLEN(IObuff);
	}
	else len = 0;

	if (len < IOSIZE - 1)
	    IObuff[len++] = '|';

	if (qfp->qf_lnum > 0)
	{
	    qf_range_text(qfp, IObuff + len, IOSIZE - len);
	    len += (int)STRLEN(IObuff + len);

	    vim_snprintf((char *)IObuff + len, IOSIZE - len, "%s", (char *)qf_types(qfp->qf_type, qfp->qf_nr));
	    len += (int)STRLEN(IObuff + len);
	}
	else if (qfp->qf_pattern != NULL)
	{
	    qf_fmt_text(qfp->qf_pattern, IObuff + len, IOSIZE - len);
	    len += (int)STRLEN(IObuff + len);
	}
	if (len < IOSIZE - 2)
	{
	    IObuff[len++] = '|';
	    IObuff[len++] = ' ';
	}

	
	
	
	qf_fmt_text(len > 3 ? skipwhite(qfp->qf_text) : qfp->qf_text, IObuff + len, IOSIZE - len);
    }

    if (ml_append_buf(buf, lnum, IObuff, (colnr_T)STRLEN(IObuff) + 1, FALSE) == FAIL)
	return FAIL;

    return OK;
}


    static list_T * call_qftf_func(qf_list_T *qfl, int qf_winid, long start_idx, long end_idx)
{
    callback_T	*cb = &qftf_cb;
    list_T	*qftf_list = NULL;
    static int	recursive = FALSE;

    if (recursive)
	return NULL;  
    recursive = TRUE;

    
    
    
    if (qfl->qf_qftf_cb.cb_name != NULL)
	cb = &qfl->qf_qftf_cb;
    if (cb->cb_name != NULL)
    {
	typval_T	args[1];
	dict_T		*d;
	typval_T	rettv;

	
	if ((d = dict_alloc_lock(VAR_FIXED)) == NULL)
	{
	    recursive = FALSE;
	    return NULL;
	}
	dict_add_number(d, "quickfix", (long)IS_QF_LIST(qfl));
	dict_add_number(d, "winid", (long)qf_winid);
	dict_add_number(d, "id", (long)qfl->qf_id);
	dict_add_number(d, "start_idx", start_idx);
	dict_add_number(d, "end_idx", end_idx);
	++d->dv_refcount;
	args[0].v_type = VAR_DICT;
	args[0].vval.v_dict = d;

	qftf_list = NULL;
	if (call_callback(cb, 0, &rettv, 1, args) != FAIL)
	{
	    if (rettv.v_type == VAR_LIST)
	    {
		qftf_list = rettv.vval.v_list;
		qftf_list->lv_refcount++;
	    }
	    clear_tv(&rettv);
	}
	dict_unref(d);
    }

    recursive = FALSE;
    return qftf_list;
}


    static void qf_fill_buffer(qf_list_T *qfl, buf_T *buf, qfline_T *old_last, int qf_winid)
{
    linenr_T	lnum;
    qfline_T	*qfp;
    int		old_KeyTyped = KeyTyped;
    list_T	*qftf_list = NULL;
    listitem_T	*qftf_li = NULL;

    if (old_last == NULL)
    {
	if (buf != curbuf)
	{
	    internal_error("qf_fill_buffer()");
	    return;
	}

	
	while ((curbuf->b_ml.ml_flags & ML_EMPTY) == 0)
	    (void)ml_delete((linenr_T)1);
    }

    
    if (qfl != NULL)
    {
	char_u		dirname[MAXPATHL];
	int		invalid_val = FALSE;
	int		prev_bufnr = -1;

	*dirname = NUL;

	
	if (old_last == NULL)
	{
	    qfp = qfl->qf_start;
	    lnum = 0;
	}
	else {
	    if (old_last->qf_next != NULL)
		qfp = old_last->qf_next;
	    else qfp = old_last;
	    lnum = buf->b_ml.ml_line_count;
	}

	qftf_list = call_qftf_func(qfl, qf_winid, (long)(lnum + 1), (long)qfl->qf_count);
	if (qftf_list != NULL)
	    qftf_li = qftf_list->lv_first;

	while (lnum < qfl->qf_count)
	{
	    char_u	*qftf_str = NULL;

	    
	    
	    
	    if (qftf_li != NULL && !invalid_val)
	    {
		qftf_str = tv_get_string_chk(&qftf_li->li_tv);
		if (qftf_str == NULL)
		    invalid_val = TRUE;
	    }

	    if (qf_buf_add_line(buf, lnum, qfp, dirname, prev_bufnr != qfp->qf_fnum, qftf_str) == FAIL)
		break;

	    prev_bufnr = qfp->qf_fnum;
	    ++lnum;
	    qfp = qfp->qf_next;
	    if (qfp == NULL)
		break;

	    if (qftf_li != NULL)
		qftf_li = qftf_li->li_next;
	}

	if (old_last == NULL)
	    
	    (void)ml_delete(lnum + 1);
    }

    
    check_lnums(TRUE);

    if (old_last == NULL)
    {
	
	
	
	++curbuf_lock;
	set_option_value_give_err((char_u *)"ft", 0L, (char_u *)"qf", OPT_LOCAL);
	curbuf->b_p_ma = FALSE;

	keep_filetype = TRUE;		
	apply_autocmds(EVENT_BUFREADPOST, (char_u *)"quickfix", NULL, FALSE, curbuf);
	apply_autocmds(EVENT_BUFWINENTER, (char_u *)"quickfix", NULL, FALSE, curbuf);
	keep_filetype = FALSE;
	--curbuf_lock;

	
	redraw_curbuf_later(UPD_NOT_VALID);
    }

    
    KeyTyped = old_KeyTyped;
}


    static void qf_list_changed(qf_list_T *qfl)
{
    qfl->qf_changedtick++;
}


    static int qf_id2nr(qf_info_T *qi, int_u qfid)
{
    int		qf_idx;

    for (qf_idx = 0; qf_idx < qi->qf_listcount; qf_idx++)
	if (qi->qf_lists[qf_idx].qf_id == qfid)
	    return qf_idx;
    return INVALID_QFIDX;
}


    static int qf_restore_list(qf_info_T *qi, int_u save_qfid)
{
    int curlist;

    if (qf_get_curlist(qi)->qf_id != save_qfid)
    {
	curlist = qf_id2nr(qi, save_qfid);
	if (curlist < 0)
	    
	    return FAIL;
	qi->qf_curlist = curlist;
    }
    return OK;
}


    static void qf_jump_first(qf_info_T *qi, int_u save_qfid, int forceit)
{
    if (qf_restore_list(qi, save_qfid) == FAIL)
	return;

    
    if (!qf_list_empty(qf_get_curlist(qi)))
	qf_jump(qi, 0, 0, forceit);
}


    int grep_internal(cmdidx_T cmdidx)
{
    return ((cmdidx == CMD_grep || cmdidx == CMD_lgrep || cmdidx == CMD_grepadd || cmdidx == CMD_lgrepadd)


	    && STRCMP("internal", *curbuf->b_p_gp == NUL ? p_gp : curbuf->b_p_gp) == 0);
}


    static char_u * make_get_auname(cmdidx_T cmdidx)
{
    switch (cmdidx)
    {
	case CMD_make:	    return (char_u *)"make";
	case CMD_lmake:	    return (char_u *)"lmake";
	case CMD_grep:	    return (char_u *)"grep";
	case CMD_lgrep:	    return (char_u *)"lgrep";
	case CMD_grepadd:   return (char_u *)"grepadd";
	case CMD_lgrepadd:  return (char_u *)"lgrepadd";
	default: return NULL;
    }
}


    static char_u * get_mef_name(void)
{
    char_u	*p;
    char_u	*name;
    static int	start = -1;
    static int	off = 0;

    stat_T	sb;


    if (*p_mef == NUL)
    {
	name = vim_tempname('e', FALSE);
	if (name == NULL)
	    emsg(_(e_cant_get_temp_file_name));
	return name;
    }

    for (p = p_mef; *p; ++p)
	if (p[0] == '#' && p[1] == '#')
	    break;

    if (*p == NUL)
	return vim_strsave(p_mef);

    
    for (;;)
    {
	if (start == -1)
	    start = mch_get_pid();
	else off += 19;

	name = alloc_id(STRLEN(p_mef) + 30, aid_qf_mef_name);
	if (name == NULL)
	    break;
	STRCPY(name, p_mef);
	sprintf((char *)name + (p - p_mef), "%d%d", start, off);
	STRCAT(name, p + 2);
	if (mch_getperm(name) < 0   && mch_lstat((char *)name, &sb) < 0  )




	    break;
	vim_free(name);
    }
    return name;
}


    static char_u * make_get_fullcmd(char_u *makecmd, char_u *fname)
{
    char_u	*cmd;
    unsigned	len;

    len = (unsigned)STRLEN(p_shq) * 2 + (unsigned)STRLEN(makecmd) + 1;
    if (*p_sp != NUL)
	len += (unsigned)STRLEN(p_sp) + (unsigned)STRLEN(fname) + 3;
    cmd = alloc_id(len, aid_qf_makecmd);
    if (cmd == NULL)
	return NULL;
    sprintf((char *)cmd, "%s%s%s", (char *)p_shq, (char *)makecmd, (char *)p_shq);

    
    if (*p_sp != NUL)
	append_redir(cmd, len, p_sp, fname);

    
    
    
    if (msg_col == 0)
	msg_didout = FALSE;
    msg_start();
    msg_puts(":!");
    msg_outtrans(cmd);		

    return cmd;
}


    void ex_make(exarg_T *eap)
{
    char_u	*fname;
    char_u	*cmd;
    char_u	*enc = NULL;
    win_T	*wp = NULL;
    qf_info_T	*qi = &ql_info;
    int		res;
    char_u	*au_name = NULL;
    int_u	save_qfid;
    char_u	*errorformat = p_efm;
    int		newlist = TRUE;

    
    if (grep_internal(eap->cmdidx))
    {
	ex_vimgrep(eap);
	return;
    }

    au_name = make_get_auname(eap->cmdidx);
    if (au_name != NULL && apply_autocmds(EVENT_QUICKFIXCMDPRE, au_name, curbuf->b_fname, TRUE, curbuf))
    {

	if (aborting())
	    return;

    }
    enc = (*curbuf->b_p_menc != NUL) ? curbuf->b_p_menc : p_menc;

    if (is_loclist_cmd(eap->cmdidx))
	wp = curwin;

    autowrite_all();
    fname = get_mef_name();
    if (fname == NULL)
	return;
    mch_remove(fname);	    

    cmd = make_get_fullcmd(eap->arg, fname);
    if (cmd == NULL)
    {
	vim_free(fname);
	return;
    }

    
    do_shell(cmd, *p_sp != NUL ? SHELL_DOOUT : 0);


    out_flush();
		
    (void)char_avail();


    incr_quickfix_busy();

    if (eap->cmdidx != CMD_make && eap->cmdidx != CMD_lmake)
	errorformat = p_gefm;
    if (eap->cmdidx == CMD_grepadd || eap->cmdidx == CMD_lgrepadd)
	newlist = FALSE;

    res = qf_init(wp, fname, errorformat, newlist, qf_cmdtitle(*eap->cmdlinep), enc);
    if (wp != NULL)
    {
	qi = GET_LOC_LIST(wp);
	if (qi == NULL)
	    goto cleanup;
    }
    if (res >= 0)
	qf_list_changed(qf_get_curlist(qi));

    
    
    save_qfid = qf_get_curlist(qi)->qf_id;
    if (au_name != NULL)
	apply_autocmds(EVENT_QUICKFIXCMDPOST, au_name, curbuf->b_fname, TRUE, curbuf);
    if (res > 0 && !eap->forceit && qflist_valid(wp, save_qfid))
	
	qf_jump_first(qi, save_qfid, FALSE);

cleanup:
    decr_quickfix_busy();
    mch_remove(fname);
    vim_free(fname);
    vim_free(cmd);
}


    int qf_get_size(exarg_T *eap)
{
    qf_info_T	*qi;

    if ((qi = qf_cmd_get_stack(eap, FALSE)) == NULL)
	return 0;
    return qf_get_curlist(qi)->qf_count;
}


    int qf_get_valid_size(exarg_T *eap)
{
    qf_info_T	*qi;
    qf_list_T	*qfl;
    qfline_T	*qfp;
    int		i, sz = 0;
    int		prev_fnum = 0;

    if ((qi = qf_cmd_get_stack(eap, FALSE)) == NULL)
	return 0;

    qfl = qf_get_curlist(qi);
    FOR_ALL_QFL_ITEMS(qfl, qfp, i)
    {
	if (qfp->qf_valid)
	{
	    if (eap->cmdidx == CMD_cdo || eap->cmdidx == CMD_ldo)
		sz++;	
	    else if (qfp->qf_fnum > 0 && qfp->qf_fnum != prev_fnum)
	    {
		
		sz++;
		prev_fnum = qfp->qf_fnum;
	    }
	}
    }

    return sz;
}


    int qf_get_cur_idx(exarg_T *eap)
{
    qf_info_T	*qi;

    if ((qi = qf_cmd_get_stack(eap, FALSE)) == NULL)
	return 0;

    return qf_get_curlist(qi)->qf_index;
}


    int qf_get_cur_valid_idx(exarg_T *eap)
{
    qf_info_T	*qi;
    qf_list_T	*qfl;
    qfline_T	*qfp;
    int		i, eidx = 0;
    int		prev_fnum = 0;

    if ((qi = qf_cmd_get_stack(eap, FALSE)) == NULL)
	return 1;

    qfl = qf_get_curlist(qi);
    qfp = qfl->qf_start;

    
    if (!qf_list_has_valid_entries(qfl))
	return 1;

    for (i = 1; i <= qfl->qf_index && qfp!= NULL; i++, qfp = qfp->qf_next)
    {
	if (qfp->qf_valid)
	{
	    if (eap->cmdidx == CMD_cfdo || eap->cmdidx == CMD_lfdo)
	    {
		if (qfp->qf_fnum > 0 && qfp->qf_fnum != prev_fnum)
		{
		    
		    eidx++;
		    prev_fnum = qfp->qf_fnum;
		}
	    }
	    else eidx++;
	}
    }

    return eidx ? eidx : 1;
}


    static int qf_get_nth_valid_entry(qf_list_T *qfl, int n, int fdo)
{
    qfline_T	*qfp;
    int		i, eidx;
    int		prev_fnum = 0;

    
    if (!qf_list_has_valid_entries(qfl))
	return 1;

    eidx = 0;
    FOR_ALL_QFL_ITEMS(qfl, qfp, i)
    {
	if (qfp->qf_valid)
	{
	    if (fdo)
	    {
		if (qfp->qf_fnum > 0 && qfp->qf_fnum != prev_fnum)
		{
		    
		    eidx++;
		    prev_fnum = qfp->qf_fnum;
		}
	    }
	    else eidx++;
	}

	if (eidx == n)
	    break;
    }

    if (i <= qfl->qf_count)
	return i;
    else return 1;
}


    void ex_cc(exarg_T *eap)
{
    qf_info_T	*qi;
    int		errornr;

    if ((qi = qf_cmd_get_stack(eap, TRUE)) == NULL)
	return;

    if (eap->addr_count > 0)
	errornr = (int)eap->line2;
    else {
	switch (eap->cmdidx)
	{
	    case CMD_cc: case CMD_ll:
		errornr = 0;
		break;
	    case CMD_crewind: case CMD_lrewind: case CMD_cfirst:
	    case CMD_lfirst:
		errornr = 1;
		break;
	    default:
		errornr = 32767;
	}
    }

    
    
    if (eap->cmdidx == CMD_cdo || eap->cmdidx == CMD_ldo || eap->cmdidx == CMD_cfdo || eap->cmdidx == CMD_lfdo)
	errornr = qf_get_nth_valid_entry(qf_get_curlist(qi), eap->addr_count > 0 ? (int)eap->line1 : 1, eap->cmdidx == CMD_cfdo || eap->cmdidx == CMD_lfdo);


    qf_jump(qi, 0, errornr, eap->forceit);
}


    void ex_cnext(exarg_T *eap)
{
    qf_info_T	*qi;
    int		errornr;
    int		dir;

    if ((qi = qf_cmd_get_stack(eap, TRUE)) == NULL)
	return;

    if (eap->addr_count > 0 && (eap->cmdidx != CMD_cdo && eap->cmdidx != CMD_ldo && eap->cmdidx != CMD_cfdo && eap->cmdidx != CMD_lfdo))

	errornr = (int)eap->line2;
    else errornr = 1;

    
    switch (eap->cmdidx)
    {
	case CMD_cnext: case CMD_lnext: case CMD_cdo: case CMD_ldo:
	    dir = FORWARD;
	    break;
	case CMD_cprevious: case CMD_lprevious: case CMD_cNext:
	case CMD_lNext:
	    dir = BACKWARD;
	    break;
	case CMD_cnfile: case CMD_lnfile: case CMD_cfdo: case CMD_lfdo:
	    dir = FORWARD_FILE;
	    break;
	case CMD_cpfile: case CMD_lpfile: case CMD_cNfile: case CMD_lNfile:
	    dir = BACKWARD_FILE;
	    break;
	default:
	    dir = FORWARD;
	    break;
    }

    qf_jump(qi, dir, errornr, eap->forceit);
}


    static qfline_T * qf_find_first_entry_in_buf(qf_list_T *qfl, int bnr, int *errornr)
{
    qfline_T	*qfp = NULL;
    int		idx = 0;

    
    FOR_ALL_QFL_ITEMS(qfl, qfp, idx)
	if (qfp->qf_fnum == bnr)
	    break;

    *errornr = idx;
    return qfp;
}


    static qfline_T * qf_find_first_entry_on_line(qfline_T *entry, int *errornr)
{
    while (!got_int && entry->qf_prev != NULL && entry->qf_fnum == entry->qf_prev->qf_fnum && entry->qf_lnum == entry->qf_prev->qf_lnum)


    {
	entry = entry->qf_prev;
	--*errornr;
    }

    return entry;
}


    static qfline_T * qf_find_last_entry_on_line(qfline_T *entry, int *errornr)
{
    while (!got_int && entry->qf_next != NULL && entry->qf_fnum == entry->qf_next->qf_fnum && entry->qf_lnum == entry->qf_next->qf_lnum)


    {
	entry = entry->qf_next;
	++*errornr;
    }

    return entry;
}


    static int qf_entry_after_pos(qfline_T *qfp, pos_T *pos, int linewise)
{
    if (linewise)
	return qfp->qf_lnum > pos->lnum;
    else return (qfp->qf_lnum > pos->lnum || (qfp->qf_lnum == pos->lnum && qfp->qf_col > pos->col));

}


    static int qf_entry_before_pos(qfline_T *qfp, pos_T *pos, int linewise)
{
    if (linewise)
	return qfp->qf_lnum < pos->lnum;
    else return (qfp->qf_lnum < pos->lnum || (qfp->qf_lnum == pos->lnum && qfp->qf_col < pos->col));

}


    static int qf_entry_on_or_after_pos(qfline_T *qfp, pos_T *pos, int linewise)
{
    if (linewise)
	return qfp->qf_lnum >= pos->lnum;
    else return (qfp->qf_lnum > pos->lnum || (qfp->qf_lnum == pos->lnum && qfp->qf_col >= pos->col));

}


    static int qf_entry_on_or_before_pos(qfline_T *qfp, pos_T *pos, int linewise)
{
    if (linewise)
	return qfp->qf_lnum <= pos->lnum;
    else return (qfp->qf_lnum < pos->lnum || (qfp->qf_lnum == pos->lnum && qfp->qf_col <= pos->col));

}


    static qfline_T * qf_find_entry_after_pos( int		bnr, pos_T		*pos, int		linewise, qfline_T	*qfp, int		*errornr)





{
    if (qf_entry_after_pos(qfp, pos, linewise))
	
	return qfp;

    
    while (qfp->qf_next != NULL && qfp->qf_next->qf_fnum == bnr && qf_entry_on_or_before_pos(qfp->qf_next, pos, linewise))

    {
	qfp = qfp->qf_next;
	++*errornr;
    }

    if (qfp->qf_next == NULL || qfp->qf_next->qf_fnum != bnr)
	
	return NULL;

    
    qfp = qfp->qf_next;
    ++*errornr;

    return qfp;
}


    static qfline_T * qf_find_entry_before_pos( int		bnr, pos_T		*pos, int		linewise, qfline_T	*qfp, int		*errornr)





{
    
    while (qfp->qf_next != NULL && qfp->qf_next->qf_fnum == bnr && qf_entry_before_pos(qfp->qf_next, pos, linewise))

    {
	qfp = qfp->qf_next;
	++*errornr;
    }

    if (qf_entry_on_or_after_pos(qfp, pos, linewise))
	return NULL;

    if (linewise)
	
	qfp = qf_find_first_entry_on_line(qfp, errornr);

    return qfp;
}


    static qfline_T * qf_find_closest_entry( qf_list_T	*qfl, int		bnr, pos_T		*pos, int		dir, int		linewise, int		*errornr)






{
    qfline_T	*qfp;

    *errornr = 0;

    
    qfp = qf_find_first_entry_in_buf(qfl, bnr, errornr);
    if (qfp == NULL)
	return NULL;		

    if (dir == FORWARD)
	qfp = qf_find_entry_after_pos(bnr, pos, linewise, qfp, errornr);
    else qfp = qf_find_entry_before_pos(bnr, pos, linewise, qfp, errornr);

    return qfp;
}


    static void qf_get_nth_below_entry(qfline_T *entry_arg, int n, int linewise, int *errornr)
{
    qfline_T *entry = entry_arg;

    while (n-- > 0 && !got_int)
    {
	int		first_errornr = *errornr;

	if (linewise)
	    
	    entry = qf_find_last_entry_on_line(entry, errornr);

	if (entry->qf_next == NULL || entry->qf_next->qf_fnum != entry->qf_fnum)
	{
	    if (linewise)
		*errornr = first_errornr;
	    break;
	}

	entry = entry->qf_next;
	++*errornr;
    }
}


    static void qf_get_nth_above_entry(qfline_T *entry, int n, int linewise, int *errornr)
{
    while (n-- > 0 && !got_int)
    {
	if (entry->qf_prev == NULL || entry->qf_prev->qf_fnum != entry->qf_fnum)
	    break;

	entry = entry->qf_prev;
	--*errornr;

	
	if (linewise)
	    entry = qf_find_first_entry_on_line(entry, errornr);
    }
}


    static int qf_find_nth_adj_entry( qf_list_T	*qfl, int		bnr, pos_T		*pos, int		n, int		dir, int		linewise)






{
    qfline_T	*adj_entry;
    int		errornr;

    
    adj_entry = qf_find_closest_entry(qfl, bnr, pos, dir, linewise, &errornr);
    if (adj_entry == NULL)
	return 0;

    if (--n > 0)
    {
	
	if (dir == FORWARD)
	    qf_get_nth_below_entry(adj_entry, n, linewise, &errornr);
	else qf_get_nth_above_entry(adj_entry, n, linewise, &errornr);
    }

    return errornr;
}


    void ex_cbelow(exarg_T *eap)
{
    qf_info_T	*qi;
    qf_list_T	*qfl;
    int		dir;
    int		buf_has_flag;
    int		errornr = 0;
    pos_T	pos;

    if (eap->addr_count > 0 && eap->line2 <= 0)
    {
	emsg(_(e_invalid_range));
	return;
    }

    
    if (eap->cmdidx == CMD_cabove || eap->cmdidx == CMD_cbelow || eap->cmdidx == CMD_cbefore || eap->cmdidx == CMD_cafter)
	buf_has_flag = BUF_HAS_QF_ENTRY;
    else buf_has_flag = BUF_HAS_LL_ENTRY;
    if (!(curbuf->b_has_qf_entry & buf_has_flag))
    {
	emsg(_(e_no_errors));
	return;
    }

    if ((qi = qf_cmd_get_stack(eap, TRUE)) == NULL)
	return;

    qfl = qf_get_curlist(qi);
    
    if (!qf_list_has_valid_entries(qfl))
    {
	emsg(_(e_no_errors));
	return;
    }

    if (eap->cmdidx == CMD_cbelow || eap->cmdidx == CMD_lbelow || eap->cmdidx == CMD_cafter || eap->cmdidx == CMD_lafter)


	
	dir = FORWARD;
    else dir = BACKWARD;

    pos = curwin->w_cursor;
    
    
    pos.col++;
    errornr = qf_find_nth_adj_entry(qfl, curbuf->b_fnum, &pos, eap->addr_count > 0 ? eap->line2 : 0, dir, eap->cmdidx == CMD_cbelow || eap->cmdidx == CMD_lbelow || eap->cmdidx == CMD_cabove || eap->cmdidx == CMD_labove);





    if (errornr > 0)
	qf_jump(qi, 0, errornr, FALSE);
    else emsg(_(e_no_more_items));
}


    static char_u * cfile_get_auname(cmdidx_T cmdidx)
{
    switch (cmdidx)
    {
	case CMD_cfile:	    return (char_u *)"cfile";
	case CMD_cgetfile:  return (char_u *)"cgetfile";
	case CMD_caddfile:  return (char_u *)"caddfile";
	case CMD_lfile:	    return (char_u *)"lfile";
	case CMD_lgetfile:  return (char_u *)"lgetfile";
	case CMD_laddfile:  return (char_u *)"laddfile";
	default:	    return NULL;
    }
}


    void ex_cfile(exarg_T *eap)
{
    char_u	*enc = NULL;
    win_T	*wp = NULL;
    qf_info_T	*qi = &ql_info;
    char_u	*au_name = NULL;
    int_u	save_qfid = 0;		
    int		res;

    au_name = cfile_get_auname(eap->cmdidx);
    if (au_name != NULL && apply_autocmds(EVENT_QUICKFIXCMDPRE, au_name, NULL, FALSE, curbuf))
    {

	if (aborting())
	    return;

    }

    enc = (*curbuf->b_p_menc != NUL) ? curbuf->b_p_menc : p_menc;

    if (cmdmod.cmod_flags & CMOD_BROWSE)
    {
	char_u *browse_file = do_browse(0, (char_u *)_("Error file"), eap->arg, NULL, NULL, (char_u *)_(BROWSE_FILTER_ALL_FILES), NULL);

	if (browse_file == NULL)
	    return;
	set_string_option_direct((char_u *)"ef", -1, browse_file, OPT_FREE, 0);
	vim_free(browse_file);
    }
    else  if (*eap->arg != NUL)

	set_string_option_direct((char_u *)"ef", -1, eap->arg, OPT_FREE, 0);

    if (is_loclist_cmd(eap->cmdidx))
	wp = curwin;

    incr_quickfix_busy();

    
    
    
    
    
    
    
    
    res = qf_init(wp, p_ef, p_efm, (eap->cmdidx != CMD_caddfile && eap->cmdidx != CMD_laddfile), qf_cmdtitle(*eap->cmdlinep), enc);

    if (wp != NULL)
    {
	qi = GET_LOC_LIST(wp);
	if (qi == NULL)
	{
	    decr_quickfix_busy();
	    return;
	}
    }
    if (res >= 0)
	qf_list_changed(qf_get_curlist(qi));
    save_qfid = qf_get_curlist(qi)->qf_id;
    if (au_name != NULL)
	apply_autocmds(EVENT_QUICKFIXCMDPOST, au_name, NULL, FALSE, curbuf);

    
    
    if (res > 0 && (eap->cmdidx == CMD_cfile || eap->cmdidx == CMD_lfile)
	    && qflist_valid(wp, save_qfid))
	
	qf_jump_first(qi, save_qfid, eap->forceit);

    decr_quickfix_busy();
}


    static char_u * vgr_get_auname(cmdidx_T cmdidx)
{
    switch (cmdidx)
    {
	case CMD_vimgrep:     return (char_u *)"vimgrep";
	case CMD_lvimgrep:    return (char_u *)"lvimgrep";
	case CMD_vimgrepadd:  return (char_u *)"vimgrepadd";
	case CMD_lvimgrepadd: return (char_u *)"lvimgrepadd";
	case CMD_grep:	      return (char_u *)"grep";
	case CMD_lgrep:	      return (char_u *)"lgrep";
	case CMD_grepadd:     return (char_u *)"grepadd";
	case CMD_lgrepadd:    return (char_u *)"lgrepadd";
	default: return NULL;
    }
}


    static void vgr_init_regmatch(regmmatch_T *regmatch, char_u *s)
{
    
    regmatch->regprog = NULL;

    if (s == NULL || *s == NUL)
    {
	
	if (last_search_pat() == NULL)
	{
	    emsg(_(e_no_previous_regular_expression));
	    return;
	}
	regmatch->regprog = vim_regcomp(last_search_pat(), RE_MAGIC);
    }
    else regmatch->regprog = vim_regcomp(s, RE_MAGIC);

    regmatch->rmm_ic = p_ic;
    regmatch->rmm_maxcol = 0;
}


    static void vgr_display_fname(char_u *fname)
{
    char_u	*p;

    msg_start();
    p = msg_strtrunc(fname, TRUE);
    if (p == NULL)
	msg_outtrans(fname);
    else {
	msg_outtrans(p);
	vim_free(p);
    }
    msg_clr_eos();
    msg_didout = FALSE;	    
    msg_nowait = TRUE;	    
    msg_col = 0;
    out_flush();
}


    static buf_T * vgr_load_dummy_buf( char_u *fname, char_u *dirname_start, char_u *dirname_now)



{
    int		save_mls;

    char_u	*save_ei = NULL;

    buf_T	*buf;


    
    
    save_ei = au_event_disable(",Filetype");

    
    save_mls = p_mls;
    p_mls = 0;

    
    
    buf = load_dummy_buffer(fname, dirname_start, dirname_now);

    p_mls = save_mls;

    au_event_restore(save_ei);


    return buf;
}


    static int vgr_qflist_valid( win_T	    *wp, qf_info_T   *qi, int_u	    qfid, char_u	    *title)




{
    
    if (!qflist_valid(wp, qfid))
    {
	if (wp != NULL)
	{
	    
	    emsg(_(e_current_location_list_was_changed));
	    return FALSE;
	}
	else {
	    
	    qf_new_list(qi, title);
	    return TRUE;
	}
    }

    if (qf_restore_list(qi, qfid) == FAIL)
	return FALSE;

    return TRUE;
}


    static int vgr_match_buflines( qf_list_T   *qfl, char_u	    *fname, buf_T	    *buf, char_u	    *spat, regmmatch_T *regmatch, long	    *tomatch, int	    duplicate_name, int	    flags)








{
    int		found_match = FALSE;
    long	lnum;
    colnr_T	col;
    int		pat_len = (int)STRLEN(spat);

    for (lnum = 1; lnum <= buf->b_ml.ml_line_count && *tomatch > 0; ++lnum)
    {
	col = 0;
	if (!(flags & VGR_FUZZY))
	{
	    
	    while (vim_regexec_multi(regmatch, curwin, buf, lnum, col, NULL) > 0)
	    {
		
		
		
		if (qf_add_entry(qfl, NULL, fname, NULL, duplicate_name ? 0 : buf->b_fnum, ml_get_buf(buf, regmatch->startpos[0].lnum + lnum, FALSE), regmatch->startpos[0].lnum + lnum, regmatch->endpos[0].lnum + lnum, regmatch->startpos[0].col + 1, regmatch->endpos[0].col + 1, FALSE, NULL, 0, 0, TRUE ) == QF_FAIL)















		{
		    got_int = TRUE;
		    break;
		}
		found_match = TRUE;
		if (--*tomatch == 0)
		    break;
		if ((flags & VGR_GLOBAL) == 0 || regmatch->endpos[0].lnum > 0)
		    break;
		col = regmatch->endpos[0].col + (col == regmatch->endpos[0].col);
		if (col > (colnr_T)STRLEN(ml_get_buf(buf, lnum, FALSE)))
		    break;
	    }
	}
	else {
	    char_u  *str = ml_get_buf(buf, lnum, FALSE);
	    int	    score;
	    int_u   matches[MAX_FUZZY_MATCHES];
	    int_u   sz = ARRAY_LENGTH(matches);

	    
	    while (fuzzy_match(str + col, spat, FALSE, &score, matches, sz) > 0)
	    {
		
		
		
		if (qf_add_entry(qfl, NULL, fname, NULL, duplicate_name ? 0 : buf->b_fnum, str, lnum, 0, matches[0] + col + 1, 0, FALSE, NULL, 0, 0, TRUE ) == QF_FAIL)














		{
		    got_int = TRUE;
		    break;
		}
		found_match = TRUE;
		if (--*tomatch == 0)
		    break;
		if ((flags & VGR_GLOBAL) == 0)
		    break;
		col = matches[pat_len - 1] + col + 1;
		if (col > (colnr_T)STRLEN(str))
		    break;
	    }
	}
	line_breakcheck();
	if (got_int)
	    break;
    }

    return found_match;
}


    static void vgr_jump_to_match( qf_info_T   *qi, int	    forceit, int	    *redraw_for_dummy, buf_T	    *first_match_buf, char_u	    *target_dir)





{
    buf_T	*buf;

    buf = curbuf;
    qf_jump(qi, 0, 0, forceit);
    if (buf != curbuf)
	
	
	*redraw_for_dummy = FALSE;

    
    if (curbuf == first_match_buf && target_dir != NULL)
    {
	exarg_T ea;

	CLEAR_FIELD(ea);
	ea.arg = target_dir;
	ea.cmdidx = CMD_lcd;
	ex_cd(&ea);
    }
}


typedef struct {
    long	tomatch;	
    char_u	*spat;		
    int		flags;		
    char_u	**fnames;	
    int		fcount;		
    regmmatch_T	regmatch;	
    char_u	*qf_title;	
} vgr_args_T;


    static int vgr_process_args( exarg_T		*eap, vgr_args_T	*args)


{
    char_u	*p;

    vim_memset(args, 0, sizeof(*args));

    args->regmatch.regprog = NULL;
    args->qf_title = vim_strsave(qf_cmdtitle(*eap->cmdlinep));

    if (eap->addr_count > 0)
	args->tomatch = eap->line2;
    else args->tomatch = MAXLNUM;

    
    p = skip_vimgrep_pat(eap->arg, &args->spat, &args->flags);
    if (p == NULL)
    {
	emsg(_(e_invalid_search_pattern_or_delimiter));
	return FAIL;
    }

    vgr_init_regmatch(&args->regmatch, args->spat);
    if (args->regmatch.regprog == NULL)
	return FAIL;

    p = skipwhite(p);
    if (*p == NUL)
    {
	emsg(_(e_file_name_missing_or_invalid_pattern));
	return FAIL;
    }

    
    if ((get_arglist_exp(p, &args->fcount, &args->fnames, TRUE) == FAIL) || args->fcount == 0)
    {
	emsg(_(e_no_match));
	return FAIL;
    }

    return OK;
}


    static int existing_swapfile(buf_T *buf)
{
    if (buf->b_ml.ml_mfp != NULL && buf->b_ml.ml_mfp->mf_fname != NULL)
    {
	char_u *fname = buf->b_ml.ml_mfp->mf_fname;
	size_t len = STRLEN(fname);

	return fname[len - 1] != 'p' || fname[len - 2] != 'w';
    }
    return FALSE;
}


    static int vgr_process_files( win_T		*wp, qf_info_T	*qi, vgr_args_T	*cmd_args, int		*redraw_for_dummy, buf_T		**first_match_buf, char_u		**target_dir)






{
    int		status = FAIL;
    int_u	save_qfid = qf_get_curlist(qi)->qf_id;
    time_t	seconds = 0;
    char_u	*fname;
    int		fi;
    buf_T	*buf;
    int		duplicate_name = FALSE;
    int		using_dummy;
    char_u	*dirname_start = NULL;
    char_u	*dirname_now = NULL;
    int		found_match;
    aco_save_T	aco;

    dirname_start = alloc_id(MAXPATHL, aid_qf_dirname_start);
    dirname_now = alloc_id(MAXPATHL, aid_qf_dirname_now);
    if (dirname_start == NULL || dirname_now == NULL)
	goto theend;

    
    
    mch_dirname(dirname_start, MAXPATHL);

    seconds = (time_t)0;
    for (fi = 0; fi < cmd_args->fcount && !got_int && cmd_args->tomatch > 0;
									++fi)
    {
	fname = shorten_fname1(cmd_args->fnames[fi]);
	if (time(NULL) > seconds)
	{
	    
	    
	    seconds = time(NULL);
	    vgr_display_fname(fname);
	}

	buf = buflist_findname_exp(cmd_args->fnames[fi]);
	if (buf == NULL || buf->b_ml.ml_mfp == NULL)
	{
	    
	    duplicate_name = (buf != NULL);
	    using_dummy = TRUE;
	    *redraw_for_dummy = TRUE;

	    buf = vgr_load_dummy_buf(fname, dirname_start, dirname_now);
	}
	else  using_dummy = FALSE;


	
	
	if (!vgr_qflist_valid(wp, qi, save_qfid, cmd_args->qf_title))
	    goto theend;

	save_qfid = qf_get_curlist(qi)->qf_id;

	if (buf == NULL)
	{
	    if (!got_int)
		smsg(_("Cannot open file \"%s\""), fname);
	}
	else {
	    
	    
	    found_match = vgr_match_buflines(qf_get_curlist(qi), fname, buf, cmd_args->spat, &cmd_args->regmatch, &cmd_args->tomatch, duplicate_name, cmd_args->flags);


	    if (using_dummy)
	    {
		if (found_match && *first_match_buf == NULL)
		    *first_match_buf = buf;
		if (duplicate_name)
		{
		    
		    
		    wipe_dummy_buffer(buf, dirname_start);
		    buf = NULL;
		}
		else if ((cmdmod.cmod_flags & CMOD_HIDE) == 0 || buf->b_p_bh[0] == 'u' || buf->b_p_bh[0] == 'w' || buf->b_p_bh[0] == 'd')


		{
		    
		    
		    
		    
		    
		    
		    if (!found_match)
		    {
			wipe_dummy_buffer(buf, dirname_start);
			buf = NULL;
		    }
		    else if (buf != *first_match_buf || (cmd_args->flags & VGR_NOJUMP)
					|| existing_swapfile(buf))
		    {
			unload_dummy_buffer(buf, dirname_start);
			
			buf->b_flags &= ~BF_DUMMY;
			buf = NULL;
		    }
		}

		if (buf != NULL)
		{
		    
		    buf->b_flags &= ~BF_DUMMY;

		    
		    
		    if (buf == *first_match_buf && *target_dir == NULL && STRCMP(dirname_start, dirname_now) != 0)

			*target_dir = vim_strsave(dirname_now);

		    
		    
		    
		    
		    aucmd_prepbuf(&aco, buf);

		    apply_autocmds(EVENT_FILETYPE, buf->b_p_ft, buf->b_fname, TRUE, buf);

		    do_modelines(OPT_NOWIN);
		    aucmd_restbuf(&aco);
		}
	    }
	}
    }

    status = OK;

theend:
    vim_free(dirname_now);
    vim_free(dirname_start);
    return status;
}


    void ex_vimgrep(exarg_T *eap)
{
    vgr_args_T	args;
    qf_info_T	*qi;
    qf_list_T	*qfl;
    int_u	save_qfid;
    win_T	*wp = NULL;
    int		redraw_for_dummy = FALSE;
    buf_T	*first_match_buf = NULL;
    char_u	*target_dir = NULL;
    char_u	*au_name =  NULL;
    int		status;

    au_name = vgr_get_auname(eap->cmdidx);
    if (au_name != NULL && apply_autocmds(EVENT_QUICKFIXCMDPRE, au_name, curbuf->b_fname, TRUE, curbuf))
    {

	if (aborting())
	    return;

    }

    qi = qf_cmd_get_or_alloc_stack(eap, &wp);
    if (qi == NULL)
	return;

    if (vgr_process_args(eap, &args) == FAIL)
	goto theend;

    if ((eap->cmdidx != CMD_grepadd && eap->cmdidx != CMD_lgrepadd && eap->cmdidx != CMD_vimgrepadd && eap->cmdidx != CMD_lvimgrepadd)

					|| qf_stack_empty(qi))
	
	qf_new_list(qi, args.qf_title);

    incr_quickfix_busy();

    status = vgr_process_files(wp, qi, &args, &redraw_for_dummy, &first_match_buf, &target_dir);
    if (status != OK)
    {
	FreeWild(args.fcount, args.fnames);
	decr_quickfix_busy();
	goto theend;
    }

    FreeWild(args.fcount, args.fnames);

    qfl = qf_get_curlist(qi);
    qfl->qf_nonevalid = FALSE;
    qfl->qf_ptr = qfl->qf_start;
    qfl->qf_index = 1;
    qf_list_changed(qfl);

    qf_update_buffer(qi, NULL);

    
    
    save_qfid = qf_get_curlist(qi)->qf_id;

    if (au_name != NULL)
	apply_autocmds(EVENT_QUICKFIXCMDPOST, au_name, curbuf->b_fname, TRUE, curbuf);
    
    
    if (!qflist_valid(wp, save_qfid)
	    || qf_restore_list(qi, save_qfid) == FAIL)
    {
	decr_quickfix_busy();
	goto theend;
    }

    
    if (!qf_list_empty(qf_get_curlist(qi)))
    {
	if ((args.flags & VGR_NOJUMP) == 0)
	    vgr_jump_to_match(qi, eap->forceit, &redraw_for_dummy, first_match_buf, target_dir);
    }
    else semsg(_(e_no_match_str_2), args.spat);

    decr_quickfix_busy();

    
    
    if (redraw_for_dummy)
    {

	foldUpdateAll(curwin);

	redraw_later(UPD_NOT_VALID);

    }

theend:
    vim_free(args.qf_title);
    vim_free(target_dir);
    vim_regfree(args.regmatch.regprog);
}


    static void restore_start_dir(char_u *dirname_start)
{
    char_u *dirname_now = alloc(MAXPATHL);

    if (NULL != dirname_now)
    {
	mch_dirname(dirname_now, MAXPATHL);
	if (STRCMP(dirname_start, dirname_now) != 0)
	{
	    
	    
	    exarg_T ea;

	    CLEAR_FIELD(ea);
	    ea.arg = dirname_start;
	    ea.cmdidx = (curwin->w_localdir == NULL) ? CMD_cd : CMD_lcd;
	    ex_cd(&ea);
	}
	vim_free(dirname_now);
    }
}


    static buf_T * load_dummy_buffer( char_u	*fname, char_u	*dirname_start, char_u	*resulting_dir)



{
    buf_T	*newbuf;
    bufref_T	newbufref;
    bufref_T	newbuf_to_wipe;
    int		failed = TRUE;
    aco_save_T	aco;
    int		readfile_result;

    
    newbuf = buflist_new(NULL, NULL, (linenr_T)1, BLN_DUMMY);
    if (newbuf == NULL)
	return NULL;
    set_bufref(&newbufref, newbuf);

    
    buf_copy_options(newbuf, BCO_ENTER | BCO_NOHELP);

    
    if (ml_open(newbuf) == OK)
    {
	
	++newbuf->b_locked;

	
	aucmd_prepbuf(&aco, newbuf);

	
	(void)setfname(curbuf, fname, NULL, FALSE);

	
	check_need_swap(TRUE);

	
	
	curbuf->b_flags &= ~BF_DUMMY;

	newbuf_to_wipe.br_buf = NULL;
	readfile_result = readfile(fname, NULL, (linenr_T)0, (linenr_T)0, (linenr_T)MAXLNUM, NULL, READ_NEW | READ_DUMMY);

	--newbuf->b_locked;
	if (readfile_result == OK && !got_int && !(curbuf->b_flags & BF_NEW))

	{
	    failed = FALSE;
	    if (curbuf != newbuf)
	    {
		
		
		
		
		set_bufref(&newbuf_to_wipe, newbuf);
		newbuf = curbuf;
	    }
	}

	
	aucmd_restbuf(&aco);
	if (newbuf_to_wipe.br_buf != NULL && bufref_valid(&newbuf_to_wipe))
	    wipe_buffer(newbuf_to_wipe.br_buf, FALSE);

	
	
	newbuf->b_flags |= BF_DUMMY;
    }

    
    
    
    mch_dirname(resulting_dir, MAXPATHL);
    restore_start_dir(dirname_start);

    if (!bufref_valid(&newbufref))
	return NULL;
    if (failed)
    {
	wipe_dummy_buffer(newbuf, dirname_start);
	return NULL;
    }
    return newbuf;
}


    static void wipe_dummy_buffer(buf_T *buf, char_u *dirname_start)
{
    
    
    while (buf->b_nwindows > 0)
    {
	int	    did_one = FALSE;
	win_T	    *wp;

	if (firstwin->w_next != NULL)
	    FOR_ALL_WINDOWS(wp)
		if (wp->w_buffer == buf)
		{
		    if (win_close(wp, FALSE) == OK)
			did_one = TRUE;
		    break;
		}
	if (!did_one)
	    return;
    }

    if (curbuf != buf && buf->b_nwindows == 0)	
    {

	cleanup_T   cs;

	
	
	
	enter_cleanup(&cs);


	wipe_buffer(buf, TRUE);


	
	
	leave_cleanup(&cs);

	
	restore_start_dir(dirname_start);
    }
}


    static void unload_dummy_buffer(buf_T *buf, char_u *dirname_start)
{
    if (curbuf != buf)		
    {
	close_buffer(NULL, buf, DOBUF_UNLOAD, FALSE, TRUE);

	
	restore_start_dir(dirname_start);
    }
}



    static int get_qfline_items(qfline_T *qfp, list_T *list)
{
    int		bufnum;
    dict_T	*dict;
    char_u	buf[2];

    
    bufnum = qfp->qf_fnum;
    if (bufnum != 0 && (buflist_findnr(bufnum) == NULL))
	bufnum = 0;

    if ((dict = dict_alloc()) == NULL)
	return FAIL;
    if (list_append_dict(list, dict) == FAIL)
	return FAIL;

    buf[0] = qfp->qf_type;
    buf[1] = NUL;
    if (dict_add_number(dict, "bufnr", (long)bufnum) == FAIL || dict_add_number(dict, "lnum",     (long)qfp->qf_lnum) == FAIL || dict_add_number(dict, "end_lnum", (long)qfp->qf_end_lnum) == FAIL || dict_add_number(dict, "col",      (long)qfp->qf_col) == FAIL || dict_add_number(dict, "end_col",  (long)qfp->qf_end_col) == FAIL || dict_add_number(dict, "vcol",     (long)qfp->qf_viscol) == FAIL || dict_add_number(dict, "nr",       (long)qfp->qf_nr) == FAIL || dict_add_string(dict, "module", qfp->qf_module) == FAIL || dict_add_string(dict, "pattern", qfp->qf_pattern) == FAIL || dict_add_string(dict, "text", qfp->qf_text) == FAIL || dict_add_string(dict, "type", buf) == FAIL || dict_add_number(dict, "valid", (long)qfp->qf_valid) == FAIL)










	return FAIL;

    return OK;
}


    static int get_errorlist( qf_info_T	*qi_arg, win_T		*wp, int		qf_idx, int		eidx, list_T		*list)





{
    qf_info_T	*qi = qi_arg;
    qf_list_T	*qfl;
    qfline_T	*qfp;
    int		i;

    if (qi == NULL)
    {
	qi = &ql_info;
	if (wp != NULL)
	{
	    qi = GET_LOC_LIST(wp);
	    if (qi == NULL)
		return FAIL;
	}
    }

    if (eidx < 0)
	return OK;

    if (qf_idx == INVALID_QFIDX)
	qf_idx = qi->qf_curlist;

    if (qf_idx >= qi->qf_listcount)
	return FAIL;

    qfl = qf_get_list(qi, qf_idx);
    if (qf_list_empty(qfl))
	return FAIL;

    FOR_ALL_QFL_ITEMS(qfl, qfp, i)
    {
	if (eidx > 0)
	{
	    if (eidx == i)
		return get_qfline_items(qfp, list);
	}
	else if (get_qfline_items(qfp, list) == FAIL)
	    return FAIL;
    }

    return OK;
}


enum {
    QF_GETLIST_NONE	= 0x0, QF_GETLIST_TITLE	= 0x1, QF_GETLIST_ITEMS	= 0x2, QF_GETLIST_NR	= 0x4, QF_GETLIST_WINID	= 0x8, QF_GETLIST_CONTEXT	= 0x10, QF_GETLIST_ID	= 0x20, QF_GETLIST_IDX	= 0x40, QF_GETLIST_SIZE	= 0x80, QF_GETLIST_TICK	= 0x100, QF_GETLIST_FILEWINID	= 0x200, QF_GETLIST_QFBUFNR	= 0x400, QF_GETLIST_QFTF	= 0x800, QF_GETLIST_ALL	= 0xFFF, };















    static int qf_get_list_from_lines(dict_T *what, dictitem_T *di, dict_T *retdict)
{
    int		status = FAIL;
    qf_info_T	*qi;
    char_u	*errorformat = p_efm;
    dictitem_T	*efm_di;
    list_T	*l;

    
    if (di->di_tv.v_type == VAR_LIST && di->di_tv.vval.v_list != NULL)
    {
	
	
	if ((efm_di = dict_find(what, (char_u *)"efm", -1)) != NULL)
	{
	    if (efm_di->di_tv.v_type != VAR_STRING || efm_di->di_tv.vval.v_string == NULL)
		return FAIL;
	    errorformat = efm_di->di_tv.vval.v_string;
	}

	l = list_alloc();
	if (l == NULL)
	    return FAIL;

	qi = qf_alloc_stack(QFLT_INTERNAL);
	if (qi != NULL)
	{
	    if (qf_init_ext(qi, 0, NULL, NULL, &di->di_tv, errorformat, TRUE, (linenr_T)0, (linenr_T)0, NULL, NULL) > 0)
	    {
		(void)get_errorlist(qi, NULL, 0, 0, l);
		qf_free(&qi->qf_lists[0]);
	    }
	    free(qi);
	}
	dict_add_list(retdict, "items", l);
	status = OK;
    }

    return status;
}


    static int qf_winid(qf_info_T *qi)
{
    win_T	*win;

    
    
    if (qi == NULL)
	return 0;
    win = qf_find_win(qi);
    if (win != NULL)
	return win->w_id;
    return 0;
}


    static int qf_getprop_qfbufnr(qf_info_T *qi, dict_T *retdict)
{
    int	bufnum = 0;

    if (qi != NULL && buflist_findnr(qi->qf_bufnr) != NULL)
	bufnum = qi->qf_bufnr;

    return dict_add_number(retdict, "qfbufnr", bufnum);
}


    static int qf_getprop_keys2flags(dict_T *what, int loclist)
{
    int		flags = QF_GETLIST_NONE;

    if (dict_has_key(what, "all"))
    {
	flags |= QF_GETLIST_ALL;
	if (!loclist)
	    
	    flags &= ~ QF_GETLIST_FILEWINID;
    }

    if (dict_has_key(what, "title"))
	flags |= QF_GETLIST_TITLE;

    if (dict_has_key(what, "nr"))
	flags |= QF_GETLIST_NR;

    if (dict_has_key(what, "winid"))
	flags |= QF_GETLIST_WINID;

    if (dict_has_key(what, "context"))
	flags |= QF_GETLIST_CONTEXT;

    if (dict_has_key(what, "id"))
	flags |= QF_GETLIST_ID;

    if (dict_has_key(what, "items"))
	flags |= QF_GETLIST_ITEMS;

    if (dict_has_key(what, "idx"))
	flags |= QF_GETLIST_IDX;

    if (dict_has_key(what, "size"))
	flags |= QF_GETLIST_SIZE;

    if (dict_has_key(what, "changedtick"))
	flags |= QF_GETLIST_TICK;

    if (loclist && dict_has_key(what, "filewinid"))
	flags |= QF_GETLIST_FILEWINID;

    if (dict_has_key(what, "qfbufnr"))
	flags |= QF_GETLIST_QFBUFNR;

    if (dict_has_key(what, "quickfixtextfunc"))
	flags |= QF_GETLIST_QFTF;

    return flags;
}


    static int qf_getprop_qfidx(qf_info_T *qi, dict_T *what)
{
    int		qf_idx;
    dictitem_T	*di;

    qf_idx = qi->qf_curlist;	
    if ((di = dict_find(what, (char_u *)"nr", -1)) != NULL)
    {
	
	if (di->di_tv.v_type == VAR_NUMBER)
	{
	    
	    if (di->di_tv.vval.v_number != 0)
	    {
		qf_idx = di->di_tv.vval.v_number - 1;
		if (qf_idx < 0 || qf_idx >= qi->qf_listcount)
		    qf_idx = INVALID_QFIDX;
	    }
	}
	else if (di->di_tv.v_type == VAR_STRING && di->di_tv.vval.v_string != NULL && STRCMP(di->di_tv.vval.v_string, "$") == 0)

	    
	    qf_idx = qi->qf_listcount - 1;
	else qf_idx = INVALID_QFIDX;
    }

    if ((di = dict_find(what, (char_u *)"id", -1)) != NULL)
    {
	
	if (di->di_tv.v_type == VAR_NUMBER)
	{
	    
	    if (di->di_tv.vval.v_number != 0)
		qf_idx = qf_id2nr(qi, di->di_tv.vval.v_number);
	}
	else qf_idx = INVALID_QFIDX;
    }

    return qf_idx;
}


    static int qf_getprop_defaults(qf_info_T *qi, int flags, int locstack, dict_T *retdict)
{
    int		status = OK;

    if (flags & QF_GETLIST_TITLE)
	status = dict_add_string(retdict, "title", (char_u *)"");
    if ((status == OK) && (flags & QF_GETLIST_ITEMS))
    {
	list_T	*l = list_alloc();
	if (l != NULL)
	    status = dict_add_list(retdict, "items", l);
	else status = FAIL;
    }
    if ((status == OK) && (flags & QF_GETLIST_NR))
	status = dict_add_number(retdict, "nr", 0);
    if ((status == OK) && (flags & QF_GETLIST_WINID))
	status = dict_add_number(retdict, "winid", qf_winid(qi));
    if ((status == OK) && (flags & QF_GETLIST_CONTEXT))
	status = dict_add_string(retdict, "context", (char_u *)"");
    if ((status == OK) && (flags & QF_GETLIST_ID))
	status = dict_add_number(retdict, "id", 0);
    if ((status == OK) && (flags & QF_GETLIST_IDX))
	status = dict_add_number(retdict, "idx", 0);
    if ((status == OK) && (flags & QF_GETLIST_SIZE))
	status = dict_add_number(retdict, "size", 0);
    if ((status == OK) && (flags & QF_GETLIST_TICK))
	status = dict_add_number(retdict, "changedtick", 0);
    if ((status == OK) && locstack && (flags & QF_GETLIST_FILEWINID))
	status = dict_add_number(retdict, "filewinid", 0);
    if ((status == OK) && (flags & QF_GETLIST_QFBUFNR))
	status = qf_getprop_qfbufnr(qi, retdict);
    if ((status == OK) && (flags & QF_GETLIST_QFTF))
	status = dict_add_string(retdict, "quickfixtextfunc", (char_u *)"");

    return status;
}


    static int qf_getprop_title(qf_list_T *qfl, dict_T *retdict)
{
    return dict_add_string(retdict, "title", qfl->qf_title);
}


    static int qf_getprop_filewinid(win_T *wp, qf_info_T *qi, dict_T *retdict)
{
    int winid = 0;

    if (wp != NULL && IS_LL_WINDOW(wp))
    {
	win_T	*ll_wp = qf_find_win_with_loclist(qi);
	if (ll_wp != NULL)
	    winid = ll_wp->w_id;
    }

    return dict_add_number(retdict, "filewinid", winid);
}


    static int qf_getprop_items(qf_info_T *qi, int qf_idx, int eidx, dict_T *retdict)
{
    int		status = OK;
    list_T	*l = list_alloc();
    if (l != NULL)
    {
	(void)get_errorlist(qi, NULL, qf_idx, eidx, l);
	dict_add_list(retdict, "items", l);
    }
    else status = FAIL;

    return status;
}


    static int qf_getprop_ctx(qf_list_T *qfl, dict_T *retdict)
{
    int		status;
    dictitem_T	*di;

    if (qfl->qf_ctx != NULL)
    {
	di = dictitem_alloc((char_u *)"context");
	if (di != NULL)
	{
	    copy_tv(qfl->qf_ctx, &di->di_tv);
	    status = dict_add(retdict, di);
	    if (status == FAIL)
		dictitem_free(di);
	}
	else status = FAIL;
    }
    else status = dict_add_string(retdict, "context", (char_u *)"");

    return status;
}


    static int qf_getprop_idx(qf_list_T *qfl, int eidx, dict_T *retdict)
{
    if (eidx == 0)
    {
	eidx = qfl->qf_index;
	if (qf_list_empty(qfl))
	    
	    eidx = 0;
    }
    return dict_add_number(retdict, "idx", eidx);
}


    static int qf_getprop_qftf(qf_list_T *qfl, dict_T *retdict)
{
    int		status;

    if (qfl->qf_qftf_cb.cb_name != NULL)
    {
	typval_T	tv;

	put_callback(&qfl->qf_qftf_cb, &tv);
	status = dict_add_tv(retdict, "quickfixtextfunc", &tv);
	clear_tv(&tv);
    }
    else status = dict_add_string(retdict, "quickfixtextfunc", (char_u *)"");

    return status;
}


    static int qf_get_properties(win_T *wp, dict_T *what, dict_T *retdict)
{
    qf_info_T	*qi = &ql_info;
    qf_list_T	*qfl;
    int		status = OK;
    int		qf_idx = INVALID_QFIDX;
    int		eidx = 0;
    dictitem_T	*di;
    int		flags = QF_GETLIST_NONE;

    if ((di = dict_find(what, (char_u *)"lines", -1)) != NULL)
	return qf_get_list_from_lines(what, di, retdict);

    if (wp != NULL)
	qi = GET_LOC_LIST(wp);

    flags = qf_getprop_keys2flags(what, (wp != NULL));

    if (!qf_stack_empty(qi))
	qf_idx = qf_getprop_qfidx(qi, what);

    
    if (qf_stack_empty(qi) || qf_idx == INVALID_QFIDX)
	return qf_getprop_defaults(qi, flags, wp != NULL, retdict);

    qfl = qf_get_list(qi, qf_idx);

    
    if ((di = dict_find(what, (char_u *)"idx", -1)) != NULL)
    {
	if (di->di_tv.v_type != VAR_NUMBER)
	    return FAIL;
	eidx = di->di_tv.vval.v_number;
    }

    if (flags & QF_GETLIST_TITLE)
	status = qf_getprop_title(qfl, retdict);
    if ((status == OK) && (flags & QF_GETLIST_NR))
	status = dict_add_number(retdict, "nr", qf_idx + 1);
    if ((status == OK) && (flags & QF_GETLIST_WINID))
	status = dict_add_number(retdict, "winid", qf_winid(qi));
    if ((status == OK) && (flags & QF_GETLIST_ITEMS))
	status = qf_getprop_items(qi, qf_idx, eidx, retdict);
    if ((status == OK) && (flags & QF_GETLIST_CONTEXT))
	status = qf_getprop_ctx(qfl, retdict);
    if ((status == OK) && (flags & QF_GETLIST_ID))
	status = dict_add_number(retdict, "id", qfl->qf_id);
    if ((status == OK) && (flags & QF_GETLIST_IDX))
	status = qf_getprop_idx(qfl, eidx, retdict);
    if ((status == OK) && (flags & QF_GETLIST_SIZE))
	status = dict_add_number(retdict, "size", qfl->qf_count);
    if ((status == OK) && (flags & QF_GETLIST_TICK))
	status = dict_add_number(retdict, "changedtick", qfl->qf_changedtick);
    if ((status == OK) && (wp != NULL) && (flags & QF_GETLIST_FILEWINID))
	status = qf_getprop_filewinid(wp, qi, retdict);
    if ((status == OK) && (flags & QF_GETLIST_QFBUFNR))
	status = qf_getprop_qfbufnr(qi, retdict);
    if ((status == OK) && (flags & QF_GETLIST_QFTF))
	status = qf_getprop_qftf(qfl, retdict);

    return status;
}


    static int qf_add_entry_from_dict( qf_list_T	*qfl, dict_T		*d, int		first_entry, int		*valid_entry)




{
    static int	did_bufnr_emsg;
    char_u	*filename, *module, *pattern, *text, *type;
    int		bufnum, valid, status, col, end_col, vcol, nr;
    long	lnum, end_lnum;

    if (first_entry)
	did_bufnr_emsg = FALSE;

    filename = dict_get_string(d, "filename", TRUE);
    module = dict_get_string(d, "module", TRUE);
    bufnum = (int)dict_get_number(d, "bufnr");
    lnum = (int)dict_get_number(d, "lnum");
    end_lnum = (int)dict_get_number(d, "end_lnum");
    col = (int)dict_get_number(d, "col");
    end_col = (int)dict_get_number(d, "end_col");
    vcol = (int)dict_get_number(d, "vcol");
    nr = (int)dict_get_number(d, "nr");
    type = dict_get_string(d, "type", TRUE);
    pattern = dict_get_string(d, "pattern", TRUE);
    text = dict_get_string(d, "text", TRUE);
    if (text == NULL)
	text = vim_strsave((char_u *)"");

    valid = TRUE;
    if ((filename == NULL && bufnum == 0) || (lnum == 0 && pattern == NULL))
	valid = FALSE;

    
    
    if (bufnum != 0 && (buflist_findnr(bufnum) == NULL))
    {
	if (!did_bufnr_emsg)
	{
	    did_bufnr_emsg = TRUE;
	    semsg(_(e_buffer_nr_not_found), bufnum);
	}
	valid = FALSE;
	bufnum = 0;
    }

    
    if (dict_has_key(d, "valid"))
	valid = (int)dict_get_bool(d, "valid", FALSE);

    status =  qf_add_entry(qfl, NULL, filename, module, bufnum, text, lnum, end_lnum, col, end_col, vcol, pattern, nr, type == NULL ? NUL : *type, valid);














    vim_free(filename);
    vim_free(module);
    vim_free(pattern);
    vim_free(text);
    vim_free(type);

    if (valid)
	*valid_entry = TRUE;

    return status;
}


    static int qf_add_entries( qf_info_T	*qi, int		qf_idx, list_T		*list, char_u		*title, int		action)





{
    qf_list_T	*qfl = qf_get_list(qi, qf_idx);
    listitem_T	*li;
    dict_T	*d;
    qfline_T	*old_last = NULL;
    int		retval = OK;
    int		valid_entry = FALSE;

    if (action == ' ' || qf_idx == qi->qf_listcount)
    {
	
	qf_new_list(qi, title);
	qf_idx = qi->qf_curlist;
	qfl = qf_get_list(qi, qf_idx);
    }
    else if (action == 'a' && !qf_list_empty(qfl))
	
	old_last = qfl->qf_last;
    else if (action == 'r')
    {
	qf_free_items(qfl);
	qf_store_title(qfl, title);
    }

    FOR_ALL_LIST_ITEMS(list, li)
    {
	if (li->li_tv.v_type != VAR_DICT)
	    continue; 

	d = li->li_tv.vval.v_dict;
	if (d == NULL)
	    continue;

	retval = qf_add_entry_from_dict(qfl, d, li == list->lv_first, &valid_entry);
	if (retval == QF_FAIL)
	    break;
    }

    
    if (valid_entry)
	qfl->qf_nonevalid = FALSE;
    else if (qfl->qf_index == 0)
	
	qfl->qf_nonevalid = TRUE;

    
    if (action != 'a')
	qfl->qf_ptr = qfl->qf_start;

    
    
    if ((action != 'a' || qfl->qf_index == 0) && !qf_list_empty(qfl))
	qfl->qf_index = 1;

    
    qf_update_buffer(qi, old_last);

    return retval;
}


    static int qf_setprop_get_qfidx( qf_info_T	*qi, dict_T		*what, int		action, int		*newlist)




{
    dictitem_T	*di;
    int		qf_idx = qi->qf_curlist;    

    if ((di = dict_find(what, (char_u *)"nr", -1)) != NULL)
    {
	
	if (di->di_tv.v_type == VAR_NUMBER)
	{
	    
	    if (di->di_tv.vval.v_number != 0)
		qf_idx = di->di_tv.vval.v_number - 1;

	    if ((action == ' ' || action == 'a') && qf_idx == qi->qf_listcount)
	    {
		
		
		
		*newlist = TRUE;
		qf_idx = qf_stack_empty(qi) ? 0 : qi->qf_listcount - 1;
	    }
	    else if (qf_idx < 0 || qf_idx >= qi->qf_listcount)
		return INVALID_QFIDX;
	    else if (action != ' ')
		*newlist = FALSE;	
	}
	else if (di->di_tv.v_type == VAR_STRING && di->di_tv.vval.v_string != NULL && STRCMP(di->di_tv.vval.v_string, "$") == 0)

	{
	    if (!qf_stack_empty(qi))
		qf_idx = qi->qf_listcount - 1;
	    else if (*newlist)
		qf_idx = 0;
	    else return INVALID_QFIDX;
	}
	else return INVALID_QFIDX;
    }

    if (!*newlist && (di = dict_find(what, (char_u *)"id", -1)) != NULL)
    {
	
	if (di->di_tv.v_type != VAR_NUMBER)
	    return INVALID_QFIDX;

	return qf_id2nr(qi, di->di_tv.vval.v_number);
    }

    return qf_idx;
}


    static int qf_setprop_title(qf_info_T *qi, int qf_idx, dict_T *what, dictitem_T *di)
{
    qf_list_T	*qfl = qf_get_list(qi, qf_idx);

    if (di->di_tv.v_type != VAR_STRING)
	return FAIL;

    vim_free(qfl->qf_title);
    qfl->qf_title = dict_get_string(what, "title", TRUE);
    if (qf_idx == qi->qf_curlist)
	qf_update_win_titlevar(qi);

    return OK;
}


    static int qf_setprop_items(qf_info_T *qi, int qf_idx, dictitem_T *di, int action)
{
    int		retval = FAIL;
    char_u	*title_save;

    if (di->di_tv.v_type != VAR_LIST)
	return FAIL;

    title_save = vim_strsave(qi->qf_lists[qf_idx].qf_title);
    retval = qf_add_entries(qi, qf_idx, di->di_tv.vval.v_list, title_save, action == ' ' ? 'a' : action);
    vim_free(title_save);

    return retval;
}


    static int qf_setprop_items_from_lines( qf_info_T	*qi, int		qf_idx, dict_T		*what, dictitem_T	*di, int		action)





{
    char_u	*errorformat = p_efm;
    dictitem_T	*efm_di;
    int		retval = FAIL;

    
    if ((efm_di = dict_find(what, (char_u *)"efm", -1)) != NULL)
    {
	if (efm_di->di_tv.v_type != VAR_STRING || efm_di->di_tv.vval.v_string == NULL)
	    return FAIL;
	errorformat = efm_di->di_tv.vval.v_string;
    }

    
    if (di->di_tv.v_type != VAR_LIST || di->di_tv.vval.v_list == NULL)
	return FAIL;

    if (action == 'r')
	qf_free_items(&qi->qf_lists[qf_idx]);
    if (qf_init_ext(qi, qf_idx, NULL, NULL, &di->di_tv, errorformat, FALSE, (linenr_T)0, (linenr_T)0, NULL, NULL) >= 0)
	retval = OK;

    return retval;
}


    static int qf_setprop_context(qf_list_T *qfl, dictitem_T *di)
{
    typval_T	*ctx;

    free_tv(qfl->qf_ctx);
    ctx =  alloc_tv();
    if (ctx != NULL)
	copy_tv(&di->di_tv, ctx);
    qfl->qf_ctx = ctx;

    return OK;
}


    static int qf_setprop_curidx(qf_info_T *qi, qf_list_T *qfl, dictitem_T *di)
{
    int		denote = FALSE;
    int		newidx;
    int		old_qfidx;
    qfline_T	*qf_ptr;

    
    if (di->di_tv.v_type == VAR_STRING && di->di_tv.vval.v_string != NULL && STRCMP(di->di_tv.vval.v_string, "$") == 0)

	newidx = qfl->qf_count;
    else {
	
	newidx = tv_get_number_chk(&di->di_tv, &denote);
	if (denote)
	    return FAIL;
    }

    if (newidx < 1)		
	return FAIL;
    if (newidx > qfl->qf_count)
	newidx = qfl->qf_count;

    old_qfidx = qfl->qf_index;
    qf_ptr = get_nth_entry(qfl, newidx, &newidx);
    if (qf_ptr == NULL)
	return FAIL;
    qfl->qf_ptr = qf_ptr;
    qfl->qf_index = newidx;

    
    
    if (qf_get_curlist(qi)->qf_id == qfl->qf_id)
	qf_win_pos_update(qi, old_qfidx);

    return OK;
}


    static int qf_setprop_qftf(qf_info_T *qi UNUSED, qf_list_T *qfl, dictitem_T *di)
{
    callback_T	cb;

    free_callback(&qfl->qf_qftf_cb);
    cb = get_callback(&di->di_tv);
    if (cb.cb_name != NULL && *cb.cb_name != NUL)
	set_callback(&qfl->qf_qftf_cb, &cb);

    return OK;
}


    static int qf_set_properties(qf_info_T *qi, dict_T *what, int action, char_u *title)
{
    dictitem_T	*di;
    int		retval = FAIL;
    int		qf_idx;
    int		newlist = FALSE;
    qf_list_T	*qfl;

    if (action == ' ' || qf_stack_empty(qi))
	newlist = TRUE;

    qf_idx = qf_setprop_get_qfidx(qi, what, action, &newlist);
    if (qf_idx == INVALID_QFIDX)	
	return FAIL;

    if (newlist)
    {
	qi->qf_curlist = qf_idx;
	qf_new_list(qi, title);
	qf_idx = qi->qf_curlist;
    }

    qfl = qf_get_list(qi, qf_idx);
    if ((di = dict_find(what, (char_u *)"title", -1)) != NULL)
	retval = qf_setprop_title(qi, qf_idx, what, di);
    if ((di = dict_find(what, (char_u *)"items", -1)) != NULL)
	retval = qf_setprop_items(qi, qf_idx, di, action);
    if ((di = dict_find(what, (char_u *)"lines", -1)) != NULL)
	retval = qf_setprop_items_from_lines(qi, qf_idx, what, di, action);
    if ((di = dict_find(what, (char_u *)"context", -1)) != NULL)
	retval = qf_setprop_context(qfl, di);
    if ((di = dict_find(what, (char_u *)"idx", -1)) != NULL)
	retval = qf_setprop_curidx(qi, qfl, di);
    if ((di = dict_find(what, (char_u *)"quickfixtextfunc", -1)) != NULL)
	retval = qf_setprop_qftf(qi, qfl, di);

    if (newlist || retval == OK)
	qf_list_changed(qfl);
    if (newlist)
	qf_update_buffer(qi, NULL);

    return retval;
}


    static void qf_free_stack(win_T *wp, qf_info_T *qi)
{
    win_T	*qfwin = qf_find_win(qi);
    win_T	*llwin = NULL;

    if (qfwin != NULL)
    {
	
	if (qi->qf_curlist < qi->qf_listcount)
	    qf_free(qf_get_curlist(qi));
	qf_update_buffer(qi, NULL);
    }

    if (wp != NULL && IS_LL_WINDOW(wp))
    {
	
	
	llwin = qf_find_win_with_loclist(qi);
	if (llwin != NULL)
	    wp = llwin;
    }

    qf_free_all(wp);
    if (wp == NULL)
    {
	
	qi->qf_curlist = 0;
	qi->qf_listcount = 0;
    }
    else if (qfwin != NULL)
    {
	
	
	qf_info_T *new_ll = qf_alloc_stack(QFLT_LOCATION);

	if (new_ll != NULL)
	{
	    new_ll->qf_bufnr = qfwin->w_buffer->b_fnum;

	    
	    ll_free_all(&qfwin->w_llist_ref);

	    qfwin->w_llist_ref = new_ll;
	    if (wp != qfwin)
		win_set_loclist(wp, new_ll);
	}
    }
}


    int set_errorlist( win_T	*wp, list_T	*list, int	action, char_u	*title, dict_T	*what)





{
    qf_info_T	*qi = &ql_info;
    int		retval = OK;

    if (wp != NULL)
    {
	qi = ll_get_or_alloc_list(wp);
	if (qi == NULL)
	    return FAIL;
    }

    if (action == 'f')
    {
	
	qf_free_stack(wp, qi);
	return OK;
    }

    
    if (list->lv_len != 0 && what != NULL)
    {
	semsg(_(e_invalid_argument_str), _("cannot have both a list and a \"what\" argument"));
	return FAIL;
    }

    incr_quickfix_busy();

    if (what != NULL)
	retval = qf_set_properties(qi, what, action, title);
    else {
	retval = qf_add_entries(qi, qi->qf_curlist, list, title, action);
	if (retval == OK)
	    qf_list_changed(qf_get_curlist(qi));
    }

    decr_quickfix_busy();

    return retval;
}


    static int mark_quickfix_ctx(qf_info_T *qi, int copyID)
{
    int		i;
    int		abort = FALSE;
    typval_T	*ctx;
    callback_T	*cb;

    for (i = 0; i < LISTCOUNT && !abort; ++i)
    {
	ctx = qi->qf_lists[i].qf_ctx;
	if (ctx != NULL && ctx->v_type != VAR_NUMBER && ctx->v_type != VAR_STRING && ctx->v_type != VAR_FLOAT)
	    abort = abort || set_ref_in_item(ctx, copyID, NULL, NULL);

	cb = &qi->qf_lists[i].qf_qftf_cb;
	abort = abort || set_ref_in_callback(cb, copyID);
    }

    return abort;
}


    int set_ref_in_quickfix(int copyID)
{
    int		abort = FALSE;
    tabpage_T	*tp;
    win_T	*win;

    abort = mark_quickfix_ctx(&ql_info, copyID);
    if (abort)
	return abort;

    abort = set_ref_in_callback(&qftf_cb, copyID);
    if (abort)
	return abort;

    FOR_ALL_TAB_WINDOWS(tp, win)
    {
	if (win->w_llist != NULL)
	{
	    abort = mark_quickfix_ctx(win->w_llist, copyID);
	    if (abort)
		return abort;
	}
	if (IS_LL_WINDOW(win) && (win->w_llist_ref->qf_refcount == 1))
	{
	    
	    
	    
	    abort = mark_quickfix_ctx(win->w_llist_ref, copyID);
	    if (abort)
		return abort;
	}
    }

    return abort;
}



    static char_u * cbuffer_get_auname(cmdidx_T cmdidx)
{
    switch (cmdidx)
    {
	case CMD_cbuffer:	return (char_u *)"cbuffer";
	case CMD_cgetbuffer:	return (char_u *)"cgetbuffer";
	case CMD_caddbuffer:	return (char_u *)"caddbuffer";
	case CMD_lbuffer:	return (char_u *)"lbuffer";
	case CMD_lgetbuffer:	return (char_u *)"lgetbuffer";
	case CMD_laddbuffer:	return (char_u *)"laddbuffer";
	default:		return NULL;
    }
}


    static int cbuffer_process_args( exarg_T		*eap, buf_T		**bufp, linenr_T	*line1, linenr_T	*line2)




{
    buf_T	*buf = NULL;

    if (*eap->arg == NUL)
	buf = curbuf;
    else if (*skipwhite(skipdigits(eap->arg)) == NUL)
	buf = buflist_findnr(atoi((char *)eap->arg));

    if (buf == NULL)
    {
	emsg(_(e_invalid_argument));
	return FAIL;
    }

    if (buf->b_ml.ml_mfp == NULL)
    {
	emsg(_(e_buffer_is_not_loaded));
	return FAIL;
    }

    if (eap->addr_count == 0)
    {
	eap->line1 = 1;
	eap->line2 = buf->b_ml.ml_line_count;
    }

    if (eap->line1 < 1 || eap->line1 > buf->b_ml.ml_line_count || eap->line2 < 1 || eap->line2 > buf->b_ml.ml_line_count)
    {
	emsg(_(e_invalid_range));
	return FAIL;
    }

    *line1 = eap->line1;
    *line2 = eap->line2;
    *bufp = buf;

    return OK;
}


    void ex_cbuffer(exarg_T *eap)
{
    buf_T	*buf = NULL;
    qf_info_T	*qi;
    char_u	*au_name = NULL;
    int		res;
    int_u	save_qfid;
    win_T	*wp = NULL;
    char_u	*qf_title;
    linenr_T	line1;
    linenr_T	line2;

    au_name = cbuffer_get_auname(eap->cmdidx);
    if (au_name != NULL && apply_autocmds(EVENT_QUICKFIXCMDPRE, au_name, curbuf->b_fname, TRUE, curbuf))
    {

	if (aborting())
	    return;

    }

    
    qi = qf_cmd_get_or_alloc_stack(eap, &wp);
    if (qi == NULL)
	return;

    if (cbuffer_process_args(eap, &buf, &line1, &line2) == FAIL)
	return;

    qf_title = qf_cmdtitle(*eap->cmdlinep);

    if (buf->b_sfname)
    {
	vim_snprintf((char *)IObuff, IOSIZE, "%s (%s)", (char *)qf_title, (char *)buf->b_sfname);
	qf_title = IObuff;
    }

    incr_quickfix_busy();

    res = qf_init_ext(qi, qi->qf_curlist, NULL, buf, NULL, p_efm, (eap->cmdidx != CMD_caddbuffer && eap->cmdidx != CMD_laddbuffer), line1, line2, qf_title, NULL);



    if (qf_stack_empty(qi))
    {
	decr_quickfix_busy();
	return;
    }
    if (res >= 0)
	qf_list_changed(qf_get_curlist(qi));

    
    
    save_qfid = qf_get_curlist(qi)->qf_id;
    if (au_name != NULL)
    {
	buf_T *curbuf_old = curbuf;

	apply_autocmds(EVENT_QUICKFIXCMDPOST, au_name, curbuf->b_fname, TRUE, curbuf);
	if (curbuf != curbuf_old)
	    
	    
	    res = 0;
    }
    
    
    if (res > 0 && (eap->cmdidx == CMD_cbuffer || eap->cmdidx == CMD_lbuffer)
	    && qflist_valid(wp, save_qfid))
	
	qf_jump_first(qi, save_qfid, eap->forceit);

    decr_quickfix_busy();
}



    char_u * cexpr_get_auname(cmdidx_T cmdidx)
{
    switch (cmdidx)
    {
	case CMD_cexpr:	    return (char_u *)"cexpr";
	case CMD_cgetexpr:  return (char_u *)"cgetexpr";
	case CMD_caddexpr:  return (char_u *)"caddexpr";
	case CMD_lexpr:	    return (char_u *)"lexpr";
	case CMD_lgetexpr:  return (char_u *)"lgetexpr";
	case CMD_laddexpr:  return (char_u *)"laddexpr";
	default:	    return NULL;
    }
}

    int trigger_cexpr_autocmd(int cmdidx)
{
    char_u	*au_name = cexpr_get_auname(cmdidx);

    if (au_name != NULL && apply_autocmds(EVENT_QUICKFIXCMDPRE, au_name, curbuf->b_fname, TRUE, curbuf))
    {
	if (aborting())
	    return FAIL;
    }
    return OK;
}

    int cexpr_core(exarg_T *eap, typval_T *tv)
{
    qf_info_T	*qi;
    win_T	*wp = NULL;

    qi = qf_cmd_get_or_alloc_stack(eap, &wp);
    if (qi == NULL)
	return FAIL;

    if ((tv->v_type == VAR_STRING && tv->vval.v_string != NULL)
	    || (tv->v_type == VAR_LIST && tv->vval.v_list != NULL))
    {
	int	res;
	int_u	save_qfid;
	char_u	*au_name = cexpr_get_auname(eap->cmdidx);

	incr_quickfix_busy();
	res = qf_init_ext(qi, qi->qf_curlist, NULL, NULL, tv, p_efm, (eap->cmdidx != CMD_caddexpr && eap->cmdidx != CMD_laddexpr), (linenr_T)0, (linenr_T)0, qf_cmdtitle(*eap->cmdlinep), NULL);



	if (qf_stack_empty(qi))
	{
	    decr_quickfix_busy();
	    return FAIL;
	}
	if (res >= 0)
	    qf_list_changed(qf_get_curlist(qi));

	
	
	save_qfid = qf_get_curlist(qi)->qf_id;
	if (au_name != NULL)
	    apply_autocmds(EVENT_QUICKFIXCMDPOST, au_name, curbuf->b_fname, TRUE, curbuf);

	
	
	if (res > 0 && (eap->cmdidx == CMD_cexpr || eap->cmdidx == CMD_lexpr)
		&& qflist_valid(wp, save_qfid))
	    
	    qf_jump_first(qi, save_qfid, eap->forceit);
	decr_quickfix_busy();
	return OK;
    }

    emsg(_(e_string_or_list_expected));
    return FAIL;
}


    void ex_cexpr(exarg_T *eap)
{
    typval_T	*tv;

    if (trigger_cexpr_autocmd(eap->cmdidx) == FAIL)
	return;

    
    
    tv = eval_expr(eap->arg, eap);
    if (tv != NULL)
    {
	(void)cexpr_core(eap, tv);
	free_tv(tv);
    }
}



    static qf_info_T * hgr_get_ll(int *new_ll)
{
    win_T	*wp;
    qf_info_T	*qi;

    
    if (bt_help(curwin->w_buffer))
	wp = curwin;
    else  wp = qf_find_help_win();


    if (wp == NULL)	    
	qi = NULL;
    else qi = wp->w_llist;

    if (qi == NULL)
    {
	
	if ((qi = qf_alloc_stack(QFLT_LOCATION)) == NULL)
	    return NULL;
	*new_ll = TRUE;
    }

    return qi;
}


    static void hgr_search_file( qf_list_T *qfl, char_u *fname, vimconv_T *p_vc, regmatch_T *p_regmatch)




{
    FILE	*fd;
    long	lnum;

    fd = mch_fopen((char *)fname, "r");
    if (fd == NULL)
	return;

    lnum = 1;
    while (!vim_fgets(IObuff, IOSIZE, fd) && !got_int)
    {
	char_u    *line = IObuff;

	
	
	if (p_vc->vc_type != CONV_NONE && has_non_ascii(IObuff))
	{
	    line = string_convert(p_vc, IObuff, NULL);
	    if (line == NULL)
		line = IObuff;
	}

	if (vim_regexec(p_regmatch, line, (colnr_T)0))
	{
	    int	l = (int)STRLEN(line);

	    
	    while (l > 0 && line[l - 1] <= ' ')
		line[--l] = NUL;

	    if (qf_add_entry(qfl, NULL, fname, NULL, 0, line, lnum, 0, (int)(p_regmatch->startp[0] - line)







			+ 1,	 (int)(p_regmatch->endp[0] - line)
			+ 1,	 FALSE, NULL, 0, 1, TRUE ) == QF_FAIL)





	    {
		got_int = TRUE;
		if (line != IObuff)
		    vim_free(line);
		break;
	    }
	}
	if (line != IObuff)
	    vim_free(line);
	++lnum;
	line_breakcheck();
    }
    fclose(fd);
}


    static void hgr_search_files_in_dir( qf_list_T *qfl, char_u *dirname, regmatch_T *p_regmatch, vimconv_T *p_vc  , char_u *lang  )








{
    int		fcount;
    char_u	**fnames;
    int		fi;

    
    add_pathsep(dirname);
    STRCAT(dirname, "doc/*.\\(txt\\|??x\\)");
    if (gen_expand_wildcards(1, &dirname, &fcount, &fnames, EW_FILE|EW_SILENT) == OK && fcount > 0)

    {
	for (fi = 0; fi < fcount && !got_int; ++fi)
	{

	    
	    if (lang != NULL && STRNICMP(lang, fnames[fi] + STRLEN(fnames[fi]) - 3, 2) != 0 && !(STRNICMP(lang, "en", 2) == 0 && STRNICMP("txt", fnames[fi] + STRLEN(fnames[fi]) - 3, 3) == 0))




		continue;


	    hgr_search_file(qfl, fnames[fi], p_vc, p_regmatch);
	}
	FreeWild(fcount, fnames);
    }
}


    static void hgr_search_in_rtp(qf_list_T *qfl, regmatch_T *p_regmatch, char_u *lang)
{
    char_u	*p;

    vimconv_T	vc;

    
    
    vc.vc_type = CONV_NONE;
    if (!enc_utf8)
	convert_setup(&vc, (char_u *)"utf-8", p_enc);

    
    p = p_rtp;
    while (*p != NUL && !got_int)
    {
	copy_option_part(&p, NameBuff, MAXPATHL, ",");

	hgr_search_files_in_dir(qfl, NameBuff, p_regmatch, &vc  , lang  );



    }

    if (vc.vc_type != CONV_NONE)
	convert_setup(&vc, NULL, NULL);
}


    void ex_helpgrep(exarg_T *eap)
{
    regmatch_T	regmatch;
    char_u	*save_cpo;
    int		save_cpo_allocated;
    qf_info_T	*qi = &ql_info;
    int		new_qi = FALSE;
    char_u	*au_name =  NULL;
    char_u	*lang = NULL;
    int		updated = FALSE;

    switch (eap->cmdidx)
    {
	case CMD_helpgrep:  au_name = (char_u *)"helpgrep"; break;
	case CMD_lhelpgrep: au_name = (char_u *)"lhelpgrep"; break;
	default: break;
    }
    if (au_name != NULL && apply_autocmds(EVENT_QUICKFIXCMDPRE, au_name, curbuf->b_fname, TRUE, curbuf))
    {

	if (aborting())
	    return;

    }

    if (is_loclist_cmd(eap->cmdidx))
    {
	qi = hgr_get_ll(&new_qi);
	if (qi == NULL)
	    return;
    }

    
    save_cpo = p_cpo;
    save_cpo_allocated = is_option_allocated("cpo");
    p_cpo = empty_option;

    incr_quickfix_busy();


    
    lang = check_help_lang(eap->arg);

    regmatch.regprog = vim_regcomp(eap->arg, RE_MAGIC + RE_STRING);
    regmatch.rm_ic = FALSE;
    if (regmatch.regprog != NULL)
    {
	qf_list_T	*qfl;

	
	qf_new_list(qi, qf_cmdtitle(*eap->cmdlinep));
	qfl = qf_get_curlist(qi);

	hgr_search_in_rtp(qfl, &regmatch, lang);

	vim_regfree(regmatch.regprog);

	qfl->qf_nonevalid = FALSE;
	qfl->qf_ptr = qfl->qf_start;
	qfl->qf_index = 1;
	qf_list_changed(qfl);
	updated = TRUE;
    }

    if (p_cpo == empty_option)
	p_cpo = save_cpo;
    else {
	
	
	if (*p_cpo == NUL)
	    set_option_value_give_err((char_u *)"cpo", 0L, save_cpo, 0);
	if (save_cpo_allocated)
	    free_string_option(save_cpo);
    }

    if (updated)
	
	
	qf_update_buffer(qi, NULL);

    if (au_name != NULL)
    {
	apply_autocmds(EVENT_QUICKFIXCMDPOST, au_name, curbuf->b_fname, TRUE, curbuf);
	
	
	if (!new_qi && IS_LL_STACK(qi) && qf_find_win_with_loclist(qi) == NULL)
	{
	    decr_quickfix_busy();
	    return;
	}
    }

    
    if (!qf_list_empty(qf_get_curlist(qi)))
	qf_jump(qi, 0, 0, FALSE);
    else semsg(_(e_no_match_str_2), eap->arg);

    decr_quickfix_busy();

    if (eap->cmdidx == CMD_lhelpgrep)
    {
	
	
	if (!bt_help(curwin->w_buffer) || curwin->w_llist == qi)
	{
	    if (new_qi)
		ll_free_all(&qi);
	}
	else if (curwin->w_llist == NULL && new_qi)
	    
	    
	    curwin->w_llist = qi;
    }
}




    static void get_qf_loc_list(int is_qf, win_T *wp, typval_T *what_arg, typval_T *rettv)
{
    if (what_arg->v_type == VAR_UNKNOWN)
    {
	if (rettv_list_alloc(rettv) == OK)
	    if (is_qf || wp != NULL)
		(void)get_errorlist(NULL, wp, -1, 0, rettv->vval.v_list);
    }
    else {
	if (rettv_dict_alloc(rettv) == OK)
	    if (is_qf || (wp != NULL))
	    {
		if (what_arg->v_type == VAR_DICT)
		{
		    dict_T	*d = what_arg->vval.v_dict;

		    if (d != NULL)
			qf_get_properties(wp, d, rettv->vval.v_dict);
		}
		else emsg(_(e_dictionary_required));
	    }
    }
}



    void f_getloclist(typval_T *argvars UNUSED, typval_T *rettv UNUSED)
{

    win_T	*wp;

    if (in_vim9script()
	    && (check_for_number_arg(argvars, 0) == FAIL || check_for_opt_dict_arg(argvars, 1) == FAIL))
	return;

    wp = find_win_by_nr_or_id(&argvars[0]);
    get_qf_loc_list(FALSE, wp, &argvars[1], rettv);

}


    void f_getqflist(typval_T *argvars UNUSED, typval_T *rettv UNUSED)
{

    if (in_vim9script() && check_for_opt_dict_arg(argvars, 0) == FAIL)
	return;

    get_qf_loc_list(TRUE, NULL, &argvars[0], rettv);

}


    static void set_qf_ll_list( win_T	*wp UNUSED, typval_T	*list_arg UNUSED, typval_T	*action_arg UNUSED, typval_T	*what_arg UNUSED, typval_T	*rettv)





{

    char_u	*act;
    int		action = 0;
    static int	recursive = 0;


    rettv->vval.v_number = -1;


    if (list_arg->v_type != VAR_LIST)
	emsg(_(e_list_required));
    else if (recursive != 0)
	emsg(_(e_autocommand_caused_recursive_behavior));
    else {
	list_T  *l = list_arg->vval.v_list;
	dict_T	*what = NULL;
	int	valid_dict = TRUE;

	if (action_arg->v_type == VAR_STRING)
	{
	    act = tv_get_string_chk(action_arg);
	    if (act == NULL)
		return;		
	    if ((*act == 'a' || *act == 'r' || *act == ' ' || *act == 'f') && act[1] == NUL)
		action = *act;
	    else semsg(_(e_invalid_action_str_1), act);
	}
	else if (action_arg->v_type == VAR_UNKNOWN)
	    action = ' ';
	else emsg(_(e_string_required));

	if (action_arg->v_type != VAR_UNKNOWN && what_arg->v_type != VAR_UNKNOWN)
	{
	    if (what_arg->v_type == VAR_DICT && what_arg->vval.v_dict != NULL)
		what = what_arg->vval.v_dict;
	    else {
		emsg(_(e_dictionary_required));
		valid_dict = FALSE;
	    }
	}

	++recursive;
	if (l != NULL && action && valid_dict && set_errorlist(wp, l, action, (char_u *)(wp == NULL ? ":setqflist()" : ":setloclist()"), what) == OK)


	    rettv->vval.v_number = 0;
	--recursive;
    }

}


    void f_setloclist(typval_T *argvars, typval_T *rettv)
{
    win_T	*win;

    rettv->vval.v_number = -1;

    if (in_vim9script()
	    && (check_for_number_arg(argvars, 0) == FAIL || check_for_list_arg(argvars, 1) == FAIL || check_for_opt_string_arg(argvars, 2) == FAIL || (argvars[2].v_type != VAR_UNKNOWN && check_for_opt_dict_arg(argvars, 3) == FAIL)))



	return;

    win = find_win_by_nr_or_id(&argvars[0]);
    if (win != NULL)
	set_qf_ll_list(win, &argvars[1], &argvars[2], &argvars[3], rettv);
}


    void f_setqflist(typval_T *argvars, typval_T *rettv)
{
    if (in_vim9script()
	    && (check_for_list_arg(argvars, 0) == FAIL || check_for_opt_string_arg(argvars, 1) == FAIL || (argvars[1].v_type != VAR_UNKNOWN && check_for_opt_dict_arg(argvars, 2) == FAIL)))


	return;

    set_qf_ll_list(NULL, &argvars[0], &argvars[1], &argvars[2], rettv);
}

