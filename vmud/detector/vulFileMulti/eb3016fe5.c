










static int linelen(int *has_tab);
static void do_filter(linenr_T line1, linenr_T line2, exarg_T *eap, char_u *cmd, int do_in, int do_out);
static int not_writing(void);
static int check_readonly(int *forceit, buf_T *buf);
static void delbuf_msg(char_u *name);


    void do_ascii(exarg_T *eap UNUSED)
{
    int		c;
    int		cval;
    char	buf1[20];
    char	buf2[20];
    char_u	buf3[7];

    char_u      *dig;

    int		cc[MAX_MCO];
    int		ci = 0;
    int		len;

    if (enc_utf8)
	c = utfc_ptr2char(ml_get_cursor(), cc);
    else c = gchar_cursor();
    if (c == NUL)
    {
	msg("NUL");
	return;
    }

    IObuff[0] = NUL;
    if (!has_mbyte || (enc_dbcs != 0 && c < 0x100) || c < 0x80)
    {
	if (c == NL)	    
	    c = NUL;
	if (c == CAR && get_fileformat(curbuf) == EOL_MAC)
	    cval = NL;	    
	else cval = c;
	if (vim_isprintc_strict(c) && (c < ' ' || c > '~'))
	{
	    transchar_nonprint(curbuf, buf3, c);
	    vim_snprintf(buf1, sizeof(buf1), "  <%s>", (char *)buf3);
	}
	else buf1[0] = NUL;
	if (c >= 0x80)
	    vim_snprintf(buf2, sizeof(buf2), "  <M-%s>", (char *)transchar(c & 0x7f));
	else buf2[0] = NUL;

	dig = get_digraph_for_char(cval);
	if (dig != NULL)
	    vim_snprintf((char *)IObuff, IOSIZE, _("<%s>%s%s  %d,  Hex %02x,  Oct %03o, Digr %s"), transchar(c), buf1, buf2, cval, cval, cval, dig);

	else  vim_snprintf((char *)IObuff, IOSIZE, _("<%s>%s%s  %d,  Hex %02x,  Octal %03o"), transchar(c), buf1, buf2, cval, cval, cval);



	if (enc_utf8)
	    c = cc[ci++];
	else c = 0;
    }

    
    while (has_mbyte && (c >= 0x100 || (enc_utf8 && c >= 0x80)))
    {
	len = (int)STRLEN(IObuff);
	
	if (len > 0)
	    IObuff[len++] = ' ';
	IObuff[len++] = '<';
	if (enc_utf8 && utf_iscomposing(c)

		&& !gui.in_use  )

	    IObuff[len++] = ' '; 
	len += (*mb_char2bytes)(c, IObuff + len);

	dig = get_digraph_for_char(c);
	if (dig != NULL)
	    vim_snprintf((char *)IObuff + len, IOSIZE - len, c < 0x10000 ? _("> %d, Hex %04x, Oct %o, Digr %s")
				    : _("> %d, Hex %08x, Oct %o, Digr %s"), c, c, c, dig);
	else  vim_snprintf((char *)IObuff + len, IOSIZE - len, c < 0x10000 ? _("> %d, Hex %04x, Octal %o")


				     : _("> %d, Hex %08x, Octal %o"), c, c, c);
	if (ci == MAX_MCO)
	    break;
	if (enc_utf8)
	    c = cc[ci++];
	else c = 0;
    }

    msg((char *)IObuff);
}


    void ex_align(exarg_T *eap)
{
    pos_T	save_curpos;
    int		len;
    int		indent = 0;
    int		new_indent;
    int		has_tab;
    int		width;


    if (curwin->w_p_rl)
    {
	
	if (eap->cmdidx == CMD_right)
	    eap->cmdidx = CMD_left;
	else if (eap->cmdidx == CMD_left)
	    eap->cmdidx = CMD_right;
    }


    width = atoi((char *)eap->arg);
    save_curpos = curwin->w_cursor;
    if (eap->cmdidx == CMD_left)    
    {
	if (width >= 0)
	    indent = width;
    }
    else {
	
	if (width <= 0)
	    width = curbuf->b_p_tw;
	if (width == 0 && curbuf->b_p_wm > 0)
	    width = curwin->w_width - curbuf->b_p_wm;
	if (width <= 0)
	    width = 80;
    }

    if (u_save((linenr_T)(eap->line1 - 1), (linenr_T)(eap->line2 + 1)) == FAIL)
	return;

    for (curwin->w_cursor.lnum = eap->line1;
		 curwin->w_cursor.lnum <= eap->line2; ++curwin->w_cursor.lnum)
    {
	if (eap->cmdidx == CMD_left)		
	    new_indent = indent;
	else {
	    has_tab = FALSE;	
	    len = linelen(eap->cmdidx == CMD_right ? &has_tab : NULL) - get_indent();

	    if (len <= 0)			
		continue;

	    if (eap->cmdidx == CMD_center)
		new_indent = (width - len) / 2;
	    else {
		new_indent = width - len;	

		
		if (has_tab)
		    while (new_indent > 0)
		    {
			(void)set_indent(new_indent, 0);
			if (linelen(NULL) <= width)
			{
			    
			    do (void)set_indent(++new_indent, 0);
			    while (linelen(NULL) <= width);
			    --new_indent;
			    break;
			}
			--new_indent;
		    }
	    }
	}
	if (new_indent < 0)
	    new_indent = 0;
	(void)set_indent(new_indent, 0);		
    }
    changed_lines(eap->line1, 0, eap->line2 + 1, 0L);
    curwin->w_cursor = save_curpos;
    beginline(BL_WHITE | BL_FIX);
}


    static int linelen(int *has_tab)
{
    char_u  *line;
    char_u  *first;
    char_u  *last;
    int	    save;
    int	    len;

    
    
    line = ml_get_curline();
    if (*line == NUL)
	return 0;

    
    first = skipwhite(line);

    
    for (last = first + STRLEN(first);
				last > first && VIM_ISWHITE(last[-1]); --last)
	;
    save = *last;
    *last = NUL;
    len = linetabsize(line);		
    if (has_tab != NULL)		
	*has_tab = (vim_strchr(first, TAB) != NULL);
    *last = save;

    return len;
}



static char_u	*sortbuf1;
static char_u	*sortbuf2;

static int	sort_lc;	
static int	sort_ic;	
static int	sort_nr;	
static int	sort_rx;	

static int	sort_flt;	


static int	sort_abort;	


typedef struct {
    linenr_T	lnum;			
    union {
	struct {
	    varnumber_T	start_col_nr;	
	    varnumber_T	end_col_nr;	
	} line;
	struct {
	    varnumber_T	value;		
	    int is_number;		
	} num;

	float_T value_flt;		

    } st_u;
} sorti_T;

    static int string_compare(const void *s1, const void *s2)
{
    if (sort_lc)
	return strcoll((char *)s1, (char *)s2);
    return sort_ic ? STRICMP(s1, s2) : STRCMP(s1, s2);
}

    static int sort_compare(const void *s1, const void *s2)
{
    sorti_T	l1 = *(sorti_T *)s1;
    sorti_T	l2 = *(sorti_T *)s2;
    int		result = 0;

    
    
    
    if (sort_abort)
	return 0;
    fast_breakcheck();
    if (got_int)
	sort_abort = TRUE;

    if (sort_nr)
    {
	if (l1.st_u.num.is_number != l2.st_u.num.is_number)
	    result = l1.st_u.num.is_number - l2.st_u.num.is_number;
	else result = l1.st_u.num.value == l2.st_u.num.value ? 0 : l1.st_u.num.value > l2.st_u.num.value ? 1 : -1;

    }

    else if (sort_flt)
	result = l1.st_u.value_flt == l2.st_u.value_flt ? 0 : l1.st_u.value_flt > l2.st_u.value_flt ? 1 : -1;

    else {
	
	
	
	STRNCPY(sortbuf1, ml_get(l1.lnum) + l1.st_u.line.start_col_nr, l1.st_u.line.end_col_nr - l1.st_u.line.start_col_nr + 1);
	sortbuf1[l1.st_u.line.end_col_nr - l1.st_u.line.start_col_nr] = 0;
	STRNCPY(sortbuf2, ml_get(l2.lnum) + l2.st_u.line.start_col_nr, l2.st_u.line.end_col_nr - l2.st_u.line.start_col_nr + 1);
	sortbuf2[l2.st_u.line.end_col_nr - l2.st_u.line.start_col_nr] = 0;

	result = string_compare(sortbuf1, sortbuf2);
    }

    
    if (result == 0)
	return (int)(l1.lnum - l2.lnum);
    return result;
}


    void ex_sort(exarg_T *eap)
{
    regmatch_T	regmatch;
    int		len;
    linenr_T	lnum;
    long	maxlen = 0;
    sorti_T	*nrs;
    size_t	count = (size_t)(eap->line2 - eap->line1 + 1);
    size_t	i;
    char_u	*p;
    char_u	*s;
    char_u	*s2;
    char_u	c;			
    int		unique = FALSE;
    long	deleted;
    colnr_T	start_col;
    colnr_T	end_col;
    int		sort_what = 0;
    int		format_found = 0;
    int		change_occurred = FALSE; 

    
    if (count <= 1)
	return;

    if (u_save((linenr_T)(eap->line1 - 1), (linenr_T)(eap->line2 + 1)) == FAIL)
	return;
    sortbuf1 = NULL;
    sortbuf2 = NULL;
    regmatch.regprog = NULL;
    nrs = ALLOC_MULT(sorti_T, count);
    if (nrs == NULL)
	goto sortend;

    sort_abort = sort_ic = sort_lc = sort_rx = sort_nr = 0;

    sort_flt = 0;


    for (p = eap->arg; *p != NUL; ++p)
    {
	if (VIM_ISWHITE(*p))
	    ;
	else if (*p == 'i')
	    sort_ic = TRUE;
	else if (*p == 'l')
	    sort_lc = TRUE;
	else if (*p == 'r')
	    sort_rx = TRUE;
	else if (*p == 'n')
	{
	    sort_nr = 1;
	    ++format_found;
	}

	else if (*p == 'f')
	{
	    sort_flt = 1;
	    ++format_found;
	}

	else if (*p == 'b')
	{
	    sort_what = STR2NR_BIN + STR2NR_FORCE;
	    ++format_found;
	}
	else if (*p == 'o')
	{
	    sort_what = STR2NR_OCT + STR2NR_FORCE;
	    ++format_found;
	}
	else if (*p == 'x')
	{
	    sort_what = STR2NR_HEX + STR2NR_FORCE;
	    ++format_found;
	}
	else if (*p == 'u')
	    unique = TRUE;
	else if (*p == '"')	
	    break;
	else if (eap->nextcmd == NULL && check_nextcmd(p) != NULL)
	{
	    eap->nextcmd = check_nextcmd(p);
	    break;
	}
	else if (!ASCII_ISALPHA(*p) && regmatch.regprog == NULL)
	{
	    s = skip_regexp_err(p + 1, *p, TRUE);
	    if (s == NULL)
		goto sortend;
	    *s = NUL;
	    
	    if (s == p + 1)
	    {
		if (last_search_pat() == NULL)
		{
		    emsg(_(e_no_previous_regular_expression));
		    goto sortend;
		}
		regmatch.regprog = vim_regcomp(last_search_pat(), RE_MAGIC);
	    }
	    else regmatch.regprog = vim_regcomp(p + 1, RE_MAGIC);
	    if (regmatch.regprog == NULL)
		goto sortend;
	    p = s;		
	    regmatch.rm_ic = p_ic;
	}
	else {
	    semsg(_(e_invalid_argument_str), p);
	    goto sortend;
	}
    }

    
    if (format_found > 1)
    {
	emsg(_(e_invalid_argument));
	goto sortend;
    }

    
    
    sort_nr += sort_what;

    
    for (lnum = eap->line1; lnum <= eap->line2; ++lnum)
    {
	s = ml_get(lnum);
	len = (int)STRLEN(s);
	if (maxlen < len)
	    maxlen = len;

	start_col = 0;
	end_col = len;
	if (regmatch.regprog != NULL && vim_regexec(&regmatch, s, 0))
	{
	    if (sort_rx)
	    {
		start_col = (colnr_T)(regmatch.startp[0] - s);
		end_col = (colnr_T)(regmatch.endp[0] - s);
	    }
	    else start_col = (colnr_T)(regmatch.endp[0] - s);
	}
	else if (regmatch.regprog != NULL)
		end_col = 0;

	if (sort_nr  || sort_flt  )



	{
	    
	    
	    s2 = s + end_col;
	    c = *s2;
	    *s2 = NUL;
	    
	    p = s + start_col;
	    if (sort_nr)
	    {
		if (sort_what & STR2NR_HEX)
		    s = skiptohex(p);
		else if (sort_what & STR2NR_BIN)
		    s = skiptobin(p);
		else s = skiptodigit(p);
		if (s > p && s[-1] == '-')
		    --s;  
		if (*s == NUL)
		{
		    
		    nrs[lnum - eap->line1].st_u.num.is_number = FALSE;
		    nrs[lnum - eap->line1].st_u.num.value = 0;
		}
		else {
		    nrs[lnum - eap->line1].st_u.num.is_number = TRUE;
		    vim_str2nr(s, NULL, NULL, sort_what, &nrs[lnum - eap->line1].st_u.num.value, NULL, 0, FALSE);

		}
	    }

	    else {
		s = skipwhite(p);
		if (*s == '+')
		    s = skipwhite(s + 1);

		if (*s == NUL)
		    
		    nrs[lnum - eap->line1].st_u.value_flt = -DBL_MAX;
		else nrs[lnum - eap->line1].st_u.value_flt = strtod((char *)s, NULL);

	    }

	    *s2 = c;
	}
	else {
	    
	    nrs[lnum - eap->line1].st_u.line.start_col_nr = start_col;
	    nrs[lnum - eap->line1].st_u.line.end_col_nr = end_col;
	}

	nrs[lnum - eap->line1].lnum = lnum;

	if (regmatch.regprog != NULL)
	    fast_breakcheck();
	if (got_int)
	    goto sortend;
    }

    
    sortbuf1 = alloc(maxlen + 1);
    if (sortbuf1 == NULL)
	goto sortend;
    sortbuf2 = alloc(maxlen + 1);
    if (sortbuf2 == NULL)
	goto sortend;

    
    qsort((void *)nrs, count, sizeof(sorti_T), sort_compare);

    if (sort_abort)
	goto sortend;

    
    lnum = eap->line2;
    for (i = 0; i < count; ++i)
    {
	linenr_T get_lnum = nrs[eap->forceit ? count - i - 1 : i].lnum;

	
	
	if (get_lnum + ((linenr_T)count - 1) != lnum)
	    change_occurred = TRUE;

	s = ml_get(get_lnum);
	if (!unique || i == 0 || string_compare(s, sortbuf1) != 0)
	{
	    
	    
	    STRCPY(sortbuf1, s);
	    if (ml_append(lnum++, sortbuf1, (colnr_T)0, FALSE) == FAIL)
		break;
	}
	fast_breakcheck();
	if (got_int)
	    goto sortend;
    }

    
    if (i == count)
	for (i = 0; i < count; ++i)
	    ml_delete(eap->line1);
    else count = 0;

    
    deleted = (long)(count - (lnum - eap->line2));
    if (deleted > 0)
    {
	mark_adjust(eap->line2 - deleted, eap->line2, (long)MAXLNUM, -deleted);
	msgmore(-deleted);
    }
    else if (deleted < 0)
	mark_adjust(eap->line2, MAXLNUM, -deleted, 0L);

    if (change_occurred || deleted != 0)
	changed_lines(eap->line1, 0, eap->line2 + 1, -deleted);

    curwin->w_cursor.lnum = eap->line1;
    beginline(BL_WHITE | BL_FIX);

sortend:
    vim_free(nrs);
    vim_free(sortbuf1);
    vim_free(sortbuf2);
    vim_regfree(regmatch.regprog);
    if (got_int)
	emsg(_(e_interrupted));
}


    int do_move(linenr_T line1, linenr_T line2, linenr_T dest)
{
    char_u	*str;
    linenr_T	l;
    linenr_T	extra;	    
    linenr_T	num_lines;  
    linenr_T	last_line;  

    win_T	*win;
    tabpage_T	*tp;


    if (dest >= line1 && dest < line2)
    {
	emsg(_(e_cannot_move_range_of_lines_into_itself));
	return FAIL;
    }

    
    
    if (dest == line1 - 1 || dest == line2)
    {
	
	
	if (dest >= line1)
	    curwin->w_cursor.lnum = dest;
	else curwin->w_cursor.lnum = dest + (line2 - line1) + 1;

	return OK;
    }

    num_lines = line2 - line1 + 1;

    
    if (u_save(dest, dest + 1) == FAIL)
	return FAIL;
    for (extra = 0, l = line1; l <= line2; l++)
    {
	str = vim_strsave(ml_get(l + extra));
	if (str != NULL)
	{
	    ml_append(dest + l - line1, str, (colnr_T)0, FALSE);
	    vim_free(str);
	    if (dest < line1)
		extra++;
	}
    }

    
    last_line = curbuf->b_ml.ml_line_count;
    mark_adjust_nofold(line1, line2, last_line - line2, 0L);
    if (dest >= line2)
    {
	mark_adjust_nofold(line2 + 1, dest, -num_lines, 0L);

	FOR_ALL_TAB_WINDOWS(tp, win) {
	    if (win->w_buffer == curbuf)
		foldMoveRange(&win->w_folds, line1, line2, dest);
	}

	if ((cmdmod.cmod_flags & CMOD_LOCKMARKS) == 0)
	{
	    curbuf->b_op_start.lnum = dest - num_lines + 1;
	    curbuf->b_op_end.lnum = dest;
	}
    }
    else {
	mark_adjust_nofold(dest + 1, line1 - 1, num_lines, 0L);

	FOR_ALL_TAB_WINDOWS(tp, win) {
	    if (win->w_buffer == curbuf)
		foldMoveRange(&win->w_folds, dest + 1, line1 - 1, line2);
	}

	if ((cmdmod.cmod_flags & CMOD_LOCKMARKS) == 0)
	{
	    curbuf->b_op_start.lnum = dest + 1;
	    curbuf->b_op_end.lnum = dest + num_lines;
	}
    }
    if ((cmdmod.cmod_flags & CMOD_LOCKMARKS) == 0)
	curbuf->b_op_start.col = curbuf->b_op_end.col = 0;
    mark_adjust_nofold(last_line - num_lines + 1, last_line, -(last_line - dest - extra), 0L);

    
    if (u_save(line1 + extra - 1, line2 + extra + 1) == FAIL)
	return FAIL;

    for (l = line1; l <= line2; l++)
	ml_delete_flags(line1 + extra, ML_DEL_MESSAGE);

    if (!global_busy && num_lines > p_report)
	smsg(NGETTEXT("%ld line moved", "%ld lines moved", num_lines), (long)num_lines);

    
    if (dest >= line1)
	curwin->w_cursor.lnum = dest;
    else curwin->w_cursor.lnum = dest + (line2 - line1) + 1;

    if (line1 < dest)
    {
	dest += num_lines + 1;
	last_line = curbuf->b_ml.ml_line_count;
	if (dest > last_line + 1)
	    dest = last_line + 1;
	changed_lines(line1, 0, dest, 0L);
    }
    else changed_lines(dest + 1, 0, line1 + num_lines, 0L);

    return OK;
}


    void ex_copy(linenr_T line1, linenr_T line2, linenr_T n)
{
    linenr_T	count;
    char_u	*p;

    count = line2 - line1 + 1;
    if ((cmdmod.cmod_flags & CMOD_LOCKMARKS) == 0)
    {
	curbuf->b_op_start.lnum = n + 1;
	curbuf->b_op_end.lnum = n + count;
	curbuf->b_op_start.col = curbuf->b_op_end.col = 0;
    }

    
    if (u_save(n, n + 1) == FAIL)
	return;

    curwin->w_cursor.lnum = n;
    while (line1 <= line2)
    {
	
	
	p = vim_strsave(ml_get(line1));
	if (p != NULL)
	{
	    ml_append(curwin->w_cursor.lnum, p, (colnr_T)0, FALSE);
	    vim_free(p);
	}
	
	if (line1 == n)
	    line1 = curwin->w_cursor.lnum;
	++line1;
	if (curwin->w_cursor.lnum < line1)
	    ++line1;
	if (curwin->w_cursor.lnum < line2)
	    ++line2;
	++curwin->w_cursor.lnum;
    }

    appended_lines_mark(n, count);
    if (VIsual_active)
	check_pos(curbuf, &VIsual);

    msgmore((long)count);
}

static char_u	*prevcmd = NULL;	


    void free_prev_shellcmd(void)
{
    vim_free(prevcmd);
}



    void do_bang( int		addr_count, exarg_T	*eap, int		forceit, int		do_in, int		do_out)





{
    char_u		*arg = eap->arg;	
    linenr_T		line1 = eap->line1;	
    linenr_T		line2 = eap->line2;	
    char_u		*newcmd = NULL;		
    int			free_newcmd = FALSE;    
    int			ins_prevcmd;
    char_u		*t;
    char_u		*p;
    char_u		*trailarg;
    int			len;
    int			scroll_save = msg_scroll;

    
    if (check_restricted() || check_secure())
	return;

    if (addr_count == 0)		
    {
	msg_scroll = FALSE;	    
	autowrite_all();
	msg_scroll = scroll_save;
    }

    
    ins_prevcmd = forceit;
    trailarg = arg;
    do {
	len = (int)STRLEN(trailarg) + 1;
	if (newcmd != NULL)
	    len += (int)STRLEN(newcmd);
	if (ins_prevcmd)
	{
	    if (prevcmd == NULL)
	    {
		emsg(_(e_no_previous_command));
		vim_free(newcmd);
		return;
	    }
	    len += (int)STRLEN(prevcmd);
	}
	if ((t = alloc(len)) == NULL)
	{
	    vim_free(newcmd);
	    return;
	}
	*t = NUL;
	if (newcmd != NULL)
	    STRCAT(t, newcmd);
	if (ins_prevcmd)
	    STRCAT(t, prevcmd);
	p = t + STRLEN(t);
	STRCAT(t, trailarg);
	vim_free(newcmd);
	newcmd = t;

	
	trailarg = NULL;
	while (*p)
	{
	    if (*p == '!')
	    {
		if (p > newcmd && p[-1] == '\\')
		    STRMOVE(p - 1, p);
		else {
		    trailarg = p;
		    *trailarg++ = NUL;
		    ins_prevcmd = TRUE;
		    break;
		}
	    }
	    ++p;
	}
    } while (trailarg != NULL);

    vim_free(prevcmd);
    prevcmd = newcmd;

    if (bangredo)	    
    {
	
	
	
	char_u *cmd = vim_strsave_escaped(prevcmd, (char_u *)"%#");

	if (cmd != NULL)
	{
	    AppendToRedobuffLit(cmd, -1);
	    vim_free(cmd);
	}
	else AppendToRedobuffLit(prevcmd, -1);
	AppendToRedobuff((char_u *)"\n");
	bangredo = FALSE;
    }
    
    if (*p_shq != NUL)
    {
	newcmd = alloc(STRLEN(prevcmd) + 2 * STRLEN(p_shq) + 1);
	if (newcmd == NULL)
	    return;
	STRCPY(newcmd, p_shq);
	STRCAT(newcmd, prevcmd);
	STRCAT(newcmd, p_shq);
	free_newcmd = TRUE;
    }
    if (addr_count == 0)		
    {
	
	msg_start();
	msg_putchar(':');
	msg_putchar('!');
	msg_outtrans(newcmd);
	msg_clr_eos();
	windgoto(msg_row, msg_col);

	do_shell(newcmd, 0);
    }
    else				 {
	
	
	do_filter(line1, line2, eap, newcmd, do_in, do_out);
	apply_autocmds(EVENT_SHELLFILTERPOST, NULL, NULL, FALSE, curbuf);
    }
    if (free_newcmd)
	vim_free(newcmd);
}


    static void do_filter( linenr_T	line1, linenr_T	line2, exarg_T	*eap, char_u	*cmd, int		do_in, int		do_out)






{
    char_u	*itmp = NULL;
    char_u	*otmp = NULL;
    linenr_T	linecount;
    linenr_T	read_linecount;
    pos_T	cursor_save;
    char_u	*cmd_buf;
    buf_T	*old_curbuf = curbuf;
    int		shell_flags = 0;
    pos_T	orig_start = curbuf->b_op_start;
    pos_T	orig_end = curbuf->b_op_end;
    int		save_cmod_flags = cmdmod.cmod_flags;

    int		stmp = p_stmp;


    if (*cmd == NUL)	    
	return;

    
    
    cmdmod.cmod_flags &= ~CMOD_LOCKMARKS;

    cursor_save = curwin->w_cursor;
    linecount = line2 - line1 + 1;
    curwin->w_cursor.lnum = line1;
    curwin->w_cursor.col = 0;
    changed_line_abv_curs();
    invalidate_botline();

    

    if (do_out)
	shell_flags |= SHELL_DOOUT;



    if (!gui.in_use && !gui.starting)
	stmp = 1;   


    if (!do_in && do_out && !stmp)
    {
	
	shell_flags |= SHELL_READ;
	curwin->w_cursor.lnum = line2;
    }
    else if (do_in && !do_out && !stmp)
    {
	
	shell_flags |= SHELL_WRITE;
	curbuf->b_op_start.lnum = line1;
	curbuf->b_op_end.lnum = line2;
    }
    else if (do_in && do_out && !stmp)
    {
	
	
	shell_flags |= SHELL_READ|SHELL_WRITE;
	curbuf->b_op_start.lnum = line1;
	curbuf->b_op_end.lnum = line2;
	curwin->w_cursor.lnum = line2;
    }
    else  if ((do_in && (itmp = vim_tempname('i', FALSE)) == NULL)

		|| (do_out && (otmp = vim_tempname('o', FALSE)) == NULL))
	{
	    emsg(_(e_cant_get_temp_file_name));
	    goto filterend;
	}


    ++no_wait_return;		
    if (itmp != NULL && buf_write(curbuf, itmp, NULL, line1, line2, eap, FALSE, FALSE, FALSE, TRUE) == FAIL)
    {
	msg_putchar('\n');		
	--no_wait_return;

	if (!aborting())

	    (void)semsg(_(e_cant_create_file_str), itmp);	
	goto filterend;
    }
    if (curbuf != old_curbuf)
	goto filterend;

    if (!do_out)
	msg_putchar('\n');

    
    cmd_buf = make_filter_cmd(cmd, itmp, otmp);
    if (cmd_buf == NULL)
	goto filterend;

    windgoto((int)Rows - 1, 0);
    cursor_on();

    
    if (!do_out || STRCMP(p_srr, ">") == 0 || !do_in)
	redraw_later_clear();

    if (do_out)
    {
	if (u_save(line2, (linenr_T)(line2 + 1)) == FAIL)
	{
	    vim_free(cmd_buf);
	    goto error;
	}
	redraw_curbuf_later(VALID);
    }
    read_linecount = curbuf->b_ml.ml_line_count;

    
    if (call_shell(cmd_buf, SHELL_FILTER | SHELL_COOKED | shell_flags))
    {
	redraw_later_clear();
	wait_return(FALSE);
    }
    vim_free(cmd_buf);

    did_check_timestamps = FALSE;
    need_check_timestamps = TRUE;

    
    
    
    ui_breakcheck();
    got_int = FALSE;

    if (do_out)
    {
	if (otmp != NULL)
	{
	    if (readfile(otmp, NULL, line2, (linenr_T)0, (linenr_T)MAXLNUM, eap, READ_FILTER) != OK)
	    {

		if (!aborting())

		{
		    msg_putchar('\n');
		    semsg(_(e_cant_read_file_str), otmp);
		}
		goto error;
	    }
	    if (curbuf != old_curbuf)
		goto filterend;
	}

	read_linecount = curbuf->b_ml.ml_line_count - read_linecount;

	if (shell_flags & SHELL_READ)
	{
	    curbuf->b_op_start.lnum = line2 + 1;
	    curbuf->b_op_end.lnum = curwin->w_cursor.lnum;
	    appended_lines_mark(line2, read_linecount);
	}

	if (do_in)
	{
	    if ((cmdmod.cmod_flags & CMOD_KEEPMARKS)
				     || vim_strchr(p_cpo, CPO_REMMARK) == NULL)
	    {
		if (read_linecount >= linecount)
		    
		    mark_adjust(line1, line2, linecount, 0L);
		else if (save_cmod_flags & CMOD_LOCKMARKS)
		{
		    
		    
		    
		    
		    mark_adjust(line2 + 1, (linenr_T)MAXLNUM, linecount - read_linecount, 0L);
		    mark_adjust(line1, line2, linecount, 0L);
		}
		else {
		    
		    
		    mark_adjust(line1, line1 + read_linecount - 1, linecount, 0L);
		    mark_adjust(line1 + read_linecount, line2, MAXLNUM, 0L);
		}
	    }

	    
	    curwin->w_cursor.lnum = line1;
	    del_lines(linecount, TRUE);
	    curbuf->b_op_start.lnum -= linecount;	
	    curbuf->b_op_end.lnum -= linecount;		
	    write_lnum_adjust(-linecount);		
							

	    foldUpdate(curwin, curbuf->b_op_start.lnum, curbuf->b_op_end.lnum);

	}
	else {
	    
	    linecount = curbuf->b_op_end.lnum - curbuf->b_op_start.lnum + 1;
	    curwin->w_cursor.lnum = curbuf->b_op_end.lnum;
	}

	beginline(BL_WHITE | BL_FIX);	    
	--no_wait_return;

	if (linecount > p_report)
	{
	    if (do_in)
	    {
		vim_snprintf(msg_buf, sizeof(msg_buf), _("%ld lines filtered"), (long)linecount);
		if (msg(msg_buf) && !msg_scroll)
		    
		    set_keep_msg((char_u *)msg_buf, 0);
	    }
	    else msgmore((long)linecount);
	}
    }
    else {
error:
	
	curwin->w_cursor = cursor_save;
	--no_wait_return;
	wait_return(FALSE);
    }

filterend:

    cmdmod.cmod_flags = save_cmod_flags;
    if (curbuf != old_curbuf)
    {
	--no_wait_return;
	emsg(_(e_filter_autocommands_must_not_change_current_buffer));
    }
    else if (cmdmod.cmod_flags & CMOD_LOCKMARKS)
    {
	curbuf->b_op_start = orig_start;
	curbuf->b_op_end = orig_end;
    }

    if (itmp != NULL)
	mch_remove(itmp);
    if (otmp != NULL)
	mch_remove(otmp);
    vim_free(itmp);
    vim_free(otmp);
}


    void do_shell( char_u	*cmd, int		flags)


{
    buf_T	*buf;

    int		save_nwr;


    int		winstart = FALSE;

    int		keep_termcap = !termcap_active;

    
    if (check_restricted() || check_secure())
    {
	msg_end();
	return;
    }


    
    if (cmd != NULL)
	keep_termcap = winstart = (STRNICMP(cmd, "start ", 6) == 0);


    
    if (gui.in_use && vim_strchr(p_go, GO_TERMINAL) != NULL)
	keep_termcap = TRUE;



    
    msg_putchar('\r');			
    if (!autocmd_busy)
    {
	if (!keep_termcap)
	    stoptermcap();
    }

    if (!winstart)

	msg_putchar('\n');		

    
    if (p_warn && !autocmd_busy && msg_silent == 0)
	FOR_ALL_BUFFERS(buf)
	    if (bufIsChangedNotTerm(buf))
	    {

		if (!keep_termcap)
		    starttermcap();	

		msg_puts(_("[No write since last change]\n"));

		if (!keep_termcap)
		    stoptermcap();

		break;
	    }

    
    
    if (!swapping_screen())
	windgoto(msg_row, msg_col);
    cursor_on();
    (void)call_shell(cmd, SHELL_COOKED | flags);
    did_check_timestamps = FALSE;
    need_check_timestamps = TRUE;

    
    if (!swapping_screen())
    {
	msg_row = Rows - 1;
	msg_col = 0;
    }

    if (autocmd_busy)
    {
	if (msg_silent == 0)
	    redraw_later_clear();
    }
    else {
	


	if (!gui.in_use)

	{
	    if (cmd == NULL  || (keep_termcap && !need_wait_return)


	       )
	    {
		if (msg_silent == 0)
		    redraw_later_clear();
		need_wait_return = FALSE;
	    }
	    else {
		
		save_nwr = no_wait_return;
		if (swapping_screen())
		    no_wait_return = FALSE;

		wait_return(term_console ? -1 : msg_silent == 0); 

		wait_return(msg_silent == 0);

		no_wait_return = save_nwr;
	    }
	}


	if (!keep_termcap)	
	    starttermcap();	

	

	if (skip_redraw)		
	{
	    if (msg_silent == 0)
		redraw_later_clear();
	}
	else if (term_console)
	{
	    OUT_STR("\033[0 q");	
	    if (got_int && msg_silent == 0)
		redraw_later_clear();	
	    else must_redraw = 0;
	}

    }

    
    display_errors();

    apply_autocmds(EVENT_SHELLCMDPOST, NULL, NULL, FALSE, curbuf);
}


    static char_u * find_pipe(char_u *cmd)
{
    char_u  *p;
    int	    inquote = FALSE;

    for (p = cmd; *p != NUL; ++p)
    {
	if (!inquote && *p == '|')
	    return p;
	if (*p == '"')
	    inquote = !inquote;
	else if (rem_backslash(p))
	    ++p;
    }
    return NULL;
}



    char_u * make_filter_cmd( char_u	*cmd, char_u	*itmp, char_u	*otmp)



{
    char_u	*buf;
    long_u	len;


    int		is_fish_shell;
    char_u	*shell_name = get_isolated_shell_name();

    if (shell_name == NULL)
	return NULL;

    
    is_fish_shell = (fnamecmp(shell_name, "fish") == 0);
    vim_free(shell_name);
    if (is_fish_shell)
	len = (long_u)STRLEN(cmd) + 13;		
    else  len = (long_u)STRLEN(cmd) + 3;

    if (itmp != NULL)
	len += (long_u)STRLEN(itmp) + 9;		
    if (otmp != NULL)
	len += (long_u)STRLEN(otmp) + (long_u)STRLEN(p_srr) + 2; 
    buf = alloc(len);
    if (buf == NULL)
	return NULL;


    
    if (itmp != NULL || otmp != NULL)
    {
	if (is_fish_shell)
	    vim_snprintf((char *)buf, len, "begin; %s; end", (char *)cmd);
	else vim_snprintf((char *)buf, len, "(%s)", (char *)cmd);
    }
    else STRCPY(buf, cmd);
    if (itmp != NULL)
    {
	STRCAT(buf, " < ");
	STRCAT(buf, itmp);
    }

    
    
    if (*p_sxe != NUL && *p_sxq == '(')
    {
	if (itmp != NULL || otmp != NULL)
	    vim_snprintf((char *)buf, len, "(%s)", (char *)cmd);
	else STRCPY(buf, cmd);
	if (itmp != NULL)
	{
	    STRCAT(buf, " < ");
	    STRCAT(buf, itmp);
	}
    }
    else {
	STRCPY(buf, cmd);
	if (itmp != NULL)
	{
	    char_u	*p;

	    
	    
	    
	    if (*p_shq == NUL)
	    {
		p = find_pipe(buf);
		if (p != NULL)
		    *p = NUL;
	    }
	    STRCAT(buf, " <");	
	    STRCAT(buf, itmp);
	    if (*p_shq == NUL)
	    {
		p = find_pipe(cmd);
		if (p != NULL)
		{
		    STRCAT(buf, " ");  
		    STRCAT(buf, p);
		}
	    }
	}
    }

    if (otmp != NULL)
	append_redir(buf, (int)len, p_srr, otmp);

    return buf;
}


    void append_redir( char_u	*buf, int		buflen, char_u	*opt, char_u	*fname)




{
    char_u	*p;
    char_u	*end;

    end = buf + STRLEN(buf);
    
    for (p = opt; (p = vim_strchr(p, '%')) != NULL; ++p)
    {
	if (p[1] == 's') 
	    break;
	if (p[1] == '%') 
	    ++p;
    }
    if (p != NULL)
    {

	*end++ = ' '; 

	vim_snprintf((char *)end, (size_t)(buflen - (end - buf)), (char *)opt, (char *)fname);
    }
    else vim_snprintf((char *)end, (size_t)(buflen - (end - buf)),  " %s %s",  " %s%s",  (char *)opt, (char *)fname);






}


    void do_fixdel(exarg_T *eap UNUSED)
{
    char_u  *p;

    p = find_termcode((char_u *)"kb");
    add_termcode((char_u *)"kD", p != NULL && *p == DEL ? (char_u *)CTRL_H_STR : DEL_STR, FALSE);
}

    void print_line_no_prefix( linenr_T	lnum, int		use_number, int		list)



{
    char	numbuf[30];

    if (curwin->w_p_nu || use_number)
    {
	vim_snprintf(numbuf, sizeof(numbuf), "%*ld ", number_width(curwin), (long)lnum);
	msg_puts_attr(numbuf, HL_ATTR(HLF_N));	
    }
    msg_prt_line(ml_get(lnum), list);
}


    void print_line(linenr_T lnum, int use_number, int list)
{
    int		save_silent = silent_mode;

    
    if (message_filtered(ml_get(lnum)))
	return;

    msg_start();
    silent_mode = FALSE;
    info_message = TRUE;	
    print_line_no_prefix(lnum, use_number, list);
    if (save_silent)
    {
	msg_putchar('\n');
	cursor_on();		
	out_flush();
	silent_mode = save_silent;
    }
    info_message = FALSE;
}

    int rename_buffer(char_u *new_fname)
{
    char_u	*fname, *sfname, *xfname;
    buf_T	*buf;

    buf = curbuf;
    apply_autocmds(EVENT_BUFFILEPRE, NULL, NULL, FALSE, curbuf);
    
    if (buf != curbuf)
	return FAIL;

    if (aborting())	    
	return FAIL;

    
    fname = curbuf->b_ffname;
    sfname = curbuf->b_sfname;
    xfname = curbuf->b_fname;
    curbuf->b_ffname = NULL;
    curbuf->b_sfname = NULL;
    if (setfname(curbuf, new_fname, NULL, TRUE) == FAIL)
    {
	curbuf->b_ffname = fname;
	curbuf->b_sfname = sfname;
	return FAIL;
    }
    curbuf->b_flags |= BF_NOTEDITED;
    if (xfname != NULL && *xfname != NUL)
    {
	buf = buflist_new(fname, xfname, curwin->w_cursor.lnum, 0);
	if (buf != NULL && (cmdmod.cmod_flags & CMOD_KEEPALT) == 0)
	    curwin->w_alt_fnum = buf->b_fnum;
    }
    vim_free(fname);
    vim_free(sfname);
    apply_autocmds(EVENT_BUFFILEPOST, NULL, NULL, FALSE, curbuf);

    
    DO_AUTOCHDIR;
    return OK;
}


    void ex_file(exarg_T *eap)
{
    
    
    if (eap->addr_count > 0 && (*eap->arg != NUL || eap->line2 > 0 || eap->addr_count > 1))


    {
	emsg(_(e_invalid_argument));
	return;
    }

    if (*eap->arg != NUL || eap->addr_count == 1)
    {
	if (rename_buffer(eap->arg) == FAIL)
	    return;
	redraw_tabline = TRUE;
    }

    
    if (*eap->arg == NUL || !shortmess(SHM_FILEINFO))
	fileinfo(FALSE, FALSE, eap->forceit);
}


    void ex_update(exarg_T *eap)
{
    if (curbufIsChanged())
	(void)do_write(eap);
}


    void ex_write(exarg_T *eap)
{
    if (eap->cmdidx == CMD_saveas)
    {
	
	eap->line1 = 1;
	eap->line2 = curbuf->b_ml.ml_line_count;
    }

    if (eap->usefilter)		
	do_bang(1, eap, FALSE, TRUE, FALSE);
    else (void)do_write(eap);
}


    static int check_writable(char_u *fname)
{
    if (mch_nodetype(fname) == NODE_OTHER)
    {
	semsg(_(e_str_is_not_file_or_writable_device), fname);
	return FAIL;
    }
    return OK;
}



    int do_write(exarg_T *eap)
{
    int		other;
    char_u	*fname = NULL;		
    char_u	*ffname;
    int		retval = FAIL;
    char_u	*free_fname = NULL;

    char_u	*browse_file = NULL;

    buf_T	*alt_buf = NULL;
    int		name_was_missing;

    if (not_writing())		
	return FAIL;

    ffname = eap->arg;

    if ((cmdmod.cmod_flags & CMOD_BROWSE) && !exiting)
    {
	browse_file = do_browse(BROWSE_SAVE, (char_u *)_("Save As"), ffname, NULL, NULL, NULL, curbuf);
	if (browse_file == NULL)
	    goto theend;
	ffname = browse_file;
    }

    if (*ffname == NUL)
    {
	if (eap->cmdidx == CMD_saveas)
	{
	    emsg(_(e_argument_required));
	    goto theend;
	}
	other = FALSE;
    }
    else {
	fname = ffname;
	free_fname = fix_fname(ffname);
	
	if (free_fname != NULL)
	    ffname = free_fname;
	other = otherfile(ffname);
    }

    
    if (other)
    {
	if (vim_strchr(p_cpo, CPO_ALTWRITE) != NULL || eap->cmdidx == CMD_saveas)
	    alt_buf = setaltfname(ffname, fname, (linenr_T)1);
	else alt_buf = buflist_findname(ffname);
	if (alt_buf != NULL && alt_buf->b_ml.ml_mfp != NULL)
	{
	    
	    
	    emsg(_(e_file_is_loaded_in_another_buffer));
	    goto theend;
	}
    }

    
    if (!other && (  bt_dontwrite_msg(curbuf) ||  check_fname() == FAIL  || check_writable(curbuf->b_ffname) == FAIL  || check_readonly(&eap->forceit, curbuf)))







	goto theend;

    if (!other)
    {
	ffname = curbuf->b_ffname;
	fname = curbuf->b_fname;
	
	if (	   (eap->line1 != 1 || eap->line2 != curbuf->b_ml.ml_line_count)
		&& !eap->forceit && !eap->append && !p_wa)

	{

	    if (p_confirm || (cmdmod.cmod_flags & CMOD_CONFIRM))
	    {
		if (vim_dialog_yesno(VIM_QUESTION, NULL, (char_u *)_("Write partial file?"), 2) != VIM_YES)
		    goto theend;
		eap->forceit = TRUE;
	    }
	    else  {

		emsg(_(e_use_bang_to_write_partial_buffer));
		goto theend;
	    }
	}
    }

    if (check_overwrite(eap, curbuf, fname, ffname, other) == OK)
    {
	if (eap->cmdidx == CMD_saveas && alt_buf != NULL)
	{
	    buf_T	*was_curbuf = curbuf;

	    apply_autocmds(EVENT_BUFFILEPRE, NULL, NULL, FALSE, curbuf);
	    apply_autocmds(EVENT_BUFFILEPRE, NULL, NULL, FALSE, alt_buf);

	    if (curbuf != was_curbuf || aborting())

	    if (curbuf != was_curbuf)

	    {
		
		retval = FAIL;
		goto theend;
	    }
	    
	    
	    
	    
	    
	    fname = alt_buf->b_fname;
	    alt_buf->b_fname = curbuf->b_fname;
	    curbuf->b_fname = fname;
	    fname = alt_buf->b_ffname;
	    alt_buf->b_ffname = curbuf->b_ffname;
	    curbuf->b_ffname = fname;
	    fname = alt_buf->b_sfname;
	    alt_buf->b_sfname = curbuf->b_sfname;
	    curbuf->b_sfname = fname;
	    buf_name_changed(curbuf);

	    apply_autocmds(EVENT_BUFFILEPOST, NULL, NULL, FALSE, curbuf);
	    apply_autocmds(EVENT_BUFFILEPOST, NULL, NULL, FALSE, alt_buf);
	    if (!alt_buf->b_p_bl)
	    {
		alt_buf->b_p_bl = TRUE;
		apply_autocmds(EVENT_BUFADD, NULL, NULL, FALSE, alt_buf);
	    }

	    if (curbuf != was_curbuf || aborting())

	    if (curbuf != was_curbuf)

	    {
		
		retval = FAIL;
		goto theend;
	    }

	    
	    if (*curbuf->b_p_ft == NUL)
	    {
		if (au_has_group((char_u *)"filetypedetect"))
		    (void)do_doautocmd((char_u *)"filetypedetect BufRead", TRUE, NULL);
		do_modelines(0);
	    }

	    
	    
	    fname = curbuf->b_sfname;
	}

	name_was_missing = curbuf->b_ffname == NULL;

	retval = buf_write(curbuf, ffname, fname, eap->line1, eap->line2, eap, eap->append, eap->forceit, TRUE, FALSE);

	
	if (eap->cmdidx == CMD_saveas)
	{
	    if (retval == OK)
	    {
		curbuf->b_p_ro = FALSE;
		redraw_tabline = TRUE;
	    }
	}

	
	
	if (eap->cmdidx == CMD_saveas || name_was_missing)
	    DO_AUTOCHDIR;
    }

theend:

    vim_free(browse_file);

    vim_free(free_fname);
    return retval;
}


    int check_overwrite( exarg_T	*eap, buf_T	*buf, char_u	*fname,  char_u	*ffname, int		other)






{
    
    if (       (other || (buf->b_flags & BF_NOTEDITED)
		|| ((buf->b_flags & BF_NEW)
		    && vim_strchr(p_cpo, CPO_OVERNEW) == NULL)
		|| (buf->b_flags & BF_READERR))
	    && !p_wa && vim_fexists(ffname))
    {
	if (!eap->forceit && !eap->append)
	{

	    
	    if (mch_isdir(ffname))
	    {
		semsg(_(e_str_is_directory), ffname);
		return FAIL;
	    }


	    if (p_confirm || (cmdmod.cmod_flags & CMOD_CONFIRM))
	    {
		char_u	buff[DIALOG_MSG_SIZE];

		dialog_msg(buff, _("Overwrite existing file \"%s\"?"), fname);
		if (vim_dialog_yesno(VIM_QUESTION, NULL, buff, 2) != VIM_YES)
		    return FAIL;
		eap->forceit = TRUE;
	    }
	    else  {

		emsg(_(e_file_exists));
		return FAIL;
	    }
	}

	
	if (other && !emsg_silent)
	{
	    char_u	*dir;
	    char_u	*p;
	    int		r;
	    char_u	*swapname;

	    
	    
	    
	    
	    
	    if (*p_dir == NUL)
	    {
		dir = alloc(5);
		if (dir == NULL)
		    return FAIL;
		STRCPY(dir, ".");
	    }
	    else {
		dir = alloc(MAXPATHL);
		if (dir == NULL)
		    return FAIL;
		p = p_dir;
		copy_option_part(&p, dir, MAXPATHL, ",");
	    }
	    swapname = makeswapname(fname, ffname, curbuf, dir);
	    vim_free(dir);
	    r = vim_fexists(swapname);
	    if (r)
	    {

		if (p_confirm || (cmdmod.cmod_flags & CMOD_CONFIRM))
		{
		    char_u	buff[DIALOG_MSG_SIZE];

		    dialog_msg(buff, _("Swap file \"%s\" exists, overwrite anyway?"), swapname);

		    if (vim_dialog_yesno(VIM_QUESTION, NULL, buff, 2)
								   != VIM_YES)
		    {
			vim_free(swapname);
			return FAIL;
		    }
		    eap->forceit = TRUE;
		}
		else  {

		    semsg(_(e_swap_file_exists_str_silent_overrides), swapname);
		    vim_free(swapname);
		    return FAIL;
		}
	    }
	    vim_free(swapname);
	}
    }
    return OK;
}


    void ex_wnext(exarg_T *eap)
{
    int		i;

    if (eap->cmd[1] == 'n')
	i = curwin->w_arg_idx + (int)eap->line2;
    else i = curwin->w_arg_idx - (int)eap->line2;
    eap->line1 = 1;
    eap->line2 = curbuf->b_ml.ml_line_count;
    if (do_write(eap) != FAIL)
	do_argfile(eap, i);
}


    void do_wqall(exarg_T *eap)
{
    buf_T	*buf;
    int		error = 0;
    int		save_forceit = eap->forceit;

    if (eap->cmdidx == CMD_xall || eap->cmdidx == CMD_wqall)
	exiting = TRUE;

    FOR_ALL_BUFFERS(buf)
    {

	if (exiting && term_job_running(buf->b_term))
	{
	    no_write_message_nobang(buf);
	    ++error;
	}
	else  if (bufIsChanged(buf) && !bt_dontwrite(buf))

	{
	    
	    if (not_writing())
	    {
		++error;
		break;
	    }

	    
	    if (buf->b_ffname == NULL && (cmdmod.cmod_flags & CMOD_BROWSE))
		browse_save_fname(buf);

	    if (buf->b_ffname == NULL)
	    {
		semsg(_(e_no_file_name_for_buffer_nr), (long)buf->b_fnum);
		++error;
	    }
	    else if (check_readonly(&eap->forceit, buf)
		    || check_overwrite(eap, buf, buf->b_fname, buf->b_ffname, FALSE) == FAIL)
	    {
		++error;
	    }
	    else {
		bufref_T bufref;

		set_bufref(&bufref, buf);
		if (buf_write_all(buf, eap->forceit) == FAIL)
		    ++error;
		
		if (!bufref_valid(&bufref))
		    buf = firstbuf;
	    }
	    eap->forceit = save_forceit;    
	}
    }
    if (exiting)
    {
	if (!error)
	    getout(0);		
	not_exiting();
    }
}


    static int not_writing(void)
{
    if (p_write)
	return FALSE;
    emsg(_(e_file_not_written_writing_is_disabled_by_write_option));
    return TRUE;
}


    static int check_readonly(int *forceit, buf_T *buf)
{
    stat_T	st;

    
    
    
    
    if (!*forceit && (buf->b_p_ro || (mch_stat((char *)buf->b_ffname, &st) >= 0 && check_file_readonly(buf->b_ffname, 0777))))

    {

	if ((p_confirm || (cmdmod.cmod_flags & CMOD_CONFIRM))
						       && buf->b_fname != NULL)
	{
	    char_u	buff[DIALOG_MSG_SIZE];

	    if (buf->b_p_ro)
		dialog_msg(buff, _("'readonly' option is set for \"%s\".\nDo you wish to write anyway?"), buf->b_fname);
	    else dialog_msg(buff, _("File permissions of \"%s\" are read-only.\nIt may still be possible to write it.\nDo you wish to try?"), buf->b_fname);


	    if (vim_dialog_yesno(VIM_QUESTION, NULL, buff, 2) == VIM_YES)
	    {
		
		*forceit = TRUE;
		return FALSE;
	    }
	    else return TRUE;
	}
	else  if (buf->b_p_ro)

	    emsg(_(e_readonly_option_is_set_add_bang_to_override));
	else semsg(_(e_str_is_read_only_add_bang_to_override), buf->b_fname);
	return TRUE;
    }

    return FALSE;
}


    int getfile( int		fnum, char_u	*ffname_arg, char_u	*sfname_arg, int		setpm, linenr_T	lnum, int		forceit)






{
    char_u	*ffname = ffname_arg;
    char_u	*sfname = sfname_arg;
    int		other;
    int		retval;
    char_u	*free_me = NULL;

    if (text_locked())
	return GETFILE_ERROR;
    if (curbuf_locked())
	return GETFILE_ERROR;

    if (fnum == 0)
    {
					
	fname_expand(curbuf, &ffname, &sfname);
	other = otherfile(ffname);
	free_me = ffname;		
    }
    else other = (fnum != curbuf->b_fnum);

    if (other)
	++no_wait_return;	    
    if (other && !forceit && curbuf->b_nwindows == 1 && !buf_hide(curbuf)
		   && curbufIsChanged() && autowrite(curbuf, forceit) == FAIL)
    {

	if (p_confirm && p_write)
	    dialog_changed(curbuf, FALSE);
	if (curbufIsChanged())

	{
	    --no_wait_return;
	    no_write_message();
	    retval = GETFILE_NOT_WRITTEN;	
	    goto theend;
	}
    }
    if (other)
	--no_wait_return;
    if (setpm)
	setpcmark();
    if (!other)
    {
	if (lnum != 0)
	    curwin->w_cursor.lnum = lnum;
	check_cursor_lnum();
	beginline(BL_SOL | BL_FIX);
	retval = GETFILE_SAME_FILE;	
    }
    else if (do_ecmd(fnum, ffname, sfname, NULL, lnum, (buf_hide(curbuf) ? ECMD_HIDE : 0) + (forceit ? ECMD_FORCEIT : 0), curwin) == OK)

	retval = GETFILE_OPEN_OTHER;	
    else retval = GETFILE_ERROR;

theend:
    vim_free(free_me);
    return retval;
}


    int do_ecmd( int		fnum, char_u	*ffname, char_u	*sfname, exarg_T	*eap, linenr_T	newlnum, int		flags, win_T	*oldwin)







{
    int		other_file;		
    int		oldbuf;			
    int		auto_buf = FALSE;	
					
    char_u	*new_name = NULL;

    int		did_set_swapcommand = FALSE;

    buf_T	*buf;
    bufref_T	bufref;
    bufref_T	old_curbuf;
    char_u	*free_fname = NULL;

    char_u	dot_path[] = ".";
    char_u	*browse_file = NULL;

    int		retval = FAIL;
    long	n;
    pos_T	orig_pos;
    linenr_T	topline = 0;
    int		newcol = -1;
    int		solcol = -1;
    pos_T	*pos;
    char_u	*command = NULL;

    int		did_get_winopts = FALSE;

    int		readfile_flags = 0;
    int		did_inc_redrawing_disabled = FALSE;
    long	*so_ptr = curwin->w_p_so >= 0 ? &curwin->w_p_so : &p_so;


    if (ERROR_IF_TERM_POPUP_WINDOW)
	return FAIL;


    if (eap != NULL)
	command = eap->do_ecmd_cmd;
    set_bufref(&old_curbuf, curbuf);

    if (fnum != 0)
    {
	if (fnum == curbuf->b_fnum)	
	    return OK;			
	other_file = TRUE;
    }
    else {

	if ((cmdmod.cmod_flags & CMOD_BROWSE) && !exiting)
	{
	    if (  !gui.in_use &&  au_has_group((char_u *)"FileExplorer"))



	    {
		
		
		if (ffname == NULL || !mch_isdir(ffname))
		    ffname = dot_path;
	    }
	    else {
		browse_file = do_browse(0, (char_u *)_("Edit File"), ffname, NULL, NULL, NULL, curbuf);
		if (browse_file == NULL)
		    goto theend;
		ffname = browse_file;
	    }
	}

	
	if (sfname == NULL)
	    sfname = ffname;

	if (sfname != NULL)
	    fname_case(sfname, 0);   


	if ((flags & (ECMD_ADDBUF | ECMD_ALTBUF))
					 && (ffname == NULL || *ffname == NUL))
	    goto theend;

	if (ffname == NULL)
	    other_file = TRUE;
					    
	else if (*ffname == NUL && curbuf->b_ffname == NULL)
	    other_file = FALSE;
	else {
	    if (*ffname == NUL)		    
	    {
		ffname = curbuf->b_ffname;
		sfname = curbuf->b_fname;
	    }
	    free_fname = fix_fname(ffname); 
	    if (free_fname != NULL)
		ffname = free_fname;
	    other_file = otherfile(ffname);
	}
    }

    
    if (  ((!other_file && !(flags & ECMD_OLDBUF))
	    || (curbuf->b_nwindows == 1 && !(flags & (ECMD_HIDE | ECMD_ADDBUF | ECMD_ALTBUF))))
	&& check_changed(curbuf, (p_awa ? CCGD_AW : 0)
			       | (other_file ? 0 : CCGD_MULTWIN)
			       | ((flags & ECMD_FORCEIT) ? CCGD_FORCEIT : 0)
			       | (eap == NULL ? 0 : CCGD_EXCMD)))
    {
	if (fnum == 0 && other_file && ffname != NULL)
	    (void)setaltfname(ffname, sfname, newlnum < 0 ? 0 : newlnum);
	goto theend;
    }

    
    reset_VIsual();


    if ((command != NULL || newlnum > (linenr_T)0)
	    && *get_vim_var_str(VV_SWAPCOMMAND) == NUL)
    {
	int	len;
	char_u	*p;

	
	if (command != NULL)
	    len = (int)STRLEN(command) + 3;
	else len = 30;
	p = alloc(len);
	if (p != NULL)
	{
	    if (command != NULL)
		vim_snprintf((char *)p, len, ":%s\r", command);
	    else vim_snprintf((char *)p, len, "%ldG", (long)newlnum);
	    set_vim_var_string(VV_SWAPCOMMAND, p, -1);
	    did_set_swapcommand = TRUE;
	    vim_free(p);
	}
    }


    
    if (other_file)
    {
	int prev_alt_fnum = curwin->w_alt_fnum;

	if (!(flags & (ECMD_ADDBUF | ECMD_ALTBUF)))
	{
	    if ((cmdmod.cmod_flags & CMOD_KEEPALT) == 0)
		curwin->w_alt_fnum = curbuf->b_fnum;
	    if (oldwin != NULL)
		buflist_altfpos(oldwin);
	}

	if (fnum)
	    buf = buflist_findnr(fnum);
	else {
	    if (flags & (ECMD_ADDBUF | ECMD_ALTBUF))
	    {
		
		
		linenr_T	tlnum = 0;
		buf_T		*newbuf;

		if (command != NULL)
		{
		    tlnum = atol((char *)command);
		    if (tlnum <= 0)
			tlnum = 1L;
		}
		
		
		newbuf = buflist_new(ffname, sfname, tlnum, BLN_LISTED | BLN_NOCURWIN);
		if (newbuf != NULL && (flags & ECMD_ALTBUF))
		    curwin->w_alt_fnum = newbuf->b_fnum;
		goto theend;
	    }
	    buf = buflist_new(ffname, sfname, 0L, BLN_CURBUF | ((flags & ECMD_SET_HELP) ? 0 : BLN_LISTED));

	    
	    if (oldwin != NULL)
		oldwin = curwin;
	    set_bufref(&old_curbuf, curbuf);
	}
	if (buf == NULL)
	    goto theend;
	if (curwin->w_alt_fnum == buf->b_fnum && prev_alt_fnum != 0)
	    
	    curwin->w_alt_fnum = prev_alt_fnum;

	if (buf->b_ml.ml_mfp == NULL)		
	{
	    oldbuf = FALSE;
	}
	else					 {
	    oldbuf = TRUE;
	    set_bufref(&bufref, buf);
	    (void)buf_check_timestamp(buf, FALSE);
	    
	    
	    if (!bufref_valid(&bufref) || curbuf != old_curbuf.br_buf)
		goto theend;

	    if (aborting())	    
		goto theend;

	}

	
	
	if ((oldbuf && newlnum == ECMD_LASTL) || newlnum == ECMD_LAST)
	{
	    pos = buflist_findfpos(buf);
	    newlnum = pos->lnum;
	    solcol = pos->col;
	}

	
	if (buf != curbuf)
	{
	    bufref_T	save_au_new_curbuf;

	    int		save_cmdwin_type = cmdwin_type;

	    
	    cmdwin_type = 0;

	    
	    if (buf->b_fname != NULL)
		new_name = vim_strsave(buf->b_fname);
	    save_au_new_curbuf = au_new_curbuf;
	    set_bufref(&au_new_curbuf, buf);
	    apply_autocmds(EVENT_BUFLEAVE, NULL, NULL, FALSE, curbuf);

	    cmdwin_type = save_cmdwin_type;

	    if (!bufref_valid(&au_new_curbuf))
	    {
		
		delbuf_msg(new_name);	
		au_new_curbuf = save_au_new_curbuf;
		goto theend;
	    }

	    if (aborting())	    
	    {
		vim_free(new_name);
		au_new_curbuf = save_au_new_curbuf;
		goto theend;
	    }

	    if (buf == curbuf)		
		auto_buf = TRUE;
	    else {
		win_T	    *the_curwin = curwin;
		int	    did_decrement;
		buf_T	    *was_curbuf = curbuf;

		
		
		the_curwin->w_closing = TRUE;
		++buf->b_locked;

		if (curbuf == old_curbuf.br_buf)
		    buf_copy_options(buf, BCO_ENTER);

		
		
		u_sync(FALSE);
		did_decrement = close_buffer(oldwin, curbuf, (flags & ECMD_HIDE) ? 0 : DOBUF_UNLOAD, FALSE, FALSE);

		
		if (win_valid(the_curwin))
		    the_curwin->w_closing = FALSE;
		--buf->b_locked;


		
		if (aborting() && curwin->w_buffer != NULL)
		{
		    vim_free(new_name);
		    au_new_curbuf = save_au_new_curbuf;
		    goto theend;
		}

		
		if (!bufref_valid(&au_new_curbuf))
		{
		    
		    delbuf_msg(new_name);	
		    au_new_curbuf = save_au_new_curbuf;
		    goto theend;
		}
		if (buf == curbuf)		
		{
		    
		    
		    if (did_decrement && buf_valid(was_curbuf))
			++was_curbuf->b_nwindows;
		    if (win_valid_any_tab(oldwin) && oldwin->w_buffer == NULL)
			oldwin->w_buffer = was_curbuf;
		    auto_buf = TRUE;
		}
		else {

		    
		    if (curwin->w_buffer == NULL || curwin->w_s == &(curwin->w_buffer->b_s))
			curwin->w_s = &(buf->b_s);

		    curwin->w_buffer = buf;
		    curbuf = buf;
		    ++curbuf->b_nwindows;

		    
		    if (!oldbuf && eap != NULL)
		    {
			set_file_options(TRUE, eap);
			set_forced_fenc(eap);
		    }
		}

		
		
		
		
		get_winopts(curbuf);

		did_get_winopts = TRUE;

	    }
	    vim_free(new_name);
	    au_new_curbuf = save_au_new_curbuf;
	}

	curwin->w_pcmark.lnum = 1;
	curwin->w_pcmark.col = 0;
    }
    else  {
	if ((flags & (ECMD_ADDBUF | ECMD_ALTBUF)) || check_fname() == FAIL)
	    goto theend;

	oldbuf = (flags & ECMD_OLDBUF);
    }

    
    
    ++RedrawingDisabled;
    did_inc_redrawing_disabled = TRUE;

    buf = curbuf;
    if ((flags & ECMD_SET_HELP) || keep_help_flag)
    {
	prepare_help_buffer();
    }
    else {
	
	
	if (!curbuf->b_help)
	    set_buflisted(TRUE);
    }

    
    
    if (buf != curbuf)
	goto theend;

    if (aborting())	    
	goto theend;


    
    
    
    did_filetype = FALSE;


    if (!other_file && !oldbuf)		
    {
	set_last_cursor(curwin);	
	if (newlnum == ECMD_LAST || newlnum == ECMD_LASTL)
	{
	    newlnum = curwin->w_cursor.lnum;
	    solcol = curwin->w_cursor.col;
	}
	buf = curbuf;
	if (buf->b_fname != NULL)
	    new_name = vim_strsave(buf->b_fname);
	else new_name = NULL;
	set_bufref(&bufref, buf);

	
	
	
	if (!(curbuf->b_flags & BF_NEVERLOADED)
		&& (p_ur < 0 || curbuf->b_ml.ml_line_count <= p_ur))
	{
	    
	    u_sync(FALSE);
	    if (u_savecommon(0, curbuf->b_ml.ml_line_count + 1, 0, TRUE)
								     == FAIL)
	    {
		vim_free(new_name);
		goto theend;
	    }
	    u_unchanged(curbuf);
	    buf_freeall(curbuf, BFA_KEEP_UNDO);

	    
	    readfile_flags = READ_KEEP_UNDO;
	}
	else buf_freeall(curbuf, 0);

	
	
	if (!bufref_valid(&bufref))
	{
	    delbuf_msg(new_name);	
	    goto theend;
	}
	vim_free(new_name);

	
	
	
	if (buf != curbuf)
	    goto theend;

	if (aborting())	    
	    goto theend;

	buf_clear_file(curbuf);
	curbuf->b_op_start.lnum = 0;	
	curbuf->b_op_end.lnum = 0;
    }


    
    retval = OK;

    
    check_arg_idx(curwin);

    if (!auto_buf)
    {
	
	curwin_init();


	
	
	{
	    win_T	    *win;
	    tabpage_T	    *tp;

	    FOR_ALL_TAB_WINDOWS(tp, win)
		if (win->w_buffer == curbuf)
		    foldUpdateAll(win);
	}


	
	DO_AUTOCHDIR;

	
	orig_pos = curwin->w_cursor;
	topline = curwin->w_topline;
	if (!oldbuf)			    
	{

	    
	    
	    if (WIN_IS_POPUP(curwin))
		curbuf->b_flags |= BF_NO_SEA;

	    swap_exists_action = SEA_DIALOG;
	    curbuf->b_flags |= BF_CHECK_RO; 

	    
	    if (flags & ECMD_NOWINENTER)
		readfile_flags |= READ_NOWINENTER;

	    if (should_abort(open_buffer(FALSE, eap, readfile_flags)))
		retval = FAIL;

	    (void)open_buffer(FALSE, eap, readfile_flags);



	    curbuf->b_flags &= ~BF_NO_SEA;

	    if (swap_exists_action == SEA_QUIT)
		retval = FAIL;
	    handle_swap_exists(&old_curbuf);
	}
	else {
	    
	    
	    
	    do_modelines(OPT_WINONLY);

	    apply_autocmds_retval(EVENT_BUFENTER, NULL, NULL, FALSE, curbuf, &retval);
	    if ((flags & ECMD_NOWINENTER) == 0)
		apply_autocmds_retval(EVENT_BUFWINENTER, NULL, NULL, FALSE, curbuf, &retval);
	}
	check_arg_idx(curwin);

	
	
	
	if (!EQUAL_POS(curwin->w_cursor, orig_pos))
	{
	    char_u *text = ml_get_curline();

	    if (curwin->w_cursor.lnum != orig_pos.lnum || curwin->w_cursor.col != (int)(skipwhite(text) - text))
	    {
		newlnum = curwin->w_cursor.lnum;
		newcol = curwin->w_cursor.col;
	    }
	}
	if (curwin->w_topline == topline)
	    topline = 0;

	
	changed_line_abv_curs();

	maketitle();

	if (WIN_IS_POPUP(curwin) && curwin->w_p_pvw && retval != FAIL)
	    popup_set_title(curwin);

    }


    
    
    
    if (curwin->w_p_diff)
    {
	diff_buf_add(curbuf);
	diff_invalidate(curbuf);
    }



    
    
    if (did_get_winopts && curwin->w_p_spell && *curwin->w_s->b_p_spl != NUL)
	(void)did_set_spelllang(curwin);


    if (command == NULL)
    {
	if (newcol >= 0)	
	{
	    curwin->w_cursor.lnum = newlnum;
	    curwin->w_cursor.col = newcol;
	    check_cursor();
	}
	else if (newlnum > 0)	
	{
	    curwin->w_cursor.lnum = newlnum;
	    check_cursor_lnum();
	    if (solcol >= 0 && !p_sol)
	    {
		
		curwin->w_cursor.col = solcol;
		check_cursor_col();
		curwin->w_cursor.coladd = 0;
		curwin->w_set_curswant = TRUE;
	    }
	    else beginline(BL_SOL | BL_FIX);
	}
	else			 {
	    if (exmode_active)
		curwin->w_cursor.lnum = curbuf->b_ml.ml_line_count;
	    beginline(BL_WHITE | BL_FIX);
	}
    }

    
    check_lnums(FALSE);

    
    if (oldbuf && !auto_buf)
    {
	int	msg_scroll_save = msg_scroll;

	
	
	if (shortmess(SHM_OVERALL) && !exiting && p_verbose == 0)
	    msg_scroll = FALSE;
	if (!msg_scroll)	
	    check_for_delay(FALSE);
	msg_start();
	msg_scroll = msg_scroll_save;
	msg_scrolled_ign = TRUE;

	if (!shortmess(SHM_FILEINFO))
	    fileinfo(FALSE, TRUE, FALSE);

	msg_scrolled_ign = FALSE;
    }


    curbuf->b_last_used = vim_time();


    if (command != NULL)
	do_cmdline(command, NULL, NULL, DOCMD_VERBOSE|DOCMD_RANGEOK);


    if (curbuf->b_kmap_state & KEYMAP_INIT)
	(void)keymap_init();


    --RedrawingDisabled;
    did_inc_redrawing_disabled = FALSE;
    if (!skip_redraw)
    {
	n = *so_ptr;
	if (topline == 0 && command == NULL)
	    *so_ptr = 9999;		
	update_topline();
	curwin->w_scbind_pos = curwin->w_topline;
	*so_ptr = n;
	redraw_curbuf_later(NOT_VALID);	
    }

    if (p_im && (State & MODE_INSERT) == 0)
	need_start_insertmode = TRUE;


    
    
    
    if (p_acd && curbuf->b_ffname != NULL)
    {
	char_u	curdir[MAXPATHL];
	char_u	filedir[MAXPATHL];

	vim_strncpy(filedir, curbuf->b_ffname, MAXPATHL - 1);
	*gettail_sep(filedir) = NUL;
	if (mch_dirname(curdir, MAXPATHL) != FAIL && vim_fnamecmp(curdir, filedir) != 0)
	    do_autochdir();
    }



    if (curbuf->b_ffname != NULL)
    {

	if ((flags & ECMD_SET_HELP) != ECMD_SET_HELP)
	    netbeans_file_opened(curbuf);

    }


theend:
    if (did_inc_redrawing_disabled)
	--RedrawingDisabled;

    if (did_set_swapcommand)
	set_vim_var_string(VV_SWAPCOMMAND, NULL, -1);


    vim_free(browse_file);

    vim_free(free_fname);
    return retval;
}

    static void delbuf_msg(char_u *name)
{
    semsg(_(e_autocommands_unexpectedly_deleted_new_buffer_str), name == NULL ? (char_u *)"" : name);
    vim_free(name);
    au_new_curbuf.br_buf = NULL;
    au_new_curbuf.br_buf_free_count = 0;
}

static int append_indent = 0;	    


    void ex_append(exarg_T *eap)
{
    char_u	*theline;
    int		did_undo = FALSE;
    linenr_T	lnum = eap->line2;
    int		indent = 0;
    char_u	*p;
    int		vcol;
    int		empty = (curbuf->b_ml.ml_flags & ML_EMPTY);


    if (not_in_vim9(eap) == FAIL)
	return;

    
    if (eap->forceit)
	curbuf->b_p_ai = !curbuf->b_p_ai;

    
    if (eap->cmdidx != CMD_change && curbuf->b_p_ai && lnum > 0)
	append_indent = get_indent_lnum(lnum);

    if (eap->cmdidx != CMD_append)
	--lnum;

    
    if (empty && lnum == 1)
	lnum = 0;

    State = MODE_INSERT;		    
    if (curbuf->b_p_iminsert == B_IMODE_LMAP)
	State |= MODE_LANGMAP;

    for (;;)
    {
	msg_scroll = TRUE;
	need_wait_return = FALSE;
	if (curbuf->b_p_ai)
	{
	    if (append_indent >= 0)
	    {
		indent = append_indent;
		append_indent = -1;
	    }
	    else if (lnum > 0)
		indent = get_indent_lnum(lnum);
	}
	ex_keep_indent = FALSE;
	if (eap->getline == NULL)
	{
	    
	    
	    if (eap->nextcmd == NULL || *eap->nextcmd == NUL)
		break;
	    p = vim_strchr(eap->nextcmd, NL);
	    if (p == NULL)
		p = eap->nextcmd + STRLEN(eap->nextcmd);
	    theline = vim_strnsave(eap->nextcmd, p - eap->nextcmd);
	    if (*p != NUL)
		++p;
	    eap->nextcmd = p;
	}
	else {
	    int save_State = State;

	    
	    
	    State = MODE_CMDLINE;
	    theline = eap->getline(  eap->cstack->cs_looplevel > 0 ? -1 :


		    NUL, eap->cookie, indent, TRUE);
	    State = save_State;
	}
	lines_left = Rows - 1;
	if (theline == NULL)
	    break;

	
	if (ex_keep_indent)
	    append_indent = indent;

	
	vcol = 0;
	for (p = theline; indent > vcol; ++p)
	{
	    if (*p == ' ')
		++vcol;
	    else if (*p == TAB)
		vcol += 8 - vcol % 8;
	    else break;
	}
	if ((p[0] == '.' && p[1] == NUL)
		|| (!did_undo && u_save(lnum, lnum + 1 + (empty ? 1 : 0))
								     == FAIL))
	{
	    vim_free(theline);
	    break;
	}

	
	if (p[0] == NUL)
	    theline[0] = NUL;

	did_undo = TRUE;
	ml_append(lnum, theline, (colnr_T)0, FALSE);
	if (empty)
	    
	    appended_lines(lnum, 1L);
	else appended_lines_mark(lnum, 1L);

	vim_free(theline);
	++lnum;

	if (empty)
	{
	    ml_delete(2L);
	    empty = FALSE;
	}
    }
    State = MODE_NORMAL;

    if (eap->forceit)
	curbuf->b_p_ai = !curbuf->b_p_ai;

    
    
    
    
    if ((cmdmod.cmod_flags & CMOD_LOCKMARKS) == 0)
    {
	curbuf->b_op_start.lnum = (eap->line2 < curbuf->b_ml.ml_line_count) ? eap->line2 + 1 : curbuf->b_ml.ml_line_count;
	if (eap->cmdidx != CMD_append)
	    --curbuf->b_op_start.lnum;
	curbuf->b_op_end.lnum = (eap->line2 < lnum)
					      ? lnum : curbuf->b_op_start.lnum;
	curbuf->b_op_start.col = curbuf->b_op_end.col = 0;
    }
    curwin->w_cursor.lnum = lnum;
    check_cursor_lnum();
    beginline(BL_SOL | BL_FIX);

    need_wait_return = FALSE;	
    ex_no_reprint = TRUE;
}


    void ex_change(exarg_T *eap)
{
    linenr_T	lnum;


    if (not_in_vim9(eap) == FAIL)
	return;

    if (eap->line2 >= eap->line1 && u_save(eap->line1 - 1, eap->line2 + 1) == FAIL)
	return;

    
    if (eap->forceit ? !curbuf->b_p_ai : curbuf->b_p_ai)
	append_indent = get_indent_lnum(eap->line1);

    for (lnum = eap->line2; lnum >= eap->line1; --lnum)
    {
	if (curbuf->b_ml.ml_flags & ML_EMPTY)	    
	    break;
	ml_delete(eap->line1);
    }

    
    check_cursor_lnum();
    deleted_lines_mark(eap->line1, (long)(eap->line2 - lnum));

    
    eap->line2 = eap->line1;
    ex_append(eap);
}

    void ex_z(exarg_T *eap)
{
    char_u	*x;
    long	bigness;
    char_u	*kind;
    int		minus = 0;
    linenr_T	start, end, curs, i;
    int		j;
    linenr_T	lnum = eap->line2;

    
    
    if (eap->forceit)
	bigness = Rows - 1;
    else if (!ONE_WINDOW)
	bigness = curwin->w_height - 3;
    else bigness = curwin->w_p_scr * 2;
    if (bigness < 1)
	bigness = 1;

    x = eap->arg;
    kind = x;
    if (*kind == '-' || *kind == '+' || *kind == '=' || *kind == '^' || *kind == '.')
	++x;
    while (*x == '-' || *x == '+')
	++x;

    if (*x != 0)
    {
	if (!VIM_ISDIGIT(*x))
	{
	    emsg(_(e_non_numeric_argument_to_z));
	    return;
	}
	else {
	    bigness = atol((char *)x);

	    
	    if (bigness > 2 * curbuf->b_ml.ml_line_count || bigness < 0)
		bigness = 2 * curbuf->b_ml.ml_line_count;

	    p_window = bigness;
	    if (*kind == '=')
		bigness += 2;
	}
    }

    
    if (*kind == '-' || *kind == '+')
	for (x = kind + 1; *x == *kind; ++x)
	    ;

    switch (*kind)
    {
	case '-':
	    start = lnum - bigness * (linenr_T)(x - kind) + 1;
	    end = start + bigness - 1;
	    curs = end;
	    break;

	case '=':
	    start = lnum - (bigness + 1) / 2 + 1;
	    end = lnum + (bigness + 1) / 2 - 1;
	    curs = lnum;
	    minus = 1;
	    break;

	case '^':
	    start = lnum - bigness * 2;
	    end = lnum - bigness;
	    curs = lnum - bigness;
	    break;

	case '.':
	    start = lnum - (bigness + 1) / 2 + 1;
	    end = lnum + (bigness + 1) / 2 - 1;
	    curs = end;
	    break;

	default:  
	    start = lnum;
	    if (*kind == '+')
		start += bigness * (linenr_T)(x - kind - 1) + 1;
	    else if (eap->addr_count == 0)
		++start;
	    end = start + bigness - 1;
	    curs = end;
	    break;
    }

    if (start < 1)
	start = 1;

    if (end > curbuf->b_ml.ml_line_count)
	end = curbuf->b_ml.ml_line_count;

    if (curs > curbuf->b_ml.ml_line_count)
	curs = curbuf->b_ml.ml_line_count;
    else if (curs < 1)
	curs = 1;

    for (i = start; i <= end; i++)
    {
	if (minus && i == lnum)
	{
	    msg_putchar('\n');

	    for (j = 1; j < Columns; j++)
		msg_putchar('-');
	}

	print_line(i, eap->flags & EXFLAG_NR, eap->flags & EXFLAG_LIST);

	if (minus && i == lnum)
	{
	    msg_putchar('\n');

	    for (j = 1; j < Columns; j++)
		msg_putchar('-');
	}
    }

    if (curwin->w_cursor.lnum != curs)
    {
	curwin->w_cursor.lnum = curs;
	curwin->w_cursor.col = 0;
    }
    ex_no_reprint = TRUE;
}


    int check_restricted(void)
{
    if (restricted)
    {
	emsg(_(e_shell_commands_and_some_functionality_not_allowed_in_rvim));
	return TRUE;
    }
    return FALSE;
}


    int check_secure(void)
{
    if (secure)
    {
	secure = 2;
	emsg(_(e_command_not_allowed_from_vimrc_in_current_dir_or_tag_search));
	return TRUE;
    }

    
    if (sandbox != 0)
    {
	emsg(_(e_not_allowed_in_sandbox));
	return TRUE;
    }

    return FALSE;
}

static char_u	*old_sub = NULL;	
static int	global_need_beginline;	


typedef struct {
    int	do_all;		
    int	do_ask;		
    int	do_count;	
    int	do_error;	
    int	do_print;	
    int	do_list;	
    int	do_number;	
    int	do_ic;		
} subflags_T;


    char_u * skip_substitute(char_u *start, int delimiter)
{
    char_u *p = start;

    while (p[0])
    {
	if (p[0] == delimiter)		
	{
	    *p++ = NUL;			
	    break;
	}
	if (p[0] == '\\' && p[1] != 0)	
	    ++p;
	MB_PTR_ADV(p);
    }
    return p;
}

    static int check_regexp_delim(int c)
{
    if (isalpha(c))
    {
	emsg(_(e_regular_expressions_cant_be_delimited_by_letters));
	return FAIL;
    }
    return OK;
}


    void ex_substitute(exarg_T *eap)
{
    linenr_T	lnum;
    long	i = 0;
    regmmatch_T regmatch;
    static subflags_T subflags = {FALSE, FALSE, FALSE, TRUE, FALSE, FALSE, FALSE, 0};

    subflags_T	subflags_save;

    int		save_do_all;		
    int		save_do_ask;		
    char_u	*pat = NULL, *sub = NULL;	
    char_u	*sub_copy = NULL;
    int		delimiter;
    int		sublen;
    int		got_quit = FALSE;
    int		got_match = FALSE;
    int		temp;
    int		which_pat;
    char_u	*cmd;
    int		save_State;
    linenr_T	first_line = 0;		
    linenr_T	last_line= 0;		
					
    linenr_T	old_line_count = curbuf->b_ml.ml_line_count;
    linenr_T	line2;
    long	nmatch;			
    char_u	*sub_firstline;		
    int		endcolumn = FALSE;	
    pos_T	old_cursor = curwin->w_cursor;
    int		start_nsubs;

    int		save_ma = 0;
    int		save_sandbox = 0;


    cmd = eap->arg;
    if (!global_busy)
    {
	sub_nsubs = 0;
	sub_nlines = 0;
    }
    start_nsubs = sub_nsubs;

    if (eap->cmdidx == CMD_tilde)
	which_pat = RE_LAST;	
    else which_pat = RE_SUBST;

				
    if (eap->cmd[0] == 's' && *cmd != NUL && !VIM_ISWHITE(*cmd)
		&& vim_strchr((char_u *)"0123456789cegriIp|\"", *cmd) == NULL)
    {
				
	if (check_regexp_delim(*cmd) == FAIL)
	    return;

	if (in_vim9script() && check_global_and_subst(eap->cmd, eap->arg)
								      == FAIL)
	    return;


	
	if (*cmd == '\\')
	{
	    if (in_vim9script())
	    {
		emsg(_(e_cannot_use_s_backslash_in_vim9_script));
		return;
	    }
	    ++cmd;
	    if (vim_strchr((char_u *)"/?&", *cmd) == NULL)
	    {
		emsg(_(e_backslash_should_be_followed_by));
		return;
	    }
	    if (*cmd != '&')
		which_pat = RE_SEARCH;	    
	    pat = (char_u *)"";		    
	    delimiter = *cmd++;		    
	}
	else		 {
	    which_pat = RE_LAST;	    
	    delimiter = *cmd++;		    
	    pat = cmd;			    
	    cmd = skip_regexp_ex(cmd, delimiter, magic_isset(), &eap->arg, NULL, NULL);
	    if (cmd[0] == delimiter)	    
		*cmd++ = NUL;		    
	}

	
	sub = cmd;	    
	cmd = skip_substitute(cmd, delimiter);

	if (!eap->skip)
	{
	    
	    if (STRCMP(sub, "%") == 0 && vim_strchr(p_cpo, CPO_SUBPERCENT) != NULL)
	    {
		if (old_sub == NULL)	
		{
		    emsg(_(e_no_previous_substitute_regular_expression));
		    return;
		}
		sub = old_sub;
	    }
	    else {
		vim_free(old_sub);
		old_sub = vim_strsave(sub);
	    }
	}
    }
    else if (!eap->skip)	
    {
	if (old_sub == NULL)	
	{
	    emsg(_(e_no_previous_substitute_regular_expression));
	    return;
	}
	pat = NULL;		
	sub = old_sub;

	
	
	endcolumn = (curwin->w_curswant == MAXCOL);
    }

    
    
    
    
    if (pat != NULL && STRCMP(pat, "\\n") == 0 && *sub == NUL && (*cmd == NUL || (cmd[1] == NUL && (*cmd == 'g' || *cmd == 'l' || *cmd == 'p' || *cmd == '#'))))


    {
	linenr_T    joined_lines_count;

	if (eap->skip)
	    return;
	curwin->w_cursor.lnum = eap->line1;
	if (*cmd == 'l')
	    eap->flags = EXFLAG_LIST;
	else if (*cmd == '#')
	    eap->flags = EXFLAG_NR;
	else if (*cmd == 'p')
	    eap->flags = EXFLAG_PRINT;

	
	
	joined_lines_count = eap->line2 - eap->line1 + 1;
	if (eap->line2 < curbuf->b_ml.ml_line_count)
	    ++joined_lines_count;
	if (joined_lines_count > 1)
	{
	    (void)do_join(joined_lines_count, FALSE, TRUE, FALSE, TRUE);
	    sub_nsubs = joined_lines_count - 1;
	    sub_nlines = 1;
	    (void)do_sub_msg(FALSE);
	    ex_may_print(eap);
	}

	if ((cmdmod.cmod_flags & CMOD_KEEPPATTERNS) == 0)
	    save_re_pat(RE_SUBST, pat, magic_isset());
	
	add_to_history(HIST_SEARCH, pat, TRUE, NUL);

	return;
    }

    
    if (*cmd == '&')
	++cmd;
    else {

	if (in_vim9script())
	{
	    
	    subflags.do_all = FALSE;
	    subflags.do_ask = FALSE;
	}
	else  if (!p_ed)

	{
	    if (p_gd)		
		subflags.do_all = TRUE;
	    else subflags.do_all = FALSE;
	    subflags.do_ask = FALSE;
	}
	subflags.do_error = TRUE;
	subflags.do_print = FALSE;
	subflags.do_list = FALSE;
	subflags.do_count = FALSE;
	subflags.do_number = FALSE;
	subflags.do_ic = 0;
    }
    while (*cmd)
    {
	
	if (*cmd == 'g')
	    subflags.do_all = !subflags.do_all;
	else if (*cmd == 'c')
	    subflags.do_ask = !subflags.do_ask;
	else if (*cmd == 'n')
	    subflags.do_count = TRUE;
	else if (*cmd == 'e')
	    subflags.do_error = !subflags.do_error;
	else if (*cmd == 'r')	    
	    which_pat = RE_LAST;
	else if (*cmd == 'p')
	    subflags.do_print = TRUE;
	else if (*cmd == '#')
	{
	    subflags.do_print = TRUE;
	    subflags.do_number = TRUE;
	}
	else if (*cmd == 'l')
	{
	    subflags.do_print = TRUE;
	    subflags.do_list = TRUE;
	}
	else if (*cmd == 'i')	    
	    subflags.do_ic = 'i';
	else if (*cmd == 'I')	    
	    subflags.do_ic = 'I';
	else break;
	++cmd;
    }
    if (subflags.do_count)
	subflags.do_ask = FALSE;

    save_do_all = subflags.do_all;
    save_do_ask = subflags.do_ask;

    
    cmd = skipwhite(cmd);
    if (VIM_ISDIGIT(*cmd))
    {
	i = getdigits(&cmd);
	if (i <= 0 && !eap->skip && subflags.do_error)
	{
	    emsg(_(e_positive_count_required));
	    return;
	}
	eap->line1 = eap->line2;
	eap->line2 += i - 1;
	if (eap->line2 > curbuf->b_ml.ml_line_count)
	    eap->line2 = curbuf->b_ml.ml_line_count;
    }

    
    cmd = skipwhite(cmd);
    if (*cmd && *cmd != '"')	    
    {
	set_nextcmd(eap, cmd);
	if (eap->nextcmd == NULL)
	{
	    semsg(_(e_trailing_characters_str), cmd);
	    return;
	}
    }

    if (eap->skip)	    
	return;

    if (!subflags.do_count && !curbuf->b_p_ma)
    {
	
	emsg(_(e_cannot_make_changes_modifiable_is_off));
	return;
    }

    if (search_regcomp(pat, RE_SUBST, which_pat, SEARCH_HIS, &regmatch) == FAIL)
    {
	if (subflags.do_error)
	    emsg(_(e_invalid_command));
	return;
    }

    
    if (subflags.do_ic == 'i')
	regmatch.rmm_ic = TRUE;
    else if (subflags.do_ic == 'I')
	regmatch.rmm_ic = FALSE;

    sub_firstline = NULL;

    
    if (sub[0] == '\\' && sub[1] == '=')
    {
	sub = vim_strsave(sub);
	if (sub == NULL)
	    return;
	sub_copy = sub;
    }
    else sub = regtilde(sub, magic_isset());

    
    line2 = eap->line2;
    for (lnum = eap->line1; lnum <= line2 && !(got_quit  || aborting()


		); ++lnum)
    {
	nmatch = vim_regexec_multi(&regmatch, curwin, curbuf, lnum, (colnr_T)0, NULL);
	if (nmatch)
	{
	    colnr_T	copycol;
	    colnr_T	matchcol;
	    colnr_T	prev_matchcol = MAXCOL;
	    char_u	*new_end, *new_start = NULL;
	    unsigned	new_start_len = 0;
	    char_u	*p1;
	    int		did_sub = FALSE;
	    int		lastone;
	    int		len, copy_len, needed_len;
	    long	nmatch_tl = 0;	
	    int		do_again;	
	    int		skip_match = FALSE;
	    linenr_T	sub_firstlnum;	

	    int		apc_flags = APC_SAVE_FOR_UNDO | APC_SUBSTITUTE;
	    colnr_T	total_added =  0;


	    
	    sub_firstlnum = lnum;
	    copycol = 0;
	    matchcol = 0;

	    
	    if (!got_match)
	    {
		setpcmark();
		got_match = TRUE;
	    }

	    
	    for (;;)
	    {
		
		
		
		if (regmatch.startpos[0].lnum > 0)
		{
		    lnum += regmatch.startpos[0].lnum;
		    sub_firstlnum += regmatch.startpos[0].lnum;
		    nmatch -= regmatch.startpos[0].lnum;
		    VIM_CLEAR(sub_firstline);
		}

		
		
		if (lnum > curbuf->b_ml.ml_line_count)
		    break;

		if (sub_firstline == NULL)
		{
		    sub_firstline = vim_strsave(ml_get(sub_firstlnum));
		    if (sub_firstline == NULL)
		    {
			vim_free(new_start);
			goto outofmem;
		    }
		}

		
		
		curwin->w_cursor.lnum = lnum;
		do_again = FALSE;

		
		if (matchcol == prev_matchcol && regmatch.endpos[0].lnum == 0 && matchcol == regmatch.endpos[0].col)

		{
		    if (sub_firstline[matchcol] == NUL)
			
			
			skip_match = TRUE;
		    else {
			 
			if (has_mbyte)
			    matchcol += mb_ptr2len(sub_firstline + matchcol);
			else ++matchcol;
		    }
		    goto skip;
		}

		
		
		matchcol = regmatch.endpos[0].col;
		prev_matchcol = matchcol;

		
		if (subflags.do_count)
		{
		    
		    
		    
		    
		    if (nmatch > 1)
		    {
			matchcol = (colnr_T)STRLEN(sub_firstline);
			nmatch = 1;
			skip_match = TRUE;
		    }
		    sub_nsubs++;
		    did_sub = TRUE;

		    
		    
		    if (!(sub[0] == '\\' && sub[1] == '='))

			goto skip;
		}

		if (subflags.do_ask)
		{
		    int typed = 0;

		    
		    
		    save_State = State;
		    State = MODE_CONFIRM;
		    setmouse();		
		    curwin->w_cursor.col = regmatch.startpos[0].col;
		    if (curwin->w_p_crb)
			do_check_cursorbind();

		    
		    
		    if (vim_strchr(p_cpo, CPO_UNDO) != NULL)
			++no_u_sync;

		    
		    while (subflags.do_ask)
		    {
			if (exmode_active)
			{
			    char_u	*resp;
			    colnr_T	sc, ec;

			    print_line_no_prefix(lnum, subflags.do_number, subflags.do_list);

			    getvcol(curwin, &curwin->w_cursor, &sc, NULL, NULL);
			    curwin->w_cursor.col = regmatch.endpos[0].col - 1;
			    if (curwin->w_cursor.col < 0)
				curwin->w_cursor.col = 0;
			    getvcol(curwin, &curwin->w_cursor, NULL, NULL, &ec);
			    curwin->w_cursor.col = regmatch.startpos[0].col;
			    if (subflags.do_number || curwin->w_p_nu)
			    {
				int numw = number_width(curwin) + 1;
				sc += numw;
				ec += numw;
			    }
			    msg_start();
			    for (i = 0; i < (long)sc; ++i)
				msg_putchar(' ');
			    for ( ; i <= (long)ec; ++i)
				msg_putchar('^');

			    resp = getexmodeline('?', NULL, 0, TRUE);
			    if (resp != NULL)
			    {
				typed = *resp;
				vim_free(resp);
				
				
				
				if (ex_normal_busy && typed == NUL)
				    typed = 'q';
			    }
			}
			else {
			    char_u *orig_line = NULL;
			    int    len_change = 0;
			    int	   save_p_lz = p_lz;

			    int save_p_fen = curwin->w_p_fen;

			    curwin->w_p_fen = FALSE;

			    
			    
			    temp = RedrawingDisabled;
			    RedrawingDisabled = 0;

			    
			    p_lz = FALSE;

			    if (new_start != NULL)
			    {
				
				
				
				
				
				orig_line = vim_strsave(ml_get(lnum));
				if (orig_line != NULL)
				{
				    char_u *new_line = concat_str(new_start, sub_firstline + copycol);

				    if (new_line == NULL)
					VIM_CLEAR(orig_line);
				    else {
					
					
					
					
					
					len_change = (int)STRLEN(new_line)
						     - (int)STRLEN(orig_line);
					curwin->w_cursor.col += len_change;
					ml_replace(lnum, new_line, FALSE);
				    }
				}
			    }

			    search_match_lines = regmatch.endpos[0].lnum - regmatch.startpos[0].lnum;
			    search_match_endcol = regmatch.endpos[0].col + len_change;
			    highlight_match = TRUE;

			    update_topline();
			    validate_cursor();
			    update_screen(SOME_VALID);
			    highlight_match = FALSE;
			    redraw_later(SOME_VALID);


			    curwin->w_p_fen = save_p_fen;

			    if (msg_row == Rows - 1)
				msg_didout = FALSE;	
			    msg_starthere();
			    i = msg_scroll;
			    msg_scroll = 0;		
							
			    msg_no_more = TRUE;
			    
			    
			    smsg_attr(HL_ATTR(HLF_R), _("replace with %s (y/n/a/q/l/^E/^Y)?"), sub);
			    msg_no_more = FALSE;
			    msg_scroll = i;
			    showruler(TRUE);
			    windgoto(msg_row, msg_col);
			    RedrawingDisabled = temp;


			    dont_scroll = FALSE; 

			    ++no_mapping;	
			    ++allow_keys;	
			    typed = plain_vgetc();
			    --allow_keys;
			    --no_mapping;

			    
			    msg_didout = FALSE;	
			    msg_col = 0;
			    gotocmdline(TRUE);
			    p_lz = save_p_lz;

			    
			    if (orig_line != NULL)
				ml_replace(lnum, orig_line, FALSE);
			}

			need_wait_return = FALSE; 
			if (typed == 'q' || typed == ESC || typed == Ctrl_C  || typed == intr_char  )



			{
			    got_quit = TRUE;
			    break;
			}
			if (typed == 'n')
			    break;
			if (typed == 'y')
			    break;
			if (typed == 'l')
			{
			    
			    subflags.do_all = FALSE;
			    line2 = lnum;
			    break;
			}
			if (typed == 'a')
			{
			    subflags.do_ask = FALSE;
			    break;
			}
			if (typed == Ctrl_E)
			    scrollup_clamp();
			else if (typed == Ctrl_Y)
			    scrolldown_clamp();
		    }
		    State = save_State;
		    setmouse();
		    if (vim_strchr(p_cpo, CPO_UNDO) != NULL)
			--no_u_sync;

		    if (typed == 'n')
		    {
			
			
			
			
			
			if (nmatch > 1)
			{
			    matchcol = (colnr_T)STRLEN(sub_firstline);
			    skip_match = TRUE;
			}
			goto skip;
		    }
		    if (got_quit)
			goto skip;
		}

		
		
		curwin->w_cursor.col = regmatch.startpos[0].col;

		

		save_ma = curbuf->b_p_ma;
		save_sandbox = sandbox;
		if (subflags.do_count)
		{
		    
		    curbuf->b_p_ma = FALSE;
		    sandbox++;
		}
		
		
		subflags_save = subflags;

		
		++textlock;

		
		
		sublen = vim_regsub_multi(&regmatch, sub_firstlnum - regmatch.startpos[0].lnum, sub, sub_firstline, 0, REGSUB_BACKSLASH | (magic_isset() ? REGSUB_MAGIC : 0));




		--textlock;

		
		
		
		subflags = subflags_save;
		if (sublen == 0 || aborting() || subflags.do_count)
		{
		    curbuf->b_p_ma = save_ma;
		    sandbox = save_sandbox;
		    goto skip;
		}


		
		
		if (nmatch > curbuf->b_ml.ml_line_count - sub_firstlnum + 1)
		{
		    nmatch = curbuf->b_ml.ml_line_count - sub_firstlnum + 1;
		    skip_match = TRUE;
		}

		
		
		
		
		
		
		
		if (nmatch == 1)
		{
		    p1 = sub_firstline;

		    if (curbuf->b_has_textprop)
		    {
			int bytes_added = sublen - 1 - (regmatch.endpos[0].col - regmatch.startpos[0].col);

			
			
			if (adjust_prop_columns(lnum, total_added + regmatch.startpos[0].col, bytes_added, apc_flags))

			    apc_flags &= ~APC_SAVE_FOR_UNDO;
			
			
			total_added += bytes_added;
		    }

		}
		else {
		    p1 = ml_get(sub_firstlnum + nmatch - 1);
		    nmatch_tl += nmatch - 1;
		}
		copy_len = regmatch.startpos[0].col - copycol;
		needed_len = copy_len + ((unsigned)STRLEN(p1)
				       - regmatch.endpos[0].col) + sublen + 1;
		if (new_start == NULL)
		{
		    
		    new_start_len = needed_len + 50;
		    if ((new_start = alloc(new_start_len)) == NULL)
			goto outofmem;
		    *new_start = NUL;
		    new_end = new_start;
		}
		else {
		    
		    len = (unsigned)STRLEN(new_start);
		    needed_len += len;
		    if (needed_len > (int)new_start_len)
		    {
			new_start_len = needed_len + 50;
			if ((p1 = alloc(new_start_len)) == NULL)
			{
			    vim_free(new_start);
			    goto outofmem;
			}
			mch_memmove(p1, new_start, (size_t)(len + 1));
			vim_free(new_start);
			new_start = p1;
		    }
		    new_end = new_start + len;
		}

		
		mch_memmove(new_end, sub_firstline + copycol, (size_t)copy_len);
		new_end += copy_len;


		++textlock;

		(void)vim_regsub_multi(&regmatch, sub_firstlnum - regmatch.startpos[0].lnum, sub, new_end, sublen, REGSUB_COPY | REGSUB_BACKSLASH | (magic_isset() ? REGSUB_MAGIC : 0));




		--textlock;

		sub_nsubs++;
		did_sub = TRUE;

		
		
		curwin->w_cursor.col = 0;

		
		
		if (nmatch > 1)
		{
		    sub_firstlnum += nmatch - 1;
		    vim_free(sub_firstline);
		    sub_firstline = vim_strsave(ml_get(sub_firstlnum));
		    
		    if (sub_firstlnum <= line2)
			do_again = TRUE;
		    else subflags.do_all = FALSE;
		}

		
		copycol = regmatch.endpos[0].col;

		if (skip_match)
		{
		    
		    
		    vim_free(sub_firstline);
		    sub_firstline = vim_strsave((char_u *)"");
		    copycol = 0;
		}

		
		for (p1 = new_end; *p1; ++p1)
		{
		    if (p1[0] == '\\' && p1[1] != NUL)  
		    {
			STRMOVE(p1, p1 + 1);

			if (curbuf->b_has_textprop)
			{
			    
			    
			    if (adjust_prop_columns(lnum, (colnr_T)(p1 - new_start), -1, apc_flags))

				apc_flags &= ~APC_SAVE_FOR_UNDO;
			}

		    }
		    else if (*p1 == CAR)
		    {
			if (u_inssub(lnum) == OK)   
			{
			    colnr_T	plen = (colnr_T)(p1 - new_start + 1);

			    *p1 = NUL;		    
			    ml_append(lnum - 1, new_start, plen, FALSE);
			    mark_adjust(lnum + 1, (linenr_T)MAXLNUM, 1L, 0L);
			    if (subflags.do_ask)
				appended_lines(lnum - 1, 1L);
			    else {
				if (first_line == 0)
				    first_line = lnum;
				last_line = lnum + 1;
			    }

			    adjust_props_for_split(lnum + 1, lnum, plen, 1);

			    
			    ++sub_firstlnum;
			    ++lnum;
			    ++line2;
			    
			    ++curwin->w_cursor.lnum;
			    
			    STRMOVE(new_start, p1 + 1);
			    p1 = new_start - 1;
			}
		    }
		    else if (has_mbyte)
			p1 += (*mb_ptr2len)(p1) - 1;
		}

		
skip:
		
		
		
		
		
		lastone = (skip_match || got_int || got_quit || lnum > line2 || !(subflags.do_all || do_again)



			|| (sub_firstline[matchcol] == NUL && nmatch <= 1 && !re_multiline(regmatch.regprog)));
		nmatch = -1;

		
		if (lastone || nmatch_tl > 0 || (nmatch = vim_regexec_multi(&regmatch, curwin, curbuf, sub_firstlnum, matchcol, NULL)) == 0 || regmatch.startpos[0].lnum > 0)




		{
		    if (new_start != NULL)
		    {
			
			STRCAT(new_start, sub_firstline + copycol);
			matchcol = (colnr_T)STRLEN(sub_firstline) - matchcol;
			prev_matchcol = (colnr_T)STRLEN(sub_firstline)
							      - prev_matchcol;

			if (u_savesub(lnum) != OK)
			    break;
			ml_replace(lnum, new_start, TRUE);

			if (nmatch_tl > 0)
			{
			    
			    ++lnum;
			    if (u_savedel(lnum, nmatch_tl) != OK)
				break;
			    for (i = 0; i < nmatch_tl; ++i)
				ml_delete(lnum);
			    mark_adjust(lnum, lnum + nmatch_tl - 1, (long)MAXLNUM, -nmatch_tl);
			    if (subflags.do_ask)
				deleted_lines(lnum, nmatch_tl);
			    --lnum;
			    line2 -= nmatch_tl; 
			    nmatch_tl = 0;
			}

			
			
			if (subflags.do_ask)
			    changed_bytes(lnum, 0);
			else {
			    if (first_line == 0)
				first_line = lnum;
			    last_line = lnum + 1;
			}

			sub_firstlnum = lnum;
			vim_free(sub_firstline);    
			sub_firstline = new_start;
			new_start = NULL;
			matchcol = (colnr_T)STRLEN(sub_firstline) - matchcol;
			prev_matchcol = (colnr_T)STRLEN(sub_firstline)
							      - prev_matchcol;
			copycol = 0;
		    }
		    if (nmatch == -1 && !lastone)
			nmatch = vim_regexec_multi(&regmatch, curwin, curbuf, sub_firstlnum, matchcol, NULL);

		    
		    if (nmatch <= 0)
		    {
			
			
			
			if (nmatch == -1)
			    lnum -= regmatch.startpos[0].lnum;
			break;
		    }
		}

		line_breakcheck();
	    }

	    if (did_sub)
		++sub_nlines;
	    vim_free(new_start);	
	    VIM_CLEAR(sub_firstline);	
	}

	line_breakcheck();
    }

    if (first_line != 0)
    {
	
	
	
	i = curbuf->b_ml.ml_line_count - old_line_count;
	changed_lines(first_line, 0, last_line - i, i);
    }

outofmem:
    vim_free(sub_firstline); 

    
    if (subflags.do_count)
	curwin->w_cursor = old_cursor;

    if (sub_nsubs > start_nsubs)
    {
	if ((cmdmod.cmod_flags & CMOD_LOCKMARKS) == 0)
	{
	    
	    curbuf->b_op_start.lnum = eap->line1;
	    curbuf->b_op_end.lnum = line2;
	    curbuf->b_op_start.col = curbuf->b_op_end.col = 0;
	}

	if (!global_busy)
	{
	    
	    if (!subflags.do_ask)
	    {
		if (endcolumn)
		    coladvance((colnr_T)MAXCOL);
		else beginline(BL_WHITE | BL_FIX);
	    }
	    if (!do_sub_msg(subflags.do_count) && subflags.do_ask)
		msg("");
	}
	else global_need_beginline = TRUE;
	if (subflags.do_print)
	    print_line(curwin->w_cursor.lnum, subflags.do_number, subflags.do_list);
    }
    else if (!global_busy)
    {
	if (got_int)		
	    emsg(_(e_interrupted));
	else if (got_match)	
	    msg("");
	else if (subflags.do_error)	
	    semsg(_(e_pattern_not_found_str), get_search_pat());
    }


    if (subflags.do_ask && hasAnyFolding(curwin))
	
	changed_window_setting();


    vim_regfree(regmatch.regprog);
    vim_free(sub_copy);

    
    subflags.do_all = save_do_all;
    subflags.do_ask = save_do_ask;
}


    int do_sub_msg( int	    count_only)

{
    
    if (((sub_nsubs > p_report && (KeyTyped || sub_nlines > 1 || p_report < 1))
		|| count_only)
	    && messaging())
    {
	char	*msg_single;
	char	*msg_plural;

	if (got_int)
	    STRCPY(msg_buf, _("(Interrupted) "));
	else *msg_buf = NUL;

	msg_single = count_only ? NGETTEXT("%ld match on %ld line", "%ld matches on %ld line", sub_nsubs)

		    : NGETTEXT("%ld substitution on %ld line", "%ld substitutions on %ld line", sub_nsubs);
	msg_plural = count_only ? NGETTEXT("%ld match on %ld lines", "%ld matches on %ld lines", sub_nsubs)

		    : NGETTEXT("%ld substitution on %ld lines", "%ld substitutions on %ld lines", sub_nsubs);

	vim_snprintf_add(msg_buf, sizeof(msg_buf), NGETTEXT(msg_single, msg_plural, sub_nlines), sub_nsubs, (long)sub_nlines);


	if (msg(msg_buf))
	    
	    set_keep_msg((char_u *)msg_buf, 0);
	return TRUE;
    }
    if (got_int)
    {
	emsg(_(e_interrupted));
	return TRUE;
    }
    return FALSE;
}

    static void global_exe_one(char_u *cmd, linenr_T lnum)
{
    curwin->w_cursor.lnum = lnum;
    curwin->w_cursor.col = 0;
    if (*cmd == NUL || *cmd == '\n')
	do_cmdline((char_u *)"p", NULL, NULL, DOCMD_NOWAIT);
    else do_cmdline(cmd, NULL, NULL, DOCMD_NOWAIT);
}


    void ex_global(exarg_T *eap)
{
    linenr_T	lnum;		
    int		ndone = 0;
    int		type;		
    char_u	*cmd;		

    char_u	delim;		
    char_u	*pat;
    regmmatch_T	regmatch;
    int		match;
    int		which_pat;

    
    
    if (global_busy && (eap->line1 != 1 || eap->line2 != curbuf->b_ml.ml_line_count))
    {
	
	emsg(_(e_cannot_do_global_recursive_with_range));
	return;
    }

    if (eap->forceit)		    
	type = 'v';
    else type = *eap->cmd;
    cmd = eap->arg;
    which_pat = RE_LAST;	    


    if (in_vim9script() && check_global_and_subst(eap->cmd, eap->arg) == FAIL)
	return;


    
    if (*cmd == '\\')
    {
	++cmd;
	if (vim_strchr((char_u *)"/?&", *cmd) == NULL)
	{
	    emsg(_(e_backslash_should_be_followed_by));
	    return;
	}
	if (*cmd == '&')
	    which_pat = RE_SUBST;	
	else which_pat = RE_SEARCH;
	++cmd;
	pat = (char_u *)"";
    }
    else if (*cmd == NUL)
    {
	emsg(_(e_regular_expression_missing_from_global));
	return;
    }
    else if (check_regexp_delim(*cmd) == FAIL)
    {
	return;
    }
    else {
	delim = *cmd;		
	++cmd;			
	pat = cmd;		
	cmd = skip_regexp_ex(cmd, delim, magic_isset(), &eap->arg, NULL, NULL);
	if (cmd[0] == delim)		    
	    *cmd++ = NUL;		    
    }

    if (search_regcomp(pat, RE_BOTH, which_pat, SEARCH_HIS, &regmatch) == FAIL)
    {
	emsg(_(e_invalid_command));
	return;
    }

    if (global_busy)
    {
	lnum = curwin->w_cursor.lnum;
	match = vim_regexec_multi(&regmatch, curwin, curbuf, lnum, (colnr_T)0, NULL);
	if ((type == 'g' && match) || (type == 'v' && !match))
	    global_exe_one(cmd, lnum);
    }
    else {
	
	for (lnum = eap->line1; lnum <= eap->line2 && !got_int; ++lnum)
	{
	    
	    match = vim_regexec_multi(&regmatch, curwin, curbuf, lnum, (colnr_T)0, NULL);
	    if (regmatch.regprog == NULL)
		break;  
	    if ((type == 'g' && match) || (type == 'v' && !match))
	    {
		ml_setmarked(lnum);
		ndone++;
	    }
	    line_breakcheck();
	}

	
	if (got_int)
	    msg(_(e_interrupted));
	else if (ndone == 0)
	{
	    if (type == 'v')
	    {
		if (in_vim9script())
		    semsg(_(e_pattern_found_in_every_line_str), pat);
		else smsg(_("Pattern found in every line: %s"), pat);
	    }
	    else {
		if (in_vim9script())
		    semsg(_(e_pattern_not_found_str), pat);
		else smsg(_("Pattern not found: %s"), pat);
	    }
	}
	else {

	    start_global_changes();

	    global_exe(cmd);

	    end_global_changes();

	}

	ml_clearmarked();	   
    }

    vim_regfree(regmatch.regprog);
}


    void global_exe(char_u *cmd)
{
    linenr_T old_lcount;	
    buf_T    *old_buf = curbuf;	
    linenr_T lnum;		

    
    setpcmark();

    
    msg_didout = TRUE;

    sub_nsubs = 0;
    sub_nlines = 0;
    global_need_beginline = FALSE;
    global_busy = 1;
    old_lcount = curbuf->b_ml.ml_line_count;
    while (!got_int && (lnum = ml_firstmarked()) != 0 && global_busy == 1)
    {
	global_exe_one(cmd, lnum);
	ui_breakcheck();
    }

    global_busy = 0;
    if (global_need_beginline)
	beginline(BL_WHITE | BL_FIX);
    else check_cursor();

    
    
    changed_line_abv_curs();

    
    
    if (msg_col == 0 && msg_scrolled == 0)
	msg_didout = FALSE;

    
    
    
    
    if (!do_sub_msg(FALSE) && curbuf == old_buf)
	msgmore(curbuf->b_ml.ml_line_count - old_lcount);
}



    char_u * get_old_sub(void)
{
    return old_sub;
}


    void set_old_sub(char_u *val)
{
    vim_free(old_sub);
    old_sub = val;
}



    void free_old_sub(void)
{
    vim_free(old_sub);
}




    int prepare_tagpreview( int		undo_sync, int		use_previewpopup, use_popup_T	use_popup)



{
    win_T	*wp;


    need_mouse_correct = TRUE;


    
    if (!curwin->w_p_pvw)
    {

	if (use_previewpopup && *p_pvp != NUL)
	{
	    wp = popup_find_preview_window();
	    if (wp != NULL)
		popup_set_wantpos_cursor(wp, wp->w_minwidth, NULL);
	}
	else if (use_popup != USEPOPUP_NONE)
	{
	    wp = popup_find_info_window();
	    if (wp != NULL)
	    {
		if (use_popup == USEPOPUP_NORMAL)
		    popup_show(wp);
		else popup_hide(wp);
		
		
		redraw_all_later(NOT_VALID);
	    }
	}
	else  {

	    FOR_ALL_WINDOWS(wp)
		if (wp->w_p_pvw)
		    break;
	}
	if (wp != NULL)
	    win_enter(wp, undo_sync);
	else {
	    

	    if ((use_previewpopup && *p_pvp != NUL)
						 || use_popup != USEPOPUP_NONE)
		return popup_create_preview_window(use_popup != USEPOPUP_NONE);

	    if (win_split(g_do_tagpreview > 0 ? g_do_tagpreview : 0, 0) == FAIL)
		return FALSE;
	    curwin->w_p_pvw = TRUE;
	    curwin->w_p_wfh = TRUE;
	    RESET_BINDING(curwin);	    
	    

	    curwin->w_p_diff = FALSE;	    


	    curwin->w_p_fdc = 0;	    

	    return TRUE;
	}
    }
    return FALSE;
}




    void ex_smile(exarg_T *eap UNUSED)
{
    static char *code[] = {
	"\34 \4o\14$\4ox\30 \2o\30$\1ox\25 \2o\36$\1o\11 \1o\1$\3 \2$\1 \1o\1$x\5 \1o\1 \1$\1 \2o\10 \1o\44$\1o\7 \2$\1 \2$\1 \2$\1o\1$x\2 \2o\1 \1$\1 \1$\1 \1\"\1$\6 \1o\11$\4 \15$\4 \11$\1o\7 \3$\1o\2$\1o\1$x\2 \1\"\6$\1o\1$\5 \1o\11$\6 \13$\6 \12$\1o\4 \10$x\4 \7$\4 \13$\6 \13$\6 \27$x\4 \27$\4 \15$\4 \16$\2 \3\"\3$x\5 \1\"\3$\4\"\61$\5 \1\"\3$x\6 \3$\3 \1o\62$\5 \1\"\3$\1ox\5 \1o\2$\1\"\3 \63$\7 \3$\1ox\5 \3$\4 \55$\1\"\1 \1\"\6$", "\5o\4$\1ox\4 \1o\3$\4o\5$\2 \45$\3 \1o\21$x\4 \10$\1\"\4$\3 \42$\5 \4$\10\"x\3 \4\"\7 \4$\4 \1\"\34$\1\"\6 \1o\3$x\16 \1\"\3$\1o\5 \3\"\22$\1\"\2$\1\"\11 \3$x\20 \3$\1o\12 \1\"\2$\2\"\6$\4\"\13 \1o\3$x\21 \4$\1o\40 \1o\3$\1\"x\22 \1\"\4$\1o\6 \1o\6$\1o\1\"\4$\1o\10 \1o\4$x\24 \1\"\5$\2o\5 \2\"\4$\1o\5$\1o\3 \1o\4$\2\"x\27 \2\"\5$\4o\2 \1\"\3$\1o\11$\3\"x\32 \2\"\7$\2o\1 \12$x\42 \4\"\13$x\46 \14$x\47 \12$\1\"x\50 \1\"\3$\4\"x" };

    char *p;
    int n;
    int i;

    msg_start();
    msg_putchar('\n');
    for (i = 0; i < 2; ++i)
	for (p = code[i]; *p != NUL; ++p)
	    if (*p == 'x')
		msg_putchar('\n');
	    else for (n = *p++; n > 0; --n)
		    if (*p == 'o' || *p == '$')
			msg_putchar_attr(*p, HL_ATTR(HLF_L));
		    else msg_putchar(*p);
    msg_clr_eos();
}


    void ex_drop(exarg_T *eap)
{
    int		split = FALSE;
    win_T	*wp;
    buf_T	*buf;
    tabpage_T	*tp;

    if (ERROR_IF_POPUP_WINDOW || ERROR_IF_TERM_POPUP_WINDOW)
	return;

    
    set_arglist(eap->arg);

    
    if (ARGCOUNT == 0)
	return;

    if (cmdmod.cmod_tab)
    {
	
	
	
	ex_all(eap);
    }
    else {
	
	
	
	buf = buflist_findnr(ARGLIST[0].ae_fnum);

	FOR_ALL_TAB_WINDOWS(tp, wp)
	{
	    if (wp->w_buffer == buf)
	    {
		goto_tabpage_win(tp, wp);
		curwin->w_arg_idx = 0;
		if (!bufIsChanged(curbuf))
		{
		    int save_ar = curbuf->b_p_ar;

		    
		    curbuf->b_p_ar = TRUE;
		    buf_check_timestamp(curbuf, FALSE);
		    curbuf->b_p_ar = save_ar;
		}
		return;
	    }
	}

	
	if (!buf_hide(curbuf))
	{
	    ++emsg_off;
	    split = check_changed(curbuf, CCGD_AW | CCGD_EXCMD);
	    --emsg_off;
	}

	
	if (split)
	{
	    eap->cmdidx = CMD_sfirst;
	    eap->cmd[0] = 's';
	}
	else eap->cmdidx = CMD_first;
	ex_rewind(eap);
    }
}


    char_u * skip_vimgrep_pat(char_u *p, char_u **s, int *flags)
{
    return skip_vimgrep_pat_ext(p, s, flags, NULL, NULL);
}


    char_u * skip_vimgrep_pat_ext(char_u *p, char_u **s, int *flags, char_u **nulp, int *cp)
{
    int		c;

    if (vim_isIDc(*p))
    {
	
	if (s != NULL)
	    *s = p;
	p = skiptowhite(p);
	if (s != NULL && *p != NUL)
	{
	    if (nulp != NULL)
	    {
		*nulp = p;
		*cp = *p;
	    }
	    *p++ = NUL;
	}
    }
    else {
	
	if (s != NULL)
	    *s = p + 1;
	c = *p;
	p = skip_regexp(p + 1, c, TRUE);
	if (*p != c)
	    return NULL;

	
	if (s != NULL)
	{
	    if (nulp != NULL)
	    {
		*nulp = p;
		*cp = *p;
	    }
	    *p = NUL;
	}
	++p;

	
	while (*p == 'g' || *p == 'j' || *p == 'f')
	{
	    if (flags != NULL)
	    {
		if (*p == 'g')
		    *flags |= VGR_GLOBAL;
		else if (*p == 'j')
		    *flags |= VGR_NOJUMP;
		else *flags |= VGR_FUZZY;
	    }
	    ++p;
	}
    }
    return p;
}



    void ex_oldfiles(exarg_T *eap UNUSED)
{
    list_T	*l = get_vim_var_list(VV_OLDFILES);
    listitem_T	*li;
    int		nr = 0;
    char_u	*fname;

    if (l == NULL)
	msg(_("No old files"));
    else {
	msg_start();
	msg_scroll = TRUE;
	for (li = l->lv_first; li != NULL && !got_int; li = li->li_next)
	{
	    ++nr;
	    fname = tv_get_string(&li->li_tv);
	    if (!message_filtered(fname))
	    {
		msg_outnum((long)nr);
		msg_puts(": ");
		msg_outtrans(fname);
		msg_clr_eos();
		msg_putchar('\n');
		out_flush();	    
		ui_breakcheck();
	    }
	}

	
	got_int = FALSE;


	if (cmdmod.cmod_flags & CMOD_BROWSE)
	{
	    quit_more = FALSE;
	    nr = prompt_for_number(FALSE);
	    msg_starthere();
	    if (nr > 0)
	    {
		char_u *p = list_find_str(get_vim_var_list(VV_OLDFILES), (long)nr);

		if (p != NULL)
		{
		    p = expand_env_save(p);
		    eap->arg = p;
		    eap->cmdidx = CMD_edit;
		    cmdmod.cmod_flags &= ~CMOD_BROWSE;
		    do_exedit(eap, NULL);
		    vim_free(p);
		}
	    }
	}

    }
}

